use std::path::Path;
use std::sync::LazyLock;

use anyhow::Result;
use colored::Colorize;
use regex::Regex;
use tokio::task::JoinHandle;

use crate::config::ScanConfig;
use crate::hosts;
use crate::report::Report;
use crate::runner;

// HTTP(S) service lines in nmap output, plus the header/body fields we scrape.
static RE_HTTP_PORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^(\d+)/tcp\s+open\s+.*(https?|ssl.http|http-proxy|http-alt)").unwrap()
});
static RE_HTTP_STATUS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"HTTP/\S+\s+(\d+)").unwrap());
static RE_HTTP_SERVER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^server:\s*(.+)").unwrap());
static RE_HTML_TITLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<title>(.*?)</title>").unwrap());
static RE_HTTP_LOCATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^location:\s*\S+://([^/:\s]+)").unwrap());

/// Figure out which ports are running HTTP(S) from nmap output.
pub fn detect_http_ports(nmap_output: &str) -> Vec<(u16, String)> {
    let mut ports = Vec::new();
    for cap in RE_HTTP_PORT.captures_iter(nmap_output) {
        if let Ok(port) = cap[1].parse::<u16>() {
            let scheme = if nmap_output.lines().any(|l| {
                l.starts_with(&format!("{port}/tcp")) && (l.contains("https") || l.contains("ssl"))
            }) {
                "https".to_string()
            } else {
                "http".to_string()
            };
            ports.push((port, scheme));
        }
    }
    ports
}

/// Hit all HTTP ports with curl/whatweb, kick off feroxbuster + vhost scans in background.
pub async fn enumerate(
    ip: &str,
    hostname: &str,
    nmap_output: &str,
    output_dir: &Path,
    report: &Report,
    scan_cfg: &ScanConfig,
) -> Result<Vec<JoinHandle<Result<()>>>> {
    let http_ports = detect_http_ports(nmap_output);
    let mut background_tasks: Vec<JoinHandle<Result<()>>> = Vec::new();
    let mut web_info = String::new();

    if http_ports.is_empty() {
        println!(
            "{} No HTTP/HTTPS ports detected -- skipping web enum",
            "[!]".yellow()
        );
        return Ok(background_tasks);
    }

    // resolve tool paths once (honours [tools] overrides from config)
    let curl = scan_cfg.tool("curl");
    let whatweb = scan_cfg.tool("whatweb");
    let ferox_bin = scan_cfg.tool("feroxbuster");
    let ffuf_bin = scan_cfg.tool("ffuf");
    let gobuster_bin = scan_cfg.tool("gobuster");

    for (port, scheme) in &http_ports {
        let url = format!("{scheme}://{ip}:{port}");
        let vhost_url = format!("{scheme}://{hostname}:{port}");

        println!("{} Probing {}", "[*]".cyan(), url.yellow());

        // grab headers + body concurrently — two independent 10s curls, so
        // fetching them in parallel halves the per-port probe latency
        let hdr_args = [
            "-sk",
            "--max-time",
            "10",
            "-D",
            "-",
            "-o",
            "/dev/null",
            &url,
        ];
        let body_args = ["-sk", "--max-time", "10", &url];
        let (hdr_result, body_result) = tokio::join!(
            runner::run_cmd(&curl, &hdr_args),
            runner::run_cmd(&curl, &body_args),
        );
        let (hdr_output, body_output) = match (hdr_result, body_result) {
            (Ok(headers), Ok(body)) => (headers, body),
            (headers, body) => {
                let detail = format!(
                    "probe {url} failed (headers: {}; body: {})",
                    headers
                        .err()
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "ok".to_string()),
                    body.err()
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "ok".to_string())
                );
                println!("{} {detail}", "[!]".yellow());
                report.add_error("WEB", &detail).await;
                continue;
            }
        };

        let status = RE_HTTP_STATUS
            .captures(&hdr_output)
            .map(|c| c[1].to_string())
            .unwrap_or_default();

        let server = RE_HTTP_SERVER
            .captures(&hdr_output)
            .map(|c| c[1].trim().replace('\r', ""))
            .unwrap_or_default();

        let title = RE_HTML_TITLE
            .captures(&body_output)
            .map(|c| c[1].to_string())
            .unwrap_or_default();

        // check for redirects to new hostnames
        if let Some(caps) = RE_HTTP_LOCATION.captures(&hdr_output) {
            let redir_host = caps[1].to_lowercase();
            if redir_host != ip && redir_host != hostname && hosts::is_valid_hostname(&redir_host) {
                println!("{} Redirect -> {}", "[!]".yellow(), redir_host.cyan());
                web_info.push_str(&format!("  redirect -> {redir_host}\n"));
                hosts::add_hosts(ip, &[redir_host]).await?;
            }
        }

        // compare IP vs hostname response (vhost detection)
        let vhost_probe = if !scan_cfg.fast {
            let vhdr_args = [
                "-sk",
                "--max-time",
                "10",
                "-D",
                "-",
                "-o",
                "/dev/null",
                &vhost_url,
            ];
            let vbody_args = ["-sk", "--max-time", "10", &vhost_url];
            let (vhdr_result, vbody_result) = tokio::join!(
                runner::run_cmd(&curl, &vhdr_args),
                runner::run_cmd(&curl, &vbody_args),
            );
            match (vhdr_result, vbody_result) {
                (Ok(vhdr), Ok(vbody)) => {
                    let status = RE_HTTP_STATUS
                        .captures(&vhdr)
                        .map(|c| c[1].to_string())
                        .unwrap_or_default();
                    let title = RE_HTML_TITLE
                        .captures(&vbody)
                        .map(|c| c[1].to_string())
                        .unwrap_or_default();
                    Some((status, title))
                }
                (headers, body) => {
                    let detail = format!(
                        "vhost probe {vhost_url} failed (headers: {}; body: {})",
                        headers
                            .err()
                            .map(|e| e.to_string())
                            .unwrap_or_else(|| "ok".to_string()),
                        body.err()
                            .map(|e| e.to_string())
                            .unwrap_or_else(|| "ok".to_string())
                    );
                    println!("{} {detail}", "[!]".yellow());
                    report.add_error("WEB", &detail).await;
                    None
                }
            }
        } else {
            None
        };

        let mut info = format!("  {scheme}://:{port}  ->  {status}");
        if !server.is_empty() {
            info.push_str(&format!("  |  {server}"));
        }
        if !title.is_empty() {
            info.push_str(&format!("  |  \"{title}\""));
        }
        web_info.push_str(&format!("{info}\n"));

        if let Some((vhost_status, vhost_title)) = &vhost_probe
            && (vhost_status != &status || vhost_title != &title)
        {
            let mut vinfo = format!("  {scheme}://{hostname}:{port}  ->  {vhost_status}");
            if !vhost_title.is_empty() {
                vinfo.push_str(&format!("  |  \"{vhost_title}\""));
            }
            web_info.push_str(&format!("{vinfo}\n"));
        }

        let server_display = if server.is_empty() {
            String::new()
        } else {
            format!("| {server} ")
        };
        let title_display = if title.is_empty() {
            String::new()
        } else {
            format!("| \"{title}\"")
        };
        println!(
            "{} Port {port}: {status} {server_display}{title_display}",
            "[+]".green()
        );

        // tech fingerprinting
        if runner::command_exists(&whatweb).await {
            match runner::run_cmd(&whatweb, &["--no-errors", "--color=never", "-a", "3", &url])
                .await
            {
                Ok(wweb) => {
                    let first_line = wweb.lines().next().unwrap_or("");
                    if !first_line.is_empty() {
                        web_info.push_str(&format!("  whatweb: {first_line}\n"));
                    }
                }
                Err(e) => {
                    let detail = format!("whatweb failed for {url}: {e}");
                    println!("{} {detail}", "[!]".yellow());
                    report.add_error("WEB", &detail).await;
                }
            }
        }

        // dir brute in background
        if runner::command_exists(&ferox_bin).await {
            let wordlist = if scan_cfg.fast {
                crate::config::find_wordlist(&scan_cfg.wordlists.dir_small)
            } else {
                crate::config::find_wordlist(&scan_cfg.wordlists.dir_medium)
            };
            if let Some(wl) = wordlist {
                let ferox_out = output_dir.join(format!("ferox-{port}.txt"));
                let ferox_url = format!("{scheme}://{hostname}:{port}");
                let ferox_out_str = ferox_out.to_string_lossy().to_string();
                let ferox_threads = scan_cfg.ferox_threads;
                let ferox_cmd = ferox_bin.clone();
                println!(
                    "{} feroxbuster on port {port} (background)...",
                    "[*]".cyan()
                );
                background_tasks.push(tokio::spawn(async move {
                    let threads = ferox_threads.to_string();
                    runner::run_cmd(
                        &ferox_cmd,
                        &[
                            "-u",
                            &ferox_url,
                            "-w",
                            &wl,
                            "-k",
                            "-q",
                            "--no-state",
                            "-t",
                            &threads,
                            "-o",
                            &ferox_out_str,
                        ],
                    )
                    .await?;
                    Ok(())
                }));
            }
        }

        // vhost brute in background (not in fast mode)
        if !scan_cfg.fast {
            let vhost_wl = crate::config::find_wordlist(&scan_cfg.wordlists.dns_subdomains);
            if let Some(wl) = vhost_wl {
                let vhost_out = output_dir.join(format!("vhosts-{port}.txt"));
                let vhost_out_str = vhost_out.to_string_lossy().to_string();
                let body_size = body_output.len().to_string();
                let vhost_domain = hostname.to_string();

                if runner::command_exists(&ffuf_bin).await {
                    let ip_owned = ip.to_string();
                    let port_owned = *port;
                    let scheme_owned = scheme.clone();
                    let ffuf_cmd = ffuf_bin.clone();
                    println!(
                        "{} ffuf vhost scan on port {port} (background)...",
                        "[*]".cyan()
                    );
                    background_tasks.push(tokio::spawn(async move {
                        let ffuf_url = format!("{scheme_owned}://{ip_owned}:{port_owned}");
                        let host_header = format!("Host: FUZZ.{vhost_domain}");
                        runner::run_cmd(
                            &ffuf_cmd,
                            &[
                                "-u",
                                &ffuf_url,
                                "-H",
                                &host_header,
                                "-w",
                                &wl,
                                "-fs",
                                &body_size,
                                "-mc",
                                "all",
                                "-fc",
                                "400",
                                "-t",
                                "40",
                                "-o",
                                &vhost_out_str,
                                "-of",
                                "csv",
                                "-noninteractive",
                            ],
                        )
                        .await?;
                        Ok(())
                    }));
                } else if runner::command_exists(&gobuster_bin).await {
                    let hostname_owned = hostname.to_string();
                    let scheme_owned = scheme.clone();
                    let port_owned = *port;
                    let gobuster_cmd = gobuster_bin.clone();
                    println!(
                        "{} gobuster vhost scan on port {port} (background)...",
                        "[*]".cyan()
                    );
                    background_tasks.push(tokio::spawn(async move {
                        let gobuster_url =
                            format!("{scheme_owned}://{hostname_owned}:{port_owned}");
                        runner::run_cmd(
                            &gobuster_cmd,
                            &[
                                "vhost",
                                "-u",
                                &gobuster_url,
                                "-w",
                                &wl,
                                "--append-domain",
                                "-k",
                                "-q",
                                "-o",
                                &vhost_out_str,
                            ],
                        )
                        .await?;
                        Ok(())
                    }));
                }
            }
        }
    }

    if !web_info.is_empty() {
        report.section("WEB").await;
        for line in web_info.lines() {
            if !line.is_empty() {
                report.add(line).await;
            }
        }
    }

    Ok(background_tasks)
}
