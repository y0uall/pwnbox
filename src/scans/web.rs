use std::path::Path;
use std::sync::LazyLock;

use anyhow::Result;
use colored::Colorize;
use regex::Regex;
use tokio::task::{JoinHandle, JoinSet};

use crate::RE_FEROX_RESULT;
use crate::config::ScanConfig;
use crate::hosts;
use crate::report::Report;
use crate::runner;

// HTTP(S) service lines in nmap output, plus the header/body fields we scrape.
// Match any nmap service field that contains "http" — this covers http, https,
// ssl/http, http-alt, https-alt, http-proxy, etc. The service name is captured
// too so the scheme decision below needs no second pass over the output.
static RE_HTTP_PORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^(\d+)/tcp\s+open\s+(\S*http\S*)").unwrap());
static RE_HTTP_STATUS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"HTTP/\S+\s+(\d+)").unwrap());
static RE_HTTP_SERVER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^server:\s*(.+)").unwrap());
static RE_HTML_TITLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<title>(.*?)</title>").unwrap());
static RE_HTTP_LOCATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^location:\s*\S+://([^/:\s]+)").unwrap());
// Any open TCP port line, for the fingerprint pass below.
static RE_TCP_PORT_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^(\d+)/tcp\s+open\s+\S+").unwrap());
// An HTTP response status line inside nmap script/fingerprint output, e.g.
// "|     HTTP/1.1 200 OK" in a fingerprint-strings GetRequest block — hard
// evidence that a service nmap labels "unknown" actually speaks HTTP.
static RE_HTTP_FINGERPRINT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\|\s+HTTP/\d").unwrap());

/// Figure out which ports are running HTTP(S) from nmap output.
///
/// Two passes: named services first ("http", "ssl/http", ...), then ports nmap
/// labels "unknown" — their fingerprint-strings block can still hold a raw
/// HTTP response (an app server on a non-standard port, e.g. 6274 with an
/// HTTP/1.1 200 to GetRequest). Those count as plain HTTP so they get probed
/// and brute-forced like any named HTTP port.
pub fn detect_http_ports(nmap_output: &str) -> Vec<(u16, String)> {
    let mut ports = Vec::new();
    for cap in RE_HTTP_PORT.captures_iter(nmap_output) {
        if let Ok(port) = cap[1].parse::<u16>() {
            // scheme comes from the captured service name (https / ssl/http ->
            // TLS) — the old code rescanned every output line per port
            // (REVIEW.md "Niedrig": detect_http_ports one-pass)
            let service = &cap[2];
            // RPC-over-HTTP is not a browsable web service — nmap names it
            // *http*, but curl-probing it just adds noise to the error
            // section (seen on AD boxes: 593/tcp + ephemeral 496xx ports)
            if matches!(service, "ncacn_http" | "http-rpc-epmap") {
                continue;
            }
            let scheme = if service.contains("https") || service.contains("ssl") {
                "https".to_string()
            } else {
                "http".to_string()
            };
            ports.push((port, scheme));
        }
    }

    // fingerprint pass: HTTP evidence in the script block of an "unknown" port
    let mut current_port: Option<u16> = None;
    for line in nmap_output.lines() {
        if let Some(cap) = RE_TCP_PORT_LINE.captures(line) {
            current_port = cap[1].parse::<u16>().ok();
        } else if line.starts_with('|') {
            // a plaintext HTTP answer (even the 400 to a TLS probe) means the
            // port speaks plain HTTP — a real TLS service wouldn't answer
            // GetRequest with an HTTP status line
            if RE_HTTP_FINGERPRINT.is_match(line)
                && let Some(port) = current_port
                && !ports.iter().any(|(p, _)| *p == port)
            {
                ports.push((port, "http".to_string()));
            }
        } else {
            // anything that is neither a port line nor script output ends the
            // port's script block (Service Info, SF: fingerprints, ...)
            current_port = None;
        }
    }
    ports
}

/// Inputs shared by every per-port probe task.
struct ProbeCtx {
    ip: String,
    hostname: String,
    fast: bool,
    curl: String,
    whatweb: String,
}

/// Outcome of probing one HTTP port. The per-port probes run concurrently
/// (REVIEW.md finding 4); enumerate() collects these and writes them to the
/// report in nmap port order, so the report content stays deterministic.
struct PortProbe {
    /// position in the nmap port list — the report keeps that order
    idx: usize,
    port: u16,
    scheme: String,
    /// report lines for this port, in order (redirect / info / vhost / whatweb)
    lines: Vec<String>,
    /// tool failures for `report.add_error("WEB", ...)` — already printed to
    /// the console at the point of failure
    errors: Vec<String>,
    /// redirect targets found in the headers; the caller adds them to /etc/hosts
    redirect_hosts: Vec<String>,
    /// the main header/body probe succeeded — brute-force tasks are only
    /// spawned for such ports (matching the old serial loop's `continue`)
    probe_ok: bool,
    /// response body size in bytes, measured by curl itself
    /// (`-w '%{size_download}'`) — the ffuf `-fs` baseline. None in fast mode
    /// or when the size probe failed; vhost brute-forcing is skipped then
    body_size: Option<u64>,
    /// the `Server:` response header (empty if none) — drives the feroxbuster
    /// `-x` extension list (IIS wants asp/aspx, everything else on HTB is PHP)
    server: String,
}

/// feroxbuster `-x` extensions picked from the `Server:` header. Without `-x`,
/// ferox only ever finds directories and misses the actual scripts/files that
/// are the point of the brute on most HTB web boxes. IIS boxes want asp/aspx;
/// everything else is overwhelmingly PHP. txt/html always earn their place
/// (config dumps, static pages, backups).
fn ferox_extensions(server: &str) -> &'static str {
    let s = server.to_lowercase();
    if s.contains("iis") || s.contains("asp.net") {
        "asp,aspx,txt,html"
    } else {
        "php,txt,html"
    }
}

/// Probe one HTTP port: headers + body (concurrently), redirect check, vhost
/// comparison, whatweb fingerprinting. Failures are collected in the returned
/// struct, never propagated — one broken port must not fail the whole phase.
async fn probe_port(idx: usize, port: u16, scheme: &str, ctx: &ProbeCtx) -> PortProbe {
    let mut probe = PortProbe {
        idx,
        port,
        scheme: scheme.to_string(),
        lines: Vec::new(),
        errors: Vec::new(),
        redirect_hosts: Vec::new(),
        probe_ok: false,
        body_size: None,
        server: String::new(),
    };

    let url = format!("{scheme}://{}:{port}", ctx.ip);
    let vhost_url = format!("{scheme}://{}:{port}", ctx.hostname);

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
        runner::run_cmd(&ctx.curl, &hdr_args),
        runner::run_cmd(&ctx.curl, &body_args),
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
            probe.errors.push(detail);
            return probe;
        }
    };
    probe.probe_ok = true;

    // measure the response size for ffuf's -fs filter with curl's own byte
    // counter — String::len() of the lossy-decoded body miscounts non-UTF-8
    // responses (REVIEW.md finding 13). Full mode only: fast mode never
    // brute-forces vhosts.
    if !ctx.fast {
        let size_args = [
            "-sk",
            "--max-time",
            "10",
            "-o",
            "/dev/null",
            "-w",
            "%{size_download}",
            &url,
        ];
        match runner::run_cmd(&ctx.curl, &size_args).await {
            Ok(out) => match out.trim().parse::<u64>() {
                Ok(size) => probe.body_size = Some(size),
                Err(_) => {
                    let detail = format!(
                        "size probe {url} returned non-numeric output: {}",
                        out.trim()
                    );
                    println!("{} {detail}", "[!]".yellow());
                    probe.errors.push(detail);
                }
            },
            Err(e) => {
                let detail = format!("size probe {url} failed: {e}");
                println!("{} {detail}", "[!]".yellow());
                probe.errors.push(detail);
            }
        }
    }

    let status = RE_HTTP_STATUS
        .captures(&hdr_output)
        .map(|c| c[1].to_string())
        .unwrap_or_default();

    let server = RE_HTTP_SERVER
        .captures(&hdr_output)
        .map(|c| c[1].trim().replace('\r', ""))
        .unwrap_or_default();
    probe.server = server.clone();

    let title = RE_HTML_TITLE
        .captures(&body_output)
        .map(|c| c[1].to_string())
        .unwrap_or_default();

    // check for redirects to new hostnames — the /etc/hosts update itself is
    // done by the caller (it can fail the phase, so it stays out of the task)
    if let Some(caps) = RE_HTTP_LOCATION.captures(&hdr_output) {
        let redir_host = caps[1].to_lowercase();
        if redir_host != ctx.ip
            && redir_host != ctx.hostname
            && hosts::is_valid_hostname(&redir_host)
        {
            println!("{} Redirect -> {}", "[!]".yellow(), redir_host.cyan());
            probe.lines.push(format!("  redirect -> {redir_host}"));
            probe.redirect_hosts.push(redir_host);
        }
    }

    // compare IP vs hostname response (vhost detection)
    let vhost_probe = if !ctx.fast {
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
            runner::run_cmd(&ctx.curl, &vhdr_args),
            runner::run_cmd(&ctx.curl, &vbody_args),
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
                probe.errors.push(detail);
                None
            }
        }
    } else {
        None
    };

    let mut info = format!("  {scheme}://{}:{port}  ->  {status}", ctx.ip);
    if !server.is_empty() {
        info.push_str(&format!("  |  {server}"));
    }
    if !title.is_empty() {
        info.push_str(&format!("  |  \"{title}\""));
    }
    probe.lines.push(info);

    if let Some((vhost_status, vhost_title)) = &vhost_probe
        && (vhost_status != &status || vhost_title != &title)
    {
        let mut vinfo = format!("  {scheme}://{}:{port}  ->  {vhost_status}", ctx.hostname);
        if !vhost_title.is_empty() {
            vinfo.push_str(&format!("  |  \"{vhost_title}\""));
        }
        probe.lines.push(vinfo);
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

    // tech fingerprinting — whatweb gets its own 60s timeout: hanging under the
    // 300s default it was the long-pole of the phase (REVIEW.md finding 4)
    if runner::command_exists(&ctx.whatweb).await {
        match runner::run_cmd_timeout(
            &ctx.whatweb,
            &["--no-errors", "--color=never", "-a", "3", &url],
            60,
        )
        .await
        {
            Ok(wweb) => {
                let first_line = wweb.lines().next().unwrap_or("");
                if !first_line.is_empty() {
                    probe.lines.push(format!("  whatweb: {first_line}"));
                }
            }
            Err(e) => {
                let detail = format!("whatweb failed for {url}: {e}");
                println!("{} {detail}", "[!]".yellow());
                probe.errors.push(detail);
            }
        }
    }

    probe
}

/// Is `hostname` currently resolvable via /etc/hosts?
///
/// feroxbuster and gobuster's vhost mode target the box *hostname*; when the
/// /etc/hosts entry failed (e.g. no passwordless sudo) the name doesn't resolve
/// and both brute-forces would die on DNS errors, so the caller falls back to
/// the bare IP (REVIEW.md "Niedrig": ferox/vhost IP fallback). ffuf needs no
/// such check: it already targets the IP and carries the domain in the Host
/// header. Checked against /etc/hosts rather than a real lookup so tests stay
/// offline.
async fn hostname_resolvable(hostname: &str) -> bool {
    let Ok(content) = tokio::fs::read_to_string("/etc/hosts").await else {
        return false;
    };
    content.lines().any(|line| {
        let line = line.split('#').next().unwrap_or("");
        line.split_whitespace().skip(1).any(|h| h == hostname)
    })
}

/// Hit all HTTP ports with curl/whatweb (probes run concurrently per port).
/// Full mode additionally kicks off feroxbuster + vhost scans in background;
/// their raw output files land in `raw_dir` (the output dir's `raw/` subdir).
/// fast mode is headers-only.
pub async fn enumerate(
    ip: &str,
    hostname: &str,
    nmap_output: &str,
    raw_dir: &Path,
    report: &Report,
    scan_cfg: &ScanConfig,
) -> Result<Vec<JoinHandle<Result<()>>>> {
    let http_ports = detect_http_ports(nmap_output);
    let mut background_tasks: Vec<JoinHandle<Result<()>>> = Vec::new();

    if http_ports.is_empty() {
        println!(
            "{} No HTTP/HTTPS ports detected -- skipping web enum",
            "[!]".yellow()
        );
        return Ok(background_tasks);
    }

    // probe context shared by all per-port tasks (tool paths honour the
    // [tools] overrides from config)
    let ctx = ProbeCtx {
        ip: ip.to_string(),
        hostname: hostname.to_string(),
        fast: scan_cfg.fast,
        curl: scan_cfg.tool("curl"),
        whatweb: scan_cfg.tool("whatweb"),
    };
    let ferox_bin = scan_cfg.tool("feroxbuster");
    let ffuf_bin = scan_cfg.tool("ffuf");
    let gobuster_bin = scan_cfg.tool("gobuster");

    // Probe all ports concurrently — with several HTTP ports the strictly
    // serial per-port probes (curl + vhost + whatweb each) dominated this
    // phase's wall time (REVIEW.md finding 4). Results are collected and
    // processed in nmap port order below, so the report stays deterministic.
    let mut probes = JoinSet::new();
    for (idx, (port, scheme)) in http_ports.iter().enumerate() {
        let ctx = ProbeCtx {
            ip: ctx.ip.clone(),
            hostname: ctx.hostname.clone(),
            fast: ctx.fast,
            curl: ctx.curl.clone(),
            whatweb: ctx.whatweb.clone(),
        };
        let port = *port;
        let scheme = scheme.clone();
        probes.spawn(async move { probe_port(idx, port, &scheme, &ctx).await });
    }

    let mut results: Vec<PortProbe> = Vec::with_capacity(http_ports.len());
    while let Some(res) = probes.join_next().await {
        match res {
            Ok(probe) => results.push(probe),
            Err(e) => {
                let detail = format!("port probe task panicked: {e}");
                println!("{} {detail}", "[!]".yellow());
                report.add_error("WEB", &detail).await;
            }
        }
    }
    // deterministic report order regardless of task completion order
    results.sort_by_key(|probe| probe.idx);

    // add redirect hostnames to /etc/hosts — a failure here still aborts the
    // phase like in the serial version (run_scan treats it as best-effort)
    for probe in &results {
        if !probe.redirect_hosts.is_empty() {
            hosts::add_hosts(ip, &probe.redirect_hosts).await?;
        }
    }

    // report lines + tool failures in port order
    let mut web_info = String::new();
    for probe in &results {
        for line in &probe.lines {
            web_info.push_str(line);
            web_info.push('\n');
        }
        for err in &probe.errors {
            report.add_error("WEB", err).await;
        }
    }

    // dir brute + vhost brute in background — full mode only: `--fast` is
    // documented as "quick TCP scan + web headers", and run_scan's fast path
    // discards the returned handles (REVIEW.md finding 2)
    if !scan_cfg.fast {
        // feroxbuster/gobuster run against the box hostname; if it never made
        // it into /etc/hosts (no passwordless sudo) the name doesn't resolve
        // and both brute-forces would die on DNS errors — hit the bare IP
        // instead (REVIEW.md "Niedrig")
        let brute_host = if hostname_resolvable(hostname).await {
            hostname.to_string()
        } else {
            println!(
                "{} {hostname} not in /etc/hosts — brute-forcing the IP instead",
                "[!]".yellow()
            );
            ip.to_string()
        };
        for probe in &results {
            // a failed probe spawns no brute-force tasks — the serial version
            // skipped them too (`continue` in the old loop)
            if !probe.probe_ok {
                continue;
            }
            let port = probe.port;
            let scheme = probe.scheme.clone();

            // dir brute
            if runner::command_exists(&ferox_bin).await
                && let Some(wl) = crate::config::find_wordlist(&scan_cfg.wordlists.dir_medium)
            {
                let ferox_out = raw_dir.join(format!("ferox-{port}.txt"));
                let ferox_url = format!("{scheme}://{brute_host}:{port}");
                let ferox_out_str = ferox_out.to_string_lossy().to_string();
                let ferox_threads = scan_cfg.ferox_threads;
                let ferox_cmd = ferox_bin.clone();
                let exts = ferox_extensions(&probe.server);
                println!(
                    "{} feroxbuster on port {port} (background, -x {exts})...",
                    "[*]".cyan()
                );
                background_tasks.push(tokio::spawn(async move {
                    let threads = ferox_threads.to_string();
                    // ferox stops itself after 10m (--time-limit) and still
                    // flushes its results; the runner timeout sits 60s above
                    // that so the 300s default can't hard-kill it mid-flush
                    // (REVIEW.md finding 10)
                    let result = runner::run_cmd_timeout(
                        &ferox_cmd,
                        &[
                            "-u",
                            &ferox_url,
                            "-w",
                            &wl,
                            "-x",
                            exts,
                            "-k",
                            "-q",
                            "--no-state",
                            "--time-limit",
                            "10m",
                            "-t",
                            &threads,
                            "-o",
                            &ferox_out_str,
                        ],
                        660,
                    )
                    .await;
                    if let Err(e) = result {
                        // Killed mid-scan (usually the 660s timeout): when the
                        // output file already holds usable hits this is a
                        // partial success, not a scan error — no add_error, and
                        // process_ferox_results still picks the file up.
                        let hits = tokio::fs::read_to_string(&ferox_out_str)
                            .await
                            .map(|content| {
                                content
                                    .lines()
                                    .filter(|l| RE_FEROX_RESULT.is_match(l))
                                    .count()
                            })
                            .unwrap_or(0);
                        if hits > 0 {
                            println!(
                                "{} feroxbuster on port {port} stopped early ({e}) — keeping {hits} partial result(s)",
                                "[!]".yellow()
                            );
                        } else {
                            return Err(e);
                        }
                    }
                    Ok(())
                }));
            }

            // vhost brute needs the curl-measured body size as -fs baseline
            if let Some(body_size) = probe.body_size
                && let Some(wl) = crate::config::find_wordlist(&scan_cfg.wordlists.dns_subdomains)
            {
                let vhost_out = raw_dir.join(format!("vhosts-{port}.txt"));
                let vhost_out_str = vhost_out.to_string_lossy().to_string();
                let body_size = body_size.to_string();
                let vhost_domain = hostname.to_string();

                if runner::command_exists(&ffuf_bin).await {
                    let ip_owned = ip.to_string();
                    let scheme_owned = scheme.clone();
                    let ffuf_cmd = ffuf_bin.clone();
                    println!(
                        "{} ffuf vhost scan on port {port} (background)...",
                        "[*]".cyan()
                    );
                    background_tasks.push(tokio::spawn(async move {
                        let ffuf_url = format!("{scheme_owned}://{ip_owned}:{port}");
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
                    let host_owned = brute_host.clone();
                    let hostname_owned = hostname.to_string();
                    let scheme_owned = scheme.clone();
                    let gobuster_cmd = gobuster_bin.clone();
                    println!(
                        "{} gobuster vhost scan on port {port} (background)...",
                        "[*]".cyan()
                    );
                    background_tasks.push(tokio::spawn(async move {
                        let gobuster_url = format!("{scheme_owned}://{host_owned}:{port}");
                        // when the URL carries the fallback IP instead of the
                        // hostname, gobuster can't derive the vhost domain from
                        // it — --domain supplies it for the Host-header wordlist
                        let mut args = vec![
                            "vhost",
                            "-u",
                            gobuster_url.as_str(),
                            "-w",
                            wl.as_str(),
                            "--append-domain",
                        ];
                        if host_owned != hostname_owned {
                            args.push("--domain");
                            args.push(hostname_owned.as_str());
                        }
                        args.extend(["-k", "-q", "-o", vhost_out_str.as_str()]);
                        runner::run_cmd(&gobuster_cmd, &args).await?;
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::{Path, PathBuf};

    use super::{detect_http_ports, enumerate, ferox_extensions};
    use crate::config::{ScanConfig, ToolsConfig, WordlistsConfig};
    use crate::report::Report;

    #[test]
    fn detects_http_https_and_variants() {
        let output = "\
80/tcp   open  http
443/tcp  open  ssl/http
8080/tcp open  http-alt
8443/tcp open  https-alt
9090/tcp open  http-proxy
22/tcp   open  ssh";
        let ports = detect_http_ports(output);
        assert!(ports.iter().any(|(p, s)| *p == 80 && s == "http"));
        assert!(ports.iter().any(|(p, s)| *p == 443 && s == "https"));
        assert!(ports.iter().any(|(p, s)| *p == 8080 && s == "http"));
        assert!(ports.iter().any(|(p, s)| *p == 8443 && s == "https"));
        assert!(ports.iter().any(|(p, s)| *p == 9090 && s == "http"));
        assert!(!ports.iter().any(|(p, _)| *p == 22));
    }

    #[test]
    fn skips_rpc_over_http_ports() {
        // AD boxes: nmap calls RPC-over-HTTP "*http*", but it is not a
        // browsable web service — probing it only adds curl errors
        let output = "\
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49680/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)";
        let ports = detect_http_ports(output);
        assert_eq!(ports, vec![(5985, "http".to_string())]);
    }

    #[test]
    fn detects_http_on_unknown_ports_via_fingerprint() {
        // app server on a non-standard port: nmap labels it "unknown", but
        // the GetRequest fingerprint holds a plaintext HTTP response
        let output = "\
80/tcp   open  http     nginx 1.18.0 (Ubuntu)
6274/tcp open  unknown
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     content-type: text/html; charset=utf-8
|   SSLSessionReq, TLSSessionReq:
|     HTTP/1.1 400 Bad Request
|_    Connection: close
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel";
        let ports = detect_http_ports(output);
        assert!(ports.iter().any(|(p, s)| *p == 6274 && s == "http"));
        assert_eq!(ports.len(), 2, "no duplicates from the two HTTP lines");
    }

    #[test]
    fn ignores_non_http_fingerprints() {
        let output = "\
2121/tcp open  unknown
| fingerprint-strings:
|   GenericLines:
|     220 ProFTPD Server ready
|_    500 Invalid command: try being more creative
Service Info: OS: Linux";
        assert!(detect_http_ports(output).is_empty());
    }

    #[test]
    fn ferox_extensions_pick_aspx_for_iis_php_otherwise() {
        assert_eq!(ferox_extensions("Microsoft-IIS/10.0"), "asp,aspx,txt,html");
        assert_eq!(ferox_extensions("Apache/2.4.52 (Ubuntu)"), "php,txt,html");
        assert_eq!(ferox_extensions("nginx/1.18.0"), "php,txt,html");
        assert_eq!(ferox_extensions(""), "php,txt,html"); // no Server header
    }

    /// ScanConfig with stubbed tools so enumerate() runs end-to-end without
    /// network or real pentest tools: `curl` is a shell script printing a canned
    /// HTTP response (title embeds the probed port), feroxbuster is `/bin/true`
    /// (exists, exits 0 instantly), and whatweb/ffuf/gobuster point at
    /// nonexistent paths so they count as missing.
    fn stub_scan_cfg(fast: bool, tmp: &Path) -> ScanConfig {
        let curl_stub = tmp.join("curl-stub.sh");
        std::fs::write(
            &curl_stub,
            "#!/bin/sh\nfor last; do :; done\nport=${last##*:}\nprintf 'HTTP/1.1 200 OK\\r\\nServer: stub\\r\\n\\r\\n<title>stub-%s</title>\\n' \"$port\"\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&curl_stub, std::fs::Permissions::from_mode(0o755)).unwrap();

        let wordlist = tmp.join("dirs.txt");
        std::fs::write(&wordlist, "admin\nlogin\n").unwrap();
        let wordlist = wordlist.to_string_lossy().to_string();

        let tools = ToolsConfig {
            curl: curl_stub.to_string_lossy().to_string(),
            feroxbuster: "/bin/true".to_string(),
            whatweb: "/nonexistent/whatweb".to_string(),
            ffuf: "/nonexistent/ffuf".to_string(),
            gobuster: "/nonexistent/gobuster".to_string(),
            ..Default::default()
        };

        // dir_small is set too: if a fast-mode spawn regresses, it must find a
        // wordlist and actually spawn — otherwise this test would pass vacuously
        let wordlists = WordlistsConfig {
            dir_medium: vec![wordlist.clone()],
            dir_small: vec![wordlist],
            ..Default::default()
        };

        ScanConfig {
            verbose: false,
            skip: HashSet::new(),
            timeout: 30,
            fast,
            ferox_threads: 50,
            wordlists,
            tools,
        }
    }

    /// REVIEW.md finding 2: fast mode ("headers only") must return zero
    /// background tasks; the same fixture in full mode spawns feroxbuster.
    #[tokio::test]
    async fn fast_mode_spawns_no_background_tasks() {
        let tmp = TmpDir::new("web_fast");
        let nmap = "8080/tcp open http Apache httpd 2.4.52";

        let fast_cfg = stub_scan_cfg(true, tmp.path());
        let report = Report::new();
        let tasks = enumerate(
            "127.0.0.1",
            "testbox.htb",
            nmap,
            tmp.path(),
            &report,
            &fast_cfg,
        )
        .await
        .unwrap();
        assert!(
            tasks.is_empty(),
            "fast mode must not spawn feroxbuster/vhost background tasks"
        );
        // the header probe itself still ran and was reported (no early bail-out)
        let out = tmp.path().join("fast-report.txt");
        report.write_to_file(&out).await.unwrap();
        assert!(std::fs::read_to_string(&out).unwrap().contains("stub-8080"));

        // same fixture in full mode: exactly one background task (ferox stub)
        let full_cfg = stub_scan_cfg(false, tmp.path());
        let report = Report::new();
        let tasks = enumerate(
            "127.0.0.1",
            "testbox.htb",
            nmap,
            tmp.path(),
            &report,
            &full_cfg,
        )
        .await
        .unwrap();
        assert_eq!(tasks.len(), 1, "full mode spawns the feroxbuster task");
        for task in tasks {
            task.await.unwrap().unwrap();
        }
    }

    /// The probes run concurrently, but the report must follow the nmap port
    /// order, not the (random) task completion order (REVIEW.md finding 4).
    #[tokio::test]
    async fn report_lines_follow_nmap_port_order() {
        let tmp = TmpDir::new("web_order");
        // deliberately not numerically sorted
        let nmap = "9090/tcp open http-alt\n8080/tcp open http";

        let cfg = stub_scan_cfg(false, tmp.path());
        let report = Report::new();
        let tasks = enumerate("127.0.0.1", "testbox.htb", nmap, tmp.path(), &report, &cfg)
            .await
            .unwrap();
        assert_eq!(tasks.len(), 2, "one feroxbuster task per port");
        for task in tasks {
            task.await.unwrap().unwrap();
        }

        let out = tmp.path().join("report.txt");
        report.write_to_file(&out).await.unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        let pos_9090 = text.find("stub-9090").unwrap();
        let pos_8080 = text.find("stub-8080").unwrap();
        assert!(
            pos_9090 < pos_8080,
            "report must keep nmap port order, got:\n{text}"
        );
    }

    /// feroxbuster stub that writes partial results to the `-o` file and then
    /// fails — emulating a timeout/kill after partial output.
    const FEROX_STUB_PARTIAL: &str = "#!/bin/sh
out=
while [ $# -gt 0 ]; do [ \"$1\" = \"-o\" ] && out=$2; shift; done
printf '200      GET      /admin\\n301      GET      /old\\n' > \"$out\"
exit 1
";

    const FEROX_STUB_NO_HITS: &str = "#!/bin/sh\nexit 1\n";

    /// Full-mode ScanConfig whose feroxbuster is replaced by the given script.
    fn stub_scan_cfg_with_ferox(tmp: &Path, ferox_script: &str) -> ScanConfig {
        let ferox = tmp.join("ferox-stub.sh");
        std::fs::write(&ferox, ferox_script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ferox, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mut cfg = stub_scan_cfg(false, tmp);
        cfg.tools.feroxbuster = ferox.to_string_lossy().to_string();
        cfg
    }

    /// REVIEW.md finding 10: a feroxbuster that died mid-scan (timeout/kill) is
    /// not a scan error when its output file already holds usable hits — the
    /// partial results still reach process_ferox_results. With no hits on disk
    /// the error must still propagate.
    #[tokio::test]
    async fn ferox_partial_results_survive_task_failure() {
        let nmap = "8080/tcp open http";

        let tmp = TmpDir::new("web_ferox_partial");
        let cfg = stub_scan_cfg_with_ferox(tmp.path(), FEROX_STUB_PARTIAL);
        let tasks = enumerate(
            "127.0.0.1",
            "testbox.htb",
            nmap,
            tmp.path(),
            &Report::new(),
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(tasks.len(), 1);
        // failed process, but hits on disk -> task reports success (the join
        // loop in run_scan therefore records no error)
        tasks.into_iter().next().unwrap().await.unwrap().unwrap();
        // and the partial results file is there for process_ferox_results
        let ferox_out = std::fs::read_to_string(tmp.path().join("ferox-8080.txt")).unwrap();
        assert!(ferox_out.contains("/admin"));

        // same failure with NO hits on disk -> the error still propagates
        let tmp = TmpDir::new("web_ferox_empty");
        let cfg = stub_scan_cfg_with_ferox(tmp.path(), FEROX_STUB_NO_HITS);
        let tasks = enumerate(
            "127.0.0.1",
            "testbox.htb",
            nmap,
            tmp.path(),
            &Report::new(),
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(tasks.len(), 1);
        assert!(tasks.into_iter().next().unwrap().await.unwrap().is_err());
    }

    /// Throwaway directory under the system temp dir, removed on drop.
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("pwnbox_web_test_{}_{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            TmpDir(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
