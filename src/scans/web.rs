use std::path::{Path, PathBuf};
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

#[derive(Clone, Copy)]
pub enum WebResultKind {
    Directory,
    Vhost,
}

/// Keep each job tied to the exact file it produces. Aborting enumerate before
/// it returns must also abort jobs not yet registered by the main pipeline.
pub struct WebTask {
    pub handle: JoinHandle<Result<()>>,
    pub output: PathBuf,
    pub kind: WebResultKind,
}

impl Drop for WebTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl WebTask {
    fn spawn<F>(output: PathBuf, kind: WebResultKind, future: F) -> Self
    where
        F: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        Self {
            handle: tokio::spawn(future),
            output,
            kind,
        }
    }
}

// HTTP(S) service lines in nmap output, plus the header/body fields we scrape.
// Match any nmap service field that contains "http" — this covers http, https,
// ssl/http, http-alt, https-alt, http-proxy, etc. The service name is captured
// too so the scheme decision below needs no second pass over the output.
static RE_HTTP_PORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^(\d+)/tcp\s+open\s+(\S*http\S*)").unwrap());
static RE_HTTP_STATUS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^HTTP/\S+[ \t]+(\d{3})(?:[ \t]|\r?\n|$)").unwrap());
static RE_HTTP_SERVER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^server:[ \t]*([^\r\n]+)").unwrap());
static RE_HTML_TITLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<title>(.*?)</title>").unwrap());
static RE_HTTP_LOCATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^location:[ \t]*https?://([^/:\s]+)").unwrap());
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
    /// Response body byte count before UTF-8 decoding — the ffuf baseline.
    /// None in headers-only mode.
    body_size: Option<u64>,
    /// the `Server:` response header (empty if none) — drives the feroxbuster
    /// `-x` extension list (IIS wants asp/aspx, everything else on HTB is PHP)
    server: String,
}

pub fn is_winrm_http_listener(port: u16, fingerprint: &str) -> bool {
    // Besides the remote WSMan ports, Windows exposes a local WinRM listener
    // on 47001 (Microsoft's "Obtaining Data from the Local Computer" docs).
    // Accept curl's Server header and nmap's product spelling. Other servers
    // on these ports and HTTPAPI elsewhere still get normal web enumeration.
    let fingerprint = fingerprint.to_ascii_lowercase();
    matches!(port, 5985 | 5986 | 47001)
        && (fingerprint.contains("microsoft-httpapi/") || fingerprint.contains("microsoft httpapi"))
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

struct HttpResponse {
    status: String,
    server: String,
    title: String,
    redirect_host: Option<String>,
    body_size: u64,
}

/// Split before decoding: lossy UTF-8 conversion must not inflate ffuf's size
/// baseline. Header regexes never see the body (which can contain fake headers).
fn parse_http_response(mut bytes: &[u8], headers_only: bool) -> Result<HttpResponse> {
    loop {
        let crlf = bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|end| (end, 4));
        let lf = bytes
            .windows(2)
            .position(|w| w == b"\n\n")
            .map(|end| (end, 2));
        let (end, separator) = crlf
            .into_iter()
            .chain(lf)
            .min_by_key(|(end, _)| *end)
            .ok_or_else(|| anyhow::anyhow!("HTTP response has no complete header block"))?;
        let headers = String::from_utf8_lossy(&bytes[..end]);
        let status = RE_HTTP_STATUS
            .captures(&headers)
            .map(|caps| caps[1].to_string())
            .ok_or_else(|| anyhow::anyhow!("HTTP status missing"))?;
        bytes = &bytes[end + separator..];
        // curl can include interim responses before the final response.
        if status.starts_with('1') && status != "101" {
            continue;
        }
        let server = RE_HTTP_SERVER
            .captures(&headers)
            .map(|c| c[1].trim().to_string())
            .unwrap_or_default();
        let redirect_host = RE_HTTP_LOCATION
            .captures(&headers)
            .map(|c| c[1].to_lowercase());
        let title = if headers_only {
            String::new()
        } else {
            RE_HTML_TITLE
                .captures(&String::from_utf8_lossy(bytes))
                .map(|c| c[1].to_string())
                .unwrap_or_default()
        };
        return Ok(HttpResponse {
            status,
            server,
            title,
            redirect_host,
            body_size: if headers_only { 0 } else { bytes.len() as u64 },
        });
    }
}

fn url_host(host: &str) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

async fn fetch_response(
    curl: &str,
    url: &str,
    headers_only: bool,
    connect_to: Option<&str>,
) -> Result<HttpResponse> {
    let mode = if headers_only { "-I" } else { "-i" };
    let mut args = vec![
        "-sSk",
        "--max-time",
        "10",
        "--suppress-connect-headers",
        mode,
    ];
    if let Some(connect_to) = connect_to {
        // Keep the URL hostname for HTTP Host/TLS SNI, but connect to the
        // selected box even when /etc/hosts is missing or contains an old IP.
        args.extend(["--connect-to", connect_to]);
    }
    args.push(url);
    let bytes = runner::run_cmd_bytes(curl, &args, runner::default_timeout().min(15)).await?;
    parse_http_response(&bytes, headers_only)
}

/// Probe one HTTP port: one response per URL, redirect check, vhost
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

    let target = url_host(&ctx.ip);
    let url = format!("{scheme}://{target}:{port}");
    let vhost_url = format!("{scheme}://{}:{port}", ctx.hostname);
    let vhost_connection = format!("{}:{port}:{target}:{port}", ctx.hostname);

    println!("{} Probing {}", "[*]".cyan(), url.yellow());

    let (response, vhost_response) =
        tokio::join!(fetch_response(&ctx.curl, &url, ctx.fast, None), async {
            if ctx.fast {
                None
            } else {
                Some(fetch_response(&ctx.curl, &vhost_url, false, Some(&vhost_connection)).await)
            }
        },);
    let response = match response {
        Ok(response) => response,
        Err(e) => {
            let detail = format!("probe {url} failed: {e}");
            println!("{} {detail}", "[!]".yellow());
            probe.errors.push(detail);
            return probe;
        }
    };
    probe.probe_ok = true;
    if !ctx.fast {
        probe.body_size = Some(response.body_size);
    }
    let status = response.status;
    let server = response.server;
    let title = response.title;
    probe.server = server.clone();
    if let Some(redir_host) = response.redirect_host
        && redir_host != ctx.ip
        && redir_host != ctx.hostname
        && hosts::is_valid_hostname(&redir_host)
    {
        probe.lines.push(format!("  redirect -> {redir_host}"));
        probe.redirect_hosts.push(redir_host);
    }
    let vhost_probe = match vhost_response {
        Some(Ok(response)) => Some((response.status, response.title)),
        Some(Err(e)) => {
            let detail = format!("vhost probe {vhost_url} failed: {e}");
            println!("{} {detail}", "[!]".yellow());
            probe.errors.push(detail);
            None
        }
        None => None,
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
    if !ctx.fast
        && !is_winrm_http_listener(port, &probe.server)
        && runner::command_exists(&ctx.whatweb).await
    {
        // Fingerprint the requested virtual host at the selected IP. Redirects
        // to other hosts must not route the scan to an obsolete hosts entry.
        let host_header = format!("Host: {}", ctx.hostname);
        match runner::run_cmd_timeout(
            &ctx.whatweb,
            &[
                "--no-errors",
                "--color=never",
                "--follow-redirect=same-site",
                "--header",
                &host_header,
                "-a",
                "3",
                &url,
            ],
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

/// Does every hosts entry for `hostname` point to the selected target?
///
/// feroxbuster and gobuster's vhost mode target the box *hostname*; when the
/// /etc/hosts entry failed (e.g. no passwordless sudo) the name doesn't resolve
/// and both brute-forces would die on DNS errors, so the caller falls back to
/// the bare IP (REVIEW.md "Niedrig": ferox/vhost IP fallback). ffuf needs no
/// such check: it already targets the IP and carries the domain in the Host
/// header. Checked against /etc/hosts rather than a real lookup so tests stay
/// offline.
async fn hostname_resolvable(hostname: &str, ip: &str) -> bool {
    let Ok(content) = tokio::fs::read_to_string("/etc/hosts").await else {
        return false;
    };
    hostname_points_to_target(&content, hostname, ip)
}

fn hostname_points_to_target(content: &str, hostname: &str, ip: &str) -> bool {
    let mut found = false;
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("");
        let mut fields = line.split_whitespace();
        let address = fields.next();
        if fields.any(|h| h.eq_ignore_ascii_case(hostname)) {
            if address != Some(ip) {
                return false;
            }
            found = true;
        }
    }
    found
}

/// Hit all HTTP ports with curl/whatweb (probes run concurrently per port).
/// Full mode additionally kicks off feroxbuster + vhost scans in background;
/// their raw output files land in a fresh subdirectory under `raw_dir`.
/// fast mode is headers-only.
pub async fn enumerate(
    ip: &str,
    hostname: &str,
    nmap_output: &str,
    raw_dir: &Path,
    report: &Report,
    scan_cfg: &ScanConfig,
) -> Result<Vec<WebTask>> {
    let http_ports = detect_http_ports(nmap_output);
    let mut background_tasks: Vec<WebTask> = Vec::new();

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

    // Probe ports concurrently — with several HTTP ports the strictly
    // serial per-port probes (curl + vhost + whatweb each) dominated this
    // phase's wall time (REVIEW.md finding 4). Results are collected and
    // processed in nmap port order below, so the report stays deterministic.
    let mut probes = JoinSet::new();
    let mut pending = http_ports.iter().enumerate();
    let mut results: Vec<PortProbe> = Vec::with_capacity(http_ports.len());
    loop {
        // Bound both subprocess pressure and retained HTTP bodies on hosts
        // exposing many HTTP ports; refill as soon as any probe finishes.
        while probes.len() < 8 {
            let Some((idx, (port, scheme))) = pending.next() else {
                break;
            };
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
        let Some(res) = probes.join_next().await else {
            break;
        };
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
        for hostname in &probe.redirect_hosts {
            report.add_hostname(hostname).await;
        }
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
        // Every run owns fresh paths, including when a tool fails before opening
        // its output. Previous evidence stays on disk but cannot be reused as
        // a successful result of the current command.
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let run_dir = raw_dir.join(format!("web-{}-{stamp}", std::process::id()));
        tokio::fs::create_dir(&run_dir).await?;
        // feroxbuster/gobuster run against the box hostname; if it never made
        // it into /etc/hosts (no passwordless sudo) the name doesn't resolve
        // and both brute-forces would die on DNS errors — hit the bare IP
        // instead (REVIEW.md "Niedrig")
        let brute_host = if hostname_resolvable(hostname, ip).await {
            hostname.to_string()
        } else {
            println!(
                "{} {hostname} has no unambiguous /etc/hosts mapping to {ip} — using the IP with a Host header",
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
            if is_winrm_http_listener(probe.port, &probe.server) {
                println!(
                    "{} Port {}: WinRM listener -- skipping directory and vhost scans",
                    "[*]".cyan(),
                    probe.port
                );
                continue;
            }
            let port = probe.port;
            let scheme = probe.scheme.clone();

            // dir brute
            if runner::command_exists(&ferox_bin).await
                && let Some(wl) = crate::config::find_wordlist(&scan_cfg.wordlists.dir_medium)
            {
                let ferox_out = run_dir.join(format!("ferox-{port}.txt"));
                let ferox_url = format!("{scheme}://{}:{port}", url_host(&brute_host));
                let host_header = (brute_host != hostname).then(|| format!("Host: {hostname}"));
                let ferox_out_str = ferox_out.to_string_lossy().to_string();
                let ferox_threads = scan_cfg.ferox_threads;
                let ferox_cmd = ferox_bin.clone();
                let exts = ferox_extensions(&probe.server);
                println!(
                    "{} feroxbuster on port {port} (background, -x {exts})...",
                    "[*]".cyan()
                );
                background_tasks.push(WebTask::spawn(ferox_out, WebResultKind::Directory, async move {
                    let threads = ferox_threads.to_string();
                    // ferox stops itself after 10m (--time-limit) and still
                    // flushes its results; the runner timeout sits 60s above
                    // that so the 300s default can't hard-kill it mid-flush
                    // (REVIEW.md finding 10)
                    let mut args = vec![
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
                        ];
                    if let Some(host_header) = &host_header {
                        args.extend(["-H", host_header]);
                    }
                    let result = runner::run_cmd_timeout(&ferox_cmd, &args, 660).await;
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
                let vhost_out = run_dir.join(format!("vhosts-{port}.txt"));
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
                    background_tasks.push(WebTask::spawn(
                        vhost_out,
                        WebResultKind::Vhost,
                        async move {
                            let ffuf_url =
                                format!("{scheme_owned}://{}:{port}", url_host(&ip_owned));
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
                        },
                    ));
                } else if runner::command_exists(&gobuster_bin).await {
                    let host_owned = brute_host.clone();
                    let hostname_owned = hostname.to_string();
                    let scheme_owned = scheme.clone();
                    let gobuster_cmd = gobuster_bin.clone();
                    println!(
                        "{} gobuster vhost scan on port {port} (background)...",
                        "[*]".cyan()
                    );
                    background_tasks.push(WebTask::spawn(
                        vhost_out,
                        WebResultKind::Vhost,
                        async move {
                            let gobuster_url =
                                format!("{scheme_owned}://{}:{port}", url_host(&host_owned));
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
                        },
                    ));
                }
            }
        }
    }

    if !web_info.is_empty() {
        report.section("WEB").await;
        for line in web_info.lines() {
            if !line.is_empty() {
                report.add_service("web", line).await;
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
    fn parses_headers_after_status_line() {
        let headers = "HTTP/1.1 302 Found\r\nsErVeR: Microsoft-IIS/10.0\r\nLocation: http://portal.example.htb/\r\n\r\n";
        let server = super::RE_HTTP_SERVER.captures(headers).unwrap();
        assert_eq!(&server[1], "Microsoft-IIS/10.0");
        assert_eq!(ferox_extensions(&server[1]), "asp,aspx,txt,html");
        assert_eq!(
            &super::RE_HTTP_LOCATION.captures(headers).unwrap()[1],
            "portal.example.htb"
        );
        assert!(
            super::RE_HTTP_SERVER
                .captures("HTTP/1.1 200 OK\r\nServer:\r\nOther: value\r\n")
                .is_none()
        );
    }

    #[test]
    fn combined_response_preserves_byte_count_and_final_headers() {
        let bytes = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n\xff\xfe\nServer: fake\n";
        let response = super::parse_http_response(bytes, false).unwrap();
        assert_eq!(response.status, "200");
        assert_eq!(response.server, "nginx");
        assert_eq!(response.body_size, b"\xff\xfe\nServer: fake\n".len() as u64);
        let response = super::parse_http_response(b"HTTP/1.1 200 OK\r\n\r\n", true).unwrap();
        assert_eq!(response.body_size, 0);
        assert!(response.title.is_empty());
        let response =
            super::parse_http_response(b"HTTP/1.1 200 OK\n\nServer: fake\r\n\r\nbody", false)
                .unwrap();
        assert!(response.server.is_empty());
        assert_eq!(response.body_size, b"Server: fake\r\n\r\nbody".len() as u64);
    }

    #[tokio::test]
    async fn fast_probe_uses_one_head_request_and_no_whatweb() {
        let tmp = TmpDir::new("web_fast_head");
        let cfg = stub_scan_cfg(true, tmp.path());
        let log = tmp.path().join("calls");
        std::fs::write(
            &cfg.tools.curl,
            format!(
                r#"#!/bin/sh
printf 'call\n' >> '{}'
for arg; do if [ "$arg" = '-I' ]; then
    printf 'HTTP/1.1 200 OK\r\nServer: test\r\n\r\n'
    exit 0
fi; done
exit 2
"#,
                log.display()
            ),
        )
        .unwrap();
        let ctx = super::ProbeCtx {
            ip: "192.0.2.1".into(),
            hostname: "test.htb".into(),
            fast: true,
            curl: cfg.tools.curl,
            whatweb: "/bin/false".into(),
        };
        let probe = super::probe_port(0, 80, "http", &ctx).await;
        assert!(probe.probe_ok);
        assert!(probe.errors.is_empty(), "{:?}", probe.errors);
        assert_eq!(std::fs::read_to_string(log).unwrap(), "call\n");
        assert_eq!(probe.body_size, None);
    }

    #[test]
    fn host_mapping_rejects_old_or_ambiguous_addresses() {
        let current = "  10.129.57.241 FIREFLOW.HTB # current box\n";
        assert!(super::hostname_points_to_target(
            current,
            "fireflow.htb",
            "10.129.57.241"
        ));
        assert!(!super::hostname_points_to_target(
            "10.129.1.1 fireflow.htb\n",
            "fireflow.htb",
            "10.129.57.241"
        ));
        assert!(!super::hostname_points_to_target(
            &format!("10.129.1.1 fireflow.htb\n{current}"),
            "fireflow.htb",
            "10.129.57.241"
        ));
        assert!(!super::hostname_points_to_target(
            "# 10.129.57.241 fireflow.htb\n",
            "fireflow.htb",
            "10.129.57.241"
        ));
    }

    #[tokio::test]
    async fn vhost_probe_pins_connection_to_selected_box() {
        let tmp = TmpDir::new("web_pinned_vhost");
        let cfg = stub_scan_cfg(false, tmp.path());
        std::fs::write(
            &cfg.tools.curl,
            r#"#!/bin/sh
pinned=false
vhost=false
for arg; do
  [ "$arg" = 'unresolved.htb:8443:192.0.2.1:8443' ] && pinned=true
  [ "$arg" = 'https://unresolved.htb:8443' ] && vhost=true
done
if $vhost; then
  $pinned || exit 6
  printf 'HTTP/1.1 200 OK\r\n\r\n<title>Selected box</title>'
else
  printf 'HTTP/1.1 301 Moved\r\n\r\n'
fi
"#,
        )
        .unwrap();
        let ctx = super::ProbeCtx {
            ip: "192.0.2.1".into(),
            hostname: "unresolved.htb".into(),
            fast: false,
            curl: cfg.tools.curl,
            whatweb: cfg.tools.whatweb,
        };
        let probe = super::probe_port(0, 8443, "https", &ctx).await;
        assert!(probe.errors.is_empty(), "{:?}", probe.errors);
        assert!(probe.lines.iter().any(|line| line.contains("Selected box")));
    }

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
            r#"#!/bin/sh
head=false
for arg; do [ "$arg" = '-I' ] && head=true; done
for last; do :; done
port=${last##*:}
printf 'HTTP/1.1 200 OK\r\nServer: stub-%s\r\n\r\n' "$port"
if [ "$head" = false ]; then printf '<title>stub-%s</title>\n' "$port"; fi
"#,
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
        for mut task in tasks {
            (&mut task.handle).await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn winrm_skips_web_brutes_but_keeps_headers_and_other_websites() {
        for (port, server, expected_tasks) in [
            (5985, "Microsoft-HTTPAPI/2.0", 0),
            (5986, "microsoft-httpapi/2.0", 0),
            (47001, "Microsoft-HTTPAPI/2.0", 0),
            (8080, "Microsoft-HTTPAPI/2.0", 1),
            (5985, "Microsoft-IIS/10.0", 1),
            (47001, "Microsoft-IIS/10.0", 1),
        ] {
            let tmp = TmpDir::new("web_winrm");
            let mut cfg = stub_scan_cfg(false, tmp.path());
            std::fs::write(
                &cfg.tools.curl,
                format!(
                    "#!/bin/sh\nprintf 'HTTP/1.1 404 Not Found\\r\\nServer: {server}\\r\\n\\r\\n'\n"
                ),
            )
            .unwrap();
            // Any unwanted WhatWeb invocation would become a report error.
            if expected_tasks == 0 {
                cfg.tools.whatweb = "/bin/false".into();
            }
            let report = Report::new();
            let nmap = format!("{port}/tcp open http");
            let tasks = enumerate("127.0.0.1", "testbox.htb", &nmap, tmp.path(), &report, &cfg)
                .await
                .unwrap();
            assert_eq!(tasks.len(), expected_tasks, "{server} on {port}");
            for mut task in tasks {
                (&mut task.handle).await.unwrap().unwrap();
            }
            assert!(report.errors().await.is_empty());
            assert!(
                report
                    .lines()
                    .await
                    .iter()
                    .any(|line| line.contains(server))
            );
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
        for mut task in tasks {
            (&mut task.handle).await.unwrap().unwrap();
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
        let mut task = tasks.into_iter().next().unwrap();
        (&mut task.handle).await.unwrap().unwrap();
        // and the partial results file is there for process_ferox_results
        let ferox_out = std::fs::read_to_string(&task.output).unwrap();
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
        let mut task = tasks.into_iter().next().unwrap();
        assert!((&mut task.handle).await.unwrap().is_err());
    }

    #[tokio::test]
    async fn repeated_scan_cannot_reuse_old_results_on_failure() {
        let tmp = TmpDir::new("web_repeat");
        let cfg = stub_scan_cfg_with_ferox(tmp.path(), FEROX_STUB_PARTIAL);
        let mut first = enumerate(
            "127.0.0.1",
            "testbox.htb",
            "8080/tcp open http",
            tmp.path(),
            &Report::new(),
            &cfg,
        )
        .await
        .unwrap()
        .remove(0);
        (&mut first.handle).await.unwrap().unwrap();
        let cfg = stub_scan_cfg_with_ferox(tmp.path(), FEROX_STUB_NO_HITS);
        let mut second = enumerate(
            "127.0.0.1",
            "testbox.htb",
            "8080/tcp open http",
            tmp.path(),
            &Report::new(),
            &cfg,
        )
        .await
        .unwrap()
        .remove(0);
        assert!((&mut second.handle).await.unwrap().is_err());
        assert_ne!(first.output, second.output);
        assert!(first.output.exists(), "previous evidence is preserved");
        assert!(
            !second.output.exists(),
            "failed command has no current evidence"
        );
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
