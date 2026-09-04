use std::path::Path;
use std::sync::LazyLock;

use anyhow::Result;
use colored::Colorize;
use regex::Regex;

use crate::config::ScanConfig;
use crate::hosts;
use crate::report::Report;
use crate::runner;
use crate::scans::port_detail_lines;

// Precompiled once — these run over every nmap TCP result, sometimes repeatedly.
static RE_RUSTSCAN_PORTS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\[([0-9,]+)\]").unwrap());
static RE_CVE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bCVE-\d{4}-\d+\b").unwrap());
static RE_SCRIPT_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\|[_ ]([a-z][a-z0-9_-]*):[ \t]*(.*)$").unwrap());
// Generic hostname extraction: no longer limited to *.htb. Invalid or local-only
// names are filtered out by `hosts::is_valid_hostname` before /etc/hosts is touched.
static RE_SSL_HOST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:commonName\s*=\s*|DNS:)([a-zA-Z0-9._-]+)").unwrap());
static RE_REDIRECT_HOST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"redirect to https?://([a-zA-Z0-9._-]+)").unwrap());
static RE_SERVICE_HOST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Service Info:.*Host:\s*([a-zA-Z0-9._-]+)").unwrap());
static RE_CERT_CN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Subject:.*?CN\s*=\s*([a-zA-Z0-9._-]+)").unwrap());
static RE_CERT_SAN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"DNS:([a-zA-Z0-9._-]+)").unwrap());

/// Rustscan for fast port discovery, then nmap -sC -sV on the results.
/// With `resume`, reuses cached nmap output if available.
/// Raw nmap output goes to `raw_dir` (the output dir's `raw/` subdirectory).
pub async fn scan(
    ip: &str,
    raw_dir: &Path,
    report: &Report,
    resume: bool,
    scan_cfg: &ScanConfig,
) -> Result<String> {
    let nmap_path = raw_dir.join("nmap-tcp.txt");

    // check for cached results first
    if resume && nmap_path.exists() {
        let cached = tokio::fs::read_to_string(&nmap_path).await?;
        println!(
            "{} Resuming: using cached {}",
            "[*]".cyan(),
            nmap_path.display().to_string().yellow()
        );
        report.section("TCP").await;
        let port_lines = port_detail_lines(&cached);
        if port_lines.is_empty() {
            report.add("  (no results)").await;
        } else {
            for line in &port_lines {
                report.add(line).await;
            }
        }
        return Ok(cached);
    }

    let nmap_output;
    let nmap = scan_cfg.tool("nmap");
    let rustscan = scan_cfg.tool("rustscan");
    let svc_timeout = runner::default_timeout();

    if runner::command_exists(&rustscan).await {
        let raw = match runner::run_cmd(&rustscan, &["-a", ip, "--ulimit", "5000", "-g"]).await {
            Ok(output) => output,
            Err(e) => {
                println!(
                    "{} RustScan failed: {e} — falling back to nmap",
                    "[!]".yellow()
                );
                String::new()
            }
        };

        // rustscan -g gives "IP -> [port1,port2,...]"
        let ports = if let Some(caps) = RE_RUSTSCAN_PORTS.captures(&raw) {
            caps[1].to_string()
        } else {
            String::new()
        };

        if !ports.is_empty() {
            println!("{} Open ports: {}", "[+]".green(), ports.cyan());
            println!(
                "{} {}",
                "[2b/6]".green(),
                "Nmap service scan on open ports...".yellow()
            );
            nmap_output = runner::run_cmd_tee(
                &nmap,
                &[
                    "-Pn",
                    "-sC",
                    "-sV",
                    "--min-rate",
                    "1000",
                    "--version-intensity",
                    "2",
                    "-p",
                    &ports,
                    ip,
                ],
                svc_timeout,
            )
            .await?;
        } else {
            println!(
                "{} RustScan found no open ports, falling back to nmap top 1000",
                "[!]".yellow()
            );
            nmap_output = runner::run_cmd_tee(
                &nmap,
                &["-Pn", "-sC", "-sV", "--min-rate", "1000", ip],
                svc_timeout,
            )
            .await?;
        }
    } else {
        println!(
            "{} RustScan not found, using nmap full scan",
            "[!]".yellow()
        );
        nmap_output = runner::run_cmd_tee(
            &nmap,
            &["-Pn", "-sC", "-sV", "-p-", "--min-rate", "5000", ip],
            svc_timeout.max(900), // full port scan needs at least 15 min
        )
        .await?;
    }

    // save raw output for later reference
    tokio::fs::write(&nmap_path, &nmap_output).await?;
    println!(
        "{} Raw nmap TCP -> {}",
        "[+]".green(),
        nmap_path.display().to_string().yellow()
    );

    // add port lines + attached script output to the text report
    report.section("TCP").await;
    let port_lines = port_detail_lines(&nmap_output);
    if port_lines.is_empty() {
        report.add("  (no results)").await;
    } else {
        for line in &port_lines {
            report.add(line).await;
        }
    }

    Ok(nmap_output)
}

/// Run nmap --script vuln on open ports. Caches results for resume.
/// Raw output goes to `raw_dir` (the output dir's `raw/` subdirectory).
pub async fn vuln_scan(
    ip: &str,
    ports: &str,
    raw_dir: &Path,
    report: &Report,
    resume: bool,
    scan_cfg: &ScanConfig,
) -> Result<()> {
    let vuln_path = raw_dir.join("nmap-vuln.txt");

    let output = if resume && vuln_path.exists() {
        let cached = tokio::fs::read_to_string(&vuln_path).await?;
        println!(
            "{} Resuming: using cached {}",
            "[*]".cyan(),
            vuln_path.display().to_string().yellow()
        );
        cached
    } else {
        println!(
            "{} Running nmap vuln scripts on ports {}...",
            "[*]".cyan(),
            ports.cyan()
        );
        let result = runner::run_cmd_timeout(
            &scan_cfg.tool("nmap"),
            &[
                "-Pn",
                "--script",
                "vuln",
                "--script-timeout",
                "30s",
                "-p",
                ports,
                ip,
            ],
            runner::default_timeout().max(120),
        )
        .await?;
        // only cache real output — don't clobber a previous good run with an
        // empty file when the rescan fails/times out
        if !result.is_empty() {
            tokio::fs::write(&vuln_path, &result).await?;
        }
        result
    };

    if output.is_empty() {
        return Ok(());
    }

    report.section("VULN SCAN").await;

    let vulns = parse_vulns(&output);

    if vulns.is_empty() {
        println!(
            "{} No positive vulnerability findings reported by nmap scripts",
            "[!]".yellow()
        );
        report
            .add("  (no positive nmap vulnerability findings)")
            .await;
    } else {
        println!(
            "{} Nmap reported {} potential vulnerability finding(s) — verify manually",
            "[!]".yellow().bold(),
            vulns.len()
        );
        for v in &vulns {
            let finding = format!("nmap (unverified): {v}");
            println!("  {} {}", "!!".yellow().bold(), finding.yellow());
            report.add(&format!("  !! {finding}")).await;
            report.add_vuln(&finding).await;
        }
    }

    Ok(())
}

/// True for nmap vuln-script verdicts meaning "not affected" — matched
/// case-insensitively because script authors vary their casing.
fn is_negative_verdict(line: &str) -> bool {
    let upper = line.to_ascii_uppercase();
    upper.contains("NOT VULNERABLE") || upper.contains("LIKELY CLEAN")
}

/// Parse `nmap --script vuln` output into finding lines.
///
/// nmap prints a full block even for negative results, and both the block
/// header ("VULNERABLE:") and its State line contain the keyword — a plain
/// `contains("VULNERABLE")` therefore false-positives on "State: NOT
/// VULNERABLE" (REVIEW.md finding 12). A block is dropped when any of its
/// lines carries a negative verdict.
fn parse_vulns(output: &str) -> Vec<String> {
    #[derive(Default)]
    struct Finding {
        positive: bool,
        negative: bool,
        title: String,
        cves: Vec<String>,
    }

    fn flush(finding: &mut Finding, scope: &str, script: &str, vulns: &mut Vec<String>) {
        if finding.positive && !finding.negative {
            let context = [scope, script]
                .into_iter()
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            let mut text = if context.is_empty() {
                "VULNERABLE".to_string()
            } else {
                format!("{context}: VULNERABLE")
            };
            if !finding.title.is_empty() {
                text.push_str(&format!(" — {}", finding.title));
            }
            for cve in &finding.cves {
                if !text.to_ascii_uppercase().contains(cve) {
                    text.push_str(&format!(" ({cve})"));
                }
            }
            if !vulns.contains(&text) {
                vulns.push(text);
            }
        }
        *finding = Finding::default();
    }

    let mut vulns = Vec::new();
    let mut finding = Finding::default();
    let mut scope = String::new();
    let mut script = String::new();
    for line in output.lines() {
        if !line.starts_with('|') {
            flush(&mut finding, &scope, &script, &mut vulns);
            script.clear();
            scope = if super::RE_PORT_LINE.is_match(line) {
                line.split_whitespace().next().unwrap_or("").to_string()
            } else {
                String::new()
            };
            continue;
        }
        let header = RE_SCRIPT_HEADER.captures(line);
        let body = if let Some(header) = &header {
            flush(&mut finding, &scope, &script, &mut vulns);
            script = header[1].to_string();
            header.get(2).map_or("", |body| body.as_str()).trim()
        } else {
            line.trim_start_matches('|').trim_start_matches('_').trim()
        };
        // Multiple findings may share one script. State lines update the
        // verdict without replacing the preceding human-readable title.
        if body.eq_ignore_ascii_case("VULNERABLE:") && finding.positive {
            flush(&mut finding, &scope, &script, &mut vulns);
        }
        if is_negative_verdict(body) {
            finding.negative = true;
        } else if body.to_ascii_uppercase().contains("VULNERABLE") {
            finding.positive = true;
        } else if finding.positive
            && finding.title.is_empty()
            && !body.is_empty()
            && !body.contains(':')
            && !RE_CVE.is_match(body)
        {
            finding.title = body.to_string();
        }
        // IDs and reference URLs frequently repeat the same CVE, including
        // on the closing |_ line. Preserve all distinct IDs exactly once.
        for cve in RE_CVE.find_iter(body) {
            let cve = cve.as_str().to_ascii_uppercase();
            if !finding.cves.contains(&cve) {
                finding.cves.push(cve);
            }
        }
        if line.starts_with("|_") {
            flush(&mut finding, &scope, &script, &mut vulns);
            script.clear();
        }
    }
    flush(&mut finding, &scope, &script, &mut vulns);
    vulns
}

/// Pull hostnames from nmap output: SSL cert CN/SAN, redirects, service info.
pub async fn extract_hostnames(nmap_output: &str, ip: &str) -> Result<Vec<String>> {
    let mut hosts_found: Vec<String> = Vec::new();

    for cap in RE_SSL_HOST.captures_iter(nmap_output) {
        let name = cap[1].to_lowercase();
        if !hosts_found.contains(&name) {
            hosts_found.push(name);
        }
    }

    for cap in RE_REDIRECT_HOST.captures_iter(nmap_output) {
        let name = cap[1].to_lowercase();
        if !hosts_found.contains(&name) {
            hosts_found.push(name);
        }
    }

    for cap in RE_SERVICE_HOST.captures_iter(nmap_output) {
        let name = cap[1].to_lowercase();
        if !hosts_found.contains(&name) {
            hosts_found.push(name);
        }
    }

    if !hosts_found.is_empty() {
        println!("{} Found hostnames in nmap output:", "[+]".green());
        for h in &hosts_found {
            println!("    {}", h.cyan());
        }
        hosts::add_hosts(ip, &hosts_found).await?;
    } else {
        println!("{} No additional hostnames in nmap output", "[!]".yellow());
    }

    Ok(hosts_found)
}

/// Use openssl s_client to grab CN/SAN from SSL certs on HTTPS ports.
pub async fn ssl_hostnames(
    ip: &str,
    ports: &[u16],
    known_hosts: &[String],
    report: &Report,
) -> Result<Vec<String>> {
    let mut new_hosts: Vec<String> = Vec::new();

    for port in ports {
        // This is the one place we still shell out (two piped openssl invocations).
        // It's safe: `ip` is validated as an IP/hostname at startup and `port` is a
        // u16, so neither can carry shell metacharacters.
        let output = match runner::run_cmd_timeout(
            "bash",
            &["-c", &format!(
                "echo | openssl s_client -connect {ip}:{port} -servername {ip} 2>/dev/null | openssl x509 -noout -text 2>/dev/null"
            )],
            10,
        )
        .await
        {
            Ok(output) => output,
            Err(e) => {
                let detail = format!("TLS certificate probe on port {port} failed: {e}");
                println!("{} {detail}", "[!]".yellow());
                report.add_error("TLS", &detail).await;
                continue;
            }
        };

        if output.is_empty() {
            continue;
        }

        if let Some(cap) = RE_CERT_CN.captures(&output) {
            let name = cap[1].to_lowercase();
            if !name.contains('*')
                && name.contains('.')
                && !known_hosts.contains(&name)
                && !new_hosts.contains(&name)
            {
                new_hosts.push(name);
            }
        }

        for cap in RE_CERT_SAN.captures_iter(&output) {
            let name = cap[1].to_lowercase();
            if !name.contains('*')
                && name.contains('.')
                && !known_hosts.contains(&name)
                && !new_hosts.contains(&name)
            {
                new_hosts.push(name);
            }
        }
    }

    if !new_hosts.is_empty() {
        println!("{} SSL cert hostnames discovered:", "[+]".green());
        for h in &new_hosts {
            println!("    {}", h.cyan());
            report.add_hostname(h).await;
        }
        hosts::add_hosts(ip, &new_hosts).await?;
    }

    Ok(new_hosts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssl_host_regex_matches_non_htb_domains() {
        let output = "commonName=dc01.corp.local\nDNS:web.inlanefreight.local\nDNS:host.htb";
        let hosts: Vec<String> = RE_SSL_HOST
            .captures_iter(output)
            .map(|c| c[1].to_lowercase())
            .collect();
        assert!(hosts.contains(&"dc01.corp.local".to_string()));
        assert!(hosts.contains(&"web.inlanefreight.local".to_string()));
        assert!(hosts.contains(&"host.htb".to_string()));
    }

    #[test]
    fn vuln_block_parsing_extracts_cve() {
        let output = "\n| VULNERABLE:
|   SMBv1 enabled
|     State: VULNERABLE
|     CVE-2017-0144
|_
";
        let vulns = parse_vulns(output);
        assert_eq!(vulns.len(), 1);
        assert!(vulns[0].contains("VULNERABLE"));
        assert!(vulns[0].contains("CVE-2017-0144"));
    }

    #[test]
    fn vuln_findings_drop_the_pipe_prefix() {
        // Human-readable findings must not carry nmap's raw pipe prefix.
        let output = "\
| http-vuln-cve2011-3192:
|   VULNERABLE:
|   Apache HTTP Server Range DoS vulnerability
|     State: VULNERABLE (CVE-2011-3192)
|_
";
        let vulns = parse_vulns(output);
        assert_eq!(vulns.len(), 1);
        assert!(!vulns[0].starts_with('|'), "raw pipe leaked: {}", vulns[0]);
    }

    #[test]
    fn vuln_parser_preserves_live_scan_context_and_deduplicates_cves() {
        let output = "443/tcp open https
| http-vuln-cve2011-3192:
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs: CVE:CVE-2011-3192 BID:49303
|     References:
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192";
        let findings = parse_vulns(output);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].contains("443/tcp http-vuln-cve2011-3192"));
        assert!(findings[0].contains("Apache byterange filter DoS"));
        assert_eq!(findings[0].matches("CVE-2011-3192").count(), 1);
    }

    #[test]
    fn vuln_parser_keeps_last_and_inline_findings() {
        let output = "22/tcp open ssh\n|_test-script: VULNERABLE CVE-2025-1234\n443/tcp open https\n| other-script:\n|   VULNERABLE:\n|   Fixture flaw\n|     State: VULNERABLE\n|     IDs: CVE-2025-5678 CVE-2025-5679";
        let findings = parse_vulns(output);
        assert_eq!(findings.len(), 2);
        assert!(findings[0].contains("22/tcp test-script"));
        assert!(findings[0].contains("CVE-2025-1234"));
        assert!(findings[1].contains("443/tcp other-script"));
        assert!(findings[1].contains("CVE-2025-5678"));
        assert!(findings[1].contains("CVE-2025-5679"));
    }

    /// REVIEW.md finding 12: nmap prints full blocks for negative results too —
    /// "State: NOT VULNERABLE" / "LIKELY CLEAN" must not become findings.
    #[test]
    fn vuln_parser_ignores_negative_verdicts() {
        let output = "\
| ssl-heartbleed:
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in OpenSSL
|     State: NOT VULNERABLE
|_
|_smb-vuln-ms17-010: target NOT VULNERABLE
| tls-poodle:
|   VULNERABLE:
|   SSL POODLE information leak
|     State: Likely clean
|_
";
        assert!(parse_vulns(output).is_empty());
    }

    #[test]
    fn vuln_parser_keeps_positive_block_next_to_negative_one() {
        let output = "\
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     CVE-2017-0144
|_
| ssl-heartbleed:
|   VULNERABLE:
|   The Heartbleed Bug
|     State: NOT VULNERABLE
|_
";
        let vulns = parse_vulns(output);
        assert_eq!(vulns.len(), 1);
        assert!(vulns[0].contains("CVE-2017-0144"));
    }
}
