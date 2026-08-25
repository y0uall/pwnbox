use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use crate::config::ScanConfig;
use crate::report::Report;
use crate::runner;
use crate::scans::port_detail_lines;

/// UDP top-100 scan via sudo nmap. Caches results for resume.
/// Raw nmap output goes to `raw_dir` (the output dir's `raw/` subdirectory).
pub async fn scan(
    ip: &str,
    raw_dir: &Path,
    report: &Report,
    resume: bool,
    scan_cfg: &ScanConfig,
) -> Result<String> {
    let nmap_path = raw_dir.join("nmap-udp.txt");

    if resume && nmap_path.exists() {
        let cached = tokio::fs::read_to_string(&nmap_path).await?;
        println!(
            "{} Resuming: using cached {}",
            "[*]".cyan(),
            nmap_path.display().to_string().yellow()
        );
        report.section("UDP").await;
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

    if !runner::has_sudo().await {
        println!(
            "{} No passwordless sudo -- skipping UDP scan",
            "[!]".yellow()
        );
        return Ok(String::new());
    }

    println!("{} UDP scan started", "[+]".green());

    // A UDP top-100 -sV sweep routinely runs past the default 300s because of
    // ICMP rate-limiting on closed ports, so give it a longer floor — otherwise
    // it gets killed mid-scan and the results are truncated. It runs in the
    // background, so a higher ceiling doesn't block the rest of the pipeline.
    let udp_timeout = runner::default_timeout().max(600);
    let output = runner::run_sudo_cmd_timeout(
        &scan_cfg.tool("nmap"),
        &[
            "-Pn",
            "-sU",
            "--top-ports",
            "100",
            "-sV",
            "--version-intensity",
            "0",
            ip,
        ],
        udp_timeout,
    )
    .await?;

    tokio::fs::write(&nmap_path, &output).await?;
    println!(
        "{} Raw nmap UDP -> {}",
        "[+]".green(),
        nmap_path.display().to_string().yellow()
    );

    report.section("UDP").await;
    let port_lines = port_detail_lines(&output);
    if port_lines.is_empty() {
        report.add("  (no results)").await;
    } else {
        for line in &port_lines {
            report.add(line).await;
        }
    }

    Ok(output)
}
