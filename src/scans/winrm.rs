use anyhow::Result;
use colored::Colorize;

use crate::config::ScanConfig;
use crate::report::Report;
use crate::runner;

/// Poke WinRM to see if it's alive.
///
/// Probes with POST (WinRM's SOAP method): without credentials a live listener
/// answers 401, and an empty envelope gets 400/500 — all prove the endpoint
/// exists. The old GET probe turned the 404/405 of a perfectly alive
/// Microsoft-HTTPAPI listener into a false "not responding".
pub async fn check(ip: &str, port: u16, scan_cfg: &ScanConfig, report: &Report) -> Result<()> {
    report.section("WINRM").await;

    let scheme = if port == 5986 { "https" } else { "http" };
    let url = format!("{scheme}://{ip}:{port}/wsman");

    println!("{} Checking WinRM at {}...", "[*]".cyan(), url.yellow());

    let (probe_ok, output) = runner::run_cmd_status(
        &scan_cfg.tool("curl"),
        &[
            "-sk",
            "--max-time",
            "5",
            "-X",
            "POST",
            "-d",
            "",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            &url,
        ],
        15,
    )
    .await?;

    if !probe_ok {
        anyhow::bail!("WinRM curl probe failed: {}", output.trim());
    }
    let status = output.trim();
    if matches!(status, "200" | "400" | "401" | "403" | "405" | "500") {
        println!("{} WinRM is active (HTTP {status})", "[+]".green());
        report
            .add_service(
                "winrm",
                &format!("  WinRM active on port {port} (HTTP {status})"),
            )
            .await;
        report
            .add_service("winrm", "  → Try: evil-winrm -i <ip> -u <user> -p <pass>")
            .await;

        if runner::command_exists("evil-winrm").await {
            println!(
                "{} evil-winrm is available — use with found creds",
                "[*]".cyan()
            );
        }
    } else {
        println!("{} WinRM not responding (HTTP {status})", "[!]".yellow());
        report
            .add_service(
                "winrm",
                &format!("  WinRM port {port}: not responding (HTTP {status})"),
            )
            .await;
    }

    Ok(())
}
