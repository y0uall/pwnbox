use anyhow::Result;
use colored::Colorize;

use crate::config::ScanConfig;
use crate::report::Report;
use crate::runner;

/// Poke WinRM to see if it's alive.
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
    if status == "401" || status == "200" || status == "403" {
        println!("{} WinRM is active (HTTP {status})", "[+]".green());
        report
            .add(&format!("  WinRM active on port {port} (HTTP {status})"))
            .await;
        report
            .add("  → Try: evil-winrm -i <ip> -u <user> -p <pass>")
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
            .add(&format!("  WinRM port {port}: not responding"))
            .await;
    }

    Ok(())
}
