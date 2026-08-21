use anyhow::{Result, bail};
use colored::Colorize;

use crate::config::ScanConfig;
use crate::report::Report;
use crate::runner;

/// Check for NFS exports via showmount.
pub async fn enumerate(ip: &str, scan_cfg: &ScanConfig, report: &Report) -> Result<()> {
    report.section("NFS").await;

    let showmount = scan_cfg.tool("showmount");
    if !runner::command_exists(&showmount).await {
        println!(
            "{} showmount not found -- skipping NFS enum",
            "[!]".yellow()
        );
        report.add("  (showmount not installed)").await;
        return Ok(());
    }

    println!("{} showmount -e {ip}...", "[*]".cyan());
    let (success, output) =
        runner::run_cmd_status(&showmount, &["-e", ip], runner::default_timeout()).await?;
    if !success {
        bail!("showmount failed: {}", output.trim());
    }

    let exports: Vec<&str> = output
        .lines()
        .filter(|line| line.trim_start().starts_with('/'))
        .collect();
    if !exports.is_empty() {
        println!("{} NFS exports found!", "[+]".green());
        let text = exports.join("\n");
        println!("{text}");
        report.add(&text).await;
    } else {
        println!("{} No NFS exports", "[!]".yellow());
        report.add("  (no exports)").await;
    }

    Ok(())
}
