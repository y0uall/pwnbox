use anyhow::{Result, bail};
use colored::Colorize;

use crate::config::ScanConfig;
use crate::report::Report;
use crate::runner;

/// Try rpcclient null session + impacket-rpcdump.
pub async fn enumerate(ip: &str, scan_cfg: &ScanConfig, report: &Report) -> Result<()> {
    report.section("RPC").await;

    if runner::command_exists("rpcclient").await {
        println!("{} rpcclient null session...", "[*]".cyan());
        let (success, output) = runner::run_cmd_status(
            "rpcclient",
            &["-U", "", "-N", ip, "-c", "enumdomusers;enumdomgroups"],
            runner::default_timeout(),
        )
        .await?;

        if success {
            println!("{} RPC null session successful!", "[+]".green());
            println!("{output}");
            report.add(&output).await;
        } else if output.contains("NT_STATUS_ACCESS_DENIED")
            || output.contains("NT_STATUS_LOGON_FAILURE")
        {
            println!("{} RPC null session denied", "[!]".yellow());
            report.add("  (null session denied)").await;
        } else {
            bail!("rpcclient failed: {}", output.trim());
        }
    }

    let rpcdump = scan_cfg.tool("impacket-rpcdump");
    if runner::command_exists(&rpcdump).await {
        println!("{} impacket-rpcdump...", "[*]".cyan());
        let output = runner::run_cmd(&rpcdump, &[ip]).await?;

        // only keep the interesting lines, don't spam the terminal
        let filtered: Vec<&str> = output
            .lines()
            .filter(|l| {
                let lower = l.to_lowercase();
                lower.contains("protocol") || lower.contains("endpoint")
            })
            .take(20)
            .collect();

        if !filtered.is_empty() {
            let text = filtered.join("\n");
            println!("{text}");
            report.add(&text).await;
        }
    }

    Ok(())
}
