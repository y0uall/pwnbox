use anyhow::Result;
use colored::Colorize;

use crate::config::ScanConfig;
use crate::report::Report;
use crate::runner;

/// Throw everything we have at SMB: enum4linux, smbclient, cme/nxc.
pub async fn enumerate(ip: &str, scan_cfg: &ScanConfig, report: &Report) -> Result<()> {
    report.section("SMB").await;

    // enum4linux-ng gives the most info
    let enum4linux = scan_cfg.tool("enum4linux-ng");
    if runner::command_exists(&enum4linux).await {
        println!("{} enum4linux-ng...", "[*]".cyan());
        let output = match runner::run_cmd_timeout(&enum4linux, &["-A", ip], 120).await {
            Ok(output) => output,
            Err(e) => {
                println!("{} enum4linux-ng failed: {e}", "[!]".yellow());
                report.add_error("SMB", &e.to_string()).await;
                String::new()
            }
        };

        if !output.is_empty() {
            // pull out the interesting bits
            let key_lines: Vec<&str> = output
                .lines()
                .filter(|l| {
                    let lower = l.to_lowercase();
                    lower.contains("share")
                        || lower.contains("user")
                        || lower.contains("os info")
                        || lower.contains("domain")
                        || lower.contains("[+]")
                        || lower.contains("[*]")
                })
                .take(40)
                .collect();

            if !key_lines.is_empty() {
                let text = key_lines.join("\n");
                println!("{text}");
                report.add(&text).await;
            }
        }
    }

    // smbclient: list shares with null session
    let smbclient = scan_cfg.tool("smbclient");
    if runner::command_exists(&smbclient).await {
        println!("{} Listing shares (null session)...", "[*]".cyan());
        let (success, output) = runner::run_cmd_status(
            &smbclient,
            &["-N", "-L", &format!("//{ip}")],
            runner::default_timeout(),
        )
        .await?;

        if success && output.contains("Sharename") {
            println!("{output}");
            report.add(&output).await;
        } else if output.contains("NT_STATUS_ACCESS_DENIED")
            || output.contains("NT_STATUS_LOGON_FAILURE")
        {
            println!("{} No shares via null session", "[!]".yellow());
            report.add("  (null session denied)").await;
        } else {
            let detail = format!("smbclient failed: {}", output.trim());
            println!("{} {detail}", "[!]".yellow());
            report.add_error("SMB", &detail).await;
        }
    }

    // cme/nxc for share enumeration
    let cme = scan_cfg.tool("crackmapexec");
    if runner::command_exists(&cme).await {
        println!("{} CrackMapExec SMB...", "[*]".cyan());
        match runner::run_cmd(&cme, &["smb", ip, "--shares", "-u", "", "-p", ""]).await {
            Ok(output) if !output.is_empty() => {
                println!("{output}");
                report.add(&output).await;
            }
            Ok(_) => {}
            Err(e) => {
                println!("{} CrackMapExec failed: {e}", "[!]".yellow());
                report.add_error("SMB", &e.to_string()).await;
            }
        }
    } else if runner::command_exists("netexec").await {
        println!("{} NetExec SMB...", "[*]".cyan());
        match runner::run_cmd("netexec", &["smb", ip, "--shares", "-u", "", "-p", ""]).await {
            Ok(output) if !output.is_empty() => {
                println!("{output}");
                report.add(&output).await;
            }
            Ok(_) => {}
            Err(e) => {
                println!("{} NetExec failed: {e}", "[!]".yellow());
                report.add_error("SMB", &e.to_string()).await;
            }
        }
    }

    Ok(())
}
