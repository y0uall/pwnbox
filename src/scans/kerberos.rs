use anyhow::Result;
use colored::Colorize;

use crate::config::{ScanConfig, find_wordlist_or_warn};
use crate::report::Report;
use crate::runner;

/// Run kerbrute userenum against the DC.
pub async fn enumerate(
    ip: &str,
    hostname: &str,
    domain: Option<&str>,
    scan_cfg: &ScanConfig,
    report: &Report,
) -> Result<()> {
    report.section("KERBEROS").await;

    let kerbrute = scan_cfg.tool("kerbrute");
    if !runner::command_exists(&kerbrute).await {
        println!(
            "{} kerbrute not found -- skipping Kerberos user enum",
            "[!]".yellow()
        );
        report
            .add("  (kerbrute not installed -- install: go install github.com/ropnop/kerbrute@latest)")
            .await;
        return Ok(());
    }

    let Some(wl) = find_wordlist_or_warn(&scan_cfg.wordlists.usernames, "kerberos usernames")
    else {
        return Ok(());
    };

    let kerb_domain =
        domain.unwrap_or_else(|| hostname.split_once('.').map(|x| x.1).unwrap_or("htb"));

    println!("{} kerbrute userenum...", "[*]".cyan());
    let output =
        runner::run_cmd(&kerbrute, &["userenum", "-d", kerb_domain, "--dc", ip, &wl]).await?;

    let valid_lines: Vec<&str> = output.lines().filter(|l| l.contains("VALID")).collect();

    if !valid_lines.is_empty() {
        println!("{} Valid users found!", "[+]".green());
        let text = valid_lines.join("\n");
        println!("{text}");
        report.add(&text).await;
    } else {
        println!("{} No valid users found", "[!]".yellow());
        report.add("  (no valid users)").await;
    }

    Ok(())
}
