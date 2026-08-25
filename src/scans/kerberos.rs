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
    // 10-minute floor, and the default wordlist is now names.txt (~10k
    // entries), which finishes well inside it — an 8.3M-entry list like
    // xato-net-10-million can never make it and only ever burned the timeout
    // (REVIEW.md finding 10)
    let output = runner::run_cmd_timeout(
        &kerbrute,
        &["userenum", "-d", kerb_domain, "--dc", ip, &wl],
        runner::default_timeout().max(600),
    )
    .await?;

    let valid_lines: Vec<&str> = output.lines().filter(|l| l.contains("VALID")).collect();

    if !valid_lines.is_empty() {
        println!("{} Valid users found!", "[+]".green());
        for line in &valid_lines {
            println!("{}", line.green().bold());
        }
        let text = valid_lines.join("\n");
        report.add(&text).await;
    } else {
        println!("{} No valid users found", "[!]".yellow());
        report.add("  (no valid users)").await;
    }

    Ok(())
}
