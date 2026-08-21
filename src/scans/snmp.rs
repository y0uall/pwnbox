use anyhow::Result;
use colored::Colorize;

use crate::config::{ScanConfig, find_wordlist};
use crate::report::Report;
use crate::runner;

const COMMUNITY_STRINGS: &[&str] = &["public", "private", "community", "manager", "snmpd"];

fn contains_snmp_data(output: &str) -> bool {
    output.lines().any(|line| line.contains(" = "))
}

fn is_expected_negative(output: &str) -> bool {
    let output = output.to_ascii_lowercase();
    output.contains("timeout")
        || output.contains("no response")
        || output.contains("authentication failure")
        || output.contains("authorization error")
        || output.contains("unknown user name")
}
/// Try common SNMP community strings via snmpwalk.
pub async fn check(ip: &str, scan_cfg: &ScanConfig, report: &Report) -> Result<()> {
    report.section("SNMP").await;

    let snmpwalk = scan_cfg.tool("snmpwalk");
    if !runner::command_exists(&snmpwalk).await {
        println!("{} snmpwalk not found — skipping SNMP enum", "[!]".yellow());
        report.add("  (snmpwalk not installed)").await;
        return Ok(());
    }

    let mut found_community = false;

    for community in COMMUNITY_STRINGS {
        println!(
            "{} Trying community string '{}'...",
            "[*]".cyan(),
            community.yellow()
        );

        let (success, output) = runner::run_cmd_status(
            &snmpwalk,
            &["-v2c", "-c", community, "-t", "3", "-r", "1", ip],
            15,
        )
        .await?;

        let lines: Vec<&str> = output.lines().take(50).collect();

        if success && contains_snmp_data(&output) {
            println!(
                "{} SNMP community '{}' works!",
                "[+]".green().bold(),
                community
            );
            found_community = true;
            report
                .add(&format!("  Community string: {community}"))
                .await;
            let text = lines.join("\n");
            println!("{text}");
            report.add(&text).await;
            break;
        } else if !success && !is_expected_negative(&output) {
            let detail = output.lines().take(3).collect::<Vec<_>>().join(" ");
            let detail = if detail.trim().is_empty() {
                format!("snmpwalk failed for community '{community}' without output")
            } else {
                format!("snmpwalk failed for community '{community}': {detail}")
            };
            report.add_error("SNMP", &detail).await;
        }
    }

    if !found_community {
        println!("{} No SNMP community strings worked", "[!]".yellow());
        report.add("  (no community strings worked)").await;

        // hint: try onesixtyone for a bigger bruteforce
        if runner::command_exists("onesixtyone").await {
            if let Some(wl) = find_wordlist(&scan_cfg.wordlists.snmp) {
                println!("{} Try: onesixtyone -c {wl} {ip}", "[*]".cyan());
            } else {
                println!(
                    "{} Try: onesixtyone -c <community-strings-file> {ip}",
                    "[*]".cyan()
                );
            }
            report.add("  → Try onesixtyone bruteforce").await;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{contains_snmp_data, is_expected_negative};

    #[test]
    fn recognizes_walk_data_instead_of_arbitrary_output() {
        assert!(contains_snmp_data("SNMPv2-MIB::sysDescr.0 = STRING: Linux"));
        assert!(!contains_snmp_data("warning: using fallback transport"));
    }

    #[test]
    fn recognizes_normal_community_rejection() {
        assert!(is_expected_negative("Timeout: No Response from 10.10.10.1"));
        assert!(!is_expected_negative("snmpwalk: unknown option -- bad"));
    }
}
