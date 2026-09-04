use anyhow::Result;
use colored::Colorize;
use tokio::task::JoinSet;

use crate::config::{ScanConfig, find_wordlist};
use crate::report::Report;
use crate::runner;

const COMMUNITY_STRINGS: &[&str] = &["public", "private", "community", "manager", "snmpd"];

/// One community-string attempt's outcome from the JoinSet race.
struct SnmpAttempt {
    /// index into COMMUNITY_STRINGS — errors are reported in that order
    idx: usize,
    community: &'static str,
    /// walk output when this community worked
    hit: Option<String>,
    /// tool-failure detail (non-fatal, like in the old serial loop)
    error: Option<String>,
}

impl SnmpAttempt {
    fn hit(idx: usize, community: &'static str, output: String) -> Self {
        SnmpAttempt {
            idx,
            community,
            hit: Some(output),
            error: None,
        }
    }

    fn error(idx: usize, community: &'static str, detail: String) -> Self {
        SnmpAttempt {
            idx,
            community,
            hit: None,
            error: Some(detail),
        }
    }

    fn denied(idx: usize, community: &'static str) -> Self {
        SnmpAttempt {
            idx,
            community,
            hit: None,
            error: None,
        }
    }
}

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
        report
            .add_service("snmp", "  (snmpwalk not installed)")
            .await;
        return Ok(());
    }

    // race the community strings, first hit wins — the serial loop cost
    // len × 15s when nothing answered (REVIEW.md finding 9). Aborted attempts
    // die via kill_on_drop.
    let mut attempts = JoinSet::new();
    for (idx, community) in COMMUNITY_STRINGS.iter().enumerate() {
        let ip = ip.to_string();
        let snmpwalk = snmpwalk.clone();
        attempts.spawn(async move {
            println!(
                "{} Trying community string '{}'...",
                "[*]".cyan(),
                community.yellow()
            );

            let (success, output) = runner::run_cmd_status(
                &snmpwalk,
                &["-v2c", "-c", community, "-t", "3", "-r", "1", &ip],
                15,
            )
            .await?;

            if success && contains_snmp_data(&output) {
                return Ok(SnmpAttempt::hit(idx, community, output));
            }
            if !success && !is_expected_negative(&output) {
                let detail = output.lines().take(3).collect::<Vec<_>>().join(" ");
                let detail = if detail.trim().is_empty() {
                    format!("snmpwalk failed for community '{community}' without output")
                } else {
                    format!("snmpwalk failed for community '{community}': {detail}")
                };
                return Ok(SnmpAttempt::error(idx, community, detail));
            }
            Ok(SnmpAttempt::denied(idx, community))
        });
    }

    // first success wins; a runner-level failure is only fatal when no
    // attempt succeeded at all (the serial loop propagated the first one)
    let mut winner: Option<(&str, String)> = None;
    let mut errors: Vec<(usize, String)> = Vec::new();
    let mut first_error: Option<anyhow::Error> = None;
    while let Some(res) = attempts.join_next().await {
        match res {
            Ok(Ok(attempt)) => {
                if let Some(output) = attempt.hit {
                    winner = Some((attempt.community, output));
                    break;
                }
                if let Some(detail) = attempt.error {
                    errors.push((attempt.idx, detail));
                }
            }
            Ok(Err(e)) => {
                first_error.get_or_insert(e);
            }
            Err(e) => {
                first_error.get_or_insert_with(|| anyhow::anyhow!("community task panicked: {e}"));
            }
        }
    }
    attempts.abort_all();
    // drain so the aborted tasks' child processes are really gone
    while attempts.join_next().await.is_some() {}

    // tool failures were collected in completion order — report them in
    // community order so the JSON error list stays deterministic
    errors.sort_by_key(|(idx, _)| *idx);
    for (_, detail) in &errors {
        report.add_error("SNMP", detail).await;
    }

    if let Some((community, output)) = winner {
        println!(
            "{} SNMP community '{}' works!",
            "[+]".green().bold(),
            community
        );
        report
            .add_service("snmp", &format!("  Community string: {community}"))
            .await;
        let lines: Vec<&str> = output.lines().take(50).collect();
        let text = lines.join("\n");
        println!("{text}");
        report.add_service("snmp", &text).await;
    } else {
        if let Some(e) = first_error {
            return Err(e);
        }

        println!("{} No SNMP community strings worked", "[!]".yellow());
        report
            .add_service("snmp", "  (no community strings worked)")
            .await;

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
            report
                .add_service("snmp", "  → Try onesixtyone bruteforce")
                .await;
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
