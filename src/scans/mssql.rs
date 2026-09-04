use anyhow::Result;
use colored::Colorize;

use crate::config::{ScanConfig, find_wordlist};
use crate::report::Report;
use crate::runner;

fn is_expected_login_denial(output: &str) -> bool {
    let output = output.to_ascii_lowercase();
    output.contains("login failed")
        || output.contains("authentication failed")
        || output.contains("invalid credentials")
        || output.contains("account is currently locked")
        || output.contains("password did not match")
        || output.contains("untrusted domain")
}

#[derive(Debug, PartialEq, Eq)]
enum LoginOutcome {
    Accepted,
    Denied,
    Failed,
}

fn login_outcome(success: bool, output: &str) -> LoginOutcome {
    if is_expected_login_denial(output) {
        LoginOutcome::Denied
    } else if success && output.contains("Microsoft SQL Server") {
        LoginOutcome::Accepted
    } else {
        // Impacket also exits 0 for some client/server errors. Only the SQL
        // version response confirms that our query actually ran.
        LoginOutcome::Failed
    }
}

async fn record_nmap_info(output: &str, report: &Report) {
    let mut details = 0;
    for line in output.lines().filter(|line| line.starts_with('|')) {
        if line.contains("ERROR:") {
            let detail = format!("nmap MSSQL discovery: {}", line.trim());
            println!("{} {detail}", "[!]".yellow());
            report.add_error("MSSQL", &detail).await;
        } else {
            details += 1;
            println!("{} {}", "[+]".green(), line.trim().cyan());
            report
                .add_service("mssql", &format!("  {}", line.trim()))
                .await;
        }
    }
    if details == 0 && !output.contains("ERROR:") {
        // Broken NSE libraries can fail silently while nmap still exits 0.
        let detail = "nmap MSSQL scripts returned no details; check the installed NSE library";
        println!("{} {detail}", "[!]".yellow());
        report.add_error("MSSQL", detail).await;
    }
}

async fn probe_login(
    client: &str,
    ip: &str,
    port: u16,
    user: &str,
    pass: &str,
) -> Result<(bool, String)> {
    let target = format!("{user}:{pass}@{ip}");
    let port = port.to_string();
    // -file is also supported by older Impacket releases. /dev/stdin lets us
    // supply a query without its interactive shell, a disk file, or the
    // unsupported -q flag. SQL authentication is the default for SA.
    runner::run_cmd_status_input(
        client,
        &[&target, "-port", &port, "-no-pass", "-file", "/dev/stdin"],
        b"SELECT @@version\n",
        10,
    )
    .await
}
/// MSSQL: nmap scripts for version info, then try default SA creds.
pub async fn check(ip: &str, port: u16, scan_cfg: &ScanConfig, report: &Report) -> Result<()> {
    println!("{} MSSQL enumeration on port {port}...", "[*]".cyan());
    report.section("MSSQL").await;

    // get version info via nmap scripts
    let nmap_bin = scan_cfg.tool("nmap");
    let nmap = match runner::run_cmd_timeout(
        &nmap_bin,
        &[
            "-Pn",
            "-p",
            &port.to_string(),
            "--script",
            "ms-sql-info,ms-sql-ntlm-info",
            ip,
        ],
        30,
    )
    .await
    {
        Ok(output) => output,
        Err(e) => {
            println!("{} MSSQL nmap scripts failed: {e}", "[!]".yellow());
            report.add_error("MSSQL", &e.to_string()).await;
            String::new()
        }
    };

    if !nmap.is_empty() {
        record_nmap_info(&nmap, report).await;
    }

    // try common sa passwords. Resolve the impacket client honouring the
    // documented alternative name (mssqlclient.py) — otherwise a host that only
    // has that one silently falls through to the slower nmap brute even though
    // the startup tool check reported the client as present.
    let mssql_client = if runner::command_exists("impacket-mssqlclient").await {
        Some("impacket-mssqlclient")
    } else if runner::command_exists("mssqlclient.py").await {
        Some("mssqlclient.py")
    } else {
        None
    };

    if let Some(mssql_client) = mssql_client {
        println!("{} Testing default SA credentials...", "[*]".cyan());

        let default_creds = [
            ("sa", ""),
            ("sa", "sa"),
            ("sa", "password"),
            ("sa", "Password1"),
        ];

        let mut denied = 0;
        for (user, pass) in &default_creds {
            // Deliberately serial (no racing like mysql/postgres/redis/snmp):
            // parallel SA logins risk tripping the account lockout policy
            // (REVIEW.md finding 9); the per-attempt timeout is lowered to 10s
            // to bound the serial worst case instead.
            let (login_ok, result) = match probe_login(mssql_client, ip, port, user, pass).await {
                Ok(result) => result,
                Err(e) => {
                    // Keep already collected version/host information if the
                    // client fails or times out during a later login attempt.
                    println!("{} MSSQL login probe failed: {e}", "[!]".yellow());
                    report.add_error("MSSQL", &e.to_string()).await;
                    break;
                }
            };

            // Impacket may exit 0 after printing a server-side login denial.
            let outcome = login_outcome(login_ok, &result);
            if outcome == LoginOutcome::Denied {
                denied += 1;
                continue;
            }

            if outcome == LoginOutcome::Failed {
                let detail = result.lines().take(5).collect::<Vec<_>>().join(" ");
                let detail = if detail.trim().is_empty() {
                    format!("{mssql_client} failed without output")
                } else {
                    format!("{mssql_client} failed: {detail}")
                };
                println!("{} {detail}", "[!]".yellow());
                report.add_error("MSSQL", &detail).await;
                break;
            }

            if outcome == LoginOutcome::Accepted {
                let cred_display = if pass.is_empty() {
                    format!("{user}:(empty)")
                } else {
                    format!("{user}:{pass}")
                };
                println!(
                    "{} MSSQL login successful: {}",
                    "[+]".green().bold(),
                    cred_display.red()
                );
                report
                    .add_service("mssql", &format!("  *** LOGIN: {cred_display} ***"))
                    .await;
                break;
            }
        }
        if denied == default_creds.len() {
            let detail = format!(
                "Default SA credentials rejected ({} attempts)",
                default_creds.len()
            );
            println!("{} {detail}", "[*]".cyan());
            report.add_service("mssql", &format!("  {detail}")).await;
        }
    } else {
        // no impacket, fall back to nmap brute
        println!(
            "{} impacket-mssqlclient not found, trying nmap...",
            "[*]".cyan()
        );

        let userdb = find_wordlist(&scan_cfg.wordlists.usernames_short);
        let passdb = find_wordlist(&scan_cfg.wordlists.passwords_short);

        if let (Some(udb), Some(pdb)) = (userdb, passdb) {
            let script_args = format!("userdb={udb},passdb={pdb}");
            let brute = match runner::run_cmd_timeout(
                &nmap_bin,
                &[
                    "-Pn",
                    "-p",
                    &port.to_string(),
                    "--script",
                    "ms-sql-brute",
                    "--script-args",
                    &script_args,
                    ip,
                ],
                60,
            )
            .await
            {
                Ok(output) => output,
                Err(e) => {
                    println!("{} MSSQL nmap brute failed: {e}", "[!]".yellow());
                    report.add_error("MSSQL", &e.to_string()).await;
                    String::new()
                }
            };

            let hits: Vec<&str> = brute
                .lines()
                .filter(|l| l.contains("Valid") || l.contains("credentials"))
                .collect();

            for hit in &hits {
                println!("{} {}", "[+]".green(), hit.trim().red());
                report
                    .add_service("mssql", &format!("  {}", hit.trim()))
                    .await;
            }
        } else {
            println!(
                "{} No wordlists found for nmap brute — skipping",
                "[!]".yellow()
            );
        }
    }

    // remind about post-exploitation options
    report
        .add_service(
            "mssql",
            "  Next: If login works → try xp_cmdshell, xp_dirtree",
        )
        .await;
    println!(
        "{} If creds work → try: xp_cmdshell, xp_dirtree, linked servers",
        "[*]".cyan()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn login_uses_file_input_and_detected_port() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("pwnbox_mssql_client_{}", std::process::id()));
        std::fs::write(
            &path,
            r#"#!/bin/sh
[ "$1" = 'sa:@192.0.2.1' ] || exit 2
[ "$2" = '-port' ] && [ "$3" = '14330' ] || exit 2
[ "$4" = '-no-pass' ] && [ "$5" = '-file' ] && [ "$6" = '/dev/stdin' ] || exit 2
read -r query
[ "$query" = 'SELECT @@version' ] || exit 3
printf 'Microsoft SQL Server fixture\n'
"#,
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let result = probe_login(path.to_str().unwrap(), "192.0.2.1", 14330, "sa", "").await;
        std::fs::remove_file(path).unwrap();
        let (success, out) = result.unwrap();
        assert!(success, "{out}");
        assert!(out.contains("Microsoft SQL Server"));
    }

    #[test]
    fn separates_bad_credentials_from_client_failures() {
        assert_eq!(
            login_outcome(true, "Login failed for user 'sa'"),
            LoginOutcome::Denied
        );
        assert_eq!(
            login_outcome(false, "Connection refused"),
            LoginOutcome::Failed
        );
        assert_eq!(
            login_outcome(true, "Impacket v0.13.0\nERROR: TLS negotiation failed"),
            LoginOutcome::Failed
        );
        assert_eq!(
            login_outcome(true, "Microsoft SQL Server 2017 (RTM) - 14.0.1000.169"),
            LoginOutcome::Accepted
        );
        assert_eq!(
            login_outcome(false, "Microsoft SQL Server\nconnection lost"),
            LoginOutcome::Failed
        );
        assert_eq!(
            login_outcome(true, "Microsoft SQL Server\nLogin failed for user 'sa'"),
            LoginOutcome::Denied
        );
    }

    #[tokio::test]
    async fn nmap_failure_keeps_successful_script_details() {
        let report = Report::new();
        record_nmap_info("1433/tcp open ms-sql-s\n| ms-sql-info:\n|   Product: Microsoft SQL Server 2017\n|_ms-sql-ntlm-info: ERROR: Script execution failed\n", &report).await;
        assert!(
            report
                .lines()
                .await
                .iter()
                .any(|line| line.contains("Microsoft SQL Server 2017"))
        );
        assert_eq!(report.errors().await.len(), 1);
        assert!(report.errors().await[0].contains("ms-sql-ntlm-info"));
    }

    #[tokio::test]
    async fn nmap_exit_zero_without_details_is_not_silent_success() {
        let report = Report::new();
        record_nmap_info(
            "PORT STATE SERVICE\n1433/tcp open ms-sql-s\nNmap done: 1 IP address\n",
            &report,
        )
        .await;
        assert!(report.lines().await.is_empty());
        assert!(report.errors().await[0].contains("returned no details"));
    }
}
