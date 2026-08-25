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

    let info_lines: Vec<&str> = nmap
        .lines()
        .filter(|l| l.contains("Version") || l.contains("name:") || l.contains("Product"))
        .collect();

    if !info_lines.is_empty() {
        for line in &info_lines {
            let trimmed = line.trim();
            println!("{} {}", "[+]".green(), trimmed.cyan());
            report.add(&format!("  {trimmed}")).await;
        }
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

        let port_str = port.to_string();
        for (user, pass) in &default_creds {
            // Deliberately serial (no racing like mysql/postgres/redis/snmp):
            // parallel SA logins risk tripping the account lockout policy
            // (REVIEW.md finding 9); the per-attempt timeout is lowered to 10s
            // to bound the serial worst case instead.
            // build the arg vector directly — no shell, no quoting games
            let target = if pass.is_empty() {
                format!("{user}@{ip}")
            } else {
                format!("{user}:{pass}@{ip}")
            };
            // sa is a SQL-auth account; -windows-auth would force NTLM and make
            // every intended default-SA check fail.
            let mut args: Vec<&str> = vec![&target, "-port", &port_str];
            if pass.is_empty() {
                args.push("-no-pass");
            }
            args.extend_from_slice(&["-q", "SELECT @@version"]);

            let (login_ok, result) = runner::run_cmd_status(mssql_client, &args, 10).await?;

            if !login_ok {
                if is_expected_login_denial(&result) {
                    continue;
                }

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

            if result.contains("Microsoft SQL Server") || result.contains("Enumerating") {
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
                    .add(&format!("  *** LOGIN: {cred_display} ***"))
                    .await;
                break;
            }
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
                report.add(&format!("  {}", hit.trim())).await;
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
        .add("  Next: If login works → try xp_cmdshell, xp_dirtree")
        .await;
    println!(
        "{} If creds work → try: xp_cmdshell, xp_dirtree, linked servers",
        "[*]".cyan()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_expected_login_denial;

    #[test]
    fn separates_bad_credentials_from_client_failures() {
        assert!(is_expected_login_denial("Login failed for user 'sa'"));
        assert!(!is_expected_login_denial("Connection refused"));
    }
}
