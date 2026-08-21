use anyhow::{Result, bail};
use colored::Colorize;

use crate::report::Report;
use crate::runner;

const DEFAULT_CREDS: &[(&str, &str)] = &[
    ("root", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("mysql", "mysql"),
];

/// Try a handful of common MySQL creds.
pub async fn check(ip: &str, port: u16, report: &Report) -> Result<()> {
    report.section("MYSQL").await;

    if !runner::command_exists("mysql").await {
        println!("{} mysql client not found — skipping", "[!]".yellow());
        report.add("  (mysql client not installed)").await;
        return Ok(());
    }

    println!(
        "{} Testing {} default credential pairs...",
        "[*]".cyan(),
        DEFAULT_CREDS.len()
    );
    for (user, pass) in DEFAULT_CREDS {
        let pass_arg = format!("--password={pass}");
        let (login_ok, output) = runner::run_cmd_status(
            "mysql",
            &[
                "-h",
                ip,
                "-P",
                &port.to_string(),
                "-u",
                user,
                &pass_arg,
                "-e",
                "SELECT VERSION(); SHOW DATABASES;",
            ],
            15,
        )
        .await?;

        if login_ok {
            let cred_display = if pass.is_empty() {
                format!("{user}:(empty)")
            } else {
                format!("{user}:{pass}")
            };
            println!(
                "{} MySQL login successful: {}",
                "[+]".green().bold(),
                cred_display.red()
            );
            let lines: Vec<&str> = output.lines().take(30).collect();
            let text = lines.join("\n");
            println!("{text}");
            report.add(&format!("  Login: YES ({cred_display})")).await;
            report.add(&text).await;
            report
                .add_vuln(&format!("MySQL: default credentials {cred_display}"))
                .await;
            return Ok(());
        }

        let lower = output.to_lowercase();
        if !lower.contains("access denied") {
            bail!(
                "mysql client failed before authentication could be determined: {}",
                output.trim()
            );
        }
    }

    println!("{} All default credentials denied", "[!]".yellow());
    report.add("  Default credentials: NO").await;
    Ok(())
}
