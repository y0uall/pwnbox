use anyhow::{Result, bail};
use colored::Colorize;

use crate::report::Report;
use crate::runner;

const DEFAULT_CREDS: &[(&str, &str)] = &[
    ("postgres", "postgres"),
    ("postgres", ""),
    ("postgres", "password"),
    ("admin", "admin"),
];

/// Try common PostgreSQL creds.
pub async fn check(ip: &str, port: u16, report: &Report) -> Result<()> {
    report.section("POSTGRESQL").await;

    if !runner::command_exists("psql").await {
        println!(
            "{} psql not found — skipping PostgreSQL check",
            "[!]".yellow()
        );
        report.add("  (psql not installed)").await;
        return Ok(());
    }

    println!(
        "{} Testing {} default credential pairs...",
        "[*]".cyan(),
        DEFAULT_CREDS.len()
    );
    for (user, pass) in DEFAULT_CREDS {
        let connstr = format!("postgresql://{user}:{pass}@{ip}:{port}/postgres");
        let (login_ok, output) =
            runner::run_cmd_status("psql", &[&connstr, "-c", "\\l", "--no-password"], 10).await?;

        if login_ok {
            let cred_display = if pass.is_empty() {
                format!("{user}:(empty)")
            } else {
                format!("{user}:{pass}")
            };
            println!(
                "{} PostgreSQL login successful: {}",
                "[+]".green().bold(),
                cred_display.red()
            );
            let lines: Vec<&str> = output.lines().take(20).collect();
            let text = lines.join("\n");
            println!("{text}");
            report.add(&format!("  Login: YES ({cred_display})")).await;
            report.add(&text).await;
            report
                .add_vuln(&format!("PostgreSQL: default credentials {cred_display}"))
                .await;
            return Ok(());
        }

        let lower = output.to_lowercase();
        if !lower.contains("password authentication failed")
            && !lower.contains("no password supplied")
            && !lower.contains("authentication failed")
        {
            bail!(
                "psql failed before authentication could be determined: {}",
                output.trim()
            );
        }
    }

    println!("{} All default credentials denied", "[!]".yellow());
    report.add("  Default credentials: NO").await;
    Ok(())
}
