use anyhow::Result;
use colored::Colorize;
use tokio::task::JoinSet;

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
        "{} Racing {} default credential pairs...",
        "[*]".cyan(),
        DEFAULT_CREDS.len()
    );

    // All attempts run concurrently and the first success wins; the serial
    // loop made a denied-but-slow server cost len × 15s (REVIEW.md finding 9).
    // Aborted losers die via kill_on_drop.
    let mut attempts = JoinSet::new();
    for (user, pass) in DEFAULT_CREDS {
        let ip = ip.to_string();
        attempts.spawn(async move {
            let pass_arg = format!("--password={pass}");
            let (login_ok, output) = runner::run_cmd_status(
                "mysql",
                &[
                    "-h",
                    &ip,
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
                return Ok(Some((cred_display, output)));
            }

            let lower = output.to_lowercase();
            if !lower.contains("access denied") {
                anyhow::bail!(
                    "mysql client failed before authentication could be determined: {}",
                    output.trim()
                );
            }
            Ok(None)
        });
    }

    // first success wins; a client-side tool error is only fatal when no
    // attempt succeeded at all (the serial loop bailed on the first one)
    let mut winner: Option<(String, String)> = None;
    let mut first_error: Option<anyhow::Error> = None;
    while let Some(res) = attempts.join_next().await {
        match res {
            Ok(Ok(Some(hit))) => {
                winner = Some(hit);
                break;
            }
            Ok(Ok(None)) => {}
            Ok(Err(e)) => {
                first_error.get_or_insert(e);
            }
            Err(e) => {
                first_error.get_or_insert_with(|| anyhow::anyhow!("credential task panicked: {e}"));
            }
        }
    }
    attempts.abort_all();
    // drain so the aborted tasks' child processes are really gone
    while attempts.join_next().await.is_some() {}

    if let Some((cred_display, output)) = winner {
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

    if let Some(e) = first_error {
        return Err(e);
    }

    println!("{} All default credentials denied", "[!]".yellow());
    report.add("  Default credentials: NO").await;
    Ok(())
}
