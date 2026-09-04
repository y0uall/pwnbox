use anyhow::Result;
use colored::Colorize;
use tokio::task::JoinSet;

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
        report
            .add_service("postgres", "  (psql not installed)")
            .await;
        return Ok(());
    }

    println!(
        "{} Racing {} default credential pairs...",
        "[*]".cyan(),
        DEFAULT_CREDS.len()
    );

    // concurrent attempts, first success wins — the serial loop cost
    // len × 10s on a denied-but-slow server (REVIEW.md finding 9)
    let mut attempts = JoinSet::new();
    for (user, pass) in DEFAULT_CREDS {
        let ip = ip.to_string();
        attempts.spawn(async move {
            let connstr = format!("postgresql://{user}:{pass}@{ip}:{port}/postgres");
            let (login_ok, output) =
                runner::run_cmd_status("psql", &[&connstr, "-c", "\\l", "--no-password"], 10)
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
            if !lower.contains("password authentication failed")
                && !lower.contains("no password supplied")
                && !lower.contains("authentication failed")
            {
                anyhow::bail!(
                    "psql failed before authentication could be determined: {}",
                    output.trim()
                );
            }
            Ok(None)
        });
    }

    // first success wins; a client-side tool error is only fatal when no
    // attempt succeeded at all
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
            "{} PostgreSQL login successful: {}",
            "[+]".green().bold(),
            cred_display.red()
        );
        let lines: Vec<&str> = output.lines().take(20).collect();
        let text = lines.join("\n");
        println!("{text}");
        report
            .add_service("postgres", &format!("  Login: YES ({cred_display})"))
            .await;
        report.add_service("postgres", &text).await;
        report
            .add_vuln(&format!("PostgreSQL: default credentials {cred_display}"))
            .await;
        return Ok(());
    }

    if let Some(e) = first_error {
        return Err(e);
    }

    println!("{} All default credentials denied", "[!]".yellow());
    report
        .add_service("postgres", "  Default credentials: NO")
        .await;
    Ok(())
}
