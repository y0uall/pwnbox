use anyhow::{Result, bail};
use colored::Colorize;

use crate::report::Report;
use crate::runner;

const COMMON_PASSWORDS: &[&str] = &["", "redis", "password", "admin", "default"];

/// Try unauthenticated access, then common passwords.
pub async fn check(ip: &str, report: &Report) -> Result<()> {
    report.section("REDIS").await;

    if runner::command_exists("redis-cli").await {
        // no auth first
        println!("{} Trying unauthenticated access...", "[*]".cyan());
        let (probe_ok, output) =
            runner::run_cmd_status("redis-cli", &["-h", ip, "INFO", "server"], 10).await?;

        if probe_ok
            && !output.is_empty()
            && !output.contains("NOAUTH")
            && !output.contains("ERR")
            && output.contains("redis_version")
        {
            println!("{} Redis unauthenticated access!", "[+]".green().bold());
            let lines: Vec<&str> = output.lines().take(15).collect();
            let text = lines.join("\n");
            println!("{text}");
            report.add("  Unauthenticated: YES").await;
            report.add(&text).await;
            report.add_vuln("Redis: unauthenticated access").await;
            return Ok(());
        }

        if output.contains("NOAUTH") {
            // needs auth, try common passwords
            println!(
                "{} Auth required — testing common passwords...",
                "[*]".cyan()
            );
            for pass in COMMON_PASSWORDS {
                if pass.is_empty() {
                    continue;
                }
                let (auth_ok, auth_output) = runner::run_cmd_status(
                    "redis-cli",
                    &["-h", ip, "-a", pass, "INFO", "server"],
                    10,
                )
                .await?;

                if auth_ok
                    && auth_output.contains("redis_version")
                    && !auth_output.contains("NOAUTH")
                {
                    println!(
                        "{} Redis login with password: {}",
                        "[+]".green().bold(),
                        pass.red()
                    );
                    report.add(&format!("  Auth: YES (password: {pass})")).await;
                    report
                        .add_vuln(&format!("Redis: default password '{pass}'"))
                        .await;
                    return Ok(());
                }

                if !auth_ok {
                    let lower = auth_output.to_ascii_lowercase();
                    if !lower.contains("wrongpass")
                        && !lower.contains("invalid password")
                        && !lower.contains("noauth")
                    {
                        bail!(
                            "redis-cli authentication probe failed: {}",
                            auth_output.trim()
                        );
                    }
                }
            }
            println!("{} Common passwords denied", "[!]".yellow());
            report
                .add("  Unauthenticated: NO (auth required, common passwords failed)")
                .await;
        } else if !probe_ok {
            bail!("redis-cli failed: {}", output.trim());
        } else {
            println!("{} Redis connection failed or refused", "[!]".yellow());
            report.add("  (connection failed)").await;
        }
    } else {
        // no redis-cli, fall back to a raw TCP probe
        let output = runner::tcp_probe(ip, 6379, b"INFO server\r\n", 5).await?;

        if output.contains("redis_version") {
            println!(
                "{} Redis unauthenticated access (raw TCP)!",
                "[+]".green().bold()
            );
            let snippet = output.lines().take(15).collect::<Vec<_>>().join("\n");
            println!("{snippet}");
            report.add("  Unauthenticated: YES").await;
            report.add(&snippet).await;
            report.add_vuln("Redis: unauthenticated access").await;
        } else {
            println!("{} Redis not accessible without auth", "[!]".yellow());
            report.add("  (not accessible or auth required)").await;
        }
    }

    Ok(())
}
