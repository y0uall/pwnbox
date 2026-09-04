use anyhow::{Result, bail};
use colored::Colorize;
use tokio::task::JoinSet;

use crate::report::Report;
use crate::runner;

const COMMON_PASSWORDS: &[&str] = &["", "redis", "password", "admin", "default"];

/// Try unauthenticated access, then common passwords.
pub async fn check(ip: &str, port: u16, report: &Report) -> Result<()> {
    report.section("REDIS").await;
    let port_str = port.to_string();

    if runner::command_exists("redis-cli").await {
        // no auth first
        println!("{} Trying unauthenticated access...", "[*]".cyan());
        let (probe_ok, output) = runner::run_cmd_status(
            "redis-cli",
            &["-h", ip, "-p", &port_str, "INFO", "server"],
            10,
        )
        .await?;

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
            report.add_service("redis", "  Unauthenticated: YES").await;
            report.add_service("redis", &text).await;
            report.add_vuln("Redis: unauthenticated access").await;
            return Ok(());
        }

        if output.contains("NOAUTH") {
            // needs auth — race the common passwords, first hit wins; the
            // serial loop cost len × 10s on a denied server (REVIEW.md
            // finding 9). Aborted attempts die via kill_on_drop.
            println!(
                "{} Auth required — racing common passwords...",
                "[*]".cyan()
            );
            let mut attempts = JoinSet::new();
            for pass in COMMON_PASSWORDS {
                if pass.is_empty() {
                    continue;
                }
                let ip = ip.to_string();
                let port_str = port_str.clone();
                attempts.spawn(async move {
                    let (auth_ok, auth_output) = runner::run_cmd_status(
                        "redis-cli",
                        &["-h", &ip, "-p", &port_str, "-a", pass, "INFO", "server"],
                        10,
                    )
                    .await?;

                    if auth_ok
                        && auth_output.contains("redis_version")
                        && !auth_output.contains("NOAUTH")
                    {
                        return Ok(Some(pass));
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
                    Ok(None)
                });
            }

            // first success wins; a client-side tool error is only fatal when
            // no attempt succeeded at all
            let mut winner: Option<&str> = None;
            let mut first_error: Option<anyhow::Error> = None;
            while let Some(res) = attempts.join_next().await {
                match res {
                    Ok(Ok(Some(pass))) => {
                        winner = Some(pass);
                        break;
                    }
                    Ok(Ok(None)) => {}
                    Ok(Err(e)) => {
                        first_error.get_or_insert(e);
                    }
                    Err(e) => {
                        first_error.get_or_insert_with(|| {
                            anyhow::anyhow!("credential task panicked: {e}")
                        });
                    }
                }
            }
            attempts.abort_all();
            // drain so the aborted tasks' child processes are really gone
            while attempts.join_next().await.is_some() {}

            if let Some(pass) = winner {
                println!(
                    "{} Redis login with password: {}",
                    "[+]".green().bold(),
                    pass.red()
                );
                report
                    .add_service("redis", &format!("  Auth: YES (password: {pass})"))
                    .await;
                report
                    .add_vuln(&format!("Redis: default password '{pass}'"))
                    .await;
                return Ok(());
            }

            if let Some(e) = first_error {
                return Err(e);
            }

            println!("{} Common passwords denied", "[!]".yellow());
            report
                .add_service(
                    "redis",
                    "  Unauthenticated: NO (auth required, common passwords failed)",
                )
                .await;
        } else if !probe_ok {
            bail!("redis-cli failed: {}", output.trim());
        } else {
            println!("{} Redis connection failed or refused", "[!]".yellow());
            report.add_service("redis", "  (connection failed)").await;
        }
    } else {
        // no redis-cli, fall back to a raw TCP probe
        let output = runner::tcp_probe(ip, port, b"INFO server\r\n", 5).await?;

        if output.contains("redis_version") {
            println!(
                "{} Redis unauthenticated access (raw TCP)!",
                "[+]".green().bold()
            );
            let snippet = output.lines().take(15).collect::<Vec<_>>().join("\n");
            println!("{snippet}");
            report.add_service("redis", "  Unauthenticated: YES").await;
            report.add_service("redis", &snippet).await;
            report.add_vuln("Redis: unauthenticated access").await;
        } else {
            println!("{} Redis not accessible without auth", "[!]".yellow());
            report
                .add_service("redis", "  (not accessible or auth required)")
                .await;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REVIEW.md finding 7: the detected port must be used. A fake server on
    /// 6380 answers both probe paths — the RESP bulk reply below is valid for
    /// a real redis-cli and contains "redis_version" for the raw TCP fallback.
    #[tokio::test]
    async fn check_uses_the_detected_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:6380")
            .await
            .unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            // read the client's INFO command first — closing the socket with
            // unread data in the receive buffer could RST away our reply
            let mut buf = [0u8; 256];
            let _ = sock.read(&mut buf).await;
            let payload = "# Server\r\nredis_version:7.4.0\r\n";
            let reply = format!("${}\r\n{payload}\r\n", payload.len());
            sock.write_all(reply.as_bytes()).await.unwrap();
        });

        let report = Report::new();
        check("127.0.0.1", 6380, &report).await.unwrap();
        server.await.unwrap();

        assert!(
            report
                .lines()
                .await
                .iter()
                .any(|l| l.contains("Unauthenticated: YES")),
            "the fake redis on port 6380 must be reported as unauthenticated"
        );
    }
}
