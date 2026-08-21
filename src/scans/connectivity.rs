use std::sync::LazyLock;

use anyhow::Result;
use colored::Colorize;
use regex::Regex;

use crate::report::Report;
use crate::runner;

// Pulls the TTL out of a ping reply line ("... ttl=64 ...").
static RE_TTL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"ttl=(\d+)").unwrap());

/// Ping the box and try to guess the OS based on TTL.
///
/// No ICMP response is not proof that a host is down. The remaining pipeline
/// uses nmap -Pn, so continue with an unknown OS instead of aborting recon.
pub async fn check(ip: &str, report: &Report) -> Result<String> {
    let output = match runner::run_cmd_status("ping", &["-c", "1", "-W", "3", ip], 10).await {
        Ok((true, output)) if output.contains("bytes from") => Some(output),
        Ok((_success, _output)) => {
            println!(
                "{} No ICMP reply from {ip} -- continuing with -Pn",
                "[!]".yellow()
            );
            None
        }
        Err(e) => {
            println!(
                "{} ping unavailable: {e} -- continuing with -Pn",
                "[!]".yellow()
            );
            report.add_error("CONNECTIVITY", &e.to_string()).await;
            None
        }
    };

    let os_guess = if let Some(output) = output {
        if let Some(caps) = RE_TTL.captures(&output) {
            let ttl: u32 = caps[1].parse().unwrap_or(0);
            if ttl <= 64 {
                format!("Linux (TTL={ttl})")
            } else if ttl <= 128 {
                format!("Windows (TTL={ttl})")
            } else {
                format!("Network device / Other (TTL={ttl})")
            }
        } else {
            "unknown (TTL unavailable)".to_string()
        }
    } else {
        "unknown (no ICMP response)".to_string()
    };

    println!(
        "{} Connectivity phase complete -- {}",
        "[+]".green(),
        os_guess.cyan()
    );
    report.section("OS GUESS").await;
    report.add(&format!("  {os_guess}")).await;

    Ok(os_guess)
}
