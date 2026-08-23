use std::sync::LazyLock;

use anyhow::Result;
use colored::Colorize;
use regex::Regex;

use crate::config::ScanConfig;
use crate::hosts;
use crate::report::Report;
use crate::runner;

// Any plausible hostname inside dig/AXFR output. The result is later filtered
// through `hosts::is_valid_hostname` so arbitrary tokens don't reach /etc/hosts.
// The match must contain at least one letter so plain IP addresses are ignored.
static RE_HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[a-zA-Z0-9._-]*[a-z][a-zA-Z0-9._-]*\.[a-zA-Z0-9._-]+\.?").unwrap()
});

/// Try zone transfer + reverse DNS, return any hostnames we find.
pub async fn recon(
    ip: &str,
    hostname: &str,
    scan_cfg: &ScanConfig,
    report: &Report,
) -> Result<Vec<String>> {
    let mut discovered: Vec<String> = Vec::new();

    let dig = scan_cfg.tool("dig");
    if !runner::command_exists(&dig).await {
        println!("{} dig not found -- skipping DNS recon", "[!]".yellow());
        return Ok(discovered);
    }

    // try AXFR against both the FQDN and the base domain
    let mut axfr_found = false;

    for domain in &[hostname, "htb"] {
        let (success, output) = runner::run_cmd_status(
            &dig,
            &[
                "axfr",
                domain,
                &format!("@{ip}"),
                "+short",
                "+noall",
                "+answer",
            ],
            runner::default_timeout(),
        )
        .await?;

        if !success {
            continue; // refused/failed AXFR is an expected negative result
        }
        let before = discovered.len();
        for cap in RE_HOST.find_iter(&output) {
            let name = cap.as_str().trim_end_matches('.').to_lowercase();
            if !discovered.contains(&name) {
                discovered.push(name);
            }
        }
        axfr_found |= discovered.len() > before;
    }

    if axfr_found {
        println!("{} Zone transfer successful!", "[+]".green());
        for h in &discovered {
            println!("    {}", h.cyan());
        }
        hosts::add_hosts(ip, &discovered).await?;
    } else {
        println!(
            "{} Zone transfer failed (normal -- not always enabled)",
            "[!]".yellow()
        );
    }

    // reverse DNS lookup
    let (ptr_ok, ptr_output) =
        runner::run_cmd_status(&dig, &["-x", ip, "+short"], runner::default_timeout()).await?;
    if !ptr_ok {
        report
            .add_error(
                "DNS",
                &format!("reverse lookup failed: {}", ptr_output.trim()),
            )
            .await;
    }
    let ptr_hosts: Vec<String> = if ptr_ok {
        ptr_output
            .lines()
            .map(|l| l.trim().trim_end_matches('.').to_lowercase())
            .filter(|l| hosts::is_valid_hostname(l))
            .collect()
    } else {
        Vec::new()
    };

    if !ptr_hosts.is_empty() {
        println!("{} Reverse DNS:", "[+]".green());
        for h in &ptr_hosts {
            println!("    {}", h.cyan());
        }
        hosts::add_hosts(ip, &ptr_hosts).await?;
        for h in ptr_hosts {
            if !discovered.contains(&h) {
                discovered.push(h);
            }
        }
    }

    if !discovered.is_empty() {
        report.section("DNS").await;
        for h in &discovered {
            report.add(&format!("  {h}")).await;
        }
    }

    Ok(discovered)
}

#[cfg(test)]
mod tests {
    use super::RE_HOST;

    #[test]
    fn extracts_generic_domains_from_axfr_output() {
        let output = "sub.corp.local.\nadmin.inlanefreight.local.\nhost.htb.";
        let hosts: Vec<String> = RE_HOST
            .find_iter(output)
            .map(|m| m.as_str().trim_end_matches('.').to_lowercase())
            .collect();
        assert!(hosts.contains(&"sub.corp.local".to_string()));
        assert!(hosts.contains(&"admin.inlanefreight.local".to_string()));
        assert!(hosts.contains(&"host.htb".to_string()));
    }

    #[test]
    fn does_not_match_plain_ips() {
        let output = "10.10.10.3\n192.168.1.1";
        assert!(RE_HOST.find_iter(output).next().is_none());
    }
}
