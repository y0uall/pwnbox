use std::sync::LazyLock;

use anyhow::{Result, bail};
use colored::Colorize;
use regex::Regex;

use crate::config::ScanConfig;
use crate::hosts;
use crate::report::Report;
use crate::runner;

// The base DN from an LDAP `namingContexts` reply, then its DC= components.
static RE_NAMING_CONTEXT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"namingContexts:\s*(.*)").unwrap());
static RE_DC_COMPONENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"DC=([^,]+)").unwrap());

fn ldap_endpoint(ip: &str, port: u16) -> String {
    let scheme = if port == 636 { "ldaps" } else { "ldap" };
    let host = if ip.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{ip}]")
    } else {
        ip.to_string()
    };
    format!("{scheme}://{host}:{port}")
}

/// Try anonymous LDAP bind, pull out the domain if we can.
pub async fn enumerate(
    ip: &str,
    port: u16,
    scan_cfg: &ScanConfig,
    report: &Report,
) -> Result<Option<String>> {
    report.section("LDAP").await;

    let ldapsearch = scan_cfg.tool("ldapsearch");
    if !runner::command_exists(&ldapsearch).await {
        println!(
            "{} ldapsearch not found -- skipping LDAP enum",
            "[!]".yellow()
        );
        report.add("  (ldapsearch not installed)").await;
        return Ok(None);
    }

    let endpoint = ldap_endpoint(ip, port);
    println!(
        "{} Anonymous bind -- querying base DN via {}...",
        "[*]".cyan(),
        endpoint.yellow()
    );
    // HTB LDAP-over-TLS commonly uses a self-signed certificate.
    let (success, output) = runner::run_cmd_status_env(
        &ldapsearch,
        &["-x", "-H", &endpoint, "-s", "base", "namingContexts"],
        &[("LDAPTLS_REQCERT", "never")],
        30,
    )
    .await?;

    if !success {
        let lower = output.to_lowercase();
        if lower.contains("operations error")
            || lower.contains("invalid credentials")
            || lower.contains("insufficient access")
        {
            println!("{} Anonymous bind denied", "[!]".yellow());
            report.add("  (anonymous bind denied)").await;
            return Ok(None);
        }
        bail!("ldapsearch failed for {endpoint}: {}", output.trim());
    }
    if output.trim().is_empty() {
        bail!("ldapsearch returned an empty response for {endpoint}");
    }

    // grab the base DN
    let base_dn = RE_NAMING_CONTEXT
        .captures(&output)
        .map(|c| c[1].trim().to_string())
        .unwrap_or_default();

    println!(
        "{} Base DN: {}",
        "[+]".green(),
        if base_dn.is_empty() {
            "unknown"
        } else {
            &base_dn
        }
        .cyan()
    );
    println!("{output}");
    report.add(&output).await;

    // reconstruct domain from DC= components
    let mut domain = None;
    if !base_dn.is_empty() {
        let parts: Vec<String> = RE_DC_COMPONENT
            .captures_iter(&base_dn)
            .map(|c| c[1].to_string())
            .collect();
        if !parts.is_empty() {
            let dom = parts.join(".");
            println!("{} Domain: {}", "[+]".green(), dom.cyan());
            report.add(&format!("  Domain: {dom}")).await;
            hosts::add_hosts(ip, std::slice::from_ref(&dom)).await?;
            domain = Some(dom);
        }
    }

    Ok(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_uses_plain_ldap_on_389() {
        assert_eq!(ldap_endpoint("10.10.10.10", 389), "ldap://10.10.10.10:389");
    }

    #[test]
    fn endpoint_uses_ldaps_and_brackets_ipv6() {
        assert_eq!(ldap_endpoint("10.10.10.10", 636), "ldaps://10.10.10.10:636");
        assert_eq!(ldap_endpoint("::1", 636), "ldaps://[::1]:636");
    }
}
