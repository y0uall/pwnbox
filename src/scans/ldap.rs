use std::path::Path;
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
    raw_dir: &Path,
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

    // The actual payoff: an anonymous subtree read of person objects. On HTB the
    // recurring win is a password left in a `description`/`info` field that
    // anonymous bind can read — base-DN discovery alone never surfaces it.
    if !base_dn.is_empty() {
        dump_directory(&ldapsearch, &endpoint, &base_dn, raw_dir, report).await;
    }

    Ok(domain)
}

/// Pull identity and secret-bearing fields out of an ldapsearch subtree dump.
/// Returns `(users, secrets)`: `users` from sAMAccountName/userPrincipalName,
/// `secrets` the full `field: value` lines for description/info/userPassword —
/// the fields that hide credentials on HTB AD boxes.
fn parse_ldap_entries(output: &str) -> (Vec<String>, Vec<String>) {
    let mut users: Vec<String> = Vec::new();
    let mut secrets: Vec<String> = Vec::new();
    for line in output.lines() {
        let l = line.trim();
        if let Some(v) = l
            .strip_prefix("sAMAccountName:")
            .or_else(|| l.strip_prefix("userPrincipalName:"))
        {
            let v = v.trim().to_string();
            if !v.is_empty() && !users.contains(&v) {
                users.push(v);
            }
        } else if (l.starts_with("description:")
            || l.starts_with("info:")
            || l.starts_with("userPassword:"))
            && !secrets.iter().any(|s| s == l)
        {
            secrets.push(l.to_string());
        }
    }
    (users, secrets)
}

/// Best-effort anonymous subtree dump. Never bails — a failure here is recorded
/// and the caller still returns whatever the base-DN query found.
async fn dump_directory(
    ldapsearch: &str,
    endpoint: &str,
    base_dn: &str,
    raw_dir: &Path,
    report: &Report,
) {
    println!(
        "{} Dumping person objects (anonymous subtree)...",
        "[*]".cyan()
    );
    let (success, output) = match runner::run_cmd_status_env(
        ldapsearch,
        &[
            "-x",
            "-H",
            endpoint,
            "-b",
            base_dn,
            "(objectClass=person)",
            "sAMAccountName",
            "userPrincipalName",
            "description",
            "info",
            "memberOf",
        ],
        &[("LDAPTLS_REQCERT", "never")],
        60,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            println!("{} Directory dump failed: {e}", "[!]".yellow());
            report.add_error("LDAP", &e.to_string()).await;
            return;
        }
    };

    if !success && output.trim().is_empty() {
        return;
    }

    // keep the full dump so the operator can grep it later
    let path = raw_dir.join("ldap-users.txt");
    if let Err(e) = tokio::fs::write(&path, &output).await {
        report
            .add_error("LDAP", &format!("could not write {}: {e}", path.display()))
            .await;
    }

    let (users, secrets) = parse_ldap_entries(&output);
    if users.is_empty() && secrets.is_empty() {
        println!(
            "{} Anonymous subtree returned no person objects",
            "[!]".yellow()
        );
        return;
    }

    if !users.is_empty() {
        println!(
            "{} {} user object(s) readable anonymously",
            "[+]".green(),
            users.len()
        );
        report.add(&format!("  Users ({}):", users.len())).await;
        for u in &users {
            report.add(&format!("    {u}")).await;
            report
                .add_service_finding("ldap", &format!("user: {u}"))
                .await;
        }
    }
    for s in &secrets {
        println!("{} Possible secret in LDAP: {}", "[+]".green(), s.yellow());
        report.add(&format!("  {s}")).await;
        report
            .add_vuln(&format!(
                "LDAP: secret-bearing field readable anonymously — {s}"
            ))
            .await;
    }
    if path.exists() {
        report
            .add(&format!("  (full dump: {})", path.display()))
            .await;
    }
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

    #[test]
    fn parse_entries_extracts_users_and_secret_fields() {
        // a trimmed-down anonymous ldapsearch dump — the classic HTB shape with
        // a password sitting in `info`
        let dump = "\
dn: CN=Guest,CN=Users,DC=htb,DC=local
sAMAccountName: guest
userPrincipalName: svc-web@htb.local
description: Service account
info: Set initial password to Welcome2024!
memberOf: CN=Domain Users,DC=htb,DC=local
";
        let (users, secrets) = parse_ldap_entries(dump);
        assert!(users.contains(&"guest".to_string()));
        assert!(users.contains(&"svc-web@htb.local".to_string()));
        assert!(secrets.iter().any(|s| s.contains("Welcome2024!")));
        assert!(secrets.iter().any(|s| s.starts_with("description:")));
        // memberOf is context, not a secret
        assert!(!secrets.iter().any(|s| s.starts_with("memberOf")));
    }
}
