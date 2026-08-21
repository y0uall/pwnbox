use anyhow::Result;
use colored::Colorize;

use crate::report::Report;
use crate::runner;

/// Grab the SSH banner and flag known-weak versions.
pub async fn check(ip: &str, report: &Report) -> Result<()> {
    report.section("SSH").await;

    // quick banner grab — SSH servers send their banner on connect
    let output = runner::tcp_probe(ip, 22, b"", 5).await?;

    let banner = output.lines().next().unwrap_or("").trim();
    if !banner.is_empty() {
        println!("{} SSH banner: {}", "[+]".green(), banner.cyan());
        report.add(&format!("  Banner: {banner}")).await;

        // flag old/weak versions
        let lower = banner.to_lowercase();
        if lower.contains("openssh_7.")
            || lower.contains("openssh_6.")
            || lower.contains("openssh_5.")
        {
            println!(
                "{} Old OpenSSH version detected — check for known CVEs!",
                "[!]".red()
            );
            report.add("  ⚠ Old OpenSSH version — check CVEs").await;
            report
                .add_vuln(&format!("SSH: Old OpenSSH version ({banner})"))
                .await;
        }
        if lower.contains("libssh") {
            println!(
                "{} libSSH detected — check CVE-2018-10933 (auth bypass)",
                "[!]".red()
            );
            report.add("  ⚠ libSSH — check CVE-2018-10933").await;
            report
                .add_vuln("SSH: libSSH detected — CVE-2018-10933 (auth bypass)")
                .await;
        }
    } else {
        println!("{} Could not grab SSH banner", "[!]".yellow());
        report.add("  (no banner)").await;
    }

    Ok(())
}
