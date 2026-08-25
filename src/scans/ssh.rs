use anyhow::Result;
use colored::Colorize;

use crate::report::Report;
use crate::runner;

/// Grab the SSH banner and flag known-weak versions.
pub async fn check(ip: &str, port: u16, report: &Report) -> Result<()> {
    report.section("SSH").await;

    // quick banner grab — SSH servers send their banner on connect
    let output = runner::tcp_probe(ip, port, b"", 5).await?;

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

#[cfg(test)]
mod tests {
    use super::*;

    /// REVIEW.md finding 7: the detected port must reach tcp_probe — a banner
    /// served on a non-standard port (2222, not 22) has to be picked up.
    #[tokio::test]
    async fn check_uses_the_detected_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:2222")
            .await
            .unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            use tokio::io::AsyncWriteExt;
            sock.write_all(b"SSH-2.0-OpenSSH_8.9p1 test-banner\r\n")
                .await
                .unwrap();
            // socket drops here -> EOF ends the client's read immediately
        });

        let report = Report::new();
        check("127.0.0.1", 2222, &report).await.unwrap();
        server.await.unwrap();

        assert!(
            report
                .lines()
                .await
                .iter()
                .any(|l| l.contains("SSH-2.0-OpenSSH_8.9p1 test-banner")),
            "banner from port 2222 must reach the report"
        );
    }
}
