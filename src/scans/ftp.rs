use anyhow::Result;
use colored::Colorize;

use crate::config::ScanConfig;
use crate::report::Report;
use crate::runner;

/// Try anonymous FTP login.
pub async fn check_anonymous(ip: &str, scan_cfg: &ScanConfig, report: &Report) -> Result<()> {
    report.section("FTP").await;

    // curl exits 0 only when the anonymous login succeeded and the directory
    // listing was retrieved. Under `-s` curl stays silent on an auth failure,
    // so the exit status — not the output text — is the reliable signal:
    // matching on error strings misses server-specific 530 wordings (Pure-FTPd
    // says "Login authentication failed", not "Login incorrect"), and a
    // successful login to an empty directory produces no output at all.
    let (login_ok, output) = runner::run_cmd_status(
        &scan_cfg.tool("curl"),
        &[
            "-s",
            "--max-time",
            "10",
            &format!("ftp://{ip}/"),
            "--user",
            "anonymous:anonymous",
        ],
        15,
    )
    .await
    .unwrap_or((false, String::new()));

    if login_ok {
        println!("{} Anonymous FTP login successful!", "[+]".green());
        report.add("  Anonymous login: YES").await;
        if !output.trim().is_empty() {
            println!("{output}");
            report.add(&output).await;
        }
    } else {
        println!("{} Anonymous login failed", "[!]".yellow());
        report.add("  Anonymous login: NO").await;
    }

    Ok(())
}
