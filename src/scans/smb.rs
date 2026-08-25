use anyhow::Result;
use colored::Colorize;

use crate::config::ScanConfig;
use crate::report::Report;
use crate::runner;
use crate::scans::strip_ansi;

/// One SMB sub-probe's outcome: the text block for the report and an optional
/// error to record. The probes run concurrently; the caller applies the
/// outcomes in a fixed order so the report layout never depends on which tool
/// finished first.
#[derive(Default)]
struct SmbOutcome {
    /// text for report.add (skipped when empty)
    text: String,
    /// detail for report.add_error("SMB", ...)
    error: Option<String>,
}

/// enum4linux-ng -A — gives the most info; its failures are soft (warn + record).
async fn probe_enum4linux(ip: &str, bin: &str) -> Result<Option<SmbOutcome>> {
    if !runner::command_exists(bin).await {
        return Ok(None);
    }
    println!("{} enum4linux-ng...", "[*]".cyan());
    let output = match runner::run_cmd_timeout(bin, &["-A", ip], 120).await {
        Ok(output) => output,
        Err(e) => {
            println!("{} enum4linux-ng failed: {e}", "[!]".yellow());
            return Ok(Some(SmbOutcome {
                text: String::new(),
                error: Some(e.to_string()),
            }));
        }
    };

    // enum4linux-ng colorizes even when piped — strip ANSI before anything
    // reaches the report
    let output = strip_ansi(&output);

    // pull out the interesting bits
    let key_lines: Vec<&str> = output
        .lines()
        .filter(|l| {
            let lower = l.to_lowercase();
            lower.contains("share")
                || lower.contains("user")
                || lower.contains("os info")
                || lower.contains("domain")
                || lower.contains("[+]")
                || lower.contains("[*]")
        })
        .take(40)
        .collect();

    Ok(Some(SmbOutcome {
        text: key_lines.join("\n"),
        error: None,
    }))
}

/// smbclient: list shares with a null session. A runner-level failure (spawn
/// error/timeout) propagates — it did in the serial version, too.
async fn probe_smbclient(ip: &str, bin: &str) -> Result<Option<SmbOutcome>> {
    if !runner::command_exists(bin).await {
        return Ok(None);
    }
    println!("{} Listing shares (null session)...", "[*]".cyan());
    // capped at 120s: the default timeout (300s+) made a hung smbclient the
    // long-pole of phase 5 (REVIEW.md finding 8)
    let (success, output) = runner::run_cmd_status(
        bin,
        &["-N", "-L", &format!("//{ip}")],
        runner::default_timeout().min(120),
    )
    .await?;

    let outcome = if success && output.contains("Sharename") {
        SmbOutcome {
            text: output,
            error: None,
        }
    } else if output.contains("NT_STATUS_ACCESS_DENIED")
        || output.contains("NT_STATUS_LOGON_FAILURE")
    {
        println!("{} No shares via null session", "[!]".yellow());
        SmbOutcome {
            text: "  (null session denied)".to_string(),
            error: None,
        }
    } else {
        let detail = format!("smbclient failed: {}", output.trim());
        println!("{} {detail}", "[!]".yellow());
        SmbOutcome {
            text: String::new(),
            error: Some(detail),
        }
    };
    Ok(Some(outcome))
}

/// Keep the meaningful cme/nxc smb lines for the report: result lines start
/// with the protocol column ("SMB"); first-run noise ("[*] Creating home
/// directory structure", default-config copying) and banners don't.
fn cme_report_lines(output: &str) -> Vec<String> {
    output
        .lines()
        .map(strip_ansi)
        .filter(|l| l.starts_with("SMB"))
        .collect()
}

/// cme/nxc share enumeration — failures are soft. Same 120s cap as smbclient.
async fn probe_cme(ip: &str, cme: &str) -> Result<Option<SmbOutcome>> {
    let (label, bin) = if runner::command_exists(cme).await {
        ("CrackMapExec", cme.to_string())
    } else if runner::command_exists("netexec").await {
        ("NetExec", "netexec".to_string())
    } else {
        return Ok(None);
    };
    println!("{} {label} SMB...", "[*]".cyan());
    match runner::run_cmd_timeout(
        &bin,
        &["smb", ip, "--shares", "-u", "", "-p", ""],
        runner::default_timeout().min(120),
    )
    .await
    {
        Ok(output) => Ok(Some(SmbOutcome {
            text: cme_report_lines(&output).join("\n"),
            error: None,
        })),
        Err(e) => {
            println!("{} {label} failed: {e}", "[!]".yellow());
            Ok(Some(SmbOutcome {
                text: String::new(),
                error: Some(e.to_string()),
            }))
        }
    }
}

/// Throw everything we have at SMB: enum4linux, smbclient, cme/nxc — all
/// running concurrently instead of back-to-back (REVIEW.md finding 8).
pub async fn enumerate(ip: &str, scan_cfg: &ScanConfig, report: &Report) -> Result<()> {
    report.section("SMB").await;

    let enum4linux = scan_cfg.tool("enum4linux-ng");
    let smbclient = scan_cfg.tool("smbclient");
    let cme = scan_cfg.tool("crackmapexec");

    let (e4l, smb, cme) = tokio::join!(
        probe_enum4linux(ip, &enum4linux),
        probe_smbclient(ip, &smbclient),
        probe_cme(ip, &cme),
    );

    // apply outcomes in a fixed order — only smbclient's runner error
    // propagates (it did in the serial version, too)
    for outcome in [e4l?, smb?, cme?].into_iter().flatten() {
        if !outcome.text.is_empty() {
            println!("{}", outcome.text);
            report.add(&outcome.text).await;
        }
        if let Some(detail) = outcome.error {
            report.add_error("SMB", &detail).await;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::cme_report_lines;

    #[test]
    fn drops_netexec_first_run_noise() {
        let output = "\
[*] First time use detected
[*] Creating home directory structure
[*] Copying default configuration file
SMB         10.0.0.1      445    DC01  [*] Windows 10.0 Build 26100 (signing:True)
SMB         10.0.0.1      445    DC01  [-] checkpoint.htb\\: STATUS_ACCESS_DENIED
";
        let lines = cme_report_lines(output);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("signing:True"));
        assert!(lines[1].contains("STATUS_ACCESS_DENIED"));
    }

    #[test]
    fn strips_ansi_from_tool_output() {
        let lines = cme_report_lines("\x1b[32mSMB  10.0.0.1  445  DC01  [+] IPC$\x1b[0m\n");
        assert_eq!(lines, vec!["SMB  10.0.0.1  445  DC01  [+] IPC$"]);
    }
}
