use std::path::Path;

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

/// Keep the useful lines from smbmap's recursive output: accessible-share rows
/// (READ/WRITE) and the file/dir entries under them (smbmap prints those with a
/// `dr--r--r--` / `fr--r--r--` permission prefix). Drops banners and NO-ACCESS
/// noise. Pure so it can be tested against a canned fixture.
fn smbmap_key_lines(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim_end)
        .filter(|l| {
            let t = l.trim_start();
            let up = t.to_uppercase();
            up.contains("READ")
                || up.contains("WRITE")
                || t.starts_with("dr")
                || t.starts_with("dw")
                || t.starts_with("fr")
                || t.starts_with("fw")
        })
        .map(str::to_string)
        .collect()
}

/// smbmap: recursively spider readable shares with a null session. This is the
/// real SMB payoff on HTB — the loot is almost always a *file inside* a share
/// (backup scripts, web.config, an .xml with creds), not the share name that
/// enum4linux/cme already print. The full listing is saved to raw/ for grepping.
async fn probe_smbmap(ip: &str, bin: &str, raw_dir: &Path) -> Result<Option<SmbOutcome>> {
    if !runner::command_exists(bin).await {
        return Ok(None);
    }
    println!("{} smbmap (recursive, null session)...", "[*]".cyan());
    let output = match runner::run_cmd_timeout(
        bin,
        &["-H", ip, "-u", "", "-p", "", "-R", "--depth", "5"],
        runner::default_timeout().min(120),
    )
    .await
    {
        Ok(o) => strip_ansi(&o),
        Err(e) => {
            println!("{} smbmap failed: {e}", "[!]".yellow());
            return Ok(Some(SmbOutcome {
                text: String::new(),
                error: Some(e.to_string()),
            }));
        }
    };

    // save the full recursive listing before filtering it down for the report
    let path = raw_dir.join("smbmap.txt");
    let error = tokio::fs::write(&path, &output)
        .await
        .err()
        .map(|e| format!("could not write {}: {e}", path.display()));

    let mut lines: Vec<String> = smbmap_key_lines(&output).into_iter().take(60).collect();
    if !lines.is_empty() && path.exists() {
        lines.push(format!("  (full listing: {})", path.display()));
    }
    Ok(Some(SmbOutcome {
        text: lines.join("\n"),
        error,
    }))
}

/// cme/nxc SMB enumeration, run sequentially (one shared nxc DB, so no
/// concurrent invocations): null-session shares, then a guest-session share list
/// (works on boxes where null is blocked), then RID cycling (domain users even
/// when enumdomusers is restricted). All soft failures; 120s cap per call.
async fn probe_cme(ip: &str, cme: &str) -> Result<Option<SmbOutcome>> {
    let (label, bin) = if runner::command_exists(cme).await {
        ("CrackMapExec", cme.to_string())
    } else if runner::command_exists("netexec").await {
        ("NetExec", "netexec".to_string())
    } else {
        return Ok(None);
    };

    let cap = runner::default_timeout().min(120);
    let mut lines: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    println!("{} {label} SMB (null session)...", "[*]".cyan());
    match runner::run_cmd_timeout(&bin, &["smb", ip, "--shares", "-u", "", "-p", ""], cap).await {
        Ok(out) => lines.extend(cme_report_lines(&out)),
        Err(e) => errors.push(format!("null --shares failed: {e}")),
    }

    println!("{} {label} SMB (guest session)...", "[*]".cyan());
    match runner::run_cmd_timeout(&bin, &["smb", ip, "--shares", "-u", "guest", "-p", ""], cap)
        .await
    {
        Ok(out) => lines.extend(cme_report_lines(&out)),
        Err(e) => errors.push(format!("guest --shares failed: {e}")),
    }

    println!("{} {label} SMB (RID brute)...", "[*]".cyan());
    match runner::run_cmd_timeout(&bin, &["smb", ip, "-u", "", "-p", "", "--rid-brute"], cap).await
    {
        // RID cycling is noisy — keep only the actual user accounts, capped
        Ok(out) => lines.extend(
            cme_report_lines(&out)
                .into_iter()
                .filter(|l| l.contains("SidTypeUser"))
                .take(80),
        ),
        Err(e) => errors.push(format!("rid-brute failed: {e}")),
    }

    // null + guest often echo the same shares — dedup while keeping order
    let mut seen = std::collections::HashSet::new();
    lines.retain(|l| seen.insert(l.clone()));

    let error = (!errors.is_empty()).then(|| format!("{label}: {}", errors.join("; ")));
    Ok(Some(SmbOutcome {
        text: lines.join("\n"),
        error,
    }))
}

/// Throw everything we have at SMB: enum4linux, smbclient, cme/nxc — all
/// running concurrently instead of back-to-back (REVIEW.md finding 8).
pub async fn enumerate(
    ip: &str,
    scan_cfg: &ScanConfig,
    raw_dir: &Path,
    report: &Report,
) -> Result<()> {
    report.section("SMB").await;

    let enum4linux = scan_cfg.tool("enum4linux-ng");
    let smbclient = scan_cfg.tool("smbclient");
    let cme = scan_cfg.tool("crackmapexec");
    let smbmap = scan_cfg.tool("smbmap");

    let (e4l, smb, cme, mapped) = tokio::join!(
        probe_enum4linux(ip, &enum4linux),
        probe_smbclient(ip, &smbclient),
        probe_cme(ip, &cme),
        probe_smbmap(ip, &smbmap, raw_dir),
    );

    // apply outcomes in a fixed order — only smbclient's runner error
    // propagates (it did in the serial version, too)
    for outcome in [e4l?, smb?, cme?, mapped?].into_iter().flatten() {
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
    use super::{cme_report_lines, smbmap_key_lines};

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

    #[test]
    fn smbmap_keeps_accessible_shares_and_files_drops_noise() {
        // trimmed smbmap -R output: banner + NO ACCESS shares + a readable share
        // with a file entry underneath
        let out = "\
[+] IP: 10.10.10.3:445\tName: lame.htb
\tDisk                          Permissions\tComment
\t----                          -----------\t-------
\tADMIN$                        NO ACCESS\tRemote Admin
\tIPC$                          READ ONLY\tRemote IPC
\ttmp                           READ, WRITE
\t.\\tmp\\*
\tfr--r--r--             1024 Mon  secret.txt
";
        let lines = smbmap_key_lines(out);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("IPC$") && l.contains("READ ONLY"))
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("tmp") && l.contains("READ, WRITE"))
        );
        assert!(lines.iter().any(|l| l.contains("secret.txt")));
        assert!(!lines.iter().any(|l| l.contains("NO ACCESS")));
        assert!(!lines.iter().any(|l| l.contains("Remote Admin")));
    }
}
