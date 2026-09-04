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
/// error/timeout) is recorded by the caller without losing other probe results.
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
/// noise. Keep directory headings so files retain their parent path.
fn smbmap_key_lines(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim_end)
        .filter(|l| {
            let t = l.trim_start();
            let up = t.to_uppercase();
            up.contains("READ")
                || up.contains("WRITE")
                || t.starts_with("./")
                || t.starts_with(".\\")
                || t.starts_with("dr")
                || t.starts_with("dw")
                || t.starts_with("fr")
                || t.starts_with("fw")
        })
        .map(str::to_string)
        .collect()
}

fn smbmap_access_denied(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    lower.contains("access denied")
        || lower.contains("status_access_denied")
        || lower.contains("status_logon_failure")
        || lower.contains("0 authenticated session")
}

/// smbmap: recursively spider readable shares with null/guest sessions. This is the
/// real SMB payoff on HTB — the loot is almost always a *file inside* a share
/// (backup scripts, web.config, an .xml with creds), not the share name that
/// enum4linux/cme already print. The full listing is saved to raw/ for grepping.
async fn probe_smbmap(ip: &str, bin: &str, raw_dir: &Path) -> Result<Option<SmbOutcome>> {
    if !runner::command_exists(bin).await {
        return Ok(None);
    }
    let started = std::time::Instant::now();
    let cap = runner::default_timeout().min(120);
    let mut output = String::new();
    let mut lines = Vec::new();
    let mut errors = Vec::new();
    for user in ["", "guest"] {
        let label = if user.is_empty() { "null" } else { "guest" };
        println!("{} smbmap (recursive, {label} session)...", "[*]".cyan());
        // Both attempts share the same budget. Only retry a denied/unauthenticated
        // null session with no listing; a transport failure must not double it.
        let remaining = cap.saturating_sub(started.elapsed().as_secs());
        if remaining == 0 {
            errors.push("smbmap session probes exhausted their timeout".to_string());
            break;
        }
        // Current SMBMap uses lowercase -r; the old -R is rejected by argparse.
        let attempt = match runner::run_cmd_timeout(
            bin,
            &["-H", ip, "-u", user, "-p", "", "-r", "--depth", "5"],
            remaining,
        )
        .await
        {
            Ok(o) => strip_ansi(&o),
            Err(e) => {
                println!("{} smbmap failed: {e}", "[!]".yellow());
                errors.push(format!("smbmap {label} session: {e}"));
                break;
            }
        };
        lines.extend(smbmap_key_lines(&attempt));
        output.push_str(&format!("=== {label} session ===\n{attempt}\n"));
        if !user.is_empty() || !lines.is_empty() || !smbmap_access_denied(&attempt) {
            break;
        }
    }

    // save the full recursive listing before filtering it down for the report
    let path = raw_dir.join("smbmap.txt");
    if !output.is_empty()
        && let Err(e) = tokio::fs::write(&path, &output).await
    {
        errors.push(format!("could not write {}: {e}", path.display()));
    }

    lines.truncate(60);
    if !lines.is_empty() && path.exists() {
        lines.push(format!("  (full listing: {})", path.display()));
    } else if lines.is_empty() && errors.is_empty() {
        lines.push("  (smbmap: no share listing available with the tested sessions)".to_string());
    }
    Ok(Some(SmbOutcome {
        text: lines.join("\n"),
        error: (!errors.is_empty()).then(|| errors.join("; ")),
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

    record_outcomes([e4l, smb, cme, mapped], report).await;
    Ok(())
}

async fn record_outcomes(outcomes: [Result<Option<SmbOutcome>>; 4], report: &Report) {
    // Preserve successful siblings when one tool fails or times out.
    for outcome in outcomes {
        let outcome = match outcome {
            Ok(Some(outcome)) => outcome,
            Ok(None) => continue,
            Err(e) => {
                println!("{} SMB probe failed: {e}", "[!]".yellow());
                report.add_error("SMB", &e.to_string()).await;
                continue;
            }
        };
        if !outcome.text.is_empty() {
            println!("{}", outcome.text);
            report.add_service("smb", &outcome.text).await;
        }
        if let Some(detail) = outcome.error {
            report.add_error("SMB", &detail).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{cme_report_lines, smbmap_key_lines};

    #[tokio::test]
    async fn smbmap_retries_denied_null_session_as_guest_and_keeps_both_outputs() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("pwnbox_smbmap_guest_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("smbmap-stub");
        std::fs::write(&bin, r#"#!/bin/sh
[ "$5" = '-p' ] && [ "$7" = '-r' ] || exit 2
if [ "$4" = '' ]; then
    printf '[*] Established 1 SMB connections(s) and 0 authenticated session(s)\n[!] Access denied on 192.0.2.1\n'
elif [ "$4" = guest ]; then
    printf 'backups READ ONLY\nfr--r--r-- 609 prod.dtsConfig\n'
else
    exit 3
fi
"#).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700)).unwrap();
        let result = super::probe_smbmap("192.0.2.1", bin.to_str().unwrap(), &dir)
            .await
            .unwrap()
            .unwrap();
        assert!(result.error.is_none(), "{:?}", result.error);
        assert!(result.text.contains("backups READ ONLY"));
        assert!(result.text.contains("prod.dtsConfig"));
        let raw = std::fs::read_to_string(dir.join("smbmap.txt")).unwrap();
        assert!(raw.contains("=== null session ==="));
        assert!(raw.contains("Access denied"));
        assert!(raw.contains("=== guest session ==="));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn failed_probe_keeps_other_findings() {
        let report = crate::report::Report::new();
        super::record_outcomes(
            [
                Ok(Some(super::SmbOutcome {
                    text: "user: alice".into(),
                    error: None,
                })),
                Err(anyhow::anyhow!("smbclient timed out")),
                Ok(Some(super::SmbOutcome {
                    text: "share: backups".into(),
                    error: None,
                })),
                Ok(None),
            ],
            &report,
        )
        .await;
        assert_eq!(report.lines().await, vec!["user: alice", "share: backups"]);
        assert_eq!(report.errors().await, vec!["SMB: smbclient timed out"]);
    }

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
        // trimmed smbmap -r output: banner + NO ACCESS shares + a readable share
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
        assert!(lines.iter().any(|l| l.contains(".\\tmp\\*")));
        assert_eq!(
            smbmap_key_lines("\t./backups/config\n"),
            vec!["\t./backups/config"]
        );
        assert!(!lines.iter().any(|l| l.contains("NO ACCESS")));
        assert!(!lines.iter().any(|l| l.contains("Remote Admin")));
    }
}
