use anyhow::Result;
use colored::Colorize;

use crate::config::{ScanConfig, find_wordlist};
use crate::report::Report;
use crate::runner;

/// SMTP: banner, VRFY/EXPN support, user enum, open relay check.
pub async fn check(ip: &str, port: u16, scan_cfg: &ScanConfig, report: &Report) -> Result<()> {
    println!("{} SMTP enumeration on port {port}...", "[*]".cyan());
    report.section("SMTP").await;

    // grab the banner — the server greets with 220 on connect
    let banner = runner::tcp_probe(ip, port, b"QUIT\r\n", 5).await?;

    if !banner.is_empty() {
        let first = banner.lines().next().unwrap_or("");
        println!("{} Banner: {}", "[+]".green(), first.cyan());
        report.add(&format!("  Banner: {first}")).await;
    }

    // check if VRFY is enabled (user enumeration). The probe pipelines
    // HELO + VRFY + QUIT, so the server sends: greeting, HELO reply, VRFY
    // reply, QUIT reply. We must read the VRFY reply specifically — scanning
    // the whole blob would always hit the HELO `250` and report a false
    // positive on servers that actually reject VRFY.
    let vrfy = runner::tcp_probe(ip, port, b"HELO x\r\nVRFY root\r\nQUIT\r\n", 5).await?;

    // 250 = user confirmed, 251 = user not local but will forward — both leak
    // whether an address exists. 252 (cannot verify), 502 (not implemented),
    // 550 (unknown user) and friends don't, so they count as restricted.
    if matches!(command_reply(&vrfy, 2), Some(250 | 251)) {
        println!(
            "{} VRFY command supported — user enumeration possible",
            "[+]".green()
        );
        report.add("  VRFY: supported (user enum possible)").await;
    } else {
        println!("{} VRFY disabled or restricted", "[!]".yellow());
        report.add("  VRFY: disabled/restricted").await;
    }

    // EXPN (mailing list expansion) — same pipelining, so read the EXPN reply
    // (2nd command) rather than matching any 250 in the exchange.
    let expn = runner::tcp_probe(ip, port, b"HELO x\r\nEXPN root\r\nQUIT\r\n", 5).await?;

    if matches!(command_reply(&expn, 2), Some(250 | 251)) {
        println!("{} EXPN command supported", "[+]".green());
        report.add("  EXPN: supported").await;
    }

    // automated user enumeration if the tool is installed
    let smtp_user_enum = scan_cfg.tool("smtp-user-enum");
    if runner::command_exists(&smtp_user_enum).await
        && let Some(userlist) = find_wordlist(&scan_cfg.wordlists.usernames_short)
    {
        println!("{} Running smtp-user-enum...", "[*]".cyan());
        let (enum_ok, enum_result) = runner::run_cmd_status(
            &smtp_user_enum,
            &[
                "-M",
                "VRFY",
                "-U",
                &userlist,
                "-t",
                ip,
                "-p",
                &port.to_string(),
            ],
            60,
        )
        .await?;
        if !enum_ok {
            report
                .add_error(
                    "SMTP",
                    &format!("smtp-user-enum failed: {}", enum_result.trim()),
                )
                .await;
        }

        let users: Vec<&str> = enum_result
            .lines()
            .filter(|l| l.contains("exists"))
            .collect();

        if !users.is_empty() {
            println!("{} Found {} valid user(s)!", "[+]".green(), users.len());
            report.add(&format!("  Users found: {}", users.len())).await;
            for u in &users {
                println!("    {}", u.cyan());
                report.add(&format!("    {u}")).await;
            }
        } else {
            println!("{} No users found via VRFY", "[!]".yellow());
        }
    }

    // open relay check. Pipeline is HELO / MAIL FROM / RCPT TO / QUIT, so the
    // replies are: greeting, HELO, MAIL FROM, RCPT TO, QUIT. Only the RCPT TO
    // reply (3rd command) decides relaying — MAIL FROM answers 250 even on a
    // locked-down server, so keying off any "250 Ok" cries relay on stock
    // Postfix, which then rejects RCPT with 554 Relay access denied.
    let relay = runner::tcp_probe(
        ip,
        port,
        b"HELO test\r\nMAIL FROM:<test@test.com>\r\nRCPT TO:<test@external.com>\r\nQUIT\r\n",
        5,
    )
    .await?;

    if command_reply(&relay, 3) == Some(250) {
        println!("{} Possible OPEN RELAY detected!", "[+]".green().bold());
        report.add("  *** OPEN RELAY DETECTED ***").await;
    }

    Ok(())
}

/// Extract SMTP *final* reply codes from a raw server response, in order.
///
/// SMTP is lockstep: the server greets with one reply (220) and then answers
/// each pipelined command with exactly one reply. A reply may span several
/// lines via `250-` continuation prefixes; only the final line (`250 <text>`)
/// carries the effective code, so continuations are skipped and each reply
/// contributes a single code. Callers then pick a command's reply by position
/// instead of scanning the whole blob (which conflates the HELO `250` with a
/// later VRFY/EXPN/RCPT reply).
fn reply_codes(resp: &str) -> Vec<u16> {
    resp.lines()
        .filter_map(|line| {
            let b = line.as_bytes();
            if b.len() < 3 || !b[..3].iter().all(|c| c.is_ascii_digit()) {
                return None;
            }
            // A '-' in the 4th column marks a continuation line; a space (or
            // end of line) marks the final line of the reply.
            match b.get(3) {
                None | Some(b' ') => line[..3].parse::<u16>().ok(),
                _ => None,
            }
        })
        .collect()
}

/// Reply code for the nth pipelined command (1-based), skipping the greeting.
/// Index 0 is the 220 greeting, so command N sits at index N. Returns `None`
/// if the dialog ended before that command was answered.
fn command_reply(resp: &str, nth: usize) -> Option<u16> {
    reply_codes(resp).get(nth).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_codes_skips_continuations_and_banner() {
        // a multiline 220 greeting collapses to a single reply
        let resp = "220-mail ESMTP\r\n220 ready\r\n250 mail.example.com\r\n221 Bye\r\n";
        assert_eq!(reply_codes(resp), vec![220, 250, 221]);
    }

    #[test]
    fn reply_codes_ignores_noise_lines() {
        let resp = "220 hi\r\nsome banner text\r\n250 ok\r\n";
        assert_eq!(reply_codes(resp), vec![220, 250]);
    }

    #[test]
    fn vrfy_rejected_is_not_supported() {
        // the HELO 250 must NOT be mistaken for VRFY support (the old bug)
        let resp = "220 mail ESMTP\r\n250 mail\r\n550 5.1.1 unknown user\r\n221 Bye\r\n";
        assert!(!matches!(command_reply(resp, 2), Some(250 | 251)));
    }

    #[test]
    fn vrfy_not_implemented_is_not_supported() {
        let resp = "220 mail\r\n250 mail\r\n502 5.5.1 VRFY disabled\r\n221 Bye\r\n";
        assert_eq!(command_reply(resp, 2), Some(502));
    }

    #[test]
    fn vrfy_confirmed_is_supported() {
        let resp = "220 mail\r\n250 mail\r\n250 2.1.5 root <root@mail>\r\n221 Bye\r\n";
        assert!(matches!(command_reply(resp, 2), Some(250 | 251)));
    }

    #[test]
    fn relay_denied_on_stock_postfix() {
        // MAIL FROM answers 250 Ok, but RCPT TO to an external domain is denied.
        // The RCPT reply (command 3) is what matters — not the MAIL FROM 250.
        let resp = "220 mail ESMTP Postfix\r\n250 mail\r\n250 2.1.0 Ok\r\n\
                    554 5.7.1 <test@external.com>: Relay access denied\r\n221 2.0.0 Bye\r\n";
        assert_ne!(command_reply(resp, 3), Some(250));
    }

    #[test]
    fn relay_open_when_rcpt_accepted() {
        let resp = "220 mail\r\n250 mail\r\n250 2.1.0 Ok\r\n250 2.1.5 Ok\r\n221 Bye\r\n";
        assert_eq!(command_reply(resp, 3), Some(250));
    }
}
