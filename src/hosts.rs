use std::sync::LazyLock;

use anyhow::Result;
use colored::Colorize;
use regex::Regex;

use crate::runner;

// strict: only alphanumeric, dots, hyphens
static VALID_HOSTNAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$").unwrap());

/// Make sure this is a real hostname and not something that could mess up /etc/hosts.
pub fn is_valid_hostname(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.contains('.')
        && VALID_HOSTNAME.is_match(h)
        && !h.contains("..")
}

/// A valid scan target is either a parseable IP address or a sane hostname.
/// Validating this up front means the target can never carry shell metacharacters
/// into the few commands that still shell out (openssl/impacket pipelines).
pub fn is_valid_target(t: &str) -> bool {
    t.parse::<std::net::IpAddr>().is_ok() || is_valid_hostname(t)
}

// Serialize the /etc/hosts read-modify-write. add_hosts is called from the
// foreground pipeline *and* from spawned background tasks (LDAP, web); without
// this lock two callers could each read the old file, then the second `sudo
// install` clobbers the first's additions (a lost hostname). A single trusted
// user, so contention is near zero — this just closes the latent race.
static HOSTS_LOCK: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Does this `/etc/hosts` line already list `host` for the target IP? Only the
/// entry part (before any `#` comment) counts, so a commented-out name doesn't
/// suppress a real re-add.
fn line_lists_host(line: &str, ip_re: &Regex, host: &str) -> bool {
    ip_re.is_match(line)
        && line
            .split('#')
            .next()
            .unwrap_or(line)
            .split_whitespace()
            .skip(1)
            .any(|existing| existing == host)
}

/// Append `new_hosts` to an existing `/etc/hosts` line, keeping any trailing
/// `# comment` *after* the names. Appending blindly would push the new names
/// behind the `#`, where they'd be treated as a comment and never resolve —
/// silently breaking every later web/vhost scan that targets them.
fn append_to_line(line: &str, new_hosts: &[String]) -> String {
    match line.split_once('#') {
        Some((entry, comment)) => {
            format!("{}  {}  #{comment}", entry.trim_end(), new_hosts.join(" "))
        }
        None => format!("{}  {}", line.trim_end(), new_hosts.join(" ")),
    }
}

/// Compute the new `/etc/hosts` contents after adding `hostnames` for `ip`.
///
/// Returns `Some((new_content, added))` — `added` being the names actually
/// appended — or `None` when every candidate was invalid or already present.
/// Pure (no I/O or sudo) so the dedup and comment-safe append logic can be
/// unit-tested directly.
fn merge_hosts(
    existing: &str,
    ip: &str,
    hostnames: &[String],
) -> Result<Option<(String, Vec<String>)>> {
    let ip_re = Regex::new(&format!(r"^{}\s+", regex::escape(ip)))?;

    // only keep valid, new hostnames we haven't seen before
    let mut new_hosts: Vec<String> = Vec::new();
    for h in hostnames {
        let h = h.to_lowercase().replace(['\r', '\n'], "");
        if h == ip || !is_valid_hostname(&h) {
            continue;
        }
        let already = existing
            .lines()
            .any(|line| line_lists_host(line, &ip_re, &h));
        if !already && !new_hosts.contains(&h) {
            new_hosts.push(h);
        }
    }

    if new_hosts.is_empty() {
        return Ok(None);
    }

    let mut lines: Vec<String> = existing.lines().map(|l| l.to_string()).collect();
    match lines.iter().position(|line| ip_re.is_match(line)) {
        Some(idx) => lines[idx] = append_to_line(&lines[idx], &new_hosts),
        None => lines.push(format!("{ip}  {}", new_hosts.join(" "))),
    }

    Ok(Some((lines.join("\n") + "\n", new_hosts)))
}

/// Add discovered hostnames to /etc/hosts (one line per IP).
/// Skips anything that looks sketchy or is already there.
pub async fn add_hosts(ip: &str, hostnames: &[String]) -> Result<()> {
    // hold the lock across the whole read-modify-write (see HOSTS_LOCK)
    let _guard = HOSTS_LOCK.lock().await;

    let hosts_content = tokio::fs::read_to_string("/etc/hosts")
        .await
        .unwrap_or_default();

    let Some((content, added)) = merge_hosts(&hosts_content, ip, hostnames)? else {
        return Ok(());
    };

    if !runner::has_sudo().await {
        println!("{} No passwordless sudo -- add manually:", "[!]".yellow());
        println!("    {ip}  {}", added.join(" "));
        return Ok(());
    }

    // hand the assembled content to sudo install via a temp file (content is
    // data, never interpolated into a shell command)
    // a failed /etc/hosts write must NOT abort the whole scan — warn and continue
    if let Err(e) = write_hosts_sudo(&content).await {
        println!("{} Could not update /etc/hosts: {e}", "[!]".yellow());
        println!("    add manually: {ip}  {}", added.join(" "));
    } else {
        println!(
            "{} Updated /etc/hosts: {}  {}",
            "[+]".green(),
            ip.cyan(),
            added.join(" ").cyan()
        );
    }

    Ok(())
}

/// Atomically replace `/etc/hosts` with `content`.
///
/// Writes to a temporary file in /tmp first, then uses `sudo install -m 644` to
/// move it into place. This guarantees that `/etc/hosts` is never observed in a
/// partially-written state, even if the process is killed mid-write. A timeout
/// guards against a password prompt or hung sudo.
async fn write_hosts_sudo(content: &str) -> Result<()> {
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::process::Command;

    // /tmp is world-writable: a predictable name (pid only) would let a local
    // attacker pre-create or swap the file before `sudo install` reads it back
    // (REVIEW.md finding 14). pid+nanos is unguessable enough, create_new
    // refuses to follow a planted file, and 0600 keeps others from rewriting
    // the content between our write and the install.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = format!("/tmp/hosts.pwnbox.{}.{nanos}", std::process::id());

    // write temp file as the current user
    {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .await?;
        file.write_all(content.as_bytes()).await?;
        file.flush().await?;
    }

    // atomically install it as /etc/hosts (preserving permissions)
    // kill_on_drop: without it a timed-out sudo would survive as an orphan
    // when the child handle is dropped on the timeout path below
    let mut child = Command::new("sudo")
        .args([
            "-n",
            "install",
            "-m",
            "644",
            "-o",
            "root",
            "-g",
            "root",
            &tmp,
            "/etc/hosts",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let result = tokio::time::timeout(Duration::from_secs(30), child.wait()).await;

    // best-effort cleanup of the temp file; ignore errors
    let _ = tokio::fs::remove_file(&tmp).await;

    match result {
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(status)) => {
            anyhow::bail!("Failed to write /etc/hosts (sudo install exited with {status})")
        }
        Ok(Err(e)) => anyhow::bail!("Failed to wait for sudo install: {e}"),
        Err(_) => anyhow::bail!("sudo install timed out after 30s (passwordless sudo required)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_hostnames() {
        assert!(is_valid_hostname("example.htb"));
        assert!(is_valid_hostname("sub.example.htb"));
        assert!(is_valid_hostname("my-host.htb"));
        assert!(is_valid_hostname("a.b"));
    }

    #[test]
    fn test_valid_targets() {
        assert!(is_valid_target("10.10.10.3")); // IPv4
        assert!(is_valid_target("::1")); // IPv6
        assert!(is_valid_target("dead:beef::1")); // IPv6
        assert!(is_valid_target("lame.htb")); // hostname
    }

    #[test]
    fn test_invalid_targets() {
        assert!(!is_valid_target("10.10.10.3; rm -rf /")); // injection attempt
        assert!(!is_valid_target("$(whoami)")); // command substitution
        assert!(!is_valid_target("has space")); // space
        assert!(!is_valid_target("")); // empty
    }

    #[test]
    fn test_invalid_hostnames() {
        assert!(!is_valid_hostname("")); // empty
        assert!(!is_valid_hostname("noperiod")); // no dot
        assert!(!is_valid_hostname(".leading.dot")); // starts with dot
        assert!(!is_valid_hostname("trailing.")); // ends with dot
        assert!(!is_valid_hostname("has spaces.htb")); // spaces
        assert!(!is_valid_hostname("semi;colon.htb")); // shell metachar
        assert!(!is_valid_hostname("back`tick.htb")); // shell metachar
        assert!(!is_valid_hostname("$(cmd).htb")); // shell injection
        assert!(!is_valid_hostname("double..dot.htb")); // double dot
        assert!(!is_valid_hostname(&"a".repeat(254))); // too long
    }

    #[test]
    fn merge_adds_a_new_line_when_ip_absent() {
        let (content, added) =
            merge_hosts("127.0.0.1 localhost\n", "10.10.10.3", &["lame.htb".into()])
                .unwrap()
                .expect("should add a line");
        assert_eq!(added, vec!["lame.htb".to_string()]);
        assert!(content.contains("10.10.10.3  lame.htb"));
        assert!(content.contains("127.0.0.1 localhost")); // existing content kept
    }

    #[test]
    fn merge_appends_to_the_existing_ip_line() {
        let (content, _) = merge_hosts(
            "10.10.10.3  lame.htb\n",
            "10.10.10.3",
            &["dev.lame.htb".into()],
        )
        .unwrap()
        .unwrap();
        let line = content
            .lines()
            .find(|l| l.starts_with("10.10.10.3"))
            .unwrap();
        assert!(line.contains("lame.htb") && line.contains("dev.lame.htb"));
    }

    #[test]
    fn merge_keeps_inline_comment_and_new_name_resolves() {
        // the bug this guards: appending after a "# comment" dropped the new
        // names behind the '#', so they were commented out and never resolved.
        let (content, _) = merge_hosts(
            "10.10.10.3  lame.htb  # HTB box\n",
            "10.10.10.3",
            &["dev.lame.htb".into()],
        )
        .unwrap()
        .unwrap();
        let line = content
            .lines()
            .find(|l| l.starts_with("10.10.10.3"))
            .unwrap();
        let hash = line.find('#').unwrap();
        let name = line.find("dev.lame.htb").unwrap();
        assert!(
            name < hash,
            "new name must sit before the comment: {line:?}"
        );
        assert!(line.contains("# HTB box"), "comment preserved: {line:?}");
    }

    #[test]
    fn merge_dedups_already_present_names_even_with_a_comment() {
        assert!(
            merge_hosts(
                "10.10.10.3  lame.htb  # note\n",
                "10.10.10.3",
                &["lame.htb".into()]
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn merge_skips_invalid_and_self_referential_names() {
        assert!(
            merge_hosts(
                "",
                "10.10.10.3",
                &["bad host".into(), "$(id).htb".into(), "10.10.10.3".into()],
            )
            .unwrap()
            .is_none()
        );
    }
}
