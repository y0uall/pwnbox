use std::sync::LazyLock;

use anyhow::{Context, Result};
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
// this lock two callers could each read the old file, then the second update
// clobbers the first's additions (a lost hostname). A single trusted
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
            .any(|existing| existing.eq_ignore_ascii_case(host))
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
/// Returns `Some((new_content, updated))` for added or reassigned names, or
/// `None` when every candidate was invalid or already mapped correctly.
/// Pure (no I/O or sudo) so the dedup and comment-safe append logic can be
/// unit-tested directly.
fn merge_hosts(
    existing: &str,
    ip: &str,
    hostnames: &[String],
) -> Result<Option<(String, Vec<String>)>> {
    let ip_re = Regex::new(&format!(r"^\s*{}\s+", regex::escape(ip)))?;

    let mut candidates: Vec<String> = Vec::new();
    for h in hostnames {
        let h = h.to_lowercase().replace(['\r', '\n'], "");
        if h == ip || !is_valid_hostname(&h) {
            continue;
        }
        if !candidates.contains(&h) {
            candidates.push(h);
        }
    }
    if candidates.is_empty() {
        return Ok(None);
    }

    // HTB instances change IPs. An older alias on a different address must
    // move, even if the new address already has it too. Keep unrelated aliases
    // and comments rather than removing the whole old entry.
    let mut moved = Vec::new();
    let mut lines = Vec::new();
    for line in existing.lines() {
        let (entry, comment) = line
            .split_once('#')
            .map_or((line, None), |(entry, comment)| (entry, Some(comment)));
        let fields: Vec<&str> = entry.split_whitespace().collect();
        if fields.len() < 2 || ip_re.is_match(line) {
            lines.push(line.to_string());
            continue;
        }
        let mut kept = vec![fields[0]];
        for alias in &fields[1..] {
            if let Some(host) = candidates.iter().find(|h| h.eq_ignore_ascii_case(alias)) {
                if !moved.contains(host) {
                    moved.push(host.clone());
                }
            } else {
                kept.push(alias);
            }
        }
        if kept.len() == fields.len() {
            lines.push(line.to_string());
        } else if kept.len() > 1 {
            let mut updated = kept.join("  ");
            if let Some(comment) = comment {
                updated.push_str(&format!("  #{comment}"));
            }
            lines.push(updated);
        } else if let Some(comment) = comment {
            lines.push(format!("#{comment}"));
        }
    }

    let new_hosts: Vec<String> = candidates
        .iter()
        .filter(|h| !lines.iter().any(|line| line_lists_host(line, &ip_re, h)))
        .cloned()
        .collect();
    if !new_hosts.is_empty() {
        match lines.iter().position(|line| ip_re.is_match(line)) {
            Some(idx) => lines[idx] = append_to_line(&lines[idx], &new_hosts),
            None => lines.push(format!("{ip}  {}", new_hosts.join(" "))),
        }
    }
    let updated: Vec<String> = candidates
        .into_iter()
        .filter(|h| moved.contains(h) || new_hosts.contains(h))
        .collect();
    if updated.is_empty() {
        return Ok(None);
    }
    Ok(Some((lines.join("\n") + "\n", updated)))
}

/// Add discovered hostnames to /etc/hosts (one line per IP).
/// Skips anything that looks sketchy or is already there.
pub async fn add_hosts(ip: &str, hostnames: &[String]) -> Result<()> {
    // hold the lock across the whole read-modify-write (see HOSTS_LOCK)
    let _guard = HOSTS_LOCK.lock().await;

    let hosts_content = tokio::fs::read_to_string("/etc/hosts")
        .await
        .context("could not read /etc/hosts; refusing to replace unknown contents")?;

    let Some((content, added)) = merge_hosts(&hosts_content, ip, hostnames)? else {
        return Ok(());
    };

    if !runner::has_sudo().await {
        println!(
            "{} No passwordless sudo -- update /etc/hosts so these names map only to {ip}:",
            "[!]".yellow()
        );
        println!("    {ip}  {}", added.join(" "));
        return Ok(());
    }

    // hand the assembled content to sudo install via a temp file (content is
    // data, never interpolated into a shell command)
    // a failed /etc/hosts write must NOT abort the whole scan — warn and continue
    if let Err(e) = write_hosts_sudo(&content).await {
        println!("{} Could not update /etc/hosts: {e}", "[!]".yellow());
        println!(
            "    update manually (replace older IP mappings): {ip}  {}",
            added.join(" ")
        );
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

// Paths are passed as positional arguments, never interpolated into shell code.
// install alone unlinks/recreates its destination. Prepare a sibling first,
// then rename on the same filesystem; failure (including a bind-mounted hosts
// file that cannot be renamed) leaves the original file intact.
const ATOMIC_REPLACE: &str = r#"
set -eu
tmp=$(mktemp -- "${2}.pwnbox.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT
install -m 644 -- "$1" "$tmp"
mv -fT -- "$tmp" "$2"
"#;

struct HostsInput(String);

impl Drop for HostsInput {
    fn drop(&mut self) {
        // Also runs when a signal cancels the async write/update operation.
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Atomically replace `/etc/hosts`, preparing the final file as root in /etc.
async fn write_hosts_sudo(content: &str) -> Result<()> {
    use tokio::io::AsyncWriteExt;

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
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .await?;
    // Only remove a file we created; a create_new collision belongs to someone else.
    let _cleanup = HostsInput(tmp.clone());
    file.write_all(content.as_bytes()).await?;
    file.flush().await?;
    drop(file);

    let result = runner::run_sudo_cmd_timeout(
        "sh",
        &["-c", ATOMIC_REPLACE, "pwnbox-hosts", &tmp, "/etc/hosts"],
        30,
    )
    .await;

    result
        .map(|_| ())
        .context("could not atomically replace /etc/hosts")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn atomic_replace_preserves_original_on_failure() {
        let dir = std::env::temp_dir().join(format!("pwnbox_hosts_atomic_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("hosts with spaces");
        let source = dir.join("source");
        std::fs::write(&dest, "original\n").unwrap();
        let args = [
            "-c",
            ATOMIC_REPLACE,
            "test",
            source.to_str().unwrap(),
            dest.to_str().unwrap(),
        ];
        assert!(runner::run_cmd_timeout("sh", &args, 5).await.is_err());
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "original\n");
        std::fs::write(&source, "replacement\n").unwrap();
        runner::run_cmd_timeout("sh", &args, 5).await.unwrap();
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "replacement\n");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

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
    fn merge_moves_old_box_alias_and_preserves_other_aliases_and_comments() {
        let (content, updated) = merge_hosts(
            "127.0.0.1 localhost\n10.129.1.1 Fireflow.htb other.htb # previous instance\n",
            "10.129.57.241",
            &["fireflow.htb".into()],
        )
        .unwrap()
        .unwrap();
        assert_eq!(updated, vec!["fireflow.htb"]);
        assert!(content.contains("10.129.1.1  other.htb  # previous instance"));
        assert!(content.contains("10.129.57.241  fireflow.htb"));
        assert!(content.contains("127.0.0.1 localhost"));
        assert_eq!(content.to_lowercase().matches("fireflow.htb").count(), 1);
    }

    #[test]
    fn merge_removes_conflict_even_when_current_mapping_already_exists() {
        let (content, updated) = merge_hosts(
            "10.129.1.1 fireflow.htb # old box\n10.129.57.241 fireflow.htb\n",
            "10.129.57.241",
            &["fireflow.htb".into()],
        )
        .unwrap()
        .unwrap();
        assert_eq!(updated, vec!["fireflow.htb"]);
        assert_eq!(content, "# old box\n10.129.57.241 fireflow.htb\n");
        assert!(
            merge_hosts(&content, "10.129.57.241", &updated)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn merge_recognizes_indented_and_case_insensitive_existing_entry() {
        assert!(
            merge_hosts(
                "  10.129.57.241 FIREFLOW.HTB\n",
                "10.129.57.241",
                &["fireflow.htb".into()],
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
