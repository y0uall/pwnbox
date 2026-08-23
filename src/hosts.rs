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

/// Add discovered hostnames to /etc/hosts (one line per IP).
/// Skips anything that looks sketchy or is already there.
pub async fn add_hosts(ip: &str, hostnames: &[String]) -> Result<()> {
    let hosts_content = tokio::fs::read_to_string("/etc/hosts")
        .await
        .unwrap_or_default();

    // only keep valid, new hostnames we haven't seen before
    let ip_escaped = regex::escape(ip);
    let ip_re = Regex::new(&format!(r"^{}\s+", ip_escaped))?;

    let mut new_hosts: Vec<String> = Vec::new();
    for h in hostnames {
        let h = h.to_lowercase().replace(['\r', '\n'], "");
        if h == ip || !is_valid_hostname(&h) {
            continue;
        }
        // skip if already present for this IP
        let already = hosts_content.lines().any(|line| {
            ip_re.is_match(line)
                && line
                    .split_whitespace()
                    .skip(1)
                    .any(|existing| existing == h)
        });
        if !already && !new_hosts.contains(&h) {
            new_hosts.push(h);
        }
    }

    if new_hosts.is_empty() {
        return Ok(());
    }

    if !runner::has_sudo().await {
        println!("{} No passwordless sudo -- add manually:", "[!]".yellow());
        println!("    {ip}  {}", new_hosts.join(" "));
        return Ok(());
    }

    // build updated /etc/hosts
    let mut lines: Vec<String> = hosts_content.lines().map(|l| l.to_string()).collect();
    let existing_idx = lines.iter().position(|line| ip_re.is_match(line));

    if let Some(idx) = existing_idx {
        // append to existing line
        let updated = format!("{}  {}", lines[idx], new_hosts.join(" "));
        println!("{} Updated /etc/hosts: {}", "[+]".green(), updated.cyan());
        lines[idx] = updated;
    } else {
        // new entry
        let new_line = format!("{}  {}", ip, new_hosts.join(" "));
        println!("{} Added to /etc/hosts: {}", "[+]".green(), new_line.cyan());
        lines.push(new_line);
    }

    // pipe through sudo tee (no shell injection risk since content goes via stdin)
    let content = lines.join("\n") + "\n";
    // a failed /etc/hosts write must NOT abort the whole scan — warn and continue
    if let Err(e) = write_hosts_sudo(&content).await {
        println!("{} Could not update /etc/hosts: {e}", "[!]".yellow());
        println!("    add manually: {ip}  {}", new_hosts.join(" "));
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

    let tmp = format!("/tmp/hosts.pwnbox.{}", std::process::id());

    // write temp file as the current user
    {
        let mut file = tokio::fs::File::create(&tmp).await?;
        file.write_all(content.as_bytes()).await?;
        file.flush().await?;
    }

    // atomically install it as /etc/hosts (preserving permissions)
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
}
