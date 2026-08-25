use std::sync::LazyLock;

use regex::Regex;

/// A line that starts with a port number, e.g. "22/tcp" or "161/udp", as emitted
/// by nmap. Shared by the TCP and UDP scanners to pick port lines out of raw tool
/// output — each previously kept its own byte-identical private copy.
pub(crate) static RE_PORT_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\d+/").unwrap());

/// Port lines *with* their attached nmap script output (the `|`-prefixed lines
/// directly under a port line), plus the host-level "Host script results"
/// block, with nmap's boilerplate (headers, "Host is up", "Not shown",
/// "Service Info", "Nmap done", ...) dropped.
///
/// The report sections used to keep only the bare port lines, so script
/// findings like ssh-hostkey fingerprints, http-title, or smb2-security-mode /
/// clock-skew on AD boxes existed solely in the raw nmap-*.txt files — exactly
/// the detail a report should carry.
pub(crate) fn port_detail_lines(output: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    // true while collecting `|`-prefixed script output attached to the last
    // kept line (a port line or the host-script header)
    let mut in_script_block = false;
    for line in output.lines() {
        if RE_PORT_LINE.is_match(line) || line == "Host script results:" {
            lines.push(line);
            in_script_block = true;
        } else if in_script_block && line.starts_with('|') {
            lines.push(line);
        } else {
            in_script_block = false;
        }
    }
    lines
}

/// ANSI escape sequences (SGR colors and other CSI codes) that tools like
/// enum4linux-ng emit even when their output is piped.
static RE_ANSI: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\x1b\[[0-9;?]*[A-Za-z]").unwrap());

/// Strip ANSI escape sequences — tool colors must not leak into report files.
pub(crate) fn strip_ansi(s: &str) -> String {
    RE_ANSI.replace_all(s, "").into_owned()
}

pub mod connectivity;
pub mod dns;
pub mod ftp;
pub mod kerberos;
pub mod ldap;
pub mod mssql;
pub mod mysql;
pub mod nfs;
pub mod postgres;
pub mod redis;
pub mod rpc;
pub mod smb;
pub mod smtp;
pub mod snmp;
pub mod ssh;
pub mod tcp;
pub mod udp;
pub mod web;
pub mod winrm;

#[cfg(test)]
mod tests {
    use super::{port_detail_lines, strip_ansi};

    // shaped like real nmap -sC -sV output: boilerplate around port lines,
    // script output ("|" / "|_" prefixes) attached to them
    const NMAP_WITH_SCRIPTS: &str = "\
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-08-25 19:01 CEST
Nmap scan report for smarthire.htb (10.129.245.215)
Host is up (0.030s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 41:3c:e3:bb:88:70:99:7f:b8:96:59:48:9b:85:98:69 (ECDSA)
|_  256 d5:9d:fd:6b:be:d8:39:6f:3f:43:ab:0e:f6:3e:22:db (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Overview | SmartHIRE
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.67 seconds";

    #[test]
    fn keeps_script_blocks_and_drops_boilerplate() {
        let lines = port_detail_lines(NMAP_WITH_SCRIPTS);
        assert_eq!(
            lines,
            vec![
                "22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)",
                "| ssh-hostkey:",
                "|   256 41:3c:e3:bb:88:70:99:7f:b8:96:59:48:9b:85:98:69 (ECDSA)",
                "|_  256 d5:9d:fd:6b:be:d8:39:6f:3f:43:ab:0e:f6:3e:22:db (ED25519)",
                "80/tcp open  http    nginx 1.18.0 (Ubuntu)",
                "|_http-title: Overview | SmartHIRE",
            ]
        );
    }

    #[test]
    fn drops_orphan_pipe_lines() {
        // script output without a preceding port line must not leak in
        let lines = port_detail_lines("| stray\n22/tcp open ssh\n| ok\nNot shown: 99 closed\n");
        assert_eq!(lines, vec!["22/tcp open ssh", "| ok"]);
    }

    #[test]
    fn keeps_host_script_results() {
        // AD boxes carry gold here: smb2-security-mode (signing) + clock-skew
        let output = "\
445/tcp open  microsoft-ds?
Service Info: Host: DC01; OS: Windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: 7h00m00s

Nmap done: 1 IP address (1 host up) scanned in 10 seconds";
        let lines = port_detail_lines(output);
        assert_eq!(
            lines,
            vec![
                "445/tcp open  microsoft-ds?",
                "Host script results:",
                "| smb2-security-mode:",
                "|   3:1:1:",
                "|_    Message signing enabled and required",
                "|_clock-skew: 7h00m00s",
            ]
        );
    }

    #[test]
    fn strips_ansi_escape_sequences() {
        assert_eq!(
            strip_ansi("\x1b[94m[*] Target\x1b[0m \x1b[92m[+]\x1b[0m ok"),
            "[*] Target [+] ok"
        );
    }
}
