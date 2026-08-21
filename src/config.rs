use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::Local;
use colored::Colorize;
use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct FileConfig {
    #[serde(default)]
    pub defaults: DefaultsConfig,
    #[serde(default)]
    pub wordlists: WordlistsConfig,
    #[serde(default)]
    pub tools: ToolsConfig,
}

#[derive(Debug, Deserialize, Default)]
pub struct DefaultsConfig {
    pub timeout: Option<u64>,
    pub ferox_threads: Option<u16>,
    pub fast: Option<bool>,
    pub verbose: Option<bool>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct WordlistsConfig {
    #[serde(default)]
    pub dir_medium: Vec<String>,
    #[serde(default)]
    pub dir_small: Vec<String>,
    #[serde(default)]
    pub dns_subdomains: Vec<String>,
    #[serde(default)]
    pub usernames: Vec<String>,
    #[serde(default)]
    pub usernames_short: Vec<String>,
    #[serde(default)]
    pub passwords_short: Vec<String>,
    #[serde(default)]
    pub snmp: Vec<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct ToolsConfig {
    #[serde(default)]
    pub nmap: String,
    #[serde(default)]
    pub rustscan: String,
    #[serde(default)]
    pub feroxbuster: String,
    #[serde(default)]
    pub ffuf: String,
    #[serde(default)]
    pub gobuster: String,
    #[serde(default)]
    pub whatweb: String,
    #[serde(default)]
    pub curl: String,
    #[serde(default)]
    pub dig: String,
    #[serde(default)]
    pub kerbrute: String,
    #[serde(default)]
    pub enum4linux_ng: String,
    #[serde(default)]
    pub smbclient: String,
    #[serde(default)]
    pub crackmapexec: String,
    #[serde(default)]
    pub ldapsearch: String,
    #[serde(default)]
    pub snmpwalk: String,
    #[serde(default)]
    pub showmount: String,
    #[serde(default)]
    pub smtp_user_enum: String,
}

// Fallback wordlist paths if nothing is set in config
impl WordlistsConfig {
    pub fn with_defaults(mut self) -> Self {
        if self.dir_medium.is_empty() {
            self.dir_medium = vec![
                "/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt".into(),
                "/opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt".into(),
                "/usr/share/dirb/wordlists/common.txt".into(),
            ];
        }
        if self.dir_small.is_empty() {
            self.dir_small = vec![
                "/opt/SecLists/Discovery/Web-Content/common.txt".into(),
                "/usr/share/dirb/wordlists/common.txt".into(),
            ];
        }
        if self.dns_subdomains.is_empty() {
            self.dns_subdomains = vec![
                "/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt".into(),
                "/opt/SecLists/Discovery/DNS/namelist.txt".into(),
                "/usr/share/dnsrecon/subdomains-top1mil-5000.txt".into(),
            ];
        }
        if self.usernames.is_empty() {
            self.usernames = vec![
                "/opt/SecLists/Usernames/xato-net-10-million-usernames.txt".into(),
                "/opt/SecLists/Usernames/top-usernames-shortlist.txt".into(),
            ];
        }
        if self.usernames_short.is_empty() {
            self.usernames_short = vec![
                "/opt/SecLists/Usernames/top-usernames-shortlist.txt".into(),
                "/usr/share/metasploit-framework/data/wordlists/unix_users.txt".into(),
            ];
        }
        if self.passwords_short.is_empty() {
            self.passwords_short = vec![
                "/opt/SecLists/Passwords/Common-Credentials/best15.txt".into(),
                "/opt/SecLists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt".into(),
            ];
        }
        if self.snmp.is_empty() {
            self.snmp = vec![
                "/opt/SecLists/Discovery/SNMP/snmp.txt".into(),
                "/opt/SecLists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt".into(),
            ];
        }
        self
    }
}

impl FileConfig {
    /// Tries explicit path, then ./config.toml, then ~/.config/pwnbox/config.toml.
    pub fn load(explicit_path: Option<&str>) -> Result<Self> {
        let candidates: Vec<PathBuf> = if let Some(p) = explicit_path {
            vec![PathBuf::from(p)]
        } else {
            let mut c = vec![PathBuf::from("config.toml")];
            if let Ok(home) = std::env::var("HOME") {
                c.push(PathBuf::from(home).join(".config/pwnbox/config.toml"));
            }
            c
        };

        for path in &candidates {
            if path.exists() {
                let content = std::fs::read_to_string(path)?;
                let mut cfg: FileConfig = toml::from_str(&content)?;
                cfg.wordlists = cfg.wordlists.with_defaults();
                println!(
                    "{} Config loaded: {}",
                    "[*]".cyan(),
                    path.display().to_string().dimmed()
                );
                return Ok(cfg);
            }
        }

        // nothing found, just go with hardcoded defaults
        println!("{} No config.toml found — using defaults", "[*]".dimmed());
        Ok(FileConfig {
            wordlists: WordlistsConfig::default().with_defaults(),
            ..Default::default()
        })
    }

    /// Writes a fresh config.toml with sane defaults.
    pub fn init(path: &Path) -> Result<()> {
        let default_content = include_str!("../config.toml");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, default_content)?;
        println!("{} Config written to {}", "[+]".green(), path.display());
        Ok(())
    }
}

/// Returns the first wordlist path that actually exists on disk.
pub fn find_wordlist(candidates: &[String]) -> Option<String> {
    for path in candidates {
        if Path::new(path).exists() {
            return Some(path.clone());
        }
    }
    None
}

/// Same as find_wordlist but prints a warning if nothing is found.
pub fn find_wordlist_or_warn(candidates: &[String], category: &str) -> Option<String> {
    if let Some(wl) = find_wordlist(candidates) {
        return Some(wl);
    }
    println!(
        "{} No {} wordlist found (checked {} paths)",
        "[!]".yellow(),
        category,
        candidates.len()
    );
    None
}

#[derive(Debug, Clone)]
pub struct BoxConfig {
    pub name: String,
    pub ip: String,
    pub output_dir: PathBuf,
    pub hostname: String,
    pub report_path: PathBuf,
}

impl BoxConfig {
    pub fn new(name: &str, ip: &str, output_dir: Option<&str>) -> Self {
        let timestamp = Local::now().format("%Y%m%d-%H%M%S").to_string();
        let box_lower = name.to_lowercase();
        let hostname = format!("{box_lower}.htb");

        let dir = match output_dir {
            Some(d) => PathBuf::from(d),
            None => {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                PathBuf::from(home).join("htb").join(&box_lower)
            }
        };

        let report_path = dir.join(format!("{box_lower}-{timestamp}.txt"));

        BoxConfig {
            name: name.to_string(),
            ip: ip.to_string(),
            output_dir: dir,
            hostname,
            report_path,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub verbose: bool,
    pub skip: HashSet<String>,
    pub timeout: u64,
    pub fast: bool,
    pub ferox_threads: u16,
    pub wordlists: WordlistsConfig,
    pub tools: ToolsConfig,
}

impl ScanConfig {
    /// Merges CLI flags with config file values (CLI wins).
    pub fn new(
        verbose: Option<bool>,
        skip: &[String],
        timeout: Option<u64>,
        fast: Option<bool>,
        ferox_threads: Option<u16>,
        file_cfg: &FileConfig,
    ) -> Self {
        let verbose = verbose.unwrap_or_else(|| file_cfg.defaults.verbose.unwrap_or(false));
        let timeout = timeout.unwrap_or_else(|| file_cfg.defaults.timeout.unwrap_or(300));
        let fast = fast.unwrap_or_else(|| file_cfg.defaults.fast.unwrap_or(false));
        let ferox_threads =
            ferox_threads.unwrap_or_else(|| file_cfg.defaults.ferox_threads.unwrap_or(50));

        let mut skip_set: HashSet<String> = skip.iter().map(|s| s.to_lowercase()).collect();
        if fast {
            skip_set.insert("udp".to_string());
        }

        ScanConfig {
            verbose,
            skip: skip_set,
            timeout,
            fast,
            ferox_threads,
            wordlists: file_cfg.wordlists.clone(),
            tools: file_cfg.tools.clone(),
        }
    }

    pub fn should_skip(&self, service: &str) -> bool {
        self.skip.contains(&service.to_lowercase())
    }

    /// Look up a tool path; falls back to just the tool name if not overridden in config.
    pub fn tool(&self, name: &str) -> String {
        let override_path = match name {
            "nmap" => &self.tools.nmap,
            "rustscan" => &self.tools.rustscan,
            "feroxbuster" => &self.tools.feroxbuster,
            "ffuf" => &self.tools.ffuf,
            "gobuster" => &self.tools.gobuster,
            "whatweb" => &self.tools.whatweb,
            "curl" => &self.tools.curl,
            "dig" => &self.tools.dig,
            "kerbrute" => &self.tools.kerbrute,
            "enum4linux-ng" => &self.tools.enum4linux_ng,
            "smbclient" => &self.tools.smbclient,
            "crackmapexec" => &self.tools.crackmapexec,
            "ldapsearch" => &self.tools.ldapsearch,
            "snmpwalk" => &self.tools.snmpwalk,
            "showmount" => &self.tools.showmount,
            "smtp-user-enum" => &self.tools.smtp_user_enum,
            _ => "",
        };
        if override_path.is_empty() {
            name.to_string()
        } else {
            override_path.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_box_config_defaults() {
        let cfg = BoxConfig::new("Lame", "10.10.10.3", None);
        assert_eq!(cfg.name, "Lame");
        assert_eq!(cfg.ip, "10.10.10.3");
        assert_eq!(cfg.hostname, "lame.htb");
        assert!(cfg.output_dir.ends_with("htb/lame"));
        assert!(cfg.report_path.to_string_lossy().contains("lame-"));
        assert!(cfg.report_path.to_string_lossy().ends_with(".txt"));
    }

    #[test]
    fn test_box_config_custom_output() {
        let cfg = BoxConfig::new("Legacy", "10.10.10.4", Some("/tmp/test-out"));
        assert_eq!(cfg.output_dir, PathBuf::from("/tmp/test-out"));
        assert_eq!(cfg.hostname, "legacy.htb");
    }

    #[test]
    fn test_scan_config_defaults() {
        let file_cfg = FileConfig::default();
        let scan = ScanConfig::new(None, &[], None, None, None, &file_cfg);
        assert!(!scan.verbose);
        assert!(!scan.fast);
        assert_eq!(scan.timeout, 300);
        assert_eq!(scan.ferox_threads, 50);
        assert!(scan.skip.is_empty());
    }

    #[test]
    fn test_scan_config_cli_overrides() {
        let file_cfg = FileConfig::default();
        let skip = vec!["smb".to_string(), "ldap".to_string()];
        let scan = ScanConfig::new(
            Some(true),
            &skip,
            Some(600),
            Some(true),
            Some(100),
            &file_cfg,
        );
        assert!(scan.verbose);
        assert!(scan.fast);
        assert_eq!(scan.timeout, 600);
        assert_eq!(scan.ferox_threads, 100);
        assert!(scan.should_skip("smb"));
        assert!(scan.should_skip("SMB")); // case insensitive
        assert!(scan.should_skip("ldap"));
        assert!(!scan.should_skip("ssh"));
    }

    #[test]
    fn test_fast_mode_skips_udp() {
        let file_cfg = FileConfig::default();
        let scan = ScanConfig::new(None, &[], None, Some(true), None, &file_cfg);
        assert!(scan.should_skip("udp"));
    }

    #[test]
    fn test_file_boolean_defaults_apply_when_cli_flag_is_absent() {
        let mut file_cfg = FileConfig::default();
        file_cfg.defaults.fast = Some(true);
        file_cfg.defaults.verbose = Some(true);

        let scan = ScanConfig::new(None, &[], None, None, None, &file_cfg);
        assert!(scan.fast);
        assert!(scan.verbose);
        assert!(scan.should_skip("udp"));
    }

    #[test]
    fn test_tool_resolver_default() {
        let file_cfg = FileConfig::default();
        let scan = ScanConfig::new(None, &[], None, None, None, &file_cfg);
        assert_eq!(scan.tool("nmap"), "nmap");
        assert_eq!(scan.tool("unknown_tool"), "unknown_tool");
    }

    #[test]
    fn test_tool_resolver_override() {
        let mut file_cfg = FileConfig::default();
        file_cfg.tools.nmap = "/usr/local/bin/nmap".to_string();
        let scan = ScanConfig::new(None, &[], None, None, None, &file_cfg);
        assert_eq!(scan.tool("nmap"), "/usr/local/bin/nmap");
        assert_eq!(scan.tool("curl"), "curl"); // not overridden
    }

    #[test]
    fn test_find_wordlist_existing() {
        // /etc/hosts should exist on any Linux system
        let result = find_wordlist(&[
            "/nonexistent/path.txt".to_string(),
            "/etc/hosts".to_string(),
        ]);
        assert_eq!(result, Some("/etc/hosts".to_string()));
    }

    #[test]
    fn test_find_wordlist_none() {
        let result = find_wordlist(&[
            "/nonexistent/a.txt".to_string(),
            "/nonexistent/b.txt".to_string(),
        ]);
        assert_eq!(result, None);
    }

    #[test]
    fn test_wordlists_with_defaults() {
        let wl = WordlistsConfig::default().with_defaults();
        assert!(!wl.dir_medium.is_empty());
        assert!(!wl.dir_small.is_empty());
        assert!(!wl.dns_subdomains.is_empty());
        assert!(!wl.usernames.is_empty());
        assert!(!wl.snmp.is_empty());
    }

    #[test]
    fn test_wordlists_custom_not_overwritten() {
        let wl = WordlistsConfig {
            dir_medium: vec!["/my/custom/wordlist.txt".to_string()],
            ..Default::default()
        };
        let wl = wl.with_defaults();
        assert_eq!(wl.dir_medium, vec!["/my/custom/wordlist.txt".to_string()]);
        // Other fields should get defaults
        assert!(!wl.dir_small.is_empty());
    }

    #[test]
    fn test_file_config_load_nonexistent_falls_back_to_defaults() {
        // When an explicit path doesn't exist, load() falls back to defaults
        let cfg = FileConfig::load(Some("/nonexistent/config.toml")).unwrap();
        assert_eq!(cfg.defaults.timeout, None);
        assert_eq!(cfg.defaults.fast, None);
    }

    #[test]
    fn test_file_config_parse_toml() {
        let toml_content = r#"
[defaults]
timeout = 120
fast = true

[wordlists]
dir_medium = ["/custom/wordlist.txt"]
"#;
        let cfg: FileConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(cfg.defaults.timeout, Some(120));
        assert_eq!(cfg.defaults.fast, Some(true));
        assert_eq!(cfg.wordlists.dir_medium, vec!["/custom/wordlist.txt"]);
    }
}
