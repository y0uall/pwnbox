use std::collections::{HashMap, HashSet};

use anyhow::Result;
use colored::Colorize;

use crate::config::ScanConfig;
use crate::runner;

struct ToolDef {
    name: &'static str,
    alternatives: &'static [&'static str], // e.g. netexec as fallback for crackmapexec
    modules: &'static [&'static str],      // which scan modules need this
    required: bool,                        // true = hard dependency, false = just a warning
}

const TOOL_DEFS: &[ToolDef] = &[
    // hard requirements
    ToolDef {
        name: "nmap",
        alternatives: &[],
        modules: &["tcp", "udp", "mssql"],
        required: true,
    },
    ToolDef {
        name: "curl",
        alternatives: &[],
        modules: &["web", "ftp", "winrm"],
        required: true,
    },
    ToolDef {
        name: "ping",
        alternatives: &[],
        modules: &["connectivity"],
        required: false,
    },
    // nice to have
    ToolDef {
        name: "rustscan",
        alternatives: &[],
        modules: &["tcp"],
        required: false,
    },
    ToolDef {
        name: "feroxbuster",
        alternatives: &[],
        modules: &["web"],
        required: false,
    },
    ToolDef {
        name: "whatweb",
        alternatives: &[],
        modules: &["web"],
        required: false,
    },
    ToolDef {
        name: "gobuster",
        alternatives: &[],
        modules: &["web"],
        required: false,
    },
    ToolDef {
        name: "ffuf",
        alternatives: &[],
        modules: &["web"],
        required: false,
    },
    ToolDef {
        name: "enum4linux-ng",
        alternatives: &[],
        modules: &["smb"],
        required: false,
    },
    ToolDef {
        name: "crackmapexec",
        alternatives: &["netexec"],
        modules: &["smb"],
        required: false,
    },
    ToolDef {
        name: "smbclient",
        alternatives: &[],
        modules: &["smb"],
        required: false,
    },
    ToolDef {
        name: "rpcclient",
        alternatives: &[],
        modules: &["rpc"],
        required: false,
    },
    ToolDef {
        name: "showmount",
        alternatives: &[],
        modules: &["nfs"],
        required: false,
    },
    ToolDef {
        name: "dig",
        alternatives: &[],
        modules: &["dns"],
        required: false,
    },
    ToolDef {
        name: "dnsx",
        alternatives: &[],
        modules: &["dns"],
        required: false,
    },
    ToolDef {
        name: "subfinder",
        alternatives: &[],
        modules: &["dns"],
        required: false,
    },
    ToolDef {
        name: "redis-cli",
        alternatives: &[],
        modules: &["redis"],
        required: false,
    },
    ToolDef {
        name: "evil-winrm",
        alternatives: &[],
        modules: &["winrm"],
        required: false,
    },
    ToolDef {
        name: "kerbrute",
        alternatives: &[],
        modules: &["kerberos"],
        required: false,
    },
    ToolDef {
        name: "smtp-user-enum",
        alternatives: &[],
        modules: &["smtp"],
        required: false,
    },
    ToolDef {
        name: "impacket-mssqlclient",
        alternatives: &["mssqlclient.py"],
        modules: &["mssql"],
        required: false,
    },
    ToolDef {
        name: "snmpwalk",
        alternatives: &[],
        modules: &["snmp"],
        required: false,
    },
    ToolDef {
        name: "onesixtyone",
        alternatives: &[],
        modules: &["snmp"],
        required: false,
    },
    ToolDef {
        name: "ldapsearch",
        alternatives: &[],
        modules: &["ldap"],
        required: false,
    },
    ToolDef {
        name: "mysql",
        alternatives: &[],
        modules: &["mysql"],
        required: false,
    },
    ToolDef {
        name: "psql",
        alternatives: &[],
        modules: &["postgres"],
        required: false,
    },
    ToolDef {
        name: "impacket-rpcdump",
        alternatives: &[],
        modules: &["rpc"],
        required: false,
    },
    ToolDef {
        name: "openssl",
        alternatives: &[],
        modules: &["tcp"],
        required: false,
    },
];

/// Tracks which tools are missing and what modules that affects.
#[derive(Debug, Default)]
pub struct ToolCheckResult {
    pub affected_modules: HashMap<String, Vec<String>>,
    pub missing_tools: HashSet<String>,
}

fn module_enabled(scan_cfg: &ScanConfig, module: &str) -> bool {
    if scan_cfg.should_skip(module) {
        return false;
    }
    !scan_cfg.fast || matches!(module, "connectivity" | "dns" | "tcp" | "web")
}

/// Verify tools needed by the resolved scan plan, honoring configured paths.
pub async fn check_all(scan_cfg: &ScanConfig) -> Result<ToolCheckResult> {
    let mut result = ToolCheckResult::default();
    let mut missing_required = Vec::new();

    for def in TOOL_DEFS {
        let active_modules: Vec<&str> = def
            .modules
            .iter()
            .copied()
            .filter(|module| module_enabled(scan_cfg, module))
            .collect();
        if active_modules.is_empty() {
            continue;
        }

        // Check the configured override first, then documented alternatives.
        let configured = scan_cfg.tool(def.name);
        let mut found = runner::command_exists(&configured).await;
        if !found {
            for alt in def.alternatives {
                if runner::command_exists(alt).await {
                    found = true;
                    break;
                }
            }
        }

        if !found {
            let display_name = if configured != def.name {
                format!("{} ({configured})", def.name)
            } else if def.alternatives.is_empty() {
                def.name.to_string()
            } else {
                format!("{}/{}", def.name, def.alternatives.join("/"))
            };

            if def.required {
                missing_required.push(display_name);
            } else {
                result.missing_tools.insert(display_name.clone());
                for module in active_modules {
                    result
                        .affected_modules
                        .entry(module.to_string())
                        .or_default()
                        .push(display_name.clone());
                }
            }
        }
    }

    if !missing_required.is_empty() {
        eprintln!(
            "{} Missing required tools: {}",
            "[!]".red().bold(),
            missing_required.join(", ").red()
        );
        anyhow::bail!(
            "install the required tools or correct their configured paths before running pwnbox"
        );
    }

    // let the user know what's missing (but non-fatal)
    if !result.missing_tools.is_empty() {
        println!("\n{} Missing optional tools:", "[*]".yellow());
        for tool in &result.missing_tools {
            // Find which modules this tool affects
            let modules: Vec<&str> = result
                .affected_modules
                .iter()
                .filter(|(_, tools)| tools.contains(tool))
                .map(|(m, _)| m.as_str())
                .collect();
            println!(
                "  {} {} {}",
                "-".dimmed(),
                tool.yellow(),
                format!("(affects: {})", modules.join(", ")).dimmed()
            );
        }
        println!(
            "{} Modules with missing tools will have reduced functionality\n",
            "[*]".dimmed()
        );
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FileConfig;

    #[test]
    fn fast_mode_checks_only_fast_pipeline_modules() {
        let file_cfg = FileConfig::default();
        let scan = ScanConfig::new(None, &[], None, Some(true), None, &file_cfg);
        assert!(module_enabled(&scan, "tcp"));
        assert!(module_enabled(&scan, "web"));
        assert!(module_enabled(&scan, "dns"));
        assert!(!module_enabled(&scan, "smb"));
        assert!(!module_enabled(&scan, "udp"));
    }

    #[test]
    fn explicitly_skipped_module_is_not_enabled() {
        let file_cfg = FileConfig::default();
        let scan = ScanConfig::new(None, &["web".to_string()], None, None, None, &file_cfg);
        assert!(!module_enabled(&scan, "web"));
        assert!(module_enabled(&scan, "tcp"));
    }
}
