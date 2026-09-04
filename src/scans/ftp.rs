use anyhow::Result;
use colored::Colorize;

use crate::config::ScanConfig;
use crate::report::Report;
use crate::runner;

/// Try anonymous FTP login.
pub async fn check_anonymous(
    ip: &str,
    port: u16,
    scan_cfg: &ScanConfig,
    report: &Report,
) -> Result<()> {
    report.section("FTP").await;

    // curl exits 0 only when the anonymous login succeeded and the directory
    // listing was retrieved. Under `-s` curl stays silent on an auth failure,
    // so the exit status — not the output text — is the reliable signal:
    // matching on error strings misses server-specific 530 wordings (Pure-FTPd
    // says "Login authentication failed", not "Login incorrect"), and a
    // successful login to an empty directory produces no output at all.
    let (login_ok, output) = runner::run_cmd_status(
        &scan_cfg.tool("curl"),
        &[
            "-s",
            "--max-time",
            "10",
            &format!("ftp://{ip}:{port}/"),
            "--user",
            "anonymous:anonymous",
        ],
        15,
    )
    .await
    .unwrap_or((false, String::new()));

    if login_ok {
        println!("{} Anonymous FTP login successful!", "[+]".green());
        report.add_service("ftp", "  Anonymous login: YES").await;
        if !output.trim().is_empty() {
            println!("{output}");
            report.add_service("ftp", &output).await;
        }
    } else {
        println!("{} Anonymous login failed", "[!]".yellow());
        report.add_service("ftp", "  Anonymous login: NO").await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::config::{ToolsConfig, WordlistsConfig};

    /// REVIEW.md finding 7: the detected port must reach the FTP URL. A stub
    /// curl records its arguments so the URL can be asserted (2121, not 21).
    #[tokio::test]
    async fn check_anonymous_uses_the_detected_port() {
        let tmp = TmpDir::new("ftp_port");
        let log = tmp.path().join("curl-args.log");
        let stub = tmp.path().join("curl-stub.sh");
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"{}\"\nexit 1\n",
                log.display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();

        let tools = ToolsConfig {
            curl: stub.to_string_lossy().to_string(),
            ..Default::default()
        };
        let cfg = ScanConfig {
            verbose: false,
            skip: HashSet::new(),
            timeout: 30,
            fast: false,
            ferox_threads: 50,
            wordlists: WordlistsConfig::default(),
            tools,
        };

        let report = Report::new();
        check_anonymous("127.0.0.1", 2121, &cfg, &report)
            .await
            .unwrap();

        let args = std::fs::read_to_string(&log).unwrap();
        assert!(
            args.lines().any(|a| a == "ftp://127.0.0.1:2121/"),
            "curl must be called with the detected port, got:\n{args}"
        );
        assert!(
            report
                .lines()
                .await
                .iter()
                .any(|l| l.contains("Anonymous login: NO"))
        );
    }

    /// Throwaway directory under the system temp dir, removed on drop.
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("pwnbox_ftp_test_{}_{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            TmpDir(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
