use std::collections::HashMap;
use std::path::Path;
use std::process::{Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use colored::Colorize;
use tokio::process::Command;

// Global per-command defaults, set once at startup from the resolved config.
// `run_cmd` and the `*_timeout` runners honour these so the --timeout / --verbose
// flags (and their config equivalents) actually take effect everywhere.
static DEFAULT_TIMEOUT: AtomicU64 = AtomicU64::new(300);
static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Set the default per-command timeout (seconds) used by `run_cmd`.
pub fn set_default_timeout(secs: u64) {
    DEFAULT_TIMEOUT.store(secs.max(1), Ordering::Relaxed);
}

/// The current default per-command timeout in seconds.
pub fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT.load(Ordering::Relaxed)
}

/// Enable/disable printing of full tool output.
pub fn set_verbose(on: bool) {
    VERBOSE.store(on, Ordering::Relaxed);
}

/// Whether verbose mode is on.
pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Memoized results of tool lookups. PATH doesn't change during a run, so we
/// only ever touch the filesystem once per command name.
fn exists_cache() -> &'static Mutex<HashMap<String, bool>> {
    static CACHE: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// True if `path` is a regular file (or a symlink to one) with any execute bit set.
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    // metadata() follows symlinks, so a symlinked tool resolves to its target
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// Resolve whether `cmd` is runnable against a given `PATH` value: an explicit
/// path (contains a '/') is checked directly, otherwise every entry in `path` is
/// probed. Split out from `resolve_command` so it can be tested with a crafted
/// `PATH` instead of the process environment.
fn resolve_in_path(cmd: &str, path: Option<&std::ffi::OsStr>) -> bool {
    if cmd.is_empty() {
        return false;
    }
    if cmd.contains('/') {
        return is_executable(Path::new(cmd));
    }
    match path {
        Some(path_var) => std::env::split_paths(path_var)
            // skip empty PATH segments so we never probe the current directory
            .any(|dir| !dir.as_os_str().is_empty() && is_executable(&dir.join(cmd))),
        None => false,
    }
}

/// Resolve whether `cmd` is runnable using the process `$PATH`. This is a pure
/// filesystem lookup — it replaces the old `which` subprocess, which was both
/// slower (a fork/exec per check) and an undeclared hard dependency (if `which`
/// was missing, every tool — including nmap/curl — looked absent).
fn resolve_command(cmd: &str) -> bool {
    resolve_in_path(cmd, std::env::var_os("PATH").as_deref())
}

/// Check if a command exists in PATH and is executable (memoized).
pub async fn command_exists(cmd: &str) -> bool {
    if let Some(&hit) = exists_cache().lock().unwrap().get(cmd) {
        return hit;
    }
    // resolve outside the lock — a benign duplicate lookup is fine and cheaper
    // than holding the mutex across a filesystem probe
    let found = resolve_command(cmd);
    exists_cache()
        .lock()
        .unwrap()
        .insert(cmd.to_string(), found);
    found
}

/// Check if we can sudo without a password prompt.
pub async fn has_sudo() -> bool {
    Command::new("sudo")
        .args(["-n", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .is_ok_and(|s| s.success())
}

/// Run a command, return combined stdout+stderr (uses the global default timeout).
pub async fn run_cmd(cmd: &str, args: &[&str]) -> Result<String> {
    run_cmd_timeout(cmd, args, default_timeout()).await
}

/// Spawn a command and capture its output while retaining the real exit status.
///
/// Keeping this as the single process primitive prevents callers from silently
/// treating a non-zero exit as a successful scan with empty/diagnostic output.
async fn capture_output(
    cmd: &str,
    args: &[&str],
    env: &[(&str, &str)],
    timeout_secs: u64,
) -> Result<Output> {
    if is_verbose() {
        eprintln!(
            "{} $ {} {}",
            "[v]".dimmed(),
            cmd.dimmed(),
            args.join(" ").dimmed()
        );
    }

    let mut command = Command::new(cmd);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (key, value) in env {
        command.env(key, value);
    }

    let child = command
        .spawn()
        .with_context(|| format!("Failed to spawn {cmd}"))?;

    match tokio::time::timeout(
        Duration::from_secs(timeout_secs.max(1)),
        child.wait_with_output(),
    )
    .await
    {
        Ok(result) => result.with_context(|| format!("Failed to wait for {cmd}")),
        Err(_) => anyhow::bail!("{cmd} timed out after {timeout_secs}s"),
    }
}

fn combined_output(output: &Output) -> String {
    let mut result = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        if !result.is_empty() {
            result.push('\n');
        }
        result.push_str(&stderr);
    }
    result
}

fn command_failed(cmd: &str, output: &str) -> anyhow::Error {
    let summary = output.lines().take(8).collect::<Vec<_>>().join(" | ");
    if summary.trim().is_empty() {
        anyhow::anyhow!("{cmd} exited unsuccessfully without diagnostic output")
    } else {
        anyhow::anyhow!("{cmd} exited unsuccessfully: {summary}")
    }
}

/// Run a command with a custom timeout, returning `(exited_successfully, output)`
/// where output is combined stdout+stderr. Use this when the exit code is the
/// reliable signal and text sniffing would be brittle — e.g. curl under `-s`,
/// which stays silent on failure, so a non-zero exit is the only tell.
pub async fn run_cmd_status(cmd: &str, args: &[&str], timeout_secs: u64) -> Result<(bool, String)> {
    run_cmd_status_env(cmd, args, &[], timeout_secs).await
}

/// `run_cmd_status` with a small, explicit environment overlay.
pub async fn run_cmd_status_env(
    cmd: &str,
    args: &[&str],
    env: &[(&str, &str)],
    timeout_secs: u64,
) -> Result<(bool, String)> {
    let output = capture_output(cmd, args, env, timeout_secs).await?;
    let result = combined_output(&output);

    if is_verbose() && !result.trim().is_empty() {
        println!("{}", result.trim_end().dimmed());
    }

    Ok((output.status.success(), result))
}

/// Run a command with a custom timeout. Kills the process if it takes too long.
pub async fn run_cmd_timeout(cmd: &str, args: &[&str], timeout_secs: u64) -> Result<String> {
    let (success, output) = run_cmd_status(cmd, args, timeout_secs).await?;
    if !success {
        return Err(command_failed(cmd, &output));
    }
    Ok(output)
}

/// Like run_cmd_timeout but also prints output to the terminal (tee-style).
pub async fn run_cmd_tee(cmd: &str, args: &[&str], timeout_secs: u64) -> Result<String> {
    let output = capture_output(cmd, args, &[], timeout_secs).await?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // print output — unfiltered in verbose mode, otherwise drop nmap's noisy
    // service fingerprint blocks
    if !stdout.is_empty() {
        if is_verbose() {
            print!("{stdout}");
        } else {
            let mut skip = false;
            for line in stdout.lines() {
                if line.contains("NEXT SERVICE FINGERPRINT")
                    || line.starts_with("SF-Port")
                    || line.starts_with("SF:")
                {
                    skip = true;
                    continue;
                }
                if skip
                    && (line.is_empty()
                        || line.starts_with("Service")
                        || line.starts_with("Nmap")
                        || line.starts_with("PORT"))
                {
                    skip = false;
                }
                if !skip {
                    println!("{line}");
                }
            }
        }
    }
    if !stderr.is_empty() {
        eprint!("{stderr}");
    }

    let mut combined = stdout;
    if !stderr.is_empty() {
        if !combined.is_empty() {
            combined.push('\n');
        }
        combined.push_str(&stderr);
    }
    if !output.status.success() {
        return Err(command_failed(cmd, &combined));
    }
    Ok(combined)
}

/// Run a command via sudo with a custom timeout.
pub async fn run_sudo_cmd_timeout(cmd: &str, args: &[&str], timeout_secs: u64) -> Result<String> {
    let mut sudo_args = vec![cmd];
    sudo_args.extend_from_slice(args);
    run_cmd_timeout("sudo", &sudo_args, timeout_secs).await
}

/// Open a raw TCP connection, optionally send `payload`, then read whatever the
/// peer sends back until it closes or goes idle for `timeout_secs`.
///
/// This replaces the old `bash -c "echo ... | nc ..."` banner-grab pattern: no
/// shell, no `nc` dependency, and the target string can never be interpreted as
/// a command. Returns an empty string on connect failure (callers treat that as
/// "nothing to see").
pub async fn tcp_probe(ip: &str, port: u16, payload: &[u8], timeout_secs: u64) -> Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let idle = Duration::from_secs(timeout_secs.max(1));
    // Hard ceiling on the whole probe so a peer that trickles one byte just under
    // the idle timeout can't keep the connection (and the scan) alive forever.
    let deadline = tokio::time::Instant::now() + idle.saturating_mul(4);
    let addr = format!("{ip}:{port}");

    if is_verbose() {
        eprintln!("{} ~ tcp connect {}", "[v]".dimmed(), addr.dimmed());
    }

    let mut stream = match tokio::time::timeout_at(deadline, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return Ok(String::new()), // connect refused / timed out
    };

    if !payload.is_empty() {
        // best-effort write; if it fails we still try to read what's there
        let _ = stream.write_all(payload).await;
        let _ = stream.flush().await;
    }

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break; // overall deadline hit
        }
        // wait at most until the idle timeout, but never past the overall deadline
        let step = idle.min(deadline - now);
        match tokio::time::timeout(step, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break, // peer closed
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() >= 65_536 {
                    break; // cap to avoid slurping a huge stream
                }
            }
            Ok(Err(_)) => break, // read error
            Err(_) => break,     // idle/overall timeout — return what we have so far
        }
    }

    let result = String::from_utf8_lossy(&buf).to_string();
    if is_verbose() && !result.trim().is_empty() {
        println!("{}", result.trim_end().dimmed());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    /// A throwaway directory under the system temp dir, removed on drop.
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("pwnbox_runner_{}_{tag}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            TmpDir(dir)
        }

        /// Create a file with exactly `mode` permission bits; return its path.
        fn file(&self, name: &str, mode: u32) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, b"#!/bin/sh\n").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            path
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn is_executable_requires_a_file_with_an_exec_bit() {
        let tmp = TmpDir::new("isexec");
        assert!(is_executable(&tmp.file("runme", 0o755)));
        assert!(!is_executable(&tmp.file("data", 0o644))); // no exec bit
        assert!(!is_executable(&tmp.0)); // a directory is not a runnable file
        assert!(!is_executable(&tmp.0.join("missing"))); // nonexistent path
    }

    #[test]
    fn resolve_command_probes_explicit_paths_directly() {
        let tmp = TmpDir::new("explicit");
        let exec = tmp.file("tool", 0o755);
        let plain = tmp.file("cfg", 0o644);
        assert!(resolve_command(exec.to_str().unwrap()));
        assert!(!resolve_command(plain.to_str().unwrap()));
        assert!(!resolve_command("")); // empty is never runnable
    }

    #[test]
    fn resolve_in_path_searches_entries_and_skips_empty_segments() {
        let tmp = TmpDir::new("pathsearch");
        tmp.file("mytool", 0o755);
        tmp.file("notexec", 0o644);
        // a leading empty segment must be skipped, never probing the CWD
        let path = OsString::from(format!(":{}", tmp.0.display()));
        assert!(resolve_in_path("mytool", Some(path.as_os_str())));
        assert!(!resolve_in_path("notexec", Some(path.as_os_str()))); // present, not +x
        assert!(!resolve_in_path("ghost", Some(path.as_os_str()))); // absent
        assert!(!resolve_in_path("mytool", None)); // no PATH at all
    }

    #[tokio::test]
    async fn command_exists_resolves_and_memoizes() {
        // the running test binary is a real executable named by an explicit path
        let me = std::env::current_exe().unwrap();
        let me = me.to_str().unwrap();
        assert!(command_exists(me).await); // resolves, then caches
        assert!(command_exists(me).await); // served from the cache
        // a name that cannot exist stays false on both miss and cache hit
        assert!(!command_exists("pwnbox_definitely_no_such_tool_zzz").await);
        assert!(!command_exists("pwnbox_definitely_no_such_tool_zzz").await);
    }

    #[tokio::test]
    async fn command_status_preserves_failure_and_checked_runner_rejects_it() {
        let tmp = TmpDir::new("exit_status");
        let script = tmp.file("fails", 0o755);
        fs::write(
            &script,
            b"#!/bin/sh\nprintf 'partial scan output\\n'\nprintf 'tool failed\\n' >&2\nexit 7\n",
        )
        .unwrap();

        let (success, output) = run_cmd_status(script.to_str().unwrap(), &[], 5)
            .await
            .unwrap();
        assert!(!success);
        assert!(output.contains("partial scan output"));
        assert!(output.contains("tool failed"));

        let error = run_cmd_timeout(script.to_str().unwrap(), &[], 5)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exited unsuccessfully"));
    }

    #[tokio::test]
    async fn command_status_env_applies_explicit_environment() {
        let tmp = TmpDir::new("env");
        let script = tmp.file("prints_env", 0o755);
        fs::write(&script, b"#!/bin/sh\nprintf '%s' \"$PWNBOX_TEST_VALUE\"\n").unwrap();

        let (success, output) = run_cmd_status_env(
            script.to_str().unwrap(),
            &[],
            &[("PWNBOX_TEST_VALUE", "expected")],
            5,
        )
        .await
        .unwrap();
        assert!(success);
        assert_eq!(output, "expected");
    }
}
