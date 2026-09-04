use std::collections::HashMap;
use std::path::Path;
use std::process::{Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use colored::Colorize;
use regex::Regex;
use tokio::process::Command;

// Global per-command defaults, set once at startup from the resolved config.
// `run_cmd` and the `*_timeout` runners honour these so the --timeout / --verbose
// flags (and their config equivalents) actually take effect everywhere.
static DEFAULT_TIMEOUT: AtomicU64 = AtomicU64::new(300);
static VERBOSE: AtomicBool = AtomicBool::new(false);
// Bound external work across all ports and modules, including background jobs.
static PROCESS_LIMIT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(16);

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
    run_cmd_status("sudo", &["-n", "true"], 10)
        .await
        .is_ok_and(|(success, _)| success)
}

/// Run a command interactively with inherited stdio and no capture — for the
/// rare call whose prompts must reach the terminal (`sudo -v`). With piped
/// stderr the password prompt would be invisible and the call would just hang
/// until the timeout (REVIEW.md finding 6). Returns true on exit status 0.
pub async fn run_cmd_interactive(cmd: &str, args: &[&str]) -> Result<bool> {
    if is_verbose() {
        eprintln!(
            "{} $ {} {}",
            "[v]".dimmed(),
            cmd.dimmed(),
            args.join(" ").dimmed()
        );
    }

    let status = Command::new(cmd)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        // so a Ctrl+C / task-abort still kills the child
        .kill_on_drop(true)
        .status()
        .await
        .with_context(|| format!("Failed to spawn {cmd}"))?;
    Ok(status.success())
}

/// Run a command, return combined stdout+stderr (uses the global default timeout).
pub async fn run_cmd(cmd: &str, args: &[&str]) -> Result<String> {
    run_cmd_timeout(cmd, args, default_timeout()).await
}

/// ETXTBSY has no `std::io::ErrorKind` variant; match the raw errno.
const ETXTBSY: i32 = 26;

/// Spawn a command, retrying briefly on ETXTBSY ("Text file busy").
///
/// execve can fail spuriously when the target file is momentarily seen as open
/// for writing — a just-(re)written script, or a write fd a concurrent fork
/// briefly inherited. The condition clears within milliseconds, so a few short
/// retries turn a flaky failure into a non-event; genuinely missing or broken
/// files still fail on the first attempt (no retryable errno).
async fn spawn_transient(command: &mut Command, cmd: &str) -> Result<tokio::process::Child> {
    let mut attempt = 0;
    loop {
        match command.spawn() {
            Err(e) if e.raw_os_error() == Some(ETXTBSY) && attempt < 3 => {
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            result => return result.with_context(|| format!("Failed to spawn {cmd}")),
        }
    }
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
    capture_output_input(cmd, args, env, None, timeout_secs).await
}

async fn capture_output_input(
    cmd: &str,
    args: &[&str],
    env: &[(&str, &str)],
    input: Option<&[u8]>,
    timeout_secs: u64,
) -> Result<Output> {
    let _permit = PROCESS_LIMIT.acquire().await?;
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
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    for (key, value) in env {
        command.env(key, value);
    }

    let mut child = spawn_transient(&mut command, cmd).await?;
    let _group = ProcessGroupGuard(child.id());
    let stdin = child.stdin.take();
    let output = async {
        use tokio::io::AsyncWriteExt;
        let write = async {
            if let (Some(mut stdin), Some(input)) = (stdin, input) {
                stdin.write_all(input).await?;
                stdin.shutdown().await?;
            }
            Ok::<_, std::io::Error>(())
        };
        let (written, output) = tokio::join!(write, child.wait_with_output());
        let output = output?;
        // Authentication failures can close stdin without consuming the query.
        if output.status.success() {
            written?;
        }
        Ok::<_, std::io::Error>(output)
    };

    match tokio::time::timeout(Duration::from_secs(timeout_secs.max(1)), output).await {
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

/// Feed a non-interactive command without a shell or a temporary query file.
pub async fn run_cmd_status_input(
    cmd: &str,
    args: &[&str],
    input: &[u8],
    timeout_secs: u64,
) -> Result<(bool, String)> {
    let output = capture_output_input(cmd, args, &[], Some(input), timeout_secs).await?;
    let result = combined_output(&output);
    if is_verbose() && !result.trim().is_empty() {
        println!("{}", result.trim_end().dimmed());
    }
    Ok((output.status.success(), result))
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

/// Preserve stdout bytes for protocols whose byte counts matter (HTTP bodies).
pub async fn run_cmd_bytes(cmd: &str, args: &[&str], timeout_secs: u64) -> Result<Vec<u8>> {
    let output = capture_output(cmd, args, &[], timeout_secs).await?;
    if !output.status.success() {
        return Err(command_failed(cmd, &combined_output(&output)));
    }
    if is_verbose() && !output.stdout.is_empty() {
        println!(
            "{}",
            String::from_utf8_lossy(&output.stdout).trim_end().dimmed()
        );
    }
    Ok(output.stdout)
}

// Captures the segments of an nmap port line so the tee'd output below can
// recolor them without losing nmap's column alignment.
static RE_TEE_PORT_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\d+)/(tcp|udp)(\s+open(?:\|filtered)?\s+)(\S+)(.*)$").unwrap());

/// Colorize an nmap port line in the tee'd output (port green, service yellow,
/// version dimmed — mirroring print_port_lines in main.rs). Open ports are the
/// scan's first findings; they should pop out of the nmap boilerplate instead
/// of scrolling by as plain text.
fn colorize_port_line(line: &str) -> String {
    match RE_TEE_PORT_LINE.captures(line) {
        Some(caps) => format!(
            "{}{}{}{}{}",
            caps[1].green(),
            format!("/{}", &caps[2]).dimmed(),
            &caps[3],
            caps[4].yellow(),
            caps[5].dimmed()
        ),
        None => line.to_string(),
    }
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
                    println!("{}", colorize_port_line(line));
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

/// Kill descendants as well as the direct child, including on task abort.
/// The guard must run with the same credentials as the child it supervises.
struct ProcessGroupGuard(Option<u32>);

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if let Some(pgid) = self.0 {
            // SAFETY: kill(2) with a negative pid targets the process group.
            // The result is ignored on purpose: ESRCH just means the group
            // already exited, and anything else (EPERM, ...) can't be handled
            // here anyway — this is best-effort cleanup.
            unsafe { libc::kill(-(pgid as i32), libc::SIGKILL) };
        }
    }
}

pub(crate) const SUDO_WORKER_FLAG: &str = "--internal-sudo-worker";

/// Supervise a privileged command from inside the sudo boundary. Closing the
/// parent's pipe cancels the command even if the parent cannot signal root
/// processes, or the parent itself is killed. The tool never inherits this
/// pipe, so a descendant cannot accidentally keep the liveness channel open.
async fn supervise_command<R: tokio::io::AsyncRead + Unpin>(
    cmd: &str,
    args: &[&str],
    timeout_secs: u64,
    mut parent: R,
) -> Result<i32> {
    use std::os::unix::process::ExitStatusExt;
    use tokio::io::AsyncReadExt;

    // Install handlers before spawning: terminal signals must trigger cleanup,
    // not terminate the supervisor while its separate process group survives.
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut command = Command::new(cmd);
    command
        .args(args)
        .stdin(Stdio::null())
        .process_group(0)
        .kill_on_drop(true);
    let mut child = spawn_transient(&mut command, cmd).await?;
    let group = ProcessGroupGuard(child.id());
    let mut byte = [0u8; 1];
    let code = tokio::select! {
        status = child.wait() => {
            let status = status?;
            status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
        }
        _ = parent.read(&mut byte) => 130,
        _ = interrupt.recv() => 130,
        _ = terminate.recv() => 130,
        _ = tokio::time::sleep(Duration::from_secs(timeout_secs.max(1))) => {
            eprintln!("{cmd} timed out after {timeout_secs}s");
            124
        }
    };
    // Kill under the tool's own UID, then reap before the worker exits.
    drop(group);
    child.wait().await?;
    Ok(code)
}

/// Internal entry point; invoked before CLI/config loading, with a pipe on
/// stdin and an explicit timeout. It does not run the normal scan pipeline.
pub(crate) async fn sudo_worker(args: &[String]) -> Result<i32> {
    use std::os::fd::AsFd;
    let (timeout, command) = args.split_first().context("missing worker timeout")?;
    let timeout = timeout.parse::<u64>().context("invalid worker timeout")?;
    let (cmd, args) = command.split_first().context("missing worker command")?;
    let stdin = std::io::stdin().as_fd().try_clone_to_owned()?;
    let parent = tokio::net::unix::pipe::Receiver::from_owned_fd(stdin)
        .context("sudo worker requires a parent pipe on stdin")?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    supervise_command(cmd, &args, timeout, parent).await
}

/// Run a command via sudo with a custom timeout.
///
/// A second instance of this binary owns the command and its timeout as root.
/// Cancellation closes stdin instead of SIGKILLing sudo before it can clean up.
pub async fn run_sudo_cmd_timeout(cmd: &str, args: &[&str], timeout_secs: u64) -> Result<String> {
    let _permit = PROCESS_LIMIT.acquire().await?;
    // -n (never prompt): has_sudo() — itself `sudo -n` — gates every caller, but
    // the cached sudo timestamp can lapse mid-scan (e.g. the UDP scan after a
    // long `-p-` TCP scan). Without -n, sudo would then prompt for a password on
    // the piped, invisible stderr and hang until the timeout fires. -n turns that
    // into a fast, visible failure instead (same invisible-prompt class as the
    // interactive path already guards against).
    let executable = std::env::current_exe()?;
    let mut command = Command::new("sudo");
    command
        .arg("-n")
        .arg("--")
        .arg(executable)
        .arg(SUDO_WORKER_FLAG)
        .arg(timeout_secs.to_string())
        .arg(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Do not kill sudo on drop: the root worker must see EOF and reap its tool.
    let mut child = spawn_transient(&mut command, "sudo").await?;
    let parent_pipe = child.stdin.take().context("missing sudo worker pipe")?;
    let result = tokio::time::timeout(
        Duration::from_secs(timeout_secs.max(1).saturating_add(5)),
        child.wait_with_output(),
    )
    .await;
    drop(parent_pipe);
    let output = result.context("sudo worker did not finish within its deadline")??;
    let result = combined_output(&output);
    if is_verbose() && !result.trim().is_empty() {
        println!("{}", result.trim_end().dimmed());
    }
    if !output.status.success() {
        return Err(command_failed("sudo", &result));
    }
    Ok(result)
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

    #[tokio::test]
    async fn supervisor_cleans_up_when_parent_disconnects() {
        let tmp = TmpDir::new("parent_disconnect");
        let ready = tmp.0.join("ready");
        let survived = tmp.0.join("survived");
        let script = format!(
            "touch {}; (sleep 1; touch {}) & wait",
            ready.display(),
            survived.display()
        );
        let (parent, reader) = tokio::io::duplex(1);
        let task =
            tokio::spawn(
                async move { supervise_command("sh", &["-c", &script], 10, reader).await },
            );
        tokio::time::timeout(Duration::from_secs(3), async {
            while !ready.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        drop(parent);
        assert_eq!(task.await.unwrap().unwrap(), 130);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(!survived.exists());
    }

    #[tokio::test]
    async fn supervisor_preserves_exit_status_and_enforces_timeout() {
        let (_parent, reader) = tokio::io::duplex(1);
        assert_eq!(
            supervise_command("sh", &["-c", "exit 7"], 5, reader)
                .await
                .unwrap(),
            7
        );
        let (_parent, reader) = tokio::io::duplex(1);
        assert_eq!(
            supervise_command("sh", &["-c", "sleep 10"], 1, reader)
                .await
                .unwrap(),
            124
        );
    }

    #[tokio::test]
    async fn ordinary_runner_abort_kills_descendants() {
        let tmp = TmpDir::new("abort_descendants");
        let ready = tmp.0.join("ready");
        let survived = tmp.0.join("survived");
        let script = format!(
            "touch {}; (sleep 1; touch {}) & wait",
            ready.display(),
            survived.display()
        );
        let task = tokio::spawn(async move { run_cmd_timeout("sh", &["-c", &script], 10).await });
        tokio::time::timeout(Duration::from_secs(3), async {
            while !ready.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        task.abort();
        let _ = task.await;
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(!survived.exists());
    }

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

    #[tokio::test]
    async fn pgroup_timeout_kills_the_whole_group() {
        let tmp = TmpDir::new("pgroup_timeout");
        let marker = tmp.0.join("grandchild-survived");
        // sh stays alive on `wait`; the marker-writing subshell is a grandchild
        // in the same process group. Killing only `sh` (the old behaviour) would
        // orphan the subshell, which would then write the marker at ~t+2s.
        let script = format!("(sleep 2; touch {}) & wait", marker.display());
        let result = capture_output("sh", &["-c", &script], &[], 1).await;
        assert!(result.is_err(), "expected the command to time out");
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(
            !marker.exists(),
            "grandchild survived the timeout — the process group was not killed"
        );
    }

    #[tokio::test]
    async fn pgroup_success_leaves_finished_group_alone() {
        let tmp = TmpDir::new("pgroup_success");
        let marker = tmp.0.join("grandchild-finished");
        let script = format!("(sleep 1; touch {}) & wait", marker.display());
        let output = capture_output("sh", &["-c", &script], &[], 10)
            .await
            .unwrap();
        assert!(output.status.success());
        assert!(
            marker.exists(),
            "guard must not kill a process group whose child exited normally"
        );
    }

    /// ETXTBSY ("Text file busy") is what the flaky full-suite failures died
    /// with: execve on a file that is still open for writing. Holding an
    /// append fd on the script reproduces it deterministically — the retry
    /// must ride it out and succeed once the writer lets go.
    #[tokio::test]
    async fn spawn_transient_retries_etxtbsy() {
        let tmp = TmpDir::new("etxtbsy");
        let script = tmp.file("busy", 0o755);
        fs::write(&script, b"#!/bin/sh\nexit 0\n").unwrap();

        let writer = fs::File::options().append(true).open(&script).unwrap();
        let path = script.to_str().unwrap().to_string();
        let handle =
            tokio::spawn(async move { spawn_transient(&mut Command::new(&path), "busy").await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(writer); // release the write lock — the next retry succeeds

        let mut child = handle.await.unwrap().unwrap();
        assert!(child.wait().await.unwrap().success());
    }
}
