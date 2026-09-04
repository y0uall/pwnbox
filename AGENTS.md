# AGENTS.md — pwnbox

Guidance for AI coding agents working in this repository. Assumes no prior
knowledge of the project.

## Project overview

**pwnbox** is a single-binary CLI that automates recon & enumeration against
HackTheBox targets: `pwnbox <BOX_NAME> <IP> [OPTIONS]`. It wraps classic
pentest tools (nmap, rustscan, feroxbuster, ffuf/gobuster, enum4linux-ng,
crackmapexec/netexec, ldapsearch, kerbrute, …) in a 6-phase async pipeline and
produces a text report (plus optional JSON) in `~/htb/<box>/`.

- Language: **Rust** (edition 2024 + stable let-chains, requires Rust 1.88+), platform: **Linux only**
- License: MIT. The version is authoritative in `Cargo.toml` only — never
  hardcode it here; the CLI string comes from `env!("CARGO_PKG_VERSION")`.
- Crate type: binary only, no lib target. Everything lives under `src/`.
- Runtime: **tokio** multi-thread; heavy parallelism via `tokio::spawn` /
  `tokio::join!` / `JoinHandle`s.

## Repository layout

```
Cargo.toml          deps + release profile (strip, lto, opt-level = "s")
config.toml         default user config; embedded into the binary via
                    include_str!() for `pwnbox --init-config`
setup.sh            bash installer for Kali/Ubuntu/Debian (tools + build +
                    install to /usr/local/bin); checked by shellcheck in CI
src/main.rs         ~2000 lines: clap CLI (derive), pipeline orchestration
                    (`run_scan`), banner/UI rendering, nmap output parsing,
                    watch mode, ferox/vhost result post-processing
src/config.rs       FileConfig/BoxConfig/ScanConfig: config file loading,
                    CLI-over-file merge, box-name validation, wordlist
                    resolution, --skip module list (KNOWN_MODULES)
src/runner.rs       the single process-execution layer + native TCP probe
src/report.rs       shared Report (text lines + JsonReport), atomic writes
src/hosts.rs        target/hostname validation, atomic /etc/hosts updates
src/tools.rs        startup tool-dependency checker (TOOL_DEFS table)
src/scans/          one module per scan phase/service (19 modules)
.github/workflows/  ci.yml (fmt/build/test/clippy/shellcheck/audit),
                    release.yml (tag-triggered GitHub release)
(REVIEW.md)         historical, no longer in the repo. The many
                    `(REVIEW.md finding N)` / `(REVIEW.md "Niedrig")` comments
                    in the source are just markers explaining past fixes —
                    there is no file to open, so don't go looking for one.
```

## Architecture

The pipeline in `run_scan` (`src/main.rs`) runs phases 0–5:

0. **Connectivity** — `scans/connectivity.rs`: ping + TTL-based OS guess.
1. **DNS** — `hosts::add_hosts` seeds `/etc/hosts` with `<box>.htb`, then
   `scans/dns.rs` (zone transfer, reverse DNS) adds discovered hostnames.
2. **TCP** — `scans/tcp.rs`: rustscan for port discovery, then
   `nmap -Pn -sC -sV` on the found ports (falls back to nmap top-1000, then
   full `-p-`). Raw output is saved to `raw/nmap-tcp.txt` (all raw tool
   output — nmap/ferox/vhost files — lives in the output dir's `raw/`
   subdirectory). A background
   `nmap --script vuln` task is spawned (`tcp::vuln_scan`). SSL cert CN/SAN
   hostnames are harvested via an openssl pipeline.
3. **UDP** — `scans/udp.rs`: `sudo nmap -sU --top-ports 100 -sV`, spawned in
   the background, joined after phase 5.
4. **Web** — `scans/web.rs`: per-HTTP-port probes (curl headers/body, vhost
   compare, whatweb with a 60s timeout) run concurrently in a `JoinSet` and are
   written to the report in nmap port order; then background feroxbuster
   (`--time-limit 10m` + 660s runner timeout; partial results on disk survive a
   kill) and ffuf/gobuster (vhost brute) tasks. Returns `Vec<JoinHandle>` to
   the caller.
5. **Services** — one spawned task per detected service: ssh, ftp, smb, rpc,
   nfs, mysql, postgres, redis, winrm, mssql, smtp, ldap, kerberos, snmp.
   Service detection (`detect_service_ports` in main.rs) matches nmap service
   names first, then well-known fallback ports — non-standard ports (e.g. SSH
   on 2222) are detected and passed through. LDAP is a task too; right after
   its join, Kerberos is spawned (it needs the discovered domain) and both are
   collected in parallel with the UDP handle; SNMP runs after the UDP join.

Key architectural patterns — follow them in new code:

- **Isolated per-task reports.** Concurrent tasks write to their own
  `Report::new()` and the main task merges them after join via
  `report.merge_from(&tr)`. This keeps section headers and bodies together.
  Never share one `Report` across parallel tasks.
- **Best-effort phases and modules.** A failing phase or service scan must not
  abort the pipeline: print a yellow `[!]` warning and
  `report.add_error(NAME, ...)`, then continue with empty output — this covers
  the TCP scan and web enumerate too. If `run_scan` still returns `Err`,
  `finalize_report` in `main` writes the report (+ JSON) before propagating.
- **`runner.rs` is the only place that spawns processes.** Use
  `run_cmd` / `run_cmd_timeout` / `run_cmd_status` / `run_cmd_tee` /
  `run_sudo_cmd_timeout`; all wrap `capture_output` (kill_on_drop + timeout,
  global default timeout from `--timeout`/config), except sudo commands, which
  run in their own process group via `capture_output_pgroup` so a timeout or
  abort kills the privileged child too. `tcp_probe` is a native
  tokio TCP banner grabber — prefer it over shelling out to `nc`.
- **Precompiled regexes.** All regexes are module-level
  `static RE_FOO: LazyLock<Regex>`. Never compile a regex inside a loop or
  hot path. A shared `scans::RE_PORT_LINE` filters nmap port lines.
- **Resume support.** TCP/UDP/vuln scans cache raw output in the output dir's
  `raw/` subdirectory and reuse it when `--resume` is passed. New scan types
  should follow the same read-cache-or-run pattern.
- **Signal handling.** `main` races the pipeline against Ctrl+C/SIGTERM. On a
  signal, `run_scan` is dropped (killing the foreground child via
  kill_on_drop), all background tasks registered in the `TaskRegistry` are
  aborted, and the runtime gets ~500ms to process the drops before the partial
  report is written and `process::exit(130)` runs — exit must come last
  because it skips destructors.

## Build and test commands

```bash
cargo build              # debug build
cargo build --release    # optimized binary at target/release/pwnbox
cargo test               # all unit tests (no network or external tools needed)
cargo clippy --all-targets -- -D warnings   # must stay warning-free
cargo fmt --check        # CI enforces rustfmt defaults
shellcheck setup.sh      # if you touched setup.sh
cargo audit --deny warnings                 # dependency advisories (CI job)
```

CI (`.github/workflows/ci.yml`) runs exactly: fmt check, build, test, clippy
with `-D warnings`, shellcheck, and cargo-audit — all must pass. Releases are
built by pushing a `v*` tag (release.yml: release binary + SHA256SUMS →
GitHub Release). Version bumps happen in `Cargo.toml` (`package.version`),
and the CLI version string comes from `env!("CARGO_PKG_VERSION")`, so no
other file needs editing.

## Testing instructions

- All tests are **inline `#[cfg(test)] mod tests`** at the bottom of each
  source file; there is no `tests/` directory. Add tests next to the code
  they cover.
- Tests are pure unit tests: parser/validator logic is fed fixture strings
  (e.g. canned nmap output), filesystem-touching tests use a `TmpDir` helper
  under the system temp dir. Tests must not hit the network, require sudo, or
  depend on pentest tools being installed.
- Async tests use `#[tokio::test]`.
- Tests that change the process CWD must serialize with the existing
  `CWD_LOCK` mutex pattern (see `config.rs`).

## Code style guidelines

- Standard rustfmt (4 spaces), clippy-clean under `-D warnings`. Run both
  before considering work done.
- Error handling: `anyhow::Result` everywhere; `bail!`/`Context` for errors.
  No `unwrap()` outside tests; `expect` only where a comment justifies it.
- Modern idioms are in use: let-chains (`if let Some(x) = ... && cond`),
  `is_ok_and`, `LazyLock`. Match the surrounding style.
- Terminal output uses the `colored` crate with semantic prefixes:
  `[*]` info (cyan), `[+]` success (green), `[!]` warning/failure (yellow or
  red), `[-]` hard error. Reports use `report.section("NAME")` +
  `report.add(...)` for text, and `add_port` / `add_service_finding` /
  `add_vuln` / `add_hostname` / `add_next_step` / `add_error` for the JSON
  side — keep both in sync when adding findings.
- Comments are English, explanatory, and focus on *why* (often referencing a
  past bug or a tool's quirk). Keep that voice; update stale comments when
  you change behavior.
- New CLI flags: clap derive struct `Cli` in main.rs. Flags hidden from the
  short `-h` view get `hide_short_help = true`.
- New skippable modules must be added to `KNOWN_MODULES` in `config.rs` and
  gated with `scan_cfg.should_skip("name")`.
- New external tools: add a `ToolDef` entry in `tools.rs` (name, alternatives,
  consuming modules, required flag), a config override field in
  `ToolsConfig` + `ScanConfig::tool()` if it needs a path override, and a
  matching entry in `config.toml`'s `[tools]` section.

## Security considerations

This tool runs external commands with user-controlled input and sometimes
sudo; preserve these invariants:

- **Validate before use.** The target (`hosts::is_valid_target`) and box name
  (`config::is_valid_box_name`) are validated at startup because they flow
  into paths, hostnames, and one `bash -c` openssl pipeline
  (`scans/tcp.rs:ssl_hostnames`). Never introduce new shell interpolation of
  user input — pass arguments as argv arrays.
- **Untrusted local config.** `[tools]` path overrides from `./config.toml`
  are ignored on purpose (`ConfigSource::Local`); only the explicit `--config`
  path and `~/.config/pwnbox/config.toml` may redirect tool binaries.
- **Atomic writes.** Reports and `/etc/hosts` are written via temp file +
  rename/install so a kill mid-write never leaves a truncated file.
- **sudo usage.** UDP scan and `/etc/hosts` writes need passwordless sudo;
  both degrade gracefully (warn + continue) when it is absent. `sudo -v` is
  warmed up at scan start via `run_cmd_interactive` (inherited stdio, so the
  password prompt reaches the terminal).
- **Command existence checks** go through the memoized `command_exists`
  (pure `$PATH` filesystem lookup, no `which` subprocess).
