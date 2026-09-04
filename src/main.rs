use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;
use clap::builder::styling::{AnsiColor, Style, Styles};
use colored::Colorize;
use regex::Regex;
use tokio::task::{AbortHandle, JoinHandle};
use unicode_width::UnicodeWidthStr;

// precompile these so we don't re-create them on every call
static RE_OPEN_PORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^(\d+)/(tcp|udp)\s+open").unwrap());
// Matches "open" and UDP's "open|filtered" so udp ports aren't dropped.
// Uses [ \t]/[^\n] rather than \s/. so the match stays on one line — otherwise a
// version-less port line would let \s eat the newline and (.*) swallow the next
// port line (in the regex crate \s matches \n).
// Distinct from the scanners' `RE_PORT_LINE` prefix filter: this one captures the
// port, proto, state, service and version fields for pretty-printing / JSON
// extraction. The state is captured verbatim so UDP's "open|filtered" reaches
// the JSON report instead of being flattened to "open" (REVIEW.md "Niedrig").
static RE_PORT_DETAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^(\d+)/(tcp|udp)[ \t]+(open(?:\|filtered)?)[ \t]+(\S+)[ \t]*([^\n]*)").unwrap()
});
static RE_TCP_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d+/tcp").unwrap());
static RE_UDP_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d+/udp").unwrap());

mod config;
mod hosts;
mod report;
mod runner;
mod scans;
mod tools;

use config::{BoxConfig, FileConfig, ScanConfig};
use report::Report;

/// Tasteful colors for `--help` / `-h` and error output, themed to match
/// pwnbox's own banner palette: magenta section headers, cyan flags, yellow
/// values, green/red for valid/invalid suggestions.
fn cli_styles() -> Styles {
    Styles::styled()
        .header(
            Style::new()
                .bold()
                .fg_color(Some(AnsiColor::BrightMagenta.into())),
        )
        .usage(
            Style::new()
                .bold()
                .fg_color(Some(AnsiColor::BrightMagenta.into())),
        )
        .literal(Style::new().fg_color(Some(AnsiColor::BrightCyan.into())))
        .placeholder(Style::new().fg_color(Some(AnsiColor::BrightYellow.into())))
        .error(
            Style::new()
                .bold()
                .fg_color(Some(AnsiColor::BrightRed.into())),
        )
        .valid(Style::new().fg_color(Some(AnsiColor::BrightGreen.into())))
        .invalid(
            Style::new()
                .bold()
                .fg_color(Some(AnsiColor::BrightRed.into())),
        )
}

// ── `-h` / `--help` header art ──────────────────────────────────────────
// "pwnbox" as a figlet "pagga" wordmark: 3 rows, each exactly LOGO_W display
// columns, drawn with a smooth horizontal truecolor gradient. The colored
// strings come from `colored`, which auto-strips ANSI when stdout isn't a TTY
// (or NO_COLOR is set), so piped/redirected help degrades to plain block art.

const LOGO: [&str; 3] = [
    "░█▀█░█░█░█▀█░█▀▄░█▀█░█░█",
    "░█▀▀░█▄█░█░█░█▀▄░█░█░▄▀▄",
    "░▀░░░▀░▀░▀░▀░▀▀░░▀▀▀░▀░▀",
];

/// Gradient colour stops (green → cyan → violet) the wordmark is painted with.
const GRADIENT: [(u8, u8, u8); 3] = [(80, 250, 123), (80, 211, 238), (199, 120, 221)];

/// How much to darken the `░` filler cells so they read as a soft shadow
/// behind the bright letters rather than competing with them (~1/3 intensity).
const SHADOW_DIM: f32 = 0.34;

/// Help layout: our colored banner, then usage/args, then the examples block.
/// `{before-help}` is long-aware — it renders `before_long_help` for `--help`
/// and `before_help` for `-h`. We drop `{about}` because the banner's tagline
/// already carries it. clap pads `{before-help}` with a trailing blank line and
/// `{after-help}` with a leading one, so we don't add those newlines ourselves.
const HELP_TEMPLATE: &str = "\
{before-help}{usage-heading} {usage}

{all-args}{after-help}
";

/// Pick a colour `frac` (0.0..=1.0) of the way along the gradient stops.
fn gradient_at(frac: f32) -> (u8, u8, u8) {
    let n = GRADIENT.len();
    if n == 1 || frac <= 0.0 {
        return GRADIENT[0];
    }
    if frac >= 1.0 {
        return GRADIENT[n - 1];
    }
    let seg_span = 1.0 / (n - 1) as f32;
    let seg = ((frac / seg_span).floor() as usize).min(n - 2);
    let local = (frac - seg as f32 * seg_span) / seg_span;
    let (r0, g0, b0) = GRADIENT[seg];
    let (r1, g1, b1) = GRADIENT[seg + 1];
    let lerp = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * local).round() as u8;
    (lerp(r0, r1), lerp(g0, g1), lerp(b0, b1))
}

/// Paint one wordmark row: solid glyphs (█ ▀ ▄) get the full horizontal
/// gradient (lined up across all three rows by column), while the `░` filler
/// cells get a darkened tint of the same column colour so they recede as a
/// soft shadow instead of competing with the letters.
fn gradient_row(line: &str) -> String {
    let cols = line.chars().count().max(1);
    let mut out = String::new();
    for (i, ch) in line.chars().enumerate() {
        let frac = i as f32 / (cols - 1).max(1) as f32;
        let (r, g, b) = gradient_at(frac);
        let painted = if ch == '░' {
            let dim = |c: u8| (c as f32 * SHADOW_DIM) as u8;
            ch.to_string().truecolor(dim(r), dim(g), dim(b)).to_string()
        } else {
            ch.to_string().truecolor(r, g, b).to_string()
        };
        out.push_str(&painted);
    }
    out
}

/// The colored header shown above `-h` (and, with `long`, `--help`) output:
/// gradient wordmark + a one-line tagline (+ a short blurb for `--help`).
fn help_banner(long: bool) -> String {
    let mut lines: Vec<String> = LOGO
        .iter()
        .map(|row| format!("  {}", gradient_row(row)))
        .collect();
    lines.push(format!(
        "  {} {} {} {} {} {} {} {}",
        "⚡".bright_yellow(),
        "Automated recon & enumeration".bright_white(),
        "·".dimmed(),
        "HackTheBox".bright_magenta().bold(),
        "·".dimmed(),
        format!("v{}", env!("CARGO_PKG_VERSION")).dimmed(),
        "·".dimmed(),
        // maker's mark — dimmed grey to match the version segment
        "by uall".dimmed(),
    ));
    if long {
        lines.push(String::new());
        lines.push(format!(
            "  {}",
            "Runs a 6-phase pipeline: discovery → TCP/UDP → service & web enum,".dimmed(),
        ));
        lines.push(format!(
            "  {}",
            "writing a clean text report (plus optional JSON with --json).".dimmed(),
        ));
    }
    lines.join("\n")
}

/// The colored examples block shown below the args (clap `after_help`).
fn help_examples() -> String {
    // (command, description) — description "" means a bare example line.
    const ROWS: [(&str, &str); 4] = [
        ("pwnbox Lame 10.10.10.3", "full recon"),
        (
            "pwnbox Lame 10.10.10.3 --fast",
            "quick TCP scan + web headers",
        ),
        ("pwnbox Lame 10.10.10.3 --skip smb,udp", ""),
        ("pwnbox --init-config", "write a default config.toml"),
    ];
    // align descriptions just past the widest command that has one
    let col = ROWS
        .iter()
        .filter(|(_, d)| !d.is_empty())
        .map(|(c, _)| c.chars().count())
        .max()
        .unwrap_or(0)
        + 2;

    let mut s = format!("{}\n", "Examples:".bright_magenta().bold());
    for (cmd, desc) in ROWS {
        if desc.is_empty() {
            s.push_str(&format!(
                "  {} {}\n",
                "▸".bright_cyan(),
                cmd.bright_yellow()
            ));
        } else {
            let pad = " ".repeat(col.saturating_sub(cmd.chars().count()));
            s.push_str(&format!(
                "  {} {}{}{}\n",
                "▸".bright_cyan(),
                cmd.bright_yellow(),
                pad,
                desc.dimmed(),
            ));
        }
    }
    s.push_str(&format!(
        "\n{}  {}",
        "HackTheBox".bright_magenta().bold(),
        "https://www.hackthebox.com/".bright_cyan().underline(),
    ));
    s
}

#[derive(Parser)]
#[command(
    name = "pwnbox",
    version,
    author = "uall",
    about = "Automated recon & enumeration for HackTheBox",
    before_help = help_banner(false),
    before_long_help = help_banner(true),
    after_help = help_examples(),
    help_template = HELP_TEMPLATE,
    styles = cli_styles(),
    arg_required_else_help = true,
    override_usage = "pwnbox [OPTIONS] <BOX> <IP>\n       pwnbox --init-config",
)]
struct Cli {
    /// Box name (e.g. Lame, Legacy)
    #[arg(value_name = "BOX", required_unless_present = "init_config")]
    box_name: Option<String>,

    /// Target IP address
    #[arg(value_name = "IP", required_unless_present = "init_config")]
    ip: Option<String>,

    // ── Common — shown in the quick `-h` view ──────────────
    /// Quick scan: TCP + web headers only
    ///
    /// Skips the UDP sweep and deep per-service enumeration — a fast first look.
    #[arg(short, long)]
    fast: bool,

    /// Skip services (comma-separated: smb,ldap,web)
    #[arg(short, long, value_delimiter = ',', value_name = "SVC")]
    skip: Vec<String>,

    /// Output directory (default: ~/htb/<box-name>/)
    #[arg(short, long, value_name = "PATH")]
    output: Option<String>,

    /// Also write a JSON report next to the text one
    #[arg(long)]
    json: bool,

    // ── Advanced — hidden from `-h`, full list in `--help` ─
    /// Reuse existing nmap output instead of re-scanning
    #[arg(long, hide_short_help = true)]
    resume: bool,

    /// Show full tool output instead of summaries
    #[arg(short, long, hide_short_help = true)]
    verbose: bool,

    /// Re-scan ports every N minutes and alert on changes
    #[arg(long, value_name = "MINUTES", hide_short_help = true)]
    watch: Option<u64>,

    /// Global timeout per command in seconds
    #[arg(short, long, value_name = "SECS", hide_short_help = true)]
    timeout: Option<u64>,

    /// Feroxbuster thread count
    #[arg(long, value_name = "N", hide_short_help = true)]
    ferox_threads: Option<u16>,

    /// Path to config.toml
    ///
    /// Default: ./config.toml or ~/.config/pwnbox/config.toml
    #[arg(short, long, value_name = "PATH", hide_short_help = true)]
    config: Option<String>,

    /// Generate a default config.toml and exit
    #[arg(long, hide_short_help = true)]
    init_config: bool,
}

/// Grab all open port/proto pairs from nmap output.
fn parse_open_ports(output: &str) -> HashSet<(u16, String)> {
    let mut ports = HashSet::new();
    for cap in RE_OPEN_PORT.captures_iter(output) {
        if let Ok(p) = cap[1].parse::<u16>() {
            ports.insert((p, cap[2].to_string()));
        }
    }
    ports
}

/// Quick check: is this port/proto combo in our set?
fn has_port(ports: &HashSet<(u16, String)>, port: u16, proto: &str) -> bool {
    // Iterate rather than `contains(&(port, proto.to_string()))`: the set is
    // small (open ports on one host) and this avoids allocating a String on
    // every call — a tuple key can't be borrowed as `(u16, &str)`.
    ports.iter().any(|(p, pr)| *p == port && pr == proto)
}

/// Build a port -> service-name map for the given protocol.
fn port_service_map(output: &str, proto: &str) -> HashMap<u16, String> {
    parse_port_entries(output)
        .into_iter()
        .filter(|(_, p, _, _, _)| p == proto)
        .map(|(port, _, _, service, _)| (port, service))
        .collect()
}

/// Decide which TCP ports belong to a service, using nmap's service name first
/// and falling back to well-known ports if no name matched.
///
/// Returns ports in a stable order: service-name matches first (sorted by port),
/// then open fallback ports (in the order given).
fn detect_service_ports(
    services: &HashMap<u16, String>,
    names: &[&str],
    fallback_ports: &[u16],
    open_ports: &HashSet<(u16, String)>,
) -> Vec<u16> {
    let mut result = Vec::new();
    let mut seen = HashSet::new();

    // Ports whose nmap service name matches any of the requested names.
    let mut named: Vec<u16> = services
        .iter()
        .filter(|(_, svc)| names.contains(&svc.as_str()))
        .map(|(&port, _)| port)
        .collect();
    named.sort_unstable();
    for port in named {
        if seen.insert(port) {
            result.push(port);
        }
    }

    // Well-known fallback ports that are actually open.
    for &port in fallback_ports {
        if has_port(open_ports, port, "tcp") && seen.insert(port) {
            result.push(port);
        }
    }

    result
}

/// Pretty-print open port lines from nmap output.
fn print_port_lines(output: &str, line_re: &Regex) {
    let lines: Vec<&str> = output.lines().filter(|l| line_re.is_match(l)).collect();
    if lines.is_empty() {
        println!("  {}", "(no open ports)".dimmed());
    } else {
        for line in &lines {
            if let Some(caps) = RE_PORT_DETAIL.captures(line) {
                println!(
                    "  {}/{} {} {}",
                    caps[1].green(),
                    caps[2].dimmed(),
                    caps[3].yellow(),
                    caps[4].dimmed()
                );
            } else {
                println!("  {line}");
            }
        }
    }
}

fn phase_header(step: &str, description: &str) {
    println!("\n{} {}", step.green(), description.yellow());
}

fn phase_done(phase_start: Instant) {
    let elapsed = phase_start.elapsed();
    println!(
        "  {} {}",
        "✓ done".green(),
        format!("({:.1}s)", elapsed.as_secs_f64()).dimmed()
    );
}

// ────────────────────────────────────────────────────────────────────────
// Banner helpers — a fully-enclosed, rounded box ("rundes Kästchen").
//
// All width math runs on the ANSI-stripped *visible* length with saturating
// arithmetic, and every variable value is truncated to the inner width before
// it is colored. So the right border can never drift out of alignment, and an
// over-long title or path can never underflow/panic. Width is measured with
// unicode-width (display columns), so wide glyphs like ⚡ count as the 2 cells
// the terminal uses and the box still lines up.
// ────────────────────────────────────────────────────────────────────────

const BANNER_INNER: usize = 56; // visible chars in the padded content area
const LABEL_W: usize = 9; // label column width (longest label + a gap)

// Strip ANSI CSI color sequences so we can measure on-screen width — the byte
// length of a ColoredString includes the escape codes, which breaks padding.
static ANSI_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\x1b\[[0-9;]*m").unwrap());

fn visible_width(s: &str) -> usize {
    // display width (not char count) so wide glyphs like ⚡ are measured as the
    // 2 cells the terminal actually uses — keeps the right border aligned.
    ANSI_RE.replace_all(s, "").width()
}

/// Truncate a plain string to at most `max` visible chars, using a leading
/// '…' when it must cut — keeping the tail (for paths, that's the filename).
fn truncate_tail(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        s.to_string()
    } else if max == 0 {
        String::new()
    } else {
        let tail: String = s.chars().skip(n - (max - 1)).collect();
        format!("…{tail}")
    }
}

/// Border/frame accent color — change this one spot to re-theme the whole box.
fn frame(s: &str) -> String {
    s.bright_magenta().to_string()
}

/// Top border with the title embedded after the corner: `╭─ <title> ─…─╮`.
/// `title` is already colored.
fn banner_top(title: &str) -> String {
    // total visible width matches a content row: │ + ' ' + INNER + ' ' + │
    let total = BANNER_INNER + 4;
    // glyphs before the dash run: ╭ ─ ' ' title ' ' (= title + 4) plus ╮ (= 1)
    let dashes = total.saturating_sub(visible_width(title) + 5);
    format!(
        "{}{} {} {}{}",
        frame("╭"),
        frame("─"),
        title,
        frame(&"─".repeat(dashes)),
        frame("╮")
    )
}

/// Bottom border: a plain rounded rule of the same total width.
fn banner_bottom() -> String {
    format!(
        "{}{}{}",
        frame("╰"),
        frame(&"─".repeat(BANNER_INNER + 2)),
        frame("╯")
    )
}

/// One content row: `│ <content padded to BANNER_INNER> │`. `content` may be
/// colored; the trailing pad is computed from its visible width.
fn banner_row(content: &str) -> String {
    let pad = BANNER_INNER.saturating_sub(visible_width(content));
    format!(
        "{} {}{} {}",
        frame("│"),
        content,
        " ".repeat(pad),
        frame("│")
    )
}

/// A `label   value` row. `value` is already colored; callers truncate any
/// unbounded value (e.g. a path) before coloring it.
fn banner_kv(label: &str, value: &str) -> String {
    let lab = format!("{:<width$}", label, width = LABEL_W);
    banner_row(&format!("  {}{}", lab.dimmed(), value))
}

/// Visible-char budget available to a value after the indent + label column.
fn kv_budget() -> usize {
    BANNER_INNER.saturating_sub(2 + LABEL_W)
}

/// Opening banner: target, start time, active modes, and skipped services.
fn print_start_banner(name: &str, ip: &str, fast: bool, resume: bool, skip: &[String], json: bool) {
    let title = format!(
        "{} {} {}",
        "pwnbox".bright_green().bold(),
        "·".dimmed(),
        "HackTheBox".bright_magenta().bold()
    );
    println!("{}", banner_top(&title));
    println!("{}", banner_row(""));

    let target = format!(
        "{} {} {}",
        name.bright_yellow().bold(),
        "→".dimmed(),
        ip.bright_red().bold()
    );
    println!("{}", banner_kv("target", &target));

    let started = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    println!("{}", banner_kv("started", &started.cyan().to_string()));

    let mut badges: Vec<String> = Vec::new();
    if fast {
        badges.push(format!(
            "{} {}",
            "⚡".yellow(),
            "fast".bright_yellow().bold()
        ));
    }
    if resume {
        badges.push(format!("{} {}", "↻".cyan(), "resume".bright_cyan().bold()));
    }
    if json {
        badges.push("json+text".green().bold().to_string());
    }
    if !badges.is_empty() {
        let sep = format!(" {} ", "·".dimmed());
        println!("{}", banner_kv("mode", &badges.join(&sep)));
    }

    if !skip.is_empty() {
        let skip_str = truncate_tail(&skip.join(", "), kv_budget());
        println!("{}", banner_kv("skip", &skip_str.yellow().to_string()));
    }

    println!("{}", banner_row(""));
    println!("{}", banner_bottom());
}

/// Closing banner: target, wall-clock duration, report (+ optional JSON) path.
fn print_finish_banner(
    name: &str,
    ip: &str,
    mins: u64,
    secs: u64,
    report_path: &str,
    json_path: Option<&str>,
    mode_tag: &str,
) {
    let title = format!(
        "{} {} {}",
        "pwnbox".bright_green().bold(),
        "·".dimmed(),
        format!("✓ {mode_tag} complete").bright_green().bold()
    );
    println!();
    println!("{}", banner_top(&title));
    println!("{}", banner_row(""));

    let target = format!(
        "{} {} {}",
        name.bright_yellow().bold(),
        "→".dimmed(),
        ip.bright_red().bold()
    );
    println!("{}", banner_kv("target", &target));

    let duration = format!("{mins}m {secs:02}s");
    println!(
        "{}",
        banner_kv("duration", &duration.bright_white().bold().to_string())
    );

    let report = truncate_tail(report_path, kv_budget());
    println!("{}", banner_kv("report", &report.yellow().to_string()));
    if let Some(jp) = json_path {
        let jp = truncate_tail(jp, kv_budget());
        println!("{}", banner_kv("json", &jp.yellow().to_string()));
    }

    println!("{}", banner_row(""));
    println!("{}", banner_bottom());
}

/// Slim section header printed above the textual scan report.
fn print_report_banner(name: &str, ip: &str) {
    let title = format!(
        "{} {} {} {} {}",
        "scan report".bright_green().bold(),
        "·".dimmed(),
        name.bright_yellow().bold(),
        "→".dimmed(),
        ip.bright_red().bold()
    );
    println!("{}", banner_top(&title));
    println!("{}", banner_bottom());
}

/// Extract structured port info from nmap output for the JSON report.
/// Returns (port, proto, state, service, version) — state keeps UDP's
/// "open|filtered" verbatim.
fn parse_port_entries(output: &str) -> Vec<(u16, String, String, String, String)> {
    let mut entries = Vec::new();
    for cap in RE_PORT_DETAIL.captures_iter(output) {
        if let Ok(port) = cap[1].parse::<u16>() {
            entries.push((
                port,
                cap[2].to_string(),
                cap[3].to_string(),
                cap[4].to_string(),
                cap[5].to_string(),
            ));
        }
    }
    entries
}

/// Abort handles for every background task the pipeline spawns (vuln scan, UDP
/// scan, service scans, web brute-forces). The signal path aborts them all so
/// their child processes are actually killed: `kill_on_drop` (runner.rs) only
/// fires when a task's future is dropped, and a bare `process::exit` would
/// never drop anything — orphaned nmap/feroxbuster children were the result
/// (REVIEW.md finding 3).
///
/// A std Mutex is enough here: the lock is only ever held for a push/iteration,
/// never across an `.await`.
#[derive(Clone, Default)]
struct TaskRegistry(Arc<Mutex<Vec<AbortHandle>>>);

impl TaskRegistry {
    /// Spawn a task and register its abort handle in one step.
    fn spawn<F>(&self, fut: F) -> JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let handle = tokio::spawn(fut);
        self.track(&handle);
        handle
    }

    /// Register a task that was spawned elsewhere (e.g. inside web::enumerate).
    fn track<T>(&self, handle: &JoinHandle<T>) {
        self.0.lock().unwrap().push(handle.abort_handle());
    }

    /// Abort every registered task; a no-op for tasks that already finished.
    fn abort_all(&self) {
        for handle in self.0.lock().unwrap().iter() {
            handle.abort();
        }
    }
}

/// LDAP task result: the task's isolated report plus the discovered domain.
type LdapTask = JoinHandle<Result<(Report, Option<String>)>>;

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().nth(1).as_deref() == Some(runner::SUDO_WORKER_FLAG) {
        let args: Vec<String> = std::env::args().skip(2).collect();
        let code = runner::sudo_worker(&args).await?;
        std::process::exit(code);
    }
    let cli = Cli::parse();

    // --init-config: dump a default config and bail
    if cli.init_config {
        let path = std::path::PathBuf::from(cli.config.as_deref().unwrap_or("config.toml"));
        return FileConfig::init(&path);
    }

    // clap enforces these via `required_unless_present = "init_config"`, and the
    // --init-config path already returned above, so they are guaranteed present.
    let box_name = cli.box_name.as_deref().expect("BOX is required by clap");
    let ip = cli.ip.as_deref().expect("IP is required by clap");

    // reject anything that isn't a real IP/hostname before it reaches any command
    if !hosts::is_valid_target(ip) {
        eprintln!(
            "{} Invalid target {:?} — expected an IP address or hostname",
            "[!]".red().bold(),
            ip
        );
        std::process::exit(1);
    }

    // box_name becomes part of the output path (~/htb/<box>/) and generated
    // hostnames — reject anything that could escape the directory or contain
    // shell metacharacters.
    if !config::is_valid_box_name(box_name) {
        eprintln!(
            "{} Invalid box name {:?} — must be alphanumeric/hyphen/underscore, 1-64 chars",
            "[!]".red().bold(),
            box_name
        );
        std::process::exit(1);
    }

    // load config (or fall back to defaults)
    let file_cfg = FileConfig::load(cli.config.as_deref())?;

    let cfg = BoxConfig::new(box_name, ip, cli.output.as_deref());
    let scan_cfg = ScanConfig::new(
        cli.verbose.then_some(true),
        &cli.skip,
        cli.timeout,
        cli.fast.then_some(true),
        cli.ferox_threads,
        &file_cfg,
    );
    let report = Report::new();

    // apply the resolved timeout/verbosity globally so every command honours them
    runner::set_default_timeout(scan_cfg.timeout);
    runner::set_verbose(scan_cfg.verbose);

    // make sure output dir exists — plus raw/, which keeps the noisy tool
    // output (nmap/ferox/vhost files) away from the final report(s)
    tokio::fs::create_dir_all(&cfg.output_dir).await?;
    tokio::fs::create_dir_all(cfg.output_dir.join("raw")).await?;

    // show the start banner
    print_start_banner(
        &cfg.name,
        &cfg.ip,
        scan_cfg.fast,
        cli.resume,
        &cli.skip,
        cli.json,
    );

    // Check only tools needed by the resolved scan plan, including overrides.
    tools::check_all(&scan_cfg).await?;

    // Prepare report clones for the interrupt path so a Ctrl+C can flush a
    // partial report even while the pipeline is still running.
    let report_for_signal = report.clone();
    let report_path = cfg.report_path.clone();
    let json_path = if cli.json {
        Some(cfg.report_path.with_extension("json"))
    } else {
        None
    };

    // Handles for the failure path: even when run_scan bails out with an error,
    // main must still flush whatever the report holds (REVIEW.md finding 1).
    let report_for_error = report.clone();
    let report_path_for_error = cfg.report_path.clone();
    let json_for_error = cli.json;

    // Abort handles for every background task the pipeline spawns, so the
    // interrupt path can stop them (and, via kill_on_drop, their child
    // processes) before exiting.
    let tasks = TaskRegistry::default();

    let scan = run_scan(cli, cfg, scan_cfg, report, tasks.clone());
    let signal = async {
        let ctrl_c = tokio::signal::ctrl_c();
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate.recv() => {},
        }
    };

    tokio::select! {
        res = scan => {
            if let Err(e) = &res {
                // The pipeline aborted before run_scan could write its report —
                // flush the partial findings instead of losing them.
                eprintln!(
                    "{} Scan failed: {e} — writing partial report...",
                    "[-]".red().bold()
                );
                finalize_report(&report_for_error, &report_path_for_error, json_for_error).await;
            }
            return res;
        }
        // Losing the select! drops `scan`, which kills the *foreground* child
        // process via kill_on_drop; the shutdown below handles the background
        // tasks and the partial report.
        _ = signal => {}
    }

    // ── graceful shutdown on SIGINT/SIGTERM (REVIEW.md finding 3) ──
    println!(
        "\n{} Interrupted — aborting background tasks...",
        "[!]".yellow()
    );
    tasks.abort_all();
    // Give runtime worker threads a moment to drop the aborted tasks' futures:
    // only when those drops run does kill_on_drop fire for their children
    // (nmap, feroxbuster, ffuf, ...). exit(130) must come AFTER this cleanup
    // because process::exit runs no destructors — exiting immediately would
    // leave the still-running children behind as (partly root-owned) orphans.
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("{} Writing partial report...", "[!]".yellow());
    if let Err(e) = report_for_signal.write_partial(&report_path).await {
        eprintln!("Failed to write partial report: {e}");
    }
    if let Some(jp) = json_path
        && let Err(e) = report_for_signal.write_json(&jp).await
    {
        eprintln!("Failed to write partial JSON report: {e}");
    }
    std::process::exit(130);
}

/// Last-ditch report flush for the error path: writes the text report (plus the
/// JSON report when `--json` was given). Write failures are logged, not
/// propagated — the original scan error is what `main` returns.
async fn finalize_report(report: &Report, report_path: &Path, json: bool) {
    if let Err(e) = report.write_to_file(report_path).await {
        eprintln!("{} Failed to write report: {e}", "[-]".red().bold());
    }
    if json {
        let json_path = report_path.with_extension("json");
        if let Err(e) = report.write_json(&json_path).await {
            eprintln!("{} Failed to write JSON report: {e}", "[-]".red().bold());
        }
    }
}

/// Persist watch-mode findings (port changes, rescan errors) right after they
/// happen. The watch loop never returns, so without this rewrite the events
/// would stay memory-only until Ctrl+C — and the interrupt flush is not
/// guaranteed to run before exit (REVIEW.md "Niedrig"). Best-effort: a failed
/// rewrite must not kill the watch loop.
async fn persist_watch_report(report: &Report, report_path: &Path, json_path: Option<&Path>) {
    if let Err(e) = report.write_to_file(report_path).await {
        println!("{} Could not update report file: {e}", "[!]".yellow());
    }
    if let Some(p) = json_path
        && let Err(e) = report.write_json(p).await
    {
        println!("{} Could not update JSON report: {e}", "[!]".yellow());
    }
}

/// Execute the full scan pipeline.
///
/// This runs inside `tokio::select!` in `main` alongside a signal handler, so it
/// can be cancelled at any point; the shared `Report` is then flushed by the
/// interrupt path. Core-phase failures (TCP scan, web enumerate) are recorded via
/// `report.add_error` and degraded to empty output instead of aborting; any error
/// that still escapes is flushed by `finalize_report` in `main`.
///
/// Every background task is spawned through `registry` so the signal path can
/// abort them all before exiting (their child processes die via kill_on_drop).
async fn run_scan(
    cli: Cli,
    cfg: BoxConfig,
    scan_cfg: ScanConfig,
    report: Report,
    registry: TaskRegistry,
) -> Result<()> {
    let start = Instant::now();
    // raw tool output (nmap/ferox/vhost files) — created in `main`, used by
    // every scan module below
    let raw_dir = cfg.output_dir.join("raw");

    // start building the report
    report
        .add(&format!("pwnbox  {}  →  {}", cfg.name, cfg.ip))
        .await;
    report
        .add(&chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string())
        .await;
    if scan_cfg.fast {
        report.add("Mode: fast").await;
    }

    // seed JSON report with basic info
    {
        let mut json = report.json_mut().await;
        json.box_name = cfg.name.clone();
        json.ip = cfg.ip.clone();
        json.timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        json.mode = if scan_cfg.fast {
            "fast".to_string()
        } else {
            "full".to_string()
        };
    }

    // warm up sudo so we don't get prompted mid-scan — interactive stdio, so a
    // password prompt actually reaches the terminal instead of hanging unseen
    // on a piped stderr until the timeout (REVIEW.md finding 6)
    if !runner::has_sudo().await {
        println!("{} sudo required (for /etc/hosts & UDP scan)", "[*]".cyan());
        let _ = runner::run_cmd_interactive("sudo", &["-v"]).await;
    }

    // --- Phase 0: ping check + OS guess from TTL ---
    let t = Instant::now();
    phase_header("[0/6]", "Connectivity check...");
    let os_guess = if scan_cfg.should_skip("connectivity") {
        println!("{} Connectivity check skipped", "[*]".dimmed());
        "unknown (connectivity skipped)".to_string()
    } else {
        scans::connectivity::check(&cfg.ip, &report).await?
    };
    {
        let mut json = report.json_mut().await;
        json.os_guess = os_guess.clone();
    }
    phase_done(t);

    // --- Phase 1: /etc/hosts + DNS recon ---
    let t = Instant::now();
    phase_header("[1/6]", "/etc/hosts + DNS recon...");
    let _ = hosts::add_hosts(&cfg.ip, std::slice::from_ref(&cfg.hostname)).await;
    report.add_hostname(&cfg.hostname).await;

    // dns::recon checks for `dig` itself, so we don't gate on the dns module's
    // optional tools (dnsx/subfinder) — and a recon error must not abort the scan
    if scan_cfg.should_skip("dns") {
        // explicitly skipped by user
    } else {
        match scans::dns::recon(&cfg.ip, &cfg.hostname, &scan_cfg, &report).await {
            Ok(dns_hosts) => {
                for h in &dns_hosts {
                    report.add_hostname(h).await;
                }
            }
            Err(e) => {
                println!("{} DNS recon failed: {e}", "[!]".yellow());
                report.add_error("DNS", &e.to_string()).await;
            }
        }
    }
    phase_done(t);

    // --- Phase 2: TCP port discovery ---
    let t = Instant::now();
    phase_header("[2/6]", "TCP port discovery...");
    // TCP is a core phase, but a failure here must not kill the whole report —
    // record the error and continue with empty port data, same as DNS above.
    let nmap_output = if scan_cfg.should_skip("tcp") {
        println!("{} TCP scan skipped", "[*]".dimmed());
        String::new()
    } else {
        match scans::tcp::scan(&cfg.ip, &raw_dir, &report, cli.resume, &scan_cfg).await {
            Ok(output) => output,
            Err(e) => {
                println!("{} TCP scan failed: {e}", "[!]".yellow());
                report.add_error("TCP", &e.to_string()).await;
                String::new()
            }
        }
    };

    // pull hostnames from nmap output (SSL certs, redirects, etc.) — best-effort
    let nmap_hosts = match scans::tcp::extract_hostnames(&nmap_output, &cfg.ip).await {
        Ok(hosts) => hosts,
        Err(e) => {
            println!("{} Hostname extraction failed: {e}", "[!]".yellow());
            report.add_error("HOSTNAMES", &e.to_string()).await;
            Vec::new()
        }
    };
    for h in &nmap_hosts {
        report.add_hostname(h).await;
    }
    phase_done(t);

    // parse ports once so we can decide which service scans to run
    let tcp_ports = parse_open_ports(&nmap_output);
    let tcp_services = port_service_map(&nmap_output, "tcp");

    // grab hostnames from SSL certs on HTTPS ports — a port counts as SSL if it's
    // a well-known TLS port or its own nmap service name mentions ssl. The
    // service names were already captured into tcp_services above, so this stays
    // a single pass over the nmap output (REVIEW.md "Niedrig").
    let ssl_ports: Vec<u16> = tcp_ports
        .iter()
        .filter(|(_, proto)| proto == "tcp")
        .map(|(p, _)| *p)
        .filter(|p| {
            [443, 8443].contains(p) || tcp_services.get(p).is_some_and(|svc| svc.contains("ssl"))
        })
        .collect();
    if !ssl_ports.is_empty() {
        let known: Vec<String> = {
            let json = report.json_mut().await;
            json.hostnames.clone()
        };
        let ssl_hosts = match scans::tcp::ssl_hostnames(&cfg.ip, &ssl_ports, &known, &report).await
        {
            Ok(hosts) => hosts,
            Err(e) => {
                println!("{} TLS hostname discovery failed: {e}", "[!]".yellow());
                report.add_error("TLS", &e.to_string()).await;
                Vec::new()
            }
        };
        for h in &ssl_hosts {
            report.add_hostname(h).await;
        }
        if !ssl_hosts.is_empty() {
            let _ = hosts::add_hosts(&cfg.ip, &ssl_hosts).await;
        }
    }

    // fill JSON report with port data
    for (port, proto, state, service, version) in parse_port_entries(&nmap_output) {
        report
            .add_port(port, &proto, &state, &service, &version)
            .await;
    }

    let resume = cli.resume;

    // kick off vuln scan in the background (skipped in fast mode)
    let vuln_handle: Option<JoinHandle<Result<Report>>> =
        if !scan_cfg.fast && !scan_cfg.should_skip("vuln") && !tcp_ports.is_empty() {
            phase_header("[2b/6]", "Nmap vuln scripts (background)...");
            let port_list: String = tcp_ports
                .iter()
                .map(|(p, _)| p.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let vuln_ip = cfg.ip.clone();
            let vuln_dir = raw_dir.clone();
            let vuln_cfg = scan_cfg.clone();
            Some(registry.spawn(async move {
                // write into an isolated report, merged back after join so this
                // section can't interleave with other concurrent writers
                let tr = Report::new();
                scans::tcp::vuln_scan(&vuln_ip, &port_list, &vuln_dir, &tr, resume, &vuln_cfg)
                    .await?;
                Ok(tr)
            }))
        } else {
            None
        };

    // fast mode: just do basic web headers, skip the rest
    if scan_cfg.fast {
        // just curl headers, no dir brute or vhost scanning
        if !scan_cfg.should_skip("web") {
            let t = Instant::now();
            phase_header("[4/6]", "Web (fast: headers only)...");
            // web::enumerate respects scan_cfg.fast internally; a failure is
            // best-effort here too — record it and still write the report below
            if let Err(e) = scans::web::enumerate(
                &cfg.ip,
                &cfg.hostname,
                &nmap_output,
                &raw_dir,
                &report,
                &scan_cfg,
            )
            .await
            {
                println!("{} Web enumeration failed: {e}", "[!]".yellow());
                report.add_error("WEB", &e.to_string()).await;
            }
            phase_done(t);
        }

        // no UDP, no deep service enum in fast mode
        println!(
            "\n{} Fast mode: skipping UDP scan + deep service enumeration",
            "[*]".yellow()
        );

        // still dump a summary + write the report
        print_summary(&cfg, &nmap_output, "", &os_guess, &[], &report).await;
        report.write_to_file(&cfg.report_path).await?;
        let json_path = if cli.json {
            let p = cfg.report_path.with_extension("json");
            report.write_json(&p).await?;
            Some(p)
        } else {
            None
        };

        let elapsed = start.elapsed();
        let mins = elapsed.as_secs() / 60;
        let secs = elapsed.as_secs() % 60;
        let json_disp = json_path.as_ref().map(|p| p.display().to_string());
        print_finish_banner(
            &cfg.name,
            &cfg.ip,
            mins,
            secs,
            &cfg.report_path.display().to_string(),
            json_disp.as_deref(),
            "fast scan",
        );

        return Ok(());
    }

    // --- Phase 3: UDP scan (runs in background) ---
    let udp_handle: Option<JoinHandle<Result<(String, Report)>>> = if !scan_cfg.should_skip("udp") {
        phase_header("[3/6]", "UDP scan (background)...");
        let udp_ip = cfg.ip.clone();
        let udp_dir = raw_dir.clone();
        let udp_cfg = scan_cfg.clone();
        Some(registry.spawn(async move {
            // isolated report, merged back after join
            let tr = Report::new();
            let out = scans::udp::scan(&udp_ip, &udp_dir, &tr, resume, &udp_cfg).await?;
            Ok((out, tr))
        }))
    } else {
        println!("\n{} UDP scan skipped", "[*]".dimmed());
        None
    };

    // Web probing and service enumeration are independent after TCP discovery.
    // Keep an isolated report while they overlap, then merge in phase order.
    let web_handle = if !scan_cfg.should_skip("web") {
        phase_header("[4/6]", "Web enumeration (parallel with services)...");
        let ip = cfg.ip.clone();
        let hostname = cfg.hostname.clone();
        let nmap = nmap_output.clone();
        let rd = raw_dir.clone();
        let sc = scan_cfg.clone();
        Some(registry.spawn(async move {
            let tr = Report::new();
            let result = scans::web::enumerate(&ip, &hostname, &nmap, &rd, &tr, &sc).await;
            (tr, result)
        }))
    } else {
        println!("\n{} Web enumeration skipped", "[*]".dimmed());
        None
    };

    // --- Phase 5: service-specific scans (all run in parallel) ---
    let t = Instant::now();
    phase_header("[5/6]", "Service enumeration (parallel)...");

    // spawn one task per service, collect results later
    // each task writes into its own Report (returned via the JoinHandle) so its
    // section can't interleave with another task's; merged back on collection
    let mut svc_handles: Vec<(&str, JoinHandle<Result<Report>>)> = Vec::new();

    // Services without a configurable port are triggered by nmap service name
    // *or* by their well-known fallback port.

    // SSH — port-aware
    for ssh_port in detect_service_ports(&tcp_services, &["ssh"], &[22], &tcp_ports) {
        if scan_cfg.should_skip("ssh") {
            break;
        }
        let r = Report::new();
        let ip = cfg.ip.clone();
        svc_handles.push((
            "SSH",
            registry.spawn(async move {
                scans::ssh::check(&ip, ssh_port, &r).await?;
                Ok(r)
            }),
        ));
    }

    // FTP — port-aware
    for ftp_port in detect_service_ports(&tcp_services, &["ftp"], &[21], &tcp_ports) {
        if scan_cfg.should_skip("ftp") {
            break;
        }
        let r = Report::new();
        let ip = cfg.ip.clone();
        let sc = scan_cfg.clone();
        svc_handles.push((
            "FTP",
            registry.spawn(async move {
                scans::ftp::check_anonymous(&ip, ftp_port, &sc, &r).await?;
                Ok(r)
            }),
        ));
    }

    // SMB
    if !detect_service_ports(&tcp_services, &["microsoft-ds", "smb"], &[445], &tcp_ports).is_empty()
        && !scan_cfg.should_skip("smb")
    {
        let r = Report::new();
        let ip = cfg.ip.clone();
        let sc = scan_cfg.clone();
        let rd = raw_dir.clone();
        svc_handles.push((
            "SMB",
            registry.spawn(async move {
                scans::smb::enumerate(&ip, &sc, &rd, &r).await?;
                Ok(r)
            }),
        ));
    }

    // RPC
    if !detect_service_ports(&tcp_services, &["msrpc", "rpc"], &[135], &tcp_ports).is_empty()
        && !scan_cfg.should_skip("rpc")
    {
        let r = Report::new();
        let ip = cfg.ip.clone();
        let sc = scan_cfg.clone();
        svc_handles.push((
            "RPC",
            registry.spawn(async move {
                scans::rpc::enumerate(&ip, &sc, &r).await?;
                Ok(r)
            }),
        ));
    }

    // NFS
    if !detect_service_ports(&tcp_services, &["nfs", "rpcbind"], &[2049, 111], &tcp_ports)
        .is_empty()
        && !scan_cfg.should_skip("nfs")
    {
        let r = Report::new();
        let ip = cfg.ip.clone();
        let sc = scan_cfg.clone();
        svc_handles.push((
            "NFS",
            registry.spawn(async move {
                scans::nfs::enumerate(&ip, &sc, &r).await?;
                Ok(r)
            }),
        ));
    }

    // MySQL — port-aware
    for mysql_port in detect_service_ports(&tcp_services, &["mysql"], &[3306], &tcp_ports) {
        if scan_cfg.should_skip("mysql") {
            break;
        }
        let r = Report::new();
        let ip = cfg.ip.clone();
        svc_handles.push((
            "MySQL",
            registry.spawn(async move {
                scans::mysql::check(&ip, mysql_port, &r).await?;
                Ok(r)
            }),
        ));
    }

    // PostgreSQL — port-aware
    for postgres_port in detect_service_ports(
        &tcp_services,
        &["postgresql", "postgres"],
        &[5432],
        &tcp_ports,
    ) {
        if scan_cfg.should_skip("postgres") {
            break;
        }
        let r = Report::new();
        let ip = cfg.ip.clone();
        svc_handles.push((
            "PostgreSQL",
            registry.spawn(async move {
                scans::postgres::check(&ip, postgres_port, &r).await?;
                Ok(r)
            }),
        ));
    }

    // Redis — port-aware
    for redis_port in detect_service_ports(&tcp_services, &["redis"], &[6379], &tcp_ports) {
        if scan_cfg.should_skip("redis") {
            break;
        }
        let r = Report::new();
        let ip = cfg.ip.clone();
        svc_handles.push((
            "Redis",
            registry.spawn(async move {
                scans::redis::check(&ip, redis_port, &r).await?;
                Ok(r)
            }),
        ));
    }

    // WinRM — first matching port only
    if let Some(winrm_port) = detect_service_ports(
        &tcp_services,
        &["winrm", "wsman"],
        &[5985, 5986],
        &tcp_ports,
    )
    .first()
    .copied()
        && !scan_cfg.should_skip("winrm")
    {
        let r = Report::new();
        let ip = cfg.ip.clone();
        let sc = scan_cfg.clone();
        svc_handles.push((
            "WinRM",
            registry.spawn(async move {
                scans::winrm::check(&ip, winrm_port, &sc, &r).await?;
                Ok(r)
            }),
        ));
    }

    // MSSQL — port-aware
    for mssql_port in
        detect_service_ports(&tcp_services, &["ms-sql-s", "mssql"], &[1433], &tcp_ports)
    {
        if scan_cfg.should_skip("mssql") {
            break;
        }
        let r = Report::new();
        let ip = cfg.ip.clone();
        let sc = scan_cfg.clone();
        svc_handles.push((
            "MSSQL",
            registry.spawn(async move {
                scans::mssql::check(&ip, mssql_port, &sc, &r).await?;
                Ok(r)
            }),
        ));
    }

    // SMTP — first matching port only
    if let Some(smtp_port) = detect_service_ports(
        &tcp_services,
        &["smtp", "smtps", "submission"],
        &[25, 465, 587],
        &tcp_ports,
    )
    .first()
    .copied()
        && !scan_cfg.should_skip("smtp")
    {
        let r = Report::new();
        let ip = cfg.ip.clone();
        let sc = scan_cfg.clone();
        svc_handles.push((
            "SMTP",
            registry.spawn(async move {
                scans::smtp::check(&ip, smtp_port, &sc, &r).await?;
                Ok(r)
            }),
        ));
    }

    // LDAP runs as its own task now (isolated report, merged after the join).
    // Kerberos only needs the domain string from it, so it can start as soon
    // as LDAP joins instead of waiting for the UDP scan (REVIEW.md finding 11).
    let ldap_handle: Option<LdapTask> = if let Some(ldap_port) =
        detect_service_ports(&tcp_services, &["ldap", "ldaps"], &[389, 636], &tcp_ports)
            .first()
            .copied()
        && !scan_cfg.should_skip("ldap")
    {
        println!("{} LDAP enumeration on port {ldap_port}...", "[*]".cyan());
        let r = Report::new();
        let ip = cfg.ip.clone();
        let sc = scan_cfg.clone();
        let rd = raw_dir.clone();
        Some(registry.spawn(async move {
            let domain = scans::ldap::enumerate(&ip, ldap_port, &sc, &rd, &r).await?;
            Ok((r, domain))
        }))
    } else {
        None
    };

    // All service tasks (including LDAP) have started before waiting for Web.
    let web_bg_tasks = if let Some(handle) = web_handle {
        match handle.await {
            Ok((tr, result)) => {
                report.merge_from(&tr).await;
                match result {
                    Ok(tasks) => {
                        for task in &tasks {
                            registry.track(&task.handle);
                        }
                        tasks
                    }
                    Err(e) => {
                        println!("{} Web enumeration failed: {e}", "[!]".yellow());
                        report.add_error("WEB", &e.to_string()).await;
                        Vec::new()
                    }
                }
            }
            Err(e) => {
                report
                    .add_error("WEB", &format!("probe task failed: {e}"))
                    .await;
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    // Collect LDAP after the web report, then start Kerberos while the other
    // service tasks and UDP continue in the background.
    let mut ldap_domain: Option<String> = None;
    if let Some(handle) = ldap_handle {
        match handle.await {
            Ok(Ok((tr, domain))) => {
                report.merge_from(&tr).await;
                println!("{} LDAP done", "[+]".green());
                ldap_domain = domain;
            }
            Ok(Err(e)) => {
                println!("{} LDAP enumeration failed: {e}", "[!]".yellow());
                report.add_error("LDAP", &e.to_string()).await;
            }
            Err(e) => {
                println!("{} LDAP task panicked: {e}", "[!]".yellow());
                report
                    .add_error("LDAP", &format!("task panicked: {e}"))
                    .await;
            }
        }
    }

    // kerberos uses the domain we found from LDAP (if any) — spawned now and
    // collected together with the UDP handle below
    let kerb_handle: Option<JoinHandle<Result<Report>>> = if !detect_service_ports(
        &tcp_services,
        &["kerberos-sec", "kerberos"],
        &[88],
        &tcp_ports,
    )
    .is_empty()
        && !scan_cfg.should_skip("kerberos")
    {
        println!("{} Kerberos enumeration...", "[*]".cyan());
        let r = Report::new();
        let ip = cfg.ip.clone();
        let hostname = cfg.hostname.clone();
        let domain = ldap_domain.clone();
        let sc = scan_cfg.clone();
        let rd = raw_dir.clone();
        Some(registry.spawn(async move {
            scans::kerberos::enumerate(&ip, &hostname, domain.as_deref(), &sc, &rd, &r).await?;
            Ok(r)
        }))
    } else {
        None
    };

    // collect results from parallel service scans, merging each task's report
    for (name, handle) in svc_handles {
        match handle.await {
            Ok(Ok(tr)) => {
                report.merge_from(&tr).await;
                println!("{} {name} done", "[+]".green());
            }
            Ok(Err(e)) => {
                println!("{} {name} failed: {e}", "[!]".yellow());
                report.add_error(name, &e.to_string()).await;
            }
            Err(e) => {
                println!("{} {name} panicked: {e}", "[!]".yellow());
                report.add_error(name, &format!("task panicked: {e}")).await;
            }
        }
    }
    phase_done(t);

    // wait for the UDP scan and the Kerberos task in parallel — Kerberos was
    // spawned right after the LDAP join and doesn't depend on UDP results
    // (REVIEW.md finding 11)
    if udp_handle.is_some() {
        println!("\n{} Waiting for UDP scan...", "[*]".yellow());
    }
    let (udp_join, kerb_join) = tokio::join!(
        async move {
            match udp_handle {
                Some(h) => Some(h.await),
                None => None,
            }
        },
        async move {
            match kerb_handle {
                Some(h) => Some(h.await),
                None => None,
            }
        },
    );

    let udp_output = match udp_join {
        Some(Ok(Ok((output, tr)))) => {
            report.merge_from(&tr).await;
            println!("{} UDP scan complete", "[+]".green());
            for (port, proto, state, service, version) in parse_port_entries(&output) {
                report
                    .add_port(port, &proto, &state, &service, &version)
                    .await;
            }
            output
        }
        Some(Ok(Err(e))) => {
            println!("{} UDP scan failed: {e}", "[!]".yellow());
            report.add_error("UDP", &e.to_string()).await;
            String::new()
        }
        Some(Err(e)) => {
            println!("{} UDP scan panicked: {e}", "[!]".yellow());
            report
                .add_error("UDP", &format!("task panicked: {e}"))
                .await;
            String::new()
        }
        None => String::new(),
    };

    // SNMP depends on UDP results, so it runs after
    let udp_ports = parse_open_ports(&udp_output);

    if has_port(&udp_ports, 161, "udp") && !scan_cfg.should_skip("snmp") {
        println!("\n{} SNMP detected — enumerating...", "[*]".cyan());
        if let Err(e) = scans::snmp::check(&cfg.ip, &scan_cfg, &report).await {
            println!("{} SNMP enumeration failed: {e}", "[!]".yellow());
            report.add_error("SNMP", &e.to_string()).await;
        }
    }

    // merge the Kerberos task's report — kept after SNMP so the report's
    // section order matches the previous serial version
    if let Some(join) = kerb_join {
        match join {
            Ok(Ok(tr)) => {
                report.merge_from(&tr).await;
                println!("{} KERBEROS done", "[+]".green());
            }
            Ok(Err(e)) => {
                println!("{} Kerberos enumeration failed: {e}", "[!]".yellow());
                report.add_error("KERBEROS", &e.to_string()).await;
            }
            Err(e) => {
                println!("{} Kerberos task panicked: {e}", "[!]".yellow());
                report
                    .add_error("KERBEROS", &format!("task panicked: {e}"))
                    .await;
            }
        }
    }

    // Keep the same current-run file list for parsing and the final summary.
    let mut web_files = Vec::new();
    // wait for feroxbuster / vhost scans to wrap up
    if !web_bg_tasks.is_empty() {
        println!(
            "\n{} Waiting for {} web background task(s)...",
            "[*]".yellow(),
            web_bg_tasks.len()
        );
        let mut web_failures = 0usize;
        let mut ferox_files = Vec::new();
        let mut vhost_files = Vec::new();
        for mut task in web_bg_tasks {
            match (&mut task.handle).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    web_failures += 1;
                    println!("{} Web background task failed: {e}", "[!]".yellow());
                    report.add_error("WEB", &e.to_string()).await;
                }
                Err(e) => {
                    web_failures += 1;
                    println!("{} Web background task panicked: {e}", "[!]".yellow());
                    report
                        .add_error("WEB", &format!("background task panicked: {e}"))
                        .await;
                }
            }
            match task.kind {
                scans::web::WebResultKind::Directory => ferox_files.push(task.output.clone()),
                scans::web::WebResultKind::Vhost => vhost_files.push(task.output.clone()),
            }
            web_files.push((task.kind, task.output.clone()));
        }
        if web_failures == 0 {
            println!("{} Web background tasks complete", "[+]".green());
        } else {
            println!(
                "{} Web background tasks complete with {web_failures} failure(s)",
                "[!]".yellow()
            );
        }

        process_ferox_results(&ferox_files, &report).await;
        process_vhost_results(&cfg, &vhost_files, &report).await;
    }

    // wait for vuln scan
    if let Some(handle) = vuln_handle {
        println!("\n{} Waiting for vuln scan...", "[*]".yellow());
        match handle.await {
            Ok(Ok(tr)) => {
                report.merge_from(&tr).await;
                println!("{} Vuln scan complete", "[+]".green());
            }
            Ok(Err(e)) => {
                println!("{} Vuln scan failed: {e}", "[!]".yellow());
                report.add_error("VULN", &e.to_string()).await;
            }
            Err(e) => {
                println!("{} Vuln scan panicked: {e}", "[!]".yellow());
                report
                    .add_error("VULN", &format!("task panicked: {e}"))
                    .await;
            }
        }
    }

    // all done, print the summary and write reports
    print_summary(
        &cfg,
        &nmap_output,
        &udp_output,
        &os_guess,
        &web_files,
        &report,
    )
    .await;
    report.write_to_file(&cfg.report_path).await?;

    let json_path = if cli.json {
        let p = cfg.report_path.with_extension("json");
        report.write_json(&p).await?;
        Some(p)
    } else {
        None
    };

    // print total runtime
    let elapsed = start.elapsed();
    let mins = elapsed.as_secs() / 60;
    let secs = elapsed.as_secs() % 60;
    let json_disp = json_path.as_ref().map(|p| p.display().to_string());
    print_finish_banner(
        &cfg.name,
        &cfg.ip,
        mins,
        secs,
        &cfg.report_path.display().to_string(),
        json_disp.as_deref(),
        "scan",
    );

    // watch mode: keep re-scanning and alert on port changes
    if cli.watch.is_some() && scan_cfg.should_skip("tcp") {
        println!(
            "{} Watch mode skipped because TCP scanning is disabled",
            "[!]".yellow()
        );
    } else if let Some(interval_mins) = cli.watch {
        let interval = std::cmp::max(interval_mins, 1);
        println!(
            "\n{} Watch mode: re-scanning every {} minute(s). Press Ctrl+C to stop.",
            "[*]".cyan().bold(),
            interval
        );
        let watch_nmap = scan_cfg.tool("nmap");
        // same floor as the initial full `-p-` scan (900s): on slow links a
        // 300s rescan times out structurally (REVIEW.md "Niedrig")
        let watch_timeout = runner::default_timeout().max(900);
        // The initial scan may have used a narrower scope (rustscan top ports) than
        // the full `-p-` rescan below, so the first watch scan establishes the
        // baseline instead of diffing against it — otherwise every port only the
        // full scan sees would be flagged as "NEW".
        let mut known_ports: Option<HashSet<(u16, String)>> = None;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(interval.saturating_mul(60))).await;
            println!(
                "\n{} Re-scanning at {}...",
                "[watch]".cyan(),
                chrono::Local::now().format("%H:%M:%S")
            );
            let rescan = match runner::run_cmd_timeout(
                &watch_nmap,
                &["-Pn", "-p-", "--min-rate", "5000", "-T4", &cfg.ip],
                watch_timeout,
            )
            .await
            {
                Ok(output) => output,
                Err(e) => {
                    println!(
                        "{} Re-scan failed; keeping previous baseline: {e}",
                        "[watch]".yellow()
                    );
                    report.add_error("WATCH", &e.to_string()).await;
                    persist_watch_report(&report, &cfg.report_path, json_path.as_deref()).await;
                    continue;
                }
            };

            let new_ports = parse_open_ports(&rescan);

            match known_ports.as_ref() {
                None => {
                    println!(
                        "{} Baseline established: {} open port(s)",
                        "[watch]".cyan(),
                        new_ports.len()
                    );
                }
                Some(prev) => {
                    let appeared: Vec<_> = new_ports.difference(prev).collect();
                    let disappeared: Vec<_> = prev.difference(&new_ports).collect();
                    let fmt_ports = |ports: &[&(u16, String)]| {
                        ports
                            .iter()
                            .map(|(p, proto)| format!("{p}/{proto}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    };

                    if !appeared.is_empty() {
                        println!(
                            "{} NEW PORTS: {}",
                            "[!!]".red().bold(),
                            fmt_ports(&appeared).red()
                        );
                    }
                    if !disappeared.is_empty() {
                        println!(
                            "{} CLOSED PORTS: {}",
                            "[--]".yellow(),
                            fmt_ports(&disappeared).yellow()
                        );
                    }
                    if appeared.is_empty() && disappeared.is_empty() {
                        println!("{} No port changes detected", "[ok]".green());
                    } else {
                        // record the change in the report too, then rewrite it —
                        // the watch loop never reaches the final report write
                        // itself (REVIEW.md "Niedrig")
                        let stamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                        for (label, ports) in
                            [("NEW PORTS", &appeared), ("CLOSED PORTS", &disappeared)]
                        {
                            if ports.is_empty() {
                                continue;
                            }
                            let line = format!("[{stamp}] {label}: {}", fmt_ports(ports));
                            report.add(&format!("[watch] {line}")).await;
                            report.add_service_finding("watch", &line).await;
                        }
                        persist_watch_report(&report, &cfg.report_path, json_path.as_deref()).await;
                    }
                }
            }
            known_ports = Some(new_ports);
        }
    }

    Ok(())
}

// Feroxbuster result lines start with an HTTP status code, e.g. "200      GET".
// pub(crate): scans/web.rs uses the same pattern to decide whether a killed
// feroxbuster left usable partial results behind.
pub(crate) static RE_FEROX_RESULT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\d{3}\s+\w+").unwrap());

/// Color a feroxbuster hit by its HTTP status class: 2xx green, 3xx cyan,
/// 4xx yellow, 5xx red — the line starts with the status code.
fn colorize_ferox_line(line: &str) -> String {
    match line.chars().next() {
        Some('2') => line.green().to_string(),
        Some('3') => line.cyan().to_string(),
        Some('4') => line.yellow().to_string(),
        Some('5') => line.red().to_string(),
        _ => line.to_string(),
    }
}

/// Clean up feroxbuster output: strip config noise, keep actual findings.
/// Only paths produced by this run are passed in, including partial results.
async fn process_ferox_results(paths: &[PathBuf], report: &Report) {
    let mut found_any = false;

    for path in paths {
        let content = match tokio::fs::read_to_string(&path).await {
            Ok(content) => content,
            Err(e) => {
                report
                    .add_error("DIR BRUTE", &format!("{}: {e}", path.display()))
                    .await;
                continue;
            }
        };
        let results: Vec<&str> = content
            .lines()
            .filter(|l| RE_FEROX_RESULT.is_match(l))
            .collect();
        if results.is_empty() {
            // Keep the raw feroxbuster output even when nothing parsed out —
            // deleting it would throw away scan evidence.
            continue;
        }
        if !found_any {
            report.section("DIR BRUTE").await;
            found_any = true;
        }
        println!(
            "{} {} ({} results)",
            "[+]".green(),
            path.display().to_string().yellow(),
            results.len()
        );
        // show the hits right away, color-coded by status class — capped so a
        // big wordlist can't flood the terminal; the report has everything
        const MAX_PRINTED: usize = 25;
        for line in results.iter().take(MAX_PRINTED) {
            println!("    {}", colorize_ferox_line(line));
        }
        if results.len() > MAX_PRINTED {
            println!(
                "    … and {} more in the report",
                results.len() - MAX_PRINTED
            );
        }
        report.add(&format!("  -> {}", path.display())).await;
        for line in &results {
            report.add(line).await;
            report
                .add_service_finding("web", &format!("dir: {line}"))
                .await;
        }
    }
}

// gobuster vhost output uses lines like "Found: shop.example.htb (Status: 200)".
static RE_GOBUSTER_FOUND: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Found:\s*(\S+)").unwrap());

fn normalize_vhost_candidate(candidate: &str, base_domain: &str) -> Option<String> {
    let mut host = candidate.trim().trim_end_matches('.').to_lowercase();
    for prefix in ["http://", "https://"] {
        if let Some(stripped) = host.strip_prefix(prefix) {
            host = stripped.to_string();
            break;
        }
    }
    host = host.split('/').next().unwrap_or("").to_string();
    if let Some((name, port)) = host.rsplit_once(':')
        && port.parse::<u16>().is_ok()
    {
        host = name.to_string();
    }
    if !host.contains('.') {
        host = format!("{host}.{base_domain}");
    }
    hosts::is_valid_hostname(&host).then_some(host)
}

/// Parse vhost scan results (ffuf CSV or gobuster format) and add to /etc/hosts.
/// Only paths produced by this run are passed in, including partial results.
async fn process_vhost_results(cfg: &BoxConfig, paths: &[PathBuf], report: &Report) {
    let mut found_any = false;

    for path in paths {
        let content = match tokio::fs::read_to_string(&path).await {
            Ok(content) => content,
            Err(e) => {
                report
                    .add_error("VHOSTS", &format!("{}: {e}", path.display()))
                    .await;
                continue;
            }
        };
        let first_line = content.lines().next().unwrap_or("");

        let candidates: Vec<String> = if first_line.contains("FUZZ") {
            // ffuf CSV: first column is the FUZZ input word
            content
                .lines()
                .skip(1)
                .filter_map(|l| l.split(',').next())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        } else {
            // gobuster emits an already-qualified hostname
            content
                .lines()
                .filter_map(|l| RE_GOBUSTER_FOUND.captures(l))
                .map(|c| c[1].to_string())
                .collect()
        };

        let mut fqdns = Vec::new();
        for candidate in &candidates {
            if let Some(fqdn) = normalize_vhost_candidate(candidate, &cfg.hostname)
                && !fqdns.contains(&fqdn)
            {
                fqdns.push(fqdn);
            }
        }

        if fqdns.is_empty() {
            println!("{} No new vhosts found", "[!]".yellow());
            // Keep the raw scan output rather than deleting it on an empty parse.
            continue;
        }

        if !found_any {
            report.section("VHOSTS").await;
            found_any = true;
        }

        println!("{} Discovered vhosts:", "[+]".green());
        for fqdn in &fqdns {
            println!("    {}", fqdn.cyan());
            report.add_hostname(fqdn).await;
        }
        if let Err(e) = hosts::add_hosts(&cfg.ip, &fqdns).await {
            report.add_error("VHOSTS", &e.to_string()).await;
        }

        report.add(&format!("  -> {}", path.display())).await;
        for fqdn in &fqdns {
            report.add(fqdn).await;
        }
    }
}

/// Print the final scan summary with ports, hosts, and next steps.
async fn print_summary(
    cfg: &BoxConfig,
    nmap_output: &str,
    udp_output: &str,
    os_guess: &str,
    web_files: &[(scans::web::WebResultKind, PathBuf)],
    report: &Report,
) {
    println!();
    print_report_banner(&cfg.name, &cfg.ip);

    println!("\n  {}", "[ OS ]".magenta().bold());
    println!("  {}", os_guess.cyan());

    println!("\n  {}", "[ TCP ]".magenta().bold());
    print_port_lines(nmap_output, &RE_TCP_LINE);

    if udp_output.lines().any(|l| RE_UDP_LINE.is_match(l)) {
        println!("\n  {}", "[ UDP ]".magenta().bold());
        print_port_lines(udp_output, &RE_UDP_LINE);
    }

    println!("\n  {}", "[ HOSTS ]".magenta().bold());
    let hosts_content = tokio::fs::read_to_string("/etc/hosts")
        .await
        .unwrap_or_default();
    if let Ok(ip_re) = Regex::new(&format!("^{}\\s+", regex::escape(&cfg.ip)))
        && let Some(line) = hosts_content.lines().find(|l| ip_re.is_match(l))
    {
        println!("  {}", line.cyan());
        report.section("HOSTS").await;
        report.add(line).await;
    }

    println!("\n  {}", "[ FILES ]".magenta().bold());
    println!(
        "  {} {}",
        "Report".dimmed(),
        cfg.report_path.display().to_string().yellow()
    );
    let nmap_tcp = cfg.output_dir.join("raw").join("nmap-tcp.txt");
    if nmap_tcp.exists() {
        println!(
            "  {} {}",
            "Nmap TCP".dimmed(),
            nmap_tcp.display().to_string().yellow()
        );
    }
    let nmap_udp = cfg.output_dir.join("raw").join("nmap-udp.txt");
    if nmap_udp.exists() {
        println!(
            "  {} {}",
            "Nmap UDP".dimmed(),
            nmap_udp.display().to_string().yellow()
        );
    }
    for (kind, path) in web_files {
        if path.exists() {
            let label = match kind {
                scans::web::WebResultKind::Directory => "Ferox",
                scans::web::WebResultKind::Vhost => "Vhosts",
            };
            println!(
                "  {} {}",
                label.dimmed(),
                path.display().to_string().yellow()
            );
        }
    }

    // suggest next steps based on which ports are open
    let mut next_steps: Vec<String> = Vec::new();
    let all_ports = extract_open_ports(nmap_output, udp_output);
    let http_ports = scans::web::detect_http_ports(nmap_output);
    let local_winrm = parse_port_entries(nmap_output)
        .iter()
        .any(|(port, _, _, _, version)| {
            *port == 47001 && scans::web::is_winrm_http_listener(*port, version)
        });
    for port in &all_ports {
        let step = match *port {
            21 => Some("FTP(21): check anonymous login, upload/download files"),
            22 => Some("SSH(22): try default/found creds, check version for CVEs"),
            25 => Some("SMTP(25): smtp-user-enum, check for open relay"),
            53 => Some("DNS(53): dig axfr, subdomain brute with dnsenum/gobuster dns"),
            80 => Some("HTTP(80): check source, robots.txt, tech stack, dir brute deeper"),
            88 => Some("Kerberos(88): kerbrute userenum, AS-REP roasting (GetNPUsers.py)"),
            110 => Some("POP3(110): try default creds, enumerate emails"),
            111 => Some("RPC(111): rpcinfo -p, showmount -e"),
            135 => Some("MSRPC(135): rpcclient -U '' -N, impacket-rpcdump"),
            139 => Some("NetBIOS(139): nbtscan, enum4linux-ng"),
            389 | 636 => Some("LDAP(389/636): ldapsearch, windapsearch, enum users/groups"),
            443 => Some("HTTPS(443): check cert CN/SAN for hostnames, dir brute, source review"),
            445 => Some("SMB(445): smbmap, crackmapexec --shares, enum4linux-ng"),
            464 => Some("Kpasswd(464): password change service — try kpasswd attacks"),
            593 => Some("HTTP-RPC(593): rpcclient, impacket tools"),
            1433 => Some("MSSQL(1433): impacket-mssqlclient, default sa creds, xp_cmdshell"),
            1521 => Some("Oracle(1521): odat, tnscmd10g, default creds"),
            2049 => Some("NFS(2049): showmount -e, mount shares"),
            3306 => Some("MySQL(3306): mysql -h -u root, default creds, UDF exploit"),
            3389 => Some("RDP(3389): xfreerdp, check for BlueKeep (CVE-2019-0708)"),
            5432 => Some("PostgreSQL(5432): psql, check for command exec via COPY/lo_export"),
            5985 | 5986 => Some("WinRM(5985/5986): evil-winrm, try found creds"),
            6379 => Some("Redis(6379): redis-cli INFO, check unauth, write webshell/ssh-key"),
            8080 => Some("HTTP(8080): check for admin panels, APIs, alternative web app"),
            8443 => Some("HTTPS(8443): check cert, admin panels, API endpoints"),
            8000 | 8888 | 9090 => Some("Web-Alt: check for admin panels, APIs, dev servers"),
            27017 => Some("MongoDB(27017): mongosh --host, check no-auth"),
            47001 if local_winrm => {
                Some("WinRM(47001): local management listener; use 5985/5986 for remote access")
            }
            _ => None,
        };
        // HTTP ports on non-standard ports (e.g. fingerprint-detected 6274)
        // aren't in the table above — give them the generic web hint too
        let step = step.map(str::to_string).or_else(|| {
            http_ports
                .iter()
                .find(|(p, _)| p == port)
                .map(|(_, scheme)| {
                    format!(
                        "{}({port}): check source, robots.txt, tech stack, dir brute deeper",
                        scheme.to_uppercase()
                    )
                })
        });
        if let Some(text) = step
            && !next_steps.contains(&text)
        {
            next_steps.push(text);
        }
    }

    if !next_steps.is_empty() {
        println!("\n  {}", "[ NEXT STEPS ]".magenta().bold());
        report.section("NEXT STEPS").await;
        for step in &next_steps {
            println!("  {} {step}", "->".yellow());
            report.add(&format!("  -> {step}")).await;
            report.add_next_step(step).await;
        }
    }

    let scan_errors = report.errors().await;
    if !scan_errors.is_empty() {
        println!("\n  {}", "[ SCAN ERRORS ]".red().bold());
        report.section("SCAN ERRORS").await;
        for error in &scan_errors {
            println!("  {} {error}", "!!".red());
            report.add(&format!("  !! {error}")).await;
        }
    }
}

/// Merge TCP + UDP port numbers into a sorted, deduplicated list.
fn extract_open_ports(tcp_output: &str, udp_output: &str) -> Vec<u16> {
    let mut ports: Vec<u16> = Vec::new();
    for output in [tcp_output, udp_output] {
        for cap in RE_OPEN_PORT.captures_iter(output) {
            if let Ok(p) = cap[1].parse::<u16>()
                && !ports.contains(&p)
            {
                ports.push(p);
            }
        }
    }
    ports.sort();
    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    const NMAP_TCP_OUTPUT: &str = "\
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.10.10.1
PORT     STATE SERVICE      VERSION
22/tcp   open  ssh          OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
80/tcp   open  http         Apache httpd 2.4.52
443/tcp  open  ssl/http     nginx 1.18.0
3306/tcp open  mysql        MySQL 8.0.32
8080/tcp open  http-proxy
Nmap done: 1 IP address (1 host up)";

    const NMAP_UDP_OUTPUT: &str = "\
PORT    STATE SERVICE
53/udp  open  domain
161/udp open  snmp
631/udp open  ipp";

    // udp commonly reports "open|filtered" — these must not be dropped
    const NMAP_UDP_FILTERED: &str = "\
PORT     STATE         SERVICE
161/udp  open|filtered snmp
500/udp  open          isakmp";

    #[test]
    fn test_parse_open_ports_tcp() {
        let ports = parse_open_ports(NMAP_TCP_OUTPUT);
        assert!(ports.contains(&(22, "tcp".to_string())));
        assert!(ports.contains(&(80, "tcp".to_string())));
        assert!(ports.contains(&(443, "tcp".to_string())));
        assert!(ports.contains(&(3306, "tcp".to_string())));
        assert!(ports.contains(&(8080, "tcp".to_string())));
        assert_eq!(ports.len(), 5);
    }

    #[test]
    fn test_parse_open_ports_udp() {
        let ports = parse_open_ports(NMAP_UDP_OUTPUT);
        assert!(ports.contains(&(53, "udp".to_string())));
        assert!(ports.contains(&(161, "udp".to_string())));
        assert!(ports.contains(&(631, "udp".to_string())));
        assert_eq!(ports.len(), 3);
    }

    #[test]
    fn test_parse_open_ports_empty() {
        let ports = parse_open_ports("no ports here");
        assert!(ports.is_empty());
    }

    #[test]
    fn test_parse_open_ports_udp_open_filtered() {
        let ports = parse_open_ports(NMAP_UDP_FILTERED);
        assert!(ports.contains(&(161, "udp".to_string())));
        assert!(ports.contains(&(500, "udp".to_string())));
    }

    #[test]
    fn test_parse_port_entries_udp_open_filtered() {
        // both "open|filtered" and plain "open" udp ports must reach the report,
        // with their real state (not flattened to "open")
        let entries = parse_port_entries(NMAP_UDP_FILTERED);
        assert!(
            entries
                .iter()
                .any(|e| e.0 == 161 && e.1 == "udp" && e.2 == "open|filtered" && e.3 == "snmp")
        );
        assert!(
            entries
                .iter()
                .any(|e| e.0 == 500 && e.1 == "udp" && e.2 == "open" && e.3 == "isakmp")
        );
    }

    #[test]
    fn test_has_port() {
        let ports = parse_open_ports(NMAP_TCP_OUTPUT);
        assert!(has_port(&ports, 22, "tcp"));
        assert!(has_port(&ports, 443, "tcp"));
        assert!(!has_port(&ports, 22, "udp"));
        assert!(!has_port(&ports, 9999, "tcp"));
    }

    #[test]
    fn test_port_service_map() {
        let services = port_service_map(NMAP_TCP_OUTPUT, "tcp");
        assert_eq!(services.get(&22), Some(&"ssh".to_string()));
        assert_eq!(services.get(&80), Some(&"http".to_string()));
        assert_eq!(services.get(&53), None); // UDP
    }

    #[test]
    fn test_detect_service_ports_finds_non_standard_ssh() {
        let output = "2222/tcp open ssh OpenSSH 8.9";
        let ports = parse_open_ports(output);
        let services = port_service_map(output, "tcp");
        let detected = detect_service_ports(&services, &["ssh"], &[22], &ports);
        assert_eq!(detected, vec![2222]);
    }

    #[test]
    fn test_detect_service_ports_prefers_service_name_over_fallback() {
        // 2222 is ssh, 22 is also open but not identified as ssh
        let output = "22/tcp open tcpwrapped\n2222/tcp open ssh OpenSSH 8.9";
        let ports = parse_open_ports(output);
        let services = port_service_map(output, "tcp");
        let detected = detect_service_ports(&services, &["ssh"], &[22], &ports);
        assert_eq!(detected, vec![2222, 22]);
    }

    #[test]
    fn test_detect_service_ports_redis_on_non_standard_port() {
        let output = "6380/tcp open redis Redis 7.0";
        let ports = parse_open_ports(output);
        let services = port_service_map(output, "tcp");
        let detected = detect_service_ports(&services, &["redis"], &[6379], &ports);
        assert_eq!(detected, vec![6380]);
    }

    #[test]
    fn test_detect_service_ports_winrm_first_only() {
        let output = "5985/tcp open winrm Microsoft HTTPAPI";
        let ports = parse_open_ports(output);
        let services = port_service_map(output, "tcp");
        let detected = detect_service_ports(&services, &["winrm"], &[5985, 5986], &ports);
        assert_eq!(detected, vec![5985]);
    }

    #[test]
    fn test_detect_service_ports_empty_when_no_match() {
        let output = "80/tcp open http";
        let ports = parse_open_ports(output);
        let services = port_service_map(output, "tcp");
        let detected = detect_service_ports(&services, &["ssh"], &[22], &ports);
        assert!(detected.is_empty());
    }

    #[test]
    fn test_parse_port_entries() {
        let entries = parse_port_entries(NMAP_TCP_OUTPUT);
        assert_eq!(entries.len(), 5);

        let ssh = &entries[0];
        assert_eq!(ssh.0, 22);
        assert_eq!(ssh.1, "tcp");
        assert_eq!(ssh.2, "open");
        assert_eq!(ssh.3, "ssh");
        assert!(ssh.4.contains("OpenSSH"));

        let mysql = entries.iter().find(|e| e.0 == 3306).unwrap();
        assert_eq!(mysql.3, "mysql");
    }

    #[test]
    fn test_parse_port_entries_empty() {
        let entries = parse_port_entries("nothing to see");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_extract_open_ports_combined() {
        let ports = extract_open_ports(NMAP_TCP_OUTPUT, NMAP_UDP_OUTPUT);
        assert!(ports.contains(&22));
        assert!(ports.contains(&53));
        assert!(ports.contains(&161));
        assert!(ports.contains(&3306));
        // Should be sorted
        assert_eq!(ports, {
            let mut sorted = ports.clone();
            sorted.sort();
            sorted
        });
    }

    #[test]
    fn test_extract_open_ports_deduplication() {
        // Same port in both outputs should appear only once
        let tcp = "22/tcp open ssh";
        let udp = "";
        let ports = extract_open_ports(tcp, udp);
        assert_eq!(ports.iter().filter(|&&p| p == 22).count(), 1);
    }

    #[test]
    fn test_extract_open_ports_empty() {
        let ports = extract_open_ports("", "");
        assert!(ports.is_empty());
    }

    #[test]
    fn vhost_word_is_qualified_with_full_box_domain() {
        assert_eq!(
            normalize_vhost_candidate("admin", "lame.htb"),
            Some("admin.lame.htb".to_string())
        );
    }

    #[test]
    fn qualified_gobuster_vhost_is_not_duplicated() {
        assert_eq!(
            normalize_vhost_candidate("shop.lame.htb", "lame.htb"),
            Some("shop.lame.htb".to_string())
        );
        assert_eq!(
            normalize_vhost_candidate("https://shop.lame.htb:443/path", "lame.htb"),
            Some("shop.lame.htb".to_string())
        );
    }

    #[test]
    fn invalid_vhost_candidate_is_rejected() {
        assert_eq!(normalize_vhost_candidate("../bad", "lame.htb"), None);
    }

    // ── banner width helpers ──────────────────────────────────────
    // The box is colored (byte-heavy with ANSI), so the only thing worth
    // asserting is the *visible* width — that's what keeps the right border
    // aligned and the corners from drifting.

    const BANNER_TOTAL: usize = BANNER_INNER + 4;

    #[test]
    fn test_visible_width_strips_ansi() {
        let s = format!("{} {}", "Lame".bright_yellow().bold(), "10.10.10.3".red());
        assert_eq!(visible_width(&s), "Lame 10.10.10.3".chars().count());
    }

    #[test]
    fn test_rows_and_borders_share_one_width() {
        let title = format!(
            "{} {} {}",
            "pwnbox".green(),
            "·".dimmed(),
            "HackTheBox".magenta()
        );
        assert_eq!(visible_width(&banner_top(&title)), BANNER_TOTAL);
        assert_eq!(visible_width(&banner_bottom()), BANNER_TOTAL);
        assert_eq!(visible_width(&banner_row("")), BANNER_TOTAL);
        assert_eq!(visible_width(&banner_row(&"x".repeat(20))), BANNER_TOTAL);
        assert_eq!(
            visible_width(&banner_kv("started", &"2026-06-14".cyan().to_string())),
            BANNER_TOTAL
        );
    }

    #[test]
    fn test_banner_top_never_panics_on_long_title() {
        // A title far wider than the box must not underflow/panic — it just
        // yields zero dashes (this is the bug the previous rewrite had).
        let long = "x".repeat(BANNER_INNER + 50);
        let top = banner_top(&long);
        assert!(visible_width(&top) >= BANNER_INNER);
    }

    #[test]
    fn test_truncate_tail() {
        assert_eq!(truncate_tail("short", 10), "short");
        assert_eq!(truncate_tail("abcdefgh", 4), "…fgh"); // keeps the tail
        assert_eq!(truncate_tail("abc", 0), "");
        // never exceeds the budget, even for a very long path
        assert!(truncate_tail(&"p".repeat(100), 20).chars().count() <= 20);
    }

    #[test]
    fn test_visible_width_counts_wide_glyphs() {
        assert_eq!(visible_width("⚡"), 2); // emoji occupies 2 terminal cells
        assert_eq!(visible_width("↻"), 1);
        assert_eq!(visible_width("→"), 1);
        // a mode row carrying an emoji must still pad out to the full width
        let row = banner_kv("mode", &format!("{} fast", "⚡".yellow()));
        assert_eq!(visible_width(&row), BANNER_TOTAL);
    }

    // ── finalize_report (REVIEW.md finding 1) ─────────────────────
    // The error path must flush the same artefacts as a successful run — a core
    // phase failure (e.g. tcp::scan) records its error in the report and the
    // report still lands on disk.

    #[tokio::test]
    async fn finalize_report_writes_txt_and_json_with_recorded_error() {
        let tmp = TmpDir::new("finalize_json");
        let report = Report::new();
        report.add("pwnbox  Testbox  →  10.10.10.3").await;
        report.add_error("TCP", "simulated tcp scan failure").await;

        let report_path = tmp.path().join("report.txt");
        finalize_report(&report, &report_path, true).await;

        let txt = std::fs::read_to_string(&report_path).unwrap();
        assert!(txt.contains("pwnbox  Testbox"));

        let json_path = report_path.with_extension("json");
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(json_path).unwrap()).unwrap();
        assert_eq!(json["errors"][0], "TCP: simulated tcp scan failure");
    }

    #[tokio::test]
    async fn finalize_report_without_json_writes_only_txt() {
        let tmp = TmpDir::new("finalize_plain");
        let report = Report::new();
        report.add("partial findings").await;

        let report_path = tmp.path().join("report.txt");
        finalize_report(&report, &report_path, false).await;

        assert!(report_path.exists());
        assert!(!report_path.with_extension("json").exists());
    }

    #[tokio::test]
    async fn directory_results_exclude_old_runs_and_keep_current_partial_output() {
        let tmp = TmpDir::new("current_web_results");
        let old = tmp.path().join("ferox-80.txt");
        let current_dir = tmp.path().join("web-current");
        std::fs::create_dir(&current_dir).unwrap();
        let current = current_dir.join("ferox-80.txt");
        std::fs::write(&old, "200 GET 1l 1w 1c http://test.htb/stale\n").unwrap();
        std::fs::write(&current, "200 GET 1l 1w 1c http://test.htb/current\n").unwrap();
        let report = Report::new();
        process_ferox_results(&[current], &report).await;
        let lines = report.lines().await.join("\n");
        assert!(lines.contains("http://test.htb/current"));
        assert!(!lines.contains("stale"));
        assert!(old.exists());
        let json = report.json_mut().await;
        assert_eq!(json.services["web"].len(), 1);
        assert!(json.services["web"][0].contains("/current"));
    }

    // ── TaskRegistry (REVIEW.md finding 3) ────────────────────────

    #[tokio::test]
    async fn task_registry_abort_all_cancels_background_tasks() {
        let registry = TaskRegistry::default();
        let handle = registry.spawn(async {
            tokio::time::sleep(Duration::from_secs(300)).await;
        });
        registry.abort_all();
        assert!(handle.await.unwrap_err().is_cancelled());
    }

    /// Throwaway directory under the system temp dir, removed on drop.
    struct TmpDir(std::path::PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("pwnbox_main_test_{}_{tag}", std::process::id()));
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
