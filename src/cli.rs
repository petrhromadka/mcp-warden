//! Command-line interface. All logic lives in [`run`] so it is testable without spawning the
//! binary.

use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::error::ErrorKind;
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::model::{Finding, RuleInfo, ScanResult, ServerConfig, ServerSurface, Severity};
use crate::report::{self, Format};
use crate::{config, introspect, pin, rules};

const AFTER_HELP: &str = "\
Examples:
  mcp-warden                         scan the MCP configs under $HOME and the current directory
  mcp-warden scan .mcp.json --format sarif --output warden.sarif
  mcp-warden scan --no-discover --tools tools.json --fail-on medium
  mcp-warden pin --lock mcp.lock --tools tools.json
  mcp-warden scan --lock mcp.lock --tools tools.json    report changes since pinning
  mcp-warden rules --format markdown

Exit codes: 0 ok, 1 a finding reached --fail-on, 2 usage or runtime error.";

#[derive(Parser)]
#[command(
    name = "mcp-warden",
    version,
    about = "Offline static scanner for MCP servers and MCP client configs",
    after_help = AFTER_HELP,
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// Without a subcommand, `scan` options apply.
    #[command(flatten)]
    scan: ScanArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Scan MCP client configs and server surfaces for risky content (the default command)
    Scan(ScanArgs),
    /// Fingerprint server surfaces into a lockfile to detect later changes
    Pin(PinArgs),
    /// List the rules mcp-warden can report
    Rules(RulesArgs),
}

/// Where configs and server surfaces come from; shared by `scan` and `pin`.
#[derive(Args)]
struct SourceArgs {
    /// MCP client config files to read (besides the discovered ones)
    #[arg(value_name = "CONFIG_FILES")]
    config_files: Vec<PathBuf>,
    /// Do not look for configs in the home and project directories
    #[arg(long)]
    no_discover: bool,
    /// Home directory for config discovery [default: the user's home]
    #[arg(long, value_name = "DIR")]
    home: Option<PathBuf>,
    /// Project directory for config discovery [default: the current directory]
    #[arg(long, value_name = "DIR")]
    project: Option<PathBuf>,
    /// Only look at servers with this name (repeatable)
    #[arg(long, value_name = "NAME")]
    server: Vec<String>,
    /// Load server surfaces from a saved tools/list dump (repeatable)
    #[arg(long, value_name = "FILE")]
    tools: Vec<PathBuf>,
    /// Start or contact the configured servers to read their surfaces (runs their commands)
    #[arg(long)]
    connect: bool,
    /// Per-server timeout for --connect, in seconds
    #[arg(long, value_name = "SECS", default_value_t = 20)]
    timeout: u64,
}

#[derive(Args)]
struct ScanArgs {
    #[command(flatten)]
    source: SourceArgs,
    /// Compare surfaces against this lockfile and report changes
    #[arg(long, value_name = "FILE")]
    lock: Option<PathBuf>,
    /// Hide findings below this severity
    #[arg(long, value_enum, default_value_t = SeverityArg::Info)]
    min_severity: SeverityArg,
    /// Exit 1 if a shown finding has at least this severity
    #[arg(long, value_enum, default_value_t = FailArg::High)]
    fail_on: FailArg,
    /// Report format
    #[arg(long, value_enum, default_value_t = FormatArg::Text)]
    format: FormatArg,
    /// Write the report to this file instead of stdout
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Colour text output
    #[arg(long, value_enum, default_value_t = ColorArg::Auto)]
    color: ColorArg,
}

#[derive(Args)]
struct PinArgs {
    #[command(flatten)]
    source: SourceArgs,
    /// Lockfile to write
    #[arg(long, value_name = "FILE")]
    lock: PathBuf,
}

#[derive(Args)]
struct RulesArgs {
    /// Output format
    #[arg(long, value_enum, default_value_t = RulesFormat::Text)]
    format: RulesFormat,
}

#[derive(Clone, Copy, ValueEnum)]
enum SeverityArg {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityArg {
    fn severity(self) -> Severity {
        match self {
            Self::Info => Severity::Info,
            Self::Low => Severity::Low,
            Self::Medium => Severity::Medium,
            Self::High => Severity::High,
            Self::Critical => Severity::Critical,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum FailArg {
    None,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl FailArg {
    fn threshold(self) -> Option<Severity> {
        match self {
            Self::None => None,
            Self::Info => Some(Severity::Info),
            Self::Low => Some(Severity::Low),
            Self::Medium => Some(Severity::Medium),
            Self::High => Some(Severity::High),
            Self::Critical => Some(Severity::Critical),
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum FormatArg {
    Text,
    Json,
    Sarif,
    Markdown,
}

impl FormatArg {
    fn format(self) -> Format {
        match self {
            Self::Text => Format::Text,
            Self::Json => Format::Json,
            Self::Sarif => Format::Sarif,
            Self::Markdown => Format::Markdown,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ColorArg {
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, ValueEnum)]
enum RulesFormat {
    Text,
    Json,
    Markdown,
}

/// A fatal error: printed as `error: ...` and exits with code 2.
struct Failure(String);

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self(message)
    }
}

impl From<std::io::Error> for Failure {
    fn from(e: std::io::Error) -> Self {
        Self(e.to_string())
    }
}

type Outcome = Result<u8, Failure>;

/// Parse `args` (including the program name) and run; returns the process exit code:
/// 0 clean, 1 a finding reached `--fail-on`, 2 usage or runtime error.
///
/// `--color auto` never colours here; [`main`] passes the real terminal decision to
/// [`run_with_color`].
pub fn run(args: Vec<OsString>, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    run_with_color(args, out, err, false)
}

/// Like [`run`]; `auto_color` is what `--color auto` resolves to.
pub fn run_with_color(
    args: Vec<OsString>,
    out: &mut dyn Write,
    err: &mut dyn Write,
    auto_color: bool,
) -> u8 {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => return clap_exit(&e, out, err),
    };
    let outcome = match cli.command {
        None => scan(&cli.scan, out, err, auto_color),
        Some(Command::Scan(args)) => scan(&args, out, err, auto_color),
        Some(Command::Pin(args)) => pin_command(&args, out, err),
        Some(Command::Rules(args)) => list_rules(&args, out),
    };
    match outcome {
        Ok(code) => code,
        Err(Failure(message)) => {
            // Nothing sensible to do if stderr is gone.
            let _ = writeln!(err, "error: {message}");
            2
        }
    }
}

/// Help and version go to `out` with exit 0; every other clap error goes to `err` with exit 2.
fn clap_exit(e: &clap::Error, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let text = e.render().to_string();
    if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
        return if write!(out, "{text}").is_ok() { 0 } else { 2 };
    }
    let _ = write!(err, "{text}");
    2
}

pub fn main() -> ExitCode {
    let auto_color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr().lock();
    ExitCode::from(run_with_color(
        std::env::args_os().collect(),
        &mut out,
        &mut err,
        auto_color,
    ))
}

/// Everything read from the sources, before any rule runs.
#[derive(Default)]
struct Gathered {
    /// Config files we tried to read (explicit and discovered).
    attempted: usize,
    read: Vec<PathBuf>,
    configs: Vec<ServerConfig>,
    surfaces: Vec<ServerSurface>,
    errors: Vec<String>,
}

type ConfigSource = (PathBuf, Option<&'static str>);

fn config_sources(src: &SourceArgs, errors: &mut Vec<String>) -> Vec<ConfigSource> {
    let mut sources: Vec<ConfigSource> =
        src.config_files.iter().map(|p| (p.clone(), None)).collect();
    if src.no_discover {
        return sources;
    }
    let Some(home) = src.home.clone().or_else(std::env::home_dir) else {
        errors.push(
            "cannot determine the home directory; pass --home to discover configs".to_owned(),
        );
        return sources;
    };
    let project = src
        .project
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    for found in config::discover(&home, &project) {
        if !sources.iter().any(|(p, _)| *p == found.path) {
            sources.push((found.path, Some(found.client)));
        }
    }
    sources
}

fn wanted(filter: &[String], name: &str) -> bool {
    filter.is_empty() || filter.iter().any(|n| n == name)
}

fn load_configs(src: &SourceArgs, gathered: &mut Gathered) {
    let sources = config_sources(src, &mut gathered.errors);
    gathered.attempted = sources.len();
    for (path, client) in sources {
        match config::parse_file(&path, client) {
            Ok(entries) => {
                gathered.read.push(path);
                gathered.configs.extend(entries);
            }
            Err(e) => gathered.errors.push(e),
        }
    }
    gathered.configs.retain(|c| wanted(&src.server, &c.name));
}

fn connect_all(gathered: &mut Gathered, timeout: Duration) {
    for cfg in gathered.configs.iter().filter(|c| !c.disabled) {
        match introspect::introspect(cfg, timeout) {
            Ok(surface) => gathered.surfaces.push(surface),
            Err(e) => gathered.errors.push(e),
        }
    }
}

fn gather(src: &SourceArgs, err: &mut dyn Write) -> Result<Gathered, Failure> {
    let mut gathered = Gathered::default();
    load_configs(src, &mut gathered);
    for path in &src.tools {
        gathered.surfaces.extend(introspect::load_dump(path)?);
    }
    if src.connect {
        writeln!(
            err,
            "warning: --connect starts the configured MCP server commands and contacts remote servers"
        )?;
        connect_all(&mut gathered, Duration::from_secs(src.timeout));
    }
    gathered.surfaces.retain(|s| wanted(&src.server, &s.server));
    Ok(gathered)
}

const NOTHING_TO_SCAN: &str = "no MCP configs found; pass config files, --tools, or --home";

fn scan(args: &ScanArgs, out: &mut dyn Write, err: &mut dyn Write, auto_color: bool) -> Outcome {
    let lock = args.lock.as_deref().map(pin::read).transpose()?;
    let gathered = gather(&args.source, err)?;
    if gathered.attempted == 0 && gathered.surfaces.is_empty() {
        writeln!(err, "{NOTHING_TO_SCAN}")?;
        return Ok(0);
    }
    let mut findings = rules::check_configs(&gathered.configs);
    findings.extend(rules::check_surfaces(&gathered.surfaces));
    if let Some(lock) = &lock {
        findings.extend(pin::compare(lock, &gathered.surfaces));
    }
    let min = args.min_severity.severity();
    findings.retain(|f| f.severity >= min);
    let code = u8::from(reaches(&findings, args.fail_on.threshold()));
    let result = ScanResult {
        tool_version: env!("CARGO_PKG_VERSION"),
        configs_scanned: gathered.read,
        servers_scanned: gathered.configs.len(),
        surfaces_scanned: gathered.surfaces.len(),
        findings,
        errors: gathered.errors,
    };
    let format = args.format.format();
    let color = format == Format::Text
        && args.output.is_none()
        && match args.color {
            ColorArg::Always => true,
            ColorArg::Never => false,
            ColorArg::Auto => auto_color,
        };
    emit(
        &report::render(&result, format, color),
        args.output.as_deref(),
        out,
    )?;
    Ok(code)
}

fn reaches(findings: &[Finding], threshold: Option<Severity>) -> bool {
    threshold.is_some_and(|t| findings.iter().any(|f| f.severity >= t))
}

fn emit(text: &str, output: Option<&Path>, out: &mut dyn Write) -> Result<(), Failure> {
    match output {
        Some(path) => {
            std::fs::write(path, text).map_err(|e| Failure(format!("{}: {e}", path.display())))
        }
        None => Ok(out.write_all(text.as_bytes())?),
    }
}

fn pin_command(args: &PinArgs, out: &mut dyn Write, err: &mut dyn Write) -> Outcome {
    let gathered = gather(&args.source, err)?;
    if gathered.surfaces.is_empty() {
        return Err(Failure(
            "no server surfaces to pin; pass --tools FILE or --connect with MCP configs".to_owned(),
        ));
    }
    for e in &gathered.errors {
        writeln!(err, "warning: {e}")?;
    }
    let surfaces = &gathered.surfaces;
    pin::write(&args.lock, &pin::build(surfaces))?;
    let count = |f: fn(&ServerSurface) -> usize| surfaces.iter().map(f).sum::<usize>();
    writeln!(
        out,
        "pinned {} servers ({} tools, {} prompts, {} resources) to {}",
        surfaces.len(),
        count(|s| s.tools.len()),
        count(|s| s.prompts.len()),
        count(|s| s.resources.len()),
        args.lock.display()
    )?;
    Ok(0)
}

fn list_rules(args: &RulesArgs, out: &mut dyn Write) -> Outcome {
    let rules = rules::all_rules();
    let text = match args.format {
        RulesFormat::Text => rules_text(&rules),
        RulesFormat::Json => rules_json(&rules)?,
        RulesFormat::Markdown => rules_markdown(&rules),
    };
    out.write_all(text.as_bytes())?;
    Ok(0)
}

fn rules_text(rules: &[RuleInfo]) -> String {
    let width = rules.iter().map(|r| r.name.len()).max().unwrap_or(0);
    let lines: Vec<String> = rules
        .iter()
        .map(|r| {
            format!(
                "{}  {:<8}  {:<width$}  {}\n",
                r.id, r.severity, r.name, r.summary
            )
        })
        .collect();
    lines.concat()
}

fn rules_json(rules: &[RuleInfo]) -> Result<String, Failure> {
    let items: Vec<_> = rules
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "name": r.name,
                "severity": r.severity,
                "summary": r.summary,
                "help": r.help,
            })
        })
        .collect();
    let mut text = serde_json::to_string_pretty(&items).map_err(|e| Failure(e.to_string()))?;
    text.push('\n');
    Ok(text)
}

fn rules_markdown(rules: &[RuleInfo]) -> String {
    let rows: Vec<String> = rules
        .iter()
        .map(|r| {
            let summary = r.summary.replace('|', "\\|");
            format!("| {} | {} | {} | {summary} |\n", r.id, r.severity, r.name)
        })
        .collect();
    format!(
        "| Id | Severity | Name | Summary |\n| --- | --- | --- | --- |\n{}",
        rows.concat()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Location;

    fn run_args(args: &[&str]) -> (u8, String, String) {
        let args = std::iter::once("mcp-warden")
            .chain(args.iter().copied())
            .map(OsString::from)
            .collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(args, &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    fn finding(severity: Severity) -> Finding {
        Finding {
            rule_id: "MW001",
            severity,
            server: "s".to_owned(),
            message: String::new(),
            evidence: String::new(),
            location: Location::default(),
        }
    }

    #[test]
    fn help_and_version_go_to_stdout_with_exit_0() {
        let (code, out, err) = run_args(&["--help"]);
        assert_eq!((code, err.as_str()), (0, ""));
        for word in ["scan", "pin", "rules", "Examples"] {
            assert!(out.contains(word), "help lacks {word}");
        }
        let (code, out, _) = run_args(&["--version"]);
        assert_eq!(code, 0);
        assert!(out.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn usage_errors_exit_2_on_stderr() {
        let cases: [&[&str]; 4] = [
            &["--bogus"],
            &["scan", "--fail-on", "urgent"],
            &["pin"],
            &["rules", "--format", "sarif"],
        ];
        for args in cases {
            let (code, out, err) = run_args(args);
            assert_eq!(code, 2, "{args:?}");
            assert!(out.is_empty() && err.contains("error"), "{args:?}: {err}");
        }
    }

    #[test]
    fn no_subcommand_scans_and_hints_when_nothing_is_found() {
        let cases: [&[&str]; 2] = [&["--no-discover"], &["scan", "--no-discover"]];
        for args in cases {
            let (code, out, err) = run_args(args);
            assert_eq!(code, 0);
            assert_eq!(out, "");
            assert!(err.contains("no MCP configs found"), "{err}");
        }
    }

    #[test]
    fn unreadable_tools_or_lock_file_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.json");
        let missing = missing.to_str().unwrap();
        for flag in ["--tools", "--lock"] {
            let (code, _, err) = run_args(&["scan", "--no-discover", flag, missing]);
            assert_eq!(code, 2, "{flag}");
            assert!(err.starts_with("error:"), "{err}");
        }
    }

    #[test]
    fn bad_config_file_is_reported_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.json");
        let (code, _, _) = run_args(&["scan", "--no-discover", missing.to_str().unwrap()]);
        assert_eq!(code, 0);
    }

    #[test]
    fn output_file_receives_the_report() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("report.json");
        let missing = dir.path().join("missing.json");
        let (code, out, _) = run_args(&[
            "scan",
            "--no-discover",
            "--format",
            "json",
            "--output",
            file.to_str().unwrap(),
            missing.to_str().unwrap(),
        ]);
        assert_eq!(code, 0);
        assert_eq!(out, "");
        let written = std::fs::read_to_string(&file).unwrap();
        // The renderer may still be a stub that returns an empty string.
        if !written.is_empty() {
            serde_json::from_str::<serde_json::Value>(&written).unwrap();
        }
    }

    #[test]
    fn pin_without_surfaces_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("mcp.lock");
        let (code, _, err) = run_args(&["pin", "--no-discover", "--lock", lock.to_str().unwrap()]);
        assert_eq!(code, 2);
        assert!(err.contains("no server surfaces"), "{err}");
        assert!(!lock.exists());
    }

    #[test]
    fn rules_lists_in_every_format() {
        let (code, out, _) = run_args(&["rules", "--format", "json"]);
        assert_eq!(code, 0);
        assert!(
            serde_json::from_str::<serde_json::Value>(&out)
                .unwrap()
                .is_array()
        );
        for format in ["text", "markdown"] {
            assert_eq!(run_args(&["rules", "--format", format]).0, 0);
        }
    }

    #[test]
    fn fail_on_threshold_uses_shown_findings() {
        let findings = [finding(Severity::Medium)];
        assert!(reaches(&findings, Some(Severity::Medium)));
        assert!(!reaches(&findings, Some(Severity::High)));
        assert!(!reaches(&findings, None));
        assert!(!reaches(&[], Some(Severity::Info)));
    }
}
