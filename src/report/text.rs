//! Plain-text report for terminals.

use std::fmt::Write as _;

use super::{
    MAX_MESSAGE, MAX_NAME, MAX_PATH, count, path_string, rule_info, severities_desc, sorted,
};
use crate::model::{Finding, ScanResult, Severity};
use crate::rules::all_rules;
use crate::text::snippet;

const RESET: &str = "\u{1b}[0m";

fn ansi(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "\u{1b}[1;31m",
        Severity::High => "\u{1b}[31m",
        Severity::Medium => "\u{1b}[33m",
        Severity::Low => "\u{1b}[36m",
        Severity::Info => "\u{1b}[2m",
    }
}

pub(super) fn render(result: &ScanResult, color: bool) -> String {
    let rules = all_rules();
    let mut out = String::new();
    let _ = writeln!(out, "mcp-warden {}", result.tool_version);
    let by_severity: Vec<String> = severities_desc()
        .map(|s| format!("{s}={}", count(result, s)))
        .collect();
    let _ = writeln!(
        out,
        "Configs: {}  Servers: {}  Surfaces: {}  Findings: {} ({})",
        result.configs_scanned.len(),
        result.servers_scanned,
        result.surfaces_scanned,
        result.findings.len(),
        by_severity.join(", ")
    );
    out.push('\n');

    let findings = sorted(result);
    if findings.is_empty() {
        out.push_str("No findings.\n");
    }
    for f in findings {
        write_finding(
            &mut out,
            f,
            rule_info(&rules, f.rule_id).map(|r| r.name),
            color,
        );
    }

    if !result.errors.is_empty() {
        out.push_str("Errors:\n");
        for e in &result.errors {
            let _ = writeln!(out, "  - {}", snippet(e, MAX_MESSAGE));
        }
    }
    out
}

fn write_finding(out: &mut String, f: &Finding, rule_name: Option<&str>, color: bool) {
    let label = format!("[{}]", f.severity.as_str().to_uppercase());
    if color {
        let _ = write!(out, "{}{label}{RESET}", ansi(f.severity));
    } else {
        out.push_str(&label);
    }
    out.push(' ');
    out.push_str(f.rule_id);
    if let Some(name) = rule_name {
        let _ = write!(out, " {name}");
    }
    let _ = writeln!(out, "  {}", snippet(&f.server, MAX_NAME));
    let _ = writeln!(out, "    {}", snippet(&f.message, MAX_MESSAGE));

    let file = f
        .location
        .file
        .as_deref()
        .map(|p| snippet(&path_string(p), MAX_PATH));
    let pointer = f.location.pointer.as_deref().map(|p| snippet(p, MAX_PATH));
    match (file, pointer) {
        (Some(file), Some(pointer)) => {
            let _ = writeln!(out, "    at: {file} #{pointer}");
        }
        (Some(file), None) => {
            let _ = writeln!(out, "    at: {file}");
        }
        (None, Some(pointer)) => {
            let _ = writeln!(out, "    at: #{pointer}");
        }
        (None, None) => {}
    }
    if !f.evidence.is_empty() {
        let _ = writeln!(out, "    evidence: {}", snippet(&f.evidence, MAX_MESSAGE));
    }
    out.push('\n');
}
