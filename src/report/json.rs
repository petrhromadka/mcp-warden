//! Machine-readable JSON report.

use serde::Serialize;

use super::{count, path_string, rule_info, sorted};
use crate::model::{ScanResult, Severity};
use crate::rules::all_rules;

#[derive(Serialize)]
struct Report<'a> {
    tool: &'static str,
    version: &'a str,
    summary: Summary,
    findings: Vec<JsonFinding<'a>>,
    errors: &'a [String],
}

#[derive(Serialize)]
struct Summary {
    configs: usize,
    servers: usize,
    surfaces: usize,
    findings: usize,
    by_severity: BySeverity,
}

#[derive(Serialize)]
struct BySeverity {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

#[derive(Serialize)]
struct JsonFinding<'a> {
    rule_id: &'a str,
    rule_name: &'a str,
    severity: Severity,
    server: &'a str,
    message: &'a str,
    evidence: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pointer: Option<&'a str>,
}

pub(super) fn render(result: &ScanResult) -> String {
    let rules = all_rules();
    let report = Report {
        tool: "mcp-warden",
        version: result.tool_version,
        summary: Summary {
            configs: result.configs_scanned.len(),
            servers: result.servers_scanned,
            surfaces: result.surfaces_scanned,
            findings: result.findings.len(),
            by_severity: BySeverity {
                critical: count(result, Severity::Critical),
                high: count(result, Severity::High),
                medium: count(result, Severity::Medium),
                low: count(result, Severity::Low),
                info: count(result, Severity::Info),
            },
        },
        findings: sorted(result)
            .into_iter()
            .map(|f| JsonFinding {
                rule_id: f.rule_id,
                rule_name: rule_info(&rules, f.rule_id).map_or("unknown", |r| r.name),
                severity: f.severity,
                server: &f.server,
                message: &f.message,
                evidence: &f.evidence,
                file: f.location.file.as_deref().map(path_string),
                pointer: f.location.pointer.as_deref(),
            })
            .collect(),
        errors: &result.errors,
    };
    let mut out =
        serde_json::to_string_pretty(&report).expect("report contains only serializable data");
    out.push('\n');
    out
}
