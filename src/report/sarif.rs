//! SARIF 2.1.0 report for GitHub code scanning.

use std::fmt::Write as _;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{MAX_MESSAGE, MAX_NAME, MAX_PATH, path_string, sorted};
use crate::model::{Finding, RuleInfo, ScanResult, Severity};
use crate::rules::all_rules;
use crate::text::snippet;

const INFORMATION_URI: &str = "https://github.com/petrhromadka/mcp-warden";

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn security_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.5",
        Severity::Low => "3.0",
        Severity::Info => "1.0",
    }
}

fn rule_json(rule: &RuleInfo) -> Value {
    json!({
        "id": rule.id,
        "name": rule.name,
        "shortDescription": {"text": rule.summary},
        "fullDescription": {"text": rule.summary},
        "help": {"text": rule.help},
        "defaultConfiguration": {"level": level(rule.severity)},
        "properties": {
            "security-severity": security_severity(rule.severity),
            "tags": ["security", "mcp"],
        },
    })
}

/// Percent-encode everything but RFC 3986 unreserved characters (and `/` and `:` when
/// `keep_path_chars`), so untrusted names stay a valid URI reference.
fn encode_uri(s: &str, keep_path_chars: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'.' | b'_' | b'~')
            || (keep_path_chars && matches!(b, b'/' | b':'))
        {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn fingerprint(f: &Finding) -> String {
    let pointer = f.location.pointer.as_deref().unwrap_or("");
    let digest = Sha256::digest(format!("{}|{}|{pointer}", f.rule_id, f.server).as_bytes());
    digest.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn message_text(f: &Finding) -> String {
    let mut text = format!(
        "{} (server: {}",
        snippet(&f.message, MAX_MESSAGE),
        snippet(&f.server, MAX_NAME)
    );
    if !f.evidence.is_empty() {
        let _ = write!(text, "; evidence: {}", snippet(&f.evidence, MAX_MESSAGE));
    }
    text.push(')');
    text
}

fn location_json(f: &Finding) -> Value {
    let (uri, with_region) = match &f.location.file {
        Some(file) => {
            let path = path_string(file).replace('\\', "/");
            (encode_uri(&snippet(&path, MAX_PATH), true), true)
        }
        None => (
            format!(
                "mcp-warden/{}",
                encode_uri(&snippet(&f.server, MAX_NAME), false)
            ),
            false,
        ),
    };
    let mut physical = json!({"artifactLocation": {"uri": uri}});
    if with_region {
        physical["region"] = json!({"startLine": 1});
    }
    let mut loc = json!({"physicalLocation": physical});
    if let Some(pointer) = &f.location.pointer {
        loc["logicalLocations"] = json!([{"name": snippet(pointer, MAX_PATH), "kind": "member"}]);
    }
    loc
}

pub(super) fn render(result: &ScanResult) -> String {
    let rules = all_rules();
    let results: Vec<Value> = sorted(result)
        .into_iter()
        .map(|f| {
            let mut r = json!({
                "ruleId": f.rule_id,
                "level": level(f.severity),
                "message": {"text": message_text(f)},
                "locations": [location_json(f)],
                "partialFingerprints": {"mcpWarden/v1": fingerprint(f)},
            });
            if let Some(index) = rules.iter().position(|rule| rule.id == f.rule_id) {
                r["ruleIndex"] = json!(index);
            }
            r
        })
        .collect();
    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "mcp-warden",
                    "version": result.tool_version,
                    "informationUri": INFORMATION_URI,
                    "rules": rules.iter().map(rule_json).collect::<Vec<_>>(),
                },
            },
            "results": results,
        }],
    });
    let mut out =
        serde_json::to_string_pretty(&sarif).expect("report contains only serializable data");
    out.push('\n');
    out
}
