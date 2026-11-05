//! Markdown report, meant to be pasted into pull requests.

use std::fmt::Write as _;

use super::{
    MAX_MESSAGE, MAX_NAME, MAX_PATH, count, path_string, rule_info, severities_desc, sorted,
};
use crate::model::{Finding, ScanResult};
use crate::rules::all_rules;
use crate::text::snippet;

/// Break `scheme://` and `www.` so renderers do not turn untrusted text into clickable links.
fn break_autolinks(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if lower[i..].starts_with("://") {
            out.push_str("\\://");
            i += 3;
        } else if lower[i..].starts_with("www.") {
            out.push_str(&s[i..i + 3]);
            out.push_str("\\.");
            i += 4;
        } else if let Some(c) = s[i..].chars().next() {
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}

/// Sanitize `s` and neutralize Markdown/HTML syntax, links and `@mentions` for use in a table
/// cell.
fn escape(s: &str, max: usize) -> String {
    let mut out = String::new();
    for c in snippet(s, max).chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '@' => out.push_str("&#64;"),
            '|' => out.push_str("\\|"),
            '\\' | '`' | '[' | ']' | '*' | '_' | '~' | '#' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    break_autolinks(&out)
}

/// Sanitize `s` and wrap it in an inline code span whose fence is longer than any backtick run
/// inside; `|` is escaped for table cells.
fn code(s: &str, max: usize) -> String {
    let text = snippet(s, max);
    if text.is_empty() {
        return String::new();
    }
    let mut longest = 0;
    let mut run = 0;
    for c in text.chars() {
        run = if c == '`' { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    let fence = "`".repeat(longest + 1);
    let pad = if text.starts_with('`') || text.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{text}{pad}{fence}").replace('|', "\\|")
}

fn location(f: &Finding) -> String {
    let file = f
        .location
        .file
        .as_deref()
        .map(|p| path_string(p).replace('\\', "/"));
    let text = match (file, f.location.pointer.as_deref()) {
        (Some(file), Some(pointer)) => format!("{file}#{pointer}"),
        (Some(file), None) => file,
        (None, Some(pointer)) => format!("#{pointer}"),
        (None, None) => String::new(),
    };
    code(&text, MAX_PATH)
}

pub(super) fn render(result: &ScanResult) -> String {
    let rules = all_rules();
    let mut out = String::from("## mcp-warden report\n\n");
    let _ = writeln!(
        out,
        "mcp-warden {} - configs: {}, servers: {}, surfaces: {}, findings: {}\n",
        escape(result.tool_version, MAX_NAME),
        result.configs_scanned.len(),
        result.servers_scanned,
        result.surfaces_scanned,
        result.findings.len()
    );

    out.push_str("| Severity | Count |\n| --- | ---: |\n");
    for s in severities_desc() {
        let _ = writeln!(out, "| {s} | {} |", count(result, s));
    }
    out.push('\n');

    let findings = sorted(result);
    if findings.is_empty() {
        out.push_str("No findings.\n");
    } else {
        out.push_str("| Severity | Rule | Server | Location | Message | Evidence |\n");
        out.push_str("| --- | --- | --- | --- | --- | --- |\n");
        for f in findings {
            let rule = match rule_info(&rules, f.rule_id) {
                Some(info) => format!("{} {}", f.rule_id, info.name),
                None => f.rule_id.to_owned(),
            };
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} | {} |",
                f.severity,
                escape(&rule, MAX_NAME),
                escape(&f.server, MAX_NAME),
                location(f),
                escape(&f.message, MAX_MESSAGE),
                code(&f.evidence, MAX_MESSAGE),
            );
        }
    }

    if !result.errors.is_empty() {
        out.push_str("\n### Errors\n\n");
        for e in &result.errors {
            let _ = writeln!(out, "- {}", escape(e, MAX_MESSAGE));
        }
    }
    out
}
