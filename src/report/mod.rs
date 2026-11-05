//! Render a [`ScanResult`] as text, JSON, SARIF 2.1.0 or Markdown.

mod json;
mod markdown;
mod sarif;
mod text;

use std::cmp::Reverse;
use std::path::Path;

use crate::model::{Finding, RuleInfo, ScanResult, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
    Sarif,
    Markdown,
}

/// `color` only affects `Text` (ANSI colours for a terminal).
pub fn render(result: &ScanResult, format: Format, color: bool) -> String {
    match format {
        Format::Text => text::render(result, color),
        Format::Json => json::render(result),
        Format::Sarif => sarif::render(result),
        Format::Markdown => markdown::render(result),
    }
}

/// Longest sanitized form of each kind of untrusted string in text, Markdown and SARIF output.
const MAX_NAME: usize = 120;
const MAX_MESSAGE: usize = 400;
const MAX_PATH: usize = 400;

/// Findings ordered by severity (worst first), then rule id, server and pointer.
fn sorted(result: &ScanResult) -> Vec<&Finding> {
    let mut findings: Vec<&Finding> = result.findings.iter().collect();
    findings.sort_by(|a, b| {
        (
            Reverse(a.severity),
            a.rule_id,
            &a.server,
            &a.location.pointer,
        )
            .cmp(&(
                Reverse(b.severity),
                b.rule_id,
                &b.server,
                &b.location.pointer,
            ))
    });
    findings
}

fn count(result: &ScanResult, severity: Severity) -> usize {
    result
        .findings
        .iter()
        .filter(|f| f.severity == severity)
        .count()
}

/// Severities from worst to least bad.
fn severities_desc() -> impl Iterator<Item = Severity> {
    Severity::ALL.into_iter().rev()
}

fn rule_info<'a>(rules: &'a [RuleInfo], id: &str) -> Option<&'a RuleInfo> {
    rules.iter().find(|r| r.id == id)
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Location;
    use serde_json::Value;
    use std::path::PathBuf;

    fn finding(
        rule_id: &'static str,
        severity: Severity,
        server: &str,
        file: Option<&str>,
        pointer: Option<&str>,
        message: &str,
        evidence: &str,
    ) -> Finding {
        Finding {
            rule_id,
            severity,
            server: server.to_owned(),
            message: message.to_owned(),
            evidence: evidence.to_owned(),
            location: Location {
                file: file.map(PathBuf::from),
                pointer: pointer.map(str::to_owned),
            },
        }
    }

    fn sample() -> ScanResult {
        ScanResult {
            tool_version: "1.2.3",
            configs_scanned: vec![PathBuf::from("a.json")],
            servers_scanned: 2,
            surfaces_scanned: 1,
            findings: vec![
                finding(
                    "MW200",
                    Severity::Low,
                    "zed",
                    Some("cfg\\mcp.json"),
                    Some("mcpServers/zed"),
                    "low one",
                    "e1",
                ),
                finding(
                    "MW001",
                    Severity::High,
                    "evil\u{1b}[31m|`srv`",
                    None,
                    Some("tools/add/description"),
                    "bad | <b>x</b>\nsecond `tick` @octocat",
                    "ignore ``all`` | \u{1b}[2J <img>",
                ),
                finding(
                    "MW100",
                    Severity::Critical,
                    "alpha",
                    Some("dir/mcp.json"),
                    None,
                    "crit",
                    "",
                ),
            ],
            errors: vec!["could not read x\u{7}.json".to_owned()],
        }
    }

    #[test]
    fn text_orders_sanitizes_and_colours_only_on_request() {
        let plain = render(&sample(), Format::Text, false);
        assert!(
            !plain.contains('\u{1b}') && !plain.contains('\u{7}'),
            "{plain}"
        );
        assert!(plain.starts_with("mcp-warden 1.2.3\n"), "{plain}");
        assert!(
            plain.contains(
                "Configs: 1  Servers: 2  Surfaces: 1  Findings: 3 \
                 (critical=1, high=1, medium=0, low=1, info=0)"
            ),
            "{plain}"
        );
        let crit = plain.find("[CRITICAL] MW100").expect("critical");
        let high = plain.find("[HIGH] MW001").expect("high");
        let low = plain.find("[LOW] MW200").expect("low");
        assert!(crit < high && high < low, "{plain}");
        assert!(plain.contains("at: dir/mcp.json\n"), "{plain}");
        assert!(plain.contains("at: #tools/add/description"), "{plain}");
        assert!(plain.contains("\\u{1b}"), "{plain}");
        assert!(
            plain.contains("Errors:\n  - could not read x\\u{7}.json"),
            "{plain}"
        );
        let coloured = render(&sample(), Format::Text, true);
        assert!(coloured.contains("\u{1b}[1;31m[CRITICAL]"), "{coloured}");
    }

    #[test]
    fn empty_result_renders_in_every_format() {
        let empty = ScanResult {
            tool_version: "0.0.1",
            ..ScanResult::default()
        };
        assert!(render(&empty, Format::Text, false).contains("No findings."));
        assert!(render(&empty, Format::Markdown, false).contains("No findings."));
        let json: Value = serde_json::from_str(&render(&empty, Format::Json, false)).unwrap();
        assert_eq!(json["findings"], serde_json::json!([]));
        assert_eq!(json["summary"]["findings"], 0);
        let sarif: Value = serde_json::from_str(&render(&empty, Format::Sarif, false)).unwrap();
        assert_eq!(sarif["runs"][0]["results"], serde_json::json!([]));
    }

    #[test]
    fn json_has_summary_and_optional_location_fields() {
        let json: Value = serde_json::from_str(&render(&sample(), Format::Json, false)).unwrap();
        assert_eq!(json["tool"], "mcp-warden");
        assert_eq!(json["version"], "1.2.3");
        assert_eq!(json["summary"]["by_severity"]["critical"], 1);
        let f = json["findings"].as_array().unwrap();
        assert_eq!(f[0]["rule_id"], "MW100");
        assert_eq!(f[0]["severity"], "critical");
        assert!(f[0].get("pointer").is_none());
        assert!(f[1].get("file").is_none());
        assert_eq!(f[1]["pointer"], "tools/add/description");
        assert_eq!(json["errors"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn sarif_locations_levels_and_fingerprints() {
        let sarif: Value = serde_json::from_str(&render(&sample(), Format::Sarif, false)).unwrap();
        assert_eq!(sarif["version"], "2.1.0");
        let run = &sarif["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "mcp-warden");
        let results = run["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);
        // Unknown rule ids still render; known ones must carry a matching ruleIndex.
        for r in results {
            if let Some(i) = r.get("ruleIndex") {
                let i = usize::try_from(i.as_u64().unwrap()).unwrap();
                assert_eq!(run["tool"]["driver"]["rules"][i]["id"], r["ruleId"]);
            }
        }
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "error");
        assert_eq!(results[2]["level"], "note");
        let loc0 = &results[0]["locations"][0];
        assert_eq!(
            loc0["physicalLocation"]["artifactLocation"]["uri"],
            "dir/mcp.json"
        );
        assert_eq!(loc0["physicalLocation"]["region"]["startLine"], 1);
        let loc1 = &results[1]["locations"][0];
        assert_eq!(
            loc1["physicalLocation"]["artifactLocation"]["uri"],
            "mcp-warden/evil%5Cu%7B1b%7D%5B31m%7C%60srv%60"
        );
        assert!(loc1["physicalLocation"].get("region").is_none());
        assert_eq!(loc1["logicalLocations"][0]["name"], "tools/add/description");
        assert_eq!(loc1["logicalLocations"][0]["kind"], "member");
        let fp = results[0]["partialFingerprints"]["mcpWarden/v1"]
            .as_str()
            .unwrap();
        assert_eq!(fp.len(), 64);
        assert!(fp.bytes().all(|b| b.is_ascii_hexdigit()));
        let loc2 = &results[2]["locations"][0];
        assert_eq!(
            loc2["physicalLocation"]["artifactLocation"]["uri"],
            "cfg/mcp.json"
        );
    }

    #[test]
    fn markdown_escapes_hostile_strings() {
        let md = render(&sample(), Format::Markdown, false);
        assert!(md.starts_with("## mcp-warden report\n"), "{md}");
        assert!(md.contains("| Severity | Rule | Server | Location | Message | Evidence |"));
        assert!(!md.contains('\u{1b}') && !md.contains("<b>"), "{md}");
        assert!(!md.contains("@octocat"), "{md}");
        // Every finding row has as many unescaped pipes as the header.
        let pipes = |l: &str| l.replace("\\|", "").matches('|').count();
        let want = pipes("| Severity | Rule | Server | Location | Message | Evidence |");
        let rows: Vec<_> = md.lines().filter(|l| l.contains("MW")).collect();
        assert_eq!(rows.len(), 3, "{md}");
        for r in rows {
            assert_eq!(pipes(r), want, "{r}");
        }
        // The evidence holds a double-backtick run, so its code span needs a longer fence.
        assert!(
            md.contains(r"```ignore ``all`` \| \u{1b}[2J <img>```"),
            "{md}"
        );
        assert!(md.contains("- could not read x"), "{md}");
    }
}
