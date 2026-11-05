//! Detection corpus: public attack classes must be reported, realistic benign servers must not
//! produce findings of severity `medium` or higher.
//!
//! Cases live in `tests/corpus/{malicious,benign}/*.json`, indexed by `tests/corpus/manifest.json`.
//! Each case file holds one `ServerSurface` or an array of them (multi-server cases).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use mcp_warden::model::{Finding, ServerSurface, Severity};
use mcp_warden::rules::check_surfaces;
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Label {
    Malicious,
    Benign,
}

#[derive(Debug, Deserialize)]
struct Case {
    file: String,
    label: Label,
    expect: Vec<String>,
    source: String,
    note: String,
}

#[derive(Default)]
struct RuleStats {
    expected: usize,
    detected: usize,
    false_positives: usize,
}

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus")
}

fn load_manifest() -> Vec<Case> {
    let path = corpus_dir().join("manifest.json");
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn load_surfaces(case: &Case) -> Vec<ServerSurface> {
    let path = corpus_dir().join(&case.file);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let value: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
    let surfaces = if value.is_array() {
        serde_json::from_value(value)
    } else {
        serde_json::from_value(value).map(|s| vec![s])
    };
    surfaces.unwrap_or_else(|e| panic!("{} is not a ServerSurface: {e}", path.display()))
}

fn percent(part: usize, total: usize) -> String {
    let permille = part * 1000 / total.max(1);
    format!("{}.{}%", permille / 10, permille % 10)
}

fn is_rule_id(id: &str) -> bool {
    id.len() == 5 && id.starts_with("MW") && id[2..].bytes().all(|b| b.is_ascii_digit())
}

#[test]
fn manifest_is_consistent() {
    let cases = load_manifest();
    let mut problems = Vec::new();
    let mut listed = BTreeSet::new();
    for case in &cases {
        if !listed.insert(case.file.clone()) {
            problems.push(format!("{}: listed twice", case.file));
        }
        let dir = if case.label == Label::Malicious {
            "malicious/"
        } else {
            "benign/"
        };
        if !case.file.starts_with(dir) {
            problems.push(format!("{}: label does not match directory", case.file));
        }
        if case.label == Label::Malicious && case.expect.is_empty() {
            problems.push(format!("{}: malicious case expects no rule", case.file));
        }
        if case.label == Label::Benign && !case.expect.is_empty() {
            problems.push(format!("{}: benign case lists expected rules", case.file));
        }
        for id in case.expect.iter().filter(|id| !is_rule_id(id)) {
            problems.push(format!("{}: bad rule id {id:?}", case.file));
        }
        if !case.source.starts_with("http") || case.note.trim().is_empty() {
            problems.push(format!("{}: missing source url or note", case.file));
        }
        if load_surfaces(case).is_empty() {
            problems.push(format!("{}: no server surface", case.file));
        }
    }
    for dir in ["malicious", "benign"] {
        let entries = fs::read_dir(corpus_dir().join(dir)).expect("corpus directory");
        for entry in entries {
            let name = entry.expect("directory entry").file_name();
            let rel = format!("{dir}/{}", name.to_string_lossy());
            if !listed.contains(&rel) {
                problems.push(format!("{rel}: not in manifest.json"));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn corpus_detection() {
    let cases = load_manifest();
    let mut stats: BTreeMap<String, RuleStats> = BTreeMap::new();
    let mut misses = Vec::new();
    let (mut malicious_total, mut malicious_ok) = (0, 0);
    let (mut benign_total, mut benign_clean) = (0, 0);

    for case in &cases {
        let findings: Vec<Finding> = check_surfaces(&load_surfaces(case));
        match case.label {
            Label::Malicious => {
                malicious_total += 1;
                let reported: BTreeSet<&str> = findings.iter().map(|f| f.rule_id).collect();
                let mut missing = Vec::new();
                for id in &case.expect {
                    let entry = stats.entry(id.clone()).or_default();
                    entry.expected += 1;
                    if reported.contains(id.as_str()) {
                        entry.detected += 1;
                    } else {
                        missing.push(id.as_str());
                    }
                }
                if missing.is_empty() {
                    malicious_ok += 1;
                } else {
                    misses.push(format!(
                        "MISSED {}: expected {:?} but not reported: {:?} (reported: {:?})",
                        case.file, case.expect, missing, reported
                    ));
                }
            }
            Label::Benign => {
                benign_total += 1;
                let loud: Vec<&Finding> = findings
                    .iter()
                    .filter(|f| f.severity >= Severity::Medium)
                    .collect();
                if loud.is_empty() {
                    benign_clean += 1;
                }
                for f in loud {
                    stats
                        .entry(f.rule_id.to_owned())
                        .or_default()
                        .false_positives += 1;
                    misses.push(format!(
                        "FALSE POSITIVE {}: {} [{}] at {:?}: {}",
                        case.file, f.rule_id, f.severity, f.location.pointer, f.evidence
                    ));
                }
            }
        }
    }

    eprintln!(
        "\n{:<7}{:>10}{:>10}{:>18}",
        "rule", "expected", "detected", "false positives"
    );
    for (id, s) in &stats {
        eprintln!(
            "{id:<7}{:>10}{:>10}{:>18}",
            s.expected, s.detected, s.false_positives
        );
    }
    eprintln!(
        "malicious cases fully detected: {malicious_ok}/{malicious_total} ({})",
        percent(malicious_ok, malicious_total)
    );
    eprintln!(
        "benign cases with a finding >= medium: {}/{benign_total} (clean: {benign_clean})\n",
        benign_total - benign_clean
    );

    assert!(
        misses.is_empty(),
        "{} corpus expectation(s) failed:\n{}",
        misses.len(),
        misses.join("\n")
    );
}
