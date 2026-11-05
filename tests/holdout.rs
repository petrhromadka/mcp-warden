//! Blind holdout set: cases written without access to the rules, used only to measure how the
//! rules generalise. A malicious case counts as detected when it gets a finding of severity
//! medium or higher; a benign case is a false positive when it gets one.

use std::fs;
use std::path::Path;

use mcp_warden::model::{ServerSurface, Severity};
use mcp_warden::rules::check_surfaces;
use serde_json::Value;

fn load(path: &Path) -> Vec<ServerSurface> {
    let value: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    match value {
        Value::Array(items) => items
            .into_iter()
            .map(|v| serde_json::from_value(v).unwrap())
            .collect(),
        v => vec![serde_json::from_value(v).unwrap()],
    }
}

#[test]
fn holdout_detection_rate() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/holdout");
    let manifest: Vec<Value> =
        serde_json::from_str(&fs::read_to_string(root.join("manifest.json")).unwrap()).unwrap();
    let (mut tp, mut mal, mut fp, mut ben) = (0, 0, 0, 0);
    for case in &manifest {
        let file = case["file"].as_str().unwrap();
        let path = [
            root.join(file),
            root.join("malicious").join(file),
            root.join("benign").join(file),
        ]
        .into_iter()
        .find(|p| p.is_file())
        .unwrap_or_else(|| panic!("missing {file}"));
        let findings = check_surfaces(&load(&path));
        let alert: Vec<_> = findings
            .iter()
            .filter(|f| f.severity >= Severity::Medium)
            .map(|f| f.rule_id)
            .collect();
        if case["label"] == "malicious" {
            mal += 1;
            if alert.is_empty() {
                eprintln!("MISSED {file}: {}", case["what"]);
            } else {
                tp += 1;
            }
        } else {
            ben += 1;
            if !alert.is_empty() {
                fp += 1;
                eprintln!("FALSE POSITIVE {file}: {alert:?}");
            }
        }
    }
    eprintln!("holdout: detected {tp}/{mal} malicious, {fp}/{ben} benign flagged");
    assert!(mal > 0 && ben > 0);
}
