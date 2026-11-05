//! Pin server surfaces to a lockfile and detect later changes ("rug pulls") (MW200-MW209).

use std::path::Path;

use crate::model::{Finding, RuleInfo, ServerSurface};

pub const RULES: &[RuleInfo] = &[];

/// Fingerprints of every tool, prompt and resource of every server, as stored on disk.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Lockfile {}

pub fn build(_surfaces: &[ServerSurface]) -> Lockfile {
    Lockfile::default()
}

pub fn read(path: &Path) -> Result<Lockfile, String> {
    Err(format!(
        "{}: lockfile reading not implemented",
        path.display()
    ))
}

pub fn write(_path: &Path, _lock: &Lockfile) -> Result<(), String> {
    Err("lockfile writing not implemented".to_owned())
}

/// Findings for every difference between `lock` and the current `surfaces`.
pub fn compare(_lock: &Lockfile, _surfaces: &[ServerSurface]) -> Vec<Finding> {
    Vec::new()
}
