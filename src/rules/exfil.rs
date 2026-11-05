//! Data-exfiltration and sensitive-data lures (MW020-MW029).

use crate::model::{Finding, RuleInfo, ServerSurface};

pub const RULES: &[RuleInfo] = &[];

pub fn check(_surfaces: &[ServerSurface]) -> Vec<Finding> {
    Vec::new()
}
