//! Hidden or obfuscated content (MW010-MW019).

use crate::model::{Finding, RuleInfo, ServerSurface};

pub const RULES: &[RuleInfo] = &[];

pub fn check(_surfaces: &[ServerSurface]) -> Vec<Finding> {
    Vec::new()
}
