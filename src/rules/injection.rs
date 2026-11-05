//! Instruction injection in descriptions (MW001-MW009).

use crate::model::{Finding, RuleInfo, ServerSurface};

pub const RULES: &[RuleInfo] = &[];

pub fn check(_surfaces: &[ServerSurface]) -> Vec<Finding> {
    Vec::new()
}
