//! Risky client configuration of MCP servers (MW100-MW119).

use crate::model::{Finding, RuleInfo, ServerConfig};

pub const RULES: &[RuleInfo] = &[];

pub fn check(_configs: &[ServerConfig]) -> Vec<Finding> {
    Vec::new()
}
