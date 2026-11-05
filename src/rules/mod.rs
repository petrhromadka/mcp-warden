//! Rule registry. Surface rules read what a server shows the model; config rules read how a
//! client launches or reaches a server.

pub mod config_rules;
pub mod exfil;
pub mod hidden;
pub mod injection;

use crate::model::{Finding, RuleInfo, ServerConfig, ServerSurface};

/// Every rule mcp-warden can report, including pin/drift rules, sorted by id.
pub fn all_rules() -> Vec<RuleInfo> {
    let mut rules: Vec<RuleInfo> = [
        injection::RULES,
        hidden::RULES,
        exfil::RULES,
        config_rules::RULES,
        crate::pin::RULES,
    ]
    .concat();
    rules.sort_by_key(|r| r.id);
    rules
}

pub fn rule(id: &str) -> Option<RuleInfo> {
    all_rules().into_iter().find(|r| r.id == id)
}

/// Run every surface rule over the given server surfaces.
pub fn check_surfaces(surfaces: &[ServerSurface]) -> Vec<Finding> {
    let mut out = injection::check(surfaces);
    out.extend(hidden::check(surfaces));
    out.extend(exfil::check(surfaces));
    out
}

/// Run every config rule over the given server entries.
pub fn check_configs(configs: &[ServerConfig]) -> Vec<Finding> {
    config_rules::check(configs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_ids_are_unique_and_well_formed() {
        let rules = all_rules();
        let mut ids: Vec<_> = rules.iter().map(|r| r.id).collect();
        ids.dedup();
        assert_eq!(ids.len(), rules.len(), "duplicate rule id");
        for r in &rules {
            assert!(r.id.len() == 5 && r.id.starts_with("MW"), "bad id {}", r.id);
            assert!(
                !r.summary.is_empty() && !r.help.is_empty(),
                "{} lacks docs",
                r.id
            );
        }
    }
}
