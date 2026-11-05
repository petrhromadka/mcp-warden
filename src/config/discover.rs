//! Known config locations per client. All OS variants are tried under `home`, so discovery
//! does not depend on the host OS.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::Discovered;

/// Per-OS bases of application data under the home directory (macOS, Windows, Linux).
const OS_BASES: [&str; 3] = ["Library/Application Support", "AppData/Roaming", ".config"];
const VSCODE_DIRS: [&str; 2] = ["Code", "Code - Insiders"];
const CLINE_REL: &str = "globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json";

const HOME_FILES: [(&str, &str); 11] = [
    ("claude-code", ".claude.json"),
    ("cursor", ".cursor/mcp.json"),
    ("copilot", ".copilot/mcp-config.json"),
    ("windsurf", ".codeium/windsurf/mcp_config.json"),
    ("windsurf", ".config/devin/mcp_config.json"),
    ("gemini-cli", ".gemini/settings.json"),
    ("codex", ".codex/config.toml"),
    ("zed", ".config/zed/settings.json"),
    ("zed", "AppData/Roaming/Zed/settings.json"),
    ("cline", ".cline/data/settings/cline_mcp_settings.json"),
    ("antigravity", ".gemini/config/mcp_config.json"),
];

const PROJECT_FILES: [(&str, &str); 8] = [
    ("claude-code", ".mcp.json"),
    ("cursor", ".cursor/mcp.json"),
    ("vscode", ".vscode/mcp.json"),
    ("windsurf", ".devin/mcp_config.json"),
    ("gemini-cli", ".gemini/settings.json"),
    ("codex", ".codex/config.toml"),
    ("zed", ".zed/settings.json"),
    ("antigravity", ".agents/mcp_config.json"),
];

fn home_candidates(home: &Path) -> Vec<(&'static str, PathBuf)> {
    let mut c: Vec<(&'static str, PathBuf)> = Vec::new();
    for base in OS_BASES {
        c.push((
            "claude-desktop",
            home.join(base).join("Claude/claude_desktop_config.json"),
        ));
        for variant in VSCODE_DIRS {
            let user = home.join(base).join(variant).join("User");
            c.push(("vscode", user.join("mcp.json")));
            c.push(("vscode", user.join("settings.json")));
            c.push(("cline", user.join(CLINE_REL)));
        }
    }
    c.extend(
        HOME_FILES
            .iter()
            .map(|(client, rel)| (*client, home.join(rel))),
    );
    c.push((
        "antigravity",
        home.join(".gemini/antigravity/mcp_config.json"),
    ));
    c
}

pub fn discover(home: &Path, project: &Path) -> Vec<Discovered> {
    let project_candidates = PROJECT_FILES
        .iter()
        .map(|(client, rel)| (*client, project.join(rel)));
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut found = Vec::new();
    for (client, path) in home_candidates(home).into_iter().chain(project_candidates) {
        if !path.is_file() {
            continue;
        }
        let key = path.canonicalize().unwrap_or_else(|_| path.clone());
        if seen.insert(key) {
            found.push(Discovered { path, client });
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn touch(root: &Path, rel: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, "{}").unwrap();
    }

    #[test]
    fn finds_existing_candidates_across_os_variants_and_dedups() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        for rel in [
            ".claude.json",
            "Library/Application Support/Claude/claude_desktop_config.json",
            "AppData/Roaming/Code - Insiders/User/settings.json",
            ".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
            ".codex/config.toml",
            ".cursor/mcp.json",
            ".gemini/antigravity/mcp_config.json",
        ] {
            touch(h, rel);
        }
        // home == project: shared paths must appear once.
        let found = discover(h, h);
        let mut clients: Vec<_> = found.iter().map(|d| d.client).collect();
        clients.sort_unstable();
        assert_eq!(
            clients,
            [
                "antigravity",
                "claude-code",
                "claude-desktop",
                "cline",
                "codex",
                "cursor",
                "vscode"
            ]
        );
    }

    #[test]
    fn finds_project_files() {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        for rel in [
            ".mcp.json",
            ".vscode/mcp.json",
            ".zed/settings.json",
            ".agents/mcp_config.json",
        ] {
            touch(project.path(), rel);
        }
        let found = discover(home.path(), project.path());
        assert_eq!(found.len(), 4);
        assert!(found.iter().any(|d| d.client == "zed"));
    }
}
