//! Find and parse MCP client configuration files into [`ServerConfig`] entries.

use std::path::{Path, PathBuf};

use crate::model::ServerConfig;

/// A config file that exists on disk and the client it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovered {
    pub path: PathBuf,
    /// Client id, e.g. `claude-desktop`, `claude-code`, `cursor`, `vscode`, `codex`.
    pub client: &'static str,
}

/// Known config locations for the user's home and the given project directory that exist.
pub fn discover(_home: &Path, _project: &Path) -> Vec<Discovered> {
    Vec::new()
}

/// Parse one config file. `client` is a hint from discovery; `None` means detect it from the
/// file name and shape (a generic `{"mcpServers": {...}}` file is client `generic`).
pub fn parse_file(path: &Path, _client: Option<&str>) -> Result<Vec<ServerConfig>, String> {
    Err(format!(
        "{}: config parsing not implemented",
        path.display()
    ))
}
