//! Get a server's surface: load a saved dump, or (opt-in) connect to the server over stdio or
//! HTTP and call `initialize`, `tools/list`, `prompts/list` and `resources/list`.

use std::path::Path;
use std::time::Duration;

use crate::model::{ServerConfig, ServerSurface};

/// Load surfaces from a JSON file. Accepts an mcp-warden surfaces file (one object or an array),
/// a raw `tools/list` result (`{"tools": [...]}`), or a JSON-RPC response wrapping one.
pub fn load_dump(path: &Path) -> Result<Vec<ServerSurface>, String> {
    Err(format!("{}: dump loading not implemented", path.display()))
}

/// Start or contact the server described by `cfg` and read its surface. This RUNS the server's
/// command for stdio servers, so callers must only do it when the user asked for it.
pub fn introspect(cfg: &ServerConfig, _timeout: Duration) -> Result<ServerSurface, String> {
    Err(format!("{}: introspection not implemented", cfg.name))
}
