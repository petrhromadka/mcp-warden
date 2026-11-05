//! mcp-warden: offline static scanner for MCP servers and MCP client configuration.
//!
//! Pipeline: discover/parse client configs (`config`) -> optionally introspect servers
//! (`introspect`, opt-in, or load a saved `tools/list` dump) -> run rules (`rules`) ->
//! compare against a pin lockfile (`pin`) -> render (`report`).

pub mod cli;
pub mod config;
pub mod introspect;
pub mod model;
pub mod pin;
pub mod report;
pub mod rules;
pub mod text;
