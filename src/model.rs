//! Shared data types. Every module depends on these; changing them is a contract change.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Ordered so `max()` gives the worst severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Severity> {
        Severity::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Static metadata of one rule, used for `mcp-warden rules`, docs and SARIF `rules`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleInfo {
    /// Stable id, e.g. `MW001`.
    pub id: &'static str,
    /// Short kebab-case name, e.g. `hidden-instruction-tag`.
    pub name: &'static str,
    pub severity: Severity,
    /// One-line summary.
    pub summary: &'static str,
    /// Why it matters and how to fix it (plain text, a few sentences).
    pub help: &'static str,
}

/// Where a finding points.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Location {
    /// Config file or tools dump the finding came from, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    /// Logical path inside the server surface or config, e.g.
    /// `tools/add/inputSchema/properties/sidenote/description` or `mcpServers/github/env/TOKEN`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub rule_id: &'static str,
    pub severity: Severity,
    /// Server name the finding is about (as named in the config or dump).
    pub server: String,
    /// Human-readable explanation, safe to print publicly.
    pub message: String,
    /// Short evidence snippet. MUST be redacted (no secret values) and already passed through
    /// `text::snippet` so it is bounded and free of control/invisible characters.
    pub evidence: String,
    pub location: Location,
}

/// How a client launches or reaches one MCP server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Transport {
    Stdio {
        command: String,
        args: Vec<String>,
        env: BTreeMap<String, String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
    },
    /// Streamable HTTP or legacy SSE endpoint.
    Http {
        url: String,
        headers: BTreeMap<String, String>,
    },
}

/// One MCP server entry found in a client configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServerConfig {
    pub name: String,
    /// Client id, e.g. `claude-desktop`, `claude-code`, `cursor`, `vscode`, `codex`, `generic`.
    pub client: String,
    /// File the entry was read from.
    pub source: PathBuf,
    /// Pointer to the entry inside that file, e.g. `mcpServers/github`.
    pub pointer: String,
    pub transport: Transport,
    /// Entry is present but disabled by the client (`disabled: true`, `enabled = false`).
    pub disabled: bool,
}

/// What a server exposes to the model: everything an attacker can put text into.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServerSurface {
    pub server: String,
    /// File the surface was loaded from (a dump), or `None` when introspected live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<PathBuf>,
    /// `initialize` result `instructions`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    #[serde(default)]
    pub tools: Vec<Tool>,
    #[serde(default)]
    pub prompts: Vec<Prompt>,
    #[serde(default)]
    pub resources: Vec<Resource>,
}

/// Mirrors the MCP `Tool` object (field names as in the spec).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub input_schema: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prompt {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub arguments: Vec<PromptArgument>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptArgument {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    pub uri: String,
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Everything one scan produced.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanResult {
    pub tool_version: &'static str,
    /// Config files that were read.
    pub configs_scanned: Vec<PathBuf>,
    pub servers_scanned: usize,
    pub surfaces_scanned: usize,
    pub findings: Vec<Finding>,
    /// Non-fatal problems (unreadable file, server that failed to start, ...).
    pub errors: Vec<String>,
}

impl ScanResult {
    pub fn worst(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}
