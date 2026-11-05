//! Get a server's surface: load a saved dump, or (opt-in) connect to the server over stdio or
//! HTTP and call `initialize`, `tools/list`, `prompts/list` and `resources/list`.
//!
//! The protocol sequence lives once in [`fetch_surface`], generic over an [`Rpc`] transport:
//! [`session::Session`] (newline-delimited JSON-RPC over any `BufRead` + `Write`, used for
//! stdio) and [`http::HttpRpc`] (Streamable HTTP).

mod dump;
mod http;
mod session;
mod stdio;

use std::fmt;
use std::time::Duration;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::model::{Prompt, Resource, ServerConfig, ServerSurface, Tool, Transport};
use crate::text::snippet;

pub use dump::load_dump;

/// Protocol revision announced in `initialize`.
const PROTOCOL_VERSION: &str = "2025-06-18";
/// Longest accepted line (stdio) or single message (HTTP) from a server.
const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
/// Most bytes accepted from one server over the whole exchange, noise included.
const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
/// Largest serialized `inputSchema` or `outputSchema` accepted for one tool.
const MAX_SCHEMA_BYTES: usize = 1024 * 1024;
/// Most items accepted from one `*/list` call sequence.
const MAX_ITEMS: usize = 10_000;
/// Most pages followed for one `*/list` call sequence.
const MAX_PAGES: usize = 100;

/// Why a JSON-RPC request failed.
#[derive(Debug)]
enum RpcError {
    /// The server answered with a JSON-RPC `error` object.
    Server(String),
    /// Transport, framing, limit or timeout problem.
    Other(String),
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RpcError::Server(m) | RpcError::Other(m) => f.write_str(m),
        }
    }
}

/// Running total of the bytes received from one server.
struct Budget {
    left: usize,
}

impl Budget {
    fn new() -> Self {
        Budget {
            left: MAX_TOTAL_BYTES,
        }
    }

    /// Account for `n` received bytes.
    fn spend(&mut self, n: usize) -> Result<(), RpcError> {
        self.left = self.left.checked_sub(n).ok_or_else(|| {
            RpcError::Other(format!(
                "server sent more than {} MiB in total",
                MAX_TOTAL_BYTES / (1024 * 1024)
            ))
        })?;
        Ok(())
    }
}

/// Fail if a tool in a `tools/list` page carries an oversize schema.
fn check_tool_schemas(tools: &[Value]) -> Result<(), RpcError> {
    for tool in tools {
        for key in ["inputSchema", "outputSchema"] {
            let size = tool.get(key).map_or(0, |schema| schema.to_string().len());
            if size > MAX_SCHEMA_BYTES {
                let name = tool.get("name").and_then(Value::as_str).unwrap_or("?");
                return Err(RpcError::Other(format!(
                    "tool `{}`: {key} is larger than {MAX_SCHEMA_BYTES} bytes",
                    snippet(name, 80)
                )));
            }
        }
    }
    Ok(())
}

/// One JSON-RPC connection to a server.
trait Rpc {
    /// Send a request and return its `result`.
    fn request(&mut self, method: &str, params: Value) -> Result<Value, RpcError>;
    /// Send a notification (no reply expected).
    fn notify(&mut self, method: &str, params: Value) -> Result<(), RpcError>;
}

/// One decoded incoming JSON-RPC message.
enum Message {
    Response {
        id: Value,
        outcome: Result<Value, RpcError>,
    },
    /// A request from the server to the client; it expects a reply.
    ServerRequest { id: Value },
    /// Notification, log noise or anything unrecognised.
    Ignore,
}

fn classify(value: &Value) -> Message {
    let Some(obj) = value.as_object() else {
        return Message::Ignore;
    };
    let id = obj.get("id").filter(|v| !v.is_null());
    if obj.get("method").is_some_and(Value::is_string) {
        return id.map_or(Message::Ignore, |id| Message::ServerRequest {
            id: id.clone(),
        });
    }
    let Some(id) = id else {
        return Message::Ignore;
    };
    if let Some(err) = obj.get("error") {
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
        let text = err.get("message").and_then(Value::as_str).unwrap_or("");
        let outcome = Err(RpcError::Server(format!(
            "JSON-RPC error {code}: {}",
            snippet(text, 200)
        )));
        return Message::Response {
            id: id.clone(),
            outcome,
        };
    }
    match obj.get("result") {
        Some(result) => Message::Response {
            id: id.clone(),
            outcome: Ok(result.clone()),
        },
        None => Message::Ignore,
    }
}

/// Run the `initialize` -> `tools/list` (+ optional `prompts/list`, `resources/list`) sequence.
fn fetch_surface(rpc: &mut impl Rpc, server: &str) -> Result<ServerSurface, RpcError> {
    let init = rpc.request(
        "initialize",
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcp-warden", "version": env!("CARGO_PKG_VERSION")},
        }),
    )?;
    let instructions = init
        .get("instructions")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let advertises = |cap: &str| {
        init.get("capabilities")
            .and_then(|c| c.get(cap))
            .is_some_and(|v| !v.is_null())
    };
    rpc.notify("notifications/initialized", json!({}))?;

    let tools = list::<Tool>(rpc, "tools/list", "tools")?;
    let prompts = if advertises("prompts") {
        optional(list::<Prompt>(rpc, "prompts/list", "prompts"))?
    } else {
        Vec::new()
    };
    let resources = if advertises("resources") {
        optional(list::<Resource>(rpc, "resources/list", "resources"))?
    } else {
        Vec::new()
    };
    Ok(ServerSurface {
        server: server.to_owned(),
        source: None,
        instructions,
        tools,
        prompts,
        resources,
    })
}

/// A JSON-RPC error from an optional list means "nothing to list"; anything else still fails.
fn optional<T>(result: Result<Vec<T>, RpcError>) -> Result<Vec<T>, RpcError> {
    match result {
        Err(RpcError::Server(_)) => Ok(Vec::new()),
        other => other,
    }
}

/// Call `method` and follow `nextCursor` pages, collecting `key` items.
fn list<T: DeserializeOwned>(
    rpc: &mut impl Rpc,
    method: &str,
    key: &str,
) -> Result<Vec<T>, RpcError> {
    let mut out: Vec<T> = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let params = cursor
            .as_ref()
            .map_or_else(|| json!({}), |c| json!({"cursor": c}));
        let result = rpc.request(method, params)?;
        let items = result
            .get(key)
            .filter(|v| v.is_array())
            .ok_or_else(|| RpcError::Other(format!("{method}: result has no `{key}` array")))?;
        if method == "tools/list" {
            check_tool_schemas(items.as_array().map_or(&[], Vec::as_slice))?;
        }
        let page = Vec::<T>::deserialize(items)
            .map_err(|e| RpcError::Other(format!("{method}: invalid `{key}`: {e}")))?;
        if out.len() + page.len() > MAX_ITEMS {
            return Err(RpcError::Other(format!(
                "{method}: more than {MAX_ITEMS} items"
            )));
        }
        out.extend(page);
        match result
            .get("nextCursor")
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty())
        {
            Some(next) => cursor = Some(next.to_owned()),
            None => return Ok(out),
        }
    }
    Err(RpcError::Other(format!(
        "{method}: more than {MAX_PAGES} pages"
    )))
}

/// Start or contact the server described by `cfg` and read its surface. This RUNS the server's
/// command for stdio servers, so callers must only do it when the user asked for it.
///
/// `timeout` bounds the whole exchange. Stdio servers are always killed afterwards. Legacy
/// HTTP+SSE servers are not supported; save their `tools/list` output and use [`load_dump`].
pub fn introspect(cfg: &ServerConfig, timeout: Duration) -> Result<ServerSurface, String> {
    let result = match &cfg.transport {
        Transport::Stdio {
            command,
            args,
            env,
            cwd,
        } => stdio::run(&cfg.name, command, args, env, cwd.as_deref(), timeout),
        Transport::Http { url, headers } => http::run(&cfg.name, url, headers, timeout),
    };
    result.map_err(|e| format!("{}: {e}", cfg.name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_runs_out() {
        let mut budget = Budget::new();
        budget.spend(MAX_TOTAL_BYTES).unwrap();
        let err = budget.spend(1).unwrap_err().to_string();
        assert!(err.contains("64 MiB"), "{err}");
    }

    #[test]
    fn oversize_schema_names_the_tool() {
        let big = "x".repeat(MAX_SCHEMA_BYTES);
        let tools = [
            json!({"name": "small", "inputSchema": {"type": "object"}}),
            json!({"name": "fat", "inputSchema": {}, "outputSchema": {"description": big}}),
        ];
        let err = check_tool_schemas(&tools).unwrap_err().to_string();
        assert!(
            err.contains("`fat`") && err.contains("outputSchema"),
            "{err}"
        );
        assert!(check_tool_schemas(&tools[..1]).is_ok());
    }
}
