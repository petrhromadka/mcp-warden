//! Load saved server surfaces from JSON files.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::model::{Prompt, Resource, ServerSurface, Tool};

/// Largest dump file accepted.
const MAX_DUMP_BYTES: u64 = 64 * 1024 * 1024;

/// Load surfaces from a JSON file. Accepted shapes:
/// - an mcp-warden surfaces file: one `ServerSurface` object or an array of them;
/// - a raw `tools/list` result (`{"tools": [...]}`, optionally with `prompts`, `resources`,
///   `instructions`), or a JSON-RPC response wrapping one;
/// - an array of such JSON-RPC responses (`initialize`, `tools/list`, `prompts/list`,
///   `resources/list`), merged into one surface.
///
/// Unless the file holds named surfaces, the server name is the file stem.
pub fn load_dump(path: &Path) -> Result<Vec<ServerSurface>, String> {
    let fail = |why: &dyn std::fmt::Display| format!("{}: {why}", path.display());
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_DUMP_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|e| fail(&e))?;
    if bytes.len() as u64 > MAX_DUMP_BYTES {
        return Err(fail(&"file is larger than 64 MiB"));
    }
    let json = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&bytes);
    let value: Value =
        serde_json::from_slice(json).map_err(|e| fail(&format!("invalid JSON: {e}")))?;
    let stem = path
        .file_stem()
        .map_or_else(|| "dump".to_owned(), |s| s.to_string_lossy().into_owned());
    let mut surfaces = parse(value, &stem).map_err(|why| fail(&why))?;
    for surface in &mut surfaces {
        surface.source = Some(path.to_path_buf());
    }
    Ok(surfaces)
}

fn parse(value: Value, stem: &str) -> Result<Vec<ServerSurface>, String> {
    let items = match value {
        Value::Array(items) => items,
        other => vec![other],
    };
    if items.is_empty() {
        return Err("empty array".to_owned());
    }
    let named = |v: &Value| v.get("server").is_some_and(Value::is_string);
    if items.iter().all(named) {
        items
            .iter()
            .enumerate()
            .map(|(i, v)| ServerSurface::deserialize(v).map_err(|e| format!("surface {i}: {e}")))
            .collect()
    } else if items.iter().any(named) {
        Err("mixes surface objects with other JSON values".to_owned())
    } else {
        merge(&items, stem).map(|surface| vec![surface])
    }
}

/// Merge raw `*/list` results and JSON-RPC responses into one surface.
fn merge(items: &[Value], stem: &str) -> Result<ServerSurface, String> {
    let mut surface = ServerSurface {
        server: stem.to_owned(),
        ..ServerSurface::default()
    };
    let mut found = false;
    let mut first_error = None;
    for item in items {
        if let Some(error) = item.get("error") {
            first_error.get_or_insert_with(|| error.to_string());
            continue;
        }
        let result = item.get("result").unwrap_or(item);
        if let Some(v) = result.get("tools") {
            surface.tools.extend(list::<Tool>(v, "tools")?);
            found = true;
        }
        if let Some(v) = result.get("prompts") {
            surface.prompts.extend(list::<Prompt>(v, "prompts")?);
            found = true;
        }
        if let Some(v) = result.get("resources") {
            surface.resources.extend(list::<Resource>(v, "resources")?);
            found = true;
        }
        if let Some(text) = result.get("instructions").and_then(Value::as_str) {
            surface.instructions = Some(text.to_owned());
            found = true;
        }
    }
    if found {
        Ok(surface)
    } else if let Some(error) = first_error {
        Err(format!("only JSON-RPC error responses: {error}"))
    } else {
        Err("no tools, prompts, resources or instructions found (expected a surfaces file, a tools/list result or JSON-RPC responses)".to_owned())
    }
}

fn list<T: DeserializeOwned>(value: &Value, key: &str) -> Result<Vec<T>, String> {
    Vec::<T>::deserialize(value).map_err(|e| format!("invalid `{key}`: {e}"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn dump(dir: &tempfile::TempDir, name: &str, content: &Value) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, content.to_string()).unwrap();
        path
    }

    #[test]
    fn surfaces_file_object_and_array() {
        let dir = tempfile::tempdir().unwrap();
        let one = dump(
            &dir,
            "one.json",
            &json!({"server": "a", "tools": [{"name": "t"}]}),
        );
        let got = load_dump(&one).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].server.as_str(), got[0].tools.len()), ("a", 1));
        assert_eq!(got[0].source.as_deref(), Some(one.as_path()));

        let many = dump(
            &dir,
            "many.json",
            &json!([{"server": "a"}, {"server": "b", "instructions": "hi"}]),
        );
        let got = load_dump(&many).unwrap();
        assert_eq!(
            got.iter().map(|s| s.server.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!(got[1].instructions.as_deref(), Some("hi"));
    }

    #[test]
    fn raw_result_and_single_response_use_file_stem() {
        let dir = tempfile::tempdir().unwrap();
        let tool = json!({"name": "add", "description": "d", "inputSchema": {"type": "object"}});
        let raw = dump(
            &dir,
            "calc.json",
            &json!({"tools": [tool], "instructions": "use me"}),
        );
        let got = load_dump(&raw).unwrap();
        assert_eq!(got[0].server, "calc");
        assert_eq!(got[0].tools[0].name, "add");
        assert_eq!(got[0].instructions.as_deref(), Some("use me"));

        let rpc = dump(
            &dir,
            "rpc.json",
            &json!({"jsonrpc": "2.0", "id": 2, "result": {"tools": [tool]}}),
        );
        assert_eq!(load_dump(&rpc).unwrap()[0].tools.len(), 1);
    }

    #[test]
    fn response_array_is_merged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dump(
            &dir,
            "merged.json",
            &json!([
                {"jsonrpc": "2.0", "id": 1, "result": {"instructions": "be nice", "capabilities": {}}},
                {"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "a"}], "nextCursor": "x"}},
                {"jsonrpc": "2.0", "id": 3, "result": {"tools": [{"name": "b"}]}},
                {"jsonrpc": "2.0", "id": 4, "result": {"prompts": [{"name": "p"}]}},
                {"jsonrpc": "2.0", "id": 5, "result": {"resources": [{"uri": "file:///x", "name": "x"}]}},
                {"jsonrpc": "2.0", "id": 6, "error": {"code": -32601, "message": "nope"}},
            ]),
        );
        let got = load_dump(&path).unwrap();
        assert_eq!(got.len(), 1);
        let s = &got[0];
        assert_eq!(s.server, "merged");
        assert_eq!(s.instructions.as_deref(), Some("be nice"));
        assert_eq!(
            s.tools.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!((s.prompts.len(), s.resources.len()), (1, 1));
    }

    #[test]
    fn bad_files_report_path_and_reason() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.json");
        assert!(
            load_dump(&missing)
                .unwrap_err()
                .starts_with(&format!("{}: ", missing.display()))
        );

        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, "{not json").unwrap();
        let err = load_dump(&bad).unwrap_err();
        assert!(
            err.starts_with(&format!("{}: invalid JSON", bad.display())),
            "{err}"
        );

        for (name, content, needle) in [
            ("empty.json", json!([]), "empty array"),
            ("other.json", json!({"hello": 1}), "no tools"),
            (
                "err.json",
                json!({"jsonrpc": "2.0", "id": 1, "error": {"code": 1, "message": "m"}}),
                "error",
            ),
            (
                "mixed.json",
                json!([{"server": "a"}, {"tools": []}]),
                "mixes",
            ),
            (
                "badtool.json",
                json!({"tools": [{"description": "no name"}]}),
                "invalid `tools`",
            ),
        ] {
            let err = load_dump(&dump(&dir, name, &content)).unwrap_err();
            assert!(err.contains(needle), "{name}: {err}");
        }
    }
}
