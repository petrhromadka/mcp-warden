//! Parse one config file (JSON, JSONC or TOML) into [`ServerConfig`] entries.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde_json::{Map, Value};

use super::jsonc;
use crate::model::{ServerConfig, Transport};

/// Config files larger than this are rejected without parsing.
pub const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;

pub fn parse_file(path: &Path, client: Option<&str>) -> Result<Vec<ServerConfig>, String> {
    let fail = |reason: &str| format!("{}: {reason}", path.display());
    let text = read_limited(path).map_err(|e| fail(&e))?;
    let client = client.map_or_else(|| detect_client(path).to_string(), str::to_string);

    let is_toml = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("toml"));
    let root: Value = if is_toml {
        // `toml::de::Error`'s Display quotes source lines, which may hold secrets: use message().
        let table: toml::Table =
            toml::from_str(&text).map_err(|e| fail(&format!("invalid TOML: {}", e.message())))?;
        serde_json::to_value(table).map_err(|e| fail(&format!("invalid TOML: {e}")))?
    } else {
        serde_json::from_str(&jsonc::strip(&text))
            .map_err(|e| fail(&format!("invalid JSON: {e}")))?
    };

    let mut ctx = Ctx {
        client: &client,
        source: path,
        out: Vec::new(),
    };
    if let Some(obj) = root.as_object() {
        collect(obj, &mut ctx);
    }
    Ok(ctx.out)
}

fn read_limited(path: &Path) -> Result<String, String> {
    let file = File::open(path).map_err(|e| format!("cannot read file: {}", e.kind()))?;
    let mut buf = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("cannot read file: {}", e.kind()))?;
    if buf.len() as u64 > MAX_FILE_BYTES {
        return Err("file larger than 32 MiB".into());
    }
    String::from_utf8(buf).map_err(|_| "file is not valid UTF-8".into())
}

struct Ctx<'a> {
    client: &'a str,
    source: &'a Path,
    out: Vec<ServerConfig>,
}

impl Ctx<'_> {
    fn section(&mut self, value: Option<&Value>, prefix: &str) {
        let Some(servers) = value.and_then(Value::as_object) else {
            return;
        };
        for (name, entry) in servers {
            if let Some((transport, disabled)) = parse_entry(entry) {
                self.out.push(ServerConfig {
                    name: name.clone(),
                    client: self.client.to_string(),
                    source: self.source.to_path_buf(),
                    pointer: format!("{prefix}/{name}"),
                    transport,
                    disabled,
                });
            }
        }
    }
}

fn collect(root: &Map<String, Value>, ctx: &mut Ctx) {
    ctx.section(root.get("mcpServers"), "mcpServers");
    // Claude Code `~/.claude.json`: per-project servers.
    if let Some(projects) = root.get("projects").and_then(Value::as_object) {
        for (project, v) in projects {
            ctx.section(
                v.get("mcpServers"),
                &format!("projects/{project}/mcpServers"),
            );
        }
    }
    // Codex TOML.
    ctx.section(root.get("mcp_servers"), "mcp_servers");
    match ctx.client {
        "vscode" => {
            ctx.section(root.get("servers"), "servers");
            ctx.section(
                root.get("mcp").and_then(|m| m.get("servers")),
                "mcp/servers",
            );
        }
        "zed" => ctx.section(root.get("context_servers"), "context_servers"),
        _ => {}
    }
}

fn stringify(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn string_list(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().map(stringify).collect())
        .unwrap_or_default()
}

fn string_map(v: Option<&Value>) -> BTreeMap<String, String> {
    v.and_then(Value::as_object)
        .map(|o| o.iter().map(|(k, v)| (k.clone(), stringify(v))).collect())
        .unwrap_or_default()
}

fn is_remote_type(t: &str) -> bool {
    matches!(
        t.to_ascii_lowercase().as_str(),
        "http" | "sse" | "streamable-http" | "streamable_http" | "streamablehttp"
    )
}

/// Returns the transport and the disabled flag, or `None` for a malformed entry.
fn parse_entry(entry: &Value) -> Option<(Transport, bool)> {
    let e = entry.as_object()?;
    let disabled = e.get("disabled").and_then(Value::as_bool) == Some(true)
        || e.get("enabled").and_then(Value::as_bool) == Some(false);
    let url = ["url", "serverUrl", "httpUrl"]
        .iter()
        .find_map(|k| e.get(*k).and_then(Value::as_str))
        .filter(|u| !u.is_empty());
    let remote_type = ["type", "transport"]
        .iter()
        .find_map(|k| e.get(*k).and_then(Value::as_str))
        .is_some_and(is_remote_type);

    let transport = match (parse_command(e), url) {
        (Some((command, args, env)), u) if !(remote_type && u.is_some()) => Transport::Stdio {
            command,
            args,
            env,
            cwd: e.get("cwd").and_then(Value::as_str).map(str::to_string),
        },
        (_, Some(url)) => {
            let mut headers = string_map(e.get("headers"));
            headers.extend(string_map(e.get("http_headers")));
            Transport::Http {
                url: url.to_string(),
                headers,
            }
        }
        _ => return None,
    };
    Some((transport, disabled))
}

type StdioParts = (String, Vec<String>, BTreeMap<String, String>);

/// `command` is a string (`args`/`env` siblings), a Zed object `{path|command, args, env}`,
/// or an array whose first item is the program.
fn parse_command(e: &Map<String, Value>) -> Option<StdioParts> {
    let (command, mut args, mut env) = match e.get("command")? {
        Value::String(s) => (s.clone(), Vec::new(), BTreeMap::new()),
        Value::Array(a) => {
            let mut items = a.iter().map(stringify);
            (items.next()?, items.collect(), BTreeMap::new())
        }
        Value::Object(o) => (
            o.get("path")
                .or_else(|| o.get("command"))
                .and_then(Value::as_str)?
                .to_string(),
            string_list(o.get("args")),
            string_map(o.get("env")),
        ),
        _ => return None,
    };
    if command.is_empty() {
        return None;
    }
    args.extend(string_list(e.get("args")));
    env.extend(string_map(e.get("env")));
    Some((command, args, env))
}

/// Detect the client from the file name and parent directory names.
pub fn detect_client(path: &Path) -> &'static str {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    // Parent directory names, closest first.
    let dirs: Vec<String> = path
        .parent()
        .into_iter()
        .flat_map(Path::ancestors)
        .filter_map(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .collect();
    let parent = dirs.first().map_or("", String::as_str);
    let in_vscode_user = parent == "user"
        && dirs.iter().any(|d| {
            matches!(
                d.as_str(),
                "code" | "code - insiders" | "code - oss" | "vscodium"
            )
        });

    match name.as_str() {
        "claude_desktop_config.json" => "claude-desktop",
        ".claude.json" | ".mcp.json" => "claude-code",
        "cline_mcp_settings.json" => "cline",
        "mcp-config.json" if parent == ".copilot" => "copilot",
        "config.toml" if parent == ".codex" => "codex",
        "mcp.json" if parent == ".cursor" => "cursor",
        "settings.json" if parent == ".gemini" => "gemini-cli",
        "settings.json" if matches!(parent, "zed" | ".zed") => "zed",
        "mcp.json" | "settings.json" if parent == ".vscode" || in_vscode_user => "vscode",
        "mcp_config.json" => dirs
            .iter()
            .find_map(|d| match d.as_str() {
                ".codeium" | ".devin" | "devin" | "windsurf" => Some("windsurf"),
                ".gemini" | ".agents" | "antigravity" => Some("antigravity"),
                _ => None,
            })
            .unwrap_or("generic"),
        _ => "generic",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn fixture(rel: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/config")
            .join(rel)
    }

    fn write(dir: &Path, rel: &str, content: &str) -> PathBuf {
        let p = dir.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, content).unwrap();
        p
    }

    fn by_pointer<'a>(servers: &'a [ServerConfig], pointer: &str) -> &'a ServerConfig {
        servers
            .iter()
            .find(|s| s.pointer == pointer)
            .unwrap_or_else(|| panic!("no entry {pointer}"))
    }

    #[test]
    fn claude_code_top_level_and_project_servers() {
        let s = parse_file(&fixture("home/.claude.json"), None).unwrap();
        assert_eq!(s.len(), 3);
        assert!(s.iter().all(|x| x.client == "claude-code"));
        let github = by_pointer(&s, "mcpServers/github");
        assert_eq!(
            github.transport,
            Transport::Stdio {
                command: "npx".into(),
                args: vec![
                    "-y".into(),
                    "@example/github-mcp".into(),
                    "8080".into(),
                    "true".into()
                ],
                env: BTreeMap::from([
                    ("TOKEN".into(), "dummy-token".into()),
                    ("DEBUG".into(), "1".into())
                ]),
                cwd: Some("/work".into()),
            }
        );
        let remote = by_pointer(&s, "projects//work/app/mcpServers/docs");
        assert_eq!(
            remote.transport,
            Transport::Http {
                url: "https://mcp.example.com/mcp".into(),
                headers: BTreeMap::from([("Authorization".into(), "Bearer dummy".into())]),
            }
        );
        assert!(by_pointer(&s, "projects//work/app/mcpServers/off").disabled);
    }

    #[test]
    fn zed_jsonc_command_forms() {
        let s = parse_file(&fixture("home/.config/zed/settings.json"), None).unwrap();
        assert!(s.iter().all(|x| x.client == "zed"));
        assert_eq!(s.len(), 3);
        let Transport::Stdio {
            command, args, env, ..
        } = &by_pointer(&s, "context_servers/obj").transport
        else {
            panic!("expected stdio");
        };
        assert_eq!(
            (command.as_str(), args.len(), env.len()),
            ("/usr/bin/srv", 1, 1)
        );
        let Transport::Stdio { command, args, .. } =
            &by_pointer(&s, "context_servers/plain").transport
        else {
            panic!("expected stdio");
        };
        assert_eq!(
            (command.as_str(), args.as_slice()),
            ("srv", ["--x".to_string()].as_slice())
        );
        assert!(matches!(
            by_pointer(&s, "context_servers/remote").transport,
            Transport::Http { .. }
        ));
    }

    #[test]
    fn vscode_servers_and_legacy_settings() {
        let s = parse_file(&fixture("proj/.vscode/mcp.json"), None).unwrap();
        assert_eq!(s.len(), 2);
        assert!(s.iter().all(|x| x.client == "vscode"));
        let legacy = parse_file(&fixture("home/.config/Code/User/settings.json"), None).unwrap();
        assert_eq!(legacy.len(), 1);
        assert_eq!(legacy[0].pointer, "mcp/servers/legacy");
    }

    #[test]
    fn codex_toml() {
        let s = parse_file(&fixture("home/.codex/config.toml"), None).unwrap();
        assert!(s.iter().all(|x| x.client == "codex"));
        assert_eq!(s.len(), 2);
        let Transport::Stdio {
            command, env, cwd, ..
        } = &by_pointer(&s, "mcp_servers/local").transport
        else {
            panic!("expected stdio");
        };
        assert_eq!(command, "uvx");
        assert_eq!(env["API_KEY"], "dummy");
        assert_eq!(cwd.as_deref(), Some("/srv"));
        let remote = by_pointer(&s, "mcp_servers/remote");
        assert!(remote.disabled);
        assert!(
            matches!(&remote.transport, Transport::Http { headers, .. } if headers["X-Key"] == "dummy")
        );
    }

    #[test]
    fn windsurf_gemini_and_generic_remote_keys() {
        let dir = tempfile::tempdir().unwrap();
        let body = r#"{"mcpServers": {
            "a": {"serverUrl": "https://a.example/sse"},
            "b": {"httpUrl": "https://b.example/mcp", "headers": {"K": 1}},
            "c": {"url": "https://c.example", "type": "streamableHttp", "command": "ignored"}
        }}"#;
        let ws = write(dir.path(), ".codeium/windsurf/mcp_config.json", body);
        let s = parse_file(&ws, None).unwrap();
        assert!(s.iter().all(|x| x.client == "windsurf"));
        assert_eq!(s.len(), 3);
        assert!(
            s.iter()
                .all(|x| matches!(x.transport, Transport::Http { .. }))
        );
        let gem = write(dir.path(), ".gemini/settings.json", body);
        assert_eq!(parse_file(&gem, None).unwrap()[0].client, "gemini-cli");
        let other = write(dir.path(), "weird.json", body);
        assert_eq!(parse_file(&other, None).unwrap()[0].client, "generic");
        assert_eq!(
            parse_file(&other, Some("cursor")).unwrap()[0].client,
            "cursor"
        );
    }

    #[test]
    fn detects_clients_by_path() {
        let cases = [
            (
                "C:/Users/x/AppData/Roaming/Claude/claude_desktop_config.json",
                "claude-desktop",
            ),
            ("/p/.mcp.json", "claude-code"),
            ("/h/.cursor/mcp.json", "cursor"),
            ("/h/.copilot/mcp-config.json", "copilot"),
            ("/h/.config/devin/mcp_config.json", "windsurf"),
            ("/h/.gemini/antigravity/mcp_config.json", "antigravity"),
            ("/p/.agents/mcp_config.json", "antigravity"),
            (
                "/h/Library/Application Support/Code - Insiders/User/mcp.json",
                "vscode",
            ),
            (
                "/h/.config/Code/User/globalStorage/x/settings/cline_mcp_settings.json",
                "cline",
            ),
            ("C:/Users/x/AppData/Roaming/Zed/settings.json", "zed"),
            ("/h/.codex/config.toml", "codex"),
            ("/h/other/settings.json", "generic"),
        ];
        for (path, want) in cases {
            assert_eq!(detect_client(Path::new(path)), want, "{path}");
        }
    }

    #[test]
    fn malformed_entries_are_skipped_and_bad_files_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            dir.path(),
            "m.json",
            r#"{"mcpServers": {"ok": {"command": "x"}, "str": "nope", "empty": {}, "nocmd": {"command": ""}, "num": {"command": 5}}}"#,
        );
        let s = parse_file(&p, None).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].name, "ok");

        let bad = write(dir.path(), "bad.json", "{not json");
        let err = parse_file(&bad, None).unwrap_err();
        assert!(err.starts_with(&bad.display().to_string()), "{err}");
        let bad_toml = write(dir.path(), "bad.toml", "token = \"secret-value\nx = ");
        let err = parse_file(&bad_toml, None).unwrap_err();
        assert!(!err.contains("secret-value"), "{err}");
        assert!(parse_file(&dir.path().join("missing.json"), None).is_err());
        let arr = write(dir.path(), "arr.json", "[1,2]");
        assert_eq!(parse_file(&arr, None).unwrap().len(), 0);
    }

    #[test]
    fn hostile_nesting_returns_error_without_panic() {
        let dir = tempfile::tempdir().unwrap();
        let deep_json = write(dir.path(), "deep.json", &"[".repeat(200_000));
        assert!(parse_file(&deep_json, None).is_err());
        let deep_obj = write(dir.path(), "deep2.json", &"{\"a\":".repeat(200_000));
        assert!(parse_file(&deep_obj, None).is_err());
        let deep_toml = write(
            dir.path(),
            "deep.toml",
            &format!("a = {}", "[".repeat(200_000)),
        );
        assert!(parse_file(&deep_toml, None).is_err());
    }
}
