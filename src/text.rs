//! Shared text helpers: enumerate every model-visible string of a server, and make evidence
//! snippets safe to print.

use serde_json::Value;

use crate::model::ServerSurface;

/// What kind of model-visible text a [`TextField`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldKind {
    ServerInstructions,
    ToolName,
    ToolTitle,
    ToolDescription,
    /// Property name inside a tool's input schema.
    ParamName,
    /// `description` / `title` anywhere inside a tool's input or output schema.
    ParamDescription,
    /// Other strings in a schema the model sees: `default`, `examples`, `enum`, `const`.
    SchemaValue,
    PromptName,
    PromptDescription,
    PromptArgName,
    PromptArgDescription,
    ResourceName,
    ResourceDescription,
    ResourceUri,
}

impl FieldKind {
    /// Names (identifiers) rather than free-form prose.
    pub fn is_name(self) -> bool {
        matches!(
            self,
            FieldKind::ToolName
                | FieldKind::ParamName
                | FieldKind::PromptName
                | FieldKind::PromptArgName
                | FieldKind::ResourceName
                | FieldKind::ResourceUri
        )
    }
}

/// One model-visible string of a server surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextField<'a> {
    pub kind: FieldKind,
    /// Logical location, e.g. `tools/add/inputSchema/properties/sidenote/description`.
    pub pointer: String,
    /// The tool / prompt / resource this text belongs to (`None` for server instructions).
    pub owner: Option<&'a str>,
    pub text: &'a str,
}

/// Every string of `surface` that ends up in the model's context, in a stable order.
pub fn text_fields(surface: &ServerSurface) -> Vec<TextField<'_>> {
    let mut out = Vec::new();
    if let Some(instr) = surface.instructions.as_deref() {
        out.push(TextField {
            kind: FieldKind::ServerInstructions,
            pointer: "instructions".to_owned(),
            owner: None,
            text: instr,
        });
    }
    for tool in &surface.tools {
        let base = format!("tools/{}", tool.name);
        let owner = Some(tool.name.as_str());
        let fields = [
            Some((FieldKind::ToolName, "name", tool.name.as_str())),
            tool.title
                .as_deref()
                .map(|t| (FieldKind::ToolTitle, "title", t)),
            tool.description
                .as_deref()
                .map(|d| (FieldKind::ToolDescription, "description", d)),
        ];
        for (kind, key, text) in fields.into_iter().flatten() {
            out.push(TextField {
                kind,
                pointer: format!("{base}/{key}"),
                owner,
                text,
            });
        }
        walk_schema(
            &tool.input_schema,
            &format!("{base}/inputSchema"),
            owner,
            &mut out,
        );
        if let Some(schema) = &tool.output_schema {
            walk_schema(schema, &format!("{base}/outputSchema"), owner, &mut out);
        }
    }
    for prompt in &surface.prompts {
        let base = format!("prompts/{}", prompt.name);
        let owner = Some(prompt.name.as_str());
        out.push(TextField {
            kind: FieldKind::PromptName,
            pointer: format!("{base}/name"),
            owner,
            text: &prompt.name,
        });
        if let Some(d) = prompt.description.as_deref() {
            out.push(TextField {
                kind: FieldKind::PromptDescription,
                pointer: format!("{base}/description"),
                owner,
                text: d,
            });
        }
        for arg in &prompt.arguments {
            let abase = format!("{base}/arguments/{}", arg.name);
            out.push(TextField {
                kind: FieldKind::PromptArgName,
                pointer: format!("{abase}/name"),
                owner,
                text: &arg.name,
            });
            if let Some(d) = arg.description.as_deref() {
                out.push(TextField {
                    kind: FieldKind::PromptArgDescription,
                    pointer: format!("{abase}/description"),
                    owner,
                    text: d,
                });
            }
        }
    }
    for res in &surface.resources {
        let base = format!("resources/{}", res.uri);
        let owner = Some(res.uri.as_str());
        out.push(TextField {
            kind: FieldKind::ResourceUri,
            pointer: format!("{base}/uri"),
            owner,
            text: &res.uri,
        });
        if !res.name.is_empty() {
            out.push(TextField {
                kind: FieldKind::ResourceName,
                pointer: format!("{base}/name"),
                owner,
                text: &res.name,
            });
        }
        if let Some(d) = res.description.as_deref() {
            out.push(TextField {
                kind: FieldKind::ResourceDescription,
                pointer: format!("{base}/description"),
                owner,
                text: d,
            });
        }
    }
    out
}

const SCHEMA_DEPTH_LIMIT: usize = 32;

fn walk_schema<'a>(
    value: &'a Value,
    pointer: &str,
    owner: Option<&'a str>,
    out: &mut Vec<TextField<'a>>,
) {
    walk(value, pointer, owner, out, 0);
}

fn walk<'a>(
    value: &'a Value,
    pointer: &str,
    owner: Option<&'a str>,
    out: &mut Vec<TextField<'a>>,
    depth: usize,
) {
    if depth > SCHEMA_DEPTH_LIMIT {
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let p = format!("{pointer}/{key}");
                match (key.as_str(), child) {
                    ("description" | "title", Value::String(s)) => out.push(TextField {
                        kind: FieldKind::ParamDescription,
                        pointer: p,
                        owner,
                        text: s,
                    }),
                    ("default" | "const", Value::String(s)) => out.push(TextField {
                        kind: FieldKind::SchemaValue,
                        pointer: p,
                        owner,
                        text: s,
                    }),
                    ("properties", Value::Object(props)) => {
                        for (name, schema) in props {
                            let pp = format!("{p}/{name}");
                            out.push(TextField {
                                kind: FieldKind::ParamName,
                                pointer: pp.clone(),
                                owner,
                                text: name,
                            });
                            walk(schema, &pp, owner, out, depth + 1);
                        }
                    }
                    ("enum" | "examples", Value::Array(items)) => {
                        for (i, item) in items.iter().enumerate() {
                            if let Value::String(s) = item {
                                out.push(TextField {
                                    kind: FieldKind::SchemaValue,
                                    pointer: format!("{p}/{i}"),
                                    owner,
                                    text: s,
                                });
                            } else {
                                walk(item, &format!("{p}/{i}"), owner, out, depth + 1);
                            }
                        }
                    }
                    _ => walk(child, &p, owner, out, depth + 1),
                }
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                walk(item, &format!("{pointer}/{i}"), owner, out, depth + 1);
            }
        }
        _ => {}
    }
}

/// Characters that render as nothing or reorder text: zero-width, bidi controls, BOM,
/// Unicode tag characters (U+E0000..U+E007F) and variation selectors.
pub fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{00AD}'
        | '\u{034F}'
        | '\u{061C}'
        | '\u{115F}' | '\u{1160}'
        | '\u{17B4}' | '\u{17B5}'
        | '\u{180B}'..='\u{180F}'
        | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{206F}'
        | '\u{3164}'
        | '\u{FE00}'..='\u{FE0F}'
        | '\u{FEFF}'
        | '\u{FFA0}'
        | '\u{1D173}'..='\u{1D17A}'
        | '\u{E0000}'..='\u{E007F}'
        | '\u{E0100}'..='\u{E01EF}'
    )
}

/// Make untrusted text safe and short enough to print as evidence: control and invisible
/// characters become `\u{..}` escapes, whitespace runs collapse to one space, and the result is
/// cut to at most `max_chars` characters (plus `…`).
pub fn snippet(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut count = 0;
    let mut last_space = false;
    for c in text.chars() {
        if count >= max_chars {
            out.push('…');
            return out;
        }
        if c.is_whitespace() && !is_invisible(c) {
            if !last_space {
                out.push(' ');
                count += 1;
            }
            last_space = true;
            continue;
        }
        last_space = false;
        if c.is_control() || is_invisible(c) {
            let esc = format!("\\u{{{:x}}}", u32::from(c));
            count += esc.chars().count();
            out.push_str(&esc);
        } else {
            out.push(c);
            count += 1;
        }
    }
    out
}

/// Evidence snippet of `text` centred on the byte range `start..end` (e.g. a regex match).
pub fn snippet_around(text: &str, start: usize, end: usize, max_chars: usize) -> String {
    let context = max_chars / 3;
    let from = text[..start]
        .char_indices()
        .rev()
        .nth(context)
        .map_or(0, |(i, _)| i);
    let to = text[end..]
        .char_indices()
        .nth(context)
        .map_or(text.len(), |(i, _)| end + i);
    let mut s = String::new();
    if from > 0 {
        s.push('…');
    }
    s.push_str(&snippet(&text[from..to], max_chars));
    if to < text.len() && !s.ends_with('…') {
        s.push('…');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Prompt, PromptArgument, Tool};
    use serde_json::json;

    #[test]
    fn enumerates_nested_schema_text() {
        let surface = ServerSurface {
            server: "s".into(),
            instructions: Some("hi".into()),
            tools: vec![Tool {
                name: "add".into(),
                description: Some("Adds".into()),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "a": {"type": "number", "description": "first"},
                        "opts": {"type": "object", "properties": {"mode": {"enum": ["x", "y"]}}}
                    }
                }),
                ..Tool::default()
            }],
            prompts: vec![Prompt {
                name: "p".into(),
                arguments: vec![PromptArgument {
                    name: "q".into(),
                    description: Some("arg".into()),
                    required: false,
                }],
                ..Prompt::default()
            }],
            ..ServerSurface::default()
        };
        let pointers: Vec<_> = text_fields(&surface)
            .into_iter()
            .map(|f| f.pointer)
            .collect();
        for want in [
            "instructions",
            "tools/add/description",
            "tools/add/inputSchema/properties/a/description",
            "tools/add/inputSchema/properties/opts/properties/mode",
            "tools/add/inputSchema/properties/opts/properties/mode/enum/1",
            "prompts/p/arguments/q/description",
        ] {
            assert!(
                pointers.iter().any(|p| p == want),
                "missing {want}: {pointers:?}"
            );
        }
    }

    #[test]
    fn snippet_escapes_invisible_and_truncates() {
        assert_eq!(snippet("a\u{200B}b\n\n c", 50), "a\\u{200b}b c");
        assert_eq!(snippet("abcdef", 3), "abc…");
        assert_eq!(snippet("x\u{E0041}", 50), "x\\u{e0041}");
    }

    #[test]
    fn snippet_around_marks_cut_context() {
        let text = format!("{}NEEDLE{}", "a".repeat(100), "b".repeat(100));
        let s = snippet_around(&text, 100, 106, 30);
        assert!(
            s.starts_with('…') && s.contains("NEEDLE") && s.ends_with('…'),
            "{s}"
        );
    }
}
