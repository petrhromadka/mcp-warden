//! Shared text helpers: enumerate every model-visible string of a server, and make evidence
//! snippets safe to print.

use std::borrow::Cow;

use serde_json::Value;

use crate::model::ServerSurface;

/// Deepest schema level (root = 0) whose children are still read.
pub const MAX_SCHEMA_DEPTH: usize = 64;
/// Most text fields collected from one surface; further text is not read (MW018 reports it).
pub const MAX_TEXT_FIELDS: usize = 100_000;
/// Longest tool/prompt/resource name or property key kept whole inside a pointer.
const MAX_SEGMENT_BYTES: usize = 128;
/// Pointers stop growing at about this size, so deep schemas cannot make them huge.
const MAX_POINTER_BYTES: usize = 512;

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
    PromptTitle,
    PromptDescription,
    PromptArgName,
    PromptArgDescription,
    ResourceName,
    ResourceTitle,
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

    /// Text that belongs to a tool (its title, description or schema), as opposed to a prompt,
    /// a resource or the server instructions.
    pub fn is_tool_prose(self) -> bool {
        matches!(
            self,
            FieldKind::ToolTitle
                | FieldKind::ToolDescription
                | FieldKind::ParamDescription
                | FieldKind::SchemaValue
        )
    }
}

/// One model-visible string of a server surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextField<'a> {
    pub kind: FieldKind,
    /// Logical location, e.g. `tools/add/inputSchema/properties/sidenote/description`. Name
    /// segments are cut at 128 bytes; `text` is never cut.
    pub pointer: String,
    /// The tool / prompt / resource this text belongs to (`None` for server instructions).
    pub owner: Option<&'a str>,
    pub text: &'a str,
    /// For a [`FieldKind::ParamName`]: index (in [`Collected::fields`]) of the parameter's own
    /// `description` field.
    pub param_description: Option<usize>,
}

/// Something the walk could not read in full. Reported as MW018 so it is never silent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitHit {
    pub pointer: Option<String>,
    pub reason: String,
}

/// Every model-visible string of one surface, plus what was left unread.
#[derive(Debug, Clone, Default)]
pub struct Collected<'a> {
    pub fields: Vec<TextField<'a>>,
    pub limits: Vec<LimitHit>,
}

/// A name or key as one pointer segment: cut on a char boundary at 128 bytes, then `…`.
pub fn pointer_segment(name: &str) -> Cow<'_, str> {
    if name.len() <= MAX_SEGMENT_BYTES {
        return Cow::Borrowed(name);
    }
    let cut = (0..=MAX_SEGMENT_BYTES)
        .rev()
        .find(|&i| name.is_char_boundary(i))
        .unwrap_or(0);
    Cow::Owned(format!("{}…", &name[..cut]))
}

/// `base/segment` with the segment cut; once `base` is [`MAX_POINTER_BYTES`] long it stops
/// growing.
fn join(base: &str, segment: &str) -> String {
    if base.len() >= MAX_POINTER_BYTES {
        return base.to_owned();
    }
    let segment = pointer_segment(segment);
    let mut out = String::with_capacity(base.len() + 1 + segment.len());
    out.push_str(base);
    out.push('/');
    out.push_str(&segment);
    out
}

struct Collector<'a> {
    fields: Vec<TextField<'a>>,
    limits: Vec<LimitHit>,
    full: bool,
    too_deep: bool,
}

impl<'a> Collector<'a> {
    /// Adds a field; `None` once [`MAX_TEXT_FIELDS`] is reached.
    fn push(
        &mut self,
        kind: FieldKind,
        pointer: String,
        owner: Option<&'a str>,
        text: &'a str,
    ) -> Option<usize> {
        if self.fields.len() >= MAX_TEXT_FIELDS {
            self.full = true;
            return None;
        }
        self.fields.push(TextField {
            kind,
            pointer,
            owner,
            text,
            param_description: None,
        });
        Some(self.fields.len() - 1)
    }

    /// Like [`Self::push`], but builds the pointer only when the field is kept.
    fn push_with(
        &mut self,
        kind: FieldKind,
        pointer: impl FnOnce() -> String,
        owner: Option<&'a str>,
        text: &'a str,
    ) {
        if self.fields.len() < MAX_TEXT_FIELDS {
            self.push(kind, pointer(), owner, text);
        } else {
            self.full = true;
        }
    }

    fn schema(&mut self, value: &'a Value, pointer: &str, owner: Option<&'a str>) {
        self.too_deep = false;
        self.walk(value, pointer, owner, 0);
        if self.too_deep {
            self.limits.push(LimitHit {
                pointer: Some(pointer.to_owned()),
                reason: format!(
                    "schema nests deeper than {MAX_SCHEMA_DEPTH} levels; text below that depth was not scanned"
                ),
            });
        }
    }

    fn walk(&mut self, value: &'a Value, pointer: &str, owner: Option<&'a str>, depth: usize) {
        if self.full {
            return;
        }
        if depth > MAX_SCHEMA_DEPTH {
            if is_non_empty_container(value) {
                self.too_deep = true;
            }
            return;
        }
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    match (key.as_str(), child) {
                        ("description" | "title", Value::String(s)) => self.push_with(
                            FieldKind::ParamDescription,
                            || join(pointer, key),
                            owner,
                            s,
                        ),
                        ("default" | "const", Value::String(s)) => {
                            self.push_with(FieldKind::SchemaValue, || join(pointer, key), owner, s);
                        }
                        ("properties", Value::Object(props)) => {
                            let p = join(pointer, key);
                            for (name, schema) in props {
                                let pp = join(&p, name);
                                let Some(idx) =
                                    self.push(FieldKind::ParamName, pp.clone(), owner, name)
                                else {
                                    return;
                                };
                                let first_child = self.fields.len();
                                self.walk(schema, &pp, owner, depth + 1);
                                if let Some(Value::String(d)) = schema.get("description") {
                                    let own = self.fields[first_child..].iter().position(|f| {
                                        f.kind == FieldKind::ParamDescription
                                            && std::ptr::eq(f.text, d.as_str())
                                    });
                                    self.fields[idx].param_description =
                                        own.map(|i| first_child + i);
                                }
                            }
                        }
                        ("enum" | "examples", Value::Array(items)) => {
                            let p = join(pointer, key);
                            for (i, item) in items.iter().enumerate() {
                                if let Value::String(s) = item {
                                    self.push_with(
                                        FieldKind::SchemaValue,
                                        || join(&p, &i.to_string()),
                                        owner,
                                        s,
                                    );
                                } else if is_container(item) {
                                    self.walk(item, &join(&p, &i.to_string()), owner, depth + 1);
                                }
                            }
                        }
                        _ if is_container(child) => {
                            self.walk(child, &join(pointer, key), owner, depth + 1);
                        }
                        _ => {}
                    }
                }
            }
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    if is_container(item) {
                        self.walk(item, &join(pointer, &i.to_string()), owner, depth + 1);
                    }
                }
            }
            _ => {}
        }
    }
}

fn is_container(value: &Value) -> bool {
    matches!(value, Value::Object(_) | Value::Array(_))
}

fn is_non_empty_container(value: &Value) -> bool {
    match value {
        Value::Object(m) => !m.is_empty(),
        Value::Array(a) => !a.is_empty(),
        _ => false,
    }
}

/// Every string of `surface` that ends up in the model's context, in a stable order.
///
/// Reading stops at [`MAX_TEXT_FIELDS`] fields and below [`MAX_SCHEMA_DEPTH`] schema levels;
/// both are recorded in [`Collected::limits`]. Prompt and resource titles are prose fields like
/// descriptions ([`FieldKind::PromptTitle`], [`FieldKind::ResourceTitle`]).
pub fn collect(surface: &ServerSurface) -> Collected<'_> {
    let mut c = Collector {
        fields: Vec::with_capacity(
            surface.tools.len() * 8 + surface.prompts.len() * 3 + surface.resources.len() * 3 + 1,
        ),
        limits: Vec::new(),
        full: false,
        too_deep: false,
    };
    if let Some(instr) = surface.instructions.as_deref() {
        c.push(
            FieldKind::ServerInstructions,
            "instructions".to_owned(),
            None,
            instr,
        );
    }
    for tool in &surface.tools {
        let base = join("tools", &tool.name);
        let owner = Some(tool.name.as_str());
        c.push_with(
            FieldKind::ToolName,
            || format!("{base}/name"),
            owner,
            &tool.name,
        );
        if let Some(t) = tool.title.as_deref() {
            c.push_with(FieldKind::ToolTitle, || format!("{base}/title"), owner, t);
        }
        if let Some(d) = tool.description.as_deref() {
            c.push_with(
                FieldKind::ToolDescription,
                || format!("{base}/description"),
                owner,
                d,
            );
        }
        c.schema(&tool.input_schema, &format!("{base}/inputSchema"), owner);
        if let Some(schema) = &tool.output_schema {
            c.schema(schema, &format!("{base}/outputSchema"), owner);
        }
    }
    for prompt in &surface.prompts {
        let base = join("prompts", &prompt.name);
        let owner = Some(prompt.name.as_str());
        c.push_with(
            FieldKind::PromptName,
            || format!("{base}/name"),
            owner,
            &prompt.name,
        );
        if let Some(t) = prompt.title.as_deref() {
            c.push_with(FieldKind::PromptTitle, || format!("{base}/title"), owner, t);
        }
        if let Some(d) = prompt.description.as_deref() {
            c.push_with(
                FieldKind::PromptDescription,
                || format!("{base}/description"),
                owner,
                d,
            );
        }
        for arg in &prompt.arguments {
            let abase = join(&format!("{base}/arguments"), &arg.name);
            c.push_with(
                FieldKind::PromptArgName,
                || format!("{abase}/name"),
                owner,
                &arg.name,
            );
            if let Some(d) = arg.description.as_deref() {
                c.push_with(
                    FieldKind::PromptArgDescription,
                    || format!("{abase}/description"),
                    owner,
                    d,
                );
            }
        }
    }
    for res in &surface.resources {
        let base = join("resources", &res.uri);
        let owner = Some(res.uri.as_str());
        c.push_with(
            FieldKind::ResourceUri,
            || format!("{base}/uri"),
            owner,
            &res.uri,
        );
        if !res.name.is_empty() {
            c.push_with(
                FieldKind::ResourceName,
                || format!("{base}/name"),
                owner,
                &res.name,
            );
        }
        if let Some(t) = res.title.as_deref() {
            c.push_with(
                FieldKind::ResourceTitle,
                || format!("{base}/title"),
                owner,
                t,
            );
        }
        if let Some(d) = res.description.as_deref() {
            c.push_with(
                FieldKind::ResourceDescription,
                || format!("{base}/description"),
                owner,
                d,
            );
        }
    }
    if c.full {
        c.limits.push(LimitHit {
            pointer: None,
            reason: format!(
                "surface has more than {MAX_TEXT_FIELDS} text fields; the rest was not scanned"
            ),
        });
    }
    Collected {
        fields: c.fields,
        limits: c.limits,
    }
}

/// Characters that render as nothing or reorder text: zero-width, bidi controls, BOM, the
/// braille blank, interlinear annotation and object-replacement marks, Unicode tag characters
/// (U+E0000..U+E007F) and variation selectors.
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
        | '\u{2800}'
        | '\u{3164}'
        | '\u{FE00}'..='\u{FE0F}'
        | '\u{FEFF}'
        | '\u{FFA0}'
        | '\u{FFF9}'..='\u{FFFC}'
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
        let pointers: Vec<_> = collect(&surface)
            .fields
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

    fn nested(levels: usize, leaf: Value) -> Value {
        (0..levels).fold(leaf, |inner, _| json!({"items": inner}))
    }

    fn tool_with_schema(schema: Value) -> ServerSurface {
        ServerSurface {
            server: "s".into(),
            tools: vec![Tool {
                name: "t".into(),
                input_schema: schema,
                ..Tool::default()
            }],
            ..ServerSurface::default()
        }
    }

    #[test]
    fn schema_text_is_read_to_depth_64_and_deeper_is_reported() {
        let leaf = || json!({"description": "hidden instruction"});
        let surface = tool_with_schema(nested(40, leaf()));
        let c = collect(&surface);
        assert!(c.fields.iter().any(|f| f.text == "hidden instruction"));
        assert_eq!(c.limits, Vec::new());

        let surface = tool_with_schema(nested(70, leaf()));
        let c = collect(&surface);
        assert!(!c.fields.iter().any(|f| f.text == "hidden instruction"));
        assert_eq!(c.limits.len(), 1, "{:?}", c.limits);
        assert_eq!(c.limits[0].pointer.as_deref(), Some("tools/t/inputSchema"));
    }

    #[test]
    fn pointer_segments_are_cut_but_texts_are_not() {
        let key = format!("k{}é", "x".repeat(300));
        let surface = tool_with_schema(json!({"properties": {key.clone(): {"description": "d"}}}));
        let c = collect(&surface);
        let name = c
            .fields
            .iter()
            .find(|f| f.kind == FieldKind::ParamName)
            .unwrap();
        assert_eq!(name.text, key);
        assert!(name.pointer.len() < 200, "{}", name.pointer.len());
        assert!(name.pointer.contains('…'));
        assert_eq!(pointer_segment(&"é".repeat(100)).chars().count(), 65);
        assert_eq!(pointer_segment("short"), "short");
    }

    #[test]
    fn long_nested_pointers_stay_bounded() {
        let key = "k".repeat(200);
        let mut schema = json!({"description": "leaf"});
        for _ in 0..60 {
            schema = json!({key.clone(): schema});
        }
        let surface = tool_with_schema(schema);
        let c = collect(&surface);
        let leaf = c.fields.iter().find(|f| f.text == "leaf").unwrap();
        assert!(leaf.pointer.len() < 1024, "{}", leaf.pointer.len());
    }

    #[test]
    fn field_count_is_capped_and_reported() {
        let props: serde_json::Map<String, Value> = (0..=MAX_TEXT_FIELDS)
            .map(|i| (format!("p{i}"), json!({})))
            .collect();
        let surface = tool_with_schema(json!({"properties": props}));
        let c = collect(&surface);
        assert_eq!(c.fields.len(), MAX_TEXT_FIELDS);
        assert_eq!(c.limits.len(), 1);
        assert!(c.limits[0].reason.contains("100000"));
    }

    #[test]
    fn prompt_and_resource_titles_are_enumerated() {
        let surface = ServerSurface {
            prompts: vec![Prompt {
                name: "p".into(),
                title: Some("<IMPORTANT>x</IMPORTANT>".into()),
                ..Prompt::default()
            }],
            resources: vec![crate::model::Resource {
                uri: "file:///a".into(),
                title: Some("res title".into()),
                ..crate::model::Resource::default()
            }],
            ..ServerSurface::default()
        };
        let c = collect(&surface);
        let titles: Vec<_> = c
            .fields
            .iter()
            .filter(|f| matches!(f.kind, FieldKind::PromptTitle | FieldKind::ResourceTitle))
            .map(|f| (f.pointer.as_str(), f.text))
            .collect();
        assert_eq!(
            titles,
            [
                ("prompts/p/title", "<IMPORTANT>x</IMPORTANT>"),
                ("resources/file:///a/title", "res title")
            ]
        );
    }

    #[test]
    fn param_description_link_points_at_own_description() {
        let surface = tool_with_schema(
            json!({"properties": {"a": {"description": "da"}, "b": {"type": "string"}}}),
        );
        let c = collect(&surface);
        let link = |name: &str| {
            c.fields
                .iter()
                .find(|f| f.kind == FieldKind::ParamName && f.text == name)
                .and_then(|f| f.param_description)
                .map(|i| c.fields[i].text)
        };
        assert_eq!(link("a"), Some("da"));
        assert_eq!(link("b"), None);
    }

    #[test]
    fn braille_blank_and_object_marks_are_invisible() {
        for c in ['\u{2800}', '\u{FFF9}', '\u{FFFA}', '\u{FFFB}', '\u{FFFC}'] {
            assert!(is_invisible(c), "{c:?}");
        }
        assert!(!is_invisible('\u{2801}'));
    }
}
