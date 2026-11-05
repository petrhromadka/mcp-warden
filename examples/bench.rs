//! Throughput benchmark for the surface rules.
//!
//! Usage: `cargo run --release --example bench -- [servers] [tools_per_server]`
//! (defaults: 1000 servers x 50 tools). Generates deterministic synthetic servers with
//! realistic descriptions and schemas, runs `check_surfaces` once and prints tools/second.

use std::time::Instant;

use mcp_warden::model::{ServerSurface, Tool};
use mcp_warden::rules::check_surfaces;
use serde_json::{Value, json};

const VERBS: [&str; 12] = [
    "list",
    "get",
    "create",
    "update",
    "delete",
    "search",
    "export",
    "import",
    "sync",
    "validate",
    "summarize",
    "archive",
];
const NOUNS: [&str; 12] = [
    "issue",
    "branch",
    "invoice",
    "customer",
    "document",
    "channel",
    "record",
    "report",
    "session",
    "deployment",
    "dashboard",
    "ticket",
];
const SENTENCES: [&str; 8] = [
    "Returns the results as JSON, sorted by creation time with the newest entries first.",
    "Supports pagination through the `cursor` parameter; the default page size is 50.",
    "Only items the current user has access to are included in the response.",
    "Use this tool when you need to inspect the current state before making changes.",
    "Dates are interpreted as UTC unless an explicit offset is given, for example 2025-01-31T12:00:00+01:00.",
    "See https://docs.example.com/api for the full field reference.",
    "IMPORTANT: always use absolute paths and never pass credentials as arguments.",
    "The operation is idempotent; repeating it with the same arguments has no further effect.",
];
const PARAMS: [(&str, &str, &str); 8] = [
    ("id", "string", "Unique identifier of the item"),
    ("query", "string", "Free-text search query"),
    ("limit", "integer", "Maximum number of results to return"),
    (
        "cursor",
        "string",
        "Pagination cursor from a previous response",
    ),
    (
        "include_archived",
        "boolean",
        "Whether archived items are included",
    ),
    ("sort", "string", "Sort order of the results"),
    (
        "path",
        "string",
        "Absolute path of the target file or directory",
    ),
    ("format", "string", "Output format"),
];

/// Small deterministic generator (`SplitMix64`) so runs are comparable without extra dependencies.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn pick(&mut self, len: usize) -> usize {
        usize::try_from(self.next() % len as u64).expect("index fits usize")
    }
}

fn schema(rng: &mut Rng) -> Value {
    let mut properties = serde_json::Map::new();
    for _ in 0..3 + rng.pick(4) {
        let (name, typ, desc) = PARAMS[rng.pick(PARAMS.len())];
        let mut prop = json!({ "type": typ, "description": desc });
        if name == "sort" {
            prop["enum"] = json!(["asc", "desc", "relevance"]);
            prop["default"] = json!("relevance");
        }
        properties.insert(name.to_owned(), prop);
    }
    json!({ "type": "object", "properties": properties, "required": [] })
}

fn tool(rng: &mut Rng, server: usize, index: usize) -> Tool {
    let verb = VERBS[rng.pick(VERBS.len())];
    let noun = NOUNS[rng.pick(NOUNS.len())];
    let mut description = format!(
        "{} {noun} entries of the connected service.",
        capitalize(verb)
    );
    for _ in 0..2 + rng.pick(4) {
        description.push(' ');
        description.push_str(SENTENCES[rng.pick(SENTENCES.len())]);
    }
    Tool {
        // Unique names: name collisions across servers are a finding of their own.
        name: format!("{verb}_{noun}_{server}_{index}"),
        description: Some(description),
        input_schema: schema(rng),
        ..Tool::default()
    }
}

fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

fn parse_arg(index: usize, default: usize) -> usize {
    std::env::args().nth(index).map_or(default, |a| {
        a.parse()
            .unwrap_or_else(|_| panic!("argument {index} must be a positive integer, got {a:?}"))
    })
}

#[allow(clippy::cast_precision_loss)] // counts and durations are far below 2^52
fn main() {
    let servers = parse_arg(1, 1000);
    let per_server = parse_arg(2, 50);
    let mut rng = Rng(42);
    let surfaces: Vec<ServerSurface> = (0..servers)
        .map(|s| ServerSurface {
            server: format!("server-{s}"),
            tools: (0..per_server).map(|i| tool(&mut rng, s, i)).collect(),
            ..ServerSurface::default()
        })
        .collect();

    let total_tools = servers * per_server;
    let start = Instant::now();
    let findings = check_surfaces(&surfaces);
    let elapsed = start.elapsed();

    println!(
        "{servers} servers x {per_server} tools = {total_tools} tools, {} findings",
        findings.len()
    );
    println!(
        "check_surfaces: {:.3} s, {:.0} tools/second",
        elapsed.as_secs_f64(),
        total_tools as f64 / elapsed.as_secs_f64().max(f64::MIN_POSITIVE)
    );
}
