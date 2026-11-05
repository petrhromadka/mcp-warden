//! Risky client configuration of MCP servers (MW100-MW119).
//!
//! These rules read how a client launches or reaches a server: literal secrets, unpinned
//! package launches, download-and-run shells, plain-HTTP transport, credentials in URLs,
//! over-privileged containers and whole-disk filesystem grants. Nothing here runs a server.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use regex::Regex;

use crate::model::{Finding, Location, RuleInfo, ServerConfig, Severity, Transport};
use crate::text::snippet;

const EVIDENCE_MAX: usize = 120;

pub const RULES: &[RuleInfo] = &[
    RuleInfo {
        id: "MW100",
        name: "secret-in-config",
        severity: Severity::High,
        summary: "A literal secret is stored in the server entry (env, header, argument or URL).",
        help: "Anyone who can read the config file, its backups or a synced copy can use the secret, \
               and the file is easily committed to a repository by accident. Replace the literal \
               with an environment variable reference (for example ${GITHUB_TOKEN}), a secret \
               manager, or the client's input prompts (for example ${input:token}), and rotate the \
               exposed value.",
    },
    RuleInfo {
        id: "MW101",
        name: "unpinned-package",
        severity: Severity::Medium,
        summary: "The server is fetched and run at launch without a pinned version.",
        help: "Every start downloads whatever is currently published under that name or tag, so a \
               hijacked account or a malicious update runs on your machine with your privileges \
               (a rug pull). Pin an exact version (pkg@1.2.3, pkg==1.2.3) or an image digest \
               (image@sha256:...), and update it deliberately.",
    },
    RuleInfo {
        id: "MW102",
        name: "remote-code-pipe",
        severity: Severity::Critical,
        summary: "A shell command downloads a script and executes it.",
        help: "Whatever the remote host serves at launch time runs unreviewed, and a compromised or \
               changed download means remote code execution. Install the server from a pinned \
               package or a reviewed local file and start it directly.",
    },
    RuleInfo {
        id: "MW103",
        name: "insecure-transport",
        severity: Severity::High,
        summary: "The server is reached over plain http:// on a non-loopback host.",
        help: "Traffic, including tool calls, results and credentials in headers, can be read and \
               modified by anyone on the network path. Use https://, or keep plain HTTP to \
               localhost only.",
    },
    RuleInfo {
        id: "MW104",
        name: "credential-in-url",
        severity: Severity::High,
        summary: "A URL carries a password or a literal token in its user info or query string.",
        help: "URLs end up in logs, proxies, shell history and error messages. Send credentials in \
               an Authorization header taken from an environment variable or input prompt instead \
               of embedding them in the URL, and rotate the exposed value.",
    },
    RuleInfo {
        id: "MW105",
        name: "privileged-container",
        severity: Severity::High,
        summary: "A docker/podman run gives the container broad access to the host.",
        help: "Privileged mode, host namespaces, dangerous capabilities and mounts of the host \
               root, /etc, the home directory or the container runtime socket let a compromised or \
               malicious server take over the host. Drop the flags and mount only the specific \
               project directory the server needs.",
    },
    RuleInfo {
        id: "MW106",
        name: "broad-filesystem-access",
        severity: Severity::Medium,
        summary: "A filesystem server is given the whole disk or the whole home directory.",
        help: "A tool-poisoned or confused model can then read or overwrite SSH keys, browser \
               profiles and other secrets. Grant only the project directories the server needs.",
    },
    RuleInfo {
        id: "MW107",
        name: "shell-wrapper",
        severity: Severity::Low,
        summary: "The server command is a shell running an inline script.",
        help: "The real command is hidden inside a script string, which makes review and \
               allow-listing harder and invites injection. Call the server executable directly \
               with its arguments.",
    },
];

// ---------------------------------------------------------------------------------------------
// Regexes and tables
// ---------------------------------------------------------------------------------------------

static KNOWN_SECRETS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    [
        ("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
        ("OpenAI API key", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
        (
            "GitHub token",
            r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,})",
        ),
        ("AWS access key ID", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        ("Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
        ("Stripe live key", r"\b[sr]k_live_[A-Za-z0-9]{16,}"),
        ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}"),
        ("GitLab token", r"\bglpat-[A-Za-z0-9_-]{20,}"),
        ("npm token", r"\bnpm_[A-Za-z0-9]{30,}"),
        ("Hugging Face token", r"\bhf_[A-Za-z0-9]{30,}"),
        (
            "JSON Web Token",
            r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*",
        ),
        ("private key", r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*"),
    ]
    .into_iter()
    .map(|(label, pat)| (label, Regex::new(pat).expect("valid secret regex")))
    .collect()
});

/// `Bearer <token>` / `Basic <credentials>`; group 1 is the scheme, group 2 the credential.
static AUTH_SCHEME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\b(bearer|basic)\s+([^\s"']+)"#).expect("valid regex"));

static URL_IN_TEXT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"[A-Za-z][A-Za-z0-9+.-]*://[^\s'"<>)]+"#).expect("valid regex"));

static ENV_REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\$[A-Za-z_][A-Za-z0-9_]*$|%[A-Za-z_][A-Za-z0-9_]*%").expect("valid regex")
});

static EXACT_SEMVER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$").expect("valid regex")
});

static POSIX_INLINE_FLAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^-[A-Za-z]*c[A-Za-z]*$").expect("valid regex"));

static HOME_DIR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(?:/(?:home|users)/[^/\\]+|[a-z]:[\\/]users[\\/][^\\/]+)$")
        .expect("valid regex")
});

static HOME_PARENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(?:/(?:home|users)|[a-z]:[\\/]users)$").expect("valid regex")
});

static WHOLE_DRIVE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z]:$").expect("valid regex"));

static DOWNLOAD_AND_RUN: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // curl/wget ... | sh
        r"(?i)\b(?:curl|wget)\b[^\n]*?\|\s*(?:sudo\s+)?(?:\S*/)?(?:ba|z|da|k)?sh\b",
        r"(?i)\b(?:curl|wget)\b[^\n]*?\|\s*(?:sudo\s+)?(?:\S*/)?(?:python[0-9.]*|perl|ruby|node)\b",
        // iwr ... | iex
        r"(?i)\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl|wget)\b[^\n]*\|\s*(?:iex|invoke-expression)\b",
        // iex (iwr ...), Invoke-Expression ((New-Object Net.WebClient).DownloadString(...))
        r"(?i)\b(?:iex|invoke-expression)\b[^\n]*\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring)\b",
        // bash <(curl ...), source <(curl ...)
        r"(?i)\b(?:(?:ba|z|da|k)?sh|source)\s+<\(\s*(?:curl|wget)\b",
        // eval "$(curl ...)", sh -c "$(curl ...)"
        r#"(?i)\b(?:eval|(?:ba|z|da|k)?sh\s+-c)\s+["']?\$\(\s*(?:curl|wget)\b"#,
    ]
    .into_iter()
    .map(|p| Regex::new(p).expect("valid regex"))
    .collect()
});

const SECRET_NAME_KEYWORDS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "API_KEY",
    "APIKEY",
    "ACCESS_KEY",
    "PRIVATE_KEY",
    "CLIENT_SECRET",
    "CREDENTIAL",
];

/// Names that look secret but name a location or an identifier, not the secret itself.
const NON_SECRET_SUFFIXES: &[&str] = &[
    "_FILE",
    "_PATH",
    "_DIR",
    "_URL",
    "_URI",
    "_ENDPOINT",
    "_ID",
    "_NAME",
    "_TYPE",
];

const SENSITIVE_QUERY_PARAMS: &[&str] = &[
    "token",
    "key",
    "api_key",
    "apikey",
    "access_token",
    "secret",
    "password",
    "auth",
    "sig",
    "signature",
];

const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ash",
    "ksh",
    "fish",
    "cmd",
    "powershell",
    "pwsh",
];

const JS_VALUE_FLAGS: &[&str] = &[
    "-p",
    "--package",
    "--registry",
    "--cache",
    "--userconfig",
    "-c",
    "--call",
    "--prefix",
    "--loglevel",
];

const UV_VALUE_FLAGS: &[&str] = &[
    "--from",
    "--with",
    "-w",
    "--with-requirements",
    "--python",
    "-p",
    "--index",
    "--index-url",
    "-i",
    "--extra-index-url",
    "--default-index",
    "--env-file",
    "--directory",
    "--project",
    "--config-file",
    "--constraints",
    "-c",
    "--overrides",
    "--cache-dir",
];

const PIPX_VALUE_FLAGS: &[&str] = &["--spec", "--python", "--index-url", "-i", "--pip-args"];

/// Top-level docker/podman flags that take a separate value (before the subcommand).
const CONTAINER_TOP_FLAGS: &[&str] = &["--context", "-H", "--host", "--config", "--log-level"];

/// `docker run` flags that take a separate value.
const RUN_VALUE_FLAGS: &[&str] = &[
    "-e",
    "--env",
    "-v",
    "--volume",
    "-p",
    "--publish",
    "--name",
    "--network",
    "--net",
    "--user",
    "-u",
    "--workdir",
    "-w",
    "--entrypoint",
    "--mount",
    "-l",
    "--label",
    "--env-file",
    "--add-host",
    "--cap-add",
    "--cap-drop",
    "--device",
    "-m",
    "--memory",
    "--cpus",
    "--pid",
    "--platform",
    "--restart",
    "--security-opt",
    "--tmpfs",
    "-h",
    "--hostname",
    "--ipc",
    "--dns",
    "--group-add",
    "--log-driver",
    "--log-opt",
    "--pull",
    "--shm-size",
    "--ulimit",
    "--userns",
    "--volumes-from",
    "--cidfile",
    "--expose",
    "--label-file",
    "--runtime",
    "--stop-signal",
    "--sysctl",
    "--uts",
    "--gpus",
    "--link",
    "-a",
    "--attach",
    "--cgroupns",
    "--ip",
    "--mac-address",
    "--pids-limit",
    "--cpuset-cpus",
    "--cpu-shares",
    "--memory-swap",
    "--health-cmd",
];

// ---------------------------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------------------------

pub fn check(configs: &[ServerConfig]) -> Vec<Finding> {
    let mut out = Vec::new();
    for cfg in configs {
        check_secrets(cfg, &mut out);
        if cfg.disabled {
            continue;
        }
        match &cfg.transport {
            Transport::Stdio {
                command, args, env, ..
            } => {
                check_stdio(cfg, command, args, &mut out);
                for (key, value) in env {
                    check_url_credentials(cfg, &format!("/env/{}", escape(key)), value, &mut out);
                }
                for (idx, arg) in args.iter().enumerate() {
                    check_url_credentials(cfg, &format!("/args/{idx}"), arg, &mut out);
                }
            }
            Transport::Http { url, .. } => {
                check_insecure_transport(cfg, url, &mut out);
                check_url_credentials(cfg, "/url", url, &mut out);
            }
        }
    }
    out
}

fn finding(
    cfg: &ServerConfig,
    rule_id: &'static str,
    suffix: &str,
    message: String,
    evidence: &str,
) -> Finding {
    let severity = RULES
        .iter()
        .find(|r| r.id == rule_id)
        .map_or(Severity::Info, |r| r.severity);
    Finding {
        rule_id,
        severity,
        server: cfg.name.clone(),
        message,
        evidence: snippet(evidence, EVIDENCE_MAX),
        location: Location {
            file: Some(cfg.source.clone()),
            pointer: Some(format!("{}{suffix}", cfg.pointer)),
        },
    }
}

/// Escape one JSON pointer reference token.
fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

// ---------------------------------------------------------------------------------------------
// Value classification helpers
// ---------------------------------------------------------------------------------------------

/// A reference to a value that lives elsewhere: `${VAR}`, `${env:VAR}`, `${input:x}`, `$VAR`,
/// `%VAR%`, `{{...}}`, `$(...)`.
fn is_reference(value: &str) -> bool {
    value.contains("${")
        || value.contains("{{")
        || value.contains("$(")
        || ENV_REFERENCE.is_match(value.trim())
}

/// Obvious stand-ins that are not real secrets.
fn is_placeholder(value: &str) -> bool {
    let t = value.trim();
    let lower = t.to_ascii_lowercase();
    t.is_empty()
        || (t.starts_with('<') && t.ends_with('>'))
        || (t.starts_with('[') && t.ends_with(']'))
        || t.chars()
            .all(|c| matches!(c, '.' | '*' | 'x' | 'X' | '-' | '_'))
        || lower.starts_with("xxx")
        || [
            "your",
            "changeme",
            "change-me",
            "change_me",
            "replace",
            "placeholder",
            "example",
            "redacted",
            "dummy",
            "insert",
            "todo",
        ]
        .iter()
        .any(|p| lower.contains(p))
}

fn is_placeholder_token(matched: &str) -> bool {
    let lower = matched.to_ascii_lowercase();
    ["xxxx", "****", "...", "example"]
        .iter()
        .any(|p| lower.contains(p))
}

/// Label of the first known secret format found in `text`.
fn known_secret(text: &str) -> Option<&'static str> {
    KNOWN_SECRETS.iter().find_map(|(label, re)| {
        re.find_iter(text)
            .any(|m| !is_placeholder_token(m.as_str()))
            .then_some(*label)
    })
}

fn is_secret_name(name: &str) -> bool {
    let norm: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    SECRET_NAME_KEYWORDS.iter().any(|k| norm.contains(k))
        && !NON_SECRET_SUFFIXES.iter().any(|s| norm.ends_with(s))
}

/// A value stored under a secret-looking name that is plausibly a real literal secret.
fn is_literal_secret(value: &str) -> bool {
    let v = value.trim();
    v.chars().count() >= 8
        && !is_reference(v)
        && !is_placeholder(v)
        && !v.starts_with(['/', '~', '.'])
        && !v.contains(":\\")
        && !v.starts_with("http://")
        && !v.starts_with("https://")
}

/// Replace every known secret, URL credential and bearer credential in `text` with `***`.
fn redact_text(text: &str) -> String {
    let mut s = URL_IN_TEXT
        .replace_all(text, |c: &regex::Captures| redact_url(&c[0]))
        .into_owned();
    for (_, re) in KNOWN_SECRETS.iter() {
        s = re.replace_all(&s, "***").into_owned();
    }
    AUTH_SCHEME.replace_all(&s, "$1 ***").into_owned()
}

// ---------------------------------------------------------------------------------------------
// MW100 secret-in-config
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    Env,
    Header,
    Arg,
    Url,
}

/// Returns the secret kind and the value with the secret redacted.
fn detect(name: Option<&str>, value: &str, source: Source) -> Option<(&'static str, String)> {
    if let Some(label) = known_secret(value) {
        return Some((label, redact_text(value)));
    }
    let may_carry_auth = source == Source::Header
        || (source == Source::Arg && value.to_ascii_lowercase().contains("authorization"));
    if may_carry_auth && let Some(c) = AUTH_SCHEME.captures(value) {
        let credential = &c[2];
        if credential.chars().count() >= 8
            && !is_reference(credential)
            && !is_placeholder(credential)
        {
            let label = if c[1].eq_ignore_ascii_case("bearer") {
                "literal bearer token"
            } else {
                "literal basic-auth credential"
            };
            return Some((label, AUTH_SCHEME.replace_all(value, "$1 ***").into_owned()));
        }
    }
    let name = name?;
    (source != Source::Url && is_secret_name(name) && is_literal_secret(value))
        .then(|| ("literal value of a secret-named setting", "***".to_string()))
}

fn check_secrets(cfg: &ServerConfig, out: &mut Vec<Finding>) {
    let mut report = |suffix: String, what: String, label: &str, evidence: String| {
        out.push(finding(
            cfg,
            "MW100",
            &suffix,
            format!(
                "{what} holds a literal secret ({label}). Anyone who can read this file can use \
                 it; reference an environment variable or secret store instead."
            ),
            &format!("{evidence} ({label})"),
        ));
    };
    match &cfg.transport {
        Transport::Stdio { args, env, .. } => {
            for (key, value) in env {
                if let Some((label, red)) = detect(Some(key), value, Source::Env) {
                    report(
                        format!("/env/{}", escape(key)),
                        format!("Environment variable `{key}`"),
                        label,
                        format!("{key}={red}"),
                    );
                }
            }
            let mut prev_flag: Option<&str> = None;
            for (idx, arg) in args.iter().enumerate() {
                let found = if let Some((label, red)) = detect(None, arg, Source::Arg) {
                    Some((label, red))
                } else if let Some((k, v)) = arg.split_once('=')
                    && k.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
                {
                    detect(Some(k.trim_start_matches('-')), v, Source::Arg)
                        .map(|(label, red)| (label, format!("{k}={red}")))
                } else if let Some(flag) = prev_flag
                    && !arg.starts_with('-')
                {
                    detect(Some(flag.trim_start_matches('-')), arg, Source::Arg)
                        .map(|(label, red)| (label, format!("{flag} {red}")))
                } else {
                    None
                };
                if let Some((label, evidence)) = found {
                    report(
                        format!("/args/{idx}"),
                        format!("Argument {idx}"),
                        label,
                        evidence,
                    );
                }
                prev_flag = (arg.starts_with('-') && !arg.contains('=')).then_some(arg.as_str());
            }
        }
        Transport::Http { url, headers } => {
            if let Some((label, red)) = detect(None, url, Source::Url) {
                report("/url".to_string(), "The URL".to_string(), label, red);
            }
            for (name, value) in headers {
                if let Some((label, red)) = detect(Some(name), value, Source::Header) {
                    report(
                        format!("/headers/{}", escape(name)),
                        format!("Header `{name}`"),
                        label,
                        format!("{name}: {red}"),
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// URL parsing (MW103, MW104)
// ---------------------------------------------------------------------------------------------

struct Url<'a> {
    scheme: &'a str,
    userinfo: Option<&'a str>,
    hostport: &'a str,
    path: &'a str,
    query: Option<&'a str>,
    fragment: Option<&'a str>,
}

impl Url<'_> {
    fn host(&self) -> &str {
        if let Some(rest) = self.hostport.strip_prefix('[') {
            rest.split(']').next().unwrap_or(rest)
        } else {
            self.hostport.split(':').next().unwrap_or(self.hostport)
        }
    }

    fn is_loopback(&self) -> bool {
        let host = self.host().to_ascii_lowercase();
        host == "localhost"
            || host.ends_with(".localhost")
            || host.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_loopback())
            || host.parse::<Ipv6Addr>().is_ok_and(|ip| ip.is_loopback())
    }
}

fn parse_url(url: &str) -> Option<Url<'_>> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))
    {
        return None;
    }
    let (rest, fragment) = rest
        .split_once('#')
        .map_or((rest, None), |(r, f)| (r, Some(f)));
    let (rest, query) = rest
        .split_once('?')
        .map_or((rest, None), |(r, q)| (r, Some(q)));
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let (userinfo, hostport) = authority
        .rsplit_once('@')
        .map_or((None, authority), |(u, h)| (Some(u), h));
    Some(Url {
        scheme,
        userinfo,
        hostport,
        path,
        query,
        fragment,
    })
}

fn is_sensitive_param(name: &str) -> bool {
    let norm = name.to_ascii_lowercase().replace('-', "_");
    SENSITIVE_QUERY_PARAMS.contains(&norm.as_str())
}

/// The URL with user info and the values of sensitive query parameters replaced by `***`.
fn redact_url(url: &str) -> String {
    let Some(u) = parse_url(url) else {
        return url.to_string();
    };
    let mut s = format!("{}://", u.scheme);
    if u.userinfo.is_some() {
        s.push_str("***@");
    }
    s.push_str(u.hostport);
    s.push_str(u.path);
    if let Some(q) = u.query {
        let params: Vec<String> = q
            .split('&')
            .map(|p| match p.split_once('=') {
                Some((k, _)) if is_sensitive_param(k) => format!("{k}=***"),
                _ => p.to_string(),
            })
            .collect();
        s.push('?');
        s.push_str(&params.join("&"));
    }
    if let Some(f) = u.fragment {
        s.push('#');
        s.push_str(f);
    }
    s
}

fn check_insecure_transport(cfg: &ServerConfig, url: &str, out: &mut Vec<Finding>) {
    let Some(u) = parse_url(url) else { return };
    let host = u.host();
    if !u.scheme.eq_ignore_ascii_case("http")
        || host.is_empty()
        || host.contains(['$', '{', '%'])
        || u.is_loopback()
    {
        return;
    }
    out.push(finding(
        cfg,
        "MW103",
        "/url",
        format!(
            "The server is reached over plain HTTP at host `{host}`; traffic and any credentials \
             can be read or modified on the network. Use https://."
        ),
        &redact_text(url),
    ));
}

// ---------------------------------------------------------------------------------------------
// MW104 credential-in-url
// ---------------------------------------------------------------------------------------------

fn is_literal_param(value: &str) -> bool {
    !value.is_empty() && !is_reference(value) && !is_placeholder(value)
}

fn url_credential_issues(url: &str) -> Vec<String> {
    let Some(u) = parse_url(url) else {
        return Vec::new();
    };
    let mut issues = Vec::new();
    if let Some((_, password)) = u.userinfo.and_then(|ui| ui.split_once(':'))
        && is_literal_param(password)
    {
        issues.push("a password in the user info".to_string());
    }
    for pair in u.query.unwrap_or_default().split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && is_sensitive_param(k)
            && is_literal_param(v)
        {
            issues.push(format!("a literal value in query parameter `{k}`"));
        }
    }
    issues
}

/// Check every URL embedded in `text` (an http URL, an argument or an env value).
fn check_url_credentials(cfg: &ServerConfig, suffix: &str, text: &str, out: &mut Vec<Finding>) {
    let issues: Vec<String> = URL_IN_TEXT
        .find_iter(text)
        .flat_map(|m| url_credential_issues(m.as_str()))
        .collect();
    if issues.is_empty() {
        return;
    }
    out.push(finding(
        cfg,
        "MW104",
        suffix,
        format!(
            "The URL contains {}. URLs end up in logs, proxies and shell history; send \
             credentials in a header taken from an environment variable or input prompt.",
            issues.join(" and ")
        ),
        &redact_text(text),
    ));
}

// ---------------------------------------------------------------------------------------------
// Launch parsing shared by MW101, MW105, MW106
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
struct Arg {
    /// Index of the original `args` entry (several tokens of a `cmd /c "..."` string share one).
    idx: usize,
    text: String,
}

struct Launch {
    prog: String,
    args: Vec<Arg>,
}

/// Lowercase executable name without directory and `.exe`/`.cmd`/`.bat`/`.ps1`.
fn prog_name(command: &str) -> String {
    let base = command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(command)
        .to_ascii_lowercase();
    for ext in [".exe", ".cmd", ".bat", ".ps1"] {
        if let Some(stem) = base.strip_suffix(ext) {
            return stem.to_string();
        }
    }
    base
}

/// The program that really runs: `cmd /c npx -y pkg` becomes `npx` with `-y pkg`.
fn launch(command: &str, args: &[String]) -> Launch {
    let mut prog = prog_name(command);
    let mut list: Vec<Arg> = args
        .iter()
        .enumerate()
        .map(|(idx, text)| Arg {
            idx,
            text: text.clone(),
        })
        .collect();
    if prog == "cmd"
        && let Some(p) = list
            .iter()
            .position(|a| a.text.eq_ignore_ascii_case("/c") || a.text.eq_ignore_ascii_case("/k"))
    {
        let rest = &list[p + 1..];
        let inner: Vec<Arg> = if let [only] = rest {
            only.text
                .trim_matches('"')
                .split_whitespace()
                .map(|t| Arg {
                    idx: only.idx,
                    text: t.to_string(),
                })
                .collect()
        } else {
            rest.to_vec()
        };
        if let Some((first, tail)) = inner.split_first() {
            prog = prog_name(&first.text);
            list = tail.to_vec();
        }
    }
    Launch { prog, args: list }
}

#[derive(Default)]
struct Scan {
    /// Position in the scanned slice of the first non-flag argument.
    positional: Option<usize>,
    /// Value of the first `from_flags` flag (`--from pkg`, `-p pkg`).
    from: Option<(usize, String)>,
    /// `-y` / `--yes` seen before the positional.
    yes: bool,
}

/// Walk leading flags (skipping the values of `value_flags`) up to the first positional.
fn scan(args: &[Arg], value_flags: &[&str], from_flags: &[&str]) -> Scan {
    let mut s = Scan::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].text.as_str();
        if a == "--" {
            s.positional = (i + 1 < args.len()).then_some(i + 1);
            break;
        }
        if !a.starts_with('-') || a == "-" {
            s.positional = Some(i);
            break;
        }
        let (name, inline) = a.split_once('=').map_or((a, None), |(n, v)| (n, Some(v)));
        if name == "-y" || name == "--yes" {
            s.yes = true;
        }
        if from_flags.contains(&name) && s.from.is_none() {
            if let Some(v) = inline {
                s.from = Some((args[i].idx, v.to_string()));
            } else if let Some(next) = args.get(i + 1) {
                s.from = Some((next.idx, next.text.clone()));
            }
        }
        i += if inline.is_none() && value_flags.contains(&name) {
            2
        } else {
            1
        };
    }
    s
}

/// The arguments after the first positional if it is one of `names` (a subcommand).
fn after_sub<'a>(args: &'a [Arg], value_flags: &[&str], names: &[&str]) -> Option<&'a [Arg]> {
    let pos = scan(args, value_flags, &[]).positional?;
    names
        .contains(&args[pos].text.as_str())
        .then(|| &args[pos + 1..])
}

fn is_local_spec(spec: &str) -> bool {
    spec.starts_with(['.', '/', '~'])
        || spec.starts_with("file:")
        || spec.as_bytes().get(1) == Some(&b':')
}

// ---------------------------------------------------------------------------------------------
// MW101 unpinned-package
// ---------------------------------------------------------------------------------------------

struct Unpinned {
    tool: &'static str,
    spec: String,
    reason: String,
    idx: usize,
    yes: bool,
}

fn npm_unpinned(spec: &str) -> Option<String> {
    if is_reference(spec) || is_local_spec(spec) {
        return None;
    }
    if ["git+", "github:", "git:"]
        .iter()
        .any(|p| spec.starts_with(p))
    {
        return (!spec.contains('#')).then(|| "a git source without a commit or tag".to_string());
    }
    if spec.contains("://") {
        return None;
    }
    match spec.rfind('@').filter(|&i| i > 0) {
        None => Some("no version given".to_string()),
        Some(i) => {
            let version = &spec[i + 1..];
            (!EXACT_SEMVER.is_match(version))
                .then(|| format!("`{version}` is a tag or range, not an exact version"))
        }
    }
}

fn python_unpinned(spec: &str) -> Option<String> {
    if is_reference(spec) || is_local_spec(spec) || spec.to_ascii_lowercase().ends_with(".py") {
        return None;
    }
    if let Some((_, after_scheme)) = spec.split_once("://") {
        if !spec.starts_with("git+") {
            return None;
        }
        let git_ref = after_scheme
            .find('/')
            .and_then(|i| after_scheme[i..].rsplit_once('@'))
            .map(|(_, r)| r);
        return match git_ref {
            Some(r) if !matches!(r, "main" | "master" | "HEAD" | "develop" | "latest") => None,
            _ => Some("a git source without a commit or tag".to_string()),
        };
    }
    if let Some((_, v)) = spec.split_once("==") {
        return v
            .contains('*')
            .then(|| "a wildcard version, not an exact one".to_string());
    }
    if let Some((_, v)) = spec.rsplit_once('@') {
        return (!v.starts_with(|c: char| c.is_ascii_digit()))
            .then(|| format!("`{v}` is not an exact version"));
    }
    Some(if spec.contains(['<', '>', '~', '!']) {
        "a version range, not an exact version".to_string()
    } else {
        "no version given".to_string()
    })
}

fn image_unpinned(image: &str) -> Option<String> {
    if is_reference(image) || image.contains("@sha256:") {
        return None;
    }
    let last = image.rsplit('/').next().unwrap_or(image);
    match last.split_once(':').map(|(_, tag)| tag) {
        None => Some("no tag, so it resolves to `latest`".to_string()),
        Some("latest") => Some("the tag `latest` moves with every release".to_string()),
        Some(_) => None,
    }
}

fn go_unpinned(arg: &str) -> Option<String> {
    if arg.starts_with('-') {
        return None;
    }
    let (_, v) = arg.rsplit_once('@')?;
    matches!(v, "latest" | "main" | "master" | "upgrade" | "patch")
        .then(|| format!("`@{v}` moves with every release"))
}

fn from_or_positional(args: &[Arg], s: &Scan) -> Option<(usize, String)> {
    s.from
        .clone()
        .or_else(|| s.positional.map(|p| (args[p].idx, args[p].text.clone())))
}

fn js_launcher(tool: &'static str, args: &[Arg]) -> Option<Unpinned> {
    let s = scan(args, JS_VALUE_FLAGS, &["-p", "--package"]);
    let (idx, spec) = from_or_positional(args, &s)?;
    let reason = npm_unpinned(&spec)?;
    Some(Unpinned {
        tool,
        spec,
        reason,
        idx,
        yes: s.yes,
    })
}

fn python_launcher(
    tool: &'static str,
    args: &[Arg],
    value_flags: &[&str],
    from_flag: &str,
) -> Option<Unpinned> {
    let s = scan(args, value_flags, &[from_flag]);
    let (idx, spec) = from_or_positional(args, &s)?;
    let reason = python_unpinned(&spec)?;
    Some(Unpinned {
        tool,
        spec,
        reason,
        idx,
        yes: false,
    })
}

fn find_unpinned(l: &Launch) -> Option<Unpinned> {
    let args = l.args.as_slice();
    match l.prog.as_str() {
        "npx" => js_launcher("npx", args),
        "bunx" => js_launcher("bunx", args),
        "pnpm" => after_sub(args, &[], &["dlx"]).and_then(|r| js_launcher("pnpm dlx", r)),
        "yarn" => after_sub(args, &[], &["dlx"]).and_then(|r| js_launcher("yarn dlx", r)),
        "npm" => after_sub(args, &[], &["exec", "x"]).and_then(|r| js_launcher("npm exec", r)),
        "uvx" => python_launcher("uvx", args, UV_VALUE_FLAGS, "--from"),
        "uv" => after_sub(args, &[], &["tool"])
            .and_then(|r| after_sub(r, &[], &["run"]))
            .and_then(|r| python_launcher("uv tool run", r, UV_VALUE_FLAGS, "--from")),
        "pipx" => after_sub(args, &[], &["run"])
            .and_then(|r| python_launcher("pipx run", r, PIPX_VALUE_FLAGS, "--spec")),
        "docker" | "podman" => {
            let run = parse_run(args)?;
            let image = run.image?;
            let reason = image_unpinned(&image.text)?;
            Some(Unpinned {
                tool: if l.prog == "docker" {
                    "docker run"
                } else {
                    "podman run"
                },
                spec: image.text,
                reason,
                idx: image.idx,
                yes: false,
            })
        }
        "go" => after_sub(args, &[], &["run"])?.iter().find_map(|a| {
            go_unpinned(&a.text).map(|reason| Unpinned {
                tool: "go run",
                spec: a.text.clone(),
                reason,
                idx: a.idx,
                yes: false,
            })
        }),
        _ => None,
    }
}

fn check_unpinned(cfg: &ServerConfig, l: &Launch, out: &mut Vec<Finding>) {
    let Some(u) = find_unpinned(l) else { return };
    let yes_note = if u.yes {
        " The -y/--yes flag installs it without asking for confirmation."
    } else {
        ""
    };
    let evidence = format!(
        "{} {}{}",
        u.tool,
        if u.yes { "-y " } else { "" },
        redact_text(&u.spec)
    );
    out.push(finding(
        cfg,
        "MW101",
        &format!("/args/{}", u.idx),
        format!(
            "`{}` runs `{}` without a pinned version ({}), so each launch fetches whatever is \
             currently published.{yes_note}",
            u.tool,
            redact_text(&u.spec),
            u.reason
        ),
        &evidence,
    ));
}

// ---------------------------------------------------------------------------------------------
// MW102 remote-code-pipe, MW107 shell-wrapper
// ---------------------------------------------------------------------------------------------

/// Index of the script argument and its text (empty when it is not readable, e.g. an encoded
/// PowerShell command) if `prog` is a shell running an inline script.
fn inline_script(prog: &str, args: &[String]) -> Option<(usize, String)> {
    match prog {
        "cmd" => {
            let p = args
                .iter()
                .position(|a| a.eq_ignore_ascii_case("/c") || a.eq_ignore_ascii_case("/k"))?;
            (p + 1 < args.len()).then(|| (p + 1, args[p + 1..].join(" ")))
        }
        "powershell" | "pwsh" => args.iter().enumerate().find_map(|(i, a)| {
            let name = a.strip_prefix(['-', '/'])?.to_ascii_lowercase();
            if name.is_empty() {
                None
            } else if "command".starts_with(&name) {
                (i + 1 < args.len()).then(|| (i + 1, args[i + 1..].join(" ")))
            } else if "encodedcommand".starts_with(&name) {
                Some((i.min(args.len() - 1), String::new()))
            } else {
                None
            }
        }),
        p if SHELLS.contains(&p) => {
            let i = args.iter().position(|a| POSIX_INLINE_FLAG.is_match(a))?;
            args.get(i + 1).map(|s| (i + 1, s.clone()))
        }
        _ => None,
    }
}

fn check_shell(cfg: &ServerConfig, command: &str, args: &[String], out: &mut Vec<Finding>) {
    let prog = prog_name(command);
    let Some((idx, script)) = inline_script(&prog, args) else {
        return;
    };
    let suffix = format!("/args/{idx}");
    let evidence = format!("{prog} {}", redact_text(&script));
    if DOWNLOAD_AND_RUN.iter().any(|re| re.is_match(&script)) {
        out.push(finding(
            cfg,
            "MW102",
            &suffix,
            format!(
                "`{prog}` downloads a script and executes it in one step; whatever the remote \
                 host serves at launch time runs unreviewed."
            ),
            &evidence,
        ));
        return;
    }
    // `cmd /c npx -y pkg` is the standard Windows launcher, not a hidden command.
    let plain_launcher = prog == "cmd" && !script.contains(['&', '|', '<', '>', ';', '^']);
    if plain_launcher {
        return;
    }
    let evidence = if script.is_empty() {
        format!("{prog} with an encoded command")
    } else {
        evidence
    };
    out.push(finding(
        cfg,
        "MW107",
        &suffix,
        format!(
            "The server command is `{prog}` running an inline script, which hides the real \
             command from review. Call the server executable directly."
        ),
        &evidence,
    ));
}

// ---------------------------------------------------------------------------------------------
// MW105 privileged-container
// ---------------------------------------------------------------------------------------------

struct Flag {
    idx: usize,
    name: String,
    value: Option<String>,
}

struct Run {
    flags: Vec<Flag>,
    image: Option<Arg>,
}

/// Parse `docker|podman [container] run [flags] IMAGE ...`.
fn parse_run(args: &[Arg]) -> Option<Run> {
    let rest = after_sub(args, CONTAINER_TOP_FLAGS, &["run"]).or_else(|| {
        after_sub(args, CONTAINER_TOP_FLAGS, &["container"])
            .and_then(|r| after_sub(r, &[], &["run"]))
    })?;
    let mut run = Run {
        flags: Vec::new(),
        image: None,
    };
    let mut i = 0;
    while i < rest.len() {
        let a = &rest[i];
        if a.text == "--" {
            run.image = rest.get(i + 1).cloned();
            break;
        }
        if !a.text.starts_with('-') {
            run.image = Some(a.clone());
            break;
        }
        let (name, inline) = a
            .text
            .split_once('=')
            .map_or((a.text.as_str(), None), |(n, v)| (n, Some(v)));
        let value = if let Some(v) = inline {
            Some(v.to_string())
        } else if RUN_VALUE_FLAGS.contains(&name) {
            i += 1;
            rest.get(i).map(|n| n.text.clone())
        } else {
            None
        };
        run.flags.push(Flag {
            idx: rest.get(i).unwrap_or(a).idx,
            name: name.to_string(),
            value,
        });
        i += 1;
    }
    Some(run)
}

/// What a path grants when given to a server or mounted into a container.
fn classify_path(path: &str, container: bool) -> Option<&'static str> {
    let t = path.trim().trim_matches(['"', '\'']);
    if t.is_empty() {
        return None;
    }
    let trimmed = t.trim_end_matches(['/', '\\']);
    if trimmed.is_empty() {
        return Some("the whole filesystem");
    }
    let lower = trimmed.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "~" | "$home" | "${home}" | "%userprofile%" | "$userprofile" | "${userprofile}"
    ) || HOME_DIR.is_match(trimmed)
    {
        return Some("the home directory");
    }
    if HOME_PARENT.is_match(trimmed) {
        return Some("all home directories");
    }
    if WHOLE_DRIVE.is_match(trimmed) {
        return Some("a whole drive");
    }
    if container {
        if lower == "/etc" {
            return Some("/etc");
        }
        if lower.ends_with("docker.sock") || lower.ends_with("podman.sock") {
            return Some("the container runtime socket");
        }
    }
    None
}

/// Host side of `-v SRC:DST[:opts]`, aware of `C:\path` drive letters.
fn volume_source(value: &str) -> &str {
    let b = value.as_bytes();
    let skip = if b.len() >= 3
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && matches!(b[2], b'\\' | b'/')
    {
        2
    } else {
        0
    };
    value[skip..]
        .find(':')
        .map_or(value, |i| &value[..skip + i])
}

fn container_issues(run: &Run) -> (usize, Vec<String>) {
    let mut issues = Vec::new();
    let mut first_idx = None;
    for f in &run.flags {
        let value = f.value.as_deref().unwrap_or_default();
        let issue = match f.name.as_str() {
            "--privileged" if value != "false" => Some("--privileged".to_string()),
            "-v" | "--volume" => classify_path(volume_source(value), true)
                .map(|k| format!("mounts {k} ({} {value})", f.name)),
            "--mount" => value
                .split(',')
                .filter_map(|kv| kv.split_once('='))
                .filter(|(k, _)| matches!(*k, "source" | "src"))
                .find_map(|(_, v)| classify_path(v, true))
                .map(|k| format!("mounts {k} (--mount {value})")),
            "--network" | "--net" if value == "host" => Some("--network host".to_string()),
            "--pid" if value == "host" => Some("--pid host".to_string()),
            "--cap-add" => {
                let cap = value.to_ascii_uppercase();
                matches!(cap.trim_start_matches("CAP_"), "SYS_ADMIN" | "ALL")
                    .then(|| format!("--cap-add {value}"))
            }
            _ => None,
        };
        if let Some(i) = issue {
            first_idx.get_or_insert(f.idx);
            issues.push(i);
        }
    }
    (first_idx.unwrap_or_default(), issues)
}

fn check_container(cfg: &ServerConfig, l: &Launch, out: &mut Vec<Finding>) {
    if !matches!(l.prog.as_str(), "docker" | "podman") {
        return;
    }
    let Some(run) = parse_run(&l.args) else {
        return;
    };
    let (idx, issues) = container_issues(&run);
    if issues.is_empty() {
        return;
    }
    out.push(finding(
        cfg,
        "MW105",
        &format!("/args/{idx}"),
        format!(
            "The container is started with broad host access: {}. A compromised server can take \
             over the host; drop these flags and mount only the project directory.",
            issues.join("; ")
        ),
        &redact_text(&issues.join("; ")),
    ));
}

// ---------------------------------------------------------------------------------------------
// MW106 broad-filesystem-access
// ---------------------------------------------------------------------------------------------

fn looks_like_filesystem_server(l: &Launch) -> bool {
    std::iter::once(l.prog.as_str())
        .chain(l.args.iter().map(|a| a.text.as_str()))
        .filter(|t| !t.starts_with(['-', '/', '~', '.']) && !t.contains(":\\"))
        .any(|t| {
            let lower = t.to_ascii_lowercase();
            ["filesystem", "server-fs", "files"]
                .iter()
                .any(|k| lower.contains(k))
        })
}

fn check_broad_fs(cfg: &ServerConfig, l: &Launch, out: &mut Vec<Finding>) {
    if !looks_like_filesystem_server(l) {
        return;
    }
    for a in &l.args {
        let value = if a.text.starts_with('-') {
            match a.text.split_once('=') {
                Some((_, v)) => v,
                None => continue,
            }
        } else {
            a.text.as_str()
        };
        if let Some(kind) = classify_path(value, false) {
            out.push(finding(
                cfg,
                "MW106",
                &format!("/args/{}", a.idx),
                format!(
                    "The filesystem server is given {kind}; a poisoned tool or confused model \
                     could read or overwrite SSH keys and other secrets. Grant only the project \
                     directories it needs."
                ),
                &format!("{} {}", l.prog, redact_text(&a.text)),
            ));
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Stdio dispatcher
// ---------------------------------------------------------------------------------------------

fn check_stdio(cfg: &ServerConfig, command: &str, args: &[String], out: &mut Vec<Finding>) {
    check_shell(cfg, command, args, out);
    let l = launch(command, args);
    check_unpinned(cfg, &l, out);
    check_container(cfg, &l, out);
    check_broad_fs(cfg, &l, out);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use super::*;

    fn cfg(transport: Transport) -> ServerConfig {
        ServerConfig {
            name: "srv".into(),
            client: "generic".into(),
            source: PathBuf::from("mcp.json"),
            pointer: "mcpServers/srv".into(),
            transport,
            disabled: false,
        }
    }

    fn stdio(command: &str, args: &[&str], env: &[(&str, &str)]) -> ServerConfig {
        cfg(Transport::Stdio {
            command: command.into(),
            args: args.iter().map(|s| (*s).to_string()).collect(),
            env: env
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            cwd: None,
        })
    }

    fn http(url: &str, headers: &[(&str, &str)]) -> ServerConfig {
        cfg(Transport::Http {
            url: url.into(),
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect::<BTreeMap<_, _>>(),
        })
    }

    fn ids(configs: &[ServerConfig]) -> Vec<&'static str> {
        check(configs).iter().map(|f| f.rule_id).collect()
    }

    fn one(config: ServerConfig) -> Finding {
        let mut found = check(&[config]);
        assert_eq!(found.len(), 1, "{found:?}");
        found.remove(0)
    }

    #[test]
    fn benign_configs_are_clean() {
        let digest = format!(
            "ghcr.io/github/github-mcp-server@sha256:{}",
            "ab".repeat(32)
        );
        let configs = [
            stdio(
                "npx",
                &["-y", "@modelcontextprotocol/server-github@2025.4.8"],
                &[("GITHUB_PERSONAL_ACCESS_TOKEN", "${GITHUB_TOKEN}")],
            ),
            stdio("uvx", &["mcp-server-fetch==2025.1.17"], &[]),
            stdio(
                "docker",
                &[
                    "run",
                    "-i",
                    "--rm",
                    "-e",
                    "GITHUB_PERSONAL_ACCESS_TOKEN",
                    &digest,
                ],
                &[],
            ),
            http(
                "https://api.example.com/mcp",
                &[("Authorization", "Bearer ${input:token}")],
            ),
            http("http://localhost:8080/mcp", &[]),
            http("http://127.0.0.1:3000/mcp", &[]),
            http("http://[::1]:3000/mcp", &[]),
            stdio(
                "npx",
                &[
                    "-y",
                    "@modelcontextprotocol/server-filesystem@2025.3.28",
                    "/home/user/projects/app",
                ],
                &[("API_TOKEN", "<your-token>"), ("PASSWORD", "changeme")],
            ),
            stdio("cmd", &["/c", "npx", "-y", "pkg@1.2.3"], &[]),
        ];
        assert_eq!(check(&configs), Vec::new());
    }

    #[test]
    fn secrets_are_found_and_never_echoed() {
        let gh = format!("ghp_{}", "a".repeat(36));
        let f = one(stdio("server", &[], &[("GITHUB_TOKEN", &gh)]));
        assert_eq!(f.rule_id, "MW100");
        assert_eq!(f.evidence, "GITHUB_TOKEN=*** (GitHub token)");
        assert_eq!(
            f.location.pointer.as_deref(),
            Some("mcpServers/srv/env/GITHUB_TOKEN")
        );
        assert!(!format!("{f:?}").contains(&gh));

        let generic = one(stdio("server", &[], &[("DB_PASSWORD", "hunter2hunter2")]));
        assert_eq!(generic.rule_id, "MW100");
        assert!(!format!("{generic:?}").contains("hunter2"));

        let bearer = one(http(
            "https://api.example.com/mcp",
            &[("Authorization", "Bearer abcdefgh12345678")],
        ));
        assert_eq!(
            bearer.evidence,
            "Authorization: Bearer *** (literal bearer token)"
        );

        let in_arg = one(stdio("server", &["--api-key=supersecretvalue"], &[]));
        assert_eq!(
            in_arg.location.pointer.as_deref(),
            Some("mcpServers/srv/args/0")
        );
        assert!(!format!("{in_arg:?}").contains("supersecretvalue"));
    }

    #[test]
    fn disabled_server_only_reports_secrets() {
        let gh = format!("ghp_{}", "a".repeat(36));
        let mut c = stdio("npx", &["-y", "pkg"], &[("GITHUB_TOKEN", &gh)]);
        c.disabled = true;
        assert_eq!(ids(&[c]), vec!["MW100"]);
    }

    #[test]
    fn unpinned_packages() {
        let f = one(stdio("npx", &["-y", "@scope/pkg"], &[]));
        assert_eq!(f.rule_id, "MW101");
        assert!(f.message.contains("-y"), "{}", f.message);
        assert_eq!(f.location.pointer.as_deref(), Some("mcpServers/srv/args/1"));

        for c in [
            stdio("npx", &["pkg@latest"], &[]),
            stdio("/usr/bin/bunx", &["pkg@^1.2.0"], &[]),
            stdio("npx.cmd", &["-y", "pkg"], &[]),
            stdio("cmd", &["/c", "npx -y pkg"], &[]),
            stdio("pnpm", &["dlx", "pkg"], &[]),
            stdio("uvx", &["--python", "3.12", "mcp-server-fetch"], &[]),
            stdio("uvx", &["--from", "mcp-server-git", "mcp-server-git"], &[]),
            stdio("pipx", &["run", "pkg>=1.0"], &[]),
            stdio(
                "docker",
                &["run", "-i", "--rm", "-v", "a:b", "ghcr.io/org/img"],
                &[],
            ),
            stdio("podman", &["run", "ghcr.io/org/img:latest"], &[]),
            stdio("go", &["run", "example.com/cmd/srv@latest"], &[]),
        ] {
            assert_eq!(
                ids(std::slice::from_ref(&c)),
                vec!["MW101"],
                "{:?}",
                c.transport
            );
        }
        for c in [
            stdio("uvx", &["mcp-server-git@2025.1.1"], &[]),
            stdio("docker", &["run", "localhost:5000/img:1.4"], &[]),
            stdio("npx", &["./local-server.js"], &[]),
            stdio("go", &["run", "./cmd/srv"], &[]),
        ] {
            assert_eq!(
                ids(std::slice::from_ref(&c)),
                Vec::<&str>::new(),
                "{:?}",
                c.transport
            );
        }
    }

    #[test]
    fn shell_download_and_run_vs_wrapper() {
        for script in [
            "curl -fsSL https://example.com/install.sh | sh",
            "wget -qO- https://example.com/i.sh | sudo bash",
            "bash <(curl -s https://example.com/i.sh)",
            "eval \"$(curl -s https://example.com/i.sh)\"",
        ] {
            let f = one(stdio("bash", &["-c", script], &[]));
            assert_eq!(f.rule_id, "MW102", "{script}");
            assert_eq!(f.severity, Severity::Critical);
        }
        let ps = one(stdio(
            "powershell.exe",
            &[
                "-NoProfile",
                "-Command",
                "iwr https://example.com/i.ps1 | iex",
            ],
            &[],
        ));
        assert_eq!(ps.rule_id, "MW102");

        let wrapper = one(stdio("sh", &["-c", "cd /srv && node server.js"], &[]));
        assert_eq!(wrapper.rule_id, "MW107");
        assert_eq!(wrapper.severity, Severity::Low);
    }

    #[test]
    fn insecure_transport_and_url_credentials() {
        let f = one(http("http://mcp.example.com/mcp", &[]));
        assert_eq!(f.rule_id, "MW103");

        let userinfo = one(http("https://alice:s3cretpass@mcp.example.com/mcp", &[]));
        assert_eq!(userinfo.rule_id, "MW104");
        assert!(
            !userinfo.evidence.contains("s3cretpass"),
            "{}",
            userinfo.evidence
        );

        let query = one(http(
            "https://mcp.example.com/mcp?api_key=abcd1234efgh&v=2",
            &[],
        ));
        assert_eq!(query.rule_id, "MW104");
        assert_eq!(
            query.evidence,
            "https://mcp.example.com/mcp?api_key=***&v=2"
        );

        let in_arg = one(stdio(
            "mcp-remote",
            &["https://mcp.example.com/sse?token=abcd1234"],
            &[],
        ));
        assert_eq!(in_arg.rule_id, "MW104");
        assert_eq!(
            in_arg.location.pointer.as_deref(),
            Some("mcpServers/srv/args/0")
        );

        assert_eq!(
            ids(&[http("https://mcp.example.com/mcp?api_key=${KEY}", &[])]),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn privileged_container_is_one_finding() {
        let f = one(stdio(
            "docker",
            &[
                "run",
                "-i",
                "--rm",
                "--privileged",
                "-v",
                "/var/run/docker.sock:/var/run/docker.sock",
                "--net=host",
                "--cap-add",
                "SYS_ADMIN",
                "-v",
                "$HOME:/home/me",
                "ghcr.io/org/img@sha256:abc",
            ],
            &[],
        ));
        assert_eq!(f.rule_id, "MW105");
        for part in [
            "--privileged",
            "runtime socket",
            "--network host",
            "SYS_ADMIN",
            "home directory",
        ] {
            assert!(
                f.message.contains(part),
                "{part} missing from {}",
                f.message
            );
        }
        assert_eq!(
            ids(&[stdio(
                "docker",
                &[
                    "run",
                    "-v",
                    "/home/user/projects/app:/work",
                    "ghcr.io/org/img@sha256:abc"
                ],
                &[],
            )]),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn broad_filesystem_access() {
        for path in [
            "/",
            "C:\\",
            "~",
            "$HOME",
            "/Users/alice",
            "C:\\Users\\alice",
        ] {
            let f = one(stdio(
                "npx",
                &[
                    "-y",
                    "@modelcontextprotocol/server-filesystem@2025.3.28",
                    path,
                ],
                &[],
            ));
            assert_eq!(f.rule_id, "MW106", "{path}");
            assert_eq!(f.location.pointer.as_deref(), Some("mcpServers/srv/args/2"));
        }
        // The same argument for a server that is not a filesystem server is not flagged here.
        assert_eq!(
            ids(&[stdio("python", &["server.py", "/"], &[])]),
            Vec::<&str>::new()
        );
    }
}
