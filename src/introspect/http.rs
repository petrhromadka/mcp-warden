//! MCP "Streamable HTTP" client: every JSON-RPC message is a POST; the reply is a JSON body or
//! a Server-Sent Events stream. The legacy HTTP+SSE transport is not supported.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{self, BufRead, BufReader, Read};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use regex::Regex;
use serde_json::{Value, json};
use ureq::Agent;

use super::session::read_bounded_line;
use super::{
    Budget, MAX_MESSAGE_BYTES, Message, PROTOCOL_VERSION, Rpc, RpcError, classify, fetch_surface,
};
use crate::model::ServerSurface;
use crate::text::snippet;

/// Headers this client sets itself; the config cannot override them.
const RESERVED_HEADERS: [&str; 4] = [
    "accept",
    "content-type",
    "mcp-session-id",
    "mcp-protocol-version",
];

pub(super) fn run(
    name: &str,
    url: &str,
    headers: &BTreeMap<String, String>,
    timeout: Duration,
) -> Result<ServerSurface, String> {
    // Not echoed: the parser's message quotes the offending part of the URL.
    if url.parse::<ureq::http::Uri>().is_err() {
        return Err("invalid server URL".to_owned());
    }
    // Redirects are not followed and the proxy variables are ignored: configured headers (API
    // keys) must not reach another host.
    let config = Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .max_redirects_will_error(false)
        .proxy(None)
        .build();
    let mut rpc = HttpRpc {
        agent: Agent::new_with_config(config),
        url,
        headers,
        session_id: None,
        protocol_negotiated: false,
        next_id: 1,
        deadline: Instant::now() + timeout,
        timeout,
        budget: Budget::new(),
    };
    fetch_surface(&mut rpc, name).map_err(|e| e.to_string())
}

/// `url` without userinfo, query and fragment, which may carry credentials.
fn redact_url(url: &str) -> String {
    let url = &url[..url.find(['?', '#']).unwrap_or(url.len())];
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    format!("{scheme}://{host}{path}")
}

/// Redact every URL in an error message produced by the HTTP stack.
fn redact_urls(message: &str, configured_url: &str) -> String {
    static URL: OnceLock<Regex> = OnceLock::new();
    let url = URL.get_or_init(|| {
        Regex::new(r#"[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>)]+"#).expect("valid regex")
    });
    let message = message.replace(configured_url, &redact_url(configured_url));
    url.replace_all(&message, |caps: &regex::Captures<'_>| redact_url(&caps[0]))
        .into_owned()
}

struct HttpRpc<'a> {
    agent: Agent,
    url: &'a str,
    headers: &'a BTreeMap<String, String>,
    session_id: Option<String>,
    protocol_negotiated: bool,
    next_id: u64,
    deadline: Instant,
    timeout: Duration,
    budget: Budget,
}

impl HttpRpc<'_> {
    /// POST `body`. For a request (`wait_for` is its id) return its `result`; for a notification
    /// return `Null` once the server accepted it. Errors never contain the URL's credentials.
    fn post(
        &mut self,
        method: &str,
        body: &Value,
        wait_for: Option<u64>,
    ) -> Result<Value, RpcError> {
        self.post_unredacted(method, body, wait_for)
            .map_err(|e| match e {
                RpcError::Other(m) => RpcError::Other(redact_urls(&m, self.url)),
                server @ RpcError::Server(_) => server,
            })
    }

    fn post_unredacted(
        &mut self,
        method: &str,
        body: &Value,
        wait_for: Option<u64>,
    ) -> Result<Value, RpcError> {
        let left = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                RpcError::Other(format!(
                    "timed out after {}s",
                    self.timeout.as_secs().max(1)
                ))
            })?;
        let mut request = self
            .agent
            .post(self.url)
            .config()
            .timeout_global(Some(left))
            .build()
            .header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json");
        if let Some(id) = &self.session_id {
            request = request.header("Mcp-Session-Id", id);
        }
        if self.protocol_negotiated {
            request = request.header("MCP-Protocol-Version", PROTOCOL_VERSION);
        }
        for (key, value) in self.headers {
            if !RESERVED_HEADERS.contains(&key.to_ascii_lowercase().as_str()) {
                request = request.header(key, value);
            }
        }
        let payload = serde_json::to_string(body).map_err(|e| RpcError::Other(e.to_string()))?;
        let mut response = request
            .send(payload)
            .map_err(|e| RpcError::Other(format!("HTTP request failed: {e}")))?;

        if let Some(id) = response
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
        {
            self.session_id = Some(id.to_owned());
        }
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(RpcError::Other(status_error(method, &response)));
        }
        let Some(id) = wait_for else {
            return Ok(Value::Null);
        };
        let is_stream = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("text/event-stream"));
        let outcome = if is_stream {
            // One byte more than the budget allows, so running out shows as an overspend.
            let cap = u64::try_from(self.budget.left).unwrap_or(u64::MAX) + 1;
            let mut limited = response.body_mut().as_reader().take(cap);
            let read = read_sse_response(BufReader::new(&mut limited), id);
            let used = usize::try_from(cap - limited.limit()).unwrap_or(usize::MAX);
            self.budget.spend(used)?;
            read.map_err(|e| RpcError::Other(format!("cannot read event stream: {e}")))?
        } else {
            let mut bytes = Vec::new();
            response
                .body_mut()
                .as_reader()
                .take(MAX_MESSAGE_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| RpcError::Other(format!("cannot read response: {e}")))?;
            if bytes.len() > MAX_MESSAGE_BYTES {
                return Err(RpcError::Other(format!(
                    "response larger than {MAX_MESSAGE_BYTES} bytes"
                )));
            }
            self.budget.spend(bytes.len())?;
            let value: Value = serde_json::from_slice(&bytes)
                .map_err(|e| RpcError::Other(format!("invalid JSON response: {e}")))?;
            find_response(&value, id)
        };
        outcome.unwrap_or_else(|| {
            Err(RpcError::Other(format!(
                "no reply to {method} in the response"
            )))
        })
    }
}

impl Rpc for HttpRpc<'_> {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, RpcError> {
        let id = self.next_id;
        self.next_id += 1;
        let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let result = self.post(method, &body, Some(id))?;
        if method == "initialize" {
            self.protocol_negotiated = true;
        }
        Ok(result)
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), RpcError> {
        let body = json!({"jsonrpc": "2.0", "method": method, "params": params});
        self.post(method, &body, None).map(drop)
    }
}

/// Status line only: a response body may echo request headers or other secrets.
fn status_error(method: &str, response: &ureq::http::Response<ureq::Body>) -> String {
    let status = response.status().as_u16();
    let mut message = format!("HTTP {status}");
    if let Some(reason) = response.status().canonical_reason() {
        let _ = write!(message, " {reason}");
    }
    let _ = write!(message, " for {method}");
    if (300..400).contains(&status) {
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("?");
        let _ = write!(
            message,
            " (redirect to {} not followed)",
            snippet(&redact_url(location), 200)
        );
    }
    if method == "initialize" && matches!(status, 400 | 404 | 405) {
        message.push_str(
            "; if this is a legacy HTTP+SSE server (GET stream with an `endpoint` event) it is not \
             supported: save its tools/list output to a file and scan that as a dump",
        );
    }
    message
}

/// Pick the response to request `id` out of a single message or a batch.
fn find_response(value: &Value, id: u64) -> Option<Result<Value, RpcError>> {
    let candidates = value
        .as_array()
        .map_or_else(|| std::slice::from_ref(value), Vec::as_slice);
    candidates.iter().find_map(|v| match classify(v) {
        Message::Response { id: got, outcome } if got.as_u64() == Some(id) => Some(outcome),
        _ => None,
    })
}

/// Read a Server-Sent Events stream until the JSON-RPC response to request `id` shows up.
/// `Ok(None)` if the stream ends without one.
fn read_sse_response(
    mut reader: impl BufRead,
    id: u64,
) -> io::Result<Option<Result<Value, RpcError>>> {
    let mut data = String::new();
    loop {
        let line = read_bounded_line(&mut reader, MAX_MESSAGE_BYTES)?;
        let end_of_event = line
            .as_deref()
            .is_none_or(|l| l.iter().all(|&b| b == b'\r'));
        if end_of_event {
            if let Ok(value) = serde_json::from_str::<Value>(&data)
                && let Some(found) = find_response(&value, id)
            {
                return Ok(Some(found));
            }
            data.clear();
            if line.is_none() {
                return Ok(None);
            }
            continue;
        }
        let line = String::from_utf8_lossy(line.as_deref().unwrap_or_default()).into_owned();
        if let Some(rest) = line.strip_prefix("data:") {
            if data.len() + rest.len() > MAX_MESSAGE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "event larger than the message limit",
                ));
            }
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(
                rest.strip_prefix(' ')
                    .unwrap_or(rest)
                    .trim_end_matches('\r'),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;

    use super::*;

    #[test]
    fn sse_stream_yields_the_matching_response() {
        let stream = ": comment\r\n\
            event: message\r\n\
            data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\r\n\
            \r\n\
            data: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"x\":0}}\r\n\
            \r\n\
            id: 5\r\n\
            data: {\"jsonrpc\":\"2.0\",\"id\":2,\r\n\
            data: \"result\":{\"tools\":[]}}";
        let found = read_sse_response(Cursor::new(stream), 2)
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(found, json!({"tools": []}));
        assert!(read_sse_response(Cursor::new(stream), 3).unwrap().is_none());
    }

    /// Read one HTTP request; return its lowercased header lines and its body.
    fn read_request(stream: &TcpStream) -> (Vec<String>, String) {
        let mut reader = BufReader::new(stream);
        let mut headers = Vec::new();
        let mut length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let line = line.trim_end().to_ascii_lowercase();
            if line.is_empty() {
                break;
            }
            if let Some(n) = line.strip_prefix("content-length:") {
                length = n.trim().parse().unwrap();
            }
            headers.push(line);
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        (headers, String::from_utf8(body).unwrap())
    }

    #[test]
    fn exchange_over_a_local_http_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/mcp", listener.local_addr().unwrap());
        let (log_tx, log_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"instructions\":\"hi\",\"capabilities\":{}}}\n\n";
            let json = "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"t\"}]}}";
            let replies = [
                ("200 OK", "text/event-stream\r\nmcp-session-id: abc", sse),
                ("202 Accepted", "text/plain", ""),
                ("200 OK", "application/json", json),
            ];
            for (status, content_type, body) in replies {
                let (mut stream, _) = listener.accept().unwrap();
                log_tx.send(read_request(&stream)).unwrap();
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        let headers = BTreeMap::from([("Authorization".to_owned(), "Bearer k".to_owned())]);
        let surface = run("srv", &url, &headers, Duration::from_secs(20)).unwrap();
        server.join().unwrap();

        assert_eq!(surface.instructions.as_deref(), Some("hi"));
        assert_eq!(surface.tools[0].name, "t");
        let log: Vec<_> = log_rx.try_iter().collect();
        assert_eq!(log.len(), 3);
        assert!(log[0].0.contains(&"authorization: bearer k".to_owned()));
        assert!(
            log[0]
                .0
                .contains(&"accept: application/json, text/event-stream".to_owned())
        );
        assert!(!log[0].0.iter().any(|h| h.starts_with("mcp-session-id")));
        for (headers, _) in &log[1..] {
            assert!(
                headers.contains(&"mcp-session-id: abc".to_owned()),
                "{headers:?}"
            );
            assert!(headers.contains(&"mcp-protocol-version: 2025-06-18".to_owned()));
        }
        assert!(log[1].1.contains("notifications/initialized"));
    }

    #[test]
    fn error_status_hides_the_body_and_the_url_credentials() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://user:hunter2@{addr}/mcp?token=abc123#frag");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&stream);
            let body = "echoed Authorization: Bearer SECRETBODY";
            write!(
                stream,
                "HTTP/1.1 500 Internal Server Error\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        let err = run("srv", &url, &BTreeMap::new(), Duration::from_secs(20)).unwrap_err();
        server.join().unwrap();
        assert!(err.contains("HTTP 500 Internal Server Error"), "{err}");
        for secret in ["SECRETBODY", "hunter2", "abc123", "frag"] {
            assert!(!err.contains(secret), "{err}");
        }
    }

    #[test]
    fn connection_errors_and_bad_urls_do_not_leak_the_url() {
        // Nothing listens on port 1.
        let url = "http://user:hunter2@127.0.0.1:1/mcp?token=abc123";
        let err = run("srv", url, &BTreeMap::new(), Duration::from_secs(20)).unwrap_err();
        for secret in ["hunter2", "abc123"] {
            assert!(!err.contains(secret), "{err}");
        }
        let err = run(
            "srv",
            "http://bad host/?token=abc123",
            &BTreeMap::new(),
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(!err.contains("abc123"), "{err}");
    }

    #[test]
    fn redaction_drops_userinfo_query_and_fragment() {
        assert_eq!(
            redact_url("https://u:p@host:8443/a/b?k=v#f"),
            "https://host:8443/a/b"
        );
        assert_eq!(redact_url("/relative?x=1"), "/relative");
        assert_eq!(
            redact_urls(
                "error sending request for url (http://u:p@h/x?k=v): refused",
                "http://u:p@h/x?k=v"
            ),
            "error sending request for url (http://h/x): refused"
        );
    }
}
