//! Newline-delimited JSON-RPC over any `BufRead` + `Write` (the MCP stdio framing).

use std::io::{self, BufRead, Write};

use serde_json::{Value, json};

use super::{MAX_MESSAGE_BYTES, Message, Rpc, RpcError, classify};

/// Read one line without its terminator, failing if it exceeds `max` bytes. `None` at EOF; a
/// final unterminated line is returned as a line.
pub(super) fn read_bounded_line(
    reader: &mut impl BufRead,
    max: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            return Ok((!line.is_empty()).then_some(line));
        }
        let newline = buf.iter().position(|&b| b == b'\n');
        let take = newline.unwrap_or(buf.len());
        if line.len() + take > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("server sent a line longer than {max} bytes"),
            ));
        }
        line.extend_from_slice(&buf[..take]);
        reader.consume(take + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Some(line));
        }
    }
}

pub(super) struct Session<R, W> {
    reader: R,
    writer: W,
    next_id: u64,
}

impl<R: BufRead, W: Write> Session<R, W> {
    pub(super) fn new(reader: R, writer: W) -> Self {
        Session {
            reader,
            writer,
            next_id: 1,
        }
    }

    fn send(&mut self, message: &Value) -> Result<(), RpcError> {
        let mut bytes = serde_json::to_vec(message).map_err(|e| RpcError::Other(e.to_string()))?;
        bytes.push(b'\n');
        self.writer
            .write_all(&bytes)
            .and_then(|()| self.writer.flush())
            .map_err(|e| RpcError::Other(format!("cannot write to server: {e}")))
    }
}

impl<R: BufRead, W: Write> Rpc for Session<R, W> {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, RpcError> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        loop {
            let line = read_bounded_line(&mut self.reader, MAX_MESSAGE_BYTES)
                .map_err(|e| RpcError::Other(format!("cannot read from server: {e}")))?
                .ok_or_else(|| {
                    RpcError::Other(format!(
                        "server closed the connection before answering {method}"
                    ))
                })?;
            // Log lines and other non-JSON output are skipped.
            let Ok(value) = serde_json::from_slice::<Value>(&line) else {
                continue;
            };
            match classify(&value) {
                Message::Response { id: got, outcome } if got.as_u64() == Some(id) => {
                    return outcome;
                }
                Message::ServerRequest { id } => self.send(&json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32601, "message": "Method not found"},
                }))?,
                Message::Response { .. } | Message::Ignore => {}
            }
        }
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), RpcError> {
        self.send(&json!({"jsonrpc": "2.0", "method": method, "params": params}))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, PipeReader, PipeWriter};
    use std::thread::{self, JoinHandle};

    use super::*;
    use crate::introspect::fetch_surface;

    /// A handler line equal to this makes the fake server hang up.
    const HANG_UP: &str = "<hang up>";

    fn result_for(request: &Value, result: &Value) -> String {
        json!({"jsonrpc": "2.0", "id": request["id"], "result": result}).to_string()
    }

    /// Fake server on in-memory pipes. `handler` maps each client message to the lines to send
    /// back; the join handle returns every message the client sent.
    fn fake_server(
        handler: impl Fn(&Value) -> Vec<String> + Send + 'static,
    ) -> (
        Session<BufReader<PipeReader>, PipeWriter>,
        JoinHandle<Vec<Value>>,
    ) {
        let (requests_in, requests_out) = io::pipe().unwrap();
        let (replies_in, mut replies_out) = io::pipe().unwrap();
        let server = thread::spawn(move || {
            let mut seen = Vec::new();
            for line in BufReader::new(requests_in).lines() {
                let message: Value = serde_json::from_str(&line.unwrap()).unwrap();
                let replies = handler(&message);
                seen.push(message);
                for reply in replies {
                    if reply == HANG_UP {
                        return seen;
                    }
                    writeln!(replies_out, "{reply}").unwrap();
                }
            }
            seen
        });
        (
            Session::new(BufReader::new(replies_in), requests_out),
            server,
        )
    }

    #[test]
    fn full_exchange_with_noise_pagination_and_server_request() {
        let (mut session, server) = fake_server(|request| {
            let params = &request["params"];
            match request["method"].as_str().unwrap_or_default() {
                "initialize" => vec![
                    "starting up...".to_owned(),
                    json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {}}).to_string(),
                    result_for(
                        request,
                        &json!({"instructions": "read me", "capabilities": {"tools": {}, "prompts": {}}}),
                    ),
                ],
                "tools/list" if params.get("cursor").is_none() => vec![result_for(
                    request,
                    &json!({"tools": [{"name": "one"}], "nextCursor": "page2"}),
                )],
                "tools/list" => {
                    assert_eq!(params["cursor"], "page2");
                    vec![
                        json!({"jsonrpc": "2.0", "id": 99, "method": "roots/list"}).to_string(),
                        result_for(request, &json!({"tools": [{"name": "two"}]})),
                    ]
                }
                "prompts/list" => vec![
                    json!({"jsonrpc": "2.0", "id": request["id"], "error": {"code": -32601, "message": "no"}})
                        .to_string(),
                ],
                _ => vec![],
            }
        });
        let surface = fetch_surface(&mut session, "fake").unwrap();
        drop(session);
        let seen = server.join().unwrap();

        assert_eq!(surface.server, "fake");
        assert_eq!(surface.instructions.as_deref(), Some("read me"));
        let names: Vec<_> = surface.tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["one", "two"]);
        assert_eq!(surface.prompts.len(), 0);

        let methods: Vec<_> = seen.iter().filter_map(|m| m["method"].as_str()).collect();
        assert_eq!(
            methods,
            [
                "initialize",
                "notifications/initialized",
                "tools/list",
                "tools/list",
                "prompts/list"
            ]
        );
        assert_eq!(seen[0]["params"]["protocolVersion"], "2025-06-18");
        assert_eq!(seen[0]["params"]["clientInfo"]["name"], "mcp-warden");
        let rejection = seen
            .iter()
            .find(|m| m["id"] == 99)
            .expect("server request was answered");
        assert_eq!(rejection["error"]["code"], -32601);
    }

    #[test]
    fn truncated_response_is_an_error() {
        let (mut session, server) = fake_server(|_| {
            vec![
                r#"{"jsonrpc":"2.0","id":1,"res"#.to_owned(),
                HANG_UP.to_owned(),
            ]
        });
        let err = fetch_surface(&mut session, "fake").unwrap_err().to_string();
        drop(session);
        server.join().unwrap();
        assert!(err.contains("closed the connection"), "{err}");
    }

    #[test]
    fn endless_pagination_stops() {
        let (mut session, server) =
            fake_server(|request| match request["method"].as_str().unwrap() {
                "initialize" => vec![result_for(request, &json!({}))],
                "tools/list" => vec![result_for(
                    request,
                    &json!({"tools": [], "nextCursor": "again"}),
                )],
                _ => vec![],
            });
        let err = fetch_surface(&mut session, "fake").unwrap_err().to_string();
        drop(session);
        server.join().unwrap();
        assert!(err.contains("100 pages"), "{err}");
    }

    #[test]
    fn overlong_line_is_rejected() {
        let mut reader = io::Cursor::new(b"0123456789\nrest".to_vec());
        assert!(read_bounded_line(&mut reader, 5).is_err());
        let mut reader = io::Cursor::new(b"abc\r\nrest".to_vec());
        assert_eq!(
            read_bounded_line(&mut reader, 10).unwrap().unwrap(),
            b"abc\r"
        );
        assert_eq!(
            read_bounded_line(&mut reader, 10).unwrap().unwrap(),
            b"rest"
        );
        assert!(read_bounded_line(&mut reader, 10).unwrap().is_none());
    }
}
