//! Newline-delimited JSON-RPC over any `BufRead` + `Write` (the MCP stdio framing).

use std::io::{self, BufRead, Write};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use serde_json::{Value, json};

use super::{Budget, MAX_MESSAGE_BYTES, Message, Rpc, RpcError, classify};

/// Most requests of its own a server may send before we give up on it.
const MAX_SERVER_REQUESTS: usize = 100;
/// Longest string id of a server request that is echoed back in the rejection.
const MAX_ECHOED_ID_BYTES: usize = 256;

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

pub(super) struct Session<R> {
    reader: R,
    /// Messages for the writer thread. Queuing never blocks, so a server that does not read its
    /// stdin cannot stall us past the deadline that bounds the reads.
    outgoing: Sender<Vec<u8>>,
    /// The writer thread's failure, if it had one.
    write_failed: Receiver<io::Error>,
    write_error: Option<String>,
    next_id: u64,
    server_requests: usize,
    budget: Budget,
}

impl<R: BufRead> Session<R> {
    pub(super) fn new(reader: R, mut writer: impl Write + Send + 'static) -> Self {
        let (outgoing, queue) = mpsc::channel::<Vec<u8>>();
        let (failed, write_failed) = mpsc::channel();
        // Ends when the session is dropped or a write fails. A write stuck on a server that does
        // not read ends when the child is killed.
        thread::spawn(move || {
            for bytes in queue {
                if let Err(e) = writer.write_all(&bytes).and_then(|()| writer.flush()) {
                    let _ = failed.send(e);
                    return;
                }
            }
        });
        Session {
            reader,
            outgoing,
            write_failed,
            write_error: None,
            next_id: 1,
            server_requests: 0,
            budget: Budget::new(),
        }
    }

    fn send(&mut self, message: &Value) -> Result<(), RpcError> {
        let mut bytes = serde_json::to_vec(message).map_err(|e| RpcError::Other(e.to_string()))?;
        bytes.push(b'\n');
        let queued = self.outgoing.send(bytes).is_ok();
        if self.write_error.is_none() {
            self.write_error = self.write_failed.try_recv().ok().map(|e| e.to_string());
        }
        match &self.write_error {
            Some(e) => Err(RpcError::Other(format!("cannot write to server: {e}"))),
            None if queued => Ok(()),
            None => Err(RpcError::Other("cannot write to server".to_owned())),
        }
    }

    /// Answer a request the server made to us: we support none of them.
    fn reject(&mut self, id: &Value) -> Result<(), RpcError> {
        self.server_requests += 1;
        if self.server_requests > MAX_SERVER_REQUESTS {
            return Err(RpcError::Other(format!(
                "server sent more than {MAX_SERVER_REQUESTS} requests of its own"
            )));
        }
        // Echoing a huge or structured id would let the server make us send as much as it likes.
        let echoable = match id {
            Value::String(s) => s.len() <= MAX_ECHOED_ID_BYTES,
            Value::Number(_) => true,
            _ => false,
        };
        if !echoable {
            return Ok(());
        }
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32601, "message": "Method not found"},
        }))
    }
}

impl<R: BufRead> Rpc for Session<R> {
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
            self.budget.spend(line.len() + 1)?;
            // Log lines and other non-JSON output are skipped.
            let Ok(value) = serde_json::from_slice::<Value>(&line) else {
                continue;
            };
            match classify(&value) {
                Message::Response { id: got, outcome } if got.as_u64() == Some(id) => {
                    return outcome;
                }
                Message::ServerRequest { id } => self.reject(&id)?,
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
    use std::io::{BufReader, PipeReader};
    use std::thread::JoinHandle;
    use std::time::Duration;

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
    ) -> (Session<BufReader<PipeReader>>, JoinHandle<Vec<Value>>) {
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
                    // The client may already have given up and closed its end.
                    if writeln!(replies_out, "{reply}").is_err() {
                        return seen;
                    }
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

    /// Reader that yields its bytes, then reports a timeout like the stdio reader does.
    struct ThenTimeout {
        data: Vec<u8>,
        pos: usize,
    }

    impl io::Read for ThenTimeout {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let available = self.fill_buf()?;
            let n = available.len().min(out.len());
            out[..n].copy_from_slice(&available[..n]);
            self.consume(n);
            Ok(n)
        }
    }

    impl BufRead for ThenTimeout {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            if self.pos >= self.data.len() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            Ok(&self.data[self.pos..])
        }

        fn consume(&mut self, amount: usize) {
            self.pos += amount;
        }
    }

    /// A stdin that accepts nothing until the test lets go of it.
    struct StuckWriter(mpsc::Receiver<()>);

    impl Write for StuckWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            let _ = self.0.recv();
            Err(io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn stuck_stdin_does_not_defeat_the_deadline() {
        let (release, stuck) = mpsc::channel();
        let flood = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"roots/list\"}\n".repeat(50);
        let (done, finished) = mpsc::channel();
        thread::spawn(move || {
            let reader = ThenTimeout {
                data: flood.into_bytes(),
                pos: 0,
            };
            let mut session = Session::new(reader, StuckWriter(stuck));
            let _ = done.send(fetch_surface(&mut session, "fake").map(drop));
        });
        let outcome = finished
            .recv_timeout(Duration::from_secs(10))
            .expect("session must not block on the stuck writer");
        drop(release);
        let err = outcome.unwrap_err().to_string();
        assert!(err.contains("cannot read from server"), "{err}");
    }

    #[test]
    fn server_request_flood_aborts() {
        let (mut session, server) = fake_server(|request| {
            if request["method"] == "initialize" {
                (0..=MAX_SERVER_REQUESTS)
                    .map(|n| json!({"jsonrpc": "2.0", "id": n, "method": "ping"}).to_string())
                    .collect()
            } else {
                vec![]
            }
        });
        let err = fetch_surface(&mut session, "fake").unwrap_err().to_string();
        drop(session);
        let seen = server.join().unwrap();
        assert!(err.contains("requests of its own"), "{err}");
        assert_eq!(seen.len(), 1 + MAX_SERVER_REQUESTS);
    }

    #[test]
    fn long_or_structured_server_ids_are_not_echoed() {
        let long = "x".repeat(MAX_ECHOED_ID_BYTES + 1);
        let (mut session, server) = fake_server(move |request| match request["method"].as_str() {
            Some("initialize") => vec![
                json!({"jsonrpc": "2.0", "id": long, "method": "ping"}).to_string(),
                json!({"jsonrpc": "2.0", "id": {"a": 1}, "method": "ping"}).to_string(),
                json!({"jsonrpc": "2.0", "id": "short", "method": "ping"}).to_string(),
                result_for(request, &json!({})),
            ],
            Some("tools/list") => vec![result_for(request, &json!({"tools": []}))],
            _ => vec![],
        });
        fetch_surface(&mut session, "fake").unwrap();
        drop(session);
        let seen = server.join().unwrap();
        let rejected: Vec<_> = seen.iter().filter(|m| m.get("error").is_some()).collect();
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0]["id"], "short");
    }

    #[test]
    fn total_budget_stops_noise() {
        let mut noise = "n".repeat(1024 * 1024);
        noise.push('\n');
        let (mut session, server) = fake_server(move |request| {
            if request["method"] == "initialize" {
                vec![noise.trim_end().to_owned(); 70]
            } else {
                vec![]
            }
        });
        let err = fetch_surface(&mut session, "fake").unwrap_err().to_string();
        drop(session);
        let _ = server.join();
        assert!(err.contains("64 MiB"), "{err}");
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
