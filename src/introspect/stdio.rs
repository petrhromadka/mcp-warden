//! Run an MCP server as a child process and talk to it over stdin/stdout.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Read};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::fetch_surface;
use super::session::Session;
use crate::model::ServerSurface;
use crate::text::snippet;

/// How much of the server's stderr is kept for error messages.
const STDERR_TAIL_BYTES: usize = 4096;
/// How long to wait for the stderr reader to drain after the child is gone.
const STDERR_DRAIN: Duration = Duration::from_millis(300);

pub(super) fn run(
    name: &str,
    command: &str,
    args: &[String],
    env: &BTreeMap<String, String>,
    cwd: Option<&str>,
    timeout: Duration,
) -> Result<ServerSurface, String> {
    let deadline = Instant::now() + timeout;
    let mut spawned = spawn(command, args, env, cwd)?;
    let (Some(stdin), Some(stdout), Some(stderr)) = (
        spawned.child.stdin.take(),
        spawned.child.stdout.take(),
        spawned.child.stderr.take(),
    ) else {
        terminate(&mut spawned);
        return Err("child process has no piped stdio".to_owned());
    };
    let tail = StderrTail::start(stderr);
    let reader = ChannelReader::start(stdout, deadline, timeout);

    let result = {
        let mut session = Session::new(reader, stdin);
        fetch_surface(&mut session, name)
    };
    terminate(&mut spawned);

    result.map_err(|e| match tail.collect() {
        Some(stderr) => format!("{e} (server stderr: {stderr})"),
        None => e.to_string(),
    })
}

struct Spawned {
    child: Child,
    /// The command was started through its `.cmd` wrapper, which leaves grandchildren behind.
    wrapper: bool,
}

fn spawn(
    command: &str,
    args: &[String],
    env: &BTreeMap<String, String>,
    cwd: Option<&str>,
) -> Result<Spawned, String> {
    let start = |program: &str| {
        let mut cmd = Command::new(program);
        cmd.args(args)
            .envs(env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        cmd.spawn()
    };
    match start(command) {
        Ok(child) => Ok(Spawned {
            child,
            wrapper: false,
        }),
        // Windows only resolves `.exe` by itself; `npx`, `npm` and friends are `.cmd` shims. Rust
        // quotes arguments safely for `.cmd` files, which `cmd /c <string>` would not.
        Err(e)
            if cfg!(windows)
                && e.kind() == io::ErrorKind::NotFound
                && !command.contains(['.', '/', '\\']) =>
        {
            start(&format!("{command}.cmd"))
                .map(|child| Spawned {
                    child,
                    wrapper: true,
                })
                .map_err(|e2| {
                    format!("cannot start `{command}`: {e} (also tried `{command}.cmd`: {e2})")
                })
        }
        Err(e) => Err(format!("cannot start `{command}`: {e}")),
    }
}

/// Kill and reap the child (and, behind a `.cmd` wrapper on Windows, its process tree).
fn terminate(spawned: &mut Spawned) {
    if spawned.wrapper && cfg!(windows) {
        let _ = Command::new("taskkill")
            .args(["/PID", &spawned.child.id().to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = spawned.child.kill();
    let _ = spawned.child.wait();
}

/// Last [`STDERR_TAIL_BYTES`] of the child's stderr, filled by a background thread.
struct StderrTail {
    buf: Arc<Mutex<Vec<u8>>>,
    /// Disconnects when the reader thread ends.
    finished: Receiver<()>,
}

impl StderrTail {
    fn start(mut stderr: impl Read + Send + 'static) -> Self {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let (done, finished) = mpsc::channel::<()>();
        let shared = Arc::clone(&buf);
        thread::spawn(move || {
            let _done = done;
            let mut chunk = [0u8; 1024];
            while let Ok(n) = stderr.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                let Ok(mut tail) = shared.lock() else { break };
                tail.extend_from_slice(&chunk[..n]);
                if tail.len() > STDERR_TAIL_BYTES {
                    let excess = tail.len() - STDERR_TAIL_BYTES;
                    tail.drain(..excess);
                }
            }
        });
        StderrTail { buf, finished }
    }

    /// Printable tail, or `None` if the child wrote nothing to stderr.
    fn collect(&self) -> Option<String> {
        // A grandchild may keep the pipe open; do not wait for it forever.
        let _ = self.finished.recv_timeout(STDERR_DRAIN);
        let bytes = self.buf.lock().ok()?;
        let text = String::from_utf8_lossy(&bytes);
        let text = snippet(text.trim(), 600);
        (!text.is_empty()).then_some(text)
    }
}

/// `BufRead` over chunks sent by a reader thread, so reads can time out at a fixed deadline.
struct ChannelReader {
    rx: Receiver<io::Result<Vec<u8>>>,
    deadline: Instant,
    timeout: Duration,
    chunk: Vec<u8>,
    pos: usize,
}

impl ChannelReader {
    fn start(mut source: impl Read + Send + 'static, deadline: Instant, timeout: Duration) -> Self {
        // A small bound makes the thread wait while we are not reading, so a flooding server
        // cannot make us buffer without limit.
        let (tx, rx) = mpsc::sync_channel(8);
        thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                let message = match source.read(&mut buf) {
                    Ok(0) => return,
                    Ok(n) => Ok(buf[..n].to_vec()),
                    Err(e) => Err(e),
                };
                let failed = message.is_err();
                if tx.send(message).is_err() || failed {
                    return;
                }
            }
        });
        ChannelReader {
            rx,
            deadline,
            timeout,
            chunk: Vec::new(),
            pos: 0,
        }
    }

    fn timed_out(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("timed out after {}s", self.timeout.as_secs().max(1)),
        )
    }
}

impl Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let n = available.len().min(out.len());
        out[..n].copy_from_slice(&available[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for ChannelReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pos >= self.chunk.len() {
            let left = self
                .deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or_else(|| self.timed_out())?;
            match self.rx.recv_timeout(left) {
                Ok(chunk) => {
                    self.chunk = chunk?;
                    self.pos = 0;
                }
                Err(RecvTimeoutError::Timeout) => return Err(self.timed_out()),
                // The reader thread ended: end of file.
                Err(RecvTimeoutError::Disconnected) => {
                    self.chunk.clear();
                    self.pos = 0;
                }
            }
        }
        Ok(&self.chunk[self.pos..])
    }

    fn consume(&mut self, amount: usize) {
        self.pos = (self.pos + amount).min(self.chunk.len());
    }
}
