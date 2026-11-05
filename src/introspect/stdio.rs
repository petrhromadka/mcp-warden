//! Run an MCP server as a child process and talk to it over stdin/stdout.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Read};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use regex::Regex;

use super::fetch_surface;
use super::session::Session;
use crate::model::ServerSurface;
use crate::text::snippet;

/// Variables a launcher (`npx`, `uvx`, `python`, ...) needs; everything else is withheld from the
/// server so CI secrets and the runner's control files (`GITHUB_ENV`, ...) do not reach it.
const INHERITED_ENV: &[&str] = &[
    "PATH",
    "PATHEXT",
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "ProgramData",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "SystemRoot",
    "SystemDrive",
    "windir",
    "ComSpec",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "USER",
    "USERNAME",
    "LOGNAME",
    "SHELL",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
];
/// Never inherited, whatever the allowlist says.
const WITHHELD_PREFIXES: &[&str] = &["GITHUB_", "ACTIONS_", "RUNNER_"];
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
        Some(stderr) => format!(
            "{e} (server stderr: {})",
            mask_configured_values(&stderr, env)
        ),
        None => e.to_string(),
    })
}

/// A server may echo the secrets it was given; mask every configured env value (4+ chars).
fn mask_configured_values(text: &str, env: &BTreeMap<String, String>) -> String {
    let mut values: Vec<&str> = env
        .values()
        .map(String::as_str)
        .filter(|v| v.chars().count() >= 4)
        .collect();
    values.sort_by_key(|v| std::cmp::Reverse(v.len()));
    values
        .into_iter()
        .fold(text.to_owned(), |acc, v| acc.replace(v, "***"))
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
    let child_env = child_env(
        std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?))),
        env,
    );
    let start = |program: &str| {
        let mut cmd = Command::new(program);
        cmd.args(args)
            .env_clear()
            .envs(&child_env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        // Own process group, so the whole tree (`npx` -> node) can be killed at once.
        #[cfg(unix)]
        std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
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

/// The environment of the server process: the allowlisted part of `inherited`, then the config's
/// own `env` (the user's explicit choice, so it may override or add anything).
fn child_env(
    inherited: impl IntoIterator<Item = (String, String)>,
    configured: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let allowed = |name: &str| {
        let upper = name.to_ascii_uppercase();
        !WITHHELD_PREFIXES.iter().any(|p| upper.starts_with(p))
            && INHERITED_ENV.iter().any(|a| {
                // Windows variable names are case-insensitive.
                if cfg!(windows) {
                    a.eq_ignore_ascii_case(name)
                } else {
                    *a == name
                }
            })
    };
    let mut env: BTreeMap<String, String> = inherited
        .into_iter()
        .filter(|(name, _)| allowed(name))
        .collect();
    env.extend(configured.iter().map(|(k, v)| (k.clone(), v.clone())));
    env
}

/// Kill and reap the child (and, behind a `.cmd` wrapper on Windows, its process tree).
fn terminate(spawned: &mut Spawned) {
    #[cfg(unix)]
    {
        // The child leads its own process group (see `spawn`); std has no `killpg`.
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{}", spawned.child.id())])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
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

/// Drop control characters (newlines and tabs become spaces) and replace long token-like runs
/// that mix letters and digits, which is what API keys and JWTs look like, with `***`.
fn mask_secrets(text: &str) -> String {
    static TOKEN: OnceLock<Regex> = OnceLock::new();
    let clean: String = text
        .chars()
        .filter_map(|c| match c {
            '\n' | '\r' | '\t' => Some(' '),
            c if c.is_control() => None,
            c => Some(c),
        })
        .collect();
    let token = TOKEN.get_or_init(|| Regex::new(r"[A-Za-z0-9_\-+/=.]{20,}").expect("valid regex"));
    token
        .replace_all(&clean, |caps: &regex::Captures<'_>| {
            let run = &caps[0];
            if run.bytes().any(|b| b.is_ascii_alphabetic())
                && run.bytes().any(|b| b.is_ascii_digit())
            {
                "***".to_owned()
            } else {
                run.to_owned()
            }
        })
        .into_owned()
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
        let text = mask_secrets(&String::from_utf8_lossy(&bytes));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn child_env_is_an_allowlist_plus_the_config() {
        let inherited = pairs(&[
            ("PATH", "/usr/bin"),
            ("HOME", "/home/ci"),
            ("GITHUB_ENV", "/runner/env"),
            ("GITHUB_PATH", "/runner/path"),
            ("GITHUB_OUTPUT", "/runner/out"),
            ("GITHUB_TOKEN", "ghs_secret"),
            ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "jwt"),
            ("RUNNER_TEMP", "/tmp"),
            ("AWS_SECRET_ACCESS_KEY", "secret"),
            ("NPM_TOKEN", "secret"),
        ]);
        let configured = BTreeMap::from([
            ("PATH".to_owned(), "/custom".to_owned()),
            ("GITHUB_TOKEN".to_owned(), "explicit".to_owned()),
            ("API_KEY".to_owned(), "k".to_owned()),
        ]);
        let env = child_env(inherited, &configured);
        let expected = BTreeMap::from([
            ("PATH".to_owned(), "/custom".to_owned()),
            ("HOME".to_owned(), "/home/ci".to_owned()),
            ("GITHUB_TOKEN".to_owned(), "explicit".to_owned()),
            ("API_KEY".to_owned(), "k".to_owned()),
        ]);
        assert_eq!(env, expected);
    }

    #[test]
    fn configured_env_values_are_masked_in_stderr() {
        let env = BTreeMap::from([
            ("API_KEY".to_owned(), "hunter2hunter2".to_owned()),
            ("MODE".to_owned(), "x".to_owned()),
        ]);
        assert_eq!(
            mask_configured_values("token is hunter2hunter2, mode x", &env),
            "token is ***, mode x"
        );
    }

    #[test]
    fn mask_secrets_hides_token_like_runs_and_control_characters() {
        let text = "boot ok\nkey=sk-ant-api03-AbCdEf0123456789xyz and /usr/local/lib/node_modules/pkg \
                    \u{1b}[31mred\u{0}\u{1b}[0m aaaaaaaaaaaaaaaaaaaaaaaa 0123456789012345678901";
        assert_eq!(
            mask_secrets(text),
            "boot ok *** and /usr/local/lib/node_modules/pkg [31mred[0m \
             aaaaaaaaaaaaaaaaaaaaaaaa 0123456789012345678901"
        );
    }
}
