//! Command-line interface. All logic lives in [`run`] so it is testable without spawning the
//! binary.

use std::ffi::OsString;
use std::io::Write;
use std::process::ExitCode;

/// Parse `args` (including the program name) and run; returns the process exit code:
/// 0 clean, 1 a finding reached `--fail-on`, 2 usage or runtime error.
pub fn run(_args: Vec<OsString>, _out: &mut dyn Write, _err: &mut dyn Write) -> u8 {
    0
}

pub fn main() -> ExitCode {
    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr().lock();
    ExitCode::from(run(std::env::args_os().collect(), &mut out, &mut err))
}
