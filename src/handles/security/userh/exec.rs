//! Runs the shadow-utils tools under the verb's deadline. Each tool gets its
//! own process group (`core::process::contain`); at the deadline the whole
//! group is stopped (`core::process::stop_tree`), so `main` reports exit
//! status 124. Standard input (for `chpasswd`) is written through a pipe and
//! never appears on a command line.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::core::process;

/// What went wrong running a tool.
#[derive(Debug)]
pub enum RunError {
    /// The program is not installed (or not on PATH).
    NotFound(String),
    /// The program could not be started for another reason.
    Spawn(String),
    /// The deadline passed; the tool was stopped. What it did stays done.
    Timeout(String),
    /// The program ran and exited unsuccessfully.
    Failed { code: Option<i32>, stderr: String },
}

/// Output of a successful run.
pub struct Ran {
    pub stdout: String,
}

const POLL: Duration = Duration::from_millis(10);

/// Runs `argv` with optional standard input, stopping it at `deadline`.
pub fn run(argv: &[String], stdin: Option<&str>, deadline: Instant) -> Result<Ran, RunError> {
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| RunError::Spawn("empty command".to_string()))?;
    if Instant::now() >= deadline {
        return Err(RunError::Timeout(format!(
            "{program} was not started: the deadline (timeout_ms) had already passed"
        )));
    }
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env("LC_ALL", "C")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    process::contain(&mut cmd);
    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            RunError::NotFound(format!("{program} is not installed or not on PATH"))
        } else {
            RunError::Spawn(format!("cannot run {program}: {e}"))
        }
    })?;
    let group = child.id() as libc::pid_t;
    // Readers first, so a tool that writes a lot never blocks on a full pipe.
    let out = reader(child.stdout.take());
    let err = reader(child.stderr.take());
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
        // A tool that exits early closes the pipe; its exit status says why.
        let _ = pipe.write_all(input.as_bytes());
        drop(pipe);
    }
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(e) => return Err(RunError::Spawn(format!("cannot wait for {program}: {e}"))),
        }
        if Instant::now() >= deadline {
            let stopped = process::stop_tree(program, group);
            let _ = child.try_wait();
            let state = match stopped {
                process::Stopped::StillRunning => "could not be stopped",
                _ => "was stopped",
            };
            return Err(RunError::Timeout(format!(
                "{program} did not finish before the deadline (timeout_ms) and {state}; \
                 the change may be partly applied"
            )));
        }
        std::thread::sleep(POLL);
    };
    let stdout = out.join().unwrap_or_default();
    let stderr = err.join().unwrap_or_default();
    if status.success() {
        Ok(Ran { stdout })
    } else {
        Err(RunError::Failed {
            code: status.code(),
            stderr: stderr.trim().to_string(),
        })
    }
}

fn reader(stream: Option<impl Read + Send + 'static>) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut s) = stream {
            let _ = s.by_ref().take(1 << 20).read_to_end(&mut buf);
            // Drain the rest so the tool never blocks on a full pipe.
            let _ = std::io::copy(&mut s, &mut std::io::sink());
        }
        String::from_utf8_lossy(&buf).into_owned()
    })
}
