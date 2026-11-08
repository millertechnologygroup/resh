//! `log://svc/<service>`: the service's journal through `journalctl`, run
//! directly (no shell) with each value in its own `--name=value` argument.
//! Without follow, journalctl runs under the core process deadline
//! (`timeout_ms`, default 600000); with follow, its output is streamed until
//! it exits or the deadline passes, and its whole process tree is stopped.

use super::scan::LineSplitter;
use super::{Fail, LogHandle, Outcome, TailOpts, emit, warn_cut};
use crate::core::process;
use crate::core::registry::IoStreams;
use crate::core::status::exit;
use anyhow::Result;
use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The line journalctl prints when nothing matched; it is not a log line.
const NO_ENTRIES: &str = "-- No entries --";
/// Longest wait for journalctl's output between deadline checks.
const RECV_WAIT: Duration = Duration::from_millis(200);

/// Arguments for `journalctl`.
pub(crate) fn args(service: &str, lines: usize, follow: bool) -> Vec<String> {
    let mut v = vec![
        format!("--unit={service}"),
        format!("--lines={lines}"),
        "--no-pager".to_string(),
        "--output=short".to_string(),
    ];
    if follow {
        v.push("--follow".to_string());
    }
    v
}

/// True when journalctl says it could not read the journal it was asked for
/// (it can still exit 0 then, so no lines would mean nothing was read).
fn denied(stderr: &str) -> bool {
    stderr.contains("not seeing messages from other") || stderr.contains("insufficient permissions")
}

fn not_found(h: &LogHandle) -> Fail {
    Fail::new(
        exit::FAILED,
        "log.journalctl_not_found",
        format!(
            "{} was not found; log://svc/<service> needs systemd's journalctl",
            h.journalctl.to_string_lossy()
        ),
    )
}

fn access_denied(service: &str, stderr: &str) -> Fail {
    Fail::new(
        exit::FAILED,
        "log.journal_access_denied",
        format!(
            "cannot read the journal of {service} (membership in the systemd-journal or \
             adm group is usually needed): {}",
            stderr.trim()
        ),
    )
}

fn failed(service: &str, status: Option<i32>, stderr: &str) -> Fail {
    let status = status.map_or("a signal".to_string(), |c| format!("status {c}"));
    let stderr = stderr.trim();
    Fail::new(
        exit::FAILED,
        "log.journal_failed",
        if stderr.is_empty() {
            format!("journalctl failed for service {service} (exit {status})")
        } else {
            format!("journalctl failed for service {service} (exit {status}): {stderr}")
        },
    )
}

fn command(h: &LogHandle, service: &str, o: &TailOpts) -> Command {
    let mut cmd = Command::new(&h.journalctl);
    cmd.args(args(service, o.lines, o.follow))
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_PAGER", "");
    cmd
}

pub(crate) fn tail(
    h: &LogHandle,
    service: &str,
    o: &TailOpts,
    start: Instant,
    io: &mut IoStreams,
) -> Result<Outcome> {
    if o.follow {
        return follow(h, service, o, start, io);
    }
    let mut cmd = command(h, service, o);
    let remaining = o
        .deadline(start)
        .map(|d| d.saturating_duration_since(Instant::now()));
    let out = match process::run(&mut cmd, remaining) {
        Ok(out) => out,
        Err(e) if e.kind() == io::ErrorKind::TimedOut => {
            // Reading the journal changes nothing: this is a plain timeout,
            // not an unknown outcome.
            let _ = process::take_lost();
            return Ok(Outcome::Failed(Fail::timeout(o.timeout)));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Outcome::Failed(not_found(h))),
        Err(e) => {
            return Ok(Outcome::Failed(Fail::new(
                exit::FAILED,
                "log.journal_failed",
                format!("cannot run {}: {e}", h.journalctl.to_string_lossy()),
            )));
        }
    };
    let stderr = String::from_utf8_lossy(&out.stderr);
    if denied(&stderr) {
        return Ok(Outcome::Failed(access_denied(service, &stderr)));
    }
    if !out.status.success() {
        return Ok(Outcome::Failed(failed(service, out.status.code(), &stderr)));
    }
    let mut lines = Vec::new();
    let mut split = LineSplitter::default();
    split.push(&out.stdout, |l| {
        lines.push(l.to_string());
        Ok(())
    });
    lines.extend(split.finish());
    lines.retain(|l| l != NO_ENTRIES);
    if split.cut > 0 {
        warn_cut(io, split.cut)?;
    }
    h.print(io, o, lines)?;
    Ok(Outcome::Done)
}

enum Msg {
    Out(Vec<u8>),
    OutEnd,
    Err(String),
    ErrEnd,
}

/// Stops journalctl and everything it started, without leaving the loss
/// for `main` to report as an unknown outcome (reading changes nothing).
/// False when something outlived SIGKILL.
fn stop(child: &mut Child) -> bool {
    let stopped = process::stop_tree("journalctl", child.id() as libc::pid_t);
    let _ = process::take_lost();
    let _ = child.try_wait();
    stopped != process::Stopped::StillRunning
}

fn follow(
    h: &LogHandle,
    service: &str,
    o: &TailOpts,
    start: Instant,
    io: &mut IoStreams,
) -> Result<Outcome> {
    let deadline = o.deadline(start);
    if deadline.is_some_and(|d| Instant::now() >= d) {
        return Ok(Outcome::Done);
    }
    let mut cmd = command(h, service, o);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    process::contain(&mut cmd);
    // SAFETY: prctl takes plain integers; it is async-signal-safe. If resh
    // dies (Ctrl-C), journalctl is told to stop instead of running on.
    unsafe {
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            Ok(())
        });
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Outcome::Failed(not_found(h))),
        Err(e) => {
            return Ok(Outcome::Failed(Fail::new(
                exit::FAILED,
                "log.journal_failed",
                format!("cannot run {}: {e}", h.journalctl.to_string_lossy()),
            )));
        }
    };

    let (tx, rx) = mpsc::channel::<Msg>();
    if let Some(mut out) = child.stdout.take() {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match out.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if tx.send(Msg::Out(buf[..n].to_vec())).is_err() {
                            return;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            let _ = tx.send(Msg::OutEnd);
        });
    } else {
        let _ = tx.send(Msg::OutEnd);
    }
    if let Some(err) = child.stderr.take() {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut r = BufReader::new(err);
            let mut line = Vec::new();
            while matches!(r.read_until(b'\n', &mut line), Ok(n) if n > 0) {
                let text = String::from_utf8_lossy(&line).into_owned();
                line.clear();
                if tx.send(Msg::Err(text)).is_err() {
                    return;
                }
            }
            let _ = tx.send(Msg::ErrEnd);
        });
    } else {
        let _ = tx.send(Msg::ErrEnd);
    }
    drop(tx);

    let mut split = LineSplitter::default();
    let mut stderr = String::new();
    let (mut out_done, mut err_done) = (false, false);
    let print = |io: &mut IoStreams, l: &str| {
        if l == NO_ENTRIES {
            Ok(())
        } else {
            emit(io, o, l)
        }
    };
    loop {
        let wait = deadline.map_or(RECV_WAIT, |d| {
            RECV_WAIT.min(d.saturating_duration_since(Instant::now()))
        });
        match rx.recv_timeout(wait) {
            Ok(Msg::Out(chunk)) => {
                split.push(&chunk, |l| print(io, l));
                if let Err(e) = split.take_error() {
                    let _ = stop(&mut child);
                    return Err(e.into());
                }
                if split.cut > 0 {
                    warn_cut(io, std::mem::take(&mut split.cut))?;
                }
            }
            Ok(Msg::Err(line)) => {
                if denied(&line) {
                    let _ = stop(&mut child);
                    return Ok(Outcome::Failed(access_denied(service, &line)));
                }
                stderr.push_str(&line);
            }
            Ok(Msg::OutEnd) => out_done = true,
            Ok(Msg::ErrEnd) => err_done = true,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => (out_done, err_done) = (true, true),
        }
        if out_done && err_done {
            if let Some(rest) = split.finish() {
                print(io, &rest)?;
            }
            let status = child.wait()?;
            if status.success() {
                return Ok(Outcome::Done);
            }
            return Ok(Outcome::Failed(failed(service, status.code(), &stderr)));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            let stopped = stop(&mut child);
            if let Some(rest) = split.finish() {
                print(io, &rest)?;
            }
            // timeout_ms is how long to follow: reaching it is the normal
            // end, unless journalctl could not be stopped.
            if stopped {
                return Ok(Outcome::Done);
            }
            return Ok(Outcome::Failed(Fail::new(
                exit::TIMEOUT,
                "log.timeout",
                "timeout_ms passed and journalctl could not be stopped; it may still be running",
            )));
        }
    }
}
