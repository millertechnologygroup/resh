//! `log://svc/<service>`: the service's journal through `journalctl`, run
//! directly (no shell) with each value in its own `--name=value` argument
//! (see `core::journal`). Without follow, journalctl runs under the core
//! process deadline (`timeout_ms`, default 600000); with follow, its output
//! is streamed until it exits or the deadline passes, and its whole process
//! tree is stopped.

use super::scan::LineSplitter;
use super::{Fail, LogHandle, Outcome, TailOpts, emit, warn_cut};
use crate::core::journal::{self as cj, End, Event, Flow, NO_ENTRIES, Query, denied};
use crate::core::process;
use crate::core::registry::IoStreams;
use crate::core::status::exit;
use anyhow::Result;
use std::io;
use std::process::Command;
use std::time::Instant;

fn query(service: &str, lines: usize, follow: bool) -> Query<'_> {
    Query {
        unit: service,
        lines: lines as u64,
        output: "short",
        follow,
        ..Query::default()
    }
}

/// Arguments for `journalctl`.
#[cfg(test)]
pub(crate) fn args(service: &str, lines: usize, follow: bool) -> Vec<String> {
    query(service, lines, follow).args()
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
    query(service, o.lines, o.follow).command(&h.journalctl)
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
    let print = |io: &mut IoStreams, l: &str| {
        if l == NO_ENTRIES {
            Ok(())
        } else {
            emit(io, o, l)
        }
    };
    let mut split = LineSplitter::default();
    let mut denied_line: Option<String> = None;
    let end = cj::follow(
        command(h, service, o),
        "journalctl",
        deadline,
        |ev| match ev {
            Event::Out(chunk) => {
                split.push(chunk, |l| print(io, l));
                split.take_error()?;
                if split.cut > 0 {
                    warn_cut(io, std::mem::take(&mut split.cut)).map_err(io::Error::other)?;
                }
                Ok(Flow::Continue)
            }
            Event::Err(line) if denied(line) => {
                denied_line = Some(line.to_string());
                Ok(Flow::Stop)
            }
            Event::Err(_) => Ok(Flow::Continue),
        },
    )?;
    if let Some(line) = denied_line {
        return Ok(Outcome::Failed(access_denied(service, &line)));
    }
    match end {
        End::SpawnFailed(e) if e.kind() == io::ErrorKind::NotFound => {
            Ok(Outcome::Failed(not_found(h)))
        }
        End::SpawnFailed(e) => Ok(Outcome::Failed(Fail::new(
            exit::FAILED,
            "log.journal_failed",
            format!("cannot run {}: {e}", h.journalctl.to_string_lossy()),
        ))),
        End::Exited(status, stderr) => {
            if let Some(rest) = split.finish() {
                print(io, &rest)?;
            }
            if status.success() {
                Ok(Outcome::Done)
            } else {
                Ok(Outcome::Failed(failed(service, status.code(), &stderr)))
            }
        }
        End::Deadline { stopped } => {
            if let Some(rest) = split.finish() {
                print(io, &rest)?;
            }
            // timeout_ms is how long to follow: reaching it is the normal
            // end, unless journalctl could not be stopped.
            if stopped {
                Ok(Outcome::Done)
            } else {
                Ok(Outcome::Failed(Fail::new(
                    exit::TIMEOUT,
                    "log.timeout",
                    "timeout_ms passed and journalctl could not be stopped; it may still be running",
                )))
            }
        }
        End::Stopped => Ok(Outcome::Done),
    }
}
