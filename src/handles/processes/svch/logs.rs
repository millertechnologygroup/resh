//! `svc://<service>.logs`: the journal through `journalctl` on systemd, the
//! service's log file through `tail` on OpenRC. Tools run directly (no
//! shell), each value in its own `--name=value` argument (see
//! `core::journal`, shared with `log://svc/<service>`). Without follow the
//! tool runs under the deadline (exit 124 past it); with follow its lines are
//! streamed as they arrive and `timeout_ms`, when given, is how long to
//! follow: reaching it ends the command normally.

use super::{Ctx, Fail, Tools};
use crate::core::journal::{self as cj, End, Event, Flow, NO_ENTRIES, Query, denied};
use crate::core::process;
use crate::core::registry::IoStreams;
use crate::core::status::exit;
use std::ffi::OsStr;
use std::io;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LogOpts {
    pub lines: u64,
    pub since: Option<String>,
    pub until: Option<String>,
    pub level: Option<&'static str>,
    pub reverse: bool,
    pub follow: bool,
    /// With follow: how long to follow (`None`: until interrupted).
    pub follow_for: Option<Duration>,
}

fn query<'a>(unit: &'a str, o: &'a LogOpts) -> Query<'a> {
    Query {
        unit,
        lines: o.lines,
        output: "short-iso",
        since: o.since.as_deref(),
        until: o.until.as_deref(),
        priority: o.level,
        reverse: o.reverse,
        follow: o.follow,
    }
}

/// journalctl arguments for `unit`.
#[cfg(test)]
pub(crate) fn journal_args(unit: &str, o: &LogOpts) -> Vec<String> {
    query(unit, o).args()
}

fn access_denied(unit: &str, stderr: &str) -> Fail {
    Fail::new(
        exit::FAILED,
        "svc.permission_denied",
        format!(
            "cannot read the journal of {unit} (membership in the systemd-journal or adm \
             group is usually needed): {}",
            stderr.trim()
        ),
    )
}

fn tool_failed(tool: &str, status: Option<i32>, stderr: &str) -> Fail {
    let status = status.map_or("a signal".to_string(), |c| format!("status {c}"));
    Fail::new(
        exit::FAILED,
        "svc.logs_failed",
        format!("{tool} failed (exit {status}): {}", stderr.trim()),
    )
}

fn print_lines(io: &mut IoStreams, lines: &[&str]) -> io::Result<()> {
    for l in lines {
        writeln!(io.stdout, "{l}")?;
    }
    io.stdout.flush()
}

pub(crate) fn journal(
    t: &Tools,
    c: &Ctx,
    o: &LogOpts,
    io: &mut IoStreams,
) -> anyhow::Result<Option<Fail>> {
    let mut cmd = query(&c.unit, o).command(&t.journalctl);
    if o.follow {
        return follow(cmd, "journalctl", &c.unit, o.follow_for, io);
    }
    let out = match run_cmd(&mut cmd, &t.journalctl, c) {
        Ok(o) => o,
        Err(f) => return Ok(Some(f)),
    };
    let stderr = String::from_utf8_lossy(&out.stderr);
    if denied(&stderr) {
        return Ok(Some(access_denied(&c.unit, &stderr)));
    }
    if !out.status.success() {
        return Ok(Some(tool_failed("journalctl", out.status.code(), &stderr)));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = text.lines().filter(|l| *l != NO_ENTRIES).collect();
    print_lines(io, &lines)?;
    Ok(None)
}

/// Runs a prepared command under the deadline, mapping the failures.
fn run_cmd(cmd: &mut Command, tool: &OsStr, c: &Ctx) -> Result<std::process::Output, Fail> {
    let remaining = c.deadline.saturating_duration_since(Instant::now());
    match process::run(cmd, Some(remaining)) {
        Ok(o) => Ok(o),
        Err(e) if e.kind() == io::ErrorKind::TimedOut => {
            // Reading changes nothing: a plain timeout.
            let _ = process::take_lost();
            Err(Fail::new(
                exit::TIMEOUT,
                "svc.timeout",
                format!(
                    "timeout_ms={} passed before {} finished",
                    c.timeout_ms,
                    tool.to_string_lossy()
                ),
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(Fail::new(
            exit::FAILED,
            "svc.tool_not_found",
            format!("{} was not found", tool.to_string_lossy()),
        )),
        Err(e) => Err(Fail::new(
            exit::FAILED,
            "svc.logs_failed",
            format!("cannot run {}: {e}", tool.to_string_lossy()),
        )),
    }
}

/// The log files checked on OpenRC, in order.
pub(crate) fn openrc_candidates(name: &str) -> [String; 3] {
    [
        format!("/var/log/{name}.log"),
        format!("/var/log/{name}/{name}.log"),
        format!("/var/log/{name}/current"),
    ]
}

pub(crate) fn openrc(
    t: &Tools,
    c: &Ctx,
    o: &LogOpts,
    io: &mut IoStreams,
) -> anyhow::Result<Option<Fail>> {
    let candidates = openrc_candidates(&c.name);
    let root = t.log_root.as_deref().unwrap_or(Path::new("/"));
    let found = candidates
        .iter()
        .map(|p| root.join(p.trim_start_matches('/')))
        .find(|p| p.is_file());
    let Some(file) = found else {
        return Ok(Some(Fail::new(
            exit::FAILED,
            "svc.no_logs",
            format!(
                "no log file found for service '{}' (checked {})",
                c.name,
                candidates.join(", ")
            ),
        )));
    };
    let mut cmd = Command::new(&t.tail);
    cmd.arg("-n").arg(o.lines.to_string());
    if o.follow {
        cmd.arg("-F");
    }
    cmd.arg("--").arg(&file);
    if o.follow {
        return follow(cmd, "tail", &c.name, o.follow_for, io);
    }
    let out = match run_cmd(&mut cmd, &t.tail, c) {
        Ok(o) => o,
        Err(f) => return Ok(Some(f)),
    };
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Ok(Some(tool_failed("tail", out.status.code(), &stderr)));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines: Vec<&str> = text.lines().collect();
    if o.reverse {
        lines.reverse();
    }
    print_lines(io, &lines)?;
    Ok(None)
}

/// Writes the complete lines in `buf`, keeping a partial last line.
fn flush_lines(buf: &mut Vec<u8>, io: &mut IoStreams) -> io::Result<()> {
    while let Some(i) = buf.iter().position(|b| *b == b'\n') {
        let line: Vec<u8> = buf.drain(..=i).collect();
        let text = String::from_utf8_lossy(&line[..i]);
        let text = text.trim_end_matches('\r');
        if text != NO_ENTRIES {
            writeln!(io.stdout, "{text}")?;
        }
    }
    io.stdout.flush()
}

/// Streams the lines of `cmd` until it exits or `run_for` has passed.
fn follow(
    cmd: Command,
    tool: &str,
    unit: &str,
    run_for: Option<Duration>,
    io: &mut IoStreams,
) -> anyhow::Result<Option<Fail>> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let deadline = run_for.map(|d| Instant::now() + d);
    let mut buf = Vec::new();
    let mut denied_line = None;
    let mut reader_gone = false;
    let end = cj::follow(cmd, tool, deadline, |ev| match ev {
        Event::Out(chunk) => {
            buf.extend_from_slice(chunk);
            if flush_lines(&mut buf, io).is_err() {
                // The reader went away: stop quietly.
                reader_gone = true;
                return Ok(Flow::Stop);
            }
            Ok(Flow::Continue)
        }
        Event::Err(line) if denied(line) => {
            denied_line = Some(line.to_string());
            Ok(Flow::Stop)
        }
        Event::Err(_) => Ok(Flow::Continue),
    })?;
    if let Some(line) = denied_line {
        return Ok(Some(access_denied(unit, &line)));
    }
    if reader_gone {
        return Ok(None);
    }
    if !buf.is_empty() {
        buf.push(b'\n');
        let _ = flush_lines(&mut buf, io);
    }
    Ok(match end {
        End::SpawnFailed(e) if e.kind() == io::ErrorKind::NotFound => Some(Fail::new(
            exit::FAILED,
            "svc.tool_not_found",
            format!("{program} was not found"),
        )),
        End::SpawnFailed(e) => Some(Fail::new(
            exit::FAILED,
            "svc.logs_failed",
            format!("cannot run {tool}: {e}"),
        )),
        End::Exited(status, _) if status.success() => None,
        End::Exited(status, stderr) => Some(tool_failed(tool, status.code(), &stderr)),
        End::Deadline { stopped: true } | End::Stopped => None,
        End::Deadline { stopped: false } => Some(Fail::new(
            exit::TIMEOUT,
            "svc.timeout",
            format!("timeout_ms passed and {tool} could not be stopped; it may still be running"),
        )),
    })
}
