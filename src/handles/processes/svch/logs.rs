//! `svc://<service>.logs`: the journal through `journalctl` on systemd, the
//! service's log file through `tail` on OpenRC. Tools run directly (no
//! shell), each value in its own `--name=value` argument. Without follow the
//! tool runs under the deadline (exit 124 past it); with follow its lines are
//! streamed as they arrive and `timeout_ms`, when given, is how long to
//! follow: reaching it ends the command normally.

use super::{Ctx, Fail, Tools};
use crate::core::process;
use crate::core::registry::IoStreams;
use crate::core::status::exit;
use std::ffi::OsStr;
use std::io::{self, BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The line journalctl prints when nothing matched; it is not a log line.
const NO_ENTRIES: &str = "-- No entries --";
const RECV_WAIT: Duration = Duration::from_millis(200);

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

/// journalctl arguments for `unit`.
pub(crate) fn journal_args(unit: &str, o: &LogOpts) -> Vec<String> {
    let mut v = vec![
        format!("--unit={unit}"),
        "--no-pager".to_string(),
        "--output=short-iso".to_string(),
        format!("--lines={}", o.lines),
    ];
    if let Some(s) = &o.since {
        v.push(format!("--since={s}"));
    }
    if let Some(u) = &o.until {
        v.push(format!("--until={u}"));
    }
    if let Some(p) = o.level {
        v.push(format!("--priority={p}"));
    }
    if o.reverse {
        v.push("--reverse".to_string());
    }
    if o.follow {
        v.push("--follow".to_string());
    }
    v
}

/// True when journalctl says it could not read the journal asked for.
fn denied(stderr: &str) -> bool {
    stderr.contains("not seeing messages from other") || stderr.contains("insufficient permissions")
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
    let mut cmd = Command::new(&t.journalctl);
    cmd.args(journal_args(&c.unit, o))
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_PAGER", "");
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

enum Msg {
    Line(String),
    OutEnd,
    Err(String),
}

/// Stops the tool and everything it started. False when something outlived
/// SIGKILL.
fn stop(child: &mut std::process::Child, tool: &str) -> bool {
    let stopped = process::stop_tree(tool, child.id() as libc::pid_t);
    // Reading changes nothing: not an unknown outcome for main to report.
    let _ = process::take_lost();
    let _ = child.try_wait();
    stopped != process::Stopped::StillRunning
}

/// Streams the lines of `cmd` until it exits or `run_for` has passed.
fn follow(
    mut cmd: Command,
    tool: &str,
    unit: &str,
    run_for: Option<Duration>,
    io: &mut IoStreams,
) -> anyhow::Result<Option<Fail>> {
    let deadline = run_for.map(|d| Instant::now() + d);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    process::contain(&mut cmd);
    // SAFETY: prctl takes plain integers and is async-signal-safe. If resh
    // dies (Ctrl-C), the tool is told to stop instead of running on.
    unsafe {
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            Ok(())
        });
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(Some(Fail::new(
                exit::FAILED,
                "svc.tool_not_found",
                format!("{} was not found", cmd.get_program().to_string_lossy()),
            )));
        }
        Err(e) => {
            return Ok(Some(Fail::new(
                exit::FAILED,
                "svc.logs_failed",
                format!("cannot run {tool}: {e}"),
            )));
        }
    };
    let (tx, rx) = mpsc::channel::<Msg>();
    if let Some(out) = child.stdout.take() {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut r = BufReader::new(out);
            let mut buf = Vec::new();
            while matches!(r.read_until(b'\n', &mut buf), Ok(n) if n > 0) {
                let line = String::from_utf8_lossy(&buf)
                    .trim_end_matches(['\n', '\r'])
                    .to_string();
                buf.clear();
                if tx.send(Msg::Line(line)).is_err() {
                    return;
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
            let r = BufReader::new(err);
            for line in r.lines().map_while(Result::ok) {
                if tx.send(Msg::Err(line)).is_err() {
                    return;
                }
            }
        });
    }
    drop(tx);
    let mut stderr = String::new();
    loop {
        let wait = deadline.map_or(RECV_WAIT, |d| {
            RECV_WAIT.min(d.saturating_duration_since(Instant::now()))
        });
        match rx.recv_timeout(wait) {
            Ok(Msg::Line(l)) => {
                if l != NO_ENTRIES {
                    let written = writeln!(io.stdout, "{l}").and_then(|_| io.stdout.flush());
                    if written.is_err() {
                        // The reader went away: stop quietly.
                        let _ = stop(&mut child, tool);
                        return Ok(None);
                    }
                }
            }
            Ok(Msg::Err(line)) => {
                if denied(&line) {
                    let _ = stop(&mut child, tool);
                    return Ok(Some(access_denied(unit, &line)));
                }
                stderr.push_str(&line);
                stderr.push('\n');
            }
            Ok(Msg::OutEnd) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                let status = child.wait()?;
                if status.success() {
                    return Ok(None);
                }
                return Ok(Some(tool_failed(tool, status.code(), &stderr)));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            if stop(&mut child, tool) {
                return Ok(None);
            }
            return Ok(Some(Fail::new(
                exit::TIMEOUT,
                "svc.timeout",
                format!(
                    "timeout_ms passed and {tool} could not be stopped; it may still be running"
                ),
            )));
        }
    }
}
