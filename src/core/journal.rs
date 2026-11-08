//! Shared `journalctl` invocation for handles that read the systemd journal
//! (`log://svc/<service>` and `svc://<service>.logs`): the argument list,
//! the environment, the messages journalctl uses for "nothing matched" and
//! "not allowed", and a follow loop that streams a tool's output until it
//! exits or a deadline passes, then stops it and everything it started.
//!
//! Each value goes in its own `--name=value` argument; no shell is used.

use crate::core::process;
use std::ffi::OsStr;
use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The line journalctl prints when nothing matched; it is not a log line.
pub const NO_ENTRIES: &str = "-- No entries --";
/// Longest wait for output between deadline checks.
const RECV_WAIT: Duration = Duration::from_millis(200);

/// What to ask journalctl for.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Query<'a> {
    pub unit: &'a str,
    pub lines: u64,
    /// The `--output` format (`short`, `short-iso`, ...).
    pub output: &'a str,
    pub since: Option<&'a str>,
    pub until: Option<&'a str>,
    /// A journalctl priority (`err`, `warning`, ...).
    pub priority: Option<&'a str>,
    pub reverse: bool,
    pub follow: bool,
}

impl Query<'_> {
    /// The journalctl arguments, in a fixed order.
    pub fn args(&self) -> Vec<String> {
        let mut v = vec![
            format!("--unit={}", self.unit),
            format!("--lines={}", self.lines),
            "--no-pager".to_string(),
            format!("--output={}", self.output),
        ];
        if let Some(s) = self.since {
            v.push(format!("--since={s}"));
        }
        if let Some(u) = self.until {
            v.push(format!("--until={u}"));
        }
        if let Some(p) = self.priority {
            v.push(format!("--priority={p}"));
        }
        if self.reverse {
            v.push("--reverse".to_string());
        }
        if self.follow {
            v.push("--follow".to_string());
        }
        v
    }

    /// The journalctl command (`journalctl` is the program to run).
    pub fn command(&self, journalctl: &OsStr) -> Command {
        let mut cmd = Command::new(journalctl);
        cmd.args(self.args())
            .env("SYSTEMD_COLORS", "0")
            .env("SYSTEMD_PAGER", "");
        cmd
    }
}

/// True when journalctl says it could not read the journal it was asked for
/// (it can still exit 0 then, so no lines would mean nothing was read).
pub fn denied(stderr: &str) -> bool {
    stderr.contains("not seeing messages from other") || stderr.contains("insufficient permissions")
}

/// Output of a followed tool, handed to the caller as it arrives.
pub enum Event<'a> {
    /// A chunk of stdout (not split into lines).
    Out(&'a [u8]),
    /// One line of stderr, with its newline.
    Err(&'a str),
}

/// What the caller wants after an event.
pub enum Flow {
    Continue,
    /// Stop the tool and return [`End::Stopped`].
    Stop,
}

/// How a follow ended.
#[derive(Debug)]
pub enum End {
    /// The tool could not be started.
    SpawnFailed(io::Error),
    /// The tool exited by itself; its stderr is attached.
    Exited(ExitStatus, String),
    /// The deadline passed; `stopped` is false when something outlived
    /// SIGKILL.
    Deadline { stopped: bool },
    /// The caller asked to stop; the tool was stopped.
    Stopped,
}

enum Msg {
    Out(Vec<u8>),
    OutEnd,
    Err(String),
    ErrEnd,
}

/// Stops the tool and everything it started, without leaving the loss for
/// `main` to report as an unknown outcome (reading changes nothing). False
/// when something outlived SIGKILL.
fn stop(child: &mut Child, tool: &str) -> bool {
    let stopped = process::stop_tree(tool, child.id() as libc::pid_t);
    let _ = process::take_lost();
    let _ = child.try_wait();
    stopped != process::Stopped::StillRunning
}

/// Runs `cmd` and hands its output to `on` until it exits, `deadline`
/// passes or `on` asks to stop. The tool gets its own process group (and is
/// told to stop if resh dies); at the end it and everything it started are
/// stopped. An error from `on` stops the tool and is returned.
pub fn follow<F>(
    mut cmd: Command,
    tool: &str,
    deadline: Option<Instant>,
    mut on: F,
) -> io::Result<End>
where
    F: FnMut(Event) -> io::Result<Flow>,
{
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    process::contain(&mut cmd);
    // SAFETY: prctl takes plain integers; it is async-signal-safe. If resh
    // dies (Ctrl-C), the tool is told to stop instead of running on.
    unsafe {
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            Ok(())
        });
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return Ok(End::SpawnFailed(e)),
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

    let mut stderr = String::new();
    let (mut out_done, mut err_done) = (false, false);
    loop {
        let wait = deadline.map_or(RECV_WAIT, |d| {
            RECV_WAIT.min(d.saturating_duration_since(Instant::now()))
        });
        let flow = match rx.recv_timeout(wait) {
            Ok(Msg::Out(chunk)) => on(Event::Out(&chunk)),
            Ok(Msg::Err(line)) => {
                let f = on(Event::Err(&line));
                stderr.push_str(&line);
                f
            }
            Ok(Msg::OutEnd) => {
                out_done = true;
                Ok(Flow::Continue)
            }
            Ok(Msg::ErrEnd) => {
                err_done = true;
                Ok(Flow::Continue)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(Flow::Continue),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                (out_done, err_done) = (true, true);
                Ok(Flow::Continue)
            }
        };
        match flow {
            Ok(Flow::Continue) => {}
            Ok(Flow::Stop) => {
                let _ = stop(&mut child, tool);
                return Ok(End::Stopped);
            }
            Err(e) => {
                let _ = stop(&mut child, tool);
                return Err(e);
            }
        }
        if out_done && err_done {
            let status = child.wait()?;
            return Ok(End::Exited(status, stderr));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            let stopped = stop(&mut child, tool);
            return Ok(End::Deadline { stopped });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_in_fixed_order() {
        let q = Query {
            unit: "a.service",
            lines: 5,
            output: "short-iso",
            since: Some("-1h"),
            until: Some("now"),
            priority: Some("err"),
            reverse: true,
            follow: false,
        };
        assert_eq!(
            q.args(),
            [
                "--unit=a.service",
                "--lines=5",
                "--no-pager",
                "--output=short-iso",
                "--since=-1h",
                "--until=now",
                "--priority=err",
                "--reverse"
            ]
        );
    }

    #[test]
    fn follow_streams_and_stops_at_the_deadline() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo a; echo oops >&2; echo b; exec sleep 30"]);
        let (mut out, mut err) = (Vec::new(), String::new());
        let start = Instant::now();
        let end = follow(
            cmd,
            "sh",
            Some(Instant::now() + Duration::from_millis(500)),
            |e| {
                match e {
                    Event::Out(b) => out.extend_from_slice(b),
                    Event::Err(l) => err.push_str(l),
                }
                Ok(Flow::Continue)
            },
        )
        .unwrap();
        assert!(matches!(end, End::Deadline { stopped: true }), "{end:?}");
        assert!(start.elapsed() < Duration::from_secs(5));
        assert_eq!(out, b"a\nb\n");
        assert_eq!(err, "oops\n");

        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo x; echo y >&2; exit 3"]);
        match follow(cmd, "sh", None, |_| Ok(Flow::Continue)).unwrap() {
            End::Exited(st, stderr) => {
                assert_eq!(st.code(), Some(3));
                assert_eq!(stderr, "y\n");
            }
            other => panic!("{other:?}"),
        }
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo x; exec sleep 30"]);
        let end = follow(cmd, "sh", None, |_| Ok(Flow::Stop)).unwrap();
        assert!(matches!(end, End::Stopped));
        let end = follow(Command::new("/nonexistent/tool"), "x", None, |_| {
            Ok(Flow::Continue)
        })
        .unwrap();
        assert!(matches!(end, End::SpawnFailed(_)));
    }
}
