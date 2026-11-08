//! Running external tools under a deadline. Each tool gets its own process
//! group, and this process becomes the subreaper of whatever the tool leaves
//! behind, so a timeout can stop the whole tree and not only the direct child:
//! a dropped future or a killed child would leave the rest running while the
//! caller is told the operation timed out.
//!
//! Stopping a tool does not undo what it already did. A timeout is reported as
//! an unknown outcome, never as a failure without effects, and `main` turns it
//! into exit status 124 whatever the handle made of it. A descendant handed to
//! another manager, such as a job started through systemd, is out of reach.

use std::io::{self, Read};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Bound on the time a tool may run when nothing else says otherwise.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);
/// Bound on each captured stream. Further output is read and discarded.
const MAX_CAPTURE: usize = 64 * 1024 * 1024;
/// Time between SIGTERM and SIGKILL.
const TERM_GRACE: Duration = Duration::from_millis(1500);
/// Time for SIGKILL to take effect.
const KILL_GRACE: Duration = Duration::from_secs(3);
/// Time for streams to end after a tool has exited.
const DRAIN_GRACE: Duration = Duration::from_secs(2);
const POLL: Duration = Duration::from_millis(10);

/// What became of a tool that outlived its deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
pub enum Stopped {
    /// It never started, so it changed nothing.
    NotStarted,
    /// Every process is gone. What it did before that stays done.
    Terminated,
    /// Something outlived SIGKILL and may still be working.
    StillRunning,
}

/// The tool a stage lost to its deadline or an interruption.
#[derive(Debug, Clone)]
pub struct LostTool {
    pub tool: String,
    pub stopped: Stopped,
}

#[cfg(not(test))]
static DEADLINE: Mutex<Option<Instant>> = Mutex::new(None);
#[cfg(test)]
thread_local! {
    // Unit tests share a process: one test's deadline must not reach another.
    static DEADLINE: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
}
static LOST: Mutex<Option<LostTool>> = Mutex::new(None);
static INTERRUPT: AtomicI32 = AtomicI32::new(0);
static SUBREAPER: AtomicBool = AtomicBool::new(false);

#[cfg(not(test))]
fn deadline() -> Option<Instant> {
    DEADLINE.lock().ok().and_then(|d| *d)
}

#[cfg(not(test))]
fn set_deadline(value: Option<Instant>) {
    if let Ok(mut deadline) = DEADLINE.lock() {
        *deadline = value;
    }
}

#[cfg(test)]
fn deadline() -> Option<Instant> {
    DEADLINE.with(|d| d.get())
}

#[cfg(test)]
fn set_deadline(value: Option<Instant>) {
    DEADLINE.with(|d| d.set(value));
}

/// Sets the deadline of the whole operation and returns `limit`, to wrap the
/// value given to `tokio::time::timeout`. A blocking tool never yields to that
/// timer, so this is what ends it.
pub fn limit(limit: Duration) -> Duration {
    // An inner step with a longer limit of its own must not extend this one.
    let requested = Instant::now().checked_add(limit);
    set_deadline(match (deadline(), requested) {
        (Some(current), Some(requested)) => Some(current.min(requested)),
        (current, requested) => current.or(requested),
    });
    limit
}

/// Clears the operation deadline.
pub fn clear_limit() {
    set_deadline(None);
}

/// True when a tool was lost in this stage.
pub fn has_lost() -> bool {
    LOST.lock().is_ok_and(|l| l.is_some())
}

/// The tool lost in this stage, if any.
pub fn take_lost() -> Option<LostTool> {
    LOST.lock().ok()?.take()
}

fn record_lost(tool: &str, stopped: Stopped) {
    if let Ok(mut lost) = LOST.lock() {
        // The worst loss decides: a later step that never started must not
        // hide one that ran, and `Terminated` must not hide `StillRunning`.
        let worse = lost.as_ref().is_none_or(|l| stopped > l.stopped);
        if worse {
            *lost = Some(LostTool {
                tool: tool.to_string(),
                stopped,
            });
        }
    }
}

extern "C" fn on_signal(signal: libc::c_int) {
    INTERRUPT.store(signal, Ordering::SeqCst);
}

/// Forwards SIGINT and SIGTERM while a tool runs. The tool's own process group
/// no longer receives the terminal's signals, so this process must act on them.
struct SignalGuard {
    previous: [libc::sighandler_t; 2],
}

impl SignalGuard {
    fn install() -> Self {
        let handler = on_signal as *const () as libc::sighandler_t;
        // SAFETY: the handler only stores to an atomic.
        let previous = unsafe {
            [
                libc::signal(libc::SIGINT, handler),
                libc::signal(libc::SIGTERM, handler),
            ]
        };
        SignalGuard { previous }
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        // SAFETY: restores the dispositions read in `install`.
        unsafe {
            libc::signal(libc::SIGINT, self.previous[0]);
            libc::signal(libc::SIGTERM, self.previous[1]);
        }
        let signal = INTERRUPT.swap(0, Ordering::SeqCst);
        if signal != 0 {
            // SAFETY: re-delivers the signal now that the tool is stopped.
            unsafe {
                libc::raise(signal);
            }
        }
    }
}

/// Puts `cmd` in a process group of its own, with this process as the
/// subreaper of everything it leaves behind.
pub fn contain(cmd: &mut Command) {
    if !SUBREAPER.swap(true, Ordering::SeqCst) {
        // SAFETY: takes plain integer arguments and changes only this process.
        unsafe {
            libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1);
        }
    }
    cmd.process_group(0);
}

/// Tools being waited on, by group: another tool's tree is not this tool's to
/// signal or reap.
static ACTIVE: Mutex<Vec<libc::pid_t>> = Mutex::new(Vec::new());

/// Holds a tool's group in `ACTIVE` while it is waited on.
struct Active(libc::pid_t);

impl Active {
    fn new(group: libc::pid_t) -> Self {
        if let Ok(mut active) = ACTIVE.lock() {
            active.push(group);
        }
        Active(group)
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        if let Ok(mut active) = ACTIVE.lock() {
            active.retain(|group| *group != self.0);
        }
    }
}

#[cfg(not(test))]
fn other_tools(group: libc::pid_t) -> Vec<libc::pid_t> {
    let mut others = ACTIVE.lock().map(|a| a.clone()).unwrap_or_default();
    others.retain(|other| *other != group);
    others
}

/// Live and exited descendants of this process, found through /proc so that a
/// process that left the tool's group with `setsid` is included. Other tools
/// and everything under them are left out.
#[cfg(test)]
fn tree(_group: libc::pid_t) -> Vec<(libc::pid_t, bool)> {
    // Unit tests share a process with tests that run tools of their own.
    Vec::new()
}

#[cfg(not(test))]
fn tree(group: libc::pid_t) -> Vec<(libc::pid_t, bool)> {
    let others = other_tools(group);
    let mut parents: Vec<(libc::pid_t, libc::pid_t, bool)> = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse().ok()) else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // The command name is in parentheses and may hold anything.
        let Some(rest) = stat.rfind(')').map(|i| &stat[i + 1..]) else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        let state = fields.next().unwrap_or("Z");
        let parent = fields.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        if !others.contains(&pid) {
            parents.push((pid, parent, state == "Z" || state == "X"));
        }
    }
    let mut found = vec![(std::process::id() as libc::pid_t, false)];
    let mut next = 0;
    while next < found.len() {
        let parent = found[next].0;
        next += 1;
        found.extend(
            parents
                .iter()
                .filter(|(_, p, _)| *p == parent)
                .map(|(pid, _, exited)| (*pid, *exited)),
        );
    }
    found.remove(0);
    found
}

fn descendants(group: libc::pid_t) -> Vec<libc::pid_t> {
    tree(group)
        .into_iter()
        .filter(|(_, exited)| !exited)
        .map(|(pid, _)| pid)
        .collect()
}

fn signal_tree(group: libc::pid_t, signal: libc::c_int) {
    // SAFETY: signals a process group this process created and its own
    // descendants.
    unsafe {
        libc::kill(-group, signal);
        for pid in descendants(group) {
            libc::kill(pid, signal);
        }
    }
}

/// Collects the tool's group and what it left to this process, and nothing
/// else: waiting on any child would take another tool's exit status from it.
fn reap(group: libc::pid_t) {
    let mut status = 0;
    // SAFETY: `status` is a valid out pointer.
    unsafe {
        while libc::waitpid(-group, &mut status, libc::WNOHANG) > 0 {}
        for (pid, exited) in tree(group) {
            if exited {
                libc::waitpid(pid, &mut status, libc::WNOHANG);
            }
        }
    }
}

fn tree_gone(group: libc::pid_t, until: Instant) -> bool {
    loop {
        reap(group);
        // SAFETY: signal 0 only tests for existence.
        let group_gone = unsafe { libc::kill(-group, 0) } != 0;
        if group_gone && descendants(group).is_empty() {
            return true;
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(POLL);
    }
}

/// Stops the tool in group `group` and everything it started, and records it.
pub fn stop_tree(tool: &str, group: libc::pid_t) -> Stopped {
    signal_tree(group, libc::SIGTERM);
    let mut gone = tree_gone(group, Instant::now() + TERM_GRACE);
    if !gone {
        signal_tree(group, libc::SIGKILL);
        gone = tree_gone(group, Instant::now() + KILL_GRACE);
    }
    let stopped = if gone {
        Stopped::Terminated
    } else {
        Stopped::StillRunning
    };
    record_lost(tool, stopped);
    stopped
}

fn capture(stream: Option<impl Read + Send + 'static>) -> (Arc<Mutex<Vec<u8>>>, Arc<AtomicBool>) {
    let data = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let (writer, finished) = (data.clone(), done.clone());
    std::thread::spawn(move || {
        if let Some(mut stream) = stream {
            let mut chunk = [0u8; 8192];
            while let Ok(n) = stream.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                if let Ok(mut data) = writer.lock() {
                    let room = MAX_CAPTURE.saturating_sub(data.len());
                    data.extend_from_slice(&chunk[..n.min(room)]);
                }
            }
        }
        finished.store(true, Ordering::SeqCst);
    });
    (data, done)
}

fn taken(data: &Arc<Mutex<Vec<u8>>>) -> Vec<u8> {
    data.lock()
        .map(|mut d| std::mem::take(&mut *d))
        .unwrap_or_default()
}

fn lost_error(tool: &str, stopped: Stopped) -> io::Error {
    let state = match stopped {
        Stopped::NotStarted => "was not started",
        Stopped::Terminated => "was stopped",
        Stopped::StillRunning => "could not be stopped",
    };
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("{tool} timed out and {state}"),
    )
}

/// The time `requested` leaves under the operation deadline.
fn remaining(requested: Option<Duration>) -> Duration {
    let requested = requested.unwrap_or(DEFAULT_TIMEOUT);
    match deadline() {
        Some(deadline) => requested.min(deadline.saturating_duration_since(Instant::now())),
        None => requested,
    }
}

/// Waits for `child`, stopping its tree at the deadline or on a signal.
fn wait(child: &mut Child, tool: &str, limit: Duration) -> io::Result<ExitStatus> {
    let group = child.id() as libc::pid_t;
    let _active = Active::new(group);
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        let interrupted = INTERRUPT.load(Ordering::SeqCst) != 0;
        if interrupted || start.elapsed() >= limit {
            let stopped = stop_tree(tool, group);
            let _ = child.try_wait();
            return Err(lost_error(tool, stopped));
        }
        std::thread::sleep(POLL);
    }
}

/// Runs `cmd` to completion with captured output. `timeout` is further bounded
/// by the operation deadline. Past either one, the tool's whole tree is stopped
/// and the error kind is `TimedOut`.
pub fn run(cmd: &mut Command, timeout: Option<Duration>) -> io::Result<Output> {
    let tool = cmd.get_program().to_string_lossy().into_owned();
    let limit = remaining(timeout);
    if limit.is_zero() {
        record_lost(&tool, Stopped::NotStarted);
        return Err(lost_error(&tool, Stopped::NotStarted));
    }
    contain(cmd);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let guard = SignalGuard::install();
    let mut child = cmd.spawn()?;
    let (out, out_done) = capture(child.stdout.take());
    let (err, err_done) = capture(child.stderr.take());
    let status = wait(&mut child, &tool, limit)?;
    // A descendant can hold a stream open after the tool itself has exited.
    let drained = Instant::now() + DRAIN_GRACE;
    while !(out_done.load(Ordering::SeqCst) && err_done.load(Ordering::SeqCst))
        && Instant::now() < drained
    {
        std::thread::sleep(POLL);
    }
    drop(guard);
    Ok(Output {
        status,
        stdout: taken(&out),
        stderr: taken(&err),
    })
}

/// `Command::output` under the rules of `run`.
pub trait BoundedOutput {
    fn bounded_output(&mut self) -> io::Result<Output>;
}

impl BoundedOutput for Command {
    fn bounded_output(&mut self) -> io::Result<Output> {
        run(self, None)
    }
}

/// `tokio::process::Command::output` under the rules of `run`. It blocks: a
/// future dropped by `tokio::time::timeout` would abandon the tool.
pub trait AsyncBoundedOutput {
    fn bounded_output(&mut self) -> std::future::Ready<io::Result<Output>>;
}

impl AsyncBoundedOutput for tokio::process::Command {
    fn bounded_output(&mut self) -> std::future::Ready<io::Result<Output>> {
        std::future::ready(run(self.as_std_mut(), None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_timeout_leaves_other_tools_alone() {
        let workers: Vec<_> = (0..8)
            .map(|i| {
                std::thread::spawn(move || {
                    for _ in 0..25 {
                        if i == 0 {
                            let mut slow = Command::new("sleep");
                            slow.arg("5");
                            let stopped = run(&mut slow, Some(Duration::from_millis(20)));
                            assert_eq!(stopped.unwrap_err().kind(), io::ErrorKind::TimedOut);
                        } else {
                            let done = run(&mut Command::new("true"), None).unwrap();
                            assert!(done.status.success());
                        }
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    }
}
