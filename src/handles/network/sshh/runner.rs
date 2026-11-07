//! Running the system ssh client: deadlines, interrupts, bounded capture.
//!
//! Every ssh run goes through [`run_ssh_process`]. Unit tests install a fake
//! runner per thread, so no test ever starts a real ssh by accident.

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

/// A fully built local command line (ssh, or sshpass running ssh).
#[derive(Debug, Clone, PartialEq)]
pub struct SshCommandLine {
    pub program: String,
    pub args: Vec<String>,
    /// Extra environment variables for the local process.
    pub env: Vec<(String, String)>,
}

impl SshCommandLine {
    /// The remote command (the last argument).
    pub fn remote(&self) -> &str {
        self.args.last().map(String::as_str).unwrap_or("")
    }

    pub fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.args);
        for (k, v) in &self.env {
            command.env(k, v);
        }
        command
    }
}

/// Output of a finished process.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProcessOutput {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// More stdout arrived than `max_stdout` (the rest was discarded).
    pub stdout_overflow: bool,
    /// More stderr arrived than `max_stderr` (the rest was discarded).
    pub stderr_overflow: bool,
}

impl ProcessOutput {
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }

    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).trim().to_string()
    }
}

#[derive(Debug)]
pub enum RunError {
    /// The deadline passed; the process tree was stopped.
    Timeout,
    /// SIGINT or SIGTERM arrived; the process tree was stopped.
    Interrupted,
    /// stdout passed `max_stdout` with `kill_on_overflow`; it was stopped.
    TooLarge,
    Spawn(String, std::io::Error),
    Io(String),
}

/// How to run one process.
#[derive(Debug, Clone, Copy)]
pub struct RunSpec<'a> {
    pub stdin: Option<&'a [u8]>,
    /// Bytes of stdout kept; the rest is read and discarded.
    pub max_stdout: u64,
    pub max_stderr: u64,
    /// Stop the process as soon as stdout passes `max_stdout`.
    pub kill_on_overflow: bool,
    /// Keep stdin open after `stdin` until output arrives.
    pub hold_stdin: bool,
    pub timeout: Option<Duration>,
}

impl Default for RunSpec<'_> {
    fn default() -> Self {
        RunSpec {
            stdin: None,
            max_stdout: 1 << 20,
            max_stderr: 64 * 1024,
            kill_on_overflow: false,
            hold_stdin: false,
            timeout: None,
        }
    }
}

/// Overall deadline of a verb (`timeout_ms`), combined with the per-step
/// limits of each ssh run.
#[derive(Debug, Clone, Copy, Default)]
pub struct Deadline {
    at: Option<Instant>,
}

impl Deadline {
    /// `timeout_ms`: `None` or 0 means no overall limit.
    pub fn new(timeout_ms: Option<u64>) -> Self {
        Deadline {
            at: timeout_ms
                .filter(|ms| *ms > 0)
                .and_then(|ms| Instant::now().checked_add(Duration::from_millis(ms))),
        }
    }

    /// The limit for one step whose own limit is `step_ms` (0 = none).
    pub fn bound(&self, step_ms: u64) -> Option<Duration> {
        let step = (step_ms > 0).then(|| Duration::from_millis(step_ms));
        let left = self
            .at
            .map(|at| at.saturating_duration_since(Instant::now()));
        match (step, left) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    pub fn expired(&self) -> bool {
        self.at.is_some_and(|at| Instant::now() >= at)
    }

    pub fn is_set(&self) -> bool {
        self.at.is_some()
    }
}

// ----------------------------------------------------------- interrupts --

static INTERRUPT: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_signal(signal: libc::c_int) {
    INTERRUPT.store(signal, Ordering::SeqCst);
}

/// Catches SIGINT and SIGTERM while ssh runs in its own process group, so
/// resh can stop it (and report) instead of dying and leaving it behind.
pub struct InterruptGuard {
    previous: [libc::sighandler_t; 2],
}

impl InterruptGuard {
    pub fn install() -> Self {
        let handler = on_signal as *const () as libc::sighandler_t;
        // SAFETY: the handler only stores to an atomic.
        let previous = unsafe {
            [
                libc::signal(libc::SIGINT, handler),
                libc::signal(libc::SIGTERM, handler),
            ]
        };
        InterruptGuard { previous }
    }

    /// True once SIGINT or SIGTERM arrived (and clears nothing).
    pub fn interrupted() -> bool {
        INTERRUPT.load(Ordering::SeqCst) != 0
    }
}

impl Drop for InterruptGuard {
    fn drop(&mut self) {
        // SAFETY: restores the dispositions read in `install`.
        unsafe {
            libc::signal(libc::SIGINT, self.previous[0]);
            libc::signal(libc::SIGTERM, self.previous[1]);
        }
        INTERRUPT.store(0, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------- runner --

#[cfg(test)]
pub type MockSshRunner =
    Box<dyn FnMut(&SshCommandLine, &RunSpec) -> Result<ProcessOutput, RunError>>;

#[cfg(test)]
thread_local! {
    /// Unit tests install a fake ssh here; without one, running ssh fails.
    pub static MOCK_SSH: std::cell::RefCell<Option<MockSshRunner>> =
        const { std::cell::RefCell::new(None) };
}

/// Runs `cmd` under `spec`.
pub fn run_ssh_process(cmd: &SshCommandLine, spec: &RunSpec) -> Result<ProcessOutput, RunError> {
    // A deadline that has already passed: nothing is started.
    if spec.timeout == Some(Duration::ZERO) {
        return Err(RunError::Timeout);
    }
    #[cfg(test)]
    {
        let mut out = MOCK_SSH.with(|m| match m.borrow_mut().as_mut() {
            Some(f) => f(cmd, spec),
            None => Err(RunError::Io("real ssh is disabled in unit tests".into())),
        })?;
        if out.stdout.len() as u64 > spec.max_stdout {
            if spec.kill_on_overflow {
                return Err(RunError::TooLarge);
            }
            out.stdout.truncate(spec.max_stdout as usize);
            out.stdout_overflow = true;
        }
        Ok(out)
    }
    #[cfg(not(test))]
    {
        run_real_process(cmd, spec)
    }
}

/// Reads `pipe` to the end, keeping at most `max` bytes. With `stop` set,
/// returns as soon as more than `max` arrived.
fn drain(mut pipe: impl Read, max: u64, stop_on_overflow: bool) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut overflow = false;
    let mut chunk = [0u8; 16 * 1024];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let room = (max as usize).saturating_sub(kept.len());
                kept.extend_from_slice(&chunk[..n.min(room)]);
                if n > room {
                    overflow = true;
                    if stop_on_overflow {
                        break;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    (kept, overflow)
}

/// Stops `child`'s process group. The outcome is decided by the caller, so
/// the loss is not left for `main` to report a second time.
pub fn stop_child(program: &str, child: &mut Child) {
    crate::core::process::stop_tree(program, child.id() as libc::pid_t);
    let _ = child.try_wait();
    let _ = crate::core::process::take_lost();
}

#[cfg(test)]
pub type MockSpawn = Box<dyn Fn(&SshCommandLine) -> SshCommandLine>;

#[cfg(test)]
thread_local! {
    /// Unit tests map a long-running ssh (tunnel) to a local stand-in.
    pub static MOCK_SPAWN: std::cell::RefCell<Option<MockSpawn>> =
        const { std::cell::RefCell::new(None) };
}

/// Starts a long-running ssh (a tunnel) the way [`spawn`] does.
pub fn spawn_ssh(cmd: &SshCommandLine) -> Result<Child, RunError> {
    #[cfg(test)]
    {
        let sub = MOCK_SPAWN.with(|m| m.borrow().as_ref().map(|f| f(cmd)));
        match sub {
            Some(sub) => spawn(&sub),
            None => Err(RunError::Io("real ssh is disabled in unit tests".into())),
        }
    }
    #[cfg(not(test))]
    {
        spawn(cmd)
    }
}

/// Starts `cmd` in its own process group with piped stdin, stdout, stderr.
pub fn spawn(cmd: &SshCommandLine) -> Result<Child, RunError> {
    let mut command = cmd.command();
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    crate::core::process::contain(&mut command);
    command
        .spawn()
        .map_err(|e| RunError::Spawn(cmd.program.clone(), e))
}

#[cfg(test)]
thread_local! {
    /// The process group a fake exec reports when its run fails.
    pub static MOCK_MARKER_PGID: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

/// Like [`run_ssh_process`], and also watches stderr for a first line
/// `<marker><number>` (the remote process group). The number is returned on
/// success and on failure, since a timed-out command must still be stopped.
pub fn run_with_marker(
    cmd: &SshCommandLine,
    spec: &RunSpec,
    marker: &str,
) -> Result<(ProcessOutput, Option<u32>), (RunError, Option<u32>)> {
    if spec.timeout == Some(Duration::ZERO) {
        return Err((RunError::Timeout, None));
    }
    #[cfg(test)]
    {
        let pgid = MOCK_MARKER_PGID.with(|c| c.get());
        match run_ssh_process(cmd, spec) {
            Ok(out) => {
                let found = parse_marker(&out.stderr, marker).or(pgid);
                Ok((out, found))
            }
            Err(e) => Err((e, pgid)),
        }
    }
    #[cfg(not(test))]
    {
        let seen = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let watch = Some((marker.to_string(), seen.clone()));
        let pgid =
            |s: &std::sync::atomic::AtomicU32| Some(s.load(Ordering::SeqCst)).filter(|n| *n > 0);
        match run_real_inner(cmd, spec, watch) {
            Ok(out) => Ok((out, pgid(&seen))),
            Err(e) => Err((e, pgid(&seen))),
        }
    }
}

/// The number after `marker` on the first line of `stderr`.
pub fn parse_marker(stderr: &[u8], marker: &str) -> Option<u32> {
    let rest = stderr.strip_prefix(marker.as_bytes())?;
    let end = rest.iter().position(|b| *b == b'\n')?;
    std::str::from_utf8(&rest[..end]).ok()?.trim().parse().ok()
}

type Watch = Option<(String, std::sync::Arc<std::sync::atomic::AtomicU32>)>;

/// The real runner (also used directly by tests with local programs).
pub fn run_real_process(cmd: &SshCommandLine, spec: &RunSpec) -> Result<ProcessOutput, RunError> {
    run_real_inner(cmd, spec, None)
}

fn run_real_inner(
    cmd: &SshCommandLine,
    spec: &RunSpec,
    watch: Watch,
) -> Result<ProcessOutput, RunError> {
    let _guard = InterruptGuard::install();
    let mut child = spawn(cmd)?;

    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    let got_output = Arc::new(AtomicBool::new(false));
    let overflowed = Arc::new(AtomicBool::new(false));
    let exited = Arc::new(AtomicBool::new(false));

    // stdin: write the data (if any) and close, so the remote side sees EOF.
    // With `hold_stdin` the pipe stays open until output arrives or the
    // process ends (a server may stop reading at end of file).
    let writer = child.stdin.take().map(|mut pipe| {
        let data = spec.stdin.map(<[u8]>::to_vec).unwrap_or_default();
        let (hold, got, done) = (spec.hold_stdin, got_output.clone(), exited.clone());
        std::thread::spawn(move || {
            let _ = pipe.write_all(&data);
            let _ = pipe.flush();
            while hold && !got.load(Ordering::SeqCst) && !done.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(10));
            }
        })
    });

    let (max_out, kill) = (spec.max_stdout, spec.kill_on_overflow);
    let out_pipe = child.stdout.take();
    let (got, over) = (got_output.clone(), overflowed.clone());
    let out_thread = std::thread::spawn(move || {
        let Some(mut pipe) = out_pipe else {
            return (Vec::new(), false);
        };
        let mut kept = Vec::new();
        let mut overflow = false;
        let mut chunk = [0u8; 16 * 1024];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    got.store(true, Ordering::SeqCst);
                    let room = (max_out as usize).saturating_sub(kept.len());
                    kept.extend_from_slice(&chunk[..n.min(room)]);
                    if n > room {
                        overflow = true;
                        over.store(true, Ordering::SeqCst);
                        if kill {
                            break;
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        (kept, overflow)
    });
    let max_err = spec.max_stderr;
    let err_pipe = child.stderr.take();
    let err_thread = std::thread::spawn(move || match (err_pipe, watch) {
        (Some(p), Some((marker, seen))) => {
            let mut p = std::io::BufReader::new(p);
            let mut first = Vec::new();
            let _ = std::io::BufRead::read_until(&mut p, b'\n', &mut first);
            if let Some(n) = parse_marker(&first, &marker) {
                seen.store(n, Ordering::SeqCst);
            }
            let (rest, overflow) = drain(p, max_err.saturating_sub(first.len() as u64), false);
            first.extend(rest);
            (first, overflow)
        }
        (Some(p), None) => drain(p, max_err, false),
        (None, _) => (Vec::new(), false),
    });

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exited.store(true, Ordering::SeqCst);
                break status;
            }
            Ok(None) => {}
            Err(e) => {
                stop_child(&cmd.program, &mut child);
                return Err(RunError::Io(e.to_string()));
            }
        }
        if kill && overflowed.load(Ordering::SeqCst) {
            stop_child(&cmd.program, &mut child);
            exited.store(true, Ordering::SeqCst);
            return Err(RunError::TooLarge);
        }
        if InterruptGuard::interrupted() {
            stop_child(&cmd.program, &mut child);
            exited.store(true, Ordering::SeqCst);
            return Err(RunError::Interrupted);
        }
        if spec.timeout.is_some_and(|t| start.elapsed() >= t) {
            stop_child(&cmd.program, &mut child);
            exited.store(true, Ordering::SeqCst);
            return Err(RunError::Timeout);
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    // A descendant can hold the pipes open after ssh exited; wait briefly.
    let drained = Instant::now() + Duration::from_secs(2);
    while !(out_thread.is_finished() && err_thread.is_finished()) && Instant::now() < drained {
        std::thread::sleep(Duration::from_millis(10));
    }
    let (stdout, stdout_overflow) = if out_thread.is_finished() {
        out_thread.join().unwrap_or_default()
    } else {
        (Vec::new(), false)
    };
    if kill && stdout_overflow {
        return Err(RunError::TooLarge);
    }
    let (stderr, stderr_overflow) = if err_thread.is_finished() {
        err_thread.join().unwrap_or_default()
    } else {
        (Vec::new(), false)
    };
    if let Some(w) = writer {
        if w.is_finished() {
            let _ = w.join();
        }
    }

    use std::os::unix::process::ExitStatusExt;
    Ok(ProcessOutput {
        exit_code: status.code(),
        signal: status.signal(),
        stdout,
        stderr,
        stdout_overflow,
        stderr_overflow,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> SshCommandLine {
        SshCommandLine {
            program: "sh".into(),
            args: vec!["-c".into(), script.into()],
            env: vec![],
        }
    }

    #[test]
    fn captures_output_exit_code_and_stdin() {
        let out = run_real_process(
            &sh("cat; echo err >&2; exit 3"),
            &RunSpec {
                stdin: Some(b"hello"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(out.exit_code, Some(3));
        assert_eq!(out.stdout, b"hello");
        assert_eq!(out.stderr, b"err\n");
        assert!(!out.stdout_overflow);
    }

    #[test]
    fn output_past_the_limit_is_discarded_without_blocking() {
        let out = run_real_process(
            &sh("head -c 300000 /dev/zero; echo done >&2"),
            &RunSpec {
                max_stdout: 10,
                timeout: Some(Duration::from_secs(10)),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(out.stdout.len(), 10);
        assert!(out.stdout_overflow);
        assert_eq!(out.stderr, b"done\n");
    }

    #[test]
    fn overflow_can_stop_the_process() {
        let start = Instant::now();
        let r = run_real_process(
            &sh("while :; do echo yyyyyyyyyyyyyyyy; done"),
            &RunSpec {
                max_stdout: 1000,
                kill_on_overflow: true,
                timeout: Some(Duration::from_secs(20)),
                ..Default::default()
            },
        );
        assert!(matches!(r, Err(RunError::TooLarge)), "{r:?}");
        assert!(start.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn output_under_the_limit_is_not_too_large_and_stdin_can_be_held() {
        for _ in 0..20 {
            let out = run_real_process(
                &sh("echo small"),
                &RunSpec {
                    max_stdout: 1000,
                    kill_on_overflow: true,
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(out.stdout, b"small\n");
        }
        // The reader answers before it sees end of file.
        let out = run_real_process(
            &sh("head -c 3; echo got"),
            &RunSpec {
                stdin: Some(b"abc"),
                hold_stdin: true,
                timeout: Some(Duration::from_secs(10)),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(out.stdout, b"abcgot\n");
    }

    #[test]
    fn a_timeout_stops_the_whole_tree() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("late");
        let script = format!("(sleep 2; touch '{}') & sleep 30", marker.display());
        let start = Instant::now();
        let r = run_real_process(
            &sh(&script),
            &RunSpec {
                timeout: Some(Duration::from_millis(200)),
                ..Default::default()
            },
        );
        assert!(matches!(r, Err(RunError::Timeout)), "{r:?}");
        assert!(start.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(2500));
        assert!(!marker.exists(), "a child outlived the timeout");
    }

    #[test]
    fn a_missing_program_is_a_spawn_error() {
        let cmd = SshCommandLine {
            program: "resh-no-such-program".into(),
            args: vec![],
            env: vec![],
        };
        match run_real_process(&cmd, &RunSpec::default()) {
            Err(RunError::Spawn(p, e)) => {
                assert_eq!(p, "resh-no-such-program");
                assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn deadline_bounds_each_step() {
        let none = Deadline::new(None);
        assert_eq!(none.bound(0), None);
        assert_eq!(none.bound(500), Some(Duration::from_millis(500)));
        assert!(!none.expired());
        let d = Deadline::new(Some(100));
        assert!(d.bound(0).unwrap() <= Duration::from_millis(100));
        assert!(d.bound(50).unwrap() <= Duration::from_millis(50));
        assert!(Deadline::new(Some(0)).bound(0).is_none());
        std::thread::sleep(Duration::from_millis(120));
        assert!(d.expired());
        assert_eq!(d.bound(1000), Some(Duration::ZERO));
    }
}
