//! `proc://<pid|self>`: signals, nice values and resource limits of one
//! process. Verbs that change something refuse the resh process itself.
//!
//! Every verb checks its arguments (one accepted-options list per verb,
//! [`verb_args`]) and the target PID before it makes a system call, so an
//! invalid call changes nothing (exit 2). Failures are reported as
//! `proc.<code>` (see [`ERROR_CODES`]) on stderr and in the JSON written to
//! stdout. Every verb is a few system calls on one process (and its
//! threads), so none takes `timeout_ms`.

use serde_json::{Map, Value, json};
use url::Url;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::{Status, exit},
};

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("proc", |u| Ok(Box::new(ProcHandle::from_url(u)?)));
    reg.set_probe_url("proc", "proc://self");
}

/// Metadata for `resh proc --help` and `resh proc <verb> --help`.
static PROC_HELP: HandleHelp = HandleHelp {
    description: "The proc handle sends signals to a running process, reads and changes \
        the nice value of every thread of it through getpriority and setpriority, and \
        sets its resource limits through prlimit. The target is a numeric process ID, \
        such as proc://1234, or self (the resh process itself), which only nice.get \
        accepts.",
    usage: "resh proc://<pid|self>.<verb>[(key=value,...)]",
    verbs: &[
        VerbHelp {
            name: "nice.get",
            definition: "Reports the current nice value of a process.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid|self>.nice.get",
                example: "resh --json-pretty proc://1234.nice.get",
                example_output: Some(
                    r#"{
  "nice": 0,
  "pid": 1234
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "signal",
            definition: "Sends a signal, given by name or number, to a process.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid>.signal sig=<name|number>",
                example: "resh --json-pretty proc://1234.signal sig=TERM",
                example_output: Some(
                    r#"{
  "ok": true,
  "pid": 1234,
  "signal": "TERM",
  "signal_num": 15,
  "verb": "signal"
}

Shown with --json-pretty. Accepted names are HUP, INT, QUIT, KILL, TERM,
STOP, CONT, USR1, USR2, PIPE, ALRM, and CHLD, with or without SIG, in
any case. Numbers go from 0 (checks that the process exists, sends
nothing) to the highest real-time signal (64 on Linux)."#,
                ),
            }),
        },
        VerbHelp {
            name: "term",
            definition: "Sends SIGTERM to a process to request graceful termination.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid>.term",
                example: "resh --json-pretty proc://1234.term",
                example_output: Some(
                    r#"{
  "ok": true,
  "pid": 1234,
  "signal": "TERM",
  "signal_num": 15,
  "verb": "term"
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "int",
            definition: "Sends SIGINT to a process, like pressing Ctrl+C.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid>.int",
                example: "resh --json-pretty proc://1234.int",
                example_output: Some(
                    r#"{
  "ok": true,
  "pid": 1234,
  "signal": "INT",
  "signal_num": 2,
  "verb": "int"
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "hup",
            definition: "Sends SIGHUP to a process, which many daemons treat as a reload request.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid>.hup",
                example: "resh --json-pretty proc://1234.hup",
                example_output: Some(
                    r#"{
  "ok": true,
  "pid": 1234,
  "signal": "HUP",
  "signal_num": 1,
  "verb": "hup"
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "kill",
            definition: "Sends SIGKILL to a process to terminate it immediately.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid>.kill",
                example: "resh --json-pretty proc://1234.kill",
                example_output: Some(
                    r#"{
  "ok": true,
  "pid": 1234,
  "signal": "KILL",
  "signal_num": 9,
  "verb": "kill"
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "stop",
            definition: "Sends SIGSTOP to a process to pause it.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid>.stop",
                example: "resh --json-pretty proc://1234.stop",
                example_output: Some(
                    r#"{
  "ok": true,
  "pid": 1234,
  "signal": "STOP",
  "signal_num": 19,
  "verb": "stop"
}

Shown for Linux with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "cont",
            definition: "Sends SIGCONT to a process to resume it after a stop.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid>.cont",
                example: "resh --json-pretty proc://1234.cont",
                example_output: Some(
                    r#"{
  "ok": true,
  "pid": 1234,
  "signal": "CONT",
  "signal_num": 18,
  "verb": "cont"
}

Shown for Linux with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "usr1",
            definition: "Sends SIGUSR1 to a process.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid>.usr1",
                example: "resh --json-pretty proc://1234.usr1",
                example_output: Some(
                    r#"{
  "ok": true,
  "pid": 1234,
  "signal": "USR1",
  "signal_num": 10,
  "verb": "usr1"
}

Shown for Linux with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "usr2",
            definition: "Sends SIGUSR2 to a process.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid>.usr2",
                example: "resh --json-pretty proc://1234.usr2",
                example_output: Some(
                    r#"{
  "ok": true,
  "pid": 1234,
  "signal": "USR2",
  "signal_num": 12,
  "verb": "usr2"
}

Shown for Linux with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "nice.set",
            definition: "Sets the nice value of every thread of a process to a value from \
                -20 to 19.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid>.nice.set value=<-20..19>",
                example: "resh --json-pretty proc://1234.nice.set value=10",
                example_output: Some(
                    r#"{
  "changed": true,
  "nice": 10,
  "pid": 1234,
  "threads": [
    {
      "changed": true,
      "nice_after": 10,
      "nice_before": 0,
      "status": "ok",
      "tid": 1234
    }
  ]
}

Shown with --json-pretty for a single-threaded process. Lowering a
nice value usually requires root. If some threads fail, the others
keep their new value and the call fails with proc.partial_failure."#,
                ),
            }),
        },
        VerbHelp {
            name: "nice.inc",
            definition: "Raises the nice value of every thread of a process by a delta, \
                lowering its priority.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid>.nice.inc delta=<0..39>",
                example: "resh --json-pretty proc://1234.nice.inc delta=5",
                example_output: Some(
                    r#"{
  "changed": true,
  "delta": 5,
  "nice_after": 5,
  "nice_before": 0,
  "pid": 1234,
  "threads": [
    {
      "changed": true,
      "nice_after": 5,
      "nice_before": 0,
      "status": "ok",
      "tid": 1234
    }
  ]
}

Shown with --json-pretty. Each thread moves from its own value; if any
would leave -20..19, the call is refused and nothing is changed."#,
                ),
            }),
        },
        VerbHelp {
            name: "nice.dec",
            definition: "Lowers the nice value of every thread of a process by a delta, \
                raising its priority.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid>.nice.dec delta=<0..39>",
                example: "resh --json-pretty proc://1234.nice.dec delta=5",
                example_output: Some(
                    r#"{
  "changed": true,
  "delta": 5,
  "nice_after": 5,
  "nice_before": 10,
  "pid": 1234,
  "threads": [
    {
      "changed": true,
      "nice_after": 5,
      "nice_before": 10,
      "status": "ok",
      "tid": 1234
    }
  ]
}

Shown with --json-pretty. Lowering a nice value usually requires root.
If any thread would leave -20..19, nothing is changed."#,
                ),
            }),
        },
        VerbHelp {
            name: "setPriority",
            definition: "Sets the nice value of every thread of a process from a named \
                priority class or an explicit nice value.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid>.setPriority\n  \
                    [class=idle|background|normal|high|realtime] [nice=<-20..19>]",
                example: "resh --json-pretty proc://1234.setPriority class=background",
                example_output: Some(
                    r#"{
  "backend": "linux-setpriority",
  "class": "background",
  "nice": 10,
  "pid": 1234,
  "previous_nice": 0,
  "threads": [
    {
      "changed": true,
      "nice_after": 10,
      "nice_before": 0,
      "status": "ok",
      "tid": 1234
    }
  ]
}

Shown with --json-pretty. Classes map to nice values idle=19,
background=10, normal=0 (the default), high=-5, and realtime=-10;
nice overrides class. No real-time scheduling policy is set."#,
                ),
            }),
        },
        VerbHelp {
            name: "limits.set",
            definition: "Sets the soft and hard resource limits of a process through \
                prlimit.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid|self>.limits.set <resource>=<soft>[:<hard>] ...\n  \
                    [pid=<n>] [dry_run=true|false]\n  \
                    resources: cpu as data stack core nofile fsize memlock nproc",
                example: "resh --json-pretty proc://1234.limits.set nofile=1024 dry_run=true",
                example_output: Some(
                    r#"{
  "backend": "prlimit",
  "dry_run": true,
  "pid": 1234,
  "results": {
    "nofile": {
      "after": {
        "hard": 524288,
        "soft": 1024
      },
      "before": {
        "hard": 524288,
        "soft": 1024
      },
      "changed": false,
      "requested": "1024",
      "status": "ok"
    }
  }
}

Shown with --json-pretty. A value is a number, unlimited, a number with
an s suffix (cpu only, seconds), or with K, M, or G (powers of 1000);
an empty side keeps the current value. pid=<n> names the target when
the URL is self; the resh process itself is refused."#,
                ),
            }),
        },
    ],
};

// ---------------------------------------------------------------------------
// Arguments and errors
// ---------------------------------------------------------------------------

/// Every error code `proc` reports (without the `proc.` prefix). The
/// dispatcher also reports `proc.invalid_target` for a target that is not
/// `self` or a valid PID, before the handle is built; the handle reports it
/// for a changing verb aimed at the resh process itself.
pub(crate) const ERROR_CODES: &[&str] = &[
    "invalid_argument",
    "invalid_target",
    "not_found",
    "permission_denied",
    "partial_failure",
    "unknown_verb",
    "failed",
    "unsupported_platform",
];

/// The resources `limits.set` accepts, in the order they are applied.
const RESOURCES: &[&str] = &[
    "cpu", "as", "data", "stack", "core", "nofile", "fsize", "memlock", "nproc",
];

const SIGNAL_ARGS: &[&str] = &["sig"];
const NO_ARGS: &[&str] = &[];
const NICE_SET_ARGS: &[&str] = &["value"];
const NICE_DELTA_ARGS: &[&str] = &["delta"];
const SET_PRIORITY_ARGS: &[&str] = &["class", "nice"];
const LIMITS_SET_ARGS: &[&str] = &[
    "pid", "dry_run", "cpu", "as", "data", "stack", "core", "nofile", "fsize", "memlock", "nproc",
];

/// The arguments `verb` accepts, or `None` for an unknown verb.
fn verb_args(verb: &str) -> Option<&'static [&'static str]> {
    Some(match verb {
        "signal" => SIGNAL_ARGS,
        "kill" | "term" | "int" | "hup" | "stop" | "cont" | "usr1" | "usr2" | "nice.get" => NO_ARGS,
        "nice.set" => NICE_SET_ARGS,
        "nice.inc" | "nice.dec" => NICE_DELTA_ARGS,
        "setPriority" => SET_PRIORITY_ARGS,
        "limits.set" => LIMITS_SET_ARGS,
        _ => return None,
    })
}

/// A failure: exit code, error code (without `proc.`) and message.
#[derive(Debug)]
struct Fail {
    exit: i32,
    code: &'static str,
    detail: String,
}

impl Fail {
    fn new(exit: i32, code: &'static str, detail: impl Into<String>) -> Self {
        debug_assert!(ERROR_CODES.contains(&code), "undocumented code {code}");
        Self {
            exit,
            code,
            detail: detail.into(),
        }
    }

    /// Invalid usage (exit 2): nothing was done.
    fn invalid(detail: impl Into<String>) -> Self {
        Self::new(exit::USAGE, "invalid_argument", detail)
    }

    fn failed(code: &'static str, detail: impl Into<String>) -> Self {
        Self::new(exit::FAILED, code, detail)
    }

    fn error_obj(&self) -> Value {
        crate::core::status::error_json(&format!("proc.{}", self.code), &self.detail)
    }

    fn status(&self, verb: &str) -> Status {
        Status::coded(
            self.exit,
            &format!("proc.{}", self.code),
            format!("proc {verb}: {}", self.detail),
        )
    }
}

/// Refuses any argument `verb` does not take, before anything is done.
fn check_args(verb: &str, allowed: &[&'static str], args: &Args) -> Result<(), Fail> {
    let mut keys: Vec<&String> = args.keys().collect();
    keys.sort();
    let Some(bad) = keys.into_iter().find(|k| !allowed.contains(&k.as_str())) else {
        return Ok(());
    };
    Err(Fail::invalid(match bad.as_str() {
        "timeout_ms" => {
            format!("timeout_ms is not accepted: {verb} returns at once; nothing was done")
        }
        "dry_run" => format!("{verb} does not support dry_run; nothing was done"),
        _ if verb == "limits.set" => format!(
            "unknown resource or argument: {bad}{} (resources: {}); nothing was done",
            hint(bad, allowed),
            RESOURCES.join(", ")
        ),
        _ => format!(
            "unknown argument for {verb}: {bad}{}{}; nothing was done",
            hint(bad, allowed),
            if allowed.is_empty() {
                " (this verb takes no arguments)".to_string()
            } else {
                format!(" (accepted: {})", allowed.join(", "))
            }
        ),
    }))
}

/// ` (did you mean `x`?)` for the candidate closest to `bad`, or "".
fn hint(bad: &str, candidates: &[&str]) -> String {
    suggest(bad, candidates)
        .map(|s| format!(" (did you mean `{s}`?)"))
        .unwrap_or_default()
}

/// The candidate closest to `bad` (edit distance at most 2 after lowercasing
/// and `-` to `_`), for a "did you mean" hint.
fn suggest<'a>(bad: &str, candidates: &[&'a str]) -> Option<&'a str> {
    fn distance(a: &str, b: &str) -> usize {
        let b: Vec<char> = b.chars().collect();
        let mut prev: Vec<usize> = (0..=b.len()).collect();
        for (i, ca) in a.chars().enumerate() {
            let mut cur = vec![i + 1; b.len() + 1];
            for (j, cb) in b.iter().enumerate() {
                let cost = usize::from(ca != *cb);
                cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
            }
            prev = cur;
        }
        prev[b.len()]
    }
    let lower = bad.to_ascii_lowercase().replace('-', "_");
    candidates
        .iter()
        .map(|c| (distance(&lower, &c.to_ascii_lowercase()), *c))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c)
}

/// Integer argument `key` in `min..=max`; `None` when absent.
fn int_arg(args: &Args, key: &str, min: i64, max: i64) -> Result<Option<i64>, Fail> {
    let Some(raw) = args.get(key) else {
        return Ok(None);
    };
    match raw.parse::<i64>() {
        Ok(v) if (min..=max).contains(&v) => Ok(Some(v)),
        _ => Err(Fail::invalid(format!(
            "invalid value for {key}: {raw:?} (expected an integer from {min} to {max}); \
             nothing was done"
        ))),
    }
}

/// Required integer argument `key` in `min..=max`.
fn required_int(args: &Args, key: &str, min: i64, max: i64) -> Result<i64, Fail> {
    int_arg(args, key, min, max)?.ok_or_else(|| {
        Fail::invalid(format!(
            "missing argument: {key}=<{min}..{max}>; nothing was done"
        ))
    })
}

/// Enumerated argument `key`; `default` when absent.
fn choice_arg<'a>(
    args: &'a Args,
    key: &str,
    choices: &[&str],
    default: &'a str,
) -> Result<&'a str, Fail> {
    match args.get(key) {
        None => Ok(default),
        Some(v) if choices.contains(&v.as_str()) => Ok(v.as_str()),
        Some(v) => Err(Fail::invalid(format!(
            "invalid value for {key}: {v:?}{} (expected {}); nothing was done",
            hint(v, choices),
            choices.join(", ")
        ))),
    }
}

/// Parse a single target PID. Only 1..=pid_t::MAX is accepted: zero, negative
/// values and anything that would wrap on conversion address process groups
/// or every process (`kill(-1, ..)`), never one process.
fn parse_pid(s: &str) -> anyhow::Result<libc::pid_t> {
    let bad = || {
        anyhow::anyhow!(
            "invalid pid: {s:?} (expected self or 1..{})",
            libc::pid_t::MAX
        )
    };
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let pid: u64 = s.parse().map_err(|_| bad())?;
    if pid == 0 {
        return Err(anyhow::anyhow!("invalid pid: must be positive"));
    }
    libc::pid_t::try_from(pid).map_err(|_| {
        anyhow::anyhow!(
            "invalid pid: {} is out of range (max {})",
            s,
            libc::pid_t::MAX
        )
    })
}

// ---------------------------------------------------------------------------
// System calls
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
// rlim_t is u64 on 64-bit targets only; the casts keep 32-bit builds working.
#[allow(clippy::unnecessary_cast)]
mod sys {
    use super::Fail;

    /// The `Fail` for a failed system call on `pid`.
    fn os_fail(what: &str, pid: libc::pid_t, err: std::io::Error) -> Fail {
        match err.raw_os_error() {
            Some(libc::ESRCH) => Fail::failed("not_found", format!("no process with pid {pid}")),
            Some(libc::EPERM) | Some(libc::EACCES) => Fail::failed(
                "permission_denied",
                format!("{what} on pid {pid}: permission denied ({err})"),
            ),
            _ => Fail::failed("failed", format!("{what} on pid {pid} failed: {err}")),
        }
    }

    pub fn get_nice(pid: libc::pid_t) -> Result<i32, Fail> {
        // getpriority can return -1 as a valid value: errno tells.
        nix::errno::Errno::clear();
        let v = unsafe { libc::getpriority(libc::PRIO_PROCESS, pid as libc::id_t) };
        if v == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error().unwrap_or(0) != 0 {
                return Err(os_fail("getpriority", pid, err));
            }
        }
        Ok(v)
    }

    pub fn set_nice(pid: libc::pid_t, value: i32) -> Result<(), Fail> {
        let r = unsafe { libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, value) };
        if r != 0 {
            return Err(os_fail("setpriority", pid, std::io::Error::last_os_error()));
        }
        Ok(())
    }

    pub fn kill(pid: libc::pid_t, sig: libc::c_int) -> Result<(), Fail> {
        if unsafe { libc::kill(pid, sig) } != 0 {
            return Err(os_fail("kill", pid, std::io::Error::last_os_error()));
        }
        Ok(())
    }

    pub fn sig_rt_range() -> (libc::c_int, libc::c_int) {
        (libc::SIGRTMIN(), libc::SIGRTMAX())
    }

    pub fn resource(name: &str) -> Option<libc::c_int> {
        Some(match name {
            "cpu" => libc::RLIMIT_CPU as libc::c_int,
            "as" => libc::RLIMIT_AS as libc::c_int,
            "data" => libc::RLIMIT_DATA as libc::c_int,
            "stack" => libc::RLIMIT_STACK as libc::c_int,
            "core" => libc::RLIMIT_CORE as libc::c_int,
            "nofile" => libc::RLIMIT_NOFILE as libc::c_int,
            "fsize" => libc::RLIMIT_FSIZE as libc::c_int,
            "memlock" => libc::RLIMIT_MEMLOCK as libc::c_int,
            "nproc" => libc::RLIMIT_NPROC as libc::c_int,
            _ => return None,
        })
    }

    pub const INFINITY: u64 = libc::RLIM_INFINITY as u64;

    /// The (soft, hard) limits of `pid` for `res`.
    pub fn get_limit(pid: libc::pid_t, res: libc::c_int) -> Result<(u64, u64), Fail> {
        let mut old = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::prlimit(pid, res as _, std::ptr::null(), &mut old) } != 0 {
            return Err(os_fail("prlimit", pid, std::io::Error::last_os_error()));
        }
        Ok((old.rlim_cur as u64, old.rlim_max as u64))
    }

    pub fn set_limit(pid: libc::pid_t, res: libc::c_int, soft: u64, hard: u64) -> Result<(), Fail> {
        let new = libc::rlimit {
            rlim_cur: soft as libc::rlim_t,
            rlim_max: hard as libc::rlim_t,
        };
        if unsafe { libc::prlimit(pid, res as _, &new, std::ptr::null_mut()) } != 0 {
            return Err(os_fail("prlimit", pid, std::io::Error::last_os_error()));
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod sys {
    use super::Fail;

    fn unsupported() -> Fail {
        Fail::failed("unsupported_platform", "proc:// is supported on Linux only")
    }
    pub fn get_nice(_: libc::pid_t) -> Result<i32, Fail> {
        Err(unsupported())
    }
    pub fn set_nice(_: libc::pid_t, _: i32) -> Result<(), Fail> {
        Err(unsupported())
    }
    pub fn kill(_: libc::pid_t, _: libc::c_int) -> Result<(), Fail> {
        Err(unsupported())
    }
    pub fn sig_rt_range() -> (libc::c_int, libc::c_int) {
        (0, 31)
    }
    pub fn resource(name: &str) -> Option<libc::c_int> {
        super::RESOURCES
            .iter()
            .position(|r| *r == name)
            .map(|i| i as libc::c_int)
    }
    pub const INFINITY: u64 = u64::MAX;
    pub fn get_limit(_: libc::pid_t, _: libc::c_int) -> Result<(u64, u64), Fail> {
        Err(unsupported())
    }
    pub fn set_limit(_: libc::pid_t, _: libc::c_int, _: u64, _: u64) -> Result<(), Fail> {
        Err(unsupported())
    }
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

/// The signal named by `sig` (a name, with or without `SIG`, in any case, or
/// a number from 0 to SIGRTMAX), as (label, number).
fn parse_signal_arg(sig: &str) -> Result<(String, libc::c_int), Fail> {
    let (_, rt_max) = sys::sig_rt_range();
    if !sig.is_empty() && sig.bytes().all(|b| b.is_ascii_digit()) {
        return match sig.parse::<libc::c_int>() {
            Ok(n) if (0..=rt_max).contains(&n) => Ok((signal_label(n), n)),
            _ => Err(Fail::invalid(format!(
                "invalid signal number: {sig} (expected 0..{rt_max}); nothing was done"
            ))),
        };
    }
    let upper = sig.to_ascii_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    match ACCEPTED_SIGNALS.iter().find(|(n, _)| *n == name) {
        Some((n, num)) => Ok((n.to_string(), *num)),
        None => {
            let names: Vec<&str> = ACCEPTED_SIGNALS.iter().map(|(n, _)| *n).collect();
            Err(Fail::invalid(format!(
                "invalid signal: {sig:?}{} (names: {}, or a number); nothing was done",
                hint(name, &names),
                names.join(", ")
            )))
        }
    }
}

/// The signal names `signal sig=` accepts.
const ACCEPTED_SIGNALS: &[(&str, libc::c_int)] = &[
    ("HUP", libc::SIGHUP),
    ("INT", libc::SIGINT),
    ("QUIT", libc::SIGQUIT),
    ("KILL", libc::SIGKILL),
    ("TERM", libc::SIGTERM),
    ("STOP", libc::SIGSTOP),
    ("CONT", libc::SIGCONT),
    ("USR1", libc::SIGUSR1),
    ("USR2", libc::SIGUSR2),
    ("PIPE", libc::SIGPIPE),
    ("ALRM", libc::SIGALRM),
    ("CHLD", libc::SIGCHLD),
];

/// Signal names by number, from the platform's libc constants (Linux
/// numbering on Linux: 10 = USR1, 12 = USR2, 17 = CHLD, 19 = STOP).
const SIGNAL_NAMES: &[(&str, libc::c_int)] = &[
    ("HUP", libc::SIGHUP),
    ("INT", libc::SIGINT),
    ("QUIT", libc::SIGQUIT),
    ("ILL", libc::SIGILL),
    ("TRAP", libc::SIGTRAP),
    ("ABRT", libc::SIGABRT),
    ("BUS", libc::SIGBUS),
    ("FPE", libc::SIGFPE),
    ("KILL", libc::SIGKILL),
    ("USR1", libc::SIGUSR1),
    ("SEGV", libc::SIGSEGV),
    ("USR2", libc::SIGUSR2),
    ("PIPE", libc::SIGPIPE),
    ("ALRM", libc::SIGALRM),
    ("TERM", libc::SIGTERM),
    ("CHLD", libc::SIGCHLD),
    ("CONT", libc::SIGCONT),
    ("STOP", libc::SIGSTOP),
    ("TSTP", libc::SIGTSTP),
    ("TTIN", libc::SIGTTIN),
    ("TTOU", libc::SIGTTOU),
    ("URG", libc::SIGURG),
    ("XCPU", libc::SIGXCPU),
    ("XFSZ", libc::SIGXFSZ),
    ("VTALRM", libc::SIGVTALRM),
    ("PROF", libc::SIGPROF),
    ("WINCH", libc::SIGWINCH),
    ("IO", libc::SIGIO),
    ("SYS", libc::SIGSYS),
    #[cfg(any(target_os = "linux", target_os = "android"))]
    ("PWR", libc::SIGPWR),
    #[cfg(any(target_os = "linux", target_os = "android"))]
    ("STKFLT", libc::SIGSTKFLT),
];

/// Name for a signal number: `NULL` for 0, `RTMIN+<n>` for real-time
/// signals, or `UNKNOWN`.
fn signal_label(num: libc::c_int) -> String {
    if num == 0 {
        return "NULL".to_string();
    }
    if let Some((name, _)) = SIGNAL_NAMES.iter().find(|(_, n)| *n == num) {
        return name.to_string();
    }
    let (rt_min, rt_max) = sys::sig_rt_range();
    if (rt_min..=rt_max).contains(&num) {
        return format!("RTMIN+{}", num - rt_min);
    }
    "UNKNOWN".to_string()
}

// ---------------------------------------------------------------------------
// The handle
// ---------------------------------------------------------------------------

pub struct ProcHandle {
    name: String, // Can be a PID or "self"
}

impl ProcHandle {
    pub fn from_url(u: &Url) -> anyhow::Result<Self> {
        // Accept host + path, strip leading slashes, parse as PID or "self"
        let mut name = String::new();
        if let Some(h) = u.host_str() {
            name.push_str(h);
        }
        if !u.path().is_empty() {
            if !name.is_empty() {
                name.push('/');
            }
            name.push_str(u.path().trim_start_matches('/'));
        }

        if name.is_empty() {
            return Err(anyhow::anyhow!("invalid pid: missing"));
        }

        // Allow "self", numeric PID, or an in-URL help flag (proc://--help)
        if name == "self" || crate::core::help::is_help_flag(&name) {
            Ok(Self { name })
        } else {
            parse_pid(&name)?;
            Ok(Self { name })
        }
    }

    /// Resolve the name to an actual PID
    fn resolve_pid(&self) -> anyhow::Result<libc::pid_t> {
        if self.name == "self" {
            libc::pid_t::try_from(std::process::id())
                .map_err(|_| anyhow::anyhow!("invalid pid: own pid out of range"))
        } else {
            parse_pid(&self.name)
        }
    }

    /// Display the approved proc help (same text as `resh proc [<verb>] --help`).
    fn display_help(&self, verb: Option<&str>, io: &mut IoStreams) -> anyhow::Result<Status> {
        let text = crate::core::help::render_legacy("proc", &PROC_HELP, self.verbs(), verb);
        write!(io.stdout, "{}", text)?;
        Ok(Status::ok())
    }
}

/// What a verb prints on success.
enum Output {
    Json(Value),
}

/// A failed verb: the error, plus fields printed with it (for example the
/// per-resource results of `limits.set`).
struct Failure {
    fail: Fail,
    extra: Map<String, Value>,
}

impl From<Fail> for Failure {
    fn from(fail: Fail) -> Self {
        Self {
            fail,
            extra: Map::new(),
        }
    }
}

type VerbResult = Result<Output, Failure>;

impl Handle for ProcHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &[
            "signal",
            "kill",
            "term",
            "int",
            "hup",
            "stop",
            "cont",
            "usr1",
            "usr2",
            "nice.get",
            "nice.set",
            "nice.inc",
            "nice.dec",
            "setPriority",
            "limits.set",
        ]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&PROC_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        if should_show_help(verb, args) {
            // `proc://1234.kill(help=1)` shows the help of `kill`.
            let topic = args
                .get("verb")
                .map(String::as_str)
                .or_else(|| verb_args(verb).map(|_| verb));
            return self.display_help(topic, io);
        }
        let pid = self.resolve_pid().ok();
        let result = self.run(verb, args);
        match result {
            Ok(Output::Json(v)) => {
                writeln!(io.stdout, "{v}")?;
                Ok(Status::ok())
            }
            Err(Failure { fail, extra }) => {
                let mut obj = Map::new();
                obj.insert("pid".into(), json!(pid));
                obj.insert("verb".into(), json!(verb));
                obj.insert("ok".into(), json!(false));
                obj.extend(extra);
                obj.insert("error".into(), fail.error_obj());
                writeln!(io.stdout, "{}", Value::Object(obj))?;
                Ok(fail.status(verb))
            }
        }
    }
}

impl ProcHandle {
    /// Checks the verb, its arguments and the target, then runs the verb.
    fn run(&self, verb: &str, args: &Args) -> VerbResult {
        let Some(allowed) = verb_args(verb) else {
            let why = if verb == "io.peek" {
                " (io.peek was removed: it read log files that nothing writes)".to_string()
            } else {
                hint(verb, self.verbs())
            };
            return Err(Fail::new(
                exit::USAGE,
                "unknown_verb",
                format!(
                    "unknown verb: {verb}{why} (verbs: {})",
                    self.verbs().join(", ")
                ),
            )
            .into());
        };
        check_args(verb, allowed, args)?;
        let pid = self
            .resolve_pid()
            .map_err(|e| Fail::new(exit::USAGE, "invalid_target", e.to_string()))?;
        // Only reading is allowed on resh itself; limits.set checks its
        // effective target (the URL or pid=) itself.
        if verb != "nice.get" && verb != "limits.set" {
            refuse_self(verb, pid)?;
        }
        match verb {
            "signal" | "kill" | "term" | "int" | "hup" | "stop" | "cont" | "usr1" | "usr2" => {
                verb_signal(pid, verb, args)
            }
            "nice.get" => {
                let nice = sys::get_nice(pid)?;
                Ok(Output::Json(json!({"pid": pid, "nice": nice})))
            }
            "nice.set" => verb_nice_set(pid, args),
            "nice.inc" => verb_nice_delta(pid, args, 1),
            "nice.dec" => verb_nice_delta(pid, args, -1),
            "setPriority" => verb_set_priority(pid, args),
            "limits.set" => verb_limits_set(pid, self.name == "self", args),
            _ => unreachable!("verb_args lists every verb"),
        }
    }
}

fn verb_signal(pid: libc::pid_t, verb: &str, args: &Args) -> VerbResult {
    let (name, num) = match verb {
        "signal" => {
            let sig = args.get("sig").ok_or_else(|| {
                Fail::invalid("missing argument: sig=<name|number>; nothing was done")
            })?;
            parse_signal_arg(sig)?
        }
        "kill" => ("KILL".to_string(), libc::SIGKILL),
        "term" => ("TERM".to_string(), libc::SIGTERM),
        "int" => ("INT".to_string(), libc::SIGINT),
        "hup" => ("HUP".to_string(), libc::SIGHUP),
        "stop" => ("STOP".to_string(), libc::SIGSTOP),
        "cont" => ("CONT".to_string(), libc::SIGCONT),
        "usr1" => ("USR1".to_string(), libc::SIGUSR1),
        "usr2" => ("USR2".to_string(), libc::SIGUSR2),
        _ => unreachable!("signal verbs only"),
    };
    sys::kill(pid, num).map_err(|fail| {
        let mut extra = Map::new();
        extra.insert("signal".into(), json!(name));
        extra.insert("signal_num".into(), json!(num));
        Failure { fail, extra }
    })?;
    Ok(Output::Json(json!({
        "pid": pid,
        "verb": verb,
        "signal": name,
        "signal_num": num,
        "ok": true
    })))
}

/// Refuses `verb` when `pid` is the resh process itself: a change to it
/// ends with resh a moment later, and a signal could stop or kill resh.
fn refuse_self(verb: &str, pid: libc::pid_t) -> Result<(), Fail> {
    if u32::try_from(pid).ok() == Some(std::process::id()) {
        return Err(Fail::new(
            exit::USAGE,
            "invalid_target",
            format!(
                "{verb} does not act on the resh process itself (pid {pid}); \
                 name another process; nothing was done"
            ),
        ));
    }
    Ok(())
}

/// The thread IDs of `pid` (from /proc/<pid>/task), the main thread first.
/// Without /proc, the main thread alone.
fn thread_ids(pid: libc::pid_t) -> Result<Vec<libc::pid_t>, Fail> {
    let dir = format!("/proc/{pid}/task");
    match std::fs::read_dir(&dir) {
        Ok(entries) => {
            let mut tids: Vec<libc::pid_t> = entries
                .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
                .filter(|t| *t != pid)
                .collect();
            tids.sort_unstable();
            tids.insert(0, pid);
            Ok(tids)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // No such process, or no /proc: getpriority tells which.
            sys::get_nice(pid)?;
            Ok(vec![pid])
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Err(Fail::failed(
            "permission_denied",
            format!("cannot list the threads of pid {pid} ({dir}): {e}"),
        )),
        Err(e) => Err(Fail::failed(
            "failed",
            format!("cannot list the threads of pid {pid} ({dir}): {e}"),
        )),
    }
}

/// The result of changing the nice value of every thread.
struct Renice {
    main_before: i32,
    main_after: i32,
    changed: bool,
    threads: Vec<Value>,
}

/// Sets each thread of `pid` to `target(its current value)`. Every target is
/// worked out (and may be refused) before any thread is changed. A thread
/// that ends meanwhile is reported as `gone`. If some threads fail, the
/// others keep their new value and the call fails with `partial_failure`;
/// if every change failed, with the first thread's error.
fn renice_threads(
    pid: libc::pid_t,
    target: impl Fn(i32) -> Result<i32, Fail>,
) -> Result<Renice, Failure> {
    let tids = thread_ids(pid)?;
    // Read every thread, then check every target: still no change.
    let mut plan = Vec::new();
    for tid in tids {
        match sys::get_nice(tid) {
            Ok(before) => plan.push((tid, before, target(before)?)),
            // The main thread decides whether the process exists.
            Err(f) if tid == pid => return Err(f.into()),
            Err(f) if f.code == "not_found" => {} // the thread ended
            Err(f) => return Err(f.into()),
        }
    }
    let (main_before, main_after) = (plan[0].1, plan[0].2);
    let mut threads = Vec::new();
    let mut changed = 0usize;
    let mut failures: Vec<Fail> = Vec::new();
    for (tid, before, after) in plan {
        let mut entry = json!({
            "tid": tid,
            "nice_before": before,
            "nice_after": after,
            "changed": before != after,
            "status": "ok"
        });
        if before != after {
            match sys::set_nice(tid, after) {
                Ok(()) => changed += 1,
                Err(f) => {
                    entry["nice_after"] = json!(before);
                    entry["changed"] = json!(false);
                    if f.code == "not_found" && tid != pid {
                        entry["status"] = json!("gone");
                    } else {
                        entry["status"] = json!("error");
                        entry["error"] = f.error_obj();
                        failures.push(f);
                    }
                }
            }
        }
        threads.push(entry);
    }
    if failures.is_empty() {
        return Ok(Renice {
            main_before,
            main_after,
            changed: changed > 0,
            threads,
        });
    }
    let n = failures.len();
    let total = threads.len();
    let first = failures.swap_remove(0);
    let fail = if changed == 0 {
        Fail {
            detail: if n > 1 {
                format!("{} (and {} more threads)", first.detail, n - 1)
            } else {
                first.detail
            },
            ..first
        }
    } else {
        Fail::failed(
            "partial_failure",
            format!(
                "{n} of {total} threads were not changed (first: {}); the other \
                 changed threads keep their new value",
                first.detail
            ),
        )
    };
    let mut extra = Map::new();
    extra.insert("threads".into(), Value::Array(threads));
    Err(Failure { fail, extra })
}

fn verb_nice_set(pid: libc::pid_t, args: &Args) -> VerbResult {
    let value = required_int(args, "value", -20, 19)? as i32;
    let r = renice_threads(pid, |_| Ok(value))?;
    Ok(Output::Json(json!({
        "pid": pid,
        "nice": value,
        "changed": r.changed,
        "threads": r.threads
    })))
}

/// `nice.inc` (`sign` 1) and `nice.dec` (`sign` -1): each thread moves by
/// `delta` from its own value.
fn verb_nice_delta(pid: libc::pid_t, args: &Args, sign: i32) -> VerbResult {
    let delta = required_int(args, "delta", 0, 39)? as i32;
    let r = renice_threads(pid, |before| {
        let after = before + sign * delta;
        if (-20..=19).contains(&after) {
            Ok(after)
        } else {
            Err(Fail::invalid(format!(
                "a nice value would be {after} ({before} {} {delta}), outside -20..19; \
                 nothing was done",
                if sign > 0 { "+" } else { "-" }
            )))
        }
    })?;
    Ok(Output::Json(json!({
        "pid": pid,
        "nice_before": r.main_before,
        "nice_after": r.main_after,
        "delta": delta,
        "changed": r.changed,
        "threads": r.threads
    })))
}

const CLASSES: &[(&str, i32)] = &[
    ("idle", 19),
    ("background", 10),
    ("normal", 0),
    ("high", -5),
    ("realtime", -10),
];

fn verb_set_priority(pid: libc::pid_t, args: &Args) -> VerbResult {
    let names: Vec<&str> = CLASSES.iter().map(|(n, _)| *n).collect();
    let class = choice_arg(args, "class", &names, "normal")?;
    let (nice, class) = match int_arg(args, "nice", -20, 19)? {
        Some(n) => {
            let n = n as i32;
            let label = CLASSES
                .iter()
                .find(|(_, v)| *v == n)
                .map_or("custom", |(c, _)| c);
            (n, label)
        }
        None => (CLASSES.iter().find(|(c, _)| *c == class).unwrap().1, class),
    };
    let r = renice_threads(pid, |_| Ok(nice))?;
    Ok(Output::Json(json!({
        "pid": pid,
        "class": class,
        "nice": nice,
        "previous_nice": r.main_before,
        "backend": "linux-setpriority",
        "threads": r.threads
    })))
}

// ---------------------------------------------------------------------------
// limits.set
// ---------------------------------------------------------------------------

/// One side of a limit value: `None` keeps the current value.
type Side = Option<u64>;

/// Parses `<soft>[:<hard>]` for `resource`.
fn parse_limit_spec(resource: &str, value: &str) -> Result<(Side, Side), Fail> {
    let bad = |why: &str| {
        Fail::invalid(format!(
            "invalid value for {resource}: {value:?} ({why}); nothing was done"
        ))
    };
    let (soft, hard) = match value.split_once(':') {
        Some((s, h)) => (s, Some(h)),
        None => (value, None),
    };
    let side = |s: &str| -> Result<Side, Fail> {
        if s.is_empty() {
            return Ok(None);
        }
        parse_single_limit(resource, s)
            .map(Some)
            .map_err(|why| bad(&why))
    };
    let soft_v = if hard.is_none() && soft.is_empty() {
        return Err(bad("expected <soft>[:<hard>]"));
    } else {
        side(soft)?
    };
    let hard_v = match hard {
        Some(h) => side(h)?,
        None => None,
    };
    if soft_v.is_none() && hard_v.is_none() {
        return Err(bad("give a soft limit, a hard limit or both"));
    }
    Ok((soft_v, hard_v))
}

/// A number, `unlimited`, `<n>s` (cpu only) or `<n>K|M|G` (powers of 1000).
fn parse_single_limit(resource: &str, s: &str) -> Result<u64, String> {
    if s == "unlimited" {
        return Ok(sys::INFINITY);
    }
    let (digits, mult) = match s.as_bytes().last() {
        Some(b's') if resource == "cpu" => (&s[..s.len() - 1], 1),
        Some(b's') => return Err("the s suffix is for cpu only".to_string()),
        Some(b'K') => (&s[..s.len() - 1], 1_000),
        Some(b'M') => (&s[..s.len() - 1], 1_000_000),
        Some(b'G') => (&s[..s.len() - 1], 1_000_000_000),
        _ => (s, 1),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err("expected a number, unlimited, or a number with a suffix".to_string());
    }
    digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .filter(|n| *n < sys::INFINITY)
        .ok_or_else(|| "number too large (use unlimited)".to_string())
}

fn verb_limits_set(url_pid: libc::pid_t, url_is_self: bool, args: &Args) -> VerbResult {
    // Everything is checked before any limit is read or changed.
    let pid = match args.get("pid") {
        None => url_pid,
        Some(raw) => {
            let p =
                parse_pid(raw).map_err(|e| Fail::invalid(format!("pid: {e}; nothing was done")))?;
            if !url_is_self && p != url_pid {
                return Err(Fail::invalid(format!(
                    "pid={p} disagrees with the target proc://{url_pid}; nothing was done"
                ))
                .into());
            }
            p
        }
    };
    refuse_self("limits.set", pid)?;
    limits_set_for(pid, args).map_err(|mut f| {
        f.extra.entry("pid").or_insert(json!(pid));
        f
    })
}

fn limits_set_for(pid: libc::pid_t, args: &Args) -> VerbResult {
    let dry_run = crate::core::lenient::dry_run(args)
        .map_err(|e| Fail::invalid(format!("{e}; nothing was done")))?;
    let mut specs = Vec::new();
    for name in RESOURCES {
        if let Some(value) = args.get(*name) {
            let res = sys::resource(name).ok_or_else(|| {
                Fail::failed(
                    "unsupported_platform",
                    format!("{name} limits are not supported on this platform"),
                )
            })?;
            specs.push((*name, res, value, parse_limit_spec(name, value)?));
        }
    }
    if specs.is_empty() {
        return Err(Fail::invalid(format!(
            "no resource given: pass <resource>=<soft>[:<hard>] (resources: {}); \
             nothing was done",
            RESOURCES.join(", ")
        ))
        .into());
    }

    // Read the current limits and work out the new ones; still no change.
    let mut plan = Vec::new();
    for (name, res, value, (soft, hard)) in specs {
        let (cur_soft, cur_hard) = sys::get_limit(pid, res)?;
        let new_soft = soft.unwrap_or(cur_soft);
        let new_hard = hard.unwrap_or(cur_hard);
        if new_soft > new_hard {
            return Err(Fail::invalid(format!(
                "{name}: the soft limit ({}) would exceed the hard limit ({}); nothing was done",
                show_limit(new_soft),
                show_limit(new_hard)
            ))
            .into());
        }
        plan.push((name, res, value, (cur_soft, cur_hard), (new_soft, new_hard)));
    }

    let mut results = Map::new();
    let mut failure: Option<Fail> = None;
    for (name, res, value, before, after) in plan {
        let changed = before != after;
        let mut entry = json!({
            "requested": value,
            "before": {"soft": before.0, "hard": before.1},
            "after": {"soft": after.0, "hard": after.1},
            "changed": changed,
            "status": "ok"
        });
        if failure.is_some() {
            // Not attempted after an earlier failure.
            entry["status"] = json!("skipped");
            entry["after"] = entry["before"].clone();
            entry["changed"] = json!(false);
        } else if changed
            && !dry_run
            && let Err(f) = sys::set_limit(pid, res, after.0, after.1)
        {
            entry["status"] = json!("error");
            entry["after"] = entry["before"].clone();
            entry["changed"] = json!(false);
            entry["error"] = f.error_obj();
            failure = Some(f);
        }
        results.insert(name.to_string(), entry);
    }

    let mut out = Map::new();
    out.insert("backend".into(), json!("prlimit"));
    out.insert("dry_run".into(), json!(dry_run));
    out.insert("results".into(), Value::Object(results));
    out.insert("pid".into(), json!(pid));
    match failure {
        None => Ok(Output::Json(Value::Object(out))),
        Some(fail) => Err(Failure { fail, extra: out }),
    }
}

fn show_limit(v: u64) -> String {
    if v == sys::INFINITY {
        "unlimited".to_string()
    } else {
        v.to_string()
    }
}

// ===========================================================================
// Helper functions for help display
// ===========================================================================

/// Check if help should be displayed. Matches whole tokens only, so a verb
/// or argument merely containing "-h" is not a help request.
fn should_show_help(method: &str, args: &Args) -> bool {
    method == "help"
        || method == "h"
        || crate::core::help::is_help_flag(method)
        || args.contains_key("help")
        || args.contains_key("h")
}

#[cfg(test)]
#[path = "proch_tests.rs"]
mod tests;
