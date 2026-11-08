//! `svc://<service>.<verb>`: system services through systemd (D-Bus, with
//! `systemctl` when the bus cannot be reached) or OpenRC.
//!
//! Every verb checks its arguments and the service name before anything
//! runs (exit 2), works under a deadline (`timeout_ms`), and reports failures
//! as `Error: [svc.<code>] <message>` with exit 1, 2 or 124. Lifecycle verbs
//! on systemd wait for the job they queue and report its real result.

mod bus;
mod logs;
mod openrc;
mod systemd;
#[cfg(test)]
mod tests;

use anyhow::Context;
use serde_json::{Value, json};
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};
use url::Url;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    lenient, process,
    registry::{Args, Handle, IoStreams},
    status::{Status, error_json, error_line, exit},
};
use bus::{Bus, BusErrKind, FileOp, SystemctlBus, ZbusBus};
use logs::LogOpts;

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("svc", |u| Ok(Box::new(SvcHandle::from_url(u)?)));
}

/// Metadata for `resh svc --help` and `resh svc <verb> --help`.
static SVC_HELP: HandleHelp = HandleHelp {
    description: "The svc handle inspects and controls system services through the host's \
        service manager, supporting systemd and OpenRC. It covers service state queries, \
        lifecycle control, boot-time configuration, and log access. Each command names \
        one service in the stage URL, such as svc://nginx.",
    usage: "resh svc://<service-name>.<verb>[(key=value,...)]",
    verbs: &[
        VerbHelp {
            name: "status",
            definition: "Reports the current state of a service, such as whether it is running \
                and its main process ID, as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh svc://<service-name>.status [timeout_ms=<ms>]",
                example: "resh svc://nginx.status",
                example_output: Some(
                    r#"{
  "active_state": "active",
  "backend": "systemd",
  "description": "A high performance web server and a reverse proxy server",
  "exit_status": 0,
  "name": "nginx.service",
  "pid": 1234,
  "sub_state": "running",
  "timestamps": {
    "active_enter": "2026-10-16T09:12:44.512309+00:00",
    "active_exit": "",
    "inactive_enter": ""
  }
}

Shown for a systemd host with --json-pretty. OpenRC hosts report the
fields name, backend, state, pid, exit_status, raw, and timestamps.
timeout_ms defaults to 30000."#,
                ),
            }),
        },
        VerbHelp {
            name: "is-enabled",
            definition: "Reports whether a service is configured to start at boot.",
            detail: Some(VerbDetail {
                usage: "resh svc://<service-name>.is-enabled [timeout_ms=<ms>]",
                example: "resh svc://nginx.is-enabled",
                example_output: Some(
                    r#"{
  "backend": "systemd",
  "enabled": true,
  "name": "nginx",
  "unit_file_state": "enabled"
}

Shown with --json-pretty. On OpenRC, enabled means the service is in the
default runlevel. A service that does not exist is an error (exit 1)."#,
                ),
            }),
        },
        VerbHelp {
            name: "start",
            definition: "Starts a service and waits for the start job to finish.",
            detail: Some(VerbDetail {
                usage: "resh svc://<service-name>.start [timeout_ms=<ms>]",
                example: "resh svc://nginx.start",
                example_output: Some(
                    r#"{
  "action": "start",
  "active_state": "active",
  "backend": "systemd",
  "job_result": "done",
  "name": "nginx.service",
  "result": "success",
  "sub_state": "running"
}

Shown for a systemd host with --json-pretty. A job that fails exits 1;
at timeout_ms (default 120000) the job is cancelled and resh exits 124."#,
                ),
            }),
        },
        VerbHelp {
            name: "stop",
            definition: "Stops a service and waits for it to become inactive.",
            detail: Some(VerbDetail {
                usage: "resh svc://<service-name>.stop [timeout_ms=<ms>] [timeout=<ms>]\n  \
                    [force=true|false]",
                example: "resh svc://nginx.stop timeout_ms=5000",
                example_output: Some(
                    r#"{
  "action": "stop",
  "backend": "systemd",
  "final_state": "inactive",
  "job_result": "done",
  "name": "nginx.service",
  "note": "stopped via StopUnit",
  "previous_state": "active",
  "reached_inactive": true,
  "requested": true,
  "timeout_ms": 5000
}

Shown for a systemd host with --json-pretty. timeout is an older name
for timeout_ms (default 120000)."#,
                ),
            }),
        },
        VerbHelp {
            name: "restart",
            definition: "Stops and then starts a service, waiting for the job to finish.",
            detail: Some(VerbDetail {
                usage: "resh svc://<service-name>.restart [timeout_ms=<ms>]",
                example: "resh svc://nginx.restart",
                example_output: Some(
                    r#"{
  "action": "restart",
  "active_state": "active",
  "backend": "systemd",
  "job_result": "done",
  "name": "nginx.service",
  "result": "success",
  "sub_state": "running"
}

Shown for a systemd host with --json-pretty. OpenRC hosts report the
service name without the .service suffix."#,
                ),
            }),
        },
        VerbHelp {
            name: "reload",
            definition: "Reloads a service's configuration without stopping it.",
            detail: Some(VerbDetail {
                usage: "resh svc://<service-name>.reload [timeout_ms=<ms>]",
                example: "resh svc://nginx.reload",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "enable",
            definition: "Configures a service to start automatically at boot.",
            detail: Some(VerbDetail {
                usage: "resh svc://<service-name>.enable [timeout_ms=<ms>]",
                example: "resh svc://nginx.enable",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "disable",
            definition: "Prevents a service from starting automatically at boot.",
            detail: Some(VerbDetail {
                usage: "resh svc://<service-name>.disable [timeout_ms=<ms>]",
                example: "resh svc://nginx.disable",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "mask",
            definition: "Blocks a service from being started at all (systemd only).",
            detail: Some(VerbDetail {
                usage: "resh svc://<service-name>.mask [timeout_ms=<ms>]",
                example: "resh svc://nginx.mask",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "unmask",
            definition: "Removes a mask so a service can be started again (systemd only).",
            detail: Some(VerbDetail {
                usage: "resh svc://<service-name>.unmask [timeout_ms=<ms>]",
                example: "resh svc://nginx.unmask",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "wait",
            definition: "Waits for a service to become active or inactive, with a timeout.",
            detail: Some(VerbDetail {
                usage: "resh svc://<service-name>.wait\n  \
                    [state=active|inactive|running|stopped] [timeout_ms=<ms>]\n  \
                    [timeout=<ms>]",
                example: "resh svc://nginx.wait state=active timeout_ms=30000",
                example_output: Some(
                    r#"{
  "active_state": "active",
  "backend": "systemd",
  "name": "nginx",
  "reached": true,
  "state": "active",
  "timeout_ms": 30000
}

Shown with --json-pretty. timeout_ms defaults to 10000 (timeout is an
older name for it); running means active and stopped means inactive."#,
                ),
            }),
        },
        VerbHelp {
            name: "logs",
            definition: "Displays recent log entries for a service.",
            detail: Some(VerbDetail {
                usage: "resh svc://<service-name>.logs [lines=<n>] [since=<time>]\n  \
                    [until=<time>] [level=<priority>] [reverse=true|false]\n  \
                    [follow=true|false] [timeout_ms=<ms>]",
                example: "resh svc://nginx.logs lines=2 level=err",
                example_output: Some(
                    r#"2026-10-16T09:12:44+00:00 web01 nginx[1234]: open() failed (2: No such file)
2026-10-16T09:14:02+00:00 web01 nginx[1234]: upstream timed out (110)

Shown for a systemd host, where output comes from journalctl
--output=short-iso and lines defaults to 200. OpenRC hosts print the last
lines of /var/log/<service>.log or a similar file; since, until, and
level apply only to systemd. With follow=true, timeout_ms is how long to
follow (exit 0 when it ends)."#,
                ),
            }),
        },
        VerbHelp {
            name: "scale",
            definition: "Sets the number of running instances of a service.",
            detail: Some(VerbDetail {
                usage: "resh svc://<service-name>.scale count=<n> [timeout_ms=<ms>]",
                example: "resh svc://nginx.scale count=1",
                example_output: Some(
                    r#"{
  "backend": "systemd",
  "desired_count": 1,
  "effective_count": 1,
  "name": "nginx.service",
  "note": "non-template service scaled to 1",
  "template": false
}

Shown for a non-template systemd unit with --json-pretty, where any
count of 1 or more means running. Template units such as worker@.service
start or stop numbered instances; OpenRC supports only 0 or 1."#,
                ),
            }),
        },
    ],
};

/// The operation verbs, in help order.
const VERBS: &[&str] = &[
    "status",
    "is-enabled",
    "start",
    "stop",
    "restart",
    "reload",
    "enable",
    "disable",
    "mask",
    "unmask",
    "wait",
    "logs",
    "scale",
];

/// The arguments each verb accepts (`dry_run=false` is also accepted;
/// `dry_run=true` is refused: svc has no dry-run mode).
pub(crate) fn verb_args(verb: &str) -> &'static [&'static str] {
    match verb {
        "stop" => &["timeout_ms", "timeout", "force"],
        "wait" => &["state", "timeout_ms", "timeout"],
        "logs" => &[
            "lines",
            "since",
            "until",
            "level",
            "reverse",
            "follow",
            "timeout_ms",
        ],
        "scale" => &["count", "timeout_ms"],
        _ => &["timeout_ms"],
    }
}

/// Every error code svc reports, as documented in
/// docs/Process_ServiceManagement/svc.md. `svc.invalid_target` and
/// `svc.failed` can also come from the dispatcher.
#[cfg(test)]
pub(crate) const ERROR_CODES: &[&str] = &[
    "svc.invalid_argument",
    "svc.invalid_target",
    "svc.unknown_verb",
    "svc.unsupported",
    "svc.not_found",
    "svc.permission_denied",
    "svc.masked",
    "svc.job_failed",
    "svc.partial_failure",
    "svc.no_backend",
    "svc.backend_unavailable",
    "svc.tool_not_found",
    "svc.no_logs",
    "svc.logs_failed",
    "svc.failed",
    "svc.timeout",
];

/// Default `timeout_ms` per verb (`logs follow=true` has none: it follows
/// until interrupted).
pub(crate) fn default_timeout_ms(verb: &str) -> u64 {
    match verb {
        "start" | "stop" | "restart" | "reload" | "scale" => 120_000,
        "wait" => 10_000,
        "logs" => 600_000,
        _ => 30_000,
    }
}
const MAX_TIMEOUT_MS: u64 = 7 * 24 * 3600 * 1000;
const DEFAULT_LINES: u64 = 200;
const MAX_LINES: u64 = 1_000_000;
const MAX_COUNT: u64 = 1000;
const MAX_NAME_BYTES: usize = 256;

/// A failure with its exit status and error code.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Fail {
    pub exit: i32,
    pub code: &'static str,
    pub msg: String,
}

impl Fail {
    pub fn new(exit: i32, code: &'static str, msg: impl Into<String>) -> Self {
        #[cfg(test)]
        assert!(ERROR_CODES.contains(&code), "undocumented code {code}");
        Fail {
            exit,
            code,
            msg: msg.into(),
        }
    }
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::new(exit::USAGE, "svc.invalid_argument", msg)
    }
}

/// What a verb produced: its JSON result (if it prints one) and its
/// failure (if any). A failing JSON result carries the error object.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Reply {
    pub json: Option<Value>,
    pub fail: Option<Fail>,
}

impl Reply {
    pub fn ok(v: Value) -> Self {
        Reply {
            json: Some(v),
            fail: None,
        }
    }
    pub fn ok_empty() -> Self {
        Reply {
            json: None,
            fail: None,
        }
    }
    pub fn failed(json: Option<Value>, f: Fail) -> Self {
        Reply {
            json,
            fail: Some(f),
        }
    }
}

/// The service a verb acts on, and its deadline.
#[derive(Debug, Clone)]
pub(crate) struct Ctx {
    /// The name as given (`nginx`).
    pub name: String,
    /// The systemd unit (`nginx.service`).
    pub unit: String,
    pub timeout_ms: u64,
    pub deadline: Instant,
}

/// The external tools svc runs. Debug builds read them from the directory
/// in `RESH_TEST_SVC_TOOLS` when it is set (tests), never from PATH then.
#[derive(Debug, Clone)]
pub(crate) struct Tools {
    pub systemctl: OsString,
    pub journalctl: OsString,
    pub rc_service: OsString,
    pub rc_update: OsString,
    pub tail: OsString,
    /// Root under which OpenRC log files are looked up (tests); `/` when
    /// unset.
    pub log_root: Option<PathBuf>,
}

impl Tools {
    fn from_env() -> Self {
        let mut t = Tools {
            systemctl: "systemctl".into(),
            journalctl: "journalctl".into(),
            rc_service: "rc-service".into(),
            rc_update: "rc-update".into(),
            tail: "tail".into(),
            log_root: None,
        };
        #[cfg(debug_assertions)]
        if let Some(dir) = std::env::var_os("RESH_TEST_SVC_TOOLS") {
            let dir = PathBuf::from(dir);
            t.systemctl = dir.join("systemctl").into();
            t.journalctl = dir.join("journalctl").into();
            t.rc_service = dir.join("rc-service").into();
            t.rc_update = dir.join("rc-update").into();
            t.tail = dir.join("tail").into();
            t.log_root = Some(dir.join("root"));
        }
        t
    }
}

/// Runs `tool args` under `deadline`: tool missing is `svc.tool_not_found`;
/// a tool still running at the deadline is stopped and the outcome is
/// unknown (`svc.timeout`, exit 124).
pub(crate) fn run_tool(
    tool: &OsString,
    args: &[&str],
    deadline: Instant,
) -> Result<std::process::Output, Fail> {
    let mut cmd = Command::new(tool);
    cmd.args(args).env("LC_ALL", "C");
    let remaining = deadline.saturating_duration_since(Instant::now());
    let name = tool.to_string_lossy();
    match process::run(&mut cmd, Some(remaining)) {
        Ok(o) => Ok(o),
        Err(e) if e.kind() == io::ErrorKind::TimedOut => {
            let lost = process::take_lost();
            let what = match lost.map(|l| l.stopped) {
                Some(process::Stopped::NotStarted) => "was not started; nothing was done",
                Some(process::Stopped::StillRunning) => {
                    "could not be stopped and may still be running; the outcome is unknown"
                }
                _ => "was stopped; what it already did stays done, so check before retrying",
            };
            Err(Fail::new(
                exit::TIMEOUT,
                "svc.timeout",
                format!("{name} {} {what}", args.join(" ")),
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(Fail::new(
            exit::FAILED,
            "svc.tool_not_found",
            format!("{name} was not found"),
        )),
        Err(e) => Err(Fail::new(
            exit::FAILED,
            "svc.failed",
            format!("cannot run {name}: {e}"),
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Systemd,
    OpenRc,
    Unknown,
}

impl Backend {
    fn label(self) -> &'static str {
        match self {
            Backend::Systemd => "systemd",
            Backend::OpenRc => "openrc",
            Backend::Unknown => "unknown",
        }
    }
}

/// How systemd is reached (debug builds can force one, for tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    /// D-Bus, with systemctl when the bus cannot be reached.
    Auto,
    /// systemctl only.
    Systemctl,
}

/// The verb and its checked options.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Op {
    Status,
    IsEnabled,
    Start,
    Stop { force: bool },
    Restart,
    Reload,
    Files(FileOp),
    Wait { active: bool, state: String },
    Logs(LogOpts),
    Scale { count: u32 },
}

pub struct SvcHandle {
    name: String,
    original_url: Url,
}

fn suggest(bad: &str, allowed: &[&'static str]) -> Option<&'static str> {
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
    let norm = bad.to_ascii_lowercase().replace('-', "_");
    allowed
        .iter()
        .map(|a| {
            let d = if a.starts_with(norm.as_str()) || norm.starts_with(a) {
                1
            } else {
                distance(&norm, a)
            };
            (d, *a)
        })
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, a)| a)
}

fn u64_arg(args: &Args, key: &str, min: u64, max: u64) -> Result<Option<u64>, Fail> {
    let Some(raw) = args.get(key) else {
        return Ok(None);
    };
    match raw.trim().parse::<u64>() {
        Ok(v) if (min..=max).contains(&v) => Ok(Some(v)),
        _ => Err(Fail::invalid(format!(
            "invalid value for {key}: {raw:?} (expected an integer from {min} to {max})"
        ))),
    }
}

fn bool_arg(args: &Args, key: &str) -> Result<bool, Fail> {
    lenient::bool_arg(args, key)
        .map(|b| b.unwrap_or(false))
        .map_err(|e| Fail::invalid(e.to_string()))
}

/// A `since`/`until` value: passed to journalctl as `--since=<value>`.
fn time_arg(args: &Args, key: &str) -> Result<Option<String>, Fail> {
    match args.get(key) {
        None => Ok(None),
        Some(v) if v.trim().is_empty() || v.chars().any(char::is_control) => {
            Err(Fail::invalid(format!(
                "invalid value for {key}: {v:?} (expected a journalctl time such as \
                 \"2026-10-16 09:00\", \"-1h\" or \"yesterday\")"
            )))
        }
        Some(v) => Ok(Some(v.clone())),
    }
}

/// Checks every argument of `verb` and returns the operation and its
/// timeout (ms; `None` only for `logs follow=true` without timeout_ms).
pub(crate) fn parse_args(verb: &str, args: &Args) -> Result<(Op, Option<u64>), Fail> {
    let allowed = verb_args(verb);
    let mut keys: Vec<&String> = args.keys().collect();
    keys.sort();
    for k in keys {
        if allowed.contains(&k.as_str()) {
            continue;
        }
        if k == "dry_run" {
            match lenient::dry_run(args) {
                Ok(false) => continue,
                Ok(true) => {
                    return Err(Fail::invalid(format!(
                        "svc {verb} has no dry-run mode; nothing was done"
                    )));
                }
                Err(e) => return Err(Fail::invalid(e.to_string())),
            }
        }
        return Err(Fail::invalid(format!(
            "unknown argument for {verb}: {k}{}",
            suggest(k, allowed)
                .map(|s| format!(" (did you mean `{s}`?)"))
                .unwrap_or_default()
        )));
    }
    let mut timeout = u64_arg(args, "timeout_ms", 1, MAX_TIMEOUT_MS)?;
    if allowed.contains(&"timeout") {
        let old = u64_arg(args, "timeout", 1, MAX_TIMEOUT_MS)?;
        if old.is_some() && timeout.is_some() {
            return Err(Fail::invalid(
                "give timeout_ms or its older name timeout, not both",
            ));
        }
        timeout = timeout.or(old);
    }
    let op = match verb {
        "status" => Op::Status,
        "is-enabled" => Op::IsEnabled,
        "start" => Op::Start,
        "restart" => Op::Restart,
        "reload" => Op::Reload,
        "enable" => Op::Files(FileOp::Enable),
        "disable" => Op::Files(FileOp::Disable),
        "mask" => Op::Files(FileOp::Mask),
        "unmask" => Op::Files(FileOp::Unmask),
        "stop" => Op::Stop {
            force: bool_arg(args, "force")?,
        },
        "wait" => {
            let state = args.get("state").map_or("active", String::as_str);
            let active = match state {
                "active" | "running" => true,
                "inactive" | "stopped" => false,
                other => {
                    return Err(Fail::invalid(format!(
                        "invalid value for state: {other:?} (expected active, inactive, \
                         running or stopped)"
                    )));
                }
            };
            Op::Wait {
                active,
                state: state.to_string(),
            }
        }
        "logs" => {
            let level = match args.get("level").map(String::as_str) {
                None => None,
                Some("debug") => Some("debug"),
                Some("info") => Some("info"),
                Some("warning") => Some("warning"),
                Some("err" | "error") => Some("err"),
                Some("crit" | "critical") => Some("crit"),
                Some(other) => {
                    return Err(Fail::invalid(format!(
                        "invalid value for level: {other:?} (expected debug, info, warning, \
                         err, error, crit or critical)"
                    )));
                }
            };
            let follow = bool_arg(args, "follow")?;
            let reverse = bool_arg(args, "reverse")?;
            if follow && reverse {
                return Err(Fail::invalid(
                    "reverse=true cannot be combined with follow=true",
                ));
            }
            let o = LogOpts {
                lines: u64_arg(args, "lines", 1, MAX_LINES)?.unwrap_or(DEFAULT_LINES),
                since: time_arg(args, "since")?,
                until: time_arg(args, "until")?,
                level,
                reverse,
                follow,
                follow_for: if follow {
                    timeout.map(Duration::from_millis)
                } else {
                    None
                },
            };
            if follow {
                return Ok((Op::Logs(o), timeout));
            }
            Op::Logs(o)
        }
        "scale" => {
            if !args.contains_key("count") {
                return Err(Fail::invalid("scale needs count=<n>"));
            }
            Op::Scale {
                count: u64_arg(args, "count", 0, MAX_COUNT)?.unwrap_or(0) as u32,
            }
        }
        other => return Err(unknown_verb(other)),
    };
    Ok((
        op,
        Some(timeout.unwrap_or_else(|| default_timeout_ms(verb))),
    ))
}

fn unknown_verb(verb: &str) -> Fail {
    Fail::new(
        exit::USAGE,
        "svc.unknown_verb",
        format!(
            "unknown verb for svc: {verb}{}; verbs: {}",
            suggest(verb, VERBS)
                .map(|s| format!(" (did you mean `{s}`?)"))
                .unwrap_or_default(),
            VERBS.join(", ")
        ),
    )
}

/// Rejects service names that are empty, too long, could be read as a
/// command-line option, or contain characters a unit or OpenRC service name
/// cannot have. Instance names such as `getty@tty1` are valid.
pub(crate) fn validate_service_name(name: &str) -> Result<(), String> {
    let bad = if name.is_empty() {
        Some("is empty".to_string())
    } else if name.len() > MAX_NAME_BYTES {
        Some(format!("is longer than {MAX_NAME_BYTES} bytes"))
    } else if name.starts_with('-') {
        Some("starts with '-'".to_string())
    } else if name.starts_with('.') {
        Some("starts with '.'".to_string())
    } else if name.contains(':') {
        Some("contains ':'".to_string())
    } else if name.contains('/') {
        Some("contains '/'".to_string())
    } else if name.chars().any(|c| c.is_whitespace() || c.is_control()) {
        Some("contains whitespace or control characters".to_string())
    } else {
        name.chars()
            .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '-' | '\\')))
            .map(|c| format!("contains {c:?}"))
    };
    match bad {
        Some(why) => Err(format!(
            "invalid service name {name:?}: {why} (letters, digits, '_', '.', '@', '-' and \
             '\\' are allowed)"
        )),
        None => Ok(()),
    }
}

impl SvcHandle {
    pub fn from_url(u: &Url) -> anyhow::Result<Self> {
        let mut name = String::new();
        // Instance units such as `getty@tty1` parse as URL userinfo
        // (`getty`) plus host (`tty1`); keep the whole name.
        if !u.username().is_empty() {
            let user = percent_encoding::percent_decode_str(u.username()).decode_utf8_lossy();
            name.push_str(&user);
            if let Some(pw) = u.password() {
                name.push(':');
                name.push_str(&percent_encoding::percent_decode_str(pw).decode_utf8_lossy());
            }
            name.push('@');
        }
        if let Some(h) = u.host_str() {
            name.push_str(&percent_encoding::percent_decode_str(h).decode_utf8_lossy());
        }
        if !u.path().is_empty() {
            if !name.is_empty() {
                name.push('/');
            }
            name.push_str(u.path().trim_start_matches('/'));
        }
        Ok(Self {
            name,
            original_url: u.clone(),
        })
    }

    fn unit_name(&self) -> String {
        if self.name.ends_with(".service") {
            self.name.clone()
        } else {
            format!("{}.service", self.name)
        }
    }

    /// The backend and, for systemd, the route. Debug builds honor
    /// `RESH_TEST_SVC_BACKEND` (`systemd`, `systemctl`, `openrc`, `none`).
    fn detect_backend() -> (Backend, Route) {
        #[cfg(debug_assertions)]
        if let Ok(forced) = std::env::var("RESH_TEST_SVC_BACKEND") {
            return match forced.as_str() {
                "systemd" => (Backend::Systemd, Route::Auto),
                "systemctl" => (Backend::Systemd, Route::Systemctl),
                "openrc" => (Backend::OpenRc, Route::Auto),
                _ => (Backend::Unknown, Route::Auto),
            };
        }
        if std::path::Path::new("/run/systemd/system").exists() || which::which("systemctl").is_ok()
        {
            return (Backend::Systemd, Route::Auto);
        }
        if which::which("rc-status").is_ok() || which::which("rc-service").is_ok() {
            return (Backend::OpenRc, Route::Auto);
        }
        (Backend::Unknown, Route::Auto)
    }

    /// Check if the URL indicates a help request. Matches whole tokens
    /// only, so targets such as `my-httpd` or `/srv/my-hosts` are not help.
    fn should_show_help(url: &Url) -> bool {
        if url.host_str().is_some_and(crate::core::help::is_help_flag) {
            return true;
        }
        let path = url.path();
        if !path.is_empty() && path != "/" && crate::core::help::is_help_flag(path) {
            return true;
        }
        url.query_pairs()
            .any(|(key, _)| key == "help" || key == "h")
    }

    /// Writes the approved help for the help verbs and in-URL help forms.
    fn display_help(&self, verb: Option<&str>, io: &mut IoStreams) -> anyhow::Result<Status> {
        if let Some(v) = verb
            && !VERBS.contains(&v)
        {
            return report(io, None, unknown_verb(v));
        }
        let text = crate::core::help::render_legacy("svc", &SVC_HELP, self.verbs(), verb);
        write!(io.stdout, "{}", text).with_context(|| "Failed to write help text to stdout")?;
        Ok(Status::ok())
    }

    /// Runs `op` on systemd through `bus`.
    fn on_systemd(bus: &dyn Bus, c: &Ctx, op: &Op, warn: &mut Vec<String>) -> Reply {
        match op {
            Op::Status => systemd::status(bus, c),
            Op::IsEnabled => systemd::is_enabled(bus, c),
            Op::Start => systemd::start(bus, c, "start"),
            Op::Restart => systemd::start(bus, c, "restart"),
            Op::Stop { force } => systemd::stop(bus, c, *force),
            Op::Reload => systemd::reload(bus, c),
            Op::Files(f) => systemd::unit_files(bus, c, *f, warn),
            Op::Wait { active, state } => systemd::wait(bus, c, *active, state),
            Op::Scale { count } => systemd::scale(bus, c, *count),
            Op::Logs(_) => Reply::ok_empty(),
        }
    }

    fn on_openrc(t: &Tools, c: &Ctx, op: &Op) -> Reply {
        let unsupported = |what: &str| {
            Reply::failed(
                None,
                Fail::new(
                    exit::USAGE,
                    "svc.unsupported",
                    format!("{what} is not supported on OpenRC; nothing was done"),
                ),
            )
        };
        match op {
            Op::Status => openrc::status(t, c),
            Op::IsEnabled => openrc::is_enabled(t, c),
            Op::Start => openrc::start(t, c, "start"),
            Op::Restart => openrc::start(t, c, "restart"),
            Op::Stop { force: true } => unsupported("stop force=true"),
            Op::Stop { force: false } => openrc::stop(t, c),
            Op::Reload => openrc::reload(t, c),
            Op::Files(FileOp::Enable) => openrc::enable(t, c, true),
            Op::Files(FileOp::Disable) => openrc::enable(t, c, false),
            Op::Files(f) => unsupported(f.verb()),
            Op::Wait { active, state } => openrc::wait(t, c, *active, state),
            Op::Scale { .. } if systemd::template_base(&c.unit).is_some() => {
                unsupported("scaling a template unit")
            }
            Op::Scale { count } => openrc::scale(t, c, *count),
            Op::Logs(_) => Reply::ok_empty(),
        }
    }

    /// The systemd bus for this call: D-Bus, or systemctl when the bus
    /// cannot be reached (or the route forces it).
    fn systemd_bus(route: Route, t: &Tools, deadline: Instant) -> Result<Box<dyn Bus>, Fail> {
        if route == Route::Auto {
            match ZbusBus::connect(deadline) {
                Ok(b) => return Ok(Box::new(b)),
                Err(e) if e.kind == BusErrKind::Unavailable => {}
                Err(e) => return Err(systemd::bus_fail(e, "the service manager")),
            }
        }
        Ok(Box::new(SystemctlBus::new(t.systemctl.clone(), deadline)))
    }

    fn run(&self, verb: &str, args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        if !VERBS.contains(&verb) {
            return report(io, None, unknown_verb(verb));
        }
        if let Err(reason) = validate_service_name(&self.name) {
            return report(
                io,
                None,
                Fail::new(exit::USAGE, "svc.invalid_target", reason),
            );
        }
        let (op, timeout_ms) = match parse_args(verb, args) {
            Ok(v) => v,
            Err(f) => return report(io, None, f),
        };
        let (backend, route) = Self::detect_backend();
        let tools = Tools::from_env();
        self.execute(backend, route, &tools, op, timeout_ms, io)
    }

    fn execute(
        &self,
        backend: Backend,
        route: Route,
        tools: &Tools,
        op: Op,
        timeout_ms: Option<u64>,
        io: &mut IoStreams,
    ) -> anyhow::Result<Status> {
        let ms = timeout_ms.unwrap_or(0);
        let c = Ctx {
            name: self.name.clone(),
            unit: self.unit_name(),
            timeout_ms: ms,
            deadline: Instant::now() + Duration::from_millis(ms),
        };
        if let Op::Logs(o) = &op {
            if backend == Backend::OpenRc
                && let Some(k) = [
                    ("since", o.since.is_some()),
                    ("until", o.until.is_some()),
                    ("level", o.level.is_some()),
                ]
                .iter()
                .find(|(_, set)| *set)
            {
                let f = Fail::new(
                    exit::USAGE,
                    "svc.unsupported",
                    format!("{} is supported only on systemd; nothing was read", k.0),
                );
                return report(io, None, f);
            }
            let r = match backend {
                Backend::Systemd => logs::journal(tools, &c, o, io)?,
                Backend::OpenRc => logs::openrc(tools, &c, o, io)?,
                Backend::Unknown => Some(no_backend()),
            };
            return match r {
                None => Ok(Status::ok()),
                Some(f) => report(io, None, f),
            };
        }
        let mut warn = Vec::new();
        let reply = match backend {
            Backend::Systemd => match Self::systemd_bus(route, tools, c.deadline) {
                Ok(bus) => Self::on_systemd(bus.as_ref(), &c, &op, &mut warn),
                Err(f) => Reply::failed(Some(self.base_json(backend, &c, &op)), f),
            },
            Backend::OpenRc => Self::on_openrc(tools, &c, &op),
            Backend::Unknown => Reply::failed(Some(self.base_json(backend, &c, &op)), no_backend()),
        };
        for w in warn {
            writeln!(io.stderr, "warning: {w}")?;
        }
        emit(io, reply)
    }

    /// The identifying fields of a verb's JSON result, for failures that
    /// happen before the backend answered.
    fn base_json(&self, backend: Backend, c: &Ctx, op: &Op) -> Value {
        let name = match (backend, op) {
            (Backend::Systemd, Op::IsEnabled | Op::Wait { .. }) => c.name.clone(),
            (Backend::Systemd, _) => c.unit.clone(),
            _ => c.name.clone(),
        };
        let mut v = json!({"name": name, "backend": backend.label()});
        match op {
            Op::Start => v["action"] = json!("start"),
            Op::Restart => v["action"] = json!("restart"),
            Op::Stop { .. } => v["action"] = json!("stop"),
            Op::Scale { count } => v["desired_count"] = json!(count),
            _ => {}
        }
        match op {
            Op::Files(_) | Op::Reload | Op::Logs(_) => Value::Null,
            _ => v,
        }
    }
}

fn no_backend() -> Fail {
    Fail::new(
        exit::FAILED,
        "svc.no_backend",
        "no supported service manager found (neither systemd nor OpenRC)",
    )
}

/// Writes the stderr error line (and, when the verb prints JSON, the result
/// with its error object) and returns the status.
fn report(io: &mut IoStreams, json: Option<Value>, f: Fail) -> anyhow::Result<Status> {
    if let Some(mut v) = json.filter(|v| !v.is_null()) {
        v["error"] = error_json(f.code, &f.msg);
        writeln!(io.stdout, "{v}")?;
        io.stdout.flush()?;
    }
    writeln!(io.stderr, "{}", error_line(f.code, &f.msg))?;
    Ok(Status::coded(f.exit, f.code, f.msg))
}

fn emit(io: &mut IoStreams, reply: Reply) -> anyhow::Result<Status> {
    match reply.fail {
        Some(f) => report(io, reply.json, f),
        None => {
            if let Some(v) = reply.json {
                writeln!(io.stdout, "{v}")?;
                io.stdout.flush()?;
            }
            Ok(Status::ok())
        }
    }
}

impl Handle for SvcHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &[
            "status",
            "is-enabled",
            "start",
            "stop",
            "restart",
            "reload",
            "enable",
            "disable",
            "mask",
            "unmask",
            "wait",
            "logs",
            "scale",
            "help",
            "--help",
            "-h",
        ]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&SVC_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        if crate::core::help::HELP_ALIASES.contains(&verb) {
            return self.display_help(args.get("verb").map(String::as_str), io);
        }
        if let Some(v) = verb.strip_prefix("--help=") {
            return self.display_help(Some(v), io);
        }
        if Self::should_show_help(&self.original_url) {
            return self.display_help(Some(verb).filter(|v| VERBS.contains(v)), io);
        }
        self.run(verb, args, io)
    }
}
