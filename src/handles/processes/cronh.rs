//! `cron://` – scheduled jobs as crontab entries (through `crontab` and the
//! system cron files) or as systemd service and timer pairs (through
//! `systemctl`).
//!
//! Every verb checks all of its arguments before it reads or changes
//! anything: unknown arguments and invalid values are refused with exit 2.
//! Every external tool runs under the verb's `timeout_ms` deadline
//! (`core::process`); past it the tool is stopped and the verb exits 124.
//! All host access goes through `CronHost`, so tests drive every verb
//! against an in-memory host.

use anyhow::Result;
use chrono::{DateTime, Datelike, FixedOffset, NaiveDate, Offset, TimeZone, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use url::Url;

use crate::core::{
    help::{self, HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::{Status, exit},
};

/// Metadata for `resh cron --help` and `resh cron <verb> --help`.
static CRON_HELP: HandleHelp = HandleHelp {
    description: "The cron handle manages scheduled jobs as crontab entries, through the \
        crontab command, or as systemd service and timer units, through systemctl. It can \
        list, add, remove, enable, and disable jobs on the local host. The host part of the \
        URL is only a label and is ignored, such as cron://local.",
    usage: "resh cron://<label>.<verb>[(key=value,...)]",
    verbs: &[
        VerbHelp {
            name: "list",
            definition: "Lists crontab entries for the chosen scope as JSON or text, with \
                optional filters, sorting, and next-run times (systemd timers are not listed).",
            detail: Some(VerbDetail {
                usage: "resh cron://<label>.list [scope=current|user|system|all]\n  \
                    [users=<user,...>] [include_system=true|false]\n  \
                    [include_files=<path,...>] [state=all|enabled|disabled]\n  \
                    [match_command=<text>] [match_comment=<text>] [match_user=<text>]\n  \
                    [match_source=<text>] [include_next_run=true|false]\n  \
                    [now_unix=<seconds>] [timezone=<IANA zone>] [max_entries=<n>]\n  \
                    [sort_by=none|user|schedule|command|source] [sort_order=asc|desc]\n  \
                    [include_raw=true|false] [include_paths=true|false]\n  \
                    [format=json|text] [timeout_ms=<ms>]\n  \
                    timezone: zone for next-run times of entries without their own\n  \
                    CRON_TZ (default: the host's local zone); now_unix: reference\n  \
                    time for next runs, Unix seconds 0-253402300799 (default now);\n  \
                    include_raw adds the text of each source; timeout_ms: 60000",
                example: "resh cron://local.list",
                example_output: Some(
                    r#"{
  "entries": [
    {
      "command": "/opt/backup.sh",
      "comment_only": false,
      "enabled": true,
      "id": "user:alice:crontab:1",
      "raw_line": "0 2 * * * /opt/backup.sh",
      "schedule": "0 2 * * *",
      "schedule_fields": {
        "day_of_month": "*",
        "day_of_week": "*",
        "hour": "2",
        "minute": "0",
        "month": "*"
      },
      "source": "user",
      "source_file": null,
      "source_line": 1,
      "user": "alice"
    }
  ],
  "entries_disabled": 0,
  "entries_returned": 1,
  "entries_total": 1,
  "human": {
    "summary": "1 cron entries (1 enabled, 0 disabled) from scope 'current'."
  },
  "include_system": false,
  "ok": true,
  "scope": "current",
  "timestamp_unix_ms": 1792161012345,
  "truncated": false,
  "users": [
    "alice"
  ],
  "warnings": []
}

Shown with --json-pretty. Commented-out jobs appear with enabled false,
and comment lines appear with comment_only true. scope=user requires
users, and the match_* filters are case-insensitive substring matches."#,
                ),
            }),
        },
        VerbHelp {
            name: "add",
            definition: "Adds a scheduled job as a crontab line or as a systemd service and \
                timer pair, preferring systemd when backend is auto.",
            detail: Some(VerbDetail {
                usage: "resh cron://<label>.add schedule=<expr> command=<cmd>\n  \
                    [backend=auto|cron|systemd] [id=<id>] [description=<text>]\n  \
                    [timezone=<IANA zone>] [include_next_run=true|false]\n  \
                    [now_unix=<seconds>] [allow_duplicate=true|false]\n  \
                    [dry_run=true|false] [format=json|text] [timeout_ms=<ms>]\n  \
                    cron backend only: [scope=current|user|system] [user=<name>]\n  \
                    [cron_file=<path>]\n  \
                    systemd backend only: [unit_name=<name>]\n  \
                    [unit_scope=auto|user|system] [persistent=true|false]\n  \
                    [accuracy_sec=<span>] [random_delay_sec=<span>]\n  \
                    [service_user=<name>] [service_working_dir=<path>]\n  \
                    [env=<KEY=VAL,...>] [env_<KEY>=<value>]\n  \
                    timezone: systemd adds it to the timer's OnCalendar; the cron\n  \
                    backend writes a CRON_TZ line and is refused unless cron is cronie\n  \
                    next run: computed in timezone (default: the host's local zone)\n  \
                    after now_unix, Unix seconds 0-253402300799 (default now)",
                example: "resh cron://local.add schedule=@daily command=/opt/backup.sh backend=cron",
                example_output: Some(
                    r#"{
  "backend_used": "cron",
  "dry_run": false,
  "duplicate": false,
  "job": {
    "backend": "cron",
    "command": "/opt/backup.sh",
    "location": {
      "file": "/var/spool/cron/alice",
      "line_added": 3,
      "scope": "current",
      "user": "alice"
    },
    "next_run_iso8601": "2026-10-17T00:00:00+00:00",
    "next_run_timezone": "UTC",
    "next_run_unix": 1792195200,
    "schedule": "@daily"
  },
  "ok": true,
  "timestamp_unix_ms": 1792161012345,
  "warnings": []
}

Shown for the cron backend with --json-pretty. With dry_run=true nothing
is written and a preview object holds the line or units to be added."#,
                ),
            }),
        },
        VerbHelp {
            name: "enable",
            definition: "Re-enables matching jobs by uncommenting crontab lines or by \
                enabling (and by default starting) systemd timers.",
            detail: Some(VerbDetail {
                usage: "resh cron://<label>.enable [id=<id>] [schedule=<expr>]\n  \
                    [command=<cmd>] [match_command=<text>] [match_comment=<text>]\n  \
                    [unit_name=<name>] [match_unit=<text>] [backend=both|cron|systemd]\n  \
                    [scope=all|current|user|system] [users=<user,...>]\n  \
                    [cron_file=<path>] [unit_scope=auto|user|system|both]\n  \
                    [start_now=true|false] [require_match=true|false]\n  \
                    [dry_run=true|false] [format=json|text] [timeout_ms=<ms>]\n  \
                    every selector given must match; cron_file: /etc/crontab or\n  \
                    /etc/cron.d/<name> only, and replaces scope",
                example: "resh cron://local.enable match_command=backup backend=cron scope=current",
                example_output: Some(
                    r#"{
  "already_enabled_count": {
    "cron": 0,
    "systemd": 0
  },
  "backend": "cron",
  "cron_modified_sources": [
    "/var/spool/cron/alice"
  ],
  "dry_run": false,
  "enabled": {
    "cron": [
      {
        "command": "/opt/backup.sh",
        "line_number": 1,
        "schedule": "0 2 * * *",
        "source": "/var/spool/cron/alice",
        "user": "alice",
        "was_disabled": true
      }
    ],
    "systemd": []
  },
  "matched_count": {
    "cron": 1,
    "systemd": 0
  },
  "ok": true,
  "systemd_scopes_touched": [],
  "timestamp_unix_ms": 1792161012345,
  "warnings": []
}

Shown with --json-pretty. At least one selector (id, schedule, command,
match_command, match_comment, unit_name, or match_unit) is required.
match_comment matches the comment line above a job or its inline comment."#,
                ),
            }),
        },
        VerbHelp {
            name: "disable",
            definition: "Disables matching jobs without deleting them by commenting out \
                crontab lines or by disabling (and by default stopping) systemd timers.",
            detail: Some(VerbDetail {
                usage: "resh cron://<label>.disable [id=<id>] [schedule=<expr>]\n  \
                    [command=<cmd>] [match_command=<text>] [match_comment=<text>]\n  \
                    [unit_name=<name>] [match_unit=<text>] [backend=both|cron|systemd]\n  \
                    [scope=all|current|user|system] [users=<user,...>]\n  \
                    [cron_file=<path>] [unit_scope=auto|user|system|both]\n  \
                    [stop_now=true|false] [require_match=true|false]\n  \
                    [dry_run=true|false] [format=json|text] [timeout_ms=<ms>]\n  \
                    every selector given must match; cron_file: /etc/crontab or\n  \
                    /etc/cron.d/<name> only, and replaces scope",
                example: "resh cron://local.disable match_command=backup backend=cron scope=current",
                example_output: Some(
                    r#"{
  "already_disabled_count": {
    "cron": 0,
    "systemd": 0
  },
  "backend": "cron",
  "cron_modified_sources": [
    "/var/spool/cron/alice"
  ],
  "disabled": {
    "cron": [
      {
        "command": "/opt/backup.sh",
        "line_number": 1,
        "schedule": "0 2 * * *",
        "source": "/var/spool/cron/alice",
        "user": "alice",
        "was_enabled": true
      }
    ],
    "systemd": []
  },
  "dry_run": false,
  "matched_count": {
    "cron": 1,
    "systemd": 0
  },
  "ok": true,
  "systemd_scopes_touched": [],
  "timestamp_unix_ms": 1792161012345,
  "warnings": []
}

Shown with --json-pretty. At least one selector (id, schedule, command,
match_command, match_comment, unit_name, or match_unit) is required.
match_comment matches the comment line above a job or its inline comment."#,
                ),
            }),
        },
        VerbHelp {
            name: "rm",
            definition: "Removes matching jobs from crontabs and deletes matching systemd \
                timers, by default along with their unit files.",
            detail: Some(VerbDetail {
                usage: "resh cron://<label>.rm [id=<id>] [schedule=<expr>] [command=<cmd>]\n  \
                    [match_command=<text>] [match_comment=<text>] [unit_name=<name>]\n  \
                    [match_unit=<text>] [backend=both|cron|systemd]\n  \
                    [scope=all|current|user|system] [users=<user,...>]\n  \
                    [cron_file=<path>] [unit_scope=auto|user|system|both]\n  \
                    [remove_units=true|false] [require_match=true|false]\n  \
                    [dry_run=true|false] [format=json|text] [timeout_ms=<ms>]\n  \
                    every selector given must match; cron_file: /etc/crontab or\n  \
                    /etc/cron.d/<name> only, and replaces scope",
                example: "resh cron://local.rm id=backup backend=cron scope=current dry_run=true",
                example_output: Some(
                    r#"{
  "backend": "cron",
  "cron_modified_sources": [
    "/var/spool/cron/alice"
  ],
  "dry_run": true,
  "matched_count": {
    "cron": 1,
    "systemd": 0
  },
  "ok": true,
  "removed": {
    "cron": [
      {
        "command": "/opt/backup.sh",
        "id": "backup",
        "line_number": 2,
        "schedule": "0 2 * * *",
        "source": "/var/spool/cron/alice",
        "user": "alice"
      }
    ],
    "systemd": []
  },
  "systemd_scopes_touched": [],
  "timestamp_unix_ms": 1792161012345,
  "warnings": []
}

Shown with --json-pretty. With dry_run=true the matches are reported but
nothing is changed; at least one selector is required."#,
                ),
            }),
        },
    ],
};

// ===========================================================================
// Arguments: one accepted list per verb (tested against the help usage)
// ===========================================================================

/// `timeout_ms` when none is given: the whole verb, every tool included.
pub(crate) const DEFAULT_TIMEOUT_MS: i64 = 60_000;
/// The largest `timeout_ms` accepted (one day).
const MAX_TIMEOUT_MS: i64 = 86_400_000;

const VERBS: &[&str] = &["list", "add", "rm", "enable", "disable"];

const LIST_ARGS: &[&str] = &[
    "scope",
    "users",
    "include_system",
    "include_files",
    "state",
    "match_command",
    "match_comment",
    "match_user",
    "match_source",
    "include_next_run",
    "now_unix",
    "timezone",
    "max_entries",
    "sort_by",
    "sort_order",
    "include_raw",
    "include_paths",
    "format",
    "timeout_ms",
];

/// `add` also accepts `env_<KEY>` (checked separately).
const ADD_ARGS: &[&str] = &[
    "schedule",
    "command",
    "backend",
    "id",
    "description",
    "timezone",
    "include_next_run",
    "now_unix",
    "allow_duplicate",
    "dry_run",
    "format",
    "timeout_ms",
    "scope",
    "user",
    "cron_file",
    "unit_name",
    "unit_scope",
    "persistent",
    "accuracy_sec",
    "random_delay_sec",
    "service_user",
    "service_working_dir",
    "env",
];

const RM_ARGS: &[&str] = &[
    "id",
    "schedule",
    "command",
    "match_command",
    "match_comment",
    "unit_name",
    "match_unit",
    "backend",
    "scope",
    "users",
    "cron_file",
    "unit_scope",
    "remove_units",
    "require_match",
    "dry_run",
    "format",
    "timeout_ms",
];

const ENABLE_ARGS: &[&str] = &[
    "id",
    "schedule",
    "command",
    "match_command",
    "match_comment",
    "unit_name",
    "match_unit",
    "backend",
    "scope",
    "users",
    "cron_file",
    "unit_scope",
    "start_now",
    "require_match",
    "dry_run",
    "format",
    "timeout_ms",
];

const DISABLE_ARGS: &[&str] = &[
    "id",
    "schedule",
    "command",
    "match_command",
    "match_comment",
    "unit_name",
    "match_unit",
    "backend",
    "scope",
    "users",
    "cron_file",
    "unit_scope",
    "stop_now",
    "require_match",
    "dry_run",
    "format",
    "timeout_ms",
];

/// The arguments `verb` accepts, or None for an unknown verb.
pub(crate) fn verb_args(verb: &str) -> Option<&'static [&'static str]> {
    Some(match verb {
        "list" => LIST_ARGS,
        "add" => ADD_ARGS,
        "rm" => RM_ARGS,
        "enable" => ENABLE_ARGS,
        "disable" => DISABLE_ARGS,
        _ => return None,
    })
}

/// Every error code the handle reports, with its exit status: 2 for
/// invalid usage (nothing was read or changed), 1 for an operation that
/// failed, 124 for a deadline that passed (outcome unknown).
pub(crate) const ERROR_CODES: &[(&str, i32)] = &[
    ("cron.invalid_argument", exit::USAGE),
    ("cron.timeout", exit::TIMEOUT),
    // A handle error the dispatcher reports (such as stdout closed).
    ("cron.failed", exit::FAILED),
    ("cron.list_invalid_argument", exit::USAGE),
    ("cron.list_error", exit::FAILED),
    ("cron.add_invalid_argument", exit::USAGE),
    ("cron.add_missing_schedule", exit::USAGE),
    ("cron.add_missing_command", exit::USAGE),
    ("cron.add_invalid_schedule", exit::USAGE),
    ("cron.add_timezone_unsupported", exit::USAGE),
    ("cron.add_schedule_translation_unsupported", exit::USAGE),
    ("cron.add_backend_unavailable", exit::FAILED),
    ("cron.add_systemd_unavailable", exit::FAILED),
    ("cron.add_error", exit::FAILED),
    ("cron.rm_invalid_argument", exit::USAGE),
    ("cron.rm_invalid_backend", exit::USAGE),
    ("cron.rm_no_selector", exit::USAGE),
    ("cron.rm_no_match", exit::FAILED),
    ("cron.rm_error", exit::FAILED),
    ("cron.enable_invalid_argument", exit::USAGE),
    ("cron.enable_invalid_backend", exit::USAGE),
    ("cron.enable_no_selector", exit::USAGE),
    ("cron.enable_no_match", exit::FAILED),
    ("cron.enable_error", exit::FAILED),
    ("cron.disable_invalid_argument", exit::USAGE),
    ("cron.disable_invalid_backend", exit::USAGE),
    ("cron.disable_no_selector", exit::USAGE),
    ("cron.disable_no_match", exit::FAILED),
    ("cron.disable_error", exit::FAILED),
];

/// The exit status for error `code` (1 for a code not in the table).
fn exit_for(code: &str) -> i32 {
    ERROR_CODES
        .iter()
        .find(|(c, _)| *c == code)
        .map_or(exit::FAILED, |(_, e)| *e)
}

/// A refusal or failure reported before (or instead of) a verb's result.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Fail {
    pub code: String,
    pub message: String,
    pub field: Option<String>,
}

impl Fail {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Fail {
            code: code.into(),
            message: message.into(),
            field: None,
        }
    }

    /// `cron.<verb>_invalid_argument` naming `field`.
    fn arg(verb: &str, field: &str, message: impl Into<String>) -> Self {
        Fail {
            code: format!("cron.{verb}_invalid_argument"),
            message: message.into(),
            field: Some(field.to_string()),
        }
    }

    fn json(&self) -> Value {
        error_value(&self.code, &self.message, self.field.as_deref())
    }
}

/// The JSON error object: `{"code", "message"}`, plus `field` when one
/// argument is at fault.
fn error_value(code: &str, message: &str, field: Option<&str>) -> Value {
    let mut v = json!({ "code": code, "message": message });
    if let Some(f) = field {
        v["field"] = json!(f);
    }
    v
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

/// Refuses any argument `verb` does not accept (`add` also takes
/// `env_<KEY>`), naming it, with a suggestion for a likely typo.
fn check_known_args(verb: &'static str, args: &Args) -> Result<(), Fail> {
    let allowed = verb_args(verb).unwrap_or(&[]);
    let mut keys: Vec<&String> = args.keys().collect();
    keys.sort();
    for key in keys {
        if allowed.contains(&key.as_str()) || (verb == "add" && key.starts_with("env_")) {
            continue;
        }
        let message = match key.as_str() {
            "dry_run" => format!("{verb} does not support dry_run; nothing was done"),
            _ => format!(
                "unknown argument for {verb}: {key}{} (accepted: {}); nothing was done",
                hint(key, allowed),
                allowed.join(", ")
            ),
        };
        return Err(Fail::arg(verb, key, message));
    }
    Ok(())
}

/// Typed access to one verb's arguments. Every value is refused (exit 2,
/// `cron.<verb>_invalid_argument`) when it is empty, holds a line break or
/// other control character, or is not a valid value for its key.
struct ArgReader<'a> {
    verb: &'static str,
    args: &'a Args,
}

impl<'a> ArgReader<'a> {
    fn fail(&self, key: &str, message: impl Into<String>) -> Fail {
        Fail::arg(self.verb, key, message)
    }

    fn has(&self, key: &str) -> bool {
        self.args.contains_key(key)
    }

    /// A text value: never empty, never a control character.
    fn text(&self, key: &str) -> Result<Option<&'a str>, Fail> {
        let Some(v) = self.args.get(key) else {
            return Ok(None);
        };
        if v.trim().is_empty() {
            return Err(self.fail(key, format!("{key} must not be empty; nothing was done")));
        }
        if v.chars().any(char::is_control) {
            return Err(self.fail(
                key,
                format!(
                    "{key} must not contain line breaks or other control characters; \
                     nothing was done"
                ),
            ));
        }
        Ok(Some(v.as_str()))
    }

    fn string(&self, key: &str) -> Result<Option<String>, Fail> {
        Ok(self.text(key)?.map(String::from))
    }

    /// A boolean in the CLI spellings (`true|false|1|0|yes|no|on|off`).
    fn flag(&self, key: &str, default: bool) -> Result<bool, Fail> {
        Ok(self.flag_opt(key)?.unwrap_or(default))
    }

    fn flag_opt(&self, key: &str) -> Result<Option<bool>, Fail> {
        crate::core::lenient::bool_arg(self.args, key)
            .map_err(|e| self.fail(key, format!("{e}; nothing was done")))
    }

    /// One of `allowed`, `default` when absent.
    fn choice(
        &self,
        key: &str,
        default: &'static str,
        allowed: &[&'static str],
    ) -> Result<&'static str, Fail> {
        match self.args.get(key) {
            None => Ok(default),
            Some(v) => allowed.iter().copied().find(|a| *a == v).ok_or_else(|| {
                self.fail(
                    key,
                    format!(
                        "invalid value for {key}: {v:?} (expected {}){}; nothing was done",
                        allowed.join(", "),
                        hint(v, allowed)
                    ),
                )
            }),
        }
    }

    /// An integer in `min..=max`.
    fn int(&self, key: &str, min: i64, max: i64) -> Result<Option<i64>, Fail> {
        let Some(raw) = self.args.get(key) else {
            return Ok(None);
        };
        match raw.trim().parse::<i64>() {
            Ok(v) if (min..=max).contains(&v) && raw.trim() == raw => Ok(Some(v)),
            _ => Err(self.fail(
                key,
                format!(
                    "invalid value for {key}: {raw:?} (expected an integer from {min} to \
                     {max}); nothing was done"
                ),
            )),
        }
    }

    /// `now_unix`: a reference time from 0 to 253402300799 (year 9999).
    fn now_unix(&self) -> Result<Option<i64>, Fail> {
        let Some(raw) = self.args.get("now_unix") else {
            return Ok(None);
        };
        match raw.parse::<i64>() {
            Ok(t) if reference_time_from_unix(t).is_some() => Ok(Some(t)),
            _ => Err(self.fail(
                "now_unix",
                format!(
                    "now_unix must be a Unix time in seconds from 0 to 253402300799 \
                     (year 9999), got {raw:?}; nothing was done"
                ),
            )),
        }
    }

    /// A comma-separated list (a JSON-style `["a","b"]` is accepted too),
    /// with no empty items.
    fn list(&self, key: &str) -> Result<Vec<String>, Fail> {
        let Some(raw) = self.text(key)? else {
            return Ok(Vec::new());
        };
        let inner = raw.trim();
        let inner = inner
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(inner);
        let items: Vec<String> = inner
            .split(',')
            .map(|u| u.trim().trim_matches('"').to_string())
            .collect();
        if items.iter().any(String::is_empty) {
            return Err(self.fail(
                key,
                format!("{key} has an empty item in {raw:?}; nothing was done"),
            ));
        }
        Ok(items)
    }

    fn timeout_ms(&self) -> Result<i64, Fail> {
        Ok(self
            .int("timeout_ms", 1, MAX_TIMEOUT_MS)?
            .unwrap_or(DEFAULT_TIMEOUT_MS))
    }

    fn format(&self) -> Result<OutputFormat, Fail> {
        Ok(match self.choice("format", "json", &["json", "text"])? {
            "text" => OutputFormat::Text,
            _ => OutputFormat::Json,
        })
    }

    /// An `InvalidField` check, reported for this verb.
    fn check(&self, r: Result<(), InvalidField>) -> Result<(), Fail> {
        r.map_err(|e| Fail::arg(self.verb, e.field, e.message))
    }
}

/// True when an error (or anything it wraps) is a tool stopped at the
/// deadline.
pub(crate) fn is_timeout(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::TimedOut)
    })
}

/// Splits off timeouts: `Err` for a deadline that passed (the verb must
/// stop), `Ok(r)` for anything else, so callers can keep going after an
/// ordinary failure.
fn unless_timeout<T>(r: Result<T>) -> Result<Result<T>> {
    match r {
        Err(e) if is_timeout(&e) => Err(e),
        other => Ok(other),
    }
}

/// The JSON error for a provider error: `cron.timeout` for a deadline that
/// passed, `fallback` otherwise.
fn provider_error(e: &anyhow::Error, fallback: &str) -> Value {
    let code = if is_timeout(e) {
        "cron.timeout"
    } else {
        fallback
    };
    error_value(code, &format!("{e:#}"), None)
}

/// Clears the verb's deadline when the verb returns.
struct DeadlineGuard;

impl Drop for DeadlineGuard {
    fn drop(&mut self) {
        crate::core::process::clear_limit();
    }
}

// ===========================================================================
// CronHandle
// ===========================================================================

#[derive(Debug)]
pub struct CronHandle {
    #[allow(dead_code)]
    alias: String,
    provider: Box<dyn CronProvider + Send + Sync>,
}

/// The selector arguments of `rm`, `enable` and `disable`.
const SELECTORS: &[&str] = &[
    "id",
    "schedule",
    "command",
    "match_command",
    "match_comment",
    "unit_name",
    "match_unit",
];

impl CronHandle {
    pub fn new(alias: String, provider: Box<dyn CronProvider>) -> Self {
        Self { alias, provider }
    }

    pub fn from_url(url: &Url) -> Result<Self> {
        let alias = url.host_str().unwrap_or("default").to_string();
        let provider = Box::new(SystemCronProvider::new());
        Ok(Self::new(alias, provider))
    }

    fn list_verb(&self, options: &CronListOptions) -> Result<String> {
        let response = match self.provider.list_cron_entries(options) {
            Ok(r) => r,
            Err(e) => CronListResponse {
                ok: false,
                timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                scope: options.scope.clone(),
                users: options.users.clone(),
                include_system: options.include_system,
                truncated: false,
                entries_total: None,
                entries_returned: 0,
                entries_disabled: 0,
                entries: Vec::new(),
                next_run_timezone: None,
                raw: None,
                paths: None,
                human: None,
                error: Some(provider_error(&e, "cron.list_error")),
                warnings: Vec::new(),
            },
        };
        // A failure is always the JSON error object (text mode included).
        if matches!(options.format, OutputFormat::Text) && response.ok {
            Ok(self.format_as_text(&response))
        } else {
            Ok(serde_json::to_string_pretty(&response)?)
        }
    }

    fn add_verb(&self, options: &CronAddOptions) -> Result<String> {
        let response = match self.provider.add_cron_job(options) {
            Ok(r) => r,
            Err(e) => CronAddResponse {
                ok: false,
                timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                backend_used: None,
                dry_run: options.dry_run,
                duplicate: false,
                job: None,
                preview: None,
                error: Some(provider_error(&e, "cron.add_error")),
                warnings: Vec::new(),
            },
        };
        if matches!(options.format, OutputFormat::Text) && response.ok {
            Ok(self.format_add_as_text(&response))
        } else {
            Ok(serde_json::to_string_pretty(&response)?)
        }
    }

    fn rm_verb(&self, options: &CronRmOptions) -> Result<String> {
        let response = match self.provider.remove_cron_jobs(options) {
            Ok(r) => r,
            Err(e) => CronRmResponse {
                ok: false,
                timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                dry_run: options.dry_run,
                backend: options.backend.clone(),
                cron_modified_sources: Vec::new(),
                systemd_scopes_touched: Vec::new(),
                removed: CronRmRemovedSummary {
                    cron: Vec::new(),
                    systemd: Vec::new(),
                },
                matched_count: CronRmMatchedCount {
                    cron: 0,
                    systemd: 0,
                },
                error: Some(provider_error(&e, "cron.rm_error")),
                warnings: Vec::new(),
            },
        };
        if matches!(options.format, OutputFormat::Text) && response.ok {
            Ok(self.format_rm_as_text(&response))
        } else {
            Ok(serde_json::to_string_pretty(&response)?)
        }
    }

    fn enable_verb(&self, options: &CronEnableOptions) -> Result<String> {
        let response = match self.provider.enable_cron_jobs(options) {
            Ok(r) => r,
            Err(e) => CronEnableResponse {
                ok: false,
                timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                dry_run: options.dry_run,
                backend: options.backend.clone(),
                enabled: CronEnableEnabledSummary {
                    cron: Vec::new(),
                    systemd: Vec::new(),
                },
                matched_count: CronEnableMatchedCount {
                    cron: 0,
                    systemd: 0,
                },
                already_enabled_count: CronEnableAlreadyEnabledCount {
                    cron: 0,
                    systemd: 0,
                },
                cron_modified_sources: Vec::new(),
                systemd_scopes_touched: Vec::new(),
                error: Some(provider_error(&e, "cron.enable_error")),
                warnings: Vec::new(),
            },
        };
        if matches!(options.format, OutputFormat::Text) && response.ok {
            Ok(self.format_enable_as_text(&response))
        } else {
            Ok(serde_json::to_string_pretty(&response)?)
        }
    }

    fn disable_verb(&self, options: &CronDisableOptions) -> Result<String> {
        let response = match self.provider.disable_cron_jobs(options) {
            Ok(r) => r,
            Err(e) => CronDisableResponse {
                ok: false,
                timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                dry_run: options.dry_run,
                backend: options.backend.clone(),
                disabled: CronDisableDisabledSummary {
                    cron: Vec::new(),
                    systemd: Vec::new(),
                },
                matched_count: CronDisableMatchedCount {
                    cron: 0,
                    systemd: 0,
                },
                already_disabled_count: CronDisableAlreadyDisabledCount {
                    cron: 0,
                    systemd: 0,
                },
                cron_modified_sources: Vec::new(),
                systemd_scopes_touched: Vec::new(),
                error: Some(provider_error(&e, "cron.disable_error")),
                warnings: Vec::new(),
            },
        };
        if matches!(options.format, OutputFormat::Text) && response.ok {
            Ok(self.format_disable_as_text(&response))
        } else {
            Ok(serde_json::to_string_pretty(&response)?)
        }
    }
}

// ===========================================================================
// Argument parsing per verb. Everything that does not need the host is
// checked here, before the provider is called.
// ===========================================================================

pub(crate) fn parse_list_args(args: &Args) -> Result<CronListOptions, Fail> {
    let r = ArgReader { verb: "list", args };
    let scope = r.choice("scope", "current", &["current", "user", "system", "all"])?;
    let users = r.list("users")?;
    for u in &users {
        r.check(check_user_name("users", u))?;
    }
    if scope == "user" && users.is_empty() {
        return Err(r.fail(
            "users",
            "scope=user requires users=<user,...>; nothing was read",
        ));
    }
    if !users.is_empty() && !matches!(scope, "user" | "all") {
        return Err(r.fail(
            "users",
            format!(
                "users applies to scope=user and scope=all, not scope={scope}; nothing was read"
            ),
        ));
    }
    let include_files = r.list("include_files")?;
    if let Some(bad) = include_files.iter().find(|p| !p.starts_with('/')) {
        return Err(r.fail(
            "include_files",
            format!("include_files paths must be absolute, got {bad:?}; nothing was read"),
        ));
    }
    let timezone = r.string("timezone")?;
    if let Some(tz) = &timezone {
        r.check(check_timezone("timezone", tz))?;
    }
    Ok(CronListOptions {
        scope: scope.to_string(),
        users,
        include_system: r.flag("include_system", false)?,
        include_files,
        state: r
            .choice("state", "all", &["all", "enabled", "disabled"])?
            .to_string(),
        match_command: r.string("match_command")?,
        match_comment: r.string("match_comment")?,
        match_user: r.string("match_user")?,
        match_source: r.string("match_source")?,
        include_next_run: r.flag("include_next_run", false)?,
        now_unix: r.now_unix()?,
        timezone,
        max_entries: r.int("max_entries", 0, u32::MAX as i64)?.unwrap_or(1024) as u32,
        sort_by: r
            .choice(
                "sort_by",
                "none",
                &["none", "user", "schedule", "command", "source"],
            )?
            .to_string(),
        sort_order: r.choice("sort_order", "asc", &["asc", "desc"])?.to_string(),
        include_raw: r.flag("include_raw", false)?,
        include_paths: r.flag("include_paths", false)?,
        format: r.format()?,
    })
}

/// `env=K=V,K2=V2` and `env_<KEY>=<value>`; `env_<KEY>` wins on a clash.
fn parse_env_args(r: &ArgReader) -> Result<Option<HashMap<String, String>>, Fail> {
    let mut env = HashMap::new();
    if let Some(raw) = r.text("env")? {
        for pair in raw.split(',') {
            match pair.split_once('=') {
                Some((k, v)) if !k.trim().is_empty() => {
                    env.insert(k.trim().to_string(), v.to_string());
                }
                _ => {
                    return Err(r.fail(
                        "env",
                        format!(
                            "env items must be KEY=VALUE separated by commas, got {pair:?}; \
                             nothing was written"
                        ),
                    ));
                }
            }
        }
    }
    let mut keys: Vec<&String> = r.args.keys().filter(|k| k.starts_with("env_")).collect();
    keys.sort();
    for key in keys {
        let name = &key["env_".len()..];
        if name.is_empty() {
            return Err(r.fail(
                "env",
                "env_<KEY> needs a variable name after env_; nothing was written",
            ));
        }
        let value = r.args[key.as_str()].clone();
        if value.chars().any(char::is_control) {
            return Err(r.fail(
                "env",
                format!("{key} must not contain line breaks or other control characters; nothing was written"),
            ));
        }
        env.insert(name.to_string(), value);
    }
    Ok((!env.is_empty()).then_some(env))
}

pub(crate) fn parse_add_args(args: &Args) -> Result<CronAddOptions, Fail> {
    let r = ArgReader { verb: "add", args };
    let Some(schedule) = args.get("schedule") else {
        return Err(Fail {
            code: "cron.add_missing_schedule".into(),
            message: "schedule is required, such as schedule='0 2 * * *' or schedule=@daily; \
                      nothing was written"
                .into(),
            field: Some("schedule".into()),
        });
    };
    if schedule.chars().any(char::is_control) {
        return Err(r.fail(
            "schedule",
            "schedule must not contain line breaks or other control characters; nothing was \
             written",
        ));
    }
    if let Err(e) = check_schedule_syntax(schedule).and_then(|()| {
        parse_schedule_with(schedule, true)
            .map(|_| ())
            .map_err(|m| invalid("schedule", m))
    }) {
        return Err(Fail {
            code: "cron.add_invalid_schedule".into(),
            message: format!("Invalid cron schedule '{schedule}': {}", e.message),
            field: Some("schedule".into()),
        });
    }
    let command = match args.get("command") {
        Some(c) if !c.trim().is_empty() => c.clone(),
        _ => {
            return Err(Fail {
                code: "cron.add_missing_command".into(),
                message: "command is required and must not be empty; nothing was written".into(),
                field: Some("command".into()),
            });
        }
    };
    if command.chars().any(char::is_control) {
        return Err(r.fail(
            "command",
            "command must not contain line breaks or other control characters; nothing was \
             written",
        ));
    }
    let id = r.string("id")?;
    if let Some(id) = &id {
        r.check(check_job_id(id))?;
    }
    let timezone = r.string("timezone")?;
    if let Some(tz) = &timezone {
        r.check(check_timezone("timezone", tz))?;
    }
    let scope = match r.has("scope") {
        true => Some(
            r.choice("scope", "current", &["current", "user", "system"])?
                .to_string(),
        ),
        false => None,
    };
    let unit_scope = match r.has("unit_scope") {
        true => Some(
            r.choice("unit_scope", "auto", &["auto", "user", "system"])?
                .to_string(),
        ),
        false => None,
    };
    let options = CronAddOptions {
        schedule: schedule.clone(),
        command,
        backend: r
            .choice("backend", "auto", &["auto", "cron", "systemd"])?
            .to_string(),
        id,
        description: r.string("description")?,
        allow_duplicate: r.flag("allow_duplicate", true)?,
        dry_run: r.flag("dry_run", false)?,
        scope,
        user: r.string("user")?,
        cron_file: r.string("cron_file")?,
        unit_name: r.string("unit_name")?,
        unit_scope,
        persistent: r.flag_opt("persistent")?,
        accuracy_sec: r.string("accuracy_sec")?,
        random_delay_sec: r.string("random_delay_sec")?,
        service_working_dir: r.string("service_working_dir")?,
        service_user: r.string("service_user")?,
        env: parse_env_args(&r)?,
        include_next_run: r.flag("include_next_run", true)?,
        now_unix: r.now_unix()?,
        timezone,
        format: r.format()?,
    };
    // The checks that do not depend on the backend.
    r.check(validate_add_options(&options, "", None))?;
    Ok(options)
}

/// The arguments shared by `rm`, `enable` and `disable`.
pub(crate) struct SelectArgs {
    pub id: Option<String>,
    pub backend: String,
    pub scope: String,
    pub users: Vec<String>,
    pub schedule: Option<String>,
    pub command: Option<String>,
    pub match_command: Option<String>,
    pub match_comment: Option<String>,
    pub cron_file: Option<String>,
    pub unit_name: Option<String>,
    pub unit_scope: String,
    pub match_unit: Option<String>,
    pub require_match: bool,
    pub dry_run: bool,
    pub format: OutputFormat,
}

/// Checks the selector and target arguments of `rm`, `enable` and
/// `disable` (`own_flag` is the verb's own boolean: `remove_units`,
/// `start_now` or `stop_now`, which only applies to timers).
fn parse_select_args(verb: &'static str, args: &Args, own_flag: &str) -> Result<SelectArgs, Fail> {
    let r = ArgReader { verb, args };
    let backend = match args.get("backend") {
        None => "both",
        Some(b) => ["both", "cron", "systemd"]
            .into_iter()
            .find(|a| a == b)
            .ok_or_else(|| Fail {
                code: format!("cron.{verb}_invalid_backend"),
                message: format!(
                    "Invalid backend '{b}'. Must be one of: cron, systemd, both{}",
                    hint(b, &["cron", "systemd", "both"])
                ),
                field: Some("backend".into()),
            })?,
    };
    if !SELECTORS.iter().any(|s| args.contains_key(*s)) {
        return Err(Fail {
            code: format!("cron.{verb}_no_selector"),
            message: "At least one selector must be provided: id, schedule, command, \
                      match_command, match_comment, unit_name, or match_unit"
                .into(),
            field: None,
        });
    }
    let id = r.string("id")?;
    if let Some(id) = &id {
        r.check(check_job_id(id))?;
    }
    let schedule = r.string("schedule")?;
    if let Some(s) = &schedule
        && let Err(e) = check_schedule_syntax(s.trim()).and_then(|()| {
            parse_schedule(s.trim())
                .map(|_| ())
                .map_err(|m| invalid("schedule", m))
        })
    {
        return Err(r.fail("schedule", e.message));
    }
    let unit_name = r.string("unit_name")?;
    if let Some(u) = &unit_name {
        r.check(check_unit_name(
            "unit_name",
            u.strip_suffix(".timer").unwrap_or(u),
        ))?;
    }
    let cron_file = r.string("cron_file")?;
    if let Some(f) = &cron_file {
        r.check(check_system_cron_file(f))?;
    }
    let scope = r.choice("scope", "all", &["all", "current", "user", "system"])?;
    let users = r.list("users")?;
    for u in &users {
        r.check(check_user_name("users", u))?;
    }
    if scope == "user" && users.is_empty() {
        return Err(r.fail(
            "users",
            "users must name at least one user with scope=user; nothing was done",
        ));
    }
    if !users.is_empty() && !matches!(scope, "user" | "all") {
        return Err(r.fail(
            "users",
            format!(
                "users applies to scope=user and scope=all, not scope={scope}; nothing was done"
            ),
        ));
    }
    let unit_scope = r.choice("unit_scope", "auto", &["auto", "user", "system", "both"])?;
    // Options of one backend are refused when only the other one runs, so
    // nothing passed is silently ignored.
    let given = |k: &str| args.contains_key(k);
    if backend == "cron" {
        for k in ["unit_name", "match_unit", "unit_scope", own_flag] {
            if given(k) {
                return Err(r.fail(
                    k,
                    format!("{k} applies to systemd timers, but backend=cron; nothing was done"),
                ));
            }
        }
    }
    if backend == "systemd" {
        for k in ["schedule", "scope", "users", "cron_file"] {
            if given(k) {
                return Err(r.fail(
                    k,
                    format!(
                        "{k} applies to crontab entries, but backend=systemd; nothing was done"
                    ),
                ));
            }
        }
    }
    Ok(SelectArgs {
        id,
        backend: backend.to_string(),
        scope: scope.to_string(),
        users,
        schedule,
        command: r.string("command")?,
        match_command: r.string("match_command")?,
        match_comment: r.string("match_comment")?,
        cron_file,
        unit_name,
        unit_scope: unit_scope.to_string(),
        match_unit: r.string("match_unit")?,
        require_match: r.flag("require_match", true)?,
        dry_run: r.flag("dry_run", false)?,
        format: r.format()?,
    })
}

pub(crate) fn parse_rm_args(args: &Args) -> Result<CronRmOptions, Fail> {
    let s = parse_select_args("rm", args, "remove_units")?;
    let remove_units = ArgReader { verb: "rm", args }.flag("remove_units", true)?;
    Ok(CronRmOptions {
        id: s.id,
        backend: s.backend,
        scope: s.scope,
        users: s.users,
        schedule: s.schedule,
        command: s.command,
        match_command: s.match_command,
        match_comment: s.match_comment,
        cron_file: s.cron_file,
        unit_name: s.unit_name,
        unit_scope: s.unit_scope,
        match_unit: s.match_unit,
        require_match: s.require_match,
        remove_units,
        dry_run: s.dry_run,
        format: s.format,
    })
}

pub(crate) fn parse_enable_args(args: &Args) -> Result<CronEnableOptions, Fail> {
    let s = parse_select_args("enable", args, "start_now")?;
    let start_now = ArgReader {
        verb: "enable",
        args,
    }
    .flag("start_now", true)?;
    Ok(CronEnableOptions {
        id: s.id,
        backend: s.backend,
        scope: s.scope,
        users: s.users,
        schedule: s.schedule,
        command: s.command,
        match_command: s.match_command,
        match_comment: s.match_comment,
        cron_file: s.cron_file,
        unit_name: s.unit_name,
        unit_scope: s.unit_scope,
        match_unit: s.match_unit,
        require_match: s.require_match,
        start_now,
        dry_run: s.dry_run,
        format: s.format,
    })
}

pub(crate) fn parse_disable_args(args: &Args) -> Result<CronDisableOptions, Fail> {
    let s = parse_select_args("disable", args, "stop_now")?;
    let stop_now = ArgReader {
        verb: "disable",
        args,
    }
    .flag("stop_now", true)?;
    Ok(CronDisableOptions {
        id: s.id,
        backend: s.backend,
        scope: s.scope,
        users: s.users,
        schedule: s.schedule,
        command: s.command,
        match_command: s.match_command,
        match_comment: s.match_comment,
        cron_file: s.cron_file,
        unit_name: s.unit_name,
        unit_scope: s.unit_scope,
        match_unit: s.match_unit,
        require_match: s.require_match,
        stop_now,
        dry_run: s.dry_run,
        format: s.format,
    })
}

/// The exit status for a verb's rendered output: a failure if it is a JSON
/// object with `"ok": false`, carrying `[<code>] <message>` as the reason
/// and the exit code that goes with the code.
fn verb_status(output: &str) -> Status {
    let Ok(value) = serde_json::from_str::<Value>(output) else {
        return Status::ok(); // text output is only rendered for successes
    };
    if value.get("ok").and_then(Value::as_bool) != Some(false) {
        return Status::ok();
    }
    let error = value.get("error");
    let code = error
        .and_then(|e| e.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("cron.failed");
    let message = error
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("operation failed");
    Status::coded(exit_for(code), code, message)
}

/// Prints a refusal as the JSON error object and returns its status.
fn refuse(io: &mut IoStreams, fail: &Fail) -> Result<Status> {
    let out = json!({ "ok": false, "error": fail.json() });
    writeln!(io.stdout, "{}", serde_json::to_string_pretty(&out)?)?;
    Ok(Status::coded(
        exit_for(&fail.code),
        &fail.code,
        &fail.message,
    ))
}

impl Handle for CronHandle {
    fn verbs(&self) -> &'static [&'static str] {
        VERBS
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&CRON_HELP)
    }

    fn call(&self, method: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check for help request before processing verbs
        if let Some(verb) = help_request(method, args) {
            write!(
                io.stdout,
                "{}",
                help::render_legacy("cron", &CRON_HELP, self.verbs(), verb.as_deref())
            )?;
            return Ok(Status::ok());
        }
        let Some(verb) = VERBS.iter().copied().find(|v| *v == method) else {
            let fail = Fail::new(
                "cron.invalid_argument",
                format!(
                    "unknown verb for cron: {method:?}{} (verbs: {}); nothing was done",
                    hint(method, VERBS),
                    VERBS.join(", ")
                ),
            );
            return refuse(io, &fail);
        };
        if let Err(fail) = check_known_args(verb, args) {
            return refuse(io, &fail);
        }
        let timeout_ms = match (ArgReader { verb, args }).timeout_ms() {
            Ok(t) => t,
            Err(fail) => return refuse(io, &fail),
        };
        let parsed = match verb {
            "list" => parse_list_args(args).map(Parsed::List),
            "add" => parse_add_args(args).map(Parsed::Add),
            "rm" => parse_rm_args(args).map(Parsed::Rm),
            "enable" => parse_enable_args(args).map(Parsed::Enable),
            _ => parse_disable_args(args).map(Parsed::Disable),
        };
        let parsed = match parsed {
            Ok(p) => p,
            Err(fail) => return refuse(io, &fail),
        };
        // Every tool the verb runs is stopped at this deadline.
        let _deadline = DeadlineGuard;
        crate::core::process::limit(Duration::from_millis(timeout_ms as u64));
        let result = match &parsed {
            Parsed::List(o) => self.list_verb(o)?,
            Parsed::Add(o) => self.add_verb(o)?,
            Parsed::Rm(o) => self.rm_verb(o)?,
            Parsed::Enable(o) => self.enable_verb(o)?,
            Parsed::Disable(o) => self.disable_verb(o)?,
        };
        writeln!(io.stdout, "{}", result)?;
        io.stdout.flush()?;
        Ok(verb_status(&result))
    }
}

/// A verb's checked arguments.
enum Parsed {
    List(CronListOptions),
    Add(CronAddOptions),
    Rm(CronRmOptions),
    Enable(CronEnableOptions),
    Disable(CronDisableOptions),
}

// ===========================================================================
// Text output
// ===========================================================================

impl CronHandle {
    fn format_as_text(&self, response: &CronListResponse) -> String {
        let mut output = String::new();

        output.push_str("Cron Jobs\n");
        output.push_str("=========\n\n");

        output.push_str(&format!("Scope      : {}\n", response.scope));
        if !response.users.is_empty() {
            output.push_str(&format!("Users      : {}\n", response.users.join(", ")));
        }
        output.push_str(&format!(
            "System     : {}\n",
            if response.include_system {
                "included"
            } else {
                "excluded"
            }
        ));
        let jobs = |enabled: bool| {
            response
                .entries
                .iter()
                .filter(|e| !e.comment_only && e.enabled == enabled)
                .count()
        };
        output.push_str(&format!(
            "Returned   : {} ({} enabled, {} disabled)\n\n",
            response.entries_returned,
            jobs(true),
            jobs(false)
        ));

        for entry in &response.entries {
            output.push_str(&format!("[{}]", entry.source));
            if let Some(ref file) = entry.source_file {
                output.push_str(&format!(" {}:{}", file, entry.source_line.unwrap_or(0)));
            } else if let Some(ref user) = entry.user {
                output.push_str(&format!(" crontab({})", user));
                if let Some(line) = entry.source_line {
                    output.push_str(&format!(":{}", line));
                }
            }
            output.push('\n');

            output.push_str(&format!(
                "  Enabled  : {}\n",
                if entry.comment_only {
                    "- (comment line)"
                } else if entry.enabled {
                    "yes"
                } else {
                    "no (commented)"
                }
            ));

            if let Some(ref user) = entry.user {
                output.push_str(&format!("  User     : {}\n", user));
            }

            if let Some(ref schedule) = entry.schedule {
                let description = match schedule.as_str() {
                    "0 2 * * *" => " (nightly)",
                    "0 0 * * *" => " (daily)",
                    "0 0 * * 0" => " (weekly)",
                    _ => "",
                };
                output.push_str(&format!("  Schedule : {}{}\n", schedule, description));
            }

            if let Some(ref special) = entry.special {
                output.push_str(&format!("  Special  : {}\n", special));
            }

            if let Some(ref command) = entry.command {
                output.push_str(&format!("  Command  : {}\n", command));
            }

            if let Some(ref comment) = entry.comment {
                output.push_str(&format!("  Comment  : {}\n", comment));
            }

            if let Some(ref tz) = entry.timezone {
                output.push_str(&format!("  TimeZone : {}\n", tz));
            }

            if let Some(ref next_run) = entry.next_run_iso8601 {
                output.push_str(&format!("  Next Run : {}\n", next_run));
            }

            output.push('\n');
        }

        if !response.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &response.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        } else {
            output.push_str("Warnings:\n  (none)\n");
        }

        if response.truncated {
            output.push_str(&format!(
                "\nNote: Entry list truncated to max_entries={}.\n",
                response.entries_returned
            ));
        }

        output
    }
    fn format_add_as_text(&self, response: &CronAddResponse) -> String {
        let mut output = String::new();

        if response.ok {
            output.push_str("Cron Job Added Successfully\n");
            output.push_str("===========================\n\n");

            if let Some(ref job) = response.job {
                output.push_str(&format!("Backend    : {}\n", job.backend));
                output.push_str(&format!("Schedule   : {}\n", job.schedule));
                output.push_str(&format!("Command    : {}\n", job.command));
                if let Some(ref id) = job.id {
                    output.push_str(&format!("Job ID     : {}\n", id));
                }
                output.push_str(&format!("Location   : {} scope\n", job.location.scope));
                if let Some(ref file) = job.location.file {
                    output.push_str(&format!("File       : {}\n", file));
                }
                if let Some(ref unit_name) = job.location.unit_name {
                    output.push_str(&format!("Unit       : {}\n", unit_name));
                }
                if let Some(ref next_run) = job.next_run_iso8601 {
                    output.push_str(&format!("Next Run   : {}\n", next_run));
                }
            }

            if response.dry_run {
                output.push_str("\n[DRY RUN] No changes were made.\n");
            }

            if response.duplicate {
                output.push_str("\n[DUPLICATE] Job already exists - no changes made.\n");
            }
        } else {
            output.push_str("Cron Job Add Failed\n");
            output.push_str("===================\n\n");
            if let Some(ref error) = response.error {
                if let Some(code) = error.get("code").and_then(|c| c.as_str()) {
                    output.push_str(&format!("Error Code : {}\n", code));
                }
                if let Some(message) = error.get("message").and_then(|m| m.as_str()) {
                    output.push_str(&format!("Message    : {}\n", message));
                }
            }
        }

        if !response.warnings.is_empty() {
            output.push_str("\nWarnings:\n");
            for warning in &response.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        }

        output
    }
    fn format_rm_as_text(&self, response: &CronRmResponse) -> String {
        let mut output = String::new();

        output.push_str("Remove Scheduled Jobs (cron + systemd)\n");
        output.push_str("======================================\n\n");

        output.push_str(&format!("Backend     : {}\n", response.backend));
        output.push_str(&format!("Dry Run     : {}\n", response.dry_run));
        output.push('\n');

        // Cron results
        output.push_str("Cron:\n");
        if response.removed.cron.is_empty() {
            output.push_str("  No cron jobs removed.\n");
        } else {
            output.push_str(&format!(
                "  Removed {} job(s):\n",
                response.removed.cron.len()
            ));
            for entry in &response.removed.cron {
                let line_info = entry
                    .line_number
                    .map(|n| format!(": line {}", n))
                    .unwrap_or_default();
                output.push_str(&format!("    {}{}\n", entry.source, line_info));
                if let (Some(schedule), Some(command)) = (&entry.schedule, &entry.command) {
                    let id_info = entry
                        .id
                        .as_ref()
                        .map(|id| format!("  # id={}", id))
                        .unwrap_or_default();
                    output.push_str(&format!("      {} {}{}\n", schedule, command, id_info));
                }
            }
        }
        output.push('\n');

        // systemd results
        output.push_str("Systemd:\n");
        if response.removed.systemd.is_empty() {
            output.push_str("  No systemd timers removed.\n");
        } else {
            output.push_str(&format!(
                "  Removed {} timer(s):\n",
                response.removed.systemd.len()
            ));
            for entry in &response.removed.systemd {
                let timer_name = entry.timer_unit.as_deref().unwrap_or("unknown");
                let service_info = entry
                    .service_unit
                    .as_ref()
                    .map(|s| format!(" ({})", s))
                    .unwrap_or_default();
                output.push_str(&format!(
                    "    [{}] {}{}\n",
                    entry.unit_scope, timer_name, service_info
                ));
            }
        }
        output.push('\n');

        // Warnings
        output.push_str("Warnings:\n");
        if response.warnings.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for warning in &response.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        }

        if response.dry_run {
            output.push_str("\nNote: dry-run mode — no changes were applied.\n");
        }

        if response.matched_count.cron == 0 && response.matched_count.systemd == 0 {
            output.push_str("\nNo matching jobs found. No changes applied.\n");
        }

        output
    }
    fn format_enable_as_text(&self, response: &CronEnableResponse) -> String {
        let mut output = String::new();

        output.push_str("Enable Scheduled Jobs (cron + systemd)\n");
        output.push_str("======================================\n\n");

        output.push_str(&format!("Backend     : {}\n", response.backend));
        output.push_str(&format!("Dry Run     : {}\n", response.dry_run));
        output.push('\n');

        // Cron results
        output.push_str("Cron:\n");
        if response.enabled.cron.is_empty() {
            output.push_str("  No cron jobs enabled.\n");
        } else {
            output.push_str(&format!(
                "  Enabled {} job(s):\n",
                response.enabled.cron.len()
            ));
            for entry in &response.enabled.cron {
                let line_info = entry
                    .line_number
                    .map(|n| format!(": line {}", n))
                    .unwrap_or_default();
                output.push_str(&format!("    {}{}\n", entry.source, line_info));
                if let (Some(schedule), Some(command)) = (&entry.schedule, &entry.command) {
                    let id_info = entry
                        .id
                        .as_ref()
                        .map(|id| format!("  # id={}", id))
                        .unwrap_or_default();
                    output.push_str(&format!("      {} {}{}\n", schedule, command, id_info));
                }
            }
        }
        output.push('\n');

        // systemd results
        output.push_str("Systemd:\n");
        if response.enabled.systemd.is_empty() {
            output.push_str("  No systemd timers enabled.\n");
        } else {
            output.push_str(&format!(
                "  Enabled {} timer(s):\n",
                response.enabled.systemd.len()
            ));
            for entry in &response.enabled.systemd {
                let timer_name = entry.timer_unit.as_deref().unwrap_or("unknown");
                let service_info = entry
                    .service_unit
                    .as_ref()
                    .map(|s| format!(" ({})", s))
                    .unwrap_or_default();
                output.push_str(&format!(
                    "    [{}] {}{}\n",
                    entry.unit_scope, timer_name, service_info
                ));
                output.push_str(&format!(
                    "    Started now: {}\n",
                    if entry.started_now { "yes" } else { "no" }
                ));
            }
        }
        output.push('\n');

        // Warnings
        output.push_str("Warnings:\n");
        if response.warnings.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for warning in &response.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        }

        if response.dry_run {
            output.push_str("\nNote: dry-run mode — no changes were applied.\n");
        }

        if response.matched_count.cron == 0 && response.matched_count.systemd == 0 {
            output.push_str("\nNo matching jobs found. No changes applied.\n");
        }

        output
    }
    fn format_disable_as_text(&self, response: &CronDisableResponse) -> String {
        let mut output = String::new();

        output.push_str("Disable Scheduled Jobs (cron + systemd)\n");
        output.push_str("=======================================\n\n");

        output.push_str(&format!("Backend     : {}\n", response.backend));
        output.push_str(&format!("Dry Run     : {}\n\n", response.dry_run));

        output.push_str("Cron:\n");
        if response.disabled.cron.is_empty() {
            output.push_str("  No cron jobs disabled.\n");
        } else {
            output.push_str(&format!(
                "  Disabled {} job(s):\n",
                response.disabled.cron.len()
            ));
            for entry in &response.disabled.cron {
                output.push_str(&format!("    {}", entry.source));
                if let Some(line_no) = entry.line_number {
                    output.push_str(&format!(": line {}", line_no));
                }
                output.push('\n');
                if let (Some(schedule), Some(command)) = (&entry.schedule, &entry.command) {
                    output.push_str(&format!("      {} {}", schedule, command));
                    if let Some(id) = &entry.id {
                        output.push_str(&format!("  # id={}", id));
                    }
                    output.push('\n');
                }
            }
        }

        output.push_str("\nSystemd:\n");
        if response.disabled.systemd.is_empty() {
            output.push_str("  No systemd timers disabled.\n");
        } else {
            output.push_str(&format!(
                "  Disabled {} timer(s):\n",
                response.disabled.systemd.len()
            ));
            for entry in &response.disabled.systemd {
                output.push_str(&format!("    [{}] ", entry.unit_scope));
                if let Some(timer_unit) = &entry.timer_unit {
                    output.push_str(timer_unit);
                    if let Some(service_unit) = &entry.service_unit {
                        output.push_str(&format!(" ({})", service_unit));
                    }
                } else {
                    output.push_str("(unknown)");
                }
                output.push('\n');
                output.push_str(&format!(
                    "    Stopped now: {}\n",
                    if entry.stopped_now { "yes" } else { "no" }
                ));
            }
        }

        output.push_str("\nWarnings:\n");
        if response.warnings.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for warning in &response.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        }

        if response.dry_run {
            output.push_str("\nNote: dry-run mode — no changes were applied.\n");
        }

        if response.matched_count.cron == 0 && response.matched_count.systemd == 0 {
            output.push_str("\nNo matching jobs found. No changes applied.\n");
        }

        output
    }
}

// ===========================================================================
// Help and line helpers
// ===========================================================================

/// Returns `Some(verb)` if this call is a help request, where `verb` is the
/// verb help was asked for (`help(verb=rm)`, `--help=rm`, `help=rm`), if any.
/// Matching is exact, so ordinary verbs and arguments are never mistaken
/// for help.
fn help_request(method: &str, args: &Args) -> Option<Option<String>> {
    let named = |v: Option<&String>| {
        v.map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "true")
    };
    if let Some(v) = method.strip_prefix("--help=") {
        return Some(Some(v.to_string()).filter(|v| !v.is_empty()));
    }
    if method == "help" || method == "h" || help::is_help_flag(method) {
        return Some(named(args.get("verb")).or_else(|| named(args.get("help"))));
    }
    if args.contains_key("help") || args.contains_key("--help") {
        return Some(
            named(args.get("help"))
                .or_else(|| named(args.get("--help")))
                .or_else(|| Some(method.to_string()).filter(|m| !m.is_empty())),
        );
    }
    None
}
/// The timer unit named in a `systemctl list-timers --plain` line. Its
/// columns (NEXT, LEFT, LAST, PASSED, UNIT, ACTIVATES) have a variable
/// number of words, so the UNIT column is found by its `.timer` suffix.
fn timer_unit(line: &str) -> Option<&str> {
    line.split_whitespace().find(|w| w.ends_with(".timer"))
}

/// Whether `parts` (a line split on whitespace) starts with a cron schedule
/// and has a command: five valid time fields, or a known `@` keyword.
fn looks_like_cron_schedule(parts: &[&str]) -> bool {
    const SPECIAL: &[&str] = &[
        "@reboot",
        "@yearly",
        "@annually",
        "@monthly",
        "@weekly",
        "@daily",
        "@midnight",
        "@hourly",
    ];
    if let Some(first) = parts.first()
        && first.starts_with('@')
    {
        return parts.len() >= 2 && SPECIAL.contains(&first.to_ascii_lowercase().as_str());
    }
    parts.len() >= 6 && parts[..5].iter().all(|f| is_cron_field(f))
}

/// One cron time field: comma-separated `*`, `N`, `N-M`, optionally `/step`,
/// where N and M are numbers or three-letter month/day names.
fn is_cron_field(field: &str) -> bool {
    let value = |v: &str| {
        (!v.is_empty() && v.len() <= 2 && v.bytes().all(|b| b.is_ascii_digit()))
            || (v.len() == 3 && v.bytes().all(|b| b.is_ascii_alphabetic()))
    };
    !field.is_empty()
        && field.split(',').all(|item| {
            let (range, step) = match item.split_once('/') {
                Some((r, s)) => (r, Some(s)),
                None => (item, None),
            };
            let step_ok =
                step.is_none_or(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()));
            let range_ok = range == "*"
                || match range.split_once('-') {
                    Some((a, b)) => value(a) && value(b),
                    None => value(range),
                };
            step_ok && range_ok
        })
}

// ===========================================================================
// CronProvider: the verbs, behind a trait so dispatch can be tested
// ===========================================================================

pub trait CronProvider: std::fmt::Debug + Send + Sync {
    fn list_cron_entries(&self, options: &CronListOptions) -> Result<CronListResponse>;
    fn add_cron_job(&self, options: &CronAddOptions) -> Result<CronAddResponse>;
    fn remove_cron_jobs(&self, options: &CronRmOptions) -> Result<CronRmResponse>;
    fn enable_cron_jobs(&self, options: &CronEnableOptions) -> Result<CronEnableResponse>;
    fn disable_cron_jobs(&self, options: &CronDisableOptions) -> Result<CronDisableResponse>;
}

#[derive(Debug)]
pub struct SystemCronProvider {
    current_user: String,
    host: Box<dyn CronHost>,
}

impl SystemCronProvider {
    pub fn new() -> Self {
        let current_user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .ok()
            .filter(|u| !u.is_empty())
            .or_else(invoking_user_name)
            .unwrap_or_else(|| "unknown".to_string());

        Self::with_host(current_user, Box::new(SystemCronHost::new()))
    }

    /// A provider acting as `current_user` on `host` (tests pass a mock).
    pub fn with_host(current_user: String, host: Box<dyn CronHost>) -> Self {
        Self { current_user, host }
    }

    fn is_root(&self) -> bool {
        self.current_user == "root"
    }
}

// ===========================================================================
// CronHost: everything the provider reads from or changes on the host
// ===========================================================================

/// What a tool printed and whether it succeeded.
#[derive(Debug, Clone, Default)]
pub struct ToolOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Everything the cron provider reads from or changes on the host: crontab
/// and cron files, systemd units, tool probes and the clock. The provider's
/// logic only goes through this, so tests can run every verb against a mock.
pub trait CronHost: std::fmt::Debug + Send + Sync {
    /// Reads and writes crontabs and system cron files.
    fn editor(&self) -> &dyn CronEditor;
    /// Runs systemctl and reads and writes unit files.
    fn systemd(&self) -> &dyn SystemdEditor;
    /// A user's crontab as `list` reads it ("" when the user has none).
    fn list_user_crontab(&self, user: &str) -> Result<String>;
    fn read_system_crontab(&self) -> Result<String>;
    /// `(file name, content)` of each file in /etc/cron.d.
    fn read_cron_d_files(&self) -> Result<Vec<(String, String)>>;
    fn read_file(&self, path: &str) -> Result<String>;
    /// Whether `program arg` can be run (backend availability).
    fn command_runs(&self, program: &str, arg: &str) -> bool;
    /// What `crontab -V` prints when it succeeds. cronie's crontab prints its
    /// package string (`cronie 1.7.2`); Debian/vixie and busybox crontab have
    /// no `-V` and fail with a usage message, giving `None`.
    fn crontab_version(&self) -> Option<String>;
    fn now(&self) -> DateTime<Utc>;
    /// The zone cron and systemd read schedules in when none is given: the
    /// host's local time zone.
    fn local_zone(&self) -> RunZone;
}

pub trait CronEditor: std::fmt::Debug + Send + Sync {
    /// A user's crontab; "" when the user has none. Any other failure is an
    /// error, so a crontab that could not be read is never replaced.
    fn read_user_crontab(&self, user: &str) -> Result<String>;
    fn write_user_crontab(&self, user: &str, content: &str) -> Result<()>;
    /// A system cron file; None when it does not exist.
    fn read_system_file(&self, path: &str) -> Result<Option<String>>;
    fn write_system_file(&self, path: &str, content: &str) -> Result<()>;
}

pub trait SystemdEditor: std::fmt::Debug + Send + Sync {
    /// Runs `systemctl [--user] <args>`.
    fn systemctl(&self, user_mode: bool, args: &[&str]) -> Result<ToolOutput>;
    /// Where `add` writes units: ~/.config/systemd/user or /etc/systemd/system.
    fn unit_dir(&self, user_mode: bool) -> Result<String>;
    /// A unit file's content; None when it does not exist.
    fn read_unit_file(&self, path: &str) -> Result<Option<String>>;
    fn write_unit_file(&self, path: &str, content: &str) -> Result<()>;
    /// Removes a unit file; false when there was none.
    fn remove_unit_file(&self, path: &str) -> Result<bool>;
    fn create_directory(&self, path: &str) -> Result<()>;
}

/// `systemctl [--user] <args>`, as an error when it fails.
fn systemctl_ok(ed: &dyn SystemdEditor, user_mode: bool, args: &[&str]) -> Result<()> {
    let out = ed.systemctl(user_mode, args)?;
    if out.success {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "systemctl{} {} failed: {}",
            if user_mode { " --user" } else { "" },
            args.join(" "),
            out.stderr.trim()
        ))
    }
}

/// Whether the (user or system) service manager answers. `systemctl
/// --version` works without one, so the manager itself is asked.
fn manager_reachable(ed: &dyn SystemdEditor, user_mode: bool) -> Result<Option<String>> {
    let out = ed.systemctl(user_mode, &["show", "--property=Version"])?;
    Ok((!out.success).then(|| out.stderr.trim().to_string()))
}

/// Every timer of a scope: the loaded ones (`list-timers --all`) and the
/// installed ones (`list-unit-files`), since a disabled, stopped timer is
/// no longer loaded after a daemon-reload and only the second list has it.
fn discover_timers(ed: &dyn SystemdEditor, user_mode: bool) -> Result<Vec<String>> {
    let mut timers: Vec<String> = Vec::new();
    for args in [
        &[
            "list-timers",
            "--all",
            "--no-legend",
            "--plain",
            "--no-pager",
        ][..],
        &[
            "list-unit-files",
            "--type=timer",
            "--no-legend",
            "--plain",
            "--no-pager",
        ][..],
    ] {
        let out = ed.systemctl(user_mode, args)?;
        if !out.success {
            return Err(anyhow::anyhow!(
                "systemctl{} {} failed: {}",
                if user_mode { " --user" } else { "" },
                args.join(" "),
                out.stderr.trim()
            ));
        }
        for line in out.stdout.lines() {
            if let Some(t) = timer_unit(line)
                && !timers.iter().any(|x| x == t)
            {
                timers.push(t.to_string());
            }
        }
    }
    Ok(timers)
}

/// The name of the user this process runs as (from the password database).
fn invoking_user_name() -> Option<String> {
    // SAFETY: getpwuid_r writes into `pwd` and `buf`, which outlive the
    // call; `pw_name` points into `buf`.
    unsafe {
        let uid = libc::getuid();
        let mut buf = vec![0 as libc::c_char; 16 * 1024];
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result);
        if rc != 0 || result.is_null() || pwd.pw_name.is_null() {
            return None;
        }
        Some(
            std::ffi::CStr::from_ptr(pwd.pw_name)
                .to_string_lossy()
                .into_owned(),
        )
    }
}

/// `-u <user>` unless `user` is the user running resh: cronie refuses `-u`
/// to anyone but root, even for the caller's own name.
fn crontab_user_args(user: &str) -> Vec<String> {
    if invoking_user_name().as_deref() == Some(user) {
        Vec::new()
    } else {
        vec!["-u".to_string(), user.to_string()]
    }
}

/// Runs a tool under the verb's deadline (`core::process::run`). A missing
/// tool, a timeout or any other failure to run it is an error that keeps
/// the underlying `io::Error`.
fn run_tool(cmd: &mut Command) -> Result<std::process::Output> {
    let tool = cmd.get_program().to_string_lossy().into_owned();
    crate::core::process::run(cmd, None).map_err(|e| {
        let what = match e.kind() {
            std::io::ErrorKind::NotFound => format!("{tool} was not found (is it installed?)"),
            std::io::ErrorKind::TimedOut => format!("{tool} was stopped at the deadline"),
            _ => format!("cannot run {tool}"),
        };
        anyhow::Error::new(e).context(what)
    })
}

/// `crontab -l` printed "no crontab for <user>": an empty crontab.
fn no_crontab(stderr: &[u8]) -> bool {
    String::from_utf8_lossy(stderr).contains("no crontab for")
}

/// The real host.
#[derive(Debug)]
pub struct SystemCronHost {
    editor: SystemCronEditor,
    systemd: SystemSystemdEditor,
}

impl SystemCronHost {
    pub fn new() -> Self {
        Self {
            editor: SystemCronEditor {},
            systemd: SystemSystemdEditor {},
        }
    }
}

impl CronHost for SystemCronHost {
    fn editor(&self) -> &dyn CronEditor {
        &self.editor
    }

    fn systemd(&self) -> &dyn SystemdEditor {
        &self.systemd
    }

    fn list_user_crontab(&self, user: &str) -> Result<String> {
        match self.editor.read_user_crontab(user) {
            Ok(content) => Ok(content),
            Err(e) if is_timeout(&e) => Err(e),
            Err(e) => {
                // crontab could not tell: the spool file, when readable.
                for path in [
                    format!("/var/spool/cron/{}", user),
                    format!("/var/spool/cron/crontabs/{}", user),
                ] {
                    if let Ok(content) = fs::read_to_string(&path) {
                        return Ok(content);
                    }
                }
                Err(e)
            }
        }
    }

    fn read_system_crontab(&self) -> Result<String> {
        fs::read_to_string("/etc/crontab")
            .map_err(|e| anyhow::anyhow!("could not read /etc/crontab: {e}"))
    }

    fn read_cron_d_files(&self) -> Result<Vec<(String, String)>> {
        let dir = Path::new("/etc/cron.d");
        let mut files = Vec::new();
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(files),
            Err(e) => return Err(anyhow::anyhow!("could not read /etc/cron.d: {e}")),
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            // cron skips hidden and backup files.
            if name.starts_with('.') || name.contains('~') {
                continue;
            }
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Ok(content) = fs::read_to_string(&path) {
                files.push((name, content));
            }
        }
        files.sort();
        Ok(files)
    }

    fn read_file(&self, path: &str) -> Result<String> {
        fs::read_to_string(path).map_err(|e| anyhow::anyhow!("could not read {path}: {e}"))
    }

    fn command_runs(&self, program: &str, arg: &str) -> bool {
        run_tool(Command::new(program).arg(arg)).is_ok()
    }

    fn crontab_version(&self) -> Option<String> {
        let output = run_tool(Command::new("crontab").arg("-V")).ok()?;
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        (output.status.success() && !version.is_empty()).then_some(version)
    }

    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }

    fn local_zone(&self) -> RunZone {
        let tz_env = std::env::var("TZ").ok();
        let localtime_link = fs::read_link("/etc/localtime").ok();
        let etc_timezone = fs::read_to_string("/etc/timezone").ok();
        detect_local_zone(
            tz_env.as_deref(),
            localtime_link.as_ref().and_then(|p| p.to_str()),
            etc_timezone.as_deref(),
            Utc::now(),
            chrono::Local::now().offset().fix(),
        )
    }
}

#[derive(Debug)]
pub struct SystemCronEditor {}

impl CronEditor for SystemCronEditor {
    fn read_user_crontab(&self, user: &str) -> Result<String> {
        let output = run_tool(
            Command::new("crontab")
                .args(crontab_user_args(user))
                .arg("-l"),
        )?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else if no_crontab(&output.stderr) {
            Ok(String::new())
        } else {
            Err(anyhow::anyhow!(
                "crontab -l for {} failed: {}",
                user,
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }

    fn write_user_crontab(&self, user: &str, content: &str) -> Result<()> {
        use std::io::{Seek, SeekFrom};
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::process::CommandExt;
        // The new crontab goes to `crontab -` on stdin from an anonymous
        // in-memory file: nothing is written to disk, and core::process
        // still bounds the tool by the deadline.
        // SAFETY: memfd_create returns a new descriptor (or -1), which the
        // File then owns.
        let fd = unsafe { libc::memfd_create(c"resh-crontab".as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err(anyhow::Error::new(std::io::Error::last_os_error())
                .context("cannot create the new crontab in memory"));
        }
        let mut file = unsafe { fs::File::from_raw_fd(fd) };
        file.write_all(content.as_bytes())?;
        file.seek(SeekFrom::Start(0))?;
        let raw = file.as_raw_fd();
        let mut cmd = Command::new("crontab");
        cmd.args(crontab_user_args(user)).arg("-");
        // SAFETY: dup2 is async-signal-safe. It runs after the standard
        // streams are set up, replacing stdin with the in-memory crontab.
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(raw, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = run_tool(&mut cmd)?;
        drop(file);
        if output.status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "crontab refused the new crontab for {}: {}",
                user,
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }

    fn read_system_file(&self, path: &str) -> Result<Option<String>> {
        use std::io::Read as _;
        use std::os::unix::fs::OpenOptionsExt;
        refuse_symlink(path)?;
        // O_NOFOLLOW: a link swapped in after the check is not read either.
        let mut content = String::new();
        match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(mut f) => {
                f.read_to_string(&mut content)
                    .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", path, e))?;
                Ok(Some(content))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow::anyhow!("Failed to read {}: {}", path, e)),
        }
    }

    fn write_system_file(&self, path: &str, content: &str) -> Result<()> {
        write_file_atomically(path, content)
    }
}

#[derive(Debug)]
pub struct SystemSystemdEditor {}

impl SystemdEditor for SystemSystemdEditor {
    fn systemctl(&self, user_mode: bool, args: &[&str]) -> Result<ToolOutput> {
        let mut cmd = Command::new("systemctl");
        if user_mode {
            cmd.arg("--user");
        }
        cmd.args(args);
        let out = run_tool(&mut cmd)?;
        Ok(ToolOutput {
            success: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    fn unit_dir(&self, user_mode: bool) -> Result<String> {
        if user_mode {
            match std::env::var("HOME") {
                Ok(home) if home.starts_with('/') => Ok(format!("{}/.config/systemd/user", home)),
                _ => Err(anyhow::anyhow!(
                    "HOME is not set to an absolute path, so the user unit directory is unknown"
                )),
            }
        } else {
            Ok("/etc/systemd/system".to_string())
        }
    }

    fn read_unit_file(&self, path: &str) -> Result<Option<String>> {
        match fs::read_to_string(path) {
            Ok(c) => Ok(Some(c)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow::anyhow!("could not read {path}: {e}")),
        }
    }

    fn write_unit_file(&self, path: &str, content: &str) -> Result<()> {
        write_file_atomically(path, content)
    }

    fn remove_unit_file(&self, path: &str) -> Result<bool> {
        match fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(anyhow::anyhow!("could not remove {path}: {e}")),
            Ok(_) => fs::remove_file(path)
                .map(|()| true)
                .map_err(|e| anyhow::anyhow!("could not remove {path}: {e}")),
        }
    }

    fn create_directory(&self, path: &str) -> Result<()> {
        fs::create_dir_all(path)
            .map_err(|e| anyhow::anyhow!("Failed to create directory {}: {}", path, e))
    }
}

// ===========================================================================
// Crontab lines
// ===========================================================================

/// What one crontab line is.
#[derive(Debug, Clone, PartialEq)]
enum LineKind {
    Blank,
    /// A comment that is not a commented-out job.
    Comment,
    /// `NAME=value` (CRON_TZ included).
    Env,
    Job(Job),
    /// Anything else (cron would reject the file).
    Other,
}

/// A job line, enabled or commented out (disabled).
#[derive(Debug, Clone, PartialEq)]
struct Job {
    disabled: bool,
    /// The five time fields joined by single spaces, or the `@` keyword.
    schedule: String,
    /// The user column of /etc/crontab and /etc/cron.d files.
    user: Option<String>,
    /// The command, without a trailing ` # comment`.
    command: String,
    inline_comment: Option<String>,
}

impl Job {
    fn is_special(&self) -> bool {
        self.schedule.starts_with('@')
    }
}

/// `NAME=value` or `NAME = value` (cron's environment lines).
fn is_env_line(trimmed: &str) -> bool {
    match trimmed.split_once('=') {
        Some((name, _)) => {
            let n = name.trim();
            n.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

/// A job from a line's text (the part after `#` for a commented line):
/// a schedule (five valid time fields or a known `@` keyword), the user
/// column for system files, and a command.
fn parse_job_text(content: &str, system: bool) -> Option<Job> {
    let mut words: Vec<(usize, &str)> = Vec::new();
    let mut start = None;
    for (i, c) in content.char_indices() {
        match (c.is_whitespace(), start) {
            (false, None) => start = Some(i),
            (true, Some(s)) => {
                words.push((s, &content[s..i]));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        words.push((s, &content[s..]));
    }
    let first = words.first()?.1;
    let (schedule, mut next) = if first.starts_with('@') {
        let parts: Vec<&str> = words.iter().map(|(_, w)| *w).collect();
        if !looks_like_cron_schedule(&parts) {
            return None;
        }
        (first.to_string(), 1)
    } else {
        if words.len() < 6 || !words[..5].iter().all(|(_, f)| is_cron_field(f)) {
            return None;
        }
        let schedule = words[..5]
            .iter()
            .map(|(_, w)| *w)
            .collect::<Vec<_>>()
            .join(" ");
        // Every field must be valid where it stands, so a comment such as
        // "# Run the job and log it" is not read as a job.
        parse_schedule(&schedule).ok()?;
        (schedule, 5)
    };
    let user = if system {
        let u = words.get(next)?.1.to_string();
        next += 1;
        Some(u)
    } else {
        None
    };
    let rest = content[words.get(next)?.0..].trim_end();
    let (command, inline_comment) = match rest.find(" #") {
        Some(pos) => {
            let comment = rest[pos + 2..].trim_start_matches('#').trim();
            (
                rest[..pos].trim_end().to_string(),
                (!comment.is_empty()).then(|| comment.to_string()),
            )
        }
        None => (rest.to_string(), None),
    };
    if command.is_empty() {
        return None;
    }
    Some(Job {
        disabled: false,
        schedule,
        user,
        command,
        inline_comment,
    })
}

fn classify(line: &str, system: bool) -> LineKind {
    let t = line.trim();
    if t.is_empty() {
        return LineKind::Blank;
    }
    if t.starts_with('#') {
        let content = t.trim_start_matches('#').trim();
        return match parse_job_text(content, system) {
            Some(job) => LineKind::Job(Job {
                disabled: true,
                ..job
            }),
            None => LineKind::Comment,
        };
    }
    if is_env_line(t) {
        return LineKind::Env;
    }
    match parse_job_text(t, system) {
        Some(job) => LineKind::Job(job),
        None => LineKind::Other,
    }
}

/// A crontab, line by line.
struct Scanned<'a> {
    lines: Vec<&'a str>,
    kinds: Vec<LineKind>,
}

impl<'a> Scanned<'a> {
    fn new(content: &'a str, system: bool) -> Self {
        let lines: Vec<&str> = content.lines().collect();
        let kinds = lines.iter().map(|l| classify(l, system)).collect();
        Scanned { lines, kinds }
    }

    /// The comment line directly above line `idx`, if that line is a plain
    /// comment (not a commented-out job).
    fn comment_above(&self, idx: usize) -> Option<&'a str> {
        (idx > 0 && self.kinds[idx - 1] == LineKind::Comment).then(|| self.lines[idx - 1].trim())
    }

    /// The job id from a `# job-id=<id>` comment directly above `idx`.
    fn job_id(&self, idx: usize) -> Option<String> {
        self.comment_above(idx).and_then(extract_job_id)
    }

    /// The job's comment: the comment line above it and its inline comment.
    fn comment(&self, idx: usize, job: &Job) -> Option<String> {
        let mut parts = Vec::new();
        if let Some(above) = self.comment_above(idx) {
            let text = above.trim_start_matches('#').trim();
            if !text.is_empty() {
                parts.push(text.to_string());
            }
        }
        parts.extend(job.inline_comment.clone());
        (!parts.is_empty()).then(|| parts.join(" "))
    }
}

/// Whitespace-normalized text, for comparing schedules and commands.
fn norm_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Uncomments a disabled job line: drops the leading `#`s and one space.
fn enable_cron_line(line: &str) -> String {
    let content = line.trim().trim_start_matches('#');
    content.strip_prefix(' ').unwrap_or(content).to_string()
}

/// Comments out a job line.
fn disable_cron_line(line: &str) -> String {
    format!("# {}", line)
}

// ===========================================================================
// Selectors (rm, enable, disable): every selector given must match
// ===========================================================================

#[derive(Debug, Clone, Default)]
pub(crate) struct Selectors {
    pub id: Option<String>,
    pub schedule: Option<String>,
    pub command: Option<String>,
    pub match_command: Option<String>,
    pub match_comment: Option<String>,
    pub unit_name: Option<String>,
    pub match_unit: Option<String>,
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

impl Selectors {
    /// Crontab lines can match unless a timer-only selector is given.
    fn for_cron(&self) -> bool {
        self.unit_name.is_none() && self.match_unit.is_none()
    }

    /// Timers can match unless a crontab-only selector (`schedule`) is given.
    fn for_timers(&self) -> bool {
        self.schedule.is_none()
    }

    fn job_matches(&self, job: &Job, id: Option<&str>, comment: Option<&str>) -> bool {
        self.for_cron()
            && self.id.as_deref().is_none_or(|w| id == Some(w))
            && self
                .schedule
                .as_deref()
                .is_none_or(|w| norm_ws(w).eq_ignore_ascii_case(&job.schedule))
            && self
                .command
                .as_deref()
                .is_none_or(|w| norm_ws(w) == norm_ws(&job.command))
            && self
                .match_command
                .as_deref()
                .is_none_or(|w| contains_ci(&job.command, w))
            && self
                .match_comment
                .as_deref()
                .is_none_or(|w| comment.is_some_and(|c| contains_ci(c, w)))
    }

    fn timer_matches(&self, t: &TimerFacts) -> bool {
        self.for_timers()
            && self
                .unit_name
                .as_deref()
                .is_none_or(|w| t.name == w || t.base() == w)
            && self
                .match_unit
                .as_deref()
                .is_none_or(|w| contains_ci(&t.name, w))
            && self
                .id
                .as_deref()
                .is_none_or(|w| t.id.as_deref() == Some(w))
            && self.command.as_deref().is_none_or(|w| {
                t.exec_start
                    .as_deref()
                    .is_some_and(|e| e == unit_literal(&exec_start_for(w)) || unescape_unit(e) == w)
            })
            && self.match_command.as_deref().is_none_or(|w| {
                t.exec_start
                    .as_deref()
                    .is_some_and(|e| contains_ci(&unescape_unit(e), w))
            })
            && self
                .match_comment
                .as_deref()
                .is_none_or(|w| contains_ci(&t.description, w))
    }
}

/// What is known about a timer for matching.
#[derive(Debug, Clone, Default)]
struct TimerFacts {
    /// `<name>.timer`
    name: String,
    /// The `[id=<id>]` that `add` writes into the Description.
    id: Option<String>,
    /// The Description of the timer and of its service.
    description: String,
    /// The service's ExecStart= value, as written in the unit file.
    exec_start: Option<String>,
}

impl TimerFacts {
    fn base(&self) -> &str {
        self.name.strip_suffix(".timer").unwrap_or(&self.name)
    }
    fn service(&self) -> String {
        format!("{}.service", self.base())
    }
}

/// A unit file value as systemd reads it: `%%` is a literal `%`.
fn unescape_unit(value: &str) -> String {
    value.replace("%%", "%")
}

/// `[id=<id>]` in a Description= line.
fn unit_job_id(content: &str) -> Option<String> {
    content
        .lines()
        .filter_map(|l| l.strip_prefix("Description="))
        .find_map(|d| {
            let start = d.find("[id=")? + "[id=".len();
            let end = d[start..].find(']')?;
            let id = &d[start..start + end];
            (!id.is_empty()).then(|| id.to_string())
        })
}

fn unit_value(content: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    content
        .lines()
        .find_map(|l| l.strip_prefix(prefix.as_str()).map(String::from))
}

// ===========================================================================
// The shared rm / enable / disable engine
// ===========================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
enum Action {
    Remove,
    Enable,
    Disable,
}

/// One request to rm, enable or disable.
struct Request<'a> {
    verb: &'static str,
    action: Action,
    backend: &'a str,
    scope: &'a str,
    users: &'a [String],
    cron_file: Option<&'a str>,
    unit_scope: &'a str,
    sel: Selectors,
    dry_run: bool,
    require_match: bool,
    /// remove_units, start_now or stop_now.
    flag: bool,
}

/// A crontab job changed (or, in a dry run, to be changed).
#[derive(Debug, Clone)]
struct CronHit {
    source: String,
    user: Option<String>,
    schedule: String,
    command: String,
    id: Option<String>,
    line_number: u32,
    timezone: Option<String>,
}

/// A timer changed (or to be changed).
#[derive(Debug, Clone)]
struct TimerHit {
    unit_scope: String,
    timer: String,
    service: String,
    id: Option<String>,
    was_enabled: bool,
    /// started_now (enable) or stopped_now (disable).
    applied: bool,
}

#[derive(Debug, Default)]
struct Outcome {
    cron: Vec<CronHit>,
    cron_already: u32,
    cron_sources: Vec<String>,
    timers: Vec<TimerHit>,
    timers_already: u32,
    scopes: Vec<String>,
    warnings: Vec<String>,
    /// Changes that were asked for and could not be made.
    failures: Vec<String>,
}

impl Outcome {
    /// The error object: failures first, then no_match.
    fn error(&self, req: &Request) -> Option<Value> {
        if !self.failures.is_empty() {
            return Some(error_value(
                &format!("cron.{}_error", req.verb),
                &format!(
                    "{} change(s) failed: {}",
                    self.failures.len(),
                    self.failures.join("; ")
                ),
                None,
            ));
        }
        let matched = self.cron.len() as u32
            + self.timers.len() as u32
            + self.cron_already
            + self.timers_already;
        (req.require_match && matched == 0).then(|| {
            error_value(
                &format!("cron.{}_no_match", req.verb),
                "No scheduled jobs matched the provided criteria.",
                None,
            )
        })
    }
}

/// A crontab `rm`, `enable` and `disable` read and rewrite.
#[derive(Debug, Clone, PartialEq)]
enum CronSource {
    User(String),
    System(String),
}

impl CronSource {
    fn name(&self) -> String {
        match self {
            CronSource::User(u) => user_crontab_path(u),
            CronSource::System(p) => p.clone(),
        }
    }
}

/// The result of applying an action to one crontab.
struct Rewrite {
    content: String,
    hits: Vec<CronHit>,
    already: u32,
}

/// Applies `action` to every job in `content` that `sel` matches.
fn rewrite_crontab(content: &str, source: &CronSource, sel: &Selectors, action: Action) -> Rewrite {
    let system = matches!(source, CronSource::System(_));
    let scanned = Scanned::new(content, system);
    let mut out: Vec<String> = Vec::with_capacity(scanned.lines.len());
    let mut hits = Vec::new();
    let mut already = 0u32;
    let mut drop_line = vec![false; scanned.lines.len()];
    let mut replace: HashMap<usize, String> = HashMap::new();
    for (idx, kind) in scanned.kinds.iter().enumerate() {
        let LineKind::Job(job) = kind else { continue };
        let id = scanned.job_id(idx);
        let comment = scanned.comment(idx, job);
        if !sel.job_matches(job, id.as_deref(), comment.as_deref()) {
            continue;
        }
        let hit = CronHit {
            source: source.name(),
            user: match source {
                CronSource::User(u) => Some(u.clone()),
                CronSource::System(_) => job.user.clone(),
            },
            schedule: job.schedule.clone(),
            command: job.command.clone(),
            id: id.clone(),
            line_number: (idx + 1) as u32,
            timezone: effective_cron_tz(&scanned.lines, idx),
        };
        match action {
            Action::Remove => {
                drop_line[idx] = true;
                if id.is_some() {
                    drop_line[idx - 1] = true;
                }
                hits.push(hit);
            }
            Action::Enable if job.disabled => {
                replace.insert(idx, enable_cron_line(scanned.lines[idx]));
                hits.push(hit);
            }
            Action::Disable if !job.disabled => {
                replace.insert(idx, disable_cron_line(scanned.lines[idx]));
                hits.push(hit);
            }
            _ => already += 1,
        }
    }
    if hits.is_empty() {
        return Rewrite {
            content: content.to_string(),
            hits,
            already,
        };
    }
    // Kept CRON_TZ lines that stood directly above a removed job.
    let mut tz_candidates = Vec::new();
    for (idx, line) in scanned.lines.iter().enumerate() {
        if drop_line[idx] {
            let is_job = matches!(scanned.kinds[idx], LineKind::Job(_));
            if is_job && out.last().is_some_and(|l| cron_tz_assignment(l).is_some()) {
                tz_candidates.push(out.len() - 1);
            }
            continue;
        }
        out.push(replace.remove(&idx).unwrap_or_else(|| line.to_string()));
    }
    let out = if action == Action::Remove {
        drop_orphaned_tz_lines(out, &tz_candidates)
    } else {
        out
    };
    let mut content = out.join("\n");
    content.push('\n');
    Rewrite {
        content,
        hits,
        already,
    }
}

impl SystemCronProvider {
    /// The crontabs a request acts on, each marked explicit (named by the
    /// caller, so a read failure is a failure) or not (a warning).
    fn cron_sources(&self, req: &Request, out: &mut Outcome) -> Result<Vec<(CronSource, bool)>> {
        if let Some(file) = req.cron_file {
            return Ok(vec![(CronSource::System(file.to_string()), true)]);
        }
        let mut sources = Vec::new();
        let current = || {
            (
                CronSource::User(self.current_user.clone()),
                req.scope == "current",
            )
        };
        match req.scope {
            "current" => sources.push(current()),
            "user" => sources.extend(
                req.users
                    .iter()
                    .map(|u| (CronSource::User(u.clone()), true)),
            ),
            _ => {
                if req.scope == "all" {
                    sources.push(current());
                    sources.extend(
                        req.users
                            .iter()
                            .filter(|u| **u != self.current_user)
                            .map(|u| (CronSource::User(u.clone()), true)),
                    );
                }
                sources.push((CronSource::System("/etc/crontab".to_string()), false));
                match unless_timeout(self.host.read_cron_d_files())? {
                    Ok(files) => sources.extend(files.into_iter().map(|(name, _)| {
                        (CronSource::System(format!("/etc/cron.d/{name}")), false)
                    })),
                    Err(e) => out.warnings.push(format!("{e:#}")),
                }
            }
        }
        Ok(sources)
    }

    fn read_source(&self, source: &CronSource) -> Result<Option<String>> {
        let editor = self.host.editor();
        match source {
            CronSource::User(u) => editor.read_user_crontab(u).map(Some),
            CronSource::System(p) => editor.read_system_file(p),
        }
    }

    fn write_source(&self, source: &CronSource, content: &str) -> Result<()> {
        let editor = self.host.editor();
        match source {
            CronSource::User(u) => editor.write_user_crontab(u, content),
            CronSource::System(p) => {
                check_system_cron_file(p)
                    .map_err(|e| anyhow::anyhow!("{p} cannot be rewritten: {}", e.message))?;
                editor.write_system_file(p, content)
            }
        }
    }

    fn apply_to_crontabs(&self, req: &Request, out: &mut Outcome) -> Result<()> {
        if !req.sel.for_cron() {
            return Ok(());
        }
        for (source, explicit) in self.cron_sources(req, out)? {
            let content = match unless_timeout(self.read_source(&source))? {
                Ok(Some(c)) => c,
                Ok(None) => continue,
                Err(e) if explicit => {
                    out.failures
                        .push(format!("could not read {}: {e:#}", source.name()));
                    continue;
                }
                Err(e) => {
                    out.warnings
                        .push(format!("Failed to read {}: {e:#}", source.name()));
                    continue;
                }
            };
            let rw = rewrite_crontab(&content, &source, &req.sel, req.action);
            out.cron_already += rw.already;
            if rw.hits.is_empty() {
                continue;
            }
            if req.dry_run {
                if let CronSource::System(p) = &source
                    && let Err(e) = check_system_cron_file(p)
                {
                    out.warnings
                        .push(format!("{p} could not be rewritten: {}", e.message));
                }
            } else if let Err(e) = unless_timeout(self.write_source(&source, &rw.content))? {
                out.failures
                    .push(format!("could not update {}: {e:#}", source.name()));
                continue;
            }
            out.cron_sources.push(source.name());
            out.cron.extend(rw.hits);
        }
        Ok(())
    }

    /// The unit scopes a request acts on.
    fn unit_scopes(&self, unit_scope: &str) -> Vec<&'static str> {
        match unit_scope {
            "user" => vec!["user"],
            "system" => vec!["system"],
            "both" => vec!["user", "system"],
            _ if self.is_root() => vec!["system"],
            _ => vec!["user"],
        }
    }

    /// Reads what matching and the report need from a timer's unit files in
    /// the unit directory (only timers resh writes have them there).
    fn timer_facts(&self, name: &str, user_mode: bool) -> Result<TimerFacts> {
        let mut facts = TimerFacts {
            name: name.to_string(),
            ..TimerFacts::default()
        };
        let ed = self.host.systemd();
        let dir = ed.unit_dir(user_mode)?;
        let timer = unless_timeout(ed.read_unit_file(&format!("{dir}/{name}")))?
            .ok()
            .flatten()
            .unwrap_or_default();
        let service = unless_timeout(ed.read_unit_file(&format!("{dir}/{}", facts.service())))?
            .ok()
            .flatten()
            .unwrap_or_default();
        facts.id = unit_job_id(&timer).or_else(|| unit_job_id(&service));
        facts.description = [
            unit_value(&timer, "Description"),
            unit_value(&service, "Description"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
        facts.exec_start = unit_value(&service, "ExecStart");
        Ok(facts)
    }

    fn apply_to_timers(&self, req: &Request, out: &mut Outcome) -> Result<()> {
        if !req.sel.for_timers() {
            return Ok(());
        }
        let ed = self.host.systemd();
        let explicit = req.backend == "systemd";
        for scope in self.unit_scopes(req.unit_scope) {
            let user_mode = scope == "user";
            let unreachable = match unless_timeout(manager_reachable(ed, user_mode))? {
                Ok(None) => None,
                Ok(Some(reason)) => Some(reason),
                Err(e) => Some(format!("{e:#}")),
            };
            if let Some(reason) = unreachable {
                let msg = format!("the {scope} service manager is not available: {reason}");
                if explicit {
                    out.failures.push(msg);
                } else {
                    out.warnings
                        .push(format!("{msg}; systemd timers were skipped"));
                }
                continue;
            }
            let timers = match unless_timeout(discover_timers(ed, user_mode))? {
                Ok(t) => t,
                Err(e) => {
                    out.failures.push(format!("{e:#}"));
                    continue;
                }
            };
            let mut touched = false;
            let mut removed_any = false;
            for name in timers {
                let facts = self.timer_facts(&name, user_mode)?;
                if !req.sel.timer_matches(&facts) {
                    continue;
                }
                touched = true;
                let enabled = ed
                    .systemctl(user_mode, &["is-enabled", "--", &name])?
                    .success;
                let active = ed
                    .systemctl(user_mode, &["is-active", "--", &name])?
                    .success;
                let hit = |applied: bool| TimerHit {
                    unit_scope: scope.to_string(),
                    timer: name.clone(),
                    service: facts.service(),
                    id: facts.id.clone(),
                    was_enabled: enabled,
                    applied,
                };
                match req.action {
                    Action::Remove => {
                        if !req.dry_run {
                            let stopped = systemctl_ok(ed, user_mode, &["stop", "--", &name]);
                            let disabled = stopped.and_then(|()| {
                                systemctl_ok(ed, user_mode, &["disable", "--", &name])
                            });
                            if let Err(e) = unless_timeout(disabled)? {
                                out.failures.push(format!("{e:#}"));
                                continue;
                            }
                            if req.flag {
                                let dir = ed.unit_dir(user_mode)?;
                                for file in [name.clone(), facts.service()] {
                                    let path = format!("{dir}/{file}");
                                    match unless_timeout(ed.remove_unit_file(&path))? {
                                        Ok(true) => removed_any = true,
                                        Ok(false) => out.warnings.push(format!(
                                            "{path} does not exist; {file} was stopped and \
                                             disabled but its unit file is not in {dir}"
                                        )),
                                        Err(e) => out.failures.push(format!("{e:#}")),
                                    }
                                }
                            }
                        }
                        out.timers.push(hit(false));
                    }
                    Action::Enable => {
                        if enabled && (!req.flag || active) {
                            out.timers_already += 1;
                            continue;
                        }
                        if !req.dry_run {
                            let mut args = vec!["enable"];
                            if req.flag {
                                args.push("--now");
                            }
                            args.extend(["--", name.as_str()]);
                            if let Err(e) = unless_timeout(systemctl_ok(ed, user_mode, &args))? {
                                out.failures.push(format!("{e:#}"));
                                continue;
                            }
                        }
                        out.timers.push(hit(req.flag));
                    }
                    Action::Disable => {
                        if !enabled && (!req.flag || !active) {
                            out.timers_already += 1;
                            continue;
                        }
                        let stop = req.flag && active;
                        if !req.dry_run {
                            let mut result = Ok(());
                            if stop {
                                result = systemctl_ok(ed, user_mode, &["stop", "--", &name]);
                            }
                            if enabled {
                                result = result.and_then(|()| {
                                    systemctl_ok(ed, user_mode, &["disable", "--", &name])
                                });
                            }
                            if let Err(e) = unless_timeout(result)? {
                                out.failures.push(format!("{e:#}"));
                                continue;
                            }
                        }
                        out.timers.push(hit(stop));
                    }
                }
            }
            if removed_any
                && let Err(e) = unless_timeout(systemctl_ok(ed, user_mode, &["daemon-reload"]))?
            {
                out.failures.push(format!("{e:#}"));
            }
            if touched {
                out.scopes.push(scope.to_string());
            }
        }
        Ok(())
    }

    fn run_request(&self, req: &Request) -> Result<Outcome> {
        let mut out = Outcome::default();
        if req.backend != "systemd" {
            self.apply_to_crontabs(req, &mut out)?;
        }
        if req.backend != "cron" {
            self.apply_to_timers(req, &mut out)?;
        }
        Ok(out)
    }
}

/// The selectors of a request's options.
macro_rules! selectors {
    ($o:expr) => {
        Selectors {
            id: $o.id.clone(),
            schedule: $o.schedule.as_deref().map(norm_ws),
            command: $o.command.clone(),
            match_command: $o.match_command.clone(),
            match_comment: $o.match_comment.clone(),
            unit_name: $o.unit_name.clone(),
            match_unit: $o.match_unit.clone(),
        }
    };
}

macro_rules! request {
    ($o:expr, $verb:expr, $action:expr, $flag:expr) => {
        Request {
            verb: $verb,
            action: $action,
            backend: &$o.backend,
            scope: &$o.scope,
            users: &$o.users,
            cron_file: $o.cron_file.as_deref(),
            unit_scope: &$o.unit_scope,
            sel: selectors!($o),
            dry_run: $o.dry_run,
            require_match: $o.require_match,
            flag: $flag,
        }
    };
}

// ===========================================================================
// The verbs
// ===========================================================================

impl CronProvider for SystemCronProvider {
    fn list_cron_entries(&self, options: &CronListOptions) -> Result<CronListResponse> {
        let start_time = self.host.now();
        let mut entries = Vec::new();
        let mut warnings = Vec::new();
        let mut paths: HashMap<String, String> = HashMap::new();
        let mut raw: serde_json::Map<String, Value> = serde_json::Map::new();

        let mut users: Vec<String> = Vec::new();
        let mut system = false;
        match options.scope.as_str() {
            "current" => users.push(self.current_user.clone()),
            "user" => users.extend(options.users.iter().cloned()),
            "system" => system = true,
            _ => {
                users.push(self.current_user.clone());
                users.extend(
                    options
                        .users
                        .iter()
                        .filter(|u| **u != self.current_user)
                        .cloned(),
                );
                system = options.include_system;
            }
        }

        for user in &users {
            match unless_timeout(self.host.list_user_crontab(user))? {
                Ok(content) => {
                    entries.extend(list_entries(
                        &content,
                        &ListSource::User(user.clone()),
                        &mut warnings,
                    ));
                    paths.insert(format!("user_{}", user), user_crontab_path(user));
                    raw.insert(user_crontab_path(user), json!(content));
                }
                Err(e) => warnings.push(format!("Could not read crontab for user {user}: {e:#}")),
            }
        }

        let mut files: Vec<(String, Result<String>)> = Vec::new();
        if system {
            files.push((
                "/etc/crontab".to_string(),
                unless_timeout(self.host.read_system_crontab())?,
            ));
            match unless_timeout(self.host.read_cron_d_files())? {
                Ok(list) => files.extend(
                    list.into_iter()
                        .map(|(name, content)| (format!("/etc/cron.d/{name}"), Ok(content))),
                ),
                Err(e) => warnings.push(format!("{e:#}")),
            }
        }
        for path in &options.include_files {
            files.push((path.clone(), unless_timeout(self.host.read_file(path))?));
        }
        for (path, content) in files {
            match content {
                Ok(content) => {
                    entries.extend(list_entries(
                        &content,
                        &ListSource::System(path.clone()),
                        &mut warnings,
                    ));
                    let key = match path.as_str() {
                        "/etc/crontab" => "system_crontab".to_string(),
                        p if p.starts_with("/etc/cron.d/")
                            && !options.include_files.contains(&path) =>
                        {
                            format!("cron_d_{}", &p["/etc/cron.d/".len()..])
                        }
                        p => format!("include_{}", p.replace('/', "_")),
                    };
                    paths.insert(key, path.clone());
                    raw.insert(path, json!(content));
                }
                Err(e) => warnings.push(format!("Could not read {path}: {e:#}")),
            }
        }

        entries = apply_filters(entries, options);

        let reference_time = options
            .now_unix
            .and_then(reference_time_from_unix)
            .unwrap_or(start_time);
        let mut next_run_timezone = None;
        if options.include_next_run {
            // An entry's own CRON_TZ counts only where cron honors it
            // (cronie); otherwise the entry runs in the default zone.
            let has_entry_zones = entries.iter().any(|e| e.timezone.is_some());
            let honor_entry_zones = has_entry_zones
                && match cronie_detected(self.host.as_ref()) {
                    Ok(_) => true,
                    Err(reason) => {
                        warnings.push(format!(
                            "CRON_TZ lines were ignored for next-run times: {}",
                            reason
                        ));
                        false
                    }
                };
            // Entries without their own zone run in timezone=, else in the
            // host's local zone, as cron reads them.
            let default_zone = match options.timezone.as_deref().and_then(parse_timezone) {
                Some(tz) => RunZone::Named(tz),
                None => self.host.local_zone(),
            };
            if let Some(w) = default_zone.offset_warning() {
                warnings.push(w);
            }
            next_run_timezone = Some(default_zone.label());
            for entry in &mut entries {
                if !entry.enabled || entry.comment_only {
                    continue;
                }
                let Some(schedule) = entry.schedule.clone().or_else(|| entry.special.clone())
                else {
                    continue;
                };
                let zone = match &entry.timezone {
                    Some(tz) if honor_entry_zones => match parse_timezone(tz) {
                        Some(zone) => RunZone::Named(zone),
                        None => {
                            warnings.push(format!(
                                "{}: CRON_TZ={} is not a known time zone; no next run computed",
                                entry.id, tz
                            ));
                            continue;
                        }
                    },
                    _ => default_zone,
                };
                if let Some((unix, iso)) = compute_next_run(&schedule, reference_time, zone) {
                    entry.next_run_unix = Some(unix);
                    entry.next_run_iso8601 = Some(iso);
                }
            }
        }

        apply_sorting(&mut entries, &options.sort_by, &options.sort_order);

        // Totals count every entry that passed the filters; comment lines
        // are neither enabled nor disabled jobs.
        let entries_total = entries.len() as u32;
        let jobs = entries.iter().filter(|e| !e.comment_only).count() as u32;
        let comments = entries_total - jobs;
        let entries_disabled = entries
            .iter()
            .filter(|e| !e.enabled && !e.comment_only)
            .count() as u32;
        let disabled_total = entries_disabled;

        let truncated = entries.len() > options.max_entries as usize;
        if truncated {
            entries.truncate(options.max_entries as usize);
            warnings.push(format!(
                "Entry list truncated to max_entries={}.",
                options.max_entries
            ));
        }
        let entries_returned = entries.len() as u32;

        Ok(CronListResponse {
            ok: true,
            timestamp_unix_ms: start_time.timestamp_millis(),
            scope: options.scope.clone(),
            users: if options.scope == "current" {
                vec![self.current_user.clone()]
            } else {
                options.users.clone()
            },
            include_system: options.include_system,
            truncated,
            entries_total: Some(entries_total),
            entries_returned,
            entries_disabled,
            entries,
            next_run_timezone,
            raw: options.include_raw.then_some(Value::Object(raw)),
            paths: options.include_paths.then(|| json!(paths)),
            human: Some(CronListHumanSummary {
                summary: format!(
                    "{} cron entries ({} enabled, {} disabled{}) from scope '{}'{}.",
                    entries_total,
                    jobs - disabled_total.min(jobs),
                    disabled_total,
                    if comments > 0 {
                        format!(", {} comment lines", comments)
                    } else {
                        String::new()
                    },
                    options.scope,
                    if system && options.scope == "all" {
                        " and system files"
                    } else {
                        ""
                    }
                ),
            }),
            error: None,
            warnings,
        })
    }

    fn add_cron_job(&self, options: &CronAddOptions) -> Result<CronAddResponse> {
        let timestamp_unix_ms = self.host.now().timestamp_millis();
        let mut warnings = Vec::new();
        let fail = |code: &str,
                    message: String,
                    field: Option<&str>,
                    backend: Option<String>,
                    warnings: Vec<String>| CronAddResponse {
            ok: false,
            timestamp_unix_ms,
            backend_used: backend,
            dry_run: options.dry_run,
            duplicate: false,
            job: None,
            preview: None,
            error: Some(error_value(code, &message, field)),
            warnings,
        };

        // Fields shared by both backends (also checked at parse time).
        if let Err(e) = validate_add_options(options, "", None) {
            return Ok(fail(
                "cron.add_invalid_argument",
                e.message,
                Some(e.field),
                None,
                warnings,
            ));
        }
        let backend = match choose_backend(self.host.as_ref(), &options.backend, &mut warnings) {
            Ok(b) => b,
            Err(e) => {
                return Ok(fail(
                    "cron.add_backend_unavailable",
                    format!("{e:#}"),
                    None,
                    None,
                    warnings,
                ));
            }
        };
        if let Err(e) = check_backend_options(options, &backend) {
            return Ok(fail(
                "cron.add_invalid_argument",
                e.message,
                Some(e.field),
                Some(backend),
                warnings,
            ));
        }
        let unit_name = (backend == "systemd").then(|| self.systemd_unit_name(options));
        if let Err(e) = validate_add_options(options, &backend, unit_name.as_deref()) {
            return Ok(fail(
                "cron.add_invalid_argument",
                e.message,
                Some(e.field),
                Some(backend),
                warnings,
            ));
        }

        // A crontab time zone only works under cronie; anywhere else the
        // CRON_TZ line would be silently ignored, so it is refused (also in
        // a dry run) before anything is read or written.
        if backend == "cron"
            && let Some(tz) = &options.timezone
            && let Err(reason) = cronie_detected(self.host.as_ref())
        {
            return Ok(fail(
                "cron.add_timezone_unsupported",
                format!(
                    "timezone={} cannot be applied with the cron backend: {}; \
                     use backend=systemd or omit timezone; nothing was written",
                    tz, reason
                ),
                Some("timezone"),
                Some(backend),
                warnings,
            ));
        }

        if options.include_next_run
            && let Some(w) = self.add_zone(options).offset_warning()
        {
            warnings.push(w);
        }

        match backend.as_str() {
            "cron" => self.add_cron_backend(options, timestamp_unix_ms, warnings),
            _ => self.add_systemd_backend(options, timestamp_unix_ms, warnings),
        }
    }

    fn remove_cron_jobs(&self, options: &CronRmOptions) -> Result<CronRmResponse> {
        let req = request!(options, "rm", Action::Remove, options.remove_units);
        let out = self.run_request(&req)?;
        let error = out.error(&req);
        Ok(CronRmResponse {
            ok: error.is_none(),
            timestamp_unix_ms: self.host.now().timestamp_millis(),
            dry_run: options.dry_run,
            backend: options.backend.clone(),
            matched_count: CronRmMatchedCount {
                cron: out.cron.len() as u32,
                systemd: out.timers.len() as u32,
            },
            error,
            removed: CronRmRemovedSummary {
                cron: out
                    .cron
                    .into_iter()
                    .map(|h| CronRmCronRemovedEntry {
                        source: h.source,
                        user: h.user,
                        schedule: Some(h.schedule),
                        command: Some(h.command),
                        id: h.id,
                        line_number: Some(h.line_number),
                        timezone: h.timezone,
                    })
                    .collect(),
                systemd: out
                    .timers
                    .into_iter()
                    .map(|t| CronRmSystemdRemovedEntry {
                        unit_scope: t.unit_scope,
                        timer_unit: Some(t.timer),
                        service_unit: Some(t.service),
                        id: t.id,
                    })
                    .collect(),
            },
            cron_modified_sources: out.cron_sources,
            systemd_scopes_touched: out.scopes,
            warnings: out.warnings,
        })
    }

    fn enable_cron_jobs(&self, options: &CronEnableOptions) -> Result<CronEnableResponse> {
        let req = request!(options, "enable", Action::Enable, options.start_now);
        let out = self.run_request(&req)?;
        let error = out.error(&req);
        Ok(CronEnableResponse {
            ok: error.is_none(),
            timestamp_unix_ms: self.host.now().timestamp_millis(),
            dry_run: options.dry_run,
            backend: options.backend.clone(),
            matched_count: CronEnableMatchedCount {
                cron: out.cron.len() as u32 + out.cron_already,
                systemd: out.timers.len() as u32 + out.timers_already,
            },
            already_enabled_count: CronEnableAlreadyEnabledCount {
                cron: out.cron_already,
                systemd: out.timers_already,
            },
            enabled: CronEnableEnabledSummary {
                cron: out
                    .cron
                    .into_iter()
                    .map(|h| CronEnableCronEntry {
                        source: h.source,
                        user: h.user,
                        schedule: Some(h.schedule),
                        command: Some(h.command),
                        id: h.id,
                        line_number: Some(h.line_number),
                        was_disabled: true,
                        timezone: h.timezone,
                    })
                    .collect(),
                systemd: out
                    .timers
                    .into_iter()
                    .map(|t| CronEnableSystemdEntry {
                        unit_scope: t.unit_scope,
                        timer_unit: Some(t.timer),
                        service_unit: Some(t.service),
                        id: t.id,
                        was_enabled: t.was_enabled,
                        started_now: t.applied,
                    })
                    .collect(),
            },
            cron_modified_sources: out.cron_sources,
            systemd_scopes_touched: out.scopes,
            error,
            warnings: out.warnings,
        })
    }

    fn disable_cron_jobs(&self, options: &CronDisableOptions) -> Result<CronDisableResponse> {
        let req = request!(options, "disable", Action::Disable, options.stop_now);
        let out = self.run_request(&req)?;
        let error = out.error(&req);
        Ok(CronDisableResponse {
            ok: error.is_none(),
            timestamp_unix_ms: self.host.now().timestamp_millis(),
            dry_run: options.dry_run,
            backend: options.backend.clone(),
            matched_count: CronDisableMatchedCount {
                cron: out.cron.len() as u32 + out.cron_already,
                systemd: out.timers.len() as u32 + out.timers_already,
            },
            already_disabled_count: CronDisableAlreadyDisabledCount {
                cron: out.cron_already,
                systemd: out.timers_already,
            },
            disabled: CronDisableDisabledSummary {
                cron: out
                    .cron
                    .into_iter()
                    .map(|h| CronDisableCronEntry {
                        source: h.source,
                        user: h.user,
                        schedule: Some(h.schedule),
                        command: Some(h.command),
                        id: h.id,
                        line_number: Some(h.line_number),
                        was_enabled: true,
                        timezone: h.timezone,
                    })
                    .collect(),
                systemd: out
                    .timers
                    .into_iter()
                    .map(|t| CronDisableSystemdEntry {
                        unit_scope: t.unit_scope,
                        timer_unit: Some(t.timer),
                        service_unit: Some(t.service),
                        id: t.id,
                        was_enabled: t.was_enabled,
                        stopped_now: t.applied,
                    })
                    .collect(),
            },
            cron_modified_sources: out.cron_sources,
            systemd_scopes_touched: out.scopes,
            error,
            warnings: out.warnings,
        })
    }
}

/// Options of the backend `add` does not use are refused, so nothing that
/// was passed is silently ignored.
fn check_backend_options(o: &CronAddOptions, backend: &str) -> Result<(), InvalidField> {
    let refuse = |field: &'static str, why: &str| {
        Err(InvalidField {
            field,
            message: format!("{field} {why}; nothing was written"),
        })
    };
    if backend == "cron" {
        for (field, given) in [
            ("unit_name", o.unit_name.is_some()),
            ("unit_scope", o.unit_scope.is_some()),
            ("persistent", o.persistent.is_some()),
            ("accuracy_sec", o.accuracy_sec.is_some()),
            ("random_delay_sec", o.random_delay_sec.is_some()),
            ("service_user", o.service_user.is_some()),
            ("service_working_dir", o.service_working_dir.is_some()),
            ("env", o.env.is_some()),
        ] {
            if given {
                return refuse(
                    field,
                    "applies only to the systemd backend, and the cron backend was chosen",
                );
            }
        }
        let scope = o.scope.as_deref().unwrap_or("current");
        if o.user.is_some() && scope == "current" {
            return refuse(
                "user",
                "applies to scope=user and scope=system, not scope=current",
            );
        }
        if o.cron_file.is_some() && scope != "system" {
            return refuse("cron_file", "applies only to scope=system");
        }
    } else {
        for (field, given) in [
            ("scope", o.scope.is_some()),
            ("user", o.user.is_some()),
            ("cron_file", o.cron_file.is_some()),
        ] {
            if given {
                return refuse(
                    field,
                    "applies only to the cron backend, and the systemd backend was chosen \
                     (use unit_scope and service_user for systemd)",
                );
            }
        }
    }
    Ok(())
}

impl SystemCronProvider {
    /// `(scope, user, file)` a cron-backend `add` writes to.
    fn cron_target(&self, options: &CronAddOptions) -> (String, String, String) {
        let scope = options.scope.clone().unwrap_or_else(|| "current".into());
        match scope.as_str() {
            "system" => {
                let user = options.user.clone().unwrap_or_else(|| "root".into());
                let file = options
                    .cron_file
                    .clone()
                    .unwrap_or_else(|| "/etc/crontab".into());
                (scope, user, file)
            }
            "user" => {
                let user = options
                    .user
                    .clone()
                    .unwrap_or_else(|| self.current_user.clone());
                let file = user_crontab_path(&user);
                (scope, user, file)
            }
            _ => (
                scope,
                self.current_user.clone(),
                user_crontab_path(&self.current_user),
            ),
        }
    }

    /// The current content of the crontab or cron file `add` writes to.
    fn read_add_target(&self, scope: &str, user: &str, file_path: &str) -> Result<String> {
        let editor = self.host.editor();
        match scope {
            "system" => Ok(editor.read_system_file(file_path)?.unwrap_or_default()),
            _ => editor.read_user_crontab(user),
        }
    }

    /// An enabled job with the same schedule, command, user column and time
    /// zone.
    fn is_cron_duplicate(
        &self,
        options: &CronAddOptions,
        content: &str,
        system: bool,
        user: &str,
    ) -> bool {
        let scanned = Scanned::new(content, system);
        scanned.kinds.iter().enumerate().any(|(idx, kind)| {
            let LineKind::Job(job) = kind else {
                return false;
            };
            !job.disabled
                && job
                    .schedule
                    .eq_ignore_ascii_case(&norm_ws(&options.schedule))
                && norm_ws(&job.command) == norm_ws(&options.command)
                && (!system || job.user.as_deref() == Some(user))
                && effective_cron_tz(&scanned.lines, idx) == options.timezone
        })
    }

    fn add_cron_backend(
        &self,
        options: &CronAddOptions,
        timestamp_unix_ms: i64,
        warnings: Vec<String>,
    ) -> Result<CronAddResponse> {
        let (scope, user, file_path) = self.cron_target(options);
        let system = scope == "system";
        let existing = self.read_add_target(&scope, &user, &file_path)?;

        if !options.allow_duplicate && self.is_cron_duplicate(options, &existing, system, &user) {
            return Ok(CronAddResponse {
                ok: true,
                timestamp_unix_ms,
                backend_used: Some("cron".to_string()),
                dry_run: options.dry_run,
                duplicate: true,
                job: Some(self.build_cron_job_info(options, &scope, &user, &file_path, None)?),
                preview: None,
                error: None,
                warnings,
            });
        }

        let (cron_line, comment_line) = self.build_cron_lines(options, &scope)?;
        let timezone = options.timezone.as_deref();
        let (new_content, line_added, added) =
            insert_cron_entry(&existing, comment_line.as_deref(), &cron_line, timezone);

        if options.dry_run {
            return Ok(CronAddResponse {
                ok: true,
                timestamp_unix_ms,
                backend_used: Some("cron".to_string()),
                dry_run: true,
                duplicate: false,
                job: Some(self.build_cron_job_info(options, &scope, &user, &file_path, None)?),
                preview: Some(CronAddPreview {
                    cron_line: Some(added.join("\n")),
                    service_unit: None,
                    timer_unit: None,
                }),
                error: None,
                warnings,
            });
        }

        let editor = self.host.editor();
        if system {
            editor.write_system_file(&file_path, &new_content)?;
        } else {
            editor.write_user_crontab(&user, &new_content)?;
        }

        Ok(CronAddResponse {
            ok: true,
            timestamp_unix_ms,
            backend_used: Some("cron".to_string()),
            dry_run: false,
            duplicate: false,
            job: Some(self.build_cron_job_info(
                options,
                &scope,
                &user,
                &file_path,
                Some(line_added),
            )?),
            preview: None,
            error: None,
            warnings,
        })
    }

    fn add_systemd_backend(
        &self,
        options: &CronAddOptions,
        timestamp_unix_ms: i64,
        warnings: Vec<String>,
    ) -> Result<CronAddResponse> {
        let ed = self.host.systemd();
        let unit_scope = self.determine_systemd_scope(options);
        let user_mode = unit_scope == "user";
        let fail = |code: &str, message: String, warnings: Vec<String>| CronAddResponse {
            ok: false,
            timestamp_unix_ms,
            backend_used: Some("systemd".to_string()),
            dry_run: options.dry_run,
            duplicate: false,
            job: None,
            preview: None,
            error: Some(error_value(code, &message, None)),
            warnings,
        };

        // The schedule must have a calendar equivalent (with the time zone).
        let on_calendar = match systemd_on_calendar(options) {
            Ok(calendar) => calendar,
            Err(e) => {
                return Ok(fail(
                    "cron.add_schedule_translation_unsupported",
                    format!(
                        "Cannot convert cron schedule '{}' to systemd OnCalendar: {}; nothing \
                         was written",
                        options.schedule, e
                    ),
                    warnings,
                ));
            }
        };

        if let Some(reason) = manager_reachable(ed, user_mode)? {
            return Ok(fail(
                "cron.add_systemd_unavailable",
                format!(
                    "the {} service manager is not available ({}); nothing was written",
                    unit_scope, reason
                ),
                warnings,
            ));
        }

        let unit_name = self.systemd_unit_name(options);
        let unit_dir = ed.unit_dir(user_mode)?;
        let timer_name = format!("{}.timer", unit_name);

        if !options.allow_duplicate {
            let exists = ed
                .read_unit_file(&format!("{unit_dir}/{timer_name}"))?
                .is_some()
                || discover_timers(ed, user_mode)?.contains(&timer_name);
            if exists {
                return Ok(CronAddResponse {
                    ok: true,
                    timestamp_unix_ms,
                    backend_used: Some("systemd".to_string()),
                    dry_run: options.dry_run,
                    duplicate: true,
                    job: Some(self.build_systemd_job_info(options, &unit_name, &unit_scope)?),
                    preview: None,
                    error: None,
                    warnings,
                });
            }
        }

        let service_content = self.build_service_unit(options, &unit_name)?;
        let timer_content = self.build_timer_unit(options, &unit_name, &on_calendar)?;

        if options.dry_run {
            return Ok(CronAddResponse {
                ok: true,
                timestamp_unix_ms,
                backend_used: Some("systemd".to_string()),
                dry_run: true,
                duplicate: false,
                job: Some(self.build_systemd_job_info(options, &unit_name, &unit_scope)?),
                preview: Some(CronAddPreview {
                    cron_line: None,
                    service_unit: Some(service_content),
                    timer_unit: Some(timer_content),
                }),
                error: None,
                warnings,
            });
        }

        let service_path = format!("{}/{}.service", unit_dir, unit_name);
        let timer_path = format!("{}/{}", unit_dir, timer_name);
        refuse_symlink(&service_path)?;
        refuse_symlink(&timer_path)?;
        ed.create_directory(&unit_dir)?;
        ed.write_unit_file(&service_path, &service_content)?;
        ed.write_unit_file(&timer_path, &timer_content)?;
        systemctl_ok(ed, user_mode, &["daemon-reload"])
            .and_then(|()| systemctl_ok(ed, user_mode, &["enable", "--now", "--", &timer_name]))
            .map_err(|e| {
                e.context(format!(
                    "{service_path} and {timer_path} were written, but the timer was not \
                     enabled"
                ))
            })?;

        Ok(CronAddResponse {
            ok: true,
            timestamp_unix_ms,
            backend_used: Some("systemd".to_string()),
            dry_run: false,
            duplicate: false,
            job: Some(self.build_systemd_job_info(options, &unit_name, &unit_scope)?),
            preview: None,
            error: None,
            warnings,
        })
    }

    fn determine_systemd_scope(&self, options: &CronAddOptions) -> String {
        match options.unit_scope.as_deref() {
            Some("user") => "user".to_string(),
            Some("system") => "system".to_string(),
            _ if self.is_root() => "system".to_string(),
            _ => "user".to_string(),
        }
    }

    /// `unit_name`, else `id`, else a name derived from the command.
    fn systemd_unit_name(&self, options: &CronAddOptions) -> String {
        options
            .unit_name
            .clone()
            .or_else(|| options.id.clone())
            .unwrap_or_else(|| derive_unit_name_from_command(&options.command))
    }

    fn build_cron_job_info(
        &self,
        options: &CronAddOptions,
        scope: &str,
        user: &str,
        file_path: &str,
        line_added: Option<u32>,
    ) -> Result<CronAddJobInfo> {
        let (next_run_unix, next_run_iso8601, next_run_timezone) = self.add_next_run(options);
        Ok(CronAddJobInfo {
            id: options.id.clone(),
            backend: "cron".to_string(),
            schedule: options.schedule.clone(),
            command: options.command.clone(),
            location: CronAddJobLocation {
                scope: scope.to_string(),
                file: Some(file_path.to_string()),
                user: Some(user.to_string()),
                line_added,
                unit_name: None,
                timer_unit: None,
                service_unit: None,
                unit_dir: None,
            },
            next_run_unix,
            next_run_iso8601,
            next_run_timezone,
        })
    }

    fn build_systemd_job_info(
        &self,
        options: &CronAddOptions,
        unit_name: &str,
        unit_scope: &str,
    ) -> Result<CronAddJobInfo> {
        let (next_run_unix, next_run_iso8601, next_run_timezone) = self.add_next_run(options);
        let unit_dir = self.host.systemd().unit_dir(unit_scope == "user")?;
        Ok(CronAddJobInfo {
            id: options.id.clone(),
            backend: "systemd".to_string(),
            schedule: format!(
                "OnCalendar={}",
                systemd_on_calendar(options).map_err(|e| anyhow::anyhow!(e))?
            ),
            command: options.command.clone(),
            location: CronAddJobLocation {
                scope: format!("{}-unit", unit_scope),
                file: None,
                user: options.service_user.clone(),
                line_added: None,
                unit_name: Some(unit_name.to_string()),
                timer_unit: Some(format!("{}.timer", unit_name)),
                service_unit: Some(format!("{}.service", unit_name)),
                unit_dir: Some(unit_dir),
            },
            next_run_unix,
            next_run_iso8601,
            next_run_timezone,
        })
    }
}

fn derive_unit_name_from_command(command: &str) -> String {
    let name = command
        .split_whitespace()
        .next()
        .and_then(|p| Path::new(p).file_name())
        .and_then(|n| n.to_str())
        .map(|n| n.split('.').next().unwrap_or(n))
        .map(|n| {
            n.chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' {
                        c
                    } else {
                        '-'
                    }
                })
                .collect::<String>()
                .trim_matches('-')
                .to_string()
        })
        .unwrap_or_default();
    if name.is_empty() {
        "cron-job".to_string()
    } else {
        name
    }
}

/// The ExecStart= command for `command`: wrapped in `/bin/sh -c` when it
/// uses shell syntax.
fn exec_start_for(command: &str) -> String {
    if command.contains(['|', '&', ';', '>', '<']) {
        format!("/bin/sh -c '{}'", command.replace('\'', "'\"'\"'"))
    } else {
        command.to_string()
    }
}

// ===========================================================================
// list parsing
// ===========================================================================

/// Where `list` read a crontab from.
enum ListSource {
    User(String),
    /// /etc/crontab, a file in /etc/cron.d, or an include_files path (all
    /// with a user column).
    System(String),
}

/// The entries `list` reports for one crontab: jobs (enabled or disabled)
/// and comment lines. Environment and CRON_TZ lines are not entries.
fn list_entries(content: &str, source: &ListSource, warnings: &mut Vec<String>) -> Vec<CronEntry> {
    let (system, path, source_type) = match source {
        ListSource::User(_) => (false, None, "user"),
        ListSource::System(p) => (
            true,
            Some(p.as_str()),
            if p == "/etc/crontab" {
                "system"
            } else {
                "file"
            },
        ),
    };
    let scanned = Scanned::new(content, system);
    let mut entries = Vec::new();
    let mut current_tz: Option<String> = None;
    for (idx, kind) in scanned.kinds.iter().enumerate() {
        let line = scanned.lines[idx];
        let n = (idx + 1) as u32;
        let comment_id = || match source {
            ListSource::User(u) => format!("user:{}:crontab:{}", u, n),
            ListSource::System(p) => format!("system:{}:{}", p, n),
        };
        match kind {
            LineKind::Blank => {}
            LineKind::Env => {
                if let Some(tz) = cron_tz_assignment(line) {
                    current_tz = Some(tz).filter(|tz| !tz.is_empty());
                }
            }
            LineKind::Other => warnings.push(format!(
                "{} line {} is not a cron entry and was skipped",
                path.map(String::from).unwrap_or_else(|| match source {
                    ListSource::User(u) => format!("crontab of {u}"),
                    ListSource::System(p) => p.clone(),
                }),
                n
            )),
            LineKind::Comment => entries.push(CronEntry {
                id: comment_id(),
                user: match source {
                    ListSource::User(u) => Some(u.clone()),
                    ListSource::System(_) => None,
                },
                source: source_type.to_string(),
                source_file: path.map(String::from),
                source_line: Some(n),
                enabled: false,
                comment_only: true,
                schedule: None,
                schedule_fields: None,
                special: None,
                command: None,
                comment: Some(line.trim().trim_start_matches('#').trim().to_string()),
                next_run_unix: None,
                next_run_iso8601: None,
                raw_line: Some(line.to_string()),
                timezone: None,
            }),
            LineKind::Job(job) => {
                let user = match source {
                    ListSource::User(u) => u.clone(),
                    ListSource::System(_) => job.user.clone().unwrap_or_default(),
                };
                let fields: Vec<&str> = job.schedule.split(' ').collect();
                entries.push(CronEntry {
                    id: format!(
                        "{}:{}:{}:{}",
                        source_type,
                        user,
                        path.unwrap_or("crontab"),
                        n
                    ),
                    user: Some(user),
                    source: source_type.to_string(),
                    source_file: path.map(String::from),
                    source_line: Some(n),
                    enabled: !job.disabled,
                    comment_only: false,
                    schedule: (!job.is_special()).then(|| job.schedule.clone()),
                    schedule_fields: (!job.is_special() && fields.len() == 5).then(|| {
                        CronScheduleFields {
                            minute: fields[0].to_string(),
                            hour: fields[1].to_string(),
                            day_of_month: fields[2].to_string(),
                            month: fields[3].to_string(),
                            day_of_week: fields[4].to_string(),
                        }
                    }),
                    special: job.is_special().then(|| job.schedule.clone()),
                    command: Some(job.command.clone()),
                    comment: scanned.comment(idx, job),
                    next_run_unix: None,
                    next_run_iso8601: None,
                    raw_line: Some(line.to_string()),
                    timezone: current_tz.clone(),
                });
            }
        }
    }
    entries
}

impl SystemCronProvider {
    fn build_cron_lines(
        &self,
        options: &CronAddOptions,
        scope: &str,
    ) -> Result<(String, Option<String>)> {
        let mut comment_parts = Vec::new();

        if let Some(ref id) = options.id {
            comment_parts.push(format!("job-id={}", id));
        }

        if let Some(ref desc) = options.description {
            comment_parts.push(format!("description={}", desc));
        }

        let comment_line = if !comment_parts.is_empty() {
            Some(format!("# {}", comment_parts.join(" ")))
        } else {
            None
        };

        let cron_line = match scope {
            "system" => {
                let user = options.user.as_deref().unwrap_or("root");
                format!("{} {} {}", options.schedule, user, options.command)
            }
            _ => {
                format!("{} {}", options.schedule, options.command)
            }
        };

        Ok((cron_line, comment_line))
    }

    /// The zone `add` reads the schedule in: `timezone`, else the host's
    /// local zone (where cron and systemd run a job without one).
    fn add_zone(&self, options: &CronAddOptions) -> RunZone {
        match options.timezone.as_deref().and_then(parse_timezone) {
            Some(tz) => RunZone::Named(tz),
            None => self.host.local_zone(),
        }
    }

    /// `add`'s next run, when `include_next_run` is set: after `now_unix`
    /// (else the current time), in `add_zone`. Returns the Unix time, the
    /// RFC 3339 text and the zone's label.
    fn add_next_run(
        &self,
        options: &CronAddOptions,
    ) -> (Option<i64>, Option<String>, Option<String>) {
        if !options.include_next_run {
            return (None, None, None);
        }
        let reference = options
            .now_unix
            .and_then(reference_time_from_unix)
            .unwrap_or_else(|| self.host.now());
        let zone = self.add_zone(options);
        match compute_next_run(&options.schedule, reference, zone) {
            Some((unix, iso)) => (Some(unix), Some(iso), Some(zone.label())),
            None => (None, None, Some(zone.label())),
        }
    }
    fn build_service_unit(&self, options: &CronAddOptions, unit_name: &str) -> Result<String> {
        let mut content = String::new();

        // [Unit] section
        content.push_str("[Unit]\n");
        let description = if let Some(ref desc) = options.description {
            if let Some(ref id) = options.id {
                format!("{} [id={}]", desc, id)
            } else {
                desc.clone()
            }
        } else if let Some(ref id) = options.id {
            format!("Cron job [id={}]", id)
        } else {
            format!("Cron job: {}", unit_name)
        };
        content.push_str(&format!("Description={}\n\n", unit_literal(&description)));

        // [Service] section
        content.push_str("[Service]\n");
        content.push_str("Type=oneshot\n");

        if let Some(ref working_dir) = options.service_working_dir {
            content.push_str(&format!("WorkingDirectory={}\n", unit_literal(working_dir)));
        }

        if let Some(ref user) = options.service_user {
            content.push_str(&format!("User={}\n", user));
        }

        if let Some(ref env_map) = options.env {
            let mut vars: Vec<_> = env_map.iter().collect();
            vars.sort();
            for (key, value) in vars {
                content.push_str(&unit_environment(key, value));
            }
        }

        let exec_start = exec_start_for(&options.command);
        content.push_str(&format!("ExecStart={}\n\n", unit_literal(&exec_start)));

        // [Install] section
        content.push_str("[Install]\n");
        content.push_str("WantedBy=multi-user.target\n");

        Ok(content)
    }

    fn build_timer_unit(
        &self,
        options: &CronAddOptions,
        unit_name: &str,
        on_calendar: &str,
    ) -> Result<String> {
        let mut content = String::new();

        // [Unit] section
        content.push_str("[Unit]\n");
        let description = if let Some(ref desc) = options.description {
            if let Some(ref id) = options.id {
                format!("Timer for {} [id={}]", desc, id)
            } else {
                format!("Timer for {}", desc)
            }
        } else if let Some(ref id) = options.id {
            format!("Timer for cron job [id={}]", id)
        } else {
            format!("Timer for {}", unit_name)
        };
        content.push_str(&format!("Description={}\n\n", unit_literal(&description)));

        // [Timer] section
        content.push_str("[Timer]\n");
        content.push_str(&format!("OnCalendar={}\n", on_calendar));

        if options.persistent.unwrap_or(true) {
            content.push_str("Persistent=true\n");
        }

        if let Some(ref accuracy) = options.accuracy_sec {
            content.push_str(&format!("AccuracySec={}\n", accuracy));
        }

        if let Some(ref delay) = options.random_delay_sec {
            content.push_str(&format!("RandomizedDelaySec={}\n", delay));
        }

        content.push_str("\n[Install]\n");
        content.push_str("WantedBy=timers.target\n");

        Ok(content)
    }
}

// ===========================================================================
// Argument and field checks
// ===========================================================================

/// A refused `add` argument and why.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct InvalidField {
    pub field: &'static str,
    pub message: String,
}

fn invalid(field: &'static str, reason: impl std::fmt::Display) -> InvalidField {
    InvalidField {
        field,
        message: format!("{} {}; nothing was written", field, reason),
    }
}

/// No control characters: a line break would start a new crontab line or
/// unit-file directive.
fn check_single_line(field: &'static str, value: &str) -> Result<(), InvalidField> {
    if value.chars().any(char::is_control) {
        return Err(invalid(
            field,
            "must not contain line breaks or other control characters",
        ));
    }
    Ok(())
}

/// Five crontab time fields, or an `@` keyword. A sixth field would be read
/// by cron as the start of the command.
fn check_schedule_syntax(schedule: &str) -> Result<(), InvalidField> {
    const SPECIAL: &[&str] = &[
        "@reboot",
        "@yearly",
        "@annually",
        "@monthly",
        "@weekly",
        "@daily",
        "@hourly",
        "@midnight",
    ];
    if schedule.starts_with('@') {
        return if SPECIAL.contains(&schedule) {
            Ok(())
        } else {
            Err(invalid(
                "schedule",
                format!("{:?} is not a supported @ keyword", schedule),
            ))
        };
    }
    let fields: Vec<&str> = schedule.split(' ').filter(|f| !f.is_empty()).collect();
    if fields.len() != 5 || !fields.iter().all(|f| is_cron_field(f)) {
        return Err(invalid(
            "schedule",
            format!(
                "must be five crontab fields (minute hour day month weekday) or an @ keyword, got {:?}",
                schedule
            ),
        ));
    }
    Ok(())
}

/// A job id is one word of `[A-Za-z0-9._@:+-]`, as read back by
/// `extract_job_id`.
fn check_job_id(id: &str) -> Result<(), InvalidField> {
    let ok = !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | ':' | '+' | '-'));
    if !ok {
        return Err(invalid(
            "id",
            "must be 1-128 characters of letters, digits and . _ @ : + -",
        ));
    }
    Ok(())
}

/// A user or group name (or numeric id) as accepted by crontab and systemd's
/// `User=`: no leading `-`, no whitespace.
fn check_user_name(field: &'static str, name: &str) -> Result<(), InvalidField> {
    let body = name.strip_suffix('$').unwrap_or(name);
    let ok = !body.is_empty()
        && name.len() <= 32
        && !body.starts_with('-')
        && body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if !ok {
        return Err(invalid(
            field,
            format!(
                "must be a user name (letters, digits, _ . -; not starting with -), got {:?}",
                name
            ),
        ));
    }
    Ok(())
}

/// The only files `scope=system` writes: /etc/crontab, or a file directly in
/// /etc/cron.d whose name cron reads (letters, digits, `_`, `-`).
pub(crate) fn check_system_cron_file(path: &str) -> Result<(), InvalidField> {
    if path == "/etc/crontab" {
        return Ok(());
    }
    let ok = path.strip_prefix("/etc/cron.d/").is_some_and(|name| {
        !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    });
    if !ok {
        return Err(invalid(
            "cron_file",
            format!(
                "must be /etc/crontab or /etc/cron.d/<name> (letters, digits, _ and -), got {:?}",
                path
            ),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Time zones. systemd timers take an IANA zone after the OnCalendar=
// expression. In a crontab, only cronie honors CRON_TZ=<zone>, and it applies
// to every entry below it in the same file (cronie builds each file's
// environment top to bottom; there is no way to unset a variable, and an
// empty `CRON_TZ=` is not the same as none: cronie computes it as the local
// time but skips such jobs while the default zone changes DST, like any
// zoned job). So `add` keeps zoned jobs in a block at the end of the file:
//
//   <existing lines and jobs added without a time zone>
//   # resh: time-zone block ...      (TZ_BLOCK_MARKER, written once)
//   CRON_TZ=Europe/Berlin            (one CRON_TZ line per job, directly
//   # job-id=backup                   above that job and its comment)
//   0 2 * * * /opt/backup.sh
//   CRON_TZ=America/New_York
//   30 6 * * * /opt/report.sh
//
// Every zoned job sets its own zone, nothing that resh writes ever follows a
// zoned job without its own CRON_TZ line (jobs without a zone are inserted
// above the marker), and no line above the block is affected. `rm` drops a
// job's CRON_TZ line only when nothing but blank lines separates it from the
// next CRON_TZ line or the end of the file, so no other line's zone changes.
// ---------------------------------------------------------------------------

/// First line of the time-zone block that `add` keeps at the end of a crontab.
const TZ_BLOCK_MARKER: &str = "# resh: time-zone block - each job below runs in the CRON_TZ \
     set just above it; add jobs without a time zone above this line";

fn is_tz_block_marker(line: &str) -> bool {
    line.trim().starts_with("# resh: time-zone block")
}

/// A valid IANA time zone name (as chrono-tz knows it), such as Europe/Berlin.
fn parse_timezone(name: &str) -> Option<Tz> {
    name.parse::<Tz>().ok()
}

/// The zone a schedule is read in for next-run times.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RunZone {
    /// An IANA zone (follows daylight-saving changes).
    Named(Tz),
    /// Only the host's current UTC offset is known: the local zone could not
    /// be named. Next runs after a daylight-saving change are off by the
    /// change.
    Offset(FixedOffset),
}

impl RunZone {
    /// The zone name, or the offset such as `+01:00`.
    fn label(&self) -> String {
        match self {
            RunZone::Named(tz) => tz.name().to_string(),
            RunZone::Offset(offset) => offset.to_string(),
        }
    }

    /// The warning for a zone known only by its offset.
    fn offset_warning(&self) -> Option<String> {
        match self {
            RunZone::Named(_) => None,
            RunZone::Offset(offset) => Some(format!(
                "the host's local time zone could not be identified by name (TZ, \
                 /etc/localtime); next-run times use its current UTC offset {}, which does \
                 not follow daylight-saving changes; pass timezone= to name the zone",
                offset
            )),
        }
    }
}

/// An IANA zone from a name (`Europe/Berlin`) or a zoneinfo path
/// (`/usr/share/zoneinfo/Europe/Berlin`, `../usr/share/zoneinfo/posix/UTC`).
fn zone_from_name_or_path(value: &str) -> Option<Tz> {
    let value = value.trim();
    if let Some(tz) = parse_timezone(value) {
        return Some(tz);
    }
    let (_, rest) = value.rsplit_once("zoneinfo/")?;
    let rest = rest
        .strip_prefix("posix/")
        .or_else(|| rest.strip_prefix("right/"))
        .unwrap_or(rest);
    parse_timezone(rest)
}

/// The host's local zone, the way the C library finds it: the `TZ`
/// variable when set (a zone name, `:name` or a zoneinfo path), else the
/// zone `/etc/localtime` links to. When `/etc/localtime` is a copy rather
/// than a link, `/etc/timezone` (Debian) names it, if that zone's offset now
/// matches the host's. Anything else (a POSIX rule such as `EST5EDT`-like
/// strings chrono-tz does not know, or no name at all) falls back to the
/// host's current offset, `local_offset`.
fn detect_local_zone(
    tz_env: Option<&str>,
    localtime_link: Option<&str>,
    etc_timezone: Option<&str>,
    now: DateTime<Utc>,
    local_offset: FixedOffset,
) -> RunZone {
    if let Some(tz) = tz_env.map(str::trim).filter(|t| !t.is_empty()) {
        // With TZ set, /etc/localtime is not consulted.
        let name = tz.strip_prefix(':').unwrap_or(tz);
        return zone_from_name_or_path(name)
            .map(RunZone::Named)
            .unwrap_or(RunZone::Offset(local_offset));
    }
    if let Some(tz) = localtime_link.and_then(zone_from_name_or_path) {
        return RunZone::Named(tz);
    }
    if let Some(tz) = etc_timezone.and_then(parse_timezone_trimmed)
        && now.with_timezone(&tz).offset().fix() == local_offset
    {
        return RunZone::Named(tz);
    }
    RunZone::Offset(local_offset)
}

fn parse_timezone_trimmed(name: &str) -> Option<Tz> {
    parse_timezone(name.trim())
}

fn check_timezone(field: &'static str, name: &str) -> Result<(), InvalidField> {
    check_single_line(field, name)?;
    if parse_timezone(name).is_none() {
        return Err(invalid(
            field,
            format!(
                "must be an IANA time zone name such as Europe/Berlin or UTC, got {:?}",
                name
            ),
        ));
    }
    Ok(())
}

/// The value of a `CRON_TZ` assignment line (cronie's environment syntax:
/// `NAME = value`, spaces around `=` allowed, value optionally quoted), or
/// None if the line is not one. An empty value gives `Some("")`.
fn cron_tz_assignment(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.starts_with('#') {
        return None;
    }
    let (name, value) = trimmed.split_once('=')?;
    if name.trim() != "CRON_TZ" {
        return None;
    }
    let value = value.trim();
    let unquoted = ['"', '\'']
        .iter()
        .find_map(|q| value.strip_prefix(*q).and_then(|v| v.strip_suffix(*q)))
        .unwrap_or(value);
    Some(unquoted.to_string())
}

/// The CRON_TZ in effect for `lines[idx]` (the last non-empty assignment
/// above it), as cronie would apply it.
fn effective_cron_tz<S: AsRef<str>>(lines: &[S], idx: usize) -> Option<String> {
    lines[..idx.min(lines.len())]
        .iter()
        .rev()
        .find_map(|l| cron_tz_assignment(l.as_ref()))
        .filter(|tz| !tz.is_empty())
}

/// Adds a job (its optional comment line, then the job line) to crontab
/// `existing`, following the time-zone layout above. Returns the new content,
/// the 1-based line number of the job line, and the lines added.
fn insert_cron_entry(
    existing: &str,
    comment_line: Option<&str>,
    cron_line: &str,
    timezone: Option<&str>,
) -> (String, u32, Vec<String>) {
    let mut lines: Vec<String> = existing.lines().map(String::from).collect();
    let mut added = Vec::new();
    let job_line;
    match timezone {
        Some(tz) => {
            if !lines.iter().any(|l| is_tz_block_marker(l)) {
                added.push(TZ_BLOCK_MARKER.to_string());
            }
            added.push(format!("CRON_TZ={}", tz));
            added.extend(comment_line.map(String::from));
            added.push(cron_line.to_string());
            lines.extend(added.iter().cloned());
            job_line = lines.len();
        }
        None => {
            added.extend(comment_line.map(String::from));
            added.push(cron_line.to_string());
            match lines.iter().position(|l| is_tz_block_marker(l)) {
                Some(marker) => {
                    lines.splice(marker..marker, added.iter().cloned());
                    job_line = marker + added.len();
                }
                None => {
                    lines.extend(added.iter().cloned());
                    job_line = lines.len();
                }
            }
        }
    }
    let mut content = lines.join("\n");
    if !content.ends_with('\n') {
        content.push('\n');
    }
    (content, job_line as u32, added)
}

/// After `rm`: drops each CRON_TZ line at `candidates` (lines that stood
/// directly above a removed job) when only blank lines separate it from the
/// next CRON_TZ line or the end of the file, so dropping it changes no other
/// line's zone; then drops the block marker if nothing but blank lines
/// follows it.
fn drop_orphaned_tz_lines(lines: Vec<String>, candidates: &[usize]) -> Vec<String> {
    let orphaned: std::collections::HashSet<usize> = candidates
        .iter()
        .copied()
        .filter(|&c| {
            lines[c + 1..]
                .iter()
                .find(|l| !l.trim().is_empty())
                .is_none_or(|l| cron_tz_assignment(l).is_some())
        })
        .collect();
    let mut out: Vec<String> = lines
        .into_iter()
        .enumerate()
        .filter(|(i, _)| !orphaned.contains(i))
        .map(|(_, l)| l)
        .collect();
    if let Some(marker) = out.iter().position(|l| is_tz_block_marker(l))
        && out[marker + 1..].iter().all(|l| l.trim().is_empty())
    {
        out.truncate(marker);
    }
    out
}

/// Whether the cron daemon honors CRON_TZ. Only cronie does; Debian/Ubuntu
/// cron (vixie) and busybox crond silently ignore it. cronie is recognized by
/// `crontab -V`, which only cronie's crontab implements (it prints the
/// package string, e.g. `cronie 1.7.2`); the crontab command and the daemon
/// come from the same package. Anything else, including no answer, is
/// treated as not cronie.
fn cronie_detected(host: &dyn CronHost) -> Result<String, String> {
    match host.crontab_version() {
        Some(v) if v.to_ascii_lowercase().contains("cronie") => Ok(v),
        Some(v) => Err(format!(
            "this host's cron is {:?}, not cronie, and only cronie honors CRON_TZ",
            v
        )),
        None => Err("the cron implementation could not be identified as cronie \
             (`crontab -V` printed no version; only cronie's crontab supports -V), \
             and only cronie honors CRON_TZ"
            .to_string()),
    }
}

/// `value` must be one of `allowed`.
fn check_choice(field: &'static str, value: &str, allowed: &[&str]) -> Result<(), InvalidField> {
    if !allowed.contains(&value) {
        return Err(invalid(
            field,
            format!("must be one of {}, got {:?}", allowed.join(", "), value),
        ));
    }
    Ok(())
}
/// A systemd unit name without its suffix: stays inside the unit directory
/// and cannot be read as a systemctl option.
fn check_unit_name(field: &'static str, name: &str) -> Result<(), InvalidField> {
    let ok = !name.is_empty()
        && name.len() <= 240
        && !name.starts_with('-')
        && !name.starts_with('.')
        && !name.ends_with('@')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '@' | '-'));
    if !ok {
        return Err(invalid(
            field,
            format!(
                "must be a systemd unit name (letters, digits, _ . : @ -; not starting with - or .), got {:?}",
                name
            ),
        ));
    }
    Ok(())
}

/// A unit-file value must not end in `\`, which continues the line into the
/// next directive.
fn check_no_continuation(field: &'static str, value: &str) -> Result<(), InvalidField> {
    if value.ends_with('\\') {
        return Err(invalid(field, "must not end with a backslash"));
    }
    Ok(())
}

/// A systemd time span such as `1min`, `30s` or `1h 30min`.
fn check_timespan(field: &'static str, value: &str) -> Result<(), InvalidField> {
    let ok = value.starts_with(|c: char| c.is_ascii_digit())
        && !value.ends_with(' ')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == ' ');
    if !ok {
        return Err(invalid(
            field,
            format!(
                "must be a systemd time span such as 30s or 5min, got {:?}",
                value
            ),
        ));
    }
    Ok(())
}

/// Checks every `add` argument that `backend` writes into a crontab or unit
/// file, and the unit name used for the unit file paths.
pub(crate) fn validate_add_options(
    options: &CronAddOptions,
    backend: &str,
    unit_name: Option<&str>,
) -> Result<(), InvalidField> {
    check_single_line("schedule", &options.schedule)?;
    check_single_line("command", &options.command)?;
    if let Some(id) = &options.id {
        check_single_line("id", id)?;
        check_job_id(id)?;
    }
    if let Some(desc) = &options.description {
        check_single_line("description", desc)?;
    }
    if let Some(tz) = &options.timezone {
        check_timezone("timezone", tz)?;
    }
    if let Some(scope) = &options.scope {
        check_choice("scope", scope, &["current", "user", "system"])?;
    }
    if let Some(unit_scope) = &options.unit_scope {
        check_choice("unit_scope", unit_scope, &["auto", "user", "system"])?;
    }
    match backend {
        "cron" => {
            // cron turns an unescaped % into a line break and sends the
            // rest of the command to its stdin. Like cron, a `\` escapes the
            // next character, so in `\\%` the `%` is unescaped.
            let mut escaped = false;
            let unescaped_percent = options.command.chars().any(|c| {
                let hit = c == '%' && !escaped;
                escaped = c == '\\' && !escaped;
                hit
            });
            if unescaped_percent {
                return Err(invalid(
                    "command",
                    "contains an unescaped % (cron turns it into a line break); write \\% for a literal %",
                ));
            }
            if let Some(user) = &options.user {
                check_user_name("user", user)?;
            }
            if options.scope.as_deref() == Some("system")
                && let Some(file) = &options.cron_file
            {
                check_single_line("cron_file", file)?;
                check_system_cron_file(file)?;
            }
        }
        "systemd" => {
            if let Some(desc) = &options.description {
                check_no_continuation("description", desc)?;
            }
            // ExecStart= prefixes change how the command runs ("+" ignores
            // User=, "-" ignores failure).
            if options
                .command
                .trim_start()
                .starts_with(['@', '-', ':', '+', '!'])
            {
                return Err(invalid(
                    "command",
                    "must not start with a systemd ExecStart prefix (@ - : + !)",
                ));
            }
            check_no_continuation("command", &options.command)?;
            if let Some(name) = unit_name {
                let field = if options.unit_name.is_some() {
                    "unit_name"
                } else if options.id.is_some() {
                    "id"
                } else {
                    "command"
                };
                check_single_line(field, name)?;
                check_unit_name(field, name)?;
            }
            if let Some(user) = &options.service_user {
                check_single_line("service_user", user)?;
                check_user_name("service_user", user)?;
            }
            if let Some(dir) = &options.service_working_dir {
                check_single_line("service_working_dir", dir)?;
                check_no_continuation("service_working_dir", dir)?;
                if !(dir.starts_with('/') || dir == "~") || dir.trim() != dir {
                    return Err(invalid(
                        "service_working_dir",
                        format!("must be an absolute path, got {:?}", dir),
                    ));
                }
            }
            for (field, value) in [
                ("accuracy_sec", &options.accuracy_sec),
                ("random_delay_sec", &options.random_delay_sec),
            ] {
                if let Some(v) = value {
                    check_single_line(field, v)?;
                    check_timespan(field, v)?;
                }
            }
            for (key, value) in options.env.iter().flatten() {
                let key_ok = key.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                    && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
                if !key_ok {
                    return Err(invalid(
                        "env",
                        format!("variable name {:?} must be letters, digits and _", key),
                    ));
                }
                check_single_line("env", value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// A value for a unit file: `%` is a systemd specifier, so it is doubled to
/// stay literal.
fn unit_literal(value: &str) -> String {
    value.replace('%', "%%")
}

/// `Environment="KEY=value"` with the value escaped for systemd's quoting.
fn unit_environment(key: &str, value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%");
    format!("Environment=\"{}={}\"\n", key, escaped)
}

/// Refuses to write through or replace a symlink at a crontab or unit path.
fn refuse_symlink(path: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(anyhow::anyhow!(
            "{} is a symbolic link; refusing to write through it",
            path
        )),
        _ => Ok(()),
    }
}

/// The temporary file used while replacing `path`: in the same directory, and
/// hidden, because cronie loads every other file in /etc/cron.d, so a leftover
/// `job.tmp.N` would run as a second copy of the jobs.
fn atomic_temp_path(path: &str) -> String {
    match path.rsplit_once('/') {
        Some((dir, name)) => format!("{}/.{}.tmp.{}", dir, name, std::process::id()),
        None => format!(".{}.tmp.{}", path, std::process::id()),
    }
}

/// Writes `content` to `path` through a new temporary file in the same
/// directory (never following a link planted at the temporary name) and an
/// atomic rename, refusing a symlink at `path`. The rename replaces a link
/// swapped in after the check instead of writing through it.
///
/// An existing file keeps its permission bits (cron ignores a cron.d file
/// that is group- or world-writable, so the umask must not loosen it); a new
/// file is created 0644 less the umask.
fn write_file_atomically(path: &str, content: &str) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    refuse_symlink(path)?;
    let existing_mode = fs::symlink_metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o777);
    let temp_path = atomic_temp_path(path);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&temp_path)
        .map_err(|e| anyhow::anyhow!("Failed to create temp file {}: {}", temp_path, e))?;
    let written = existing_mode
        .map_or(Ok(()), |mode| {
            file.set_permissions(fs::Permissions::from_mode(mode))
        })
        .and_then(|()| file.write_all(content.as_bytes()))
        .and_then(|()| file.sync_all());
    if let Err(e) = written {
        let _ = fs::remove_file(&temp_path);
        return Err(anyhow::anyhow!(
            "Failed to write temp file {}: {}",
            temp_path,
            e
        ));
    }
    drop(file);
    fs::rename(&temp_path, path).map_err(|e| {
        let _ = fs::remove_file(&temp_path);
        anyhow::anyhow!("Failed to rename {} to {}: {}", temp_path, path, e)
    })
}

// ===========================================================================
// Schedules: crontab syntax, next runs and systemd calendar expressions
// ===========================================================================

/// A crontab schedule as cron (vixie cron and cronie) reads it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CronSpec {
    /// Bit m for minute m (0-59).
    minutes: u64,
    /// Bit h for hour h (0-23).
    hours: u32,
    /// Bit d for day of month d (1-31).
    days: u32,
    /// Bit m for month m (1-12).
    months: u16,
    /// Bit w for weekday w (0-6, Sunday = 0; cron's 7 is Sunday too).
    weekdays: u8,
    /// The day-of-month field starts with `*`.
    day_star: bool,
    /// The weekday field starts with `*`.
    weekday_star: bool,
}

const MONTH_NAMES: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];
const WEEKDAY_NAMES: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
const SYSTEMD_WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/// The five-field form of each `@` keyword (None for `@reboot`).
fn keyword_expansion(keyword: &str) -> Option<Option<&'static str>> {
    Some(match keyword.to_ascii_lowercase().as_str() {
        "@reboot" => None,
        "@yearly" | "@annually" => Some("0 0 1 1 *"),
        "@monthly" => Some("0 0 1 * *"),
        "@weekly" => Some("0 0 * * 0"),
        "@daily" | "@midnight" => Some("0 0 * * *"),
        "@hourly" => Some("0 * * * *"),
        _ => return None,
    })
}

/// One crontab time field as a bit set over `min..=max`. Items are `*`,
/// `N`, `N-M` or a name, each optionally `/step`. `N/step` is read as
/// `N-max/step` in lines found in files; `strict` (add) refuses it, as
/// cronie and Debian's cron both do.
fn parse_field(
    field: &str,
    min: u32,
    max: u32,
    names: &[&str],
    name_base: u32,
    what: &str,
    strict: bool,
) -> Result<u64, String> {
    let value = |v: &str| -> Result<u32, String> {
        if let Ok(n) = v.parse::<u32>()
            && v.bytes().all(|b| b.is_ascii_digit())
        {
            return if (min..=max).contains(&n) {
                Ok(n)
            } else {
                Err(format!("{what} {n} is out of range {min}-{max}"))
            };
        }
        names
            .iter()
            .position(|name| name.eq_ignore_ascii_case(v))
            .map(|i| i as u32 + name_base)
            .ok_or_else(|| format!("{v:?} is not a valid {what}"))
    };
    let mut bits = 0u64;
    for item in field.split(',') {
        if item.is_empty() {
            return Err(format!("empty item in {what} field {field:?}"));
        }
        let (range, step) = match item.split_once('/') {
            Some((r, s)) => match s.parse::<u32>() {
                Ok(n) if n > 0 && s.bytes().all(|b| b.is_ascii_digit()) => (r, Some(n)),
                _ => return Err(format!("invalid step {s:?} in {what} field {field:?}")),
            },
            None => (item, None),
        };
        let (lo, hi) = if range == "*" {
            (min, max)
        } else if let Some((a, b)) = range.split_once('-') {
            (value(a)?, value(b)?)
        } else {
            let v = value(range)?;
            match step {
                Some(_) if strict => {
                    return Err(format!(
                        "{item:?} in the {what} field: a step needs a range, such as \
                         {v}-{max}/{}",
                        step.unwrap_or(1)
                    ));
                }
                Some(_) => (v, max),
                None => (v, v),
            }
        };
        if lo > hi {
            return Err(format!("range {range:?} in the {what} field is reversed"));
        }
        let mut v = lo;
        while v <= hi {
            bits |= 1 << v;
            v += step.unwrap_or(1);
        }
    }
    Ok(bits)
}

/// A crontab schedule (five fields or an `@` keyword); `Ok(None)` for
/// `@reboot`, which has no time.
pub(crate) fn parse_schedule(schedule: &str) -> Result<Option<CronSpec>, String> {
    parse_schedule_with(schedule, false)
}

fn parse_schedule_with(schedule: &str, strict: bool) -> Result<Option<CronSpec>, String> {
    let schedule = schedule.trim();
    let expanded = if schedule.starts_with('@') {
        match keyword_expansion(schedule) {
            Some(Some(e)) => e,
            Some(None) => return Ok(None),
            None => return Err(format!("{schedule:?} is not a supported @ keyword")),
        }
    } else {
        schedule
    };
    let f: Vec<&str> = expanded.split_whitespace().collect();
    if f.len() != 5 {
        return Err(format!(
            "must be five crontab fields (minute hour day month weekday) or an @ keyword, \
             got {schedule:?}"
        ));
    }
    let weekdays = parse_field(f[4], 0, 7, &WEEKDAY_NAMES, 0, "weekday", strict)?;
    Ok(Some(CronSpec {
        minutes: parse_field(f[0], 0, 59, &[], 0, "minute", strict)?,
        hours: parse_field(f[1], 0, 23, &[], 0, "hour", strict)? as u32,
        days: parse_field(f[2], 1, 31, &[], 0, "day of month", strict)? as u32,
        months: parse_field(f[3], 1, 12, &MONTH_NAMES, 1, "month", strict)? as u16,
        // cron's weekday 7 is Sunday (0).
        weekdays: ((weekdays | (weekdays >> 7)) & 0x7f) as u8,
        day_star: f[2].starts_with('*'),
        weekday_star: f[4].starts_with('*'),
    }))
}

impl CronSpec {
    /// cron's day rule: when either day field starts with `*`, both must
    /// match; otherwise a day matches if either field does.
    fn day_matches(&self, date: NaiveDate) -> bool {
        let dom = self.days & (1 << date.day()) != 0;
        let dow = self.weekdays & (1 << date.weekday().num_days_from_sunday()) != 0;
        if self.day_star || self.weekday_star {
            dom && dow
        } else {
            dom || dow
        }
    }

    /// The first run strictly after `after`, with the schedule read in
    /// `zone`. A local time skipped by a daylight-saving change is skipped;
    /// a repeated one runs at its first occurrence.
    fn next_after(&self, after: DateTime<Utc>, zone: RunZone) -> Option<(i64, String)> {
        let local = match zone {
            RunZone::Named(tz) => after.with_timezone(&tz).naive_local(),
            RunZone::Offset(o) => after.with_timezone(&o).naive_local(),
        };
        let mut date = local.date().pred_opt()?;
        // Feb 29 on a given weekday can be 28 years away.
        for _ in 0..(366 * 29) {
            if self.months & (1 << date.month()) != 0 && self.day_matches(date) {
                for h in (0..24).filter(|h| self.hours & (1 << h) != 0) {
                    for m in (0..60).filter(|m| self.minutes & (1u64 << m) != 0) {
                        let naive = date.and_hms_opt(h, m, 0)?;
                        let found = match zone {
                            RunZone::Named(tz) => tz
                                .from_local_datetime(&naive)
                                .earliest()
                                .filter(|t| t.with_timezone(&Utc) > after)
                                .map(|t| (t.timestamp(), t.to_rfc3339())),
                            RunZone::Offset(o) => o
                                .from_local_datetime(&naive)
                                .earliest()
                                .filter(|t| t.with_timezone(&Utc) > after)
                                .map(|t| (t.timestamp(), t.to_rfc3339())),
                        };
                        if found.is_some() {
                            return found;
                        }
                    }
                }
            }
            date = date.succ_opt()?;
        }
        None
    }
}

/// The `now_unix` values accepted as a next-run reference: 1970-01-01T00:00:00Z
/// through 9999-12-31T23:59:59Z.
const NOW_UNIX_RANGE: std::ops::RangeInclusive<i64> = 0..=253_402_300_799;

/// `now_unix` as a reference time, if it is in `NOW_UNIX_RANGE`.
fn reference_time_from_unix(now_unix: i64) -> Option<DateTime<Utc>> {
    if !NOW_UNIX_RANGE.contains(&now_unix) {
        return None;
    }
    Utc.timestamp_opt(now_unix, 0).single()
}

/// The first run of a crontab schedule after `reference_time`, with the
/// schedule read in `zone`, as the Unix time and as RFC 3339 text in that
/// zone's offset. None for `@reboot`, for a schedule that never runs, for an
/// invalid schedule and for a reference outside `NOW_UNIX_RANGE`.
fn compute_next_run(
    schedule_str: &str,
    reference_time: DateTime<Utc>,
    zone: RunZone,
) -> Option<(i64, String)> {
    if !NOW_UNIX_RANGE.contains(&reference_time.timestamp()) {
        return None;
    }
    parse_schedule(schedule_str)
        .ok()
        .flatten()?
        .next_after(reference_time, zone)
}

/// The values in a bit set over `min..=max`, `*` when all are set.
fn calendar_list(bits: u64, min: u32, max: u32, render: impl Fn(u32) -> String) -> String {
    let values: Vec<u32> = (min..=max).filter(|v| bits & (1u64 << v) != 0).collect();
    if values.len() as u32 == max - min + 1 {
        "*".to_string()
    } else {
        values.into_iter().map(render).collect::<Vec<_>>().join(",")
    }
}

/// The systemd `OnCalendar=` expression for a crontab schedule. Lists are
/// written out value by value, so every crontab range and step keeps its
/// meaning. A schedule whose day-of-month and weekday fields are both
/// restricted cannot be expressed: cron runs it when either matches,
/// systemd only when both do.
fn convert_cron_to_oncalendar(schedule: &str) -> Result<String, String> {
    let schedule = schedule.trim();
    match schedule.to_ascii_lowercase().as_str() {
        "@reboot" => {
            return Err("@reboot has no systemd calendar equivalent (it runs at boot)".into());
        }
        "@hourly" => return Ok("hourly".into()),
        "@daily" | "@midnight" => return Ok("daily".into()),
        "@monthly" => return Ok("monthly".into()),
        "@yearly" | "@annually" => return Ok("yearly".into()),
        "@weekly" => return Ok("Sun *-*-* 0:0".into()),
        _ => {}
    }
    let spec = parse_schedule(schedule)?.ok_or("no time to convert")?;
    if !spec.day_star && !spec.weekday_star {
        return Err(
            "cron runs this job when either the day of month or the weekday matches, \
             and a systemd calendar expression needs both to match"
                .into(),
        );
    }
    let minute = calendar_list(spec.minutes, 0, 59, |v| v.to_string());
    let hour = calendar_list(spec.hours as u64, 0, 23, |v| v.to_string());
    let day = calendar_list(spec.days as u64, 1, 31, |v| v.to_string());
    let month = calendar_list(spec.months as u64, 1, 12, |v| v.to_string());
    let weekday = calendar_list(spec.weekdays as u64, 0, 6, |v| {
        SYSTEMD_WEEKDAYS[v as usize].to_string()
    });
    Ok(
        match (
            minute.as_str(),
            hour.as_str(),
            day.as_str(),
            month.as_str(),
            weekday.as_str(),
        ) {
            ("0", "*", "*", "*", "*") => "hourly".into(),
            ("0", "0", "*", "*", "*") => "daily".into(),
            ("0", "0", "1", "*", "*") => "monthly".into(),
            ("0", "0", "1", "1", "*") => "yearly".into(),
            (m, h, "*", "*", "*") => format!("{h}:{m}"),
            (m, h, d, mo, "*") => format!("*-{mo}-{d} {h}:{m}"),
            (m, h, d, mo, w) => format!("{w} *-{mo}-{d} {h}:{m}"),
        },
    )
}

/// The timer's `OnCalendar=` value: the translated schedule, followed by the
/// IANA time zone when `timezone` is given (systemd evaluates the expression
/// in that zone, e.g. `2:0 Europe/Berlin`).
fn systemd_on_calendar(options: &CronAddOptions) -> Result<String, String> {
    let calendar = convert_cron_to_oncalendar(&options.schedule)?;
    Ok(match &options.timezone {
        Some(tz) => format!("{} {}", calendar, tz),
        None => calendar,
    })
}

/// The backend `add` uses: `cron` or `systemd` when available, and for
/// `auto` systemd whenever systemctl runs, cron otherwise.
fn choose_backend(
    host: &dyn CronHost,
    requested: &str,
    warnings: &mut Vec<String>,
) -> Result<String> {
    let crontab = || host.command_runs("crontab", "-V");
    let systemctl = || host.command_runs("systemctl", "--version");
    match requested {
        "cron" if crontab() => Ok("cron".into()),
        "cron" => Err(anyhow::anyhow!(
            "cron backend requested but the crontab command is not available"
        )),
        "systemd" if systemctl() => Ok("systemd".into()),
        "systemd" => Err(anyhow::anyhow!(
            "systemd backend requested but systemctl is not available"
        )),
        _ if systemctl() => Ok("systemd".into()),
        _ if crontab() => {
            warnings.push("systemd not available, using cron backend".to_string());
            Ok("cron".into())
        }
        _ => Err(anyhow::anyhow!(
            "Neither systemd nor cron backends are available"
        )),
    }
}

// ===========================================================================
// Data structures
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    Json,
    Text,
}

#[derive(Debug, Clone)]
pub struct CronListOptions {
    pub scope: String,
    pub users: Vec<String>,
    pub include_system: bool,
    pub include_files: Vec<String>,
    pub state: String,
    pub match_command: Option<String>,
    pub match_comment: Option<String>,
    pub match_user: Option<String>,
    pub match_source: Option<String>,
    pub include_next_run: bool,
    pub now_unix: Option<i64>,
    /// The zone schedules without their own CRON_TZ are read in for
    /// next-run times (the host's local zone when None).
    pub timezone: Option<String>,
    pub max_entries: u32,
    pub sort_by: String,
    pub sort_order: String,
    pub include_raw: bool,
    pub include_paths: bool,
    pub format: OutputFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronScheduleFields {
    pub minute: String,
    pub hour: String,
    pub day_of_month: String,
    pub month: String,
    pub day_of_week: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronEntry {
    pub id: String,
    pub user: Option<String>,
    pub source: String,
    pub source_file: Option<String>,
    pub source_line: Option<u32>,
    pub enabled: bool,
    pub comment_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule_fields: Option<CronScheduleFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub special: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_run_unix: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_run_iso8601: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_line: Option<String>,
    /// The CRON_TZ in effect for this line (honored only by cronie).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronListHumanSummary {
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronListResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,
    pub scope: String,
    pub users: Vec<String>,
    pub include_system: bool,
    pub truncated: bool,
    pub entries_total: Option<u32>,
    pub entries_returned: u32,
    pub entries_disabled: u32,
    pub entries: Vec<CronEntry>,
    /// The zone next-run times of entries without their own CRON_TZ were
    /// computed in (`timezone=`, else the host's local zone; an offset such
    /// as `+01:00` when the local zone has no known name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_run_timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human: Option<CronListHumanSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    pub warnings: Vec<String>,
}

// ===========================================================================
// CronAdd types and structures
// ===========================================================================

#[derive(Debug, Clone)]
pub struct CronAddOptions {
    pub schedule: String,
    pub command: String,

    pub backend: String, // "auto" | "cron" | "systemd"

    pub id: Option<String>,
    pub description: Option<String>,
    pub allow_duplicate: bool,
    pub dry_run: bool,

    /// "current" | "user" | "system" (cron backend; "current" when None).
    pub scope: Option<String>,
    pub user: Option<String>,
    pub cron_file: Option<String>,

    pub unit_name: Option<String>,
    /// "auto" | "user" | "system" (systemd backend; "auto" when None).
    pub unit_scope: Option<String>,
    /// Persistent= of the timer (systemd backend; true when None).
    pub persistent: Option<bool>,
    pub accuracy_sec: Option<String>,
    pub random_delay_sec: Option<String>,
    pub service_working_dir: Option<String>,
    pub service_user: Option<String>,
    pub env: Option<HashMap<String, String>>,

    pub include_next_run: bool,
    /// Reference time for `next_run_*` (the current time when None).
    pub now_unix: Option<i64>,
    /// IANA zone: systemd `OnCalendar=` suffix, or a cronie `CRON_TZ` line.
    pub timezone: Option<String>,

    pub format: OutputFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronAddJobLocation {
    pub scope: String, // "current" | "user" | "system" | "user-unit" | "system-unit"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>, // cron file, if applicable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_added: Option<u32>, // for cron

    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timer_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronAddJobInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub backend: String, // "cron" | "systemd"
    pub schedule: String,
    pub command: String,

    pub location: CronAddJobLocation,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_run_unix: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_run_iso8601: Option<String>,
    /// The zone the next run was computed in (`timezone`, else the host's
    /// local zone; an offset such as `+01:00` when it has no known name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_run_timezone: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronAddPreview {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cron_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timer_unit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronAddResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_used: Option<String>,
    pub dry_run: bool,
    pub duplicate: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub job: Option<CronAddJobInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<CronAddPreview>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    pub warnings: Vec<String>,
}

// ===========================================================================
// CronRm types and structures
// ===========================================================================

#[derive(Debug, Clone)]
pub struct CronRmOptions {
    pub id: Option<String>,
    pub backend: String, // "both" | "cron" | "systemd"

    pub scope: String, // "current" | "user" | "system" | "all"
    pub users: Vec<String>,
    pub schedule: Option<String>,
    pub command: Option<String>,
    pub match_command: Option<String>,
    pub match_comment: Option<String>,
    /// A system cron file (/etc/crontab or /etc/cron.d/<name>) to act on
    /// instead of the crontabs chosen by `scope`.
    pub cron_file: Option<String>,

    pub unit_name: Option<String>,
    pub unit_scope: String, // "auto" | "user" | "system" | "both"
    pub match_unit: Option<String>,

    pub require_match: bool,
    pub remove_units: bool,
    pub dry_run: bool,

    pub format: OutputFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronRmCronRemovedEntry {
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
    /// The CRON_TZ in effect for the job (honored only by cronie).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronRmSystemdRemovedEntry {
    pub unit_scope: String, // "user" | "system"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timer_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronRmRemovedSummary {
    pub cron: Vec<CronRmCronRemovedEntry>,
    pub systemd: Vec<CronRmSystemdRemovedEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronRmMatchedCount {
    pub cron: u32,
    pub systemd: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronRmResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub dry_run: bool,
    pub backend: String,
    pub cron_modified_sources: Vec<String>,
    pub systemd_scopes_touched: Vec<String>,

    pub removed: CronRmRemovedSummary,
    pub matched_count: CronRmMatchedCount,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    pub warnings: Vec<String>,
}

// ===========================================================================
// CronEnable types and structures
// ===========================================================================

#[derive(Debug, Clone)]
pub struct CronEnableOptions {
    pub id: Option<String>,
    pub backend: String, // "both" | "cron" | "systemd"

    // Cron selectors
    pub scope: String, // "current" | "user" | "system" | "all"
    pub users: Vec<String>,
    pub schedule: Option<String>,
    pub command: Option<String>,
    pub match_command: Option<String>,
    pub match_comment: Option<String>,
    /// A system cron file (/etc/crontab or /etc/cron.d/<name>) to act on
    /// instead of the crontabs chosen by `scope`.
    pub cron_file: Option<String>,

    // systemd selectors
    pub unit_name: Option<String>,
    pub unit_scope: String, // "auto" | "user" | "system" | "both"
    pub match_unit: Option<String>,

    pub require_match: bool,
    pub start_now: bool,
    pub dry_run: bool,

    pub format: OutputFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronEnableCronEntry {
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
    pub was_disabled: bool,
    /// The CRON_TZ in effect for the job (honored only by cronie).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronEnableSystemdEntry {
    pub unit_scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timer_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub was_enabled: bool,
    pub started_now: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronEnableEnabledSummary {
    pub cron: Vec<CronEnableCronEntry>,
    pub systemd: Vec<CronEnableSystemdEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronEnableMatchedCount {
    pub cron: u32,
    pub systemd: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronEnableAlreadyEnabledCount {
    pub cron: u32,
    pub systemd: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronEnableResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub dry_run: bool,
    pub backend: String,

    pub enabled: CronEnableEnabledSummary,

    pub matched_count: CronEnableMatchedCount,
    pub already_enabled_count: CronEnableAlreadyEnabledCount,

    pub cron_modified_sources: Vec<String>,
    pub systemd_scopes_touched: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    pub warnings: Vec<String>,
}

// ===========================================================================
// CronDisable types and structures
// ===========================================================================

#[derive(Debug, Clone)]
pub struct CronDisableOptions {
    pub id: Option<String>,
    pub backend: String, // "both" | "cron" | "systemd"

    // Cron selectors
    pub scope: String, // "current" | "user" | "system" | "all"
    pub users: Vec<String>,
    pub schedule: Option<String>,
    pub command: Option<String>,
    pub match_command: Option<String>,
    pub match_comment: Option<String>,
    pub cron_file: Option<String>,

    // systemd selectors
    pub unit_name: Option<String>,
    pub unit_scope: String, // "auto" | "user" | "system" | "both"
    pub match_unit: Option<String>,

    pub require_match: bool,
    pub stop_now: bool,
    pub dry_run: bool,

    pub format: OutputFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronDisableCronEntry {
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
    pub was_enabled: bool,
    /// The CRON_TZ in effect for the job (honored only by cronie).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronDisableSystemdEntry {
    pub unit_scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timer_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub was_enabled: bool,
    pub stopped_now: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronDisableDisabledSummary {
    pub cron: Vec<CronDisableCronEntry>,
    pub systemd: Vec<CronDisableSystemdEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronDisableMatchedCount {
    pub cron: u32,
    pub systemd: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronDisableAlreadyDisabledCount {
    pub cron: u32,
    pub systemd: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronDisableResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub dry_run: bool,
    pub backend: String,

    pub disabled: CronDisableDisabledSummary,

    pub matched_count: CronDisableMatchedCount,
    pub already_disabled_count: CronDisableAlreadyDisabledCount,

    pub cron_modified_sources: Vec<String>,
    pub systemd_scopes_touched: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    pub warnings: Vec<String>,
}

// ===========================================================================
// Paths, ids, filters and sorting
// ===========================================================================

/// Path reported for a user's crontab spool file. Debian-style systems use
/// /var/spool/cron/crontabs/<user>; others (cronie) use /var/spool/cron/<user>.
fn user_crontab_path(user: &str) -> String {
    if Path::new("/var/spool/cron/crontabs").is_dir() {
        format!("/var/spool/cron/crontabs/{}", user)
    } else {
        format!("/var/spool/cron/{}", user)
    }
}

/// Extracts the id from a `# job-id=<id> ...` comment line written by add.
/// Returns None when there is no `job-id=` or the id is empty.
fn extract_job_id(line: &str) -> Option<String> {
    let start = line.find("job-id=")? + "job-id=".len();
    let rest = &line[start..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let id = &rest[..end];
    if id.is_empty() {
        None
    } else {
        Some(id.to_string())
    }
}

/// Keeps the entries that pass `state` and the `match_*` filters. Comment
/// lines are neither enabled nor disabled jobs: `state=enabled` and
/// `state=disabled` leave them out.
fn apply_filters(mut entries: Vec<CronEntry>, options: &CronListOptions) -> Vec<CronEntry> {
    let contains = |field: Option<&str>, pattern: &Option<String>| match pattern {
        Some(p) => field
            .map(|f| f.to_lowercase().contains(&p.to_lowercase()))
            .unwrap_or(false),
        None => true,
    };
    entries.retain(|entry| {
        let state_ok = match options.state.as_str() {
            "enabled" => entry.enabled && !entry.comment_only,
            "disabled" => !entry.enabled && !entry.comment_only,
            _ => true, // "all" - no filtering
        };
        let source = entry
            .source_file
            .as_deref()
            .unwrap_or(entry.source.as_str());
        state_ok
            && contains(entry.command.as_deref(), &options.match_command)
            && contains(entry.comment.as_deref(), &options.match_comment)
            && contains(entry.user.as_deref(), &options.match_user)
            && (contains(Some(source), &options.match_source)
                || contains(Some(entry.source.as_str()), &options.match_source))
    });

    entries
}

fn apply_sorting(entries: &mut [CronEntry], sort_by: &str, sort_order: &str) {
    use std::cmp::Ordering;

    let ascending = sort_order != "desc";

    entries.sort_by(|a, b| {
        let result = match sort_by {
            "user" => {
                let user_cmp = a.user.cmp(&b.user);
                if user_cmp != Ordering::Equal {
                    user_cmp
                } else {
                    a.schedule.cmp(&b.schedule)
                }
            }
            "schedule" => {
                // If we have next_run_unix, sort by that, otherwise by schedule string
                if a.next_run_unix.is_some() && b.next_run_unix.is_some() {
                    a.next_run_unix.cmp(&b.next_run_unix)
                } else {
                    a.schedule.cmp(&b.schedule)
                }
            }
            "command" => a.command.cmp(&b.command),
            "source" => {
                let source_cmp = a.source.cmp(&b.source);
                if source_cmp != Ordering::Equal {
                    source_cmp
                } else {
                    a.source_file.cmp(&b.source_file)
                }
            }
            _ => Ordering::Equal, // "none" or unknown
        };

        if ascending { result } else { result.reverse() }
    });
}

// ===========================================================================
// Registration
// ===========================================================================

pub fn register(registry: &mut crate::core::Registry) {
    registry.register_scheme("cron", |url| Ok(Box::new(CronHandle::from_url(url)?)));
}

#[cfg(test)]
#[path = "cronh_tests.rs"]
mod tests;
