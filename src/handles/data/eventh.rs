//! `event://.<verb>`: a local event log shared by every resh process of the
//! user.
//!
//! Events are stored as one JSON Lines file per topic under the user's state
//! directory (see [`store`]), so an event emitted by one resh command is read
//! by any later or concurrently running one. Every verb validates all of its
//! arguments before it touches the store (unknown or invalid arguments exit
//! 2), lock waits and reads are bounded by `timeout_ms` (exit 124,
//! `event.timeout`), and failures are reported as
//! `Error: [event.<code>] <message>` on stderr; `emit`, `subscribe` and
//! `list-topics` also print their JSON result with `"ok": false` and an
//! `"error": {"code", "message"}` object.

mod store;
#[cfg(test)]
mod tests;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use url::Url;
use uuid::Uuid;

use crate::core::{
    help::{self, HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::{Status, exit},
};
pub use store::Store;
use store::{LockKind, OFFSETS_LOCK};

// ===========================================================================
// Hooks
// ===========================================================================

/// A hook called after a successful `emit` or `subscribe`. Hooks write
/// notes to stderr only, so the JSON on stdout stays parseable.
pub trait EventHook: Send + Sync {
    /// Called after an event was stored.
    fn on_emit(&self, event: &EventEnvelope, out: &mut dyn Write) -> std::io::Result<()>;

    /// Called after `subscribe` delivered a batch of `events_returned` events
    /// for `topic` (the pattern).
    fn on_subscribe(
        &self,
        topic: &str,
        events_returned: usize,
        out: &mut dyn Write,
    ) -> std::io::Result<()>;

    /// The hook name.
    fn name(&self) -> &str;
}

/// The value of the first tag of `event` that starts with `prefix`.
fn tag_value<'a>(event: &'a EventEnvelope, prefix: &str) -> Option<&'a str> {
    event.tags.iter().find_map(|t| t.strip_prefix(prefix))
}

/// Simulated message-queue forwarding: notes events tagged `mq:<topic>`.
pub struct MQHook;

impl EventHook for MQHook {
    fn on_emit(&self, event: &EventEnvelope, out: &mut dyn Write) -> std::io::Result<()> {
        if let Some(topic) = tag_value(event, "mq:") {
            writeln!(
                out,
                "MQ Hook: Would forward event {} to MQ topic: {}",
                event.id, topic
            )?;
        }
        Ok(())
    }

    fn on_subscribe(&self, _topic: &str, n: usize, out: &mut dyn Write) -> std::io::Result<()> {
        writeln!(out, "MQ hook processed subscription with {n} events")
    }

    fn name(&self) -> &str {
        "mq"
    }
}

/// Simulated log forwarding: notes events tagged `log:<path>`.
pub struct LogHook;

impl EventHook for LogHook {
    fn on_emit(&self, event: &EventEnvelope, out: &mut dyn Write) -> std::io::Result<()> {
        if let Some(path) = tag_value(event, "log:") {
            writeln!(
                out,
                "Log Hook: Event {}: {} -> {}",
                event.id, event.topic, path
            )?;
        }
        Ok(())
    }

    fn on_subscribe(&self, topic: &str, n: usize, out: &mut dyn Write) -> std::io::Result<()> {
        writeln!(out, "Log hook: subscription to {topic} returned {n} events")
    }

    fn name(&self) -> &str {
        "log"
    }
}

/// Simulated process actions: notes events tagged `proc:<action>`.
pub struct ProcHook;

impl EventHook for ProcHook {
    fn on_emit(&self, event: &EventEnvelope, out: &mut dyn Write) -> std::io::Result<()> {
        if let Some(action) = tag_value(event, "proc:") {
            writeln!(
                out,
                "Process Hook: Action requested: {} for event {}",
                action, event.id
            )?;
        }
        Ok(())
    }

    fn on_subscribe(&self, topic: &str, _n: usize, out: &mut dyn Write) -> std::io::Result<()> {
        if topic.starts_with("proc.") {
            writeln!(out, "Process monitoring subscription: {topic}")?;
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "proc"
    }
}

/// Simulated filesystem watching: notes events tagged `fs:<path>`.
pub struct FsWatchHook;

impl EventHook for FsWatchHook {
    fn on_emit(&self, event: &EventEnvelope, out: &mut dyn Write) -> std::io::Result<()> {
        if let Some(path) = tag_value(event, "fs:") {
            writeln!(out, "FS Hook: Filesystem event for path: {path}")?;
        }
        Ok(())
    }

    fn on_subscribe(&self, topic: &str, _n: usize, out: &mut dyn Write) -> std::io::Result<()> {
        if topic.starts_with("fs.") {
            writeln!(out, "Filesystem watch subscription: {topic}")?;
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "fs"
    }
}

/// Names of the built-in hooks, sorted (the order they run in).
const HOOK_NAMES: &[&str] = &["fs", "log", "mq", "proc"];

fn builtin_hook(name: &str) -> Option<Arc<dyn EventHook>> {
    Some(match name {
        "fs" => Arc::new(FsWatchHook),
        "log" => Arc::new(LogHook),
        "mq" => Arc::new(MQHook),
        "proc" => Arc::new(ProcHook),
        _ => return None,
    })
}

/// How long hooks.enable and hooks.disable wait for the store lock.
const HOOK_LOCK_WAIT: Duration = Duration::from_secs(10);

// ===========================================================================
// Registration and help
// ===========================================================================

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("event", |u| Ok(Box::new(EventHandle::from_url(u)?)));
}

/// Metadata for `resh event --help` and `resh event <verb> --help`.
static EVENT_HELP: HandleHelp = HandleHelp {
    description: "The event handle appends structured events to a local event store, one \
        JSON Lines file per topic under the user's state directory (normally \
        ~/.local/state/resh/events), and reads them back by topic pattern with offsets \
        and consumer groups. Events emitted by one resh command are read by any later or \
        concurrently running resh command of the same user. The stage has no target, so \
        the verb follows a dot directly, as in event://.emit.",
    usage: "resh event://.<verb> [key=value ...]",
    verbs: &[
        VerbHelp {
            name: "list-topics",
            definition: "Lists the topics in the event store with their event counts and \
                newest event time, and optionally the payload fields of the latest event, as \
                a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh event://.list-topics [prefix=<text>] [match=<text>]\n  \
                    [sources=event] [limit=<n>] [include_hidden=true|false]\n  \
                    [include_stats=true|false] [include_schema=true|false]\n  \
                    [format=json|text] [timeout_ms=<n>]",
                example: "resh --json-pretty event://.list-topics prefix=jobs. \
                    include_stats=true",
                example_output: Some(
                    r#"{
  "error": null,
  "filters": {
    "include_hidden": false,
    "include_schema": false,
    "include_stats": true,
    "limit": 1000,
    "match": null,
    "prefix": "jobs.",
    "sources": [
      "event"
    ]
  },
  "ok": true,
  "timestamp_unix_ms": 1792166019775,
  "topics": [
    {
      "backends": [
        {
          "handle": "event",
          "id": "event:jobs.backup.completed",
          "type": "event"
        }
      ],
      "category": "jobs",
      "description": null,
      "display_name": "jobs.backup.completed",
      "first_seen_unix_ms": 1792166019757,
      "is_hidden": false,
      "name": "jobs.backup.completed",
      "origin": null,
      "schema": null,
      "sources": [
        "event"
      ],
      "stats": {
        "approx_message_count": 1,
        "last_event_unix_ms": 1792166019757,
        "partitions": null,
        "replication_factor": null,
        "throughput_per_minute": null
      },
      "tags": []
    }
  ],
  "topics_returned": 1,
  "topics_total": 1,
  "truncated": false,
  "warnings": []
}

Shown with --json-pretty. Topics starting with _ are hidden unless
include_hidden=true. match is a case-insensitive substring. Expired
events (ttl_ms) are not counted. timeout_ms defaults to 30000."#,
                ),
            }),
        },
        VerbHelp {
            name: "subscribe",
            definition: "Reads stored events whose topic matches a pattern (with * and ? \
                wildcards) from an offset, optionally as a consumer group, waiting for new \
                events or following the topics, and prints them as one JSON object or, with \
                follow=true, one JSON line per event.",
            detail: Some(VerbDetail {
                usage: "resh event://.subscribe topic=<pattern>\n  \
                    [offset=latest|earliest|next|<n>] [limit=<n>] [group_id=<id>]\n  \
                    [consumer_id=<id>] [auto_commit=true|false]\n  \
                    [manual_commit_offset=<n>] [wait=true|false] [wait_timeout_ms=<n>]\n  \
                    [follow=true|false] [max_events=<n>] [timeout_ms=<n>]\n  \
                    [match_tags=<json-array>] [match_correlation_id=<id>]\n  \
                    [match_source=<name>] [max_latency_ms=<n>]\n  \
                    [include_data=true|false] [include_summary=true|false]\n  \
                    [include_raw=true|false] [format=json|text]",
                example: "resh --json-pretty event://.subscribe 'topic=jobs.*' offset=earliest",
                example_output: Some(
                    r#"{
  "committed": false,
  "committed_offset": null,
  "consumer_id": null,
  "effective_offset": "earliest",
  "error": null,
  "events": [
    {
      "backend": "state_file",
      "causation_id": null,
      "correlation_id": null,
      "data": {
        "status": "success"
      },
      "id": "evt_1792166019757_224a64d890cb",
      "key": null,
      "mode": "fire_and_forget",
      "mode_used": "fire_and_forget",
      "offset": "0",
      "priority": "normal",
      "raw": null,
      "schema_version": null,
      "source": null,
      "summary": null,
      "tags": [],
      "timestamp_unix_ms": 1792166019757,
      "topic": "jobs.backup.completed",
      "ttl_ms": null
    }
  ],
  "events_returned": 1,
  "group_id": null,
  "high_watermark": "1",
  "next_offset": "1",
  "offset_end": "0",
  "offset_start": "0",
  "ok": true,
  "timed_out": false,
  "timestamp_unix_ms": 1792166019771,
  "topic": "jobs.*",
  "warnings": []
}

Shown with --json-pretty. Offsets index the matching events in the
order they were stored; limit (default 100) caps the events returned.
With group_id, offset=next resumes after the group's committed offset
and the read and commit are atomic, so consumers of one group never get
the same event. wait=true waits for an event until wait_timeout_ms
(default 30000) or timeout_ms passes. follow=true prints each event as a
JSON line as it arrives, until max_events or timeout_ms (default: no
limit). Without wait or follow, timeout_ms defaults to 30000. Enabled
hooks print notes on stderr."#,
                ),
            }),
        },
        VerbHelp {
            name: "emit",
            definition: "Appends an event with a JSON payload to a topic's file in the event \
                store and prints the stored event as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh event://.emit topic=<topic> data=<json> [source=<name>]\n  \
                    [key=<key>] [correlation_id=<id>] [causation_id=<id>]\n  \
                    [tags=<json-array>] [priority=low|normal|high]\n  \
                    [mode=fire_and_forget|wait_for_persist] [ttl_ms=<n>]\n  \
                    [summarize=true|false] [schema_version=<v>] [format=json|text]\n  \
                    [timeout_ms=<n>]",
                example: "resh event://.emit topic=jobs.backup.completed \
                    'data={\"status\":\"success\"}'",
                example_output: Some(
                    r#"{
  "error": null,
  "event": {
    "backend": "state_file",
    "causation_id": null,
    "correlation_id": null,
    "data": {
      "status": "success"
    },
    "id": "evt_1792166019757_224a64d890cb",
    "key": null,
    "mode": "fire_and_forget",
    "mode_used": "fire_and_forget",
    "priority": "normal",
    "schema_version": null,
    "source": null,
    "summary": null,
    "tags": [],
    "timestamp_unix_ms": 1792166019757,
    "topic": "jobs.backup.completed",
    "ttl_ms": null
  },
  "ok": true,
  "timestamp_unix_ms": 1792166019757,
  "warnings": []
}

The topic must not contain the wildcards * or ?. mode=wait_for_persist
syncs the file to disk before the reply. subscribe skips an event once
its ttl_ms has passed. timeout_ms (default 30000, 0 = no limit) bounds
the wait for the store lock; when it passes nothing is written."#,
                ),
            }),
        },
        VerbHelp {
            name: "hooks.list",
            definition: "Lists the built-in hooks that are enabled and those disabled with \
                hooks.disable, as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh event://.hooks.list",
                example: "resh --json-pretty event://.hooks.list",
                example_output: Some(
                    r#"{
  "disabled": [],
  "global_hooks": [
    "fs",
    "log",
    "mq",
    "proc"
  ],
  "instance_hooks": [],
  "total": 4
}

Shown with --json-pretty. Without it the object is one line. The hooks
only print notes on stderr; they do not forward events."#,
                ),
            }),
        },
        VerbHelp {
            name: "hooks.enable",
            definition: "Enables one of the built-in hooks fs, log, mq, or proc for this and \
                every later resh command of the user.",
            detail: Some(VerbDetail {
                usage: "resh event://.hooks.enable name=fs|log|mq|proc",
                example: "resh event://.hooks.enable name=mq",
                example_output: Some(
                    r#"{"changed":true,"enabled":true,"hook":"mq"}

changed is false if the hook was already enabled."#,
                ),
            }),
        },
        VerbHelp {
            name: "hooks.disable",
            definition: "Disables one of the built-in hooks fs, log, mq, or proc for this \
                and every later resh command of the user, recording it in the event store.",
            detail: Some(VerbDetail {
                usage: "resh event://.hooks.disable name=fs|log|mq|proc",
                example: "resh event://.hooks.disable name=mq",
                example_output: Some(
                    r#"{"changed":true,"disabled":true,"hook":"mq"}

changed is false if the hook was already disabled."#,
                ),
            }),
        },
    ],
};

// ===========================================================================
// Errors
// ===========================================================================

/// A failure with its exit code and `event.<code>` error code.
#[derive(Debug, Clone)]
pub(crate) struct Fail {
    exit: i32,
    code: &'static str,
    message: String,
}

impl Fail {
    fn new(exit: i32, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            exit,
            code,
            message: message.into(),
        }
    }
    fn invalid(message: impl Into<String>) -> Self {
        Self::new(exit::USAGE, "event.invalid_argument", message)
    }
    fn missing(message: impl Into<String>) -> Self {
        Self::new(exit::USAGE, "event.missing_argument", message)
    }
    fn store(message: impl Into<String>) -> Self {
        Self::new(exit::FAILED, "event.store_error", message)
    }
    fn unavailable(message: impl Into<String>) -> Self {
        Self::new(exit::FAILED, "event.store_unavailable", message)
    }
    fn corrupt(message: impl Into<String>) -> Self {
        Self::new(exit::FAILED, "event.store_corrupt", message)
    }
    fn timeout(message: impl Into<String>) -> Self {
        Self::new(exit::TIMEOUT, "event.timeout", message)
    }
    fn status(&self) -> Status {
        Status::coded(self.exit, self.code, &self.message)
    }
    fn json(&self) -> Value {
        crate::core::status::error_json(self.code, &self.message)
    }
}

/// Every error code the handle emits (documented in
/// docs/Data_StateManagement/event.md).
#[cfg(test)]
const ERROR_CODES: &[&str] = &[
    "event.invalid_argument",
    "event.missing_argument",
    "event.invalid_topic",
    "event.invalid_data",
    "event.invalid_tags",
    "event.invalid_target",
    "event.unknown_hook",
    "event.unknown_verb",
    "event.store_unavailable",
    "event.store_error",
    "event.store_corrupt",
    "event.timeout",
    "event.output_failed",
];

// ===========================================================================
// Arguments
// ===========================================================================

/// The arguments each verb accepts, or None for an unknown verb.
fn verb_args(verb: &str) -> Option<&'static [&'static str]> {
    Some(match verb {
        "emit" => &[
            "topic",
            "data",
            "source",
            "key",
            "correlation_id",
            "causation_id",
            "tags",
            "priority",
            "mode",
            "ttl_ms",
            "summarize",
            "schema_version",
            "format",
            "timeout_ms",
        ],
        "subscribe" => &[
            "topic",
            "offset",
            "limit",
            "group_id",
            "consumer_id",
            "auto_commit",
            "manual_commit_offset",
            "wait",
            "wait_timeout_ms",
            "follow",
            "max_events",
            "timeout_ms",
            "match_tags",
            "match_correlation_id",
            "match_source",
            "max_latency_ms",
            "include_data",
            "include_summary",
            "include_raw",
            "format",
        ],
        "list-topics" => &[
            "prefix",
            "match",
            "sources",
            "limit",
            "include_hidden",
            "include_stats",
            "include_schema",
            "format",
            "timeout_ms",
        ],
        "hooks.list" => &[],
        "hooks.enable" | "hooks.disable" => &["name"],
        _ => return None,
    })
}

/// Refuses any argument `verb` does not take. `dry_run=false` is accepted
/// (no verb has a dry-run mode, so `dry_run=true` is refused).
fn check_args(verb: &str, args: &Args) -> Result<(), Fail> {
    let allowed = verb_args(verb).unwrap_or(&[]);
    let mut keys: Vec<&String> = args.keys().collect();
    keys.sort();
    for k in keys {
        let k = k.as_str();
        if allowed.contains(&k) {
            continue;
        }
        if k == "dry_run" {
            match crate::core::lenient::dry_run(args) {
                Ok(false) => continue,
                Ok(true) => {
                    return Err(Fail::invalid(format!(
                        "event {verb} does not support dry_run; nothing was done"
                    )));
                }
                Err(e) => return Err(Fail::invalid(e.to_string())),
            }
        }
        if k == "timeout_ms" {
            return Err(Fail::invalid(format!(
                "{verb} does not take timeout_ms: it is a quick local operation"
            )));
        }
        return Err(Fail::invalid(format!(
            "unknown argument for {verb}: {k}{}",
            suggest(k, allowed)
                .map(|s| format!(" (did you mean `{s}`?)"))
                .unwrap_or_default()
        )));
    }
    Ok(())
}

/// The candidate closest to `bad` (a prefix of at least three characters,
/// or an edit distance of at most 2), for a "did you mean" hint.
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
    if lower.len() >= 3
        && let Some(c) = candidates.iter().find(|c| c.starts_with(lower.as_str()))
    {
        return Some(c);
    }
    candidates
        .iter()
        .map(|c| (distance(&lower, c), *c))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c)
}

/// Longest timeout_ms, wait_timeout_ms and max_latency_ms: one day.
const MAX_MS: u64 = 86_400_000;
/// Longest ttl_ms: 100 years.
const MAX_TTL_MS: u64 = 100 * 365 * 86_400_000;
/// Default timeout_ms of emit, list-topics and a plain subscribe.
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
/// Default wait_timeout_ms.
const DEFAULT_WAIT_TIMEOUT_MS: u64 = 30_000;
/// Largest limit.
const MAX_LIMIT: u64 = 10_000;
/// How often wait and follow look for new events.
const POLL: Duration = Duration::from_millis(100);

/// A string argument that must not be empty, if present.
fn text_arg(args: &Args, key: &str) -> Result<Option<String>, Fail> {
    match args.get(key) {
        None => Ok(None),
        Some(v) if v.is_empty() => Err(Fail::invalid(format!("{key} cannot be empty"))),
        Some(v) => Ok(Some(v.clone())),
    }
}

/// An integer argument in `min..=max`, if present.
fn u64_arg(args: &Args, key: &str, min: u64, max: u64) -> Result<Option<u64>, Fail> {
    let Some(raw) = args.get(key) else {
        return Ok(None);
    };
    match raw.parse::<u64>() {
        Ok(v) if (min..=max).contains(&v) => Ok(Some(v)),
        _ => Err(Fail::invalid(format!(
            "invalid value for {key}: {raw:?} (expected an integer from {min} to {max})"
        ))),
    }
}

/// A boolean argument, `default` when absent.
fn bool_arg(args: &Args, key: &str, default: bool) -> Result<bool, Fail> {
    crate::core::lenient::bool_arg(args, key)
        .map(|v| v.unwrap_or(default))
        .map_err(|e| Fail::invalid(e.to_string()))
}

/// One of `choices`, `default` when absent.
fn choice_arg(
    args: &Args,
    key: &str,
    default: &'static str,
    choices: &[&'static str],
) -> Result<&'static str, Fail> {
    let Some(raw) = args.get(key) else {
        return Ok(default);
    };
    choices
        .iter()
        .find(|c| **c == raw.as_str())
        .copied()
        .ok_or_else(|| {
            Fail::invalid(format!(
                "invalid value for {key}: {raw:?} (expected {})",
                choices.join(", ")
            ))
        })
}

/// timeout_ms: `default` when absent; 0 means no limit.
fn timeout_arg(args: &Args, default: u64) -> Result<u64, Fail> {
    Ok(u64_arg(args, "timeout_ms", 0, MAX_MS)?.unwrap_or(default))
}

fn deadline_after(start: Instant, ms: u64) -> Option<Instant> {
    (ms > 0).then(|| start + Duration::from_millis(ms))
}

/// True if `s` is a stored topic name: 1 to 256 letters, digits, `.`, `_`,
/// `:` or `-`.
fn valid_topic_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
}

/// Validates a topic (`pattern=false`) or a topic pattern, which may also
/// use the wildcards `*` and `?`.
fn check_topic(s: &str, pattern: bool) -> Result<(), Fail> {
    let fail = |m: String| Fail::new(exit::USAGE, "event.invalid_topic", m);
    if s.is_empty() {
        return Err(fail("topic cannot be empty".into()));
    }
    if s.len() > 256 {
        return Err(fail("topic cannot exceed 256 characters".into()));
    }
    if !pattern && has_wildcard(s) {
        return Err(fail(format!(
            "emit topic cannot contain the wildcards * or ?: {s:?}"
        )));
    }
    let ok = |c: char| {
        c.is_ascii_alphanumeric()
            || matches!(c, '.' | '_' | ':' | '-')
            || (pattern && matches!(c, '*' | '?'))
    };
    if let Some(bad) = s.chars().find(|c| !ok(*c)) {
        return Err(fail(format!(
            "topic {s:?} contains {bad:?}; only letters, digits, '.', '_', ':' and '-'{} \
             are allowed",
            if pattern { ", '*' and '?'" } else { "" }
        )));
    }
    Ok(())
}

/// A JSON array of tags; each tag is 1 to 64 printable ASCII characters.
fn tags_arg(args: &Args, key: &str) -> Result<Vec<String>, Fail> {
    let Some(raw) = args.get(key) else {
        return Ok(Vec::new());
    };
    let fail = |m: String| Fail::new(exit::USAGE, "event.invalid_tags", m);
    let tags: Vec<String> = serde_json::from_str(raw).map_err(|_| {
        fail(format!(
            "{key} must be a JSON array of strings, for example {key}='[\"deploy\",\"prod\"]'"
        ))
    })?;
    for tag in &tags {
        if tag.is_empty() {
            return Err(fail(format!("{key}: a tag cannot be empty")));
        }
        if tag.len() > 64 {
            return Err(fail(format!(
                "{key}: tag {tag:?} is longer than 64 characters"
            )));
        }
        if !tag.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
            return Err(fail(format!("{key}: tag {tag:?} must be printable ASCII")));
        }
    }
    Ok(tags)
}

/// True if `topic` equals `pattern`, or matches it with `*` (any run of
/// characters) and `?` (one character) as wildcards. Topics never contain
/// `/`, so these are the shell's glob rules.
pub(crate) fn topic_matches_pattern(topic: &str, pattern: &str) -> bool {
    fn matches(t: &[u8], p: &[u8]) -> bool {
        let (mut ti, mut pi) = (0, 0);
        let (mut star, mut mark) = (None, 0);
        while ti < t.len() {
            if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
                ti += 1;
                pi += 1;
            } else if pi < p.len() && p[pi] == b'*' {
                star = Some(pi);
                mark = ti;
                pi += 1;
            } else if let Some(s) = star {
                pi = s + 1;
                mark += 1;
                ti = mark;
            } else {
                return false;
            }
        }
        while pi < p.len() && p[pi] == b'*' {
            pi += 1;
        }
        pi == p.len()
    }
    matches(topic.as_bytes(), pattern.as_bytes())
}

fn has_wildcard(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?')
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ===========================================================================
// Event types
// ===========================================================================

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OutputFormat {
    Json,
    Text,
}

fn format_arg(args: &Args) -> Result<OutputFormat, Fail> {
    Ok(
        match choice_arg(args, "format", "json", &["json", "text"])? {
            "text" => OutputFormat::Text,
            _ => OutputFormat::Json,
        },
    )
}

/// The format a failure is reported in: text only if format=text was given.
fn failure_format(args: &Args) -> OutputFormat {
    if args.get("format").map(String::as_str) == Some("text") {
        OutputFormat::Text
    } else {
        OutputFormat::Json
    }
}

/// A stored event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub id: String,
    pub topic: String,
    pub timestamp_unix_ms: i64,

    pub mode: String,
    pub mode_used: String,
    pub priority: String,
    pub ttl_ms: Option<u64>,

    pub key: Option<String>,
    pub correlation_id: Option<String>,
    pub causation_id: Option<String>,
    pub source: Option<String>,
    pub tags: Vec<String>,
    pub schema_version: Option<String>,

    pub data: Value,
    pub summary: Option<String>,
    pub backend: String,

    /// Index in a subscribe result (not stored).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<String>,
    /// The stored record, with include_raw=true (not stored).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
    /// Store-wide sequence number: the order events were stored in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
}

impl EventEnvelope {
    /// The event as printed by emit.
    fn emit_json(&self) -> Value {
        json!({
            "id": self.id,
            "topic": self.topic,
            "timestamp_unix_ms": self.timestamp_unix_ms,
            "mode": self.mode,
            "mode_used": self.mode_used,
            "priority": self.priority,
            "ttl_ms": self.ttl_ms,
            "key": self.key,
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "source": self.source,
            "tags": self.tags,
            "schema_version": self.schema_version,
            "data": self.data,
            "summary": self.summary,
            "backend": self.backend,
        })
    }

    /// The event as printed by subscribe.
    fn subscribe_json(&self) -> Value {
        let mut v = self.emit_json();
        v["offset"] = json!(self.offset);
        v["raw"] = json!(self.raw);
        v
    }

    /// True if the event's ttl_ms has passed at `now_ms`.
    fn expired(&self, now_ms: i64) -> bool {
        self.ttl_ms
            .is_some_and(|ttl| self.timestamp_unix_ms.saturating_add(ttl as i64) <= now_ms)
    }

    /// One line for format=text.
    fn text_line(&self) -> String {
        let when = chrono::DateTime::from_timestamp_millis(self.timestamp_unix_ms)
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
            .unwrap_or_else(|| self.timestamp_unix_ms.to_string());
        let offset = self
            .offset
            .as_ref()
            .map(|o| format!("[{o}] "))
            .unwrap_or_default();
        format!(
            "{offset}{} @ {when} id={} data={}",
            self.topic, self.id, self.data
        )
    }
}

// ===========================================================================
// emit
// ===========================================================================

struct EmitOpts {
    topic: String,
    data: Value,
    key: Option<String>,
    correlation_id: Option<String>,
    causation_id: Option<String>,
    source: Option<String>,
    tags: Vec<String>,
    wait_for_persist: bool,
    priority: &'static str,
    ttl_ms: Option<u64>,
    summarize: bool,
    schema_version: Option<String>,
    format: OutputFormat,
    timeout_ms: u64,
}

fn parse_emit(args: &Args) -> Result<EmitOpts, Fail> {
    check_args("emit", args)?;
    let topic = args
        .get("topic")
        .ok_or_else(|| Fail::missing("emit needs topic=<topic>"))?
        .clone();
    check_topic(&topic, false)?;
    let raw = args
        .get("data")
        .ok_or_else(|| Fail::missing("emit needs data=<json>"))?;
    let data: Value = serde_json::from_str(raw).map_err(|e| {
        Fail::new(
            exit::USAGE,
            "event.invalid_data",
            format!(
                "data is not valid JSON ({e}); quote text as JSON, for example 'data=\"text\"'"
            ),
        )
    })?;
    let mode = choice_arg(
        args,
        "mode",
        "fire_and_forget",
        &["fire_and_forget", "wait_for_persist"],
    )?;
    Ok(EmitOpts {
        topic,
        data,
        key: text_arg(args, "key")?,
        correlation_id: text_arg(args, "correlation_id")?,
        causation_id: text_arg(args, "causation_id")?,
        source: text_arg(args, "source")?,
        tags: tags_arg(args, "tags")?,
        wait_for_persist: mode == "wait_for_persist",
        priority: choice_arg(args, "priority", "normal", &["low", "normal", "high"])?,
        ttl_ms: u64_arg(args, "ttl_ms", 1, MAX_TTL_MS)?,
        summarize: bool_arg(args, "summarize", false)?,
        schema_version: text_arg(args, "schema_version")?,
        format: format_arg(args)?,
        timeout_ms: timeout_arg(args, DEFAULT_TIMEOUT_MS)?,
    })
}

fn generate_event_id(now_ms: i64) -> String {
    let uuid = Uuid::new_v4().simple().to_string();
    format!("evt_{}_{}", now_ms, &uuid[..12])
}

fn summary_of(data: &Value, topic: &str) -> String {
    match data {
        Value::Object(map) => format!(
            "Event '{}' with {} fields: {}",
            topic,
            map.len(),
            map.keys().cloned().collect::<Vec<_>>().join(", ")
        ),
        Value::String(s) => format!("Event '{topic}': {s}"),
        _ => format!("Event '{topic}' emitted"),
    }
}

// ===========================================================================
// subscribe
// ===========================================================================

#[derive(Clone, Copy, Debug, PartialEq)]
enum Offset {
    Latest,
    Earliest,
    Next,
    At(u64),
}

impl Offset {
    fn label(&self) -> String {
        match self {
            Offset::Latest => "latest".into(),
            Offset::Earliest => "earliest".into(),
            Offset::Next => "next".into(),
            Offset::At(n) => n.to_string(),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Filters {
    match_tags: Vec<String>,
    match_correlation_id: Option<String>,
    match_source: Option<String>,
    max_latency_ms: Option<u64>,
}

impl Filters {
    fn passes(&self, e: &EventEnvelope, now_ms: i64) -> bool {
        !e.expired(now_ms)
            && self.match_tags.iter().all(|t| e.tags.contains(t))
            && self
                .match_correlation_id
                .as_ref()
                .is_none_or(|id| e.correlation_id.as_ref() == Some(id))
            && self
                .match_source
                .as_ref()
                .is_none_or(|s| e.source.as_ref() == Some(s))
            && self
                .max_latency_ms
                .is_none_or(|ms| e.timestamp_unix_ms >= now_ms - ms as i64)
    }
}

struct SubscribeOpts {
    topic: String,
    offset: Offset,
    limit: usize,
    group_id: Option<String>,
    consumer_id: Option<String>,
    auto_commit: bool,
    manual_commit_offset: Option<u64>,
    wait: bool,
    wait_timeout_ms: u64,
    follow: bool,
    max_events: u64,
    timeout_ms: u64,
    filters: Filters,
    include_data: bool,
    include_summary: bool,
    include_raw: bool,
    format: OutputFormat,
}

impl SubscribeOpts {
    fn commit_key(&self) -> Option<String> {
        self.group_id
            .as_ref()
            .map(|g| format!("{g}:{}", self.topic))
    }
    /// True if reads by this call commit the group's offset.
    fn group_commit(&self) -> bool {
        self.group_id.is_some() && self.auto_commit
    }
}

/// Arguments that only affect reading, refused with manual_commit_offset.
const READ_ONLY_ARGS: &[&str] = &[
    "offset",
    "limit",
    "auto_commit",
    "wait",
    "wait_timeout_ms",
    "follow",
    "max_events",
    "match_tags",
    "match_correlation_id",
    "match_source",
    "max_latency_ms",
    "include_data",
    "include_summary",
    "include_raw",
];

fn parse_subscribe(args: &Args) -> Result<SubscribeOpts, Fail> {
    check_args("subscribe", args)?;
    let topic = args
        .get("topic")
        .ok_or_else(|| Fail::missing("subscribe needs topic=<pattern>"))?
        .clone();
    check_topic(&topic, true)?;
    let offset = match args.get("offset").map(String::as_str) {
        None | Some("latest") => Offset::Latest,
        Some("earliest") => Offset::Earliest,
        Some("next") => Offset::Next,
        Some(raw) => Offset::At(raw.parse().map_err(|_| {
            Fail::invalid(format!(
                "invalid value for offset: {raw:?} (expected latest, earliest, next or a \
                 non-negative integer)"
            ))
        })?),
    };
    let group_id = text_arg(args, "group_id")?;
    let wait = bool_arg(args, "wait", false)?;
    let follow = bool_arg(args, "follow", false)?;
    let manual_commit_offset = u64_arg(args, "manual_commit_offset", 0, u64::MAX)?;

    if offset == Offset::Next && group_id.is_none() {
        return Err(Fail::missing("offset=next needs group_id=<id>"));
    }
    if manual_commit_offset.is_some() {
        if group_id.is_none() {
            return Err(Fail::missing("manual_commit_offset needs group_id=<id>"));
        }
        if let Some(k) = READ_ONLY_ARGS.iter().find(|k| args.contains_key(**k)) {
            return Err(Fail::invalid(format!(
                "manual_commit_offset only commits an offset and reads no events; it \
                 cannot be combined with {k}"
            )));
        }
    }
    if args.contains_key("auto_commit") && group_id.is_none() {
        return Err(Fail::invalid("auto_commit needs group_id=<id>"));
    }
    if wait && follow {
        return Err(Fail::invalid(
            "wait and follow cannot be combined: follow=true already waits for events",
        ));
    }
    if args.contains_key("wait_timeout_ms") && !wait {
        return Err(Fail::invalid("wait_timeout_ms needs wait=true"));
    }
    if args.contains_key("max_events") && !follow {
        return Err(Fail::invalid("max_events needs follow=true"));
    }
    let wait_timeout_ms =
        u64_arg(args, "wait_timeout_ms", 1, MAX_MS)?.unwrap_or(DEFAULT_WAIT_TIMEOUT_MS);
    // With wait, the default only bounds a stuck lock or read after the wait.
    let default_timeout = if follow {
        0
    } else if wait {
        wait_timeout_ms + DEFAULT_TIMEOUT_MS
    } else {
        DEFAULT_TIMEOUT_MS
    };
    Ok(SubscribeOpts {
        offset,
        limit: u64_arg(args, "limit", 1, MAX_LIMIT)?.unwrap_or(100) as usize,
        consumer_id: text_arg(args, "consumer_id")?,
        auto_commit: bool_arg(args, "auto_commit", true)?,
        manual_commit_offset,
        wait,
        wait_timeout_ms,
        follow,
        max_events: u64_arg(args, "max_events", 1, u64::MAX)?.unwrap_or(0),
        timeout_ms: timeout_arg(args, default_timeout)?,
        filters: Filters {
            match_tags: tags_arg(args, "match_tags")?,
            match_correlation_id: text_arg(args, "match_correlation_id")?,
            match_source: text_arg(args, "match_source")?,
            max_latency_ms: u64_arg(args, "max_latency_ms", 1, MAX_MS)?,
        },
        include_data: bool_arg(args, "include_data", true)?,
        include_summary: bool_arg(args, "include_summary", true)?,
        include_raw: bool_arg(args, "include_raw", false)?,
        format: format_arg(args)?,
        group_id,
        topic,
    })
}

/// A batch selected from the matching events.
#[derive(Default)]
struct Batch {
    events: Vec<EventEnvelope>,
    /// Index the scan started at.
    start: u64,
    /// Index after the last event scanned.
    next: u64,
    /// Number of matching events.
    high: u64,
}

/// Scans `events` from `start`, keeping events that pass `filters`, until
/// `limit` are kept or the end is reached.
fn select(
    events: &[EventEnvelope],
    start: u64,
    limit: usize,
    filters: &Filters,
    now_ms: i64,
) -> Batch {
    let high = events.len() as u64;
    let start = start.min(high);
    let mut i = start as usize;
    let mut out = Vec::new();
    while i < events.len() && out.len() < limit {
        if filters.passes(&events[i], now_ms) {
            out.push(events[i].clone());
        }
        i += 1;
    }
    Batch {
        events: out,
        start,
        next: i as u64,
        high,
    }
}

/// The result of a one-shot subscribe.
struct SubscribeResult {
    batch: Batch,
    timed_out: bool,
    committed_offset: Option<u64>,
    warnings: Vec<String>,
}

fn skipped_warning(skipped: usize) -> Option<String> {
    (skipped > 0).then(|| format!("{skipped} stored line(s) could not be parsed and were skipped"))
}

// ===========================================================================
// list-topics
// ===========================================================================

struct ListOpts {
    prefix: Option<String>,
    match_substr: Option<String>,
    limit: usize,
    include_hidden: bool,
    include_stats: bool,
    include_schema: bool,
    format: OutputFormat,
    timeout_ms: u64,
}

/// The catalogs of earlier versions that list-topics no longer serves.
const OLD_SOURCES: &[&str] = &["mq", "log", "proc", "fs_watch"];

fn parse_list_topics(args: &Args) -> Result<ListOpts, Fail> {
    check_args("list-topics", args)?;
    if let Some(raw) = args.get("sources") {
        let names: Vec<String> = if raw.trim_start().starts_with('[') {
            serde_json::from_str(raw).map_err(|_| {
                Fail::invalid("sources must be a comma-separated list or a JSON array")
            })?
        } else {
            raw.split(',').map(|s| s.trim().to_string()).collect()
        };
        for name in &names {
            if name == "event" {
                continue;
            }
            if OLD_SOURCES.contains(&name.as_str()) {
                return Err(Fail::invalid(format!(
                    "source {name:?} is not available: list-topics lists only the event \
                     store (sources=event)"
                )));
            }
            return Err(Fail::invalid(format!(
                "invalid value for sources: {name:?} (expected event)"
            )));
        }
    }
    Ok(ListOpts {
        prefix: text_arg(args, "prefix")?,
        match_substr: text_arg(args, "match")?,
        limit: u64_arg(args, "limit", 1, MAX_LIMIT)?.unwrap_or(1000) as usize,
        include_hidden: bool_arg(args, "include_hidden", false)?,
        include_stats: bool_arg(args, "include_stats", false)?,
        include_schema: bool_arg(args, "include_schema", false)?,
        format: format_arg(args)?,
        timeout_ms: timeout_arg(args, DEFAULT_TIMEOUT_MS)?,
    })
}

/// The JSON type name of `v`.
fn json_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// One topic as printed by list-topics.
fn topic_json(file: &store::TopicFile, live: &[&EventEnvelope], opts: &ListOpts) -> Value {
    let first = live.iter().map(|e| e.timestamp_unix_ms).min();
    let last = live.iter().map(|e| e.timestamp_unix_ms).max();
    let mut tags: Vec<&String> = live.iter().flat_map(|e| e.tags.iter()).collect();
    tags.sort();
    tags.dedup();
    let category = file.topic.split('.').next().filter(|c| *c != file.topic);
    let stats = opts.include_stats.then(|| {
        json!({
            "approx_message_count": live.len(),
            "last_event_unix_ms": last,
            "partitions": null,
            "replication_factor": null,
            "throughput_per_minute": null,
        })
    });
    let schema = opts
        .include_schema
        .then(|| {
            let latest = live.iter().max_by_key(|e| (e.seq, e.timestamp_unix_ms))?;
            let fields: Vec<Value> = match &latest.data {
                Value::Object(map) => map
                    .iter()
                    .map(|(k, v)| {
                        json!({
                            "name": k,
                            "type": json_type(v),
                            "required": live.iter().all(|e| e.data.get(k).is_some()),
                        })
                    })
                    .collect(),
                _ => Vec::new(),
            };
            Some(json!({
                "schema_version": latest.schema_version,
                "example": latest.data,
                "fields": fields,
            }))
        })
        .flatten();
    json!({
        "name": file.topic,
        "display_name": file.topic,
        "description": null,
        "category": category,
        "is_hidden": file.topic.starts_with('_'),
        "sources": ["event"],
        "backends": [{"type": "event", "handle": "event", "id": format!("event:{}", file.topic)}],
        "stats": stats,
        "schema": schema,
        "tags": tags,
        "origin": null,
        "first_seen_unix_ms": first,
    })
}

// ===========================================================================
// The handle
// ===========================================================================

pub struct EventHandle {
    store: Option<Store>,
    /// Set when the URL names a target; the handle has none.
    target_error: Option<String>,
    /// Hooks registered on this handle object (library use).
    instance_hooks: Mutex<BTreeMap<String, Arc<dyn EventHook>>>,
}

impl EventHandle {
    /// A handle on the store at `store`.
    pub fn new(store: Store) -> Self {
        Self {
            store: Some(store),
            target_error: None,
            instance_hooks: Mutex::new(BTreeMap::new()),
        }
    }

    /// Uses the store under the user's state directory. Without a state
    /// directory every verb fails with `event.store_unavailable`.
    pub fn from_url(url: &Url) -> Result<Self> {
        let host = url.host_str().unwrap_or("");
        let path = url.path();
        let target_error = (!host.is_empty() || !(path.is_empty() || path == "/")).then(|| {
            format!(
                "the event handle has no target: use event://.<verb>, not {}",
                url.as_str()
            )
        });
        Ok(Self {
            store: Store::default_base().map(Store::new),
            target_error,
            instance_hooks: Mutex::new(BTreeMap::new()),
        })
    }

    /// Registers a hook on this handle object only.
    pub fn register_hook(&self, hook: Arc<dyn EventHook>) {
        if let Ok(mut h) = self.instance_hooks.lock() {
            h.insert(hook.name().to_string(), hook);
        }
    }

    /// Removes a hook registered with [`register_hook`](Self::register_hook).
    pub fn remove_hook(&self, name: &str) {
        if let Ok(mut h) = self.instance_hooks.lock() {
            h.remove(name);
        }
    }

    fn instance_hook_names(&self) -> Vec<String> {
        self.instance_hooks
            .lock()
            .map(|h| h.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn store(&self) -> Result<&Store, Fail> {
        self.store.as_ref().ok_or_else(|| {
            Fail::unavailable(
                "there is no state directory for the event store (set HOME or \
                 XDG_STATE_HOME); nothing was done",
            )
        })
    }

    /// The hooks to run: the enabled built-in hooks, then this handle's
    /// own. An unreadable hook state file runs every built-in hook, with a
    /// warning.
    fn active_hooks(&self, store: &Store, warnings: &mut Vec<String>) -> Vec<Arc<dyn EventHook>> {
        let disabled = match store.disabled_hooks() {
            Ok(d) => d,
            Err(e) => {
                warnings.push(format!("{}; all built-in hooks ran", e.message));
                Default::default()
            }
        };
        let mut hooks: Vec<Arc<dyn EventHook>> = HOOK_NAMES
            .iter()
            .filter(|n| !disabled.contains(**n))
            .filter_map(|n| builtin_hook(n))
            .collect();
        if let Ok(h) = self.instance_hooks.lock() {
            hooks.extend(h.values().cloned());
        }
        hooks
    }

    /// Writes the approved help for `help`, `--help`, `-h`, `--help=<verb>`
    /// and `help(verb=<verb>)`; returns None for any other verb.
    fn check_and_display_help(
        &self,
        verb: &str,
        args: &Args,
        io: &mut IoStreams,
    ) -> Result<Option<Status>> {
        let help_verb = if help::HELP_ALIASES.contains(&verb) {
            args.get("verb").map(String::as_str)
        } else if let Some(v) = verb.strip_prefix("--help=") {
            Some(v)
        } else {
            return Ok(None);
        };
        write!(
            io.stdout,
            "{}",
            help::render_legacy("event", &EVENT_HELP, self.verbs(), help_verb)
        )?;
        Ok(Some(Status::ok()))
    }

    // ------------------------------------------------------------- emit --

    /// Stores the event described by `opts`; returns it with any warnings.
    fn emit(
        &self,
        opts: &EmitOpts,
        hook_out: &mut dyn Write,
    ) -> Result<(EventEnvelope, Vec<String>), Fail> {
        let store = self.store()?;
        let started = Instant::now();
        let now = now_unix_ms();
        let mode = if opts.wait_for_persist {
            "wait_for_persist"
        } else {
            "fire_and_forget"
        };
        let mut evt = EventEnvelope {
            id: generate_event_id(now),
            topic: opts.topic.clone(),
            timestamp_unix_ms: now,
            mode: mode.into(),
            mode_used: mode.into(),
            priority: opts.priority.into(),
            ttl_ms: opts.ttl_ms,
            key: opts.key.clone(),
            correlation_id: opts.correlation_id.clone(),
            causation_id: opts.causation_id.clone(),
            source: opts.source.clone(),
            tags: opts.tags.clone(),
            schema_version: opts.schema_version.clone(),
            summary: opts.summarize.then(|| summary_of(&opts.data, &opts.topic)),
            data: opts.data.clone(),
            backend: "state_file".into(),
            offset: None,
            raw: None,
            seq: None,
        };
        store.append(
            &mut evt,
            opts.wait_for_persist,
            deadline_after(started, opts.timeout_ms),
        )?;
        let mut warnings = Vec::new();
        for hook in self.active_hooks(store, &mut warnings) {
            let _ = hook.on_emit(&evt, hook_out);
        }
        Ok((evt, warnings))
    }

    fn handle_emit(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let result = parse_emit(args).and_then(|opts| {
            let (evt, warnings) = self.emit(&opts, io.stderr)?;
            Ok((opts.format, evt, warnings))
        });
        match result {
            Ok((OutputFormat::Json, evt, warnings)) => {
                let out = json!({
                    "ok": true,
                    "timestamp_unix_ms": evt.timestamp_unix_ms,
                    "event": evt.emit_json(),
                    "error": null,
                    "warnings": warnings,
                });
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&out)?)?;
                Ok(Status::ok())
            }
            Ok((OutputFormat::Text, evt, warnings)) => {
                write!(io.stdout, "{}", emit_text(&evt, &warnings)?)?;
                Ok(Status::ok())
            }
            Err(f) => {
                if failure_format(args) == OutputFormat::Json {
                    let out = json!({
                        "ok": false,
                        "timestamp_unix_ms": now_unix_ms(),
                        "event": null,
                        "error": f.json(),
                        "warnings": [],
                    });
                    writeln!(io.stdout, "{}", serde_json::to_string_pretty(&out)?)?;
                }
                Ok(f.status())
            }
        }
    }

    // -------------------------------------------------------- subscribe --

    /// The index a read starts at, given the cursor of this call (None on
    /// the first read).
    fn start_index(
        &self,
        store: &Store,
        opts: &SubscribeOpts,
        cursor: Option<u64>,
        high: u64,
    ) -> Result<u64, Fail> {
        if opts.offset == Offset::Next && (opts.group_commit() || cursor.is_none()) {
            // Group consumers that commit re-read the committed offset on
            // every read, so they share the work.
            let key = opts.commit_key().unwrap_or_default();
            return Ok(store.read_offsets()?.get(&key).copied().unwrap_or(0));
        }
        Ok(match (cursor, opts.offset) {
            (Some(c), _) => c,
            (None, Offset::Latest) => high,
            (None, Offset::Earliest) => 0,
            (None, Offset::At(n)) => n,
            (None, Offset::Next) => unreachable!("handled above"),
        })
    }

    #[allow(clippy::too_many_arguments)]
    /// One read: under the group's offsets lock (when it commits), selects
    /// the next batch, lets `deliver` use it, and then commits.
    fn read_once(
        &self,
        store: &Store,
        opts: &SubscribeOpts,
        cursor: &mut Option<u64>,
        limit: usize,
        deadline: Option<Instant>,
        warnings: &mut Vec<String>,
        deliver: &mut dyn FnMut(&Batch) -> Result<bool, Fail>,
    ) -> Result<(Batch, Option<u64>), Fail> {
        // A missing store has no events (and no room for the lock file);
        // if events appear meanwhile, read again under the lock.
        let (_lock, loaded) = loop {
            let lock = if opts.group_commit() && store.exists()? {
                Some(store.lock(OFFSETS_LOCK, LockKind::Exclusive, deadline)?)
            } else {
                None
            };
            let loaded = store.load(&opts.topic, deadline)?;
            if opts.group_commit() && lock.is_none() && !loaded.events.is_empty() {
                continue;
            }
            break (lock, loaded);
        };
        if let Some(w) = skipped_warning(loaded.skipped)
            && !warnings.contains(&w)
        {
            warnings.push(w);
        }
        let high = loaded.events.len() as u64;
        let start = self.start_index(store, opts, *cursor, high)?;
        let mut batch = select(&loaded.events, start, limit, &opts.filters, now_unix_ms());
        for e in &mut batch.events {
            if opts.include_raw {
                let mut stored = e.clone();
                stored.offset = None;
                e.raw = serde_json::to_value(&stored).ok();
            }
            if !opts.include_data {
                e.data = Value::Null;
            }
            if !opts.include_summary {
                e.summary = None;
            }
        }
        let commit = deliver(&batch)?;
        let mut committed = None;
        if commit
            && batch.next > batch.start
            && let Some(key) = opts.commit_key().filter(|_| opts.group_commit())
        {
            store.commit_offset(&key, batch.next)?;
            committed = Some(batch.next);
        }
        *cursor = Some(batch.next);
        Ok((batch, committed))
    }

    /// A one-shot subscribe (with or without wait).
    fn subscribe_once(&self, opts: &SubscribeOpts) -> Result<SubscribeResult, Fail> {
        let store = self.store()?;
        let started = Instant::now();
        let deadline = deadline_after(started, opts.timeout_ms);
        let wait_end = opts.wait.then(|| {
            let w = started + Duration::from_millis(opts.wait_timeout_ms);
            deadline.map_or(w, |d| d.min(w))
        });
        let mut warnings = Vec::new();
        let mut cursor = None;
        let mut committed_offset = None;
        let mut last_fp: Option<store::Fingerprint> = None;
        let mut last_batch = Batch::default();
        loop {
            let fp = store.fingerprint(&opts.topic, opts.offset == Offset::Next)?;
            if last_fp.as_ref() != Some(&fp) {
                let (batch, committed) = self.read_once(
                    store,
                    opts,
                    &mut cursor,
                    opts.limit,
                    deadline,
                    &mut warnings,
                    &mut |_| Ok(true),
                )?;
                committed_offset = committed.or(committed_offset);
                let waiting = wait_end.is_some_and(|w| Instant::now() < w);
                if !batch.events.is_empty() || !waiting {
                    return Ok(SubscribeResult {
                        timed_out: opts.wait && batch.events.is_empty(),
                        batch,
                        committed_offset,
                        warnings,
                    });
                }
                last_batch = batch;
                last_fp = Some(fp);
            }
            if wait_end.is_none_or(|w| Instant::now() >= w) {
                // Nothing new since the last (empty) read, and the wait is over.
                return Ok(SubscribeResult {
                    timed_out: true,
                    batch: last_batch,
                    committed_offset,
                    warnings,
                });
            }
            let left = wait_end.map_or(POLL, |w| w.saturating_duration_since(Instant::now()));
            std::thread::sleep(POLL.min(left));
        }
    }

    /// follow=true: prints each event as one line as it arrives, until
    /// max_events lines were printed or timeout_ms passes.
    fn subscribe_follow(&self, opts: &SubscribeOpts, io: &mut IoStreams) -> Result<(), Fail> {
        let store = self.store()?;
        let started = Instant::now();
        let deadline = deadline_after(started, opts.timeout_ms);
        let mut warnings = Vec::new();
        let mut cursor = None;
        let mut printed: u64 = 0;
        let mut last_fp: Option<store::Fingerprint> = None;
        let hooks = self.active_hooks(store, &mut warnings);
        for w in warnings.drain(..) {
            let _ = writeln!(io.stderr, "Warning: {w}");
        }
        loop {
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return Ok(());
            }
            let fp = store.fingerprint(&opts.topic, opts.offset == Offset::Next)?;
            if last_fp.as_ref() != Some(&fp) {
                let left = if opts.max_events > 0 {
                    (opts.max_events - printed).min(opts.limit as u64) as usize
                } else {
                    opts.limit
                };
                let stdout = &mut *io.stdout;
                let format = opts.format;
                let read = self.read_once(
                    store,
                    opts,
                    &mut cursor,
                    left,
                    deadline,
                    &mut warnings,
                    &mut |batch| {
                        for e in &batch.events {
                            let line = match format {
                                OutputFormat::Json => e.subscribe_json().to_string(),
                                OutputFormat::Text => e.text_line(),
                            };
                            writeln!(stdout, "{line}")
                                .and_then(|_| stdout.flush())
                                .map_err(|e| {
                                    Fail::new(
                                        exit::FAILED,
                                        "event.output_failed",
                                        format!("cannot write to stdout: {e}"),
                                    )
                                })?;
                        }
                        Ok(true)
                    },
                );
                let batch = match read {
                    Ok((batch, _)) => batch,
                    // The run time is over: a normal end.
                    Err(f) if f.code == "event.timeout" => return Ok(()),
                    Err(f) => return Err(f),
                };
                for w in warnings.drain(..) {
                    let _ = writeln!(io.stderr, "Warning: {w}");
                }
                if !batch.events.is_empty() {
                    for hook in &hooks {
                        let _ = hook.on_subscribe(&opts.topic, batch.events.len(), io.stderr);
                    }
                }
                printed += batch.events.len() as u64;
                if opts.max_events > 0 && printed >= opts.max_events {
                    return Ok(());
                }
                // More events may be waiting beyond this batch.
                if batch.next < batch.high {
                    continue;
                }
                last_fp = Some(fp);
            }
            let left = deadline.map_or(POLL, |d| d.saturating_duration_since(Instant::now()));
            std::thread::sleep(POLL.min(left));
        }
    }

    /// manual_commit_offset: commits the offset and reads nothing.
    fn manual_commit(&self, opts: &SubscribeOpts, offset: u64) -> Result<(), Fail> {
        let store = self.store()?;
        let deadline = deadline_after(Instant::now(), opts.timeout_ms);
        let _lock = store.lock(OFFSETS_LOCK, LockKind::Exclusive, deadline)?;
        store.commit_offset(&opts.commit_key().unwrap_or_default(), offset)
    }

    fn handle_subscribe(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let opts = match parse_subscribe(args) {
            Ok(o) => o,
            Err(f) => return self.subscribe_failure(args, None, &f, io),
        };
        if opts.follow {
            return Ok(match self.subscribe_follow(&opts, io) {
                Ok(()) => Status::ok(),
                Err(f) => f.status(),
            });
        }
        let base = json!({
            "topic": opts.topic,
            "group_id": opts.group_id,
            "consumer_id": opts.consumer_id,
        });
        if let Some(offset) = opts.manual_commit_offset {
            if let Err(f) = self.manual_commit(&opts, offset) {
                return self.subscribe_failure(args, Some(&opts), &f, io);
            }
            let mut out = base;
            for (k, v) in [
                ("ok", json!(true)),
                ("timestamp_unix_ms", json!(now_unix_ms())),
                ("effective_offset", json!("commit")),
                ("offset_start", Value::Null),
                ("offset_end", Value::Null),
                ("next_offset", Value::Null),
                ("high_watermark", Value::Null),
                ("timed_out", json!(false)),
                ("events_returned", json!(0)),
                ("events", json!([])),
                ("committed", json!(true)),
                ("committed_offset", json!(offset.to_string())),
                ("error", Value::Null),
                ("warnings", json!([])),
            ] {
                out[k] = v;
            }
            return self.print_subscribe(&opts, &out, io);
        }
        let result = match self.subscribe_once(&opts) {
            Ok(r) => r,
            Err(f) => return self.subscribe_failure(args, Some(&opts), &f, io),
        };
        let mut warnings = result.warnings;
        let n = result.batch.events.len();
        if let Ok(store) = self.store() {
            for hook in self.active_hooks(store, &mut warnings) {
                let _ = hook.on_subscribe(&opts.topic, n, io.stderr);
            }
        }
        let first = result.batch.events.first().and_then(|e| e.offset.clone());
        let last = result.batch.events.last().and_then(|e| e.offset.clone());
        let mut out = base;
        for (k, v) in [
            ("ok", json!(true)),
            ("timestamp_unix_ms", json!(now_unix_ms())),
            ("effective_offset", json!(opts.offset.label())),
            ("offset_start", json!(first)),
            ("offset_end", json!(last)),
            ("next_offset", json!(result.batch.next.to_string())),
            ("high_watermark", json!(result.batch.high.to_string())),
            ("timed_out", json!(result.timed_out)),
            ("events_returned", json!(n)),
            (
                "events",
                Value::Array(
                    result
                        .batch
                        .events
                        .iter()
                        .map(EventEnvelope::subscribe_json)
                        .collect(),
                ),
            ),
            ("committed", json!(result.committed_offset.is_some())),
            (
                "committed_offset",
                json!(result.committed_offset.map(|o| o.to_string())),
            ),
            ("error", Value::Null),
            ("warnings", json!(warnings)),
        ] {
            out[k] = v;
        }
        self.print_subscribe(&opts, &out, io)
    }

    fn print_subscribe(
        &self,
        opts: &SubscribeOpts,
        out: &Value,
        io: &mut IoStreams,
    ) -> Result<Status> {
        match opts.format {
            OutputFormat::Json => writeln!(io.stdout, "{}", serde_json::to_string_pretty(out)?)?,
            OutputFormat::Text => write!(io.stdout, "{}", subscribe_text(out))?,
        }
        Ok(Status::ok())
    }

    fn subscribe_failure(
        &self,
        args: &Args,
        opts: Option<&SubscribeOpts>,
        f: &Fail,
        io: &mut IoStreams,
    ) -> Result<Status> {
        let follow = opts.is_some_and(|o| o.follow);
        if !follow && failure_format(args) == OutputFormat::Json {
            let out = json!({
                "ok": false,
                "timestamp_unix_ms": now_unix_ms(),
                "topic": args.get("topic"),
                "group_id": args.get("group_id"),
                "consumer_id": args.get("consumer_id"),
                "effective_offset": opts.map(|o| o.offset.label()),
                "offset_start": null,
                "offset_end": null,
                "next_offset": null,
                "high_watermark": null,
                "timed_out": f.code == "event.timeout",
                "events_returned": 0,
                "events": [],
                "committed": false,
                "committed_offset": null,
                "error": f.json(),
                "warnings": [],
            });
            writeln!(io.stdout, "{}", serde_json::to_string_pretty(&out)?)?;
        }
        Ok(f.status())
    }

    // ------------------------------------------------------ list-topics --

    fn list_topics(&self, opts: &ListOpts) -> Result<Value, Fail> {
        let store = self.store()?;
        let deadline = deadline_after(Instant::now(), opts.timeout_ms);
        let files = store.topics(deadline)?;
        let now = now_unix_ms();
        let mut warnings = Vec::new();
        let skipped: usize = files.iter().map(|f| f.skipped).sum();
        warnings.extend(skipped_warning(skipped));
        let match_lower = opts.match_substr.as_ref().map(|m| m.to_lowercase());
        let selected: Vec<&store::TopicFile> = files
            .iter()
            .filter(|f| opts.include_hidden || !f.topic.starts_with('_'))
            .filter(|f| opts.prefix.as_ref().is_none_or(|p| f.topic.starts_with(p)))
            .filter(|f| {
                match_lower
                    .as_ref()
                    .is_none_or(|m| f.topic.to_lowercase().contains(m))
            })
            .collect();
        let total = selected.len();
        let truncated = total > opts.limit;
        if truncated {
            warnings.push(format!(
                "Result truncated to limit={}; refine filters or increase limit.",
                opts.limit
            ));
        }
        let topics: Vec<Value> = selected
            .iter()
            .take(opts.limit)
            .map(|f| {
                let live: Vec<&EventEnvelope> =
                    f.events.iter().filter(|e| !e.expired(now)).collect();
                topic_json(f, &live, opts)
            })
            .collect();
        Ok(json!({
            "ok": true,
            "timestamp_unix_ms": now,
            "filters": {
                "prefix": opts.prefix,
                "match": opts.match_substr,
                "sources": ["event"],
                "limit": opts.limit,
                "include_hidden": opts.include_hidden,
                "include_stats": opts.include_stats,
                "include_schema": opts.include_schema,
            },
            "topics_total": total,
            "topics_returned": topics.len(),
            "truncated": truncated,
            "topics": topics,
            "error": null,
            "warnings": warnings,
        }))
    }

    fn handle_list_topics(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let result = parse_list_topics(args).and_then(|o| Ok((self.list_topics(&o)?, o.format)));
        match result {
            Ok((out, OutputFormat::Json)) => {
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&out)?)?;
                Ok(Status::ok())
            }
            Ok((out, OutputFormat::Text)) => {
                write!(io.stdout, "{}", list_topics_text(&out))?;
                Ok(Status::ok())
            }
            Err(f) => {
                if failure_format(args) == OutputFormat::Json {
                    let out = json!({
                        "ok": false,
                        "timestamp_unix_ms": now_unix_ms(),
                        "filters": {},
                        "topics_total": 0,
                        "topics_returned": 0,
                        "truncated": false,
                        "topics": [],
                        "error": f.json(),
                        "warnings": [],
                    });
                    writeln!(io.stdout, "{}", serde_json::to_string_pretty(&out)?)?;
                }
                Ok(f.status())
            }
        }
    }

    // ------------------------------------------------------------ hooks --

    fn hooks_list(&self) -> Result<Value, Fail> {
        let disabled = self.store()?.disabled_hooks()?;
        let enabled: Vec<&str> = HOOK_NAMES
            .iter()
            .copied()
            .filter(|n| !disabled.contains(*n))
            .collect();
        let instance = self.instance_hook_names();
        // Names in the file that are not built-in hooks are not listed.
        let disabled: Vec<&str> = HOOK_NAMES
            .iter()
            .copied()
            .filter(|n| disabled.contains(*n))
            .collect();
        Ok(json!({
            "global_hooks": enabled,
            "instance_hooks": instance,
            "disabled": disabled,
            "total": enabled.len() + instance.len(),
        }))
    }

    fn hook_name(args: &Args) -> Result<&str, Fail> {
        let name = args
            .get("name")
            .ok_or_else(|| Fail::missing("name=<hook> is required (fs, log, mq or proc)"))?;
        if HOOK_NAMES.contains(&name.as_str()) {
            return Ok(name);
        }
        Err(Fail::new(
            exit::USAGE,
            "event.unknown_hook",
            format!(
                "unknown hook {name:?}{} (built-in hooks: fs, log, mq, proc)",
                suggest(name, HOOK_NAMES)
                    .map(|s| format!("; did you mean `{s}`?"))
                    .unwrap_or_default()
            ),
        ))
    }

    fn hooks_set(&self, verb: &str, args: &Args, enabled: bool) -> Result<Value, Fail> {
        check_args(verb, args)?;
        let name = Self::hook_name(args)?;
        let changed =
            self.store()?
                .set_hook_enabled(name, enabled, Some(Instant::now() + HOOK_LOCK_WAIT))?;
        Ok(if enabled {
            json!({"hook": name, "enabled": true, "changed": changed})
        } else {
            json!({"hook": name, "disabled": true, "changed": changed})
        })
    }

    fn handle_hooks(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let result = match verb {
            "hooks.list" => check_args(verb, args).and_then(|_| self.hooks_list()),
            "hooks.enable" => self.hooks_set(verb, args, true),
            _ => self.hooks_set(verb, args, false),
        };
        match result {
            Ok(out) => {
                writeln!(io.stdout, "{out}")?;
                Ok(Status::ok())
            }
            Err(f) => Ok(f.status()),
        }
    }
}

// ===========================================================================
// Text output
// ===========================================================================

fn emit_text(evt: &EventEnvelope, warnings: &[String]) -> Result<String> {
    let mut s = String::new();
    s.push_str("Event Emitted\n=============\n\n");
    s.push_str(&format!("ID        : {}\n", evt.id));
    s.push_str(&format!("Topic     : {}\n", evt.topic));
    s.push_str(&format!("Backend   : {}\n", evt.backend));
    s.push_str(&format!("Mode      : {}\n", evt.mode));
    s.push_str(&format!("Priority  : {}\n", evt.priority));
    if let Some(ttl) = evt.ttl_ms {
        s.push_str(&format!("TTL (ms)  : {ttl}\n"));
    }
    if let Some(src) = &evt.source {
        s.push_str(&format!("Source    : {src}\n"));
    }
    if !evt.tags.is_empty() {
        s.push_str(&format!("Tags      : {}\n", evt.tags.join(", ")));
    }
    if let Some(c) = &evt.correlation_id {
        s.push_str(&format!("Correlation ID : {c}\n"));
    }
    if let Some(summary) = &evt.summary {
        s.push_str(&format!("\nSummary   : {summary}\n"));
    }
    s.push_str("\nData:\n");
    for line in serde_json::to_string_pretty(&evt.data)?.lines() {
        s.push_str(&format!("  {line}\n"));
    }
    push_warnings(&mut s, warnings.iter().map(String::as_str));
    Ok(s)
}

fn push_warnings<'a>(s: &mut String, warnings: impl Iterator<Item = &'a str>) {
    let warnings: Vec<&str> = warnings.collect();
    s.push_str("\nWarnings:\n");
    if warnings.is_empty() {
        s.push_str("  (none)\n");
    }
    for w in warnings {
        s.push_str(&format!("  - {w}\n"));
    }
}

fn json_warnings(v: &Value) -> impl Iterator<Item = &str> {
    v["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

fn subscribe_text(out: &Value) -> String {
    let mut s = String::new();
    s.push_str("Event Subscription Result\n=========================\n\n");
    s.push_str(&format!(
        "Topic       : {}\n",
        out["topic"].as_str().unwrap_or("")
    ));
    if let Some(g) = out["group_id"].as_str() {
        s.push_str(&format!("Group ID    : {g}\n"));
    }
    if let Some(c) = out["consumer_id"].as_str() {
        s.push_str(&format!("Consumer ID : {c}\n"));
    }
    s.push_str(&format!(
        "Offset      : {}\n",
        out["effective_offset"].as_str().unwrap_or("")
    ));
    if let Some(c) = out["committed_offset"].as_str() {
        s.push_str(&format!("Committed   : {c}\n"));
    }
    s.push_str(&format!(
        "Returned    : {} event(s)\n",
        out["events_returned"].as_u64().unwrap_or(0)
    ));
    s.push_str(&format!(
        "Timed Out   : {}\n",
        if out["timed_out"].as_bool() == Some(true) {
            "yes"
        } else {
            "no"
        }
    ));
    let events: Vec<EventEnvelope> = out["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| serde_json::from_value(e.clone()).ok())
        .collect();
    if !events.is_empty() {
        s.push_str("\nEvents:\n");
        for e in &events {
            s.push_str(&format!("  {}\n", e.text_line()));
        }
    }
    push_warnings(&mut s, json_warnings(out));
    s
}

fn list_topics_text(out: &Value) -> String {
    let mut s = String::new();
    s.push_str("Event Topics\n============\n\n");
    let topics = out["topics"].as_array().cloned().unwrap_or_default();
    s.push_str(&format!(
        "Topics ({} total, {} shown):\n",
        out["topics_total"].as_u64().unwrap_or(0),
        topics.len()
    ));
    for t in &topics {
        s.push_str(&format!("  {}", t["name"].as_str().unwrap_or("")));
        if let Some(n) = t["stats"]["approx_message_count"].as_u64() {
            s.push_str(&format!("  events={n}"));
        }
        if let Some(ms) = t["stats"]["last_event_unix_ms"].as_i64()
            && let Some(dt) = chrono::DateTime::from_timestamp_millis(ms)
        {
            s.push_str(&format!("  last={}", dt.format("%Y-%m-%dT%H:%M:%SZ")));
        }
        if let Some(fields) = t["schema"]["fields"].as_array() {
            let names: Vec<&str> = fields.iter().filter_map(|f| f["name"].as_str()).collect();
            s.push_str(&format!("  fields={}", names.join(",")));
        }
        s.push('\n');
    }
    push_warnings(&mut s, json_warnings(out));
    s
}

// ===========================================================================
// Dispatch
// ===========================================================================

impl Handle for EventHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &[
            "emit",
            "subscribe",
            "list-topics",
            "hooks.list",
            "hooks.enable",
            "hooks.disable",
            "help",
            "--help",
            "-h",
        ]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&EVENT_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        if let Some(status) = self.check_and_display_help(verb, args, io)? {
            return Ok(status);
        }
        if verb_args(verb).is_none() {
            let verbs = [
                "emit",
                "subscribe",
                "list-topics",
                "hooks.list",
                "hooks.enable",
                "hooks.disable",
            ];
            return Ok(Status::coded(
                exit::USAGE,
                "event.unknown_verb",
                format!(
                    "unknown verb {verb:?} for the event handle{}",
                    suggest(verb, &verbs)
                        .map(|s| format!(" (did you mean `{s}`?)"))
                        .unwrap_or_default()
                ),
            ));
        }
        if let Some(msg) = &self.target_error {
            return Ok(Status::coded(exit::USAGE, "event.invalid_target", msg));
        }
        match verb {
            "emit" => self.handle_emit(args, io),
            "subscribe" => self.handle_subscribe(args, io),
            "list-topics" => self.handle_list_topics(args, io),
            _ => self.handle_hooks(verb, args, io),
        }
    }
}
