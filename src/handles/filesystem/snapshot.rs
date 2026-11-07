//! `snapshot://`: full local copies of a file or directory, with diff, list
//! and restore.
//!
//! Storage layout (under `$XDG_STATE_HOME/resh/snapshots`):
//!
//! ```text
//! <group>/<name>/meta.json   metadata (id, name, target, kind, ...)
//! <group>/<name>/content     the copied file, or the copied directory tree
//! ```
//!
//! `<group>` is the absolute target path with every character other than
//! letters, digits, `.`, `-` and `_` replaced by `_`, truncated to 120
//! characters. Two targets can share a group; every lookup therefore also
//! checks the `target` recorded in `meta.json`.
//!
//! Snapshots written before `kind` was recorded ("legacy") keep a file
//! snapshot in `content` and a directory snapshot directly in `<name>/`
//! next to `meta.json`; they are still read.

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};
use url::Url;
use uuid::Uuid;
use walkdir::WalkDir;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::{Status, error_json, error_line},
};

/// Placeholder target used for an in-URL help request.
const HELP_PATH: &str = "--help";

/// Arguments each verb accepts; anything else is refused (exit 2). The
/// help usage of each verb lists exactly these (tested).
pub const LS_OPTIONS: &[&str] = &[
    "limit",
    "name_prefix",
    "since",
    "until",
    "state",
    "tag",
    "json_pretty",
    "timeout_ms",
];
pub const DIFF_OPTIONS: &[&str] = &["from", "to", "path", "format", "timeout_ms"];
pub const CREATE_OPTIONS: &[&str] = &[
    "name",
    "description",
    "ttl",
    "tags",
    "if_exists",
    "backend",
    "timeout_ms",
];
pub const RESTORE_OPTIONS: &[&str] = &["target", "force", "dry_run", "mode", "timeout_ms"];

/// Exit code for invalid usage (unknown argument, bad value): nothing was
/// done.
pub const EXIT_USAGE: i32 = 2;

/// Exit code for a verb stopped at its `timeout_ms` deadline (the
/// project-wide timeout code). Nothing is left behind: partial copies are
/// removed before exiting.
pub const EXIT_TIMEOUT: i32 = 124;

/// Longest accepted snapshot name (the storage group truncates at 120).
const MAX_NAME_LEN: usize = 120;

/// Read/write buffer for file copies and hashing; the deadline is checked
/// between chunks.
const CHUNK: usize = 1 << 20;

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("snapshot", |u| Ok(Box::new(SnapshotHandle::from_url(u)?)));
}

/// Metadata for `resh snapshot --help` and `resh snapshot <verb> --help`.
static SNAPSHOT_HELP: HandleHelp = HandleHelp {
    description: "The snapshot handle saves full local copies of a file or directory, \
        compares them with each other or with the live filesystem, lists them, and \
        restores them. Snapshots are stored under the user state directory, for example \
        ~/.local/state/resh/snapshots, grouped by the absolute path of their target. The \
        URL names the target path for create, diff, and ls, as in snapshot:///srv/app, \
        and the snapshot name or ID for restore, as in snapshot://backup-v1.",
    usage: "resh snapshot://<target-path-or-snapshot-name>.<verb>[(key=value,...)]",
    verbs: &[
        VerbHelp {
            name: "ls",
            definition: "Lists the snapshots taken of a target path, newest first, with \
                their IDs, names, creation times, states, tags, and descriptions, as JSON.",
            detail: Some(VerbDetail {
                usage: "resh snapshot://<target-path>.ls [limit=<n>] [name_prefix=<prefix>]\n  \
                    [since=<rfc3339>] [until=<rfc3339>] [state=<state>] [tag=<tag>]\n  \
                    [json_pretty=true|false] [timeout_ms=<ms>]",
                example: "resh --json-pretty snapshot:///srv/app.ls limit=5",
                example_output: Some(
                    r#"[
  {
    "backend": "local",
    "created_at": "2026-10-16T09:12:44.512309876+00:00",
    "description": "nightly",
    "expires_at": "2026-10-23T09:12:44.512309876+00:00",
    "id": "73265a09-2b27-49d7-a5ab-49315543eacb",
    "name": "backup-v1",
    "size_bytes": 5120,
    "state": "complete",
    "tags": [
      "nightly"
    ],
    "target": "/srv/app"
  }
]

Shown with --json-pretty. Snapshots made by create have state complete.
Expired snapshots (expires_at in the past) are never listed; ls deletes
this target's expired snapshots and notes each on stderr. A relative
target is resolved against the working directory. An unknown target prints
an empty array. Exit 2 on an invalid argument, 1 when the
store cannot be read, 124 on timeout."#,
                ),
            }),
        },
        VerbHelp {
            name: "diff",
            definition: "Compares two snapshots of a target, or a snapshot and the live \
                filesystem, and reports added, removed, modified, and unchanged files.",
            detail: Some(VerbDetail {
                usage: "resh snapshot://<target-path>.diff [from=<snapshot>|live]\n  \
                    [to=<snapshot>|live] [path=<subpath>] [format=json|summary]\n  \
                    [timeout_ms=<ms>]",
                example: "resh snapshot:///srv/app.diff from=backup-v1 to=live format=summary",
                example_output: Some(
                    r#"snapshot: /srv/app
from: backup-v1 (snapshot)
to:   live (live)
root: /srv/app
path: /

added: 1
removed: 0
modified: 2
unchanged: 14

A snapshot is named by name or ID; an expired one is not found. An
omitted from or to means live; at least one must name a snapshot. The
default format=json prints name, from, to, from_kind, to_kind, root, path,
a summary object, and an entries array with per-file from and to details.
Exit 2 on an invalid argument, 1 when a snapshot or the target is not
found or cannot be read, 124 on timeout."#,
                ),
            }),
        },
        VerbHelp {
            name: "create",
            definition: "Copies a file or directory into a new named snapshot with an \
                optional description, tags, and expiry time, and reports its ID and storage path.",
            detail: Some(VerbDetail {
                usage: "resh snapshot://<target-path>.create name=<name>\n  \
                    [description=<text>] [ttl=<seconds>] [tags=<tag>,...]\n  \
                    [if_exists=error|skip|overwrite] [backend=local] [timeout_ms=<ms>]",
                example: "resh --json-pretty snapshot:///srv/app.create name=backup-v1 ttl=86400",
                example_output: Some(
                    r#"{
  "backend": "local",
  "created_at": "2026-10-16T09:12:44.512309876+00:00",
  "expires_at": "2026-10-17T09:12:44.512309876+00:00",
  "id": "73265a09-2b27-49d7-a5ab-49315543eacb",
  "name": "backup-v1",
  "ok": true,
  "path": "/home/alice/.local/state/resh/snapshots/_srv_app/backup-v1",
  "skipped": false,
  "target": "/srv/app"
}

Shown with --json-pretty. Names use letters, digits, '.', '-' and '_' and
do not start with '.' or '-'. Without ttl, expires_at is null. After
expires_at the snapshot is hidden from ls, diff and restore, and the next
create or ls of the target deletes it. With if_exists=skip and an existing
snapshot, skipped is true.
Exit 2 on an invalid argument, 1 when the snapshot exists or the copy
fails, 124 on timeout (no snapshot is left behind in either case)."#,
                ),
            }),
        },
        VerbHelp {
            name: "restore",
            definition: "Copies a named snapshot back to a target path, replacing existing \
                content only when force is true, or lists the planned actions on a dry run.",
            detail: Some(VerbDetail {
                usage: "resh snapshot://<snapshot-name-or-id>.restore target=<path>\n  \
                    [force=true|false] [dry_run=true|false] [mode=overwrite]\n  \
                    [timeout_ms=<ms>]",
                example: "resh --json-pretty snapshot://backup-v1.restore target=/srv/app force=true",
                example_output: Some(
                    r#"{
  "mode": "overwrite",
  "snapshot": "backup-v1",
  "status": "ok",
  "target": "/srv/app"
}

Shown with --json-pretty. With dry_run=true the result has dry_run,
force, and an actions list instead of status. An expired snapshot is not
restored (not found, with a message saying it expired). Exit 2 on an
invalid or ambiguous argument, 1 when the snapshot is not found, the
target exists without force, or the copy fails, 124 on timeout (the
target is left unchanged)."#,
                ),
            }),
        },
    ],
};

// ---------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------

/// Every error code the handle can emit, as reported (`snapshot.<code>`);
/// each is documented in docs/Filesystem_Storage/snapshot.md. A `Failure`
/// holds the name after the `snapshot.` prefix.
pub const ERROR_CODES: &[&str] = &[
    "snapshot.missing_argument",
    "snapshot.invalid_argument",
    "snapshot.unsupported_backend",
    "snapshot.unsupported_mode",
    "snapshot.invalid_target",
    "snapshot.ambiguous_snapshot",
    "snapshot.unknown_verb",
    "snapshot.target_not_found",
    "snapshot.snapshot_exists",
    "snapshot.name_conflict",
    "snapshot.snapshot_not_found",
    "snapshot.metadata_not_found",
    "snapshot.metadata_invalid",
    "snapshot.content_not_found",
    "snapshot.target_exists",
    "snapshot.target_not_empty",
    "snapshot.copy_failed",
    "snapshot.write_failed",
    "snapshot.backup_failed",
    "snapshot.restore_failed",
    "snapshot.read_failed",
    "snapshot.timeout",
];

/// A verb failure: exit code, stable error code (without the `snapshot.`
/// prefix) and message, plus optional extra fields for the JSON result.
#[derive(Debug)]
struct Failure {
    exit: i32,
    code: &'static str,
    message: String,
    extra: Map<String, Value>,
}

impl Failure {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            exit: exit_for(code),
            code,
            message: message.into(),
            extra: Map::new(),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::new("invalid_argument", message)
    }

    fn timeout(what: &str) -> Self {
        Self::new(
            "timeout",
            format!("{what} did not finish within timeout_ms; nothing was changed"),
        )
    }

    fn with(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.extra.insert(key.to_string(), value.into());
        self
    }
}

/// The exit status for an error code: 2 for invalid usage (nothing was
/// done), 124 for a timeout, 1 for every other failure.
fn exit_for(code: &str) -> i32 {
    match code {
        "invalid_argument"
        | "missing_argument"
        | "unsupported_backend"
        | "unsupported_mode"
        | "ambiguous_snapshot"
        | "unknown_verb"
        | "invalid_target" => EXIT_USAGE,
        "timeout" => EXIT_TIMEOUT,
        _ => 1,
    }
}

type VResult<T> = std::result::Result<T, Failure>;

/// Error from a copy, walk or hash step.
#[derive(Debug)]
enum OpError {
    Timeout,
    Io(String),
}

type OpResult<T> = std::result::Result<T, OpError>;

fn op_io(context: impl std::fmt::Display, e: impl std::fmt::Display) -> OpError {
    OpError::Io(format!("{context}: {e}"))
}

impl OpError {
    /// The verb failure for this error: `timeout`, or the given I/O code.
    fn into_failure(self, what: &str, code: &'static str) -> Failure {
        match self {
            OpError::Timeout => Failure::timeout(what),
            OpError::Io(m) => Failure::new(code, m),
        }
    }
}

/// Writes the failure (the standard `Error: [snapshot.<code>] <message>`
/// line on stderr, and a JSON result with `"error": {"code", "message"}` on
/// stdout) and returns its status.
fn emit_failure(io: &mut IoStreams, f: Failure) -> Result<Status> {
    let code = format!("snapshot.{}", f.code);
    debug_assert!(ERROR_CODES.contains(&code.as_str()), "{code} not listed");
    writeln!(io.stderr, "{}", error_line(&code, &f.message))?;
    let mut obj = Map::new();
    obj.insert("ok".into(), Value::Bool(false));
    obj.insert("error".into(), error_json(&code, &f.message));
    for (k, v) in f.extra {
        obj.insert(k, v);
    }
    writeln!(io.stdout, "{}", Value::Object(obj))?;
    Ok(Status::coded(f.exit, &code, &f.message))
}

// ---------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------

fn check_known_args(args: &Args, allowed: &[&str], verb: &str) -> VResult<()> {
    let mut unknown: Vec<&str> = args
        .keys()
        .map(String::as_str)
        .filter(|k| !allowed.contains(k))
        .collect();
    unknown.sort_unstable();
    if let Some(k) = unknown.first() {
        let hint = suggest(k, allowed)
            .map(|s| format!("; did you mean {s:?}?"))
            .unwrap_or_default();
        return Err(Failure::invalid(format!(
            "unknown argument {k:?} for snapshot {verb}{hint} (accepted: {}); nothing was done",
            allowed.join(", ")
        ))
        .with("argument", *k));
    }
    Ok(())
}

/// The accepted option closest to `key` (edit distance at most 2, or one
/// is a prefix of the other), for a "did you mean" hint.
fn suggest<'a>(key: &str, allowed: &[&'a str]) -> Option<&'a str> {
    let key = key.to_ascii_lowercase().replace('-', "_");
    allowed
        .iter()
        .map(|a| (edit_distance(&key, a), *a))
        .filter(|(d, a)| {
            *d <= 2 || (key.len() >= 3 && (a.starts_with(key.as_str()) || key.starts_with(a)))
        })
        .min_by_key(|(d, _)| *d)
        .map(|(_, a)| a)
}

fn edit_distance(a: &str, b: &str) -> usize {
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

fn bool_arg(args: &Args, key: &str) -> VResult<Option<bool>> {
    crate::core::lenient::bool_arg(args, key)
        .map_err(|e| Failure::invalid(e.to_string()).with("argument", key))
}

/// A snapshot name: letters, digits, `.`, `-` and `_`, at most 120
/// characters, not starting with `.` or `-`.
fn validate_name(name: &str, what: &str) -> VResult<()> {
    let bad = |why: &str| {
        Err(Failure::invalid(format!("invalid {what} {name:?}: {why}")).with("argument", what))
    };
    if name.is_empty() {
        return bad("must not be empty");
    }
    if name.len() > MAX_NAME_LEN {
        return bad("longer than 120 characters");
    }
    if name.starts_with('-') || name.starts_with('.') {
        return bad("must not start with '-' or '.'");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return bad("only letters, digits, '.', '-' and '_' are allowed");
    }
    Ok(())
}

/// The `timeout_ms` deadline. Absent or `0` means no limit.
#[derive(Clone, Copy, Debug)]
struct Deadline(Option<Instant>);

impl Deadline {
    fn from_args(args: &Args) -> VResult<Self> {
        match args.get("timeout_ms") {
            None => Ok(Self(None)),
            Some(v) => match v.trim().parse::<u64>() {
                Ok(0) => Ok(Self(None)),
                Ok(ms) => Ok(Self(Instant::now().checked_add(Duration::from_millis(ms)))),
                Err(_) => Err(Failure::invalid(format!(
                    "invalid timeout_ms {v:?}: must be a non-negative integer of milliseconds"
                ))
                .with("argument", "timeout_ms")),
            },
        }
    }

    /// A deadline that has already passed.
    #[cfg(test)]
    fn expired() -> Self {
        Self(Some(Instant::now()))
    }

    fn check(&self) -> OpResult<()> {
        match self.0 {
            Some(end) if Instant::now() >= end => Err(OpError::Timeout),
            _ => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/// Root of the snapshot store.
fn store_base() -> PathBuf {
    #[cfg(test)]
    if let Some(base) = test_store::get() {
        return base;
    }
    match dirs::state_dir() {
        Some(dir) => dir.join("resh").join("snapshots"),
        None => PathBuf::from("/tmp").join("resh").join("snapshots"),
    }
}

fn sanitize_path_component(s: &str) -> String {
    let mut result: String = s
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    result.truncate(120);
    if result.is_empty() {
        "_".to_string()
    } else {
        result
    }
}

fn group_dir(base: &Path, target: &Path) -> PathBuf {
    base.join(sanitize_path_component(&target.to_string_lossy()))
}

/// The contents of `meta.json`. Everything but `id` is optional so that
/// metadata written by older versions (or by hand) still loads.
#[derive(Debug, Clone, Deserialize, Serialize)]
struct StoredMeta {
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    backend: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    size_bytes: Option<u64>,
}

impl StoredMeta {
    fn created(&self) -> Option<DateTime<Utc>> {
        self.created_at
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc))
    }

    fn expires(&self) -> Option<DateTime<Utc>> {
        self.expires_at
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc))
    }

    /// True when `expires_at` is set, valid and not after `now`. A missing
    /// or unparseable `expires_at` never expires.
    fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires().is_some_and(|e| e <= now)
    }

    fn expired_note(&self) -> String {
        format!(
            "snapshot {} expired at {}",
            self.name.as_deref().unwrap_or(&self.id),
            self.expires_at.as_deref().unwrap_or("?")
        )
    }

    /// True when the metadata belongs to `target` (or records no target).
    fn is_for(&self, target: &Path) -> bool {
        self.target
            .as_deref()
            .is_none_or(|t| Path::new(t) == target)
    }
}

fn read_meta(snapshot_dir: &Path) -> std::result::Result<StoredMeta, String> {
    let file = snapshot_dir.join("meta.json");
    let text = fs::read_to_string(&file).map_err(|e| format!("cannot read {file:?}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("invalid metadata in {file:?}: {e}"))
}

/// A snapshot found on disk.
#[derive(Debug, Clone)]
struct Found {
    dir: PathBuf,
    meta: StoredMeta,
}

/// Where a snapshot's content lives.
#[derive(Debug, Clone)]
enum Content {
    File(PathBuf),
    /// A directory tree; `legacy` trees sit next to `meta.json`, which is
    /// then not part of the content.
    Dir {
        root: PathBuf,
        legacy: bool,
    },
}

impl Found {
    fn label(&self) -> String {
        self.meta
            .name
            .clone()
            .unwrap_or_else(|| self.meta.id.clone())
    }

    fn content(&self) -> VResult<Content> {
        let content = self.dir.join("content");
        let missing = || {
            Failure::new(
                "content_not_found",
                format!("snapshot content not found: {}", self.label()),
            )
            .with("snapshot", self.label())
        };
        match self.meta.kind.as_deref() {
            Some("file") if content.is_file() => Ok(Content::File(content)),
            Some("dir") if content.is_dir() => Ok(Content::Dir {
                root: content,
                legacy: false,
            }),
            Some("file") | Some("dir") => Err(missing()),
            Some(other) => Err(Failure::new(
                "metadata_invalid",
                format!("snapshot {} has unknown kind {other:?}", self.label()),
            )),
            None if content.is_file() => Ok(Content::File(content)),
            None if self.dir.is_dir() => Ok(Content::Dir {
                root: self.dir.clone(),
                legacy: true,
            }),
            None => Err(missing()),
        }
    }
}

/// Every readable snapshot in `group` whose recorded target is `target`.
/// Unreadable entries are reported in `warnings` and skipped.
fn snapshots_in_group(
    group: &Path,
    target: Option<&Path>,
    deadline: Deadline,
    warnings: &mut Vec<String>,
) -> VResult<Vec<Found>> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(group) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => {
            return Err(Failure::new(
                "read_failed",
                format!("cannot read snapshot group {group:?}: {e}"),
            ));
        }
    };
    for entry in entries {
        deadline
            .check()
            .map_err(|e| e.into_failure("listing snapshots", "read_failed"))?;
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warnings.push(format!("cannot read an entry of {group:?}: {e}"));
                continue;
            }
        };
        let fname = entry.file_name().to_string_lossy().into_owned();
        // Temporary directories of creates in progress start with '.'.
        if fname.starts_with('.') || !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let dir = entry.path();
        if !dir.join("meta.json").exists() {
            warnings.push(format!("skipping {fname}: meta.json not found"));
            continue;
        }
        match read_meta(&dir) {
            Ok(meta) => {
                if target.is_none_or(|t| meta.is_for(t)) {
                    out.push(Found { dir, meta });
                }
            }
            Err(e) => warnings.push(format!("skipping {fname}: {e}")),
        }
    }
    Ok(out)
}

/// The current time; tests can pin it (see `test_store::set_now`).
fn now() -> DateTime<Utc> {
    #[cfg(test)]
    if let Some(t) = test_store::now() {
        return t;
    }
    Utc::now()
}

/// Splits snapshots into (live, expired) at `now`.
fn split_expired(all: Vec<Found>, now: DateTime<Utc>) -> (Vec<Found>, Vec<Found>) {
    all.into_iter().partition(|f| !f.meta.is_expired(now))
}

/// Deletes the expired snapshots of `target` in its group (ttl enforced
/// on access). Best effort: every problem becomes a warning. Only a real
/// directory (not a symbolic link) directly inside a real group directory
/// of the store, whose own `meta.json` has an `expires_at` in the past and
/// names `target`, is deleted; the metadata is read again right before
/// deleting. Returns the notes to report.
fn purge_expired(base: &Path, target: &Path, now: DateTime<Utc>, warnings: &mut Vec<String>) {
    let group = group_dir(base, target);
    let real_dir = |p: &Path| fs::symlink_metadata(p).is_ok_and(|m| m.is_dir());
    if !real_dir(base) || !real_dir(&group) {
        return;
    }
    let mut ignored = Vec::new();
    let all = match snapshots_in_group(&group, Some(target), Deadline(None), &mut ignored) {
        Ok(a) => a,
        Err(f) => {
            warnings.push(format!(
                "could not check for expired snapshots: {}",
                f.message
            ));
            return;
        }
    };
    for f in all.into_iter().filter(|f| f.meta.is_expired(now)) {
        let note = f.meta.expired_note();
        if f.dir.parent() != Some(group.as_path()) || !real_dir(&f.dir) {
            warnings.push(format!(
                "{note}; not deleted: unexpected location {}",
                f.dir.display()
            ));
            continue;
        }
        // Re-check the metadata in place: never delete on stale data.
        match read_meta(&f.dir) {
            Ok(m) if m.is_expired(now) && m.is_for(target) && m.id == f.meta.id => {}
            _ => continue,
        }
        // Move it out of the way first so a partial delete never leaves a
        // half-removed snapshot visible under its name.
        let doomed = group.join(format!(".expired-{}", Uuid::new_v4()));
        if let Err(e) = fs::rename(&f.dir, &doomed) {
            warnings.push(format!("{note}; hidden, but could not delete it: {e}"));
            continue;
        }
        // remove_dir_all does not follow symbolic links.
        match fs::remove_dir_all(&doomed) {
            Ok(()) => warnings.push(format!("{note}; deleted")),
            Err(e) => warnings.push(format!(
                "{note}; moved to {} but could not delete it: {e}",
                doomed.display()
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Copying
// ---------------------------------------------------------------------------

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Applies owner (when running as root), mode and times of `meta` to `dst`.
fn apply_metadata(dst: &Path, meta: &fs::Metadata) -> OpResult<()> {
    use std::os::unix::fs::MetadataExt;
    if is_root() {
        std::os::unix::fs::chown(dst, Some(meta.uid()), Some(meta.gid()))
            .map_err(|e| op_io(format!("cannot set owner of {dst:?}"), e))?;
    }
    fs::set_permissions(dst, meta.permissions())
        .map_err(|e| op_io(format!("cannot set mode of {dst:?}"), e))?;
    filetime::set_file_times(
        dst,
        filetime::FileTime::from_last_access_time(meta),
        filetime::FileTime::from_last_modification_time(meta),
    )
    .map_err(|e| op_io(format!("cannot set times of {dst:?}"), e))
}

/// Copies one regular file to a new path, in chunks so the deadline can
/// stop a large copy, then applies the source metadata.
fn copy_file(src: &Path, dst: &Path, deadline: Deadline) -> OpResult<u64> {
    deadline.check()?;
    let meta = fs::metadata(src).map_err(|e| op_io(format!("cannot stat {src:?}"), e))?;
    let mut r = fs::File::open(src).map_err(|e| op_io(format!("cannot read {src:?}"), e))?;
    let mut w = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)
        .map_err(|e| op_io(format!("cannot create {dst:?}"), e))?;
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        deadline.check()?;
        let n = r
            .read(&mut buf)
            .map_err(|e| op_io(format!("cannot read {src:?}"), e))?;
        if n == 0 {
            break;
        }
        w.write_all(&buf[..n])
            .map_err(|e| op_io(format!("cannot write {dst:?}"), e))?;
        total += n as u64;
    }
    drop(w);
    apply_metadata(dst, &meta)?;
    Ok(total)
}

/// Totals of a copy.
#[derive(Debug, Default)]
struct CopyStats {
    bytes: u64,
    /// Entries that are neither regular files nor directories (sockets,
    /// FIFOs, devices), relative to the source root.
    skipped: Vec<String>,
}

/// Copies directory `src` to the new directory `dst`, following symbolic
/// links. Directory modes and times are applied after their contents.
/// `exclude` names directories (by device and inode) that are not copied,
/// and `skip_top_meta` leaves out a top-level `meta.json` (legacy layout).
fn copy_tree(
    src: &Path,
    dst: &Path,
    exclude: Option<(u64, u64)>,
    skip_top_meta: bool,
    deadline: Deadline,
    stats: &mut CopyStats,
) -> OpResult<()> {
    use std::os::unix::fs::MetadataExt;
    deadline.check()?;
    let root_meta = fs::metadata(src).map_err(|e| op_io(format!("cannot stat {src:?}"), e))?;
    fs::create_dir(dst).map_err(|e| op_io(format!("cannot create {dst:?}"), e))?;
    let mut dirs: Vec<(PathBuf, fs::Metadata)> = Vec::new();

    let walker = WalkDir::new(src)
        .follow_links(true)
        .min_depth(1)
        .into_iter()
        .filter_entry(|e| {
            if skip_top_meta && e.depth() == 1 && e.file_name() == "meta.json" {
                return false;
            }
            if let Some((dev, ino)) = exclude {
                if e.file_type().is_dir() {
                    if let Ok(m) = e.metadata() {
                        if m.dev() == dev && m.ino() == ino {
                            return false;
                        }
                    }
                }
            }
            true
        });

    for entry in walker {
        deadline.check()?;
        let entry = entry.map_err(|e| {
            let at = e
                .path()
                .map(|p| format!("{p:?}"))
                .unwrap_or_else(|| format!("{src:?}"));
            op_io(format!("cannot read {at}"), e)
        })?;
        let rel = entry
            .path()
            .strip_prefix(src)
            .map_err(|e| op_io(format!("unexpected path {:?}", entry.path()), e))?;
        let out = dst.join(rel);
        let ft = entry.file_type();
        if ft.is_dir() {
            let meta = entry
                .metadata()
                .map_err(|e| op_io(format!("cannot stat {:?}", entry.path()), e))?;
            fs::create_dir(&out).map_err(|e| op_io(format!("cannot create {out:?}"), e))?;
            dirs.push((out, meta));
        } else if ft.is_file() {
            stats.bytes += copy_file(entry.path(), &out, deadline)?;
        } else {
            stats.skipped.push(rel.to_string_lossy().into_owned());
        }
    }

    for (path, meta) in dirs.iter().rev() {
        apply_metadata(path, meta)?;
    }
    apply_metadata(dst, &root_meta)
}

/// Creates `dir` and missing parents. The snapshot store holds copies of
/// configuration and possibly secrets, so the directories resh owns there
/// (store, groups, snapshots) are owner-only (0700); an existing directory
/// is tightened to 0700 as well.
fn private_dir_all(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

/// Removes a file or directory tree; best effort for cleanup paths.
fn remove_any(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Removes a temporary path when dropped, unless disarmed.
struct TempGuard(Option<PathBuf>);

impl TempGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            // Cleanup of our own temporary copy; a failure here cannot be
            // reported more usefully than the error already being returned.
            let _ = remove_any(&p);
        }
    }
}

// ---------------------------------------------------------------------------
// Diff types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileTypeKind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryStatus {
    Added,
    Removed,
    Modified,
    Unchanged,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileInfo {
    pub exists: bool,
    pub file_type: Option<FileTypeKind>,
    pub size: Option<u64>,
    pub mtime: Option<String>,
    pub mode: Option<String>,
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub file_type: FileTypeKind,
    pub status: EntryStatus,
    pub from: FileInfo,
    pub to: FileInfo,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiffSummary {
    pub added: u32,
    pub removed: u32,
    pub modified: u32,
    pub unchanged: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    pub name: String,
    pub from: String,
    pub to: String,
    pub from_kind: String,
    pub to_kind: String,
    pub root: String,
    pub path: String,
    pub summary: DiffSummary,
    pub entries: Vec<DiffEntry>,
}

/// One side of a diff.
struct Tree {
    kind: &'static str,
    /// Snapshot id for snapshot sides (to detect a snapshot compared with
    /// itself).
    id: Option<String>,
    source: TreeSource,
}

enum TreeSource {
    /// A single file, reported under `key`.
    File {
        path: PathBuf,
        key: String,
    },
    Dir {
        root: PathBuf,
        legacy: bool,
    },
}

fn hash_file(path: &Path, deadline: Deadline) -> OpResult<String> {
    let mut file = fs::File::open(path).map_err(|e| op_io(format!("cannot read {path:?}"), e))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        deadline.check()?;
        let n = file
            .read(&mut buf)
            .map_err(|e| op_io(format!("cannot read {path:?}"), e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn file_info(
    path: &Path,
    meta: &fs::Metadata,
    deadline: Deadline,
    warnings: &mut Vec<String>,
) -> OpResult<FileInfo> {
    use std::os::unix::fs::PermissionsExt;
    let file_type = if meta.is_file() {
        FileTypeKind::File
    } else if meta.is_dir() {
        FileTypeKind::Dir
    } else if meta.file_type().is_symlink() {
        FileTypeKind::Symlink
    } else {
        FileTypeKind::Other
    };
    let mtime = meta
        .modified()
        .ok()
        .map(|t| DateTime::<Utc>::from(t).to_rfc3339());
    let hash = if meta.is_file() {
        match hash_file(path, deadline) {
            Ok(h) => Some(h),
            Err(OpError::Timeout) => return Err(OpError::Timeout),
            Err(OpError::Io(m)) => {
                warnings.push(format!("{m}; compared by size, mode and mtime"));
                None
            }
        }
    } else {
        None
    };
    Ok(FileInfo {
        exists: true,
        file_type: Some(file_type),
        size: meta.is_file().then(|| meta.len()),
        mtime,
        mode: Some(format!("{:o}", meta.permissions().mode() & 0o7777)),
        hash,
    })
}

fn collect_tree(
    tree: &Tree,
    subpath: &str,
    deadline: Deadline,
    warnings: &mut Vec<String>,
) -> OpResult<BTreeMap<String, FileInfo>> {
    let mut entries = BTreeMap::new();
    let (root, legacy) = match &tree.source {
        TreeSource::File { path, key } => {
            let meta = fs::metadata(path).map_err(|e| op_io(format!("cannot stat {path:?}"), e))?;
            entries.insert(key.clone(), file_info(path, &meta, deadline, warnings)?);
            return Ok(entries);
        }
        TreeSource::Dir { root, legacy } => (root, *legacy),
    };
    let rel = subpath.trim_start_matches('/');
    let search_root = if rel.is_empty() {
        root.clone()
    } else {
        root.join(rel)
    };
    let meta = match fs::metadata(&search_root) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(entries),
        Err(e) => return Err(op_io(format!("cannot stat {search_root:?}"), e)),
    };
    if !meta.is_dir() {
        let key = search_root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        entries.insert(key, file_info(&search_root, &meta, deadline, warnings)?);
        return Ok(entries);
    }
    // In a legacy layout only the snapshot's own top-level meta.json is
    // metadata; with a subpath the walk is already below it.
    let skip_meta = legacy && rel.is_empty();
    let walker = WalkDir::new(&search_root)
        .follow_links(true)
        .min_depth(1)
        .into_iter()
        .filter_entry(|e| !(skip_meta && e.depth() == 1 && e.file_name() == "meta.json"));
    for entry in walker {
        deadline.check()?;
        let entry = entry.map_err(|e| {
            let at = e
                .path()
                .map(|p| format!("{p:?}"))
                .unwrap_or_else(|| format!("{search_root:?}"));
            op_io(format!("cannot read {at}"), e)
        })?;
        let meta = entry
            .metadata()
            .map_err(|e| op_io(format!("cannot stat {:?}", entry.path()), e))?;
        let key = entry
            .path()
            .strip_prefix(&search_root)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        entries.insert(key, file_info(entry.path(), &meta, deadline, warnings)?);
    }
    Ok(entries)
}

fn files_differ(a: &FileInfo, b: &FileInfo) -> bool {
    if a.exists != b.exists || a.file_type != b.file_type || a.mode != b.mode {
        return true;
    }
    if a.file_type == Some(FileTypeKind::Dir) {
        // A directory's own mtime changes with any entry below it; those
        // entries are reported themselves.
        return false;
    }
    if a.size != b.size {
        return true;
    }
    match (&a.hash, &b.hash) {
        (Some(x), Some(y)) => x != y,
        _ => a.mtime != b.mtime,
    }
}

fn compare_entries(
    a: &BTreeMap<String, FileInfo>,
    b: &BTreeMap<String, FileInfo>,
) -> (DiffSummary, Vec<DiffEntry>) {
    let mut summary = DiffSummary::default();
    let mut entries = Vec::new();
    let mut paths: Vec<&String> = a.keys().chain(b.keys()).collect();
    paths.sort();
    paths.dedup();
    for path in paths {
        let (from, to) = (a.get(path), b.get(path));
        let (status, ft) = match (from, to) {
            (None, Some(t)) => {
                summary.added += 1;
                (EntryStatus::Added, t.file_type.clone())
            }
            (Some(f), None) => {
                summary.removed += 1;
                (EntryStatus::Removed, f.file_type.clone())
            }
            (Some(f), Some(t)) => {
                if files_differ(f, t) {
                    summary.modified += 1;
                    (EntryStatus::Modified, t.file_type.clone())
                } else {
                    summary.unchanged += 1;
                    continue;
                }
            }
            (None, None) => continue,
        };
        entries.push(DiffEntry {
            path: path.clone(),
            file_type: ft.unwrap_or(FileTypeKind::Other),
            status,
            from: from.cloned().unwrap_or_default(),
            to: to.cloned().unwrap_or_default(),
        });
    }
    (summary, entries)
}

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

pub struct SnapshotHandle {
    target: PathBuf,
}

impl SnapshotHandle {
    pub fn from_url(url: &Url) -> Result<Self> {
        // A host-position target keeps the rest of its path, so
        // snapshot://dir/app is dir/app rather than dir.
        let path = url.path();
        let path_str = match url.host_str().filter(|h| !h.is_empty()) {
            Some(host) if path.is_empty() || path == "/" => host.to_string(),
            Some(host) => format!("{}{}", host, path),
            None => path.to_string(),
        };

        let decoded = match percent_decode_str(&path_str).decode_utf8() {
            Ok(d) => d.into_owned(),
            Err(e) => bail!(
                "[snapshot.invalid_target] invalid UTF-8 in snapshot URL path {path_str:?}: {e}"
            ),
        };

        // In-URL help (snapshot://--help, snapshot://-h). Exact match only,
        // so names such as pre-hotfix are ordinary targets.
        if crate::core::help::is_help_flag(&decoded) {
            return Ok(Self {
                target: PathBuf::from(HELP_PATH),
            });
        }

        Ok(Self {
            target: normalize_path(Path::new(&decoded)),
        })
    }

    /// The URL target as an absolute, normalized path (relative targets are
    /// resolved against the working directory).
    fn absolute_target(&self) -> VResult<PathBuf> {
        absolute(&self.target)
    }

    // -- create -------------------------------------------------------------

    fn create(&self, args: &Args, warnings: &mut Vec<String>) -> VResult<Value> {
        check_known_args(args, CREATE_OPTIONS, "create")?;
        let deadline = Deadline::from_args(args)?;

        let name = match args.get("name").map(|s| s.trim()) {
            Some(n) if !n.is_empty() => n,
            _ => {
                return Err(
                    Failure::new("missing_argument", "missing required argument: name")
                        .with("argument", "name"),
                );
            }
        };
        validate_name(name, "name")?;

        let backend = args.get("backend").map(String::as_str).unwrap_or("local");
        if backend != "local" {
            return Err(Failure::new(
                "unsupported_backend",
                format!("unsupported backend: {backend} (only local is supported)"),
            ));
        }

        let if_exists = match args.get("if_exists").map(String::as_str) {
            None | Some("error") => "error",
            Some("skip") => "skip",
            Some("overwrite") => "overwrite",
            Some(other) => {
                return Err(Failure::invalid(format!(
                    "invalid if_exists {other:?} (must be error, skip or overwrite)"
                ))
                .with("argument", "if_exists"));
            }
        };

        let created_at = now();
        let expires_at = match args.get("ttl") {
            None => None,
            Some(v) => {
                let bad = || {
                    Failure::invalid(format!(
                        "invalid ttl {v:?}: must be a non-negative integer of seconds"
                    ))
                    .with("argument", "ttl")
                };
                let secs: u64 = v.trim().parse().map_err(|_| bad())?;
                let delta = i64::try_from(secs)
                    .ok()
                    .and_then(chrono::Duration::try_seconds)
                    .ok_or_else(bad)?;
                Some(created_at.checked_add_signed(delta).ok_or_else(bad)?)
            }
        };

        let tags: Vec<String> = match args.get("tags") {
            None => Vec::new(),
            Some(v) => {
                let tags: Vec<String> = v.split(',').map(|t| t.trim().to_string()).collect();
                if tags
                    .iter()
                    .any(|t| t.is_empty() || t.chars().any(char::is_control))
                {
                    return Err(Failure::invalid(format!(
                        "invalid tags {v:?}: a comma-separated list of non-empty tags"
                    ))
                    .with("argument", "tags"));
                }
                tags
            }
        };
        let description = args.get("description").cloned();

        let target = self.absolute_target()?;
        let target_meta = match fs::metadata(&target) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Failure::new(
                    "target_not_found",
                    format!("target path does not exist: {}", target.display()),
                )
                .with("target", target.to_string_lossy()));
            }
            Err(e) => {
                return Err(Failure::new(
                    "read_failed",
                    format!("cannot read target {}: {e}", target.display()),
                ));
            }
        };
        if !target_meta.is_file() && !target_meta.is_dir() {
            return Err(Failure::new(
                "invalid_target",
                format!(
                    "target is neither a file nor a directory: {}",
                    target.display()
                ),
            ));
        }

        let base = store_base();
        private_dir_all(&base).map_err(|e| {
            Failure::new(
                "write_failed",
                format!("cannot create snapshot store {}: {e}", base.display()),
            )
        })?;
        let canon_base = fs::canonicalize(&base).unwrap_or_else(|_| base.clone());
        let canon_target = fs::canonicalize(&target).unwrap_or_else(|_| target.clone());
        if canon_target.starts_with(&canon_base) {
            return Err(Failure::new(
                "invalid_target",
                format!(
                    "target {} is inside the snapshot store {}",
                    target.display(),
                    base.display()
                ),
            ));
        }

        // ttl is enforced on access: drop this target's expired snapshots.
        purge_expired(&base, &target, created_at, warnings);
        let group = group_dir(&base, &target);
        let final_dir = group.join(name);
        let mut replace_existing = false;
        if fs::symlink_metadata(&final_dir).is_ok() {
            match read_meta(&final_dir) {
                Ok(meta) if !meta.is_for(&target) => {
                    return Err(Failure::new(
                        "name_conflict",
                        format!(
                            "snapshot name {name} is already used by target {} in the same \
                             storage group; choose another name",
                            meta.target.as_deref().unwrap_or("?")
                        ),
                    ));
                }
                // An expired snapshot that could not be purged is replaced.
                Ok(meta) if meta.is_expired(created_at) => replace_existing = true,
                Ok(meta) => match if_exists {
                    "skip" => {
                        return Ok(json!({
                            "ok": true,
                            "backend": meta.backend.as_deref().unwrap_or("local"),
                            "id": meta.id,
                            "name": meta.name.as_deref().unwrap_or(name),
                            "target": meta.target.as_deref().unwrap_or(&target.to_string_lossy()),
                            "path": final_dir.to_string_lossy(),
                            "created_at": meta.created_at,
                            "expires_at": meta.expires_at,
                            "skipped": true,
                        }));
                    }
                    "overwrite" => replace_existing = true,
                    _ => {
                        return Err(Failure::new(
                            "snapshot_exists",
                            format!(
                                "snapshot already exists: {name} (use if_exists=skip or overwrite)"
                            ),
                        ));
                    }
                },
                Err(e) => match if_exists {
                    "overwrite" => replace_existing = true,
                    _ => {
                        return Err(Failure::new(
                            "snapshot_exists",
                            format!(
                                "snapshot directory {} exists but is unreadable ({e}); \
                                 use if_exists=overwrite to replace it",
                                final_dir.display()
                            ),
                        ));
                    }
                },
            }
        }

        private_dir_all(&group).map_err(|e| {
            Failure::new(
                "write_failed",
                format!("cannot create {}: {e}", group.display()),
            )
        })?;
        let temp = group.join(format!(".{name}.tmp-{}", Uuid::new_v4()));
        private_dir_all(&temp).map_err(|e| {
            Failure::new(
                "write_failed",
                format!("cannot create {}: {e}", temp.display()),
            )
        })?;
        let mut guard = TempGuard(Some(temp.clone()));

        let exclude = {
            use std::os::unix::fs::MetadataExt;
            fs::metadata(&base).ok().map(|m| (m.dev(), m.ino()))
        };
        let mut stats = CopyStats::default();
        let content = temp.join("content");
        let kind = if target_meta.is_file() {
            stats.bytes = copy_file(&target, &content, deadline)
                .map_err(|e| e.into_failure("create", "copy_failed"))?;
            "file"
        } else {
            copy_tree(&target, &content, exclude, false, deadline, &mut stats)
                .map_err(|e| e.into_failure("create", "copy_failed"))?;
            "dir"
        };
        for s in &stats.skipped {
            warnings.push(format!(
                "skipped {s}: not a regular file or directory (not copied)"
            ));
        }

        let id = Uuid::new_v4().to_string();
        let meta = json!({
            "id": id,
            "backend": "local",
            "target": target.to_string_lossy(),
            "name": name,
            "kind": kind,
            "state": "complete",
            "tags": tags,
            "size_bytes": stats.bytes,
            "created_at": created_at.to_rfc3339(),
            "expires_at": expires_at.map(|d| d.to_rfc3339()),
            "path": final_dir.to_string_lossy(),
            "description": description,
        });
        let meta_text = serde_json::to_string_pretty(&meta)
            .map_err(|e| Failure::new("write_failed", format!("cannot encode metadata: {e}")))?;
        {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(temp.join("meta.json"))
                .and_then(|mut f| f.write_all(meta_text.as_bytes()))
                .map_err(|e| Failure::new("write_failed", format!("cannot write metadata: {e}")))?;
        }
        deadline
            .check()
            .map_err(|e| e.into_failure("create", "copy_failed"))?;

        // Swap into place. An existing snapshot is moved aside first and
        // only removed once the new one is in place.
        let old = if replace_existing {
            let old = group.join(format!(".{name}.old-{}", Uuid::new_v4()));
            fs::rename(&final_dir, &old).map_err(|e| {
                Failure::new(
                    "write_failed",
                    format!("cannot move existing snapshot aside: {e}"),
                )
            })?;
            Some(old)
        } else {
            None
        };
        if let Err(e) = fs::rename(&temp, &final_dir) {
            if let Some(old) = &old {
                if let Err(e2) = fs::rename(old, &final_dir) {
                    warnings.push(format!(
                        "could not put the previous snapshot back from {}: {e2}",
                        old.display()
                    ));
                }
            }
            return Err(Failure::new(
                "write_failed",
                format!("cannot move snapshot into place: {e}"),
            ));
        }
        guard.disarm();
        if let Some(old) = old {
            if let Err(e) = remove_any(&old) {
                warnings.push(format!(
                    "could not remove the replaced snapshot {}: {e}",
                    old.display()
                ));
            }
        }

        Ok(json!({
            "ok": true,
            "backend": "local",
            "id": id,
            "name": name,
            "target": target.to_string_lossy(),
            "path": final_dir.to_string_lossy(),
            "created_at": created_at.to_rfc3339(),
            "expires_at": expires_at.map(|d| d.to_rfc3339()),
            "skipped": false,
        }))
    }

    // -- diff ---------------------------------------------------------------

    /// Resolves `from`/`to`: `live`, or a snapshot of the target by id or
    /// name.
    fn resolve_tree(
        &self,
        which: &str,
        target: &Path,
        deadline: Deadline,
        warnings: &mut Vec<String>,
    ) -> VResult<Tree> {
        let file_key = || {
            target
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| target.to_string_lossy().into_owned())
        };
        if which == "live" {
            let meta = match fs::metadata(target) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(Failure::new(
                        "target_not_found",
                        format!("live target path does not exist: {}", target.display()),
                    ));
                }
                Err(e) => {
                    return Err(Failure::new(
                        "read_failed",
                        format!("cannot read live target {}: {e}", target.display()),
                    ));
                }
            };
            let source = if meta.is_dir() {
                TreeSource::Dir {
                    root: target.to_path_buf(),
                    legacy: false,
                }
            } else {
                TreeSource::File {
                    path: target.to_path_buf(),
                    key: file_key(),
                }
            };
            return Ok(Tree {
                kind: "live",
                id: None,
                source,
            });
        }

        let group = group_dir(&store_base(), target);
        let all = snapshots_in_group(&group, Some(target), deadline, warnings)?;
        let (live, expired) = split_expired(all, now());
        let pick = |list: &[Found]| -> Option<Found> {
            list.iter()
                .find(|f| f.meta.id == which)
                .or_else(|| {
                    list.iter().find(|f| {
                        f.dir.file_name().is_some_and(|n| n == which)
                            || f.meta.name.as_deref() == Some(which)
                    })
                })
                .cloned()
        };
        let found = match pick(&live) {
            Some(f) => f,
            None => {
                // An expired snapshot is hidden; say so instead of a bare
                // "not found".
                let msg = match pick(&expired) {
                    Some(e) => format!(
                        "{}; expired snapshots are not used (target {})",
                        e.meta.expired_note(),
                        target.display()
                    ),
                    None => format!(
                        "snapshot '{which}' not found by id or name for target {}",
                        target.display()
                    ),
                };
                return Err(Failure::new("snapshot_not_found", msg).with("snapshot", which));
            }
        };
        let source = match found.content()? {
            Content::File(path) => TreeSource::File {
                path,
                key: file_key(),
            },
            Content::Dir { root, legacy } => TreeSource::Dir { root, legacy },
        };
        Ok(Tree {
            kind: "snapshot",
            id: Some(found.meta.id.clone()),
            source,
        })
    }

    fn diff(&self, args: &Args, warnings: &mut Vec<String>) -> VResult<String> {
        check_known_args(args, DIFF_OPTIONS, "diff")?;
        let deadline = Deadline::from_args(args)?;
        let from = args
            .get("from")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("live");
        let to = args
            .get("to")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("live");
        let format = args.get("format").map(String::as_str).unwrap_or("json");
        if format != "json" && format != "summary" {
            return Err(Failure::invalid(format!(
                "unknown format: {format} (must be json or summary)"
            ))
            .with("argument", "format"));
        }
        if from == "live" && to == "live" {
            return Err(Failure::invalid(
                "nothing to compare: name a snapshot in from or to (both sides are live)",
            ));
        }
        let path_filter = args.get("path").map(|s| s.trim()).unwrap_or("/");
        let path_filter = if path_filter.is_empty() {
            "/"
        } else {
            path_filter
        };
        if Path::new(path_filter)
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(Failure::invalid(format!(
                "invalid path {path_filter:?}: must stay inside the target ('..' is not allowed)"
            ))
            .with("argument", "path"));
        }

        let target = self.absolute_target()?;
        let from_tree = self.resolve_tree(from, &target, deadline, warnings)?;
        let to_tree = self.resolve_tree(to, &target, deadline, warnings)?;
        if from_tree.id.is_some() && from_tree.id == to_tree.id {
            return Err(Failure::invalid(
                "cannot diff a snapshot against itself (from and to are the same snapshot)",
            ));
        }
        let restricted = path_filter.trim_start_matches('/') != "";
        if restricted
            && [&from_tree, &to_tree]
                .iter()
                .any(|t| matches!(t.source, TreeSource::File { .. }))
        {
            return Err(Failure::invalid(
                "path= applies only to directory targets; this target is a file",
            )
            .with("argument", "path"));
        }

        let from_entries = collect_tree(&from_tree, path_filter, deadline, warnings)
            .map_err(|e| e.into_failure("diff", "read_failed"))?;
        let to_entries = collect_tree(&to_tree, path_filter, deadline, warnings)
            .map_err(|e| e.into_failure("diff", "read_failed"))?;
        let (summary, entries) = compare_entries(&from_entries, &to_entries);
        let result = DiffResult {
            name: target.to_string_lossy().into_owned(),
            from: from.to_string(),
            to: to.to_string(),
            from_kind: from_tree.kind.to_string(),
            to_kind: to_tree.kind.to_string(),
            root: target.to_string_lossy().into_owned(),
            path: path_filter.to_string(),
            summary,
            entries,
        };

        if format == "json" {
            serde_json::to_string(&result)
                .map(|s| s + "\n")
                .map_err(|e| Failure::new("write_failed", format!("cannot encode result: {e}")))
        } else {
            Ok(format!(
                "snapshot: {}\nfrom: {} ({})\nto:   {} ({})\nroot: {}\npath: {}\n\n\
                 added: {}\nremoved: {}\nmodified: {}\nunchanged: {}\n",
                result.name,
                result.from,
                result.from_kind,
                result.to,
                result.to_kind,
                result.root,
                result.path,
                result.summary.added,
                result.summary.removed,
                result.summary.modified,
                result.summary.unchanged
            ))
        }
    }

    // -- ls -----------------------------------------------------------------

    fn ls(&self, args: &Args, warnings: &mut Vec<String>) -> VResult<String> {
        check_known_args(args, LS_OPTIONS, "ls")?;
        let deadline = Deadline::from_args(args)?;
        let limit = match args.get("limit") {
            None => None,
            Some(v) => match v.trim().parse::<usize>() {
                Ok(n) if n > 0 => Some(n),
                _ => {
                    return Err(Failure::invalid(format!(
                        "invalid limit {v:?}: must be a positive integer"
                    ))
                    .with("argument", "limit"));
                }
            },
        };
        let time_arg = |key: &str| -> VResult<Option<DateTime<Utc>>> {
            match args.get(key) {
                None => Ok(None),
                Some(v) => DateTime::parse_from_rfc3339(v.trim())
                    .map(|d| Some(d.with_timezone(&Utc)))
                    .map_err(|e| {
                        Failure::invalid(format!(
                            "invalid {key} {v:?}: expected an RFC 3339 timestamp ({e})"
                        ))
                        .with("argument", key)
                    }),
            }
        };
        let since = time_arg("since")?;
        let until = time_arg("until")?;
        let pretty = bool_arg(args, "json_pretty")?.unwrap_or(false);
        let state = args.get("state").map(|s| s.to_lowercase());
        let tag = args.get("tag").map(|s| s.to_lowercase());
        let prefix = args.get("name_prefix");

        let target = self.absolute_target()?;
        let group = group_dir(&store_base(), &target);
        // ttl is enforced on access: delete this target's expired
        // snapshots (best effort), and never list an expired one.
        let at = now();
        purge_expired(&store_base(), &target, at, warnings);
        let (mut list, _) = split_expired(
            snapshots_in_group(&group, Some(&target), deadline, warnings)?,
            at,
        );

        list.retain(|f| {
            let m = &f.meta;
            let created = m.created();
            state
                .as_ref()
                .is_none_or(|s| m.state.as_deref().unwrap_or("unknown").to_lowercase() == *s)
                && tag.as_ref().is_none_or(|t| {
                    m.tags
                        .as_ref()
                        .is_some_and(|tags| tags.iter().any(|x| x.to_lowercase() == *t))
                })
                && since.is_none_or(|s| created.is_some_and(|c| c >= s))
                && until.is_none_or(|u| created.is_some_and(|c| c <= u))
                && prefix
                    .is_none_or(|p| m.name.as_deref().is_some_and(|n| n.starts_with(p.as_str())))
        });
        list.sort_by(|a, b| match (a.meta.created(), b.meta.created()) {
            (Some(x), Some(y)) => y.cmp(&x).then_with(|| a.meta.id.cmp(&b.meta.id)),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.meta.id.cmp(&b.meta.id),
        });
        if let Some(n) = limit {
            list.truncate(n);
        }

        let out: Vec<Value> = list
            .iter()
            .map(|f| {
                let m = &f.meta;
                let mut o = Map::new();
                o.insert("id".into(), json!(m.id));
                let opt = |o: &mut Map<String, Value>, k: &str, v: &Option<String>| {
                    if let Some(v) = v {
                        o.insert(k.into(), json!(v));
                    }
                };
                opt(&mut o, "name", &m.name);
                opt(&mut o, "created_at", &m.created_at);
                opt(&mut o, "backend", &m.backend);
                opt(&mut o, "target", &m.target);
                opt(&mut o, "state", &m.state);
                opt(&mut o, "expires_at", &m.expires_at);
                if let Some(s) = m.size_bytes {
                    o.insert("size_bytes".into(), json!(s));
                }
                if let Some(t) = m.tags.as_ref().filter(|t| !t.is_empty()) {
                    o.insert("tags".into(), json!(t));
                }
                opt(&mut o, "description", &m.description);
                Value::Object(o)
            })
            .collect();
        let text = if pretty {
            serde_json::to_string_pretty(&out)
        } else {
            serde_json::to_string(&out)
        };
        text.map(|s| s + "\n")
            .map_err(|e| Failure::new("write_failed", format!("cannot encode result: {e}")))
    }

    // -- restore ------------------------------------------------------------

    /// Finds the snapshot named (or with the id) `name` across all targets.
    fn find_for_restore(
        &self,
        name: &str,
        deadline: Deadline,
        warnings: &mut Vec<String>,
    ) -> VResult<Found> {
        let base = store_base();
        let not_found = || {
            Failure::new("snapshot_not_found", format!("snapshot not found: {name}"))
                .with("snapshot", name)
        };
        let groups = match fs::read_dir(&base) {
            Ok(g) => g,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(not_found()),
            Err(e) => {
                return Err(Failure::new(
                    "snapshot_not_found",
                    format!("cannot read snapshot store {}: {e}", base.display()),
                ));
            }
        };
        let mut by_name = Vec::new();
        let mut by_id = Vec::new();
        let mut broken: Option<Failure> = None;
        for g in groups.flatten() {
            if !g.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let group = g.path();
            let candidate = group.join(name);
            if candidate.is_dir() {
                if !candidate.join("meta.json").exists() {
                    broken = Some(Failure::new(
                        "metadata_not_found",
                        format!("snapshot metadata not found: {name}"),
                    ));
                } else {
                    match read_meta(&candidate) {
                        Ok(meta) => by_name.push(Found {
                            dir: candidate,
                            meta,
                        }),
                        Err(e) => {
                            broken = Some(Failure::new(
                                "metadata_invalid",
                                format!("snapshot {name} has unusable metadata: {e}"),
                            ))
                        }
                    }
                }
            }
            for f in snapshots_in_group(&group, None, deadline, &mut Vec::new())? {
                if f.meta.id == name {
                    by_id.push(f);
                }
            }
        }
        let at = now();
        let (by_name, expired_name) = split_expired(by_name, at);
        let (by_id, expired_id) = split_expired(by_id, at);
        let matches = if by_name.is_empty() { by_id } else { by_name };
        if !matches.is_empty() {
            for e in expired_name.iter().chain(expired_id.iter()) {
                warnings.push(format!("ignoring {}", e.meta.expired_note()));
            }
        } else {
            if let Some(e) = expired_name.first().or(expired_id.first()) {
                return Err(Failure::new(
                    "snapshot_not_found",
                    format!(
                        "snapshot not found: {name} ({}; expired snapshots cannot be restored)",
                        e.meta.expired_note()
                    ),
                )
                .with("snapshot", name)
                .with("expired", true));
            }
        }
        match matches.len() {
            0 => Err(broken
                .map(|f| f.with("snapshot", name))
                .unwrap_or_else(not_found)),
            1 => matches.into_iter().next().ok_or_else(not_found),
            _ => {
                let choices: Vec<Value> = matches
                    .iter()
                    .map(|f| json!({"id": f.meta.id, "target": f.meta.target}))
                    .collect();
                Err(Failure::new(
                    "ambiguous_snapshot",
                    format!(
                        "snapshot name {name} exists for {} targets; restore by id instead \
                         (snapshot://<id>.restore)",
                        matches.len()
                    ),
                )
                .with("snapshot", name)
                .with("matches", Value::Array(choices)))
            }
        }
    }

    fn restore(&self, args: &Args, warnings: &mut Vec<String>) -> VResult<String> {
        check_known_args(args, RESTORE_OPTIONS, "restore")?;
        let deadline = Deadline::from_args(args)?;
        let target_arg = match args.get("target").map(|s| s.trim()) {
            Some(t) if !t.is_empty() => t.to_string(),
            _ => {
                return Err(
                    Failure::new("missing_argument", "missing required argument: target")
                        .with("argument", "target"),
                );
            }
        };
        let force = bool_arg(args, "force")?.unwrap_or(false);
        let dry_run = bool_arg(args, "dry_run")?.unwrap_or(false);
        let mode = args.get("mode").map(String::as_str).unwrap_or("overwrite");
        if mode != "overwrite" {
            return Err(Failure::new(
                "unsupported_mode",
                format!("unsupported mode: '{mode}' (only 'overwrite' is supported)"),
            )
            .with("mode", mode));
        }
        let snapshot_name = self.target.to_string_lossy().into_owned();
        validate_name(&snapshot_name, "snapshot name")?;

        let target = absolute(Path::new(&target_arg))?;
        let parent = match target.parent() {
            Some(p) => p.to_path_buf(),
            None => {
                return Err(Failure::new(
                    "invalid_target",
                    format!("target path has no parent directory: {}", target.display()),
                )
                .with("target", target_arg.as_str()));
            }
        };

        let found = self.find_for_restore(&snapshot_name, deadline, warnings)?;
        let content = found.content()?;

        // Refuse a target that is, or contains, the snapshot itself.
        let canon_snap = fs::canonicalize(&found.dir).unwrap_or_else(|_| found.dir.clone());
        let canon_target = fs::canonicalize(&target).unwrap_or_else(|_| target.clone());
        if canon_snap.starts_with(&canon_target) || canon_target.starts_with(&canon_snap) {
            return Err(Failure::new(
                "invalid_target",
                format!(
                    "target {} overlaps the snapshot store entry {}",
                    target.display(),
                    found.dir.display()
                ),
            )
            .with("target", target_arg.as_str()));
        }

        let existing = match fs::symlink_metadata(&target) {
            Ok(m) => Some(m),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(Failure::new(
                    "read_failed",
                    format!("cannot inspect target {}: {e}", target.display()),
                )
                .with("target", target_arg.as_str()));
            }
        };
        if let Some(m) = &existing {
            if m.is_dir() {
                let empty = fs::read_dir(&target)
                    .map(|mut d| d.next().is_none())
                    .map_err(|e| {
                        Failure::new(
                            "copy_failed",
                            format!("cannot read target directory {}: {e}", target.display()),
                        )
                    })?;
                if !empty && !force {
                    return Err(Failure::new("target_not_empty",
                        format!(
                            "target directory exists and is not empty (use force=true to overwrite): {}",
                            target.display()
                        ),
                    )
                    .with("target", target_arg.as_str()));
                }
            } else if !force {
                return Err(Failure::new(
                    "target_exists",
                    format!(
                        "target file exists (use force=true to overwrite): {}",
                        target.display()
                    ),
                )
                .with("target", target_arg.as_str()));
            }
        }

        let source = match &content {
            Content::File(p) => p.clone(),
            Content::Dir { root, .. } => root.clone(),
        };
        if dry_run {
            let mut actions = Vec::new();
            if let Some(m) = &existing {
                if m.is_dir() {
                    actions.push(format!("DELETE DIRECTORY {:?}", target));
                } else {
                    actions.push(format!("DELETE FILE {:?}", target));
                }
            }
            actions.push(format!("COPY {:?} -> {:?}", source, target));
            let v = json!({
                "dry_run": true,
                "snapshot": snapshot_name,
                "target": target_arg,
                "mode": mode,
                "force": force,
                "actions": actions,
            });
            return serde_json::to_string_pretty(&v)
                .map(|s| s + "\n")
                .map_err(|e| Failure::new("write_failed", format!("cannot encode result: {e}")));
        }

        fs::create_dir_all(&parent).map_err(|e| {
            Failure::new(
                "copy_failed",
                format!("cannot create parent directory {}: {e}", parent.display()),
            )
        })?;
        let temp = parent.join(format!(".resh-restore-{}.tmp", Uuid::new_v4()));
        let mut guard = TempGuard(Some(temp.clone()));
        let mut stats = CopyStats::default();
        match &content {
            Content::File(p) => copy_file(p, &temp, deadline).map(|_| ()),
            Content::Dir { root, legacy } => {
                copy_tree(root, &temp, None, *legacy, deadline, &mut stats)
            }
        }
        .map_err(|e| {
            e.into_failure("restore", "copy_failed")
                .with("snapshot", snapshot_name.as_str())
        })?;
        for s in &stats.skipped {
            warnings.push(format!("skipped {s}: not a regular file or directory"));
        }
        deadline
            .check()
            .map_err(|e| e.into_failure("restore", "copy_failed"))?;

        if existing.is_some() {
            let backup = parent.join(format!(".resh-backup-{}.bak", Uuid::new_v4()));
            fs::rename(&target, &backup).map_err(|e| {
                Failure::new(
                    "backup_failed",
                    format!("failed to move existing target aside: {e}"),
                )
                .with("target", target_arg.as_str())
            })?;
            if let Err(e) = fs::rename(&temp, &target) {
                let mut msg = format!("failed to restore snapshot: {e}");
                if let Err(e2) = fs::rename(&backup, &target) {
                    msg.push_str(&format!(
                        "; the previous target could not be put back and is at {} ({e2})",
                        backup.display()
                    ));
                }
                return Err(
                    Failure::new("restore_failed", msg).with("snapshot", snapshot_name.as_str())
                );
            }
            guard.disarm();
            if let Err(e) = remove_any(&backup) {
                warnings.push(format!(
                    "restored, but could not remove the previous content at {}: {e}",
                    backup.display()
                ));
            }
        } else {
            fs::rename(&temp, &target).map_err(|e| {
                Failure::new("restore_failed", format!("failed to restore snapshot: {e}"))
                    .with("snapshot", snapshot_name.as_str())
            })?;
            guard.disarm();
        }

        Ok(json!({
            "snapshot": snapshot_name,
            "target": target_arg,
            "mode": mode,
            "status": "ok",
        })
        .to_string()
            + "\n")
    }
}

/// `p` made absolute against the working directory and normalized.
fn absolute(p: &Path) -> VResult<PathBuf> {
    if p.is_absolute() {
        return Ok(normalize_path(p));
    }
    let cwd = std::env::current_dir().map_err(|e| {
        Failure::new(
            "invalid_target",
            format!("cannot resolve relative path {}: {e}", p.display()),
        )
    })?;
    Ok(normalize_path(&cwd.join(p)))
}

/// Lexical normalization: drops `.`, resolves `..` against earlier
/// components. A relative path keeps leading `..` components.
fn normalize_path(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::RootDir => out.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                let last_normal =
                    matches!(out.components().next_back(), Some(Component::Normal(_)));
                if last_normal {
                    out.pop();
                } else if !out.has_root() {
                    out.push("..");
                }
            }
            Component::Normal(n) => out.push(n),
            Component::Prefix(_) => {}
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        out
    }
}

impl Handle for SnapshotHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &[
            "create", "diff", "restore", "ls", "help", "--help", "-h", "h",
        ]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&SNAPSHOT_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // In-URL help: snapshot://--help, snapshot://--help=<verb>, or a
        // help alias as the verb (snapshot:///srv/app.help(verb=ls)).
        if self.target.as_os_str() == HELP_PATH || crate::core::help::HELP_ALIASES.contains(&verb) {
            let verb = args.get("verb").map(String::as_str);
            write!(
                io.stdout,
                "{}",
                crate::core::help::render_legacy("snapshot", &SNAPSHOT_HELP, self.verbs(), verb)
            )?;
            return Ok(Status::ok());
        }

        let mut warnings = Vec::new();
        let result = match verb {
            "create" => self
                .create(args, &mut warnings)
                .map(|v| v.to_string() + "\n"),
            "diff" => self.diff(args, &mut warnings),
            "restore" => self.restore(args, &mut warnings),
            "ls" => self.ls(args, &mut warnings),
            _ => Err(Failure::new(
                "unknown_verb",
                format!(
                    "unknown verb for snapshot://: {verb} (available: create, diff, restore, ls)"
                ),
            )),
        };
        // On failure the Error line comes first, then any warnings.
        let status = match result {
            Ok(text) => {
                for w in &warnings {
                    writeln!(io.stderr, "snapshot {verb}: warning: {w}")?;
                }
                io.stdout.write_all(text.as_bytes())?;
                Status::ok()
            }
            Err(f) => {
                let status = emit_failure(io, f)?;
                for w in &warnings {
                    writeln!(io.stderr, "snapshot {verb}: warning: {w}")?;
                }
                status
            }
        };
        Ok(status)
    }
}

/// Test-only snapshot store location for the current thread, so tests
/// never touch the user's real state directory.
#[cfg(test)]
pub(crate) mod test_store {
    use std::cell::RefCell;
    use std::path::PathBuf;

    thread_local! {
        static BASE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    }

    pub fn get() -> Option<PathBuf> {
        BASE.with(|b| b.borrow().clone())
    }

    pub struct Guard;

    pub fn install(base: PathBuf) -> Guard {
        BASE.with(|b| *b.borrow_mut() = Some(base));
        Guard
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            BASE.with(|b| *b.borrow_mut() = None);
            NOW.with(|n| *n.borrow_mut() = None);
        }
    }

    thread_local! {
        static NOW: RefCell<Option<chrono::DateTime<chrono::Utc>>> = const { RefCell::new(None) };
    }

    /// The pinned test clock, if any.
    pub fn now() -> Option<chrono::DateTime<chrono::Utc>> {
        NOW.with(|n| *n.borrow())
    }

    /// Pins the clock for this thread (until the store guard drops).
    pub fn set_now(t: chrono::DateTime<chrono::Utc>) {
        NOW.with(|n| *n.borrow_mut() = Some(t));
    }
}

#[cfg(test)]
#[path = "snapshot_tests.rs"]
mod verb_tests;
