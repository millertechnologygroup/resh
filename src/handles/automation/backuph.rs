use anyhow::{Context, Result, bail};
use chrono::{DateTime, Datelike, Utc};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use url::Url;

use crate::core::{
    envelope::{BackendInfo, BackupEnvelope, BackupError},
    help::{self, HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::Status,
};

/// Backup handle implementing all required verbs with JSON envelope per specification
#[derive(Debug)]
pub struct BackupHandle {
    /// Repository identifier from URL
    pub repo: String,
    /// Target URL for JSON responses
    pub target: String,
}

/// Backend capabilities for backup operations per specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupCapabilities {
    pub incremental: bool,
    pub dedup: bool,
    pub encryption: bool,
    pub retention: bool,
    pub verify: bool,
    pub cloud_targets: Vec<String>,
}

/// Metadata for `resh backup --help` and `resh backup <verb> --help`.
static BACKUP_HELP: HandleHelp = HandleHelp {
    description: "The backup handle creates, lists, restores, verifies, and prunes backup \
        snapshots by running restic, borg, rsync, or tar, using the first one installed \
        unless backend is given. The stage URL names a backup profile, such as \
        backup://db, and the repository location is passed with repo_url. restic and \
        borg take the repository password from password or password_file, or from \
        their usual environment variables, and every verb prints a JSON envelope.",
    usage: "resh backup://<profile>.<verb>[(key=value,...)]",
    verbs: &[
        VerbHelp {
            name: "list",
            definition: "Lists the snapshots in a repository by running the backend's listing \
                command, such as restic snapshots or borg list.",
            detail: Some(VerbDetail {
                usage: "resh backup://<profile>.list [backend=restic|borg|rsync|tar]\n  \
                    [repo_url=<repo>] [password=<secret>|password_file=<path>]\n  \
                    [tag=<tag>;...] [timeout_ms=<ms>]",
                example: "resh --json-pretty backup://db.list backend=restic \
                    repo_url=/srv/restic",
                example_output: Some(
                    r#"{
  "backend": {
    "command": [
      "restic",
      "snapshots",
      "--json"
    ],
    "env_redacted": {
      "RESTIC_REPOSITORY": "/srv/restic"
    },
    "id": "restic",
    "simulated": false,
    "timeout_ms": 10000
  },
  "dry_run": false,
  "duration_ms": 412,
  "events": [],
  "handle": "backup",
  "ok": true,
  "result": {
    "capabilities": {
      "cloud_targets": [
        "s3",
        "azure",
        "gcs",
        "file"
      ],
      "dedup": true,
      "encryption": true,
      "incremental": true,
      "retention": true,
      "verify": true
    },
    "snapshots": [
      {
        "created_at": "2026-10-16T02:00:04.118372+00:00",
        "id": "4f2a9c1e",
        "label": "web01",
        "sources": [
          "/etc"
        ],
        "tags": [
          "daily"
        ]
      }
    ],
    "total_count": 1
  },
  "target": "backup://db",
  "ts": "2026-10-16T09:12:44.931277+00:00",
  "verb": "list",
  "warnings": []
}

Shown for restic with --json-pretty and RESTIC_PASSWORD_FILE set in the
environment; password=<secret> would add a redacted RESTIC_PASSWORD. The
label field holds the restic hostname. tar and rsync read the repository
directory directly, so their command is empty. Without a password, restic
and borg fail with MISSING_PASSWORD before running."#,
                ),
            }),
        },
        VerbHelp {
            name: "verify",
            definition: "Checks repository integrity with the backend's check command, reading \
                all data when mode is thorough or data.",
            detail: Some(VerbDetail {
                usage: "resh backup://<profile>.verify [backend=restic|borg|rsync|tar]\n  \
                    [repo_url=<repo>] [password=<secret>|password_file=<path>]\n  \
                    [mode=quick|thorough|data] [snapshot_id=<id>] [timeout_ms=<ms>]",
                example: "resh --json-pretty backup://db.verify backend=restic \
                    repo_url=/srv/restic",
                example_output: Some(
                    r#"{
  "backend": {
    "command": [
      "restic",
      "check"
    ],
    "env_redacted": {
      "RESTIC_REPOSITORY": "/srv/restic"
    },
    "id": "restic",
    "simulated": false,
    "timeout_ms": 3600000
  },
  "dry_run": false,
  "duration_ms": 2318,
  "events": [],
  "handle": "backup",
  "ok": true,
  "result": {
    "capabilities": {
      "cloud_targets": [
        "s3",
        "azure",
        "gcs",
        "file"
      ],
      "dedup": true,
      "encryption": true,
      "incremental": true,
      "retention": true,
      "verify": true
    },
    "mode": "quick",
    "snapshot_id": null,
    "verification": {
      "errors": [],
      "files_checked": 6,
      "issues": [],
      "success": true
    }
  },
  "target": "backup://db",
  "ts": "2026-10-16T09:12:44.931277+00:00",
  "verb": "verify",
  "warnings": []
}

Shown for restic with --json-pretty and RESTIC_PASSWORD_FILE set in the
environment. files_checked counts restic
output lines, and snapshot_id is only echoed back. tar runs tar -tzf on each
archive, rsync opens every file, and problems give a VERIFY_FAILED error."#,
                ),
            }),
        },
        VerbHelp {
            name: "create",
            definition: "Backs up one or more source paths with the selected backend and \
                reports the new snapshot id and sizes read from the backend's output.",
            detail: Some(VerbDetail {
                usage: "resh backup://<profile>.create src=<path>[;<path>...]\n  \
                    [backend=restic|borg|rsync|tar] [repo_url=<repo>]\n  \
                    [password=<secret>|password_file=<path>] [tag=<tag>;...]\n  \
                    [label=<text>] [exclude=<pattern>;...] [dry_run=true|false]\n  \
                    [timeout_ms=<ms>]",
                example: "resh backup://db.create src=/etc backend=tar repo_url=/srv/backup \
                    dry_run=true",
                example_output: Some(
                    r#"{
  "backend": {
    "command": [
      "tar",
      "--force-local",
      "-czf",
      "/srv/backup/backup_20261016_091244.tar.gz",
      "--",
      "/etc"
    ],
    "env_redacted": {},
    "id": "tar",
    "simulated": true,
    "timeout_ms": 1800000
  },
  "dry_run": true,
  "duration_ms": 0,
  "events": [],
  "handle": "backup",
  "ok": true,
  "result": {
    "backend_raw": {
      "stderr": "",
      "stdout": ""
    },
    "capabilities": {
      "cloud_targets": [
        "file"
      ],
      "dedup": false,
      "encryption": false,
      "incremental": true,
      "retention": true,
      "verify": true
    },
    "dry_run_mode": "plan",
    "snapshot": {
      "created_at": "2026-10-16T09:12:44.930811+00:00",
      "id": "dry-run-id",
      "sources": [
        "/etc"
      ],
      "tags": []
    }
  },
  "target": "backup://db",
  "ts": "2026-10-16T09:12:44.931277+00:00",
  "verb": "create",
  "warnings": [
    "Dry run: no backup was created"
  ]
}

Shown for a tar dry run, indented as with --json-pretty. A real run
reports the archive, directory or restic snapshot id, such as
backup_20261016_091244, and the raw output. restic and borg need password,
password_file, RESTIC_PASSWORD(_FILE) or BORG_PASSPHRASE/BORG_PASSCOMMAND,
else they fail with MISSING_PASSWORD.
tar, rsync and borg need repo_url (there is no default repository), else
every verb fails with INVALID_ARGS; use a directory only you can write."#,
                ),
            }),
        },
        VerbHelp {
            name: "restore",
            definition: "Restores a snapshot into a destination directory with the selected \
                backend.",
            detail: Some(VerbDetail {
                usage: "resh backup://<profile>.restore snapshot_id=<id> dest=<path>\n  \
                    [backend=restic|borg|rsync|tar] [repo_url=<repo>]\n  \
                    [password=<secret>|password_file=<path>] [include=<pattern>,...]\n  \
                    [exclude=<pattern>;...] [timeout_ms=<ms>]",
                example: "resh --json-pretty backup://db.restore snapshot_id=4f2a9c1e \
                    dest=/tmp/restore",
                example_output: Some(
                    r#"{
  "backend": {
    "command": [
      "restic",
      "restore",
      "4f2a9c1e",
      "--target",
      "/tmp/restore"
    ],
    "env_redacted": {},
    "id": "restic",
    "simulated": false,
    "timeout_ms": 1800000
  },
  "dry_run": false,
  "duration_ms": 5120,
  "events": [],
  "handle": "backup",
  "ok": true,
  "result": {
    "capabilities": {
      "cloud_targets": [
        "s3",
        "azure",
        "gcs",
        "file"
      ],
      "dedup": true,
      "encryption": true,
      "incremental": true,
      "retention": true,
      "verify": true
    },
    "destination": "/tmp/restore",
    "restored": {
      "bytes_restored": 0,
      "files_restored": 1,
      "success": true
    },
    "snapshot_id": "4f2a9c1e"
  },
  "target": "backup://db",
  "ts": "2026-10-16T09:12:44.931277+00:00",
  "verb": "restore",
  "warnings": []
}

Shown for restic, the first backend tried when none is given, with
--json-pretty and RESTIC_PASSWORD_FILE set in the environment. The
files_restored field counts backend output lines that mention restoring,
and bytes_restored is always 0. include is used only by restic."#,
                ),
            }),
        },
        VerbHelp {
            name: "prune",
            definition: "Removes snapshots outside the keep_daily, keep_weekly, and \
                keep_monthly limits, or reports what would be removed when dry_run is true.",
            detail: Some(VerbDetail {
                usage: "resh backup://<profile>.prune [backend=restic|borg|rsync|tar]\n  \
                    [repo_url=<repo>] [password=<secret>|password_file=<path>]\n  \
                    [keep_daily=<n>] [keep_weekly=<n>] [keep_monthly=<n>]\n  \
                    [dry_run=true|false] [timeout_ms=<ms>]",
                example: "resh --json-pretty backup://db.prune backend=restic \
                    keep_daily=7 dry_run=true",
                example_output: Some(
                    r#"{
  "backend": {
    "command": [
      "restic",
      "forget",
      "--json",
      "--keep-daily",
      "7",
      "--dry-run"
    ],
    "env_redacted": {},
    "id": "restic",
    "simulated": false,
    "timeout_ms": 3600000
  },
  "dry_run": true,
  "duration_ms": 0,
  "events": [],
  "handle": "backup",
  "ok": true,
  "result": {
    "capabilities": {
      "cloud_targets": [
        "s3",
        "azure",
        "gcs",
        "file"
      ],
      "dedup": true,
      "encryption": true,
      "incremental": true,
      "retention": true,
      "verify": true
    },
    "dry_run": true,
    "policy": {
      "keep_daily": 7,
      "keep_monthly": null,
      "keep_weekly": null
    },
    "would_prune": {
      "bytes_freed": null,
      "snapshots_removed": 3,
      "success": true
    }
  },
  "target": "backup://db",
  "ts": "2026-10-16T09:12:44.931277+00:00",
  "verb": "prune",
  "warnings": []
}

Shown for a restic dry run with --json-pretty and RESTIC_PASSWORD_FILE set
in the environment. A dry run runs the backend's
own dry run, which leaves snapshots alone but takes a repository lock
(exclusive for borg), writes the backend's local cache and needs the
repository credentials. A real run reports pruned instead of would_prune.
tar and rsync apply the policy to archives or snapshot directories by
modification time (UTC days) and report bytes_freed. At least one keep_* is
required."#,
                ),
            }),
        },
        VerbHelp {
            name: "schedule",
            definition: "Reports a backup schedule definition and the detected scheduler \
                without installing a timer or cron job or writing any file.",
            detail: Some(VerbDetail {
                usage: "resh backup://<profile>.schedule when=<cron> src=<path>\n  \
                    [backend=restic|borg|rsync|tar] [enabled=true|false] [timeout_ms=<ms>]",
                example: "resh --json-pretty backup://db.schedule 'when=0 2 * * *' \
                    src=/etc backend=tar",
                example_output: Some(
                    r#"{
  "backend": {
    "command": [
      "tar"
    ],
    "env_redacted": {},
    "id": "tar",
    "simulated": false,
    "timeout_ms": 10000
  },
  "dry_run": false,
  "duration_ms": 0,
  "events": [],
  "handle": "backup",
  "ok": true,
  "result": {
    "capabilities": {
      "cloud_targets": [
        "file"
      ],
      "dedup": false,
      "encryption": false,
      "incremental": true,
      "retention": true,
      "verify": true
    },
    "schedule": {
      "definition_path": "/home/alice/resh-backup-default.json",
      "enabled": true,
      "runner": "systemd",
      "when": "0 2 * * *"
    }
  },
  "target": "backup://db",
  "ts": "2026-10-16T09:12:44.931277+00:00",
  "verb": "schedule",
  "warnings": []
}

Shown on a systemd host with --json-pretty. The runner is cron when only
crontab is found, and none (with a warning) when neither is found."#,
                ),
            }),
        },
    ],
};

/// Backend types supported by the backup handle
#[derive(Debug, Clone, PartialEq)]
pub enum BackendType {
    Restic,
    Borg,
    Rsync,
    Tar,
}

impl std::fmt::Display for BackendType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendType::Restic => write!(f, "restic"),
            BackendType::Borg => write!(f, "borg"),
            BackendType::Rsync => write!(f, "rsync"),
            BackendType::Tar => write!(f, "tar"),
        }
    }
}

/// Snapshot information for list/create operations per specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotInfo {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub tags: Vec<String>,
    pub created_at: String,
    pub sources: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_sent: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_total: Option<u64>,
}

/// Backend command execution result (full, untruncated output)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

/// Retention policy configuration per specification
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RetentionPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_last: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_daily: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_weekly: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_monthly: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_yearly: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub keep_tags: Vec<String>,
}

/// Verification check result per specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationCheck {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

/// Schedule configuration per specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleConfig {
    pub when: String,
    pub enabled: bool,
    pub runner: String,
    pub definition_path: String,
}

/// Waits for `child` to exit, collecting its stdout and stderr, for at most
/// `timeout`. Returns `Ok(None)` after killing and reaping the child when the
/// deadline passes. Output pipes are drained on separate threads so a
/// chatty child cannot block on a full pipe. Also used by the firewall
/// handle for its command timeouts.
pub(crate) fn wait_with_deadline(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<Option<std::process::Output>> {
    use std::io::Read;

    fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut p) = pipe {
                let _ = p.read_to_end(&mut buf);
            }
            buf
        })
    }
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());

    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .context("Failed to wait for backend process")?
        {
            return Ok(Some(std::process::Output {
                status,
                stdout: stdout.join().unwrap_or_default(),
                stderr: stderr.join().unwrap_or_default(),
            }));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait(); // reap; no zombie is left behind
            // The readers finish when the pipes close; they are not joined
            // because a grandchild may still hold the pipes open.
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(10).min(deadline - Instant::now()));
    }
}

/// Constants for default timeouts per specification (in milliseconds)
const DEFAULT_CREATE_TIMEOUT_MS: u64 = 1_800_000; // 30 minutes
const DEFAULT_LIST_TIMEOUT_MS: u64 = 10_000; // 10 seconds
const DEFAULT_RESTORE_TIMEOUT_MS: u64 = 1_800_000; // 30 minutes
const DEFAULT_VERIFY_TIMEOUT_MS: u64 = 3_600_000; // 60 minutes
const DEFAULT_PRUNE_TIMEOUT_MS: u64 = 3_600_000; // 60 minutes
const DEFAULT_SCHEDULE_TIMEOUT_MS: u64 = 10_000; // 10 seconds

/// Maximum output capture size per specification (256KB)
const MAX_OUTPUT_SIZE: usize = 256 * 1024;

/// Error tail size for error details per specification (8KB)
const ERROR_TAIL_SIZE: usize = 8 * 1024;

/// Secret key patterns for redaction per specification (case insensitive)
const SECRET_PATTERNS: &[&str] = &[
    "password",
    "passphrase",
    "passcommand",
    "secret",
    "token",
    "key",
    "access_key",
    "secret_key",
    "session_token",
];

/// Environment variables through which restic already has a repository password.
const RESTIC_SECRET_ENV: &[&str] = &[
    "RESTIC_PASSWORD",
    "RESTIC_PASSWORD_FILE",
    "RESTIC_PASSWORD_COMMAND",
];

/// Environment variables through which borg already has a repository passphrase.
const BORG_SECRET_ENV: &[&str] = &["BORG_PASSPHRASE", "BORG_PASSCOMMAND", "BORG_PASSPHRASE_FD"];

const REDACTED: &str = "***REDACTED***";

fn is_secret_key(key: &str) -> bool {
    let key = key.to_lowercase();
    SECRET_PATTERNS.iter().any(|pattern| key.contains(pattern))
}

// ---------------------------------------------------------------------------
// Command construction (pure functions, unit tested below)
// ---------------------------------------------------------------------------

/// One backend program invocation.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CmdSpec {
    /// Program to run (the first argv element).
    pub program: String,
    /// Arguments after the program name.
    pub args: Vec<String>,
    /// Extra environment variables for the child.
    pub env: HashMap<String, String>,
    /// Inherited environment variables to remove from the child.
    pub env_remove: Vec<String>,
    /// Working directory for the child.
    pub cwd: Option<String>,
}

impl CmdSpec {
    fn new(program: &str) -> Self {
        CmdSpec {
            program: program.to_string(),
            ..Default::default()
        }
    }

    fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    fn args<I, S>(mut self, it: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(it.into_iter().map(Into::into));
        self
    }

    /// Full argv, program first.
    pub fn argv(&self) -> Vec<String> {
        std::iter::once(self.program.clone())
            .chain(self.args.iter().cloned())
            .collect()
    }
}

/// `--flag=v1 --flag=v2 ...`. The value is attached with `=` so that every
/// backend's option parser (GNU getopt, popt, pflag, argparse) reads a value
/// starting with `-` as the value, never as another option.
fn repeat_flag(flag: &str, values: &[String]) -> Vec<String> {
    values.iter().map(|v| format!("{}={}", flag, v)).collect()
}

/// A local path as an rsync argument. rsync reads `host:path` (a `:` before
/// the first `/`) as a remote location and starts a remote shell for it, so
/// a relative path gets a `./` prefix and is always local.
fn rsync_local(path: &str) -> String {
    if path.starts_with('/') || path.starts_with("./") {
        path.to_string()
    } else {
        format!("./{}", path)
    }
}

/// Local repository directory for tar/rsync, accepting `file://` URLs.
/// `repo_or_return!` has already rejected a missing `repo_url`.
fn local_repo_path(repo_url: Option<&String>) -> String {
    repo_url
        .map(|u| u.strip_prefix("file://").unwrap_or(u).to_string())
        .unwrap_or_default()
}

fn borg_repo(repo_url: Option<&String>) -> String {
    repo_url.cloned().unwrap_or_default()
}

/// tar, rsync and borg have no safe default repository: the former `/tmp`
/// defaults were world-readable and accepted directories planted by other
/// users. restic reads `RESTIC_REPOSITORY` itself when `repo_url` is absent.
fn repo_url_required(backend: &BackendType, args: &Args) -> Option<String> {
    let needs = matches!(
        backend,
        BackendType::Tar | BackendType::Rsync | BackendType::Borg
    );
    let given = args
        .get("repo_url")
        .map(|u| !u.trim().is_empty() && u.trim() != "file://")
        .unwrap_or(false);
    (needs && !given).then(|| {
        format!(
            "repo_url is required for the {} backend (there is no default repository); \
             pass a directory only you can write, for example repo_url=/var/backups/resh/<profile>",
            backend
        )
    })
}

/// Snapshot (archive or directory) name: `<label>_<ts>` or `backup_<ts>`.
/// Characters other than ASCII letters, digits, `.`, `-` and `_` in the label
/// become `_`, so a label cannot escape the repository directory.
pub(crate) fn snapshot_name(label: Option<&str>, timestamp: &str) -> String {
    match label {
        Some(l) => {
            let clean: String = l
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            format!("{}_{}", clean, timestamp)
        }
        None => format!("backup_{}", timestamp),
    }
}

// ---------------------------------------------------------------------------
// Argument validation (runs before any plan is reported or backend is run)
// ---------------------------------------------------------------------------

/// A caller value refused before anything runs: the argument it came from
/// and why.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct UnsafeArg {
    pub field: &'static str,
    pub message: String,
}

fn unsafe_arg(field: &'static str, reason: impl std::fmt::Display) -> UnsafeArg {
    UnsafeArg {
        field,
        message: format!("{} {}; nothing was run", field, reason),
    }
}

/// A value attached to a backend option (`--exclude=<v>`): any text without
/// control characters.
fn check_option_value(field: &'static str, value: &str) -> Result<(), UnsafeArg> {
    if value.chars().any(char::is_control) {
        return Err(unsafe_arg(field, "must not contain control characters"));
    }
    Ok(())
}

/// A value passed as a backend positional or as the value of a short option:
/// additionally non-empty and not starting with `-`, which a backend would
/// read as an option even where `--` is not available.
fn check_positional(field: &'static str, value: &str) -> Result<(), UnsafeArg> {
    check_option_value(field, value)?;
    if value.is_empty() {
        return Err(unsafe_arg(field, "must not be empty"));
    }
    if value.starts_with('-') {
        return Err(unsafe_arg(
            field,
            format!(
                "must not start with '-' (got {:?}); prefix a relative path with ./",
                value
            ),
        ));
    }
    Ok(())
}

/// A tar archive or rsync snapshot name: one entry of the repository
/// directory, so it cannot name a file outside it.
fn check_snapshot_entry(field: &'static str, value: &str) -> Result<(), UnsafeArg> {
    check_positional(field, value)?;
    if value.contains('/') || value == "." || value == ".." {
        return Err(unsafe_arg(
            field,
            "must be a snapshot name in the repository, not a path",
        ));
    }
    Ok(())
}

/// A restic or borg repository location. Both can reach a repository over
/// ssh (borg `ssh://host/...` and `user@host:path`, restic `sftp:host:path`)
/// and pass the host to ssh, which would read a host starting with `-` as an
/// option. No component may start with `-`.
fn check_remote_repo(value: &str) -> Result<(), UnsafeArg> {
    check_positional("repo_url", value)?;
    let bytes = value.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        let after_sep =
            matches!(b, b':' | b'@' | b'[') || (*b == b'/' && i > 0 && bytes[i - 1] == b'/');
        if after_sep && bytes.get(i + 1) == Some(&b'-') {
            return Err(unsafe_arg(
                "repo_url",
                format!(
                    "has a host or user component starting with '-' (got {:?})",
                    value
                ),
            ));
        }
    }
    Ok(())
}

/// Checks every caller value that `verb` places in a backend command line.
pub(crate) fn validate_request(
    backend: &BackendType,
    verb: &str,
    args: &Args,
) -> Result<(), UnsafeArg> {
    if let Some(repo) = args.get("repo_url") {
        match backend {
            BackendType::Restic | BackendType::Borg => check_remote_repo(repo)?,
            // A local directory: tar uses --force-local, rsync gets ./.
            BackendType::Tar | BackendType::Rsync => check_positional("repo_url", repo)?,
        }
    }
    let list = |key: &'static str, sep: char| -> Vec<String> {
        args.get(key)
            .map(|v| split_list(v, sep))
            .unwrap_or_default()
    };
    for tag in list("tag", ';') {
        check_option_value("tag", &tag)?;
    }
    for pattern in list("exclude", ';') {
        check_option_value("exclude", &pattern)?;
    }
    match verb {
        "create" => {
            let sources = list("src", ';');
            if sources.is_empty() {
                return Err(unsafe_arg("src", "must name at least one path"));
            }
            for src in &sources {
                check_positional("src", src)?;
            }
            if let Some(label) = args.get("label") {
                check_option_value("label", label)?;
            }
        }
        "restore" => {
            if let Some(id) = args.get("snapshot_id") {
                match backend {
                    BackendType::Tar | BackendType::Rsync => {
                        check_snapshot_entry("snapshot_id", id)?
                    }
                    BackendType::Restic | BackendType::Borg => check_positional("snapshot_id", id)?,
                }
            }
            if let Some(dest) = args.get("dest") {
                check_positional("dest", dest)?;
            }
            for pattern in list("include", ',') {
                check_option_value("include", &pattern)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn restic_base(repo_url: Option<&String>, sub: &str) -> CmdSpec {
    let mut c = CmdSpec::new("restic").arg(sub);
    if let Some(repo) = repo_url {
        c.env.insert("RESTIC_REPOSITORY".to_string(), repo.clone());
    }
    c
}

fn keep_flags(policy: &RetentionPolicy) -> Vec<String> {
    let mut v = Vec::new();
    for (flag, val) in [
        ("--keep-daily", policy.keep_daily),
        ("--keep-weekly", policy.keep_weekly),
        ("--keep-monthly", policy.keep_monthly),
    ] {
        if let Some(n) = val {
            v.push(flag.to_string());
            v.push(n.to_string());
        }
    }
    v
}

// Positional values always follow `--`, and the values have been checked by
// `validate_request` (no leading `-`, no control characters) as well.
// `--force-local` stops GNU tar from reading an archive name containing `:`
// as `host:file` on a remote host.

pub(crate) fn build_tar_create(archive: &str, sources: &[String], exclude: &[String]) -> CmdSpec {
    CmdSpec::new("tar")
        .args(["--force-local", "-czf", archive])
        .args(repeat_flag("--exclude", exclude))
        .arg("--")
        .args(sources.iter().cloned())
}

pub(crate) fn build_restic_create(
    repo_url: Option<&String>,
    sources: &[String],
    tags: &[String],
    label: Option<&str>,
    exclude: &[String],
) -> CmdSpec {
    let mut c = restic_base(repo_url, "backup").args(repeat_flag("--tag", tags));
    if let Some(label) = label {
        c = c.arg(format!("--hostname={}", label));
    }
    c.args(repeat_flag("--exclude", exclude))
        .arg("--json")
        .arg("--")
        .args(sources.iter().cloned())
}

pub(crate) fn build_borg_create(
    repo: &str,
    archive: &str,
    sources: &[String],
    exclude: &[String],
) -> CmdSpec {
    CmdSpec::new("borg")
        .args(["create", "--json", "--compression", "lz4"])
        .args(repeat_flag("--exclude", exclude))
        .arg("--")
        .arg(format!("{}::{}", repo, archive))
        .args(sources.iter().cloned())
}

pub(crate) fn build_rsync_create(
    dest_dir: &str,
    sources: &[String],
    exclude: &[String],
) -> CmdSpec {
    CmdSpec::new("rsync")
        .args(["-a", "--stats"])
        .args(repeat_flag("--exclude", exclude))
        .arg("--")
        .args(sources.iter().map(|s| rsync_local(s)))
        .arg(rsync_local(dest_dir))
}

pub(crate) fn build_restic_list(repo_url: Option<&String>, tags: &[String]) -> CmdSpec {
    restic_base(repo_url, "snapshots")
        .arg("--json")
        .args(repeat_flag("--tag", tags))
}

pub(crate) fn build_borg_list(repo: &str) -> CmdSpec {
    CmdSpec::new("borg").args(["list", "--json", "--", repo])
}

pub(crate) fn build_restic_restore(
    repo_url: Option<&String>,
    snapshot_id: &str,
    dest: &str,
    include: &[String],
    exclude: &[String],
) -> CmdSpec {
    restic_base(repo_url, "restore")
        .arg(format!("--target={}", dest))
        .args(repeat_flag("--include", include))
        .args(repeat_flag("--exclude", exclude))
        .args(["--", snapshot_id])
}

/// borg extracts into its working directory, so the destination is the cwd.
pub(crate) fn build_borg_restore(
    repo: &str,
    snapshot_id: &str,
    dest: &str,
    exclude: &[String],
) -> CmdSpec {
    let mut c = CmdSpec::new("borg")
        .arg("extract")
        .args(repeat_flag("--exclude", exclude))
        .arg("--")
        .arg(format!("{}::{}", repo, snapshot_id));
    c.cwd = Some(dest.to_string());
    c
}

pub(crate) fn build_tar_restore(archive: &str, dest: &str, exclude: &[String]) -> CmdSpec {
    CmdSpec::new("tar")
        .args(["--force-local", "-xzf", archive])
        .args(repeat_flag("--exclude", exclude))
        .args(["-C", dest])
}

pub(crate) fn build_rsync_restore(snapshot_dir: &str, dest: &str, exclude: &[String]) -> CmdSpec {
    CmdSpec::new("rsync")
        .arg("-av")
        .args(repeat_flag("--exclude", exclude))
        .arg("--")
        .args([rsync_local(snapshot_dir), rsync_local(dest)])
}

pub(crate) fn build_restic_verify(repo_url: Option<&String>, read_data: bool) -> CmdSpec {
    let c = restic_base(repo_url, "check");
    if read_data { c.arg("--read-data") } else { c }
}

pub(crate) fn build_borg_verify(repo: &str, verify_data: bool) -> CmdSpec {
    let c = CmdSpec::new("borg").arg("check");
    let c = if verify_data {
        c.arg("--verify-data")
    } else {
        c
    };
    c.args(["--", repo])
}

pub(crate) fn build_tar_verify(archive: &str) -> CmdSpec {
    CmdSpec::new("tar").args(["--force-local", "-tzf", archive])
}

pub(crate) fn build_restic_prune(
    repo_url: Option<&String>,
    policy: &RetentionPolicy,
    dry_run: bool,
) -> CmdSpec {
    restic_base(repo_url, "forget")
        .arg("--json")
        .args(keep_flags(policy))
        .arg(if dry_run { "--dry-run" } else { "--prune" })
}

pub(crate) fn build_borg_prune(repo: &str, policy: &RetentionPolicy, dry_run: bool) -> CmdSpec {
    CmdSpec::new("borg")
        .args(["prune", "--list"])
        .args(keep_flags(policy))
        .arg(if dry_run { "--dry-run" } else { "--stats" })
        .args(["--", repo])
}

// ---------------------------------------------------------------------------
// Repository password (C1)
// ---------------------------------------------------------------------------

/// Environment changes that give the backend its repository password.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct RepoSecret {
    pub set: HashMap<String, String>,
    pub remove: Vec<String>,
}

impl RepoSecret {
    fn apply(self, spec: &mut CmdSpec) {
        spec.env.extend(self.set);
        spec.env_remove.extend(self.remove);
    }
}

/// Resolves the restic/borg repository password from `password=` or
/// `password_file=`, else from the backend's usual environment variables.
/// tar and rsync need none. Returns an error message (never containing the
/// secret) when restic or borg has no password source.
pub(crate) fn resolve_repo_secret(
    backend: &BackendType,
    args: &Args,
    env_has: impl Fn(&str) -> bool,
    read_file: impl Fn(&str) -> std::io::Result<String>,
) -> std::result::Result<RepoSecret, String> {
    let mut secret = RepoSecret::default();
    match backend {
        BackendType::Restic => {
            if let Some(p) = args.get("password") {
                secret.set.insert("RESTIC_PASSWORD".to_string(), p.clone());
                // restic prefers a password file or command over RESTIC_PASSWORD.
                secret.remove = vec![
                    "RESTIC_PASSWORD_FILE".to_string(),
                    "RESTIC_PASSWORD_COMMAND".to_string(),
                ];
            } else if let Some(f) = args.get("password_file") {
                secret
                    .set
                    .insert("RESTIC_PASSWORD_FILE".to_string(), f.clone());
                // restic refuses both a password file and a password command.
                secret.remove = vec!["RESTIC_PASSWORD_COMMAND".to_string()];
            } else if !RESTIC_SECRET_ENV.iter().any(|k| env_has(k)) {
                return Err(
                    "restic needs a repository password: pass password=<secret> or \
                    password_file=<path>, or set RESTIC_PASSWORD or RESTIC_PASSWORD_FILE"
                        .to_string(),
                );
            }
        }
        BackendType::Borg => {
            if let Some(p) = args.get("password") {
                secret.set.insert("BORG_PASSPHRASE".to_string(), p.clone());
            } else if let Some(f) = args.get("password_file") {
                let content =
                    read_file(f).map_err(|e| format!("cannot read password_file {}: {}", f, e))?;
                secret.set.insert(
                    "BORG_PASSPHRASE".to_string(),
                    content.trim_end_matches(['\r', '\n']).to_string(),
                );
            } else if !BORG_SECRET_ENV.iter().any(|k| env_has(k)) {
                return Err(
                    "borg needs a repository passphrase: pass password=<secret> or \
                    password_file=<path>, or set BORG_PASSPHRASE or BORG_PASSCOMMAND \
                    (BORG_PASSPHRASE may be empty for an unencrypted repository)"
                        .to_string(),
                );
            }
        }
        BackendType::Rsync | BackendType::Tar => {}
    }
    Ok(secret)
}

// ---------------------------------------------------------------------------
// Output parsing (pure functions)
// ---------------------------------------------------------------------------

/// The restic `--json` summary message (the last line with message_type summary).
pub(crate) fn parse_restic_summary(stdout: &str) -> Option<Value> {
    stdout
        .lines()
        .rev()
        .filter_map(|l| serde_json::from_str::<Value>(l.trim()).ok())
        .find(|v| v["message_type"] == "summary")
}

/// A number after `prefix` on an rsync `--stats` line, such as
/// `Total file size: 1,234 bytes`.
fn rsync_stat(stdout: &str, prefix: &str) -> Option<u64> {
    stdout.lines().find_map(|l| {
        let rest = l.trim().strip_prefix(prefix)?;
        rest.split_whitespace()
            .next()?
            .replace(',', "")
            .parse()
            .ok()
    })
}

/// (total file size, transferred file size) from rsync `--stats` output.
pub(crate) fn parse_rsync_stats(stdout: &str) -> (Option<u64>, Option<u64>) {
    (
        rsync_stat(stdout, "Total file size:"),
        rsync_stat(stdout, "Total transferred file size:"),
    )
}

/// Exit codes that mean the backup was written, with a warning.
pub(crate) fn create_exit_warning(backend: &BackendType, code: i32) -> Option<&'static str> {
    match (backend, code) {
        (BackendType::Restic, 3) => {
            Some("restic could not read some source files; the snapshot was created without them")
        }
        (BackendType::Borg, 1) => {
            Some("borg finished with warnings; see result.backend_raw.stderr")
        }
        (BackendType::Rsync, 24) => Some("some source files vanished during the rsync transfer"),
        (BackendType::Tar, 1) => Some("some files changed while tar was reading them"),
        _ => None,
    }
}

/// Snapshot details for a completed backup. Returns None only when restic's
/// output has no summary with a snapshot id; the backup still succeeded.
pub(crate) fn parse_create_output(
    backend: &BackendType,
    stdout: &str,
    known_id: Option<&str>,
    sources: &[String],
    tags: &[String],
    label: Option<&str>,
) -> Option<SnapshotInfo> {
    let mut snap = SnapshotInfo {
        id: known_id.unwrap_or_default().to_string(),
        label: label.map(String::from),
        tags: tags.to_vec(),
        created_at: Utc::now().to_rfc3339(),
        sources: sources.to_vec(),
        bytes_sent: None,
        bytes_total: None,
    };
    match backend {
        BackendType::Tar => {}
        BackendType::Restic => {
            let summary = parse_restic_summary(stdout)?;
            snap.id = summary["snapshot_id"].as_str()?.to_string();
            snap.bytes_sent = summary["data_added"].as_u64();
            snap.bytes_total = summary["total_bytes_processed"].as_u64();
        }
        BackendType::Borg => {
            if let Ok(v) = serde_json::from_str::<Value>(stdout.trim()) {
                let archive = &v["archive"];
                if let Some(name) = archive["name"].as_str() {
                    snap.id = name.to_string();
                }
                if let Some(start) = archive["start"].as_str() {
                    snap.created_at = start.to_string();
                }
                snap.bytes_sent = archive["stats"]["deduplicated_size"].as_u64();
                snap.bytes_total = archive["stats"]["original_size"].as_u64();
            }
        }
        BackendType::Rsync => {
            let (total, sent) = parse_rsync_stats(stdout);
            snap.bytes_total = total;
            snap.bytes_sent = sent;
        }
    }
    if snap.id.is_empty() { None } else { Some(snap) }
}

fn json_strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Snapshots from `restic snapshots --json` or `borg list --json`.
pub(crate) fn parse_list_output(backend: &BackendType, output: &str) -> Result<Vec<SnapshotInfo>> {
    match backend {
        BackendType::Restic => {
            let snapshots: Option<Vec<Value>> = serde_json::from_str(output.trim())
                .context("restic snapshots output is not JSON")?;
            Ok(snapshots
                .unwrap_or_default()
                .into_iter()
                .filter_map(|s| {
                    let id = s["short_id"]
                        .as_str()
                        .map(String::from)
                        .or_else(|| s["id"].as_str().map(|i| i.chars().take(8).collect()))?;
                    Some(SnapshotInfo {
                        id,
                        label: s["hostname"].as_str().map(String::from),
                        tags: json_strings(&s["tags"]),
                        created_at: s["time"].as_str().unwrap_or_default().to_string(),
                        sources: json_strings(&s["paths"]),
                        bytes_sent: None,
                        bytes_total: None,
                    })
                })
                .collect())
        }
        BackendType::Borg => {
            let data: Value =
                serde_json::from_str(output.trim()).context("borg list output is not JSON")?;
            Ok(data["archives"]
                .as_array()
                .map(|archives| {
                    archives
                        .iter()
                        .filter_map(|a| {
                            Some(SnapshotInfo {
                                id: a["name"].as_str()?.to_string(),
                                label: None,
                                tags: vec![],
                                created_at: a["start"].as_str().unwrap_or_default().to_string(),
                                sources: vec![],
                                bytes_sent: None,
                                bytes_total: a["stats"]["compressed_size"].as_u64(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default())
        }
        BackendType::Rsync | BackendType::Tar => bail!(
            "{} snapshots are listed from the repository directory",
            backend
        ),
    }
}

fn parse_restore_output(backend: &BackendType, output: &str) -> Value {
    let files_count = match backend {
        BackendType::Restic => output
            .lines()
            .filter(|line| line.contains("restoring"))
            .count(),
        BackendType::Borg => output.lines().filter(|line| line.contains("files")).count(),
        BackendType::Tar => output.lines().count(),
        BackendType::Rsync => output
            .lines()
            .filter(|line| {
                !line.trim().is_empty()
                    && !line.contains("receiving incremental")
                    && !line.contains("sending incremental")
            })
            .count(),
    };
    json!({
        "files_restored": files_count,
        "bytes_restored": 0,
        "success": true
    })
}

/// Number of snapshots removed (or that would be removed) by a prune run.
pub(crate) fn parse_prune_count(
    backend: &BackendType,
    stdout: &str,
    stderr: &str,
) -> Option<usize> {
    match backend {
        BackendType::Restic => {
            // `restic forget --json` prints one JSON array of groups.
            let groups: Vec<Value> = stdout
                .lines()
                .map(str::trim)
                .filter(|l| l.starts_with('['))
                .find_map(|l| serde_json::from_str(l).ok())?;
            Some(
                groups
                    .iter()
                    .map(|g| g["remove"].as_array().map_or(0, |r| r.len()))
                    .sum(),
            )
        }
        BackendType::Borg => Some(
            stdout
                .lines()
                .chain(stderr.lines())
                .map(str::trim)
                .filter(|l| l.starts_with("Pruning archive") || l.starts_with("Would prune"))
                .count(),
        ),
        BackendType::Rsync | BackendType::Tar => None,
    }
}

// ---------------------------------------------------------------------------
// Local (tar/rsync) repositories
// ---------------------------------------------------------------------------

/// A tar archive or rsync snapshot directory in a local repository.
#[derive(Debug, Clone)]
pub(crate) struct LocalSnapshot {
    pub id: String,
    pub path: std::path::PathBuf,
    pub modified: DateTime<Utc>,
    pub bytes: Option<u64>,
}

/// Total size of the regular files under `path`, not following symlinks.
fn dir_size(path: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(entry.path());
            } else if meta.is_file() {
                total += meta.len();
            }
        }
    }
    total
}

/// tar: `*.tar.gz` files (id is the name without `.tar.gz`); rsync: snapshot
/// directories. Newest first.
pub(crate) fn scan_local_snapshots(
    backend: &BackendType,
    repo: &Path,
    with_sizes: bool,
) -> std::io::Result<Vec<LocalSnapshot>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(repo)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        // DirEntry::metadata does not follow symlinks.
        let meta = entry.metadata()?;
        let modified: DateTime<Utc> = meta.modified()?.into();
        match backend {
            BackendType::Tar if meta.is_file() => {
                if let Some(id) = name.strip_suffix(".tar.gz") {
                    out.push(LocalSnapshot {
                        id: id.to_string(),
                        path: entry.path(),
                        modified,
                        bytes: Some(meta.len()),
                    });
                }
            }
            BackendType::Rsync if meta.is_dir() => {
                let bytes = with_sizes.then(|| dir_size(&entry.path()));
                out.push(LocalSnapshot {
                    id: name,
                    path: entry.path(),
                    modified,
                    bytes,
                });
            }
            _ => {}
        }
    }
    out.sort_by(|a, b| b.modified.cmp(&a.modified).then_with(|| a.id.cmp(&b.id)));
    Ok(out)
}

/// Ids to remove under a keep_daily/keep_weekly/keep_monthly policy. For each
/// rule, the newest snapshot of each of the newest N UTC days, ISO weeks or
/// months is kept; a snapshot kept by any rule is not removed.
pub(crate) fn select_prune(
    snapshots: &[(String, DateTime<Utc>)],
    policy: &RetentionPolicy,
) -> Vec<String> {
    let mut snaps: Vec<&(String, DateTime<Utc>)> = snapshots.iter().collect();
    snaps.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let rules: [(Option<u32>, fn(&DateTime<Utc>) -> String); 3] = [
        (policy.keep_daily, |t| t.format("%Y-%m-%d").to_string()),
        (policy.keep_weekly, |t| {
            let w = t.iso_week();
            format!("{}-W{:02}", w.year(), w.week())
        }),
        (policy.keep_monthly, |t| t.format("%Y-%m").to_string()),
    ];

    let mut keep = vec![false; snaps.len()];
    for (limit, bucket) in rules {
        let Some(limit) = limit else { continue };
        let mut last: Option<String> = None;
        let mut count = 0;
        for (i, (_, t)) in snaps.iter().enumerate() {
            if count >= limit {
                break;
            }
            let key = bucket(t);
            if last.as_deref() != Some(key.as_str()) {
                keep[i] = true;
                count += 1;
                last = Some(key);
            }
        }
    }
    snaps
        .iter()
        .zip(keep)
        .filter(|(_, kept)| !kept)
        .map(|((id, _), _)| id.clone())
        .collect()
}

/// Opens every regular file under `root` for reading. Returns
/// (files checked, errors).
fn check_files_readable(root: &Path) -> (usize, Vec<String>) {
    let mut checked = 0;
    let mut errors = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                errors.push(format!("{}: {}", dir.display(), e));
                continue;
            }
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(entry.path());
            } else if meta.is_file() {
                checked += 1;
                if let Err(e) = fs::File::open(entry.path()) {
                    errors.push(format!("{}: {}", entry.path().display(), e));
                }
            }
        }
    }
    (checked, errors)
}

// ---------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------

fn split_list(s: &str, sep: char) -> Vec<String> {
    s.split(sep)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Boolean argument; accepts true/false, 1/0, yes/no.
fn arg_flag(args: &Args, key: &str, default: bool) -> bool {
    match args.get(key).map(|s| s.trim().to_ascii_lowercase()) {
        Some(v) if matches!(v.as_str(), "true" | "1" | "yes" | "on") => true,
        Some(v) if matches!(v.as_str(), "false" | "0" | "no" | "off") => false,
        _ => default,
    }
}

fn arg_timeout(args: &Args, default: u64) -> u64 {
    args.get("timeout_ms")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(default)
}

fn arg_u32(args: &Args, key: &str) -> std::result::Result<Option<u32>, String> {
    match args.get(key) {
        None => Ok(None),
        Some(v) => v
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| format!("{} must be a non-negative integer, got {:?}", key, v)),
    }
}

fn truncate_output(s: &str) -> String {
    if s.len() <= MAX_OUTPUT_SIZE {
        return s.to_string();
    }
    let mut end = MAX_OUTPUT_SIZE;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...[TRUNCATED]", &s[..end])
}

/// Per-call envelope settings.
struct Reply {
    verb: &'static str,
    pretty: bool,
    dry_run: bool,
    start: Instant,
}

impl Reply {
    fn new(verb: &'static str, args: &Args, dry_run: bool) -> Self {
        Reply {
            verb,
            pretty: arg_flag(args, "json_pretty", false),
            dry_run,
            start: Instant::now(),
        }
    }

    fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

impl BackupHandle {
    /// Create a new BackupHandle from a URL per specification
    pub fn from_url(url: Url) -> Result<Self> {
        // The documented form `backup://<profile>` puts the profile in the
        // URL host; `backup:///<profile>` puts it in the path. Both name the
        // same profile, and `backup://<profile>/<sub>` joins them.
        let decode = |s: &str| -> Result<String> {
            Ok(percent_decode_str(s)
                .decode_utf8()
                .context("Invalid UTF-8 in repository path")?
                .into_owned())
        };
        let host = url
            .host_str()
            .filter(|h| !h.is_empty())
            .map(decode)
            .transpose()?;
        let path = url.path().strip_prefix('/').unwrap_or(url.path());
        let path = if path.is_empty() {
            None
        } else {
            Some(decode(path)?)
        };
        let repo = match (host, path) {
            (Some(h), Some(p)) => format!("{}/{}", h, p),
            (Some(h), None) => h,
            (None, Some(p)) => p,
            (None, None) => "default".to_string(),
        };

        Ok(BackupHandle {
            repo,
            target: url.to_string(),
        })
    }

    /// Get capabilities for a specific backend per specification
    fn get_capabilities(&self, backend: &BackendType) -> BackupCapabilities {
        match backend {
            BackendType::Restic => BackupCapabilities {
                incremental: true,
                dedup: true,
                encryption: true,
                retention: true,
                verify: true,
                cloud_targets: vec![
                    "s3".to_string(),
                    "azure".to_string(),
                    "gcs".to_string(),
                    "file".to_string(),
                ],
            },
            BackendType::Borg => BackupCapabilities {
                incremental: true,
                dedup: true,
                encryption: true,
                retention: true,
                verify: true,
                cloud_targets: vec!["file".to_string()], // Borg primarily file-based
            },
            BackendType::Rsync => BackupCapabilities {
                incremental: true, // Limited with link-dest
                dedup: false,
                encryption: false, // Unless external
                retention: true,   // Limited
                verify: true,      // Limited
                cloud_targets: vec!["file".to_string()],
            },
            BackendType::Tar => BackupCapabilities {
                incremental: true, // Limited with --listed-incremental
                dedup: false,
                encryption: false, // Unless external
                retention: true,   // Limited
                verify: true,      // Limited
                cloud_targets: vec!["file".to_string()],
            },
        }
    }

    /// Auto-select backend based on availability per specification
    fn select_backend(&self, requested: &str) -> Result<BackendType> {
        if requested != "auto" {
            return match requested {
                "restic" => Ok(BackendType::Restic),
                "borg" => Ok(BackendType::Borg),
                "rsync" => Ok(BackendType::Rsync),
                "tar" => Ok(BackendType::Tar),
                _ => bail!("Unknown backend: {}", requested),
            };
        }

        // Auto-selection order per specification: restic, borg, rsync, tar
        for backend in &["restic", "borg", "rsync", "tar"] {
            if which::which(backend).is_ok() {
                return self.select_backend(backend);
            }
        }

        bail!("No supported backend found. Install one of: restic, borg, rsync, tar")
    }

    /// Repository password for restic/borg from args or the process environment.
    fn repo_secret(
        &self,
        backend: &BackendType,
        args: &Args,
    ) -> std::result::Result<RepoSecret, String> {
        resolve_repo_secret(
            backend,
            args,
            |k| std::env::var_os(k).is_some(),
            |p| fs::read_to_string(p),
        )
    }

    /// Execute a backend command with timeout and output capture per specification
    fn execute_backend_command(&self, spec: &CmdSpec, timeout_ms: u64) -> Result<BackendResult> {
        let start = Instant::now();

        if which::which(&spec.program).is_err() {
            bail!("Backend binary '{}' not found in PATH", spec.program);
        }

        let mut cmd = Command::new(&spec.program);
        cmd.args(&spec.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for key in &spec.env_remove {
            cmd.env_remove(key);
        }
        for (key, value) in &spec.env {
            cmd.env(key, value);
        }
        if let Some(cwd) = &spec.cwd {
            cmd.current_dir(cwd);
        }

        let child = cmd.spawn().context("Failed to spawn backend process")?;
        let output = wait_with_deadline(child, Duration::from_millis(timeout_ms))?
            .ok_or_else(|| anyhow::anyhow!("Backend command timed out after {}ms", timeout_ms))?;
        let duration = start.elapsed();

        Ok(BackendResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            duration_ms: duration.as_millis() as u64,
        })
    }

    /// BackendInfo for the envelope; secret environment values are redacted.
    /// `spec` is None for operations done directly on a local repository.
    fn backend_info(
        &self,
        backend: &BackendType,
        spec: Option<&CmdSpec>,
        timeout_ms: u64,
        simulated: bool,
    ) -> BackendInfo {
        let env_redacted = spec
            .map(|s| {
                s.env
                    .iter()
                    .map(|(k, v)| {
                        let v = if is_secret_key(k) {
                            REDACTED.to_string()
                        } else {
                            v.clone()
                        };
                        (k.clone(), v)
                    })
                    .collect()
            })
            .unwrap_or_default();
        BackendInfo {
            id: backend.to_string(),
            version: None,
            command: spec.map(CmdSpec::argv).unwrap_or_default(),
            env_redacted,
            cwd: spec.and_then(|s| s.cwd.clone()),
            timeout_ms,
            simulated,
        }
    }

    fn unknown_backend_info(&self, timeout_ms: u64) -> BackendInfo {
        BackendInfo {
            id: "unknown".to_string(),
            version: None,
            command: vec![],
            env_redacted: HashMap::new(),
            cwd: None,
            timeout_ms,
            simulated: false,
        }
    }

    /// Write envelope to stdout per specification
    fn write_envelope(
        &self,
        envelope: &BackupEnvelope,
        io: &mut IoStreams,
        pretty: bool,
    ) -> Result<()> {
        let json_str = if pretty {
            serde_json::to_string_pretty(envelope)?
        } else {
            serde_json::to_string(envelope)?
        };
        writeln!(io.stdout, "{}", json_str)?;
        Ok(())
    }

    fn ok(
        &self,
        r: &Reply,
        io: &mut IoStreams,
        info: BackendInfo,
        result: Value,
        warnings: Vec<String>,
    ) -> Result<Status> {
        let mut envelope = BackupEnvelope::success(
            r.verb,
            &self.target,
            info,
            result,
            r.dry_run,
            r.elapsed_ms(),
        );
        envelope.warnings = warnings;
        self.write_envelope(&envelope, io, r.pretty)?;
        Ok(Status::success())
    }

    #[allow(clippy::too_many_arguments)]
    fn fail(
        &self,
        r: &Reply,
        io: &mut IoStreams,
        info: BackendInfo,
        kind: &str,
        message: &str,
        details: Option<Value>,
        warnings: Vec<String>,
        code: i32,
    ) -> Result<Status> {
        let error = BackupError {
            kind: kind.to_string(),
            message: message.to_string(),
            details,
        };
        let mut envelope =
            BackupEnvelope::error(r.verb, &self.target, info, error, r.dry_run, r.elapsed_ms());
        envelope.warnings = warnings;
        self.write_envelope(&envelope, io, r.pretty)?;
        Ok(Status::err(
            if code == 0 { 1 } else { code },
            message.to_string(),
        ))
    }

    /// BACKEND_FAILED envelope for a non-zero exit.
    fn fail_exit(
        &self,
        r: &Reply,
        io: &mut IoStreams,
        info: BackendInfo,
        res: &BackendResult,
        warnings: Vec<String>,
    ) -> Result<Status> {
        let details = json!({
            "exit_code": res.exit_code,
            "stderr_tail": self.get_stderr_tail(&res.stderr)
        });
        self.fail(
            r,
            io,
            info,
            "BACKEND_FAILED",
            "Backend command failed",
            Some(details),
            warnings,
            res.exit_code,
        )
    }

    /// TIMEOUT or `kind` envelope for a command that could not be run.
    fn fail_exec(
        &self,
        r: &Reply,
        io: &mut IoStreams,
        info: BackendInfo,
        kind: &str,
        e: anyhow::Error,
        warnings: Vec<String>,
    ) -> Result<Status> {
        let msg = e.to_string();
        let kind = if msg.contains("timed out") {
            "TIMEOUT"
        } else {
            kind
        };
        self.fail(r, io, info, kind, &msg, None, warnings, 1)
    }

    /// Helper method to get stderr tail for error details per specification
    fn get_stderr_tail(&self, stderr: &str) -> String {
        if stderr.len() <= ERROR_TAIL_SIZE {
            return stderr.to_string();
        }
        let mut start = stderr.len() - ERROR_TAIL_SIZE;
        while !stderr.is_char_boundary(start) {
            start += 1;
        }
        format!("...{}", &stderr[start..])
    }
}

/// Resolves the backend, or writes a BACKEND_NOT_FOUND envelope and returns.
macro_rules! select_or_return {
    ($self:ident, $r:ident, $io:ident, $args:ident, $timeout:expr) => {{
        let name = $args.get("backend").map(String::as_str).unwrap_or("auto");
        match $self.select_backend(name) {
            Ok(b) => b,
            Err(e) => {
                let info = $self.unknown_backend_info($timeout);
                return $self.fail(
                    &$r,
                    $io,
                    info,
                    "BACKEND_NOT_FOUND",
                    &e.to_string(),
                    None,
                    vec![],
                    1,
                );
            }
        }
    }};
}

/// Writes an INVALID_ARGS envelope (before anything runs) and returns when
/// the backend needs `repo_url` and none was given.
macro_rules! repo_or_return {
    ($self:ident, $r:ident, $io:ident, $args:ident, $backend:expr, $timeout:expr) => {{
        if let Some(msg) = repo_url_required(&$backend, $args) {
            let info = $self.backend_info(&$backend, None, $timeout, $r.dry_run);
            return $self.fail(&$r, $io, info, "INVALID_ARGS", &msg, None, vec![], 1);
        }
    }};
}

/// Writes an INVALID_ARGS envelope (before anything runs or a dry-run plan
/// is reported) and returns when a caller value is unsafe for the backend
/// command line.
macro_rules! validated_or_return {
    ($self:ident, $r:ident, $io:ident, $args:ident, $backend:expr, $timeout:expr) => {{
        if let Err(e) = validate_request(&$backend, $r.verb, $args) {
            let info = $self.backend_info(&$backend, None, $timeout, $r.dry_run);
            let details = json!({ "field": e.field });
            return $self.fail(
                &$r,
                $io,
                info,
                "INVALID_ARGS",
                &e.message,
                Some(details),
                vec![],
                1,
            );
        }
    }};
}

/// Adds the repository password to `spec`, or writes a MISSING_PASSWORD
/// envelope (before anything runs) and returns.
macro_rules! secret_or_return {
    ($self:ident, $r:ident, $io:ident, $args:ident, $backend:expr, $spec:expr, $timeout:expr) => {{
        match $self.repo_secret(&$backend, $args) {
            Ok(secret) => secret.apply(&mut $spec),
            Err(msg) => {
                let info = $self.backend_info(&$backend, Some(&$spec), $timeout, $r.dry_run);
                return $self.fail(&$r, $io, info, "MISSING_PASSWORD", &msg, None, vec![], 1);
            }
        }
    }};
}

// Verb implementations per specification
impl BackupHandle {
    /// Create backup snapshot per specification
    fn verb_create(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let src = args
            .get("src")
            .ok_or_else(|| anyhow::anyhow!("Missing required argument: src"))?;
        let timeout_ms = arg_timeout(args, DEFAULT_CREATE_TIMEOUT_MS);
        let r = Reply::new("create", args, crate::core::lenient::dry_run(args)?);
        let backend = select_or_return!(self, r, io, args, timeout_ms);
        repo_or_return!(self, r, io, args, backend, timeout_ms);
        validated_or_return!(self, r, io, args, backend, timeout_ms);

        let sources = split_list(src, ';');
        let mut tags = args
            .get("tag")
            .map(|t| split_list(t, ';'))
            .unwrap_or_default();
        tags.sort();
        let exclude = args
            .get("exclude")
            .map(|e| split_list(e, ';'))
            .unwrap_or_default();
        let label = args.get("label").cloned();
        let repo_url = args.get("repo_url");
        let name = snapshot_name(
            label.as_deref(),
            &Utc::now().format("%Y%m%d_%H%M%S").to_string(),
        );

        // (command, snapshot id known in advance, repo dir to create, tar archive)
        let (mut spec, known_id, repo_dir, archive) = match backend {
            BackendType::Tar => {
                let repo = local_repo_path(repo_url);
                let archive = format!("{}/{}.tar.gz", repo, name);
                (
                    build_tar_create(&archive, &sources, &exclude),
                    Some(name.clone()),
                    Some(repo),
                    Some(archive),
                )
            }
            BackendType::Restic => (
                build_restic_create(repo_url, &sources, &tags, label.as_deref(), &exclude),
                None,
                None,
                None,
            ),
            BackendType::Borg => (
                build_borg_create(&borg_repo(repo_url), &name, &sources, &exclude),
                Some(name.clone()),
                None,
                None,
            ),
            BackendType::Rsync => {
                let repo = local_repo_path(repo_url);
                let dest = format!("{}/{}/", repo, name);
                (
                    build_rsync_create(&dest, &sources, &exclude),
                    Some(name.clone()),
                    Some(repo),
                    None,
                )
            }
        };
        secret_or_return!(self, r, io, args, backend, spec, timeout_ms);

        let mut warnings = Vec::new();
        let capabilities = self.get_capabilities(&backend);
        let info = self.backend_info(&backend, Some(&spec), timeout_ms, r.dry_run);

        if r.dry_run {
            let snapshot = SnapshotInfo {
                id: "dry-run-id".to_string(),
                label: label.clone(),
                tags: tags.clone(),
                created_at: Utc::now().to_rfc3339(),
                sources: sources.clone(),
                bytes_sent: None,
                bytes_total: None,
            };
            let result = json!({
                "capabilities": capabilities,
                "snapshot": snapshot,
                "backend_raw": { "stdout": "", "stderr": "" },
                "dry_run_mode": "plan"
            });
            warnings.push("Dry run: no backup was created".to_string());
            return self.ok(&r, io, info, result, warnings);
        }

        if let Some(dir) = &repo_dir {
            if let Err(e) = fs::create_dir_all(dir) {
                let msg = format!("Failed to create repository directory {}: {}", dir, e);
                return self.fail(&r, io, info, "IO", &msg, None, warnings, 1);
            }
        }

        let res = match self.execute_backend_command(&spec, timeout_ms) {
            Ok(res) => res,
            Err(e) => return self.fail_exec(&r, io, info, "IO", e, warnings),
        };
        if res.exit_code != 0 {
            match create_exit_warning(&backend, res.exit_code) {
                Some(w) => warnings.push(w.to_string()),
                None => return self.fail_exit(&r, io, info, &res, warnings),
            }
        }

        // The backup has been written: report success even if the output
        // cannot be parsed.
        let mut snapshot = parse_create_output(
            &backend,
            &res.stdout,
            known_id.as_deref(),
            &sources,
            &tags,
            label.as_deref(),
        );
        if let (Some(snap), Some(archive)) = (snapshot.as_mut(), &archive) {
            snap.bytes_total = fs::metadata(archive).ok().map(|m| m.len());
        }
        if snapshot.is_none() {
            warnings.push(format!(
                "Backup completed, but no snapshot id was found in the {} output; see result.backend_raw",
                backend
            ));
        }

        let result = json!({
            "capabilities": capabilities,
            "snapshot": snapshot,
            "backend_raw": {
                "stdout": truncate_output(&res.stdout),
                "stderr": truncate_output(&res.stderr)
            }
        });
        self.ok(&r, io, info, result, warnings)
    }

    /// List backup snapshots per specification
    fn verb_list(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let timeout_ms = arg_timeout(args, DEFAULT_LIST_TIMEOUT_MS);
        let r = Reply::new("list", args, false);
        let backend = select_or_return!(self, r, io, args, timeout_ms);
        repo_or_return!(self, r, io, args, backend, timeout_ms);
        validated_or_return!(self, r, io, args, backend, timeout_ms);
        let repo_url = args.get("repo_url");
        let mut tags = args
            .get("tag")
            .map(|t| split_list(t, ';'))
            .unwrap_or_default();
        tags.sort();
        let capabilities = self.get_capabilities(&backend);

        let mut spec = match backend {
            BackendType::Restic => build_restic_list(repo_url, &tags),
            BackendType::Borg => build_borg_list(&borg_repo(repo_url)),
            BackendType::Tar | BackendType::Rsync => {
                let repo = local_repo_path(repo_url);
                let info = self.backend_info(&backend, None, timeout_ms, false);
                let snaps = match scan_local_snapshots(&backend, Path::new(&repo), false) {
                    Ok(s) => s,
                    Err(e) => {
                        let msg = format!("Cannot read repository directory {}: {}", repo, e);
                        return self.fail(&r, io, info, "IO", &msg, None, vec![], 1);
                    }
                };
                let snapshots: Vec<SnapshotInfo> = snaps
                    .into_iter()
                    .map(|s| SnapshotInfo {
                        id: s.id,
                        label: None,
                        tags: vec![],
                        created_at: s.modified.to_rfc3339(),
                        sources: vec![],
                        bytes_sent: None,
                        bytes_total: s.bytes,
                    })
                    .collect();
                let result = json!({
                    "snapshots": snapshots,
                    "total_count": snapshots.len(),
                    "capabilities": capabilities
                });
                return self.ok(&r, io, info, result, vec![]);
            }
        };
        secret_or_return!(self, r, io, args, backend, spec, timeout_ms);
        let info = self.backend_info(&backend, Some(&spec), timeout_ms, false);

        let res = match self.execute_backend_command(&spec, timeout_ms) {
            Ok(res) => res,
            Err(e) => return self.fail_exec(&r, io, info, "EXECUTION_FAILED", e, vec![]),
        };
        if res.exit_code != 0 {
            return self.fail_exit(&r, io, info, &res, vec![]);
        }
        let snapshots = match parse_list_output(&backend, &res.stdout) {
            Ok(s) => s,
            Err(e) => {
                return self.fail(&r, io, info, "PARSE", &format!("{:#}", e), None, vec![], 1);
            }
        };
        let result = json!({
            "snapshots": snapshots,
            "total_count": snapshots.len(),
            "capabilities": capabilities
        });
        self.ok(&r, io, info, result, vec![])
    }

    /// Restore backup snapshot per specification
    fn verb_restore(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let snapshot_id = args
            .get("snapshot_id")
            .ok_or_else(|| anyhow::anyhow!("Missing required argument: snapshot_id"))?;
        let dest = args
            .get("dest")
            .ok_or_else(|| anyhow::anyhow!("Missing required argument: dest"))?;
        let timeout_ms = arg_timeout(args, DEFAULT_RESTORE_TIMEOUT_MS);
        // restore has no dry-run mode. A dry-run request must never become a
        // real restore over `dest`, so it is refused before anything runs.
        if crate::core::lenient::dry_run(args)? {
            anyhow::bail!("backup restore does not support dry_run; nothing was restored");
        }
        let r = Reply::new("restore", args, false);
        let backend = select_or_return!(self, r, io, args, timeout_ms);
        repo_or_return!(self, r, io, args, backend, timeout_ms);
        validated_or_return!(self, r, io, args, backend, timeout_ms);

        let repo_url = args.get("repo_url");
        let include = args
            .get("include")
            .map(|i| split_list(i, ','))
            .unwrap_or_default();
        let exclude = args
            .get("exclude")
            .map(|e| split_list(e, ';'))
            .unwrap_or_default();
        let mut warnings = Vec::new();
        if !include.is_empty() && backend != BackendType::Restic {
            warnings.push(format!(
                "include is only supported by restic; {} restores the whole snapshot",
                backend
            ));
        }

        let mut spec = match backend {
            BackendType::Restic => {
                build_restic_restore(repo_url, snapshot_id, dest, &include, &exclude)
            }
            BackendType::Borg => {
                build_borg_restore(&borg_repo(repo_url), snapshot_id, dest, &exclude)
            }
            BackendType::Tar => {
                let repo = local_repo_path(repo_url);
                build_tar_restore(&format!("{}/{}.tar.gz", repo, snapshot_id), dest, &exclude)
            }
            BackendType::Rsync => {
                let repo = local_repo_path(repo_url);
                build_rsync_restore(&format!("{}/{}/", repo, snapshot_id), dest, &exclude)
            }
        };
        secret_or_return!(self, r, io, args, backend, spec, timeout_ms);
        let info = self.backend_info(&backend, Some(&spec), timeout_ms, false);

        // borg extracts into its working directory and tar -C needs an
        // existing directory.
        if matches!(backend, BackendType::Borg | BackendType::Tar) {
            if let Err(e) = fs::create_dir_all(dest) {
                let msg = format!("Failed to create destination directory {}: {}", dest, e);
                return self.fail(&r, io, info, "IO", &msg, None, warnings, 1);
            }
        }

        let res = match self.execute_backend_command(&spec, timeout_ms) {
            Ok(res) => res,
            Err(e) => return self.fail_exec(&r, io, info, "EXECUTION_FAILED", e, warnings),
        };
        if res.exit_code != 0 {
            return self.fail_exit(&r, io, info, &res, warnings);
        }
        let result = json!({
            "restored": parse_restore_output(&backend, &res.stdout),
            "snapshot_id": snapshot_id,
            "destination": dest,
            "capabilities": self.get_capabilities(&backend)
        });
        self.ok(&r, io, info, result, warnings)
    }

    /// Verify backup integrity per specification
    fn verb_verify(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let timeout_ms = arg_timeout(args, DEFAULT_VERIFY_TIMEOUT_MS);
        let r = Reply::new("verify", args, false);
        let backend = select_or_return!(self, r, io, args, timeout_ms);
        repo_or_return!(self, r, io, args, backend, timeout_ms);
        validated_or_return!(self, r, io, args, backend, timeout_ms);
        let mode = args
            .get("mode")
            .cloned()
            .unwrap_or_else(|| "quick".to_string());
        let repo_url = args.get("repo_url");
        let read_data = mode == "thorough" || mode == "data";
        let capabilities = self.get_capabilities(&backend);

        let verification = match backend {
            BackendType::Restic | BackendType::Borg => {
                let mut spec = if backend == BackendType::Restic {
                    build_restic_verify(repo_url, read_data)
                } else {
                    build_borg_verify(&borg_repo(repo_url), read_data)
                };
                secret_or_return!(self, r, io, args, backend, spec, timeout_ms);
                let info = self.backend_info(&backend, Some(&spec), timeout_ms, false);
                let res = match self.execute_backend_command(&spec, timeout_ms) {
                    Ok(res) => res,
                    Err(e) => return self.fail_exec(&r, io, info, "EXECUTION_FAILED", e, vec![]),
                };
                if res.exit_code != 0 {
                    return self.fail_exit(&r, io, info, &res, vec![]);
                }
                let files_checked = if backend == BackendType::Restic {
                    res.stdout.lines().count()
                } else {
                    0
                };
                let verification = json!({
                    "success": true,
                    "issues": Vec::<String>::new(),
                    "files_checked": files_checked,
                    "errors": Vec::<String>::new()
                });
                (info, verification)
            }
            BackendType::Tar => {
                let repo = local_repo_path(repo_url);
                let mut info = self.backend_info(&backend, None, timeout_ms, false);
                let archives = match scan_local_snapshots(&backend, Path::new(&repo), false) {
                    Ok(a) => a,
                    Err(e) => {
                        let msg = format!("Cannot read repository directory {}: {}", repo, e);
                        return self.fail(&r, io, info, "IO", &msg, None, vec![], 1);
                    }
                };
                let mut files_checked = 0;
                let mut issues = Vec::new();
                let mut errors = Vec::new();
                let mut checked = Vec::new();
                for a in &archives {
                    let spec = build_tar_verify(&a.path.to_string_lossy());
                    info.command = spec.argv();
                    match self.execute_backend_command(&spec, timeout_ms) {
                        Ok(res) if res.exit_code == 0 => {
                            let members = res.stdout.lines().count();
                            files_checked += members;
                            checked.push(json!({ "id": a.id, "ok": true, "members": members }));
                        }
                        Ok(res) => {
                            issues.push(format!("{}: tar exited with {}", a.id, res.exit_code));
                            errors.push(self.get_stderr_tail(&res.stderr));
                            checked.push(json!({ "id": a.id, "ok": false, "members": 0 }));
                        }
                        Err(e) => {
                            return self.fail_exec(&r, io, info, "EXECUTION_FAILED", e, vec![]);
                        }
                    }
                }
                if archives.is_empty() {
                    issues.push(format!("no .tar.gz archives found in {}", repo));
                }
                let verification = json!({
                    "success": issues.is_empty(),
                    "issues": issues,
                    "files_checked": files_checked,
                    "errors": errors,
                    "archives": checked
                });
                (info, verification)
            }
            BackendType::Rsync => {
                let repo = local_repo_path(repo_url);
                let info = self.backend_info(&backend, None, timeout_ms, false);
                if !Path::new(&repo).is_dir() {
                    let msg = format!("Repository directory {} does not exist", repo);
                    return self.fail(&r, io, info, "IO", &msg, None, vec![], 1);
                }
                let (files_checked, errors) = check_files_readable(Path::new(&repo));
                let issues: Vec<String> = if errors.is_empty() {
                    vec![]
                } else {
                    vec!["File access issues found".to_string()]
                };
                let verification = json!({
                    "success": errors.is_empty(),
                    "issues": issues,
                    "files_checked": files_checked,
                    "errors": errors
                });
                (info, verification)
            }
        };
        let (info, verification) = verification;

        if verification["success"] != json!(true) {
            return self.fail(
                &r,
                io,
                info,
                "VERIFY_FAILED",
                "Backup verification found problems",
                Some(verification),
                vec![],
                1,
            );
        }
        let result = json!({
            "verification": verification,
            "mode": mode,
            "snapshot_id": args.get("snapshot_id"),
            "capabilities": capabilities
        });
        self.ok(&r, io, info, result, vec![])
    }

    /// Prune old snapshots per specification
    fn verb_prune(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let timeout_ms = arg_timeout(args, DEFAULT_PRUNE_TIMEOUT_MS);
        let r = Reply::new("prune", args, crate::core::lenient::dry_run(args)?);
        let backend = select_or_return!(self, r, io, args, timeout_ms);
        repo_or_return!(self, r, io, args, backend, timeout_ms);
        validated_or_return!(self, r, io, args, backend, timeout_ms);
        let repo_url = args.get("repo_url");
        let capabilities = self.get_capabilities(&backend);

        let mut policy = RetentionPolicy::default();
        for (key, slot) in [
            ("keep_daily", &mut policy.keep_daily),
            ("keep_weekly", &mut policy.keep_weekly),
            ("keep_monthly", &mut policy.keep_monthly),
        ] {
            match arg_u32(args, key) {
                Ok(v) => *slot = v,
                Err(msg) => {
                    let info = self.backend_info(&backend, None, timeout_ms, r.dry_run);
                    return self.fail(&r, io, info, "INVALID_ARGS", &msg, None, vec![], 1);
                }
            }
        }
        let policy_json = json!({
            "keep_daily": policy.keep_daily,
            "keep_weekly": policy.keep_weekly,
            "keep_monthly": policy.keep_monthly
        });
        if policy.keep_daily.is_none()
            && policy.keep_weekly.is_none()
            && policy.keep_monthly.is_none()
        {
            let info = self.backend_info(&backend, None, timeout_ms, r.dry_run);
            let msg = "prune needs at least one of keep_daily, keep_weekly, keep_monthly";
            return self.fail(&r, io, info, "INVALID_ARGS", msg, None, vec![], 1);
        }
        let stats_key = if r.dry_run { "would_prune" } else { "pruned" };
        let mut warnings = Vec::new();

        match backend {
            BackendType::Restic | BackendType::Borg => {
                let mut spec = if backend == BackendType::Restic {
                    build_restic_prune(repo_url, &policy, r.dry_run)
                } else {
                    build_borg_prune(&borg_repo(repo_url), &policy, r.dry_run)
                };
                secret_or_return!(self, r, io, args, backend, spec, timeout_ms);
                let info = self.backend_info(&backend, Some(&spec), timeout_ms, false);
                let res = match self.execute_backend_command(&spec, timeout_ms) {
                    Ok(res) => res,
                    Err(e) => return self.fail_exec(&r, io, info, "EXECUTION_FAILED", e, warnings),
                };
                if res.exit_code != 0 {
                    return self.fail_exit(&r, io, info, &res, warnings);
                }
                let removed = parse_prune_count(&backend, &res.stdout, &res.stderr);
                if removed.is_none() {
                    warnings.push(format!(
                        "could not count removed snapshots in the {} output",
                        backend
                    ));
                }
                let mut result = json!({
                    "dry_run": r.dry_run,
                    "policy": policy_json,
                    "capabilities": capabilities
                });
                if r.dry_run {
                    // Only the backend can apply its retention policy to its
                    // repository, so this dry run runs it with its own
                    // --dry-run flag (documented in backup.md 4.5).
                    result["dry_run_mode"] = json!("backend");
                    warnings.push(format!(
                        "Dry run: {} ran in its own --dry-run mode; nothing was removed",
                        backend
                    ));
                }
                result[stats_key] = json!({
                    "snapshots_removed": removed,
                    "bytes_freed": null,
                    "success": true
                });
                self.ok(&r, io, info, result, warnings)
            }
            BackendType::Tar | BackendType::Rsync => {
                let repo = local_repo_path(repo_url);
                let info = self.backend_info(&backend, None, timeout_ms, false);
                let snaps = match scan_local_snapshots(&backend, Path::new(&repo), true) {
                    Ok(s) => s,
                    Err(e) => {
                        let msg = format!("Cannot read repository directory {}: {}", repo, e);
                        return self.fail(&r, io, info, "IO", &msg, None, warnings, 1);
                    }
                };
                let pairs: Vec<(String, DateTime<Utc>)> =
                    snaps.iter().map(|s| (s.id.clone(), s.modified)).collect();
                let to_remove = select_prune(&pairs, &policy);

                let mut removed = Vec::new();
                let mut bytes_freed = 0u64;
                let mut errors = Vec::new();
                for s in snaps.iter().filter(|s| to_remove.contains(&s.id)) {
                    let outcome = if r.dry_run {
                        Ok(())
                    } else if backend == BackendType::Tar {
                        fs::remove_file(&s.path)
                    } else {
                        fs::remove_dir_all(&s.path)
                    };
                    match outcome {
                        Ok(()) => {
                            removed.push(s.id.clone());
                            bytes_freed += s.bytes.unwrap_or(0);
                        }
                        Err(e) => errors.push(format!("{}: {}", s.path.display(), e)),
                    }
                }
                let stats = json!({
                    "snapshots_removed": removed.len(),
                    "bytes_freed": bytes_freed,
                    "removed": removed,
                    "success": errors.is_empty()
                });
                if !errors.is_empty() {
                    let details = json!({ stats_key: stats, "errors": errors });
                    return self.fail(
                        &r,
                        io,
                        info,
                        "IO",
                        "Some snapshots could not be removed",
                        Some(details),
                        warnings,
                        1,
                    );
                }
                let mut result = json!({
                    "dry_run": r.dry_run,
                    "policy": policy_json,
                    "capabilities": capabilities
                });
                if r.dry_run {
                    result["dry_run_mode"] = json!("plan");
                }
                result[stats_key] = stats;
                self.ok(&r, io, info, result, warnings)
            }
        }
    }

    /// Schedule automated backups per specification
    fn verb_schedule(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let when = args
            .get("when")
            .ok_or_else(|| anyhow::anyhow!("Missing required argument: when"))?;
        let _src = args
            .get("src")
            .ok_or_else(|| anyhow::anyhow!("Missing required argument: src"))?;
        let enabled = arg_flag(args, "enabled", true);
        let timeout_ms = arg_timeout(args, DEFAULT_SCHEDULE_TIMEOUT_MS);
        let r = Reply::new("schedule", args, false);
        let backend = select_or_return!(self, r, io, args, timeout_ms);

        let mut warnings = Vec::new();

        // Determine runner type per specification
        let runner = if which::which("systemctl").is_ok() {
            "systemd"
        } else if which::which("crontab").is_ok() {
            "cron"
        } else {
            warnings.push("No supported scheduler found (systemd/cron)".to_string());
            "none"
        };

        // Generate schedule definition path per specification
        let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let definition_path = format!("{}/resh-backup-{}.json", home_dir, &self.repo);

        let spec = CmdSpec::new(&backend.to_string());
        let info = self.backend_info(&backend, Some(&spec), timeout_ms, false);
        let result = json!({
            "capabilities": self.get_capabilities(&backend),
            "schedule": {
                "when": when,
                "enabled": enabled,
                "runner": runner,
                "definition_path": definition_path
            }
        });
        self.ok(&r, io, info, result, warnings)
    }
}

impl BackupHandle {
    /// True for an in-URL or argument help request. Exact matches only, so a
    /// profile or verb merely containing "-h" is not a help request.
    fn should_show_help(verb: &str, args: &Args) -> bool {
        verb == "help"
            || help::is_help_flag(verb)
            || verb.starts_with("--help=")
            || ["help", "h", "--help", "-h"]
                .iter()
                .any(|k| args.contains_key(*k))
    }

    /// The verb a help request names (`--help=create`, or `verb=create`).
    fn help_verb<'a>(verb: &'a str, args: &'a Args) -> Option<&'a str> {
        verb.strip_prefix("--help=")
            .or_else(|| args.get("verb").map(String::as_str))
    }
}

/// Register the backup handle with the registry per specification
pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("backup", |u| {
        Ok(Box::new(BackupHandle::from_url(u.clone())?))
    });
}

impl Handle for BackupHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["create", "list", "restore", "verify", "prune", "schedule"]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&BACKUP_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        if Self::should_show_help(verb, args) {
            let text = help::render_legacy(
                "backup",
                &BACKUP_HELP,
                self.verbs(),
                Self::help_verb(verb, args),
            );
            write!(io.stdout, "{}", text)?;
            return Ok(Status::success());
        }

        match verb {
            "create" => self.verb_create(args, io),
            "list" => self.verb_list(args, io),
            "restore" => self.verb_restore(args, io),
            "verify" => self.verb_verify(args, io),
            "prune" => self.verb_prune(args, io),
            "schedule" => self.verb_schedule(args, io),
            _ => bail!("unknown verb for backup://: {}", verb),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn args(kv: &[(&str, &str)]) -> Args {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn handle(url: &str) -> BackupHandle {
        BackupHandle::from_url(Url::parse(url).unwrap()).unwrap()
    }

    fn call(h: &BackupHandle, verb: &str, a: &Args) -> (Status, String) {
        let mut stdin = std::io::empty();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let status = {
            let mut io = IoStreams {
                stdin: &mut stdin,
                stdout: &mut out,
                stderr: &mut err,
            };
            h.call(verb, a, &mut io).unwrap()
        };
        (status, String::from_utf8(out).unwrap())
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("resh_backuph_test_{}_{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    // ---- H4: exact argv for every backend command ----

    #[test]
    fn create_commands_argv() {
        let src = s(&["/etc", "/home"]);
        let ex = s(&["*.tmp"]);
        assert_eq!(
            build_tar_create("/r/backup_1.tar.gz", &src, &ex).argv(),
            s(&[
                "tar",
                "--force-local",
                "-czf",
                "/r/backup_1.tar.gz",
                "--exclude=*.tmp",
                "--",
                "/etc",
                "/home"
            ])
        );
        let repo = "/srv/restic".to_string();
        let c = build_restic_create(Some(&repo), &src, &s(&["daily"]), Some("web01"), &ex);
        assert_eq!(
            c.argv(),
            s(&[
                "restic",
                "backup",
                "--tag=daily",
                "--hostname=web01",
                "--exclude=*.tmp",
                "--json",
                "--",
                "/etc",
                "/home"
            ])
        );
        assert_eq!(c.env.get("RESTIC_REPOSITORY"), Some(&repo));
        assert_eq!(
            build_borg_create("/srv/borg", "backup_1", &src, &ex).argv(),
            s(&[
                "borg",
                "create",
                "--json",
                "--compression",
                "lz4",
                "--exclude=*.tmp",
                "--",
                "/srv/borg::backup_1",
                "/etc",
                "/home"
            ])
        );
        assert_eq!(
            build_rsync_create("/r/backup_1/", &src, &ex).argv(),
            s(&[
                "rsync",
                "-a",
                "--stats",
                "--exclude=*.tmp",
                "--",
                "/etc",
                "/home",
                "/r/backup_1/"
            ])
        );
    }

    #[test]
    fn list_restore_verify_prune_argv() {
        let repo = "/srv/restic".to_string();
        assert_eq!(
            build_restic_list(Some(&repo), &s(&["a"])).argv(),
            s(&["restic", "snapshots", "--json", "--tag=a"])
        );
        assert_eq!(
            build_borg_list("/b").argv(),
            s(&["borg", "list", "--json", "--", "/b"])
        );

        assert_eq!(
            build_restic_restore(None, "4f2a", "/tmp/r", &s(&["*.conf"]), &s(&["*.tmp"])).argv(),
            s(&[
                "restic",
                "restore",
                "--target=/tmp/r",
                "--include=*.conf",
                "--exclude=*.tmp",
                "--",
                "4f2a"
            ])
        );
        let b = build_borg_restore("/b", "backup_1", "/tmp/r", &[]);
        assert_eq!(b.argv(), s(&["borg", "extract", "--", "/b::backup_1"]));
        assert_eq!(b.cwd.as_deref(), Some("/tmp/r"));
        assert_eq!(
            build_tar_restore("/r/backup_1.tar.gz", "/tmp/r", &[]).argv(),
            s(&[
                "tar",
                "--force-local",
                "-xzf",
                "/r/backup_1.tar.gz",
                "-C",
                "/tmp/r"
            ])
        );
        assert_eq!(
            build_rsync_restore("/r/backup_1/", "/tmp/r", &[]).argv(),
            s(&["rsync", "-av", "--", "/r/backup_1/", "/tmp/r"])
        );

        assert_eq!(
            build_restic_verify(None, false).argv(),
            s(&["restic", "check"])
        );
        assert_eq!(
            build_restic_verify(None, true).argv(),
            s(&["restic", "check", "--read-data"])
        );
        assert_eq!(
            build_borg_verify("/b", true).argv(),
            s(&["borg", "check", "--verify-data", "--", "/b"])
        );
        assert_eq!(
            build_tar_verify("/r/a.tar.gz").argv(),
            s(&["tar", "--force-local", "-tzf", "/r/a.tar.gz"])
        );

        let p = RetentionPolicy {
            keep_daily: Some(7),
            keep_monthly: Some(12),
            ..Default::default()
        };
        assert_eq!(
            build_restic_prune(None, &p, true).argv(),
            s(&[
                "restic",
                "forget",
                "--json",
                "--keep-daily",
                "7",
                "--keep-monthly",
                "12",
                "--dry-run"
            ])
        );
        assert_eq!(
            build_restic_prune(None, &p, false).argv(),
            s(&[
                "restic",
                "forget",
                "--json",
                "--keep-daily",
                "7",
                "--keep-monthly",
                "12",
                "--prune"
            ])
        );
        assert_eq!(
            build_borg_prune("/b", &p, true).argv(),
            s(&[
                "borg",
                "prune",
                "--list",
                "--keep-daily",
                "7",
                "--keep-monthly",
                "12",
                "--dry-run",
                "--",
                "/b"
            ])
        );
        assert_eq!(
            build_borg_prune("/b", &p, false).argv(),
            s(&[
                "borg",
                "prune",
                "--list",
                "--keep-daily",
                "7",
                "--keep-monthly",
                "12",
                "--stats",
                "--",
                "/b"
            ])
        );
    }

    #[test]
    fn snapshot_name_sanitizes_label() {
        assert_eq!(
            snapshot_name(None, "20261016_091244"),
            "backup_20261016_091244"
        );
        assert_eq!(snapshot_name(Some("daily run"), "T"), "daily_run_T");
        assert_eq!(snapshot_name(Some("../etc"), "T"), ".._etc_T");
    }

    #[test]
    fn local_repo_path_strips_file_scheme() {
        assert_eq!(
            local_repo_path(Some(&"file:///srv/b".to_string())),
            "/srv/b"
        );
        assert_eq!(local_repo_path(Some(&"/srv/b".to_string())), "/srv/b");
    }

    // ---- C1: repository password ----

    fn no_env(_: &str) -> bool {
        false
    }

    fn no_file(_: &str) -> std::io::Result<String> {
        Err(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"))
    }

    #[test]
    fn restic_password_sources() {
        let r = resolve_repo_secret(
            &BackendType::Restic,
            &args(&[("password", "s3cr3t")]),
            no_env,
            no_file,
        )
        .unwrap();
        assert_eq!(
            r.set.get("RESTIC_PASSWORD").map(String::as_str),
            Some("s3cr3t")
        );
        assert!(r.remove.contains(&"RESTIC_PASSWORD_FILE".to_string()));

        let r = resolve_repo_secret(
            &BackendType::Restic,
            &args(&[("password_file", "/k")]),
            no_env,
            no_file,
        )
        .unwrap();
        assert_eq!(
            r.set.get("RESTIC_PASSWORD_FILE").map(String::as_str),
            Some("/k")
        );

        let r = resolve_repo_secret(
            &BackendType::Restic,
            &args(&[]),
            |k| k == "RESTIC_PASSWORD_FILE",
            no_file,
        )
        .unwrap();
        assert!(r.set.is_empty());

        let e = resolve_repo_secret(&BackendType::Restic, &args(&[]), no_env, no_file).unwrap_err();
        assert!(
            e.contains("password=") && e.contains("RESTIC_PASSWORD"),
            "{e}"
        );
    }

    #[test]
    fn borg_password_sources() {
        let r = resolve_repo_secret(
            &BackendType::Borg,
            &args(&[("password", "pw")]),
            no_env,
            no_file,
        )
        .unwrap();
        assert_eq!(r.set.get("BORG_PASSPHRASE").map(String::as_str), Some("pw"));

        let r = resolve_repo_secret(
            &BackendType::Borg,
            &args(&[("password_file", "/k")]),
            no_env,
            |_| Ok("pw\n".to_string()),
        )
        .unwrap();
        assert_eq!(r.set.get("BORG_PASSPHRASE").map(String::as_str), Some("pw"));

        let e = resolve_repo_secret(
            &BackendType::Borg,
            &args(&[("password_file", "/k")]),
            no_env,
            no_file,
        )
        .unwrap_err();
        assert!(e.contains("cannot read password_file /k"), "{e}");

        let r = resolve_repo_secret(
            &BackendType::Borg,
            &args(&[]),
            |k| k == "BORG_PASSCOMMAND",
            no_file,
        )
        .unwrap();
        assert!(r.set.is_empty());

        assert!(resolve_repo_secret(&BackendType::Borg, &args(&[]), no_env, no_file).is_err());
        assert_eq!(
            resolve_repo_secret(&BackendType::Tar, &args(&[]), no_env, no_file).unwrap(),
            RepoSecret::default()
        );
    }

    #[test]
    fn no_hard_coded_password_in_commands() {
        let repo = "/r".to_string();
        let p = RetentionPolicy {
            keep_daily: Some(1),
            ..Default::default()
        };
        for spec in [
            build_restic_create(Some(&repo), &s(&["/etc"]), &[], None, &[]),
            build_restic_list(Some(&repo), &[]),
            build_restic_restore(Some(&repo), "x", "/d", &[], &[]),
            build_restic_verify(Some(&repo), false),
            build_restic_prune(Some(&repo), &p, true),
            build_borg_create("/r", "a", &s(&["/etc"]), &[]),
            build_borg_list("/r"),
            build_borg_verify("/r", false),
            build_borg_prune("/r", &p, true),
        ] {
            assert!(!spec.env.keys().any(|k| k.contains("PASS")), "{:?}", spec);
        }
    }

    #[test]
    fn backend_info_redacts_secrets() {
        let h = handle("backup://db");
        let mut spec = build_restic_list(Some(&"/r".to_string()), &[]);
        spec.env.insert("RESTIC_PASSWORD".into(), "hunter2".into());
        spec.env.insert("BORG_PASSPHRASE".into(), "hunter2".into());
        spec.env
            .insert("BORG_PASSCOMMAND".into(), "pass show hunter2".into());
        let info = h.backend_info(&BackendType::Restic, Some(&spec), 1, false);
        let text = serde_json::to_string(&info).unwrap();
        assert!(!text.contains("hunter2"), "{text}");
        assert_eq!(
            info.env_redacted
                .get("RESTIC_REPOSITORY")
                .map(String::as_str),
            Some("/r")
        );
        assert_eq!(
            info.env_redacted
                .get("BORG_PASSCOMMAND")
                .map(String::as_str),
            Some(REDACTED)
        );
    }

    #[test]
    fn restic_without_password_fails_before_running() {
        if RESTIC_SECRET_ENV
            .iter()
            .any(|k| std::env::var_os(k).is_some())
        {
            return; // the test environment supplies a password
        }
        let h = handle("backup://db");
        let a = args(&[
            ("src", "/etc"),
            ("backend", "restic"),
            ("repo_url", "/nonexistent/resh-test"),
        ]);
        let (status, out) = call(&h, "create", &a);
        assert!(!status.ok);
        let v: Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["kind"], "MISSING_PASSWORD");
        assert_eq!(v["backend"]["command"][0], "restic");
    }

    #[test]
    fn password_arg_is_redacted_in_envelope() {
        let h = handle("backup://db");
        let a = args(&[
            ("src", "/etc"),
            ("backend", "restic"),
            ("password", "hunter2"),
            ("dry_run", "true"),
        ]);
        let (status, out) = call(&h, "create", &a);
        assert!(status.ok);
        assert!(!out.contains("hunter2"), "{out}");
        let v: Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["backend"]["env_redacted"]["RESTIC_PASSWORD"], REDACTED);
    }

    // ---- H5: create output parsing ----

    #[test]
    fn parses_restic_summary() {
        let out = concat!(
            r#"{"message_type":"status","percent_done":0.5}"#,
            "\n",
            r#"{"message_type":"summary","files_new":3,"data_added":1200,"total_bytes_processed":5000,"snapshot_id":"4f2a9c1e0011"}"#,
            "\n"
        );
        let snap =
            parse_create_output(&BackendType::Restic, out, None, &s(&["/etc"]), &[], None).unwrap();
        assert_eq!(snap.id, "4f2a9c1e0011");
        assert_eq!(snap.bytes_sent, Some(1200));
        assert_eq!(snap.bytes_total, Some(5000));
        // Unparseable restic output yields no snapshot rather than an error.
        assert!(
            parse_create_output(&BackendType::Restic, "garbage", None, &[], &[], None).is_none()
        );
    }

    #[test]
    fn parses_borg_json() {
        let out = r#"{"archive":{"name":"backup_1","start":"2026-10-16T02:00:04.000000","stats":{"original_size":9000,"deduplicated_size":100}},"repository":{}}"#;
        let snap =
            parse_create_output(&BackendType::Borg, out, Some("backup_1"), &[], &[], None).unwrap();
        assert_eq!(snap.id, "backup_1");
        assert_eq!(snap.created_at, "2026-10-16T02:00:04.000000");
        assert_eq!((snap.bytes_total, snap.bytes_sent), (Some(9000), Some(100)));
        // Non-JSON borg output still reports the known archive name.
        let snap =
            parse_create_output(&BackendType::Borg, "", Some("backup_1"), &[], &[], None).unwrap();
        assert_eq!(snap.id, "backup_1");
    }

    #[test]
    fn parses_rsync_stats() {
        let out = "\nNumber of files: 3 (reg: 2, dir: 1)\nTotal file size: 1,234,567 bytes\nTotal transferred file size: 2,048 bytes\n";
        assert_eq!(parse_rsync_stats(out), (Some(1_234_567), Some(2048)));
        let snap = parse_create_output(&BackendType::Rsync, out, Some("backup_1"), &[], &[], None)
            .unwrap();
        assert_eq!(
            (snap.id.as_str(), snap.bytes_total),
            ("backup_1", Some(1_234_567))
        );
        assert_eq!(parse_rsync_stats("nothing"), (None, None));
    }

    #[test]
    fn warning_exit_codes_count_as_success() {
        assert!(create_exit_warning(&BackendType::Restic, 3).is_some());
        assert!(create_exit_warning(&BackendType::Borg, 1).is_some());
        assert!(create_exit_warning(&BackendType::Rsync, 24).is_some());
        assert!(create_exit_warning(&BackendType::Restic, 1).is_none());
        assert!(create_exit_warning(&BackendType::Borg, 2).is_none());
    }

    // ---- list / prune parsing ----

    #[test]
    fn restic_list_keeps_snapshots_without_tags_or_paths() {
        let out = r#"[{"short_id":"aa","time":"t1","hostname":"h","tags":["x"],"paths":["/etc"]},{"short_id":"bb","time":"t2"}]"#;
        let snaps = parse_list_output(&BackendType::Restic, out).unwrap();
        assert_eq!(snaps.len(), 2);
        assert!(snaps[1].tags.is_empty() && snaps[1].sources.is_empty());
        assert!(
            parse_list_output(&BackendType::Restic, "null")
                .unwrap()
                .is_empty()
        );
        assert!(parse_list_output(&BackendType::Restic, "not json").is_err());
    }

    #[test]
    fn counts_pruned_snapshots() {
        let restic = r#"[{"keep":[{}],"remove":[{},{}]},{"keep":[{}],"remove":null}]"#;
        assert_eq!(parse_prune_count(&BackendType::Restic, restic, ""), Some(2));
        assert_eq!(parse_prune_count(&BackendType::Restic, "text", ""), None);
        let borg = "Keeping archive: a\nWould prune:     b\nWould prune:     c\n";
        assert_eq!(parse_prune_count(&BackendType::Borg, "", borg), Some(2));
    }

    #[test]
    fn select_prune_applies_policy() {
        let t = |d: u32, h: u32| Utc.with_ymd_and_hms(2026, 10, d, h, 0, 0).unwrap();
        let snaps = vec![
            ("d16b".to_string(), t(16, 12)),
            ("d16a".to_string(), t(16, 2)),
            ("d15".to_string(), t(15, 2)),
            ("d14".to_string(), t(14, 2)),
            ("d01".to_string(), t(1, 2)),
        ];
        let daily2 = RetentionPolicy {
            keep_daily: Some(2),
            ..Default::default()
        };
        let mut removed = select_prune(&snaps, &daily2);
        removed.sort();
        assert_eq!(removed, s(&["d01", "d14", "d16a"]));

        let monthly1 = RetentionPolicy {
            keep_monthly: Some(1),
            keep_daily: Some(1),
            ..Default::default()
        };
        let mut removed = select_prune(&snaps, &monthly1);
        removed.sort();
        assert_eq!(removed, s(&["d01", "d14", "d15", "d16a"]));
    }

    #[test]
    fn tar_list_and_prune_use_repository_directory() {
        let dir = temp_dir("tar");
        for name in ["backup_a.tar.gz", "backup_b.tar.gz", "notes.txt"] {
            fs::write(dir.join(name), b"x").unwrap();
        }
        let h = handle("backup://db");
        let repo = dir.to_string_lossy().to_string();

        let (status, out) = call(
            &h,
            "list",
            &args(&[("backend", "tar"), ("repo_url", &repo)]),
        );
        assert!(status.ok, "{out}");
        let v: Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["result"]["total_count"], 2);
        assert_eq!(v["backend"]["command"], json!([]));

        // Dry run keeps both files and reports one removal.
        let a = args(&[
            ("backend", "tar"),
            ("repo_url", &repo),
            ("keep_daily", "1"),
            ("dry_run", "true"),
        ]);
        let (status, out) = call(&h, "prune", &a);
        assert!(status.ok, "{out}");
        let v: Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["result"]["would_prune"]["snapshots_removed"], 1);
        assert!(dir.join("backup_a.tar.gz").exists() && dir.join("backup_b.tar.gz").exists());

        let (status, out) = call(
            &h,
            "prune",
            &args(&[("backend", "tar"), ("repo_url", &repo)]),
        );
        assert!(!status.ok);
        assert!(out.contains("INVALID_ARGS"));

        let _ = fs::remove_dir_all(&dir);
    }

    // ---- L1 / H2: help ----

    #[test]
    fn help_detection_is_exact() {
        let none = Args::new();
        assert!(BackupHandle::should_show_help("help", &none));
        assert!(BackupHandle::should_show_help("--help", &none));
        assert!(BackupHandle::should_show_help("-h", &none));
        assert!(BackupHandle::should_show_help("--help=create", &none));
        assert!(!BackupHandle::should_show_help("create", &none));
        assert!(!BackupHandle::should_show_help("my-host", &none));
        assert!(!BackupHandle::should_show_help("pre-hotfix", &none));
    }

    #[test]
    fn help_uses_approved_metadata() {
        let h = handle("backup://db");
        let (_, out) = call(&h, "help", &Args::new());
        assert!(out.starts_with("Handle: backup"), "{out}");
        let (_, out) = call(&h, "help", &args(&[("verb", "prune")]));
        assert!(out.starts_with("Handle: backup\nVerb: prune"), "{out}");
        let (_, out) = call(&h, "--help=create", &Args::new());
        assert!(out.contains("Verb: create"), "{out}");
    }
}

// H7: each documented `backup://<profile>` gets its own profile.
#[cfg(test)]
mod profile_tests {
    use super::*;

    fn repo(url: &str) -> String {
        BackupHandle::from_url(Url::parse(url).unwrap())
            .unwrap()
            .repo
    }

    #[test]
    fn profile_comes_from_the_url_host() {
        assert_eq!(repo("backup://db"), "db");
        assert_eq!(repo("backup://web"), "web");
        // Unchanged forms.
        assert_eq!(repo("backup://"), "default");
        assert_eq!(repo("backup:///legacy"), "legacy");
        assert_eq!(repo("backup://db/nightly"), "db/nightly");
        assert_eq!(repo("backup://my%20db"), "my db");
    }

    #[test]
    fn profile_survives_the_cli_parser() {
        let parsed = crate::core::parse::parse_stage("backup://db.list").unwrap();
        assert_eq!(repo(&parsed.target), "db");
    }
}

// Stage 4: a dry-run request never performs a real backup, prune or
// restore. Malformed dry_run values are errors (shared lenient parser), and
// restore, which has no dry-run mode, refuses dry_run=true.
// tar, rsync and borg have no default repository (v1.0.3-beta, release gate
// RB-3: the former /tmp defaults leaked backups and accepted directories
// planted by other users).
#[cfg(test)]
mod repo_url_required_tests {
    use super::*;
    use tempfile::TempDir;

    fn args(kv: &[(&str, &str)]) -> Args {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn local_backends_require_repo_url() {
        for b in [BackendType::Tar, BackendType::Rsync, BackendType::Borg] {
            assert!(repo_url_required(&b, &args(&[])).is_some(), "{b}");
            assert!(
                repo_url_required(&b, &args(&[("repo_url", " ")])).is_some(),
                "{b}"
            );
            assert!(
                repo_url_required(&b, &args(&[("repo_url", "file://")])).is_some(),
                "{b}"
            );
            assert!(
                repo_url_required(&b, &args(&[("repo_url", "/srv/b")])).is_none(),
                "{b}"
            );
        }
        // restic falls back to its own RESTIC_REPOSITORY.
        assert!(repo_url_required(&BackendType::Restic, &args(&[])).is_none());
    }

    #[test]
    fn tar_without_repo_url_fails_before_running() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir(&src).unwrap();
        let h = BackupHandle::from_url(Url::parse("backup://rb3").unwrap()).unwrap();
        for (verb, extra) in [
            ("create", vec![("src", src.to_str().unwrap())]),
            (
                "create",
                vec![("src", src.to_str().unwrap()), ("dry_run", "true")],
            ),
            ("list", vec![]),
            ("verify", vec![]),
            ("prune", vec![("keep_daily", "1")]),
            (
                "restore",
                vec![
                    ("snapshot_id", "backup_1"),
                    ("dest", tmp.path().to_str().unwrap()),
                ],
            ),
        ] {
            let mut kv = vec![("backend", "tar")];
            kv.extend(extra);
            let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
            let mut io = IoStreams {
                stdin: &mut i,
                stdout: &mut o,
                stderr: &mut e,
            };
            let st = h.call(verb, &args(&kv), &mut io).unwrap();
            assert!(!st.ok, "{verb} {kv:?}");
            let out = String::from_utf8_lossy(&o);
            assert!(
                out.contains("INVALID_ARGS") && out.contains("repo_url is required"),
                "{verb}: {out}"
            );
        }
        assert!(!Path::new("/tmp/resh_backup_rb3").exists());
    }
}

#[cfg(test)]
mod dry_run_tests {
    use super::*;
    use tempfile::TempDir;

    fn call(verb: &str, kv: &[(&str, &str)]) -> Result<Status> {
        let h = BackupHandle::from_url(Url::parse("backup://t").unwrap()).unwrap();
        let args: Args = kv
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
        let mut io = IoStreams {
            stdin: &mut i,
            stdout: &mut o,
            stderr: &mut e,
        };
        h.call(verb, &args, &mut io)
    }

    fn entries(p: &std::path::Path) -> usize {
        std::fs::read_dir(p).map(|d| d.count()).unwrap_or(0)
    }

    #[test]
    fn malformed_dry_run_is_refused_and_nothing_runs() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("a.txt"), "data").unwrap();
        let repo = tmp.path().join("repo");
        let (s, r) = (src.to_str().unwrap(), repo.to_str().unwrap());
        for bad in ["maybe", "2", "", "y", "treu"] {
            let base = [("backend", "tar"), ("repo_url", r), ("dry_run", bad)];
            let mut create = base.to_vec();
            create.push(("src", s));
            assert!(call("create", &create).is_err(), "create dry_run={bad:?}");
            assert!(call("prune", &base).is_err(), "prune dry_run={bad:?}");
            assert_eq!(entries(&repo), 0, "dry_run={bad:?} wrote a backup");
        }
        // Real spellings still work: a dry run writes nothing, a real run does.
        for yes in ["true", "1", "yes", "ON"] {
            let st = call(
                "create",
                &[
                    ("backend", "tar"),
                    ("repo_url", r),
                    ("src", s),
                    ("dry_run", yes),
                ],
            )
            .unwrap();
            assert!(st.ok, "dry_run={yes}");
            assert_eq!(entries(&repo), 0, "dry_run={yes} wrote a backup");
        }
        let st = call(
            "create",
            &[
                ("backend", "tar"),
                ("repo_url", r),
                ("src", s),
                ("dry_run", "off"),
            ],
        )
        .unwrap();
        assert!(st.ok);
        assert_eq!(entries(&repo), 1);
    }

    #[test]
    fn restore_refuses_dry_run_and_leaves_dest_untouched() {
        let tmp = TempDir::new().unwrap();
        let dest = tmp.path().join("dest");
        std::fs::create_dir(&dest).unwrap();
        std::fs::write(dest.join("keep.txt"), "original").unwrap();
        let d = dest.to_str().unwrap();
        let repo = tmp.path().join("repo");
        let r = repo.to_str().unwrap();
        for v in ["true", "1", "yes", "on", "maybe"] {
            let res = call(
                "restore",
                &[
                    ("backend", "tar"),
                    ("repo_url", r),
                    ("snapshot_id", "x"),
                    ("dest", d),
                    ("dry_run", v),
                ],
            );
            let err = res
                .expect_err(&format!("restore dry_run={v} must fail"))
                .to_string();
            if v != "maybe" {
                assert!(err.contains("does not support dry_run"), "{err}");
            }
        }
        assert_eq!(entries(&dest), 1);
        assert_eq!(
            std::fs::read_to_string(dest.join("keep.txt")).unwrap(),
            "original"
        );
    }
}

// FUNC-08: backup timeouts are enforced: the backend is killed at the
// deadline and the operation fails with a timeout error.
#[cfg(test)]
mod timeout_tests {
    use super::*;

    fn piped(program: &str, args: &[&str]) -> std::process::Child {
        Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    #[test]
    fn deadline_kills_and_reaps_a_hung_backend() {
        let child = piped("sleep", &["5"]);
        let pid = child.id() as libc::pid_t;
        let start = Instant::now();
        let out = wait_with_deadline(child, Duration::from_millis(200)).unwrap();
        assert!(out.is_none(), "timed out");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "returned at the deadline"
        );
        // Killed and reaped: the pid no longer exists.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    }

    #[test]
    fn fast_commands_are_unaffected() {
        let child = piped("sh", &["-c", "echo out; echo err >&2; exit 3"]);
        let out = wait_with_deadline(child, Duration::from_secs(10))
            .unwrap()
            .unwrap();
        assert_eq!(out.status.code(), Some(3));
        assert_eq!(out.stdout, b"out\n");
        assert_eq!(out.stderr, b"err\n");
    }

    #[test]
    fn large_output_does_not_deadlock() {
        let child = piped("head", &["-c", "300000", "/dev/zero"]);
        let out = wait_with_deadline(child, Duration::from_secs(10))
            .unwrap()
            .unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout.len(), 300000);
    }

    #[test]
    fn backend_command_timeout_is_an_error() {
        let h = BackupHandle {
            repo: "t".into(),
            target: "backup://t".into(),
        };
        let spec = CmdSpec {
            program: "sleep".into(),
            args: vec!["5".into()],
            env: HashMap::new(),
            env_remove: Vec::new(),
            cwd: None,
        };
        let start = Instant::now();
        let err = h.execute_backend_command(&spec, 150).unwrap_err();
        assert!(err.to_string().contains("timed out after 150ms"), "{err}");
        assert!(start.elapsed() < Duration::from_secs(2));

        let quick = CmdSpec {
            program: "true".into(),
            args: vec![],
            ..spec
        };
        let res = h.execute_backend_command(&quick, 5000).unwrap();
        assert_eq!(res.exit_code, 0);
    }
}

/// Stage 6B (B1-B3): caller values are checked before a backend command is
/// built, and the command line keeps them out of option position.
#[cfg(test)]
mod argument_safety_tests {
    use super::*;

    fn args(kv: &[(&str, &str)]) -> Args {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn field(backend: BackendType, verb: &str, kv: &[(&str, &str)]) -> Option<&'static str> {
        validate_request(&backend, verb, &args(kv))
            .err()
            .map(|e| e.field)
    }

    #[test]
    fn option_shaped_and_control_values_are_refused() {
        use BackendType::*;
        let repo = ("repo_url", "/srv/repo");
        for b in [Tar, Rsync, Borg, Restic] {
            for src in ["-v", "--probe", "/etc;-x", "a\nb", "a\0b", ""] {
                assert_eq!(
                    field(b.clone(), "create", &[repo, ("src", src)]),
                    Some("src"),
                    "{src:?}"
                );
            }
            assert_eq!(
                field(b.clone(), "create", &[("repo_url", "-r"), ("src", "/etc")]),
                Some("repo_url")
            );
            assert_eq!(
                field(
                    b.clone(),
                    "create",
                    &[repo, ("src", "/etc"), ("exclude", "a\rb")]
                ),
                Some("exclude")
            );
            assert_eq!(
                field(
                    b.clone(),
                    "create",
                    &[repo, ("src", "/etc"), ("label", "a\nb")]
                ),
                Some("label")
            );
            assert_eq!(
                field(b.clone(), "list", &[repo, ("tag", "a\nb")]),
                Some("tag")
            );
            assert_eq!(
                field(
                    b.clone(),
                    "restore",
                    &[repo, ("snapshot_id", "-x"), ("dest", "/d")]
                ),
                Some("snapshot_id")
            );
            assert_eq!(
                field(
                    b.clone(),
                    "restore",
                    &[repo, ("snapshot_id", "s1"), ("dest", "-d")]
                ),
                Some("dest")
            );
            assert_eq!(
                field(
                    b.clone(),
                    "restore",
                    &[
                        repo,
                        ("snapshot_id", "s1"),
                        ("dest", "/d"),
                        ("include", "a\nb")
                    ]
                ),
                Some("include")
            );
            // Legitimate values, including option-looking values that are
            // attached to their option with `=`.
            assert_eq!(
                field(
                    b.clone(),
                    "create",
                    &[
                        repo,
                        ("src", "/etc;rel/dir;a:b"),
                        ("exclude", "-x;*.tmp"),
                        ("label", "web 01")
                    ]
                ),
                None
            );
            assert_eq!(
                field(
                    b.clone(),
                    "restore",
                    &[repo, ("snapshot_id", "backup_1"), ("dest", "./-d")]
                ),
                None
            );
        }
    }

    #[test]
    fn local_snapshot_ids_stay_in_the_repository() {
        use BackendType::*;
        for b in [Tar, Rsync] {
            for id in ["../x", "a/b", "..", "."] {
                let kv = [("repo_url", "/r"), ("snapshot_id", id), ("dest", "/d")];
                assert_eq!(
                    field(b.clone(), "restore", &kv),
                    Some("snapshot_id"),
                    "{id}"
                );
            }
        }
        // restic `<id>:<subfolder>` and borg archive names are not paths.
        let kv = [
            ("repo_url", "/r"),
            ("snapshot_id", "latest:/etc"),
            ("dest", "/d"),
        ];
        assert_eq!(field(Restic, "restore", &kv), None);
    }

    #[test]
    fn remote_repository_hosts_cannot_be_options() {
        use BackendType::*;
        for repo in [
            "ssh://-oX/repo",
            "ssh://user@-oX/repo",
            "-oX:repo",
            "user@-oX:repo",
            "sftp:-oX:/repo",
            "sftp:user@-oX:/repo",
            "ssh://[-oX]/repo",
        ] {
            for b in [Borg, Restic] {
                assert_eq!(
                    field(b, "list", &[("repo_url", repo)]),
                    Some("repo_url"),
                    "{repo}"
                );
            }
        }
        for repo in [
            "/srv/borg",
            "/srv/a-b/-c",
            "ssh://backup@host.example:2222/./repo",
            "backup@host.example:repo",
            "sftp:backup@host.example:/srv/restic",
            "s3:https://s3.example/bucket",
        ] {
            for b in [Borg, Restic] {
                assert_eq!(field(b, "list", &[("repo_url", repo)]), None, "{repo}");
            }
        }
        // A local repository path may contain `:-`: tar uses --force-local
        // and rsync gets a ./ prefix, so nothing is remote.
        assert_eq!(field(Tar, "list", &[("repo_url", "/srv/a:-b")]), None);
    }

    #[test]
    fn rsync_local_paths_never_look_remote() {
        assert_eq!(rsync_local("/abs/a:b"), "/abs/a:b");
        assert_eq!(rsync_local("host:path"), "./host:path");
        assert_eq!(rsync_local("rsync://host/x"), "./rsync://host/x");
        assert_eq!(rsync_local("./x"), "./x");
        let c = build_rsync_create("repo/backup_1/", &["data".to_string()], &[]);
        assert_eq!(
            c.argv(),
            ["rsync", "-a", "--stats", "--", "./data", "./repo/backup_1/"]
        );
    }
}
