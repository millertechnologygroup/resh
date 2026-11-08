//! `backup://` — creates, lists, restores, verifies and prunes backup
//! snapshots by running restic, borg, rsync or tar, and reports a schedule
//! definition. Every verb prints one JSON envelope (`BackupEnvelope`), and
//! every failure has a stable `backup.<code>` error code (see `Code`).

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Datelike, Utc};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use url::Url;

use crate::core::{
    envelope::{BackendInfo, BackupEnvelope, BackupError},
    help::{self, HandleHelp, VerbDetail, VerbHelp},
    process,
    registry::{Args, Handle, IoStreams},
    status::{self, Status, exit},
};

/// Backup handle implementing all required verbs with JSON envelope per specification
#[derive(Debug)]
pub struct BackupHandle {
    /// Profile name from the URL
    pub repo: String,
    /// Target URL for JSON responses
    pub target: String,
    /// Directory the backend programs are taken from instead of `PATH`
    /// (unit tests only; `None` in the binary).
    bin_dir: Option<PathBuf>,
    /// The cron provider `schedule` installs jobs with (unit tests only;
    /// `None` uses the host's cron or systemd).
    #[cfg(test)]
    cron_provider: Option<std::sync::Arc<dyn crate::handles::processes::cronh::CronProvider>>,
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
        unless backend is given, and reports schedule definitions. The stage URL names a \
        backup profile, such as backup://db, and the repository location is passed with \
        repo_url, and restic and borg take the repository password from password or \
        password_file, or from their usual environment variables; every verb prints a \
        JSON envelope, and failures carry a backup.<code> error code.",
    usage: "resh backup://<profile>.<verb>[(key=value,...)]",
    verbs: &[
        VerbHelp {
            name: "list",
            definition: "Lists the snapshots in a repository by running the backend's listing \
                command, such as restic snapshots or borg list, or by reading a tar or rsync \
                repository directory.",
            detail: Some(VerbDetail {
                usage: "resh backup://<profile>.list\n  \
                    [backend=auto|restic|borg|rsync|tar] [repo_url=<repo>]\n  \
                    [password=<secret>|password_file=<path>] [tag=<tag>;...]\n  \
                    [timeout_ms=<ms>] [json_pretty=true|false]\n  \
                    tag: restic only. timeout_ms default 10000",
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

Shown for restic with RESTIC_PASSWORD_FILE set in the environment. The
label field holds the restic hostname. tar and rsync read the repository
directory directly, so their command is empty. Without a password, restic
and borg fail with backup.missing_password (exit 2) before running."#,
                ),
            }),
        },
        VerbHelp {
            name: "verify",
            definition: "Checks repository integrity with the backend's check command, or \
                reads every tar archive or rsync snapshot, reading all data when mode is \
                thorough or data.",
            detail: Some(VerbDetail {
                usage: "resh backup://<profile>.verify\n  \
                    [backend=auto|restic|borg|rsync|tar] [repo_url=<repo>]\n  \
                    [password=<secret>|password_file=<path>]\n  \
                    [mode=quick|thorough|data] [snapshot_id=<id>]\n  \
                    [timeout_ms=<ms>] [json_pretty=true|false]\n  \
                    snapshot_id: borg, tar and rsync only.\n  \
                    timeout_ms default 3600000, for the whole verb",
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
      "files_checked": null,
      "issues": [],
      "success": true
    }
  },
  "target": "backup://db",
  "ts": "2026-10-16T09:12:44.931277+00:00",
  "verb": "verify",
  "warnings": []
}

Shown for restic with RESTIC_PASSWORD_FILE set in the environment.
files_checked counts tar archive members or rsync files (null for restic
and borg). Problems found by tar or rsync give backup.verify_failed; a
failing restic or borg check gives backup.backend_failed."#,
                ),
            }),
        },
        VerbHelp {
            name: "create",
            definition: "Backs up one or more source paths with the selected backend and \
                reports the new snapshot id and sizes read from the backend's output.",
            detail: Some(VerbDetail {
                usage: "resh backup://<profile>.create src=<path>[;<path>...]\n  \
                    [backend=auto|restic|borg|rsync|tar] [repo_url=<repo>]\n  \
                    [password=<secret>|password_file=<path>] [tag=<tag>;...]\n  \
                    [label=<text>] [exclude=<pattern>;...] [dry_run=true|false]\n  \
                    [progress=true|false] [timeout_ms=<ms>] [json_pretty=true|false]\n  \
                    tag: restic only. progress: restic and borg; one JSON line per\n  \
                    progress event before the envelope. timeout_ms default 1800000",
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
backup_20261016_091244, and the raw output. tar, rsync and borg need
repo_url (there is no default repository); a missing tar or rsync
repository is created owner-only (0700) and archives are written 0600."#,
                ),
            }),
        },
        VerbHelp {
            name: "restore",
            definition: "Restores a snapshot into a destination directory with the selected \
                backend, optionally only the paths matching include patterns.",
            detail: Some(VerbDetail {
                usage: "resh backup://<profile>.restore snapshot_id=<id> dest=<path>\n  \
                    [backend=auto|restic|borg|rsync|tar] [repo_url=<repo>]\n  \
                    [password=<secret>|password_file=<path>] [include=<pattern>,...]\n  \
                    [exclude=<pattern>;...] [dry_run=true|false]\n  \
                    [progress=true|false] [timeout_ms=<ms>] [json_pretty=true|false]\n  \
                    dry_run: lists what would be restored, writes nothing.\n  \
                    progress: restic and borg. timeout_ms default 1800000",
                example: "resh backup://db.restore repo_url=/srv/r \
                    snapshot_id=4f2a9c1e dest=restore",
                example_output: Some(
                    r#"{
  "backend": {
    "command": [
      "restic",
      "restore",
      "--json",
      "--target=restore",
      "--",
      "4f2a9c1e"
    ],
    "env_redacted": {
      "RESTIC_REPOSITORY": "/srv/r"
    },
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
    "destination": "restore",
    "restored": {
      "bytes_restored": 3172,
      "files_restored": 12,
      "success": true
    },
    "snapshot_id": "4f2a9c1e"
  },
  "target": "backup://db",
  "ts": "2026-10-16T09:12:44.931277+00:00",
  "verb": "restore",
  "warnings": []
}

Shown for restic, the first backend tried when backend is not given,
indented as with --json-pretty, with RESTIC_PASSWORD_FILE set in the
environment. The counts are restic's (files and directories) and the
regular files written for tar, rsync and borg. A missing dest is created
owner-only (0700); a symlink dest is refused. dry_run=true reports
destination and would_restore instead and writes nothing."#,
                ),
            }),
        },
        VerbHelp {
            name: "prune",
            definition: "Removes snapshots outside the keep_daily, keep_weekly, and \
                keep_monthly limits, or reports what would be removed when dry_run is true.",
            detail: Some(VerbDetail {
                usage: "resh backup://<profile>.prune\n  \
                    [backend=auto|restic|borg|rsync|tar] [repo_url=<repo>]\n  \
                    [password=<secret>|password_file=<path>]\n  \
                    [keep_daily=<n>] [keep_weekly=<n>] [keep_monthly=<n>]\n  \
                    [dry_run=true|false] [timeout_ms=<ms>] [json_pretty=true|false]\n  \
                    at least one keep_* (n >= 1). timeout_ms default 3600000",
                example: "resh backup://db.prune backend=borg repo_url=/srv/b \
                    keep_daily=7 dry_run=true",
                example_output: Some(
                    r#"{
  "backend": {
    "command": [
      "borg",
      "prune",
      "--list",
      "--keep-daily",
      "7",
      "--dry-run",
      "--",
      "/srv/b"
    ],
    "env_redacted": {},
    "id": "borg",
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
        "file"
      ],
      "dedup": true,
      "encryption": true,
      "incremental": true,
      "retention": true,
      "verify": true
    },
    "dry_run": true,
    "dry_run_mode": "backend",
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
  "warnings": [
    "Dry run: borg ran in its own --dry-run mode; nothing was removed"
  ]
}

Shown for borg, indented as with --json-pretty, with BORG_PASSPHRASE set
in the environment. A restic or borg dry run runs the backend's own dry
run, which leaves snapshots alone but takes a repository lock (exclusive
for borg), writes the backend's local cache and needs the repository
credentials. tar and rsync apply the policy to archives or snapshot
directories by modification time (UTC days) and report bytes_freed."#,
                ),
            }),
        },
        VerbHelp {
            name: "schedule",
            definition: "Installs a scheduled create for the profile as a systemd timer or \
                crontab line through the cron handle, or reports what would be installed \
                when dry_run is true.",
            detail: Some(VerbDetail {
                usage: "resh backup://<profile>.schedule when=<cron> src=<path>[;<path>...]\n  \
                    [backend=auto|restic|borg|rsync|tar] [repo_url=<repo>]\n  \
                    [password_file=<path>] [enabled=true|false]\n  \
                    [scheduler=auto|cron|systemd] [dry_run=true|false]\n  \
                    [timeout_ms=<ms>] [json_pretty=true|false]\n  \
                    when: five crontab fields or an @ keyword (checked by cron add)",
                example: "resh backup://db.schedule when=@daily src=/e backend=tar \
                    repo_url=/b dry_run=1",
                example_output: Some(
                    r#"{
  "backend": {
    "command": [],
    "env_redacted": {},
    "id": "tar",
    "simulated": false,
    "timeout_ms": 0
  },
  "dry_run": true,
  "duration_ms": 3,
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
      "command": [
        "/usr/local/bin/resh",
        "backup://db.create",
        "src=/e",
        "backend=tar",
        "repo_url=/b"
      ],
      "duplicate": false,
      "enabled": true,
      "id": "resh-backup-db",
      "installed": false,
      "job": {
        "backend": "cron",
        "id": "resh-backup-db",
        "schedule": "@daily"
      },
      "preview": {},
      "remove_command": [
        "resh",
        "cron://backup-db.rm",
        "id=resh-backup-db",
        "backend=cron"
      ],
      "scheduler": "cron",
      "when": "@daily"
    }
  },
  "target": "backup://db",
  "ts": "2026-10-16T09:12:44.931277+00:00",
  "verb": "schedule",
  "warnings": [
    "Dry run: nothing was installed"
  ]
}

Shown shortened (job and preview are the cron handle's add result, with
the full crontab line or units) on a host without systemd. Without
dry_run the job is installed and installed is true; enabled=false then
disables it. Run remove_command to remove it."#,
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

impl BackendType {
    fn is_local(&self) -> bool {
        matches!(self, BackendType::Tar | BackendType::Rsync)
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
    /// Exit status, or None when the backend was killed by a signal.
    pub exit_code: Option<i32>,
    /// The signal that ended the backend, if any.
    pub signal: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

impl BackendResult {
    fn success(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// Retention policy (`keep_daily`, `keep_weekly`, `keep_monthly`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RetentionPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_daily: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_weekly: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_monthly: Option<u32>,
}

/// Default timeouts in milliseconds; each is the deadline of the whole verb.
const DEFAULT_CREATE_TIMEOUT_MS: u64 = 1_800_000; // 30 minutes
const DEFAULT_LIST_TIMEOUT_MS: u64 = 10_000; // 10 seconds
const DEFAULT_RESTORE_TIMEOUT_MS: u64 = 1_800_000; // 30 minutes
const DEFAULT_VERIFY_TIMEOUT_MS: u64 = 3_600_000; // 60 minutes
const DEFAULT_PRUNE_TIMEOUT_MS: u64 = 3_600_000; // 60 minutes
/// Largest accepted `timeout_ms` (30 days).
const MAX_TIMEOUT_MS: u64 = 2_592_000_000;

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

/// Environment variables through which restic already has a repository.
const RESTIC_REPO_ENV: &[&str] = &["RESTIC_REPOSITORY", "RESTIC_REPOSITORY_FILE"];

/// Environment variables through which borg already has a repository passphrase.
const BORG_SECRET_ENV: &[&str] = &["BORG_PASSPHRASE", "BORG_PASSCOMMAND", "BORG_PASSPHRASE_FD"];

const REDACTED: &str = "***REDACTED***";

fn is_secret_key(key: &str) -> bool {
    let key = key.to_lowercase();
    SECRET_PATTERNS.iter().any(|pattern| key.contains(pattern))
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// Every failure the handle reports. `code()` is the stable
/// `backup.<name>` code (stderr line and `error.code`), `kind()` the
/// earlier upper-case `error.kind`, kept for compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Code {
    InvalidArgument,
    UnknownVerb,
    BackendNotFound,
    MissingPassword,
    PasswordFileUnreadable,
    BackendFailed,
    Timeout,
    ExecutionFailed,
    Io,
    Parse,
    VerifyFailed,
    SnapshotNotFound,
    ScheduleFailed,
}

impl Code {
    #[cfg(test)]
    pub(crate) const ALL: [Code; 13] = [
        Code::InvalidArgument,
        Code::UnknownVerb,
        Code::BackendNotFound,
        Code::MissingPassword,
        Code::PasswordFileUnreadable,
        Code::BackendFailed,
        Code::Timeout,
        Code::ExecutionFailed,
        Code::Io,
        Code::Parse,
        Code::VerifyFailed,
        Code::SnapshotNotFound,
        Code::ScheduleFailed,
    ];

    pub(crate) fn code(self) -> &'static str {
        match self {
            Code::InvalidArgument => "backup.invalid_argument",
            Code::UnknownVerb => "backup.unknown_verb",
            Code::BackendNotFound => "backup.backend_not_found",
            Code::MissingPassword => "backup.missing_password",
            Code::PasswordFileUnreadable => "backup.password_file_unreadable",
            Code::BackendFailed => "backup.backend_failed",
            Code::Timeout => "backup.timeout",
            Code::ExecutionFailed => "backup.execution_failed",
            Code::Io => "backup.io",
            Code::Parse => "backup.parse",
            Code::VerifyFailed => "backup.verify_failed",
            Code::SnapshotNotFound => "backup.snapshot_not_found",
            Code::ScheduleFailed => "backup.schedule_failed",
        }
    }

    pub(crate) fn kind(self) -> &'static str {
        match self {
            Code::InvalidArgument | Code::UnknownVerb => "INVALID_ARGS",
            Code::BackendNotFound => "BACKEND_NOT_FOUND",
            Code::MissingPassword | Code::PasswordFileUnreadable => "MISSING_PASSWORD",
            Code::BackendFailed => "BACKEND_FAILED",
            Code::Timeout => "TIMEOUT",
            Code::ExecutionFailed => "EXECUTION_FAILED",
            Code::Io => "IO",
            Code::Parse => "PARSE",
            Code::VerifyFailed => "VERIFY_FAILED",
            Code::SnapshotNotFound => "NOT_FOUND",
            Code::ScheduleFailed => "SCHEDULE_FAILED",
        }
    }

    /// The process exit status: 2 when the request itself is invalid and
    /// nothing was done, 124 for a timeout, otherwise 1.
    pub(crate) fn exit(self) -> i32 {
        match self {
            Code::InvalidArgument | Code::UnknownVerb | Code::MissingPassword => exit::USAGE,
            Code::Timeout => exit::TIMEOUT,
            _ => exit::FAILED,
        }
    }
}

/// A failure of a verb: its code, message and optional details.
#[derive(Debug)]
pub(crate) struct Fail {
    pub code: Code,
    pub message: String,
    pub details: Option<Value>,
}

impl Fail {
    fn new(code: Code, message: impl Into<String>) -> Self {
        Fail {
            code,
            message: message.into(),
            details: None,
        }
    }

    fn with(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    /// An invalid argument value; `details.field` names the argument.
    fn invalid(field: &str, message: impl Into<String>) -> Self {
        Fail::new(Code::InvalidArgument, message).with(json!({ "field": field }))
    }
}

type VResult<T> = std::result::Result<T, Fail>;

// ---------------------------------------------------------------------------
// Accepted arguments (one list per verb; the help usage lists exactly these)
// ---------------------------------------------------------------------------

/// Arguments every verb except schedule accepts.
const COMMON_ARGS: &[&str] = &[
    "backend",
    "repo_url",
    "password",
    "password_file",
    "timeout_ms",
    "json_pretty",
];

/// The arguments `verb` accepts, or None for an unknown verb.
pub(crate) fn accepted_args(verb: &str) -> Option<Vec<&'static str>> {
    let own: &[&'static str] = match verb {
        "create" => &["src", "tag", "label", "exclude", "dry_run", "progress"],
        "list" => &["tag"],
        "restore" => &[
            "snapshot_id",
            "dest",
            "include",
            "exclude",
            "dry_run",
            "progress",
        ],
        "verify" => &["mode", "snapshot_id"],
        "prune" => &["keep_daily", "keep_weekly", "keep_monthly", "dry_run"],
        "schedule" => {
            return Some(vec![
                "when",
                "src",
                "backend",
                "repo_url",
                "password_file",
                "enabled",
                "scheduler",
                "dry_run",
                "timeout_ms",
                "json_pretty",
            ]);
        }
        _ => return None,
    };
    Some(COMMON_ARGS.iter().chain(own).copied().collect())
}

/// Levenshtein distance between two strings (by `char`).
fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            cur[j + 1] = (prev[j] + usize::from(ca != *cb))
                .min(prev[j + 1] + 1)
                .min(cur[j] + 1);
        }
        prev = cur;
    }
    prev[b.len()]
}

/// The accepted name `bad` is most likely a typo of, if any.
pub(crate) fn suggest<'a>(bad: &str, allowed: &[&'a str]) -> Option<&'a str> {
    let bad = bad.to_ascii_lowercase();
    // An unambiguous prefix is the strongest hint (`timeout` -> `timeout_ms`).
    let prefixed: Vec<&&str> = allowed.iter().filter(|a| a.starts_with(&bad)).collect();
    if prefixed.len() == 1 && bad.chars().count() >= 2 {
        return Some(prefixed[0]);
    }
    let limit = (bad.chars().count() / 3).max(2);
    allowed
        .iter()
        .map(|a| (edit_distance(&bad, a), *a))
        .filter(|(d, _)| *d <= limit && *d < bad.chars().count())
        .min_by_key(|(d, _)| *d)
        .map(|(_, a)| a)
}

/// Refuses an argument `verb` does not accept (exit 2, before anything runs).
fn check_known_args(verb: &str, args: &Args) -> VResult<()> {
    let Some(allowed) = accepted_args(verb) else {
        return Ok(());
    };
    let mut keys: Vec<&String> = args.keys().collect();
    keys.sort();
    for key in keys {
        if allowed.contains(&key.as_str()) {
            continue;
        }
        if key == "dry_run" {
            let what = if verb == "restore" {
                "nothing was restored"
            } else {
                "nothing was done"
            };
            return Err(Fail::invalid(
                key,
                format!("backup {verb} does not support dry_run; {what}"),
            ));
        }
        let mut msg = format!("unknown argument {key:?} for backup {verb}");
        if let Some(s) = suggest(key, &allowed) {
            msg.push_str(&format!("; did you mean {s}?"));
        }
        msg.push_str(&format!(
            " (accepted: {}); nothing was done",
            allowed.join(", ")
        ));
        return Err(Fail::invalid(key, msg));
    }
    Ok(())
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

impl From<UnsafeArg> for Fail {
    fn from(e: UnsafeArg) -> Self {
        Fail::invalid(e.field, e.message)
    }
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
    if let Some(f) = args.get("password_file") {
        check_positional("password_file", f)?;
    }
    match verb {
        "create" | "schedule" => {
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
        "restore" | "verify" => {
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
        c = c.arg(format!("--host={}", label));
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
        .arg("--json")
        .arg(format!("--target={}", dest))
        .args(repeat_flag("--include", include))
        .args(repeat_flag("--exclude", exclude))
        .args(["--", snapshot_id])
}

/// borg extracts into its working directory, so the destination is the cwd.
/// `--list` names every extracted item; include patterns are borg PATH
/// arguments after the archive.
pub(crate) fn build_borg_restore(
    repo: &str,
    snapshot_id: &str,
    dest: &str,
    include: &[String],
    exclude: &[String],
) -> CmdSpec {
    let mut c = CmdSpec::new("borg")
        .args(["extract", "--list"])
        .args(repeat_flag("--exclude", exclude))
        .arg("--")
        .arg(format!("{}::{}", repo, snapshot_id))
        .args(include.iter().cloned());
    c.cwd = Some(dest.to_string());
    c
}

/// `-v` names every extracted member. Include patterns are shell-style
/// member patterns (`*` does not match `/`) after `--`.
pub(crate) fn build_tar_restore(
    archive: &str,
    dest: &str,
    include: &[String],
    exclude: &[String],
) -> CmdSpec {
    let c = CmdSpec::new("tar")
        .args(["--force-local", "-v", "-xzf", archive])
        .args(repeat_flag("--exclude", exclude))
        .args(["-C", dest]);
    if include.is_empty() {
        c
    } else {
        c.args(["--wildcards", "--no-wildcards-match-slash", "--"])
            .args(include.iter().cloned())
    }
}

/// Excludes come first (the first matching rsync rule wins); include
/// patterns then select files, every directory is traversed, everything
/// else is excluded and directories left empty are not created.
pub(crate) fn build_rsync_restore(
    snapshot_dir: &str,
    dest: &str,
    include: &[String],
    exclude: &[String],
) -> CmdSpec {
    let mut c = CmdSpec::new("rsync")
        .args(["-a", "--stats"])
        .args(repeat_flag("--exclude", exclude));
    if !include.is_empty() {
        c = c
            .arg("--include=*/")
            .args(repeat_flag("--include", include))
            .args(["--exclude=*", "--prune-empty-dirs"]);
    }
    c.arg("--")
        .args([rsync_local(snapshot_dir), rsync_local(dest)])
}

/// Restore dry run for tar: the members a restore would extract, with
/// sizes (`tar -tv`), under the same include and exclude patterns.
pub(crate) fn build_tar_restore_list(
    archive: &str,
    include: &[String],
    exclude: &[String],
) -> CmdSpec {
    let c = CmdSpec::new("tar")
        .args(["--force-local", "-tvzf", archive])
        .args(repeat_flag("--exclude", exclude));
    if include.is_empty() {
        c
    } else {
        c.args(["--wildcards", "--no-wildcards-match-slash", "--"])
            .args(include.iter().cloned())
    }
}

/// Restore dry run for borg: the archive items a restore would extract
/// (`borg list --json-lines`), under the same include and exclude patterns.
pub(crate) fn build_borg_restore_list(
    repo: &str,
    snapshot_id: &str,
    include: &[String],
    exclude: &[String],
) -> CmdSpec {
    CmdSpec::new("borg")
        .args(["list", "--json-lines"])
        .args(repeat_flag("--exclude", exclude))
        .arg("--")
        .arg(format!("{}::{}", repo, snapshot_id))
        .args(include.iter().cloned())
}

/// Inserts `flags` into the argument list at `at` (after the subcommand,
/// where every backend reads its global options).
fn with_flags(mut spec: CmdSpec, at: usize, flags: &[&str]) -> CmdSpec {
    let at = at.min(spec.args.len());
    spec.args
        .splice(at..at, flags.iter().map(|f| f.to_string()));
    spec
}

/// (regular files, bytes) in a `tar -tv` listing.
pub(crate) fn parse_tar_listing(stdout: &str) -> (u64, u64) {
    let (mut files, mut bytes) = (0, 0);
    for line in stdout.lines().filter(|l| l.starts_with('-')) {
        files += 1;
        bytes += line
            .split_whitespace()
            .nth(2)
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(0);
    }
    (files, bytes)
}

/// (regular files, bytes) in `borg list --json-lines` output.
pub(crate) fn parse_borg_listing(stdout: &str) -> (u64, u64) {
    let (mut files, mut bytes) = (0, 0);
    for v in stdout
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l.trim()).ok())
    {
        if v["type"] == "-" {
            files += 1;
            bytes += v["size"].as_u64().unwrap_or(0);
        }
    }
    (files, bytes)
}

/// (files_restored, bytes_restored) from restic `restore --json`'s summary.
pub(crate) fn parse_restic_restore_summary(stdout: &str) -> (Option<u64>, Option<u64>) {
    match parse_restic_summary(stdout) {
        Some(v) => (v["files_restored"].as_u64(), v["bytes_restored"].as_u64()),
        None => (parse_restic_restored(stdout), None),
    }
}

/// The paths borg listed as extracted: plain `--list` lines, or with
/// `--log-json` the messages of the `borg.output.list` logger.
pub(crate) fn borg_listed(stdout: &str, stderr: &str) -> String {
    let mut out = String::new();
    for line in stdout.lines().chain(stderr.lines()) {
        match serde_json::from_str::<Value>(line.trim()) {
            Ok(v) if v.is_object() => {
                if v["name"] == "borg.output.list"
                    && let Some(m) = v["message"].as_str()
                {
                    out.push_str(m);
                    out.push('\n');
                }
            }
            _ => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

/// A progress event in a backend output line: restic `--json` status
/// messages (stdout) and borg `--log-json` progress records (stderr).
pub(crate) fn progress_event(backend: &BackendType, stdout: bool, line: &str) -> Option<Value> {
    let v: Value = serde_json::from_str(line.trim()).ok()?;
    let is_progress = match backend {
        BackendType::Restic => stdout && v["message_type"] == "status",
        BackendType::Borg => {
            !stdout
                && matches!(
                    v["type"].as_str(),
                    Some("archive_progress" | "progress_percent" | "progress_message")
                )
        }
        _ => false,
    };
    is_progress.then_some(v)
}

pub(crate) fn build_restic_verify(repo_url: Option<&String>, read_data: bool) -> CmdSpec {
    let c = restic_base(repo_url, "check");
    if read_data { c.arg("--read-data") } else { c }
}

/// `archive`: check only that archive (`<repo>::<archive>`).
pub(crate) fn build_borg_verify(repo: &str, archive: Option<&str>, verify_data: bool) -> CmdSpec {
    let c = CmdSpec::new("borg").arg("check");
    let c = if verify_data {
        c.arg("--verify-data")
    } else {
        c
    };
    match archive {
        Some(a) => c.args(["--".to_string(), format!("{}::{}", repo, a)]),
        None => c.args(["--", repo]),
    }
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
// Repository password
// ---------------------------------------------------------------------------

/// Environment changes that give the backend its repository password.
/// Passwords reach the backend through its environment, never its argv.
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

/// Why no repository password could be provided.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SecretError {
    /// No password source at all.
    Missing(String),
    /// `password_file` cannot be read.
    Unreadable(String),
}

/// Resolves the restic/borg repository password from `password=` or
/// `password_file=`, else from the backend's usual environment variables.
/// tar and rsync need none. The error message never contains the secret.
pub(crate) fn resolve_repo_secret(
    backend: &BackendType,
    args: &Args,
    env_has: impl Fn(&str) -> bool,
    read_file: impl Fn(&str) -> std::io::Result<String>,
) -> std::result::Result<RepoSecret, SecretError> {
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
                // Checked here so an unreadable file is reported before
                // anything runs; restic reads it again itself.
                read_file(f).map_err(|e| {
                    SecretError::Unreadable(format!("cannot read password_file {}: {}", f, e))
                })?;
                secret
                    .set
                    .insert("RESTIC_PASSWORD_FILE".to_string(), f.clone());
                // restic refuses both a password file and a password command.
                secret.remove = vec![
                    "RESTIC_PASSWORD".to_string(),
                    "RESTIC_PASSWORD_COMMAND".to_string(),
                ];
            } else if !RESTIC_SECRET_ENV.iter().any(|k| env_has(k)) {
                return Err(SecretError::Missing(
                    "restic needs a repository password: pass password=<secret> or \
                    password_file=<path>, or set RESTIC_PASSWORD or RESTIC_PASSWORD_FILE"
                        .to_string(),
                ));
            }
        }
        BackendType::Borg => {
            if let Some(p) = args.get("password") {
                secret.set.insert("BORG_PASSPHRASE".to_string(), p.clone());
                secret.remove = vec![
                    "BORG_PASSCOMMAND".to_string(),
                    "BORG_PASSPHRASE_FD".to_string(),
                ];
            } else if let Some(f) = args.get("password_file") {
                let content = read_file(f).map_err(|e| {
                    SecretError::Unreadable(format!("cannot read password_file {}: {}", f, e))
                })?;
                secret.set.insert(
                    "BORG_PASSPHRASE".to_string(),
                    content.trim_end_matches(['\r', '\n']).to_string(),
                );
                secret.remove = vec![
                    "BORG_PASSCOMMAND".to_string(),
                    "BORG_PASSPHRASE_FD".to_string(),
                ];
            } else if !BORG_SECRET_ENV.iter().any(|k| env_has(k)) {
                return Err(SecretError::Missing(
                    "borg needs a repository passphrase: pass password=<secret> or \
                    password_file=<path>, or set BORG_PASSPHRASE or BORG_PASSCOMMAND \
                    (BORG_PASSPHRASE may be empty for an unencrypted repository)"
                        .to_string(),
                ));
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

/// The number in restic's `Summary: Restored <n> files/dirs (...)` line.
pub(crate) fn parse_restic_restored(output: &str) -> Option<u64> {
    output.lines().find_map(|l| {
        let rest = l.trim().strip_prefix("Summary: Restored ")?;
        rest.split_whitespace().next()?.parse().ok()
    })
}

/// Regular files (count, bytes) under `dest` among the relative paths a
/// backend listed as extracted. Symlinks are not followed.
fn count_listed_files(dest: &Path, listed: &str) -> (u64, u64) {
    let mut seen = std::collections::HashSet::new();
    let (mut files, mut bytes) = (0, 0);
    for line in listed.lines() {
        let rel = line.trim_end().trim_start_matches("./");
        let rel = rel.trim_start_matches('/');
        if rel.is_empty() || !seen.insert(rel.to_string()) {
            continue;
        }
        if let Ok(meta) = fs::symlink_metadata(dest.join(rel))
            && meta.is_file()
        {
            files += 1;
            bytes += meta.len();
        }
    }
    (files, bytes)
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
    pub path: PathBuf,
    pub modified: DateTime<Utc>,
    pub bytes: Option<u64>,
}

/// The deadline passed during in-process work.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct DeadlinePassed;

fn check_deadline(deadline: Instant) -> std::result::Result<(), DeadlinePassed> {
    if Instant::now() >= deadline {
        Err(DeadlinePassed)
    } else {
        Ok(())
    }
}

/// Total size of the regular files under `path`, not following symlinks.
fn dir_size(path: &Path, deadline: Instant) -> std::result::Result<u64, DeadlinePassed> {
    let mut total = 0;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        check_deadline(deadline)?;
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
    Ok(total)
}

/// Why a local repository could not be scanned.
#[derive(Debug)]
pub(crate) enum ScanError {
    Io(std::io::Error),
    Deadline,
}

/// tar: `*.tar.gz` files (id is the name without `.tar.gz`); rsync: snapshot
/// directories. Newest first.
pub(crate) fn scan_local_snapshots(
    backend: &BackendType,
    repo: &Path,
    with_sizes: bool,
    deadline: Instant,
) -> std::result::Result<Vec<LocalSnapshot>, ScanError> {
    let mut out = Vec::new();
    for entry in fs::read_dir(repo).map_err(ScanError::Io)? {
        check_deadline(deadline).map_err(|_| ScanError::Deadline)?;
        let entry = entry.map_err(ScanError::Io)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        // DirEntry::metadata does not follow symlinks.
        let meta = entry.metadata().map_err(ScanError::Io)?;
        let modified: DateTime<Utc> = meta.modified().map_err(ScanError::Io)?.into();
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
                let bytes = if with_sizes {
                    Some(dir_size(&entry.path(), deadline).map_err(|_| ScanError::Deadline)?)
                } else {
                    None
                };
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

/// Opens (quick) or reads completely (`read_data`) every regular file under
/// `root`. Returns (files checked, errors), or the deadline.
fn check_files_readable(
    root: &Path,
    read_data: bool,
    deadline: Instant,
) -> std::result::Result<(usize, Vec<String>), DeadlinePassed> {
    let mut checked = 0;
    let mut errors = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut buf = vec![0u8; 64 * 1024];
    while let Some(dir) = stack.pop() {
        check_deadline(deadline)?;
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
                match fs::File::open(entry.path()) {
                    Err(e) => errors.push(format!("{}: {}", entry.path().display(), e)),
                    Ok(mut f) if read_data => loop {
                        check_deadline(deadline)?;
                        match f.read(&mut buf) {
                            Ok(0) => break,
                            Ok(_) => {}
                            Err(e) => {
                                errors.push(format!("{}: {}", entry.path().display(), e));
                                break;
                            }
                        }
                    },
                    Ok(_) => {}
                }
            }
        }
    }
    Ok((checked, errors))
}

/// Creates `path` and missing parents owner-only (0700). An existing
/// directory is left as it is.
fn create_private_dir_all(path: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

/// True if anything (including a dangling symlink) exists at `path`.
fn entry_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// A snapshot name not yet used in `repo` (`<name>`, then `<name>_2`, ...),
/// so a second backup in the same second never overwrites the first.
fn unique_local_name(repo: &Path, name: &str, suffix: &str) -> String {
    let mut candidate = name.to_string();
    let mut n = 2;
    while entry_exists(&repo.join(format!("{candidate}{suffix}"))) {
        candidate = format!("{name}_{n}");
        n += 1;
    }
    candidate
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

/// A strict boolean argument (`core::lenient::bool_arg`); absent is `default`.
fn bool_arg(args: &Args, key: &str, default: bool) -> VResult<bool> {
    crate::core::lenient::bool_arg(args, key)
        .map(|v| v.unwrap_or(default))
        .map_err(|e| Fail::invalid(key, format!("{e}; nothing was done")))
}

/// `timeout_ms`: an integer from 1 to MAX_TIMEOUT_MS, or `default`.
fn arg_timeout(args: &Args, default: u64) -> VResult<u64> {
    match args.get("timeout_ms") {
        None => Ok(default),
        Some(v) => match v.trim().parse::<u64>() {
            Ok(n) if (1..=MAX_TIMEOUT_MS).contains(&n) => Ok(n),
            _ => Err(Fail::invalid(
                "timeout_ms",
                format!(
                    "timeout_ms must be an integer from 1 to {MAX_TIMEOUT_MS} (milliseconds), \
                     got {v:?}; nothing was done"
                ),
            )),
        },
    }
}

/// `progress`: stream progress events (restic and borg only).
fn arg_progress(args: &Args, backend: &BackendType) -> VResult<bool> {
    let progress = bool_arg(args, "progress", false)?;
    if progress && backend.is_local() {
        return Err(Fail::invalid(
            "progress",
            format!("progress is supported for restic and borg, not {backend}; nothing was done"),
        ));
    }
    Ok(progress)
}

/// A `keep_*` count: absent, or an integer of at least 1.
fn arg_keep(args: &Args, key: &str) -> VResult<Option<u32>> {
    match args.get(key) {
        None => Ok(None),
        Some(v) => match v.trim().parse::<u32>() {
            Ok(n) if n >= 1 => Ok(Some(n)),
            _ => Err(Fail::invalid(
                key,
                format!(
                    "{key} must be an integer of at least 1 (omit it to not keep by this \
                     rule), got {v:?}; nothing was pruned"
                ),
            )),
        },
    }
}

fn required<'a>(args: &'a Args, key: &str) -> VResult<&'a String> {
    args.get(key).ok_or_else(|| {
        Fail::invalid(
            key,
            format!("missing required argument {key}; nothing was done"),
        )
    })
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

fn stderr_tail(stderr: &str) -> String {
    if stderr.len() <= ERROR_TAIL_SIZE {
        return stderr.to_string();
    }
    let mut start = stderr.len() - ERROR_TAIL_SIZE;
    while !stderr.is_char_boundary(start) {
        start += 1;
    }
    format!("...{}", &stderr[start..])
}

/// A word as a POSIX shell would read it back: unchanged when it holds only
/// safe characters, else single-quoted.
fn shell_quote(word: &str) -> String {
    let safe = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-=:,@+%".contains(c));
    if safe {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', r"'\''"))
    }
}

/// What a restore would find at `dest`. A symlink or an existing
/// non-directory is refused (never restored through or over).
fn check_destination(path: &Path, dest: &str) -> VResult<Value> {
    fn writable(p: &Path) -> bool {
        use std::os::unix::ffi::OsStrExt;
        let p = if p.as_os_str().is_empty() {
            Path::new(".")
        } else {
            p
        };
        std::ffi::CString::new(p.as_os_str().as_bytes())
            // SAFETY: a valid NUL-terminated path; access only reads it.
            .map(|c| unsafe { libc::access(c.as_ptr(), libc::W_OK) } == 0)
            .unwrap_or(false)
    }
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(Fail::invalid(
            "dest",
            format!(
                "dest {dest} is a symbolic link; pass the directory it points to; \
                 nothing was restored"
            ),
        )),
        Ok(m) if !m.is_dir() => Err(Fail::invalid(
            "dest",
            format!("dest {dest} exists and is not a directory; nothing was restored"),
        )),
        Ok(_) => Ok(json!({
            "path": dest,
            "exists": true,
            "would_create": false,
            "empty": fs::read_dir(path).ok().map(|mut d| d.next().is_none()),
            "writable": writable(path),
        })),
        Err(_) => {
            let parent = path
                .ancestors()
                .skip(1)
                .find(|a| a.as_os_str().is_empty() || a.exists())
                .unwrap_or(Path::new("."));
            Ok(json!({
                "path": dest,
                "exists": false,
                "would_create": true,
                "empty": true,
                "writable": writable(parent),
            }))
        }
    }
}

/// The inputs of a restore dry run.
struct RestorePlan<'a> {
    args: &'a Args,
    cx: &'a mut Ctx,
    c: &'a Common,
    snapshot_id: &'a str,
    dest: &'a str,
    archive: &'a str,
    snapshot_dir: &'a str,
    include: &'a [String],
    exclude: &'a [String],
    destination: Value,
}

/// Lets unit tests give `schedule` a cron provider they keep a handle on.
#[cfg(test)]
#[derive(Debug)]
struct SharedCronProvider(std::sync::Arc<dyn crate::handles::processes::cronh::CronProvider>);

#[cfg(test)]
impl crate::handles::processes::cronh::CronProvider for SharedCronProvider {
    fn list_cron_entries(
        &self,
        o: &crate::handles::processes::cronh::CronListOptions,
    ) -> Result<crate::handles::processes::cronh::CronListResponse> {
        self.0.list_cron_entries(o)
    }
    fn add_cron_job(
        &self,
        o: &crate::handles::processes::cronh::CronAddOptions,
    ) -> Result<crate::handles::processes::cronh::CronAddResponse> {
        self.0.add_cron_job(o)
    }
    fn remove_cron_jobs(
        &self,
        o: &crate::handles::processes::cronh::CronRmOptions,
    ) -> Result<crate::handles::processes::cronh::CronRmResponse> {
        self.0.remove_cron_jobs(o)
    }
    fn enable_cron_jobs(
        &self,
        o: &crate::handles::processes::cronh::CronEnableOptions,
    ) -> Result<crate::handles::processes::cronh::CronEnableResponse> {
        self.0.enable_cron_jobs(o)
    }
    fn disable_cron_jobs(
        &self,
        o: &crate::handles::processes::cronh::CronDisableOptions,
    ) -> Result<crate::handles::processes::cronh::CronDisableResponse> {
        self.0.disable_cron_jobs(o)
    }
}

/// Per-call state: what the envelope reports, also on failure.
struct Ctx {
    verb: String,
    pretty: bool,
    dry_run: bool,
    start: Instant,
    timeout_ms: u64,
    deadline: Instant,
    info: BackendInfo,
    warnings: Vec<String>,
}

impl Ctx {
    fn new(verb: &str) -> Self {
        let now = Instant::now();
        Ctx {
            verb: verb.to_string(),
            pretty: false,
            dry_run: false,
            start: now,
            timeout_ms: 0,
            deadline: now,
            info: BackendInfo {
                id: "unknown".to_string(),
                version: None,
                command: vec![],
                env_redacted: HashMap::new(),
                cwd: None,
                timeout_ms: 0,
                simulated: false,
            },
            warnings: Vec::new(),
        }
    }

    /// Starts the verb's deadline: `timeout_ms` covers the whole verb.
    fn set_timeout(&mut self, timeout_ms: u64) {
        self.timeout_ms = timeout_ms;
        self.info.timeout_ms = timeout_ms;
        let limit = Duration::from_millis(timeout_ms);
        // This verb's deadline replaces any earlier one in this thread.
        process::clear_limit();
        self.deadline = self.start + process::limit(limit);
    }

    fn timeout_fail(&self, what: &str) -> Fail {
        Fail::new(
            Code::Timeout,
            format!(
                "{what} did not finish within timeout_ms={}",
                self.timeout_ms
            ),
        )
    }
}

/// The repository-related arguments every backend verb shares.
struct Common {
    backend: BackendType,
    repo_url: Option<String>,
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
            bin_dir: None,
            #[cfg(test)]
            cron_provider: None,
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

    /// The executable for `program`: from the test directory when one is
    /// set, else from `PATH`.
    fn program_path(&self, program: &str) -> Option<PathBuf> {
        match &self.bin_dir {
            Some(dir) => {
                let p = dir.join(program);
                p.is_file().then_some(p)
            }
            None => which::which(program).ok(),
        }
    }

    /// The backend named by `backend=` (default `auto`: the first of restic,
    /// borg, rsync, tar that is installed).
    fn select_backend(&self, args: &Args) -> VResult<BackendType> {
        let requested = args.get("backend").map(String::as_str).unwrap_or("auto");
        let parsed = match requested {
            "restic" => Some(BackendType::Restic),
            "borg" => Some(BackendType::Borg),
            "rsync" => Some(BackendType::Rsync),
            "tar" => Some(BackendType::Tar),
            "auto" => None,
            other => {
                let mut msg =
                    format!("backend must be auto, restic, borg, rsync or tar, got {other:?}");
                if let Some(s) = suggest(other, &["auto", "restic", "borg", "rsync", "tar"]) {
                    msg.push_str(&format!("; did you mean {s}?"));
                }
                msg.push_str("; nothing was done");
                return Err(Fail::invalid("backend", msg));
            }
        };
        if let Some(b) = parsed {
            return Ok(b);
        }
        for b in [
            BackendType::Restic,
            BackendType::Borg,
            BackendType::Rsync,
            BackendType::Tar,
        ] {
            if self.program_path(&b.to_string()).is_some() {
                return Ok(b);
            }
        }
        Err(Fail::new(
            Code::BackendNotFound,
            "no supported backend found; install one of restic, borg, rsync, tar",
        ))
    }

    /// Fails with backend_not_found when `program` is not installed.
    fn require_program(&self, program: &str) -> VResult<()> {
        if self.program_path(program).is_none() {
            return Err(Fail::new(
                Code::BackendNotFound,
                format!("{program} is not installed (not found on PATH); nothing was done"),
            ));
        }
        Ok(())
    }

    /// Backend, repository, password and value checks shared by the
    /// repository verbs. Runs before anything is done.
    fn common(&self, verb: &str, args: &Args, cx: &mut Ctx) -> VResult<Common> {
        let backend = self.select_backend(args)?;
        cx.info.id = backend.to_string();
        if let Some(msg) = repo_url_required(&backend, args) {
            return Err(Fail::invalid("repo_url", msg));
        }
        validate_request(&backend, verb, args)?;
        if backend == BackendType::Restic
            && args.get("repo_url").is_none()
            && !RESTIC_REPO_ENV
                .iter()
                .any(|k| std::env::var_os(k).is_some())
        {
            return Err(Fail::invalid(
                "repo_url",
                "restic needs a repository: pass repo_url=<repo> or set RESTIC_REPOSITORY; \
                 nothing was done",
            ));
        }
        if backend.is_local() {
            for key in ["password", "password_file"] {
                if args.contains_key(key) {
                    return Err(Fail::invalid(
                        key,
                        format!(
                            "{key} is not used by the {backend} backend ({backend} \
                             repositories are not encrypted); nothing was done"
                        ),
                    ));
                }
            }
        } else if args.contains_key("password") && args.contains_key("password_file") {
            return Err(Fail::invalid(
                "password",
                "pass either password or password_file, not both; nothing was done",
            ));
        }
        if args.contains_key("tag") && backend != BackendType::Restic {
            return Err(Fail::invalid(
                "tag",
                format!("tag is only supported by restic, not {backend}; nothing was done"),
            ));
        }
        Ok(Common {
            backend,
            repo_url: args.get("repo_url").cloned(),
        })
    }

    /// Adds the repository password to `spec` (restic/borg), or fails before
    /// anything runs.
    fn apply_secret(&self, c: &Common, args: &Args, spec: &mut CmdSpec) -> VResult<()> {
        let secret = resolve_repo_secret(
            &c.backend,
            args,
            |k| std::env::var_os(k).is_some(),
            |p| fs::read_to_string(p),
        )
        .map_err(|e| match e {
            SecretError::Missing(m) => Fail::new(Code::MissingPassword, m),
            SecretError::Unreadable(m) => Fail::new(Code::PasswordFileUnreadable, m),
        })?;
        secret.apply(spec);
        Ok(())
    }

    /// Runs `spec` under the verb's deadline. The whole process tree of the
    /// backend is stopped at the deadline.
    fn execute(&self, cx: &Ctx, spec: &CmdSpec) -> VResult<BackendResult> {
        let start = Instant::now();
        let program = self.program_path(&spec.program).ok_or_else(|| {
            Fail::new(
                Code::BackendNotFound,
                format!("{} is not installed (not found on PATH)", spec.program),
            )
        })?;
        let mut cmd = Command::new(&program);
        cmd.args(&spec.args);
        for key in &spec.env_remove {
            cmd.env_remove(key);
        }
        for (key, value) in &spec.env {
            cmd.env(key, value);
        }
        if let Some(cwd) = &spec.cwd {
            cmd.current_dir(cwd);
        }
        let limit = cx.deadline.saturating_duration_since(Instant::now());
        let output = match process::run(&mut cmd, Some(limit)) {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                return Err(Fail::new(
                    Code::Timeout,
                    format!("{e} at the deadline (timeout_ms={})", cx.timeout_ms),
                )
                .with(json!({ "timeout_ms": cx.timeout_ms })));
            }
            Err(e) => {
                return Err(Fail::new(
                    Code::ExecutionFailed,
                    format!("cannot run {}: {}", spec.program, e),
                ));
            }
        };
        use std::os::unix::process::ExitStatusExt;
        Ok(BackendResult {
            exit_code: output.status.code(),
            signal: output.status.signal(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Like `execute`, and writes each progress event of the backend as one
    /// JSON line on stdout as it happens (flushed per line).
    fn execute_streaming(
        &self,
        cx: &Ctx,
        spec: &CmdSpec,
        backend: &BackendType,
        io: &mut IoStreams,
    ) -> VResult<BackendResult> {
        use std::io::BufRead;
        use std::os::unix::process::ExitStatusExt;
        use std::sync::mpsc;
        let start = Instant::now();
        let program = self.program_path(&spec.program).ok_or_else(|| {
            Fail::new(
                Code::BackendNotFound,
                format!("{} is not installed (not found on PATH)", spec.program),
            )
        })?;
        let mut cmd = Command::new(&program);
        cmd.args(&spec.args);
        for key in &spec.env_remove {
            cmd.env_remove(key);
        }
        for (key, value) in &spec.env {
            cmd.env(key, value);
        }
        if let Some(cwd) = &spec.cwd {
            cmd.current_dir(cwd);
        }
        process::contain(&mut cmd);
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| {
            Fail::new(
                Code::ExecutionFailed,
                format!("cannot run {}: {}", spec.program, e),
            )
        })?;
        let group = child.id() as libc::pid_t;
        let (tx, rx) = mpsc::channel::<(bool, String)>();
        let pipes: [(bool, Option<Box<dyn Read + Send>>); 2] = [
            (
                true,
                child
                    .stdout
                    .take()
                    .map(|p| Box::new(p) as Box<dyn Read + Send>),
            ),
            (
                false,
                child
                    .stderr
                    .take()
                    .map(|p| Box::new(p) as Box<dyn Read + Send>),
            ),
        ];
        for (is_stdout, pipe) in pipes {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let Some(pipe) = pipe else { return };
                let mut reader = std::io::BufReader::new(pipe);
                let mut buf = Vec::new();
                while matches!(reader.read_until(b'\n', &mut buf), Ok(n) if n > 0) {
                    let line = String::from_utf8_lossy(&buf).into_owned();
                    if tx.send((is_stdout, line)).is_err() {
                        return;
                    }
                    buf.clear();
                }
            });
        }
        drop(tx);
        let (mut stdout, mut stderr) = (String::new(), String::new());
        let mut exited: Option<(std::process::ExitStatus, Instant)> = None;
        loop {
            match rx.recv_timeout(Duration::from_millis(20)) {
                Ok((is_stdout, line)) => {
                    if let Some(p) = progress_event(backend, is_stdout, &line) {
                        let event = json!({
                            "event": "progress",
                            "handle": "backup",
                            "verb": cx.verb,
                            "backend": backend.to_string(),
                            "ts": Utc::now().to_rfc3339(),
                            "progress": p,
                        });
                        let _ = writeln!(io.stdout, "{event}");
                        let _ = io.stdout.flush();
                    }
                    if is_stdout {
                        stdout.push_str(&line);
                    } else {
                        stderr.push_str(&line);
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    if exited.is_some() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            if exited.is_none()
                && let Ok(Some(status)) = child.try_wait()
            {
                exited = Some((status, Instant::now()));
            }
            // A descendant can hold the output open after the backend exits.
            if let Some((_, at)) = exited
                && at.elapsed() >= Duration::from_secs(2)
            {
                break;
            }
            if exited.is_none() && Instant::now() >= cx.deadline {
                let stopped = process::stop_tree(&spec.program, group);
                let _ = child.try_wait();
                let state = match stopped {
                    process::Stopped::StillRunning => "could not be stopped",
                    _ => "was stopped",
                };
                return Err(Fail::new(
                    Code::Timeout,
                    format!(
                        "{} timed out and {state} at the deadline (timeout_ms={})",
                        spec.program, cx.timeout_ms
                    ),
                )
                .with(json!({ "timeout_ms": cx.timeout_ms })));
            }
        }
        let Some((status, _)) = exited else {
            unreachable!("the loop ends only after the backend exited")
        };
        Ok(BackendResult {
            exit_code: status.code(),
            signal: status.signal(),
            stdout,
            stderr,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Runs `spec`, streaming progress events when `progress` is set.
    fn run_backend(
        &self,
        cx: &Ctx,
        spec: &CmdSpec,
        backend: &BackendType,
        progress: bool,
        io: &mut IoStreams,
    ) -> VResult<BackendResult> {
        if progress {
            self.execute_streaming(cx, spec, backend, io)
        } else {
            self.execute(cx, spec)
        }
    }

    /// backend_failed for a backend that exited non-zero or was killed.
    fn exit_fail(&self, spec: &CmdSpec, res: &BackendResult) -> Fail {
        let last = res
            .stderr
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("")
            .trim();
        let how = match (res.exit_code, res.signal) {
            (Some(c), _) => format!("exited with status {c}"),
            (None, Some(s)) => format!("was killed by signal {s}"),
            (None, None) => "failed".to_string(),
        };
        let mut message = format!("{} {}", spec.program, how);
        if !last.is_empty() {
            message.push_str(&format!(": {last}"));
        }
        Fail::new(Code::BackendFailed, message).with(json!({
            "exit_code": res.exit_code,
            "signal": res.signal,
            "stderr_tail": stderr_tail(&res.stderr),
        }))
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

    fn set_info(&self, cx: &mut Ctx, backend: &BackendType, spec: Option<&CmdSpec>) {
        cx.info = self.backend_info(backend, spec, cx.timeout_ms, cx.dry_run && spec.is_some());
    }

    /// Warns (stderr) when the password is given on the command line.
    fn warn_plain_password(args: &Args, io: &mut IoStreams) {
        if args.contains_key("password") {
            let _ = writeln!(
                io.stderr,
                "Warning: password= puts the repository password on the command line, where \
                 the process list and shell history can show it; use password_file=<path> or \
                 the backend's password environment variables"
            );
        }
    }

    /// Writes the envelope for `outcome` and returns the status.
    fn finish(&self, cx: Ctx, outcome: VResult<Value>, io: &mut IoStreams) -> Result<Status> {
        let elapsed = cx.start.elapsed().as_millis() as u64;
        let (envelope, status) = match outcome {
            Ok(result) => {
                let mut e = BackupEnvelope::success(
                    &cx.verb,
                    &self.target,
                    cx.info,
                    result,
                    cx.dry_run,
                    elapsed,
                );
                e.warnings = cx.warnings;
                (e, Status::success())
            }
            Err(f) => {
                let code = f.code.code();
                let error = BackupError {
                    code: code.to_string(),
                    kind: f.code.kind().to_string(),
                    message: f.message.clone(),
                    details: f.details,
                };
                let mut e = BackupEnvelope::error(
                    &cx.verb,
                    &self.target,
                    cx.info,
                    error,
                    cx.dry_run,
                    elapsed,
                );
                e.warnings = cx.warnings;
                // A backend lost to its deadline is reported by main
                // (`[backup.timeout] outcome unknown ...`); every other
                // failure is reported here, in the standard format.
                if !(f.code == Code::Timeout && process::has_lost()) {
                    let _ = writeln!(io.stderr, "{}", status::error_line(code, &f.message));
                }
                (e, Status::coded(f.code.exit(), code, &f.message))
            }
        };
        let text = if cx.pretty {
            serde_json::to_string_pretty(&envelope)?
        } else {
            serde_json::to_string(&envelope)?
        };
        writeln!(io.stdout, "{}", text)?;
        io.stdout.flush()?;
        Ok(status)
    }
}

// Verb implementations
impl BackupHandle {
    fn verb_create(&self, args: &Args, cx: &mut Ctx, io: &mut IoStreams) -> VResult<Value> {
        let src = required(args, "src")?;
        cx.set_timeout(arg_timeout(args, DEFAULT_CREATE_TIMEOUT_MS)?);
        let c = self.common("create", args, cx)?;
        let backend = c.backend.clone();
        let repo_url = c.repo_url.as_ref();
        let progress = arg_progress(args, &backend)?;

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
        let name = snapshot_name(
            label.as_deref(),
            &Utc::now().format("%Y%m%d_%H%M%S").to_string(),
        );

        // (command, snapshot id known in advance, repo dir, tar archive, rsync dir)
        let (mut spec, known_id, repo_dir, archive, snap_dir) = match backend {
            BackendType::Tar => {
                let repo = local_repo_path(repo_url);
                let name = unique_local_name(Path::new(&repo), &name, ".tar.gz");
                let archive = format!("{}/{}.tar.gz", repo, name);
                (
                    build_tar_create(&archive, &sources, &exclude),
                    Some(name),
                    Some(repo),
                    Some(archive),
                    None,
                )
            }
            BackendType::Restic => (
                build_restic_create(repo_url, &sources, &tags, label.as_deref(), &exclude),
                None,
                None,
                None,
                None,
            ),
            BackendType::Borg => (
                build_borg_create(&borg_repo(repo_url), &name, &sources, &exclude),
                Some(name),
                None,
                None,
                None,
            ),
            BackendType::Rsync => {
                let repo = local_repo_path(repo_url);
                let name = unique_local_name(Path::new(&repo), &name, "");
                let dir = format!("{}/{}", repo, name);
                (
                    build_rsync_create(&format!("{dir}/"), &sources, &exclude),
                    Some(name),
                    Some(repo),
                    None,
                    Some(dir),
                )
            }
        };
        if progress && backend == BackendType::Borg {
            spec = with_flags(spec, 1, &["--progress", "--log-json"]);
        }
        self.set_info(cx, &backend, Some(&spec));
        self.apply_secret(&c, args, &mut spec)?;
        self.set_info(cx, &backend, Some(&spec));
        self.require_program(&spec.program)?;
        let capabilities = self.get_capabilities(&backend);

        if cx.dry_run {
            let snapshot = SnapshotInfo {
                id: "dry-run-id".to_string(),
                label: label.clone(),
                tags: tags.clone(),
                created_at: Utc::now().to_rfc3339(),
                sources: sources.clone(),
                bytes_sent: None,
                bytes_total: None,
            };
            cx.warnings
                .push("Dry run: no backup was created".to_string());
            return Ok(json!({
                "capabilities": capabilities,
                "snapshot": snapshot,
                "backend_raw": { "stdout": "", "stderr": "" },
                "dry_run_mode": "plan"
            }));
        }

        // Local repositories and their snapshots are owner-only, and the
        // snapshot is created new: nothing planted at its name is written
        // through.
        let mut created: Option<PathBuf> = None;
        if let Some(dir) = &repo_dir {
            create_private_dir_all(Path::new(dir)).map_err(|e| {
                Fail::new(
                    Code::Io,
                    format!("cannot create repository directory {dir}: {e}"),
                )
            })?;
        }
        if let Some(archive) = &archive {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(archive)
                .map_err(|e| Fail::new(Code::Io, format!("cannot create {archive}: {e}")))?;
            created = Some(PathBuf::from(archive));
        }
        if let Some(dir) = &snap_dir {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(dir)
                .map_err(|e| Fail::new(Code::Io, format!("cannot create {dir}: {e}")))?;
            created = Some(PathBuf::from(dir));
        }
        // A failed or stopped backup leaves no partial snapshot behind.
        let clean_up = |f: Fail| -> Fail {
            let Some(path) = &created else { return f };
            let removed = if path.is_dir() {
                fs::remove_dir_all(path)
            } else {
                fs::remove_file(path)
            };
            let mut details = f.details.clone().unwrap_or_else(|| json!({}));
            details["partial_snapshot"] = json!(path.display().to_string());
            details["partial_snapshot_removed"] = json!(removed.is_ok());
            Fail {
                details: Some(details),
                ..f
            }
        };

        let res = self
            .run_backend(cx, &spec, &backend, progress, io)
            .map_err(clean_up)?;
        if !res.success() {
            match res.exit_code.and_then(|c| create_exit_warning(&backend, c)) {
                Some(w) => cx.warnings.push(w.to_string()),
                None => return Err(clean_up(self.exit_fail(&spec, &res))),
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
            cx.warnings.push(format!(
                "Backup completed, but no snapshot id was found in the {} output; see result.backend_raw",
                backend
            ));
        }
        Ok(json!({
            "capabilities": capabilities,
            "snapshot": snapshot,
            "backend_raw": {
                "stdout": truncate_output(&res.stdout),
                "stderr": truncate_output(&res.stderr)
            }
        }))
    }

    fn verb_list(&self, args: &Args, cx: &mut Ctx) -> VResult<Value> {
        cx.set_timeout(arg_timeout(args, DEFAULT_LIST_TIMEOUT_MS)?);
        let c = self.common("list", args, cx)?;
        let backend = c.backend.clone();
        let repo_url = c.repo_url.as_ref();
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
                self.set_info(cx, &backend, None);
                let snaps = scan_local_snapshots(&backend, Path::new(&repo), false, cx.deadline)
                    .map_err(|e| match e {
                        ScanError::Io(e) => Fail::new(
                            Code::Io,
                            format!("cannot read repository directory {repo}: {e}"),
                        ),
                        ScanError::Deadline => cx.timeout_fail("listing the repository"),
                    })?;
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
                return Ok(json!({
                    "snapshots": snapshots,
                    "total_count": snapshots.len(),
                    "capabilities": capabilities
                }));
            }
        };
        self.set_info(cx, &backend, Some(&spec));
        self.apply_secret(&c, args, &mut spec)?;
        self.set_info(cx, &backend, Some(&spec));
        self.require_program(&spec.program)?;

        let res = self.execute(cx, &spec)?;
        if !res.success() {
            return Err(self.exit_fail(&spec, &res));
        }
        let snapshots = parse_list_output(&backend, &res.stdout)
            .map_err(|e| Fail::new(Code::Parse, format!("{:#}", e)))?;
        Ok(json!({
            "snapshots": snapshots,
            "total_count": snapshots.len(),
            "capabilities": capabilities
        }))
    }

    fn verb_restore(&self, args: &Args, cx: &mut Ctx, io: &mut IoStreams) -> VResult<Value> {
        let snapshot_id = required(args, "snapshot_id")?;
        let dest = required(args, "dest")?;
        cx.set_timeout(arg_timeout(args, DEFAULT_RESTORE_TIMEOUT_MS)?);
        let c = self.common("restore", args, cx)?;
        let backend = c.backend.clone();
        let repo_url = c.repo_url.as_ref();
        let progress = arg_progress(args, &backend)?;
        let include = args
            .get("include")
            .map(|i| split_list(i, ','))
            .unwrap_or_default();
        let exclude = args
            .get("exclude")
            .map(|e| split_list(e, ';'))
            .unwrap_or_default();

        // Never restore through a symlink planted at dest.
        let dest_path = Path::new(dest);
        let destination = check_destination(dest_path, dest)?;
        let repo = local_repo_path(repo_url);
        let archive = format!("{}/{}.tar.gz", repo, snapshot_id);
        let snapshot_dir = format!("{}/{}/", repo, snapshot_id);

        if cx.dry_run {
            return self.restore_plan(RestorePlan {
                args,
                cx,
                c: &c,
                snapshot_id,
                dest,
                archive: &archive,
                snapshot_dir: &snapshot_dir,
                include: &include,
                exclude: &exclude,
                destination,
            });
        }

        let mut spec = match backend {
            BackendType::Restic => {
                build_restic_restore(repo_url, snapshot_id, dest, &include, &exclude)
            }
            BackendType::Borg => {
                let spec =
                    build_borg_restore(&borg_repo(repo_url), snapshot_id, dest, &include, &exclude);
                if progress {
                    with_flags(spec, 1, &["--progress", "--log-json"])
                } else {
                    spec
                }
            }
            BackendType::Tar => build_tar_restore(&archive, dest, &include, &exclude),
            BackendType::Rsync => build_rsync_restore(&snapshot_dir, dest, &include, &exclude),
        };
        self.set_info(cx, &backend, Some(&spec));
        self.apply_secret(&c, args, &mut spec)?;
        self.set_info(cx, &backend, Some(&spec));
        self.require_program(&spec.program)?;

        // A missing destination is created owner-only; borg extracts into
        // its working directory and tar -C needs an existing directory.
        if !dest_path.exists() {
            create_private_dir_all(dest_path).map_err(|e| {
                Fail::new(
                    Code::Io,
                    format!("cannot create destination directory {dest}: {e}"),
                )
            })?;
        }

        let partial = |f: Fail| -> Fail {
            let mut details = f.details.clone().unwrap_or_else(|| json!({}));
            details["destination"] = json!(dest);
            details["partial_restore_possible"] = json!(true);
            Fail {
                details: Some(details),
                ..f
            }
        };
        let res = self
            .run_backend(cx, &spec, &backend, progress, io)
            .map_err(partial)?;
        if !res.success() {
            return Err(partial(self.exit_fail(&spec, &res)));
        }
        let (files, bytes): (Option<u64>, Option<u64>) = match backend {
            BackendType::Restic => parse_restic_restore_summary(&res.stdout),
            BackendType::Tar => {
                let (f, b) = count_listed_files(dest_path, &res.stdout);
                (Some(f), Some(b))
            }
            BackendType::Borg => {
                let listed = borg_listed(&res.stdout, &res.stderr);
                let (f, b) = count_listed_files(dest_path, &listed);
                (Some(f), Some(b))
            }
            BackendType::Rsync => (
                rsync_stat(&res.stdout, "Number of regular files transferred:"),
                rsync_stat(&res.stdout, "Total transferred file size:"),
            ),
        };
        if files.is_none() {
            cx.warnings.push(format!(
                "the {backend} output did not say how many files were restored"
            ));
        }
        Ok(json!({
            "restored": {
                "files_restored": files,
                "bytes_restored": bytes,
                "success": true
            },
            "snapshot_id": snapshot_id,
            "destination": dest,
            "capabilities": self.get_capabilities(&backend)
        }))
    }

    /// `restore dry_run=true`: checks the destination and lists what the
    /// restore would write with the backend's read-only listing (restic
    /// `restore --dry-run`, borg `list`, tar `-t`, rsync `--dry-run`).
    /// Nothing is written to the destination.
    fn restore_plan(&self, p: RestorePlan<'_>) -> VResult<Value> {
        let RestorePlan {
            args,
            cx,
            c,
            snapshot_id,
            dest,
            archive,
            snapshot_dir,
            include,
            exclude,
            destination,
        } = p;
        let backend = c.backend.clone();
        let repo_url = c.repo_url.as_ref();
        match backend {
            BackendType::Tar if !Path::new(archive).is_file() => {
                return Err(Fail::new(
                    Code::SnapshotNotFound,
                    format!("no archive {archive}; nothing was restored"),
                ));
            }
            BackendType::Rsync if !Path::new(snapshot_dir).is_dir() => {
                return Err(Fail::new(
                    Code::SnapshotNotFound,
                    format!("no snapshot directory {snapshot_dir}; nothing was restored"),
                ));
            }
            _ => {}
        }
        let mut spec = match backend {
            BackendType::Restic => with_flags(
                build_restic_restore(repo_url, snapshot_id, dest, include, exclude),
                2,
                &["--dry-run"],
            ),
            BackendType::Borg => {
                build_borg_restore_list(&borg_repo(repo_url), snapshot_id, include, exclude)
            }
            BackendType::Tar => build_tar_restore_list(archive, include, exclude),
            BackendType::Rsync => with_flags(
                build_rsync_restore(snapshot_dir, dest, include, exclude),
                2,
                &["--dry-run"],
            ),
        };
        // The listing runs, so the command is reported as run, not simulated.
        cx.info = self.backend_info(&backend, Some(&spec), cx.timeout_ms, false);
        self.apply_secret(c, args, &mut spec)?;
        cx.info = self.backend_info(&backend, Some(&spec), cx.timeout_ms, false);
        self.require_program(&spec.program)?;
        let res = self.execute(cx, &spec)?;
        if !res.success() {
            return Err(self.exit_fail(&spec, &res));
        }
        let (files, bytes) = match backend {
            BackendType::Restic => parse_restic_restore_summary(&res.stdout),
            BackendType::Borg => {
                let (f, b) = parse_borg_listing(&res.stdout);
                (Some(f), Some(b))
            }
            BackendType::Tar => {
                let (f, b) = parse_tar_listing(&res.stdout);
                (Some(f), Some(b))
            }
            BackendType::Rsync => (
                rsync_stat(&res.stdout, "Number of regular files transferred:"),
                rsync_stat(&res.stdout, "Total transferred file size:"),
            ),
        };
        if destination["empty"] == json!(false) {
            cx.warnings.push(format!(
                "dest {dest} is not empty: a restore may overwrite files in it"
            ));
        }
        if destination["writable"] == json!(false) {
            cx.warnings
                .push(format!("dest {dest} is not writable by this user"));
        }
        cx.warnings
            .push("Dry run: nothing was restored".to_string());
        Ok(json!({
            "dry_run": true,
            "dry_run_mode": "backend",
            "snapshot_id": snapshot_id,
            "destination": destination,
            "would_restore": { "files": files, "bytes": bytes },
            "capabilities": self.get_capabilities(&backend)
        }))
    }

    fn verb_verify(&self, args: &Args, cx: &mut Ctx) -> VResult<Value> {
        cx.set_timeout(arg_timeout(args, DEFAULT_VERIFY_TIMEOUT_MS)?);
        let mode = args.get("mode").map(String::as_str).unwrap_or("quick");
        if !matches!(mode, "quick" | "thorough" | "data") {
            return Err(Fail::invalid(
                "mode",
                format!("mode must be quick, thorough or data, got {mode:?}; nothing was done"),
            ));
        }
        let c = self.common("verify", args, cx)?;
        let backend = c.backend.clone();
        let repo_url = c.repo_url.as_ref();
        let snapshot_id = args.get("snapshot_id");
        if snapshot_id.is_some() && backend == BackendType::Restic {
            return Err(Fail::invalid(
                "snapshot_id",
                "restic check always checks the whole repository; snapshot_id is supported \
                 for borg, tar and rsync; nothing was done",
            ));
        }
        let read_data = mode != "quick";
        let capabilities = self.get_capabilities(&backend);

        let verification = match backend {
            BackendType::Restic | BackendType::Borg => {
                let mut spec = if backend == BackendType::Restic {
                    build_restic_verify(repo_url, read_data)
                } else {
                    build_borg_verify(
                        &borg_repo(repo_url),
                        snapshot_id.map(String::as_str),
                        read_data,
                    )
                };
                self.set_info(cx, &backend, Some(&spec));
                self.apply_secret(&c, args, &mut spec)?;
                self.set_info(cx, &backend, Some(&spec));
                self.require_program(&spec.program)?;
                let res = self.execute(cx, &spec)?;
                if !res.success() {
                    return Err(self.exit_fail(&spec, &res));
                }
                json!({
                    "success": true,
                    "issues": Vec::<String>::new(),
                    "files_checked": null,
                    "errors": Vec::<String>::new()
                })
            }
            BackendType::Tar => {
                let repo = local_repo_path(repo_url);
                self.set_info(cx, &backend, None);
                self.require_program("tar")?;
                let mut archives =
                    scan_local_snapshots(&backend, Path::new(&repo), false, cx.deadline).map_err(
                        |e| match e {
                            ScanError::Io(e) => Fail::new(
                                Code::Io,
                                format!("cannot read repository directory {repo}: {e}"),
                            ),
                            ScanError::Deadline => cx.timeout_fail("reading the repository"),
                        },
                    )?;
                if let Some(id) = snapshot_id {
                    archives.retain(|a| &a.id == id);
                    if archives.is_empty() {
                        return Err(Fail::new(
                            Code::SnapshotNotFound,
                            format!("no archive {id}.tar.gz in {repo}"),
                        ));
                    }
                }
                let mut files_checked = 0;
                let mut issues = Vec::new();
                let mut errors = Vec::new();
                let mut checked = Vec::new();
                for a in &archives {
                    let spec = build_tar_verify(&a.path.to_string_lossy());
                    cx.info.command = spec.argv();
                    let res = self.execute(cx, &spec).map_err(|f| {
                        let mut details = f.details.clone().unwrap_or_else(|| json!({}));
                        details["archives"] = json!(checked);
                        Fail {
                            details: Some(details),
                            ..f
                        }
                    })?;
                    if res.success() {
                        let members = res.stdout.lines().count();
                        files_checked += members;
                        checked.push(json!({ "id": a.id, "ok": true, "members": members }));
                    } else {
                        issues.push(format!(
                            "{}: tar exited with {}",
                            a.id,
                            res.exit_code
                                .map_or("a signal".to_string(), |c| c.to_string())
                        ));
                        errors.push(stderr_tail(&res.stderr));
                        checked.push(json!({ "id": a.id, "ok": false, "members": 0 }));
                    }
                }
                if archives.is_empty() {
                    issues.push(format!("no .tar.gz archives found in {}", repo));
                }
                json!({
                    "success": issues.is_empty(),
                    "issues": issues,
                    "files_checked": files_checked,
                    "errors": errors,
                    "archives": checked
                })
            }
            BackendType::Rsync => {
                let repo = local_repo_path(repo_url);
                self.set_info(cx, &backend, None);
                if !Path::new(&repo).is_dir() {
                    return Err(Fail::new(
                        Code::Io,
                        format!("repository directory {repo} does not exist"),
                    ));
                }
                let root = match snapshot_id {
                    Some(id) => {
                        let p = Path::new(&repo).join(id);
                        let is_dir = fs::symlink_metadata(&p).is_ok_and(|m| m.is_dir());
                        if !is_dir {
                            return Err(Fail::new(
                                Code::SnapshotNotFound,
                                format!("no snapshot directory {id} in {repo}"),
                            ));
                        }
                        p
                    }
                    None => PathBuf::from(&repo),
                };
                let (files_checked, errors) =
                    check_files_readable(&root, read_data, cx.deadline)
                        .map_err(|_| cx.timeout_fail("reading the repository"))?;
                let issues: Vec<String> = if errors.is_empty() {
                    vec![]
                } else {
                    vec!["File access issues found".to_string()]
                };
                json!({
                    "success": errors.is_empty(),
                    "issues": issues,
                    "files_checked": files_checked,
                    "errors": errors
                })
            }
        };

        if verification["success"] != json!(true) {
            return Err(
                Fail::new(Code::VerifyFailed, "Backup verification found problems")
                    .with(verification),
            );
        }
        Ok(json!({
            "verification": verification,
            "mode": mode,
            "snapshot_id": snapshot_id,
            "capabilities": capabilities
        }))
    }

    fn verb_prune(&self, args: &Args, cx: &mut Ctx) -> VResult<Value> {
        cx.set_timeout(arg_timeout(args, DEFAULT_PRUNE_TIMEOUT_MS)?);
        let policy = RetentionPolicy {
            keep_daily: arg_keep(args, "keep_daily")?,
            keep_weekly: arg_keep(args, "keep_weekly")?,
            keep_monthly: arg_keep(args, "keep_monthly")?,
        };
        if policy.keep_daily.is_none()
            && policy.keep_weekly.is_none()
            && policy.keep_monthly.is_none()
        {
            return Err(Fail::invalid(
                "keep_daily",
                "prune needs at least one of keep_daily, keep_weekly, keep_monthly; \
                 nothing was pruned",
            ));
        }
        let c = self.common("prune", args, cx)?;
        let backend = c.backend.clone();
        let repo_url = c.repo_url.as_ref();
        let capabilities = self.get_capabilities(&backend);
        let policy_json = json!({
            "keep_daily": policy.keep_daily,
            "keep_weekly": policy.keep_weekly,
            "keep_monthly": policy.keep_monthly
        });
        let stats_key = if cx.dry_run { "would_prune" } else { "pruned" };

        match backend {
            BackendType::Restic | BackendType::Borg => {
                let mut spec = if backend == BackendType::Restic {
                    build_restic_prune(repo_url, &policy, cx.dry_run)
                } else {
                    build_borg_prune(&borg_repo(repo_url), &policy, cx.dry_run)
                };
                cx.info = self.backend_info(&backend, Some(&spec), cx.timeout_ms, false);
                self.apply_secret(&c, args, &mut spec)?;
                // The backend runs even in a dry run (its own --dry-run), so
                // the command is not simulated.
                cx.info = self.backend_info(&backend, Some(&spec), cx.timeout_ms, false);
                self.require_program(&spec.program)?;
                let res = self.execute(cx, &spec)?;
                if !res.success() {
                    return Err(self.exit_fail(&spec, &res));
                }
                let removed = parse_prune_count(&backend, &res.stdout, &res.stderr);
                if removed.is_none() {
                    cx.warnings.push(format!(
                        "could not count removed snapshots in the {} output",
                        backend
                    ));
                }
                let mut result = json!({
                    "dry_run": cx.dry_run,
                    "policy": policy_json,
                    "capabilities": capabilities
                });
                if cx.dry_run {
                    // Only the backend can apply its retention policy to its
                    // repository, so this dry run runs it with its own
                    // --dry-run flag (documented in backup.md 4.5).
                    result["dry_run_mode"] = json!("backend");
                    cx.warnings.push(format!(
                        "Dry run: {} ran in its own --dry-run mode; nothing was removed",
                        backend
                    ));
                }
                result[stats_key] = json!({
                    "snapshots_removed": removed,
                    "bytes_freed": null,
                    "success": true
                });
                Ok(result)
            }
            BackendType::Tar | BackendType::Rsync => {
                let repo = local_repo_path(repo_url);
                self.set_info(cx, &backend, None);
                let snaps = scan_local_snapshots(&backend, Path::new(&repo), true, cx.deadline)
                    .map_err(|e| match e {
                        ScanError::Io(e) => Fail::new(
                            Code::Io,
                            format!("cannot read repository directory {repo}: {e}"),
                        ),
                        ScanError::Deadline => cx.timeout_fail("reading the repository"),
                    })?;
                let pairs: Vec<(String, DateTime<Utc>)> =
                    snaps.iter().map(|s| (s.id.clone(), s.modified)).collect();
                let to_remove = select_prune(&pairs, &policy);

                let mut removed = Vec::new();
                let mut bytes_freed = 0u64;
                let mut errors = Vec::new();
                let mut timed_out = false;
                for s in snaps.iter().filter(|s| to_remove.contains(&s.id)) {
                    if check_deadline(cx.deadline).is_err() {
                        timed_out = true;
                        break;
                    }
                    let outcome = if cx.dry_run {
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
                    "success": errors.is_empty() && !timed_out
                });
                if timed_out {
                    return Err(cx
                        .timeout_fail("pruning")
                        .with(json!({ stats_key: stats, "errors": errors })));
                }
                if !errors.is_empty() {
                    return Err(Fail::new(Code::Io, "Some snapshots could not be removed")
                        .with(json!({ stats_key: stats, "errors": errors })));
                }
                let mut result = json!({
                    "dry_run": cx.dry_run,
                    "policy": policy_json,
                    "capabilities": capabilities
                });
                if cx.dry_run {
                    result["dry_run_mode"] = json!("plan");
                }
                result[stats_key] = stats;
                Ok(result)
            }
        }
    }

    /// Installs a scheduled `create` for this profile with the cron handle's
    /// `add` (systemd timer or crontab line; every check is cron's own), or
    /// with `dry_run=true` reports what would be installed.
    fn verb_schedule(&self, args: &Args, cx: &mut Ctx) -> VResult<Value> {
        let when = required(args, "when")?;
        let src = required(args, "src")?;
        let enabled = bool_arg(args, "enabled", true)?;
        let scheduler = args.get("scheduler").map(String::as_str).unwrap_or("auto");
        if !matches!(scheduler, "auto" | "cron" | "systemd") {
            return Err(Fail::invalid(
                "scheduler",
                format!(
                    "scheduler must be auto, cron or systemd, got {scheduler:?}; nothing was done"
                ),
            ));
        }
        if args.contains_key("timeout_ms") {
            // Checked here; enforced by the cron handle on its tools.
            cx.info.timeout_ms = arg_timeout(args, 0)?;
        }
        let profile_ok = !self.repo.is_empty()
            && self
                .repo
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/'));
        if !profile_ok {
            return Err(Fail::invalid(
                "profile",
                format!(
                    "profile {:?} cannot be scheduled: use letters, digits, '-', '_' or '/'; \
                     nothing was done",
                    self.repo
                ),
            ));
        }
        let backend = self.select_backend(args)?;
        cx.info.id = backend.to_string();
        if let Some(msg) = repo_url_required(&backend, args) {
            return Err(Fail::invalid("repo_url", msg));
        }
        validate_request(&backend, "schedule", args)?;
        if backend.is_local() && args.contains_key("password_file") {
            return Err(Fail::invalid(
                "password_file",
                format!(
                    "password_file is not used by the {backend} backend ({backend} \
                     repositories are not encrypted); nothing was done"
                ),
            ));
        }
        if self.program_path(&backend.to_string()).is_none() {
            cx.warnings.push(format!(
                "{backend} is not installed here; the scheduled backup needs it"
            ));
        }
        if !backend.is_local() && !args.contains_key("password_file") {
            cx.warnings.push(format!(
                "no password_file: the scheduled job needs the {backend} password in its \
                 environment"
            ));
        }
        if backend == BackendType::Restic && !args.contains_key("repo_url") {
            cx.warnings.push(
                "no repo_url: the scheduled job needs RESTIC_REPOSITORY in its environment"
                    .to_string(),
            );
        }

        let mut command = vec![
            self.resh_program(),
            format!("backup://{}.create", self.repo),
            format!("src={src}"),
            format!("backend={backend}"),
        ];
        for key in ["repo_url", "password_file"] {
            if let Some(v) = args.get(key) {
                command.push(format!("{key}={v}"));
            }
        }
        let flat = self.repo.replace('/', "-");
        let label = format!("backup-{flat}");
        let id = format!("resh-backup-{flat}");
        let line: Vec<String> = command.iter().map(|w| shell_quote(w)).collect();
        let add = |dry_run: bool| {
            let mut add: Vec<(&str, String)> = vec![
                ("schedule", when.clone()),
                ("command", line.join(" ")),
                ("backend", scheduler.to_string()),
                ("id", id.clone()),
                ("description", format!("resh backup profile {}", self.repo)),
                ("allow_duplicate", "false".to_string()),
                ("dry_run", dry_run.to_string()),
            ];
            if let Some(t) = args.get("timeout_ms") {
                add.push(("timeout_ms", t.clone()));
            }
            add
        };
        // First cron's own dry run: the scheduler it picks, and whether this
        // exact job is already installed.
        let planned = self.cron_call(&label, "add", &add(true))?;
        let used = planned["backend_used"]
            .as_str()
            .unwrap_or(scheduler)
            .to_string();
        let duplicate = planned["duplicate"] == json!(true);
        if !duplicate {
            // Another job of this profile (a different schedule or command)
            // is never added beside it: remove it first.
            let probe = vec![
                ("id", id.clone()),
                ("backend", used.clone()),
                ("require_match", "false".to_string()),
                ("dry_run", "true".to_string()),
            ];
            let found = self.cron_call(&label, "rm", &probe)?;
            let matched = found["matched_count"]["cron"].as_u64().unwrap_or(0)
                + found["matched_count"]["systemd"].as_u64().unwrap_or(0);
            if matched > 0 {
                return Err(Fail::new(
                    Code::ScheduleFailed,
                    format!(
                        "a different job for profile {} (id {id}) is already installed; remove it \
                         with resh cron://{label}.rm id={id} backend={used} and schedule again; \
                         nothing was changed",
                        self.repo
                    ),
                )
                .with(json!({
                    "id": id,
                    "remove_command": ["resh", format!("cron://{label}.rm"), format!("id={id}"), format!("backend={used}")],
                })));
            }
        }
        let added = if cx.dry_run || duplicate {
            planned
        } else {
            self.cron_call(&label, "add", &add(false))?
        };
        cx.warnings.extend(json_strings(&added["warnings"]));

        if !enabled && !cx.dry_run {
            let disable = vec![("id", id.clone()), ("backend", used.clone())];
            let disabled = self.cron_call(&label, "disable", &disable).map_err(|f| {
                let mut details = f.details.clone().unwrap_or_else(|| json!({}));
                details["installed"] = json!(true);
                Fail {
                    details: Some(details),
                    ..f
                }
            })?;
            cx.warnings.extend(json_strings(&disabled["warnings"]));
        }
        if cx.dry_run {
            cx.warnings
                .push("Dry run: nothing was installed".to_string());
        }
        Ok(json!({
            "capabilities": self.get_capabilities(&backend),
            "schedule": {
                "when": when,
                "enabled": enabled,
                "scheduler": used,
                "id": id,
                "installed": !cx.dry_run,
                "duplicate": duplicate,
                "command": command,
                "job": added["job"],
                "preview": added["preview"],
                "remove_command": [
                    "resh",
                    format!("cron://{label}.rm"),
                    format!("id={id}"),
                    format!("backend={used}"),
                ],
            }
        }))
    }

    /// The program the scheduled job runs: this resh executable.
    fn resh_program(&self) -> String {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.to_str().map(String::from))
            .unwrap_or_else(|| "resh".to_string())
    }

    /// Runs a cron handle verb in-process and returns its JSON result, or
    /// its failure as a backup failure: a refused argument is
    /// `backup.invalid_argument` (exit 2), a timeout `backup.timeout`, any
    /// other failure `backup.schedule_failed`. `details.cron_error` carries
    /// the cron handle's error object.
    fn cron_call(&self, label: &str, verb: &str, args: &[(&str, String)]) -> VResult<Value> {
        let cron_args: Args = args
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect();
        let handle = self.cron_handle(label)?;
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut stdin = std::io::empty();
        let status = {
            let mut io = IoStreams::new(&mut stdin, &mut out, &mut err);
            handle.call(verb, &cron_args, &mut io)
        }
        .map_err(|e| Fail::new(Code::ScheduleFailed, format!("cron {verb} failed: {e:#}")))?;
        let text = String::from_utf8_lossy(&out);
        let value: Value = serde_json::from_str(text.trim()).unwrap_or(Value::Null);
        if status.ok {
            return Ok(value);
        }
        let error = value["error"].clone();
        let code = error["code"].as_str().unwrap_or("cron.failed").to_string();
        let message = error["message"]
            .as_str()
            .map(String::from)
            .or_else(|| status.reason.clone())
            .unwrap_or_else(|| format!("cron {verb} failed"));
        let details = json!({ "cron_error": error });
        Err(match status.exit_code() {
            exit::USAGE => {
                let field = if code.contains("schedule") {
                    "when"
                } else {
                    "scheduler"
                };
                Fail::invalid(field, format!("{message} ({code})")).with(json!({
                    "field": field,
                    "cron_error": details["cron_error"]
                }))
            }
            exit::TIMEOUT => Fail::new(Code::Timeout, format!("{message} ({code})")).with(details),
            _ => Fail::new(Code::ScheduleFailed, format!("{message} ({code})")).with(details),
        })
    }

    /// The cron handle `schedule` installs jobs with.
    fn cron_handle(&self, label: &str) -> VResult<crate::handles::processes::cronh::CronHandle> {
        use crate::handles::processes::cronh::CronHandle;
        #[cfg(test)]
        if let Some(p) = &self.cron_provider {
            return Ok(CronHandle::new(
                label.to_string(),
                Box::new(SharedCronProvider(p.clone())),
            ));
        }
        let url = Url::parse(&format!("cron://{label}")).map_err(|e| {
            Fail::invalid("profile", format!("profile cannot name a cron job: {e}"))
        })?;
        CronHandle::from_url(&url)
            .map_err(|e| Fail::new(Code::ScheduleFailed, format!("cron handle: {e:#}")))
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

    /// The verb a help request names (`--help=create`, `verb=create`, or
    /// the verb itself in `backup://db.create help`).
    fn help_verb<'a>(verb: &'a str, args: &'a Args) -> Option<&'a str> {
        verb.strip_prefix("--help=")
            .or_else(|| args.get("verb").map(String::as_str))
            .or_else(|| accepted_args(verb).is_some().then_some(verb))
    }

    /// Runs `verb` and writes its envelope.
    fn run_verb(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let mut cx = Ctx::new(verb);
        let outcome = (|| -> VResult<Value> {
            if accepted_args(verb).is_none() {
                let mut msg = format!("unknown verb {verb:?} for backup://");
                if let Some(s) = suggest(verb, self.verbs()) {
                    msg.push_str(&format!("; did you mean {s}?"));
                }
                msg.push_str(&format!(" (verbs: {})", self.verbs().join(", ")));
                return Err(Fail::new(Code::UnknownVerb, msg));
            }
            cx.pretty = bool_arg(args, "json_pretty", false)?;
            check_known_args(verb, args)?;
            if matches!(verb, "create" | "prune" | "restore" | "schedule") {
                cx.dry_run = bool_arg(args, "dry_run", false)?;
            }
            match verb {
                "create" => self.verb_create(args, &mut cx, io),
                "list" => self.verb_list(args, &mut cx),
                "restore" => self.verb_restore(args, &mut cx, io),
                "verify" => self.verb_verify(args, &mut cx),
                "prune" => self.verb_prune(args, &mut cx),
                _ => self.verb_schedule(args, &mut cx),
            }
        })();
        if outcome.is_ok()
            || outcome
                .as_ref()
                .is_err_and(|f| f.code.exit() != exit::USAGE)
        {
            Self::warn_plain_password(args, io);
        }
        self.finish(cx, outcome, io)
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
        self.run_verb(verb, args, io)
    }
}

#[cfg(test)]
#[path = "backuph_tests.rs"]
mod tests;
