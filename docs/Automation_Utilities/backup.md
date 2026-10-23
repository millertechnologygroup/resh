# Resource Shell (resh) – Backup Handle Documentation

## 1. Overview

Resource Shell (resh) is a command-line tool that runs operations on resources named by URLs and reports the results as JSON.

The `backup://` handle creates, lists, restores, verifies and prunes backup snapshots by running an installed backup tool: `restic`, `borg`, `rsync` or `tar`. It also has a `schedule` verb, which only **reports** a schedule definition. It does not install a timer or cron job and does not write any file (see 4.6).

The handle does not implement backups itself. Every operation runs the backend program (or, for some tar/rsync operations, reads the repository directory directly) and wraps the outcome in one JSON envelope.

Each verb is written as a stage:

```text
resh backup://<profile>.<verb> key=value ...
```

Where:

* `<profile>` names the backup profile. It is taken from the URL host, so `backup://db.create` uses the profile `db`. `backup:///db` (path form) names the same profile, and `backup://db/sub` gives the profile `db/sub`. With no profile, the profile is `default`.
* `<verb>` is one of `create`, `list`, `restore`, `verify`, `prune`, `schedule`.
* `key=value` words are the verb's arguments. The form `'backup://db.list(backend=tar)'` (quoted for the shell) is also accepted.

The profile is only used to name the default tar repository and the reported schedule definition path. Everything else about the repository comes from the arguments.

---

## 2. Design Notes

* **One envelope for every verb.** Success and failure both print the same JSON object on stdout (see 3.2). On failure resh also prints `Error: <message>` on stderr and exits non-zero.
* **The backend does the work.** Capabilities such as encryption, deduplication and cloud storage are whatever the selected backend provides. The `capabilities` object in the result is a fixed description per backend, not a probe of the repository.
* **Dry run is limited.** Only `create` and `prune` have a dry-run mode. `restore` has none, so `restore dry_run=true` is refused with an error and nothing is restored. `list`, `verify` and `schedule` have no dry-run mode either; like every such verb, they refuse `dry_run=true` (exit 2).
* **Timeouts.** Where a backend process is run, `timeout_ms` is enforced: at the deadline the backend process is killed and the verb fails with error kind `TIMEOUT`. Only the direct child process is killed; programs that the backend itself started may keep running. Operations done in-process (tar/rsync listing and pruning, rsync verification) do not use the timeout. Details per verb are in section 4.
* **Each invocation is independent.** Nothing persists between `resh` invocations except what the backend writes to the repository.

---

## 3. Command Syntax and Execution Model

### 3.1 Arguments common to several verbs

| Argument        | Verbs                                   | Meaning |
| --------------- | --------------------------------------- | ------- |
| `backend`       | all                                     | `restic`, `borg`, `rsync` or `tar`. Without it, the first of these found on `PATH` is used, in that order. An unknown name fails with `BACKEND_NOT_FOUND`. |
| `repo_url`      | create, list, restore, verify, prune    | Repository location. restic receives it as `RESTIC_REPOSITORY`; borg uses it as the repository path; tar and rsync use it as a local directory (a `file://` prefix is stripped). |
| `password`      | create, list, restore, verify, prune    | restic/borg repository password (passed to the backend in its environment, redacted in the output). It still appears in the `resh` command line and shell history; prefer `password_file` or the environment variables. |
| `password_file` | create, list, restore, verify, prune    | File holding the password. restic receives it as `RESTIC_PASSWORD_FILE`; for borg resh reads the file and passes the content as `BORG_PASSPHRASE`. |
| `timeout_ms`    | all                                     | Backend deadline in milliseconds. A value that is not a non-negative integer is **silently ignored** and the default is used. |
| `json_pretty`   | all                                     | `true` pretty-prints the envelope (same as the global `--json-pretty` flag). |

**Password sources (restic and borg only).** restic and borg need a repository password from `password=`, `password_file=`, or their usual environment variables (`RESTIC_PASSWORD`, `RESTIC_PASSWORD_FILE`, `RESTIC_PASSWORD_COMMAND`; `BORG_PASSPHRASE`, `BORG_PASSCOMMAND`, `BORG_PASSPHRASE_FD`). With none of these, the verb fails with error kind `MISSING_PASSWORD` before the backend is run. tar and rsync need no password.

**Default repositories.** When `repo_url` is not given:

| Backend | Default repository |
| ------- | ------------------ |
| tar     | `/tmp/resh_backup_<profile>` |
| rsync   | `/tmp/rsync_backup` |
| borg    | `/tmp/borg_repo` |
| restic  | none: restic uses `RESTIC_REPOSITORY` from the environment, and fails if that is not set |

These defaults are in the world-writable `/tmp` directory, are created with default permissions, and are accepted if another user created them first. `prune` deletes inside them. Always pass an explicit `repo_url` for real backups.

### 3.2 Response envelope

Every verb prints one JSON object with these fields (the field set comes from the `BackupEnvelope` structure in `src/core/envelope.rs`):

| Field         | Meaning |
| ------------- | ------- |
| `ok`          | `true` on success, `false` on failure |
| `handle`      | always `"backup"` |
| `verb`        | the verb that ran |
| `target`      | the stage URL without the verb, such as `backup://db` |
| `ts`          | timestamp (RFC 3339) |
| `duration_ms` | elapsed time |
| `dry_run`     | whether the run was a dry run |
| `backend`     | `id`, `command` (argv run, empty when the repository was read directly), `env_redacted` (extra environment with secrets replaced by `***REDACTED***`), optional `cwd`, `timeout_ms`, `simulated` |
| `result`      | verb-specific result (success only) |
| `events`      | always an empty list in the current code |
| `warnings`    | non-fatal notices |
| `error`       | on failure: `kind`, `message`, optional `details` |

Example, a tar dry run (shortened from real output; `--json-pretty` sorts keys):

```json
{
  "backend": {
    "command": ["tar", "-czf", "/srv/backups/backup_20261016_091244.tar.gz", "/etc"],
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
    "backend_raw": { "stderr": "", "stdout": "" },
    "capabilities": {
      "cloud_targets": ["file"],
      "dedup": false,
      "encryption": false,
      "incremental": true,
      "retention": true,
      "verify": true
    },
    "snapshot": {
      "created_at": "2026-10-16T09:12:44.930811+00:00",
      "id": "dry-run-id",
      "sources": ["/etc"],
      "tags": []
    }
  },
  "target": "backup://db",
  "ts": "2026-10-16T09:12:44.931277+00:00",
  "verb": "create",
  "warnings": ["Dry run: no backup was created"]
}
```

Example failure (restic with no password source):

```json
{
  "ok": false,
  "handle": "backup",
  "verb": "list",
  "target": "backup://db",
  "ts": "2026-10-23T13:06:51.337408831+00:00",
  "duration_ms": 0,
  "dry_run": false,
  "backend": {
    "id": "restic",
    "command": ["restic", "snapshots", "--json"],
    "env_redacted": { "RESTIC_REPOSITORY": "/srv/restic" },
    "timeout_ms": 10000,
    "simulated": false
  },
  "events": [],
  "warnings": [],
  "error": {
    "kind": "MISSING_PASSWORD",
    "message": "restic needs a repository password: pass password=<secret> or password_file=<path>, or set RESTIC_PASSWORD or RESTIC_PASSWORD_FILE"
  }
}
```

Error kinds produced by the code: `BACKEND_NOT_FOUND`, `MISSING_PASSWORD`, `BACKEND_FAILED` (the backend exited non-zero; `details` has `exit_code` and `stderr_tail`), `TIMEOUT`, `EXECUTION_FAILED`, `IO`, `PARSE`, `INVALID_ARGS`, `VERIFY_FAILED`.

Exit status: 0 on success. On `BACKEND_FAILED` resh exits with the backend's exit code (1 if that is outside 1-255); other failures exit 1. A missing required argument (`src`, `when`, `snapshot_id`, `dest`) is reported only as `Error: Missing required argument: ...` on stderr, with exit 1 and no JSON envelope.

Check `ok` (or the exit status) to decide success.

---

## 4. Verbs

Per-verb help with usage and example output: `resh backup <verb> --help`.

### 4.1 create

Backs up one or more source paths.

```bash
resh --json-pretty backup://db.create src=/etc backend=tar repo_url=/srv/backups dry_run=true
resh backup://db.create src=/etc backend=tar repo_url=/srv/backups
resh backup://db.create 'src=/etc;/home' backend=restic repo_url=/srv/restic password_file=/root/.restic-pass tag=daily
```

| Argument  | Required | Meaning |
| --------- | -------- | ------- |
| `src`     | yes      | Source path(s), separated by `;` |
| `tag`     | no       | Tags, separated by `;` (passed to restic only) |
| `label`   | no       | For tar, rsync and borg, the snapshot name prefix (`<label>_<timestamp>`, characters other than letters, digits, `.`, `-`, `_` become `_`); for restic, the `--hostname` value |
| `exclude` | no       | Exclude patterns, separated by `;` |
| `dry_run` | no       | `true`/`1`/`yes`/`on` (any case, or a bare `dry_run`) reports the command without running it. `false`/`0`/`no`/`off` runs it. Any other value is an error and nothing runs |

Plus `backend`, `repo_url`, `password`, `password_file`, `timeout_ms` (default 1800000, enforced).

Backend commands: `tar -czf <repo>/<name>.tar.gz ...`, `rsync -a --stats ... <repo>/<name>/`, `borg create --json --compression lz4 <repo>::<name> ...`, `restic backup ... --json`. The snapshot id is the archive or directory name for tar/rsync/borg, and the restic snapshot id read from restic's output. For tar and rsync the repository directory is created if missing.

Source paths are passed to the backend as plain arguments with no `--` separator, so a path beginning with `-` is read as a backend option. Do not pass untrusted values in `src`, `exclude`, `snapshot_id` or `dest`.

### 4.2 list

Lists snapshots in the repository.

```bash
resh --json-pretty backup://db.list backend=tar repo_url=/srv/backups
resh backup://db.list backend=restic repo_url=/srv/restic password_file=/root/.restic-pass tag=daily
```

Arguments: `tag` (`;`-separated, restic only), plus `backend`, `repo_url`, `password`, `password_file`, `timeout_ms` (default 10000).

* restic runs `restic snapshots --json`; borg runs `borg list --json`. The timeout is enforced on that command.
* tar and rsync read the repository directory directly (`*.tar.gz` files or snapshot directories); no command runs and `timeout_ms` is not used.

The result has `snapshots` (each with `id`, `created_at`, `sources`, `tags`, and optionally `label`, `bytes_total`), `total_count` and `capabilities`.

### 4.3 restore

Restores a snapshot into a destination directory.

```bash
resh backup://db.restore snapshot_id=backup_20261016_091244 dest=/srv/restore backend=tar repo_url=/srv/backups
```

| Argument      | Required | Meaning |
| ------------- | -------- | ------- |
| `snapshot_id` | yes      | Snapshot id (tar: archive name without `.tar.gz`; rsync: directory name) |
| `dest`        | yes      | Destination directory (created for tar and borg) |
| `include`     | no       | Include patterns, separated by `,` (restic only; other backends warn and restore everything) |
| `exclude`     | no       | Exclude patterns, separated by `;` |

Plus `backend`, `repo_url`, `password`, `password_file`, `timeout_ms` (default 1800000, enforced).

`restore` has **no dry run**: `dry_run=true` (or any true spelling) is refused with `Error: backup restore does not support dry_run; nothing was restored`, and a malformed `dry_run` value is an error. Without `dry_run` the restore is performed. The result's `restored.files_restored` counts backend output lines mentioning a restore, and `bytes_restored` is always 0.

### 4.4 verify

Checks repository integrity.

```bash
resh backup://db.verify backend=tar repo_url=/srv/backups
resh backup://db.verify backend=restic repo_url=/srv/restic password_file=/root/.restic-pass mode=thorough
```

| Argument      | Meaning |
| ------------- | ------- |
| `mode`        | `thorough` or `data` reads all data (`restic check --read-data`, `borg check --verify-data`). Any other value, including the default `quick`, runs the plain check |
| `snapshot_id` | Only echoed back in the result; it does not limit the check |

Plus `backend`, `repo_url`, `password`, `password_file`, `timeout_ms` (default 3600000).

* restic and borg run their `check` command with the timeout enforced.
* tar runs `tar -tzf` on each archive in the repository. Each archive gets the full `timeout_ms`; it is not a total for the verb. An empty repository is reported as a problem.
* rsync opens every file in the repository in-process; `timeout_ms` is not used.

Problems give error kind `VERIFY_FAILED` with the findings in `error.details`.

### 4.5 prune

Removes snapshots outside a retention policy.

```bash
resh backup://db.prune backend=tar repo_url=/srv/backups keep_daily=7 dry_run=true
resh backup://db.prune backend=restic repo_url=/srv/restic password_file=/root/.restic-pass keep_daily=7 keep_weekly=4
```

| Argument       | Meaning |
| -------------- | ------- |
| `keep_daily`   | Number of daily snapshots to keep |
| `keep_weekly`  | Number of weekly snapshots to keep |
| `keep_monthly` | Number of monthly snapshots to keep |
| `dry_run`      | Report what would be removed. Same parsing as `create`: an unrecognised value is an error and nothing is pruned |

At least one `keep_*` is required, and each must be a non-negative integer, otherwise the verb fails with `INVALID_ARGS`. Plus `backend`, `repo_url`, `password`, `password_file`, `timeout_ms` (default 3600000).

* restic runs `restic forget --json --keep-... --prune` (or `--dry-run`); borg runs `borg prune --list --keep-... --stats` (or `--dry-run`). The timeout is enforced.
* tar and rsync apply the policy themselves to archives or snapshot directories by modification time (UTC days) and delete them in-process; `timeout_ms` is not used.

The result reports `pruned` (or `would_prune` in a dry run) with `snapshots_removed`, `bytes_freed` (null for restic and borg) and `success`.

### 4.6 schedule

Reports a schedule definition. **It does not install anything**: no systemd timer, no crontab entry, and no file is written, including the reported `definition_path`.

```bash
resh --json-pretty backup://db.schedule 'when=0 2 * * *' src=/etc backend=tar
```

| Argument  | Required | Meaning |
| --------- | -------- | ------- |
| `when`    | yes      | Schedule expression; echoed back, not validated |
| `src`     | yes      | Required but not used in the result |
| `enabled` | no       | Echoed back (default `true`) |
| `backend` | no       | Selected as for other verbs |

`timeout_ms` is accepted and echoed in `backend.timeout_ms`, but nothing runs, so it has no effect. The result's `schedule` object has `when`, `enabled`, `runner` (`systemd` if `systemctl` is on `PATH`, else `cron` if `crontab` is, else `none` with a warning) and `definition_path` (`$HOME/resh-backup-<profile>.json`, not created). To run backups on a schedule, add the `resh backup://... create ...` command to cron or a systemd timer yourself.

### 4.7 timeout_ms summary

| Verb     | restic / borg | tar | rsync |
| -------- | ------------- | --- | ----- |
| create   | enforced (default 30 min) | enforced | enforced |
| restore  | enforced (default 30 min) | enforced | enforced |
| list     | enforced (default 10 s) | not used (directory read) | not used (directory read) |
| verify   | enforced (default 60 min) | enforced per archive | not used (in-process) |
| prune    | enforced (default 60 min) | not used (in-process) | not used (in-process) |
| schedule | not used (nothing runs) | not used | not used |

A malformed `timeout_ms` is not rejected; the default is used silently.

---

## 5. Platform Support

Only Linux is supported and verified. The backend programs must be installed and on `PATH`.

---

## 6. Operational Notes

* Always pass `repo_url`; the defaults are shared locations under `/tmp` (see 3.1).
* For restic and borg, provide the password with `password_file=` or the backend's environment variables rather than `password=` on the command line.
* Use `dry_run=true` before `prune`. A mistyped value is refused rather than run.
* `restore` cannot be simulated; restore into an empty scratch directory first if unsure.
* `verify` regularly, and test restores; a successful `create` only means the backend exited 0 (restic exit 3, borg exit 1, rsync exit 24 and tar exit 1 are reported as warnings, not failures).
* Gate automation on `ok` or the exit status.

---

## 7. Use Cases

* Snapshot configuration directories (`create`) before an upgrade and roll back with `restore`.
* Apply a retention policy from cron with `prune`.
* Check repositories in CI or maintenance windows with `verify`, failing the job on `ok: false`.

---

## 8. Implementation

The handle is written in Rust (`src/handles/automation/backuph.rs`). Backend commands are built as argument vectors (no shell), run with stdin closed and stdout/stderr captured (up to 256 KB each in `backend_raw`), and killed at the deadline as described above.
