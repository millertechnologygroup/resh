# Resource Shell (resh) – Backup Handle Documentation

## 1. Overview

Resource Shell (resh) is a command-line tool that runs operations on resources named by URLs and reports the results as JSON.

The `backup://` handle creates, lists, restores, verifies and prunes backup snapshots by running an installed backup tool: `restic`, `borg`, `rsync` or `tar`. Its `schedule` verb installs a scheduled `create` as a systemd timer or crontab line through the `cron://` handle (see 4.6).

The handle does not implement backups itself. Every operation runs the backend program (or, for some tar/rsync operations, reads the repository directory directly) and wraps the outcome in one JSON envelope.

Each verb is written as a stage:

```text
resh backup://<profile>.<verb> key=value ...
```

Where:

* `<profile>` names the backup profile. It is taken from the URL host, so `backup://db.create` uses the profile `db`. `backup:///db` (path form) names the same profile, and `backup://db/sub` gives the profile `db/sub`. With no profile, the profile is `default`.
* `<verb>` is one of `create`, `list`, `restore`, `verify`, `prune`, `schedule`. Any other verb fails with `backup.unknown_verb` (exit 2) and a "did you mean" hint.
* `key=value` words are the verb's arguments. The form `'backup://db.list(backend=restic)'` (quoted for the shell) is also accepted.

The profile is only used by `schedule` (the installed backup command and the cron job id `resh-backup-<profile>`). Everything else about the repository comes from the arguments.

---

## 2. Design Notes

* **Arguments are checked first.** Each verb has one list of accepted arguments (the usage in `resh backup <verb> --help`). An unknown argument, a missing required argument or an invalid value is refused before anything is done: exit 2, error code `backup.invalid_argument`, `error.details.field` naming the argument, and a "did you mean" hint for a likely typo.
* **One envelope for every verb.** Success and failure both print the same JSON object on stdout (see 3.2). On failure resh also prints `Error: [backup.<code>] <message>` on stderr.
* **Exit status.** 0 success; 1 the operation failed (backend error, missing program, I/O error, verification problems); 2 invalid usage, nothing was done; 124 timeout (the outcome is unknown).
* **The backend does the work.** Capabilities such as encryption, deduplication and cloud storage are whatever the selected backend provides. The `capabilities` object in the result is a fixed description per backend, not a probe of the repository.
* **Dry run.** `create`, `restore`, `prune` and `schedule` have a dry-run mode. `list` and `verify` change nothing and refuse `dry_run` in any spelling (exit 2).
* **Progress.** `create` and `restore` with `progress=true` (restic and borg) print one JSON line per backend progress event as it happens, then the envelope (see 4.8).
* **Timeouts.** `timeout_ms` is the deadline of the whole verb (defaults in 4.7). At the deadline the backend and every process it started are stopped, and in-process work (tar/rsync listing, pruning, rsync verification) stops too; the verb fails with `backup.timeout` and exit 124. A `create` stopped this way removes its partial tar archive or rsync directory.
* **Private files.** A tar or rsync repository directory that resh creates is owner-only (0700); tar archives are created 0600 and rsync snapshot directories 0700. A restore destination that resh creates is 0700. A snapshot is always created under a new name, so a second backup in the same second gets a `_2` suffix instead of overwriting the first, and nothing planted at the name is written through.
* **Each invocation is independent.** Nothing persists between `resh` invocations except what the backend writes to the repository.

---

## 3. Command Syntax and Execution Model

### 3.1 Arguments common to several verbs

| Argument        | Verbs                                   | Meaning |
| --------------- | --------------------------------------- | ------- |
| `backend`       | all                                     | `auto` (default), `restic`, `borg`, `rsync` or `tar`. `auto` uses the first of restic, borg, rsync, tar found on `PATH`, and fails with `backup.backend_not_found` (exit 1) when none is. Any other name is refused (exit 2). A named backend that is not installed fails with `backup.backend_not_found` (exit 1) before anything is done. |
| `repo_url`      | all                                     | Repository location. **Required for tar, rsync and borg.** restic receives it as `RESTIC_REPOSITORY`; without it, restic needs `RESTIC_REPOSITORY` or `RESTIC_REPOSITORY_FILE` in the environment (else exit 2). borg uses it as the repository path; tar and rsync use it as a local directory (a `file://` prefix is stripped). |
| `password`      | create, list, restore, verify, prune    | restic/borg repository password, passed to the backend in its environment (`RESTIC_PASSWORD`, `BORG_PASSPHRASE`) and redacted in the output. It appears in the `resh` command line and shell history, so resh prints a warning on stderr each time; prefer `password_file` or the environment variables. |
| `password_file` | create, list, restore, verify, schedule, prune | File holding the password. restic receives it as `RESTIC_PASSWORD_FILE`; for borg resh reads the file and passes the content as `BORG_PASSPHRASE`. The file must be readable, else `backup.password_file_unreadable` (exit 1) before anything runs. |
| `timeout_ms`    | all                                     | Deadline of the whole verb in milliseconds, an integer from 1 to 2592000000 (30 days). Anything else is refused (exit 2). |
| `json_pretty`   | all                                     | `true` pretty-prints the envelope (same as the global `--json-pretty` flag). Booleans accept `true/false`, `1/0`, `yes/no`, `on/off`; anything else is refused. |

**Password sources (restic and borg only).** restic and borg need a repository password from `password=`, `password_file=`, or their usual environment variables (`RESTIC_PASSWORD`, `RESTIC_PASSWORD_FILE`, `RESTIC_PASSWORD_COMMAND`; `BORG_PASSPHRASE`, `BORG_PASSCOMMAND`, `BORG_PASSPHRASE_FD`). With none of these, the verb fails with `backup.missing_password` (exit 2) before the backend is run. Giving both `password` and `password_file` is refused. A password never appears in a backend's argv. resh does not store repository passwords.

**tar and rsync take no password.** Their repositories are not encrypted, so `password` and `password_file` are refused for them (exit 2) rather than silently ignored.

**No default repository.** tar, rsync and borg require `repo_url`. Without it every verb (including a dry run) fails with `backup.invalid_argument` before anything runs.

Before v1.0.3-beta, tar, rsync and borg fell back to `/tmp/resh_backup_<profile>`, `/tmp/rsync_backup` and `/tmp/borg_repo`. Those directories were created with default permissions (archives readable by every local user) and were accepted when another user had created them first, so they were removed.

resh does not check the ownership or mode of an existing repository directory; use a directory only you (or root) can write, for example one created with `install -d -m 0700 /var/backups/resh/db`.

### 3.2 Response envelope and errors

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
| `backend`     | `id` (`unknown` when the request failed before a backend was chosen), `command` (argv run, empty when the repository was read directly or nothing ran), `env_redacted` (extra environment with secrets replaced by `***REDACTED***`), optional `cwd`, `timeout_ms` (0 when no deadline applies), `simulated` (true for a create dry-run plan) |
| `result`      | verb-specific result (success only) |
| `events`      | always an empty list in the current code |
| `warnings`    | non-fatal notices |
| `error`       | on failure: `code`, `kind`, `message`, optional `details` |

Example, a tar dry run (shortened from real output; `--json-pretty` sorts keys):

```json
{
  "backend": {
    "command": ["tar", "--force-local", "-czf", "/srv/backups/backup_20261016_091244.tar.gz", "--", "/etc"],
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
    "dry_run_mode": "plan",
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

Example failure (restic with no password source), with `Error: [backup.missing_password] restic needs a repository password: ...` on stderr and exit 2:

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
    "code": "backup.missing_password",
    "kind": "MISSING_PASSWORD",
    "message": "restic needs a repository password: pass password=<secret> or password_file=<path>, or set RESTIC_PASSWORD or RESTIC_PASSWORD_FILE"
  }
}
```

**Error codes.** `error.code` is the stable code, also printed on stderr as `Error: [<code>] <message>`. `error.kind` is the upper-case kind of earlier releases, kept for compatibility.

| `error.code` | `error.kind` | Exit | Meaning |
| ------------ | ------------ | ---- | ------- |
| `backup.invalid_argument` | `INVALID_ARGS` | 2 | Unknown argument, missing required argument, invalid value, unsafe value (3.3), `dry_run` on a verb without one, missing `repo_url`. `details.field` names the argument. Nothing was done. |
| `backup.unknown_verb` | `INVALID_ARGS` | 2 | The verb is not one of the six. |
| `backup.missing_password` | `MISSING_PASSWORD` | 2 | restic or borg has no password source. Nothing was run. |
| `backup.password_file_unreadable` | `MISSING_PASSWORD` | 1 | `password_file` cannot be read. Nothing was run. |
| `backup.backend_not_found` | `BACKEND_NOT_FOUND` | 1 | The backend program is not installed (or, with `backend=auto`, none is). |
| `backup.backend_failed` | `BACKEND_FAILED` | 1 | The backend exited non-zero or was killed by a signal. `details` has `exit_code` (the backend's own status, null after a signal), `signal` and `stderr_tail`; the message ends with the backend's last stderr line. |
| `backup.execution_failed` | `EXECUTION_FAILED` | 1 | The backend could not be started (for example permission denied). |
| `backup.timeout` | `TIMEOUT` | 124 | The deadline passed. The backend was stopped; what it already did stays done. On stderr resh reports `Error: [backup.timeout] outcome unknown: <program> was stopped; ...` when a backend was stopped. |
| `backup.io` | `IO` | 1 | A repository or destination directory cannot be read, created or written; a tar/rsync prune could not remove some snapshots (`details` lists what was removed and the errors). |
| `backup.parse` | `PARSE` | 1 | restic or borg `list` output is not the expected JSON. |
| `backup.verify_failed` | `VERIFY_FAILED` | 1 | tar or rsync verification found problems; `details` has the findings. |
| `backup.snapshot_not_found` | `NOT_FOUND` | 1 | `verify snapshot_id=` or a `restore` dry run names a tar archive or rsync snapshot that is not in the repository. |
| `backup.schedule_failed` | `SCHEDULE_FAILED` | 1 | The cron handle could not install (or disable) the scheduled job, for example the requested scheduler is not available. `details.cron_error` has the cron handle's error object; a refused cron argument is `backup.invalid_argument` instead. |

Before this release a backend failure exited with the backend's own exit code, a missing required argument printed only an error line (exit 1, no envelope), and refused values exited 1. Now usage errors exit 2 with an envelope, and a backend failure exits 1 with the backend's status in `error.details.exit_code`.

Check `ok` (or the exit status) to decide success.

### 3.3 How argument values reach the backend

Since v1.0.4-beta every caller value that ends up on a backend command line is checked **before** anything runs, including before a dry-run plan is reported. A refused value gives `backup.invalid_argument`, exit 2, `details.field` naming the argument, and the backend is not started.

* `src`, `dest`, `snapshot_id`, `repo_url` and `password_file` must not be empty, must not start with `-` (write `./-name` for a relative path that does), and must not contain control characters such as line breaks. `src` must name at least one path.
* For tar and rsync, `snapshot_id` (restore and verify) is the name of an archive or snapshot directory in the repository and must not contain `/` or be `.` or `..`.
* For restic and borg, no component of `repo_url` that names a host or user (after `ssh://`, `@`, `:` or `[`) may start with `-`.
* `exclude`, `include`, `tag` and `label` may contain any text except control characters.

The command lines are built so a value cannot change its role:

* Option values are attached with `=` (`--exclude=<pattern>`, `--include=<pattern>`, `--tag=<tag>`, `--host=<label>`, `--target=<dest>`), so a value beginning with `-` stays a value.
* Positional values (sources, repository, snapshot, include patterns for tar and borg) follow a `--` separator.
* tar always gets `--force-local`, so an archive path containing `:` is never treated as `host:file` on a remote host.
* rsync gets relative paths with a `./` prefix, so a path such as `name:dir` is never treated as a remote location.

Do not rely on this checking alone for untrusted input: the backend still reads and writes whatever paths it is given.

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
| `tag`     | no       | Tags, separated by `;`. restic only: refused for the other backends (exit 2) |
| `label`   | no       | For tar, rsync and borg, the snapshot name prefix (`<label>_<timestamp>`, characters other than letters, digits, `.`, `-`, `_` become `_`); for restic, the `--host` value |
| `progress` | no      | `true` streams progress events (restic and borg; refused for tar and rsync), see 4.8 |
| `exclude` | no       | Exclude patterns, separated by `;`, in the backend's own pattern syntax |
| `dry_run` | no       | `true` (or `1`/`yes`/`on`, or a bare `dry_run`) validates the arguments and reports the command without running it or creating anything (`result.dry_run_mode` is `plan`, `backend.simulated` is true). Any value other than a boolean spelling is refused |

Plus `backend`, `repo_url`, `password`, `password_file`, `timeout_ms` (default 1800000), `json_pretty`.

Backend commands (with `progress=true` borg also gets `--progress --log-json`): `tar --force-local -czf <repo>/<name>.tar.gz ... -- <src>...`, `rsync -a --stats ... -- <src>... <repo>/<name>/`, `borg create --json --compression lz4 ... -- <repo>::<name> <src>...`, `restic backup ... --json -- <src>...`. The snapshot id is the archive or directory name for tar/rsync/borg (with a `_2`, `_3` ... suffix when the name is taken), and the restic snapshot id read from restic's output. For tar and rsync a missing repository directory is created 0700, the archive 0600 and the snapshot directory 0700. If the backup fails or is stopped at the deadline, the partial tar archive or rsync directory is removed (`error.details.partial_snapshot` and `partial_snapshot_removed`).

The exit statuses restic 3, borg 1, rsync 24 and tar 1 mean the backup was written with a warning; they are reported as success with a warning.

Sources are checked and passed as described in 3.3.

### 4.2 list

Lists snapshots in the repository.

```bash
resh --json-pretty backup://db.list backend=tar repo_url=/srv/backups
resh backup://db.list backend=restic repo_url=/srv/restic password_file=/root/.restic-pass tag=daily
```

Arguments: `tag` (`;`-separated, restic only; refused for the other backends), plus `backend`, `repo_url`, `password`, `password_file`, `timeout_ms` (default 10000), `json_pretty`.

* restic runs `restic snapshots --json`; borg runs `borg list --json -- <repo>`.
* tar and rsync read the repository directory directly (`*.tar.gz` files or snapshot directories); no command runs. A missing directory gives `backup.io`.

The result has `snapshots` (each with `id`, `created_at`, `sources`, `tags`, and optionally `label`, `bytes_total`), `total_count` and `capabilities`.

### 4.3 restore

Restores a snapshot into a destination directory, or with `dry_run=true` reports what a restore would write.

```bash
resh backup://db.restore snapshot_id=backup_20261016_091244 dest=/srv/restore backend=tar repo_url=/srv/backups dry_run=true
resh backup://db.restore snapshot_id=backup_20261016_091244 dest=/srv/restore backend=tar repo_url=/srv/backups
resh backup://db.restore snapshot_id=latest dest=/srv/restore backend=restic repo_url=/srv/restic password_file=/root/.restic-pass 'include=/etc/*.conf'
```

| Argument      | Required | Meaning |
| ------------- | -------- | ------- |
| `snapshot_id` | yes      | Snapshot id (tar: archive name without `.tar.gz`; rsync: directory name; borg: archive name; restic: snapshot id or `latest`) |
| `dest`        | yes      | Destination directory. Created 0700 when missing. A `dest` that is a symbolic link or an existing non-directory is refused (exit 2), also in a dry run |
| `include`     | no       | Only restore matching paths; patterns separated by `,` (see below) |
| `exclude`     | no       | Do not restore matching paths; patterns separated by `;` |
| `dry_run`     | no       | Report what would be restored; nothing is written (see below) |
| `progress`    | no       | `true` streams progress events (restic and borg), see 4.8 |

Plus `backend`, `repo_url`, `password`, `password_file`, `timeout_ms` (default 1800000), `json_pretty`.

Backend commands: `restic restore --json --target=<dest> ... -- <id>`, `borg extract --list ... -- <repo>::<id> [include...]` (in `dest`), `tar --force-local -v -xzf <archive> ... -C <dest>`, `rsync -a --stats ... -- <repo>/<id>/ <dest>`.

`include` and `exclude` use each backend's own pattern rules:

* restic: `--include=` / `--exclude=` patterns, matched against the original absolute paths (`/etc/*.conf`); a pattern without `/` matches a name at any depth.
* tar: include patterns are archive member patterns (members have no leading `/`, for example `etc/*.conf`), shell-style: `*` does not match `/`; a directory member restores everything below it. Exclude patterns match any member name component (`*.tmp`). A pattern that matches nothing makes tar fail (`backup.backend_failed`).
* rsync: rsync filter patterns relative to the snapshot (`*.conf`, `data/sub/`); with `include`, directories are traversed and those left empty are not created.
* borg: include patterns are borg PATH arguments (path prefixes such as `etc/hosts`, or borg pattern syntax such as `sh:etc/*.conf`); exclude patterns are borg `--exclude` patterns.

Existing files in `dest` are overwritten by the backend.

The result's `restored` has `files_restored` and `bytes_restored`: restic's own summary counts (restic counts files and directories), the regular files written and their total size for tar and borg (from the extracted-member list), and the regular files transferred and their size for rsync. When a restore fails or is stopped, files already written stay in `dest` (`error.details.partial_restore_possible`).

**Dry run.** `dry_run=true` checks the arguments and the destination and runs the backend's read-only listing with the same include and exclude patterns: `restic restore --json --dry-run`, `borg list --json-lines`, `tar -tvzf`, `rsync --dry-run`. Nothing is written to `dest`, which is not created. A tar or rsync snapshot that does not exist gives `backup.snapshot_not_found`. The result has `dry_run_mode: "backend"`, `snapshot_id`, `destination` (`path`, `exists`, `would_create`, `empty`, `writable`) and `would_restore` (`files`, `bytes`: regular files and their size; restic's own counts). A non-empty or unwritable destination gives a warning. Like a prune dry run, restic takes a repository lock and reads its cache, and both restic and borg need the repository credentials.

### 4.4 verify

Checks repository integrity.

```bash
resh backup://db.verify backend=tar repo_url=/srv/backups
resh backup://db.verify backend=restic repo_url=/srv/restic password_file=/root/.restic-pass mode=thorough
resh backup://db.verify backend=borg repo_url=/srv/borg password_file=/root/.borg-pass snapshot_id=db_20261016_020000
```

| Argument      | Meaning |
| ------------- | ------- |
| `mode`        | `quick` (default), `thorough` or `data`. `thorough` and `data` read all data: `restic check --read-data`, `borg check --verify-data`, and for rsync every file is read completely (`quick` only opens each file). tar always reads each archive completely. Any other value is refused (exit 2) |
| `snapshot_id` | Check only this snapshot: borg `check -- <repo>::<archive>`, one tar archive, or one rsync snapshot directory. restic cannot check a single snapshot, so `snapshot_id` is refused for restic (exit 2). A tar or rsync snapshot that does not exist gives `backup.snapshot_not_found` |

Plus `backend`, `repo_url`, `password`, `password_file`, `timeout_ms` (default 3600000, for the whole verb, all archives together), `json_pretty`.

* restic and borg run their `check` command. A failing check is `backup.backend_failed` (exit 1) with the backend's output in `details`.
* tar runs `tar --force-local -tzf` on each archive. An empty repository is reported as a problem.
* rsync opens (or reads) every file in the repository in-process.

tar and rsync problems give `backup.verify_failed` with the findings in `error.details`. `result.verification.files_checked` counts tar archive members or rsync files; it is null for restic and borg, which do not report a count.

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
| `dry_run`      | Report what would be removed. Same parsing as `create` |

At least one `keep_*` is required, and each must be an integer of at least 1 (omit a rule instead of passing 0), otherwise the verb fails with `backup.invalid_argument` (exit 2). Plus `backend`, `repo_url`, `password`, `password_file`, `timeout_ms` (default 3600000), `json_pretty`.

* restic runs `restic forget --json --keep-... --prune` (or `--dry-run`); borg runs `borg prune --list --keep-... --stats -- <repo>` (or `--dry-run`). restic applies the policy separately to each group of snapshots with the same host and paths (its default `--group-by host,paths`), so snapshots made with a different `label` (restic hostname) are kept by their own group; borg applies it to all archives in the repository.
* tar and rsync apply the policy themselves to archives or snapshot directories by modification time (UTC days, ISO weeks, months) and delete them in-process. At the deadline the removal stops between snapshots and the verb fails with `backup.timeout`, listing what was removed in `error.details`.

The result reports `pruned` (or `would_prune` in a dry run) with `snapshots_removed`, `bytes_freed` (null for restic and borg) and `success`; tar and rsync also list the `removed` ids.

**What a prune dry run does.** The arguments are validated first in every case, and a refused value stops the verb before any backend runs. Then:

* tar and rsync: a pure plan. No program runs and nothing is removed; `result.dry_run_mode` is `plan`.
* restic and borg: only the backend can apply its retention policy to its repository, so resh **runs the backend** with its own `--dry-run` flag and reports what it would remove; `result.dry_run_mode` is `backend`, `backend.simulated` is `false`, `backend.command` is the argv that ran, and a warning says so. If your automation requires that a dry run starts no external program, do not use `prune dry_run=true` with restic or borg.

  What resh's tests verify: the arguments are validated before the backend starts, the backend receives its own `--dry-run` flag (and never `--prune` or `--stats`), the result is labelled as above, and (in containers with real restic and borg) no snapshot is removed.

  **A restic or borg prune dry run is not free of side effects.** The following was observed with restic 0.18.0 and borg 1.4.0 on local repositories (verified for v1.0.5-beta):

  * Repository data was not changed: the same snapshots and archives existed before and after.
  * Both took a repository lock, which is a write to the repository: restic creates and then deletes a lock file; borg creates and then removes an **exclusive** lock (`lock.exclusive`, `lock.roster`). Because borg's lock is exclusive, it can block a concurrent backup (`borg create`) of the same repository while the dry run holds it.
  * Both wrote to their local cache (restic's cache directory; borg's cache lock and cache metadata). borg also created and removed temporary files in `/tmp`.
  * Both needed the repository credentials (restic's password, borg's passphrase).
  * Neither made a network connection for a local repository.

  Not verified: remote repositories. A dry run against a remote repository (ssh, sftp, S3 and so on) is expected to connect to it, authenticate and take the same lock there; resh's tests do not cover this. Backend logging, if you have configured it, may also be written.

### 4.6 schedule

Installs a scheduled backup of the profile: the `resh backup://<profile>.create ...` command, run by a systemd timer or a crontab line. The job is added with the `cron://` handle's `add` verb (run in-process), so the scheduler choice, the schedule check, duplicate detection and the files written are exactly those of `cron add` (see `cron.md`). With `dry_run=true` cron add only reports what it would write.

```bash
resh --json-pretty backup://db.schedule 'when=0 2 * * *' src=/etc backend=tar repo_url=/srv/backups dry_run=true
resh backup://db.schedule 'when=0 2 * * *' src=/etc backend=restic repo_url=/srv/restic password_file=/root/.restic-pass
```

| Argument        | Required | Meaning |
| --------------- | -------- | ------- |
| `when`          | yes      | Five crontab fields or an `@` keyword (`@daily`, `@reboot`, ...), checked by cron add; an invalid schedule is refused (`backup.invalid_argument`, `details.field` `when`, exit 2) |
| `src`           | yes      | Source path(s) for the scheduled `create`, checked as in 3.3 |
| `backend`       | no       | As for other verbs. A named backend that is not installed here gives a warning, not an error |
| `repo_url`      | no       | Repository for the scheduled `create`; required for tar, rsync and borg |
| `password_file` | no       | Password file for the scheduled `create` (restic and borg; refused for tar and rsync). `password=` is not accepted, so a password never ends up in a crontab or unit |
| `enabled`       | no       | `true` (default). `false` installs the job and then disables it with cron `disable` |
| `scheduler`     | no       | `auto` (default: a systemd timer when systemctl runs, else a crontab line), `cron` or `systemd`; cron add's `backend` |
| `dry_run`       | no       | Report what would be installed; nothing is written |
| `timeout_ms`    | no       | Passed to the cron handle, which bounds crontab and systemctl with it (cron's default 60000) |

The job's command is this resh executable's absolute path, `backup://<profile>.create`, `src`, `backend`, and `repo_url`/`password_file` when given. The cron job id is `resh-backup-<profile>` (`/` becomes `-`) and the cron label `backup-<profile>`. resh first runs cron add's own dry run (with `allow_duplicate=false`). If this exact job is already installed, the result has `duplicate: true` and nothing changes (for systemd, a timer of that name counts as installed). If a different job of the profile (another schedule or command) is installed, `schedule` fails with `backup.schedule_failed` and changes nothing; `details.remove_command` removes the old job, after which `schedule` can run again.

The result's `schedule` object has `when`, `enabled`, `scheduler` (the cron backend used), `id`, `installed` (false in a dry run), `duplicate`, `command` (the job's argv), `job` and `preview` (cron add's job object and, in a dry run, the line or units it would write) and `remove_command` (the `resh cron://backup-<profile>.rm id=... backend=...` argv that removes the job). Cron's warnings are added to the envelope's warnings, and warnings say when the job will need a password or `RESTIC_REPOSITORY` in its environment.

A cron argument the cron handle refuses is `backup.invalid_argument` (exit 2) with the cron error in `details.cron_error`; a failure to install or disable is `backup.schedule_failed` (exit 1; `details.installed` says whether a job was left installed when only the disable failed); a cron timeout is `backup.timeout`. The profile must consist of letters, digits, `-`, `_` and `/` to be scheduled.

Before this release `schedule` installed nothing and only reported a `runner` and a `definition_path`; both fields are gone.

### 4.7 timeout_ms summary

`timeout_ms` is the deadline of the whole verb. Defaults:

| Verb     | Default | What it bounds |
| -------- | ------- | -------------- |
| create   | 1800000 (30 min) | the backend run |
| restore  | 1800000 (30 min) | the backend run |
| list     | 10000 (10 s) | restic/borg run; tar/rsync directory read |
| verify   | 3600000 (60 min) | restic/borg check; all tar archives together; the rsync read |
| prune    | 3600000 (60 min) | restic/borg run; tar/rsync scan, size count and removal |
| schedule | cron's (60000) | crontab and systemctl, run by the cron handle |

At the deadline the backend's whole process tree is stopped (SIGTERM, then SIGKILL) and the verb exits 124 with `backup.timeout`.

### 4.8 progress

`create` and `restore` accept `progress=true` (default `false`) for restic and borg; tar and rsync refuse it (exit 2). While the backend runs, each progress record it reports is printed at once as one JSON line, flushed per line, and the envelope follows as the last line:

```json
{"backend":"restic","event":"progress","handle":"backup","progress":{"message_type":"status","percent_done":0.5,"files_done":1,"total_files":3},"ts":"2026-11-08T13:07:14+00:00","verb":"create"}
```

`progress` is the backend's own record: restic's `--json` `status` messages, and borg's `--log-json` records of type `archive_progress`, `progress_percent` and `progress_message` (borg gets `--progress --log-json` for this). Read the output line by line and treat the line with `"handle":"backup"` and an `ok` field as the result. With `--json-pretty` the output is buffered until the end and, holding several JSON lines, printed unchanged, so use `progress` without it. The deadline and every failure behave as without `progress`.

---

## 5. Platform Support

Only Linux is supported and verified. The backend programs must be installed and on `PATH`. Real restic, borg, rsync and tar are exercised in Debian containers by `tests/backup_e2e_docker.rs`.

---

## 6. Operational Notes

* tar, rsync and borg require `repo_url`; use a directory only you can write (see 3.1).
* For restic and borg, provide the password with `password_file=` or the backend's environment variables rather than `password=` on the command line.
* Use `dry_run=true` before `prune`. A mistyped value is refused rather than run.
* `restore` cannot be simulated; restore into an empty scratch directory first if unsure.
* `verify` regularly, and test restores; a successful `create` only means the backend exited 0 (restic exit 3, borg exit 1, rsync exit 24 and tar exit 1 are reported as warnings, not failures).
* Gate automation on `ok` or the exit status.

---

## 7. Use Cases

* Snapshot configuration directories (`create`) before an upgrade and roll back with `restore`.
* Apply a retention policy from cron with `prune`; get the cron command from `schedule`.
* Check repositories in CI or maintenance windows with `verify`, failing the job on `ok: false`.

---

## 8. Implementation

The handle is written in Rust (`src/handles/automation/backuph.rs`, tests in `backuph_tests.rs`, `tests/backup_verbs.rs` and `tests/backup_e2e_docker.rs`). Backend commands are built as argument vectors (no shell), run in their own process group with stdin closed and stdout/stderr captured (up to 256 KB each in `backend_raw`), and stopped at the deadline as described above.
