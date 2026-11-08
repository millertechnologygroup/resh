# Resource Shell (resh) – Snapshot Handle Documentation

## 1. Overview

The `snapshot://` handle saves full local copies of a file or directory,
compares them with each other or with the live filesystem, lists them and
restores them. It is a plain file-copy mechanism: it does not use
filesystem-level snapshots (LVM, Btrfs, ZFS), and there is no compression,
deduplication or incremental snapshotting. The only backend is `local`.

Verbs: `create`, `diff`, `ls`, `restore`.

Platform: Linux only is supported and tested.

---

## 2. Command Syntax

```text
resh snapshot://<target-path>.create name=<name> ...
resh snapshot://<target-path>.diff from=<snapshot>|live to=<snapshot>|live ...
resh snapshot://<target-path>.ls ...
resh snapshot://<snapshot-name-or-id>.restore target=<path> ...
```

The URL names the target path for `create`, `diff` and `ls`, and the
snapshot name (or ID) for `restore`. Absolute paths take three slashes
(`snapshot:///srv/app.create`). A relative target (`snapshot://app.ls`) is
resolved against the working directory by every verb, so
`snapshot://app.create` run in `/srv` and `snapshot:///srv/app.ls` name the
same target.

Help: `resh snapshot --help`, `resh snapshot <verb> --help`, and the
in-URL forms `snapshot://--help`, `snapshot://--help=<verb>` and
`snapshot:///<path>.help`.

### Snapshot names

A name uses only letters, digits, `.`, `-` and `_`, is at most 120
characters long, and does not start with `.` or `-`. Anything else is
rejected with `snapshot.invalid_argument`.

### Storage location

Snapshots are stored under the XDG state directory:
`$XDG_STATE_HOME/resh/snapshots` (default `~/.local/state/resh/snapshots`).
With neither `XDG_STATE_HOME` nor `HOME` set, every verb fails
(`snapshot.write_failed` for create, `snapshot.read_failed` otherwise, exit
1) instead of using a shared directory. Each
target gets a group directory named after its absolute path with every
character other than letters, digits, `.`, `-` and `_` replaced by `_`
(for example `/srv/app` becomes `_srv_app`), truncated to 120 characters.
Each snapshot is a directory named after the snapshot, holding `meta.json`
and `content` (the copied file, or a directory with the copied tree).

```text
~/.local/state/resh/snapshots/_srv_app/backup-v1/meta.json
~/.local/state/resh/snapshots/_srv_app/backup-v1/content/...
```

The store, group and snapshot directories are created owner-only (0700)
and `meta.json` is written with mode 0600, because snapshots often hold
configuration files and secrets; the copied files keep their own modes.

`meta.json` records `id`, `name`, `target`, `kind` (`file` or `dir`),
`state` (`complete`), `tags`, `size_bytes`, `created_at`, `expires_at`,
`backend`, `path` and `description`.

Two different targets can map to the same group directory (for example
`/srv/a b` and `/srv/a_b`, or long paths that share their first 120
characters). Every verb checks the target recorded in `meta.json`, so their
snapshots are never mixed up; reusing a snapshot name already taken by the
other target is refused with `snapshot.name_conflict`.

Snapshots written by earlier versions (no `kind` in `meta.json`; a
directory snapshot stored beside `meta.json`) are still listed, compared
and restored.

### Errors and exit status

Every failure prints `Error: [<code>] <message>` on stderr and a JSON object
on stdout:

```json
{"ok":false,"error":{"code":"snapshot.snapshot_not_found","message":"snapshot not found: v9"},"snapshot":"v9"}
```

`error.code` is one of the codes below and `error.message` repeats the
stderr message; some errors add fields such as `argument`, `snapshot`,
`target` or `matches`.

Arguments are strict: each verb accepts exactly the options listed in its
section (and in `resh snapshot <verb> --help`). An unknown argument, including
`dry_run` on `create`, `diff` and `ls`, is refused with exit 2 and
`snapshot.invalid_argument` before anything is done; `argument` names the key, and the
message suggests the closest accepted option for a likely typo (`nmae` ->
`did you mean "name"?`).

| Exit | Meaning |
| ---- | ------- |
| 0 | Success (created or skipped, compared, listed, restored, or dry run printed) |
| 1 | The operation failed: snapshot or target not found, snapshot already exists, target exists without `force`, a read, copy or write failed |
| 2 | Invalid usage: unknown argument, missing or malformed value, unsupported backend or mode, invalid or ambiguous target or snapshot; nothing was done |
| 124 | `timeout_ms` passed; everything written so far was removed (see below) |

Error codes:

| Code | Verbs | Exit | Meaning |
| ---- | ----- | ---- | ------- |
| `snapshot.missing_argument` | create, restore | 2 | `name` / `target` missing or empty |
| `snapshot.invalid_argument` | all | 2 | Unknown argument, or a malformed value (name, `ttl`, `tags`, `if_exists`, `limit`, `since`, `until`, boolean, `timeout_ms`, `format`, `path`); also `diff` with both sides `live` or both sides the same snapshot |
| `snapshot.unsupported_backend` | create | 2 | `backend` other than `local` |
| `snapshot.unsupported_mode` | restore | 2 | `mode` other than `overwrite` |
| `snapshot.invalid_target` | create, restore | 2 | Not a regular file or directory; inside the snapshot store; restore target `/` or overlapping the snapshot |
| `snapshot.ambiguous_snapshot` | restore | 2 | The name exists for several targets; `matches` lists their IDs; restore by ID |
| `snapshot.target_not_found` | create, diff | 1 | The target (or the live side of a diff) does not exist |
| `snapshot.snapshot_exists` | create | 1 | Name already used for this target and `if_exists=error` |
| `snapshot.name_conflict` | create | 1 | Name already used by another target in the same group directory |
| `snapshot.snapshot_not_found` | diff, restore | 1 | No snapshot with that name or ID |
| `snapshot.metadata_not_found` | restore | 1 | The snapshot directory has no `meta.json` |
| `snapshot.metadata_invalid` | diff, restore | 1 | `meta.json` cannot be parsed, or records an unknown `kind` |
| `snapshot.content_not_found` | diff, restore | 1 | `meta.json` is present but the content is missing |
| `snapshot.target_exists`, `snapshot.target_not_empty` | restore | 1 | The target (file, symbolic link, or non-empty directory) exists and `force` is not true |
| `snapshot.copy_failed` | create, restore | 1 | Reading the source or writing the copy failed (for example permission denied, a broken symbolic link) |
| `snapshot.write_failed` | create | 1 | The store or the metadata could not be written |
| `snapshot.backup_failed`, `snapshot.restore_failed` | restore | 1 | Moving the old target aside, or the copy into place, failed; the old target is put back |
| `snapshot.read_failed` | all | 1 | A directory or the target could not be read or inspected |
| `snapshot.unknown_verb` | - | 2 | The verb is not `create`, `diff`, `restore` or `ls` |
| `snapshot.timeout` | all | 124 | `timeout_ms` passed; see below |

**Change note (breaking):** earlier versions printed `Error: <message>`
and reported `"error": "<code>"` (without the `snapshot.` prefix) next to a
top-level `"message"`. Failures now print `Error: [snapshot.<code>]
<message>`, and `error` is an object `{"code": "snapshot.<code>",
"message": "..."}` (the top-level `message` field is gone; the other fields
are unchanged). An unknown verb is now `snapshot.unknown_verb` with exit 2
(was a plain error with exit 1). Exit codes are otherwise unchanged.

### timeout_ms

Every verb accepts `timeout_ms` (milliseconds; absent or `0` means no
limit; anything other than a non-negative integer is `snapshot.invalid_argument`,
exit 2).
The deadline is checked between files and between 1 MiB chunks of a file.
When it passes, the verb stops, removes everything it had written and exits
124 with error `snapshot.timeout`: `create` leaves no snapshot (an existing snapshot
replaced by `if_exists=overwrite` is kept), and `restore` leaves the target
unchanged. The final swap of `restore` and `create` is not interrupted.

---

## 3. Verbs

### 3.1 create

```bash
resh --json-pretty snapshot:///srv/app.create name=backup-v1 ttl=86400
resh snapshot:///etc/nginx.create name=pre-change description='before upgrade' if_exists=skip
resh snapshot:///srv/app.create name=nightly-1 tags=nightly,auto timeout_ms=60000
```

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `name` | required | Snapshot name, case-sensitive (see section 2) |
| `description` | none | Stored in metadata, shown by `ls` |
| `ttl` | none | Seconds until the snapshot expires (`expires_at`); `0` expires it at once. See "Expiry" below |
| `tags` | none | Comma-separated list, stored in metadata, matched by `ls tag=` |
| `if_exists` | `error` | `error` (exit 1, `snapshot.snapshot_exists`), `skip` (`"skipped": true`), `overwrite` |
| `backend` | `local` | Only `local` exists |
| `timeout_ms` | none | See section 2 |

The copy is made in a temporary directory in the group directory and
renamed into place, so a failed or timed-out create leaves no half-written
snapshot. With `if_exists=overwrite` the previous snapshot is removed only
after the new one is in place. File and directory modes and modification
times are kept; when resh runs as root, file ownership is kept as well.
Symbolic links are followed: the snapshot (and a later restore) contains a
copy of what the link points to, not the link; a broken link fails the
create (`snapshot.copy_failed`). Sockets, FIFOs and device files are not copied; each
one is reported on stderr as `snapshot create: warning: skipped <path>: ...`.
The snapshot store is never copied into a snapshot (snapshotting `$HOME`
skips `~/.local/state/resh/snapshots`), and a target inside the store is
refused.

#### Expiry (`ttl`)

`ttl` is enforced when snapshots are accessed; there is no background job.
A snapshot is expired once the current time is at or after its
`expires_at` (a missing or unreadable `expires_at` never expires).

* `ls`, `diff` and `restore` never use an expired snapshot. `diff` and
  `restore` that name one (by name or ID) fail with `snapshot.snapshot_not_found`
  (exit 1) and a message saying when it expired; `restore`'s error object
  also has `"expired": true`. This applies to `restore dry_run` too.
* Every `create` and `ls` of a target deletes that target's expired
  snapshots first, and notes each on stderr
  (`snapshot ls: warning: snapshot old expired at ...; deleted`).
  Deletion is best effort: a failure is reported as a warning (the
  snapshot stays hidden) and never fails the verb. `diff` and `restore`
  only hide expired snapshots; they do not delete them.
* Only a real directory directly inside the target's group directory of
  the store, whose own `meta.json` names that target and has an
  `expires_at` in the past, is deleted. Symbolic links (as snapshots or as
  the group directory) are never followed, and snapshots of other targets
  that share the group are left alone.
* `create` with the name of an expired snapshot replaces it, whatever
  `if_exists` says; `if_exists=skip` never returns an expired snapshot.
* When `restore` finds a live snapshot by name, expired snapshots with the
  same name (of other targets) are ignored with a warning instead of
  making the name ambiguous.

Output:

```json
{
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
```

`skipped` is true only when `if_exists=skip` found an existing snapshot;
the output then describes that snapshot.

### 3.2 diff

```bash
resh snapshot:///srv/app.diff from=backup-v1 to=live format=summary
resh snapshot:///srv/app.diff from=backup-v1 to=backup-v2
resh snapshot:///srv/app.diff from=backup-v1 to=live path=conf
```

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `from`, `to` | `live` | A snapshot name or ID, or `live` for the current filesystem. An omitted `from` or `to` means `live` (so `from=backup-v1` alone compares the snapshot with the live tree, and `to=backup-v1` alone compares live with the snapshot). At least one side must be a snapshot; the same snapshot on both sides is rejected; an expired snapshot is not found |
| `path` | `/` | Restrict the comparison to a subpath of a directory target; `..` is rejected |
| `format` | `json` | `json` or `summary` (text) |
| `timeout_ms` | none | See section 2 |

Symbolic links in the live tree are followed, as in `create`. Files are
compared by type, mode, size and SHA-256 content hash; a directory by type
and mode only (changes below it are reported as their own entries). A file
that cannot be read is compared by modification time instead, with a
warning on stderr. The JSON report contains `name`, `from`, `to`,
`from_kind`, `to_kind`, `root`, `path`, a `summary` object (`added`,
`removed`, `modified`, `unchanged`) and an `entries` array with one object
per added, removed or modified path (`path`, `type`, `status`, and `from`
and `to` objects with `exists`, `file_type`, `size`, `mtime`, `mode`,
`hash`). For a file target the single entry is named after the file.
Summary format:

```text
snapshot: /srv/app
from: backup-v1 (snapshot)
to:   live (live)
root: /srv/app
path: /

added: 1
removed: 0
modified: 2
unchanged: 14
```

### 3.3 ls

```bash
resh --json-pretty snapshot:///srv/app.ls limit=5
resh snapshot:///srv/app.ls name_prefix=deploy- since=2026-10-01T00:00:00Z
resh snapshot:///srv/app.ls tag=nightly state=complete
```

| Argument | Notes |
| -------- | ----- |
| `limit` | Positive integer; at most this many entries |
| `name_prefix` | Names starting with this prefix |
| `since`, `until` | RFC 3339 timestamps, inclusive |
| `state` | Case-insensitive; snapshots made by `create` are `complete` |
| `tag` | Case-insensitive; matches one of the snapshot's tags |
| `json_pretty` | `true` to indent the JSON (also `--json-pretty`) |
| `timeout_ms` | See section 2 |

Prints a JSON array, newest first, with `id`, `name`, `created_at`,
`backend`, `target`, `state`, `expires_at` (when set), `size_bytes`,
`tags` (when not empty) and `description` (when set). Expired snapshots
are never listed; `ls` deletes them first (see "Expiry" in 3.1). An
unknown target prints `[]`. A snapshot directory whose `meta.json` is
missing or unreadable is skipped with a warning on stderr.

### 3.4 restore

```bash
resh --json-pretty snapshot://backup-v1.restore target=/srv/app force=true
resh --json-pretty snapshot://backup-v1.restore target=/srv/app force=true dry_run
resh snapshot://backup-v1.restore target=/srv/app-copy
resh snapshot://73265a09-2b27-49d7-a5ab-49315543eacb.restore target=/srv/app force=true
```

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `target` | required | Where to restore; may differ from the original path; relative paths are resolved against the working directory |
| `force` | `false` | Required to replace an existing file, symbolic link or non-empty directory |
| `dry_run` | `false` | Print the planned `actions` without changing anything |
| `mode` | `overwrite` | The only supported mode |
| `timeout_ms` | none | See section 2 |

The URL names the snapshot by name, searched across all targets, or by ID.
If the same name was used for snapshots of different targets the restore
is refused with `snapshot.ambiguous_snapshot` (exit 2); the error's `matches` field
lists the IDs and targets, and `snapshot://<id>.restore` picks one.

The snapshot is copied to a temporary location next to the target
(keeping modes, modification times and, as root, ownership); an existing
target is moved aside, the copy is renamed into place, and the old content
is removed. If the final rename fails, the old target is put back. Missing
parent directories of the target are created. A target that is `/`, or
that contains or lies inside the snapshot being restored, is refused.

Output:

```json
{"mode":"overwrite","snapshot":"backup-v1","status":"ok","target":"/srv/app"}
```

Dry run output (always indented):

```json
{
  "actions": [
    "DELETE DIRECTORY \"/srv/app\"",
    "COPY \"/home/alice/.local/state/resh/snapshots/_srv_app/backup-v1/content\" -> \"/srv/app\""
  ],
  "dry_run": true,
  "force": true,
  "mode": "overwrite",
  "snapshot": "backup-v1",
  "target": "/srv/app"
}
```

---

## 4. Limitations

* `ttl` is enforced only when snapshots are accessed: `create` and `ls`
  delete expired snapshots of their target, and `diff` and `restore`
  refuse them; nothing runs in the background.
* Symbolic links are copied as the files they point to; sockets, FIFOs and
  device files are skipped with a warning.
* Ownership is kept only when resh runs as root; otherwise copies belong
  to the user running resh.
* `diff` does not compare ownership.
* Local backend only; full copies only.

---

## 5. Example Workflow

```bash
resh snapshot:///srv/app.create name=deploy-20261023

# deploy the application

resh snapshot:///srv/app.diff from=deploy-20261023 to=live format=summary

# roll back
resh snapshot://deploy-20261023.restore target=/srv/app force=true dry_run
resh snapshot://deploy-20261023.restore target=/srv/app force=true
```
