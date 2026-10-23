# Resource Shell (resh) – Snapshot Handle Documentation

## 1. Overview

The `snapshot://` handle saves full local copies of a file or directory,
compares them with each other or with the live filesystem, lists them and
restores them. It is a plain file-copy mechanism: it does not use
filesystem-level snapshots (LVM, Btrfs, ZFS), and there is no compression,
deduplication or incremental snapshotting.

Verbs: `create`, `diff`, `ls`, `restore`.

Platform: Linux only is supported and tested.

---

## 2. Command Syntax

```text
resh snapshot://<target-path>.create name=<name> ...
resh snapshot://<target-path>.diff from=<snapshot>|live to=<snapshot>|live ...
resh snapshot://<target-path>.ls ...
resh snapshot://<snapshot-name>.restore target=<path> ...
```

The URL names the target path for `create`, `diff` and `ls`, and the
snapshot name for `restore`. Absolute paths take three slashes
(`snapshot:///srv/app.create`).

**Use absolute target paths.** `create` turns a relative target into an
absolute one before storing the snapshot, but `ls` and `diff` look the
target up exactly as written. A snapshot created with
`snapshot://app.create` is therefore not found by `snapshot://app.ls`
(empty list) or `snapshot://app.diff` (error "no snapshots found for
target"); use the absolute path for all three.

Help: `resh snapshot --help`, `resh snapshot <verb> --help`.

### Storage location

Snapshots are stored under the XDG state directory:
`$XDG_STATE_HOME/resh/snapshots` (default `~/.local/state/resh/snapshots`;
`/tmp/resh/snapshots` if no state directory can be determined). Each
target gets a group directory named after its absolute path with every
character other than letters, digits, `.`, `-` and `_` replaced by `_`
(for example `/srv/app` becomes `_srv_app`), truncated to 120 characters.
Each snapshot is a directory named after the snapshot, holding the copied
content and a `meta.json` file.

```text
~/.local/state/resh/snapshots/_srv_app/backup-v1/meta.json
```

### Exit status

0 on success, 1 on failure for `create`, `diff` and `ls`. `restore` uses:

| Code | Meaning (restore) |
| ---- | ----------------- |
| 0 | Restored (or dry run printed) |
| 1 | Missing/invalid argument, unsupported `mode` |
| 2 | Snapshot, its metadata or its content not found |
| 3 | Target exists (file, or non-empty directory) and `force` is not true |
| 4 | Copy or swap into place failed |

The reason is printed on stderr (`Error: ...`); most failures also print a
small JSON object with `error` and `message` on stdout.

### timeout_ms

No snapshot verb reads `timeout_ms`; it is ignored.

---

## 3. Verbs

### 3.1 create

```bash
resh --json-pretty snapshot:///srv/app.create name=backup-v1 ttl=86400
resh snapshot:///etc/nginx.create name=pre-change description='before upgrade' if_exists=skip
```

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `name` | required | Snapshot name, case-sensitive |
| `description` | none | Stored in metadata, shown by `ls` |
| `ttl` | none | Seconds; sets `expires_at` in the metadata only |
| `if_exists` | `error` | `error` (exit 1), `skip` (`"skipped": true`), `overwrite` |
| `backend` | `local` | Only `local` exists |

The copy is made in a temporary directory and renamed into place, so a
failed create leaves no half-written snapshot. File modes and modification
times are kept. Symbolic links are followed: the snapshot (and a later
restore) contains a regular-file copy of the link target, not the link.

`ttl` is not enforced: nothing deletes or hides a snapshot after
`expires_at`. Remove old snapshot directories yourself.

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

### 3.2 diff

```bash
resh snapshot:///srv/app.diff from=backup-v1 to=live format=summary
resh snapshot:///srv/app.diff from=backup-v1 to=backup-v2
resh snapshot:///srv/app.diff from=backup-v1 to=live path=conf
```

| Argument | Notes |
| -------- | ----- |
| `from`, `to` | A snapshot name or id, or `live` for the current filesystem. At least one is required; `live` against `live` is rejected |
| `path` | Restrict the comparison to a subpath |
| `format` | `json` (default) or `summary` (text) |

**Always pass both `from` and `to`.** A side that is left out is compared
as an empty tree, not as the live filesystem: `from=backup-v1` alone
reports every file in the snapshot as `removed` (the report shows
`to: empty (live)`).

Files are compared by content hash when available, otherwise by
modification time. The JSON report contains `name`, `from`, `to`,
`from_kind`, `to_kind`, `root`, `path`, a `summary` object (`added`,
`removed`, `modified`, `unchanged`) and an `entries` array. Summary format:

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
```

Arguments: `limit`, `name_prefix`, `since`, `until` (RFC 3339), `state`,
`tag`, `json_pretty`. Prints a JSON array, newest first, with `id`, `name`,
`created_at`, `backend`, `target` and `description` (when set). An unknown
target prints `[]`.

Snapshots made by `create` record no state or tags, so `state=` and `tag=`
match only metadata written by other means.

### 3.4 restore

```bash
resh --json-pretty snapshot://backup-v1.restore target=/srv/app force=true
resh --json-pretty snapshot://backup-v1.restore target=/srv/app force=true dry_run
resh snapshot://backup-v1.restore target=/srv/app-copy
```

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `target` | required | Where to restore; may differ from the original path |
| `force` | `false` | Required to replace an existing file or non-empty directory |
| `dry_run` | `false` | Print the planned `actions` without changing anything |
| `mode` | `overwrite` | The only supported mode |

The snapshot is found by name across all target groups. If the same name
was used for snapshots of different targets, the first match found is
restored, so keep snapshot names unique.

The snapshot is copied to a temporary location next to the target; an
existing target is moved aside, the copy is renamed into place, and the old
content is removed. If the final rename fails, the old target is put back.

Output:

```json
{"mode":"overwrite","snapshot":"backup-v1","status":"ok","target":"/srv/app"}
```

---

## 4. Limitations

* Relative targets do not work with `ls` and `diff` (see section 2).
* An omitted `from`/`to` in `diff` means an empty tree, not live.
* `ttl` is recorded but never enforced.
* Symbolic links are copied as the files they point to.
* Ownership is not explicitly preserved; restored files belong to the user
  running resh.
* Target group names are truncated to 120 characters, so two long target
  paths that share the same first 120 (sanitized) characters share one
  group: `ls` lists both, and their snapshot names collide.
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
