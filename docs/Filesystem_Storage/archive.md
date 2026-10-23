# Resource Shell (resh) – Archive Handle Documentation

## 1. Overview

The `archive://` handle creates, inspects, verifies, extracts and modifies
local archive files using built-in Rust libraries (no external `tar`, `zip`
or `7z` binary is called). Each operation prints a JSON report (or a text
report with `format_output=text`).

What each format supports today:

| Format (extension)            | create | list / info / test / extract | add / remove |
| ----------------------------- | ------ | ---------------------------- | ------------ |
| tar (`.tar`)                  | yes    | yes                          | yes          |
| tar.gz (`.tar.gz`, `.tgz`)    | yes    | yes                          | yes          |
| tar.xz (`.tar.xz`, `.txz`)    | no     | yes                          | yes          |
| tar.zst (`.tar.zst`, `.tar.zstd`) | no | yes                          | yes          |
| zip (`.zip`)                  | yes (unencrypted only) | yes          | yes          |
| gzip single file              | yes, only with `format=gzip` | yes (`.gz`) | no         |
| raw xz / zstd stream (`.xz`, `.zst`) | no | yes                         | no           |
| 7z (`.7z`)                    | no     | no                           | no           |

Unsupported combinations fail with an error; they never produce a partial or
different-format archive:

* `create` for tar.xz, tar.zst, 7z, or an output ending in `.gz`, `.xz` or
  `.zst` without `format=gzip` fails with
  `archive.create_compression_failed` ("Archive format ... not yet
  implemented"). To create a single-file gzip, pass `format=gzip`
  (only one source file is accepted).
* 7z: `list` fails with `archive.list_7z_unsupported`, `test` with
  `archive.test_7z_unsupported`, `info` with `archive.info_archive_read_error`,
  `extract` with `archive.extract_archive_read_error`, `add` with
  `archive.add_7z_unsupported`, `remove` with `archive.remove_7z_unsupported`
  (or the corresponding read error).
* `add` / `remove` on a raw compressed stream fail with
  `archive.add_unsupported_for_raw` / `archive.remove_unsupported_for_raw`.
* Password-protected archives cannot be created. Any `password=` argument,
  even an empty one, makes `create` fail with
  `archive.create_password_not_supported` before anything is written; it
  never falls back to an unencrypted archive.

Platform: Linux only is supported and tested.

---

## 2. Command Syntax

The URL target is left empty, so the URL is `archive://.` followed by the
verb. Every path is a `key=value` argument; lists of paths or patterns are
JSON arrays (quote them for the shell).

```text
resh archive://.<verb> key=value ...
resh 'archive://.<verb>(key=value,...)'
```

`archive://create` (without the dot) does not parse.

```bash
resh archive://.create output=backup.tar.gz 'sources=["data"]'
resh archive://.extract archive=backup.tar.gz destination=restore
resh archive://.list archive=backup.tar.gz
resh archive://.test archive=backup.tar.gz
resh archive://.info archive=backup.tar.gz
resh archive://.add archive=backup.tar.gz 'inputs=["data/new.txt"]'
resh archive://.remove archive=backup.tar.gz 'paths=["old.txt"]'
```

Help: `resh archive --help` and `resh archive <verb> --help`.

### Verbs

| Verb      | Description |
| --------- | ----------- |
| `create`  | Create a new archive from `sources` |
| `extract` | Extract an archive into `destination` |
| `list`    | List entries with size, mode, owner and mtime |
| `test`    | Read every entry (and its data) and report validity |
| `info`    | Archive-level details: format, compression, sizes, counts, mtime range |
| `add`     | Add files to an existing archive by rewriting it |
| `remove`  | Remove entries by path, glob or directory prefix by rewriting it |

### Format detection

`format` defaults to detection from the file extension (`format=auto` is the
same). Accepted `format` values: `tar`, `tar.gz`/`tgz`, `tar.xz`/`txz`,
`tar.zst`/`tar.zstd`, `zip`, `7z`, `gzip`/`gz`, `raw`. The read verbs also
take `compression=auto|none|gzip|xz|zstd`. A file whose extension is not
recognized needs an explicit `format=`.

### Exit status and errors

Exit code 0 on success, 1 on failure. On failure the JSON report still goes
to stdout with `"ok": false` and `error` set to a two-element array
`[code, message]`, and stderr gets
`Error: [<error code>] <message>`, for example:

```text
Error: [archive.create_output_exists] Output file exists and overwrite=false
```

### Boolean arguments

The security-related booleans `allow_symlinks`, `allow_absolute_paths`,
`allow_parent_traversal`, `overwrite` and `follow_symlinks`, and `dry_run` on
`remove`, accept `true/false/1/0/yes/no/on/off` (case-insensitive) and reject
any other value with an error. The other booleans (`include_hidden`,
`create_destination`, `include_manifest`, `verify_data`, ...) accept only
`true` or `false`; any other value is silently treated as the default.

### timeout_ms

No archive verb reads `timeout_ms`. It is ignored if passed; operations run
to completion.

---

## 3. Verb Reference

Argument names below are the ones the code reads. Run
`resh archive <verb> --help` for a full example output.

### 3.1 create

```bash
resh --json-pretty archive://.create output=logs.tar.gz 'sources=["app.log"]'
resh archive://.create output=site.zip 'sources=["public"]' compression_level=9
resh archive://.create output=app.log.gz format=gzip 'sources=["app.log"]'
resh archive://.create output=src.tar 'sources=["."]' 'include_patterns=["*.rs"]' 'exclude_patterns=["target/*"]'
```

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `output` | required | Output file |
| `sources` | required | JSON array of files/directories |
| `format` | from extension | `tar`, `tar.gz`, `zip`, `gzip` can be written |
| `base_dir` | none | Base for relative archive paths |
| `compression_level` | 6 (gzip, zip) | 1-9; rejected for plain `tar` |
| `include_patterns` / `exclude_patterns` | `[]` | JSON arrays of globs |
| `include_hidden` | `true` | `false` skips dot-files |
| `follow_symlinks` | `false` | |
| `overwrite` | `false` | Existing output fails with `archive.create_output_exists` |
| `max_files` | 100000 | Exceeding it fails with `archive.create_max_files_exceeded` |
| `max_size_mb` | 10240 | Total input size limit, in whole megabytes |
| `format_output` | `json` | `json` or `text` |
| `password` | none | Always rejected (see Overview) |

`preserve_permissions`, `preserve_timestamps` and `progress` are accepted but
have no effect.

### 3.2 extract

```bash
resh --json-pretty archive://.extract archive=logs.tar.gz destination=restore
resh archive://.extract archive=untrusted.tar.gz destination=safe max_total_bytes=1073741824 max_file_bytes=10485760
resh archive://.extract archive=release.tar.gz destination=app strip_components=1 overwrite=true
```

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `archive`, `destination` | required | |
| `includes` / `excludes` | `[]` | JSON arrays of globs |
| `overwrite` | `false` | Existing files are skipped with a warning, not an error |
| `strip_components` | 0 | Leading path components to drop |
| `create_destination` | `true` | `false` fails if the directory is missing |
| `allow_absolute_paths` | `false` | |
| `allow_parent_traversal` | `false` | |
| `allow_symlinks` | `true` | `false` skips symlink entries with a warning |
| `follow_symlinks` | `false` | |
| `max_entries` | 1000000 | |
| `max_total_bytes`, `max_file_bytes` | no limit | Byte limits on uncompressed data |
| `fail_on_missing_archive` | `true` | |
| `include_manifest` | `true` | |
| `format`, `compression`, `format_output` | auto / auto / json | |

#### Extraction safety

* An unsafe entry stops the whole extraction with `"ok": false`, exit code 1
  and one of these error codes; the message says how many entries were
  already written:
  * `archive.extract_path_traversal_detected` – an entry path with `..`
    (rejected by default). With `allow_parent_traversal=true`, `..` is
    accepted only while the resolved path stays inside the destination;
    it can never climb out of it.
  * `archive.extract_absolute_path_rejected` – an absolute entry path (by
    default). With `allow_absolute_paths=true` such entries are re-rooted
    under the destination (`/tmp/x` becomes `<destination>/tmp/x`); they are
    never written at their absolute location.
  * `archive.extract_symlink_rejected` – a symlink whose target points
    outside the destination.
  * `archive.extract_unsupported_entry_type` – device nodes and other
    special entries.
* Extraction never writes through a symlink, whether the archive created it
  or it already existed in the destination.
* Hard links must name a regular file already extracted inside the
  destination.
* There is no default size cap: set `max_total_bytes` / `max_file_bytes`
  when extracting untrusted archives. `max_entries` defaults to 1000000.
* The containment checks are path-based. They protect against a malicious
  archive, not against another process that modifies the destination tree
  while the extraction runs. Extract only into a directory that other users
  cannot write, and never as root into a shared directory such as `/tmp`.

### 3.3 list

```bash
resh --json-pretty archive://.list archive=logs.tar.gz
resh archive://.list archive=logs.tar.gz 'includes=["*.log"]' include_metadata=false
```

Arguments: `archive` (required), `includes`, `excludes`, `include_metadata`
(default `true`), `include_compressed_size` (default `true`), `max_entries`,
`max_total_bytes`, `format`, `compression`, `fail_on_missing_archive`,
`format_output`.

### 3.4 test

```bash
resh --json-pretty archive://.test archive=logs.tar.gz
resh archive://.test archive=logs.tar.gz report_entries=false
```

Arguments: `archive` (required), `verify_data` (default `true`),
`report_entries` (default `true`), `stop_on_first_error` (default `true`),
`max_entries`, `max_total_bytes`, `max_file_bytes`, `format`, `compression`,
`fail_on_missing_archive`, `format_output`. `summary.valid` gives the
overall result.

### 3.5 info

```bash
resh --json-pretty archive://.info archive=logs.tar.gz
```

Arguments: `archive` (required), `scan_entries` (default `true`),
`max_entries`, `max_total_bytes`, `format`, `compression`,
`fail_on_missing_archive`, `format_output`.

### 3.6 add

```bash
resh --json-pretty archive://.add archive=logs.tar.gz 'inputs=["db.log"]'
resh archive://.add archive=logs.tar.gz 'inputs=["app.log"]' overwrite=true
```

Arguments: `archive`, `inputs` (JSON array; an item prefixed with `glob:` is
expanded as a pattern, see the note below), `base_dir`, `includes`, `excludes`, `overwrite`
(replace entries that already exist), `follow_symlinks`, `backup_suffix`,
`tmp_dir`, `max_entries`, `max_total_bytes`, `format`, `compression`,
`format_output`. The archive is rewritten in full.

`deterministic`, `keep_existing_dirs`, `preserve_owner`,
`preserve_permissions` and `preserve_timestamps` are accepted and echoed in
the report but have no effect.

When `add` or `remove` rewrites a tar archive, the entries that stay in it
keep their original headers (mode, owner, modification time, and symlink or
hard-link type and target). The archive is written to a new temporary file
with an unpredictable name and the original archive's permissions, then
renamed over the original; an error while finishing the compressed stream
fails the operation and leaves the original archive unchanged. For ZIP
archives, `add` keeps the existing entries' Unix permissions, modification
times and compression method.

Note on `glob:` inputs: the pattern is expanded to absolute paths, and
without `base_dir` the entry is stored under its full path (leading `/`
removed, e.g. `home/user/work/n.txt`). Pass `base_dir=<absolute dir>` to
store paths relative to that directory.

### 3.7 remove

```bash
resh --json-pretty archive://.remove archive=logs.tar.gz 'paths=["db.log"]'
resh archive://.remove archive=logs.tar.gz 'patterns=["*.tmp"]' dry_run
resh archive://.remove archive=logs.tar.gz 'dir_prefixes=["cache/"]' backup_suffix=.bak
```

At least one of `paths`, `patterns` or `dir_prefixes` (JSON arrays) is
required. Other arguments: `dry_run` (report only, archive unchanged),
`remove_empty_dirs` (default `true`), `backup_suffix`, `tmp_dir`,
`max_entries`, `max_total_bytes`, `format`, `compression`,
`fail_on_missing_archive`, `format_output`. Unlike `add`, `remove` keeps the
metadata of the remaining tar entries.

---

## 4. Output

Every verb prints one JSON object with `ok`, `timestamp_unix_ms`, `query`
(the parsed arguments), a verb-specific body (`result`/`files`/`statistics`
for `create`; `summary` plus `manifest`, `entries` or `details` for the
others), `error` and `warnings`. Abbreviated `info` output:

```json
{
  "ok": true,
  "summary": {
    "archive": "logs.tar.gz",
    "format": "tar.gz",
    "compression": "gzip",
    "entries_total": 1,
    "archive_size_bytes": 115,
    "uncompressed_bytes_total": 14,
    "encrypted": false
  },
  "error": null,
  "warnings": []
}
```

Abbreviated error report (stdout); stderr carries the
`Error: [code] message` line:

```json
{
  "ok": false,
  "error": [
    "archive.extract_path_traversal_detected",
    "Unsafe archive entry '../evil.txt': Path traversal detected (..); extraction stopped after 1 entries were written"
  ]
}
```

Automation should check the exit code and the `ok` field.

---

## 5. Compression Levels (create)

| Format | Range | Default |
| ------ | ----- | ------- |
| tar.gz | 1-9   | 6       |
| zip    | 1-9   | 6       |
| gzip   | 1-9   | 6       |
| tar    | not accepted | – |

A level outside the range fails with
`archive.create_invalid_compression_level`. `add` and `remove` rewrite
compressed tar archives with fixed default levels.

---

## 6. Limitations

* No creation of tar.xz, tar.zst, 7z or raw xz/zstd files; no 7z support at
  all.
* No password-protected (encrypted) archive creation.
* `timeout_ms` is ignored by every verb.
* Linux only.

---

## 7. Best Practices

* Run `test` after `create` and before deploying an archive.
* Set `max_total_bytes` and `max_file_bytes` when extracting untrusted
  archives; keep the default `allow_absolute_paths=false` and
  `allow_parent_traversal=false`.
* Run `remove` with `dry_run` first, and use `backup_suffix` for
  modifications of archives you cannot recreate.
* Check the exit code and `ok` in CI.

```bash
resh archive://.create output=release.tar.gz 'sources=["build"]'
resh archive://.test archive=release.tar.gz
```
