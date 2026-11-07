# Resource Shell (resh) – Archive Handle Documentation

## 1. Overview

The `archive://` handle creates, inspects, verifies, extracts and modifies
local archive files using built-in Rust libraries (no external `tar`, `zip`
or `7z` binary is called). Each operation prints a JSON report (or a text
report with `format_output=text`).

What each format supports:

| Format (extension)                | create | list / info / test / extract | add / remove |
| --------------------------------- | ------ | ---------------------------- | ------------ |
| tar (`.tar`)                      | yes    | yes                          | yes          |
| tar.gz (`.tar.gz`, `.tgz`)        | yes    | yes                          | yes          |
| tar.xz (`.tar.xz`, `.txz`)        | yes    | yes                          | yes          |
| tar.zst (`.tar.zst`, `.tar.zstd`) | yes    | yes                          | yes          |
| zip (`.zip`)                      | yes (unencrypted only) | yes          | yes          |
| gzip single file                  | yes, only with `format=gzip` | yes (`.gz`) | no         |
| raw xz / zstd stream (`.xz`, `.zst`) | no  | yes                          | no           |
| 7z (`.7z`)                        | no     | no                           | no           |

Unsupported combinations fail before anything is written; they never
produce a partial or different-format archive:

* `create` for 7z, or for an output ending in `.gz`, `.xz` or `.zst`
  (a raw stream) without `format=gzip`, fails with
  `archive.create_compression_failed` ("Archive format ... not yet
  implemented for create"). To create a single-file gzip, pass
  `format=gzip` (exactly one regular file is accepted).
* 7z: `list`, `test`, `info`, `extract`, `add` and `remove` fail with
  `archive.<verb>_7z_unsupported`.
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
JSON arrays of strings (quote them for the shell).

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

Help: `resh archive --help` and `resh archive <verb> --help`. The usage
line of each verb lists every argument the verb accepts.

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
`tar.zst`/`tar.zstd`, `zip`, `7z`, `gzip`/`gz`, `raw`. A file whose
extension is not recognized needs an explicit `format=`.

The verbs that read an archive also take
`compression=auto|none|gzip|xz|zstd`. A compressed tar format implies its
compression and zip implies none; a `compression` that contradicts the
format fails with `archive.<verb>_invalid_format_compression`. With
`format=tar` or `format=raw` an automatic compression is taken from the
extension (so `format=tar` on `x.tar.gz` reads it as tar.gz), and
`format=gzip` on a read verb means a raw gzip stream. A raw stream needs a
compression.

### Arguments

Every verb refuses an argument it does not accept, before doing anything,
with exit status 2 and `archive.<verb>_invalid_argument`; the message names
the argument and suggests the closest accepted one ("did you mean ...?").
That includes `dry_run` on any verb but `remove`.

* Booleans accept `true/false/1/0/yes/no/on/off` (any case); any other value
  is refused with `archive.<verb>_invalid_argument`.
* Numbers (`max_entries`, `max_total_bytes`, `max_file_bytes`,
  `strip_components`, `max_files`, `max_size_mb`, `compression_level`,
  `timeout_ms`) are whole numbers written with the digits 0-9 only. A sign,
  fraction, exponent, unit, whitespace or a value above
  18446744073709551615 is refused with the code named for that argument
  (for example `archive.list_invalid_max_size` for `max_total_bytes`).
* Lists are JSON arrays of strings. Glob patterns are checked before
  anything runs. All glob arguments of this handle (`sources`,
  `includes`, `excludes`, `include_patterns`, `exclude_patterns`,
  `patterns`, `glob:` inputs) are shell-style: `*` and `?` do not match
  `/`, and `**` matches across directories. `data/*.txt` matches
  `data/a.txt` but not `data/sub/b.txt`; `**/*.txt` matches both. Names are
  matched as stored in the archive, so `*.txt` matches only top-level
  files. (Before this release `*` also matched `/`.)
* `format_output` is `json` (default) or `text`.

### timeout_ms

Every verb accepts `timeout_ms=<n>` (a positive number of milliseconds;
absent means no limit). The limit is checked between entries and on every
read of the archive or of a source file, so one large entry cannot outlive
it. When it passes, the verb fails with `archive.<verb>_timeout` and exit
status 124:

* `create` leaves no output (it writes to a temporary file that is
  removed); an existing output is unchanged.
* `add` and `remove` leave the archive unchanged.
* `extract` keeps the entries written before the deadline (as for any
  other extraction failure).
* `list`, `test` and `info` report nothing.

### Exit status and errors

| Exit | Meaning |
| ---- | ------- |
| 0    | Success |
| 1    | The operation failed (missing archive, unreadable or corrupt archive, limit exceeded, I/O error, unsafe entry) |
| 2    | Invalid usage: an argument, value, format or archive type the verb cannot work with; nothing was done |
| 124  | `timeout_ms` passed |

Error codes have the form `archive.<verb>_<kind>`.

* An argument refused before the verb runs prints only
  `[<error code>] <message>` on stderr; nothing goes to stdout.
* A failure while the verb runs prints the JSON report on stdout with
  `"ok": false` and `error` set to `[code, message]`, and
  `Error: [<error code>] <message>` on stderr, for example:

```text
Error: [archive.create_output_exists] Output file exists and overwrite=false
```


Codes every verb can return: `invalid_argument` (2), `timeout` (124),
`internal_error` (1). The verb-specific codes are listed in each section of
chapter 3, with their exit status.

### fail_on_missing_archive

`list`, `test`, `info`, `extract` and `remove` take
`fail_on_missing_archive` (default `true`). When it is `false` and the
archive does not exist, the verb succeeds (exit 0) without doing anything:
`warnings` says the archive is missing, `summary` is `null` (for `test`,
`summary.valid` is `false` with no entries tested) and `extract` does not
create the destination. A path that exists but is a directory is always
an error (`archive.<verb>_invalid_archive_path`).

---

## 3. Verb Reference

Argument names below are the ones the code reads. Run
`resh archive <verb> --help` for a full example output.

### 3.1 create

```bash
resh --json-pretty archive://.create output=logs.tar.gz 'sources=["app.log"]'
resh archive://.create output=site.zip 'sources=["public"]' compression_level=9
resh archive://.create output=app.log.gz format=gzip 'sources=["app.log"]'
resh archive://.create output=src.tar 'sources=["."]' 'include_patterns=["**/*.rs"]' 'exclude_patterns=["target/**"]'
```

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `output` | required | Output file |
| `sources` | required | JSON array of files, directories or glob patterns, relative to `base_dir` |
| `format` | from extension | `tar`, `tar.gz`, `tar.xz`, `tar.zst`, `zip`, `gzip` can be written |
| `base_dir` | current directory | Must be an existing directory; archive names are relative to it |
| `compression_level` | see chapter 5 | Rejected for plain `tar` |
| `include_patterns` / `exclude_patterns` | `[]` | JSON arrays of globs, matched against the archive name |
| `include_hidden` | `true` | `false` skips dot-files and everything under a dot-directory |
| `follow_symlinks` | `false` | `false` stores symlinks as symlinks; `true` stores what they point to |
| `overwrite` | `false` | An existing output fails with `archive.create_output_exists` |
| `preserve_permissions` | `true` | `false` stores mode 0644 for files, 0755 for directories (gzip: the output file gets the source's mode when `true`) |
| `preserve_timestamps` | `true` | `false` stores the time of the run (gzip: the source mtime goes into the gzip header when `true`) |
| `max_files` | 100000 | Entries (files, directories, links); more fails with `archive.create_max_files_exceeded` |
| `max_size_mb` | 10240 | Total size of the source files, in MiB; more fails with `archive.create_max_size_exceeded` |
| `progress` | `false` | `true` writes `archive create: [n/total] <name>` to stderr as each entry is archived |
| `timeout_ms` | none | See 2 |
| `format_output` | `json` | `json` or `text` |
| `password` | none | Always refused (see Overview) |

Behavior:

* The archive is written to a temporary file in the output's directory and
  moved into place only when it is complete; a failure leaves no output
  and an existing output (with `overwrite=true`) unchanged. Without
  `overwrite` an output that appears meanwhile is not replaced.
* An existing output is never archived into itself (for example
  `sources=["."]` with `overwrite=true`).
* A source given twice, or a file inside a directory source also given on
  its own, is stored once.
* An absolute source outside `base_dir` is stored under its full path
  without the leading `/`. A source that would be stored with a `..`
  component (for example `../x` without `base_dir`) is refused with
  `archive.create_invalid_sources`.
* Special files (FIFOs, sockets, devices) are skipped with a warning.
* `compression_ratio` in the report is `1 - compressed/total` (negative
  when the archive is larger than its contents, as for tiny files).

Error codes (`archive.create_...`): `invalid_output` (2; missing, empty, or
a directory), `invalid_sources` (2; missing, empty, not a JSON array,
outside `base_dir`, or not exactly one file with `format=gzip`),
`invalid_format` (2), `invalid_base_dir` (2), `invalid_compression_level`
(2), `invalid_pattern` (2), `invalid_max_files` (2), `invalid_max_size`
(2), `password_not_supported` (2), `compression_failed` (2 for an
unsupported output format; 1 when writing the archive fails),
`output_exists` (1), `source_not_found` (1), `source_permission_denied`
(1), `max_files_exceeded` (1), `max_size_exceeded` (1),
`permission_denied` (1; the output cannot be created), `disk_full` (1),
`timeout` (124).

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
| `follow_symlinks` | `false` | Only `false` is accepted: extraction never follows or writes through a symlink, so `true` is refused with `archive.extract_invalid_argument` |
| `max_entries` | 1000000 | More entries fail with `archive.extract_max_entries_exceeded` |
| `max_total_bytes`, `max_file_bytes` | no limit | Byte limits on uncompressed data; digits only |
| `fail_on_missing_archive` | `true` | See 2 |
| `include_manifest` | `true` | `false` leaves `manifest` null |
| `format`, `compression`, `format_output` | auto / auto / json | |
| `timeout_ms` | none | See 2 |

A raw stream (`.gz`, `.xz`, `.zst`) is written to one file named after the
archive without its compression extension.

Error codes (`archive.extract_...`): `invalid_archive_path` (2),
`invalid_destination` (2; missing, empty, or an existing non-directory),
`invalid_format` / `invalid_format_infer` / `invalid_compression` /
`invalid_format_compression` (2), `invalid_include_pattern` /
`invalid_exclude_pattern` (2), `invalid_strip_components` (2),
`invalid_max_entries` / `invalid_max_size` / `invalid_max_file_size` (2),
`7z_unsupported` (2), `missing_archive` (1), `destination_missing` (1),
`destination_create_failed` (1), `path_traversal_detected`,
`absolute_path_rejected`, `symlink_rejected`, `unsupported_entry_type` (1,
see below), `max_entries_exceeded` (1), `max_size_exceeded` (1;
`max_total_bytes`), `max_file_size_exceeded` (1; `max_file_bytes`),
`archive_read_error` (1; corrupt or truncated data), `io_error` (1;
writing into the destination failed), `timeout` (124).

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
* Symlink entries of tar and zip archives (a zip entry whose Unix mode is a
  symlink) are created as symlinks after the same checks; with
  `allow_symlinks=false` they are skipped.
* Extraction never writes through a symlink, whether the archive created it
  or it already existed in the destination.
* Hard links must name a regular file already extracted inside the
  destination.
* There is no default size cap: set `max_total_bytes` / `max_file_bytes`
  when extracting untrusted archives. `max_entries` defaults to 1000000.
* Since v1.0.5-beta the size limits apply to the bytes each entry actually
  produces when it is decompressed, for zip, tar and raw streams, not only
  to the size the archive records. An entry whose size is known in advance
  and too large is refused before anything is written; otherwise writing
  stops at the limit. Either way extraction fails with exit code 1 and
  `archive.extract_max_file_size_exceeded` (`max_file_bytes`) or
  `archive.extract_max_size_exceeded` (`max_total_bytes`); v1.0.5-beta
  reported both as `archive.extract_archive_read_error`.
* Since v1.0.5-beta `max_total_bytes` and `max_file_bytes` must be a whole
  number of bytes written with the digits 0-9 only (`0` allows only empty
  files). Any other value, such as `1e6`, `1.5`, `-1`, `+1`, `10MB`, an
  empty value or a number above 18446744073709551615, is refused before
  anything is extracted, with exit code 2 and
  `archive.extract_invalid_max_size` or
  `archive.extract_invalid_max_file_size` on stderr. Earlier versions
  ignored such a value, which meant no limit. The same rule now applies to
  the limits of `list`, `test`, `info`, `add` and `remove`.
* Since v1.0.5-beta every verb that reads a tar archive (`list`, `test`,
  `info`, `extract`, `add`, `remove`, and plugin installation) refuses a
  member preceded by more than 1 MiB (1048576 bytes) of tar header data:
  its header, PAX extended headers, GNU long name and long link headers and
  GNU sparse extension blocks, counted after decompression. Earlier
  versions read that header data into memory, up to the size the header
  declared, before any size limit applied. File contents do not count
  toward this limit. The verb fails with exit code 1 and a message naming
  the limit, with `archive.<verb>_archive_read_error` (v1.0.5-beta reported
  `archive.add_archive_write_error` for `add` and
  `archive.list_internal_error`, on stderr only, for `list`); `test`
  reports it as `archive.test_entry_header_error` on the entry.
* Every regular file is written to a temporary file next to its final name
  and renamed into place only when complete. If an entry fails (a size
  limit, corrupt data, a truncated archive), its temporary file and any
  directories created only for it are removed, and an existing file of the
  same name is left unchanged. Entries extracted before the failing one are
  kept; extraction does not roll back completed entries. If resh is killed
  mid-entry, a `.resh-extract-*` temporary file can remain in the
  destination.
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
(default `true`; `false` leaves mode, owner and mtime null),
`include_compressed_size` (default `true`; zip and raw streams only),
`max_entries` (default 1000000), `max_total_bytes` (no limit; counts the
listed entries), `format`, `compression`, `fail_on_missing_archive`,
`timeout_ms`, `format_output`.

A raw compressed stream is listed as one entry whose `size` is its
decompressed size. Hard links and symlinks are both reported with
`is_symlink: true`.

Error codes (`archive.list_...`): `invalid_archive_path`, `invalid_format`,
`invalid_format_infer`, `invalid_compression`,
`invalid_format_compression`, `invalid_include_pattern`,
`invalid_exclude_pattern`, `invalid_max_entries`, `invalid_max_size`,
`7z_unsupported` (all 2), `missing_archive`, `io_error`,
`max_entries_exceeded`, `max_size_exceeded`, `archive_read_error` (1),
`timeout` (124).

### 3.4 test

```bash
resh --json-pretty archive://.test archive=logs.tar.gz
resh archive://.test archive=logs.tar.gz report_entries=false
```

Arguments: `archive` (required), `verify_data` (default `true`; `false`
checks headers only), `report_entries` (default `true`),
`stop_on_first_error` (default `true`), `max_entries` (default 1000000),
`max_total_bytes`, `max_file_bytes`, `format`, `compression`,
`fail_on_missing_archive`, `timeout_ms`, `format_output`.
`summary.valid` gives the overall result.

A damaged entry is reported on the entry (`status: "error"` with
`archive.test_entry_header_error`, `entry_io_error`,
`entry_compression_error`, `entry_checksum_error`, `entry_size_mismatch` or
`max_file_size_exceeded`) and the verb fails with
`archive.test_entry_failed` (1). An archive with more than `max_entries`
entries, or more than `max_total_bytes` of data, fails with
`archive.test_max_entries_exceeded` / `archive.test_max_size_exceeded` (1)
instead of being reported valid after a partial check.

Error codes (`archive.test_...`): `invalid_archive_path`, `invalid_format`,
`invalid_format_infer`, `invalid_compression`,
`invalid_format_compression`, `invalid_max_entries`, `invalid_max_size`,
`invalid_max_file_size`, `7z_unsupported` (all 2), `missing_archive`,
`io_error`, `entry_failed`, `max_entries_exceeded`, `max_size_exceeded`,
`archive_read_error` (1), `timeout` (124).

### 3.5 info

```bash
resh --json-pretty archive://.info archive=logs.tar.gz
```

Arguments: `archive` (required), `scan_entries` (default `true`; `false`
reports only the file's size and mtime, with the counts and
`compression_ratio` null), `max_entries`, `max_total_bytes`, `format`,
`compression`, `fail_on_missing_archive`, `timeout_ms`, `format_output`.

`compression_ratio` is uncompressed bytes divided by archive bytes. For zip
archives the entry mtimes, symlinks (by Unix mode) and encrypted entries
are reported. A raw stream is decompressed to count its size.

Error codes (`archive.info_...`): `invalid_archive_path`, `invalid_format`,
`invalid_format_infer`, `invalid_compression`,
`invalid_format_compression`, `invalid_max_entries`, `invalid_max_size`,
`7z_unsupported` (all 2), `missing_archive`, `io_error`,
`max_entries_exceeded`, `max_size_exceeded`, `archive_read_error` (1),
`timeout` (124).

### 3.6 add

```bash
resh --json-pretty archive://.add archive=logs.tar.gz 'inputs=["db.log"]'
resh archive://.add archive=logs.tar.gz 'inputs=["app.log"]' overwrite=true
```

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `archive` | required | Must exist |
| `inputs` | required | JSON array of paths; an item prefixed with `glob:` is expanded as a pattern (see below) |
| `base_dir` | none | Inputs under it are stored relative to it |
| `includes` / `excludes` | `[]` | Globs matched against the archive name |
| `overwrite` | `false` | Replace entries that already exist; otherwise they are skipped with a warning |
| `keep_existing_dirs` | `true` | An input directory whose entry already exists keeps the existing entry, silently, even with `overwrite=true`. `false` treats directory entries like files (replaced or skipped with a warning) |
| `follow_symlinks` | `false` | `false` stores symlinks as symlinks |
| `preserve_owner` | `false` | `true` stores the files' uid/gid and user/group names (tar only; zip stores no owner); `false` stores uid/gid 0 and no names |
| `preserve_permissions` | `true` | `false` stores mode 0644 (files) / 0755 (directories) |
| `preserve_timestamps` | `true` | `false` stores the time of the run |
| `deterministic` | `false` | `true` adds new entries sorted by name, with mtime 1980-01-01T00:00:00Z and owner 0 (overrides `preserve_timestamps` and `preserve_owner`) |
| `backup_suffix` | none | Copy the original to `<archive>.<suffix>` first (a leading dot is optional) |
| `tmp_dir` | archive's directory | Where the rewrite is written; must exist |
| `max_entries`, `max_total_bytes` | 1000000 / none | Limits on the entries being added |
| `format`, `compression`, `format_output`, `timeout_ms` | | |

Behavior:

* The archive is rewritten: the existing entries are copied (tar: with
  their original headers, full names and link targets; zip: with their
  name, Unix mode, file type, modification time and compression method,
  recompressed) followed by the new ones, to a new temporary file
  with an unpredictable name and the original archive's permissions, which
  is then renamed over the original (copied first when `tmp_dir` is on
  another filesystem). An error leaves the original archive unchanged and
  no temporary file. The existing data is streamed, not held in memory.
* When there is nothing to add (every input skipped), the archive is not
  rewritten and a warning says so.
* Archive names are normalized (`./a` is stored as `a`); an input that
  would be stored with a `..` component is refused with
  `archive.add_invalid_input`. The archive itself is never added into
  itself, and duplicate inputs are added once.
* `glob:` inputs are expanded to absolute paths, and without `base_dir` the
  entry is stored under its full path (leading `/` removed, e.g.
  `home/user/work/n.txt`). Pass `base_dir=<absolute dir>` to store paths
  relative to that directory.
* `backup_suffix` writes the copy to a new temporary file and renames it
  into place; an existing symlink at the backup name is refused and `add`
  fails with `archive.add_backup_failed` before the archive is changed.

Error codes (`archive.add_...`): `invalid_archive_path`, `invalid_input`
(missing, empty or not a JSON array; an input that does not exist or
cannot be read; a `..` name), `invalid_format`, `invalid_format_infer`,
`invalid_compression`, `invalid_format_compression`,
`invalid_include_pattern`, `invalid_exclude_pattern`,
`invalid_max_entries`, `invalid_max_size`, `unsupported_for_raw`,
`7z_unsupported` (all 2), `missing_archive`, `io_error` (an input
directory cannot be walked, `tmp_dir` missing), `max_entries_exceeded`,
`max_size_exceeded`, `archive_read_error`, `archive_write_error`,
`backup_failed` (1), `timeout` (124).

### 3.7 remove

```bash
resh --json-pretty archive://.remove archive=logs.tar.gz 'paths=["db.log"]'
resh archive://.remove archive=logs.tar.gz 'patterns=["*.tmp"]' dry_run
resh archive://.remove archive=logs.tar.gz 'dir_prefixes=["cache/"]' backup_suffix=.bak
```

At least one of `paths` (exact names), `patterns` (globs) or
`dir_prefixes` (a directory and everything under it) is required; a
trailing `/` and a leading `./` are ignored when matching. Other
arguments: `dry_run` (report only, archive unchanged; the size after is
estimated), `remove_empty_dirs` (default `true`: a directory entry whose
contents were all removed by this call is removed too; directories that
were already empty are kept), `backup_suffix` (copy the original to
`<archive>.<suffix>` before replacing it), `tmp_dir`, `max_entries` and
`max_total_bytes` (limits on reading the archive), `format`,
`compression`, `fail_on_missing_archive`, `timeout_ms`, `format_output`.

The remaining entries keep their original headers, full names and link
targets (tar) or their mode, type, time and compression method (zip).
When nothing matches, the
archive is not rewritten. Selectors that match nothing produce a warning
(and `paths` are listed in `details.not_found`). The rewrite is atomic in
the same way as for `add`.

Error codes (`archive.remove_...`): `invalid_archive_path`,
`nothing_to_remove`, `invalid_argument` (also a `paths` or `dir_prefixes`
value that is not a JSON array or contains an empty name),
`invalid_pattern`, `invalid_format`, `invalid_format_infer`,
`invalid_compression`, `invalid_format_compression`,
`invalid_max_entries`, `invalid_max_size`, `unsupported_for_raw`,
`7z_unsupported` (all 2), `missing_archive`, `io_error`,
`max_entries_exceeded`, `max_size_exceeded`, `archive_read_error`,
`archive_write_error`, `backup_failed`, `replace_failed` (1), `timeout`
(124).

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

| Format  | Range | Default |
| ------- | ----- | ------- |
| tar.gz  | 1-9   | 6       |
| tar.xz  | 1-9   | 6       |
| tar.zst | 1-22  | 3       |
| zip     | 1-9   | 6       |
| gzip    | 1-9   | 6       |
| tar     | not accepted | – |

A level outside the range, or any level for plain `tar`, fails with
`archive.create_invalid_compression_level` (exit 2). `add` and `remove`
rewrite compressed tar archives with the default levels.

---

## 6. Limitations

* No creation of 7z or raw xz/zstd files; no 7z support at all.
* No password-protected (encrypted) archive creation. Encrypted zip
  entries are counted by `info` but cannot be tested or extracted, and
  `add` / `remove` fail with `archive_write_error` (archive unchanged) when
  such an entry would have to be kept.
* The 1 MiB limit on tar header data per member is fixed. A tar archive
  whose members carry more metadata than that (for example, very large
  extended attributes stored as PAX records) cannot be read.
* When `add` or `remove` rewrites a tar archive, PAX extended attributes of
  the kept entries (extended attributes, sub-second times) are not
  carried over; mode, owner, times, names and link targets are.
* Linux only.

---

## 7. Best Practices

* Run `test` after `create` and before deploying an archive.
* Set `max_total_bytes` and `max_file_bytes` when extracting untrusted
  archives; keep the default `allow_absolute_paths=false` and
  `allow_parent_traversal=false`.
* Run `remove` with `dry_run` first, and use `backup_suffix` for
  modifications of archives you cannot recreate.
* Use `timeout_ms` for unattended runs on archives of unknown size.
* Check the exit code and `ok` in CI.

```bash
resh archive://.create output=release.tar.gz 'sources=["build"]'
resh archive://.test archive=release.tar.gz
```
