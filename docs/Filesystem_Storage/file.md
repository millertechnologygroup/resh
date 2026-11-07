# Resource Shell (resh) – File Handle Documentation

## 1. Overview

The `file://` handle reads, writes, inspects, hashes and searches files and
directories on the local filesystem, and manages permissions, ownership,
extended attributes and tags. It uses the Rust standard library for file
I/O, the `xattr` crate for extended attributes and the `notify` crate for
`watch`.

Platform: Linux only is supported and tested.

---

## 2. Command Syntax

```text
resh file://<path>.<verb> key=value ...
resh 'file://<path>.<verb>(key=value,...)'
```

The verb is the part after the last dot of the URL (`ea.get`, `ea.set`,
`tag.add`, `tag.rm` are recognized as a whole), so a file name with dots
works: `file:///etc/app.conf.read` reads `/etc/app.conf`.

Paths:

* Absolute paths take three slashes: `file:///var/log/syslog.tail`.
* Relative paths resolve from the current directory:
  `file://data.txt.read`, `file://./logs/app.log.tail`. Relative directories
  work too (`file://src.find`). The current directory itself is
  `file://./.find` (`file://.find` has an empty path, which the URL parser
  turns into `/`).
* URL parsing lowercases the first segment of a relative path and drops a
  leading `localhost`, so write `file://./Report.txt.read` for a mixed-case
  relative name.
* `%xx` escapes are decoded, and `\ `, `\\`, `\t`, `\n` are unescaped, in the
  path and in `to=` destinations.

Help: `resh file --help`, `resh file <verb> --help`, or the `help`/`h` verb.

### Arguments

Every verb accepts exactly the arguments shown in its usage
(`resh file <verb> --help` and the tables below). Anything else is refused
before anything is done, with exit code 2, `INVALID_ARG` and a
"did you mean" hint for a likely typo. This includes `dry_run` (only
`replace` has a dry-run mode) and `timeout_ms` (only `watch` and
`tail follow=true` use it). Invalid values (a negative or non-numeric count,
an unknown enum value, a malformed octal mode or digest) are refused the
same way.

Booleans accept `true/false`, `1/0`, `yes/no`, `on/off` (any case); any
other value is `INVALID_ARG`. Numbers are non-negative integers; where a
minimum applies it is given below.

### Errors and exit status

0 on success. Every failure prints `Error: <CODE>: <message>` on stderr:

| Code | Exit | Meaning |
| ---- | ---- | ------- |
| `INVALID_ARG` | 2 | Missing, unknown, malformed or conflicting argument, or unknown verb. Nothing was done. |
| `NOT_FOUND` | 1 | The path, source, or destination parent does not exist (or a path component is not a directory). |
| `ATTR_NOT_FOUND` | 1 | The extended attribute does not exist (`ea.get`, `ea.set mode=update`). |
| `PERMISSION_DENIED` | 1 | The system refused the operation (EACCES/EPERM). |
| `ALREADY_EXISTS` | 1 | The destination exists and `overwrite` is not set, or `ea.set mode=create` found the attribute. |
| `IS_A_DIRECTORY` | 1 | The verb needs a file but the path is a directory, or `delete` of a directory without `recursive=true`. |
| `NOT_A_FILE` | 1 | The path is a FIFO, socket or device where a regular file is needed (only `read` streams those). |
| `NO_MATCH` | 1 | `grep` found no matching line. |
| `VERIFY_FAILED` | 1 | `verify` found a different digest or size. |
| `TOO_LARGE` | 1 | Hashing a file over 10 GiB. |
| `NOT_UTF8` | 1 | `replace` on a file that is not UTF-8 text. |
| `PARSE_ERROR` | 1 | `schema` with a forced `format=` that the sample does not parse as. |
| `UNSUPPORTED` | 1 | The filesystem does not support the operation (for example extended attributes, or an attribute namespace). |
| `REFUSED` | 1 | Refused for safety: deleting `/`, `.` or `..`; moving a directory into itself. |
| `PARTIAL` | 1 | Part of the work was done; the message says what (for example `find` could not read some directories). |
| `IO_ERROR` | 1 | Any other I/O failure. |

### timeout_ms

`watch` stops after `timeout_ms` (default 30000; `0` means no limit, so it
waits for `max_events`) and exits 0. `tail follow=true` follows the file
until `timeout_ms` (default: no limit, so until interrupted) and exits 0;
`timeout_ms` without `follow=true` is `INVALID_ARG`. No other verb accepts
`timeout_ms`.

`watch` and `tail follow=true` write and flush each event or each piece of
new data as it happens.

---

## 3. Verbs

### 3.1 Reading and inspection

| Verb      | Arguments | Output |
| --------- | --------- | ------ |
| `read`    | – | Raw file contents |
| `exists`  | – | `{"exists":true,"kind":"file","path":...}` |
| `stat`    | `nofollow` (default false) | JSON: `file_type`, `size`, `mode`, `uid`, `gid`, `readonly`, `accessed`, `modified`, `created` |
| `preview` | `max_bytes` (default 4096, min 1), `max_lines` (default 40, min 1), `mode=auto\|text\|binary`, `encoding=base64\|hex`, `include_metadata` (default true) | JSON sample |
| `summary` | `max_bytes` (default 65536, min 1, at most 1 MiB is read) | JSON: size, mtime, content type, line stats (entry count for directories) |
| `analyze` | `max_bytes` (default 65536, min 1) | JSON: `ascii_ratio`, `entropy`, `line_count`, `classification` |
| `schema`  | `format=json\|ndjson\|csv\|tsv\|text`, `max_bytes` (default 65536, min 1), `max_rows` (default 100, min 1) | JSON structure report |
| `tail`    | `lines` (default 10, min 1) or `bytes` (min 1), `follow`, `timeout_ms` | Raw lines |

```bash
resh file:///etc/hostname.read
resh --json-pretty file:///etc/hosts.stat
resh file://./logs/app.log.tail lines=50
resh --json-pretty file:///srv/data/users.csv.schema
```

* `exists` reports `kind` `file`, `dir`, `symlink` (also for a dangling
  link), `other`, or `none` with `exists:false` when nothing is there.
* `read` streams any readable file. `preview`, `summary`, `analyze`,
  `schema`, `tail` and `grep` need a regular file (`NOT_A_FILE` otherwise,
  since a FIFO or device could block forever).
* `preview` cuts the sample at `max_bytes`, then at `max_lines` lines;
  `is_truncated` is true when the file is longer than the bytes read.
* `schema` treats the first CSV/TSV line as the header and samples
  `max_rows` data rows after it. With `format=` the sample must parse as that
  format, otherwise `PARSE_ERROR`.
* `tail` counts lines, not newlines: a last line without a newline counts.
  `lines` and `bytes` together are `INVALID_ARG`. With `follow=true` it then
  prints data appended to the file; a file that shrinks (truncated or
  replaced) is read again from the start, and a file that disappears ends
  the follow with `NOT_FOUND`.

### 3.2 Searching

| Verb   | Arguments |
| ------ | --------- |
| `grep` | `pattern` (required), `regex` (default true), `ignore_case`, `invert`, `max` (stop after n matches, min 1), `before`, `after`, `format=text\|json`, `line_numbers` (default true) |
| `find` | `name=<glob>`, `type=file\|dir\|symlink`, `max_depth`, `limit`, `include_hidden`, `follow_symlinks` |

```bash
resh file:///var/log/app.log.grep pattern=error ignore_case=true max=20
resh --json-pretty file:///srv/www.find name='*.html' type=file max_depth=3
```

* `grep` text output is `<line>:<text>`, or `<text>` with
  `line_numbers=false`. With `before`/`after` context, matching lines are
  prefixed `:` and context lines `-` (`:2:ERROR disk full`, `-3:next`).
  After-context lines still follow the last match allowed by `max`. Lines
  that are not valid UTF-8 are matched and shown lossily, and line numbers
  stay exact. `format=json` prints an array of
  `{"path","line","text","matched"}`; `before`, `after` and
  `line_numbers` apply to text output only and are `INVALID_ARG` with
  `format=json`. No match exits 1 with `NO_MATCH`.
* `find` prints a JSON array of entries (`path` made absolute, `type`,
  `size`, `mode`, `mtime`, `is_hidden`, `depth`), starting with the root at
  depth 0, sorted by name. `include_hidden=false` (the default) skips
  dot-files and dot-directories and everything inside them; the root itself
  is always walked. `limit` caps the number of entries. Entries that cannot
  be read are reported as `Warning:` lines on stderr; the listing is still
  printed and the command exits 1 with `PARTIAL`. A symlink loop (with
  `follow_symlinks=true`) is only a warning.

### 3.3 Watching

```bash
resh file:///etc/nginx/nginx.conf.watch events=modify timeout_ms=60000
resh file://./incoming.watch max_events=1
```

Arguments: `timeout_ms` (default 30000), `max_events` (default 1, min 1),
`events=create,modify,remove,rename` (default all; other names are
`INVALID_ARG`). `watch` stops at the first of the two limits, so by default
it returns after one event or 30 seconds. Each event is printed as one line
of JSON (`event`, `path`, `kind`, `timestamp`) and counts toward
`max_events`. A rename prints two `rename` lines, one for the old and one
for the new name. The path is watched non-recursively; a missing path is
`NOT_FOUND`.

### 3.4 Hashing and verification

| Verb | Arguments | Algorithms |
| ---- | --------- | ---------- |
| `md5`, `sha1`, `sha256`, `sha512` | – | fixed |
| `hash` | `algo` (default `sha256`) | `sha256`, `sha512`, `sha1`, `md5`, `blake3` |
| `verify` | `algo` (default `sha256`), `expected=<hex>`, `expected_any=<hex>;<hex>...`, `size=<bytes>` | `sha256`, `sha512`, `sha1`, `md5`, `blake3` |

Algorithm names are case-insensitive. An unsupported algorithm is
`INVALID_ARG` (exit 2). Only regular files are hashed; files larger than
10 GiB are refused with `TOO_LARGE`.

`verify` checks `expected` (or any of `expected_any`) and `size` when given;
with neither it only computes the digest. Expected digests must be hex of
the algorithm's length (spaces are ignored, case does not matter), otherwise
`INVALID_ARG`. It prints a JSON report; on a mismatch `verified` is false
and it exits 1 with `VERIFY_FAILED`. When the file cannot be hashed (missing,
a directory, too large) the report has `verified:false` and the error in
`error`, and the command fails with that error's code.

```bash
resh --json-pretty file:///srv/data/users.csv.sha256
resh --json-pretty file:///srv/data/users.csv.hash algo=blake3
resh --json-pretty file:///deploy/app.bin.verify algo=sha256 expected=58603e637dd7dc6b9bafe03f99f57a1df21bfe591f460fef091c533969c47984
```

Output of the fixed-algorithm verbs:

```json
{"algorithm":"sha256","hash":"58603e637dd7dc6b9bafe03f99f57a1df21bfe591f460fef091c533969c47984","path":"log.txt","size":21}
```

### 3.5 Writing and modifying content

| Verb | Arguments |
| ---- | --------- |
| `write` | `data`, `create` (default `true`), `mode=<octal>` |
| `append` | `data`, `create` (default `true`) |
| `replace` | `pattern` (required, not empty), `replacement` (required), `regex` (default false), `count` (min 1), `dry_run`, `backup=<suffix>` |

```bash
resh file:///tmp/greeting.txt.write data='hello world'
resh file:///var/tmp/jobs.log.append data='job finished'
resh --json-pretty file:///etc/app.conf.replace pattern=8080 replacement=9090 dry_run
```

`write` replaces the file atomically: the data goes to a new temporary file
in the same directory, which is synced and renamed over the target. The
replaced file keeps its permission bits (and, when the process may set it,
its owner) unless `mode=` is given; a new file gets `mode=` or the umask
default. `mode` is octal, at most `7777`. If the path is a symbolic link,
the link is replaced by a regular file. Missing parent directories are
created. It prints `{"bytes":...,"path":...,"written":true}`.

`append` appends with `O_APPEND`, syncs, and prints
`{"appended":true,"bytes":...,"path":...}`. No newline is added. Missing
parent directories are created when `create=true`.

`create=false` makes a missing file `NOT_FOUND` (nothing is created). A
directory is `IS_A_DIRECTORY`, a FIFO or device `NOT_A_FILE`.

**`write` and `append` without `data=` read standard input until EOF.**
If standard input is empty (for example `< /dev/null`, or a non-interactive
job with no input), `write` truncates the file to 0 bytes and still reports
success. Always pass `data=` unless you mean to pipe content in:

```bash
printf 'line\n' | resh file:///tmp/out.txt.write
```

`replace` reads a UTF-8 file (`NOT_UTF8` otherwise), replaces `pattern`
(literal text, or a regular expression with `regex=true`) at most `count`
times (all by default), and rewrites the file atomically, keeping its
permission bits. In `replacement`, `\n`, `\t` and `\\` are unescaped, and
with `regex=true` `$1` or `${name}` insert capture groups (`$$` is a
literal `$`). `dry_run` reports the replacement count without changing
anything. The JSON report (`replacements`, `changed`, `original_bytes`,
`new_bytes`, ...) is printed only after the file was written. `backup` must
be a file name suffix (no `/`).

### 3.6 Copying, moving, deleting

| Verb | Arguments |
| ---- | --------- |
| `copy` | `to` (required), `overwrite`, `preserve_mode` (default `true`), `preserve_times` (default `false`) |
| `rename` | `to` (required), `overwrite`, `create_parents`, `atomic` (default `true`) |
| `move` / `mv` | `to` (required), `overwrite`; moves into `to` when it is an existing directory |
| `delete` / `remove` | `recursive`, `force`, `missing_ok` |

```bash
resh file:///etc/nginx/nginx.conf.copy to=/etc/nginx/nginx.conf.bak
resh --json-pretty file:///srv/data/old.csv.rename to=/srv/data/new.csv
resh file:///tmp/report.pdf.move to=/srv/reports
resh file:///tmp/build.cache.delete recursive=true
```

* `copy` copies a regular file through a temporary file in the destination
  directory that is synced and renamed into place. `preserve_mode` keeps
  the permission bits (otherwise the umask default applies);
  `preserve_times` keeps the access and modification times. The destination
  may not be a directory. `copy`, `move` and `delete` print nothing on
  success.
* `to=` may be absolute, relative (`backup/new.txt`) or a bare name
  (`to=new.txt`), which is relative to the working directory. A missing
  parent directory is `NOT_FOUND` ("destination parent does not exist")
  unless `create_parents=true` (rename only).
* `rename` and `move` refuse an existing destination unless
  `overwrite=true`. A file replaces a file atomically. When a directory is
  involved, the old destination is first renamed aside, put back if the
  rename fails, and removed afterwards, so a failed rename never loses it.
  Moving a directory into itself is `REFUSED`.
* Across filesystems the data is copied (files, directories, symlinks; with
  permission bits, times and, when permitted, ownership) and the source is
  then removed. With `atomic=true` (the default) the copy is made under a
  temporary name next to the destination and renamed into place, so the
  destination appears complete or not at all; with `atomic=false` it is
  copied directly to the destination (a partial copy is removed on
  failure). `rename` then reports `"cross_filesystem": true`. If the source
  cannot be removed after the copy, the command fails with `PARTIAL`.
  Special files (FIFOs, sockets, devices) cannot be copied (`NOT_A_FILE`).
* `delete` refuses `/`, `.`, `..` and paths ending in `..` (`REFUSED`); a
  directory needs `recursive=true` (`IS_A_DIRECTORY` otherwise). A symbolic
  link is removed itself, never its target. `force=true` or
  `missing_ok=true` make a missing path succeed. If a recursive delete fails
  part way, the message says that part of the tree may already be deleted.

### 3.7 Permissions, ownership, attributes, tags

| Verb | Arguments |
| ---- | --------- |
| `chmod` | `mode=<octal>` (required, at most `7777`) |
| `chown` | `user` or `uid`, `group` or `gid` (at least one), `recursive` |
| `ea.get` | `name` (required), `allow_missing` |
| `ea.set` | `name`, `value` (required), `mode=create\|update\|upsert` (default `upsert`) |
| `tag.add` | `name=<tag>[,<tag>...]` (required) |
| `tag.rm` | `name=<tag>[,<tag>...]` (required) |

```bash
resh file:///usr/local/bin/backup.sh.chmod mode=755
resh file:///srv/www.chown user=alice group=www recursive=true
resh --json-pretty file:///srv/data/report.pdf.ea.get name=user.comment
resh --json-pretty file:///srv/data/report.pdf.tag.add name=work,q3
```

* `chmod` and `chown` follow a symbolic link named in the URL, like
  chmod(1) and chown(1). `chown recursive=true` changes every entry below a
  directory too; symbolic links inside the tree are changed themselves
  (never their targets, so nothing outside the tree changes). It stops at
  the first failure and the message says how many entries were already
  changed. `user`/`uid` and `group`/`gid` together are `INVALID_ARG`, as are
  unknown user or group names. Changing ownership to another user needs
  root (`PERMISSION_DENIED` otherwise).
* Attribute names need a namespace: `user.`, `trusted.`, `security.` or
  `system.` followed by a name. `ea.get` of a missing attribute is
  `ATTR_NOT_FOUND` unless `allow_missing=true` (then `exists:false`,
  `value:null`). Values that are not UTF-8 are base64 encoded and add
  `"encoding":"base64"`. `ea.set mode=create` fails with `ALREADY_EXISTS`
  when the attribute exists, `mode=update` with `ATTR_NOT_FOUND` when it does
  not (checked atomically by the kernel). The output reports `previous` and
  `current`; `encoding` is that of the previous value.
* Tags are lowercased, may use letters, digits, `_`, `-` and `.`, and are
  stored sorted, comma-separated, in the `user.resh.tags` extended
  attribute; `tag.add`/`tag.rm` print `{"path":...,"tags":[...]}`. Removing
  the last tag removes the attribute. At least one tag is required.
* Extended attributes need a filesystem that supports them (`UNSUPPORTED`
  otherwise).

---

## 4. Best Practices

* Pass `data=` to `write` explicitly in scripts; never rely on stdin unless
  you pipe into it.
* Use `create=false` to avoid creating files by accident and keep
  `overwrite` off unless needed.
* Use `replace dry_run` or `backup=<suffix>` before editing configuration. The backup (`<file><suffix>`) is written to a new temporary file and renamed into place with the original's permission bits; an existing symlink at the backup name is refused and the replace fails without changing the file.
* Use SHA-256, SHA-512 or BLAKE3 for integrity checks; MD5 and SHA-1 are
  for compatibility only.
* Bound `find` with `max_depth`/`limit` and `grep` with `max`.
* Check the error code, not the message text, in scripts: exit 2 means
  nothing was done.
