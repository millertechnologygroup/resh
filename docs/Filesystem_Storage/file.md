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
  work too (`file://src.find`).
* URL parsing lowercases the first segment of a relative path and drops a
  leading `localhost`, so write `file://./Report.txt.read` for a mixed-case
  relative name.

Help: `resh file --help`, `resh file <verb> --help`, or the `help`/`h` verb.

### Exit status

0 on success. On failure the exit code is non-zero; the handle uses 1, 2 or
3 depending on the verb and error (for example 2 for "file does not exist"
in several verbs, 3 for a permission error in `write`/`append`). The codes
are not consistent across verbs, so treat any non-zero code as failure and
read the message on stderr (`Error: <reason>`). `grep` exits 1 when there
are no matches.

### timeout_ms

Only `watch` reads `timeout_ms` (default 30000; it stops after that many
milliseconds and exits 0; `timeout_ms=0` means no time limit, so it waits
until `max_events` events have arrived). Every other verb ignores
it, including `tail follow=true`, which runs until interrupted.

---

## 3. Verbs

### 3.1 Reading and inspection

| Verb      | Arguments | Output |
| --------- | --------- | ------ |
| `read`    | – | Raw file contents |
| `exists`  | – | `{"exists":true,"kind":"file","path":...}` |
| `stat`    | `nofollow=true` | JSON: `file_type`, `size`, `mode`, `uid`, `gid`, `readonly`, `accessed`, `modified`, `created` |
| `preview` | `max_bytes`, `max_lines`, `mode=auto\|text\|binary`, `encoding=base64\|hex`, `include_metadata` | JSON sample |
| `summary` | `max_bytes` | JSON: size, mtime, content type, line stats (entry count for directories) |
| `analyze` | `max_bytes` | JSON: `ascii_ratio`, `entropy`, `line_count`, `classification` |
| `schema`  | `format=json\|ndjson\|csv\|tsv\|text`, `max_bytes`, `max_rows` | JSON structure report |
| `tail`    | `lines` (default 10) or `bytes`, `follow=true\|false` | Raw lines |

```bash
resh file:///etc/hostname.read
resh --json-pretty file:///etc/hosts.stat
resh file://./logs/app.log.tail lines=50
resh --json-pretty file:///srv/data/users.csv.schema
```

### 3.2 Searching

| Verb   | Arguments |
| ------ | --------- |
| `grep` | `pattern` (required), `regex`, `ignore_case`, `invert`, `max` (stop after n matches), `before`, `after`, `format=text\|json`, `line_numbers` |
| `find` | `name=<glob>`, `type=file\|dir\|symlink`, `max_depth`, `limit`, `include_hidden`, `follow_symlinks` |

```bash
resh file:///var/log/app.log.grep pattern=error ignore_case=true max=20
resh --json-pretty file:///srv/www.find name='*.html' type=file max_depth=3
```

The match limit for `grep` is `max`; there is no `max_count` argument (it is
ignored). `find` prints a JSON array of entries with absolute paths.

Limitation: `find include_hidden=false` hides dot-files and dot-directories
themselves but still descends into hidden directories, so files inside
them (for example `.git/config`) are listed.

### 3.3 Watching

```bash
resh file:///etc/nginx/nginx.conf.watch events=modify timeout_ms=60000
resh file://./incoming.watch max_events=1
```

Arguments: `timeout_ms` (default 30000), `max_events` (default 1),
`events=create,modify,remove,rename` (default all). `watch` stops at the
first of the two limits, so by default it returns after one event or 30
seconds. Each event is printed as one line of JSON. The path is watched
non-recursively.

### 3.4 Hashing and verification

| Verb | Arguments | Algorithms |
| ---- | --------- | ---------- |
| `md5`, `sha1`, `sha256`, `sha512` | – | fixed |
| `hash` | `algo` (default `sha256`) | `sha256`, `sha512`, `blake3` |
| `verify` | `algo` (default `sha256`), `expected=<hex>`, `expected_any=<hex>;<hex>...`, `size=<bytes>` | `sha256`, `sha1`, `md5`, `blake3` |

`hash` does not accept `md5` or `sha1`; `verify` does not accept `sha512`.
An unsupported algorithm fails with exit code 2. Files larger than 10 GiB
are refused by the hashing functions. `verify` prints a JSON report and
fails (non-zero) on a mismatch.

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
| `replace` | `pattern`, `replacement` (required), `regex`, `count`, `dry_run`, `backup=<suffix>` |

```bash
resh file:///tmp/greeting.txt.write data='hello world'
resh file:///var/tmp/jobs.log.append data='job finished'
resh --json-pretty file:///etc/app.conf.replace pattern=8080 replacement=9090 dry_run
```

`write` replaces the file atomically (temporary file plus rename) and
prints `{"bytes":...,"path":...,"written":true}`.

**`write` and `append` without `data=` read standard input until EOF.**
If standard input is empty (for example `< /dev/null`, or a non-interactive
job with no input), `write` truncates the file to 0 bytes and still reports
success. Always pass `data=` unless you mean to pipe content in:

```bash
printf 'line\n' | resh file:///tmp/out.txt.write
```

`replace` rewrites the file atomically; `dry_run` reports the replacement
count without changing it.

### 3.6 Copying, moving, deleting

| Verb | Arguments |
| ---- | --------- |
| `copy` | `to` (required), `overwrite`, `preserve_mode` (default `true`) |
| `rename` | `to` (required), `overwrite`, `create_parents`, `atomic` (default `true`) |
| `move` / `mv` | `to` (required), `overwrite`; moves into `to` when it is an existing directory |
| `delete` / `remove` | `recursive`, `force`, `missing_ok` |

```bash
resh file:///etc/nginx/nginx.conf.copy to=/etc/nginx/nginx.conf.bak
resh --json-pretty file:///srv/data/old.csv.rename to=/srv/data/new.csv
resh file:///tmp/report.pdf.move to=/srv/reports
resh file:///tmp/build.cache.delete recursive=true
```

* `copy` only copies regular files. `preserve_times` is accepted but not
  implemented (it prints a warning and the copy keeps the current time).
* `to=` may be absolute, relative (`backup/new.txt`) or a bare name
  (`to=new.txt`), which is relative to the working directory. A missing
  parent directory fails with "destination parent does not exist" unless
  `create_parents=true` (rename only).
* `rename overwrite=true` checks the destination's parent first, then
  deletes an existing destination and renames. If the final rename itself
  fails (for example across filesystems with `atomic=true`), the deleted
  destination is not restored.
* `delete` refuses `/`; a directory needs `recursive=true`. `force=true` or
  `missing_ok=true` make a missing path succeed.

### 3.7 Permissions, ownership, attributes, tags

| Verb | Arguments |
| ---- | --------- |
| `chmod` | `mode=<octal>` (required) |
| `chown` | `user`, `uid`, `group`, `gid`, `recursive` |
| `ea.get` | `name` (required), `allow_missing` |
| `ea.set` | `name`, `value` (required), `mode=create\|update\|upsert` |
| `tag.add` | `name=<tag>[,<tag>...]` |
| `tag.rm` | `name=<tag>[,<tag>...]` |

```bash
resh file:///usr/local/bin/backup.sh.chmod mode=755
resh file:///srv/www.chown user=alice group=www recursive=true
resh --json-pretty file:///srv/data/report.pdf.ea.get name=user.comment
resh --json-pretty file:///srv/data/report.pdf.tag.add name=work,q3
```

Tags are lowercased and stored, comma-separated, in the `user.resh.tags`
extended attribute; `tag.add`/`tag.rm` print `{"path":...,"tags":[...]}`.
Extended attributes need a filesystem that supports `user.*` attributes.

---

## 4. Boolean arguments

`overwrite` (copy, move), `recursive` (delete, chown), `force` (delete) and
`dry_run` (replace) accept `true/false/1/0/yes/no/on/off` and reject other
values. Some other booleans are looser: `write`/`append` `create` is false
only for the exact string `false`; `stat nofollow` is true only for `true`;
`missing_ok` and `preserve_mode` accept `true/1/yes` as true and anything
else as false.

---

## 5. Best Practices

* Pass `data=` to `write` explicitly in scripts; never rely on stdin unless
  you pipe into it.
* Use `create=false` to avoid creating files by accident and keep
  `overwrite` off unless needed.
* Use `replace dry_run` or `backup=<suffix>` before editing configuration. The backup (`<file><suffix>`) is written to a new temporary file and renamed into place with the original's permission bits; an existing symlink at the backup name is refused and the replace fails without changing the file.
* Use SHA-256, SHA-512 or BLAKE3 for integrity checks; MD5 and SHA-1 are
  for compatibility only.
* Bound `find` with `max_depth`/`limit` and `grep` with `max`.
