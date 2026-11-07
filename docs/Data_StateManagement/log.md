# Resource Shell (resh) – Log Handle Documentation

## 1. Overview

Resource Shell (resh) is a command-line tool that runs operations on resources named by URLs.

The `log://` handle has one verb, `tail`. It prints the most recent lines of a plain-text log file, or of a systemd service's journal through `journalctl`, optionally keeping only the lines that contain a substring, and can keep printing new lines as they are written (`follow=true`). Output is the raw lines or a JSON object.

```text
resh log:///<absolute-path>.tail [lines=<n>] [pattern=<text>] [mode=raw|json]
  [follow=true|false] [timeout_ms=<ms>]
resh log://./<relative-path>.tail ...
resh log://../<relative-path>.tail ...
resh log://svc/<service>.tail ...
```

The verb is the text after the last dot, so `log:///var/log/app.log.tail` reads `/var/log/app.log`.

---

## 2. Design Notes

* Read-only: the handle never writes or rotates logs.
* Files are read backward from the end, so large files are not read in full. Memory stays bounded however long a line is (section 4.1).
* `pattern` is a case-sensitive substring match, not a regular expression.
* `follow=true` streams new lines as they are written, like `tail -F`: it survives truncation and rotation (section 4.3).
* `journalctl` is run directly (no shell), with each value in its own `--name=value` argument; the service name is validated first.

---

## 3. Command Syntax and Execution Model

### 3.1 Targets

| Target form             | Reads                                                         |
| ----------------------- | ------------------------------------------------------------- |
| `log:///var/log/syslog` | Absolute file path                                            |
| `log://./logs/app.log`  | Path relative to the current directory                        |
| `log://../logs/app.log` | Path relative to the parent of the current directory          |
| `log://svc/nginx`       | `journalctl --unit=nginx --lines=<lines> --no-pager --output=short` |

* The URL path is percent-decoded: `log:///var/log/my%20app.log` (or the quoted `'log:///var/log/my app.log.tail'`) reads `my app.log`. A path that decodes to a NUL byte is refused.
* Any other host (for example `log://var/log/syslog`) is refused with `log.invalid_target` (exit 2).
* A service name may contain only letters, digits and `: _ . @ - \`, is at most 256 bytes, and cannot start with `-` or `.`; anything else is refused with `log.invalid_target` (exit 2) before `journalctl` runs. Glob patterns are not accepted.

### 3.2 Arguments

Every argument is checked before anything is read. An unknown argument or an invalid value is refused with `log.invalid_argument` (exit 2), with a "did you mean" hint for a likely typo (`line=5` suggests `lines`).

| Argument     | Description                                         | Default |
| ------------ | --------------------------------------------------- | ------- |
| `lines`      | Number of lines to read from the end (1-1000000)    | `100`   |
| `pattern`    | Keep only lines containing this text (not empty)    | none    |
| `mode`       | `raw` or `json`                                     | `raw`   |
| `follow`     | `true` keeps printing new lines (`mode=raw` only); booleans are `true/false`, `1/0`, `yes/no`, `on/off` | `false` |
| `timeout_ms` | Time limit for the whole command (1-604800000)      | `600000` without `follow`; no limit with `follow` |

`dry_run=false` is accepted and changes nothing; `dry_run=true` is refused (exit 2), as `tail` only reads.

`pattern` is applied **after** the last `lines` lines are taken: `lines=50 pattern=ERROR` returns the matching lines among the last 50, not the last 50 matching lines. With `follow=true`, every new line is checked against `pattern`.

### 3.3 Example commands

```bash
resh log:///var/log/syslog.tail lines=10
resh log:///var/log/syslog.tail lines=500 pattern=ERROR mode=json
resh 'log:///var/log/syslog.tail(lines=10)'
resh log://./logs/app.log.tail lines=20
resh log://./logs/app.log.tail follow=true pattern=ERROR
resh log://./logs/app.log.tail follow=true timeout_ms=60000
resh log://svc/nginx.tail lines=50 pattern=error
resh log://svc/nginx.service.tail follow=true
```

### 3.4 Output

`mode=raw` prints the lines only. `mode=json` (shown with `--json-pretty`):

```json
{
  "lines": [
    "Oct 16 09:12:44 host kernel: eth0: link up",
    "Oct 16 09:13:02 host app[901]: error: disk quota exceeded"
  ],
  "path": "/var/log/syslog",
  "pattern": null,
  "requested_lines": 2,
  "returned_lines": 2
}
```

For `log://svc/<service>` the object has `service` in place of `path`. `path` is the path as given (relative paths stay relative).

On failure, `mode=json` prints an object with an `error` object, and the error line is written to stderr in both modes (nothing is printed on stdout with `mode=raw`):

```json
{
  "error": {
    "code": "log.not_found",
    "message": "log file does not exist: /tmp/missing.log"
  },
  "path": "/tmp/missing.log",
  "requested_lines": 10,
  "returned_lines": 0
}
```

```text
Error: [log.not_found] log file does not exist: /tmp/missing.log
```

An invalid argument is reported on stderr only (the options could not be read, so there is no JSON object).

### 3.5 Exit codes and error codes

| Exit | Meaning |
| ---- | ------- |
| 0    | Success (including an empty file, no matching lines, or no journal entries); also when the reader of a followed output goes away (for example `| head`) |
| 1    | The log could not be read (see the codes below) |
| 2    | Invalid usage: an unknown argument, an invalid value, an invalid target or an unknown verb; nothing was read |
| 124  | `timeout_ms` passed (`log.timeout`) |

| Code | Exit | When |
| ---- | ---- | ---- |
| `log.invalid_argument` | 2 | Unknown argument, invalid value, `follow=true` with `mode=json`, `dry_run=true` |
| `log.invalid_target` | 2 | Unsupported URL host, empty path, NUL byte in the path, invalid service name |
| `log.unknown_verb` | 2 | A verb other than `tail` (also for `--help=<verb>`) |
| `log.not_found` | 1 | The file does not exist |
| `log.not_a_file` | 1 | The path is a directory, FIFO, socket or device |
| `log.permission_denied` | 1 | The file cannot be opened or read for lack of permission |
| `log.read_failed` | 1 | Any other error opening or reading the file |
| `log.journalctl_not_found` | 1 | `journalctl` is not installed (not on `PATH`) |
| `log.journal_access_denied` | 1 | `journalctl` could not read the journal (it says the user is "not seeing messages from other users", or cites "insufficient permissions"), even if it exited 0 |
| `log.journal_failed` | 1 | `journalctl` could not be run, or exited with a non-zero status; its stderr is in the message |
| `log.timeout` | 124 | `timeout_ms` passed. Lines already printed stay printed; `journalctl` and anything it started is stopped |
| `log.failed` | 1 | The output could not be written (reported by resh itself) |

**Changed in this release:** a missing file or a path that is not a file now exits 1 (was 2); a failing `journalctl` exits 1 (was its own exit status); unknown arguments and invalid values (`lines=abc`, `lines=0`, `mode=xml`, an empty `pattern`) are refused with exit 2 (`lines=abc` used to mean 100); the JSON `error` is an object with `code` and `message` (was a string); a raw-mode error is no longer printed on stdout.

---

## 4. Verb: tail

### 4.1 Files

* The file is scanned backward from its end in 64 KiB steps, keeping only the positions of newlines, until `lines` lines are found; then each line is read. A huge file is not read in full and the scan is bounded by `timeout_ms`.
* Lines are split on `\n`; a `\r` before it is dropped. Multi-line log entries are not grouped. A final line without a newline counts as a line.
* Invalid UTF-8 is replaced with U+FFFD, whatever the file size.
* A line longer than 1 MiB (1048576 bytes) is cut to its first 1 MiB, and a warning on stderr says how many lines were cut. The exit status is not changed.
* Only regular files are read. A directory, FIFO, socket or device is refused with `log.not_a_file` (a FIFO is opened without blocking, so the command does not hang).

### 4.2 Service journals

`log://svc/<service>` runs `journalctl --unit=<service> --lines=<lines> --no-pager --output=short` (with `--follow` added for `follow=true`). It needs systemd's `journalctl` and permission to read the journal (often membership in the `systemd-journal` or `adm` group). `journalctl` exits 0 even when it cannot see the system journal; the handle reports that as `log.journal_access_denied` instead of an empty result. When no entry matches, the result is empty (journalctl's `-- No entries --` line is not returned as a log line).

Without `follow`, `journalctl` runs under the process deadline (`timeout_ms`, default 600000): at the deadline, it and anything it started is stopped and the command exits 124 (`log.timeout`). Its output is captured up to 64 MiB.

```bash
resh log://svc/postgresql.tail lines=30 mode=json
```

### 4.3 Follow mode

`follow=true` prints the last `lines` lines (filtered by `pattern`) and then every new line as it is written, flushing each line at once, so it can be piped into other tools. It works with `mode=raw` only (`mode=json` is refused with exit 2).

* **Files** are checked for new data every 100 ms.
  * A file truncated in place (shorter than what was read) is read again from the start, with a warning on stderr.
  * A file replaced at its path (rotated by rename and re-create) is read to its end, then the new file is followed from its start, with a warning on stderr. While nothing exists at the path, the old file is still followed.
  * A last line still being written (no newline yet) is printed once it is complete, or when the command stops.
* **Service journals** run `journalctl --follow` and stream its output. If `journalctl` exits on its own, the command ends with its result. If `resh` is killed, `journalctl` is told to stop too.

Without `timeout_ms`, follow mode runs until interrupted (Ctrl-C) or until the reader of its output goes away (exit 0). With `timeout_ms`, it stops at the deadline: the lines already printed stay printed and the exit status is 124 (`log.timeout`), so a script can tell a time limit from an error.

```bash
resh log://./logs/app.log.tail follow=true lines=1 pattern=ERROR timeout_ms=30000
```

### 4.4 Counting matches in a script

```bash
ERROR_COUNT=$(resh log:///var/log/app.log.tail lines=1000 pattern=ERROR mode=json | jq '.returned_lines')
```

### 4.5 timeout_ms

`timeout_ms` bounds the whole command: the file scan, the `journalctl` run, and follow mode. Without `follow` the default is 600000 (10 minutes); with `follow` there is no default limit. Reaching it exits 124 with `log.timeout`.

---

## 5. Limitations

* A file whose name contains a literal `%` followed by two hex digits must be written percent-encoded (`%25`), since the path is percent-decoded.
* Follow mode polls files every 100 ms rather than using inotify. A file truncated and refilled past the previous size between two checks is not seen as truncated.
* With `follow=true`, `journalctl --follow` shows only entries of the current boot (systemd's own behavior), so `lines` may return fewer old lines than without `follow`.
* Service names cannot be glob patterns, and there are no time-range or priority filters.
* No regular expressions.

---

## 6. Platform Support

Linux is the only supported and tested platform. `log://svc/...` needs systemd's `journalctl`; on systems without systemd (for example OpenRC) only file logs work.

---

## 7. Usage Guidance

* Always set `lines` in automation, and make it large enough for `pattern` to find matches (section 3.2).
* Use `mode=json` with `jq` for scripts.
* Use absolute paths for system logs.
* Give follow mode a `timeout_ms` in scripts, and treat exit 124 as "time is up".
* For anything beyond substring filtering, pipe raw output into `grep`, `awk` or similar tools.

---

## 8. Implementation Notes

* Written in Rust (`src/handles/data/logh.rs`, `logh/scan.rs`, `logh/journal.rs`).
* `journalctl` is run directly (no shell) in its own process group, with the service name passed as `--unit=<name>` so it can never be read as another option.
* Tests: unit tests in `src/handles/data/logh/tests.rs` (a fake `journalctl`), binary tests in `tests/log_verbs.rs`, and real journal queries in a container in `tests/log_e2e_docker.rs` (`cargo test --features e2e-docker --test log_e2e_docker`).
