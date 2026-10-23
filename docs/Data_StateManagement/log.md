# Resource Shell (resh) – Log Handle Documentation

## 1. Overview

Resource Shell (resh) is a command-line tool that runs operations on resources named by URLs.

The `log://` handle has one verb, `tail`. It prints the most recent lines of a plain-text log file, or of a systemd service's journal through `journalctl`, optionally keeping only the lines that contain a substring. Output is the raw lines or a JSON object.

```text
resh log:///<absolute-path>.tail [lines=<n>] [pattern=<text>] [mode=raw|json]
resh log://./<relative-path>.tail ...
resh log://svc/<service>.tail ...
```

The verb is the text after the last dot, so `log:///var/log/app.log.tail` reads `/var/log/app.log`.

---

## 2. Design Notes

* Read-only: the handle never writes or rotates logs.
* Files are read backward from the end, so large files are not read in full.
* `pattern` is a case-sensitive substring match, not a regular expression.
* There is no follow mode (`tail -f`); each command prints once and exits.

---

## 3. Command Syntax and Execution Model

### 3.1 Targets

| Target form            | Reads                                                     |
| ---------------------- | --------------------------------------------------------- |
| `log:///var/log/syslog` | Absolute file path                                       |
| `log://./logs/app.log` | Path relative to the current directory                    |
| `log://svc/nginx`      | `journalctl -u nginx -n <lines> --no-pager -o short`      |

Any other host (for example `log://var/log/syslog`) is rejected.

### 3.2 Arguments

| Argument  | Description                           | Default |
| --------- | ------------------------------------- | ------- |
| `lines`   | Number of lines to read from the end  | 100     |
| `pattern` | Keep only lines containing this text  | none    |
| `mode`    | `raw` or `json`                       | `raw`   |

`pattern` is applied **after** the last `lines` lines are taken: `lines=50 pattern=ERROR` returns the matching lines among the last 50, not the last 50 matching lines.

### 3.3 Example commands

```bash
resh log:///var/log/syslog.tail lines=10
resh log:///var/log/syslog.tail lines=500 pattern=ERROR mode=json
resh 'log:///var/log/syslog.tail(lines=10)'
resh log://./logs/app.log.tail lines=20
resh log://svc/nginx.tail lines=50 pattern=error
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

For `log://svc/<service>` the object has `service` in place of `path`.

Missing file in `mode=json`:

```json
{
  "error": "Log file does not exist: /tmp/missing.log",
  "path": "/tmp/missing.log",
  "requested_lines": 10,
  "returned_lines": 0
}
```

### 3.5 Exit codes

These codes are set by the handle (verified in the source):

| Code | Meaning                                                            |
| ---- | ------------------------------------------------------------------ |
| 0    | Success (including an empty file or no matching lines)             |
| 2    | `lines=0`, an invalid `mode`, a missing file, or a path that is not a file |
| other | For `log://svc/...`, the exit code of a failing `journalctl`     |

Other failures, such as a file that cannot be opened because of permissions, exit 1.

---

## 4. Verb: tail

### 4.1 Files

* Files smaller than 64 KiB are read whole; larger files are read backward in 8 KiB chunks until enough lines are found.
* Lines are split on newlines; multi-line log entries are not grouped.
* In files of 64 KiB or more, invalid UTF-8 is replaced with U+FFFD. In smaller files, invalid UTF-8 makes the command fail.

### 4.2 Service journals

`log://svc/<service>` runs `journalctl -u <service> -n <lines> --no-pager -o short`. It needs systemd's `journalctl` and permission to read the journal (often membership in the `systemd-journal` or `adm` group). If `journalctl` fails, its error is reported (in the JSON object with `mode=json`, otherwise on stderr).

```bash
resh log://svc/postgresql.tail lines=30 mode=json
```

### 4.3 Counting matches in a script

```bash
ERROR_COUNT=$(resh log:///var/log/app.log.tail lines=1000 pattern=ERROR mode=json | jq '.returned_lines')
```

### 4.4 timeout_ms

`tail` does not read `timeout_ms`; it is ignored if given. A `journalctl` call has no time limit.

---

## 5. Limitations

* **The URL path is not percent-decoded.** A file whose name contains a space or another character that URLs encode (for example `my app.log`) cannot be read, because the handle looks for `my%20app.log`. Use a symlink with a plain name.
* Relative paths cannot reach the parent directory: leading `..` components are dropped, so `log://../x.log` reads `./x.log`. Use an absolute path instead.
* A non-numeric `lines` value (for example `lines=abc`) is silently replaced by 100.
* In a boundary case on files of 64 KiB or more, the first returned line can be cut off at the start (when the backward scan stops exactly at the requested number of newlines in the middle of a line).
* In `mode=raw`, a missing-file error is printed to stdout as `Error: ...` (and again to stderr by resh).
* No regular expressions, no follow mode, no time-range filters.

---

## 6. Platform Support

Linux is the only supported and tested platform. `log://svc/...` needs systemd's `journalctl`; on systems without systemd (for example OpenRC) only file logs work.

---

## 7. Usage Guidance

* Always set `lines` in automation, and make it large enough for `pattern` to find matches (section 3.2).
* Use `mode=json` with `jq` for scripts.
* Use absolute paths for system logs.
* For anything beyond substring filtering, pipe raw output into `grep`, `awk` or similar tools.

---

## 8. Implementation Notes

* Written in Rust. `journalctl` is run directly (no shell), with the service name passed as a separate argument.
