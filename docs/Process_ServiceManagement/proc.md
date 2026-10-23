# Resource Shell (resh) – Proc Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using URI-based commands. The `proc://` handle sends signals to a running process and reads or changes its nice value, using the kernel's `kill`, `getpriority` and `setpriority` calls. It also has two verbs, `io.peek` and `limits.set`, that are of limited use in this release (see section 3).

### Purpose

The `proc` handle lets you:

* Send signals to a process, by name or number
* Read and change a process's nice value, directly or through a named priority class
* Read log files from the resh state directory (`io.peek`; nothing in resh writes these files)
* Report resource limits through `setrlimit` (`limits.set`; applies only to the short-lived resh process itself)

Every verb prints a single JSON object.

### Architectural Problem Addressed

`kill`, `renice` and `ulimit` each have their own syntax and text output. `proc` puts signals and nice values behind one URI form and returns JSON, so a script can check fields such as `ok`, `signal_num` or `nice` instead of parsing text.

### Resource-Oriented URI Model

```text
proc://<pid|self>.<verb> [key=value ...]
```

* **handle**: `proc://`
* **target**: a numeric process ID, or `self` (the resh process itself)
* **verb**: the operation; dotted verbs such as `nice.get` and `limits.set` are recognized as a whole
* **options**: `key=value` words after the stage

Examples:

```bash
resh proc://1234.term
resh proc://self.nice.get
resh proc://1234.signal sig=HUP
```

---

## 2. Design Philosophy and Core Principles

### Interface Model

Sixteen verbs:

| Group | Verbs |
| ----- | ----- |
| Signals | `signal`, `term`, `int`, `hup`, `kill`, `stop`, `cont`, `usr1`, `usr2` |
| Priority | `nice.get`, `nice.set`, `nice.inc`, `nice.dec`, `setPriority` |
| Limited | `io.peek`, `limits.set` |

Help: `resh proc --help` and `resh proc <verb> --help`.

### PID validation

The target must be `self` or a decimal PID from 1 to 2147483647. Zero, negative numbers, values above 2147483647, hex and anything non-numeric are rejected before any system call, with `Error: invalid pid: ...` and exit code 1. This means a PID can never address a process group or every process (`kill(-1, ...)`).

### Safety

* Signal and nice verbs act immediately. There is **no dry run** for them; `dry_run=true` is refused (exit 2) and nothing runs.
* Only `limits.set` reads `dry_run` (see below).
* The kernel enforces permissions: you can signal or renice only your own processes unless you are root, and lowering a nice value below its current value needs privilege.

### Timeouts

No `proc` verb has a timeout, and none reads `timeout_ms`. Signal and nice verbs make one system call and return. For `signal`, `nice.*`, `setPriority` and `io.peek` a `timeout_ms` argument is silently ignored. For `limits.set` any unrecognized argument, including `timeout_ms`, is treated as an unknown resource and makes the call fail (exit 1).

---

## 3. Command Syntax and Execution Model

### 3.1 Signal verbs

```bash
resh proc://1234.signal sig=TERM
resh proc://1234.signal sig=SIGHUP
resh proc://1234.signal sig=10
resh proc://1234.term
resh proc://1234.int
resh proc://1234.hup
resh proc://1234.kill
resh proc://1234.stop
resh proc://1234.cont
resh proc://1234.usr1
resh proc://1234.usr2
```

`signal` needs `sig=`. Accepted names (case-insensitive, with or without `SIG`): `HUP`, `INT`, `QUIT`, `KILL`, `TERM`, `STOP`, `CONT`, `USR1`, `USR2`, `PIPE`, `ALRM`, `CHLD`. A number is sent as given; the `signal` field then shows the Linux name for that number, or `UNKNOWN`.

Linux signal numbers for the fixed verbs and common names:

| Signal | Number (Linux) |
| ------ | -------------- |
| HUP | 1 |
| INT | 2 |
| QUIT | 3 |
| KILL | 9 |
| USR1 | 10 |
| USR2 | 12 |
| PIPE | 13 |
| ALRM | 14 |
| TERM | 15 |
| CHLD | 17 |
| CONT | 18 |
| STOP | 19 |

Output (shown with `--json-pretty`):

```json
{
  "ok": true,
  "pid": 1234,
  "signal": "TERM",
  "signal_num": 15,
  "verb": "signal"
}
```

On failure the same shape is printed with `"ok": false` and an `error` field, for example `"error": "process not found"`.

### 3.2 Priority verbs

```bash
resh proc://self.nice.get
resh proc://1234.nice.set value=5
resh proc://1234.nice.inc delta=1
resh proc://1234.nice.dec delta=1
resh proc://1234.setPriority class=background
resh proc://1234.setPriority nice=7
```

* `nice.get` → `{"nice": 0, "pid": 1234}`
* `nice.set value=<-20..19>` → `{"changed": true, "nice": 10, "pid": 1234}`. A value outside -20..19 is rejected.
* `nice.inc delta=<n>` raises the nice value (lower priority); `nice.dec delta=<n>` lowers it (higher priority). Output: `{"changed": true, "delta": 5, "nice_after": 5, "nice_before": 0, "pid": 1234}`. If the result would leave -20..19, nothing is changed and the call fails.
* `setPriority` sets the nice value from a class or from `nice=`:

  | Class | Nice value |
  | ----- | ---------- |
  | idle | 19 |
  | background | 10 |
  | normal (default) | 0 |
  | high | -5 |
  | realtime | -10 |

  `nice=` overrides `class=`. A `nice` value outside -20..19 is clamped into that range without an error. "realtime" is only a nice value of -10; it does not set a real-time scheduling policy.

  ```json
  {
    "backend": "linux-setpriority",
    "class": "background",
    "nice": 10,
    "pid": 1234,
    "previous_nice": 0
  }
  ```

### 3.3 io.peek (limited)

```bash
resh proc://1234.io.peek stream=stdout max_bytes=1024
resh proc://1234.io.peek stream=both
```

`io.peek` reads the tail of `<state_dir>/resh/proc/<pid>/stdout.log` and `stderr.log`, where `<state_dir>` is `$XDG_STATE_HOME` or `~/.local/state` (`/tmp` if neither can be determined). **Nothing in resh creates or writes these files.** `io.peek` does not capture a running process's output; it only returns data if something else wrote those files. For an ordinary process it fails with `log file not found` (exit 2).

Arguments: `stream=stdout|stderr|both` (default `stdout`), `max_bytes=<n>` (default 4096), `tail=<n>` (bytes read from the end; default `max_bytes`), `encoding=auto|utf8|base64` (default `auto`, which falls back to base64 for non-UTF-8 data), `json=true|false` (default true; `json=false` prints the raw data and is allowed only with `stream=stdout`).

```json
{
  "auto_fallback": false,
  "bytes_read": 26,
  "data": "worker started\nprocessing\n",
  "encoding": "utf8",
  "pid": 1234,
  "stream": "stdout",
  "truncated": false
}
```

With `stream=both` the per-stream fields are nested under `streams.stdout` and `streams.stderr`; a missing file appears as an `error` field inside that stream and the call still exits 0.

### 3.4 limits.set (not functional for other processes)

```bash
resh proc://self.limits.set nofile=4096 dry_run=true
```

`limits.set` calls `getrlimit`/`setrlimit`, which act on the calling process: **the resh process itself**, which exits immediately afterwards. It never changes the limits of the process in the URL or of the `pid=` argument. `pid=` is checked (it must be a positive integer) and echoed in the output, but it has no effect, and the `before` values in the output are resh's own limits. In practice the verb only shows what resh's current limits are and whether a requested value parses.

* Arguments are `<resource>=<soft>` or `<resource>=<soft>:<hard>` (either side may be empty to keep the current value). Resources: `cpu`, `as`, `data`, `stack`, `core`, `nofile`, `fsize`, `memlock`, `nproc`.
* Values: a number, `unlimited`, a number with an `s` suffix (seconds), or with `K`, `M` or `G` (powers of 1000).
* `dry_run` (true/false/1/0/yes/no/on/off, or a bare `dry_run` word) skips the `setrlimit` call. Any other `dry_run` value is an error.
* Every argument other than `pid` and `dry_run` is treated as a resource name; an unknown one is reported with `"status": "error"` and the call exits 1.

```json
{
  "backend": "rlimit",
  "pid": 41872,
  "results": {
    "nofile": {
      "after": { "hard": 524288, "soft": 4096 },
      "before": { "hard": 524288, "soft": 1024 },
      "requested": "4096",
      "status": "ok"
    }
  }
}
```

To set limits on another process, use a tool such as `prlimit(1)`.

---

## 3.5 Execution Semantics

### Output channels

`proc` writes its JSON (including error objects) to **stdout**, so a failing call still produces JSON on stdout. A one-line `Error: <reason>` also goes to stderr.

### Exit codes

Verified against `src/handles/processes/proch.rs`. Codes differ by verb:

| Verb(s) | Code | When |
| ------- | ---- | ---- |
| all | 0 | Success |
| all | 1 | Invalid PID in the URL (rejected before any system call) |
| signal verbs | 1 | Missing or unknown `sig`, or another `kill` failure |
| signal verbs | 3 | Process not found |
| signal verbs | 4 | Permission denied |
| `nice.get` | 1 | Any failure, including no such process or permission denied |
| `nice.set` | 2 | `value` missing or not an integer |
| `nice.set` | 3 | `value` outside -20..19 |
| `nice.set`, `nice.inc`, `nice.dec` | 4 | Permission denied while setting |
| `nice.set`, `nice.inc`, `nice.dec` | 1 | Other failures, including no such process |
| `nice.inc`, `nice.dec` | 2 | `delta` missing or not an integer |
| `nice.inc`, `nice.dec` | 3 | Result outside -20..19 |
| `setPriority` | 2 | `nice` is not an integer |
| `setPriority` | 3 | Unknown `class` |
| `setPriority` | 4 | No such process, permission denied, or another priority failure |
| `io.peek` | 3 | Invalid `stream`, `encoding`, `max_bytes`, `tail`, or `json=false` with a stream other than stdout |
| `io.peek` | 2 | Log file not found or unreadable (`stream=stdout` or `stderr`) |
| `limits.set` | 2 | `pid=` is not a positive integer |
| `limits.set` | 1 | Any resource failed (unknown name, bad value, soft above hard, `setrlimit` error) or invalid `dry_run` |

---

## 4. Functional Domains

### 4.1 Automation Utilities

* Graceful shutdown escalation: `term`, check the process, then `kill` if needed. Exit code 3 means the process is already gone.
* Lowering the priority of background jobs with `setPriority class=background`.

### 4.2 Data & State Management

`nice.get` reports a process's nice value. `proc` does not report process state, CPU, memory, command line or resource limits of other processes.

### 4.3 Filesystem & Storage

No file access except `io.peek`, which reads only files under the resh state directory (see 3.3).

### 4.4 Network & Remote Operations

Local only. There is no remote target.

### 4.5 Packages & Software

Can signal daemons after an update, for example `hup` to ask a daemon to reload its configuration (if that daemon treats SIGHUP that way). For managed services, prefer `svc://<name>.reload`.

### 4.6 Process & Service Management

`proc` works on single PIDs. Use `svc://` for services managed by systemd or OpenRC (its `status` output includes the main PID) and `cron://` for scheduled jobs.

### 4.7 Security & Secrets

* PIDs are range-checked so a value can never target a process group or all processes.
* Only signal processes you have identified; PIDs are reused by the kernel.
* Prefer TERM before KILL.
* Lowering nice values below their current value needs privilege.

### 4.8 System Information

Reports PID, nice value, previous nice value, priority class and signal number. Nothing else about the process is reported.

---

## 5. Platform Support

Linux only. The signal table and signal numbers are Linux's (for example USR1 is 10 and USR2 is 12). Nothing was built or tested on macOS, BSD or Windows.

---

## 6. Operational Best Practices

### Safe usage

* Send TERM before KILL and give the process time to clean up.
* Check that the PID is the process you expect before sending a signal.
* Do not rely on `limits.set` to restrict another process; it cannot.
* Do not rely on `io.peek` to see a process's output unless you arrange for the log files to be written.

### Automation

* Check the exit code; the JSON `ok` field is present on signal verbs.
* Handle exit code 3 from signal verbs as "process already gone".

### Example escalation

```bash
resh proc://1234.term
resh proc://1234.signal sig=0
resh proc://1234.kill
```

`sig=0` sends no signal but checks that the process exists (exit 3 if it does not).

---

## 7. Use Cases by Role

### DevOps Engineers

* Stop or pause (`stop`, `cont`) build or batch processes.
* Lower the priority of background tasks.

### SRE Engineers

* Escalate signals during incident response.
* Send `hup`, `usr1` or `usr2` to daemons that use them for reload or log rotation.

### Network Administrators

* Tune daemon priority with `nice.set` or `setPriority`.
* Pause and resume processes during maintenance.

### Automation Engineers

* Build escalation logic on the exit codes and JSON fields.

---

## 8. Technical Foundation

* Implemented in Rust in `src/handles/processes/proch.rs`.
* Signals use `libc::kill`; nice values use `getpriority`/`setpriority` with `PRIO_PROCESS`; `limits.set` uses `getrlimit`/`setrlimit` on the resh process.
* Each `resh` invocation is a separate process; nothing is kept between calls.
* Unknown argument names are ignored by every verb except `limits.set`, which treats them as resource names.
