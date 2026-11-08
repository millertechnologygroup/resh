# Resource Shell (resh) – Proc Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using URI-based commands. The `proc://` handle sends signals to a running process, reads or changes its nice value, and sets its resource limits, using the kernel's `kill`, `getpriority`, `setpriority` and `prlimit` calls. It can also read output log files kept for a process in the resh state directory (`io.peek`; nothing in resh writes them, see 3.3).

### Purpose

The `proc` handle lets you:

* Send signals to a process, by name or number
* Read and change a process's nice value, directly or through a named priority class
* Set a process's soft and hard resource limits (`limits.set`, through `prlimit`)
* Read log files from the resh state directory (`io.peek`; nothing in resh writes these files)

Every verb prints a single JSON object (`io.peek json=false` prints the data alone).

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
| Limits | `limits.set` |
| Logs | `io.peek` |

Help: `resh proc --help` and `resh proc <verb> --help`.

### PID validation

The target must be `self` or a decimal PID from 1 to 2147483647. Zero, negative numbers, values above 2147483647, hex and anything non-numeric are rejected before any system call with `proc.invalid_target` and exit code 2. This means a PID can never address a process group or every process (`kill(-1, ...)`). `limits.set pid=` is checked the same way (`proc.invalid_argument`).

### Strict arguments

Every verb accepts only the options in its usage (see each verb's `--help`). An unknown argument, a misspelled one (with a "did you mean" hint), `timeout_ms`, `dry_run` on a verb other than `limits.set`, a missing required argument, or an invalid value is refused with `proc.invalid_argument` and exit code 2 before any system call is made. **Breaking change:** earlier releases ignored unknown arguments on every verb except `limits.set`.

### Safety

* Signal and nice verbs act immediately. There is **no dry run** for them; `dry_run=true` is refused (exit 2) and nothing runs.
* Only `limits.set` has a dry run (`dry_run=true`): it reads the target's current limits, checks the request and reports what it would set, without changing anything.
* The kernel enforces permissions: you can signal or renice only your own processes unless you are root, and lowering a nice value below its current value needs privilege.

### Timeouts

No `proc` verb waits: signal, nice and limit verbs make a few system calls and return, and `io.peek` reads at most 16 MiB of one regular file (a FIFO or device is refused without blocking). So no verb takes `timeout_ms`; passing it is refused (exit 2, `proc.invalid_argument`).

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

`signal` needs `sig=`. Accepted names (case-insensitive, with or without `SIG`): `HUP`, `INT`, `QUIT`, `KILL`, `TERM`, `STOP`, `CONT`, `USR1`, `USR2`, `PIPE`, `ALRM`, `CHLD`. A number from 0 to the highest real-time signal (`SIGRTMAX`, 64 on Linux) is sent as given; the `signal` field then shows the Linux name for that number, `NULL` for 0, `RTMIN+<n>` for a real-time signal, or `UNKNOWN` (32 and 33, reserved by the C library). Any other name or number is refused (exit 2) and nothing is sent. The fixed verbs (`term` ... `usr2`) take no arguments.

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

On failure the same shape is printed with `"ok": false` and an `error` object, for example `"error": {"code": "proc.not_found", "message": "no process with pid 1234"}`.

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
* `nice.set value=<-20..19>` → `{"changed": true, "nice": 10, "pid": 1234}`. `changed` is false when the process already had that value (nothing is set then). A value outside -20..19 is refused (exit 2).
* `nice.inc delta=<0..39>` raises the nice value (lower priority); `nice.dec delta=<0..39>` lowers it (higher priority). Output: `{"changed": true, "delta": 5, "nice_after": 5, "nice_before": 0, "pid": 1234}`. If the result would leave -20..19, nothing is changed and the call is refused (exit 2, `proc.invalid_argument`). A negative delta is refused; use the other verb.
* Lowering a nice value below its current value needs `CAP_SYS_NICE` (root) unless the target process's `RLIMIT_NICE` allows it (a soft limit of `n` allows nice values down to `20 - n`); otherwise the call fails with `proc.permission_denied` (exit 1) and nothing changes.
* On Linux the nice value belongs to a thread: these verbs (like `renice`) change the thread whose ID is the PID, which is the main thread. Other threads of a multi-threaded process keep their values.
* `setPriority` sets the nice value from a class or from `nice=`:

  | Class | Nice value |
  | ----- | ---------- |
  | idle | 19 |
  | background | 10 |
  | normal (default) | 0 |
  | high | -5 |
  | realtime | -10 |

  `nice=` overrides `class=` (`class` is still checked). A `nice` value outside -20..19 is refused (exit 2); earlier releases clamped it silently. With `nice=`, `class` in the output is the class with that value, or `custom`. "realtime" is only a nice value of -10; it does not set a real-time scheduling policy.

  ```json
  {
    "backend": "linux-setpriority",
    "class": "background",
    "nice": 10,
    "pid": 1234,
    "previous_nice": 0
  }
  ```

### 3.3 io.peek

```bash
resh proc://1234.io.peek stream=stdout max_bytes=1024
resh proc://1234.io.peek stream=both
```

`io.peek` reads the tail of `<state_dir>/resh/proc/<pid>/stdout.log` and `stderr.log`, where `<state_dir>` is `$XDG_STATE_HOME` or `~/.local/state`. If neither `XDG_STATE_HOME` nor `HOME` gives a directory the call fails (`proc.failed`); it never falls back to a shared directory such as `/tmp`. **Nothing in resh creates or writes these files.** `io.peek` does not capture a running process's output; it only returns data if something else (a supervisor script, a redirect) wrote those files. For an ordinary process it fails with `proc.log_not_found` (exit 1).

Arguments:

* `stream=stdout|stderr|both` (default `stdout`)
* `max_bytes=<1..16777216>` (default 4096) and `tail=<1..16777216>` (default `max_bytes`): the last `min(tail, max_bytes)` bytes of the file are returned
* `encoding=auto|utf8|base64` (default `auto`, which uses base64, with `auto_fallback: true`, when the data is not valid UTF-8; `utf8` replaces invalid bytes with U+FFFD). A cut at the start of the tail can split a multi-byte character, which makes `auto` fall back to base64.
* `json=true|false` (default true; any of `true/false/1/0/yes/no/on/off`). `json=false` prints only the `data` text (already encoded) and is allowed only with `stream=stdout`.

`bytes_read` is the number of bytes returned; `truncated` is true when the file holds more than that. Only regular files are read: a FIFO, device or directory at the log path is refused (`proc.failed`) without blocking on it. An unreadable file is `proc.permission_denied`.

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

With `stream=both` the per-stream fields are nested under `streams.stdout` and `streams.stderr`. A stream that cannot be read appears as `{"error": {"code", "message"}}` inside `streams`; the other stream is still shown, and the call fails with that stream's code (exit 1). Earlier releases exited 0 in that case.

### 3.4 limits.set

```bash
resh proc://1234.limits.set nofile=4096
resh proc://1234.limits.set nofile=1024:4096 core=0 dry_run=true
resh proc://self.limits.set pid=1234 cpu=60s
```

`limits.set` reads and changes the limits of the target process with `prlimit(2)`. The target is the PID in the URL, or `pid=<n>` (useful with `proc://self`; with a numeric URL, `pid=` must name the same PID). `proc://self` is the resh process itself, which exits right after the call, so changing it has no lasting effect.

* Arguments are `<resource>=<soft>`, `<resource>=<soft>:<hard>` or `<resource>=:<hard>` (an empty side keeps the current value). Resources: `cpu`, `as`, `data`, `stack`, `core`, `nofile`, `fsize`, `memlock`, `nproc`. At least one is required.
* Values: a number, `unlimited`, a number with an `s` suffix (seconds; `cpu` only), or with `K`, `M` or `G` (powers of 1000). A number too large to be a limit is refused (use `unlimited`).
* `dry_run` (true/false/1/0/yes/no/on/off, or a bare `dry_run` word) reads the current limits and reports the result, but changes nothing. Any other `dry_run` value is refused.
* Any other argument is refused (exit 2) with a "did you mean" hint. Earlier releases reported it as an unknown resource (exit 1).

Order of work: all arguments are checked first, then the current limits of every requested resource are read and the new soft and hard values worked out. A soft limit above the hard limit is refused (exit 2) before anything changes. Then the resources are set one at a time in the order listed above. If one fails (for example raising a hard limit without `CAP_SYS_RESOURCE`: `proc.permission_denied`), the ones before it stay set, it has `"status": "error"` with an `error` object, the ones after it are not attempted (`"status": "skipped"`), and the call exits 1 with that resource's error code.

Permissions: an unprivileged user can change the limits of their own processes and lower hard limits; raising a hard limit, or changing another user's process, needs `CAP_SYS_RESOURCE` (root).

```json
{
  "backend": "prlimit",
  "dry_run": false,
  "pid": 1234,
  "results": {
    "nofile": {
      "after": { "hard": 524288, "soft": 4096 },
      "before": { "hard": 524288, "soft": 1024 },
      "changed": true,
      "requested": "4096",
      "status": "ok"
    }
  }
}
```

`unlimited` is shown as 18446744073709551615 (`RLIM_INFINITY`). `changed` is false when the limit already had the requested value (nothing is set then). Earlier releases called `setrlimit` on the resh process itself and only echoed `pid`; the backend was named `rlimit`.

---

## 3.5 Execution Semantics

### Output channels

`proc` writes its JSON to **stdout**, including on failure: the failure object has `pid`, `verb`, `"ok": false` and `"error": {"code": "proc.<code>", "message": "..."}` (plus the verb's partial results, such as `results` for `limits.set` or `streams` for `io.peek stream=both`). One line `Error: [proc.<code>] proc <verb>: <message>` goes to stderr.

### Exit codes and error codes

Exit codes: 0 success; 1 the operation failed (`proc.not_found`, `proc.permission_denied`, `proc.log_not_found`, `proc.failed`, `proc.unsupported_platform`); 2 invalid usage, nothing was done (`proc.invalid_argument`, `proc.invalid_target`). No verb exits 124. **Breaking change:** earlier releases used exit 3 for "process not found", exit 4 for permission errors, exit 3 for invalid `nice`/`class`/`io.peek` values, and exit 2 for a missing `io.peek` log.

| Code | Exit | When |
| ---- | ---- | ---- |
| `proc.invalid_argument` | 2 | Unknown verb or argument, `timeout_ms`, `dry_run` on a verb other than `limits.set`, a missing `sig`/`value`/`delta` or `limits.set` resource, an invalid value (signal name or number, nice value, delta, class, stream, encoding, size, boolean, limit value, `pid=`), a nice result outside -20..19 (`nice.inc`, `nice.dec`), a soft limit above the hard limit, or `pid=` different from the URL's PID. |
| `proc.invalid_target` | 2 | The target is not `self` or a PID from 1 to 2147483647. |
| `proc.not_found` | 1 | No process has that PID (`ESRCH`). |
| `proc.permission_denied` | 1 | The kernel refused (`EPERM`/`EACCES`): another user's process, lowering a nice value, raising a hard limit; or an `io.peek` log file that cannot be read. |
| `proc.log_not_found` | 1 | `io.peek`: the log file does not exist. |
| `proc.failed` | 1 | Any other system call failure (for example a limit above the kernel's maximum, `EINVAL`), an `io.peek` log path that is not a regular file, or no state directory. |
| `proc.unsupported_platform` | 1 | Not Linux: the system calls are implemented for Linux only. |

------- | ---- | ---- |
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

* Graceful shutdown escalation: `term`, check the process, then `kill` if needed. Error code `proc.not_found` (exit 1) means the process is already gone.
* Lowering the priority of background jobs with `setPriority class=background`.

### 4.2 Data & State Management

`nice.get` reports a process's nice value; `limits.set dry_run=true` reports its current limits for the resources named. `proc` does not report process state, CPU, memory or command line.

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
* Lowering nice values below their current value, raising a hard limit, and acting on another user's process need privilege (`CAP_SYS_NICE`, `CAP_SYS_RESOURCE`, `CAP_KILL`).

### 4.8 System Information

Reports PID, nice value, previous nice value, priority class, signal number and resource limits. Nothing else about the process is reported.

---

## 5. Platform Support

Linux only. The signal table and signal numbers are Linux's (for example USR1 is 10 and USR2 is 12). Nothing was built or tested on macOS, BSD or Windows.

---

## 6. Operational Best Practices

### Safe usage

* Send TERM before KILL and give the process time to clean up.
* Check that the PID is the process you expect before sending a signal.
* `limits.set` changes a running process; a child it starts later inherits the limits it has then.
* Do not rely on `io.peek` to see a process's output unless you arrange for the log files to be written.

### Automation

* Check the exit code and, on failure, `error.code` in the JSON (or the `[proc.<code>]` on stderr).
* Handle `proc.not_found` from signal verbs as "process already gone".

### Example escalation

```bash
resh proc://1234.term
resh proc://1234.signal sig=0
resh proc://1234.kill
```

`sig=0` sends no signal but checks that the process exists (`proc.not_found`, exit 1, if it does not).

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
* Signals use `libc::kill`; nice values use `getpriority`/`setpriority` with `PRIO_PROCESS`; `limits.set` uses `prlimit` on the target process.
* Each `resh` invocation is a separate process; nothing is kept between calls.
* Every verb refuses arguments it does not take (see "Strict arguments" in section 2).
