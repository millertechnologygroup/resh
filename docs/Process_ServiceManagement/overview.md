# Resource Shell (resh) – Process & Service Management Overview Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using URI-based commands. This category has three handles for the local host:

| Handle | Purpose | Detailed documentation |
| ------ | ------- | ---------------------- |
| `cron://` | Scheduled jobs as crontab entries or systemd timers | [cron.md](cron.md) |
| `proc://` | Signals and nice values for a single process | [proc.md](proc.md) |
| `svc://` | System services through systemd or OpenRC | [svc.md](svc.md) |

### Purpose

These handles let you:

* List, add, remove, enable and disable scheduled jobs
* Send signals to processes and change their nice values
* Start, stop, restart, reload, enable and disable services, and read their state and logs

Most verbs print a JSON object. Exceptions: `svc ... .logs` prints plain log lines, and `svc` `reload`, `enable`, `disable`, `mask` and `unmask` print nothing on success. `cron` verbs accept `format=text` for a text summary.

### Architectural Problem Addressed

`crontab`, `kill`, `renice`, `systemctl` and `rc-service` each have their own syntax and text output. These handles give one URI form and JSON output, so scripts can check fields and exit codes instead of parsing text.

### Resource-Oriented URI Model

```text
<scheme>://<target>.<verb> [key=value ...]
```

* **scheme**: `cron`, `proc` or `svc`
* **target**: a label for `cron` (ignored; always the local host), a PID or `self` for `proc`, a service name for `svc`
* **verb**: the operation, after the last dot (dotted verbs such as `nice.get` are recognized as a whole)
* **options**: `key=value` words after the stage; quote values with spaces

Examples:

```bash
resh cron://local.list
resh proc://1234.nice.get
resh svc://nginx.restart
```

---

## 2. Design Philosophy and Core Principles

### Interface Model

* Each domain has its own handle and its own verbs:
  * `cron`: `list`, `add`, `rm`, `enable`, `disable`
  * `proc`: `signal`, `term`, `int`, `hup`, `kill`, `stop`, `cont`, `usr1`, `usr2`, `nice.get`, `nice.set`, `nice.inc`, `nice.dec`, `setPriority`, `io.peek`, `limits.set`
  * `svc`: `status`, `is-enabled`, `start`, `stop`, `restart`, `reload`, `enable`, `disable`, `mask`, `unmask`, `wait`, `logs`, `scale`
* Help for any handle or verb: `resh <handle> --help`, `resh <handle> <verb> --help`.

### Safety

* `cron` `add`, `rm`, `enable` and `disable` support `dry_run` (true/false/1/0/yes/no/on/off, or a bare `dry_run` word; any other value is an error).
* `svc` and the `proc` signal and nice verbs have **no dry run**; they act immediately.
* Input checks done before any action: `proc` PIDs must be 1 to 2147483647 (or `self`); `svc` service names are rejected if they start with `-`, contain `.`/`..` path segments, whitespace, control characters or `:` (exit 2).
* `cron` does not reject newlines in job fields; see the limitations in [cron.md](cron.md).

### Timeouts

* Only `svc` `stop` and `wait` have a timeout, given as `timeout=<milliseconds>`. A timeout that expires exits with code 124.
* No verb in this category reads `timeout_ms`. It is ignored everywhere except `proc` `limits.set`, which treats any unrecognized argument (including `timeout_ms`) as an unknown resource and fails.

### Exit status

* 0 on success; non-zero on failure, with `Error: <reason>` on stderr if the handle did not already write to stderr.
* `cron`: every failure exits 1, and the JSON `ok` field always agrees with the exit status.
* `proc` and `svc` use a few specific codes (for example `proc` exit 3 for "process not found", `svc` exit 124 for a timeout). See each handle's document for the verified list.

### Limited verbs

* `proc` `limits.set` applies `setrlimit` to the resh process itself, not to the target or `pid=` process, so it cannot change another process's limits.
* `proc` `io.peek` reads log files in the resh state directory that nothing in resh writes.

---

## 3. Command Syntax and Execution Model

### 3.1 Examples

#### List scheduled jobs

```bash
resh cron://local.list
```

#### Add a scheduled job (crontab)

```bash
resh cron://local.add 'schedule=0 2 * * *' command=/usr/bin/backup.sh backend=cron id=backup dry_run
resh cron://local.add 'schedule=0 2 * * *' command=/usr/bin/backup.sh backend=cron id=backup
```

#### Signal a process

```bash
resh proc://1234.term
resh proc://1234.signal sig=HUP
```

#### Change process priority

```bash
resh proc://1234.nice.get
resh proc://1234.nice.set value=10
resh proc://1234.setPriority class=background
```

#### Check, restart and enable a service

```bash
resh svc://nginx.status
resh svc://postgresql.restart
resh svc://postgresql.wait state=active timeout=30000
resh svc://nginx.enable
```

---

## 3.2 Execution Semantics

### Output shapes

There is no common response envelope across these handles; each verb has its own fields. Examples:

`svc://nginx.status` on systemd (abbreviated):

```json
{
  "active_state": "active",
  "backend": "systemd",
  "name": "nginx.service",
  "pid": 1234,
  "sub_state": "running"
}
```

`proc://1234.term`:

```json
{
  "ok": true,
  "pid": 1234,
  "signal": "TERM",
  "signal_num": 15,
  "verb": "term"
}
```

`cron` failure (any verb):

```json
{
  "ok": false,
  "error": {
    "code": "cron.rm_no_match",
    "message": "No scheduled jobs matched the provided criteria."
  }
}
```

`proc` does not report process state, CPU or memory; there is no `proc` status verb.

### Backend selection

* `svc` uses systemd if `/run/systemd/system` exists or `systemctl` is on `PATH`, otherwise OpenRC if `rc-service` or `rc-status` is on `PATH`.
* `cron add backend=auto` uses systemd timers whenever `systemctl --version` runs; pass `backend=cron` for a crontab line.

### State

Each `resh` invocation is a separate process. Nothing is kept between invocations; all state lives in the service manager, the crontabs and the unit files.

---

## 4. Functional Domains

### 4.1 Automation Utilities

`cron://` for recurring jobs: backups, maintenance, monitoring scripts, cleanup.

### 4.2 Data & State Management

`svc` `status` and `is-enabled` for service state; `cron` `list` for the crontab inventory; `proc` `nice.get` for a process's nice value.

### 4.3 Filesystem & Storage

Indirect only: `cron` edits crontab and unit files; `svc logs` on OpenRC reads files under `/var/log`.

### 4.4 Network & Remote Operations

All three handles act on the local host only. To manage another host, run resh on it.

```bash
resh svc://apache2.status
```

### 4.5 Packages & Software

Restart or reload services after package updates, enable newly installed services, disable or mask unwanted ones.

### 4.6 Process & Service Management

* `cron`: schedule, list and remove jobs
* `proc`: signal processes and adjust nice values
* `svc`: control and inspect services

### 4.7 Security & Secrets

* Most `svc` changes, system crontabs and system units need root.
* `proc` can signal or renice only processes you own unless you are root.
* Do not put secrets in cron commands or environment values; they are stored in plain text.
* Do not pass untrusted input as cron job fields (no newline validation).

### 4.8 System Information

* Service state, main PID and timestamps (systemd) or state and raw output (OpenRC)
* Scheduled job inventory from crontabs (systemd timers are not listed)
* Detected init backend (`backend` field in `svc` output)

---

## 5. Platform Support

Linux only. The code uses Unix-only system calls and Linux signal numbers, and nothing was built or tested on macOS, BSD or Windows.

| Handle | Requirements |
| ------ | ------------ |
| `cron` | `crontab` for the cron backend; `systemctl` for systemd timers |
| `proc` | Linux kernel interfaces (`kill`, `getpriority`, `setpriority`) |
| `svc` | systemd (D-Bus, `systemctl`, `journalctl`) or OpenRC (`rc-service`, `rc-status`, `rc-update`) |

---

## 6. Operational Best Practices

### Safe usage

* Check `svc` status before changing a service; there is no dry run.
* Use `dry_run` before every changing `cron` verb.
* Send TERM before KILL.
* Avoid disabling critical system services.

### Automation

* Check exit codes first, then JSON fields.
* Use `svc wait` with `timeout` in milliseconds after a restart.
* Use `id=` for cron jobs so they can be removed or disabled exactly.

### CI/CD integration

1. Deploy the updated service binary.
2. `resh svc://app.restart`
3. `resh svc://app.wait state=active timeout=60000`
4. `resh svc://app.status`
5. Schedule recurring maintenance with `cron add backend=cron`.

---

## 7. Use Cases by Role

### DevOps Engineers

* Restart and verify services after deployments.
* Schedule recurring maintenance jobs.

### SRE Engineers

* Diagnose and restart failed services; read logs with `svc logs`.
* Escalate signals to hung processes with `proc`.

### Network Administrators

* Manage network-facing daemons and their boot configuration.

### Automation Engineers

* Build remediation scripts on exit codes and JSON fields.
* Audit scheduled jobs with `cron list`.

---

## 8. Technical Foundation

* Implemented in Rust under `src/handles/processes/` (`cronh.rs`, `proch.rs`, `svch.rs`).
* `svc` talks to systemd over D-Bus (`zbus`) with `systemctl`/`journalctl` fallbacks, and shells out to OpenRC tools.
* `proc` uses `libc` system calls directly.
* `cron` shells out to `crontab` and `systemctl` and edits crontab and unit files.
* Argument checking varies by verb; unknown argument names are generally ignored. See each handle's document.
