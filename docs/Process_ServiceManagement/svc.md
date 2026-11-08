# Resource Shell (resh) – Service Management Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using URI-based commands. The `svc://` handle inspects and controls system services through the host's service manager. Two backends exist: **systemd** and **OpenRC**. There is no other backend.

### Purpose

The `svc` handle lets you:

* Start, stop, restart and reload services
* Configure boot-time behavior (`enable`, `disable`, and on systemd `mask`, `unmask`)
* Inspect service state (`status`, `is-enabled`)
* Read recent service logs (`logs`)
* Wait for a service to become active or inactive (`wait`)
* Start or stop numbered instances of a systemd template unit (`scale`)

`status`, `is-enabled`, `wait`, `stop`, `start`, `restart` and `scale` print a single JSON object (also when they fail: it then carries an `error` object). `logs` prints log lines as plain text. `reload`, `enable`, `disable`, `mask` and `unmask` print nothing on success.

### Architectural Problem Addressed

Service managers differ in commands and output. `svc` puts the common operations behind one URI form and reports state as JSON, so scripts do not have to parse `systemctl` or `rc-service` text. It does not hide every difference: some fields and verbs differ by backend (see section 5).

### Resource-Oriented URI Model

```text
svc://<service-name>.<verb> [key=value ...]
```

* **handle**: `svc://`
* **target**: the service name, such as `nginx`, `sshd`, `getty@tty1` or `worker@.service`
* **verb**: the operation, after the last dot of the URL
* **options**: `key=value` words after the stage (or the quoted form `'svc://nginx.stop(timeout_ms=5000)'`)

Examples:

```bash
resh svc://nginx.status
resh svc://myapp.restart
resh svc://postgresql.wait state=active timeout_ms=30000
resh svc://getty@tty1.status
```

---

## 2. Design Philosophy and Core Principles

### Interface Model

* Thirteen verbs: `status`, `is-enabled`, `start`, `stop`, `restart`, `reload`, `enable`, `disable`, `mask`, `unmask`, `wait`, `logs`, `scale`.
* The service name is always given explicitly in the URL.
* The backend is detected on every call (see "Backend detection" below); it cannot be chosen by an option.

### Backend detection

systemd is used if `/run/systemd/system` exists **or** a `systemctl` binary is on `PATH`. Otherwise OpenRC is used if `rc-status` or `rc-service` is on `PATH`. If neither is found, the backend is `unknown` and every verb fails with `svc.no_backend` (exit 1).

On systemd, resh talks to systemd over the system D-Bus. If the bus cannot be reached (for example a container without `dbus`), it uses `systemctl --no-ask-password` instead, for every verb; systemctl then talks to systemd's private socket (root only). If neither works, the verb fails with `svc.backend_unavailable` (exit 1). resh never asks for a password interactively. Because the `systemctl` check alone is enough, a host that runs OpenRC but has a `systemctl` binary installed is treated as systemd.

### Service names

* A name without a suffix gets `.service` appended on systemd (`nginx` → `nginx.service`). A name already ending in `.service` is used as given. OpenRC uses the name as given.
* Instance names work: `svc://getty@tty1.status` targets `getty@tty1.service`, and `svc://user@1000.status` targets `user@1000.service`.
* Before any backend command runs, names are rejected (exit 2, `Error: [svc.invalid_target] invalid service name ...`) if they are empty or longer than 256 bytes, start with `-` or `.`, or contain any character other than ASCII letters, digits, `_`, `.`, `@`, `-` and `\` (so `:`, `/`, whitespace and control characters are refused).
* Other unit types (`.socket`, `.timer`, ...) cannot be named: a name not ending in `.service` always gets `.service` appended.

### Safety

* There is **no dry run** for any `svc` verb. `start`, `stop`, `restart`, `reload`, `enable`, `disable`, `mask`, `unmask` and `scale` act immediately. A `dry_run=true` argument is refused (exit 2, `svc.invalid_argument`) and nothing runs; `dry_run=false` is accepted.
* Every argument is checked before anything runs: an unknown argument name or an invalid value is refused with exit 2 and `svc.invalid_argument` (with a "did you mean" hint for a likely typo). Booleans accept `true|false|1|0|yes|no|on|off`.
* Most changes need root (or a polkit rule on systemd). A refusal for lack of privileges is `svc.permission_denied` (exit 1).

### Timeouts

Every verb takes `timeout_ms=<milliseconds>` (1 to 604800000). `stop` and `wait` also accept the older name `timeout` (give one or the other, not both).

| Verbs | Default `timeout_ms` |
| ----- | -------------------- |
| `start`, `stop`, `restart`, `reload`, `scale` | 120000 |
| `status`, `is-enabled`, `enable`, `disable`, `mask`, `unmask` | 30000 |
| `wait` | 10000 |
| `logs` | 600000; with `follow=true`, no limit unless given |

* When the deadline passes, resh exits **124** with `svc.timeout`. A systemd job still running then is **cancelled** (`Job.Cancel`); the JSON result says whether that worked (`job_canceled`). What the job already did (for example a process it started) stays done, so check the service before retrying.
* An external tool (`systemctl`, `rc-service`, `rc-update`, `journalctl`, `tail`) still running at the deadline is stopped with everything it started. For a mutating verb the outcome is then unknown (exit 124). A job that `systemctl` had already queued keeps running in systemd: it cannot be cancelled from resh.
* For `logs follow=true`, `timeout_ms` is how long to follow: reaching it is a normal end (exit 0).

---

## 3. Command Syntax and Execution Model

### 3.1 Verbs and arguments

| Verb | Arguments | Output |
| ---- | --------- | ------ |
| `status` | `timeout_ms` | JSON state object |
| `is-enabled` | `timeout_ms` | `{"backend","enabled","name","unit_file_state"}` |
| `start` | `timeout_ms` | JSON result |
| `stop` | `timeout_ms` (or `timeout`), `force=true\|false` | JSON result |
| `restart` | `timeout_ms` | JSON result |
| `reload` | `timeout_ms` | nothing on success |
| `enable` | `timeout_ms` | nothing on success |
| `disable` | `timeout_ms` | nothing on success |
| `mask` | `timeout_ms` (systemd only) | nothing on success |
| `unmask` | `timeout_ms` (systemd only) | nothing on success |
| `wait` | `state=active\|inactive\|running\|stopped`, `timeout_ms` (or `timeout`) | JSON result |
| `logs` | `lines=<n>`, `since=<time>`, `until=<time>`, `level=<priority>`, `reverse=true\|false`, `follow=true\|false`, `timeout_ms` | plain log lines |
| `scale` | `count=<n>` (required), `timeout_ms` | JSON result |

Any other argument is refused (exit 2, `svc.invalid_argument`).

### Examples

#### Check service status

```bash
resh svc://nginx.status
resh svc://sshd.status
resh svc://getty@tty1.status
```

#### Start and verify

```bash
resh svc://myapp.start
resh svc://myapp.status
```

#### Stop and wait up to 30 seconds

```bash
resh svc://nginx.stop timeout_ms=30000
```

#### Force stop (systemd)

```bash
resh svc://myapp.stop force=true timeout_ms=60000
```

#### Reload configuration

```bash
resh svc://nginx.reload
```

#### Boot configuration

```bash
resh svc://postgresql.enable
resh svc://test-service.disable
resh svc://vulnerable-daemon.mask
resh svc://vulnerable-daemon.unmask
```

#### View logs

```bash
resh svc://nginx.logs lines=100
resh svc://nginx.logs lines=2 level=err
resh svc://myapp.logs follow=true
```

#### Scale a template unit (systemd)

```bash
resh svc://worker@.service.scale count=5
```

---

## 3.2 Execution Semantics

### status

Reports the service state. On systemd the unit is loaded and read over D-Bus (`LoadUnit`), so units that are installed but not currently loaded are reported too. Through `systemctl` (no D-Bus) the timestamps are empty.

systemd output (shown with `--json-pretty`):

```json
{
  "active_state": "active",
  "backend": "systemd",
  "description": "A high performance web server and a reverse proxy server",
  "exit_status": 0,
  "name": "nginx.service",
  "pid": 1234,
  "sub_state": "running",
  "timestamps": {
    "active_enter": "2026-10-16T09:12:44.512309+00:00",
    "active_exit": "",
    "inactive_enter": ""
  }
}
```

OpenRC output has the fields `name`, `backend` (`"openrc"`), `state` (`"running"` or `"stopped_or_unknown"`), `pid` (parsed from the `rc-service` output, or `null`), `exit_status` (`null`), `timestamps` (`null`) and `raw` (the `rc-service` output).

* A service that does not exist is a failure: the object carries an `error` object and resh exits 1 with `Error: [svc.not_found] unit nosuch.service not found`.
* A stopped service is a successful query (exit 0); check `active_state` or `state`.

### is-enabled

```json
{
  "backend": "systemd",
  "enabled": true,
  "name": "nginx",
  "unit_file_state": "enabled"
}
```

On systemd, `enabled` is true when the unit file state is `enabled`, `static` or `indirect`; `unit_file_state` is the state systemd reports (`enabled`, `disabled`, `static`, `masked`, `alias`, ...). On OpenRC, `enabled` is true when the service is in the `default` runlevel (`rc-update show default`), and there is no `unit_file_state`. A service that does not exist is `svc.not_found` (exit 1), and a check that fails is an error too: `false` always means "not enabled".

### start, restart

```json
{
  "action": "start",
  "active_state": "active",
  "backend": "systemd",
  "job_result": "done",
  "name": "nginx.service",
  "result": "success",
  "sub_state": "running"
}
```

On systemd, resh queues a `StartUnit`/`RestartUnit` job (mode `replace`) and **waits for the job to finish** (systemd's `JobRemoved` signal), so the result is the job's real outcome:

* `job_result` `done` (or `skipped`): `"result": "success"`, exit 0. `active_state`/`sub_state` are read after the job; a oneshot service without `RemainAfterExit` is `inactive` again by then.
* any other job result (`failed`, `dependency`, `timeout`, `canceled`, ...): `"result": "failed"`, exit 1, `svc.job_failed`.
* the unit does not exist: `svc.not_found`; it is masked: `svc.masked`; not permitted: `svc.permission_denied` (all exit 1, nothing queued).
* `timeout_ms` passes first: the job is cancelled, `"result": "timeout"`, `job_canceled` true or false, exit 124 (`svc.timeout`).

What "done" means depends on the unit type: for `Type=simple` systemd considers the service started as soon as its process is forked, so a service that crashes a moment later still reports success (as `systemctl start` does). Use `Type=notify`, `forking` or `exec` units, or follow with `status`, when that matters.

Without D-Bus, resh runs `systemctl start|restart` (which waits for the job too); `job_canceled` is then always false at the deadline. On OpenRC it runs `rc-service <name> start|restart`, which returns once the service is started; the result has `state` instead of `active_state` and reports the name without the `.service` suffix.

### stop

```json
{
  "action": "stop",
  "backend": "systemd",
  "final_state": "inactive",
  "job_result": "done",
  "name": "nginx.service",
  "note": "stopped via StopUnit",
  "previous_state": "active",
  "reached_inactive": true,
  "requested": true,
  "timeout_ms": 5000
}
```

* resh queues a `StopUnit` job and waits for it to finish, up to `timeout_ms` (default 120000; `timeout` is an older name). `timeout_ms` and `reached_inactive` are always present; `reached_inactive` is true when `final_state` is `inactive` or `failed`.
* A job result other than `done`/`skipped` is `svc.job_failed` (exit 1). At the deadline the job is cancelled and resh exits **124** (`svc.timeout`, with `job_canceled`).
* A unit that does not exist is `svc.not_found` (exit 1) and nothing is queued.
* `force=true` (systemd only) queues the stop job with mode `replace-irreversibly`, so no later job can replace it (through systemctl: `--job-mode=replace-irreversibly`). On OpenRC, `force=true` is refused (exit 2, `svc.unsupported`).
* On OpenRC the object has no `note` or `job_result`, and `previous_state`/`final_state` use the OpenRC state values.
* If the stop request fails, the object has `"requested": false` and an `error` object, and resh exits 1.

### reload, enable, disable, mask, unmask

* systemd: `reload` queues a `ReloadUnit` job and waits for its result like `start` (a unit without `ExecReload` is refused by systemd: `svc.failed`). `enable`, `disable`, `mask` and `unmask` call `EnableUnitFiles` (with force), `DisableUnitFiles`, `MaskUnitFiles` (with force) and `UnmaskUnitFiles`, then reload systemd's configuration as `systemctl` does. Without D-Bus they run `systemctl enable|disable|mask|unmask`.
* `enable` of a unit without an `[Install]` section succeeds but changes nothing; a warning on stderr says so.
* OpenRC: `reload` runs `rc-service <name> reload`; `enable`/`disable` run `rc-update add|del <name> default` (a service that does not exist is `svc.not_found`); `mask` and `unmask` are refused (exit 2, `svc.unsupported`).
* Success prints nothing. Failure prints `Error: [svc.<code>] <reason>` on stderr.

### wait

```json
{
  "active_state": "active",
  "backend": "systemd",
  "name": "nginx",
  "reached": true,
  "state": "active",
  "timeout_ms": 30000
}
```

* `state` defaults to `active`. `running` means active and `stopped` means inactive (on systemd, `failed` counts as inactive). Any other value is refused (exit 2).
* `timeout_ms` (or the older `timeout`) is in milliseconds and defaults to 10000; an invalid value is refused (exit 2).
* resh polls every 200 ms. If the state is not reached in time, `reached` is `false` and resh exits **124** (`svc.timeout`). `active_state` (systemd) is the last state seen.
* Waiting on a service that does not exist fails (exit 1, `svc.not_found`). With no detected backend the verb fails with `svc.no_backend` (exit 1).

### logs

* systemd: runs `journalctl --unit=<unit> --no-pager --output=short-iso --lines=<lines>`, adding `--since=<time>`, `--until=<time>`, `--priority=<level>`, `--reverse` and `--follow`. Each value is passed as one argument. `lines` is 1 to 1000000 (default 200). `level` is one of `debug`, `info`, `warning`, `err`/`error`, `crit`/`critical`; `since`/`until` take any journalctl time (`"2026-10-16 09:00"`, `-1h`, `yesterday`) and must not be empty. Invalid values are refused (exit 2).
* A failing journalctl is `svc.logs_failed` (exit 1, with its message); a missing journalctl is `svc.tool_not_found`; a journal the caller may not read is `svc.permission_denied`.
* OpenRC: prints the last `lines` lines of the first file found among `/var/log/<name>.log`, `/var/log/<name>/<name>.log` and `/var/log/<name>/current`, using `tail` (`tail -F` with `follow=true`). `since`, `until` and `level` are refused on OpenRC (exit 2, `svc.unsupported`). If none of the files exists, resh exits 1 with `svc.no_logs`, naming the checked paths.
* `reverse=true` cannot be combined with `follow=true` (exit 2).
* `follow=true` streams lines as they arrive, until interrupted or until `timeout_ms` (if given) has passed, which ends the command with exit 0.

### scale

`count` is required and must be an integer from 0 to 1000; otherwise resh exits 2 (`svc.invalid_argument`) and nothing runs.

* systemd template unit (a name ending in `@.service`, such as `worker@.service`): queues start jobs for `worker@1.service` … `worker@<count>.service` that are not active and stop jobs for active numbered instances above `count`, then waits for all of them. The output has `name`, `backend`, `desired_count`, `template` (`true`), `instances_started` and `instances_stopped` (jobs that succeeded), `effective_count` (active instances afterwards), `note` and, if any job failed, `errors` with `svc.partial_failure` (exit 1). At the deadline, unfinished jobs are cancelled and resh exits 124.
* systemd non-template unit: `count=0` stops the service and any `count` of 1 or more starts it (a job, as for `start`/`stop`). A unit that does not exist is `svc.not_found`.

  ```json
  {
    "backend": "systemd",
    "desired_count": 1,
    "effective_count": 1,
    "name": "nginx.service",
    "note": "non-template service scaled to 1",
    "template": false
  }
  ```

* OpenRC: only 0 or 1 is meaningful (stop or start); `note` is `"openrc scaling is min/max 1 only"`. A template name is refused (exit 2, `svc.unsupported`).

### Exit codes

| Exit | When |
| ---- | ---- |
| 0 | Success. Includes `status` of a stopped service and `is-enabled` returning `false`. |
| 1 | The operation failed: not found, refused by the service manager, a job that failed, a tool error, a partial failure, no backend. |
| 2 | Invalid usage: unknown verb, invalid service name, unknown argument or invalid value, or an option the backend does not support. Nothing was done. |
| 124 | The deadline passed (`timeout_ms`), or the outcome is unknown. |

### Error codes

Errors are printed as `Error: [<code>] <message>` on stderr; verbs that print a JSON result also print it on failure, with `"error": {"code": "<code>", "message": "..."}`.

| Code | Exit | When |
| ---- | ---- | ---- |
| `svc.invalid_argument` | 2 | Unknown argument, invalid value, `dry_run=true`, both `timeout` and `timeout_ms`, missing `count`. |
| `svc.invalid_target` | 2 | Invalid service name, or a URL that cannot be parsed. |
| `svc.unknown_verb` | 2 | The verb does not exist (with a suggestion). |
| `svc.unsupported` | 2 | The backend cannot do this: `mask`/`unmask`, `stop force=true`, template `scale`, or `logs` `since`/`until`/`level` on OpenRC. |
| `svc.not_found` | 1 | The unit or service does not exist. |
| `svc.permission_denied` | 1 | Not permitted (root or a polkit rule is needed), or the journal cannot be read. |
| `svc.masked` | 1 | The unit is masked, so it cannot be started. |
| `svc.job_failed` | 1 | A systemd job finished with a result other than `done`/`skipped`; the result is in the message and in `job_result`. |
| `svc.partial_failure` | 1 | `scale` of a template: some instance jobs failed (see `errors`). |
| `svc.no_backend` | 1 | Neither systemd nor OpenRC was detected. |
| `svc.backend_unavailable` | 1 | systemd was detected but neither D-Bus nor `systemctl` could reach it. |
| `svc.tool_not_found` | 1 | `rc-service`, `rc-update`, `journalctl` or `tail` is missing. |
| `svc.no_logs` | 1 | OpenRC `logs`: no log file found. |
| `svc.logs_failed` | 1 | `journalctl` or `tail` failed. |
| `svc.failed` | 1 | Any other refusal or failure from the service manager or a tool (also an unexpected internal error). |
| `svc.timeout` | 124 | The deadline passed; for a mutating verb the job was cancelled where possible, otherwise the outcome is unknown. |

---

## 4. Functional Domains

### 4.1 Automation Utilities

Use `svc` in deployment scripts: restart a service (resh waits for the restart job and fails if it fails), then check `status`. Exit codes are non-zero on failure and 124 on a timeout, so a shell script can stop on the first failure.

### 4.2 Data & State Management

`status` and `is-enabled` give machine-readable state for audits, such as checking in CI that a service is active and enabled. A check that cannot be made is an error, never `false`.

### 4.3 Filesystem & Storage

`logs` on OpenRC reads plain log files under `/var/log`. `svc` does not read or validate unit files or service configuration.

### 4.4 Network & Remote Operations

`svc` acts only on the local host. There is no remote target; to manage another host, run resh there (for example over `ssh`).

### 4.5 Packages & Software

Typical use after a package change: `restart` or `reload` the service, `enable` a newly installed one, `disable` or (on systemd) `mask` one that should not run.

### 4.6 Process & Service Management

`svc` works at the service-manager level. For signals or nice values on a single process, use `proc://` (for example with the `pid` from `status`). For scheduled jobs, use `cron://`.

### 4.7 Security & Secrets

* Most mutating verbs need root or a matching polkit rule.
* There is no dry run; test commands on a non-production host.
* `mask` (systemd) prevents a unit from being started at all, including as a dependency.

### 4.8 System Information

`status` reports active state, sub-state, description, main PID, exit status and timestamps on systemd; state, PID and the raw `rc-service` output on OpenRC. It does not report memory or CPU usage.

---

## 5. Platform Support

Linux only. Nothing was built or tested on macOS, BSD or Windows.

| Backend | Status |
| ------- | ------ |
| systemd | Implemented through D-Bus, with `systemctl` when the bus cannot be reached, and `journalctl`. Every verb is tested against a mock service manager and end to end against systemd running in a container (`tests/svc_e2e_docker.rs`), over D-Bus and through `systemctl`. |
| OpenRC | Implemented through `rc-service`, `rc-update` and `tail`. Tested with fake tools (`tests/svc_verbs.rs`); not run against a live OpenRC host in this release. |

Feature differences:

| Feature | systemd | OpenRC |
| ------- | ------- | ------ |
| status | yes (D-Bus or `systemctl show`) | yes (`rc-service status`; fewer fields) |
| start / stop / restart / reload | yes | yes |
| enable / disable | yes (unit files) | yes (`default` runlevel only) |
| mask / unmask | yes | no (fails) |
| stop `force=true` | yes | refused |
| wait | yes | yes (running vs not running) |
| logs | `journalctl`, with `since`/`until`/`level` | `tail` of a log file; no filters |
| scale | template units (numbered instances) and 0/1 for plain units | 0/1 only |

---

## 6. Operational Best Practices

### Safe usage

* Run `status` before lifecycle operations, and remember there is no dry run.
* Prefer `reload` over `restart` when the service supports it.
* `start` and `restart` wait for the job; use `wait` (with `timeout_ms`) when something else starts the service.
* Use `force=true` only when a normal stop does not work.
* Check boot configuration with `is-enabled` after `enable` or `disable`.

### Automation

* Check the exit code first; then read state fields such as `active_state` (systemd) or `state` (OpenRC).
* `reload`, `enable`, `disable`, `mask` and `unmask` print nothing on success, so rely on the exit code.

### CI/CD integration

```bash
resh svc://app.restart timeout_ms=60000
resh svc://app.status
resh svc://app.logs lines=50
```

---

## 7. Use Cases by Role

### DevOps Engineers

* Restart and verify services during deployments.
* Scale systemd template units such as `worker@.service`.

### SRE Engineers

* Inspect and restart failed services during incidents.
* Read recent logs with `logs`, filtered by `level` on systemd.

### Network Administrators

* Manage SSH, DNS, web and proxy services on the local host.
* Enable or disable network daemons at boot.

### Automation Engineers

* Use the JSON from `status`, `wait`, `stop` and `scale` in remediation scripts.
* Detect boot-configuration drift with `is-enabled`.

---

## 8. Technical Foundation

* Implemented in Rust in `src/handles/processes/svch.rs`.
* systemd access uses the `zbus` D-Bus client against `org.freedesktop.systemd1` (`LoadUnit`, `StartUnit`, `StopUnit`, `RestartUnit`, `ReloadUnit`, the `*UnitFiles` calls, `Reload`, `ListUnits`, the `JobRemoved` signal and `Job.Cancel`); without the bus it runs `systemctl --no-ask-password`, and `logs` runs `journalctl`.
* OpenRC access runs `rc-service`, `rc-update` and `tail`, directly (no shell).
* Each `resh` invocation is a separate process; nothing is kept between calls.
* Every argument is checked before anything runs (see Safety).
