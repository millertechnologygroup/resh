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

`status`, `is-enabled`, `wait`, `stop`, `start`, `restart` and `scale` print a single JSON object. `logs` prints log lines as plain text. `reload`, `enable`, `disable`, `mask` and `unmask` print nothing on success.

### Architectural Problem Addressed

Service managers differ in commands and output. `svc` puts the common operations behind one URI form and reports state as JSON, so scripts do not have to parse `systemctl` or `rc-service` text. It does not hide every difference: some fields and verbs differ by backend (see section 5).

### Resource-Oriented URI Model

```text
svc://<service-name>.<verb> [key=value ...]
```

* **handle**: `svc://`
* **target**: the service name, such as `nginx`, `sshd`, `getty@tty1` or `worker@.service`
* **verb**: the operation, after the last dot of the URL
* **options**: `key=value` words after the stage (or the quoted form `'svc://nginx.stop(timeout=5000)'`)

Examples:

```bash
resh svc://nginx.status
resh svc://myapp.restart
resh svc://postgresql.wait state=active timeout=30000
resh svc://getty@tty1.status
```

---

## 2. Design Philosophy and Core Principles

### Interface Model

* Thirteen verbs: `status`, `is-enabled`, `start`, `stop`, `restart`, `reload`, `enable`, `disable`, `mask`, `unmask`, `wait`, `logs`, `scale`.
* The service name is always given explicitly in the URL.
* The backend is detected on every call (see "Backend detection" below); it cannot be chosen by an option.

### Backend detection

systemd is used if `/run/systemd/system` exists **or** a `systemctl` binary is on `PATH`. Otherwise OpenRC is used if `rc-status` or `rc-service` is on `PATH`. If neither is found, the backend is `unknown` and every verb except `is-enabled` fails. Because the `systemctl` check alone is enough, a host that runs OpenRC but has a `systemctl` binary installed is treated as systemd.

### Service names

* A name without a suffix gets `.service` appended on systemd (`nginx` → `nginx.service`). A name already ending in `.service` is used as given. OpenRC uses the name as given.
* Instance names work: `svc://getty@tty1.status` targets `getty@tty1.service`, and `svc://user@1000.status` targets `user@1000.service`.
* Before any backend command runs, names are rejected (exit code 2, `Error: invalid service name ...` on stderr) if they are empty, start with `-`, contain a `.` or `..` path segment, contain whitespace or control characters, or contain `:`.

### Safety

* There is **no dry run** for any `svc` verb. `start`, `stop`, `restart`, `reload`, `enable`, `disable`, `mask`, `unmask` and `scale` act immediately. A `dry_run=true` argument is refused (exit 2) and nothing runs.
* Most changes need root (or a polkit rule on systemd). Permission errors come from the service manager and are reported as failures (exit 1).

### Timeouts

* `stop` and `wait` take `timeout=<milliseconds>`. They are the only verbs with a timeout.
* `timeout_ms` is **not** read by any `svc` verb and is silently ignored; use `timeout`.
* No other verb has a timeout: `start`, `restart`, `reload` and the boot-configuration verbs wait as long as the service manager does, and `logs follow=true` runs until interrupted.

---

## 3. Command Syntax and Execution Model

### 3.1 Verbs and arguments

| Verb | Arguments | Output |
| ---- | --------- | ------ |
| `status` | none | JSON state object |
| `is-enabled` | none | `{"backend","enabled","name"}` |
| `start` | none | JSON result |
| `stop` | `timeout=<ms>`, `force=true\|false` | JSON result |
| `restart` | none | JSON result |
| `reload` | none | nothing on success |
| `enable` | none | nothing on success |
| `disable` | none | nothing on success |
| `mask` | none (systemd only) | nothing on success |
| `unmask` | none (systemd only) | nothing on success |
| `wait` | `state=active\|inactive\|running\|stopped`, `timeout=<ms>` | JSON result |
| `logs` | `lines=<n>`, `since=<time>`, `until=<time>`, `level=<priority>`, `reverse=true\|false`, `follow=true\|false` | plain log lines |
| `scale` | `count=<n>` (required) | JSON result |

Unknown argument names are ignored.

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
resh svc://myapp.wait state=active timeout=30000
```

#### Stop and wait up to 30 seconds

```bash
resh svc://nginx.stop timeout=30000
```

#### Force stop (systemd)

```bash
resh svc://myapp.stop force=true timeout=60000
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

Reports the service state. On systemd the state is read over D-Bus; if the unit is not loaded, resh falls back to `systemctl show`, which reports `pid` 0 and empty timestamps.

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

* A service that does not exist is a failure: the object carries an `error` field and resh exits 1 (for example `Error: svc status nosuch: service 'nosuch' does not exist`).
* A stopped service is a successful query (exit 0); check `active_state` or `state`.

### is-enabled

```json
{
  "backend": "systemd",
  "enabled": true,
  "name": "nginx"
}
```

On systemd, `enabled` is true when the unit file state is `enabled`, `static` or `indirect`. On OpenRC, it is true when the service is in the `default` runlevel (`rc-update show default`). Errors while checking are reported as `"enabled": false` with exit 0, so `false` can also mean "could not tell".

### start, restart

```json
{
  "action": "start",
  "backend": "systemd",
  "name": "nginx.service",
  "result": "success"
}
```

On systemd, resh calls `StartUnit`/`RestartUnit` over D-Bus and falls back to `systemctl start`/`restart` if D-Bus fails. On OpenRC it runs `rc-service <name> start|restart`. On failure a JSON object with an `error` field is written to stderr and resh exits 1. OpenRC output reports the name without the `.service` suffix.

### stop

```json
{
  "action": "stop",
  "backend": "systemd",
  "final_state": "inactive",
  "name": "nginx.service",
  "note": "stopped via StopUnit",
  "previous_state": "active",
  "reached_inactive": true,
  "requested": true,
  "timeout_ms": 5000
}
```

* Without `timeout`, the stop is requested and `final_state` is read once; `timeout_ms` and `reached_inactive` are omitted.
* With `timeout=<ms>`, resh polls every 200 ms until the service is inactive or the timeout passes. If it is still active, the object gets `"error": "timeout waiting for service to stop"` and resh exits **124**.
* A `timeout` value that is not a non-negative integer is an error (exit 1).
* `force=true` (systemd only) uses `StopUnit` with mode `replace-irreversibly`, or, if D-Bus fails, `systemctl kill --signal=SIGTERM` followed by `systemctl stop`. `force` accepts only `true` or `false`; anything else is an error. On OpenRC `force` is accepted but has no effect.
* On OpenRC the object has no `note` field, and `previous_state`/`final_state` use the OpenRC state values.
* If the stop request fails, the object (with `"requested": false` and `error`) is written to stdout and resh exits 1.

### reload, enable, disable, mask, unmask

* systemd: D-Bus calls `ReloadUnit`, `EnableUnitFiles`, `DisableUnitFiles`, `MaskUnitFiles`, `UnmaskUnitFiles`. There is no `systemctl` fallback for these verbs, so they fail if the system D-Bus is unavailable.
* OpenRC: `reload` runs `rc-service <name> reload`; `enable`/`disable` run `rc-update add|del <name> default`; `mask` and `unmask` fail with `mask/unmask unsupported on OpenRC`.
* Success prints nothing. Failure prints `Error: <reason>` on stderr and exits 1.

### wait

```json
{
  "backend": "systemd",
  "name": "nginx",
  "reached": true,
  "state": "active",
  "timeout_ms": 30000
}
```

* `state` defaults to `active`. `running` means active and `stopped` means inactive. Any other value is treated as `active` without an error.
* `timeout` is in milliseconds and defaults to 10000. A value that is not a number is silently replaced by 10000.
* resh polls every 200 ms. If the state is not reached in time, `reached` is `false` and resh exits **124**.
* On systemd, waiting on a service that does not exist fails (exit 1). With no detected backend, `reached` is `false` immediately (exit 124).

### logs

* systemd: runs `journalctl -u <unit> --no-pager --output=short-iso -n <lines>`, adding `--since`, `--until`, `-p <level>`, `-r` (`reverse=true`) and `-f` (`follow=true`). `lines` defaults to 200 (a non-numeric value also gives 200). `level` accepts `debug`, `info`, `warning`, `err`/`error`, `crit`/`critical`; any other value is ignored. If `journalctl` fails, resh exits with its exit code.
* OpenRC: prints the last `lines` lines of the first file found among `/var/log/<name>.log`, `/var/log/<name>/<name>.log` and `/var/log/<name>/current`, using `tail`. `since`, `until` and `level` are ignored. If none of these files exists, resh lists the checked paths on stderr and exits **2**.
* `reverse` and `follow` are true only for the exact value `true`.
* `follow=true` streams until interrupted.

### scale

`count` is required and must be a non-negative integer; otherwise a JSON error is printed and resh exits 1.

* systemd template unit (a name ending in `@.service`, such as `worker@.service`): starts `worker@1.service` … `worker@<count>.service` if they are not active, and stops active numbered instances above `count`. The output has `name`, `backend`, `desired_count`, `template` (`true`), `instances_started`, `instances_stopped`, `effective_count`, `note` and, if any start or stop failed, `errors` (exit 1). This path uses D-Bus only.
* systemd non-template unit: `count=0` stops the service and any `count` of 1 or more starts it.

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

* OpenRC: only 0 or 1 is meaningful (stop or start); `note` is `"openrc scaling is min/max 1 only"`.

### Exit codes

The codes below are the ones the `svc` code returns; the exit code is 0 on success.

| Code | When |
| ---- | ---- |
| 0 | Success. Includes `status` of a stopped service and `is-enabled` returning `false`. |
| 1 | Any operation failure: missing service on `status`, failed start/stop/restart/reload/enable/disable/mask/unmask, invalid `stop` arguments, invalid or missing `count`, no backend detected. |
| 2 | Invalid service name (rejected before any command runs); OpenRC `logs` found no log file. |
| 124 | `stop timeout=<ms>` or `wait` did not reach the requested state in time. |
| other | `logs` passes through the exit code of `journalctl` or `tail` when they fail. |

---

## 4. Functional Domains

### 4.1 Automation Utilities

Use `svc` in deployment scripts: restart a service, then `wait` for it to become active, then check `status`. Exit codes are non-zero on failure and 124 on a wait timeout, so a shell script can stop on the first failure.

### 4.2 Data & State Management

`status` and `is-enabled` give machine-readable state for audits, such as checking in CI that a service is active and enabled. Remember that `is-enabled` reports `false` when the check itself fails.

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
| systemd | Implemented through D-Bus, with `systemctl`/`journalctl` fallbacks. In this release's verification the systemd paths were checked at parser and unit-test level only, not against a live systemd host. |
| OpenRC | Implemented through `rc-service`, `rc-status`, `rc-update` and `tail`. `status` was verified live on an OpenRC host; mutating verbs were not run live. |

Feature differences:

| Feature | systemd | OpenRC |
| ------- | ------- | ------ |
| status | yes (D-Bus or `systemctl show`) | yes (`rc-service status`; fewer fields) |
| start / stop / restart / reload | yes | yes |
| enable / disable | yes (unit files) | yes (`default` runlevel only) |
| mask / unmask | yes | no (fails) |
| stop `force=true` | yes | ignored |
| wait | yes | yes (running vs not running) |
| logs | `journalctl`, with `since`/`until`/`level` | `tail` of a log file; no filters |
| scale | template units (numbered instances) and 0/1 for plain units | 0/1 only |

---

## 6. Operational Best Practices

### Safe usage

* Run `status` before lifecycle operations, and remember there is no dry run.
* Prefer `reload` over `restart` when the service supports it.
* Use `wait` (with `timeout` in milliseconds) after `start` or `restart` in scripts.
* Use `force=true` only when a normal stop does not work.
* Check boot configuration with `is-enabled` after `enable` or `disable`.

### Automation

* Check the exit code first; then read state fields such as `active_state` (systemd) or `state` (OpenRC).
* `reload`, `enable`, `disable`, `mask` and `unmask` print nothing on success, so rely on the exit code.

### CI/CD integration

```bash
resh svc://app.restart
resh svc://app.wait state=active timeout=60000
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
* systemd access uses the `zbus` D-Bus client against `org.freedesktop.systemd1`; fallbacks shell out to `systemctl` and `journalctl`.
* OpenRC access shells out to `rc-service`, `rc-status`, `rc-update` and `tail`.
* Each `resh` invocation is a separate process; nothing is kept between calls.
* Argument checking is partial: `stop` validates `timeout` and `force` and `scale` validates `count`, but `wait` and `logs` fall back to defaults for bad values, and unknown argument names are ignored.
