# Resource Shell (resh) – Cron Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using URI-based commands. The `cron://` handle manages scheduled jobs on the local host, either as crontab entries (through the `crontab` command and the system crontab files) or as systemd service and timer unit pairs (through `systemctl`).

### Purpose

The `cron` handle lets you:

* List crontab entries (`list`; systemd timers are not listed)
* Add a job as a crontab line or as a systemd `.service` + `.timer` pair (`add`)
* Remove jobs (`rm`)
* Disable jobs without deleting them (`disable`), and re-enable them (`enable`)

Every verb prints a JSON object by default (`format=text` gives a text summary on success).

### Architectural Problem Addressed

crontab files and systemd timers are edited and inspected in different ways, and neither gives machine-readable output. `cron` offers one set of verbs for both, reports what it matched and changed as JSON, and supports a dry run for every changing verb.

### Resource-Oriented URI Model

```text
cron://<label>.<verb> [key=value ...]
```

* **handle**: `cron://`
* **target**: a label such as `local`. It is only a label and is ignored; `cron` always acts on the local host.
* **verb**: `list`, `add`, `rm`, `enable`, `disable`
* **options**: `key=value` words after the stage. Quote values that contain spaces, such as schedules.

Examples:

```bash
resh cron://local.list
resh cron://local.add 'schedule=0 2 * * *' command=/usr/local/bin/backup backend=cron id=daily-backup
resh cron://local.rm id=daily-backup backend=cron dry_run=true
```

---

## 2. Design Philosophy and Core Principles

### Interface Model

* Five verbs: `list`, `add`, `rm`, `enable`, `disable`.
* `rm`, `enable` and `disable` need at least one selector: `id`, `schedule`, `command`, `match_command`, `match_comment`, `unit_name` or `match_unit`.
* Backend and scope are chosen with options (`backend=`, `scope=`, `unit_scope=`).

### Dry run

`add`, `rm`, `enable` and `disable` accept `dry_run`. The values `true`, `false`, `1`, `0`, `yes`, `no`, `on`, `off` (any case) are accepted, and a bare `dry_run` word means `dry_run=true`. Any other value is an error and nothing is changed. With a dry run the response reports what would be matched or written (`add` includes a `preview` object), and no crontab or unit file is touched. A misspelled key (for example `dryrun`) is not recognized and is ignored, so the change runs for real.

### Other boolean options

`list` booleans (`include_system`, `include_next_run`, `include_raw`, `include_paths`) accept `true`/`1`/`yes` and `false`/`0`/`no`; anything else is an error.

For `add`, `rm`, `enable` and `disable`, the booleans `allow_duplicate`, `persistent`, `include_next_run`, `require_match`, `remove_units`, `start_now` and `stop_now` are true **only for the exact lowercase value `true`**. Any other value, including `yes`, `1` or `TRUE`, means false.

### Timeouts

No `cron` verb has a timeout and none reads `timeout_ms`; a `timeout_ms` argument is silently ignored. Each verb runs `crontab` or `systemctl` commands and waits for them to finish.

### Output and exit status

* Success: exit 0 and a JSON object with `"ok": true`.
* Failure: the JSON object has `"ok": false` and an `error` object with `code` and `message`; resh exits 1 and prints `Error: cron <verb>: <message>` on stderr. In `format=text` a failure is still printed as the JSON error object.
* Missing required arguments to `add` (`schedule`, `command`) and invalid `list` options are reported as `Error: <reason>` on stderr only, with exit 1.
* The JSON `ok` field and the exit status always agree. `cron` has no other exit codes.

---

## 3. Command Syntax and Execution Model

### 3.1 Verbs

| Verb | Description |
| ---- | ----------- |
| `list` | List crontab entries for a scope, with filters, sorting and optional next-run times |
| `add` | Add a job as a crontab line or as a systemd service and timer |
| `rm` | Remove matching crontab lines and systemd timers (by default with their unit files) |
| `enable` | Uncomment matching disabled crontab lines, or enable (and by default start) matching timers |
| `disable` | Comment out matching crontab lines, or disable (and by default stop) matching timers |

### 3.2 list

```text
resh cron://<label>.list [scope=current|user|system|all] [users=<user,...>]
  [include_system=true|false] [include_files=<path,...>] [state=all|enabled|disabled]
  [match_command=<text>] [match_comment=<text>] [match_user=<text>] [match_source=<text>]
  [include_next_run=true|false] [now_unix=<seconds>] [max_entries=<n>]
  [sort_by=none|user|schedule|command|source] [sort_order=asc|desc]
  [include_raw=true|false] [include_paths=true|false] [format=json|text]
```

* `scope` defaults to `current` (the current user's crontab via `crontab -l`). `scope=user` requires `users=`. `system` reads `/etc/crontab` and `/etc/cron.d`.
* `match_*` filters are case-insensitive substring matches.
* Commented-out jobs appear with `"enabled": false`; plain comment lines appear with `"comment_only": true`.
* `max_entries` defaults to 1024; `truncated` is true when more entries existed.
* A `timezone` argument is accepted but not used.
* systemd timers are not listed.

```bash
resh cron://local.list
resh cron://local.list scope=all state=disabled
resh cron://local.list match_command=backup include_next_run=true
```

Output (abbreviated to one entry, shown with `--json-pretty`):

```json
{
  "entries": [
    {
      "command": "/opt/backup.sh",
      "comment_only": false,
      "enabled": true,
      "id": "user:alice:crontab:1",
      "raw_line": "0 2 * * * /opt/backup.sh",
      "schedule": "0 2 * * *",
      "schedule_fields": {
        "day_of_month": "*",
        "day_of_week": "*",
        "hour": "2",
        "minute": "0",
        "month": "*"
      },
      "source": "user",
      "source_file": null,
      "source_line": 1,
      "user": "alice"
    }
  ],
  "entries_disabled": 0,
  "entries_returned": 1,
  "entries_total": 1,
  "human": {
    "summary": "1 cron entries (1 enabled, 0 disabled) from scope 'current'."
  },
  "include_system": false,
  "ok": true,
  "scope": "current",
  "timestamp_unix_ms": 1792161012345,
  "truncated": false,
  "users": ["alice"],
  "warnings": []
}
```

### 3.3 add

```text
resh cron://<label>.add schedule=<expr> command=<cmd>
  [backend=auto|cron|systemd] [id=<id>] [description=<text>]
  [scope=current|user|system] [user=<name>] [cron_file=<path>]
  [unit_name=<name>] [unit_scope=auto|user|system]
  [allow_duplicate=true|false] [persistent=true|false]
  [accuracy_sec=<v>] [random_delay_sec=<v>]
  [service_user=<name>] [service_working_dir=<path>]
  [env=KEY=VAL,KEY2=VAL2] [env_<KEY>=<value>]
  [include_next_run=true|false] [now_unix=<seconds>]
  [dry_run=true|false] [format=json|text]
```

* `backend` defaults to `auto`, which uses **systemd whenever `systemctl --version` runs**, and cron otherwise. Pass `backend=cron` to get a crontab line on a systemd host.
* Cron backend: `scope=current` (default) and `scope=user` add to a user crontab through `crontab`; `scope=system` appends to `/etc/crontab` or `cron_file=` with a user column (`user=`, default `root`). `id` and `description` are written as a comment line above the job: `# job-id=<id> description=<text>`.
* systemd backend: writes `<unit_name>.service` and `<unit_name>.timer` into `~/.config/systemd/user` (user scope) or `/etc/systemd/system` (system scope), runs `daemon-reload`, and enables and starts the timer (`systemctl enable --now`). `unit_scope=auto` means system for root and user otherwise. The unit name is derived from the command if `unit_name` is not given. `persistent` (default true), `accuracy_sec`, `random_delay_sec`, `service_user`, `service_working_dir` and the `env` options apply only to the systemd backend.
* `allow_duplicate` defaults to **true**, so the same job can be added twice. With `allow_duplicate=false`, an existing job with the same schedule and command makes `add` return `"ok": true, "duplicate": true` without writing.
* A `timezone` argument is accepted but not used.

```bash
resh cron://local.add schedule=@daily command=/opt/backup.sh backend=cron
resh cron://local.add 'schedule=30 3 * * *' command=/opt/rotate.sh backend=cron id=rotate allow_duplicate=false
resh cron://local.add 'schedule=0 4 * * *' command=/opt/report.sh backend=systemd unit_name=nightly-report dry_run
```

Output (shown with `--json-pretty`):

```json
{
  "backend_used": "cron",
  "dry_run": false,
  "duplicate": false,
  "job": {
    "backend": "cron",
    "command": "/opt/backup.sh",
    "location": {
      "file": "/var/spool/cron/alice",
      "line_added": 3,
      "scope": "current",
      "user": "alice"
    },
    "next_run_iso8601": "2026-10-17T00:00:00+00:00",
    "next_run_unix": 1792195200,
    "schedule": "@daily"
  },
  "ok": true,
  "timestamp_unix_ms": 1792161012345,
  "warnings": []
}
```

### 3.4 rm, enable, disable

```text
resh cron://<label>.rm|enable|disable [id=<id>] [schedule=<expr>] [command=<cmd>]
  [match_command=<text>] [match_comment=<text>] [unit_name=<name>] [match_unit=<text>]
  [backend=both|cron|systemd] [scope=all|current|user|system] [users=<user,...>]
  [unit_scope=auto|user|system|both] [require_match=true|false]
  [dry_run=true|false] [format=json|text]
  rm only:      [remove_units=true|false]
  enable only:  [start_now=true|false]
  disable only: [cron_file=<path>] [stop_now=true|false]
```

* `backend` defaults to `both` and `scope` defaults to `all` (current user's crontab, `/etc/crontab` and `/etc/cron.d`). Narrow them (for example `backend=cron scope=current`) to avoid touching system files.
* `require_match` defaults to true: if nothing matches, the response has `"ok": false` with code `cron.<verb>_no_match` and resh exits 1.
* `disable` comments a crontab line out by prefixing `# `; `enable` removes the prefix. `enable` only uncomments a commented line that starts with a real cron schedule (five valid time fields, or an `@` keyword, followed by a command). Ordinary comments are left alone. A commented line that is itself a valid cron entry (such as an example in a distribution's crontab header) is treated as a disabled job and can be enabled by a broad `match_command`.
* systemd timers are found by the UNIT column of `systemctl list-timers --all --plain`. `disable` disables the timer and, with `stop_now` (default true), stops it. `enable` enables it and, with `start_now` (default true), starts it. `rm` stops and disables it and, with `remove_units` (default true), deletes the `.timer` and `.service` files.
* If systemd is not available, the systemd part is skipped with a warning.

```bash
resh cron://local.disable match_command=backup backend=cron scope=current
resh cron://local.enable match_command=backup backend=cron scope=current
resh cron://local.rm id=backup backend=cron scope=current dry_run=true
resh cron://local.disable unit_name=nightly-report backend=systemd unit_scope=user
```

Output of `rm` (shown with `--json-pretty`):

```json
{
  "backend": "cron",
  "cron_modified_sources": ["/var/spool/cron/alice"],
  "dry_run": true,
  "matched_count": { "cron": 1, "systemd": 0 },
  "ok": true,
  "removed": {
    "cron": [
      {
        "command": "/opt/backup.sh",
        "id": "backup",
        "line_number": 2,
        "schedule": "0 2 * * *",
        "source": "/var/spool/cron/alice",
        "user": "alice"
      }
    ],
    "systemd": []
  },
  "systemd_scopes_touched": [],
  "timestamp_unix_ms": 1792161012345,
  "warnings": []
}
```

`enable` and `disable` return the same kind of object with `enabled`/`disabled` lists (entries carry `was_disabled`/`was_enabled`) and `already_enabled_count`/`already_disabled_count`. See `resh cron enable --help` and `resh cron disable --help` for the full example output.

### 3.5 Error example

```json
{
  "ok": false,
  "error": {
    "code": "cron.add_invalid_schedule",
    "message": "Invalid cron schedule '0 0 * * 0': ..."
  }
}
```

Error codes used in the `error.code` field include `cron.add_invalid_schedule`, `cron.add_missing_command`, `cron.add_backend_unavailable`, `cron.add_systemd_unavailable`, `cron.add_schedule_translation_unsupported`, `cron.<verb>_no_selector`, `cron.<verb>_invalid_backend`, `cron.<verb>_no_match`, `cron.<verb>_error` and `cron.list_error`. All of them exit 1.

---

## 3.6 Known limitations

These are current behaviors of this release, verified in `src/handles/processes/cronh.rs`:

* **Weekday numbering.** Schedules are validated and next-run times computed with the `cron` crate, which numbers weekdays 1-7 with Sunday = 1, while crontab uses 0-7 with Sunday = 0 (and 7). As a result `add` rejects a numeric weekday of `0` (for example `0 0 * * 0`), and `next_run_*` for numeric weekdays 1-7 is one day early (crontab's 1 = Monday is computed as Sunday). Three-letter day names (`sun`, `mon`, …) are interpreted correctly.
* **Six-field expressions.** `add` also accepts the `cron` crate's six-field form (with seconds) and writes it unchanged, which crontab cannot read. Use five fields.
* **`@midnight`** is not accepted by `add` (use `@daily`).
* **systemd OnCalendar translation** (`add` with the systemd backend) handles only simple schedules, and some translations are wrong:
  * `* * * * *` becomes `*:*:*`, which systemd runs every **second**, not every minute.
  * `@weekly` becomes `weekly`, which systemd runs on **Monday**; cron runs `@weekly` on Sunday.
  * A daily schedule with an hour or minute range or list (for example `0 9-17 * * *`) is copied as `9-17:0`, which is not valid systemd syntax.
  * Schedules with steps (`*/5`) or a specific day of month, month or weekday (other than the fixed patterns for hourly, daily, monthly and yearly) are rejected with `cron.add_schedule_translation_unsupported`.
  * `@reboot` is rejected for systemd.
* **`allow_duplicate` defaults to true.** Pass `allow_duplicate=false` to skip an identical existing job.
* **No newline validation.** Newlines in `description`, `id`, `command` or `env` values are not rejected and are written into the crontab line or unit file, where they can create extra crontab lines or unit directives. `unit_name` is used in file paths without validation, and `%` in commands is not escaped for crontab. Only pass trusted values.

---

## 4. Functional Domains

### 4.1 Automation Utilities

Scheduled backups, health checks, cleanup and log rotation jobs, added and removed by id from scripts.

### 4.2 Data & State Management

`list` gives a JSON inventory of crontab entries, including disabled ones, for audits and drift checks. It does not include systemd timers.

### 4.3 Filesystem & Storage

`cron` edits user crontabs through `crontab`, and edits `/etc/crontab`, `/etc/cron.d/*` and systemd unit files directly when the scope requires it.

### 4.4 Network & Remote Operations

Local host only; the URL label does not select a host.

### 4.5 Packages & Software

Schedule update or cleanup jobs; remove them by id when no longer needed.

### 4.6 Process & Service Management

Use `svc://` to manage services and `proc://` to signal processes; `cron` only manages the schedule entries.

### 4.7 Security & Secrets

* Do not put secrets in commands or `env` values; they are stored in plain text in crontabs or unit files.
* System scope and system unit scope need root.
* See the newline limitation in 3.6: never pass untrusted input as a job field.
* Use `dry_run` before `rm`, `enable` or `disable` with broad selectors.

### 4.8 System Information

`list` reports the schedule, its fields, command, user, source file and line, enabled state, and optionally the next run time (subject to the weekday limitation above).

---

## 5. Platform Support

Linux only. Nothing was built or tested on macOS, BSD or Windows.

| Backend | Status |
| ------- | ------ |
| crontab | `list` verified live. Changing verbs are covered by unit tests of the generated crontab text (including a byte-identical disable/enable round trip); no live crontab was changed during verification. |
| systemd timers | Implemented; timer discovery reads the UNIT column of `systemctl list-timers`. Not exercised on a live systemd host. |

---

## 6. Operational Best Practices

### Safe usage

* Use `dry_run` first for every `add`, `rm`, `enable` and `disable`.
* Give jobs an `id` so they can be selected exactly later.
* Pass `backend=cron` or `backend=systemd` explicitly; `auto` picks systemd whenever `systemctl` exists.
* Narrow `scope` and `backend` for `rm`, `enable` and `disable` (the defaults are `all` and `both`).
* Prefer `disable` over `rm` for temporary changes.
* Use day names rather than numbers for weekdays.

### Automation

* Check the exit code; on failure read `error.code` and `error.message`.
* Remember that booleans other than `dry_run` on the changing verbs are true only for `true`.

### CI/CD integration

```bash
resh cron://local.add 'schedule=0 3 * * *' command=/opt/maint.sh backend=cron id=maint allow_duplicate=false
resh cron://local.list match_comment=maint
resh cron://local.disable id=maint backend=cron scope=current
resh cron://local.enable id=maint backend=cron scope=current
```

---

## 7. Use Cases by Role

### DevOps Engineers

* Add and remove recurring operational jobs by id.
* Disable jobs during deployments and re-enable them afterwards.

### SRE Engineers

* Disable problematic jobs during incidents.
* Audit system-wide schedules with `list scope=all`.

### Network Administrators

* Schedule monitoring and maintenance scripts.

### Automation Engineers

* Use the JSON inventory from `list` to detect unexpected job changes.

---

## 8. Technical Foundation

* Implemented in Rust in `src/handles/processes/cronh.rs`.
* Crontab access through the `crontab` command and direct reads/writes of `/etc/crontab` and `/etc/cron.d`; systemd access through `systemctl` and unit files.
* Schedule validation and next-run times use the `cron` crate (see the weekday limitation).
* Each `resh` invocation is a separate process; nothing is kept between calls.
* Unknown argument names are ignored.
