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
* `rm`, `enable` and `disable` need at least one selector: `id`, `schedule`, `command`, `match_command`, `match_comment`, `unit_name` or `match_unit`. **Every selector given must match** (see 3.4).
* Backend and scope are chosen with options (`backend=`, `scope=`, `unit_scope=`).

### Arguments are checked first

Every verb accepts only the arguments listed in its usage (section 3 and `resh cron <verb> --help`). Before anything is read or changed, each verb refuses, with exit 2 and the code `cron.<verb>_invalid_argument` (`error.field` names the argument):

* an unknown argument (with a "did you mean" hint for a likely typo, such as `schedul`), including `dry_run` on `list`;
* an empty value, or a value with a line break or other control character;
* a value outside its documented set (`scope`, `state`, `format`, `sort_by`, ...), a malformed number (`max_entries`, `now_unix`, `timeout_ms`) or a malformed boolean;
* an option of the backend that does not run (for example `unit_scope` with `backend=cron`, see 3.3 and 3.4).

Since this release unknown arguments are refused; before, they were ignored.

### Booleans

Every boolean option (`dry_run`, `include_system`, `include_next_run`, `include_raw`, `include_paths`, `allow_duplicate`, `persistent`, `require_match`, `remove_units`, `start_now`, `stop_now`) accepts `true`, `false`, `1`, `0`, `yes`, `no`, `on`, `off` in any case. Anything else is refused with exit 2. Before this release the booleans of `add`, `rm`, `enable` and `disable` other than `dry_run` were true only for the exact value `true`.

### Dry run

`add`, `rm`, `enable` and `disable` accept `dry_run`, and a bare `dry_run` word means `dry_run=true`. With a dry run the response reports what would be matched or written (`add` includes a `preview` object), and no crontab or unit file is changed and no timer is started, stopped, enabled or disabled. Crontabs and unit files are still read.

### Timeouts

Every verb accepts `timeout_ms` (1 to 86400000, default **60000**): the time for the whole verb, every `crontab` and `systemctl` call included. A tool still running at the deadline is stopped (with everything it started), and resh exits **124** with `cron.timeout`: what the verb did before the deadline stays done, so check before retrying.

### Output and exit status

* Success: exit 0 and a JSON object with `"ok": true`.
* Failure: the JSON object has `"ok": false` and an `error` object with `code` and `message` (and `field` when one argument is at fault); stderr has one line `Error: [<code>] <message>`. In `format=text` a failure is still printed as the JSON error object.
* Exit codes: **2** invalid usage (nothing was read or changed), **1** the operation failed (no match, a tool or host error, a partial failure), **124** the deadline passed. Section 3.5 lists every code.
* The JSON `ok` field and the exit status always agree.

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
  [include_next_run=true|false] [now_unix=<seconds>] [timezone=<IANA zone>]
  [max_entries=<n>] [sort_by=none|user|schedule|command|source] [sort_order=asc|desc]
  [include_raw=true|false] [include_paths=true|false] [format=json|text]
  [timeout_ms=<ms>]
```

* `scope` defaults to `current` (the current user's crontab via `crontab -l`). `scope=user` requires `users=`; `users=` is accepted with `scope=user` and `scope=all` only. `system` reads `/etc/crontab` and `/etc/cron.d`; `all` reads the current user's crontab, the `users=` crontabs and, with `include_system=true`, the system files.
* `include_files=<path,...>` (absolute paths) adds files in the system format (with a user column).
* A crontab that cannot be read (or a user without one, read as empty) gives a warning, not a failure.
* `match_*` filters are case-insensitive substring matches. `match_comment` matches the comment line directly above a job (such as the `# job-id=... description=...` line `add` writes) and the job's inline ` # comment`.
* Commented-out jobs appear with `"enabled": false`. A commented line counts as a job only when it is one: five valid time fields (or an `@` keyword), the user column in system files, and a command. Other comment lines appear with `"comment_only": true` and count as neither enabled nor disabled jobs: `state=enabled` and `state=disabled` leave them out, and `entries_disabled` counts only disabled jobs. Before this release a commented sentence of six or more words was listed as a disabled job.
* Environment lines (`SHELL=`, `MAILTO=`, `CRON_TZ=`) are not entries. Any other line that is not a job is skipped with a warning.
* `max_entries` (0 to 4294967295) defaults to 1024; `truncated` is true when more entries existed. `entries_total` and `entries_disabled` count all entries that passed the filters.
* `include_raw=true` adds `raw`, an object with the full text of each crontab and file that was read, by path. `include_paths=true` adds `paths`, the path of each source.
* `include_next_run=true` adds `next_run_unix` and `next_run_iso8601` to enabled jobs (`@` keywords included, except `@reboot`). Next runs follow crontab's rules: weekdays 0-7 with Sunday as 0 and 7, names such as `mon`, and a job whose day-of-month and weekday fields are both restricted (neither starts with `*`) runs when either matches. A local time skipped by a daylight-saving change has no run that day; a repeated local time runs at its first occurrence. `now_unix` is the reference time (Unix seconds from 0 to 253402300799, i.e. up to the year 9999; default: now; anything else is an error). A schedule is read in its own `CRON_TZ` zone when it has one and the cron daemon is cronie. Otherwise it is read in `timezone`, and without `timezone` in the **host's local zone**, as cron reads it. `next_run_iso8601` carries that zone's offset, and the response's `next_run_timezone` names the zone used for entries without their own `CRON_TZ`. If the cron is not cronie, `CRON_TZ` lines are ignored for next-run times and a warning says so. A `timezone` that is not an IANA zone name (such as `Europe/Berlin` or `UTC`) is an error.
* An entry that follows a `CRON_TZ=` line has a `timezone` field with that zone.
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
  [timezone=<IANA zone>] [include_next_run=true|false]
  [now_unix=<seconds>] [allow_duplicate=true|false]
  [dry_run=true|false] [format=json|text] [timeout_ms=<ms>]
  cron backend only: [scope=current|user|system] [user=<name>]
  [cron_file=<path>]
  systemd backend only: [unit_name=<name>]
  [unit_scope=auto|user|system] [persistent=true|false]
  [accuracy_sec=<span>] [random_delay_sec=<span>]
  [service_user=<name>] [service_working_dir=<path>]
  [env=<KEY=VAL,...>] [env_<KEY>=<value>]
```

* `backend` defaults to `auto`, which uses **systemd whenever `systemctl --version` runs**, and cron otherwise. Pass `backend=cron` to get a crontab line on a systemd host. A requested backend whose tool is missing gives `cron.add_backend_unavailable` (exit 1).
* **Options of the other backend are refused** (exit 2, `cron.add_invalid_argument`, `field` naming the option), so nothing passed is silently ignored: the cron backend refuses `unit_name`, `unit_scope`, `persistent`, `accuracy_sec`, `random_delay_sec`, `service_user`, `service_working_dir`, `env` and `env_<KEY>`; the systemd backend refuses `scope`, `user` and `cron_file`. With `backend=auto` the check follows the backend chosen. Before this release they were ignored.
* Cron backend: `scope=current` (default) adds to the current user's crontab, `scope=user` to the crontab of `user=` (default: the current user), both through `crontab`; `scope=system` appends to `/etc/crontab` or `cron_file=` with a user column (`user=`, default `root`). `user` is refused with `scope=current`, and `cron_file` with any scope but `system`. `id` and `description` are written as a comment line above the job: `# job-id=<id> description=<text>`. `crontab` is run without `-u` for the user running resh, because cronie refuses `-u` to anyone but root.
* A crontab or cron file that exists but cannot be read is never replaced: `add` fails (`cron.add_error`, exit 1). A user without a crontab starts with an empty one.
* systemd backend: writes `<unit_name>.service` and `<unit_name>.timer` into `~/.config/systemd/user` (user scope) or `/etc/systemd/system` (system scope), runs `daemon-reload`, and enables and starts the timer (`systemctl enable --now`). `unit_scope=auto` means system for root and user otherwise. Before anything is written, the service manager of that scope must answer (`systemctl [--user] show`); otherwise `cron.add_systemd_unavailable` (exit 1). If `daemon-reload` or `enable` fails after the unit files were written, `add` fails with `cron.add_error` and the message names the files. The unit name is `unit_name`, else `id`, else derived from the command. `persistent` defaults to true.
* `env=KEY=VAL,KEY2=VAL2` items must each be `KEY=VALUE`; `env_<KEY>=<value>` sets one variable (and wins over `env`).
* `allow_duplicate` defaults to **true**, so the same job can be added twice. With `allow_duplicate=false`, an existing enabled job with the same schedule, command (whitespace aside), user column and time zone, or for systemd an existing timer of that unit name, makes `add` return `"ok": true, "duplicate": true` without writing.
* `include_next_run` (default true) reports the job's next run (`next_run_unix`, `next_run_iso8601`) and the zone it was computed in (`next_run_timezone`).
  * `now_unix` is the reference "now" the next run is counted from: Unix seconds from 0 to 253402300799 (up to the year 9999), default the current time. It changes only the reported next run, never the job. A value that is not an integer in that range is refused with `cron.add_invalid_argument` (`field` `now_unix`), exit 2.
  * The schedule is read in `timezone`, and without it in the **host's local zone**, which is where cron and systemd run a job without a zone.

**Host local zone.** Found the way the C library finds it: the `TZ` variable when set (a zone name, `:name`, or a zoneinfo path such as `/usr/share/zoneinfo/Europe/Berlin`), else the zone `/etc/localtime` links to, else `/etc/timezone` when that zone's current offset matches the host's. If none of these names a known zone (for example `TZ` holds a POSIX rule, or `/etc/localtime` is a plain copy), only the host's current UTC offset is known: next runs use that offset, `next_run_timezone` is the offset (such as `+03:00`), and a warning says the zone has no name and the offset does not follow daylight-saving changes.

**Time zones (`timezone=`).** The value must be an IANA time zone name such as `Europe/Berlin`, `America/New_York` or `UTC`; anything else is refused with `cron.add_invalid_argument` (`field` `timezone`) and exit 2 for both backends.

* systemd backend: the zone is added to the timer's calendar expression, for example `OnCalendar=2:0 Europe/Berlin`, and systemd runs the timer in that zone.
* Cron backend: only **cronie** honors `CRON_TZ`. Debian/Ubuntu cron and busybox crond ignore it without any error. So the cron backend refuses `timezone` (`cron.add_timezone_unsupported`, exit 2, also with `dry_run`) unless `crontab -V` prints a cronie version string. Only cronie's crontab has `-V`, and the crontab command and the daemon come from the same package. If the cron cannot be identified as cronie, `timezone` is refused, never written.
* With cronie, a `CRON_TZ=` line applies to every following line in the same file. An empty `CRON_TZ=` does not fully reset it either: cronie handles such jobs differently while the default zone changes DST. So `add` keeps zoned jobs in a block at the end of the file, and each zoned job has its own `CRON_TZ` line:

  ```text
  <existing lines, and jobs added later without a time zone>
  # resh: time-zone block - each job below runs in the CRON_TZ set just above it; add jobs without a time zone above this line
  CRON_TZ=Europe/Berlin
  # job-id=backup
  0 2 * * * /opt/backup.sh
  CRON_TZ=America/New_York
  30 6 * * * /opt/report.sh
  ```

  Jobs above the block are not affected. Later `add` calls insert jobs without a zone above the marker line and append zoned jobs to the block, each with its own `CRON_TZ` line. `rm` removes a job's `CRON_TZ` line with it when nothing but blank lines separates that line from the next `CRON_TZ` line or the end of the file. Removing it then changes no other job. The marker goes once the block is empty. `disable` and `enable` leave `CRON_TZ` lines in place. `list`, `rm`, `enable` and `disable` report each job's `timezone`. A job you add **by hand** below the block runs in the zone of the `CRON_TZ` line above it, as cronie reads the file; add such jobs above the marker.

**Argument checks (since v1.0.4-beta).** Before anything is written, and before a dry-run preview is returned, every value is checked against the syntax of the place it is written to. A refused value gives `"ok": false`, exit 2, error code `cron.add_invalid_argument` and `error.field` naming the argument:

* No argument may contain a line break or other control character.
* `schedule` is required (`cron.add_missing_schedule`) and `command` must be given and not blank (`cron.add_missing_command`).
* `schedule` must be five valid crontab fields or one of `@reboot`, `@yearly`, `@annually`, `@monthly`, `@weekly`, `@daily`, `@midnight`, `@hourly`; anything else gives `cron.add_invalid_schedule` (exit 2). Each field is checked as cron reads it: minute 0-59, hour 0-23, day 1-31, month 1-12 or `jan`-`dec`, weekday 0-7 (0 and 7 are Sunday) or `sun`-`sat`; `*`, lists, ranges and `/step` (step 1 or more), no reversed ranges. A step after a single value (`5/10`) is refused because cronie and Debian's cron both reject it; write `5-59/10`.
* `id` is 1-128 characters of letters, digits and `. _ @ : + -`.
* Cron backend: `command` must not contain an unescaped `%` (cron would turn it into a line break and feed the rest to the command's standard input); write `\%` for a literal `%`. As in cron, `\\` is an escaped backslash, so the `%` in `\\%` is unescaped and refused. `user` must be a user name. With `scope=system`, `cron_file` must be `/etc/crontab` or `/etc/cron.d/<name>` with a name of letters, digits, `_` and `-`, and resh refuses to read or write it through a symbolic link. The file is replaced atomically (through a hidden temporary file in the same directory, which cron ignores) and keeps its permission bits; if it exists but cannot be read, `add` fails instead of replacing it.
* systemd backend: the unit name (`unit_name`, else `id`, else derived from the command) must be letters, digits and `_ . : @ -`, not starting with `-` or `.` and not ending with `@`. `service_user` must be a user name, `service_working_dir` an absolute path (or `~`), `accuracy_sec`/`random_delay_sec` a time span such as `30s` or `5min`, and `env` names letters, digits and `_`. `command` must not start with a systemd `ExecStart=` prefix (`@ - : + !`), and no value written into a unit may end with a backslash. Existing unit files that are symbolic links are not replaced.

In the unit files, `%` is written as `%%` (so it is not a systemd specifier) and `env` values are escaped for systemd's double quotes, so each value means exactly what was passed. The timer is enabled with `systemctl enable --now -- <unit>.timer`.

**Schedule translation (systemd backend).** The crontab schedule becomes an `OnCalendar=` expression with the same runs. Lists, ranges and steps are written out value by value; weekdays become `Sun`..`Sat`. Examples: `0 2 * * *` → `2:0`, `* * * * *` → `*:*` (every minute), `*/15 * * * *` → `*:0,15,30,45`, `0 9-17 * * *` → `9,10,11,12,13,14,15,16,17:0`, `30 6 * * mon-fri` → `Mon,Tue,Wed,Thu,Fri *-*-* 6:30`, `0 3 1,15 * *` → `*-*-1,15 3:0`, `@weekly` and `0 0 * * 0` → `Sun *-*-* 0:0`; `0 * * * *`, `0 0 * * *`, `0 0 1 * *`, `0 0 1 1 *` (and `@hourly`, `@daily`/`@midnight`, `@monthly`, `@yearly`/`@annually`) become `hourly`, `daily`, `monthly`, `yearly`. Two schedules are refused with `cron.add_schedule_translation_unsupported` (exit 2, nothing written): `@reboot`, and a schedule whose day-of-month and weekday fields are both restricted (cron runs it when either matches; a calendar expression needs both). Before this release `* * * * *` ran every second, `@weekly` ran on Mondays, hour ranges gave invalid expressions, and steps and day restrictions were refused.

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
    "next_run_timezone": "UTC",
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
  [cron_file=<path>] [unit_scope=auto|user|system|both] [require_match=true|false]
  [dry_run=true|false] [format=json|text] [timeout_ms=<ms>]
  rm only:      [remove_units=true|false]
  enable only:  [start_now=true|false]
  disable only: [stop_now=true|false]
```

**Selectors.** At least one is required (`cron.<verb>_no_selector`, exit 2), and **every selector given must match**:

| Selector | Crontab job | systemd timer |
| -------- | ----------- | ------------- |
| `id` | the `# job-id=<id>` comment directly above the job | the `[id=<id>]` that `add` writes into the unit Description |
| `schedule` | the five fields (or `@` keyword), whitespace aside | never matches a timer |
| `command` | the command, whitespace aside | the service's `ExecStart` as `add` writes it for that command |
| `match_command` | case-insensitive substring of the command | substring of the service's `ExecStart` |
| `match_comment` | substring of the comment line above the job or its inline ` # comment` | substring of the timer and service Descriptions |
| `unit_name` | never matches a crontab job | the timer name, with or without `.timer` |
| `match_unit` | never matches a crontab job | substring of the timer name |

`id`, `command`, `match_command` and `match_comment` read the unit files in the unit directory `add` uses (`~/.config/systemd/user` or `/etc/systemd/system`), so for timers installed elsewhere only `unit_name` and `match_unit` match. Before this release `rm` required all selectors while `enable` and `disable` took any one of them (and ignored `schedule` without `command`).

Selector values are checked like `add`'s: `id` as a job id, `schedule` as a crontab schedule, `unit_name` as a unit name; an empty value is refused (an empty `match_command` would match every job).

**Targets.**

* `backend` defaults to `both` and `scope` defaults to `all`: the current user's crontab, the crontabs of `users=` (accepted with `scope=user` and `scope=all` only), `/etc/crontab` and `/etc/cron.d`. Narrow them (for example `backend=cron scope=current`) to avoid touching system files. `scope=user` requires `users=`.
* `cron_file=<path>` makes the verb act on that system cron file only, instead of the crontabs chosen by `scope`. It must be `/etc/crontab` or `/etc/cron.d/<name>`, as for `add`; any other path is refused (exit 2, `cron.<verb>_invalid_argument`, `field` `cron_file`) and nothing is read or written. A missing file matches nothing.
* With `backend=cron`, `unit_name`, `match_unit`, `unit_scope` and the verb's timer option (`remove_units`, `start_now`, `stop_now`) are refused; with `backend=systemd`, `schedule`, `scope`, `users` and `cron_file` are refused (exit 2, `cron.<verb>_invalid_argument`). Since this release `disable` checks `scope`, `users` and `unit_scope` like `rm` and `enable`.
* System files have a user column: `command` and `match_command` see the command after it, and entries report that user.

**Changes.**

* `disable` comments a crontab line out by prefixing `# `; `enable` removes the prefix. A commented line counts as a disabled job only when it is one (five valid time fields or an `@` keyword, the user column in system files, and a command); ordinary comments are never uncommented. A commented line that is itself a valid cron entry (such as an example in a distribution's crontab header) is treated as a disabled job and can be enabled by a broad `match_command`.
* `rm` removes a job, enabled or disabled, with its `# job-id=` comment line.
* A user crontab is read and written through `crontab` (`-u` only for another user). A crontab that cannot be read is a failure when it was named (`scope=current`, `scope=user`, `users=`, `cron_file`) and a warning otherwise (`scope=all` and `scope=system`).
* systemd timers are found with `systemctl list-timers --all` and `systemctl list-unit-files --type=timer`, so a disabled, stopped timer that systemd no longer has loaded is found too. `disable` disables the timer and, with `stop_now` (default true), stops it. `enable` enables it and, with `start_now` (default true), starts it (`enable --now`). `rm` stops and disables it and, with `remove_units` (default true), deletes the `.timer` and `.service` files from the unit directory and runs `daemon-reload`. A timer counts as already enabled when it is enabled (and, with `start_now`, active), and as already disabled when it is disabled (and, with `stop_now`, not active).
* `unit_scope=auto` is the system manager for root and the user manager otherwise. If that service manager does not answer, the systemd part is skipped with a warning when `backend=both`, and the verb fails (`cron.<verb>_error`, exit 1) when `backend=systemd`.
* `require_match` defaults to true: if nothing matches (jobs already in the wanted state count as matches), the response has `"ok": false` with code `cron.<verb>_no_match` and resh exits 1.
* **Partial failure.** If a crontab, cron file or timer could not be changed, the verb fails with `cron.<verb>_error` (exit 1) and the message lists what failed. The response still lists the changes that were made; a job that could not be changed is not listed.

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

### 3.5 Errors

```json
{
  "ok": false,
  "error": {
    "code": "cron.add_invalid_schedule",
    "field": "schedule",
    "message": "Invalid cron schedule '0 0 * * 8': schedule weekday 8 is out of range 0-7"
  }
}
```

stderr: `Error: [cron.add_invalid_schedule] Invalid cron schedule '0 0 * * 8': ...`

| Code | Exit | When |
| ---- | ---- | ---- |
| `cron.invalid_argument` | 2 | Unknown verb, an argument that is not `key=value`, or a malformed `dry_run` (the last two are reported by resh before the handle runs, without JSON) |
| `cron.list_invalid_argument` | 2 | A `list` argument is unknown or invalid (`field` names it) |
| `cron.add_invalid_argument` | 2 | An `add` argument is unknown or invalid, or belongs to the other backend |
| `cron.add_missing_schedule` | 2 | `add` without `schedule` |
| `cron.add_missing_command` | 2 | `add` without `command`, or with a blank one |
| `cron.add_invalid_schedule` | 2 | `schedule` is not a valid crontab schedule |
| `cron.add_timezone_unsupported` | 2 | `timezone` with the cron backend where cron is not cronie |
| `cron.add_schedule_translation_unsupported` | 2 | The schedule has no systemd calendar equivalent (`@reboot`, or both day fields restricted) |
| `cron.rm_invalid_argument`, `cron.enable_invalid_argument`, `cron.disable_invalid_argument` | 2 | An argument is unknown or invalid, or belongs to the backend that does not run |
| `cron.rm_invalid_backend`, `cron.enable_invalid_backend`, `cron.disable_invalid_backend` | 2 | `backend` is not `both`, `cron` or `systemd` |
| `cron.rm_no_selector`, `cron.enable_no_selector`, `cron.disable_no_selector` | 2 | No selector given |
| `cron.rm_no_match`, `cron.enable_no_match`, `cron.disable_no_match` | 1 | Nothing matched and `require_match` is true |
| `cron.add_backend_unavailable` | 1 | The requested backend's tool (`crontab`, `systemctl`) is missing, or neither is there for `auto` |
| `cron.add_systemd_unavailable` | 1 | The user or system service manager does not answer |
| `cron.list_error`, `cron.add_error` | 1 | Reading or writing failed (for example a crontab that cannot be read, `crontab` refusing the new crontab, `systemctl` failing) |
| `cron.rm_error`, `cron.enable_error`, `cron.disable_error` | 1 | A crontab that was named could not be read, or a change could not be made (partial failure: the response lists what was done) |
| `cron.failed` | 1 | An unexpected handle error reported by resh (such as standard output closed) |
| `cron.timeout` | 124 | `timeout_ms` passed; the running tool was stopped and the outcome is unknown |

---

## 3.6 Known limitations

These are current behaviors of this release, verified in `src/handles/processes/cronh.rs`:

* **Fixed in this release.** Next-run times now follow crontab's own rules (weekday 0 and 7 are Sunday; numeric weekdays were a day off before, and `0 0 * * 0` was refused), `@midnight` is accepted by `add`, and the systemd translation keeps every schedule's meaning (see 3.3).
* **Six-field expressions.** Before v1.0.4-beta `add` accepted a six-field form (with seconds) and wrote it unchanged, so cron read the sixth field as the start of the command. Such schedules are refused; use five fields.
* **systemd translation limits.** `@reboot` and schedules with both day fields restricted cannot be expressed as one `OnCalendar=` and are refused (3.3). Use `backend=cron` for them.
* **Daylight-saving changes.** Next-run times skip a local time that does not exist on a DST start day; cron implementations differ in how they run such jobs.
* **Timers installed elsewhere.** `rm`, `enable` and `disable` read `id`, commands and descriptions only from unit files in resh's unit directory (3.4).
* **`allow_duplicate` defaults to true.** Pass `allow_duplicate=false` to skip an identical existing job.
* **Next-run times use the host's local zone** without `timezone` (and without a `CRON_TZ` for the entry). Before this release they were computed in UTC. If the local zone cannot be named, its current offset is used and a warning says so (see 3.3).
* **Time zones with the cron backend need cronie.** See 3.3. Jobs typed in by hand below the time-zone block run in the zone above them.
* **Commands are code.** `command` is run by a shell (cron) or by systemd exactly as given; the checks above stop it from adding crontab lines or unit directives, not from doing what it says. Only schedule commands you trust. Before v1.0.4-beta line breaks in job fields and path characters in `unit_name` were not rejected (see 3.3).

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
* Commands are code (3.6): never pass untrusted input as a job field.
* Use `dry_run` before `rm`, `enable` or `disable` with broad selectors.
* A new crontab is handed to `crontab` on standard input from memory; no temporary file is written.

### 4.8 System Information

`list` reports the schedule, its fields, command, user, source file and line, enabled state, comment, the `CRON_TZ` zone of the entry, and optionally the next run time.

---

## 5. Platform Support

Linux only. Nothing was built or tested on macOS, BSD or Windows.

| Backend | Status |
| ------- | ------ |
| crontab | Every verb tested end to end in throwaway containers (`tests/cron_e2e_docker.rs`): cronie on Fedora (time zones, `-u` refused to non-root users) and Debian's cron, as root and as an ordinary user, checked with `crontab -l` and the cron files. |
| systemd timers | Every verb tested end to end in a container running systemd: timers created, listed, enabled, disabled and removed, checked with `systemctl list-timers` and `systemd-analyze calendar`. User units are covered by unit tests only. |

---

## 6. Operational Best Practices

### Safe usage

* Use `dry_run` first for every `add`, `rm`, `enable` and `disable`.
* Give jobs an `id` so they can be selected exactly later.
* Pass `backend=cron` or `backend=systemd` explicitly; `auto` picks systemd whenever `systemctl` exists.
* Narrow `scope` and `backend` for `rm`, `enable` and `disable` (the defaults are `all` and `both`).
* Prefer `disable` over `rm` for temporary changes.

### Automation

* Check the exit code (0, 1, 2 or 124); on failure read `error.code` and `error.message`.
* Set `timeout_ms` to bound a verb; after exit 124, check the state before retrying.

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
* Schedules are parsed and next-run times computed by resh itself, following cron's field rules; time zone names are checked against the IANA database built into the `chrono-tz` crate.
* Each `resh` invocation is a separate process; nothing is kept between calls.
* Unknown argument names are refused (exit 2).
