# Cron Handle Documentation

The Resource Shell's cron handle provides a complete way to manage scheduled tasks on your system. It works with both traditional cron jobs and modern systemd timers, letting you list, add, remove, enable, and disable scheduled tasks through a simple interface.

## How Cron Works

The cron handle manages two types of scheduled tasks:

- **Cron Jobs**: Traditional Unix cron jobs stored in user crontabs, system crontab, or `/etc/cron.d/` files
- **Systemd Timers**: Modern systemd timer units that trigger service units on a schedule

The handle automatically detects which backend to use or lets you specify which one you prefer.

## URL Format

Cron URLs follow this pattern:
```
cron://host.verb(arguments)
```

For most operations, the host part can be any name (like "local" or "system").

## Available Operations

The cron handle supports five main operations:

### list - Show Scheduled Tasks

Shows all scheduled tasks on your system with their details.

**Basic Usage:**
```bash
cron://local.list
```

**Output:**
```json
{
  "ok": true,
  "timestamp_unix_ms": 1701234567890,
  "scope": "current",
  "users": ["testuser"],
  "include_system": false,
  "truncated": false,
  "entries_total": 0,
  "entries_returned": 0,
  "entries_disabled": 0,
  "entries": [],
  "raw": null,
  "paths": null,
  "human": null,
  "error": null,
  "warnings": []
}
```

The `list` operation returns:
- **ok**: Whether the operation succeeded
- **scope**: What jobs were included ("current", "user", "system", "all")
- **users**: List of users whose jobs were checked
- **include_system**: Whether system-wide jobs were included
- **entries**: Array of scheduled task details
- **entries_returned**: Number of tasks found
- **entries_disabled**: Number of disabled tasks found

### add - Create New Scheduled Tasks

Creates a new scheduled task using cron or systemd.

**Basic Cron Job:**
```bash
cron://local.add(schedule=* * * * *,command=/usr/local/bin/backup)
```

**With Job ID and Description:**
```bash
cron://local.add(schedule=* * * * *,command=/usr/local/bin/backup,id=test-job,description=Test backup job)
```

**Output:**
```json
{
  "ok": true,
  "timestamp_unix_ms": 1701234567890,
  "backend_used": "cron",
  "dry_run": false,
  "duplicate": false,
  "job": {
    "id": "test-job",
    "backend": "cron",
    "schedule": "* * * * *",
    "command": "/usr/local/bin/backup",
    "location": {
      "scope": "current",
      "file": "/tmp/crontab",
      "user": "testuser",
      "line_added": 1,
      "unit_name": null,
      "timer_unit": null,
      "service_unit": null,
      "unit_dir": null
    }
  },
  "preview": null,
  "error": null,
  "warnings": []
}
```

**Arguments:**
- `schedule`: Cron schedule expression (required, e.g., "0 2 * * *" for daily at 2am)
- `command`: Command to run (required)
- `backend`: Which system to use ("cron", "systemd", or "auto")
- `id`: Unique identifier for the job
- `description`: Human-readable description
- `allow_duplicate`: Allow creating duplicate jobs (default: true)
- `dry_run`: Test without actually creating (default: false)
- `scope`: Where to create the job ("current", "user", "system")

**Error Cases:**
- Missing schedule returns error code "cron.add_error"
- Missing command returns error code "cron.add_error"
- Invalid schedule format returns error with validation details

### rm - Remove Scheduled Tasks

Removes scheduled tasks that match the given criteria.

**Remove by ID:**
```bash
cron://local.rm(id=test-job)
```

**Remove by Schedule and Command:**
```bash
cron://local.rm(schedule=0 2 * * *,command=/usr/local/bin/backup --full)
```

**Remove with Pattern Matching:**
```bash
cron://local.rm(match_command=backup)
```

**Output:**
```json
{
  "ok": true,
  "timestamp_unix_ms": 1701234567890,
  "dry_run": false,
  "backend": "both",
  "removed": {
    "cron": [],
    "systemd": []
  },
  "matched_count": {
    "cron": 0,
    "systemd": 0
  },
  "cron_modified_sources": [],
  "systemd_scopes_touched": [],
  "error": null,
  "warnings": []
}
```

**Arguments:**
- `id`: Job identifier to remove
- `schedule`: Exact schedule to match
- `command`: Exact command to match
- `match_command`: Pattern to match in command text
- `match_comment`: Pattern to match in job comments
- `backend`: Which system to check ("cron", "systemd", "both")
- `dry_run`: Test without actually removing (default: false)
- `scope`: Where to look for jobs ("current", "user", "system", "all")

**Error Cases:**
- No selector provided returns error code "cron.rm_no_selector"
- Invalid backend returns error code "cron.rm_invalid_backend"

### enable - Enable Disabled Tasks

Enables scheduled tasks that have been disabled (commented out or stopped).

**Enable by ID:**
```bash
cron://local.enable(id=backup-job,backend=cron)
```

**Enable by Schedule and Command:**
```bash
cron://local.enable(backend=cron,schedule=0 2 * * *,command=/usr/local/bin/backup --full)
```

**Enable by Command Pattern:**
```bash
cron://local.enable(backend=cron,match_command=backup)
```

**Output:**
```json
{
  "ok": true,
  "timestamp_unix_ms": 1701234567890,
  "dry_run": false,
  "backend": "cron",
  "enabled": {
    "cron": [
      {
        "id": "backup-job",
        "schedule": "0 2 * * *",
        "command": "/usr/local/bin/backup --full",
        "backend": "cron",
        "was_disabled": true,
        "location": {
          "scope": "current",
          "file": "/tmp/crontab",
          "user": "testuser",
          "line_number": 1,
          "unit_name": null,
          "timer_unit": null,
          "service_unit": null,
          "unit_dir": null
        }
      }
    ],
    "systemd": []
  },
  "matched_count": {
    "cron": 1,
    "systemd": 0
  },
  "already_enabled_count": {
    "cron": 0,
    "systemd": 0
  },
  "cron_modified_sources": [
    "/tmp/crontab"
  ],
  "systemd_scopes_touched": [],
  "error": null,
  "warnings": []
}
```

**Arguments:**
- `id`: Job identifier to enable
- `schedule`: Exact schedule to match
- `command`: Exact command to match
- `match_command`: Pattern to match in command text
- `backend`: Which system to use ("cron", "systemd", "both")
- `dry_run`: Test without actually enabling (default: false)
- `scope`: Where to look for jobs ("current", "user", "system", "all")

### disable - Disable Active Tasks

Disables scheduled tasks by commenting them out or stopping systemd timers.

**Disable by ID:**
```bash
cron://local.disable(id=backup-job,backend=cron)
```

**Disable by Schedule and Command:**
```bash
cron://local.disable(backend=cron,schedule=0 2 * * *,command=/usr/local/bin/backup --full)
```

**Disable with Command Pattern:**
```bash
cron://local.disable(match_command=backup)
```

**Output:**
```json
{
  "ok": true,
  "timestamp_unix_ms": 1701234567890,
  "dry_run": false,
  "backend": "cron",
  "disabled": {
    "cron": [
      {
        "id": "backup-job",
        "schedule": "0 2 * * *",
        "command": "/usr/local/bin/backup --full",
        "backend": "cron",
        "was_enabled": true,
        "location": {
          "scope": "current",
          "file": "/tmp/crontab",
          "user": "testuser",
          "line_number": 1,
          "unit_name": null,
          "timer_unit": null,
          "service_unit": null,
          "unit_dir": null
        }
      }
    ],
    "systemd": []
  },
  "matched_count": {
    "cron": 1,
    "systemd": 0
  },
  "already_disabled_count": {
    "cron": 0,
    "systemd": 0
  },
  "cron_modified_sources": [
    "/tmp/crontab"
  ],
  "systemd_scopes_touched": [],
  "error": null,
  "warnings": []
}
```

**Arguments:**
- `id`: Job identifier to disable
- `schedule`: Exact schedule to match
- `command`: Exact command to match
- `match_command`: Pattern to match in command text
- `backend`: Which system to use ("cron", "systemd", "both")
- `dry_run`: Test without actually disabling (default: false)
- `stop_now`: Stop running systemd timers immediately (default: true)
- `scope`: Where to look for jobs ("current", "user", "system", "all")

## Understanding Cron Schedules

Cron schedules use five fields separated by spaces:
```
* * * * *
| | | | |
| | | | +-- Day of Week (0-6, Sunday=0)
| | | +---- Month (1-12)
| | +------ Day of Month (1-31)
| +-------- Hour (0-23)
+---------- Minute (0-59)
```

**Examples:**
- `0 2 * * *` - Daily at 2:00 AM
- `*/5 * * * *` - Every 5 minutes
- `0 0 * * 0` - Weekly on Sunday at midnight
- `0 9-17 * * 1-5` - Hourly during business hours (9 AM - 5 PM, Monday - Friday)

## Backends

The cron handle supports two backends:

### Cron Backend
- Uses traditional Unix cron system
- Jobs stored in user crontabs or system files
- Good for simple scheduled tasks
- Works on all Unix-like systems

### Systemd Backend
- Uses systemd timers and services
- More powerful scheduling options
- Better logging and monitoring
- Requires systemd (most modern Linux systems)

### Auto Backend
When you use `backend=auto`, the handle will:
1. Try systemd first if available
2. Fall back to cron if systemd is not available
3. Choose the best option based on the task requirements

## Common Use Cases

**Daily Backup:**
```bash
cron://local.add(schedule=0 2 * * *,command=/usr/local/bin/backup,id=daily-backup,description=Daily system backup)
```

**Check Disk Space Every Hour:**
```bash
cron://local.add(schedule=0 * * * *,command=/usr/local/bin/disk-check,id=disk-monitor)
```

**Remove All Backup Jobs:**
```bash
cron://local.rm(match_command=backup)
```

**Temporarily Disable a Job:**
```bash
cron://local.disable(id=daily-backup)
```

**Re-enable the Job Later:**
```bash
cron://local.enable(id=daily-backup)
```

**Test What Would Be Removed:**
```bash
cron://local.rm(match_command=backup,dry_run=true)
```

## Error Handling

All operations return detailed error information when something goes wrong:

```json
{
  "ok": false,
  "error": {
    "code": "cron.add_error",
    "message": "schedule parameter is required"
  }
}
```

Common error codes:
- `cron.add_error`: Problem creating a scheduled task
- `cron.rm_error`: Problem removing scheduled tasks
- `cron.rm_no_selector`: No criteria provided for removal
- `cron.rm_invalid_backend`: Invalid backend specified
- `cron.list_error`: Problem listing scheduled tasks