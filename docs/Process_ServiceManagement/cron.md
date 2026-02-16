# Resource Shell (resh) – Cron Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using structured URI-based commands. The `cron://` handle provides structured management of scheduled tasks across supported backends.

### Purpose

The cron handle enables:

* Listing scheduled tasks
* Creating scheduled jobs
* Removing jobs
* Enabling and disabling tasks
* Managing both traditional cron jobs and systemd timers

All operations return structured JSON suitable for automation workflows.

### Architectural Problem Addressed

Traditional scheduling mechanisms:

* Use backend-specific interfaces (cron, systemd timers)
* Produce unstructured output
* Require manual file editing or service interaction
* Provide inconsistent error reporting

resh addresses these issues by:

* Exposing scheduling operations through typed verbs
* Standardizing parameter formats
* Supporting multiple backends under a single interface
* Returning structured JSON responses
* Providing explicit exit codes and error identifiers

### Resource-Oriented URI Model

Cron operations follow:

```
handle://target.verb(arguments)
```

For scheduling:

* **handle**: `cron://`
* **target**: Logical host identifier (e.g., `local`, `system`)
* **verb**: `list`, `add`, `rm`, `enable`, `disable`
* **arguments**: Structured parameters

Examples:

```
cron://local.list
cron://local.add(schedule="0 2 * * *",command="/usr/local/bin/backup")
cron://local.rm(id="daily-backup")
```

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

* Explicit verbs define scheduling lifecycle operations.
* Parameters are defined per verb.
* Scope and backend selection are explicit.
* Structured output replaces manual crontab inspection.

---

### Safety-First Execution

* `dry_run` supported for state-changing verbs.
* Explicit selectors required for removal.
* Permission-aware scope management.
* Backend validation before execution.

---

### Deterministic Behavior

* Identical inputs yield consistent structured responses.
* Explicit backend selection (`cron`, `systemd`, `auto`).
* Scope values strictly enforced.
* Clear error codes for missing or invalid arguments.

---

### JSON-Based Structured Output

All operations return:

* `ok` boolean
* Operation metadata
* Backend identification
* Matched and modified entries
* Error and warning arrays

Representative example:

```json
{
  "ok": true,
  "backend_used": "cron",
  "dry_run": false,
  "matched_count": {
    "cron": 1,
    "systemd": 0
  },
  "error": null,
  "warnings": []
}
```

---

### AI-Readiness

Structured output enables:

* Scheduled task auditing
* Automated compliance checks
* Drift detection
* Bulk job management
* Backend-aware orchestration

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
cron://host.VERB(arguments)
```

| Component   | Description                        |
| ----------- | ---------------------------------- |
| `handle`    | `cron://`                          |
| `host`      | Logical identifier (e.g., `local`) |
| `VERB`      | Scheduling operation               |
| `arguments` | Structured parameters              |

---

### Core Verbs

| Verb      | Description           |
| --------- | --------------------- |
| `list`    | Show scheduled tasks  |
| `add`     | Create scheduled task |
| `rm`      | Remove scheduled task |
| `enable`  | Enable disabled task  |
| `disable` | Disable active task   |

---

### Production Examples

#### List Current User Jobs

```
cron://local.list(scope="current")
```

#### Add Daily Backup

```
cron://local.add(
  schedule="0 2 * * *",
  command="/usr/local/bin/backup",
  id="daily-backup"
)
```

#### Remove Matching Jobs

```
cron://local.rm(match_command="backup",dry_run=true)
```

#### Disable System Job

```
cron://local.disable(id="cleanup",scope="system")
```

#### Enable All Monitoring Jobs

```
cron://local.enable(match_command="monitor",backend="both")
```

---

## 3.2 Execution Semantics

### Deterministic Behavior

* Verbs require explicit arguments.
* Removal requires selector criteria.
* Backend availability validated before execution.
* Scope controls permission boundaries.

---

### Structured Output Contracts

Example output from `list`:

```json
{
  "ok": true,
  "scope": "current",
  "entries_total": 2,
  "entries_returned": 2,
  "entries_disabled": 0,
  "entries": [
    {
      "id": "daily-backup",
      "schedule": "0 2 * * *",
      "command": "/usr/local/bin/backup",
      "backend": "cron"
    }
  ],
  "error": null,
  "warnings": []
}
```

---

### Error Handling Structure

Example error:

```json
{
  "ok": false,
  "error": {
    "code": "cron.add_missing_schedule",
    "message": "schedule parameter is required"
  }
}
```

Defined exit codes include:

| Code | Meaning             |
| ---- | ------------------- |
| 0    | Success             |
| 1    | General error       |
| 2    | Invalid arguments   |
| 3    | Permission denied   |
| 4    | Job not found       |
| 5    | Duplicate job       |
| 6    | Invalid schedule    |
| 7    | Backend unavailable |

---

## 4. Functional Domains

---

### 4.1 Automation Utilities

**Scope**

Time-based job automation.

**Handle**

* `cron://`

**Use Cases**

* Scheduled backups
* Health checks
* Cleanup routines
* Log rotation

---

### 4.2 Data & State Management

**Scope**

Inspection and auditing of scheduled tasks.

**Use Cases**

* Compliance verification
* Duplicate detection
* Disabled job auditing
* Drift detection

---

### 4.3 Filesystem & Storage

Indirectly supports:

* Scheduled backup scripts
* File cleanup tasks
* Log maintenance automation

---

### 4.4 Network & Remote Operations

Supports scheduling of:

* Remote synchronization tasks
* Monitoring probes
* Periodic network checks

---

### 4.5 Packages & Software

Supports lifecycle operations for:

* Scheduled software updates
* Dependency cleanup jobs
* Automated package validation tasks

---

### 4.6 Process & Service Management

Coordinates with:

* `proc://` for process monitoring
* `svc://` for service restarts triggered by schedule

---

### 4.7 Security & Secrets

Security considerations:

* Avoid embedding sensitive data in commands.
* Use secure scripts instead of inline secrets.
* Restrict system-scope job modification.
* Audit scheduled tasks regularly.

---

### 4.8 System Information

Structured reporting includes:

* Job ID
* Schedule expression
* Backend type
* Scope
* Disabled state
* Backend file or unit references

---

## 5. Platform Support

| Platform | Support                       |
| -------- | ----------------------------- |
| Linux    | Full support (cron + systemd) |
| macOS    | Cron support (no systemd)     |
| BSD      | Cron support                  |
| Windows  | Not supported                 |

Backend behavior depends on system capabilities.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Always test with `dry_run=true`.
* Use job IDs for manageability.
* Validate schedules before deployment.
* Prefer disable over remove for temporary changes.
* Avoid overlapping execution schedules.

---

### Automation Considerations

* Consume JSON output.
* Validate `ok` before proceeding.
* Use backend filtering to limit scope.
* Avoid parsing raw crontab content.

---

### CI/CD Integration

Typical workflow:

1. Add maintenance job.
2. Validate via `list`.
3. Disable during deployment.
4. Re-enable post-deployment.
5. Audit system-wide schedules.

---

### Production Recommendations

* Distribute heavy jobs across time windows.
* Use systemd backend for advanced scheduling.
* Review system-wide jobs periodically.
* Log job output and errors.
* Maintain backup of scheduling configuration.

---

## 7. Use Cases by Role

### DevOps Engineers

* Automate recurring operational tasks.
* Manage scheduled CI-related jobs.
* Audit deployment-time cron changes.

---

### SRE Engineers

* Diagnose failed scheduled tasks.
* Disable problematic jobs during incidents.
* Audit system-wide schedules for compliance.

---

### Network Administrators

* Schedule monitoring and maintenance.
* Manage cleanup jobs.
* Audit system-level scheduled tasks.

---

### AI / Automation Engineers

* Parse structured job inventory.
* Detect unauthorized job changes.
* Trigger remediation workflows.
* Validate scheduling policy compliance.

---

## 8. Technical Foundation

### Rust Implementation Advantages

resh is implemented in Rust, providing:

* Memory safety
* Predictable concurrency behavior
* Structured command parsing
* Efficient file and system interaction

---

### Type Safety

* Enumerated verbs
* Strict argument validation
* Structured error codes
* Controlled backend selection

---

### Performance Characteristics

* Minimal overhead for listing and modification
* Direct crontab and systemd interaction
* Controlled file I/O operations

---

### Cross-Platform Architecture

* Backend abstraction layer for cron and systemd
* Scope-based permission control
* Unified JSON output across supported platforms

