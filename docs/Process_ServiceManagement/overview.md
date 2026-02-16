# Resource Shell (resh) – Process & Service Management Overview Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using structured URI-based commands. It provides typed handles for managing processes, services, and scheduled tasks in a deterministic and automation-friendly manner.

### Purpose

resh enables:

* Structured management of running processes
* Declarative service lifecycle control
* Scheduled task configuration
* Machine-readable output for automation and orchestration

resh replaces traditional text-based CLI tooling with structured command invocation and JSON output contracts.

### Architectural Problem Addressed

Traditional process and service tooling:

* Produces unstructured text output
* Varies across init systems (systemd, OpenRC, cron)
* Requires shell parsing for automation
* Lacks consistent output schemas

resh addresses these issues by:

* Exposing process, service, and scheduling capabilities via typed handles
* Standardizing verbs and input parameters
* Returning structured JSON output
* Supporting deterministic execution semantics

### Resource-Oriented URI Model

resh commands follow:

```
handle://target.verb(options)
```

For process and service management:

* **handle**: `cron://`, `proc://`, `svc://`
* **target**: Resource identifier (e.g., PID, service name, local scheduler)
* **verb**: Operation (e.g., `status`, `list`, `start`, `stop`)
* **options**: Structured parameters (where applicable)

Examples:

```
cron://local.list
proc://1234.status
svc://nginx.restart
```

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

* Each domain is exposed via a distinct handle.
* Operations are defined as explicit verbs.
* Targets are clearly identified (PID, service name, scheduler).
* Output is standardized in JSON format.

---

### Safety-First Execution

* Explicit verbs required for state-changing operations.
* No implicit destructive behavior.
* Clear separation between inspection and modification.
* Platform-specific limitations are documented.

---

### Deterministic Behavior

* Identical inputs yield consistent structured outputs.
* Exit behavior reflects operation success or failure.
* Service management operations respect system init configuration.

---

### JSON-Based Structured Output

All operations return JSON objects describing:

* Target metadata
* Operation result
* Status indicators
* Error information (when applicable)

Representative example:

```json
{
  "ok": true,
  "service": "nginx",
  "status": "running",
  "enabled": true,
  "manager": "systemd"
}
```

---

### AI-Readiness

Structured output enables:

* Automated health checks
* Programmatic service orchestration
* Scheduled task validation
* Process state reasoning

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
handle://target.verb(options)
```

| Component | Description                    |
| --------- | ------------------------------ |
| `handle`  | `cron://`, `proc://`, `svc://` |
| `target`  | Resource identifier            |
| `verb`    | Operation to perform           |
| `options` | Optional structured parameters |

---

### Production Examples

#### List Scheduled Tasks

```
cron://local.list
```

#### Add Scheduled Task

```
cron://local.add(schedule="0 2 * * *", command="/usr/bin/backup.sh")
```

#### Check Process Status

```
proc://1234.status
```

#### Change Process Priority

```
proc://1234.renice(priority=10)
```

#### Check Service Status

```
svc://nginx.status
```

#### Restart Service

```
svc://postgresql.restart
```

#### Enable Service at Boot

```
svc://nginx.enable
```

---

## 3.2 Execution Semantics

### Deterministic Behavior

* Operations require explicit targets.
* No implicit service resolution.
* Verb-based design prevents ambiguous operations.
* Platform-specific backends selected automatically (e.g., systemd vs OpenRC).

---

### Structured Output Contracts

Each operation returns:

* `ok` status
* Target information
* Result metadata
* Backend manager identification (when applicable)

Example (process status):

```json
{
  "ok": true,
  "pid": 1234,
  "name": "backup.sh",
  "state": "running",
  "priority": 0,
  "cpu_usage_percent": 2.3,
  "memory_usage_mb": 15.4
}
```

---

### Error Handling Structure

Representative error:

```json
{
  "ok": false,
  "error": {
    "code": "svc.service_not_found",
    "message": "Service 'unknown' does not exist"
  }
}
```

Errors are structured and machine-readable.

---

## 4. Functional Domains

---

### 4.1 Automation Utilities

**Scope**

Infrastructure task automation and scheduling.

**Handles**

* `cron://`

**Use Cases**

* Daily backups
* System maintenance tasks
* Monitoring scripts
* Cleanup jobs

**Integration Scenarios**

* Schedule database dumps
* Trigger log rotation tasks
* Periodic health checks

---

### 4.2 Data & State Management

**Scope**

Inspection of process and service state.

**Handles**

* `proc://`
* `svc://`

**Use Cases**

* Retrieve service status
* Inspect process runtime data
* Validate scheduled jobs

---

### 4.3 Filesystem & Storage

Indirectly supports:

* Scheduled file cleanup
* Backup execution
* Log management automation

---

### 4.4 Network & Remote Operations

Supports management of:

* Network-facing services (e.g., web servers)
* Background daemons
* Infrastructure services

Example:

```
svc://apache2.status
```

---

### 4.5 Packages & Software

Supports lifecycle management of installed services:

* Restart after package updates
* Enable service post-install
* Disable deprecated services

---

### 4.6 Process & Service Management

**Handles**

* `cron://`
* `proc://`
* `svc://`

**Capabilities**

* Schedule tasks
* Manage PIDs
* Send signals
* Adjust process priority
* Start/stop/restart services
* Enable/disable services at boot

---

### 4.7 Security & Secrets

Security considerations include:

* Restricting service enablement
* Limiting process privilege changes
* Reviewing scheduled tasks
* Preventing unauthorized service activation

---

### 4.8 System Information

Provides structured reporting for:

* Service health
* Process runtime metrics
* Scheduler configuration
* Backend init system (systemd, OpenRC)
* Task schedules

---

## 5. Platform Support

| Platform   | Support Level                                                     |
| ---------- | ----------------------------------------------------------------- |
| Linux      | Full support                                                      |
| Unix/macOS | Most features supported (systemd-specific features may not apply) |
| Windows    | Limited support                                                   |

Platform compatibility depends on:

* Availability of init system (systemd, OpenRC)
* Native scheduling tools
* Process control capabilities

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Validate service existence before modification.
* Use status inspection before restart.
* Avoid disabling critical system services.
* Audit scheduled tasks regularly.

---

### Automation Considerations

* Consume structured JSON output.
* Validate `ok` before proceeding.
* Avoid parsing human-readable output.
* Use deterministic schedules in cron.

---

### CI/CD Integration

Typical workflow:

1. Deploy updated service binary.
2. Restart service via `svc`.
3. Verify status.
4. Schedule recurring maintenance with `cron`.
5. Monitor long-running jobs with `proc`.

---

### Production Environment Recommendations

* Enable only required services at boot.
* Document scheduled jobs.
* Monitor high-CPU processes.
* Limit process priority changes to necessary cases.
* Test restart procedures in staging before production rollout.

---

## 7. Use Cases by Role

### DevOps Engineers

* Automate service restarts post-deployment.
* Schedule recurring maintenance jobs.
* Validate process state in pipelines.

---

### SRE Engineers

* Diagnose failed services.
* Restart or reload services during incidents.
* Inspect process metrics during outages.

---

### Network Administrators

* Manage network-facing daemons.
* Enable/disable services at boot.
* Monitor service health.

---

### AI / Automation Engineers

* Consume structured service health metadata.
* Automate remediation workflows.
* Trigger escalations based on process state.
* Validate scheduled job integrity programmatically.

---

## 8. Technical Foundation

### Rust Implementation Advantages

resh is implemented in Rust, providing:

* Memory safety
* Strong compile-time guarantees
* Predictable execution
* Efficient system call management

---

### Type Safety

* Explicit verb enumeration
* Strict parameter validation
* Structured error typing
* Deterministic output schemas

---

### Performance Characteristics

* Native binary execution
* Low overhead process invocation
* Controlled timeout and scheduling logic

---

### Cross-Platform Architecture

* Backend abstraction for systemd and OpenRC
* Cron and systemd timer support
* Consistent structured output across supported systems
