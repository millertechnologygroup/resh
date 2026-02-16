# Resource Shell (resh) – Proc Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using structured URI-based commands. The `proc://` handle provides structured process control capabilities, including signaling, priority management, output inspection, and resource limit configuration.

### Purpose

The process control domain enables:

* Sending POSIX signals to running processes
* Managing process scheduling priority (nice values and priority classes)
* Inspecting process output streams
* Applying resource limits using rlimit controls

All operations return structured JSON responses suitable for automation and infrastructure orchestration.

### Architectural Problem Addressed

Traditional process management tooling:

* Produces unstructured text output
* Requires manual interpretation of signal behavior
* Varies in syntax across commands (`kill`, `renice`, `ulimit`)
* Lacks consistent automation contracts

resh addresses these limitations by:

* Exposing process operations as typed verbs
* Standardizing parameter validation
* Providing structured JSON output
* Enforcing explicit argument requirements
* Defining deterministic exit codes

### Resource-Oriented URI Model

Process control operations follow:

```
handle://target.verb(options)
```

For process control:

* **handle**: `proc://`
* **target**: Process ID (PID) or `self`
* **verb**: Process operation
* **options**: Operation-specific parameters

Examples:

```
proc://1234.term
proc://self.nice.get
proc://1234.limits.set(nofile=4096:8192)
```

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

* Sixteen verbs organized into logical categories:

  * Signal Operations
  * Priority Operations
  * Output Monitoring
  * Resource Limits
* Explicit argument validation per verb
* Structured JSON response schema for all operations
* Built-in help system accessible via `resh proc:// --help`

---

### Safety-First Execution

* Explicit PID required for all operations
* Missing arguments result in structured errors
* `dry_run` supported for resource limits
* Clear separation between inspection and modification
* Permission enforcement aligned with OS policies

---

### Deterministic Behavior

* Identical input produces consistent JSON output
* Explicit signal naming or numbering
* Strict nice value range enforcement (-20 to 19)
* Structured backend reporting for limit changes

---

### JSON-Based Structured Output

All operations return structured JSON including:

* `pid`
* `verb`
* Operation result fields
* `ok` boolean
* `error` (if applicable)

Representative example:

```json
{
  "pid": 1234,
  "verb": "term",
  "signal": "TERM",
  "signal_num": 15,
  "ok": true
}
```

---

### AI-Readiness

Structured output enables:

* Automated signal escalation workflows
* Programmatic priority enforcement
* Process output monitoring
* Automated resource sandboxing
* Deterministic remediation logic

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
proc://PID.verb(arguments)
proc://self.verb(arguments)
```

| Component   | Description           |
| ----------- | --------------------- |
| `handle`    | `proc://`             |
| `PID`       | Process ID number     |
| `self`      | Current process       |
| `verb`      | Operation             |
| `arguments` | Structured parameters |

---

### Core Categories and Examples

---

### Signal Operations

Send signals by name or number:

```
proc://1234.signal(sig=TERM)
proc://1234.kill
proc://1234.term
proc://1234.hup
proc://1234.stop
proc://1234.cont
```

Supported signal references include:

* SIGHUP (1)
* SIGINT (2)
* SIGQUIT (3)
* SIGKILL (9)
* SIGTERM (15)
* SIGSTOP (19)
* SIGCONT (18)
* SIGUSR1 (30)
* SIGUSR2 (31)

---

### Priority Operations

Inspect and modify nice values:

```
proc://self.nice.get
proc://1234.nice.set(value=5)
proc://1234.nice.inc(delta=1)
proc://1234.nice.dec(delta=1)
proc://1234.setPriority(class=background)
```

Nice range: `-20` (highest priority) to `19` (lowest priority)

Priority classes:

| Class      | Nice Value |
| ---------- | ---------- |
| idle       | 19         |
| background | 10         |
| normal     | 0          |
| high       | -5         |
| realtime   | -20        |

---

### Output Monitoring

Inspect process output logs:

```
proc://1234.io.peek
proc://1234.io.peek(stream=stderr)
proc://1234.io.peek(stream=both,max_bytes=200)
```

---

### Resource Limits

Apply rlimit-based constraints:

```
proc://1234.limits.set(nofile=4096:8192)
proc://self.limits.set(cpu=300s)
proc://1234.limits.set(as=1G,data=512M)
proc://1234.limits.set(dry_run=true,nofile=2048)
```

Supported limit types include:

* cpu
* as
* data
* stack
* core
* nofile
* fsize
* memlock
* nproc (Linux only)

---

## 3.2 Execution Semantics

### Deterministic Behavior

* Missing arguments produce structured errors.
* Invalid signal names are rejected.
* Nice values strictly validated.
* Resource limit values validated for format and range.
* Platform support enforced at runtime.

---

### Structured Output Contracts

Example: Resource limit application

```json
{
  "pid": 1234,
  "backend": "rlimit",
  "results": {
    "nofile": {
      "requested": "4096:8192",
      "before": {"soft":1024,"hard":4096},
      "after": {"soft":4096,"hard":8192},
      "status": "ok"
    }
  }
}
```

---

### Error Handling Structure

Example: Invalid signal

```json
{
  "pid": 1234,
  "verb": "signal",
  "ok": false,
  "error": "invalid signal: NOPE"
}
```

Defined exit codes:

| Code | Meaning                   |
| ---- | ------------------------- |
| 1    | General error             |
| 2    | Missing/invalid arguments |
| 3    | Process not found         |
| 4    | Permission denied         |
| 5    | Platform not supported    |

---

## 4. Functional Domains

---

### 4.1 Automation Utilities

**Handle:** `proc://`

**Scope**

* Automated process lifecycle control
* Signal-based remediation
* Priority tuning in automation pipelines

**Use Cases**

* Graceful shutdown escalation (TERM → KILL)
* Background job demotion
* Scheduled maintenance control

---

### 4.2 Data & State Management

**Scope**

* Process state inspection
* Nice value auditing
* Limit enforcement verification

---

### 4.3 Filesystem & Storage

Indirectly supports:

* Log inspection via `io.peek`
* Core dump size control
* File descriptor limits

---

### 4.4 Network & Remote Operations

Supports management of:

* Network daemons
* Service child processes
* Monitoring agents

---

### 4.5 Packages & Software

Supports:

* Post-install process tuning
* Priority adjustments after package updates
* Controlled restart sequencing

---

### 4.6 Process & Service Management

Primary capabilities:

* Signal delivery
* Priority control
* Output monitoring
* Resource limit enforcement

Works alongside:

* `svc://` for service-level control
* `cron://` for scheduled execution

---

### 4.7 Security & Secrets

Security considerations:

* Only signal owned processes (unless root)
* Avoid unnecessary SIGKILL usage
* Validate PID before destructive operations
* Restrict negative nice values to privileged contexts
* Avoid exposing sensitive data via `io.peek`

---

### 4.8 System Information

Structured reporting includes:

* PID
* Nice value
* Priority class
* Resource limits (soft/hard)
* Output stream metadata
* Backend identification

---

## 5. Platform Support

| Platform   | Support       |
| ---------- | ------------- |
| Unix/Linux | Full support  |
| Windows    | Not supported |

All verbs return platform error on unsupported systems.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Use SIGTERM before SIGKILL.
* Allow cleanup time after graceful signals.
* Validate PID ownership.
* Use `dry_run` when applying limits.
* Avoid system-wide priority inflation.

---

### Automation Considerations

* Always check `ok` field before chaining operations.
* Monitor process state after priority change.
* Log structured JSON responses.
* Use priority classes for consistency.
* Implement escalation logic in automation scripts.

---

### CI/CD Integration

Typical pattern:

1. Lower priority of background build tasks.
2. Monitor build process via `io.peek`.
3. Enforce file descriptor limits.
4. Gracefully terminate orphaned processes.

---

### Production Recommendations

* Avoid frequent use of negative nice values.
* Use resource limits to sandbox untrusted workloads.
* Monitor long-running processes regularly.
* Restrict SIGKILL to emergency cases.
* Audit limit settings for compliance.

---

## 7. Use Cases by Role

### DevOps Engineers

* Manage deployment processes.
* Control background tasks.
* Apply temporary resource limits during builds.

---

### SRE Engineers

* Escalate signals during incident response.
* Inspect unresponsive processes.
* Enforce memory or file descriptor limits.

---

### Network Administrators

* Tune daemon priority.
* Pause/resume services for maintenance.
* Investigate process resource consumption.

---

### AI / Automation Engineers

* Trigger escalation workflows.
* Detect priority drift.
* Apply automated sandboxing.
* Interpret structured process metadata.

---

## 8. Technical Foundation

### Rust Implementation Advantages

resh is implemented in Rust, providing:

* Memory safety
* Strong compile-time guarantees
* Deterministic execution
* Efficient system call handling

---

### Type Safety

* Enumerated verbs
* Strict argument parsing
* Validated signal names
* Controlled limit formats
* Structured error reporting

---

### Performance Characteristics

* Direct POSIX system call invocation
* Minimal overhead JSON serialization
* Efficient limit enforcement
* Controlled output buffer handling

---

### Cross-Platform Architecture

* POSIX-based implementation for Unix/Linux
* Structured backend abstraction
* Consistent JSON output across supported environments

