# Resource Shell (resh) – System Information Overview Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using structured URI-based commands. It provides typed handles for interacting with system resources and returns deterministic, structured JSON output suitable for automation.

The **System Information** domain is exposed via the `system://` handle and provides structured access to hardware details, runtime status, and resource utilization metrics.

### Purpose

The `system://` handle enables:

* Retrieval of operating system and kernel metadata
* Monitoring of CPU load and performance
* Inspection of memory usage (RAM and swap)
* Reporting of disk usage across mounted filesystems
* Querying uptime and boot time
* Listing environment variables

All operations are read-only and return structured JSON suitable for automation, diagnostics, and monitoring workflows.

### Architectural Problem Addressed

Traditional system monitoring tools:

* Use multiple independent commands (`uptime`, `free`, `df`, `top`, `env`)
* Produce human-oriented text output
* Require parsing for automation
* Lack consistent output schemas

resh addresses these limitations by:

* Providing a unified `system://` handle
* Standardizing monitoring verbs
* Returning structured JSON output
* Normalizing platform-specific data
* Supporting deterministic automation contracts

### Resource-Oriented URI Model

System monitoring operations follow:

```
handle://target.verb(options)
```

For system information:

* **handle**: `system://`
* **target**: `.` (system context)
* **verb**: Information category (e.g., `info`, `memory`, `disk`)
* **options**: Optional structured parameters

Examples:

```
system://.info
system://.memory
system://.disk
system://.env.list
```

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

* Seven explicitly defined information verbs.
* Each verb corresponds to a specific monitoring category.
* Output format is consistent across commands.
* All operations are read-only.

---

### Safety-First Execution

* No system state modification.
* Sensitive values automatically protected where applicable.
* Graceful handling of missing or unsupported metrics.
* Safe operation in containers and virtual environments.

---

### Deterministic Behavior

* Identical inputs yield consistent JSON structures.
* Platform detection is automatic.
* Unsupported metrics are reported explicitly.
* No hidden side effects.

---

### JSON-Based Structured Output

All responses include:

* Structured metric values
* Percentage representations where applicable
* Timestamps and trend indicators where relevant
* Human-readable summaries alongside raw data

Representative example:

```json
{
  "ok": true,
  "system": {
    "os": "Linux",
    "kernel": "6.6.0",
    "architecture": "x86_64"
  },
  "uptime": {
    "seconds": 86400,
    "human": "1 day"
  },
  "load": {
    "1m": 0.42,
    "5m": 0.38,
    "15m": 0.35
  }
}
```

---

### AI-Readiness

Structured output enables:

* Automated health monitoring
* Threshold-based alerting
* Capacity planning analysis
* Drift detection
* Predictive workload modeling
* Policy enforcement

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
system://.VERB(options)
```

| Component | Description          |
| --------- | -------------------- |
| `handle`  | `system://`          |
| `target`  | `.` (system context) |
| `VERB`    | Monitoring operation |
| `options` | Optional parameters  |

---

### Available Verbs

| Verb       | Purpose                  |
| ---------- | ------------------------ |
| `info`     | System overview          |
| `uptime`   | Uptime and boot time     |
| `load`     | CPU load averages        |
| `memory`   | RAM and swap usage       |
| `cpu`      | CPU performance metrics  |
| `disk`     | Disk usage across mounts |
| `env.list` | Environment variables    |

---

### Production Examples

#### Full System Overview

```
system://.info
```

#### Check Memory Usage

```
system://.memory
```

#### Inspect Disk Utilization

```
system://.disk
```

#### Monitor CPU Load

```
system://.load
```

#### View CPU Topology

```
system://.cpu
```

#### List Environment Variables

```
system://.env.list
```

---

## 3.2 Execution Semantics

### Deterministic Behavior

* Each verb maps to a specific metric set.
* Output structure is stable across runs.
* Platform-specific differences are normalized.
* Missing metrics are reported without failure.

---

### Structured Output Contracts

Example: Memory Usage

```json
{
  "ok": true,
  "memory": {
    "total_bytes": 17179869184,
    "used_bytes": 8589934592,
    "free_bytes": 4294967296,
    "used_percent": 50.0,
    "swap_total_bytes": 2147483648,
    "swap_used_percent": 12.5
  }
}
```

Example: Disk Usage

```json
{
  "ok": true,
  "disks": [
    {
      "mount": "/",
      "total_bytes": 107374182400,
      "used_percent": 72.4
    }
  ]
}
```

---

### Error Handling Structure

Representative error:

```json
{
  "ok": false,
  "error": {
    "code": "system.unsupported_platform",
    "message": "Requested metric not available on this platform"
  }
}
```

---

## 4. Functional Domains

---

### 4.1 Automation Utilities

**Handle**

* `system://`

**Scope**

* Health checks
* Resource threshold validation
* Deployment readiness checks
* Automated diagnostics

---

### 4.2 Data & State Management

**Scope**

* Real-time memory and CPU metrics
* Uptime tracking
* Environment configuration inspection
* Disk capacity reporting

---

### 4.3 Filesystem & Storage

**Scope**

* Mounted filesystem enumeration
* Storage capacity monitoring
* Utilization percentage reporting
* Disk exhaustion detection

Example:

```
system://.disk
```

---

### 4.4 Network & Remote Operations

Indirect support through:

* System load analysis for remote deployments
* Capacity checks prior to scaling
* Baseline host metrics for remote orchestration

---

### 4.5 Packages & Software

Supports:

* Pre-install resource validation
* Post-install health checks
* Memory availability verification
* Environment variable inspection

---

### 4.6 Process & Service Management

Integrates with:

* `proc://` for process-level metrics
* `svc://` for service lifecycle management
* Load monitoring before service restart
* Memory validation before deployment

---

### 4.7 Security & Secrets

Supports:

* Environment variable auditing
* Detection of unexpected configuration variables
* Validation of runtime environment settings
* Safe omission of sensitive data where applicable

---

### 4.8 System Information

Primary domain includes:

| Category    | Description                        |
| ----------- | ---------------------------------- |
| OS Info     | Operating system and kernel        |
| Uptime      | Runtime duration and boot time     |
| Load        | CPU load averages                  |
| Memory      | RAM and swap utilization           |
| CPU         | Core count and performance metrics |
| Disk        | Filesystem usage                   |
| Environment | Process environment variables      |

---

## 5. Platform Support

| Platform       | Support Level                                           |
| -------------- | ------------------------------------------------------- |
| Linux          | Full support                                            |
| macOS/Unix     | Basic support (some Linux-specific metrics unavailable) |
| Windows        | Limited support                                         |
| Containers/WSL | Supported with environment-aware warnings               |

Platform detection is automatic, and unavailable metrics are handled gracefully.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Use `memory` before large deployments.
* Monitor `disk` prior to data-intensive tasks.
* Check `load` before scaling operations.
* Use `info` during troubleshooting.
* Avoid exposing environment variables in logs.

---

### Automation Considerations

* Validate `ok` field before processing.
* Use percentage fields for threshold checks.
* Log structured JSON for audit trails.
* Use load averages for scaling decisions.
* Monitor swap usage as early memory pressure indicator.

---

### CI/CD Integration

Typical workflow:

1. `system://.memory` – ensure sufficient RAM.
2. `system://.disk` – verify storage capacity.
3. `system://.load` – confirm system stability.
4. Proceed with deployment.
5. Validate via `system://.info`.

---

### Production Environment Recommendations

* Establish resource thresholds.
* Monitor disk utilization proactively.
* Review uptime to determine patch cycles.
* Audit environment variables regularly.
* Integrate monitoring with alerting systems.
* Avoid reliance on single-point health metrics.

---

## 7. Use Cases by Role

### DevOps Engineers

* Validate system readiness before deployments.
* Monitor memory and disk consumption.
* Inspect environment variables for configuration drift.
* Integrate system checks into pipelines.

---

### SRE Engineers

* Diagnose performance issues.
* Track system stability via uptime.
* Monitor load during incident response.
* Validate resource pressure indicators.

---

### Network Administrators

* Confirm system capacity for network services.
* Monitor disk usage for log growth.
* Check system load for peak periods.
* Inspect runtime environment settings.

---

### AI / Automation Engineers

* Parse structured resource metrics.
* Detect anomalies in usage patterns.
* Trigger automated remediation.
* Implement threshold-based orchestration.

---

## 8. Technical Foundation

### Rust Implementation Advantages

resh is implemented in Rust, providing:

* Memory safety
* Deterministic system interaction
* Strong compile-time guarantees
* Efficient metric collection

---

### Type Safety

* Enumerated verbs
* Strict output schemas
* Explicit error modeling
* Structured metric representation

---

### Performance Characteristics

* Lightweight data collection
* Efficient `/proc` and `/sys` access on Linux
* Minimal overhead sampling
* Real-time metric reporting

---

### Cross-Platform Architecture

* Platform-aware metric collection
* Graceful degradation on unsupported systems
* Unified JSON schema
* Deterministic output across environments
