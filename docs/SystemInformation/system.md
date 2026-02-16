# Resource Shell (resh) – System Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line interface that models infrastructure operations using structured URI-based commands. The `system://` handle provides comprehensive Linux system information through a consistent, structured execution model.

### Purpose

The system handle enables:

* Collection of CPU, memory, disk, and load metrics
* Retrieval of operating system and kernel information
* Inspection of environment variables with security controls
* Monitoring of container and cgroup resource limits
* Structured output suitable for automation and machine processing

### Architectural Problem Addressed

Traditional system monitoring tools:

* Produce unstructured text output
* Require parsing for automation
* Vary in format across distributions
* Mix human-readable and machine-usable output

The system handle addresses these limitations by:

* Standardizing access to Linux system metrics
* Using explicit verbs with defined parameters
* Returning structured JSON responses
* Integrating directly with the Linux `/proc` and `/sys` interfaces

### Resource-Oriented URI Model

resh commands follow the URI format:

```
handle://target.verb(options)
```

For system operations:

* `handle`: `system://`
* `target`: optional (commonly omitted)
* `verb`: `info`, `cpu`, `memory`, `disk`, `load`, `uptime`, `env.list`
* `options`: structured parameters

Example:

```bash
resh 'system://.cpu(sample_duration_ms=500)'
```

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

* Each operation is exposed as a verb.
* Parameters are explicitly declared and validated.
* Output schema is consistent across executions.
* JSON is the default response format.

### Safety-First Execution

* Read-only access to `/proc` and `/sys`.
* No modification of system state.
* Environment variable masking enabled by default.
* Explicit limits for response size (e.g., `max_mounts`, `max_variables`).

### Deterministic Behavior

* Identical inputs produce consistent schema and field ordering.
* Sampling parameters explicitly control CPU measurement.
* Scope-based collection avoids implicit data gathering.

### JSON-Based Structured Output

All verbs return:

* `ok` status
* `timestamp_unix_ms`
* Structured data fields
* `warnings` array
* Optional raw and path metadata

### AI-Readiness

Structured responses allow:

* Automated health validation
* Threshold-based alerting
* Machine reasoning over metrics
* Integration with CI/CD and monitoring pipelines

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
handle://target.verb(options)
```

| Component | Description                               |
| --------- | ----------------------------------------- |
| `handle`  | `system://`                               |
| `target`  | Typically omitted                         |
| `verb`    | Operation such as `info`, `cpu`, `memory` |
| `options` | Named parameters controlling behavior     |

### Production Examples

**Comprehensive system information**

```bash
resh 'system://.info'
```

**CPU sampling (1 second)**

```bash
resh 'system://.cpu(sample_duration_ms=1000)'
```

**Disk usage with I/O**

```bash
resh 'system://.disk(include_io=true)'
```

**Memory including cgroup limits**

```bash
resh 'system://.memory(include_cgroup=true)'
```

**Load normalized per CPU**

```bash
resh 'system://.load(normalize_per_cpu=true)'
```

**Filtered environment variables**

```bash
resh 'system://.env.list(name_filter="^PATH$")'
```

---

### 3.2 Execution Semantics

#### Deterministic Behavior

* All metrics derived from `/proc` or system calls.
* CPU utilization calculated from time-differenced samples.
* Explicit parameters define scope and duration.

#### Structured Output Contract

Representative JSON response:

```json
{
  "ok": true,
  "timestamp_unix_ms": 1764860363960,
  "system": {
    "logical_count": 20,
    "utilization_pct": 0.2,
    "idle_pct": 99.8
  },
  "warnings": []
}
```

#### Error Handling Structure

Errors return structured responses:

```json
{
  "ok": false,
  "error": {
    "code": "system.info_proc_unavailable",
    "message": "/proc filesystem not accessible"
  }
}
```

---

## 4. Functional Domains

### 4.1 Automation Utilities

**Operational Scope**

* Health checks
* System inventory
* Automated diagnostics

**Supported Handle**

* `system://`

**Example**

```bash
system://.info(scopes=["os","kernel","cpu","memory","load"])
```

**Integration Scenario**

Used in CI pipelines for host validation before deployment.

---

### 4.2 Data & State Management

**Operational Scope**

* Memory metrics
* CPU sampling
* Load analysis
* Pressure stall information

**Example**

```bash
system://.memory(include_swap=true)
```

Used for runtime validation in orchestration systems.

---

### 4.3 Filesystem & Storage

**Operational Scope**

* Mounted filesystem space
* Inode utilization
* Block device I/O metrics

**Example**

```bash
system://.disk(include_io=true)
```

Used in capacity planning and disk health monitoring.

---

### 4.4 Network & Remote Operations

Indirectly supports diagnostics through:

* Load interpretation
* Pressure metrics
* System health evaluation

---

### 4.5 Packages & Software

System handle does not manage packages directly but supports:

* Host environment validation before software deployment
* Kernel and OS version inspection

---

### 4.6 Process & Service Management

**Operational Scope**

* Process counts
* Runnable vs total processes
* CPU load correlation

**Example**

```bash
system://.load(include_queue=true)
```

Used to diagnose overload conditions.

---

### 4.7 Security & Secrets

**Operational Scope**

* Environment variable inspection
* Automatic masking of sensitive data
* Process-specific environment retrieval

**Example**

```bash
system://.env.list(mask_sensitive=true)
```

Sensitive variables are masked by default.

---

### 4.8 System Information

**Operational Scope**

* OS and distribution details
* Kernel version
* Virtualization detection
* Cgroup resource limits
* PSI (pressure stall information)

**Example**

```bash
system://.info(scopes=["virtualization","cgroup"])
```

Used for container-aware monitoring.

---

## 5. Platform Support

### Linux

* Full support.
* Requires `/proc` filesystem.
* Some metrics require elevated privileges.

### Containers (Docker, Podman, LXC)

* Most metrics available.
* Cgroup metrics particularly relevant.
* Some `/proc` entries may be restricted.

### WSL

* Generally supported.
* Hardware topology may be limited.

### Non-Linux Systems

The system handle depends on `/proc` and is Linux-specific. Support outside Linux is not defined in the provided documentation. 

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Use read-only contexts.
* Enable masking for environment variables.
* Validate sampling duration for CPU accuracy.
* Monitor warnings in responses.

### Automation Considerations

* Use JSON format for machine parsing.
* Normalize load per CPU.
* Limit response size via `max_mounts` and `max_variables`.
* Cache results externally when polling frequently.

### CI/CD Integration

* Validate OS version before deployment.
* Confirm disk capacity before artifact extraction.
* Check CPU and memory availability pre-build.

### Production Recommendations

* Sample CPU for ≥ 1 second for accuracy.
* Alert at load > 0.7 per CPU.
* Monitor `mem_available` instead of `mem_free`.
* Track swap usage trends.

---

## 7. Use Cases by Role

### DevOps Engineers

* Validate build hosts.
* Confirm resource availability before deployments.
* Automate host readiness checks.

### SRE Engineers

* Diagnose overload conditions.
* Monitor memory pressure and swap activity.
* Correlate load with CPU utilization.

### Network Administrators

* Evaluate system load impact on services.
* Review environment configurations.
* Inspect kernel versions for compatibility.

### AI / Automation Engineers

* Feed structured metrics into decision systems.
* Trigger scaling based on load thresholds.
* Analyze pressure stall data programmatically.

---

## 8. Technical Foundation

### Rust Implementation Advantages

* Memory safety without garbage collection.
* Strong compile-time guarantees.
* Deterministic execution behavior.
* Efficient interaction with `/proc`.

### Type Safety

* Enumerated verbs.
* Structured parameter validation.
* Defined error codes.
* Stable JSON schema.

### Performance Characteristics

* Direct `/proc` reads.
* Low overhead system calls.
* Configurable CPU sampling duration.
* No internal caching.

### Cross-Platform Architecture

* Designed for Linux systems.
* Compatible with containerized environments.
* Portable across Linux distributions.
* Uniform JSON output structure.
