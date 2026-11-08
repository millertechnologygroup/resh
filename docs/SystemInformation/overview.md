# Resource Shell (resh) – System Information Overview Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using structured URI-based commands. It provides typed handles for interacting with system resources and returns structured JSON output suitable for automation.

The **System Information** domain is exposed via the `system://` handle, which reports read-only information about the local Linux host. Full reference: [system.md](system.md).

### Purpose

The `system://` handle provides:

* Operating system and kernel metadata
* CPU utilization, topology and frequency
* Load averages
* Memory usage (RAM, swap, hugepages, cgroup limits)
* Disk usage across mounted filesystems, with I/O statistics
* Uptime and boot time
* Environment variable listing with masking of sensitive values

All operations are read-only and print one JSON object (or text with `format=text`).

### Resource-Oriented URI Model

The URL has no target, but the dot before the verb is required:

```text
resh system://.<verb> [<option>=<value> ...] [input=<json>]
```

* **handle**: `system://`
* **target**: empty
* **verb**: `info`, `uptime`, `load`, `memory`, `cpu`, `disk`, `env.list`
* **options**: `key=value` words and/or one JSON object in `input`

Examples:

```bash
resh system://.info
resh system://.memory
resh system://.disk
resh system://.env.list
```

---

## 2. Design Principles

* Seven read-only verbs, one per information category.
* No system state is modified.
* Sensitive environment values are masked by default.
* Missing or unavailable metrics are reported as `available: false` or in `warnings` rather than failing the command.
* Options are checked strictly: an unknown option or a bad value is refused (exit 2, `system.invalid_argument`) before anything is read; see `resh system <verb> --help`.

---

## 3. Command Syntax and Execution Model

### 3.1 Available Verbs

| Verb       | Purpose                  |
| ---------- | ------------------------ |
| `info`     | Combined report for selected scopes (`os`, `kernel`, `cpu`, `memory`, `load`, `disk`, `process`, `pressure`, `cgroup`, `virtualization`) |
| `uptime`   | Uptime, boot time, idle time |
| `load`     | 1/5/15-minute load averages, per-CPU values, process counts |
| `memory`   | RAM, swap, hugepage and cgroup memory usage |
| `cpu`      | Sampled CPU utilization, topology, frequency, cgroup CPU limits |
| `disk`     | Capacity, inode usage and I/O statistics for mounted filesystems |
| `env.list` | Environment variables of resh or of another process (`pid=`) |

### 3.2 Examples

#### System Overview

```bash
resh system://.info
```

#### Memory Usage

```bash
resh system://.memory
```

#### Disk Utilization of the Root Filesystem

```bash
resh system://.disk mount_points=/
```

#### Load Averages

```bash
resh system://.load
```

#### CPU Utilization and Topology

```bash
resh system://.cpu sample_duration_ms=1000
```

#### Selected Environment Variables

```bash
resh system://.env.list names=PATH,HOME
```

---

### 3.3 Execution Semantics

* Values are read from `/proc`, `/sys`, `/etc/os-release` and system calls (`statvfs`, `uname`) at call time; no program is run.
* Each `resh` invocation is a separate process; nothing is cached or kept between invocations.
* **Timeouts**: `disk` and `info` take `timeout_ms` (default 30000), because `statvfs` on a hung network filesystem can block; at the deadline they report what they have and exit 124 (`system.timeout`). The other verbs only read `/proc` and `/sys` and refuse `timeout_ms`; `cpu` samples for `sample_duration_ms` (default 250, at most 60000).

### 3.4 Output

Representative `memory` output (with `include_cgroup=false include_hugepages=false include_human=false`):

```json
{
  "ok": true,
  "timestamp_unix_ms": 1792761175370,
  "system": {
    "available": true,
    "mem_total_bytes": 134047248384,
    "mem_free_bytes": 20854009856,
    "mem_available_bytes": 106859823104,
    "buffers_bytes": 2104233984,
    "cached_bytes": 79905128448,
    "shmem_bytes": 906797056,
    "sreclaimable_bytes": 4256710656,
    "swap_total_bytes": 4294963200,
    "swap_free_bytes": 2236887040,
    "mem_used_bytes": 27187425280,
    "mem_used_pct": 20.28,
    "swap_used_bytes": 2058076160,
    "swap_used_pct": 47.92
  },
  "warnings": []
}
```

Representative `disk` output (with `mount_points=/ include_io=false include_human=false`):

```json
{
  "ok": true,
  "timestamp_unix_ms": 1792761175376,
  "mounts_truncated": false,
  "mounts": [
    {
      "mount_point": "/",
      "device": "/dev/nvme0n1p3",
      "fs_type": "ext4",
      "virtual_fs": false,
      "total_bytes": 1962561503232,
      "used_bytes": 704683360256,
      "free_bytes": 1257878142976,
      "avail_bytes": 1158109913088,
      "used_pct": 38.0,
      "used_of_total_pct": 35.91,
      "free_pct": 64.09,
      "inodes_total": 121774080,
      "inodes_used": 2944929,
      "inodes_free": 118829151,
      "inodes_used_pct": 2.42,
      "tags": ["rootfs"]
    }
  ],
  "warnings": []
}
```

### 3.5 Errors

On an error the handle writes `Error: [<code>] <message>` to standard error and, with `format=json`, prints a JSON object with `ok: false` and an `error` object. Invalid arguments exit 2, failures to read the host exit 1, a timeout exits 124. The codes are listed in [system.md](system.md) section 3.4.

```json
{
  "error": {
    "code": "system.invalid_argument",
    "message": "invalid scopes value \"bogus\" (expected one of: os, kernel, cpu, memory, load, disk, process, pressure, cgroup, virtualization)"
  },
  "ok": false
}
```

---

## 4. Functional Domains

### 4.1 Automation Utilities

* Health checks
* Resource threshold validation
* Deployment readiness checks
* Automated diagnostics

### 4.2 Data & State Management

* Point-in-time memory and CPU metrics
* Uptime tracking
* Environment configuration inspection
* Disk capacity reporting

### 4.3 Filesystem & Storage

* Mounted filesystem enumeration (virtual filesystems skipped unless `include_virtual=true`)
* Capacity and inode utilization
* Block device I/O counters

```bash
resh system://.disk include_io=true
```

### 4.4 Process & Service Management

* Runnable and total process counts (`load`)
* Process information (`info` scope `process`)
* Process-level detail is provided by the separate `proc://` handle.

### 4.5 Security & Secrets

* Environment variable auditing (`env.list`)
* Values of variables whose names look sensitive (containing `password`, `secret`, `token`, `api_key`, and similar) or whose value is a URL with a password are replaced with `***MASKED***` unless `include_sensitive=true` (see system.md 3.2).

### 4.6 System Information

| Category    | Verb / scope |
| ----------- | ------------ |
| OS Info     | `info` scopes `os`, `kernel` |
| Uptime      | `uptime` |
| Load        | `load` |
| Memory      | `memory` |
| CPU         | `cpu` |
| Disk        | `disk` |
| Pressure    | `info` scope `pressure` |
| Containers  | `info` scopes `cgroup`, `virtualization` |
| Environment | `env.list` |

---

## 5. Platform Support

* Linux only. The handle requires `/proc` (and `/sys` for some metrics); no other operating system is supported.
* cgroup v1 and v2 are supported. In containers, the `cgroup` sections report the container's own limits and usage, while `/proc`-based figures (system memory, CPU utilization, load, uptime) describe the whole host; unavailable data is reported in `warnings` or as `available: false`.

---

## 6. Operational Best Practices

* Check `ok` and `warnings` before using the values.
* Use the percentage fields (`mem_used_pct`, `used_pct`) for threshold checks.
* Prefer `mem_available_bytes` over `mem_free_bytes`.
* Use per-CPU load (`load_1m_per_cpu`) for scaling decisions.
* Avoid writing environment variable values to logs; use `include_values=false` when only names are needed.

### CI/CD Integration

Typical workflow:

1. `resh system://.memory` – ensure sufficient RAM.
2. `resh system://.disk` – verify storage capacity.
3. `resh system://.load` – confirm system stability.
4. Proceed with deployment.

---

## 7. Use Cases by Role

### DevOps Engineers

* Validate system readiness before deployments.
* Monitor memory and disk consumption.
* Integrate system checks into pipelines.

### SRE Engineers

* Diagnose performance issues.
* Monitor load during incident response.
* Check pressure stall information.

### AI / Automation Engineers

* Parse structured resource metrics.
* Implement threshold-based orchestration.

---

## 8. Technical Foundation

* Implemented in Rust; reads `/proc` and `/sys` directly and runs no programs.
* Fixed verb set with one accepted-options list per verb.
* Errors carry a code such as `system.invalid_argument` (see system.md 3.4).
