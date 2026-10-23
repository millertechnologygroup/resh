# Resource Shell (resh) – System Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line interface that models infrastructure operations using structured URI-based commands. The `system://` handle reports read-only information about the local Linux host, read from `/proc`, `/sys` and system calls (the `os` and `kernel` scopes of `info` also run `uname -a` and `hostname`).

### Purpose

The system handle provides:

* CPU, memory, disk and load metrics
* Operating system and kernel information
* Environment variable inspection with masking of sensitive values
* cgroup resource limits (containers)
* Pressure stall information (PSI) and virtualization detection, through `info` scopes

It never changes system state.

### Resource-Oriented URI Model

The stage URL has no target, so every command has the form:

```text
resh system://.<verb> [<option>=<value> ...] [input=<json>]
```

* `handle`: `system://`
* `target`: empty (the dot is still required)
* `verb`: `info`, `uptime`, `load`, `memory`, `cpu`, `disk`, `env.list`
* options: `key=value` words, one JSON object in `input`, or both (plain `key=value` words override keys in `input`)

List options accept a JSON array string or comma-separated items (`scopes=kernel,load`). Booleans accept `true|false|1|0|yes|no|on|off`.

Example:

```bash
resh system://.cpu sample_duration_ms=500
```

The parenthesised form also works when quoted:

```bash
resh 'system://.cpu(sample_duration_ms=500)'
```

---

## 2. Verbs and Options

Only the options listed here have an effect. **Unknown option names are silently ignored**, so a misspelt option (or an option from another handle) is not reported as an error.

| Verb | Options (default) |
| ---- | ----------------- |
| `info` | `scopes` (`os,kernel,cpu,memory,load`; also `disk`, `process`, `pressure`, `cgroup`, `virtualization`), `fields` (filter the response), `sample_duration_ms` (0 = no CPU sampling), `sample_min_ms` (50), `per_cpu` (false), `max_mounts` (32), `format` (`json`) |
| `uptime` | `include_idle` (true), `include_boot_time` (true), `include_human` (true), `include_raw` (false), `include_paths` (false), `format` |
| `load` | `normalize_per_cpu` (true), `include_queue` (true), `include_human` (true), `include_raw` (false), `include_paths` (false), `min_cpu_count` (1), `format` |
| `memory` | `include_cgroup` (true), `include_hugepages` (true), `include_human` (true), `include_raw` (false), `include_paths` (false), `format` |
| `cpu` | `sample_duration_ms` (250), `sample_min_ms` (50), `per_cpu` (true), `include_topology` (true), `include_frequency` (true), `include_cgroup` (true), `include_human` (true), `include_raw` (false), `include_paths` (false), `format` |
| `disk` | `mount_points`, `devices`, `fs_types`, `include_virtual` (false), `max_mounts` (64), `include_io` (true), `include_fs_types` (true), `include_human` (true), `include_raw` (false), `include_paths` (false), `format` |
| `env.list` | `pid` (resh itself), `names`, `prefix_filters`, `regex_filters`, `include_values` (true), `include_sensitive` (false), `truncate_length` (512), `max_vars` (1024), `sort_by` (`name`/`length`/`none`), `sort_order` (`asc`/`desc`), `include_raw`, `include_paths`, `format` |

`format` is `json` (default) or `text`; any other value is an error.

Options that are accepted but have **no effect**:

* `info`: `max_process_classes`, `include_raw`, `include_paths`
* `memory`: `include_swap` (swap figures are always included in the `system` section)

There is no `name_filter`, `mask_sensitive` or `max_variables` option for `env.list`; use `names` / `prefix_filters` / `regex_filters`, `include_sensitive` and `max_vars`.

Built-in help: `resh system --help`, `resh system <verb> --help`.

---

## 3. Command Syntax and Execution Model

### 3.1 Examples

**Default host information**

```bash
resh system://.info
```

**Selected info scopes**

```bash
resh system://.info 'input={"scopes":["kernel","load"]}'
```

**CPU sampling (1 second)**

```bash
resh system://.cpu sample_duration_ms=1000
```

**Disk usage with I/O statistics for the root filesystem**

```bash
resh system://.disk 'input={"mount_points":["/"]}' include_io=true
```

**Memory including cgroup limits**

```bash
resh system://.memory include_cgroup=true
```

**Load normalized per CPU**

```bash
resh system://.load normalize_per_cpu=true
```

**Selected environment variables**

```bash
resh system://.env.list names=PATH,HOME
```

**Environment variables by regular expression**

```bash
resh system://.env.list 'input={"regex_filters":["^XDG_"]}'
```

**Text output**

```bash
resh system://.uptime format=text
```

---

### 3.2 Execution Semantics

* All metrics come from `/proc`, `/sys` or system calls at the moment of the call; nothing is cached and nothing persists between invocations.
* CPU utilization is computed from two samples `sample_duration_ms` apart (`sample_duration_ms` must be at least `sample_min_ms`).
* **Timeouts**: the system handle has no `timeout_ms` option. A `timeout_ms` argument is ignored like any other unknown option; the only time-related option is the CPU sampling interval.

### 3.3 Output

Representative `cpu` response (abbreviated):

```json
{
  "ok": true,
  "timestamp_unix_ms": 1764860363960,
  "system": {
    "available": true,
    "logical_count": 20,
    "utilization_pct": 0.2,
    "idle_pct": 99.8
  },
  "warnings": []
}
```

Every response has `ok`, `timestamp_unix_ms` and `warnings`. `raw` and `paths` appear only when `include_raw` / `include_paths` are true (and are not produced by `info`).

### 3.4 Errors

On an error (for example an invalid `format`, an unknown `info` scope, or an unreadable PID for `env.list`) the handle prints a JSON object with `ok: false` and an `error` object, writes `Error: <reason>` to standard error, and exits 1:

```json
{
  "error": {
    "code": "system.info_scope_invalid",
    "message": "invalid scope: bogus"
  },
  "ok": false
}
```

---

## 4. Functional Domains

### 4.1 Automation Utilities

* Health checks
* System inventory
* Automated diagnostics

```bash
resh system://.info scopes=os,kernel,cpu,memory,load
```

Used in CI pipelines for host validation before deployment.

### 4.2 Data & State Management

* Memory metrics
* CPU sampling
* Load analysis
* Pressure stall information (`info` scope `pressure`)

```bash
resh system://.memory include_hugepages=false
```

### 4.3 Filesystem & Storage

* Mounted filesystem space
* Inode utilization
* Block device I/O metrics

```bash
resh system://.disk include_io=true
```

Virtual filesystems are skipped unless `include_virtual=true`.

### 4.4 Process & Service Management

* Runnable vs total process counts (`load` with `include_queue=true`)
* Process information (`info` scope `process`)

```bash
resh system://.load include_queue=true
```

### 4.5 Security & Secrets

* Environment variable inspection for resh itself or another process (`pid`, read from `/proc/<pid>/environ`, which normally requires the same user or root)
* Values of variables whose names contain `password`, `passwd`, `secret`, `token`, `api_key`, `access_key`, `private_key`, `client_secret`, or both `auth` and `key` (case-insensitive) are replaced with `***MASKED***` unless `include_sensitive=true`. Other variables (for example a `DATABASE_URL` containing a password) are not masked.

```bash
resh system://.env.list include_values=false
```

### 4.6 System Information

* OS and distribution details
* Kernel version
* Virtualization detection
* cgroup resource limits
* PSI (pressure stall information)

```bash
resh system://.info scopes=virtualization,cgroup
```

---

## 5. Platform Support

* Linux only. The handle requires `/proc` (and `/sys` for some metrics). No other operating system is supported.
* In containers, most metrics are available; cgroup metrics reflect the container's limits, and some `/proc` entries may be restricted.
* Some metrics may need elevated privileges; missing data is reported in `warnings` or as `available: false`.

---

## 6. Limitations

* Unknown options are ignored without a warning (see section 2), including `timeout_ms`.
* `info` ignores `max_process_classes`, `include_raw` and `include_paths`; `memory` ignores `include_swap`.
* The `kernel.machine` value of `info` is taken from the last word of `uname -a`, which on most systems is the OS name (for example `GNU/Linux`), not the hardware architecture.
* `disk` can panic when a mounted device name under `/dev/` starts with `sd`, `hd` or `vd` and has a non-ASCII character at the third position (device-name parsing slices bytes). Kernel-assigned device names are ASCII, so this is not expected in normal use.

---

## 7. Operational Best Practices

* Check `warnings` in every response.
* Sample CPU for a sufficiently long interval (for example 1000 ms) when accuracy matters.
* Use per-CPU normalized load (`load_1m_per_cpu` etc.) when comparing hosts.
* Prefer `mem_available_bytes` over `mem_free_bytes` for capacity decisions.
* Limit response size with `max_mounts` and `max_vars`.
* Keep `include_sensitive=false` unless you need the raw values.

---

## 8. Use Cases by Role

### DevOps Engineers

* Validate build hosts.
* Confirm resource availability before deployments.

### SRE Engineers

* Diagnose overload conditions.
* Monitor memory pressure and swap usage.
* Correlate load with CPU utilization.

### AI / Automation Engineers

* Feed structured metrics into decision systems.
* Trigger scaling based on load thresholds.
* Analyze pressure stall data programmatically.

---

## 9. Technical Foundation

* Implemented in Rust; reads `/proc` and `/sys` directly. The only subprocesses are `uname -a` and `hostname`, used for the `os`/`kernel` information.
* Fixed verb set; options are deserialized per verb (unknown names ignored).
* Errors carry a code such as `system.info_scope_invalid`.
