# Resource Shell (resh) – System Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line interface that models infrastructure operations using structured URI-based commands. The `system://` handle reports read-only information about the local Linux host, read from `/proc`, `/sys`, `/etc/os-release` and system calls (`statvfs`, `uname`). It changes nothing and runs no programs.

### Purpose

The system handle provides:

* CPU, memory, disk and load metrics
* Operating system and kernel information
* Environment variable inspection with masking of sensitive values
* cgroup (v1 and v2) resource limits and usage, for containers and services
* Pressure stall information (PSI), process counts and virtualization detection, through `info` scopes

### Resource-Oriented URI Model

The stage URL has no target, so every command has the form:

```text
resh system://.<verb> [<option>=<value> ...] [input=<json>]
```

* `handle`: `system://`
* `target`: none (the dot is still required). A target such as `system://host.info` is refused (exit 2, `system.invalid_target`).
* `verb`: `info`, `uptime`, `load`, `memory`, `cpu`, `disk`, `env.list`
* options: `key=value` words, the keys of one JSON object in `input`, or both (a `key=value` word overrides the same key in `input`). No option is required; every option has a default.

List options accept a JSON array string (`'scopes=["kernel","load"]'`) or comma-separated items (`scopes=kernel,load`); use the JSON form when an item contains a comma (for example a regular expression). Booleans accept `true|false|1|0|yes|no|on|off`; numbers are whole numbers.

Example:

```bash
resh system://.cpu sample_duration_ms=500
```

---

## 2. Verbs and Options

Arguments are checked before anything is read: an unknown option (in a word or in `input`), an option of another verb, `timeout_ms` on a verb without a time limit, `dry_run`, a value of the wrong type or out of range, and an `input` that is not a JSON object are refused with exit 2 and `system.invalid_argument`, naming the argument (with a "did you mean" hint for likely typos). This is stricter than resh v1.0.6-beta, which ignored unknown options.

| Verb | Options (default) |
| ---- | ----------------- |
| `info` | `scopes` (`os,kernel,cpu,memory,load`; also `disk`, `process`, `pressure`, `cgroup`, `virtualization`), `fields` (none: every key), `sample_duration_ms` (0 = no CPU sampling; 0 to 60000), `sample_min_ms` (50; 1 to 60000), `per_cpu` (false; needs sampling), `max_mounts` (32), `max_process_classes` (5), `include_raw` (false), `include_paths` (false), `timeout_ms` (30000), `format` (`json`) |
| `uptime` | `include_idle` (true), `include_boot_time` (true), `include_human` (true), `include_raw` (false), `include_paths` (false), `format` |
| `load` | `normalize_per_cpu` (true), `include_queue` (true), `include_human` (true), `include_raw` (false), `include_paths` (false), `min_cpu_count` (1; at least 1), `format` |
| `memory` | `include_swap` (true), `include_cgroup` (true), `include_hugepages` (true), `include_human` (true), `include_raw` (false), `include_paths` (false), `format` |
| `cpu` | `sample_duration_ms` (250; 0 uses `sample_min_ms`; at most 60000), `sample_min_ms` (50; 1 to 60000), `per_cpu` (true), `include_topology` (true), `include_frequency` (true), `include_cgroup` (true), `include_human` (true), `include_raw` (false), `include_paths` (false), `format` |
| `disk` | `mount_points` (all), `devices` (all), `fs_types` (all), `include_virtual` (false), `max_mounts` (64), `include_io` (true), `include_fs_types` (true), `include_human` (true), `include_raw` (false), `include_paths` (false), `timeout_ms` (30000), `format` |
| `env.list` | `pid` (resh itself), `names`, `prefix_filters`, `regex_filters`, `include_values` (true), `include_sensitive` (false), `truncate_length` (512; 0 = no limit), `max_vars` (1024), `sort_by` (`name`, `length` or `none`), `sort_order` (`asc` or `desc`), `include_raw` (false), `include_paths` (false), `format` |

`format` is `json` (default, pretty-printed) or `text`.

Option details:

* `include_raw` adds a `raw` object with the source text that was read; `include_paths` adds a `paths` object naming the files read. Both work for every verb, including `info` (keyed by scope).
* `include_human` adds human-readable summaries (`human`, `uptime_human`, `human_summary`).
* `info fields` lists `<scope>` (the whole scope) or `<scope>.<key>` entries; only those are reported, and a scope no entry names is left out of the report (it is still listed in `scopes`). Each entry must name a requested scope and a key that scope reports (see 3.3); anything else is refused.
* `info max_process_classes` is the number of process names (`classes`, by count) the `process` scope lists; 0 lists none.
* `disk mount_points` and `devices` select mounts; each one given must be mounted, otherwise the verb fails (exit 1, `system.disk_mount_not_found`). A trailing slash on a mount point is ignored.
* `env.list regex_filters` are Rust regular expressions matched against variable names; an invalid one is refused (exit 2).

Built-in help: `resh system --help`, `resh system <verb> --help` (also `-h`, `help`, `resh help system [verb]`).

---

## 3. Command Syntax and Execution Model

### 3.1 Examples

```bash
resh system://.info
resh system://.info scopes=kernel,load fields=kernel.release,load
resh system://.cpu sample_duration_ms=1000
resh system://.disk mount_points=/ include_io=true
resh system://.memory include_hugepages=false
resh system://.load normalize_per_cpu=true
resh system://.env.list names=PATH,HOME
resh system://.env.list 'input={"regex_filters":["^XDG_"]}'
resh system://.uptime format=text
```

### 3.2 Execution Semantics and Units

All figures come from the kernel at the moment of the call; nothing is cached or kept between invocations.

* **Bytes** everywhere (`*_bytes`). `/proc/meminfo` values in kB are multiplied by 1024.
* **uptime**: `uptime_seconds` and `idle_seconds` are the two fields of `/proc/uptime`. `idle_seconds` is summed over all CPUs; `idle_seconds_per_cpu` divides it by the number of online CPUs. `boot_time_unix` is `btime` from `/proc/stat` (else now minus uptime, with a warning).
* **load**: `load_1m`/`load_5m`/`load_15m`, `runnable_processes` and `total_processes` are the fields of `/proc/loadavg` (the kernel counts tasks, so `total_processes` includes threads). Per-CPU values divide by the number of online CPUs (`cpuN` lines of `/proc/stat`, `cpu_count_logical`), or by `min_cpu_count` if that is larger. `human.status` classifies the 1-minute load per CPU: `idle` < 0.1 ≤ `normal` < 0.7 ≤ `busy` ≤ 1.5 < `overloaded`.
* **memory**: `mem_used_bytes` = `MemTotal` − `MemAvailable` (on kernels without `MemAvailable`: `MemTotal` − `MemFree` − `Buffers` − `Cached`, with a warning); `mem_used_pct` is that share of `MemTotal`. `swap_used_bytes` = `SwapTotal` − `SwapFree`. Hugepage counts are pages; `page_bytes` is `Hugepagesize`. With `include_swap=false` no swap figure is reported (system or cgroup).
* **cpu**: `/proc/stat` is read twice, `sample_duration_ms` apart (the interval used is in `sample_duration_ms` of the response), and each percentage is that field's share of the CPU time that passed: `user_pct + nice_pct + system_pct + idle_pct + iowait_pct + irq_pct + softirq_pct + steal_pct` = 100. Guest time is part of user (and guest_nice of nice) time, as the kernel counts it, so `guest_pct`/`guest_nice_pct` are not added again. `utilization_pct` = 100 − `idle_pct` − `iowait_pct` (time waiting for I/O is idle CPU time). If no CPU time passed between the samples the percentages are omitted with a warning and `human.status` is `unknown`. Per-CPU `id`s are the kernel's CPU numbers (offline CPUs are absent). `logical_count` counts online CPUs; `physical_count` counts distinct (socket, core) pairs and `socket_count` distinct packages from `/sys/devices/system/cpu/cpuN/topology`. `frequency_current_hz` is the mean of the CPUs' `scaling_cur_freq`, `frequency_max_hz` the highest `cpuinfo_max_freq` (cpufreq reports kHz; these are Hz). `human.status`: `idle` < 5% ≤ `normal` < 60% ≤ `busy` < 85% ≤ `overloaded`; `per_cpu_hotspots` lists CPUs above 80%.
* **disk**: mounts come from `/proc/self/mounts` (else `/proc/mounts`, with a warning), in table order, with escaped characters (`\040` and so on) decoded. Capacity comes from `statvfs`: `total_bytes` = blocks × fragment size, `free_bytes` includes blocks reserved for root, `avail_bytes` is what unprivileged users can use, `used_bytes` = total − free, `used_pct`/`free_pct` are shares of `total_bytes` (so `used_pct` is lower than the `Use%` of `df`, which divides by used + avail). Pseudo and read-only image filesystems (`proc`, `sysfs`, `devtmpfs`, `devpts`, `tmpfs`, `ramfs`, `securityfs`, `debugfs`, `tracefs`, `configfs`, `fusectl`, `cgroup`, `cgroup2`, `pstore`, `efivarfs`, `bpf`, `binfmt_misc`, `mqueue`, `hugetlbfs`, `autofs`, `nsfs`, `rpc_pipefs`, `nfsd`, `selinuxfs`, `squashfs`, `iso9660`, `udf`) are skipped unless `include_virtual=true`; `overlay` (a container's root) is reported. `io_device` is the whole disk behind the mount, found through the mount's device number and `/sys/dev/block` (a partition maps to its disk, `/dev/mapper/*` to its `dm-N`), else from the device name; `io.devices` are those disks' counters from `/proc/diskstats` (cumulative since boot; sectors are 512 bytes). A mount whose `statvfs` fails is listed without figures, with a warning.
* **env.list**: without `pid`, the environment of the resh process; with `pid`, `/proc/<pid>/environ` (the environment the process started with), which needs the same user or root. Values are masked (`***MASKED***`) unless `include_sensitive=true` when the name contains (case-insensitively) `password`, `passwd`, `pass`, `pwd`, `secret`, `token`, `api_key`, `apikey`, `access_key`, `private_key`, `client_secret`, `cred`, `cookie`, `session`, `database_url`, `dsn`, or both `auth` and `key` (`PWD` and `OLDPWD` themselves are not masked), or when the value is a URL with user information (`scheme://user:pass@host`). `include_raw` lists the same `NAME=value` entries, masked the same way. `value_length` and `truncate_length` count characters. `max_vars` keeps the first variables after sorting.
* **info**: each scope is read independently; a scope that cannot be read has `"available": false` and a warning, and the verb still succeeds. `kernel.machine` and `os.architecture` are the hardware name from `uname` (for example `x86_64`). `cpu.utilization_pct` is measured only when `sample_duration_ms` > 0 (same method as `cpu`). `memory.usage_pct` is (`MemTotal` − `MemAvailable`) / `MemTotal`. The `disk` scope lists non-pseudo filesystems, `/`, `/home`, `/var`, `/data`, `/boot` and `/tmp` first. The `process` scope counts processes in `/proc` by state (`sleeping` includes idle kernel threads, `stopped` includes traced ones) and lists the most common process names in `classes`.
* **Timeouts**: `statvfs` on a hung network filesystem can block, so `disk` and `info` take `timeout_ms` (default 30000). At the deadline the verb stops, prints what it collected with `"ok": false` and a `system.timeout` error, and exits 124. The other verbs only read `/proc` and `/sys` files and refuse `timeout_ms`; `cpu` takes `sample_duration_ms` (at most 60000) instead, and for `info` `sample_duration_ms` must be shorter than `timeout_ms`.

### 3.3 Output

Every successful response has `ok: true`, `timestamp_unix_ms` and `warnings`. The help of each verb (`resh system <verb> --help`) shows a complete example. Keys by `info` scope:

| Scope | Keys |
| ----- | ---- |
| `os` | `available`, `name`, `distribution`, `distribution_version`, `hostname`, `architecture` |
| `kernel` | `available`, `release`, `version`, `machine`, `boot_time_unix`, `uptime_seconds` |
| `cpu` | `available`, `count_logical` (present CPUs), `count_physical`, `online_logical`, `utilization_pct`, `per_cpu` (with `per_cpu=true`) |
| `memory` | `available`, `mem_total_bytes`, `mem_free_bytes`, `mem_available_bytes`, `buffers_bytes`, `cached_bytes`, `swap_total_bytes`, `swap_free_bytes`, `usage_pct` |
| `load` | `available`, `load_1m`, `load_5m`, `load_15m`, `runnable_processes`, `total_processes` |
| `disk` | `available`, `mounts_truncated`, `mounts` (`mount_point`, `fs_type`, `device`, `total_bytes`, `used_bytes`, `free_bytes`, `usage_pct`) |
| `process` | `available`, `total_processes`, `running`, `sleeping`, `zombie`, `stopped`, `blocked`, `classes` (`name`, `count`) |
| `pressure` | `available`, `cpu`, `io`, `memory` (each `some_avg10`, `some_avg60`, `some_avg300` and, when the kernel reports it, `full_*`; `null` when absent) |
| `cgroup` | `available`, `unified`, `paths` (`base`, `cpu`, `memory`), `limits` (`cpu_quota_pct`, `memory_limit_bytes`, only when limited) |
| `virtualization` | `available`, `is_container`, `container_type` (`docker`, `podman`, `kubernetes`, `lxc`), `is_virtual_machine`, `hypervisor_type` |

### 3.4 Errors

Failures print `Error: [<code>] <message>` on standard error. With `format=json` (the default) standard output also gets a JSON object with `ok: false` and `error: {code, message}` (for a timeout, with the partial results); with `format=text` nothing is printed on standard output.

```json
{
  "error": {
    "code": "system.invalid_argument",
    "message": "invalid scopes value \"kernal\" (did you mean `kernel`?) (expected one of: os, kernel, cpu, memory, load, disk, process, pressure, cgroup, virtualization)"
  },
  "ok": false
}
```

| Code | Exit | When |
| ---- | ---- | ---- |
| `system.invalid_argument` | 2 | Unknown option, bad value, bad `input`, `timeout_ms` or `dry_run` where not accepted. Nothing was read. |
| `system.invalid_target` | 2 | The URL has a target (`system://x.info`). |
| `system.unknown_verb` | 2 | The verb is not one of the seven. |
| `system.timeout` | 124 | `disk` or `info` reached `timeout_ms` waiting for `statvfs`. |
| `system.uptime_unavailable` | 1 | `/proc/uptime` cannot be read. |
| `system.uptime_parse_error` | 1 | `/proc/uptime` has no number of seconds. |
| `system.load_unavailable` | 1 | `/proc/loadavg` cannot be read. |
| `system.load_parse_error` | 1 | `/proc/loadavg` has no three load averages. |
| `system.memory_meminfo_unavailable` | 1 | `/proc/meminfo` cannot be read. |
| `system.memory_meminfo_parse_error` | 1 | `/proc/meminfo` has no `MemTotal`. |
| `system.cpu_stat_unavailable` | 1 | `/proc/stat` cannot be read (for either sample). |
| `system.cpu_stat_parse_error` | 1 | `/proc/stat` has no aggregate `cpu` line, or a `cpu` line is malformed. |
| `system.disk_mounts_unavailable` | 1 | Neither `/proc/self/mounts` nor `/proc/mounts` can be read. |
| `system.disk_mounts_parse_error` | 1 | The mounts table has lines but none can be read. |
| `system.disk_mount_not_found` | 1 | A `mount_points` or `devices` entry is not mounted. |
| `system.env_list_pid_not_found` | 1 | No process has that `pid`. |
| `system.env_list_permission_denied` | 1 | `/proc/<pid>/environ` belongs to another user (needs that user or root). |
| `system.env_list_unavailable` | 1 | `/proc/<pid>/environ` cannot be read for another reason. |

Missing optional figures (cgroup, topology, frequency, hugepages, I/O counters, queue counts, idle time) are not errors: they are left out or marked `available: false`, with a warning.

---

## 4. Containers and cgroups

* The cgroup figures are those of the resh process's own cgroup, found through `/proc/self/cgroup` and `/proc/self/mountinfo` (so they are right inside containers and cgroup namespaces, on the host and for systemd services). Both cgroup v2 (unified) and v1 are supported; on a hybrid host a controller attached to a v1 hierarchy is read there. `unified` is `true` for v2.
* Limits are hierarchical: the reported limit is the smallest one set on the process's cgroup or any ancestor up to the hierarchy's mount point.
* `memory` cgroup: `memory_usage_bytes` is `memory.current` (v2) or `memory.usage_in_bytes` (v1), which include page cache; `memory_limit_bytes` is `memory.max` / `memory.limit_in_bytes` and is absent when unlimited (`max`, or the v1 "unlimited" value). Swap: `memory.swap.max` / `memory.swap.current` on v2; on v1 the `memsw` files count memory plus swap, so swap is their difference from the memory figures. `memory_used_pct` is usage / limit.
* `cpu` cgroup: `cpu_quota_cores` = quota / period from `cpu.max` (v2) or `cpu.cfs_quota_us` / `cpu.cfs_period_us` (v1), for example 1.5 for `docker run --cpus 1.5`; absent when unlimited (`max` or -1). `usage_seconds`, `usage_user_seconds` and `usage_system_seconds` are cumulative CPU time of the cgroup (`cpu.stat` on v2; `cpuacct.usage` and `cpuacct.stat` on v1).
* `/proc/stat`, `/proc/meminfo`, `/proc/loadavg` and `/proc/uptime` are not namespaced: inside a container, the `system` sections of `memory` and `cpu`, `load` and `uptime` describe the whole host. Use the `cgroup` sections for the container's own limits and usage. `cpu.system.logical_count` counts the host's online CPUs, not a `--cpuset-cpus` set.
* Without cgroup information (no `/proc/self/cgroup`, or no controller for the process) the `cgroup` section has `available: false` and a warning.

---

## 5. Platform Support

* Linux only. The handle needs `/proc` (and `/sys` for topology, frequency and cgroup figures).
* `/proc/<pid>/environ` of another user's process needs that user or root.

---

## 6. Limitations

* `statvfs` cannot be interrupted: after a `timeout_ms` the worker thread waiting on a hung mount is abandoned, and the process may wait for it to return when it exits.
* The `cpu` utilization is for the whole host even inside a container (see section 4); the cgroup CPU time is reported only as cumulative seconds.
* The `disk` I/O counters are cumulative since boot, not rates.
* `env.list pid=<n>` shows the environment a process started with; later changes inside that process are not visible.

---

## 7. Operational Best Practices

* Check `warnings` in every response.
* Sample CPU for longer (for example 1000 ms) when accuracy matters.
* Use the per-CPU normalized load (`load_1m_per_cpu` etc.) when comparing hosts.
* Prefer `mem_available_bytes` over `mem_free_bytes` for capacity decisions; in containers, compare `cgroup.memory_usage_bytes` with `cgroup.memory_limit_bytes`.
* Limit response size with `max_mounts`, `max_vars` and `info fields`.
* Keep `include_sensitive=false` unless you need the raw values.

---

## 8. Use Cases by Role

### DevOps Engineers

* Validate build hosts.
* Confirm resource availability (including container limits) before deployments.

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

* Implemented in Rust; reads `/proc`, `/sys` and `/etc/os-release` directly and calls `statvfs` and `uname`. No subprocess is run.
* Fixed verb set; options are checked against one list per verb.
* Error codes are listed in section 3.4.
