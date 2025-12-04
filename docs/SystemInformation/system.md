# System Handle

The system handle provides access to system information including CPU, memory, disk usage, load averages, and environment variables. It collects data from Linux systems through `/proc` filesystem interfaces and other system sources.

## Overview

The system handle supports seven verbs for gathering different types of system information:

- `info` - Comprehensive system information across multiple scopes
- `uptime` - System uptime and boot time information  
- `load` - CPU load averages and process counts
- `memory` - RAM and swap memory usage details
- `cpu` - CPU utilization and topology information
- `disk` - Disk usage and mount point statistics
- `env.list` - Environment variables listing and filtering

All verbs return JSON output by default, with optional text formatting available for some verbs.

## Common Features

### Output Format
Most verbs support format selection through options:
- `json` (default) - Structured JSON response
- `text` - Human-readable text format

### Optional Data
Verbs can include additional data fields:
- `include_raw` - Include raw system data in response
- `include_paths` - Include file paths used for data collection
- `include_human` - Include human-readable summaries

### Error Handling
All verbs return structured error information when issues occur, including specific error codes and descriptive messages.

## Verbs

### info

Gathers comprehensive system information across configurable scopes including operating system details, kernel information, CPU metrics, memory usage, and load averages.

**Basic Usage:**
```bash
resh 'system://.info'
```

**Example Output:**
```json
{
  "ok": true,
  "timestamp_unix_ms": 1764860354626,
  "scopes": ["os", "kernel", "cpu", "memory", "load"],
  "os": {
    "available": true,
    "name": "Linux",
    "distribution": "Ubuntu", 
    "distribution_version": "22.04",
    "hostname": "ASUS-LT",
    "architecture": "GNU/Linux"
  },
  "kernel": {
    "available": true,
    "release": "6.6.87.2-microsoft-standard-WSL2",
    "version": "#1",
    "machine": "GNU/Linux",
    "uptime_seconds": 4545.68,
    "boot_time_unix": 1764855808
  },
  "cpu": {
    "available": true,
    "count_logical": 20,
    "count_physical": null,
    "online_logical": 20,
    "utilization_pct": null
  },
  "memory": {
    "available": true,
    "mem_total_bytes": 8129781760,
    "mem_free_bytes": 592498688,
    "mem_available_bytes": 6139670528,
    "buffers_bytes": 129314816,
    "cached_bytes": 5430431744,
    "swap_total_bytes": 2147483648,
    "swap_free_bytes": 1874522112,
    "usage_pct": 24.479270056075897
  },
  "load": {
    "available": true,
    "load_1m": 0.47,
    "load_5m": 5.42,
    "load_15m": 11.88,
    "runnable_processes": 2,
    "total_processes": 575
  },
  "warnings": []
}
```

**Options:**
```json
{
  "scopes": ["os", "kernel", "cpu", "memory", "load"],
  "fields": null,
  "sample_duration_ms": 0,
  "sample_min_ms": 50,
  "per_cpu": false,
  "max_mounts": 32,
  "max_process_classes": 5,
  "include_raw": false,
  "include_paths": false,
  "format": "json"
}
```

**Available Scopes:**
- `os` - Operating system information
- `kernel` - Kernel version and system details
- `cpu` - CPU count and utilization 
- `memory` - Memory and swap usage
- `load` - System load averages
- `disk` - Disk usage statistics
- `process` - Process information
- `pressure` - System pressure metrics
- `cgroup` - Control group information
- `virtualization` - Virtualization platform details

### uptime

Reports system uptime, boot time, and idle time information.

**Basic Usage:**
```bash
resh 'system://.uptime'
```

**Example Output:**
```json
{
  "ok": true,
  "timestamp_unix_ms": 1764860357059,
  "uptime_seconds": 4548.11,
  "uptime_human": "1h 15m 48s",
  "boot_time_unix": 1764855808,
  "idle_seconds": 84183.96,
  "idle_seconds_per_cpu": 4209.198,
  "warnings": []
}
```

**Options:**
```json
{
  "include_idle": true,
  "include_boot_time": true, 
  "include_human": true,
  "include_raw": false,
  "include_paths": false,
  "format": "json"
}
```

**Text Format Example:**
Use `"format": "text"` for readable output showing system uptime details with timestamps and human-friendly duration formatting.

### load

Provides system load averages, process counts, and load analysis.

**Basic Usage:**
```bash
resh 'system://.load'
```

**Example Output:**
```json
{
  "ok": true,
  "timestamp_unix_ms": 1764860361714,
  "load_1m": 0.43,
  "load_5m": 5.33, 
  "load_15m": 11.82,
  "load_1m_per_cpu": 0.0215,
  "load_5m_per_cpu": 0.2665,
  "load_15m_per_cpu": 0.591,
  "cpu_count_logical": 20,
  "runnable_processes": 1,
  "total_processes": 575,
  "human": {
    "status": "idle",
    "status_reason": "1m load per CPU is very low (< 0.1)",
    "load_vs_cpu_ratio": 0.0215
  },
  "warnings": []
}
```

**Options:**
```json
{
  "normalize_per_cpu": true,
  "include_queue": true,
  "include_human": true,
  "include_raw": false,
  "include_paths": false,
  "min_cpu_count": 1,
  "format": "json"
}
```

**Load Status Interpretation:**
- Load per CPU < 0.1: idle
- Load per CPU 0.1-0.7: normal  
- Load per CPU 0.7-1.0: busy
- Load per CPU > 1.0: overloaded

### memory

Shows system memory usage including RAM, swap, buffers, cache, and cgroup information.

**Basic Usage:**
```bash
resh 'system://.memory'
```

**Example Output:**
```json
{
  "ok": true,
  "timestamp_unix_ms": 1764860359389,
  "system": {
    "available": true,
    "mem_total_bytes": 8129781760,
    "mem_free_bytes": 581423104,
    "mem_available_bytes": 6128668672,
    "buffers_bytes": 129339392,
    "cached_bytes": 5430489088,
    "shmem_bytes": 2904064,
    "sreclaimable_bytes": 191078400,
    "swap_total_bytes": 2147483648,
    "swap_free_bytes": 1874784256,
    "mem_used_bytes": 2001113088,
    "mem_used_pct": 24.61459787082895,
    "swap_used_bytes": 272699392,
    "swap_used_pct": 12.698554992675781
  },
  "hugepages": {
    "available": true,
    "total": 0,
    "free": 0,
    "reserved": 0,
    "surplus": 0,
    "page_bytes": 2097152
  },
  "cgroup": {
    "available": false,
    "unified": false
  },
  "human": {
    "system_summary": "7.6 GiB total, 1.9 GiB used (24.6%), 0.3 GiB swap used (12.7%)"
  },
  "warnings": [
    "Cgroup v2 memory metrics not available, trying v1",
    "Cgroup memory metrics not available on this system"
  ]
}
```

**Options:**
```json
{
  "include_swap": true,
  "include_cgroup": true,
  "include_hugepages": true,
  "include_human": true,
  "include_raw": false,
  "include_paths": false,
  "format": "json"
}
```

### cpu

Reports CPU utilization, topology, frequency, and per-core statistics.

**Basic Usage:**
```bash
resh 'system://.cpu'
```

**Example Output:**
```json
{
  "ok": true,
  "timestamp_unix_ms": 1764860363960,
  "system": {
    "available": true,
    "logical_count": 20,
    "physical_count": 10,
    "socket_count": 1,
    "utilization_pct": 0.2,
    "user_pct": 0.2,
    "nice_pct": 0.0,
    "system_pct": 0.0,
    "idle_pct": 99.8,
    "iowait_pct": 0.0,
    "irq_pct": 0.0,
    "softirq_pct": 0.0,
    "steal_pct": 0.0,
    "guest_pct": 0.0,
    "guest_nice_pct": 0.0
  },
  "per_cpu": [
    {
      "id": 0,
      "utilization_pct": 3.8461538461538463,
      "user_pct": 3.8461538461538463,
      "nice_pct": 0.0,
      "system_pct": 0.0,
      "idle_pct": 96.15384615384616,
      "iowait_pct": 0.0,
      "irq_pct": 0.0,
      "softirq_pct": 0.0,
      "steal_pct": 0.0,
      "guest_pct": 0.0,
      "guest_nice_pct": 0.0,
      "core_id": 0,
      "socket_id": 0
    }
  ],
  "cgroup": {
    "available": false
  },
  "human": {
    "status": "idle",
    "status_reason": "Overall CPU utilization is 0.2%, system is idle.",
    "per_cpu_hotspots": []
  },
  "warnings": [
    "CPU frequency information not available",
    "CPU cgroup information not available"
  ]
}
```

**Options:**
```json
{
  "sample_duration_ms": 250,
  "sample_min_ms": 50,
  "per_cpu": true,
  "include_topology": true,
  "include_frequency": true,
  "include_cgroup": true,
  "include_human": true,
  "include_raw": false,
  "include_paths": false,
  "format": "json"
}
```

**Sampling:**
- Default sample duration: 250ms
- Minimum sample duration: 50ms
- Per-CPU metrics available with `per_cpu: true`

### disk

Shows disk usage statistics for mounted filesystems including space utilization and I/O metrics.

**Basic Usage:**
```bash
resh 'system://.disk'
```

**Example Output (abbreviated):**
```json
{
  "ok": true,
  "timestamp_unix_ms": 1764860368195,
  "mounts_truncated": false,
  "mounts": [
    {
      "mount_point": "/",
      "device": "/dev/sdd",
      "fs_type": "ext4",
      "virtual_fs": false,
      "total_bytes": 1081101176832,
      "used_bytes": 283048882176,
      "free_bytes": 798052294656,
      "avail_bytes": 743059939328,
      "used_pct": 26.18153492399583,
      "free_pct": 73.81846507600417,
      "inodes_total": 67108864,
      "inodes_used": 1385458,
      "inodes_free": 65723406,
      "inodes_used_pct": 2.0644932985305786,
      "io_device": "sdd",
      "tags": ["rootfs"],
      "human_summary": "/: 1006.9 GiB total, 263.6 GiB used (26.2%)"
    }
  ],
  "io": {
    "available": true,
    "devices": [
      {
        "name": "sdd",
        "maj_min": "8:48", 
        "reads_completed": 4514767,
        "writes_completed": 1693369,
        "sectors_read": 448590746,
        "sectors_written": 36754440,
        "read_bytes": 229678461952,
        "write_bytes": 18818273280,
        "time_reading_ms": 12390378,
        "time_writing_ms": 71411137,
        "ios_in_progress": 0,
        "time_in_io_ms": 366984,
        "weighted_time_in_io_ms": 83827093
      }
    ]
  },
  "human": {
    "summaries": [
      "/: 1006.9 GiB total, 263.6 GiB used (26.2%)"
    ]
  },
  "warnings": []
}
```

**Options:**
```json
{
  "mount_points": [],
  "devices": [],
  "fs_types": [],
  "include_virtual": false,
  "include_io": true,
  "include_human": true,
  "include_raw": false,
  "include_paths": false,
  "max_mounts": 32,
  "format": "json"
}
```

**Filtering:**
- `mount_points` - Filter by specific mount points
- `devices` - Filter by device names 
- `fs_types` - Filter by filesystem types
- `include_virtual` - Include virtual/pseudo filesystems

**Filesystem Tags:**
- `rootfs` - Root filesystem mount
- `home` - Home directory mount
- `data` - Data storage mount

### env.list

Lists and filters environment variables from the current process or a specified process ID.

**Basic Usage:**
The `env.list` verb can be used to examine environment variables:

**Unit Test Example:**
From the unit tests, basic environment variable listing works with the default options:

```rust
let opts = SystemEnvListOptions::default();
let response = handle.collect_env_list(&opts, &provider);
```

**Test Data Example:**
```rust
let mock_env = vec![
    ("PATH".to_string(), "/usr/bin".to_string()),
    ("HOME".to_string(), "/home/user".to_string()),
    ("USER".to_string(), "testuser".to_string()),
    ("PASSWORD".to_string(), "secret123".to_string()),
    ("API_KEY".to_string(), "abc123def456".to_string())
];
```

**Response Format:**
Based on the unit tests, responses include:
- `ok` - Success status
- `timestamp_unix_ms` - Collection timestamp
- `env_count_returned` - Number of variables returned
- `env_count_total` - Total variables available
- `variables` - Array of environment variable entries
- `source` - Source information (current process or PID)
- `warnings` - Any collection warnings

**Variable Entry Format:**
Each variable contains:
- `name` - Variable name
- `value` - Variable value (may be masked for sensitive data)
- `masked` - Whether the value was masked for security
- `byte_length` - Length in bytes

**Security Features:**
- Automatic masking of sensitive variables (passwords, keys, tokens)
- Configurable filtering by name patterns
- Process isolation (can access environment from specific PIDs)

**Options:**
```rust
{
  "pid": null,              // Process ID (null for current process)
  "name_filter": null,      // Regex filter for variable names
  "mask_sensitive": true,   // Mask sensitive variables
  "max_variables": 1000,    // Limit number of variables returned
  "max_value_bytes": 16384, // Limit variable value size
  "include_masked": true,   // Include masked variables in output
  "include_raw": false,     // Include raw environment data
  "include_paths": false,   // Include file paths used
  "format": "json"          // Output format
}
```

## Error Codes

The system handle returns specific error codes for different failure scenarios:

### Common Errors
- `system.info_scope_invalid` - Invalid scope specified
- `system.info_fields_invalid` - Invalid fields specification  
- `system.info_proc_unavailable` - `/proc` filesystem unavailable
- `system.info_timeout` - Operation timeout
- `system.info_data_too_large` - Response data exceeds limits

### Memory Errors
- `system.memory_unavailable` - Memory information unavailable
- `system.memory_meminfo_unavailable` - `/proc/meminfo` unavailable
- `system.memory_parse_error` - Error parsing memory data

### CPU Errors  
- `system.cpu_unavailable` - CPU information unavailable
- `system.cpu_stat_unavailable` - `/proc/stat` unavailable
- `system.cpu_parse_error` - Error parsing CPU data

### Disk Errors
- `system.disk_unavailable` - Disk information unavailable
- `system.disk_mounts_unavailable` - Mount information unavailable
- `system.disk_statvfs_failed` - Filesystem stats failed

### Environment Errors
- `system.env_list_unavailable` - Environment listing unavailable
- `system.env_list_pid_unavailable` - Process environment unavailable
- `system.env_list_invalid_regex` - Invalid regex filter

## Performance Notes

### Sampling
- CPU utilization requires sampling over time (default 250ms)
- Shorter sampling periods may be less accurate
- Longer periods provide more stable measurements

### Resource Usage
- Disk verb can return large amounts of data with many mounts
- Use `max_mounts` option to limit output size
- Environment listing can be filtered to reduce data volume

### Caching
- System information is collected fresh on each request
- No internal caching is performed
- For frequent monitoring, consider external caching strategies

## Platform Support

The system handle is designed for Linux systems and uses:
- `/proc` filesystem for most system information
- `statvfs()` system call for disk statistics  
- `/sys` filesystem for hardware topology
- Standard Unix environment variable access

Virtual environments (containers, WSL) are supported with appropriate warnings when certain features are unavailable.