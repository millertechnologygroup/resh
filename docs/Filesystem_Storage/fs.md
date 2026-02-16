# Resource Shell (resh) – Filesystem Handle Documentation

## 1. Overview

Resource Shell (resh) is a structured command execution framework that standardizes infrastructure operations using a resource-oriented URI model.

The `fs://` handle provides comprehensive management of mounted filesystems and storage devices. It supports:

* Mounting and unmounting filesystems
* Disk usage monitoring
* Filesystem resizing
* Integrity checks and repair
* Quota inspection
* Mount configuration snapshotting
* Mount inventory reporting

Traditional filesystem administration relies on heterogeneous tools (`mount`, `umount`, `df`, `fsck`, `quota`, `resize2fs`, etc.), each with different syntax and output formats. This fragmentation complicates automation and increases parsing complexity.

The `fs://` handle addresses this by:

* Providing a unified URI-based interface
* Standardizing argument structures
* Returning structured output where applicable
* Defining explicit exit codes
* Supporting dry-run and timeout controls for safety

All filesystem operations follow:

```
fs://alias.VERB(arguments)
```

Where `alias` represents a logical filesystem profile (e.g., `system`, `local`, or a custom-defined alias).

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

Filesystem operations use a consistent URI structure:

```
fs://alias.verb(arguments)
```

Examples:

```bash
fs://system.mount(target="/mnt/usb",source="/dev/sdb1")
fs://system.usage()
fs://system.check(target="/dev/sdb1")
```

The handle provides **9 verbs** grouped into functional categories.

---

### Safety-First Execution

Safety mechanisms include:

* `dry_run=true` support for non-destructive validation
* Explicit flags for risky operations (`allow_shrink`, `allow_repair`, `force`)
* Timeout controls (`timeout_ms`)
* Explicit remount and fail-if conditions
* Automatic directory creation safeguards
* Explicit unmount requirements before shrink or repair operations

Most operations require root privileges and return exit code `13` if insufficient permissions are detected.

---

### Deterministic Behavior

Filesystem operations:

* Require explicit `target` paths or devices
* Use structured argument validation
* Return consistent exit codes
* Avoid ambiguous positional arguments
* Support explicit selection of resolution methods (`by=auto|mountpoint|device`)

---

### JSON-Based Structured Output

Structured output is provided for:

* `snapshot`
* `quota`
* `quota_summary`
* `usage`
* `list-mounts`

Example snapshot output:

```json
{
  "timestamp": "2025-02-07T10:30:00Z",
  "mounts": [
    {
      "target": "/",
      "source": "/dev/sda1",
      "type": "ext4",
      "options": ["rw", "relatime"],
      "usage": {
        "total_bytes": 107374182400,
        "used_bytes": 53687091200,
        "available_bytes": 53687091200,
        "used_percent": 50.0
      }
    }
  ]
}
```

Automation systems should rely on structured JSON and exit codes rather than parsing textual output.

---

### AI-Readiness

The URI grammar and structured outputs enable:

* Infrastructure automation
* Policy validation workflows
* Predictable orchestration
* Deterministic error handling
* Programmatic inspection of filesystem state

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
fs://alias.verb(arguments)
```

#### Components

| Component   | Description                |
| ----------- | -------------------------- |
| `fs`        | Filesystem handle          |
| `alias`     | Logical filesystem profile |
| `verb`      | Operation to perform       |
| `arguments` | Named parameters           |

**Common aliases:**

* `system`
* `local`
* Custom-defined aliases

---

### Example Commands

Mount USB device:

```bash
fs://system.mount(target="/mnt/usb",source="/dev/sdb1",type="ext4")
```

List mounts:

```bash
fs://system.list-mounts()
```

Check disk usage:

```bash
fs://system.usage(human_readable=true)
```

Resize filesystem:

```bash
fs://system.resize(target="/data",delta="+50G")
```

Repair filesystem:

```bash
fs://system.check(target="/dev/sdb1",mode="repair",allow_repair=true)
```

---

### 3.2 Execution Semantics

Operations may:

* Return no output (success indicated by exit code 0)
* Return structured JSON (snapshot, quota, usage)
* Return error codes for safety or system conditions

Common exit codes:

| Code | Meaning                    |
| ---- | -------------------------- |
| 0    | Success                    |
| 1    | Invalid arguments          |
| 2    | Target not found           |
| 3    | Unsupported                |
| 13   | Permission denied          |
| 16   | Resource busy              |
| 17   | Conflicting operation      |
| 18   | Failed to create directory |
| 19   | Not mounted                |
| 32   | General failure            |
| 62   | Timeout                    |
| 95   | Unknown verb               |

Automation should always inspect exit codes.

---

## 4. Functional Domains

### 4.1 Automation Utilities

#### snapshot

Creates a mount configuration snapshot.

Use cases:

* Change auditing
* Pre-maintenance capture
* Compliance tracking

Example:

```bash
fs://system.snapshot(format="json",include_usage=true)
```

---

### 4.2 Data & State Management

#### usage

Reports disk usage.

```bash
fs://system.usage(mode="aggregate")
```

#### quota

Reports quota information.

```bash
fs://system.quota(subject="alice",path="/home")
```

#### quota_summary

Aggregates quota data across filesystems.

```bash
fs://system.quota_summary(all_subjects=true)
```

Use cases:

* Capacity planning
* Multi-tenant system monitoring
* Threshold-based alerting

---

### 4.3 Filesystem & Storage

#### mount

Mount filesystem to target.

#### unmount (alias: umount)

Unmount filesystem.

#### list-mounts

Inventory mounted filesystems.

Example:

```bash
fs://system.mount(target="/mnt/data",source="/dev/sdb1",create_target=true)
fs://system.unmount(target="/mnt/data")
```

Use cases:

* USB drive management
* NFS/CIFS mounting
* Bind mounts
* Secure chroot environments

---

### 4.4 Storage Management

#### resize

Resize filesystem and optionally underlying volumes.

```bash
fs://system.resize(target="/data",delta="+50G",manage_underlying_volume=true)
```

#### check (alias: fsck)

Check and optionally repair filesystem.

```bash
fs://system.check(target="/dev/sdb1",mode="check")
```

Use cases:

* Volume expansion
* LVM workflows
* Maintenance windows
* Filesystem integrity verification

---

### 4.5 Network & Remote Operations

Network mounts supported via:

* NFS
* CIFS

Example:

```bash
fs://system.mount(target="/mnt/nfs",source="server:/export",type="nfs",network=true)
```

Use cases:

* Centralized storage
* Backup targets
* Shared enterprise filesystems

---

### 4.6 Packages & Software

Not applicable to `fs://`.

---

### 4.7 Process & Service Management

Not applicable to `fs://`.

---

### 4.8 Security & Secrets

Security-related operations include:

* Read-only mounts (`read_only=true`)
* Security mount options (`noexec`, `nosuid`, `nodev`)
* Quota enforcement
* Permission enforcement via root-only execution

Example:

```bash
fs://system.mount(target="/secure",source="/dev/sdb1",options=["noexec","nosuid","nodev"])
```

---

### 4.9 System Information

#### list-mounts

Enumerates mount table.

#### usage

Reports usage metrics.

Supports:

* Type filtering
* Source filtering
* Threshold filtering
* Label resolution

Example:

```bash
fs://system.list-mounts(include_types=["ext4","xfs"])
```

---

## 5. Platform Support

Based on provided documentation:

* Designed for Unix-like systems.
* Requires root privileges for most operations.
* Supports Linux filesystem types including ext4, xfs, btrfs, ntfs, vfat, exfat, NFS, CIFS.
* Virtual filesystem filtering supported (`proc`, `sysfs`, `tmpfs`, `devtmpfs`).

No Windows-native support details provided in the source documentation.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Always test with `dry_run=true`.
* Create `snapshot` before major changes.
* Use explicit flags for shrink or repair.
* Avoid `force=true` unless required.
* Exclude pseudo filesystems during monitoring.
* Use read-only mounts where applicable.

---

### Automation Considerations

* Use threshold filters in monitoring workflows.
* Use `aggregate` mode for capacity dashboards.
* Always verify resize operations with `usage`.
* Set explicit `timeout_ms` for long-running operations.

---

### CI/CD Integration

Typical patterns:

```bash
# Snapshot before deployment
fs://system.snapshot(format="json")

# Verify mount state
fs://system.list-mounts()

# Validate capacity
fs://system.usage(threshold_used_percent_min=80)
```

---

### Production Recommendations

* Use read-only mounts for backups.
* Enable quotas in multi-user environments.
* Monitor grace periods.
* Exclude pseudo filesystems in monitoring.
* Use bind mounts for isolation patterns.
* Verify health with `check` before resizing.

---

## 7. Use Cases by Role

### DevOps Engineers

* Automate mount management during deployment.
* Monitor storage thresholds.
* Resize volumes in CI/CD.
* Snapshot configuration before infrastructure changes.

---

### SRE Engineers

* Diagnose resource exhaustion.
* Perform safe filesystem repair.
* Monitor quota enforcement.
* Track mount drift via snapshots.

---

### Network Administrators

* Mount and manage NFS/CIFS shares.
* Secure mounts with restrictive options.
* Monitor remote storage availability.
* Enforce quota policies.

---

### AI / Automation Engineers

* Use structured JSON outputs for monitoring systems.
* Integrate `usage` thresholds into alerting engines.
* Automate capacity expansion workflows.
* Orchestrate deterministic maintenance procedures.

---

## 8. Technical Foundation

The filesystem handle is implemented within resh’s Rust-based execution framework.

### Rust Implementation Advantages

* Memory safety guarantees
* Strong type enforcement
* Deterministic error handling
* Controlled privilege operations

---

### Type Safety

* Strict argument parsing
* Explicit mode flags
* Enumerated option validation
* Explicit exit code mapping

---

### Performance Characteristics

* Timeout-controlled long-running operations
* Structured mount filtering
* Targeted filesystem resolution methods
* Efficient mount inventory reporting

---

### Cross-Platform Architecture

The documentation describes integration with Unix-style filesystem management tools and filesystem types.

Operations assume:

* Standard mount interfaces
* Unix-style permission model
* Root privilege model

No non-Unix implementation details are provided in the source documentation.

