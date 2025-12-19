# Filesystem Handle Documentation

The filesystem handle in Resource Shell helps you work with mounted filesystems and storage devices. It provides tools to mount and unmount filesystems, check disk usage, resize partitions, and create snapshots of your filesystem configuration.

## URL Format

Filesystem handle URLs use the `fs://` scheme followed by an alias:
```
fs://alias.verb(arguments)
```

Common aliases include `system`, `local`, or custom names you define.

## Available Verbs

### mount
Mounts a filesystem to a directory on your system.

**Arguments:**
- `target` - Where to mount the filesystem (required)
- `source` - What device or filesystem to mount (optional for some operations)
- `type` - Filesystem type like "ext4", "xfs", "btrfs" (optional, auto-detected if not provided)
- `options` - List of mount options (default: empty list)
- `read_only` - Mount as read-only (default: false)
- `bind` - Create a bind mount (default: false)
- `create_target` - Create the target directory if it doesn't exist (default: true)
- `make_parents` - Create parent directories too (default: true)
- `fail_if_mounted` - Fail if already mounted (default: false)
- `remount` - Remount an existing mount with new options (default: false)
- `network` - This is a network filesystem (default: false)
- `timeout_ms` - How long to wait before giving up (default: 30000)
- `dry_run` - Show what would be done without doing it (default: false)

**Examples:**
```bash
# Mount a USB drive
fs://system.mount(target="/mnt/usb", source="/dev/sdb1", type="ext4")
```

```bash
# Create target directory and mount with specific options
fs://system.mount(target="/mnt/data", source="/dev/sdb1", create_target=true, options=["noatime", "user_xattr"])
```

```bash
# Dry run to see what would happen
fs://system.mount(target="/mnt/test", source="/dev/sdb1", type="ext4", dry_run=true)
```

### unmount (or umount)
Removes a mounted filesystem from your system.

**Arguments:**
- `target` - What to unmount (required)
- `by` - How to find what to unmount: "target", "source", or "auto" (default: "target")
- `force` - Force unmount even if busy (default: false)
- `lazy` - Detach the filesystem now, clean up later (default: false)
- `detach_children` - Also unmount child mounts (default: false)
- `fail_if_not_mounted` - Fail if nothing is mounted there (default: false)
- `timeout_ms` - How long to wait before giving up (default: 5000)
- `dry_run` - Show what would be done without doing it (default: false)

**Examples:**
```bash
# Unmount by target directory
fs://system.unmount(target="/mnt/usb")
```

```bash
# Force unmount if filesystem is busy
fs://system.unmount(target="/mnt/data", force=true)
```

```bash
# Unmount by source device
fs://system.unmount(target="/dev/sdb1", by="source")
```

### snapshot
Creates a snapshot of your current filesystem mount configuration.

**Arguments:**
- `include_mountpoints` - Only include these mount points (default: include all)
- `exclude_mountpoints` - Skip these mount points (default: empty list)
- `include_types` - Only include these filesystem types (default: include all)
- `exclude_types` - Skip these filesystem types (default: empty list)
- `include_sources` - Only include these source devices (default: include all)
- `exclude_sources` - Skip these source devices (default: empty list)
- `include_usage` - Include disk space usage information (default: true)
- `include_inodes` - Include inode usage information (default: false)
- `include_fs_metadata` - Include filesystem details (default: true)
- `include_os_metadata` - Include system information (default: true)
- `normalize_paths` - Clean up path formatting (default: true)
- `format` - Output format: "json", "yaml", or "text" (default: "json")
- `inline` - Include data in response vs file reference (default: true)
- `timeout_ms` - How long to wait for information (default: 5000)

**Examples:**
```bash
# Basic snapshot with usage information
fs://system.snapshot(include_types=["ext4", "xfs"], exclude_mountpoints=["/proc", "/sys", "/dev", "/run"])
```

```bash
# Text format snapshot without usage data
fs://local.snapshot(include_mountpoints=["/"], exclude_types=["proc", "sysfs", "tmpfs"], include_usage=false, format="text")
```

### quota
Shows disk quota information for users or groups on quota-enabled filesystems.

**Arguments:**
- `path` - Filesystem path to check quotas on (optional)
- `subject` - User or group name to check (optional, shows current user if not specified)
- `subject_type` - Whether subject is "user" or "group" (default: "user")
- `resolve_uid_gid` - Convert user/group IDs to names (default: true)
- `include_space` - Show disk space quotas (default: true)
- `include_inodes` - Show file count quotas (default: true)
- `include_grace` - Show grace period information (default: true)
- `all_subjects` - Show quotas for all users/groups (default: false)
- `units` - Display units: "auto", "bytes", "kilobytes", "megabytes", "gigabytes", or "blocks" (default: "auto")
- `timeout_ms` - How long to wait for quota information (default: 5000)

**Examples:**
```bash
# Check current user's quota
fs://system.quota(path="/home")
```

```bash
# Check quotas for specific user
fs://system.quota(subject="alice", path="/var/mail")
```

```bash
# Show all user quotas on a filesystem
fs://system.quota(path="/data", all_subjects=true)
```

### quota_summary
Shows a summary of quota usage across multiple filesystems.

**Arguments:**
- `subject` - User or group name (optional, shows current user if not specified)
- `subject_type` - Whether subject is "user" or "group" (default: "auto")
- `resolve_uid_gid` - Convert user/group IDs to names (default: true)
- `include_mountpoints` - Only check these mount points (default: check all)
- `exclude_mountpoints` - Skip these mount points (default: empty list)
- `include_types` - Only check these filesystem types (default: check all)
- `exclude_types` - Skip these filesystem types (default: empty list)
- `include_sources` - Only check these source devices (default: check all)
- `exclude_sources` - Skip these source devices (default: empty list)
- `include_space` - Show disk space quotas (default: true)
- `include_inodes` - Show file count quotas (default: true)
- `include_grace` - Show grace period information (default: true)
- `all_subjects` - Show quotas for all users/groups (default: false)
- `units` - Display units: "auto", "bytes", "kilobytes", "megabytes", "gigabytes", or "blocks" (default: "auto")
- `timeout_ms` - How long to wait for quota information (default: 5000)

**Examples:**
```bash
# Summary of current user's quotas across all filesystems
fs://system.quota_summary()
```

```bash
# Summary excluding system filesystems
fs://system.quota_summary(exclude_types=["proc", "sysfs", "tmpfs", "devtmpfs"])
```

### usage
Shows disk space usage information for filesystems or specific paths.

**Arguments:**
- `paths` - Specific paths to check (default: empty list, use mode setting)
- `mode` - How to report usage: "mounts" (all mount points), "paths" (specific paths), or "aggregate" (combined totals) (default: "mounts")
- `include_mountpoints` - Only include these mount points (default: include all)
- `exclude_mountpoints` - Skip these mount points (default: empty list)
- `include_types` - Only include these filesystem types (default: include all)
- `exclude_types` - Skip these filesystem types (default: empty list)
- `include_sources` - Only include these source devices (default: include all)
- `exclude_sources` - Skip these source devices (default: empty list)
- `include_inodes` - Include file count information (default: true)
- `include_readonly` - Include read-only filesystems (default: true)
- `normalize_paths` - Clean up path formatting (default: true)
- `units` - Display units: "auto", "bytes", "kilobytes", "megabytes", "gigabytes", or "blocks" (default: "auto")
- `human_readable` - Use human-friendly sizes like "1.2G" (default: false)
- `threshold_used_percent_min` - Only show filesystems above this usage percent (optional)
- `threshold_used_percent_max` - Only show filesystems below this usage percent (optional)
- `timeout_ms` - How long to wait for usage information (default: 5000)

**Examples:**
```bash
# Show usage for all mounted filesystems
fs://system.usage()
```

```bash
# Show usage excluding system filesystems with human-readable sizes
fs://system.usage(exclude_types=["proc", "sysfs", "tmpfs", "devtmpfs"], human_readable=true)
```

```bash
# Show total usage across all filesystems
fs://system.usage(mode="aggregate", exclude_types=["proc", "sysfs", "tmpfs", "devtmpfs"])
```

```bash
# Check specific paths
fs://system.usage(mode="paths", paths=["/", "/home", "/var"])
```

### resize
Changes the size of a filesystem or its underlying storage.

**Arguments:**
- `target` - Filesystem mount point or device to resize (required)
- `by` - How to find the target: "auto", "mountpoint", or "device" (default: "auto")
- `size` - New size (e.g., "100G", "500M") - use either this or delta
- `delta` - Size change (e.g., "+50G", "-10G") - use either this or size
- `size_units` - Units for sizes: "auto", "bytes", "kilobytes", "megabytes", "gigabytes", or "terabytes" (default: "auto")
- `mode` - Resize direction: "grow", "shrink", or "auto" (default: "grow")
- `allow_shrink` - Allow making filesystem smaller (default: false)
- `min_free_space_percent` - Keep at least this much free space (default: 5.0)
- `manage_underlying_volume` - Also resize LVM/storage volumes (default: false)
- `volume_resize_only` - Only resize volume, not filesystem (default: false)
- `filesystem_resize_only` - Only resize filesystem, not volume (default: false)
- `require_unmounted_for_shrink` - Unmount before shrinking (default: true)
- `force` - Skip safety checks (default: false)
- `dry_run` - Show what would be done without doing it (default: false)
- `timeout_ms` - How long to wait for resize operation (default: 600000)

**Examples:**
```bash
# Grow filesystem to 100GB
fs://system.resize(target="/data", size="100G")
```

```bash
# Add 50GB to current size
fs://system.resize(target="/data", delta="+50G")
```

```bash
# Shrink filesystem by 20GB (must allow shrinking)
fs://system.resize(target="/data", delta="-20G", allow_shrink=true)
```

```bash
# Dry run to see what would happen
fs://system.resize(target="/data", size="100G", dry_run=true)
```

### check (or fsck)
Checks a filesystem for errors and optionally repairs them.

**Arguments:**
- `target` - Filesystem mount point or device to check (required)
- `by` - How to find the target: "auto", "mountpoint", or "device" (default: "auto")
- `filesystem_type` - Override filesystem type detection (optional)
- `mode` - What to do: "check", "repair", or "auto" (default: "check")
- `aggressiveness` - How thorough: "safe", "normal", or "aggressive" (default: "safe")
- `allow_repair` - Allow fixing errors found (default: false)
- `allow_online_check` - Check mounted filesystems if supported (default: true)
- `require_unmounted_for_repair` - Unmount before repairing (default: true)
- `skip_if_mounted` - Skip check if filesystem is mounted (default: false)
- `force` - Override safety checks (default: false)
- `max_pass` - Maximum number of check passes (optional)
- `btrfs_use_scrub` - Use scrub for btrfs instead of fsck (default: true)
- `btrfs_allow_offline_check` - Allow offline btrfs check (default: false)
- `dry_run` - Show what would be done without doing it (default: false)
- `timeout_ms` - How long to wait for check operation (default: 600000)

**Examples:**
```bash
# Check filesystem for errors (read-only)
fs://system.check(target="/dev/sdb1")
```

```bash
# Check and repair filesystem if errors found
fs://system.check(target="/dev/sdb1", mode="repair", allow_repair=true)
```

```bash
# Aggressive check of unmounted filesystem
fs://system.check(target="/data", aggressiveness="aggressive", skip_if_mounted=false)
```

### list-mounts
Shows information about currently mounted filesystems.

**Arguments:**
- `paths` - Only show mounts for these specific paths (default: show all)
- `include_mountpoints` - Only include these mount points (default: include all)
- `exclude_mountpoints` - Skip these mount points (default: empty list)
- `include_types` - Only include these filesystem types (default: include all)
- `exclude_types` - Skip these filesystem types (default: empty list)
- `include_sources` - Only include these source devices (default: include all)
- `exclude_sources` - Skip these source devices (default: empty list)
- `include_readonly` - Include read-only mounts (default: true)
- `include_readwrite` - Include read-write mounts (default: true)
- `include_pseudo` - Include virtual filesystems like proc, sysfs (default: false)
- `include_loop` - Include loop device mounts (default: true)
- `include_network` - Include network filesystems (default: true)
- `normalize_paths` - Clean up path formatting (default: true)
- `resolve_labels` - Look up filesystem labels and UUIDs (default: false)
- `resolve_fs_features` - Include detailed filesystem information (default: false)
- `timeout_ms` - How long to wait for mount information (default: 3000)

**Examples:**
```bash
# List all mounted filesystems
fs://system.list-mounts()
```

```bash
# List only real filesystems, excluding virtual ones
fs://system.list-mounts(exclude_types=["proc", "sysfs", "tmpfs", "devtmpfs"], include_pseudo=false)
```

```bash
# Detailed listing with labels and filesystem features
fs://system.list-mounts(resolve_labels=true, resolve_fs_features=true)
```

```bash
# Show only ext4 and xfs filesystems
fs://system.list-mounts(include_types=["ext4", "xfs"])
```

## Common Patterns

### Mounting a USB Drive
```bash
# Check what's available
fs://system.list-mounts(include_types=["ext4", "fat32", "exfat"])

# Mount the drive
fs://system.mount(target="/mnt/usb", source="/dev/sdb1", create_target=true)

# Check usage
fs://system.usage(paths=["/mnt/usb"])

# Safely unmount
fs://system.unmount(target="/mnt/usb")
```

### Managing Disk Space
```bash
# Check overall usage
fs://system.usage(exclude_types=["proc", "sysfs", "tmpfs"], human_readable=true)

# Find filesystems over 80% full
fs://system.usage(threshold_used_percent_min=80, exclude_types=["proc", "sysfs", "tmpfs"])

# Check specific user's quotas
fs://system.quota(subject="alice", all_subjects=false)
```

### Filesystem Maintenance
```bash
# Check filesystem health
fs://system.check(target="/dev/sdb1", mode="check")

# Create a configuration snapshot before changes
fs://system.snapshot(format="json", include_usage=true)

# Grow filesystem if needed
fs://system.resize(target="/data", delta="+10G", dry_run=true)
fs://system.resize(target="/data", delta="+10G")
```

## Error Codes

The filesystem handle returns specific error codes for different situations:

- **1**: Invalid configuration or arguments
- **2**: Target not found or profile missing  
- **3**: Operation not supported on this system
- **13**: Permission denied (need root privileges)
- **16**: Resource busy (filesystem in use)
- **17**: Conflicting operation (already mounted)
- **18**: Failed to create target directory
- **19**: Not mounted when expected to be
- **32**: Operation failed (general failure)
- **62**: Operation timed out
- **95**: Unknown verb or unsupported option

## Notes

- Many operations require root privileges, especially mounting and resizing
- Always use `dry_run=true` to test operations before running them
- Some filesystem operations require unmounting first
- Network filesystems may need additional configuration
- Quota operations only work on filesystems with quotas enabled
- Resize operations may require specific filesystem tools to be installed