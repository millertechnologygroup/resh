use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::time::Duration;
use thiserror::Error;
use tokio::time::timeout;
use url::Url;

#[path = "fsh_support.rs"]
mod support;
#[cfg(test)]
#[path = "fsh_tests.rs"]
mod verb_tests;
use support::{run, tool, tool_available, tool_message};

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::Status,
};

/// Sample output shared by `unmount` and its alias `umount`.
const FS_UNMOUNT_EXAMPLE_OUTPUT: &str = r#"{
  "action": "unmounted",
  "alias": "local",
  "backend": "fs",
  "by": "target",
  "detach_children": false,
  "errors": [],
  "force": false,
  "lazy": false,
  "skipped": [],
  "target": "/mnt/data",
  "unmounted": [
    {
      "options": [
        "rw",
        "relatime"
      ],
      "source": "/dev/loop0",
      "target": "/mnt/data",
      "type": "ext4"
    }
  ],
  "verb": "unmount"
}

Shown with --json-pretty. The verb field is "unmount" for both spellings.
A target that is not mounted gives action "already_unmounted" (an error
with fail_if_not_mounted=true). If any mount cannot be unmounted, the
result still lists what was unmounted, skipped and failed, and resh
exits 1. Defaults: by=target, force, lazy, detach_children and
fail_if_not_mounted false, timeout_ms=5000."#;

/// Sample output shared by `check` and its alias `fsck`.
const FS_CHECK_EXAMPLE_OUTPUT: &str = r#"{
  "action": "check",
  "alias": "local",
  "allow_repair": false,
  "analysis": {
    "errors_found": false,
    "filesystem_state": "clean",
    "needs_repair": false,
    "repaired": false
  },
  "backend": "fs",
  "by": "auto",
  "dry_run": null,
  "filesystem": {
    "fstype": "ext4",
    "mounted": false,
    "readonly": false,
    "source": "/srv/disk.img"
  },
  "mode": "check",
  "plan": null,
  "reason": null,
  "summary": {
    "skipped_reason": null,
    "status": "success"
  },
  "target": "/srv/disk.img",
  "tool": {
    "command": "fsck.ext4 -n /srv/disk.img",
    "exit_code": 0,
    "name": "fsck.ext4",
    "stderr": "e2fsck 1.47.0 (5-Feb-2023)\n",
    "stdout": "/srv/disk.img: clean, 11/65536 files, 12955/262144 blocks\n"
  },
  "verb": "check"
}

Shown for an unmounted ext4 image file with --json-pretty. The verb field
is "check" for both spellings. Supported types: ext2, ext3, ext4, vfat,
xfs, btrfs. mode=repair (needs allow_repair=true) runs fsck -p (-y with
aggressiveness=aggressive), fsck.vfat -a, xfs_repair or btrfs check
--repair on an unmounted filesystem; a mounted btrfs is scrubbed. Errors
found are reported in analysis with exit 0; a tool that fails to run its
check exits 1. Defaults: by=auto, mode=check, aggressiveness=safe,
allow_repair=false, allow_online_check=true,
require_unmounted_for_repair=true, btrfs_use_scrub=true,
timeout_ms=600000."#;

/// Metadata for `resh fs --help` and `resh fs <verb> --help`.
static FS_HELP: HandleHelp = HandleHelp {
    description: "The fs handle manages mounted filesystems on the local host, covering \
        mounting and unmounting, mount table listings and lockfile snapshots, disk usage, \
        quotas, resizing, and consistency checks. It reads /proc/mounts and statvfs data \
        and runs system tools such as mount, umount, quota, repquota, resize2fs, \
        xfs_growfs, btrfs, and fsck. The URL host is a free-form alias, such as fs://local, that is echoed back \
        in the JSON result.",
    usage: "resh fs://<alias>.<verb>[(key=value,...)]",
    verbs: &[
        VerbHelp {
            name: "list-mounts",
            definition: "Lists the mounted filesystems from the mount table with their \
                options and read-only, pseudo, network, and loop flags, as JSON.",
            detail: Some(VerbDetail {
                usage: "resh fs://<alias>.list-mounts [paths=<path,...>]\n  \
                    [include_readonly=true|false] [include_readwrite=true|false]\n  \
                    [include_pseudo=true|false] [include_loop=true|false]\n  \
                    [include_network=true|false] [normalize_paths=true|false]\n  \
                    [resolve_labels=true|false] [resolve_fs_features=true|false]\n  \
                    [include_mountpoints=<path,...>] [exclude_mountpoints=<path,...>]\n  \
                    [include_types=<type,...>] [exclude_types=<type,...>]\n  \
                    [include_sources=<source,...>] [exclude_sources=<source,...>]\n  \
                    [timeout_ms=<ms>]",
                example: "resh --json-pretty fs://local.list-mounts",
                example_output: Some(
                    r#"{
  "alias": "local",
  "backend": "fs",
  "filters": {
    "exclude_mountpoints": [],
    "exclude_sources": [],
    "exclude_types": [],
    "include_loop": true,
    "include_mountpoints": [],
    "include_network": true,
    "include_pseudo": false,
    "include_readonly": true,
    "include_readwrite": true,
    "include_sources": [],
    "include_types": [],
    "paths": []
  },
  "mounts": [
    {
      "fstype": "ext4",
      "loop": false,
      "network": false,
      "options": [
        "noatime",
        "rw"
      ],
      "pseudo": false,
      "read_only": false,
      "source": "/dev/sda2",
      "target": "/"
    }
  ],
  "verb": "list-mounts"
}

Shown with --json-pretty and one mount. List options take
comma-separated values, for example include_types=ext4,xfs. Mount point
filters match whole path components (/home matches /home/a, not
/homex). Defaults: include_pseudo=false, resolve_labels and
resolve_fs_features false, the other switches true, timeout_ms=3000."#,
                ),
            }),
        },
        VerbHelp {
            name: "usage",
            definition: "Reports size, used, and free space and inode counts for each \
                mounted filesystem, or an aggregate total, as JSON.",
            detail: Some(VerbDetail {
                usage: "resh fs://<alias>.usage [mode=mounts|paths|aggregate] [paths=<path,...>]\n  \
                    [units=auto|bytes|kilobytes|megabytes|gigabytes|blocks]\n  \
                    [human_readable=true|false] [include_inodes=true|false]\n  \
                    [include_readonly=true|false] [normalize_paths=true|false]\n  \
                    [threshold_used_percent_min=<0-100>]\n  \
                    [threshold_used_percent_max=<0-100>]\n  \
                    [include_mountpoints=<path,...>] [exclude_mountpoints=<path,...>]\n  \
                    [include_types=<type,...>] [exclude_types=<type,...>]\n  \
                    [include_sources=<source,...>] [exclude_sources=<source,...>]\n  \
                    [timeout_ms=<ms>]",
                example: "resh --json-pretty fs://local.usage units=megabytes",
                example_output: Some(
                    r#"{
  "alias": "local",
  "backend": "fs",
  "filesystems": [
    {
      "free": 61440,
      "fstype": "ext4",
      "inodes": {
        "free": 5120000,
        "total": 6553600,
        "used": 1433600,
        "used_percent": 21.875
      },
      "read_only": false,
      "size": 102400,
      "source": "/dev/sda2",
      "target": "/",
      "used": 40960,
      "used_percent": 40.0
    }
  ],
  "filters": {
    "exclude_mountpoints": [],
    "exclude_sources": [],
    "exclude_types": [],
    "include_mountpoints": [],
    "include_sources": [],
    "include_types": []
  },
  "include_inodes": true,
  "mode": "mounts",
  "units": "megabytes",
  "verb": "usage"
}

Shown with --json-pretty and one filesystem. With mode=aggregate the
result also has an aggregate object with the summed size, used, free,
used_percent, and inodes. paths is used only with mode=paths, which adds
a path_to_filesystem list. Mounts whose usage cannot be read are skipped
and listed in a warnings array. Filters that select nothing are an
error; thresholds may leave an empty list. Defaults: mode=mounts,
units=auto (bytes), include_inodes=true, include_readonly=true,
timeout_ms=5000."#,
                ),
            }),
        },
        VerbHelp {
            name: "snapshot",
            definition: "Captures the current mount table, with usage and filesystem \
                metadata, as a deterministic fs-lock/v1 lockfile string.",
            detail: Some(VerbDetail {
                usage: "resh fs://<alias>.snapshot [format=json|yaml|text]\n  \
                    [include_usage=true|false] [include_inodes=true|false]\n  \
                    [include_fs_metadata=true|false] [include_os_metadata=true|false]\n  \
                    [normalize_paths=true|false]\n  \
                    [include_mountpoints=<path,...>] [exclude_mountpoints=<path,...>]\n  \
                    [include_types=<type,...>] [exclude_types=<type,...>]\n  \
                    [include_sources=<source,...>] [exclude_sources=<source,...>]\n  \
                    [timeout_ms=<ms>]",
                example: "resh --json-pretty fs://local.snapshot format=json",
                example_output: Some(
                    r#"{
  "action": "snapshot",
  "alias": "local",
  "backend": "fs",
  "format": "json",
  "lockfile": "{\n  \"lockfile_version\": \"fs-lock/v1\",\n  ...\n}",
  "parsed": {
    "filters_applied": false,
    "host": {
      "architecture": "x86_64",
      "hostname": "web01",
      "kernel": "6.8.0-45-generic",
      "os_family": "Linux",
      "os_name": "Ubuntu",
      "os_version": "24.04"
    },
    "lockfile_version": "fs-lock/v1",
    "mount_count": 25
  }
}

Shown with --json-pretty; the lockfile string is abbreviated. It holds
the generated_at time, alias, host, filters, and one entry per mount, as
JSON, YAML or text. Nothing is written to disk. Defaults: format=json,
include_usage, include_fs_metadata and include_os_metadata true,
include_inodes=false, timeout_ms=5000."#,
                ),
            }),
        },
        VerbHelp {
            name: "quota",
            definition: "Reports the disk space and inode quota usage and limits of one \
                user, group, or project, or of every subject, on the filesystem holding a \
                path, using quota or repquota.",
            detail: Some(VerbDetail {
                usage: "resh fs://<alias>.quota [path=<path>] [subject=<name-or-id>]\n  \
                    [subject_type=auto|user|group|project] [all_subjects=true|false]\n  \
                    [units=auto|blocks|bytes] [include_space=true|false]\n  \
                    [include_inodes=true|false] [include_grace=true|false]\n  \
                    [resolve_uid_gid=true|false] [timeout_ms=<ms>]",
                example: "resh --json-pretty fs://local.quota path=/home subject=alice",
                example_output: Some(
                    r#"{
  "alias": "local",
  "backend": "fs",
  "filesystem": {
    "fstype": "ext4",
    "source": "/dev/sda3",
    "target": "/home"
  },
  "inode_quota_enabled": true,
  "path": "/home",
  "space_quota_enabled": true,
  "subject_query": {
    "resolved_gid": 1000,
    "resolved_uid": 1000,
    "subject": "alice",
    "subject_type": "user"
  },
  "subjects": [
    {
      "gid": 1000,
      "inodes": {
        "grace_exceeded": false,
        "grace_time_remaining_sec": null,
        "hard_limit": 120000,
        "soft_limit": 100000,
        "used": 4210,
        "used_percent_of_soft": 4.21
      },
      "space": {
        "grace_exceeded": false,
        "grace_time_remaining_sec": null,
        "hard_limit": 12582912,
        "soft_limit": 10485760,
        "used": 2097152,
        "used_percent_of_soft": 20.0
      },
      "subject": "alice",
      "subject_type": "user",
      "uid": 1000
    }
  ],
  "units": "auto",
  "verb": "quota"
}

Shown with --json-pretty. Without path the root filesystem is queried,
and without subject the current user is queried. all_subjects=true
lists every subject on the filesystem (repquota, needs root). Sizes are
bytes, or 1 KiB blocks with units=blocks. Defaults: subject_type=auto,
units=auto, the include switches and resolve_uid_gid true,
timeout_ms=5000."#,
                ),
            }),
        },
        VerbHelp {
            name: "quota_summary",
            definition: "Aggregates the quota usage and limits of one user, group, or \
                project, or of every subject, across the mounted filesystems, listing \
                filesystems without quotas separately.",
            detail: Some(VerbDetail {
                usage: "resh fs://<alias>.quota_summary [subject=<name-or-id>]\n  \
                    [subject_type=auto|user|group|project] [all_subjects=true|false]\n  \
                    [units=auto|blocks|bytes] [include_space=true|false]\n  \
                    [include_inodes=true|false] [include_grace=true|false]\n  \
                    [resolve_uid_gid=true|false]\n  \
                    [include_mountpoints=<path,...>] [exclude_mountpoints=<path,...>]\n  \
                    [include_types=<type,...>] [exclude_types=<type,...>]\n  \
                    [include_sources=<source,...>] [exclude_sources=<source,...>]\n  \
                    [timeout_ms=<ms>]",
                example: "resh --json-pretty fs://local.quota_summary subject=alice",
                example_output: Some(
                    r#"{
  "alias": "local",
  "all_subjects": false,
  "backend": "fs",
  "filesystems": [
    {
      "fstype": "ext4",
      "inode_quota_enabled": true,
      "inodes": {
        "grace_exceeded": false,
        "grace_time_remaining_sec": null,
        "hard_limit": 120000,
        "soft_limit": 100000,
        "used": 4210,
        "used_percent_of_soft": 4.21
      },
      "source": "/dev/sda3",
      "space": {
        "grace_exceeded": false,
        "grace_time_remaining_sec": null,
        "hard_limit": 12582912,
        "soft_limit": 10485760,
        "used": 2097152,
        "used_percent_of_soft": 20.0
      },
      "space_quota_enabled": true,
      "target": "/home"
    }
  ],
  "filesystems_without_quotas": [
    {
      "fstype": "vfat",
      "source": "/dev/sda1",
      "target": "/boot/efi"
    }
  ],
  "filters": {
    "exclude_mountpoints": [],
    "exclude_sources": [],
    "exclude_types": [],
    "include_mountpoints": [],
    "include_sources": [],
    "include_types": []
  },
  "include_inodes": true,
  "include_space": true,
  "partial_failures": [],
  "subject_query": {
    "resolved_gid": 1000,
    "resolved_uid": 1000,
    "subject": "alice",
    "subject_type": "user"
  },
  "summary": {
    "inodes": {
      "any_grace_exceeded": false,
      "hard_limit": 120000,
      "soft_limit": 100000,
      "used": 4210,
      "used_percent_of_soft": 4.21
    },
    "space": {
      "any_grace_exceeded": false,
      "hard_limit": 12582912,
      "soft_limit": 10485760,
      "used": 2097152,
      "used_percent_of_soft": 20.0
    }
  },
  "units": "auto",
  "verb": "quota_summary"
}

Shown with --json-pretty, trimmed to one filesystem in each list.
Pseudo filesystems are not considered. With all_subjects=true the result
has a subjects list with one total per subject instead of summary.
Defaults as for quota, timeout_ms=8000."#,
                ),
            }),
        },
        VerbHelp {
            name: "mount",
            definition: "Mounts a device, network share, or bind source on a target \
                directory, creating the directory if needed, and reports the result as JSON.",
            detail: Some(VerbDetail {
                usage: "resh fs://<alias>.mount target=<dir> [source=<device-or-path>]\n  \
                    [type=<fstype>] [options=<opt,opt,...>] [read_only=true|false]\n  \
                    [bind=true|false] [remount=true|false] [network=true|false]\n  \
                    [create_target=true|false] [make_parents=true|false]\n  \
                    [fail_if_mounted=true|false] [dry_run=true|false] [timeout_ms=<ms>]",
                example: "resh --json-pretty fs://local.mount target=/mnt/data source=/srv/disk.img",
                example_output: Some(
                    r#"{
  "action": "mounted",
  "alias": "local",
  "backend": "fs",
  "bind": false,
  "created_target": true,
  "details": {
    "device": "/srv/disk.img",
    "from_existing": false,
    "fs_type": null,
    "mount_flags": []
  },
  "dry_run": null,
  "options": [],
  "plan": null,
  "read_only": false,
  "remount": false,
  "source": "/srv/disk.img",
  "target": "/mnt/data",
  "type": null,
  "verb": "mount"
}

Shown with --json-pretty; an image file is attached to a loop device by
mount(8). An existing compatible mount returns action "already_mounted";
dry_run=true returns action "planned" with a plan. A relative target is
resolved from the current directory. Defaults: create_target=true,
make_parents=true, other switches false, timeout_ms=5000."#,
                ),
            }),
        },
        VerbHelp {
            name: "unmount",
            definition: "Unmounts the filesystems matching a mount point or source device, \
                optionally with their child mounts, and reports the result as JSON.",
            detail: Some(VerbDetail {
                usage: "resh fs://<alias>.unmount target=<dir-or-device>\n  \
                    [by=target|source|auto] [force=true|false] [lazy=true|false]\n  \
                    [detach_children=true|false] [fail_if_not_mounted=true|false]\n  \
                    [dry_run=true|false] [timeout_ms=<ms>]",
                example: "resh --json-pretty fs://local.unmount target=/mnt/data",
                example_output: Some(FS_UNMOUNT_EXAMPLE_OUTPUT),
            }),
        },
        VerbHelp {
            name: "umount",
            definition: "Alias for unmount.",
            detail: Some(VerbDetail {
                usage: "resh fs://<alias>.umount target=<dir-or-device>\n  \
                    [by=target|source|auto] [force=true|false] [lazy=true|false]\n  \
                    [detach_children=true|false] [fail_if_not_mounted=true|false]\n  \
                    [dry_run=true|false] [timeout_ms=<ms>]",
                example: "resh --json-pretty fs://local.umount target=/mnt/data",
                example_output: Some(FS_UNMOUNT_EXAMPLE_OUTPUT),
            }),
        },
        VerbHelp {
            name: "resize",
            definition: "Grows or shrinks a filesystem, located by mount point or device, to an \
                absolute size or by a delta using resize2fs, xfs_growfs, or btrfs.",
            detail: Some(VerbDetail {
                usage: "resh fs://<alias>.resize target=<dir-or-device>\n  \
                    size=<size> | delta=<+size|-size> [by=auto|mountpoint|device]\n  \
                    [size_units=auto|bytes|kilobytes|megabytes|gigabytes|terabytes]\n  \
                    [mode=grow|shrink|auto] [allow_shrink=true|false]\n  \
                    [min_free_space_percent=<0-100>]\n  \
                    [manage_underlying_volume=true|false]\n  \
                    [volume_resize_only=true|false] [filesystem_resize_only=true|false]\n  \
                    [require_unmounted_for_shrink=true|false] [force=true|false]\n  \
                    [dry_run=true|false] [timeout_ms=<ms>]",
                example: "resh --json-pretty fs://local.resize target=/mnt/data size=2G",
                example_output: Some(
                    r#"{
  "action": "success",
  "actions": [
    {
      "command": "resize2fs /dev/loop0 2097152K",
      "status": "success",
      "tool": "resize2fs",
      "type": "filesystem_resize"
    }
  ],
  "alias": "local",
  "backend": "fs",
  "by": "auto",
  "delta_bytes": 1073741824,
  "dry_run": false,
  "filesystem": {
    "current_size_bytes": 1073741824,
    "delta_bytes": 1073741824,
    "fstype": "ext4",
    "mounted": true,
    "requested_size_bytes": 2147483648,
    "source": "/dev/loop0"
  },
  "final_size_bytes": 2147483648,
  "mode": "grow",
  "plan": null,
  "previous_size_bytes": 1073741824,
  "reason": null,
  "requested_size_bytes": 2147483648,
  "summary": {
    "grew": true,
    "shrink": false,
    "status": "success"
  },
  "target": "/mnt/data",
  "verb": "resize"
}

Shown for an ext4 filesystem with --json-pretty. Sizes accept K, M, G
and T suffixes (powers of 1024); a bare number counts size_units. A size
equal to the current size returns action "noop". Shrinking needs
mode=shrink or auto and allow_shrink=true, is refused for xfs, and needs
an unmounted ext3/ext4 filesystem; xfs and btrfs are resized while
mounted. force=true passes -f to resize2fs. Defaults: by=auto,
mode=grow, size_units=auto (bytes), min_free_space_percent=5,
require_unmounted_for_shrink=true, timeout_ms=600000."#,
                ),
            }),
        },
        VerbHelp {
            name: "check",
            definition: "Checks a filesystem for errors with fsck, xfs_repair, or btrfs, \
                read-only unless repair is allowed, and reports the tool output and \
                analysis as JSON.",
            detail: Some(VerbDetail {
                usage: "resh fs://<alias>.check target=<dir-or-device>\n  \
                    [by=auto|mountpoint|device] [filesystem_type=<fstype>]\n  \
                    [mode=check|repair|auto] [allow_repair=true|false]\n  \
                    [aggressiveness=safe|normal|aggressive] [force=true|false]\n  \
                    [allow_online_check=true|false]\n  \
                    [require_unmounted_for_repair=true|false]\n  \
                    [skip_if_mounted=true|false] [btrfs_use_scrub=true|false]\n  \
                    [btrfs_allow_offline_check=true|false] [dry_run=true|false]\n  \
                    [timeout_ms=<ms>]",
                example: "resh --json-pretty fs://local.check target=/srv/disk.img",
                example_output: Some(FS_CHECK_EXAMPLE_OUTPUT),
            }),
        },
        VerbHelp {
            name: "fsck",
            definition: "Alias for check.",
            detail: Some(VerbDetail {
                usage: "resh fs://<alias>.fsck target=<dir-or-device>\n  \
                    [by=auto|mountpoint|device] [filesystem_type=<fstype>]\n  \
                    [mode=check|repair|auto] [allow_repair=true|false]\n  \
                    [aggressiveness=safe|normal|aggressive] [force=true|false]\n  \
                    [allow_online_check=true|false]\n  \
                    [require_unmounted_for_repair=true|false]\n  \
                    [skip_if_mounted=true|false] [btrfs_use_scrub=true|false]\n  \
                    [btrfs_allow_offline_check=true|false] [dry_run=true|false]\n  \
                    [timeout_ms=<ms>]",
                example: "resh --json-pretty fs://local.fsck target=/srv/disk.img",
                example_output: Some(FS_CHECK_EXAMPLE_OUTPUT),
            }),
        },
    ],
};

/// Filesystem handle for mounting operations
#[derive(Debug)]
pub struct FsHandle {
    alias: String,
}

/// Mount configuration structure
#[derive(Debug, Clone, Deserialize)]
pub struct MountConfig {
    pub source: Option<String>,
    pub target: String,
    pub r#type: Option<String>,
    pub options: Vec<String>,
    pub read_only: bool,
    pub bind: bool,
    pub create_target: bool,
    pub make_parents: bool,
    pub fail_if_mounted: bool,
    pub remount: bool,
    pub network: bool,
    pub timeout_ms: u64,
    pub dry_run: bool,
}

/// Information about an existing mount
#[derive(Debug, Clone)]
pub struct ExistingMount {
    pub source: String,
    pub target: String,
    pub fs_type: String,
    pub options: Vec<String>,
}

/// Mount operation result
#[derive(Debug, Serialize)]
pub struct MountResult {
    pub backend: String,
    pub verb: String,
    pub alias: String,
    pub source: Option<String>,
    pub target: String,
    pub r#type: Option<String>,
    pub options: Vec<String>,
    pub read_only: bool,
    pub bind: bool,
    pub remount: bool,
    pub action: String, // "mounted" | "remounted" | "already_mounted"
    pub created_target: bool,
    pub details: MountDetails,
    pub dry_run: Option<bool>,
    pub plan: Option<MountPlan>,
}

/// Details about the mount operation
#[derive(Debug, Serialize)]
pub struct MountDetails {
    pub device: Option<String>,
    pub fs_type: Option<String>,
    pub mount_flags: Vec<String>,
    pub from_existing: bool,
}

/// Plan for dry-run operations
#[derive(Debug, Serialize)]
pub struct MountPlan {
    pub create_directory: Vec<String>,
    pub mount_commands: Vec<String>,
}

/// Unmount configuration structure
#[derive(Debug, Clone, Deserialize)]
pub struct UnmountConfig {
    pub target: String,
    pub by: UnmountTargetKind,
    pub force: bool,
    pub lazy: bool,
    pub detach_children: bool,
    pub fail_if_not_mounted: bool,
    pub timeout_ms: u64,
    pub dry_run: bool,
}

/// How to interpret the target field
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UnmountTargetKind {
    Target,
    Source,
    Auto,
}

/// Unmount operation result
#[derive(Debug, Serialize)]
pub struct UnmountResult {
    pub backend: String,
    pub verb: String,
    pub alias: String,
    pub target: String,
    pub by: String,
    pub force: bool,
    pub lazy: bool,
    pub detach_children: bool,
    pub action: String, // "unmounted" | "already_unmounted" | "partially_unmounted"
    pub unmounted: Vec<MountInfo>,
    pub skipped: Vec<MountInfo>,
    pub errors: Vec<UnmountError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<UnmountPlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_mounts: Option<Vec<MountInfo>>,
}

/// Information about a mount
#[derive(Debug, Clone, Serialize)]
pub struct MountInfo {
    pub source: String,
    pub target: String,
    #[serde(rename = "type")]
    pub fs_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
}

/// Unmount error information
#[derive(Debug, Serialize)]
pub struct UnmountError {
    pub target: String,
    pub code: String,
    pub message: String,
}

/// Plan for dry-run unmount operations
#[derive(Debug, Serialize)]
pub struct UnmountPlan {
    pub order: Vec<String>,
    pub commands: Vec<String>,
}

/// Filesystem-specific errors
#[derive(Error, Debug)]
pub enum FsError {
    #[error("Invalid mount configuration: {0}")]
    InvalidMountConfig(String),
    #[error("Invalid unmount configuration: {0}")]
    InvalidUnmountConfig(String),
    #[error("Profile not found: {0}")]
    ProfileNotFound(String),
    #[error("Mount operations are not supported here: the mount tool was not found")]
    MountUnsupported,
    #[error("Unmount operations are not supported here: the umount tool was not found")]
    UnmountUnsupported,
    #[error("Permission denied for mount operation")]
    MountPermissionDenied,
    #[error("Permission denied for unmount operation")]
    UnmountPermissionDenied,
    #[error("Target already mounted: {0}")]
    AlreadyMounted(String),
    #[error("Conflicting mount at target: {0}")]
    ConflictingMount(String),
    #[error("Mount operation failed: {0}")]
    MountFailure(String),
    #[error("Unmount operation failed: {0}")]
    UnmountFailure(String),
    #[error("Mount operation timed out")]
    MountTimeout,
    #[error("Unmount operation timed out")]
    UnmountTimeout,
    #[error("Failed to create target directory: {0}")]
    TargetCreationFailed(String),
    #[error("Target is not mounted: {0}")]
    NotMounted(String),
    #[error("Target is busy and cannot be unmounted: {0}")]
    UnmountBusy(String),
    #[error("Unmount option not supported on this platform: {0}")]
    UnmountOptionUnsupported(String),
    #[error("Invalid snapshot configuration: {0}")]
    InvalidSnapshotConfig(String),
    #[error("Snapshot operations are not supported on this platform")]
    SnapshotUnsupported,
    #[error("Snapshot operation timed out")]
    SnapshotTimeout,
    #[error("Snapshot operation failed: {0}")]
    SnapshotFailed(String),
    #[error("Invalid quota configuration: {0}")]
    InvalidQuotaConfig(String),
    #[error(
        "Quota operations are not supported here: the quota tools (quota, repquota) or the mount table were not found"
    )]
    QuotaUnsupported,
    #[error("Quotas are not enabled on the target filesystem: {0}")]
    QuotaNotEnabled(String),
    #[error("Quota subject not found: {0}")]
    QuotaSubjectNotFound(String),
    #[error("Quota operation timed out")]
    QuotaTimeout,
    #[error("Quota operation failed: {0}")]
    QuotaFailed(String),
    #[error("Invalid quota summary configuration: {0}")]
    InvalidQuotaSummaryConfig(String),
    #[error(
        "Quota summary operations are not supported here: the quota tools (quota, repquota) or the mount table were not found"
    )]
    QuotaSummaryUnsupported,
    #[error("No filesystems with quotas enabled found: {0}")]
    QuotaSummaryNoQuotaFilesystems(String),
    #[error("Quota summary operation timed out")]
    QuotaSummaryTimeout,
    #[error("Quota summary operation failed: {0}")]
    QuotaSummaryFailed(String),
    #[error("Invalid usage configuration: {0}")]
    InvalidUsageConfig(String),
    #[error("Usage operations are not supported on this platform")]
    UsageUnsupported,
    #[error("Usage operation timed out")]
    UsageTimeout,
    #[error("Usage operation failed: {0}")]
    UsageFailed(String),
    #[error("Path not found: {0}")]
    PathNotFound(String),
    #[error("No filesystems selected after applying filters")]
    UsageNothingSelected,
    #[error("Invalid resize configuration: {0}")]
    InvalidResizeConfig(String),
    #[error("Resize target not found: {0}")]
    ResizeTargetNotFound(String),
    #[error("Resize operations are not supported for filesystem type: {0}")]
    ResizeUnsupportedFilesystem(String),
    #[error("Shrink operations are not allowed (allow_shrink=false)")]
    ResizeShrinkNotAllowed,
    #[error("Shrink operations are not supported for filesystem type: {0}")]
    ResizeShrinkNotSupportedForFilesystem(String),
    #[error("Shrink operations require the filesystem to be unmounted: {0}")]
    ResizeShrinkRequiresUnmount(String),
    #[error("Resize would violate minimum free space requirement")]
    ResizeWouldViolateMinFree,
    #[error("Target size exceeds device capacity")]
    ResizeTargetExceedsDevice,
    #[error("Invalid target size specified: {0}")]
    ResizeInvalidTargetSize(String),
    #[error("Volume management operations are not supported")]
    ResizeVolumeManagementUnsupported,
    #[error("Resize operation timed out")]
    ResizeTimeout,
    #[error("Resize operation failed: {0}")]
    ResizeFailed(String),
    #[error("Invalid check configuration: {0}")]
    InvalidCheckConfig(String),
    #[error("Check target not found: {0}")]
    CheckTargetNotFound(String),
    #[error("Check operations are not supported for filesystem type: {0}")]
    CheckUnsupportedFilesystem(String),
    #[error("Repair requested but allow_repair=false")]
    CheckRepairNotAllowed,
    #[error("Repair requires filesystem to be unmounted: {0}")]
    CheckRequiresUnmountForRepair(String),
    #[error("Check operations must be performed offline but filesystem is mounted: {0}")]
    CheckMustBeOffline(String),
    #[error("Check tool not available: {0}")]
    CheckToolNotAvailable(String),
    #[error("Check operation timed out")]
    CheckTimeout,
    #[error("Check operation failed: {0}")]
    CheckFailed(String),
    #[error("Invalid list-mounts configuration: {0}")]
    InvalidListMountsConfig(String),
    #[error("List-mounts operations are not supported on this platform")]
    ListMountsUnsupported,
    #[error("List-mounts operation timed out")]
    ListMountsTimeout,
    #[error("List-mounts operation failed: {0}")]
    ListMountsFailed(String),
    /// Some of the work was done and some was not. `output` is the result
    /// object describing both; it is printed before the failure is reported.
    #[error("{message}")]
    Incomplete {
        output: Value,
        code: i32,
        message: String,
    },
}

impl Default for FsQuotaConfig {
    fn default() -> Self {
        Self {
            path: None,
            subject: None,
            subject_type: SubjectType::Auto,
            resolve_uid_gid: true,
            include_space: true,
            include_inodes: true,
            include_grace: true,
            all_subjects: false,
            units: QuotaUnits::Auto,
            timeout_ms: 5000,
        }
    }
}

impl Default for FsQuotaSummaryConfig {
    fn default() -> Self {
        Self {
            subject: None,
            subject_type: SubjectType::Auto,
            resolve_uid_gid: true,
            include_mountpoints: Vec::new(),
            exclude_mountpoints: Vec::new(),
            include_types: Vec::new(),
            exclude_types: Vec::new(),
            include_sources: Vec::new(),
            exclude_sources: Vec::new(),
            include_space: true,
            include_inodes: true,
            include_grace: true,
            all_subjects: false,
            units: QuotaUnits::Auto,
            timeout_ms: 8000,
        }
    }
}

impl Default for FsUsageConfig {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            mode: UsageMode::Mounts,
            include_mountpoints: Vec::new(),
            exclude_mountpoints: Vec::new(),
            include_types: Vec::new(),
            exclude_types: Vec::new(),
            include_sources: Vec::new(),
            exclude_sources: Vec::new(),
            include_inodes: true,
            include_readonly: true,
            normalize_paths: true,
            units: UsageUnits::Auto,
            human_readable: false,
            threshold_used_percent_min: None,
            threshold_used_percent_max: None,
            timeout_ms: 5000,
        }
    }
}

impl Default for FsResizeConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            by: ResizeTargetKind::Auto,
            size: None,
            delta: None,
            size_units: SizeUnits::Auto,
            mode: ResizeMode::Grow,
            allow_shrink: false,
            min_free_space_percent: 5.0,
            manage_underlying_volume: false,
            volume_resize_only: false,
            filesystem_resize_only: false,
            require_unmounted_for_shrink: true,
            force: false,
            dry_run: false,
            timeout_ms: 600000, // 10 minutes
        }
    }
}

/// Check configuration structure
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FsCheckConfig {
    pub target: String,
    pub by: CheckTargetKind,
    pub filesystem_type: Option<String>,
    pub mode: CheckMode,
    pub aggressiveness: CheckAggressiveness,
    pub allow_repair: bool,
    pub allow_online_check: bool,
    pub require_unmounted_for_repair: bool,
    pub skip_if_mounted: bool,
    pub force: bool,
    pub btrfs_use_scrub: bool,
    pub btrfs_allow_offline_check: bool,
    pub dry_run: bool,
    pub timeout_ms: u64,
}

/// How to interpret the target field for check operations
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CheckTargetKind {
    Auto,
    Mountpoint,
    Device,
}

/// Check operation mode
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CheckMode {
    Check,
    Repair,
    Auto,
}

/// Check operation aggressiveness
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CheckAggressiveness {
    Safe,
    Normal,
    Aggressive,
}

/// Filesystem information for check operations
#[derive(Debug, Clone, Serialize)]
pub struct CheckFilesystemInfo {
    pub source: String,
    pub fstype: String,
    pub mounted: bool,
    pub readonly: bool,
}

/// Tool execution information
#[derive(Debug, Clone, Serialize)]
pub struct CheckTool {
    pub name: String,
    pub command: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Analysis of check results
#[derive(Debug, Clone, Serialize)]
pub struct CheckAnalysis {
    pub errors_found: bool,
    pub repaired: bool,
    pub needs_repair: bool,
    pub filesystem_state: String, // "clean" | "checked_with_warnings" | "errors_detected" | "repaired"
}

/// Summary of check operation
#[derive(Debug, Clone, Serialize)]
pub struct CheckSummary {
    pub status: String, // "success" | "skipped" | "failure"
    pub skipped_reason: Option<String>,
}

/// Plan for dry-run check operations
#[derive(Debug, Clone, Serialize)]
pub struct CheckPlan {
    pub tool: String,
    pub arguments: Vec<String>,
    pub requires_unmount_for_repair: bool,
    pub would_run: bool,
}

/// Check operation result
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub backend: String,
    pub verb: String,
    pub alias: Option<String>,
    pub target: String,
    pub by: String,
    pub filesystem: Option<CheckFilesystemInfo>,
    pub mode: String,
    pub allow_repair: bool,
    pub tool: Option<CheckTool>,
    pub analysis: Option<CheckAnalysis>,
    pub summary: CheckSummary,
    pub action: Option<String>,
    pub reason: Option<String>,
    pub dry_run: Option<bool>,
    pub plan: Option<CheckPlan>,
}

impl Default for FsCheckConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            by: CheckTargetKind::Auto,
            filesystem_type: None,
            mode: CheckMode::Check,
            aggressiveness: CheckAggressiveness::Safe,
            allow_repair: false,
            allow_online_check: true,
            require_unmounted_for_repair: true,
            skip_if_mounted: false,
            force: false,
            btrfs_use_scrub: true,
            btrfs_allow_offline_check: false,
            dry_run: false,
            timeout_ms: 600000, // 10 minutes
        }
    }
}

impl Default for MountConfig {
    fn default() -> Self {
        Self {
            source: None,
            target: String::new(),
            r#type: None,
            options: Vec::new(),
            read_only: false,
            bind: false,
            create_target: true,
            make_parents: true,
            fail_if_mounted: false,
            remount: false,
            network: false,
            timeout_ms: 5000,
            dry_run: false,
        }
    }
}

impl Default for UnmountConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            by: UnmountTargetKind::Target,
            force: false,
            lazy: false,
            detach_children: false,
            fail_if_not_mounted: false,
            timeout_ms: 5000,
            dry_run: false,
        }
    }
}

/// Snapshot configuration structure
#[derive(Debug, Clone, Deserialize)]
pub struct SnapshotConfig {
    #[serde(default)]
    pub include_mountpoints: Vec<String>,
    #[serde(default)]
    pub exclude_mountpoints: Vec<String>,
    #[serde(default)]
    pub include_types: Vec<String>,
    #[serde(default)]
    pub exclude_types: Vec<String>,
    #[serde(default)]
    pub include_sources: Vec<String>,
    #[serde(default)]
    pub exclude_sources: Vec<String>,
    #[serde(default = "default_true")]
    pub include_usage: bool,
    #[serde(default)]
    pub include_inodes: bool,
    #[serde(default = "default_true")]
    pub include_fs_metadata: bool,
    #[serde(default = "default_true")]
    pub include_os_metadata: bool,
    #[serde(default = "default_true")]
    pub normalize_paths: bool,
    #[serde(default = "default_json_format")]
    pub format: SnapshotFormat,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

/// Snapshot format enum
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotFormat {
    Json,
    Yaml,
    Text,
}

/// Snapshot lockfile schema
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotLockfile {
    pub lockfile_version: String,
    pub generated_at: DateTime<Utc>,
    pub alias: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<HostInfo>,
    pub filters: FilterInfo,
    pub mounts: Vec<MountEntry>,
}

/// Host information
#[derive(Debug, Clone, Serialize)]
pub struct HostInfo {
    pub hostname: String,
    pub os_family: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel: String,
    pub architecture: String,
}

/// Filter information
#[derive(Debug, Clone, Serialize)]
pub struct FilterInfo {
    pub include_mountpoints: Vec<String>,
    pub exclude_mountpoints: Vec<String>,
    pub include_types: Vec<String>,
    pub exclude_types: Vec<String>,
    pub include_sources: Vec<String>,
    pub exclude_sources: Vec<String>,
}

/// Mount entry in the lockfile
#[derive(Debug, Clone, Serialize)]
pub struct MountEntry {
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub options: Vec<String>,
    pub dump: i32,
    pub pass: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<UsageInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inodes: Option<InodeInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs_metadata: Option<FsMetadata>,
}

/// Usage information
#[derive(Debug, Clone, Serialize)]
pub struct UsageInfo {
    pub size_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub used_percent: f64,
}

/// Inode information
#[derive(Debug, Clone, Serialize)]
pub struct InodeInfo {
    pub total: u64,
    pub used: u64,
    pub free: u64,
    pub used_percent: f64,
}

/// Filesystem metadata
#[derive(Debug, Clone, Serialize)]
pub struct FsMetadata {
    pub block_size: u64,
    pub blocks: u64,
    pub flags: Vec<String>,
    pub device: String,
}

/// Snapshot result
#[derive(Debug, Serialize)]
pub struct SnapshotResult {
    pub backend: String,
    pub action: String,
    pub alias: String,
    pub format: String,
    pub lockfile: String,
    pub parsed: SnapshotSummary,
}

/// Snapshot summary
#[derive(Debug, Serialize)]
pub struct SnapshotSummary {
    pub lockfile_version: String,
    pub mount_count: usize,
    pub filters_applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<HostInfo>,
}

/// Raw mount information from system
#[derive(Debug, Clone)]
pub struct RawMountInfo {
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub options: String,
    pub dump: i32,
    pub pass: i32,
}

// Helper functions for default values
fn default_true() -> bool {
    true
}
fn default_json_format() -> SnapshotFormat {
    SnapshotFormat::Json
}
fn default_timeout() -> u64 {
    5000
}

/// Subject type for quota queries
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SubjectType {
    Auto,
    User,
    Group,
    Project,
}

/// Units for quota reporting
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum QuotaUnits {
    Auto,
    Blocks,
    Bytes,
}

/// Quota configuration structure
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FsQuotaConfig {
    pub path: Option<String>,
    pub subject: Option<String>,
    pub subject_type: SubjectType,
    pub resolve_uid_gid: bool,
    pub include_space: bool,
    pub include_inodes: bool,
    pub include_grace: bool,
    pub all_subjects: bool,
    pub units: QuotaUnits,
    pub timeout_ms: u64,
}

/// Quota summary configuration structure
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FsQuotaSummaryConfig {
    pub subject: Option<String>,
    pub subject_type: SubjectType,
    pub resolve_uid_gid: bool,
    pub include_mountpoints: Vec<String>,
    pub exclude_mountpoints: Vec<String>,
    pub include_types: Vec<String>,
    pub exclude_types: Vec<String>,
    pub include_sources: Vec<String>,
    pub exclude_sources: Vec<String>,
    pub include_space: bool,
    pub include_inodes: bool,
    pub include_grace: bool,
    pub all_subjects: bool,
    pub units: QuotaUnits,
    pub timeout_ms: u64,
}

/// Usage mode enum
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UsageMode {
    Mounts,
    Paths,
    Aggregate,
}

/// Usage units enum
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UsageUnits {
    Auto,
    Bytes,
    Kilobytes,
    Megabytes,
    Gigabytes,
    Blocks,
}

/// Filesystem usage configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FsUsageConfig {
    pub paths: Vec<String>,
    pub mode: UsageMode,
    pub include_mountpoints: Vec<String>,
    pub exclude_mountpoints: Vec<String>,
    pub include_types: Vec<String>,
    pub exclude_types: Vec<String>,
    pub include_sources: Vec<String>,
    pub exclude_sources: Vec<String>,
    pub include_inodes: bool,
    pub include_readonly: bool,
    pub normalize_paths: bool,
    pub units: UsageUnits,
    pub human_readable: bool,
    pub threshold_used_percent_min: Option<f64>,
    pub threshold_used_percent_max: Option<f64>,
    pub timeout_ms: u64,
}

/// Target identification for resize operations
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ResizeTargetKind {
    Auto,
    Mountpoint,
    Device,
}

/// Resize operation mode
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ResizeMode {
    Grow,
    Shrink,
    Auto,
}

/// Size units for resize operations
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SizeUnits {
    Auto,
    Bytes,
    Kilobytes,
    Megabytes,
    Gigabytes,
    Terabytes,
}

/// Filesystem resize configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FsResizeConfig {
    pub target: String,
    pub by: ResizeTargetKind,
    pub size: Option<Value>,
    pub delta: Option<Value>,
    pub size_units: SizeUnits,
    pub mode: ResizeMode,
    pub allow_shrink: bool,
    pub min_free_space_percent: f64,
    pub manage_underlying_volume: bool,
    pub volume_resize_only: bool,
    pub filesystem_resize_only: bool,
    pub require_unmounted_for_shrink: bool,
    pub force: bool,
    pub dry_run: bool,
    pub timeout_ms: u64,
}

/// Filesystem information for resize operations
#[derive(Debug, Clone, Serialize)]
pub struct ResizeFilesystemInfo {
    pub source: String,
    pub fstype: String,
    pub mounted: bool,
    pub current_size_bytes: u64,
    pub requested_size_bytes: Option<u64>,
    pub delta_bytes: Option<i64>,
}

/// Resize action step
#[derive(Debug, Clone, Serialize)]
pub struct ResizeAction {
    pub r#type: String,
    pub tool: String,
    pub status: String,
    pub command: String,
}

/// Resize operation plan for dry-run
#[derive(Debug, Clone, Serialize)]
pub struct ResizePlan {
    pub steps: Vec<ResizeAction>,
}

/// Resize operation result
#[derive(Debug, Clone, Serialize)]
pub struct ResizeResult {
    pub backend: String,
    pub verb: String,
    pub alias: Option<String>,
    pub target: String,
    pub by: String,
    pub filesystem: ResizeFilesystemInfo,
    pub requested_size_bytes: Option<u64>,
    pub previous_size_bytes: Option<u64>,
    pub final_size_bytes: Option<u64>,
    pub delta_bytes: Option<i64>,
    pub mode: String,
    pub action: String,
    pub reason: Option<String>,
    pub actions: Option<Vec<ResizeAction>>,
    pub summary: Option<ResizeSummary>,
    pub dry_run: Option<bool>,
    pub plan: Option<ResizePlan>,
}

/// Resize operation summary
#[derive(Debug, Clone, Serialize)]
pub struct ResizeSummary {
    pub status: String,
    pub shrink: bool,
    pub grew: bool,
}

/// Filesystem information for quota queries
#[derive(Debug, Clone, Serialize)]
pub struct QuotaFilesystem {
    pub source: String,
    pub target: String,
    pub fstype: String,
}

/// Subject query information
#[derive(Debug, Clone, Serialize)]
pub struct QuotaSubjectQuery {
    pub subject: String,
    pub subject_type: String,
    pub resolved_uid: Option<u32>,
    pub resolved_gid: Option<u32>,
}

/// Space quota information
#[derive(Debug, Clone, Serialize)]
pub struct SpaceQuota {
    pub used: u64,
    pub soft_limit: Option<u64>,
    pub hard_limit: Option<u64>,
    pub grace_exceeded: bool,
    pub grace_time_remaining_sec: Option<u64>,
    pub used_percent_of_soft: Option<f64>,
}

/// Inode quota information
#[derive(Debug, Clone, Serialize)]
pub struct InodeQuota {
    pub used: u64,
    pub soft_limit: Option<u64>,
    pub hard_limit: Option<u64>,
    pub grace_exceeded: bool,
    pub grace_time_remaining_sec: Option<u64>,
    pub used_percent_of_soft: Option<f64>,
}

/// Subject quota information
#[derive(Debug, Clone, Serialize)]
pub struct QuotaSubject {
    pub subject: String,
    pub subject_type: String,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub space: Option<SpaceQuota>,
    pub inodes: Option<InodeQuota>,
}

/// Quota operation result
#[derive(Debug, Clone, Serialize)]
pub struct QuotaResult {
    pub backend: String,
    pub verb: String,
    pub alias: String,
    pub path: String,
    pub filesystem: QuotaFilesystem,
    pub subject_query: QuotaSubjectQuery,
    pub units: String,
    pub space_quota_enabled: bool,
    pub inode_quota_enabled: bool,
    pub subjects: Vec<QuotaSubject>,
}

/// Aggregated space quota summary
#[derive(Debug, Clone, Serialize)]
pub struct SpaceQuotaSummary {
    pub used: u64,
    pub soft_limit: Option<u64>,
    pub hard_limit: Option<u64>,
    pub used_percent_of_soft: Option<f64>,
    pub any_grace_exceeded: bool,
}

/// Aggregated inode quota summary
#[derive(Debug, Clone, Serialize)]
pub struct InodeQuotaSummary {
    pub used: u64,
    pub soft_limit: Option<u64>,
    pub hard_limit: Option<u64>,
    pub used_percent_of_soft: Option<f64>,
    pub any_grace_exceeded: bool,
}

/// Filesystem with quota information
#[derive(Debug, Clone, Serialize)]
pub struct QuotaSummaryFilesystem {
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub space_quota_enabled: bool,
    pub inode_quota_enabled: bool,
    pub space: Option<SpaceQuota>,
    pub inodes: Option<InodeQuota>,
}

/// Filesystem without quota support
#[derive(Debug, Clone, Serialize)]
pub struct FilesystemWithoutQuotas {
    pub source: String,
    pub target: String,
    pub fstype: String,
}

/// Partial failure information
#[derive(Debug, Clone, Serialize)]
pub struct PartialFailure {
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub error: PartialFailureError,
}

/// Partial failure error information
#[derive(Debug, Clone, Serialize)]
pub struct PartialFailureError {
    pub code: String,
    pub message: String,
}

/// Quota summary filters
#[derive(Debug, Clone, Serialize)]
pub struct QuotaSummaryFilters {
    pub include_mountpoints: Vec<String>,
    pub exclude_mountpoints: Vec<String>,
    pub include_types: Vec<String>,
    pub exclude_types: Vec<String>,
    pub include_sources: Vec<String>,
    pub exclude_sources: Vec<String>,
}

/// Subject summary for multi-subject aggregation
#[derive(Debug, Clone, Serialize)]
pub struct SubjectSummary {
    pub subject: String,
    pub subject_type: String,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub space: Option<SpaceQuotaSummary>,
    pub inodes: Option<InodeQuotaSummary>,
}

/// Quota summary operation result
#[derive(Debug, Clone, Serialize)]
pub struct QuotaSummaryResult {
    pub backend: String,
    pub verb: String,
    pub alias: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_query: Option<QuotaSubjectQuery>,
    pub filters: QuotaSummaryFilters,
    pub units: String,
    pub include_space: bool,
    pub include_inodes: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<QuotaSummaryData>,
    pub all_subjects: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subjects: Option<Vec<SubjectSummary>>,
    pub filesystems: Vec<QuotaSummaryFilesystem>,
    pub filesystems_without_quotas: Vec<FilesystemWithoutQuotas>,
    pub partial_failures: Vec<PartialFailure>,
}

/// Summary data for single subject
#[derive(Debug, Clone, Serialize)]
pub struct QuotaSummaryData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space: Option<SpaceQuotaSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inodes: Option<InodeQuotaSummary>,
}

/// Filesystem usage information with extended details
#[derive(Debug, Clone, Serialize)]
pub struct FilesystemUsage {
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub read_only: bool,
    pub size: u64,
    pub used: u64,
    pub free: u64,
    pub used_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_human: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_human: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_human: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inodes: Option<FilesystemInodes>,
}

/// Inode usage information for filesystems
#[derive(Debug, Clone, Serialize)]
pub struct FilesystemInodes {
    pub total: u64,
    pub used: u64,
    pub free: u64,
    pub used_percent: Option<f64>,
}

/// Aggregate usage information
#[derive(Debug, Clone, Serialize)]
pub struct AggregateUsage {
    pub size: u64,
    pub used: u64,
    pub free: u64,
    pub used_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_human: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_human: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_human: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inodes: Option<FilesystemInodes>,
}

/// Path to filesystem mapping
#[derive(Debug, Clone, Serialize)]
pub struct PathToFilesystem {
    pub path: String,
    pub target: String,
    pub source: String,
}

/// Usage filters applied
#[derive(Debug, Clone, Serialize)]
pub struct UsageFilters {
    pub include_mountpoints: Vec<String>,
    pub exclude_mountpoints: Vec<String>,
    pub include_types: Vec<String>,
    pub exclude_types: Vec<String>,
    pub include_sources: Vec<String>,
    pub exclude_sources: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold_used_percent_min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold_used_percent_max: Option<f64>,
}

/// Usage operation result
#[derive(Debug, Clone, Serialize)]
pub struct UsageResult {
    pub backend: String,
    pub verb: String,
    pub alias: String,
    pub mode: String,
    pub units: String,
    pub include_inodes: bool,
    pub filters: UsageFilters,
    pub filesystems: Vec<FilesystemUsage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate: Option<AggregateUsage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_to_filesystem: Option<Vec<PathToFilesystem>>,
    /// Mounts that were skipped because their usage could not be read.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            include_mountpoints: Vec::new(),
            exclude_mountpoints: Vec::new(),
            include_types: Vec::new(),
            exclude_types: Vec::new(),
            include_sources: Vec::new(),
            exclude_sources: Vec::new(),
            include_usage: true,
            include_inodes: false,
            include_fs_metadata: true,
            include_os_metadata: true,
            normalize_paths: true,
            format: SnapshotFormat::Json,
            timeout_ms: 5000,
        }
    }
}

/// List-mounts configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ListMountsConfig {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub include_mountpoints: Vec<String>,
    #[serde(default)]
    pub exclude_mountpoints: Vec<String>,
    #[serde(default)]
    pub include_types: Vec<String>,
    #[serde(default)]
    pub exclude_types: Vec<String>,
    #[serde(default)]
    pub include_sources: Vec<String>,
    #[serde(default)]
    pub exclude_sources: Vec<String>,
    #[serde(default = "default_true")]
    pub include_readonly: bool,
    #[serde(default = "default_true")]
    pub include_readwrite: bool,
    #[serde(default = "default_false")]
    pub include_pseudo: bool,
    #[serde(default = "default_true")]
    pub include_loop: bool,
    #[serde(default = "default_true")]
    pub include_network: bool,
    #[serde(default = "default_true")]
    pub normalize_paths: bool,
    #[serde(default = "default_false")]
    pub resolve_labels: bool,
    #[serde(default = "default_false")]
    pub resolve_fs_features: bool,
    #[serde(default = "default_list_mounts_timeout")]
    pub timeout_ms: u64,
}

/// Mount entry for list-mounts response
#[derive(Debug, Clone, Serialize)]
pub struct ListMountEntry {
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub options: Vec<String>,
    pub read_only: bool,
    pub pseudo: bool,
    pub network: bool,
    #[serde(rename = "loop")]
    pub loop_device: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs_features: Option<FsFeatures>,
}

/// Device metadata for mounted filesystems
#[derive(Debug, Clone, Serialize)]
pub struct DeviceMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partlabel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partuuid: Option<String>,
}

/// Filesystem features information
#[derive(Debug, Clone, Serialize)]
pub struct FsFeatures {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inode_size: Option<u64>,
}

/// Filters applied for list-mounts
#[derive(Debug, Clone, Serialize)]
pub struct ListMountsFilters {
    pub paths: Vec<String>,
    pub include_mountpoints: Vec<String>,
    pub exclude_mountpoints: Vec<String>,
    pub include_types: Vec<String>,
    pub exclude_types: Vec<String>,
    pub include_sources: Vec<String>,
    pub exclude_sources: Vec<String>,
    pub include_readonly: bool,
    pub include_readwrite: bool,
    pub include_pseudo: bool,
    pub include_loop: bool,
    pub include_network: bool,
}

/// List-mounts operation result
#[derive(Debug, Serialize)]
pub struct ListMountsResult {
    pub backend: String,
    pub verb: String,
    pub alias: String,
    pub filters: ListMountsFilters,
    pub mounts: Vec<ListMountEntry>,
}

// Helper functions for default values
fn default_false() -> bool {
    false
}
fn default_list_mounts_timeout() -> u64 {
    3000
}

impl FsHandle {
    pub fn from_url(url: Url) -> Result<Self> {
        let alias = url
            .host_str()
            .unwrap_or("default")
            .trim_end_matches(".mount")
            .to_string();

        Ok(Self { alias })
    }

    pub fn new_for_test(alias: String) -> Self {
        Self { alias }
    }

    /// Main mount operation implementation
    pub async fn mount(&self, args: Value) -> Result<Value, anyhow::Error> {
        let config = self.parse_mount_config(args)?;
        self.validate_mount_config(&config)?;
        let limit = crate::core::process::limit(Duration::from_millis(config.timeout_ms));
        timeout(limit, self.mount_inner(&config))
            .await
            .map_err(|_| FsError::MountTimeout)?
    }

    async fn mount_inner(&self, config: &MountConfig) -> Result<Value, anyhow::Error> {
        let existing_mounts = self
            .get_existing_mounts()
            .await
            .map_err(|e| FsError::MountFailure(format!("cannot read the mount table: {e}")))?;
        let existing_mount = self.find_existing_mount(&existing_mounts, config);

        if let Some(existing) = &existing_mount {
            if config.fail_if_mounted {
                return Err(FsError::AlreadyMounted(config.target.clone()).into());
            }

            if !config.remount && !self.is_mount_compatible(existing, config) {
                return Err(FsError::ConflictingMount(format!(
                    "{} has {} ({}) mounted",
                    config.target, existing.source, existing.fs_type
                ))
                .into());
            }

            if !config.remount {
                // Idempotent: the requested mount is already in place.
                return Ok(json!(MountResult {
                    backend: "fs".to_string(),
                    verb: "mount".to_string(),
                    alias: self.alias.clone(),
                    source: existing.source.clone().into(),
                    target: config.target.clone(),
                    r#type: existing.fs_type.clone().into(),
                    options: existing.options.clone(),
                    read_only: existing.options.contains(&"ro".to_string()),
                    bind: config.bind,
                    remount: false,
                    action: "already_mounted".to_string(),
                    created_target: false,
                    details: MountDetails {
                        device: Some(existing.source.clone()),
                        fs_type: Some(existing.fs_type.clone()),
                        mount_flags: existing.options.clone(),
                        from_existing: true,
                    },
                    dry_run: if config.dry_run { Some(true) } else { None },
                    plan: None,
                }));
            }
        } else if config.remount {
            // Nothing to remount: mount(8) would fail with a vaguer message.
            return Err(FsError::NotMounted(config.target.clone()).into());
        }

        if config.dry_run {
            return Ok(json!(self.create_mount_plan(config, false)?));
        }

        self.execute_mount(config, existing_mount.is_some()).await
    }

    /// Parse mount configuration from arguments. Every value is checked:
    /// a boolean that is not one of the documented spellings, a timeout that
    /// is not a number or a malformed list is an error, never a default.
    fn parse_mount_config(&self, args: Value) -> Result<MountConfig, anyhow::Error> {
        let invalid = |m: String| -> anyhow::Error { FsError::InvalidMountConfig(m).into() };
        let mut config = MountConfig::default();
        let Some(obj) = args.as_object() else {
            return Err(invalid("arguments must be key=value pairs".to_string()));
        };
        for (key, value) in obj {
            match key.as_str() {
                "target" => config.target = support::string_value(key, value).map_err(invalid)?,
                "source" => {
                    config.source = Some(support::string_value(key, value).map_err(invalid)?)
                }
                "type" => config.r#type = Some(support::string_value(key, value).map_err(invalid)?),
                "options" => config.options = support::list_value(key, value).map_err(invalid)?,
                "read_only" => {
                    config.read_only = support::bool_value(key, value).map_err(invalid)?
                }
                "bind" => config.bind = support::bool_value(key, value).map_err(invalid)?,
                "create_target" => {
                    config.create_target = support::bool_value(key, value).map_err(invalid)?
                }
                "make_parents" => {
                    config.make_parents = support::bool_value(key, value).map_err(invalid)?
                }
                "fail_if_mounted" => {
                    config.fail_if_mounted = support::bool_value(key, value).map_err(invalid)?
                }
                "remount" => config.remount = support::bool_value(key, value).map_err(invalid)?,
                "network" => config.network = support::bool_value(key, value).map_err(invalid)?,
                "dry_run" => config.dry_run = self.parse_dry_run_value(value)?,
                "timeout_ms" => {
                    config.timeout_ms = support::u64_value(key, value).map_err(invalid)?
                }
                // Unknown keys are refused by `call` before this runs.
                _ => {}
            }
        }

        // 0 selects the default.
        if config.timeout_ms == 0 {
            config.timeout_ms = 5000;
        }

        // A relative target is resolved from the current directory, so that
        // it can be compared with the (absolute) mount table.
        if !config.target.trim().is_empty() && !config.target.starts_with('-') {
            config.target = support::absolute(&config.target);
        }

        if config.read_only && !config.options.contains(&"ro".to_string()) {
            config.options.push("ro".to_string());
        }

        Ok(config)
    }

    /// `dry_run` for mount and unmount. A value that is not a recognised
    /// boolean is an error: a mistyped dry run must not mount or unmount for
    /// real.
    fn parse_dry_run_value(&self, value: &Value) -> Result<bool, anyhow::Error> {
        let parsed = match value {
            Value::Bool(b) => Some(*b),
            Value::String(s) => crate::core::lenient::parse_bool(s),
            _ => None,
        };
        parsed.ok_or_else(|| {
            FsError::InvalidMountConfig(format!(
                "invalid dry_run value {value}: expected true/false/1/0/yes/no/on/off"
            ))
            .into()
        })
    }

    /// Validate mount configuration
    fn validate_mount_config(&self, config: &MountConfig) -> Result<(), anyhow::Error> {
        let invalid = |m: &str| -> anyhow::Error { FsError::InvalidMountConfig(m.into()).into() };
        if config.target.trim().is_empty() {
            return Err(invalid("target is required and cannot be empty"));
        }
        if config.timeout_ms == 0 {
            return Err(invalid("timeout_ms must be greater than 0"));
        }
        if config.source.as_ref().is_some_and(|s| s.trim().is_empty()) {
            return Err(invalid("source cannot be empty"));
        }
        if config.bind && config.source.is_none() {
            return Err(invalid("bind mounts require a source path"));
        }

        // An option-shaped operand would be read by mount as an option
        if config.target.starts_with('-') {
            return Err(invalid("target cannot start with '-'"));
        }
        if config.source.as_ref().is_some_and(|s| s.starts_with('-')) {
            return Err(invalid("source cannot start with '-'"));
        }
        if let Some(t) = &config.r#type {
            let ok = !t.is_empty()
                && !t.starts_with('-')
                && t.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c));
            if !ok {
                return Err(invalid(
                    "type must be a filesystem type name (letters, digits, '.', '_', '+', '-')",
                ));
            }
        }
        if config
            .options
            .iter()
            .any(|o| o.chars().any(char::is_whitespace))
        {
            return Err(invalid("mount options cannot contain whitespace"));
        }

        if config.remount && config.fail_if_mounted {
            return Err(invalid("remount and fail_if_mounted are contradictory"));
        }
        if config.bind && config.network {
            return Err(invalid("bind and network are contradictory"));
        }

        // network=true declares a network share: the source must name one,
        // and an explicit type must be a network filesystem type.
        if config.network {
            let Some(source) = &config.source else {
                return Err(invalid(
                    "network mounts require a source (host:/path or //host/share)",
                ));
            };
            let looks_remote = source.starts_with("//")
                || source
                    .split_once(':')
                    .is_some_and(|(host, _)| !host.is_empty() && !host.contains('/'));
            if !looks_remote {
                return Err(invalid(
                    "network=true needs a network source such as host:/path or //host/share",
                ));
            }
            if let Some(t) = &config.r#type {
                if !is_network_fstype(t) {
                    return Err(FsError::InvalidMountConfig(format!(
                        "network=true but type {t} is not a network filesystem"
                    ))
                    .into());
                }
            }
        }

        Ok(())
    }

    /// Mount table entries (decoded) as `ExistingMount`s.
    async fn get_existing_mounts(&self) -> Result<Vec<ExistingMount>, anyhow::Error> {
        let table = support::read_mount_table().context("Failed to read the mount table")?;
        Ok(table
            .into_iter()
            .map(|m| ExistingMount {
                source: m.source,
                target: m.target,
                fs_type: m.fstype,
                options: m.options.split(',').map(|s| s.to_string()).collect(),
            })
            .collect())
    }

    /// The mount currently visible at the target: the last one mounted
    /// there when several are stacked.
    fn find_existing_mount(
        &self,
        mounts: &[ExistingMount],
        config: &MountConfig,
    ) -> Option<ExistingMount> {
        mounts
            .iter()
            .rev()
            .find(|mount| mount.target == config.target)
            .cloned()
    }

    /// Check if existing mount is compatible with requested configuration
    fn is_mount_compatible(&self, existing: &ExistingMount, config: &MountConfig) -> bool {
        if let Some(ref source) = config.source {
            if config.bind {
                // The mount table names the device, not the bound directory:
                // compare the directory itself with what the target shows.
                let same = match (fs::metadata(source), fs::metadata(&config.target)) {
                    (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
                    _ => false,
                };
                if !same {
                    return false;
                }
            } else if !support::same_source(&existing.source, source) {
                return false;
            }
        }

        if let Some(ref fs_type) = config.r#type {
            if fs_type != "auto" && existing.fs_type != *fs_type {
                return false;
            }
        }

        true
    }

    /// The `mount` arguments for `config` (without the program name).
    fn mount_args(&self, config: &MountConfig, is_remount: bool) -> Vec<String> {
        let mut cmd = Vec::new();
        if config.remount || is_remount {
            cmd.push("-o".to_string());
            cmd.push("remount".to_string());
        }
        if let Some(ref fs_type) = config.r#type {
            cmd.push("-t".to_string());
            cmd.push(fs_type.clone());
        }
        if config.bind {
            cmd.push("--bind".to_string());
        }
        if !config.options.is_empty() {
            cmd.push("-o".to_string());
            cmd.push(config.options.join(","));
        }
        // Operands after `--` are never read as options
        cmd.push("--".to_string());
        if let Some(ref source) = config.source {
            cmd.push(source.clone());
        }
        cmd.push(config.target.clone());
        cmd
    }

    /// Create a plan for dry-run mode
    fn create_mount_plan(
        &self,
        config: &MountConfig,
        already_mounted: bool,
    ) -> Result<MountResult, anyhow::Error> {
        let mut plan = MountPlan {
            create_directory: Vec::new(),
            mount_commands: Vec::new(),
        };

        if config.create_target && !Path::new(&config.target).exists() {
            if config.make_parents {
                plan.create_directory
                    .push(format!("mkdir -p {}", config.target));
            } else {
                plan.create_directory
                    .push(format!("mkdir {}", config.target));
            }
        }

        if !already_mounted || config.remount {
            let mut cmd = vec!["mount".to_string()];
            cmd.extend(self.mount_args(config, false));
            plan.mount_commands.push(cmd.join(" "));
        }

        Ok(MountResult {
            backend: "fs".to_string(),
            verb: "mount".to_string(),
            alias: self.alias.clone(),
            source: config.source.clone(),
            target: config.target.clone(),
            r#type: config.r#type.clone(),
            options: config.options.clone(),
            read_only: config.read_only,
            bind: config.bind,
            remount: config.remount,
            action: if already_mounted {
                "already_mounted"
            } else {
                "planned"
            }
            .to_string(),
            created_target: false,
            details: MountDetails {
                device: config.source.clone(),
                fs_type: config.r#type.clone(),
                mount_flags: config.options.clone(),
                from_existing: false,
            },
            dry_run: Some(true),
            plan: Some(plan),
        })
    }

    /// Execute the actual mount operation
    async fn execute_mount(
        &self,
        config: &MountConfig,
        is_remount: bool,
    ) -> Result<Value, anyhow::Error> {
        let target_path = Path::new(&config.target);
        // The first directory this call creates, removed again if the mount
        // fails so that a failed mount leaves nothing behind.
        let mut created: Option<std::path::PathBuf> = None;

        if config.remount || is_remount {
            // A remount changes an existing mount; there is nothing to create.
        } else if !target_path.exists() {
            if !config.create_target {
                return Err(FsError::TargetCreationFailed(format!(
                    "{} does not exist and create_target=false",
                    config.target
                ))
                .into());
            }
            let parent_exists = target_path.parent().is_none_or(|p| p.exists());
            if !config.make_parents && !parent_exists {
                return Err(FsError::TargetCreationFailed(format!(
                    "parent of {} does not exist and make_parents=false",
                    config.target
                ))
                .into());
            }
            let mut first_missing = target_path.to_path_buf();
            while let Some(parent) = first_missing.parent() {
                if parent.exists() {
                    break;
                }
                first_missing = parent.to_path_buf();
            }
            std::fs::create_dir_all(target_path)
                .map_err(|e| FsError::TargetCreationFailed(format!("{}: {e}", config.target)))?;
            created = Some(first_missing);
        } else if !target_path.is_dir() && !config.bind {
            return Err(FsError::InvalidMountConfig(format!(
                "target {} exists and is not a directory",
                config.target
            ))
            .into());
        }

        let undo = |created: &Option<std::path::PathBuf>| {
            if let Some(dir) = created {
                let _ = std::fs::remove_dir_all(dir);
            }
        };

        let mut cmd = tool("mount");
        cmd.args(self.mount_args(config, is_remount));
        let output = match run(&mut cmd).await {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                undo(&created);
                return Err(FsError::MountUnsupported.into());
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::TimedOut {
                    undo(&created);
                }
                return Err(FsError::MountFailure(e.to_string()).into());
            }
        };

        if !output.status.success() {
            undo(&created);
            let msg = tool_message(&output);
            if support::is_permission_message(&msg) {
                return Err(FsError::MountPermissionDenied.into());
            }
            return Err(FsError::MountFailure(msg).into());
        }

        let action = if config.remount || is_remount {
            "remounted"
        } else {
            "mounted"
        };

        Ok(json!(MountResult {
            backend: "fs".to_string(),
            verb: "mount".to_string(),
            alias: self.alias.clone(),
            source: config.source.clone(),
            target: config.target.clone(),
            r#type: config.r#type.clone(),
            options: config.options.clone(),
            read_only: config.read_only,
            bind: config.bind,
            remount: config.remount || is_remount,
            action: action.to_string(),
            created_target: created.is_some(),
            details: MountDetails {
                device: config.source.clone(),
                fs_type: config.r#type.clone(),
                mount_flags: config.options.clone(),
                from_existing: false,
            },
            dry_run: None,
            plan: None,
        }))
    }

    /// Main unmount operation implementation
    pub async fn unmount(&self, args: Value) -> Result<Value, anyhow::Error> {
        let config = self.parse_unmount_config(args)?;
        self.validate_unmount_config(&config)?;
        let limit = crate::core::process::limit(Duration::from_millis(config.timeout_ms));
        timeout(limit, self.unmount_inner(&config))
            .await
            .map_err(|_| FsError::UnmountTimeout)?
    }

    async fn unmount_inner(&self, config: &UnmountConfig) -> Result<Value, anyhow::Error> {
        let existing_mounts = self
            .get_existing_mounts()
            .await
            .map_err(|e| FsError::UnmountFailure(format!("cannot read the mount table: {e}")))?;
        let matched_mounts = self.find_mounts_to_unmount(&existing_mounts, config)?;

        if matched_mounts.is_empty() {
            if config.fail_if_not_mounted {
                return Err(FsError::NotMounted(config.target.clone()).into());
            }

            return Ok(json!(UnmountResult {
                backend: "fs".to_string(),
                verb: "unmount".to_string(),
                alias: self.alias.clone(),
                target: config.target.clone(),
                by: format!("{:?}", config.by).to_lowercase(),
                force: config.force,
                lazy: config.lazy,
                detach_children: config.detach_children,
                action: "already_unmounted".to_string(),
                unmounted: vec![],
                skipped: vec![],
                errors: vec![],
                dry_run: if config.dry_run { Some(true) } else { None },
                plan: if config.dry_run {
                    Some(UnmountPlan {
                        order: vec![],
                        commands: vec![],
                    })
                } else {
                    None
                },
                matched_mounts: None,
            }));
        }

        let unmount_order =
            self.compute_unmount_order(&matched_mounts, &existing_mounts, config)?;

        if config.dry_run {
            return Ok(json!(self.create_unmount_plan(config, &unmount_order)?));
        }

        self.execute_unmount(config, &unmount_order).await
    }

    /// Parse unmount configuration from arguments. Every value is checked.
    fn parse_unmount_config(&self, args: Value) -> Result<UnmountConfig, anyhow::Error> {
        let invalid = |m: String| -> anyhow::Error { FsError::InvalidUnmountConfig(m).into() };
        let mut config = UnmountConfig::default();
        let Some(obj) = args.as_object() else {
            return Err(invalid("arguments must be key=value pairs".to_string()));
        };
        for (key, value) in obj {
            match key.as_str() {
                "target" => config.target = support::string_value(key, value).map_err(invalid)?,
                "by" => {
                    config.by = match support::string_value(key, value).map_err(invalid)?.as_str() {
                        "target" => UnmountTargetKind::Target,
                        "source" => UnmountTargetKind::Source,
                        "auto" => UnmountTargetKind::Auto,
                        other => {
                            return Err(invalid(format!(
                                "invalid value for by: {other:?} (expected target, source or auto)"
                            )));
                        }
                    }
                }
                "force" => config.force = support::bool_value(key, value).map_err(invalid)?,
                "lazy" => config.lazy = support::bool_value(key, value).map_err(invalid)?,
                "detach_children" => {
                    config.detach_children = support::bool_value(key, value).map_err(invalid)?
                }
                "fail_if_not_mounted" => {
                    config.fail_if_not_mounted = support::bool_value(key, value).map_err(invalid)?
                }
                "dry_run" => {
                    config.dry_run = self.parse_dry_run_value(value).map_err(|e| {
                        anyhow::Error::from(FsError::InvalidUnmountConfig(
                            e.to_string()
                                .trim_start_matches("Invalid mount configuration: ")
                                .to_string(),
                        ))
                    })?
                }
                "timeout_ms" => {
                    config.timeout_ms = support::u64_value(key, value).map_err(invalid)?
                }
                _ => {}
            }
        }

        if config.timeout_ms == 0 {
            config.timeout_ms = 5000;
        }

        Ok(config)
    }

    /// Validate unmount configuration
    fn validate_unmount_config(&self, config: &UnmountConfig) -> Result<(), anyhow::Error> {
        if config.target.trim().is_empty() {
            return Err(FsError::InvalidUnmountConfig(
                "target is required and cannot be empty".to_string(),
            )
            .into());
        }
        if config.target.starts_with('-') {
            return Err(
                FsError::InvalidUnmountConfig("target cannot start with '-'".to_string()).into(),
            );
        }
        if config.timeout_ms == 0 {
            return Err(FsError::InvalidUnmountConfig(
                "timeout_ms must be greater than 0".to_string(),
            )
            .into());
        }
        Ok(())
    }

    /// Find mounts to unmount based on the target and strategy. A mount
    /// point is compared after making it absolute and normalized; a source
    /// also matches through symlinks (`/dev/disk/by-uuid/...`), `UUID=` and
    /// `LABEL=` tags, and an image file attached to a loop device.
    fn find_mounts_to_unmount(
        &self,
        existing_mounts: &[ExistingMount],
        config: &UnmountConfig,
    ) -> Result<Vec<ExistingMount>, anyhow::Error> {
        let as_target = if config.target.starts_with('/') || !config.target.contains(':') {
            support::absolute(&config.target)
        } else {
            config.target.clone()
        };
        let by_target = || -> Vec<ExistingMount> {
            existing_mounts
                .iter()
                .filter(|m| m.target == as_target)
                .cloned()
                .collect()
        };
        let by_source = || -> Vec<ExistingMount> {
            existing_mounts
                .iter()
                .filter(|m| support::same_source(&m.source, &config.target))
                .cloned()
                .collect()
        };

        Ok(match config.by {
            UnmountTargetKind::Target => by_target(),
            UnmountTargetKind::Source => by_source(),
            UnmountTargetKind::Auto => {
                let found = by_target();
                if found.is_empty() { by_source() } else { found }
            }
        })
    }

    /// Compute the order of unmount operations, including children if requested
    fn compute_unmount_order(
        &self,
        matched_mounts: &[ExistingMount],
        all_mounts: &[ExistingMount],
        config: &UnmountConfig,
    ) -> Result<Vec<ExistingMount>, anyhow::Error> {
        let mut unmount_list: Vec<ExistingMount> = Vec::new();

        // Stacked mounts are unmounted top (last mounted) first.
        for matched_mount in matched_mounts.iter().rev() {
            if config.detach_children {
                let mut children: Vec<ExistingMount> = all_mounts
                    .iter()
                    .filter(|m| {
                        m.target != matched_mount.target
                            && support::path_is_under(&m.target, &matched_mount.target)
                    })
                    .cloned()
                    .collect();

                // Deepest first
                children.sort_by(|a, b| {
                    let depth_a = Path::new(&a.target).components().count();
                    let depth_b = Path::new(&b.target).components().count();
                    depth_b.cmp(&depth_a)
                });

                for child in children {
                    if !unmount_list
                        .iter()
                        .any(|m| m.target == child.target && m.source == child.source)
                    {
                        unmount_list.push(child);
                    }
                }
            }

            unmount_list.push(matched_mount.clone());
        }

        Ok(unmount_list)
    }

    /// The `umount` arguments for one mount (without the program name).
    fn umount_args(&self, config: &UnmountConfig, target: &str) -> Vec<String> {
        let mut args = Vec::new();
        if config.lazy {
            args.push("-l".to_string());
        }
        if config.force {
            args.push("-f".to_string());
        }
        args.push("--".to_string());
        args.push(target.to_string());
        args
    }

    /// Create unmount plan for dry-run
    fn create_unmount_plan(
        &self,
        config: &UnmountConfig,
        unmount_order: &[ExistingMount],
    ) -> Result<UnmountResult, anyhow::Error> {
        let mut order = Vec::new();
        let mut commands = Vec::new();

        for mount in unmount_order {
            order.push(mount.target.clone());
            let mut cmd_parts = vec!["umount".to_string()];
            cmd_parts.extend(self.umount_args(config, &mount.target));
            commands.push(cmd_parts.join(" "));
        }

        let matched_mounts: Vec<MountInfo> = unmount_order
            .iter()
            .map(|mount| MountInfo {
                source: mount.source.clone(),
                target: mount.target.clone(),
                fs_type: mount.fs_type.clone(),
                options: Some(mount.options.clone()),
            })
            .collect();

        Ok(UnmountResult {
            backend: "fs".to_string(),
            verb: "unmount".to_string(),
            alias: self.alias.clone(),
            target: config.target.clone(),
            by: format!("{:?}", config.by).to_lowercase(),
            force: config.force,
            lazy: config.lazy,
            detach_children: config.detach_children,
            action: "planned".to_string(),
            unmounted: vec![],
            skipped: vec![],
            errors: vec![],
            dry_run: Some(true),
            plan: Some(UnmountPlan { order, commands }),
            matched_mounts: Some(matched_mounts),
        })
    }

    /// Execute the unmount operations in order. When a child cannot be
    /// unmounted its parent is skipped (it would be busy). Any failure makes
    /// the whole call fail, after printing which mounts were and were not
    /// unmounted.
    async fn execute_unmount(
        &self,
        config: &UnmountConfig,
        unmount_order: &[ExistingMount],
    ) -> Result<Value, anyhow::Error> {
        let mut unmounted = Vec::new();
        let mut skipped = Vec::new();
        let mut errors = Vec::new();
        let mut first_code: Option<i32> = None;

        let info = |mount: &ExistingMount| MountInfo {
            source: mount.source.clone(),
            target: mount.target.clone(),
            fs_type: mount.fs_type.clone(),
            options: Some(mount.options.clone()),
        };

        for mount in unmount_order {
            let failed_child = errors.iter().any(|e: &UnmountError| {
                e.target != mount.target && support::path_is_under(&e.target, &mount.target)
            });
            if failed_child {
                skipped.push(info(mount));
                continue;
            }
            match self.execute_single_unmount(config, mount).await {
                Ok(()) => unmounted.push(info(mount)),
                Err(e) => {
                    if first_code.is_none() {
                        first_code =
                            Some(e.downcast_ref::<FsError>().map(fs_exit_code).unwrap_or(1));
                    }
                    errors.push(UnmountError {
                        target: mount.target.clone(),
                        code: self.map_error_to_code(&e),
                        message: e.to_string(),
                    });
                }
            }
        }

        let action = if errors.is_empty() {
            "unmounted"
        } else if unmounted.is_empty() {
            "failed"
        } else {
            "partially_unmounted"
        };

        let result = json!(UnmountResult {
            backend: "fs".to_string(),
            verb: "unmount".to_string(),
            alias: self.alias.clone(),
            target: config.target.clone(),
            by: format!("{:?}", config.by).to_lowercase(),
            force: config.force,
            lazy: config.lazy,
            detach_children: config.detach_children,
            action: action.to_string(),
            unmounted,
            skipped,
            errors,
            dry_run: None,
            plan: None,
            matched_mounts: None,
        });

        if let Some(code) = first_code {
            let first = &result["errors"][0];
            let message = format!(
                "{}: {}",
                if action == "failed" {
                    "nothing was unmounted"
                } else {
                    "some mounts were not unmounted"
                },
                first["message"].as_str().unwrap_or("unmount failed")
            );
            return Err(FsError::Incomplete {
                output: result,
                code,
                message,
            }
            .into());
        }

        Ok(result)
    }

    /// Execute a single unmount operation
    async fn execute_single_unmount(
        &self,
        config: &UnmountConfig,
        mount: &ExistingMount,
    ) -> Result<(), anyhow::Error> {
        let mut cmd = tool("umount");
        cmd.args(self.umount_args(config, &mount.target));

        let output = match run(&mut cmd).await {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(FsError::UnmountUnsupported.into());
            }
            Err(e) => return Err(FsError::UnmountFailure(e.to_string()).into()),
        };

        if !output.status.success() {
            let msg = tool_message(&output);
            if support::is_permission_message(&msg) {
                return Err(FsError::UnmountPermissionDenied.into());
            } else if msg.contains("busy") {
                return Err(FsError::UnmountBusy(mount.target.clone()).into());
            } else if msg.contains("not mounted") {
                return Err(FsError::NotMounted(mount.target.clone()).into());
            }
            return Err(FsError::UnmountFailure(msg).into());
        }

        Ok(())
    }

    /// Map errors to error codes for JSON responses
    fn map_error_to_code(&self, error: &anyhow::Error) -> String {
        if let Some(fs_err) = error.downcast_ref::<FsError>() {
            match fs_err {
                FsError::InvalidMountConfig(_) => "fs.invalid_mount_config",
                FsError::InvalidUnmountConfig(_) => "fs.invalid_unmount_config",
                FsError::InvalidSnapshotConfig(_) => "fs.invalid_snapshot_config",
                FsError::InvalidQuotaConfig(_) => "fs.invalid_quota_config",
                FsError::ProfileNotFound(_) => "fs.profile_not_found",
                FsError::MountUnsupported => "fs.mount_unsupported",
                FsError::UnmountUnsupported => "fs.unmount_unsupported",
                FsError::SnapshotUnsupported => "fs.snapshot_unsupported",
                FsError::QuotaUnsupported => "fs.quota_unsupported",
                FsError::MountPermissionDenied => "fs.mount_permission_denied",
                FsError::UnmountPermissionDenied => "fs.unmount_permission_denied",
                FsError::AlreadyMounted(_) => "fs.already_mounted",
                FsError::ConflictingMount(_) => "fs.conflicting_mount",
                FsError::NotMounted(_) => "fs.not_mounted",
                FsError::QuotaNotEnabled(_) => "fs.quota_not_enabled",
                FsError::QuotaSubjectNotFound(_) => "fs.quota_subject_not_found",
                FsError::MountFailure(_) => "fs.mount_failure",
                FsError::UnmountFailure(_) => "fs.unmount_failure",
                FsError::SnapshotFailed(_) => "fs.snapshot_failed",
                FsError::QuotaFailed(_) => "fs.quota_failed",
                FsError::MountTimeout => "fs.mount_timeout",
                FsError::UnmountTimeout => "fs.unmount_timeout",
                FsError::SnapshotTimeout => "fs.snapshot_timeout",
                FsError::QuotaTimeout => "fs.quota_timeout",
                FsError::TargetCreationFailed(_) => "fs.target_creation_failed",
                FsError::UnmountBusy(_) => "fs.unmount_busy",
                FsError::UnmountOptionUnsupported(_) => "fs.unmount_option_unsupported",
                FsError::InvalidQuotaSummaryConfig(_) => "fs.invalid_quota_summary_config",
                FsError::QuotaSummaryUnsupported => "fs.quota_summary_unsupported",
                FsError::QuotaSummaryNoQuotaFilesystems(_) => {
                    "fs.quota_summary_no_quota_filesystems"
                }
                FsError::Incomplete { .. } => "fs.incomplete",
                FsError::QuotaSummaryTimeout => "fs.quota_summary_timeout",
                FsError::QuotaSummaryFailed(_) => "fs.quota_summary_failed",
                FsError::InvalidUsageConfig(_) => "fs.invalid_usage_config",
                FsError::UsageUnsupported => "fs.usage_unsupported",
                FsError::UsageTimeout => "fs.usage_timeout",
                FsError::UsageFailed(_) => "fs.usage_failed",
                FsError::PathNotFound(_) => "fs.path_not_found",
                FsError::UsageNothingSelected => "fs.usage_nothing_selected",
                FsError::InvalidResizeConfig(_) => "fs.invalid_resize_config",
                FsError::ResizeTargetNotFound(_) => "fs.resize_target_not_found",
                FsError::ResizeUnsupportedFilesystem(_) => "fs.resize_unsupported_filesystem",
                FsError::ResizeShrinkNotAllowed => "fs.resize_shrink_not_allowed",
                FsError::ResizeShrinkNotSupportedForFilesystem(_) => {
                    "fs.resize_shrink_not_supported_for_filesystem"
                }
                FsError::ResizeShrinkRequiresUnmount(_) => "fs.resize_shrink_requires_unmount",
                FsError::ResizeWouldViolateMinFree => "fs.resize_would_violate_min_free",
                FsError::ResizeTargetExceedsDevice => "fs.resize_target_exceeds_device",
                FsError::ResizeInvalidTargetSize(_) => "fs.resize_invalid_target_size",
                FsError::ResizeVolumeManagementUnsupported => {
                    "fs.resize_volume_management_unsupported"
                }
                FsError::ResizeTimeout => "fs.resize_timeout",
                FsError::ResizeFailed(_) => "fs.resize_failed",
                FsError::InvalidCheckConfig(_) => "fs.invalid_check_config",
                FsError::CheckTargetNotFound(_) => "fs.check_target_not_found",
                FsError::CheckUnsupportedFilesystem(_) => "fs.check_unsupported_filesystem",
                FsError::CheckRepairNotAllowed => "fs.check_repair_not_allowed",
                FsError::CheckRequiresUnmountForRepair(_) => "fs.check_requires_unmount_for_repair",
                FsError::CheckMustBeOffline(_) => "fs.check_must_be_offline",
                FsError::CheckToolNotAvailable(_) => "fs.check_tool_not_available",
                FsError::CheckTimeout => "fs.check_timeout",
                FsError::CheckFailed(_) => "fs.check_failed",
                FsError::InvalidListMountsConfig(_) => "fs.invalid_list_mounts_config",
                FsError::ListMountsUnsupported => "fs.list_mounts_unsupported",
                FsError::ListMountsTimeout => "fs.list_mounts_timeout",
                FsError::ListMountsFailed(_) => "fs.list_mounts_failed",
            }
        } else {
            "fs.unknown_error"
        }
        .to_string()
    }

    /// Main snapshot operation implementation
    pub async fn snapshot(&self, args: Value) -> Result<Value, anyhow::Error> {
        let config = self.parse_snapshot_config(args)?;
        self.validate_snapshot_config(&config)?;

        let limit = crate::core::process::limit(Duration::from_millis(config.timeout_ms));
        timeout(limit, self.execute_snapshot(&config))
            .await
            .map_err(|_| FsError::SnapshotTimeout)?
    }

    /// Parse snapshot configuration from arguments
    fn parse_snapshot_config(&self, args: Value) -> Result<SnapshotConfig, anyhow::Error> {
        let mut config: SnapshotConfig =
            parse_typed(args).map_err(|e| FsError::InvalidSnapshotConfig(e.to_string()))?;

        // 0 selects the default.
        if config.timeout_ms == 0 {
            config.timeout_ms = 5000;
        }

        Ok(config)
    }

    /// Validate snapshot configuration
    fn validate_snapshot_config(&self, config: &SnapshotConfig) -> Result<(), anyhow::Error> {
        if config.timeout_ms == 0 {
            return Err(FsError::InvalidSnapshotConfig(
                "timeout_ms must be greater than 0".to_string(),
            )
            .into());
        }
        support::check_filter_lists(&support::filter_pairs([
            &config.include_mountpoints,
            &config.exclude_mountpoints,
            &config.include_types,
            &config.exclude_types,
            &config.include_sources,
            &config.exclude_sources,
        ]))
        .map_err(FsError::InvalidSnapshotConfig)?;

        Ok(())
    }

    /// Execute the actual snapshot operation
    async fn execute_snapshot(&self, config: &SnapshotConfig) -> Result<Value, anyhow::Error> {
        let raw_mounts = self.read_mount_table().await.map_err(|e| match e {
            MountTableError::Missing => anyhow::Error::from(FsError::SnapshotUnsupported),
            MountTableError::Unreadable(m) => FsError::SnapshotFailed(m).into(),
        })?;

        let filtered_mounts = self.apply_snapshot_filters(&raw_mounts, config)?;

        let mut mount_entries = Vec::new();
        for raw_mount in filtered_mounts {
            let mut entry = MountEntry {
                source: raw_mount.source.clone(),
                target: if config.normalize_paths {
                    self.normalize_path(&raw_mount.target)
                } else {
                    raw_mount.target.clone()
                },
                fstype: raw_mount.fstype.clone(),
                options: self.parse_and_sort_options(&raw_mount.options),
                dump: raw_mount.dump,
                pass: raw_mount.pass,
                usage: None,
                inodes: None,
                fs_metadata: None,
            };

            if config.include_usage {
                entry.usage = self.get_usage_info(&raw_mount.target).await;
            }
            if config.include_inodes {
                entry.inodes = self.get_inode_info(&raw_mount.target).await;
            }
            if config.include_fs_metadata {
                entry.fs_metadata = self.get_fs_metadata(&raw_mount).await;
            }

            mount_entries.push(entry);
        }

        mount_entries.sort_by(|a, b| {
            a.target
                .cmp(&b.target)
                .then_with(|| a.source.cmp(&b.source))
                .then_with(|| a.fstype.cmp(&b.fstype))
        });

        let host_info = if config.include_os_metadata {
            self.get_host_info().await
        } else {
            None
        };

        let lockfile = SnapshotLockfile {
            lockfile_version: "fs-lock/v1".to_string(),
            generated_at: Utc::now(),
            alias: self.alias.clone(),
            host: host_info.clone(),
            filters: FilterInfo {
                include_mountpoints: config.include_mountpoints.clone(),
                exclude_mountpoints: config.exclude_mountpoints.clone(),
                include_types: config.include_types.clone(),
                exclude_types: config.exclude_types.clone(),
                include_sources: config.include_sources.clone(),
                exclude_sources: config.exclude_sources.clone(),
            },
            mounts: mount_entries.clone(),
        };

        let lockfile_content = self.serialize_lockfile(&lockfile, &config.format)?;

        let summary = SnapshotSummary {
            lockfile_version: lockfile.lockfile_version.clone(),
            mount_count: mount_entries.len(),
            filters_applied: self.has_filters(config),
            host: host_info,
        };

        let result = SnapshotResult {
            backend: "fs".to_string(),
            action: "snapshot".to_string(),
            alias: self.alias.clone(),
            format: match config.format {
                SnapshotFormat::Json => "json",
                SnapshotFormat::Yaml => "yaml",
                SnapshotFormat::Text => "text",
            }
            .to_string(),
            lockfile: lockfile_content,
            parsed: summary,
        };

        Ok(serde_json::to_value(result)?)
    }

    /// Read the system mount table. A missing table (no /proc) means the
    /// platform is not supported.
    async fn read_mount_table(&self) -> Result<Vec<RawMountInfo>, MountTableError> {
        support::read_mount_table().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                MountTableError::Missing
            } else {
                MountTableError::Unreadable(format!("cannot read the mount table: {e}"))
            }
        })
    }

    /// Apply the include/exclude filters. Mount point filters match whole
    /// path components (`/home` matches `/home/a`, not `/homex`).
    fn apply_snapshot_filters(
        &self,
        mounts: &[RawMountInfo],
        config: &SnapshotConfig,
    ) -> Result<Vec<RawMountInfo>, anyhow::Error> {
        Ok(apply_mount_filters(
            mounts,
            &MountFilters {
                include_mountpoints: &config.include_mountpoints,
                exclude_mountpoints: &config.exclude_mountpoints,
                include_types: &config.include_types,
                exclude_types: &config.exclude_types,
                include_sources: &config.include_sources,
                exclude_sources: &config.exclude_sources,
            },
            |m| (&m.target, &m.fstype, &m.source),
        ))
    }

    /// Normalize filesystem path
    fn normalize_path(&self, path: &str) -> String {
        let mut normalized = path.to_string();
        while normalized.contains("//") {
            normalized = normalized.replace("//", "/");
        }
        if normalized.len() > 1 && normalized.ends_with('/') {
            normalized.pop();
        }
        if normalized.is_empty() {
            "/".to_string()
        } else {
            normalized
        }
    }

    /// Parse and sort mount options
    fn parse_and_sort_options(&self, options_str: &str) -> Vec<String> {
        let mut options: Vec<String> = options_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        options.sort();
        options
    }

    /// Get filesystem usage information
    async fn get_usage_info(&self, path: &str) -> Option<UsageInfo> {
        self.get_statvfs_info(path).await
    }

    /// Size, used and available bytes of the filesystem at `path`, from
    /// `df -P -B1`. The tool runs under the operation deadline, so a hung
    /// network mount cannot stall the call past `timeout_ms`.
    async fn get_statvfs_info(&self, path: &str) -> Option<UsageInfo> {
        let mut cmd = tool("df");
        cmd.args(["-P", "-B1", "--"]).arg(path);
        let output = run(&mut cmd).await.ok()?;
        if !output.status.success() {
            return None;
        }
        let content = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = content.lines().nth(1)?.split_whitespace().collect();
        let (size, used, available) = (
            parts.get(1)?.parse::<u64>().ok()?,
            parts.get(2)?.parse::<u64>().ok()?,
            parts.get(3)?.parse::<u64>().ok()?,
        );
        let used_percent = if size > 0 {
            (used as f64 / size as f64) * 100.0
        } else {
            0.0
        };
        Some(UsageInfo {
            size_bytes: size,
            used_bytes: used,
            free_bytes: available,
            used_percent,
        })
    }

    /// Inode counts of the filesystem at `path`, from `df -P -i`.
    async fn get_inode_info(&self, path: &str) -> Option<InodeInfo> {
        let mut cmd = tool("df");
        cmd.args(["-P", "-i", "--"]).arg(path);
        let output = run(&mut cmd).await.ok()?;
        if !output.status.success() {
            return None;
        }
        let content = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = content.lines().nth(1)?.split_whitespace().collect();
        let (total, used, available) = (
            parts.get(1)?.parse::<u64>().ok()?,
            parts.get(2)?.parse::<u64>().ok()?,
            parts.get(3)?.parse::<u64>().ok()?,
        );
        let used_percent = if total > 0 {
            (used as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        Some(InodeInfo {
            total,
            used,
            free: available,
            used_percent,
        })
    }

    /// Get filesystem metadata
    async fn get_fs_metadata(&self, mount: &RawMountInfo) -> Option<FsMetadata> {
        let metadata = fs::metadata(&mount.target).ok()?;
        let dev = metadata.dev();
        Some(FsMetadata {
            block_size: metadata.blksize(),
            blocks: metadata.blocks(),
            flags: Vec::new(),
            device: format!("{}:{}", libc::major(dev), libc::minor(dev)),
        })
    }

    /// Get host system information, from /proc and /etc/os-release.
    async fn get_host_info(&self) -> Option<HostInfo> {
        let kernel_field = |name: &str| {
            fs::read_to_string(format!("/proc/sys/kernel/{name}"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        };
        let hostname = kernel_field("hostname");
        let mut os_family = kernel_field("ostype");
        let kernel = kernel_field("osrelease");
        let mut os_name = String::new();
        let mut os_version = String::new();

        if let Ok(content) = fs::read_to_string("/etc/os-release") {
            for line in content.lines() {
                if let Some(v) = line.strip_prefix("NAME=") {
                    os_name = v.trim_matches('"').to_string();
                } else if let Some(v) = line.strip_prefix("VERSION_ID=") {
                    os_version = v.trim_matches('"').to_string();
                }
            }
        }

        if os_family.is_empty() {
            os_family = "Linux".to_string();
        }

        Some(HostInfo {
            hostname,
            os_family,
            os_name,
            os_version,
            kernel,
            architecture: std::env::consts::ARCH.to_string(),
        })
    }

    /// Check if any filters are applied
    fn has_filters(&self, config: &SnapshotConfig) -> bool {
        !config.include_mountpoints.is_empty()
            || !config.exclude_mountpoints.is_empty()
            || !config.include_types.is_empty()
            || !config.exclude_types.is_empty()
            || !config.include_sources.is_empty()
            || !config.exclude_sources.is_empty()
    }

    /// Serialize lockfile to requested format
    fn serialize_lockfile(
        &self,
        lockfile: &SnapshotLockfile,
        format: &SnapshotFormat,
    ) -> Result<String, anyhow::Error> {
        match format {
            SnapshotFormat::Json => serde_json::to_string_pretty(lockfile)
                .context("Failed to serialize lockfile to JSON"),
            SnapshotFormat::Yaml => support::to_yaml(lockfile)
                .map_err(|e| FsError::SnapshotFailed(format!("cannot write YAML: {e}")).into()),
            SnapshotFormat::Text => self.serialize_lockfile_text(lockfile),
        }
    }

    /// Serialize lockfile to human-readable text format
    fn serialize_lockfile_text(
        &self,
        lockfile: &SnapshotLockfile,
    ) -> Result<String, anyhow::Error> {
        let mut output = String::new();

        output.push_str(&format!("# {}\n", lockfile.lockfile_version));
        output.push_str(&format!(
            "generated_at: {}\nalias: {}\n",
            lockfile.generated_at.to_rfc3339(),
            lockfile.alias
        ));

        if let Some(host) = &lockfile.host {
            output.push_str(&format!(
                "host: {} ({} {} {}, kernel {})\n",
                host.hostname, host.os_name, host.os_version, host.architecture, host.kernel
            ));
        }

        output.push_str("filters:\n");
        let f = &lockfile.filters;
        for (name, list) in [
            ("include_mountpoints", &f.include_mountpoints),
            ("exclude_mountpoints", &f.exclude_mountpoints),
            ("include_types", &f.include_types),
            ("exclude_types", &f.exclude_types),
            ("include_sources", &f.include_sources),
            ("exclude_sources", &f.exclude_sources),
        ] {
            if !list.is_empty() {
                output.push_str(&format!("  {name}: {list:?}\n"));
            }
        }

        output.push('\n');

        for mount in &lockfile.mounts {
            output.push_str(&format!(
                "{} on {} type={} opts={} dump={} pass={}",
                mount.source,
                mount.target,
                mount.fstype,
                mount.options.join(","),
                mount.dump,
                mount.pass
            ));

            if let Some(usage) = &mount.usage {
                output.push_str(&format!(
                    " size_bytes={} used_bytes={} free_bytes={}",
                    usage.size_bytes, usage.used_bytes, usage.free_bytes
                ));
            }
            if let Some(inodes) = &mount.inodes {
                output.push_str(&format!(
                    " inodes={} inodes_used={}",
                    inodes.total, inodes.used
                ));
            }

            output.push('\n');
        }

        Ok(output)
    }

    /// Main quota operation implementation
    pub async fn quota(&self, args: Value) -> Result<Value, anyhow::Error> {
        let config = self.parse_quota_config(args)?;
        self.validate_quota_config(&config)?;

        let limit = crate::core::process::limit(Duration::from_millis(config.timeout_ms));
        timeout(limit, self.execute_quota(&config))
            .await
            .map_err(|_| FsError::QuotaTimeout)?
    }

    /// Parse quota configuration from arguments
    fn parse_quota_config(&self, args: Value) -> Result<FsQuotaConfig, anyhow::Error> {
        let mut config: FsQuotaConfig =
            parse_typed(args).map_err(|e| FsError::InvalidQuotaConfig(e.to_string()))?;

        // 0 selects the default.
        if config.timeout_ms == 0 {
            config.timeout_ms = 5000;
        }

        Ok(config)
    }

    /// Validate quota configuration
    fn validate_quota_config(&self, config: &FsQuotaConfig) -> Result<(), anyhow::Error> {
        let invalid = |m: &str| -> anyhow::Error { FsError::InvalidQuotaConfig(m.into()).into() };
        if config.timeout_ms == 0 {
            return Err(invalid("timeout_ms must be greater than 0"));
        }
        if !config.include_space && !config.include_inodes {
            return Err(invalid(
                "Either include_space or include_inodes must be true",
            ));
        }
        if config.path.as_ref().is_some_and(|p| p.trim().is_empty()) {
            return Err(invalid("path cannot be empty"));
        }
        if config.subject.as_ref().is_some_and(|s| s.trim().is_empty()) {
            return Err(invalid("subject cannot be empty"));
        }
        if config.subject.as_ref().is_some_and(|s| s.starts_with('-')) {
            return Err(invalid("subject cannot start with '-'"));
        }
        if config.all_subjects && config.subject.is_some() {
            return Err(invalid("subject and all_subjects=true are contradictory"));
        }
        Ok(())
    }

    /// Execute the actual quota operation
    async fn execute_quota(&self, config: &FsQuotaConfig) -> Result<Value, anyhow::Error> {
        let target_path = config.path.as_deref().unwrap_or("/");
        let filesystem = self.resolve_filesystem(target_path).await?;

        let (subject_query, mut subjects) = if config.all_subjects {
            let kind = match config.subject_type {
                SubjectType::Auto => SubjectType::User,
                ref k => k.clone(),
            };
            if !tool_available("repquota") {
                return Err(FsError::QuotaUnsupported.into());
            }
            let rows = self
                .repquota(&kind, &filesystem.target)
                .await
                .map_err(|e| self.quota_error(e, &filesystem))?;
            let subjects: Vec<QuotaSubject> = rows
                .iter()
                .map(|(name, line)| {
                    let mut s = self.subject_from_report_name(name, &kind);
                    (s.space, s.inodes) = quota_entries(
                        line,
                        &config.units,
                        config.include_space,
                        config.include_inodes,
                    );
                    s
                })
                .collect();
            let query = QuotaSubjectQuery {
                subject: "*".to_string(),
                subject_type: subject_type_name(&kind).to_string(),
                resolved_uid: None,
                resolved_gid: None,
            };
            (query, subjects)
        } else {
            if !tool_available("quota") {
                return Err(FsError::QuotaUnsupported.into());
            }
            let mut subject = self.resolve_single_subject(
                config.subject.as_deref(),
                &config.subject_type,
                config.resolve_uid_gid,
            )?;
            let lines = self.quota_report(&subject).await?;
            let line = lines
                .iter()
                .find(|l| support::same_source(&filesystem.source, &l.filesystem))
                .ok_or_else(|| {
                    FsError::QuotaNotEnabled(format!(
                        "{} on {} ({})",
                        filesystem.source, filesystem.target, filesystem.fstype
                    ))
                })?;
            (subject.space, subject.inodes) = quota_entries(
                line,
                &config.units,
                config.include_space,
                config.include_inodes,
            );
            let query = QuotaSubjectQuery {
                subject: subject.subject.clone(),
                subject_type: subject.subject_type.clone(),
                resolved_uid: subject.uid,
                resolved_gid: subject.gid,
            };
            (query, vec![subject])
        };
        subjects.sort_by(|a, b| a.subject.cmp(&b.subject));

        let result = QuotaResult {
            backend: "fs".to_string(),
            verb: "quota".to_string(),
            alias: self.alias.clone(),
            path: target_path.to_string(),
            filesystem,
            subject_query,
            units: format!("{:?}", config.units).to_lowercase(),
            // `quota` lists a filesystem only when quota accounting is on
            // for it, and then reports both space and inodes.
            space_quota_enabled: true,
            inode_quota_enabled: true,
            subjects,
        };

        let mut value = serde_json::to_value(result)?;
        if !config.include_grace {
            strip_grace(&mut value);
        }
        Ok(value)
    }

    /// The mounted filesystem holding `path`.
    async fn resolve_filesystem(&self, path: &str) -> Result<QuotaFilesystem, anyhow::Error> {
        let abs = support::absolute(path);
        if !Path::new(&abs).exists() {
            return Err(FsError::PathNotFound(path.to_string()).into());
        }
        let resolved = fs::canonicalize(&abs)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or(abs);
        let table = self.read_mount_table().await.map_err(|e| match e {
            MountTableError::Missing => anyhow::Error::from(FsError::QuotaUnsupported),
            MountTableError::Unreadable(m) => FsError::QuotaFailed(m).into(),
        })?;
        let m = support::mount_for_path(&table, &resolved)
            .ok_or_else(|| FsError::QuotaFailed(format!("no mounted filesystem holds {path}")))?;
        Ok(QuotaFilesystem {
            source: m.source.clone(),
            target: m.target.clone(),
            fstype: m.fstype.clone(),
        })
    }

    /// Resolves the subject of a quota query. A numeric subject is always
    /// accepted as an id; a name must exist in the user, group or project
    /// database unless `resolve` is false, in which case it is passed to
    /// `quota` as given.
    fn resolve_single_subject(
        &self,
        subject: Option<&str>,
        subject_type: &SubjectType,
        resolve: bool,
    ) -> Result<QuotaSubject, anyhow::Error> {
        use nix::unistd::{Gid, Group, Uid, User};

        let name = match subject {
            Some(s) => s.to_string(),
            None => match User::from_uid(Uid::current()) {
                Ok(Some(u)) => u.name,
                _ => Uid::current().as_raw().to_string(),
            },
        };
        let numeric = name.parse::<u32>().ok();
        let not_found = || -> anyhow::Error { FsError::QuotaSubjectNotFound(name.clone()).into() };
        let make = |kind: &str, uid: Option<u32>, gid: Option<u32>| QuotaSubject {
            subject: name.clone(),
            subject_type: kind.to_string(),
            uid,
            gid,
            space: None,
            inodes: None,
        };
        let user = || -> Option<User> {
            match numeric {
                Some(id) => User::from_uid(Uid::from_raw(id)).ok().flatten(),
                None => User::from_name(&name).ok().flatten(),
            }
        };
        let group = || -> Option<Group> {
            match numeric {
                Some(id) => Group::from_gid(Gid::from_raw(id)).ok().flatten(),
                None => Group::from_name(&name).ok().flatten(),
            }
        };

        if !resolve {
            let kind = match subject_type {
                SubjectType::Auto | SubjectType::User => "user",
                SubjectType::Group => "group",
                SubjectType::Project => "project",
            };
            return Ok(match kind {
                "user" => make(kind, numeric, None),
                _ => make(kind, None, numeric),
            });
        }

        match subject_type {
            SubjectType::Auto => {
                if let Some(u) = user() {
                    Ok(make("user", Some(u.uid.as_raw()), Some(u.gid.as_raw())))
                } else if let Some(g) = group() {
                    Ok(make("group", None, Some(g.gid.as_raw())))
                } else if let Some(id) = numeric {
                    Ok(make("user", Some(id), None))
                } else {
                    Err(not_found())
                }
            }
            SubjectType::User => match (user(), numeric) {
                (Some(u), _) => Ok(make("user", Some(u.uid.as_raw()), Some(u.gid.as_raw()))),
                (None, Some(id)) => Ok(make("user", Some(id), None)),
                (None, None) => Err(not_found()),
            },
            SubjectType::Group => match (group(), numeric) {
                (Some(g), _) => Ok(make("group", None, Some(g.gid.as_raw()))),
                (None, Some(id)) => Ok(make("group", None, Some(id))),
                (None, None) => Err(not_found()),
            },
            SubjectType::Project => match numeric.or_else(|| project_id(&name)) {
                Some(id) => Ok(make("project", None, Some(id))),
                None => Err(not_found()),
            },
        }
    }

    /// A subject named in a `repquota` report (`#1001` for an id without a
    /// name).
    fn subject_from_report_name(&self, name: &str, kind: &SubjectType) -> QuotaSubject {
        use nix::unistd::{Group, User};
        let id = name.strip_prefix('#').and_then(|n| n.parse::<u32>().ok());
        let (uid, gid) = match kind {
            SubjectType::Group => (
                None,
                id.or_else(|| {
                    Group::from_name(name)
                        .ok()
                        .flatten()
                        .map(|g| g.gid.as_raw())
                }),
            ),
            SubjectType::Project => (None, id.or_else(|| project_id(name))),
            _ => match User::from_name(name).ok().flatten() {
                Some(u) => (Some(u.uid.as_raw()), Some(u.gid.as_raw())),
                None => (id, None),
            },
        };
        QuotaSubject {
            subject: name.to_string(),
            subject_type: subject_type_name(kind).to_string(),
            uid,
            gid,
            space: None,
            inodes: None,
        }
    }

    /// Runs `quota -v -w -p` for one subject and returns one line per
    /// filesystem with quotas on. `quota` exits 1 when a limit is exceeded,
    /// so its output, not its status, decides success.
    async fn quota_report(
        &self,
        subject: &QuotaSubject,
    ) -> Result<Vec<support::QuotaLine>, anyhow::Error> {
        let (flag, id) = match subject.subject_type.as_str() {
            "group" => ("-g", subject.gid),
            "project" => ("-P", subject.gid),
            _ => ("-u", subject.uid),
        };
        let who = id
            .map(|i| i.to_string())
            .unwrap_or_else(|| subject.subject.clone());
        let mut cmd = tool("quota");
        cmd.args(["-v", "-w", "-p", flag, "--"]).arg(&who);
        let output = match run(&mut cmd).await {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(FsError::QuotaUnsupported.into());
            }
            Err(e) => return Err(FsError::QuotaFailed(e.to_string()).into()),
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("quotas for") {
            return Ok(support::parse_quota_report(&stdout));
        }
        let msg = tool_message(&output);
        let lower = msg.to_ascii_lowercase();
        if lower.contains("no such")
            || lower.contains("doesn't exist")
            || lower.contains("does not exist")
            || lower.contains("unknown")
        {
            return Err(FsError::QuotaSubjectNotFound(subject.subject.clone()).into());
        }
        Err(FsError::QuotaFailed(format!("quota failed: {msg}")).into())
    }

    /// Runs `repquota -O csv -p` on one filesystem and returns every subject
    /// with its usage.
    async fn repquota(
        &self,
        kind: &SubjectType,
        mountpoint: &str,
    ) -> Result<Vec<(String, support::QuotaLine)>, RepquotaError> {
        let flag = match kind {
            SubjectType::Group => "-g",
            SubjectType::Project => "-P",
            _ => "-u",
        };
        let mut cmd = tool("repquota");
        cmd.args(["-O", "csv", "-p", flag, "--"]).arg(mountpoint);
        let output = match run(&mut cmd).await {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(RepquotaError::Unsupported);
            }
            Err(e) => return Err(RepquotaError::Failed(e.to_string())),
        };
        let msg = tool_message(&output);
        if !output.status.success() {
            if msg.contains("no quota enabled") || msg.contains("not using quota") {
                return Err(RepquotaError::NotEnabled);
            }
            return Err(RepquotaError::Failed(format!("repquota failed: {msg}")));
        }
        Ok(support::parse_repquota_csv(&String::from_utf8_lossy(
            &output.stdout,
        )))
    }

    fn quota_error(&self, e: RepquotaError, filesystem: &QuotaFilesystem) -> anyhow::Error {
        match e {
            RepquotaError::Unsupported => FsError::QuotaUnsupported.into(),
            RepquotaError::NotEnabled => FsError::QuotaNotEnabled(format!(
                "{} on {} ({})",
                filesystem.source, filesystem.target, filesystem.fstype
            ))
            .into(),
            RepquotaError::Failed(m) => FsError::QuotaFailed(m).into(),
        }
    }

    /// Main quota summary operation implementation
    pub async fn quota_summary(&self, args: Value) -> Result<Value, anyhow::Error> {
        let config = self.parse_quota_summary_config(args)?;
        self.validate_quota_summary_config(&config)?;

        let limit = crate::core::process::limit(Duration::from_millis(config.timeout_ms));
        timeout(limit, self.execute_quota_summary(&config))
            .await
            .map_err(|_| FsError::QuotaSummaryTimeout)?
    }

    /// Parse quota summary configuration from arguments
    pub fn parse_quota_summary_config(
        &self,
        args: Value,
    ) -> Result<FsQuotaSummaryConfig, anyhow::Error> {
        let mut config: FsQuotaSummaryConfig =
            parse_typed(args).map_err(|e| FsError::InvalidQuotaSummaryConfig(e.to_string()))?;

        // 0 selects the default.
        if config.timeout_ms == 0 {
            config.timeout_ms = 8000;
        }

        Ok(config)
    }

    /// Validate quota summary configuration
    pub fn validate_quota_summary_config(
        &self,
        config: &FsQuotaSummaryConfig,
    ) -> Result<(), anyhow::Error> {
        let invalid =
            |m: &str| -> anyhow::Error { FsError::InvalidQuotaSummaryConfig(m.into()).into() };
        if config.timeout_ms == 0 {
            return Err(invalid("timeout_ms must be greater than 0"));
        }
        if !config.include_space && !config.include_inodes {
            return Err(invalid(
                "Either include_space or include_inodes must be true",
            ));
        }
        if config.subject.as_ref().is_some_and(|s| s.trim().is_empty()) {
            return Err(invalid("subject cannot be empty"));
        }
        if config.subject.as_ref().is_some_and(|s| s.starts_with('-')) {
            return Err(invalid("subject cannot start with '-'"));
        }
        if config.all_subjects && config.subject.is_some() {
            return Err(invalid("subject and all_subjects=true are contradictory"));
        }
        support::check_filter_lists(&support::filter_pairs([
            &config.include_mountpoints,
            &config.exclude_mountpoints,
            &config.include_types,
            &config.exclude_types,
            &config.include_sources,
            &config.exclude_sources,
        ]))
        .map_err(FsError::InvalidQuotaSummaryConfig)?;
        Ok(())
    }

    /// Execute the actual quota summary operation
    async fn execute_quota_summary(
        &self,
        config: &FsQuotaSummaryConfig,
    ) -> Result<Value, anyhow::Error> {
        let all_filesystems = self.discover_filesystems().await?;
        let filtered_filesystems = self.apply_filesystem_filters(&all_filesystems, config);

        if filtered_filesystems.is_empty() {
            return Err(FsError::QuotaSummaryNoQuotaFilesystems(
                "no filesystem matched the filters".to_string(),
            )
            .into());
        }

        let result = if config.all_subjects {
            self.summary_all_subjects(&filtered_filesystems, config)
                .await?
        } else {
            self.summary_one_subject(&filtered_filesystems, config)
                .await?
        };

        let mut value = serde_json::to_value(result)?;
        if !config.include_grace {
            strip_grace(&mut value);
        }
        Ok(value)
    }

    async fn summary_one_subject(
        &self,
        filesystems: &[QuotaFilesystem],
        config: &FsQuotaSummaryConfig,
    ) -> Result<QuotaSummaryResult, anyhow::Error> {
        if !tool_available("quota") {
            return Err(FsError::QuotaSummaryUnsupported.into());
        }
        let subject = self.resolve_single_subject(
            config.subject.as_deref(),
            &config.subject_type,
            config.resolve_uid_gid,
        )?;
        let lines =
            self.quota_report(&subject)
                .await
                .map_err(|e| match e.downcast_ref::<FsError>() {
                    Some(FsError::QuotaUnsupported) => FsError::QuotaSummaryUnsupported.into(),
                    Some(FsError::QuotaFailed(m)) => FsError::QuotaSummaryFailed(m.clone()).into(),
                    _ => e,
                })?;

        let mut with = Vec::new();
        let mut without = Vec::new();
        for fs in filesystems {
            match lines
                .iter()
                .find(|l| support::same_source(&fs.source, &l.filesystem))
            {
                Some(line) => {
                    let (space, inodes) = quota_entries(
                        line,
                        &config.units,
                        config.include_space,
                        config.include_inodes,
                    );
                    with.push(QuotaSummaryFilesystem {
                        source: fs.source.clone(),
                        target: fs.target.clone(),
                        fstype: fs.fstype.clone(),
                        space_quota_enabled: true,
                        inode_quota_enabled: true,
                        space,
                        inodes,
                    });
                }
                None => without.push(FilesystemWithoutQuotas {
                    source: fs.source.clone(),
                    target: fs.target.clone(),
                    fstype: fs.fstype.clone(),
                }),
            }
        }

        if with.is_empty() {
            return Err(FsError::QuotaSummaryNoQuotaFilesystems(format!(
                "none of the {} selected filesystems has quotas enabled",
                filesystems.len()
            ))
            .into());
        }

        Ok(self.build_single_subject_summary_result(&subject, &with, &without, &[], config))
    }

    async fn summary_all_subjects(
        &self,
        filesystems: &[QuotaFilesystem],
        config: &FsQuotaSummaryConfig,
    ) -> Result<QuotaSummaryResult, anyhow::Error> {
        if !tool_available("repquota") {
            return Err(FsError::QuotaSummaryUnsupported.into());
        }
        let kind = match config.subject_type {
            SubjectType::Auto => SubjectType::User,
            ref k => k.clone(),
        };

        let mut with = Vec::new();
        let mut without = Vec::new();
        let mut failures = Vec::new();
        // Subjects in first-seen order, each with its per-filesystem usage.
        let mut per_subject: Vec<(QuotaSubject, Vec<QuotaSummaryFilesystem>)> = Vec::new();

        for fs in filesystems {
            match self.repquota(&kind, &fs.target).await {
                Ok(rows) => {
                    with.push(QuotaSummaryFilesystem {
                        source: fs.source.clone(),
                        target: fs.target.clone(),
                        fstype: fs.fstype.clone(),
                        space_quota_enabled: true,
                        inode_quota_enabled: true,
                        space: None,
                        inodes: None,
                    });
                    for (name, line) in rows {
                        let (space, inodes) = quota_entries(
                            &line,
                            &config.units,
                            config.include_space,
                            config.include_inodes,
                        );
                        let entry = QuotaSummaryFilesystem {
                            source: fs.source.clone(),
                            target: fs.target.clone(),
                            fstype: fs.fstype.clone(),
                            space_quota_enabled: true,
                            inode_quota_enabled: true,
                            space,
                            inodes,
                        };
                        match per_subject.iter_mut().find(|(s, _)| s.subject == name) {
                            Some((_, list)) => list.push(entry),
                            None => per_subject
                                .push((self.subject_from_report_name(&name, &kind), vec![entry])),
                        }
                    }
                }
                Err(RepquotaError::NotEnabled) => without.push(FilesystemWithoutQuotas {
                    source: fs.source.clone(),
                    target: fs.target.clone(),
                    fstype: fs.fstype.clone(),
                }),
                Err(RepquotaError::Unsupported) => {
                    return Err(FsError::QuotaSummaryUnsupported.into());
                }
                Err(RepquotaError::Failed(message)) => failures.push(PartialFailure {
                    source: fs.source.clone(),
                    target: fs.target.clone(),
                    fstype: fs.fstype.clone(),
                    error: PartialFailureError {
                        code: "fs.quota_failed".to_string(),
                        message,
                    },
                }),
            }
        }

        if with.is_empty() {
            if let Some(first) = failures.first() {
                return Err(FsError::QuotaSummaryFailed(format!(
                    "{}: {}",
                    first.target, first.error.message
                ))
                .into());
            }
            return Err(FsError::QuotaSummaryNoQuotaFilesystems(format!(
                "none of the {} selected filesystems has quotas enabled",
                filesystems.len()
            ))
            .into());
        }

        per_subject.sort_by(|a, b| a.0.subject.cmp(&b.0.subject));
        Ok(self.build_multi_subject_summary_result(
            &per_subject,
            &with,
            &without,
            &failures,
            config,
        ))
    }

    /// The mounted filesystems that can carry quotas: pseudo filesystems are
    /// left out, and a device mounted at several places counts once.
    async fn discover_filesystems(&self) -> Result<Vec<QuotaFilesystem>, anyhow::Error> {
        let table = self.read_mount_table().await.map_err(|e| match e {
            MountTableError::Missing => anyhow::Error::from(FsError::QuotaSummaryUnsupported),
            MountTableError::Unreadable(m) => FsError::QuotaSummaryFailed(m).into(),
        })?;
        let mut filesystems: Vec<QuotaFilesystem> = Vec::new();
        for m in table {
            if self.is_pseudo_filesystem(&m.fstype) {
                continue;
            }
            if filesystems.iter().any(|f| f.source == m.source) {
                continue;
            }
            filesystems.push(QuotaFilesystem {
                source: m.source,
                target: m.target,
                fstype: m.fstype,
            });
        }
        Ok(filesystems)
    }

    /// Apply filters to filesystem list. Mount point filters match whole
    /// path components.
    pub fn apply_filesystem_filters(
        &self,
        filesystems: &[QuotaFilesystem],
        config: &FsQuotaSummaryConfig,
    ) -> Vec<QuotaFilesystem> {
        apply_mount_filters(
            filesystems,
            &MountFilters {
                include_mountpoints: &config.include_mountpoints,
                exclude_mountpoints: &config.exclude_mountpoints,
                include_types: &config.include_types,
                exclude_types: &config.exclude_types,
                include_sources: &config.include_sources,
                exclude_sources: &config.exclude_sources,
            },
            |f| (&f.target, &f.fstype, &f.source),
        )
    }

    fn summary_filters(&self, config: &FsQuotaSummaryConfig) -> QuotaSummaryFilters {
        QuotaSummaryFilters {
            include_mountpoints: config.include_mountpoints.clone(),
            exclude_mountpoints: config.exclude_mountpoints.clone(),
            include_types: config.include_types.clone(),
            exclude_types: config.exclude_types.clone(),
            include_sources: config.include_sources.clone(),
            exclude_sources: config.exclude_sources.clone(),
        }
    }

    /// Build result for single subject summary
    fn build_single_subject_summary_result(
        &self,
        subject: &QuotaSubject,
        quota_filesystems: &[QuotaSummaryFilesystem],
        filesystems_without_quotas: &[FilesystemWithoutQuotas],
        partial_failures: &[PartialFailure],
        config: &FsQuotaSummaryConfig,
    ) -> QuotaSummaryResult {
        let (space_summary, inode_summary) = self.aggregate_quota_data(quota_filesystems, config);

        QuotaSummaryResult {
            backend: "fs".to_string(),
            verb: "quota_summary".to_string(),
            alias: self.alias.clone(),
            subject_query: Some(QuotaSubjectQuery {
                subject: subject.subject.clone(),
                subject_type: subject.subject_type.clone(),
                resolved_uid: subject.uid,
                resolved_gid: subject.gid,
            }),
            filters: self.summary_filters(config),
            units: format!("{:?}", config.units).to_lowercase(),
            include_space: config.include_space,
            include_inodes: config.include_inodes,
            summary: Some(QuotaSummaryData {
                space: space_summary,
                inodes: inode_summary,
            }),
            all_subjects: false,
            subjects: None,
            filesystems: quota_filesystems.to_vec(),
            filesystems_without_quotas: filesystems_without_quotas.to_vec(),
            partial_failures: partial_failures.to_vec(),
        }
    }

    /// Build result for multi-subject summary: one aggregate per subject,
    /// from that subject's usage on each filesystem.
    fn build_multi_subject_summary_result(
        &self,
        per_subject: &[(QuotaSubject, Vec<QuotaSummaryFilesystem>)],
        quota_filesystems: &[QuotaSummaryFilesystem],
        filesystems_without_quotas: &[FilesystemWithoutQuotas],
        partial_failures: &[PartialFailure],
        config: &FsQuotaSummaryConfig,
    ) -> QuotaSummaryResult {
        let subject_summaries = per_subject
            .iter()
            .map(|(subject, usage)| {
                self.aggregate_subject_quota_across_filesystems(subject, usage, config)
            })
            .collect();

        QuotaSummaryResult {
            backend: "fs".to_string(),
            verb: "quota_summary".to_string(),
            alias: self.alias.clone(),
            subject_query: None,
            filters: self.summary_filters(config),
            units: format!("{:?}", config.units).to_lowercase(),
            include_space: config.include_space,
            include_inodes: config.include_inodes,
            summary: None,
            all_subjects: true,
            subjects: Some(subject_summaries),
            filesystems: quota_filesystems.to_vec(),
            filesystems_without_quotas: filesystems_without_quotas.to_vec(),
            partial_failures: partial_failures.to_vec(),
        }
    }

    /// Aggregate quota data across all filesystems for a single subject
    pub fn aggregate_quota_data(
        &self,
        quota_filesystems: &[QuotaSummaryFilesystem],
        config: &FsQuotaSummaryConfig,
    ) -> (Option<SpaceQuotaSummary>, Option<InodeQuotaSummary>) {
        let space = if config.include_space {
            sum_quotas(
                quota_filesystems
                    .iter()
                    .filter(|f| f.space_quota_enabled)
                    .filter_map(|f| f.space.as_ref())
                    .map(|s| (s.used, s.soft_limit, s.hard_limit, s.grace_exceeded)),
            )
            .map(|t| SpaceQuotaSummary {
                used: t.used,
                soft_limit: t.soft,
                hard_limit: t.hard,
                used_percent_of_soft: t.used_percent_of_soft,
                any_grace_exceeded: t.any_grace_exceeded,
            })
        } else {
            None
        };
        let inodes = if config.include_inodes {
            sum_quotas(
                quota_filesystems
                    .iter()
                    .filter(|f| f.inode_quota_enabled)
                    .filter_map(|f| f.inodes.as_ref())
                    .map(|s| (s.used, s.soft_limit, s.hard_limit, s.grace_exceeded)),
            )
            .map(|t| InodeQuotaSummary {
                used: t.used,
                soft_limit: t.soft,
                hard_limit: t.hard,
                used_percent_of_soft: t.used_percent_of_soft,
                any_grace_exceeded: t.any_grace_exceeded,
            })
        } else {
            None
        };
        (space, inodes)
    }

    /// Aggregate quota data for a single subject across all filesystems
    fn aggregate_subject_quota_across_filesystems(
        &self,
        subject: &QuotaSubject,
        quota_filesystems: &[QuotaSummaryFilesystem],
        config: &FsQuotaSummaryConfig,
    ) -> SubjectSummary {
        let (space, inodes) = self.aggregate_quota_data(quota_filesystems, config);
        SubjectSummary {
            subject: subject.subject.clone(),
            subject_type: subject.subject_type.clone(),
            uid: subject.uid,
            gid: subject.gid,
            space,
            inodes,
        }
    }

    /// Main usage operation implementation
    pub async fn usage(&self, args: Value) -> Result<Value, anyhow::Error> {
        // Parse and validate configuration
        let config = self.parse_usage_config(args)?;
        self.validate_usage_config(&config)?;

        let limit = crate::core::process::limit(Duration::from_millis(config.timeout_ms));
        timeout(limit, self.execute_usage(&config))
            .await
            .map_err(|_| FsError::UsageTimeout)?
    }

    /// Parse usage configuration from arguments
    fn parse_usage_config(&self, args: Value) -> Result<FsUsageConfig, anyhow::Error> {
        let config: FsUsageConfig =
            parse_typed(args).map_err(|e| FsError::InvalidUsageConfig(e.to_string()))?;

        Ok(config)
    }

    /// Validate usage configuration
    fn validate_usage_config(&self, config: &FsUsageConfig) -> Result<(), anyhow::Error> {
        if config.timeout_ms == 0 {
            return Err(FsError::InvalidUsageConfig(
                "timeout_ms must be greater than 0".to_string(),
            )
            .into());
        }

        if let Some(min) = config.threshold_used_percent_min {
            if min < 0.0 || min > 100.0 {
                return Err(FsError::InvalidUsageConfig(
                    "threshold_used_percent_min must be between 0 and 100".to_string(),
                )
                .into());
            }
        }

        if let Some(max) = config.threshold_used_percent_max {
            if max < 0.0 || max > 100.0 {
                return Err(FsError::InvalidUsageConfig(
                    "threshold_used_percent_max must be between 0 and 100".to_string(),
                )
                .into());
            }
        }

        if let (Some(min), Some(max)) = (
            config.threshold_used_percent_min,
            config.threshold_used_percent_max,
        ) {
            if min > max {
                return Err(FsError::InvalidUsageConfig(
                    "threshold_used_percent_min cannot be greater than threshold_used_percent_max"
                        .to_string(),
                )
                .into());
            }
        }

        if config.mode == UsageMode::Paths && config.paths.is_empty() {
            return Err(FsError::InvalidUsageConfig(
                "paths cannot be empty when mode is 'paths'".to_string(),
            )
            .into());
        }

        if config.mode != UsageMode::Paths && !config.paths.is_empty() {
            return Err(FsError::InvalidUsageConfig(
                "paths is only used with mode=paths".to_string(),
            )
            .into());
        }

        support::check_filter_lists(&[("paths", &config.paths)])
            .and_then(|_| {
                support::check_filter_lists(&support::filter_pairs([
                    &config.include_mountpoints,
                    &config.exclude_mountpoints,
                    &config.include_types,
                    &config.exclude_types,
                    &config.include_sources,
                    &config.exclude_sources,
                ]))
            })
            .map_err(FsError::InvalidUsageConfig)?;

        Ok(())
    }

    /// Execute the actual usage operation
    async fn execute_usage(&self, config: &FsUsageConfig) -> Result<Value, anyhow::Error> {
        // 1. Read current mount table
        let raw_mounts = self.read_mount_table().await.map_err(|e| match e {
            MountTableError::Missing => anyhow::Error::from(FsError::UsageUnsupported),
            MountTableError::Unreadable(m) => FsError::UsageFailed(m).into(),
        })?;

        // 2. Select filesystems based on mode and paths
        let mut selected_mounts = if config.mode == UsageMode::Paths && !config.paths.is_empty() {
            self.resolve_paths_to_filesystems(&raw_mounts, &config.paths)
                .await?
        } else {
            raw_mounts
        };

        // 3. Apply filters
        selected_mounts = self.apply_usage_filters(&selected_mounts, config)?;

        // 4. The filters must leave something to report on. (The usage
        // thresholds below may then legitimately leave an empty list.)
        if selected_mounts.is_empty() {
            return Err(FsError::UsageNothingSelected.into());
        }

        // 5. Collect usage statistics for each filesystem
        // A mount whose statistics cannot be read (for example a stale
        // network mount or a mountpoint without permission) is skipped with a
        // warning instead of failing the whole call.
        let mut filesystem_usages = Vec::new();
        let mut warnings = Vec::new();
        for mount in selected_mounts {
            match self.get_filesystem_usage(&mount, config).await {
                Ok(usage) => filesystem_usages.push(usage),
                Err(_) => warnings.push(format!(
                    "skipped {}: usage statistics could not be read",
                    mount.target
                )),
            }
        }

        // 6. Apply threshold filters
        if let Some(min_threshold) = config.threshold_used_percent_min {
            filesystem_usages
                .retain(|fs| fs.used_percent.map_or(false, |pct| pct >= min_threshold));
        }

        if let Some(max_threshold) = config.threshold_used_percent_max {
            filesystem_usages.retain(|fs| fs.used_percent.map_or(true, |pct| pct <= max_threshold));
        }

        // 7. Sort filesystems deterministically
        filesystem_usages.sort_by(|a, b| {
            a.target
                .cmp(&b.target)
                .then_with(|| a.source.cmp(&b.source))
                .then_with(|| a.fstype.cmp(&b.fstype))
        });

        // 8. Compute aggregate if requested
        let aggregate = if config.mode == UsageMode::Aggregate {
            Some(self.compute_aggregate_usage(&filesystem_usages, config))
        } else {
            None
        };

        // 9. Build path to filesystem mapping if mode is paths
        let path_to_filesystem = if config.mode == UsageMode::Paths {
            Some(
                self.build_path_to_filesystem_mapping(&config.paths, &filesystem_usages)
                    .await?,
            )
        } else {
            None
        };

        // 10. Build result
        let result = UsageResult {
            backend: "fs".to_string(),
            verb: "usage".to_string(),
            alias: self.alias.clone(),
            mode: format!("{:?}", config.mode).to_lowercase(),
            units: format!("{:?}", config.units).to_lowercase(),
            include_inodes: config.include_inodes,
            filters: self.build_usage_filters(config),
            filesystems: filesystem_usages,
            aggregate,
            path_to_filesystem,
            warnings,
        };

        Ok(serde_json::to_value(result)?)
    }

    /// Resolve paths to their underlying filesystems
    async fn resolve_paths_to_filesystems(
        &self,
        mounts: &[RawMountInfo],
        paths: &[String],
    ) -> Result<Vec<RawMountInfo>, anyhow::Error> {
        let mut resolved_mounts = Vec::new();
        let mut seen_targets = std::collections::HashSet::new();

        for path in paths {
            let abs = support::absolute(path);
            if !Path::new(&abs).exists() {
                return Err(FsError::PathNotFound(path.clone()).into());
            }

            // Match on whole path components so /homex is not placed under /home.
            let resolved = fs::canonicalize(&abs)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or(abs);
            if let Some(mount) = support::mount_for_path(mounts, &resolved) {
                if seen_targets.insert(mount.target.clone()) {
                    resolved_mounts.push(mount.clone());
                }
            }
        }

        Ok(resolved_mounts)
    }

    /// Apply filters to mount list. Mount point filters match whole path
    /// components; `ro` is matched as a whole mount option.
    fn apply_usage_filters(
        &self,
        mounts: &[RawMountInfo],
        config: &FsUsageConfig,
    ) -> Result<Vec<RawMountInfo>, anyhow::Error> {
        let mut filtered = apply_mount_filters(
            mounts,
            &MountFilters {
                include_mountpoints: &config.include_mountpoints,
                exclude_mountpoints: &config.exclude_mountpoints,
                include_types: &config.include_types,
                exclude_types: &config.exclude_types,
                include_sources: &config.include_sources,
                exclude_sources: &config.exclude_sources,
            },
            |m| (&m.target, &m.fstype, &m.source),
        );
        if !config.include_readonly {
            filtered.retain(|mount| !support::has_option(&mount.options, "ro"));
        }
        Ok(filtered)
    }

    /// Get filesystem usage statistics
    async fn get_filesystem_usage(
        &self,
        mount: &RawMountInfo,
        config: &FsUsageConfig,
    ) -> Result<FilesystemUsage, anyhow::Error> {
        // Use the existing statvfs-based implementation
        let usage_info = self.get_statvfs_info(&mount.target).await.ok_or_else(|| {
            FsError::UsageFailed(format!("Failed to get usage info for {}", mount.target))
        })?;

        let inode_info = if config.include_inodes {
            self.get_inode_info(&mount.target)
                .await
                .map(|info| FilesystemInodes {
                    total: info.total,
                    used: info.used,
                    free: info.free,
                    used_percent: Some(info.used_percent),
                })
        } else {
            None
        };

        // Convert units if requested
        let (size, used, free) = self.convert_usage_units(
            usage_info.size_bytes,
            usage_info.used_bytes,
            usage_info.free_bytes,
            &config.units,
        );

        // Generate human readable strings if requested
        let (size_human, used_human, free_human) = if config.human_readable {
            (
                Some(self.format_human_readable(usage_info.size_bytes)),
                Some(self.format_human_readable(usage_info.used_bytes)),
                Some(self.format_human_readable(usage_info.free_bytes)),
            )
        } else {
            (None, None, None)
        };

        Ok(FilesystemUsage {
            source: mount.source.clone(),
            target: if config.normalize_paths {
                self.normalize_path(&mount.target)
            } else {
                mount.target.clone()
            },
            fstype: mount.fstype.clone(),
            read_only: support::has_option(&mount.options, "ro"),
            size,
            used,
            free,
            used_percent: Some(usage_info.used_percent),
            size_human,
            used_human,
            free_human,
            inodes: inode_info,
        })
    }

    /// Convert usage values according to specified units
    fn convert_usage_units(
        &self,
        size_bytes: u64,
        used_bytes: u64,
        free_bytes: u64,
        units: &UsageUnits,
    ) -> (u64, u64, u64) {
        match units {
            UsageUnits::Auto | UsageUnits::Bytes => (size_bytes, used_bytes, free_bytes),
            UsageUnits::Kilobytes => (size_bytes / 1024, used_bytes / 1024, free_bytes / 1024),
            UsageUnits::Megabytes => (
                size_bytes / (1024 * 1024),
                used_bytes / (1024 * 1024),
                free_bytes / (1024 * 1024),
            ),
            UsageUnits::Gigabytes => (
                size_bytes / (1024 * 1024 * 1024),
                used_bytes / (1024 * 1024 * 1024),
                free_bytes / (1024 * 1024 * 1024),
            ),
            UsageUnits::Blocks => {
                // Assume 512-byte blocks (traditional Unix block size)
                (size_bytes / 512, used_bytes / 512, free_bytes / 512)
            }
        }
    }

    /// Format bytes in human-readable format
    fn format_human_readable(&self, bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "K", "M", "G", "T", "P"];
        const THRESHOLD: u64 = 1024;

        if bytes < THRESHOLD {
            return format!("{}B", bytes);
        }

        let mut size = bytes as f64;
        let mut unit_index = 0;

        while size >= THRESHOLD as f64 && unit_index < UNITS.len() - 1 {
            size /= THRESHOLD as f64;
            unit_index += 1;
        }

        format!("{:.1}{}", size, UNITS[unit_index])
    }

    /// Compute aggregate usage across filesystems
    fn compute_aggregate_usage(
        &self,
        filesystems: &[FilesystemUsage],
        config: &FsUsageConfig,
    ) -> AggregateUsage {
        let total_size: u64 = filesystems.iter().map(|fs| fs.size).sum();
        let total_used: u64 = filesystems.iter().map(|fs| fs.used).sum();
        let total_free: u64 = filesystems.iter().map(|fs| fs.free).sum();

        let used_percent = if total_size > 0 {
            Some((total_used as f64 / total_size as f64) * 100.0)
        } else {
            None
        };

        let (size_human, used_human, free_human) = if config.human_readable {
            // Convert back to bytes for human readable formatting
            let (size_bytes, used_bytes, free_bytes) = match config.units {
                UsageUnits::Auto | UsageUnits::Bytes => (total_size, total_used, total_free),
                UsageUnits::Kilobytes => (total_size * 1024, total_used * 1024, total_free * 1024),
                UsageUnits::Megabytes => (
                    total_size * 1024 * 1024,
                    total_used * 1024 * 1024,
                    total_free * 1024 * 1024,
                ),
                UsageUnits::Gigabytes => (
                    total_size * 1024 * 1024 * 1024,
                    total_used * 1024 * 1024 * 1024,
                    total_free * 1024 * 1024 * 1024,
                ),
                UsageUnits::Blocks => (total_size * 512, total_used * 512, total_free * 512),
            };
            (
                Some(self.format_human_readable(size_bytes)),
                Some(self.format_human_readable(used_bytes)),
                Some(self.format_human_readable(free_bytes)),
            )
        } else {
            (None, None, None)
        };

        // Aggregate inode information if available
        let inodes = if config.include_inodes {
            let total_inodes: u64 = filesystems
                .iter()
                .filter_map(|fs| fs.inodes.as_ref())
                .map(|inodes| inodes.total)
                .sum();
            let used_inodes: u64 = filesystems
                .iter()
                .filter_map(|fs| fs.inodes.as_ref())
                .map(|inodes| inodes.used)
                .sum();
            let free_inodes: u64 = filesystems
                .iter()
                .filter_map(|fs| fs.inodes.as_ref())
                .map(|inodes| inodes.free)
                .sum();

            if total_inodes > 0 {
                Some(FilesystemInodes {
                    total: total_inodes,
                    used: used_inodes,
                    free: free_inodes,
                    used_percent: Some((used_inodes as f64 / total_inodes as f64) * 100.0),
                })
            } else {
                None
            }
        } else {
            None
        };

        AggregateUsage {
            size: total_size,
            used: total_used,
            free: total_free,
            used_percent,
            size_human,
            used_human,
            free_human,
            inodes,
        }
    }

    /// Build path to filesystem mapping
    async fn build_path_to_filesystem_mapping(
        &self,
        paths: &[String],
        filesystems: &[FilesystemUsage],
    ) -> Result<Vec<PathToFilesystem>, anyhow::Error> {
        let mut mapping = Vec::new();

        for path in paths {
            // Find the filesystem that contains this path
            let mut best_match: Option<&FilesystemUsage> = None;
            let mut best_match_len = 0;

            let abs = support::absolute(path);
            let resolved = fs::canonicalize(&abs).unwrap_or_else(|_| Path::new(&abs).to_path_buf());
            for usage in filesystems {
                if resolved.starts_with(&usage.target) && usage.target.len() >= best_match_len {
                    best_match = Some(usage);
                    best_match_len = usage.target.len();
                }
            }

            if let Some(fs) = best_match {
                mapping.push(PathToFilesystem {
                    path: path.clone(),
                    target: fs.target.clone(),
                    source: fs.source.clone(),
                });
            }
        }

        Ok(mapping)
    }

    /// Build usage filters for result
    fn build_usage_filters(&self, config: &FsUsageConfig) -> UsageFilters {
        UsageFilters {
            include_mountpoints: config.include_mountpoints.clone(),
            exclude_mountpoints: config.exclude_mountpoints.clone(),
            include_types: config.include_types.clone(),
            exclude_types: config.exclude_types.clone(),
            include_sources: config.include_sources.clone(),
            exclude_sources: config.exclude_sources.clone(),
            threshold_used_percent_min: config.threshold_used_percent_min,
            threshold_used_percent_max: config.threshold_used_percent_max,
        }
    }

    /// Main resize operation implementation
    pub async fn resize(&self, args: Value) -> Result<Value, anyhow::Error> {
        let config = self.parse_resize_config(args)?;
        self.validate_resize_config(&config)?;

        let limit = crate::core::process::limit(Duration::from_millis(config.timeout_ms));
        timeout(limit, self.execute_resize(&config))
            .await
            .map_err(|_| FsError::ResizeTimeout)?
    }

    /// Parse resize configuration from input arguments
    fn parse_resize_config(&self, args: Value) -> Result<FsResizeConfig, anyhow::Error> {
        if args.is_null() {
            return Ok(FsResizeConfig::default());
        }
        parse_typed(args).map_err(|e| FsError::InvalidResizeConfig(e.to_string()).into())
    }

    /// Validate resize configuration
    fn validate_resize_config(&self, config: &FsResizeConfig) -> Result<(), anyhow::Error> {
        let invalid = |m: &str| -> anyhow::Error { FsError::InvalidResizeConfig(m.into()).into() };
        if config.target.trim().is_empty() {
            return Err(invalid("target is required and cannot be empty"));
        }
        if config.target.starts_with('-') {
            return Err(invalid("target cannot start with '-'"));
        }
        if config.timeout_ms == 0 {
            return Err(invalid("timeout_ms must be greater than 0"));
        }

        match (&config.size, &config.delta) {
            (None, None) => {
                return Err(invalid(
                    "exactly one of 'size' or 'delta' must be specified",
                ));
            }
            (Some(_), Some(_)) => return Err(invalid("cannot specify both 'size' and 'delta'")),
            _ => {}
        }
        // Both must parse before anything is looked at.
        if let Some(size) = &config.size {
            let bytes = self.parse_size(size, &config.size_units)?;
            if bytes <= 0 {
                return Err(FsError::ResizeInvalidTargetSize(
                    "size must be greater than 0".to_string(),
                )
                .into());
            }
        }
        if let Some(delta) = &config.delta {
            if self.parse_size(delta, &config.size_units)? == 0 {
                return Err(
                    FsError::ResizeInvalidTargetSize("delta must not be 0".to_string()).into(),
                );
            }
        }

        if !(0.0..=100.0).contains(&config.min_free_space_percent) {
            return Err(invalid("min_free_space_percent must be between 0 and 100"));
        }
        if config.volume_resize_only && config.filesystem_resize_only {
            return Err(invalid(
                "volume_resize_only and filesystem_resize_only are mutually exclusive",
            ));
        }
        if config.volume_resize_only && !config.manage_underlying_volume {
            return Err(invalid(
                "volume_resize_only needs manage_underlying_volume=true",
            ));
        }
        if config.mode == ResizeMode::Shrink && !config.allow_shrink {
            return Err(FsError::ResizeShrinkNotAllowed.into());
        }

        Ok(())
    }

    /// Execute the resize operation. Every check (target, type, sizes,
    /// policies, volume manager) is done before the first tool that changes
    /// anything runs.
    async fn execute_resize(&self, config: &FsResizeConfig) -> Result<Value, anyhow::Error> {
        let fs_info = self.discover_filesystem(config).await?;

        let current_size = fs_info.current_size_bytes;
        let target_size = self.compute_target_size(config, current_size)?;
        let delta_bytes = target_size as i64 - current_size as i64;

        if delta_bytes == 0 {
            return Ok(json!(ResizeResult {
                backend: "fs".to_string(),
                verb: "resize".to_string(),
                alias: Some(self.alias.clone()),
                target: config.target.clone(),
                by: format!("{:?}", config.by).to_lowercase(),
                filesystem: ResizeFilesystemInfo {
                    source: fs_info.source.clone(),
                    fstype: fs_info.fstype.clone(),
                    mounted: fs_info.mounted,
                    current_size_bytes: current_size,
                    requested_size_bytes: Some(target_size),
                    delta_bytes: Some(0),
                },
                requested_size_bytes: Some(target_size),
                previous_size_bytes: Some(current_size),
                final_size_bytes: Some(current_size),
                delta_bytes: Some(0),
                mode: format!("{:?}", config.mode).to_lowercase(),
                action: "noop".to_string(),
                reason: Some("requested size equals current filesystem size".to_string()),
                actions: None,
                summary: None,
                dry_run: Some(config.dry_run),
                plan: None,
            }));
        }

        let is_shrink = delta_bytes < 0;
        if is_shrink {
            if config.mode == ResizeMode::Grow {
                return Err(FsError::InvalidResizeConfig(
                    "the requested size is smaller than the filesystem; shrinking needs \
                     mode=shrink or mode=auto"
                        .to_string(),
                )
                .into());
            }
            if !config.allow_shrink {
                return Err(FsError::ResizeShrinkNotAllowed.into());
            }
            if config.volume_resize_only {
                return Err(FsError::InvalidResizeConfig(
                    "shrinking only the volume would cut off the end of the filesystem".to_string(),
                )
                .into());
            }
            match fs_info.fstype.as_str() {
                "xfs" => {
                    return Err(FsError::ResizeShrinkNotSupportedForFilesystem(
                        fs_info.fstype.clone(),
                    )
                    .into());
                }
                "ext3" | "ext4" if config.require_unmounted_for_shrink && fs_info.mounted => {
                    return Err(FsError::ResizeShrinkRequiresUnmount(config.target.clone()).into());
                }
                _ => {}
            }
            self.validate_min_free_space(&fs_info, target_size, config.min_free_space_percent)
                .await?;
        } else if config.mode == ResizeMode::Shrink {
            return Err(FsError::InvalidResizeConfig(
                "the requested size is larger than the filesystem; growing needs mode=grow \
                 or mode=auto"
                    .to_string(),
            )
            .into());
        }

        if config.manage_underlying_volume && !config.filesystem_resize_only {
            if !self.is_lvm_device(&fs_info.source).await {
                return Err(FsError::ResizeVolumeManagementUnsupported.into());
            }
        } else if !is_shrink {
            let device_size = self.get_device_size(&fs_info.source).await?;
            if target_size > device_size {
                return Err(FsError::ResizeTargetExceedsDevice.into());
            }
        }

        let steps = self.resize_steps(config, &fs_info, target_size, is_shrink)?;

        if config.dry_run {
            let planned = steps
                .iter()
                .map(|(kind, argv)| ResizeAction {
                    r#type: kind.to_string(),
                    tool: argv[0].clone(),
                    status: "planned".to_string(),
                    command: argv.join(" "),
                })
                .collect();
            return Ok(json!(ResizeResult {
                backend: "fs".to_string(),
                verb: "resize".to_string(),
                alias: Some(self.alias.clone()),
                target: config.target.clone(),
                by: format!("{:?}", config.by).to_lowercase(),
                filesystem: ResizeFilesystemInfo {
                    source: fs_info.source.clone(),
                    fstype: fs_info.fstype.clone(),
                    mounted: fs_info.mounted,
                    current_size_bytes: current_size,
                    requested_size_bytes: Some(target_size),
                    delta_bytes: Some(delta_bytes),
                },
                requested_size_bytes: Some(target_size),
                previous_size_bytes: Some(current_size),
                final_size_bytes: Some(target_size),
                delta_bytes: Some(delta_bytes),
                mode: format!("{:?}", config.mode).to_lowercase(),
                action: "plan".to_string(),
                reason: None,
                actions: None,
                summary: None,
                dry_run: Some(true),
                plan: Some(ResizePlan { steps: planned }),
            }));
        }

        let mut actions: Vec<ResizeAction> = Vec::new();
        for (kind, argv) in &steps {
            let mut cmd = tool(&argv[0]);
            cmd.args(&argv[1..]);
            let command = argv.join(" ");
            let failed = |msg: String, actions: &[ResizeAction]| -> anyhow::Error {
                if actions.is_empty() {
                    FsError::ResizeFailed(msg).into()
                } else {
                    FsError::ResizeFailed(format!(
                        "{msg}; already done: {}",
                        actions
                            .iter()
                            .map(|a| a.command.as_str())
                            .collect::<Vec<_>>()
                            .join("; ")
                    ))
                    .into()
                }
            };
            let output = match run(&mut cmd).await {
                Ok(o) => o,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(failed(format!("{} is not installed", argv[0]), &actions));
                }
                Err(e) => return Err(failed(format!("{command}: {e}"), &actions)),
            };
            if !output.status.success() {
                return Err(failed(
                    format!("{command} failed: {}", tool_message(&output)),
                    &actions,
                ));
            }
            actions.push(ResizeAction {
                r#type: kind.to_string(),
                tool: argv[0].clone(),
                status: "success".to_string(),
                command,
            });
        }

        let final_size = if config.volume_resize_only {
            current_size
        } else {
            self.filesystem_size(
                &fs_info.fstype,
                &fs_info.source,
                fs_info.mountpoint.as_deref(),
            )
            .await
            .unwrap_or(target_size)
        };

        Ok(json!(ResizeResult {
            backend: "fs".to_string(),
            verb: "resize".to_string(),
            alias: Some(self.alias.clone()),
            target: config.target.clone(),
            by: format!("{:?}", config.by).to_lowercase(),
            filesystem: ResizeFilesystemInfo {
                source: fs_info.source.clone(),
                fstype: fs_info.fstype.clone(),
                mounted: fs_info.mounted,
                current_size_bytes: current_size,
                requested_size_bytes: Some(target_size),
                delta_bytes: Some(delta_bytes),
            },
            requested_size_bytes: Some(target_size),
            previous_size_bytes: Some(current_size),
            final_size_bytes: Some(final_size),
            delta_bytes: Some(delta_bytes),
            mode: format!("{:?}", config.mode).to_lowercase(),
            action: "success".to_string(),
            reason: None,
            actions: Some(actions),
            summary: Some(ResizeSummary {
                status: "success".to_string(),
                shrink: is_shrink,
                grew: !is_shrink,
            }),
            dry_run: Some(false),
            plan: None,
        }))
    }

    /// The commands that resize the volume and the filesystem, in order:
    /// a growing volume before the filesystem, a shrinking one after it.
    fn resize_steps(
        &self,
        config: &FsResizeConfig,
        fs_info: &DiscoveredFilesystem,
        target_size: u64,
        is_shrink: bool,
    ) -> Result<Vec<(&'static str, Vec<String>)>, anyhow::Error> {
        let volume = config.manage_underlying_volume && !config.filesystem_resize_only;
        let filesystem = !config.volume_resize_only;
        let mut steps = Vec::new();
        let lv = |shrink: bool| -> (&'static str, Vec<String>) {
            let mut argv = vec![
                if shrink { "lvreduce" } else { "lvextend" }.to_string(),
                "-L".to_string(),
                format!("{target_size}b"),
            ];
            if shrink {
                argv.push("-f".to_string());
            }
            argv.push("--".to_string());
            argv.push(fs_info.source.clone());
            ("volume_resize", argv)
        };

        if volume && !is_shrink {
            steps.push(lv(false));
        }
        if filesystem {
            let mountpoint = || -> Result<String, anyhow::Error> {
                fs_info.mountpoint.clone().ok_or_else(|| {
                    FsError::ResizeUnsupportedFilesystem(format!(
                        "{} can only be resized while mounted",
                        fs_info.fstype
                    ))
                    .into()
                })
            };
            let argv = match fs_info.fstype.as_str() {
                "ext3" | "ext4" => {
                    let mut argv = vec!["resize2fs".to_string()];
                    if config.force {
                        argv.push("-f".to_string());
                    }
                    argv.push(fs_info.source.clone());
                    argv.push(resize2fs_size_arg(target_size));
                    argv
                }
                "xfs" => {
                    let block = fs_info.block_size.max(1);
                    vec![
                        "xfs_growfs".to_string(),
                        "-D".to_string(),
                        (target_size / block).to_string(),
                        mountpoint()?,
                    ]
                }
                "btrfs" => vec![
                    "btrfs".to_string(),
                    "filesystem".to_string(),
                    "resize".to_string(),
                    format!("{}:{}", fs_info.btrfs_devid.unwrap_or(1), target_size),
                    mountpoint()?,
                ],
                other => return Err(FsError::ResizeUnsupportedFilesystem(other.into()).into()),
            };
            steps.push(("filesystem_resize", argv));
        }
        if volume && is_shrink {
            steps.push(lv(true));
        }
        Ok(steps)
    }

    /// Discover filesystem information based on target and method
    async fn discover_filesystem(
        &self,
        config: &FsResizeConfig,
    ) -> Result<DiscoveredFilesystem, anyhow::Error> {
        let (target, by) = (config.target.as_str(), &config.by);
        let mounts = self.get_existing_mounts().await?;
        let as_mountpoint = support::absolute(target);
        let mounted_at = mounts.iter().rev().find(|m| m.target == as_mountpoint);

        let (source, mountpoint, fstype) = match (by, mounted_at) {
            (ResizeTargetKind::Auto | ResizeTargetKind::Mountpoint, Some(m)) => {
                (m.source.clone(), Some(m.target.clone()), m.fs_type.clone())
            }
            (ResizeTargetKind::Mountpoint, None) => {
                return Err(FsError::ResizeTargetNotFound(format!(
                    "no filesystem is mounted at {target}"
                ))
                .into());
            }
            _ => {
                let meta = fs::metadata(target).map_err(|_| {
                    FsError::ResizeTargetNotFound(format!("no such device: {target}"))
                })?;
                if meta.is_dir() {
                    return Err(FsError::ResizeTargetNotFound(format!(
                        "{target} is a directory but not a mount point"
                    ))
                    .into());
                }
                match mounts
                    .iter()
                    .rev()
                    .find(|m| support::same_source(&m.source, target))
                {
                    Some(m) => (m.source.clone(), Some(m.target.clone()), m.fs_type.clone()),
                    None => (
                        target.to_string(),
                        None,
                        self.detect_filesystem_type(target).await?,
                    ),
                }
            }
        };

        let mut info = DiscoveredFilesystem {
            mounted: mountpoint.is_some(),
            source,
            mountpoint,
            fstype,
            current_size_bytes: 0,
            block_size: 4096,
            btrfs_devid: None,
        };
        self.validate_filesystem_support(&info, config)?;
        let (size, block, devid) = self
            .filesystem_geometry(&info.fstype, &info.source, info.mountpoint.as_deref())
            .await?;
        info.current_size_bytes = size;
        info.block_size = block;
        info.btrfs_devid = devid;
        Ok(info)
    }

    /// Detect the filesystem type of an unmounted device with `blkid`.
    async fn detect_filesystem_type(&self, device: &str) -> Result<String, anyhow::Error> {
        let mut cmd = tool("blkid");
        cmd.args(["-p", "-s", "TYPE", "-o", "value", "--"])
            .arg(device);
        match run(&mut cmd).await {
            Ok(output) => {
                let fstype = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if output.status.success() && !fstype.is_empty() {
                    Ok(fstype)
                } else {
                    Err(FsError::ResizeUnsupportedFilesystem(format!(
                        "no filesystem found on {device}"
                    ))
                    .into())
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(FsError::ResizeFailed("blkid is not installed".to_string()).into())
            }
            Err(e) => Err(FsError::ResizeFailed(e.to_string()).into()),
        }
    }

    /// Validate filesystem type and options before anything runs
    fn validate_filesystem_support(
        &self,
        fs_info: &DiscoveredFilesystem,
        config: &FsResizeConfig,
    ) -> Result<(), anyhow::Error> {
        match fs_info.fstype.as_str() {
            "ext3" | "ext4" => Ok(()),
            "xfs" | "btrfs" => {
                if config.force {
                    return Err(FsError::InvalidResizeConfig(format!(
                        "force applies to ext3/ext4 only, not {}",
                        fs_info.fstype
                    ))
                    .into());
                }
                if !fs_info.mounted && !config.volume_resize_only {
                    return Err(FsError::ResizeUnsupportedFilesystem(format!(
                        "{} can only be resized while mounted",
                        fs_info.fstype
                    ))
                    .into());
                }
                Ok(())
            }
            other => Err(FsError::ResizeUnsupportedFilesystem(other.to_string()).into()),
        }
    }

    /// Parses a size or delta in bytes. A bare number is a count of
    /// `size_units`; `K`, `M`, `G` and `T` suffixes are powers of 1024.
    fn parse_size(&self, size_value: &Value, units: &SizeUnits) -> Result<i128, anyhow::Error> {
        let unit: u64 = match units {
            SizeUnits::Auto | SizeUnits::Bytes => 1,
            SizeUnits::Kilobytes => 1 << 10,
            SizeUnits::Megabytes => 1 << 20,
            SizeUnits::Gigabytes => 1 << 30,
            SizeUnits::Terabytes => 1 << 40,
        };
        let text = match size_value {
            Value::Number(n) => n.to_string(),
            Value::String(s) => s.clone(),
            _ => {
                return Err(FsError::InvalidResizeConfig(
                    "size must be a number or string".to_string(),
                )
                .into());
            }
        };
        support::parse_signed_size(&text, unit).map_err(|e| FsError::InvalidResizeConfig(e).into())
    }

    /// Compute target size from configuration
    fn compute_target_size(
        &self,
        config: &FsResizeConfig,
        current_size: u64,
    ) -> Result<u64, anyhow::Error> {
        let target: i128 = if let Some(size_value) = &config.size {
            let size = self.parse_size(size_value, &config.size_units)?;
            if size < 0 {
                return Err(FsError::InvalidResizeConfig(
                    "size cannot be negative; use delta=-<size> to shrink by an amount".to_string(),
                )
                .into());
            }
            size
        } else if let Some(delta_value) = &config.delta {
            current_size as i128 + self.parse_size(delta_value, &config.size_units)?
        } else {
            return Err(FsError::InvalidResizeConfig(
                "either size or delta must be specified".to_string(),
            )
            .into());
        };
        if target <= 0 {
            return Err(FsError::ResizeInvalidTargetSize(format!(
                "the resulting size would be {target} bytes"
            ))
            .into());
        }
        u64::try_from(target)
            .map_err(|_| FsError::ResizeInvalidTargetSize("size is too large".into()).into())
    }

    /// The filesystem's own size in bytes (not what `df` reports, which
    /// leaves out metadata), its block size, and for btrfs the device id.
    async fn filesystem_geometry(
        &self,
        fstype: &str,
        source: &str,
        mountpoint: Option<&str>,
    ) -> Result<(u64, u64, Option<u64>), anyhow::Error> {
        let query = |argv: Vec<String>| async move {
            let mut cmd = tool(&argv[0]);
            cmd.args(&argv[1..]);
            let output = match run(&mut cmd).await {
                Ok(o) => o,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(anyhow::Error::from(FsError::ResizeFailed(format!(
                        "{} is not installed",
                        argv[0]
                    ))));
                }
                Err(e) => return Err(FsError::ResizeFailed(e.to_string()).into()),
            };
            if !output.status.success() {
                return Err(FsError::ResizeFailed(format!(
                    "{} failed: {}",
                    argv.join(" "),
                    tool_message(&output)
                ))
                .into());
            }
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        };
        let unreadable = |what: &str| -> anyhow::Error {
            FsError::ResizeFailed(format!("cannot read the size of {what}")).into()
        };
        match fstype {
            "ext3" | "ext4" => {
                let text = query(vec!["dumpe2fs".into(), "-h".into(), source.to_string()]).await?;
                let count = support::colon_field(&text, "Block count");
                let block = support::colon_field(&text, "Block size");
                match (count, block) {
                    (Some(c), Some(b)) => Ok((c * b, b, None)),
                    _ => Err(unreadable(source)),
                }
            }
            "xfs" => {
                let at = mountpoint.unwrap_or(source).to_string();
                let text = query(vec!["xfs_info".into(), at.clone()]).await?;
                let (bsize, blocks) =
                    support::xfs_data_geometry(&text).ok_or_else(|| unreadable(&at))?;
                Ok((bsize * blocks, bsize, None))
            }
            "btrfs" => {
                // The superblock of the device itself: `btrfs filesystem
                // show` goes through the blkid cache, which can still name
                // an earlier filesystem on a reused (loop) device.
                let text = query(vec![
                    "btrfs".into(),
                    "inspect-internal".into(),
                    "dump-super".into(),
                    "--".into(),
                    source.to_string(),
                ])
                .await?;
                let (devid, size, sector) =
                    support::btrfs_super_geometry(&text).ok_or_else(|| unreadable(source))?;
                Ok((size, sector, Some(devid)))
            }
            other => Err(FsError::ResizeUnsupportedFilesystem(other.to_string()).into()),
        }
    }

    /// The filesystem's size in bytes, as `filesystem_geometry` reads it.
    async fn filesystem_size(
        &self,
        fstype: &str,
        source: &str,
        mountpoint: Option<&str>,
    ) -> Result<u64, anyhow::Error> {
        Ok(self
            .filesystem_geometry(fstype, source, mountpoint)
            .await?
            .0)
    }

    /// Size of a block device (`blockdev --getsize64`) or image file.
    async fn get_device_size(&self, device: &str) -> Result<u64, anyhow::Error> {
        if let Ok(meta) = fs::metadata(device) {
            if meta.is_file() {
                return Ok(meta.len());
            }
        }
        let mut cmd = tool("blockdev");
        cmd.arg("--getsize64").arg(device);
        let output = run(&mut cmd)
            .await
            .map_err(|e| FsError::ResizeFailed(format!("blockdev: {e}")))?;
        if !output.status.success() {
            return Err(FsError::ResizeFailed(format!(
                "cannot read the size of {device}: {}",
                tool_message(&output)
            ))
            .into());
        }
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u64>()
            .map_err(|_| FsError::ResizeFailed("cannot parse device size".to_string()).into())
    }

    /// Bytes in use on the filesystem: `df` when mounted, the superblock
    /// counters for an unmounted ext filesystem.
    async fn used_bytes(&self, fs_info: &DiscoveredFilesystem) -> Result<u64, anyhow::Error> {
        if let Some(mp) = &fs_info.mountpoint {
            return self
                .get_statvfs_info(mp)
                .await
                .map(|u| u.used_bytes)
                .ok_or_else(|| {
                    FsError::ResizeFailed(format!("cannot read the space used on {mp}")).into()
                });
        }
        let mut cmd = tool("dumpe2fs");
        cmd.arg("-h").arg(&fs_info.source);
        let output = run(&mut cmd)
            .await
            .map_err(|e| FsError::ResizeFailed(format!("dumpe2fs: {e}")))?;
        let text = String::from_utf8_lossy(&output.stdout);
        match (
            support::colon_field(&text, "Block count"),
            support::colon_field(&text, "Free blocks"),
            support::colon_field(&text, "Block size"),
        ) {
            (Some(count), Some(free), Some(bs)) if output.status.success() => {
                Ok(count.saturating_sub(free) * bs)
            }
            _ => Err(FsError::ResizeFailed(format!(
                "cannot read the space used on {}",
                fs_info.source
            ))
            .into()),
        }
    }

    /// Refuses a shrink that would leave less than `min_free_percent` of
    /// the new size free. When usage cannot be read the shrink is refused.
    async fn validate_min_free_space(
        &self,
        fs_info: &DiscoveredFilesystem,
        target_size: u64,
        min_free_percent: f64,
    ) -> Result<(), anyhow::Error> {
        let used_bytes = self.used_bytes(fs_info).await?;
        let required_free_bytes = (min_free_percent / 100.0) * target_size as f64;
        let would_be_free = target_size as f64 - used_bytes as f64;
        if would_be_free < required_free_bytes {
            return Err(FsError::ResizeWouldViolateMinFree.into());
        }
        Ok(())
    }

    /// True when `lsblk` reports the device as an LVM logical volume.
    async fn is_lvm_device(&self, device: &str) -> bool {
        let mut cmd = tool("lsblk");
        cmd.args(["-dno", "TYPE", "--"]).arg(device);
        match run(&mut cmd).await {
            Ok(output) if output.status.success() => {
                String::from_utf8_lossy(&output.stdout).trim() == "lvm"
            }
            _ => false,
        }
    }

    /// Main check operation implementation
    pub async fn check(&self, args: Value) -> Result<Value, anyhow::Error> {
        let config = self.parse_check_config(args)?;
        self.validate_check_config(&config)?;

        let limit = crate::core::process::limit(Duration::from_millis(config.timeout_ms));
        timeout(limit, self.execute_check(&config))
            .await
            .map_err(|_| FsError::CheckTimeout)?
    }

    /// Parse check configuration from input arguments
    fn parse_check_config(&self, args: Value) -> Result<FsCheckConfig, anyhow::Error> {
        let config: FsCheckConfig =
            parse_typed(args).map_err(|e| FsError::InvalidCheckConfig(e.to_string()))?;

        if config.target.trim().is_empty() {
            return Err(FsError::InvalidCheckConfig("target cannot be empty".to_string()).into());
        }

        Ok(config)
    }

    /// Validate check configuration
    fn validate_check_config(&self, config: &FsCheckConfig) -> Result<(), anyhow::Error> {
        let invalid = |m: &str| -> anyhow::Error { FsError::InvalidCheckConfig(m.into()).into() };
        if config.target.trim().is_empty() {
            return Err(invalid("target cannot be empty"));
        }
        if config.target.starts_with('-') {
            return Err(invalid("target cannot start with '-'"));
        }
        if config.timeout_ms == 0 {
            return Err(invalid("timeout_ms must be greater than 0"));
        }
        if let Some(t) = &config.filesystem_type {
            if !CHECK_FILESYSTEMS.contains(&t.as_str()) {
                return Err(FsError::InvalidCheckConfig(format!(
                    "filesystem_type {t:?} is not supported (supported: {})",
                    CHECK_FILESYSTEMS.join(", ")
                ))
                .into());
            }
        }
        if config.mode == CheckMode::Repair && !config.allow_repair {
            return Err(FsError::CheckRepairNotAllowed.into());
        }
        Ok(())
    }

    /// Execute the check operation
    async fn execute_check(&self, config: &FsCheckConfig) -> Result<Value, anyhow::Error> {
        let fs_info = self.resolve_check_target(config).await?;

        if let Some(skip_result) = self.apply_check_skip_policies(config, &fs_info)? {
            return Ok(serde_json::to_value(skip_result)?);
        }

        self.validate_check_filesystem_support(&fs_info.info.fstype)?;
        let repair = self.enforce_check_policies(config, &fs_info)?;
        let (tool_name, args_vec) = self.select_check_tool(config, &fs_info, repair)?;

        if config.dry_run {
            return Ok(serde_json::to_value(CheckResult {
                backend: "fs".to_string(),
                verb: "check".to_string(),
                alias: Some(self.alias.clone()),
                target: config.target.clone(),
                by: format!("{:?}", config.by).to_lowercase(),
                filesystem: Some(fs_info.info.clone()),
                mode: format!("{:?}", config.mode).to_lowercase(),
                allow_repair: config.allow_repair,
                tool: None,
                analysis: None,
                summary: CheckSummary {
                    status: "success".to_string(),
                    skipped_reason: None,
                },
                action: Some("planned".to_string()),
                reason: None,
                dry_run: Some(true),
                plan: Some(CheckPlan {
                    tool: tool_name.clone(),
                    arguments: args_vec.clone(),
                    requires_unmount_for_repair: repair && config.require_unmounted_for_repair,
                    would_run: true,
                }),
            })?);
        }

        let tool_result = self.execute_check_tool(&tool_name, &args_vec).await?;
        let analysis = self.analyze_check_results(config, &fs_info.info, &tool_result, repair)?;

        Ok(serde_json::to_value(CheckResult {
            backend: "fs".to_string(),
            verb: "check".to_string(),
            alias: Some(self.alias.clone()),
            target: config.target.clone(),
            by: format!("{:?}", config.by).to_lowercase(),
            filesystem: Some(fs_info.info),
            mode: format!("{:?}", config.mode).to_lowercase(),
            allow_repair: config.allow_repair,
            tool: Some(tool_result),
            analysis: Some(analysis),
            summary: CheckSummary {
                status: "success".to_string(),
                skipped_reason: None,
            },
            action: Some(if repair { "repair" } else { "check" }.to_string()),
            reason: None,
            dry_run: None,
            plan: None,
        })?)
    }

    /// Resolve the check target to filesystem information
    async fn resolve_check_target(
        &self,
        config: &FsCheckConfig,
    ) -> Result<CheckTarget, anyhow::Error> {
        let mounts = self
            .get_existing_mounts()
            .await
            .map_err(|e| FsError::CheckFailed(format!("cannot read the mount table: {e}")))?;
        let as_mountpoint = support::absolute(&config.target);
        let at_mountpoint = mounts.iter().rev().find(|m| m.target == as_mountpoint);

        let (source, mount) = match (&config.by, at_mountpoint) {
            (CheckTargetKind::Mountpoint | CheckTargetKind::Auto, Some(m)) => {
                (m.source.clone(), Some(m.clone()))
            }
            (CheckTargetKind::Mountpoint, None) => {
                return Err(FsError::CheckTargetNotFound(format!(
                    "no filesystem is mounted at {}",
                    config.target
                ))
                .into());
            }
            _ => {
                let mount = mounts
                    .iter()
                    .rev()
                    .find(|m| support::same_source(&m.source, &config.target))
                    .cloned();
                if mount.is_none() {
                    let meta = fs::metadata(&config.target).map_err(|_| {
                        FsError::CheckTargetNotFound(format!("device not found: {}", config.target))
                    })?;
                    let ft = meta.file_type();
                    if !(ft.is_block_device() || ft.is_file()) {
                        return Err(FsError::CheckTargetNotFound(format!(
                            "{} is neither a mount point nor a device or image file",
                            config.target
                        ))
                        .into());
                    }
                }
                (config.target.clone(), mount)
            }
        };

        let fstype = match (&config.filesystem_type, &mount) {
            (Some(t), _) => t.clone(),
            (None, Some(m)) => m.fs_type.clone(),
            (None, None) => {
                let mut cmd = tool("blkid");
                cmd.args(["-p", "-s", "TYPE", "-o", "value", "--"])
                    .arg(&source);
                let output = match run(&mut cmd).await {
                    Ok(o) => o,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        return Err(FsError::CheckToolNotAvailable("blkid".to_string()).into());
                    }
                    Err(e) => return Err(FsError::CheckFailed(e.to_string()).into()),
                };
                let t = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !output.status.success() || t.is_empty() {
                    return Err(FsError::CheckUnsupportedFilesystem(format!(
                        "no filesystem found on {source}"
                    ))
                    .into());
                }
                t
            }
        };

        Ok(CheckTarget {
            info: CheckFilesystemInfo {
                source,
                fstype,
                mounted: mount.is_some(),
                readonly: mount
                    .as_ref()
                    .is_some_and(|m| m.options.iter().any(|o| o == "ro")),
            },
            mountpoint: mount.map(|m| m.target),
        })
    }

    /// Apply skip policies
    fn apply_check_skip_policies(
        &self,
        config: &FsCheckConfig,
        fs_info: &CheckTarget,
    ) -> Result<Option<CheckResult>, anyhow::Error> {
        if config.skip_if_mounted && fs_info.info.mounted {
            return Ok(Some(CheckResult {
                backend: "fs".to_string(),
                verb: "check".to_string(),
                alias: Some(self.alias.clone()),
                target: config.target.clone(),
                by: format!("{:?}", config.by).to_lowercase(),
                filesystem: Some(fs_info.info.clone()),
                mode: format!("{:?}", config.mode).to_lowercase(),
                allow_repair: config.allow_repair,
                tool: None,
                analysis: None,
                summary: CheckSummary {
                    status: "skipped".to_string(),
                    skipped_reason: Some(
                        "Filesystem is mounted and skip_if_mounted=true".to_string(),
                    ),
                },
                action: Some("skipped_mounted".to_string()),
                reason: Some("Filesystem is mounted and skip_if_mounted=true".to_string()),
                dry_run: if config.dry_run { Some(true) } else { None },
                plan: None,
            }));
        }

        Ok(None)
    }

    /// Validate filesystem support for check operations
    fn validate_check_filesystem_support(&self, fstype: &str) -> Result<(), anyhow::Error> {
        if CHECK_FILESYSTEMS.contains(&fstype) {
            Ok(())
        } else {
            Err(FsError::CheckUnsupportedFilesystem(fstype.to_string()).into())
        }
    }

    /// Enforce check policies. Returns whether the run repairs.
    fn enforce_check_policies(
        &self,
        config: &FsCheckConfig,
        target: &CheckTarget,
    ) -> Result<bool, anyhow::Error> {
        let fs_info = &target.info;
        let is_ext = matches!(fs_info.fstype.as_str(), "ext2" | "ext3" | "ext4");
        let mounted_rw = fs_info.mounted && !fs_info.readonly;

        // Options that the selected tool has no use for are refused, not
        // ignored.
        if !is_ext && config.aggressiveness != CheckAggressiveness::Safe {
            return Err(FsError::InvalidCheckConfig(format!(
                "aggressiveness applies to ext2/ext3/ext4 only, not {}",
                fs_info.fstype
            ))
            .into());
        }
        if config.force && !is_ext && fs_info.fstype != "btrfs" {
            return Err(FsError::InvalidCheckConfig(format!(
                "force applies to ext2/ext3/ext4 and btrfs only, not {}",
                fs_info.fstype
            ))
            .into());
        }

        if fs_info.mounted && !config.allow_online_check {
            return Err(FsError::CheckMustBeOffline(fs_info.source.clone()).into());
        }

        // A repair needs exclusive access: only an ext filesystem mounted
        // read-only (or with require_unmounted_for_repair=false) may be
        // repaired while mounted.
        let repair_possible = !fs_info.mounted
            || (is_ext && (fs_info.readonly || !config.require_unmounted_for_repair));
        let repair = match config.mode {
            CheckMode::Check => false,
            CheckMode::Repair => {
                if !repair_possible {
                    return Err(
                        FsError::CheckRequiresUnmountForRepair(fs_info.source.clone()).into(),
                    );
                }
                true
            }
            CheckMode::Auto => config.allow_repair && repair_possible,
        };

        // xfs_repair cannot even check a filesystem that is mounted
        // read-write.
        if fs_info.fstype == "xfs" && mounted_rw {
            return Err(FsError::CheckMustBeOffline(fs_info.source.clone()).into());
        }
        if fs_info.fstype == "vfat" && mounted_rw {
            return Err(FsError::CheckMustBeOffline(fs_info.source.clone()).into());
        }
        if fs_info.fstype == "btrfs"
            && fs_info.mounted
            && !config.btrfs_use_scrub
            && !config.btrfs_allow_offline_check
        {
            return Err(FsError::CheckMustBeOffline(fs_info.source.clone()).into());
        }

        Ok(repair)
    }

    /// Select appropriate tool for the filesystem
    fn select_check_tool(
        &self,
        config: &FsCheckConfig,
        target: &CheckTarget,
        repair: bool,
    ) -> Result<(String, Vec<String>), anyhow::Error> {
        match target.info.fstype.as_str() {
            "ext2" | "ext3" | "ext4" | "vfat" => {
                self.build_fsck_command(config, &target.info, repair)
            }
            "xfs" => self.build_xfs_repair_command(&target.info, repair),
            "btrfs" => self.build_btrfs_command(config, target, repair),
            other => Err(FsError::CheckUnsupportedFilesystem(other.to_string()).into()),
        }
    }

    /// Build the fsck command for ext2/3/4 (e2fsck) and vfat (fsck.fat).
    ///
    /// ext: check is `-n`; repair is `-p` (preen), or `-y` with
    /// aggressiveness=aggressive. `-f` (check even a clean filesystem) is
    /// added for aggressiveness normal/aggressive and for force=true.
    /// vfat: check is `-n`, repair is `-a`.
    fn build_fsck_command(
        &self,
        config: &FsCheckConfig,
        fs_info: &CheckFilesystemInfo,
        repair: bool,
    ) -> Result<(String, Vec<String>), anyhow::Error> {
        let tool_name = format!("fsck.{}", fs_info.fstype);
        let mut args = vec![];

        if fs_info.fstype == "vfat" {
            args.push(if repair { "-a" } else { "-n" }.to_string());
        } else {
            args.push(
                match (repair, &config.aggressiveness) {
                    (false, _) => "-n",
                    (true, CheckAggressiveness::Aggressive) => "-y",
                    (true, _) => "-p",
                }
                .to_string(),
            );
            if config.force || config.aggressiveness != CheckAggressiveness::Safe {
                args.push("-f".to_string());
            }
        }

        args.push(fs_info.source.clone());
        Ok((tool_name, args))
    }

    /// Build xfs_repair command: `-n` (no modify) unless repairing.
    fn build_xfs_repair_command(
        &self,
        fs_info: &CheckFilesystemInfo,
        repair: bool,
    ) -> Result<(String, Vec<String>), anyhow::Error> {
        let mut args = vec![];
        if !repair {
            args.push("-n".to_string());
        }
        args.push(fs_info.source.clone());
        Ok(("xfs_repair".to_string(), args))
    }

    /// Build btrfs command: a scrub of a mounted filesystem (`-r`, read-only,
    /// unless repairing), or `btrfs check` of the device.
    fn build_btrfs_command(
        &self,
        config: &FsCheckConfig,
        target: &CheckTarget,
        repair: bool,
    ) -> Result<(String, Vec<String>), anyhow::Error> {
        let fs_info = &target.info;
        let mut args = vec![];

        match (&target.mountpoint, config.btrfs_use_scrub) {
            (Some(mountpoint), true) => {
                args.extend(["scrub", "start", "-B"].map(String::from));
                if !repair {
                    args.push("-r".to_string());
                }
                args.push(mountpoint.clone());
            }
            (Some(_), false) if !config.btrfs_allow_offline_check => {
                return Err(FsError::CheckMustBeOffline(fs_info.source.clone()).into());
            }
            (mounted, _) => {
                args.push("check".to_string());
                args.push(if repair { "--repair" } else { "--readonly" }.to_string());
                if mounted.is_some() || config.force {
                    args.push("--force".to_string());
                }
                args.push(fs_info.source.clone());
            }
        }

        Ok(("btrfs".to_string(), args))
    }

    /// Execute the check tool
    async fn execute_check_tool(
        &self,
        tool_name: &str,
        args: &[String],
    ) -> Result<CheckTool, anyhow::Error> {
        if !tool_available(tool_name) {
            return Err(FsError::CheckToolNotAvailable(tool_name.to_string()).into());
        }

        let full_command = format!("{} {}", tool_name, args.join(" "));
        let mut cmd = tool(tool_name);
        cmd.args(args);

        let output = match run(&mut cmd).await {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(FsError::CheckToolNotAvailable(tool_name.to_string()).into());
            }
            Err(e) => {
                return Err(
                    FsError::CheckFailed(format!("Failed to execute {tool_name}: {e}")).into(),
                );
            }
        };

        Ok(CheckTool {
            name: tool_name.to_string(),
            command: full_command,
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    /// Analyze check results. An exit status that means the tool itself
    /// failed (could not open the device, usage error, cancelled, killed)
    /// is an error, not a check result.
    fn analyze_check_results(
        &self,
        config: &FsCheckConfig,
        fs_info: &CheckFilesystemInfo,
        tool: &CheckTool,
        repair: bool,
    ) -> Result<CheckAnalysis, anyhow::Error> {
        let analysis = match fs_info.fstype.as_str() {
            "ext2" | "ext3" | "ext4" => self.analyze_fsck_results(config, tool),
            "vfat" => analyze_fat_results(tool, repair),
            "xfs" => self.analyze_xfs_repair_results(config, tool),
            "btrfs" => self.analyze_btrfs_results(config, tool),
            other => return Err(FsError::CheckUnsupportedFilesystem(other.to_string()).into()),
        }?;
        Ok(analysis)
    }

    /// e2fsck exit status is a bit mask: 1 errors corrected, 2 corrected and
    /// a reboot is needed, 4 errors left uncorrected, 8 operational error,
    /// 16 usage error, 32 cancelled, 128 shared library error.
    fn analyze_fsck_results(
        &self,
        _config: &FsCheckConfig,
        tool: &CheckTool,
    ) -> Result<CheckAnalysis, anyhow::Error> {
        let code = tool.exit_code;
        if !(0..=7).contains(&code) {
            return Err(check_tool_failure(tool));
        }
        let uncorrected = code & 4 != 0;
        let corrected = code & 3 != 0;
        Ok(CheckAnalysis {
            errors_found: uncorrected || corrected,
            repaired: corrected,
            needs_repair: uncorrected,
            filesystem_state: if uncorrected {
                "errors_detected"
            } else if corrected {
                "repaired"
            } else {
                "clean"
            }
            .to_string(),
        })
    }

    /// xfs_repair: 0 consistent (or repaired), 1 corruption found with -n,
    /// 2 a dirty log that must be replayed by mounting first. Anything else
    /// is a failure of the tool.
    fn analyze_xfs_repair_results(
        &self,
        _config: &FsCheckConfig,
        tool: &CheckTool,
    ) -> Result<CheckAnalysis, anyhow::Error> {
        let no_modify = tool.command.split_whitespace().any(|a| a == "-n");
        match tool.exit_code {
            0 => Ok(CheckAnalysis {
                errors_found: false,
                repaired: false,
                needs_repair: false,
                filesystem_state: "clean".to_string(),
            }),
            1 if no_modify => Ok(CheckAnalysis {
                errors_found: true,
                repaired: false,
                needs_repair: true,
                filesystem_state: "errors_detected".to_string(),
            }),
            2 => Ok(CheckAnalysis {
                errors_found: true,
                repaired: false,
                needs_repair: true,
                filesystem_state: "errors_detected".to_string(),
            }),
            _ => Err(check_tool_failure(tool)),
        }
    }

    /// btrfs scrub: 0 finished (errors, if any, were corrected), 3
    /// uncorrectable errors, anything else a failure. btrfs check: 0 clean,
    /// 1 with an error report means errors were found, otherwise a failure.
    fn analyze_btrfs_results(
        &self,
        _config: &FsCheckConfig,
        tool: &CheckTool,
    ) -> Result<CheckAnalysis, anyhow::Error> {
        let is_scrub = tool.command.contains(" scrub ");
        let is_repair = tool.command.contains("--repair");
        let text = format!("{}\n{}", tool.stdout, tool.stderr).to_ascii_lowercase();

        if is_scrub {
            return match tool.exit_code {
                0 if text.contains("no errors found") => Ok(CheckAnalysis {
                    errors_found: false,
                    repaired: false,
                    needs_repair: false,
                    filesystem_state: "clean".to_string(),
                }),
                0 => {
                    let read_only = tool.command.split_whitespace().any(|a| a == "-r");
                    Ok(CheckAnalysis {
                        errors_found: true,
                        repaired: !read_only,
                        needs_repair: read_only,
                        filesystem_state: if read_only {
                            "errors_detected"
                        } else {
                            "repaired"
                        }
                        .to_string(),
                    })
                }
                3 => Ok(CheckAnalysis {
                    errors_found: true,
                    repaired: false,
                    needs_repair: true,
                    filesystem_state: "errors_detected".to_string(),
                }),
                _ => Err(check_tool_failure(tool)),
            };
        }

        match tool.exit_code {
            0 => Ok(CheckAnalysis {
                errors_found: false,
                repaired: false,
                needs_repair: false,
                filesystem_state: "clean".to_string(),
            }),
            1 if text.contains("errors found") || text.contains("error(s) found") => {
                Ok(CheckAnalysis {
                    errors_found: true,
                    repaired: false,
                    needs_repair: !is_repair,
                    filesystem_state: "errors_detected".to_string(),
                })
            }
            _ => Err(check_tool_failure(tool)),
        }
    }

    /// Main list-mounts operation implementation
    pub async fn list_mounts(&self, args: Value) -> Result<Value, anyhow::Error> {
        // Parse and validate configuration
        let config = self.parse_list_mounts_config(args)?;
        self.validate_list_mounts_config(&config)?;

        let limit = crate::core::process::limit(Duration::from_millis(config.timeout_ms));
        timeout(limit, self.execute_list_mounts(&config))
            .await
            .map_err(|_| FsError::ListMountsTimeout)?
    }

    /// Parse list-mounts configuration from arguments
    fn parse_list_mounts_config(&self, args: Value) -> Result<ListMountsConfig, anyhow::Error> {
        let mut config: ListMountsConfig =
            parse_typed(args).map_err(|e| FsError::InvalidListMountsConfig(e.to_string()))?;

        // Set default timeout if not provided or zero
        if config.timeout_ms == 0 {
            config.timeout_ms = 3000;
        }

        Ok(config)
    }

    /// Validate list-mounts configuration
    fn validate_list_mounts_config(&self, config: &ListMountsConfig) -> Result<(), anyhow::Error> {
        if config.timeout_ms == 0 {
            return Err(FsError::InvalidListMountsConfig(
                "timeout_ms must be greater than 0".to_string(),
            )
            .into());
        }

        if !config.include_readonly && !config.include_readwrite {
            return Err(FsError::InvalidListMountsConfig(
                "Both include_readonly=false and include_readwrite=false - nothing allowed"
                    .to_string(),
            )
            .into());
        }

        support::check_filter_lists(&[("paths", &config.paths)])
            .and_then(|_| {
                support::check_filter_lists(&support::filter_pairs([
                    &config.include_mountpoints,
                    &config.exclude_mountpoints,
                    &config.include_types,
                    &config.exclude_types,
                    &config.include_sources,
                    &config.exclude_sources,
                ]))
            })
            .map_err(FsError::InvalidListMountsConfig)?;

        Ok(())
    }

    /// Execute the actual list-mounts operation
    async fn execute_list_mounts(&self, config: &ListMountsConfig) -> Result<Value, anyhow::Error> {
        // 1. Read mount table
        let raw_mounts = self.read_mount_table().await.map_err(|e| match e {
            MountTableError::Missing => FsError::ListMountsUnsupported,
            MountTableError::Unreadable(m) => FsError::ListMountsFailed(m),
        })?;

        // 2. Parse and classify mounts
        let mut mount_entries: Vec<ListMountEntry> = Vec::new();
        for raw_mount in raw_mounts.iter() {
            let mut entry = ListMountEntry {
                source: raw_mount.source.clone(),
                target: if config.normalize_paths {
                    self.normalize_path(&raw_mount.target)
                } else {
                    raw_mount.target.clone()
                },
                fstype: raw_mount.fstype.clone(),
                options: self.parse_and_sort_options(&raw_mount.options),
                read_only: self.is_read_only(&raw_mount.options),
                pseudo: self.is_pseudo_filesystem(&raw_mount.fstype),
                network: self.is_network_filesystem(&raw_mount.fstype, &raw_mount.source),
                loop_device: self.is_loop_device(&raw_mount.source),
                device: None,
                fs_features: None,
            };

            // Optionally resolve labels
            if config.resolve_labels {
                entry.device = self.resolve_device_labels(&raw_mount.source).await;
            }

            // Optionally resolve filesystem features
            if config.resolve_fs_features {
                entry.fs_features = self
                    .resolve_filesystem_features(&raw_mount.fstype, &raw_mount.source)
                    .await;
            }

            mount_entries.push(entry);
        }

        // 3. Apply path-based restriction if specified
        if !config.paths.is_empty() {
            mount_entries = self.filter_mounts_by_paths(&mount_entries, &config.paths)?;
        }

        // 4. Apply filters
        mount_entries = self.apply_list_mounts_filters(mount_entries, config)?;

        // 5. Sort deterministically
        mount_entries.sort_by(|a, b| {
            a.target
                .cmp(&b.target)
                .then_with(|| a.source.cmp(&b.source))
                .then_with(|| a.fstype.cmp(&b.fstype))
        });

        // 6. Build response
        let filters = ListMountsFilters {
            paths: config.paths.clone(),
            include_mountpoints: config.include_mountpoints.clone(),
            exclude_mountpoints: config.exclude_mountpoints.clone(),
            include_types: config.include_types.clone(),
            exclude_types: config.exclude_types.clone(),
            include_sources: config.include_sources.clone(),
            exclude_sources: config.exclude_sources.clone(),
            include_readonly: config.include_readonly,
            include_readwrite: config.include_readwrite,
            include_pseudo: config.include_pseudo,
            include_loop: config.include_loop,
            include_network: config.include_network,
        };

        Ok(json!(ListMountsResult {
            backend: "fs".to_string(),
            verb: "list-mounts".to_string(),
            alias: self.alias.clone(),
            filters,
            mounts: mount_entries,
        }))
    }

    /// Check if mount options indicate read-only
    fn is_read_only(&self, options: &str) -> bool {
        options.split(',').any(|opt| opt.trim() == "ro")
    }

    /// Check if filesystem type is a pseudo filesystem
    fn is_pseudo_filesystem(&self, fstype: &str) -> bool {
        matches!(
            fstype,
            "proc"
                | "sysfs"
                | "devtmpfs"
                | "devpts"
                | "tmpfs"
                | "ramfs"
                | "cgroup"
                | "cgroup2"
                | "pstore"
                | "securityfs"
                | "debugfs"
                | "tracefs"
                | "bpf"
                | "configfs"
                | "fusectl"
                | "mqueue"
                | "hugetlbfs"
                | "nsfs"
                | "autofs"
                | "efivarfs"
                | "binfmt_misc"
                | "rpc_pipefs"
                | "selinuxfs"
        )
    }

    /// Check if filesystem is a network filesystem
    fn is_network_filesystem(&self, fstype: &str, source: &str) -> bool {
        if is_network_fstype(fstype) {
            return true;
        }

        // Check by source format (server:/path or //server/share)
        source.contains(":/") || source.starts_with("//")
    }

    /// Check if device is a loop device
    fn is_loop_device(&self, source: &str) -> bool {
        source
            .strip_prefix("/dev/loop")
            .is_some_and(|n| n.chars().all(|c| c.is_ascii_digit()) && !n.is_empty())
    }

    /// Filter mounts by paths - only include filesystems backing the
    /// specified paths. Paths are made absolute and symlinks resolved when
    /// the path exists; mount points match whole path components.
    fn filter_mounts_by_paths(
        &self,
        mounts: &[ListMountEntry],
        paths: &[String],
    ) -> Result<Vec<ListMountEntry>, anyhow::Error> {
        let mut selected_mounts: Vec<ListMountEntry> = Vec::new();

        for path in paths {
            let abs = support::absolute(path);
            let resolved = fs::canonicalize(&abs)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or(abs);
            let best = mounts
                .iter()
                .filter(|m| support::path_is_under(&resolved, &m.target))
                .max_by_key(|m| Path::new(&m.target).components().count());
            if let Some(mount) = best {
                if !selected_mounts.iter().any(|m| m.target == mount.target) {
                    selected_mounts.push(mount.clone());
                }
            }
        }

        Ok(selected_mounts)
    }

    /// Apply all the include/exclude filters
    fn apply_list_mounts_filters(
        &self,
        mounts: Vec<ListMountEntry>,
        config: &ListMountsConfig,
    ) -> Result<Vec<ListMountEntry>, anyhow::Error> {
        let mut mounts = apply_mount_filters(
            &mounts,
            &MountFilters {
                include_mountpoints: &config.include_mountpoints,
                exclude_mountpoints: &config.exclude_mountpoints,
                include_types: &config.include_types,
                exclude_types: &config.exclude_types,
                include_sources: &config.include_sources,
                exclude_sources: &config.exclude_sources,
            },
            |m| (&m.target, &m.fstype, &m.source),
        );

        if !config.include_readonly {
            mounts.retain(|mount| !mount.read_only);
        }
        if !config.include_readwrite {
            mounts.retain(|mount| mount.read_only);
        }
        if !config.include_pseudo {
            mounts.retain(|mount| !mount.pseudo);
        }
        if !config.include_loop {
            mounts.retain(|mount| !mount.loop_device);
        }
        if !config.include_network {
            mounts.retain(|mount| !mount.network);
        }

        Ok(mounts)
    }

    /// Resolve device labels using blkid
    async fn resolve_device_labels(&self, source: &str) -> Option<DeviceMeta> {
        // Only try to resolve labels for block devices
        if !source.starts_with("/dev/") || source.contains(":") || source.starts_with("//") {
            return None;
        }

        let mut cmd = tool("blkid");
        cmd.args(["-o", "export", "--"]).arg(source);
        match run(&mut cmd).await {
            Ok(output) if output.status.success() => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                let mut meta = DeviceMeta {
                    label: None,
                    uuid: None,
                    partlabel: None,
                    partuuid: None,
                };

                for line in output_str.lines() {
                    if let Some((key, value)) = line.split_once('=') {
                        match key {
                            "LABEL" => meta.label = Some(value.to_string()),
                            "UUID" => meta.uuid = Some(value.to_string()),
                            "PARTLABEL" => meta.partlabel = Some(value.to_string()),
                            "PARTUUID" => meta.partuuid = Some(value.to_string()),
                            _ => {}
                        }
                    }
                }

                Some(meta)
            }
            _ => None,
        }
    }

    /// Resolve filesystem features
    async fn resolve_filesystem_features(&self, fstype: &str, source: &str) -> Option<FsFeatures> {
        // Only try for real filesystems and block devices
        if source.contains(":") || source.starts_with("//") || !source.starts_with("/dev/") {
            return None;
        }

        match fstype {
            "ext2" | "ext3" | "ext4" => self.resolve_ext_features(source).await,
            "xfs" => self.resolve_xfs_features(source).await,
            "btrfs" => self.resolve_btrfs_features(source).await,
            _ => None,
        }
    }

    /// Resolve ext filesystem features
    async fn resolve_ext_features(&self, source: &str) -> Option<FsFeatures> {
        let mut cmd = tool("tune2fs");
        cmd.arg("-l").arg(source);
        match run(&mut cmd).await {
            Ok(output) if output.status.success() => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                let mut features = Vec::new();
                let mut block_size = None;
                let mut inode_size = None;

                for line in output_str.lines() {
                    if line.starts_with("Filesystem features:") {
                        if let Some(features_str) = line.split(':').nth(1) {
                            features = features_str
                                .split_whitespace()
                                .map(|s| s.to_string())
                                .collect();
                        }
                    } else if line.starts_with("Block size:") {
                        if let Some(size_str) = line.split(':').nth(1) {
                            if let Ok(size) = size_str.trim().parse::<u64>() {
                                block_size = Some(size);
                            }
                        }
                    } else if line.starts_with("Inode size:") {
                        if let Some(size_str) = line.split(':').nth(1) {
                            if let Ok(size) = size_str.trim().parse::<u64>() {
                                inode_size = Some(size);
                            }
                        }
                    }
                }

                Some(FsFeatures {
                    features: if features.is_empty() {
                        None
                    } else {
                        Some(features)
                    },
                    block_size,
                    inode_size,
                })
            }
            _ => None,
        }
    }

    /// Resolve XFS filesystem features: the data block size and inode size
    /// from `xfs_info`, and the on-disk feature flags that are set.
    async fn resolve_xfs_features(&self, source: &str) -> Option<FsFeatures> {
        let mut cmd = tool("xfs_info");
        cmd.arg(source);
        let output = run(&mut cmd).await.ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        Some(xfs_features(&text))
    }

    /// Resolve Btrfs filesystem features from the superblock: the sector
    /// size and the incompat/compat_ro flags.
    async fn resolve_btrfs_features(&self, source: &str) -> Option<FsFeatures> {
        let mut cmd = tool("btrfs");
        cmd.args(["inspect-internal", "dump-super", "--"])
            .arg(source);
        let output = run(&mut cmd).await.ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        Some(btrfs_features(&text))
    }
}

/// Features from `xfs_info` output.
fn xfs_features(text: &str) -> FsFeatures {
    let block_size = support::xfs_data_geometry(text).map(|(b, _)| b);
    let mut inode_size = None;
    let mut features = Vec::new();
    for token in text.split(|c: char| c.is_whitespace() || c == ',') {
        if let Some((k, v)) = token.split_once('=') {
            if k == "isize" {
                inode_size = v.parse().ok();
            } else if v == "1"
                && matches!(
                    k,
                    "crc"
                        | "finobt"
                        | "sparse"
                        | "rmapbt"
                        | "reflink"
                        | "bigtime"
                        | "inobtcount"
                        | "nrext64"
                        | "projid32bit"
                        | "ftype"
                )
            {
                features.push(k.to_string());
            }
        }
    }
    FsFeatures {
        features: if features.is_empty() {
            None
        } else {
            Some(features)
        },
        block_size,
        inode_size,
    }
}

/// Features from `btrfs inspect-internal dump-super` output: the flag names
/// listed in parentheses under `incompat_flags` and `compat_ro_flags`.
fn btrfs_features(text: &str) -> FsFeatures {
    let block_size = text.lines().find_map(|l| {
        let mut w = l.split_whitespace();
        if w.next() == Some("sectorsize") {
            w.next()?.parse().ok()
        } else {
            None
        }
    });
    let mut features = Vec::new();
    let mut in_flags = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("incompat_flags") || t.starts_with("compat_ro_flags") {
            in_flags = true;
            continue;
        }
        if in_flags && (t.starts_with('(') || t.ends_with(')') || t.ends_with('|')) {
            for name in t.split(['(', ')', '|']) {
                let name = name.trim();
                if !name.is_empty() {
                    features.push(name.to_ascii_lowercase());
                }
            }
            if t.ends_with(')') {
                in_flags = false;
            }
            continue;
        }
        in_flags = false;
    }
    FsFeatures {
        features: if features.is_empty() {
            None
        } else {
            Some(features)
        },
        block_size,
        inode_size: None,
    }
}

impl Handle for FsHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &[
            "mount",
            "unmount",
            "umount",
            "snapshot",
            "quota",
            "quota_summary",
            "usage",
            "resize",
            "check",
            "fsck",
            "list-mounts",
            "help",
            "h",
        ]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&FS_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        if matches!(verb, "help" | "h") {
            let verb = args.get("verb").map(String::as_str);
            write!(
                io.stdout,
                "{}",
                crate::core::help::render_legacy("fs", &FS_HELP, self.verbs(), verb)
            )
            .context("Failed to write help text to stdout")?;
            return Ok(Status::ok());
        }

        let Some(allowed) = support::options_for(verb) else {
            return Ok(Status::err(2, format!("unknown verb: {verb}")));
        };
        // An option the verb does not know would otherwise be ignored, so a
        // misspelled `read_only` would mount read-write.
        if let Some(bad) = support::unknown_option(args.keys(), allowed) {
            return Ok(Status::err(
                2,
                support::unknown_option_message(verb, bad, allowed),
            ));
        }

        let args_value = serde_json::to_value(args).context("Failed to serialize the arguments")?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to create async runtime")?;

        let result = rt.block_on(async {
            match verb {
                "mount" => self.mount(args_value).await,
                "unmount" | "umount" => self.unmount(args_value).await,
                "snapshot" => self.snapshot(args_value).await,
                "quota" => self.quota(args_value).await,
                "quota_summary" => self.quota_summary(args_value).await,
                "usage" => self.usage(args_value).await,
                "resize" => self.resize(args_value).await,
                "check" | "fsck" => self.check(args_value).await,
                "list-mounts" => self.list_mounts(args_value).await,
                _ => Err(anyhow::anyhow!("unknown verb: {verb}")),
            }
        });

        match result {
            Ok(value) => {
                let text = serde_json::to_string(&value).context("Failed to serialize result")?;
                writeln!(io.stdout, "{text}")?;
                Ok(Status::ok())
            }
            Err(e) => match e.downcast_ref::<FsError>() {
                Some(FsError::Incomplete {
                    output,
                    code,
                    message,
                }) => {
                    // Report what was and was not done before failing.
                    writeln!(io.stdout, "{}", serde_json::to_string(output)?)?;
                    Ok(Status::err(*code, message))
                }
                Some(fs_err) => Ok(Status::err(fs_exit_code(fs_err), e.to_string())),
                // Not a validation error: reading the system or running a
                // tool failed.
                None => Ok(Status::err(1, format!("{e:#}"))),
            },
        }
    }
}

/// The exit status for an fs error, following the project convention:
/// 2 invalid usage (nothing was done), 124 timeout, 1 any other failure.
/// The message says which condition it was.
fn fs_exit_code(e: &FsError) -> i32 {
    use FsError::*;
    match e {
        InvalidMountConfig(_)
        | InvalidUnmountConfig(_)
        | InvalidSnapshotConfig(_)
        | InvalidQuotaConfig(_)
        | InvalidQuotaSummaryConfig(_)
        | InvalidUsageConfig(_)
        | InvalidResizeConfig(_)
        | InvalidCheckConfig(_)
        | InvalidListMountsConfig(_)
        | ResizeShrinkNotAllowed
        | ResizeInvalidTargetSize(_)
        | CheckRepairNotAllowed => 2,
        MountTimeout | UnmountTimeout | SnapshotTimeout | QuotaTimeout | QuotaSummaryTimeout
        | UsageTimeout | ResizeTimeout | CheckTimeout | ListMountsTimeout => 124,
        Incomplete { code, .. } => *code,
        _ => 1,
    }
}

/// Deserializes a verb's arguments. When a value cannot be read, the
/// error names the argument: each one is tried on its own to find it.
fn parse_typed<T: serde::de::DeserializeOwned>(args: Value) -> Result<T, String> {
    match crate::core::lenient::from_value::<T>(args.clone()) {
        Ok(v) => Ok(v),
        Err(e) => {
            if let Some(obj) = args.as_object() {
                let mut keys: Vec<&String> = obj.keys().collect();
                keys.sort();
                for key in keys {
                    let single = json!({ key.as_str(): obj[key].clone() });
                    if let Err(e) = crate::core::lenient::from_value::<T>(single) {
                        return Err(format!("invalid value for {key}: {}: {e}", obj[key]));
                    }
                }
            }
            Err(e.to_string())
        }
    }
}

/// Why the mount table could not be read.
#[derive(Debug)]
enum MountTableError {
    /// There is no /proc mount table: the platform is not supported.
    Missing,
    Unreadable(String),
}

/// Why a `repquota` run gave no report.
#[derive(Debug)]
enum RepquotaError {
    Unsupported,
    NotEnabled,
    Failed(String),
}

/// What `resize` found out about its target before changing anything.
#[derive(Debug, Clone)]
struct DiscoveredFilesystem {
    source: String,
    mountpoint: Option<String>,
    fstype: String,
    mounted: bool,
    current_size_bytes: u64,
    block_size: u64,
    btrfs_devid: Option<u64>,
}

/// What `check` found out about its target.
#[derive(Debug, Clone)]
struct CheckTarget {
    info: CheckFilesystemInfo,
    mountpoint: Option<String>,
}

/// Filesystem types `check` supports.
const CHECK_FILESYSTEMS: &[&str] = &["ext2", "ext3", "ext4", "vfat", "xfs", "btrfs"];

/// The include/exclude filters shared by several verbs.
struct MountFilters<'a> {
    include_mountpoints: &'a [String],
    exclude_mountpoints: &'a [String],
    include_types: &'a [String],
    exclude_types: &'a [String],
    include_sources: &'a [String],
    exclude_sources: &'a [String],
}

/// Keeps the items that pass the filters. `key` gives an item's mount
/// point, type and source. Mount point filters match whole path components;
/// types and sources match exactly.
fn apply_mount_filters<T: Clone>(
    items: &[T],
    f: &MountFilters,
    key: impl Fn(&T) -> (&String, &String, &String),
) -> Vec<T> {
    items
        .iter()
        .filter(|item| {
            let (target, fstype, source) = key(item);
            (f.include_mountpoints.is_empty()
                || f.include_mountpoints
                    .iter()
                    .any(|p| support::path_is_under(target, p)))
                && !f
                    .exclude_mountpoints
                    .iter()
                    .any(|p| support::path_is_under(target, p))
                && (f.include_types.is_empty() || f.include_types.contains(fstype))
                && !f.exclude_types.contains(fstype)
                && (f.include_sources.is_empty() || f.include_sources.contains(source))
                && !f.exclude_sources.contains(source)
        })
        .cloned()
        .collect()
}

/// True for filesystem types that live on another host.
fn is_network_fstype(fstype: &str) -> bool {
    matches!(
        fstype,
        "nfs"
            | "nfs4"
            | "cifs"
            | "smb"
            | "smb3"
            | "smbfs"
            | "sshfs"
            | "glusterfs"
            | "ceph"
            | "9p"
            | "fuse.sshfs"
            | "fuse.cifs"
            | "fuse.glusterfs"
    )
}

fn subject_type_name(kind: &SubjectType) -> &'static str {
    match kind {
        SubjectType::Group => "group",
        SubjectType::Project => "project",
        _ => "user",
    }
}

/// The id of project `name` from /etc/projid (`name:id` lines).
fn project_id(name: &str) -> Option<u32> {
    let text = fs::read_to_string("/etc/projid").ok()?;
    text.lines().find_map(|l| {
        let (n, id) = l.split_once(':')?;
        if n == name {
            id.trim().parse().ok()
        } else {
            None
        }
    })
}

/// The grace state of a limit: `(exceeded, seconds remaining)`. `grace` is
/// the time (seconds since the epoch) the grace period ends, 0 when none is
/// running.
fn grace_state(grace: u64, now: u64) -> (bool, Option<u64>) {
    match grace {
        0 => (false, None),
        g if g <= now => (true, Some(0)),
        g => (false, Some(g - now)),
    }
}

/// Space and inode quota entries from one report line. Block counts from
/// `quota`/`repquota` are KiB; `units=blocks` keeps them, `bytes` and `auto`
/// report bytes. A limit of 0 means no limit.
fn quota_entries(
    line: &support::QuotaLine,
    units: &QuotaUnits,
    include_space: bool,
    include_inodes: bool,
) -> (Option<SpaceQuota>, Option<InodeQuota>) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mul = match units {
        QuotaUnits::Blocks => 1,
        _ => 1024,
    };
    let limit = |v: u64, m: u64| (v != 0).then_some(v.saturating_mul(m));
    let percent = |used: u64, soft: Option<u64>| {
        soft.filter(|s| *s > 0)
            .map(|s| (used as f64 / s as f64) * 100.0)
    };

    let space = include_space.then(|| {
        let used = line.blocks.saturating_mul(mul);
        let soft = limit(line.block_soft, mul);
        let (grace_exceeded, grace_time_remaining_sec) = grace_state(line.block_grace, now);
        SpaceQuota {
            used,
            soft_limit: soft,
            hard_limit: limit(line.block_hard, mul),
            grace_exceeded,
            grace_time_remaining_sec,
            used_percent_of_soft: percent(used, soft),
        }
    });
    let inodes = include_inodes.then(|| {
        let soft = limit(line.file_soft, 1);
        let (grace_exceeded, grace_time_remaining_sec) = grace_state(line.file_grace, now);
        InodeQuota {
            used: line.files,
            soft_limit: soft,
            hard_limit: limit(line.file_hard, 1),
            grace_exceeded,
            grace_time_remaining_sec,
            used_percent_of_soft: percent(line.files, soft),
        }
    });
    (space, inodes)
}

/// Totals of several quota entries: `(used, soft, hard, grace exceeded)`.
struct QuotaTotals {
    used: u64,
    soft: Option<u64>,
    hard: Option<u64>,
    used_percent_of_soft: Option<f64>,
    any_grace_exceeded: bool,
}

fn sum_quotas(
    entries: impl Iterator<Item = (u64, Option<u64>, Option<u64>, bool)>,
) -> Option<QuotaTotals> {
    let mut any = false;
    let (mut used, mut soft, mut hard, mut exceeded) = (0u64, 0u64, 0u64, false);
    for (u, s, h, g) in entries {
        any = true;
        used = used.saturating_add(u);
        soft = soft.saturating_add(s.unwrap_or(0));
        hard = hard.saturating_add(h.unwrap_or(0));
        exceeded |= g;
    }
    any.then(|| QuotaTotals {
        used,
        soft: (soft > 0).then_some(soft),
        hard: (hard > 0).then_some(hard),
        used_percent_of_soft: (soft > 0).then(|| (used as f64 / soft as f64) * 100.0),
        any_grace_exceeded: exceeded,
    })
}

/// Removes the grace fields from every `space` and `inodes` object
/// (`include_grace=false`).
fn strip_grace(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for key in ["space", "inodes"] {
                if let Some(Value::Object(q)) = map.get_mut(key) {
                    q.remove("grace_exceeded");
                    q.remove("grace_time_remaining_sec");
                    q.remove("any_grace_exceeded");
                }
            }
            for v in map.values_mut() {
                strip_grace(v);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(strip_grace),
        _ => {}
    }
}

/// fsck.fat: 0 clean, 1 errors found (with -n) or corrected (with -a),
/// anything else a failure.
fn analyze_fat_results(tool: &CheckTool, repair: bool) -> Result<CheckAnalysis, anyhow::Error> {
    match tool.exit_code {
        0 => Ok(CheckAnalysis {
            errors_found: false,
            repaired: false,
            needs_repair: false,
            filesystem_state: "clean".to_string(),
        }),
        1 => Ok(CheckAnalysis {
            errors_found: true,
            repaired: repair,
            needs_repair: !repair,
            filesystem_state: if repair {
                "repaired"
            } else {
                "errors_detected"
            }
            .to_string(),
        }),
        _ => Err(check_tool_failure(tool)),
    }
}

/// The error for a check tool that failed to run its check.
fn check_tool_failure(tool: &CheckTool) -> anyhow::Error {
    let detail = format!("{} {}", tool.stderr.trim(), tool.stdout.trim());
    FsError::CheckFailed(format!(
        "{} exited with status {}: {}",
        tool.command,
        tool.exit_code,
        detail.trim()
    ))
    .into()
}

/// Register the filesystem handle with the registry
pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("fs", |u| Ok(Box::new(FsHandle::from_url(u.clone())?)));
}

/// The size argument for resize2fs. resize2fs reads a `K` suffix as KiB, so
/// the byte count is divided by 1024 (it used to be divided by the 4 KiB block
/// size, which asked for a quarter of the requested size).
fn resize2fs_size_arg(target_bytes: u64) -> String {
    format!("{}K", target_bytes / 1024)
}

// Stage 4 regression tests: resize size argument and strict dry_run.
#[cfg(test)]
mod stage4_tests {
    use super::*;

    #[test]
    fn resize2fs_gets_the_requested_size() {
        let gib = 1024u64 * 1024 * 1024;
        assert_eq!(resize2fs_size_arg(200 * gib), "209715200K");
        assert_eq!(resize2fs_size_arg(gib), "1048576K");
        // Never rounds up past the requested size.
        assert_eq!(resize2fs_size_arg(1024 * 10 + 1023), "10K");
    }

    #[test]
    fn mount_and_unmount_dry_run_parse_strictly() {
        let h = FsHandle {
            alias: "test".to_string(),
        };
        for bad in ["ture", "maybe", "2", ""] {
            assert!(
                h.parse_mount_config(
                    json!({"target": "/mnt/x", "source": "/dev/x", "dry_run": bad})
                )
                .is_err(),
                "{bad:?}"
            );
            assert!(
                h.parse_unmount_config(json!({"target": "/mnt/x", "dry_run": bad}))
                    .is_err(),
                "{bad:?}"
            );
        }
        for (v, want) in [
            ("true", true),
            ("1", true),
            ("YES", true),
            ("on", true),
            ("false", false),
            ("0", false),
            ("off", false),
        ] {
            assert_eq!(
                h.parse_mount_config(json!({"target": "/mnt/x", "source": "/dev/x", "dry_run": v}))
                    .unwrap()
                    .dry_run,
                want,
                "{v}"
            );
            assert_eq!(
                h.parse_unmount_config(json!({"target": "/mnt/x", "dry_run": v}))
                    .unwrap()
                    .dry_run,
                want,
                "{v}"
            );
        }
        // Through call(): a mistyped dry run fails before any mount command.
        let mut args = Args::new();
        for (k, v) in [
            ("target", "/nonexistent/resh-test-mnt"),
            ("source", "/dev/null"),
            ("dry_run", "ture"),
        ] {
            args.insert(k.into(), v.into());
        }
        let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
        let mut io = IoStreams {
            stdin: &mut i,
            stdout: &mut o,
            stderr: &mut e,
        };
        let st = h.call("mount", &args, &mut io).unwrap();
        assert!(!st.ok);
        assert!(!std::path::Path::new("/nonexistent/resh-test-mnt").exists());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_mount_config_validation() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        // Test empty target
        let config = MountConfig {
            target: "".to_string(),
            ..Default::default()
        };
        assert!(handle.validate_mount_config(&config).is_err());

        // Test bind without source
        let config = MountConfig {
            target: "/mnt/test".to_string(),
            bind: true,
            source: None,
            ..Default::default()
        };
        assert!(handle.validate_mount_config(&config).is_err());

        // Test contradictory flags
        let config = MountConfig {
            target: "/mnt/test".to_string(),
            remount: true,
            fail_if_mounted: true,
            ..Default::default()
        };
        assert!(handle.validate_mount_config(&config).is_err());

        // Test valid config
        let config = MountConfig {
            target: "/mnt/test".to_string(),
            source: Some("/dev/sdb1".to_string()),
            r#type: Some("ext4".to_string()),
            ..Default::default()
        };
        assert!(handle.validate_mount_config(&config).is_ok());
    }

    #[test]
    fn test_mount_config_defaults() {
        let args = json!({
            "target": "/mnt/test",
            "source": "/dev/sdb1"
        });

        let handle = FsHandle {
            alias: "test".to_string(),
        };
        let config = handle.parse_mount_config(args).unwrap();

        assert_eq!(config.target, "/mnt/test");
        assert_eq!(config.source, Some("/dev/sdb1".to_string()));
        assert_eq!(config.timeout_ms, 5000);
        assert_eq!(config.create_target, true);
        assert_eq!(config.make_parents, true);
        assert_eq!(config.read_only, false);
        assert_eq!(config.bind, false);
        assert_eq!(config.remount, false);
        assert_eq!(config.fail_if_mounted, false);
        assert_eq!(config.dry_run, false);
    }

    #[test]
    fn test_read_only_option_injection() {
        let args = json!({
            "target": "/mnt/test",
            "source": "/dev/sdb1",
            "read_only": true
        });

        let handle = FsHandle {
            alias: "test".to_string(),
        };
        let config = handle.parse_mount_config(args).unwrap();

        assert!(config.read_only);
        assert!(config.options.contains(&"ro".to_string()));
    }

    #[test]
    fn test_mount_compatibility() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        let existing = ExistingMount {
            source: "/dev/sdb1".to_string(),
            target: "/mnt/test".to_string(),
            fs_type: "ext4".to_string(),
            options: vec!["rw".to_string(), "noatime".to_string()],
        };

        // Compatible config
        let config = MountConfig {
            target: "/mnt/test".to_string(),
            source: Some("/dev/sdb1".to_string()),
            r#type: Some("ext4".to_string()),
            ..Default::default()
        };
        assert!(handle.is_mount_compatible(&existing, &config));

        // Incompatible source
        let config = MountConfig {
            target: "/mnt/test".to_string(),
            source: Some("/dev/sdc1".to_string()),
            r#type: Some("ext4".to_string()),
            ..Default::default()
        };
        assert!(!handle.is_mount_compatible(&existing, &config));

        // Incompatible filesystem type
        let config = MountConfig {
            target: "/mnt/test".to_string(),
            source: Some("/dev/sdb1".to_string()),
            r#type: Some("xfs".to_string()),
            ..Default::default()
        };
        assert!(!handle.is_mount_compatible(&existing, &config));
    }

    #[tokio::test]
    async fn test_dry_run_plan() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        let config = MountConfig {
            target: "/mnt/test".to_string(),
            source: Some("/dev/sdb1".to_string()),
            r#type: Some("ext4".to_string()),
            options: vec!["noatime".to_string()],
            dry_run: true,
            ..Default::default()
        };

        let result = handle.create_mount_plan(&config, false).unwrap();

        assert_eq!(result.action, "planned");
        assert!(result.dry_run == Some(true));
        assert!(result.plan.is_some());

        let plan = result.plan.unwrap();
        assert!(plan.create_directory.len() > 0);
        assert!(plan.mount_commands.len() > 0);
        assert!(plan.mount_commands[0].contains("mount"));
        assert!(plan.mount_commands[0].contains("-t ext4"));
        assert!(plan.mount_commands[0].contains("-o noatime"));
        assert!(plan.mount_commands[0].contains("/dev/sdb1"));
        assert!(plan.mount_commands[0].contains("/mnt/test"));
    }

    #[test]
    fn test_unmount_config_validation() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        // Test empty target
        let config = UnmountConfig {
            target: "".to_string(),
            ..Default::default()
        };
        assert!(handle.validate_unmount_config(&config).is_err());

        // Test whitespace-only target
        let config = UnmountConfig {
            target: "   ".to_string(),
            ..Default::default()
        };
        assert!(handle.validate_unmount_config(&config).is_err());

        // Test zero timeout
        let config = UnmountConfig {
            target: "/mnt/test".to_string(),
            timeout_ms: 0,
            ..Default::default()
        };
        assert!(handle.validate_unmount_config(&config).is_err());

        // Valid config
        let config = UnmountConfig {
            target: "/mnt/test".to_string(),
            ..Default::default()
        };
        assert!(handle.validate_unmount_config(&config).is_ok());
    }

    #[test]
    fn test_parse_unmount_config() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        // Test JSON deserialization
        let args = json!({
            "target": "/mnt/test",
            "by": "target",
            "force": true,
            "lazy": false,
            "detach_children": true,
            "timeout_ms": 10000,
            "dry_run": true
        });

        let config = handle.parse_unmount_config(args).unwrap();
        assert_eq!(config.target, "/mnt/test");
        assert_eq!(config.by, UnmountTargetKind::Target);
        assert!(config.force);
        assert!(!config.lazy);
        assert!(config.detach_children);
        assert_eq!(config.timeout_ms, 10000);
        assert!(config.dry_run);

        // Test string-based parsing
        let args = json!({
            "target": "/mnt/test",
            "by": "source",
            "force": "true",
            "lazy": "false",
            "timeout_ms": "5000"
        });

        let config = handle.parse_unmount_config(args).unwrap();
        assert_eq!(config.by, UnmountTargetKind::Source);
        assert!(config.force);
        assert_eq!(config.timeout_ms, 5000);
    }

    #[test]
    fn test_find_mounts_to_unmount() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        let existing_mounts = vec![
            ExistingMount {
                source: "/dev/sdb1".to_string(),
                target: "/mnt/data".to_string(),
                fs_type: "ext4".to_string(),
                options: vec!["rw".to_string()],
            },
            ExistingMount {
                source: "tmpfs".to_string(),
                target: "/mnt/data/tmp".to_string(),
                fs_type: "tmpfs".to_string(),
                options: vec!["rw".to_string(), "size=1G".to_string()],
            },
            ExistingMount {
                source: "/dev/sdc1".to_string(),
                target: "/mnt/backup".to_string(),
                fs_type: "xfs".to_string(),
                options: vec!["rw".to_string()],
            },
        ];

        // Test by target
        let config = UnmountConfig {
            target: "/mnt/data".to_string(),
            by: UnmountTargetKind::Target,
            ..Default::default()
        };
        let matched = handle
            .find_mounts_to_unmount(&existing_mounts, &config)
            .unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].target, "/mnt/data");

        // Test by source
        let config = UnmountConfig {
            target: "/dev/sdb1".to_string(),
            by: UnmountTargetKind::Source,
            ..Default::default()
        };
        let matched = handle
            .find_mounts_to_unmount(&existing_mounts, &config)
            .unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].source, "/dev/sdb1");

        // Test auto (first tries target, then source)
        let config = UnmountConfig {
            target: "/mnt/data".to_string(),
            by: UnmountTargetKind::Auto,
            ..Default::default()
        };
        let matched = handle
            .find_mounts_to_unmount(&existing_mounts, &config)
            .unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].target, "/mnt/data");

        // Test auto fallback to source
        let config = UnmountConfig {
            target: "/dev/sdc1".to_string(),
            by: UnmountTargetKind::Auto,
            ..Default::default()
        };
        let matched = handle
            .find_mounts_to_unmount(&existing_mounts, &config)
            .unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].source, "/dev/sdc1");
    }

    #[test]
    fn test_compute_unmount_order() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        let all_mounts = vec![
            ExistingMount {
                source: "/dev/sdb1".to_string(),
                target: "/mnt/data".to_string(),
                fs_type: "ext4".to_string(),
                options: vec!["rw".to_string()],
            },
            ExistingMount {
                source: "tmpfs".to_string(),
                target: "/mnt/data/tmp".to_string(),
                fs_type: "tmpfs".to_string(),
                options: vec!["rw".to_string()],
            },
            ExistingMount {
                source: "/dev/loop0".to_string(),
                target: "/mnt/data/tmp/nested".to_string(),
                fs_type: "ext4".to_string(),
                options: vec!["rw".to_string()],
            },
            ExistingMount {
                source: "/dev/sdc1".to_string(),
                target: "/mnt/other".to_string(),
                fs_type: "xfs".to_string(),
                options: vec!["rw".to_string()],
            },
        ];

        let matched_mounts = vec![all_mounts[0].clone()]; // /mnt/data

        // Test without detach_children
        let config = UnmountConfig {
            target: "/mnt/data".to_string(),
            detach_children: false,
            ..Default::default()
        };
        let order = handle
            .compute_unmount_order(&matched_mounts, &all_mounts, &config)
            .unwrap();
        assert_eq!(order.len(), 1);
        assert_eq!(order[0].target, "/mnt/data");

        // Test with detach_children
        let config = UnmountConfig {
            target: "/mnt/data".to_string(),
            detach_children: true,
            ..Default::default()
        };
        let order = handle
            .compute_unmount_order(&matched_mounts, &all_mounts, &config)
            .unwrap();
        assert_eq!(order.len(), 3);
        // Should be deepest first: /mnt/data/tmp/nested, /mnt/data/tmp, /mnt/data
        assert_eq!(order[0].target, "/mnt/data/tmp/nested");
        assert_eq!(order[1].target, "/mnt/data/tmp");
        assert_eq!(order[2].target, "/mnt/data");
    }

    #[test]
    fn test_unmount_dry_run_plan() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        let unmount_order = vec![
            ExistingMount {
                source: "tmpfs".to_string(),
                target: "/mnt/data/tmp".to_string(),
                fs_type: "tmpfs".to_string(),
                options: vec!["rw".to_string()],
            },
            ExistingMount {
                source: "/dev/sdb1".to_string(),
                target: "/mnt/data".to_string(),
                fs_type: "ext4".to_string(),
                options: vec!["rw".to_string()],
            },
        ];

        let config = UnmountConfig {
            target: "/mnt/data".to_string(),
            force: true,
            lazy: false,
            detach_children: true,
            ..Default::default()
        };

        let result = handle.create_unmount_plan(&config, &unmount_order).unwrap();

        assert_eq!(result.action, "planned");
        assert_eq!(result.dry_run, Some(true));
        assert!(result.plan.is_some());
        assert!(result.matched_mounts.is_some());

        let plan = result.plan.unwrap();
        assert_eq!(plan.order.len(), 2);
        assert_eq!(plan.order[0], "/mnt/data/tmp");
        assert_eq!(plan.order[1], "/mnt/data");

        assert_eq!(plan.commands.len(), 2);
        assert!(plan.commands[0].contains("umount"));
        assert!(plan.commands[0].contains("-f"));
        assert!(plan.commands[0].contains("/mnt/data/tmp"));
        assert!(plan.commands[1].contains("-f"));
        assert!(plan.commands[1].contains("/mnt/data"));
    }

    #[test]
    fn test_unmount_error_mapping() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        // Test error code mapping
        let error = FsError::InvalidUnmountConfig("test".to_string());
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.invalid_unmount_config"
        );

        let error = FsError::UnmountBusy("/mnt/test".to_string());
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.unmount_busy"
        );

        let error = FsError::UnmountTimeout;
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.unmount_timeout"
        );

        let error = FsError::NotMounted("/mnt/test".to_string());
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.not_mounted"
        );
    }

    #[test]
    fn test_snapshot_config_validation() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        // Test zero timeout
        let config = SnapshotConfig {
            timeout_ms: 0,
            ..Default::default()
        };
        assert!(handle.validate_snapshot_config(&config).is_err());

        // Test valid config
        let config = SnapshotConfig {
            timeout_ms: 5000,
            include_usage: true,
            include_inodes: false,
            format: SnapshotFormat::Json,
            ..Default::default()
        };
        assert!(handle.validate_snapshot_config(&config).is_ok());
    }

    #[test]
    fn test_snapshot_filtering() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        let raw_mounts = vec![
            RawMountInfo {
                source: "/dev/sda1".to_string(),
                target: "/".to_string(),
                fstype: "ext4".to_string(),
                options: "rw,relatime".to_string(),
                dump: 0,
                pass: 1,
            },
            RawMountInfo {
                source: "proc".to_string(),
                target: "/proc".to_string(),
                fstype: "proc".to_string(),
                options: "rw,nosuid,nodev,noexec,relatime".to_string(),
                dump: 0,
                pass: 0,
            },
            RawMountInfo {
                source: "/dev/sda2".to_string(),
                target: "/mnt/data".to_string(),
                fstype: "ext4".to_string(),
                options: "rw,relatime".to_string(),
                dump: 0,
                pass: 2,
            },
        ];

        // Test include_mountpoints filter
        let config = SnapshotConfig {
            include_mountpoints: vec!["/mnt".to_string()],
            ..Default::default()
        };
        let filtered = handle.apply_snapshot_filters(&raw_mounts, &config).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].target, "/mnt/data");

        // Test exclude_types filter
        let config = SnapshotConfig {
            exclude_types: vec!["proc".to_string()],
            ..Default::default()
        };
        let filtered = handle.apply_snapshot_filters(&raw_mounts, &config).unwrap();
        assert_eq!(filtered.len(), 2);
        assert!(!filtered.iter().any(|m| m.fstype == "proc"));

        // Test include_types filter
        let config = SnapshotConfig {
            include_types: vec!["ext4".to_string()],
            ..Default::default()
        };
        let filtered = handle.apply_snapshot_filters(&raw_mounts, &config).unwrap();
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|m| m.fstype == "ext4"));
    }

    #[test]
    fn test_path_normalization() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        assert_eq!(handle.normalize_path("/mnt//data/"), "/mnt/data");
        assert_eq!(handle.normalize_path("/"), "/");
        assert_eq!(handle.normalize_path("//"), "/");
        assert_eq!(handle.normalize_path("/mnt/data"), "/mnt/data");
        assert_eq!(handle.normalize_path(""), "/");
    }

    #[test]
    fn test_options_parsing() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        let options = handle.parse_and_sort_options("rw,relatime,noatime");
        assert_eq!(options, vec!["noatime", "relatime", "rw"]);

        let options = handle.parse_and_sort_options("defaults");
        assert_eq!(options, vec!["defaults"]);

        let options = handle.parse_and_sort_options("");
        assert_eq!(options.len(), 0);
    }

    #[test]
    fn test_has_filters() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        let config = SnapshotConfig::default();
        assert!(!handle.has_filters(&config));

        let config = SnapshotConfig {
            include_types: vec!["ext4".to_string()],
            ..Default::default()
        };
        assert!(handle.has_filters(&config));

        let config = SnapshotConfig {
            exclude_mountpoints: vec!["/proc".to_string()],
            ..Default::default()
        };
        assert!(handle.has_filters(&config));
    }

    #[test]
    fn test_snapshot_error_mapping() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        let error = FsError::InvalidSnapshotConfig("test".to_string());
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.invalid_snapshot_config"
        );

        let error = FsError::SnapshotUnsupported;
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.snapshot_unsupported"
        );

        let error = FsError::SnapshotTimeout;
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.snapshot_timeout"
        );

        let error = FsError::SnapshotFailed("test".to_string());
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.snapshot_failed"
        );
    }

    #[test]
    fn test_subject_type_enum() {
        // Test deserialization
        assert_eq!(
            serde_json::from_str::<SubjectType>("\"auto\"").unwrap(),
            SubjectType::Auto
        );
        assert_eq!(
            serde_json::from_str::<SubjectType>("\"user\"").unwrap(),
            SubjectType::User
        );
        assert_eq!(
            serde_json::from_str::<SubjectType>("\"group\"").unwrap(),
            SubjectType::Group
        );
        assert_eq!(
            serde_json::from_str::<SubjectType>("\"project\"").unwrap(),
            SubjectType::Project
        );

        // Test that invalid values fail
        assert!(serde_json::from_str::<SubjectType>("\"invalid\"").is_err());
    }

    #[test]
    fn test_quota_units_enum() {
        // Test deserialization
        assert_eq!(
            serde_json::from_str::<QuotaUnits>("\"auto\"").unwrap(),
            QuotaUnits::Auto
        );
        assert_eq!(
            serde_json::from_str::<QuotaUnits>("\"blocks\"").unwrap(),
            QuotaUnits::Blocks
        );
        assert_eq!(
            serde_json::from_str::<QuotaUnits>("\"bytes\"").unwrap(),
            QuotaUnits::Bytes
        );

        // Test that invalid values fail
        assert!(serde_json::from_str::<QuotaUnits>("\"invalid\"").is_err());
    }

    #[test]
    fn test_quota_config_default() {
        let config = FsQuotaConfig::default();

        assert!(config.path.is_none());
        assert!(config.subject.is_none());
        assert_eq!(config.subject_type, SubjectType::Auto);
        assert_eq!(config.resolve_uid_gid, true);
        assert_eq!(config.include_space, true);
        assert_eq!(config.include_inodes, true);
        assert_eq!(config.include_grace, true);
        assert_eq!(config.all_subjects, false);
        assert_eq!(config.units, QuotaUnits::Auto);
        assert_eq!(config.timeout_ms, 5000);
    }

    #[test]
    fn test_quota_error_mapping() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        let error = FsError::InvalidQuotaConfig("test".to_string());
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.invalid_quota_config"
        );

        let error = FsError::QuotaUnsupported;
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.quota_unsupported"
        );

        let error = FsError::QuotaNotEnabled("test".to_string());
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.quota_not_enabled"
        );

        let error = FsError::QuotaSubjectNotFound("test".to_string());
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.quota_subject_not_found"
        );

        let error = FsError::QuotaTimeout;
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.quota_timeout"
        );

        let error = FsError::QuotaFailed("test".to_string());
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.quota_failed"
        );
    }

    #[test]
    fn test_check_config_validation() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        // Test empty target
        let config = FsCheckConfig {
            target: "".to_string(),
            ..Default::default()
        };
        assert!(handle.validate_check_config(&config).is_err());

        // Test zero timeout
        let config = FsCheckConfig {
            target: "/dev/sdb1".to_string(),
            timeout_ms: 0,
            ..Default::default()
        };
        assert!(handle.validate_check_config(&config).is_err());

        // Test repair mode without allow_repair
        let config = FsCheckConfig {
            target: "/dev/sdb1".to_string(),
            mode: CheckMode::Repair,
            allow_repair: false,
            ..Default::default()
        };
        assert!(handle.validate_check_config(&config).is_err());

        // Test valid config
        let config = FsCheckConfig {
            target: "/dev/sdb1".to_string(),
            mode: CheckMode::Check,
            ..Default::default()
        };
        assert!(handle.validate_check_config(&config).is_ok());

        // Test valid repair config
        let config = FsCheckConfig {
            target: "/dev/sdb1".to_string(),
            mode: CheckMode::Repair,
            allow_repair: true,
            ..Default::default()
        };
        assert!(handle.validate_check_config(&config).is_ok());
    }

    #[test]
    fn test_check_filesystem_support() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        // Test supported filesystems
        assert!(handle.validate_check_filesystem_support("ext2").is_ok());
        assert!(handle.validate_check_filesystem_support("ext3").is_ok());
        assert!(handle.validate_check_filesystem_support("ext4").is_ok());
        assert!(handle.validate_check_filesystem_support("xfs").is_ok());
        assert!(handle.validate_check_filesystem_support("btrfs").is_ok());
        assert!(handle.validate_check_filesystem_support("vfat").is_ok());
        assert!(
            handle
                .validate_check_filesystem_support("reiserfs")
                .is_err()
        );

        // Test unsupported filesystem
        assert!(handle.validate_check_filesystem_support("zfs").is_err());
        assert!(handle.validate_check_filesystem_support("unknown").is_err());
    }

    #[test]
    fn test_check_error_mapping() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        let error = FsError::InvalidCheckConfig("test".to_string());
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.invalid_check_config"
        );

        let error = FsError::CheckTargetNotFound("test".to_string());
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.check_target_not_found"
        );

        let error = FsError::CheckUnsupportedFilesystem("test".to_string());
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.check_unsupported_filesystem"
        );

        let error = FsError::CheckRepairNotAllowed;
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.check_repair_not_allowed"
        );

        let error = FsError::CheckRequiresUnmountForRepair("test".to_string());
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.check_requires_unmount_for_repair"
        );

        let error = FsError::CheckMustBeOffline("test".to_string());
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.check_must_be_offline"
        );

        let error = FsError::CheckToolNotAvailable("test".to_string());
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.check_tool_not_available"
        );

        let error = FsError::CheckTimeout;
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.check_timeout"
        );

        let error = FsError::CheckFailed("test".to_string());
        assert_eq!(
            handle.map_error_to_code(&anyhow::anyhow!(error)),
            "fs.check_failed"
        );
    }

    #[test]
    fn test_aggregate_subject_quota_across_filesystems_with_data() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        // Create test subject
        let subject = QuotaSubject {
            subject: "user1".to_string(),
            subject_type: "user".to_string(),
            uid: Some(1001),
            gid: Some(1001),
            space: None,
            inodes: None,
        };

        // Create test filesystems with quota data
        let quota_filesystems = vec![
            QuotaSummaryFilesystem {
                source: "/dev/sda1".to_string(),
                target: "/home".to_string(),
                fstype: "ext4".to_string(),
                space_quota_enabled: true,
                inode_quota_enabled: true,
                space: Some(SpaceQuota {
                    used: 1024 * 1024 * 100,              // 100MB
                    soft_limit: Some(1024 * 1024 * 500),  // 500MB
                    hard_limit: Some(1024 * 1024 * 1000), // 1GB
                    grace_exceeded: false,
                    grace_time_remaining_sec: Some(7200), // 2 hours
                    used_percent_of_soft: Some(20.0),
                }),
                inodes: Some(InodeQuota {
                    used: 1000,
                    soft_limit: Some(5000),
                    hard_limit: Some(10000),
                    grace_exceeded: false,
                    grace_time_remaining_sec: Some(3600), // 1 hour
                    used_percent_of_soft: Some(20.0),
                }),
            },
            QuotaSummaryFilesystem {
                source: "/dev/sdb1".to_string(),
                target: "/var".to_string(),
                fstype: "ext4".to_string(),
                space_quota_enabled: true,
                inode_quota_enabled: true,
                space: Some(SpaceQuota {
                    used: 1024 * 1024 * 200,             // 200MB
                    soft_limit: Some(1024 * 1024 * 300), // 300MB
                    hard_limit: Some(1024 * 1024 * 500), // 500MB
                    grace_exceeded: true,
                    grace_time_remaining_sec: Some(0), // expired
                    used_percent_of_soft: Some(66.7),
                }),
                inodes: Some(InodeQuota {
                    used: 2000,
                    soft_limit: Some(3000),
                    hard_limit: Some(6000),
                    grace_exceeded: true,
                    grace_time_remaining_sec: Some(0), // expired
                    used_percent_of_soft: Some(66.7),
                }),
            },
        ];

        // Create test configuration
        let config = FsQuotaSummaryConfig {
            subject: None,
            subject_type: SubjectType::Auto,
            resolve_uid_gid: false,
            include_space: true,
            include_inodes: true,
            include_grace: true,
            all_subjects: true,
            units: QuotaUnits::Bytes,
            timeout_ms: 5000,
            include_mountpoints: vec![],
            exclude_mountpoints: vec![],
            include_types: vec![],
            exclude_types: vec![],
            include_sources: vec![],
            exclude_sources: vec![],
        };

        // Test aggregation
        let result = handle.aggregate_subject_quota_across_filesystems(
            &subject,
            &quota_filesystems,
            &config,
        );

        // Check subject information
        assert_eq!(result.subject, "user1");
        assert_eq!(result.subject_type, "user");
        assert_eq!(result.uid, Some(1001));
        assert_eq!(result.gid, Some(1001));

        // Check space aggregation
        assert!(result.space.is_some());
        let space = result.space.unwrap();
        assert_eq!(space.used, 1024 * 1024 * 300); // 100MB + 200MB = 300MB
        assert_eq!(space.soft_limit, Some(1024 * 1024 * 800)); // 500MB + 300MB = 800MB
        assert_eq!(space.hard_limit, Some(1024 * 1024 * 1500)); // 1GB + 500MB = 1500MB
        assert_eq!(space.any_grace_exceeded, true); // One filesystem has expired grace

        // Check inode aggregation
        assert!(result.inodes.is_some());
        let inodes = result.inodes.unwrap();
        assert_eq!(inodes.used, 3000); // 1000 + 2000 = 3000
        assert_eq!(inodes.soft_limit, Some(8000)); // 5000 + 3000 = 8000
        assert_eq!(inodes.hard_limit, Some(16000)); // 10000 + 6000 = 16000
        assert_eq!(inodes.any_grace_exceeded, true); // One filesystem has expired grace
    }

    #[test]
    fn test_aggregate_subject_quota_space_only() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        // Create test subject
        let subject = QuotaSubject {
            subject: "user1".to_string(),
            subject_type: "user".to_string(),
            uid: Some(1001),
            gid: Some(1001),
            space: None,
            inodes: None,
        };

        // Create filesystem with space quota only
        let quota_filesystems = vec![QuotaSummaryFilesystem {
            source: "/dev/sda1".to_string(),
            target: "/home".to_string(),
            fstype: "ext4".to_string(),
            space_quota_enabled: true,
            inode_quota_enabled: false,
            space: Some(SpaceQuota {
                used: 1024 * 1024 * 150,              // 150MB
                soft_limit: Some(1024 * 1024 * 500),  // 500MB
                hard_limit: Some(1024 * 1024 * 1000), // 1GB
                grace_exceeded: false,
                grace_time_remaining_sec: None,
                used_percent_of_soft: Some(30.0),
            }),
            inodes: None,
        }];

        // Create test configuration - space only
        let config = FsQuotaSummaryConfig {
            subject: None,
            subject_type: SubjectType::Auto,
            resolve_uid_gid: false,
            include_space: true,
            include_inodes: false,
            include_grace: true,
            all_subjects: true,
            units: QuotaUnits::Bytes,
            timeout_ms: 5000,
            include_mountpoints: vec![],
            exclude_mountpoints: vec![],
            include_types: vec![],
            exclude_types: vec![],
            include_sources: vec![],
            exclude_sources: vec![],
        };

        // Test aggregation
        let result = handle.aggregate_subject_quota_across_filesystems(
            &subject,
            &quota_filesystems,
            &config,
        );

        // Check space aggregation
        assert!(result.space.is_some());
        let space = result.space.unwrap();
        assert_eq!(space.used, 1024 * 1024 * 150);
        assert_eq!(space.soft_limit, Some(1024 * 1024 * 500));
        assert_eq!(space.hard_limit, Some(1024 * 1024 * 1000));
        assert_eq!(space.any_grace_exceeded, false);

        // Check that inodes is not included
        assert!(result.inodes.is_none());
    }

    #[test]
    fn test_aggregate_subject_quota_no_limits() {
        let handle = FsHandle {
            alias: "test".to_string(),
        };

        // Create test subject
        let subject = QuotaSubject {
            subject: "user1".to_string(),
            subject_type: "user".to_string(),
            uid: Some(1001),
            gid: Some(1001),
            space: None,
            inodes: None,
        };

        // Create filesystem with no quota limits
        let quota_filesystems = vec![QuotaSummaryFilesystem {
            source: "/dev/sda1".to_string(),
            target: "/home".to_string(),
            fstype: "ext4".to_string(),
            space_quota_enabled: true,
            inode_quota_enabled: true,
            space: Some(SpaceQuota {
                used: 1024 * 1024 * 100, // 100MB
                soft_limit: None,        // No soft limit
                hard_limit: None,        // No hard limit
                grace_exceeded: false,
                grace_time_remaining_sec: None,
                used_percent_of_soft: None,
            }),
            inodes: Some(InodeQuota {
                used: 1000,
                soft_limit: None, // No soft limit
                hard_limit: None, // No hard limit
                grace_exceeded: false,
                grace_time_remaining_sec: None,
                used_percent_of_soft: None,
            }),
        }];

        // Create test configuration
        let config = FsQuotaSummaryConfig {
            subject: None,
            subject_type: SubjectType::Auto,
            resolve_uid_gid: false,
            include_space: true,
            include_inodes: true,
            include_grace: true,
            all_subjects: true,
            units: QuotaUnits::Bytes,
            timeout_ms: 5000,
            include_mountpoints: vec![],
            exclude_mountpoints: vec![],
            include_types: vec![],
            exclude_types: vec![],
            include_sources: vec![],
            exclude_sources: vec![],
        };

        // Test aggregation
        let result = handle.aggregate_subject_quota_across_filesystems(
            &subject,
            &quota_filesystems,
            &config,
        );

        // Check space aggregation
        assert!(result.space.is_some());
        let space = result.space.unwrap();
        assert_eq!(space.used, 1024 * 1024 * 100);
        assert_eq!(space.soft_limit, None);
        assert_eq!(space.hard_limit, None);
        assert_eq!(space.used_percent_of_soft, None);
        assert_eq!(space.any_grace_exceeded, false);

        // Check inode aggregation
        assert!(result.inodes.is_some());
        let inodes = result.inodes.unwrap();
        assert_eq!(inodes.used, 1000);
        assert_eq!(inodes.soft_limit, None);
        assert_eq!(inodes.hard_limit, None);
        assert_eq!(inodes.used_percent_of_soft, None);
        assert_eq!(inodes.any_grace_exceeded, false);
    }

    fn cli_args(pairs: &[(&str, &str)]) -> Value {
        let args: Args = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        serde_json::to_value(args).unwrap()
    }

    #[test]
    fn cli_string_args_parse_into_typed_configs() {
        let h = FsHandle::new_for_test("t".to_string());

        let c = h
            .parse_snapshot_config(cli_args(&[
                ("include_inodes", "true"),
                ("timeout_ms", "1234"),
                ("include_types", "ext4,xfs"),
            ]))
            .unwrap();
        assert!(c.include_inodes);
        assert_eq!(c.timeout_ms, 1234);
        assert_eq!(c.include_types, vec!["ext4", "xfs"]);

        let c = h
            .parse_resize_config(cli_args(&[
                ("target", "/data"),
                ("mode", "shrink"),
                ("allow_shrink", "true"),
                ("dry_run", "true"),
                ("timeout_ms", "9000"),
            ]))
            .unwrap();
        assert_eq!(c.mode, ResizeMode::Shrink);
        assert!(c.allow_shrink && c.dry_run);
        assert_eq!(c.timeout_ms, 9000);
        assert!(
            h.validate_resize_config(&FsResizeConfig {
                size: Some(json!("1G")),
                ..c
            })
            .is_ok()
        );

        let c = h
            .parse_check_config(cli_args(&[
                ("target", "/dev/sdz9"),
                ("mode", "repair"),
                ("allow_repair", "yes"),
            ]))
            .unwrap();
        assert_eq!(c.mode, CheckMode::Repair);
        assert!(c.allow_repair);

        let c = h
            .parse_list_mounts_config(cli_args(&[
                ("include_pseudo", "true"),
                ("include_readonly", "false"),
                ("timeout_ms", "100"),
            ]))
            .unwrap();
        assert!(c.include_pseudo && !c.include_readonly);
        assert_eq!(c.timeout_ms, 100);

        let c = h
            .parse_quota_config(cli_args(&[
                ("include_inodes", "false"),
                ("timeout_ms", "42"),
                ("units", "bytes"),
            ]))
            .unwrap();
        assert!(!c.include_inodes && c.include_space && c.resolve_uid_gid);
        assert_eq!(c.timeout_ms, 42);
        assert_eq!(c.units, QuotaUnits::Bytes);

        let c = h
            .parse_quota_summary_config(cli_args(&[
                ("all_subjects", "true"),
                ("include_types", "ext4"),
            ]))
            .unwrap();
        assert!(c.all_subjects);
        assert_eq!(c.include_types, vec!["ext4"]);
        assert_eq!(c.timeout_ms, 8000);

        let c = h
            .parse_usage_config(cli_args(&[
                ("mode", "paths"),
                ("paths", "/a,/b"),
                ("human_readable", "true"),
                ("threshold_used_percent_min", "10.5"),
            ]))
            .unwrap();
        assert_eq!(c.mode, UsageMode::Paths);
        assert_eq!(c.paths, vec!["/a", "/b"]);
        assert!(c.human_readable && c.include_inodes);
        assert_eq!(c.threshold_used_percent_min, Some(10.5));
        assert!(h.validate_usage_config(&c).is_ok());
    }

    #[test]
    fn cli_invalid_typed_args_are_reported() {
        let h = FsHandle::new_for_test("t".to_string());
        assert!(
            h.parse_quota_config(cli_args(&[("timeout_ms", "soon")]))
                .is_err()
        );
        assert!(
            h.parse_usage_config(cli_args(&[("units", "parsecs")]))
                .is_err()
        );
        assert!(
            h.parse_check_config(cli_args(&[("target", "/x"), ("allow_repair", "maybe")]))
                .is_err()
        );
    }

    #[test]
    fn resize_bare_number_string_uses_size_units() {
        let h = FsHandle::new_for_test("t".to_string());
        assert_eq!(
            h.parse_size(&json!("2"), &SizeUnits::Kilobytes).unwrap(),
            2048
        );
        assert_eq!(h.parse_size(&json!("1K"), &SizeUnits::Auto).unwrap(), 1024);
    }

    #[test]
    fn usage_paths_mode_with_cli_list() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        std::fs::create_dir(&a).unwrap();
        let paths = format!("{},{}", a.display(), dir.path().display());
        let h = FsHandle::new_for_test("t".to_string());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let out = rt
            .block_on(h.usage(cli_args(&[("mode", "paths"), ("paths", &paths)])))
            .unwrap();
        assert_eq!(out["mode"], "paths");
        let mapping = out["path_to_filesystem"].as_array().unwrap();
        assert_eq!(mapping.len(), 2);
    }

    #[test]
    fn help_verb_renders_approved_help() {
        let h = FsHandle::new_for_test("t".to_string());
        let mut stdin = std::io::empty();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut io = IoStreams::new(&mut stdin, &mut out, &mut err);
        h.call("help", &Args::new(), &mut io).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("Handle: fs"));

        let mut stdin = std::io::empty();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut io = IoStreams::new(&mut stdin, &mut out, &mut err);
        let args: Args = [("verb".to_string(), "resize".to_string())]
            .into_iter()
            .collect();
        h.call("help", &args, &mut io).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("Handle: fs\nVerb: resize"));
    }
}

// v1.0.5-beta: mount and umount operands cannot be read as options.
#[cfg(test)]
mod mount_argument_tests {
    use super::*;

    fn handle() -> FsHandle {
        FsHandle {
            alias: "local".to_string(),
        }
    }

    fn config(source: Option<&str>, target: &str) -> MountConfig {
        MountConfig {
            source: source.map(str::to_string),
            target: target.to_string(),
            r#type: Some("ext4".to_string()),
            dry_run: true,
            ..Default::default()
        }
    }

    #[test]
    fn option_shaped_source_or_target_is_refused() {
        let h = handle();
        for (source, target, field) in [
            (Some("-Pprobe"), "/mnt/x", "source"),
            (Some("--probe"), "/mnt/x", "source"),
            (Some("/dev/sdb1"), "-probe", "target"),
            (None, "--probe-target-only", "target"),
            (Some("-"), "/mnt/x", "source"),
        ] {
            let err = h
                .validate_mount_config(&config(source, target))
                .expect_err(&format!("{source:?} {target}"));
            assert!(
                err.to_string()
                    .contains(&format!("{field} cannot start with '-'")),
                "{err}"
            );
        }
    }

    #[test]
    fn ordinary_sources_and_targets_are_accepted() {
        let h = handle();
        for (source, target) in [
            (Some("/dev/sdb1"), "/mnt/usb"),
            (Some("server:/export"), "/mnt/nfs"),
            (Some("//host/share"), "/mnt/smb"),
            (Some("UUID=1234-abcd"), "/mnt/data"),
            (Some("tmpfs"), "/mnt/a-b"),
            (Some("/data/-odd-name"), "/mnt/-odd"),
            (None, "/mnt/fstab-entry"),
            // Relative targets still only warn
            (Some("/dev/sdb1"), "mnt/rel"),
        ] {
            assert!(
                h.validate_mount_config(&config(source, target)).is_ok(),
                "{source:?} {target}"
            );
        }
    }

    #[test]
    fn planned_mount_puts_operands_after_a_separator() {
        let h = handle();
        let mut c = config(Some("/dev/sdb1"), "/nonexistent/resh-7a-mnt");
        c.options = vec!["noatime".to_string()];
        c.create_target = false;
        let r = h.create_mount_plan(&c, false).unwrap();
        assert_eq!(
            r.plan.unwrap().mount_commands,
            vec!["mount -t ext4 -o noatime -- /dev/sdb1 /nonexistent/resh-7a-mnt"]
        );

        let c = config(None, "/nonexistent/resh-7a-mnt");
        let r = h.create_mount_plan(&c, false).unwrap();
        assert!(r.plan.unwrap().mount_commands[0].ends_with(" -- /nonexistent/resh-7a-mnt"));
    }

    #[test]
    fn option_shaped_values_are_refused_through_the_handle() {
        let h = handle();
        for (k, v) in [("source", "-Pprobe"), ("target", "-probe")] {
            for dry_run in ["true", "false"] {
                let mut args = Args::new();
                args.insert("target".into(), "/nonexistent/resh-7a-mnt".into());
                args.insert("source".into(), "/dev/null".into());
                args.insert(k.into(), v.into());
                args.insert("dry_run".into(), dry_run.into());
                let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
                let mut io = IoStreams {
                    stdin: &mut i,
                    stdout: &mut o,
                    stderr: &mut e,
                };
                let st = h.call("mount", &args, &mut io).unwrap();
                assert!(!st.ok, "{k}={v} dry_run={dry_run}");
                assert!(!std::path::Path::new(v).exists());
                assert!(!std::path::Path::new("/nonexistent/resh-7a-mnt").exists());
            }
        }
    }
}
