# Resource Shell (resh) – Filesystem Handle Documentation

## 1. Overview

The `fs://` handle works with mounted filesystems on the local Linux host:
mount and unmount, mount-table listing and lockfile snapshots, disk usage,
quotas, resizing and consistency checks. It reads `/proc/mounts` and
`statvfs` data and runs system tools: `mount`, `umount`, `df`, `quota`,
`resize2fs`, `xfs_growfs`, `btrfs`, `fsck`, `xfs_repair`, and
`lvextend`/`lvreduce` when volume management is requested.

Most changing operations (mount, unmount, resize, repair) need root.
Platform: Linux only is supported and tested.

---

## 2. Command Syntax

```text
resh fs://<alias>.<verb> key=value ...
resh 'fs://<alias>.<verb>(key=value,...)'
```

The URL host (`local`, `system`, ...) is a free-form alias that is echoed
back in the JSON result as `alias`. It does not select a profile or a
remote host.

List arguments (`options`, `paths`, `include_types`, ...) are given as
comma-separated values, e.g. `include_types=ext4,xfs`.

Help: `resh fs --help`, `resh fs <verb> --help`, or the `help`/`h` verb.

### Verbs

| Verb | Description |
| ---- | ----------- |
| `list-mounts` | Mount table with options and read-only/pseudo/network/loop flags |
| `usage` | Size, used, free and inodes per filesystem, per path, or aggregated |
| `snapshot` | Current mount table as an `fs-lock/v1` lockfile string |
| `quota` | Quota usage and limits of one user/group/project on one filesystem |
| `quota_summary` | Quota of one user or group across all mounted filesystems |
| `mount` | Mount a device, network share or bind source |
| `unmount` / `umount` | Unmount by mount point or source device |
| `resize` | Grow or shrink a filesystem (see the warnings in 3.7) |
| `check` / `fsck` | Check (and optionally repair) a filesystem |

Every verb prints one JSON object on success.

### Exit status

0 on success. Failures use the codes mapped in the handle source:

| Verb | Codes |
| ---- | ----- |
| all | 1 invalid arguments, 32 tool/operation failure, 62 timeout, 95 unknown verb |
| `mount` | 3 unsupported, 13 permission denied, 16 already mounted, 17 conflicting mount, 18 target directory could not be created, 19 not mounted |
| `unmount` | 3 unsupported, 13 permission denied, 16 busy, 19 not mounted, 95 unsupported option |
| `snapshot`, `list-mounts` | 3 unsupported |
| `quota` | 3 unsupported (for example the `quota` tool is missing), 4 quotas not enabled, 5 subject not found |
| `quota_summary` | 3 unsupported, 4 no filesystem with quotas, 5 subject not found |
| `usage` | 2 path not found, 3 unsupported, 4 nothing selected |
| `resize` | 2 target not found, 3 unsupported filesystem, 4 shrink not allowed, 5 shrink not supported for this filesystem, 6 shrink requires unmount, 7 would violate `min_free_space_percent`, 8 target exceeds device, 9 invalid target size, 10 volume management unsupported |
| `check` | 2 target not found, 3 unsupported filesystem, 4 repair not allowed, 5 repair requires unmount, 6 must be offline, 7 tool not available |

The reason is printed on stderr as `Error: <reason>`.

### timeout_ms

Every fs verb enforces `timeout_ms`: the operation is abandoned and the
command exits 62 when it runs longer. Defaults: 5000 ms for `mount`,
`unmount`, `snapshot`, `quota` and `usage`; 8000 ms for `quota_summary`;
3000 ms for `list-mounts`; 600000 ms (10 minutes) for `resize` and `check`.
`timeout_ms=0` selects the default for `mount`, `unmount`, `snapshot`,
`quota`, `quota_summary` and `list-mounts`, and is rejected (exit 1) by
`usage`, `resize` and `check`. A timeout stops resh waiting; it does not
stop an external tool already started (for example `mount`, `lvextend`,
`resize2fs` or `fsck`). Such a tool either keeps running and completes
after resh has reported the timeout, or is killed by `SIGPIPE` the next
time it writes output, possibly part-way through. A multi-step `resize`
can therefore leave the volume and the filesystem at different sizes;
check them after a timeout.

### Boolean arguments

For `usage`, `snapshot`, `quota`, `quota_summary`, `resize`, `check` and
`list-mounts`, booleans accept `true/false/1/0/yes/no/on/off` and any other
value is an error (exit 1). For `mount` and `unmount`, `dry_run` is
parsed the same strict way (a mistyped `dry_run=ture` is an error and
nothing is mounted or unmounted), but their other booleans (`force`,
`lazy`, `read_only`, ...) treat `true/1/yes/on` as true and every other
value as false.

---

## 3. Verb Reference

### 3.1 list-mounts

```bash
resh --json-pretty fs://local.list-mounts
resh fs://local.list-mounts include_types=ext4,xfs include_pseudo=false
```

Arguments: `paths`, `include_mountpoints`, `exclude_mountpoints`,
`include_types`, `exclude_types`, `include_sources`, `exclude_sources`,
`include_readonly` (default `true`), `include_readwrite` (`true`),
`include_pseudo` (`false`), `include_loop` (`true`), `include_network`
(`true`), `normalize_paths`, `resolve_labels`, `resolve_fs_features`,
`timeout_ms`.

### 3.2 usage

```bash
resh --json-pretty fs://local.usage units=megabytes
resh fs://local.usage mode=aggregate human_readable=true
resh fs://local.usage mode=paths paths=/var,/home
resh fs://local.usage threshold_used_percent_min=80
```

| Argument | Notes |
| -------- | ----- |
| `mode` | `mounts` (default), `paths` (needs `paths`, adds `path_to_filesystem`), `aggregate` (adds an `aggregate` object) |
| `units` | `auto`, `bytes`, `kilobytes`, `megabytes`, `gigabytes`, `blocks` |
| `human_readable` | Adds `size_human`, `used_human`, `free_human` strings |
| `threshold_used_percent_min` / `_max` | Keep only filesystems within the range (0-100) |
| `include_inodes`, `include_readonly`, include/exclude filters | as for `list-mounts` |

Mounts whose usage cannot be read are skipped and listed in `warnings`.

### 3.3 snapshot

```bash
resh --json-pretty fs://local.snapshot format=json
resh fs://local.snapshot format=text include_usage=false
```

Arguments: `format=json|yaml|text`, `include_usage` (default `true`),
`include_inodes`, `include_fs_metadata`, `include_os_metadata`,
`normalize_paths`, the include/exclude filters, `timeout_ms`.

The result is a JSON object whose `lockfile` field holds the lockfile as a
string (`fs-lock/v1`: generation time, alias, host, filters, one entry per
mount), plus a `parsed` summary. `format=yaml` currently produces the same
JSON text as `format=json`. Nothing is written to disk.

### 3.4 quota

```bash
resh --json-pretty fs://local.quota path=/home subject=alice
```

Arguments: `path` (default `/`), `subject` (default current user),
`subject_type=auto|user|group|project`, `units=auto|blocks|bytes`,
`include_space`, `include_inodes`, `include_grace`, `resolve_uid_gid`,
`timeout_ms`. Requires the `quota` tool; without it the command exits 3
("Quota operations are not supported on this platform").

`all_subjects=true` is not implemented: it fails with
"all_subjects=true is not yet implemented" (exit 32).

### 3.5 quota_summary

```bash
resh --json-pretty fs://local.quota_summary subject=alice
```

Same arguments as `quota` (without `path`) plus the include/exclude
filters. Filesystems without quotas are listed in
`filesystems_without_quotas`. `all_subjects=true` is not implemented
(exit 32).

### 3.6 mount / unmount

```bash
resh --json-pretty fs://local.mount target=/mnt/usb source=/dev/sdb1 type=ext4 dry_run
resh fs://local.mount target=/mnt/data source=/dev/sdb1 create_target=true options=noexec,nosuid,nodev
resh fs://local.mount target=/mnt/nfs source=server:/export type=nfs network=true
resh fs://local.mount target=/srv/chroot/data source=/data bind=true read_only=true
resh --json-pretty fs://local.unmount target=/mnt/usb
resh fs://local.unmount target=/dev/sdb1 by=source detach_children=true
```

`mount` arguments: `target` (required), `source`, `type`, `options`
(comma-separated), `read_only` (adds `ro`), `bind`, `remount`, `network`,
`create_target`, `make_parents`, `fail_if_mounted`, `dry_run`,
`timeout_ms`. An existing compatible mount returns action
`already_mounted`; `dry_run` returns action `planned` with a `plan`.
`source` and `target` must not start with `-`; they are passed to `mount`
after `--`, so they are never read as options. A relative `target` still
only prints a warning and is resolved from the current directory.

`unmount` arguments: `target` (required), `by=target|source|auto`, `force`,
`lazy`, `detach_children`, `fail_if_not_mounted`, `dry_run`, `timeout_ms`.

See the boolean warning in section 2 for these two verbs.

### 3.7 resize

```bash
resh --json-pretty fs://local.resize target=/data size=200G dry_run
resh fs://local.resize target=/data delta=+50G dry_run
```

Arguments: `target` (required), exactly one of `size` or `delta`,
`by=auto|mountpoint|device`, `size_units` (unit for bare numbers),
`mode=grow|shrink|auto`, `allow_shrink`, `min_free_space_percent`,
`manage_underlying_volume` (LVM only: runs `lvextend`/`lvreduce`),
`volume_resize_only`, `filesystem_resize_only`,
`require_unmounted_for_shrink`, `force`, `dry_run`, `timeout_ms`.
Sizes accept `K`, `M`, `G`, `T` suffixes (powers of 1024). A size equal to
the current size returns action `noop`. Shrinking needs
`allow_shrink=true`, is refused for xfs, and needs an unmounted ext3/ext4
filesystem.

Known problems (always run with `dry_run` first and read the planned
command):

* **ext3/ext4 size argument.** `resize2fs` receives the target size in
  KiB (`size=200G` gives `resize2fs <dev> 209715200K`). Earlier builds
  divided by 4096 instead and asked for a quarter of the requested size;
  check the planned command with `dry_run` before resizing.
* **A negative `delta` never works.** `delta=-10G` is rejected with
  "calculated size cannot be negative". To shrink, pass the absolute
  target with `size=`.

### 3.8 check / fsck

```bash
resh --json-pretty fs://local.check target=/dev/sdb1
resh fs://local.check target=/dev/sdb1 mode=repair allow_repair=true dry_run
```

Arguments: `target` (required), `by=auto|mountpoint|device`,
`filesystem_type`, `mode=check|repair|auto`, `allow_repair`,
`aggressiveness=safe|normal|aggressive`, `allow_online_check`,
`require_unmounted_for_repair`, `skip_if_mounted`, `force`,
`btrfs_use_scrub`, `btrfs_allow_offline_check`, `dry_run`, `timeout_ms`.
`mode=check` (default) is read-only (`fsck -n`). `mode=repair` with
`allow_repair=true` runs `fsck -p`, `xfs_repair` or `btrfs check --repair`
on an unmounted filesystem. `max_pass` is accepted but has no effect.

---

## 4. Limitations

* `resize` cannot use negative deltas (see 3.7).
* `quota` and `quota_summary` with `all_subjects=true` are not implemented.
* `snapshot format=yaml` outputs JSON.
* `mount`/`unmount` silently treat unrecognized boolean values as false.
* Linux only.

---

## 5. Best Practices

* Run `mount`, `unmount`, `resize` and `check mode=repair` with `dry_run`
  first, and inspect the `plan`.
* Run `check` before resizing; keep `allow_shrink` and `allow_repair` off
  unless needed.
* Capture `fs://local.snapshot` before maintenance and keep the output.
* Exclude pseudo filesystems (the default for `list-mounts`) in monitoring.
