# Resource Shell (resh) – Filesystem Handle Documentation

## 1. Overview

The `fs://` handle works with mounted filesystems on the local Linux host:
mount and unmount, mount-table listing and lockfile snapshots, disk usage,
quotas, resizing and consistency checks. It reads the mount table
(`/proc/self/mounts`) and runs system tools: `mount`, `umount`, `df`,
`quota`, `repquota`, `blkid`, `blockdev`, `lsblk`, `dumpe2fs`, `tune2fs`,
`resize2fs`, `xfs_info`, `xfs_growfs`, `btrfs`, `fsck.<type>`, `xfs_repair`,
and `lvextend`/`lvreduce` when volume management is requested.

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
comma-separated values, e.g. `include_types=ext4,xfs`. An empty item
(`a,,b`) is an error.

Help: `resh fs --help`, `resh fs <verb> --help`, or the `help`/`h` verb
(`resh fs://local.help verb=mount`). Each verb's usage lists exactly the
arguments it accepts.

### Verbs

| Verb | Description |
| ---- | ----------- |
| `list-mounts` | Mount table with options and read-only/pseudo/network/loop flags |
| `usage` | Size, used, free and inodes per filesystem, per path, or aggregated |
| `snapshot` | Current mount table as an `fs-lock/v1` lockfile string (JSON, YAML or text) |
| `quota` | Quota usage and limits of one user/group/project, or of every subject, on one filesystem |
| `quota_summary` | Quota of one subject, or of every subject, across the mounted filesystems |
| `mount` | Mount a device, image file, network share or bind source |
| `unmount` / `umount` | Unmount by mount point or source device |
| `resize` | Grow or shrink a filesystem (and optionally its LVM volume) |
| `check` / `fsck` | Check (and optionally repair) a filesystem |

Every verb prints one JSON object on success.

### Arguments are checked before anything is done

Every verb refuses, with exit status 2 and nothing done:

* an argument it does not accept (the message names it and suggests the
  closest accepted name, e.g. `unknown argument "read_onyl" for fs mount;
  did you mean "read_only"?`), including `dry_run` on a verb without a dry
  run (`list-mounts`, `usage`, `snapshot`, `quota`, `quota_summary`);
* a value it cannot read: a boolean other than
  `true/false/1/0/yes/no/on/off`, a number that is not a number, a value
  outside an enumeration (`mode`, `units`, `by`, ...), an empty list item;
* contradictory or incomplete arguments (listed per verb below);
* a `target`, `source` or `subject` that starts with `-`.

This is stricter than v1.0.6-beta, where unknown arguments were ignored and
`mount`/`unmount` read an unrecognised boolean as false.

### Exit status

| Status | Meaning |
| ------ | ------- |
| 0 | Success. `check` also exits 0 when it finds errors: they are reported in `analysis`. |
| 1 | The operation failed: target or subject not found, refused by the system or by a policy (for example a mounted filesystem that must be unmounted), a tool missing or failing, or a partial failure (`unmount` prints the result object first). |
| 2 | Invalid usage or arguments; nothing was done. |
| 124 | Timeout: `timeout_ms` passed. If an external tool was running, resh stopped it and every process it started and prints `Error: outcome unknown: <tool> was stopped; it may already have made changes, so check before retrying`. |

The reason is printed on stderr as `Error: <reason>`. The conditions per
verb are listed in each verb's section.

### timeout_ms

Every verb enforces `timeout_ms` for the whole operation. Defaults: 5000 ms
for `mount`, `unmount`, `snapshot`, `quota` and `usage`; 8000 ms for
`quota_summary`; 3000 ms for `list-mounts`; 600000 ms (10 minutes) for
`resize` and `check`. `timeout_ms=0` selects the default for `mount`,
`unmount`, `snapshot`, `quota`, `quota_summary` and `list-mounts`, and is
refused (exit 2) by `usage`, `resize` and `check`.

Each external tool runs in its own process group. When the deadline
passes, resh stops the tool and everything it started (SIGTERM, then
SIGKILL) and exits 124, also when the verb could carry on without that
tool (for example `usage` skipping a mount): the result printed is then
incomplete. Stopping a tool does not undo what it already did:
a multi-step `resize` (for example `lvextend` then `resize2fs`) can leave
the volume and the filesystem at different sizes, so check them after a
timeout.

---

## 3. Verb Reference

Mount point filters (`include_mountpoints`, `exclude_mountpoints`) and the
`paths` arguments match whole path components: `/home` matches `/home` and
`/home/a`, not `/homex`. Type and source filters match exactly. Mount table
fields with spaces (`/mnt/my disk`) are decoded.

### 3.1 list-mounts

```bash
resh --json-pretty fs://local.list-mounts
resh fs://local.list-mounts include_types=ext4,xfs include_pseudo=false
resh fs://local.list-mounts paths=/var/log,/home resolve_labels=true
```

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `paths` | | Only the mounts backing these paths |
| `include_readonly`, `include_readwrite` | `true` | Setting both false is an error |
| `include_pseudo` | `false` | proc, sysfs, tmpfs, cgroup, ... |
| `include_loop`, `include_network` | `true` | Loop: source `/dev/loopN`; network: nfs/cifs/sshfs/... or `host:/path`, `//host/share` |
| `normalize_paths` | `true` | Collapse repeated and trailing slashes |
| `resolve_labels` | `false` | Adds `device` (label, uuid, partlabel, partuuid) from `blkid` |
| `resolve_fs_features` | `false` | Adds `fs_features`: ext (`tune2fs -l`), xfs (`xfs_info`), btrfs (superblock flags); omitted when the device cannot be read (usually needs root) |
| include/exclude filters, `timeout_ms` | | |

Errors: 2 for invalid arguments; 1 when the mount table cannot be read.

### 3.2 usage

```bash
resh --json-pretty fs://local.usage units=megabytes
resh fs://local.usage mode=aggregate human_readable=true
resh fs://local.usage mode=paths paths=/var,/home
resh fs://local.usage threshold_used_percent_min=80
```

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `mode` | `mounts` | `mounts`, `paths` (needs `paths`, adds `path_to_filesystem`), `aggregate` (adds an `aggregate` object) |
| `paths` | | Only with `mode=paths` (otherwise exit 2) |
| `units` | `auto` | `auto` and `bytes` report bytes; `kilobytes`, `megabytes`, `gigabytes` (powers of 1024), `blocks` (512 bytes) |
| `human_readable` | `false` | Adds `size_human`, `used_human`, `free_human` |
| `include_inodes` | `true` | |
| `include_readonly` | `true` | |
| `normalize_paths` | `true` | |
| `threshold_used_percent_min` / `_max` | | Keep only filesystems within the range (0-100, min <= max) |
| include/exclude filters, `timeout_ms` | | |

Usage comes from `df -P` under the deadline. Mounts whose usage cannot be
read (for example a stale network mount) are skipped and listed in
`warnings`. Errors: 2 for invalid arguments; 1 for a path that does not
exist, filters that select no filesystem ("No filesystems selected after
applying filters"), or an unreadable mount table. Thresholds may leave an
empty `filesystems` list (exit 0).

### 3.3 snapshot

```bash
resh --json-pretty fs://local.snapshot format=json
resh fs://local.snapshot format=yaml include_usage=false
```

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `format` | `json` | `json`, `yaml` or `text` |
| `include_usage` | `true` | Size, used, free bytes per mount |
| `include_inodes` | `false` | |
| `include_fs_metadata` | `true` | Block size, blocks, device major:minor |
| `include_os_metadata` | `true` | Host name, OS name and version (`VERSION_ID`), kernel, architecture |
| `normalize_paths` | `true` | |
| include/exclude filters, `timeout_ms` | | |

The result is a JSON object whose `lockfile` field holds the lockfile as a
string (`fs-lock/v1`: generation time, alias, host, filters, one entry per
mount, sorted by target) plus a `parsed` summary. Nothing is written to
disk. Errors: 2 for invalid arguments; 1 when the mount table cannot be
read.

### 3.4 quota

```bash
resh --json-pretty fs://local.quota path=/home subject=alice
resh fs://local.quota path=/home subject=developers subject_type=group
resh fs://local.quota path=/home all_subjects=true
```

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `path` | `/` | The filesystem holding this path is queried |
| `subject` | current user | Name or numeric id |
| `subject_type` | `auto` | `auto` (user, then group), `user`, `group`, `project` (id, or a name from `/etc/projid`) |
| `all_subjects` | `false` | Every subject on the filesystem, from `repquota` (usually needs root); not with `subject` |
| `units` | `auto` | `auto`/`bytes`: bytes; `blocks`: the 1 KiB blocks `quota` reports |
| `include_space`, `include_inodes` | `true` | At least one must be true |
| `include_grace` | `true` | false removes `grace_exceeded` and `grace_time_remaining_sec` |
| `resolve_uid_gid` | `true` | false passes the subject to `quota` as given (no user/group lookup) |
| `timeout_ms` | 5000 | |

Uses `quota -v -w -p` (or `repquota -O csv -p`). A limit of 0 is reported
as `null` (no limit). `grace_time_remaining_sec` is the time left in a
running grace period, `grace_exceeded` is true once it has ended.

Errors: 2 for invalid arguments; 1 when the path does not exist ("Path not
found"), the subject does not exist ("Quota subject not found"), the
filesystem has no quotas enabled ("Quotas are not enabled on the target
filesystem"), the `quota`/`repquota` tool is missing ("Quota operations
are not supported here"), or the tool fails.

### 3.5 quota_summary

```bash
resh --json-pretty fs://local.quota_summary subject=alice
resh fs://local.quota_summary all_subjects=true include_types=ext4,xfs
```

Same arguments as `quota` (without `path`) plus the include/exclude
filters; default `timeout_ms` 8000. Pseudo filesystems are not considered,
and a device mounted at several places counts once. Filesystems without
quotas are listed in `filesystems_without_quotas`. With
`all_subjects=true` the result has a `subjects` list with one total per
subject (and no `summary`); a filesystem whose `repquota` run fails is
listed in `partial_failures`.

Errors: 2 for invalid arguments; 1 when no filesystem matches the filters
or none of them has quotas ("No filesystems with quotas enabled found"),
the subject does not exist, the tools are missing, or every `repquota`
run fails.

### 3.6 mount / unmount

```bash
resh --json-pretty fs://local.mount target=/mnt/data source=/srv/disk.img
resh fs://local.mount target=/mnt/usb source=/dev/sdb1 type=ext4 dry_run
resh fs://local.mount target=/mnt/data source=/dev/sdb1 options=noexec,nosuid,nodev
resh fs://local.mount target=/mnt/nfs source=server:/export type=nfs network=true
resh fs://local.mount target=/srv/chroot/data source=/data bind=true read_only=true
resh fs://local.mount target=/mnt/data remount=true options=ro
resh --json-pretty fs://local.unmount target=/mnt/data
resh fs://local.unmount target=/dev/sdb1 by=source detach_children=true
```

`mount` arguments:

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `target` | required | A relative target is resolved from the current directory |
| `source` | | Device, image file (attached to a loop device by mount), `host:/path`, or a directory for `bind` |
| `type` | | Filesystem type name |
| `options` | | Comma-separated mount options; no whitespace |
| `read_only` | `false` | Adds `ro` |
| `bind` | `false` | Needs `source` |
| `remount` | `false` | Changes the options of an existing mount; not with `fail_if_mounted` |
| `network` | `false` | Declares a network share: `source` must be `host:/path` or `//host/share`, and a given `type` must be a network type |
| `create_target` | `true` | Create a missing target directory |
| `make_parents` | `true` | Also create missing parents |
| `fail_if_mounted` | `false` | Fail when something is mounted at the target |
| `dry_run`, `timeout_ms` | | |

An existing mount with the same source (also through `/dev/disk/by-*`
symlinks, `UUID=`/`LABEL=` tags, or the image file behind a loop device)
and type returns action `already_mounted`; `dry_run` returns action
`planned` with a `plan` and creates nothing. `source` and `target` are
passed to `mount` after `--`. If the mount fails, the directories it
created are removed again.

`mount` errors: 2 for invalid arguments; 1 for a target that is a
symbolic link (mount would follow it, so it is refused), a different mount
at the target ("Conflicting mount"), `fail_if_mounted` with a mount present,
`remount` with nothing mounted ("Target is not mounted"), a missing target
with `create_target=false` or missing parents with `make_parents=false`,
permission denied (not root), a missing `mount` tool, or `mount` failing
(its message is included).

`unmount` arguments: `target` (required), `by=target|source|auto` (default
`target`; `auto` tries the mount point, then the source), `force` (`-f`),
`lazy` (`-l`), `detach_children` (unmount mounts below the target first,
deepest first), `fail_if_not_mounted`, `dry_run`, `timeout_ms`. A target
that is not mounted gives action `already_unmounted` (exit 0).

`unmount` errors: 2 for invalid arguments; 1 for nothing mounted with
`fail_if_not_mounted=true`, a missing `umount` tool, or any mount that
could not be unmounted (busy, permission denied, ...). In that last case
the result object is still printed on stdout, with `unmounted`, `skipped`
(a parent whose child could not be unmounted) and `errors` (each with a
code such as `fs.unmount_busy`), and `action` `failed` or
`partially_unmounted`.

### 3.7 resize

```bash
resh --json-pretty fs://local.resize target=/mnt/data size=2G
resh fs://local.resize target=/data delta=+50G dry_run
resh fs://local.resize target=/dev/sdb1 delta=-10G mode=shrink allow_shrink=true
resh fs://local.resize target=/data size=200G manage_underlying_volume=true
```

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `target` | required | Mount point or device/image file |
| `size` / `delta` | | Exactly one. `K`, `M`, `G`, `T` suffixes are powers of 1024; a bare number counts `size_units`. `delta` may be negative. |
| `by` | `auto` | `auto` (mount point, then device), `mountpoint`, `device` |
| `size_units` | `auto` | Unit of a bare number: `auto`/`bytes`, `kilobytes`, `megabytes`, `gigabytes`, `terabytes` |
| `mode` | `grow` | `grow`, `shrink` or `auto` (either way) |
| `allow_shrink` | `false` | Required to shrink |
| `min_free_space_percent` | `5` | A shrink must leave this much of the new size free |
| `manage_underlying_volume` | `false` | Resize the LVM logical volume too (`lvextend` before growing, `lvreduce` after shrinking) |
| `volume_resize_only` | `false` | Only the volume (needs `manage_underlying_volume`; not for shrinking) |
| `filesystem_resize_only` | `false` | Only the filesystem |
| `require_unmounted_for_shrink` | `true` | ext3/ext4 shrinks need an unmounted filesystem |
| `force` | `false` | ext3/ext4 only: `resize2fs -f` (for example an unmounted filesystem that was not checked recently) |
| `dry_run`, `timeout_ms` | | |

Supported: ext3/ext4 (`resize2fs`, online grow, offline shrink), xfs
(`xfs_growfs -D <blocks>`, grow only, mounted), btrfs (`btrfs filesystem
resize <devid>:<bytes>`, grow and shrink, mounted). The current size is
the filesystem's own size (ext: `dumpe2fs`, xfs: `xfs_info`, btrfs: the
superblock), not what `df` shows. A size equal to it returns action
`noop`. Every check is made before the first command that changes
anything runs; `dry_run` returns the planned commands.

Errors: 2 for invalid arguments, `size` or resulting size 0 or less, a
shrink with `allow_shrink=false`, a shrink with `mode=grow` or a grow with
`mode=shrink`, `force` for xfs/btrfs, `volume_resize_only` with a shrink.
1 for a target that is not found, an unsupported filesystem (or xfs/btrfs
not mounted), xfs shrink, an ext shrink while mounted, a shrink below
`min_free_space_percent` (or when the space used cannot be read), a size
larger than the device without volume management, a device that is not an
LVM volume with `manage_underlying_volume`, a missing or failing tool
(the message lists the commands already done).

### 3.8 check / fsck

```bash
resh --json-pretty fs://local.check target=/srv/disk.img
resh fs://local.check target=/dev/sdb1 mode=repair allow_repair=true dry_run
resh fs://local.check target=/mnt/data skip_if_mounted=true
```

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `target` | required | Mount point, block device or image file |
| `by` | `auto` | `auto`, `mountpoint`, `device` |
| `filesystem_type` | detected | One of ext2, ext3, ext4, vfat, xfs, btrfs |
| `mode` | `check` | `check` (read-only), `repair` (needs `allow_repair=true`), `auto` (repair when allowed and possible, else check) |
| `allow_repair` | `false` | |
| `aggressiveness` | `safe` | ext only. check: `-n`, plus `-f` (full check) for `normal`/`aggressive`. repair: `-p` (preen), or `-y` for `aggressive`, plus `-f` for `normal`/`aggressive` |
| `force` | `false` | ext: `-f`; btrfs: `btrfs check --force` |
| `allow_online_check` | `true` | false refuses any mounted filesystem |
| `require_unmounted_for_repair` | `true` | false lets an ext filesystem mounted read-write be repaired (e2fsck itself may still refuse) |
| `skip_if_mounted` | `false` | Return `summary.status` `skipped` for a mounted filesystem |
| `btrfs_use_scrub` | `true` | Mounted btrfs: `btrfs scrub start -B` (`-r` unless repairing) |
| `btrfs_allow_offline_check` | `false` | Mounted btrfs without scrub: `btrfs check --readonly --force` |
| `dry_run`, `timeout_ms` | | |

Tools: `fsck.ext2/3/4` (e2fsck), `fsck.vfat` (`-n` / `-a`), `xfs_repair`
(`-n` unless repairing; refuses a filesystem mounted read-write), `btrfs`.
A repair needs an unmounted filesystem; an ext filesystem mounted
read-only may also be repaired. Results are in `analysis`
(`errors_found`, `repaired`, `needs_repair`, `filesystem_state`:
`clean`, `errors_detected` or `repaired`) with exit 0.

Errors: 2 for invalid arguments (including `mode=repair` without
`allow_repair`, an unsupported `filesystem_type`, `aggressiveness` other
than `safe` for non-ext filesystems, `force` for xfs/vfat). 1 for a target
that is not found (or a directory that is not a mount point), no
filesystem or an unsupported one on the target, a repair of a mounted
filesystem, a mounted filesystem with `allow_online_check=false` (and a
mounted xfs/vfat, or a mounted btrfs with neither scrub nor
`btrfs_allow_offline_check`), a missing tool ("Check tool not available"),
or a tool that fails to run its check (for example e2fsck status 8 and
above, `btrfs scrub` status 1/2): the message includes its status and
output.

---

## 4. Limitations

* Linux only.
* `quota` and `quota_summary` report only what `quota -v` lists, that is
  filesystems with quota accounting on; quotas of a subject other than the
  caller, and `all_subjects=true`, usually need root.
* `resize` of a multi-device btrfs filesystem resizes the device the
  target names (devid 1 when it is given by mount point).
* After `xfs_repair` without `-n`, a status of 0 is reported as `clean`:
  the tool does not say whether it changed anything.

---

## 5. Best Practices

* Run `mount`, `unmount`, `resize` and `check mode=repair` with `dry_run`
  first, and inspect the `plan`.
* Run `check` before resizing; keep `allow_shrink` and `allow_repair` off
  unless needed.
* Capture `fs://local.snapshot` before maintenance and keep the output.
* Exclude pseudo filesystems (the default for `list-mounts`) in monitoring.

## 6. Tests

Every verb is tested through the handle with fake tools and a fake mount
table (`src/handles/filesystem/fsh_tests.rs`), through the binary
(`tests/fs_verbs.rs`, `tests/fs_help.rs`), and as root against real ext4,
xfs, btrfs and vfat images, loop devices and quotas in a privileged Docker
container (`cargo test --features e2e-docker --test fs_docker`).
