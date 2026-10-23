# Resource Shell (resh) – Filesystem & Storage Documentation

## 1. Overview

The Filesystem & Storage category has four handles:

| Handle | Purpose | Details |
| ------ | ------- | ------- |
| `file://` | Read, write, inspect, hash, search, copy/move/delete files; permissions, extended attributes, tags | [file.md](file.md) |
| `archive://` | Create, list, test, inspect, extract and modify tar, tar.gz, zip and gzip archives (tar.xz / tar.zst read-only) | [archive.md](archive.md) |
| `fs://` | Mounted filesystems: list, usage, mount table snapshot, quotas, mount/unmount, resize, check | [fs.md](fs.md) |
| `snapshot://` | Full local copies of a file or directory, with diff, list and restore | [snapshot.md](snapshot.md) |

Platform: Linux only is supported and tested. Nothing here has been built
or tested on macOS or Windows.

---

## 2. Command Syntax

```text
resh <scheme>://<target>.<verb> key=value ...
resh '<scheme>://<target>.<verb>(key=value,...)'
```

The verb is the part after the last dot of the URL. What the target means
differs per handle:

| Handle | Target | Example |
| ------ | ------ | ------- |
| `file` | The file or directory path (absolute with three slashes, or relative) | `file:///etc/hosts.read` |
| `archive` | Empty; every path is an argument. The dot is still required | `archive://.list archive=a.tar.gz` |
| `fs` | A free-form alias echoed back in the result | `fs://local.usage` |
| `snapshot` | The target path (`create`, `diff`, `ls`) or the snapshot name (`restore`) | `snapshot:///srv/app.ls` |

Help for any handle: `resh <handle> --help` and
`resh <handle> <verb> --help`. Add `--json-pretty` before the stage for
indented JSON.

Each `resh` invocation is a separate process. State persists only where a
handle writes it to disk: `snapshot://` stores its copies under
`$XDG_STATE_HOME/resh/snapshots` (default `~/.local/state/resh/snapshots`).

### Exit status and output

Exit code 0 means success. On failure the exit code is the handle's code
(see each handle page) or 1, and the reason is printed on stderr as
`Error: <reason>`. There is no shared response envelope: each handle prints
its own JSON shape (or raw content, for example `file://...read`).

---

## 3. Examples

Files:

```bash
resh file:///etc/hosts.read
resh file:///tmp/config.yaml.write data='key: value'
resh file:///tmp/source.txt.copy to=/tmp/destination.txt
resh --json-pretty file:///srv/release.tar.gz.sha256
```

Archives:

```bash
resh archive://.create output=release.tar.gz 'sources=["build"]'
resh archive://.test archive=release.tar.gz
resh archive://.extract archive=release.tar.gz destination=deploy
```

Mounted filesystems:

```bash
resh --json-pretty fs://local.usage mode=aggregate
resh fs://local.list-mounts include_types=ext4,xfs
resh fs://local.mount target=/mnt/data source=/dev/sdb1 type=ext4 dry_run
```

Snapshots:

```bash
resh snapshot:///home/user/config.create name=pre-upgrade
resh snapshot:///home/user/config.diff from=pre-upgrade to=live format=summary
resh snapshot://pre-upgrade.restore target=/home/user/config force=true dry_run
```

---

## 4. Important Limitations

The handle pages list all limitations. The ones most likely to matter:

* `file://...write` without `data=` reads standard input and truncates the
  file when standard input is empty.
* `archive://` cannot create tar.xz, tar.zst or 7z archives, cannot read 7z
  at all, and cannot create password-protected archives (`password=` is
  always rejected).
* `fs://...resize` rejects negative deltas; `all_subjects=true` for quotas
  is not implemented.
* `snapshot://` `ls` and `diff` need the absolute target path; an omitted
  `from`/`to` in `diff` is an empty tree, not live; `ttl` is not enforced.

---

## 5. Best Practices

* Take a `snapshot://` copy before changing configuration, and `diff`
  against `live` afterwards.
* Use `dry_run` where offered (`archive remove`, `file replace`,
  `fs mount/unmount/resize/check`, `snapshot restore`).
* Use `archive://.test` and `file://...verify` to check artifacts.
* Set `max_total_bytes`/`max_file_bytes` when extracting untrusted
  archives.
* Check the exit code; read JSON fields, not text output.
