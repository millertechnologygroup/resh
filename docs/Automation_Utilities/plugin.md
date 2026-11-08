# Resource Shell (resh) – Plugin Handle Documentation

## 1. Overview

Resource Shell (resh) is a command-line tool that runs operations on resources named by URLs and reports the results as JSON.

The `plugin://` handle manages resh plugins in a local plugin store: it installs, updates, removes, enables and disables plugins, lists what is installed, and reads plugin catalogs and indexes.

Lifecycle verbs name the plugin before the verb; catalog and listing verbs take no plugin name:

```text
resh plugin://<plugin-id>.<verb> key=value ...     install, update, remove, enable, disable
resh plugin://available.<verb> key=value ...       available.list, available.search, available.info
resh plugin://installed.list key=value ...
```

The older doubled forms `plugin://available.available.list` and `plugin://installed.installed.list` are still accepted. A lifecycle verb with no plugin id (for example `plugin://install`) is an error (exit 2, `plugin.invalid_target`).

Local state (all under the XDG directories of the user running resh):

| What | Location |
| ---- | -------- |
| Plugin store (installed versions) | `$XDG_DATA_HOME/resh/plugins` (default `~/.local/share/resh/plugins`) |
| User enable state (`enable`/`disable`, `scope=user`; read by `installed.list`) | `$XDG_STATE_HOME/resh/plugins/state.json` (default `~/.local/state/...`) |
| System enable state (`scope=system`) | `/var/lib/resh/plugins/state.json` (needs write access there) |
| `available.search` cache | `$XDG_STATE_HOME/resh/plugins/index-cache.json` (default index) or `cache-<url>.json` |
| `available.info` index cache | `$XDG_CACHE_HOME/resh/plugin-indexes/<index>_<channel>.json` (default `~/.cache/...`) |
| Plugin data deleted by `remove purge=true` | `resh/plugins/<plugin-id>` under `$XDG_STATE_HOME`, `$XDG_CACHE_HOME` and `$XDG_CONFIG_HOME` |

### 1.1 Safe locations

Every directory resh uses below these base directories (`resh/`, `resh/plugins/`, the plugin's own directories) must be a real directory, not a symbolic link, owned by the user running resh (or by root), and not writable by group or others. Each base directory itself must belong to that user or to root. Anything else fails with `plugin.unsafe_path` (exit 1) before anything is changed.

So running plugin verbs as root with another user's environment (for example `sudo -E resh plugin://...`, or a sudo policy that keeps `HOME` or `XDG_*`) is refused: those directories belong to that user. Run plugin verbs as the user who owns the store, or as root with root's own `HOME` (`sudo -H`, `sudo -i`).

Files are never written through a symbolic link: state and cache files are written to a new temporary file and renamed into place (state and caches 0600 in 0700 directories; the system state 0644 in a 0755 directory, so every user's `installed.list` can read it). A symbolic link at a file resh reads (`state.json`, a cache, `metadata.json`) is refused with `plugin.unsafe_path`.

---

## 2. Security Model for Installation

`install` and `update` download and unpack third-party code. The rules below are enforced by the code (`src/handles/pluginh/plugin/{registry,engine,store}.rs`, `src/handles/pluginh/net.rs`).

### 2.1 Transport: HTTPS only

* Registry, index and artifact URLs must be `https://` URLs with a host and without a user name or password. Anything else (`http://`, `file://`, a local path) is refused (exit 2) before any connection is made.
* TLS certificates are always verified against the built-in roots. `ca_file=<pem>` adds the certificates of a PEM file (a private CA) for that call; verification stays on. There is no option to turn verification off.
* A redirect is followed (at most 5) only to another `https://` URL.

### 2.2 Integrity: `verify=sha256` (the default)

* A registry entry gives, per platform, an artifact name and a SHA-256. With `verify=sha256`, that SHA-256 must be 64 hexadecimal digits. A missing, empty or malformed checksum fails with `plugin.verify_failed` before anything is downloaded.
* The downloaded artifact is hashed and compared before anything is unpacked. A mismatch (a tampered artifact) fails with `plugin.verify_failed` and nothing is installed; the installed version, if any, stays active.
* **Limit:** the checksum comes from the same registry as the artifact. It proves the artifact was not altered in transit and matches what the registry published. It does **not** prove who published the plugin; there is no signature support. A compromised or malicious registry is not detected; trust rests on HTTPS and on the registry operator.
* `source=url` (and `update url=`) has no trusted checksum, so it is refused under `verify=sha256` (exit 2) and needs an explicit `verify=none`.
* `source=file` (a local file) is accepted under `verify=sha256` without a checksum; no transport is involved.
* `verify=none` skips the checksum. The artifact is then **installed unverified** (the result carries a warning): only HTTPS protects it. Use it only for artifacts you have checked yourself.
* `verify` accepts exactly `sha256` or `none`. Any other value (such as `md5`, `NONE`, `off` or empty) is an error (exit 2) and nothing runs.

### 2.3 Artifact contents

* An artifact whose name ends in `.tar.gz` is unpacked; anything else is installed as a single executable file named like the plugin.
* A `.tar.gz` artifact may contain only regular files and directories with plain relative paths. A symbolic link, hard link, device node, FIFO, absolute path or `..` entry fails the whole install with `plugin.extract_failed`, and nothing is installed. An existing installed version is left untouched.
* File modes are reduced to 0644 or 0755: setuid, setgid and sticky bits and group/other write bits are dropped. Store directories are 0755.
* The archive handle's tar limit applies: more than 1 MiB of tar header data (PAX extended headers, GNU long name or long link headers) before one entry fails the install with `plugin.extract_failed`.
* Size limits: an artifact may be at most 512 MiB (download or local file), hold at most 100,000 entries and unpack to at most 2 GiB. Larger artifacts fail with `plugin.download_failed` or `plugin.extract_failed`.
* The plugin executable is the first regular file of `bin/plugin`, `plugin`, `bin/<os>-<arch>/plugin`, `<plugin-id>`, or else the first executable file at the top level of the artifact.

### 2.4 Plugin ids and versions

* Plugin ids, versions and artifact names taken from a registry must each be a single safe path component: 1-128 characters of `A-Z a-z 0-9 . _ + -`, starting with a letter or digit.
* An id containing `/` (for example `plugin://acme/tool.install`) is refused (exit 2, `plugin.invalid_target`), and the id `locks` is reserved.
* The id is checked before anything is fetched; a registry-supplied version or artifact name is checked before the artifact is downloaded (`plugin.catalog_invalid`). Nothing is written when either check fails.

### 2.5 How an install is applied

The new version is unpacked into a private staging directory (`<store>/.staging/<random>`), then moved to `<store>/<id>/versions/<version>`, and `<store>/<id>/current` is switched to it in one rename. Only then is the old version deleted. A failure or timeout before the switch leaves the installed version active and removes the staged files; nothing half-installed is left behind. Install, update and remove of one plugin take a lock (`<store>/.locks/<id>.lock`), so two of them never run at once; a second one waits, up to its `timeout_ms`.

---

## 3. Response Envelopes

Every verb prints one JSON object on stdout, except when its arguments are refused (exit 2), which prints only the error line. On failure resh also prints `Error: [<code>] <message>` on stderr. Exit codes: 0 success, 1 failed, 2 invalid usage (nothing was done), 124 timeout.

Every envelope has `op`, `ok`, `code` (the exit code), `target`, `args`, `actions`, `result`, `error` and `ts`; `error` is `null` on success and `{"code": "plugin.<name>", "message": "..."}` on failure. On failure `actions` lists the steps that ran, the last one with `ok: false`.

* **install, update, remove, enable, disable**: `target` is an object (`name`, `requested_name`, `install_root`, and `version`/`bin_path` when known); `warnings` is present when there are warnings. Actions have `id`, `type`, `name`, `ok` and optional `details`.
  * install/update `result`: `installed`, `changed`, `version`, `previous_version`.
  * remove `result`: `removed`, `purged`, `installed`, `previous_version`.
  * enable/disable `result`: `installed`, `version`, `scope`, `enabled`, `was_enabled`, `changed`, and `reason` when given.
* **available.list, available.search, available.info, installed.list**: `target` is the stage URL; `warnings` is always present.

Real output of a local-file install dry run (paths shortened):

```json
{
  "op": "plugin.install",
  "ok": true,
  "code": 0,
  "target": { "name": "demo", "requested_name": "demo", "install_root": "/home/alice/.local/share/resh/plugins" },
  "args": { "allow_downgrade": false, "dry_run": true, "force": false, "path": "/home/alice/demo.tar.gz",
            "source": "file", "timeout_ms": 300000, "verify": "sha256", "version": "latest" },
  "actions": [
    { "id": "check_installed-0", "type": "check_installed", "name": "Plugin not installed", "ok": true },
    { "id": "resolve-1", "type": "resolve", "name": "Resolved plugin version: local", "ok": true, "details": { "version": "local" } },
    { "id": "install-2", "type": "install", "name": "Dry run: no changes made", "ok": true,
      "details": { "artifact_kind": "tar.gz", "artifact_path": "/home/alice/demo.tar.gz", "artifact_url": null,
                   "dry_run": true, "from_version": null, "sha256": null, "to_version": "local" } }
  ],
  "result": { "changed": false, "installed": false, "previous_version": null, "version": "local" },
  "error": null,
  "ts": "2026-11-08T13:07:43.301630502+00:00"
}
```

A real install adds `download`, `verify`, `extract`, `install`, `activate` and `cleanup` actions and reports `result.installed: true`. A local file installs as version `local`; a `source=url` artifact as version `unknown`.

A tampered registry artifact:

```text
$ resh plugin://demo.install registry=https://plugins.example.org
Error: [plugin.verify_failed] the artifact's SHA-256 is 3f5a..., but the registry gives 9b1c...; nothing was installed
```

---

## 4. Verbs

Per-verb help: `resh plugin <verb> --help`. Every verb refuses arguments it does not list (exit 2, `plugin.invalid_argument`, with a "did you mean" hint) and malformed values; booleans accept `true/false/1/0/yes/no/on/off`.

### 4.1 install

```bash
resh plugin://demo.install source=file path=/home/alice/demo.tar.gz dry_run=true
resh plugin://demo.install source=file path=/home/alice/demo.tar.gz
resh plugin://aws.install version=1.2.3
resh plugin://aws.install registry=https://plugins.example.org ca_file=/etc/ssl/private-ca.pem
resh plugin://tool.install source=url url=https://example.org/tool.tar.gz verify=none
```

| Argument          | Meaning |
| ----------------- | ------- |
| `source`          | `registry` (default), `url` or `file` |
| `registry`        | Registry base URL (`https://` only) for `source=registry`, default `https://plugins.reshshell.dev`. The entry is fetched from `<registry>/v1/plugins/<id>` and the artifact from `<registry>/v1/artifacts/<id>/<version>/<bin>` |
| `url`             | Artifact URL (`https://` only), required for `source=url` |
| `path`            | Local artifact file, required for `source=file` |
| `version`         | Version to install from the registry (default `latest`, the highest version in semantic-version order: `1.10.0` is newer than `1.9.0`, a pre-release is older than its release) |
| `verify`          | `sha256` (default) or `none`; see 2.2 |
| `force`           | Reinstall the same version, or allow a downgrade |
| `allow_downgrade` | Allow installing a version older than the installed one (otherwise `plugin.downgrade_refused`) |
| `dry_run`         | Resolve and report the plan; nothing is downloaded or written (a registry is still contacted to resolve the version) |
| `timeout_ms`      | Deadline for the whole verb, default 300000; see 4.10 |
| `ca_file`         | PEM file of extra trusted CA certificates (not with `source=file`) |

An option that does not apply to the chosen `source` (for example `registry` or `version` with `source=file`) is an error (exit 2). Installing the version that is already installed, without `force`, succeeds as a no-op (`changed: false`).

### 4.2 update

```bash
resh plugin://aws.update dry_run=true
resh plugin://aws.update registry=https://plugins.example.org strict=true
```

Resolves the newest version of an installed plugin from `registry` (default `https://plugins.reshshell.dev`), or takes the artifact at `url`, and installs and activates it (2.5). If anything fails, the previous version stays installed and active. Arguments: `registry` or `url` (not both), `verify` (as for install; a `url` update needs `verify=none`), `strict`, `dry_run`, `timeout_ms` (default 300000), `ca_file`.

When the installed version is current or newer, `update` succeeds as a no-op, or fails with `plugin.no_update_available` when `strict=true`. A `url` artifact has no version to compare, so a `url` update always installs it (as version `unknown`). Updating a plugin that is not installed fails with `plugin.not_installed` before anything is fetched. There is no `version` argument: update always targets the newest version.

### 4.3 remove

```bash
resh plugin://aws.remove dry_run=true
resh plugin://aws.remove purge=true
```

Removes the plugin's directory from the store (all its files). Arguments: `force` (remove even while a process runs a file of the plugin; otherwise `plugin.in_use`), `purge` (also delete the plugin's data directories `resh/plugins/<plugin-id>` under the XDG state, cache and config directories, and its user enable-state entry), `dry_run`, `timeout_ms` (default 30000). Removing a plugin that is not installed fails with `plugin.not_installed`.

The plugin directory is first renamed into staging, so the plugin disappears at once, and then deleted. Nothing outside the store and the three data directories is deleted, whatever the store's `metadata.json` says. A purge directory that is a symbolic link is refused (`plugin.unsafe_path`) before anything is removed.

### 4.4 enable / disable

```bash
resh plugin://aws.enable dry_run=true
resh plugin://aws.enable reason="needed by deploy jobs"
resh plugin://aws.disable scope=user
```

Marks an installed plugin enabled or disabled in the state file of `scope` (`user`, the default, or `system`). Arguments: `scope`, `force`, `reason` (at most 200 characters, no control characters; recorded with the time of the change), `dry_run`. These verbs finish at once and do not take `timeout_ms`.

* Enabling or disabling a plugin that is not installed fails with `plugin.not_installed`.
* A plugin already in the requested state is left as it is (`changed: false`); `force=true` writes the entry again (with the new `reason` and time).
* `disable` refuses while a process runs a file of the plugin (`plugin.in_use`) unless `force=true`.
* Writing `scope=system` needs write access to `/var/lib/resh/plugins` (otherwise `plugin.permission_denied`).
* Concurrent changes of one state file are serialized with a lock; if another process holds it for more than 10 seconds, the verb fails with `plugin.locked`.

### 4.5 installed.list

```bash
resh --json-pretty plugin://installed.list format=names
resh plugin://installed.list prefix=aws sort=installed_at order=desc limit=10
```

Lists the plugins in the local store. Arguments: `enabled` (boolean), `name` (exact), `prefix`, `tag` (from the plugin's own `manifest.json`), `source` (`registry`, `url`, `file`), `limit` (1-500, default 200), `offset`, `sort` (`name`, `installed_at`, `updated_at`), `order` (`asc`, `desc`), `format` (`full`, `summary`, `names`).

`enabled` is the plugin's user enable state, or its system state when the user scope has no entry. `installed_at` is when the plugin was first installed, `updated_at` when its current version was installed. A store entry that cannot be read is listed with `health: "broken"` and a `problem`. Listing never creates the store.

### 4.6 available.list

```bash
resh --json-pretty plugin://available.list query=docker limit=1
resh plugin://available.list source=file:/srv/catalog.json tags=container,docker
```

Lists plugins from a catalog. `source=default` (the default) reads the catalog built into resh; `source=file:<path>` reads the given file. Other arguments: `query`, `tags` (`,`-separated, all must match), `publisher`, `platform` (`<os>-<arch>`, default the current platform), `include_prerelease`, `limit` (1-1000, default 100), `offset`, `format` (`summary` or `full`). No network access. A missing file is `plugin.not_found`, an invalid one `plugin.catalog_invalid`.

### 4.7 available.search

```bash
resh --json-pretty plugin://available.search q=docker offline=true
resh plugin://available.search q=backup 'tags=storage;backup' max_results=10
```

Searches a plugin index and returns scored matches; a plugin that matches none of the query's fields is not returned. Arguments: `q`, `tags` (`;`-separated, all must match), `owner`, `name`, `min_version` (a version; compared in semantic-version order), `max_results` (1-200, default 25), `source` (`default`, which is `https://plugins.reshshell.dev/index.json`, or an `https://` URL), `offline`, `refresh`, `timeout_ms` (default 5000), `ca_file`.

* Without `refresh`, the cached index of the source is used when there is one; otherwise the index is fetched and cached.
* `offline=true` reads only the cache and never contacts the network; with no cache it fails with `plugin.not_found`.
* `refresh=true` always fetches. `offline=true` with `refresh=true` (or with `ca_file`) is an error (exit 2).

### 4.8 available.info

```bash
resh --json-pretty plugin://available.info name=resh.docker offline=true
```

Reports index details for one plugin. Arguments: `name` or `id` (at least one required), `version` (numeric `x.y` or `x.y.z`), `channel` (`stable`, `beta`, `nightly`), `os`, `arch` (default the current system), `source` (`default` = official and community, `official` or `community`), `offline`, `timeout_ms` (default 5000), `ca_file`.

Without `offline=true` each index is fetched over HTTPS from `<index>/index-<channel>.json` unless a fresh cache exists (official: 1 hour, community: 30 minutes). An index that cannot be loaded is a warning while another one loads. The newest matching version that supports the target OS and architecture and this resh version (`compatibility.resh_min`/`resh_max`) is reported, official before community. No match is `plugin.not_found`.

### 4.9 Errors

| Code | Exit | Meaning |
| ---- | ---- | ------- |
| `plugin.invalid_argument` | 2 | Unknown argument, invalid value, or options that do not go together; nothing was done |
| `plugin.invalid_target` | 2 | Missing or unsafe plugin id, or a plugin id given to a catalog verb |
| `plugin.unknown_verb` | 2 | No such verb (with a "did you mean" hint) |
| `plugin.not_installed` | 1 | The plugin is not installed |
| `plugin.not_found` | 1 | No such plugin, version, catalog file, local artifact or cached index; HTTP 404 |
| `plugin.platform_unsupported` | 1 | The registry has no artifact for this `<os>-<arch>` |
| `plugin.download_failed` | 1 | Connection, TLS or HTTP failure, or a download over the size limit |
| `plugin.catalog_invalid` | 1 | A registry entry, index or catalog is not valid (or names an unsafe version or artifact) |
| `plugin.verify_failed` | 1 | Checksum missing, malformed or not matching; nothing was installed |
| `plugin.extract_failed` | 1 | The artifact cannot be unpacked or breaks the rules of 2.3 |
| `plugin.install_failed` | 1 | The new version could not be written or activated; the old one stays |
| `plugin.downgrade_refused` | 1 | A newer version is installed and `allow_downgrade` is not set |
| `plugin.no_update_available` | 1 | `update strict=true` found no newer version |
| `plugin.in_use` | 1 | A process runs the plugin (`remove`, `disable`) and `force` is not set |
| `plugin.remove_failed` | 1 | The plugin or its data could not be removed |
| `plugin.io_error` | 1 | A state, cache or store file cannot be read or written, or is damaged |
| `plugin.permission_denied` | 1 | Permission denied (for example `scope=system` as a normal user) |
| `plugin.unsafe_path` | 1 | A location breaks the rules of 1.1 (symlink, other owner, writable by others) |
| `plugin.locked` | 1 | Another process kept the enable-state lock for 10 seconds |
| `plugin.timeout` | 124 | `timeout_ms` was reached; see 4.10 for what was left done |

### 4.10 timeout_ms

`timeout_ms` is a deadline for the whole verb (1 ms to 24 hours). Reaching it fails with `plugin.timeout` (exit 124).

| Verb             | Default | Behavior at the deadline |
| ---------------- | ------- | ------------------------ |
| install, update  | 300000  | Covers resolving, downloading (including reading the body), unpacking, and waiting for the plugin's lock. A timeout before the new version is activated removes the staged files and leaves the installed version as it was |
| remove           | 30000   | Covers the in-use check and waiting for the lock. Checked before the plugin directory is renamed away; after that the removal completes |
| available.search | 5000    | Covers fetching the index |
| available.info   | 5000    | Covers fetching every index together |
| enable, disable, available.list, installed.list | none | Refused (exit 2): these verbs read or write local files only |

---

## 5. Platform Support

Only Linux is supported and verified. Registry artifacts are chosen by the `<os>-<arch>` key of the running system (for example `linux-x86_64`).

---

## 6. Limitations

* Registry checksums prove integrity in transit only, not publisher authenticity (2.2). There is no signature support.
* `source=url` cannot be verified; it needs `verify=none` and is then unverified.
* The in-use check (`remove`, `disable`) looks for processes whose executable is a file of the plugin; a plugin run by an interpreter (for example `sh plugin`) is not detected.
* Only the current version of a plugin is kept; there is no rollback to an earlier version except installing it again (`allow_downgrade=true`).

---

## 7. Operational Notes

* Prefer `source=registry` with the default `verify=sha256`, from a registry you trust.
* Use `source=file` for artifacts you built or reviewed yourself.
* Run `dry_run=true` first; it reports the resolved version and artifact without installing anything (a registry is still contacted to resolve).
* Pin `version=` for reproducible installs.
* Gate automation on `ok` or the exit status.

---

## 8. Implementation

Written in Rust: `src/handles/automation/pluginh.rs` (help, argument parsing, dispatch), `src/handles/pluginh/plugin/engine.rs` (install/update/remove), `registry.rs` (resolution and checksums), `store.rs` (plugin store), `src/handles/pluginh/state.rs` (enable/disable), `catalog.rs` (`available.list`, `available.search`, `installed.list`), `available/` (`available.info`), `net.rs` (HTTPS), `paths.rs` (locations and safe file access) and `common.rs` (arguments, error codes, versions).
