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

The older doubled forms `plugin://available.available.list` and `plugin://installed.installed.list` are still accepted. A lifecycle verb with no plugin id (for example `plugin://install`) is an error.

Local state (all under the XDG directories of the user running resh):

| What | Location |
| ---- | -------- |
| Plugin store (installed versions) | `$XDG_DATA_HOME/resh/plugins` (default `~/.local/share/resh/plugins`) |
| User enable/disable state (`enable`/`disable`, `scope=user`) | `$XDG_STATE_HOME/resh/plugins/state.json` |
| System enable/disable state (`scope=system`) | `/var/lib/resh/plugins/state.json` (needs write access there) |
| Enabled list read by `installed.list` | `$XDG_STATE_HOME/resh/plugins/enabled.json` (see Limitations: this is not the file `enable` writes) |
| `available.search` cache | `$XDG_STATE_HOME/resh/plugins/index-cache.json` |
| `available.info` index cache | `$RESH_STATE_DIR/cache/plugin-indexes`, or `~/.resh/cache/plugin-indexes` |

**Do not run plugin verbs as root with another user's environment** (for example `sudo -E resh plugin://...`, or a sudo policy that keeps `HOME` or `XDG_*`). The locations above then resolve into that user's directories, which the user controls: `remove` deletes the binary path recorded in the store's `metadata.json` without checking that it lies inside the store, and `remove purge=true` follows a symlinked parent directory under the state, cache and config locations. Run plugin verbs as the user who owns the store, or as root with root's own `HOME` (for example `sudo -H` or `sudo -i`).

---

## 2. Security Model for Installation

`install` and `update` download and unpack third-party code. The rules below are enforced by the code (`src/handles/pluginh/plugin/{registry,engine,store}.rs`).

### 2.1 Transport: HTTPS only

* Remote registries and artifact URLs must use `https://` with a valid certificate. TLS certificates are always verified.
* A plain `http://` URL (or any other scheme) is refused before any connection is made. A redirect from HTTPS to HTTP is also refused.
* These rules apply whatever `verify` says; `verify=none` does not allow `http://`.

### 2.2 Integrity: `verify=sha256` (the default)

* A registry entry gives, per platform, an artifact name and a SHA-256. With `verify=sha256`, that SHA-256 must be a well-formed 64-digit hexadecimal value. A missing, empty or malformed checksum fails with `PLUGIN_VERIFY_FAILED` before anything is downloaded.
* The downloaded artifact is hashed and compared before anything is extracted. A mismatch fails with `PLUGIN_VERIFY_FAILED` and nothing is installed.
* **Limit:** the checksum comes from the same registry as the artifact. It proves the artifact was not altered in transit and matches what the registry published. It does **not** prove who published the plugin. A compromised or malicious registry is not detected; trust rests on HTTPS and on the registry operator.
* `source=url` has no trusted checksum (there is no `sha256=` argument), so it is refused under `verify=sha256` and needs an explicit `verify=none`.
* `source=file` (a local file) is accepted under `verify=sha256` without a checksum; no transport is involved.
* `verify=none` skips the checksum. The artifact is then **installed unverified**: only the HTTPS transport protects it. This is not equivalent to a verified install; use it only for artifacts you have checked yourself.
* `verify` accepts exactly `sha256` or `none`. Any other value (such as `md5`, `NONE`, `off` or empty) is an error and nothing runs.

### 2.3 Artifact contents

* An artifact whose name ends in `.tar.gz` is unpacked; anything else is installed as a single executable file.
* A `.tar.gz` artifact may contain only regular files and directories with plain relative paths. A symbolic link, hard link, device node, FIFO, absolute path or `..` entry fails the whole install, and nothing is installed. An existing installed version is left untouched.
* File modes are reduced to 0644 or 0755: setuid, setgid and sticky bits and group/other write bits are dropped.
* Since v1.0.5-beta an entry preceded by more than 1 MiB of tar header data (PAX extended headers, GNU long name or long link headers) fails the whole install with `PLUGIN_EXTRACT_FAILED`, and nothing is installed.

### 2.4 Plugin ids and versions

* Plugin ids, and versions taken from a registry, must each be a single safe path component: 1-128 characters of `A-Z a-z 0-9 . _ + -`, starting with a letter or digit.
* An id containing `/` (for example `plugin://acme/tool.install`) is refused, and the id `locks` is reserved.
* The id is checked before anything is fetched; a registry-supplied version is checked before the artifact is downloaded. Nothing is written when either check fails.

---

## 3. Response Envelopes

Every verb prints one JSON object on stdout. On failure resh also prints `Error: <message>` on stderr and exits non-zero. The shape differs between verb groups:

* **install, update, remove** (`src/handles/pluginh/plugin/engine.rs`): `op` (`plugin.install`, ...), `ok`, `code`, `target` (`name`, `requested_name`, `install_root`, and `version`/`bin_path` when known), `args` (`dry_run`, `timeout_ms`; remove also `force`, `purge`), `actions`, `result`, `error` (`kind`, `message`, `details`), `ts`.
* **enable, disable**: `op`, `ok`, `code`, `target`, `args`, `actions` (each with `id`, `type`, `name`, `ok`, optional `details`), `result` (`installed`, `enabled`, `was_enabled`, `version`), `error`, `ts`.
* **available.list**: `op`, `ok`, `code`, `target` (the stage URL), `args`, `actions`, `result`, `error` (`kind`, `message`), `ts`.
* **available.search**: `op`, `ok`, `target`, `args`, `actions`, `result`, `error` (`code`, `message`, `details`).
* **available.info**: `op`, `ok`, `target`, `ts`, `args`, `actions`, `result`, `error` (`code`, `message`, `details`).
* **installed.list**: `op`, `ok`, `target`, `args`, `actions`, `result` (`items`, `count`, `total`, `limit`, `offset`), `warnings`, `error`, `ts`.

Real output of a local-file install dry run (paths shortened):

```json
{
  "op": "plugin.install",
  "ok": true,
  "code": 0,
  "target": {
    "name": "demo",
    "requested_name": "demo",
    "install_root": "/home/alice/.local/share/resh/plugins"
  },
  "args": { "dry_run": true, "timeout_ms": 300000 },
  "actions": [
    { "id": "resolve-0", "type": "resolve", "name": "Resolved plugin version: local", "ok": true, "details": { "version": "local" } },
    { "id": "check-1", "type": "check_installed", "name": "Plugin not installed", "ok": true },
    { "id": "plan-2", "type": "install", "name": "Dry run: no changes made", "ok": true,
      "details": { "artifact_kind": "tar.gz", "artifact_path": "/home/alice/demo.tar.gz", "artifact_url": null,
                   "dry_run": true, "from_version": null, "sha256": null, "to_version": "local" } }
  ],
  "result": { "installed": false, "version": "local" },
  "ts": "2026-10-23T13:07:43.301630502+00:00"
}
```

A real install adds `download`, `verify`, `extract`, `install`, `activate` and `cleanup` actions and reports `result.installed: true`. A local file installs as version `local`; a `source=url` artifact as version `unknown`.

Real output of a refused `source=url` install:

```json
{
  "op": "plugin.install",
  "ok": false,
  "code": 4,
  "target": { "name": "demo", "requested_name": "demo", "install_root": "/home/alice/.local/share/resh/plugins" },
  "args": { "dry_run": false, "timeout_ms": 300000 },
  "actions": [],
  "result": { "removed": false, "purged": false, "installed": false },
  "error": {
    "kind": "PLUGIN_VERIFY_FAILED",
    "message": "PLUGIN_VERIFY_FAILED: No trusted SHA-256 is available for a source=url artifact, so verify=sha256 cannot be satisfied; install from a registry, or pass verify=none to install without integrity verification",
    "details": {}
  },
  "ts": "2026-10-23T13:07:43.342541492+00:00"
}
```

For install, update and remove failures, rely on `ok` and on the code prefix at the start of `error.message` (such as `PLUGIN_VERIFY_FAILED:` or `PLUGIN_EXTRACT_FAILED:`). `error.kind` and `code` are derived from words in the message and are often `PLUGIN_UNKNOWN_ERROR` with code 1, even for a checksum or extraction failure. On failure `actions` is empty.

---

## 4. Verbs

Per-verb help: `resh plugin <verb> --help`.

### 4.1 install

```bash
resh plugin://demo.install source=file path=/home/alice/demo.tar.gz dry_run=true
resh plugin://demo.install source=file path=/home/alice/demo.tar.gz
resh plugin://aws.install version=1.2.3
resh plugin://aws.install registry=https://plugins.example.org
resh plugin://tool.install source=url url=https://example.org/tool.tar.gz verify=none
```

| Argument          | Meaning |
| ----------------- | ------- |
| `source`          | `registry` (default), `url` or `file`. Anything else is an error |
| `registry`        | Registry base URL for `source=registry`, default `https://plugins.reshshell.dev`. The entry is fetched from `<registry>/v1/plugins/<id>` and the artifact from `<registry>/v1/artifacts/<id>/<version>/<bin>`. A value that is not a URL is read as a local JSON registry file, but the artifact URL built from it is not HTTPS, so such an install fails at download |
| `url`             | Artifact URL, required for `source=url`; must be `https://` |
| `path`            | Local artifact file, required for `source=file` |
| `version`         | Version to install from the registry (default latest). "Latest" is the highest version string in plain text order, not semantic-version order |
| `verify`          | `sha256` (default) or `none`; see 2.2 |
| `force`           | Reinstall the same version, or allow a downgrade |
| `allow_downgrade` | Allow installing a version older than the installed one |
| `dry_run`         | Resolve and report the plan; nothing is downloaded or installed (the empty plugin store directory may be created) |
| `timeout_ms`      | See 4.10 |

`force`, `allow_downgrade` and `dry_run` accept true/false/1/0/yes/no/on/off; anything else is an error. Installing the version that is already installed, without `force`, succeeds as a no-op. A dry run with a registry source still contacts the registry to resolve the version.

### 4.2 update

```bash
resh plugin://aws.update dry_run=true
resh plugin://aws.update registry=https://plugins.example.org strict=true
```

Resolves the latest version of an installed plugin from `registry` (default `https://plugins.reshshell.dev`), or from `url` if given, and installs and activates it. If the new version fails to install, the previous version is restored. Arguments: `registry`, `url`, `verify` (as for install; a `url` update needs `verify=none`), `strict`, `dry_run`, `timeout_ms`.

When the installed version is current or newer, `update` succeeds as a no-op, or fails with `PLUGIN_NO_UPDATE_AVAILABLE` when `strict=true`. Updating a plugin that is not installed fails with `PLUGIN_NOT_INSTALLED`. `version` is not read: update always targets the latest version.

### 4.3 remove

```bash
resh plugin://aws.remove dry_run=true
resh plugin://aws.remove purge=true
```

Removes the plugin's manifest, binary and support files. Arguments: `force` (remove even if a process running the plugin binary is found), `purge` (also delete the plugin's data), `dry_run`, `timeout_ms` (accepted but not used). Removing a plugin that is not installed fails with `PLUGIN_NOT_INSTALLED`.

### 4.4 enable / disable

```bash
resh plugin://aws.enable dry_run=true
resh plugin://aws.disable scope=user
```

Marks an installed plugin enabled or disabled in the state file for `scope` (`user`, the default, or `system`; anything else is an error). Arguments: `scope`, `force` (override the in-use check), `reason` (accepted, at most 200 characters, but not recorded), `dry_run`, `timeout_ms` (accepted but not used). Enabling a plugin that is not installed fails with `PLUGIN_NOT_INSTALLED` (code 3).

### 4.5 installed.list

```bash
resh --json-pretty plugin://installed.list format=names
resh plugin://installed.list prefix=aws sort=installed_at order=desc limit=10
```

Lists the plugins in the local store. Arguments: `enabled` (`true`/`false`), `name` (exact), `prefix`, `tag`, `source`, `limit` (default 200), `offset`, `sort` (`name`, `installed_at`, `updated_at`), `order` (`asc`, `desc`), `format` (`full`, `summary`, `names`). Invalid values for `enabled`, `limit`, `sort`, `order` or `format` are errors. The `enabled` field reflects `enabled.json`, not the state written by `enable` (see Limitations).

### 4.6 available.list

```bash
resh --json-pretty plugin://available.list query=docker limit=1
resh plugin://available.list source=file:/srv/catalog.json tags=container,docker
```

Lists plugins from a local catalog file. `source=default` (the default) reads `assets/plugins/catalog.json` **under the current directory**, so it fails elsewhere; `source=file:<path>` reads the given file. `url:` sources are not supported. Other arguments: `query`, `tags` (`,`-separated), `publisher`, `platform` (default the current `<os>-<arch>`), `include_prerelease`, `limit` (1-1000, default 100), `offset`, `format` (`summary` or `full`). No network access.

### 4.7 available.search

```bash
resh --json-pretty plugin://available.search q=docker offline=true
resh plugin://available.search q=backup 'tags=storage;backup' max_results=10
```

Searches a plugin index and returns scored matches. Arguments: `q`, `tags` (`;`-separated), `owner`, `name`, `min_version`, `max_results` (1-200, default 25), `source` (`default`, which is `https://plugins.reshshell.dev/index.json`, or an `https://` URL), `offline`, `refresh`, `timeout_ms`.

* With `offline=true` it reads only the local cache (or a test fixture at `tests/fixtures/plugins-index.json` under the current directory, if present) and never contacts the network.
* Otherwise it uses the cache when present (unless `refresh=true`), else fetches the index and caches it. If the fetch fails, it falls back to that test fixture when present.
* `offline` and `refresh` are true only for the exact value `true`.

### 4.8 available.info

```bash
resh --json-pretty plugin://available.info name=resh.docker offline=true
```

Reports index details for one plugin. Arguments: `name` or `id` (at least one required), `version` (numeric `x.y` or `x.y.z`), `channel` (`stable`, `beta`, `nightly`), `os`, `arch`, `source` (`default`, `official` or `community`; other values are errors), `offline` (exact `true`), `timeout_ms`. Without `offline=true` it fetches the official and community indexes over HTTPS unless a fresh cache exists.

### 4.9 Errors commonly seen

`PLUGIN_NOT_INSTALLED`, `PLUGIN_VERIFY_FAILED`, `PLUGIN_EXTRACT_FAILED`, `PLUGIN_DOWNLOAD_FAILED`, `PLUGIN_NO_UPDATE_AVAILABLE`, `PLUGIN_VERSION_CONFLICT`, `PLUGIN_IN_USE`, `PLUGIN_IO_ERROR`. As noted in section 3, for install/update/remove these appear reliably as the prefix of `error.message`, not always in `error.kind`.

### 4.10 timeout_ms

| Verb             | Default | Behavior |
| ---------------- | ------- | -------- |
| install, update  | 300000  | Used as the per-request timeout for each registry and artifact HTTPS request. It is not a deadline for the whole operation, and has no effect on `source=file`. A malformed value is silently replaced by the default |
| remove           | 30000   | Accepted and echoed in `args`, not used. Malformed values silently become the default |
| enable, disable  | 15000   | Clamped to 1000-120000 and echoed in `args`, not used. Malformed values silently become the default |
| available.search | 5000    | Enforced for the index fetch. Must be an integer from 100 to 60000, otherwise the verb fails |
| available.info   | 5000    | Enforced for each index fetch. Must be an integer (otherwise an error) and is clamped to 100-30000 |
| available.list, installed.list | none | Not read (local files only) |

---

## 5. Platform Support

Only Linux is supported and verified. Registry artifacts are chosen by the `<os>-<arch>` key of the running system (for example `linux-x86_64`).

---

## 6. Limitations

* `installed.list` reads enabled state from `enabled.json`, but `enable`/`disable` write `state.json`, so `installed.list` reports `enabled: false` for a plugin enabled with `plugin://<id>.enable`.
* Registry checksums prove integrity in transit only, not publisher authenticity (2.2). There is no signature support.
* `source=url` cannot be verified; it needs `verify=none` and is then unverified.
* `error.kind` and `code` for install/update/remove failures are often `PLUGIN_UNKNOWN_ERROR` / 1; use the message prefix.
* "Latest" version selection compares version strings as text (`1.9.0` sorts above `1.10.0`).
* `available.list` with the default source only works when run from a directory containing `assets/plugins/catalog.json`.

---

## 7. Operational Notes

* Prefer `source=registry` with the default `verify=sha256`, from a registry you trust.
* Use `source=file` for artifacts you built or reviewed yourself.
* Run `dry_run=true` first; it reports the resolved version and artifact without installing anything (a registry is still contacted to resolve).
* Pin `version=` for reproducible installs.
* Gate automation on `ok` or the exit status.

---

## 8. Implementation

Written in Rust: `src/handles/automation/pluginh.rs` (argument parsing, catalog verbs), `src/handles/pluginh/plugin/engine.rs` (install/update/remove), `registry.rs` (HTTPS client and checksums), `store.rs` (plugin store and path validation), `src/handles/pluginh/state.rs` (enable/disable) and `src/handles/pluginh/available/` (`available.info`).
