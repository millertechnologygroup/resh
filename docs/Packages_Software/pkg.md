# Resource Shell (resh) – Package Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using structured URI-based commands. The `pkg://` handle installs, removes, updates, queries and snapshots system packages by running the host's package manager: `apt` (apt-get / apt-cache / dpkg-query), `dnf`, `yum`, `pacman`, `apk` or `brew`.

### Purpose

The Package handle provides:

* Installation and removal of packages
* Index refresh, updates and upgrades
* Package search and metadata inspection
* Installed package inventory reporting
* Snapshots of the installed package set as a `pkg-lock/v1` lockfile
* A best-effort `restore` that installs missing packages and optionally removes extra ones (see 3.4: it does **not** pin locked versions)

### Resource-Oriented URI Model

```text
resh pkg://<alias>.<verb> input=<json>
```

* **handle**: `pkg://`
* **alias**: a free-form label (commonly `system`), echoed as `alias` in the output
* **verb**: one of the verbs below
* **input**: one JSON object holding all options. It is the only argument the handle reads; other `key=value` words are ignored.

Every verb requires the `manager` key: one of `apt`, `dnf`, `yum`, `pacman`, `apk`, `brew`, or `auto`. With `auto`, the first manager binary found on `PATH` is used, in the order apt-get, dnf, yum, pacman, apk, brew. An explicit manager whose binary is not on `PATH` is an error.

Example:

```bash
resh pkg://system.install 'input={"manager":"auto","packages":[{"name":"curl"}]}'
```

---

## 2. Verbs

| Verb             | Description | Required `input` keys |
| ---------------- | ----------- | --------------------- |
| `install`        | Install packages (refreshes the index first by default; skips installed packages by default) | `manager`, `packages` (array of `{name, version}`) |
| `remove`         | Remove packages, optionally purging configuration and unused dependencies | `manager`, `packages` (array of `{name}`) |
| `update`         | Refresh the index and by default upgrade all or the listed packages; `check_only` only reports; `security_only` with dnf/yum only (see 4.4) | `manager` |
| `upgrade`        | Upgrade all or the listed packages; `check_only` only reports; `security_only` with dnf only (see 4.4) | `manager` |
| `info`           | Details for named packages | `manager`, `packages` (array of names) |
| `search`         | Search the package index | `manager`, `query` |
| `list_installed` | List installed packages, optionally filtered and paginated | `manager` |
| `snapshot`       | Capture the installed package set as a lockfile (JSON, YAML or text) | `manager` |
| `restore`        | Install / remove packages so the host matches a lockfile (best effort, see 3.4) | `manager`, `lockfile` (lockfile content as a string) |
| `apply_lock`     | Alias for `restore` | same as `restore` |

`resh pkg <verb> --help` lists every accepted key for a verb.

---

## 3. Command Syntax and Execution Model

### 3.1 Example Commands

Each example passes one JSON object on a single line. Quote it for the shell.

#### Install Packages (Dry Run)

```bash
resh pkg://system.install 'input={"manager":"auto","packages":[{"name":"curl"},{"name":"git"}],"dry_run":true}'
```

#### Install a Specific Version

```bash
resh pkg://system.install 'input={"manager":"apt","packages":[{"name":"jq","version":"1.7.1-3build1"}]}'
```

Version pinning is passed to apt (`name=version`), dnf/yum (`name-version`) and apk (`name=version`). With pacman a version is rejected; with brew it is ignored. The `source` field of a package entry is accepted but not used.

#### Remove Package (Dry Run)

```bash
resh pkg://system.remove 'input={"manager":"auto","packages":[{"name":"curl"}],"purge":false,"dry_run":true}'
```

#### Check for Updates

```bash
resh pkg://system.update 'input={"manager":"auto","check_only":true}'
```

#### Search for Packages

```bash
resh pkg://system.search 'input={"manager":"auto","query":"curl","limit":20}'
```

#### Create Snapshot

```bash
resh pkg://system.snapshot 'input={"manager":"auto","scope":"all","include_versions":"exact","format":"json"}'
```

#### Restore from Snapshot (Dry Run)

`lockfile` is the lockfile content as a JSON string, so it is easiest to build the request in a file:

```bash
resh pkg://system.restore "input=$(cat restore.json)"
```

with `restore.json` such as (lockfile string shortened):

```json
{
  "manager": "apt",
  "lockfile": "{\"lockfile_version\":\"pkg-lock/v1\", ...}",
  "dry_run": true
}
```

---

### 3.2 Execution Semantics

* No shell is used. Each package-manager command is run directly with an argument vector; caller values (package names, versions, arch, `extra_args`) are always single arguments and are never interpreted as shell syntax.
* Package names, versions and `arch` are validated: 1–256 characters, must start with a letter or digit (so they cannot be read as an option), and may contain only `A-Z a-z 0-9 . _ + : ~ @ / = -`.
* Package names read from a restore lockfile are additionally rejected if they contain `://`, a `..` path segment, or end in a package-file suffix (`.rpm`, `.deb`, `.apk`, `.pkg.tar`, `.pkg.tar.zst`, `.pkg.tar.xz`, `.pkg.tar.gz`), so a lockfile cannot make the manager fetch a URL or install a local file.
* `dry_run` (inside the JSON) is available for `install`, `remove`, `update`, `upgrade` and `restore`; it reports the planned commands without running them. A `dry_run=true` given as a separate argument (outside `input=`) is refused with exit 2 and nothing runs; put `"dry_run":true` inside the JSON.
* Each `resh` invocation is a separate process; nothing is kept between invocations.

### 3.3 Timeouts

Every verb enforces `timeout_ms` (a key inside the JSON) as a wall-clock limit on the whole operation. Defaults:

| Verb | Default `timeout_ms` |
| ---- | -------------------- |
| `info`, `search` | 5000 (5 s) |
| `snapshot` | 15000 (15 s) |
| `restore`, `apply_lock` | 180000 (3 min) |
| `install`, `remove`, `list_installed` | 600000 (10 min) |
| `update`, `upgrade` | 900000 (15 min) |

`timeout_ms` must be greater than 0. `search` runs an extra query per match (for example `apt-cache policy` on apt), so on slow systems it may need a larger `timeout_ms` than the 5 s default. When the timeout expires, resh stops waiting and reports a timeout error (exit 1); the package-manager process it started is not explicitly killed. What happens next depends on the tool: one that writes no more output keeps running and may finish the change after resh has reported the timeout; one that writes output afterwards is killed by `SIGPIPE` at that point, possibly in the middle of a transaction. After a timeout, check the package manager's state (for example `dpkg --audit` / `dpkg --configure -a` on apt systems) before retrying.

### 3.4 Restore Behavior and Limitations

`restore` compares the lockfile with the installed packages and builds a plan with `install`, `upgrade`, `downgrade`, `remove`, `keep`, `extra` and `unresolved` lists:

* A locked package that is not installed is installed **by name** (latest available version).
* A locked package whose installed version string differs is put in `upgrade` or `downgrade` by a plain string comparison of the version strings, not a package-manager version comparison. The "upgrade" step reinstalls by name (latest available version); the "downgrade" step (only with `allow_downgrades`, and only apt, dnf, yum) also runs by name. **The locked version is never passed to the package manager**, so restore does not reproduce exact versions.
* With `allow_newer` (default `true`) a newer installed version is kept.
* Packages installed on the host but not in the lockfile are listed in `extra`, or **removed** when `allow_removals` is `true`. Use this with care: on a full system it removes every package missing from the lockfile.
* `mode` (`exact` / `best_effort`) is echoed in the output but does not change the plan.
* `on_repo_mismatch` and `include_dependencies` are accepted but have no effect on restore; `extra_args` is not passed to the restore commands.
* `on_platform_mismatch: "fail"` rejects a lockfile whose OS name or architecture differs from the host.
* `on_missing_package: "fail"` makes the restore fail if any package is `unresolved`.

Restore is therefore not a rollback mechanism: it cannot return a host to the exact package versions in a snapshot.

### 3.5 Output

All verbs print one JSON object to standard output. Representative `install` output (apt):

```json
{
  "alias": "system",
  "backend": "pkg",
  "dry_run": false,
  "manager": "apt",
  "packages": [
    {
      "action": "installed",
      "from_cache": false,
      "installed_version": "1.7.1-3build1",
      "name": "jq",
      "requested_version": null
    }
  ],
  "summary": {
    "failed": 0,
    "installed": 1,
    "reinstalled": 0,
    "unchanged": 0,
    "upgraded": 0
  },
  "update_cache": true
}
```

Representative `snapshot` output (abbreviated; the `lockfile` field holds the full lockfile as a string):

```json
{
  "action": "snapshot",
  "alias": "system",
  "backend": "pkg",
  "format": "json",
  "lockfile": "{\n  \"lockfile_version\": \"pkg-lock/v1\",\n  ...\n}",
  "manager": "apt",
  "parsed": {
    "lockfile_version": "pkg-lock/v1",
    "manager": { "alias": "system", "name": "apt", "version": "apt 2.7.14 (amd64)" },
    "packages_count": 214,
    "platform": {
      "architecture": "x86_64",
      "kernel": "Linux 6.8.0-45-generic",
      "os_family": "debian",
      "os_name": "Ubuntu",
      "os_version": "24.04"
    },
    "scope": "manual"
  }
}
```

### 3.6 Errors and Exit Codes

* Invalid input (bad JSON, missing `manager`, invalid package name, `timeout_ms` of 0), an unavailable manager, or a timeout: resh prints `Error: <reason>` to standard error and exits 1.
* `install`, `remove`, `update`, `upgrade` and `restore` print their JSON result and then exit 1 if any package operation failed, with a reason such as `pkg install: 1 of 2 package operations failed` on standard error. A partial failure is a failure.
* Otherwise the exit code is 0.

---

## 4. Functional Domains

### 4.1 Automation Utilities

* CI/CD build agent setup
* Environment standardization
* Automated patching

### 4.2 Data & State Management

* Dependency auditing
* Drift detection (compare snapshots, or run `restore` with `dry_run` to see the plan)
* Recording the installed package set

### 4.3 Packages & Software

**Managers in the code**

* apt
* dnf
* yum
* pacman
* apk
* brew

**Core Capabilities**

* Install/remove packages
* Upgrade the system
* Inspect metadata
* Search repositories
* Snapshot the package set and reinstall missing packages from a lockfile

### 4.4 Security

* Security-only updates (`security_only=true`) are honored only where resh can pass `--security`: `update` with dnf or yum, and `upgrade` with dnf. For any other manager (update: apt, pacman, apk, brew; upgrade: apt, yum, pacman, apk, brew) the request fails before anything runs, including in `dry_run` and `check_only`, with `security_only is not supported by pkg <verb> for <manager> (only ...); nothing was run.` It is never silently dropped.
* Lockfile package names are validated before any command runs
* Platform mismatch detection on restore (`on_platform_mismatch`)
* Package-manager commands require root privileges; resh does not elevate privileges itself.

### 4.5 System Information

`info`, `list_installed` and `snapshot` can report installed and candidate versions, architecture, repository, installation reason, OS metadata and the manager version, depending on the manager and the `include_*` keys.

---

## 5. Platform Support

* Linux is the only supported platform for resh.
* The apt, dnf, yum, pacman and apk backends were exercised in Linux test sandboxes.
* The brew backend exists in the code but was never executed in testing; treat it as untested.

---

## 6. Operational Best Practices

* Use `dry_run` before applying changes.
* Take snapshots before upgrades to record what was installed (restoring will not pin versions).
* Rely on the default `only_if_missing` behaviour for idempotent installs.
* Set a larger `timeout_ms` for `search` and `info` on slow systems.
* Check the exit code and `summary.failed` after mutating verbs.
* Use `check_only` when validating changes.
* Do not use `allow_removals` unless the lockfile lists every package you need.

### CI/CD Integration

Typical sequence:

1. `update` (refresh index)
2. `install` dependencies
3. `snapshot` environment state
4. Validate build

---

## 7. Use Cases by Role

### DevOps Engineers

* Provision build agents.
* Automate dependency installation.
* Standardize environments across teams.

### SRE Engineers

* Audit installed packages.
* Apply security patches.
* Detect drift via snapshots.

### AI / Automation Engineers

* Analyze structured install results.
* Detect failed operations programmatically.
* Compare snapshot states automatically.

---

## 8. Technical Foundation

* Implemented in Rust; package managers are run as subprocesses with argument vectors (no shell).
* Fixed verb set; input is one JSON object deserialized per verb.
* Wall-clock timeouts on every verb.
