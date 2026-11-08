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
* `restore`, which brings the host to a lockfile: it installs the locked versions (`mode: exact`) or the closest it can get (`mode: best_effort`), see 3.4

### Resource-Oriented URI Model

```text
resh pkg://<alias>.<verb> input=<json>
```

* **handle**: `pkg://`
* **alias**: a free-form label (commonly `system`), echoed as `alias` in the output
* **verb**: one of the verbs below
* **input**: one JSON object holding all options. It is the only argument a verb reads. Any other `key=value` argument is refused (exit 2, `pkg.invalid_argument`), and so is any key inside the object that the verb does not accept, with a "did you mean" hint for a likely typo. Nothing runs when a request is refused.

Every verb requires the `manager` key: one of `apt`, `dnf`, `yum`, `pacman`, `apk`, `brew`, or `auto`. With `auto`, the first manager binary found on `PATH` is used, in the order apt-get, dnf, yum, pacman, apk, brew. An explicit manager whose binary is not on `PATH` is an error (`pkg.manager_not_found`, exit 1).

Example:

```bash
resh pkg://system.install 'input={"manager":"auto","packages":[{"name":"curl"}]}'
```

---

## 2. Verbs

| Verb             | Description | Required `input` keys |
| ---------------- | ----------- | --------------------- |
| `install`        | Install packages (refreshes the index first by default; skips installed packages by default) | `manager`, `packages` (array of `{name, version}`) |
| `remove`         | Remove packages, optionally purging configuration and unused dependencies | `manager`, `packages` (array of `{name, version}`) |
| `update`         | Refresh the index and by default upgrade all or the listed packages; `check_only` only reports; `security_only` with dnf/yum only (see 4.4) | `manager` |
| `upgrade`        | Upgrade all or the listed packages; `check_only` only reports; `security_only` with dnf only (see 4.4) | `manager` |
| `info`           | Details for named packages; `include_repo: false` sets `repository` and `repository_url` to null | `manager`, `packages` (array of names) |
| `search`         | Search the package index | `manager`, `query` |
| `list_installed` | List installed packages, optionally filtered and paginated; `include_versions: false` sets `version` to null | `manager` |
| `snapshot`       | Capture the installed package set as a lockfile (JSON, YAML or text) | `manager` |
| `restore`        | Install, upgrade, downgrade or remove packages so the host matches a lockfile (see 3.4) | `manager`, `lockfile` (lockfile content as a string) |
| `apply_lock`     | Alias for `restore` | same as `restore` |

`resh pkg <verb> --help` lists every accepted key for a verb, with its default.

Every verb also accepts `timeout_ms` (see 3.3) and `env`, an object of environment variables set for every package-manager command the verb runs (names non-empty, without `=`; values strings). The verbs that run one main command (`install`, `remove`, `update`, `upgrade`, `search`, `restore`) accept `extra_args`, a list of arguments added to that command (for `restore`, to every install and remove command). `info`, `list_installed` and `snapshot` run several queries and refuse `extra_args`.

### Options by manager

Some options exist only where the package manager has them. A request that sets one for a manager without it is refused before anything runs (exit 2, `pkg.unsupported_option`), dry run included; it is never silently dropped.

| Option | apt | dnf | yum | pacman | apk | brew |
| ------ | --- | --- | --- | ------ | --- | ---- |
| package `version` (install) | `name=ver` | `name-ver` | `name-ver` | refused | `name=ver` | refused |
| package `version` (remove) | `name=ver` | `name-ver` | `name-ver` | refused | refused | refused |
| `arch` | `name:arch` | `name.arch` | `name.arch` | refused | refused | refused |
| `purge` (remove) | `apt-get purge` | refused | refused | `-n` | `--purge` | refused |
| `recursive` (remove) | `apt-get autoremove` | `dnf autoremove` | `yum autoremove` | `-s` | always (apk removes unneeded dependencies on every removal) | `brew autoremove` |
| `assume_yes: false` | yes | yes | yes | yes | refused | refused |
| `security_only` | refused | update, upgrade | update | refused | refused | refused |
| restore `mode: exact` with locked versions | yes | yes | yes | only the repository version | yes | refused |

`assume_yes: false` runs the manager without its yes flag (`-y`, `--noconfirm`). resh gives the manager no terminal, so when it asks for confirmation it reads end-of-file and stops without changing anything; the package is reported as failed. apk and brew do not ask, so `false` cannot be honored for them.

With apk, a package installed with a version (`name=ver`) stays pinned to it in `/etc/apk/world` until it is installed again without a version; that is how apk installs a given version.

---

## 3. Command Syntax and Execution Model

### 3.1 Example Commands

Each example passes one JSON object on a single line. Quote it for the shell.

#### Install Packages (Dry Run)

```bash
resh pkg://system.install 'input={"manager":"auto","packages":[{"name":"curl"},{"name":"git"}],"dry_run":true}'
```

The dry run reports, per package, the action it would take and the exact commands it would run, without running them.

#### Install a Specific Version

```bash
resh pkg://system.install 'input={"manager":"apt","packages":[{"name":"jq","version":"1.7.1-3build1"}]}'
```

A package entry may not have a `source` field (`install` and `remove`). No manager backend can take a package from a given source; packages always come from the manager's configured repositories. A request with `source` set is refused before anything runs, dry run included (exit 2, `pkg.invalid_argument`).

`install` works on one package at a time: a package that is already installed is left alone (`only_if_missing`, default true) unless a different `version` is requested, `upgrade` upgrades it in place (`apt-get install --only-upgrade`, `dnf upgrade`, `pacman -S --needed`, `apk add --upgrade`, `brew upgrade`) and `reinstall` reinstalls it (`apk fix` on apk). The reported action (`installed`, `upgraded`, `downgraded`, `reinstalled`, `unchanged`) comes from the installed version before and after the command; a failed package is `failed` with an `error` object (`code`, `message`).

A requested `version` older than the installed one (in the manager's version order) is a downgrade. Without `allow_downgrade: true` (default false) the request is refused before anything runs, dry run included (exit 1, `pkg.downgrade_refused`). With it, apt installs with `--allow-downgrades`, dnf and yum use `downgrade`, and apk installs the version with `add` (which downgrades). pacman and brew take no version at all (see "Options by manager").

#### Remove Package (Dry Run)

```bash
resh pkg://system.remove 'input={"manager":"auto","packages":[{"name":"curl"}],"purge":false,"dry_run":true}'
```

`remove` runs one remove command for the installed packages and then checks that each one is gone. A package that is not installed is reported as `not_installed`; with `fail_if_missing` (which needs `only_if_installed: false`) it is a failure. `only_if_installed: false` alone hands packages that are not installed to the manager as well. A package `version` must match the installed version. If the dependency cleanup of `recursive` fails, the result has an `autoremove_error` object and the exit status is 1.

#### Check for Updates

```bash
resh pkg://system.update 'input={"manager":"auto","check_only":true}'
```

`check_only` (and `dry_run`) list the pending updates and the commands a real run would use, including the index refresh, without running the refresh or the upgrade, so the list comes from the current index. With `packages`, only those installed packages are upgraded; a listed package that is not installed is not installed by `update` or `upgrade`.

#### Search for Packages

```bash
resh pkg://system.search 'input={"manager":"auto","query":"curl","limit":20}'
```

The `query` must not start with `-` and must not contain control characters.

#### Create Snapshot

```bash
resh pkg://system.snapshot 'input={"manager":"auto","scope":"all","include_versions":"exact","format":"json"}'
```

`include_versions` is `exact` (the default), `minimal` or `none`. `minimal` records only the upstream version: the epoch and the distribution revision are dropped (apt `1:8.5.0-2ubuntu10` becomes `8.5.0`; dnf, yum and pacman `[epoch:]version-release` becomes `version`; apk `1.8.2-r0` becomes `1.8.2`; brew `1.7.1_1` becomes `1.7.1`). The lockfile is marked with `manager.config.include_versions: "minimal"` (`# include_versions: minimal` in a text lockfile), and `restore` then accepts any installed build of each upstream version (see 3.4). `exclude_patterns` are shell-style globs (`*`, `?`, `[...]`) matched against package names; an invalid pattern is refused. With apt, a package that was removed but still has configuration files (dpkg state `config-files`) is not listed as installed by `list_installed`, `snapshot` or `restore`.

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
* Package names, versions and `arch` are validated (`install`, `remove`, `update`, `upgrade`, `info`, and every lockfile entry): 1–256 characters, must start with a letter or digit (so they cannot be read as an option), and may contain only `A-Z a-z 0-9 . _ + : ~ @ / = -`.
* Package names read from a restore lockfile are additionally rejected if they contain `://`, a `..` path segment, or end in a package-file suffix (`.rpm`, `.deb`, `.apk`, `.pkg.tar`, `.pkg.tar.zst`, `.pkg.tar.xz`, `.pkg.tar.gz`), so a lockfile cannot make the manager fetch a URL or install a local file.
* Package-manager commands run with `LC_ALL=C`, so their output is in the language resh parses; `env` can override it. apt commands also get `DEBIAN_FRONTEND=noninteractive`.
* `dry_run` (inside the JSON) is available for `install`, `remove`, `update`, `upgrade` and `restore`; it reports the planned commands without running them. The read-only verbs refuse it. A `dry_run=true` given as a separate argument (outside `input=`) is refused with exit 2 and nothing runs; put `"dry_run":true` inside the JSON.
* Each `resh` invocation is a separate process; nothing is kept between invocations.

### 3.3 Timeouts

Every verb enforces `timeout_ms` (a key inside the JSON) as a wall-clock limit on the whole operation, dry runs and queries included. Defaults:

| Verb | Default `timeout_ms` |
| ---- | -------------------- |
| `info`, `search` | 5000 (5 s) |
| `snapshot` | 15000 (15 s) |
| `restore`, `apply_lock` | 180000 (3 min) |
| `install`, `remove`, `list_installed` | 600000 (10 min) |
| `update`, `upgrade` | 900000 (15 min) |

`timeout_ms` must be greater than 0. `search` looks up the details (version, installed state, repository) of each returned result with the same queries as `info`, so a large `limit` on a slow system may need a larger `timeout_ms` than the 5 s default; `include_installed`, `include_versions` and `include_repo` all false skip those queries.

At the deadline the package manager that is running is stopped: resh sends `SIGTERM` to its whole process group (the manager and every process it started, such as `dpkg` or a maintainer script), then `SIGKILL` after 1.5 s to whatever is left. No further command is started. resh then exits with status 124 and `Error: [pkg.timeout] ...`; for the verbs that print a result before stopping (`install`, `remove`, `restore`), the packages handled so far are in it. A timeout means the outcome is unknown: the manager may have been stopped in the middle of a change.

What a stopped package manager may leave behind, and how to check:

* **apt / dpkg**: packages unpacked but not configured, or half-installed. `dpkg --audit` lists them and `dpkg --configure -a` finishes them; then run the same `pkg` request again. An interrupted `apt-get update` leaves partial index files that the next update replaces. apt's and dpkg's locks are released when the processes end.
* **dnf / yum**: an rpm transaction stopped part-way can leave both the old and the new version of a package in the rpm database, or a package whose scriptlets did not run. `dnf check` (or `rpm -Va`) shows problems; `dnf distro-sync` or reinstalling the package repairs them. The transaction may be missing from `dnf history`.
* **pacman**: pacman keeps its lock file `/var/lib/pacman/db.lck` when it is killed, so the next pacman command fails with "unable to lock database". Check that no pacman is running, delete the file, and run `pacman -Dk` to check the database.
* **apk**: files of a package may be partly extracted. `apk fix` reinstalls the packages in the world file; `apk audit` lists changed files.
* **brew**: not tested; `brew doctor` and `brew missing` report problems.

### 3.4 Restore Behavior

`restore` compares the lockfile with the installed packages and builds a plan with `install`, `upgrade`, `downgrade`, `remove`, `keep`, `extra` and `unresolved` lists:

* A locked package that is not installed goes to `install`.
* A locked package installed at a different version goes to `upgrade` when the installed version is older and to `downgrade` when it is newer, in the manager's own version order (dpkg's for apt, rpm's for dnf and yum, `vercmp`'s for pacman, apk's for apk; brew compares the version strings). A newer installed version is kept when `allow_newer` is true (the default); otherwise it is downgraded with `allow_downgrades`, or else it is `unresolved`.
* A locked package without a version that is installed is kept.
* With a lockfile of upstream versions (`include_versions: minimal`), an installed package whose upstream version equals the locked one is kept whatever its build, and versions are compared by their upstream part. `exact` installs the newest build of the locked upstream version that the repositories carry (apt `apt-cache madison`, dnf and yum `list --showduplicates --available`, apk `apk policy`; pacman only when its repository version is a build of it) and accepts any build of it afterwards; when no build of it is available the pinned command fails (`best_effort` then installs the repository version).
* Packages installed on the host but not in the lockfile are listed in `extra`, or **removed** when `allow_removals` is `true`. Use this with care: on a full system it removes every package missing from the lockfile.
* `mode` decides the versions:
  * `exact` (the default) installs, upgrades and downgrades to the **locked version** (`name=ver` for apt and apk, `name-ver` for dnf and yum; apt downgrades with `--allow-downgrades`, dnf and yum with `downgrade`). After each command, resh reads the installed version; a package that is not at the locked version is a failure. pacman and brew cannot install a given version: pacman installs by name the packages whose locked version is the one its repositories carry (`pacman -Si`), and a plan that needs any other version is refused before anything runs (exit 2, `pkg.unsupported_option`), as is any locked version for brew.
  * `best_effort` also passes the locked version, but when that command fails (the version is no longer in the repositories) it installs the repository version instead and adds a warning naming the package. With pacman and brew the repository version is installed (with a warning) and a downgrade, which they cannot do, is `unresolved`.
* Each package is installed, upgraded, downgraded or removed with its own command, in that order, so one failure does not stop the others; `results` reports each operation with `from_version`, `to_version`, `locked_version` and, on failure, `error` (`code`, `message`). A dry run lists the exact commands (`commands`).
* `on_missing_package` decides what happens with `unresolved` packages: `fail` (the default) refuses the restore before anything runs, dry run included (exit 1, `pkg.unresolved`); `warn` adds a warning and leaves them; `ignore` leaves them silently.
* `include_dependencies` (default `true`): with `false`, locked packages whose `install_reason` is `dependency` are left out of the plan. They are not installed, kept, upgraded or removed (not even with `allow_removals`), and are listed in `plan.skipped_dependencies`. A lockfile without install reasons cannot be filtered: a text lockfile without reasons, or a snapshot taken with `include_install_reason: false`. Such packages stay in the plan and a warning names them.
* `on_repo_mismatch` (`fail` / `warn` / `ignore`, default `warn`) compares each locked package's recorded `repository` with the host's repository for that package. The host side is looked up with the same query `snapshot` uses, so both sides have the same form. The host repository is only known for installed packages. A mismatch makes `fail` refuse the restore before anything runs, dry run included (exit 1, `pkg.repo_mismatch`). With `warn` it adds a warning; `ignore` skips the check. With `fail` and `warn`, packages that cannot be compared are reported in warnings rather than passed silently: no repository in the lockfile, not installed on the host, or a host repository that could not be determined. Packages left out by `include_dependencies: false` are not checked. With apt, the repository is the suite and component that `apt-cache policy` lists for the **installed** version (such as `noble/main`, or `./` for a flat repository); a package that only appears in `/var/lib/dpkg/status` (installed from a local file, or its version is no longer in any repository) has no repository. Lockfiles written by earlier releases recorded the priority (such as `500`) for apt packages, so with them every apt package reports a mismatch; take a new snapshot.
* `on_platform_mismatch` (`fail` / `warn` / `ignore`, default `warn`) compares the lockfile's OS name and architecture with the host's, read the same way `snapshot` reads them: `fail` refuses the restore before anything runs (exit 1, `pkg.platform_mismatch`), `warn` adds a warning.
* `extra_args` is added to every install, upgrade, downgrade and remove command; `env` is set for every command.
* The output has a `warnings` list (empty when there is nothing to report).
* The lockfile `format` is `auto` (the default: JSON, then YAML, then text), `json`, `yaml` or `text`. A text lockfile has one package per line, `name[=version]`, optionally followed by ` [arch]`, ` @repository`, ` (manual|dependency)` and ` [pinned]`, as `snapshot` writes it; `#` lines are comments, and `# manager: <name>` records the manager. A text lockfile without a manager line restores with the given manager, or with the detected one for `manager: auto`. A lockfile that names an unknown manager, or a different manager than the request (dnf and yum count as the same), is refused (exit 2).
* The lockfile's `pinned` (held) flags and `architecture` are recorded but not applied: restore neither holds packages nor selects architectures, and multi-arch duplicates of one name (such as `libc6` for two architectures) are treated as one package.

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

Errors are printed to standard error as `Error: [pkg.<code>] <message>`. Exit statuses: 0 success; 1 the operation failed; 2 the request was refused and nothing was run; 124 the deadline passed (outcome unknown).

| Code | Exit | Meaning |
| ---- | ---- | ------- |
| `pkg.unknown_verb` | 2 | A verb the handle does not have. |
| `pkg.invalid_argument` | 2 | Missing or malformed `input`, an argument other than `input`, an unknown key, a value of the wrong type or outside its set, an invalid package name, version, arch, query, pattern or `env`, `timeout_ms` of 0, contradictory options (such as `only_if_missing` with `reinstall`), a package `source` |
| `pkg.unsupported_option` | 2 | An option the manager cannot honor (see "Options by manager"), `security_only` where it is not supported, a restore `mode: exact` that needs a version pacman or brew cannot install |
| `pkg.invalid_lockfile` | 2 | A restore lockfile that cannot be read, has an unsupported `lockfile_version`, an invalid package entry or an unknown manager |
| `pkg.manager_mismatch` | 2 | The request's manager differs from the lockfile's |
| `pkg.manager_not_found` | 1 | The manager binary is not on `PATH` (or none is found for `auto`) |
| `pkg.not_found` | 1 | A package is unknown to the manager (`install`, `info`), or not installed for `remove` |
| `pkg.permission_denied` | 1 | The manager reports a permission error (run as root) |
| `pkg.dependency_failure` | 1 | The manager reports unresolvable or broken dependencies |
| `pkg.conflict` | 1 | The manager reports a conflict |
| `pkg.index_failed` | 1 | Refreshing the package index failed |
| `pkg.command_failed` | 1 | Any other package-manager or query failure |
| `pkg.partial_failure` | 1 | `install`, `remove`, `update`, `upgrade`, `restore` or `info` printed its result, but some package operations or queries failed (`summary.failed`, `error` per package, `autoremove_error`) |
| `pkg.platform_mismatch` | 1 | `on_platform_mismatch: fail` and the lockfile is from another OS or architecture |
| `pkg.repo_mismatch` | 1 | `on_repo_mismatch: fail` and a package comes from another repository |
| `pkg.unresolved` | 1 | `on_missing_package: fail` and the plan has unresolved packages |
| `pkg.downgrade_refused` | 1 | `install` with a `version` older than the installed one, without `allow_downgrade` |
| `pkg.timeout` | 124 | `timeout_ms` passed; the package manager was stopped (see 3.3) |

Inside a result, `install` and `remove` mark a failed package with `"action": "failed"` and `restore` with `"status": "failed"`; each carries `"error": {"code": "pkg.<code>", "message": "..."}` with one of the codes above. `info` reports an unknown package with `"found": false` and exits 1 (`pkg.not_found`).

---

## 4. Functional Domains

### 4.1 Automation Utilities

* CI/CD build agent setup
* Environment standardization
* Automated patching

### 4.2 Data & State Management

* Dependency auditing
* Drift detection (compare snapshots, or run `restore` with `dry_run` to see the plan)
* Recording and restoring the installed package set

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
* Snapshot the package set and restore it, at the locked versions where the manager can install them

### 4.4 Security

* Security-only updates (`security_only=true`) are honored only where resh can pass `--security`: `update` with dnf or yum, and `upgrade` with dnf. For any other manager (update: apt, pacman, apk, brew; upgrade: apt, yum, pacman, apk, brew) the request fails before anything runs, including in `dry_run` and `check_only`, with `security_only is not supported by pkg <verb> for <manager> (only ...); nothing was run.` (exit 2, `pkg.unsupported_option`). It is never silently dropped.
* Lockfile package names are validated before any command runs
* Platform mismatch detection on restore (`on_platform_mismatch`)
* Package-manager commands require root privileges; resh does not elevate privileges itself.

### 4.5 System Information

`info`, `list_installed` and `snapshot` can report installed and candidate versions, architecture, repository, installation reason, OS metadata and the manager version, depending on the manager and the `include_*` keys. `info` and `search` report `repository` in the same form as `snapshot` (for apt the suite/component of the installed version, or of the candidate when the package is not installed, such as `noble/main`) and the source URL in `repository_url` (apt only; null elsewhere). `info` with `include_repo: false` and `list_installed` with `include_versions: false` keep the `repository`, `repository_url` / `version` keys and set them to null. `snapshot` always returns the lockfile in the `lockfile` field; a request with an `inline` key (which older releases accepted without effect) is refused before anything runs (exit 2, `pkg.invalid_argument`).

---

## 5. Platform Support

* Linux is the only supported platform for resh.
* apt (Debian 13, Ubuntu 24.04), dnf (Fedora 42), yum (Rocky Linux 9, where `yum` is dnf's compatibility command), pacman (Arch Linux) and apk (Alpine) are tested end to end in throwaway Docker containers (`tests/pkg_e2e_docker.rs`): install, remove, upgrade, snapshot, restore with `mode: exact`, and timeouts that stop the manager. Other verbs and options are tested against fake package managers.
* The brew backend exists in the code but was never executed in testing; treat it as untested.
* Other package managers (such as zypper or eopkg) are not supported.

---

## 6. Operational Best Practices

* Use `dry_run` before applying changes.
* Take snapshots before upgrades; `restore` with `mode: exact` can then return to the recorded versions while the repositories still carry them.
* Rely on the default `only_if_missing` behaviour for idempotent installs.
* Set a larger `timeout_ms` for `search` and `info` on slow systems, and check the package manager's state after a timeout (3.3).
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

* Implemented in Rust; package managers are run as subprocesses with argument vectors (no shell), each in its own process group so a timeout stops everything it started.
* Fixed verb set; input is one JSON object deserialized per verb, with the accepted keys checked first.
* Wall-clock timeouts on every verb.
