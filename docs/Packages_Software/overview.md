# Resource Shell (resh) – Packages & Software Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using structured URI-based commands. The **Packages & Software** domain covers two handles:

* `pkg://` – system packages through the host package manager (apt, dnf, yum, pacman, apk, brew). See [pkg.md](pkg.md).
* `git://` – local Git repositories through libgit2. See [git.md](git.md).

### Purpose

This domain provides:

* Installation, update, removal, search and inspection of system packages
* Snapshots of the installed package set as a lockfile
* Git repository status, diffs, branches, tags, commits, merges, rebases, clone, pull, push and fast-forward sync
* JSON output for automation

### Resource-Oriented URI Model

```text
resh pkg://<alias>.<verb> input=<json>
resh git://<alias>.<verb> path=<repo-dir> [key=value ...]
```

* **alias**: a free-form label (for example `system` or `main`), echoed in the output
* **pkg** verbs take all options as one JSON object in `input`, which must include `manager` (`apt`, `dnf`, `yum`, `pacman`, `apk`, `brew` or `auto`)
* **git** verbs take `key=value` arguments and always need `path`, the repository directory

Examples:

```bash
resh pkg://system.install 'input={"manager":"auto","packages":[{"name":"nginx"}]}'
resh git://main.clone url=https://github.com/org/project.git path=/srv/project
```

---

## 2. Verbs

| Handle | Registered verbs |
| ------ | ---------------- |
| `pkg`  | `install`, `remove`, `update`, `upgrade`, `info`, `search`, `list_installed`, `snapshot`, `restore`, `apply_lock` (alias for `restore`) |
| `git`  | `status`, `status_summary`, `status_short`, `diff`, `branch`, `tag`, `commit`, `merge`, `rebase`, `clone`, `pull`, `push`, `sync` |

Built-in help: `resh pkg --help`, `resh git --help`, `resh <handle> <verb> --help`.

---

## 3. Command Syntax and Execution Model

### 3.1 Examples

#### Install Software Package

```bash
resh pkg://system.install 'input={"manager":"auto","packages":[{"name":"curl"}]}'
```

#### Check for Updates

```bash
resh pkg://system.update 'input={"manager":"auto","check_only":true}'
```

#### Remove Package (Dry Run)

```bash
resh pkg://system.remove 'input={"manager":"auto","packages":[{"name":"nginx"}],"dry_run":true}'
```

#### Search for Software

```bash
resh pkg://system.search 'input={"manager":"auto","query":"database"}'
```

#### Clone Git Repository

```bash
resh git://repo.clone url=https://github.com/example/project.git path=/srv/project
```

#### Commit Changes

```bash
resh git://repo.commit path=/srv/project 'message=Fix configuration issue' all=true
```

#### Pull Updates (fast-forward only)

```bash
resh git://repo.pull path=/srv/project remote=origin
```

---

### 3.2 Execution Semantics

* `pkg` runs the package manager directly with an argument vector (no shell) and validates package names, versions and architectures before running anything.
* `git` uses libgit2 linked into resh; it does not run the `git` binary or Git credential helpers.
* Each `resh` invocation is a separate process; nothing is kept between invocations.

### 3.3 Timeouts

* `pkg`: every verb enforces `timeout_ms` (a key inside the JSON). Defaults range from 5 s (`info`, `search`) to 15 min (`update`, `upgrade`); see [pkg.md](pkg.md).
* `git`: `timeout_ms` is **rejected** with exit code 2 for every verb, because libgit2 calls cannot be interrupted. Git operations are not time-limited; use an external `timeout(1)` if needed.

### 3.4 Output

Both handles print one JSON object on success. Representative `pkg install` output (apt):

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

### 3.5 Errors

Errors are printed as one line on standard error and the exit code is 1 (git `timeout_ms` rejection: 2). There is no JSON error object. Examples:

```text
Error: Invalid info configuration: Invalid JSON: missing field `manager` at line 1 column 18
Error: git.repository_not_found: repository not found: /srv/project
```

A `pkg` verb that changes packages exits 1 if any package operation failed (for example `pkg install: 1 of 2 package operations failed`), after printing its JSON result.

---

## 4. Functional Domains

### 4.1 Automation Utilities

* CI/CD dependency provisioning
* Automated environment bootstrapping
* System maintenance automation

### 4.2 Data & State Management

* Dependency auditing (`list_installed`, `info`, `snapshot`)
* Repository status inspection (`status`, `status_summary`)

### 4.3 Filesystem & Storage

* Cloning repositories
* Managing branches
* Staging and committing changes

### 4.4 Network & Remote Operations

* Downloading packages from the configured repositories
* Cloning, pulling (fast-forward only), pushing, and fast-forward `sync`

### 4.5 Packages & Software

**Package Management Capabilities**

* Install, update, upgrade and remove packages
* Search the package index
* Inspect installed versions
* Snapshot the installed package set. `restore` reinstalls missing packages by name; it does **not** pin the locked versions (see [pkg.md](pkg.md)).

**Git Capabilities**

* Clone repositories (no shallow clone, no submodules)
* Commit, branch, tag, diff
* Explicit `merge` and `rebase` verbs
* `pull` and `sync` fast-forward only; they never merge or rebase diverged branches

### 4.6 Security & Secrets

* Install from trusted repositories.
* `pkg` package-manager commands generally need root; resh does not elevate privileges.
* Git credentials passed as arguments (`password=`, `token=`) are visible in the process list and shell history.
* Avoid committing sensitive data.

---

## 5. Platform Support

* Linux is the only supported platform for resh.
* `pkg`: the apt, dnf, yum, pacman and apk backends were exercised in Linux test sandboxes; the brew backend exists in the code but was never executed in testing.
* `git`: uses the libgit2 built into resh; no `git` binary is required.

---

## 6. Operational Best Practices

* Use `dry_run` (inside the `pkg` JSON) before changing packages.
* Check the exit code and `summary.failed` after `pkg` changes.
* Use `git status_summary` before destructive Git operations.
* When `git sync` reports diverged history, rebase or merge explicitly, then sync again.

### CI/CD Integration

Typical workflow:

1. Install required dependencies via `pkg install`.
2. Clone the repository via `git clone`.
3. `git pull` (fast-forward) before build.
4. Commit changes during automation workflows.
5. Validate installed versions with `pkg list_installed` or `pkg info`.

---

## 7. Use Cases by Role

### DevOps Engineers

* Provision development environments.
* Automate dependency installation.
* Manage repository workflows.

### SRE Engineers

* Keep systems patched.
* Audit package versions.
* Track infrastructure code changes.

### AI / Automation Engineers

* Automate environment setup.
* Analyze dependency state programmatically.
* Trigger updates based on structured version checks.

---

## 8. Technical Foundation

* Implemented in Rust.
* `pkg` runs package managers as subprocesses with argument vectors; `git` uses libgit2 in-process.
* Fixed verb sets with per-verb argument validation.
