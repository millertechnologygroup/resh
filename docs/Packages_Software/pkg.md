# Resource Shell (resh) – Package Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using structured URI-based commands. The `pkg://` handle provides package management capabilities across multiple operating systems and package managers.

### Purpose

The Package Manager handle enables:

* Installation and removal of software packages
* System-wide updates and upgrades
* Package search and metadata inspection
* Installed package inventory reporting
* System state snapshot and restoration
* Cross-platform abstraction across major package managers

All operations use structured JSON input and produce structured output suitable for automation.

### Architectural Problem Addressed

Traditional package manager tooling:

* Varies significantly across platforms (`apt`, `dnf`, `yum`, `pacman`, `apk`, `brew`)
* Produces human-oriented output
* Requires shell parsing for automation
* Has inconsistent behavior across systems

resh addresses this by:

* Abstracting multiple package managers under a unified interface
* Standardizing verb semantics
* Enforcing structured JSON input
* Returning structured, machine-readable results
* Supporting dry-run execution and deterministic output contracts

### Resource-Oriented URI Model

resh commands use:

```
handle://target.verb(options)
```

For package management:

* **handle**: `pkg://`
* **target**: alias (commonly `system`)
* **verb**: package operation (`install`, `remove`, `update`, etc.)
* **options**: JSON configuration passed via `input`

Example:

```
resh pkg://system.install input='{"manager":"auto","packages":[{"name":"curl"}]}'
```

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

* Nine explicit verbs define package lifecycle operations.
* All configuration is provided via JSON.
* Structured output reports operation results.
* Manager auto-detection is standardized.

---

### Safety-First Execution

* `dry_run` available for install, remove, update, upgrade, restore.
* `only_if_missing` prevents unnecessary reinstallations.
* `fail_if_missing` controls strict removal behavior.
* Timeout control (`timeout_ms`) limits execution duration.
* Snapshot and restore enable state rollback capability.

---

### Deterministic Behavior

* Explicit flags control behavior (e.g., `assume_yes`, `reinstall`, `security_only`).
* Identical JSON input yields consistent structured output.
* Auto-detection logic is consistent across supported managers.
* Exit codes reflect defined failure categories.

---

### JSON-Based Structured Output

Each verb returns structured JSON summarizing:

* Operation counts (installed, upgraded, removed, failed)
* Metadata (manager, alias)
* Warnings and errors
* Status indicators

Example (install result):

```json
{
  "installed": 2,
  "upgraded": 0,
  "reinstalled": 0,
  "unchanged": 0,
  "failed": 0
}
```

---

### AI-Readiness

Structured outputs allow:

* Automated dependency validation
* Change detection
* Idempotent configuration enforcement
* Snapshot-based state comparison
* Machine reasoning over system state

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
resh pkg://alias.verb input='{"json":"config"}'
```

| Component | Description                           |
| --------- | ------------------------------------- |
| `handle`  | `pkg://`                              |
| `alias`   | Logical system alias (e.g., `system`) |
| `verb`    | Package operation                     |
| `input`   | JSON configuration                    |

---

### Supported Verbs

| Verb             | Description                       |
| ---------------- | --------------------------------- |
| `install`        | Install packages                  |
| `remove`         | Remove packages                   |
| `update`         | Refresh index and update packages |
| `upgrade`        | Upgrade packages                  |
| `info`           | Package metadata lookup           |
| `search`         | Search repositories               |
| `list_installed` | List installed packages           |
| `snapshot`       | Capture system package state      |
| `restore`        | Restore from snapshot             |
| `apply_lock`     | Alias for `restore`               |

---

### Example Commands

#### Install Packages (Dry Run)

```bash
resh pkg://system.install input='{
  "manager":"auto",
  "packages":[{"name":"curl"},{"name":"git"}],
  "dry_run":true
}'
```

#### Remove Package

```bash
resh pkg://system.remove input='{
  "packages":[{"name":"curl"}],
  "purge":false,
  "dry_run":true
}'
```

#### Update System

```bash
resh pkg://system.update input='{
  "refresh_index":true,
  "upgrade":true
}'
```

#### Search for Packages

```bash
resh pkg://system.search input='{
  "query":"curl",
  "limit":20
}'
```

#### Create Snapshot

```bash
resh pkg://system.snapshot input='{
  "scope":"all",
  "include_versions":"exact",
  "format":"json"
}'
```

#### Restore from Snapshot

```bash
resh pkg://system.restore input='{
  "lockfile":"{...}",
  "mode":"exact",
  "dry_run":true
}'
```

---

## 3.2 Execution Semantics

### Deterministic Behavior

* Operations depend solely on JSON input.
* Auto-detection selects appropriate backend manager.
* Snapshot captures reproducible state.
* Restore behavior controlled via `mode`, `allow_downgrades`, etc.

---

### Structured Output Contracts

Representative snapshot output:

```json
{
  "lockfile_version": "1.0",
  "manager": {
    "name": "apt",
    "alias": "system"
  },
  "platform": {
    "os_family": "unix",
    "architecture": "x86_64"
  },
  "packages": [
    {
      "name": "curl",
      "version": "7.68.0-1ubuntu2.19"
    }
  ]
}
```

---

### Error Handling Structure

Representative error:

```json
{
  "status": "failure",
  "failed": 1,
  "warnings": [
    "Repository mismatch for package xyz"
  ]
}
```

Exit codes are defined and documented within built-in help.

---

## 4. Functional Domains

### 4.1 Automation Utilities

**Scope**

System provisioning and dependency automation.

**Use Cases**

* CI/CD build agent setup
* Environment standardization
* Automated patching

---

### 4.2 Data & State Management

**Scope**

Package state inspection and reproducibility.

**Use Cases**

* Dependency auditing
* Drift detection
* System state backups
* Lockfile-based enforcement

---

### 4.3 Filesystem & Storage

**Scope**

Snapshot and restore operations managing system package state as lockfiles.

**Use Cases**

* Backup before major upgrades
* Rollback capability
* System cloning

---

### 4.4 Network & Remote Operations

Indirectly supports:

* Downloading packages from repositories
* Remote repository synchronization

---

### 4.5 Packages & Software

**Supported Managers**

* apt
* dnf
* yum
* pacman
* apk
* brew

**Core Capabilities**

* Install/remove packages
* Upgrade system
* Inspect metadata
* Search repositories
* Capture and restore state

---

### 4.6 Process & Service Management

Indirectly supports:

* Installing service binaries
* Updating service versions
* Removing deprecated services

---

### 4.7 Security & Secrets

Security-related capabilities:

* Security-only updates (`security_only`)
* Snapshot validation
* Strict restore policies (`on_missing_package`)
* Platform mismatch detection

---

### 4.8 System Information

Structured reporting includes:

* Installed package versions
* Architecture
* Repository source
* Installation reason
* OS metadata
* Manager version

---

## 5. Platform Support

Supported package managers:

| Manager | Platform              |
| ------- | --------------------- |
| apt     | Ubuntu, Debian        |
| dnf     | Fedora, CentOS Stream |
| yum     | RHEL, CentOS          |
| pacman  | Arch Linux            |
| apk     | Alpine Linux          |
| brew    | macOS, Linux          |

Auto-detection (`manager: "auto"`) selects the appropriate backend.

No additional platform limitations are specified in documentation.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Use `dry_run` before applying changes.
* Take snapshots before upgrades.
* Use `only_if_missing` to maintain idempotency.
* Apply security updates regularly.
* Set appropriate `timeout_ms`.

---

### Automation Considerations

* Always evaluate `failed` and `warnings`.
* Use snapshots for drift detection.
* Enforce strict restore policies in production.
* Use `check_only` when validating changes.

---

### CI/CD Integration

Typical sequence:

1. `update` (refresh index)
2. `install` dependencies
3. `snapshot` environment state
4. Validate build
5. Restore environment as needed

---

### Production Environment Recommendations

* Maintain periodic snapshots.
* Use exact version restore for production.
* Enable `security_only` updates where required.
* Avoid force removal without validation.
* Review repository mismatches carefully.

---

## 7. Use Cases by Role

### DevOps Engineers

* Provision build agents.
* Automate dependency installation.
* Standardize environments across teams.

---

### SRE Engineers

* Audit installed packages.
* Apply security patches.
* Detect configuration drift via snapshots.

---

### Network Administrators

* Install networking tools.
* Maintain consistent package baselines.
* Verify repository sources.

---

### AI / Automation Engineers

* Analyze structured install results.
* Detect failed operations programmatically.
* Implement environment compliance validation.
* Compare snapshot states automatically.

---

## 8. Technical Foundation

### Rust Implementation Advantages

resh is implemented in Rust, providing:

* Memory safety
* Strong compile-time guarantees
* Deterministic execution
* Efficient subprocess management

---

### Type Safety

* Enumerated verb set
* Strict JSON schema validation
* Controlled parameter behavior
* Structured error typing

---

### Performance Characteristics

* Native binary execution
* Controlled timeouts
* Efficient backend invocation
* Minimal parsing overhead

---

### Cross-Platform Architecture

* Unified abstraction over multiple package managers
* OS-specific manager detection
* Consistent JSON output across supported systems

