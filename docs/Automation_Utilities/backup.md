# Resource Shell (resh) – Backup Handle Documentation

## 1. Overview

Resource Shell (resh) is a structured command-line framework that standardizes system automation through a resource-oriented URI execution model.

The `backup://` handle provides lifecycle management for backups, including creation, listing, restoration, verification, pruning, and scheduling of backup operations.

Traditional backup tooling often requires:

* Backend-specific command syntax
* Manual output parsing
* Separate scheduling configuration
* Custom scripting for retention policies
* Inconsistent error handling

The `backup://` handle addresses these issues by:

* Providing a consistent URI-based interface
* Normalizing backend execution
* Returning structured JSON output
* Supporting deterministic automation workflows

All backup operations follow the resource URI format:

```
backup://profile.verb(arguments)
```

Where:

* `profile` identifies the logical backup configuration
* `verb` defines the operation
* `arguments` define execution parameters

---

## 2. Design Philosophy and Core Principles

The `backup://` handle follows resh architectural principles.

### Structured Interface Model

All backup operations use:

```
backup://profile.verb(arguments)
```

This removes backend-specific command complexity and provides a unified abstraction layer across multiple backup tools.

### Safety-First Execution

The handle supports:

* `dry_run` simulation
* Structured error envelopes
* Timeout control
* Retention policy management
* Explicit restore targets

These features reduce operational risk during backup and recovery workflows.

### Deterministic Behavior

Operations provide:

* Predictable command grammar
* Consistent JSON response structure
* Explicit status indicators (`ok` or `error`)
* Standard metadata fields

### JSON-Based Structured Output

All backup operations return structured JSON, enabling:

* CI/CD pipeline validation
* Programmatic restore automation
* Monitoring integration
* Audit logging

### AI-Readiness

The uniform interface and structured responses allow integration with:

* Automation agents
* Orchestration engines
* Declarative infrastructure workflows

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

All backup operations follow:

```
backup://profile.verb(arguments)
```

#### Components

| Component   | Description                                                            |
| ----------- | ---------------------------------------------------------------------- |
| `backup`    | Handle identifier                                                      |
| `profile`   | Logical backup configuration                                           |
| `verb`      | Operation (`create`, `list`, `restore`, `verify`, `prune`, `schedule`) |
| `arguments` | Named parameters controlling execution                                 |

---

### Examples

Create a backup:

```sh
backup://myapp.create(src="/data")
```

List snapshots:

```sh
backup://myapp.list()
```

Restore from snapshot:

```sh
backup://myapp.restore(snapshot_id="abcd1234", dest="/restore")
```

Verify repository:

```sh
backup://myapp.verify(mode="thorough")
```

Prune using retention policy:

```sh
backup://myapp.prune(keep_daily="7", keep_weekly="4")
```

Schedule automated backups:

```sh
backup://myapp.schedule(when="0 2 * * *", src="/data")
```

---

### 3.2 Execution Semantics

All operations follow a consistent response contract:

* `op` – Operation identifier
* `status` – `"ok"` or `"error"`
* `target` – Original URI invocation
* `backend` – Backend metadata and executed command
* `result` – Operation-specific output
* `dry_run` – Boolean simulation flag
* `duration_ms` – Execution time
* `warnings` – Non-fatal notices

#### Representative JSON Response

```json
{
  "op": "backup.create",
  "status": "ok",
  "target": "backup://myapp.create()",
  "backend": {
    "id": "restic",
    "command": ["restic", "backup", "--json", "/data"],
    "timeout_ms": 1800000,
    "simulated": false
  },
  "result": {
    "snapshot": {
      "id": "abcd1234",
      "label": "daily-backup",
      "created_at": "2024-01-01T12:00:00Z",
      "sources": ["/data"]
    }
  },
  "dry_run": false,
  "duration_ms": 5000,
  "warnings": []
}
```

#### Error Example

```json
{
  "op": "backup.create",
  "status": "error",
  "error": {
    "kind": "BACKEND_FAILED",
    "message": "Backend command failed"
  }
}
```

Automation logic must evaluate the `status` field for success or failure.

---

## 4. Functional Domain – Backup Handle

### Operational Scope

The `backup://` handle supports:

* Snapshot creation
* Snapshot listing
* Snapshot restoration
* Integrity verification
* Retention-based pruning
* Automated scheduling

---

### Supported Backends

The handle automatically selects the best available backend in this order:

1. `restic`
2. `borg`
3. `rsync`
4. `tar`

Backend selection may also be explicitly specified using the `backend` argument.

---

### Verbs

#### 4.1 create

Creates a backup snapshot.

**Required Argument:**

* `src` – Source path(s) (semicolon-separated)

**Optional Arguments:**

* `backend`
* `repo_url`
* `tag`
* `label`
* `exclude`
* `dry_run`
* `timeout_ms`
* `json_pretty`

---

#### 4.2 list

Lists snapshots in the repository.

Optional filtering via:

* `tag`
* `backend`
* `repo_url`

---

#### 4.3 restore

Restores a snapshot to a destination.

**Required:**

* `snapshot_id`
* `dest`

Optional filtering via:

* `include`
* `exclude`

---

#### 4.4 verify

Verifies repository or snapshot integrity.

Optional:

* `mode` (`quick` or `thorough`)
* `snapshot_id`

---

#### 4.5 prune

Applies retention policy rules:

* `keep_daily`
* `keep_weekly`
* `keep_monthly`
* `dry_run`

---

#### 4.6 schedule

Configures automated backups using system schedulers.

**Required:**

* `when` (cron or timer format)
* `src`

Optional:

* `enabled`
* `backend`

---

## 5. Platform Support

The backup handle supports:

| Platform   | Support Level                               |
| ---------- | ------------------------------------------- |
| Linux      | Full support                                |
| Unix/macOS | Supported                                   |
| Windows    | Supported (subject to backend availability) |

Platform behavior may vary depending on installed backup backend tools.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Use `dry_run="true"` before prune operations.
* Verify repositories regularly.
* Test restore procedures in staging environments.
* Use explicit `dest` paths during restore operations.

### Automation Considerations

* Parse structured JSON responses.
* Monitor `duration_ms` for performance tracking.
* Log `warnings` fields for audit review.
* Use timeout controls for long-running operations.

### CI/CD Integration

* Run `backup://profile.verify()` before deployment.
* Create pre-release snapshots.
* Validate retention compliance automatically.
* Gate pipeline progression based on `status` value.

### Production Recommendations

* Use descriptive tags and labels.
* Enable encryption when supported by backend.
* Define retention policies to control storage growth.
* Monitor backend health and exit codes.

---

## 7. Use Cases by Role

### DevOps Engineers

* Create deployment snapshots prior to upgrades.
* Automate backup retention management.
* Integrate verification into CI/CD workflows.

### SRE Engineers

* Validate repository integrity during maintenance windows.
* Restore services during incident recovery.
* Schedule recurring system backups.

### Network Administrators

* Protect configuration directories.
* Backup firewall and routing configurations.
* Restore network state after failure events.

### AI/Automation Engineers

* Integrate deterministic backup workflows into orchestration engines.
* Evaluate JSON status for automated remediation.
* Use `dry_run` for safe simulation scenarios.

---

## 8. Technical Foundation

The `backup://` handle is implemented within the resh framework, written in Rust.

### Rust Advantages

* Memory safety
* Compile-time validation
* Strong type enforcement
* Predictable binary behavior

### Type Safety

Argument parsing and response construction are type-validated to reduce runtime ambiguity.

### Performance Characteristics

* Efficient execution model
* Structured timeout enforcement
* Backend command encapsulation

### Cross-Platform Architecture

The handle operates across:

* Linux
* Unix/macOS
* Windows

Compatibility depends on installed backend utilities.
