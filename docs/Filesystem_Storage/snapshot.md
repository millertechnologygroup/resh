# Resource Shell (resh) – Snapshot Handle Documentation

## 1. Overview

Resource Shell (resh) is a structured command execution framework that standardizes infrastructure operations using a resource-oriented URI model.

The `snapshot://` handle provides filesystem snapshot management with atomic guarantees. It enables:

* Creation of filesystem snapshots
* Restoration of snapshots to target paths
* Comparison of snapshots and live filesystem state
* Listing and filtering snapshots within logical groups

Snapshots capture the complete state of files or directories at a point in time. All operations are designed to be atomic, ensuring no partial state is exposed during creation or restoration.

Traditional snapshot and backup workflows often depend on external tools, manual directory copying, or filesystem-specific snapshot features. The `snapshot://` handle provides a uniform, portable interface independent of underlying filesystem capabilities.

All snapshot operations follow one of two URI formats:

**Create / Diff (path-based):**

```
snapshot://TARGET_PATH.verb(arguments)
```

**Restore / List (snapshot-based):**

```
snapshot://SNAPSHOT_NAME.verb(arguments)
```

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

All operations use consistent URI grammar:

```
snapshot://target.verb(arguments)
```

The handle provides four verbs:

* `create`
* `restore`
* `diff`
* `ls`

The grammar separates snapshot identity from filesystem targets to reduce ambiguity.

---

### Safety-First Execution

Safety mechanisms include:

* Atomic snapshot creation
* Atomic restore staging and swap
* Explicit `force=true` requirement for overwrites
* `dry_run=true` support for restore
* Explicit name conflict handling (`if_exists`)
* TTL-based expiration controls

No partial snapshots are left behind on failure.

---

### Deterministic Behavior

Snapshot operations:

* Require explicit arguments
* Enforce case-sensitive snapshot names
* Use strict exit codes
* Preserve metadata and permissions
* Prevent live-to-live diff comparisons
* Require at least one of `from` or `to` in diff operations

Exit Codes:

| Code | Meaning          |
| ---- | ---------------- |
| 0    | Success          |
| 1    | General error    |
| 2    | Not found        |
| 3    | Already exists   |
| 4    | Target not empty |

Automation systems must rely on exit codes and structured output.

---

### JSON-Based Structured Output

Most operations return structured JSON.

Example (create):

```json
{
  "ok": true,
  "backend": "local",
  "id": "generated-id",
  "name": "backup-v1",
  "target": "/srv/app",
  "created_at": "2025-11-15T18:01:02Z",
  "expires_at": null,
  "skipped": false
}
```

Example (diff summary section):

```json
{
  "summary": {
    "added": 2,
    "removed": 1,
    "modified": 3,
    "unchanged": 10
  }
}
```

Structured output supports:

* CI/CD validation
* Change auditing
* Automated rollback workflows
* Compliance checks

---

### AI-Readiness

The snapshot handle enables:

* Deterministic change tracking
* Structured difference analysis
* Automated rollback decision-making
* Integration into orchestration agents

The `diff` verb provides machine-readable delta information suitable for automated policy evaluation.

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
snapshot://target.verb(arguments)
```

#### Components

| Component   | Description                                   |
| ----------- | --------------------------------------------- |
| `snapshot`  | Handle identifier                             |
| `target`    | Filesystem path or snapshot name              |
| `verb`      | Operation (`create`, `restore`, `diff`, `ls`) |
| `arguments` | Named parameters                              |

---

### Examples

Create snapshot:

```bash
snapshot:///srv/app.create(name="before-deploy")
```

Restore snapshot:

```bash
snapshot://before-deploy.restore(target="/srv/app",force=true)
```

Compare snapshot to live:

```bash
snapshot:///srv/app.diff(from="before-deploy",to="live",format="summary")
```

List snapshots:

```bash
snapshot://myapp.ls(limit=10)
```

---

### 3.2 Execution Semantics

Operations follow atomic semantics:

**Create**

* Snapshot staged in temporary location
* Moved atomically into final storage
* Metadata written last

**Restore**

* Target staged
* Final replacement atomic
* Original data preserved until completion

**Diff**

* Computes file-level comparisons
* Supports JSON and summary formats
* Supports path filtering

Representative JSON (restore):

```json
{
  "snapshot": "backup-v1",
  "target": "/srv/app",
  "mode": "overwrite",
  "status": "ok"
}
```

Representative JSON (ls):

```json
[
  {
    "id": "snap-003",
    "name": "deploy-v2",
    "created_at": "2025-11-15T18:03:02Z",
    "backend": "local",
    "target": "/srv/app",
    "state": "ready"
  }
]
```

---

## 4. Functional Domains

### 4.1 Automation Utilities

Snapshot operations enable:

* Pre-deployment state capture
* Post-change verification
* Change detection
* Rollback orchestration

Common pattern:

```bash
snapshot:///srv/app.create(name="pre-change")
```

---

### 4.2 Data & State Management

Snapshots preserve:

* Full directory trees
* File permissions
* Metadata
* Timestamps
* Optional expiration metadata

Use cases:

* Configuration tracking
* Data state preservation
* Version tracking
* Compliance validation

---

### 4.3 Filesystem & Storage

Snapshots operate on:

* Files
* Directories

Limitations:

* Local backend only
* No compression
* No deduplication
* No incremental snapshots
* No cross-filesystem snapshotting

Storage structure:

```
<state_dir>/resh/snapshots/<group>/<snapshot>/
```

---

### 4.4 Network & Remote Operations

Not applicable (local storage only).

---

### 4.5 Packages & Software

Indirectly supports deployment workflows by enabling:

* Version checkpointing
* Safe rollbacks
* Deployment verification

---

### 4.6 Process & Service Management

Supports safe configuration updates when combined with service restarts.

---

### 4.7 Security & Secrets

Preserves:

* File modes
* Special permission bits
* Symbolic links

Ownership preservation depends on execution privileges.

---

### 4.8 System Information

`ls` supports filtering by:

* State
* Tag
* Time range (`since`, `until`)
* Name prefix
* Result limit

Example:

```bash
snapshot://myapp.ls(state=ready,limit=5)
```

---

## 5. Platform Support

Based strictly on documentation:

* Linux supported
* macOS supported
* Windows supported

Storage locations:

* Linux: `$XDG_STATE_HOME/resh/snapshots`
* macOS: `~/Library/Application Support/resh/snapshots`
* Windows: `%APPDATA%/resh/snapshots`

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Always snapshot before risky operations.
* Use `if_exists="error"` for manual operations.
* Use `if_exists="skip"` for idempotent automation.
* Use `dry_run=true` before restore with force.
* Apply TTL to manage storage lifecycle.

---

### Automation Considerations

* Use JSON output for CI pipelines.
* Validate `ok` flag.
* Monitor snapshot storage growth.
* Use consistent naming conventions.
* Filter `ls` output by prefix or tags.

---

### CI/CD Integration

Deployment example:

```bash
snapshot:///srv/app.create(name="deploy-20250207")

# deploy application

snapshot:///srv/app.diff(from="deploy-20250207",to="live",format="summary")
```

Rollback example:

```bash
snapshot://deploy-20250207.restore(target="/srv/app",force=true)
```

---

### Production Recommendations

* Use timestamped names for automated backups.
* Enforce retention using TTL.
* Avoid force restore without review.
* Snapshot only required directories.
* Monitor storage capacity regularly.

---

## 7. Use Cases by Role

### DevOps Engineers

* Create deployment checkpoints.
* Compare release states.
* Implement automated rollback.
* Track configuration drift.

---

### SRE Engineers

* Perform safe recovery during incidents.
* Audit filesystem changes.
* Validate state after outages.
* Track system configuration evolution.

---

### Network Administrators

* Preserve configuration before updates.
* Restore device configurations.
* Track configuration differences.

---

### AI / Automation Engineers

* Use diff JSON for policy evaluation.
* Trigger rollback based on modified file count.
* Automate change validation.
* Integrate snapshot lifecycle management.

---

## 8. Technical Foundation

The snapshot handle is implemented within resh’s Rust-based execution framework.

### Rust Implementation Advantages

* Memory safety
* Atomic file operations
* Deterministic error handling
* Cross-platform compatibility

---

### Type Safety

* Strict argument validation
* Required parameter enforcement
* Controlled overwrite semantics
* Case-sensitive snapshot identity

---

### Performance Characteristics

* Full copy snapshots
* No deduplication
* Snapshot time proportional to data size
* Diff faster than full snapshot
* Restore speed dependent on target filesystem

---

### Cross-Platform Architecture

Supported on:

* Linux
* macOS
* Windows

Snapshots rely on local filesystem storage and operate independently of underlying filesystem snapshot capabilities.

