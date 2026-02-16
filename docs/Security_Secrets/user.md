# Resource Shell (resh) – User Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using structured URI-based commands. The `user://` handle manages user accounts, groups, passwords, and group memberships on Linux/Unix systems.

### Purpose

The user domain enables:

* Creation and deletion of users and groups
* Group membership management
* Password management
* Account locking and unlocking
* Existence checks and group inspection
* Safe automation using dry-run and protection controls
* Support for both system and mock backends

All operations return structured JSON output suitable for automation, CI/CD workflows, and infrastructure orchestration.

### Architectural Problem Addressed

Traditional user management tools:

* Use imperative CLI flags
* Produce unstructured text output
* Require manual parsing for automation
* Provide inconsistent safety controls
* Lack structured dry-run and idempotent behavior

resh addresses these limitations by:

* Exposing user lifecycle operations as typed verbs
* Using structured parameters
* Returning deterministic JSON output
* Enforcing safety controls for system accounts
* Supporting idempotent scripting patterns

### Resource-Oriented URI Model

User operations follow:

```
handle://target.verb(options)
```

For user management:

* **handle**: `user://`
* **target**: user, group, or membership identifier
* **verb**: action (`add`, `delete`, `passwd`, `lock`, `unlock`, `groups`, `exists`)
* **options**: structured parameters

Examples:

```
user://alice.add(mode=user,username=alice)
user://group/admins.add(mode=group,group_name=admins)
user://alice.passwd(new_password_plain=Secret123!)
```

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

* Seven explicitly defined verbs.
* Typed `mode` for add/delete operations.
* Backend abstraction (`system`, `mock`).
* Deterministic JSON output.
* Explicit identity resolution via username or UID.

---

### Safety-First Execution

* `dry_run=true` supported for all mutating verbs.
* System user protection (UID < 1000).
* `protect_system_users=true` by default.
* `force=true` required to override safety checks.
* `ignore_if_missing` and `ignore_if_exists` for idempotency.
* Minimum UID enforcement for destructive operations.

---

### Deterministic Behavior

* Explicit parameter validation.
* Username and group validation rules.
* Structured output regardless of format.
* Consistent exit codes.
* Backend-specific behavior abstracted.

---

### JSON-Based Structured Output

Representative example (user creation):

```json
{
  "ok": true,
  "mode": "user",
  "backend": "mock",
  "dry_run": false,
  "user": {
    "username": "alice",
    "uid": 1001,
    "created": true,
    "existed": false
  },
  "warnings": []
}
```

All operations return structured objects describing:

* User existence state
* Changes performed
* Warnings
* Backend used

---

### AI-Readiness

Structured output enables:

* Automated user provisioning workflows
* Compliance validation
* System account protection auditing
* Idempotent infrastructure scripts
* Drift detection in access control

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
user://target.VERB(options)
```

| Component | Description                    |
| --------- | ------------------------------ |
| `handle`  | `user://`                      |
| `target`  | Username, group, or membership |
| `VERB`    | Action                         |
| `options` | Structured arguments           |

---

### Available Verbs

| Verb     | Purpose                           |
| -------- | --------------------------------- |
| `add`    | Create user, group, or membership |
| `delete` | Remove user, group, or membership |
| `passwd` | Change password                   |
| `lock`   | Lock account                      |
| `unlock` | Unlock account                    |
| `groups` | List group memberships            |
| `exists` | Check existence                   |

---

### Production Examples

#### Create User

```
user://alice.add(mode=user,username=alice,backend=system)
```

#### Create Group

```
user://group/dev.add(mode=group,group_name=dev)
```

#### Add Membership

```
user://membership/alice.add(mode=membership,member=alice,groups=dev,docker)
```

#### Delete User Safely

```
user://alice.delete(
  mode=user,
  remove_home=true,
  remove_from_all_groups=true,
  ignore_if_missing=true
)
```

#### Lock Account

```
user://alice.lock
```

#### Check Existence

```
user://alice.exists
```

---

## 3.2 Execution Semantics

### Deterministic Behavior

* Must provide `username` or `uid` for identity-based operations.
* `mode` required for add/delete.
* Conflicting password sources rejected.
* UID mismatch produces explicit failure.
* Dry-run produces structured preview without changes.

---

### Structured Output Contracts

Example: Password Change

```json
{
  "ok": true,
  "backend": "system",
  "user": {
    "username": "alice",
    "existed": true
  },
  "password": {
    "changed": true,
    "scheme": "sha512_crypt",
    "source": "plain"
  },
  "warnings": []
}
```

Example: Existence Check

```json
{
  "ok": true,
  "query": {
    "username": "alice",
    "uid": null
  },
  "user": {
    "exists": true,
    "username": "alice",
    "uid": 1001
  }
}
```

---

### Error Handling Structure

Representative error:

```json
{
  "ok": false,
  "error": {
    "code": "user.invalid_username",
    "message": "username cannot be empty"
  }
}
```

---

### Exit Codes

| Code | Meaning                |
| ---- | ---------------------- |
| 0    | Success                |
| 1    | General error          |
| 2    | Not found              |
| 3    | Already exists         |
| 4    | Validation error       |
| 5    | Permission denied      |
| 6    | System user protection |
| 7    | Invalid arguments      |

---

## 4. Functional Domains

---

### 4.1 Automation Utilities

**Handle**

* `user://`

**Scope**

* Automated user provisioning
* Idempotent infrastructure scripts
* Access lifecycle management
* Dev environment bootstrapping

---

### 4.2 Data & State Management

**Scope**

* Existence verification
* Group membership inspection
* UID/GID validation
* User lifecycle tracking

Example:

```
user://alice.groups(include_system_groups=false)
```

---

### 4.3 Filesystem & Storage

Operations interact with:

* `/etc/passwd`
* `/etc/shadow`
* `/etc/group`

Home directory management supported via:

```
remove_home=true
```

---

### 4.4 Network & Remote Operations

Indirectly supports:

* SSH access management
* Service account provisioning
* Identity-based access control for remote services

---

### 4.5 Packages & Software

Supports:

* Service account creation during deployment
* Post-install user/group configuration
* Permission assignment for applications

---

### 4.6 Process & Service Management

Integrates with:

* `svc://` for restarting services after account changes
* `exec://` for command execution under specific users
* `file://` for verifying home directory state

---

### 4.7 Security & Secrets

Primary capabilities:

* Password hashing (sha512_crypt, pbkdf2)
* System user protection
* UID/GID validation
* Forced operations require explicit override
* Lock/unlock operations for incident response

---

### 4.8 System Information

Structured reporting includes:

* UID
* Primary group
* Supplementary groups
* System group flag
* Existence state
* Lock status

---

## 5. Platform Support

| Platform   | Support Level   |
| ---------- | --------------- |
| Linux      | Full support    |
| Unix/macOS | Limited support |
| Windows    | Not supported   |

System backend relies on native system tools:

* `useradd`
* `userdel`
* `usermod`
* `passwd`

Mock backend provides test-only functionality.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Use `dry_run=true` before destructive operations.
* Keep `protect_system_users=true`.
* Avoid `force=true` in automation.
* Use `ignore_if_missing=true` for idempotent scripts.
* Lock accounts before deletion when appropriate.

---

### Automation Considerations

* Always check `ok` field.
* Use `exists` before `add` in idempotent workflows.
* Validate UID ranges.
* Use explicit backend selection in CI.

---

### CI/CD Integration

Example workflow:

1. `user://alice.exists`
2. `user://alice.add(...)` if missing
3. `user://alice.groups`
4. Validate membership
5. Continue deployment

---

### Production Environment Recommendations

* Audit group memberships regularly.
* Use service accounts for applications.
* Rotate passwords periodically.
* Remove access immediately when no longer needed.
* Log all user management operations.
* Avoid modifying system users unless necessary.

---

## 7. Use Cases by Role

### DevOps Engineers

* Automate developer account provisioning.
* Manage service accounts.
* Enforce least-privilege group memberships.
* Integrate user lifecycle into pipelines.

---

### SRE Engineers

* Lock compromised accounts.
* Audit UID/GID conflicts.
* Validate group assignments.
* Investigate authentication issues.

---

### Network Administrators

* Manage SSH-enabled users.
* Control administrative group membership.
* Enforce account policies.

---

### AI / Automation Engineers

* Parse structured group membership data.
* Detect policy violations.
* Trigger remediation workflows.
* Enforce UID/GID standards programmatically.

---

## 8. Technical Foundation

### Rust Implementation Advantages

resh is implemented in Rust, providing:

* Memory safety
* Deterministic command parsing
* Strong type validation
* Secure system interaction

---

### Type Safety

* Enumerated verbs
* Strict validation rules
* Explicit backend abstraction
* Structured error modeling

---

### Performance Characteristics

* Lightweight execution model
* Fast mock backend for testing
* Efficient group membership scanning
* Deterministic JSON serialization

---

### Cross-Platform Architecture

* Backend abstraction layer
* System and mock backend support
* Deterministic structured output
* Explicit unsupported-platform signaling
