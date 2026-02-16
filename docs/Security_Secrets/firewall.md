# Resource Shell (resh) – Firewall Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using structured URI-based commands. The `firewall://` handle provides unified firewall management across multiple Linux firewall backends.

### Purpose

The firewall domain enables:

* Rule listing, filtering, and inspection
* Rule creation and deletion
* Firewall configuration persistence and reload
* Backend status inspection
* Firewall service enable/disable control

Supported backends:

* `iptables`
* `nftables`
* `ufw`
* `firewalld`
* `auto` (backend auto-detection)

All operations return structured JSON output suitable for automation and infrastructure workflows.

### Architectural Problem Addressed

Traditional firewall management:

* Requires backend-specific tools
* Produces human-oriented output
* Lacks structured API contracts
* Requires manual parsing for automation
* Varies significantly across distributions

resh addresses these issues by:

* Providing a unified `firewall://` handle
* Standardizing verbs across backends
* Normalizing rule representation
* Returning deterministic JSON output
* Defining consistent exit codes and structured error responses

### Resource-Oriented URI Model

Firewall operations follow:

```
handle://target.verb(options)
```

For firewall management:

* **handle**: `firewall://`
* **target**: `.` (firewall context)
* **verb**: Operation
* **options**: Structured parameters

Examples:

```
firewall://.status
firewall://.rules.list
firewall://.rules.add(backend=iptables,direction=input,action=accept,proto=tcp,dport=22)
```

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

* Eight explicitly defined verbs:

  * `rules.list`
  * `rules.add`
  * `rules.delete`
  * `rules.save`
  * `rules.reload`
  * `status`
  * `enable`
  * `disable`
* Backend abstraction layer
* Explicit parameter validation
* Normalized rule structure across backends
* Built-in help (`resh firewall:// --help`)

---

### Safety-First Execution

* `dry_run` supported for rule changes
* `require_match` controls deletion behavior
* `backup_before_apply` supported for disable/reload
* Validation prior to reload (`validate_before_apply`)
* Timeouts prevent indefinite execution

---

### Deterministic Behavior

* Explicit backend selection or `auto`
* Structured rule matching
* Predictable JSON output
* Standardized exit codes
* Strict parameter validation

---

### JSON-Based Structured Output

All verbs return JSON by default:

```json
{
  "ok": true,
  "result": {
    "operation": "rules.add",
    "backend": "iptables",
    "rule": {
      "direction": "input",
      "action": "accept",
      "proto": "tcp",
      "dport": "22"
    }
  }
}
```

---

### AI-Readiness

Structured output enables:

* Automated compliance validation
* Rule drift detection
* Policy enforcement automation
* Change management workflows
* Backend migration orchestration

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
firewall://.VERB(options)
```

| Component | Description            |
| --------- | ---------------------- |
| `handle`  | `firewall://`          |
| `target`  | `.` (firewall context) |
| `VERB`    | Firewall operation     |
| `options` | Structured parameters  |

---

### Core Examples

#### Check Status

```
firewall://.status
```

#### List Rules

```
firewall://.rules.list
firewall://.rules.list(backend=iptables,family=ipv4)
```

#### Add Rule

```
firewall://.rules.add(
  backend=iptables,
  direction=input,
  action=accept,
  proto=tcp,
  dport=22
)
```

#### Delete Rule

```
firewall://.rules.delete(
  backend=iptables,
  direction=input,
  proto=tcp,
  dport=22
)
```

#### Save Configuration

```
firewall://.rules.save(backend=iptables,path=/tmp/firewall.json)
```

#### Reload Configuration

```
firewall://.rules.reload(
  backend=iptables,
  source_format=backend_native,
  path=/tmp/iptables.rules
)
```

#### Enable Firewall

```
firewall://.enable(backend=ufw)
```

#### Disable Firewall

```
firewall://.disable(backend=iptables,backup_before_apply=true)
```

---

## 3.2 Execution Semantics

### Deterministic Behavior

* Explicit backend validation.
* Structured rule filtering.
* Consistent normalized representation.
* Timeout enforcement.
* Predictable dry-run behavior.

---

### Structured Output Contracts

Example: `status`

```json
{
  "ok": true,
  "backends": [
    {
      "backend": "iptables",
      "available": true,
      "active": true,
      "enabled": true
    }
  ]
}
```

Example: `rules.list`

```json
{
  "ok": true,
  "backends": [
    {
      "backend": "iptables",
      "family": "ipv4",
      "rules": [
        {
          "chain": "INPUT",
          "action": "ACCEPT",
          "proto": "tcp",
          "dport": "22"
        }
      ]
    }
  ]
}
```

---

### Error Handling Structure

Example:

```json
{
  "ok": false,
  "error": {
    "code": "firewall.rules_add_invalid_backend",
    "message": "Invalid backend specified"
  }
}
```

---

### Exit Codes

| Code | Meaning             |
| ---- | ------------------- |
| 0    | Success             |
| 1    | Invalid arguments   |
| 2    | Backend unavailable |
| 3    | Permission denied   |
| 4    | Operation failed    |
| 5    | No matches          |
| 6    | Timeout             |
| 7    | Internal error      |

---

## 4. Functional Domains

---

### 4.1 Automation Utilities

**Handle**

* `firewall://`

**Scope**

* Infrastructure-as-code firewall management
* Rule drift detection
* Policy enforcement
* Backend migration automation

**Use Cases**

* Automated server provisioning
* CI/CD rule validation
* Security compliance checks

---

### 4.2 Data & State Management

**Scope**

* Normalized rule export (`rules.save`)
* Rule reload from JSON or native formats
* Backend status inspection

Example:

```
firewall://.rules.save(format=normalized_json)
```

---

### 4.3 Filesystem & Storage

**Scope**

* Firewall configuration persistence
* Backup creation prior to destructive operations
* Rule snapshot storage

---

### 4.4 Network & Remote Operations

**Scope**

* TCP/UDP rule enforcement
* IPv4 and IPv6 family support
* Interface-based filtering
* CIDR-based address restrictions

---

### 4.5 Packages & Software

Supports:

* Enabling firewall services after installation
* Integration with system service managers
* Backend-specific service activation

---

### 4.6 Process & Service Management

Integrates with:

* `svc://` for firewall daemon control
* `cron://` for scheduled rule auditing
* `log://` for change tracking

---

### 4.7 Security & Secrets

Primary capabilities:

* Allow-list and deny-list rule modeling
* Default deny posture enforcement
* Backend-agnostic rule normalization
* Structured rule validation
* Root-privilege enforcement

---

### 4.8 System Information

Structured reporting includes:

* Backend availability
* Active/enabled state
* Rule counts
* Metrics (optional)
* Raw backend output (optional)

---

## 5. Platform Support

### Supported Platforms

| Platform | Support       |
| -------- | ------------- |
| Linux    | Full support  |
| BSD      | Not supported |
| macOS    | Not supported |
| Windows  | Not supported |

Backend availability depends on distribution:

| Backend   | Typical Usage                 |
| --------- | ----------------------------- |
| iptables  | Universal Linux compatibility |
| nftables  | Modern Linux distributions    |
| ufw       | Ubuntu/Debian                 |
| firewalld | RHEL/CentOS/Fedora            |

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Always allow SSH before applying restrictive rules.
* Use `dry_run=true` before applying changes.
* Save configuration after rule changes.
* Use `backup_before_apply` for destructive operations.
* Validate rule filters before deletion.

---

### Automation Considerations

* Always check `ok` field.
* Use normalized JSON for portability.
* Validate reload files before applying.
* Limit `max_rules` in large environments.
* Use timeouts in automation scripts.

---

### CI/CD Integration

Example workflow:

1. `firewall://.status`
2. `firewall://.rules.add(...,dry_run=true)`
3. Apply rule without dry run.
4. `firewall://.rules.save`
5. Validate using `rules.list`.

---

### Production Recommendations

* Enforce least privilege.
* Prefer allow-list model.
* Keep rule sets minimal.
* Document rules with comments.
* Regularly audit rule sets.
* Monitor firewall logs externally.

---

## 7. Use Cases by Role

### DevOps Engineers

* Automate firewall configuration during provisioning.
* Manage rule consistency across environments.
* Validate rules in CI pipelines.

---

### SRE Engineers

* Investigate network connectivity issues.
* Audit rule drift.
* Restore firewall configurations.
* Perform safe backend migrations.

---

### Network Administrators

* Manage inbound/outbound policies.
* Enforce subnet restrictions.
* Segment services.
* Monitor rule usage counters.

---

### AI / Automation Engineers

* Interpret normalized rule JSON.
* Detect policy violations.
* Automate remediation.
* Evaluate rule complexity and ordering.

---

## 8. Technical Foundation

### Rust Implementation Advantages

resh is implemented in Rust, providing:

* Memory safety
* Strong type guarantees
* Efficient backend command execution
* Deterministic argument parsing

---

### Type Safety

* Enumerated verbs
* Explicit backend values
* Strict parameter validation
* Structured error codes

---

### Performance Characteristics

* Backend auto-detection cached
* Efficient rule normalization
* Controlled timeouts
* Minimal overhead JSON serialization

---

### Cross-Platform Architecture

* Backend abstraction layer
* Unified rule model
* Deterministic JSON output
* Explicit unsupported-platform signaling
