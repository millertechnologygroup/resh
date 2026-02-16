# Resource Shell (resh) – Service Management Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using structured URI-based commands. The `svc://` handle provides structured control and monitoring of system services across supported service managers.

### Purpose

The service management domain enables:

* Starting, stopping, restarting, and reloading services
* Configuring boot-time behavior (enable/disable/mask)
* Inspecting service state and metadata
* Viewing recent service logs
* Waiting for state transitions
* Scaling template service instances (systemd)

All operations return structured JSON output for automation and orchestration use.

### Architectural Problem Addressed

Traditional service management tools:

* Differ across service managers (systemd, OpenRC, init scripts)
* Produce unstructured, human-oriented output
* Require shell parsing for automation
* Provide inconsistent error handling and state modeling

resh addresses these limitations by:

* Exposing service lifecycle operations as typed verbs
* Abstracting supported service managers behind a unified URI model
* Returning structured JSON with explicit state fields
* Defining consistent exit codes and error categories

### Resource-Oriented URI Model

Service operations follow:

```
handle://target.verb(options)
```

For service management:

* **handle**: `svc://`
* **target**: Service name (e.g., `nginx`, `sshd`, `myapp@`)
* **verb**: Operation to perform
* **options**: Structured parameters (where applicable)

Examples:

```
svc://nginx.status
svc://myapp.restart
svc://worker@.scale(instances=3)
svc://postgresql.wait(state=active,timeout=30)
```

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

* Thirteen explicitly defined verbs grouped by lifecycle, monitoring, and configuration.
* Clear separation between inspection (`status`, `is-enabled`) and mutation (`start`, `mask`, `scale`).
* Service name is always explicit.
* Backend (systemd, OpenRC, generic init) detected automatically.

---

### Safety-First Execution

* State-changing verbs require explicit invocation.
* `wait` requires explicit state argument.
* `stop` supports controlled shutdown via `timeout`.
* `mask` provides strong service-blocking semantics.
* Permission enforcement aligned with operating system policies.

---

### Deterministic Behavior

* Verbs map directly to underlying service manager operations.
* Structured states are returned consistently (`active`, `inactive`, `failed`, etc.).
* Exit codes are standardized across supported backends.
* Unsupported operations return explicit structured errors.

---

### JSON-Based Structured Output

All verbs return JSON output describing:

* Backend used
* Service name
* Action performed
* Result status
* State or metadata fields (where applicable)

Example: `status`

```json
{
  "backend": "systemd",
  "service": "nginx",
  "loaded": true,
  "active_state": "active",
  "sub_state": "running",
  "pid": 1234
}
```

---

### AI-Readiness

Structured output enables:

* Automated deployment verification
* Service health validation
* State-driven orchestration workflows
* Log ingestion and correlation
* Programmatic boot configuration auditing

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
svc://service-name.VERB(arguments)
```

| Component      | Description                    |
| -------------- | ------------------------------ |
| `handle`       | `svc://`                       |
| `service-name` | System service identifier      |
| `VERB`         | Service operation              |
| `arguments`    | Optional structured parameters |

---

### Core Verbs (13)

| Category           | Verbs                                 |
| ------------------ | ------------------------------------- |
| Status & Info      | `status`, `is-enabled`                |
| Lifecycle          | `start`, `stop`, `restart`, `reload`  |
| Boot Configuration | `enable`, `disable`, `mask`, `unmask` |
| Monitoring         | `wait`, `logs`                        |
| Advanced           | `scale`                               |

---

### Production Examples

#### Check Service Status

```
svc://nginx.status
svc://sshd.status
svc://getty@tty1.status
```

#### Start and Verify

```
svc://myapp.start
svc://myapp.wait(state=active,timeout=30)
```

#### Stop with Timeout

```
svc://nginx.stop(timeout=30)
```

#### Force Stop

```
svc://service.stop(force=true,timeout=60)
```

#### Reload Configuration

```
svc://nginx.reload
```

#### Enable at Boot

```
svc://postgresql.enable
```

#### Disable and Stop

```
svc://test-service.disable
svc://test-service.stop
```

#### Mask Service

```
svc://vulnerable-daemon.mask
```

#### View Logs

```
svc://nginx.logs(lines=100)
svc://myapp.logs(follow=true)
```

#### Scale Template Service (systemd)

```
svc://worker@.scale(instances=5)
```

---

## 3.2 Execution Semantics

### Deterministic Behavior

* Verbs map directly to backend operations.
* `wait` blocks until specified state or timeout.
* `logs` returns recent entries (or follows).
* `scale` applies only to systemd template services.

---

### Structured Output Contracts

Example: `start`

```json
{
  "backend": "systemd",
  "service": "nginx",
  "action": "start",
  "success": true
}
```

Example: `wait`

```json
{
  "backend": "systemd",
  "service": "nginx",
  "action": "wait",
  "success": true,
  "state": "active",
  "elapsed_ms": 842
}
```

---

### Error Handling Structure

Representative errors include:

* `service not found`
* `permission denied`
* `operation not supported`
* `timeout waiting for state`
* `service is masked`

Standardized exit codes:

| Code | Meaning                       |
| ---- | ----------------------------- |
| 0    | Success                       |
| 1    | General error                 |
| 2    | Service not found             |
| 3    | Permission denied             |
| 4    | Service manager not available |
| 5    | Invalid arguments             |
| 6    | Timeout                       |
| 7    | Operation not supported       |

---

## 4. Functional Domains

---

### 4.1 Automation Utilities

**Scope**

Service lifecycle automation during deployment and maintenance.

**Handle**

* `svc://`

**Use Cases**

* Deployment startup sequencing
* Automated restarts after configuration change
* Scheduled service health validation

---

### 4.2 Data & State Management

**Scope**

Service state inspection and metadata retrieval.

**Use Cases**

* Boot configuration auditing
* Service state validation in CI pipelines
* Instance count verification

---

### 4.3 Filesystem & Storage

Indirect support through:

* Log retrieval
* Service file inspection (external tools)
* Configuration validation prior to reload

---

### 4.4 Network & Remote Operations

Supports management of:

* Web servers
* Databases
* SSH daemons
* Network resolvers
* Custom application services

---

### 4.5 Packages & Software

Supports:

* Restart after package updates
* Enable service post-install
* Disable deprecated services
* Mask vulnerable daemons

---

### 4.6 Process & Service Management

Primary domain:

* Full service lifecycle control
* Boot-time configuration
* State monitoring
* Template service scaling

Integrates with:

* `proc://` for process-level control
* `cron://` for scheduled orchestration

---

### 4.7 Security & Secrets

Security considerations include:

* Root privileges required for many operations
* Masking unused services
* Disabling unnecessary boot services
* Reviewing enabled services periodically
* Monitoring logs for anomalous behavior

---

### 4.8 System Information

Structured reporting includes:

* Active state
* Sub-state
* PID
* Timestamps
* Memory and CPU metrics (systemd)
* Boot enablement state

---

## 5. Platform Support

| Platform             | Support Level   |
| -------------------- | --------------- |
| Linux (systemd)      | Full support    |
| Linux (OpenRC)       | Partial support |
| Linux (generic init) | Basic support   |
| BSD                  | Limited         |
| macOS                | Not supported   |
| Windows              | Not supported   |

Feature differences:

| Feature        | systemd | OpenRC  | Generic |
| -------------- | ------- | ------- | ------- |
| Start/Stop     | ✓       | ✓       | ✓       |
| Enable/Disable | ✓       | ✓       | ✗       |
| Logs           | ✓       | ✓       | ✗       |
| Wait           | ✓       | Limited | ✗       |
| Scale          | ✓       | ✗       | ✗       |
| Mask           | ✓       | ✗       | ✗       |

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Use `status` before lifecycle operations.
* Prefer `reload` over `restart` when supported.
* Use `wait` in automation scripts.
* Avoid `force=true` unless necessary.
* Verify boot configuration after `enable` or `disable`.

---

### Automation Considerations

* Always validate `success` or state fields.
* Combine `restart` with `wait`.
* Monitor logs during deployment.
* Use structured JSON output instead of parsing systemctl output.

---

### CI/CD Integration

Typical workflow:

1. Deploy application.
2. `svc://app.restart`
3. `svc://app.wait(state=active,timeout=60)`
4. Validate with `svc://app.status`
5. Monitor logs if failure detected.

---

### Production Recommendations

* Enable critical services explicitly.
* Disable unused services.
* Use mask for security isolation.
* Document service dependencies.
* Monitor logs during upgrades.
* Test restart cycles in staging environments.

---

## 7. Use Cases by Role

### DevOps Engineers

* Automate service lifecycle during deployments.
* Manage template service scaling.
* Validate state transitions in pipelines.

---

### SRE Engineers

* Investigate service failures.
* Restart failed services during incidents.
* Monitor logs and state transitions.
* Enforce boot-time service policy.

---

### Network Administrators

* Manage SSH, DNS, web, and proxy services.
* Enable/disable network daemons.
* Troubleshoot service-level network issues.

---

### AI / Automation Engineers

* Use structured state metadata for orchestration.
* Implement remediation workflows.
* Detect drift in boot configuration.
* Automate scale adjustments.

---

## 8. Technical Foundation

### Rust Implementation Advantages

resh is implemented in Rust, providing:

* Memory safety
* Strong type guarantees
* Efficient system call integration
* Predictable concurrency behavior

---

### Type Safety

* Enumerated verbs
* Strict argument validation
* Structured error modeling
* Explicit state modeling

---

### Performance Characteristics

* Native binary execution
* Minimal overhead service invocation
* Efficient log retrieval
* Controlled timeout handling

---

### Cross-Platform Architecture

* Backend abstraction layer
* Automatic service manager detection
* Consistent JSON output across supported systems
* Explicit unsupported-operation signaling
