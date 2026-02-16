# Resource Shell (resh) – Net Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using structured URI-based commands. The `net://` handle provides network utilities including interface inspection, connectivity testing, DNS lookup, TCP checks, port scanning, and routing table inspection.

### Purpose

The net handle enables:

* Structured network diagnostics
* Deterministic connectivity testing
* Programmatic port scanning
* DNS queries
* Routing table inspection (Linux)

It provides consistent JSON output for automation, monitoring, and troubleshooting workflows.

### Architectural Problem Addressed

Traditional network tools:

* Produce text-based output
* Require parsing for automation
* Differ in formatting across platforms
* Mix diagnostic and informational output

This introduces fragility in automated scripts and monitoring systems.

resh addresses this by:

* Exposing network operations as typed verbs
* Returning structured JSON responses
* Defining explicit argument validation
* Standardizing error handling and exit codes

### Resource-Oriented URI Model

Commands follow:

```
handle://target.verb(options)
```

For network operations:

* **handle**: `net://`
* **target**: Host, interface, or logical host identifier
* **verb**: `list`, `ping`, `tcp_check`, `scan`, `dns`, `route.list`
* **options**: Explicit key-value parameters

Example:

```
net://127.0.0.1.ping(count=1,timeout_ms=1000)
```

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

* Each network capability is a defined verb.
* Arguments are validated before execution.
* JSON output is standardized.
* Help documentation is available offline.

---

### Safety-First Execution

* Timeout values are enforced.
* Port scan concurrency is limited (1–256).
* Argument validation prevents invalid execution.
* Help operations have no side effects.
* Exit codes are defined per failure category.

---

### Deterministic Behavior

* Identical parameters yield consistent structured output.
* Explicit fallback behavior for `ping`.
* Configurable retry logic for TCP checks.
* Controlled scan concurrency.

---

### JSON-Based Structured Output

All verbs return structured JSON including:

* Operation metadata
* Query or target
* Result objects
* Error details when applicable

This removes dependency on text parsing.

---

### AI-Readiness

Structured responses include:

* Reachability state
* Port state (`open`, `closed`, `timeout`)
* Routing metadata
* DNS record details

This enables programmatic reasoning over network state.

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
handle://target.verb(options)
```

| Component | Description                          |
| --------- | ------------------------------------ |
| `handle`  | `net://`                             |
| `target`  | Host, interface, or logical resource |
| `verb`    | Network operation                    |
| `options` | Structured arguments                 |

---

### Supported Verbs

| Verb         | Description                     |
| ------------ | ------------------------------- |
| `list`       | List network interfaces         |
| `ping`       | Test host reachability          |
| `tcp_check`  | Test TCP connectivity           |
| `scan`       | TCP port scan                   |
| `dns`        | DNS lookup                      |
| `route.list` | List routing table (Linux only) |

---

### Production Examples

#### List Interfaces

```
net://iface.list(family=ipv4)
```

#### ICMP/TCP Reachability

```
net://192.168.1.10.ping(count=3,timeout_ms=2000)
```

#### TCP Connectivity Check

```
net://db.internal:5432.tcp_check(timeout_ms=5000,retries=2)
```

#### Port Scan

```
net://web.internal.scan(ports=80,443,timeout_ms=500)
```

#### DNS Lookup

```
net://example.com.dns(type=MX)
```

#### Route Table (Linux)

```
net://host.route.list(family=ipv4)
```

---

## 3.2 Execution Semantics

### Deterministic Behavior

* `ping` attempts system ping, then TCP fallback if necessary.
* `tcp_check` performs explicit retries with backoff.
* `scan` enforces concurrency limits.
* DNS uses system resolver by default.

---

### Structured Output Contracts

Each verb returns:

* Target metadata
* Execution parameters
* Result object
* Error object (when applicable)

---

### Representative JSON Response (Ping)

```json
{
  "host": "127.0.0.1",
  "port": 80,
  "backend": "system_ping",
  "sent": 1,
  "received": 1,
  "loss": 0.0,
  "avg_rtt_ms": 0.1,
  "timeout_ms": 1000,
  "reachable": true
}
```

---

### Representative JSON Response (TCP Check Failure)

```json
{
  "host": "127.0.0.1",
  "port": 65534,
  "ok": false,
  "attempts": 1,
  "timeout_ms": 200,
  "retries": 1,
  "backend": "tcp",
  "error": "Connection refused (os error 111)",
  "tls_checked": false
}
```

---

### Error Handling

Defined exit codes include:

| Exit Code | Meaning                     |
| --------- | --------------------------- |
| 1         | General failure             |
| 2         | Invalid arguments           |
| 3         | Missing required parameters |
| 50        | System error                |
| 111       | Connection failure          |

Structured error example:

```json
{
  "error": "invalid_type",
  "detail": "Unknown record type: FOO",
  "query": "example.com",
  "rtype": "FOO"
}
```

---

## 4. Functional Domains

### 4.1 Automation Utilities

**Scope**

Programmatic network diagnostics for automation pipelines.

**Use Cases**

* Health validation
* Service reachability checks
* Infrastructure validation before deployment

---

### 4.2 Data & State Management

**Scope**

Structured reporting of:

* Interface metadata
* DNS records
* Routing tables
* Port states

---

### 4.3 Filesystem & Storage

Not defined in provided documentation.

---

### 4.4 Network & Remote Operations

**Scope**

Core networking operations including:

* ICMP/TCP reachability
* TCP port validation
* Port scanning
* DNS lookup
* Routing inspection

**Supported Handle**

* `net://`

**Integration Scenarios**

* CI/CD readiness checks
* Firewall validation
* Network diagnostics automation
* Incident response workflows

---

### 4.5 Packages & Software

Not defined in provided documentation.

---

### 4.6 Process & Service Management

Used indirectly for:

* Verifying service port availability
* Confirming network readiness before service startup

---

### 4.7 Security & Secrets

* TLS expectation validation in `tcp_check`
* Controlled port scanning
* Configurable timeouts and concurrency

---

### 4.8 System Information

Provides structured system-level network metadata:

* Interface list
* Routing table entries (Linux)
* DNS records
* Port state information

---

## 5. Platform Support

| Verb         | Platform Support |
| ------------ | ---------------- |
| `list`       | All platforms    |
| `ping`       | All platforms    |
| `tcp_check`  | All platforms    |
| `scan`       | All platforms    |
| `dns`        | All platforms    |
| `route.list` | Linux only       |

Route inspection is limited to Linux systems.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Limit port scanning scope.
* Use conservative concurrency values.
* Configure appropriate timeouts.
* Validate input parameters before automation execution.

---

### Automation Considerations

* Consume structured JSON instead of parsing text.
* Handle exit codes explicitly.
* Implement retry logic in automation based on `ok` or `reachable` fields.
* Validate DNS before service cutover.

---

### CI/CD Integration

Recommended usage pattern:

1. `tcp_check` to validate service port.
2. `ping` to verify host reachability.
3. `dns` to confirm name resolution.
4. `scan` to confirm open service ports.

---

### Production Environment Recommendations

* Avoid aggressive scanning in production networks.
* Monitor concurrency limits.
* Use TLS expectation validation where required.
* Ensure sufficient permissions for route inspection.

---

## 7. Use Cases by Role

### DevOps Engineers

* Validate service ports before deployment.
* Confirm DNS resolution.
* Automate health checks in pipelines.

---

### SRE Engineers

* Diagnose connectivity failures.
* Identify port-level issues.
* Inspect routing table during incident response.

---

### Network Administrators

* Audit open ports.
* Verify routing configuration.
* Inspect interface configuration.

---

### AI / Automation Engineers

* Consume structured reachability metrics.
* Automate remediation based on `reachable` and `ok` flags.
* Integrate DNS and port state into decision models.

---

## 8. Technical Foundation

### Rust Implementation Advantages

resh is implemented in Rust, providing:

* Memory safety
* Strong type enforcement
* Predictable execution behavior
* Efficient network operations

---

### Type Safety

* Enumerated argument validation (family, protocol, etc.)
* Structured error types
* Controlled parameter ranges

---

### Performance Characteristics

* Native binary execution
* Configurable concurrency
* Efficient socket operations
* Controlled timeout behavior

---

### Cross-Platform Architecture

* CLI-based model
* Platform-dependent routing support (Linux only for `route.list`)
* Consistent structured output across environments


