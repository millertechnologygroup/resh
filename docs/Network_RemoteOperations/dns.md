# Resource Shell (resh) – DNS Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that provides structured, typed operations over infrastructure domains. Commands are expressed as URI-like resource invocations and return structured output, primarily in JSON format.

### Purpose

resh enables deterministic infrastructure operations by:

* Replacing string-based shell pipelines with structured resource invocations
* Returning machine-readable output
* Defining explicit operational verbs for infrastructure tasks
* Standardizing command semantics across domains

### Architectural Problem Addressed

Traditional shells rely on:

* Textual output
* Implicit formatting assumptions
* String parsing via pipelines (e.g., `grep`, `awk`, `sed`)
* Non-contractual command output

This approach introduces brittleness in automation systems. Changes in formatting, localization, or CLI versions can break dependent scripts.

resh addresses this by:

* Defining explicit resource handles
* Enforcing structured output contracts
* Returning predictable JSON responses
* Eliminating reliance on free-form text parsing

### Resource-Oriented URI Model

resh commands use a resource URI structure:

```
handle://target.verb(options)
```

Each command consists of:

* **handle** – Resource domain (e.g., `dns`)
* **target** – Logical or contextual resource target
* **verb** – Operation performed on the resource
* **options** – Explicit parameters passed to the operation

This model treats infrastructure operations as structured resource interactions rather than shell text execution.

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

* Each domain is implemented as a handle (e.g., `dns://`).
* Each handle exposes a defined set of verbs.
* Parameters are explicitly defined and validated.
* Output is schema-consistent.

This aligns CLI execution with API design principles.

---

### Safety-First Execution

* Parameters are validated before execution.
* Invalid inputs produce explicit error codes.
* Potentially destructive operations (e.g., zone updates) support safeguards such as `dry_run`.

This reduces unintended infrastructure changes.

---

### Deterministic Behavior

* Identical input parameters produce consistent structured output.
* No reliance on terminal formatting.
* No implicit side effects beyond the invoked verb.

Determinism enables safe CI/CD and automation use.

---

### JSON-Based Structured Output

Default output format:

```
format=json
```

Structured responses include:

* `ok` status flag
* Query metadata
* Operation results
* Error codes when applicable

This eliminates the need for parsing free-form text output.

---

### AI-Readiness

Because resh output is structured:

* AI agents can consume responses directly.
* Infrastructure state can be reasoned about programmatically.
* No natural-language interpretation is required.

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
handle://target.verb(options)
```

| Component | Description                             |
| --------- | --------------------------------------- |
| `handle`  | Resource domain (e.g., `dns`)           |
| `target`  | Resource context (optional or implicit) |
| `verb`    | Operation to execute                    |
| `options` | Key-value parameters                    |

---

### Production Examples (DNS Handle)

#### A Record Lookup

```bash
dns:// lookup name=example.com rtype=A
```

#### MX Record Lookup with Custom Server

```bash
dns:// lookup name=example.com rtype=MX servers=8.8.8.8
```

#### Host Resolution (IPv4 Only)

```bash
dns:// resolve name=example.com mode=host family=ipv4
```

#### DNS Trace from Root

```bash
dns://.trace name=example.com rtype=A
```

#### Zone Transfer (AXFR)

```bash
dns://.zone.fetch zone=example.com transfer=AXFR servers=["192.0.2.53"]
```

#### Dynamic Zone Update

```bash
dns://.zone.update zone=example.com adds='[{"name":"www.example.com","rtype":"A","ttl":300,"data":{"address":"203.0.113.10"}}]'
```

---

### 3.2 Execution Semantics

#### Deterministic Behavior

* Input parameters fully define execution.
* Output format is stable.
* Error conditions return defined codes.

---

#### Structured Output Contracts

Each DNS response includes:

* `ok` – Boolean success indicator
* `query` – Structured query parameters
* Operation-specific result fields
* Response metadata
* Structured error codes when applicable

---

#### Representative JSON Response

```json
{
  "ok": true,
  "query": {
    "name": "example.com",
    "rtype": "A",
    "servers": ["1.1.1.1"],
    "port": 53,
    "use_tcp": false,
    "timeout_ms": 2000,
    "retries": 1,
    "dnssec": false
  },
  "answers": [
    {
      "name": "example.com",
      "rtype": "A",
      "class": "IN",
      "ttl": 3600,
      "data": {
        "address": "93.184.216.34"
      }
    }
  ],
  "response": {
    "rcode": "NOERROR",
    "authoritative": false,
    "round_trip_time_ms": 10
  }
}
```

---

#### Error Handling Structure

Examples of defined error codes:

* `DNS_LOOKUP_INVALID_NAME`
* `DNS_LOOKUP_TIMEOUT`
* `DNS_RESOLVE_INVALID_MODE`
* `DNS_ZONE_FETCH_INVALID_TRANSFER_TYPE`
* `DNS_ZONE_UPDATE_INVALID_PREREQUISITE`

Error conditions return:

* `ok: false`
* Structured error identifier
* Contextual metadata

---

## 4. Functional Domains

The provided documentation covers the **DNS functional domain**.

---

### 4.1 Automation Utilities

**Operational Scope**

Infrastructure automation primitives exposed as structured commands.

**Use Cases**

* Integrating DNS validation in deployment pipelines
* Programmatic resolution checks in CI/CD
* Automated infrastructure verification workflows

---

### 4.2 Data & State Management

**Operational Scope**

Structured retrieval and manipulation of DNS records and zone state.

**Use Cases**

* Querying authoritative data
* Extracting structured record metadata
* Programmatic DNS validation

---

### 4.3 Filesystem & Storage

Not defined in the provided documentation.

---

### 4.4 Network & Remote Operations

**Operational Scope**

DNS-based network operations including:

* Record lookup
* Resolution logic
* Resolution tracing
* Zone transfers
* Dynamic updates

**Supported Handle**

* `dns://`

**Supported Verbs**

* `lookup`
* `resolve`
* `trace`
* `zone.fetch`
* `zone.update`

---

### Common DevOps/SRE Use Cases

| Scenario                  | resh Command                                       |
| ------------------------- | -------------------------------------------------- |
| Verify A record           | `dns:// lookup name=example.com rtype=A`           |
| Validate MX setup         | `dns:// resolve name=example.com mode=mail`        |
| Debug resolution chain    | `dns://.trace name=example.com`                    |
| Audit zone contents       | `dns://.zone.fetch zone=example.com transfer=AXFR` |
| Update record dynamically | `dns://.zone.update zone=example.com adds='[...]'` |

---

### Integration Scenarios

* Pre-deployment DNS validation
* DNSSEC validation checks
* Infrastructure inventory extraction
* Authoritative zone synchronization workflows
* Automated failover record updates

---

### 4.5 Packages & Software

Not defined in the provided documentation.

---

### 4.6 Process & Service Management

Not defined in the provided documentation.

---

### 4.7 Security & Secrets

**Operational Scope**

DNS security-related operations including:

* DNSSEC validation
* TSIG authentication for:

  * Zone transfers
  * Zone updates

TSIG parameters:

* `tsig_key_name`
* `tsig_secret`
* `tsig_algorithm`

All must be supplied together for authenticated operations.

---

### 4.8 System Information

DNS resolution metadata includes:

* TTL values
* Authoritative flags
* Recursion flags
* Round-trip time
* Response codes

---

## 5. Platform Support

The provided documentation does not define platform-specific limitations.

DNS operations require:

* Network connectivity
* Access to specified DNS servers

Behavior depends on network environment configuration.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Use `dry_run=true` for zone updates before applying changes.
* Validate input parameters.
* Use TCP for large responses (e.g., AXFR).
* Apply TSIG authentication where required.

---

### Automation Considerations

* Always check `ok` field in JSON output.
* Handle defined error codes explicitly.
* Set appropriate `timeout_ms` and `retries` values.
* Avoid relying on text output format.

---

### CI/CD Integration

Recommended workflow:

1. Validate DNS configuration before deployment.
2. Confirm resolution via `resolve`.
3. Trace resolution path if failure occurs.
4. Apply updates with `zone.update` (optional dry run first).
5. Validate post-update resolution.

---

### Production Recommendations

* Use DNSSEC validation where required.
* Authenticate zone transfers and updates using TSIG.
* Respect DNS server rate limits.
* Configure appropriate timeouts for production environments.

---

## 7. Use Cases by Role

### DevOps Engineers

* Validate DNS prior to release cutover.
* Confirm MX configuration for mail deployments.
* Integrate DNS resolution checks into pipelines.

---

### SRE Engineers

* Trace DNS failures during incidents.
* Validate authoritative zone configuration.
* Monitor DNS resolution latency.

---

### Network Administrators

* Perform AXFR/IXFR zone transfers.
* Manage dynamic DNS updates.
* Validate record consistency using prerequisites.

---

### AI / Automation Engineers

* Consume structured JSON DNS results.
* Automate remediation workflows.
* Implement validation logic based on structured error codes.
* Build deterministic infrastructure agents.

---

## 8. Technical Foundation

### Rust Implementation Advantages

resh is implemented in Rust, providing:

* Memory safety guarantees
* Strong compile-time type checking
* Predictable execution behavior

---

### Type Safety

* Parameter validation
* Explicit enum types (record types, resolution modes)
* Structured error identifiers

---

### Performance Characteristics

* Native binary execution
* Efficient network query handling
* Configurable timeout and retry behavior

---

### Cross-Platform Architecture

* CLI-based execution model
* Network-dependent operation
* Consistent JSON output across environments

