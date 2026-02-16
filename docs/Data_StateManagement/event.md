# Resource Shell (resh) – Event Handle Documentation

## 1. Overview

Resource Shell (resh) is a structured command-line framework that standardizes infrastructure operations using a resource-oriented URI execution model.

The `event://` handle provides a messaging system for publishing, subscribing, and managing events within resh. It supports:

* Event emission with structured metadata
* Topic-based subscriptions with wildcard support
* Consumer group coordination
* Hook-based integrations
* Structured JSON output for automation workflows

Traditional event-driven tooling often requires:

* External messaging systems
* Custom client libraries
* Manual offset management
* Unstructured CLI outputs
* Inconsistent filtering behavior

The `event://` handle addresses these issues by:

* Providing a uniform URI-based command interface
* Enforcing structured JSON envelopes
* Supporting topic validation and metadata tracking
* Enabling deterministic automation workflows

All event operations follow the URI pattern:

```
event://verb(arguments)
event://target.verb(arguments)
```

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

All event operations use a consistent URI grammar:

```
event://emit
event://subscribe
event://list-topics
event://hooks.enable
```

This standardizes event publication, consumption, and management.

### Safety-First Execution

The handle enforces:

* Topic validation rules
* Structured error reporting
* Input validation for tags and metadata
* Controlled offset behavior
* Explicit consumer group requirements for resumable processing

### Deterministic Behavior

Each operation:

* Returns a structured JSON response
* Includes explicit `ok` status indicators
* Separates `event`, `error`, and `warnings` fields
* Includes timestamp metadata

### JSON-Based Structured Output

All responses are machine-readable and consistent, enabling:

* CI/CD integration
* Automated monitoring
* Structured event processing
* Deterministic filtering

### AI-Readiness

The uniform grammar and structured metadata model allow automated orchestration agents to publish and consume events without parsing unstructured text.

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
event://verb(arguments)
```

Or for hook management:

```
event://hooks.verb(arguments)
```

#### Components

| Component   | Description                                          |
| ----------- | ---------------------------------------------------- |
| `event`     | Handle identifier                                    |
| `verb`      | Operation (`emit`, `subscribe`, `list-topics`, etc.) |
| `arguments` | Named parameters                                     |

---

### Example Commands

Emit event:

```bash
event://emit topic="system.fs.resized" data='{"mount":"/data"}'
```

Subscribe to topic:

```bash
event://subscribe topic="jobs.backup.completed" offset="latest"
```

List topics:

```bash
event://list-topics
```

Enable hook:

```bash
event://hooks.enable name="mq"
```

---

### 3.2 Execution Semantics

All operations return structured JSON envelopes.

#### Representative Emit Success Response

```json
{
  "ok": true,
  "timestamp_unix_ms": 1732538400000,
  "event": {
    "id": "evt_1732538400000_abcd1234",
    "topic": "system.fs.resized",
    "timestamp_unix_ms": 1732538400000,
    "mode": "fire_and_forget",
    "priority": "normal",
    "data": {
      "mount": "/data"
    },
    "backend": "in_memory_bus"
  },
  "error": null,
  "warnings": []
}
```

#### Representative Error Response

```json
{
  "ok": false,
  "timestamp_unix_ms": 1732538400000,
  "event": null,
  "error": {
    "code": "event.emit_invalid_topic",
    "message": "topic cannot be empty"
  },
  "warnings": []
}
```

Automation systems must evaluate `ok` and `error.code` for control flow.

---

## 4. Functional Domain – Event Handle

---

### 4.1 Core Operations

#### emit

Publishes an event to a topic.

Required:

* `topic`
* `data` (JSON)

Optional:

* `mode`
* `priority`
* `ttl_ms`
* `key`
* `correlation_id`
* `causation_id`
* `source`
* `tags`
* `schema_version`
* `format`

---

#### subscribe

Consumes events from a topic or wildcard pattern.

Required:

* `topic`

Optional:

* `offset` (`latest`, `earliest`, `next`)
* `limit`
* `group_id`
* `consumer_id`
* `auto_commit`
* `wait`
* `match_tags`
* `match_correlation_id`
* `match_source`
* `include_data`
* `format`

Supports wildcard patterns such as:

```
jobs.backup.*
```

---

#### list-topics

Lists topics with optional metadata.

Optional:

* `prefix`
* `match`
* `sources`
* `include_stats`
* `include_schema`
* `limit`

---

### 4.2 Hook Management

#### hooks.list

Lists available hooks.

#### hooks.enable

Enables a hook (`mq`, `log`, `proc`, `fs`).

#### hooks.disable

Disables a hook.

---

### 4.3 Topic Validation Rules

* Maximum length: 256 characters
* Allowed characters: alphanumeric, `.`, `_`, `:`, `-`, `*`, `?`
* Cannot be empty

Tag rules:

* Maximum length: 64 characters
* Must be ASCII
* JSON array format required

---

### 4.4 Event Metadata Fields

Each event may include:

* `id`
* `timestamp_unix_ms`
* `topic`
* `data`
* `priority`
* `ttl_ms`
* `key`
* `correlation_id`
* `causation_id`
* `source`
* `tags`
* `schema_version`

---

### 4.5 Consumer Groups

Consumer groups enable load-balanced consumption:

```
event://subscribe topic="jobs.process" group_id="workers" consumer_id="w1" offset="next"
```

`offset="next"` requires `group_id`.

---

### 4.6 Backend Characteristics

Current backend: `in_memory_bus`

Characteristics:

* In-memory storage
* No persistence across restarts
* Immediate delivery
* Single-process scope

`wait_for_persist` mode is downgraded with a warning due to lack of durable storage.

---

## 5. Platform Support

| Platform   | Support Level |
| ---------- | ------------- |
| Linux      | Supported     |
| macOS/Unix | Supported     |
| Windows    | Supported     |

Event behavior depends on runtime environment and backend configuration.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Use structured topics with clear naming patterns.
* Validate topic names before emission.
* Use correlation IDs for workflow tracing.
* Use consumer groups for scalable processing.

### Automation Considerations

* Evaluate `ok` and `error` fields.
* Use `limit` to control subscription volume.
* Use `match_*` filters to reduce unnecessary processing.
* Avoid `offset="earliest"` in high-volume production systems unless required.

### CI/CD Integration

* Emit deployment lifecycle events.
* Subscribe for verification events.
* Use structured metadata for traceability.
* Validate schema with `include_schema`.

### Production Recommendations

* Monitor event counts via `include_stats`.
* Use tags for filtering and classification.
* Separate internal topics using `_internal.*`.
* Avoid reliance on persistence with in-memory backend.

---

## 7. Use Cases by Role

### DevOps Engineers

* Emit deployment lifecycle events.
* Implement event-driven pipelines.
* Monitor build and backup completion events.

### SRE Engineers

* Subscribe to system-level topics.
* Monitor job completion and failure events.
* Use correlation IDs for incident tracing.

### Network Administrators

* Emit network configuration events.
* Subscribe to system.fs and network-related topics.
* Track configuration changes.

### AI/Automation Engineers

* Consume structured events for orchestration.
* Use correlation tracking for workflow automation.
* Implement event-driven decision logic.

---

## 8. Technical Foundation

The `event://` handle operates within resh, implemented in Rust.

### Rust Implementation Advantages

* Memory safety
* Structured type validation
* Deterministic error propagation
* High-performance event dispatch

### Type Safety

Arguments and metadata are type-validated, reducing malformed event risks.

### Performance Characteristics

* Low-latency event dispatch
* Efficient metadata processing
* Structured JSON serialization

### Cross-Platform Architecture

Supported across:

* Linux
* macOS/Unix
* Windows

Behavior is dependent on backend implementation.


