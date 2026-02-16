# Resource Shell (resh) – Config Handle Documentation

## 1. Overview

Resource Shell (resh) is a structured command-line framework that standardizes system and application operations using a resource-oriented URI execution model.

The `config://` handle provides persistent configuration management using hierarchical namespaces and JSON-based storage. Configuration data is stored as JSON files under:

```
~/.config/resh/config/
```

Traditional configuration management in shell environments often involves:

* Environment variables without hierarchy
* Flat configuration files
* Ad hoc parsing logic
* Non-atomic writes
* Manual change tracking

The `config://` handle addresses these limitations by:

* Enforcing a hierarchical namespace/key structure
* Supporting JSON-typed values
* Providing atomic write operations
* Enabling real-time change monitoring
* Returning structured output for automation workflows

All configuration operations follow the resh URI format:

```
config://namespace/key.verb(options)
```

If no namespace is specified, the `default` namespace is used.

---

## 2. Design Philosophy and Core Principles

The `config://` handle adheres to resh architectural principles.

### Structured Interface Model

All configuration operations use:

```
config://namespace/path/to/key.verb(options)
```

This provides consistent hierarchical organization and predictable command structure.

### Safety-First Execution

The handle supports:

* Atomic file writes
* Structured exit codes
* JSON validation controls
* Input sanitization
* Namespace isolation

These prevent partial writes and inconsistent configuration state.

### Deterministic Behavior

Each command:

* Returns predictable JSON structures (where applicable)
* Uses defined exit codes
* Separates value retrieval from metadata operations
* Ensures consistent storage location resolution

### JSON-Based Structured Output

Values are stored and retrieved as JSON, supporting:

* Strings
* Numbers
* Booleans
* Objects
* Arrays
* Null

Structured storage enables automation systems to consume configuration deterministically.

### AI-Readiness

The predictable URI grammar and JSON-based storage allow automated configuration orchestration without ad hoc parsing.

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
config://namespace/key.verb(options)
config://key.verb(options)              # Uses default namespace
config://namespace/path/to/key.verb(options)
```

#### Components

| Component   | Description                 |
| ----------- | --------------------------- |
| `config`    | Handle identifier           |
| `namespace` | Top-level grouping          |
| `key`       | Configuration item          |
| `verb`      | `get`, `set`, `ls`, `watch` |
| `options`   | Named parameters            |

---

### Examples

Set configuration value:

```sh
config://app/theme.set(value="dark")
```

Set JSON object explicitly:

```sh
config://app/settings.set(value={"timeout":30,"retries":3},raw=true)
```

Retrieve value:

```sh
config://app/theme.get
```

List namespace contents:

```sh
config://app.ls(recursive=true)
```

Watch for changes:

```sh
config://app.watch(prefix="db",initial=true)
```

---

### 3.2 Execution Semantics

Operations return structured JSON or typed values depending on verb.

#### Example: Get JSON Value

```json
{
  "theme": "dark",
  "font_size": 14
}
```

#### Example: List Output

```json
{
  "prefix": "app",
  "recursive": false,
  "entries": [
    {
      "key": "theme",
      "full_key": "app/theme",
      "kind": "leaf",
      "has_value": true
    }
  ]
}
```

#### Example: Watch Event

```json
{
  "op": "set",
  "scope": "app",
  "key": "theme",
  "value": "light",
  "version": 2,
  "ts": "2024-01-01T00:00:01Z",
  "source": "config"
}
```

Automation systems must evaluate exit codes for control flow:

| Code | Meaning                           |
| ---- | --------------------------------- |
| 0    | Success                           |
| 1    | Missing key or required argument  |
| 2    | Invalid JSON or invalid parameter |
| 3    | Filesystem I/O error              |

---

## 4. Functional Domain – Configuration Handle

---

### 4.1 Hierarchical Storage

Configuration items consist of:

* **Namespace**
* **Key**
* **Value (JSON)**

Example filesystem structure:

```
~/.config/resh/config/
  app/
    db/
      url.json
      timeout.json
```

Namespaces support nested paths:

```
config://app/db/url.get
```

---

### 4.2 get – Retrieve Configuration

Retrieves the stored JSON value.

Example:

```sh
config://app/db/timeout.get
```

Returns the raw JSON value stored in the key.

---

### 4.3 set – Store Configuration

Stores JSON-typed values.

Arguments:

* `value` (required)
* `raw` (optional)

Behavior:

* Without `raw=true`, valid JSON is auto-parsed; otherwise stored as string.
* With `raw=true`, value must be valid JSON.

Examples:

```sh
config://app/timeout.set(value=30,raw=true)
config://app/theme.set(value="dark")
```

Atomic write guarantees prevent partial file corruption.

---

### 4.4 ls – List Configuration

Lists namespaces and keys.

Arguments:

* `recursive`
* `pattern`
* `limit`
* `offset`

Example:

```sh
config://app.ls(recursive=true)
```

Entry types:

| Kind     | Description               |
| -------- | ------------------------- |
| `leaf`   | JSON file (value)         |
| `branch` | Directory containing keys |

---

### 4.5 watch – Monitor Changes

Monitors configuration changes in real time.

Arguments:

* `key` OR `prefix` (mutually exclusive)
* `timeout_ms`
* `max_events`
* `initial`

Example:

```sh
config://app/db.watch(prefix="",initial=true)
```

Emits structured JSON lines:

* `snapshot`
* `set`
* `rm`

---

### 4.6 Namespace Behavior

Default namespace:

```
config://mykey.get → default/mykey.json
```

Sanitization rules allow only safe characters; unsafe characters are replaced with underscores.

---

## 5. Platform Support

| Platform   | Support Level |
| ---------- | ------------- |
| Linux      | Supported     |
| Unix/macOS | Supported     |
| Windows    | Supported     |

Support depends on filesystem permissions and user home directory resolution.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Use hierarchical organization (e.g., `app/db/connection`).
* Use `raw=true` for numeric, boolean, and object types.
* Avoid storing sensitive data without encryption.
* Leverage atomic write guarantees.

### Automation Considerations

* Validate exit codes.
* Use `ls(recursive=true)` for configuration inspection.
* Use `watch` for dynamic reconfiguration.
* Use pagination for large configuration trees.

### CI/CD Integration

* Validate required configuration keys during build.
* Use structured `get` output for pipeline validation.
* Monitor config changes for runtime reconfiguration.

### Production Recommendations

* Separate environments using namespaces (`prod`, `dev`, `test`).
* Use descriptive key names.
* Version-control configuration schemas.
* Monitor configuration changes via `watch`.

---

## 7. Use Cases by Role

### DevOps Engineers

* Manage environment-specific configuration.
* Store deployment parameters.
* Implement feature flags.

### SRE Engineers

* Monitor configuration changes.
* Validate runtime parameters.
* Implement layered configuration management.

### Network Administrators

* Store network configuration metadata.
* Maintain environment separation.
* Monitor configuration updates.

### AI/Automation Engineers

* Dynamically read configuration state.
* Subscribe to configuration changes.
* Orchestrate runtime reconfiguration workflows.

---

## 8. Technical Foundation

The `config://` handle operates within resh, implemented in Rust.

### Rust Implementation Advantages

* Memory safety
* Atomic filesystem operations
* Deterministic error handling
* Strong type guarantees

### Type Safety

JSON parsing and validation enforce consistent configuration types.

### Performance Characteristics

* Lightweight file-based storage
* Efficient hierarchical lookups
* Minimal runtime overhead

### Cross-Platform Architecture

Supported across:

* Linux
* macOS/Unix
* Windows

Operation depends on filesystem accessibility and user permissions.


