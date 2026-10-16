# Resource Shell (resh) – Plugin Handle Documentation

## 1. Overview

Resource Shell (resh) is a structured command-line framework that standardizes system automation using a resource-oriented URI execution model.

The `plugin://` handle provides lifecycle management for resh plugins, including installation, updates, removal, enablement, disablement, discovery, and catalog inspection.

Traditional extension systems often require:

* Manual download and installation procedures
* Inconsistent update workflows
* Unstructured output
* Separate discovery mechanisms
* Script-based lifecycle management

The `plugin://` handle addresses these limitations by:

* Providing a uniform URI-based command structure
* Supporting multiple plugin sources (registry, URL, file)
* Returning structured JSON output
* Enforcing deterministic lifecycle operations

All plugin operations follow the resource URI format:

```
plugin://target.verb(arguments)
```

Where:

* `target` is either a plugin ID or a special target (`available`, `installed`)
* `verb` defines the lifecycle or catalog operation
* `arguments` define execution parameters

---

## 2. Design Philosophy and Core Principles

The `plugin://` handle adheres to resh architectural principles.

### Structured Interface Model

All plugin operations follow a uniform pattern:

```
plugin://plugin-id.verb(arguments)
plugin://special-target.verb(arguments)
```

This removes ambiguity in plugin management and standardizes lifecycle control.

### Safety-First Execution

Operations include safeguards such as:

* `dry_run` simulation
* SHA256 verification (default)
* Scoped enable/disable operations
* Timeout enforcement
* Force flags for explicit override

These controls reduce operational risk during plugin changes.

### Deterministic Behavior

Operations return consistent JSON envelopes with:

* Explicit `ok` status indicator
* Exit `code`
* Parsed `args`
* Structured `result`
* Enumerated `actions`
* Structured `error` object

### JSON-Based Structured Output

Structured responses enable:

* CI/CD validation
* Declarative automation
* Audit logging
* Programmatic lifecycle control

### AI-Readiness

The deterministic URI grammar and structured response format support automated plugin lifecycle orchestration by AI agents and automation systems.

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
plugin://target.verb(arguments)
```

#### Components

| Component   | Description                                            |
| ----------- | ------------------------------------------------------ |
| `plugin`    | Handle identifier                                      |
| `target`    | Plugin ID; omitted for `available.*` and `installed.list` |
| `verb`      | Lifecycle or catalog operation                         |
| `arguments` | Named parameters controlling execution                 |

---

### Examples

Install plugin:

```sh
plugin://aws.install()
```

Install specific version:

```sh
plugin://aws.install(version="1.2.3")
```

Search catalog:

```sh
plugin://available.search(q="docker")
```

List installed plugins:

```sh
plugin://installed.list()
```

Enable plugin:

```sh
plugin://aws.enable(scope="system")
```

Remove plugin:

```sh
plugin://aws.remove(purge="true")
```

Preview an install without changing anything:

```sh
plugin://aws.install(dry_run="true")
```

The older doubled forms, such as `plugin://available.available.list` and
`plugin://installed.installed.list`, are still accepted.

---

### 3.2 Execution Semantics

All plugin operations return structured JSON with the following envelope:

* `op` – Operation name
* `ok` – Boolean success indicator
* `code` – Exit code
* `ts` – Timestamp
* `target` – The plugin addressed (an object with `name`, `requested_name`,
  and `install_root` for lifecycle verbs; the stage URL for catalog verbs)
* `args` – Parsed arguments
* `result` – Operation-specific data
* `actions` – Performed actions
* `error` – Error details (if any)

#### Representative JSON Response

```json
{
  "op": "plugin.install",
  "ok": true,
  "code": 0,
  "target": {
    "name": "aws",
    "requested_name": "aws",
    "version": "1.2.3",
    "install_root": "/home/alice/.local/share/resh/plugins",
    "bin_path": "/home/alice/.local/share/resh/plugins/aws/versions/1.2.3/plugin"
  },
  "args": {
    "dry_run": false,
    "timeout_ms": 300000
  },
  "actions": [
    {"id": "resolve-0", "type": "resolve", "name": "Resolved plugin version: 1.2.3", "ok": true},
    {"id": "check-1", "type": "check_installed", "name": "Plugin not installed", "ok": true},
    {"id": "download-2", "type": "download", "name": "Downloaded artifact (1048576 bytes)", "ok": true},
    {"id": "verify-3", "type": "verify", "name": "Checksum verified successfully", "ok": true},
    {"id": "extract-4", "type": "extract", "name": "Extracted artifact to: ...", "ok": true},
    {"id": "install-5", "type": "install", "name": "Plugin installed successfully", "ok": true},
    {"id": "activate-6", "type": "activate", "name": "Plugin activated successfully", "ok": true},
    {"id": "cleanup-7", "type": "cleanup", "name": "Staging cleanup completed", "ok": true}
  ],
  "result": {
    "installed": true,
    "version": "1.2.3"
  },
  "ts": "2026-10-16T12:00:00Z"
}
```

With `dry_run="true"`, nothing is downloaded or written: the envelope
reports the resolved version and a `plan` action, and `result.installed`
is `false`.

#### Error Example

```json
{
  "op": "plugin.install",
  "ok": false,
  "code": 2,
  "target": {
    "name": "nonexistent",
    "requested_name": "nonexistent",
    "install_root": "/home/alice/.local/share/resh/plugins"
  },
  "error": {
    "kind": "PLUGIN_NOT_FOUND",
    "message": "Plugin not found in registry: nonexistent (status: 404 Not Found)"
  }
}
```

Automation systems must evaluate `ok` and `code` fields for control flow decisions.

---

## 4. Functional Domain – Plugin Handle

### Operational Scope

The `plugin://` handle supports:

* Plugin installation
* Version updates
* Removal and purge
* Enable/disable operations
* Catalog listing and search
* Installed plugin inspection

---

### Plugin Sources

Supported sources:

| Source Type | Description                        |
| ----------- | ---------------------------------- |
| `registry`  | Official plugin registry (default) |
| `url`       | Direct HTTP/HTTPS download         |
| `file`      | Local filesystem archive           |

---

### Lifecycle Verbs

#### install

Installs a plugin from a supported source.

Optional controls include:

* `version`
* `verify`
* `force`
* `allow_downgrade`
* `dry_run`
* `timeout_ms`

---

#### update

Updates an installed plugin to latest or specified version.

Supports:

* `registry`
* `url`
* `strict`
* `dry_run`

---

#### remove

Removes a plugin from the system.

Optional:

* `force`
* `purge`
* `dry_run`

---

#### enable / disable

Controls plugin activation.

Optional:

* `scope` (`user` or `system`)
* `reason`
* `force`
* `dry_run`

---

### Catalog Verbs

#### available.list

Lists available plugins from the catalog.

Optional filtering:

* `query`
* `tags`
* `max_results`
* `sort`
* `order`

---

#### available.search

Searches plugins using:

* `q`
* `tags`
* `owner`
* `min_version`
* `max_results`
* `offline`

---

#### available.info

Retrieves metadata for a specific plugin.

Optional:

* `version`
* `channel`
* `os`
* `arch`
* `offline`

---

#### installed.list

Lists installed plugins.

Optional filters:

* `enabled`
* `name`
* `prefix`
* `tag`
* `limit`
* `offset`
* `sort`
* `format`

---

## 5. Platform Support

Platform compatibility depends on resh installation and plugin architecture.

| Platform   | Support   |
| ---------- | --------- |
| Linux      | Supported |
| Unix/macOS | Supported |
| Windows    | Supported |

Plugin compatibility may vary by OS and architecture as defined in plugin metadata.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Use `dry_run="true"` before force operations.
* Retain SHA256 verification.
* Avoid `allow_downgrade` unless explicitly required.
* Use scoped enable/disable operations carefully.

### Automation Considerations

* Parse `ok` and `code` for workflow gating.
* Pin plugin versions in CI/CD for reproducibility.
* Validate catalog availability before deployment.
* Use `offline="true"` for deterministic environments.

### CI/CD Integration

* Install specific versions during build stages.
* Validate plugin integrity before deployment.
* Use catalog search for environment validation.
* Enforce strict update policies in production.

### Production Recommendations

* Prefer registry source over direct URL.
* Monitor installed plugin health.
* Regularly review plugin versions.
* Restrict system-wide enable operations.

---

## 7. Use Cases by Role

### DevOps Engineers

* Install plugins during pipeline provisioning.
* Pin versions for reproducible builds.
* Automate updates during release cycles.
* Validate plugin availability prior to deployment.

### SRE Engineers

* Enable/disable plugins during incident response.
* Remove compromised plugins.
* Audit installed plugins regularly.
* Monitor plugin health metadata.

### Network Administrators

* Install infrastructure-related plugins.
* Validate plugin compatibility for platform environments.
* Use scoped enablement for controlled activation.

### AI/Automation Engineers

* Integrate plugin lifecycle management into orchestration agents.
* Parse structured JSON results for state management.
* Use `dry_run` for simulation environments.
* Automate catalog inspection for capability discovery.

---

## 8. Technical Foundation

The `plugin://` handle operates within the resh framework, implemented in Rust.

### Rust Implementation Advantages

* Memory safety
* Strong compile-time guarantees
* Deterministic binary behavior
* Reduced runtime instability

### Type Safety

Argument parsing and response construction are type-validated, ensuring consistent operational contracts.

### Performance Characteristics

* Efficient catalog querying
* Controlled timeout enforcement
* Structured action logging

### Cross-Platform Architecture

The plugin handle operates across:

* Linux
* macOS/Unix
* Windows

Plugin compatibility is defined per plugin metadata (OS and architecture constraints).
