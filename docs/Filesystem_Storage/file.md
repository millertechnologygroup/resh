# Resource Shell (resh) – File Handle Documentation

## 1. Overview

Resource Shell (resh) is a structured command-line framework that standardizes infrastructure operations using a resource-oriented URI execution model.

The `file://` handle provides comprehensive file and directory management capabilities for local filesystems. It supports:

* Basic file I/O operations
* Metadata inspection
* File manipulation
* Permission management (Unix)
* Cryptographic hashing and verification
* Content search and replacement
* File structure analysis
* Change monitoring
* Extended attributes (Unix)

Traditional file management from shell environments often relies on multiple utilities (`cat`, `cp`, `mv`, `chmod`, `grep`, `find`, `sha256sum`, etc.) with inconsistent syntax and output formats. This complicates automation and increases parsing fragility.

The `file://` handle addresses these limitations by:

* Providing a unified URI-based interface
* Enforcing absolute-path addressing
* Returning structured JSON output where appropriate
* Standardizing exit codes
* Supporting deterministic automation workflows

All file operations follow the URI format:

```
file:///absolute/path/to/resource.VERB(arguments)
```

Absolute paths are required for reliability and determinism.

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

All operations follow:

```
file://absolute-path.verb(arguments)
```

Examples:

```bash
file:///tmp/data.txt.read
file:///var/log/app.log.tail(lines=50)
file:///etc/config.yaml.replace(pattern="old",replacement="new")
```

This enforces consistent grammar across 30 verbs covering file lifecycle operations.

---

### Safety-First Execution

The `file://` handle implements:

* Atomic write and append operations (where possible)
* Explicit overwrite controls
* Backup options for destructive operations
* Exit codes for deterministic error handling
* Optional creation flags (`create=false`)
* Hash size limits (10GB maximum)

Platform-specific operations (e.g., `chmod`, `chown`, extended attributes) return exit code `95` when unsupported.

---

### Deterministic Behavior

Operations:

* Require absolute paths
* Use strict argument validation
* Return structured JSON for metadata and hashing
* Use predictable exit codes
* Avoid implicit shell expansion

Exit Codes:

| Code | Meaning               |
| ---- | --------------------- |
| 0    | Success               |
| 1    | General error         |
| 2    | File not found        |
| 3    | Permission denied     |
| 95   | Feature not supported |

Automation should rely on exit codes and JSON responses rather than parsing textual output.

---

### JSON-Based Structured Output

Structured JSON output is provided for:

* `exists`
* `stat`
* Hashing operations
* `verify`
* `find`
* Metadata and analysis verbs

Example:

```json
{
  "path": "/tmp/file.txt",
  "algorithm": "sha256",
  "hash": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
  "size": 5
}
```

---

### AI-Readiness

The predictable URI grammar and structured outputs enable:

* Deterministic automation
* CI/CD pipeline integration
* Integrity validation workflows
* Agent-based orchestration
* Programmatic content inspection

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
file:///absolute/path.VERB(arguments)
```

#### Components

| Component     | Description              |
| ------------- | ------------------------ |
| `file`        | Handle identifier        |
| Absolute Path | Target file or directory |
| `VERB`        | Operation                |
| `arguments`   | Named parameters         |

**Requirements:**

* Absolute paths required
* Case-sensitive
* URL encoding required for special characters

---

### Example Commands

Basic read:

```bash
file:///tmp/example.txt.read
```

Write content:

```bash
file:///tmp/example.txt.write(data="hello")
```

Calculate SHA-256:

```bash
file:///tmp/example.txt.sha256
```

Search text:

```bash
file:///tmp/example.txt.grep(pattern="ERROR")
```

---

### 3.2 Execution Semantics

Operations return either:

* Raw output (e.g., `read`)
* Structured JSON (e.g., `stat`, `hash`)
* Exit-code-based success/failure

#### Representative JSON Output (exists)

```json
{
  "path": "/tmp/file.txt",
  "exists": true,
  "kind": "file"
}
```

#### Representative JSON Output (verify)

```json
{
  "path": "/tmp/file.txt",
  "algorithm": "sha256",
  "verified": true,
  "size": 1024
}
```

Automation must inspect:

* Exit codes
* `verified` flag
* Structured JSON fields

---

## 4. Functional Domain – File Handle

The `file://` handle belongs to the **Filesystem & Storage** domain.

It provides 30 verbs across several categories.

---

### 4.1 Basic I/O

| Verb     | Description                |
| -------- | -------------------------- |
| `read`   | Stream entire file         |
| `write`  | Atomic overwrite or create |
| `append` | Atomic append              |

Example:

```bash
file:///tmp/log.txt.append(data="entry")
```

---

### 4.2 File Information

| Verb     | Description          |
| -------- | -------------------- |
| `exists` | Check file existence |
| `stat`   | Retrieve metadata    |

---

### 4.3 File Operations

| Verb     | Description |
| -------- | ----------- |
| `copy`   | Copy file   |
| `delete` | Remove file |
| `rename` | Rename file |
| `move`   | Move file   |

Example:

```bash
file:///tmp/file.txt.copy(to="/backup/file.txt",overwrite=true)
```

---

### 4.4 Permissions (Unix Only)

| Verb    | Description      |
| ------- | ---------------- |
| `chmod` | Change file mode |
| `chown` | Change ownership |

Example:

```bash
file:///tmp/script.sh.chmod(mode=755)
```

---

### 4.5 Hashing & Integrity

Supported algorithms:

* MD5
* SHA-1
* SHA-256
* SHA-512
* BLAKE3

Verbs:

| Verb                              | Description             |
| --------------------------------- | ----------------------- |
| `md5`, `sha1`, `sha256`, `sha512` | Fixed algorithm         |
| `hash(algo=...)`                  | Configurable            |
| `verify(...)`                     | Verify hash and/or size |

Example:

```bash
file:///tmp/file.iso.verify(algo=sha256,expected=<hash>)
```

Security Note:

* SHA-256+ recommended
* 10GB hash size limit enforced

---

### 4.6 Search and Analysis

| Verb      | Description         |
| --------- | ------------------- |
| `find`    | Recursive search    |
| `grep`    | Pattern search      |
| `replace` | Pattern replacement |
| `tail`    | Last lines          |
| `preview` | Intelligent preview |
| `schema`  | Structure detection |
| `summary` | File summary        |
| `watch`   | Monitor changes     |
| `analyze` | Content analysis    |

Example:

```bash
file:///var/log/app.log.tail(lines=100,follow=true)
```

---

### 4.7 Extended Attributes (Unix Only)

| Verb      | Description             |
| --------- | ----------------------- |
| `ea.get`  | Get extended attributes |
| `ea.set`  | Set extended attributes |
| `tag.add` | Add tags                |
| `tag.rm`  | Remove tags             |

These operations return exit code `95` on unsupported platforms.

---

## 5. Platform Support

| Platform | Support                        |
| -------- | ------------------------------ |
| Linux    | Full support                   |
| macOS    | Full support                   |
| Windows  | Supported (no Unix-only verbs) |

Unix-only features:

* `chmod`
* `chown`
* Extended attributes
* Tag operations

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Always use absolute paths.
* Use `create=false` to prevent unintended file creation.
* Use `overwrite=false` to prevent accidental overwrites.
* Create backups before `replace` operations.
* Use secure permission modes (600, 640) for sensitive files.
* Use `verify` after critical file transfers.

---

### Automation Considerations

* Always inspect exit codes.
* Use JSON-returning verbs in CI pipelines.
* Limit search depth in `find`.
* Use `max_count` in `grep`.
* Avoid hashing files near 10GB limit.

---

### CI/CD Integration

Typical workflows:

* Validate file integrity after artifact download.
* Replace configuration safely with backup enabled.
* Verify permission modes post-deployment.
* Monitor log files in post-deployment checks.

Example:

```bash
file:///deploy/app.bin.verify(algo=sha256,expected=<published>)
```

---

### Production Environment Recommendations

* Use SHA-256 or SHA-512 for security validation.
* Restrict permissions using `chmod`.
* Use atomic `write` and `rename`.
* Monitor file changes with `watch`.
* Avoid MD5 and SHA-1 for security-sensitive validation.

---

## 7. Use Cases by Role

### DevOps Engineers

* Validate deployment artifacts.
* Manage configuration files.
* Monitor logs during rollout.
* Replace values programmatically.

### SRE Engineers

* Investigate incidents via file inspection.
* Verify integrity after transfers.
* Secure sensitive files.
* Monitor change events.

### Network Administrators

* Manage configuration backups.
* Secure credentials with strict permissions.
* Analyze log files.
* Track file changes.

### AI/Automation Engineers

* Use deterministic JSON output for orchestration.
* Validate file integrity in automated pipelines.
* Extract schema metadata programmatically.
* Monitor configuration drift via `watch`.

---

## 8. Technical Foundation

The `file://` handle is implemented in Rust as part of resh.

### Rust Implementation Advantages

* Memory safety
* Deterministic file I/O
* Strong type enforcement
* Safe concurrency primitives

### Type Safety

* Validated argument parsing
* Algorithm whitelist enforcement
* Strict path handling
* Explicit exit code mapping

### Performance Characteristics

* Atomic write/append
* Efficient streaming for `read`
* Hash size enforcement
* Directory traversal optimization in `find`

### Cross-Platform Architecture

Supported on:

* Linux
* macOS
* Windows

Unix-only features return exit code `95` on unsupported platforms.


