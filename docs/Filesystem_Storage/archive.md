# Resource Shell (resh) – Archive Handle Documentation

## 1. Overview

Resource Shell (resh) is a structured command-line framework that standardizes infrastructure operations using a resource-oriented URI execution model.

The `archive://` handle provides comprehensive archive management across multiple formats, including:

* tar
* tar.gz / tgz
* tar.xz
* tar.zst / tar.zstd
* zip
* 7z
* gzip (single-file)
* raw compressed formats

It supports:

* Archive creation
* Extraction
* Listing contents
* Integrity testing
* Metadata inspection
* Incremental modification (add/remove)

Traditional archive workflows often rely on multiple utilities (`tar`, `zip`, `7z`, `gzip`) with inconsistent flags and output formats. This complicates automation and increases risk in CI/CD and production environments.

The `archive://` handle addresses these issues by:

* Providing a unified URI-based command model
* Supporting structured JSON output
* Enforcing security protections during extraction
* Offering format auto-detection
* Supporting deterministic automation

All operations follow the resh URI model:

```
handle://target.verb(options)
```

For the archive domain:

```
archive://archive-file.verb(options)
```

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

Archive operations use a consistent resource-oriented grammar:

```
archive://target.verb(options)
```

Examples:

```bash
archive://backup.tar.gz.create(...)
archive://backup.tar.gz.extract(...)
archive://backup.tar.gz.list(...)
```

This eliminates tool fragmentation and enforces consistent syntax across archive formats.

---

### Safety-First Execution

The archive handle enforces multiple safeguards:

* Path traversal protection (`..` blocked by default)
* Absolute path rejection
* Size and entry limits
* Symlink handling controls
* Decompression bomb protection
* Optional dry-run for destructive operations

Security-sensitive parameters include:

* `allow_parent_traversal`
* `allow_absolute_paths`
* `max_entries`
* `max_total_bytes`
* `max_file_bytes`
* `dry_run`

Safe defaults are enforced unless explicitly overridden.

---

### Deterministic Behavior

Operations:

* Follow strict argument validation
* Return consistent structured results
* Use explicit format detection rules
* Enforce entry and size limits predictably
* Separate operational success from structured error reporting

Exit codes:

| Code | Meaning |
| ---- | ------- |
| 0    | Success |
| 1    | Error   |

Automation systems must rely on exit codes and structured JSON output.

---

### JSON-Based Structured Output

By default, operations return structured JSON:

```json
{
  "ok": true,
  "summary": {
    "format": "tar.gz",
    "entries_total": 3,
    "archive_size_bytes": 2048
  }
}
```

Structured output supports:

* CI/CD validation
* Integrity verification
* Automated auditing
* Programmatic inspection

---

### AI-Readiness

The URI grammar and JSON output model allow archive inspection, verification, and modification to be integrated into automated agents and orchestration workflows without fragile text parsing.

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
archive://target.verb(options)
```

#### Components

| Component | Description                          |
| --------- | ------------------------------------ |
| `archive` | Handle identifier                    |
| `target`  | Archive file path                    |
| `verb`    | Archive operation                    |
| `options` | Named arguments controlling behavior |

---

### Example Commands

Create archive:

```bash
archive://create output=backup.tar.gz sources='["/data"]'
```

Extract archive:

```bash
archive://extract archive=backup.tar.gz destination=/restore
```

List contents:

```bash
archive://list archive=backup.tar.gz
```

Test integrity:

```bash
archive://test archive=backup.tar.gz
```

Add files:

```bash
archive://add archive=backup.tar.gz inputs='["/data/new.txt"]'
```

Remove files:

```bash
archive://remove archive=backup.tar.gz paths='["old.txt"]'
```

---

### 3.2 Execution Semantics

All operations validate:

* Format detection
* Size constraints
* Entry limits
* Security flags

Representative JSON output:

```json
{
  "ok": true,
  "summary": {
    "format": "tar.gz",
    "compression": "gzip",
    "entries_extracted": 3,
    "bytes_extracted": 2048
  }
}
```

Representative error example:

```json
{
  "ok": false,
  "error_code": "archive.extract_path_traversal_detected",
  "message": "Blocked path traversal attempt"
}
```

Automation should evaluate:

* `ok` field
* `summary`
* Exit code

---

## 4. Functional Domain – Archive Management

### Operational Scope

The `archive://` handle supports:

* Multi-format archive creation
* Selective extraction
* Integrity validation
* Incremental modification
* Metadata inspection
* Security-controlled extraction

---

### 4.1 Supported Formats

| Extension     | Format   |
| ------------- | -------- |
| .tar          | tar      |
| .tar.gz, .tgz | tar.gz   |
| .tar.xz       | tar.xz   |
| .tar.zst      | tar.zstd |
| .zip          | zip      |
| .7z           | 7z       |
| .gz           | raw/gzip |
| .xz           | raw/xz   |
| .zst          | raw/zstd |

Format detection defaults to `auto`.

Override example:

```bash
format="tar.gz"
```

---

### 4.2 Core Verbs

| Verb                   | Description                          |
| ---------------------- | ------------------------------------ |
| `create`               | Create new archive                   |
| `extract`              | Extract archive contents             |
| `list`                 | List archive contents                |
| `test`                 | Verify archive integrity             |
| `info`                 | Display archive metadata             |
| `add`                  | Add entries to existing archive      |
| `remove`               | Remove entries from existing archive |
| `help`, `--help`, `-h` | Display documentation                |

---

### 4.3 Common DevOps Use Cases

* Build artifact packaging
* Backup creation
* Secure extraction of third-party archives
* Integrity verification in CI pipelines
* Incremental archive updates
* Deployment packaging

---

### 4.4 Security Features

| Protection              | Default  |
| ----------------------- | -------- |
| Path traversal blocking | Enabled  |
| Absolute path blocking  | Enabled  |
| Symlink control         | Enabled  |
| Entry limits            | Enforced |
| Total size limits       | Enforced |
| File size limits        | Enforced |

Extraction example with limits:

```bash
archive://extract archive=untrusted.tar.gz destination=/safe max_total_bytes=1073741824 max_file_bytes=10485760
```

---

### 4.5 Compression Levels

| Format | Min | Max | Default |
| ------ | --- | --- | ------- |
| gzip   | 1   | 9   | 6       |
| xz     | 1   | 9   | 6       |
| zstd   | 1   | 22  | 3       |
| zip    | 1   | 9   | 6       |
| 7z     | 1   | 9   | 5       |

Lower level = faster compression
Higher level = smaller archive

---

## 5. Platform Support

| Platform | Support Level                       |
| -------- | ----------------------------------- |
| Linux    | Full support                        |
| macOS    | Supported                           |
| Windows  | Supported with metadata limitations |

Metadata preservation varies by platform and format.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Test archives after creation.
* Use size limits for untrusted archives.
* Use `dry_run` before destructive `remove`.
* Back up archives before modification.
* Use `strip_components` when extracting untrusted archives.

---

### Automation Considerations

* Always use JSON output in CI environments.
* Validate `ok` field and exit codes.
* Enforce maximum entry limits.
* Use `include_patterns` and `exclude_patterns` to reduce workload.

---

### CI/CD Integration

Common pipeline pattern:

1. Create archive
2. Test integrity
3. Validate contents
4. Deploy or publish

Example:

```bash
archive://create output=release.tar.gz sources='["/build"]'
archive://test archive=release.tar.gz
```

---

### Production Recommendations

* Prefer `tar.gz` for Unix systems.
* Use `zip` for cross-platform distribution.
* Use `tar.zstd` for faster compression.
* Avoid compressing already compressed files.
* Monitor compression ratio efficiency.

---

## 7. Use Cases by Role

### DevOps Engineers

* Package build artifacts.
* Verify deployment archives.
* Implement secure extraction in pipelines.
* Create filtered backups.

### SRE Engineers

* Validate archive integrity during incident response.
* Extract production backups safely.
* Enforce decompression size limits.
* Audit archive metadata.

### Network Administrators

* Package configuration backups.
* Distribute firmware bundles.
* Validate downloaded archives.
* Extract vendor packages securely.

### AI/Automation Engineers

* Inspect archive metadata programmatically.
* Validate contents using JSON manifest.
* Integrate structured archive validation into agents.
* Trigger workflows based on archive summary data.

---

## 8. Technical Foundation

The `archive://` handle operates within resh, implemented in Rust.

### Rust Implementation Advantages

* Memory safety
* Deterministic error handling
* Efficient streaming I/O
* Strong type validation

### Type Safety

Arguments are validated for:

* Format compatibility
* Compression level ranges
* Size constraints
* Required parameter presence

Invalid configurations result in structured error responses.

---

### Performance Characteristics

* Streaming TAR processing
* Format-specific compression performance
* Full-archive rewrite for modification operations
* Controlled memory usage
* Deterministic entry limits

---

### Cross-Platform Architecture

Supported on:

* Linux
* macOS
* Windows

Behavior varies by filesystem semantics and metadata capabilities.

