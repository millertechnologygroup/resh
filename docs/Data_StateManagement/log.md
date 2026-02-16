# Resource Shell (resh) – Log Handle Documentation

## 1. Overview

Resource Shell (resh) is a structured command-line framework that standardizes system and infrastructure operations using a resource-oriented URI execution model.

The `log://` handle provides structured access to:

* File-based log files
* System service logs via `journalctl`

It supports:

* Tail-style retrieval of recent log entries
* Substring-based pattern filtering
* Structured JSON output
* Efficient handling of large log files

Traditional log analysis from the shell typically involves:

* Direct use of `tail`, `grep`, `awk`
* Service-specific commands
* Manual parsing of output
* Inefficient reading of large files
* Inconsistent error handling

The `log://` handle addresses these issues by:

* Providing a consistent URI-based interface
* Returning deterministic output structures
* Implementing efficient file-reading algorithms
* Supporting structured JSON output for automation
* Exposing a built-in help system

All operations follow the resh URI format:

```
log://target.verb(options)
```

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

All log operations follow:

```
log://path_or_service.verb(arguments)
```

Examples:

* File log: `log:///var/log/syslog.tail`
* Relative file: `log://./app.log.tail`
* Service log: `log://svc/nginx.tail`

This standardizes log access across file and service sources.

### Safety-First Execution

The handle enforces:

* Explicit argument validation
* Structured exit codes
* Controlled memory usage
* Clear error reporting for file and permission failures

Invalid arguments and file access errors result in consistent exit status `2`.

### Deterministic Behavior

Operations:

* Return predictable output based on `mode`
* Use consistent argument validation rules
* Provide stable JSON structures in `mode=json`
* Separate data from error information

### JSON-Based Structured Output

When `mode=json` is specified, output includes:

* `path`
* `requested_lines`
* `returned_lines`
* `pattern`
* `lines`

This enables deterministic parsing in automation workflows.

### AI-Readiness

The consistent URI grammar and structured JSON output enable log inspection and filtering within automated systems without reliance on fragile text parsing.

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
log://target.verb(options)
```

#### Components

| Component | Description                               |
| --------- | ----------------------------------------- |
| `log`     | Handle identifier                         |
| `target`  | File path or service (`svc/service-name`) |
| `verb`    | `tail`, `help`, `--help`, `-h`            |
| `options` | Named parameters                          |

---

### File Log Formats

| Format        | Example                      |
| ------------- | ---------------------------- |
| Absolute file | `log:///var/log/syslog.tail` |
| Relative file | `log://./app.log.tail`       |
| Service log   | `log://svc/nginx.tail`       |

---

### Preferred Syntax (Space-Separated)

```bash
resh log:///var/log/syslog.tail lines=10
resh log:///var/log/syslog.tail pattern=ERROR mode=json
```

### Alternative Syntax (Quoted)

```bash
resh "log:///var/log/syslog.tail(lines=10)"
```

Parentheses syntax must be quoted to avoid shell parsing errors.

---

### 3.2 Execution Semantics

All operations return output in one of two modes:

* `raw` (default)
* `json`

#### JSON Mode Example

```json
{
  "path": "/var/log/syslog",
  "requested_lines": 30,
  "returned_lines": 6,
  "pattern": "ERROR",
  "lines": [
    "Jan 01 10:00:01 host ERROR failure detected",
    "Jan 01 10:00:02 host ERROR retrying"
  ]
}
```

#### Error Example (JSON Mode)

```json
{
  "error": "Log file does not exist: /tmp/missing.log",
  "path": "/tmp/missing.log",
  "requested_lines": 10,
  "returned_lines": 0
}
```

Exit codes:

| Code | Meaning                               |
| ---- | ------------------------------------- |
| 0    | Success                               |
| 2    | Invalid argument or file access error |

Automation systems must evaluate exit codes and structured fields rather than parsing human-readable messages.

---

## 4. Functional Domain – Log Handle

The `log://` handle falls under **System Information and Observability**.

### Operational Scope

* Read last N lines of log files
* Filter logs using substring matching
* Access systemd service logs
* Produce structured output for automation
* Handle large files efficiently

---

### 4.1 Core Verb: `tail`

Retrieves the last N lines of a log source.

#### Arguments

| Argument  | Description                    | Default |
| --------- | ------------------------------ | ------- |
| `lines`   | Number of lines to return (>0) | 100     |
| `pattern` | Substring filter               | None    |
| `mode`    | `raw` or `json`                | `raw`   |

---

### Examples

Basic tail:

```bash
resh log:///tmp/app.log.tail
```

Specific line count:

```bash
resh log:///tmp/app.log.tail lines=20
```

Pattern filtering:

```bash
resh log:///tmp/app.log.tail lines=50 pattern=ERROR
```

JSON output:

```bash
resh log:///var/log/syslog.tail lines=100 pattern=CRON mode=json
```

Service log access:

```bash
resh log://svc/nginx.tail lines=50 pattern=error
```

---

### 4.2 Help System

The log handle includes an integrated help system.

Full help:

```bash
log://help
log://--help
log://-h
```

Verb-specific help:

```bash
log://--help=tail
```

The help system includes syntax, performance guidance, examples, and error-handling documentation.

---

### 4.3 File Format Support

Supported:

* Plain text logs
* Syslog
* Web server logs
* Application logs
* Custom line-based logs

Characteristics:

* Line-based processing
* Case-sensitive substring matching
* No regex support
* No multi-line entry handling
* No streaming mode (`tail -f` not supported)

---

### 4.4 Performance Characteristics

The handle uses size-based optimization:

| File Size | Strategy                    |
| --------- | --------------------------- |
| < 64KB    | Read entire file            |
| ≥ 64KB    | Backward scan in 8KB chunks |

Large files are processed without loading entire contents into memory, enabling efficient tail operations on multi-gigabyte logs.

---

### 4.5 Service Logs

Service logs use `journalctl`.

Requirements:

* `journalctl` must be installed
* Service must exist
* User must have permission

Example:

```bash
resh log://svc/postgresql.tail lines=30 mode=json
```

Service log behavior depends on system configuration.

---

## 5. Platform Support

| Platform   | Support Level       |
| ---------- | ------------------- |
| Linux      | Supported           |
| macOS/Unix | File logs supported |
| Windows    | File logs supported |

Service log functionality depends on `journalctl` availability and systemd presence.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Always specify `lines` in automation.
* Use `mode=json` for programmatic processing.
* Validate exit codes.
* Confirm file existence before automation loops.
* Limit output size for large logs.

### Automation Considerations

* Use `pattern` to reduce output volume.
* Combine JSON mode with tools such as `jq`.
* Handle empty file responses explicitly.
* Avoid excessive line counts in production scripts.

### CI/CD Integration

* Validate recent log entries after deployment.
* Detect error conditions via pattern matching.
* Use JSON mode to count matching lines.
* Gate pipeline stages based on structured results.

Example:

```bash
ERROR_COUNT=$(resh log:///var/log/app.log.tail pattern=ERROR mode=json | jq '.returned_lines')
```

### Production Recommendations

* Use absolute paths for system logs.
* Monitor log rotation behavior.
* Use service logs for systemd-managed services.
* Keep substring patterns simple.
* Combine with Unix tools for advanced analysis.

---

## 7. Use Cases by Role

### DevOps Engineers

* Validate deployments by inspecting recent logs.
* Automate post-deployment checks.
* Extract structured error counts in pipelines.

### SRE Engineers

* Investigate incidents using efficient tail operations.
* Monitor service logs via systemd.
* Analyze error frequency through structured output.

### Network Administrators

* Inspect system logs for network-related events.
* Monitor service startup and failure conditions.
* Filter logs for configuration changes.

### AI/Automation Engineers

* Use structured JSON responses for anomaly detection.
* Integrate log inspection into orchestration agents.
* Trigger actions based on filtered log output.

---

## 8. Technical Foundation

The `log://` handle operates within resh, implemented in Rust.

### Rust Implementation Advantages

* Memory safety
* Efficient file I/O handling
* Deterministic error propagation
* Predictable cross-platform behavior

### Type Safety

Argument parsing enforces:

* Valid line counts
* Valid output modes
* Correct URL structure

Invalid inputs return explicit error codes.

### Performance Characteristics

* Optimized backward file scanning
* Minimal memory footprint for large logs
* Efficient substring filtering
* Structured JSON serialization

### Cross-Platform Architecture

Supported across:

* Linux
* macOS/Unix
* Windows (file-based logs)

Service log support depends on `journalctl` availability.

