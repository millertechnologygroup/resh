# Resource Shell (resh) – SSH Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using structured URI-based commands. The `ssh://` handle enables secure remote execution, file transfer, tunneling, key management, and SSH configuration inspection through typed verbs and structured output.

### Purpose

The SSH handle provides:

* Remote command execution
* Secure file upload and download
* SSH tunnel management (local, remote, dynamic)
* SSH key inspection and management
* Connection testing and configuration retrieval

All operations return structured JSON or formatted text output suitable for automation and infrastructure workflows.

### Architectural Problem Addressed

Traditional SSH tooling:

* Produces unstructured terminal output
* Mixes stdout/stderr and connection metadata
* Requires manual scripting for error handling
* Relies on implicit authentication behavior

This complicates automation, CI/CD integration, and AI-driven workflows.

resh addresses this by:

* Exposing SSH operations as explicit verbs
* Validating parameters before execution
* Returning structured result objects
* Defining machine-readable error codes
* Supporting dry-run execution

### Resource-Oriented URI Model

SSH commands follow:

```
handle://target.verb(options)
```

For SSH:

* **handle**: `ssh://`
* **target**: `[username@]hostname[:port]`
* **verb**: `exec`, `upload`, `download`, `tunnel`, `keys.list`, `key.add`, `config.get`, `test`
* **options**: Structured parameters

Example:

```
ssh://user@server.example.com.exec(command="whoami")
```

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

* Each SSH capability is exposed as a distinct verb.
* Authentication methods are explicitly defined.
* File transfer and tunnel modes are parameterized.
* Output is structured and predictable.

---

### Safety-First Execution

* Required parameters are enforced (e.g., host, command).
* Dry-run mode allows safe validation.
* Overwrite behavior must be explicitly enabled.
* Host key verification modes are configurable.
* Tunnel wildcard binds require explicit permission.

---

### Deterministic Behavior

* Identical parameters yield consistent response structures.
* Retry and timeout behaviors are explicitly configurable.
* Output capture can be controlled.
* Authentication method selection is explicit.

---

### JSON-Based Structured Output

All verbs return structured JSON by default, including:

* `ok`
* `dry_run`
* `connection` metadata
* Operation-specific `result`
* `error` object (if failure)
* `warnings` (if applicable)

---

### AI-Readiness

Structured output includes:

* Exit codes
* Authentication method used
* Remote stdout and stderr
* Tunnel parameters
* Transfer metadata
* Checksum verification results

This enables programmatic reasoning over SSH operations.

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
ssh://[username@]hostname[:port].verb(options)
```

| Component | Description              |
| --------- | ------------------------ |
| `handle`  | `ssh://`                 |
| `target`  | `[username@]host[:port]` |
| `verb`    | SSH operation            |
| `options` | Structured parameters    |

**Important Requirement:**
An explicit verb is required. `ssh://user@host` without `.verb` results in a parsing error.

---

### Production Examples

#### Execute Remote Command

```
ssh://admin@prod-server.exec(command="uptime")
```

#### Test SSH Connectivity

```
ssh://deploy@host.test
```

#### Upload File Atomically

```
ssh://user@host.upload(
  source="/local/config.yaml",
  source_mode=file,
  dest="/etc/app/config.yaml",
  atomic=true,
  overwrite=true
)
```

#### Download Remote File

```
ssh://deploy@example.com.download(
  source="/etc/app/config.yaml",
  dest="/tmp/config.yaml",
  overwrite=true
)
```

#### Create Local Tunnel

```
ssh://user@host.tunnel(
  mode=local,
  local_bind_port=5433,
  remote_dest_host=db.internal,
  remote_dest_port=5432
)
```

---

## 3.2 Execution Semantics

### Deterministic Behavior

* SSH URLs require explicit verbs.
* `dry_run=true` simulates execution.
* Authentication method must be specified or defaulted.
* Exit codes reflect operation success or failure.

---

### Structured Output Contracts

All responses include connection metadata:

```json
{
  "ok": true,
  "dry_run": false,
  "connection": {
    "host": "host.com",
    "port": 22,
    "username": "user",
    "auth_method": "agent"
  },
  "result": {
    "executed": true,
    "exit_code": 0,
    "stdout": "hello\n",
    "stderr": ""
  }
}
```

---

### Error Handling Structure

Structured error example:

```json
{
  "ok": false,
  "error": {
    "code": "ssh.auth_missing_password",
    "message": "Password is required for password authentication"
  }
}
```

Common error codes include:

* `ssh.host_required`
* `ssh.command_required`
* `ssh.auth_missing_password`
* `ssh.auth_missing_key`
* `ssh.upload_dest_exists`
* `ssh.upload_checksum_mismatch`
* `ssh.download_source_missing`
* `ssh.tunnel_mode_required`

---

## 4. Functional Domains

### 4.1 Automation Utilities

**Scope**

Remote execution and orchestration of infrastructure tasks.

**Use Cases**

* Deployment automation
* Configuration validation
* Remote service inspection

---

### 4.2 Data & State Management

**Scope**

File transfer and configuration management.

**Use Cases**

* Uploading configuration files
* Retrieving logs
* Validating file integrity via checksum

---

### 4.3 Filesystem & Storage

**Supported Operations**

* `upload`
* `download`

**Capabilities**

* Atomic writes
* Overwrite control
* Base64 encoding
* Checksum verification
* Parent directory creation

---

### 4.4 Network & Remote Operations

**Supported Operations**

* `exec`
* `test`
* `tunnel`

**Tunnel Modes**

* `local`
* `remote`
* `dynamic` (SOCKS proxy)

**Integration Scenarios**

* Secure database forwarding
* Remote service exposure
* Bastion-based infrastructure access

---

### 4.5 Packages & Software

Used for:

* Remote installation validation
* Package inspection via `exec`
* Artifact transfer

---

### 4.6 Process & Service Management

Via `exec`:

* Check service status
* Restart services
* Inspect logs

Example:

```
ssh://admin@host.exec(command="systemctl status nginx")
```

---

### 4.7 Security & Secrets

**Authentication Methods**

| Method     | Description                     |
| ---------- | ------------------------------- |
| `agent`    | SSH agent (default)             |
| `password` | Password (requires sshpass)     |
| `key`      | Private key file or inline data |

**Host Key Verification Modes**

* `strict`
* `accept_new`
* `insecure`

Security-related features:

* Key-based authentication
* Host key verification control
* Tunnel wildcard bind restrictions
* Output capture control

---

### 4.8 System Information

SSH responses include:

* Remote exit codes
* Output metadata
* Tunnel configuration
* Connection details
* File size and checksum information

---

## 5. Platform Support

Platform behavior includes:

* SSH operations depend on system SSH capabilities.
* Password authentication requires `sshpass`.
* Tunnel and file transfer features operate across supported platforms.
* No additional OS-specific limitations are defined in documentation.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Always specify explicit verbs.
* Use `dry_run=true` for validation.
* Avoid password authentication in automation.
* Use key-based authentication with passphrases.
* Enforce strict host key verification in production.

---

### Automation Considerations

* Consume JSON output in pipelines.
* Check `ok` and `exit_code` values.
* Handle structured error codes.
* Set explicit timeouts for long-running commands.
* Limit output capture size with `max_output_bytes`.

---

### CI/CD Integration

Recommended workflow:

1. Use `test` to verify connectivity.
2. Upload artifacts using `upload`.
3. Execute deployment commands with `exec`.
4. Validate service status.
5. Use `download` for log retrieval on failure.

---

### Production Environment Recommendations

* Use SSH keys instead of passwords.
* Protect private keys with restrictive permissions.
* Avoid wildcard tunnel binds unless required.
* Limit tunnel lifetimes and connection counts.
* Enable checksum verification for file transfers.

---

## 7. Use Cases by Role

### DevOps Engineers

* Automate remote deployments.
* Manage configuration files.
* Execute remote health checks.

---

### SRE Engineers

* Diagnose production systems.
* Retrieve logs securely.
* Create temporary tunnels for debugging.

---

### Network Administrators

* Configure secure tunnels.
* Validate SSH connectivity.
* Inspect host keys.

---

### AI / Automation Engineers

* Consume structured execution metadata.
* Trigger workflows based on exit codes.
* Analyze file transfer validation results.
* Implement policy enforcement via structured error codes.

---

## 8. Technical Foundation

### Rust Implementation Advantages

resh is implemented in Rust, providing:

* Memory safety
* Strong compile-time guarantees
* Predictable execution
* Efficient process management

---

### Type Safety

* Enumerated authentication methods
* Defined tunnel modes
* Explicit parameter validation
* Structured error typing

---

### Performance Characteristics

* Native binary execution
* Efficient SSH process invocation
* Configurable timeouts and retries
* Controlled output capture

---

### Cross-Platform Architecture

* CLI-based execution model
* Platform-dependent SSH availability
* Consistent JSON output across environments

