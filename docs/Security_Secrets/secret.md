# Resource Shell (resh) – Secret Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using structured URI-based commands. The `secret://` handle provides secure storage and retrieval of sensitive information such as API keys, passwords, tokens, and cryptographic material.

### Purpose

The secret domain enables:

* Secure storage of sensitive values
* Retrieval with optional redaction
* Secret listing and removal
* Cryptographic secret generation and rotation
* Integration with environment variables

All operations return structured JSON output suitable for automation, CI/CD pipelines, and infrastructure orchestration.

### Architectural Problem Addressed

Traditional secret management approaches:

* Store secrets in plaintext files or environment variables
* Lack encryption at rest
* Provide no structured interface
* Require ad hoc scripting for rotation
* Produce unstructured output

resh addresses these limitations by:

* Providing an encrypted local secret store
* Exposing a structured URI-based command model
* Enforcing JSON output contracts
* Supporting deterministic secret generation
* Enabling programmatic redaction for safe logging

### Resource-Oriented URI Model

Secret operations follow:

```
secret://scope/key_path.verb(options)
```

Where:

* **handle**: `secret://`
* **scope**: `local`, `env`, or `vault` (planned)
* **key_path**: Hierarchical key identifier
* **verb**: Operation (`get`, `set`, `rm`, `ls`, `rotate`)
* **options**: Structured parameters

Examples:

```
secret://local/openai/api_key.set(value="sk-test123")
secret://local/openai/api_key.get(redact=true)
secret://env/DATABASE_URL.get
secret://local/.ls
```

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

* Five explicitly defined verbs.
* Hierarchical key path addressing.
* Scope-based storage abstraction.
* Deterministic JSON output.
* Verb-specific structured parameters.

---

### Safety-First Execution

* Local secrets encrypted at rest.
* File permissions restricted to owner (0600).
* Redaction support (`redact=true`).
* Environment scope is read-only.
* Atomic file writes prevent corruption.
* Secret exposure requires explicit parameter (`expose_value=true`).

---

### Deterministic Behavior

* Identical inputs produce consistent JSON responses.
* Scope behavior strictly enforced.
* Parameter validation required per verb.
* Invalid operations return structured errors.

---

### JSON-Based Structured Output

Representative example:

```json
{
  "scope": "local",
  "key": "openai/api_key",
  "backend": "local",
  "exists": true,
  "value": null,
  "redacted": true
}
```

All responses include scope, key, backend, and operation-specific metadata.

---

### AI-Readiness

Structured output enables:

* Automated secret audits
* Compliance verification
* Rotation policy enforcement
* Secret existence validation
* Programmatic redaction safety

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
secret://scope/key_path.verb(arguments)
```

| Component   | Description                       |
| ----------- | --------------------------------- |
| `handle`    | `secret://`                       |
| `scope`     | `local`, `env`, `vault` (planned) |
| `key_path`  | Hierarchical secret identifier    |
| `verb`      | Operation                         |
| `arguments` | Structured parameters             |

---

### Available Verbs

| Verb     | Purpose             |
| -------- | ------------------- |
| `get`    | Retrieve secret     |
| `set`    | Store secret        |
| `rm`     | Remove secret       |
| `ls`     | List secrets        |
| `rotate` | Generate new secret |

---

### Production Examples

#### Store Secret

```
secret://local/myapp/db/password.set(from_env="MYAPP_DB_PASSWORD")
```

#### Retrieve Secret (Redacted)

```
secret://local/myapp/db/password.get(redact=true)
```

#### List Secrets

```
secret://local/myapp.ls
```

#### Remove Secret

```
secret://local/myapp/db/password.rm
```

#### Rotate Secret

```
secret://local/myapp/token.rotate(strategy=random,length=256)
```

#### Generate RSA Key Pair

```
secret://local/crypto/rsa.rotate(strategy=rsa,length=4096)
```

---

## 3.2 Execution Semantics

### Deterministic Behavior

* `set` requires either `value` or `from_env`.
* `env` scope is read-only.
* `rotate` defaults to random 256-bit generation.
* `expose_value=false` by default.
* File writes are atomic.
* Missing keys return structured error.

---

### Structured Output Contracts

Example: Set operation

```json
{
  "scope": "local",
  "key": "myapp/db/password",
  "backend": "local",
  "set": true,
  "source": "env"
}
```

Example: Rotate operation

```json
{
  "scope": "local",
  "key": "myapp/token",
  "backend": "local",
  "rotated": true,
  "strategy": "random",
  "length": 256
}
```

---

### Error Handling Structure

Representative error:

```json
{
  "scope": "local",
  "key": "nonexistent",
  "backend": "local",
  "error": "key not found"
}
```

Errors are structured and suitable for programmatic evaluation.

---

## 4. Functional Domains

---

### 4.1 Automation Utilities

**Handle**

* `secret://`

**Scope**

* CI/CD secret injection
* Application provisioning
* Automated rotation
* Environment synchronization

---

### 4.2 Data & State Management

**Scope**

* Secret inventory via `ls`
* Existence checks
* Prefix-based grouping
* Secret lifecycle management

Example:

```
secret://local/projectX.ls
```

---

### 4.3 Filesystem & Storage

**Local Scope Storage Locations**

| Platform | Path                                          |
| -------- | --------------------------------------------- |
| Linux    | `~/.local/state/resh/secrets/`                |
| macOS    | `~/Library/Application Support/resh/secrets/` |
| Windows  | `%APPDATA%\resh\secrets\`                     |

Features:

* Encrypted JSON storage
* 0600 file permissions
* Atomic writes

---

### 4.4 Network & Remote Operations

Supports secure integration with:

* HTTP clients
* Service deployments
* TLS configurations
* API authentication

Example:

```
secret://local/api/token.get(redact=true)
```

---

### 4.5 Packages & Software

Supports:

* Secure configuration of installed applications
* Credential injection post-install
* Environment isolation per deployment stage

---

### 4.6 Process & Service Management

Integrates with:

* `svc://` for service reload after secret update
* `cron://` for scheduled rotation
* `config://` for configuration referencing

---

### 4.7 Security & Secrets

Primary capabilities:

| Scope | Access               |
| ----- | -------------------- |
| local | Read/write encrypted |
| env   | Read-only            |
| vault | Planned              |

Rotation strategies:

* `random`
* `uuid`
* `aes`
* `rsa`

Security controls:

* Encrypted storage
* Explicit value exposure
* Strong random generation
* No automatic exposure in logs

---

### 4.8 System Information

Structured reporting includes:

* Scope
* Backend
* Key path
* Existence status
* Rotation metadata
* Strategy and length (for generated secrets)

---

## 5. Platform Support

| Platform | Support Level |
| -------- | ------------- |
| Linux    | Full support  |
| macOS    | Full support  |
| Windows  | Full support  |

Notes:

* Storage paths differ by OS.
* Environment scope depends on OS environment variables.
* Vault integration not yet implemented.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Always use `redact=true` in logs.
* Avoid plaintext secrets in scripts.
* Use hierarchical paths (`app/env/service/key`).
* Rotate secrets periodically.
* Remove unused secrets.
* Limit secret exposure to required contexts only.

---

### Automation Considerations

* Always validate JSON `error` field.
* Use `from_env` during initial migration.
* Avoid `expose_value=true` in automated logs.
* Automate rotation with cron or pipeline tasks.
* Use consistent naming conventions.

---

### CI/CD Integration

Typical workflow:

1. Import secrets from environment:

   ```
   secret://local/app/db/password.set(from_env="DB_PASSWORD")
   ```
2. Validate existence:

   ```
   secret://local/app/db/password.get(redact=true)
   ```
3. Rotate on schedule:

   ```
   secret://local/app/db/password.rotate
   ```
4. Reload dependent services.

---

### Production Environment Recommendations

* Enforce minimum 256-bit random secrets.
* Use RSA 2048+ for asymmetric keys.
* Document rotation policies.
* Maintain separate secret scopes per environment.
* Audit secret inventory regularly.
* Avoid environment variable leakage.

---

## 7. Use Cases by Role

### DevOps Engineers

* Inject secrets into deployment pipelines.
* Manage environment-specific credentials.
* Automate secret rotation workflows.
* Secure application configuration.

---

### SRE Engineers

* Audit secret existence and usage.
* Rotate compromised credentials.
* Validate encryption compliance.
* Ensure redacted logging in production.

---

### Network Administrators

* Manage TLS private keys.
* Secure API tokens.
* Rotate access credentials.
* Validate secret storage integrity.

---

### AI / Automation Engineers

* Interpret structured secret metadata.
* Detect missing or misconfigured secrets.
* Trigger remediation workflows.
* Validate compliance policies programmatically.

---

## 8. Technical Foundation

### Rust Implementation Advantages

resh is implemented in Rust, providing:

* Memory safety
* Strong type guarantees
* Deterministic argument parsing
* Secure file I/O handling

---

### Type Safety

* Enumerated verbs
* Strict parameter validation
* Explicit scope enforcement
* Structured error modeling

---

### Performance Characteristics

* Efficient encrypted file operations
* Atomic writes
* Minimal JSON serialization overhead
* Fast prefix-based secret listing

---

### Cross-Platform Architecture

* OS-aware storage path resolution
* Consistent JSON output
* Scope abstraction layer
* Explicit unsupported-scope signaling
