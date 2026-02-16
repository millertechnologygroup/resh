# Resource Shell (resh) – Mail Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that expresses infrastructure operations using structured URI-based commands. The `mail://` handle provides SMTP-based email operations including message delivery, template rendering, connection testing, and profile management.

### Purpose

The mail handle enables:

* Structured email delivery via SMTP
* Deterministic SMTP connection testing
* Template-based email rendering
* Profile-based SMTP configuration management
* Structured JSON response envelopes for automation

It replaces ad-hoc email scripting with a typed, structured execution model.

### Architectural Problem Addressed

Traditional CLI-based email tools:

* Rely on text-based output
* Provide inconsistent exit behavior
* Require manual SMTP configuration
* Lack structured response metadata

In automation contexts, this leads to:

* Weak error handling
* Parsing ambiguity
* Hidden authentication failures
* Inconsistent retry logic

resh addresses this by:

* Defining explicit mail verbs
* Enforcing parameter validation
* Returning structured JSON responses
* Providing standardized error codes

### Resource-Oriented URI Model

Mail commands follow:

```
handle://target.verb(options)
```

For mail:

* **handle**: `mail://`
* **target**: implicit for most verbs
* **verb**: `send`, `send_template`, `test`, `config`
* **options**: structured parameters

Example:

```
mail://send to="user@example.com" subject="Test" text_body="Hello"
```

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

* Email operations are defined as explicit verbs.
* SMTP parameters are explicitly declared.
* Profiles are managed via a configuration interface.
* Output is structured and machine-readable.

---

### Safety-First Execution

* Required fields (recipients, subject, body) are validated.
* TLS mode must be explicitly selected.
* Authentication failures return defined error codes.
* `dry_run` allows template validation without sending.
* Retry logic is configurable.

---

### Deterministic Behavior

* Defined parameter precedence.
* Structured retry behavior.
* Explicit timeout handling.
* Controlled exit status based on success or failure.

---

### JSON-Based Structured Output

All verbs can return structured JSON:

* `ok` success indicator
* `timestamp_unix_ms`
* `query` metadata
* `result` or operation-specific fields
* `error`
* `warnings`

This enables reliable programmatic consumption.

---

### AI-Readiness

Because output is structured:

* AI agents can detect delivery status.
* SMTP authentication state is explicit.
* Template rendering output is inspectable.
* Error codes are stable and machine-readable.

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
handle://target.verb(options)
```

| Component | Description                               |
| --------- | ----------------------------------------- |
| `handle`  | `mail://`                                 |
| `target`  | Implicit                                  |
| `verb`    | `send`, `send_template`, `test`, `config` |
| `options` | Structured parameters                     |

---

### Supported Verbs

| Verb            | Description                                         |
| --------------- | --------------------------------------------------- |
| `send`          | Send email with custom content                      |
| `send_template` | Send email using template rendering                 |
| `test`          | Test SMTP connection and optionally send test email |
| `config`        | Manage SMTP profiles                                |

---

### Production Examples

#### Send Email

```
mail://send 
  to="user@example.com"
  subject="Deployment Complete"
  text_body="Release finished successfully"
  smtp_host="smtp.internal.local"
  smtp_port=587
  use_tls="starttls"
```

---

#### Send Template (Dry Run)

```
mail://send_template
  template="welcome"
  to="user@example.com"
  vars='{"user_name":"Alice"}'
  dry_run=true
  format_output="json"
```

---

#### Test SMTP Connection

```
mail://test
  smtp_host="smtp.internal.local"
  smtp_port=587
  use_tls="starttls"
  connection_only=true
```

---

#### Create SMTP Profile

```
mail://config
  action="set"
  profile="production"
  smtp_host="smtp.example.com"
  smtp_port=587
  use_tls="starttls"
  smtp_username="user@example.com"
  smtp_password="password"
  from="noreply@example.com"
```

---

### 3.2 Execution Semantics

### Deterministic Behavior

* Required parameters enforced.
* Retry behavior controlled via:

  * `max_retry`
  * `retry_backoff_ms`
* Timeout controlled via `timeout_ms`.
* SMTP TLS behavior explicitly configured.

---

### Structured Output Contracts

All responses include:

* `ok`
* `timestamp_unix_ms`
* `query`
* Operation-specific sections
* `error`
* `warnings`

---

### Representative JSON Response (Send)

```json
{
  "ok": true,
  "timestamp_unix_ms": 1672531200000,
  "query": {
    "to": ["user@example.com"],
    "subject": "Deployment Complete"
  },
  "result": {
    "message_id": "12345",
    "smtp_host": "smtp.internal.local",
    "smtp_port": 587,
    "attempts": 1,
    "last_response": "250 OK: queued as 12345"
  },
  "error": null,
  "warnings": []
}
```

---

### Representative JSON Response (Connection Test)

```json
{
  "ok": true,
  "connection": {
    "smtp_host": "smtp.internal.local",
    "smtp_port": 587,
    "use_tls": "starttls",
    "tls_established": true,
    "auth_attempted": true,
    "auth_succeeded": true,
    "attempts": 1
  }
}
```

---

### Error Handling Structure

Defined error codes include:

#### Send Errors

* `mail.send_missing_recipients`
* `mail.send_missing_subject`
* `mail.send_missing_body`
* `mail.send_smtp_auth_failed`
* `mail.send_smtp_rejected`

#### Test Errors

* `mail.test_connection_failed`
* `mail.test_auth_failed`
* `mail.test_invalid_timeout`

#### Config Errors

* `mail.config_invalid_action`
* `mail.config_profile_not_found`
* `mail.config_no_active_profile`

#### Template Errors

* `mail.send_template_missing_var`
* `mail.send_template_render_error`

Errors are structured and machine-readable.

---

## 4. Functional Domains

### 4.1 Automation Utilities

**Scope**

Structured notification and messaging workflows.

**Use Cases**

* CI/CD pipeline alerts
* Deployment notifications
* Incident escalation emails
* Automated reporting

---

### 4.2 Data & State Management

**Scope**

Template rendering and structured metadata output.

**Use Cases**

* Template-based dynamic email generation
* Environment-aware messaging
* Localization via `locale`

---

### 4.3 Filesystem & Storage

**Scope**

Attachment handling via file path references.

**Example**

```
mail://send 
  to="ops@example.com"
  subject="Logs"
  text_body="Attached logs"
  attachments='["/var/log/app.log"]'
```

---

### 4.4 Network & Remote Operations

**Scope**

SMTP-based remote communication.

**Capabilities**

* TLS encryption modes:

  * `"none"`
  * `"starttls"`
  * `"tls"`
* Certificate validation control
* Retry and timeout handling

---

### 4.5 Packages & Software

Not defined in provided documentation.

---

### 4.6 Process & Service Management

Used indirectly for:

* Operational status notifications
* Service failure alerts
* Deployment reporting

---

### 4.7 Security & Secrets

**Scope**

* SMTP authentication
* TLS configuration
* Certificate validation control
* Profile-based credential management

Security-related parameters:

* `smtp_username`
* `smtp_password`
* `use_tls`
* `tls_accept_invalid_certs`

---

### 4.8 System Information

Structured reporting includes:

* SMTP host
* TLS state
* Authentication result
* Retry attempts
* SMTP response codes

---

## 5. Platform Support

The documentation does not specify OS-level limitations.

Mail functionality requires:

* Network connectivity
* Access to SMTP server
* TLS support (if enabled)

No platform-specific restrictions are defined.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Always validate configuration using `test` before sending production emails.
* Use `dry_run=true` for template verification.
* Avoid `tls_accept_invalid_certs=true` in production.
* Store SMTP credentials securely.

---

### Automation Considerations

* Consume JSON output in automation.
* Handle structured error codes.
* Configure retry logic for transient SMTP failures.
* Explicitly define `timeout_ms` for CI pipelines.

---

### CI/CD Integration

Typical workflow:

1. Validate SMTP profile using `test`.
2. Send deployment notification using `send`.
3. Use template-based structured messages for consistency.
4. Capture `message_id` for audit logging.

---

### Production Environment Recommendations

* Use `starttls` or `tls` encryption.
* Use authenticated SMTP.
* Manage credentials through profiles.
* Monitor retry counts.
* Validate certificate handling.

---

## 7. Use Cases by Role

### DevOps Engineers

* Deployment success/failure notifications.
* Release reporting.
* Automated email alerts in pipelines.

---

### SRE Engineers

* Incident notification.
* Escalation workflows.
* Monitoring failure alerts.

---

### Network Administrators

* Validate SMTP connectivity.
* Test TLS configuration.
* Confirm authentication behavior.

---

### AI / Automation Engineers

* Inspect structured delivery results.
* Automate retry logic.
* Integrate structured template rendering.
* Trigger workflows based on SMTP success state.

---

## 8. Technical Foundation

### Rust Implementation Advantages

resh is implemented in Rust, providing:

* Memory safety
* Strong type enforcement
* Deterministic execution
* Efficient networking behavior

---

### Type Safety

* Parameter validation
* Enumerated TLS modes
* Defined error codes
* Structured response schema

---

### Performance Characteristics

* Native binary execution
* Configurable timeouts
* Configurable retry behavior
* Efficient SMTP handling

---

### Cross-Platform Architecture

* CLI-based execution
* Network-dependent behavior
* Consistent JSON output across environments


