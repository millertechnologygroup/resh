# Resource Shell (resh) – HTTP Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that expresses infrastructure operations using structured URI-based commands. The HTTP handle enables HTTP and HTTPS interactions through typed verbs and structured responses.

### Purpose

resh provides deterministic HTTP interactions by:

* Exposing HTTP methods as explicit verbs
* Enforcing structured parameter definitions
* Supporting structured JSON response envelopes
* Returning predictable status behavior

It replaces ad-hoc `curl`-style string invocation with a structured execution model.

### Architectural Problem Addressed

Traditional HTTP command-line tools:

* Rely on textual output
* Mix headers, body, and metadata
* Require manual parsing
* Depend on implicit behavior and flags

This introduces automation fragility when:

* Response formats change
* Headers must be parsed manually
* Error handling depends on text inspection

resh addresses this by:

* Defining HTTP verbs explicitly
* Structuring responses (especially via `json`, `headers`, `head`, `options`)
* Providing consistent parameter handling
* Returning structured JSON when required

### Resource-Oriented URI Model

resh HTTP commands follow:

```
handle://target.verb(options)
```

For HTTP:

* **handle**: `http://` or `https://`
* **target**: Host, port, and path
* **verb**: HTTP method abstraction (`get`, `post`, `json`, etc.)
* **options**: Structured parameters (headers, body, timeout, etc.)

Example:

```
https://api.example.com/users.get(query="active=true",accept="json")
```

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

* Each HTTP method is exposed as a verb.
* Parameters are defined and validated.
* Responses are controlled via `accept` modes.
* Structured envelope verbs (`json`, `headers`, `head`) provide machine-readable metadata.

This models HTTP operations as typed resource interactions.

---

### Safety-First Execution

* Non-2xx responses (for most verbs) exit with non-zero status.
* Timeout behavior is explicitly configurable.
* JSON parsing failures produce command failure.
* HTTPS validation is enabled by default.

This prevents silent failure in automation pipelines.

---

### Deterministic Behavior

* Identical inputs produce consistent structured outputs.
* Headers are normalized.
* Binary and text modes are explicitly selectable.
* Parameter precedence rules are defined (e.g., `body_file` overrides `body`).

---

### JSON-Based Structured Output

resh supports:

* `accept="json"` for parsed JSON responses
* `json` verb for structured response envelopes
* `headers` verb for header-only structured output
* `head` and `options` structured metadata output

Structured envelope example:

```json
{
  "status": 200,
  "status_text": "OK",
  "url": "https://api.example.com/test",
  "body": {
    "type": "json",
    "value": {
      "ok": true,
      "value": 42
    }
  }
}
```

---

### AI-Readiness

Structured response envelopes:

* Expose HTTP metadata
* Preserve header arrays
* Provide explicit status codes
* Eliminate natural-language parsing

This enables automated reasoning over HTTP responses.

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
handle://target.verb(options)
```

| Component | Description                |
| --------- | -------------------------- |
| `handle`  | `http://` or `https://`    |
| `target`  | Host, port, and path       |
| `verb`    | HTTP operation abstraction |
| `options` | Structured parameters      |

---

### Supported HTTP Verbs

| Verb        | Description                         |
| ----------- | ----------------------------------- |
| `get`       | Retrieve resource                   |
| `head`      | Retrieve headers only               |
| `post`      | Create resource                     |
| `put`       | Create or replace resource          |
| `patch`     | Partial update                      |
| `delete`    | Remove resource                     |
| `options`   | Discover allowed methods            |
| `preflight` | CORS preflight request              |
| `json`      | Structured JSON envelope request    |
| `headers`   | Retrieve headers as structured JSON |

---

### Production Examples

#### Basic GET

```
http://api.internal.local/health.get
```

#### GET with JSON Mode

```
http://api.internal.local/metrics.get(accept="json")
```

#### POST with JSON Body

```
http://api.internal.local/users.post(
  body="{\"name\":\"alice\"}",
  content_type="application/json",
  accept="json"
)
```

#### PUT with File Upload

```
http://127.0.0.1:8080/upload.put(
  body_file="/tmp/data.bin",
  accept="text"
)
```

#### DELETE with JSON Response

```
http://api.internal.local/item.delete(query="force=true",accept="json")
```

#### HEAD Request

```
http://api.internal.local/status.head
```

#### OPTIONS Request

```
http://api.internal.local/resource.options
```

#### CORS Preflight

```
http://api.internal.local/resource.preflight(
  origin="https://app.example.com",
  method="POST",
  request_headers="X-Auth-Token"
)
```

#### Structured JSON Envelope

```
http://api.internal.local/data.json(method="GET",accept="json")
```

---

### Common Parameters

| Parameter        | Description                                   |
| ---------------- | --------------------------------------------- |
| `headers`        | Custom headers (`Header:value;Header2:value`) |
| `query`          | Query string parameters                       |
| `accept`         | `json`, `text`, `bytes`                       |
| `timeout_ms`     | Request timeout                               |
| `allow_insecure` | Allow invalid HTTPS certificates              |
| `body`           | Inline body content                           |
| `body_file`      | File body (overrides `body`)                  |
| `content_type`   | Content-Type header                           |

---

### 3.2 Execution Semantics

#### Deterministic Behavior

* Explicit parameter precedence (`body_file` > `body`)
* Explicit accept mode
* Explicit timeout handling

---

#### Structured Output Contracts

Structured verbs (`head`, `options`, `json`, `headers`, `preflight`) return JSON envelopes with:

* `status`
* `ok`
* `headers`
* `url`
* `body` (when applicable)

---

#### Error Handling Structure

* Most verbs exit non-zero for non-2xx responses.
* Response body is still emitted.
* Timeout produces failure.
* Invalid JSON (when `accept="json"`) produces failure.

---

### Representative Structured Response

```json
{
  "status": 204,
  "reason": "No Content",
  "allowed_methods": ["GET", "POST", "OPTIONS"],
  "headers": {
    "allow": "GET, POST, OPTIONS"
  },
  "url": "http://api.internal.local/resource"
}
```

---

## 4. Functional Domains

### 4.1 Automation Utilities

**Scope**

HTTP-based automation for service orchestration and integration.

**Use Cases**

* Deployment validation
* Health checks
* Service integration testing

---

### 4.2 Data & State Management

**Scope**

Retrieving and modifying API-backed state via REST endpoints.

**Example**

```
http://api.internal.local/config.get(accept="json")
```

---

### 4.3 Filesystem & Storage

**Scope**

Uploading and retrieving binary data via HTTP.

**Example**

```
http://storage.internal/upload.put(body_file="/tmp/archive.tar",accept="text")
```

---

### 4.4 Network & Remote Operations

**Scope**

HTTP and HTTPS communication with remote services.

**Supported Handles**

* `http://`
* `https://`

**Use Cases**

* API validation
* Service status checks
* CORS diagnostics
* Header inspection
* REST automation

---

### 4.5 Packages & Software

HTTP can be used for:

* Artifact retrieval
* Repository access
* Package metadata inspection

---

### 4.6 Process & Service Management

HTTP health endpoints allow:

* Service readiness checks
* Liveness validation
* Operational diagnostics

---

### 4.7 Security & Secrets

* HTTPS enabled
* Certificate validation by default
* Optional `allow_insecure="true"` for development
* Support for authentication via headers

---

### 4.8 System Information

Structured access to:

* Response headers
* Allowed HTTP methods
* CORS policies
* Status metadata

---

## 5. Platform Support

The documentation does not define OS-specific limitations.

HTTP operations depend on:

* Network connectivity
* TLS support for HTTPS
* Valid DNS resolution

No platform-specific restrictions are specified.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Avoid `allow_insecure="true"` in production.
* Use explicit `timeout_ms` in automation.
* Validate response status via structured output.
* Handle non-2xx exits in CI pipelines.

---

### Automation Considerations

* Prefer `accept="json"` when consuming APIs.
* Use `json` verb for structured envelope with metadata.
* Use `headers` verb when only header metadata is required.
* Use `head` for lightweight availability checks.

---

### CI/CD Integration

Recommended pattern:

1. `head` for quick readiness.
2. `get(accept="json")` for health endpoint validation.
3. `post` or `put` for deployment triggers.
4. `delete` for cleanup.

---

### Production Recommendations

* Enforce HTTPS.
* Set appropriate timeout values.
* Avoid parsing raw text responses.
* Use structured envelope verbs for decision logic.

---

## 7. Use Cases by Role

### DevOps Engineers

* Automate deployment validation.
* Validate REST APIs in pipelines.
* Inspect CORS configuration.

---

### SRE Engineers

* Monitor service health endpoints.
* Validate allowed methods via `options`.
* Inspect response headers programmatically.

---

### Network Administrators

* Test endpoint availability.
* Validate CORS headers.
* Inspect TLS behavior.

---

### AI / Automation Engineers

* Consume structured JSON envelopes.
* Implement conditional logic based on `status`.
* Analyze header metadata.
* Integrate HTTP automation with orchestration systems.

---

## 8. Technical Foundation

### Rust Implementation Advantages

resh is implemented in Rust, providing:

* Memory safety
* Strong type guarantees
* Predictable binary execution behavior

---

### Type Safety

* Parameter validation
* Enumerated verb definitions
* Explicit accept modes
* Controlled output formats

---

### Performance Characteristics

* Native binary execution
* Efficient request handling
* Configurable timeouts

---

### Cross-Platform Architecture

* CLI-based execution
* Network-dependent behavior
* Structured output consistent across environments


