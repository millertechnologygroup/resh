# Resource Shell (resh) – Template Handle Documentation

## 1. Overview

Resource Shell (resh) is a structured command-line framework that standardizes system automation using a resource-oriented URI execution model.

The `template://` handle provides template rendering, validation, and testing capabilities using the Tera template engine. It supports both file-based and inline templates with dynamic data injection and structured output.

Traditional configuration generation and templating workflows often require:

* External scripting languages
* Unstructured output handling
* Separate validation tooling
* Custom test harnesses
* Manual variable checking

The `template://` handle addresses these limitations by:

* Providing a uniform URI-based interface
* Supporting structured JSON context injection
* Returning deterministic JSON responses
* Enabling built-in validation and automated testing

All template operations follow the URI model:

```
template://path/to/template.ext.verb(arguments)
template://inline.verb(arguments)
```

---

## 2. Design Philosophy and Core Principles

The `template://` handle adheres to resh design principles.

### Structured Interface Model

All template operations follow:

```
template://target.verb(arguments)
```

Where `target` is either:

* A file path to a template
* The reserved target `inline` for inline template content

This ensures consistent invocation semantics across render, validate, and test operations.

### Safety-First Execution

The handle supports:

* Strict variable validation
* Structured error reporting
* Deterministic output typing
* Explicit output format selection

These features reduce runtime configuration errors.

### Deterministic Behavior

All operations return structured JSON with:

* Explicit success indicator (`ok`)
* Structured error lists
* Defined output format metadata
* Template and context metadata

### JSON-Based Structured Output

Outputs are structured and machine-readable, enabling:

* CI/CD validation
* Configuration generation pipelines
* Automated regression testing
* Deterministic downstream parsing

### AI-Readiness

The deterministic grammar and structured response model allow template rendering to be safely invoked within automation agents and orchestration systems.

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
template://target.verb(arguments)
```

#### Components

| Component   | Description                            |
| ----------- | -------------------------------------- |
| `template`  | Handle identifier                      |
| `target`    | Template file path or `inline`         |
| `verb`      | `render`, `validate`, or `test`        |
| `arguments` | Named parameters controlling execution |

---

### Examples

Inline render:

```sh
template://inline.render(template="Hello {{ name }}", context="{\"name\":\"world\"}")
```

File render:

```sh
template://config.yaml.render(context_file="/data/vars.json")
```

Validate template:

```sh
template://email.html.validate()
```

Run tests:

```sh
template://newsletter.html.test()
```

---

### 3.2 Execution Semantics

All template operations return structured JSON envelopes.

#### Render Success Example

```json
{
  "ok": true,
  "engine": "tera",
  "template": {
    "source": "inline",
    "name": "inline",
    "size": 15
  },
  "context": {
    "keys": ["name"],
    "raw": {"name": "world"}
  },
  "body": {
    "type": "text",
    "value": "Hello world"
  },
  "errors": []
}
```

#### Validation Failure Example

```json
{
  "ok": false,
  "strict": true,
  "errors": [
    {
      "kind": "missing_variable",
      "message": "Missing variable: Variable `user` not found"
    }
  ],
  "warnings": []
}
```

Automation logic should evaluate the `ok` field and inspect `errors` and `warnings`.

---

## 4. Functional Domain – Template Handle

### Operational Scope

The `template://` handle supports:

* Rendering templates
* Syntax validation
* Strict variable validation
* Automated test execution
* Inline and file-based templates
* Multiple output formats

---

### Supported Verbs

#### render

Renders template content using Tera.

**Required:**

* Template file path OR `template` argument for inline content

**Optional:**

* `context` (JSON string)
* `context_file` (JSON file path)
* `format` (`text`, `html`, `json`, `bytes`)
* `encoding` (utf-8 supported)

---

#### validate

Validates template syntax and checks for missing variables.

**Optional:**

* `context`
* `strict` (default: true)

---

#### test

Executes defined test cases against a template.

**Optional:**

* `cases`
* `cases_file`
* `stop_on_first_fail`
* `capture_output`

---

### Template Engine

The handle uses the **Tera template engine**, supporting:

* Variable substitution: `{{ variable }}`
* Conditionals: `{% if %}`
* Loops: `{% for %}`
* Filters: `{{ name | upper }}`
* Template inheritance
* Comments: `{# comment #}`

---

### Data Sources

Data injection precedence:

1. Inline `context`
2. `context_file`
3. URL parameters

Context files must be valid JSON.

---

### Output Formats

| Format  | Description                    |
| ------- | ------------------------------ |
| `text`  | Plain text output              |
| `html`  | HTML-labeled output            |
| `json`  | Parses rendered output as JSON |
| `bytes` | Base64-encoded binary output   |

---

### Test Case Format

Test cases are JSON arrays with:

* `name`
* `context`
* `expected` (exact match)
* `contains`
* `not_contains`

---

### Common Error Types

* `template_not_found`
* `context_parse`
* `syntax`
* `missing_variable`
* `render`
* `json_parse`

---

## 5. Platform Support

The template handle operates within resh and supports:

| Platform   | Support   |
| ---------- | --------- |
| Linux      | Supported |
| Unix/macOS | Supported |
| Windows    | Supported |

Template compatibility depends on file system accessibility and JSON parsing capabilities.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Validate templates before rendering.
* Use strict mode in production.
* Test templates with representative data.
* Avoid embedding secrets directly in templates.

### Automation Considerations

* Use `format="json"` for structured output pipelines.
* Validate `ok` before consuming rendered output.
* Separate data into context files for maintainability.
* Use automated tests to prevent regression.

### CI/CD Integration

* Validate templates during build stages.
* Run `test` verb for configuration validation.
* Render configuration artifacts during deployment.
* Fail pipelines if `ok=false`.

### Production Recommendations

* Maintain version control of templates.
* Use explicit context files.
* Enforce strict validation.
* Log structured JSON outputs for auditing.

---

## 7. Use Cases by Role

### DevOps Engineers

* Generate environment-specific configuration files.
* Validate configuration prior to deployment.
* Automate manifest rendering during build pipelines.

### SRE Engineers

* Render runtime configuration safely.
* Validate templates during incident recovery.
* Test templates before applying changes.

### Network Administrators

* Generate network configuration files.
* Create templated firewall policies.
* Render device configuration templates.

### AI/Automation Engineers

* Integrate template rendering into orchestration agents.
* Use structured JSON output for downstream processing.
* Automate validation prior to execution workflows.

---

## 8. Technical Foundation

The `template://` handle operates within resh, implemented in Rust.

### Rust Implementation Advantages

* Memory safety
* Strong compile-time guarantees
* Deterministic binary execution

### Type Safety

Argument parsing and response construction are type-validated, reducing runtime ambiguity.

### Performance Characteristics

* Efficient template rendering
* Controlled error propagation
* Deterministic JSON serialization

### Cross-Platform Architecture

The template handle operates across:

* Linux
* macOS/Unix
* Windows

Functionality is dependent on file system access and JSON support.
