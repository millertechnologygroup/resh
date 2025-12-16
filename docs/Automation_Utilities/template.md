# template:// Handle

The `template://` handle provides template rendering, validation, and testing using the Tera template engine. This handle supports both file-based and inline templates with dynamic data injection.

## Overview

The template handle follows a simple pattern:

```
template://path/to/file.ext.verb(arguments)
```

or for inline templates:

```
template://inline.verb(arguments)
```

The handle supports three main operations (verbs):
- **render** - Render a template with provided data
- **validate** - Validate template syntax and data requirements
- **test** - Run automated tests against templates

## Template Engine

All templates use the **Tera template engine**, which provides:
- Variable substitution: `{{ variable }}`
- Control structures: `{% if %}`, `{% for %}`, `{% block %}`
- Filters and functions
- Template inheritance
- Strict or permissive variable handling

## Verbs

### template://…render

Renders a template with provided context data and outputs the result.

**Required Arguments:**
- Either a template file path in URL or `template` argument for inline content

**Optional Arguments:**
- `template` - Inline template content (alternative to file path)
- `context` - JSON string containing template variables
- `context_file` - Path to JSON file containing template variables
- `format` - Output format: "text", "html", "json", "bytes" (default: "text")

**Examples**

Inline template rendering:
```sh
template://inline.render(template="Hello {{ name }}", context="{\"name\":\"world\"}")
```

File template with context file:
```sh
template://greeting.html.render(context_file="/data/context.json")
```

JSON output format:
```sh
template://config.json.render(context="{\"port\":8080}", format="json")
```

**Output**

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

**Error Output Example**

```json
{
  "ok": false,
  "engine": "tera",
  "template": {
    "source": "file", 
    "name": "missing.html",
    "path": "missing.html"
  },
  "context": {
    "keys": [],
    "raw": {}
  },
  "body": null,
  "errors": [
    {
      "kind": "template_not_found",
      "message": "failed to read template file 'missing.html': No such file or directory"
    }
  ]
}
```

### template://…validate

Validates template syntax and checks if all required variables are available in the provided context.

**Required Arguments:**
- Either a template file path in URL or template content

**Optional Arguments:**
- `template` - Inline template content (alternative to file path)
- `context` - JSON string containing template variables for validation
- `strict` - Whether to treat missing variables as errors (default: true)

**Examples**

Basic syntax validation:
```sh
template://welcome.html.validate()
```

Validate with context data:
```sh
template://user-profile.html.validate(context="{\"user\":{\"name\":\"alice\"}}")
```

Non-strict validation (warnings instead of errors):
```sh
template://partial.html.validate(context="{}", strict="false")
```

**Output**

```json
{
  "ok": true,
  "template": {
    "source": "file",
    "name": "welcome.html", 
    "path": "welcome.html",
    "size": 156
  },
  "strict": true,
  "errors": [],
  "warnings": []
}
```

**Error Output Example**

```json
{
  "ok": false,
  "template": {
    "source": "inline",
    "name": "inline",
    "size": 20
  },
  "strict": true,
  "errors": [
    {
      "kind": "missing_variable",
      "message": "Missing variable: Variable `user` not found in context while rendering 'validate_template'"
    }
  ],
  "warnings": []
}
```

### template://…test

Runs automated tests against a template using predefined test cases.

**Required Arguments:**
- Template file path in URL

**Optional Arguments:**
- `cases` - JSON array of test cases inline
- `cases_file` - Path to JSON file containing test cases
- `stop_on_first_fail` - Stop testing on first failure (default: false)
- `capture_output` - Output capture mode: "none", "summary", "full" (default: "summary")

**Test Case Format:**
Test cases are JSON arrays containing objects with:
- `name` - Test case name
- `context` - Variables to use for rendering
- `expected` - Exact expected output (optional)
- `contains` - String that must be present in output (optional)
- `not_contains` - String that must NOT be present in output (optional)

**Examples**

Run default tests (looks for `template.tests.json`):
```sh
template://hello.html.test()
```

Run tests with inline cases:
```sh
template://greeting.html.test(cases="[{\"name\":\"basic\",\"context\":{\"user\":\"alice\"},\"expected\":\"Hello alice!\"}]")
```

Run tests from external file:
```sh
template://complex.html.test(cases_file="test-cases.json", stop_on_first_fail="true")
```

**Output**

```json
{
  "template": "hello.html",
  "ok": true,
  "total": 2,
  "passed": 2,
  "failed": 0,
  "stop_on_first_fail": false,
  "cases": [
    {
      "name": "basic",
      "ok": true,
      "expected": "Hello Alice!",
      "rendered": null
    },
    {
      "name": "contains_only", 
      "ok": true,
      "contains": "Bob"
    }
  ]
}
```

**Failed Test Output Example**

```json
{
  "template": "complex.html",
  "ok": false,
  "total": 3,
  "passed": 2,
  "failed": 1,
  "stop_on_first_fail": false,
  "cases": [
    {
      "name": "good_case",
      "ok": true
    },
    {
      "name": "failing_case",
      "ok": false,
      "error": "expected output mismatch",
      "expected": "Expected text",
      "rendered": "Actual output",
      "diff": "Expected: \"Expected text\", Got: \"Actual output\""
    },
    {
      "name": "another_good_case", 
      "ok": true
    }
  ]
}
```

## Data Sources

Templates can receive data from multiple sources, with the following precedence:

1. **Inline context** - `context` parameter (highest priority)
2. **Context file** - `context_file` parameter
3. **URL parameters** - Individual parameters from the URL

### Context File Formats

The handle supports JSON context files:

```json
{
  "user": {
    "name": "Alice",
    "email": "alice@example.com"
  },
  "environment": "production",
  "features": ["auth", "api", "web"]
}
```

## Output Formats

The render verb supports different output formats:

- **text** (default) - Plain text output
- **html** - HTML content (same as text but semantically labeled)
- **json** - Parses rendered output as JSON and returns structured data
- **bytes** - Returns base64-encoded binary data

## Error Handling

When operations fail, the handle returns structured error information:

**Common Error Types:**
- `template_not_found` - Template file does not exist
- `context_parse` - Invalid JSON in context data
- `syntax` - Template syntax errors
- `missing_variable` - Required variables not found in context
- `render` - Template rendering failures
- `json_parse` - Invalid JSON in rendered output (format=json)

## Template Testing

### Test File Convention

For a template file `hello.html`, the default test file is `hello.tests.json`:

```json
[
  {
    "name": "basic_greeting",
    "context": {"user": "Alice"},
    "expected": "Hello Alice!"
  },
  {
    "name": "contains_username", 
    "context": {"user": "Bob"},
    "contains": "Bob"
  },
  {
    "name": "no_admin_content",
    "context": {"user": "guest", "role": "user"},
    "not_contains": "admin"
  }
]
```

### Test Assertion Types

1. **Exact Match** - `expected`: Output must match exactly
2. **Contains** - `contains`: Output must include the specified string
3. **Not Contains** - `not_contains`: Output must NOT include the specified string

## Best Practices

1. **Use validation during development** to catch template errors early
2. **Write comprehensive tests** covering different data scenarios
3. **Use strict mode** in production to catch missing variables
4. **Separate complex data** into context files for maintainability
5. **Use meaningful test case names** for easier debugging
6. **Test edge cases** like empty data, missing fields, and special characters

## Common Use Cases

### Configuration File Generation
```sh
template://config.yaml.render(context_file="/deployment/vars.json")
```

### Email Template Processing
```sh
template://welcome-email.html.render(context="{\"user\":{\"name\":\"John\",\"email\":\"john@example.com\"}}", format="html")
```

### Template Development Workflow
```sh
# 1. Validate syntax
template://new-template.html.validate()

# 2. Test with sample data  
template://new-template.html.validate(context="{\"test\":\"data\"}")

# 3. Run automated tests
template://new-template.html.test()

# 4. Render final output
template://new-template.html.render(context_file="production-data.json")
```

### Inline Template Quick Testing
```sh
template://inline.render(template="Hello {{ name }}", context="{\"name\":\"World\"}")
```

## Template Syntax Reference

The handle uses Tera template syntax:

- **Variables**: `{{ variable_name }}`
- **Conditionals**: `{% if condition %}...{% endif %}`
- **Loops**: `{% for item in items %}...{% endfor %}`
- **Filters**: `{{ name | upper }}`
- **Comments**: `{# This is a comment #}`

For complete Tera syntax documentation, visit: https://tera.netlify.app/