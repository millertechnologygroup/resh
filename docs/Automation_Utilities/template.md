# Resource Shell (resh) – Template Handle Documentation

## 1. Overview

Resource Shell (resh) is a command-line tool that runs operations on resources named by URLs and reports the results as JSON.

The `template://` handle renders, validates and tests text templates with the [Tera](https://keats.github.io/tera/) engine. Every verb prints one JSON object.

```text
resh template://<path>.<verb> key=value ...     template file, relative to the current directory
resh template://inline.<verb> key=value ...     template text passed as an argument
```

* `<path>` is a template file such as `welcome.txt` or `templates/nginx.conf`. The verb is the part after the last dot, so `template://nginx.conf.render` renders the file `nginx.conf`.
* `inline` (or an empty target) means there is no file; the template text comes from an argument.
* `<verb>` is `render`, `validate` or `test`. Any other verb fails with `Error: unknown verb: <verb>` and exit status 1.

---

## 2. Design Notes

* Each template is compiled on its own. `{% extends %}`, `{% include %}` and `{% import %}` of other template files are not supported, because no other templates are loaded.
* Tera's built-in functions are available, including `get_env`, which reads environment variables of the `resh` process (`{{ get_env(name="HOME") }}`). Do not render untrusted templates.
* None of the verbs read `timeout_ms`, which is ignored. None has a dry-run mode, so `dry_run=true` is refused (exit 2). Rendering never writes files.
* Context values come only from the `context` / `context_file` arguments (and, for `test`, each case's `context`). There are no other data sources.

---

## 3. Verbs

Per-verb help: `resh template <verb> --help`.

### 3.1 render

Renders a template with a JSON context.

```bash
resh --json-pretty template://welcome.txt.render 'context={"name":"alice"}'
resh template://inline.render 'template=Hello {{ name }}' 'context={"name":"world"}'
resh template://nginx.conf.render context_file=/srv/vars/prod.json
resh template://inline.render 'template={"port": {{ port }}}' 'context={"port":8080}' format=json
```

| Argument       | Meaning |
| -------------- | ------- |
| `template`     | Template text (takes precedence over the file) |
| `from`         | Template text, older spelling; used when `template` is absent |
| `context`      | JSON context. If both are given, `context` replaces `context_file` entirely (they are not merged) |
| `context_file` | Path of a JSON context file |
| `format`       | `text` (default), `html`, `json` (parse the rendered text as JSON into `body.value`) or `bytes` (base64 in `body.base64`). Other values give an `invalid_format` error |

Output for a file containing `Hello, {{ name }}!`:

```json
{
  "ok": true,
  "engine": "tera",
  "template": { "source": "file", "name": "welcome.txt", "path": "welcome.txt", "size": 18 },
  "context": { "keys": ["name"], "raw": { "name": "alice" } },
  "body": { "type": "text", "value": "Hello, alice!" },
  "errors": []
}
```

On failure `ok` is `false`, `body` is absent and `errors` holds objects with `kind` and `message`. Error kinds: `template_not_found`, `io`, `context_parse`, `render` (template parse or render error, including a missing variable; the message is Tera's top-level message, such as `Failed to render 'render_template'`, so use `validate` to see which variable is missing), `json_parse`, `invalid_format`. The process exits non-zero.

### 3.2 validate

Checks a template for syntax errors and, by rendering it with the given context, for render errors such as missing variables.

```bash
resh --json-pretty template://welcome.txt.validate 'context={"name":"alice"}'
resh template://welcome.txt.validate strict=false
resh template://inline.validate 'from=Hello {{ name }}'
```

| Argument   | Meaning |
| ---------- | ------- |
| `from`     | Template text (`inline=` is also accepted). **`template=` is not read by `validate`**: with only `template=`, validate reports `Failed to read template` |
| `context`  | JSON context (`context_file` is not read by `validate`) |
| `strict`   | Default `true`. When given, only the exact value `true` keeps strict mode; any other value (`false`, `no`, `0`, or a typo such as `ture`) turns it off. With strict off, missing variables are reported in `warnings` and the command succeeds |
| `encoding` | Only `utf-8` is accepted |

Output:

```json
{
  "ok": false,
  "template": { "source": "file", "name": "welcome.txt", "path": "welcome.txt", "size": 18 },
  "strict": true,
  "errors": [
    { "kind": "missing_variable", "message": "Missing variable: Variable `name` not found in context while rendering 'validate_template'" }
  ],
  "warnings": []
}
```

Error kinds: `file_read`, `encoding`, `context_parse`, `syntax`, `missing_variable`, `render`. On any error the command exits with status 1.

### 3.3 test

Renders a template once per test case and checks the result.

```bash
resh --json-pretty template://welcome.txt.test
resh template://welcome.txt.test cases_file=/srv/tests/welcome-cases.json stop_on_first_fail=true
resh template://inline.test 'template=Hi {{ n }}' 'cases=[{"name":"one","context":{"n":1},"expected":"Hi 1"}]'
```

| Argument             | Meaning |
| -------------------- | ------- |
| `template` / `from`  | Template text instead of the file |
| `cases`              | JSON array of test cases |
| `cases_file`         | File holding the JSON array |
| `stop_on_first_fail` | Exact value `true` stops after the first failing case |
| `capture_output`     | `summary` (default: include `rendered` only for failing cases), `full` (always), `none` (never) |

Without `cases` or `cases_file`, the cases are read from the file next to the template with the extension `.tests.json` (for `welcome.txt`, `welcome.tests.json`).

Each case has `name`, `context` (both required), and optionally `expected` (exact match), `contains` and `not_contains` (substring checks).

Output:

```json
{
  "template": "welcome.txt",
  "ok": true,
  "total": 1,
  "passed": 1,
  "failed": 0,
  "stop_on_first_fail": false,
  "cases": [ { "name": "alice", "ok": true, "expected": "Hello, alice!" } ]
}
```

A missing template or missing cases sets `ok: false`, an `error` message and exit status 2.

---

## 4. Platform Support

Only Linux is supported and verified.

---

## 5. Operational Notes

* Run `validate` (strict) before `render` in pipelines, and fail the job when `ok` is `false`.
* Keep context in JSON files (`context_file`) under version control alongside the templates.
* Use `test` with a `.tests.json` file next to each template to catch regressions.
* Do not put secrets in templates; note that `get_env` can read the environment.

---

## 6. Implementation

Written in Rust (`src/handles/automation/templateh.rs`) on the Tera 1.x engine.
