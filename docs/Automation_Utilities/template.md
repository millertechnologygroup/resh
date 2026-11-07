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
* Every verb takes `timeout_ms` (milliseconds; 0, the default, means no limit). Rendering runs on a worker thread; if it has not finished in time the verb reports an error of kind `timeout` and exits 124. The abandoned render ends with the process.
* Every argument is checked before the template or context is read. An argument the verb does not take, a boolean that is not one of `true/false`, `1/0`, `yes/no`, `on/off`, an unknown `format`, `capture_output` or `encoding`, or a `timeout_ms` that is not a non-negative integer is reported (kind `invalid_argument`, or `invalid_format` / `encoding`) with exit code 2.
* None has a dry-run mode, so `dry_run=true` is refused (exit 2). Rendering never writes files.
* A template path is relative to the current directory. A leading `..` is kept (`template://../x.txt` reads `../x.txt`); `a/..` inside the path cancels out.
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
| `context`      | JSON object. If both are given, `context` replaces `context_file` entirely (they are not merged) |
| `context_file` | Path of a JSON context file |
| `format`       | `text` (default), `html`, `json` (parse the rendered text as JSON into `body.value`) or `bytes` (base64 in `body.base64`). Other values give an `invalid_format` error (exit 2) before anything is rendered |
| `timeout_ms`   | Stop after this many milliseconds (0 = no limit, the default) |

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

On failure `ok` is `false`, `body` is absent and `errors` holds objects with `kind` and `message`:

| Exit | Error kinds |
| ---- | ----------- |
| 2    | `invalid_argument`, `invalid_format`, `template_not_found` (no template or missing file), `io` (template file unreadable) |
| 3    | `context_parse` (invalid JSON or not an object), `io` (`context_file` unreadable) |
| 4    | `render`: a template parse or render error. The message includes Tera's causes, for example ``Variable `name` not found in context`` |
| 5    | `json_parse` (`format=json` and the rendered text is not JSON) |
| 124  | `timeout` |

### 3.2 validate

Checks a template for syntax errors and, by rendering it with the given context, for render errors such as missing variables.

```bash
resh --json-pretty template://welcome.txt.validate 'context={"name":"alice"}'
resh template://welcome.txt.validate strict=false
resh template://inline.validate 'from=Hello {{ name }}'
```

| Argument   | Meaning |
| ---------- | ------- |
| `template` / `from` / `inline` | Template text instead of the file, in that order of precedence |
| `context`  | JSON context. If both are given, `context` replaces `context_file` |
| `context_file` | Path of a JSON context file |
| `strict`   | Default `true`. `false` (or `0`, `no`, `off`) reports missing variables in `warnings` and the command succeeds. A value that is not a boolean (such as `ture`) is refused with exit 2 |
| `encoding` | Only `utf-8` is accepted |
| `timeout_ms` | Stop after this many milliseconds (0 = no limit, the default) |

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

Error kinds: `file_read` (template or `context_file` unreadable), `context_parse`, `syntax`, `missing_variable`, `render` exit with status 1; `invalid_argument` and `encoding` exit 2; `timeout` exits 124.

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
| `stop_on_first_fail` | `true` stops after the first failing case (default `false`) |
| `capture_output`     | `summary` (default: include `rendered` only for failing cases), `full` (always), `none` (never). Other values are refused (exit 2) |
| `timeout_ms`         | Stop after this many milliseconds for the whole run (0 = no limit, the default) |

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

Exit status: 0 when every case passes; 1 when a case fails or the case list is empty; 2 for an invalid argument, a missing template, or missing or unreadable cases; 3 when the template does not compile; 124 when `timeout_ms` passes. On a timeout, `cases` holds the cases that finished and `error` says how many of the supplied cases ran. Setup errors set `ok: false` and an `error` message.

---

### 3.4 Limitations

* A template whose macros call themselves without end overflows the stack, and the process aborts (exit 134) before `timeout_ms` can stop it. Tera has no recursion limit.

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
