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
* `<verb>` is `render`, `validate` or `test`. Any other verb fails with `Error: [template.unknown_verb] unknown verb: <verb>` and exit status 2.

---

## 2. Design Notes

* Each template is compiled on its own. `{% extends %}`, `{% include %}` and `{% import %}` of other template files are not supported, because no other templates are loaded.
* Tera's built-in functions are available, including `get_env`, which reads environment variables of the `resh` process (`{{ get_env(name="HOME") }}`). Do not render untrusted templates.
* Every verb takes `timeout_ms` (milliseconds; 0, the default, means no limit). Rendering runs on a worker thread; if it has not finished in time the verb reports an error of kind `timeout` and exits 124. The abandoned render ends with the process.
* Every argument is checked before the template or context is read. An argument the verb does not take, a boolean that is not one of `true/false`, `1/0`, `yes/no`, `on/off`, an unknown `format`, `capture_output` or `encoding`, or a `timeout_ms` that is not a non-negative integer is reported (kind `invalid_argument`, or `invalid_format` / `encoding`) with exit code 2. A misspelled argument name gets a hint such as ``(did you mean `context`?)``.
* Exit codes follow the resh convention: 0 success, 1 the operation failed, 2 invalid usage (nothing was done), 124 timeout. The error code tells failures with the same exit code apart.
* Every failure is reported on stderr as `Error: [<code>] <message>` and, in the JSON result, as `"error": {"code": "<code>", "message": "..."}`. For `render` and `validate` the code is `template.<kind>` for the first error's `kind`. All codes are listed in [3.4 Error codes](#34-error-codes).
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

On failure `ok` is `false`, `body` is absent, `errors` holds objects with `kind` and `message`, and `error` holds the code and message of the failure (`{"code": "template.<kind>", "message": "..."}`):

| Exit | Error kinds |
| ---- | ----------- |
| 1    | `template_not_found` (the named file is missing), `io` (template or `context_file` unreadable), `context_parse` (invalid JSON or not an object), `render` (a template parse or render error; the message includes Tera's causes, for example ``Variable `name` not found in context``), `json_parse` (`format=json` and the rendered text is not JSON) |
| 2    | `invalid_argument`, `invalid_format`, `template_not_found` for `template://inline` with no `template` or `from` argument |
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
  "warnings": [],
  "error": { "code": "template.missing_variable", "message": "Missing variable: Variable `name` not found in context while rendering 'validate_template'" }
}
```

Error kinds: `file_read` (template or `context_file` unreadable), `context_parse`, `syntax`, `missing_variable`, `render` exit with status 1; `invalid_argument`, `encoding`, and `file_read` for `template://inline` with no template argument exit 2; `timeout` exits 124.

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

Exit status: 0 when every case passes; 1 when a case fails, the case list is empty, the template file is missing, `cases_file` or the default `.tests.json` file cannot be read or parsed, or the template does not compile (`tera_parse_failed`); 2 for an invalid argument, no template given, no cases given, or `cases=` that is not a JSON case list; 124 when `timeout_ms` passes. On failure `error` is `{"code", "message"}`: `template.tests_failed` when a case fails (message `<n> of <total> test cases failed`), `template.timeout` on a timeout (the message says how many of the supplied cases ran, and `cases` holds the cases that finished), and the setup error otherwise (`template.template_not_found`, `template.no_test_cases`, `template.invalid_cases`, `template.tera_parse_failed`, `template.invalid_argument`) with `ok: false`. A failing case's own `error` field is a plain message.

---

### 3.4 Error codes

| Code                          | Exit | Verbs | Meaning |
| ----------------------------- | ---- | ----- | ------- |
| `template.invalid_argument`   | 2    | all   | An argument the verb does not take (with a "did you mean" hint), a bad boolean, `capture_output` or `timeout_ms` |
| `template.invalid_format`     | 2    | render | `format` is not `text`, `html`, `json` or `bytes` |
| `template.encoding`           | 2    | validate | `encoding` is not supported |
| `template.template_not_found` | 1 (2 for `template://inline` with no `template`/`from`) | render, test | The template file is missing, or no template was given |
| `template.io`                 | 1    | render | The template or `context_file` cannot be read |
| `template.file_read`          | 1 (2 with no template given) | validate | The template or `context_file` cannot be read, or no template was given |
| `template.context_parse`      | 1    | render, validate | The context is not valid JSON or not an object |
| `template.syntax`             | 1    | validate | The template does not compile |
| `template.missing_variable`   | 1    | validate | Rendering needs a variable the context lacks (`strict=true`) |
| `template.render`             | 1    | render, validate | A template parse or render error (the message includes Tera's causes) |
| `template.json_parse`         | 1    | render | `format=json` and the rendered text is not JSON |
| `template.timeout`            | 124  | all   | `timeout_ms` passed |
| `template.no_test_cases`      | 2 (1 for an empty case list) | test | No cases were given and there is no `.tests.json` file, or the case list is empty |
| `template.invalid_cases`      | 2 (`cases=`) / 1 (files) | test | `cases=` is not a JSON case list, or `cases_file` / the `.tests.json` file cannot be read or parsed |
| `template.tera_parse_failed`  | 1    | test  | The template does not compile |
| `template.tests_failed`       | 1    | test  | At least one case failed |
| `template.unknown_verb`       | 2    | -     | The verb is not `render`, `validate` or `test` (also for help on an unknown verb) |

**Change note (breaking):** earlier versions printed a bare kind or phrase on stderr (for example `Error: render`, `Error: Template syntax error`, `Error: no_test_cases`), and `test` reported `error` as a plain string. Failures now print `Error: [template.<code>] <message>`, every failed result carries `"error": {"code", "message"}`, a bad `cases=` list or unreadable cases file is `template.invalid_cases` instead of `no_test_cases`, and help for an unknown verb exits 2 instead of 1. The `errors` array and its `kind` values are unchanged.

### 3.5 Limitations

* Macro calls may nest at most 200 levels deep. Tera itself has no recursion limit, so a macro that called itself without end used to overflow the stack and abort resh; resh now gives every macro a hidden depth argument, and a call past the limit fails the render with ``macro calls nested deeper than 200 levels`` (kind `render`, exit 1). Bounded recursion within the limit works as before.

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
