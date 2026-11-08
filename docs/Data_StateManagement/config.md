# Resource Shell (resh) – Config Handle Documentation

## 1. Overview

Resource Shell (resh) is a command-line tool that runs operations on resources named by URLs.

The `config://` handle stores JSON configuration values, one file per key, under the user's config directory:

```text
$XDG_CONFIG_HOME/resh/config/      (default ~/.config/resh/config/)
```

Values can be read (`get`), written (`set`), listed by prefix (`ls`) and watched for changes (`watch`). There is no delete verb; remove the key's file to delete it.

All operations use this form:

```text
resh config://[<namespace>/]<key>.<verb> [key=value ...]
```

* `config://app/db/url` names namespace `app` and key `db/url`, stored as `app/db/url.json`.
* A single segment such as `config://theme` uses the namespace `default`, stored as `default/theme.json`.

---

## 2. Design Notes

* `set` writes to a temporary file in the same directory, syncs it, and renames it into place, so a reader never sees a half-written value.
* `get` prints the stored JSON text exactly as saved, with no envelope.
* `set` prints nothing on success.
* On failure resh prints `Error: [<code>] <reason>` to stderr (for example `Error: [config.not_found] not found`); the codes are listed in [3.5 Error codes](#35-error-codes).
* There is no dry-run mode: `dry_run=true` is refused (exit 2) and nothing is done.
* Every argument is checked before anything is read or written. An argument the verb does not take (including `timeout_ms` on `get`, `set` and `ls`), a boolean that is not one of `true/false`, `1/0`, `yes/no`, `on/off`, or a number that does not parse is refused with exit code 2 and no side effect.

---

## 3. Command Syntax and Execution Model

### 3.1 URL structure

| Component   | Description                                                       |
| ----------- | ----------------------------------------------------------------- |
| `config`    | Handle scheme                                                     |
| `namespace` | First path segment; `default` when the URL has only one segment   |
| `key`       | The remaining segments, joined with `/`                           |
| `verb`      | `get`, `set`, `ls`, `watch`                                       |

### 3.2 Example commands

Store a string:

```bash
resh config://app/theme.set value=dark
```

Store a JSON object:

```bash
resh config://app/settings.set 'value={"timeout":30,"retries":3}'
```

Read a value:

```bash
resh config://app/theme.get
```

List a namespace recursively:

```bash
resh --json-pretty config://app.ls recursive=true
```

Watch the `db/` keys of the `app` namespace for ten seconds, printing current values first:

```bash
resh config://app/db.watch prefix=db/ initial=true timeout_ms=10000
```

### 3.3 Output

`get` prints the stored value:

```text
"dark"
```

`ls` (shown with `--json-pretty`):

```json
{
  "entries": [
    {
      "full_key": "app/db",
      "has_value": true,
      "key": "db",
      "kind": "branch",
      "meta": {}
    },
    {
      "full_key": "app/theme",
      "has_value": true,
      "key": "theme",
      "kind": "leaf",
      "meta": {
        "size": 6,
        "updated_at": "2026-10-16T09:12:44.512309817+00:00"
      }
    }
  ],
  "limit": null,
  "offset": 0,
  "pattern": null,
  "prefix": "app",
  "recursive": false
}
```

`watch` prints one JSON object per line:

```json
{"op":"set","scope":"app/db","key":"db/url","value":"postgres://db.example.com:5432/app","version":1,"ts":"2026-10-23T13:09:14.115023610+00:00","source":"config"}
```

### 3.4 Exit codes

These codes are set by the handle (verified in the source):

| Code | Meaning                                                                      |
| ---- | ---------------------------------------------------------------------------- |
| 0    | Success                                                                      |
| 1    | The operation failed: key not found; the stored file is not valid JSON; a file I/O error (reading a value, creating the key's directory, writing or renaming the value file, walking the directory for `ls`); `watch` cannot create or watch its directory |
| 2    | Invalid usage, nothing was done: empty key; `set` without `value`; `set raw=true` with invalid JSON; an unknown argument (with a "did you mean" hint for a likely typo); `timeout_ms` on `get`/`set`/`ls`; an unreadable boolean; an invalid `limit`, `offset`, `pattern`, `timeout_ms` or `max_events`; `watch` with both `key` and `prefix`; a target with a `.` or `..` segment; `dry_run=true`; an unknown verb |

The reason is printed on stderr as `Error: [<code>] <reason>` (see 3.5).

### 3.5 Error codes

Every failure printed by the handle carries one of these codes, in the project-wide format `Error: [config.<code>] <message>`:

| Code                          | Exit | Meaning |
| ----------------------------- | ---- | ------- |
| `config.not_found`            | 1    | `get`: the key has no stored value |
| `config.corrupt_value`        | 1    | `get`: the stored file is not valid JSON |
| `config.io_error`             | 1    | Reading a value, creating the key's directory, writing or renaming the value file, or walking the directory for `ls` failed |
| `config.serialization_failed` | 1    | `ls`: the listing could not be encoded as JSON |
| `config.watch_failed`         | 1    | `watch` cannot create or watch its directory |
| `config.invalid_argument`     | 2    | An unknown argument (with a "did you mean" hint), `timeout_ms` on `get`/`set`/`ls`, an unreadable boolean, an invalid `limit`, `offset`, `pattern`, `timeout_ms` or `max_events`, or `watch` with both `key` and `prefix` |
| `config.missing_argument`     | 2    | `set` without `value` |
| `config.invalid_json`         | 2    | `set raw=true` with a value that is not valid JSON |
| `config.invalid_target`       | 2    | An empty key for `get`/`set`, or a target with a `.` or `..` segment |
| `config.unknown_verb`         | 2    | The verb is not `get`, `set`, `ls` or `watch` |

`dry_run=true` is refused (exit 2) by resh before the handle runs, with a message saying the verb does not support dry_run.

**Change note (breaking):** earlier versions printed `Error: <reason>` with no code (for example `Error: not found`, `Error: invalid json`). Scripts that matched those lines must match the `[config.<code>]` prefix instead. Exit codes also changed to the shared 0/1/2/124 convention: I/O errors (were 3) and a corrupt stored value (was 2) now exit 1; usage errors such as `set` without `value` or an empty key (were 1) now exit 2.

---

## 4. Verbs

### 4.1 get

Prints the value stored for the key. Fails with "not found" if the key has no file, and with "invalid json" if the file does not hold valid JSON.

```bash
resh config://app/db/url.get
```

### 4.2 set

Stores `value=` for the key.

* Without `raw`, the value is parsed as JSON when possible (so `value=30` stores the number 30 and `value=true` the boolean), and otherwise stored as a JSON string (`value=dark` stores `"dark"`).
* With `raw=true`, the value must be valid JSON or the command fails with exit code 2 and the stored value is unchanged.
* Value files are written owner-only (mode 0600) and directories `set` creates are owner-only (0700). Rewriting an existing value replaces its file, so an older, more open file is tightened to 0600.
* If the write fails, the temporary file is removed and the command exits 1.

```bash
resh config://app/timeout.set value=30
resh config://app/flags.set 'value={"beta":true}' raw=true
```

To store text that looks like JSON as a string, quote it as JSON: `'value="30"'`.

### 4.3 ls

Lists the keys (`kind: "leaf"`) and sub-directories (`kind: "branch"`) under the URL's prefix, sorted by `full_key`. `config://.ls` lists the namespaces.

| Argument    | Description                                  | Default |
| ----------- | -------------------------------------------- | ------- |
| `recursive` | `true` to walk all levels                    | `false` |
| `pattern`   | Glob matched against key names               | none    |
| `limit`     | Maximum entries returned                     | all     |
| `offset`    | Entries to skip                              | 0       |

```bash
resh config://app.ls recursive=true 'pattern=*' limit=50
```

With `recursive=true` every descendant is listed (the prefix directory itself is not an entry). Any `recursive` value other than a boolean spelling is refused (exit 2).

### 4.4 watch

Prints one JSON line per change until `timeout_ms` passes or `max_events` lines have been printed. With neither set it runs until interrupted.

| Argument     | Description                                                    | Default |
| ------------ | -------------------------------------------------------------- | ------- |
| `key`        | Report only this key                                           | all     |
| `prefix`     | Report only keys starting with this text                       | all     |
| `timeout_ms` | Stop after this many milliseconds (0 = no timeout)             | 0       |
| `max_events` | Stop after this many lines (0 = no limit)                      | 0       |
| `initial`    | `true` to print a `snapshot` line for each current value first | `false` |

`key` and `prefix` cannot be used together. Each line has `op` (`snapshot`, `set` or `rm`), `scope`, `key`, `value` (absent for `rm`), `version` (a counter starting at 1 for this run), `ts` and `source: "config"`.

What is watched depends on the URL:

* A target with a namespace, such as `config://app/db`, watches the whole `app` namespace directory, and keys are reported relative to it (`db/url`). The rest of the URL path (`db`) does not filter anything; use `prefix=db/` or `key=db/url` to narrow the output.
* A single-segment target, such as `config://app`, uses the `default` namespace and therefore watches the whole config directory; keys are reported with their namespace (`app/db/url`).

```bash
resh config://app.watch prefix=app/db timeout_ms=10000 max_events=5
```

A `timeout_ms` or `max_events` value that is not a non-negative integer, or an `initial` value that is not a boolean, is refused with exit code 2 before anything is watched.

Each line is written as the change is seen, so a reader of resh's output gets events while `watch` runs.

### 4.5 timeout_ms

Only `watch` takes `timeout_ms`, and it enforces it as a run time limit (0 = no limit). `get`, `set` and `ls` are local file operations with no time limit; given `timeout_ms` they refuse it with exit code 2 instead of ignoring it.

---

## 5. Path Rules and Limitations

* In the namespace, any character other than letters, digits, `.`, `_` and `-` is replaced with `_`. In the key, `/` is also kept.
* A target with a `.` or `..` segment (for example `config://../x`) is refused with exit code 2 before anything is read or written, so values always stay inside the config directory. `..` segments inside the key path are collapsed by URL parsing before resh sees them (`config://app/a/../b` is `app/b`).
* Value files are owner-only (0600) and the directories `set` and `watch` create are owner-only (0700). Directories that already exist keep their mode. For secrets, use the `secret` handle instead.
* `get` and `ls` never create directories. `watch` creates the directory it watches if it is missing.
* The watcher uses filesystem notifications and also re-reads the directory every 500 ms when no timeout is set. Files that do not hold valid JSON are skipped.

---

## 6. Platform Support

Linux is the only supported and tested platform. The directory comes from the XDG config path.

---

## 7. Usage Guidance

* Separate environments with namespaces, for example `config://prod/db/url` and `config://dev/db/url`.
* In scripts, read values with `get` and parse them as JSON (for example with `jq`).
* Check the exit code of `get`: a missing key exits 1.
* Use `watch` with `timeout_ms` or `max_events` in automation so it always ends.

---

## 8. Implementation Notes

* Written in Rust. Values are serialized with `serde_json`; directory walks use `walkdir`; `watch` uses the `notify` crate.
