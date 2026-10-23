# Resource Shell (resh) – Secret Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations as URI-style commands. The `secret://` handle stores and reads small secret values (API keys, passwords, tokens) in a local keystore file, and reads values from the process environment.

### What the handle does

* Stores a secret from a literal value or from an environment variable (`set`).
* Reads a secret, optionally withholding the value from the output (`get`).
* Lists keys by prefix (`ls`).
* Removes a secret (`rm`).
* `rotate` is registered but **not implemented**: it always fails (see below).

Every verb prints one JSON object on stdout.

### What the handle does not do

* **No encryption at rest.** The local keystore is a plain JSON file. Its protection is file permissions only (see [Storage](#4-storage)). Anyone who can read the file as your user, or as root, can read every secret in it.
* **No secret generation or rotation.** `rotate` returns a "not implemented" error. There are no `strategy` or `length` options.
* **No Vault integration.** The `vault` scope is accepted in the URL, but every verb on it fails with "vault backend not implemented yet".
* **No locking.** See [Limitations](#7-limitations).

---

## 2. Command Syntax

```text
resh secret://<scope>/<key-path>.<verb> [key=value ...]
```

| Component  | Description                                                          |
| ---------- | -------------------------------------------------------------------- |
| `scope`    | `local` (keystore file), `env` (process environment, read-only), or `vault` (not implemented) |
| `key-path` | Key name. Slashes group keys (`app/db_password`); `ls` uses them as prefixes. |
| `verb`     | `get`, `set`, `rm`, `ls`, `rotate`                                   |

Any other scope is rejected with `unsupported scope '<x>'; supported scopes: local, env, vault`.

The verb is the text after the last dot of the URL, so a key path should not end in something that looks like a verb.

Built-in help:

```bash
resh secret --help
resh secret get --help
```

---

## 3. Verbs

| Verb     | Scopes       | Arguments                         | Result                                   |
| -------- | ------------ | --------------------------------- | ---------------------------------------- |
| `get`    | local, env   | `redact=true` (optional)          | `exists`, `value` (or `null`), `redacted` |
| `set`    | local only   | `value=<secret>` or `from_env=<VAR>` | `set: true`, `source: "literal"` or `"env"` |
| `rm`     | local only   | none                              | `removed: true/false`                    |
| `ls`     | local, env   | none (the key path is the prefix) | sorted `keys`, `prefix`                  |
| `rotate` | none         | none                              | always fails, exit status 2              |

### get

```bash
resh --json-pretty secret://local/app/db_password.get
resh secret://local/app/db_password.get redact=true
resh secret://env/DATABASE_URL.get
```

* **`get` prints the secret value in plain text by default.** Pass `redact=true` to get `"value": null` and `"redacted": true` instead. Only the exact string `true` turns redaction on; `redact=yes` or `redact=1` still prints the value.
* There is no `expose_value` argument.
* A missing key is not an error: the command exits 0 with `"exists": false` and `"value": null`. Check `exists`.

```json
{
  "backend": "local",
  "exists": true,
  "key": "app/db_password",
  "scope": "local",
  "value": "s3cr3t-value"
}
```

With `redact=true`:

```json
{
  "backend": "local",
  "exists": true,
  "key": "app/db_password",
  "redacted": true,
  "scope": "local",
  "value": null
}
```

### set

```bash
resh secret://local/app/db_password.set from_env=DB_PASSWORD
resh secret://local/app/api_key.set value=sk-test123
```

* `value=` takes precedence if both are given.
* `from_env=<VAR>` reads the value from the named environment variable of the `resh` process; if it is unset, the command fails.
* **Prefer `from_env=`.** A `value=` argument is visible to other local users in the process list (`ps`) and is kept in shell history.
* `set` overwrites an existing key without warning.
* `env` scope is read-only: `set` fails with `env backend is read-only`.

```json
{
  "backend": "local",
  "key": "app/db_password",
  "scope": "local",
  "set": true,
  "source": "env"
}
```

### rm

```bash
resh secret://local/app/old_token.rm
```

Removing a key that does not exist succeeds with `"removed": false`.

### ls

```bash
resh secret://local/app.ls
resh secret://local/.ls
```

Lists keys equal to the key path or nested under it (`app` matches `app` and `app/...`). An empty key path (`secret://local/.ls`) lists every key. Values are never printed by `ls`.

For `env` scope, `ls` lists environment variable **names** of the `resh` process (`secret://env/.ls` lists all of them).

```json
{
  "backend": "local",
  "keys": ["app/api_key", "app/db_password"],
  "prefix": "app",
  "scope": "local"
}
```

### rotate (not implemented)

```bash
resh secret://local/app/api_key.rotate
```

Always prints the error object below and exits with status 2. It does not change the stored value.

```json
{
  "backend": "local",
  "error": "rotate operation not implemented yet",
  "key": "app/api_key",
  "scope": "local"
}
```

---

## 4. Storage

The `local` scope uses one file:

```text
<state-dir>/resh/secrets/local.json
```

`<state-dir>` is `$XDG_STATE_HOME`, or `~/.local/state` when that is unset (Linux). If no state directory can be determined, local-scope verbs fail; there is no fallback location such as `/tmp`.

* The file is **plain, unencrypted JSON** mapping key paths to values.
* The directory is created with mode 0700 (and tightened to 0700 if it was more open).
* Each write goes to a new temporary file created with mode 0600 in the same directory, is synced to disk, and is renamed over `local.json`. A crash during a write leaves either the old or the new file, not a partial one.
* `get` and `ls` only read the file. `set` and `rm` read the whole file, change it in memory, and write it back.

Protect the file the way you would protect any plaintext credential file: keep it out of backups and shared home directories you do not trust, and use full-disk encryption if the threat model includes a lost disk.

---

## 5. Errors and Exit Codes

Errors are printed as a JSON object with an `error` string on **stdout**. resh also prints `Error: <reason>` on stderr.

```json
{
  "backend": "env",
  "error": "env backend is read-only",
  "key": "X",
  "scope": "env"
}
```

| Exit status | When (verified in the source)                                                         |
| ----------- | ------------------------------------------------------------------------------------- |
| 0           | Success, including `get` of a missing key and `rm` of a missing key                   |
| 1           | Missing key path, missing `value`/`from_env`, unset `from_env` variable, write to `env` scope, keystore read/parse/write failure |
| 2           | `rotate` (not implemented) and any verb on `vault` scope (not implemented)            |

---

## 6. Options That Are Not Supported

The secret handle reads only the arguments listed in [Verbs](#3-verbs). Every other argument is **ignored without an error**, including:

* `timeout_ms`: ignored (all operations are local file or environment reads).
* `dry_run`: no verb has a dry-run mode, so `dry_run=true` is refused (exit 2) and nothing is written.
* `strategy`, `length`, `expose_value`: do not exist.

---

## 7. Limitations

* **Plaintext storage.** No encryption at rest; see [Storage](#4-storage).
* **No locking.** Two `resh secret` processes running `set` or `rm` at the same time can each load the file, change it, and write it back; the last writer wins and the other change is lost. Run writers one at a time.
* **Command-line exposure.** `value=` is visible in the process list; use `from_env=`.
* **`get` output contains the secret** unless `redact=true`. Do not log it.
* **`rotate` and `vault` are not implemented.**
* **Platform.** Linux is the only supported and tested platform. The keystore path comes from the XDG state directory; on platforms where no state directory is defined (for example macOS and Windows), local-scope verbs fail.

---

## 8. Usage Guidance

* Import a secret from an environment variable rather than typing it on the command line:

  ```bash
  resh secret://local/app/db/password.set from_env=DB_PASSWORD
  ```

* Check that a secret exists without printing it:

  ```bash
  resh secret://local/app/db/password.get redact=true
  ```

  Then test the `exists` field of the JSON.

* Use hierarchical key paths (`app/env/service/key`) so `ls` can list one application's keys.
* Remove secrets you no longer need with `rm`.
* To change a secret, run `set` again with the new value; there is no automatic rotation.
