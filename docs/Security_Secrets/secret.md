# Resource Shell (resh) – Secret Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations as URI-style commands. The `secret://` handle stores and reads small secret values (API keys, passwords, tokens) in the OS keyring or in HashiCorp Vault, and reads values from the process environment.

### What the handle does

* Stores a secret from a literal value or from an environment variable (`set`).
* Reads a secret, optionally withholding the value from the output (`get`).
* Lists keys by prefix, never values (`ls`).
* Removes a secret (`rm`).
* Replaces a secret with a newly generated one: random bytes, a UUID, an AES key or an RSA private key (`rotate`).

Every verb prints one JSON object on stdout.

### Scopes

| Scope   | Where the values are                                                                                   | Verbs                        |
| ------- | ------------------------------------------------------------------------------------------------------ | ---------------------------- |
| `local` | The OS keyring (Secret Service on Linux, Keychain on macOS). A small index file lists only key names. | `get`, `set`, `rm`, `ls`, `rotate` |
| `env`   | The environment of the `resh` process (read-only).                                                     | `get`, `ls`                  |
| `vault` | A HashiCorp Vault KV version 2 secrets engine.                                                         | `get`, `set`, `rm`, `ls`, `rotate` |

### What the handle does not do

* **No plaintext files.** resh never writes a secret value to a file. If no OS keyring is available, `local` writes are refused (see [local scope](#4-local-scope-os-keyring)).
* **No dry-run mode.** `dry_run=true` is refused (exit 2) and nothing is written.
* **No Vault authentication methods.** resh uses a Vault token you already have (`VAULT_TOKEN` or `~/.vault-token`); it does not log in.
* **No KV version 1 engines** and no other Vault secrets engines.

---

## 2. Command Syntax

```text
resh secret://<scope>/<key-path>.<verb> [key=value ...]
```

| Component  | Description                                                          |
| ---------- | -------------------------------------------------------------------- |
| `scope`    | `local`, `env` or `vault`                                            |
| `key-path` | Key name. Slashes group keys (`app/db_password`); `ls` uses them as prefixes. |
| `verb`     | `get`, `set`, `rm`, `ls`, `rotate`                                   |

`secret:///<scope>/<key-path>.<verb>` (scope in the path) is accepted too.

Any other scope is rejected with `secret.invalid_target` (exit 2): `unsupported scope '<x>'; supported scopes: local, env, vault`.

The verb is the text after the last dot of the URL, so a key path may contain dots (`app/v1.2/token.get` reads `app/v1.2/token`) but should not end in something that looks like a verb. Percent-encoded characters in the key path are decoded (`a%20b` is `a b`).

For `local` and `vault`, a key path is made of non-empty `/`-separated segments; empty segments (leading, trailing or doubled `/`), `.` and `..` segments, control characters and paths over 1024 bytes are refused with `secret.invalid_key`. For `env`, the key is a variable name and must not contain `=`.

Built-in help:

```bash
resh secret --help
resh secret get --help
```

---

## 3. Verbs

Every verb accepts only the arguments listed for it; any other argument is refused with `secret.invalid_argument` (exit 2), with a "did you mean" hint for a likely typo.

| Verb     | Scopes            | Arguments                                                      | Result                                    |
| -------- | ----------------- | -------------------------------------------------------------- | ----------------------------------------- |
| `get`    | local, env, vault | `redact=true\|false`                                           | `exists`, `value` (or `null`), `redacted` |
| `set`    | local, vault      | `value=<secret>` or `from_env=<VAR>`                           | `set: true`, `source: "literal"` or `"env"` |
| `rm`     | local, vault      | none                                                           | `removed: true/false`                     |
| `ls`     | local, env, vault | none (the key path is the prefix)                              | sorted `keys`, `prefix`                   |
| `rotate` | local, vault      | `strategy=`, `length=`, `encoding=`                            | `rotated: true`, `existed`, `strategy`, `length`, `encoding`, `public_key` (rsa) |

Common arguments:

| Argument      | Scopes       | Meaning |
| ------------- | ------------ | ------- |
| `timeout_ms`  | local, vault | Total time for the operation, 1 to 86400000 ms. When it passes, the command fails with `secret.timeout` (exit 124). `env` is instant and refuses it. |
| `mount`       | vault        | KV v2 mount path, default `secret`. May be nested (`kv/team`). |
| `field`       | vault (`get`, `set`, `rotate`) | Field of the Vault secret that holds the value, default `value`. |
| `ca_file`     | vault        | PEM bundle of extra CA certificates to trust for the Vault server (added to the built-in roots; verification stays on). Default: `VAULT_CACERT`. |

### get

```bash
resh --json-pretty secret://local/app/db_password.get
resh secret://local/app/db_password.get redact=true
resh secret://env/DATABASE_URL.get
resh secret://vault/app/db.get field=password
```

* **`get` prints the secret value in plain text by default.** Pass `redact=true` to get `"value": null` and `"redacted": true` instead. `redact` takes `true/false`, `1/0`, `yes/no` or `on/off`; any other value is refused (exit 2) rather than printing the secret.
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

When a result carries warnings (for example a value read from a legacy plaintext store), they are listed in a `"warnings"` array and also printed to stderr as `Warning: <text>`.

### set

```bash
resh secret://local/app/db_password.set from_env=DB_PASSWORD
resh secret://local/app/api_key.set value=sk-test123
resh secret://vault/app/db.set from_env=DB_PASSWORD field=password
```

* Give exactly one of `value=` and `from_env=`; both, neither, or an empty value is refused (exit 2) and nothing is stored.
* `from_env=<VAR>` reads the value from the named environment variable of the `resh` process; if it is unset, the command fails with `secret.env_not_set` (exit 1).
* **Prefer `from_env=`.** A `value=` argument is visible to other local users in the process list (`ps`) and is kept in shell history.
* `set` overwrites an existing key.
* `env` scope is read-only: `set`, `rm` and `rotate` fail with `secret.read_only` (exit 2).

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

Removing a key that does not exist succeeds with `"removed": false`. In `vault`, `rm` deletes the secret's metadata: every version and every field of the secret is removed permanently.

### ls

```bash
resh secret://local/app.ls
resh secret://local/.ls
resh secret://vault/app.ls mount=kv
```

Lists keys equal to the key path or nested under it (`app` matches `app` and `app/...`, not `application`). An empty key path (`secret://local/.ls`) lists every key. Values are never printed by `ls`, and `ls` on `local` does not need the keyring (it reads the index).

For `env` scope, `ls` lists environment variable **names** of the `resh` process (`secret://env/.ls` lists all of them). For `vault`, `ls` walks the mount's metadata recursively.

```json
{
  "backend": "local",
  "keys": ["app/api_key", "app/db_password"],
  "prefix": "app",
  "scope": "local"
}
```

### rotate

```bash
resh secret://local/app/api_key.rotate
resh secret://local/app/session_key.rotate strategy=aes length=256 encoding=base64
resh secret://local/app/request_id_salt.rotate strategy=uuid
resh secret://vault/svc/signing_key.rotate strategy=rsa length=4096
```

Generates a new value from the operating system's secure random source, stores it under the key (replacing any existing value, or creating the key), and reports what it did. **The new value is never printed**; read it with `get`. `existed` tells whether the key had a value before.

| `strategy`         | `length` (bits)                    | `encoding`                                 | Stored value |
| ------------------ | ---------------------------------- | ------------------------------------------ | ------------ |
| `random` (default) | multiple of 8, 64 to 8192; default 256 | `hex` (default), `base64`, `base64url` (no padding) | Random bytes, encoded |
| `aes`              | 128, 192 or 256; default 256       | `hex` (default), `base64`, `base64url`     | A random AES key, encoded |
| `uuid`             | not accepted (always 128)          | not accepted                               | A version 4 UUID |
| `rsa`              | 2048, 3072 (default) or 4096       | not accepted                               | A PKCS#8 PEM RSA private key; the public key (SPKI PEM) is printed as `public_key` |

Any other strategy, length or encoding is refused (exit 2) before anything is generated. RSA generation can take several seconds; `timeout_ms` bounds it (exit 124, nothing stored).

```json
{
  "backend": "local",
  "encoding": "hex",
  "existed": true,
  "key": "app/api_key",
  "length": 256,
  "rotated": true,
  "scope": "local",
  "strategy": "random"
}
```

`rotate` is not atomic with whatever uses the secret: update the consumers (a service reload, a config render) after it.

---

## 4. local scope: OS keyring

* Values are stored in the OS keyring through the Secret Service API on Linux (GNOME Keyring, KWallet's Secret Service, KeePassXC) or the Keychain on macOS, under the service name `resh-secret` with the key path as the account. On Linux you can inspect them with `secret-tool lookup service resh-secret username <key-path>`.
* An index file lists the key names and their keyring references (`keyring:resh-secret/<key-path>`), never the values, so `ls` works without unlocking the keyring:

  ```text
  <state-dir>/resh/secrets/local.json
  ```

  `<state-dir>` is `$XDG_STATE_HOME`, or `~/.local/state` when that is unset (Linux). If no state directory can be determined, local-scope verbs fail; there is no fallback location such as `/tmp`.
* The index is created with mode 0600 from the start, in a directory with mode 0700 (tightened to 0700 if it was more open). It is written atomically (a new temporary file renamed into place), and a symlink planted at its path is refused, never followed.
* Writers (`set`, `rm`, `rotate`) take an exclusive lock (`local.lock` next to the index), so concurrent `resh` processes do not lose each other's changes. A writer waits up to `timeout_ms` (default 10 s) for the lock and then fails with `secret.timeout` (exit 124).
* `get` reads the keyring; a key listed in the index but missing from the keyring (removed outside resh) reads as `"exists": false` with a warning.
* A keyring call that does not answer (for example a locked keyring waiting for an unlock prompt) fails after `timeout_ms`, or 10 s by default, with `secret.timeout` (exit 124).

### No keyring

If the OS keyring is not available (no Secret Service on the session D-Bus, for example over SSH without a desktop session, or in a container), `get`, `set`, `rm` and `rotate` on `local` fail with `secret.keyring_unavailable` (exit 1) and nothing is changed. resh never falls back to a file. Alternatives:

* pass the secret to the consuming command per call, or keep it in an environment variable and read it with `secret://env/<VAR>.get`;
* use the `vault` scope;
* on a headless Linux host, run a Secret Service provider in the session, for example `dbus-run-session -- sh -c 'echo -n "$PW" | gnome-keyring-daemon --unlock --components=secrets; ...'`.

### Legacy plaintext store

Releases up to v1.0.6-beta kept `local` values in plain JSON in the same `local.json` file. Such a file is still read:

* `get` returns a value from it, and `get` and `ls` add a warning;
* the next `set`, `rm` or `rotate` moves every value into the keyring and rewrites the file as an index of names only. Without a keyring that write is refused (exit 1) and the old file is left as it was.

---

## 5. vault scope: HashiCorp Vault

Configuration comes from the standard Vault environment variables:

| Variable          | Meaning |
| ----------------- | ------- |
| `VAULT_ADDR`      | Server URL, `http://` or `https://` (required). |
| `VAULT_TOKEN`     | Token sent as `X-Vault-Token`. When unset, `~/.vault-token` (written by `vault login`) is used. |
| `VAULT_NAMESPACE` | Sent as `X-Vault-Namespace` (Vault Enterprise / HCP). |
| `VAULT_CACERT`    | Default for `ca_file=`. |

`VAULT_SKIP_VERIFY` is **not** honoured: certificates are always verified. A missing or invalid `VAULT_ADDR`, or no token, fails with `secret.vault_not_configured` (exit 2). The token is never printed.

* Each key path is a secret in the KV v2 engine at `mount` (default `secret`); the value is the secret's `field` (default `value`). Every path segment is percent-encoded, so a key path cannot reach another API endpoint.
* `get` reads the latest version. A secret without the field fails with `secret.vault_field_missing` (exit 1) and lists the fields it has. A non-string field is returned as its JSON text.
* `set` and `rotate` read the secret, change only `field`, keep the other fields, and write a new version with check-and-set. If someone else wrote the secret in between, the write fails with `secret.vault_conflict` (exit 1) and nothing is stored.
* `rm` deletes the secret's metadata and all of its versions.
* Requests use `timeout_ms`, or 30 s each by default; a timeout fails with `secret.timeout` (exit 124).
* HTTP redirects are not followed.

---

## 6. Errors and Exit Codes

A failure prints the standard line on stderr:

```text
Error: [secret.<code>] <message>
```

and a JSON object on stdout:

```json
{
  "backend": "env",
  "error": {"code": "secret.read_only", "message": "the env scope is read-only (it is the resh process environment); nothing was changed"},
  "key": "X",
  "ok": false,
  "scope": "env"
}
```

(`ls` failures carry `prefix` instead of `key`.) Errors raised before the handle runs (an unsupported scope, a bare word that is not `key=value`, a refused `dry_run`) print only the stderr line.

| Exit | Code                          | When |
| ---- | ----------------------------- | ---- |
| 0    |                               | Success, including `get` of a missing key and `rm` of a missing key |
| 2    | `secret.invalid_argument`     | Unknown argument, bad `redact`/`timeout_ms`/`strategy`/`length`/`encoding`/`mount`/`field`/`ca_file`, both `value=` and `from_env=` |
| 2    | `secret.unknown_verb`         | A verb other than get, set, rm, ls, rotate |
| 2    | `secret.missing_key`          | No key path for `get`, `set`, `rm` or `rotate` |
| 2    | `secret.invalid_key`          | Key path with an empty, `.` or `..` segment, a control character, over 1024 bytes, or an env name with `=` |
| 2    | `secret.missing_value`        | `set` without `value=`/`from_env=`, or with an empty value |
| 2    | `secret.read_only`            | `set`, `rm` or `rotate` on `env` |
| 2    | `secret.vault_not_configured` | No or invalid `VAULT_ADDR`, or no Vault token |
| 2    | `secret.invalid_target`       | Unsupported scope (reported by the dispatcher) |
| 1    | `secret.env_not_set`          | The `from_env=` variable is not set |
| 1    | `secret.keyring_unavailable`  | No usable OS keyring for a `local` read or write |
| 1    | `secret.store_error`          | The index file cannot be read, parsed or written; no state directory; RSA generation failed |
| 1    | `secret.vault_denied`         | Vault answered 403 (bad token or policy) |
| 1    | `secret.vault_error`          | Vault unreachable, TLS failure, unknown mount/route, or another unexpected answer |
| 1    | `secret.vault_field_missing`  | The Vault secret has no such field |
| 1    | `secret.vault_conflict`       | A concurrent Vault write changed the secret (check-and-set failed) |
| 124  | `secret.timeout`              | `timeout_ms` (or a default limit) passed: keystore lock, keyring call, Vault request or RSA generation |

---

## 7. Limitations

* **Command-line exposure.** `value=` is visible in the process list; use `from_env=`.
* **`get` output contains the secret** unless `redact=true`. Do not log it.
* **Keyring access is per user session.** Any process running as your user in the unlocked session can read the `resh-secret` entries, as with any keyring item.
* **The macOS Keychain path is not tested;** Linux with a Secret Service provider is the tested platform. Windows is not supported (no state directory).
* **The index and the keyring are separate stores.** If the index write fails after a keyring write, the value is stored but `ls` does not list it (the error says so; run `set` again).
* **Vault:** token authentication only, KV version 2 only; `rm` is a permanent delete of all versions.

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
* Rotate a token and then restart its consumer:

  ```bash
  resh secret://local/app/api_token.rotate && resh svc://app.restart
  ```

* Remove secrets you no longer need with `rm`.
