# Resource Shell (resh) – Cache Handle Documentation

## 1. Overview

Resource Shell (resh) is a command-line tool that runs operations on resources named by URLs.

The `cache://` handle reads and writes keys in Redis or Memcached. It supports key namespaces, TTLs, conditional writes and value encoding, and prints its results as JSON.

The target names a backend and a connection alias:

```text
resh cache://<backend>/<alias>.<verb> url=<connection-url> [key=value ...]
```

* `backend` is `redis` or `memcached` (exactly these words; `memcache` is rejected).
* `alias` is a label for the connection. If it is omitted, the alias is `default`.
* `verb` is one of `connect`, `get`, `exists`, `ttl`, `keys`, `set`, `incr`, `del`.

**Connections do not persist between `resh` invocations.** Each `resh` command is a separate process and runs one stage. A connection made by `connect` lives only in that process, so in practice every verb must be given `url=` and connects on demand. `connect` on its own is useful only as a connectivity check.

---

## 2. Design Notes

* Each verb prints one JSON object to stdout.
* On failure the handle prints a JSON error object to stdout (not stderr), and resh also prints `Error: <reason>` to stderr. The exit code is 1.
* Keys can be prefixed with a namespace (`namespace=prod` turns `user:1` into `prod:user:1`).
* Conditional writes (`only_if_not_exists`, `only_if_exists`) can stop a write from overwriting a value, or from creating one.
* There is no dry-run mode. `set`, `incr` and `del` change the server immediately.

---

## 3. Command Syntax and Execution Model

### 3.1 URL structure

| Component | Description                                                                 |
| --------- | --------------------------------------------------------------------------- |
| `cache`   | Handle scheme                                                               |
| `backend` | `redis` or `memcached`                                                      |
| `alias`   | Connection label (default `default`)                                        |
| `verb`    | `connect`, `get`, `exists`, `ttl`, `keys`, `set`, `incr`, `del`             |
| arguments | `key=value` words after the stage, or `(key=value,...)` inside quotes       |

### 3.2 Connection URLs

| Backend     | Accepted `url=` schemes                          | Example                        |
| ----------- | ------------------------------------------------ | ------------------------------ |
| `redis`     | `redis://`, `rediss://`, `redis+unix://`, `unix://` | `redis://localhost:6379/0`  |
| `memcached` | `memcache://`, `memcached://`                    | `memcache://localhost:11211`   |

`connect_timeout_ms` (default 5000) limits how long opening and verifying the connection may take (Redis `PING`, Memcached `VERSION`). It is read by every verb, because every verb may connect on demand.

**Security note:** a password in `url=` (for example `redis://:secret@host/0`) is visible to other local users in the process list while resh runs, and may be kept in shell history. The `endpoint` field in the output does not include credentials.

### 3.3 Example commands

Connectivity check:

```bash
resh --json-pretty cache://redis/main.connect url=redis://localhost:6379/0
```

Store a value with a 60-second TTL:

```bash
resh cache://redis/main.set key=user:123 value=alice ttl_ms=60000 url=redis://localhost:6379/0
```

Read it back:

```bash
resh cache://redis/main.get key=user:123 url=redis://localhost:6379/0
```

Increment a counter:

```bash
resh cache://redis/main.incr key=page_views by=1 url=redis://localhost:6379/0
```

Check the remaining TTL:

```bash
resh cache://redis/main.ttl key=user:123 url=redis://localhost:6379/0
```

### 3.4 Output

Successful `get` (shown with `--json-pretty`):

```json
{
  "alias": "main",
  "backend": "redis",
  "hit": true,
  "key": "user:123",
  "value": "alice"
}
```

Error (for example, no `url=` given):

```json
{
  "error": {
    "code": "cache.connection_not_found",
    "details": { "alias": "main", "backend": "redis" },
    "message": "connection not found for backend 'redis' alias 'main'. Pass url=<connection-url> (or run connect earlier in the same pipeline)"
  }
}
```

Error codes have the form `cache.<kind>`, for example `cache.invalid_get_config`, `cache.connect_failed`, `cache.get_timeout`, `cache.keys_unsupported`.

---

## 4. Verbs

### 4.1 connect

Opens and verifies a connection and registers it under the alias for the rest of the same process.

Arguments: `url` (required), `connect_timeout_ms`.

Output fields: `alias`, `backend`, `endpoint`, `status` (`"connected"`).

### 4.2 get

Reads one key (`key=`) or a list of keys (`keys=<json-array>`).

| Argument     | Description                                        | Default  |
| ------------ | -------------------------------------------------- | -------- |
| `key`/`keys` | Exactly one is required                            |          |
| `namespace`  | Prefix added as `<namespace>:<key>`                | none     |
| `decode`     | `utf8`, `bytes` or `json`                          | `utf8`   |
| `default`    | Value returned on a miss                           | `null`   |
| `timeout_ms` | Operation timeout                                  | 1000     |

```bash
resh cache://redis/main.get 'keys=["user:1","user:2"]' url=redis://localhost:6379/0
```

With `keys=` the output has `alias`, `backend` and a `results` array of `key`, `value`, `hit`.

### 4.3 set

Stores `value=` under `key=`, or `values=<json-array>` under `keys=<json-array>` (same length).

| Argument             | Description                                          | Default |
| -------------------- | ---------------------------------------------------- | ------- |
| `ttl_ms`             | Expiry in milliseconds                               | none    |
| `encode`             | `utf8`, `bytes` or `json`                            | `utf8` for a string value, otherwise `json` |
| `only_if_not_exists` | Write only if the key is missing                     | `false` |
| `only_if_exists`     | Write only if the key exists                         | `false` |
| `namespace`          | Key prefix                                           | none    |
| `timeout_ms`         | Operation timeout                                    | 1000    |

```bash
resh cache://redis/main.set key=lock:deploy value=host-a only_if_not_exists=true ttl_ms=30000 url=redis://localhost:6379/0
```

A write skipped by a condition reports `"stored": false` and `"reason": "condition_not_met"`. The two conditions cannot both be true.

### 4.4 del

Deletes `key=` or `keys=<json-array>`. With `keys=` the output has a `results` array and `total_deleted`.

```bash
resh cache://redis/main.del 'keys=["session:1","session:2"]' url=redis://localhost:6379/0
```

### 4.5 incr

Increments an integer counter. Arguments: `key` (required), `by` (default 1), `initial` (starting value when the key is missing, default 0), `ttl_ms`, `namespace`, `timeout_ms`.

Output (with `--json-pretty`):

```json
{
  "alias": "main",
  "backend": "redis",
  "created": false,
  "key": "page_views",
  "value": 47
}
```

### 4.6 exists

Reports whether `key=` (or each of `keys=`) exists. With `keys=` the output has a `results` array and `total_exists`. See the Memcached limitation in section 5.

### 4.7 keys

Lists keys that match a glob `pattern=` (default `*`) one page at a time with Redis `SCAN`. Arguments: `pattern`, `namespace`, `cursor`, `limit` (default 100; the `COUNT` sent to Redis is capped at 1000), `timeout_ms`.

```bash
resh --json-pretty cache://redis/main.keys 'pattern=user:*' url=redis://localhost:6379/0
```

Output fields: `alias`, `backend`, `keys`, `count`, `cursor` (a string, or `null` when there are no more pages), `has_more`. Memcached cannot list keys and returns the `cache.keys_unsupported` error.

### 4.8 ttl

Reports `exists`, `has_expiry`, `supports_ttl` and `ttl_ms` for `key=` or each of `keys=`. Only Redis can report a TTL; Memcached reports `supports_ttl: false` and `ttl_ms: null`.

### 4.9 Encoding

| Format  | On `set`                             | On `get`                               |
| ------- | ------------------------------------ | -------------------------------------- |
| `utf8`  | Stores the text                      | Returns a string; fails on invalid UTF-8 |
| `json`  | Stores the value serialized as JSON  | Parses the stored bytes as JSON        |
| `bytes` | Expects base64 text, stores the bytes | Returns the bytes base64-encoded      |

### 4.10 timeout_ms

* `get`, `set`, `del`, `incr`, `exists`, `keys` and `ttl` enforce `timeout_ms` (default 1000 ms) around the operation. On expiry they fail with `cache.<verb>_timeout`. `timeout_ms=0` is rejected.
* A `timeout_ms` value that is not a plain number (for example `timeout_ms=abc`) is silently ignored and the default is used.
* `connect` does not read `timeout_ms`; it uses `connect_timeout_ms`.

---

## 5. Limitations

These are behaviours of the current code, not plans:

* **Numeric-looking values are dropped or rejected.** Each argument value that parses as JSON is passed to the verb as JSON, and the key, namespace and cursor options are read only as strings. So `key=42` is rejected ("exactly one of 'key' or 'keys' is required"), `namespace=2024` is silently ignored, and `cursor=17` is silently ignored, so `keys` paging restarts from the beginning instead of advancing. The same applies to `true`, `false` and `null`. Workaround: quote the value as a JSON string, for example `'key="42"'`, `'namespace="2024"'` or `'cursor="17"'`.
* **Memcached `exists` and `ttl` report `exists: true` for missing keys**, because a miss is not distinguished from a hit. Do not rely on them with Memcached; use `get` and check `hit`.
* **Memcached `incr`** treats any increment error (missing key, non-numeric value, server error) as "missing" and overwrites the key with `initial + by`. Negative results are clamped to 0.
* **Memcached TTLs are whole seconds.** `ttl_ms` is divided by 1000 and rounded down; with `set`, a `ttl_ms` below 1000 becomes 0, which means no expiry.
* `keys` is Redis-only.
* Connections are per process (section 1). There is no persistent connection profile.

---

## 6. Platform Support

Linux is the only supported and tested platform. The handle needs network (or Unix socket) access to a Redis or Memcached server.

---

## 7. Usage Guidance

* Pass `url=` on every command; scripts can keep it in a variable.
* Check `hit` (for `get`) and `stored` (for `set`) rather than only the exit code.
* Use `only_if_not_exists=true` with `ttl_ms` for simple locks on Redis.
* Use namespaces to separate environments (`namespace=prod`, `namespace=staging`).
* Quote numeric keys, namespaces and cursors as JSON strings (section 5).

---

## 8. Implementation Notes

* Written in Rust, using the `redis` crate (async connection manager) and the `memcache` crate (blocking calls run on a worker thread).
* Arguments are validated before the server is contacted: `key`/`keys` must be non-empty, `decode`/`encode` must be one of the listed formats, and `ttl_ms` and `limit` must be greater than 0.
