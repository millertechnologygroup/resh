# Resource Shell (resh): Cache Handle

## 1. Overview

The `cache://` handle reads and writes keys in Redis or Memcached. It supports
key namespaces, TTLs, conditional writes and value encodings, and prints one
JSON object per command.

```text
resh cache://<backend>/<alias>.<verb> url=<connection-url> [key=value ...]
```

* `backend` is `redis` or `memcached` (exactly these words; `memcache` is
  refused with `cache.invalid_target`, exit 2).
* `alias` is a label for the connection. If it is omitted, the alias is
  `default`.
* `verb` is one of `connect`, `get`, `exists`, `ttl`, `keys`, `set`, `incr`,
  `del`.

**Connections do not persist between `resh` invocations.** Each `resh`
command is a separate process and runs one stage, so every verb is given
`url=` and connects on demand. A connection made by `connect` (or on demand)
is registered under the alias only for the rest of the same process; a later
verb with a different `url=` replaces it. `connect` on its own is a
connectivity check.

## 2. Command syntax

### 2.1 Arguments

Arguments are `key=value` words after the stage, or `(key=value,...)` inside
the quoted stage. Every verb refuses arguments it does not take (exit 2,
`cache.invalid_argument`, with a "did you mean" hint for a likely typo) and
checks every value before it contacts the server, so an invalid command
never reaches the cache.

Values are used exactly as typed. `key=123`, `namespace=2024` and
`cursor=17` are plain text; quotes are part of the value (`value='"x"'`
stores the three characters `"x"`).

| Argument             | Verbs                         | Default | Notes |
| -------------------- | ----------------------------- | ------- | ----- |
| `url`                | all                           |         | Connection URL (2.2). Required unless the alias is already connected in this process. |
| `connect_timeout_ms` | all                           | `5000`  | Time allowed to connect and check the server (1-600000). |
| `timeout_ms`         | all but `connect`             | `1000`  | Time allowed for the command itself (1-86400000). |
| `key`                | all but `connect`, `keys`     |         | One key. |
| `keys`               | `get`, `exists`, `ttl`, `set`, `del` |  | A JSON array of strings, for example `keys='["a","b"]'`. Exactly one of `key` and `keys` is required. |
| `namespace`          | all but `connect`             | none    | Prefix: `namespace=prod` turns `user:1` into `prod:user:1`. Output shows keys without it. |

### 2.2 Connection URLs

| Backend     | `url=` forms | Default port |
| ----------- | ------------ | ------------ |
| `redis`     | `redis://[[user]:password@]host[:port][/db]`, `redis+unix:///path/to/socket[?db=N&pass=...]` (also `unix://`) | 6379 |
| `memcached` | `memcache://host[:port]` (also `memcached://`) | 11211 |

* **No TLS.** `rediss://` is refused with `cache.tls_unsupported` (exit 2):
  this build of resh has no TLS support for cache servers, so it never sends
  data unencrypted to a server you meant to reach over TLS. Use `redis://`
  only on a trusted network, or a Unix socket. `ca_file=` is refused the
  same way.
* Memcached URLs cannot carry a user name, password, path or `?options`
  (exit 2): SASL authentication is not supported, and the old client options
  (`timeout`, `connect_timeout`, `protocol`, `tcp_nodelay`) are replaced by
  `connect_timeout_ms` and `timeout_ms`. resh speaks the memcached text
  protocol.
* **Security note:** a password in `url=` (for example
  `redis://:secret@host/0`) is visible to other local users in the process
  list while resh runs, and may be kept in shell history. The `endpoint`
  field in the output never includes credentials. resh stores no
  connection settings or passwords.

### 2.3 Examples

```bash
resh --json-pretty cache://redis/main.connect url=redis://localhost:6379/0
resh cache://redis/main.set key=user:123 value=alice ttl_ms=60000 url=redis://localhost:6379/0
resh cache://redis/main.get key=user:123 url=redis://localhost:6379/0
resh cache://redis/main.incr key=page_views by=1 url=redis://localhost:6379/0
resh cache://memcached/sessions.get 'keys=["s1","s2"]' url=memcache://localhost:11211
```

## 3. Verbs

### connect

Opens a connection, checks that the server answers (Redis `PING`, Memcached
`version`) within `connect_timeout_ms`, and registers it under the alias.

Arguments: `url` (required), `connect_timeout_ms`.

```json
{"alias":"main","backend":"redis","endpoint":"localhost:6379","status":"connected"}
```

### get

Reads `key=` or `keys=`.

| Argument  | Default | Notes |
| --------- | ------- | ----- |
| `decode`  | `utf8`  | `utf8`, `bytes` or `json` (3.9). |
| `default` | `null`  | Returned for a missing key: as text, or parsed as JSON with `decode=json` (it must then be valid JSON). |

```json
{"alias":"main","backend":"redis","key":"user:123","value":"alice","hit":true}
```

With `keys=` the output is `alias`, `backend` and a `results` array of
`key`, `value`, `hit`, in the order of `keys`. A stored value that cannot be
decoded as asked fails the command (`cache.decode_failed`). On Redis,
`keys=` uses `MGET`, which reports a key holding a non-string type (a list,
a hash) as a miss; `key=` reports it as `cache.wrong_type`.

### exists

Reports whether `key=` (or each of `keys=`) exists:
`{"key","exists"}`, or `results` and `total_exists` with `keys=`. Memcached
1.6+ answers with `mg` (the value is not fetched); older servers with `get`.

### ttl

Reports, for `key=` or each of `keys=`:

| Field          | Meaning |
| -------------- | ------- |
| `exists`       | The key exists. |
| `supports_ttl` | The server can report TTLs: Redis, and Memcached 1.6+ (`mg ... t`). |
| `has_expiry`   | The key exists and has an expiry. |
| `ttl_ms`       | Milliseconds left, or `null` (missing key, no expiry, or `supports_ttl` false). Memcached reports whole seconds. |

With `keys=` the output has `results` and `found` (how many exist).

### keys

Lists keys that match a glob `pattern=` (default `*`), one page at a time.

| Argument  | Default | Notes |
| --------- | ------- | ----- |
| `pattern` | `*`     | Glob: `*`, `?`, `[abc]`, `[^a]`, `[a-z]`, `\x` (the Redis syntax, on both backends). Matched against the key without the namespace. |
| `cursor`  | start   | The `cursor` a previous page returned (`0` or empty means start). |
| `limit`   | `100`   | 1-10000. |

```json
{"alias":"main","backend":"redis","keys":["user:42","user:43"],"count":2,"cursor":null,"has_more":false}
```

When `has_more` is true, pass the returned `cursor` (a string) to get the
next page; the last page has `cursor: null`.

* **Redis** uses `SCAN cursor MATCH pattern COUNT min(limit, 1000)`. `limit`
  is a hint: a page may hold fewer or more keys, may be empty while
  `has_more` is true, and a key may appear on two pages (Redis `SCAN`
  semantics).
* **Memcached** uses `lru_crawler metadump all` (memcached 1.4.31 or later,
  with the LRU crawler enabled, the default since 1.5). Each page reads the
  whole key list, sorts it and returns up to `limit` keys after the cursor
  (the cursor encodes the last key of the previous page), so pages never
  overlap. Expired items are skipped. While another crawl is running, resh
  retries until `timeout_ms`. A server that cannot dump keys fails with
  `cache.keys_unsupported`. On a large cache each page costs a full crawl.

### set

Stores `value=` under `key=`, or `values=<json-array>` under `keys=` (same
length).

| Argument             | Default | Notes |
| -------------------- | ------- | ----- |
| `encode`             | `utf8`  | `utf8`, `bytes` or `json` (3.9). |
| `ttl_ms`             | none    | Expiry, 1 ms to 100 years. |
| `only_if_not_exists` | `false` | Write only if the key is missing (Redis `NX`, Memcached `add`). |
| `only_if_exists`     | `false` | Write only if the key exists (Redis `XX`, Memcached `replace`). The two conditions cannot both be true. |

```json
{"alias":"main","backend":"redis","key":"u1","stored":true,"ttl_ms":60000}
```

A write skipped by a condition reports `"stored": false` and
`"reason": "condition_not_met"` (exit 0). With `keys=` the output has
`results` (`key`, `stored`, `reason`) and `total_stored`. Each key is a
separate command (sent in one Redis pipeline), so a multi-key write is not
atomic: if it fails part-way, earlier keys may be written.

On Memcached, TTLs are whole seconds, rounded **up** (`ttl_ms=500` expires
after one second; a TTL never turns into "no expiry"), and TTLs over 30 days
are sent as absolute times as memcached requires.

There is no dry-run mode: `set`, `incr` and `del` change the server
immediately, and `dry_run=true` is refused (exit 2).

### incr

Adds `by` (default 1, may be negative) to the integer counter `key=`. A
missing key is created as `initial` (default 0) + `by`.

| Argument  | Default | Notes |
| --------- | ------- | ----- |
| `by`      | `1`     | Any 64-bit integer. |
| `initial` | `0`     | Start value of a missing counter. `initial + by` must fit in 64 bits. |
| `ttl_ms`  | none    | Sets the counter's expiry on every call (it is renewed by each increment). |

```json
{"alias":"main","backend":"redis","key":"views","value":47,"created":false}
```

* **Redis:** one Lua script creates, increments and sets the expiry
  atomically; values are exact 64-bit integers. A value that is not an
  integer fails with `cache.wrong_type`, and an increment that would
  overflow with `cache.server_error`; both leave the key unchanged.
* **Memcached:** counters are unsigned. A negative `by` decrements and stops
  at 0; a missing counter whose start would be negative is created at 0;
  `initial` must be 0 or more (exit 2). A missing key is created with `add`,
  so two clients creating it at once both count. A value that is not a
  number fails with `cache.wrong_type` and is left unchanged.

### del

Deletes `key=` or `keys=`: `{"key","deleted"}`, or `results` and
`total_deleted`. Deleting a missing key is not an error (`deleted: false`).

### 3.9 Encodings

| Format  | On `set`                                       | On `get` |
| ------- | ---------------------------------------------- | -------- |
| `utf8`  | Stores the text exactly as given               | Returns the text; fails (`cache.decode_failed`) on bytes that are not UTF-8 |
| `json`  | Parses the text as JSON and stores it compactly | Parses the stored bytes as JSON; fails if they are not |
| `bytes` | Decodes base64 text and stores the bytes       | Returns the bytes base64-encoded |

With `values=`, a string item is handled like `value=`; any other item (a
number, object, array) is stored as its JSON text with `utf8` or `json`.
With `encode=json`, a string item is stored as a JSON string (with quotes).

## 4. Timeouts

* `connect_timeout_ms` (default 5000) bounds connecting and checking the
  server. If it passes, the command fails with `cache.connect_timeout`
  (exit 124) and nothing was sent.
* `timeout_ms` (default 1000) bounds the command itself, including every
  key of a multi-key command and, for `keys`, waiting for a busy crawler.
  If it passes, the command fails with `cache.timeout` (exit 124). For
  `set`, `incr` and `del` the change may or may not have been made.
* A command can therefore take up to `connect_timeout_ms` + `timeout_ms`.

## 5. Errors and exit codes

Exit codes: 0 success (including a `get` miss, a `set` skipped by its
condition and a `del` of a missing key); 1 failed; 2 invalid usage, nothing
was done; 124 timeout or unknown outcome.

On failure the handle prints
`{"alias","backend","error":{"code","message"}}` on stdout and
`Error: [cache.<code>] cache <verb>: <message>` on stderr.

| Code | Exit | Meaning |
| ---- | ---- | ------- |
| `cache.invalid_argument` | 2 | Unknown argument, invalid value, invalid URL, a key memcached cannot take (empty, over 250 bytes, spaces or control characters), unknown verb. |
| `cache.invalid_target` | 2 | The backend in the target is not `redis` or `memcached` (raised by the dispatcher). |
| `cache.tls_unsupported` | 2 | `rediss://` or `ca_file=`: TLS is not supported. |
| `cache.connection_not_found` | 2 | No `url=` and no connection for the alias in this process. |
| `cache.connect_failed` | 1 | The connection was refused, the host was not found, authentication failed, or the server did not answer `PING`/`version` correctly. |
| `cache.connect_timeout` | 124 | No connection within `connect_timeout_ms`. |
| `cache.timeout` | 124 | No answer within `timeout_ms`; a write may or may not have happened. |
| `cache.connection_lost` | 1 or 124 | The connection broke during the command: exit 1 for reads, 124 for writes (the outcome is unknown). |
| `cache.server_error` | 1 | The server refused the command (for example Redis `OOM`, memcached `SERVER_ERROR out of memory`, a value too large). |
| `cache.wrong_type` | 1 | `incr` on a value that is not an integer counter, or a Redis key of another type (`WRONGTYPE`). |
| `cache.decode_failed` | 1 | A stored value is not valid for `decode=utf8` or `decode=json`. |
| `cache.keys_unsupported` | 1 | The memcached server cannot list keys (`lru_crawler metadump`). |

## 6. Limitations

* No TLS and no Memcached authentication (2.2).
* Connections last for one process (section 1); there are no stored
  connection profiles.
* Redis Cluster is not supported (no `MOVED`/`ASK` redirects); use a single
  node or a proxy.
* A multi-key `set` or `del` is not atomic (3, `set`).
* Memcached TTLs are whole seconds (3, `set`), and Memcached `ttl` needs
  1.6+ to report remaining time.
* Memcached `keys` reads the whole key list on every page (3, `keys`).

## 7. Platform support

Linux is the only supported and tested platform. The handle needs network
(or Unix socket) access to a Redis or Memcached server. It is tested against
the official `redis:7` and `memcached:1.6` images.

## 8. Implementation notes

* Redis: the `redis` crate (async connection manager); multi-key verbs send
  one pipeline.
* Memcached: resh's own text-protocol client (`src/handles/data/cacheh/memcached.rs`),
  so every server reply (`STORED`/`NOT_STORED`, `DELETED`/`NOT_FOUND`,
  `CLIENT_ERROR`, `SERVER_ERROR`) is told apart. Keys are checked before
  they are sent, so a key cannot inject another command.
