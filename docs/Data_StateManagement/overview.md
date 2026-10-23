# Resource Shell (resh) – Data & State Management Overview

## 1. Overview

Resource Shell (resh) is a command-line tool that runs operations on resources named by URLs.

The Data & State Management category groups six handles that store, read or move data:

| Handle   | What it does                                                        | Where the data lives                                 |
| -------- | ------------------------------------------------------------------- | ---------------------------------------------------- |
| `cache`  | Reads and writes keys in Redis or Memcached                         | The cache server (`url=` on every command)           |
| `config` | Stores JSON values, one file per key                                | `$XDG_CONFIG_HOME/resh/config/` (default `~/.config/resh/config/`) |
| `db`     | Runs SQL on SQLite, PostgreSQL or MySQL/MariaDB                     | The database (`dsn=` or `DB_<ALIAS>_DSN`)            |
| `event`  | Appends events to topics and reads them back                        | `$XDG_STATE_HOME/resh/events/` (default `~/.local/state/resh/events/`) |
| `log`    | Prints the last lines of a log file or a systemd service journal    | Existing log files, or `journalctl`                  |
| `mq`     | Local file-based FIFO queue                                         | `$XDG_STATE_HOME/resh/mq/<queue>/`                   |

All commands use the resh stage form:

```text
resh <scheme>://<target>.<verb> key=value ...
resh '<scheme>://<target>.<verb>(key=value,...)'
```

The verb is the text after the last dot of the URL. A URL with no target still needs the dot, as in `event://.emit`.

---

## 2. Things to Know Before Scripting

* **Each `resh` command is a separate process that runs one stage.** Nothing held in memory survives between commands. `cache` connections, `db` pools and `db` transactions opened by one command are gone when it exits, so `cache` verbs take `url=` and `db` verbs take `dsn=` (or `DB_<ALIAS>_DSN`) every time. Only `config`, `event` and `mq` keep state, and they keep it on disk in the directories above.
* **Output formats differ by handle.** There is no common response envelope:
  * `cache` and `db` print a JSON object for the result, or `{"error": {"code", "message", "details"}}` on failure.
  * `event` prints a JSON object with `ok`, `error` and `warnings`.
  * `config get` prints the stored JSON value as is; `config ls` prints a JSON object; `config watch` prints one JSON object per line.
  * `log tail` prints raw lines, or a JSON object with `mode=json`.
  * `mq get`/`peek` print the message bytes; `mq len` prints a number.
* **Exit codes:** 0 on success. On failure, the handle's own code if it sets one (for example `mq get` on an empty queue exits 2), otherwise 1. resh prints `Error: <reason>` to stderr if the handle did not already write to stderr.
* `--json-pretty` (before the stage) re-indents JSON output.
* Help: `resh <handle> --help` and `resh <handle> <verb> --help`.

---

## 3. Examples

Cache:

```bash
resh cache://redis/main.set key=user:123 value=alice ttl_ms=60000 url=redis://localhost:6379/0
resh cache://redis/main.get key=user:123 url=redis://localhost:6379/0
```

Configuration:

```bash
resh config://app/db/host.set value=db.example.com
resh config://app/db/host.get
```

Database:

```bash
resh db://sqlite/main.query 'sql=SELECT * FROM users' dsn=sqlite:app.db
```

Logs:

```bash
resh log:///var/log/syslog.tail lines=100 mode=json
```

Events:

```bash
resh event://.emit topic=user.created 'data={"id":123}'
resh event://.subscribe topic=user.created offset=earliest
```

Message queue:

```bash
resh mq://jobs.put 'data={"task":"rebuild"}'
resh mq://jobs.get
```

Sample `db query` output (shown with `--json-pretty`):

```json
{
  "meta": {
    "columns": [
      { "name": "id", "type": "INTEGER" },
      { "name": "name", "type": "TEXT" }
    ],
    "row_count": 1,
    "truncated": false
  },
  "rows": [
    { "id": 1, "name": "Alice" }
  ]
}
```

Sample `config get` failure (stderr, exit code 1):

```text
Error: not found
```

---

## 4. Handles

### 4.1 Cache (`cache`)

Verbs: `connect`, `get`, `exists`, `ttl`, `keys`, `set`, `incr`, `del`. Supports namespaces, TTLs, conditional writes and utf8/json/bytes encoding. Limitations include numeric-looking keys, namespaces and cursors being dropped unless quoted as JSON strings, and Memcached `exists`/`ttl` reporting missing keys as present. See [cache.md](cache.md).

### 4.2 Configuration (`config`)

Verbs: `get`, `ls`, `watch`, `set`. Values are JSON, written atomically. There is no delete verb. A namespace of `..` resolves one level above the config directory, so do not build config URLs from untrusted input. See [config.md](config.md).

### 4.3 Database (`db`)

Verbs: `connect`, `ping`, `query`, `tables`, `schema`, `exec`, `transaction`. Parameters are bound with `params=`. Multi-statement transactions run in one command with `transaction statements=[...]`. PostgreSQL `NUMERIC` columns cannot be decoded. See [db.md](db.md).

### 4.4 Events (`event`)

Verbs: `emit`, `subscribe`, `list-topics`, `hooks.list`, `hooks.enable`, `hooks.disable`. Events persist as JSON Lines files in the state directory. `list-topics` returns sample data, and the built-in hooks only print notes to stderr. See [event.md](event.md).

### 4.5 Logs (`log`)

Verb: `tail`. Reads files (absolute or `./` relative) or `log://svc/<service>` journals through `journalctl`, with substring filtering. File paths are not percent-decoded. See [log.md](log.md).

### 4.6 Message queues (`mq`)

Verbs: `create`, `put`, `get`, `peek`, `len`, `purge`. A local, single-host FIFO queue with one file per message. It is not a distributed queue and has no acknowledgement or retry; a consumer can read a message that is still being written. See [mq.md](mq.md).

---

## 5. Platform Support

Linux is the only supported and tested platform. The state and config directories come from the XDG paths. `cache` and `db` need network access to their servers, and `log://svc/...` needs systemd's `journalctl`.

---

## 6. Usage Guidance

* Pass connection details (`url=`, `dsn=`) on every `cache` and `db` command. Prefer `DB_<ALIAS>_DSN` for database passwords, because command-line arguments are visible in the process list.
* Check exit codes, and for JSON output check the handle's own success fields (`hit`, `stored`, `ok`, `status`).
* Do not store secrets with `config`, `event` or `mq`; their files are plain text. Use the `secret` handle.
* Use `config watch`, `event subscribe wait=true` and `log tail` with limits (`timeout_ms`, `wait_timeout_ms`, `lines`) so scripts always end.

---

## 7. timeout_ms Summary

| Handle   | Enforces `timeout_ms`                                    | Ignores `timeout_ms`                 |
| -------- | -------------------------------------------------------- | ------------------------------------ |
| `cache`  | `get`, `set`, `del`, `incr`, `exists`, `keys`, `ttl` (default 1000; `0` rejected) | `connect` (uses `connect_timeout_ms`) |
| `db`     | `ping` (per attempt, default 1000), `query`, `exec`, `tables`, `schema`, `transaction` (default 5000; `0` and non-numbers rejected) | `connect` (uses `connect_timeout_ms`) |
| `config` | `watch` (run time limit; default none)                   | `get`, `set`, `ls`                   |
| `event`  | none (`subscribe wait=true` uses `wait_timeout_ms`)      | all verbs                            |
| `log`    | none                                                     | `tail`                               |
| `mq`     | none                                                     | all verbs                            |

---

## 8. Implementation Notes

All six handles are written in Rust and compiled into the single `resh` binary. `cache` uses the `redis` and `memcache` crates, `db` uses `sqlx`, `config watch` uses `notify`, and `log` runs `journalctl` directly without a shell.
