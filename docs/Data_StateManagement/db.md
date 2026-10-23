# Resource Shell (resh) – Database Handle Documentation

## 1. Overview

Resource Shell (resh) is a command-line tool that runs operations on resources named by URLs.

The `db://` handle runs SQL against SQLite, PostgreSQL and MySQL/MariaDB through `sqlx` connection pools and prints the results as JSON. It can run queries and data-changing statements with bound parameters, list tables, describe a table's schema, check connectivity, and run a list of statements in one transaction.

All operations use this form:

```text
resh db://<driver>/<alias>.<verb> [key=value ...]
```

* `driver` is `sqlite`, `postgres` or `mysql`.
* `alias` is a label for the connection. It also names the environment variable `DB_<ALIAS>_DSN` (alias in upper case) that is read when `dsn=` is not given.

**Nothing persists between `resh` invocations.** Each `resh` command is a separate process that runs one stage. A pool opened by `connect`, and a transaction opened by `transaction action=begin`, exist only inside that process and are gone when it exits. Therefore:

* Every verb connects on its own when given `dsn=` or when `DB_<ALIAS>_DSN` is set. Without either, it fails with `db.connection_not_found`.
* To run several statements atomically, use `transaction` with `statements=` (action `run`, the default), which begins, runs and commits in one invocation.

---

## 2. Design Notes

* Each verb prints one JSON object to stdout.
* On failure the handle prints a JSON error object to stdout (not stderr), and resh also prints `Error: <reason>` to stderr. The exit code is 1.
* `params=` binds values to placeholders, so data does not have to be spliced into the SQL text.
* Numeric and boolean options are validated strictly: `timeout_ms=abc` is an error, not a silent default.
* There is no dry-run mode. `exec`, `transaction` and data-changing `query` statements change the database immediately.

---

## 3. Command Syntax and Execution Model

### 3.1 URL structure

| Component | Description                      |
| --------- | -------------------------------- |
| `db`      | Handle scheme                    |
| `driver`  | `sqlite`, `postgres` or `mysql`  |
| `alias`   | Connection label                 |
| `verb`    | `connect`, `ping`, `query`, `exec`, `tables`, `schema`, `transaction` |

### 3.2 DSNs

| Driver     | Example DSN                                  |
| ---------- | -------------------------------------------- |
| `sqlite`   | `sqlite:app.db` (relative to the working directory), `sqlite:/var/lib/app/app.db`, `sqlite::memory:` |
| `postgres` | `postgresql://user@db.example.com:5432/app`  |
| `mysql`    | `mysql://user@db.example.com:3306/app`       |

A SQLite file must already exist; add `?mode=rwc` (for example `'dsn=sqlite:new.db?mode=rwc'`) to create it.

**Security note:** a password in `dsn=` is visible to other local users in the process list while resh runs, and may be kept in shell history. Prefer setting `DB_<ALIAS>_DSN` in the environment, which is not shown in the process list.

### 3.3 Example commands

```bash
resh db://sqlite/app.query 'sql=SELECT id, email FROM users' dsn=sqlite:app.db
```

```bash
export DB_STOCKS_DSN='mysql://report@db.example.com:3306/stocks'
resh db://mysql/stocks.query 'sql=SELECT COUNT(*) FROM stocks' mode=scalar
```

```bash
resh db://postgres/app.exec 'sql=INSERT INTO users (email) VALUES ($1)' 'params=["alice@example.com"]' dsn=postgresql://app@localhost:5432/appdb
```

### 3.4 Output

`query` in `rows` mode (actual SQLite output, shown pretty-printed):

```json
{
  "meta": {
    "columns": [
      { "name": "id", "type": "INTEGER" },
      { "name": "email", "type": "TEXT" }
    ],
    "row_count": 2,
    "truncated": false
  },
  "rows": [
    { "email": "a@example.com", "id": 1 },
    { "email": "b@example.com", "id": 2 }
  ]
}
```

`exec`:

```json
{ "rows_affected": 1 }
```

Error:

```json
{
  "error": {
    "code": "db.connection_not_found",
    "details": { "alias": "app", "driver": "sqlite" },
    "message": "connection not found for driver 'sqlite' alias 'app'. Use connect verb first"
  }
}
```

The message says "Use connect verb first", but a separate `connect` command does not help (section 1); pass `dsn=` or set `DB_<ALIAS>_DSN`.

---

## 4. Verbs

### 4.1 connect

Opens a pool and reports its statistics. Because the pool ends with the process, `connect` is mainly a connectivity and DSN check.

Arguments: `dsn`, `max_connections` (default 10), `min_connections` (default 1), `connect_timeout_ms` (default 5000, the pool acquire timeout), `idle_timeout_ms` (default 600000), `max_lifetime_ms`, `log_queries`, `tls_mode` (`disable`, `allow`, `prefer`, `require`, `verify_ca`, `verify_full`; overrides any SSL mode in the DSN; MySQL rejects `allow` and SQLite accepts only `disable`). These connection arguments are also accepted by every other verb, which uses them when it connects on demand.

```bash
resh db://sqlite/app.connect dsn=sqlite:app.db
```

```json
{
  "alias": "app",
  "driver": "sqlite",
  "pool_stats": {
    "current_size": 1,
    "idle_connections": 1,
    "max_connections": 10,
    "min_connections": 1
  },
  "reused": false,
  "type": "db_connection"
}
```

### 4.2 ping

Runs `SELECT 1`, retrying on failure. Arguments: `timeout_ms` (per attempt, default 1000), `retries` (default 0), `backoff_ms` (default 100), `detailed` (adds `last_error`).

```bash
resh db://postgres/app.ping timeout_ms=2000 retries=2 dsn=postgresql://app@localhost:5432/appdb
```

Success output: `alias`, `attempts`, `driver`, `latency_ms`, `status: "ok"`. When every attempt fails, `status` is `"error"`, an `error` object is added, and the command exits non-zero. If the DSN itself cannot be opened (for example a missing SQLite file), the command fails with `db.connect_failed` before any ping attempt.

### 4.3 query

Runs a SQL statement. Arguments: `sql` (required), `params` (JSON array), `mode` (`rows`, `scalar` or `exec`; default `rows`), `max_rows` (default 1000; `meta.truncated` is true when rows were cut), `timeout_ms` (default 5000), connection arguments.

* `mode=rows` returns `rows` and `meta` (`columns` with `name` and `type`, `row_count`, `truncated`).
* `mode=scalar` returns `value` (first column of the first row) and `meta`.
* `mode=exec` returns `rows_affected`.

### 4.4 exec

Runs one data-changing statement and returns `rows_affected`. Arguments: `sql`, `params`, `return_last_insert_id`, `timeout_ms` (default 5000), connection arguments.

`return_last_insert_id=true` adds `last_insert_id`. It is always `null` on PostgreSQL (use `INSERT ... RETURNING id` with `query` instead). On SQLite it currently reports 0 (see section 5).

### 4.5 tables

Lists tables, or describes one table's columns when `table=` is given. Arguments: `table`, `schema`, `include_views`, `include_system`, `max_tables`, `timeout_ms` (default 5000), connection arguments.

```bash
resh db://sqlite/app.tables dsn=sqlite:app.db
```

```json
{
  "meta": { "count": 1, "truncated": false },
  "tables": [ { "name": "users", "schema": null, "type": "BASE TABLE" } ]
}
```

SQLite reports `schema` as `null` in the list. With `table=` the output has a `table` object and a `columns` array.

### 4.6 schema

Describes a table: `columns` (`name`, `data_type`, `is_nullable`, `is_primary_key`, `default`, `ordinal_position`), `primary_key`, and the sections selected by `include_indexes`, `include_foreign_keys`, `include_unique_constraints`, `include_checks`, `include_triggers`. Arguments also include `table` (required), `schema`, `timeout_ms` (default 5000) and connection arguments.

```bash
resh db://postgres/app.schema table=users include_indexes=true include_foreign_keys=true dsn=postgresql://app@localhost:5432/appdb
```

Index, foreign key and constraint details are filled in for SQLite only; PostgreSQL and MySQL return empty lists for those sections.

### 4.7 transaction

Default action `run`: runs every statement in `statements=` inside one transaction, commits if all succeed, and rolls back otherwise. Items are SQL strings or `{"sql": ..., "params": [...]}` objects.

```bash
resh db://sqlite/app.transaction 'statements=["DELETE FROM sessions", {"sql":"UPDATE users SET active = ? WHERE id = ?","params":[false, 7]}]' dsn=sqlite:app.db
```

```json
{
  "action": "run",
  "alias": "app",
  "committed": true,
  "driver": "sqlite",
  "results": [
    { "index": 0, "rows_affected": 3 },
    { "index": 1, "rows_affected": 1 }
  ],
  "status": "ok"
}
```

If a statement fails, everything is rolled back and the error names the failing statement's index. If the whole run exceeds `timeout_ms` (default 5000), it is rolled back.

Other arguments:

* `isolation`: `default`, `read_uncommitted`, `read_committed`, `repeatable_read`, `serializable`. Applied on PostgreSQL and MySQL by `SET TRANSACTION ISOLATION LEVEL` after the transaction starts. Ignored on SQLite.
* `read_only=true`: applied on PostgreSQL only. Ignored on MySQL and SQLite.

`action=begin`, `action=commit tx_id=<id>` and `action=rollback tx_id=<id>` exist, but the transaction is held in process memory. A `tx_id` returned by `begin` cannot be used by a later `resh` command, and the transaction is discarded when the process exits. `query` and `exec` accept `tx_id=` for the same reason only within one process. From the command line, use `action=run`.

### 4.8 Parameter binding

Placeholders follow the database: `?` for SQLite and MySQL, `$1`, `$2`, ... for PostgreSQL. `params=` is a JSON array; strings, numbers, booleans and `null` are bound with their JSON types. Arrays and objects are rejected as parameters.

```bash
resh db://sqlite/app.query 'sql=SELECT * FROM users WHERE id = ?' 'params=[1]' dsn=sqlite:app.db
```

### 4.9 timeout_ms

* `ping` enforces `timeout_ms` per attempt (default 1000 ms).
* `query`, `exec`, `tables`, `schema` and `transaction` enforce `timeout_ms` (default 5000 ms) and fail with a `db.*_timeout` error when it expires.
* `connect` does not read `timeout_ms`; it uses `connect_timeout_ms`.
* `timeout_ms=0` and non-numeric values are rejected.

---

## 5. Limitations

* **PostgreSQL `NUMERIC`/`DECIMAL` columns cannot be decoded.** A `rows` or `scalar` query that returns such a column fails with a "Failed to get float column" error. Cast in SQL, for example `SELECT price::float8` or `price::text`.
* Other PostgreSQL column types without a specific decoder are read as text; a type that cannot be read as text makes the query fail.
* `return_last_insert_id=true` on SQLite reports 0 instead of the new row id, because the id is read on a different pooled connection. Use `INSERT ... RETURNING id` with `query` instead (SQLite 3.35 and later).
* `schema` returns index, foreign key and constraint details for SQLite only.
* Transactions and pools do not span invocations (section 1).

---

## 6. Platform Support

Linux is the only supported and tested platform. PostgreSQL and MySQL need network access to the server.

---

## 7. Usage Guidance

* Use `params=` instead of building SQL strings in the shell.
* Keep credentials out of `dsn=` on shared hosts; set `DB_<ALIAS>_DSN` instead.
* Use `transaction` with `statements=` for multi-statement changes.
* Use `max_rows` to bound large results and check `meta.truncated`.
* Use `ping retries=<n>` as a readiness check in deployment scripts; it exits non-zero when the database is unreachable.

---

## 8. Implementation Notes

* Written in Rust on `sqlx` with a Tokio runtime.
* `params` and `statements` are parsed as JSON; all other arguments are strings that each verb parses and validates.
