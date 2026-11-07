# Resource Shell (resh) – Database Handle Documentation

## 1. Overview

Resource Shell (resh) is a command-line tool that runs operations on resources named by URLs.

The `db://` handle runs SQL against PostgreSQL, MySQL/MariaDB and SQLite through `sqlx` and prints the results as JSON. It runs queries and data-changing statements with bound parameters, lists tables, describes a table's schema, checks connectivity, and runs a list of statements in one transaction.

All operations use this form:

```text
resh db://<driver>/<alias>.<verb> [key=value ...]
```

* `driver` is `postgres` (or `postgresql`), `mysql` (or `mariadb`; MariaDB uses the same driver) or `sqlite`.
* `alias` is a label of up to 64 letters, digits, `_` and `-`. It names the environment variable `DB_<ALIAS>_DSN` (alias in upper case, `-` as `_`) that is read when `dsn=` is not given.

Each verb opens **one connection**, does its work and closes the connection. Nothing is kept between `resh` runs: there is no connection pool, and a transaction lives only inside one `transaction` call.

---

## 2. Design Notes

* Arguments are checked strictly before anything connects: an unknown argument, a malformed value or a combination that cannot work is refused with exit code 2 and `db.invalid_argument`, with a "did you mean" hint for a misspelled name.
* `params=` values are always **bound** to placeholders, never spliced into the SQL. Table and schema names (`tables`, `schema`) are bound as values too.
* `sql=` (and each `transaction` item) must be exactly one statement. The check knows each database's quoting and comments; a trailing `;` is allowed.
* `timeout_ms` covers connecting **and** the work. At the deadline the running statement is stopped on the server: PostgreSQL gets `pg_cancel_backend` and MySQL/MariaDB `KILL QUERY` from a second connection; SQLite interrupts it. The exit code is then 124.
* DSNs and passwords never appear in output or error messages; they are replaced by `***`.
* There is no dry-run mode. `exec`, `transaction` and data-changing `query` statements change the database at once (`dry_run=true` is refused).

---

## 3. Command Syntax

### 3.1 DSNs

| Driver     | Example DSN |
| ---------- | ----------- |
| `sqlite`   | `sqlite:app.db` (relative to the working directory), `sqlite:/var/lib/app/app.db`, `sqlite::memory:` |
| `postgres` | `postgresql://user@db.example.com:5432/app` (`postgres://` also works) |
| `mysql`    | `mysql://user@db.example.com:3306/app` (`mariadb://` also works) |

A SQLite file must already exist; add `?mode=rwc` (for example `'dsn=sqlite:new.db?mode=rwc'`) to create it. Special characters in a user name or password must be percent-encoded (`$` as `%24`, `@` as `%40`, `#` as `%23`, `%` as `%25`), and the DSN should be quoted in single quotes.

**Security note:** a password in `dsn=` is visible to other local users in the process list while resh runs, and may be kept in shell history. Prefer `DB_<ALIAS>_DSN` in the environment. resh does not store DSNs or passwords.

### 3.2 Options every verb takes

| Option | Meaning |
| ------ | ------- |
| `dsn=<dsn>` | The connection string. Default: `DB_<ALIAS>_DSN`. |
| `tls_mode=<mode>` | `disable`, `allow` (PostgreSQL only), `prefer`, `require`, `verify_ca` or `verify_full`. Overrides any SSL mode in the DSN. SQLite accepts only `disable`. |
| `ca_file=<pem>` | PEM file of CA certificates to trust in addition to the built-in roots, for a private CA. Verification stays on. Without `tls_mode` it implies `verify_full`; with `disable`, `allow`, `prefer` or `require` it is refused. Not for SQLite. |
| `timeout_ms=<ms>` | Deadline for connecting and the work, 1 to 86400000. Default 5000 (ping: 1000 per attempt). |
| `log_queries=true` | Writes each SQL statement resh sends to stderr as `db: sql: <statement>` (the text only, never parameter values). |

**TLS.** Only `verify_ca` (the certificate chains to a trusted CA) and `verify_full` (also checks that the certificate names the host) authenticate the server. In this version `verify_ca` also checks the host name, like `verify_full` (a limitation of sqlx 0.8.6 with the rustls in use; it fails closed): a certificate that does not name the host given in the DSN is refused. `prefer` (the PostgreSQL and MySQL default when neither `tls_mode` nor the DSN sets a mode), `require` and `allow` encrypt without checking the certificate: they protect against eavesdropping but **not** against an impostor server, and are insecure on untrusted networks. Use `tls_mode=verify_full`, with `ca_file=` for a private CA.

### 3.3 Example commands

```bash
resh db://sqlite/app.query 'sql=SELECT id, email FROM users' dsn=sqlite:app.db
```

```bash
export DB_STOCKS_DSN='mysql://report@db.example.com:3306/stocks'
resh db://mysql/stocks.query 'sql=SELECT COUNT(*) FROM stocks' mode=scalar tls_mode=verify_full
```

```bash
resh db://postgres/app.exec 'sql=INSERT INTO users (email) VALUES ($1)' 'params=["alice@example.com"]' dsn=postgresql://app@localhost:5432/appdb
```

### 3.4 Output and errors

Each verb prints one JSON object on stdout. A failure prints an error object on stdout and the standard line on stderr:

```json
{"error":{"code":"db.query_failed","message":"error returned from database: (code: 1) no such table: nope"}}
```

```text
Error: [db.query_failed] error returned from database: (code: 1) no such table: nope
```

Invalid usage (exit 2) prints only the stderr line.

Exit codes: 0 success; 1 the operation failed (connection, login, TLS, SQL error, missing table); 2 invalid usage, nothing was done; 124 `timeout_ms` passed (the statement was stopped, nothing was committed, except that an unfinished `COMMIT` leaves the outcome unknown).

| Code | Exit | Meaning |
| ---- | ---- | ------- |
| `db.invalid_argument` | 2 | Unknown argument, malformed value, or options that cannot be combined. |
| `db.unknown_verb` | 2 | The verb does not exist. |
| `db.dsn_missing` | 2 | Neither `dsn=` nor `DB_<ALIAS>_DSN` is set. |
| `db.invalid_dsn` | 2 | The DSN is not valid for the driver (it is not shown). |
| `db.connect_failed` | 1 | The server could not be reached, or the SQLite file could not be opened. |
| `db.auth_failed` | 1 | The server refused the login. |
| `db.tls_failed` | 1 | TLS failed: the server has no TLS, or its certificate is not trusted or does not name the host. |
| `db.query_failed` | 1 | The statement (or a catalog query of `tables`/`schema`) failed. |
| `db.unsupported_column_type` | 1 | A result column has a type with no JSON form; cast it in SQL (the message suggests how). |
| `db.table_not_found` | 1 | `tables table=` or `schema table=` names no table or view. |
| `db.transaction_failed` | 1 | A transaction statement or the commit failed; everything was rolled back. The error has `index` and `rolled_back`. |
| `db.ping_failed` | 1 | Every ping attempt failed. |
| `db.output_failed` | 1 | The result could not be written to stdout. |
| `db.timeout` | 124 | `timeout_ms` passed; the running statement was cancelled. |

---

## 4. Verbs

### 4.1 connect

Connects, reports the server and the session, and disconnects. Use it to check a DSN and TLS settings.

```bash
resh --json-pretty db://postgres/app.connect tls_mode=verify_full
```

```json
{
  "alias": "app",
  "database": "app",
  "driver": "postgres",
  "latency_ms": 14,
  "server_version": "17.2",
  "tls": true,
  "user": "app"
}
```

`tls` tells whether the session is encrypted. SQLite reports `database` `"main"`, `user` `null` and `tls` `false`.

### 4.2 ping

Connects and runs `SELECT 1`. Each attempt uses a new connection and must finish within `timeout_ms` (default 1000). Arguments: `retries` (0-10, default 0), `backoff_ms` (pause between attempts, 0-60000, default 100), `detailed` (adds `last_error` to the error object).

```bash
resh db://postgres/app.ping timeout_ms=2000 retries=5 backoff_ms=1000
```

Success: `{"alias","attempts","driver","latency_ms","status":"ok"}`. When every attempt fails, `status` is `"error"`, `attempts` is the number made, the `error` object gives the last reason, and the exit code is 1 (`db.ping_failed`, or `db.auth_failed`/`db.tls_failed` when that was the reason) or 124 when the last attempt timed out. This makes `ping` a readiness check for deployment scripts.

### 4.3 query

Runs one SQL statement. Arguments: `sql` (required), `params` (JSON array), `mode` (`rows`, `scalar` or `exec`; default `rows`), `max_rows` (1-1000000, default 1000; not with `mode=exec`).

* `mode=rows` returns `rows` and `meta` (`columns` with `name` and `type`, `row_count`, `truncated`). Rows are written as they arrive; at `max_rows` reading stops and `truncated` is true. If the statement fails or times out after rows were written, the document still ends correctly, with the rows so far, their `meta` and an `error` object.
* `mode=scalar` returns `value` (first column of the first row, `null` when there are no rows) and `meta`.
* `mode=exec` returns `rows_affected`.

`query` in `rows` mode (SQLite output, shown pretty-printed):

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

**Values.** Integers, floats, booleans, text and JSON columns become the matching JSON values. Exact decimals (PostgreSQL `NUMERIC`, MySQL `DECIMAL`) are strings with every digit (`"12.50"`). Binary values are `"base64:<data>"`. Timestamps are ISO 8601 (`"2024-05-01T12:30:00"`; PostgreSQL `timestamptz` with `Z`), dates `"2024-05-01"`, times `"12:30:00"`. PostgreSQL `uuid`, `inet`/`cidr`, `macaddr`, enums and arrays of common types are supported; `interval` is `{"months","days","microseconds"}`. NaN and infinite floats are the strings `"NaN"`, `"Infinity"`, `"-Infinity"`. A column of any other type fails with `db.unsupported_column_type`; cast it in SQL (`col::text`, `CAST(col AS CHAR)`). MySQL marks text with a binary collation (such as MariaDB `JSON` or `utf8mb4_bin` columns) like binary data, so for `BINARY`/`VARBINARY`/`BLOB` columns valid UTF-8 is shown as text and anything else as base64. When two result columns have the same name, the later ones get `_2`, `_3`, ... suffixes.

### 4.4 exec

Runs one data-changing statement and returns `rows_affected`. Arguments: `sql`, `params`, `return_last_insert_id`.

```bash
resh db://sqlite/app.exec 'sql=DELETE FROM sessions WHERE user_id = ?' 'params=[7]' dsn=sqlite:app.db
```

```json
{ "rows_affected": 3 }
```

`return_last_insert_id=true` adds `last_insert_id` (MySQL `LAST_INSERT_ID()`, SQLite rowid). PostgreSQL has no such value: the option is refused there; use `INSERT ... RETURNING id` with `query`.

### 4.5 tables

Lists tables, or describes one table's columns when `table=` is given. Arguments: `table`, `schema`, `include_views`, `include_system`, `max_tables` (1-100000, default 1000). `include_views`, `include_system` and `max_tables` apply to the list only.

```bash
resh --json-pretty db://sqlite/app.tables dsn=sqlite:app.db
```

```json
{
  "meta": { "count": 1, "truncated": false },
  "tables": [ { "name": "users", "schema": "main", "type": "BASE TABLE" } ]
}
```

Without `schema=`: PostgreSQL lists every schema except `pg_catalog`, `information_schema` and the toast/temp schemas (`include_system=true` adds them); MySQL lists the DSN's database (`include_system=true` adds `mysql`, `information_schema`, `performance_schema` and `sys`); SQLite lists every attached database (`include_system=true` adds the `sqlite_*` tables). Types: `BASE TABLE`, `VIEW`, PostgreSQL `MATERIALIZED VIEW` and `FOREIGN TABLE`, SQLite `VIRTUAL TABLE`, MySQL `SYSTEM VIEW`.

With `table=` the output has a `table` object and a `columns` array, as in `schema`.

### 4.6 schema

Describes a table: `table`, `columns` (`name`, `data_type`, `is_nullable`, `is_primary_key`, `default`, `ordinal_position`), `primary_key` (`{"name","columns"}` or `null`), and the sections selected by `include_indexes`, `include_foreign_keys`, `include_unique_constraints` (all three default true), `include_checks` and `include_triggers` (default false). Arguments also include `table` (required) and `schema`.

```bash
resh db://postgres/app.schema table=users include_checks=true dsn=postgresql://app@localhost:5432/appdb
```

* `indexes`: `[{"name","columns","is_unique","is_primary"}]` (an expression column is shown as the expression on PostgreSQL, `null` on SQLite, `""` on MySQL).
* `foreign_keys`: `[{"name","columns","referenced_table":{"schema","name"},"referenced_columns","on_update","on_delete"}]`.
* `unique_constraints`: `[{"name","columns"}]`.
* `checks`: `[{"name","expression"}]`.
* `triggers`: `[{"name","timing","events","definition"}]`.

Without `schema=`, PostgreSQL finds the table through the `search_path`, MySQL in the DSN's database and SQLite in `temp`, then `main`, then attached databases. `data_type` is the full type (`character varying(20)`, `varchar(20)`). SQLite does not name primary keys or foreign keys (`null`), and its checks are read from the `CREATE TABLE` text. On MariaDB, `JSON` columns have an automatic `json_valid` check.

### 4.7 transaction

Runs every statement in `statements=` inside one transaction, commits if all succeed, and rolls back otherwise. Items are SQL strings or `{"sql": ..., "params": [...]}` objects, one statement each.

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

If a statement fails, everything is rolled back and the `db.transaction_failed` error has the failing statement's `index` and `rolled_back`. `timeout_ms` (default 5000) covers the whole transaction: at the deadline the running statement is cancelled and nothing is committed; only a `COMMIT` that was already sent leaves the outcome unknown (the message says so).

Other arguments:

* `isolation`: `default`, `read_uncommitted`, `read_committed`, `repeatable_read`, `serializable`. PostgreSQL: `BEGIN ISOLATION LEVEL ...`; MySQL: `SET TRANSACTION ISOLATION LEVEL ...` before `START TRANSACTION`. SQLite transactions are always serializable, so only `default` and `serializable` are accepted there.
* `read_only=true`: PostgreSQL `BEGIN ... READ ONLY`, MySQL `START TRANSACTION READ ONLY`, SQLite `PRAGMA query_only`. Writes then fail with `db.transaction_failed`.
* `action=run` is the only action (the default). A transaction cannot outlive one resh run, so `begin`, `commit` and `rollback` are refused.

### 4.8 Parameter binding

Placeholders follow the database: `?` for SQLite and MySQL, `$1`, `$2`, ... for PostgreSQL. `params=` is a JSON array; strings, numbers, booleans and `null` are bound with their JSON types (integers as 64-bit integers, other numbers as double precision). Arrays, objects and integers beyond the signed 64-bit range are refused. On PostgreSQL a string is sent as `text` and `null` as a null `text`; where the column has another type, cast the placeholder (`$1::timestamptz`, `$1::int`).

```bash
resh db://sqlite/app.query 'sql=SELECT * FROM users WHERE id = ?' 'params=[1]' dsn=sqlite:app.db
```

---

## 5. Limitations

* Strings are bound as `text` on PostgreSQL, so `$1` must be cast where another type is expected (section 4.8).
* `tls_mode=verify_ca` also requires the certificate to name the host (section 3.2).
* On MySQL, a statement the prepared-statement protocol does not support (error 1295) is retried as plain text when it has no `params`. MySQL 8 with binary logging needs `log_bin_trust_function_creators` (or the SUPER privilege) for `CREATE TRIGGER` and `CREATE FUNCTION`.
* Types without a JSON form (for example PostgreSQL geometric types, ranges, `timetz`) must be cast in SQL.
* `row_count` is the number of rows returned; when `truncated` is true the full result size is not known.
* A transaction and a connection never span resh runs.

---

## 6. Platform Support

Linux is the only supported and tested platform. PostgreSQL 17, MySQL 8.4 and MariaDB 11 are tested in containers, with and without TLS.

---

## 7. Usage Guidance

* Use `params=` instead of building SQL strings in the shell.
* Keep credentials out of `dsn=` on shared hosts; set `DB_<ALIAS>_DSN` instead.
* Use `tls_mode=verify_full` (with `ca_file=` for a private CA) for servers reached over a network.
* Use `transaction` with `statements=` for multi-statement changes.
* Use `max_rows` to bound large results and check `meta.truncated`.
* Use `ping retries=<n>` as a readiness check in deployment scripts; it exits non-zero when the database is unreachable.

---

## 8. Implementation Notes

* Written in Rust on `sqlx` with a Tokio runtime; TLS uses rustls with the webpki root certificates.
* PostgreSQL statements use the extended protocol, MySQL statements prepared statements; SQLite statements run on the bundled SQLite.
