# MySQL Connection Guide for RESH

This guide covers connecting `resh db://mysql/...` to a MySQL or MariaDB
server. The full reference is `docs/Data_StateManagement/db.md`.

## How connections work

Every `db` verb opens one connection, runs its work and disconnects. Nothing
is kept between `resh` runs, so each command needs the DSN: pass `dsn=` or,
better, set `DB_<ALIAS>_DSN` (the alias in upper case, `-` as `_`).

```bash
export DB_STOCKS_DSN='mysql://appuser:secret@db.example.com:3306/stocks'
resh db://mysql/stocks.connect tls_mode=verify_full
resh db://mysql/stocks.query 'sql=SELECT symbol, price FROM stocks WHERE price > ?' 'params=[100]'
```

The environment variable keeps the password out of the process list and the
shell history; resh never prints it (errors show `***`).

## DSN format

```text
mysql://username:password@host:port/database
```

`mariadb://` works too. Special characters in the user name or password must
be percent-encoded, and the DSN should be in single quotes:

| Character | Encoded |
| --------- | ------- |
| `$`       | `%24`   |
| `@`       | `%40`   |
| `#`       | `%23`   |
| `%`       | `%25`   |
| space     | `%20`   |

```bash
export DB_APP_DSN='mysql://appuser:pa%24%24word@db.example.com:3306/app'
```

A DSN that is not a valid URL is refused with `db.invalid_dsn` (exit 2); the
DSN itself is not shown in the message.

## TLS

MySQL 8 and recent MariaDB offer TLS with a self-signed certificate by
default. The default `tls_mode=prefer` uses it without checking the
certificate, which does not protect against an impostor server. Use
`tls_mode=verify_full`, and `ca_file=` when the server certificate comes from
a private CA:

```bash
resh db://mysql/app.connect tls_mode=verify_full ca_file=/etc/ssl/private-ca.pem
```

`connect` reports `"tls": true` when the session is encrypted.

## Examples

```bash
# Check the connection
resh db://mysql/app.connect

# Readiness check: up to 10 attempts, 2 s apart
resh db://mysql/app.ping retries=10 backoff_ms=2000 timeout_ms=2000

# Select data with a bound parameter
resh db://mysql/app.query 'sql=SELECT id, name FROM users WHERE id = ?' 'params=[42]'

# Count rows
resh db://mysql/app.query 'sql=SELECT COUNT(*) FROM users' mode=scalar

# Insert and get the new id
resh db://mysql/app.exec 'sql=INSERT INTO users (name) VALUES (?)' 'params=["alice"]' return_last_insert_id=true

# Several changes atomically
resh db://mysql/app.transaction 'statements=["DELETE FROM sessions", "UPDATE users SET active = 0"]'
```

## Troubleshooting

| Error | Cause |
| ----- | ----- |
| `db.dsn_missing` | Neither `dsn=` nor `DB_<ALIAS>_DSN` is set. |
| `db.invalid_dsn` | The DSN is not a valid `mysql://` URL; percent-encode special characters. |
| `db.connect_failed` | The server is not reachable (check host, port, firewall). |
| `db.auth_failed` | Wrong user name or password, or the user may not connect from this host. |
| `db.tls_failed` | The server has no TLS, or its certificate is not trusted (`ca_file=`) or does not name the host. |
| `db.timeout` (exit 124) | `timeout_ms` (default 5000) passed; the statement was stopped with `KILL QUERY`. |
