//! `db://<driver>/<alias>.<verb>`: SQL on PostgreSQL, MySQL/MariaDB and
//! SQLite through sqlx, one connection per run.
//!
//! Every verb reads its arguments strictly (exit 2 on anything unknown or
//! malformed, before connecting), connects within `timeout_ms` and finishes
//! its work within the same deadline. At the deadline a running statement is
//! cancelled on the server (PostgreSQL `pg_cancel_backend`, MySQL `KILL
//! QUERY` from a second connection, SQLite's progress handler) and the verb
//! exits 124. Failures print `{"error":{"code","message"}}` on stdout and
//! `Error: [db.<code>] <message>` on stderr; DSNs and passwords are removed
//! from every message.

mod args;
mod conn;
mod introspect;
mod run;
mod sql;
mod values;

#[cfg(test)]
mod tests;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::{Status, error_line, exit},
};
use anyhow::{Result, bail};
use conn::{Redactor, Session, Spec};
use run::{Log, RowsOut};
use serde_json::{Map, Value, json};
use std::io::Write;
use std::time::Instant;
use url::Url;

/// Every error code the handle reports (without the `db.` prefix), each
/// documented in docs/Data_StateManagement/db.md.
pub const ERROR_CODES: &[&str] = &[
    "invalid_argument",
    "unknown_verb",
    "dsn_missing",
    "invalid_dsn",
    "connect_failed",
    "auth_failed",
    "tls_failed",
    "query_failed",
    "unsupported_column_type",
    "table_not_found",
    "transaction_failed",
    "ping_failed",
    "output_failed",
    "timeout",
];

/// Every argument `verb` accepts (its own, then the connection options), or
/// `None` for an unknown verb. The help usage lists exactly these.
pub fn verb_args(verb: &str) -> Option<Vec<&'static str>> {
    args::verb_options(verb).map(|_| args::accepted(verb))
}

/// A database driver (the URL host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Driver {
    Postgres,
    Mysql,
    Sqlite,
}

impl Driver {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "postgres" | "postgresql" => Some(Driver::Postgres),
            "mysql" | "mariadb" => Some(Driver::Mysql),
            "sqlite" => Some(Driver::Sqlite),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Driver::Postgres => "postgres",
            Driver::Mysql => "mysql",
            Driver::Sqlite => "sqlite",
        }
    }
}

/// A failure with its code (without `db.`), message, exit code and any
/// extra fields for the JSON error object.
#[derive(Debug, Clone)]
pub struct DbError {
    pub code: &'static str,
    pub message: String,
    pub exit: i32,
    pub extra: Map<String, Value>,
}

impl DbError {
    /// A failure (exit 1).
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            exit: exit::FAILED,
            extra: Map::new(),
        }
    }

    /// Invalid usage (exit 2, `db.invalid_argument`): nothing was done.
    pub fn usage(message: impl Into<String>) -> Self {
        Self::usage_code("invalid_argument", message)
    }

    /// Invalid usage with a specific code (exit 2).
    pub fn usage_code(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            exit: exit::USAGE,
            ..Self::new(code, message)
        }
    }

    /// The deadline passed (exit 124).
    pub fn timeout(message: impl Into<String>) -> Self {
        Self {
            exit: exit::TIMEOUT,
            ..Self::new("timeout", message)
        }
    }

    pub fn with(mut self, key: &str, value: Value) -> Self {
        self.extra.insert(key.to_string(), value);
        self
    }

    pub fn full_code(&self) -> String {
        format!("db.{}", self.code)
    }

    /// The `{"code","message",...}` object.
    pub fn object(&self) -> Value {
        let mut m = self.extra.clone();
        m.insert("code".into(), json!(self.full_code()));
        m.insert("message".into(), json!(self.message));
        Value::Object(m)
    }

    fn scrubbed(mut self, r: &Redactor) -> Self {
        self.message = r.scrub(&self.message);
        for v in self.extra.values_mut() {
            if let Value::String(s) = v {
                *s = r.scrub(s);
            }
        }
        self
    }
}

/// The usage of `verb`: its own options, then the connection options.
macro_rules! usage {
    ($verb:literal, $own:literal) => {
        concat!(
            "resh db://<driver>/<alias>.",
            $verb,
            $own,
            "\n",
            "  [dsn=<dsn>] [tls_mode=<mode>] [ca_file=<pem>] [timeout_ms=<ms>]\n  \
             [log_queries=true|false]"
        )
    };
}

/// Metadata for `resh db --help` and `resh db <verb> --help`.
static DB_HELP: HandleHelp = HandleHelp {
    description: "The db handle runs SQL on PostgreSQL, MySQL/MariaDB and SQLite and \
        prints the results as JSON. The target names a driver and an alias, such as \
        db://postgres/app, and the DSN comes from dsn= or the DB_<ALIAS>_DSN environment \
        variable. Each verb opens one connection for its work, binds params= values \
        instead of splicing them into the SQL, and stops at timeout_ms.",
    usage: "resh db://<driver>/<alias>.<verb> [key=value ...]",
    verbs: &[
        VerbHelp {
            name: "connect",
            definition: "Connects, reports the server version, database, user and whether \
                the session is encrypted, and disconnects.",
            detail: Some(VerbDetail {
                usage: usage!("connect", ""),
                example: "resh --json-pretty db://postgres/app.connect ca_file=ca.pem",
                example_output: Some(
                    r#"{
  "alias": "app",
  "database": "app",
  "driver": "postgres",
  "latency_ms": 14,
  "server_version": "17.2",
  "tls": true,
  "user": "app"
}

Shown with DB_APP_DSN set. driver is postgres, mysql (also MariaDB) or
sqlite. tls_mode: disable, allow (postgres), prefer, require, verify_ca or
verify_full. Only verify_ca and verify_full check the server certificate;
the others do not stop an impostor server. Without tls_mode (or an SSL
mode in the DSN), remote hosts use verify_full and localhost, loopback
addresses and Unix sockets use prefer. ca_file=<pem> adds a private CA
(verification stays on) and implies verify_full. timeout_ms (default
5000) covers connecting and the work; at the deadline a running statement
is cancelled and the exit code is 124.
log_queries=true writes each SQL statement sent to stderr."#,
                ),
            }),
        },
        VerbHelp {
            name: "ping",
            definition: "Connects and runs SELECT 1, retrying with a new connection on \
                failure, and reports the latency and number of attempts.",
            detail: Some(VerbDetail {
                usage: usage!(
                    "ping",
                    " [retries=<0-10>] [backoff_ms=<ms>]\n  [detailed=true|false]"
                ),
                example: "resh --json-pretty db://sqlite/app.ping dsn=sqlite:app.db retries=2",
                example_output: Some(
                    r#"{
  "alias": "app",
  "attempts": 1,
  "driver": "sqlite",
  "latency_ms": 3,
  "status": "ok"
}

timeout_ms (default 1000) limits each attempt. When every attempt fails,
status is "error", the error object gives the reason (with last_error when
detailed=true) and the exit code is 1, or 124 if the last attempt timed
out."#,
                ),
            }),
        },
        VerbHelp {
            name: "query",
            definition: "Runs one SQL statement with bound parameters and returns its \
                rows with column metadata, one scalar value, or the affected row count.",
            detail: Some(VerbDetail {
                usage: usage!(
                    "query",
                    " sql=<sql> [params=<json-array>]\n  [mode=rows|scalar|exec] \
                     [max_rows=<n>]"
                ),
                example: "resh db://sqlite/app.query 'sql=SELECT * FROM users WHERE id<?' params=[3]",
                example_output: Some(
                    r#"{
  "meta": {
    "columns": [
      { "name": "id", "type": "INTEGER" },
      { "name": "name", "type": "TEXT" }
    ],
    "row_count": 2,
    "truncated": false
  },
  "rows": [
    { "id": 1, "name": "alice" },
    { "id": 2, "name": "bob" }
  ]
}

Shown with --json-pretty and DB_APP_DSN=sqlite:app.db set.
Placeholders are ? (SQLite, MySQL) or $1, $2 (PostgreSQL); params items
are strings, numbers, booleans or null. Rows are streamed; max_rows
(default 1000) stops reading and sets truncated. mode=scalar returns value
(first column of the first row) and meta; mode=exec returns rows_affected.
NUMERIC/DECIMAL values are exact strings, binary values "base64:...",
timestamps ISO 8601. timeout_ms defaults to 5000."#,
                ),
            }),
        },
        VerbHelp {
            name: "exec",
            definition: "Runs one data-changing statement, such as INSERT, UPDATE or \
                DELETE, with bound parameters and reports the number of rows affected.",
            detail: Some(VerbDetail {
                usage: usage!(
                    "exec",
                    " sql=<sql> [params=<json-array>]\n  \
                     [return_last_insert_id=true|false]"
                ),
                example: "resh db://sqlite/app.exec 'sql=DELETE FROM sessions WHERE uid=?' params=[7]",
                example_output: Some(
                    r#"{
  "rows_affected": 3
}

Shown with --json-pretty and DB_APP_DSN=sqlite:app.db set.
return_last_insert_id=true adds last_insert_id on MySQL and SQLite; on
PostgreSQL use INSERT ... RETURNING id with query. There is no dry run:
the change is made at once. timeout_ms defaults to 5000."#,
                ),
            }),
        },
        VerbHelp {
            name: "tables",
            definition: "Lists the tables (and views) in the database, or describes one \
                table's columns when table= is given.",
            detail: Some(VerbDetail {
                usage: usage!(
                    "tables",
                    " [table=<name>] [schema=<name>]\n  \
                     [include_views=true|false] [include_system=true|false]\n  \
                     [max_tables=<n>]"
                ),
                example: "resh --json-pretty db://postgres/app.tables include_views=true",
                example_output: Some(
                    r#"{
  "meta": {
    "count": 2,
    "truncated": false
  },
  "tables": [
    { "name": "active_users", "schema": "public", "type": "VIEW" },
    { "name": "orders", "schema": "public", "type": "BASE TABLE" }
  ]
}

Shown with DB_APP_DSN set. Without schema=, PostgreSQL lists every
non-system schema, MySQL the DSN's database and SQLite every attached
database. max_tables defaults to 1000. With table= the output is a table
object and a columns array, as in schema."#,
                ),
            }),
        },
        VerbHelp {
            name: "schema",
            definition: "Describes a table's columns and primary key, plus the indexes, \
                foreign keys, unique constraints, checks and triggers selected by the \
                include flags.",
            detail: Some(VerbDetail {
                usage: usage!(
                    "schema",
                    " table=<name> [schema=<name>]\n  \
                     [include_indexes=true|false] [include_foreign_keys=true|false]\n  \
                     [include_unique_constraints=true|false]\n  \
                     [include_checks=true|false] [include_triggers=true|false]"
                ),
                example: "resh --json-pretty db://sqlite/app.schema table=users \
                    dsn=sqlite:app.db",
                example_output: Some(
                    r#"{
  "columns": [
    { "data_type": "INTEGER", "default": null, "is_nullable": false,
      "is_primary_key": true, "name": "id", "ordinal_position": 1 },
    { "data_type": "TEXT", "default": null, "is_nullable": false,
      "is_primary_key": false, "name": "email", "ordinal_position": 2 }
  ],
  "foreign_keys": [],
  "indexes": [
    { "columns": ["email"], "is_primary": false, "is_unique": true,
      "name": "idx_users_email" }
  ],
  "primary_key": { "columns": ["id"], "name": null },
  "table": { "name": "users", "schema": "main", "type": "BASE TABLE" },
  "unique_constraints": []
}

Indexes, foreign keys and unique constraints are included by default;
checks and triggers with include_checks=true and include_triggers=true.
Without schema=, PostgreSQL uses the search_path and MySQL the DSN's
database. SQLite names neither primary keys nor foreign keys (null)."#,
                ),
            }),
        },
        VerbHelp {
            name: "transaction",
            definition: "Runs a list of statements in one transaction, committing only if \
                every statement succeeds and rolling back otherwise.",
            detail: Some(VerbDetail {
                usage: usage!(
                    "transaction",
                    " statements=<json-array> [action=run]\n  \
                     [isolation=<level>] [read_only=true|false]"
                ),
                example: "resh db://sqlite/db.transaction 'statements=[\"DELETE FROM a\",\"DELETE FROM b\"]'",
                example_output: Some(
                    r#"{
  "action": "run",
  "alias": "db",
  "committed": true,
  "driver": "sqlite",
  "results": [
    { "index": 0, "rows_affected": 3 },
    { "index": 1, "rows_affected": 1 }
  ],
  "status": "ok"
}

Shown with --json-pretty and DB_DB_DSN=sqlite:app.db set.
Items are SQL strings or {"sql":...,"params":[...]} objects, one
statement each. If one fails, all are rolled back and the error names its
index. isolation: default, read_uncommitted, read_committed,
repeatable_read or serializable (SQLite: default or serializable).
read_only=true makes the transaction read-only. timeout_ms (default 5000)
covers the whole transaction; at the deadline nothing is committed,
unless COMMIT itself was running (the outcome is then unknown)."#,
                ),
            }),
        },
    ],
};

/// The db handle for one target.
#[derive(Debug)]
pub struct DbHandle {
    driver: Driver,
    alias: String,
    /// The target itself asked for help (`db://--help`).
    help_target: bool,
}

/// One timed run: the runtime for one verb.
fn runtime() -> std::result::Result<tokio::runtime::Runtime, DbError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| DbError::new("connect_failed", format!("cannot start the runtime: {e}")))
}

impl DbHandle {
    pub fn from_url(url: &Url) -> Result<Self> {
        let host = url.host_str().unwrap_or("");
        let path = url.path();
        if crate::core::help::is_help_flag(host) || crate::core::help::is_help_flag(path) {
            return Ok(Self {
                driver: Driver::Sqlite,
                alias: String::new(),
                help_target: true,
            });
        }
        let Some(driver) = Driver::parse(host) else {
            if host.is_empty() {
                bail!("db targets are db://<driver>/<alias> (driver postgres, mysql or sqlite)");
            }
            bail!("unknown db driver {host:?}: use postgres, mysql or sqlite");
        };
        let alias = path.trim_start_matches('/');
        if alias.is_empty() {
            bail!("db targets are db://<driver>/<alias>; the alias is missing");
        }
        if alias.len() > 64
            || !alias
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            bail!(
                "invalid db alias {alias:?}: use up to 64 letters, digits, _ and - \
                 (it names DB_<ALIAS>_DSN)"
            );
        }
        Ok(Self {
            driver,
            alias: alias.to_string(),
            help_target: false,
        })
    }

    /// `Some(topic)` when the call asks for help: the verb is `help`,
    /// `--help` or `-h`, or `--help=<verb>`, or a bare help flag is among
    /// the arguments, or the target was a help flag.
    fn help_topic<'a>(&self, verb: &'a str, args: &'a Args) -> Option<Option<&'a str>> {
        let from_args = || {
            args.get("verb")
                .map(|s| s.as_str())
                .filter(|s| !s.is_empty())
        };
        if verb == "help" || crate::core::help::is_help_flag(verb) || self.help_target {
            return Some(from_args());
        }
        if let Some(v) = verb.strip_prefix("--help=") {
            return Some(Some(v).filter(|s| !s.is_empty()));
        }
        if ["help", "h", "--help", "-h"]
            .iter()
            .any(|k| args.contains_key(*k))
        {
            return Some(Some(verb));
        }
        None
    }

    fn base(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("alias".into(), json!(self.alias));
        m.insert("driver".into(), json!(self.driver.name()));
        m
    }

    /// Runs `verb`, writing its result to `out`. Returns `Ok(true)` when the
    /// output was already written in full.
    fn execute(
        &self,
        verb: &str,
        a: &Args,
        out: &mut dyn Write,
        err: &mut dyn Write,
        partial: &mut bool,
    ) -> std::result::Result<Status, DbError> {
        args::check_names(verb, a)?;
        let r = args::Reader { args: a };
        let d = self.driver;
        let default_timeout = if verb == "ping" { 1000 } else { 5000 };
        // Verb arguments are checked before the connection settings, and
        // everything before connecting.
        enum Work {
            Connect,
            Ping(args::PingArgs),
            Query(args::QueryArgs),
            Exec(args::ExecArgs),
            Tables(args::TablesArgs),
            Schema(args::SchemaArgs),
            Tx(args::TxArgs),
        }
        let work = match verb {
            "connect" => Work::Connect,
            "ping" => Work::Ping(args::ping(r)?),
            "query" => Work::Query(args::query(r, d)?),
            "exec" => Work::Exec(args::exec(r, d)?),
            "tables" => Work::Tables(args::tables(r)?),
            "schema" => Work::Schema(args::schema(r)?),
            "transaction" => Work::Tx(args::transaction(r, d)?),
            _ => unreachable!("verb checked by the caller"),
        };
        let c = args::common(r, d, &self.alias, default_timeout)?;
        let spec = || Spec::new(d, &c.dsn, c.tls_mode, c.ca_pem.clone(), c.timeout);
        let mut log = Log {
            on: c.log_queries,
            err,
        };
        let rt = runtime()?;
        let started = Instant::now();
        let print = |out: &mut dyn Write, v: Value| -> std::result::Result<Status, DbError> {
            writeln!(out, "{v}")
                .and_then(|_| out.flush())
                .map_err(|e| {
                    DbError::new("output_failed", format!("cannot write the result: {e}"))
                })?;
            Ok(Status::ok())
        };

        if let Work::Ping(p) = &work {
            return self.ping(&rt, p, spec, c.timeout, &mut log, out);
        }

        rt.block_on(async {
            let mut s = Session::open(spec()?, c.timeout).await?;
            match work {
                Work::Connect => {
                    let mut m = run::connect(&mut s, &mut log).await?;
                    m.extend(self.base());
                    m.insert(
                        "latency_ms".into(),
                        json!(started.elapsed().as_millis() as u64),
                    );
                    print(out, Value::Object(m))
                }
                Work::Query(q) => {
                    let mut rows = RowsOut::new(out);
                    match run::query(&mut s, &q, &mut rows, &mut log).await {
                        Ok(None) => {
                            rows.finish()?;
                            Ok(Status::ok())
                        }
                        Ok(Some(v)) => {
                            drop(rows);
                            print(out, v)
                        }
                        Err(e) => {
                            // Rows already written: the caller ends the
                            // document with the error object.
                            *partial = rows.close_partial();
                            Err(e)
                        }
                    }
                }
                Work::Exec(x) => {
                    let v = run::exec(&mut s, &x, &mut log).await?;
                    print(out, v)
                }
                Work::Tables(t) => {
                    let v = introspect::tables(&mut s, &t, &mut log).await?;
                    print(out, v)
                }
                Work::Schema(t) => {
                    let v = introspect::schema(&mut s, &t, &mut log).await?;
                    print(out, v)
                }
                Work::Tx(t) => {
                    let results = run::transaction(&mut s, d, &t, &mut log).await?;
                    let mut m = self.base();
                    m.insert("action".into(), json!("run"));
                    m.insert("committed".into(), json!(true));
                    m.insert("results".into(), json!(results));
                    m.insert("status".into(), json!("ok"));
                    print(out, Value::Object(m))
                }
                Work::Ping(_) => unreachable!(),
            }
        })
    }

    /// `ping`: each attempt connects and runs SELECT 1 within timeout_ms.
    fn ping(
        &self,
        rt: &tokio::runtime::Runtime,
        p: &args::PingArgs,
        spec: impl Fn() -> std::result::Result<Spec, DbError>,
        timeout: std::time::Duration,
        log: &mut Log<'_>,
        out: &mut dyn Write,
    ) -> std::result::Result<Status, DbError> {
        let attempts = 1 + p.retries;
        let mut last: Option<DbError> = None;
        for attempt in 1..=attempts {
            let started = Instant::now();
            let res = rt.block_on(async {
                let mut s = Session::open(spec()?, timeout).await?;
                run::ping(&mut s, log).await
            });
            match res {
                Ok(()) => {
                    let mut m = self.base();
                    m.insert("attempts".into(), json!(attempt));
                    m.insert(
                        "latency_ms".into(),
                        json!(started.elapsed().as_millis() as u64),
                    );
                    m.insert("status".into(), json!("ok"));
                    writeln!(out, "{}", Value::Object(m)).map_err(|e| {
                        DbError::new("output_failed", format!("cannot write the result: {e}"))
                    })?;
                    return Ok(Status::ok());
                }
                // A DSN that cannot be used will not work on a retry.
                Err(e) if e.exit == exit::USAGE => return Err(e),
                Err(e) => last = Some(e),
            }
            if attempt < attempts {
                std::thread::sleep(p.backoff);
            }
        }
        let last = last.expect("at least one attempt");
        let code = match last.code {
            "timeout" | "auth_failed" | "tls_failed" => last.code,
            _ => "ping_failed",
        };
        let mut e = DbError::new(
            code,
            format!("ping failed after {attempts} attempt(s): {}", last.message),
        )
        .with("attempts", json!(attempts));
        e.exit = last.exit;
        if p.detailed {
            e = e.with("last_error", json!(last.message));
        }
        Err(e)
    }

    /// Reports a failure: the JSON error on stdout (runtime failures only)
    /// and the standard line on stderr.
    fn report(&self, verb: &str, e: DbError, partial: bool, io: &mut IoStreams) -> Result<Status> {
        if e.exit != exit::USAGE && !partial {
            let doc = if verb == "ping" {
                let mut m = self.base();
                m.insert("status".into(), json!("error"));
                if let Some(a) = e.extra.get("attempts") {
                    m.insert("attempts".into(), a.clone());
                }
                let mut obj = e.clone();
                obj.extra.remove("attempts");
                m.insert("error".into(), obj.object());
                Value::Object(m)
            } else {
                json!({ "error": e.object() })
            };
            writeln!(io.stdout, "{doc}")?;
        }
        io.stdout.flush()?;
        writeln!(io.stderr, "{}", error_line(&e.full_code(), &e.message))?;
        Ok(Status::coded(e.exit, &e.full_code(), &e.message))
    }
}

impl Handle for DbHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &[
            "connect",
            "ping",
            "query",
            "exec",
            "tables",
            "schema",
            "transaction",
        ]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&DB_HELP)
    }

    fn call(&self, verb: &str, a: &Args, io: &mut IoStreams) -> Result<Status> {
        if let Some(topic) = self.help_topic(verb, a) {
            let text = crate::core::help::render_legacy("db", &DB_HELP, self.verbs(), topic);
            write!(io.stdout, "{text}")?;
            return Ok(Status::ok());
        }
        if args::verb_options(verb).is_none() {
            let e = DbError::usage_code(
                "unknown_verb",
                format!(
                    "unknown verb for db: {verb}{} (verbs: {})",
                    args::did_you_mean(verb, self.verbs()),
                    self.verbs().join(", ")
                ),
            );
            return self.report(verb, e, false, io);
        }
        // Secrets of the DSN in use, removed from every message.
        let dsn = a
            .get("dsn")
            .cloned()
            .or_else(|| std::env::var(conn::env_var(&self.alias)).ok())
            .unwrap_or_default();
        let redactor = Redactor::for_dsn(&dsn);
        let mut partial = false;
        let IoStreams { stdout, stderr, .. } = io;
        let res = self.execute(verb, a, *stdout, *stderr, &mut partial);
        match res {
            Ok(st) => Ok(st),
            Err(e) => {
                let e = e.scrubbed(&redactor);
                if partial {
                    // Close the streamed rows document with the error.
                    let _ = writeln!(io.stdout, ",\"error\":{}}}", e.object());
                }
                self.report(verb, e, partial, io)
            }
        }
    }
}

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("db", |u| Ok(Box::new(DbHandle::from_url(u)?)));
    reg.set_probe_url("db", "db://sqlite/resh-help-probe");
}
