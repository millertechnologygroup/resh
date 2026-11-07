//! The work of connect, query, exec and transaction on an open session.

use super::args::{ExecArgs, Isolation, Mode, QueryArgs, TxArgs};
use super::conn::{Conn, Session};
use super::values::{JsonRow, Param, bind_params};
use super::{DbError, Driver};
use futures_util::{Stream, TryStreamExt};
use serde_json::{Map, Value, json};
use std::cell::Cell;
use std::io::Write;

/// Writes each SQL statement resh sends to stderr when `log_queries=true`
/// (the text only, never parameter values).
pub struct Log<'a> {
    pub on: bool,
    pub err: &'a mut dyn Write,
}

impl Log<'_> {
    pub fn sql(&mut self, sql: &str) {
        if self.on {
            let line = sql.trim().replace(['\n', '\r'], " ");
            let _ = writeln!(self.err, "db: sql: {line}");
        }
    }
}

/// Classifies a statement failure; a SQLite statement stopped by the
/// deadline's progress handler becomes `interrupted` (turned into a timeout
/// by `Control::within`).
pub fn stmt_error(code: &'static str, e: sqlx::Error) -> DbError {
    if let sqlx::Error::Database(d) = &e {
        if d.code().as_deref() == Some("9") || d.message().contains("interrupted") {
            return DbError::new("interrupted", e.to_string());
        }
    }
    DbError::new(code, e.to_string())
}

fn io_err(e: std::io::Error) -> DbError {
    DbError::new("output_failed", format!("cannot write the result: {e}"))
}

/// Streams `{"rows":[...],"meta":{...}}` to stdout as rows arrive.
pub struct RowsOut<'a> {
    out: &'a mut dyn Write,
    started: bool,
    n: u64,
    columns: Option<Vec<Value>>,
    truncated: bool,
}

impl<'a> RowsOut<'a> {
    pub fn new(out: &'a mut dyn Write) -> Self {
        Self {
            out,
            started: false,
            n: 0,
            columns: None,
            truncated: false,
        }
    }

    fn push<R: JsonRow>(&mut self, row: &R) -> Result<(), DbError> {
        if self.columns.is_none() {
            self.columns = Some(row.column_meta());
        }
        let obj = Value::Object(row.to_json()?);
        let sep = if self.started { "," } else { "{\"rows\":[" };
        write!(self.out, "{sep}{obj}").map_err(io_err)?;
        self.started = true;
        self.n += 1;
        Ok(())
    }

    fn meta(&self) -> Value {
        json!({
            "columns": self.columns.clone().unwrap_or_default(),
            "row_count": self.n,
            "truncated": self.truncated,
        })
    }

    /// Ends the JSON document.
    pub fn finish(&mut self) -> Result<(), DbError> {
        if !self.started {
            write!(self.out, "{{\"rows\":[").map_err(io_err)?;
        }
        writeln!(self.out, "],\"meta\":{}}}", self.meta()).map_err(io_err)?;
        self.out.flush().map_err(io_err)
    }

    /// After a failure: when rows were already written, closes the rows
    /// array and writes their meta, leaving the document open for the
    /// error object, and returns true. Returns false when nothing was
    /// written yet.
    pub fn close_partial(&mut self) -> bool {
        if !self.started {
            return false;
        }
        let _ = write!(self.out, "],\"meta\":{}", self.meta());
        true
    }
}

/// A failure while reading rows: the database's own error (which may call
/// for a retry) or one of ours.
enum Fail {
    Sql(sqlx::Error),
    Db(DbError),
}

impl From<DbError> for Fail {
    fn from(e: DbError) -> Self {
        Fail::Db(e)
    }
}

impl Fail {
    fn db(self) -> DbError {
        match self {
            Fail::Sql(e) => stmt_error("query_failed", e),
            Fail::Db(e) => e,
        }
    }
}

/// MySQL refuses some statements in the prepared-statement protocol
/// (error 1295); those run as plain text when they have no parameters.
fn unpreparable(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::Database(d) => d
            .try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
            .is_some_and(|m| m.number() == 1295),
        _ => false,
    }
}

/// Reads rows until `max` are written; one more row marks `truncated`.
async fn drain<S, R>(mut rows: S, max: u64, out: &mut RowsOut<'_>) -> Result<(), Fail>
where
    S: Stream<Item = Result<R, sqlx::Error>> + Unpin,
    R: JsonRow,
{
    while let Some(row) = rows.try_next().await.map_err(Fail::Sql)? {
        if out.n == max {
            out.truncated = true;
            break;
        }
        out.push(&row)?;
    }
    Ok(())
}

/// The first column of the first row, the column list and the row count.
async fn scalar<S, R>(mut rows: S, max: u64) -> Result<Value, Fail>
where
    S: Stream<Item = Result<R, sqlx::Error>> + Unpin,
    R: JsonRow,
{
    let mut value = Value::Null;
    let mut columns = Vec::new();
    let mut n = 0u64;
    let mut truncated = false;
    while let Some(row) = rows.try_next().await.map_err(Fail::Sql)? {
        if n == max {
            truncated = true;
            break;
        }
        if n == 0 {
            columns = row.column_meta();
            if !row.columns().is_empty() {
                value = row.cell(0)?;
            }
        }
        n += 1;
    }
    Ok(json!({
        "value": value,
        "meta": {"columns": columns, "row_count": n, "truncated": truncated},
    }))
}

macro_rules! each_conn {
    ($conn:expr, $c:ident => $body:expr) => {
        match $conn {
            Conn::Pg($c) => $body,
            Conn::My($c) => $body,
            Conn::Lite($c) => $body,
        }
    };
}

/// `connect`: server version, database, user and whether the session is
/// encrypted.
pub async fn connect(s: &mut Session, log: &mut Log<'_>) -> Result<Map<String, Value>, DbError> {
    use sqlx::Row;
    let conn = &mut s.conn;
    let work = async {
        let fail = |e| stmt_error("connect_failed", e);
        let (version, database, user, tls): (String, Option<String>, Option<String>, bool) =
            match conn {
                Conn::Pg(c) => {
                    let sql = "SELECT current_setting('server_version'), \
                               current_database()::text, current_user::text, \
                               COALESCE((SELECT ssl FROM pg_stat_ssl \
                               WHERE pid = pg_backend_pid()), false)";
                    log.sql(sql);
                    let r = sqlx::query(sql).fetch_one(&mut *c).await.map_err(fail)?;
                    (r.get(0), r.get(1), r.get(2), r.get(3))
                }
                Conn::My(c) => {
                    let sql = "SELECT CAST(VERSION() AS CHAR), CAST(DATABASE() AS CHAR), \
                               CAST(CURRENT_USER() AS CHAR)";
                    log.sql(sql);
                    let r = sqlx::query(sql).fetch_one(&mut *c).await.map_err(fail)?;
                    let tls_sql = "SHOW SESSION STATUS LIKE 'Ssl_cipher'";
                    log.sql(tls_sql);
                    let st = sqlx::raw_sql(tls_sql)
                        .fetch_all(&mut *c)
                        .await
                        .map_err(fail)?;
                    let cipher: String = st
                        .first()
                        .and_then(|r| r.try_get::<String, _>(1).ok())
                        .unwrap_or_default();
                    (r.get(0), r.get(1), r.get(2), !cipher.is_empty())
                }
                Conn::Lite(c) => {
                    let sql = "SELECT sqlite_version()";
                    log.sql(sql);
                    let r = sqlx::query(sql).fetch_one(&mut *c).await.map_err(fail)?;
                    (r.get(0), Some("main".to_string()), None, false)
                }
            };
        let mut m = Map::new();
        m.insert("server_version".into(), json!(version));
        m.insert("database".into(), json!(database));
        m.insert("user".into(), json!(user));
        m.insert("tls".into(), json!(tls));
        Ok(m)
    };
    s.ctl.within("connect", work).await
}

/// `query`. Rows are streamed to `out`; scalar and exec results are
/// returned.
pub async fn query(
    s: &mut Session,
    a: &QueryArgs,
    out: &mut RowsOut<'_>,
    log: &mut Log<'_>,
) -> Result<Option<Value>, DbError> {
    let conn = &mut s.conn;
    log.sql(&a.sql);
    let work = async {
        match a.mode {
            Mode::Rows => {
                let res = each_conn!(&mut *conn, c => {
                    let q = bind_params!(sqlx::query(&a.sql).persistent(false), &a.params);
                    drain(q.fetch(&mut *c), a.max_rows, out).await
                });
                match (res, &mut *conn) {
                    (Err(Fail::Sql(e)), Conn::My(c))
                        if a.params.is_empty() && out.n == 0 && unpreparable(&e) =>
                    {
                        drain(sqlx::raw_sql(&a.sql).fetch(&mut *c), a.max_rows, out)
                            .await
                            .map_err(Fail::db)?
                    }
                    (r, _) => r.map_err(Fail::db)?,
                }
                Ok(None)
            }
            Mode::Scalar => {
                let res = each_conn!(&mut *conn, c => {
                    let q = bind_params!(sqlx::query(&a.sql).persistent(false), &a.params);
                    scalar(q.fetch(&mut *c), a.max_rows).await
                });
                Ok(Some(match (res, &mut *conn) {
                    (Err(Fail::Sql(e)), Conn::My(c)) if a.params.is_empty() && unpreparable(&e) => {
                        scalar(sqlx::raw_sql(&a.sql).fetch(&mut *c), a.max_rows)
                            .await
                            .map_err(Fail::db)?
                    }
                    (r, _) => r.map_err(Fail::db)?,
                }))
            }
            Mode::Exec => {
                let (n, _) = exec_one(conn, &a.sql, &a.params)
                    .await
                    .map_err(|e| stmt_error("query_failed", e))?;
                Ok(Some(json!({"rows_affected": n})))
            }
        }
    };
    s.ctl.within("the query", work).await
}

/// Runs one statement; returns rows affected and the last insert id
/// (MySQL and SQLite).
async fn exec_one(
    conn: &mut Conn,
    sql: &str,
    params: &[Param],
) -> Result<(u64, Option<i64>), sqlx::Error> {
    Ok(match conn {
        Conn::Pg(c) => {
            let r = bind_params!(sqlx::query(sql).persistent(false), params)
                .execute(&mut *c)
                .await?;
            (r.rows_affected(), None)
        }
        Conn::My(c) => {
            let res = bind_params!(sqlx::query(sql).persistent(false), params)
                .execute(&mut *c)
                .await;
            let r = match res {
                Err(e) if params.is_empty() && unpreparable(&e) => {
                    sqlx::raw_sql(sql).execute(&mut *c).await?
                }
                r => r?,
            };
            (r.rows_affected(), Some(r.last_insert_id() as i64))
        }
        Conn::Lite(c) => {
            let r = bind_params!(sqlx::query(sql).persistent(false), params)
                .execute(&mut *c)
                .await?;
            (r.rows_affected(), Some(r.last_insert_rowid()))
        }
    })
}

/// A transaction-control statement, sent as plain SQL.
async fn control(conn: &mut Conn, sql: &str) -> Result<(), sqlx::Error> {
    each_conn!(conn, c => sqlx::raw_sql(sql).execute(&mut *c).await.map(|_| ()))
}

/// `exec`.
pub async fn exec(s: &mut Session, a: &ExecArgs, log: &mut Log<'_>) -> Result<Value, DbError> {
    let conn = &mut s.conn;
    log.sql(&a.sql);
    let work = async {
        let (n, id) = exec_one(conn, &a.sql, &a.params)
            .await
            .map_err(|e| stmt_error("query_failed", e))?;
        let mut v = json!({"rows_affected": n});
        if a.return_last_insert_id {
            v["last_insert_id"] = json!(id);
        }
        Ok(v)
    };
    s.ctl.within("the statement", work).await
}

/// The statements that start a transaction with the requested isolation
/// and access mode.
pub fn begin_statements(driver: Driver, isolation: Isolation, read_only: bool) -> Vec<String> {
    match driver {
        Driver::Postgres => {
            let mut b = "BEGIN".to_string();
            if let Some(l) = isolation.sql() {
                b.push_str(" ISOLATION LEVEL ");
                b.push_str(l);
            }
            if read_only {
                b.push_str(" READ ONLY");
            }
            vec![b]
        }
        // MySQL sets the characteristics of the next transaction first.
        Driver::Mysql => {
            let mut v = Vec::new();
            if let Some(l) = isolation.sql() {
                v.push(format!("SET TRANSACTION ISOLATION LEVEL {l}"));
            }
            v.push(if read_only {
                "START TRANSACTION READ ONLY".to_string()
            } else {
                "START TRANSACTION".to_string()
            });
            v
        }
        // SQLite transactions are serializable; read-only is a connection
        // setting.
        Driver::Sqlite => {
            let mut v = Vec::new();
            if read_only {
                v.push("PRAGMA query_only = ON".to_string());
            }
            v.push("BEGIN".to_string());
            v
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Begin,
    Statement(usize),
    Commit,
}

/// `transaction`: begins, runs every statement, and commits; any failure
/// rolls everything back.
pub async fn transaction(
    s: &mut Session,
    driver: Driver,
    a: &TxArgs,
    log: &mut Log<'_>,
) -> Result<Vec<Value>, DbError> {
    let phase = Cell::new(Phase::Begin);
    let conn = &mut s.conn;
    let work = async {
        for b in begin_statements(driver, a.isolation, a.read_only) {
            log.sql(&b);
            control(conn, &b)
                .await
                .map_err(|e| stmt_error("transaction_failed", e))?;
        }
        let mut results = Vec::with_capacity(a.statements.len());
        for (i, (sql, params)) in a.statements.iter().enumerate() {
            phase.set(Phase::Statement(i));
            log.sql(sql);
            match exec_one(conn, sql, params).await {
                Ok((n, _)) => results.push(json!({"index": i, "rows_affected": n})),
                Err(e) => {
                    let err = stmt_error("transaction_failed", e);
                    if err.code == "interrupted" {
                        return Err(err);
                    }
                    log.sql("ROLLBACK");
                    let rolled_back = control(conn, "ROLLBACK").await.is_ok();
                    return Err(DbError::new(
                        "transaction_failed",
                        format!(
                            "statements[{i}] failed: {}; {}",
                            err.message,
                            if rolled_back {
                                "the transaction was rolled back"
                            } else {
                                "the rollback failed; the server discards the \
                                 transaction when the connection closes"
                            }
                        ),
                    )
                    .with("index", json!(i))
                    .with("rolled_back", json!(rolled_back)));
                }
            }
        }
        phase.set(Phase::Commit);
        log.sql("COMMIT");
        control(conn, "COMMIT").await.map_err(|e| {
            DbError::new("transaction_failed", format!("COMMIT failed: {e}"))
                .with("rolled_back", json!(true))
        })?;
        Ok(results)
    };
    match s.ctl.within("the transaction", work).await {
        Err(mut e) if e.code == "timeout" => {
            // The connection is closed without a commit, so the server
            // discards the transaction; only an unfinished COMMIT leaves the
            // outcome unknown.
            match phase.get() {
                Phase::Commit => {
                    e.message.push_str(
                        "; COMMIT was sent but did not finish, so the outcome is unknown",
                    );
                }
                Phase::Statement(i) => {
                    e.message.push_str(&format!(
                        "; statements[{i}] was running; nothing was committed"
                    ));
                    e = e.with("index", json!(i));
                }
                Phase::Begin => e.message.push_str("; nothing was committed"),
            }
            Err(e)
        }
        r => r,
    }
}

/// Runs `SELECT 1`.
pub async fn ping(s: &mut Session, log: &mut Log<'_>) -> Result<(), DbError> {
    let conn = &mut s.conn;
    log.sql("SELECT 1");
    let work = async {
        each_conn!(conn, c => sqlx::query("SELECT 1")
            .execute(&mut *c)
            .await
            .map(|_| ())
            .map_err(|e| stmt_error("ping_failed", e)))
    };
    s.ctl.within("the ping", work).await
}
