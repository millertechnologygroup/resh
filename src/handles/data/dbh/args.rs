//! The arguments each db verb accepts, read strictly: an unknown name, a
//! malformed value or a combination that cannot work is refused (exit 2)
//! before anything connects.

use super::conn::{self, TlsMode};
use super::values::Param;
use super::{DbError, Driver, sql};
use crate::core::registry::Args;
use serde_json::Value;
use std::time::Duration;

/// Options every verb takes (connection, TLS, deadline, logging).
pub const COMMON: &[&str] = &["dsn", "tls_mode", "ca_file", "timeout_ms", "log_queries"];

/// The options of `verb` besides [`COMMON`], or `None` for an unknown verb.
pub fn verb_options(verb: &str) -> Option<&'static [&'static str]> {
    Some(match verb {
        "connect" => &[],
        "ping" => &["retries", "backoff_ms", "detailed"],
        "query" => &["sql", "params", "mode", "max_rows"],
        "exec" => &["sql", "params", "return_last_insert_id"],
        "tables" => &[
            "table",
            "schema",
            "include_views",
            "include_system",
            "max_tables",
        ],
        "schema" => &[
            "table",
            "schema",
            "include_indexes",
            "include_foreign_keys",
            "include_unique_constraints",
            "include_checks",
            "include_triggers",
        ],
        "transaction" => &["statements", "action", "isolation", "read_only"],
        _ => return None,
    })
}

/// Every option `verb` accepts.
pub fn accepted(verb: &str) -> Vec<&'static str> {
    let mut v = verb_options(verb).unwrap_or(&[]).to_vec();
    v.extend_from_slice(COMMON);
    v
}

const POOL: &str = "resh opens one connection per run and keeps no pool; remove it";

/// Options of earlier versions that no longer exist, with the reason.
const REMOVED: &[(&str, &str)] = &[
    ("max_connections", POOL),
    ("min_connections", POOL),
    ("idle_timeout_ms", POOL),
    ("max_lifetime_ms", POOL),
    (
        "connect_timeout_ms",
        "use timeout_ms, which covers connecting and running the statement",
    ),
    (
        "tx_id",
        "a transaction cannot outlive one resh run; run the statements together with \
         transaction statements=[...]",
    ),
];

/// " (did you mean `x`?)" when `bad` looks like a typo of an accepted name.
pub fn did_you_mean(bad: &str, allowed: &[&str]) -> String {
    fn distance(a: &str, b: &str) -> usize {
        let b: Vec<char> = b.chars().collect();
        let mut prev: Vec<usize> = (0..=b.len()).collect();
        for (i, ca) in a.chars().enumerate() {
            let mut cur = vec![i + 1];
            for (j, cb) in b.iter().enumerate() {
                let cost = usize::from(ca != *cb);
                cur.push((prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1));
            }
            prev = cur;
        }
        prev[b.len()]
    }
    let lower = bad.to_ascii_lowercase().replace('-', "_");
    allowed
        .iter()
        .map(|a| (distance(&lower, a), *a))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, a)| format!(" (did you mean `{a}`?)"))
        .unwrap_or_default()
}

/// Refuses any argument `verb` does not accept. `dry_run` reaches the
/// handle only as false (the core refuses a dry-run request first).
pub fn check_names(verb: &str, args: &Args) -> Result<(), DbError> {
    let allowed = accepted(verb);
    let mut keys: Vec<&String> = args.keys().collect();
    keys.sort();
    for k in keys {
        if allowed.contains(&k.as_str()) || k == "dry_run" {
            continue;
        }
        if let Some((_, why)) = REMOVED.iter().find(|(r, _)| r == k) {
            return Err(DbError::usage(format!(
                "db {verb} does not take {k}: {why}"
            )));
        }
        return Err(DbError::usage(format!(
            "unknown argument for db {verb}: {k}{}",
            did_you_mean(k, &allowed)
        )));
    }
    Ok(())
}

/// Typed, strict access to one call's arguments.
#[derive(Clone, Copy)]
pub struct Reader<'a> {
    pub args: &'a Args,
}

impl<'a> Reader<'a> {
    /// The value of `key`; an empty value is refused.
    pub fn str(&self, key: &str) -> Result<Option<&'a str>, DbError> {
        match self.args.get(key) {
            None => Ok(None),
            Some(v) if v.trim().is_empty() => Err(DbError::usage(format!("{key} is empty"))),
            Some(v) => Ok(Some(v.as_str())),
        }
    }

    pub fn required(&self, key: &str) -> Result<&'a str, DbError> {
        self.str(key)?
            .ok_or_else(|| DbError::usage(format!("{key}= is required")))
    }

    pub fn u64_in(&self, key: &str, min: u64, max: u64, default: u64) -> Result<u64, DbError> {
        let Some(v) = self.str(key)? else {
            return Ok(default);
        };
        match v.trim().parse::<u64>() {
            Ok(n) if (min..=max).contains(&n) => Ok(n),
            _ => Err(DbError::usage(format!(
                "invalid value for {key}: {v:?} (expected an integer from {min} to {max})"
            ))),
        }
    }

    pub fn bool(&self, key: &str, default: bool) -> Result<bool, DbError> {
        let Some(v) = self.str(key)? else {
            return Ok(default);
        };
        crate::core::lenient::parse_bool(v).ok_or_else(|| {
            DbError::usage(format!(
                "invalid value for {key}: {v:?} (expected true or false)"
            ))
        })
    }

    pub fn has(&self, key: &str) -> bool {
        self.args.contains_key(key)
    }
}

/// Connection, TLS, deadline and logging settings (every verb).
#[derive(Debug, Clone)]
pub struct Common {
    pub dsn: String,
    pub tls_mode: Option<TlsMode>,
    pub ca_pem: Option<Vec<u8>>,
    pub timeout: Duration,
    pub log_queries: bool,
}

/// The longest accepted timeout_ms (one day).
pub const MAX_TIMEOUT_MS: u64 = 86_400_000;

/// Reads the common options. `dsn` comes from `dsn=` or `DB_<ALIAS>_DSN`.
pub fn common(
    r: Reader,
    driver: Driver,
    alias: &str,
    default_timeout_ms: u64,
) -> Result<Common, DbError> {
    let timeout_ms = r.u64_in("timeout_ms", 1, MAX_TIMEOUT_MS, default_timeout_ms)?;
    let log_queries = r.bool("log_queries", false)?;
    let tls_mode = match r.str("tls_mode")? {
        None => None,
        Some(v) => Some(TlsMode::parse(v).ok_or_else(|| {
            DbError::usage(format!(
                "invalid value for tls_mode: {v:?} (expected {})",
                TlsMode::NAMES
            ))
        })?),
    };
    let ca_file = r.str("ca_file")?;
    match (driver, tls_mode) {
        (Driver::Sqlite, Some(m)) if m != TlsMode::Disable => {
            return Err(DbError::usage(
                "sqlite does not use TLS; omit tls_mode or use tls_mode=disable",
            ));
        }
        (Driver::Mysql, Some(TlsMode::Allow)) => {
            return Err(DbError::usage(
                "mysql has no tls_mode=allow; use disable, prefer, require, verify_ca or \
                 verify_full",
            ));
        }
        _ => {}
    }
    let mut tls_mode = tls_mode;
    let ca_pem = match ca_file {
        None => None,
        Some(_) if driver == Driver::Sqlite => {
            return Err(DbError::usage(
                "sqlite does not use TLS; ca_file does not apply",
            ));
        }
        Some(path) => {
            match tls_mode {
                // A private CA is only useful when certificates are checked.
                None => tls_mode = Some(TlsMode::VerifyFull),
                Some(m) if m.verifies() => {}
                Some(_) => {
                    return Err(DbError::usage(
                        "ca_file needs certificate verification; use tls_mode=verify_full \
                         (or verify_ca), or omit tls_mode",
                    ));
                }
            }
            Some(
                conn::load_ca_file(path)
                    .map_err(|e| DbError::usage(format!("invalid ca_file: {e}")))?,
            )
        }
    };
    let env = conn::env_var(alias);
    let dsn = match r.str("dsn")? {
        Some(d) => d.to_string(),
        None => match std::env::var(&env) {
            Ok(d) if !d.trim().is_empty() => d,
            _ => {
                return Err(DbError::usage_code(
                    "dsn_missing",
                    format!("no DSN for alias {alias:?}: pass dsn=<dsn> or set {env}"),
                ));
            }
        },
    };
    conn::check_dsn(driver, &dsn)?;
    if driver == Driver::Sqlite {
        conn::check_sqlite_not_linked(&dsn)?;
    }
    // Without tls_mode= (or an SSL mode in the DSN), remote servers are
    // verified and the local machine uses prefer.
    let tls_mode = tls_mode.or_else(|| conn::default_tls_mode(driver, &dsn));
    Ok(Common {
        dsn,
        tls_mode,
        ca_pem,
        timeout: Duration::from_millis(timeout_ms),
        log_queries,
    })
}

/// `params=`: a JSON array of strings, numbers, booleans and nulls.
pub fn params(r: Reader) -> Result<Vec<Param>, DbError> {
    let Some(text) = r.str("params")? else {
        return Ok(Vec::new());
    };
    let v: Value = serde_json::from_str(text).map_err(|e| {
        DbError::usage(format!(
            "params must be a JSON array (for example '[1,\"a\"]'): {e}"
        ))
    })?;
    param_list(&v, "params")
}

fn param_list(v: &Value, what: &str) -> Result<Vec<Param>, DbError> {
    let Value::Array(items) = v else {
        return Err(DbError::usage(format!("{what} must be a JSON array")));
    };
    items
        .iter()
        .enumerate()
        .map(|(i, p)| Param::from_json(p, &format!("{what}[{i}]")).map_err(DbError::usage))
        .collect()
}

/// `sql=`, checked to be exactly one statement.
pub fn one_statement(r: Reader, driver: Driver) -> Result<String, DbError> {
    let sql = r.required("sql")?;
    sql::single_statement(sql, driver, "sql").map_err(DbError::usage)?;
    Ok(sql.to_string())
}

/// A table or schema name. Names are always bound as values, never spliced
/// into SQL, so only emptiness, length and NUL are checked.
pub fn name(r: Reader, key: &str) -> Result<Option<String>, DbError> {
    let Some(v) = r.str(key)? else {
        return Ok(None);
    };
    if v.len() > 1024 || v.contains('\0') {
        return Err(DbError::usage(format!(
            "invalid value for {key}: names are at most 1024 bytes, without NUL"
        )));
    }
    Ok(Some(v.to_string()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Rows,
    Scalar,
    Exec,
}

pub struct QueryArgs {
    pub sql: String,
    pub params: Vec<Param>,
    pub mode: Mode,
    pub max_rows: u64,
}

pub fn query(r: Reader, driver: Driver) -> Result<QueryArgs, DbError> {
    let mode = match r.str("mode")?.unwrap_or("rows") {
        "rows" => Mode::Rows,
        "scalar" => Mode::Scalar,
        "exec" => Mode::Exec,
        m => {
            return Err(DbError::usage(format!(
                "invalid value for mode: {m:?} (expected rows, scalar or exec)"
            )));
        }
    };
    let max_rows = r.u64_in("max_rows", 1, 1_000_000, 1000)?;
    if mode == Mode::Exec && r.has("max_rows") {
        return Err(DbError::usage("max_rows does not apply to mode=exec"));
    }
    Ok(QueryArgs {
        sql: one_statement(r, driver)?,
        params: params(r)?,
        mode,
        max_rows,
    })
}

pub struct ExecArgs {
    pub sql: String,
    pub params: Vec<Param>,
    pub return_last_insert_id: bool,
}

pub fn exec(r: Reader, driver: Driver) -> Result<ExecArgs, DbError> {
    let return_last_insert_id = r.bool("return_last_insert_id", false)?;
    if return_last_insert_id && driver == Driver::Postgres {
        return Err(DbError::usage(
            "return_last_insert_id is not available on postgres; use \
             INSERT ... RETURNING id with query",
        ));
    }
    Ok(ExecArgs {
        sql: one_statement(r, driver)?,
        params: params(r)?,
        return_last_insert_id,
    })
}

pub struct TablesArgs {
    pub table: Option<String>,
    pub schema: Option<String>,
    pub include_views: bool,
    pub include_system: bool,
    pub max_tables: u64,
}

pub fn tables(r: Reader) -> Result<TablesArgs, DbError> {
    let table = name(r, "table")?;
    if table.is_some()
        && let Some(k) = ["include_views", "include_system", "max_tables"]
            .into_iter()
            .find(|k| r.has(k))
    {
        return Err(DbError::usage(format!(
            "{k} applies to listing tables, not to table="
        )));
    }
    Ok(TablesArgs {
        table,
        schema: name(r, "schema")?,
        include_views: r.bool("include_views", false)?,
        include_system: r.bool("include_system", false)?,
        max_tables: r.u64_in("max_tables", 1, 100_000, 1000)?,
    })
}

pub struct SchemaArgs {
    pub table: String,
    pub schema: Option<String>,
    pub indexes: bool,
    pub foreign_keys: bool,
    pub unique_constraints: bool,
    pub checks: bool,
    pub triggers: bool,
}

pub fn schema(r: Reader) -> Result<SchemaArgs, DbError> {
    Ok(SchemaArgs {
        table: name(r, "table")?.ok_or_else(|| DbError::usage("table= is required"))?,
        schema: name(r, "schema")?,
        indexes: r.bool("include_indexes", true)?,
        foreign_keys: r.bool("include_foreign_keys", true)?,
        unique_constraints: r.bool("include_unique_constraints", true)?,
        checks: r.bool("include_checks", false)?,
        triggers: r.bool("include_triggers", false)?,
    })
}

pub struct PingArgs {
    pub retries: u64,
    pub backoff: Duration,
    pub detailed: bool,
}

pub fn ping(r: Reader) -> Result<PingArgs, DbError> {
    Ok(PingArgs {
        retries: r.u64_in("retries", 0, 10, 0)?,
        backoff: Duration::from_millis(r.u64_in("backoff_ms", 0, 60_000, 100)?),
        detailed: r.bool("detailed", false)?,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isolation {
    Default,
    ReadUncommitted,
    ReadCommitted,
    RepeatableRead,
    Serializable,
}

impl Isolation {
    /// The SQL words for the level, or `None` for the server default.
    pub fn sql(self) -> Option<&'static str> {
        match self {
            Isolation::Default => None,
            Isolation::ReadUncommitted => Some("READ UNCOMMITTED"),
            Isolation::ReadCommitted => Some("READ COMMITTED"),
            Isolation::RepeatableRead => Some("REPEATABLE READ"),
            Isolation::Serializable => Some("SERIALIZABLE"),
        }
    }
}

pub struct TxArgs {
    pub statements: Vec<(String, Vec<Param>)>,
    pub isolation: Isolation,
    pub read_only: bool,
}

pub fn transaction(r: Reader, driver: Driver) -> Result<TxArgs, DbError> {
    match r.str("action")? {
        None | Some("run") => {}
        Some(a @ ("begin" | "commit" | "rollback")) => {
            return Err(DbError::usage(format!(
                "action={a} is not available: a transaction cannot outlive one resh run; \
                 run the statements together with statements=[...]"
            )));
        }
        Some(a) => {
            return Err(DbError::usage(format!(
                "invalid value for action: {a:?} (expected run)"
            )));
        }
    }
    let isolation = match r.str("isolation")?.unwrap_or("default") {
        "default" => Isolation::Default,
        "read_uncommitted" => Isolation::ReadUncommitted,
        "read_committed" => Isolation::ReadCommitted,
        "repeatable_read" => Isolation::RepeatableRead,
        "serializable" => Isolation::Serializable,
        v => {
            return Err(DbError::usage(format!(
                "invalid value for isolation: {v:?} (expected default, read_uncommitted, \
                 read_committed, repeatable_read or serializable)"
            )));
        }
    };
    if driver == Driver::Sqlite
        && !matches!(isolation, Isolation::Default | Isolation::Serializable)
    {
        return Err(DbError::usage(
            "sqlite transactions are always serializable; use isolation=default or \
             serializable",
        ));
    }
    let text = r.required("statements")?;
    let v: Value = serde_json::from_str(text).map_err(|e| {
        DbError::usage(format!(
            "statements must be a JSON array of SQL strings or {{\"sql\",\"params\"}} \
             objects: {e}"
        ))
    })?;
    let Value::Array(items) = v else {
        return Err(DbError::usage("statements must be a JSON array"));
    };
    if items.is_empty() {
        return Err(DbError::usage("statements is an empty array"));
    }
    let mut statements = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let what = format!("statements[{i}]");
        let (sql, params) = match item {
            Value::String(s) => (s.clone(), Vec::new()),
            Value::Object(o) => {
                if let Some(k) = o.keys().find(|k| *k != "sql" && *k != "params") {
                    return Err(DbError::usage(format!(
                        "{what} has an unknown key {k:?} (expected sql and params)"
                    )));
                }
                let sql = o
                    .get("sql")
                    .and_then(Value::as_str)
                    .ok_or_else(|| DbError::usage(format!("{what} needs a string sql")))?;
                let params = match o.get("params") {
                    None | Some(Value::Null) => Vec::new(),
                    Some(p) => param_list(p, &format!("{what}.params"))?,
                };
                (sql.to_string(), params)
            }
            _ => {
                return Err(DbError::usage(format!(
                    "{what} must be a SQL string or an object with sql and params"
                )));
            }
        };
        sql::single_statement(&sql, driver, &what).map_err(DbError::usage)?;
        statements.push((sql, params));
    }
    Ok(TxArgs {
        statements,
        isolation,
        read_only: r.bool("read_only", false)?,
    })
}
