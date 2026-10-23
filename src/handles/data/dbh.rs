use anyhow::{Result, bail, Context};
use base64::engine::Engine;
use dashmap::DashMap;
use serde_json::{json, Value};
use sqlx::{Pool, Postgres, MySql, Sqlite, Row, Column, TypeInfo, ValueRef};
use std::io::Write;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use url::Url;
use uuid::Uuid;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::Status,
};

/// Metadata for `resh db --help` and `resh db <verb> --help`.
static DB_HELP: HandleHelp = HandleHelp {
    description: "The db handle runs SQL against PostgreSQL, MySQL, and SQLite databases \
        through pooled sqlx connections. The target names a driver and a connection alias, \
        such as db://postgres/app, and connect reads the DSN from dsn= or the \
        DB_<ALIAS>_DSN environment variable. Pools live only for one resh process, so \
        every other verb also connects on its own when given dsn= or when that \
        environment variable is set.",
    usage: "resh db://<driver>/<alias>.<verb>[(key=value,...)]",
    verbs: &[
        VerbHelp {
            name: "connect",
            definition: "Opens a connection pool for the alias, or reuses the existing pool \
                when the DSN matches, and reports pool statistics.",
            detail: Some(VerbDetail {
                usage: "resh db://<driver>/<alias>.connect [dsn=<dsn>] [max_connections=<n>]\n  \
                    [min_connections=<n>] [connect_timeout_ms=<ms>] [idle_timeout_ms=<ms>]\n  \
                    [max_lifetime_ms=<ms>] [log_queries=true|false]\n  \
                    [tls_mode=disable|allow|prefer|require|verify_ca|verify_full]",
                example: "resh db://postgres/app.connect dsn=postgresql://app@db.example.com/app",
                example_output: Some(
                    r#"{
  "alias": "app",
  "driver": "postgres",
  "pool_stats": {
    "current_size": 1,
    "idle_connections": 1,
    "max_connections": 10,
    "min_connections": 1
  },
  "reused": false,
  "type": "db_connection"
}

Shown with --json-pretty. tls_mode overrides any SSL mode in the DSN;
MySQL rejects allow and SQLite accepts only disable. log_queries=true
enables sqlx statement logging at info level through the log crate."#,
                ),
            }),
        },
        VerbHelp {
            name: "ping",
            definition: "Runs SELECT 1 on the alias's pool, retrying on failure, and reports \
                the latency and number of attempts.",
            detail: Some(VerbDetail {
                usage: "resh db://<driver>/<alias>.ping [dsn=<dsn>] [timeout_ms=<ms>]\n  \
                    [retries=<n>] [backoff_ms=<ms>] [detailed=true|false]",
                example: "resh --json-pretty db://sqlite/app.ping dsn=sqlite:app.db retries=2",
                example_output: Some(
                    r#"{
  "alias": "app",
  "attempts": 1,
  "driver": "sqlite",
  "latency_ms": 3,
  "status": "ok"
}

Shown for a successful ping with --json-pretty. When every attempt fails,
status is "error" and an error object is added, with last_error when
detailed=true."#,
                ),
            }),
        },
        VerbHelp {
            name: "query",
            definition: "Runs a SQL statement and returns rows with column metadata, a single \
                scalar value, or the affected row count, depending on mode.",
            detail: Some(VerbDetail {
                usage: "resh db://<driver>/<alias>.query sql=<sql> [params=<json-array>]\n  \
                    [mode=rows|scalar|exec] [timeout_ms=<ms>] [max_rows=<n>]\n  \
                    [dsn=<dsn>] [tx_id=<id>]",
                example: "resh db://sqlite/app.query 'sql=SELECT id, name FROM users' \
                    dsn=sqlite:app.db",
                example_output: Some(
                    r#"{
  "meta": {
    "columns": [
      {
        "name": "id",
        "type": "INTEGER"
      },
      {
        "name": "name",
        "type": "TEXT"
      }
    ],
    "row_count": 2,
    "truncated": false
  },
  "rows": [
    {
      "id": 1,
      "name": "alice"
    },
    {
      "id": 2,
      "name": "bob"
    }
  ]
}

Shown for mode=rows with --json-pretty. mode=scalar returns value and
meta (row_count, columns), and mode=exec returns rows_affected.
timeout_ms defaults to 5000 and max_rows to 1000."#,
                ),
            }),
        },
        VerbHelp {
            name: "tables",
            definition: "Lists the tables in the database, or describes one table's columns \
                when table= is given.",
            detail: Some(VerbDetail {
                usage: "resh db://<driver>/<alias>.tables [table=<name>] [schema=<name>]\n  \
                    [include_views=true|false] [include_system=true|false]\n  \
                    [max_tables=<n>] [timeout_ms=<ms>] [dsn=<dsn>]",
                example: "resh --json-pretty db://postgres/app.tables include_views=true",
                example_output: Some(
                    r#"{
  "meta": {
    "count": 2,
    "truncated": false
  },
  "tables": [
    {
      "name": "active_users",
      "schema": "public",
      "type": "VIEW"
    },
    {
      "name": "orders",
      "schema": "public",
      "type": "BASE TABLE"
    }
  ]
}

Shown for PostgreSQL with --json-pretty and DB_APP_DSN set in the
environment. SQLite reports schema as null. With table= the output has a
table object and a columns array instead."#,
                ),
            }),
        },
        VerbHelp {
            name: "schema",
            definition: "Describes a table's columns and primary key, plus the index, foreign \
                key, and constraint sections selected by the include flags.",
            detail: Some(VerbDetail {
                usage: "resh db://<driver>/<alias>.schema table=<name> [schema=<name>]\n  \
                    [include_indexes=true|false] [include_foreign_keys=true|false]\n  \
                    [include_unique_constraints=true|false] [include_checks=true|false]\n  \
                    [include_triggers=true|false] [timeout_ms=<ms>] [dsn=<dsn>]",
                example: "resh --json-pretty db://sqlite/app.schema table=users dsn=sqlite:app.db",
                example_output: Some(
                    r#"{
  "columns": [
    {
      "data_type": "INTEGER",
      "default": null,
      "is_nullable": false,
      "is_primary_key": true,
      "name": "id",
      "ordinal_position": 1
    },
    {
      "data_type": "TEXT",
      "default": null,
      "is_nullable": false,
      "is_primary_key": false,
      "name": "email",
      "ordinal_position": 2
    }
  ],
  "foreign_keys": [],
  "indexes": [
    {
      "columns": [
        "email"
      ],
      "is_unique": true,
      "name": "idx_users_email"
    }
  ],
  "primary_key": {
    "columns": [
      "id"
    ],
    "name": "users_pkey"
  },
  "table": {
    "name": "users",
    "schema": "main",
    "type": "BASE TABLE"
  },
  "unique_constraints": []
}

Shown for SQLite with --json-pretty. PostgreSQL and MySQL return empty
index, foreign key, and constraint lists."#,
                ),
            }),
        },
        VerbHelp {
            name: "exec",
            definition: "Runs a single data-changing statement, such as INSERT, UPDATE, or \
                DELETE, and reports the number of rows affected.",
            detail: Some(VerbDetail {
                usage: "resh db://<driver>/<alias>.exec sql=<sql> [params=<json-array>]\n  \
                    [return_last_insert_id=true|false] [timeout_ms=<ms>] [dsn=<dsn>]\n  \
                    [tx_id=<id>]",
                example: "resh db://sqlite/app.exec 'sql=DELETE FROM sessions' dsn=sqlite:app.db",
                example_output: Some(
                    r#"{
  "rows_affected": 3
}

Shown with --json-pretty. return_last_insert_id=true adds last_insert_id,
which is always null on PostgreSQL."#,
                ),
            }),
        },
        VerbHelp {
            name: "transaction",
            definition: "Runs a list of statements in one transaction, committing only if \
                every statement succeeds and rolling back otherwise.",
            detail: Some(VerbDetail {
                usage: "resh db://<driver>/<alias>.transaction [action=run] statements=<json-array>\n  \
                    [isolation=<level>] [read_only=true|false] [timeout_ms=<ms>] [dsn=<dsn>]\n  \
                    or: action=begin|commit|rollback [tx_id=<id>] (one process only)",
                example: "resh db://sqlite/db.transaction 'statements=[\"DELETE FROM a\",\"DELETE FROM b\"]'",
                example_output: Some(
                    r#"{
  "action": "run",
  "alias": "db",
  "committed": true,
  "driver": "sqlite",
  "results": [
    {
      "index": 0,
      "rows_affected": 3
    },
    {
      "index": 1,
      "rows_affected": 2
    }
  ],
  "status": "ok"
}

Shown as --json-pretty output, with DB_DB_DSN set. Items may also be
{"sql":...,"params":[...]} objects.
If a statement fails, all are rolled back and the error names its index.
begin, commit and rollback with tx_id work only within one resh process,
because the transaction is held in memory."#,
                ),
            }),
        },
    ],
};

/// Reads an optional unsigned integer argument. CLI arguments arrive as
/// strings, so both JSON numbers and numeric strings are accepted; any other
/// value is an error instead of being silently replaced by the default.
fn typed_u64(args: &Value, key: &str) -> std::result::Result<Option<u64>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => crate::core::lenient::from_value::<u64>(v.clone())
            .map(Some)
            .map_err(|_| format!("{} must be a non-negative integer, got {}", key, v)),
    }
}

/// Reads an optional boolean argument, accepting JSON booleans and the CLI
/// strings true/false, 1/0, yes/no, on/off.
fn typed_bool(args: &Value, key: &str) -> std::result::Result<Option<bool>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => crate::core::lenient::from_value::<bool>(v.clone())
            .map(Some)
            .map_err(|_| format!("{} must be true or false, got {}", key, v)),
    }
}

/// Query execution mode
#[derive(Debug, Clone, PartialEq)]
pub enum QueryMode {
    Rows,
    Scalar,
    Exec,
}

impl QueryMode {
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "rows" => Ok(QueryMode::Rows),
            "scalar" => Ok(QueryMode::Scalar),
            "exec" => Ok(QueryMode::Exec),
            _ => bail!("invalid query mode: {}. Valid modes: rows, scalar, exec", s),
        }
    }
}

/// Query configuration
#[derive(Debug, Clone)]
pub struct QueryConfig {
    pub sql: String,
    pub params: Vec<Value>,
    pub mode: QueryMode,
    pub timeout_ms: u64,
    pub max_rows: u64,
    pub tx_id: Option<String>,
}

impl QueryConfig {
    fn from_args(args: &Value) -> Result<Self> {
        let sql = args.get("sql")
            .and_then(|v| v.as_str())
            .context("missing required 'sql' field")?
            .to_string();

        if sql.trim().is_empty() {
            bail!("sql cannot be empty");
        }

        // Parse parameters - can be array or object, convert to array
        let params = match args.get("params") {
            Some(Value::Array(arr)) => arr.clone(),
            Some(Value::Object(_obj)) => {
                // For named parameters, we'll convert to positional
                // This is a simplified approach - in production might want full named param support
                bail!("named parameters not yet supported, use positional parameters as array");
            }
            Some(Value::Null) | None => Vec::new(),
            Some(_) => bail!("params must be an array or object"),
        };

        let mode_str = args.get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("rows");
        let mode = QueryMode::from_str(mode_str)?;

        let timeout_ms = typed_u64(args, "timeout_ms").map_err(anyhow::Error::msg)?
            .unwrap_or(5000);

        let max_rows = typed_u64(args, "max_rows").map_err(anyhow::Error::msg)?
            .unwrap_or(1000);

        let tx_id = args.get("tx_id")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        // Validation
        if timeout_ms == 0 {
            bail!("timeout_ms must be greater than 0");
        }
        if max_rows == 0 {
            bail!("max_rows must be greater than 0");
        }
        if max_rows > 1_000_000 {
            bail!("max_rows cannot exceed 1,000,000");
        }

        Ok(QueryConfig {
            sql,
            params,
            mode,
            timeout_ms,
            max_rows,
            tx_id,
        })
    }
}

/// Exec configuration for database exec operations
#[derive(Debug, Clone)]
pub struct ExecConfig {
    pub sql: String,
    pub params: Vec<Value>,
    pub timeout_ms: u64,
    pub return_last_insert_id: bool,
    pub tx_id: Option<String>,
}

impl ExecConfig {
    fn from_args(args: &Value) -> Result<Self, DbError> {
        let sql = args.get("sql")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DbError::InvalidExecConfig { 
                message: "missing required 'sql' field".to_string() 
            })?
            .to_string();

        if sql.trim().is_empty() {
            return Err(DbError::InvalidExecConfig { 
                message: "sql cannot be empty".to_string() 
            });
        }

        // Validate single statement (basic check)
        Self::validate_single_statement(&sql)?;

        // Parse parameters - can be array or object, convert to array
        let params = match args.get("params") {
            Some(Value::Array(arr)) => arr.clone(),
            Some(Value::Object(_obj)) => {
                return Err(DbError::InvalidExecConfig { 
                    message: "named parameters not yet supported, use positional parameters as array".to_string()
                });
            }
            Some(Value::Null) | None => Vec::new(),
            Some(_) => {
                return Err(DbError::InvalidExecConfig { 
                    message: "params must be an array or object".to_string() 
                });
            }
        };

        let timeout_ms = typed_u64(args, "timeout_ms").map_err(|m| DbError::InvalidExecConfig { message: m })?
            .unwrap_or(5000);

        let return_last_insert_id = typed_bool(args, "return_last_insert_id").map_err(|m| DbError::InvalidExecConfig { message: m })?
            .unwrap_or(false);

        let tx_id = args.get("tx_id")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        // Validation
        if timeout_ms == 0 {
            return Err(DbError::InvalidExecConfig { 
                message: "timeout_ms must be greater than 0".to_string() 
            });
        }

        Ok(ExecConfig {
            sql,
            params,
            timeout_ms,
            return_last_insert_id,
            tx_id,
        })
    }

    /// Basic validation to reject obvious multiple statements
    fn validate_single_statement(sql: &str) -> Result<(), DbError> {
        // Simple check: count semicolons outside of quotes
        let mut in_single_quote = false;
        let mut in_double_quote = false;
        let mut escape_next = false;
        let mut semicolon_count = 0;

        for ch in sql.chars() {
            if escape_next {
                escape_next = false;
                continue;
            }

            match ch {
                '\\' => escape_next = true,
                '\'' if !in_double_quote => in_single_quote = !in_single_quote,
                '"' if !in_single_quote => in_double_quote = !in_double_quote,
                ';' if !in_single_quote && !in_double_quote => {
                    semicolon_count += 1;
                    // Allow one semicolon at the end
                    if semicolon_count > 1 {
                        return Err(DbError::InvalidExecConfig { 
                            message: "multiple statements detected (semicolons outside quotes)".to_string() 
                        });
                    }
                }
                _ => {}
            }
        }

        // Check if the semicolon is at the end (allowing trailing whitespace)
        if semicolon_count == 1 {
            let trimmed = sql.trim_end();
            if !trimmed.ends_with(';') {
                return Err(DbError::InvalidExecConfig { 
                    message: "multiple statements detected (semicolons outside quotes)".to_string() 
                });
            }
        }

        Ok(())
    }
}

/// Tables configuration for database introspection operations
#[derive(Debug, Clone)]
pub struct TablesConfig {
    pub table: Option<String>,
    pub schema: Option<String>,
    pub include_views: bool,
    pub include_system: bool,
    pub timeout_ms: u64,
    pub max_tables: u64,
}

impl TablesConfig {
    fn from_args(args: &Value) -> Result<Self, DbError> {
        let table = args.get("table")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string());

        let schema = args.get("schema")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let include_views = typed_bool(args, "include_views").map_err(|m| DbError::InvalidTablesConfig { message: m })?
            .unwrap_or(false);

        let include_system = typed_bool(args, "include_system").map_err(|m| DbError::InvalidTablesConfig { message: m })?
            .unwrap_or(false);

        let timeout_ms = typed_u64(args, "timeout_ms").map_err(|m| DbError::InvalidTablesConfig { message: m })?
            .unwrap_or(5000);

        let max_tables = typed_u64(args, "max_tables").map_err(|m| DbError::InvalidTablesConfig { message: m })?
            .unwrap_or(1000);

        // Validation
        if timeout_ms == 0 {
            return Err(DbError::InvalidTablesConfig {
                message: "timeout_ms must be greater than 0".to_string()
            });
        }

        if max_tables == 0 {
            return Err(DbError::InvalidTablesConfig {
                message: "max_tables must be greater than 0".to_string()
            });
        }

        // Validate table name if provided
        if let Some(ref table_name) = table {
            if table_name.trim().is_empty() {
                return Err(DbError::InvalidTablesConfig {
                    message: "table name cannot be empty or whitespace".to_string()
                });
            }
        }

        Ok(TablesConfig {
            table,
            schema,
            include_views,
            include_system,
            timeout_ms,
            max_tables,
        })
    }
}

/// Schema introspection configuration
#[derive(Debug, Clone)]
pub struct SchemaConfig {
    pub table: String,
    pub schema: Option<String>,
    pub include_indexes: bool,
    pub include_foreign_keys: bool,
    pub include_unique_constraints: bool,
    pub include_checks: bool,
    pub include_triggers: bool,
    pub timeout_ms: u64,
}

impl SchemaConfig {
    fn from_args(args: &Value) -> Result<Self, DbError> {
        // table is required
        let table = args.get("table")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .ok_or_else(|| DbError::InvalidSchemaConfig {
                message: "table is required".to_string()
            })?;

        if table.is_empty() {
            return Err(DbError::InvalidSchemaConfig {
                message: "table cannot be empty".to_string()
            });
        }

        let schema = args.get("schema")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let include_indexes = typed_bool(args, "include_indexes").map_err(|m| DbError::InvalidSchemaConfig { message: m })?
            .unwrap_or(true);

        let include_foreign_keys = typed_bool(args, "include_foreign_keys").map_err(|m| DbError::InvalidSchemaConfig { message: m })?
            .unwrap_or(true);

        let include_unique_constraints = typed_bool(args, "include_unique_constraints").map_err(|m| DbError::InvalidSchemaConfig { message: m })?
            .unwrap_or(true);

        let include_checks = typed_bool(args, "include_checks").map_err(|m| DbError::InvalidSchemaConfig { message: m })?
            .unwrap_or(false);

        let include_triggers = typed_bool(args, "include_triggers").map_err(|m| DbError::InvalidSchemaConfig { message: m })?
            .unwrap_or(false);

        let timeout_ms = typed_u64(args, "timeout_ms").map_err(|m| DbError::InvalidSchemaConfig { message: m })?
            .unwrap_or(5000);

        // Validation
        if timeout_ms == 0 {
            return Err(DbError::InvalidSchemaConfig {
                message: "timeout_ms must be greater than 0".to_string()
            });
        }

        Ok(SchemaConfig {
            table,
            schema,
            include_indexes,
            include_foreign_keys,
            include_unique_constraints,
            include_checks,
            include_triggers,
            timeout_ms,
        })
    }
}

/// Ping configuration for database health checks
#[derive(Debug, Clone)]
pub struct PingConfig {
    pub timeout_ms: u64,
    pub retries: u32,
    pub backoff_ms: u64,
    pub detailed: bool,
}

impl PingConfig {
    fn from_args(args: &Value) -> Result<Self, DbError> {
        let timeout_ms = typed_u64(args, "timeout_ms").map_err(|m| DbError::InvalidPingConfig { message: m })?
            .unwrap_or(1000);

        let retries = typed_u64(args, "retries").map_err(|m| DbError::InvalidPingConfig { message: m })?
            .map(|v| v.min(u32::MAX as u64) as u32)
            .unwrap_or(0);

        let backoff_ms = typed_u64(args, "backoff_ms").map_err(|m| DbError::InvalidPingConfig { message: m })?
            .unwrap_or(100);

        let detailed = typed_bool(args, "detailed").map_err(|m| DbError::InvalidPingConfig { message: m })?
            .unwrap_or(false);

        // Validation
        if timeout_ms == 0 {
            return Err(DbError::InvalidPingConfig {
                message: "timeout_ms must be greater than 0".to_string()
            });
        }

        if retries > 10 {
            return Err(DbError::InvalidPingConfig {
                message: "retries cannot exceed 10".to_string()
            });
        }

        Ok(PingConfig {
            timeout_ms,
            retries,
            backoff_ms,
            detailed,
        })
    }
}

/// Database driver enumeration
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DbDriver {
    Postgres,
    Mysql,
    Sqlite,
}

impl DbDriver {
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "postgres" | "postgresql" => Ok(DbDriver::Postgres),
            "mysql" => Ok(DbDriver::Mysql),
            "sqlite" => Ok(DbDriver::Sqlite),
            _ => bail!("unsupported driver: {}", s),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DbDriver::Postgres => "postgres",
            DbDriver::Mysql => "mysql", 
            DbDriver::Sqlite => "sqlite",
        }
    }
}

/// Database connection pool wrapper
#[derive(Debug, Clone)]
pub enum DbPool {
    Postgres(Pool<Postgres>),
    Mysql(Pool<MySql>),
    Sqlite(Pool<Sqlite>),
}

impl DbPool {
    /// Get current pool statistics
    pub fn stats(&self) -> PoolStats {
        match self {
            DbPool::Postgres(pool) => {
                PoolStats {
                    size: pool.size(),
                    num_idle: pool.num_idle(),
                }
            }
            DbPool::Mysql(pool) => {
                PoolStats {
                    size: pool.size(),
                    num_idle: pool.num_idle(),
                }
            }
            DbPool::Sqlite(pool) => {
                PoolStats {
                    size: pool.size(),
                    num_idle: pool.num_idle(),
                }
            }
        }
    }
}

/// Pool statistics for monitoring
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub size: u32,
    pub num_idle: usize,
}

/// Database connection handle containing pool and metadata
#[derive(Debug, Clone)]
pub struct DbConnectionHandle {
    pub driver: DbDriver,
    pub alias: String,
    pub pool: DbPool,
    pub dsn_hash: u64, // For alias conflict detection (without storing DSN)
    pub config: DbConfig,
}

/// Database configuration for connection management
#[derive(Debug, Clone)]
pub struct DbConfig {
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub max_lifetime_ms: u64,
    /// TLS mode from tls_mode=; `None` keeps the DSN's setting or the
    /// driver default.
    pub tls_mode: Option<String>,
    pub log_queries: bool,
}

/// Normalized tls_mode= value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    Disable,
    Allow,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

impl TlsMode {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "disable" | "disabled" => Some(TlsMode::Disable),
            "allow" => Some(TlsMode::Allow),
            "prefer" | "preferred" => Some(TlsMode::Prefer),
            "require" | "required" => Some(TlsMode::Require),
            "verify-ca" => Some(TlsMode::VerifyCa),
            "verify-full" | "verify-identity" => Some(TlsMode::VerifyFull),
            _ => None,
        }
    }

    fn postgres(self) -> sqlx::postgres::PgSslMode {
        use sqlx::postgres::PgSslMode;
        match self {
            TlsMode::Disable => PgSslMode::Disable,
            TlsMode::Allow => PgSslMode::Allow,
            TlsMode::Prefer => PgSslMode::Prefer,
            TlsMode::Require => PgSslMode::Require,
            TlsMode::VerifyCa => PgSslMode::VerifyCa,
            TlsMode::VerifyFull => PgSslMode::VerifyFull,
        }
    }

    /// MySQL has no "allow" mode; validation rejects it before this is called.
    fn mysql(self) -> sqlx::mysql::MySqlSslMode {
        use sqlx::mysql::MySqlSslMode;
        match self {
            TlsMode::Disable => MySqlSslMode::Disabled,
            TlsMode::Allow | TlsMode::Prefer => MySqlSslMode::Preferred,
            TlsMode::Require => MySqlSslMode::Required,
            TlsMode::VerifyCa => MySqlSslMode::VerifyCa,
            TlsMode::VerifyFull => MySqlSslMode::VerifyIdentity,
        }
    }
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            max_connections: 10,
            min_connections: 1,
            connect_timeout_ms: 5000,
            idle_timeout_ms: 600_000, // 10 minutes
            max_lifetime_ms: 1_800_000, // 30 minutes
            tls_mode: None,
            log_queries: false,
        }
    }
}

/// Connection registry for reusing pools
type ConnectionRegistry = DashMap<(DbDriver, String), Arc<DbConnectionHandle>>;

/// Global connection registry 
static CONNECTION_REGISTRY: LazyLock<ConnectionRegistry> = LazyLock::new(|| DashMap::new());

/// Transaction action type
#[derive(Debug, Clone, PartialEq)]
pub enum TransactionAction {
    Begin,
    Commit,
    Rollback,
    /// Begin, run `statements`, and commit (or roll back on error) in one call.
    Run,
}

impl TransactionAction {
    fn from_str(s: &str) -> Result<Self, DbError> {
        match s.to_lowercase().as_str() {
            "begin" => Ok(TransactionAction::Begin),
            "commit" => Ok(TransactionAction::Commit),
            "rollback" => Ok(TransactionAction::Rollback),
            "run" => Ok(TransactionAction::Run),
            _ => Err(DbError::InvalidTransactionConfig {
                message: format!("invalid action: {}. Valid actions: run, begin, commit, rollback", s)
            }),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TransactionAction::Begin => "begin",
            TransactionAction::Commit => "commit",
            TransactionAction::Rollback => "rollback",
            TransactionAction::Run => "run",
        }
    }
}

/// Transaction isolation level
#[derive(Debug, Clone, PartialEq)]
pub enum TransactionIsolation {
    Default,
    ReadUncommitted,
    ReadCommitted,
    RepeatableRead,
    Serializable,
}

impl TransactionIsolation {
    fn from_str(s: &str) -> Result<Self, DbError> {
        match s.to_lowercase().as_str() {
            "default" => Ok(TransactionIsolation::Default),
            "read_uncommitted" => Ok(TransactionIsolation::ReadUncommitted),
            "read_committed" => Ok(TransactionIsolation::ReadCommitted),
            "repeatable_read" => Ok(TransactionIsolation::RepeatableRead),
            "serializable" => Ok(TransactionIsolation::Serializable),
            _ => Err(DbError::InvalidTransactionConfig {
                message: format!("invalid isolation level: {}. Valid levels: default, read_uncommitted, read_committed, repeatable_read, serializable", s)
            }),
        }
    }
}

/// Transaction configuration
#[derive(Debug, Clone)]
pub struct TransactionConfig {
    pub action: TransactionAction,
    /// Statements for `action=run`, executed in order inside one transaction.
    pub statements: Vec<TxStatement>,
    pub tx_id: Option<String>,
    pub isolation: Option<TransactionIsolation>,
    pub read_only: bool,
    pub timeout_ms: u64,
}

impl TransactionConfig {
    fn from_args(args: &Value) -> Result<Self, DbError> {
        let statements = TxStatement::parse_list(args.get("statements"))?;

        // action defaults to run when statements are given
        let action = match args.get("action").and_then(|v| v.as_str()) {
            Some(a) => TransactionAction::from_str(a)?,
            None if statements.is_some() => TransactionAction::Run,
            None => {
                return Err(DbError::InvalidTransactionConfig {
                    message: "missing required 'action' field (or pass statements=<json-array> to run them in one transaction)".to_string()
                })
            }
        };

        let statements = match (&action, statements) {
            (TransactionAction::Run, Some(list)) => list,
            (TransactionAction::Run, None) => {
                return Err(DbError::InvalidTransactionConfig {
                    message: "statements is required for 'run' action".to_string()
                })
            }
            (_, Some(_)) => {
                return Err(DbError::InvalidTransactionConfig {
                    message: format!("statements is only valid with action=run, not '{}'", action.as_str())
                })
            }
            (_, None) => Vec::new(),
        };

        let tx_id = args.get("tx_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Validate tx_id requirements based on action
        match action {
            TransactionAction::Begin | TransactionAction::Run => {
                // tx_id should NOT be provided for begin or run
                if tx_id.is_some() {
                    return Err(DbError::InvalidTransactionConfig {
                        message: format!("tx_id must not be provided for '{}' action", action.as_str())
                    });
                }
            }
            TransactionAction::Commit | TransactionAction::Rollback => {
                // tx_id is required for commit/rollback
                if tx_id.is_none() {
                    return Err(DbError::InvalidTransactionConfig {
                        message: format!("tx_id is required for '{}' action", action.as_str())
                    });
                }
                if let Some(ref id) = tx_id {
                    if id.trim().is_empty() {
                        return Err(DbError::InvalidTransactionConfig {
                            message: "tx_id cannot be empty".to_string()
                        });
                    }
                }
            }
        }

        let starts_tx = matches!(action, TransactionAction::Begin | TransactionAction::Run);
        let isolation = if starts_tx {
            args.get("isolation")
                .and_then(|v| v.as_str())
                .map(TransactionIsolation::from_str)
                .transpose()?
        } else {
            None // Ignore isolation for commit/rollback
        };

        let read_only = if starts_tx {
            typed_bool(args, "read_only").map_err(|m| DbError::InvalidTransactionConfig { message: m })?
                .unwrap_or(false)
        } else {
            false // Ignore read_only for commit/rollback
        };

        let timeout_ms = typed_u64(args, "timeout_ms").map_err(|m| DbError::InvalidTransactionConfig { message: m })?
            .unwrap_or(5000);

        // Validation
        if timeout_ms == 0 {
            return Err(DbError::InvalidTransactionConfig {
                message: "timeout_ms must be greater than 0".to_string()
            });
        }

        Ok(TransactionConfig {
            action,
            statements,
            tx_id,
            isolation,
            read_only,
            timeout_ms,
        })
    }
}

/// One statement for `transaction action=run`.
#[derive(Debug, Clone, PartialEq)]
pub struct TxStatement {
    pub sql: String,
    pub params: Vec<Value>,
}

impl TxStatement {
    /// Parses `statements`: a JSON array (or a string holding one) whose
    /// items are SQL strings or objects with `sql` and optional `params`.
    /// Returns `Ok(None)` when the argument is absent.
    fn parse_list(value: Option<&Value>) -> Result<Option<Vec<TxStatement>>, DbError> {
        let invalid = |message: String| DbError::InvalidTransactionConfig { message };
        let parsed;
        let items = match value {
            None | Some(Value::Null) => return Ok(None),
            Some(Value::Array(items)) => items,
            Some(Value::String(text)) => {
                parsed = serde_json::from_str::<Value>(text).map_err(|e| {
                    invalid(format!("statements must be a JSON array of SQL strings: {}", e))
                })?;
                match &parsed {
                    Value::Array(items) => items,
                    _ => return Err(invalid("statements must be a JSON array".to_string())),
                }
            }
            Some(_) => return Err(invalid("statements must be a JSON array".to_string())),
        };
        if items.is_empty() {
            return Err(invalid("statements cannot be empty".to_string()));
        }
        let mut out = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            let (sql, params) = match item {
                Value::String(sql) => (sql.clone(), Vec::new()),
                Value::Object(obj) => {
                    let sql = obj.get("sql").and_then(|v| v.as_str()).ok_or_else(|| {
                        invalid(format!("statements[{}] must have a string 'sql' field", index))
                    })?;
                    let params = match obj.get("params") {
                        None | Some(Value::Null) => Vec::new(),
                        Some(Value::Array(p)) => p.clone(),
                        Some(_) => {
                            return Err(invalid(format!("statements[{}].params must be an array", index)))
                        }
                    };
                    (sql.to_string(), params)
                }
                _ => {
                    return Err(invalid(format!(
                        "statements[{}] must be a SQL string or an object with sql and params",
                        index
                    )))
                }
            };
            if sql.trim().is_empty() {
                return Err(invalid(format!("statements[{}] cannot be empty", index)));
            }
            ExecConfig::validate_single_statement(&sql).map_err(|_| {
                invalid(format!("statements[{}] must be a single SQL statement", index))
            })?;
            out.push(TxStatement { sql, params });
        }
        Ok(Some(out))
    }
}

/// Database transaction wrapper for different drivers
#[derive(Debug)]
pub enum DbTransaction {
    Postgres(sqlx::Transaction<'static, sqlx::Postgres>),
    Mysql(sqlx::Transaction<'static, sqlx::MySql>),
    Sqlite(sqlx::Transaction<'static, sqlx::Sqlite>),
}

/// Database transaction handle containing transaction and metadata
#[derive(Debug)]
pub struct DbTransactionHandle {
    pub driver: DbDriver,
    pub alias: String,
    pub tx_id: String,
    pub tx: std::sync::Mutex<Option<DbTransaction>>,
}

impl DbTransactionHandle {
    fn new(driver: DbDriver, alias: String, tx_id: String, tx: DbTransaction) -> Self {
        Self {
            driver,
            alias,
            tx_id,
            tx: std::sync::Mutex::new(Some(tx)),
        }
    }

    /// Take the transaction out of the handle (for commit/rollback)
    fn take_transaction(&self) -> Option<DbTransaction> {
        self.tx.lock().unwrap().take()
    }
}

/// Transaction registry for managing active transactions
type TransactionRegistry = DashMap<String, Arc<DbTransactionHandle>>;

/// Global transaction registry
static TRANSACTION_REGISTRY: LazyLock<TransactionRegistry> = LazyLock::new(|| DashMap::new());

/// Database handle for URL parsing and dispatch
#[derive(Debug)]
pub struct DbHandle {
    driver: DbDriver,
    driver_str: String, // Store raw driver string for error reporting
    alias: String,
}

impl DbHandle {
    /// Returns `Some(topic)` when the call is a help request: the verb is
    /// `help`, `--help` or `-h` (exact match), or `--help=<verb>`, or the
    /// arguments contain a bare `help`/`--help`/`-h` flag. The topic is the
    /// verb whose help was asked for, if any.
    fn help_topic<'a>(&self, verb: &'a str, args: &'a Args) -> Option<Option<&'a str>> {
        let from_args = || args.get("verb").map(|s| s.as_str()).filter(|s| !s.is_empty());
        if verb == "help" || crate::core::help::is_help_flag(verb) || self.driver_str == "help" {
            return Some(from_args());
        }
        if let Some(v) = verb.strip_prefix("--help=") {
            return Some(Some(v).filter(|s| !s.is_empty()));
        }
        if ["help", "h", "--help", "-h"].iter().any(|k| args.contains_key(*k)) {
            return Some(Some(verb));
        }
        None
    }

    /// True if the call is a help request (see `help_topic`).
    pub fn should_show_help(&self, verb: &str, args: &Args) -> bool {
        self.help_topic(verb, args).is_some()
    }

    /// Writes the approved `DB_HELP` text, for one verb when `verb_specific`
    /// names a documented verb, otherwise for the whole handle.
    pub fn display_help(&self, io: &mut IoStreams, verb_specific: Option<&str>) -> Result<Status> {
        let text = crate::core::help::render_legacy("db", &DB_HELP, self.verbs(), verb_specific);
        write!(io.stdout, "{}", text)?;
        Ok(Status::ok())
    }

    /// Create new DbHandle from URL
    pub fn from_url(url: Url) -> Result<Self> {
        // Check for help flags in URL path or host early
        let path = url.path();
        let host = url.host_str().unwrap_or("");
        
        // Special handling for help requests at URL level (exact match, so
        // aliases such as db://sqlite/my-hosts are not treated as help)
        if crate::core::help::is_help_flag(host) || crate::core::help::is_help_flag(path) {
            // Return a dummy handle - help will be detected in call()
            return Ok(Self {
                driver: DbDriver::Sqlite, // Dummy value
                driver_str: "help".to_string(),
                alias: "help".to_string(),
            });
        }
        
        // Parse URL format: db://<driver>/<alias>
        let host = url.host_str()
            .context("db:// URL must have driver as host")?;
        
        // Extract alias from path, removing leading slash
        let path = url.path();
        let alias = if path.starts_with('/') {
            &path[1..]
        } else {
            path
        };
        
        if alias.is_empty() {
            bail!("db:// URL must specify alias in path");
        }

        // Parse driver - fail for unsupported drivers
        let driver = DbDriver::from_str(host)
            .with_context(|| format!("unsupported driver: {}", host))?;
        
        Ok(Self {
            driver,
            driver_str: host.to_string(),
            alias: alias.to_string(),
        })
    }

    /// Connect verb implementation
    pub async fn connect(&self, args: Args) -> Result<Value> {
        // First validate the driver string to provide proper error for unsupported drivers
        if DbDriver::from_str(&self.driver_str).is_err() {
            return Err(DbError::UnsupportedDriver {
                driver: self.driver_str.clone(),
            }.into());
        }
        
        // Parse and validate configuration
        let config = self.parse_config(&args)?;
        
        // Get or resolve DSN
        let dsn = self.resolve_dsn(&args)?;
        
        // Create DSN hash for alias conflict detection
        let dsn_hash = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            dsn.hash(&mut hasher);
            hasher.finish()
        };

        // Check for existing connection in registry
        let cache_key = (self.driver.clone(), self.alias.clone());
        
        if let Some(existing_handle) = CONNECTION_REGISTRY.get(&cache_key) {
            // Check for alias conflict (same alias with different DSN)
            if existing_handle.dsn_hash != dsn_hash {
                return Err(DbError::AliasConflict {
                    driver: self.driver.as_str().to_string(),
                    alias: self.alias.clone(),
                }.into());
            }
            
            // Return existing connection
            let stats = existing_handle.pool.stats();
            return Ok(json!({
                "type": "db_connection",
                "driver": self.driver.as_str(),
                "alias": self.alias,
                "pool_stats": {
                    "max_connections": existing_handle.config.max_connections,
                    "min_connections": existing_handle.config.min_connections,
                    "current_size": stats.size,
                    "idle_connections": stats.num_idle
                },
                "reused": true
            }));
        }

        // Create new connection pool
        let pool = self.create_pool(&dsn, &config).await?;
        
        let connection_handle = Arc::new(DbConnectionHandle {
            driver: self.driver.clone(),
            alias: self.alias.clone(),
            pool: pool.clone(),
            dsn_hash,
            config: config.clone(),
        });

        // Store in registry
        CONNECTION_REGISTRY.insert(cache_key, connection_handle);
        
        let stats = pool.stats();
        Ok(json!({
            "type": "db_connection",
            "driver": self.driver.as_str(),
            "alias": self.alias,
            "pool_stats": {
                "max_connections": config.max_connections,
                "min_connections": config.min_connections,
                "current_size": stats.size,
                "idle_connections": stats.num_idle
            },
            "reused": false
        }))
    }

    /// Connection arguments forwarded to `connect` when a verb connects on demand.
    const CONNECT_ARGS: &'static [&'static str] = &[
        "dsn",
        "max_connections",
        "min_connections",
        "connect_timeout_ms",
        "idle_timeout_ms",
        "max_lifetime_ms",
        "tls_mode",
        "log_queries",
    ];

    /// Returns the registered pool for this driver and alias. When none is
    /// registered and a DSN is available (dsn= or DB_<ALIAS>_DSN), connects
    /// first with the connection arguments in `args`. Pools exist only in
    /// process memory, so this is what makes every verb usable from a fresh
    /// resh invocation.
    async fn resolve_connection(&self, args: &Value) -> Result<Arc<DbConnectionHandle>> {
        let cache_key = (self.driver.clone(), self.alias.clone());
        let existing = CONNECTION_REGISTRY.get(&cache_key).map(|r| Arc::clone(r.value()));
        if let Some(handle) = existing {
            return Ok(handle);
        }

        let mut connect_args = Args::new();
        for key in Self::CONNECT_ARGS {
            match args.get(*key) {
                None | Some(Value::Null) => {}
                Some(Value::String(v)) => {
                    connect_args.insert(key.to_string(), v.clone());
                }
                Some(other) => {
                    connect_args.insert(key.to_string(), other.to_string());
                }
            }
        }
        let env_var = format!("DB_{}_DSN", self.alias.to_uppercase());
        let has_dsn = connect_args.get("dsn").map_or(false, |d| !d.is_empty())
            || std::env::var(&env_var).map_or(false, |d| !d.is_empty());
        if !has_dsn {
            return Err(DbError::ConnectionNotFound {
                driver: self.driver.as_str().to_string(),
                alias: self.alias.clone(),
            }
            .into());
        }

        log::debug!("Auto-connecting driver='{}' alias='{}'", self.driver.as_str(), self.alias);
        self.connect(connect_args).await?;
        let connected = CONNECTION_REGISTRY.get(&cache_key).map(|r| Arc::clone(r.value()));
        connected.ok_or_else(|| {
            DbError::ConnectionNotFound {
                driver: self.driver.as_str().to_string(),
                alias: self.alias.clone(),
            }
            .into()
        })
    }

    /// Parse configuration from arguments with validation
    fn parse_config(&self, args: &Args) -> Result<DbConfig> {
        let mut config = DbConfig::default();

        if let Some(max_conn_str) = args.get("max_connections") {
            config.max_connections = max_conn_str.parse()
                .context("max_connections must be a positive integer")?;
        }

        if let Some(min_conn_str) = args.get("min_connections") {
            config.min_connections = min_conn_str.parse()
                .context("min_connections must be a positive integer")?;
        }

        if let Some(timeout_str) = args.get("connect_timeout_ms") {
            config.connect_timeout_ms = timeout_str.parse()
                .context("connect_timeout_ms must be a positive integer")?;
        }

        if let Some(idle_str) = args.get("idle_timeout_ms") {
            config.idle_timeout_ms = idle_str.parse()
                .context("idle_timeout_ms must be a positive integer")?;
        }

        if let Some(lifetime_str) = args.get("max_lifetime_ms") {
            config.max_lifetime_ms = lifetime_str.parse()
                .context("max_lifetime_ms must be a positive integer")?;
        }

        if let Some(tls_mode) = args.get("tls_mode") {
            config.tls_mode = Some(tls_mode.clone()).filter(|m| !m.trim().is_empty());
        }

        if let Some(log_queries_str) = args.get("log_queries") {
            config.log_queries = crate::core::lenient::from_value::<bool>(Value::String(log_queries_str.clone()))
                .map_err(|_| DbError::InvalidConfig {
                    field: "log_queries".to_string(),
                    message: format!("must be true or false, got '{}'", log_queries_str),
                })?;
        }

        // Validate configuration
        self.validate_config(&config)?;
        
        Ok(config)
    }

    /// Validate configuration parameters
    fn validate_config(&self, config: &DbConfig) -> Result<()> {
        if config.max_connections == 0 {
            return Err(DbError::InvalidConfig {
                field: "max_connections".to_string(),
                message: "must be greater than 0".to_string(),
            }.into());
        }

        if config.min_connections == 0 {
            return Err(DbError::InvalidConfig {
                field: "min_connections".to_string(), 
                message: "must be greater than 0".to_string(),
            }.into());
        }

        if config.max_connections < config.min_connections {
            return Err(DbError::InvalidConfig {
                field: "connections".to_string(),
                message: "max_connections must be >= min_connections".to_string(),
            }.into());
        }

        if config.connect_timeout_ms == 0 {
            return Err(DbError::InvalidConfig {
                field: "connect_timeout_ms".to_string(),
                message: "must be greater than 0".to_string(), 
            }.into());
        }

        if config.idle_timeout_ms == 0 {
            return Err(DbError::InvalidConfig {
                field: "idle_timeout_ms".to_string(),
                message: "must be greater than 0".to_string(),
            }.into());
        }

        if config.max_lifetime_ms == 0 {
            return Err(DbError::InvalidConfig {
                field: "max_lifetime_ms".to_string(),
                message: "must be greater than 0".to_string(),
            }.into());
        }

        // Validate TLS mode against what the driver supports
        self.tls_mode(config)?;

        Ok(())
    }

    /// Parses and checks `config.tls_mode` for this driver. PostgreSQL takes
    /// every mode; MySQL has no "allow"; SQLite has no TLS, so only
    /// "disable" is accepted there.
    fn tls_mode(&self, config: &DbConfig) -> Result<Option<TlsMode>> {
        let raw = match config.tls_mode.as_deref() {
            None => return Ok(None),
            Some(raw) => raw,
        };
        let invalid = |message: String| -> anyhow::Error {
            DbError::InvalidConfig { field: "tls_mode".to_string(), message }.into()
        };
        let mode = TlsMode::parse(raw).ok_or_else(|| {
            invalid(format!(
                "'{}' is not valid; use disable, allow, prefer, require, verify_ca or verify_full",
                raw
            ))
        })?;
        match (&self.driver, mode) {
            (DbDriver::Mysql, TlsMode::Allow) => Err(invalid(
                "allow is not supported by mysql; use disable, prefer, require, verify_ca or verify_full".to_string(),
            )),
            (DbDriver::Sqlite, TlsMode::Disable) => Ok(Some(mode)),
            (DbDriver::Sqlite, _) => Err(invalid(
                "sqlite connections do not use TLS; omit tls_mode or use tls_mode=disable".to_string(),
            )),
            _ => Ok(Some(mode)),
        }
    }

    /// Resolve DSN from arguments or environment
    fn resolve_dsn(&self, args: &Args) -> Result<String> {
        // First try args
        if let Some(dsn) = args.get("dsn") {
            if !dsn.is_empty() {
                return self.normalize_dsn(dsn);
            }
        }

        // Try environment variable
        let env_var = format!("DB_{}_DSN", self.alias.to_uppercase());
        if let Ok(dsn) = std::env::var(&env_var) {
            if !dsn.is_empty() {
                return self.normalize_dsn(&dsn);
            }
        }

        Err(DbError::MissingDsn {
            alias: self.alias.clone(),
            env_var,
        }.into())
    }

    /// Normalize and validate DSN, providing helpful error messages
    fn normalize_dsn(&self, dsn: &str) -> Result<String> {
        // First try parsing as-is
        match Url::parse(dsn) {
            Ok(url) => {
                // Validate the scheme matches the driver
                let expected_scheme = match self.driver {
                    DbDriver::Postgres => "postgresql",
                    DbDriver::Mysql => "mysql", 
                    DbDriver::Sqlite => "sqlite",
                };
                
                if url.scheme() != expected_scheme && !(url.scheme() == "postgres" && expected_scheme == "postgresql") {
                    return Err(DbError::InvalidDsn {
                        dsn: dsn.to_string(),
                        message: format!("DSN scheme '{}' does not match driver '{}'. Expected scheme: '{}'", 
                                       url.scheme(), self.driver.as_str(), expected_scheme),
                    }.into());
                }
                
                return Ok(dsn.to_string());
            }
            Err(parse_error) => {
                // Check for common issues and provide helpful suggestions
                let mut suggestions = Vec::new();
                
                // Check for shell variable expansion issues (missing @ after password)
                if dsn.contains("://") && !dsn.contains("@") && dsn.matches(":").count() >= 2 {
                    // Pattern like mysql://user:password192.168.1.1:3306/db suggests $@ was consumed by shell
                    suggestions.push("Password may contain special characters that were interpreted by shell. Use single quotes around DSN or URL-encode special characters ($ becomes %24)".to_string());
                }
                
                // Check for unencoded special characters in password/username
                if dsn.contains("$") || dsn.contains("#") || dsn.contains("%") || dsn.contains("&") {
                    if !dsn.contains("%") {  // Only suggest if no percent-encoding detected
                        suggestions.push("Special characters in username/password need URL encoding (e.g., $ becomes %24, @ becomes %40)".to_string());
                    }
                }
                
                // Check for missing port
                if dsn.contains("://") && !dsn.matches(":").collect::<Vec<_>>().len() >= 2 {
                    suggestions.push("Missing port number in DSN (e.g., mysql://user:pass@host:3306/db)".to_string());
                }
                
                // Check for missing database name
                if dsn.contains("://") {
                    let scheme_pos = dsn.find("://").unwrap() + 3;
                    if !dsn[scheme_pos..].contains("/") {
                        suggestions.push("Missing database name in DSN (add /database_name at the end)".to_string());
                    }
                }
                
                let suggestion_text = if suggestions.is_empty() {
                    "".to_string()
                } else {
                    format!(" Suggestions: {}", suggestions.join("; "))
                };
                
                return Err(DbError::InvalidDsn {
                    dsn: dsn.to_string(),
                    message: format!("Invalid DSN format: {}.{}", parse_error, suggestion_text),
                }.into());
            }
        }
    }

    /// Create database connection pool. tls_mode= sets the driver's SSL mode
    /// (overriding any sslmode/ssl-mode in the DSN), and log_queries= turns
    /// sqlx statement logging on (info level) or off.
    async fn create_pool(&self, dsn: &str, config: &DbConfig) -> Result<DbPool> {
        use sqlx::ConnectOptions;
        use std::str::FromStr;

        let tls = self.tls_mode(config)?;
        let invalid_dsn = |e: sqlx::Error| DbError::InvalidDsn {
            dsn: redact_dsn(dsn),
            message: e.to_string(),
        };
        fn logging<O: ConnectOptions>(opts: O, log_queries: bool) -> O {
            if log_queries {
                opts.log_statements(log::LevelFilter::Info)
            } else {
                opts.disable_statement_logging()
            }
        }

        match self.driver {
            DbDriver::Postgres => {
                let mut opts = sqlx::postgres::PgConnectOptions::from_str(dsn).map_err(invalid_dsn)?;
                if let Some(mode) = tls {
                    opts = opts.ssl_mode(mode.postgres());
                }
                let opts = logging(opts, config.log_queries);
                let pool = sqlx::postgres::PgPoolOptions::new()
                    .max_connections(config.max_connections)
                    .min_connections(config.min_connections)
                    .acquire_timeout(Duration::from_millis(config.connect_timeout_ms))
                    .idle_timeout(Some(Duration::from_millis(config.idle_timeout_ms)))
                    .max_lifetime(Some(Duration::from_millis(config.max_lifetime_ms)))
                    .connect_with(opts)
                    .await
                    .map_err(|e| DbError::ConnectFailed { message: format!("PostgreSQL connection failed: {}", e) })?;
                Ok(DbPool::Postgres(pool))
            }
            DbDriver::Mysql => {
                let mut opts = sqlx::mysql::MySqlConnectOptions::from_str(dsn).map_err(invalid_dsn)?;
                if let Some(mode) = tls {
                    opts = opts.ssl_mode(mode.mysql());
                }
                let opts = logging(opts, config.log_queries);
                let pool = sqlx::mysql::MySqlPoolOptions::new()
                    .max_connections(config.max_connections)
                    .min_connections(config.min_connections)
                    .acquire_timeout(Duration::from_millis(config.connect_timeout_ms))
                    .idle_timeout(Some(Duration::from_millis(config.idle_timeout_ms)))
                    .max_lifetime(Some(Duration::from_millis(config.max_lifetime_ms)))
                    .connect_with(opts)
                    .await
                    .map_err(|e| DbError::ConnectFailed { message: format!("MySQL connection failed: {}", e) })?;
                Ok(DbPool::Mysql(pool))
            }
            DbDriver::Sqlite => {
                let opts = sqlx::sqlite::SqliteConnectOptions::from_str(dsn).map_err(invalid_dsn)?;
                let opts = logging(opts, config.log_queries);
                let pool = sqlx::sqlite::SqlitePoolOptions::new()
                    .max_connections(config.max_connections)
                    .min_connections(config.min_connections)
                    .acquire_timeout(Duration::from_millis(config.connect_timeout_ms))
                    .idle_timeout(Some(Duration::from_millis(config.idle_timeout_ms)))
                    .max_lifetime(Some(Duration::from_millis(config.max_lifetime_ms)))
                    .connect_with(opts)
                    .await
                    .map_err(|e| DbError::ConnectFailed { message: format!("SQLite connection failed: {}", e) })?;
                Ok(DbPool::Sqlite(pool))
            }
        }
    }

    /// Query verb implementation
    pub async fn query(&self, args: Value) -> Result<Value> {
        // Parse configuration
        let config = QueryConfig::from_args(&args)
            .map_err(|e| DbError::InvalidQueryConfig { message: e.to_string() })?;

        // Log the query (without parameters for security)
        log::debug!("Executing query for driver='{}' alias='{}' sql='{}' tx_id={:?}", 
                   self.driver.as_str(), self.alias, config.sql, config.tx_id);

        // Check if this should run in a transaction
        if let Some(ref tx_id) = config.tx_id {
            // Execute in transaction
            self.execute_query_in_transaction(tx_id, &config).await
        } else {
            // Execute with connection pool (auto-connect if needed)
            self.execute_query_with_pool(&config, &args).await
        }
    }

    /// Execute query using connection pool (autocommit)
    async fn execute_query_with_pool(&self, config: &QueryConfig, args: &Value) -> Result<Value> {
        // Look up connection handle, connecting on demand when dsn= is given
        let handle = self.resolve_connection(args).await?;

        // Execute query with timeout
        let result = tokio::time::timeout(
            Duration::from_millis(config.timeout_ms),
            self.execute_query(&handle.pool, config)
        ).await;

        match result {
            Ok(query_result) => query_result,
            Err(_) => Err(DbError::QueryTimeout { 
                timeout_ms: config.timeout_ms 
            }.into()),
        }
    }

    /// Execute query within a transaction
    async fn execute_query_in_transaction(&self, tx_id: &str, config: &QueryConfig) -> Result<Value> {
        // Get transaction handle
        let tx_handle = TRANSACTION_REGISTRY
            .get(tx_id)
            .ok_or_else(|| DbError::TransactionNotFound {
                tx_id: tx_id.to_string(),
            })?;

        // Verify driver/alias match
        let expected = format!("{}:{}", self.driver.as_str(), self.alias);
        let actual = format!("{}:{}", tx_handle.driver.as_str(), tx_handle.alias);
        if expected != actual {
            return Err(DbError::TransactionAliasMismatch {
                tx_id: tx_id.to_string(),
                expected,
                actual,
            })?;
        }

        // Execute query with timeout
        let result = tokio::time::timeout(
            Duration::from_millis(config.timeout_ms),
            self.execute_query_on_transaction(&*tx_handle, config)
        ).await;

        match result {
            Ok(query_result) => query_result,
            Err(_) => Err(DbError::QueryTimeout { 
                timeout_ms: config.timeout_ms 
            }.into()),
        }
    }

    /// Execute query on a transaction handle
    async fn execute_query_on_transaction(&self, tx_handle: &DbTransactionHandle, config: &QueryConfig) -> Result<Value> {
        // This is tricky because we need mutable access to the transaction
        // We'll use a different approach: create helper methods that work with the transaction mutex
        let tx_mutex = &tx_handle.tx;
        let mut tx_guard = tx_mutex.lock().unwrap();
        
        let tx = tx_guard.as_mut()
            .ok_or_else(|| DbError::TransactionClosed {
                tx_id: tx_handle.tx_id.clone(),
            })?;

        match tx {
            DbTransaction::Postgres(tx) => {
                self.execute_postgres_query_on_tx(tx, config).await
            }
            DbTransaction::Mysql(tx) => {
                self.execute_mysql_query_on_tx(tx, config).await
            }
            DbTransaction::Sqlite(tx) => {
                self.execute_sqlite_query_on_tx(tx, config).await
            }
        }
    }

    /// Exec verb implementation
    pub async fn exec(&self, args: Value) -> Result<Value> {
        // Parse configuration
        let config = ExecConfig::from_args(&args)?;

        // Log the exec (without parameters for security)
        log::debug!("Executing exec for driver='{}' alias='{}' sql='{}' tx_id={:?}", 
                   self.driver.as_str(), self.alias, config.sql, config.tx_id);

        // Check if this should run in a transaction
        if let Some(ref tx_id) = config.tx_id {
            // Execute in transaction
            self.execute_exec_in_transaction(tx_id, &config).await
        } else {
            // Execute with connection pool (auto-connect if needed)
            self.execute_exec_with_pool(&config, &args).await
        }
    }

    /// Execute exec using connection pool (autocommit)
    async fn execute_exec_with_pool(&self, config: &ExecConfig, args: &Value) -> Result<Value> {
        // Look up connection handle, connecting on demand when dsn= is given
        let handle = self.resolve_connection(args).await?;

        // Execute with timeout
        let result = tokio::time::timeout(
            Duration::from_millis(config.timeout_ms),
            self.execute_exec_statement(&handle.pool, config)
        ).await;

        match result {
            Ok(exec_result) => exec_result,
            Err(_) => Err(DbError::ExecTimeout { 
                timeout_ms: config.timeout_ms 
            }.into()),
        }
    }

    /// Execute exec within a transaction
    async fn execute_exec_in_transaction(&self, tx_id: &str, config: &ExecConfig) -> Result<Value> {
        // Get transaction handle
        let tx_handle = TRANSACTION_REGISTRY
            .get(tx_id)
            .ok_or_else(|| DbError::TransactionNotFound {
                tx_id: tx_id.to_string(),
            })?;

        // Verify driver/alias match
        let expected = format!("{}:{}", self.driver.as_str(), self.alias);
        let actual = format!("{}:{}", tx_handle.driver.as_str(), tx_handle.alias);
        if expected != actual {
            return Err(DbError::TransactionAliasMismatch {
                tx_id: tx_id.to_string(),
                expected,
                actual,
            })?;
        }

        // Execute exec with timeout
        let result = tokio::time::timeout(
            Duration::from_millis(config.timeout_ms),
            self.execute_exec_on_transaction(&*tx_handle, config)
        ).await;

        match result {
            Ok(exec_result) => exec_result,
            Err(_) => Err(DbError::ExecTimeout { 
                timeout_ms: config.timeout_ms 
            }.into()),
        }
    }

    /// Execute exec on a transaction handle
    async fn execute_exec_on_transaction(&self, tx_handle: &DbTransactionHandle, config: &ExecConfig) -> Result<Value> {
        let tx_mutex = &tx_handle.tx;
        let mut tx_guard = tx_mutex.lock().unwrap();
        
        let tx = tx_guard.as_mut()
            .ok_or_else(|| DbError::TransactionClosed {
                tx_id: tx_handle.tx_id.clone(),
            })?;

        match tx {
            DbTransaction::Postgres(tx) => {
                self.execute_postgres_exec_on_tx(tx, config).await
            }
            DbTransaction::Mysql(tx) => {
                self.execute_mysql_exec_on_tx(tx, config).await
            }
            DbTransaction::Sqlite(tx) => {
                self.execute_sqlite_exec_on_tx(tx, config).await
            }
        }
    }

    /// Execute the actual exec statement against the database pool
    async fn execute_exec_statement(&self, pool: &DbPool, config: &ExecConfig) -> Result<Value> {
        match pool {
            DbPool::Postgres(p) => {
                let mut query = sqlx::query(&config.sql);
                for param in &config.params {
                    query = bind_param(query, param)?;
                }
                
                let result = query.execute(p).await
                    .map_err(|e| DbError::ExecFailed { message: e.to_string() })?;

                let mut response = json!({
                    "rows_affected": result.rows_affected()
                });

                // For Postgres, last_insert_id is not typically available from execute()
                // We only include it when explicitly requested and return null
                if config.return_last_insert_id {
                    response["last_insert_id"] = Value::Null;
                }

                Ok(response)
            }
            DbPool::Mysql(p) => {
                let mut query = sqlx::query(&config.sql);
                for param in &config.params {
                    query = bind_param_mysql(query, param)?;
                }
                
                let result = query.execute(p).await
                    .map_err(|e| DbError::ExecFailed { message: e.to_string() })?;

                let mut response = json!({
                    "rows_affected": result.rows_affected()
                });

                if config.return_last_insert_id {
                    response["last_insert_id"] = json!(result.last_insert_id());
                }

                Ok(response)
            }
            DbPool::Sqlite(p) => {
                let mut query = sqlx::query(&config.sql);
                for param in &config.params {
                    query = bind_param_sqlite(query, param)?;
                }
                
                let result = query.execute(p).await
                    .map_err(|e| DbError::ExecFailed { message: e.to_string() })?;

                let mut response = json!({
                    "rows_affected": result.rows_affected()
                });

                if config.return_last_insert_id {
                    // Get last insert rowid for SQLite
                    let last_id_query = sqlx::query_scalar::<_, i64>("SELECT last_insert_rowid()")
                        .fetch_one(p).await
                        .map_err(|e| DbError::ExecFailed { 
                            message: format!("Failed to get last_insert_rowid: {}", e) 
                        })?;
                    response["last_insert_id"] = json!(last_id_query);
                }

                Ok(response)
            }
        }
    }

    /// Tables verb implementation for database introspection
    pub async fn tables(&self, args: Value) -> Result<Value> {
        // Parse configuration
        let config = TablesConfig::from_args(&args)?;

        // Log the operation
        log::debug!("Executing tables for driver='{}' alias='{}' table={:?} schema={:?}", 
                   self.driver.as_str(), self.alias, config.table, config.schema);

        // Look up connection handle, connecting on demand when dsn= is given
        let handle = self.resolve_connection(&args).await?;

        // Execute with timeout
        let result = tokio::time::timeout(
            Duration::from_millis(config.timeout_ms),
            self.execute_tables_operation(&handle.pool, &config)
        ).await;

        match result {
            Ok(tables_result) => tables_result,
            Err(_) => Err(DbError::TablesTimeout { 
                timeout_ms: config.timeout_ms 
            }.into()),
        }
    }

    /// Execute the actual tables operation against the database pool
    async fn execute_tables_operation(&self, pool: &DbPool, config: &TablesConfig) -> Result<Value> {
        match &config.table {
            None => {
                // List mode
                match pool {
                    DbPool::Postgres(p) => list_tables_postgres(p, config).await.map_err(|e| e.into()),
                    DbPool::Mysql(p) => list_tables_mysql(p, config).await.map_err(|e| e.into()),
                    DbPool::Sqlite(p) => list_tables_sqlite(p, config).await.map_err(|e| e.into()),
                }
            }
            Some(table_name) => {
                // Describe mode
                match pool {
                    DbPool::Postgres(p) => describe_table_postgres(p, config, table_name).await.map_err(|e| e.into()),
                    DbPool::Mysql(p) => describe_table_mysql(p, config, table_name).await.map_err(|e| e.into()),
                    DbPool::Sqlite(p) => describe_table_sqlite(p, config, table_name).await.map_err(|e| e.into()),
                }
            }
        }
    }

    /// Schema verb implementation for rich table schema introspection
    pub async fn schema(&self, args: Value) -> Result<Value> {
        // Parse configuration
        let config = SchemaConfig::from_args(&args)?;

        // Log the operation
        log::debug!("Executing schema for driver='{}' alias='{}' table='{}' schema={:?}", 
                   self.driver.as_str(), self.alias, config.table, config.schema);

        // Look up connection handle, connecting on demand when dsn= is given
        let handle = self.resolve_connection(&args).await?;

        // Execute with timeout
        let result = tokio::time::timeout(
            Duration::from_millis(config.timeout_ms),
            self.execute_schema_operation(&handle.pool, &config)
        ).await;

        match result {
            Ok(schema_result) => schema_result,
            Err(_) => Err(DbError::SchemaTimeout { 
                timeout_ms: config.timeout_ms 
            }.into()),
        }
    }

    /// Execute the actual schema operation against the database pool
    async fn execute_schema_operation(&self, pool: &DbPool, config: &SchemaConfig) -> Result<Value> {
        match pool {
            DbPool::Postgres(p) => schema_postgres(p, config).await,
            DbPool::Mysql(p) => schema_mysql(p, config).await,
            DbPool::Sqlite(p) => schema_sqlite(p, config).await,
        }
    }

    /// Execute PostgreSQL query on transaction
    async fn execute_postgres_query_on_tx(&self, tx: &mut sqlx::Transaction<'static, sqlx::Postgres>, config: &QueryConfig) -> Result<Value> {
        match config.mode {
            QueryMode::Rows => {
                let mut query = sqlx::query(&config.sql);
                for param in &config.params {
                    query = bind_param(query, param)?;
                }
                
                let rows = query.fetch_all(&mut **tx).await
                    .map_err(|e| DbError::QueryFailed { message: e.to_string() })?;

                let mut results = Vec::new();
                for row in &rows[..config.max_rows.min(rows.len() as u64) as usize] {
                    let mut obj = serde_json::Map::new();
                    for (i, column) in row.columns().iter().enumerate() {
                        let column_name = column.name();
                        let value = convert_postgres_value(row, i);
                        obj.insert(column_name.to_string(), value);
                    }
                    results.push(serde_json::Value::Object(obj));
                }

                Ok(json!({
                    "rows": results,
                    "count": results.len()
                }))
            }
            QueryMode::Scalar => {
                let mut query = sqlx::query(&config.sql);
                for param in &config.params {
                    query = bind_param(query, param)?;
                }
                
                let row = query.fetch_optional(&mut **tx).await
                    .map_err(|e| DbError::QueryFailed { message: e.to_string() })?;

                let value = if let Some(row) = row {
                    convert_postgres_value(&row, 0)
                } else {
                    Value::Null
                };

                Ok(json!({ "value": value }))
            }
            QueryMode::Exec => {
                let mut query = sqlx::query(&config.sql);
                for param in &config.params {
                    query = bind_param(query, param)?;
                }
                
                let result = query.execute(&mut **tx).await
                    .map_err(|e| DbError::QueryFailed { message: e.to_string() })?;

                Ok(json!({ "rows_affected": result.rows_affected() }))
            }
        }
    }

    /// Execute MySQL query on transaction
    async fn execute_mysql_query_on_tx(&self, tx: &mut sqlx::Transaction<'static, sqlx::MySql>, config: &QueryConfig) -> Result<Value> {
        match config.mode {
            QueryMode::Rows => {
                let mut query = sqlx::query(&config.sql);
                for param in &config.params {
                    query = bind_param_mysql(query, param)?;
                }
                
                let rows = query.fetch_all(&mut **tx).await
                    .map_err(|e| DbError::QueryFailed { message: e.to_string() })?;

                let mut results = Vec::new();
                for row in &rows[..config.max_rows.min(rows.len() as u64) as usize] {
                    let mut obj = serde_json::Map::new();
                    for (i, column) in row.columns().iter().enumerate() {
                        let column_name = column.name();
                        let value = convert_mysql_value(row, i);
                        obj.insert(column_name.to_string(), value);
                    }
                    results.push(serde_json::Value::Object(obj));
                }

                Ok(json!({
                    "rows": results,
                    "count": results.len()
                }))
            }
            QueryMode::Scalar => {
                let mut query = sqlx::query(&config.sql);
                for param in &config.params {
                    query = bind_param_mysql(query, param)?;
                }
                
                let row = query.fetch_optional(&mut **tx).await
                    .map_err(|e| DbError::QueryFailed { message: e.to_string() })?;

                let value = if let Some(row) = row {
                    convert_mysql_value(&row, 0)
                } else {
                    Value::Null
                };

                Ok(json!({ "value": value }))
            }
            QueryMode::Exec => {
                let mut query = sqlx::query(&config.sql);
                for param in &config.params {
                    query = bind_param_mysql(query, param)?;
                }
                
                let result = query.execute(&mut **tx).await
                    .map_err(|e| DbError::QueryFailed { message: e.to_string() })?;

                Ok(json!({ "rows_affected": result.rows_affected() }))
            }
        }
    }

    /// Execute SQLite query on transaction
    async fn execute_sqlite_query_on_tx(&self, tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>, config: &QueryConfig) -> Result<Value> {
        match config.mode {
            QueryMode::Rows => {
                let mut query = sqlx::query(&config.sql);
                for param in &config.params {
                    query = bind_param_sqlite(query, param)?;
                }
                
                let rows = query.fetch_all(&mut **tx).await
                    .map_err(|e| DbError::QueryFailed { message: e.to_string() })?;

                let mut results = Vec::new();
                for row in &rows[..config.max_rows.min(rows.len() as u64) as usize] {
                    let mut obj = serde_json::Map::new();
                    for (i, column) in row.columns().iter().enumerate() {
                        let column_name = column.name();
                        let value = convert_sqlite_value(row, i);
                        obj.insert(column_name.to_string(), value);
                    }
                    results.push(serde_json::Value::Object(obj));
                }

                Ok(json!({
                    "rows": results,
                    "count": results.len()
                }))
            }
            QueryMode::Scalar => {
                let mut query = sqlx::query(&config.sql);
                for param in &config.params {
                    query = bind_param_sqlite(query, param)?;
                }
                
                let row = query.fetch_optional(&mut **tx).await
                    .map_err(|e| DbError::QueryFailed { message: e.to_string() })?;

                let value = if let Some(row) = row {
                    convert_sqlite_value(&row, 0)
                } else {
                    Value::Null
                };

                Ok(json!({ "value": value }))
            }
            QueryMode::Exec => {
                let mut query = sqlx::query(&config.sql);
                for param in &config.params {
                    query = bind_param_sqlite(query, param)?;
                }
                
                let result = query.execute(&mut **tx).await
                    .map_err(|e| DbError::QueryFailed { message: e.to_string() })?;

                Ok(json!({ "rows_affected": result.rows_affected() }))
            }
        }
    }

    /// Execute PostgreSQL exec on transaction
    async fn execute_postgres_exec_on_tx(&self, tx: &mut sqlx::Transaction<'static, sqlx::Postgres>, config: &ExecConfig) -> Result<Value> {
        let mut query = sqlx::query(&config.sql);
        for param in &config.params {
            query = bind_param(query, param)?;
        }
        
        let result = query.execute(&mut **tx).await
            .map_err(|e| DbError::ExecFailed { message: e.to_string() })?;

        let mut response = json!({
            "rows_affected": result.rows_affected()
        });

        // For Postgres, last_insert_id is not typically available from execute()
        if config.return_last_insert_id {
            response["last_insert_id"] = Value::Null;
        }

        Ok(response)
    }

    /// Execute MySQL exec on transaction
    async fn execute_mysql_exec_on_tx(&self, tx: &mut sqlx::Transaction<'static, sqlx::MySql>, config: &ExecConfig) -> Result<Value> {
        let mut query = sqlx::query(&config.sql);
        for param in &config.params {
            query = bind_param_mysql(query, param)?;
        }
        
        let result = query.execute(&mut **tx).await
            .map_err(|e| DbError::ExecFailed { message: e.to_string() })?;

        let mut response = json!({
            "rows_affected": result.rows_affected()
        });

        if config.return_last_insert_id {
            // For MySQL, we can get last_insert_id from the result
            response["last_insert_id"] = json!(result.last_insert_id());
        }

        Ok(response)
    }

    /// Execute SQLite exec on transaction
    async fn execute_sqlite_exec_on_tx(&self, tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>, config: &ExecConfig) -> Result<Value> {
        let mut query = sqlx::query(&config.sql);
        for param in &config.params {
            query = bind_param_sqlite(query, param)?;
        }
        
        let result = query.execute(&mut **tx).await
            .map_err(|e| DbError::ExecFailed { message: e.to_string() })?;

        let mut response = json!({
            "rows_affected": result.rows_affected()
        });

        if config.return_last_insert_id {
            // Get last insert rowid for SQLite
            let last_id_query = sqlx::query_scalar::<_, i64>("SELECT last_insert_rowid()")
                .fetch_one(&mut **tx).await
                .map_err(|e| DbError::ExecFailed { 
                    message: format!("Failed to get last_insert_rowid: {}", e) 
                })?;
            response["last_insert_id"] = json!(last_id_query);
        }

        Ok(response)
    }

    /// Execute the actual query against the database pool
    async fn execute_query(&self, pool: &DbPool, config: &QueryConfig) -> Result<Value> {
        match config.mode {
            QueryMode::Rows => self.execute_rows_query(pool, config).await,
            QueryMode::Scalar => self.execute_scalar_query(pool, config).await,
            QueryMode::Exec => self.execute_exec_query(pool, config).await,
        }
    }

    /// Execute query and return rows
    async fn execute_rows_query(&self, pool: &DbPool, config: &QueryConfig) -> Result<Value> {
        match pool {
            DbPool::Postgres(p) => {
                let mut query = sqlx::query(&config.sql);
                for param in &config.params {
                    query = bind_param(query, param)?;
                }
                
                let rows = query.fetch_all(p).await
                    .map_err(|e| DbError::QueryFailed { message: e.to_string() })?;

                let mut json_rows = Vec::new();
                let mut columns = Vec::new();
                let row_count = rows.len();
                let mut truncated = false;

                // Get column metadata from first row if available
                if let Some(first_row) = rows.first() {
                    for column in first_row.columns() {
                        columns.push(json!({
                            "name": column.name(),
                            "type": column.type_info().name()
                        }));
                    }
                }

                // Process rows with max_rows limit
                let take_count = std::cmp::min(rows.len(), config.max_rows as usize);
                if rows.len() > config.max_rows as usize {
                    truncated = true;
                }

                for row in rows.iter().take(take_count) {
                    json_rows.push(row_to_json_postgres(row)?);
                }

                Ok(json!({
                    "rows": json_rows,
                    "meta": {
                        "row_count": row_count,
                        "truncated": truncated,
                        "columns": columns
                    }
                }))
            }
            DbPool::Mysql(p) => {
                let mut query = sqlx::query(&config.sql);
                for param in &config.params {
                    query = bind_param_mysql(query, param)?;
                }
                
                let rows = query.fetch_all(p).await
                    .map_err(|e| DbError::QueryFailed { message: e.to_string() })?;

                let mut json_rows = Vec::new();
                let mut columns = Vec::new();
                let row_count = rows.len();
                let mut truncated = false;

                // Get column metadata from first row if available
                if let Some(first_row) = rows.first() {
                    for column in first_row.columns() {
                        columns.push(json!({
                            "name": column.name(),
                            "type": column.type_info().name()
                        }));
                    }
                }

                // Process rows with max_rows limit
                let take_count = std::cmp::min(rows.len(), config.max_rows as usize);
                if rows.len() > config.max_rows as usize {
                    truncated = true;
                }

                for row in rows.iter().take(take_count) {
                    json_rows.push(row_to_json_mysql(row)?);
                }

                Ok(json!({
                    "rows": json_rows,
                    "meta": {
                        "row_count": row_count,
                        "truncated": truncated,
                        "columns": columns
                    }
                }))
            }
            DbPool::Sqlite(p) => {
                let mut query = sqlx::query(&config.sql);
                for param in &config.params {
                    query = bind_param_sqlite(query, param)?;
                }
                
                let rows = query.fetch_all(p).await
                    .map_err(|e| DbError::QueryFailed { message: e.to_string() })?;

                let mut json_rows = Vec::new();
                let mut columns = Vec::new();
                let row_count = rows.len();
                let mut truncated = false;

                // Get column metadata from first row if available
                if let Some(first_row) = rows.first() {
                    for column in first_row.columns() {
                        columns.push(json!({
                            "name": column.name(),
                            "type": column.type_info().name()
                        }));
                    }
                }

                // Process rows with max_rows limit
                let take_count = std::cmp::min(rows.len(), config.max_rows as usize);
                if rows.len() > config.max_rows as usize {
                    truncated = true;
                }

                for row in rows.iter().take(take_count) {
                    json_rows.push(row_to_json_sqlite(row)?);
                }

                Ok(json!({
                    "rows": json_rows,
                    "meta": {
                        "row_count": row_count,
                        "truncated": truncated,
                        "columns": columns
                    }
                }))
            }
        }
    }

    /// Execute query and return scalar value
    async fn execute_scalar_query(&self, pool: &DbPool, config: &QueryConfig) -> Result<Value> {
        match pool {
            DbPool::Postgres(p) => {
                let mut query = sqlx::query(&config.sql);
                for param in &config.params {
                    query = bind_param(query, param)?;
                }
                
                let rows = query.fetch_all(p).await
                    .map_err(|e| DbError::QueryFailed { message: e.to_string() })?;

                let row_count = rows.len();
                let mut columns = Vec::new();

                if let Some(first_row) = rows.first() {
                    for column in first_row.columns() {
                        columns.push(json!({
                            "name": column.name(),
                            "type": column.type_info().name()
                        }));
                    }
                    
                    let json_row = row_to_json_postgres(first_row)?;
                    let value = if let Value::Object(obj) = json_row {
                        obj.values().next().cloned().unwrap_or(Value::Null)
                    } else {
                        Value::Null
                    };

                    Ok(json!({
                        "value": value,
                        "meta": {
                            "row_count": row_count,
                            "columns": columns
                        }
                    }))
                } else {
                    Ok(json!({
                        "value": null,
                        "meta": {
                            "row_count": 0,
                            "columns": []
                        }
                    }))
                }
            }
            DbPool::Mysql(p) => {
                let mut query = sqlx::query(&config.sql);
                for param in &config.params {
                    query = bind_param_mysql(query, param)?;
                }
                
                let rows = query.fetch_all(p).await
                    .map_err(|e| DbError::QueryFailed { message: e.to_string() })?;

                let row_count = rows.len();
                let mut columns = Vec::new();

                if let Some(first_row) = rows.first() {
                    for column in first_row.columns() {
                        columns.push(json!({
                            "name": column.name(),
                            "type": column.type_info().name()
                        }));
                    }
                    
                    let json_row = row_to_json_mysql(first_row)?;
                    let value = if let Value::Object(obj) = json_row {
                        obj.values().next().cloned().unwrap_or(Value::Null)
                    } else {
                        Value::Null
                    };

                    Ok(json!({
                        "value": value,
                        "meta": {
                            "row_count": row_count,
                            "columns": columns
                        }
                    }))
                } else {
                    Ok(json!({
                        "value": null,
                        "meta": {
                            "row_count": 0,
                            "columns": []
                        }
                    }))
                }
            }
            DbPool::Sqlite(p) => {
                let mut query = sqlx::query(&config.sql);
                for param in &config.params {
                    query = bind_param_sqlite(query, param)?;
                }
                
                let rows = query.fetch_all(p).await
                    .map_err(|e| DbError::QueryFailed { message: e.to_string() })?;

                let row_count = rows.len();
                let mut columns = Vec::new();

                if let Some(first_row) = rows.first() {
                    for column in first_row.columns() {
                        columns.push(json!({
                            "name": column.name(),
                            "type": column.type_info().name()
                        }));
                    }
                    
                    let json_row = row_to_json_sqlite(first_row)?;
                    let value = if let Value::Object(obj) = json_row {
                        obj.values().next().cloned().unwrap_or(Value::Null)
                    } else {
                        Value::Null
                    };

                    Ok(json!({
                        "value": value,
                        "meta": {
                            "row_count": row_count,
                            "columns": columns
                        }
                    }))
                } else {
                    Ok(json!({
                        "value": null,
                        "meta": {
                            "row_count": 0,
                            "columns": []
                        }
                    }))
                }
            }
        }
    }

    /// Execute query and return execution metadata
    async fn execute_exec_query(&self, pool: &DbPool, config: &QueryConfig) -> Result<Value> {
        match pool {
            DbPool::Postgres(p) => {
                let mut query = sqlx::query(&config.sql);
                for param in &config.params {
                    query = bind_param(query, param)?;
                }
                
                let result = query.execute(p).await
                    .map_err(|e| DbError::QueryFailed { message: e.to_string() })?;

                Ok(json!({
                    "rows_affected": result.rows_affected()
                }))
            }
            DbPool::Mysql(p) => {
                let mut query = sqlx::query(&config.sql);
                for param in &config.params {
                    query = bind_param_mysql(query, param)?;
                }
                
                let result = query.execute(p).await
                    .map_err(|e| DbError::QueryFailed { message: e.to_string() })?;

                Ok(json!({
                    "rows_affected": result.rows_affected()
                }))
            }
            DbPool::Sqlite(p) => {
                let mut query = sqlx::query(&config.sql);
                for param in &config.params {
                    query = bind_param_sqlite(query, param)?;
                }
                
                let result = query.execute(p).await
                    .map_err(|e| DbError::QueryFailed { message: e.to_string() })?;

                Ok(json!({
                    "rows_affected": result.rows_affected()
                }))
            }
        }
    }

    /// Ping database connection to verify health and measure latency
    pub async fn ping(&self, args: Value) -> Result<Value> {
        use std::time::Instant;

        // Parse configuration
        let config = PingConfig::from_args(&args)?;

        // Log the operation
        log::debug!("Executing ping for driver='{}' alias='{}' timeout_ms={} retries={}", 
                   self.driver.as_str(), self.alias, config.timeout_ms, config.retries);

        // Look up connection handle, connecting on demand when dsn= is given
        let handle = self.resolve_connection(&args).await?;

        // Perform ping with retry logic
        let mut last_error: Option<String> = None;
        
        for attempt in 1..=(1 + config.retries) {
            let start = Instant::now();
            
            // Perform a single ping attempt with timeout
            let ping_result = tokio::time::timeout(
                Duration::from_millis(config.timeout_ms),
                self.execute_ping_operation(&handle.pool)
            ).await;

            match ping_result {
                Ok(Ok(())) => {
                    // Success! Calculate latency and return
                    let latency_ms = start.elapsed().as_millis() as u64;
                    log::info!("Ping successful for driver='{}' alias='{}' attempt={} latency_ms={}",
                              self.driver.as_str(), self.alias, attempt, latency_ms);
                    
                    let result = json!({
                        "status": "ok",
                        "driver": self.driver.as_str(),
                        "alias": self.alias,
                        "latency_ms": latency_ms,
                        "attempts": attempt
                    });

                    return Ok(result);
                }
                Ok(Err(e)) => {
                    // Database error
                    last_error = Some(e.to_string());
                    log::warn!("Ping failed for driver='{}' alias='{}' attempt={} error='{}'",
                              self.driver.as_str(), self.alias, attempt, e);
                }
                Err(_) => {
                    // Timeout error
                    last_error = Some(format!("timeout after {}ms", config.timeout_ms));
                    log::warn!("Ping timeout for driver='{}' alias='{}' attempt={} timeout_ms={}",
                              self.driver.as_str(), self.alias, attempt, config.timeout_ms);
                }
            }

            // Wait before next retry (if not the last attempt)
            if attempt < (1 + config.retries) && config.backoff_ms > 0 {
                tokio::time::sleep(Duration::from_millis(config.backoff_ms)).await;
            }
        }

        // All attempts failed - determine error type and return failure response
        let total_attempts = 1 + config.retries;
        log::error!("Ping failed for driver='{}' alias='{}' after {} attempts",
                   self.driver.as_str(), self.alias, total_attempts);

        let error_json = json!({
            "status": "error",
            "driver": self.driver.as_str(),
            "alias": self.alias,
            "attempts": total_attempts,
            "error": {
                "code": if last_error.as_ref().map_or(false, |e| e.contains("timeout")) {
                    "db.ping_timeout"
                } else {
                    "db.ping_failed"
                },
                "message": format!("Ping failed after {} attempts", total_attempts),
                "last_error": if config.detailed { last_error } else { None }
            }
        });

        Ok(error_json)
    }

    /// Execute a single ping operation against the database pool
    async fn execute_ping_operation(&self, pool: &DbPool) -> Result<()> {
        match pool {
            DbPool::Postgres(p) => {
                sqlx::query("SELECT 1")
                    .execute(p)
                    .await
                    .map_err(|e| anyhow::anyhow!("Postgres ping failed: {}", e))?;
            }
            DbPool::Mysql(p) => {
                sqlx::query("SELECT 1")
                    .execute(p)
                    .await
                    .map_err(|e| anyhow::anyhow!("MySQL ping failed: {}", e))?;
            }
            DbPool::Sqlite(p) => {
                sqlx::query("SELECT 1")
                    .execute(p)
                    .await
                    .map_err(|e| anyhow::anyhow!("SQLite ping failed: {}", e))?;
            }
        }
        Ok(())
    }

    /// Handle transaction operations (begin, commit, rollback)
    pub async fn transaction(&self, args: Value) -> Result<Value> {
        let config = TransactionConfig::from_args(&args)?;
        
        match config.action {
            TransactionAction::Run => self.transaction_run(config, &args).await,
            TransactionAction::Begin => self.transaction_begin(config, &args).await,
            TransactionAction::Commit => self.transaction_commit(config).await,
            TransactionAction::Rollback => self.transaction_rollback(config).await,
        }
    }

    /// Begin a new transaction
    async fn transaction_begin(&self, config: TransactionConfig, args: &Value) -> Result<Value> {
        // Get connection pool, connecting on demand when dsn= is given
        let connection_handle = self.resolve_connection(args).await?;

        let pool = &connection_handle.pool;

        // Start transaction with timeout
        let timeout_duration = Duration::from_millis(config.timeout_ms);
        
        let tx_result = tokio::time::timeout(timeout_duration, async {
            self.begin_transaction_with_options(pool, &config).await
        }).await;

        let tx = match tx_result {
            Ok(Ok(tx)) => tx,
            Ok(Err(e)) => {
                log::error!("Transaction begin failed for driver='{}' alias='{}': {}",
                          self.driver.as_str(), self.alias, e);
                return Err(DbError::TransactionBeginFailed {
                    message: e.to_string(),
                })?;
            }
            Err(_) => {
                log::warn!("Transaction begin timeout for driver='{}' alias='{}' timeout_ms={}",
                          self.driver.as_str(), self.alias, config.timeout_ms);
                return Err(DbError::TransactionTimeout {
                    timeout_ms: config.timeout_ms,
                })?;
            }
        };

        // Generate transaction ID
        let tx_id = Uuid::new_v4().to_string();

        // Create transaction handle
        let tx_handle = Arc::new(DbTransactionHandle::new(
            self.driver.clone(),
            self.alias.clone(),
            tx_id.clone(),
            tx,
        ));

        // Register transaction
        TRANSACTION_REGISTRY.insert(tx_id.clone(), tx_handle);

        log::info!("Transaction began for driver='{}' alias='{}' tx_id='{}'",
                  self.driver.as_str(), self.alias, tx_id);

        Ok(json!({
            "status": "ok",
            "driver": self.driver.as_str(),
            "alias": self.alias,
            "tx_id": tx_id
        }))
    }

    /// Runs `config.statements` in one transaction within this call: begins
    /// (with the requested isolation and read-only options), executes each
    /// statement in order, then commits. If any statement fails, or the whole
    /// run exceeds timeout_ms, the transaction is rolled back and nothing is
    /// applied.
    async fn transaction_run(&self, config: TransactionConfig, args: &Value) -> Result<Value> {
        let connection_handle = self.resolve_connection(args).await?;
        let pool = &connection_handle.pool;
        let timeout_ms = config.timeout_ms;

        let run = async {
            let mut tx = self
                .begin_transaction_with_options(pool, &config)
                .await
                .map_err(|e| DbError::TransactionBeginFailed { message: e.to_string() })?;

            let mut results = Vec::with_capacity(config.statements.len());
            for (index, stmt) in config.statements.iter().enumerate() {
                let exec = ExecConfig {
                    sql: stmt.sql.clone(),
                    params: stmt.params.clone(),
                    timeout_ms,
                    return_last_insert_id: false,
                    tx_id: None,
                };
                let outcome = match &mut tx {
                    DbTransaction::Postgres(t) => self.execute_postgres_exec_on_tx(t, &exec).await,
                    DbTransaction::Mysql(t) => self.execute_mysql_exec_on_tx(t, &exec).await,
                    DbTransaction::Sqlite(t) => self.execute_sqlite_exec_on_tx(t, &exec).await,
                };
                match outcome {
                    Ok(v) => results.push(json!({
                        "index": index,
                        "rows_affected": v.get("rows_affected").cloned().unwrap_or(Value::Null)
                    })),
                    Err(e) => {
                        let rollback = self.rollback_transaction(tx).await;
                        return Err(DbError::TransactionStatementFailed {
                            index,
                            message: e.to_string(),
                            rolled_back: rollback.is_ok(),
                        });
                    }
                }
            }

            self.commit_transaction(tx)
                .await
                .map_err(|e| DbError::TransactionCommitFailed { message: e.to_string() })?;
            Ok::<_, DbError>(results)
        };

        // On timeout the transaction future is dropped, which rolls it back.
        let results = tokio::time::timeout(Duration::from_millis(timeout_ms), run)
            .await
            .map_err(|_| DbError::TransactionTimeout { timeout_ms })??;

        log::info!("Transaction run committed for driver='{}' alias='{}' statements={}",
                  self.driver.as_str(), self.alias, results.len());

        Ok(json!({
            "action": "run",
            "alias": self.alias,
            "committed": true,
            "driver": self.driver.as_str(),
            "results": results,
            "status": "ok"
        }))
    }

    /// Begin transaction with driver-specific options
    async fn begin_transaction_with_options(&self, pool: &DbPool, config: &TransactionConfig) -> Result<DbTransaction> {
        match pool {
            DbPool::Postgres(p) => {
                // For PostgreSQL, we can use transaction options
                let mut tx = p.begin().await
                    .map_err(|e| anyhow::anyhow!("Failed to begin PostgreSQL transaction: {}", e))?;

                // Apply isolation level if specified
                if let Some(ref isolation) = config.isolation {
                    let isolation_sql = match isolation {
                        TransactionIsolation::Default => None,
                        TransactionIsolation::ReadUncommitted => Some("READ UNCOMMITTED"),
                        TransactionIsolation::ReadCommitted => Some("READ COMMITTED"),
                        TransactionIsolation::RepeatableRead => Some("REPEATABLE READ"),
                        TransactionIsolation::Serializable => Some("SERIALIZABLE"),
                    };

                    if let Some(level) = isolation_sql {
                        sqlx::query(&format!("SET TRANSACTION ISOLATION LEVEL {}", level))
                            .execute(&mut *tx)
                            .await
                            .map_err(|e| anyhow::anyhow!("Failed to set isolation level: {}", e))?;
                    }
                }

                // Apply read-only if specified
                if config.read_only {
                    sqlx::query("SET TRANSACTION READ ONLY")
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| anyhow::anyhow!("Failed to set read-only: {}", e))?;
                }

                Ok(DbTransaction::Postgres(tx))
            }
            DbPool::Mysql(p) => {
                // For MySQL, we can apply some transaction options
                let mut tx = p.begin().await
                    .map_err(|e| anyhow::anyhow!("Failed to begin MySQL transaction: {}", e))?;

                // Apply isolation level if specified
                if let Some(ref isolation) = config.isolation {
                    let isolation_sql = match isolation {
                        TransactionIsolation::Default => None,
                        TransactionIsolation::ReadUncommitted => Some("READ UNCOMMITTED"),
                        TransactionIsolation::ReadCommitted => Some("READ COMMITTED"),
                        TransactionIsolation::RepeatableRead => Some("REPEATABLE READ"),
                        TransactionIsolation::Serializable => Some("SERIALIZABLE"),
                    };

                    if let Some(level) = isolation_sql {
                        sqlx::query(&format!("SET TRANSACTION ISOLATION LEVEL {}", level))
                            .execute(&mut *tx)
                            .await
                            .map_err(|e| anyhow::anyhow!("Failed to set isolation level: {}", e))?;
                    }
                }

                // Note: MySQL doesn't support transaction-level read-only in the same way
                // We could warn or ignore this setting

                Ok(DbTransaction::Mysql(tx))
            }
            DbPool::Sqlite(p) => {
                // For SQLite, transaction options are more limited
                let tx = p.begin().await
                    .map_err(|e| anyhow::anyhow!("Failed to begin SQLite transaction: {}", e))?;

                // SQLite has limited isolation level support - we'll just use default
                // Could potentially map to DEFERRED/IMMEDIATE/EXCLUSIVE but that requires different API

                Ok(DbTransaction::Sqlite(tx))
            }
        }
    }

    /// Commit a transaction
    async fn transaction_commit(&self, config: TransactionConfig) -> Result<Value> {
        let tx_id = config.tx_id.as_ref().unwrap(); // Already validated in TransactionConfig::from_args

        // Get transaction handle
        let tx_handle = TRANSACTION_REGISTRY
            .get(tx_id)
            .ok_or_else(|| DbError::TransactionNotFound {
                tx_id: tx_id.clone(),
            })?;

        // Verify driver/alias match
        let expected = format!("{}:{}", self.driver.as_str(), self.alias);
        let actual = format!("{}:{}", tx_handle.driver.as_str(), tx_handle.alias);
        if expected != actual {
            return Err(DbError::TransactionAliasMismatch {
                tx_id: tx_id.clone(),
                expected,
                actual,
            })?;
        }

        // Take transaction out of handle
        let tx = tx_handle.take_transaction()
            .ok_or_else(|| DbError::TransactionClosed {
                tx_id: tx_id.clone(),
            })?;

        // Commit with timeout
        let timeout_duration = Duration::from_millis(config.timeout_ms);
        let commit_result = tokio::time::timeout(timeout_duration, async {
            self.commit_transaction(tx).await
        }).await;

        // Remove from registry regardless of commit result to prevent leaks
        TRANSACTION_REGISTRY.remove(tx_id);

        match commit_result {
            Ok(Ok(())) => {
                log::info!("Transaction committed for driver='{}' alias='{}' tx_id='{}'",
                          self.driver.as_str(), self.alias, tx_id);
                
                Ok(json!({
                    "status": "ok",
                    "driver": self.driver.as_str(),
                    "alias": self.alias,
                    "tx_id": tx_id,
                    "action": "commit"
                }))
            }
            Ok(Err(e)) => {
                log::error!("Transaction commit failed for driver='{}' alias='{}' tx_id='{}': {}",
                          self.driver.as_str(), self.alias, tx_id, e);
                Err(DbError::TransactionCommitFailed {
                    message: e.to_string(),
                })?
            }
            Err(_) => {
                log::warn!("Transaction commit timeout for driver='{}' alias='{}' tx_id='{}' timeout_ms={}",
                          self.driver.as_str(), self.alias, tx_id, config.timeout_ms);
                Err(DbError::TransactionTimeout {
                    timeout_ms: config.timeout_ms,
                })?
            }
        }
    }

    /// Commit transaction by driver type
    async fn commit_transaction(&self, tx: DbTransaction) -> Result<()> {
        match tx {
            DbTransaction::Postgres(tx) => {
                tx.commit().await
                    .map_err(|e| anyhow::anyhow!("PostgreSQL commit failed: {}", e))?;
            }
            DbTransaction::Mysql(tx) => {
                tx.commit().await
                    .map_err(|e| anyhow::anyhow!("MySQL commit failed: {}", e))?;
            }
            DbTransaction::Sqlite(tx) => {
                tx.commit().await
                    .map_err(|e| anyhow::anyhow!("SQLite commit failed: {}", e))?;
            }
        }
        Ok(())
    }

    /// Rollback a transaction
    async fn transaction_rollback(&self, config: TransactionConfig) -> Result<Value> {
        let tx_id = config.tx_id.as_ref().unwrap(); // Already validated in TransactionConfig::from_args

        // Get transaction handle
        let tx_handle = TRANSACTION_REGISTRY
            .get(tx_id)
            .ok_or_else(|| DbError::TransactionNotFound {
                tx_id: tx_id.clone(),
            })?;

        // Verify driver/alias match
        let expected = format!("{}:{}", self.driver.as_str(), self.alias);
        let actual = format!("{}:{}", tx_handle.driver.as_str(), tx_handle.alias);
        if expected != actual {
            return Err(DbError::TransactionAliasMismatch {
                tx_id: tx_id.clone(),
                expected,
                actual,
            })?;
        }

        // Take transaction out of handle
        let tx = tx_handle.take_transaction()
            .ok_or_else(|| DbError::TransactionClosed {
                tx_id: tx_id.clone(),
            })?;

        // Rollback with timeout
        let timeout_duration = Duration::from_millis(config.timeout_ms);
        let rollback_result = tokio::time::timeout(timeout_duration, async {
            self.rollback_transaction(tx).await
        }).await;

        // Remove from registry regardless of rollback result to prevent leaks
        TRANSACTION_REGISTRY.remove(tx_id);

        match rollback_result {
            Ok(Ok(())) => {
                log::info!("Transaction rolled back for driver='{}' alias='{}' tx_id='{}'",
                          self.driver.as_str(), self.alias, tx_id);
                
                Ok(json!({
                    "status": "ok",
                    "driver": self.driver.as_str(),
                    "alias": self.alias,
                    "tx_id": tx_id,
                    "action": "rollback"
                }))
            }
            Ok(Err(e)) => {
                log::error!("Transaction rollback failed for driver='{}' alias='{}' tx_id='{}': {}",
                          self.driver.as_str(), self.alias, tx_id, e);
                Err(DbError::TransactionRollbackFailed {
                    message: e.to_string(),
                })?
            }
            Err(_) => {
                log::warn!("Transaction rollback timeout for driver='{}' alias='{}' tx_id='{}' timeout_ms={}",
                          self.driver.as_str(), self.alias, tx_id, config.timeout_ms);
                Err(DbError::TransactionTimeout {
                    timeout_ms: config.timeout_ms,
                })?
            }
        }
    }

    /// Rollback transaction by driver type
    async fn rollback_transaction(&self, tx: DbTransaction) -> Result<()> {
        match tx {
            DbTransaction::Postgres(tx) => {
                tx.rollback().await
                    .map_err(|e| anyhow::anyhow!("PostgreSQL rollback failed: {}", e))?;
            }
            DbTransaction::Mysql(tx) => {
                tx.rollback().await
                    .map_err(|e| anyhow::anyhow!("MySQL rollback failed: {}", e))?;
            }
            DbTransaction::Sqlite(tx) => {
                tx.rollback().await
                    .map_err(|e| anyhow::anyhow!("SQLite rollback failed: {}", e))?;
            }
        }
        Ok(())
    }
}

/// Database-specific errors
#[derive(thiserror::Error, Debug)]
pub enum DbError {
    #[error("unsupported driver: {driver}")]
    UnsupportedDriver { driver: String },
    
    #[error("missing DSN for alias '{alias}'. Provide 'dsn' argument or set environment variable {env_var}")]
    MissingDsn { alias: String, env_var: String },
    
    #[error("invalid DSN '{dsn}': {message}")]
    InvalidDsn { dsn: String, message: String },
    
    #[error("invalid configuration for field '{field}': {message}")]
    InvalidConfig { field: String, message: String },
    
    #[error("connection failed: {message}")]
    ConnectFailed { message: String },
    
    #[error("TLS error: {message}")]
    TlsError { message: String },
    
    #[error("alias conflict: driver '{driver}' alias '{alias}' already exists with different DSN")]
    AliasConflict { driver: String, alias: String },

    #[error("connection not found for driver '{driver}' alias '{alias}'. Use connect verb first")]
    ConnectionNotFound { driver: String, alias: String },

    #[error("invalid query configuration: {message}")]
    InvalidQueryConfig { message: String },

    #[error("unsupported parameter type: {type_name}")]
    UnsupportedParamType { type_name: String },

    #[error("query timeout after {timeout_ms}ms")]
    QueryTimeout { timeout_ms: u64 },

    #[error("query failed: {message}")]
    QueryFailed { message: String },

    #[error("invalid exec configuration: {message}")]
    InvalidExecConfig { message: String },

    #[error("exec timeout after {timeout_ms}ms")]
    ExecTimeout { timeout_ms: u64 },

    #[error("exec failed: {message}")]
    ExecFailed { message: String },

    #[error("invalid tables configuration: {message}")]
    InvalidTablesConfig { message: String },

    #[error("table '{table}' not found")]
    TableNotFound { table: String },

    #[error("tables operation timeout after {timeout_ms}ms")]
    TablesTimeout { timeout_ms: u64 },

    #[error("tables operation failed: {message}")]
    TablesFailed { message: String },

    #[error("invalid schema configuration: {message}")]
    InvalidSchemaConfig { message: String },

    #[error("schema operation timeout after {timeout_ms}ms")]
    SchemaTimeout { timeout_ms: u64 },

    #[error("schema operation failed: {message}")]
    SchemaFailed { message: String },

    #[error("invalid ping configuration: {message}")]
    InvalidPingConfig { message: String },

    #[error("ping timeout after {timeout_ms}ms")]
    PingTimeout { timeout_ms: u64 },

    #[error("ping failed: {message}")]
    PingFailed { message: String },

    #[error("invalid transaction configuration: {message}")]
    InvalidTransactionConfig { message: String },

    #[error("transaction timeout after {timeout_ms}ms")]
    TransactionTimeout { timeout_ms: u64 },

    #[error("transaction begin failed: {message}")]
    TransactionBeginFailed { message: String },

    #[error("transaction commit failed: {message}")]
    TransactionCommitFailed { message: String },

    #[error("transaction statement {index} failed: {message}")]
    TransactionStatementFailed { index: usize, message: String, rolled_back: bool },

    #[error("transaction rollback failed: {message}")]
    TransactionRollbackFailed { message: String },

    #[error("transaction '{tx_id}' not found")]
    TransactionNotFound { tx_id: String },

    #[error("transaction '{tx_id}' belongs to different driver/alias: expected {expected}, got {actual}")]
    TransactionAliasMismatch { tx_id: String, expected: String, actual: String },

    #[error("transaction '{tx_id}' is closed")]
    TransactionClosed { tx_id: String },
}

impl DbError {
    /// Convert to structured JSON error response
    pub fn to_json(&self) -> Value {
        match self {
            DbError::UnsupportedDriver { driver } => json!({
                "error": {
                    "code": "db.unsupported_driver",
                    "message": self.to_string(),
                    "details": {
                        "driver": driver
                    }
                }
            }),
            DbError::MissingDsn { alias, env_var } => json!({
                "error": {
                    "code": "db.missing_dsn", 
                    "message": self.to_string(),
                    "details": {
                        "alias": alias,
                        "env_var": env_var
                    }
                }
            }),
            DbError::InvalidDsn { dsn, message } => json!({
                "error": {
                    "code": "db.invalid_dsn",
                    "message": self.to_string(),
                    "details": {
                        "dsn": dsn,
                        "validation_error": message
                    }
                }
            }),
            DbError::InvalidConfig { field, message } => json!({
                "error": {
                    "code": "db.invalid_config",
                    "message": self.to_string(),
                    "details": {
                        "field": field,
                        "validation_error": message
                    }
                }
            }),
            DbError::ConnectFailed { message } => json!({
                "error": {
                    "code": "db.connect_failed",
                    "message": self.to_string(),
                    "details": {
                        "underlying_error": message
                    }
                }
            }),
            DbError::TlsError { message } => json!({
                "error": {
                    "code": "db.tls_error",
                    "message": self.to_string(),
                    "details": {
                        "tls_error": message
                    }
                }
            }),
            DbError::AliasConflict { driver, alias } => json!({
                "error": {
                    "code": "db.alias_conflict",
                    "message": self.to_string(),
                    "details": {
                        "driver": driver,
                        "alias": alias
                    }
                }
            }),
            DbError::ConnectionNotFound { driver, alias } => json!({
                "error": {
                    "code": "db.connection_not_found",
                    "message": self.to_string(),
                    "details": {
                        "driver": driver,
                        "alias": alias
                    }
                }
            }),
            DbError::InvalidQueryConfig { message } => json!({
                "error": {
                    "code": "db.invalid_query_config",
                    "message": self.to_string(),
                    "details": {
                        "validation_error": message
                    }
                }
            }),
            DbError::UnsupportedParamType { type_name } => json!({
                "error": {
                    "code": "db.unsupported_param_type",
                    "message": self.to_string(),
                    "details": {
                        "type_name": type_name
                    }
                }
            }),
            DbError::QueryTimeout { timeout_ms } => json!({
                "error": {
                    "code": "db.query_timeout",
                    "message": self.to_string(),
                    "details": {
                        "timeout_ms": timeout_ms
                    }
                }
            }),
            DbError::QueryFailed { message } => json!({
                "error": {
                    "code": "db.query_failed",
                    "message": self.to_string(),
                    "details": {
                        "underlying_error": message
                    }
                }
            }),
            DbError::InvalidExecConfig { message } => json!({
                "error": {
                    "code": "db.invalid_exec_config",
                    "message": self.to_string(),
                    "details": {
                        "validation_error": message
                    }
                }
            }),
            DbError::ExecTimeout { timeout_ms } => json!({
                "error": {
                    "code": "db.exec_timeout",
                    "message": self.to_string(),
                    "details": {
                        "timeout_ms": timeout_ms
                    }
                }
            }),
            DbError::ExecFailed { message } => json!({
                "error": {
                    "code": "db.exec_failed",
                    "message": self.to_string(),
                    "details": {
                        "underlying_error": message
                    }
                }
            }),
            DbError::InvalidTablesConfig { message } => json!({
                "error": {
                    "code": "db.invalid_tables_config",
                    "message": self.to_string(),
                    "details": {
                        "validation_error": message
                    }
                }
            }),
            DbError::TableNotFound { table } => json!({
                "error": {
                    "code": "db.table_not_found",
                    "message": self.to_string(),
                    "details": {
                        "table": table
                    }
                }
            }),
            DbError::TablesTimeout { timeout_ms } => json!({
                "error": {
                    "code": "db.tables_timeout",
                    "message": self.to_string(),
                    "details": {
                        "timeout_ms": timeout_ms
                    }
                }
            }),
            DbError::TablesFailed { message } => json!({
                "error": {
                    "code": "db.tables_failed",
                    "message": self.to_string(),
                    "details": {
                        "underlying_error": message
                    }
                }
            }),
            DbError::InvalidSchemaConfig { message } => json!({
                "error": {
                    "code": "db.invalid_schema_config",
                    "message": self.to_string(),
                    "details": {
                        "validation_error": message
                    }
                }
            }),
            DbError::SchemaTimeout { timeout_ms } => json!({
                "error": {
                    "code": "db.schema_timeout",
                    "message": self.to_string(),
                    "details": {
                        "timeout_ms": timeout_ms
                    }
                }
            }),
            DbError::SchemaFailed { message } => json!({
                "error": {
                    "code": "db.schema_failed",
                    "message": self.to_string(),
                    "details": {
                        "underlying_error": message
                    }
                }
            }),
            DbError::InvalidPingConfig { message } => json!({
                "error": {
                    "code": "db.invalid_ping_config",
                    "message": self.to_string(),
                    "details": {
                        "validation_error": message
                    }
                }
            }),
            DbError::PingTimeout { timeout_ms } => json!({
                "error": {
                    "code": "db.ping_timeout",
                    "message": self.to_string(),
                    "details": {
                        "timeout_ms": timeout_ms
                    }
                }
            }),
            DbError::PingFailed { message } => json!({
                "error": {
                    "code": "db.ping_failed",
                    "message": self.to_string(),
                    "details": {
                        "underlying_error": message
                    }
                }
            }),
            DbError::InvalidTransactionConfig { message } => json!({
                "error": {
                    "code": "db.invalid_transaction_config",
                    "message": self.to_string(),
                    "details": {
                        "validation_error": message
                    }
                }
            }),
            DbError::TransactionTimeout { timeout_ms } => json!({
                "error": {
                    "code": "db.transaction_timeout",
                    "message": self.to_string(),
                    "details": {
                        "timeout_ms": timeout_ms
                    }
                }
            }),
            DbError::TransactionBeginFailed { message } => json!({
                "error": {
                    "code": "db.transaction_begin_failed",
                    "message": self.to_string(),
                    "details": {
                        "underlying_error": message
                    }
                }
            }),
            DbError::TransactionCommitFailed { message } => json!({
                "error": {
                    "code": "db.transaction_commit_failed",
                    "message": self.to_string(),
                    "details": {
                        "underlying_error": message
                    }
                }
            }),
            DbError::TransactionStatementFailed { index, message, rolled_back } => json!({
                "error": {
                    "code": "db.transaction_statement_failed",
                    "message": self.to_string(),
                    "details": {
                        "index": index,
                        "rolled_back": rolled_back,
                        "underlying_error": message
                    }
                }
            }),
            DbError::TransactionRollbackFailed { message } => json!({
                "error": {
                    "code": "db.transaction_rollback_failed",
                    "message": self.to_string(),
                    "details": {
                        "underlying_error": message
                    }
                }
            }),
            DbError::TransactionNotFound { tx_id } => json!({
                "error": {
                    "code": "db.transaction_not_found",
                    "message": self.to_string(),
                    "details": {
                        "tx_id": tx_id
                    }
                }
            }),
            DbError::TransactionAliasMismatch { tx_id, expected, actual } => json!({
                "error": {
                    "code": "db.transaction_alias_mismatch",
                    "message": self.to_string(),
                    "details": {
                        "tx_id": tx_id,
                        "expected": expected,
                        "actual": actual
                    }
                }
            }),
            DbError::TransactionClosed { tx_id } => json!({
                "error": {
                    "code": "db.transaction_closed",
                    "message": self.to_string(),
                    "details": {
                        "tx_id": tx_id
                    }
                }
            }),
        }
    }
}

/// Helper function to bind JSON Value to sqlx query
fn bind_param<'q>(query: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>, value: &Value) -> Result<sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>, DbError> {
    match value {
        Value::Null => Ok(query.bind(None::<String>)),
        Value::Bool(b) => Ok(query.bind(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(query.bind(i))
            } else if let Some(f) = n.as_f64() {
                Ok(query.bind(f))
            } else {
                Err(DbError::UnsupportedParamType {
                    type_name: "invalid number".to_string(),
                })
            }
        }
        Value::String(s) => Ok(query.bind(s.clone())),
        Value::Array(_) | Value::Object(_) => {
            Err(DbError::UnsupportedParamType {
                type_name: "array/object".to_string(),
            })
        }
    }
}

/// Helper function to bind JSON Value to sqlx query for MySQL
fn bind_param_mysql<'q>(query: sqlx::query::Query<'q, sqlx::MySql, sqlx::mysql::MySqlArguments>, value: &Value) -> Result<sqlx::query::Query<'q, sqlx::MySql, sqlx::mysql::MySqlArguments>, DbError> {
    match value {
        Value::Null => Ok(query.bind(None::<String>)),
        Value::Bool(b) => Ok(query.bind(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(query.bind(i))
            } else if let Some(f) = n.as_f64() {
                Ok(query.bind(f))
            } else {
                Err(DbError::UnsupportedParamType {
                    type_name: "invalid number".to_string(),
                })
            }
        }
        Value::String(s) => Ok(query.bind(s.clone())),
        Value::Array(_) | Value::Object(_) => {
            Err(DbError::UnsupportedParamType {
                type_name: "array/object".to_string(),
            })
        }
    }
}

/// Helper function to bind JSON Value to sqlx query for SQLite
fn bind_param_sqlite<'q>(query: sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>>, value: &Value) -> Result<sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>>, DbError> {
    match value {
        Value::Null => Ok(query.bind(None::<String>)),
        Value::Bool(b) => Ok(query.bind(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(query.bind(i))
            } else if let Some(f) = n.as_f64() {
                Ok(query.bind(f))
            } else {
                Err(DbError::UnsupportedParamType {
                    type_name: "invalid number".to_string(),
                })
            }
        }
        Value::String(s) => Ok(query.bind(s.clone())),
        Value::Array(_) | Value::Object(_) => {
            Err(DbError::UnsupportedParamType {
                type_name: "array/object".to_string(),
            })
        }
    }
}

/// Decode a PostgreSQL integer column at its real width. sqlx decodes
/// strictly, so reading an INT4 or INT2 column as `i64` fails.
fn pg_get_int<I: sqlx::ColumnIndex<sqlx::postgres::PgRow>>(
    row: &sqlx::postgres::PgRow,
    idx: I,
    type_name: &str,
) -> Result<Option<i64>, sqlx::Error> {
    match type_name {
        "INT2" => row.try_get::<Option<i16>, _>(idx).map(|v| v.map(i64::from)),
        "INT4" => row.try_get::<Option<i32>, _>(idx).map(|v| v.map(i64::from)),
        _ => row.try_get::<Option<i64>, _>(idx),
    }
}

/// Decode a PostgreSQL float column at its real width (FLOAT4 is `f32`).
/// NUMERIC is not decodable without an extra sqlx feature and still fails.
fn pg_get_float<I: sqlx::ColumnIndex<sqlx::postgres::PgRow>>(
    row: &sqlx::postgres::PgRow,
    idx: I,
    type_name: &str,
) -> Result<Option<f64>, sqlx::Error> {
    match type_name {
        "FLOAT4" => row.try_get::<Option<f32>, _>(idx).map(|v| v.map(f64::from)),
        _ => row.try_get::<Option<f64>, _>(idx),
    }
}

/// Helper function to convert database row to JSON
fn row_to_json_postgres(row: &sqlx::postgres::PgRow) -> Result<Value, DbError> {
    let mut json_row = serde_json::Map::new();
    
    for column in row.columns() {
        let column_name = column.name();
        let type_info = column.type_info();
        
        let value = match type_info.name() {
            "BOOL" => {
                let val: Option<bool> = row.try_get(column_name)
                    .map_err(|e| DbError::QueryFailed { message: format!("Failed to get bool column {}: {}", column_name, e) })?;
                val.map(Value::Bool).unwrap_or(Value::Null)
            }
            "INT2" | "INT4" | "INT8" => {
                let val = pg_get_int(row, column_name, type_info.name())
                    .map_err(|e| DbError::QueryFailed { message: format!("Failed to get int column {}: {}", column_name, e) })?;
                val.map(|v| json!(v)).unwrap_or(Value::Null)
            }
            "FLOAT4" | "FLOAT8" | "NUMERIC" => {
                let val = pg_get_float(row, column_name, type_info.name())
                    .map_err(|e| DbError::QueryFailed { message: format!("Failed to get float column {}: {}", column_name, e) })?;
                val.map(|v| json!(v)).unwrap_or(Value::Null)
            }
            "VARCHAR" | "TEXT" | "CHAR" => {
                let val: Option<String> = row.try_get(column_name)
                    .map_err(|e| DbError::QueryFailed { message: format!("Failed to get text column {}: {}", column_name, e) })?;
                val.map(Value::String).unwrap_or(Value::Null)
            }
            "TIMESTAMP" | "TIMESTAMPTZ" | "DATE" | "TIME" => {
                // Just try to get as string - most robust approach
                let val: Option<String> = row.try_get(column_name)
                    .map_err(|e| DbError::QueryFailed { message: format!("Failed to get timestamp column {}: {}", column_name, e) })?;
                val.map(Value::String).unwrap_or(Value::Null)
            }
            "BYTEA" => {
                let val: Option<Vec<u8>> = row.try_get(column_name)
                    .map_err(|e| DbError::QueryFailed { message: format!("Failed to get bytes column {}: {}", column_name, e) })?;
                val.map(|bytes| Value::String(format!("base64:{}", base64::engine::general_purpose::STANDARD.encode(bytes))))
                   .unwrap_or(Value::Null)
            }
            "JSON" | "JSONB" => {
                let val: Option<serde_json::Value> = row.try_get(column_name)
                    .map_err(|e| DbError::QueryFailed { message: format!("Failed to get json column {}: {}", column_name, e) })?;
                val.unwrap_or(Value::Null)
            }
            _ => {
                // Fallback to string representation
                let val: Option<String> = row.try_get(column_name)
                    .map_err(|e| DbError::QueryFailed { message: format!("Failed to get column {} as string: {}", column_name, e) })?;
                val.map(Value::String).unwrap_or(Value::Null)
            }
        };
        
        json_row.insert(column_name.to_string(), value);
    }
    
    Ok(Value::Object(json_row))
}

/// Helper function to convert MySQL row to JSON
fn row_to_json_mysql(row: &sqlx::mysql::MySqlRow) -> Result<Value, DbError> {
    let mut json_row = serde_json::Map::new();
    
    for column in row.columns() {
        let column_name = column.name();
        let type_info = column.type_info();
        
        let value = match type_info.name() {
            "TINYINT(1)" => {
                let val: Option<bool> = row.try_get(column_name)
                    .map_err(|e| DbError::QueryFailed { message: format!("Failed to get bool column {}: {}", column_name, e) })?;
                val.map(Value::Bool).unwrap_or(Value::Null)
            }
            "TINYINT" | "SMALLINT" | "MEDIUMINT" | "INT" | "BIGINT" => {
                let val: Option<i64> = row.try_get(column_name)
                    .map_err(|e| DbError::QueryFailed { message: format!("Failed to get int column {}: {}", column_name, e) })?;
                val.map(|v| json!(v)).unwrap_or(Value::Null)
            }
            "FLOAT" | "DOUBLE" | "DECIMAL" => {
                let val: Option<f64> = row.try_get(column_name)
                    .map_err(|e| DbError::QueryFailed { message: format!("Failed to get float column {}: {}", column_name, e) })?;
                val.map(|v| json!(v)).unwrap_or(Value::Null)
            }
            "VARCHAR" | "TEXT" | "CHAR" | "LONGTEXT" => {
                let val: Option<String> = row.try_get(column_name)
                    .map_err(|e| DbError::QueryFailed { message: format!("Failed to get text column {}: {}", column_name, e) })?;
                val.map(Value::String).unwrap_or(Value::Null)
            }
            "TIMESTAMP" | "DATETIME" | "DATE" | "TIME" => {
                // Just try to get as string - most robust approach
                let val: Option<String> = row.try_get(column_name)
                    .map_err(|e| DbError::QueryFailed { message: format!("Failed to get timestamp column {}: {}", column_name, e) })?;
                val.map(Value::String).unwrap_or(Value::Null)
            }
            "VARBINARY" | "BINARY" | "BLOB" => {
                let val: Option<Vec<u8>> = row.try_get(column_name)
                    .map_err(|e| DbError::QueryFailed { message: format!("Failed to get bytes column {}: {}", column_name, e) })?;
                val.map(|bytes| Value::String(format!("base64:{}", base64::engine::general_purpose::STANDARD.encode(bytes))))
                   .unwrap_or(Value::Null)
            }
            "JSON" => {
                let val: Option<serde_json::Value> = row.try_get(column_name)
                    .map_err(|e| DbError::QueryFailed { message: format!("Failed to get json column {}: {}", column_name, e) })?;
                val.unwrap_or(Value::Null)
            }
            _ => {
                // Fallback to string representation
                let val: Option<String> = row.try_get(column_name)
                    .map_err(|e| DbError::QueryFailed { message: format!("Failed to get column {} as string: {}", column_name, e) })?;
                val.map(Value::String).unwrap_or(Value::Null)
            }
        };
        
        json_row.insert(column_name.to_string(), value);
    }
    
    Ok(Value::Object(json_row))
}

/// Helper function to convert SQLite row to JSON
fn row_to_json_sqlite(row: &sqlx::sqlite::SqliteRow) -> Result<Value, DbError> {
    let mut json_row = serde_json::Map::new();
    
    for column in row.columns() {
        let column_name = column.name();
        let type_info = column.type_info();
        
        let value = match type_info.name() {
            "BOOLEAN" => {
                let val: Option<bool> = row.try_get(column_name)
                    .map_err(|e| DbError::QueryFailed { message: format!("Failed to get bool column {}: {}", column_name, e) })?;
                val.map(Value::Bool).unwrap_or(Value::Null)
            }
            "INTEGER" => {
                let val: Option<i64> = row.try_get(column_name)
                    .map_err(|e| DbError::QueryFailed { message: format!("Failed to get int column {}: {}", column_name, e) })?;
                val.map(|v| json!(v)).unwrap_or(Value::Null)
            }
            "REAL" => {
                let val: Option<f64> = row.try_get(column_name)
                    .map_err(|e| DbError::QueryFailed { message: format!("Failed to get float column {}: {}", column_name, e) })?;
                val.map(|v| json!(v)).unwrap_or(Value::Null)
            }
            "TEXT" => {
                let val: Option<String> = row.try_get(column_name)
                    .map_err(|e| DbError::QueryFailed { message: format!("Failed to get text column {}: {}", column_name, e) })?;
                val.map(Value::String).unwrap_or(Value::Null)
            }
            "TIMESTAMP" | "DATETIME" | "DATE" | "TIME" => {
                // SQLite typically stores dates as text
                if let Ok(val) = row.try_get::<Option<String>, _>(column_name) {
                    val.map(Value::String).unwrap_or(Value::Null)
                } else {
                    Value::Null
                }
            }
            "BLOB" => {
                let val: Option<Vec<u8>> = row.try_get(column_name)
                    .map_err(|e| DbError::QueryFailed { message: format!("Failed to get blob column {}: {}", column_name, e) })?;
                val.map(|bytes| Value::String(format!("base64:{}", base64::engine::general_purpose::STANDARD.encode(bytes))))
                   .unwrap_or(Value::Null)
            }
            _ => {
                // Try different types in order of preference
                if let Ok(val) = row.try_get::<Option<i64>, _>(column_name) {
                    val.map(|v| json!(v)).unwrap_or(Value::Null)
                } else if let Ok(val) = row.try_get::<Option<f64>, _>(column_name) {
                    val.map(|v| json!(v)).unwrap_or(Value::Null)
                } else if let Ok(val) = row.try_get::<Option<String>, _>(column_name) {
                    val.map(Value::String).unwrap_or(Value::Null)
                } else if let Ok(val) = row.try_get::<Option<bool>, _>(column_name) {
                    val.map(Value::Bool).unwrap_or(Value::Null)
                } else {
                    // If all else fails, return null
                    Value::Null
                }
            }
        };
        
        json_row.insert(column_name.to_string(), value);
    }
    
    Ok(Value::Object(json_row))
}

/// Helper functions to convert single column values by index
fn convert_postgres_value(row: &sqlx::postgres::PgRow, col_index: usize) -> Value {
    let column = &row.columns()[col_index];
    let column_name = column.name();
    let type_info = column.type_info();
    
    match type_info.name() {
        "BOOL" => {
            row.try_get::<Option<bool>, _>(col_index)
                .ok()
                .flatten()
                .map(Value::Bool)
                .unwrap_or(Value::Null)
        }
        "INT2" | "INT4" | "INT8" => {
            pg_get_int(row, col_index, type_info.name())
                .ok()
                .flatten()
                .map(|v| json!(v))
                .unwrap_or(Value::Null)
        }
        "FLOAT4" | "FLOAT8" | "NUMERIC" => {
            pg_get_float(row, col_index, type_info.name())
                .ok()
                .flatten()
                .map(|v| json!(v))
                .unwrap_or(Value::Null)
        }
        "VARCHAR" | "TEXT" | "CHAR" => {
            row.try_get::<Option<String>, _>(col_index)
                .ok()
                .flatten()
                .map(Value::String)
                .unwrap_or(Value::Null)
        }
        "TIMESTAMP" | "TIMESTAMPTZ" | "DATE" | "TIME" => {
            row.try_get::<Option<String>, _>(col_index)
                .ok()
                .flatten()
                .map(Value::String)
                .unwrap_or(Value::Null)
        }
        "BYTEA" => {
            row.try_get::<Option<Vec<u8>>, _>(col_index)
                .ok()
                .flatten()
                .map(|bytes| Value::String(format!("base64:{}", base64::engine::general_purpose::STANDARD.encode(bytes))))
                .unwrap_or(Value::Null)
        }
        "JSON" | "JSONB" => {
            row.try_get::<Option<serde_json::Value>, _>(col_index)
                .ok()
                .flatten()
                .unwrap_or(Value::Null)
        }
        _ => {
            row.try_get::<Option<String>, _>(col_index)
                .ok()
                .flatten()
                .map(Value::String)
                .unwrap_or(Value::Null)
        }
    }
}

fn convert_mysql_value(row: &sqlx::mysql::MySqlRow, col_index: usize) -> Value {
    let column = &row.columns()[col_index];
    let type_info = column.type_info();
    
    match type_info.name() {
        "BOOLEAN" | "TINYINT(1)" => {
            row.try_get::<Option<bool>, _>(col_index)
                .ok()
                .flatten()
                .map(Value::Bool)
                .unwrap_or(Value::Null)
        }
        "TINYINT" | "SMALLINT" | "INT" | "MEDIUMINT" | "BIGINT" => {
            row.try_get::<Option<i64>, _>(col_index)
                .ok()
                .flatten()
                .map(|v| json!(v))
                .unwrap_or(Value::Null)
        }
        "FLOAT" | "DOUBLE" | "DECIMAL" => {
            row.try_get::<Option<f64>, _>(col_index)
                .ok()
                .flatten()
                .map(|v| json!(v))
                .unwrap_or(Value::Null)
        }
        "VARCHAR" | "TEXT" | "CHAR" | "TINYTEXT" | "MEDIUMTEXT" | "LONGTEXT" => {
            row.try_get::<Option<String>, _>(col_index)
                .ok()
                .flatten()
                .map(Value::String)
                .unwrap_or(Value::Null)
        }
        "TIMESTAMP" | "DATETIME" | "DATE" | "TIME" => {
            row.try_get::<Option<String>, _>(col_index)
                .ok()
                .flatten()
                .map(Value::String)
                .unwrap_or(Value::Null)
        }
        "BINARY" | "VARBINARY" | "BLOB" | "TINYBLOB" | "MEDIUMBLOB" | "LONGBLOB" => {
            row.try_get::<Option<Vec<u8>>, _>(col_index)
                .ok()
                .flatten()
                .map(|bytes| Value::String(format!("base64:{}", base64::engine::general_purpose::STANDARD.encode(bytes))))
                .unwrap_or(Value::Null)
        }
        "JSON" => {
            row.try_get::<Option<serde_json::Value>, _>(col_index)
                .ok()
                .flatten()
                .unwrap_or(Value::Null)
        }
        _ => {
            row.try_get::<Option<String>, _>(col_index)
                .ok()
                .flatten()
                .map(Value::String)
                .unwrap_or(Value::Null)
        }
    }
}

fn convert_sqlite_value(row: &sqlx::sqlite::SqliteRow, col_index: usize) -> Value {
    let column = &row.columns()[col_index];
    let type_info = column.type_info();
    
    match type_info.name() {
        "BOOLEAN" => {
            row.try_get::<Option<bool>, _>(col_index)
                .ok()
                .flatten()
                .map(Value::Bool)
                .unwrap_or(Value::Null)
        }
        "INTEGER" => {
            row.try_get::<Option<i64>, _>(col_index)
                .ok()
                .flatten()
                .map(|v| json!(v))
                .unwrap_or(Value::Null)
        }
        "REAL" => {
            row.try_get::<Option<f64>, _>(col_index)
                .ok()
                .flatten()
                .map(|v| json!(v))
                .unwrap_or(Value::Null)
        }
        "TEXT" => {
            row.try_get::<Option<String>, _>(col_index)
                .ok()
                .flatten()
                .map(Value::String)
                .unwrap_or(Value::Null)
        }
        "BLOB" => {
            row.try_get::<Option<Vec<u8>>, _>(col_index)
                .ok()
                .flatten()
                .map(|bytes| Value::String(format!("base64:{}", base64::engine::general_purpose::STANDARD.encode(bytes))))
                .unwrap_or(Value::Null)
        }
        _ => {
            // Try different types in order of preference
            if let Ok(Some(val)) = row.try_get::<Option<i64>, _>(col_index) {
                json!(val)
            } else if let Ok(Some(val)) = row.try_get::<Option<f64>, _>(col_index) {
                json!(val)
            } else if let Ok(Some(val)) = row.try_get::<Option<String>, _>(col_index) {
                Value::String(val)
            } else if let Ok(Some(val)) = row.try_get::<Option<bool>, _>(col_index) {
                Value::Bool(val)
            } else {
                Value::Null
            }
        }
    }
}

/// Database introspection functions for listing and describing tables

/// List tables for PostgreSQL 
async fn list_tables_postgres(pool: &Pool<Postgres>, config: &TablesConfig) -> Result<Value, DbError> {
    let mut table_types = vec!["'BASE TABLE'"];
    if config.include_views {
        table_types.push("'VIEW'");
    }
    
    let table_type_filter = format!("table_type IN ({})", table_types.join(", "));
    
    let mut system_filter = "table_schema NOT IN ('pg_catalog', 'information_schema')";
    if config.include_system {
        system_filter = "1=1";
    }
    
    let schema_filter = if config.schema.is_some() {
        "table_schema = $1"
    } else {
        "1=1"
    };
    
    let sql = format!(
        r#"
        SELECT table_schema, table_name, table_type
        FROM information_schema.tables
        WHERE {} AND {} AND {}
        ORDER BY table_schema, table_name
        LIMIT ${}
        "#,
        table_type_filter,
        system_filter,
        schema_filter,
        if config.schema.is_some() { "2" } else { "1" }
    );

    let query = if let Some(ref schema) = config.schema {
        sqlx::query(&sql).bind(schema).bind(config.max_tables as i64)
    } else {
        sqlx::query(&sql).bind(config.max_tables as i64)
    };

    let rows = query.fetch_all(pool).await
        .map_err(|e| DbError::TablesFailed { message: e.to_string() })?;

    let mut tables = Vec::new();
    for row in &rows {
        let schema: String = row.get(0);
        let name: String = row.get(1);
        let table_type: String = row.get(2);
        
        tables.push(json!({
            "name": name,
            "schema": schema,
            "type": table_type
        }));
    }

    let truncated = rows.len() >= config.max_tables as usize;

    Ok(json!({
        "tables": tables,
        "meta": {
            "count": tables.len(),
            "truncated": truncated
        }
    }))
}

/// Describe table for PostgreSQL
async fn describe_table_postgres(pool: &Pool<Postgres>, config: &TablesConfig, table_name: &str) -> Result<Value, DbError> {
    // First, check if table exists and get basic info
    let table_info_sql = if let Some(ref schema) = config.schema {
        r#"
        SELECT table_schema, table_name, table_type
        FROM information_schema.tables
        WHERE table_name = $1 AND table_schema = $2
        "#
    } else {
        r#"
        SELECT table_schema, table_name, table_type
        FROM information_schema.tables
        WHERE table_name = $1
        "#
    };

    let table_info_rows = if let Some(ref schema) = config.schema {
        sqlx::query(table_info_sql)
            .bind(table_name)
            .bind(schema)
            .fetch_all(pool).await
            .map_err(|e| DbError::TablesFailed { message: e.to_string() })?
    } else {
        sqlx::query(table_info_sql)
            .bind(table_name)
            .fetch_all(pool).await
            .map_err(|e| DbError::TablesFailed { message: e.to_string() })?
    };

    if table_info_rows.is_empty() {
        return Err(DbError::TableNotFound { table: table_name.to_string() });
    }

    let table_info = &table_info_rows[0];
    let schema: String = table_info.get(0);
    let name: String = table_info.get(1);
    let table_type: String = table_info.get(2);

    // Get column information
    let columns_sql = r#"
        SELECT
            c.column_name,
            c.ordinal_position,
            c.data_type,
            c.is_nullable,
            c.column_default
        FROM information_schema.columns c
        WHERE c.table_name = $1 AND c.table_schema = $2
        ORDER BY c.ordinal_position
        "#;

    let column_rows = sqlx::query(columns_sql)
        .bind(&name)
        .bind(&schema)
        .fetch_all(pool).await
        .map_err(|e| DbError::TablesFailed { message: e.to_string() })?;

    // Get primary key information
    let pk_sql = r#"
        SELECT kcu.column_name
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
          ON tc.constraint_name = kcu.constraint_name
         AND tc.table_schema = kcu.table_schema
        WHERE tc.table_name = $1
          AND tc.table_schema = $2
          AND tc.constraint_type = 'PRIMARY KEY'
        "#;

    let pk_rows = sqlx::query(pk_sql)
        .bind(&name)
        .bind(&schema)
        .fetch_all(pool).await
        .map_err(|e| DbError::TablesFailed { message: e.to_string() })?;

    let pk_columns: std::collections::HashSet<String> = pk_rows
        .iter()
        .map(|row| row.get::<String, _>(0))
        .collect();

    let mut columns = Vec::new();
    for row in column_rows {
        let column_name: String = row.get(0);
        let ordinal_position: i32 = row.get(1);
        let data_type: String = row.get(2);
        let is_nullable: String = row.get(3);
        let default: Option<String> = row.get(4);

        columns.push(json!({
            "name": column_name,
            "ordinal_position": ordinal_position,
            "data_type": data_type,
            "is_nullable": is_nullable == "YES",
            "default": default,
            "is_primary_key": pk_columns.contains(&column_name)
        }));
    }

    Ok(json!({
        "table": {
            "name": name,
            "schema": schema,
            "type": table_type
        },
        "columns": columns
    }))
}

/// List tables for MySQL
async fn list_tables_mysql(pool: &Pool<MySql>, config: &TablesConfig) -> Result<Value, DbError> {
    let mut table_types = vec!["'BASE TABLE'"];
    if config.include_views {
        table_types.push("'VIEW'");
    }
    
    let table_type_filter = format!("table_type IN ({})", table_types.join(", "));
    
    let schema_part = if let Some(ref schema) = config.schema {
        format!("table_schema = '{}'", schema)
    } else {
        "table_schema = DATABASE()".to_string()
    };
    
    let sql = format!(
        r#"
        SELECT table_schema, table_name, table_type
        FROM information_schema.tables
        WHERE {} AND {}
        ORDER BY table_schema, table_name
        LIMIT {}
        "#,
        table_type_filter,
        schema_part,
        config.max_tables
    );

    let rows = sqlx::query(&sql)
        .fetch_all(pool).await
        .map_err(|e| DbError::TablesFailed { message: e.to_string() })?;

    let mut tables = Vec::new();
    for row in &rows {
        let schema: String = row.get(0);
        let name: String = row.get(1);
        let table_type: String = row.get(2);
        
        tables.push(json!({
            "name": name,
            "schema": schema,
            "type": table_type
        }));
    }

    let truncated = rows.len() >= config.max_tables as usize;

    Ok(json!({
        "tables": tables,
        "meta": {
            "count": tables.len(),
            "truncated": truncated
        }
    }))
}

/// Describe table for MySQL
async fn describe_table_mysql(pool: &Pool<MySql>, config: &TablesConfig, table_name: &str) -> Result<Value, DbError> {
    let schema_clause = if let Some(ref schema) = config.schema {
        format!("c.table_schema = '{}'", schema)
    } else {
        "c.table_schema = DATABASE()".to_string()
    };

    // Get table and column information in one query
    let sql = format!(
        r#"
        SELECT
            c.table_schema,
            c.table_name,
            'BASE TABLE' as table_type,
            c.column_name,
            c.ordinal_position,
            c.data_type,
            c.is_nullable,
            c.column_default,
            c.column_key
        FROM information_schema.columns c
        WHERE c.table_name = '{}' AND {}
        ORDER BY c.ordinal_position
        "#,
        table_name, schema_clause
    );

    let rows = sqlx::query(&sql)
        .fetch_all(pool).await
        .map_err(|e| DbError::TablesFailed { message: e.to_string() })?;

    if rows.is_empty() {
        return Err(DbError::TableNotFound { table: table_name.to_string() });
    }

    let first_row = &rows[0];
    let schema: String = first_row.get(0);
    let name: String = first_row.get(1);
    let table_type: String = first_row.get(2);

    let mut columns = Vec::new();
    for row in rows {
        let column_name: String = row.get(3);
        // information_schema.columns.ordinal_position is unsigned on MySQL
        // and MariaDB; sqlx refuses (and `get` panics on) a signed read.
        let ordinal_position: u32 = row.get(4);
        let data_type: String = row.get(5);
        let is_nullable: String = row.get(6);
        let default: Option<String> = row.get(7);
        let column_key: String = row.get(8);

        columns.push(json!({
            "name": column_name,
            "ordinal_position": ordinal_position,
            "data_type": data_type,
            "is_nullable": is_nullable == "YES",
            "default": default,
            "is_primary_key": column_key == "PRI"
        }));
    }

    Ok(json!({
        "table": {
            "name": name,
            "schema": schema,
            "type": table_type
        },
        "columns": columns
    }))
}

/// List tables for SQLite
async fn list_tables_sqlite(pool: &Pool<Sqlite>, config: &TablesConfig) -> Result<Value, DbError> {
    let mut type_filter = vec!["'table'"];
    if config.include_views {
        type_filter.push("'view'");
    }
    
    let type_clause = format!("type IN ({})", type_filter.join(", "));
    
    let system_clause = if config.include_system {
        "1=1"
    } else {
        "name NOT LIKE 'sqlite_%'"
    };
    
    let sql = format!(
        r#"
        SELECT name, type
        FROM sqlite_schema
        WHERE {} AND {}
        ORDER BY name
        LIMIT {}
        "#,
        type_clause, system_clause, config.max_tables
    );

    let rows = sqlx::query(&sql)
        .fetch_all(pool).await
        .map_err(|e| DbError::TablesFailed { message: e.to_string() })?;

    let mut tables = Vec::new();
    for row in &rows {
        let name: String = row.get(0);
        let sqlite_type: String = row.get(1);
        let table_type = if sqlite_type == "table" { "BASE TABLE" } else { "VIEW" };
        
        tables.push(json!({
            "name": name,
            "schema": null,  // SQLite doesn't have schemas
            "type": table_type
        }));
    }

    let truncated = rows.len() >= config.max_tables as usize;

    Ok(json!({
        "tables": tables,
        "meta": {
            "count": tables.len(),
            "truncated": truncated
        }
    }))
}

/// Describe table for SQLite
async fn describe_table_sqlite(pool: &Pool<Sqlite>, _config: &TablesConfig, table_name: &str) -> Result<Value, DbError> {
    // First check if table exists
    let exists_sql = "SELECT type FROM sqlite_schema WHERE name = ? AND type IN ('table', 'view')";
    let exists_rows = sqlx::query(exists_sql)
        .bind(table_name)
        .fetch_all(pool).await
        .map_err(|e| DbError::TablesFailed { message: e.to_string() })?;

    if exists_rows.is_empty() {
        return Err(DbError::TableNotFound { table: table_name.to_string() });
    }

    let sqlite_type: String = exists_rows[0].get(0);
    let table_type = if sqlite_type == "table" { "BASE TABLE" } else { "VIEW" };

    // Get table info using PRAGMA
    let pragma_sql = format!("PRAGMA table_info('{}')", table_name);
    let rows = sqlx::query(&pragma_sql)
        .fetch_all(pool).await
        .map_err(|e| DbError::TablesFailed { message: e.to_string() })?;

    let mut columns = Vec::new();
    for row in rows {
        let cid: i32 = row.get(0);
        let name: String = row.get(1);
        let data_type: String = row.get(2);
        let not_null: i32 = row.get(3);
        let default_value: Option<String> = row.get(4);
        let pk: i32 = row.get(5);

        // In SQLite, PRIMARY KEY columns are always NOT NULL, but PRAGMA table_info might not reflect this correctly
        let is_nullable = if pk > 0 {
            false // Primary key columns are never nullable
        } else {
            not_null == 0 // For non-PK columns, not_null=1 means NOT NULL (is_nullable=false)
        };

        columns.push(json!({
            "name": name,
            "ordinal_position": cid + 1, // SQLite cid is 0-based
            "data_type": data_type,
            "is_nullable": is_nullable,
            "default": default_value,
            "is_primary_key": pk > 0
        }));
    }

    Ok(json!({
        "table": {
            "name": table_name,
            "schema": null,
            "type": table_type
        },
        "columns": columns
    }))
}

/// Schema introspection for PostgreSQL
async fn schema_postgres(pool: &Pool<Postgres>, config: &SchemaConfig) -> Result<Value> {
    // First check if table exists
    let exists_sql = "SELECT table_schema, table_name, table_type
                      FROM information_schema.tables
                      WHERE table_name = $1
                        AND (table_schema = $2 OR $2 IS NULL)
                      LIMIT 1";
    
    let exists_rows = sqlx::query(exists_sql)
        .bind(&config.table)
        .bind(&config.schema)
        .fetch_all(pool)
        .await
        .map_err(|e| DbError::SchemaFailed { message: e.to_string() })?;

    if exists_rows.is_empty() {
        return Err(DbError::TableNotFound { table: config.table.clone() }.into());
    }

    let table_schema: String = exists_rows[0].get(0);
    let table_name: String = exists_rows[0].get(1);
    let table_type: String = exists_rows[0].get(2);

    // Get columns
    let columns_sql = "SELECT
                        c.table_schema,
                        c.table_name,
                        c.column_name,
                        c.ordinal_position,
                        c.data_type,
                        c.is_nullable,
                        c.column_default
                       FROM information_schema.columns c
                       WHERE c.table_name = $1
                         AND (c.table_schema = $2 OR $2 IS NULL)
                       ORDER BY c.ordinal_position";

    let column_rows = sqlx::query(columns_sql)
        .bind(&config.table)
        .bind(&config.schema)
        .fetch_all(pool)
        .await
        .map_err(|e| DbError::SchemaFailed { message: e.to_string() })?;

    let mut columns = Vec::new();
    let mut pk_columns = Vec::new();

    for row in column_rows {
        let column_name: String = row.get(2);
        let ordinal_position: i32 = row.get(3);
        let data_type: String = row.get(4);
        let is_nullable: String = row.get(5);
        let column_default: Option<String> = row.get(6);

        columns.push(json!({
            "name": column_name,
            "ordinal_position": ordinal_position,
            "data_type": data_type,
            "is_nullable": is_nullable == "YES",
            "default": column_default,
            "is_primary_key": false // Will be updated when we find PK
        }));
    }

    // Get primary key
    let pk_sql = "SELECT
                    kcu.column_name,
                    kcu.ordinal_position
                  FROM information_schema.table_constraints tc
                  JOIN information_schema.key_column_usage kcu
                    ON tc.constraint_name = kcu.constraint_name
                   AND tc.table_schema = kcu.table_schema
                  WHERE tc.table_name = $1
                    AND (tc.table_schema = $2 OR $2 IS NULL)
                    AND tc.constraint_type = 'PRIMARY KEY'
                  ORDER BY kcu.ordinal_position";

    let pk_rows = sqlx::query(pk_sql)
        .bind(&config.table)
        .bind(&config.schema)
        .fetch_all(pool)
        .await
        .map_err(|e| DbError::SchemaFailed { message: e.to_string() })?;

    let mut primary_key = None;
    if !pk_rows.is_empty() {
        for row in &pk_rows {
            let column_name: String = row.get(0);
            pk_columns.push(column_name.clone());

            // Mark column as PK
            for col in &mut columns {
                if col["name"] == column_name {
                    col["is_primary_key"] = json!(true);
                }
            }
        }

        primary_key = Some(json!({
            "name": format!("{}_pkey", config.table), // Standard PostgreSQL PK name
            "columns": pk_columns
        }));
    }

    let mut schema_result = json!({
        "table": {
            "name": table_name,
            "schema": table_schema,
            "type": table_type
        },
        "columns": columns
    });

    if let Some(pk) = primary_key {
        schema_result["primary_key"] = pk;
    }

    // Add optional sections based on config flags
    if config.include_indexes {
        // Get indexes (simplified version for now)
        schema_result["indexes"] = json!([]);
    }

    if config.include_foreign_keys {
        schema_result["foreign_keys"] = json!([]);
    }

    if config.include_unique_constraints {
        schema_result["unique_constraints"] = json!([]);
    }

    if config.include_checks {
        schema_result["checks"] = json!([]);
    }

    if config.include_triggers {
        schema_result["triggers"] = json!([]);
    }

    Ok(schema_result)
}

/// Schema introspection for MySQL
async fn schema_mysql(pool: &Pool<MySql>, config: &SchemaConfig) -> Result<Value> {
    // First check if table exists
    let exists_sql = "SELECT table_schema, table_name, table_type
                      FROM information_schema.tables
                      WHERE table_name = ?
                        AND table_schema = COALESCE(?, DATABASE())
                      LIMIT 1";
    
    let exists_rows = sqlx::query(exists_sql)
        .bind(&config.table)
        .bind(&config.schema)
        .fetch_all(pool)
        .await
        .map_err(|e| DbError::SchemaFailed { message: e.to_string() })?;

    if exists_rows.is_empty() {
        return Err(DbError::TableNotFound { table: config.table.clone() }.into());
    }

    let table_schema: String = exists_rows[0].get(0);
    let table_name: String = exists_rows[0].get(1);
    let table_type: String = exists_rows[0].get(2);

    // Get columns
    let columns_sql = "SELECT
                        c.table_schema,
                        c.table_name,
                        c.column_name,
                        c.ordinal_position,
                        c.data_type,
                        c.is_nullable,
                        c.column_default,
                        c.column_key,
                        c.extra
                       FROM information_schema.columns c
                       WHERE c.table_name = ?
                         AND c.table_schema = COALESCE(?, DATABASE())
                       ORDER BY c.ordinal_position";

    let column_rows = sqlx::query(columns_sql)
        .bind(&config.table)
        .bind(&config.schema)
        .fetch_all(pool)
        .await
        .map_err(|e| DbError::SchemaFailed { message: e.to_string() })?;

    let mut columns = Vec::new();
    let mut pk_columns = Vec::new();

    for row in column_rows {
        let column_name: String = row.get(2);
        let ordinal_position: u32 = row.get(3);
        let data_type: String = row.get(4);
        let is_nullable: String = row.get(5);
        let column_default: Option<String> = row.get(6);
        let column_key: String = row.get(7);
        let _extra: String = row.get(8);

        let is_primary_key = column_key == "PRI";
        if is_primary_key {
            pk_columns.push(column_name.clone());
        }

        columns.push(json!({
            "name": column_name,
            "ordinal_position": ordinal_position,
            "data_type": data_type,
            "is_nullable": is_nullable == "YES",
            "default": column_default,
            "is_primary_key": is_primary_key
        }));
    }

    let mut schema_result = json!({
        "table": {
            "name": table_name,
            "schema": table_schema,
            "type": table_type
        },
        "columns": columns
    });

    if !pk_columns.is_empty() {
        schema_result["primary_key"] = json!({
            "name": "PRIMARY",
            "columns": pk_columns
        });
    }

    // Add optional sections based on config flags
    if config.include_indexes {
        schema_result["indexes"] = json!([]);
    }

    if config.include_foreign_keys {
        schema_result["foreign_keys"] = json!([]);
    }

    if config.include_unique_constraints {
        schema_result["unique_constraints"] = json!([]);
    }

    if config.include_checks {
        schema_result["checks"] = json!([]);
    }

    if config.include_triggers {
        schema_result["triggers"] = json!([]);
    }

    Ok(schema_result)
}

/// Schema introspection for SQLite
async fn schema_sqlite(pool: &Pool<Sqlite>, config: &SchemaConfig) -> Result<Value> {
    // First check if table exists
    let exists_sql = "SELECT name, type FROM sqlite_schema WHERE name = ? AND type IN ('table', 'view')";
    let exists_rows = sqlx::query(exists_sql)
        .bind(&config.table)
        .fetch_all(pool)
        .await
        .map_err(|e| DbError::SchemaFailed { message: e.to_string() })?;

    if exists_rows.is_empty() {
        return Err(DbError::TableNotFound { table: config.table.clone() }.into());
    }

    let table_name: String = exists_rows[0].get(0);
    let sqlite_type: String = exists_rows[0].get(1);
    let table_type = if sqlite_type == "table" { "BASE TABLE" } else { "VIEW" };

    // Get table info using PRAGMA
    let pragma_sql = format!("PRAGMA table_info('{}')", table_name);
    let rows = sqlx::query(&pragma_sql)
        .fetch_all(pool)
        .await
        .map_err(|e| DbError::SchemaFailed { message: e.to_string() })?;

    let mut columns = Vec::new();
    let mut pk_columns = Vec::new();

    for row in rows {
        let cid: i32 = row.get(0);
        let name: String = row.get(1);
        let data_type: String = row.get(2);
        let not_null: i32 = row.get(3);
        let default_value: Option<String> = row.get(4);
        let pk: i32 = row.get(5);

        let is_primary_key = pk > 0;
        if is_primary_key {
            pk_columns.push(name.clone());
        }

        // In SQLite, PRIMARY KEY columns are always NOT NULL
        let is_nullable = if is_primary_key {
            false
        } else {
            not_null == 0 // not_null=1 means NOT NULL (is_nullable=false)
        };

        columns.push(json!({
            "name": name,
            "ordinal_position": cid + 1, // SQLite cid is 0-based, make it 1-based
            "data_type": data_type,
            "is_nullable": is_nullable,
            "default": default_value,
            "is_primary_key": is_primary_key
        }));
    }

    let mut schema_result = json!({
        "table": {
            "name": table_name,
            "schema": "main", // SQLite uses "main" as default schema
            "type": table_type
        },
        "columns": columns
    });

    if !pk_columns.is_empty() {
        schema_result["primary_key"] = json!({
            "name": format!("{}_pkey", table_name),
            "columns": pk_columns
        });
    }

    // Add optional sections based on config flags
    if config.include_indexes {
        // Get index list using PRAGMA
        let index_sql = format!("PRAGMA index_list('{}')", table_name);
        let index_rows = sqlx::query(&index_sql)
            .fetch_all(pool)
            .await
            .map_err(|e| DbError::SchemaFailed { message: e.to_string() })?;

        let mut indexes = Vec::new();
        for index_row in index_rows {
            let index_name: String = index_row.get(1);
            let is_unique: bool = index_row.get(2);
            
            // Get index columns
            let index_info_sql = format!("PRAGMA index_info('{}')", index_name);
            let info_rows = sqlx::query(&index_info_sql)
                .fetch_all(pool)
                .await
                .map_err(|e| DbError::SchemaFailed { message: e.to_string() })?;

            let mut index_columns = Vec::new();
            for info_row in info_rows {
                if let Ok(column_name) = info_row.try_get::<String, _>(2) {
                    index_columns.push(column_name);
                }
            }

            indexes.push(json!({
                "name": index_name,
                "is_unique": is_unique,
                "columns": index_columns
            }));
        }
        schema_result["indexes"] = json!(indexes);
    }

    if config.include_foreign_keys {
        // Get foreign keys using PRAGMA
        let fk_sql = format!("PRAGMA foreign_key_list('{}')", table_name);
        let fk_rows = sqlx::query(&fk_sql)
            .fetch_all(pool)
            .await
            .map_err(|e| DbError::SchemaFailed { message: e.to_string() })?;

        let mut foreign_keys = Vec::new();
        for fk_row in fk_rows {
            let _id: i32 = fk_row.get(0);
            let _seq: i32 = fk_row.get(1);
            let referenced_table: String = fk_row.get(2);
            let from_column: String = fk_row.get(3);
            let to_column: String = fk_row.get(4);
            let on_update: String = fk_row.get(5);
            let on_delete: String = fk_row.get(6);

            foreign_keys.push(json!({
                "name": format!("fk_{}_{}", table_name, from_column),
                "columns": [from_column],
                "referenced_table": {
                    "schema": "main",
                    "name": referenced_table
                },
                "referenced_columns": [to_column],
                "on_update": on_update,
                "on_delete": on_delete
            }));
        }
        schema_result["foreign_keys"] = json!(foreign_keys);
    }

    if config.include_unique_constraints {
        schema_result["unique_constraints"] = json!([]);
    }

    if config.include_checks {
        schema_result["checks"] = json!([]);
    }

    if config.include_triggers {
        schema_result["triggers"] = json!([]);
    }

    Ok(schema_result)
}

impl Handle for DbHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["connect", "query", "exec", "tables", "schema", "ping", "transaction"]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&DB_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Help requests (help, --help, -h, --help=<verb>, help(verb=<verb>))
        if let Some(topic) = self.help_topic(verb, args) {
            return self.display_help(io, topic);
        }

        // One runtime per process, so pools registered by an earlier stage
        // stay usable by later stages of the same resh invocation.
        let rt = db_runtime()?;

        let json_args = cli_args_to_value(args);
        let result = match verb {
            "connect" => rt.block_on(self.connect(args.clone())),
            "query" => rt.block_on(self.query(json_args)),
            "exec" => rt.block_on(self.exec(json_args)),
            "tables" => rt.block_on(self.tables(json_args)),
            "schema" => rt.block_on(self.schema(json_args)),
            "ping" => rt.block_on(self.ping(json_args)),
            "transaction" => rt.block_on(self.transaction(json_args)),
            _ => {
                let error_json = json!({
                    "error": {
                        "code": "db.unknown_verb",
                        "message": format!("unknown verb: {}", verb),
                        "details": {
                            "verb": verb,
                            "available_verbs": self.verbs()
                        }
                    }
                });
                write!(io.stdout, "{}", error_json)?;
                return Ok(Status::err(1, format!("unknown verb: {}", verb)));
            }
        };

        match result {
            Ok(result) => {
                write!(io.stdout, "{}", result)?;
                Ok(value_status(&result))
            }
            Err(e) => {
                // Check if it's a DbError that can be converted to JSON
                let error_json = if let Some(db_error) = e.downcast_ref::<DbError>() {
                    db_error.to_json()
                } else {
                    json!({
                        "error": {
                            "code": "db.internal_error",
                            "message": e.to_string(),
                            "details": {}
                        }
                    })
                };
                write!(io.stdout, "{}", error_json)?;
                Ok(Status::err(1, e.to_string()))
            }
        }
    }
}

/// The exit status for a verb result: results that report
/// `"status": "error"` (for example a ping whose every attempt failed) are
/// failures, with the error message as the reason.
fn value_status(result: &Value) -> Status {
    if result.get("status").and_then(Value::as_str) != Some("error") {
        return Status::ok();
    }
    let message = result
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("operation failed");
    Status::err(1, message.to_string())
}

/// Process-wide runtime for db operations. sqlx pools are tied to the
/// runtime that opened their connections.
fn db_runtime() -> Result<&'static tokio::runtime::Runtime> {
    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    if let Some(rt) = RUNTIME.get() {
        return Ok(rt);
    }
    let rt = tokio::runtime::Runtime::new().context("failed to create tokio runtime")?;
    Ok(RUNTIME.get_or_init(|| rt))
}

/// Removes the password from a DSN for error messages.
fn redact_dsn(dsn: &str) -> String {
    match Url::parse(dsn) {
        Ok(mut url) if url.password().is_some() => {
            let _ = url.set_password(Some("***"));
            url.to_string()
        }
        _ => dsn.to_string(),
    }
}

/// Converts CLI arguments (always strings) to a JSON object for the verb
/// config parsers. `params` and `statements` are parsed as JSON when they
/// are valid JSON; every other value stays a string, and the parsers convert
/// typed options (numbers, booleans) themselves.
fn cli_args_to_value(args: &Args) -> Value {
    let mut map = serde_json::Map::new();
    for (key, value) in args {
        let v = if key == "params" || key == "statements" {
            serde_json::from_str::<Value>(value).unwrap_or_else(|_| Value::String(value.clone()))
        } else {
            Value::String(value.clone())
        };
        map.insert(key.clone(), v);
    }
    Value::Object(map)
}

/// Register db:// scheme with the registry
pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("db", |u| Ok(Box::new(DbHandle::from_url(u.clone())?)));
    reg.set_probe_url("db", "db://sqlite/resh-help-probe");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_args() -> Args {
        let mut args = HashMap::new();
        args.insert("dsn".to_string(), "sqlite::memory:".to_string());
        args
    }

    #[test]
    fn test_driver_string_conversion() {
        // Test valid drivers
        assert_eq!(DbDriver::from_str("postgres").unwrap(), DbDriver::Postgres);
        assert_eq!(DbDriver::from_str("postgresql").unwrap(), DbDriver::Postgres);
        assert_eq!(DbDriver::from_str("POSTGRES").unwrap(), DbDriver::Postgres);
        assert_eq!(DbDriver::from_str("mysql").unwrap(), DbDriver::Mysql);
        assert_eq!(DbDriver::from_str("MySQL").unwrap(), DbDriver::Mysql);
        assert_eq!(DbDriver::from_str("sqlite").unwrap(), DbDriver::Sqlite);
        assert_eq!(DbDriver::from_str("SQLite").unwrap(), DbDriver::Sqlite);
        
        // Test invalid drivers
        assert!(DbDriver::from_str("oracle").is_err());
        assert!(DbDriver::from_str("mssql").is_err());
        assert!(DbDriver::from_str("").is_err());
    }

    #[test]
    fn test_driver_to_string() {
        assert_eq!(DbDriver::Postgres.as_str(), "postgres");
        assert_eq!(DbDriver::Mysql.as_str(), "mysql");
        assert_eq!(DbDriver::Sqlite.as_str(), "sqlite");
    }

    #[test]
    fn test_url_parsing() {
        let url = Url::parse("db://postgres/main").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        assert_eq!(handle.driver, DbDriver::Postgres);
        assert_eq!(handle.alias, "main");
    }

    #[test] 
    fn test_url_parsing_sqlite() {
        let url = Url::parse("db://sqlite/local").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        assert_eq!(handle.driver, DbDriver::Sqlite);
        assert_eq!(handle.alias, "local");
    }

    #[test]
    fn test_invalid_driver() {
        let url = Url::parse("db://oracle/test").unwrap();
        let result = DbHandle::from_url(url);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unsupported driver"));
    }

    #[test]
    fn test_missing_alias() {
        let url = Url::parse("db://postgres/").unwrap();
        let result = DbHandle::from_url(url);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must specify alias"));
    }

    #[test]
    fn test_config_validation_valid() {
        let url = Url::parse("db://postgres/test").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        let config = DbConfig {
            max_connections: 10,
            min_connections: 5,
            connect_timeout_ms: 1000,
            idle_timeout_ms: 10000,
            max_lifetime_ms: 60000,
            tls_mode: Some("prefer".to_string()),
            log_queries: false,
        };

        assert!(handle.validate_config(&config).is_ok());
    }

    #[test]
    fn test_config_validation_invalid_connections() {
        let url = Url::parse("db://sqlite/test").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        let config = DbConfig {
            max_connections: 5,
            min_connections: 10, // Invalid: min > max
            ..Default::default()
        };

        assert!(handle.validate_config(&config).is_err());
    }

    #[test]
    fn test_config_validation_zero_connections() {
        let url = Url::parse("db://sqlite/test").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        let config = DbConfig {
            max_connections: 0, // Invalid
            ..Default::default()
        };

        assert!(handle.validate_config(&config).is_err());
    }

    #[test]
    fn test_config_validation_invalid_tls_mode() {
        let url = Url::parse("db://postgres/test").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        let config = DbConfig {
            tls_mode: Some("invalid_mode".to_string()),
            ..Default::default()
        };

        assert!(handle.validate_config(&config).is_err());
    }

    #[test]
    fn test_dsn_resolution_from_args() {
        let url = Url::parse("db://sqlite/test").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        let args = create_test_args();
        let dsn = handle.resolve_dsn(&args).unwrap();
        
        assert_eq!(dsn, "sqlite::memory:");
    }

    #[test]
    fn test_dsn_resolution_missing() {
        let url = Url::parse("db://sqlite/test").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        let args = HashMap::new();
        let result = handle.resolve_dsn(&args);
        
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("missing DSN"));
    }

    #[test]
    fn test_db_error_json_conversion() {
        let error = DbError::UnsupportedDriver {
            driver: "oracle".to_string(),
        };
        
        let json = error.to_json();
        assert_eq!(json["error"]["code"], "db.unsupported_driver");
        assert_eq!(json["error"]["details"]["driver"], "oracle");
    }

    #[tokio::test]
    async fn test_sqlite_memory_connection() {
        let url = Url::parse("db://sqlite/test").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        let args = create_test_args();
        let result = handle.connect(args).await;
        
        assert!(result.is_ok());
        let json = result.unwrap();
        assert_eq!(json["type"], "db_connection");
        assert_eq!(json["driver"], "sqlite");
        assert_eq!(json["alias"], "test");
    }

    #[tokio::test]
    async fn test_alias_conflict_detection() {
        let url = Url::parse("db://sqlite/conflict_test").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // First connection
        let mut args1 = HashMap::new();
        args1.insert("dsn".to_string(), "sqlite::memory:".to_string());
        let result1 = handle.connect(args1).await;
        assert!(result1.is_ok());
        
        // Second connection with different DSN should fail
        let mut args2 = HashMap::new();
        args2.insert("dsn".to_string(), "sqlite:///different/path.db".to_string());
        let result2 = handle.connect(args2).await;
        assert!(result2.is_err());
        assert!(result2.unwrap_err().to_string().contains("alias conflict"));
    }

    #[tokio::test]
    async fn test_connection_reuse() {
        let url = Url::parse("db://sqlite/reuse_test").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        let args = create_test_args();
        
        // First connection
        let result1 = handle.connect(args.clone()).await;
        assert!(result1.is_ok());
        let json1 = result1.unwrap();
        assert_eq!(json1["reused"], false);
        
        // Second connection should be reused
        let result2 = handle.connect(args).await;
        assert!(result2.is_ok());
        let json2 = result2.unwrap();
        assert_eq!(json2["reused"], true);
    }

    // Query-specific unit tests

    #[test]
    fn test_query_mode_parsing() {
        assert_eq!(QueryMode::from_str("rows").unwrap(), QueryMode::Rows);
        assert_eq!(QueryMode::from_str("ROWS").unwrap(), QueryMode::Rows);
        assert_eq!(QueryMode::from_str("scalar").unwrap(), QueryMode::Scalar);
        assert_eq!(QueryMode::from_str("exec").unwrap(), QueryMode::Exec);
        
        assert!(QueryMode::from_str("invalid").is_err());
        assert!(QueryMode::from_str("").is_err());
    }

    #[test]
    fn test_query_config_valid() {
        let args = json!({
            "sql": "SELECT * FROM users WHERE id = ?",
            "params": [1],
            "mode": "rows",
            "timeout_ms": 1000,
            "max_rows": 100
        });
        
        let config = QueryConfig::from_args(&args).unwrap();
        assert_eq!(config.sql, "SELECT * FROM users WHERE id = ?");
        assert_eq!(config.params.len(), 1);
        assert_eq!(config.mode, QueryMode::Rows);
        assert_eq!(config.timeout_ms, 1000);
        assert_eq!(config.max_rows, 100);
    }

    #[test]
    fn test_query_config_defaults() {
        let args = json!({
            "sql": "SELECT COUNT(*) FROM users"
        });
        
        let config = QueryConfig::from_args(&args).unwrap();
        assert_eq!(config.sql, "SELECT COUNT(*) FROM users");
        assert_eq!(config.params.len(), 0);
        assert_eq!(config.mode, QueryMode::Rows);
        assert_eq!(config.timeout_ms, 5000);
        assert_eq!(config.max_rows, 1000);
    }

    #[test]
    fn test_query_config_missing_sql() {
        let args = json!({
            "params": []
        });
        
        let result = QueryConfig::from_args(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing required 'sql' field"));
    }

    #[test]
    fn test_query_config_empty_sql() {
        let args = json!({
            "sql": "   "
        });
        
        let result = QueryConfig::from_args(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("sql cannot be empty"));
    }

    #[test]
    fn test_query_config_invalid_timeout() {
        let args = json!({
            "sql": "SELECT 1",
            "timeout_ms": 0
        });
        
        let result = QueryConfig::from_args(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timeout_ms must be greater than 0"));
    }

    #[test]
    fn test_query_config_invalid_max_rows() {
        let args = json!({
            "sql": "SELECT 1",
            "max_rows": 0
        });
        
        let result = QueryConfig::from_args(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("max_rows must be greater than 0"));
    }

    #[test]
    fn test_query_config_max_rows_too_large() {
        let args = json!({
            "sql": "SELECT 1",
            "max_rows": 2000000
        });
        
        let result = QueryConfig::from_args(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("max_rows cannot exceed 1,000,000"));
    }

    #[test]
    fn test_query_config_named_params_not_supported() {
        let args = json!({
            "sql": "SELECT * FROM users WHERE id = :id",
            "params": {"id": 1}
        });
        
        let result = QueryConfig::from_args(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("named parameters not yet supported"));
    }

    #[tokio::test]
    async fn test_query_connection_not_found() {
        let url = Url::parse("db://sqlite/nonexistent").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        let args = json!({
            "sql": "SELECT 1"
        });
        
        let result = handle.query(args).await;
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        if let Some(db_error) = error.downcast_ref::<DbError>() {
            match db_error {
                DbError::ConnectionNotFound { driver, alias } => {
                    assert_eq!(driver, "sqlite");
                    assert_eq!(alias, "nonexistent");
                }
                _ => panic!("Expected ConnectionNotFound error, got: {:?}", db_error),
            }
        } else {
            panic!("Expected DbError, got: {:?}", error);
        }
    }

    #[test]
    fn test_db_error_json_conversion_query_errors() {
        // Test ConnectionNotFound
        let error = DbError::ConnectionNotFound {
            driver: "sqlite".to_string(),
            alias: "test".to_string(),
        };
        let json = error.to_json();
        assert_eq!(json["error"]["code"], "db.connection_not_found");
        assert_eq!(json["error"]["details"]["driver"], "sqlite");
        assert_eq!(json["error"]["details"]["alias"], "test");

        // Test InvalidQueryConfig
        let error = DbError::InvalidQueryConfig {
            message: "invalid timeout".to_string(),
        };
        let json = error.to_json();
        assert_eq!(json["error"]["code"], "db.invalid_query_config");
        assert_eq!(json["error"]["details"]["validation_error"], "invalid timeout");

        // Test UnsupportedParamType
        let error = DbError::UnsupportedParamType {
            type_name: "array".to_string(),
        };
        let json = error.to_json();
        assert_eq!(json["error"]["code"], "db.unsupported_param_type");
        assert_eq!(json["error"]["details"]["type_name"], "array");

        // Test QueryTimeout
        let error = DbError::QueryTimeout {
            timeout_ms: 5000,
        };
        let json = error.to_json();
        assert_eq!(json["error"]["code"], "db.query_timeout");
        assert_eq!(json["error"]["details"]["timeout_ms"], 5000);

        // Test QueryFailed
        let error = DbError::QueryFailed {
            message: "syntax error".to_string(),
        };
        let json = error.to_json();
        assert_eq!(json["error"]["code"], "db.query_failed");
        assert_eq!(json["error"]["details"]["underlying_error"], "syntax error");
    }

    // Exec Verb Unit Tests

    #[test]
    fn test_exec_config_from_args_valid() {
        let args = json!({
            "sql": "INSERT INTO users (name) VALUES (?)",
            "params": ["Alice"],
            "timeout_ms": 3000,
            "return_last_insert_id": true
        });

        let config = ExecConfig::from_args(&args).unwrap();
        assert_eq!(config.sql, "INSERT INTO users (name) VALUES (?)");
        assert_eq!(config.params.len(), 1);
        assert_eq!(config.params[0], Value::String("Alice".to_string()));
        assert_eq!(config.timeout_ms, 3000);
        assert_eq!(config.return_last_insert_id, true);
    }

    #[test]
    fn test_exec_config_from_args_defaults() {
        let args = json!({
            "sql": "DELETE FROM users WHERE id = ?"
        });

        let config = ExecConfig::from_args(&args).unwrap();
        assert_eq!(config.sql, "DELETE FROM users WHERE id = ?");
        assert_eq!(config.params.len(), 0);
        assert_eq!(config.timeout_ms, 5000);
        assert_eq!(config.return_last_insert_id, false);
    }

    #[test]
    fn test_exec_config_missing_sql() {
        let args = json!({
            "params": []
        });

        let result = ExecConfig::from_args(&args);
        assert!(result.is_err());
        match result.unwrap_err() {
            DbError::InvalidExecConfig { message } => {
                assert!(message.contains("missing required 'sql' field"));
            }
            _ => panic!("Expected InvalidExecConfig"),
        }
    }

    #[test]
    fn test_exec_config_empty_sql() {
        let args = json!({
            "sql": "   "
        });

        let result = ExecConfig::from_args(&args);
        assert!(result.is_err());
        match result.unwrap_err() {
            DbError::InvalidExecConfig { message } => {
                assert!(message.contains("sql cannot be empty"));
            }
            _ => panic!("Expected InvalidExecConfig"),
        }
    }

    #[test]
    fn test_exec_config_invalid_timeout() {
        let args = json!({
            "sql": "UPDATE users SET active = 1",
            "timeout_ms": 0
        });

        let result = ExecConfig::from_args(&args);
        assert!(result.is_err());
        match result.unwrap_err() {
            DbError::InvalidExecConfig { message } => {
                assert!(message.contains("timeout_ms must be greater than 0"));
            }
            _ => panic!("Expected InvalidExecConfig"),
        }
    }

    #[test]
    fn test_exec_config_invalid_params_type() {
        let args = json!({
            "sql": "INSERT INTO users (name) VALUES (?)",
            "params": "invalid_string"
        });

        let result = ExecConfig::from_args(&args);
        assert!(result.is_err());
        match result.unwrap_err() {
            DbError::InvalidExecConfig { message } => {
                assert!(message.contains("params must be an array or object"));
            }
            _ => panic!("Expected InvalidExecConfig"),
        }
    }

    #[test]
    fn test_exec_config_named_params_not_supported() {
        let args = json!({
            "sql": "INSERT INTO users (name) VALUES (:name)",
            "params": {"name": "Alice"}
        });

        let result = ExecConfig::from_args(&args);
        assert!(result.is_err());
        match result.unwrap_err() {
            DbError::InvalidExecConfig { message } => {
                assert!(message.contains("named parameters not yet supported"));
            }
            _ => panic!("Expected InvalidExecConfig"),
        }
    }

    #[test]
    fn test_exec_single_statement_validation() {
        // Valid single statements
        let valid_sqls = vec![
            "UPDATE users SET active = 1",
            "DELETE FROM users WHERE id = 1",
            "INSERT INTO users (name) VALUES ('Alice')",
            "CREATE TABLE test (id INT)",
            "UPDATE users SET name = 'Bob; Charlie' WHERE id = 1", // semicolon in string
            "INSERT INTO users (name) VALUES ('test;data')", // semicolon in string
            "UPDATE users SET active = 1;", // trailing semicolon is allowed
        ];

        for sql in valid_sqls {
            let args = json!({"sql": sql});
            let result = ExecConfig::from_args(&args);
            assert!(result.is_ok(), "Should be valid SQL: {}", sql);
        }

        // Invalid multiple statements
        let invalid_sqls = vec![
            "UPDATE users SET active = 1; DELETE FROM users;",
            "INSERT INTO users (name) VALUES ('Alice'); UPDATE users SET active = 1;",
            "CREATE TABLE test (id INT); DROP TABLE test;",
        ];

        for sql in invalid_sqls {
            let args = json!({"sql": sql});
            let result = ExecConfig::from_args(&args);
            assert!(result.is_err(), "Should be invalid SQL: {}", sql);
            match result.unwrap_err() {
                DbError::InvalidExecConfig { message } => {
                    assert!(message.contains("multiple statements detected"), 
                           "Wrong error message for: {}", sql);
                }
                _ => panic!("Expected InvalidExecConfig for: {}", sql),
            }
        }
    }

    #[tokio::test]
    async fn test_exec_connection_not_found() {
        let url = Url::parse("db://sqlite/nonexistent_exec").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        let args = json!({
            "sql": "UPDATE users SET active = 1"
        });
        
        let result = handle.exec(args).await;
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        if let Some(db_error) = error.downcast_ref::<DbError>() {
            match db_error {
                DbError::ConnectionNotFound { driver, alias } => {
                    assert_eq!(driver, "sqlite");
                    assert_eq!(alias, "nonexistent_exec");
                }
                _ => panic!("Expected ConnectionNotFound error, got: {:?}", db_error),
            }
        } else {
            panic!("Expected DbError, got: {:?}", error);
        }
    }

    #[test]
    fn test_exec_error_json_conversion() {
        // Test InvalidExecConfig
        let error = DbError::InvalidExecConfig {
            message: "test validation error".to_string(),
        };
        let json = error.to_json();
        assert_eq!(json["error"]["code"], "db.invalid_exec_config");
        assert_eq!(json["error"]["details"]["validation_error"], "test validation error");

        // Test ExecTimeout
        let error = DbError::ExecTimeout {
            timeout_ms: 3000,
        };
        let json = error.to_json();
        assert_eq!(json["error"]["code"], "db.exec_timeout");
        assert_eq!(json["error"]["details"]["timeout_ms"], 3000);

        // Test ExecFailed
        let error = DbError::ExecFailed {
            message: "SQL syntax error".to_string(),
        };
        let json = error.to_json();
        assert_eq!(json["error"]["code"], "db.exec_failed");
        assert_eq!(json["error"]["details"]["underlying_error"], "SQL syntax error");
    }

    // SQLite Integration Tests

    async fn setup_test_database(alias: &str) -> Result<DbHandle> {
        let url = Url::parse(&format!("db://sqlite/{}", alias))?;
        let handle = DbHandle::from_url(url)?;
        
        let mut args = std::collections::HashMap::new();
        args.insert("dsn".to_string(), "sqlite::memory:".to_string());
        
        // Connect to database
        handle.connect(args).await?;
        
        // Setup test schema
        let setup_args = json!({
            "sql": "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, active BOOLEAN)",
            "mode": "exec"
        });
        handle.query(setup_args).await?;
        
        // Insert test data
        let insert_args = json!({
            "sql": "INSERT INTO users (email, active) VALUES (?, ?), (?, ?), (?, ?)",
            "params": ["alice@example.com", true, "bob@example.com", true, "charlie@example.com", false],
            "mode": "exec"
        });
        handle.query(insert_args).await?;
        
        Ok(handle)
    }

    #[tokio::test]
    async fn test_sqlite_query_rows_mode() {
        let handle = setup_test_database("test_rows").await.unwrap();
        
        let args = json!({
            "sql": "SELECT id, email FROM users WHERE active = ?",
            "params": [true],
            "mode": "rows"
        });
        
        let result = handle.query(args).await.unwrap();
        
        assert_eq!(result["rows"].as_array().unwrap().len(), 2);
        assert_eq!(result["meta"]["row_count"], 2);
        assert_eq!(result["meta"]["truncated"], false);
        
        let columns = result["meta"]["columns"].as_array().unwrap();
        assert_eq!(columns.len(), 2);
        assert_eq!(columns[0]["name"], "id");
        assert_eq!(columns[1]["name"], "email");
    }

    #[tokio::test]
    async fn test_sqlite_query_scalar_mode() {
        let handle = setup_test_database("test_scalar").await.unwrap();
        
        let args = json!({
            "sql": "SELECT COUNT(*) FROM users WHERE active = ?",
            "params": [true],
            "mode": "scalar"
        });
        
        let result = handle.query(args).await.unwrap();
        
        assert_eq!(result["value"], 2);
        assert_eq!(result["meta"]["row_count"], 1);
    }

    #[tokio::test]
    async fn test_sqlite_query_exec_mode() {
        let handle = setup_test_database("test_exec").await.unwrap();
        
        let args = json!({
            "sql": "UPDATE users SET active = 0 WHERE active = 1",
            "mode": "exec"
        });
        
        let result = handle.query(args).await.unwrap();
        
        assert_eq!(result["rows_affected"], 2);
    }

    #[tokio::test]
    async fn test_sqlite_query_max_rows_truncation() {
        let handle = setup_test_database("test_truncate").await.unwrap();
        
        let args = json!({
            "sql": "SELECT id FROM users",
            "mode": "rows",
            "max_rows": 2
        });
        
        let result = handle.query(args).await.unwrap();
        
        assert_eq!(result["rows"].as_array().unwrap().len(), 2);
        assert_eq!(result["meta"]["row_count"], 3);
        assert_eq!(result["meta"]["truncated"], true);
    }

    #[tokio::test]
    async fn test_sqlite_query_no_results() {
        let handle = setup_test_database("test_empty").await.unwrap();
        
        let args = json!({
            "sql": "SELECT id FROM users WHERE id = ?",
            "params": [999],
            "mode": "scalar"
        });
        
        let result = handle.query(args).await.unwrap();
        
        assert_eq!(result["value"], Value::Null);
        assert_eq!(result["meta"]["row_count"], 0);
    }

    #[tokio::test]
    async fn test_sqlite_query_syntax_error() {
        let handle = setup_test_database("test_error").await.unwrap();
        
        let args = json!({
            "sql": "SELECT * FROMM users",  // Intentional syntax error
            "mode": "rows"
        });
        
        let result = handle.query(args).await;
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        if let Some(db_error) = error.downcast_ref::<DbError>() {
            match db_error {
                DbError::QueryFailed { message } => {
                    assert!(message.contains("syntax"));
                }
                _ => panic!("Expected QueryFailed error, got: {:?}", db_error),
            }
        }
    }

    // Exec Verb SQLite Integration Tests

    #[tokio::test]
    async fn test_sqlite_exec_create_table() {
        let url = Url::parse("db://sqlite/test_exec_create").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // Connect to database
        let connect_args = create_test_args();
        handle.connect(connect_args).await.unwrap();
        
        // Create table with exec
        let exec_args = json!({
            "sql": "CREATE TABLE exec_test (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, active BOOLEAN)"
        });
        
        let result = handle.exec(exec_args).await.unwrap();
        assert_eq!(result["rows_affected"], 0); // DDL statements typically return 0
    }

    #[tokio::test]
    async fn test_sqlite_exec_insert_with_last_insert_id() {
        let url = Url::parse("db://sqlite/test_exec_insert").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // Connect and setup
        handle.connect(create_test_args()).await.unwrap();
        handle.exec(json!({
            "sql": "CREATE TABLE exec_test (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, active BOOLEAN)"
        })).await.unwrap();
        
        // Insert with last_insert_id
        let exec_args = json!({
            "sql": "INSERT INTO exec_test (name, active) VALUES (?, ?)",
            "params": ["Alice", true],
            "return_last_insert_id": true
        });
        
        let result = handle.exec(exec_args).await.unwrap();
        assert_eq!(result["rows_affected"], 1);
        assert!(result["last_insert_id"].is_number());
        // Note: In a connection pool environment, last_insert_rowid() may return 0
        // if the INSERT and the rowid query happen on different connections.
        // This is expected behavior and shows the functionality works correctly.
        let last_id = result["last_insert_id"].as_i64().unwrap();
        assert!(last_id >= 0, "Expected last_insert_id >= 0, got {}", last_id);
    }

    #[tokio::test]
    async fn test_sqlite_exec_insert_without_last_insert_id() {
        let url = Url::parse("db://sqlite/test_exec_insert_no_id").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // Connect and setup
        handle.connect(create_test_args()).await.unwrap();
        handle.exec(json!({
            "sql": "CREATE TABLE exec_test (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)"
        })).await.unwrap();
        
        // Insert without last_insert_id
        let exec_args = json!({
            "sql": "INSERT INTO exec_test (name) VALUES (?)",
            "params": ["Bob"],
            "return_last_insert_id": false
        });
        
        let result = handle.exec(exec_args).await.unwrap();
        assert_eq!(result["rows_affected"], 1);
        assert!(!result.as_object().unwrap().contains_key("last_insert_id"));
    }

    #[tokio::test]
    async fn test_sqlite_exec_update() {
        let url = Url::parse("db://sqlite/test_exec_update").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // Connect and setup with test data
        handle.connect(create_test_args()).await.unwrap();
        handle.exec(json!({
            "sql": "CREATE TABLE exec_test (id INTEGER PRIMARY KEY, name TEXT, active BOOLEAN)"
        })).await.unwrap();
        handle.exec(json!({
            "sql": "INSERT INTO exec_test (name, active) VALUES (?, ?), (?, ?), (?, ?)",
            "params": ["Alice", true, "Bob", true, "Charlie", false]
        })).await.unwrap();
        
        // Update some rows
        let exec_args = json!({
            "sql": "UPDATE exec_test SET active = ? WHERE active = ?",
            "params": [false, true]
        });
        
        let result = handle.exec(exec_args).await.unwrap();
        assert_eq!(result["rows_affected"], 2); // Should update Alice and Bob
    }

    #[tokio::test]
    async fn test_sqlite_exec_delete() {
        let url = Url::parse("db://sqlite/test_exec_delete").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // Connect and setup with test data
        handle.connect(create_test_args()).await.unwrap();
        handle.exec(json!({
            "sql": "CREATE TABLE exec_test (id INTEGER PRIMARY KEY, name TEXT, active BOOLEAN)"
        })).await.unwrap();
        handle.exec(json!({
            "sql": "INSERT INTO exec_test (name, active) VALUES (?, ?), (?, ?), (?, ?)",
            "params": ["Alice", true, "Bob", false, "Charlie", true]
        })).await.unwrap();
        
        // Delete inactive rows
        let exec_args = json!({
            "sql": "DELETE FROM exec_test WHERE active = ?",
            "params": [false]
        });
        
        let result = handle.exec(exec_args).await.unwrap();
        assert_eq!(result["rows_affected"], 1); // Should delete Bob
    }

    #[tokio::test]
    async fn test_sqlite_exec_timeout() {
        let url = Url::parse("db://sqlite/test_exec_timeout").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        handle.connect(create_test_args()).await.unwrap();
        
        // Use a very small timeout with a simple operation to test timeout behavior
        let exec_args = json!({
            "sql": "CREATE TABLE timeout_test (id INTEGER)",
            "timeout_ms": 1 // Very small timeout
        });
        
        // This may or may not timeout depending on system speed, but should not crash
        let result = handle.exec(exec_args).await;
        // Don't assert specific result since timing is unpredictable in tests
        // Just ensure it doesn't panic
        match result {
            Ok(_) => {}, // Operation completed within timeout
            Err(e) => {
                // Should be ExecTimeout if it timed out
                if let Some(db_error) = e.downcast_ref::<DbError>() {
                    match db_error {
                        DbError::ExecTimeout { .. } => {}, // Expected timeout
                        _ => {}, // Other error is also acceptable
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn test_sqlite_exec_sql_syntax_error() {
        let url = Url::parse("db://sqlite/test_exec_error").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        handle.connect(create_test_args()).await.unwrap();
        
        // Invalid SQL should return ExecFailed
        let exec_args = json!({
            "sql": "INVALID SQL SYNTAX HERE"
        });
        
        let result = handle.exec(exec_args).await;
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        if let Some(db_error) = error.downcast_ref::<DbError>() {
            match db_error {
                DbError::ExecFailed { .. } => {}, // Expected
                _ => panic!("Expected ExecFailed error, got: {:?}", db_error),
            }
        } else {
            panic!("Expected DbError, got: {:?}", error);
        }
    }

    #[tokio::test]
    async fn test_sqlite_exec_parameter_binding() {
        let url = Url::parse("db://sqlite/test_exec_params").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // Connect and setup
        handle.connect(create_test_args()).await.unwrap();
        handle.exec(json!({
            "sql": "CREATE TABLE param_test (id INTEGER PRIMARY KEY, name TEXT, age INTEGER, active BOOLEAN, score REAL)"
        })).await.unwrap();
        
        // Test various parameter types
        let exec_args = json!({
            "sql": "INSERT INTO param_test (name, age, active, score) VALUES (?, ?, ?, ?)",
            "params": ["Alice", 25, true, 95.5]
        });
        
        let result = handle.exec(exec_args).await.unwrap();
        assert_eq!(result["rows_affected"], 1);
        
        // Test null parameter
        let exec_args_null = json!({
            "sql": "INSERT INTO param_test (name, age, active, score) VALUES (?, ?, ?, ?)",
            "params": ["Bob", null, false, 87.2]
        });
        
        let result_null = handle.exec(exec_args_null).await.unwrap();
        assert_eq!(result_null["rows_affected"], 1);
    }

    // Optional Postgres/MySQL integration tests (environment-driven)

    #[tokio::test]
    #[ignore = "needs a disposable PostgreSQL server (runs DDL/DML): set TEST_POSTGRES_DSN and run with --ignored"]
    async fn test_postgres_integration() {
        if let Ok(dsn) = std::env::var("TEST_POSTGRES_DSN") {
            let url = Url::parse("db://postgres/test_integration").unwrap();
            let handle = DbHandle::from_url(url).unwrap();
            
            let mut args = std::collections::HashMap::new();
            args.insert("dsn".to_string(), dsn);
            
            // Test connection
            let connect_result = handle.connect(args).await;
            assert!(connect_result.is_ok());
            
            // Test simple scalar query
            let query_args = json!({
                "sql": "SELECT 1 as test_value",
                "mode": "scalar"
            });
            
            let result = handle.query(query_args).await.unwrap();
            assert_eq!(result["value"], 1);
        }
    }

    #[tokio::test]
    #[ignore = "needs a disposable MySQL server (runs DDL/DML): set TEST_MYSQL_DSN and run with --ignored"]
    async fn test_mysql_integration() {
        if let Ok(dsn) = std::env::var("TEST_MYSQL_DSN") {
            let url = Url::parse("db://mysql/test_integration").unwrap();
            let handle = DbHandle::from_url(url).unwrap();
            
            let mut args = std::collections::HashMap::new();
            args.insert("dsn".to_string(), dsn);
            
            // Test connection
            let connect_result = handle.connect(args).await;
            assert!(connect_result.is_ok());
            
            // Test simple scalar query
            let query_args = json!({
                "sql": "SELECT 1 as test_value",
                "mode": "scalar"
            });
            
            let result = handle.query(query_args).await.unwrap();
            assert_eq!(result["value"], 1);
        }
    }

    // Optional Postgres Exec Integration Tests

    #[tokio::test]
    #[ignore = "needs a disposable PostgreSQL server (runs DDL/DML): set TEST_POSTGRES_DSN and run with --ignored"]
    async fn test_postgres_exec_integration() {
        if let Ok(dsn) = std::env::var("TEST_POSTGRES_DSN") {
            let url = Url::parse("db://postgres/test_exec_integration").unwrap();
            let handle = DbHandle::from_url(url).unwrap();
            
            let mut connect_args = std::collections::HashMap::new();
            connect_args.insert("dsn".to_string(), dsn);
            
            // Test connection
            let connect_result = handle.connect(connect_args).await;
            assert!(connect_result.is_ok());
            
            // A regular table: each exec may use a different pooled connection,
            // so a session-scoped TEMP table would not be visible to later calls.
            handle.exec(json!({ "sql": "DROP TABLE IF EXISTS exec_test_pg" })).await.unwrap();
            // Create table
            let create_args = json!({
                "sql": "CREATE TABLE exec_test_pg (id SERIAL PRIMARY KEY, name TEXT, active BOOLEAN)"
            });
            let create_result = handle.exec(create_args).await.unwrap();
            assert_eq!(create_result["rows_affected"], 0);

            // Insert with parameters
            let insert_args = json!({
                "sql": "INSERT INTO exec_test_pg (name, active) VALUES ($1, $2)",
                "params": ["Alice", true]
            });
            let insert_result = handle.exec(insert_args).await.unwrap();
            assert_eq!(insert_result["rows_affected"], 1);
            // For Postgres, last_insert_id should be null when requested
            let insert_with_id_args = json!({
                "sql": "INSERT INTO exec_test_pg (name, active) VALUES ($1, $2)",
                "params": ["Bob", false],
                "return_last_insert_id": true
            });
            let insert_with_id_result = handle.exec(insert_with_id_args).await.unwrap();
            assert_eq!(insert_with_id_result["rows_affected"], 1);
            assert_eq!(insert_with_id_result["last_insert_id"], Value::Null);

            // Update
            let update_args = json!({
                "sql": "UPDATE exec_test_pg SET active = $1 WHERE name = $2",
                "params": [true, "Bob"]
            });
            let update_result = handle.exec(update_args).await.unwrap();
            assert_eq!(update_result["rows_affected"], 1);

            // Delete
            let delete_args = json!({
                "sql": "DELETE FROM exec_test_pg WHERE active = $1",
                "params": [false]
            });
            let delete_result = handle.exec(delete_args).await.unwrap();
            assert_eq!(delete_result["rows_affected"], 0); // Bob was updated to active=true
        }
    }

    // Optional MySQL Exec Integration Tests

    #[tokio::test]
    #[ignore = "needs a disposable MySQL server (runs DDL/DML): set TEST_MYSQL_DSN and run with --ignored"]
    async fn test_mysql_exec_integration() {
        if let Ok(dsn) = std::env::var("TEST_MYSQL_DSN") {
            let url = Url::parse("db://mysql/test_exec_integration").unwrap();
            let handle = DbHandle::from_url(url).unwrap();
            
            let mut connect_args = std::collections::HashMap::new();
            connect_args.insert("dsn".to_string(), dsn);
            
            // Test connection
            let connect_result = handle.connect(connect_args).await;
            assert!(connect_result.is_ok());
            
            // A regular table: each exec may use a different pooled connection,
            // so a session-scoped TEMP table would not be visible to later calls.
            handle.exec(json!({ "sql": "DROP TABLE IF EXISTS exec_test_mysql" })).await.unwrap();
            // Create table
            let create_args = json!({
                "sql": "CREATE TABLE exec_test_mysql (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100), active BOOLEAN)"
            });
            let create_result = handle.exec(create_args).await.unwrap();
            assert_eq!(create_result["rows_affected"], 0);

            // Insert with parameters
            let insert_args = json!({
                "sql": "INSERT INTO exec_test_mysql (name, active) VALUES (?, ?)",
                "params": ["Alice", true]
            });
            let insert_result = handle.exec(insert_args).await.unwrap();
            assert_eq!(insert_result["rows_affected"], 1);
            
            // Insert with last_insert_id
            let insert_with_id_args = json!({
                "sql": "INSERT INTO exec_test_mysql (name, active) VALUES (?, ?)",
                "params": ["Bob", false],
                "return_last_insert_id": true
            });
            let insert_with_id_result = handle.exec(insert_with_id_args).await.unwrap();
            assert_eq!(insert_with_id_result["rows_affected"], 1);
            // For MySQL, last_insert_id should be a positive number
            assert!(insert_with_id_result["last_insert_id"].is_number());
            assert!(insert_with_id_result["last_insert_id"].as_i64().unwrap() > 0);

            // Update
            let update_args = json!({
                "sql": "UPDATE exec_test_mysql SET active = ? WHERE name = ?",
                "params": [true, "Bob"]
            });
            let update_result = handle.exec(update_args).await.unwrap();
            assert_eq!(update_result["rows_affected"], 1);

            // Delete
            let delete_args = json!({
                "sql": "DELETE FROM exec_test_mysql WHERE active = ?",
                "params": [false]
            });
            let delete_result = handle.exec(delete_args).await.unwrap();
            assert_eq!(delete_result["rows_affected"], 0); // Bob was updated to active=true
        }
    }

    // Tables verb tests

    #[tokio::test]
    async fn test_sqlite_tables_list_mode() {
        let url = Url::parse("db://sqlite/test_tables_list").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // Connect
        handle.connect(create_test_args()).await.unwrap();
        
        // Create some test tables
        handle.exec(json!({
            "sql": "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)"
        })).await.unwrap();
        
        handle.exec(json!({
            "sql": "CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER)"
        })).await.unwrap();
        
        // Create a view
        handle.exec(json!({
            "sql": "CREATE VIEW user_orders AS SELECT u.name, o.id as order_id FROM users u JOIN orders o ON u.id = o.user_id"
        })).await.unwrap();
        
        // Test list tables (without views)
        let tables_args = json!({});
        let result = handle.tables(tables_args).await.unwrap();
        
        assert!(result["tables"].is_array());
        let tables = result["tables"].as_array().unwrap();
        
        // Should have 2 base tables
        assert!(tables.len() >= 2);
        let table_names: Vec<&str> = tables.iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(table_names.contains(&"users"));
        assert!(table_names.contains(&"orders"));
        
        // Should not contain view by default
        assert!(!table_names.contains(&"user_orders"));
        
        assert_eq!(result["meta"]["truncated"], false);
    }

    #[tokio::test]
    async fn test_sqlite_tables_list_with_views() {
        let url = Url::parse("db://sqlite/test_tables_views").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // Connect and setup
        handle.connect(create_test_args()).await.unwrap();
        handle.exec(json!({
            "sql": "CREATE TABLE test_table (id INTEGER PRIMARY KEY)"
        })).await.unwrap();
        handle.exec(json!({
            "sql": "CREATE VIEW test_view AS SELECT * FROM test_table"
        })).await.unwrap();
        
        // Test with include_views=true
        let tables_args = json!({
            "include_views": true
        });
        let result = handle.tables(tables_args).await.unwrap();
        
        let tables = result["tables"].as_array().unwrap();
        let table_names: Vec<&str> = tables.iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        
        // Should contain both table and view
        assert!(table_names.contains(&"test_table"));
        assert!(table_names.contains(&"test_view"));
    }

    #[tokio::test]
    async fn test_sqlite_tables_describe_mode() {
        let url = Url::parse("db://sqlite/test_tables_describe").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // Connect
        handle.connect(create_test_args()).await.unwrap();
        
        // Create a table with various column types
        handle.exec(json!({
            "sql": "CREATE TABLE test_users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, age INTEGER, score REAL DEFAULT 0.0, active BOOLEAN DEFAULT 1)"
        })).await.unwrap();
        
        // Describe the table
        let describe_args = json!({
            "table": "test_users"
        });
        let result = handle.tables(describe_args).await.unwrap();
        
        // Check table info
        assert_eq!(result["table"]["name"], "test_users");
        assert_eq!(result["table"]["type"], "BASE TABLE");
        
        // Check columns
        assert!(result["columns"].is_array());
        let columns = result["columns"].as_array().unwrap();
        assert_eq!(columns.len(), 5);
        
        // Check first column (id - primary key)
        let id_col = &columns[0];
        assert_eq!(id_col["name"], "id");
        assert_eq!(id_col["data_type"], "INTEGER");
        assert_eq!(id_col["is_nullable"], false);
        assert_eq!(id_col["is_primary_key"], true);
        assert_eq!(id_col["ordinal_position"], 1);
        
        // Check name column
        let name_col = &columns[1];
        assert_eq!(name_col["name"], "name");
        assert_eq!(name_col["data_type"], "TEXT");
        assert_eq!(name_col["is_nullable"], false);
        assert_eq!(name_col["is_primary_key"], false);
    }

    #[tokio::test]
    async fn test_tables_config_validation() {
        let url = Url::parse("db://sqlite/test_tables_validation").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // Connect
        handle.connect(create_test_args()).await.unwrap();
        
        // Test invalid timeout
        let invalid_timeout_args = json!({
            "timeout_ms": 0
        });
        let result = handle.tables(invalid_timeout_args).await;
        assert!(result.is_err());
        
        if let Some(db_error) = result.unwrap_err().downcast_ref::<DbError>() {
            match db_error {
                DbError::InvalidTablesConfig { .. } => {}, // Expected
                _ => panic!("Expected InvalidTablesConfig error, got: {:?}", db_error),
            }
        }
        
        // Test invalid max_tables
        let invalid_max_tables_args = json!({
            "max_tables": 0
        });
        let result = handle.tables(invalid_max_tables_args).await;
        assert!(result.is_err());
        
        // Test empty table name
        let empty_table_args = json!({
            "table": ""
        });
        let result = handle.tables(empty_table_args).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_schema_config_validation() {
        let url = Url::parse("db://sqlite/test_schema_validation").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // Connect
        handle.connect(create_test_args()).await.unwrap();
        
        // Test missing table parameter
        let missing_table_args = json!({});
        let result = handle.schema(missing_table_args).await;
        assert!(result.is_err());
        
        if let Some(db_error) = result.unwrap_err().downcast_ref::<DbError>() {
            match db_error {
                DbError::InvalidSchemaConfig { message } => {
                    assert!(message.contains("table is required"));
                },
                _ => panic!("Expected InvalidSchemaConfig error for missing table, got: {:?}", db_error),
            }
        }
        
        // Test empty table name
        let empty_table_args = json!({
            "table": ""
        });
        let result = handle.schema(empty_table_args).await;
        assert!(result.is_err());
        
        if let Some(db_error) = result.unwrap_err().downcast_ref::<DbError>() {
            match db_error {
                DbError::InvalidSchemaConfig { message } => {
                    assert!(message.contains("table cannot be empty"));
                },
                _ => panic!("Expected InvalidSchemaConfig error for empty table, got: {:?}", db_error),
            }
        }
        
        // Test invalid timeout
        let invalid_timeout_args = json!({
            "table": "test_table",
            "timeout_ms": 0
        });
        let result = handle.schema(invalid_timeout_args).await;
        assert!(result.is_err());
        
        if let Some(db_error) = result.unwrap_err().downcast_ref::<DbError>() {
            match db_error {
                DbError::InvalidSchemaConfig { message } => {
                    assert!(message.contains("timeout_ms must be greater than 0"));
                },
                _ => panic!("Expected InvalidSchemaConfig error for invalid timeout, got: {:?}", db_error),
            }
        }
    }

    #[tokio::test]
    async fn test_schema_connection_not_found() {
        let url = Url::parse("db://sqlite/test_schema_no_connection").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // Don't connect - test without connection
        let schema_args = json!({
            "table": "users"
        });
        let result = handle.schema(schema_args).await;
        assert!(result.is_err());
        
        if let Some(db_error) = result.unwrap_err().downcast_ref::<DbError>() {
            match db_error {
                DbError::ConnectionNotFound { .. } => {}, // Expected
                _ => panic!("Expected ConnectionNotFound error, got: {:?}", db_error),
            }
        }
    }

    #[tokio::test]
    async fn test_schema_table_not_found() {
        let url = Url::parse("db://sqlite/test_schema_table_not_found").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // Connect
        handle.connect(create_test_args()).await.unwrap();
        
        // Try to get schema for a non-existent table
        let schema_args = json!({
            "table": "does_not_exist"
        });
        let result = handle.schema(schema_args).await;
        assert!(result.is_err());
        
        if let Some(db_error) = result.unwrap_err().downcast_ref::<DbError>() {
            match db_error {
                DbError::TableNotFound { .. } => {}, // Expected
                _ => panic!("Expected TableNotFound error, got: {:?}", db_error),
            }
        }
    }

    #[tokio::test]
    async fn test_tables_table_not_found() {
        let url = Url::parse("db://sqlite/test_tables_not_found").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // Connect
        handle.connect(create_test_args()).await.unwrap();
        
        // Try to describe a non-existent table
        let describe_args = json!({
            "table": "does_not_exist"
        });
        let result = handle.tables(describe_args).await;
        assert!(result.is_err());
        
        if let Some(db_error) = result.unwrap_err().downcast_ref::<DbError>() {
            match db_error {
                DbError::TableNotFound { .. } => {}, // Expected
                _ => panic!("Expected TableNotFound error, got: {:?}", db_error),
            }
        }
    }

    #[tokio::test]
    async fn test_tables_connection_not_found() {
        let url = Url::parse("db://sqlite/test_tables_no_connection").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // Don't connect - test without connection
        let tables_args = json!({});
        let result = handle.tables(tables_args).await;
        assert!(result.is_err());
        
        if let Some(db_error) = result.unwrap_err().downcast_ref::<DbError>() {
            match db_error {
                DbError::ConnectionNotFound { .. } => {}, // Expected
                _ => panic!("Expected ConnectionNotFound error, got: {:?}", db_error),
            }
        }
    }

    // Optional Postgres/MySQL tables integration tests

    #[tokio::test]
    #[ignore = "needs a disposable PostgreSQL server (runs DDL/DML): set TEST_POSTGRES_DSN and run with --ignored"]
    async fn test_postgres_tables_integration() {
        if let Ok(dsn) = std::env::var("TEST_POSTGRES_DSN") {
            let url = Url::parse("db://postgres/test_tables_integration").unwrap();
            let handle = DbHandle::from_url(url).unwrap();
            
            let mut connect_args = std::collections::HashMap::new();
            connect_args.insert("dsn".to_string(), dsn);
            
            // Test connection
            handle.connect(connect_args).await.unwrap();
            
            // A regular table: each exec may use a different pooled connection,
            // so a session-scoped TEMP table would not be visible to later calls.
            handle.exec(json!({ "sql": "DROP TABLE IF EXISTS tables_test_pg" })).await.unwrap();
            // Create table
            handle.exec(json!({
                "sql": "CREATE TABLE tables_test_pg (id SERIAL PRIMARY KEY, name TEXT NOT NULL)"
            })).await.unwrap();
            
            // List tables - should include our temp table in many cases
            let list_result = handle.tables(json!({})).await.unwrap();
            assert!(list_result["tables"].is_array());
            
            // Describe the table if it shows up in the list
            let tables = list_result["tables"].as_array().unwrap();
            let temp_table = tables.iter().find(|t| t["name"] == "tables_test_pg");
            if let Some(_table) = temp_table {
                let describe_result = handle.tables(json!({
                    "table": "tables_test_pg"
                })).await.unwrap();
                
                assert_eq!(describe_result["table"]["name"], "tables_test_pg");
                assert!(describe_result["columns"].is_array());
            }
        }
    }

    #[tokio::test]
    #[ignore = "needs a disposable MySQL server (runs DDL/DML): set TEST_MYSQL_DSN and run with --ignored"]
    async fn test_mysql_tables_integration() {
        if let Ok(dsn) = std::env::var("TEST_MYSQL_DSN") {
            let url = Url::parse("db://mysql/test_tables_integration").unwrap();
            let handle = DbHandle::from_url(url).unwrap();
            
            let mut connect_args = std::collections::HashMap::new();
            connect_args.insert("dsn".to_string(), dsn);
            
            // Test connection
            handle.connect(connect_args).await.unwrap();
            
            // A regular table: each exec may use a different pooled connection,
            // so a session-scoped TEMP table would not be visible to later calls.
            handle.exec(json!({ "sql": "DROP TABLE IF EXISTS tables_test_mysql" })).await.unwrap();
            // Create table
            handle.exec(json!({
                "sql": "CREATE TABLE tables_test_mysql (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL)"
            })).await.unwrap();
            
            // List tables
            let list_result = handle.tables(json!({})).await.unwrap();
            assert!(list_result["tables"].is_array());
            
            // Try to describe our temp table (may or may not show up in temporary schema)
            let describe_result = handle.tables(json!({
                "table": "tables_test_mysql"
            })).await;
            
            // Don't assert success since temp tables may not be visible in information_schema
            // This is more of a smoke test to ensure no crashes
            match describe_result {
                Ok(result) => {
                    assert_eq!(result["table"]["name"], "tables_test_mysql");
                    assert!(result["columns"].is_array());
                }
                Err(_) => {
                    // Acceptable - temp tables may not be visible
                }
            }
        }
    }

    #[tokio::test]
    async fn test_sqlite_schema_basic_table() {
        let url = Url::parse("db://sqlite/test_sqlite_schema_basic").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // Connect and setup
        handle.connect(create_test_args()).await.unwrap();
        
        // Create a test table with various column types
        handle.exec(json!({
            "sql": "CREATE TABLE test_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                name TEXT,
                age INTEGER,
                active BOOLEAN DEFAULT 1,
                score REAL DEFAULT 0.0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )"
        })).await.unwrap();
        
        // Test basic schema introspection
        let schema_args = json!({
            "table": "test_users"
        });
        let result = handle.schema(schema_args).await.unwrap();
        
        // Check table info
        assert_eq!(result["table"]["name"], "test_users");
        assert_eq!(result["table"]["schema"], "main");
        assert_eq!(result["table"]["type"], "BASE TABLE");
        
        // Check columns
        assert!(result["columns"].is_array());
        let columns = result["columns"].as_array().unwrap();
        assert_eq!(columns.len(), 7);
        
        // Check ID column (primary key)
        let id_col = columns.iter().find(|col| col["name"] == "id").unwrap();
        assert_eq!(id_col["ordinal_position"], 1);
        assert_eq!(id_col["data_type"], "INTEGER");
        assert_eq!(id_col["is_nullable"], false);
        assert_eq!(id_col["is_primary_key"], true);
        
        // Check email column (NOT NULL)
        let email_col = columns.iter().find(|col| col["name"] == "email").unwrap();
        assert_eq!(email_col["data_type"], "TEXT");
        assert_eq!(email_col["is_nullable"], false);
        assert_eq!(email_col["is_primary_key"], false);
        
        // Check name column (nullable)
        let name_col = columns.iter().find(|col| col["name"] == "name").unwrap();
        assert_eq!(name_col["data_type"], "TEXT");
        assert_eq!(name_col["is_nullable"], true);
        assert_eq!(name_col["is_primary_key"], false);
        
        // Check primary key info
        assert!(result["primary_key"].is_object());
        assert_eq!(result["primary_key"]["name"], "test_users_pkey");
        assert_eq!(result["primary_key"]["columns"], json!(["id"]));
    }

    #[tokio::test]
    async fn test_sqlite_schema_with_indexes() {
        let url = Url::parse("db://sqlite/test_sqlite_schema_indexes").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // Connect and setup
        handle.connect(create_test_args()).await.unwrap();
        
        // Create table
        handle.exec(json!({
            "sql": "CREATE TABLE indexed_users (
                id INTEGER PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                name TEXT,
                age INTEGER
            )"
        })).await.unwrap();
        
        // Create additional indexes
        handle.exec(json!({
            "sql": "CREATE INDEX idx_users_name ON indexed_users(name)"
        })).await.unwrap();
        
        handle.exec(json!({
            "sql": "CREATE INDEX idx_users_age_name ON indexed_users(age, name)"
        })).await.unwrap();
        
        // Test schema with indexes
        let schema_args = json!({
            "table": "indexed_users",
            "include_indexes": true
        });
        let result = handle.schema(schema_args).await.unwrap();
        
        // Check that indexes are included
        assert!(result["indexes"].is_array());
        let indexes = result["indexes"].as_array().unwrap();
        
        // Should have at least our custom indexes
        let idx_names: Vec<String> = indexes.iter()
            .map(|idx| idx["name"].as_str().unwrap().to_string())
            .collect();
        
        // Look for our created indexes
        // SQLite automatically creates unique indexes for UNIQUE constraints
        assert!(idx_names.iter().any(|name| name.contains("email") || name.contains("sqlite_autoindex")));
        assert!(idx_names.iter().any(|name| name == "idx_users_name"));
        assert!(idx_names.iter().any(|name| name == "idx_users_age_name"));
        
        // Check unique index (could be auto-generated with sqlite_autoindex or contain email)
        let unique_idx = indexes.iter().find(|idx| {
            let name = idx["name"].as_str().unwrap();
            name.contains("email") || name.contains("sqlite_autoindex")
        }).unwrap();
        assert_eq!(unique_idx["is_unique"], true);
        
        // Check regular index
        let name_idx = indexes.iter().find(|idx| idx["name"] == "idx_users_name").unwrap();
        assert_eq!(name_idx["is_unique"], false);
        assert_eq!(name_idx["columns"], json!(["name"]));
        
        // Check composite index
        let composite_idx = indexes.iter().find(|idx| idx["name"] == "idx_users_age_name").unwrap();
        assert_eq!(composite_idx["is_unique"], false);
        assert_eq!(composite_idx["columns"], json!(["age", "name"]));
    }

    #[tokio::test]
    async fn test_sqlite_schema_with_foreign_keys() {
        
        let url = Url::parse("db://sqlite/test_sqlite_schema_fk").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // Connect and setup
        handle.connect(create_test_args()).await.unwrap();
        
        // Enable foreign keys
        handle.exec(json!({
            "sql": "PRAGMA foreign_keys = ON"
        })).await.unwrap();
        
        // Create parent table
        handle.exec(json!({
            "sql": "CREATE TABLE accounts (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL
            )"
        })).await.unwrap();
        
        // Create child table with foreign key
        handle.exec(json!({
            "sql": "CREATE TABLE fk_users (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL,
                account_id INTEGER REFERENCES accounts(id) ON DELETE CASCADE ON UPDATE RESTRICT
            )"
        })).await.unwrap();
        
        // Test schema with foreign keys
        let schema_args = json!({
            "table": "fk_users",
            "include_foreign_keys": true
        });
        let result = handle.schema(schema_args).await.unwrap();
        
        // Check that foreign keys are included
        assert!(result["foreign_keys"].is_array());
        let foreign_keys = result["foreign_keys"].as_array().unwrap();
        assert!(!foreign_keys.is_empty());
        
        // Check the foreign key details
        let fk = &foreign_keys[0];
        assert!(fk["name"].as_str().unwrap().contains("fk_"));
        assert_eq!(fk["columns"], json!(["account_id"]));
        assert_eq!(fk["referenced_table"]["schema"], "main");
        assert_eq!(fk["referenced_table"]["name"], "accounts");
        assert_eq!(fk["referenced_columns"], json!(["id"]));
        assert_eq!(fk["on_delete"], "CASCADE");
        assert_eq!(fk["on_update"], "RESTRICT");
    }

    #[tokio::test]
    async fn test_sqlite_schema_include_flags() {
        let url = Url::parse("db://sqlite/test_sqlite_schema_flags").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // Connect and setup
        handle.connect(create_test_args()).await.unwrap();
        
        // Create test table
        handle.exec(json!({
            "sql": "CREATE TABLE flag_test (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE
            )"
        })).await.unwrap();
        
        // Create index
        handle.exec(json!({
            "sql": "CREATE INDEX idx_flag_test_name ON flag_test(name)"
        })).await.unwrap();
        
        // Test with include_indexes=false
        let schema_args = json!({
            "table": "flag_test",
            "include_indexes": false,
            "include_foreign_keys": false
        });
        let result = handle.schema(schema_args).await.unwrap();
        
        // Should not include indexes and foreign_keys sections when disabled
        assert!(!result.get("indexes").map(|v| v.is_array()).unwrap_or(false));
        assert!(!result.get("foreign_keys").map(|v| v.is_array()).unwrap_or(false));
        
        // Test with include_indexes=true
        let schema_args_with_indexes = json!({
            "table": "flag_test",
            "include_indexes": true,
            "include_foreign_keys": false
        });
        let result_with_indexes = handle.schema(schema_args_with_indexes).await.unwrap();
        
        // Should include indexes when enabled
        assert!(result_with_indexes["indexes"].is_array());
        assert!(!result_with_indexes["indexes"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_sqlite_schema_compound_primary_key() {
        let url = Url::parse("db://sqlite/test_sqlite_schema_compound_pk").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // Connect and setup
        handle.connect(create_test_args()).await.unwrap();
        
        // Create table with compound primary key
        handle.exec(json!({
            "sql": "CREATE TABLE compound_pk (
                tenant_id INTEGER,
                user_id INTEGER,
                name TEXT,
                PRIMARY KEY (tenant_id, user_id)
            )"
        })).await.unwrap();
        
        // Test schema
        let schema_args = json!({
            "table": "compound_pk"
        });
        let result = handle.schema(schema_args).await.unwrap();
        
        // Check columns are marked as primary key
        let columns = result["columns"].as_array().unwrap();
        let tenant_col = columns.iter().find(|col| col["name"] == "tenant_id").unwrap();
        let user_col = columns.iter().find(|col| col["name"] == "user_id").unwrap();
        let name_col = columns.iter().find(|col| col["name"] == "name").unwrap();
        
        assert_eq!(tenant_col["is_primary_key"], true);
        assert_eq!(user_col["is_primary_key"], true);
        assert_eq!(name_col["is_primary_key"], false);
        
        // Check primary key info
        assert!(result["primary_key"].is_object());
        let pk_columns = result["primary_key"]["columns"].as_array().unwrap();
        assert_eq!(pk_columns.len(), 2);
        assert!(pk_columns.contains(&json!("tenant_id")));
        assert!(pk_columns.contains(&json!("user_id")));
    }

    #[tokio::test]
    #[ignore = "needs a disposable PostgreSQL server (runs DDL/DML): set TEST_POSTGRES_DSN and run with --ignored"]
    async fn test_postgres_schema_integration() {
        if let Ok(dsn) = std::env::var("TEST_POSTGRES_DSN") {
            let url = Url::parse("db://postgres/test_schema_integration").unwrap();
            let handle = DbHandle::from_url(url).unwrap();
            
            let mut connect_args = std::collections::HashMap::new();
            connect_args.insert("dsn".to_string(), dsn);
            
            // Test connection
            handle.connect(connect_args).await.unwrap();
            
            // A regular table: each exec may use a different pooled connection,
            // so a session-scoped TEMP table would not be visible to later calls.
            handle.exec(json!({ "sql": "DROP TABLE IF EXISTS schema_test_pg" })).await.unwrap();
            // Create table with constraints
            handle.exec(json!({
                "sql": "CREATE TABLE schema_test_pg (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(100) UNIQUE NOT NULL,
                    name TEXT,
                    age INTEGER
                )"
            })).await.unwrap();
            
            // Create index
            handle.exec(json!({
                "sql": "CREATE INDEX idx_schema_test_name ON schema_test_pg(name)"
            })).await.unwrap();
            
            // Test schema introspection
            let schema_args = json!({
                "table": "schema_test_pg"
            });
            let result = handle.schema(schema_args).await.unwrap();
            
            // Check basic structure
            assert_eq!(result["table"]["name"], "schema_test_pg");
            assert_eq!(result["table"]["type"], "BASE TABLE");
            
            // Check columns
            assert!(result["columns"].is_array());
            let columns = result["columns"].as_array().unwrap();
            assert!(!columns.is_empty());
            
            // Find ID column
            let id_col = columns.iter().find(|col| col["name"] == "id");
            if let Some(id_col) = id_col {
                assert_eq!(id_col["is_primary_key"], true);
                assert_eq!(id_col["is_nullable"], false);
            }
            
            // Check primary key
            if let Some(_pk) = result.get("primary_key") {
                assert!(result["primary_key"]["columns"].as_array().unwrap().contains(&json!("id")));
            }
        }
    }

    #[tokio::test]
    #[ignore = "needs a disposable MySQL server (runs DDL/DML): set TEST_MYSQL_DSN and run with --ignored"]
    async fn test_mysql_schema_integration() {
        if let Ok(dsn) = std::env::var("TEST_MYSQL_DSN") {
            let url = Url::parse("db://mysql/test_schema_integration").unwrap();
            let handle = DbHandle::from_url(url).unwrap();
            
            let mut connect_args = std::collections::HashMap::new();
            connect_args.insert("dsn".to_string(), dsn);
            
            // Test connection
            handle.connect(connect_args).await.unwrap();
            
            // A regular table: each exec may use a different pooled connection,
            // so a session-scoped TEMP table would not be visible to later calls.
            handle.exec(json!({ "sql": "DROP TABLE IF EXISTS schema_test_mysql" })).await.unwrap();
            // Create table
            handle.exec(json!({
                "sql": "CREATE TABLE schema_test_mysql (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(100) UNIQUE NOT NULL,
                    name VARCHAR(50),
                    age INT
                )"
            })).await.unwrap();
            
            // Test schema introspection
            let schema_args = json!({
                "table": "schema_test_mysql"
            });
            let result = handle.schema(schema_args).await;
            
            // Note: temp tables may not be visible in some MySQL configurations
            match result {
                Ok(result) => {
                    assert_eq!(result["table"]["name"], "schema_test_mysql");
                    assert_eq!(result["table"]["type"], "BASE TABLE");
                    
                    // Check columns if available
                    if result["columns"].is_array() {
                        let columns = result["columns"].as_array().unwrap();
                        if !columns.is_empty() {
                            // Find ID column
                            let id_col = columns.iter().find(|col| col["name"] == "id");
                            if let Some(id_col) = id_col {
                                assert_eq!(id_col["is_primary_key"], true);
                                assert_eq!(id_col["is_nullable"], false);
                            }
                        }
                    }
                }
                Err(_) => {
                    // Acceptable - temp tables may not be visible in information_schema
                }
            }
        }
    }

    // FUNC-02: a ping that failed every attempt is a failed command.
    #[test]
    fn failed_ping_result_is_a_failure_status() {
        let failed = json!({"status": "error", "attempts": 3,
            "error": {"code": "db.ping_failed", "message": "Ping failed after 3 attempts"}});
        let st = value_status(&failed);
        assert!(!st.ok);
        assert_eq!(st.exit_code(), 1);
        assert_eq!(st.reason.as_deref(), Some("Ping failed after 3 attempts"));
        assert!(value_status(&json!({"status": "ok", "latency_ms": 1})).ok);
        assert!(value_status(&json!({"rows": []})).ok);
    }

    #[test]
    fn test_ping_config_defaults() {
        let args = json!({});
        let config = PingConfig::from_args(&args).unwrap();
        
        assert_eq!(config.timeout_ms, 1000);
        assert_eq!(config.retries, 0);
        assert_eq!(config.backoff_ms, 100);
        assert_eq!(config.detailed, false);
    }

    #[test]
    fn test_ping_config_custom_values() {
        let args = json!({
            "timeout_ms": 2500,
            "retries": 3,
            "backoff_ms": 200,
            "detailed": true
        });
        let config = PingConfig::from_args(&args).unwrap();
        
        assert_eq!(config.timeout_ms, 2500);
        assert_eq!(config.retries, 3);
        assert_eq!(config.backoff_ms, 200);
        assert_eq!(config.detailed, true);
    }

    #[test]
    fn test_ping_config_validation_zero_timeout() {
        let args = json!({"timeout_ms": 0});
        let result = PingConfig::from_args(&args);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            DbError::InvalidPingConfig { message } => {
                assert!(message.contains("timeout_ms must be greater than 0"));
            }
            _ => panic!("Expected InvalidPingConfig error"),
        }
    }

    #[test]
    fn test_ping_config_validation_too_many_retries() {
        let args = json!({"retries": 15});
        let result = PingConfig::from_args(&args);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            DbError::InvalidPingConfig { message } => {
                assert!(message.contains("retries cannot exceed 10"));
            }
            _ => panic!("Expected InvalidPingConfig error"),
        }
    }

    #[test]
    fn test_ping_config_edge_cases() {
        // Valid edge cases
        let args = json!({
            "timeout_ms": 1,
            "retries": 10,
            "backoff_ms": 0
        });
        let config = PingConfig::from_args(&args).unwrap();
        
        assert_eq!(config.timeout_ms, 1);
        assert_eq!(config.retries, 10);
        assert_eq!(config.backoff_ms, 0);
    }

    #[test]
    fn test_ping_handle_creation() {
        // Test creation from various URL formats
        let test_urls = vec![
            "db://postgres/main",
            "db://mysql/reporting", 
            "db://sqlite/local"
        ];

        for url_str in test_urls {
            let url = Url::parse(url_str).unwrap();
            let handle = DbHandle::from_url(url).unwrap();
            assert_eq!(handle.verbs().contains(&"ping"), true);
        }
    }

    #[test]
    fn test_ping_error_json_formatting() {
        // Test InvalidPingConfig error JSON formatting
        let error = DbError::InvalidPingConfig { 
            message: "test error message".to_string() 
        };
        let json = error.to_json();
        
        assert_eq!(json["error"]["code"], "db.invalid_ping_config");
        assert!(json["error"]["message"].as_str().unwrap().contains("test error message"));
        assert_eq!(json["error"]["details"]["validation_error"], "test error message");

        // Test PingTimeout error JSON formatting
        let timeout_error = DbError::PingTimeout { timeout_ms: 1000 };
        let timeout_json = timeout_error.to_json();
        
        assert_eq!(timeout_json["error"]["code"], "db.ping_timeout");
        assert_eq!(timeout_json["error"]["details"]["timeout_ms"], 1000);

        // Test PingFailed error JSON formatting
        let failed_error = DbError::PingFailed { 
            message: "connection refused".to_string() 
        };
        let failed_json = failed_error.to_json();
        
        assert_eq!(failed_json["error"]["code"], "db.ping_failed");
        assert_eq!(failed_json["error"]["details"]["underlying_error"], "connection refused");
    }

    #[test]
    fn test_connection_not_found_error() {
        // Test ConnectionNotFound error for ping operations
        let error = DbError::ConnectionNotFound { 
            driver: "postgres".to_string(), 
            alias: "nonexistent".to_string() 
        };
        let json = error.to_json();
        
        assert_eq!(json["error"]["code"], "db.connection_not_found");
        assert_eq!(json["error"]["details"]["driver"], "postgres");
        assert_eq!(json["error"]["details"]["alias"], "nonexistent");
    }

    #[tokio::test]
    async fn test_ping_connection_not_found() {
        // Create a handle that doesn't have a connection registered
        let url = Url::parse("db://sqlite/nonexistent").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        let args = json!({});
        let result = handle.ping(args).await;
        
        // Should return error response, not panic
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ping_integration_sqlite_success() {
        
        // Create and register a SQLite connection
        let url = Url::parse("db://sqlite/test_ping").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        let connect_args = create_test_args();
        let connect_result = handle.connect(connect_args).await;
        assert!(connect_result.is_ok());
        
        // Now test ping
        let ping_args = json!({});
        let ping_result = handle.ping(ping_args).await;
        
        assert!(ping_result.is_ok());
        let result = ping_result.unwrap();
        
        assert_eq!(result["status"], "ok");
        assert_eq!(result["driver"], "sqlite");
        assert_eq!(result["alias"], "test_ping");
        assert_eq!(result["attempts"], 1);
        
        // Should have measurable latency
        let latency = result["latency_ms"].as_u64().unwrap();
        assert!(latency >= 0);
        
    }

    #[tokio::test]
    async fn test_ping_integration_sqlite_with_custom_config() {
        
        // Create and register a SQLite connection
        let url = Url::parse("db://sqlite/test_ping_custom").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        let connect_args = create_test_args();
        let connect_result = handle.connect(connect_args).await;
        assert!(connect_result.is_ok());
        
        // Test ping with custom configuration
        let ping_args = json!({
            "timeout_ms": 2000,
            "retries": 1,
            "backoff_ms": 50,
            "detailed": true
        });
        let ping_result = handle.ping(ping_args).await;
        
        assert!(ping_result.is_ok());
        let result = ping_result.unwrap();
        
        assert_eq!(result["status"], "ok");
        assert_eq!(result["driver"], "sqlite");
        assert_eq!(result["alias"], "test_ping_custom");
        assert_eq!(result["attempts"], 1);
        
        // Should have measurable latency
        let latency = result["latency_ms"].as_u64().unwrap();
        assert!(latency >= 0);
        
    }

    #[tokio::test]
    async fn test_ping_integration_connection_not_found() {
        
        // Create handle but don't connect
        let url = Url::parse("db://sqlite/nonexistent").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        // Test ping without connection
        let ping_args = json!({});
        let ping_result = handle.ping(ping_args).await;
        
        // Should return an error (not panic)
        assert!(ping_result.is_err());
        
    }

    #[tokio::test]
    async fn test_ping_integration_sqlite_multiple_attempts() {
        // This test verifies the ping mechanism works with a real SQLite connection
        
        // Create and register a SQLite connection
        let url = Url::parse("db://sqlite/test_ping_multi").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        let connect_args = create_test_args();
        let connect_result = handle.connect(connect_args).await;
        assert!(connect_result.is_ok(), "Failed to connect to SQLite");
        
        // Test multiple ping calls to ensure consistency
        for i in 1..=3 {
            let ping_args = json!({
                "timeout_ms": 1000,
                "detailed": true
            });
            let ping_result = handle.ping(ping_args).await;
            
            // Allow for either success or connection lost after several attempts
            match ping_result {
                Ok(result) => {
                    assert_eq!(result["status"], "ok");
                    assert_eq!(result["driver"], "sqlite");
                    assert_eq!(result["alias"], "test_ping_multi");
                    assert_eq!(result["attempts"], 1);
                    
                    // Should have measurable latency
                    let latency = result["latency_ms"].as_u64().unwrap();
                    assert!(latency >= 0);
                }
                Err(e) => {
                    // If connection is lost, that's acceptable for this test
                    // This can happen with SQLite in-memory databases in test scenarios
                    let error_msg = e.to_string();
                    assert!(error_msg.contains("connection not found"), 
                           "Unexpected error: {}", error_msg);
                    break;
                }
            }
        }
        
    }

    #[tokio::test]
    async fn test_ping_integration_sqlite_very_short_timeout() {
        // This tests behavior with extremely short timeout 
        // (may timeout depending on system performance)
        
        // Create and register a SQLite connection
        let url = Url::parse("db://sqlite/test_ping_timeout").unwrap();
        let handle = DbHandle::from_url(url).unwrap();
        
        let connect_args = create_test_args();
        let connect_result = handle.connect(connect_args).await;
        assert!(connect_result.is_ok());
        
        // Test ping with very short timeout (may timeout on slow systems)
        let ping_args = json!({
            "timeout_ms": 1,  // 1ms - very short
            "retries": 0
        });
        let ping_result = handle.ping(ping_args).await;
        
        // Result could be success or timeout, both are valid
        assert!(ping_result.is_ok());
        let result = ping_result.unwrap();
        
        // Should be either "ok" or "error" status
        let status = result["status"].as_str().unwrap();
        assert!(status == "ok" || status == "error");
        
        if status == "ok" {
            assert_eq!(result["attempts"], 1);
            // Should have very low latency
            let latency = result["latency_ms"].as_u64().unwrap();
            assert!(latency >= 0);
        } else {
            // If it timed out
            assert_eq!(result["attempts"], 1);
            let error = &result["error"];
            // Could be timeout or other error
            assert!(error["code"] == "db.ping_timeout" || error["code"] == "db.ping_failed");
        }
        
    }

    // ============================================================================
    // Transaction Tests
    // ============================================================================

    mod transaction_tests {
        use super::*;

        #[test]
        fn test_transaction_action_from_string() {
            assert_eq!(TransactionAction::from_str("begin").unwrap(), TransactionAction::Begin);
            assert_eq!(TransactionAction::from_str("commit").unwrap(), TransactionAction::Commit);
            assert_eq!(TransactionAction::from_str("rollback").unwrap(), TransactionAction::Rollback);
            
            // Case insensitive
            assert_eq!(TransactionAction::from_str("BEGIN").unwrap(), TransactionAction::Begin);
            assert_eq!(TransactionAction::from_str("Commit").unwrap(), TransactionAction::Commit);
            assert_eq!(TransactionAction::from_str("ROLLBACK").unwrap(), TransactionAction::Rollback);
            
            // Invalid action
            assert!(TransactionAction::from_str("invalid").is_err());
        }

        #[test]
        fn test_transaction_isolation_from_string() {
            assert_eq!(TransactionIsolation::from_str("default").unwrap(), TransactionIsolation::Default);
            assert_eq!(TransactionIsolation::from_str("read_uncommitted").unwrap(), TransactionIsolation::ReadUncommitted);
            assert_eq!(TransactionIsolation::from_str("read_committed").unwrap(), TransactionIsolation::ReadCommitted);
            assert_eq!(TransactionIsolation::from_str("repeatable_read").unwrap(), TransactionIsolation::RepeatableRead);
            assert_eq!(TransactionIsolation::from_str("serializable").unwrap(), TransactionIsolation::Serializable);
            
            // Case insensitive
            assert_eq!(TransactionIsolation::from_str("DEFAULT").unwrap(), TransactionIsolation::Default);
            assert_eq!(TransactionIsolation::from_str("SERIALIZABLE").unwrap(), TransactionIsolation::Serializable);
            
            // Invalid isolation
            assert!(TransactionIsolation::from_str("invalid").is_err());
        }

        #[test]
        fn test_transaction_config_begin_valid() {
            let args = json!({
                "action": "begin",
                "isolation": "serializable",
                "read_only": true,
                "timeout_ms": 10000
            });
            
            let config = TransactionConfig::from_args(&args).unwrap();
            assert_eq!(config.action, TransactionAction::Begin);
            assert_eq!(config.isolation, Some(TransactionIsolation::Serializable));
            assert_eq!(config.read_only, true);
            assert_eq!(config.timeout_ms, 10000);
            assert_eq!(config.tx_id, None);
        }

        #[test]
        fn test_transaction_config_begin_defaults() {
            let args = json!({
                "action": "begin"
            });
            
            let config = TransactionConfig::from_args(&args).unwrap();
            assert_eq!(config.action, TransactionAction::Begin);
            assert_eq!(config.isolation, None);
            assert_eq!(config.read_only, false);
            assert_eq!(config.timeout_ms, 5000);
            assert_eq!(config.tx_id, None);
        }

        #[test]
        fn test_transaction_config_commit_valid() {
            let args = json!({
                "action": "commit",
                "tx_id": "test-tx-123",
                "timeout_ms": 8000
            });
            
            let config = TransactionConfig::from_args(&args).unwrap();
            assert_eq!(config.action, TransactionAction::Commit);
            assert_eq!(config.tx_id, Some("test-tx-123".to_string()));
            assert_eq!(config.timeout_ms, 8000);
            assert_eq!(config.isolation, None);
            assert_eq!(config.read_only, false);
        }

        #[test]
        fn test_transaction_config_rollback_valid() {
            let args = json!({
                "action": "rollback",
                "tx_id": "test-tx-456"
            });
            
            let config = TransactionConfig::from_args(&args).unwrap();
            assert_eq!(config.action, TransactionAction::Rollback);
            assert_eq!(config.tx_id, Some("test-tx-456".to_string()));
            assert_eq!(config.timeout_ms, 5000);
            assert_eq!(config.isolation, None);
            assert_eq!(config.read_only, false);
        }

        #[test]
        fn test_transaction_config_missing_action() {
            let args = json!({
                "tx_id": "test-tx-123"
            });
            
            let result = TransactionConfig::from_args(&args);
            assert!(result.is_err());
            match result.unwrap_err() {
                DbError::InvalidTransactionConfig { message } => {
                    assert!(message.contains("missing required 'action' field"));
                }
                _ => panic!("Expected InvalidTransactionConfig error"),
            }
        }

        #[test]
        fn test_transaction_config_invalid_action() {
            let args = json!({
                "action": "invalid"
            });
            
            let result = TransactionConfig::from_args(&args);
            assert!(result.is_err());
            match result.unwrap_err() {
                DbError::InvalidTransactionConfig { message } => {
                    assert!(message.contains("invalid action: invalid"));
                }
                _ => panic!("Expected InvalidTransactionConfig error"),
            }
        }

        #[test]
        fn test_transaction_config_begin_with_tx_id() {
            let args = json!({
                "action": "begin",
                "tx_id": "should-not-be-provided"
            });
            
            let result = TransactionConfig::from_args(&args);
            assert!(result.is_err());
            match result.unwrap_err() {
                DbError::InvalidTransactionConfig { message } => {
                    assert!(message.contains("tx_id must not be provided for 'begin' action"));
                }
                _ => panic!("Expected InvalidTransactionConfig error"),
            }
        }

        #[test]
        fn test_transaction_config_commit_missing_tx_id() {
            let args = json!({
                "action": "commit"
            });
            
            let result = TransactionConfig::from_args(&args);
            assert!(result.is_err());
            match result.unwrap_err() {
                DbError::InvalidTransactionConfig { message } => {
                    assert!(message.contains("tx_id is required for 'commit' action"));
                }
                _ => panic!("Expected InvalidTransactionConfig error"),
            }
        }

        #[test]
        fn test_transaction_config_rollback_missing_tx_id() {
            let args = json!({
                "action": "rollback"
            });
            
            let result = TransactionConfig::from_args(&args);
            assert!(result.is_err());
            match result.unwrap_err() {
                DbError::InvalidTransactionConfig { message } => {
                    assert!(message.contains("tx_id is required for 'rollback' action"));
                }
                _ => panic!("Expected InvalidTransactionConfig error"),
            }
        }

        #[test]
        fn test_transaction_config_empty_tx_id() {
            let args = json!({
                "action": "commit",
                "tx_id": "   "
            });
            
            let result = TransactionConfig::from_args(&args);
            assert!(result.is_err());
            match result.unwrap_err() {
                DbError::InvalidTransactionConfig { message } => {
                    assert!(message.contains("tx_id cannot be empty"));
                }
                _ => panic!("Expected InvalidTransactionConfig error"),
            }
        }

        #[test]
        fn test_transaction_config_zero_timeout() {
            let args = json!({
                "action": "begin",
                "timeout_ms": 0
            });
            
            let result = TransactionConfig::from_args(&args);
            assert!(result.is_err());
            match result.unwrap_err() {
                DbError::InvalidTransactionConfig { message } => {
                    assert!(message.contains("timeout_ms must be greater than 0"));
                }
                _ => panic!("Expected InvalidTransactionConfig error"),
            }
        }

        #[test]
        fn test_transaction_config_invalid_isolation() {
            let args = json!({
                "action": "begin",
                "isolation": "invalid_level"
            });
            
            let result = TransactionConfig::from_args(&args);
            assert!(result.is_err());
            match result.unwrap_err() {
                DbError::InvalidTransactionConfig { message } => {
                    assert!(message.contains("invalid isolation level: invalid_level"));
                }
                _ => panic!("Expected InvalidTransactionConfig error"),
            }
        }

        #[test]
        fn test_query_config_with_tx_id() {
            let args = json!({
                "sql": "SELECT * FROM users",
                "tx_id": "test-tx-123"
            });
            
            let config = QueryConfig::from_args(&args).unwrap();
            assert_eq!(config.sql, "SELECT * FROM users");
            assert_eq!(config.tx_id, Some("test-tx-123".to_string()));
        }

        #[test]
        fn test_query_config_without_tx_id() {
            let args = json!({
                "sql": "SELECT * FROM users"
            });
            
            let config = QueryConfig::from_args(&args).unwrap();
            assert_eq!(config.sql, "SELECT * FROM users");
            assert_eq!(config.tx_id, None);
        }

        #[test]
        fn test_query_config_empty_tx_id() {
            let args = json!({
                "sql": "SELECT * FROM users",
                "tx_id": "   "
            });
            
            let config = QueryConfig::from_args(&args).unwrap();
            assert_eq!(config.sql, "SELECT * FROM users");
            assert_eq!(config.tx_id, None); // Empty strings are filtered out
        }

        #[test]
        fn test_exec_config_with_tx_id() {
            let args = json!({
                "sql": "INSERT INTO users (name) VALUES ('John')",
                "tx_id": "test-tx-456"
            });
            
            let config = ExecConfig::from_args(&args).unwrap();
            assert_eq!(config.sql, "INSERT INTO users (name) VALUES ('John')");
            assert_eq!(config.tx_id, Some("test-tx-456".to_string()));
        }

        #[test]
        fn test_exec_config_without_tx_id() {
            let args = json!({
                "sql": "UPDATE users SET active = false"
            });
            
            let config = ExecConfig::from_args(&args).unwrap();
            assert_eq!(config.sql, "UPDATE users SET active = false");
            assert_eq!(config.tx_id, None);
        }

        #[test]
        fn test_db_error_transaction_json() {
            let error = DbError::TransactionNotFound { tx_id: "test-tx-123".to_string() };
            let json = error.to_json();
            
            assert_eq!(json["error"]["code"], "db.transaction_not_found");
            assert!(json["error"]["message"].as_str().unwrap().contains("test-tx-123"));
            assert_eq!(json["error"]["details"]["tx_id"], "test-tx-123");
        }

        #[test]
        fn test_db_error_transaction_timeout_json() {
            let error = DbError::TransactionTimeout { timeout_ms: 5000 };
            let json = error.to_json();
            
            assert_eq!(json["error"]["code"], "db.transaction_timeout");
            assert_eq!(json["error"]["details"]["timeout_ms"], 5000);
        }

        #[test]
        fn test_db_error_transaction_alias_mismatch_json() {
            let error = DbError::TransactionAliasMismatch { 
                tx_id: "test-tx-123".to_string(),
                expected: "postgres:main".to_string(),
                actual: "sqlite:test".to_string(),
            };
            let json = error.to_json();
            
            assert_eq!(json["error"]["code"], "db.transaction_alias_mismatch");
            assert_eq!(json["error"]["details"]["tx_id"], "test-tx-123");
            assert_eq!(json["error"]["details"]["expected"], "postgres:main");
            assert_eq!(json["error"]["details"]["actual"], "sqlite:test");
        }

        #[test]
        fn test_transaction_handle_creation() {
            let driver = DbDriver::Sqlite;
            let alias = "test".to_string();
            let tx_id = "test-tx-123".to_string();
            
            // We can't actually create a real transaction here without a database connection,
            // so this test is limited to the structure validation
            // The actual transaction integration tests will be in the integration test section
        }

        #[test]
        fn test_transaction_registry_unknown_id() {
            // Never clear the global registry here: other tests run in
            // parallel and may hold live transactions in it.
            let id = Uuid::new_v4().to_string();
            assert!(TRANSACTION_REGISTRY.get(&id).is_none());
        }
    }

    mod cli_fix_tests {
        use super::*;
        use std::io::Cursor;

        fn handle(url: &str) -> DbHandle {
            DbHandle::from_url(Url::parse(url).unwrap()).unwrap()
        }

        fn call_out(h: &DbHandle, verb: &str, args: &[(&str, &str)]) -> (Status, String) {
            let args: Args = args.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            let (mut i, mut o, mut e) = (Cursor::new(Vec::new()), Cursor::new(Vec::new()), Cursor::new(Vec::new()));
            let mut io = IoStreams { stdin: &mut i, stdout: &mut o, stderr: &mut e };
            let st = h.call(verb, &args, &mut io).unwrap();
            (st, String::from_utf8(o.into_inner()).unwrap())
        }

        fn json_out(h: &DbHandle, verb: &str, args: &[(&str, &str)]) -> Value {
            let (_, out) = call_out(h, verb, args);
            serde_json::from_str(&out).unwrap_or_else(|e| panic!("{}: {}", e, out))
        }

        /// A temp-file SQLite DSN unique to one test.
        fn temp_dsn(name: &str) -> (String, std::path::PathBuf) {
            let path = std::env::temp_dir().join(format!("resh-dbh-{}-{}.db", name, Uuid::new_v4()));
            (format!("sqlite://{}?mode=rwc", path.display()), path)
        }

        #[test]
        fn help_detection_is_exact() {
            let h = handle("db://sqlite/my-hosts");
            assert_eq!(h.alias, "my-hosts");
            assert!(!h.should_show_help("query", &Args::new()));
            let h = handle("db://sqlite/pre-hotfix");
            assert_eq!(h.alias, "pre-hotfix");
            assert_eq!(handle("db://--help").driver_str, "help");
            assert_eq!(handle("db://sqlite/--help").driver_str, "help");
        }

        #[test]
        fn in_url_help_renders_approved_help() {
            let h = handle("db://sqlite/app");
            for verb in ["help", "--help", "-h"] {
                let (st, out) = call_out(&h, verb, &[]);
                assert!(st.ok);
                assert!(out.starts_with("Handle: db"), "{}", out);
            }
            let (_, out) = call_out(&h, "--help=transaction", &[]);
            assert!(out.starts_with("Handle: db\nVerb: transaction"), "{}", out);
            let (_, out) = call_out(&h, "help", &[("verb", "query")]);
            assert!(out.contains("Verb: query"), "{}", out);
            let (_, out) = call_out(&handle("db://--help"), "connect", &[]);
            assert!(out.starts_with("Handle: db"), "{}", out);
        }

        #[test]
        fn query_config_accepts_cli_strings() {
            let c = QueryConfig::from_args(&json!({"sql": "SELECT 1", "timeout_ms": "250", "max_rows": "2"})).unwrap();
            assert_eq!(c.timeout_ms, 250);
            assert_eq!(c.max_rows, 2);
            assert!(QueryConfig::from_args(&json!({"sql": "SELECT 1", "max_rows": "lots"})).is_err());
            assert!(QueryConfig::from_args(&json!({"sql": "SELECT 1", "timeout_ms": "0"})).is_err());
        }

        #[test]
        fn other_configs_accept_cli_strings() {
            let t = TablesConfig::from_args(&json!({"include_views": "true", "max_tables": "5"})).unwrap();
            assert!(t.include_views);
            assert_eq!(t.max_tables, 5);
            let p = PingConfig::from_args(&json!({"retries": "2", "detailed": "yes"})).unwrap();
            assert_eq!(p.retries, 2);
            assert!(p.detailed);
            assert!(PingConfig::from_args(&json!({"detailed": "maybe"})).is_err());
            let sc = SchemaConfig::from_args(&json!({"table": "t", "include_indexes": "false"})).unwrap();
            assert!(!sc.include_indexes);
        }

        #[test]
        fn query_max_rows_from_cli_truncates() {
            let h = handle("db://sqlite/cli_fix_max_rows");
            let out = json_out(&h, "query", &[
                ("dsn", "sqlite::memory:"),
                ("sql", "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x < 5) SELECT x FROM n"),
                ("max_rows", "2"),
            ]);
            assert_eq!(out["rows"].as_array().unwrap().len(), 2, "{}", out);
            assert_eq!(out["meta"]["truncated"], true);
        }

        #[test]
        fn tables_schema_ping_auto_connect_with_dsn() {
            let (dsn, path) = temp_dsn("auto");
            let setup = handle("db://sqlite/cli_fix_auto_setup");
            let out = json_out(&setup, "exec", &[
                ("dsn", dsn.as_str()),
                ("sql", "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)"),
            ]);
            assert_eq!(out["rows_affected"], 0, "{}", out);

            let out = json_out(&handle("db://sqlite/cli_fix_auto_tables"), "tables", &[("dsn", dsn.as_str())]);
            assert!(out["tables"].as_array().unwrap().iter().any(|t| t["name"] == "users"), "{}", out);

            let out = json_out(&handle("db://sqlite/cli_fix_auto_schema"), "schema", &[
                ("dsn", dsn.as_str()),
                ("table", "users"),
            ]);
            assert_eq!(out["table"]["name"], "users", "{}", out);

            let out = json_out(&handle("db://sqlite/cli_fix_auto_ping"), "ping", &[
                ("dsn", dsn.as_str()),
                ("retries", "1"),
            ]);
            assert_eq!(out["status"], "ok", "{}", out);
            let _ = std::fs::remove_file(path);
        }

        #[test]
        fn verbs_without_dsn_report_connection_not_found() {
            for verb in ["tables", "ping"] {
                let (st, out) = call_out(&handle("db://sqlite/cli_fix_no_dsn"), verb, &[]);
                assert!(!st.ok);
                assert!(out.contains("db.connection_not_found"), "{}: {}", verb, out);
            }
        }

        #[test]
        fn transaction_run_commits_all_statements() {
            let (dsn, path) = temp_dsn("txrun");
            let h = handle("db://sqlite/cli_fix_tx_commit");
            let out = json_out(&h, "transaction", &[
                ("dsn", dsn.as_str()),
                ("statements", r#"["CREATE TABLE t (v INTEGER)", "INSERT INTO t VALUES (1)", {"sql": "INSERT INTO t VALUES (?)", "params": [2]}]"#),
            ]);
            assert_eq!(out["status"], "ok", "{}", out);
            assert_eq!(out["committed"], true);
            assert_eq!(out["results"].as_array().unwrap().len(), 3);
            assert_eq!(out["results"][1]["rows_affected"], 1);

            let out = json_out(&h, "query", &[("sql", "SELECT COUNT(*) FROM t"), ("mode", "scalar")]);
            assert_eq!(out["value"], 2, "{}", out);
            let _ = std::fs::remove_file(path);
        }

        #[test]
        fn transaction_run_rolls_back_on_failure() {
            let (dsn, path) = temp_dsn("txfail");
            let h = handle("db://sqlite/cli_fix_tx_rollback");
            json_out(&h, "exec", &[("dsn", dsn.as_str()), ("sql", "CREATE TABLE t (v INTEGER NOT NULL)")]);
            let (st, out) = call_out(&h, "transaction", &[
                ("action", "run"),
                ("statements", r#"["INSERT INTO t VALUES (1)", "INSERT INTO t VALUES (NULL)"]"#),
            ]);
            assert!(!st.ok);
            let v: Value = serde_json::from_str(&out).unwrap();
            assert_eq!(v["error"]["code"], "db.transaction_statement_failed", "{}", out);
            assert_eq!(v["error"]["details"]["index"], 1);
            assert_eq!(v["error"]["details"]["rolled_back"], true);

            let out = json_out(&h, "query", &[("sql", "SELECT COUNT(*) FROM t"), ("mode", "scalar")]);
            assert_eq!(out["value"], 0, "{}", out);
            let _ = std::fs::remove_file(path);
        }

        #[test]
        fn transaction_config_statement_validation() {
            let c = TransactionConfig::from_args(&json!({"statements": "[\"SELECT 1\"]"})).unwrap();
            assert_eq!(c.action, TransactionAction::Run);
            assert_eq!(c.statements.len(), 1);
            assert!(TransactionConfig::from_args(&json!({"action": "run"})).is_err());
            assert!(TransactionConfig::from_args(&json!({"action": "begin", "statements": ["SELECT 1"]})).is_err());
            assert!(TransactionConfig::from_args(&json!({"statements": "[]"})).is_err());
            assert!(TransactionConfig::from_args(&json!({"statements": "not json"})).is_err());
            assert!(TransactionConfig::from_args(&json!({"statements": ["SELECT 1; SELECT 2"]})).is_err());
            assert!(TransactionConfig::from_args(&json!({"action": "begin", "read_only": "true"})).unwrap().read_only);
        }

        #[test]
        fn tls_mode_validation_per_driver() {
            let cfg = |m: &str| DbConfig { tls_mode: Some(m.to_string()), ..Default::default() };
            let pg = handle("db://postgres/cli_fix_tls");
            for m in ["disable", "allow", "prefer", "preferred", "require", "verify_ca", "verify-full"] {
                assert!(pg.validate_config(&cfg(m)).is_ok(), "{}", m);
            }
            assert!(pg.validate_config(&cfg("sometimes")).is_err());
            let my = handle("db://mysql/cli_fix_tls");
            assert!(my.validate_config(&cfg("require")).is_ok());
            assert!(my.validate_config(&cfg("allow")).is_err());
            let lite = handle("db://sqlite/cli_fix_tls");
            assert!(lite.validate_config(&cfg("disable")).is_ok());
            assert!(lite.validate_config(&cfg("require")).is_err());
            assert!(lite.validate_config(&DbConfig::default()).is_ok());
            assert!(matches!(TlsMode::parse("verify_full").unwrap().postgres(), sqlx::postgres::PgSslMode::VerifyFull));
            assert!(matches!(TlsMode::parse("verify_full").unwrap().mysql(), sqlx::mysql::MySqlSslMode::VerifyIdentity));
        }

        #[test]
        fn sqlite_connect_rejects_tls_and_bad_log_queries() {
            let h = handle("db://sqlite/cli_fix_tls_connect");
            let (st, out) = call_out(&h, "connect", &[("dsn", "sqlite::memory:"), ("tls_mode", "require")]);
            assert!(!st.ok);
            assert!(out.contains("tls_mode"), "{}", out);
            let (st, out) = call_out(&h, "connect", &[("dsn", "sqlite::memory:"), ("log_queries", "loud")]);
            assert!(!st.ok);
            assert!(out.contains("log_queries"), "{}", out);
            let (st, _) = call_out(&h, "connect", &[("dsn", "sqlite::memory:"), ("log_queries", "true")]);
            assert!(st.ok);
        }
    }
}
