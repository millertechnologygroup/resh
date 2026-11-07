//! `tables` and `schema`: catalog queries for each database. Table and
//! schema names are always bound as values; the one identifier that SQLite
//! needs in the SQL text (an attached database's name, for its
//! `sqlite_schema`) is quoted.

use super::DbError;
use super::args::{SchemaArgs, TablesArgs};
use super::conn::{Conn, Session};
use super::run::{Log, stmt_error};
use super::sql;
use serde_json::{Value, json};
use sqlx::Row;
use sqlx::mysql::MySqlConnection;
use sqlx::postgres::PgConnection;
use sqlx::sqlite::SqliteConnection;

fn failed(e: sqlx::Error) -> DbError {
    stmt_error("query_failed", e)
}

/// Column `i` of a catalog row; a type mismatch is an error, not a panic.
fn g<'r, T, R>(r: &'r R, i: usize) -> Result<T, DbError>
where
    R: Row,
    usize: sqlx::ColumnIndex<R>,
    T: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    r.try_get(i).map_err(failed)
}

/// A table found in the catalog.
struct Found {
    schema: String,
    name: String,
    kind: String,
    /// PostgreSQL: the table's oid.
    oid: i64,
}

impl Found {
    fn json(&self) -> Value {
        json!({"name": self.name, "schema": self.schema, "type": self.kind})
    }
}

fn not_found(table: &str, schema: Option<&str>, hint: &str) -> DbError {
    let where_ = match schema {
        Some(s) => format!(" in schema {s:?}"),
        None => String::new(),
    };
    DbError::new(
        "table_not_found",
        format!("no table or view named {table:?}{where_}{hint}"),
    )
    .with("table", json!(table))
}

/// Groups `(key, item)` rows, in order, into `(key, [items])`.
fn group<K: PartialEq + Clone, T>(rows: Vec<(K, T)>) -> Vec<(K, Vec<T>)> {
    let mut out: Vec<(K, Vec<T>)> = Vec::new();
    for (k, t) in rows {
        match out.last_mut() {
            Some((last, items)) if *last == k => items.push(t),
            _ => out.push((k, vec![t])),
        }
    }
    out
}

pub async fn tables(s: &mut Session, a: &TablesArgs, log: &mut Log<'_>) -> Result<Value, DbError> {
    let conn = &mut s.conn;
    let work = async {
        match &a.table {
            Some(table) => {
                let found = find(conn, table, a.schema.as_deref(), log).await?;
                let columns = columns(conn, &found, log).await?;
                Ok(json!({"table": found.json(), "columns": columns}))
            }
            None => list(conn, a, log).await,
        }
    };
    s.ctl.within("listing tables", work).await
}

pub async fn schema(s: &mut Session, a: &SchemaArgs, log: &mut Log<'_>) -> Result<Value, DbError> {
    let conn = &mut s.conn;
    let work = async {
        let found = find(conn, &a.table, a.schema.as_deref(), log).await?;
        let mut out = json!({
            "table": found.json(),
            "columns": columns(conn, &found, log).await?,
        });
        match conn {
            Conn::Pg(c) => pg_details(c, &found, a, &mut out, log).await?,
            Conn::My(c) => my_details(c, &found, a, &mut out, log).await?,
            Conn::Lite(c) => lite_details(c, &found, a, &mut out, log).await?,
        }
        Ok(out)
    };
    s.ctl.within("reading the schema", work).await
}

// --- listing -------------------------------------------------------------------

const PG_KIND: &str = "CASE c.relkind WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW' \
                       WHEN 'f' THEN 'FOREIGN TABLE' ELSE 'BASE TABLE' END";

async fn list(conn: &mut Conn, a: &TablesArgs, log: &mut Log<'_>) -> Result<Value, DbError> {
    let limit = a.max_tables as i64 + 1;
    let mut rows: Vec<(String, String, String)> = match conn {
        Conn::Pg(c) => {
            let mut kinds = vec!["r".to_string(), "p".to_string(), "f".to_string()];
            if a.include_views {
                kinds.extend(["v".to_string(), "m".to_string()]);
            }
            let q = format!(
                "SELECT n.nspname::text, c.relname::text, {PG_KIND} \
                 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                 WHERE c.relkind::text = ANY($1::text[]) \
                 AND ($2::text IS NULL OR n.nspname = $2) \
                 AND ($2::text IS NOT NULL OR $3 OR (n.nspname NOT IN \
                 ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\\_toast%' \
                 AND n.nspname NOT LIKE 'pg\\_temp\\_%')) \
                 ORDER BY 1, 2 LIMIT $4"
            );
            log.sql(&q);
            sqlx::query(&q)
                .bind(kinds)
                .bind(a.schema.as_deref())
                .bind(a.include_system)
                .bind(limit)
                .fetch_all(&mut *c)
                .await
                .map_err(failed)?
                .iter()
                .map(|r| -> Result<_, DbError> { Ok((g(r, 0)?, g(r, 1)?, g(r, 2)?)) })
                .collect::<Result<Vec<_>, DbError>>()?
        }
        Conn::My(c) => {
            let q = "SELECT CAST(table_schema AS CHAR), CAST(table_name AS CHAR), \
                     CAST(table_type AS CHAR) FROM information_schema.tables \
                     WHERE (table_type IN ('BASE TABLE', 'SYSTEM VERSIONED') \
                     OR (? AND table_type IN ('VIEW', 'SYSTEM VIEW'))) \
                     AND (table_schema = COALESCE(?, DATABASE()) OR (? IS NULL AND ? AND \
                     table_schema IN ('mysql', 'information_schema', 'performance_schema', \
                     'sys'))) ORDER BY 1, 2 LIMIT ?";
            log.sql(q);
            sqlx::query(q)
                .bind(a.include_views)
                .bind(a.schema.as_deref())
                .bind(a.schema.as_deref())
                .bind(a.include_system)
                .bind(limit)
                .fetch_all(&mut *c)
                .await
                .map_err(failed)?
                .iter()
                .map(|r| -> Result<_, DbError> { Ok((g(r, 0)?, g(r, 1)?, g(r, 2)?)) })
                .collect::<Result<Vec<_>, DbError>>()?
        }
        Conn::Lite(c) => {
            let q = "SELECT schema, name, type FROM pragma_table_list \
                     WHERE (type IN ('table', 'virtual') OR (? AND type = 'view')) \
                     AND (? IS NULL OR schema = ?) \
                     AND (? OR name NOT LIKE 'sqlite\\_%' ESCAPE '\\') \
                     ORDER BY 1, 2 LIMIT ?";
            log.sql(q);
            sqlx::query(q)
                .bind(a.include_views)
                .bind(a.schema.as_deref())
                .bind(a.schema.as_deref())
                .bind(a.include_system)
                .bind(limit)
                .fetch_all(&mut *c)
                .await
                .map_err(failed)?
                .iter()
                .map(|r| -> Result<_, DbError> {
                    Ok({
                        let t: String = g(r, 2)?;
                        (g(r, 0)?, g(r, 1)?, sqlite_kind(&t).to_string())
                    })
                })
                .collect::<Result<Vec<_>, DbError>>()?
        }
    };
    let truncated = rows.len() as u64 > a.max_tables;
    rows.truncate(a.max_tables as usize);
    let tables: Vec<Value> = rows
        .into_iter()
        .map(|(schema, name, kind)| json!({"name": name, "schema": schema, "type": kind}))
        .collect();
    Ok(json!({
        "tables": tables,
        "meta": {"count": tables.len(), "truncated": truncated},
    }))
}

fn sqlite_kind(t: &str) -> &'static str {
    match t {
        "view" => "VIEW",
        "virtual" => "VIRTUAL TABLE",
        _ => "BASE TABLE",
    }
}

// --- one table -------------------------------------------------------------------

async fn find(
    conn: &mut Conn,
    table: &str,
    schema: Option<&str>,
    log: &mut Log<'_>,
) -> Result<Found, DbError> {
    match conn {
        Conn::Pg(c) => {
            let q = format!(
                "SELECT n.nspname::text, c.relname::text, {PG_KIND}, c.oid::int8 \
                 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                 WHERE c.relname = $1 AND c.relkind IN ('r', 'p', 'v', 'm', 'f') \
                 AND CASE WHEN $2::text IS NULL THEN pg_table_is_visible(c.oid) \
                 ELSE n.nspname = $2 END"
            );
            log.sql(&q);
            let r = sqlx::query(&q)
                .bind(table)
                .bind(schema)
                .fetch_optional(&mut *c)
                .await
                .map_err(failed)?
                .ok_or_else(|| {
                    not_found(table, schema, " (without schema=, the search_path is used)")
                })?;
            let r = &r;
            Ok(Found {
                schema: g(r, 0)?,
                name: g(r, 1)?,
                kind: g(r, 2)?,
                oid: g(r, 3)?,
            })
        }
        Conn::My(c) => {
            let q = "SELECT CAST(table_schema AS CHAR), CAST(table_name AS CHAR), \
                     CAST(table_type AS CHAR) FROM information_schema.tables \
                     WHERE table_schema = COALESCE(?, DATABASE()) AND table_name = ?";
            log.sql(q);
            let r = sqlx::query(q)
                .bind(schema)
                .bind(table)
                .fetch_optional(&mut *c)
                .await
                .map_err(failed)?
                .ok_or_else(|| {
                    not_found(
                        table,
                        schema,
                        " (without schema=, the DSN's database is used)",
                    )
                })?;
            let r = &r;
            Ok(Found {
                schema: g(r, 0)?,
                name: g(r, 1)?,
                kind: g(r, 2)?,
                oid: 0,
            })
        }
        Conn::Lite(c) => {
            let q = "SELECT schema, name, type FROM pragma_table_list \
                     WHERE name = ? AND (? IS NULL OR schema = ?) \
                     AND type IN ('table', 'view', 'virtual') \
                     ORDER BY CASE schema WHEN 'temp' THEN 0 WHEN 'main' THEN 1 ELSE 2 END \
                     LIMIT 1";
            log.sql(q);
            let r = sqlx::query(q)
                .bind(table)
                .bind(schema)
                .bind(schema)
                .fetch_optional(&mut *c)
                .await
                .map_err(failed)?
                .ok_or_else(|| not_found(table, schema, ""))?;
            let r = &r;
            let t: String = g(r, 2)?;
            Ok(Found {
                schema: g(r, 0)?,
                name: g(r, 1)?,
                kind: sqlite_kind(&t).to_string(),
                oid: 0,
            })
        }
    }
}

fn column_json(
    name: String,
    ordinal: i64,
    data_type: String,
    nullable: bool,
    default: Option<String>,
    pk: bool,
) -> Value {
    json!({
        "name": name,
        "ordinal_position": ordinal,
        "data_type": data_type,
        "is_nullable": nullable,
        "default": default,
        "is_primary_key": pk,
    })
}

async fn columns(conn: &mut Conn, t: &Found, log: &mut Log<'_>) -> Result<Vec<Value>, DbError> {
    Ok(match conn {
        Conn::Pg(c) => {
            let q = "SELECT a.attname::text, a.attnum::int8, format_type(a.atttypid, a.atttypmod), \
                     NOT a.attnotnull, pg_get_expr(d.adbin, d.adrelid), \
                     EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = a.attrelid \
                     AND contype = 'p' AND a.attnum = ANY(conkey)) \
                     FROM pg_attribute a LEFT JOIN pg_attrdef d \
                     ON d.adrelid = a.attrelid AND d.adnum = a.attnum \
                     WHERE a.attrelid = $1::int8::oid AND a.attnum > 0 AND NOT a.attisdropped \
                     ORDER BY a.attnum";
            log.sql(q);
            sqlx::query(q)
                .bind(t.oid)
                .fetch_all(&mut *c)
                .await
                .map_err(failed)?
                .iter()
                .map(|r| -> Result<_, DbError> {
                    Ok(column_json(
                        g(r, 0)?,
                        g(r, 1)?,
                        g(r, 2)?,
                        g(r, 3)?,
                        g(r, 4)?,
                        g(r, 5)?,
                    ))
                })
                .collect::<Result<Vec<_>, DbError>>()?
        }
        Conn::My(c) => {
            let q = "SELECT CAST(column_name AS CHAR), CAST(ordinal_position AS SIGNED), \
                     CAST(column_type AS CHAR), CAST(is_nullable AS CHAR), \
                     CAST(CASE WHEN VERSION() LIKE '%MariaDB%' AND column_default = 'NULL' \
                     THEN NULL ELSE column_default END AS CHAR), CAST(column_key AS CHAR) \
                     FROM information_schema.columns WHERE table_schema = ? AND table_name = ? \
                     ORDER BY ordinal_position";
            log.sql(q);
            sqlx::query(q)
                .bind(&t.schema)
                .bind(&t.name)
                .fetch_all(&mut *c)
                .await
                .map_err(failed)?
                .iter()
                .map(|r| -> Result<_, DbError> {
                    Ok({
                        let nullable: String = g(r, 3)?;
                        let key: Option<String> = g(r, 5)?;
                        column_json(
                            g(r, 0)?,
                            g(r, 1)?,
                            g(r, 2)?,
                            nullable == "YES",
                            g(r, 4)?,
                            key.as_deref() == Some("PRI"),
                        )
                    })
                })
                .collect::<Result<Vec<_>, DbError>>()?
        }
        Conn::Lite(c) => {
            let q = "SELECT cid, name, type, \"notnull\", dflt_value, pk \
                     FROM pragma_table_info(?, ?) ORDER BY cid";
            log.sql(q);
            sqlx::query(q)
                .bind(&t.name)
                .bind(&t.schema)
                .fetch_all(&mut *c)
                .await
                .map_err(failed)?
                .iter()
                .map(|r| -> Result<_, DbError> {
                    Ok({
                        let cid: i64 = g(r, 0)?;
                        let ty: String = g(r, 2)?;
                        let notnull: i64 = g(r, 3)?;
                        let pk: i64 = g(r, 5)?;
                        // INTEGER PRIMARY KEY is the rowid and never NULL; other
                        // SQLite primary key columns accept NULL unless declared
                        // NOT NULL.
                        let rowid = pk > 0 && ty.eq_ignore_ascii_case("INTEGER");
                        column_json(
                            g(r, 1)?,
                            cid + 1,
                            ty,
                            notnull == 0 && !rowid,
                            g(r, 4)?,
                            pk > 0,
                        )
                    })
                })
                .collect::<Result<Vec<_>, DbError>>()?
        }
    })
}

// --- PostgreSQL details ----------------------------------------------------------

fn pg_action(c: &str) -> &'static str {
    match c {
        "r" => "RESTRICT",
        "c" => "CASCADE",
        "n" => "SET NULL",
        "d" => "SET DEFAULT",
        _ => "NO ACTION",
    }
}

const PG_KEY_COLS: &str = "ARRAY(SELECT a.attname::text FROM unnest(con.conkey) \
                           WITH ORDINALITY k(n, o) JOIN pg_attribute a \
                           ON a.attrelid = con.conrelid AND a.attnum = k.n ORDER BY k.o)";

async fn pg_details(
    c: &mut PgConnection,
    t: &Found,
    a: &SchemaArgs,
    out: &mut Value,
    log: &mut Log<'_>,
) -> Result<(), DbError> {
    let keys = |kind: &'static str| {
        format!(
            "SELECT con.conname::text, {PG_KEY_COLS} FROM pg_constraint con \
             WHERE con.conrelid = $1::int8::oid AND con.contype::text = '{kind}' ORDER BY 1"
        )
    };
    let q = keys("p");
    log.sql(&q);
    let pk = sqlx::query(&q)
        .bind(t.oid)
        .fetch_optional(&mut *c)
        .await
        .map_err(failed)?;
    out["primary_key"] = match pk {
        Some(r) => json!({"name": g::<String, _>(&r, 0)?, "columns": g::<Vec<String>, _>(&r, 1)?}),
        None => Value::Null,
    };
    if a.unique_constraints {
        let q = keys("u");
        log.sql(&q);
        let rows = sqlx::query(&q)
            .bind(t.oid)
            .fetch_all(&mut *c)
            .await
            .map_err(failed)?;
        out["unique_constraints"] = rows
            .iter()
            .map(|r| -> Result<_, DbError> {
                Ok(json!({"name": g::<String, _>(r, 0)?, "columns": g::<Vec<String>, _>(r, 1)?}))
            })
            .collect::<Result<Vec<_>, DbError>>()?
            .into();
    }
    if a.indexes {
        let q = "SELECT i.relname::text, ix.indisunique, ix.indisprimary, \
                 ARRAY(SELECT pg_get_indexdef(ix.indexrelid, k, true) \
                 FROM generate_series(1, ix.indnkeyatts) k ORDER BY k) \
                 FROM pg_index ix JOIN pg_class i ON i.oid = ix.indexrelid \
                 WHERE ix.indrelid = $1::int8::oid ORDER BY 1";
        log.sql(q);
        let rows = sqlx::query(q)
            .bind(t.oid)
            .fetch_all(&mut *c)
            .await
            .map_err(failed)?;
        out["indexes"] = rows
            .iter()
            .map(|r| -> Result<_, DbError> {
                Ok({
                    json!({
                        "name": g::<String, _>(r, 0)?,
                        "is_unique": g::<bool, _>(r, 1)?,
                        "is_primary": g::<bool, _>(r, 2)?,
                        "columns": g::<Vec<String>, _>(r, 3)?,
                    })
                })
            })
            .collect::<Result<Vec<_>, DbError>>()?
            .into();
    }
    if a.foreign_keys {
        let q = format!(
            "SELECT con.conname::text, {PG_KEY_COLS}, rn.nspname::text, rc.relname::text, \
             ARRAY(SELECT a.attname::text FROM unnest(con.confkey) WITH ORDINALITY k(n, o) \
             JOIN pg_attribute a ON a.attrelid = con.confrelid AND a.attnum = k.n \
             ORDER BY k.o), con.confupdtype::text, con.confdeltype::text \
             FROM pg_constraint con JOIN pg_class rc ON rc.oid = con.confrelid \
             JOIN pg_namespace rn ON rn.oid = rc.relnamespace \
             WHERE con.conrelid = $1::int8::oid AND con.contype = 'f' ORDER BY 1"
        );
        log.sql(&q);
        let rows = sqlx::query(&q)
            .bind(t.oid)
            .fetch_all(&mut *c)
            .await
            .map_err(failed)?;
        out["foreign_keys"] = rows
            .iter()
            .map(|r| -> Result<_, DbError> {
                Ok({
                    json!({
                        "name": g::<String, _>(r, 0)?,
                        "columns": g::<Vec<String>, _>(r, 1)?,
                        "referenced_table": {
                            "schema": g::<String, _>(r, 2)?,
                            "name": g::<String, _>(r, 3)?,
                        },
                        "referenced_columns": g::<Vec<String>, _>(r, 4)?,
                        "on_update": pg_action(&g::<String, _>(r, 5)?),
                        "on_delete": pg_action(&g::<String, _>(r, 6)?),
                    })
                })
            })
            .collect::<Result<Vec<_>, DbError>>()?
            .into();
    }
    if a.checks {
        let q = "SELECT conname::text, pg_get_constraintdef(oid, true) FROM pg_constraint \
                 WHERE conrelid = $1::int8::oid AND contype = 'c' ORDER BY 1";
        log.sql(q);
        let rows = sqlx::query(q)
            .bind(t.oid)
            .fetch_all(&mut *c)
            .await
            .map_err(failed)?;
        out["checks"] = rows
            .iter()
            .map(|r| -> Result<_, DbError> {
                Ok({
                    let def: String = g(r, 1)?;
                    json!({"name": g::<String, _>(r, 0)?, "expression": check_expression(&def)})
                })
            })
            .collect::<Result<Vec<_>, DbError>>()?
            .into();
    }
    if a.triggers {
        let q = "SELECT trigger_name::text, action_timing::text, event_manipulation::text, \
                 action_statement::text FROM information_schema.triggers \
                 WHERE event_object_schema = $1 AND event_object_table = $2 \
                 ORDER BY 1, 3";
        log.sql(q);
        let rows: Vec<(String, (String, String, String))> = sqlx::query(q)
            .bind(&t.schema)
            .bind(&t.name)
            .fetch_all(&mut *c)
            .await
            .map_err(failed)?
            .iter()
            .map(|r| -> Result<_, DbError> { Ok((g(r, 0)?, (g(r, 1)?, g(r, 2)?, g(r, 3)?))) })
            .collect::<Result<Vec<_>, DbError>>()?;
        out["triggers"] = triggers_json(rows);
    }
    Ok(())
}

/// `CHECK ((a > 0))` -> `(a > 0)`; a trailing `NOT VALID` is kept.
fn check_expression(def: &str) -> String {
    let d = def.trim();
    match d.strip_prefix("CHECK ") {
        Some(rest) => rest.trim().to_string(),
        None => d.to_string(),
    }
}

/// Trigger rows `(name, (timing, event, statement))`, one per event, as
/// `[{"name","timing","events","definition"}]`.
fn triggers_json(rows: Vec<(String, (String, String, String))>) -> Value {
    group(rows)
        .into_iter()
        .map(|(name, items)| {
            let timing = items[0].0.clone();
            let definition = items[0].2.clone();
            let events: Vec<String> = items.into_iter().map(|i| i.1).collect();
            json!({"name": name, "timing": timing, "events": events, "definition": definition})
        })
        .collect()
}

// --- MySQL details -----------------------------------------------------------------

async fn my_details(
    c: &mut MySqlConnection,
    t: &Found,
    a: &SchemaArgs,
    out: &mut Value,
    log: &mut Log<'_>,
) -> Result<(), DbError> {
    let q = "SELECT CAST(tc.constraint_name AS CHAR), CAST(tc.constraint_type AS CHAR), \
             CAST(k.column_name AS CHAR) FROM information_schema.table_constraints tc \
             JOIN information_schema.key_column_usage k \
             ON k.constraint_schema = tc.constraint_schema \
             AND k.constraint_name = tc.constraint_name \
             AND k.table_schema = tc.table_schema AND k.table_name = tc.table_name \
             WHERE tc.table_schema = ? AND tc.table_name = ? \
             AND tc.constraint_type IN ('PRIMARY KEY', 'UNIQUE') \
             ORDER BY tc.constraint_type, tc.constraint_name, k.ordinal_position";
    log.sql(q);
    let rows: Vec<((String, String), String)> = sqlx::query(q)
        .bind(&t.schema)
        .bind(&t.name)
        .fetch_all(&mut *c)
        .await
        .map_err(failed)?
        .iter()
        .map(|r| -> Result<_, DbError> { Ok(((g(r, 0)?, g(r, 1)?), g(r, 2)?)) })
        .collect::<Result<Vec<_>, DbError>>()?;
    let keys = group(rows);
    out["primary_key"] = keys
        .iter()
        .find(|((_, kind), _)| kind == "PRIMARY KEY")
        .map(|((name, _), cols)| json!({"name": name, "columns": cols}))
        .unwrap_or(Value::Null);
    if a.unique_constraints {
        out["unique_constraints"] = keys
            .iter()
            .filter(|((_, kind), _)| kind == "UNIQUE")
            .map(|((name, _), cols)| json!({"name": name, "columns": cols}))
            .collect();
    }
    if a.indexes {
        let q = "SELECT CAST(index_name AS CHAR), CAST(non_unique AS SIGNED), \
                 CAST(COALESCE(column_name, '') AS CHAR) FROM information_schema.statistics \
                 WHERE table_schema = ? AND table_name = ? ORDER BY index_name, seq_in_index";
        log.sql(q);
        let rows: Vec<((String, i64), String)> = sqlx::query(q)
            .bind(&t.schema)
            .bind(&t.name)
            .fetch_all(&mut *c)
            .await
            .map_err(failed)?
            .iter()
            .map(|r| -> Result<_, DbError> { Ok(((g(r, 0)?, g(r, 1)?), g(r, 2)?)) })
            .collect::<Result<Vec<_>, DbError>>()?;
        out["indexes"] = group(rows)
            .into_iter()
            .map(|((name, non_unique), cols)| {
                json!({
                    "is_primary": name == "PRIMARY",
                    "name": name,
                    "is_unique": non_unique == 0,
                    "columns": cols,
                })
            })
            .collect();
    }
    if a.foreign_keys {
        let q = "SELECT CAST(k.constraint_name AS CHAR), CAST(k.column_name AS CHAR), \
                 CAST(k.referenced_table_schema AS CHAR), CAST(k.referenced_table_name AS CHAR), \
                 CAST(k.referenced_column_name AS CHAR), CAST(r.update_rule AS CHAR), \
                 CAST(r.delete_rule AS CHAR) FROM information_schema.key_column_usage k \
                 JOIN information_schema.referential_constraints r \
                 ON r.constraint_schema = k.constraint_schema \
                 AND r.constraint_name = k.constraint_name AND r.table_name = k.table_name \
                 WHERE k.table_schema = ? AND k.table_name = ? \
                 AND k.referenced_table_name IS NOT NULL \
                 ORDER BY k.constraint_name, k.ordinal_position";
        log.sql(q);
        type Fk = (String, String, String, String, String);
        let rows: Vec<(Fk, (String, String))> = sqlx::query(q)
            .bind(&t.schema)
            .bind(&t.name)
            .fetch_all(&mut *c)
            .await
            .map_err(failed)?
            .iter()
            .map(|r| -> Result<_, DbError> {
                Ok({
                    (
                        (g(r, 0)?, g(r, 2)?, g(r, 3)?, g(r, 5)?, g(r, 6)?),
                        (g(r, 1)?, g(r, 4)?),
                    )
                })
            })
            .collect::<Result<Vec<_>, DbError>>()?;
        out["foreign_keys"] = group(rows)
            .into_iter()
            .map(|((name, rs, rt, upd, del), cols)| {
                let (from, to): (Vec<String>, Vec<String>) = cols.into_iter().unzip();
                json!({
                    "name": name,
                    "columns": from,
                    "referenced_table": {"schema": rs, "name": rt},
                    "referenced_columns": to,
                    "on_update": upd,
                    "on_delete": del,
                })
            })
            .collect();
    }
    if a.checks {
        // MariaDB names checks per table and lists the table; MySQL names
        // them per schema.
        let v = "SELECT CAST(VERSION() AS CHAR)";
        log.sql(v);
        let version: String = sqlx::query_scalar(v)
            .fetch_one(&mut *c)
            .await
            .map_err(failed)?;
        let q = if version.to_ascii_lowercase().contains("mariadb") {
            "SELECT CAST(constraint_name AS CHAR), CAST(check_clause AS CHAR) \
             FROM information_schema.check_constraints \
             WHERE constraint_schema = ? AND table_name = ? ORDER BY 1"
        } else {
            "SELECT CAST(cc.constraint_name AS CHAR), CAST(cc.check_clause AS CHAR) \
             FROM information_schema.check_constraints cc \
             JOIN information_schema.table_constraints tc \
             ON tc.constraint_schema = cc.constraint_schema \
             AND tc.constraint_name = cc.constraint_name \
             WHERE tc.table_schema = ? AND tc.table_name = ? \
             AND tc.constraint_type = 'CHECK' ORDER BY 1"
        };
        log.sql(q);
        let rows = sqlx::query(q)
            .bind(&t.schema)
            .bind(&t.name)
            .fetch_all(&mut *c)
            .await
            .map_err(failed)?;
        out["checks"] = rows
            .iter()
            .map(|r| -> Result<_, DbError> {
                Ok(json!({"name": g::<String, _>(r, 0)?, "expression": g::<String, _>(r, 1)?}))
            })
            .collect::<Result<Vec<_>, DbError>>()?
            .into();
    }
    if a.triggers {
        let q = "SELECT CAST(trigger_name AS CHAR), CAST(action_timing AS CHAR), \
                 CAST(event_manipulation AS CHAR), CAST(action_statement AS CHAR) \
                 FROM information_schema.triggers \
                 WHERE event_object_schema = ? AND event_object_table = ? ORDER BY 1, 3";
        log.sql(q);
        let rows: Vec<(String, (String, String, String))> = sqlx::query(q)
            .bind(&t.schema)
            .bind(&t.name)
            .fetch_all(&mut *c)
            .await
            .map_err(failed)?
            .iter()
            .map(|r| -> Result<_, DbError> { Ok((g(r, 0)?, (g(r, 1)?, g(r, 2)?, g(r, 3)?))) })
            .collect::<Result<Vec<_>, DbError>>()?;
        out["triggers"] = triggers_json(rows);
    }
    Ok(())
}

// --- SQLite details ------------------------------------------------------------------

async fn lite_index_columns(
    c: &mut SqliteConnection,
    index: &str,
    schema: &str,
    log: &mut Log<'_>,
) -> Result<Vec<Option<String>>, DbError> {
    let q = "SELECT name FROM pragma_index_info(?, ?) ORDER BY seqno";
    log.sql(q);
    sqlx::query(q)
        .bind(index)
        .bind(schema)
        .fetch_all(&mut *c)
        .await
        .map_err(failed)?
        .iter()
        .map(|r| -> Result<_, DbError> { g::<Option<String>, _>(r, 0) })
        .collect::<Result<Vec<_>, DbError>>()
}

async fn lite_details(
    c: &mut SqliteConnection,
    t: &Found,
    a: &SchemaArgs,
    out: &mut Value,
    log: &mut Log<'_>,
) -> Result<(), DbError> {
    // The primary key, in key order (pk is the position in the key).
    let q = "SELECT name FROM pragma_table_info(?, ?) WHERE pk > 0 ORDER BY pk";
    log.sql(q);
    let pk: Vec<String> = sqlx::query(q)
        .bind(&t.name)
        .bind(&t.schema)
        .fetch_all(&mut *c)
        .await
        .map_err(failed)?
        .iter()
        .map(|r| -> Result<_, DbError> { g(r, 0) })
        .collect::<Result<Vec<_>, DbError>>()?;
    out["primary_key"] = if pk.is_empty() {
        Value::Null
    } else {
        json!({"name": null, "columns": pk})
    };

    let q = "SELECT name, \"unique\", origin FROM pragma_index_list(?, ?) ORDER BY name";
    log.sql(q);
    let list: Vec<(String, bool, String)> = sqlx::query(q)
        .bind(&t.name)
        .bind(&t.schema)
        .fetch_all(&mut *c)
        .await
        .map_err(failed)?
        .iter()
        .map(|r| -> Result<_, DbError> { Ok((g(r, 0)?, r.get::<i64, _>(1) != 0, g(r, 2)?)) })
        .collect::<Result<Vec<_>, DbError>>()?;
    let mut indexes = Vec::new();
    let mut uniques = Vec::new();
    for (name, unique, origin) in list {
        let cols = lite_index_columns(c, &name, &t.schema, log).await?;
        if origin == "u" {
            uniques.push(json!({"name": name, "columns": cols}));
        }
        indexes.push(json!({
            "name": name,
            "is_unique": unique,
            "is_primary": origin == "pk",
            "columns": cols,
        }));
    }
    if a.indexes {
        out["indexes"] = json!(indexes);
    }
    if a.unique_constraints {
        out["unique_constraints"] = json!(uniques);
    }
    if a.foreign_keys {
        let q = "SELECT id, \"table\", \"from\", \"to\", on_update, on_delete \
                 FROM pragma_foreign_key_list(?, ?) ORDER BY id, seq";
        log.sql(q);
        type Fk = (i64, String, String, String);
        let rows: Vec<(Fk, (String, Option<String>))> = sqlx::query(q)
            .bind(&t.name)
            .bind(&t.schema)
            .fetch_all(&mut *c)
            .await
            .map_err(failed)?
            .iter()
            .map(|r| -> Result<_, DbError> {
                Ok((
                    (g(r, 0)?, g(r, 1)?, g(r, 4)?, g(r, 5)?),
                    (g(r, 2)?, g(r, 3)?),
                ))
            })
            .collect::<Result<Vec<_>, DbError>>()?;
        out["foreign_keys"] = group(rows)
            .into_iter()
            .map(|((_, table, upd, del), cols)| {
                let (from, to): (Vec<String>, Vec<Option<String>>) = cols.into_iter().unzip();
                json!({
                    "name": null,
                    "columns": from,
                    "referenced_table": {"schema": t.schema, "name": table},
                    "referenced_columns": to,
                    "on_update": upd,
                    "on_delete": del,
                })
            })
            .collect();
    }
    if a.checks || a.triggers {
        // The schema name comes from pragma_table_list and is quoted.
        let master = format!("{}.sqlite_schema", sql::quote_sqlite_ident(&t.schema));
        if a.checks {
            let q = format!("SELECT sql FROM {master} WHERE type = 'table' AND name = ?");
            log.sql(&q);
            let create: Option<String> = sqlx::query_scalar(&q)
                .bind(&t.name)
                .fetch_optional(&mut *c)
                .await
                .map_err(failed)?
                .flatten();
            out["checks"] = create
                .map(|s| sql::sqlite_checks(&s))
                .unwrap_or_default()
                .into_iter()
                .map(|(name, expr)| json!({"name": name, "expression": expr}))
                .collect();
        }
        if a.triggers {
            let q = format!(
                "SELECT name, sql FROM {master} WHERE type = 'trigger' AND tbl_name = ? \
                 ORDER BY name"
            );
            log.sql(&q);
            let rows = sqlx::query(&q)
                .bind(&t.name)
                .fetch_all(&mut *c)
                .await
                .map_err(failed)?;
            out["triggers"] = rows
                .iter()
                .map(|r| -> Result<_, DbError> {
                    Ok({
                        let def: String = g(r, 1)?;
                        let (timing, events) = sql::sqlite_trigger_parts(&def);
                        json!({
                            "name": g::<String, _>(r, 0)?,
                            "timing": timing,
                            "events": events,
                            "definition": def,
                        })
                    })
                })
                .collect::<Result<Vec<_>, DbError>>()?
                .into();
        }
    }
    Ok(())
}
