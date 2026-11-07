//! db verbs through `DbHandle::call`, on SQLite files in temporary
//! directories (PostgreSQL, MySQL and MariaDB run in tests/db_e2e_docker.rs).

use super::*;
use serde_json::Value;
use tempfile::TempDir;

struct Out {
    status: Status,
    out: String,
    err: String,
}

impl Out {
    fn json(&self) -> Value {
        serde_json::from_str(self.out.trim())
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {:?}", self.out))
    }

    fn ok(self) -> Self {
        assert!(self.status.ok, "stdout: {}\nstderr: {}", self.out, self.err);
        assert!(self.err.is_empty(), "{}", self.err);
        self
    }

    /// Failed with `exit`, JSON error `code` and the standard stderr line.
    fn fails(self, exit: i32, code: &str) -> Self {
        assert_eq!(
            self.status.exit_code(),
            exit,
            "stdout: {}\nstderr: {}",
            self.out,
            self.err
        );
        assert_eq!(self.json()["error"]["code"], code, "{}", self.out);
        assert!(
            self.err.starts_with(&format!("Error: [{code}] ")),
            "{}",
            self.err
        );
        self
    }

    /// Exit 2, nothing on stdout, `Error: [code] ...` containing `needle`.
    fn usage(self, code: &str, needle: &str) -> Self {
        assert_eq!(
            self.status.exit_code(),
            2,
            "stdout: {}\nstderr: {}",
            self.out,
            self.err
        );
        assert!(self.out.is_empty(), "{}", self.out);
        assert!(
            self.err.starts_with(&format!("Error: [{code}] ")),
            "{}",
            self.err
        );
        assert!(self.err.contains(needle), "{:?} lacks {needle:?}", self.err);
        self
    }
}

fn handle(url: &str) -> DbHandle {
    DbHandle::from_url(&Url::parse(url).unwrap()).unwrap()
}

fn call_on(h: &DbHandle, verb: &str, args: &[(&str, &str)]) -> Out {
    let args: Args = args
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
    let mut io = IoStreams {
        stdin: &mut i,
        stdout: &mut o,
        stderr: &mut e,
    };
    let status = h.call(verb, &args, &mut io).unwrap();
    Out {
        status,
        out: String::from_utf8(o).unwrap(),
        err: String::from_utf8(e).unwrap(),
    }
}

/// A SQLite database file in its own temporary directory.
struct Db {
    _dir: TempDir,
    dsn: String,
    path: std::path::PathBuf,
}

impl Db {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("app.db");
        let dsn = format!("sqlite:{}?mode=rwc", path.display());
        Self {
            _dir: dir,
            dsn,
            path,
        }
    }

    /// Runs `verb` on db://sqlite/app with this database's DSN.
    fn call(&self, verb: &str, args: &[(&str, &str)]) -> Out {
        let mut a = vec![("dsn", self.dsn.as_str())];
        a.extend_from_slice(args);
        call_on(&handle("db://sqlite/app"), verb, &a)
    }

    fn exec(&self, sql: &str) {
        self.call("exec", &[("sql", sql)]).ok();
    }

    fn rows(&self, sql: &str) -> Vec<Value> {
        self.call("query", &[("sql", sql)]).ok().json()["rows"]
            .as_array()
            .unwrap()
            .clone()
    }

    /// A users table with two rows.
    fn with_users() -> Self {
        let db = Self::new();
        db.exec(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, \
             active BOOLEAN, score REAL, data BLOB)",
        );
        db.exec(
            "INSERT INTO users (email, active, score, data) VALUES \
             ('a@x.com', 1, 1.5, x'00ff'), ('b@x.com', 0, NULL, NULL)",
        );
        db
    }
}

/// A recursive CTE that never ends on its own.
const ENDLESS: &str =
    "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT x FROM c";

// --- target, help and unknown verbs -------------------------------------------

#[test]
fn targets_name_a_driver_and_an_alias() {
    let h = handle("db://postgresql/my-app_1");
    assert_eq!(h.driver, Driver::Postgres);
    assert_eq!(h.alias, "my-app_1");
    assert_eq!(handle("db://mariadb/x").driver, Driver::Mysql);
    assert_eq!(handle("db://SQLite/x").driver, Driver::Sqlite);
    for (url, needle) in [
        ("db://oracle/app", "unknown db driver"),
        ("db://sqlite/", "alias is missing"),
        ("db://sqlite", "alias is missing"),
        ("db://sqlite/a%20b", "invalid db alias"),
        ("db://sqlite/a/b", "invalid db alias"),
    ] {
        let e = DbHandle::from_url(&Url::parse(url).unwrap()).unwrap_err();
        assert!(e.to_string().contains(needle), "{url}: {e}");
    }
}

#[test]
fn help_detection_is_exact() {
    let h = handle("db://sqlite/my-hosts");
    assert!(h.help_topic("query", &Args::new()).is_none());
    assert!(handle("db://--help").help_target);
    assert!(handle("db://sqlite/--help").help_target);
    assert!(!handle("db://sqlite/pre-hotfix").help_target);
}

#[test]
fn in_url_help_renders_the_approved_help() {
    let h = handle("db://sqlite/app");
    for verb in ["help", "--help", "-h"] {
        let o = call_on(&h, verb, &[]).ok();
        assert!(o.out.starts_with("Handle: db\n"), "{}", o.out);
    }
    let o = call_on(&h, "--help=transaction", &[]).ok();
    assert!(
        o.out.starts_with("Handle: db\nVerb: transaction"),
        "{}",
        o.out
    );
    let o = call_on(&h, "help", &[("verb", "query")]).ok();
    assert!(o.out.contains("Verb: query"), "{}", o.out);
    let o = call_on(&h, "query", &[("--help", "")]).ok();
    assert!(o.out.contains("Verb: query"), "{}", o.out);
    let o = call_on(&handle("db://--help"), "connect", &[]).ok();
    assert!(o.out.starts_with("Handle: db\n"), "{}", o.out);
}

#[test]
fn unknown_verb_is_a_usage_error_with_a_suggestion() {
    call_on(&handle("db://sqlite/app"), "querry", &[])
        .usage("db.unknown_verb", "did you mean `query`?");
    call_on(&handle("db://sqlite/app"), "frobnicate", &[])
        .usage("db.unknown_verb", "verbs: connect, ping, query");
}

// --- strict arguments -------------------------------------------------------------

#[test]
fn every_verb_refuses_unknown_arguments_before_connecting() {
    let h = handle("db://sqlite/app");
    for verb in h.verbs() {
        call_on(&h, verb, &[("timout_ms", "5")])
            .usage("db.invalid_argument", "did you mean `timeout_ms`?");
        call_on(&h, verb, &[("zzz", "1")]).usage("db.invalid_argument", "unknown argument");
    }
}

#[test]
fn removed_options_explain_what_to_use() {
    let h = handle("db://sqlite/app");
    for k in [
        "max_connections",
        "min_connections",
        "idle_timeout_ms",
        "max_lifetime_ms",
    ] {
        call_on(&h, "connect", &[(k, "5")]).usage("db.invalid_argument", "keeps no pool");
    }
    call_on(&h, "connect", &[("connect_timeout_ms", "5")])
        .usage("db.invalid_argument", "use timeout_ms");
    call_on(&h, "query", &[("sql", "SELECT 1"), ("tx_id", "abc")])
        .usage("db.invalid_argument", "statements=[...]");
    for a in ["begin", "commit", "rollback"] {
        call_on(
            &h,
            "transaction",
            &[("action", a), ("statements", "[\"SELECT 1\"]")],
        )
        .usage("db.invalid_argument", "cannot outlive one resh run");
    }
}

#[test]
fn dry_run_false_is_accepted() {
    let db = Db::new();
    db.call("connect", &[("dry_run", "false")]).ok();
}

#[test]
fn invalid_values_are_refused_with_the_argument_named() {
    let db = Db::new();
    let cases: &[(&str, &[(&str, &str)], &str)] = &[
        (
            "query",
            &[("sql", "SELECT 1"), ("timeout_ms", "0")],
            "timeout_ms",
        ),
        (
            "query",
            &[("sql", "SELECT 1"), ("timeout_ms", "soon")],
            "timeout_ms",
        ),
        (
            "query",
            &[("sql", "SELECT 1"), ("timeout_ms", "86400001")],
            "timeout_ms",
        ),
        (
            "query",
            &[("sql", "SELECT 1"), ("max_rows", "0")],
            "max_rows",
        ),
        ("query", &[("sql", "SELECT 1"), ("mode", "table")], "mode"),
        (
            "query",
            &[("sql", "SELECT 1"), ("mode", "exec"), ("max_rows", "5")],
            "max_rows",
        ),
        (
            "query",
            &[("sql", "SELECT 1"), ("log_queries", "maybe")],
            "log_queries",
        ),
        ("query", &[], "sql= is required"),
        ("query", &[("sql", "  ")], "sql is empty"),
        ("query", &[("sql", "SELECT 1; SELECT 2")], "2 statements"),
        ("query", &[("sql", "SELECT 'x")], "unterminated"),
        (
            "query",
            &[("sql", "SELECT ?"), ("params", "1")],
            "params must be a JSON array",
        ),
        (
            "query",
            &[("sql", "SELECT ?"), ("params", "[1")],
            "params must be a JSON array",
        ),
        (
            "query",
            &[("sql", "SELECT ?"), ("params", "[[1]]")],
            "params[0]",
        ),
        (
            "query",
            &[("sql", "SELECT ?"), ("params", "[{}]")],
            "params[0]",
        ),
        (
            "query",
            &[("sql", "SELECT ?"), ("params", "[18446744073709551615]")],
            "range",
        ),
        (
            "exec",
            &[("sql", "DELETE FROM t"), ("return_last_insert_id", "x")],
            "return_last",
        ),
        (
            "exec",
            &[("sql", "DELETE FROM a; DELETE FROM b")],
            "2 statements",
        ),
        ("ping", &[("retries", "11")], "retries"),
        ("ping", &[("backoff_ms", "-1")], "backoff_ms"),
        ("ping", &[("detailed", "2")], "detailed"),
        (
            "tables",
            &[("table", "t"), ("include_views", "true")],
            "include_views",
        ),
        (
            "tables",
            &[("table", "t"), ("max_tables", "3")],
            "max_tables",
        ),
        ("tables", &[("max_tables", "0")], "max_tables"),
        ("tables", &[("table", "")], "table is empty"),
        ("schema", &[], "table= is required"),
        (
            "schema",
            &[("table", "t"), ("include_checks", "yesno")],
            "include_checks",
        ),
        ("transaction", &[], "statements= is required"),
        ("transaction", &[("statements", "[]")], "empty array"),
        ("transaction", &[("statements", "{}")], "JSON array"),
        ("transaction", &[("statements", "[1]")], "statements[0]"),
        (
            "transaction",
            &[("statements", "[\"SELECT 1; SELECT 2\"]")],
            "statements[0]",
        ),
        (
            "transaction",
            &[("statements", "[{\"sql\":\"x\",\"p\":[]}]")],
            "unknown key",
        ),
        (
            "transaction",
            &[("statements", "[{\"params\":[]}]")],
            "needs a string sql",
        ),
        (
            "transaction",
            &[("statements", "[{\"sql\":\"x\",\"params\":1}]")],
            "JSON array",
        ),
        (
            "transaction",
            &[("statements", "[\"x\"]"), ("action", "go")],
            "action",
        ),
        (
            "transaction",
            &[("statements", "[\"x\"]"), ("isolation", "chaos")],
            "isolation",
        ),
        (
            "transaction",
            &[("statements", "[\"x\"]"), ("isolation", "read_committed")],
            "serializable",
        ),
        (
            "transaction",
            &[("statements", "[\"x\"]"), ("read_only", "no way")],
            "read_only",
        ),
        (
            "connect",
            &[("tls_mode", "require")],
            "sqlite does not use TLS",
        ),
        ("connect", &[("tls_mode", "bogus")], "tls_mode"),
        ("connect", &[("ca_file", "/nonexistent.pem")], "ca_file"),
    ];
    for (verb, args, needle) in cases {
        db.call(verb, args).usage("db.invalid_argument", needle);
    }
    // Nothing was created by any of them.
    assert_eq!(std::fs::metadata(&db.path).map(|m| m.len()).unwrap_or(0), 0);
}

#[test]
fn postgres_and_mysql_option_checks_happen_before_connecting() {
    // An address that is never contacted: every case is refused first.
    let pg = handle("db://postgres/app");
    let my = handle("db://mysql/app");
    let pg_dsn = ("dsn", "postgresql://u:pw@127.0.0.1:1/db");
    let my_dsn = ("dsn", "mysql://u:pw@127.0.0.1:1/db");
    call_on(
        &pg,
        "exec",
        &[
            pg_dsn,
            ("sql", "INSERT INTO t VALUES (1)"),
            ("return_last_insert_id", "true"),
        ],
    )
    .usage("db.invalid_argument", "RETURNING");
    call_on(&my, "connect", &[my_dsn, ("tls_mode", "allow")])
        .usage("db.invalid_argument", "no tls_mode=allow");
    let dir = TempDir::new().unwrap();
    let not_pem = dir.path().join("x.pem");
    std::fs::write(&not_pem, "hello").unwrap();
    let not_pem = not_pem.to_str().unwrap();
    call_on(&pg, "connect", &[pg_dsn, ("ca_file", not_pem)])
        .usage("db.invalid_argument", "no PEM certificate");
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pem = dir.path().join("ca.pem");
    std::fs::write(&pem, cert.serialize_pem().unwrap()).unwrap();
    let pem = pem.to_str().unwrap();
    for mode in ["disable", "allow", "prefer", "require"] {
        call_on(
            &pg,
            "connect",
            &[pg_dsn, ("ca_file", pem), ("tls_mode", mode)],
        )
        .usage(
            "db.invalid_argument",
            "ca_file needs certificate verification",
        );
    }
    // Scheme mismatch, and a DSN that is not a URL: the DSN is not echoed.
    call_on(&pg, "connect", &[my_dsn]).usage("db.invalid_dsn", "does not match driver postgres");
    let o = call_on(
        &my,
        "connect",
        &[("dsn", "mysql://u:Pa55word@127.0.0.1:99999/db")],
    )
    .usage("db.invalid_dsn", "percent-encode");
    assert!(!o.err.contains("Pa55word"), "{}", o.err);
    call_on(&handle("db://sqlite/app"), "connect", &[("dsn", "app.db")])
        .usage("db.invalid_dsn", "starts with sqlite:");
}

#[test]
fn a_missing_dsn_names_the_environment_variable() {
    call_on(
        &handle("db://sqlite/no-such-alias-xyz"),
        "query",
        &[("sql", "SELECT 1")],
    )
    .usage("db.dsn_missing", "DB_NO_SUCH_ALIAS_XYZ_DSN");
}

// --- secrets ------------------------------------------------------------------------

#[test]
fn redactor_removes_the_password_and_the_dsn() {
    let r = Redactor::for_dsn("postgresql://app:p%40ss-w0rd@db/app?sslpassword=k3y-pass");
    let msg = "failed for postgresql://app:p%40ss-w0rd@db/app?sslpassword=k3y-pass \
               (p@ss-w0rd, p%40ss-w0rd, k3y-pass)";
    let s = r.scrub(msg);
    for secret in ["p@ss-w0rd", "p%40ss-w0rd", "k3y-pass", "postgresql://app:"] {
        assert!(!s.contains(secret), "{s}");
    }
    assert_eq!(Redactor::for_dsn("sqlite::memory:").scrub("x"), "x");
}

#[test]
fn connect_failures_never_show_the_dsn() {
    // Nothing listens on port 1: the error names the failure, not the DSN.
    let o = call_on(
        &handle("db://postgres/app"),
        "connect",
        &[
            ("dsn", "postgresql://app:Sup3r-Secret@127.0.0.1:1/app"),
            ("timeout_ms", "2000"),
        ],
    )
    .fails(1, "db.connect_failed");
    assert!(!o.out.contains("Sup3r-Secret") && !o.err.contains("Sup3r-Secret"));
    assert!(!o.err.contains("postgresql://"), "{}", o.err);
}

// --- connect and ping -----------------------------------------------------------------

#[test]
fn connect_reports_the_server_and_disconnects() {
    let db = Db::new();
    let v = db.call("connect", &[]).ok().json();
    assert_eq!(v["alias"], "app");
    assert_eq!(v["driver"], "sqlite");
    assert_eq!(v["database"], "main");
    assert_eq!(v["tls"], false);
    assert!(v["server_version"].as_str().unwrap().starts_with('3'));
    assert!(v["latency_ms"].is_u64());
    // tls_mode=disable is accepted on sqlite.
    db.call("connect", &[("tls_mode", "disable")]).ok();
}

#[test]
fn connect_to_a_missing_sqlite_file_fails() {
    let dir = TempDir::new().unwrap();
    let dsn = format!("sqlite:{}", dir.path().join("none.db").display());
    let o = call_on(&handle("db://sqlite/app"), "connect", &[("dsn", &dsn)])
        .fails(1, "db.connect_failed");
    assert!(!dir.path().join("none.db").exists());
    drop(o);
}

#[test]
fn ping_succeeds_and_reports_attempts() {
    let db = Db::new();
    let v = db.call("ping", &[("retries", "2")]).ok().json();
    assert_eq!(v["status"], "ok");
    assert_eq!(v["attempts"], 1);
}

#[test]
fn ping_retries_with_a_new_connection_and_then_fails() {
    let dir = TempDir::new().unwrap();
    let dsn = format!("sqlite:{}", dir.path().join("none.db").display());
    let h = handle("db://sqlite/app");
    let start = Instant::now();
    let o = call_on(
        &h,
        "ping",
        &[("dsn", &dsn), ("retries", "2"), ("backoff_ms", "50")],
    )
    .fails(1, "db.ping_failed");
    assert!(start.elapsed().as_millis() >= 100);
    let v = o.json();
    assert_eq!(v["status"], "error");
    assert_eq!(v["attempts"], 3);
    assert!(v["error"].get("last_error").is_none());
    let v = call_on(&h, "ping", &[("dsn", &dsn), ("detailed", "true")])
        .fails(1, "db.ping_failed")
        .json();
    assert!(
        v["error"]["last_error"]
            .as_str()
            .unwrap()
            .contains("cannot connect")
    );
}

// --- query --------------------------------------------------------------------------------

#[test]
fn query_rows_with_column_metadata_and_typed_values() {
    let db = Db::with_users();
    let v = db
        .call(
            "query",
            &[(
                "sql",
                "SELECT id, email, active, score, data FROM users ORDER BY id",
            )],
        )
        .ok()
        .json();
    assert_eq!(
        v["rows"],
        json!([
            {"id": 1, "email": "a@x.com", "active": true, "score": 1.5, "data": "base64:AP8="},
            {"id": 2, "email": "b@x.com", "active": false, "score": null, "data": null},
        ])
    );
    assert_eq!(v["meta"]["row_count"], 2);
    assert_eq!(v["meta"]["truncated"], false);
    assert_eq!(
        v["meta"]["columns"],
        json!([
            {"name": "id", "type": "INTEGER"},
            {"name": "email", "type": "TEXT"},
            {"name": "active", "type": "BOOLEAN"},
            {"name": "score", "type": "REAL"},
            {"name": "data", "type": "BLOB"},
        ])
    );
}

#[test]
fn query_binds_every_parameter_type() {
    let db = Db::new();
    let v = db
        .call(
            "query",
            &[
                ("sql", "SELECT ? AS s, ? AS i, ? AS f, ? AS b, ? AS n"),
                ("params", r#"["it's", -9007199254740993, 2.5, true, null]"#),
            ],
        )
        .ok()
        .json();
    assert_eq!(
        v["rows"][0],
        json!({"s": "it's", "i": -9007199254740993i64, "f": 2.5, "b": 1, "n": null})
    );
}

#[test]
fn parameters_are_data_never_sql() {
    let db = Db::with_users();
    let evil = "x'); DROP TABLE users; --";
    db.call(
        "exec",
        &[
            ("sql", "INSERT INTO users (email) VALUES (?)"),
            ("params", &serde_json::to_string(&[evil]).unwrap()),
        ],
    )
    .ok();
    let rows = db.rows("SELECT email FROM users WHERE id = 3");
    assert_eq!(rows[0]["email"], evil);
    assert_eq!(db.rows("SELECT count(*) AS n FROM users")[0]["n"], 3);
}

#[test]
fn query_scalar_and_exec_modes() {
    let db = Db::with_users();
    let v = db
        .call(
            "query",
            &[
                ("sql", "SELECT count(*) AS n FROM users"),
                ("mode", "scalar"),
            ],
        )
        .ok()
        .json();
    assert_eq!(v["value"], 2);
    assert_eq!(v["meta"]["row_count"], 1);
    assert_eq!(
        v["meta"]["columns"],
        json!([{"name": "n", "type": "INTEGER"}])
    );
    let v = db
        .call("query", &[("sql", "SELECT 1 WHERE 0"), ("mode", "scalar")])
        .ok()
        .json();
    assert_eq!(v["value"], Value::Null);
    assert_eq!(v["meta"]["row_count"], 0);
    let v = db
        .call(
            "query",
            &[("sql", "UPDATE users SET active = 1"), ("mode", "exec")],
        )
        .ok()
        .json();
    assert_eq!(v, json!({"rows_affected": 2}));
}

#[test]
fn query_max_rows_truncates_and_zero_rows_is_an_empty_list() {
    let db = Db::with_users();
    let v = db
        .call(
            "query",
            &[
                ("sql", "SELECT id FROM users ORDER BY id"),
                ("max_rows", "1"),
            ],
        )
        .ok()
        .json();
    assert_eq!(v["rows"], json!([{"id": 1}]));
    assert_eq!(v["meta"]["truncated"], true);
    assert_eq!(v["meta"]["row_count"], 1);
    let v = db
        .call(
            "query",
            &[
                ("sql", "SELECT id FROM users ORDER BY id"),
                ("max_rows", "2"),
            ],
        )
        .ok()
        .json();
    assert_eq!(v["meta"]["truncated"], false);
    let v = db
        .call("query", &[("sql", "SELECT id FROM users WHERE id > 5")])
        .ok()
        .json();
    assert_eq!(v["rows"], json!([]));
    assert_eq!(v["meta"]["row_count"], 0);
}

#[test]
fn repeated_column_names_are_kept_apart() {
    let db = Db::new();
    let v = db
        .call("query", &[("sql", "SELECT 1 AS a, 2 AS a, 3 AS a")])
        .ok()
        .json();
    assert_eq!(v["rows"][0], json!({"a": 1, "a_2": 2, "a_3": 3}));
    assert_eq!(v["meta"]["columns"][1]["name"], "a_2");
}

#[test]
fn a_failing_statement_is_query_failed() {
    let db = Db::new();
    let o = db
        .call("query", &[("sql", "SELECT x FROM nope")])
        .fails(1, "db.query_failed");
    assert!(o.err.contains("no such table"), "{}", o.err);
}

#[test]
fn query_timeout_interrupts_the_statement() {
    let db = Db::new();
    let start = Instant::now();
    let o = db
        .call(
            "query",
            &[
                (
                    "sql",
                    "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) \
                      SELECT count(*) FROM c",
                ),
                ("timeout_ms", "300"),
            ],
        )
        .fails(124, "db.timeout");
    assert!(start.elapsed().as_millis() < 5000);
    assert!(o.err.contains("timeout_ms=300"), "{}", o.err);
}

#[test]
fn rows_streamed_before_a_timeout_stay_in_a_valid_document() {
    let db = Db::new();
    let o = db.call(
        "query",
        &[
            ("sql", ENDLESS),
            ("max_rows", "1000000"),
            ("timeout_ms", "400"),
        ],
    );
    assert_eq!(o.status.exit_code(), 124, "{}", o.err);
    let v = o.json();
    let n = v["rows"].as_array().unwrap().len() as u64;
    assert!(n > 0);
    assert_eq!(v["meta"]["row_count"], n);
    assert_eq!(v["error"]["code"], "db.timeout");
    assert!(o.err.starts_with("Error: [db.timeout] "), "{}", o.err);
}

#[test]
fn log_queries_writes_the_sql_but_not_the_parameters() {
    let db = Db::new();
    let o = db.call(
        "query",
        &[
            ("sql", "SELECT ?\n AS secret"),
            ("params", "[\"hunter2\"]"),
            ("log_queries", "true"),
        ],
    );
    assert!(o.status.ok);
    assert!(o.err.contains("db: sql: SELECT ?  AS secret"), "{}", o.err);
    assert!(!o.err.contains("hunter2"));
    // A failure still ends with the standard error line.
    let o = db.call(
        "query",
        &[("sql", "SELECT x FROM nope"), ("log_queries", "true")],
    );
    assert_eq!(o.status.exit_code(), 1);
    assert!(
        o.err.starts_with("db: sql: SELECT x FROM nope\n"),
        "{}",
        o.err
    );
    assert!(o.err.contains("Error: [db.query_failed] "), "{}", o.err);
}

// --- exec ----------------------------------------------------------------------------------

#[test]
fn exec_reports_rows_affected_and_the_new_row_id() {
    let db = Db::with_users();
    let v = db
        .call(
            "exec",
            &[
                ("sql", "INSERT INTO users (email) VALUES (?)"),
                ("params", "[\"c@x.com\"]"),
                ("return_last_insert_id", "true"),
            ],
        )
        .ok()
        .json();
    assert_eq!(v, json!({"rows_affected": 1, "last_insert_id": 3}));
    let v = db
        .call(
            "exec",
            &[("sql", "DELETE FROM users WHERE id < ?"), ("params", "[3]")],
        )
        .ok()
        .json();
    assert_eq!(v, json!({"rows_affected": 2}));
    db.call(
        "exec",
        &[("sql", "INSERT INTO users (email) VALUES ('c@x.com')")],
    )
    .fails(1, "db.query_failed");
}

#[test]
fn exec_timeout_is_exit_124() {
    let db = Db::new();
    db.exec("CREATE TABLE t (x INTEGER)");
    db.call(
        "exec",
        &[
            ("sql", &format!("INSERT INTO t {ENDLESS}")),
            ("timeout_ms", "300"),
        ],
    )
    .fails(124, "db.timeout");
    assert_eq!(db.rows("SELECT count(*) AS n FROM t")[0]["n"], 0);
}

// --- tables -----------------------------------------------------------------------------------

fn sample_schema(db: &Db) {
    db.exec(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, \
         name TEXT DEFAULT 'anon', CONSTRAINT email_len CHECK (length(email) > 3))",
    );
    db.exec(
        "CREATE TABLE orders (id INTEGER, line INTEGER, user_id INTEGER, \
         total REAL CHECK (total >= 0), PRIMARY KEY (id, line), \
         FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE)",
    );
    db.exec("CREATE INDEX orders_user ON orders (user_id, total)");
    db.exec("CREATE VIEW active AS SELECT id FROM users");
    db.exec(
        "CREATE TRIGGER orders_audit AFTER INSERT ON orders BEGIN \
         UPDATE users SET name = name WHERE id = NEW.user_id; END",
    );
}

#[test]
fn tables_lists_tables_and_optionally_views_and_system_tables() {
    let db = Db::new();
    sample_schema(&db);
    db.exec("CREATE TABLE seq (id INTEGER PRIMARY KEY AUTOINCREMENT)");
    let v = db.call("tables", &[]).ok().json();
    let names: Vec<&str> = v["tables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["orders", "seq", "users"]);
    assert_eq!(
        v["tables"][0],
        json!({"name": "orders", "schema": "main", "type": "BASE TABLE"})
    );
    assert_eq!(v["meta"], json!({"count": 3, "truncated": false}));
    let v = db.call("tables", &[("include_views", "true")]).ok().json();
    assert!(
        v["tables"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["type"] == "VIEW")
    );
    let v = db.call("tables", &[("include_system", "true")]).ok().json();
    assert!(
        v["tables"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "sqlite_sequence")
    );
    let v = db.call("tables", &[("max_tables", "2")]).ok().json();
    assert_eq!(v["meta"], json!({"count": 2, "truncated": true}));
    let v = db.call("tables", &[("max_tables", "3")]).ok().json();
    assert_eq!(v["meta"], json!({"count": 3, "truncated": false}));
    let v = db.call("tables", &[("schema", "temp")]).ok().json();
    assert_eq!(v["tables"], json!([]));
}

#[test]
fn tables_with_table_describes_its_columns() {
    let db = Db::new();
    sample_schema(&db);
    let v = db.call("tables", &[("table", "users")]).ok().json();
    assert_eq!(
        v["table"],
        json!({"name": "users", "schema": "main", "type": "BASE TABLE"})
    );
    assert_eq!(
        v["columns"][2],
        json!({"name": "name", "ordinal_position": 3, "data_type": "TEXT",
               "is_nullable": true, "default": "'anon'", "is_primary_key": false})
    );
    assert_eq!(v["columns"][0]["is_nullable"], false);
    let v = db.call("tables", &[("table", "active")]).ok().json();
    assert_eq!(v["table"]["type"], "VIEW");
    db.call("tables", &[("table", "nope")])
        .fails(1, "db.table_not_found");
    // A name with quotes is only ever a value.
    db.call("tables", &[("table", "users'); DROP TABLE users; --")])
        .fails(1, "db.table_not_found");
    db.call("tables", &[("table", "users\"")])
        .fails(1, "db.table_not_found");
    assert_eq!(db.rows("SELECT count(*) AS n FROM users")[0]["n"], 0);
}

// --- schema ------------------------------------------------------------------------------------

#[test]
fn schema_reports_every_section() {
    let db = Db::new();
    sample_schema(&db);
    let v = db
        .call(
            "schema",
            &[
                ("table", "orders"),
                ("include_checks", "true"),
                ("include_triggers", "true"),
            ],
        )
        .ok()
        .json();
    assert_eq!(
        v["primary_key"],
        json!({"name": null, "columns": ["id", "line"]})
    );
    // In SQLite only INTEGER PRIMARY KEY (the rowid) is never NULL.
    assert_eq!(v["columns"][0]["is_primary_key"], true);
    assert_eq!(
        v["foreign_keys"],
        json!([{"name": null, "columns": ["user_id"],
                "referenced_table": {"schema": "main", "name": "users"},
                "referenced_columns": ["id"], "on_update": "NO ACTION", "on_delete": "CASCADE"}])
    );
    let idx = v["indexes"].as_array().unwrap();
    assert!(
        idx.contains(&json!({"name": "orders_user", "is_unique": false,
                                  "is_primary": false, "columns": ["user_id", "total"]}))
    );
    assert!(idx.iter().any(|i| i["is_primary"] == true));
    assert_eq!(
        v["checks"],
        json!([{"name": null, "expression": "total >= 0"}])
    );
    assert_eq!(v["triggers"][0]["name"], "orders_audit",);
    assert_eq!(v["triggers"][0]["timing"], "AFTER");
    assert_eq!(v["triggers"][0]["events"], json!(["INSERT"]));
    let v = db
        .call("schema", &[("table", "users"), ("include_checks", "true")])
        .ok()
        .json();
    assert_eq!(v["primary_key"], json!({"name": null, "columns": ["id"]}));
    assert_eq!(v["unique_constraints"][0]["columns"], json!(["email"]));
    assert_eq!(
        v["checks"],
        json!([{"name": "email_len", "expression": "length(email) > 3"}])
    );
    assert!(v.get("triggers").is_none());
}

#[test]
fn schema_include_flags_select_sections() {
    let db = Db::new();
    sample_schema(&db);
    let v = db
        .call(
            "schema",
            &[
                ("table", "orders"),
                ("include_indexes", "false"),
                ("include_foreign_keys", "false"),
                ("include_unique_constraints", "false"),
            ],
        )
        .ok()
        .json();
    let mut keys: Vec<&String> = v.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(keys, ["columns", "primary_key", "table"]);
    db.call("schema", &[("table", "nope")])
        .fails(1, "db.table_not_found");
    db.call("schema", &[("table", "users"), ("schema", "other")])
        .fails(1, "db.table_not_found");
}

// --- transaction -------------------------------------------------------------------------------

#[test]
fn transaction_commits_every_statement() {
    let db = Db::with_users();
    let v = db
        .call(
            "transaction",
            &[(
                "statements",
                r#"["DELETE FROM users WHERE id = 2",
                    {"sql": "UPDATE users SET email = ? WHERE id = ?", "params": ["z@x.com", 1]}]"#,
            )],
        )
        .ok()
        .json();
    assert_eq!(
        v,
        json!({"action": "run", "alias": "app", "committed": true, "driver": "sqlite",
               "results": [{"index": 0, "rows_affected": 1}, {"index": 1, "rows_affected": 1}],
               "status": "ok"})
    );
    assert_eq!(
        db.rows("SELECT email FROM users"),
        [json!({"email": "z@x.com"})]
    );
    db.call(
        "transaction",
        &[
            ("statements", "[\"DELETE FROM users\"]"),
            ("action", "run"),
            ("isolation", "serializable"),
        ],
    )
    .ok();
}

#[test]
fn transaction_rolls_back_everything_when_a_statement_fails() {
    let db = Db::with_users();
    let v = db
        .call(
            "transaction",
            &[(
                "statements",
                r#"["DELETE FROM users WHERE id = 2", "INSERT INTO users (email) VALUES ('a@x.com')"]"#,
            )],
        )
        .fails(1, "db.transaction_failed")
        .json();
    assert_eq!(v["error"]["index"], 1);
    assert_eq!(v["error"]["rolled_back"], true);
    assert_eq!(db.rows("SELECT count(*) AS n FROM users")[0]["n"], 2);
}

#[test]
fn read_only_transactions_refuse_writes() {
    let db = Db::with_users();
    let o = db
        .call(
            "transaction",
            &[
                ("statements", "[\"DELETE FROM users\"]"),
                ("read_only", "true"),
            ],
        )
        .fails(1, "db.transaction_failed");
    assert!(
        o.err.contains("readonly") || o.err.contains("read-only") || o.err.contains("query_only"),
        "{}",
        o.err
    );
    assert_eq!(db.rows("SELECT count(*) AS n FROM users")[0]["n"], 2);
    db.call(
        "transaction",
        &[("statements", "[\"SELECT 1\"]"), ("read_only", "true")],
    )
    .ok();
}

#[test]
fn transaction_timeout_commits_nothing() {
    let db = Db::with_users();
    let o = db
        .call(
            "transaction",
            &[
                (
                    "statements",
                    &serde_json::to_string(&[
                        "DELETE FROM users".to_string(),
                        format!("INSERT INTO users (email) SELECT 'u' || x FROM ({ENDLESS})"),
                    ])
                    .unwrap(),
                ),
                ("timeout_ms", "300"),
            ],
        )
        .fails(124, "db.timeout");
    assert!(o.err.contains("nothing was committed"), "{}", o.err);
    assert_eq!(o.json()["error"]["index"], 1);
    assert_eq!(db.rows("SELECT count(*) AS n FROM users")[0]["n"], 2);
}

// --- error codes ------------------------------------------------------------------------------

#[test]
fn error_codes_are_valid_and_documented() {
    let doc = include_str!("../../../../docs/Data_StateManagement/db.md");
    for c in ERROR_CODES {
        let code = format!("db.{c}");
        assert!(crate::core::status::is_valid_error_code(&code), "{code}");
        assert!(
            doc.contains(&format!("`{code}`")),
            "{code} is not documented"
        );
    }
}

#[test]
fn begin_statements_per_driver() {
    use args::Isolation;
    assert_eq!(
        run::begin_statements(Driver::Postgres, Isolation::Serializable, true),
        ["BEGIN ISOLATION LEVEL SERIALIZABLE READ ONLY"]
    );
    assert_eq!(
        run::begin_statements(Driver::Mysql, Isolation::ReadCommitted, true),
        [
            "SET TRANSACTION ISOLATION LEVEL READ COMMITTED",
            "START TRANSACTION READ ONLY"
        ]
    );
    assert_eq!(
        run::begin_statements(Driver::Mysql, Isolation::Default, false),
        ["START TRANSACTION"]
    );
    assert_eq!(
        run::begin_statements(Driver::Sqlite, Isolation::Default, true),
        ["PRAGMA query_only = ON", "BEGIN"]
    );
}
