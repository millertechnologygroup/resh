//! `db://` verbs and help through the real `resh` binary, on SQLite files in
//! a temporary directory (the working directory of each run). PostgreSQL,
//! MySQL and MariaDB run in tests/db_e2e_docker.rs.

use resh::handles::data::dbh::verb_args;
use serde_json::{Value, json};
use std::path::Path;
use tempfile::TempDir;

struct Run {
    code: i32,
    out: String,
    err: String,
}

impl Run {
    fn json(&self) -> Value {
        serde_json::from_str(self.out.trim())
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {:?}", self.out))
    }

    fn ok(self) -> Self {
        assert_eq!(self.code, 0, "stdout: {}\nstderr: {}", self.out, self.err);
        assert!(self.err.is_empty(), "{}", self.err);
        self
    }

    fn fails(self, exit: i32, code: &str) -> Self {
        assert_eq!(
            self.code, exit,
            "stdout: {}\nstderr: {}",
            self.out, self.err
        );
        assert_eq!(self.json()["error"]["code"], code, "{}", self.out);
        assert_eq!(
            self.err.lines().last().unwrap_or_default(),
            format!(
                "Error: [{code}] {}",
                self.json()["error"]["message"].as_str().unwrap()
            ),
        );
        self
    }

    fn usage(self, code: &str, needle: &str) -> Self {
        assert_eq!(self.code, 2, "stdout: {}\nstderr: {}", self.out, self.err);
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

struct Env {
    tmp: TempDir,
    vars: Vec<(String, String)>,
}

impl Env {
    fn new() -> Self {
        Self {
            tmp: TempDir::new().unwrap(),
            vars: Vec::new(),
        }
    }

    fn var(mut self, k: &str, v: &str) -> Self {
        self.vars.push((k.into(), v.into()));
        self
    }

    fn dir(&self) -> &Path {
        self.tmp.path()
    }

    fn run(&self, args: &[&str]) -> Run {
        let d = self.dir();
        let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
        cmd.current_dir(d).env("HOME", d);
        for (k, _) in std::env::vars() {
            if k.starts_with("DB_") && k.ends_with("_DSN") {
                cmd.env_remove(k);
            }
        }
        for (k, v) in &self.vars {
            cmd.env(k, v);
        }
        let out = cmd.args(args).output().unwrap();
        Run {
            code: out.status.code().unwrap_or(-1),
            out: String::from_utf8(out.stdout).unwrap(),
            err: String::from_utf8(out.stderr).unwrap(),
        }
    }

    /// `app.db` in the working directory, with a users table.
    fn with_app_db(self) -> Self {
        self.run(&[
            "db://sqlite/app.exec",
            "dsn=sqlite:app.db?mode=rwc",
            "sql=CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)",
        ])
        .ok();
        self.run(&[
            "db://sqlite/app.exec",
            "dsn=sqlite:app.db",
            "sql=INSERT INTO users (name) VALUES ('alice'), ('bob'), ('carol')",
        ])
        .ok();
        self
    }
}

// --- help ---------------------------------------------------------------------------

const VERBS: [&str; 7] = [
    "connect",
    "ping",
    "query",
    "exec",
    "tables",
    "schema",
    "transaction",
];

fn golden(verb: Option<&str>) -> &'static str {
    match verb {
        None => include_str!("golden/db_help.txt"),
        Some("connect") => include_str!("golden/db_connect_help.txt"),
        Some("ping") => include_str!("golden/db_ping_help.txt"),
        Some("query") => include_str!("golden/db_query_help.txt"),
        Some("exec") => include_str!("golden/db_exec_help.txt"),
        Some("tables") => include_str!("golden/db_tables_help.txt"),
        Some("schema") => include_str!("golden/db_schema_help.txt"),
        Some("transaction") => include_str!("golden/db_transaction_help.txt"),
        Some(v) => panic!("no golden for {v}"),
    }
}

fn assert_plain_text(out: &str) {
    assert!(out.is_ascii() && !out.contains('\x1b'));
    for l in out.lines() {
        assert!(l.len() <= 80, "line over 80 columns: {l:?}");
        assert!(!l.ends_with(' '), "trailing space: {l:?}");
    }
}

#[test]
fn handle_help_matches_golden_and_lists_registered_verbs() {
    let env = Env::new();
    for form in [
        vec!["db", "--help"],
        vec!["db", "-h"],
        vec!["db", "help"],
        vec!["help", "db"],
        vec!["db://--help"],
        vec!["db://-h"],
        vec!["db://sqlite/app.help"],
    ] {
        let r = env.run(&form).ok();
        assert_eq!(r.out, golden(None), "{form:?}");
    }
    let out = golden(None);
    assert_plain_text(out);
    let listed: Vec<&str> = out
        .split("Available Verbs:\n")
        .nth(1)
        .unwrap()
        .split("\n\n")
        .next()
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(listed, VERBS);
}

#[test]
fn verb_help_matches_golden_and_lists_exactly_the_accepted_options() {
    let env = Env::new();
    for verb in VERBS {
        for form in [
            vec!["db", verb, "--help"],
            vec!["db", verb, "-h"],
            vec!["help", "db", verb],
        ] {
            let r = env.run(&form).ok();
            assert_eq!(r.out, golden(Some(verb)), "{form:?}");
        }
        let in_url = env.run(&[&format!("db://sqlite/app.--help={verb}")]).ok();
        assert_eq!(in_url.out, golden(Some(verb)));
        let out = golden(Some(verb));
        assert_plain_text(out);
        for section in ["Usage:\n", "Example:\n", "Example Output:\n"] {
            assert!(out.contains(section), "{verb}: {section}");
        }
        let usage = out
            .split("Usage:\n")
            .nth(1)
            .unwrap()
            .split("\n\n")
            .next()
            .unwrap();
        let mut listed: Vec<&str> = usage
            .split(['[', ' ', '\n'])
            .filter_map(|w| w.split_once('='))
            .map(|(k, _)| k.trim_start_matches('['))
            .filter(|k| !k.is_empty() && !k.contains('/'))
            .collect();
        listed.sort_unstable();
        listed.dedup();
        let mut expected = verb_args(verb).unwrap();
        expected.sort_unstable();
        assert_eq!(listed, expected, "{verb} usage: {usage}");
    }
    assert!(verb_args("frobnicate").is_none());
}

#[test]
fn unknown_verb_help_is_an_error() {
    let r = Env::new().run(&["db", "querry", "--help"]);
    assert_eq!(r.code, 2);
    assert!(r.err.contains("query"), "{}", r.err);
}

// --- the help examples, run for real -------------------------------------------------

#[test]
fn help_examples_work_on_sqlite() {
    // The examples that rely on the environment, as their notes say.
    let env = Env::new()
        .with_app_db()
        .var("DB_APP_DSN", "sqlite:app.db")
        .var("DB_DB_DSN", "sqlite:app.db");
    let v = env
        .run(&[
            "--json-pretty",
            "db://sqlite/app.query",
            "sql=SELECT * FROM users WHERE id<?",
            "params=[3]",
        ])
        .ok()
        .json();
    assert_eq!(
        v["rows"],
        json!([{"id": 1, "name": "alice"}, {"id": 2, "name": "bob"}])
    );
    assert_eq!(
        v["meta"]["columns"],
        json!([{"name": "id", "type": "INTEGER"}, {"name": "name", "type": "TEXT"}])
    );
    assert_eq!(v["meta"]["row_count"], 2);

    let v = env
        .run(&[
            "--json-pretty",
            "db://sqlite/app.ping",
            "dsn=sqlite:app.db",
            "retries=2",
        ])
        .ok()
        .json();
    assert_eq!(v["status"], "ok");
    assert_eq!(v["attempts"], 1);

    let v = env
        .run(&[
            "--json-pretty",
            "db://sqlite/app.schema",
            "table=users",
            "dsn=sqlite:app.db",
        ])
        .ok()
        .json();
    assert_eq!(
        v["table"],
        json!({"name": "users", "schema": "main", "type": "BASE TABLE"})
    );
    assert_eq!(v["primary_key"], json!({"name": null, "columns": ["id"]}));

    env.run(&[
        "db://sqlite/app.exec",
        "dsn=sqlite:app.db",
        "sql=CREATE TABLE sessions (uid INTEGER)",
    ])
    .ok();
    env.run(&[
        "db://sqlite/app.exec",
        "dsn=sqlite:app.db",
        "sql=INSERT INTO sessions VALUES (7), (7), (7), (8)",
    ])
    .ok();
    let v = env
        .run(&[
            "--json-pretty",
            "db://sqlite/app.exec",
            "sql=DELETE FROM sessions WHERE uid=?",
            "params=[7]",
        ])
        .ok()
        .json();
    assert_eq!(v, json!({"rows_affected": 3}));

    env.run(&[
        "db://sqlite/app.exec",
        "dsn=sqlite:app.db",
        "sql=CREATE TABLE a (id INTEGER)",
    ])
    .ok();
    env.run(&[
        "db://sqlite/app.exec",
        "dsn=sqlite:app.db",
        "sql=CREATE TABLE b (id INTEGER)",
    ])
    .ok();
    env.run(&[
        "db://sqlite/app.exec",
        "dsn=sqlite:app.db",
        "sql=INSERT INTO b VALUES (7)",
    ])
    .ok();
    let v = env
        .run(&[
            "--json-pretty",
            "db://sqlite/db.transaction",
            "statements=[\"DELETE FROM a\",\"DELETE FROM b\"]",
        ])
        .ok()
        .json();
    assert_eq!(v["committed"], true);
    assert_eq!(v["alias"], "db");
    assert_eq!(
        v["results"],
        json!([{"index": 0, "rows_affected": 0}, {"index": 1, "rows_affected": 1}])
    );

    let v = env
        .run(&[
            "db://sqlite/app.tables",
            "dsn=sqlite:app.db",
            "include_views=true",
        ])
        .ok()
        .json();
    assert_eq!(v["meta"]["count"], 4);
    let v = env
        .run(&["db://sqlite/app.connect", "dsn=sqlite:app.db"])
        .ok()
        .json();
    assert_eq!(v["tls"], false);
}

// --- DSN resolution ------------------------------------------------------------------------

#[test]
fn the_dsn_comes_from_dsn_or_the_alias_environment_variable() {
    let env = Env::new()
        .with_app_db()
        .var("DB_MY_APP_DSN", "sqlite:app.db");
    let v = env
        .run(&[
            "db://sqlite/my-app.query",
            "sql=SELECT count(*) AS n FROM users",
        ])
        .ok()
        .json();
    assert_eq!(v["rows"][0]["n"], 3);
    // dsn= wins over the environment.
    env.run(&["db://sqlite/my-app.connect", "dsn=sqlite:missing.db"])
        .fails(1, "db.connect_failed");
    env.run(&["db://sqlite/other.query", "sql=SELECT 1"])
        .usage("db.dsn_missing", "DB_OTHER_DSN");
}

#[test]
fn passwords_in_the_environment_dsn_are_never_printed() {
    let env = Env::new().var(
        "DB_APP_DSN",
        "postgresql://app:Hunter2-Secret@127.0.0.1:1/app",
    );
    let r = env
        .run(&["db://postgres/app.connect", "timeout_ms=2000"])
        .fails(1, "db.connect_failed");
    assert!(!r.out.contains("Hunter2") && !r.err.contains("Hunter2"));
    let r = env
        .run(&[
            "db://postgres/app.ping",
            "detailed=true",
            "retries=1",
            "backoff_ms=0",
        ])
        .fails(1, "db.ping_failed");
    assert!(!r.out.contains("Hunter2") && !r.err.contains("Hunter2"));
}

// --- exit codes and output format ---------------------------------------------------------

#[test]
fn usage_errors_exit_2_and_change_nothing() {
    let env = Env::new().with_app_db();
    env.run(&[
        "db://sqlite/app.query",
        "dsn=sqlite:app.db",
        "sql=SELECT 1",
        "mode=table",
    ])
    .usage("db.invalid_argument", "mode");
    env.run(&[
        "db://sqlite/app.exec",
        "dsn=sqlite:app.db",
        "sql=DELETE FROM users; DELETE FROM x",
    ])
    .usage("db.invalid_argument", "2 statements");
    env.run(&[
        "db://sqlite/app.exec",
        "dsn=sqlite:app.db",
        "sql=DELETE FROM users",
        "dry_run=true",
    ])
    .usage("db.invalid_argument", "does not support dry_run");
    env.run(&[
        "db://sqlite/app.exec",
        "dsn=sqlite:app.db",
        "sql=DELETE FROM users",
        "dry-run",
    ])
    .usage("db.invalid_argument", "nothing was done");
    env.run(&["db://sqlite/app.frob"])
        .usage("db.unknown_verb", "unknown verb");
    env.run(&["db://oracle/app.query"])
        .usage("db.invalid_target", "unknown db driver");
    let v = env
        .run(&[
            "db://sqlite/app.query",
            "dsn=sqlite:app.db",
            "sql=SELECT count(*) AS n FROM users",
        ])
        .ok()
        .json();
    assert_eq!(v["rows"][0]["n"], 3);
}

#[test]
fn failures_print_the_error_object_and_the_stderr_line() {
    let env = Env::new().with_app_db();
    env.run(&[
        "db://sqlite/app.query",
        "dsn=sqlite:app.db",
        "sql=SELECT x FROM nope",
    ])
    .fails(1, "db.query_failed");
    env.run(&["db://sqlite/app.schema", "dsn=sqlite:app.db", "table=nope"])
        .fails(1, "db.table_not_found");
    env.run(&[
        "db://sqlite/app.query",
        "dsn=sqlite:app.db",
        "sql=WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT count(*) FROM c",
        "timeout_ms=200",
    ])
    .fails(124, "db.timeout");
}

#[test]
fn streamed_rows_pretty_print_and_log_queries_goes_to_stderr() {
    let env = Env::new().with_app_db();
    let r = env.run(&[
        "--json-pretty",
        "db://sqlite/app.query",
        "dsn=sqlite:app.db",
        "sql=SELECT name FROM users ORDER BY id",
        "max_rows=2",
        "log_queries=true",
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.err, "db: sql: SELECT name FROM users ORDER BY id\n");
    assert!(r.out.contains("\n  \"meta\": {"), "{}", r.out);
    let v = r.json();
    assert_eq!(v["rows"], json!([{"name": "alice"}, {"name": "bob"}]));
    assert_eq!(v["meta"]["truncated"], true);
}
