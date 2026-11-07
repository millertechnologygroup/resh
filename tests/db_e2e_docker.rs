//! `db://` against real servers in throwaway Docker containers published on
//! 127.0.0.1 only: PostgreSQL 17, MySQL 8.4 and MariaDB 11. Every verb runs
//! on every server twice, in plain text and over TLS verified against a
//! private CA (`tls_mode=verify_full ca_file=`). Also: a statement stopped
//! at timeout_ms is gone from the server, a timed-out transaction commits
//! nothing, untrusted and misnamed certificates are refused, and passwords
//! never appear in output. Run with
//! `cargo test --features e2e-docker --test db_e2e_docker`.
#![cfg(feature = "e2e-docker")]

use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// One server at a time: the machine is memory-constrained.
static SERIAL: Mutex<()> = Mutex::new(());

const PASSWORD: &str = "Db-Pa55word-x9";

/// A container address on a test bridge network: reached from the host
/// without loopback, so the remote TLS default (verify_full) applies.
const BRIDGE_IP: &str = "172.31.213.10";

/// A Docker bridge network for [`BRIDGE_IP`], removed on drop.
struct Network {
    name: String,
}

impl Network {
    fn new() -> Self {
        let name = "resh-db-e2e".to_string();
        // A network left over by an interrupted run.
        let _ = Command::new("docker")
            .args(["network", "rm", &name])
            .output();
        let out = Command::new("docker")
            .args(["network", "create", "--subnet", "172.31.213.0/24", &name])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        Self { name }
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["network", "rm", &self.name])
            .output();
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Postgres,
    Mysql,
    Mariadb,
}

impl Kind {
    fn driver(self) -> &'static str {
        match self {
            Kind::Postgres => "postgres",
            _ => "mysql",
        }
    }
}

/// A private CA and server certificates signed by it.
struct Pki {
    dir: TempDir,
}

impl Pki {
    fn new() -> Self {
        use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, SanType};
        let dir = TempDir::new().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new());
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "resh db test CA");
        let ca = Certificate::from_params(ca_params).unwrap();
        let leaf = |sans: Vec<SanType>, name: &str| {
            let mut p = CertificateParams::new(Vec::<String>::new());
            p.subject_alt_names = sans;
            p.distinguished_name.push(rcgen::DnType::CommonName, "db");
            let c = Certificate::from_params(p).unwrap();
            let d = dir.path().join(name);
            std::fs::create_dir(&d).unwrap();
            std::fs::write(
                d.join("server.crt"),
                c.serialize_pem_with_signer(&ca).unwrap(),
            )
            .unwrap();
            std::fs::write(d.join("server.key"), c.serialize_private_key_pem()).unwrap();
            std::fs::write(d.join("ca.crt"), ca.serialize_pem().unwrap()).unwrap();
        };
        // Names 127.0.0.1: verify_full passes.
        leaf(
            vec![
                SanType::IpAddress("127.0.0.1".parse().unwrap()),
                SanType::IpAddress(BRIDGE_IP.parse().unwrap()),
                SanType::DnsName("localhost".into()),
            ],
            "good",
        );
        // Names another host: only verify_ca passes.
        leaf(
            vec![SanType::DnsName("db.example.invalid".into())],
            "misnamed",
        );
        std::fs::write(dir.path().join("ca.pem"), ca.serialize_pem().unwrap()).unwrap();
        let other = rcgen::generate_simple_self_signed(vec!["x".to_string()]).unwrap();
        std::fs::write(dir.path().join("other.pem"), other.serialize_pem().unwrap()).unwrap();
        use std::os::unix::fs::PermissionsExt;
        for entry in walk(dir.path()) {
            let mode = if entry.is_dir() { 0o755 } else { 0o644 };
            std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        Self { dir }
    }

    fn ca(&self) -> String {
        self.dir.path().join("ca.pem").display().to_string()
    }

    fn other_ca(&self) -> String {
        self.dir.path().join("other.pem").display().to_string()
    }

    fn certs(&self, which: &str) -> PathBuf {
        self.dir.path().join(which)
    }
}

fn walk(p: &Path) -> Vec<PathBuf> {
    let mut out = vec![p.to_path_buf()];
    if p.is_dir() {
        for e in std::fs::read_dir(p).unwrap() {
            out.extend(walk(&e.unwrap().path()));
        }
    }
    out
}

/// A database container, removed on drop.
struct Server {
    id: String,
    port: u16,
    kind: Kind,
}

impl Server {
    /// Starts `kind`, with TLS from `certs` (server.crt, server.key,
    /// ca.crt) when given.
    fn start(kind: Kind, certs: Option<&Path>) -> Self {
        Self::start_on(kind, certs, None)
    }

    /// Like `start`, also attached to `net` at [`BRIDGE_IP`].
    fn start_on(kind: Kind, certs: Option<&Path>, net: Option<&Network>) -> Self {
        let mut cmd = Command::new("docker");
        cmd.args(["run", "-d", "-p"]);
        let (image, port) = match kind {
            Kind::Postgres => ("postgres:17", "5432"),
            Kind::Mysql => ("mysql:8.4", "3306"),
            Kind::Mariadb => ("mariadb:11", "3306"),
        };
        cmd.arg(format!("127.0.0.1::{port}"));
        if let Some(n) = net {
            cmd.args(["--network", &n.name, "--ip", BRIDGE_IP]);
        }
        if let Some(c) = certs {
            cmd.arg("-v").arg(format!("{}:/certs:ro", c.display()));
        }
        match kind {
            Kind::Postgres => {
                cmd.args([
                    "-e",
                    "POSTGRES_USER=app",
                    "-e",
                    &format!("POSTGRES_PASSWORD={PASSWORD}"),
                    "-e",
                    "POSTGRES_DB=app",
                ]);
                if certs.is_some() {
                    // The key must belong to the postgres user, mode 0600.
                    cmd.args([
                        "--entrypoint",
                        "bash",
                        image,
                        "-c",
                        "cp /certs/server.crt /certs/server.key /tmp/ && \
                         chown postgres /tmp/server.key /tmp/server.crt && \
                         chmod 600 /tmp/server.key && \
                         exec docker-entrypoint.sh postgres -c ssl=on \
                         -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key",
                    ]);
                } else {
                    cmd.arg(image);
                }
            }
            Kind::Mysql | Kind::Mariadb => {
                let p = if kind == Kind::Mysql {
                    "MYSQL"
                } else {
                    "MARIADB"
                };
                cmd.args([
                    "-e",
                    &format!("{p}_ROOT_PASSWORD=root-{PASSWORD}"),
                    "-e",
                    &format!("{p}_DATABASE=app"),
                    "-e",
                    &format!("{p}_USER=app"),
                    "-e",
                    &format!("{p}_PASSWORD={PASSWORD}"),
                    image,
                    "--log-bin-trust-function-creators=1",
                ]);
                if certs.is_some() {
                    cmd.args([
                        "--ssl-ca=/certs/ca.crt",
                        "--ssl-cert=/certs/server.crt",
                        "--ssl-key=/certs/server.key",
                    ]);
                }
            }
        }
        let out = cmd.output().expect("docker");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let id = String::from_utf8(out.stdout).unwrap().trim().to_string();
        let o = Command::new("docker")
            .args(["port", &id, &format!("{port}/tcp")])
            .output()
            .unwrap();
        let s = String::from_utf8(o.stdout).unwrap();
        let port = s
            .lines()
            .next()
            .and_then(|l| l.rsplit(':').next())
            .and_then(|p| p.trim().parse().ok())
            .unwrap_or_else(|| panic!("no port: {s}"));
        let server = Self { id, port, kind };
        server.wait_ready();
        server
    }

    fn dsn(&self) -> String {
        let scheme = if self.kind == Kind::Postgres {
            "postgresql"
        } else {
            "mysql"
        };
        format!("{scheme}://app:{PASSWORD}@127.0.0.1:{}/app", self.port)
    }

    /// The DSN by the container's bridge address (a remote host to resh).
    fn remote_dsn(&self) -> String {
        let (scheme, port) = if self.kind == Kind::Postgres {
            ("postgresql", 5432)
        } else {
            ("mysql", 3306)
        };
        format!("{scheme}://app:{PASSWORD}@{BRIDGE_IP}:{port}/app")
    }

    /// Waits until the real server (not the init-time one) answers, using
    /// ping with retries.
    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(180);
        while Instant::now() < deadline {
            let r = self.run(&[&self.url("ping"), "timeout_ms=2000", "tls_mode=disable"]);
            if r.code == 0 {
                // MySQL images restart once after init; make sure it stays up.
                std::thread::sleep(Duration::from_millis(1500));
                if self.run(&[&self.url("ping"), "tls_mode=disable"]).code == 0 {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(1000));
        }
        let logs = Command::new("docker")
            .args(["logs", &self.id])
            .output()
            .unwrap();
        panic!(
            "server did not start: {}",
            String::from_utf8_lossy(&logs.stderr)
        );
    }

    fn url(&self, verb: &str) -> String {
        format!("db://{}/app.{verb}", self.kind.driver())
    }

    /// Runs resh with DB_APP_DSN set to this server.
    fn run(&self, args: &[&str]) -> Run {
        run_with(args, &[("DB_APP_DSN", &self.dsn())])
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.id]).output();
    }
}

struct Run {
    code: i32,
    out: String,
    err: String,
}

impl Run {
    fn json(&self) -> Value {
        serde_json::from_str(self.out.trim())
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {:?}\n{}", self.out, self.err))
    }

    fn ok(self) -> Self {
        assert_eq!(self.code, 0, "stdout: {}\nstderr: {}", self.out, self.err);
        self
    }

    fn fails(self, exit: i32, code: &str) -> Self {
        assert_eq!(
            self.code, exit,
            "stdout: {}\nstderr: {}",
            self.out, self.err
        );
        assert_eq!(self.json()["error"]["code"], code, "{}", self.out);
        assert!(
            self.err.contains(&format!("Error: [{code}] ")),
            "{}",
            self.err
        );
        assert!(!self.out.contains(PASSWORD) && !self.err.contains(PASSWORD));
        self
    }
}

fn run_with(args: &[&str], env: &[(&str, &str)]) -> Run {
    let tmp = TempDir::new().unwrap();
    run_in(tmp.path(), args, env)
}

/// Runs resh with `dir` as working directory and HOME.
fn run_in(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Run {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
    cmd.current_dir(dir).env("HOME", dir);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.args(args).output().unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        out: String::from_utf8(out.stdout).unwrap(),
        err: String::from_utf8(out.stderr).unwrap(),
    }
}

/// Every verb on `s`, with `extra` (TLS) arguments on each call. Table
/// names start with `p` so plain and TLS runs do not collide.
fn every_verb(s: &Server, extra: &[&str], p: &str, expect_tls: bool) {
    let pg = s.kind == Kind::Postgres;
    let call = |verb: &str, args: &[&str]| -> Run {
        let url = s.url(verb);
        let mut a: Vec<&str> = vec![&url];
        a.extend_from_slice(args);
        a.extend_from_slice(extra);
        s.run(&a)
    };
    let ph = |n: usize| if pg { format!("${n}") } else { "?".to_string() };

    // connect
    let v = call("connect", &[]).ok().json();
    assert_eq!(v["database"], "app");
    assert_eq!(v["tls"], expect_tls, "{v}");
    assert!(v["user"].as_str().unwrap().starts_with("app"));
    if s.kind == Kind::Mariadb {
        assert!(v["server_version"].as_str().unwrap().contains("MariaDB"));
    }
    // ping
    let v = call("ping", &[]).ok().json();
    assert_eq!(v["status"], "ok");

    // exec: schema objects
    let users = format!("{p}_users");
    let orders = format!("{p}_orders");
    for sql in if pg {
        vec![
            format!(
                "CREATE TABLE {users} (id SERIAL PRIMARY KEY, email TEXT NOT NULL UNIQUE, \
                 active BOOLEAN, score NUMERIC(10,2), data BYTEA, created TIMESTAMP, \
                 born DATE, meta JSONB, CONSTRAINT {p}_email_len CHECK (length(email) > 3))"
            ),
            format!(
                "CREATE TABLE {orders} (id INT, line INT, user_id INT REFERENCES {users}(id) \
                 ON DELETE CASCADE, total NUMERIC(8,2), PRIMARY KEY (id, line))"
            ),
            format!("CREATE INDEX {p}_orders_user ON {orders} (user_id, total)"),
            format!("CREATE VIEW {p}_active AS SELECT id FROM {users} WHERE active"),
            format!(
                "CREATE FUNCTION {p}_noop() RETURNS trigger AS $$ BEGIN RETURN NEW; END; $$ \
                 LANGUAGE plpgsql"
            ),
            format!(
                "CREATE TRIGGER {p}_audit AFTER INSERT OR UPDATE ON {orders} \
                 FOR EACH ROW EXECUTE FUNCTION {p}_noop()"
            ),
        ]
    } else {
        vec![
            format!(
                "CREATE TABLE {users} (id INT AUTO_INCREMENT PRIMARY KEY, \
                 email VARCHAR(100) NOT NULL UNIQUE, active BOOLEAN, score DECIMAL(10,2), \
                 data VARBINARY(16), created DATETIME, born DATE, meta JSON, \
                 CONSTRAINT {p}_email_len CHECK (length(email) > 3))"
            ),
            format!(
                "CREATE TABLE {orders} (id INT, line INT, user_id INT, total DECIMAL(8,2), \
                 PRIMARY KEY (id, line), CONSTRAINT {p}_fk FOREIGN KEY (user_id) \
                 REFERENCES {users}(id) ON DELETE CASCADE)"
            ),
            format!("CREATE INDEX {p}_orders_user ON {orders} (user_id, total)"),
            format!("CREATE VIEW {p}_active AS SELECT id FROM {users} WHERE active"),
            format!(
                "CREATE TRIGGER {p}_audit AFTER INSERT ON {orders} FOR EACH ROW \
                 SET @resh_last = NEW.id"
            ),
        ]
    } {
        call("exec", &[&format!("sql={sql}")]).ok();
    }

    // exec with bound parameters, including SQL-looking text
    let evil = "x'); DROP TABLE users; --";
    let insert = format!(
        "sql=INSERT INTO {users} (email, active, score, data, created, born, meta) \
         VALUES ({}, {}, {}, {}, {}, {}, {})",
        ph(1),
        ph(2),
        if pg { "$3::numeric".into() } else { ph(3) },
        if pg {
            "decode('00ff', 'hex')".into()
        } else {
            "x'00ff'".to_string()
        },
        if pg { "$4::timestamp".into() } else { ph(4) },
        if pg { "$5::date".into() } else { ph(5) },
        if pg { "$6::jsonb".into() } else { ph(6) },
    );
    let params = json!([
        "a@x.com",
        true,
        "12.5",
        "2024-05-01 12:30:00",
        "2020-02-03",
        "{\"k\":[1,2]}"
    ]);
    let mut args = vec![insert.clone(), format!("params={params}")];
    if !pg {
        args.push("return_last_insert_id=true".into());
    }
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    let v = call("exec", &a).ok().json();
    assert_eq!(v["rows_affected"], 1);
    if !pg {
        assert_eq!(v["last_insert_id"], 1);
    }
    let v = call(
        "exec",
        &[
            &format!(
                "sql=INSERT INTO {users} (email, active) VALUES ({}, {})",
                ph(1),
                ph(2)
            ),
            &format!("params={}", json!([evil, false])),
        ],
    )
    .ok()
    .json();
    assert_eq!(v["rows_affected"], 1);
    call(
        "exec",
        &[&format!(
            "sql=INSERT INTO {orders} (id, line, user_id, total) VALUES (1, 1, 1, 9.99)"
        )],
    )
    .ok();
    if pg {
        assert_eq!(
            call(
                "exec",
                &["sql=INSERT INTO t VALUES (1)", "return_last_insert_id=true"]
            )
            .code,
            2
        );
    }

    // query: typed rows
    let v = call(
        "query",
        &[&format!(
            "sql=SELECT id, email, active, score, data, created, born, meta FROM {users} \
             ORDER BY id"
        )],
    )
    .ok()
    .json();
    let first = &v["rows"][0];
    assert_eq!(first["id"], 1);
    assert_eq!(first["email"], "a@x.com");
    assert_eq!(first["active"], true);
    assert_eq!(first["score"], "12.50");
    assert_eq!(first["born"], "2020-02-03");
    assert_eq!(first["created"], "2024-05-01T12:30:00");
    if pg {
        assert_eq!(first["data"], "base64:AP8=");
        assert_eq!(first["meta"], json!({"k": [1, 2]}));
    } else {
        // VARBINARY that is not UTF-8 stays base64.
        assert_eq!(first["data"], "base64:AP8=");
        if s.kind == Kind::Mysql {
            assert_eq!(first["meta"], json!({"k": [1, 2]}));
        } else {
            // MariaDB JSON is text.
            let m: Value = serde_json::from_str(first["meta"].as_str().unwrap()).unwrap();
            assert_eq!(m, json!({"k": [1, 2]}));
        }
    }
    assert_eq!(v["rows"][1]["email"], evil);
    assert_eq!(v["meta"]["row_count"], 2);
    assert_eq!(v["meta"]["columns"][0]["name"], "id");

    let v = call(
        "query",
        &[
            &format!("sql=SELECT email FROM {users} WHERE email = {}", ph(1)),
            &format!("params={}", json!([evil])),
        ],
    )
    .ok()
    .json();
    assert_eq!(v["rows"], json!([{"email": evil}]));
    let v = call(
        "query",
        &[
            &format!("sql=SELECT count(*) AS n FROM {users}"),
            "mode=scalar",
        ],
    )
    .ok()
    .json();
    assert_eq!(v["value"], 2);
    let v = call(
        "query",
        &[
            &format!("sql=SELECT id FROM {users} ORDER BY id"),
            "max_rows=1",
        ],
    )
    .ok()
    .json();
    assert_eq!(v["meta"]["truncated"], true);
    let v = call(
        "query",
        &[
            &format!(
                "sql=UPDATE {users} SET active = {} WHERE id = 2",
                if pg { "true" } else { "1" }
            ),
            "mode=exec",
        ],
    )
    .ok()
    .json();
    assert_eq!(v["rows_affected"], 1);
    call("query", &["sql=SELECT nope FROM nothing"]).fails(1, "db.query_failed");
    assert_eq!(call("query", &["sql=SELECT 1; SELECT 2"]).code, 2);
    if pg {
        let r =
            call("query", &["sql=SELECT point(1, 2) AS p"]).fails(1, "db.unsupported_column_type");
        assert!(r.err.contains("p::text"), "{}", r.err);
        let v = call(
            "query",
            &[
                "sql=SELECT gen_random_uuid() IS NOT NULL AS u, '10.0.0.0/8'::cidr AS c, \
               ARRAY[1,2] AS a, interval '1 day' AS i, 'NaN'::float8 AS f",
            ],
        )
        .ok()
        .json();
        assert_eq!(
            v["rows"][0],
            json!({"u": true, "c": "10.0.0.0/8", "a": [1, 2],
                   "i": {"months": 0, "days": 1, "microseconds": 0}, "f": "NaN"})
        );
    }

    // tables
    let v = call("tables", &[]).ok().json();
    let names: Vec<&str> = v["tables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&users.as_str()) && names.contains(&orders.as_str()),
        "{names:?}"
    );
    assert!(!names.contains(&format!("{p}_active").as_str()));
    let v = call("tables", &["include_views=true"]).ok().json();
    assert!(
        v["tables"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == format!("{p}_active") && t["type"] == "VIEW")
    );
    let v = call(
        "tables",
        &[
            "include_system=true",
            "include_views=true",
            "max_tables=100000",
        ],
    )
    .ok()
    .json();
    let schemas: Vec<&str> = v["tables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["schema"].as_str().unwrap())
        .collect();
    assert!(schemas.contains(&if pg {
        "pg_catalog"
    } else {
        "information_schema"
    }));
    let v = call("tables", &[&format!("table={users}")]).ok().json();
    assert_eq!(v["table"]["name"], users);
    assert_eq!(v["columns"][0]["is_primary_key"], true);
    assert_eq!(v["columns"][1]["is_nullable"], false);
    call("tables", &["table=nope'; DROP TABLE x; --"]).fails(1, "db.table_not_found");

    // schema: every section
    let v = call(
        "schema",
        &[
            &format!("table={orders}"),
            "include_checks=true",
            "include_triggers=true",
        ],
    )
    .ok()
    .json();
    assert_eq!(v["primary_key"]["columns"], json!(["id", "line"]));
    assert_eq!(v["foreign_keys"][0]["columns"], json!(["user_id"]));
    assert_eq!(v["foreign_keys"][0]["referenced_table"]["name"], users);
    assert_eq!(v["foreign_keys"][0]["referenced_columns"], json!(["id"]));
    assert_eq!(v["foreign_keys"][0]["on_delete"], "CASCADE");
    assert!(
        v["indexes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["name"] == format!("{p}_orders_user")
                && i["columns"] == json!(["user_id", "total"])),
        "{}",
        v["indexes"]
    );
    assert_eq!(v["triggers"][0]["name"], format!("{p}_audit"));
    assert_eq!(v["triggers"][0]["timing"], "AFTER");
    assert!(
        v["triggers"][0]["events"]
            .as_array()
            .unwrap()
            .contains(&json!("INSERT"))
    );
    let v = call(
        "schema",
        &[&format!("table={users}"), "include_checks=true"],
    )
    .ok()
    .json();
    assert!(
        v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == format!("{p}_email_len")),
        "{}",
        v["checks"]
    );
    assert_eq!(v["unique_constraints"][0]["columns"], json!(["email"]));
    assert_eq!(v["table"]["schema"], if pg { "public" } else { "app" });
    call("schema", &["table=nope"]).fails(1, "db.table_not_found");

    // transaction: commit, rollback, isolation, read-only
    let count = |t: &str| -> i64 {
        call(
            "query",
            &[&format!("sql=SELECT count(*) AS n FROM {t}"), "mode=scalar"],
        )
        .ok()
        .json()["value"]
            .as_i64()
            .unwrap()
    };
    let stmts = json!([
        format!("DELETE FROM {orders}"),
        {"sql": format!("UPDATE {users} SET email = {} WHERE id = {}", ph(1), ph(2)), "params": ["z@x.com", 1]},
    ]);
    let v = call(
        "transaction",
        &[&format!("statements={stmts}"), "isolation=serializable"],
    )
    .ok()
    .json();
    assert_eq!(v["committed"], true);
    assert_eq!(v["results"][1]["rows_affected"], 1);
    assert_eq!(count(&orders), 0);
    let stmts = json!([
        format!("DELETE FROM {users} WHERE id = 2"),
        format!("INSERT INTO {users} (email) VALUES ('z@x.com')"),
    ]);
    let v = call(
        "transaction",
        &[&format!("statements={stmts}"), "isolation=read_committed"],
    )
    .fails(1, "db.transaction_failed")
    .json();
    assert_eq!(v["error"]["index"], 1);
    assert_eq!(v["error"]["rolled_back"], true);
    assert_eq!(count(&users), 2);
    let stmts = json!([format!("DELETE FROM {users}")]);
    call(
        "transaction",
        &[&format!("statements={stmts}"), "read_only=true"],
    )
    .fails(1, "db.transaction_failed");
    assert_eq!(count(&users), 2);

    // timeouts stop the statement on the server
    let sleep = if pg {
        "SELECT pg_sleep(30)"
    } else {
        "SELECT SLEEP(30)"
    };
    let start = Instant::now();
    let r = call("query", &[&format!("sql={sleep}"), "timeout_ms=1500"]).fails(124, "db.timeout");
    assert!(r.err.contains("cancelled on the server"), "{}", r.err);
    assert!(start.elapsed() < Duration::from_secs(10));
    let running = if pg {
        format!(
            "sql=SELECT count(*) FROM pg_stat_activity WHERE query = '{sleep}' \
             AND state = 'active'"
        )
    } else {
        format!(
            "sql=SELECT count(*) FROM information_schema.processlist \
             WHERE info = '{sleep}'"
        )
    };
    let mut gone = false;
    for _ in 0..20 {
        let v = call("query", &[&running, "mode=scalar"]).ok().json();
        if v["value"] == 0 {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(gone, "the timed-out statement still runs on the server");
    let stmts = json!([format!("DELETE FROM {users}"), sleep]);
    let r = call(
        "transaction",
        &[&format!("statements={stmts}"), "timeout_ms=1500"],
    )
    .fails(124, "db.timeout");
    assert!(r.err.contains("nothing was committed"), "{}", r.err);
    assert_eq!(count(&users), 2);
}

fn tls_args(pki: &Pki) -> Vec<String> {
    vec![
        "tls_mode=verify_full".into(),
        format!("ca_file={}", pki.ca()),
    ]
}

fn plain_and_tls(kind: Kind) {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let pki = Pki::new();
    let s = Server::start(kind, Some(&pki.certs("good")));
    every_verb(&s, &["tls_mode=disable"], "plain", false);
    let tls = tls_args(&pki);
    let tls: Vec<&str> = tls.iter().map(String::as_str).collect();
    every_verb(&s, &tls, "tls", true);

    // ca_file alone implies verify_full.
    let ca = format!("ca_file={}", pki.ca());
    let v = s.run(&[&s.url("connect"), &ca]).ok().json();
    assert_eq!(v["tls"], true);
    let v = s
        .run(&[&s.url("connect"), "tls_mode=verify_ca", &ca])
        .ok()
        .json();
    assert_eq!(v["tls"], true);
    // Without the CA, or with another CA, verification fails.
    s.run(&[&s.url("connect"), "tls_mode=verify_full"])
        .fails(1, "db.tls_failed");
    s.run(&[&s.url("connect"), "tls_mode=verify_ca"])
        .fails(1, "db.tls_failed");
    let other = format!("ca_file={}", pki.other_ca());
    s.run(&[&s.url("query"), "sql=SELECT 1", &other])
        .fails(1, "db.tls_failed");
    // require encrypts without checking the certificate.
    let v = s.run(&[&s.url("connect"), "tls_mode=require"]).ok().json();
    assert_eq!(v["tls"], true);
    // Every verb checks the certificate.
    for (verb, args) in [
        ("ping", vec![]),
        ("exec", vec!["sql=DELETE FROM plain_orders"]),
        ("tables", vec![]),
        ("schema", vec!["table=plain_users"]),
        (
            "transaction",
            vec!["statements=[\"DELETE FROM plain_orders\"]"],
        ),
    ] {
        let mut a = vec![s.url(verb)];
        a.extend(args.iter().map(|x| x.to_string()));
        a.push("tls_mode=verify_full".into());
        let a: Vec<&str> = a.iter().map(String::as_str).collect();
        let r = s.run(&a);
        assert_ne!(r.code, 0, "{verb}: {}", r.out);
        assert!(r.out.contains("db.tls_failed"), "{verb}: {}", r.out);
    }
    // A wrong password: no password in the output.
    let bad = s.dsn().replace(PASSWORD, "wrong-password");
    let r = run_with(&[&s.url("connect"), &format!("dsn={bad}")], &[]).fails(1, "db.auth_failed");
    assert!(!r.err.contains("wrong-password"), "{}", r.err);
}

fn misnamed_certificate(kind: Kind) {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let pki = Pki::new();
    let s = Server::start(kind, Some(&pki.certs("misnamed")));
    let ca = format!("ca_file={}", pki.ca());
    // The chain is trusted, but the certificate names another host.
    let r = s
        .run(&[&s.url("connect"), "tls_mode=verify_full", &ca])
        .fails(1, "db.tls_failed");
    assert!(r.err.contains("not valid for name"), "{}", r.err);
    // verify_ca also checks the name with sqlx 0.8.6 and rustls 0.23.46
    // (sqlx skips only the older form of the name error), so it fails
    // closed too. A known issue, documented.
    s.run(&[&s.url("connect"), "tls_mode=verify_ca", &ca])
        .fails(1, "db.tls_failed");
    s.run(&[
        &s.url("query"),
        "sql=SELECT 1 AS one",
        "tls_mode=verify_ca",
        &ca,
    ])
    .fails(1, "db.tls_failed");
    // Plain text still works on this server.
    let v = s
        .run(&[&s.url("query"), "sql=SELECT 1 AS one", "tls_mode=disable"])
        .ok()
        .json();
    assert_eq!(v["rows"], json!([{"one": 1}]));
}

#[test]
fn postgres_every_verb_plain_and_tls() {
    plain_and_tls(Kind::Postgres);
}

#[test]
fn mysql_every_verb_plain_and_tls() {
    plain_and_tls(Kind::Mysql);
}

#[test]
fn mariadb_every_verb_plain_and_tls() {
    plain_and_tls(Kind::Mariadb);
}

#[test]
fn postgres_checks_the_certificate_name() {
    misnamed_certificate(Kind::Postgres);
}

#[test]
fn mysql_checks_the_certificate_name() {
    misnamed_certificate(Kind::Mysql);
}

#[test]
fn mariadb_checks_the_certificate_name() {
    misnamed_certificate(Kind::Mariadb);
}

/// Without TLS on the server: require and verify modes fail, prefer falls
/// back to plain text.
#[test]
fn postgres_without_tls() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let net = Network::new();
    let s = Server::start_on(Kind::Postgres, None, Some(&net));
    let v = s.run(&[&s.url("connect")]).ok().json();
    assert_eq!(v["tls"], false);
    for mode in ["require", "verify_ca", "verify_full"] {
        s.run(&[&s.url("connect"), &format!("tls_mode={mode}")])
            .fails(1, "db.tls_failed");
    }
    // A remote address defaults to verify_full: no TLS, no connection.
    let remote = s.remote_dsn();
    let env = [("DB_APP_DSN", remote.as_str())];
    let r = run_with(&[&s.url("connect")], &env).fails(1, "db.tls_failed");
    assert!(r.err.contains("does not support TLS"), "{}", r.err);
    let v = run_with(&[&s.url("connect"), "tls_mode=disable"], &env)
        .ok()
        .json();
    assert_eq!(v["tls"], false);
    let v = run_with(&[&s.url("connect"), "tls_mode=prefer"], &env)
        .ok()
        .json();
    assert_eq!(v["tls"], false);
}

/// The default TLS mode for a remote host is verify_full: a server whose
/// certificate a private CA signed is refused without `ca_file=` and
/// verified with it; an explicit tls_mode wins; 127.0.0.1 uses prefer.
fn remote_default(kind: Kind) {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let pki = Pki::new();
    let net = Network::new();
    let s = Server::start_on(kind, Some(&pki.certs("good")), Some(&net));
    let remote = s.remote_dsn();
    let env = [("DB_APP_DSN", remote.as_str())];
    let ca = format!("ca_file={}", pki.ca());
    for (verb, args) in [
        ("connect", vec![]),
        ("ping", vec![]),
        ("query", vec!["sql=SELECT 1 AS one"]),
        ("exec", vec!["sql=CREATE TABLE r (id INT)"]),
        ("tables", vec![]),
        ("schema", vec!["table=r"]),
        (
            "transaction",
            vec!["statements=[\"INSERT INTO r VALUES (1)\"]"],
        ),
    ] {
        let url = s.url(verb);
        let mut a: Vec<&str> = vec![&url];
        a.extend(args.iter().copied());
        // Without the CA: refused.
        let r = run_with(&a, &env).fails(1, "db.tls_failed");
        assert!(r.err.contains("UnknownIssuer"), "{verb}: {}", r.err);
        // With it: verified.
        a.push(&ca);
        run_with(&a, &env).ok();
    }
    let v = run_with(&[&s.url("connect"), &ca], &env).ok().json();
    assert_eq!(v["tls"], true);
    // An SSL mode in the DSN is used as given.
    let in_dsn = if kind == Kind::Postgres {
        format!("{remote}?sslmode=disable")
    } else {
        format!("{remote}?ssl-mode=disabled")
    };
    let v = run_with(
        &[&s.url("query"), "sql=SELECT count(*) AS n FROM r"],
        &[("DB_APP_DSN", &in_dsn)],
    )
    .ok()
    .json();
    assert_eq!(v["rows"][0]["n"], 1);
    // An explicit tls_mode wins over the default.
    let v = run_with(&[&s.url("connect"), "tls_mode=require"], &env)
        .ok()
        .json();
    assert_eq!(v["tls"], true);
    let v = run_with(&[&s.url("connect"), "tls_mode=disable"], &env)
        .ok()
        .json();
    assert_eq!(v["tls"], false);
    // 127.0.0.1 (the published port): prefer, encrypted but not verified.
    let v = s.run(&[&s.url("connect")]).ok().json();
    assert_eq!(v["tls"], true);
    if kind == Kind::Postgres {
        // The connect and tables help examples, as written.
        let dir = TempDir::new().unwrap();
        std::fs::copy(pki.ca(), dir.path().join("ca.pem")).unwrap();
        let v = run_in(
            dir.path(),
            &[
                "--json-pretty",
                "db://postgres/app.connect",
                "ca_file=ca.pem",
            ],
            &env,
        )
        .ok()
        .json();
        assert_eq!(v["tls"], true);
        assert_eq!(v["database"], "app");
        let v = s
            .run(&[
                "--json-pretty",
                "db://postgres/app.tables",
                "include_views=true",
            ])
            .ok()
            .json();
        assert_eq!(v["tables"][0]["name"], "r");
    }
}

#[test]
fn postgres_remote_hosts_are_verified_by_default() {
    remote_default(Kind::Postgres);
}

#[test]
fn mysql_remote_hosts_are_verified_by_default() {
    remote_default(Kind::Mysql);
}

#[test]
fn mariadb_remote_hosts_are_verified_by_default() {
    remote_default(Kind::Mariadb);
}

/// MySQL generates a self-signed certificate: TLS by default (prefer), but
/// not trusted by verify_full.
#[test]
fn mysql_default_certificate_is_not_trusted() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let s = Server::start(Kind::Mysql, None);
    let v = s.run(&[&s.url("connect")]).ok().json();
    assert_eq!(v["tls"], true);
    s.run(&[&s.url("connect"), "tls_mode=verify_full"])
        .fails(1, "db.tls_failed");
}

/// ping retries until the server answers.
#[test]
fn ping_waits_for_a_starting_server() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    // A port that is reserved but not yet listening: start the server on it
    // after the first attempts have failed.
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let dsn = format!("postgresql://app:{PASSWORD}@127.0.0.1:{port}/app");
    let child = std::thread::spawn(move || {
        run_with(
            &[
                "db://postgres/app.ping",
                "retries=10",
                "backoff_ms=2000",
                "timeout_ms=2000",
                "detailed=true",
            ],
            &[("DB_APP_DSN", &dsn)],
        )
    });
    std::thread::sleep(Duration::from_secs(1));
    let out = Command::new("docker")
        .args([
            "run",
            "-d",
            "--rm",
            "-p",
            &format!("127.0.0.1:{port}:5432"),
            "-e",
            "POSTGRES_USER=app",
            "-e",
            &format!("POSTGRES_PASSWORD={PASSWORD}"),
            "-e",
            "POSTGRES_DB=app",
            "postgres:17",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let id = String::from_utf8(out.stdout).unwrap().trim().to_string();
    let r = child.join().unwrap();
    let _ = Command::new("docker").args(["rm", "-f", &id]).output();
    let v = r.ok().json();
    assert_eq!(v["status"], "ok");
    assert!(v["attempts"].as_u64().unwrap() > 1, "{v}");
}
