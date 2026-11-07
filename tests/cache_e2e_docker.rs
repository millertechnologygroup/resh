//! `cache://` against real servers in throwaway Docker containers (the
//! official redis and memcached images), published on 127.0.0.1 only:
//! every verb on both backends, Redis AUTH, Unix sockets and TLS, the help
//! examples, and a server that stops answering.
//! Run with `cargo test --features e2e-docker --test cache_e2e_docker`.
#![cfg(feature = "e2e-docker")]

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::process::Command;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const REDIS_IMAGE: &str = "redis:7.4-alpine";
const MEMCACHED_IMAGE: &str = "memcached:1.6-alpine";

/// A container, removed on drop.
struct Container {
    id: String,
    port: u16,
    _dir: Option<TempDir>,
}

impl Container {
    fn start(
        image: &str,
        inner_port: u16,
        extra: &[&str],
        cmd: &[&str],
        dir: Option<TempDir>,
    ) -> Self {
        let out = Command::new("docker")
            .args(["run", "-d", "--rm", "-p"])
            .arg(format!("127.0.0.1::{inner_port}"))
            .args(extra)
            .arg(image)
            .args(cmd)
            .output()
            .expect("docker");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let id = String::from_utf8(out.stdout).unwrap().trim().to_string();
        let o = Command::new("docker")
            .args(["port", &id, &format!("{inner_port}/tcp")])
            .output()
            .unwrap();
        let s = String::from_utf8(o.stdout).unwrap();
        let port = s
            .lines()
            .next()
            .and_then(|l| l.rsplit(':').next())
            .and_then(|p| p.trim().parse().ok())
            .unwrap_or_else(|| panic!("no port: {s}"));
        Self {
            id,
            port,
            _dir: dir,
        }
    }

    fn redis(cmd: &[&str]) -> Self {
        let mut full = vec!["redis-server"];
        full.extend_from_slice(cmd);
        let c = Self::start(REDIS_IMAGE, 6379, &[], &full, None);
        c.wait_ready(&["exec", &c.id, "redis-cli", "ping"]);
        c
    }

    /// Items are limited to 64 KiB, so the size limit is easy to reach.
    fn memcached() -> Self {
        let c = Self::start(
            MEMCACHED_IMAGE,
            11211,
            &[],
            &["-I", "64k", "-o", "slab_chunk_max=32"],
            None,
        );
        let url = c.memcached_url();
        let deadline = Instant::now() + Duration::from_secs(20);
        while resh(&["cache://memcached/w.connect", &url]).code != 0 {
            assert!(Instant::now() < deadline, "memcached did not start");
            std::thread::sleep(Duration::from_millis(100));
        }
        c
    }

    fn wait_ready(&self, docker_args: &[&str]) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let o = Command::new("docker").args(docker_args).output().unwrap();
            // A server with requirepass answers NOAUTH: it is up.
            let text = String::from_utf8_lossy(&o.stdout);
            if o.status.success() && (text.contains("PONG") || text.contains("NOAUTH")) {
                return;
            }
            assert!(Instant::now() < deadline, "container did not start");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn redis_url(&self) -> String {
        format!("url=redis://127.0.0.1:{}/0", self.port)
    }

    fn memcached_url(&self) -> String {
        format!("url=memcache://127.0.0.1:{}", self.port)
    }

    fn redis_cli(&self, args: &[&str]) -> String {
        let o = Command::new("docker")
            .args(["exec", &self.id, "redis-cli"])
            .args(args)
            .output()
            .unwrap();
        assert!(o.status.success());
        String::from_utf8(o.stdout).unwrap().trim().to_string()
    }

    fn docker(&self, verb: &str) {
        assert!(
            Command::new("docker")
                .args([verb, &self.id])
                .status()
                .unwrap()
                .success()
        );
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.id]).output();
    }
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    json: Value,
}

fn resh(args: &[&str]) -> Run {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
    cmd.env_remove("SSH_AUTH_SOCK").args(args);
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        json: serde_json::from_str(&stdout).unwrap_or(Value::Null),
        stdout,
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

/// Runs `cache://<backend>/e.<verb>` with `args` and the server url.
fn verb(backend: &str, url: &str, verb: &str, args: &[&str]) -> Run {
    let stage = format!("cache://{backend}/e.{verb}");
    let mut argv = vec![stage.as_str()];
    argv.extend_from_slice(args);
    argv.push(url);
    resh(&argv)
}

fn ok(r: &Run) -> &Value {
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    &r.json
}

fn fails(r: &Run, exit: i32, code: &str) {
    assert_eq!(r.code, exit, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(r.json["error"]["code"], code, "{}", r.stdout);
    assert!(
        r.stderr.starts_with(&format!("Error: [{code}] ")),
        "{}",
        r.stderr
    );
}

/// The verbs every backend must pass, against `url`.
fn common_flow(b: &str, url: &str) {
    let v = |name: &str, args: &[&str]| verb(b, url, name, args);
    assert_eq!(ok(&v("connect", &[]))["status"], "connected");

    // set / get, values stored exactly; numeric keys are keys.
    assert_eq!(
        *ok(&v("set", &["key=123", "value=42"])),
        json!({"alias": "e", "backend": b, "key": "123", "stored": true})
    );
    assert_eq!(
        *ok(&v("get", &["key=123"])),
        json!({"alias": "e", "backend": b, "key": "123", "value": "42", "hit": true})
    );
    ok(&v("set", &["key=q", "value= \"x\" "]));
    assert_eq!(ok(&v("get", &["key=q"]))["value"], " \"x\" ");
    let r = v("get", &["key=missing", "default=none"]);
    assert_eq!(ok(&r)["value"], "none");
    assert_eq!(r.json["hit"], false);

    // Encodings.
    ok(&v(
        "set",
        &["key=j", "value={ \"a\": [1, 2] }", "encode=json"],
    ));
    assert_eq!(ok(&v("get", &["key=j"]))["value"], r#"{"a":[1,2]}"#);
    assert_eq!(
        ok(&v("get", &["key=j", "decode=json"]))["value"],
        json!({"a": [1, 2]})
    );
    ok(&v("set", &["key=bin", "value=AAEC/w==", "encode=bytes"]));
    assert_eq!(
        ok(&v("get", &["key=bin", "decode=bytes"]))["value"],
        "AAEC/w=="
    );
    fails(&v("get", &["key=bin"]), 1, "cache.decode_failed");

    // Multi-key with a namespace.
    let r = v(
        "set",
        &[
            r#"keys=["a","b"]"#,
            r#"values=["x",{"n":1}]"#,
            "namespace=ns",
            "ttl_ms=60000",
        ],
    );
    assert_eq!(ok(&r)["total_stored"], 2);
    let r = v("get", &[r#"keys=["a","zz","b"]"#, "namespace=ns"]);
    assert_eq!(
        ok(&r)["results"],
        json!([{"key": "a", "value": "x", "hit": true},
               {"key": "zz", "value": null, "hit": false},
               {"key": "b", "value": "{\"n\":1}", "hit": true}])
    );
    assert_eq!(ok(&v("get", &["key=ns:a"]))["value"], "x");
    let r = v("exists", &[r#"keys=["a","zz"]"#, "namespace=ns"]);
    assert_eq!(ok(&r)["total_exists"], 1);
    assert_eq!(ok(&v("exists", &["key=zz"]))["exists"], false);

    // ttl.
    let r = v("ttl", &["key=a", "namespace=ns"]);
    assert_eq!(ok(&r)["exists"], true);
    assert_eq!(r.json["supports_ttl"], true);
    assert_eq!(r.json["has_expiry"], true);
    let t = r.json["ttl_ms"].as_u64().unwrap();
    assert!((55_000..=60_000).contains(&t), "{t}");
    let r = v("ttl", &[r#"keys=["123","nope"]"#]);
    assert_eq!(ok(&r)["found"], 1);
    assert_eq!(r.json["results"][0]["has_expiry"], false);
    assert_eq!(r.json["results"][0]["ttl_ms"], Value::Null);
    assert_eq!(r.json["results"][1]["exists"], false);

    // Conditional writes.
    let r = v("set", &["key=lock", "value=a", "only_if_exists=true"]);
    assert_eq!(ok(&r)["stored"], false);
    assert_eq!(r.json["reason"], "condition_not_met");
    assert_eq!(
        ok(&v(
            "set",
            &["key=lock", "value=a", "only_if_not_exists=true"]
        ))["stored"],
        true
    );
    assert_eq!(
        ok(&v(
            "set",
            &["key=lock", "value=b", "only_if_not_exists=true"]
        ))["stored"],
        false
    );
    assert_eq!(
        ok(&v("set", &["key=lock", "value=c", "only_if_exists=true"]))["stored"],
        true
    );
    assert_eq!(ok(&v("get", &["key=lock"]))["value"], "c");

    // A short TTL expires (memcached rounds 500 ms up to one second).
    ok(&v("set", &["key=short", "value=v", "ttl_ms=500"]));
    std::thread::sleep(Duration::from_millis(2_200));
    assert_eq!(ok(&v("get", &["key=short"]))["hit"], false);

    // incr.
    let r = v("incr", &["key=c", "initial=10", "by=5"]);
    assert_eq!(
        *ok(&r),
        json!({"alias": "e", "backend": b, "key": "c", "value": 15, "created": true})
    );
    let r = v("incr", &["key=c"]);
    assert_eq!(ok(&r)["value"], 16);
    assert_eq!(r.json["created"], false);
    ok(&v("incr", &["key=c", "ttl_ms=60000"]));
    assert!(ok(&v("ttl", &["key=c"]))["ttl_ms"].as_u64().unwrap() > 50_000);
    fails(&v("incr", &["key=q"]), 1, "cache.wrong_type");
    assert_eq!(ok(&v("get", &["key=q"]))["value"], " \"x\" ");

    // keys: every key exactly once across pages.
    let mut want = BTreeSet::new();
    for i in 0..60 {
        let k = format!("page:{i:02}");
        ok(&v("set", &[&format!("key={k}"), "value=1"]));
        want.insert(k);
    }
    let mut got = BTreeSet::new();
    let mut cursor = String::new();
    for _ in 0..1000 {
        let mut args = vec!["pattern=page:*".to_string(), "limit=7".to_string()];
        if !cursor.is_empty() {
            args.push(format!("cursor={cursor}"));
        }
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        let r = v("keys", &a);
        for k in ok(&r)["keys"].as_array().unwrap() {
            got.insert(k.as_str().unwrap().to_string());
        }
        assert_eq!(r.json["count"], r.json["keys"].as_array().unwrap().len());
        if r.json["has_more"] == false {
            assert_eq!(r.json["cursor"], Value::Null);
            break;
        }
        cursor = r.json["cursor"].as_str().unwrap().to_string();
    }
    assert_eq!(got, want);
    let r = v("keys", &["namespace=ns", "limit=1000"]);
    let mut ns: Vec<&str> = ok(&r)["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap())
        .collect();
    ns.sort();
    assert_eq!(ns, ["a", "b"]);

    // del.
    let r = v("del", &[r#"keys=["a","zz"]"#, "namespace=ns"]);
    assert_eq!(ok(&r)["total_deleted"], 1);
    assert_eq!(ok(&v("del", &["key=123"]))["deleted"], true);
    assert_eq!(ok(&v("del", &["key=123"]))["deleted"], false);
    assert_eq!(ok(&v("exists", &["key=123"]))["exists"], false);
}

#[test]
fn redis_every_verb() {
    let c = Container::redis(&[]);
    let url = c.redis_url();
    common_flow("redis", &url);
    let v = |name: &str, args: &[&str]| verb("redis", &url, name, args);

    // Exact 64-bit counters, negative steps.
    let r = v("incr", &["key=big", "initial=9007199254740993", "by=0"]);
    assert_eq!(ok(&r)["value"], json!(9007199254740993i64));
    assert_eq!(ok(&v("incr", &["key=neg", "by=-5"]))["value"], -5);
    ok(&v("set", &["key=max", "value=9223372036854775807"]));
    fails(&v("incr", &["key=max"]), 1, "cache.server_error");
    assert_eq!(ok(&v("get", &["key=max"]))["value"], "9223372036854775807");
    // Sub-second TTLs are kept in milliseconds.
    ok(&v("set", &["key=ms", "value=v", "ttl_ms=800"]));
    let t = ok(&v("ttl", &["key=ms"]))["ttl_ms"].as_u64().unwrap();
    assert!(t <= 800 && t > 0, "{t}");

    // A key of another Redis type.
    c.redis_cli(&["LPUSH", "list", "x"]);
    fails(&v("get", &["key=list"]), 1, "cache.wrong_type");
    fails(&v("incr", &["key=list"]), 1, "cache.wrong_type");
    assert_eq!(ok(&v("exists", &["key=list"]))["exists"], true);
    // Keys with glob characters in the namespace match only themselves.
    ok(&v("set", &["key=k", "value=1", "namespace=a*"]));
    ok(&v("set", &["key=k", "value=1", "namespace=ab"]));
    assert_eq!(ok(&v("keys", &["namespace=a*"]))["keys"], json!(["k"]));
    // Server-side refusal.
    c.redis_cli(&["CONFIG", "SET", "maxmemory", "1"]);
    fails(&v("set", &["key=oom", "value=v"]), 1, "cache.server_error");
    c.redis_cli(&["CONFIG", "SET", "maxmemory", "0"]);

    // A server that stops answering.
    c.docker("pause");
    let r = v("get", &["key=k", "connect_timeout_ms=500"]);
    c.docker("unpause");
    fails(&r, 124, "cache.connect_timeout");
}

#[test]
fn redis_auth_and_unix_socket() {
    let c = Container::redis(&["--requirepass", "s3cret"]);
    let base = format!("127.0.0.1:{}", c.port);
    let r = verb("redis", &format!("url=redis://{base}"), "connect", &[]);
    fails(&r, 1, "cache.connect_failed");
    let r = verb(
        "redis",
        &format!("url=redis://:wrong@{base}"),
        "connect",
        &[],
    );
    fails(&r, 1, "cache.connect_failed");
    assert!(!r.stdout.contains("wrong") && !r.stderr.contains("wrong"));
    let r = verb(
        "redis",
        &format!("url=redis://:s3cret@{base}/2"),
        "connect",
        &[],
    );
    assert_eq!(ok(&r)["endpoint"], base);
    assert!(!r.stdout.contains("s3cret"));
    let url = format!("url=redis://:s3cret@{base}/2");
    ok(&verb("redis", &url, "set", &["key=k", "value=db2"]));
    assert_eq!(
        c.redis_cli(&["-a", "s3cret", "--no-auth-warning", "-n", "2", "GET", "k"]),
        "db2"
    );

    // Unix socket in a directory shared with the container.
    let dir = TempDir::new().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    let mount = format!("{}:/sock", dir.path().display());
    let s = Container::start(
        REDIS_IMAGE,
        6379,
        &["-v", &mount],
        &[
            "redis-server",
            "--unixsocket",
            "/sock/redis.sock",
            "--unixsocketperm",
            "777",
        ],
        None,
    );
    s.wait_ready(&["exec", &s.id, "redis-cli", "ping"]);
    let sock = dir.path().join("redis.sock");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !sock.exists() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(50));
    }
    let url = format!("url=redis+unix://{}", sock.display());
    let r = verb("redis", &url, "connect", &[]);
    assert_eq!(ok(&r)["endpoint"], sock.display().to_string());
    ok(&verb("redis", &url, "set", &["key=u", "value=sock"]));
    assert_eq!(ok(&verb("redis", &url, "get", &["key=u"]))["value"], "sock");
    drop(s);
}

#[test]
fn memcached_every_verb() {
    let c = Container::memcached();
    let url = c.memcached_url();
    common_flow("memcached", &url);
    let v = |name: &str, args: &[&str]| verb("memcached", &url, name, args);

    // Counters stop at 0 and cannot start negative.
    assert_eq!(
        ok(&v("incr", &["key=dn", "initial=3", "by=-1"]))["value"],
        2
    );
    assert_eq!(ok(&v("incr", &["key=dn", "by=-10"]))["value"], 0);
    fails(
        &v("incr", &["key=x", "initial=-1"]),
        2,
        "cache.invalid_argument",
    );
    // Keys memcached cannot take are refused before sending.
    fails(
        &v("set", &["key=a b", "value=v"]),
        2,
        "cache.invalid_argument",
    );
    fails(
        &v("get", &[&format!("key={}", "k".repeat(251))]),
        2,
        "cache.invalid_argument",
    );
    // A value over the item size limit (64 KiB here).
    let big = "x".repeat(100 * 1024);
    fails(
        &v("set", &["key=big", &format!("value={big}")]),
        1,
        "cache.server_error",
    );
    // A cursor from another backend.
    fails(&v("keys", &["cursor=!!"]), 2, "cache.invalid_argument");

    c.docker("pause");
    let r = v("get", &["key=k", "connect_timeout_ms=500"]);
    c.docker("unpause");
    fails(&r, 124, "cache.connect_timeout");
}

// ------------------------------------------------------------- help --

/// The keys of a JSON value, recursively (array items merged).
fn shape(v: &Value, prefix: &str, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, v) in m {
                let p = format!("{prefix}.{k}");
                out.push(p.clone());
                shape(v, &p, out);
            }
        }
        Value::Array(a) => {
            for v in a {
                shape(v, &format!("{prefix}[]"), out);
            }
        }
        _ => {}
    }
}

fn shape_of(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    shape(v, "", &mut out);
    out.sort();
    out.dedup();
    out
}

/// Every help example runs against a real Redis and prints the fields of
/// its sample output.
#[test]
fn help_examples_run_and_match_their_sample_output() {
    let c = Container::redis(&[]);
    let local = format!("redis://127.0.0.1:{}/0", c.port);
    let setup = format!("url={local}");
    ok(&verb(
        "redis",
        &setup,
        "set",
        &["key=user:42", "value=alice"],
    ));
    ok(&verb("redis", &setup, "set", &["key=user:43", "value=bob"]));
    ok(&verb(
        "redis",
        &setup,
        "set",
        &["key=session:1", "value=s", "ttl_ms=60000"],
    ));
    for v in [
        "connect", "get", "exists", "ttl", "keys", "set", "incr", "del",
    ] {
        let help = resh(&["cache", v, "--help"]).stdout;
        let example = help
            .split("Example:\n")
            .nth(1)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .trim()
            .replace("url=redis://localhost:6379/0", &setup)
            .replace("url=redis://cache", &setup);
        let mut argv: Vec<String> = example
            .split_whitespace()
            .map(|w| w.trim_matches('\'').to_string())
            .collect();
        assert_eq!(argv.remove(0), "resh");
        if !argv.iter().any(|a| a == "--json-pretty") {
            argv.insert(0, "--json-pretty".into());
        }
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        let r = resh(&argv);
        assert_eq!(r.code, 0, "{v}: {example}: {}\n{}", r.stdout, r.stderr);
        let sample: String = help
            .split("Example Output:\n")
            .nth(1)
            .unwrap()
            .split("\n\n")
            .next()
            .unwrap()
            .lines()
            .map(|l| l.strip_prefix("  ").unwrap_or(l))
            .collect::<Vec<_>>()
            .join("\n");
        let sample: Value = serde_json::from_str(&sample).unwrap();
        let got = shape_of(&r.json);
        for key in shape_of(&sample) {
            assert!(got.contains(&key), "{v}: {key} missing in {}", r.stdout);
        }
        // The sample's values hold where they are deterministic.
        for k in [
            "alias",
            "backend",
            "status",
            "hit",
            "exists",
            "stored",
            "deleted",
            "has_expiry",
        ] {
            if let Some(want) = sample.get(k) {
                assert_eq!(&r.json[k], want, "{v}: {k}");
            }
        }
    }
}

// ------------------------------------------------------------------ TLS --

/// A CA and a server certificate for `san` (an IP address or a DNS name)
/// signed by it: (ca, leaf PEM, leaf key PEM).
fn ca_and_leaf(san: &str) -> (rcgen::Certificate, String, String) {
    use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, SanType};
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "resh test CA");
    let ca = Certificate::from_params(ca_params).unwrap();
    let mut leaf_params = CertificateParams::default();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "redis");
    leaf_params.subject_alt_names = vec![match san.parse::<std::net::IpAddr>() {
        Ok(ip) => SanType::IpAddress(ip),
        Err(_) => SanType::DnsName(san.to_string()),
    }];
    let leaf = Certificate::from_params(leaf_params).unwrap();
    let leaf_pem = leaf.serialize_pem_with_signer(&ca).unwrap();
    let key = leaf.serialize_private_key_pem();
    (ca, leaf_pem, key)
}

/// A Redis that only speaks TLS, with this certificate and key.
fn tls_redis(ca_pem: &str, leaf_pem: &str, key_pem: &str) -> Container {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    for (name, body) in [
        ("ca.pem", ca_pem),
        ("cert.pem", leaf_pem),
        ("key.pem", key_pem),
    ] {
        let p = dir.path().join(name);
        std::fs::write(&p, body).unwrap();
        // The container user must read the key.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let mount = format!("{}:/tls:ro", dir.path().display());
    let c = Container::start(
        REDIS_IMAGE,
        6379,
        &["-v", &mount],
        &[
            "redis-server",
            "--port",
            "0",
            "--tls-port",
            "6379",
            "--tls-cert-file",
            "/tls/cert.pem",
            "--tls-key-file",
            "/tls/key.pem",
            "--tls-ca-cert-file",
            "/tls/ca.pem",
            "--tls-auth-clients",
            "no",
        ],
        Some(dir),
    );
    // In-container readiness probe only; resh never skips verification.
    c.wait_ready(&["exec", &c.id, "redis-cli", "--tls", "--insecure", "ping"]);
    c
}

fn resh_env(args: &[&str], env: &[(&str, &str)]) -> Run {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
    cmd.env_remove("SSH_AUTH_SOCK").args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        json: serde_json::from_str(&stdout).unwrap_or(Value::Null),
        stdout,
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

#[test]
fn rediss_verifies_the_certificate_and_host_name() {
    let (ca, leaf, key) = ca_and_leaf("127.0.0.1");
    let ca_pem = ca.serialize_pem().unwrap();
    let good = tls_redis(&ca_pem, &leaf, &key);
    let files = TempDir::new().unwrap();
    let ca_file = files.path().join("ca.pem");
    std::fs::write(&ca_file, &ca_pem).unwrap();
    let ca_arg = format!("ca_file={}", ca_file.display());
    let url = format!("url=rediss://127.0.0.1:{}/0", good.port);

    // The right CA: the verbs work over TLS.
    let r = resh(&["cache://redis/t.connect", &url, &ca_arg]);
    assert_eq!(ok(&r)["endpoint"], format!("127.0.0.1:{}", good.port));
    ok(&resh(&[
        "cache://redis/t.set",
        "key=k",
        "value=over tls",
        &url,
        &ca_arg,
    ]));
    let r = resh(&["cache://redis/t.get", "key=k", &url, &ca_arg]);
    assert_eq!(ok(&r)["value"], "over tls");
    let r = resh(&["cache://redis/t.incr", "key=n", &url, &ca_arg]);
    assert_eq!(ok(&r)["value"], 1);
    // SSL_CERT_FILE replaces the system bundle, as for other TLS clients.
    let r = resh_env(
        &["cache://redis/t.get", "key=k", &url],
        &[("SSL_CERT_FILE", ca_file.to_str().unwrap())],
    );
    assert_eq!(ok(&r)["value"], "over tls");

    // No ca_file: the system bundle does not trust the test CA.
    fails(
        &resh(&["cache://redis/t.get", "key=k", &url]),
        1,
        "cache.tls_failed",
    );
    // Another CA.
    let (other, _, _) = ca_and_leaf("127.0.0.1");
    let other_file = files.path().join("other.pem");
    std::fs::write(&other_file, other.serialize_pem().unwrap()).unwrap();
    let other_arg = format!("ca_file={}", other_file.display());
    fails(
        &resh(&["cache://redis/t.get", "key=k", &url, &other_arg]),
        1,
        "cache.tls_failed",
    );
    // No insecure escape hatch.
    let insecure = format!("url=rediss://127.0.0.1:{}/0#insecure", good.port);
    fails(
        &resh(&["cache://redis/t.get", "key=k", &insecure]),
        2,
        "cache.invalid_argument",
    );
    // Plain redis:// to the TLS port does not get an answer.
    let plain = format!("url=redis://127.0.0.1:{}/0", good.port);
    let r = resh(&[
        "cache://redis/t.get",
        "key=k",
        &plain,
        "connect_timeout_ms=2000",
    ]);
    assert_ne!(r.code, 0, "{}", r.stdout);
    // ca_file is refused for plain connections.
    fails(
        &resh(&["cache://redis/t.get", "key=k", &plain, &ca_arg]),
        2,
        "cache.invalid_argument",
    );

    // A certificate for another name, from the trusted CA.
    let (ca2, leaf2, key2) = ca_and_leaf("redis.elsewhere.test");
    let ca2_pem = ca2.serialize_pem().unwrap();
    let wrong_name = tls_redis(&ca2_pem, &leaf2, &key2);
    let ca2_file = files.path().join("ca2.pem");
    std::fs::write(&ca2_file, &ca2_pem).unwrap();
    let url2 = format!("url=rediss://127.0.0.1:{}/0", wrong_name.port);
    let r = resh(&[
        "cache://redis/t.get",
        "key=k",
        &url2,
        &format!("ca_file={}", ca2_file.display()),
    ]);
    fails(&r, 1, "cache.tls_failed");
    assert!(
        r.stderr.to_lowercase().contains("certificate"),
        "{}",
        r.stderr
    );

    // rediss:// to a server without TLS: Redis waits for a command line
    // that the TLS hello never completes, so the connection times out.
    let plain_server = Container::redis(&[]);
    let r = resh(&[
        "cache://redis/t.get",
        "key=k",
        &format!("url=rediss://127.0.0.1:{}/0", plain_server.port),
        &ca_arg,
        "connect_timeout_ms=2000",
    ]);
    assert!(
        matches!(
            r.json["error"]["code"].as_str(),
            Some("cache.tls_failed" | "cache.connect_timeout")
        ),
        "{}",
        r.stdout
    );
    assert!(r.code == 1 || r.code == 124);
}
