//! Integration tests for `net://`: every verb run through the built `resh`
//! binary, against listeners, TLS and DNS servers this test opens on
//! 127.0.0.1 only; exit codes and the error format; the fallbacks (no
//! `ping`, no or failing `ip`) with a controlled PATH; help output (golden
//! files) and the help examples.

mod common;

use serde_json::{Value, json};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const VERBS: &[&str] = &["list", "route.list", "dns", "ping", "tcp_check", "scan"];

/// The options each verb accepts (src/handles/network/neth.rs `verb_args`).
fn options_for(verb: &str) -> &'static [&'static str] {
    match verb {
        "list" => &["family", "up"],
        "route.list" => &["family", "table", "timeout_ms"],
        "dns" => &["type", "server", "port", "timeout_ms"],
        "ping" => &["count", "timeout_ms", "port", "family", "raw"],
        "tcp_check" => &["port", "timeout_ms", "retries", "backoff_ms", "expect_tls"],
        "scan" => &["ports", "timeout_ms", "concurrency", "host", "protocol"],
        _ => unreachable!(),
    }
}

/// The error codes documented in docs/Network_RemoteOperations/net.md.
const ERROR_CODES: &[&str] = &[
    "net.invalid_argument",
    "net.lookup_failed",
    "net.resolve_failed",
    "net.timeout",
    "net.unreachable",
    "net.ping_failed",
    "net.connect_failed",
    "net.tls_failed",
    "net.scan_failed",
    "net.route_read_failed",
    "net.interfaces_failed",
    "net.unsupported_platform",
];

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    json: Value,
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

fn resh(args: &[&str]) -> Run {
    resh_env(args, &[])
}

/// Asserts a failure with `exit` and `code` on stdout (JSON) and stderr.
fn assert_fail(r: &Run, exit: i32, code: &str) {
    assert_eq!(r.code, exit, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(r.json["error"]["code"], code, "{}", r.stdout);
    assert!(r.json["error"]["message"].is_string(), "{}", r.stdout);
    assert!(
        r.stderr.starts_with(&format!("Error: [{code}] ")),
        "{}",
        r.stderr
    );
    assert!(ERROR_CODES.contains(&code), "{code} is not documented");
}

fn open_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for s in l.incoming().flatten() {
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(300));
                drop(s);
            });
        }
    });
    port
}

/// A port of 127.0.0.1 that refuses connections. The listener is closed;
/// the port is not reused right away by the kernel's ephemeral allocator.
fn closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// A DNS server on 127.0.0.1 answering A queries for `example.com` and
/// `host.test` with 192.0.2.10 (TTL 60).
fn dns_server() -> u16 {
    use trust_dns_proto::op::{Message, MessageType, ResponseCode};
    use trust_dns_proto::rr::{RData, Record, RecordType, rdata};
    use trust_dns_proto::serialize::binary::BinDecodable;
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while let Ok((n, peer)) = sock.recv_from(&mut buf) {
            let Ok(req) = Message::from_bytes(&buf[..n]) else {
                continue;
            };
            let q = req.queries()[0].clone();
            let mut resp = Message::new();
            resp.set_id(req.id())
                .set_message_type(MessageType::Response)
                .set_recursion_desired(true)
                .set_recursion_available(true);
            let name = q.name().to_ascii();
            let known = name == "example.com." || name == "host.test.";
            if known && q.query_type() == RecordType::A {
                resp.add_answer(Record::from_rdata(
                    q.name().clone(),
                    60,
                    RData::A(rdata::A("192.0.2.10".parse().unwrap())),
                ));
            } else {
                resp.set_response_code(ResponseCode::NXDomain);
            }
            resp.add_query(q);
            sock.send_to(&resp.to_vec().unwrap(), peer).ok();
        }
    });
    port
}

// ------------------------------------------------------------------ list --

#[test]
fn list_through_the_binary() {
    let r = resh(&["net://if.list"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let lo = r.json["interfaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == "lo")
        .unwrap()
        .clone();
    assert!(lo["flags"].as_array().unwrap().contains(&json!("loopback")));
    assert_eq!(lo["mac"], "00:00:00:00:00:00");
    let r = resh(&["net://if.list", "family=ipv6", "up=false"]);
    assert_eq!(r.code, 0);
    let r = resh(&["net://if.list(family=ipv4,up=1)"]);
    assert_eq!(r.code, 0);
    assert_fail(
        &resh(&["net://if.list", "up=maybe"]),
        2,
        "net.invalid_argument",
    );
    assert_fail(
        &resh(&["net://if.list", "timeout_ms=5"]),
        2,
        "net.invalid_argument",
    );
    let r = resh(&["net://if.list", "famly=ipv4"]);
    assert_fail(&r, 2, "net.invalid_argument");
    assert!(r.stderr.contains("did you mean `family`?"), "{}", r.stderr);
    // dry_run=true is refused by the dispatcher before the handle runs.
    let r = resh(&["net://if.list", "dry_run=true"]);
    assert_eq!(r.code, 2, "{}", r.stderr);
}

// ------------------------------------------------------------ route.list --

/// A directory holding executable scripts named after tools.
fn fake_tools(tools: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().unwrap();
    for (name, body) in tools {
        common::write_executable(&dir.path().join(name), body);
    }
    dir
}

#[test]
fn route_list_through_the_binary() {
    let r = resh(&["net://localhost.route.list"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.json.is_array());
    assert!(
        r.json
            .as_array()
            .unwrap()
            .iter()
            .all(|x| x["family"] == "ipv4")
    );
    let r = resh(&["net://localhost.route.list", "family=all", "table=all"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_fail(
        &resh(&["net://localhost.route.list", "table=nope"]),
        2,
        "net.invalid_argument",
    );
}

#[test]
fn route_list_without_ip_reads_proc() {
    let empty = TempDir::new().unwrap();
    let path = empty.path().to_str().unwrap();
    let r = resh_env(&["net://localhost.route.list"], &[("PATH", path)]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stderr, "", "no ip is not worth a warning");
    for route in r.json.as_array().unwrap() {
        assert_eq!(route["protocol"], Value::Null);
        assert_eq!(route["table"], "main");
    }
    // Only ip can read other tables.
    let r = resh_env(
        &["net://localhost.route.list", "table=local"],
        &[("PATH", path)],
    );
    assert_fail(&r, 1, "net.route_read_failed");
}

#[test]
fn route_list_with_failing_or_stuck_ip() {
    let tools = fake_tools(&[("ip", "#!/bin/sh\necho 'ip: broken' >&2\nexit 1\n")]);
    let path = format!("{}:/usr/bin:/bin", tools.path().display());
    let r = resh_env(&["net://localhost.route.list"], &[("PATH", &path)]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stderr.contains("Warning: ip route failed"),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("ip: broken"), "{}", r.stderr);

    let tools = fake_tools(&[("ip", "#!/bin/sh\nexec sleep 30\n")]);
    let path = format!("{}:/usr/bin:/bin", tools.path().display());
    let start = Instant::now();
    let r = resh_env(
        &["net://localhost.route.list", "timeout_ms=300"],
        &[("PATH", &path)],
    );
    assert_fail(&r, 124, "net.timeout");
    assert!(start.elapsed() < Duration::from_secs(5));
}

// ------------------------------------------------------------------- dns --

#[test]
fn dns_through_the_binary() {
    let port = dns_server().to_string();
    let r = resh(&[
        "net://host.test.dns",
        "server=127.0.0.1",
        &format!("port={port}"),
    ]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(
        r.json["records"],
        json!([{"name": "host.test", "ttl": 60, "data": "192.0.2.10"}])
    );
    let r = resh(&[
        "net://missing.test.dns",
        "server=127.0.0.1",
        &format!("port={port}"),
    ]);
    assert_fail(&r, 1, "net.lookup_failed");
    // A server that never answers.
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    let silent_port = silent.local_addr().unwrap().port();
    let r = resh(&[
        "net://host.test.dns",
        "server=127.0.0.1",
        &format!("port={silent_port}"),
        "timeout_ms=300",
    ]);
    assert_fail(&r, 124, "net.timeout");
    assert_fail(
        &resh(&["net://host.test.dns", "type=BOGUS"]),
        2,
        "net.invalid_argument",
    );
    assert_fail(
        &resh(&["net://host.test.dns", "port=53"]),
        2,
        "net.invalid_argument",
    );
}

// ------------------------------------------------------------------ ping --

#[test]
fn ping_through_the_binary() {
    let r = resh(&["net://127.0.0.1.ping", "count=1"]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(r.json["backend"], "system_ping");
    assert_eq!(r.json["reachable"], true);
    assert_fail(
        &resh(&["net://127.0.0.1.ping", "count=0"]),
        2,
        "net.invalid_argument",
    );
}

#[test]
fn ping_without_the_ping_command_uses_tcp() {
    let empty = TempDir::new().unwrap();
    let path = empty.path().to_str().unwrap();
    let open = open_port();
    let r = resh_env(
        &["net://localhost.ping", "count=2", &format!("port={open}")],
        &[("PATH", path)],
    );
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(r.json["backend"], "tcp_fallback");
    assert_eq!(r.json["port"], open);
    assert_eq!(r.json["sent"], 2);
    assert_eq!(r.json["received"], 2);

    // Nothing answers: the host is reported unreachable and the exit is 1.
    let closed = closed_port();
    let r = resh_env(
        &[&format!("net://127.0.0.1:{closed}.ping"), "count=2"],
        &[("PATH", path)],
    );
    assert_fail(&r, 1, "net.unreachable");
    assert_eq!(r.json["reachable"], false);
    assert_eq!(r.json["received"], 0);
    assert_eq!(r.json["backend"], "tcp_fallback");
}

#[test]
fn ping_reports_a_ping_that_fails_to_run() {
    // A ping that cannot open its socket: the TCP fallback is used.
    let tools = fake_tools(&[(
        "ping",
        "#!/bin/sh\necho 'ping: socket: Operation not permitted' >&2\nexit 2\n",
    )]);
    let path = format!("{}:/usr/bin:/bin", tools.path().display());
    let open = open_port();
    let r = resh_env(
        &[
            &format!("net://127.0.0.1:{open}.ping"),
            "count=1",
            "raw=true",
        ],
        &[("PATH", &path)],
    );
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(r.json["backend"], "tcp_fallback");
    assert!(r.stderr.contains("Operation not permitted"), "{}", r.stderr);

    // A name that does not resolve is not retried over TCP.
    let tools = fake_tools(&[(
        "ping",
        "#!/bin/sh\necho 'ping: nohost.test: Name or service not known' >&2\nexit 2\n",
    )]);
    let path = format!("{}:/usr/bin:/bin", tools.path().display());
    let r = resh_env(&["net://nohost.test.ping"], &[("PATH", &path)]);
    assert_fail(&r, 1, "net.resolve_failed");

    // A ping that hangs is stopped: outcome unknown.
    let tools = fake_tools(&[("ping", "#!/bin/sh\nexec sleep 30\n")]);
    let path = format!("{}:/usr/bin:/bin", tools.path().display());
    let start = Instant::now();
    let r = resh_env(
        &["net://127.0.0.1.ping", "timeout_ms=100"],
        &[("PATH", &path)],
    );
    assert_fail(&r, 124, "net.timeout");
    assert!(start.elapsed() < Duration::from_secs(8));

    // ICMP errors are not replies (they used to be counted).
    let tools = fake_tools(&[(
        "ping",
        "#!/bin/sh\ncat <<'EOF'\nPING 192.0.2.9 (192.0.2.9) 56(84) bytes of data.\n\
         From 192.0.2.1 icmp_seq=1 Destination Host Unreachable\n\n\
         --- 192.0.2.9 ping statistics ---\n\
         1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms\nEOF\nexit 1\n",
    )]);
    let path = format!("{}:/usr/bin:/bin", tools.path().display());
    let r = resh_env(&["net://192.0.2.9.ping", "count=1"], &[("PATH", &path)]);
    assert_fail(&r, 1, "net.unreachable");
    assert_eq!(r.json["backend"], "system_ping");
    assert_eq!(r.json["sent"], 1);
    assert_eq!(r.json["received"], 0);
    assert_eq!(r.json["loss"], 1.0);
}

#[test]
fn ping_passes_count_deadline_and_family_to_ping() {
    let dir = TempDir::new().unwrap();
    let log = dir.path().join("argv");
    let tools = fake_tools(&[(
        "ping",
        &format!(
            "#!/bin/sh\necho \"$@\" > {}\necho '1 packets transmitted, 1 received, 0% packet loss'\n",
            log.display()
        ),
    )]);
    let path = format!("{}:/usr/bin:/bin", tools.path().display());
    let r = resh_env(
        &[
            "net://127.0.0.1.ping",
            "count=4",
            "timeout_ms=2500",
            "family=ipv4",
        ],
        &[("PATH", &path)],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        std::fs::read_to_string(&log).unwrap().trim(),
        "-4 -c 4 -w 3 127.0.0.1"
    );
}

// ------------------------------------------------------------- tcp_check --

#[test]
fn tcp_check_through_the_binary() {
    let open = open_port();
    let r = resh(&[&format!("net://127.0.0.1:{open}.tcp_check")]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(r.json["ok"], true);
    // port= is the port connected to.
    let r = resh(&["net://localhost.tcp_check", &format!("port={open}")]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(r.json["port"], open);

    let closed = closed_port();
    let r = resh(&[
        &format!("net://127.0.0.1:{closed}.tcp_check"),
        "retries=2",
        "backoff_ms=50",
    ]);
    assert_fail(&r, 1, "net.connect_failed");
    assert_eq!(r.json["ok"], false);
    assert_eq!(r.json["attempts"], 2);
    assert_fail(
        &resh(&["net://127.0.0.1.tcp_check"]),
        2,
        "net.invalid_argument",
    );
}

#[test]
fn tcp_check_expect_tls_uses_ssl_cert_file() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let mut ca_params = rcgen::CertificateParams::new(vec![]);
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = rcgen::Certificate::from_params(ca_params).unwrap();
    let leaf = rcgen::Certificate::from_params(rcgen::CertificateParams::new(vec![
        "localhost".to_string(),
    ]))
    .unwrap();
    let dir = TempDir::new().unwrap();
    let ca_file = dir.path().join("ca.pem");
    std::fs::write(&ca_file, ca.serialize_pem().unwrap()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(
                    leaf.serialize_der_with_signer(&ca).unwrap(),
                )],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.serialize_private_key_der())),
            )
            .unwrap(),
    );
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let config = Arc::clone(&config);
            thread::spawn(move || {
                let mut conn = rustls::ServerConnection::new(config).unwrap();
                s.set_read_timeout(Some(Duration::from_secs(2))).ok();
                while conn.is_handshaking() {
                    if conn.complete_io(&mut s).is_err() {
                        return;
                    }
                }
            });
        }
    });
    let ca_env = ca_file.to_str().unwrap();
    let url = format!("net://localhost:{port}.tcp_check");
    let r = resh_env(&[&url, "expect_tls=true"], &[("SSL_CERT_FILE", ca_env)]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(r.json["tls_checked"], true);
    // 127.0.0.1 is not a name in the certificate.
    let r = resh_env(
        &[
            &format!("net://127.0.0.1:{port}.tcp_check"),
            "expect_tls=true",
        ],
        &[("SSL_CERT_FILE", ca_env)],
    );
    assert_fail(&r, 1, "net.tls_failed");
    // A plain TCP port is not TLS.
    let open = open_port();
    let r = resh_env(
        &[
            &format!("net://localhost:{open}.tcp_check"),
            "expect_tls=yes",
            "timeout_ms=500",
        ],
        &[("SSL_CERT_FILE", ca_env)],
    );
    assert!(r.code == 1 || r.code == 124, "{}", r.stdout);
    assert_eq!(r.json["ok"], false);
    let missing = dir.path().join("missing.pem");
    let r = resh_env(
        &[&url, "expect_tls=true"],
        &[("SSL_CERT_FILE", missing.to_str().unwrap())],
    );
    assert_fail(&r, 1, "net.tls_failed");
}

// ------------------------------------------------------------------ scan --

#[test]
fn scan_through_the_binary() {
    let open = open_port();
    let closed = closed_port();
    let r = resh(&[
        "net://127.0.0.1.scan",
        &format!("ports={open},{closed}"),
        "timeout_ms=300",
    ]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(r.json["ports"][0], json!({"port": open, "state": "open"}));
    assert_eq!(r.json["ports"][1]["state"], "closed");
    let r = resh(&["net://255.255.255.255.scan", "ports=80"]);
    assert_fail(&r, 1, "net.scan_failed");
    assert_fail(
        &resh(&["net://127.0.0.1.scan", "ports=1-5000"]),
        2,
        "net.invalid_argument",
    );
    assert_fail(
        &resh(&["net://127.0.0.1.scan", "protocol=udp"]),
        2,
        "net.invalid_argument",
    );
}

#[test]
fn unknown_verb_and_error_codes_are_documented() {
    let r = resh(&["net://localhost.status"]);
    assert_eq!(r.code, 2, "{}", r.stderr);
    let doc = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/Network_RemoteOperations/net.md"),
    )
    .unwrap();
    for code in ERROR_CODES {
        assert!(doc.contains(&format!("`{code}`")), "{code} not in net.md");
    }
}

// ------------------------------------------------------------------ help --

fn assert_plain(out: &str) {
    assert!(out.is_ascii(), "non-ASCII");
    for line in out.lines() {
        assert!(line.len() <= 80, "line over 80 columns: {line:?}");
        assert!(!line.ends_with(' '), "trailing space: {line:?}");
    }
}

fn golden(verb: &str) -> &'static str {
    match verb {
        "list" => include_str!("golden/net_list_help.txt"),
        "route.list" => include_str!("golden/net_route.list_help.txt"),
        "dns" => include_str!("golden/net_dns_help.txt"),
        "ping" => include_str!("golden/net_ping_help.txt"),
        "tcp_check" => include_str!("golden/net_tcp_check_help.txt"),
        "scan" => include_str!("golden/net_scan_help.txt"),
        _ => unreachable!(),
    }
}

#[test]
fn handle_help_matches_golden() {
    let r = resh(&["net", "--help"]);
    assert_eq!(r.code, 0);
    assert_eq!(r.stderr, "");
    assert_plain(&r.stdout);
    assert_eq!(r.stdout, include_str!("golden/net_help.txt"));
    let listed: Vec<&str> = r
        .stdout
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
    for alt in [
        &["net", "-h"][..],
        &["net", "help"][..],
        &["help", "net"][..],
        &["net://--help"][..],
    ] {
        assert_eq!(resh(alt).stdout, r.stdout, "{alt:?}");
    }
}

fn usage_options(out: &str) -> Vec<String> {
    let usage = out
        .split("Usage:\n")
        .nth(1)
        .unwrap()
        .split("\n\n")
        .next()
        .unwrap();
    let mut v: Vec<String> = usage
        .split(|c: char| c.is_whitespace() || c == '[' || c == ']')
        .filter_map(|w| w.split_once('=').map(|(k, _)| k.to_string()))
        .filter(|k| !k.is_empty() && !k.contains(':'))
        .collect();
    v.sort();
    v.dedup();
    v
}

#[test]
fn verb_help_matches_golden_and_lists_every_option() {
    for verb in VERBS {
        let r = resh(&["net", verb, "--help"]);
        assert_eq!(r.code, 0, "{verb}");
        assert_eq!(r.stderr, "");
        assert_plain(&r.stdout);
        assert!(
            r.stdout
                .starts_with(&format!("Handle: net\nVerb: {verb}\nDefinition: "))
        );
        for section in ["\nUsage:\n", "\nExample:\n", "\nExample Output:\n"] {
            assert!(r.stdout.contains(section), "{verb}: {section:?}");
        }
        assert_eq!(r.stdout, golden(verb), "{verb}: help differs from golden");
        let mut want: Vec<String> = options_for(verb).iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(usage_options(&r.stdout), want, "{verb}");
        for alt in [
            vec!["net".to_string(), verb.to_string(), "-h".into()],
            vec!["help".into(), "net".into(), verb.to_string()],
            vec![format!("net://--help={verb}")],
            vec![format!("net://x.{verb}(help=1)")],
        ] {
            let argv: Vec<&str> = alt.iter().map(String::as_str).collect();
            assert_eq!(resh(&argv).stdout, r.stdout, "{alt:?}");
        }
    }
}

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

/// Every help example runs, pointed at local servers instead of the
/// documentation addresses, and prints the fields of its sample output.
#[test]
fn help_examples_run_and_match_their_sample_output() {
    let open = open_port();
    let closed = closed_port();
    let dns_port = dns_server();
    // Keep a connection to `open` alive so scan sees it open.
    let _keep = TcpStream::connect(("127.0.0.1", open)).unwrap();
    for verb in VERBS {
        let help = resh(&["net", verb, "--help"]).stdout;
        let example = help
            .split("Example:\n")
            .nth(1)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .trim()
            .to_string();
        let local = example
            .replace("192.0.2.10:22", &format!("127.0.0.1:{open}"))
            .replace("ports=22,80", &format!("ports={open},{closed}"))
            .replace("192.0.2.10", "127.0.0.1");
        let mut argv: Vec<String> = local.split_whitespace().map(String::from).collect();
        assert_eq!(argv.remove(0), "resh");
        if *verb == "dns" {
            argv.push("server=127.0.0.1".into());
            argv.push(format!("port={dns_port}"));
        }
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        let r = resh(&argv);
        assert_eq!(r.code, 0, "{verb}: {local}: {}\n{}", r.stdout, r.stderr);
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
            assert!(got.contains(&key), "{verb}: {key} missing in {}", r.stdout);
        }
    }
}
