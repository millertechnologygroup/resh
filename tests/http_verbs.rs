//! Binary tests for the http and https handles: every verb runs the built
//! `resh` against servers on 127.0.0.1 (plain HTTP via httptest or a raw
//! socket server, HTTPS via `openssl s_server` with a certificate made by
//! rcgen in the test). Nothing here contacts another host.

use httptest::{Expectation, Server, all_of, matchers::*, responders::*};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const VERBS: [&str; 10] = [
    "get",
    "head",
    "headers",
    "options",
    "preflight",
    "json",
    "post",
    "put",
    "patch",
    "delete",
];

const PROXY_VARS: [&str; 8] = [
    "http_proxy",
    "HTTP_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "no_proxy",
    "NO_PROXY",
];

fn resh() -> assert_cmd::Command {
    let mut c = assert_cmd::cargo::cargo_bin_cmd!("resh");
    for v in PROXY_VARS {
        c.env_remove(v);
    }
    c
}

struct Run {
    code: i32,
    out: Vec<u8>,
    err: String,
}

impl Run {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.out).into_owned()
    }
    fn json(&self) -> Value {
        serde_json::from_slice(&self.out)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {} / {}", self.text(), self.err))
    }
}

fn run_cmd(mut c: assert_cmd::Command) -> Run {
    let o = c.output().unwrap();
    Run {
        code: o.status.code().unwrap_or(-1),
        out: o.stdout,
        err: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

fn run(args: &[&str]) -> Run {
    let mut c = resh();
    c.args(args);
    run_cmd(c)
}

// --- local servers -------------------------------------------------------------

fn closed_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn silent_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for s in l.incoming().flatten() {
            held.push(s);
        }
    });
    port
}

fn read_request(r: &mut impl BufRead) -> Option<String> {
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).ok()? == 0 {
            return None;
        }
        head.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }
    let len = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let mut body = vec![0; len];
    r.read_exact(&mut body).ok()?;
    head.push_str(&String::from_utf8_lossy(&body));
    Some(head)
}

/// Answers each connection's request with `respond(request)` (a complete
/// HTTP response) and closes it, so a body can also be delimited by the
/// close. Records the requests.
fn raw_server(
    respond: impl Fn(&str) -> Vec<u8> + Send + Sync + 'static,
) -> (u16, Arc<Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    let respond = Arc::new(respond);
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let (seen, respond) = (seen2.clone(), respond.clone());
            std::thread::spawn(move || {
                let mut s: TcpStream = s;
                let mut r = BufReader::new(s.try_clone().unwrap());
                if let Some(req) = read_request(&mut r) {
                    seen.lock().unwrap().push(req.clone());
                    let _ = s.write_all(&respond(&req));
                }
            });
        }
    });
    (port, seen)
}

fn response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut r = format!("HTTP/1.1 {status}\r\n");
    for (k, v) in headers {
        r.push_str(&format!("{k}: {v}\r\n"));
    }
    r.push_str("\r\n");
    let mut r = r.into_bytes();
    r.extend_from_slice(body);
    r
}

fn with_len(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let len = body.len().to_string();
    let mut h = vec![("Content-Length", len.as_str())];
    h.extend_from_slice(headers);
    response(status, &h, body)
}

// --- TLS server --------------------------------------------------------------------

/// An HTTPS server for one connection: `openssl s_server` with a fresh
/// self-signed certificate for localhost and 127.0.0.1. It answers the
/// request with `reply`, or never answers when `reply` is `None`.
struct TlsServer {
    port: u16,
    child: Child,
    request: Option<std::thread::JoinHandle<String>>,
    _dir: tempfile::TempDir,
}

impl TlsServer {
    fn start(reply: Option<Vec<u8>>) -> Option<TlsServer> {
        if which::which("openssl").is_err() {
            eprintln!("SKIPPED: openssl is not installed; HTTPS tests need `openssl s_server`");
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]);
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()));
        let cert = rcgen::Certificate::from_params(params).unwrap();
        let (c, k) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
        std::fs::write(&c, cert.serialize_pem().unwrap()).unwrap();
        std::fs::write(&k, cert.serialize_private_key_pem()).unwrap();
        let mut child = Command::new("openssl")
            .args(["s_server", "-accept", "127.0.0.1:0", "-naccept", "1"])
            .arg("-cert")
            .arg(&c)
            .arg("-key")
            .arg(&k)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let port = loop {
            let mut line = String::new();
            assert!(out.read_line(&mut line).unwrap() > 0, "s_server exited");
            if let Some(addr) = line.trim().strip_prefix("ACCEPT ") {
                break addr.rsplit(':').next().unwrap().parse().unwrap();
            }
        };
        let mut stdin = child.stdin.take().unwrap();
        let request = std::thread::spawn(move || {
            let req = read_request(&mut out).unwrap_or_default();
            if let Some(reply) = reply {
                let _ = stdin.write_all(&reply);
                let _ = stdin.flush();
                // EOF on stdin makes s_server close the connection.
                drop(stdin);
            } else {
                // Keep the connection open without answering.
                std::thread::sleep(Duration::from_secs(30));
            }
            req
        });
        Some(TlsServer {
            port,
            child,
            request: Some(request),
            _dir: dir,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.port)
    }

    /// The request the server received.
    fn request(mut self) -> String {
        self.request.take().unwrap().join().unwrap()
    }
}

impl Drop for TlsServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// --- every verb, plain HTTP -------------------------------------------------------

#[test]
fn every_verb_succeeds_against_a_local_server() {
    let (port, seen) = raw_server(|req| {
        let body: &[u8] = if req.starts_with("HEAD") {
            b""
        } else {
            br#"{"ok":true}"#
        };
        with_len(
            "200 OK",
            &[("Content-Type", "application/json"), ("Allow", "GET, HEAD")],
            body,
        )
    });
    for verb in VERBS {
        let stage = format!("http://127.0.0.1:{port}/api/item.{verb}");
        let r = run(&[&stage]);
        assert_eq!(r.code, 0, "{verb}: {}", r.err);
        assert_eq!(r.err, "", "{verb}");
        assert!(!r.out.is_empty(), "{verb} printed nothing");
    }
    let methods: Vec<String> = seen
        .lock()
        .unwrap()
        .iter()
        .map(|r| r.split(' ').next().unwrap().to_string())
        .collect();
    assert_eq!(
        methods,
        [
            "GET", "HEAD", "GET", "OPTIONS", "OPTIONS", "GET", "POST", "PUT", "PATCH", "DELETE"
        ]
    );
}

#[test]
fn get_text_bytes_and_json_modes() {
    let server = Server::run();
    server.expect(
        Expectation::matching(all_of![
            request::method_path("GET", "/v1/users"),
            request::query(url_decoded(contains(("page", "2")))),
            request::headers(contains(("authorization", "Bearer secret-token"))),
        ])
        .times(3)
        .respond_with(json_encoded(json!([{"id": 1}]))),
    );
    let stage = format!("{}.get", server.url_str("/v1/users"));
    let auth = "headers=Authorization:Bearer secret-token";
    let r = run(&[&stage, "query=page=2", auth]);
    assert_eq!(
        (r.code, r.text()),
        (0, r#"[{"id":1}]"#.to_string()),
        "{}",
        r.err
    );
    let r = run(&[&stage, "query=page=2", auth, "accept=bytes"]);
    assert_eq!(r.out, br#"[{"id":1}]"#);
    let r = run(&[&stage, "query=page=2", auth, "accept=json"]);
    assert_eq!(r.json()["body"], json!([{"id": 1}]));
}

#[test]
fn head_and_headers_report_status() {
    let (port, _) = raw_server(|_| with_len("200 OK", &[("X-Thing", "v")], b""));
    let r = run(&[&format!("http://127.0.0.1:{port}/a.head")]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.json()["headers"]["x-thing"], "v");
    let r = run(&[&format!("http://127.0.0.1:{port}/a.headers"), "method=HEAD"]);
    assert_eq!(r.code, 0);
    assert_eq!(r.json()["headers"]["x-thing"], json!(["v"]));
}

#[test]
fn options_and_preflight() {
    let (port, seen) = raw_server(|_| {
        with_len(
            "204 No Content",
            &[
                ("Allow", "GET, POST"),
                ("Access-Control-Allow-Origin", "https://app.test"),
                ("Access-Control-Allow-Methods", "POST"),
            ],
            b"",
        )
    });
    let r = run(&[&format!("http://127.0.0.1:{port}/o.options")]);
    assert_eq!(r.code, 0);
    assert_eq!(r.json()["allowed_methods"], json!(["GET", "POST"]));
    let r = run(&[
        &format!("http://127.0.0.1:{port}/o.preflight"),
        "origin=https://app.test",
        "method=POST",
        "request_headers=X-A,X-B",
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(
        r.json()["cors"]["allowed_origins"],
        json!(["https://app.test"])
    );
    let req = seen.lock().unwrap()[1].to_ascii_lowercase();
    assert!(
        req.contains("access-control-request-headers: x-a, x-b"),
        "{req}"
    );
}

#[test]
fn request_bodies_from_args_files_and_stdin() {
    let (port, seen) = raw_server(|req| {
        let body = req.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        with_len("200 OK", &[], format!("echo:{body}").as_bytes())
    });
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("body.txt");
    std::fs::write(&file, "from-file").unwrap();
    let body_file = format!("body_file={}", file.display());
    for verb in ["post", "put", "patch", "delete"] {
        let stage = format!("http://127.0.0.1:{port}/b.{verb}");
        let r = run(&[&stage, "body=inline data"]);
        assert_eq!(
            (r.code, r.text()),
            (0, "echo:inline data".to_string()),
            "{verb}"
        );
        let r = run(&[&stage, &body_file]);
        assert_eq!(r.text(), "echo:from-file", "{verb}");
        let mut c = resh();
        c.args([&stage, "body_file=/dev/stdin"])
            .write_stdin("from-stdin");
        let r = run_cmd(c);
        assert_eq!(
            (r.code, r.text()),
            (0, "echo:from-stdin".to_string()),
            "{verb}"
        );
        let r = run(&[&stage, "body=a", &body_file]);
        assert_eq!(r.code, 2, "{verb}");
        assert!(r.err.contains("body and body_file cannot be used together"));
    }
    let r = run(&[
        &format!("http://127.0.0.1:{port}/b.json"),
        "method=POST",
        r#"body={"a":1}"#,
    ]);
    assert_eq!(r.json()["body"]["value"], r#"echo:{"a":1}"#);
    // Function-call form.
    let r = run(&[&format!(
        "http://127.0.0.1:{port}/b.post(body=fn-form,content_type=text/plain)"
    )]);
    assert_eq!(r.text(), "echo:fn-form");
    assert!(
        seen.lock()
            .unwrap()
            .last()
            .unwrap()
            .to_ascii_lowercase()
            .contains("content-type: text/plain")
    );
}

#[test]
fn large_uploads_and_downloads() {
    let size = 5 * 1024 * 1024;
    let (port, seen) = raw_server(move |req| {
        if req.starts_with("GET") {
            let body: Vec<u8> = (0..size).map(|i| (i % 253) as u8).collect();
            with_len("200 OK", &[], &body)
        } else {
            with_len("200 OK", &[], format!("got {}", req.len()).as_bytes())
        }
    });
    let r = run(&[&format!("http://127.0.0.1:{port}/big.get"), "accept=bytes"]);
    assert_eq!(r.code, 0);
    assert_eq!(r.out.len(), size);
    assert!(r.out.iter().enumerate().all(|(i, b)| *b == (i % 253) as u8));
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("up");
    std::fs::write(&f, vec![b'z'; size]).unwrap();
    let r = run(&[
        &format!("http://127.0.0.1:{port}/up.put"),
        &format!("body_file={}", f.display()),
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(seen.lock().unwrap()[1].ends_with(&"z".repeat(1000)));
}

#[test]
fn chunked_responses() {
    let (port, _) = raw_server(|_| {
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n".to_vec()
    });
    let r = run(&[&format!("http://127.0.0.1:{port}/c.get")]);
    assert_eq!(r.text(), r#"{"a":1}"#);
    let r = run(&[&format!("http://127.0.0.1:{port}/c.json")]);
    assert_eq!(r.json()["body"]["value"], json!({"a": 1}));
}

// --- exit codes ---------------------------------------------------------------------

#[test]
fn error_statuses_exit_1_with_the_reason_on_stderr_for_every_verb() {
    let (port, _) = raw_server(|_| with_len("503 Service Unavailable", &[], b"down"));
    for verb in VERBS {
        let r = run(&[&format!("http://127.0.0.1:{port}/x.{verb}")]);
        assert_eq!(r.code, 1, "{verb}");
        assert_eq!(
            r.err, "Error: [http.status_error] HTTP 503 Service Unavailable\n",
            "{verb}"
        );
    }
}

#[test]
fn network_failures_exit_1_and_timeouts_exit_124() {
    let refused = closed_port();
    let silent = silent_server();
    for verb in VERBS {
        let r = run(&[&format!("http://127.0.0.1:{refused}/x.{verb}")]);
        assert_eq!(r.code, 1, "{verb}: {}", r.err);
        assert!(
            r.err
                .starts_with("Error: [http.connection_failed] Connection failed"),
            "{verb}: {}",
            r.err
        );
        let start = Instant::now();
        let r = run(&[
            &format!("http://127.0.0.1:{silent}/x.{verb}"),
            "timeout_ms=300",
        ]);
        assert_eq!(r.code, 124, "{verb}: {}", r.err);
        assert_eq!(
            r.err, "Error: [http.timeout] Request timed out after 300 ms\n",
            "{verb}"
        );
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}

#[test]
fn usage_errors_exit_2_and_send_nothing() {
    let server = Server::run(); // panics on drop if any request arrives
    let base = server.url_str("/x");
    for verb in VERBS {
        let stage = format!("{base}.{verb}");
        for bad in [
            "timout_ms=5",
            "timeout_ms=soon",
            "follow_redirects=maybe",
            "allow_insecure=sometimes",
            "headers=nocolon",
            "dry_run=true",
        ] {
            let r = run(&[&stage, bad]);
            assert_eq!(r.code, 2, "{verb} {bad}: {}", r.err);
            // dry_run=true is refused by the dispatcher, the rest by http.
            let prefix = if bad == "dry_run=true" {
                "Error: "
            } else {
                "Error: [http."
            };
            assert!(r.err.starts_with(prefix), "{verb} {bad}: {}", r.err);
        }
    }
    let r = run(&[&format!("{base}.get"), "acept=json"]);
    assert!(r.err.contains("did you mean `accept`?"), "{}", r.err);
    let r = run(&[&format!("{base}.fetch")]);
    assert_eq!(r.code, 2);
}

// --- redirects and proxies -----------------------------------------------------------

#[test]
fn redirects_follow_by_default_and_can_be_disabled() {
    let (port, _) = raw_server(|req| {
        if req.contains(" /old ") {
            // The server closes each connection after one response.
            with_len(
                "301 Moved Permanently",
                &[("Location", "/new"), ("Connection", "close")],
                b"",
            )
        } else {
            with_len("200 OK", &[("Connection", "close")], b"new place")
        }
    });
    for verb in VERBS {
        let stage = format!("http://127.0.0.1:{port}/old.{verb}");
        assert_eq!(run(&[&stage]).code, 0, "{verb}");
        let r = run(&[&stage, "follow_redirects=false"]);
        assert_eq!(r.code, 0, "{verb}: {}", r.err);
    }
    let r = run(&[&format!("http://127.0.0.1:{port}/old.get")]);
    assert_eq!(r.text(), "new place");
    let r = run(&[
        &format!("http://127.0.0.1:{port}/old.json"),
        "follow_redirects=false",
    ]);
    assert_eq!(r.json()["status"], 301);
}

#[test]
fn proxy_environment_variables_are_honored() {
    // A plain-HTTP request goes to the proxy in absolute form.
    let (port, seen) = raw_server(|_| with_len("200 OK", &[], b"via proxy"));
    let mut c = resh();
    c.env("HTTP_PROXY", format!("http://127.0.0.1:{port}"))
        .arg("http://resh-proxy-test.invalid/p.get");
    let r = run_cmd(c);
    assert_eq!(
        (r.code, r.text()),
        (0, "via proxy".to_string()),
        "{}",
        r.err
    );
    assert!(
        seen.lock().unwrap()[0].starts_with("GET http://resh-proxy-test.invalid/p HTTP/1.1"),
        "{:?}",
        seen.lock().unwrap()
    );
    // HTTPS goes through CONNECT; a refusing proxy is a connection failure.
    let (port, seen) = raw_server(|_| with_len("403 Forbidden", &[], b""));
    let mut c = resh();
    c.env("HTTPS_PROXY", format!("http://127.0.0.1:{port}"))
        .arg("https://resh-proxy-test.invalid/p.get");
    let r = run_cmd(c);
    assert_eq!(r.code, 1, "{}", r.err);
    assert!(seen.lock().unwrap()[0].starts_with("CONNECT resh-proxy-test.invalid:443 "));
    // NO_PROXY bypasses it.
    let (target, _) = raw_server(|_| with_len("200 OK", &[], b"direct"));
    let mut c = resh();
    c.env("HTTP_PROXY", format!("http://127.0.0.1:{}", closed_port()))
        .env("NO_PROXY", "127.0.0.1")
        .arg(format!("http://127.0.0.1:{target}/d.get"));
    assert_eq!(run_cmd(c).text(), "direct");
}

// --- https -----------------------------------------------------------------------------

#[test]
fn https_rejects_an_untrusted_certificate_for_every_verb() {
    for verb in VERBS {
        let Some(server) = TlsServer::start(Some(with_len("200 OK", &[], b"secret"))) else {
            return;
        };
        let r = run(&[&server.url(&format!("/x.{verb}"))]);
        assert_eq!(r.code, 1, "{verb}: {}", r.err);
        assert!(
            r.err
                .starts_with("Error: [http.connection_failed] Connection failed"),
            "{verb}: {}",
            r.err
        );
        assert!(
            r.err.to_ascii_lowercase().contains("certificate"),
            "{verb}: {}",
            r.err
        );
        assert!(!r.text().contains("secret"));
    }
}

#[test]
fn https_allow_insecure_works_for_every_verb() {
    for verb in VERBS {
        let Some(server) = TlsServer::start(Some(with_len(
            "200 OK",
            &[
                ("Content-Type", "application/json"),
                ("Connection", "close"),
            ],
            if verb == "head" {
                b""
            } else {
                br#"{"tls":true}"#
            },
        ))) else {
            return;
        };
        let mut args = vec![
            server.url(&format!("/secure.{verb}")),
            "allow_insecure=true".into(),
        ];
        if ["post", "put", "patch", "delete"].contains(&verb) {
            args.push("body=payload".into());
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let r = run(&args);
        assert_eq!(r.code, 0, "{verb}: {}", r.err);
        let req = server.request();
        assert!(req.contains(" /secure HTTP/1.1"), "{verb}: {req}");
        if args.len() == 3 {
            assert!(req.ends_with("payload"), "{verb}: {req}");
        }
    }
}

#[test]
fn https_timeout_exits_124() {
    let Some(server) = TlsServer::start(None) else {
        return;
    };
    let start = Instant::now();
    let r = run(&[
        &server.url("/slow.get"),
        "allow_insecure=true",
        "timeout_ms=500",
    ]);
    assert_eq!(r.code, 124, "{}", r.err);
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
fn https_allow_insecure_false_still_verifies() {
    let Some(server) = TlsServer::start(Some(with_len("200 OK", &[], b"x"))) else {
        return;
    };
    let r = run(&[&server.url("/x.put"), "allow_insecure=false", "body=a"]);
    assert_eq!(r.code, 1, "{}", r.err);
}

// --- --json-pretty ---------------------------------------------------------------------

#[test]
fn json_pretty_reformats_envelopes() {
    let (port, _) = raw_server(|_| {
        with_len(
            "200 OK",
            &[("Content-Type", "application/json")],
            b"{\"a\":1}",
        )
    });
    let r = run(&["--json-pretty", &format!("http://127.0.0.1:{port}/p.json")]);
    assert!(r.text().contains("\n  \"body\": {\n"), "{}", r.text());
}

// --- help -----------------------------------------------------------------------------

fn golden(scheme: &str, verb: Option<&str>) -> &'static str {
    match (scheme, verb) {
        ("http", None) => include_str!("golden/http_help.txt"),
        ("https", None) => include_str!("golden/https_help.txt"),
        ("http", Some("get")) => include_str!("golden/http_get_help.txt"),
        ("http", Some("head")) => include_str!("golden/http_head_help.txt"),
        ("http", Some("headers")) => include_str!("golden/http_headers_help.txt"),
        ("http", Some("options")) => include_str!("golden/http_options_help.txt"),
        ("http", Some("preflight")) => include_str!("golden/http_preflight_help.txt"),
        ("http", Some("json")) => include_str!("golden/http_json_help.txt"),
        ("http", Some("post")) => include_str!("golden/http_post_help.txt"),
        ("http", Some("put")) => include_str!("golden/http_put_help.txt"),
        ("http", Some("patch")) => include_str!("golden/http_patch_help.txt"),
        ("http", Some("delete")) => include_str!("golden/http_delete_help.txt"),
        ("https", Some("get")) => include_str!("golden/https_get_help.txt"),
        ("https", Some("head")) => include_str!("golden/https_head_help.txt"),
        ("https", Some("headers")) => include_str!("golden/https_headers_help.txt"),
        ("https", Some("options")) => include_str!("golden/https_options_help.txt"),
        ("https", Some("preflight")) => include_str!("golden/https_preflight_help.txt"),
        ("https", Some("json")) => include_str!("golden/https_json_help.txt"),
        ("https", Some("post")) => include_str!("golden/https_post_help.txt"),
        ("https", Some("put")) => include_str!("golden/https_put_help.txt"),
        ("https", Some("patch")) => include_str!("golden/https_patch_help.txt"),
        ("https", Some("delete")) => include_str!("golden/https_delete_help.txt"),
        _ => unreachable!(),
    }
}

/// The options each verb parses (kept in step with `verb_args` and
/// `COMMON_ARGS` in src/handles/network/httph.rs; a unit test there checks
/// the usage text against those lists).
fn options(verb: &str) -> Vec<&'static str> {
    let mut v: Vec<&str> = match verb {
        "get" | "head" => vec!["accept"],
        "headers" => vec!["method"],
        "options" => vec!["include_body"],
        "preflight" => vec!["origin", "method", "request_headers"],
        "json" => vec!["method", "body", "content_type", "accept"],
        "post" => vec!["body", "body_file", "content_type"],
        "put" | "patch" | "delete" => vec!["body", "body_file", "content_type", "accept"],
        _ => unreachable!(),
    };
    v.extend([
        "query",
        "headers",
        "timeout_ms",
        "follow_redirects",
        "allow_insecure",
    ]);
    v.sort();
    v
}

fn section<'a>(help: &'a str, name: &str) -> &'a str {
    help.split(&format!("\n{name}:\n"))
        .nth(1)
        .unwrap_or_else(|| panic!("no {name} section"))
        .split("\n\n")
        .next()
        .unwrap()
}

fn assert_plain(out: &str) {
    assert!(out.is_ascii() && !out.contains('\x1b'));
    for line in out.lines() {
        assert!(line.len() <= 80, "line over 80 columns: {line:?}");
        assert!(!line.ends_with(' '), "trailing space: {line:?}");
    }
}

#[test]
fn handle_help_matches_golden_for_both_schemes_and_all_aliases() {
    for scheme in ["http", "https"] {
        for alias in ["--help", "-h", "help"] {
            let r = run(&[scheme, alias]);
            assert_eq!((r.code, r.err.as_str()), (0, ""), "{scheme} {alias}");
            assert_eq!(r.text(), golden(scheme, None), "{scheme} {alias}");
        }
        let r = run(&["help", scheme]);
        assert_eq!(r.text(), golden(scheme, None));
        let r = run(&[&format!("{scheme}://--help")]);
        assert_eq!((r.code, r.text()), (0, golden(scheme, None).to_string()));
        let out = golden(scheme, None);
        assert_plain(out);
        assert!(out.starts_with(&format!("Handle: {scheme}\n")));
        let mut listed: Vec<&str> = section(out, "Available Verbs")
            .lines()
            .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
            .map(|l| l.split_whitespace().next().unwrap())
            .collect();
        listed.sort();
        let mut verbs = VERBS.to_vec();
        verbs.sort();
        assert_eq!(listed, verbs);
    }
}

#[test]
fn verb_help_matches_golden_and_lists_parsed_options() {
    for scheme in ["http", "https"] {
        for verb in VERBS {
            for alias in ["--help", "-h", "help"] {
                let r = run(&[scheme, verb, alias]);
                assert_eq!((r.code, r.err.as_str()), (0, ""), "{scheme} {verb} {alias}");
                assert_eq!(
                    r.text(),
                    golden(scheme, Some(verb)),
                    "{scheme} {verb} {alias}"
                );
            }
            let r = run(&["help", scheme, verb]);
            assert_eq!(r.text(), golden(scheme, Some(verb)));
            let out = golden(scheme, Some(verb));
            assert_plain(out);
            assert!(out.starts_with(&format!("Handle: {scheme}\nVerb: {verb}\nDefinition: ")));
            let usage = section(out, "Usage");
            assert!(usage.contains(&format!("{scheme}://<host>/<path>.{verb} ")));
            let mut listed: Vec<&str> = usage
                .split(|c: char| c == '[' || c.is_whitespace())
                .filter_map(|w| w.split_once('=').map(|(k, _)| k))
                .collect();
            listed.sort();
            assert_eq!(listed, options(verb), "{scheme} {verb} usage options");
            assert!(
                section(out, "Example")
                    .trim_start()
                    .starts_with(&format!("resh {scheme}://"))
            );
        }
    }
}

/// Splits a help example into words, honoring single quotes.
fn words(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut quoted) = (Vec::new(), String::new(), false);
    for c in s.chars() {
        match c {
            '\'' => quoted = !quoted,
            ' ' if !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// The JSON or text shown under "Example Output:", up to its note.
fn example_output(help: &str) -> String {
    help.split("\nExample Output:\n")
        .nth(1)
        .unwrap()
        .split("\n\n")
        .next()
        .unwrap()
        .lines()
        .map(|l| l.strip_prefix("  ").unwrap_or(l))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The response a local server gives so each help example prints the
/// documented output.
fn example_response(verb: &str) -> Vec<u8> {
    let ct = ("Content-Type", "application/json");
    match verb {
        "get" => with_len("200 OK", &[ct], br#"{"id":42,"name":"alice"}"#),
        "json" => response("200 OK", &[ct], br#"{"id":42,"name":"alice"}"#),
        "head" => response(
            "200 OK",
            &[
                ("Content-Length", "1256"),
                ("Content-Type", "text/html; charset=UTF-8"),
                ("Last-Modified", "Mon, 13 Jan 2025 20:11:20 GMT"),
            ],
            b"",
        ),
        "headers" => response(
            "200 OK",
            &[("Content-Type", "text/html"), ("Server", "nginx")],
            b"",
        ),
        "options" => response(
            "204 No Content",
            &[("Allow", "GET, POST, OPTIONS"), ("Content-Length", "0")],
            b"",
        ),
        "preflight" => response(
            "204 No Content",
            &[
                ("Access-Control-Allow-Origin", "https://example.org"),
                ("Access-Control-Allow-Methods", "GET, POST"),
                ("Access-Control-Allow-Headers", "Content-Type"),
                ("Access-Control-Max-Age", "600"),
            ],
            b"",
        ),
        "post" => response("201 Created", &[], br#"{"id":43,"name":"alice"}"#),
        "put" => response("200 OK", &[], br#"{"id":42,"name":"alice"}"#),
        "patch" => response("200 OK", &[], br#"{"id":42,"name":"bob"}"#),
        "delete" => response("200 OK", &[ct], br#"{"deleted":true,"id":42}"#),
        _ => unreachable!(),
    }
}

#[test]
fn help_examples_run_and_print_the_documented_output() {
    for verb in VERBS {
        let (port, seen) = raw_server(move |_| example_response(verb));
        let help = golden("http", Some(verb));
        let example = section(help, "Example").trim();
        let mut w = words(example);
        assert_eq!(w.remove(0), "resh");
        let stage = w[0].clone();
        let host = stage
            .strip_prefix("http://")
            .unwrap()
            .split(['/', '.'])
            .take_while(|p| *p != "com")
            .collect::<Vec<_>>()
            .join(".")
            + ".com";
        w[0] = stage.replacen(&host, &format!("127.0.0.1:{port}"), 1);
        let r = run(&w.iter().map(String::as_str).collect::<Vec<_>>());
        assert_eq!(r.code, 0, "{verb}: {example}: {}", r.err);
        let shown = example_output(help);
        let actual = r.text().replace(&format!("127.0.0.1:{port}"), &host);
        match serde_json::from_str::<Value>(&shown) {
            Ok(expected) if verb != "delete" => {
                let got: Value = serde_json::from_str(&actual)
                    .unwrap_or_else(|e| panic!("{verb}: {e}: {actual}"));
                assert_eq!(got, expected, "{verb}");
            }
            // delete pretty-prints; post, put and patch print the body as is.
            _ => assert_eq!(actual, shown, "{verb}"),
        }
        assert_eq!(seen.lock().unwrap().len(), 1, "{verb}");
    }
}
