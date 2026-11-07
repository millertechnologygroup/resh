//! Dispatch tests for the http/https handle: every verb through
//! `Handle::call`, against local servers on 127.0.0.1 only.

use super::*;
use httptest::{Expectation, Server, all_of, matchers::*, responders::*};
use std::io::{BufRead, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Instant;

struct Out {
    status: Status,
    out: Vec<u8>,
    err: String,
}

impl Out {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.out).into_owned()
    }
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.out)
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {}", self.text()))
    }
    fn code(&self) -> i32 {
        self.status.exit_code()
    }
    fn reason(&self) -> String {
        self.status.reason.clone().unwrap_or_default()
    }
}

fn args(pairs: &[(&str, &str)]) -> Args {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn call(url: &str, verb: &str, pairs: &[(&str, &str)]) -> Out {
    let h = HttpHandle::from_url(&Url::parse(url).unwrap()).unwrap();
    let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
    let mut io = IoStreams::new(&mut i, &mut o, &mut e);
    let status = h.call(verb, &args(pairs), &mut io).unwrap();
    Out {
        status,
        out: o,
        err: String::from_utf8_lossy(&e).into_owned(),
    }
}

fn assert_code(o: &Out, code: i32, reason_part: &str) {
    assert_eq!(o.code(), code, "reason: {:?} out: {}", o.reason(), o.text());
    assert!(
        o.reason().contains(reason_part),
        "reason {:?} lacks {reason_part:?}",
        o.reason()
    );
}

const ALL_VERBS: [&str; 10] = [
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

// --- local servers ---------------------------------------------------------

/// A port with nothing listening on it.
fn closed_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A server that accepts connections and never answers.
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

/// Reads one HTTP/1.1 request (head and Content-Length body) from `s`.
fn read_request(s: &mut TcpStream) -> Option<String> {
    let mut r = BufReader::new(s.try_clone().ok()?);
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

/// A server that answers every request with the bytes `respond` returns for
/// it (a full HTTP response), and records the requests.
fn raw_server(
    respond: impl Fn(&str) -> Vec<u8> + Send + Sync + 'static,
) -> (u16, Arc<Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    let respond = Arc::new(respond);
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let seen = seen2.clone();
            let respond = respond.clone();
            std::thread::spawn(move || {
                while let Some(req) = read_request(&mut s) {
                    seen.lock().unwrap().push(req.clone());
                    if s.write_all(&respond(&req)).is_err() {
                        return;
                    }
                }
            });
        }
    });
    (port, seen)
}

fn http_response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut r = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n", body.len());
    for (k, v) in headers {
        r.push_str(&format!("{k}: {v}\r\n"));
    }
    r.push_str("\r\n");
    let mut r = r.into_bytes();
    r.extend_from_slice(body);
    r
}

/// Sends the response head and part of the body, then stalls.
fn stalled_body_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for mut s in l.incoming().flatten() {
            let _ = read_request(&mut s);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial");
            held.push(s);
        }
    });
    port
}

fn url(server: &Server, path: &str) -> String {
    server.url_str(path)
}

// --- argument checking (nothing is sent) --------------------------------------

#[test]
fn unknown_arguments_are_refused_with_a_suggestion_and_nothing_is_sent() {
    // The server has no expectations: any request makes it panic on drop.
    let server = Server::run();
    let u = url(&server, "/x");
    for verb in ALL_VERBS {
        let o = call(&u, verb, &[("timout_ms", "5")]);
        assert_code(&o, 2, "unknown argument");
        assert!(o.reason().contains("did you mean `timeout_ms`?"), "{verb}");
        let o = call(&u, verb, &[("zzzzzzzz", "1")]);
        assert_code(&o, 2, "zzzzzzzz");
        assert!(!o.reason().contains("did you mean"), "{verb}");
        let o = call(&u, verb, &[("dry_run", "false")]);
        assert_code(&o, 2, "does not support dry_run");
    }
    // Options of other verbs are unknown here.
    assert_code(
        &call(&u, "get", &[("body", "x")]),
        2,
        "unknown argument for http get: body",
    );
    assert_code(&call(&u, "post", &[("accept", "json")]), 2, "post: accept");
    assert_code(&call(&u, "head", &[("method", "GET")]), 2, "head: method");
    assert_code(
        &call(&u, "json", &[("body_file", "/x")]),
        2,
        "json: body_file",
    );
}

#[test]
fn unknown_verb_is_a_usage_error() {
    let o = call("http://127.0.0.1:1/", "fetch", &[]);
    assert_code(&o, 2, "unknown verb for http://: fetch");
    let o = call("https://127.0.0.1:1/", "fetch", &[]);
    assert_code(&o, 2, "unknown verb for https://");
}

#[test]
fn common_option_values_are_validated_for_every_verb() {
    let server = Server::run();
    let u = url(&server, "/x");
    for verb in ALL_VERBS {
        for bad in ["soon", "0", "-5", "", "1.5"] {
            let o = call(&u, verb, &[("timeout_ms", bad)]);
            assert_code(&o, 2, "invalid timeout_ms");
        }
        for key in ["follow_redirects", "allow_insecure"] {
            let o = call(&u, verb, &[(key, "maybe")]);
            assert_code(&o, 2, key);
        }
        let o = call(&u, verb, &[("headers", "NoColonHere")]);
        assert_code(&o, 2, "invalid header format");
        let o = call(&u, verb, &[("headers", "Bad Name:x")]);
        assert_code(&o, 2, "invalid header name");
        let o = call(&u, verb, &[("headers", "X-A:line\nbreak")]);
        assert_code(&o, 2, "invalid value for header");
    }
}

#[test]
fn verb_specific_values_are_validated() {
    let server = Server::run();
    let u = url(&server, "/x");
    for verb in ["get", "head", "json", "put", "patch", "delete"] {
        assert_code(&call(&u, verb, &[("accept", "xml")]), 2, "invalid accept");
    }
    assert_code(
        &call(&u, "json", &[("method", "TRACE")]),
        2,
        "Unsupported method",
    );
    assert_code(
        &call(&u, "json", &[("method", "GET"), ("body", "{}")]),
        2,
        "body is sent only with POST, PUT, PATCH or DELETE",
    );
    assert_code(
        &call(&u, "options", &[("include_body", "perhaps")]),
        2,
        "include_body",
    );
    assert_code(
        &call(&u, "preflight", &[("method", "BAD METHOD")]),
        2,
        "invalid method",
    );
    assert_code(
        &call(&u, "preflight", &[("method", "")]),
        2,
        "invalid method",
    );
    assert_code(
        &call(
            &u,
            "preflight",
            &[("request_headers", "Content-Type,Bad Header")],
        ),
        2,
        "invalid header name in request_headers",
    );
    assert_code(
        &call(&u, "preflight", &[("origin", "a\nb")]),
        2,
        "invalid origin",
    );
    for verb in ["post", "put", "patch", "delete"] {
        assert_code(
            &call(&u, verb, &[("body", "a"), ("body_file", "/etc/hostname")]),
            2,
            "body and body_file cannot be used together",
        );
        assert_code(
            &call(&u, verb, &[("body_file", "")]),
            2,
            "body_file is empty",
        );
        assert_code(
            &call(&u, verb, &[("content_type", "a\nb")]),
            2,
            "invalid content_type",
        );
        let o = call(&u, verb, &[("body_file", "/nonexistent/resh-http-body")]);
        assert_code(
            &o,
            1,
            "failed to read body_file '/nonexistent/resh-http-body'",
        );
    }
    assert_code(
        &call(&u, "json", &[("content_type", "a\nb")]),
        2,
        "invalid content_type",
    );
}

#[test]
fn help_usage_lists_exactly_the_accepted_options() {
    for help in [&HTTP_HELP, &HTTPS_HELP] {
        for verb in help.verbs {
            let usage = verb.detail.as_ref().unwrap().usage;
            let mut in_usage: Vec<&str> = usage
                .split(|c: char| c == '[' || c.is_whitespace())
                .filter_map(|w| w.split_once('=').map(|(k, _)| k))
                .collect();
            in_usage.sort();
            let mut accepted: Vec<&str> = verb_args(verb.name)
                .unwrap()
                .iter()
                .chain(COMMON_ARGS.iter())
                .copied()
                .collect();
            accepted.sort();
            assert_eq!(in_usage, accepted, "usage of {}", verb.name);
        }
        let names: Vec<&str> = help.verbs.iter().map(|v| v.name).collect();
        assert_eq!(names.len(), ALL_VERBS.len());
        for v in ALL_VERBS {
            assert!(names.contains(&v));
        }
    }
}

// --- network failures -------------------------------------------------------

#[test]
fn connection_refused_exits_1_for_every_verb() {
    let u = format!("http://127.0.0.1:{}/x", closed_port());
    for verb in ALL_VERBS {
        let o = call(&u, verb, &[]);
        assert_code(&o, 1, "Connection failed");
        assert!(o.err.is_empty(), "{verb} wrote to stderr: {}", o.err);
    }
    // The JSON verbs still print their documented error shapes.
    let j = call(&u, "json", &[]).json();
    assert_eq!(j["status"], 0);
    assert!(
        j["error"]
            .as_str()
            .unwrap()
            .starts_with("Connection failed")
    );
    let h = call(&u, "headers", &[]).json();
    assert_eq!(h["error"]["kind"], "network");
    let p = call(&u, "preflight", &[]).json();
    assert_eq!(
        (p["ok"].clone(), p["status"].clone()),
        (json!(false), json!(null))
    );
    assert!(
        p["error"]
            .as_str()
            .unwrap()
            .starts_with("Connection failed")
    );
}

#[test]
fn a_server_that_never_answers_times_out_with_124_for_every_verb() {
    let u = format!("http://127.0.0.1:{}/x", silent_server());
    for verb in ALL_VERBS {
        let start = Instant::now();
        let o = call(&u, verb, &[("timeout_ms", "300")]);
        assert_code(&o, 124, "Request timed out after 300 ms");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{verb} took too long"
        );
    }
    assert_eq!(
        call(&u, "headers", &[("timeout_ms", "200")]).json()["error"]["kind"],
        "timeout"
    );
    assert!(
        call(&u, "json", &[("timeout_ms", "200")]).json()["error"]
            .as_str()
            .unwrap()
            .contains("timed out")
    );
}

#[test]
fn the_timeout_also_bounds_reading_the_body() {
    let u = format!("http://127.0.0.1:{}/x", stalled_body_server());
    for verb in ["get", "options", "json", "post", "put", "patch", "delete"] {
        let start = Instant::now();
        let o = call(&u, verb, &[("timeout_ms", "400")]);
        assert_code(&o, 124, "timed out");
        assert!(
            start.elapsed() < Duration::from_millis(2_000),
            "{verb}: {:?}",
            start.elapsed()
        );
    }
}

#[test]
fn https_to_a_plain_http_server_fails_with_exit_1() {
    let server = Server::run();
    let u = format!("https://127.0.0.1:{}/x", server.addr().port());
    for verb in ALL_VERBS {
        let o = call(&u, verb, &[("timeout_ms", "3000")]);
        assert_eq!(o.code(), 1, "{verb}: {}", o.reason());
    }
}

// --- HTTP status and exit codes ------------------------------------------------

#[test]
fn error_statuses_exit_1_for_every_verb_with_output_still_printed() {
    for code in [404u16, 500] {
        let (port, _) = raw_server(move |_| {
            http_response(
                &format!("{code} X"),
                &[("Content-Type", "application/json")],
                br#"{"error":"nope"}"#,
            )
        });
        let u = format!("http://127.0.0.1:{port}/x");
        for verb in ALL_VERBS {
            let o = call(&u, verb, &[]);
            let reason = if code == 404 {
                "HTTP 404 Not Found"
            } else {
                "HTTP 500 Internal Server Error"
            };
            assert_code(&o, 1, reason);
            if verb != "head" {
                assert!(!o.out.is_empty(), "{verb} printed nothing for {code}");
            }
        }
        let u = &u;
        assert_eq!(call(u, "head", &[]).json()["ok"], false);
        assert_eq!(call(u, "head", &[]).json()["status"], code);
        assert_eq!(call(u, "headers", &[]).json()["status"], code);
        assert_eq!(call(u, "json", &[]).json()["status"], code);
        assert_eq!(
            call(u, "json", &[]).json()["body"]["value"]["error"],
            "nope"
        );
        assert_eq!(call(u, "get", &[]).text(), r#"{"error":"nope"}"#);
        assert_eq!(
            call(u, "patch", &[("accept", "json")]).text(),
            r#"{"error":"nope"}"#
        );
    }
}

#[test]
fn success_statuses_exit_0() {
    for code in [200u16, 201, 204] {
        let (port, _) = raw_server(move |_| http_response(&format!("{code} X"), &[], b""));
        let u = format!("http://127.0.0.1:{port}/x");
        for verb in ALL_VERBS {
            let o = call(&u, verb, &[]);
            assert_eq!(o.code(), 0, "{verb} {code}: {}", o.reason());
        }
    }
}

#[test]
fn redirects_are_followed_by_every_verb_unless_disabled() {
    let (port, seen) = raw_server(|req| {
        if req.starts_with("GET /old")
            || req.starts_with("HEAD /old")
            || req.starts_with("OPTIONS /old")
        {
            http_response("302 Found", &[("Location", "/new")], b"moved")
        } else {
            http_response(
                "200 OK",
                &[("Content-Type", "application/json")],
                b"{\"at\":\"new\"}",
            )
        }
    });
    let u = format!("http://127.0.0.1:{port}/old");
    for verb in ["get", "head", "headers", "options", "preflight", "json"] {
        let o = call(&u, verb, &[]);
        assert_eq!(o.code(), 0, "{verb}: {}", o.reason());
        seen.lock().unwrap().clear();
        let o = call(&u, verb, &[("follow_redirects", "false")]);
        // The redirect itself is the answer: exit 0, and nothing else fetched.
        assert_eq!(o.code(), 0, "{verb} no-follow: {}", o.reason());
        assert_eq!(seen.lock().unwrap().len(), 1, "{verb}");
    }
    let get = call(&u, "get", &[]);
    assert_eq!(get.text(), "{\"at\":\"new\"}");
    assert!(
        call(&u, "head", &[]).json()["url"]
            .as_str()
            .unwrap()
            .ends_with("/new")
    );
    let h = call(&u, "headers", &[("follow_redirects", "false")]).json();
    assert_eq!(h["status"], 302);
    assert_eq!(h["headers"]["location"][0], "/new");
    assert_eq!(
        call(&u, "get", &[("follow_redirects", "no")]).text(),
        "moved"
    );
}

#[test]
fn a_redirect_loop_fails_with_exit_1() {
    let (port, _) = raw_server(|_| http_response("302 Found", &[("Location", "/loop")], b""));
    let u = format!("http://127.0.0.1:{port}/loop");
    for verb in ["get", "json", "headers"] {
        assert_code(&call(&u, verb, &[]), 1, "Redirect failed");
    }
}

#[test]
fn a_final_redirect_that_is_not_followed_exits_1() {
    // 300 without Location cannot be followed: it is not a success.
    let (port, _) = raw_server(|_| http_response("300 Multiple Choices", &[], b"pick"));
    let u = format!("http://127.0.0.1:{port}/x");
    let o = call(&u, "get", &[]);
    assert_code(&o, 1, "HTTP 300 Multiple Choices");
    assert_eq!(o.text(), "pick");
    assert_eq!(call(&u, "options", &[]).code(), 1);
    assert_eq!(
        call(&u, "options", &[("follow_redirects", "false")]).code(),
        0
    );
}

// --- get ----------------------------------------------------------------------

#[test]
fn get_prints_the_body_in_each_accept_mode() {
    let server = Server::run();
    server.expect(
        Expectation::matching(request::method_path("GET", "/u/42"))
            .times(3)
            .respond_with(json_encoded(json!({"id": 42}))),
    );
    let u = url(&server, "/u/42");
    let o = call(&u, "get", &[]);
    assert_eq!((o.code(), o.text()), (0, r#"{"id":42}"#.to_string()));
    assert_eq!(call(&u, "get", &[("accept", "bytes")]).out, br#"{"id":42}"#);
    let j = call(&u, "get", &[("accept", "json")]).json();
    assert_eq!(j["status"], 200);
    assert_eq!(j["ok"], true);
    assert_eq!(j["method"], "GET");
    assert_eq!(j["body"]["id"], 42);
    assert_eq!(j["body_text"], r#"{"id":42}"#);
    assert_eq!(j["headers"]["content-type"][0], "application/json");
}

#[test]
fn get_json_envelope_keeps_a_non_json_body_as_a_string() {
    let (port, _) =
        raw_server(|_| http_response("200 OK", &[("Content-Type", "text/plain")], b"{\"a\":1}"));
    let j = call(
        &format!("http://127.0.0.1:{port}/"),
        "get",
        &[("accept", "json")],
    )
    .json();
    assert_eq!(j["body"], "{\"a\":1}");
}

#[test]
fn get_bytes_and_text_keep_binary_bodies_intact() {
    let bin: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let b2 = bin.clone();
    let (port, _) = raw_server(move |_| http_response("200 OK", &[], &b2));
    let u = format!("http://127.0.0.1:{port}/b");
    assert_eq!(call(&u, "get", &[("accept", "bytes")]).out, bin);
    assert_eq!(call(&u, "get", &[]).out, bin);
}

#[test]
fn get_sends_query_and_headers() {
    let server = Server::run();
    server.expect(
        Expectation::matching(all_of![
            request::method_path("GET", "/s"),
            request::query(url_decoded(contains(("a", "1")))),
            request::query(url_decoded(contains(("b", "two words")))),
            request::query(url_decoded(contains(("keep", "yes")))),
            request::headers(contains(("x-token", "abc"))),
            request::headers(contains(("x-multi", "1"))),
            request::headers(contains(("x-multi", "2"))),
            request::headers(contains(("authorization", "Bearer t0k"))),
        ])
        .respond_with(status_code(200).body("ok")),
    );
    let o = call(
        &url(&server, "/s?keep=yes"),
        "get",
        &[
            ("query", "a=1&b=two%20words"),
            (
                "headers",
                "X-Token: abc; X-Multi:1;X-Multi:2;Authorization:Bearer t0k",
            ),
        ],
    );
    assert_eq!(
        (o.code(), o.text()),
        (0, "ok".to_string()),
        "{}",
        o.reason()
    );
}

#[test]
fn dropped_headers_are_not_forwarded() {
    let (port, seen) = raw_server(|_| http_response("200 OK", &[], b""));
    let u = format!("http://127.0.0.1:{port}/d");
    let o = call(
        &u,
        "get",
        &[("headers", "Host:evil.example;Connection:upgrade;X-Ok:1")],
    );
    assert_eq!(o.code(), 0);
    let req = seen.lock().unwrap()[0].to_ascii_lowercase();
    assert!(req.contains(&format!("host: 127.0.0.1:{port}")), "{req}");
    assert!(!req.contains("evil.example"));
    assert!(!req.contains("connection: upgrade"));
    assert!(req.contains("x-ok: 1"));
}

#[test]
fn get_reads_large_and_chunked_bodies() {
    let big: Vec<u8> = (0..8 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let big2 = big.clone();
    let (port, _) = raw_server(move |_| http_response("200 OK", &[], &big2));
    let o = call(
        &format!("http://127.0.0.1:{port}/big"),
        "get",
        &[("accept", "bytes")],
    );
    assert_eq!(o.code(), 0);
    assert!(o.out == big, "large body differs ({} bytes)", o.out.len());

    let (port, _) = raw_server(|_| {
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n7\r\n, world\r\n0\r\n\r\n"
            .to_vec()
    });
    let u = format!("http://127.0.0.1:{port}/c");
    assert_eq!(call(&u, "get", &[]).text(), "hello, world");
    assert_eq!(
        call(&u, "json", &[]).json()["body"]["value"],
        "hello, world"
    );
    assert_eq!(call(&u, "post", &[]).text(), "hello, world");
}

#[test]
fn a_truncated_body_fails_with_exit_1() {
    // The server closes the connection after 5 of 50 promised bytes.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Some(Ok(mut s)) = l.incoming().next() {
            let _ = read_request(&mut s);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort");
        }
    });
    let o = call(&format!("http://127.0.0.1:{port}/t"), "get", &[]);
    assert_code(&o, 1, "Request failed");
}

// --- head -----------------------------------------------------------------------

#[test]
fn head_reports_status_and_joined_headers() {
    let (port, seen) = raw_server(|_| {
        b"HTTP/1.1 200 OK\r\nContent-Length: 1256\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Type: text/html\r\n\r\n".to_vec()
    });
    let u = format!("http://127.0.0.1:{port}/index.html");
    let o = call(&u, "head", &[("query", "v=1"), ("accept", "json")]);
    assert_eq!(o.code(), 0, "{}", o.reason());
    let j = o.json();
    assert_eq!(j["url"], format!("http://127.0.0.1:{port}/index.html?v=1"));
    assert_eq!(j["status"], 200);
    assert_eq!(j["ok"], true);
    assert_eq!(j["reason"], "OK");
    assert_eq!(j["headers"]["set-cookie"], "a=1, b=2");
    assert_eq!(j["headers"]["content-length"], "1256");
    let req = seen.lock().unwrap()[0].clone();
    assert!(req.starts_with("HEAD /index.html?v=1 HTTP/1.1"), "{req}");
    assert!(
        req.to_ascii_lowercase()
            .contains("accept: application/json")
    );
    for (accept, header) in [("text", "text/*"), ("bytes", "*/*")] {
        seen.lock().unwrap().clear();
        call(&u, "head", &[("accept", accept), ("headers", "Accept:x/y")]);
        let req = seen.lock().unwrap()[0].to_ascii_lowercase();
        assert!(req.contains(&format!("accept: {header}")), "{req}");
        assert!(!req.contains("x/y"), "accept= wins over headers=");
    }
}

// --- headers -----------------------------------------------------------------------

#[test]
fn headers_sends_the_chosen_method_without_a_body() {
    let (port, seen) =
        raw_server(|_| http_response("200 OK", &[("X-A", "1"), ("X-A", "2")], b"body"));
    let u = format!("http://127.0.0.1:{port}/h");
    let j = call(&u, "headers", &[]).json();
    assert_eq!(j["status"], 200);
    assert_eq!(j["status_text"], "OK");
    assert_eq!(j["headers"]["x-a"], json!(["1", "2"]));
    assert!(j.get("body").is_none());
    for m in ["get", "HEAD", "Post", "PUT", "PATCH", "DELETE", "OPTIONS"] {
        seen.lock().unwrap().clear();
        let o = call(&u, "headers", &[("method", m), ("query", "q=1")]);
        assert_eq!(o.code(), 0, "{m}");
        let req = seen.lock().unwrap()[0].clone();
        assert!(
            req.starts_with(&format!("{} /h?q=1 ", m.to_uppercase())),
            "{req}"
        );
    }
}

#[test]
fn headers_reports_argument_errors_as_json_with_exit_2() {
    let u = "http://127.0.0.1:1/h";
    let o = call(u, "headers", &[("method", "TRACE")]);
    assert_code(&o, 2, "Unsupported method");
    let j = o.json();
    assert_eq!(j["error"]["kind"], "invalid_argument");
    assert_eq!(j["url"], u);
    let o = call(u, "headers", &[("headers", "oops")]);
    assert_code(&o, 2, "invalid headers");
    assert_eq!(o.json()["error"]["kind"], "invalid_argument");
}

// --- options -------------------------------------------------------------------

#[test]
fn options_reports_allowed_methods_and_optional_body() {
    let (port, seen) =
        raw_server(|_| http_response("200 OK", &[("Allow", "GET, POST,OPTIONS")], b"docs"));
    let u = format!("http://127.0.0.1:{port}/o");
    let j = call(&u, "options", &[("query", "x=1"), ("headers", "X-K:v")]).json();
    assert_eq!(j["allowed_methods"], json!(["GET", "POST", "OPTIONS"]));
    assert_eq!(j["backend"], "reqwest");
    assert_eq!(j["has_body"], true);
    assert_eq!(j["reason"], "OK");
    assert!(j.get("body").is_none());
    let req = seen.lock().unwrap()[0].clone();
    assert!(req.starts_with("OPTIONS /o?x=1 "), "{req}");
    assert!(req.to_ascii_lowercase().contains("x-k: v"));
    let j = call(&u, "options", &[("include_body", "yes")]).json();
    assert_eq!(j["body"], "docs");
}

// --- preflight -------------------------------------------------------------------

#[test]
fn preflight_sends_cors_headers_and_parses_the_answer() {
    let (port, seen) = raw_server(|_| {
        http_response(
            "204 No Content",
            &[
                ("Access-Control-Allow-Origin", "https://example.org"),
                ("Access-Control-Allow-Methods", "GET, POST"),
                (
                    "Access-Control-Allow-Headers",
                    "Content-Type; Authorization",
                ),
                ("Access-Control-Expose-Headers", "X-Total"),
                ("Access-Control-Allow-Credentials", "TRUE"),
                ("Access-Control-Max-Age", "600"),
            ],
            b"",
        )
    });
    let u = format!("http://127.0.0.1:{port}/users");
    let o = call(
        &u,
        "preflight",
        &[
            ("origin", "https://example.org"),
            ("method", "POST"),
            ("request_headers", "Content-Type;Authorization"),
            ("query", "v=2"),
        ],
    );
    assert_eq!(o.code(), 0, "{}", o.reason());
    let j = o.json();
    assert_eq!(j["status"], 204);
    assert_eq!(j["ok"], true);
    assert_eq!(j["method"], "OPTIONS");
    assert_eq!(j["cors"]["allowed_origins"], json!(["https://example.org"]));
    assert_eq!(j["cors"]["allowed_methods"], json!(["GET", "POST"]));
    assert_eq!(
        j["cors"]["allowed_headers"],
        json!(["Content-Type", "Authorization"])
    );
    assert_eq!(j["cors"]["exposed_headers"], json!(["X-Total"]));
    assert_eq!(j["cors"]["allow_credentials"], true);
    assert_eq!(j["cors"]["max_age_seconds"], 600);
    assert_eq!(j["raw_headers"]["access-control-max-age"], "600");
    let req = seen.lock().unwrap()[0].to_ascii_lowercase();
    assert!(req.starts_with("options /users?v=2 "), "{req}");
    assert!(req.contains("origin: https://example.org"));
    assert!(req.contains("access-control-request-method: post"));
    assert!(req.contains("access-control-request-headers: content-type, authorization"));
}

#[test]
fn preflight_handles_wildcards_and_missing_headers() {
    let (port, _) = raw_server(|_| {
        http_response(
            "200 OK",
            &[
                ("Access-Control-Allow-Origin", "*"),
                ("Access-Control-Max-Age", "x"),
            ],
            b"",
        )
    });
    let j = call(&format!("http://127.0.0.1:{port}/"), "preflight", &[]).json();
    assert_eq!(j["cors"]["allowed_origins"], json!(["*"]));
    assert_eq!(j["cors"]["allowed_methods"], json!([]));
    assert_eq!(j["cors"]["allow_credentials"], false);
    assert_eq!(j["cors"]["max_age_seconds"], json!(null));
}

// --- json -------------------------------------------------------------------------

#[test]
fn json_envelope_in_each_accept_mode() {
    let (port, seen) = raw_server(|_| {
        http_response(
            "200 OK",
            &[("Content-Type", "application/json")],
            br#"{"id":42}"#,
        )
    });
    let u = format!("http://127.0.0.1:{port}/u");
    let j = call(&u, "json", &[]).json();
    assert_eq!(j["url"], u);
    assert_eq!(j["status"], 200);
    assert_eq!(j["status_text"], "OK");
    assert_eq!(j["body"], json!({"type": "json", "value": {"id": 42}}));
    assert_eq!(
        call(&u, "json", &[("accept", "text")]).json()["body"],
        json!({"type": "text", "value": "{\"id\":42}"})
    );
    assert_eq!(
        call(&u, "json", &[("accept", "bytes")]).json()["body"],
        json!({"type": "bytes", "base64": BASE64_STANDARD.encode(br#"{"id":42}"#)})
    );
    // No Accept header is added.
    assert!(
        !seen.lock().unwrap()[0]
            .to_ascii_lowercase()
            .contains("accept: application/json")
    );
}

#[test]
fn json_sends_a_body_with_a_default_json_content_type() {
    let (port, seen) = raw_server(|_| http_response("201 Created", &[], b"not json"));
    let u = format!("http://127.0.0.1:{port}/u");
    let o = call(
        &u,
        "json",
        &[("method", "post"), ("body", r#"{"a":1}"#), ("query", "z=9")],
    );
    assert_eq!(o.code(), 0);
    assert_eq!(
        o.json()["body"],
        json!({"type": "text", "value": "not json"})
    );
    let req = seen.lock().unwrap()[0].clone();
    assert!(req.starts_with("POST /u?z=9 "), "{req}");
    assert!(
        req.to_ascii_lowercase()
            .contains("content-type: application/json")
    );
    assert!(req.ends_with(r#"{"a":1}"#));
    for m in ["PUT", "PATCH", "DELETE"] {
        seen.lock().unwrap().clear();
        call(
            &u,
            "json",
            &[("method", m), ("body", "x"), ("content_type", "text/plain")],
        );
        let req = seen.lock().unwrap()[0].clone();
        assert!(req.starts_with(m), "{req}");
        assert!(
            req.to_ascii_lowercase()
                .contains("content-type: text/plain")
        );
        assert!(req.ends_with("\r\n\r\nx"));
    }
    for m in ["HEAD", "OPTIONS"] {
        assert_eq!(call(&u, "json", &[("method", m)]).code(), 0, "{m}");
    }
}

// --- post / put / patch / delete --------------------------------------------------

#[test]
fn post_sends_inline_and_file_bodies() {
    let server = Server::run();
    server.expect(
        Expectation::matching(all_of![
            request::method_path("POST", "/p"),
            request::body("inline"),
            request::headers(contains(("content-type", "text/csv"))),
        ])
        .respond_with(status_code(201).body("created")),
    );
    let o = call(
        &url(&server, "/p"),
        "post",
        &[("body", "inline"), ("content_type", "text/csv")],
    );
    assert_eq!(
        (o.code(), o.text()),
        (0, "created".to_string()),
        "{}",
        o.reason()
    );

    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("payload.bin");
    let payload: Vec<u8> = (0..70_000u32).map(|i| (i % 256) as u8).collect();
    std::fs::write(&f, &payload).unwrap();
    let (port, seen) = raw_server(|_| http_response("200 OK", &[], b"ok"));
    let u = format!("http://127.0.0.1:{port}/p");
    let o = call(&u, "post", &[("body_file", f.to_str().unwrap())]);
    assert_eq!(o.code(), 0);
    let req = seen.lock().unwrap()[0].clone();
    assert!(
        req.contains("content-length: 70000") || req.contains("Content-Length: 70000"),
        "{req:.200}"
    );
    // post sends no default content type.
    assert!(!req.to_ascii_lowercase().contains("content-type"));
    // An empty POST is allowed.
    assert_eq!(call(&u, "post", &[]).code(), 0);
}

#[test]
fn put_default_content_types_and_accept_modes() {
    let (port, seen) = raw_server(|_| {
        http_response(
            "200 OK",
            &[("Content-Type", "application/json")],
            br#"{"ok":true}"#,
        )
    });
    let u = format!("http://127.0.0.1:{port}/r");
    let o = call(&u, "put", &[("body", "hello")]);
    assert_eq!((o.code(), o.text()), (0, r#"{"ok":true}"#.to_string()));
    let req = seen.lock().unwrap()[0].to_ascii_lowercase();
    assert!(req.starts_with("put /r "), "{req}");
    assert!(req.contains("content-type: text/plain; charset=utf-8"));
    assert!(req.ends_with("hello"));

    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("c.json");
    std::fs::write(&f, "{}").unwrap();
    seen.lock().unwrap().clear();
    let j = call(
        &u,
        "put",
        &[("body_file", f.to_str().unwrap()), ("accept", "json")],
    )
    .json();
    assert_eq!(j["status"], 200);
    assert_eq!(j["ok"], true);
    assert_eq!(j["body"], json!({"ok": true}));
    let req = seen.lock().unwrap()[0].to_ascii_lowercase();
    assert!(
        !req.contains("content-type"),
        "body_file gets no default: {req}"
    );
    assert_eq!(
        call(&u, "put", &[("accept", "bytes")]).out,
        br#"{"ok":true}"#
    );
    seen.lock().unwrap().clear();
    call(&u, "put", &[("body", "x"), ("headers", "Content-Type:a/b")]);
    let req = seen.lock().unwrap()[0].to_ascii_lowercase();
    assert!(
        req.contains("content-type: a/b") && !req.contains("text/plain"),
        "{req}"
    );
}

#[test]
fn patch_accept_modes_and_body_sources() {
    let (port, seen) = raw_server(|req| {
        if req.contains("/bad") {
            http_response("200 OK", &[], b"not-json")
        } else {
            http_response("200 OK", &[], b"{ \"id\" : 42 }")
        }
    });
    let u = format!("http://127.0.0.1:{port}/p");
    assert_eq!(
        call(&u, "patch", &[("body", "b")]).text(),
        "{ \"id\" : 42 }"
    );
    assert_eq!(
        call(&u, "patch", &[("accept", "json")]).text(),
        r#"{"id":42}"#
    );
    assert_eq!(
        call(&u, "patch", &[("accept", "text")]).text(),
        "{ \"id\" : 42 }"
    );
    let req = seen.lock().unwrap()[0].clone();
    assert!(
        req.starts_with("PATCH /p ") && req.ends_with("\r\n\r\nb"),
        "{req}"
    );
    assert!(!req.to_ascii_lowercase().contains("content-type"));
    let o = call(
        &format!("http://127.0.0.1:{port}/bad"),
        "patch",
        &[("accept", "json")],
    );
    assert_code(&o, 1, "not valid JSON");
    assert!(o.out.is_empty());
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("p");
    std::fs::write(&f, "from-file").unwrap();
    seen.lock().unwrap().clear();
    call(
        &u,
        "patch",
        &[("body_file", f.to_str().unwrap()), ("content_type", "a/b")],
    );
    let req = seen.lock().unwrap()[0].clone();
    assert!(req.ends_with("from-file") && req.to_ascii_lowercase().contains("content-type: a/b"));
}

#[test]
fn delete_bodies_and_accept_modes() {
    let (port, seen) = raw_server(|req| {
        if req.contains("/text") {
            http_response("200 OK", &[], b"gone")
        } else {
            http_response("200 OK", &[], br#"{"deleted":true,"id":42}"#)
        }
    });
    let u = format!("http://127.0.0.1:{port}/u/42");
    let o = call(&u, "delete", &[]);
    assert_eq!(o.text(), r#"{"deleted":true,"id":42}"#);
    let req = seen.lock().unwrap()[0].to_ascii_lowercase();
    assert!(
        req.starts_with("delete /u/42 ") && !req.contains("content-type"),
        "{req}"
    );
    assert_eq!(
        call(&u, "delete", &[("accept", "json")]).text(),
        "{\n  \"deleted\": true,\n  \"id\": 42\n}"
    );
    let j = call(
        &format!("http://127.0.0.1:{port}/text"),
        "delete",
        &[("accept", "json")],
    )
    .json();
    assert_eq!(
        j,
        json!({"status": {"code": 200, "ok": true}, "body": "gone"})
    );
    seen.lock().unwrap().clear();
    call(&u, "delete", &[("body", "why"), ("accept", "bytes")]);
    let req = seen.lock().unwrap()[0].to_ascii_lowercase();
    assert!(req.contains("content-type: application/octet-stream") && req.ends_with("why"));
}

// --- https -------------------------------------------------------------------------

#[test]
fn allow_insecure_parses_strictly() {
    let t = Duration::from_secs(1);
    for v in ["true", "yes", "1", "on", "false", "no", "0", "off"] {
        assert!(bool_opt(&args(&[("allow_insecure", v)]), "allow_insecure", false).is_ok());
    }
    for bad in ["maybe", "", "2", "insecure"] {
        let err = bool_opt(&args(&[("allow_insecure", bad)]), "allow_insecure", false).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(err.reason.unwrap().contains("allow_insecure"));
    }
    assert!(HttpHandle::build_client(t, true, true).is_ok());
    assert!(HttpHandle::build_client(t, false, false).is_ok());
}

// --- help ---------------------------------------------------------------------------

fn help_output(url: &str, verb: &str, pairs: &[(&str, &str)]) -> Option<String> {
    let h = HttpHandle::from_url(&Url::parse(url).unwrap()).unwrap();
    let a = args(pairs);
    let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
    let mut io = IoStreams::new(&mut i, &mut o, &mut e);
    let shown = h
        .check_and_display_help(verb, &a, &mut io)
        .unwrap()
        .is_some();
    shown.then(|| String::from_utf8(o).unwrap())
}

#[test]
fn in_url_help_renders_approved_help() {
    let out = help_output("http://--help", "help", &[]).unwrap();
    assert!(out.starts_with("Handle: http\n"), "{out}");
    let out = help_output("https://--help", "--help", &[]).unwrap();
    assert!(out.starts_with("Handle: https\n"), "{out}");
    let all = help_output("http://--help", "help", &[]).unwrap();
    let get = help_output("http://--help", "help", &[("verb", "get")]).unwrap();
    assert_ne!(all, get);
    assert_eq!(help_output("http://x", "--help=get", &[]).unwrap(), get);
    // An unknown verb shows the handle help.
    assert_eq!(help_output("http://x", "--help=nope", &[]).unwrap(), all);
}

#[test]
fn non_help_verbs_are_not_help() {
    assert!(help_output("http://my-httpd/", "get", &[]).is_none());
    assert!(help_output("http://x/pre-hotfix", "headers", &[]).is_none());
}
