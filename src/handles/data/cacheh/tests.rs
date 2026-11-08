//! Dispatch-level tests for `cache://`: every verb through `Handle::call`,
//! argument validation and error paths without a server, and the memcached
//! verbs against an in-process fake memcached on 127.0.0.1. Redis is tested
//! end to end in tests/cache_e2e_docker.rs.

use super::*;
use std::io::{BufRead, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};

// ------------------------------------------------------- fake memcached --

/// How the fake server misbehaves.
#[derive(Clone, Copy, Default, PartialEq)]
enum Mode {
    #[default]
    Normal,
    /// Answers `ERROR` to `mg` and `lru_crawler` (memcached before 1.6).
    Old,
    /// Never answers anything.
    Silent,
    /// Answers `version`, then never answers again.
    HangAfterVersion,
    /// `SERVER_ERROR out of memory storing object` for every store.
    StoreFails,
    /// Closes the connection on any store.
    DropOnStore,
    /// `BUSY` to the first metadump.
    BusyOnce,
}

#[derive(Default)]
struct State {
    items: HashMap<String, (Vec<u8>, u64)>,
    /// Every command line received.
    log: Vec<String>,
    busy_sent: bool,
}

struct FakeMc {
    port: u16,
    state: Arc<Mutex<State>>,
}

impl FakeMc {
    fn start(mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(State::default()));
        let st = Arc::clone(&state);
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { return };
                let st = Arc::clone(&st);
                std::thread::spawn(move || serve(conn, mode, st));
            }
        });
        Self { port, state }
    }

    fn url(&self) -> String {
        format!("memcache://127.0.0.1:{}", self.port)
    }

    fn put(&self, key: &str, value: &[u8], exp: u64) {
        self.state
            .lock()
            .unwrap()
            .items
            .insert(key.into(), (value.to_vec(), exp));
    }

    fn item(&self, key: &str) -> Option<(Vec<u8>, u64)> {
        self.state.lock().unwrap().items.get(key).cloned()
    }

    fn log(&self) -> Vec<String> {
        self.state.lock().unwrap().log.clone()
    }
}

fn abs_exp(exp: u64) -> u64 {
    match exp {
        0 => 0,
        e if e <= 2_592_000 => memcached::now_unix() + e,
        e => e,
    }
}

fn serve(conn: TcpStream, mode: Mode, st: Arc<Mutex<State>>) {
    let mut out = conn.try_clone().unwrap();
    let mut r = BufReader::new(conn);
    let mut versioned = false;
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let line = line.trim_end_matches(['\r', '\n']).to_string();
        st.lock().unwrap().log.push(line.clone());
        if mode == Mode::Silent || (mode == Mode::HangAfterVersion && versioned) {
            std::thread::sleep(Duration::from_secs(30));
            return;
        }
        let w: Vec<&str> = line.split(' ').collect();
        let now = memcached::now_unix();
        let mut s = st.lock().unwrap();
        s.items.retain(|_, (_, e)| *e == 0 || *e > now);
        let reply: String = match w[0] {
            "version" => {
                versioned = true;
                "VERSION 1.6.99\r\n".into()
            }
            "get" => {
                let mut o = Vec::new();
                for k in &w[1..] {
                    if let Some((v, _)) = s.items.get(*k) {
                        o.extend_from_slice(format!("VALUE {k} 0 {}\r\n", v.len()).as_bytes());
                        o.extend_from_slice(v);
                        o.extend_from_slice(b"\r\n");
                    }
                }
                o.extend_from_slice(b"END\r\n");
                drop(s);
                out.write_all(&o).unwrap();
                continue;
            }
            "set" | "add" | "replace" => {
                let len: usize = w[4].parse().unwrap();
                let mut data = vec![0u8; len + 2];
                drop(s);
                r.read_exact(&mut data).unwrap();
                data.truncate(len);
                let mut s = st.lock().unwrap();
                if mode == Mode::DropOnStore {
                    return;
                }
                let reply = if mode == Mode::StoreFails {
                    "SERVER_ERROR out of memory storing object\r\n".to_string()
                } else {
                    let exists = s.items.contains_key(w[1]);
                    let ok = match w[0] {
                        "add" => !exists,
                        "replace" => exists,
                        _ => true,
                    };
                    if ok {
                        let exp = abs_exp(w[3].parse().unwrap());
                        s.items.insert(w[1].into(), (data, exp));
                        "STORED\r\n".into()
                    } else {
                        "NOT_STORED\r\n".into()
                    }
                };
                drop(s);
                out.write_all(reply.as_bytes()).unwrap();
                continue;
            }
            "delete" => {
                if s.items.remove(w[1]).is_some() {
                    "DELETED\r\n".into()
                } else {
                    "NOT_FOUND\r\n".into()
                }
            }
            "incr" | "decr" => match s.items.get_mut(w[1]) {
                None => "NOT_FOUND\r\n".into(),
                Some((v, _)) => match String::from_utf8_lossy(v).parse::<u64>() {
                    Err(_) => {
                        "CLIENT_ERROR cannot increment or decrement non-numeric value\r\n".into()
                    }
                    Ok(n) => {
                        let by: u64 = w[2].parse().unwrap();
                        let n = if w[0] == "incr" {
                            n.wrapping_add(by)
                        } else {
                            n.saturating_sub(by)
                        };
                        *v = n.to_string().into_bytes();
                        format!("{n}\r\n")
                    }
                },
            },
            "touch" => match s.items.get_mut(w[1]) {
                None => "NOT_FOUND\r\n".into(),
                Some((_, e)) => {
                    *e = abs_exp(w[2].parse().unwrap());
                    "TOUCHED\r\n".into()
                }
            },
            "mg" if mode == Mode::Old => "ERROR\r\n".into(),
            "mg" => match s.items.get(w[1]) {
                None => "EN\r\n".into(),
                Some((_, e)) if w.get(2) == Some(&"t") => {
                    let t = if *e == 0 { -1 } else { (*e - now) as i64 };
                    format!("HD t{t}\r\n")
                }
                Some(_) => "HD\r\n".into(),
            },
            "lru_crawler" if mode == Mode::Old => "ERROR\r\n".into(),
            "lru_crawler" if mode == Mode::BusyOnce && !s.busy_sent => {
                s.busy_sent = true;
                "BUSY currently processing crawler request\r\n".into()
            }
            "lru_crawler" => {
                // As memcached 1.6 writes it: OK, items ending in " \n", END.
                let mut o = String::from("OK\r\n");
                for (k, (_, e)) in &s.items {
                    let exp = if *e == 0 { -1 } else { *e as i64 };
                    let enc = percent_encoding::utf8_percent_encode(
                        k,
                        percent_encoding::NON_ALPHANUMERIC,
                    );
                    o.push_str(&format!(
                        "key={enc} exp={exp} la=0 cas=1 fetch=no cls=1 size=60 flags=0 \n"
                    ));
                }
                o + "END\r\n"
            }
            _ => "ERROR\r\n".into(),
        };
        drop(s);
        if out.write_all(reply.as_bytes()).is_err() {
            return;
        }
    }
}

/// A port with nothing listening.
fn closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

// --------------------------------------------------------------- helpers --

/// A fresh alias, so tests never share a registered connection.
fn alias() -> String {
    static N: AtomicUsize = AtomicUsize::new(0);
    format!("t{}", N.fetch_add(1, Ordering::SeqCst))
}

struct Out {
    status: Status,
    json: Value,
}

fn call_target(target: &str, verb: &str, args: &[(&str, &str)]) -> Out {
    let h = CacheHandle::from_url(&Url::parse(target).unwrap()).unwrap();
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
    let text = String::from_utf8(o).unwrap();
    Out {
        status,
        json: serde_json::from_str(&text).unwrap_or(Value::Null),
    }
}

/// Runs `verb` on memcached alias `a` with `args`.
fn mc(a: &str, verb: &str, args: &[(&str, &str)]) -> Out {
    call_target(&format!("cache://memcached/{a}"), verb, args)
}

fn ok(o: &Out) -> &Value {
    assert!(o.status.ok, "{:?} {}", o.status, o.json);
    &o.json
}

/// Asserts a failure with `exit` and `cache.<code>` in both the JSON error
/// and the stderr reason.
fn fails(o: &Out, exit: i32, code: &str) -> String {
    assert!(!o.status.ok, "expected {code}, got {}", o.json);
    assert_eq!(o.status.exit_code(), exit, "{:?} {}", o.status, o.json);
    let full = format!("cache.{code}");
    assert_eq!(o.json["error"]["code"], full, "{}", o.json);
    let reason = o.status.reason.clone().unwrap_or_default();
    assert!(reason.starts_with(&format!("[{full}] ")), "{reason}");
    assert!(crate::core::status::is_valid_error_code(&full));
    o.json["error"]["message"].as_str().unwrap().to_string()
}

// ------------------------------------------------------------ arguments --

#[test]
fn unknown_arguments_are_refused_with_a_suggestion() {
    let url = format!("memcache://127.0.0.1:{}", closed_port());
    let o = mc(&alias(), "get", &[("url", &url), ("kye", "a")]);
    let msg = fails(&o, 2, "invalid_argument");
    assert!(
        msg.contains("unknown argument: kye") && msg.contains("`key`"),
        "{msg}"
    );
    let o = mc(
        &alias(),
        "set",
        &[("url", &url), ("key", "a"), ("value", "b"), ("ttl", "5")],
    );
    assert!(fails(&o, 2, "invalid_argument").contains("ttl_ms"));
    // Every verb refuses another verb's options.
    for (verb, bad) in [
        ("connect", "key"),
        ("get", "value"),
        ("exists", "decode"),
        ("ttl", "ttl_ms"),
        ("keys", "key"),
        ("set", "default"),
        ("incr", "keys"),
        ("del", "pattern"),
    ] {
        let o = mc(&alias(), verb, &[("url", &url), (bad, "x")]);
        assert!(
            fails(&o, 2, "invalid_argument").contains(&format!("unknown argument: {bad}")),
            "{verb} {bad}"
        );
    }
    let o = mc(&alias(), "connect", &[("url", &url), ("timeout_ms", "5")]);
    assert!(fails(&o, 2, "invalid_argument").contains("connect_timeout_ms"));
    let o = mc(
        &alias(),
        "get",
        &[("url", &url), ("key", "a"), ("ca_file", "/x")],
    );
    assert!(fails(&o, 2, "invalid_argument").contains("rediss://"));
    // dry_run=false is accepted (and the connection is then attempted).
    let o = mc(
        &alias(),
        "get",
        &[("url", &url), ("key", "a"), ("dry_run", "false")],
    );
    fails(&o, 1, "connect_failed");
    let o = mc(
        &alias(),
        "set",
        &[
            ("url", &url),
            ("key", "a"),
            ("value", "b"),
            ("dry_run", "true"),
        ],
    );
    fails(&o, 2, "invalid_argument");
}

#[test]
fn unknown_verb_exits_2() {
    let o = mc(&alias(), "flush", &[]);
    assert_eq!(o.status.exit_code(), 2);
    assert!(
        o.status
            .reason
            .unwrap()
            .starts_with("[cache.invalid_argument] unknown verb")
    );
}

#[test]
fn invalid_values_are_refused_before_connecting() {
    // Nothing listens here: reaching the server would be connect_failed.
    let url = format!("memcache://127.0.0.1:{}", closed_port());
    /// (verb, arguments, part of the expected message)
    type Case<'a> = (&'a str, &'a [(&'a str, &'a str)], &'a str);
    let cases: &[Case] = &[
        ("get", &[], "key=<key> or keys=<json-array> is required"),
        ("get", &[("key", "a"), ("keys", "[\"b\"]")], "not both"),
        ("get", &[("keys", "a,b")], "JSON array"),
        ("get", &[("keys", "[]")], "empty array"),
        ("get", &[("keys", "[\"a\",1]")], "array of strings"),
        ("get", &[("key", "")], "cannot be empty"),
        ("get", &[("key", "a"), ("decode", "hex")], "decode"),
        (
            "get",
            &[("key", "a"), ("decode", "json"), ("default", "nope")],
            "default",
        ),
        ("get", &[("key", "a"), ("timeout_ms", "abc")], "timeout_ms"),
        ("get", &[("key", "a"), ("timeout_ms", "0")], "timeout_ms"),
        (
            "get",
            &[("key", "a"), ("timeout_ms", "86400001")],
            "timeout_ms",
        ),
        (
            "get",
            &[("key", "a"), ("connect_timeout_ms", "0")],
            "connect_timeout_ms",
        ),
        ("get", &[("key", "a"), ("namespace", "")], "namespace"),
        ("get", &[("key", "a b")], "spaces or control"),
        ("get", &[("key", "a\r\nflush_all")], "spaces or control"),
        ("get", &[("key", &"k".repeat(251))], "250 bytes"),
        (
            "get",
            &[("key", &"k".repeat(248)), ("namespace", "ns")],
            "250 bytes",
        ),
        ("set", &[("key", "a")], "needs value"),
        ("set", &[("keys", "[\"a\"]")], "needs values"),
        (
            "set",
            &[("keys", "[\"a\",\"b\"]"), ("values", "[1]")],
            "2 items but values has 1",
        ),
        (
            "set",
            &[("key", "a"), ("value", "1"), ("values", "[1]")],
            "not both",
        ),
        (
            "set",
            &[("key", "a"), ("value", "1"), ("encode", "hex")],
            "encode",
        ),
        (
            "set",
            &[("key", "a"), ("value", "%%"), ("encode", "bytes")],
            "base64",
        ),
        (
            "set",
            &[("key", "a"), ("value", "{"), ("encode", "json")],
            "JSON",
        ),
        (
            "set",
            &[("keys", "[\"a\"]"), ("values", "[1]"), ("encode", "bytes")],
            "base64",
        ),
        (
            "set",
            &[
                ("key", "a"),
                ("value", "1"),
                ("only_if_exists", "true"),
                ("only_if_not_exists", "1"),
            ],
            "cannot both",
        ),
        (
            "set",
            &[("key", "a"), ("value", "1"), ("only_if_exists", "maybe")],
            "only_if_exists",
        ),
        (
            "set",
            &[("key", "a"), ("value", "1"), ("ttl_ms", "0")],
            "ttl_ms",
        ),
        (
            "set",
            &[("key", "a"), ("value", "1"), ("ttl_ms", "-5")],
            "ttl_ms",
        ),
        ("incr", &[], "key=<key> is required"),
        ("incr", &[("key", "c"), ("by", "1.5")], "by"),
        (
            "incr",
            &[
                ("key", "c"),
                ("by", "9223372036854775807"),
                ("initial", "1"),
            ],
            "overflows",
        ),
        (
            "incr",
            &[("key", "c"), ("initial", "-1")],
            "cannot be negative",
        ),
        ("keys", &[("limit", "0")], "limit"),
        ("keys", &[("limit", "10001")], "limit"),
        ("keys", &[("cursor", "!!")], "invalid cursor"),
        ("keys", &[("pattern", "")], "pattern"),
        ("connect", &[], "url is required"),
    ];
    for (verb, args, want) in cases {
        let mut all: Vec<(&str, &str)> = args.to_vec();
        if *verb != "connect" || !args.is_empty() {
            all.push(("url", &url));
        }
        let o = mc(&alias(), verb, &all);
        let msg = fails(&o, 2, "invalid_argument");
        assert!(msg.contains(want), "{verb} {args:?}: {msg}");
    }
}

#[test]
fn connection_urls_are_checked() {
    let redis = |url: &str| {
        call_target(
            &format!("cache://redis/{}", alias()),
            "connect",
            &[("url", url)],
        )
    };
    let u = ConnUrl::parse(Backend::Redis, "rediss://cache.local").unwrap();
    assert!(u.tls);
    assert_eq!(u.endpoint, "cache.local:6379");
    for bad in [
        "http://x",
        "memcache://x",
        "",
        "not a url",
        "redis://",
        "rediss://127.0.0.1/#insecure",
    ] {
        fails(&redis(bad), 2, "invalid_argument");
    }
    let m = |url: &str| mc(&alias(), "connect", &[("url", url)]);
    for bad in [
        "redis://127.0.0.1",
        "memcache://user:pw@127.0.0.1",
        "memcache://127.0.0.1?timeout=1",
        "memcache://127.0.0.1/x",
        "memcache:///tmp/sock",
    ] {
        fails(&m(bad), 2, "invalid_argument");
    }
    let u = ConnUrl::parse(Backend::Redis, "redis://:secret@cache.local/3").unwrap();
    assert_eq!(u.endpoint, "cache.local:6379");
    let u = ConnUrl::parse(Backend::Redis, "redis+unix:///run/redis.sock").unwrap();
    assert_eq!(u.endpoint, "/run/redis.sock");
    let u = ConnUrl::parse(Backend::Memcached, "memcached://[::1]").unwrap();
    assert_eq!(u.addr.as_deref(), Some("[::1]:11211"));
    let u = ConnUrl::parse(Backend::Memcached, "memcache://h:1234/").unwrap();
    assert_eq!(u.endpoint, "h:1234");
}

#[test]
fn unsupported_backend_is_refused() {
    assert!(CacheHandle::from_url(&Url::parse("cache://memcache/x").unwrap()).is_err());
    let h = CacheHandle::from_url(&Url::parse("cache://redis").unwrap()).unwrap();
    assert_eq!(h.alias, "default");
}

#[test]
fn no_url_and_no_connection_is_a_usage_error() {
    let o = mc(&alias(), "get", &[("key", "a")]);
    assert!(fails(&o, 2, "connection_not_found").contains("url="));
}

// -------------------------------------------------------- connection paths --

#[test]
fn refused_connection_exits_1() {
    let url = format!("memcache://127.0.0.1:{}", closed_port());
    fails(
        &mc(&alias(), "connect", &[("url", &url)]),
        1,
        "connect_failed",
    );
    let url = format!("redis://127.0.0.1:{}", closed_port());
    let o = call_target(
        &format!("cache://redis/{}", alias()),
        "get",
        &[("url", &url), ("key", "a")],
    );
    fails(&o, 1, "connect_failed");
}

#[test]
fn silent_server_is_a_connect_timeout() {
    let s = FakeMc::start(Mode::Silent);
    let started = std::time::Instant::now();
    let o = mc(
        &alias(),
        "connect",
        &[("url", &s.url()), ("connect_timeout_ms", "200")],
    );
    fails(&o, 124, "connect_timeout");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn a_command_without_an_answer_times_out_and_drops_the_connection() {
    let s = FakeMc::start(Mode::HangAfterVersion);
    let a = alias();
    let o = mc(
        &a,
        "get",
        &[("url", &s.url()), ("key", "k"), ("timeout_ms", "200")],
    );
    assert!(!fails(&o, 124, "timeout").contains("may or may not"));
    assert!(registered(Backend::Memcached, &a).is_none());
    let o = mc(
        &a,
        "set",
        &[
            ("url", &s.url()),
            ("key", "k"),
            ("value", "v"),
            ("timeout_ms", "200"),
        ],
    );
    assert!(fails(&o, 124, "timeout").contains("may or may not"));
}

#[test]
fn connect_registers_the_alias_for_later_verbs() {
    let s = FakeMc::start(Mode::Normal);
    let a = alias();
    let o = mc(&a, "connect", &[("url", &s.url())]);
    assert_eq!(
        *ok(&o),
        json!({"alias": a, "backend": "memcached", "endpoint": format!("127.0.0.1:{}", s.port), "status": "connected"})
    );
    s.put("k", b"v", 0);
    assert_eq!(ok(&mc(&a, "get", &[("key", "k")]))["value"], "v");
    // A different url replaces the connection.
    let s2 = FakeMc::start(Mode::Normal);
    s2.put("k", b"other", 0);
    assert_eq!(
        ok(&mc(&a, "get", &[("key", "k"), ("url", &s2.url())]))["value"],
        "other"
    );
    assert_eq!(ok(&mc(&a, "get", &[("key", "k")]))["value"], "other");
}

#[test]
fn server_errors_and_lost_connections() {
    let s = FakeMc::start(Mode::StoreFails);
    let o = mc(
        &alias(),
        "set",
        &[("url", &s.url()), ("key", "k"), ("value", "v")],
    );
    assert!(fails(&o, 1, "server_error").contains("out of memory"));
    let s = FakeMc::start(Mode::DropOnStore);
    let a = alias();
    let o = mc(
        &a,
        "set",
        &[("url", &s.url()), ("key", "k"), ("value", "v")],
    );
    fails(&o, 124, "connection_lost");
    assert!(registered(Backend::Memcached, &a).is_none());
}

// ------------------------------------------------------------- memcached --

#[test]
fn set_get_round_trip_and_values_are_stored_exactly() {
    let s = FakeMc::start(Mode::Normal);
    let u = s.url();
    let a = alias();
    let o = mc(&a, "set", &[("url", &u), ("key", "123"), ("value", "42")]);
    assert_eq!(
        *ok(&o),
        json!({"alias": a, "backend": "memcached", "key": "123", "stored": true})
    );
    assert_eq!(s.item("123").unwrap().0, b"42");
    let o = mc(&a, "get", &[("key", "123")]);
    assert_eq!(
        *ok(&o),
        json!({"alias": a, "backend": "memcached", "key": "123", "value": "42", "hit": true})
    );
    // Text is stored as typed, quotes and spaces included.
    ok(&mc(&a, "set", &[("key", "q"), ("value", " \"x\" ")]));
    assert_eq!(s.item("q").unwrap().0, b" \"x\" ");
    // encode=json stores compact JSON; decode=json returns it parsed.
    ok(&mc(
        &a,
        "set",
        &[
            ("key", "j"),
            ("value", "{ \"a\": [1, 2] }"),
            ("encode", "json"),
        ],
    ));
    assert_eq!(s.item("j").unwrap().0, br#"{"a":[1,2]}"#);
    assert_eq!(
        ok(&mc(&a, "get", &[("key", "j"), ("decode", "json")]))["value"],
        json!({"a": [1, 2]})
    );
    // bytes: base64 in, base64 out.
    ok(&mc(
        &a,
        "set",
        &[("key", "b"), ("value", "AAEC/w=="), ("encode", "bytes")],
    ));
    assert_eq!(s.item("b").unwrap().0, [0, 1, 2, 255]);
    assert_eq!(
        ok(&mc(&a, "get", &[("key", "b"), ("decode", "bytes")]))["value"],
        "AAEC/w=="
    );
    // Not UTF-8 or not JSON: decode_failed.
    fails(&mc(&a, "get", &[("key", "b")]), 1, "decode_failed");
    ok(&mc(&a, "set", &[("key", "t"), ("value", "plain text")]));
    fails(
        &mc(&a, "get", &[("key", "t"), ("decode", "json")]),
        1,
        "decode_failed",
    );
    // A miss returns the default.
    let o = mc(&a, "get", &[("key", "nope"), ("default", "0")]);
    assert_eq!(ok(&o)["value"], "0");
    assert_eq!(o.json["hit"], false);
    let o = mc(
        &a,
        "get",
        &[("key", "nope"), ("default", "[1]"), ("decode", "json")],
    );
    assert_eq!(ok(&o)["value"], json!([1]));
    assert_eq!(ok(&mc(&a, "get", &[("key", "nope")]))["value"], Value::Null);
}

#[test]
fn multi_key_get_set_del_with_namespace() {
    let s = FakeMc::start(Mode::Normal);
    let a = alias();
    let u = s.url();
    let o = mc(
        &a,
        "set",
        &[
            ("url", &u),
            ("keys", r#"["a","b"]"#),
            ("values", r#"["x",{"n":1}]"#),
            ("namespace", "ns"),
            ("ttl_ms", "1500"),
        ],
    );
    assert_eq!(
        *ok(&o),
        json!({"alias": a, "backend": "memcached", "ttl_ms": 1500, "total_stored": 2,
               "results": [{"key": "a", "stored": true}, {"key": "b", "stored": true}]})
    );
    assert_eq!(s.item("ns:a").unwrap().0, b"x");
    assert_eq!(s.item("ns:b").unwrap().0, br#"{"n":1}"#);
    assert!(
        s.log().iter().any(|l| l == "set ns:a 0 2 1"),
        "{:?}",
        s.log()
    );
    let o = mc(
        &a,
        "get",
        &[("keys", r#"["a","zz","b"]"#), ("namespace", "ns")],
    );
    assert_eq!(
        ok(&o)["results"],
        json!([{"key": "a", "value": "x", "hit": true},
               {"key": "zz", "value": null, "hit": false},
               {"key": "b", "value": "{\"n\":1}", "hit": true}])
    );
    let o = mc(&a, "del", &[("keys", r#"["a","zz"]"#), ("namespace", "ns")]);
    assert_eq!(ok(&o)["total_deleted"], 1);
    assert_eq!(
        o.json["results"],
        json!([{"key": "a", "deleted": true}, {"key": "zz", "deleted": false}])
    );
    let o = mc(&a, "del", &[("key", "b"), ("namespace", "ns")]);
    assert_eq!(ok(&o)["deleted"], true);
    assert!(s.item("ns:b").is_none());
}

#[test]
fn conditional_writes() {
    let s = FakeMc::start(Mode::Normal);
    let a = alias();
    let u = s.url();
    let o = mc(
        &a,
        "set",
        &[
            ("url", &u),
            ("key", "k"),
            ("value", "1"),
            ("only_if_exists", "true"),
        ],
    );
    assert_eq!(ok(&o)["stored"], false);
    assert_eq!(o.json["reason"], "condition_not_met");
    assert!(s.item("k").is_none());
    assert_eq!(
        ok(&mc(
            &a,
            "set",
            &[("key", "k"), ("value", "1"), ("only_if_not_exists", "yes")]
        ))["stored"],
        true
    );
    let o = mc(
        &a,
        "set",
        &[("key", "k"), ("value", "2"), ("only_if_not_exists", "true")],
    );
    assert_eq!(ok(&o)["stored"], false);
    assert_eq!(s.item("k").unwrap().0, b"1");
    assert_eq!(
        ok(&mc(
            &a,
            "set",
            &[("key", "k"), ("value", "3"), ("only_if_exists", "on")]
        ))["stored"],
        true
    );
    assert_eq!(s.item("k").unwrap().0, b"3");
}

#[test]
fn ttl_below_a_second_still_expires() {
    let s = FakeMc::start(Mode::Normal);
    ok(&mc(
        &alias(),
        "set",
        &[
            ("url", &s.url()),
            ("key", "k"),
            ("value", "v"),
            ("ttl_ms", "500"),
        ],
    ));
    assert!(s.log().iter().any(|l| l == "set k 0 1 1"), "{:?}", s.log());
}

#[test]
fn exists_and_ttl_tell_missing_keys_apart() {
    for mode in [Mode::Normal, Mode::Old] {
        let s = FakeMc::start(mode);
        let a = alias();
        s.put("forever", b"1", 0);
        s.put("soon", b"1", memcached::now_unix() + 100);
        let u = s.url();
        assert_eq!(
            ok(&mc(&a, "exists", &[("url", &u), ("key", "forever")]))["exists"],
            true
        );
        assert_eq!(
            ok(&mc(&a, "exists", &[("key", "missing")]))["exists"],
            false
        );
        let o = mc(&a, "exists", &[("keys", r#"["forever","missing","soon"]"#)]);
        assert_eq!(ok(&o)["total_exists"], 2);
        let o = mc(&a, "ttl", &[("keys", r#"["forever","missing","soon"]"#)]);
        let r = &ok(&o)["results"];
        assert_eq!(o.json["found"], 2);
        assert_eq!(r[0]["exists"], true);
        assert_eq!(r[1]["exists"], false);
        assert_eq!(r[1]["ttl_ms"], Value::Null);
        assert_eq!(r[2]["exists"], true);
        if mode == Mode::Normal {
            assert_eq!(r[0]["supports_ttl"], true);
            assert_eq!(r[0]["has_expiry"], false);
            assert_eq!(r[2]["has_expiry"], true);
            let t = r[2]["ttl_ms"].as_u64().unwrap();
            assert!((98_000..=100_000).contains(&t), "{t}");
        } else {
            assert_eq!(r[2]["supports_ttl"], false);
            assert_eq!(r[2]["ttl_ms"], Value::Null);
        }
    }
}

#[test]
fn incr_creates_counts_and_refuses_non_counters() {
    let s = FakeMc::start(Mode::Normal);
    let a = alias();
    let u = s.url();
    let o = mc(
        &a,
        "incr",
        &[("url", &u), ("key", "c"), ("initial", "10"), ("by", "5")],
    );
    assert_eq!(
        *ok(&o),
        json!({"alias": a, "backend": "memcached", "key": "c", "value": 15, "created": true})
    );
    let o = mc(&a, "incr", &[("key", "c")]);
    assert_eq!(ok(&o)["value"], 16);
    assert_eq!(o.json["created"], false);
    let o = mc(&a, "incr", &[("key", "c"), ("by", "-20")]);
    assert_eq!(ok(&o)["value"], 0);
    // A missing counter with a negative start is created at 0.
    let o = mc(&a, "incr", &[("key", "d"), ("by", "-3")]);
    assert_eq!(ok(&o)["value"], 0);
    assert_eq!(o.json["created"], true);
    // ttl_ms is applied on every call.
    ok(&mc(&a, "incr", &[("key", "c"), ("ttl_ms", "60000")]));
    assert!(s.log().iter().any(|l| l == "touch c 60"), "{:?}", s.log());
    s.put("text", b"abc", 0);
    let o = mc(&a, "incr", &[("key", "text")]);
    fails(&o, 1, "wrong_type");
    assert_eq!(s.item("text").unwrap().0, b"abc");
}

#[test]
fn keys_lists_pages_and_filters() {
    let s = FakeMc::start(Mode::Normal);
    let a = alias();
    for k in ["user:1", "user:2", "user:3", "other", "ns:user:9", "a*b"] {
        s.put(k, b"v", 0);
    }
    s.put("user:expired", b"v", 1);
    let u = s.url();
    let o = mc(
        &a,
        "keys",
        &[("url", &u), ("pattern", "user:*"), ("limit", "2")],
    );
    assert_eq!(ok(&o)["keys"], json!(["user:1", "user:2"]));
    assert_eq!(o.json["count"], 2);
    assert_eq!(o.json["has_more"], true);
    let cursor = o.json["cursor"].as_str().unwrap().to_string();
    let o = mc(
        &a,
        "keys",
        &[("pattern", "user:*"), ("limit", "2"), ("cursor", &cursor)],
    );
    assert_eq!(ok(&o)["keys"], json!(["user:3"]));
    assert_eq!(o.json["has_more"], false);
    assert_eq!(o.json["cursor"], Value::Null);
    let o = mc(&a, "keys", &[("namespace", "ns")]);
    assert_eq!(ok(&o)["keys"], json!(["user:9"]));
    let o = mc(&a, "keys", &[("pattern", "a\\*b")]);
    assert_eq!(ok(&o)["keys"], json!(["a*b"]));
    let o = mc(&a, "keys", &[]);
    assert_eq!(ok(&o)["count"], 6);
}

#[test]
fn keys_waits_for_a_busy_crawler_and_reports_old_servers() {
    let s = FakeMc::start(Mode::BusyOnce);
    s.put("k", b"v", 0);
    let o = mc(&alias(), "keys", &[("url", &s.url())]);
    assert_eq!(ok(&o)["keys"], json!(["k"]));
    let s = FakeMc::start(Mode::Old);
    let o = mc(&alias(), "keys", &[("url", &s.url())]);
    assert!(fails(&o, 1, "keys_unsupported").contains("1.4.31"));
}

#[test]
fn help_forms_print_help() {
    for (target, verb, args) in [
        ("cache://--help", "x", vec![]),
        ("cache://redis/a", "help", vec![]),
        ("cache://redis/a", "--help=get", vec![]),
        ("cache://redis/a", "get", vec![("help", "1")]),
    ] {
        let o = call_target(target, verb, &args);
        assert!(o.status.ok, "{target} {verb}");
    }
}

#[test]
fn every_error_code_is_documented() {
    let doc = include_str!("../../../../docs/Data_StateManagement/cache.md");
    for code in ERROR_CODES {
        assert!(
            doc.contains(&format!("`cache.{code}`")),
            "cache.{code} not in cache.md"
        );
    }
}

#[test]
fn redis_errors_are_mapped() {
    use redis::{ErrorKind, RedisError, ServerErrorKind};
    let e = RedisError::from((
        ErrorKind::Server(ServerErrorKind::ResponseError),
        "An error was signalled by the server",
        "value is not an integer or out of range".to_string(),
    ));
    assert_eq!(redis_ops::redis_fail(e, "x", true).code, "wrong_type");
    let e = RedisError::from(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "gone"));
    let f = redis_ops::redis_fail(e, "x", true);
    assert_eq!((f.code, f.exit), ("connection_lost", 124));
    let e = RedisError::from(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "gone"));
    assert_eq!(redis_ops::redis_fail(e, "x", false).exit, 1);
    let e = RedisError::from((
        ErrorKind::Server(ServerErrorKind::ResponseError),
        "An error was signalled by the server",
        "OOM".to_string(),
    ));
    assert_eq!(redis_ops::redis_fail(e, "x", true).code, "server_error");
}

#[test]
fn ca_file_is_checked_and_added_to_the_trusted_cas() {
    let dir = tempfile::TempDir::new().unwrap();
    let ca = rcgen::generate_simple_self_signed(vec!["ca.test".to_string()]).unwrap();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, ca.serialize_pem().unwrap()).unwrap();
    let empty = dir.path().join("empty.pem");
    std::fs::write(&empty, "not a certificate\n").unwrap();
    let ca_s = ca_path.to_str().unwrap();
    let r = |url: &str, ca: &str| {
        call_target(
            &format!("cache://redis/{}", alias()),
            "get",
            &[("url", url), ("key", "k"), ("ca_file", ca)],
        )
    };
    // Only for rediss://, and only a readable file of certificates.
    assert!(fails(&r("redis://127.0.0.1", ca_s), 2, "invalid_argument").contains("rediss://"));
    let o = mc(
        &alias(),
        "connect",
        &[("url", "memcache://127.0.0.1"), ("ca_file", ca_s)],
    );
    fails(&o, 2, "invalid_argument");
    let o = call_target(
        &format!("cache://redis/{}", alias()),
        "get",
        &[("key", "k"), ("ca_file", ca_s)],
    );
    fails(&o, 2, "invalid_argument");
    let missing = dir.path().join("missing.pem");
    fails(
        &r("rediss://127.0.0.1", missing.to_str().unwrap()),
        2,
        "invalid_argument",
    );
    assert!(
        fails(
            &r("rediss://127.0.0.1", empty.to_str().unwrap()),
            2,
            "invalid_argument"
        )
        .contains("no PEM certificate")
    );
    // A valid file is accepted; nothing listens, so the connection fails.
    let url = format!("rediss://127.0.0.1:{}", closed_port());
    fails(&r(&url, ca_s), 1, "connect_failed");
    // The trusted set is the system bundle plus the file.
    let loaded = CaFile::load(ca_s).unwrap();
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let der = |pem: &[u8]| -> Vec<Vec<u8>> {
        CertificateDer::pem_slice_iter(pem)
            .map(|c| c.unwrap().to_vec())
            .collect()
    };
    let roots = der(&tls_roots(Some(&loaded)).unwrap());
    let mine = der(&loaded.pem);
    assert!(roots.contains(&mine[0]), "ca_file missing from roots");
    if SYSTEM_BUNDLES
        .iter()
        .any(|p| std::path::Path::new(p).is_file())
    {
        assert!(roots.len() > 1);
    }
}

#[test]
fn help_usage_lists_exactly_the_accepted_arguments() {
    for verb in CACHE_HELP.verbs {
        let usage = verb.detail.as_ref().unwrap().usage;
        let listed = crate::core::test_support::usage_option_names(usage);
        let mut accepted = allowed_args(verb.name);
        accepted.sort_unstable();
        accepted.dedup();
        assert_eq!(listed, accepted, "{}: {usage}", verb.name);
    }
}
