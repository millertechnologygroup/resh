//! Integration tests for `cache://` through the built `resh` binary, with
//! no cache server: argument validation (exit 2), the error format,
//! connection failures against 127.0.0.1, and help output (golden files).
//! The verbs against real Redis and Memcached servers are in
//! cache_e2e_docker.rs; the memcached protocol paths are also unit-tested
//! against a fake server in src/handles/data/cacheh/tests.rs.

use serde_json::Value;
use std::net::TcpListener;
use std::path::Path;

const VERBS: &[&str] = &[
    "connect", "get", "exists", "ttl", "keys", "set", "incr", "del",
];

/// The options each verb accepts (src/handles/data/cacheh.rs `verb_args`).
fn options_for(verb: &str) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = match verb {
        "connect" => vec![],
        "get" => vec!["key", "keys", "namespace", "decode", "default"],
        "exists" | "ttl" | "del" => vec!["key", "keys", "namespace"],
        "keys" => vec!["pattern", "namespace", "cursor", "limit"],
        "set" => vec![
            "key",
            "keys",
            "value",
            "values",
            "namespace",
            "ttl_ms",
            "encode",
            "only_if_not_exists",
            "only_if_exists",
        ],
        "incr" => vec!["key", "by", "initial", "ttl_ms", "namespace"],
        _ => unreachable!(),
    };
    v.extend(["url", "connect_timeout_ms"]);
    if verb != "connect" {
        v.push("timeout_ms");
    }
    v
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

/// Asserts a handle failure: exit code, JSON error on stdout, one
/// `Error: [code] cache <verb>: ...` line on stderr.
fn assert_fail(r: &Run, exit: i32, code: &str) {
    assert_eq!(r.code, exit, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(r.json["error"]["code"], code, "{}", r.stdout);
    assert!(r.json["error"]["message"].is_string(), "{}", r.stdout);
    assert!(r.json["alias"].is_string() && r.json["backend"].is_string());
    assert!(
        r.stderr.starts_with(&format!("Error: [{code}] cache ")),
        "{}",
        r.stderr
    );
    assert_eq!(r.stderr.lines().count(), 1, "{}", r.stderr);
}

fn closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

#[test]
fn invalid_arguments_exit_2_before_connecting() {
    let url = format!("url=memcache://127.0.0.1:{}", closed_port());
    for (stage, args, needle) in [
        (
            "cache://memcached/a.get",
            vec!["kye=x"],
            "did you mean `key`",
        ),
        (
            "cache://memcached/a.get",
            vec!["key=x", "timeout_ms=soon"],
            "timeout_ms",
        ),
        ("cache://memcached/a.set", vec!["key=x"], "needs value"),
        ("cache://memcached/a.get", vec!["key=a b"], "spaces"),
        ("cache://memcached/a.incr", vec!["key=c", "by=x"], "by"),
        ("cache://memcached/a.keys", vec!["limit=0"], "limit"),
        (
            "cache://memcached/a.get",
            vec!["key=x", "(decode=hex)"],
            "not key=value",
        ),
    ] {
        let mut argv = vec![stage];
        argv.extend(args.iter().copied());
        argv.push(&url);
        let r = resh(&argv);
        if needle == "not key=value" {
            // Refused by the dispatcher.
            assert_eq!(r.code, 2);
            continue;
        }
        assert_fail(&r, 2, "cache.invalid_argument");
        assert!(r.stderr.contains(needle), "{stage} {args:?}: {}", r.stderr);
    }
    // Arguments inside the stage are checked the same way.
    let r = resh(&[&format!("cache://memcached/a.get(key=x,decode=hex,{url})")]);
    assert_fail(&r, 2, "cache.invalid_argument");
}

#[test]
fn numeric_looking_values_are_text() {
    // key=123 is a key, not "missing key": the command gets as far as
    // connecting.
    let url = format!("url=memcache://127.0.0.1:{}", closed_port());
    let r = resh(&["cache://memcached/a.get", "key=123", "namespace=2024", &url]);
    assert_fail(&r, 1, "cache.connect_failed");
}

#[test]
fn dispatcher_and_target_errors() {
    let r = resh(&["cache://redis/a.set", "key=k", "value=v", "dry_run=true"]);
    assert_eq!(r.code, 2);
    assert!(
        r.stderr.contains("does not support dry_run"),
        "{}",
        r.stderr
    );
    let r = resh(&["cache://memcache/a.get", "key=k"]);
    assert_eq!(r.code, 2);
    assert!(
        r.stderr.starts_with("Error: [cache.invalid_target]"),
        "{}",
        r.stderr
    );
    let r = resh(&["cache://redis/a.flush"]);
    assert_eq!(r.code, 2);
    assert!(
        r.stderr
            .starts_with("Error: [cache.invalid_argument] unknown verb")
    );
}

#[test]
fn connection_errors() {
    let r = resh(&["cache://redis/a.get", "key=k"]);
    assert_fail(&r, 2, "cache.connection_not_found");
    let r = resh(&["cache://redis/a.connect", "url=rediss://127.0.0.1:6380"]);
    assert_fail(&r, 2, "cache.tls_unsupported");
    for url in [
        format!("url=redis://127.0.0.1:{}", closed_port()),
        format!("url=memcache://127.0.0.1:{}", closed_port()),
    ] {
        let backend = if url.contains("redis") {
            "redis"
        } else {
            "memcached"
        };
        let r = resh(&[&format!("cache://{backend}/a.connect"), &url]);
        assert_fail(&r, 1, "cache.connect_failed");
    }
    // A server that accepts but never answers.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "url=memcache://127.0.0.1:{}",
        l.local_addr().unwrap().port()
    );
    let r = resh(&[
        "cache://memcached/a.connect",
        &url,
        "connect_timeout_ms=300",
    ]);
    assert_fail(&r, 124, "cache.connect_timeout");
}

#[test]
fn every_error_code_is_documented() {
    let doc = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/Data_StateManagement/cache.md"),
    )
    .unwrap();
    for code in [
        "invalid_argument",
        "invalid_target",
        "tls_unsupported",
        "connection_not_found",
        "connect_failed",
        "connect_timeout",
        "timeout",
        "connection_lost",
        "server_error",
        "wrong_type",
        "decode_failed",
        "keys_unsupported",
    ] {
        assert!(doc.contains(&format!("`cache.{code}`")), "{code}");
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
        "connect" => include_str!("golden/cache_connect_help.txt"),
        "get" => include_str!("golden/cache_get_help.txt"),
        "exists" => include_str!("golden/cache_exists_help.txt"),
        "ttl" => include_str!("golden/cache_ttl_help.txt"),
        "keys" => include_str!("golden/cache_keys_help.txt"),
        "set" => include_str!("golden/cache_set_help.txt"),
        "incr" => include_str!("golden/cache_incr_help.txt"),
        "del" => include_str!("golden/cache_del_help.txt"),
        _ => unreachable!(),
    }
}

#[test]
fn handle_help_matches_golden() {
    let r = resh(&["cache", "--help"]);
    assert_eq!(r.code, 0);
    assert_eq!(r.stderr, "");
    assert_plain(&r.stdout);
    assert_eq!(r.stdout, include_str!("golden/cache_help.txt"));
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
        &["cache", "-h"][..],
        &["cache", "help"][..],
        &["help", "cache"][..],
        &["cache://--help"][..],
        &["cache://redis/x.help"][..],
    ] {
        assert_eq!(resh(alt).stdout, r.stdout, "{alt:?}");
    }
}

/// The `name=` options in a usage block.
fn usage_options(out: &str) -> Vec<String> {
    let usage = out
        .split("Usage:\n")
        .nth(1)
        .unwrap()
        .split("\n\n")
        .next()
        .unwrap();
    let mut v: Vec<String> = usage
        .split(|c: char| c.is_whitespace() || matches!(c, '[' | ']' | '|'))
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
        let r = resh(&["cache", verb, "--help"]);
        assert_eq!(r.code, 0, "{verb}");
        assert_eq!(r.stderr, "");
        assert_plain(&r.stdout);
        assert!(
            r.stdout
                .starts_with(&format!("Handle: cache\nVerb: {verb}\nDefinition: "))
        );
        for section in ["\nUsage:\n", "\nExample:\n", "\nExample Output:\n"] {
            assert!(r.stdout.contains(section), "{verb}: {section:?}");
        }
        assert_eq!(r.stdout, golden(verb), "{verb}: help differs from golden");
        let mut want: Vec<String> = options_for(verb).iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(usage_options(&r.stdout), want, "{verb}");
        for alt in [
            vec!["cache".to_string(), verb.to_string(), "-h".into()],
            vec!["help".into(), "cache".into(), verb.to_string()],
            vec![format!("cache://--help={verb}")],
            vec![format!("cache://redis/x.{verb}(help=1)")],
        ] {
            let argv: Vec<&str> = alt.iter().map(String::as_str).collect();
            assert_eq!(resh(&argv).stdout, r.stdout, "{alt:?}");
        }
    }
}
