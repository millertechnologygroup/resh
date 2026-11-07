//! `cache://<backend>/<alias>.<verb>`: keys in Redis or Memcached.
//!
//! Every verb validates all of its arguments before it contacts a server
//! (unknown or invalid arguments exit 2 with `cache.invalid_argument`),
//! then connects on demand with `url=` (or reuses a connection made earlier
//! in the same process under the same alias) and bounds the work with
//! `timeout_ms` (exit 124, `cache.timeout`). Results are one JSON object on
//! stdout; failures print `{"alias","backend","error":{"code","message"}}`
//! and `Error: [cache.<code>] ...` on stderr.

mod memcached;
mod redis_ops;
#[cfg(test)]
mod tests;

use anyhow::{Context, Result};
use base64::prelude::*;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use url::Url;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::Status,
};
use memcached::Memcached;

/// Metadata for `resh cache --help` and `resh cache <verb> --help`.
static CACHE_HELP: HandleHelp = HandleHelp {
    description: "The cache handle reads and writes keys in Redis or Memcached, with key \
        namespaces, TTLs, conditional writes and value encodings, and prints JSON. The \
        target names a backend and a connection alias, such as cache://redis/main or \
        cache://memcached/main. Connections last only for one resh process, so every \
        verb takes url=<connection-url> and connects on demand.",
    usage: "resh cache://<backend>/<alias>.<verb> url=<connection-url> [key=value ...]",
    verbs: &[
        VerbHelp {
            name: "connect",
            definition: "Opens a connection to the server at url, checks that it answers, \
                and registers it under the alias for the rest of the resh process.",
            detail: Some(VerbDetail {
                usage: "resh cache://<backend>/<alias>.connect url=<connection-url>\n  \
                    [connect_timeout_ms=<ms>]",
                example: "resh --json-pretty cache://redis/main.connect \
                    url=redis://localhost:6379/0",
                example_output: Some(
                    r#"{
  "alias": "main",
  "backend": "redis",
  "endpoint": "localhost:6379",
  "status": "connected"
}

Shown with --json-pretty. Redis takes redis://[:password@]host[:port][/db]
or redis+unix:///path; Memcached takes memcache://host[:port]. TLS
(rediss://) is not supported. connect_timeout_ms defaults to 5000."#,
                ),
            }),
        },
        VerbHelp {
            name: "get",
            definition: "Reads one key or a list of keys and decodes each value, returning \
                the default value for a missing key.",
            detail: Some(VerbDetail {
                usage: "resh cache://<backend>/<alias>.get key=<key>|keys=<json-array>\n  \
                    url=<connection-url> [namespace=<ns>] [decode=utf8|bytes|json]\n  \
                    [default=<value>] [timeout_ms=<ms>] [connect_timeout_ms=<ms>]",
                example: "resh --json-pretty cache://redis/main.get key=user:42 url=redis://cache",
                example_output: Some(
                    r#"{
  "alias": "main",
  "backend": "redis",
  "hit": true,
  "key": "user:42",
  "value": "alice"
}

Shown with --json-pretty. With keys= the output has alias, backend,
and a results array of key, value, hit."#,
                ),
            }),
        },
        VerbHelp {
            name: "exists",
            definition: "Reports whether one key, or each key in a list, exists.",
            detail: Some(VerbDetail {
                usage: "resh cache://<backend>/<alias>.exists key=<key>|keys=<json-array>\n  \
                    url=<connection-url> [namespace=<ns>] [timeout_ms=<ms>]\n  \
                    [connect_timeout_ms=<ms>]",
                example: "resh --json-pretty cache://redis/main.exists key=user:42 url=redis://cache",
                example_output: Some(
                    r#"{
  "alias": "main",
  "backend": "redis",
  "exists": true,
  "key": "user:42"
}

Shown with --json-pretty. With keys= the output has a results array
and a total_exists count."#,
                ),
            }),
        },
        VerbHelp {
            name: "ttl",
            definition: "Reports whether keys exist and how many milliseconds remain before \
                they expire.",
            detail: Some(VerbDetail {
                usage: "resh cache://<backend>/<alias>.ttl key=<key>|keys=<json-array>\n  \
                    url=<connection-url> [namespace=<ns>] [timeout_ms=<ms>]\n  \
                    [connect_timeout_ms=<ms>]",
                example: "resh --json-pretty cache://redis/main.ttl key=session:1 url=redis://cache",
                example_output: Some(
                    r#"{
  "alias": "main",
  "backend": "redis",
  "exists": true,
  "has_expiry": true,
  "key": "session:1",
  "supports_ttl": true,
  "ttl_ms": 59000
}

Shown with --json-pretty. ttl_ms is null for a key without an expiry.
Memcached 1.6+ reports whole seconds; older servers report supports_ttl
false. With keys= the output has a results array and a found count."#,
                ),
            }),
        },
        VerbHelp {
            name: "keys",
            definition: "Lists keys that match a glob pattern one page at a time, with \
                Redis SCAN or the Memcached LRU crawler.",
            detail: Some(VerbDetail {
                usage: "resh cache://<backend>/<alias>.keys url=<connection-url>\n  \
                    [pattern=<glob>] [namespace=<ns>] [cursor=<cursor>] [limit=<n>]\n  \
                    [timeout_ms=<ms>] [connect_timeout_ms=<ms>]",
                example: "resh --json-pretty cache://redis/main.keys 'pattern=user:*' url=redis://cache",
                example_output: Some(
                    r#"{
  "alias": "main",
  "backend": "redis",
  "count": 2,
  "cursor": null,
  "has_more": false,
  "keys": [
    "user:42",
    "user:43"
  ]
}

Shown with --json-pretty. When has_more is true, pass the returned
cursor to fetch the next page. On Redis, limit is a SCAN COUNT hint."#,
                ),
            }),
        },
        VerbHelp {
            name: "set",
            definition: "Stores a value under one key, or values under a list of keys, with \
                an optional TTL and an only-if-missing or only-if-present condition.",
            detail: Some(VerbDetail {
                usage: "resh cache://<backend>/<alias>.set key=<key>|keys=<json-array>\n  \
                    value=<value>|values=<json-array> url=<connection-url>\n  \
                    [namespace=<ns>] [ttl_ms=<ms>] [encode=utf8|bytes|json]\n  \
                    [only_if_not_exists=true|false] [only_if_exists=true|false]\n  \
                    [timeout_ms=<ms>] [connect_timeout_ms=<ms>]",
                example: "resh cache://redis/main.set key=u1 value=alice ttl_ms=60000 \
                    url=redis://cache",
                example_output: Some(
                    r#"{
  "alias": "main",
  "backend": "redis",
  "key": "u1",
  "stored": true,
  "ttl_ms": 60000
}

Shown as --json-pretty output. A write skipped by a condition reports
stored false and reason condition_not_met. With keys= the output has a
results array and a total_stored count."#,
                ),
            }),
        },
        VerbHelp {
            name: "incr",
            definition: "Adds an integer to a counter, creating it from the initial value \
                when the key is missing.",
            detail: Some(VerbDetail {
                usage: "resh cache://<backend>/<alias>.incr key=<key> url=<connection-url>\n  \
                    [by=<n>] [initial=<n>] [ttl_ms=<ms>] [namespace=<ns>]\n  \
                    [timeout_ms=<ms>] [connect_timeout_ms=<ms>]",
                example: "resh --json-pretty cache://redis/main.incr key=views by=5 url=redis://cache",
                example_output: Some(
                    r#"{
  "alias": "main",
  "backend": "redis",
  "created": false,
  "key": "views",
  "value": 47
}

Shown with --json-pretty. by may be negative; Memcached counters stop
at 0. ttl_ms sets the counter's expiry on every call."#,
                ),
            }),
        },
        VerbHelp {
            name: "del",
            definition: "Deletes one key or a list of keys and reports which keys were removed.",
            detail: Some(VerbDetail {
                usage: "resh cache://<backend>/<alias>.del key=<key>|keys=<json-array>\n  \
                    url=<connection-url> [namespace=<ns>] [timeout_ms=<ms>]\n  \
                    [connect_timeout_ms=<ms>]",
                example: "resh --json-pretty cache://redis/main.del key=user:42 url=redis://cache",
                example_output: Some(
                    r#"{
  "alias": "main",
  "backend": "redis",
  "deleted": true,
  "key": "user:42"
}

Shown with --json-pretty. With keys= the output has a results array
and a total_deleted count."#,
                ),
            }),
        },
    ],
};

// ------------------------------------------------------------- errors --

/// Every error code `cache` reports (without the `cache.` prefix).
pub(crate) const ERROR_CODES: &[&str] = &[
    "invalid_argument",
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
];

/// A failed verb: exit code (1, 2 or 124), error code and message.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Fail {
    pub exit: i32,
    pub code: &'static str,
    pub message: String,
}

impl Fail {
    fn new(exit: i32, code: &'static str, message: impl Into<String>) -> Self {
        debug_assert!(ERROR_CODES.contains(&code), "undocumented code {code}");
        Self {
            exit,
            code,
            message: message.into(),
        }
    }

    /// Invalid usage (exit 2): nothing was done.
    fn invalid(message: impl Into<String>) -> Self {
        Self::new(2, "invalid_argument", message)
    }

    /// A failure reported by the server (exit 1).
    fn server(message: impl Into<String>) -> Self {
        Self::new(1, "server_error", message)
    }

    /// The connection broke during the command. A write may or may not have
    /// happened (exit 124); a read changed nothing (exit 1).
    fn lost(write: bool, message: impl Into<String>) -> Self {
        Self::new(if write { 124 } else { 1 }, "connection_lost", message)
    }
}

// ------------------------------------------------------------ arguments --

/// Arguments every verb except `connect` takes.
const COMMON: &[&str] = &["url", "connect_timeout_ms", "timeout_ms"];

/// Arguments `verb` takes, or `None` for an unknown verb.
fn verb_args(verb: &str) -> Option<&'static [&'static str]> {
    Some(match verb {
        "connect" => &["url", "connect_timeout_ms"],
        "get" => &["key", "keys", "namespace", "decode", "default"],
        "exists" | "ttl" | "del" => &["key", "keys", "namespace"],
        "keys" => &["pattern", "namespace", "cursor", "limit"],
        "set" => &[
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
        "incr" => &["key", "by", "initial", "ttl_ms", "namespace"],
        _ => return None,
    })
}

/// Every argument `verb` accepts.
fn allowed_args(verb: &str) -> Vec<&'static str> {
    let mut all: Vec<&'static str> = verb_args(verb).unwrap_or(&[]).to_vec();
    if verb != "connect" {
        all.extend_from_slice(COMMON);
    }
    all
}

/// Refuses any argument `verb` does not take. `dry_run=false` is accepted
/// everywhere (the dispatcher refuses `dry_run=true`: no verb has a dry-run
/// mode).
fn check_args(verb: &str, args: &Args) -> Result<(), Fail> {
    let allowed = allowed_args(verb);
    let mut keys: Vec<&String> = args.keys().collect();
    keys.sort();
    for k in keys {
        let k = k.as_str();
        if allowed.contains(&k) {
            continue;
        }
        if k == "dry_run" {
            match crate::core::lenient::dry_run(args) {
                Ok(false) => continue,
                Ok(true) => {
                    return Err(Fail::invalid(format!(
                        "cache {verb} does not support dry_run; nothing was done"
                    )));
                }
                Err(e) => return Err(Fail::invalid(e.to_string())),
            }
        }
        if verb == "connect" && k == "timeout_ms" {
            return Err(Fail::invalid(
                "timeout_ms is not accepted by connect: use connect_timeout_ms",
            ));
        }
        if k == "ca_file" {
            return Err(Fail::new(
                2,
                "tls_unsupported",
                "ca_file is not accepted: this build of resh has no TLS support for cache \
                 servers",
            ));
        }
        return Err(Fail::invalid(format!(
            "unknown argument: {k}{}",
            suggest(k, &allowed)
                .map(|s| format!(" (did you mean `{s}`?)"))
                .unwrap_or_default()
        )));
    }
    Ok(())
}

/// The accepted argument closest to `bad` (edit distance at most 2 after
/// lowercasing and `-` to `_`), for a "did you mean" hint.
fn suggest(bad: &str, allowed: &[&'static str]) -> Option<&'static str> {
    fn distance(a: &str, b: &str) -> usize {
        let b: Vec<char> = b.chars().collect();
        let mut prev: Vec<usize> = (0..=b.len()).collect();
        for (i, ca) in a.chars().enumerate() {
            let mut cur = vec![i + 1; b.len() + 1];
            for (j, cb) in b.iter().enumerate() {
                let cost = usize::from(ca != *cb);
                cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
            }
            prev = cur;
        }
        prev[b.len()]
    }
    let lower = bad.to_ascii_lowercase().replace('-', "_");
    // A shortened name (`ttl` for `ttl_ms`).
    if lower.len() >= 3
        && let Some(a) = allowed.iter().find(|a| a.starts_with(lower.as_str()))
    {
        return Some(a);
    }
    allowed
        .iter()
        .map(|a| (distance(&lower, a), *a))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, a)| a)
}

/// Integer argument `key` in `min..=max`, `default` when absent.
fn u64_arg(args: &Args, key: &str, default: u64, min: u64, max: u64) -> Result<u64, Fail> {
    let Some(raw) = args.get(key) else {
        return Ok(default);
    };
    match raw.trim().parse::<u64>() {
        Ok(v) if (min..=max).contains(&v) => Ok(v),
        _ => Err(Fail::invalid(format!(
            "invalid value for {key}: {raw:?} (expected an integer from {min} to {max})"
        ))),
    }
}

/// Optional integer argument `key` in `min..=max`.
fn opt_u64_arg(args: &Args, key: &str, min: u64, max: u64) -> Result<Option<u64>, Fail> {
    if args.contains_key(key) {
        u64_arg(args, key, min, min, max).map(Some)
    } else {
        Ok(None)
    }
}

/// Signed integer argument `key`, `default` when absent.
fn i64_arg(args: &Args, key: &str, default: i64) -> Result<i64, Fail> {
    let Some(raw) = args.get(key) else {
        return Ok(default);
    };
    raw.trim().parse::<i64>().map_err(|_| {
        Fail::invalid(format!(
            "invalid value for {key}: {raw:?} (expected a whole number from {} to {})",
            i64::MIN,
            i64::MAX
        ))
    })
}

/// Boolean argument (`true|false|1|0|yes|no|on|off`), false when absent.
fn bool_arg(args: &Args, key: &str) -> Result<bool, Fail> {
    crate::core::lenient::bool_arg(args, key)
        .map(|v| v.unwrap_or(false))
        .map_err(|e| Fail::invalid(e.to_string()))
}

/// One of `choices`, `default` when absent.
fn choice_arg(
    args: &Args,
    key: &str,
    default: &'static str,
    choices: &[&'static str],
) -> Result<&'static str, Fail> {
    let Some(raw) = args.get(key) else {
        return Ok(default);
    };
    choices
        .iter()
        .find(|c| **c == raw.as_str())
        .copied()
        .ok_or_else(|| {
            Fail::invalid(format!(
                "invalid value for {key}: {raw:?} (expected {})",
                choices.join(", ")
            ))
        })
}

/// A JSON array argument (`keys=`, `values=`).
fn json_array_arg(args: &Args, key: &str) -> Result<Option<Vec<Value>>, Fail> {
    let Some(raw) = args.get(key) else {
        return Ok(None);
    };
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Array(items)) if !items.is_empty() => Ok(Some(items)),
        Ok(Value::Array(_)) => Err(Fail::invalid(format!("{key} cannot be an empty array"))),
        _ => Err(Fail::invalid(format!(
            "invalid value for {key}: expected a JSON array, for example {key}='[\"a\",\"b\"]'"
        ))),
    }
}

/// Default time allowed to open and check a connection.
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 5_000;
/// Default time allowed for the command itself.
const DEFAULT_TIMEOUT_MS: u64 = 1_000;
/// Longest timeout_ms: one day.
const MAX_TIMEOUT_MS: u64 = 86_400_000;
/// Longest connect_timeout_ms: ten minutes.
const MAX_CONNECT_TIMEOUT_MS: u64 = 600_000;
/// Longest ttl_ms: 100 years.
const MAX_TTL_MS: u64 = 100 * 365 * 86_400_000;
/// Largest keys page.
const MAX_LIMIT: u64 = 10_000;
/// Largest Redis SCAN COUNT hint.
const MAX_SCAN_COUNT: u64 = 1_000;

/// The cache backend named by the target host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Backend {
    Redis,
    Memcached,
}

impl Backend {
    fn as_str(self) -> &'static str {
        match self {
            Backend::Redis => "redis",
            Backend::Memcached => "memcached",
        }
    }
}

/// A checked `url=`: what to connect to and how to show it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ConnUrl {
    /// The URL as given (identifies the connection in the registry).
    pub url: String,
    /// `host:port` or socket path, without credentials.
    pub endpoint: String,
    /// Memcached: the `host:port` to connect to.
    pub addr: Option<String>,
}

impl ConnUrl {
    pub(crate) fn parse(backend: Backend, raw: &str) -> Result<Self, Fail> {
        if raw.trim().is_empty() {
            return Err(Fail::invalid("url cannot be empty"));
        }
        let parsed =
            Url::parse(raw.trim()).map_err(|e| Fail::invalid(format!("invalid url: {e}")))?;
        let scheme = parsed.scheme().to_ascii_lowercase();
        let host = parsed.host_str().unwrap_or("").to_string();
        match backend {
            Backend::Redis => {
                if scheme == "rediss" {
                    return Err(Fail::new(
                        2,
                        "tls_unsupported",
                        "rediss:// (TLS) is not supported by this build of resh; use \
                         redis:// on a trusted network or redis+unix:// for a local socket",
                    ));
                }
                if !matches!(scheme.as_str(), "redis" | "redis+unix" | "unix") {
                    return Err(Fail::invalid(format!(
                        "url scheme {scheme:?} is not valid for redis: use \
                         redis://host[:port][/db] or redis+unix:///path"
                    )));
                }
                redis::Client::open(raw.trim())
                    .map_err(|e| Fail::invalid(format!("invalid redis url: {e}")))?;
                let endpoint = if scheme == "redis" {
                    if host.is_empty() {
                        return Err(Fail::invalid("redis url must include a host"));
                    }
                    format!("{host}:{}", parsed.port().unwrap_or(6379))
                } else {
                    parsed.path().to_string()
                };
                Ok(Self {
                    url: raw.trim().to_string(),
                    endpoint,
                    addr: None,
                })
            }
            Backend::Memcached => {
                if !matches!(scheme.as_str(), "memcache" | "memcached") {
                    return Err(Fail::invalid(format!(
                        "url scheme {scheme:?} is not valid for memcached: use \
                         memcache://host[:port]"
                    )));
                }
                if host.is_empty() {
                    return Err(Fail::invalid("memcached url must include a host"));
                }
                if !parsed.username().is_empty() || parsed.password().is_some() {
                    return Err(Fail::invalid(
                        "memcached authentication is not supported: remove the user name \
                         and password from url",
                    ));
                }
                if parsed.query().is_some() {
                    return Err(Fail::invalid(
                        "memcached url options are not supported: remove the ?query from url \
                         (use connect_timeout_ms and timeout_ms)",
                    ));
                }
                if !matches!(parsed.path(), "" | "/") {
                    return Err(Fail::invalid(format!(
                        "memcached url cannot have a path: {:?}",
                        parsed.path()
                    )));
                }
                let addr = format!("{host}:{}", parsed.port().unwrap_or(11211));
                Ok(Self {
                    url: raw.trim().to_string(),
                    endpoint: addr.clone(),
                    addr: Some(addr),
                })
            }
        }
    }
}

/// Settings every verb shares.
struct Common {
    url: Option<ConnUrl>,
    connect_timeout_ms: u64,
    timeout_ms: u64,
}

impl Common {
    fn parse(backend: Backend, args: &Args) -> Result<Self, Fail> {
        Ok(Self {
            url: args
                .get("url")
                .map(|u| ConnUrl::parse(backend, u))
                .transpose()?,
            connect_timeout_ms: u64_arg(
                args,
                "connect_timeout_ms",
                DEFAULT_CONNECT_TIMEOUT_MS,
                1,
                MAX_CONNECT_TIMEOUT_MS,
            )?,
            timeout_ms: u64_arg(args, "timeout_ms", DEFAULT_TIMEOUT_MS, 1, MAX_TIMEOUT_MS)?,
        })
    }
}

/// The keys a verb works on: as given (for output) and as stored (with
/// the namespace prefix).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct KeySet {
    /// `keys=` was used: the output has a results array.
    pub many: bool,
    pub given: Vec<String>,
    pub stored: Vec<String>,
}

/// The `namespace=` prefix, checked.
fn namespace_arg(args: &Args) -> Result<Option<&str>, Fail> {
    match args.get("namespace") {
        None => Ok(None),
        Some(ns) if ns.is_empty() => Err(Fail::invalid("namespace cannot be empty")),
        Some(ns) => Ok(Some(ns.as_str())),
    }
}

fn stored_key(ns: Option<&str>, key: &str) -> String {
    match ns {
        Some(ns) => format!("{ns}:{key}"),
        None => key.to_string(),
    }
}

/// Checks a stored key for `backend` (memcached keys are limited).
fn check_stored_key(backend: Backend, key: &str) -> Result<(), Fail> {
    if key.is_empty() {
        return Err(Fail::invalid("a key cannot be empty"));
    }
    if backend == Backend::Memcached
        && let Some(why) = memcached::check_key(key)
    {
        return Err(Fail::invalid(why));
    }
    Ok(())
}

/// Exactly one of `key=` or `keys=<json-array of strings>`.
fn key_set(backend: Backend, args: &Args) -> Result<KeySet, Fail> {
    let ns = namespace_arg(args)?;
    let (many, given) = match (args.get("key"), json_array_arg(args, "keys")?) {
        (Some(_), Some(_)) => return Err(Fail::invalid("give key or keys, not both")),
        (None, None) => return Err(Fail::invalid("key=<key> or keys=<json-array> is required")),
        (Some(k), None) => (false, vec![k.clone()]),
        (None, Some(items)) => {
            let mut keys = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::String(s) => keys.push(s),
                    other => {
                        return Err(Fail::invalid(format!(
                            "keys must be a JSON array of strings; found {other}"
                        )));
                    }
                }
            }
            (true, keys)
        }
    };
    let stored: Vec<String> = given.iter().map(|k| stored_key(ns, k)).collect();
    for (g, s) in given.iter().zip(&stored) {
        if g.is_empty() {
            return Err(Fail::invalid("a key cannot be empty"));
        }
        check_stored_key(backend, s)?;
    }
    Ok(KeySet {
        many,
        given,
        stored,
    })
}

/// How a value is turned into stored bytes, or stored bytes back into a
/// value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Codec {
    Utf8,
    Bytes,
    Json,
}

fn codec_arg(args: &Args, key: &str) -> Result<Codec, Fail> {
    Ok(
        match choice_arg(args, key, "utf8", &["utf8", "bytes", "json"])? {
            "utf8" => Codec::Utf8,
            "bytes" => Codec::Bytes,
            _ => Codec::Json,
        },
    )
}

/// The bytes to store for text given on the command line (`value=`).
fn encode_text(text: &str, codec: Codec) -> Result<Vec<u8>, String> {
    match codec {
        Codec::Utf8 => Ok(text.as_bytes().to_vec()),
        Codec::Bytes => BASE64_STANDARD
            .decode(text.trim())
            .map_err(|e| format!("encode=bytes needs base64 text: {e}")),
        Codec::Json => serde_json::from_str::<Value>(text)
            .map(|v| v.to_string().into_bytes())
            .map_err(|e| format!("encode=json needs valid JSON: {e}")),
    }
}

/// The bytes to store for one item of `values=`: a string is its text (as
/// for `value=`); anything else is its JSON text.
fn encode_item(item: &Value, codec: Codec) -> Result<Vec<u8>, String> {
    match (item, codec) {
        (Value::String(s), Codec::Utf8 | Codec::Bytes) => encode_text(s, codec),
        (_, Codec::Bytes) => Err("encode=bytes needs base64 strings in values".into()),
        (_, Codec::Json) | (_, Codec::Utf8) => Ok(item.to_string().into_bytes()),
    }
}

/// Decodes stored bytes for output.
fn decode_bytes(raw: &[u8], codec: Codec) -> Result<Value, String> {
    match codec {
        Codec::Utf8 => std::str::from_utf8(raw)
            .map(|s| Value::String(s.to_string()))
            .map_err(|_| "the stored value is not UTF-8 text (use decode=bytes)".to_string()),
        Codec::Bytes => Ok(Value::String(BASE64_STANDARD.encode(raw))),
        Codec::Json => serde_json::from_slice(raw)
            .map_err(|e| format!("the stored value is not JSON ({e}); use decode=utf8")),
    }
}

/// The write condition of `set`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Cond {
    Always,
    IfMissing,
    IfExists,
}

/// A verb's work, fully validated.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Op {
    Connect,
    Get {
        keys: KeySet,
        decode: Codec,
        default: Value,
    },
    Exists {
        keys: KeySet,
    },
    Ttl {
        keys: KeySet,
    },
    Del {
        keys: KeySet,
    },
    Set {
        keys: KeySet,
        data: Vec<Vec<u8>>,
        ttl_ms: Option<u64>,
        cond: Cond,
    },
    Incr {
        key: String,
        stored: String,
        by: i64,
        initial: i64,
        ttl_ms: Option<u64>,
    },
    Keys {
        /// Glob over stored keys (namespace prefix included and escaped).
        pattern: String,
        /// Length of the `<namespace>:` prefix to strip from results.
        prefix_len: usize,
        cursor: Option<String>,
        limit: u64,
    },
}

impl Op {
    fn parse(backend: Backend, verb: &str, args: &Args) -> Result<Self, Fail> {
        Ok(match verb {
            "connect" => {
                if !args.contains_key("url") {
                    return Err(Fail::invalid(
                        "url is required, for example url=redis://localhost:6379/0",
                    ));
                }
                Op::Connect
            }
            "get" => {
                let decode = codec_arg(args, "decode")?;
                let default = match args.get("default") {
                    None => Value::Null,
                    Some(d) if decode == Codec::Json => serde_json::from_str(d).map_err(|e| {
                        Fail::invalid(format!("default must be JSON when decode=json: {e}"))
                    })?,
                    Some(d) => Value::String(d.clone()),
                };
                Op::Get {
                    keys: key_set(backend, args)?,
                    decode,
                    default,
                }
            }
            "exists" => Op::Exists {
                keys: key_set(backend, args)?,
            },
            "ttl" => Op::Ttl {
                keys: key_set(backend, args)?,
            },
            "del" => Op::Del {
                keys: key_set(backend, args)?,
            },
            "set" => Self::parse_set(backend, args)?,
            "incr" => {
                let Some(key) = args.get("key") else {
                    return Err(Fail::invalid("key=<key> is required"));
                };
                if key.is_empty() {
                    return Err(Fail::invalid("a key cannot be empty"));
                }
                let stored = stored_key(namespace_arg(args)?, key);
                check_stored_key(backend, &stored)?;
                let by = i64_arg(args, "by", 1)?;
                let initial = i64_arg(args, "initial", 0)?;
                if initial.checked_add(by).is_none() {
                    return Err(Fail::invalid(format!(
                        "initial + by overflows a 64-bit integer ({initial} + {by})"
                    )));
                }
                if backend == Backend::Memcached && initial < 0 {
                    return Err(Fail::invalid(
                        "memcached counters cannot be negative: initial must be 0 or more",
                    ));
                }
                Op::Incr {
                    key: key.clone(),
                    stored,
                    by,
                    initial,
                    ttl_ms: opt_u64_arg(args, "ttl_ms", 1, MAX_TTL_MS)?,
                }
            }
            "keys" => {
                let ns = namespace_arg(args)?;
                let pattern = args.get("pattern").map(String::as_str).unwrap_or("*");
                if pattern.is_empty() {
                    return Err(Fail::invalid("pattern cannot be empty (use pattern=*)"));
                }
                let (pattern, prefix_len) = match ns {
                    Some(ns) => (
                        format!("{}:{pattern}", memcached::glob_escape(ns)),
                        ns.len() + 1,
                    ),
                    None => (pattern.to_string(), 0),
                };
                let cursor = match args.get("cursor").map(String::as_str) {
                    None | Some("") | Some("0") => None,
                    Some(c) => {
                        check_cursor(backend, c)?;
                        Some(c.to_string())
                    }
                };
                Op::Keys {
                    pattern,
                    prefix_len,
                    cursor,
                    limit: u64_arg(args, "limit", 100, 1, MAX_LIMIT)?,
                }
            }
            _ => return Err(Fail::invalid(format!("unknown verb: {verb}"))),
        })
    }

    fn parse_set(backend: Backend, args: &Args) -> Result<Self, Fail> {
        let keys = key_set(backend, args)?;
        let encode = codec_arg(args, "encode")?;
        let data: Vec<Vec<u8>> = match (
            keys.many,
            args.get("value"),
            json_array_arg(args, "values")?,
        ) {
            (_, Some(_), Some(_)) => return Err(Fail::invalid("give value or values, not both")),
            (false, Some(v), None) => vec![encode_text(v, encode).map_err(Fail::invalid)?],
            (false, None, _) => {
                return Err(Fail::invalid("key= needs value=<value>"));
            }
            (true, None, Some(items)) => {
                if items.len() != keys.given.len() {
                    return Err(Fail::invalid(format!(
                        "keys has {} items but values has {}",
                        keys.given.len(),
                        items.len()
                    )));
                }
                items
                    .iter()
                    .map(|i| encode_item(i, encode).map_err(Fail::invalid))
                    .collect::<Result<_, _>>()?
            }
            (true, _, None) => {
                return Err(Fail::invalid("keys= needs values=<json-array>"));
            }
        };
        let cond = match (
            bool_arg(args, "only_if_not_exists")?,
            bool_arg(args, "only_if_exists")?,
        ) {
            (true, true) => {
                return Err(Fail::invalid(
                    "only_if_not_exists and only_if_exists cannot both be true",
                ));
            }
            (true, false) => Cond::IfMissing,
            (false, true) => Cond::IfExists,
            (false, false) => Cond::Always,
        };
        Ok(Op::Set {
            keys,
            data,
            ttl_ms: opt_u64_arg(args, "ttl_ms", 1, MAX_TTL_MS)?,
            cond,
        })
    }

    /// True for verbs that change the cache.
    fn writes(&self) -> bool {
        matches!(self, Op::Set { .. } | Op::Del { .. } | Op::Incr { .. })
    }
}

/// Checks a `cursor=` from an earlier `keys` page: a SCAN cursor number on
/// Redis, an opaque base64 position on Memcached.
fn check_cursor(backend: Backend, c: &str) -> Result<(), Fail> {
    let ok = match backend {
        Backend::Redis => c.parse::<u64>().is_ok(),
        Backend::Memcached => memcached_cursor_key(c).is_some(),
    };
    if ok {
        Ok(())
    } else {
        Err(Fail::invalid(format!(
            "invalid cursor {c:?}: pass the cursor a previous keys call returned"
        )))
    }
}

/// The last stored key of the previous Memcached page.
fn memcached_cursor_key(c: &str) -> Option<String> {
    BASE64_URL_SAFE_NO_PAD
        .decode(c)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|k| !k.is_empty())
}

fn memcached_cursor(last: &str) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(last.as_bytes())
}

// ----------------------------------------------------------- connections --

/// A connected client.
pub(crate) enum Client {
    Redis(redis::aio::ConnectionManager),
    Memcached(tokio::sync::Mutex<Memcached>),
}

/// A connection registered under a backend and alias.
pub(crate) struct Conn {
    url: String,
    endpoint: String,
    client: Client,
}

type Registry = Mutex<HashMap<(Backend, String), Arc<Conn>>>;

/// Connections made in this process, by backend and alias.
static CONNECTIONS: LazyLock<Registry> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn registered(backend: Backend, alias: &str) -> Option<Arc<Conn>> {
    CONNECTIONS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&(backend, alias.to_string()))
        .cloned()
}

fn register_conn(backend: Backend, alias: &str, conn: Arc<Conn>) {
    CONNECTIONS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert((backend, alias.to_string()), conn);
}

fn forget_conn(backend: Backend, alias: &str) {
    CONNECTIONS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&(backend, alias.to_string()));
}

/// Process-wide runtime. A Redis connection drives its socket from a task
/// on the runtime that created it, so registered connections are only
/// usable while that runtime lives.
fn cache_runtime() -> Result<&'static tokio::runtime::Runtime> {
    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    if let Some(rt) = RUNTIME.get() {
        return Ok(rt);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("failed to create the tokio runtime")?;
    Ok(RUNTIME.get_or_init(|| rt))
}

/// Opens and checks a connection (Redis `PING`, Memcached `version`)
/// within `timeout_ms`.
async fn open(backend: Backend, url: &ConnUrl, timeout_ms: u64) -> Result<Conn, Fail> {
    let limit = Duration::from_millis(timeout_ms);
    let endpoint = &url.endpoint;
    let timed_out = || {
        Fail::new(
            124,
            "connect_timeout",
            format!("no answer from {endpoint} within connect_timeout_ms={timeout_ms}"),
        )
    };
    let client = match backend {
        Backend::Redis => {
            let client = redis::Client::open(url.url.as_str())
                .map_err(|e| Fail::invalid(format!("invalid redis url: {e}")))?;
            let fut = async {
                // Commands are bounded by timeout_ms, not by the client.
                let mut manager = redis::aio::ConnectionManager::new_with_backoff_and_timeouts(
                    client,
                    2,
                    100,
                    0,
                    Duration::from_secs(86_400),
                    limit,
                )
                .await?;
                redis::cmd("PING")
                    .query_async::<_, String>(&mut manager)
                    .await?;
                Ok::<_, redis::RedisError>(manager)
            };
            let manager = tokio::time::timeout(limit, fut)
                .await
                .map_err(|_| timed_out())?
                .map_err(|e| {
                    if e.is_timeout() {
                        timed_out()
                    } else {
                        Fail::new(
                            1,
                            "connect_failed",
                            format!("cannot connect to redis at {endpoint}: {e}"),
                        )
                    }
                })?;
            Client::Redis(manager)
        }
        Backend::Memcached => {
            let addr = url.addr.clone().unwrap_or_default();
            let fut = async {
                let mut mc = Memcached::connect(&addr)
                    .await
                    .map_err(memcached::McError::Io)?;
                mc.version().await?;
                Ok::<_, memcached::McError>(mc)
            };
            let mc = tokio::time::timeout(limit, fut)
                .await
                .map_err(|_| timed_out())?
                .map_err(|e| {
                    Fail::new(
                        1,
                        "connect_failed",
                        format!("cannot connect to memcached at {endpoint}: {e}"),
                    )
                })?;
            Client::Memcached(tokio::sync::Mutex::new(mc))
        }
    };
    Ok(Conn {
        url: url.url.clone(),
        endpoint: url.endpoint.clone(),
        client,
    })
}

// ---------------------------------------------------------------- handle --

/// `cache://<backend>/<alias>`.
pub struct CacheHandle {
    backend: Backend,
    alias: String,
}

impl CacheHandle {
    pub fn from_url(url: &Url) -> Result<Self> {
        let host = url.host_str().unwrap_or("");
        // cache://--help: every call prints help.
        if crate::core::help::is_help_flag(host) {
            return Ok(Self {
                backend: Backend::Redis,
                alias: "--help".into(),
            });
        }
        let backend = match host.to_ascii_lowercase().as_str() {
            "redis" => Backend::Redis,
            "memcached" => Backend::Memcached,
            other => anyhow::bail!(
                "unsupported cache backend {other:?}: use cache://redis/<alias> or \
                 cache://memcached/<alias>"
            ),
        };
        let path = url.path().trim_start_matches('/');
        let alias = if path.is_empty() { "default" } else { path };
        Ok(Self {
            backend,
            alias: alias.to_string(),
        })
    }

    /// Handles the in-URL help forms (`help`, `--help`, `-h`,
    /// `--help=<verb>`, `help(verb=<verb>)`).
    fn check_and_display_help(
        &self,
        verb: &str,
        args: &Args,
        io: &mut IoStreams,
    ) -> Result<Option<Status>> {
        let topic: Option<&str> = if verb == "help"
            || crate::core::help::is_help_flag(verb)
            || crate::core::help::is_help_flag(&self.alias)
        {
            Some(args.get("verb").map(|s| s.as_str()).unwrap_or(""))
        } else if let Some(v) = verb.strip_prefix("--help=") {
            Some(v)
        } else if args.contains_key("help") && verb_args(verb).is_some() {
            Some(verb)
        } else {
            None
        };
        match topic {
            Some(t) => {
                let v = if t.is_empty() { None } else { Some(t) };
                let text = crate::core::help::render_legacy("cache", &CACHE_HELP, self.verbs(), v);
                write!(io.stdout, "{}", text)?;
                Ok(Some(Status::ok()))
            }
            None => Ok(None),
        }
    }

    /// Runs `verb`: validates every argument, connects (or reuses this
    /// alias's connection), then does the work within `timeout_ms`.
    pub(crate) fn run(&self, verb: &str, args: &Args) -> Result<Value, Fail> {
        check_args(verb, args)?;
        let common = Common::parse(self.backend, args)?;
        let op = Op::parse(self.backend, verb, args)?;
        let rt = cache_runtime().map_err(|e| Fail::server(format!("{e:#}")))?;
        rt.block_on(self.run_async(&common, &op))
    }

    async fn run_async(&self, common: &Common, op: &Op) -> Result<Value, Fail> {
        let conn = self.resolve(common, matches!(op, Op::Connect)).await?;
        if let Op::Connect = op {
            return Ok(json!({
                "alias": self.alias,
                "backend": self.backend.as_str(),
                "endpoint": conn.endpoint,
                "status": "connected",
            }));
        }
        let limit = Duration::from_millis(common.timeout_ms);
        let result = match tokio::time::timeout(limit, self.execute(&conn, op)).await {
            Ok(r) => r,
            Err(_) => Err(Fail::new(
                124,
                "timeout",
                if op.writes() {
                    format!(
                        "no answer within timeout_ms={}; the change may or may not have \
                         been made",
                        common.timeout_ms
                    )
                } else {
                    format!("no answer within timeout_ms={}", common.timeout_ms)
                },
            )),
        };
        // A connection whose command was cut short is in an unknown state.
        if matches!(&result, Err(f) if f.code == "timeout" || f.code == "connection_lost") {
            forget_conn(self.backend, &self.alias);
        }
        let mut out = result?;
        if let Value::Object(m) = &mut out {
            m.insert("alias".into(), json!(self.alias));
            m.insert("backend".into(), json!(self.backend.as_str()));
        }
        Ok(out)
    }

    /// The connection for this alias: a new one for `connect` or a
    /// different `url=`, otherwise the registered one.
    async fn resolve(&self, common: &Common, fresh: bool) -> Result<Arc<Conn>, Fail> {
        let existing = registered(self.backend, &self.alias);
        let url = match (&common.url, existing) {
            (Some(url), Some(c)) if !fresh && c.url == url.url => return Ok(c),
            (Some(url), _) => url,
            (None, Some(c)) => return Ok(c),
            (None, None) => {
                return Err(Fail::new(
                    2,
                    "connection_not_found",
                    format!(
                        "no connection for cache://{}/{}: pass url=<connection-url>",
                        self.backend.as_str(),
                        self.alias
                    ),
                ));
            }
        };
        let conn = Arc::new(open(self.backend, url, common.connect_timeout_ms).await?);
        register_conn(self.backend, &self.alias, Arc::clone(&conn));
        Ok(conn)
    }

    async fn execute(&self, conn: &Conn, op: &Op) -> Result<Value, Fail> {
        match &conn.client {
            Client::Redis(m) => redis_ops::execute(m.clone(), op).await,
            Client::Memcached(mc) => {
                let mut mc = mc.lock().await;
                memcached_execute(&mut mc, op).await
            }
        }
    }
}

/// Writes the result of `run` and returns the status.
fn report(
    io: &mut IoStreams,
    backend: Backend,
    alias: &str,
    verb: &str,
    result: Result<Value, Fail>,
) -> Result<Status> {
    match result {
        Ok(v) => {
            writeln!(io.stdout, "{v}")?;
            Ok(Status::ok())
        }
        Err(f) => {
            let code = format!("cache.{}", f.code);
            let mut obj = Map::new();
            obj.insert("alias".into(), json!(alias));
            obj.insert("backend".into(), json!(backend.as_str()));
            obj.insert(
                "error".into(),
                crate::core::status::error_json(&code, &f.message),
            );
            writeln!(io.stdout, "{}", Value::Object(obj))?;
            Ok(Status::coded(
                f.exit,
                &code,
                format!("cache {verb}: {}", f.message),
            ))
        }
    }
}

impl Handle for CacheHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &[
            "connect", "get", "set", "del", "incr", "exists", "keys", "ttl", "help", "--help", "-h",
        ]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&CACHE_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        if let Some(status) = self.check_and_display_help(verb, args, io)? {
            return Ok(status);
        }
        if verb_args(verb).is_none() {
            return Ok(Status::coded(
                2,
                "cache.invalid_argument",
                format!(
                    "unknown verb for cache://: {verb} (verbs: connect, get, exists, ttl, keys, \
                     set, incr, del)"
                ),
            ));
        }
        let result = self.run(verb, args);
        report(io, self.backend, &self.alias, verb, result)
    }
}

/// Register the cache:// scheme.
pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("cache", |u| Ok(Box::new(CacheHandle::from_url(u)?)));
    reg.set_probe_url("cache", "cache://redis/resh-help-probe");
}

// ------------------------------------------------------------- memcached --

/// Maps a memcached error. `write`: the command may have changed the cache.
fn mc_fail(e: memcached::McError, what: &str, write: bool) -> Fail {
    match e {
        memcached::McError::Io(e) => Fail::lost(write, format!("{what}: {e}")),
        other => Fail::server(format!("{what}: {other}")),
    }
}

/// Runs `op` on a memcached connection.
async fn memcached_execute(mc: &mut Memcached, op: &Op) -> Result<Value, Fail> {
    let write = op.writes();
    match op {
        Op::Connect => unreachable!("connect is answered before execute"),
        Op::Get {
            keys,
            decode,
            default,
        } => {
            let found = mc
                .get_many(&keys.stored)
                .await
                .map_err(|e| mc_fail(e, "memcached get failed", write))?;
            let raw: Vec<Option<Vec<u8>>> =
                keys.stored.iter().map(|k| found.get(k).cloned()).collect();
            get_output(keys, raw, *decode, default)
        }
        Op::Exists { keys } => {
            let mut results = Vec::new();
            for k in &keys.stored {
                let hit = match mc.meta_get(k, false).await {
                    Ok(memcached::Meta::Unsupported) => mc
                        .get_many(std::slice::from_ref(k))
                        .await
                        .map(|f| f.contains_key(k)),
                    Ok(memcached::Meta::Miss) => Ok(false),
                    Ok(memcached::Meta::Hit { .. }) => Ok(true),
                    Err(e) => Err(e),
                }
                .map_err(|e| mc_fail(e, "memcached exists failed", write))?;
                results.push(hit);
            }
            Ok(exists_output(keys, &results))
        }
        Op::Ttl { keys } => {
            let mut results = Vec::new();
            for k in &keys.stored {
                let meta = mc
                    .meta_get(k, true)
                    .await
                    .map_err(|e| mc_fail(e, "memcached ttl failed", write))?;
                results.push(match meta {
                    memcached::Meta::Unsupported => {
                        let exists = mc
                            .get_many(std::slice::from_ref(k))
                            .await
                            .map_err(|e| mc_fail(e, "memcached ttl failed", write))?
                            .contains_key(k);
                        TtlInfo {
                            exists,
                            supports_ttl: false,
                            ttl_ms: None,
                        }
                    }
                    memcached::Meta::Miss => TtlInfo {
                        exists: false,
                        supports_ttl: true,
                        ttl_ms: None,
                    },
                    memcached::Meta::Hit { ttl_secs } => TtlInfo {
                        exists: true,
                        supports_ttl: true,
                        ttl_ms: ttl_secs.map(|s| s.saturating_mul(1000)),
                    },
                });
            }
            Ok(ttl_output(keys, &results))
        }
        Op::Del { keys } => {
            let mut results = Vec::new();
            for k in &keys.stored {
                results.push(
                    mc.delete(k)
                        .await
                        .map_err(|e| mc_fail(e, "memcached delete failed", write))?,
                );
            }
            Ok(del_output(keys, &results))
        }
        Op::Set {
            keys,
            data,
            ttl_ms,
            cond,
        } => {
            let cmd = match cond {
                Cond::Always => "set",
                Cond::IfMissing => "add",
                Cond::IfExists => "replace",
            };
            let exp = memcached::exptime(*ttl_ms);
            let mut results = Vec::new();
            for (k, d) in keys.stored.iter().zip(data) {
                results.push(
                    mc.store(cmd, k, d, exp)
                        .await
                        .map_err(|e| mc_fail(e, "memcached set failed", write))?,
                );
            }
            Ok(set_output(keys, &results, *ttl_ms))
        }
        Op::Incr {
            key,
            stored,
            by,
            initial,
            ttl_ms,
        } => {
            let (value, created) = memcached_incr(mc, stored, *by, *initial, *ttl_ms).await?;
            Ok(json!({ "key": key, "value": value, "created": created }))
        }
        Op::Keys {
            pattern,
            prefix_len,
            cursor,
            limit,
        } => memcached_keys(mc, pattern, *prefix_len, cursor.as_deref(), *limit).await,
    }
}

/// `incr` on memcached: `incr`/`decr`, or `add` of the start value for a
/// missing key (retried as an increment if another client created it
/// first), then `touch` for the TTL.
async fn memcached_incr(
    mc: &mut Memcached,
    key: &str,
    by: i64,
    initial: i64,
    ttl_ms: Option<u64>,
) -> Result<(u64, bool), Fail> {
    let fail = |e| mc_fail(e, "memcached incr failed", true);
    let (cmd, amount) = if by >= 0 {
        ("incr", by.unsigned_abs())
    } else {
        ("decr", by.unsigned_abs())
    };
    let exp = memcached::exptime(ttl_ms);
    for _ in 0..2 {
        match mc.incr_decr(cmd, key, amount).await {
            Ok(Some(v)) => {
                if ttl_ms.is_some() {
                    mc.touch(key, exp).await.map_err(fail)?;
                }
                return Ok((v, false));
            }
            Ok(None) => {}
            Err(memcached::McError::Client(m)) => {
                return Err(Fail::new(
                    1,
                    "wrong_type",
                    format!("the value of {key:?} is not a counter (memcached: {m})"),
                ));
            }
            Err(e) => return Err(fail(e)),
        }
        // Missing: create it. Counters cannot go below 0.
        let start = (initial + by).max(0) as u64;
        if mc
            .store("add", key, start.to_string().as_bytes(), exp)
            .await
            .map_err(fail)?
        {
            return Ok((start, true));
        }
    }
    Err(Fail::server(format!(
        "memcached incr failed: {key:?} kept appearing and disappearing"
    )))
}

/// `keys` on memcached: one `lru_crawler metadump`, filtered, sorted, and
/// paged by the last key of the previous page.
async fn memcached_keys(
    mc: &mut Memcached,
    pattern: &str,
    prefix_len: usize,
    cursor: Option<&str>,
    limit: u64,
) -> Result<Value, Fail> {
    let dumped = loop {
        match mc
            .metadump()
            .await
            .map_err(|e| mc_fail(e, "memcached keys failed", false))?
        {
            memcached::Dump::Keys(k) => break k,
            // Another crawl is running; timeout_ms bounds the wait.
            memcached::Dump::Busy => tokio::time::sleep(Duration::from_millis(50)).await,
            memcached::Dump::Unsupported(why) => {
                return Err(Fail::new(1, "keys_unsupported", why));
            }
        }
    };
    let now = memcached::now_unix();
    let mut keys: Vec<String> = dumped
        .into_iter()
        .filter(|d| d.exp.is_none_or(|e| e > now))
        .map(|d| d.key)
        .filter(|k| memcached::glob_match(pattern.as_bytes(), k.as_bytes()))
        .collect();
    keys.sort();
    keys.dedup();
    let after = cursor.and_then(memcached_cursor_key);
    let start = match &after {
        Some(a) => keys.partition_point(|k| k <= a),
        None => 0,
    };
    let rest = &keys[start..];
    let page: Vec<&String> = rest.iter().take(limit as usize).collect();
    let has_more = rest.len() > page.len();
    let next = if has_more {
        page.last().map(|k| memcached_cursor(k))
    } else {
        None
    };
    let shown: Vec<String> = page.iter().map(|k| k[prefix_len..].to_string()).collect();
    Ok(json!({
        "keys": shown,
        "count": shown.len(),
        "cursor": next,
        "has_more": has_more,
    }))
}

// ---------------------------------------------------------------- output --

/// `get` output from the raw values, in key order.
pub(crate) fn get_output(
    keys: &KeySet,
    raw: Vec<Option<Vec<u8>>>,
    decode: Codec,
    default: &Value,
) -> Result<Value, Fail> {
    let mut results = Vec::new();
    for (key, raw) in keys.given.iter().zip(raw) {
        let (value, hit) = match raw {
            Some(bytes) => (
                decode_bytes(&bytes, decode)
                    .map_err(|e| Fail::new(1, "decode_failed", format!("{key}: {e}")))?,
                true,
            ),
            None => (default.clone(), false),
        };
        results.push(json!({ "key": key, "value": value, "hit": hit }));
    }
    Ok(if keys.many {
        json!({ "results": results })
    } else {
        results.remove(0)
    })
}

pub(crate) fn exists_output(keys: &KeySet, exists: &[bool]) -> Value {
    if !keys.many {
        return json!({ "key": keys.given[0], "exists": exists[0] });
    }
    let results: Vec<Value> = keys
        .given
        .iter()
        .zip(exists)
        .map(|(k, e)| json!({ "key": k, "exists": e }))
        .collect();
    json!({
        "results": results,
        "total_exists": exists.iter().filter(|e| **e).count(),
    })
}

pub(crate) fn del_output(keys: &KeySet, deleted: &[bool]) -> Value {
    if !keys.many {
        return json!({ "key": keys.given[0], "deleted": deleted[0] });
    }
    let results: Vec<Value> = keys
        .given
        .iter()
        .zip(deleted)
        .map(|(k, d)| json!({ "key": k, "deleted": d }))
        .collect();
    json!({
        "results": results,
        "total_deleted": deleted.iter().filter(|d| **d).count(),
    })
}

pub(crate) fn set_output(keys: &KeySet, stored: &[bool], ttl_ms: Option<u64>) -> Value {
    let item = |k: &String, s: bool| {
        let mut v = json!({ "key": k, "stored": s });
        if !s {
            v["reason"] = json!("condition_not_met");
        }
        v
    };
    let mut out = if keys.many {
        json!({
            "results": keys.given.iter().zip(stored).map(|(k, s)| item(k, *s)).collect::<Vec<_>>(),
            "total_stored": stored.iter().filter(|s| **s).count(),
        })
    } else {
        item(&keys.given[0], stored[0])
    };
    if let Some(ttl) = ttl_ms {
        out["ttl_ms"] = json!(ttl);
    }
    out
}

/// What `ttl` reports for one key.
pub(crate) struct TtlInfo {
    pub exists: bool,
    pub supports_ttl: bool,
    /// Remaining time; `None` for a missing key or one without an expiry.
    pub ttl_ms: Option<u64>,
}

pub(crate) fn ttl_output(keys: &KeySet, infos: &[TtlInfo]) -> Value {
    let item = |i: &TtlInfo| {
        json!({
            "exists": i.exists,
            "supports_ttl": i.supports_ttl,
            "has_expiry": i.ttl_ms.is_some(),
            "ttl_ms": i.ttl_ms,
        })
    };
    if !keys.many {
        let mut v = item(&infos[0]);
        v["key"] = json!(keys.given[0]);
        return v;
    }
    let results: Vec<Value> = keys
        .given
        .iter()
        .zip(infos)
        .map(|(k, i)| {
            let mut v = item(i);
            v["key"] = json!(k);
            v
        })
        .collect();
    json!({
        "results": results,
        "found": infos.iter().filter(|i| i.exists).count(),
    })
}
