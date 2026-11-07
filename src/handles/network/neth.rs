//! `net://`: local interfaces and routes, and TCP/ICMP/DNS probes of a host.
//!
//! Every verb takes exactly the arguments listed in [`verb_args`]; anything
//! else is refused (exit 2) before any work is done. Exit codes: 0 success,
//! 1 the operation failed, 2 invalid arguments, 124 timeout or outcome
//! unknown. Failures print a JSON object with
//! `"error": {"code": "net.<code>", "message"}` on stdout, and
//! `Error: [net.<code>] <message>` on stderr.

use anyhow::{Context, Result};
use serde_json::{Map, Value, json};
use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use trust_dns_resolver::error::ResolveErrorKind;
use trust_dns_resolver::proto::rr::{RData, RecordType as TrustDnsRecordType};
use trust_dns_resolver::{
    IntoName, TokioAsyncResolver,
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
};
use url::Url;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::Status,
};

/// Metadata for `resh net --help` and `resh net <verb> --help`.
static NET_HELP: HandleHelp = HandleHelp {
    description: "The net handle lists local network interfaces and routes and probes remote \
        hosts with ping, TCP connection checks, port scans, and DNS queries. It uses the \
        system ping and ip commands where available, with TCP and /proc fallbacks. The URL \
        host names the target, such as net://example.com or net://192.0.2.10:22, and \
        net://if is used for interface listing.",
    usage: "resh net://<host>[:<port>].<verb>[(key=value,...)]",
    verbs: &[
        VerbHelp {
            name: "list",
            definition: "Lists local network interfaces with their flags, index, MAC \
                address, MTU and IP addresses as JSON.",
            detail: Some(VerbDetail {
                usage: "resh net://if.list [family=ipv4|ipv6|all] [up=true|false]",
                example: "resh net://if.list family=ipv4 up=true",
                example_output: Some(
                    r#"{
  "interfaces": [
    {
      "addresses": [
        {
          "addr": "192.0.2.10",
          "family": "ipv4",
          "scope": "global"
        }
      ],
      "flags": [
        "up",
        "broadcast",
        "running",
        "multicast",
        "lower_up"
      ],
      "index": 2,
      "mac": "52:54:00:12:34:56",
      "mtu": 1500,
      "name": "eth0"
    }
  ]
}

Shown with --json-pretty. up=true keeps interfaces that are
administratively up, up=false those that are down. With a family,
only interfaces with an address of that family are listed."#,
                ),
            }),
        },
        VerbHelp {
            name: "route.list",
            definition: "Lists the local routing table as a JSON array, read from the ip \
                command or /proc on Linux.",
            detail: Some(VerbDetail {
                usage: "resh net://<host>.route.list [family=ipv4|ipv6|all]\n  \
                    [table=main|local|default|all|<id>] [timeout_ms=<ms>]",
                example: "resh net://localhost.route.list",
                example_output: Some(
                    r#"[
  {
    "dst": "default",
    "family": "ipv4",
    "flags": [
      "gateway"
    ],
    "gateway": "192.0.2.1",
    "iface": "eth0",
    "metric": 100,
    "protocol": "dhcp",
    "scope": null,
    "table": "main"
  },
  {
    "dst": "192.0.2.0/24",
    "family": "ipv4",
    "flags": [
      "link"
    ],
    "gateway": null,
    "iface": "eth0",
    "metric": 100,
    "protocol": "kernel",
    "scope": "link",
    "table": "main"
  }
]

Shown for a Linux host with the ip command. Without it, routes come from
/proc/net/route with null protocol and scope (main table only)."#,
                ),
            }),
        },
        VerbHelp {
            name: "dns",
            definition: "Looks up DNS records of one type for the URL host and prints \
                them as JSON.",
            detail: Some(VerbDetail {
                usage: "resh net://<name>.dns [type=A|AAAA|CNAME|MX|TXT|NS|SRV|PTR]\n  \
                    [server=<ip>] [port=<n>] [timeout_ms=<ms>]",
                example: "resh net://example.com.dns type=A",
                example_output: Some(
                    r#"{
  "query": "example.com",
  "records": [
    {
      "data": "192.0.2.10",
      "name": "example.com",
      "ttl": 300
    }
  ],
  "rtype": "A",
  "server": "system"
}

Shown with --json-pretty. Without server=, the system resolver
(/etc/resolv.conf) is asked. MX and SRV records report data as an object."#,
                ),
            }),
        },
        VerbHelp {
            name: "ping",
            definition: "Pings a host with the system ping command, falling back to TCP \
                connection attempts, and reports reachability and round-trip time.",
            detail: Some(VerbDetail {
                usage: "resh net://<host>.ping [count=<n>] [timeout_ms=<ms>] [port=<n>]\n  \
                    [family=auto|ipv4|ipv6] [raw=true|false]",
                example: "resh net://192.0.2.10.ping count=3",
                example_output: Some(
                    r#"{
  "avg_rtt_ms": 0.412,
  "backend": "system_ping",
  "host": "192.0.2.10",
  "loss": 0.0,
  "port": 80,
  "reachable": true,
  "received": 3,
  "sent": 3,
  "timeout_ms": 3000
}

Shown with --json-pretty. Exits 1 when no reply came back. If the ping
command cannot run, backend is tcp_fallback and port is the TCP port
that was tried."#,
                ),
            }),
        },
        VerbHelp {
            name: "tcp_check",
            definition: "Tests whether a TCP connection to the URL host and port succeeds, \
                optionally with a TLS handshake and retries, and reports the result as JSON.",
            detail: Some(VerbDetail {
                usage: "resh net://<host>:<port>.tcp_check [port=<n>] [timeout_ms=<ms>]\n  \
                    [retries=<n>] [backoff_ms=<ms>] [expect_tls=true|false]",
                example: "resh net://192.0.2.10:22.tcp_check retries=3",
                example_output: Some(
                    r#"{
  "attempts": 1,
  "backend": "tcp",
  "host": "192.0.2.10",
  "latency_ms": 2,
  "ok": true,
  "port": 22,
  "retries": 3,
  "timeout_ms": 3000,
  "tls_checked": false
}

Shown for an open port with --json-pretty. A failed check has ok false
and an error field instead of latency_ms, and exits 1 (124 when the last
attempt timed out)."#,
                ),
            }),
        },
        VerbHelp {
            name: "scan",
            definition: "Scans a list of TCP ports on a host and reports each port as \
                open, closed, timeout, or error.",
            detail: Some(VerbDetail {
                usage: "resh net://<host>.scan [ports=<list>] [timeout_ms=<ms>]\n  \
                    [concurrency=<n>] [host=<host>] [protocol=tcp]",
                example: "resh net://192.0.2.10.scan ports=22,80",
                example_output: Some(
                    r#"{
  "ports": [
    {
      "port": 22,
      "state": "open"
    },
    {
      "error": "connection refused",
      "port": 80,
      "state": "closed"
    }
  ],
  "protocol": "tcp",
  "scan": {
    "concurrency": 32,
    "duration_ms": 3,
    "started_at": "2026-10-16T09:12:44.512309123+00:00",
    "timeout_ms": 500
  },
  "target": "192.0.2.10"
}

Shown with --json-pretty. Ports accept lists and ranges such as
22,80,8000-8005 and default to 80,443."#,
                ),
            }),
        },
    ],
};

// ------------------------------------------------------------- arguments --

const LIST_ARGS: &[&str] = &["family", "up"];
const ROUTE_LIST_ARGS: &[&str] = &["family", "table", "timeout_ms"];
const DNS_ARGS: &[&str] = &["type", "server", "port", "timeout_ms"];
const PING_ARGS: &[&str] = &["count", "timeout_ms", "port", "family", "raw"];
const TCP_CHECK_ARGS: &[&str] = &["port", "timeout_ms", "retries", "backoff_ms", "expect_tls"];
const SCAN_ARGS: &[&str] = &["ports", "timeout_ms", "concurrency", "host", "protocol"];

/// The largest accepted `timeout_ms` / `backoff_ms` (24 hours).
const MAX_MS: u64 = 86_400_000;
/// The largest number of ports one scan may probe.
const MAX_SCAN_PORTS: usize = 4096;

/// The arguments `verb` accepts, or `None` for an unknown verb. This is the
/// single list the argument check and the help usage are tested against.
fn verb_args(verb: &str) -> Option<&'static [&'static str]> {
    Some(match verb {
        "list" => LIST_ARGS,
        "route.list" => ROUTE_LIST_ARGS,
        "dns" => DNS_ARGS,
        "ping" => PING_ARGS,
        "tcp_check" => TCP_CHECK_ARGS,
        "scan" => SCAN_ARGS,
        _ => return None,
    })
}

/// A failure of a verb: its exit code, error code and message.
#[derive(Debug)]
struct Fail {
    exit: i32,
    code: &'static str,
    detail: String,
}

impl Fail {
    fn new(exit: i32, code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            exit,
            code,
            detail: detail.into(),
        }
    }

    /// Invalid usage (exit 2): nothing was done.
    fn invalid(detail: impl Into<String>) -> Self {
        Self::new(2, "invalid_argument", detail)
    }
}

/// Every error code `net` reports (without the `net.` prefix).
const ERROR_CODES: &[&str] = &[
    "invalid_argument",
    "lookup_failed",
    "resolve_failed",
    "timeout",
    "unreachable",
    "ping_failed",
    "connect_failed",
    "tls_failed",
    "scan_failed",
    "route_read_failed",
    "interfaces_failed",
    "unsupported_platform",
];

/// `{"code": "net.<code>", "message": ...}`, the `error` of a JSON failure.
fn error_obj(code: &str, message: &str) -> Value {
    debug_assert!(ERROR_CODES.contains(&code), "undocumented code {code}");
    json!({"code": format!("net.{code}"), "message": message})
}

/// A failure status whose message is `[net.<code>] <message>`.
fn coded(exit: i32, code: &str, message: &str) -> Status {
    debug_assert!(ERROR_CODES.contains(&code), "undocumented code {code}");
    Status::err(exit, format!("[net.{code}] {message}"))
}

/// Prints `fail` as `{"verb", ...extra, "error": {"code", "message"}}` on
/// stdout and returns its status.
fn report(io: &mut IoStreams, verb: &str, fail: Fail, extra: &[(&str, Value)]) -> Result<Status> {
    let mut obj = Map::new();
    obj.insert("verb".into(), json!(verb));
    for (k, v) in extra {
        obj.insert((*k).to_string(), v.clone());
    }
    obj.insert("error".into(), error_obj(fail.code, &fail.detail));
    writeln!(io.stdout, "{}", Value::Object(obj))?;
    Ok(coded(
        fail.exit,
        fail.code,
        &format!("net {verb}: {}", fail.detail),
    ))
}

/// Refuses any argument `verb` does not take.
fn check_args(verb: &str, args: &Args) -> Result<(), Fail> {
    let allowed = verb_args(verb).unwrap_or(&[]);
    let mut keys: Vec<&String> = args.keys().collect();
    keys.sort();
    let Some(bad) = keys.into_iter().find(|k| !allowed.contains(&k.as_str())) else {
        return Ok(());
    };
    Err(Fail::invalid(match bad.as_str() {
        "timeout_ms" => "timeout_ms is not accepted: this verb does not wait".to_string(),
        "dry_run" => "dry_run is not accepted: this verb changes nothing".to_string(),
        _ => format!(
            "unknown argument: {bad}{}",
            suggest(bad, allowed)
                .map(|s| format!(" (did you mean `{s}`?)"))
                .unwrap_or_default()
        ),
    }))
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

/// Optional port argument (1-65535).
fn port_arg(args: &Args) -> Result<Option<u16>, Fail> {
    if !args.contains_key("port") {
        return Ok(None);
    }
    Ok(Some(u64_arg(args, "port", 0, 1, 65535)? as u16))
}

/// Boolean argument (`true|false|1|0|yes|no|on|off`).
fn bool_arg(args: &Args, key: &str, default: bool) -> Result<bool, Fail> {
    crate::core::lenient::bool_arg(args, key)
        .map(|v| v.unwrap_or(default))
        .map_err(|e| Fail::invalid(e.to_string()))
}

/// One of `choices`, `default` when absent.
fn choice_arg<'a>(
    args: &'a Args,
    key: &str,
    default: &'a str,
    choices: &[&str],
) -> Result<&'a str, Fail> {
    let v = args.get(key).map(String::as_str).unwrap_or(default);
    if choices.contains(&v) {
        Ok(v)
    } else {
        Err(Fail::invalid(format!(
            "invalid value for {key}: {v:?} (expected {})",
            choices.join(", ")
        )))
    }
}

/// A host name or address given by the user: non-empty, no whitespace or
/// control characters, and not option-shaped (it is passed to `ping`).
fn check_host(host: &str, what: &str) -> Result<(), Fail> {
    if host.is_empty() {
        return Err(Fail::invalid(format!("{what} is empty")));
    }
    if host.starts_with('-') {
        return Err(Fail::invalid(format!(
            "{what} {host:?} starts with '-' and could be read as an option"
        )));
    }
    if host.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(Fail::invalid(format!(
            "{what} {host:?} contains whitespace or control characters"
        )));
    }
    Ok(())
}

/// Resolves `host:port`, giving up after `timeout` (the system resolver has
/// no time limit of its own). An IP literal needs no lookup.
fn resolve(host: &str, port: u16, timeout: Duration) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let (tx, rx) = mpsc::channel();
    let name = host.to_string();
    thread::spawn(move || {
        let found = (name.as_str(), port)
            .to_socket_addrs()
            .map(|a| a.collect::<Vec<_>>());
        // The receiver is gone when the lookup outlived its timeout; the
        // late result is simply dropped.
        tx.send(found).ok();
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(addrs)) if addrs.is_empty() => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no address found for {host}"),
        )),
        Ok(Ok(addrs)) => Ok(addrs),
        Ok(Err(e)) => Err(io::Error::new(
            e.kind(),
            format!("cannot resolve {host}: {e}"),
        )),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "resolving {host} took longer than {} ms",
                timeout.as_millis()
            ),
        )),
    }
}

/// Takes the record of a tool stopped at its deadline. The tools net runs
/// (`ping`, `ip`) only read, so the verb reports the timeout itself
/// (`net.timeout`, exit 124) instead of the generic "may already have made
/// changes" outcome; a tool that could not be stopped is still named.
fn take_lost_note() -> String {
    match crate::core::process::take_lost() {
        Some(l) if matches!(l.stopped, crate::core::process::Stopped::StillRunning) => {
            format!("; {} could not be stopped and may still be running", l.tool)
        }
        _ => String::new(),
    }
}

/// True when `err` is a timeout.
fn is_timeout(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

// ------------------------------------------------------------------- DNS --

#[derive(Debug, Clone, PartialEq)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    SRV,
    PTR,
}

impl RecordType {
    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "A" => Ok(Self::A),
            "AAAA" => Ok(Self::AAAA),
            "CNAME" => Ok(Self::CNAME),
            "MX" => Ok(Self::MX),
            "TXT" => Ok(Self::TXT),
            "NS" => Ok(Self::NS),
            "SRV" => Ok(Self::SRV),
            "PTR" => Ok(Self::PTR),
            _ => anyhow::bail!("Unknown record type: {}", s),
        }
    }

    fn to_trust_dns(&self) -> TrustDnsRecordType {
        match self {
            Self::A => TrustDnsRecordType::A,
            Self::AAAA => TrustDnsRecordType::AAAA,
            Self::CNAME => TrustDnsRecordType::CNAME,
            Self::MX => TrustDnsRecordType::MX,
            Self::TXT => TrustDnsRecordType::TXT,
            Self::NS => TrustDnsRecordType::NS,
            Self::SRV => TrustDnsRecordType::SRV,
            Self::PTR => TrustDnsRecordType::PTR,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::A => "A",
            Self::AAAA => "AAAA",
            Self::CNAME => "CNAME",
            Self::MX => "MX",
            Self::TXT => "TXT",
            Self::NS => "NS",
            Self::SRV => "SRV",
            Self::PTR => "PTR",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedRecord {
    pub name: String,
    pub ttl: u32,
    pub kind: ResolvedKind,
}

#[derive(Debug, Clone)]
pub enum ResolvedKind {
    A(String),
    AAAA(String),
    CNAME(String),
    MX {
        priority: u16,
        exchange: String,
    },
    TXT(String),
    NS(String),
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    PTR(String),
}

pub type ResolvedRecords = Vec<ResolvedRecord>;

/// A DNS lookup that did not finish within its time limit.
#[derive(Debug)]
pub struct DnsTimeout;

impl std::fmt::Display for DnsTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DNS lookup timed out")
    }
}

impl std::error::Error for DnsTimeout {}

pub trait DnsResolver: Send + Sync {
    /// Looks up `name`. A lookup that runs out of time fails with a
    /// [`DnsTimeout`] in its error chain.
    fn lookup(
        &self,
        name: &str,
        rtype: RecordType,
        server: Option<SocketAddr>,
        timeout: Duration,
    ) -> Result<ResolvedRecords>;
}

/// Resolver backed by trust-dns: the given server, or the system
/// configuration (`/etc/resolv.conf`).
pub struct SystemDnsResolver;

impl SystemDnsResolver {
    pub fn new() -> Self {
        Self
    }
}

impl DnsResolver for SystemDnsResolver {
    fn lookup(
        &self,
        name: &str,
        rtype: RecordType,
        server: Option<SocketAddr>,
        timeout: Duration,
    ) -> Result<ResolvedRecords> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("cannot start the DNS runtime")?;
        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        let config = match server {
            Some(server_addr) => {
                let mut config = ResolverConfig::new();
                config.add_name_server(NameServerConfig::new(server_addr, Protocol::Udp));
                config
            }
            None => crate::handles::network::dnsh::system_resolver_config()?,
        };
        rt.block_on(async {
            let resolver = TokioAsyncResolver::tokio(config, opts);
            // The whole lookup (retries, several servers) gets `timeout`.
            match tokio::time::timeout(timeout, perform_lookup(&resolver, name, rtype)).await {
                Ok(result) => result,
                Err(_) => Err(anyhow::Error::new(DnsTimeout)),
            }
        })
    }
}

async fn perform_lookup(
    resolver: &TokioAsyncResolver,
    name: &str,
    rtype: RecordType,
) -> Result<ResolvedRecords> {
    let lookup = if rtype == RecordType::PTR {
        let ip: IpAddr = name
            .parse()
            .with_context(|| format!("PTR lookup requires an IP address, got: {name}"))?;
        resolver
            .lookup(ip.into_name()?, TrustDnsRecordType::PTR)
            .await
    } else {
        resolver.lookup(name, rtype.to_trust_dns()).await
    };
    let lookup = match lookup {
        Ok(l) => l,
        Err(e) if matches!(e.kind(), ResolveErrorKind::Timeout) => {
            return Err(anyhow::Error::new(DnsTimeout));
        }
        Err(e) => {
            return Err(anyhow::Error::new(e))
                .context(format!("{} record lookup failed", rtype.as_str()));
        }
    };
    let mut records = Vec::new();
    for record in lookup.records() {
        let ttl = record.ttl();
        let owner = record.name().to_string();
        let (rname, kind) = match (record.data(), &rtype) {
            (Some(RData::A(a)), RecordType::A) => {
                (name.to_string(), ResolvedKind::A(a.to_string()))
            }
            (Some(RData::AAAA(a)), RecordType::AAAA) => {
                (name.to_string(), ResolvedKind::AAAA(a.to_string()))
            }
            (Some(RData::CNAME(c)), RecordType::CNAME) => {
                (owner, ResolvedKind::CNAME(c.to_string()))
            }
            (Some(RData::MX(mx)), RecordType::MX) => (
                name.to_string(),
                ResolvedKind::MX {
                    priority: mx.preference(),
                    exchange: mx.exchange().to_string(),
                },
            ),
            (Some(RData::TXT(txt)), RecordType::TXT) => (
                name.to_string(),
                ResolvedKind::TXT(
                    txt.txt_data()
                        .iter()
                        .map(|b| String::from_utf8_lossy(b).into_owned())
                        .collect::<Vec<_>>()
                        .join(""),
                ),
            ),
            (Some(RData::NS(ns)), RecordType::NS) => (owner, ResolvedKind::NS(ns.to_string())),
            (Some(RData::SRV(srv)), RecordType::SRV) => (
                owner,
                ResolvedKind::SRV {
                    priority: srv.priority(),
                    weight: srv.weight(),
                    port: srv.port(),
                    target: srv.target().to_string(),
                },
            ),
            (Some(RData::PTR(p)), RecordType::PTR) => {
                (name.to_string(), ResolvedKind::PTR(p.to_string()))
            }
            // CNAMEs followed on the way to the answer, and anything else.
            _ => continue,
        };
        records.push(ResolvedRecord {
            name: rname,
            ttl,
            kind,
        });
    }
    Ok(records)
}

fn record_json(record: ResolvedRecord) -> Value {
    let data = match record.kind {
        ResolvedKind::A(s)
        | ResolvedKind::AAAA(s)
        | ResolvedKind::CNAME(s)
        | ResolvedKind::NS(s)
        | ResolvedKind::PTR(s)
        | ResolvedKind::TXT(s) => json!(s),
        ResolvedKind::MX { priority, exchange } => {
            json!({"priority": priority, "exchange": exchange})
        }
        ResolvedKind::SRV {
            priority,
            weight,
            port,
            target,
        } => json!({"priority": priority, "weight": weight, "port": port, "target": target}),
    };
    json!({"name": record.name, "ttl": record.ttl, "data": data})
}

// ---------------------------------------------------------------- handle --

pub struct NetHandle {
    resource: String, // e.g., "if", "interfaces", or host for ping/tcp_check
    host: Option<String>,
    port: Option<u16>,
    resolver: Arc<dyn DnsResolver>,
    /// CA bundle for `expect_tls`; `None` reads `SSL_CERT_FILE` or the
    /// system bundle. Tests set it instead of the environment.
    ca_file: Option<PathBuf>,
}

impl NetHandle {
    pub fn from_url(u: &Url) -> Result<Self> {
        let host = u
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("net:// URL missing host"))?;
        // An IPv6 literal comes back in brackets.
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host)
            .to_string();
        let port = u.port();

        let (resource, actual_host) = if host == "if" || host == "interfaces" || host == "iface" {
            (host.clone(), None)
        } else {
            (host.clone(), Some(host))
        };

        Ok(NetHandle {
            resource,
            host: actual_host,
            port,
            resolver: Arc::new(SystemDnsResolver::new()),
            ca_file: None,
        })
    }

    /// A handle for `target` that asks `resolver` for DNS lookups.
    #[cfg(test)]
    pub fn with_resolver(target: String, resolver: Arc<dyn DnsResolver>) -> Self {
        NetHandle {
            resource: target.clone(),
            host: Some(target),
            port: None,
            resolver,
            ca_file: None,
        }
    }

    // Extract domain name from URL for DNS queries
    fn extract_dns_query_name(&self) -> Result<String, Fail> {
        let query_name = self.resource.strip_suffix(".dns").unwrap_or(&self.resource);
        if query_name.is_empty() || self.host.is_none() {
            return Err(Fail::invalid(
                "No valid domain name or IP provided for DNS query",
            ));
        }
        check_host(query_name, "query name")?;
        Ok(query_name.to_string())
    }

    /// The URL host, refused when missing (`net://if`) or option-shaped.
    fn target_host(&self, verb: &str) -> Result<&str, Fail> {
        let host = self.host.as_deref().ok_or_else(|| {
            Fail::invalid(format!(
                "needs a host: net://<host>.{verb} (\"{}\" names the interface list)",
                self.resource
            ))
        })?;
        check_host(host, "host")?;
        Ok(host)
    }

    /// Check if this is a help request (`help`, `--help`, `-h`, or
    /// `--help=<verb>`) and, if so, write the approved help.
    fn check_and_display_help(
        &self,
        verb: &str,
        args: &Args,
        io: &mut IoStreams,
    ) -> Result<Option<Status>> {
        let specific = if crate::core::help::HELP_ALIASES.contains(&verb) {
            args.get("verb").map(String::as_str)
        } else if let Some(v) = verb.strip_prefix("--help=") {
            Some(v)
        } else if args.contains_key("help") {
            // `net://host.ping(help=1)`
            Some(verb)
        } else {
            return Ok(None);
        };
        let text = crate::core::help::render_legacy("net", &NET_HELP, self.verbs(), specific);
        write!(io.stdout, "{}", text)?;
        Ok(Some(Status::ok()))
    }
}

impl Handle for NetHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &[
            "list",
            "ping",
            "tcp_check",
            "scan",
            "dns",
            "route.list",
            "help",
            "--help",
            "-h",
        ]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&NET_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        if let Some(status) = self.check_and_display_help(verb, args, io)? {
            return Ok(status);
        }
        if verb_args(verb).is_none() {
            return Ok(coded(
                2,
                "invalid_argument",
                &format!(
                    "unknown verb for net://: {verb} (verbs: list, route.list, dns, ping, \
                     tcp_check, scan)"
                ),
            ));
        }
        if let Err(fail) = check_args(verb, args) {
            return report(io, verb, fail, &[]);
        }
        match verb {
            "list" => list_interfaces(args, io),
            "ping" => self.verb_ping(args, io),
            "tcp_check" => self.verb_tcp_check(args, io),
            "scan" => self.scan(args, io),
            "dns" => self.call_dns(args, io),
            _ => self.route_list(args, io),
        }
    }
}

// ------------------------------------------------------------------- dns --

impl NetHandle {
    fn call_dns(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let query_name = match self.extract_dns_query_name() {
            Ok(name) => name,
            Err(fail) => {
                let q = json!(self.resource);
                return report(io, "dns", fail, &[("query", q)]);
            }
        };
        let q = json!(query_name);

        let type_str = args.get("type").map(String::as_str).unwrap_or("A");
        let rtype = match RecordType::from_str(type_str) {
            Ok(rt) => rt,
            Err(e) => {
                let fail = Fail::invalid(format!(
                    "{e} (expected A, AAAA, CNAME, MX, TXT, NS, SRV or PTR)"
                ));
                return report(io, "dns", fail, &[("query", q), ("rtype", json!(type_str))]);
            }
        };
        let ctx = [("query", q), ("rtype", json!(rtype.as_str()))];

        if rtype == RecordType::PTR && query_name.parse::<IpAddr>().is_err() {
            let fail = Fail::invalid(format!(
                "PTR lookup requires an IP address as the URL host, got: {query_name}"
            ));
            return report(io, "dns", fail, &ctx);
        }

        let timeout_ms = match u64_arg(args, "timeout_ms", 3000, 1, MAX_MS) {
            Ok(t) => t,
            Err(f) => return report(io, "dns", f, &ctx),
        };
        let timeout = Duration::from_millis(timeout_ms);

        let port = match port_arg(args) {
            Ok(p) => p,
            Err(f) => return report(io, "dns", f, &ctx),
        };
        let server = match args.get("server") {
            Some(server_str) => match server_str.trim().parse::<IpAddr>() {
                Ok(ip) => Some(SocketAddr::new(ip, port.unwrap_or(53))),
                Err(e) => {
                    let fail = Fail::invalid(format!("Cannot parse server IP {server_str:?}: {e}"));
                    return report(io, "dns", fail, &ctx);
                }
            },
            None if port.is_some() => {
                let fail = Fail::invalid(
                    "port= needs server=<ip>; the system resolver \
                     uses the ports in /etc/resolv.conf",
                );
                return report(io, "dns", fail, &ctx);
            }
            None => None,
        };

        match self
            .resolver
            .lookup(&query_name, rtype.clone(), server, timeout)
        {
            Ok(records) => {
                let server_info = server
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "system".to_string());
                let output = json!({
                    "query": query_name,
                    "rtype": rtype.as_str(),
                    "server": server_info,
                    "records": records.into_iter().map(record_json).collect::<Vec<_>>()
                });
                writeln!(io.stdout, "{}", output)?;
                Ok(Status::ok())
            }
            Err(e) if e.chain().any(|c| c.is::<DnsTimeout>()) => {
                let fail = Fail::new(
                    124,
                    "timeout",
                    format!("DNS lookup did not finish within timeout_ms={timeout_ms}"),
                );
                report(io, "dns", fail, &ctx)
            }
            Err(e) => {
                let fail = Fail::new(1, "lookup_failed", format!("DNS lookup failed: {e:#}"));
                report(io, "dns", fail, &ctx)
            }
        }
    }
}

// ------------------------------------------------------------------ ping --

struct PingResult {
    sent: u32,
    received: u32,
    avg_rtt_ms: Option<f64>,
}

impl PingResult {
    fn loss(&self) -> f64 {
        if self.sent == 0 {
            1.0
        } else {
            1.0 - (self.received.min(self.sent) as f64 / self.sent as f64)
        }
    }
}

/// What running the system `ping` came to.
enum SystemPing {
    /// It ran and reported its counts.
    Ran(PingResult),
    /// The host name does not resolve.
    Unresolved(String),
    /// It could not run here (missing, no permission, no route...): use the
    /// TCP fallback.
    Unavailable(String),
    /// It did not finish in time.
    TimedOut,
}

/// Counts and average round trip from the output of `ping` (iputils or
/// busybox). Only the summary line counts replies: ICMP error lines such as
/// `From 192.0.2.1 icmp_seq=1 Destination Host Unreachable` are not
/// replies.
fn parse_ping_output(stdout: &str) -> Option<PingResult> {
    let mut summary = None;
    let mut avg_rtt_ms = None;
    for line in stdout.lines() {
        if let Some(pos) = line.find(" packets transmitted, ") {
            let sent = line[..pos].trim().parse::<u32>().ok();
            let rest = &line[pos + " packets transmitted, ".len()..];
            let received = rest
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|n| n.parse::<u32>().ok());
            if let (Some(sent), Some(received)) = (sent, received) {
                summary = Some((sent, received));
            }
        }
        if let Some(pos) = line.find("min/avg/max") {
            if let Some(eq) = line[pos..].find(" = ") {
                let stats = &line[pos + eq + 3..];
                avg_rtt_ms = stats
                    .split(['/', ' '])
                    .nth(1)
                    .and_then(|v| v.parse::<f64>().ok());
            }
        }
    }
    let (sent, received) = summary?;
    Some(PingResult {
        sent,
        received,
        avg_rtt_ms: if received > 0 { avg_rtt_ms } else { None },
    })
}

/// True when `ping`'s error output says the name does not resolve.
fn is_resolve_error(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    [
        "name or service not known",
        "temporary failure in name resolution",
        "unknown host",
        "no address associated",
        "bad address",
        "nodename nor servname",
    ]
    .iter()
    .any(|p| s.contains(p))
}

impl NetHandle {
    fn verb_ping(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let parsed = (|| {
            let host = self.target_host("ping")?.to_string();
            let count = u64_arg(args, "count", 3, 1, u32::MAX as u64)? as u32;
            let timeout_ms = u64_arg(args, "timeout_ms", 3000, 100, MAX_MS)?;
            let port = port_arg(args)?;
            let family = choice_arg(args, "family", "auto", &["auto", "ipv4", "ipv6"])?.to_string();
            let raw = bool_arg(args, "raw", false)?;
            Ok::<_, Fail>((host, count, timeout_ms, port, family, raw))
        })();
        let (host, count, timeout_ms, port, family, raw) = match parsed {
            Ok(p) => p,
            Err(fail) => return report(io, "ping", fail, &[]),
        };
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let fallback_port = port.or(self.port).unwrap_or(80);
        let host_json = json!(host);

        let (backend, result) = match self
            .system_ping(&host, count, timeout_ms, &family, raw, io)?
        {
            SystemPing::Ran(r) => ("system_ping", r),
            SystemPing::TimedOut => {
                let fail = Fail::new(
                    124,
                    "timeout",
                    format!(
                        "ping did not finish within timeout_ms={timeout_ms} and was stopped{}",
                        take_lost_note()
                    ),
                );
                return report(io, "ping", fail, &[("host", host_json)]);
            }
            SystemPing::Unresolved(msg) => {
                let fail = Fail::new(1, "resolve_failed", msg);
                return report(io, "ping", fail, &[("host", host_json)]);
            }
            SystemPing::Unavailable(why) => {
                if raw {
                    writeln!(
                        io.stderr,
                        "system ping unavailable ({why}); using TCP connects"
                    )?;
                }
                match tcp_ping(&host, fallback_port, count, timeout_ms, &family, deadline) {
                    Ok(r) => ("tcp_fallback", r),
                    Err(e) => {
                        let (exit, code) = if is_timeout(&e) {
                            (124, "timeout")
                        } else {
                            (1, "ping_failed")
                        };
                        let fail = Fail::new(
                            exit,
                            code,
                            format!("system ping unavailable ({why}) and TCP fallback failed: {e}"),
                        );
                        return report(io, "ping", fail, &[("host", host_json)]);
                    }
                }
            }
        };

        let reachable = result.received > 0;
        let no_reply = format!(
            "net ping: no reply from {host} ({} sent, 0 received)",
            result.sent
        );
        let mut json_obj = json!({
            "host": host,
            "port": fallback_port,
            "backend": backend,
            "sent": result.sent,
            "received": result.received,
            "loss": result.loss(),
            "avg_rtt_ms": result.avg_rtt_ms,
            "timeout_ms": timeout_ms,
            "reachable": reachable
        });
        if !reachable {
            json_obj["error"] = error_obj("unreachable", &no_reply);
        }
        writeln!(io.stdout, "{}", json_obj)?;
        if reachable {
            Ok(Status::ok())
        } else {
            Ok(coded(1, "unreachable", &no_reply))
        }
    }

    /// Runs `ping -c <count> -w <seconds>`: ping stops once `count` replies
    /// arrived or `timeout_ms` (rounded up to whole seconds) passed.
    fn system_ping(
        &self,
        host: &str,
        count: u32,
        timeout_ms: u64,
        family: &str,
        raw: bool,
        io: &mut IoStreams,
    ) -> Result<SystemPing> {
        let (program, family_flag) = match family {
            "ipv6" if which::which("ping6").is_ok() => ("ping6", None),
            "ipv6" => ("ping", Some("-6")),
            "ipv4" => ("ping", Some("-4")),
            _ => ("ping", None),
        };
        if which::which(program).is_err() {
            return Ok(SystemPing::Unavailable(format!(
                "{program} not found in PATH"
            )));
        }
        let deadline_s = timeout_ms.div_ceil(1000).max(1);
        let mut cmd = Command::new(program);
        if let Some(flag) = family_flag {
            cmd.arg(flag);
        }
        cmd.arg("-c")
            .arg(count.to_string())
            .arg("-w")
            .arg(deadline_s.to_string())
            .arg(host);

        // ping ends itself at -w; the limit only catches a stuck tool.
        let limit = Duration::from_millis(deadline_s * 1000 + 2000);
        let output = match crate::core::process::run(&mut cmd, Some(limit)) {
            Ok(o) => o,
            Err(e) if e.kind() == io::ErrorKind::TimedOut => return Ok(SystemPing::TimedOut),
            Err(e) => {
                return Ok(SystemPing::Unavailable(format!(
                    "cannot run {program}: {e}"
                )));
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if raw {
            write!(
                io.stderr,
                "Raw ping output:\nSTDOUT:\n{}\nSTDERR:\n{}\n",
                stdout, stderr
            )?;
        }
        if let Some(result) = parse_ping_output(&stdout) {
            return Ok(SystemPing::Ran(result));
        }
        let msg = stderr.trim();
        if is_resolve_error(msg) {
            return Ok(SystemPing::Unresolved(format!(
                "cannot resolve {host}: {msg}"
            )));
        }
        Ok(SystemPing::Unavailable(format!(
            "{program} exited with {}: {}",
            output.status,
            if msg.is_empty() { "no output" } else { msg }
        )))
    }
}

/// The TCP fallback: up to `count` connects to `port`, each with a timeout
/// of `max(200, timeout_ms / count)` ms, all within `deadline`.
fn tcp_ping(
    host: &str,
    port: u16,
    count: u32,
    timeout_ms: u64,
    family: &str,
    deadline: Instant,
) -> io::Result<PingResult> {
    let left = deadline.saturating_duration_since(Instant::now());
    let addrs: Vec<SocketAddr> = resolve(host, port, left)?
        .into_iter()
        .filter(|a| match family {
            "ipv4" => a.is_ipv4(),
            "ipv6" => a.is_ipv6(),
            _ => true,
        })
        .collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{host} has no {family} address"),
        ));
    }
    let per_attempt = Duration::from_millis((timeout_ms / count as u64).max(200));
    let mut result = PingResult {
        sent: 0,
        received: 0,
        avg_rtt_ms: None,
    };
    let mut total_rtt = 0.0;
    while result.sent < count {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        result.sent += 1;
        let start = Instant::now();
        let attempt_end = start + per_attempt.min(left);
        // Like a name with A and AAAA records, the first address that
        // answers counts.
        for addr in &addrs {
            let left = attempt_end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            if TcpStream::connect_timeout(addr, left).is_ok() {
                total_rtt += start.elapsed().as_secs_f64() * 1000.0;
                result.received += 1;
                break;
            }
        }
    }
    if result.received > 0 {
        result.avg_rtt_ms = Some(total_rtt / result.received as f64);
    }
    Ok(result)
}

// ------------------------------------------------------------- tcp_check --

/// Why one tcp_check attempt failed.
struct AttemptError {
    message: String,
    /// `timeout`, `resolve_failed`, `connect_failed` or `tls_failed`.
    code: &'static str,
    tls_tried: bool,
}

impl NetHandle {
    fn verb_tcp_check(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let parsed = (|| {
            let host = self.target_host("tcp_check")?.to_string();
            let port = match (port_arg(args)?, self.port) {
                (Some(p), _) | (None, Some(p)) => p,
                (None, None) => {
                    return Err(Fail::invalid(
                        "needs a port: net://<host>:<port>.tcp_check or port=<n>",
                    ));
                }
            };
            if port == 0 {
                return Err(Fail::invalid("port 0 cannot be connected to"));
            }
            let timeout_ms = u64_arg(args, "timeout_ms", 3000, 1, MAX_MS)?;
            let retries = u64_arg(args, "retries", 1, 1, 1000)? as u32;
            let backoff_ms = u64_arg(args, "backoff_ms", 0, 0, MAX_MS)?;
            let expect_tls = bool_arg(args, "expect_tls", false)?;
            Ok::<_, Fail>((host, port, timeout_ms, retries, backoff_ms, expect_tls))
        })();
        let (host, port, timeout_ms, retries, backoff_ms, expect_tls) = match parsed {
            Ok(p) => p,
            Err(fail) => return report(io, "tcp_check", fail, &[]),
        };

        let tls = if expect_tls {
            let ca = self
                .ca_file
                .clone()
                .or_else(|| std::env::var_os("SSL_CERT_FILE").map(PathBuf::from));
            match tls::client_config(ca.as_deref()) {
                Ok(c) => Some(c),
                Err(e) => {
                    let fail = Fail::new(1, "tls_failed", e);
                    return report(
                        io,
                        "tcp_check",
                        fail,
                        &[("host", json!(host)), ("port", json!(port))],
                    );
                }
            }
        } else {
            None
        };

        let timeout = Duration::from_millis(timeout_ms);
        let mut last: Option<AttemptError> = None;
        for attempt in 1..=retries {
            let start = Instant::now();
            match attempt_connect(&host, port, timeout, tls.as_ref()) {
                Ok(()) => {
                    let json_output = json!({
                        "host": host,
                        "port": port,
                        "ok": true,
                        "attempts": attempt,
                        "latency_ms": start.elapsed().as_millis() as u64,
                        "timeout_ms": timeout_ms,
                        "retries": retries,
                        "backend": "tcp",
                        "tls_checked": expect_tls
                    });
                    writeln!(io.stdout, "{}", json_output)?;
                    return Ok(Status::ok());
                }
                Err(e) => last = Some(e),
            }
            if attempt < retries && backoff_ms > 0 {
                thread::sleep(Duration::from_millis(backoff_ms));
            }
        }

        let last = last.unwrap_or(AttemptError {
            message: "no attempt was made".into(),
            code: "connect_failed",
            tls_tried: false,
        });
        let message = format!("{host}:{port}: {}", last.message);
        let json_output = json!({
            "host": host,
            "port": port,
            "ok": false,
            "attempts": retries,
            "timeout_ms": timeout_ms,
            "retries": retries,
            "backend": "tcp",
            "error": error_obj(last.code, &message),
            "tls_checked": last.tls_tried
        });
        writeln!(io.stdout, "{}", json_output)?;
        let exit = if last.code == "timeout" { 124 } else { 1 };
        Ok(coded(exit, last.code, &format!("net tcp_check: {message}")))
    }
}

/// One attempt: resolve, connect to each address in turn, and (with `tls`)
/// complete a verified TLS handshake, all within `timeout`.
fn attempt_connect(
    host: &str,
    port: u16,
    timeout: Duration,
    tls: Option<&Arc<rustls::ClientConfig>>,
) -> Result<(), AttemptError> {
    let deadline = Instant::now() + timeout;
    let fail = |e: io::Error, code: &'static str, tls_tried: bool| AttemptError {
        code: if is_timeout(&e) { "timeout" } else { code },
        message: e.to_string(),
        tls_tried,
    };
    let addrs = resolve(host, port, timeout).map_err(|e| fail(e, "resolve_failed", false))?;
    let mut last = None;
    for addr in addrs {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&addr, left) {
            Ok(mut stream) => {
                let Some(config) = tls else {
                    return Ok(());
                };
                return tls::handshake(&mut stream, host, deadline, config).map_err(|e| {
                    let mut err = fail(e, "tls_failed", true);
                    err.message = format!("TLS handshake failed: {}", err.message);
                    err
                });
            }
            Err(e) => last = Some(e),
        }
    }
    Err(fail(
        last.unwrap_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "connection timed out")),
        "connect_failed",
        false,
    ))
}

mod tls {
    //! The TLS client handshake of `tcp_check expect_tls=true`.

    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, RootCertStore};
    use std::io;
    use std::net::TcpStream;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Instant;

    /// CA bundles of the common Linux distributions.
    const SYSTEM_BUNDLES: &[&str] = &[
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/ssl/cert.pem",
    ];

    /// A client configuration trusting the CAs in `ca_file`, or in the
    /// system bundle when it is `None`.
    pub fn client_config(ca_file: Option<&Path>) -> Result<Arc<ClientConfig>, String> {
        let path = match ca_file {
            Some(p) => p.to_path_buf(),
            None => SYSTEM_BUNDLES
                .iter()
                .map(Path::new)
                .find(|p| p.is_file())
                .ok_or("no CA bundle found (set SSL_CERT_FILE)")?
                .to_path_buf(),
        };
        let mut roots = RootCertStore::empty();
        let certs = CertificateDer::pem_file_iter(&path)
            .map_err(|e| format!("cannot read CA bundle {}: {e}", path.display()))?;
        for cert in certs {
            let cert = cert.map_err(|e| format!("bad certificate in {}: {e}", path.display()))?;
            // A certificate the verifier cannot use is skipped, as other
            // TLS clients do with system bundles.
            roots.add(cert).ok();
        }
        if roots.is_empty() {
            return Err(format!("no usable CA certificate in {}", path.display()));
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("TLS setup failed: {e}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Arc::new(config))
    }

    /// Completes a TLS handshake with `host` over `stream` by `deadline`,
    /// verifying the certificate chain and the host name (or IP address).
    pub fn handshake(
        stream: &mut TcpStream,
        host: &str,
        deadline: Instant,
        config: &Arc<ClientConfig>,
    ) -> io::Result<()> {
        let name = ServerName::try_from(host.to_string())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut conn = ClientConnection::new(Arc::clone(config), name)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        while conn.is_handshaking() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "handshake did not finish in time",
                ));
            }
            stream.set_read_timeout(Some(left))?;
            stream.set_write_timeout(Some(left))?;
            match conn.complete_io(stream) {
                Ok((0, 0)) if conn.is_handshaking() && conn.wants_read() => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the server closed the connection",
                    ));
                }
                Ok(_) => {}
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "no TLS answer from the server in time",
                    ));
                }
                Err(e) => return Err(e),
            }
        }
        // Say goodbye cleanly; the check is already decided.
        conn.send_close_notify();
        conn.write_tls(stream).ok();
        Ok(())
    }
}

// ------------------------------------------------------------------ scan --

/// Parses `ports` ("80,443,8000-8005") into a list without duplicates, in
/// the order given.
fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for token in spec.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let num = |s: &str| -> Result<u16, String> {
            match s.trim().parse::<u16>() {
                Ok(p) if p > 0 => Ok(p),
                _ => Err(format!("invalid port {s:?} (expected 1-65535)")),
            }
        };
        let (start, end) = match token.split_once('-') {
            Some((a, b)) => (num(a)?, num(b)?),
            None => {
                let p = num(token)?;
                (p, p)
            }
        };
        if start > end {
            return Err(format!("invalid range {token}: start > end"));
        }
        for port in start..=end {
            if seen.insert(port) {
                ports.push(port);
                if ports.len() > MAX_SCAN_PORTS {
                    return Err(format!("too many ports; at most {MAX_SCAN_PORTS}"));
                }
            }
        }
    }
    if ports.is_empty() {
        return Err("no port given".into());
    }
    Ok(ports)
}

/// The result of connecting to `port` on any of `addrs`.
fn scan_port(addrs: &[IpAddr], port: u16, timeout: Duration) -> Value {
    let mut last = None;
    for ip in addrs {
        match TcpStream::connect_timeout(&SocketAddr::new(*ip, port), timeout) {
            Ok(_) => return json!({"port": port, "state": "open"}),
            Err(e) => last = Some(e),
        }
    }
    match last {
        Some(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            json!({"port": port, "state": "closed", "error": "connection refused"})
        }
        Some(e) if is_timeout(&e) => json!({"port": port, "state": "timeout"}),
        Some(e) => json!({"port": port, "state": "error", "error": e.to_string()}),
        None => json!({"port": port, "state": "error", "error": "no address to connect to"}),
    }
}

impl NetHandle {
    fn scan(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let parsed = (|| {
            let target = match args.get("host") {
                Some(h) => {
                    let h = h.trim();
                    let h = h
                        .strip_prefix('[')
                        .and_then(|x| x.strip_suffix(']'))
                        .unwrap_or(h);
                    check_host(h, "host")?;
                    h.to_string()
                }
                None => self.target_host("scan")?.to_string(),
            };
            let protocol = choice_arg(args, "protocol", "tcp", &["tcp"])?.to_string();
            let timeout_ms = u64_arg(args, "timeout_ms", 500, 1, MAX_MS)?;
            // Documented as clamped to 1-256.
            let concurrency = u64_arg(args, "concurrency", 32, 0, u64::MAX)?.clamp(1, 256) as usize;
            let spec = args.get("ports").map(String::as_str).unwrap_or("80,443");
            let ports = parse_ports(spec)
                .map_err(|e| Fail::invalid(format!("invalid ports {spec:?}: {e}")))?;
            Ok::<_, Fail>((target, protocol, timeout_ms, concurrency, ports))
        })();
        let (target, protocol, timeout_ms, concurrency, ports) = match parsed {
            Ok(p) => p,
            Err(fail) => return report(io, "scan", fail, &[]),
        };

        let start_time = Instant::now();
        let started_at = chrono::Utc::now().to_rfc3339();
        let timeout = Duration::from_millis(timeout_ms);

        // Resolve once, not once per port.
        let resolve_limit = timeout.max(Duration::from_secs(5));
        let results: Vec<Value> = match resolve(&target, 0, resolve_limit) {
            Ok(addrs) => {
                let ips: Vec<IpAddr> = addrs.iter().map(|a| a.ip()).collect();
                scan_ports(&ips, &ports, timeout, concurrency)
            }
            Err(e) => ports
                .iter()
                .map(|p| json!({"port": p, "state": "error", "error": e.to_string()}))
                .collect(),
        };

        let all_error = results.iter().all(|p| p["state"] == "error");
        let failed = format!("net scan: no port of {target} could be probed");
        let mut output = json!({
            "target": target,
            "protocol": protocol,
            "ports": results,
            "scan": {
                "timeout_ms": timeout_ms,
                "concurrency": concurrency,
                "started_at": started_at,
                "duration_ms": start_time.elapsed().as_millis() as u64
            }
        });
        // Every probe failing, for example on a name that does not resolve,
        // says nothing about the ports.
        if all_error {
            output["error"] = error_obj("scan_failed", &failed);
        }
        writeln!(io.stdout, "{}", output)?;
        if all_error {
            return Ok(coded(1, "scan_failed", &failed));
        }
        Ok(Status::ok())
    }
}

/// Probes `ports` with at most `concurrency` connects at a time and returns
/// the results in the order of `ports`.
fn scan_ports(
    addrs: &[IpAddr],
    ports: &[u16],
    timeout: Duration,
    concurrency: usize,
) -> Vec<Value> {
    let next = AtomicUsize::new(0);
    let slots: Mutex<Vec<Option<Value>>> = Mutex::new(vec![None; ports.len()]);
    thread::scope(|s| {
        for _ in 0..concurrency.min(ports.len()) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&port) = ports.get(i) else { break };
                    let result = scan_port(addrs, port, timeout);
                    let mut slots = slots.lock().unwrap_or_else(|e| e.into_inner());
                    slots[i] = Some(result);
                }
            });
        }
    });
    slots
        .into_inner()
        .unwrap_or_else(|e| e.into_inner())
        .into_iter()
        .zip(ports)
        .map(|(r, p)| {
            r.unwrap_or_else(|| json!({"port": p, "state": "error", "error": "not probed"}))
        })
        .collect()
}

// ------------------------------------------------------------ route.list --

/// Route flags of the ip JSON output, normalized.
fn route_flags(gateway: bool, scope: Option<&str>, extra: &[Value]) -> Vec<String> {
    let mut flags = Vec::new();
    if gateway {
        flags.push("gateway".to_string());
    }
    match scope {
        Some("link") => flags.push("link".to_string()),
        Some("host") => flags.push("host".to_string()),
        _ => {}
    }
    for f in extra.iter().filter_map(Value::as_str) {
        if !flags.iter().any(|x| x == f) {
            flags.push(f.to_string());
        }
    }
    flags
}

/// Normalizes `ip -j [-6] route show table <table>` output.
fn normalize_ip_routes(stdout: &str, v6: bool, table: &str) -> Result<Vec<Value>, String> {
    if stdout.trim().is_empty() {
        return Ok(Vec::new());
    }
    let parsed: Value =
        serde_json::from_str(stdout).map_err(|e| format!("ip printed invalid JSON: {e}"))?;
    let routes = parsed
        .as_array()
        .ok_or("ip printed JSON that is not an array")?;
    // ip names the table only when listing several; one listed table, or
    // main, is not named.
    let default_table = if table == "all" { "main" } else { table };
    Ok(routes
        .iter()
        .map(|route| {
            let s = |k: &str| route.get(k).and_then(Value::as_str);
            // A multipath route keeps its gateway and device in nexthops.
            let first_hop = route
                .get("nexthops")
                .and_then(Value::as_array)
                .and_then(|h| h.first());
            let hop = |k: &str| s(k).or_else(|| first_hop.and_then(|h| h.get(k)?.as_str()));
            let gateway = hop("gateway");
            let scope = s("scope");
            let empty = Vec::new();
            let extra = route
                .get("flags")
                .and_then(Value::as_array)
                .unwrap_or(&empty);
            let table = match route.get("table") {
                Some(Value::String(t)) => json!(t),
                Some(Value::Number(n)) => json!(n.to_string()),
                _ => json!(default_table),
            };
            json!({
                "family": if v6 { "ipv6" } else { "ipv4" },
                "dst": s("dst").unwrap_or("default"),
                "gateway": gateway,
                "iface": hop("dev"),
                "metric": route.get("metric").and_then(Value::as_u64).unwrap_or(0),
                "table": table,
                "protocol": s("protocol"),
                "scope": scope,
                "flags": route_flags(gateway.is_some(), scope, extra),
            })
        })
        .collect())
}

/// Address from a little-endian hex field of `/proc/net/route`.
fn hex_to_ipv4(hex_str: &str) -> Option<std::net::Ipv4Addr> {
    if hex_str.len() != 8 {
        return None;
    }
    let val = u32::from_str_radix(hex_str, 16).ok()?;
    Some(std::net::Ipv4Addr::from(val.to_le_bytes()))
}

/// Address from a hex field of `/proc/net/ipv6_route`.
fn hex_to_ipv6(hex_str: &str) -> Option<std::net::Ipv6Addr> {
    if hex_str.len() != 32 {
        return None;
    }
    u128::from_str_radix(hex_str, 16)
        .ok()
        .map(std::net::Ipv6Addr::from)
}

fn kernel_route_flags(flags: u32, names: &[(u32, &'static str)]) -> Vec<&'static str> {
    names
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, n)| *n)
        .collect()
}

/// Routes of the main IPv4 table from the text of `/proc/net/route`.
fn parse_proc_net_route(contents: &str) -> Result<Vec<Value>, String> {
    const NAMES: &[(u32, &str)] = &[
        (0x0001, "up"),
        (0x0002, "gateway"),
        (0x0004, "host"),
        (0x0008, "reinstate"),
        (0x0010, "dynamic"),
        (0x0020, "modified"),
        (0x0200, "reject"),
    ];
    let mut routes = Vec::new();
    for line in contents.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 11 {
            continue;
        }
        let bad = || format!("malformed /proc/net/route line: {line:?}");
        let dest = hex_to_ipv4(f[1]).ok_or_else(bad)?;
        let gateway = hex_to_ipv4(f[2]).ok_or_else(bad)?;
        let flags = u32::from_str_radix(f[3], 16).map_err(|_| bad())?;
        let metric = f[6].parse::<u64>().map_err(|_| bad())?;
        let mask = hex_to_ipv4(f[7]).ok_or_else(bad)?;
        let prefix = u32::from(mask).leading_ones();
        let dst = match prefix {
            0 if dest.is_unspecified() => "default".to_string(),
            32 => dest.to_string(),
            _ => format!("{dest}/{prefix}"),
        };
        routes.push(json!({
            "family": "ipv4",
            "dst": dst,
            "gateway": (!gateway.is_unspecified()).then(|| gateway.to_string()),
            "iface": f[0],
            "metric": metric,
            "table": "main",
            "protocol": null,
            "scope": null,
            "flags": kernel_route_flags(flags, NAMES)
        }));
    }
    Ok(routes)
}

/// IPv6 routes from the text of `/proc/net/ipv6_route` (every table: the
/// file does not say which table a route is in, so `table` is null).
fn parse_proc_net_ipv6_route(contents: &str) -> Result<Vec<Value>, String> {
    const NAMES: &[(u32, &str)] = &[
        (0x0001, "up"),
        (0x0002, "gateway"),
        (0x0004, "host"),
        (0x0200, "reject"),
        (0x8000_0000, "local"),
    ];
    let mut routes = Vec::new();
    for line in contents.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let bad = || format!("malformed /proc/net/ipv6_route line: {line:?}");
        let dest = hex_to_ipv6(f[0]).ok_or_else(bad)?;
        let prefix = u32::from_str_radix(f[1], 16).map_err(|_| bad())?;
        let next_hop = hex_to_ipv6(f[4]).ok_or_else(bad)?;
        let metric = u32::from_str_radix(f[5], 16).map_err(|_| bad())?;
        let flags = u32::from_str_radix(f[8], 16).map_err(|_| bad())?;
        let dst = match prefix {
            0 if dest.is_unspecified() => "default".to_string(),
            128 => dest.to_string(),
            _ => format!("{dest}/{prefix}"),
        };
        routes.push(json!({
            "family": "ipv6",
            "dst": dst,
            "gateway": (!next_hop.is_unspecified()).then(|| next_hop.to_string()),
            "iface": f[9],
            "metric": metric as u64,
            "table": null,
            "protocol": null,
            "scope": null,
            "flags": kernel_route_flags(flags, NAMES)
        }));
    }
    Ok(routes)
}

impl NetHandle {
    fn route_list(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let ctx = [("backend", json!("net"))];
        let parsed = (|| {
            let family = choice_arg(args, "family", "ipv4", &["ipv4", "ipv6", "all"])?.to_string();
            let table = args
                .get("table")
                .map(|t| t.trim())
                .unwrap_or("main")
                .to_string();
            let named = ["main", "local", "default", "all"].contains(&table.as_str());
            if !named && table.parse::<u32>().is_err() {
                return Err(Fail::invalid(format!(
                    "invalid value for table: {table:?} (expected main, local, default, all \
                     or a table number)"
                )));
            }
            let timeout_ms = u64_arg(args, "timeout_ms", 5000, 1, MAX_MS)?;
            Ok::<_, Fail>((family, table, timeout_ms))
        })();
        let (family, table, timeout_ms) = match parsed {
            Ok(p) => p,
            Err(fail) => return report(io, "route.list", fail, &ctx),
        };

        if !cfg!(target_os = "linux") {
            let fail = Fail::new(
                1,
                "unsupported_platform",
                "route.list is only supported on Linux",
            );
            return report(io, "route.list", fail, &ctx);
        }

        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let mut all_routes = Vec::new();
        for v6 in [false, true] {
            let wanted = family == "all" || (family == "ipv6") == v6;
            if !wanted {
                continue;
            }
            match self.routes(v6, &table, deadline, io) {
                Ok(mut routes) => all_routes.append(&mut routes),
                // With family=all an unreadable IPv6 table (IPv6 disabled)
                // does not hide the IPv4 routes.
                Err(fail) if v6 && family == "all" && fail.exit != 124 => {
                    writeln!(io.stderr, "Warning: no IPv6 routes: {}", fail.detail)?;
                }
                Err(fail) => return report(io, "route.list", fail, &ctx),
            }
        }

        writeln!(io.stdout, "{}", serde_json::to_string_pretty(&all_routes)?)?;
        Ok(Status::ok())
    }

    /// Routes of one family: from `ip -j route`, else from /proc.
    fn routes(
        &self,
        v6: bool,
        table: &str,
        deadline: Instant,
        io: &mut IoStreams,
    ) -> Result<Vec<Value>, Fail> {
        let ip_error = match which::which("ip") {
            Ok(ip) => {
                let mut cmd = Command::new(ip);
                cmd.arg("-j");
                if v6 {
                    cmd.arg("-6");
                }
                cmd.args(["route", "show", "table", table]);
                let left = deadline.saturating_duration_since(Instant::now());
                match crate::core::process::run(&mut cmd, Some(left)) {
                    Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                        return Err(Fail::new(
                            124,
                            "timeout",
                            format!(
                                "the ip command did not finish within timeout_ms and was \
                                 stopped{}",
                                take_lost_note()
                            ),
                        ));
                    }
                    Err(e) => format!("cannot run ip: {e}"),
                    Ok(out) if out.status.success() => {
                        match normalize_ip_routes(&String::from_utf8_lossy(&out.stdout), v6, table)
                        {
                            Ok(routes) => return Ok(routes),
                            Err(e) => e,
                        }
                    }
                    Ok(out) => format!(
                        "ip route failed ({}): {}",
                        out.status,
                        String::from_utf8_lossy(&out.stderr).trim()
                    ),
                }
            }
            Err(_) => "the ip command is not installed".to_string(),
        };

        // /proc/net/route only holds the main IPv4 table.
        if (!v6 && table != "main") || (v6 && table != "all" && table != "main") {
            return Err(Fail::new(
                1,
                "route_read_failed",
                format!("table={table} needs the ip command ({ip_error})"),
            ));
        }
        let path = if v6 {
            "/proc/net/ipv6_route"
        } else {
            "/proc/net/route"
        };
        if which::which("ip").is_ok() {
            writeln!(io.stderr, "Warning: {ip_error}; reading {path}")
                .map_err(|e| Fail::new(1, "route_read_failed", e.to_string()))?;
        }
        let contents = std::fs::read_to_string(path).map_err(|e| {
            Fail::new(
                1,
                "route_read_failed",
                format!("cannot read {path}: {e} ({ip_error})"),
            )
        })?;
        let parsed = if v6 {
            parse_proc_net_ipv6_route(&contents)
        } else {
            parse_proc_net_route(&contents)
        };
        parsed.map_err(|e| Fail::new(1, "route_read_failed", e))
    }
}

// ------------------------------------------------------------------ list --

/// Interface flag bits (`<linux/if.h>`) and their names, in bit order.
const IFF_NAMES: &[(u32, &str)] = &[
    (0x1, "up"),
    (0x2, "broadcast"),
    (0x8, "loopback"),
    (0x10, "pointopoint"),
    (0x40, "running"),
    (0x80, "noarp"),
    (0x100, "promisc"),
    (0x200, "allmulti"),
    (0x1000, "multicast"),
    (0x10000, "lower_up"),
    (0x20000, "dormant"),
];
const IFF_UP: u32 = 0x1;

#[derive(Debug, Default)]
struct InterfaceData {
    index: Option<u32>,
    mac: Option<String>,
    flags: u32,
    addresses: Vec<IpAddr>,
}

/// Interfaces and their addresses from `getifaddrs(3)`, by name.
fn read_interfaces() -> io::Result<std::collections::BTreeMap<String, InterfaceData>> {
    let mut map: std::collections::BTreeMap<String, InterfaceData> = Default::default();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list freed below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list getifaddrs returned.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: a non-null ifa_name is a NUL-terminated string.
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let entry = map.entry(name).or_default();
        entry.flags |= ifa.ifa_flags;
        if ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: ifa_addr points to a sockaddr of the family it names.
        unsafe {
            match i32::from((*ifa.ifa_addr).sa_family) {
                libc::AF_INET => {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    entry.addresses.push(IpAddr::V4(ip));
                }
                libc::AF_INET6 => {
                    let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    entry.addresses.push(IpAddr::V6(ip));
                }
                #[cfg(target_os = "linux")]
                libc::AF_PACKET => {
                    let sll = &*(ifa.ifa_addr as *const libc::sockaddr_ll);
                    if sll.sll_ifindex > 0 {
                        entry.index = Some(sll.sll_ifindex as u32);
                    }
                    let len = usize::from(sll.sll_halen).min(sll.sll_addr.len());
                    if len > 0 {
                        entry.mac = Some(
                            sll.sll_addr[..len]
                                .iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<Vec<_>>()
                                .join(":"),
                        );
                    }
                }
                _ => {}
            }
        }
    }
    // SAFETY: `head` came from getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(head) };
    Ok(map)
}

/// The kernel index of interface `name`, if it has one.
fn if_index(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: `c` is a valid NUL-terminated string.
    let index = unsafe { libc::if_nametoindex(c.as_ptr()) };
    (index != 0).then_some(index)
}

/// The MTU of interface `name` from sysfs.
fn if_mtu(name: &str) -> Option<u32> {
    if name.contains('/') || name.starts_with('.') {
        return None;
    }
    std::fs::read_to_string(Path::new("/sys/class/net").join(name).join("mtu"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn address_scope(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(v4) if v4.is_loopback() => "host",
        IpAddr::V4(v4) if v4.is_link_local() => "link",
        IpAddr::V6(v6) if v6.is_loopback() => "host",
        IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80 => "link",
        _ => "global",
    }
}

fn list_interfaces(args: &Args, io: &mut IoStreams) -> Result<Status> {
    let parsed = (|| {
        let family = args.get("family").map(|f| f.to_ascii_lowercase());
        let family = match family.as_deref() {
            None | Some("all") => None,
            Some("ipv4") => Some(false),
            Some("ipv6") => Some(true),
            Some(_) => {
                return Err(Fail::invalid(format!(
                    "invalid value for family: {:?} (expected ipv4, ipv6, all)",
                    args.get("family").map(String::as_str).unwrap_or_default()
                )));
            }
        };
        let up =
            crate::core::lenient::bool_arg(args, "up").map_err(|e| Fail::invalid(e.to_string()))?;
        Ok::<_, Fail>((family, up))
    })();
    let (family_v6, up_filter) = match parsed {
        Ok(p) => p,
        Err(fail) => return report(io, "list", fail, &[]),
    };

    let interfaces = match read_interfaces() {
        Ok(i) => i,
        Err(e) => {
            let fail = Fail::new(
                1,
                "interfaces_failed",
                format!("cannot list interfaces: {e}"),
            );
            return report(io, "list", fail, &[]);
        }
    };

    let mut result = Vec::new();
    for (name, iface) in interfaces {
        if up_filter.is_some_and(|up| up != (iface.flags & IFF_UP != 0)) {
            continue;
        }
        let addresses: Vec<Value> = iface
            .addresses
            .iter()
            .filter(|ip| family_v6.is_none_or(|v6| ip.is_ipv6() == v6))
            .map(|ip| {
                json!({
                    "family": if ip.is_ipv6() { "ipv6" } else { "ipv4" },
                    "addr": ip.to_string(),
                    "scope": address_scope(ip)
                })
            })
            .collect();
        if family_v6.is_some() && addresses.is_empty() {
            continue;
        }
        let flags: Vec<&str> = IFF_NAMES
            .iter()
            .filter(|(bit, _)| iface.flags & bit != 0)
            .map(|(_, n)| *n)
            .collect();
        result.push(json!({
            "name": name,
            "index": iface.index.or_else(|| if_index(&name)),
            "mac": iface.mac,
            "flags": flags,
            "mtu": if_mtu(&name),
            "addresses": addresses
        }));
    }

    writeln!(io.stdout, "{}", json!({ "interfaces": result }))?;
    Ok(Status::ok())
}

// Mock DNS resolver for testing
#[cfg(test)]
pub struct MockResolver {
    pub records: ResolvedRecords,
    pub should_error: bool,
    pub error_message: String,
}

#[cfg(test)]
impl MockResolver {
    pub fn new(records: ResolvedRecords) -> Self {
        Self {
            records,
            should_error: false,
            error_message: String::new(),
        }
    }

    pub fn with_error(error_message: String) -> Self {
        Self {
            records: vec![],
            should_error: true,
            error_message,
        }
    }
}

#[cfg(test)]
impl DnsResolver for MockResolver {
    fn lookup(
        &self,
        _name: &str,
        _rtype: RecordType,
        _server: Option<SocketAddr>,
        _timeout: Duration,
    ) -> Result<ResolvedRecords> {
        if self.should_error {
            anyhow::bail!("{}", self.error_message);
        }
        Ok(self.records.clone())
    }
}

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("net", |u| Ok(Box::new(NetHandle::from_url(u)?)));
}

#[cfg(test)]
#[path = "neth_tests.rs"]
mod tests;
