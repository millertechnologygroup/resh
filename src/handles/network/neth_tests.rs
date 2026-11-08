//! Unit and dispatch tests for `net://`. Every network test talks only to
//! listeners and DNS servers this test opens on 127.0.0.1 / ::1.

use super::*;
use crate::core::registry::Args;
use std::net::{TcpListener, UdpSocket};
use std::os::fd::{FromRawFd, OwnedFd};

// --------------------------------------------------------------- helpers --

struct Out {
    status: Status,
    stdout: String,
    stderr: String,
    json: Value,
}

fn args_of(args: &[(&str, &str)]) -> Args {
    args.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn call_on(h: &NetHandle, verb: &str, args: &[(&str, &str)]) -> Out {
    let args = args_of(args);
    let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
    let mut io = IoStreams::new(&mut i, &mut o, &mut e);
    let status = h.call(verb, &args, &mut io).unwrap();
    let stdout = String::from_utf8(o).unwrap();
    Out {
        status,
        json: serde_json::from_str(&stdout).unwrap_or(Value::Null),
        stdout,
        stderr: String::from_utf8(e).unwrap(),
    }
}

fn handle(url: &str) -> NetHandle {
    NetHandle::from_url(&Url::parse(url).unwrap()).unwrap()
}

fn call(url: &str, verb: &str, args: &[(&str, &str)]) -> Out {
    call_on(&handle(url), verb, args)
}

fn code(o: &Out) -> i32 {
    o.status.exit_code()
}

/// Asserts a failure with exit `exit` and error code `error`.
fn assert_fail(o: &Out, exit: i32, error: &str) {
    assert_eq!(code(o), exit, "{}\n{}", o.stdout, o.stderr);
    assert_eq!(
        o.json["error"]["code"],
        format!("net.{error}"),
        "{}",
        o.stdout
    );
}

/// A port of 127.0.0.1 that refuses connections: bound (so no other test
/// can take it) but not listening.
struct Closed {
    port: u16,
    _fd: OwnedFd,
}

fn closed() -> Closed {
    let (fd, port) = bound_socket();
    Closed { port, _fd: fd }
}

/// A TCP socket bound to 127.0.0.1 on a free port.
fn bound_socket() -> (OwnedFd, u16) {
    // SAFETY: plain socket calls on a socket this function owns.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        assert!(fd >= 0);
        let owned = OwnedFd::from_raw_fd(fd);
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::LOCALHOST).to_be();
        let len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        assert_eq!(
            libc::bind(fd, &addr as *const _ as *const libc::sockaddr, len),
            0
        );
        let mut got: libc::sockaddr_in = std::mem::zeroed();
        let mut glen = len;
        libc::getsockname(fd, &mut got as *mut _ as *mut libc::sockaddr, &mut glen);
        (owned, u16::from_be(got.sin_port))
    }
}

/// A listener whose accept queue is full: further connects time out, like
/// a port behind a dropping firewall.
struct Filtered {
    port: u16,
    _listener: OwnedFd,
    _fill: Vec<TcpStream>,
}

fn filtered_port() -> Filtered {
    use std::os::fd::AsRawFd;
    let (owned, port) = bound_socket();
    // SAFETY: listen on the socket bound above.
    assert_eq!(unsafe { libc::listen(owned.as_raw_fd(), 0) }, 0);
    let target: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut fill = Vec::new();
    // Fill the queue until a connect no longer completes.
    for _ in 0..8 {
        match TcpStream::connect_timeout(&target, Duration::from_millis(200)) {
            Ok(s) => fill.push(s),
            Err(_) => break,
        }
    }
    Filtered {
        port,
        _listener: owned,
        _fill: fill,
    }
}

/// A listener that accepts every connection (and keeps it a moment).
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

// ------------------------------------------------------------------ help --

fn help_output(url: &str, verb: &str, args: &[(&str, &str)]) -> Option<String> {
    let h = handle(url);
    let args = args_of(args);
    let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
    let mut io = IoStreams::new(&mut i, &mut o, &mut e);
    let shown = h
        .check_and_display_help(verb, &args, &mut io)
        .unwrap()
        .is_some();
    shown.then(|| String::from_utf8(o).unwrap())
}

#[test]
fn in_url_help_renders_approved_help() {
    let all = help_output("net://--help", "help", &[]).unwrap();
    assert!(all.starts_with("Handle: net\n"), "{all}");
    let ping = help_output("net://--help", "help", &[("verb", "ping")]).unwrap();
    assert_ne!(all, ping);
    assert_eq!(help_output("net://x", "--help=ping", &[]).unwrap(), ping);
    assert!(help_output("net://my-hosts", "list", &[]).is_none());
}

#[test]
fn verb_args_match_help_usage() {
    for verb in NET_HELP.verbs {
        let usage = verb.detail.as_ref().unwrap().usage;
        let mut in_usage: Vec<&str> = usage
            .split(|c: char| c == '[' || c.is_whitespace())
            .filter_map(|w| w.split_once('=').map(|(k, _)| k))
            .filter(|k| !k.is_empty() && !k.contains(':'))
            .collect();
        in_usage.sort();
        let mut parsed = verb_args(verb.name).unwrap().to_vec();
        parsed.sort();
        assert_eq!(in_usage, parsed, "usage of {} disagrees", verb.name);
    }
    let mut registered: Vec<&str> = handle("net://x")
        .verbs()
        .iter()
        .copied()
        .filter(|v| verb_args(v).is_some())
        .collect();
    let mut helped: Vec<&str> = NET_HELP.verbs.iter().map(|v| v.name).collect();
    registered.sort();
    helped.sort();
    assert_eq!(registered, helped);
}

// --------------------------------------------------------- strict args --

#[test]
fn every_verb_refuses_unknown_arguments_before_acting() {
    let cases = [
        ("net://if", "list", "familly", "family"),
        ("net://localhost", "route.list", "tabel", "table"),
        ("net://example.test", "dns", "typ", "type"),
        ("net://127.0.0.1", "ping", "cout", "count"),
        ("net://127.0.0.1:1", "tcp_check", "retrys", "retries"),
        ("net://127.0.0.1", "scan", "prots", "ports"),
    ];
    for (url, verb, bad, good) in cases {
        let o = call(url, verb, &[(bad, "1")]);
        assert_fail(&o, 2, "invalid_argument");
        let detail = o.json["error"]["message"].as_str().unwrap();
        assert!(
            detail.contains(&format!("unknown argument: {bad} (did you mean `{good}`?)")),
            "{verb}: {detail}"
        );
        assert_eq!(o.json["verb"], verb);
        assert!(
            o.status
                .reason
                .as_deref()
                .unwrap()
                .starts_with(&format!("[net.invalid_argument] net {verb}: "))
        );
        // dry_run is refused too: no verb has a dry-run mode.
        assert_fail(
            &call(url, verb, &[("dry_run", "false")]),
            2,
            "invalid_argument",
        );
        // An unrelated name gets no suggestion.
        let o = call(url, verb, &[("zzzzzzzz", "1")]);
        assert!(!o.stdout.contains("did you mean"), "{}", o.stdout);
    }
    // Only the instant verb refuses timeout_ms.
    let o = call("net://if", "list", &[("timeout_ms", "100")]);
    assert_fail(&o, 2, "invalid_argument");
    assert!(o.stdout.contains("timeout_ms is not accepted"));
}

#[test]
fn unknown_verb_is_usage_error() {
    let o = call("net://if", "status", &[]);
    assert_eq!(code(&o), 2);
    assert!(o.status.reason.unwrap().contains("unknown verb"));
}

#[test]
fn option_shaped_or_missing_host_is_refused() {
    let resolver = Arc::new(MockResolver::new(vec![]));
    let h = NetHandle::with_resolver("-c".into(), resolver);
    for verb in ["ping", "tcp_check", "scan"] {
        let o = call_on(&h, verb, &[("port", "80")]);
        let o = if verb == "scan" {
            call_on(&h, verb, &[])
        } else {
            o
        };
        assert_fail(&o, 2, "invalid_argument");
        assert!(
            o.stdout.contains("could be read as an option"),
            "{}",
            o.stdout
        );
    }
    assert_fail(&call_on(&h, "dns", &[]), 2, "invalid_argument");
    for (verb, args) in [
        ("ping", &[("port", "80")][..]),
        ("tcp_check", &[("port", "80")][..]),
        ("scan", &[][..]),
    ] {
        let o = call("net://if", verb, args);
        assert_fail(&o, 2, "invalid_argument");
        assert!(o.stdout.contains("needs a host"), "{}", o.stdout);
    }
}

#[test]
fn suggest_handles_case_and_dashes() {
    assert_eq!(suggest("Timeout-MS", PING_ARGS), Some("timeout_ms"));
    assert_eq!(suggest("xyzzy", PING_ARGS), None);
}

// ------------------------------------------------------------------ list --

fn iface<'a>(o: &'a Out, name: &str) -> Option<&'a Value> {
    o.json["interfaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == name)
}

#[test]
fn list_reports_real_loopback_details() {
    let o = call("net://if", "list", &[]);
    assert_eq!(code(&o), 0, "{}", o.stderr);
    let lo = iface(&o, "lo").expect("lo listed");
    let flags: Vec<&str> = lo["flags"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    assert!(
        flags.contains(&"up") && flags.contains(&"loopback"),
        "{flags:?}"
    );
    assert!(lo["index"].as_u64().unwrap() >= 1);
    assert_eq!(lo["mac"], "00:00:00:00:00:00");
    assert!(lo["mtu"].as_u64().unwrap() > 0);
    assert!(
        lo["addresses"]
            .as_array()
            .unwrap()
            .contains(&json!({"family": "ipv4", "addr": "127.0.0.1", "scope": "host"}))
    );
    // Sorted by name, and the URL host does not matter.
    let names: Vec<&str> = o.json["interfaces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["name"].as_str().unwrap())
        .collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
    assert_eq!(code(&call("net://interfaces", "list", &[])), 0);
}

#[test]
fn list_family_filter() {
    for (family, want) in [("ipv4", "ipv4"), ("IPv6", "ipv6")] {
        let o = call("net://if", "list", &[("family", family)]);
        assert_eq!(code(&o), 0);
        for i in o.json["interfaces"].as_array().unwrap() {
            let addrs = i["addresses"].as_array().unwrap();
            assert!(!addrs.is_empty(), "{i}");
            assert!(addrs.iter().all(|a| a["family"] == want), "{i}");
        }
    }
    let all = call("net://if", "list", &[("family", "all")]);
    assert_eq!(all.json, call("net://if", "list", &[]).json);
    assert_fail(
        &call("net://if", "list", &[("family", "ipv5")]),
        2,
        "invalid_argument",
    );
}

#[test]
fn list_up_filter_uses_the_interface_state() {
    let up = call("net://if", "list", &[("up", "true")]);
    assert_eq!(code(&up), 0);
    // lo is up, so up=true keeps it (it used to mean "not loopback").
    assert!(iface(&up, "lo").is_some());
    for i in up.json["interfaces"].as_array().unwrap() {
        assert!(i["flags"].as_array().unwrap().contains(&json!("up")), "{i}");
    }
    let down = call("net://if", "list", &[("up", "no")]);
    assert_eq!(code(&down), 0);
    assert!(iface(&down, "lo").is_none());
    for i in down.json["interfaces"].as_array().unwrap() {
        assert!(
            !i["flags"].as_array().unwrap().contains(&json!("up")),
            "{i}"
        );
    }
    let o = call("net://if", "list", &[("up", "maybe")]);
    assert_fail(&o, 2, "invalid_argument");
    assert!(o.stdout.contains("invalid value for up"));
}

#[test]
fn address_scopes() {
    let scope = |s: &str| address_scope(&s.parse().unwrap());
    assert_eq!(scope("127.0.0.1"), "host");
    assert_eq!(scope("169.254.1.1"), "link");
    assert_eq!(scope("192.0.2.1"), "global");
    assert_eq!(scope("::1"), "host");
    assert_eq!(scope("fe80::1"), "link");
    assert_eq!(scope("2001:db8::1"), "global");
}

// ------------------------------------------------------------ route.list --

#[test]
fn normalize_ip_route_output() {
    let out = r#"[
      {"dst":"default","gateway":"192.0.2.1","dev":"eth0","protocol":"dhcp","metric":100,"flags":[]},
      {"dst":"192.0.2.0/24","dev":"eth0","protocol":"kernel","scope":"link","prefsrc":"192.0.2.10","flags":["linkdown"]},
      {"type":"local","dst":"127.0.0.1","dev":"lo","table":"local","protocol":"kernel","scope":"host","flags":[]},
      {"dst":"10.0.0.0/8","table":"100","nexthops":[{"gateway":"192.0.2.2","dev":"eth1"}],"flags":[]},
      {"type":"unreachable","dst":"203.0.113.0/24","flags":[]}
    ]"#;
    let routes = normalize_ip_routes(out, false, "all").unwrap();
    assert_eq!(
        routes[0],
        json!({"family":"ipv4","dst":"default","gateway":"192.0.2.1","iface":"eth0",
               "metric":100,"table":"main","protocol":"dhcp","scope":null,"flags":["gateway"]})
    );
    assert_eq!(routes[1]["flags"], json!(["link", "linkdown"]));
    assert_eq!(routes[1]["metric"], 0);
    assert_eq!(routes[2]["table"], "local");
    assert_eq!(routes[2]["flags"], json!(["host"]));
    assert_eq!(routes[3]["gateway"], "192.0.2.2");
    assert_eq!(routes[3]["iface"], "eth1");
    assert_eq!(routes[3]["table"], "100");
    assert_eq!(routes[4]["iface"], Value::Null);
    // One listed table is not named by ip: the requested one is reported.
    let local = normalize_ip_routes(
        r#"[{"dst":"127.0.0.1","dev":"lo","scope":"host"}]"#,
        false,
        "local",
    )
    .unwrap();
    assert_eq!(local[0]["table"], "local");
    let v6 =
        normalize_ip_routes(r#"[{"dst":"::1","dev":"lo","metric":256}]"#, true, "main").unwrap();
    assert_eq!(v6[0]["family"], "ipv6");
    assert_eq!(
        normalize_ip_routes("  \n", false, "main").unwrap(),
        Vec::<Value>::new()
    );
    assert!(normalize_ip_routes("not json", false, "main").is_err());
    assert!(normalize_ip_routes("{}", false, "main").is_err());
}

#[test]
fn parse_proc_route_tables() {
    let v4 = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
              eth0\t00000000\t010200C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
              eth0\t000200C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n\
              eth0\t0A0200C0\t00000000\t0005\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n";
    let r = parse_proc_net_route(v4).unwrap();
    assert_eq!(
        r[0],
        json!({"family":"ipv4","dst":"default","gateway":"192.0.2.1","iface":"eth0","metric":100,
               "table":"main","protocol":null,"scope":null,"flags":["up","gateway"]})
    );
    assert_eq!(r[1]["dst"], "192.0.2.0/24");
    assert_eq!(r[1]["gateway"], Value::Null);
    assert_eq!(r[2]["dst"], "192.0.2.10");
    assert_eq!(r[2]["flags"], json!(["up", "host"]));
    assert!(parse_proc_net_route("h\neth0 zz 0 0 0 0 0 0 0 0 0\n").is_err());

    let v6 = "00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 00000001       lo\n\
              fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n\
              00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n";
    let r = parse_proc_net_ipv6_route(v6).unwrap();
    assert_eq!(r[0]["dst"], "::1");
    assert_eq!(r[1]["dst"], "fe80::/64");
    assert_eq!(r[1]["metric"], 256);
    assert_eq!(r[2]["dst"], "default");
    assert_eq!(r[2]["gateway"], "fe80::1");
    assert_eq!(r[2]["flags"], json!(["up", "gateway"]));
    assert_eq!(r[2]["table"], Value::Null);
    assert!(parse_proc_net_ipv6_route("zz 0 0 0 0 0 0 0 0 eth0\n").is_err());
}

#[test]
fn route_list_on_this_host() {
    for family in ["ipv4", "ipv6", "all"] {
        let o = call("net://localhost", "route.list", &[("family", family)]);
        assert_eq!(code(&o), 0, "{family}: {}", o.stderr);
        for r in o.json.as_array().unwrap() {
            if family != "all" {
                assert_eq!(r["family"], family);
            }
            for k in [
                "dst", "family", "gateway", "iface", "metric", "protocol", "scope", "table",
                "flags",
            ] {
                assert!(r.get(k).is_some(), "{k} missing in {r}");
            }
        }
    }
    // The local table holds the loopback address.
    let o = call("net://localhost", "route.list", &[("table", "local")]);
    assert_eq!(code(&o), 0, "{}", o.stderr);
    assert!(
        o.json
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["dst"] == "127.0.0.1" && r["table"] == "local"),
        "{}",
        o.stdout
    );
    let o = call(
        "net://localhost",
        "route.list",
        &[("table", "254"), ("timeout_ms", "5000")],
    );
    assert_eq!(code(&o), 0, "{}", o.stderr);
}

#[test]
fn route_list_argument_errors() {
    for args in [
        [("family", "ipv5")],
        [("table", "main; rm")],
        [("timeout_ms", "0")],
        [("timeout_ms", "soon")],
    ] {
        let o = call("net://localhost", "route.list", &args);
        assert_fail(&o, 2, "invalid_argument");
        assert_eq!(o.json["backend"], "net");
    }
}

// ------------------------------------------------------------------- dns --

/// A DNS server on 127.0.0.1 that answers from a fixed zone; `silent`
/// never answers.
fn dns_server(silent: bool) -> u16 {
    use trust_dns_resolver::proto::op::{Message, MessageType, ResponseCode};
    use trust_dns_resolver::proto::rr::{Name, Record, rdata};
    use trust_dns_resolver::proto::serialize::binary::BinDecodable;
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut buf = [0u8; 1500];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf) else {
                return;
            };
            if silent {
                continue;
            }
            let Ok(req) = Message::from_bytes(&buf[..n]) else {
                continue;
            };
            let mut resp = Message::new();
            resp.set_id(req.id())
                .set_message_type(MessageType::Response)
                .set_recursion_desired(true)
                .set_recursion_available(true);
            let q = req.queries()[0].clone();
            let name = q.name().clone();
            let n = |s: &str| Name::from_ascii(s).unwrap();
            let data: Vec<RData> = match (name.to_ascii().as_str(), q.query_type()) {
                ("host.test.", TrustDnsRecordType::A) => {
                    vec![RData::A(rdata::A("192.0.2.7".parse().unwrap()))]
                }
                ("host.test.", TrustDnsRecordType::AAAA) => {
                    vec![RData::AAAA(rdata::AAAA("2001:db8::7".parse().unwrap()))]
                }
                ("host.test.", TrustDnsRecordType::MX) => {
                    vec![RData::MX(rdata::MX::new(10, n("mx.host.test.")))]
                }
                ("host.test.", TrustDnsRecordType::TXT) => {
                    vec![RData::TXT(rdata::TXT::new(vec![
                        "v=1".into(),
                        " ok".into(),
                    ]))]
                }
                ("host.test.", TrustDnsRecordType::NS) => {
                    vec![RData::NS(rdata::NS(n("ns1.test.")))]
                }
                ("alias.test.", TrustDnsRecordType::CNAME) => {
                    vec![RData::CNAME(rdata::CNAME(n("host.test.")))]
                }
                ("_sip._tcp.host.test.", TrustDnsRecordType::SRV) => {
                    vec![RData::SRV(rdata::SRV::new(1, 2, 5060, n("sip.host.test.")))]
                }
                ("7.2.0.192.in-addr.arpa.", TrustDnsRecordType::PTR) => {
                    vec![RData::PTR(rdata::PTR(n("host.test.")))]
                }
                _ => vec![],
            };
            if data.is_empty() {
                resp.set_response_code(ResponseCode::NXDomain);
            }
            resp.add_query(q);
            for d in data {
                resp.add_answer(Record::from_rdata(name.clone(), 123, d));
            }
            if let Ok(bytes) = resp.to_vec() {
                sock.send_to(&bytes, peer).ok();
            }
        }
    });
    port
}

fn dns(name: &str, port: u16, args: &[(&str, &str)]) -> Out {
    let p = port.to_string();
    let mut all = vec![("server", "127.0.0.1"), ("port", p.as_str())];
    all.extend_from_slice(args);
    call(&format!("net://{name}"), "dns", &all)
}

#[test]
fn dns_every_record_type_against_a_local_server() {
    let port = dns_server(false);
    let server = format!("127.0.0.1:{port}");
    let o = dns("host.test", port, &[]);
    assert_eq!(code(&o), 0, "{}", o.stdout);
    assert_eq!(
        o.json,
        json!({"query":"host.test","rtype":"A","server":server,
               "records":[{"name":"host.test","ttl":123,"data":"192.0.2.7"}]})
    );
    let o = dns("host.test", port, &[("type", "aaaa")]);
    assert_eq!(o.json["records"][0]["data"], "2001:db8::7");
    assert_eq!(o.json["records"][0]["ttl"], 123);
    let o = dns("host.test", port, &[("type", "MX")]);
    assert_eq!(
        o.json["records"][0],
        json!({"name":"host.test","ttl":123,"data":{"priority":10,"exchange":"mx.host.test."}})
    );
    let o = dns("host.test", port, &[("type", "TXT")]);
    assert_eq!(o.json["records"][0]["data"], "v=1 ok");
    assert_eq!(o.json["records"][0]["ttl"], 123);
    let o = dns("host.test", port, &[("type", "NS")]);
    assert_eq!(o.json["records"][0]["data"], "ns1.test.");
    assert_eq!(o.json["records"][0]["name"], "host.test.");
    let o = dns("alias.test", port, &[("type", "CNAME")]);
    assert_eq!(o.json["records"][0]["data"], "host.test.");
    let o = dns("_sip._tcp.host.test", port, &[("type", "SRV")]);
    assert_eq!(
        o.json["records"][0]["data"],
        json!({"priority":1,"weight":2,"port":5060,"target":"sip.host.test."})
    );
    let o = dns("192.0.2.7", port, &[("type", "PTR")]);
    assert_eq!(code(&o), 0, "{}", o.stdout);
    assert_eq!(
        o.json["records"][0],
        json!({"name":"192.0.2.7","ttl":123,"data":"host.test."})
    );
}

#[test]
fn dns_failures() {
    let port = dns_server(false);
    let o = dns("missing.test", port, &[]);
    assert_fail(&o, 1, "lookup_failed");
    assert_eq!(o.json["query"], "missing.test");
    assert_eq!(o.json["rtype"], "A");

    let silent = dns_server(true);
    let start = Instant::now();
    let o = dns("host.test", silent, &[("timeout_ms", "300")]);
    assert_fail(&o, 124, "timeout");
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "{:?}",
        start.elapsed()
    );
}

#[test]
fn dns_argument_errors() {
    let cases: &[(&str, &[(&str, &str)], &str)] = &[
        ("net://host.test", &[("type", "FOO")], "invalid_argument"),
        (
            "net://host.test",
            &[("timeout_ms", "0")],
            "invalid_argument",
        ),
        (
            "net://host.test",
            &[("timeout_ms", "-1")],
            "invalid_argument",
        ),
        (
            "net://host.test",
            &[("server", "not-an-ip")],
            "invalid_argument",
        ),
        (
            "net://host.test",
            &[("server", "127.0.0.1"), ("port", "0")],
            "invalid_argument",
        ),
        (
            "net://host.test",
            &[("server", "127.0.0.1"), ("port", "x")],
            "invalid_argument",
        ),
        // port= without server= would be silently unused.
        ("net://host.test", &[("port", "5353")], "invalid_argument"),
        ("net://host.test", &[("type", "PTR")], "invalid_argument"),
        ("net://if", &[], "invalid_argument"),
    ];
    for (url, args, err) in cases {
        let o = call(url, "dns", args);
        assert_fail(&o, 2, err);
    }
}

#[test]
fn test_dns_invalid_query_name() {
    let h = NetHandle::with_resolver("".into(), Arc::new(MockResolver::new(vec![])));
    let o = call_on(&h, "dns", &[]);
    assert_fail(&o, 2, "invalid_argument");
}

#[test]
fn test_dns_invalid_record_type() {
    let h = NetHandle::with_resolver("example.com".into(), Arc::new(MockResolver::new(vec![])));
    let o = call_on(&h, "dns", &[("type", "FOO")]);
    assert_fail(&o, 2, "invalid_argument");
    assert!(o.stdout.contains("Unknown record type: FOO"));
}

#[test]
fn test_dns_successful_mock_records() {
    let records = vec![
        ResolvedRecord {
            name: "example.com.".into(),
            ttl: 3600,
            kind: ResolvedKind::MX {
                priority: 10,
                exchange: "mail.example.com.".into(),
            },
        },
        ResolvedRecord {
            name: "_sip._tcp.example.com.".into(),
            ttl: 300,
            kind: ResolvedKind::SRV {
                priority: 10,
                weight: 20,
                port: 5060,
                target: "sip.example.com.".into(),
            },
        },
    ];
    let h = NetHandle::with_resolver("example.com".into(), Arc::new(MockResolver::new(records)));
    let o = call_on(&h, "dns", &[("type", "MX")]);
    assert_eq!(code(&o), 0);
    assert_eq!(o.json["server"], "system");
    assert_eq!(o.json["records"][0]["data"]["priority"], 10);
    assert_eq!(o.json["records"][1]["data"]["port"], 5060);
}

#[test]
fn test_dns_lookup_failed() {
    let h = NetHandle::with_resolver(
        "nonexistent.example.com".into(),
        Arc::new(MockResolver::with_error("NXDOMAIN".into())),
    );
    let o = call_on(&h, "dns", &[]);
    assert_fail(&o, 1, "lookup_failed");
    assert!(
        o.json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("NXDOMAIN")
    );
}

#[test]
fn test_record_type_parsing() {
    assert_eq!(RecordType::from_str("A").unwrap(), RecordType::A);
    assert_eq!(RecordType::from_str("aaaa").unwrap(), RecordType::AAAA);
    assert_eq!(RecordType::from_str("MX").unwrap(), RecordType::MX);
    assert_eq!(RecordType::from_str("txt").unwrap(), RecordType::TXT);
    assert!(RecordType::from_str("UNKNOWN").is_err());
}

#[test]
fn test_url_domain_extraction() {
    assert_eq!(
        handle("net://example.com.dns")
            .extract_dns_query_name()
            .unwrap(),
        "example.com"
    );
    assert_eq!(
        handle("net://8.8.8.8.dns")
            .extract_dns_query_name()
            .unwrap(),
        "8.8.8.8"
    );
    assert_eq!(handle("net://[::1]").host.as_deref(), Some("::1"));
}

// ------------------------------------------------------------------ ping --

const IPUTILS_OK: &str = "PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.040 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.052 ms

--- 127.0.0.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 0.040/0.046/0.052/0.006 ms
";

const IPUTILS_UNREACHABLE: &str = "PING 192.0.2.9 (192.0.2.9) 56(84) bytes of data.
From 192.0.2.1 icmp_seq=1 Destination Host Unreachable
From 192.0.2.1 icmp_seq=2 Destination Host Unreachable
From 192.0.2.1 icmp_seq=3 Destination Host Unreachable

--- 192.0.2.9 ping statistics ---
3 packets transmitted, 0 received, +3 errors, 100% packet loss, time 2040ms
";

const BUSYBOX_OK: &str = "PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: seq=0 ttl=64 time=0.051 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 0.051/0.051/0.051 ms
";

#[test]
fn ping_output_parsing() {
    let r = parse_ping_output(IPUTILS_OK).unwrap();
    assert_eq!((r.sent, r.received), (2, 2));
    assert_eq!(r.avg_rtt_ms, Some(0.046));
    assert_eq!(r.loss(), 0.0);
    // ICMP error lines are not replies.
    let r = parse_ping_output(IPUTILS_UNREACHABLE).unwrap();
    assert_eq!((r.sent, r.received), (3, 0));
    assert_eq!(r.avg_rtt_ms, None);
    assert_eq!(r.loss(), 1.0);
    let r = parse_ping_output(BUSYBOX_OK).unwrap();
    assert_eq!((r.sent, r.received), (1, 1));
    assert_eq!(r.avg_rtt_ms, Some(0.051));
    assert!(parse_ping_output("ping: socket: Operation not permitted\n").is_none());
    assert!(is_resolve_error(
        "ping: nohost.test: Name or service not known"
    ));
    assert!(is_resolve_error("ping: bad address 'x'"));
    assert!(!is_resolve_error("ping: connect: Network is unreachable"));
}

#[test]
fn ping_loopback_with_every_option() {
    let o = call(
        "net://127.0.0.1",
        "ping",
        &[("count", "2"), ("timeout_ms", "3000")],
    );
    assert_eq!(code(&o), 0, "{}\n{}", o.stdout, o.stderr);
    assert_eq!(o.json["backend"], "system_ping");
    assert_eq!(o.json["sent"], 2);
    assert_eq!(o.json["received"], 2);
    assert_eq!(o.json["reachable"], true);
    assert_eq!(o.json["loss"], 0.0);
    assert!(o.json["avg_rtt_ms"].as_f64().is_some());
    assert_eq!(o.json["port"], 80);

    let o = call(
        "net://127.0.0.1:8080",
        "ping",
        &[("count", "1"), ("family", "ipv4"), ("raw", "yes")],
    );
    assert_eq!(code(&o), 0, "{}", o.stderr);
    assert_eq!(o.json["port"], 8080);
    assert!(o.stderr.contains("Raw ping output"), "{}", o.stderr);
    assert!(o.stderr.contains("1 packets transmitted"), "{}", o.stderr);

    let o = call(
        "net://127.0.0.1",
        "ping",
        &[("count", "1"), ("port", "443")],
    );
    assert_eq!(o.json["port"], 443);
}

#[test]
fn ping_ipv6_loopback() {
    let o = call("net://[::1]", "ping", &[("count", "1"), ("family", "ipv6")]);
    // Hosts without IPv6 make ping fall back or fail; when IPv6 works the
    // reply comes from the system ping.
    if code(&o) == 0 {
        assert_eq!(o.json["host"], "::1");
        assert_eq!(o.json["received"], 1);
    }
}

#[test]
fn ping_argument_errors() {
    for args in [
        [("count", "0")],
        [("count", "x")],
        [("timeout_ms", "99")],
        [("timeout_ms", "")],
        [("port", "0")],
        [("port", "70000")],
        [("family", "ipv5")],
        [("raw", "maybe")],
    ] {
        let o = call("net://127.0.0.1", "ping", &args);
        assert_fail(&o, 2, "invalid_argument");
    }
}

#[test]
fn ping_tcp_fallback_counts_connects() {
    let deadline = Instant::now() + Duration::from_secs(3);
    let open = open_port();
    let r = tcp_ping("127.0.0.1", open, 3, 3000, "auto", deadline).unwrap();
    assert_eq!((r.sent, r.received), (3, 3));
    assert!(r.avg_rtt_ms.is_some());
    let c = closed();
    let r = tcp_ping("127.0.0.1", c.port, 2, 3000, "auto", deadline).unwrap();
    assert_eq!((r.sent, r.received), (2, 0));
    assert_eq!(r.avg_rtt_ms, None);
    // IPv6 literals work now (only IPv4 literals did).
    if let Ok(l) = TcpListener::bind("[::1]:0") {
        let p = l.local_addr().unwrap().port();
        let r = tcp_ping("::1", p, 1, 1000, "ipv6", deadline).unwrap();
        assert_eq!(r.received, 1);
    }
    // A family the host has no address of.
    assert!(tcp_ping("127.0.0.1", open, 1, 1000, "ipv6", deadline).is_err());
    // The whole fallback stops at the deadline.
    let f = filtered_port();
    let start = Instant::now();
    // 30 probes of 400 ms would take 12 s; the deadline ends them at
    // 400 ms (the bound leaves seconds of slack for a busy machine).
    let r = tcp_ping(
        "127.0.0.1",
        f.port,
        30,
        400,
        "auto",
        start + Duration::from_millis(400),
    )
    .unwrap();
    assert_eq!(r.received, 0);
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
}

// ------------------------------------------------------------- tcp_check --

#[test]
fn tcp_check_open_closed_and_port_argument() {
    let open = open_port();
    let o = call(&format!("net://127.0.0.1:{open}"), "tcp_check", &[]);
    assert_eq!(code(&o), 0, "{}", o.stdout);
    assert_eq!(o.json["ok"], true);
    assert_eq!(o.json["attempts"], 1);
    assert_eq!(o.json["port"], open);
    assert_eq!(o.json["tls_checked"], false);
    assert!(o.json["latency_ms"].is_u64());

    // port= chooses the port connected to (it used to be only reported).
    let closed_guard = closed();
    let closed = closed_guard.port;
    let p = open.to_string();
    let o = call(
        &format!("net://127.0.0.1:{closed}"),
        "tcp_check",
        &[("port", &p)],
    );
    assert_eq!(code(&o), 0, "{}", o.stdout);
    assert_eq!(o.json["port"], open);
    let o = call("net://127.0.0.1", "tcp_check", &[("port", &p)]);
    assert_eq!(code(&o), 0, "{}", o.stdout);
    let o = call("net://localhost", "tcp_check", &[("port", &p)]);
    assert_eq!(code(&o), 0, "{}", o.stdout);

    let start = Instant::now();
    let o = call(
        &format!("net://127.0.0.1:{closed}"),
        "tcp_check",
        &[
            ("retries", "3"),
            ("backoff_ms", "100"),
            ("timeout_ms", "500"),
        ],
    );
    assert_eq!(code(&o), 1, "{}", o.stdout);
    assert_eq!(o.json["ok"], false);
    assert_eq!(o.json["attempts"], 3);
    assert!(
        o.json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("refused"),
        "{}",
        o.stdout
    );
    assert!(o.json.get("latency_ms").is_none());
    assert!(start.elapsed() >= Duration::from_millis(200));
}

#[test]
fn tcp_check_timeout_exits_124() {
    let f = filtered_port();
    let start = Instant::now();
    let o = call(
        &format!("net://127.0.0.1:{}", f.port),
        "tcp_check",
        &[("timeout_ms", "300"), ("retries", "2")],
    );
    assert_eq!(code(&o), 124, "{}", o.stdout);
    assert_eq!(o.json["ok"], false);
    assert!(start.elapsed() < Duration::from_secs(3));
}

#[test]
fn tcp_check_argument_errors() {
    let cases: &[(&str, &[(&str, &str)])] = &[
        ("net://127.0.0.1", &[]),
        ("net://127.0.0.1:80", &[("port", "0")]),
        ("net://127.0.0.1:80", &[("port", "http")]),
        ("net://127.0.0.1:80", &[("timeout_ms", "0")]),
        ("net://127.0.0.1:80", &[("retries", "0")]),
        ("net://127.0.0.1:80", &[("backoff_ms", "-5")]),
        ("net://127.0.0.1:80", &[("expect_tls", "maybe")]),
    ];
    for (url, args) in cases {
        let o = call(url, "tcp_check", args);
        assert_fail(&o, 2, "invalid_argument");
    }
}

/// A CA and a server certificate for `sans`, signed by it.
fn certs(sans: &[&str]) -> (String, Vec<u8>, Vec<u8>) {
    let mut ca_params = rcgen::CertificateParams::new(vec![]);
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "resh test CA");
    let ca = rcgen::Certificate::from_params(ca_params).unwrap();
    let leaf = rcgen::Certificate::from_params(rcgen::CertificateParams::new(
        sans.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    ))
    .unwrap();
    (
        ca.serialize_pem().unwrap(),
        leaf.serialize_der_with_signer(&ca).unwrap(),
        leaf.serialize_private_key_der(),
    )
}

/// A TLS server on 127.0.0.1 for `sans`; returns its port and CA PEM.
fn tls_server(sans: &[&str]) -> (u16, String) {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let (ca_pem, leaf, key) = certs(sans);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(leaf)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
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
                conn.complete_io(&mut s).ok();
            });
        }
    });
    (port, ca_pem)
}

/// A server that answers with `banner` and never speaks TLS.
fn plain_server(banner: &'static [u8]) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            thread::spawn(move || {
                use std::io::Write as _;
                s.write_all(banner).ok();
                thread::sleep(Duration::from_secs(2));
            });
        }
    });
    port
}

fn tls_handle(url: &str, ca_pem: &str, dir: &Path) -> NetHandle {
    let ca = dir.join("ca.pem");
    std::fs::write(&ca, ca_pem).unwrap();
    let mut h = handle(url);
    h.ca_file = Some(ca);
    h
}

#[test]
fn tcp_check_ca_file_adds_a_private_ca() {
    let dir = tempfile::tempdir().unwrap();
    let (port, ca) = tls_server(&["127.0.0.1"]);
    let right = dir.path().join("right.pem");
    std::fs::write(&right, &ca).unwrap();
    let (other_ca, _, _) = certs(&["x"]);
    let other = dir.path().join("other.pem");
    std::fs::write(&other, &other_ca).unwrap();
    // The base trust (system bundle stand-in) does not know the server's CA.
    let base_dir = tempfile::tempdir().unwrap();
    let h = tls_handle(
        &format!("net://127.0.0.1:{port}"),
        &other_ca,
        base_dir.path(),
    );
    let r = right.to_str().unwrap();
    let o = call_on(&h, "tcp_check", &[("expect_tls", "true"), ("ca_file", r)]);
    assert_eq!(code(&o), 0, "{}", o.stdout);
    assert_eq!(o.json["tls_checked"], true);
    // Without it, or with another CA, verification fails.
    let o = call_on(&h, "tcp_check", &[("expect_tls", "true")]);
    assert_fail(&o, 1, "tls_failed");
    let o = call_on(
        &h,
        "tcp_check",
        &[("expect_tls", "true"), ("ca_file", other.to_str().unwrap())],
    );
    assert_fail(&o, 1, "tls_failed");
    // Refusals (exit 2), before connecting.
    let o = call_on(&h, "tcp_check", &[("ca_file", r)]);
    assert_fail(&o, 2, "invalid_argument");
    assert!(o.stdout.contains("only used with expect_tls=true"));
    let missing = dir.path().join("missing.pem");
    let empty = dir.path().join("empty.pem");
    std::fs::write(&empty, "not a certificate\n").unwrap();
    for f in [missing.to_str().unwrap(), empty.to_str().unwrap(), ""] {
        let o = call_on(&h, "tcp_check", &[("expect_tls", "true"), ("ca_file", f)]);
        assert_fail(&o, 2, "invalid_argument");
    }
}

#[test]
fn tcp_check_expect_tls() {
    let dir = tempfile::tempdir().unwrap();
    let (port, ca) = tls_server(&["127.0.0.1", "localhost"]);

    // A verified handshake by IP address and by name.
    for host in ["127.0.0.1", "localhost"] {
        let h = tls_handle(&format!("net://{host}:{port}"), &ca, dir.path());
        let o = call_on(&h, "tcp_check", &[("expect_tls", "true")]);
        assert_eq!(code(&o), 0, "{host}: {}", o.stdout);
        assert_eq!(o.json["ok"], true);
        assert_eq!(o.json["tls_checked"], true);
    }
    // expect_tls=false does not handshake.
    let h = tls_handle(&format!("net://127.0.0.1:{port}"), &ca, dir.path());
    let o = call_on(&h, "tcp_check", &[("expect_tls", "off")]);
    assert_eq!(o.json["tls_checked"], false);

    // Not issued for this name.
    let (other, other_ca) = tls_server(&["other.example"]);
    let h = tls_handle(&format!("net://127.0.0.1:{other}"), &other_ca, dir.path());
    let o = call_on(&h, "tcp_check", &[("expect_tls", "true")]);
    assert_eq!(code(&o), 1, "{}", o.stdout);
    assert_eq!(o.json["tls_checked"], true);
    assert!(
        o.json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("TLS handshake failed"),
        "{}",
        o.stdout
    );

    // Signed by a CA that is not trusted.
    let (unrelated_ca, _, _) = certs(&["x"]);
    let h = tls_handle(
        &format!("net://127.0.0.1:{port}"),
        &unrelated_ca,
        dir.path(),
    );
    let o = call_on(&h, "tcp_check", &[("expect_tls", "true")]);
    assert_eq!(code(&o), 1, "{}", o.stdout);
    assert!(
        o.json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("TLS handshake failed")
    );

    // A port that speaks another protocol.
    let ssh = plain_server(b"SSH-2.0-OpenSSH_9.6\r\n");
    let h = tls_handle(&format!("net://127.0.0.1:{ssh}"), &ca, dir.path());
    let o = call_on(&h, "tcp_check", &[("expect_tls", "1")]);
    assert_eq!(code(&o), 1, "{}", o.stdout);
    assert_eq!(o.json["ok"], false);

    // A port that never answers the handshake: outcome unknown.
    let quiet = plain_server(b"");
    let h = tls_handle(&format!("net://127.0.0.1:{quiet}"), &ca, dir.path());
    let start = Instant::now();
    let o = call_on(
        &h,
        "tcp_check",
        &[("expect_tls", "true"), ("timeout_ms", "300")],
    );
    assert_eq!(code(&o), 124, "{}", o.stdout);
    assert!(start.elapsed() < Duration::from_secs(2));

    // An unreadable CA bundle fails before connecting.
    let mut h = handle(&format!("net://127.0.0.1:{port}"));
    h.ca_file = Some(dir.path().join("missing.pem"));
    let o = call_on(&h, "tcp_check", &[("expect_tls", "true")]);
    assert_fail(&o, 1, "tls_failed");
    std::fs::write(dir.path().join("empty.pem"), "").unwrap();
    h.ca_file = Some(dir.path().join("empty.pem"));
    assert_fail(
        &call_on(&h, "tcp_check", &[("expect_tls", "true")]),
        1,
        "tls_failed",
    );
}

// ------------------------------------------------------------------ scan --

fn states(o: &Out) -> Vec<(u64, String)> {
    o.json["ports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["port"].as_u64().unwrap(),
                p["state"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn scan_reports_open_closed_and_timeout_in_order() {
    let open = open_port();
    let closed_guard = closed();
    let closed = closed_guard.port;
    let f = filtered_port();
    let ports = format!("{closed},{open},{},{open}", f.port);
    for concurrency in ["1", "4"] {
        let o = call(
            "net://127.0.0.1",
            "scan",
            &[
                ("ports", &ports),
                ("timeout_ms", "300"),
                ("concurrency", concurrency),
            ],
        );
        assert_eq!(code(&o), 0, "{}", o.stdout);
        // Duplicates are scanned once; the order is kept.
        assert_eq!(
            states(&o),
            vec![
                (closed as u64, "closed".to_string()),
                (open as u64, "open".to_string()),
                (f.port as u64, "timeout".to_string()),
            ]
        );
        assert_eq!(o.json["ports"][0]["error"], "connection refused");
        assert_eq!(o.json["target"], "127.0.0.1");
        assert_eq!(o.json["protocol"], "tcp");
        assert_eq!(o.json["scan"]["timeout_ms"], 300);
        assert_eq!(
            o.json["scan"]["concurrency"],
            concurrency.parse::<u64>().unwrap()
        );
        assert!(o.json["scan"]["started_at"].is_string());
    }
}

#[test]
fn scan_ranges_host_override_and_clamping() {
    let open = open_port();
    let range = format!("{}-{}", open, open as u32 + 2);
    let o = call(
        "net://if",
        "scan",
        &[
            ("host", "localhost"),
            ("ports", &range),
            ("concurrency", "1000"),
        ],
    );
    assert_eq!(code(&o), 0, "{}", o.stdout);
    assert_eq!(o.json["target"], "localhost");
    assert_eq!(o.json["ports"].as_array().unwrap().len(), 3);
    assert_eq!(o.json["ports"][0]["state"], "open");
    assert_eq!(o.json["scan"]["concurrency"], 256);
    let o = call(
        "net://127.0.0.1",
        "scan",
        &[("ports", "1"), ("concurrency", "0")],
    );
    assert_eq!(o.json["scan"]["concurrency"], 1);
    // Defaults.
    let o = call("net://127.0.0.1", "scan", &[]);
    assert_eq!(code(&o), 0);
    assert_eq!(
        states(&o).iter().map(|s| s.0).collect::<Vec<_>>(),
        vec![80, 443]
    );
    assert_eq!(o.json["scan"]["timeout_ms"], 500);
    assert_eq!(o.json["scan"]["concurrency"], 32);
}

#[test]
fn scan_with_every_port_failing_exits_1() {
    // The kernel refuses TCP to the broadcast address without sending.
    let o = call("net://255.255.255.255", "scan", &[("ports", "80,81")]);
    assert_eq!(code(&o), 1, "{}", o.stdout);
    assert!(states(&o).iter().all(|s| s.1 == "error"), "{}", o.stdout);
}

#[test]
fn scan_argument_errors() {
    for args in [
        vec![("ports", "0")],
        vec![("ports", "70000")],
        vec![("ports", "http")],
        vec![("ports", "90-80")],
        vec![("ports", "1-2-3")],
        vec![("ports", ",")],
        vec![("ports", "1-5000")],
        vec![("protocol", "udp")],
        vec![("timeout_ms", "0")],
        vec![("timeout_ms", "x")],
        vec![("concurrency", "many")],
        vec![("host", "")],
        vec![("host", "-p")],
    ] {
        let o = call("net://127.0.0.1", "scan", &args);
        assert_fail(&o, 2, "invalid_argument");
    }
}

#[test]
fn port_list_parsing() {
    assert_eq!(
        parse_ports("80, 443,8000-8002").unwrap(),
        vec![80, 443, 8000, 8001, 8002]
    );
    assert_eq!(parse_ports("22,22,21-23").unwrap(), vec![22, 21, 23]);
    assert_eq!(parse_ports("1-4096").unwrap().len(), 4096);
    assert!(parse_ports("1-4097").is_err());
    assert!(parse_ports("1-65535").is_err());
}

#[test]
fn error_codes_are_valid_and_documented() {
    let doc = include_str!("../../../docs/Network_RemoteOperations/net.md");
    for code in ERROR_CODES {
        let full = format!("net.{code}");
        assert!(crate::core::status::is_valid_error_code(&full), "{full}");
        assert!(doc.contains(&format!("`{full}`")), "{full} not documented");
    }
}
