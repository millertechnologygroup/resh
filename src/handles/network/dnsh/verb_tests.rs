//! Dispatch tests for lookup, resolve, trace and zone.fetch through
//! `Handle::call`, against the fake servers in `test_server.rs`.

use super::test_server::*;
use super::*;
use std::net::Ipv4Addr;
use std::time::Instant;
use trust_dns_proto::rr::{Name, Record, RecordType};

struct Run {
    status: Status,
    json: Option<Value>,
    stdout: String,
}

impl Run {
    fn code(&self) -> i32 {
        self.status.exit_code()
    }
    fn json(&self) -> &Value {
        self.json
            .as_ref()
            .unwrap_or_else(|| panic!("no JSON: {}", self.stdout))
    }
    fn error_code(&self) -> String {
        self.json()["error"]["code"]
            .as_str()
            .unwrap_or("")
            .to_string()
    }
    /// The `[code]` of a usage error (no JSON printed).
    fn reason(&self) -> String {
        self.status.reason.clone().unwrap_or_default()
    }
}

fn call(verb: &str, kv: &[(&str, &str)]) -> Run {
    let h = DnsHandle::from_url(&Url::parse("dns://").unwrap()).unwrap();
    let args: Args = kv
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
    let status = {
        let mut io = IoStreams::new(&mut i, &mut o, &mut e);
        h.call(verb, &args, &mut io).unwrap()
    };
    assert!(e.is_empty(), "the handle wrote stderr itself");
    let stdout = String::from_utf8(o).unwrap();
    Run {
        status,
        json: serde_json::from_str(&stdout).ok(),
        stdout,
    }
}

fn usage_error(run: &Run, code: &str) {
    assert_eq!(run.code(), 2, "{}", run.reason());
    assert!(run.json.is_none(), "{}", run.stdout);
    assert!(
        run.reason().starts_with(&format!("[{code}] ")),
        "expected [{code}]: {}",
        run.reason()
    );
}

fn example_zone() -> Zone {
    zone(
        "example.com.",
        vec![
            soa("example.com.", 2026010101),
            ns("example.com.", "ns1.example.com."),
            a("ns1.example.com.", "192.0.2.53"),
            a("example.com.", "192.0.2.10"),
            a("www.example.com.", "192.0.2.10"),
            aaaa("www.example.com.", "2001:db8::10"),
            mx("example.com.", 20, "mx2.example.com."),
            mx("example.com.", 10, "mail.example.com."),
            a("mail.example.com.", "192.0.2.25"),
            a("mx2.example.com.", "192.0.2.26"),
            cname("alias.example.com.", "www.example.com."),
            cname("ext.example.com.", "host.other.test."),
            cname("loop1.example.com.", "loop2.example.com."),
            cname("loop2.example.com.", "loop1.example.com."),
            cname("c1.example.com.", "c2.example.com."),
            cname("c2.example.com.", "c3.example.com."),
            cname("c3.example.com.", "www.example.com."),
            srv("_sip._tcp.example.com.", 20, 1, 5061, "sip2.example.com."),
            srv("_sip._tcp.example.com.", 10, 5, 5060, "sip.example.com."),
            a("sip.example.com.", "192.0.2.60"),
            a("sip2.example.com.", "192.0.2.61"),
            txt("txt.example.com.", "hello"),
            mx("nullmx.example.com.", 0, "."),
        ],
    )
}

fn other_zone() -> Zone {
    zone(
        "other.test.",
        vec![soa("other.test.", 1), a("host.other.test.", "198.51.100.7")],
    )
}

fn reverse_zone() -> Zone {
    zone(
        "2.0.192.in-addr.arpa.",
        vec![
            soa("2.0.192.in-addr.arpa.", 1),
            ptr("10.2.0.192.in-addr.arpa.", "www.example.com."),
            ptr("99.2.0.192.in-addr.arpa.", "www.example.com."),
        ],
    )
}

fn resolver() -> Fake {
    Fake::start(authoritative(vec![
        example_zone(),
        other_zone(),
        reverse_zone(),
    ]))
}

// ================================================================ lookup ==

#[test]
fn lookup_reports_answer_authority_and_additional_sections() {
    let s = resolver();
    let r = call(
        "lookup",
        &[
            ("name", "example.com"),
            ("rtype", "MX"),
            ("servers", "127.0.0.1"),
            ("port", &s.port_str()),
        ],
    );
    assert_eq!(r.code(), 0, "{}", r.stdout);
    let v = r.json();
    assert_eq!(v["ok"], true);
    assert_eq!(v["response"]["rcode"], "NOERROR");
    assert_eq!(v["response"]["authoritative"], true);
    assert_eq!(v["response"]["server_used"], "127.0.0.1");
    assert_eq!(v["response"]["dnssec_validated"], Value::Null);
    let answers = v["answers"].as_array().unwrap();
    assert_eq!(answers.len(), 2);
    assert_eq!(answers[0]["rtype"], "MX");
    assert_eq!(answers[0]["class"], "IN");
    let addl = v["additional"].as_array().unwrap();
    assert_eq!(addl.len(), 2, "{v}");
    assert_eq!(addl[0]["rtype"], "A");
    assert_eq!(v["query"]["port"], s.port);
    assert_eq!(v["warnings"].as_array().unwrap().len(), 0);
    // A query went over UDP with RD set.
    let reqs = s.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].0, Transport::Udp);
    assert!(parse(&reqs[0].1).recursion_desired());

    // NODATA: authority carries the SOA; it can be switched off.
    let r = call(
        "lookup",
        &[
            ("name", "txt.example.com"),
            ("rtype", "A"),
            ("servers", "127.0.0.1"),
            ("port", &s.port_str()),
        ],
    );
    assert_eq!(r.code(), 0);
    assert_eq!(r.json()["authority"][0]["rtype"], "SOA");
    assert!(
        r.json()["warnings"][0]
            .as_str()
            .unwrap()
            .contains("no A records")
    );
    let r = call(
        "lookup",
        &[
            ("name", "example.com"),
            ("rtype", "mx"),
            ("servers", "127.0.0.1"),
            ("port", &s.port_str()),
            ("include_additional", "no"),
            ("include_authority", "false"),
        ],
    );
    assert_eq!(r.json()["additional"].as_array().unwrap().len(), 0);
    assert_eq!(r.json()["authority"].as_array().unwrap().len(), 0);
}

#[test]
fn lookup_every_record_type() {
    let s = resolver();
    for (name, rtype, field) in [
        ("www.example.com", "AAAA", "address"),
        ("txt.example.com", "TXT", "text"),
        ("alias.example.com", "CNAME", "cname"),
        ("example.com", "NS", "nsdname"),
        ("_sip._tcp.example.com", "SRV", "target"),
        ("10.2.0.192.in-addr.arpa", "PTR", "ptrdname"),
        ("example.com", "SOA", "serial"),
        ("example.com", "ANY", "address"),
    ] {
        let r = call(
            "lookup",
            &[
                ("name", name),
                ("rtype", rtype),
                ("servers", "127.0.0.1"),
                ("port", &s.port_str()),
            ],
        );
        assert_eq!(r.code(), 0, "{rtype}: {}", r.stdout);
        assert!(
            r.json()["answers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["data"].get(field).is_some()),
            "{rtype}: {}",
            r.stdout
        );
    }
}

#[test]
fn lookup_follows_cnames_unless_told_not_to() {
    let s = resolver();
    let port = s.port_str();
    // ext -> host.other.test is out of zone: the server stops at the CNAME.
    let r = call(
        "lookup",
        &[
            ("name", "ext.example.com"),
            ("servers", "127.0.0.1"),
            ("port", &port),
        ],
    );
    assert_eq!(r.code(), 0);
    let answers = r.json()["answers"].as_array().unwrap().clone();
    assert_eq!(answers.len(), 2, "{answers:?}");
    assert_eq!(answers[0]["rtype"], "CNAME");
    assert_eq!(answers[1]["data"]["address"], "198.51.100.7");
    assert_eq!(s.requests().len(), 2);
    let r = call(
        "lookup",
        &[
            ("name", "ext.example.com"),
            ("servers", "127.0.0.1"),
            ("port", &port),
            ("follow_cname", "false"),
        ],
    );
    assert_eq!(r.json()["answers"].as_array().unwrap().len(), 1);
    assert_eq!(s.requests().len(), 3);
}

#[test]
fn lookup_rcode_errors_exit_1_with_codes() {
    let s = resolver();
    let r = call(
        "lookup",
        &[
            ("name", "nope.example.com"),
            ("servers", "127.0.0.1"),
            ("port", &s.port_str()),
        ],
    );
    assert_eq!(r.code(), 1);
    assert_eq!(r.json()["ok"], false);
    assert_eq!(r.error_code(), DNS_LOOKUP_NXDOMAIN);
    assert_eq!(r.json()["response"]["rcode"], "NXDOMAIN");
    assert!(r.reason().starts_with("[dns.lookup_nxdomain] "));
    for (rcode, code) in [
        (ResponseCode::ServFail, DNS_LOOKUP_SERVFAIL),
        (ResponseCode::Refused, DNS_LOOKUP_REFUSED),
        (ResponseCode::FormErr, DNS_LOOKUP_FORMERR),
        (ResponseCode::NotImp, DNS_LOOKUP_RCODE_ERROR),
        (ResponseCode::YXDomain, DNS_LOOKUP_RCODE_ERROR),
    ] {
        let f = Fake::start(fixed_rcode(rcode));
        let r = call(
            "lookup",
            &[
                ("name", "x.test"),
                ("servers", "127.0.0.1"),
                ("port", &f.port_str()),
            ],
        );
        assert_eq!(r.code(), 1, "{code}");
        assert_eq!(r.error_code(), code);
    }
}

#[test]
fn lookup_timeout_exits_124_after_all_attempts() {
    let f = Fake::start(silent());
    let started = Instant::now();
    let r = call(
        "lookup",
        &[
            ("name", "x.test"),
            ("servers", "127.0.0.1"),
            ("port", &f.port_str()),
            ("timeout_ms", "150"),
            ("retries", "2"),
        ],
    );
    let elapsed = started.elapsed();
    assert_eq!(r.code(), 124);
    assert_eq!(r.error_code(), DNS_LOOKUP_TIMEOUT);
    assert_eq!(f.requests().len(), 3);
    assert!(
        elapsed >= Duration::from_millis(450) && elapsed < Duration::from_secs(3),
        "{elapsed:?}"
    );
}

#[test]
fn lookup_network_error_and_server_failover() {
    // Nothing listens on the TCP port: connection refused.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port().to_string()
    };
    let r = call(
        "lookup",
        &[
            ("name", "x.test"),
            ("servers", "127.0.0.1"),
            ("port", &port),
            ("use_tcp", "true"),
            ("retries", "0"),
        ],
    );
    assert_eq!(r.code(), 1);
    assert_eq!(r.error_code(), DNS_LOOKUP_NETWORK_ERROR);

    // First server SERVFAILs, the second answers (same port, other address).
    let servers = start_many(
        &[Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(127, 0, 0, 2)],
        vec![
            fixed_rcode(ResponseCode::ServFail),
            authoritative(vec![example_zone()]),
        ],
    );
    let r = call(
        "lookup",
        &[
            ("name", "www.example.com"),
            ("servers", "127.0.0.1,127.0.0.2"),
            ("port", &servers[0].port_str()),
            ("randomize_servers", "false"),
        ],
    );
    assert_eq!(r.code(), 0, "{}", r.stdout);
    assert_eq!(r.json()["response"]["server_used"], "127.0.0.2");
    assert!(
        r.json()["warnings"][0]
            .as_str()
            .unwrap()
            .contains("SERVFAIL")
    );

    // Two silent servers: all failed, every failure a timeout.
    let quiet = start_many(
        &[Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(127, 0, 0, 2)],
        vec![silent(), silent()],
    );
    let r = call(
        "lookup",
        &[
            ("name", "x.test"),
            ("servers", r#"["127.0.0.1","127.0.0.2"]"#),
            ("port", &quiet[0].port_str()),
            ("timeout_ms", "100"),
            ("retries", "0"),
        ],
    );
    assert_eq!(r.code(), 124);
    assert_eq!(r.error_code(), DNS_LOOKUP_ALL_SERVERS_FAILED);
    assert_eq!(r.json()["warnings"].as_array().unwrap().len(), 2);
}

#[test]
fn lookup_tcp_truncation_and_dnssec() {
    let s = resolver();
    let port = s.port_str();
    let r = call(
        "lookup",
        &[
            ("name", "www.example.com"),
            ("servers", "127.0.0.1"),
            ("port", &port),
            ("use_tcp", "true"),
        ],
    );
    assert_eq!(r.code(), 0);
    assert_eq!(s.requests().last().unwrap().0, Transport::Tcp);

    // A truncated UDP reply is retried over TCP.
    let tc = Fake::start(responder(|t, req| {
        let m = parse(req);
        let mut r = answer(&[example_zone()], &m);
        if t == Transport::Udp {
            r = reply_to(&m, ResponseCode::NoError);
            r.set_truncated(true);
        }
        vec![r.to_vec().unwrap()]
    }));
    let r = call(
        "lookup",
        &[
            ("name", "www.example.com"),
            ("servers", "127.0.0.1"),
            ("port", &tc.port_str()),
        ],
    );
    assert_eq!(r.code(), 0);
    assert_eq!(r.json()["answers"][0]["data"]["address"], "192.0.2.10");
    assert_eq!(r.json()["response"]["truncated"], false);
    let t: Vec<Transport> = tc.requests().iter().map(|(t, _)| *t).collect();
    assert_eq!(t, [Transport::Udp, Transport::Tcp]);

    // dnssec=true sends EDNS0 with DO and reports the AD bit.
    let ad = Fake::start(responder(|_, req| {
        let m = parse(req);
        let mut r = answer(&[example_zone()], &m);
        r.set_authentic_data(m.extensions().as_ref().is_some_and(|e| e.dnssec_ok()));
        vec![r.to_vec().unwrap()]
    }));
    let r = call(
        "lookup",
        &[
            ("name", "www.example.com"),
            ("servers", "127.0.0.1"),
            ("port", &ad.port_str()),
            ("dnssec", "on"),
        ],
    );
    assert_eq!(r.json()["response"]["dnssec_validated"], true);
    let req = parse(&ad.requests()[0].1);
    assert!(req.extensions().as_ref().unwrap().dnssec_ok());
}

#[test]
fn lookup_text_format() {
    let s = resolver();
    let r = call(
        "lookup",
        &[
            ("name", "www.example.com"),
            ("servers", "127.0.0.1"),
            ("port", &s.port_str()),
            ("format", "text"),
        ],
    );
    assert_eq!(r.code(), 0);
    assert!(r.stdout.starts_with("DNS Lookup Result"));
    assert!(r.stdout.contains("192.0.2.10"));
}

#[test]
fn lookup_rejects_bad_arguments_before_sending() {
    let s = resolver();
    let port = s.port_str();
    let base = [("servers", "127.0.0.1"), ("port", port.as_str())];
    let with = |extra: &[(&'static str, &'static str)]| -> Vec<(&str, &str)> {
        let mut v: Vec<(&str, &str)> = base.to_vec();
        v.extend_from_slice(extra);
        v
    };
    for (extra, code) in [
        (vec![], DNS_LOOKUP_INVALID_NAME),
        (vec![("name", "")], DNS_LOOKUP_INVALID_NAME),
        (vec![("name", "-x")], DNS_LOOKUP_INVALID_NAME),
        (vec![("name", "a..b")], DNS_LOOKUP_INVALID_NAME),
        (
            vec![("name", "x.test"), ("rtype", "BOGUS")],
            DNS_LOOKUP_INVALID_TYPE,
        ),
        (
            vec![("name", "x.test"), ("timeout_ms", "0")],
            DNS_LOOKUP_INVALID_TIMEOUT,
        ),
        (
            vec![("name", "x.test"), ("timeout_ms", "abc")],
            DNS_LOOKUP_INVALID_TIMEOUT,
        ),
        (
            vec![("name", "x.test"), ("retries", "101")],
            DNS_LOOKUP_INVALID_RETRIES,
        ),
        (
            vec![("name", "x.test"), ("use_tcp", "maybe")],
            args::DNS_INVALID_ARGUMENT,
        ),
        (
            vec![("name", "x.test"), ("format", "xml")],
            args::DNS_INVALID_ARGUMENT,
        ),
        (
            vec![("name", "x.test"), ("dry_run", "true")],
            args::DNS_UNKNOWN_ARGUMENT,
        ),
        (
            vec![("name", "x.test"), ("rtyp", "A")],
            args::DNS_UNKNOWN_ARGUMENT,
        ),
    ] {
        let r = call("lookup", &with(&extra));
        usage_error(&r, code);
    }
    for (k, v, code) in [
        ("servers", "ns.example.com", DNS_LOOKUP_INVALID_SERVER),
        ("port", "0", DNS_LOOKUP_INVALID_PORT),
        ("port", "65536", DNS_LOOKUP_INVALID_PORT),
    ] {
        let r = call("lookup", &[("name", "x.test"), (k, v)]);
        usage_error(&r, code);
    }
    let r = call("lookup", &with(&[("name", "x.test"), ("rtyp", "A")]));
    assert!(
        r.reason().contains("did you mean `rtype`?"),
        "{}",
        r.reason()
    );
    assert!(s.requests().is_empty());
}

// =============================================================== resolve ==

fn resolve(port: &str, extra: &[(&str, &str)]) -> Run {
    let mut kv = vec![("servers", "127.0.0.1"), ("port", port)];
    kv.extend_from_slice(extra);
    call("resolve", &kv)
}

#[test]
fn resolve_host_follows_cnames_and_orders_families() {
    let s = resolver();
    let p = s.port_str();
    let r = resolve(&p, &[("name", "c1.example.com")]);
    assert_eq!(r.code(), 0, "{}", r.stdout);
    let res = &r.json()["resolution"];
    assert_eq!(res["canonical_name"], "www.example.com.");
    let ips: Vec<&str> = res["addresses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["ip"].as_str().unwrap())
        .collect();
    assert_eq!(ips, ["2001:db8::10", "192.0.2.10"]);
    assert_eq!(res["source_server"], "127.0.0.1");
    assert_eq!(r.json()["raw"], Value::Null);

    let r = resolve(&p, &[("name", "www.example.com"), ("family", "ipv4")]);
    assert_eq!(
        r.json()["resolution"]["addresses"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(r.json()["resolution"]["canonical_name"], "www.example.com");
    let r = resolve(&p, &[("name", "www.example.com"), ("family", "ipv6")]);
    assert_eq!(r.json()["resolution"]["addresses"][0]["family"], "ipv6");

    // Out-of-zone CNAME target is queried separately.
    let r = resolve(&p, &[("name", "ext.example.com"), ("family", "ipv4")]);
    assert_eq!(r.json()["resolution"]["addresses"][0]["ip"], "198.51.100.7");

    // want_raw keeps every response.
    let r = resolve(
        &p,
        &[
            ("name", "www.example.com"),
            ("family", "ipv4"),
            ("want_raw", "true"),
        ],
    );
    let ex = r.json()["raw"]["exchanges"].as_array().unwrap();
    assert_eq!(ex.len(), 1);
    let wire = hex::decode(ex[0]["response_hex"].as_str().unwrap()).unwrap();
    assert_eq!(Message::from_vec(&wire).unwrap().answers().len(), 1);
}

#[test]
fn resolve_host_errors() {
    let s = resolver();
    let p = s.port_str();
    let r = resolve(&p, &[("name", "c1.example.com"), ("max_cname_depth", "2")]);
    assert_eq!(r.code(), 1);
    assert_eq!(r.error_code(), DNS_RESOLVE_CNAME_LOOP);
    let r = resolve(&p, &[("name", "loop1.example.com")]);
    assert_eq!(r.error_code(), DNS_RESOLVE_CNAME_LOOP);
    let r = resolve(&p, &[("name", "nope.example.com")]);
    assert_eq!(r.code(), 1);
    assert_eq!(r.error_code(), DNS_RESOLVE_HOST_NOT_FOUND);
    assert!(
        r.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("NXDOMAIN")
    );
    let r = resolve(&p, &[("name", "txt.example.com")]);
    assert_eq!(r.error_code(), DNS_RESOLVE_HOST_NOT_FOUND);

    let f = Fake::start(fixed_rcode(ResponseCode::ServFail));
    let r = resolve(&f.port_str(), &[("name", "x.test")]);
    assert_eq!(r.code(), 1);
    assert_eq!(r.error_code(), DNS_RESOLVE_LOOKUP_ERROR);
    let q = Fake::start(silent());
    let r = resolve(
        &q.port_str(),
        &[("name", "x.test"), ("timeout_ms", "100"), ("retries", "0")],
    );
    assert_eq!(r.code(), 124);
    assert_eq!(r.error_code(), DNS_RESOLVE_TIMEOUT);
}

#[test]
fn resolve_mail_service_and_reverse() {
    let s = resolver();
    let p = s.port_str();
    let r = resolve(
        &p,
        &[
            ("name", "example.com"),
            ("mode", "mail"),
            ("family", "ipv4"),
        ],
    );
    assert_eq!(r.code(), 0, "{}", r.stdout);
    let mx = r.json()["resolution"]["mx"].as_array().unwrap().clone();
    assert_eq!(mx[0]["exchange"], "mail.example.com.");
    assert_eq!(mx[0]["addresses"][0]["ip"], "192.0.2.25");
    assert_eq!(mx[1]["preference"], 20);
    assert_eq!(
        r.json()["resolution"]["addresses"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let r = resolve(&p, &[("name", "www.example.com"), ("mode", "mail")]);
    assert_eq!(r.error_code(), DNS_RESOLVE_NO_MX);
    let r = resolve(&p, &[("name", "nullmx.example.com"), ("mode", "mail")]);
    assert_eq!(r.code(), 0);
    assert!(
        r.json()["warnings"][0]
            .as_str()
            .unwrap()
            .contains("null MX")
    );

    let r = resolve(
        &p,
        &[("name", "_sip._tcp.example.com"), ("mode", "service")],
    );
    assert_eq!(r.code(), 0);
    let srv = r.json()["resolution"]["srv"].as_array().unwrap().clone();
    assert_eq!(srv[0]["port"], 5060);
    assert_eq!(srv[0]["addresses"][0]["ip"], "192.0.2.60");
    let r = resolve(
        &p,
        &[
            ("name", "_sip._tcp.example.com"),
            ("mode", "service"),
            ("follow_srv", "false"),
        ],
    );
    assert_eq!(
        r.json()["resolution"]["srv"][0]["addresses"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        r.json()["resolution"]["addresses"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let r = resolve(&p, &[("name", "_x._tcp.example.com"), ("mode", "service")]);
    assert_eq!(r.error_code(), DNS_RESOLVE_NO_SRV);

    let r = resolve(&p, &[("name", "192.0.2.10"), ("mode", "reverse")]);
    assert_eq!(r.code(), 0);
    assert_eq!(r.json()["resolution"]["ptr_name"], "www.example.com.");
    assert_eq!(
        r.json()["resolution"]["forward_addresses"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let r = resolve(
        &p,
        &[
            ("name", "192.0.2.10"),
            ("mode", "reverse"),
            ("validate_reverse", "true"),
        ],
    );
    assert_eq!(
        r.json()["resolution"]["forward_addresses"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(r.json()["warnings"].as_array().unwrap().len(), 0);
    let r = resolve(
        &p,
        &[
            ("name", "192.0.2.99"),
            ("mode", "reverse"),
            ("validate_reverse", "true"),
        ],
    );
    assert!(
        r.json()["warnings"][0]
            .as_str()
            .unwrap()
            .contains("does not include 192.0.2.99")
    );
    let r = resolve(&p, &[("name", "192.0.2.77"), ("mode", "reverse")]);
    assert_eq!(r.error_code(), DNS_RESOLVE_NO_PTR);
}

#[test]
fn resolve_rejects_bad_arguments() {
    for (kv, code) in [
        (vec![], DNS_RESOLVE_INVALID_NAME),
        (
            vec![("name", "x.test"), ("mode", "bogus")],
            DNS_RESOLVE_INVALID_MODE,
        ),
        (
            vec![("name", "x.test"), ("family", "ipv5")],
            DNS_RESOLVE_INVALID_FAMILY,
        ),
        (
            vec![("name", "x.test"), ("servers", "1.2.3")],
            DNS_RESOLVE_INVALID_SERVER,
        ),
        (
            vec![("name", "x.test"), ("port", "x")],
            DNS_RESOLVE_INVALID_PORT,
        ),
        (
            vec![("name", "x.test"), ("timeout_ms", "0")],
            DNS_RESOLVE_INVALID_TIMEOUT,
        ),
        (
            vec![("name", "x.test"), ("retries", "-1")],
            DNS_RESOLVE_INVALID_RETRIES,
        ),
        (
            vec![("name", "x.test"), ("mode", "reverse")],
            DNS_RESOLVE_INVALID_NAME,
        ),
        (
            vec![("name", "x.test"), ("validate_reverse", "true")],
            args::DNS_INVALID_ARGUMENT,
        ),
        (
            vec![("name", "x.test"), ("max_cname_depth", "65")],
            args::DNS_INVALID_ARGUMENT,
        ),
        (
            vec![("name", "x.test"), ("want_raw", "2")],
            args::DNS_INVALID_ARGUMENT,
        ),
        (
            vec![("name", "x.test"), ("timeout", "5")],
            args::DNS_UNKNOWN_ARGUMENT,
        ),
    ] {
        usage_error(&call("resolve", &kv), code);
    }
}

// ================================================================= trace ==

/// A hierarchy on one port: root at .1, com. at .2, example.com. at .3,
/// other.net. (holding a glueless name server's address) at .4.
fn hierarchy(example_com: Responder) -> Vec<Fake> {
    let root = zone(
        ".",
        vec![
            soa(".", 1),
            ns("com.", "a.gtld.test."),
            a("a.gtld.test.", "127.0.0.2"),
            ns("net.", "a.gtld.test."),
            ns("org.", "ns.other.net."),
            ns("lame.", "lame-ns.test."),
            a("lame-ns.test.", "127.0.0.1"),
        ],
    );
    let com = zone(
        "com.",
        vec![
            soa("com.", 1),
            ns("example.com.", "ns1.example.com."),
            a("ns1.example.com.", "127.0.0.3"),
            ns("glueless.com.", "ns.other.net."),
            ns("noglue.com.", "ns.noglue.com."),
        ],
    );
    let net = zone(
        "net.",
        vec![
            soa("net.", 1),
            ns("other.net.", "ns.other.net."),
            a("ns.other.net.", "127.0.0.4"),
        ],
    );
    let other = zone(
        "other.net.",
        vec![soa("other.net.", 1), a("ns.other.net.", "127.0.0.4")],
    );
    let glueless = zone(
        "glueless.com.",
        vec![
            soa("glueless.com.", 1),
            a("www.glueless.com.", "203.0.113.5"),
        ],
    );
    let ips: Vec<Ipv4Addr> = (1..=4).map(|i| Ipv4Addr::new(127, 0, 0, i)).collect();
    start_many(
        &ips,
        vec![
            authoritative(vec![root]),
            authoritative(vec![com, net]),
            example_com,
            authoritative(vec![other, glueless]),
        ],
    )
}

fn trace(port: &str, extra: &[(&str, &str)]) -> Run {
    let mut kv = vec![("root_servers", "127.0.0.1"), ("port", port)];
    kv.extend_from_slice(extra);
    call("trace", &kv)
}

#[test]
fn trace_walks_referrals_to_the_answer() {
    let h = hierarchy(authoritative(vec![example_zone()]));
    let p = h[0].port_str();
    let r = trace(&p, &[("name", "www.example.com")]);
    assert_eq!(r.code(), 0, "{}", r.stdout);
    let t = &r.json()["trace"];
    let hops = t["hops"].as_array().unwrap();
    let zones: Vec<&str> = hops.iter().map(|h| h["zone"].as_str().unwrap()).collect();
    assert_eq!(zones, [".", "com.", "example.com."]);
    let servers: Vec<&str> = hops
        .iter()
        .map(|h| h["server_ip"].as_str().unwrap())
        .collect();
    assert_eq!(servers, ["127.0.0.1", "127.0.0.2", "127.0.0.3"]);
    assert_eq!(hops[0]["ns_names"][0], "a.gtld.test.");
    assert_eq!(hops[0]["ns_addresses"][0]["ip"], "127.0.0.2");
    assert_eq!(hops[0]["authority"][0]["rtype"], "NS");
    assert_eq!(hops[0]["additional"][0]["rtype"], "A");
    assert_eq!(hops[1]["server_name"], "a.gtld.test.");
    assert_eq!(hops[0]["raw"], Value::Null);
    assert_eq!(t["final_rcode"], "NOERROR");
    assert_eq!(t["final_authoritative"], true);
    assert_eq!(t["final_answers"][0]["data"]["address"], "192.0.2.10");
    assert_eq!(t["depth"], 3);
    // Iterative queries: RD is clear.
    assert!(!parse(&h[0].requests()[0].1).recursion_desired());

    let r = trace(
        &p,
        &[
            ("name", "www.example.com"),
            ("include_additional", "false"),
            ("want_raw", "true"),
        ],
    );
    let hops = r.json()["trace"]["hops"].as_array().unwrap().clone();
    assert_eq!(hops[0]["additional"].as_array().unwrap().len(), 0);
    assert_eq!(hops[0]["ns_addresses"][0]["ip"], "127.0.0.2");
    assert!(hops[2]["raw"]["response_hex"].as_str().unwrap().len() > 24);

    // NODATA ends the walk successfully with no answers.
    let r = trace(
        &p,
        &[
            ("name", "txt.example.com"),
            ("rtype", "MX"),
            ("format", "text"),
        ],
    );
    assert_eq!(r.code(), 0);
    assert!(r.stdout.contains("Hop 3:"));
}

#[test]
fn trace_cnames_glueless_servers_and_errors() {
    let h = hierarchy(authoritative(vec![example_zone()]));
    let p = h[0].port_str();
    // CNAME into another tree: not followed by default.
    let r = trace(&p, &[("name", "ext.example.com")]);
    assert_eq!(r.code(), 0);
    assert_eq!(r.json()["trace"]["final_answers"][0]["rtype"], "CNAME");
    assert_eq!(r.json()["trace"]["cname_chain"][0], "host.other.test.");
    // follow_cname restarts at the root; other.test. does not exist there.
    let r = trace(&p, &[("name", "ext.example.com"), ("follow_cname", "true")]);
    assert_eq!(r.code(), 1);
    assert_eq!(r.error_code(), DNS_TRACE_NXDOMAIN);
    assert_eq!(r.json()["trace"]["hops"].as_array().unwrap().len(), 4);

    // A delegation without glue: the name server is found by its own walk.
    let r = trace(&p, &[("name", "www.glueless.com")]);
    assert_eq!(r.code(), 0, "{}", r.stdout);
    let hops = r.json()["trace"]["hops"].as_array().unwrap().clone();
    assert_eq!(hops.last().unwrap()["server_ip"], "127.0.0.4");
    assert_eq!(
        r.json()["trace"]["final_answers"][0]["data"]["address"],
        "203.0.113.5"
    );

    // In-zone name server without glue: no usable server.
    let r = trace(&p, &[("name", "www.noglue.com")]);
    assert_eq!(r.code(), 1);
    assert_eq!(r.error_code(), DNS_TRACE_NO_NS);
    // A referral that does not lead closer is a loop.
    let r = trace(&p, &[("name", "x.lame")]);
    assert_eq!(r.error_code(), DNS_TRACE_LOOP_DETECTED);
    // max_depth limits the number of queries.
    let r = trace(&p, &[("name", "www.example.com"), ("max_depth", "2")]);
    assert_eq!(r.code(), 1);
    assert_eq!(r.error_code(), DNS_TRACE_MAX_DEPTH_EXCEEDED);
    let r = trace(&p, &[("name", "nope.example.com")]);
    assert_eq!(r.error_code(), DNS_TRACE_NXDOMAIN);
}

#[test]
fn trace_server_failures() {
    let h = hierarchy(fixed_rcode(ResponseCode::Refused));
    let r = trace(&h[0].port_str(), &[("name", "www.example.com")]);
    assert_eq!(r.code(), 1);
    assert_eq!(r.error_code(), DNS_TRACE_REFUSED);
    assert_eq!(r.json()["trace"]["hops"].as_array().unwrap().len(), 3);
    let h = hierarchy(fixed_rcode(ResponseCode::ServFail));
    let r = trace(&h[0].port_str(), &[("name", "www.example.com")]);
    assert_eq!(r.error_code(), DNS_TRACE_SERVFAIL);
    let h = hierarchy(fixed_rcode(ResponseCode::NotImp));
    let r = trace(&h[0].port_str(), &[("name", "www.example.com")]);
    assert_eq!(r.error_code(), DNS_TRACE_RCODE_ERROR);
    let h = hierarchy(silent());
    let r = trace(
        &h[0].port_str(),
        &[
            ("name", "www.example.com"),
            ("timeout_ms", "100"),
            ("retries", "0"),
        ],
    );
    assert_eq!(r.code(), 124);
    assert_eq!(r.error_code(), DNS_TRACE_TIMEOUT);
    let r = trace(
        &h[0].port_str(),
        &[
            ("name", "www.example.com"),
            ("root_servers", "127.0.0.3,127.0.0.3"),
            ("timeout_ms", "100"),
            ("retries", "0"),
        ],
    );
    assert_eq!(r.code(), 124);
    assert_eq!(r.error_code(), DNS_TRACE_ALL_SERVERS_FAILED);
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port().to_string()
    };
    let r = trace(
        &port,
        &[("name", "x.test"), ("use_tcp", "true"), ("retries", "0")],
    );
    assert_eq!(r.code(), 1);
    assert_eq!(r.error_code(), DNS_TRACE_NETWORK_ERROR);
}

#[test]
fn trace_rejects_bad_arguments() {
    for (kv, code) in [
        (vec![], DNS_TRACE_INVALID_NAME),
        (
            vec![("name", "x.test"), ("rtype", "AXFR")],
            DNS_TRACE_INVALID_TYPE,
        ),
        (
            vec![("name", "x.test"), ("root_servers", "a.root-servers.net")],
            DNS_TRACE_INVALID_ROOT_SERVER,
        ),
        (
            vec![("name", "x.test"), ("port", "0")],
            DNS_TRACE_INVALID_PORT,
        ),
        (
            vec![("name", "x.test"), ("timeout_ms", "0")],
            DNS_TRACE_INVALID_TIMEOUT,
        ),
        (
            vec![("name", "x.test"), ("retries", "x")],
            DNS_TRACE_INVALID_RETRIES,
        ),
        (
            vec![("name", "x.test"), ("max_depth", "0")],
            DNS_TRACE_INVALID_MAX_DEPTH,
        ),
        (
            vec![("name", "x.test"), ("prefer_ipv6", "1.0")],
            args::DNS_INVALID_ARGUMENT,
        ),
        (
            vec![("name", "x.test"), ("servers", "127.0.0.1")],
            args::DNS_UNKNOWN_ARGUMENT,
        ),
    ] {
        usage_error(&call("trace", &kv), code);
    }
}

#[test]
fn trace_root_hints_follow_prefer_ipv6() {
    let opts = |v6: &str| {
        DnsTraceOptions::from_args(
            &[("name", "x.test"), ("prefer_ipv6", v6)]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
        .unwrap()
    };
    let v4 = query::trace_roots(&opts("false"));
    assert!(!v4.is_empty() && v4.iter().all(|(_, ip)| ip.is_ipv4()));
    let v6 = query::trace_roots(&opts("true"));
    assert!(!v6.is_empty() && v6.iter().all(|(_, ip)| ip.is_ipv6()));
}

// ============================================================ zone.fetch ==

fn zone_records() -> Vec<Record> {
    let mut v = vec![soa("example.com.", 2026010102)];
    v.push(ns("example.com.", "ns1.example.com."));
    for i in 0..20 {
        v.push(a(&format!("h{i}.example.com."), &format!("192.0.2.{i}")));
    }
    v.push(txt("txt.example.com.", "hello"));
    v
}

fn fetch(port: &str, extra: &[(&str, &str)]) -> Run {
    let mut kv = vec![
        ("zone", "example.com"),
        ("servers", "127.0.0.1"),
        ("port", port),
    ];
    kv.extend_from_slice(extra);
    call("zone.fetch", &kv)
}

const TSIG: [(&str, &str); 2] = [("tsig_key_name", KEY_NAME), ("tsig_secret", KEY_B64)];

#[test]
fn zone_fetch_axfr_across_messages() {
    let s = Fake::start(xfr_server(zone_records(), None, 5, Signing::None));
    let r = fetch(&s.port_str(), &[]);
    assert_eq!(r.code(), 0, "{}", r.stdout);
    let z = &r.json()["zone"];
    assert_eq!(z["name"], "example.com.");
    assert_eq!(z["serial"], 2026010102);
    assert_eq!(z["soa"]["mname"], "ns1.example.com.");
    assert_eq!(z["record_count"], 23);
    assert_eq!(z["records"].as_array().unwrap().len(), 23);
    assert_eq!(z["records"][0]["rtype"], "SOA");
    assert_eq!(z["transfer_used"], "AXFR");
    assert_eq!(z["server_used"], "127.0.0.1");
    assert_eq!(r.json()["changes"], Value::Null);
    assert_eq!(r.json()["raw"], Value::Null);
    assert_eq!(r.json()["error"], Value::Null);
    let req = parse(&s.requests()[0].1);
    assert_eq!(req.queries()[0].query_type(), RecordType::AXFR);
    assert!(req.extensions().is_none());

    let r = fetch(
        &s.port_str(),
        &[
            ("include_raw", "true"),
            ("dnssec", "true"),
            ("format", "json"),
        ],
    );
    assert_eq!(r.json()["raw"]["response_hex"].as_array().unwrap().len(), 5);
    assert!(r.json()["raw"]["request_hex"].is_string());
    assert!(
        parse(&s.requests()[1].1)
            .extensions()
            .as_ref()
            .unwrap()
            .dnssec_ok()
    );

    let r = fetch(&s.port_str(), &[("format", "text")]);
    assert!(r.stdout.starts_with("Zone Fetch"));
    assert!(r.stdout.contains("Records     : 23"));
}

#[test]
fn zone_fetch_tsig_signs_and_verifies_every_message() {
    for how in [Signing::Every(1), Signing::Every(2), Signing::Every(3)] {
        let s = Fake::start(xfr_server(zone_records(), None, 3, how));
        let r = fetch(&s.port_str(), &TSIG);
        assert_eq!(r.code(), 0, "{how:?}: {}", r.stdout);
        assert_eq!(r.json()["zone"]["record_count"], 23);
        assert_eq!(r.json()["query"]["tsig_key_name"], KEY_NAME);
        // The request carried a valid signature (checked by the server).
        assert!(
            super::split_trailing_tsig(&s.requests()[0].1)
                .unwrap()
                .1
                .is_some()
        );
    }
    for (how, needle) in [
        (
            Signing::LastUnsigned(2),
            "last reply message is not TSIG-signed",
        ),
        (Signing::CorruptAt(0), "does not verify"),
        (Signing::CorruptAt(4), "does not verify"),
        (Signing::None, "first reply message is not TSIG-signed"),
        (Signing::Error(17), "BADKEY"),
    ] {
        let s = Fake::start(xfr_server(zone_records(), None, 3, how));
        let r = fetch(&s.port_str(), &TSIG);
        assert_eq!(r.code(), 1, "{how:?}");
        assert_eq!(r.error_code(), DNS_ZONE_FETCH_TSIG_FAILED, "{how:?}");
        assert!(
            r.json()["error"]["message"]
                .as_str()
                .unwrap()
                .contains(needle),
            "{how:?}: {}",
            r.json()["error"]
        );
        assert_eq!(r.json()["zone"], Value::Null);
    }
    // Wrong key: the server cannot verify the request (it panics the
    // responder thread and closes the connection), so nothing is trusted.
    let s = Fake::start(xfr_server(zone_records(), None, 3, Signing::Every(1)));
    let r = fetch(
        &s.port_str(),
        &[
            ("tsig_key_name", KEY_NAME),
            ("tsig_secret", "b3RoZXIta2V5"),
            ("retries", "0"),
        ],
    );
    assert_eq!(r.code(), 1);
    // A signed reply when no key was given is accepted with a warning.
    let s = Fake::start(responder(|_, req| {
        let m = parse(req);
        sign_stream(
            axfr_messages(&m, &zone_records(), 5),
            &[],
            Signing::Every(1),
        )
    }));
    let r = fetch(&s.port_str(), &[]);
    assert_eq!(r.code(), 0);
    assert!(
        r.json()["warnings"][0]
            .as_str()
            .unwrap()
            .contains("not verified")
    );
}

#[test]
fn zone_fetch_ixfr_incremental_up_to_date_and_fallback() {
    let old = 2026010101u32;
    let newer = 2026010102u32;
    let diff = vec![
        soa("example.com.", newer),
        soa("example.com.", old),
        a("gone.example.com.", "192.0.2.99"),
        soa("example.com.", newer),
        a("new.example.com.", "192.0.2.100"),
        txt("txt.example.com.", "hello"),
        soa("example.com.", newer),
    ];
    let s = Fake::start(xfr_server(zone_records(), Some(diff), 2, Signing::Every(2)));
    let r = fetch(
        &s.port_str(),
        &[
            ("transfer", "IXFR"),
            ("serial", &old.to_string()),
            TSIG[0],
            TSIG[1],
        ],
    );
    assert_eq!(r.code(), 0, "{}", r.stdout);
    let c = &r.json()["changes"];
    assert_eq!(c["old_serial"], old);
    assert_eq!(c["new_serial"], newer);
    assert_eq!(c["deleted"][0]["name"], "gone.example.com.");
    assert_eq!(c["added"].as_array().unwrap().len(), 2);
    assert_eq!(r.json()["zone"]["transfer_used"], "IXFR");
    assert_eq!(r.json()["zone"]["record_count"], 0);
    let req = parse(&s.requests()[0].1);
    assert_eq!(req.queries()[0].query_type(), RecordType::IXFR);
    match req.name_servers()[0].data() {
        Some(RData::SOA(x)) => assert_eq!(x.serial(), old),
        other => panic!("no SOA in the IXFR request: {other:?}"),
    }

    // Up to date: a single SOA.
    let s = Fake::start(xfr_server(
        zone_records(),
        Some(vec![soa("example.com.", newer)]),
        2,
        Signing::None,
    ));
    let r = fetch(
        &s.port_str(),
        &[("transfer", "ixfr"), ("serial", &newer.to_string())],
    );
    assert_eq!(r.code(), 0, "{}", r.stdout);
    assert_eq!(r.json()["changes"]["added"].as_array().unwrap().len(), 0);
    assert_eq!(r.json()["changes"]["old_serial"], newer);

    // The server answers IXFR with a full transfer.
    let s = Fake::start(xfr_server(zone_records(), None, 4, Signing::None));
    let r = fetch(&s.port_str(), &[("transfer", "IXFR"), ("serial", "1")]);
    assert_eq!(r.code(), 0);
    assert_eq!(r.json()["zone"]["transfer_used"], "AXFR");
    assert_eq!(r.json()["zone"]["transfer_requested"], "IXFR");
    assert_eq!(r.json()["changes"], Value::Null);
    assert!(
        r.json()["warnings"][0]
            .as_str()
            .unwrap()
            .contains("full zone transfer")
    );
}

#[test]
fn zone_fetch_failures() {
    // Limit
    let s = Fake::start(xfr_server(zone_records(), None, 5, Signing::None));
    let r = fetch(&s.port_str(), &[("max_records", "10")]);
    assert_eq!(r.code(), 1);
    assert_eq!(r.error_code(), DNS_ZONE_FETCH_MAX_RECORDS_EXCEEDED);
    let r = fetch(&s.port_str(), &[("max_records", "23")]);
    assert_eq!(r.code(), 0);
    // RCODEs
    for (rcode, code) in [
        (ResponseCode::Refused, DNS_ZONE_FETCH_REFUSED),
        (ResponseCode::NotAuth, DNS_ZONE_FETCH_RCODE_ERROR),
        (ResponseCode::ServFail, DNS_ZONE_FETCH_SERVFAIL),
        (ResponseCode::NXDomain, DNS_ZONE_FETCH_NXDOMAIN),
        (ResponseCode::FormErr, DNS_ZONE_FETCH_FORMERR),
    ] {
        let f = Fake::start(fixed_rcode(rcode));
        let r = fetch(&f.port_str(), &[]);
        assert_eq!(r.code(), 1);
        assert_eq!(r.error_code(), code);
    }
    // Not starting with SOA
    let bad = Fake::start(responder(|_, req| {
        let m = parse(req);
        stream_messages(&m, &[a("x.example.com.", "192.0.2.1")], 1)
    }));
    let r = fetch(&bad.port_str(), &[]);
    assert_eq!(r.error_code(), DNS_ZONE_FETCH_INVALID_AXFR_STREAM);
    // Connection closed in the middle
    let short = Fake::start(responder(|_, req| {
        let m = parse(req);
        let mut msgs = axfr_messages(&m, &zone_records(), 5);
        msgs.pop();
        msgs
    }));
    let r = fetch(&short.port_str(), &[]);
    assert_eq!(r.error_code(), DNS_ZONE_FETCH_INVALID_AXFR_STREAM);
    // Timeout (silent server) and retries
    let q = Fake::start(silent());
    let started = Instant::now();
    let r = fetch(&q.port_str(), &[("timeout_ms", "150"), ("retries", "1")]);
    assert_eq!(r.code(), 124);
    assert_eq!(r.error_code(), DNS_ZONE_FETCH_TIMEOUT);
    assert_eq!(q.tcp_connections(), 2);
    assert!(started.elapsed() < Duration::from_secs(3));
    // Nothing listening
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port().to_string()
    };
    let r = fetch(&port, &[("retries", "0")]);
    assert_eq!(r.code(), 1);
    assert_eq!(r.error_code(), DNS_ZONE_FETCH_NETWORK_ERROR);
    // Two servers: the first refuses, the second transfers.
    let two = start_many(
        &[Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(127, 0, 0, 2)],
        vec![
            fixed_rcode(ResponseCode::Refused),
            xfr_server(zone_records(), None, 5, Signing::None),
        ],
    );
    let r = fetch(&two[0].port_str(), &[("servers", "127.0.0.1,127.0.0.2")]);
    assert_eq!(r.code(), 0);
    assert_eq!(r.json()["zone"]["server_used"], "127.0.0.2");
    assert!(
        r.json()["warnings"][0]
            .as_str()
            .unwrap()
            .contains("REFUSED")
    );
    let both = start_many(
        &[Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(127, 0, 0, 2)],
        vec![
            fixed_rcode(ResponseCode::Refused),
            fixed_rcode(ResponseCode::Refused),
        ],
    );
    let r = fetch(
        &both[0].port_str(),
        &[("servers", r#"["127.0.0.1","127.0.0.2"]"#)],
    );
    assert_eq!(r.code(), 1);
    assert_eq!(r.error_code(), DNS_ZONE_FETCH_ALL_SERVERS_FAILED);
}

#[test]
fn zone_fetch_rejects_bad_arguments() {
    for (kv, code) in [
        (vec![], DNS_ZONE_FETCH_INVALID_ZONE),
        (
            vec![("zone", "example.com"), ("transfer", "XFR")],
            DNS_ZONE_FETCH_INVALID_TRANSFER_TYPE,
        ),
        (
            vec![("zone", "example.com"), ("transfer", "IXFR")],
            DNS_ZONE_FETCH_MISSING_SERIAL,
        ),
        (
            vec![("zone", "example.com"), ("serial", "5")],
            args::DNS_INVALID_ARGUMENT,
        ),
        (
            vec![("zone", "example.com"), ("servers", "ns1.example.com")],
            DNS_ZONE_FETCH_INVALID_SERVER,
        ),
        (
            vec![("zone", "example.com"), ("port", "0")],
            DNS_ZONE_FETCH_INVALID_PORT,
        ),
        (
            vec![("zone", "example.com"), ("timeout_ms", "0")],
            DNS_ZONE_FETCH_INVALID_TIMEOUT,
        ),
        (
            vec![("zone", "example.com"), ("retries", "101")],
            DNS_ZONE_FETCH_INVALID_RETRIES,
        ),
        (
            vec![("zone", "example.com"), ("max_records", "0")],
            DNS_ZONE_FETCH_INVALID_MAX_RECORDS,
        ),
        (
            vec![("zone", "example.com"), ("use_tcp", "false")],
            DNS_ZONE_FETCH_TCP_REQUIRED,
        ),
        (
            vec![("zone", "example.com"), ("tsig_key_name", "k")],
            DNS_ZONE_FETCH_INVALID_TSIG_CONFIG,
        ),
        (
            vec![("zone", "example.com"), ("tsig_algorithm", "hmac-sha256")],
            DNS_ZONE_FETCH_INVALID_TSIG_CONFIG,
        ),
        (
            vec![
                ("zone", "example.com"),
                ("tsig_key_name", "k"),
                ("tsig_secret", "!!"),
            ],
            DNS_ZONE_FETCH_INVALID_TSIG_SECRET,
        ),
        (
            vec![
                ("zone", "example.com"),
                ("tsig_key_name", "k"),
                ("tsig_secret", KEY_B64),
                ("tsig_algorithm", "hmac-md5"),
            ],
            DNS_ZONE_FETCH_UNSUPPORTED_TSIG_ALGORITHM,
        ),
        (
            vec![("zone", "example.com"), ("dry_run", "true")],
            args::DNS_UNKNOWN_ARGUMENT,
        ),
        (
            vec![("zone", "example.com"), ("include_raw", "sure")],
            args::DNS_INVALID_ARGUMENT,
        ),
    ] {
        usage_error(&call("zone.fetch", &kv), code);
    }
}

#[test]
fn zone_fetch_discovers_authoritative_servers() {
    let s = resolver();
    let resolvers = [SocketAddr::new("127.0.0.1".parse().unwrap(), s.port)];
    let cfg = client::QueryConfig {
        use_tcp: false,
        timeout: Duration::from_millis(500),
        retries: 0,
        dnssec: false,
        recursion_desired: true,
    };
    let mut warnings = Vec::new();
    let found = run_async(xfr::discover_servers(
        &Name::from_ascii("example.com.").unwrap(),
        &resolvers,
        &cfg,
        false,
        &mut warnings,
    ))
    .unwrap();
    assert_eq!(found.unwrap(), vec!["192.0.2.53".to_string()]);
    let missing = run_async(xfr::discover_servers(
        &Name::from_ascii("nope.example.com.").unwrap(),
        &resolvers,
        &cfg,
        false,
        &mut warnings,
    ))
    .unwrap();
    assert!(missing.unwrap_err().contains("NXDOMAIN"));
}

// ============================================================ help/args ==

#[test]
fn help_usage_lists_exactly_the_accepted_options() {
    for verb in DNS_HELP.verbs {
        let usage = verb.detail.as_ref().unwrap().usage;
        let mut in_usage: Vec<&str> = usage
            .split(|c: char| c == '[' || c.is_whitespace())
            .filter_map(|w| w.split_once('=').map(|(k, _)| k))
            .collect();
        in_usage.sort();
        let mut accepted = verb_options(verb.name).unwrap().to_vec();
        accepted.sort();
        assert_eq!(
            in_usage, accepted,
            "usage of {} disagrees with its options",
            verb.name
        );
    }
}

#[test]
fn every_error_code_is_documented() {
    let doc = include_str!("../../../../docs/Network_RemoteOperations/dns.md");
    let src = include_str!("../dnsh.rs");
    let mut codes: Vec<&str> = src
        .split("pub const DNS_")
        .skip(1)
        .filter_map(|chunk| chunk.split(';').next())
        .filter_map(|decl| decl.split('"').nth(1))
        .collect();
    codes.push(args::DNS_UNKNOWN_ARGUMENT);
    codes.push(args::DNS_INVALID_ARGUMENT);
    assert!(codes.len() > 60);
    for code in codes {
        assert!(
            code.starts_with("dns.") && crate::core::status::is_valid_error_code(code),
            "{code}"
        );
        assert!(
            doc.contains(&format!("`{code}`")),
            "{code} is not documented in dns.md"
        );
    }
}
