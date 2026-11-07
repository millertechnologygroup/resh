//! Every `dns://` verb through the built `resh` binary, against fake DNS
//! servers on 127.0.0.x (never the internet): exit codes, JSON output,
//! help output (golden files) and the help examples.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use resh::handles::network::dnsh::verb_options;
use serde_json::Value;
use tempfile::TempDir;
use trust_dns_proto::op::{Message, MessageType, ResponseCode};
use trust_dns_proto::rr::rdata::{A, MX, NS, SOA};
use trust_dns_proto::rr::{Name, RData, Record, RecordType};

type Responder = Arc<dyn Fn(bool, &[u8]) -> Vec<Vec<u8>> + Send + Sync>;

/// UDP and TCP servers on each of `ips`, all on one port.
fn serve(ips: &[Ipv4Addr], responders: Vec<Responder>) -> u16 {
    'retry: loop {
        let first = UdpSocket::bind((ips[0], 0)).unwrap();
        let port = first.local_addr().unwrap().port();
        let mut socks = vec![];
        let mut first = Some(first);
        for ip in ips {
            let udp = match first.take() {
                Some(u) => u,
                None => match UdpSocket::bind((*ip, port)) {
                    Ok(u) => u,
                    Err(_) => continue 'retry,
                },
            };
            let Ok(tcp) = TcpListener::bind((*ip, port)) else {
                continue 'retry;
            };
            socks.push((udp, tcp));
        }
        for ((udp, tcp), r) in socks.into_iter().zip(responders) {
            let r2 = r.clone();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 65535];
                while let Ok((len, peer)) = udp.recv_from(&mut buf) {
                    for reply in r2(false, &buf[..len]) {
                        let _ = udp.send_to(&reply, peer);
                    }
                }
            });
            std::thread::spawn(move || {
                for s in tcp.incoming() {
                    let Ok(mut s) = s else { continue };
                    let r = r.clone();
                    std::thread::spawn(move || {
                        let mut len = [0u8; 2];
                        if s.read_exact(&mut len).is_err() {
                            return;
                        }
                        let mut req = vec![0u8; u16::from_be_bytes(len) as usize];
                        if s.read_exact(&mut req).is_err() {
                            return;
                        }
                        let replies = r(true, &req);
                        if replies.is_empty() {
                            std::thread::sleep(Duration::from_secs(5));
                        }
                        for reply in replies {
                            let mut f = (reply.len() as u16).to_be_bytes().to_vec();
                            f.extend_from_slice(&reply);
                            let _ = s.write_all(&f);
                        }
                    });
                }
            });
        }
        return port;
    }
}

fn n(s: &str) -> Name {
    Name::from_str(s).unwrap()
}

fn a(name: &str, ip: &str) -> Record {
    Record::from_rdata(n(name), 300, RData::A(A(ip.parse().unwrap())))
}

fn soa() -> Record {
    Record::from_rdata(
        n("example.com."),
        3600,
        RData::SOA(SOA::new(
            n("ns1.example.com."),
            n("hostmaster.example.com."),
            7,
            7200,
            3600,
            1209600,
            300,
        )),
    )
}

fn reply(req: &[u8]) -> (Message, Message) {
    let m = Message::from_vec(req).unwrap();
    let mut r = Message::new();
    r.set_id(m.id())
        .set_message_type(MessageType::Response)
        .set_op_code(m.op_code())
        .add_queries(m.queries().to_vec());
    (m, r)
}

/// example.com. data, plus referrals at "." and "com." when `level` says
/// this server is the root (0) or the com. server (1).
fn server(level: u8) -> Responder {
    Arc::new(move |_, req| {
        let (m, mut r) = reply(req);
        let q = &m.queries()[0];
        let name = q.name().to_string();
        match level {
            0 => {
                r.add_name_server(Record::from_rdata(
                    n("com."),
                    3600,
                    RData::NS(NS(n("a.gtld.test."))),
                ));
                r.add_additional(a("a.gtld.test.", "127.0.0.2"));
            }
            1 => {
                r.add_name_server(Record::from_rdata(
                    n("example.com."),
                    3600,
                    RData::NS(NS(n("ns1.example.com."))),
                ));
                r.add_additional(a("ns1.example.com.", "127.0.0.3"));
            }
            _ => {
                r.set_authoritative(true);
                match (name.as_str(), q.query_type()) {
                    ("example.com.", RecordType::MX) => {
                        r.add_answer(Record::from_rdata(
                            n("example.com."),
                            3600,
                            RData::MX(MX::new(10, n("mail.example.com."))),
                        ));
                        r.add_additional(a("mail.example.com.", "192.0.2.25"));
                    }
                    ("example.com.", RecordType::A) | ("www.example.com.", RecordType::A) => {
                        r.add_answer(a(&name, "192.0.2.10"));
                    }
                    ("mail.example.com.", RecordType::A) => {
                        r.add_answer(a(&name, "192.0.2.25"));
                    }
                    ("example.com.", RecordType::AXFR) => {
                        let records = [soa(), a("www.example.com.", "192.0.2.10"), soa()];
                        return records
                            .chunks(2)
                            .map(|c| {
                                let (_, mut r) = reply(req);
                                r.set_authoritative(true);
                                r.add_answers(c.to_vec());
                                r.to_vec().unwrap()
                            })
                            .collect();
                    }
                    (_, RecordType::AAAA) | ("example.com.", _) => {
                        r.add_name_server(soa());
                    }
                    _ => {
                        r.set_response_code(ResponseCode::NXDomain);
                        r.add_name_server(soa());
                    }
                }
            }
        }
        vec![r.to_vec().unwrap()]
    })
}

/// The fake hierarchy: root .1, com. .2, example.com. .3 (one port).
fn hierarchy() -> String {
    let ips: Vec<Ipv4Addr> = (1..=3).map(|i| Ipv4Addr::new(127, 0, 0, i)).collect();
    serve(&ips, vec![server(0), server(1), server(2)]).to_string()
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| panic!("{e}: {}", self.stdout))
    }
}

fn resh(dir: &std::path::Path, args: &[&str]) -> Out {
    let out = assert_cmd::cargo::cargo_bin_cmd!("resh")
        .current_dir(dir)
        .env("HOME", dir)
        .env_remove("SSH_AUTH_SOCK")
        .args(args)
        .timeout(Duration::from_secs(30))
        .output()
        .unwrap();
    Out {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Where the example.com. data server lives for `lookup`/`resolve`.
fn data_args(port: &str) -> Vec<String> {
    vec!["servers=127.0.0.3".into(), format!("port={port}")]
}

fn run(dir: &std::path::Path, stage: &str, args: &[String]) -> Out {
    let mut v: Vec<&str> = vec![stage];
    v.extend(args.iter().map(String::as_str));
    resh(dir, &v)
}

#[test]
fn lookup_succeeds_and_maps_failures_to_exit_codes() {
    let tmp = TempDir::new().unwrap();
    let port = hierarchy();
    let mut args = data_args(&port);
    args.extend(["name=example.com".into(), "rtype=MX".into()]);
    let r = run(tmp.path(), "dns://.lookup", &args);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let v = r.json();
    assert_eq!(v["answers"][0]["data"]["exchange"], "mail.example.com.");
    assert_eq!(v["additional"][0]["data"]["address"], "192.0.2.25");
    assert_eq!(v["response"]["authoritative"], true);

    let mut args = data_args(&port);
    args.push("name=nope.example.com".into());
    let r = run(tmp.path(), "dns://.lookup", &args);
    assert_eq!(r.code, 1);
    assert_eq!(r.json()["error"]["code"], "dns.lookup_nxdomain");
    assert!(
        r.stderr.starts_with("Error: [dns.lookup_nxdomain] "),
        "{}",
        r.stderr
    );

    // Usage error: exit 2, nothing on stdout.
    let r = resh(
        tmp.path(),
        &["dns://.lookup", "name=example.com", "rtpye=MX"],
    );
    assert_eq!(r.code, 2);
    assert_eq!(r.stdout, "");
    assert!(
        r.stderr.starts_with("Error: [dns.unknown_argument] "),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("did you mean `rtype`?"));

    // Timeout: exit 124.
    let silent = serve(&[Ipv4Addr::LOCALHOST], vec![Arc::new(|_, _| vec![])]).to_string();
    let r = resh(
        tmp.path(),
        &[
            "dns://.lookup",
            "name=x.test",
            "servers=127.0.0.1",
            &format!("port={silent}"),
            "timeout_ms=100",
            "retries=0",
        ],
    );
    assert_eq!(r.code, 124);
    assert_eq!(r.json()["error"]["code"], "dns.lookup_timeout");
}

#[test]
fn resolve_host_and_mail() {
    let tmp = TempDir::new().unwrap();
    let port = hierarchy();
    let mut args = data_args(&port);
    args.extend(["name=www.example.com".into(), "family=ipv4".into()]);
    let r = run(tmp.path(), "dns://.resolve", &args);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.json()["resolution"]["addresses"][0]["ip"], "192.0.2.10");
    let mut args = data_args(&port);
    args.extend(["name=example.com".into(), "mode=mail".into()]);
    let r = run(tmp.path(), "dns://.resolve", &args);
    assert_eq!(r.code, 0);
    assert_eq!(
        r.json()["resolution"]["mx"][0]["addresses"][0]["ip"],
        "192.0.2.25"
    );
    let r = resh(
        tmp.path(),
        &[
            "dns://.resolve",
            "name=www.example.com",
            "validate_reverse=true",
        ],
    );
    assert_eq!(r.code, 2);
}

#[test]
fn trace_walks_the_fake_hierarchy() {
    let tmp = TempDir::new().unwrap();
    let port = hierarchy();
    let r = resh(
        tmp.path(),
        &[
            "dns://.trace",
            "name=www.example.com",
            "root_servers=127.0.0.1",
            &format!("port={port}"),
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stdout);
    let v = r.json();
    assert_eq!(v["trace"]["depth"], 3);
    assert_eq!(
        v["trace"]["final_answers"][0]["data"]["address"],
        "192.0.2.10"
    );
    let r = resh(tmp.path(), &["dns://.trace", "name=x.test", "max_depth=0"]);
    assert_eq!(r.code, 2);
    assert!(r.stderr.contains("[dns.trace_invalid_max_depth]"));
}

#[test]
fn zone_fetch_transfers_and_refuses_bad_input() {
    let tmp = TempDir::new().unwrap();
    let port = hierarchy();
    let r = resh(
        tmp.path(),
        &[
            "dns://.zone.fetch",
            "zone=example.com",
            "servers=127.0.0.3",
            &format!("port={port}"),
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stdout);
    let v = r.json();
    assert_eq!(v["zone"]["record_count"], 2);
    assert_eq!(v["zone"]["serial"], 7);
    let r = resh(
        tmp.path(),
        &["dns://.zone.fetch", "zone=example.com", "use_tcp=false"],
    );
    assert_eq!(r.code, 2);
    assert!(r.stderr.contains("[dns.zone_fetch_tcp_required]"));
}

#[test]
fn zone_update_dry_run_and_strict_arguments() {
    let tmp = TempDir::new().unwrap();
    let r = resh(
        tmp.path(),
        &[
            "dns://.zone.update",
            "zone=example.com",
            "servers=192.0.2.53",
            "dry_run=yes",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.json()["summary"]["dry_run"], true);
    let r = resh(
        tmp.path(),
        &[
            "dns://.zone.update",
            "zone=example.com",
            "use_tcp=sometimes",
        ],
    );
    assert_eq!(r.code, 2);
    assert!(r.stderr.starts_with("Error: [dns.invalid_argument] "));
}

// ------------------------------------------------------------------ help --

const VERBS: [&str; 5] = ["lookup", "resolve", "trace", "zone.fetch", "zone.update"];

fn golden(verb: &str) -> &'static str {
    match verb {
        "lookup" => include_str!("golden/dns_lookup_help.txt"),
        "resolve" => include_str!("golden/dns_resolve_help.txt"),
        "trace" => include_str!("golden/dns_trace_help.txt"),
        "zone.fetch" => include_str!("golden/dns_zone_fetch_help.txt"),
        "zone.update" => include_str!("golden/dns_zone_update_help.txt"),
        _ => unreachable!(),
    }
}

fn usage_section(help: &str) -> &str {
    let start = help.find("\nUsage:\n").unwrap() + 8;
    let end = help[start..]
        .find("\n\n")
        .map(|e| start + e)
        .unwrap_or(help.len());
    &help[start..end]
}

fn usage_options(usage: &str) -> Vec<String> {
    let mut v: Vec<String> = usage
        .split(|c: char| c.is_whitespace() || c == '[' || c == ']')
        .filter_map(|w| w.split_once('=').map(|(k, _)| k.to_string()))
        .filter(|k| !k.is_empty())
        .collect();
    v.sort();
    v.dedup();
    v
}

#[test]
fn handle_help_matches_golden() {
    let tmp = TempDir::new().unwrap();
    let r = resh(tmp.path(), &["dns", "--help"]);
    assert_eq!(r.code, 0);
    assert_eq!(r.stdout, include_str!("golden/dns_help.txt"));
    assert_eq!(resh(tmp.path(), &["dns", "-h"]).stdout, r.stdout);
    assert_eq!(resh(tmp.path(), &["dns", "help"]).stdout, r.stdout);
}

#[test]
fn verb_help_matches_golden_and_lists_every_option() {
    let tmp = TempDir::new().unwrap();
    for verb in VERBS {
        let r = resh(tmp.path(), &["dns", verb, "--help"]);
        assert_eq!(r.code, 0, "{verb}");
        assert_eq!(r.stderr, "");
        assert!(r.stdout.is_ascii());
        assert!(r.stdout.lines().all(|l| l.len() <= 80), "{verb}");
        assert!(
            r.stdout
                .starts_with(&format!("Handle: dns\nVerb: {verb}\nDefinition: "))
        );
        for section in ["\nUsage:\n", "\nExample:\n", "\nExample Output:\n"] {
            assert!(r.stdout.contains(section), "{verb}: {section:?}");
        }
        assert_eq!(r.stdout, golden(verb), "{verb}: help differs from golden");
        let mut want: Vec<String> = verb_options(verb)
            .unwrap()
            .iter()
            .map(|s| s.to_string())
            .collect();
        want.sort();
        assert_eq!(usage_options(usage_section(&r.stdout)), want, "{verb}");
        assert_eq!(
            resh(tmp.path(), &[&format!("dns://--help={verb}")]).stdout,
            r.stdout
        );
        assert_eq!(
            resh(tmp.path(), &[&format!("dns://.{verb}(help=1)")]).stdout,
            r.stdout
        );
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
        Value::Array(a) => a.iter().for_each(|v| shape(v, &format!("{prefix}[]"), out)),
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

/// Each help example runs (pointed at the fake servers) and prints JSON of
/// the same shape as its sample output.
#[test]
fn help_examples_run_and_match_their_sample_output() {
    let tmp = TempDir::new().unwrap();
    let port = hierarchy();
    for verb in VERBS {
        let help = resh(tmp.path(), &["dns", verb, "--help"]).stdout;
        let example = help
            .split("\nExample:\n")
            .nth(1)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .trim();
        let mut words: Vec<String> = example
            .split_whitespace()
            .skip(1)
            .map(String::from)
            .collect();
        // Point the example at the fake servers.
        words.retain(|w| !w.starts_with("servers="));
        match verb {
            "trace" => words.push("root_servers=127.0.0.1".into()),
            _ => words.push("servers=127.0.0.3".into()),
        }
        words.push(format!("port={port}"));
        let args: Vec<&str> = words.iter().map(String::as_str).collect();
        let r = resh(tmp.path(), &args);
        assert_eq!(r.code, 0, "{verb}: {example}: {}{}", r.stdout, r.stderr);
        let sample_text = help.split("\nExample Output:\n").nth(1).unwrap();
        let sample_json: String = sample_text
            .split("\n\n")
            .next()
            .unwrap()
            .lines()
            .map(|l| l.strip_prefix("  ").unwrap_or(l))
            .collect::<Vec<_>>()
            .join("\n");
        let sample: Value =
            serde_json::from_str(&sample_json).unwrap_or_else(|e| panic!("{verb}: {e}"));
        let mut actual = shape_of(&r.json());
        // The trace sample shows only the root hop, which has no answers.
        actual.retain(|k| !k.starts_with(".trace.hops[].answers[]"));
        // Record data fields depend on the record type.
        let mut expected = shape_of(&sample);
        for v in [&mut actual, &mut expected] {
            v.retain(|k| !k.starts_with(".zone.records[].data."));
        }
        assert_eq!(actual, expected, "{verb}");
    }
}
