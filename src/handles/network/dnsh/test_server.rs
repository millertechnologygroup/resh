//! In-process fake DNS servers for the verb tests: UDP and TCP on the
//! same 127.0.0.x address and port, answering from a closure. Includes an
//! authoritative responder built from zone data (referrals with glue,
//! CNAMEs, NXDOMAIN and NODATA), AXFR/IXFR responders, and a server-side
//! TSIG signer written from RFC 8945 independently of the client code.

use hmac::Mac;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use trust_dns_proto::op::{Message, MessageType, OpCode, ResponseCode};
use trust_dns_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT};
use trust_dns_proto::rr::{Name, RData, Record, RecordType};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Transport {
    Udp,
    Tcp,
}

/// Returns the messages to send back (none: stay silent).
pub type Responder = Arc<dyn Fn(Transport, &[u8]) -> Vec<Vec<u8>> + Send + Sync>;

pub fn responder(
    f: impl Fn(Transport, &[u8]) -> Vec<Vec<u8>> + Send + Sync + 'static,
) -> Responder {
    Arc::new(f)
}

pub struct Fake {
    pub port: u16,
    requests: Arc<Mutex<Vec<(Transport, Vec<u8>)>>>,
    connections: Arc<Mutex<usize>>,
}

impl Fake {
    /// A server on 127.0.0.1 with a free port.
    pub fn start(r: Responder) -> Fake {
        start_many(&[Ipv4Addr::LOCALHOST], vec![r]).remove(0)
    }

    pub fn requests(&self) -> Vec<(Transport, Vec<u8>)> {
        self.requests.lock().unwrap().clone()
    }

    pub fn tcp_connections(&self) -> usize {
        *self.connections.lock().unwrap()
    }

    pub fn port_str(&self) -> String {
        self.port.to_string()
    }
}

fn bind_all(ips: &[Ipv4Addr]) -> (u16, Vec<(UdpSocket, TcpListener)>) {
    'outer: loop {
        let first = UdpSocket::bind((ips[0], 0)).unwrap();
        let port = first.local_addr().unwrap().port();
        let mut socks = Vec::new();
        let mut first = Some(first);
        for ip in ips {
            let udp = match first.take() {
                Some(u) => u,
                None => match UdpSocket::bind((*ip, port)) {
                    Ok(u) => u,
                    Err(_) => continue 'outer,
                },
            };
            let Ok(tcp) = TcpListener::bind((*ip, port)) else {
                continue 'outer;
            };
            socks.push((udp, tcp));
        }
        return (port, socks);
    }
}

/// Servers on each of `ips` (127.0.0.x), all on the same port.
pub fn start_many(ips: &[Ipv4Addr], responders: Vec<Responder>) -> Vec<Fake> {
    let (port, socks) = bind_all(ips);
    let mut out = Vec::new();
    for ((udp, tcp), resp) in socks.into_iter().zip(responders) {
        let requests: Arc<Mutex<Vec<(Transport, Vec<u8>)>>> = Arc::default();
        let connections: Arc<Mutex<usize>> = Arc::default();
        let (reqs, r) = (requests.clone(), resp.clone());
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65535];
            while let Ok((len, peer)) = udp.recv_from(&mut buf) {
                let req = buf[..len].to_vec();
                reqs.lock().unwrap().push((Transport::Udp, req.clone()));
                for reply in r(Transport::Udp, &req) {
                    let _ = udp.send_to(&reply, peer);
                }
            }
        });
        let (reqs, r, conns) = (requests.clone(), resp, connections.clone());
        std::thread::spawn(move || {
            for stream in tcp.incoming() {
                let Ok(mut stream) = stream else { continue };
                *conns.lock().unwrap() += 1;
                let (reqs, r) = (reqs.clone(), r.clone());
                std::thread::spawn(move || {
                    let mut len = [0u8; 2];
                    if stream.read_exact(&mut len).is_err() {
                        return;
                    }
                    let mut req = vec![0u8; u16::from_be_bytes(len) as usize];
                    if stream.read_exact(&mut req).is_err() {
                        return;
                    }
                    reqs.lock().unwrap().push((Transport::Tcp, req.clone()));
                    let replies = r(Transport::Tcp, &req);
                    if replies.is_empty() {
                        // Silent: hold the connection open for a while.
                        std::thread::sleep(std::time::Duration::from_secs(5));
                        return;
                    }
                    for reply in replies {
                        let mut framed = (reply.len() as u16).to_be_bytes().to_vec();
                        framed.extend_from_slice(&reply);
                        if stream.write_all(&framed).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        out.push(Fake {
            port,
            requests,
            connections,
        });
    }
    out
}

// ---------------------------------------------------------------- records --

pub fn n(s: &str) -> Name {
    Name::from_str(s).unwrap()
}

pub fn rec(name: &str, ttl: u32, data: RData) -> Record {
    Record::from_rdata(n(name), ttl, data)
}

pub fn a(name: &str, ip: &str) -> Record {
    rec(name, 300, RData::A(A(ip.parse().unwrap())))
}

pub fn aaaa(name: &str, ip: &str) -> Record {
    rec(name, 300, RData::AAAA(AAAA(ip.parse().unwrap())))
}

pub fn ns(name: &str, target: &str) -> Record {
    rec(name, 3600, RData::NS(NS(n(target))))
}

pub fn cname(name: &str, target: &str) -> Record {
    rec(name, 60, RData::CNAME(CNAME(n(target))))
}

pub fn mx(name: &str, pref: u16, target: &str) -> Record {
    rec(name, 3600, RData::MX(MX::new(pref, n(target))))
}

pub fn srv(name: &str, prio: u16, weight: u16, port: u16, target: &str) -> Record {
    rec(
        name,
        60,
        RData::SRV(SRV::new(prio, weight, port, n(target))),
    )
}

pub fn ptr(name: &str, target: &str) -> Record {
    rec(name, 60, RData::PTR(PTR(n(target))))
}

pub fn txt(name: &str, text: &str) -> Record {
    rec(name, 60, RData::TXT(TXT::new(vec![text.to_string()])))
}

pub fn soa(zone: &str, serial: u32) -> Record {
    let zone_part = if zone == "." { "" } else { zone };
    rec(
        zone,
        3600,
        RData::SOA(SOA::new(
            n(&format!("ns1.{zone_part}")),
            n(&format!("hostmaster.{zone_part}")),
            serial,
            7200,
            3600,
            1_209_600,
            300,
        )),
    )
}

// --------------------------------------------------------------- replies --

pub fn parse(req: &[u8]) -> Message {
    let (stripped, _) = super::split_trailing_tsig(req).unwrap();
    Message::from_vec(&stripped).unwrap()
}

/// An empty reply to `req` with `rcode`.
pub fn reply_to(req: &Message, rcode: ResponseCode) -> Message {
    let mut r = Message::new();
    r.set_id(req.id())
        .set_message_type(MessageType::Response)
        .set_op_code(req.op_code())
        .set_recursion_desired(req.recursion_desired())
        .set_response_code(rcode)
        .add_queries(req.queries().to_vec());
    r
}

pub fn fixed_rcode(rcode: ResponseCode) -> Responder {
    responder(move |_, req| vec![reply_to(&parse(req), rcode).to_vec().unwrap()])
}

pub fn silent() -> Responder {
    responder(|_, _| vec![])
}

/// Zone data: an origin and its records (apex SOA/NS, delegations with
/// glue, anything else).
#[derive(Clone)]
pub struct Zone {
    pub origin: Name,
    pub records: Vec<Record>,
}

pub fn zone(origin: &str, records: Vec<Record>) -> Zone {
    Zone {
        origin: n(origin),
        records,
    }
}

/// Answers authoritatively for `zones` (the deepest zone containing the
/// name), with referrals at delegation points. Over UDP, a reply over 512
/// bytes is replaced by an empty truncated one.
pub fn authoritative(zones: Vec<Zone>) -> Responder {
    responder(move |t, req| {
        let m = parse(req);
        let reply = answer(&zones, &m);
        let wire = reply.to_vec().unwrap();
        if t == Transport::Udp && wire.len() > 512 {
            let mut tc = reply_to(&m, ResponseCode::NoError);
            tc.set_truncated(true);
            return vec![tc.to_vec().unwrap()];
        }
        vec![wire]
    })
}

fn glue_for(z: &Zone, targets: &[Name]) -> Vec<Record> {
    z.records
        .iter()
        .filter(|r| {
            matches!(r.record_type(), RecordType::A | RecordType::AAAA)
                && targets.iter().any(|t| t == r.name())
        })
        .cloned()
        .collect()
}

pub fn answer(zones: &[Zone], m: &Message) -> Message {
    let q = &m.queries()[0];
    let (name, qtype) = (q.name().clone(), q.query_type());
    let Some(z) = zones
        .iter()
        .filter(|z| z.origin.zone_of(&name))
        .max_by_key(|z| z.origin.num_labels())
    else {
        return reply_to(m, ResponseCode::Refused);
    };
    let mut r = reply_to(m, ResponseCode::NoError);
    // Delegation below the origin on the way to the name?
    let cut = z
        .records
        .iter()
        .filter(|rec| {
            rec.record_type() == RecordType::NS
                && rec.name() != &z.origin
                && rec.name().zone_of(&name)
        })
        .map(|rec| rec.name().clone())
        .max_by_key(|c| c.num_labels());
    if let Some(cut) = cut {
        let nsr: Vec<Record> = z
            .records
            .iter()
            .filter(|rec| rec.record_type() == RecordType::NS && rec.name() == &cut)
            .cloned()
            .collect();
        let targets: Vec<Name> = nsr
            .iter()
            .filter_map(|r| match r.data() {
                Some(RData::NS(t)) => Some(t.0.clone()),
                _ => None,
            })
            .collect();
        r.add_name_servers(nsr);
        r.add_additionals(glue_for(z, &targets));
        return r;
    }
    r.set_authoritative(true);
    let soa_rec: Vec<Record> = z
        .records
        .iter()
        .filter(|rec| rec.record_type() == RecordType::SOA)
        .cloned()
        .collect();
    let mut qname = name.clone();
    for _ in 0..10 {
        let at: Vec<&Record> = z
            .records
            .iter()
            .filter(|rec| rec.name() == &qname)
            .collect();
        if at.is_empty() {
            let exists_below = z.records.iter().any(|rec| qname.zone_of(rec.name()));
            if qname == name && !exists_below {
                r.set_response_code(ResponseCode::NXDomain);
            }
            if r.answers().is_empty() || qname == name {
                r.add_name_servers(soa_rec.clone());
            }
            return r;
        }
        let matching: Vec<Record> = at
            .iter()
            .filter(|rec| qtype == RecordType::ANY || rec.record_type() == qtype)
            .map(|rec| (*rec).clone())
            .collect();
        if !matching.is_empty() {
            let targets: Vec<Name> = matching
                .iter()
                .filter_map(|rec| match rec.data() {
                    Some(RData::MX(x)) => Some(x.exchange().clone()),
                    Some(RData::SRV(x)) => Some(x.target().clone()),
                    Some(RData::NS(x)) => Some(x.0.clone()),
                    _ => None,
                })
                .collect();
            r.add_answers(matching);
            r.add_additionals(glue_for(z, &targets));
            return r;
        }
        let cn = at.iter().find_map(|rec| match rec.data() {
            Some(RData::CNAME(c)) if qtype != RecordType::CNAME => {
                Some(((*rec).clone(), c.0.clone()))
            }
            _ => None,
        });
        match cn {
            Some((rec, target)) => {
                r.add_answer(rec);
                if !z.origin.zone_of(&target) {
                    return r;
                }
                qname = target;
            }
            None => {
                r.add_name_servers(soa_rec.clone());
                return r;
            }
        }
    }
    r
}

// ------------------------------------------------------------------ TSIG --

pub const KEY_B64: &str = "c2VjcmV0LWtleS1ieXRlcy0xMjM0NTY3ODkwYWJjZGVm";
pub const KEY_NAME: &str = "tsig-key.example";
const KEY_WIRE: &[u8] = b"\x08tsig-key\x07example\x00";
const ALG_WIRE: &[u8] = b"\x0bhmac-sha256\x00";

fn hmac256(data: &[u8]) -> Vec<u8> {
    use base64::Engine as _;
    let secret = base64::engine::general_purpose::STANDARD
        .decode(KEY_B64)
        .unwrap();
    let mut m =
        <hmac::Hmac<sha2::Sha256> as hmac::digest::KeyInit>::new_from_slice(&secret).unwrap();
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The request's TSIG MAC, checked as a server would (RFC 8945 4.3.3).
pub fn verify_request(req: &[u8]) -> Vec<u8> {
    let (stripped, tsig) = super::split_trailing_tsig(req).unwrap();
    let tsig = tsig.expect("request must be TSIG-signed");
    let mut data = stripped;
    data.extend_from_slice(&variables(tsig.time_signed, 0));
    assert_eq!(hmac256(&data), tsig.mac, "request MAC does not verify");
    tsig.mac
}

fn variables(time: u64, error: u16) -> Vec<u8> {
    let mut v = KEY_WIRE.to_vec();
    v.extend_from_slice(&[0x00, 0xFF, 0, 0, 0, 0]);
    v.extend_from_slice(ALG_WIRE);
    v.extend_from_slice(&time.to_be_bytes()[2..]);
    v.extend_from_slice(&[0x01, 0x2C]);
    v.extend_from_slice(&error.to_be_bytes());
    v.extend_from_slice(&[0, 0]);
    v
}

fn append_tsig(msg: &mut Vec<u8>, mac: &[u8], time: u64, error: u16) {
    let mut rdata = ALG_WIRE.to_vec();
    rdata.extend_from_slice(&time.to_be_bytes()[2..]);
    rdata.extend_from_slice(&[0x01, 0x2C]);
    rdata.extend_from_slice(&(mac.len() as u16).to_be_bytes());
    rdata.extend_from_slice(mac);
    rdata.extend_from_slice(&msg[0..2]);
    rdata.extend_from_slice(&error.to_be_bytes());
    rdata.extend_from_slice(&[0, 0]);
    let mut rr = KEY_WIRE.to_vec();
    rr.extend_from_slice(&[0x00, 0xFA, 0x00, 0xFF, 0, 0, 0, 0]);
    rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    rr.extend_from_slice(&rdata);
    msg.extend_from_slice(&rr);
    let ar = u16::from_be_bytes([msg[10], msg[11]]) + 1;
    msg[10..12].copy_from_slice(&ar.to_be_bytes());
}

/// How to sign a multi-message reply.
#[derive(Clone, Copy, Debug)]
pub enum Signing {
    None,
    /// Sign message i when `i % every == 0` or it is the last message.
    Every(usize),
    /// Like `Every`, but the last message is left unsigned.
    LastUnsigned(usize),
    /// Sign every message but flip a bit in message `i`'s MAC.
    CorruptAt(usize),
    /// Reply with a TSIG error (BADKEY = 17) and no MAC.
    Error(u16),
}

/// Signs `msgs` (a reply to a request with MAC `req_mac`) per RFC 8945
/// section 5.3.1: the first signed message covers the request MAC and the
/// full variables, later ones the prior MAC, the unsigned messages since
/// then and the timers.
pub fn sign_stream(msgs: Vec<Vec<u8>>, req_mac: &[u8], how: Signing) -> Vec<Vec<u8>> {
    let time = now();
    let count = msgs.len();
    let mut prior = req_mac.to_vec();
    let mut pending: Vec<u8> = Vec::new();
    let mut out = Vec::new();
    for (i, mut m) in msgs.into_iter().enumerate() {
        let last = i + 1 == count;
        let sign = match how {
            Signing::None => false,
            Signing::Every(k) => i % k == 0 || last,
            Signing::LastUnsigned(k) => !last && i % k == 0,
            Signing::CorruptAt(_) => true,
            Signing::Error(_) => i == 0,
        };
        if !sign {
            pending.extend_from_slice(&m);
            out.push(m);
            continue;
        }
        if let Signing::Error(code) = how {
            append_tsig(&mut m, &[], time, code);
            out.push(m);
            continue;
        }
        let mut data = (prior.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&prior);
        data.extend_from_slice(&pending);
        data.extend_from_slice(&m);
        if i == 0 {
            data.extend_from_slice(&variables(time, 0));
        } else {
            data.extend_from_slice(&time.to_be_bytes()[2..]);
            data.extend_from_slice(&[0x01, 0x2C]);
        }
        let mut mac = hmac256(&data);
        prior = mac.clone();
        if matches!(how, Signing::CorruptAt(c) if c == i) {
            mac[0] ^= 1;
        }
        append_tsig(&mut m, &mac, time, 0);
        pending.clear();
        out.push(m);
    }
    out
}

/// AXFR messages for `records` (SOA first), `per_msg` records each,
/// closed by the SOA again.
pub fn axfr_messages(req: &Message, records: &[Record], per_msg: usize) -> Vec<Vec<u8>> {
    let mut all = records.to_vec();
    all.push(records[0].clone());
    stream_messages(req, &all, per_msg)
}

pub fn stream_messages(req: &Message, all: &[Record], per_msg: usize) -> Vec<Vec<u8>> {
    all.chunks(per_msg.max(1))
        .map(|chunk| {
            let mut r = reply_to(req, ResponseCode::NoError);
            r.set_authoritative(true);
            r.add_answers(chunk.to_vec());
            r.to_vec().unwrap()
        })
        .collect()
}

/// A responder for zone transfers: AXFR of `records`, and IXFR answered
/// with `ixfr` (records after the leading SOA) when given, else AXFR.
pub fn xfr_server(
    records: Vec<Record>,
    ixfr: Option<Vec<Record>>,
    per_msg: usize,
    signing: Signing,
) -> Responder {
    responder(move |t, req| {
        if t == Transport::Udp {
            return vec![];
        }
        let m = parse(req);
        let qtype = m.queries()[0].query_type();
        let msgs = match (qtype, &ixfr) {
            (RecordType::IXFR, Some(diff)) => stream_messages(&m, diff, per_msg),
            (RecordType::AXFR | RecordType::IXFR, _) => axfr_messages(&m, &records, per_msg),
            _ => vec![reply_to(&m, ResponseCode::NotImp).to_vec().unwrap()],
        };
        match signing {
            Signing::None => msgs,
            how => sign_stream(msgs, &verify_request(req), how),
        }
    })
}

#[test]
fn sign_stream_patterns() {
    let req = {
        let mut m = Message::new();
        m.set_id(7).set_op_code(OpCode::Query);
        m
    };
    let msgs = vec![reply_to(&req, ResponseCode::NoError).to_vec().unwrap(); 5];
    let signed = |how| {
        sign_stream(msgs.clone(), &[1, 2, 3], how)
            .iter()
            .map(|m| m[11] == 1)
            .collect::<Vec<_>>()
    };
    assert_eq!(signed(Signing::Every(2)), [true, false, true, false, true]);
    assert_eq!(signed(Signing::Every(1)), [true; 5]);
    assert_eq!(
        signed(Signing::LastUnsigned(2)),
        [true, false, true, false, false]
    );
    assert_eq!(signed(Signing::CorruptAt(3)), [true; 5]);
}
