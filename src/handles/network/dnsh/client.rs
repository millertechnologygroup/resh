//! A small DNS stub client on top of the wire exchange used by
//! `zone.update`: it sends one question to one server (UDP with TCP
//! fallback on truncation, or TCP), checks that the reply answers it, and
//! keeps the whole reply (flags, answer, authority and additional
//! sections, raw bytes) for the verbs to report.

use super::{ExchangeError, PreparedRequest, tcp_exchange, udp_exchange};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use trust_dns_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use trust_dns_proto::rr::{Name, RecordType};

/// How each query is sent.
#[derive(Debug, Clone)]
pub struct QueryConfig {
    pub use_tcp: bool,
    /// Per attempt.
    pub timeout: Duration,
    /// Extra attempts per server after a timeout or network error.
    pub retries: u32,
    /// Send EDNS0 with the DO bit.
    pub dnssec: bool,
    /// The RD flag (true for stub lookups, false for a trace).
    pub recursion_desired: bool,
}

/// One answered query.
#[derive(Debug, Clone)]
pub struct Exchange {
    pub server: SocketAddr,
    pub message: Message,
    pub wire: Vec<u8>,
    pub rtt_ms: u64,
}

impl Exchange {
    pub fn rcode(&self) -> ResponseCode {
        self.message.response_code()
    }
}

/// Builds the query message for `name`/`rtype`.
fn build_query(
    name: &Name,
    rtype: RecordType,
    cfg: &QueryConfig,
) -> Result<PreparedRequest, ExchangeError> {
    let mut message = Message::new();
    let id: u16 = rand::random();
    message
        .set_id(id)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(cfg.recursion_desired)
        .add_query(Query::query(name.clone(), rtype));
    if cfg.dnssec {
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true).set_max_payload(1232);
        message.set_edns(edns);
    }
    let wire = message
        .to_vec()
        .map_err(|e| ExchangeError::network(format!("cannot encode query: {e}")))?;
    Ok(PreparedRequest {
        wire,
        id,
        mac: None,
    })
}

/// Sends one question to `addr` (`retries + 1` attempts on timeouts and
/// network errors) and returns the checked reply.
pub async fn query_one(
    addr: SocketAddr,
    name: &Name,
    rtype: RecordType,
    cfg: &QueryConfig,
) -> Result<Exchange, ExchangeError> {
    let request = build_query(name, rtype, cfg)?;
    let mut last_error = None;
    for _ in 0..=cfg.retries {
        let start = Instant::now();
        let reply = if cfg.use_tcp {
            tcp_exchange(addr, &request, cfg.timeout).await
        } else {
            match udp_exchange(addr, &request, cfg.timeout).await {
                Ok(r) if r.len() > 2 && r[2] & 0x02 != 0 => {
                    tcp_exchange(addr, &request, cfg.timeout).await
                }
                other => other,
            }
        };
        let wire = match reply {
            Ok(w) => w,
            Err(e) => {
                last_error = Some(e);
                continue;
            }
        };
        let rtt_ms = start.elapsed().as_millis() as u64;
        let message = Message::from_vec(&wire)
            .map_err(|e| ExchangeError::network(format!("{addr}: unparsable reply: {e}")))?;
        let answers_question = message.message_type() == MessageType::Response
            && message.id() == request.id
            && message.queries().len() == 1
            && message.queries()[0].query_type() == rtype
            && message.queries()[0].name() == name;
        if !answers_question {
            // A reply with an empty question section is allowed for errors.
            let header_only = message.queries().is_empty()
                && message.id() == request.id
                && message.response_code() != ResponseCode::NoError;
            if !header_only {
                return Err(ExchangeError::network(format!(
                    "{addr}: the reply does not answer the question"
                )));
            }
        }
        return Ok(Exchange {
            server: addr,
            message,
            wire,
            rtt_ms,
        });
    }
    Err(last_error.unwrap_or_else(|| ExchangeError::network("no attempt was made")))
}

/// The outcome of asking a list of servers.
#[derive(Debug, Default)]
pub struct SetResult {
    pub reply: Option<Exchange>,
    pub failures: Vec<ExchangeError>,
    pub warnings: Vec<String>,
}

impl SetResult {
    /// True when no server answered and every failure was a timeout.
    pub fn all_timed_out(&self) -> bool {
        self.reply.is_none() && !self.failures.is_empty() && self.failures.iter().all(|f| f.timeout)
    }
}

/// Is `rcode` a server-side failure worth trying another server for?
fn try_next_on(rcode: ResponseCode) -> bool {
    matches!(
        rcode,
        ResponseCode::ServFail
            | ResponseCode::Refused
            | ResponseCode::NotImp
            | ResponseCode::FormErr
    )
}

/// Asks the servers in order. A timeout, network error or a SERVFAIL,
/// REFUSED, NOTIMP or FORMERR answer moves on to the next server (noted in
/// `warnings`); any other answer is returned at once. When every server
/// failed, the last failing DNS answer (if any) is returned as `reply`.
pub async fn query_servers(
    servers: &[SocketAddr],
    name: &Name,
    rtype: RecordType,
    cfg: &QueryConfig,
) -> SetResult {
    let mut result = SetResult::default();
    let mut last_bad: Option<Exchange> = None;
    for &addr in servers {
        match query_one(addr, name, rtype, cfg).await {
            Ok(ex) if try_next_on(ex.rcode()) => {
                result.warnings.push(format!(
                    "server {} answered {} for {} {}",
                    addr.ip(),
                    super::rcode_mnemonic(ex.rcode()),
                    name,
                    rtype
                ));
                last_bad = Some(ex);
            }
            Ok(ex) => {
                result.reply = Some(ex);
                return result;
            }
            Err(e) => {
                result
                    .warnings
                    .push(format!("server {}: {}", addr.ip(), e.message));
                result.failures.push(e);
            }
        }
    }
    result.reply = last_bad;
    result
}

/// The name servers in the host's resolver configuration
/// (`/etc/resolv.conf`), in order and without duplicates.
pub fn system_nameservers() -> anyhow::Result<Vec<IpAddr>> {
    let config = super::system_resolver_config()?;
    let mut ips: Vec<IpAddr> = Vec::new();
    for ns in config.name_servers() {
        let ip = ns.socket_addr.ip();
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    if ips.is_empty() {
        anyhow::bail!("the system resolver configuration lists no name servers");
    }
    Ok(ips)
}

/// Parses a DNS name given by the user (a trailing dot is optional).
pub fn parse_name(name: &str) -> Result<Name, String> {
    let fqdn = if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    };
    if name.contains("..") {
        return Err(format!("invalid DNS name {name:?}: empty label"));
    }
    Name::from_utf8(&fqdn).map_err(|e| format!("invalid DNS name {name:?}: {e}"))
}
