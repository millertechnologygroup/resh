//! The `lookup`, `resolve` and `trace` engines, on the wire client in
//! `client.rs`.

use super::client::{
    Exchange, QueryConfig, SetResult, parse_name, query_one, query_servers, system_nameservers,
};
use super::*;
use std::future::Future;
use std::pin::Pin;
use trust_dns_proto::rr::{Name, Record, RecordType};

/// A failure that ends a verb: error code, message, and whether it was a
/// timeout (exit 124).
#[derive(Debug, Clone)]
pub(super) struct Failure {
    pub code: &'static str,
    pub message: String,
    pub timed_out: bool,
}

impl Failure {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            timed_out: false,
        }
    }
}

/// Maps a set of transport failures to (timeout, network, all-failed).
fn transport_failure(set: &SetResult, codes: [&'static str; 3], what: &str) -> Failure {
    let [timeout, network, all] = codes;
    let timed_out = set.all_timed_out();
    match set.failures.len() {
        0 => Failure::new(all, format!("no name server to ask for {what}")),
        1 => Failure {
            code: if set.failures[0].timeout {
                timeout
            } else {
                network
            },
            message: set.failures[0].message.clone(),
            timed_out,
        },
        n => Failure {
            code: all,
            message: format!("all {n} name servers failed for {what} (see warnings)"),
            timed_out,
        },
    }
}

/// The servers to ask: the given IPs, or the system resolvers, on `port`.
fn server_addrs(servers: &[String], port: u16) -> std::result::Result<Vec<SocketAddr>, String> {
    if servers.is_empty() {
        let ips = system_nameservers().map_err(|e| format!("{e:#}"))?;
        return Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect());
    }
    servers
        .iter()
        .map(|s| {
            s.parse::<IpAddr>()
                .map(|ip| SocketAddr::new(ip, port))
                .map_err(|_| format!("invalid server IP address: {s}"))
        })
        .collect()
}

pub(super) fn to_dns_record(r: &Record) -> DnsRecord {
    let rtype = r.record_type().to_string();
    DnsRecord {
        name: r.name().to_string(),
        class: r.dns_class().to_string(),
        ttl: r.ttl(),
        data: r
            .data()
            .map(|d| rdata_to_json(d, &rtype))
            .unwrap_or_else(|| json!({})),
        rtype,
    }
}

fn to_trace_record(r: &Record) -> DnsTraceRecord {
    let d = to_dns_record(r);
    DnsTraceRecord {
        name: d.name,
        rtype: d.rtype,
        ttl: d.ttl,
        data: d.data,
    }
}

/// The CNAME target owned by `name` in `records`, if any.
fn cname_of(records: &[Record], name: &Name) -> Option<Name> {
    records.iter().find_map(|r| match r.data() {
        Some(RData::CNAME(c)) if r.name() == name => Some(c.0.clone()),
        _ => None,
    })
}

fn has_type(records: &[Record], name: &Name, rtype: RecordType) -> bool {
    records
        .iter()
        .any(|r| r.name() == name && (rtype == RecordType::ANY || r.record_type() == rtype))
}

/// Follows the CNAME chain from `name` inside one answer section.
fn chain_end(records: &[Record], name: &Name, limit: usize) -> (Name, Vec<Name>) {
    let mut cur = name.clone();
    let mut chain = Vec::new();
    while let Some(target) = cname_of(records, &cur) {
        if chain.contains(&target) || chain.len() >= limit {
            break;
        }
        chain.push(target.clone());
        cur = target;
    }
    (cur, chain)
}

fn rcode_failure_lookup(rcode: ResponseCode, name: &str) -> Failure {
    let mnemonic = rcode_mnemonic(rcode);
    let (code, message) = match rcode {
        ResponseCode::NXDomain => (
            DNS_LOOKUP_NXDOMAIN,
            format!("{name} does not exist (NXDOMAIN)"),
        ),
        ResponseCode::ServFail => (DNS_LOOKUP_SERVFAIL, "server failure (SERVFAIL)".to_string()),
        ResponseCode::Refused => (DNS_LOOKUP_REFUSED, "query refused (REFUSED)".to_string()),
        ResponseCode::FormErr => (DNS_LOOKUP_FORMERR, "format error (FORMERR)".to_string()),
        _ => (
            DNS_LOOKUP_RCODE_ERROR,
            format!("the server answered {mnemonic}"),
        ),
    };
    Failure::new(code, message)
}

fn query_config(
    use_tcp: bool,
    timeout_ms: u64,
    retries: u32,
    dnssec: bool,
    rd: bool,
) -> QueryConfig {
    QueryConfig {
        use_tcp,
        timeout: Duration::from_millis(timeout_ms),
        retries,
        dnssec,
        recursion_desired: rd,
    }
}

// ============================== lookup ==============================

/// Longest CNAME chain `lookup` follows with extra queries.
const MAX_LOOKUP_CNAME_HOPS: usize = 8;

pub(super) async fn perform_dns_lookup(opts: &DnsLookupOptions) -> DnsLookupResponse {
    let mut response = DnsLookupResponse::new(opts);
    if let Err(f) = run_lookup(opts, &mut response).await {
        response.ok = false;
        response.timed_out = f.timed_out;
        response.error = Some((f.code.to_string(), f.message));
    }
    response
}

async fn run_lookup(
    opts: &DnsLookupOptions,
    response: &mut DnsLookupResponse,
) -> std::result::Result<(), Failure> {
    let start = Instant::now();
    let name = parse_name(&opts.name).map_err(|e| Failure::new(DNS_LOOKUP_INVALID_NAME, e))?;
    let mut addrs = server_addrs(&opts.servers, opts.port)
        .map_err(|e| Failure::new(DNS_LOOKUP_NETWORK_ERROR, e))?;
    if opts.randomize_servers {
        addrs.shuffle(&mut rand::thread_rng());
    }
    let rtype = opts.rtype.to_trust_dns();
    let cfg = query_config(
        opts.use_tcp,
        opts.timeout_ms,
        opts.retries,
        opts.dnssec,
        true,
    );
    let mut qname = name;
    let mut visited = vec![qname.clone()];
    let last: Exchange = loop {
        let set = query_servers(&addrs, &qname, rtype, &cfg).await;
        response.warnings.extend(set.warnings.iter().cloned());
        let Some(ex) = set.reply.clone() else {
            return Err(transport_failure(
                &set,
                [
                    DNS_LOOKUP_TIMEOUT,
                    DNS_LOOKUP_NETWORK_ERROR,
                    DNS_LOOKUP_ALL_SERVERS_FAILED,
                ],
                &opts.name,
            ));
        };
        response
            .answers
            .extend(ex.message.answers().iter().map(to_dns_record));
        if ex.rcode() != ResponseCode::NoError
            || !opts.follow_cname
            || matches!(rtype, RecordType::CNAME | RecordType::ANY)
        {
            break ex;
        }
        let (end, _) = chain_end(ex.message.answers(), &qname, MAX_LOOKUP_CNAME_HOPS);
        if end == qname || has_type(ex.message.answers(), &end, rtype) {
            break ex;
        }
        if visited.contains(&end) || visited.len() > MAX_LOOKUP_CNAME_HOPS {
            response.warnings.push(format!(
                "CNAME chain from {} not followed further at {end}",
                opts.name
            ));
            break ex;
        }
        visited.push(end.clone());
        qname = end;
    };
    let msg = &last.message;
    response.response.rcode = rcode_mnemonic(last.rcode());
    response.response.authoritative = msg.authoritative();
    response.response.truncated = msg.truncated();
    response.response.dnssec_validated = opts.dnssec.then(|| msg.authentic_data());
    response.response.server_used = Some(last.server.ip().to_string());
    response.response.round_trip_time_ms = Some(start.elapsed().as_millis() as u64);
    if opts.include_authority {
        response.authority = msg.name_servers().iter().map(to_dns_record).collect();
    }
    if opts.include_additional {
        response.additional = msg.additionals().iter().map(to_dns_record).collect();
    }
    if last.rcode() != ResponseCode::NoError {
        return Err(rcode_failure_lookup(last.rcode(), &opts.name));
    }
    if !response
        .answers
        .iter()
        .any(|r| rtype == RecordType::ANY || r.rtype == opts.rtype.as_str())
    {
        response.warnings.push(format!(
            "no {} records for {} (NOERROR, no data)",
            opts.rtype.as_str(),
            opts.name
        ));
    }
    response.ok = true;
    Ok(())
}

// ============================== resolve ==============================

struct Resolver<'a> {
    opts: &'a DnsResolveOptions,
    addrs: Vec<SocketAddr>,
    cfg: QueryConfig,
    warnings: Vec<String>,
    raw: Vec<Value>,
    source_server: Option<String>,
}

/// Addresses of one host, after CNAMEs.
struct HostAddresses {
    canonical: Option<Name>,
    addresses: Vec<ResolvedAddress>,
    nxdomain: bool,
}

impl Resolver<'_> {
    /// One question to the server set. NOERROR and NXDOMAIN are returned;
    /// any other outcome is a failure.
    async fn ask(
        &mut self,
        name: &Name,
        rtype: RecordType,
    ) -> std::result::Result<Exchange, Failure> {
        let set = query_servers(&self.addrs, name, rtype, &self.cfg).await;
        self.warnings.extend(set.warnings.iter().cloned());
        let Some(ex) = set.reply.clone() else {
            return Err(transport_failure(
                &set,
                [
                    DNS_RESOLVE_TIMEOUT,
                    DNS_RESOLVE_NETWORK_ERROR,
                    DNS_RESOLVE_ALL_SERVERS_FAILED,
                ],
                &format!("{name} {rtype}"),
            ));
        };
        if self.opts.want_raw {
            self.raw.push(json!({
                "server": ex.server.ip().to_string(),
                "name": name.to_string(),
                "rtype": rtype.to_string(),
                "rcode": rcode_mnemonic(ex.rcode()),
                "response_hex": hex::encode(&ex.wire),
            }));
        }
        if self.source_server.is_none() {
            self.source_server = Some(ex.server.ip().to_string());
        }
        match ex.rcode() {
            ResponseCode::NoError | ResponseCode::NXDomain => Ok(ex),
            other => Err(Failure::new(
                DNS_RESOLVE_LOOKUP_ERROR,
                format!(
                    "the server answered {} for {name} {rtype}",
                    rcode_mnemonic(other)
                ),
            )),
        }
    }

    /// A/AAAA for `name` per `family`, following CNAMEs (at most
    /// `max_cname_depth` hops).
    async fn host(
        &mut self,
        name: &Name,
        family: &AddressFamily,
    ) -> std::result::Result<HostAddresses, Failure> {
        let mut out = HostAddresses {
            canonical: None,
            addresses: Vec::new(),
            nxdomain: false,
        };
        let types: &[RecordType] = match family {
            AddressFamily::Any => &[RecordType::AAAA, RecordType::A],
            AddressFamily::Ipv4 => &[RecordType::A],
            AddressFamily::Ipv6 => &[RecordType::AAAA],
        };
        let max = usize::from(self.opts.max_cname_depth);
        for &rtype in types {
            let mut qname = name.clone();
            let mut chain: Vec<Name> = vec![name.clone()];
            loop {
                let ex = self.ask(&qname, rtype).await?;
                if ex.rcode() == ResponseCode::NXDomain {
                    out.nxdomain = true;
                    break;
                }
                let answers = ex.message.answers();
                let mut cur = qname.clone();
                while let Some(target) = cname_of(answers, &cur) {
                    if chain.contains(&target) {
                        return Err(Failure::new(
                            DNS_RESOLVE_CNAME_LOOP,
                            format!("CNAME loop at {target}"),
                        ));
                    }
                    if chain.len() > max {
                        return Err(Failure::new(
                            DNS_RESOLVE_CNAME_LOOP,
                            format!("more than max_cname_depth={max} CNAME hops from {name}"),
                        ));
                    }
                    chain.push(target.clone());
                    cur = target;
                }
                let found: Vec<ResolvedAddress> = answers
                    .iter()
                    .filter(|r| r.name() == &cur)
                    .filter_map(|r| match r.data() {
                        Some(RData::A(a)) => Some(ResolvedAddress {
                            ip: a.to_string(),
                            family: AddressFamily::Ipv4,
                            ttl: Some(r.ttl()),
                        }),
                        Some(RData::AAAA(a)) => Some(ResolvedAddress {
                            ip: a.to_string(),
                            family: AddressFamily::Ipv6,
                            ttl: Some(r.ttl()),
                        }),
                        _ => None,
                    })
                    .collect();
                if found.is_empty() && cur != qname {
                    // The server gave the CNAME but not the target's data.
                    qname = cur;
                    continue;
                }
                if out.canonical.is_none() {
                    out.canonical = Some(cur);
                }
                for a in found {
                    if !out.addresses.iter().any(|b| b.ip == a.ip) {
                        out.addresses.push(a);
                    }
                }
                break;
            }
            if out.nxdomain {
                break;
            }
        }
        Ok(out)
    }

    /// Addresses of an MX or SRV target; a failure becomes a warning.
    async fn target(&mut self, target: &Name) -> Vec<ResolvedAddress> {
        let family = self.opts.family.clone();
        match self.host(target, &family).await {
            Ok(h) => {
                if h.addresses.is_empty() {
                    self.warnings
                        .push(format!("no addresses found for {target}"));
                }
                h.addresses
            }
            Err(f) => {
                self.warnings.push(format!(
                    "cannot resolve {target}: [{}] {}",
                    f.code, f.message
                ));
                Vec::new()
            }
        }
    }
}

fn empty_resolution(opts: &DnsResolveOptions) -> DnsResolution {
    DnsResolution {
        canonical_name: opts.name.clone(),
        mode: opts.mode.clone(),
        family: opts.family.clone(),
        addresses: Vec::new(),
        mx: Vec::new(),
        srv: Vec::new(),
        ptr_name: None,
        forward_addresses: Vec::new(),
        source_server: None,
        round_trip_time_ms: None,
    }
}

pub(super) async fn perform_dns_resolve(opts: &DnsResolveOptions) -> DnsResolveResponse {
    let mut response = DnsResolveResponse::new(opts);
    let start = Instant::now();
    let addrs = match server_addrs(&opts.servers, opts.port) {
        Ok(a) => a,
        Err(e) => {
            response.error = Some((DNS_RESOLVE_NETWORK_ERROR.to_string(), e));
            return response;
        }
    };
    let mut r = Resolver {
        opts,
        addrs,
        cfg: query_config(
            opts.use_tcp,
            opts.timeout_ms,
            opts.retries,
            opts.dnssec,
            true,
        ),
        warnings: Vec::new(),
        raw: Vec::new(),
        source_server: None,
    };
    let result = run_resolve(&mut r).await;
    response.warnings = std::mem::take(&mut r.warnings);
    if opts.want_raw {
        response.raw = Some(json!({ "exchanges": r.raw }));
    }
    match result {
        Ok(mut resolution) => {
            resolution.source_server = r.source_server.clone();
            resolution.round_trip_time_ms = Some(start.elapsed().as_millis() as u64);
            response.ok = true;
            response.resolution = Some(resolution);
        }
        Err(f) => {
            response.ok = false;
            response.timed_out = f.timed_out;
            response.error = Some((f.code.to_string(), f.message));
        }
    }
    response
}

async fn run_resolve(r: &mut Resolver<'_>) -> std::result::Result<DnsResolution, Failure> {
    let opts = r.opts;
    let mut res = empty_resolution(opts);
    match opts.mode {
        ResolveMode::Host => {
            let name =
                parse_name(&opts.name).map_err(|e| Failure::new(DNS_RESOLVE_INVALID_NAME, e))?;
            let h = r.host(&name, &opts.family).await?;
            if h.addresses.is_empty() {
                let why = if h.nxdomain {
                    format!("{} does not exist (NXDOMAIN)", opts.name)
                } else {
                    format!("no addresses found for {}", opts.name)
                };
                return Err(Failure::new(DNS_RESOLVE_HOST_NOT_FOUND, why));
            }
            if let Some(c) = h.canonical.filter(|c| *c != name) {
                res.canonical_name = c.to_string();
            }
            res.addresses = h.addresses;
        }
        ResolveMode::Mail => {
            let name =
                parse_name(&opts.name).map_err(|e| Failure::new(DNS_RESOLVE_INVALID_NAME, e))?;
            let ex = r.ask(&name, RecordType::MX).await?;
            let (end, _) = chain_end(ex.message.answers(), &name, 16);
            let mut mx: Vec<(u16, Name)> = ex
                .message
                .answers()
                .iter()
                .filter(|rec| rec.name() == &end)
                .filter_map(|rec| match rec.data() {
                    Some(RData::MX(m)) => Some((m.preference(), m.exchange().clone())),
                    _ => None,
                })
                .collect();
            if mx.is_empty() {
                let why = if ex.rcode() == ResponseCode::NXDomain {
                    format!("{} does not exist (NXDOMAIN)", opts.name)
                } else {
                    format!("no MX records for {}", opts.name)
                };
                return Err(Failure::new(DNS_RESOLVE_NO_MX, why));
            }
            mx.sort_by_key(|(p, _)| *p);
            for (preference, exchange) in mx {
                let addresses = if exchange.is_root() {
                    r.warnings
                        .push(format!("{} has a null MX: it accepts no mail", opts.name));
                    Vec::new()
                } else {
                    r.target(&exchange).await
                };
                for a in &addresses {
                    if !res.addresses.iter().any(|b| b.ip == a.ip) {
                        res.addresses.push(a.clone());
                    }
                }
                res.mx.push(ResolvedMx {
                    preference,
                    exchange: exchange.to_string(),
                    addresses,
                });
            }
        }
        ResolveMode::Service => {
            let name =
                parse_name(&opts.name).map_err(|e| Failure::new(DNS_RESOLVE_INVALID_NAME, e))?;
            let ex = r.ask(&name, RecordType::SRV).await?;
            let (end, _) = chain_end(ex.message.answers(), &name, 16);
            let mut srv: Vec<(u16, u16, u16, Name)> = ex
                .message
                .answers()
                .iter()
                .filter(|rec| rec.name() == &end)
                .filter_map(|rec| match rec.data() {
                    Some(RData::SRV(s)) => {
                        Some((s.priority(), s.weight(), s.port(), s.target().clone()))
                    }
                    _ => None,
                })
                .collect();
            if srv.is_empty() {
                let why = if ex.rcode() == ResponseCode::NXDomain {
                    format!("{} does not exist (NXDOMAIN)", opts.name)
                } else {
                    format!("no SRV records for {}", opts.name)
                };
                return Err(Failure::new(DNS_RESOLVE_NO_SRV, why));
            }
            srv.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
            for (priority, weight, port, target) in srv {
                let addresses = if target.is_root() {
                    r.warnings.push(format!(
                        "{} has a \".\" SRV target: the service is not available",
                        opts.name
                    ));
                    Vec::new()
                } else if opts.follow_srv {
                    r.target(&target).await
                } else {
                    Vec::new()
                };
                for a in &addresses {
                    if !res.addresses.iter().any(|b| b.ip == a.ip) {
                        res.addresses.push(a.clone());
                    }
                }
                res.srv.push(ResolvedSrv {
                    priority,
                    weight,
                    port,
                    target: target.to_string(),
                    addresses,
                });
            }
        }
        ResolveMode::Reverse => {
            let ptr = ip_to_ptr_name(&opts.name)
                .map_err(|e| Failure::new(DNS_RESOLVE_INVALID_NAME, e.to_string()))?;
            let ptr = parse_name(&ptr).map_err(|e| Failure::new(DNS_RESOLVE_INVALID_NAME, e))?;
            let ex = r.ask(&ptr, RecordType::PTR).await?;
            let (end, _) = chain_end(ex.message.answers(), &ptr, 16);
            let target = ex
                .message
                .answers()
                .iter()
                .find_map(|rec| match rec.data() {
                    Some(RData::PTR(p)) if rec.name() == &end => Some(p.0.clone()),
                    _ => None,
                });
            let Some(target) = target else {
                let why = if ex.rcode() == ResponseCode::NXDomain {
                    format!("{ptr} does not exist (NXDOMAIN)")
                } else {
                    format!("no PTR record for {}", opts.name)
                };
                return Err(Failure::new(DNS_RESOLVE_NO_PTR, why));
            };
            res.ptr_name = Some(target.to_string());
            if opts.validate_reverse {
                let forward = r.target(&target).await;
                let ip: Option<IpAddr> = opts.name.parse().ok();
                if !forward.iter().any(|a| a.ip.parse::<IpAddr>().ok() == ip) {
                    r.warnings.push(format!(
                        "forward lookup of {target} does not include {}",
                        opts.name
                    ));
                }
                res.addresses = forward.clone();
                res.forward_addresses = forward;
            }
        }
    }
    Ok(res)
}

// ============================== trace ==============================

/// How a walk ended.
enum WalkEnd {
    /// The final answer (possibly empty: no data).
    Answer(Vec<Record>),
    /// The name does not exist.
    NxDomain,
}

struct Walker<'a> {
    opts: &'a DnsTraceOptions,
    cfg: QueryConfig,
    roots: Vec<(Option<String>, IpAddr)>,
    hops: Vec<DnsTraceHop>,
    warnings: Vec<String>,
    /// Queries left for walks resolving name servers without glue.
    side_budget: u32,
}

type WalkFuture<'a> = Pin<Box<dyn Future<Output = std::result::Result<WalkEnd, Failure>> + 'a>>;

fn rcode_failure_trace(rcode: ResponseCode, server: IpAddr) -> Failure {
    let mnemonic = rcode_mnemonic(rcode);
    let code = match rcode {
        ResponseCode::ServFail => DNS_TRACE_SERVFAIL,
        ResponseCode::Refused => DNS_TRACE_REFUSED,
        _ => DNS_TRACE_RCODE_ERROR,
    };
    Failure::new(code, format!("{server} answered {mnemonic}"))
}

impl<'a> Walker<'a> {
    fn hop(
        &self,
        zone: &Name,
        name: &Name,
        rtype: RecordType,
        ns_name: &Option<String>,
        ex: &Exchange,
    ) -> DnsTraceHop {
        let msg = &ex.message;
        let ns_names: Vec<String> = msg
            .answers()
            .iter()
            .chain(msg.name_servers())
            .filter_map(|r| match r.data() {
                Some(RData::NS(ns)) => Some(ns.0.to_string()),
                _ => None,
            })
            .collect();
        let ns_addresses: Vec<DnsTraceNsAddress> = msg
            .additionals()
            .iter()
            .filter(|r| {
                ns_names
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case(&r.name().to_string()))
            })
            .filter_map(|r| match r.data() {
                Some(RData::A(a)) => Some((r.name().to_string(), a.to_string(), "ipv4")),
                Some(RData::AAAA(a)) => Some((r.name().to_string(), a.to_string(), "ipv6")),
                _ => None,
            })
            .map(|(name, ip, family)| DnsTraceNsAddress {
                name,
                ip,
                family: family.to_string(),
            })
            .collect();
        DnsTraceHop {
            hop_index: self.hops.len() as u32 + 1,
            zone: zone.to_string(),
            query_name: name.to_string(),
            query_rtype: rtype.to_string(),
            server_ip: ex.server.ip().to_string(),
            server_name: ns_name.clone(),
            rtt_ms: Some(ex.rtt_ms),
            rcode: rcode_mnemonic(ex.rcode()),
            authoritative: msg.authoritative(),
            truncated: msg.truncated(),
            dnssec: DnsTraceDnssec {
                requested: self.opts.dnssec,
                do_bit: self.opts.dnssec,
                ad_bit: msg.authentic_data(),
                validated: self.opts.dnssec.then(|| msg.authentic_data()),
            },
            ns_names,
            ns_addresses,
            answers: msg.answers().iter().map(to_trace_record).collect(),
            authority: msg.name_servers().iter().map(to_trace_record).collect(),
            additional: if self.opts.include_additional {
                msg.additionals().iter().map(to_trace_record).collect()
            } else {
                Vec::new()
            },
            raw: self
                .opts
                .want_raw
                .then(|| json!({ "response_hex": hex::encode(&ex.wire) })),
        }
    }

    /// Glue addresses for the referral's name servers, preferred family
    /// first.
    fn glue(&self, msg: &Message, ns: &[Name]) -> Vec<(Option<String>, IpAddr)> {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for n in ns {
            for r in msg.additionals().iter().filter(|r| r.name() == n) {
                match r.data() {
                    Some(RData::A(a)) => v4.push((Some(n.to_string()), IpAddr::V4(a.0))),
                    Some(RData::AAAA(a)) => v6.push((Some(n.to_string()), IpAddr::V6(a.0))),
                    _ => {}
                }
            }
        }
        if self.opts.prefer_ipv6 {
            v6.extend(v4);
            v6
        } else {
            v4.extend(v6);
            v4
        }
    }

    /// Iterates from the root servers to the answer for `name`/`rtype`.
    /// Hops are recorded only for the main walk (`record`).
    fn walk(&mut self, name: Name, rtype: RecordType, record: bool) -> WalkFuture<'_> {
        Box::pin(async move {
            let mut name = name;
            let mut zone = Name::root();
            let mut servers = self.roots.clone();
            let mut cnames: Vec<Name> = Vec::new();
            let mut depth: u32 = 0;
            loop {
                if record {
                    depth += 1;
                    if depth > u32::from(self.opts.max_depth) {
                        return Err(Failure::new(
                            DNS_TRACE_MAX_DEPTH_EXCEEDED,
                            format!("no answer within max_depth={} queries", self.opts.max_depth),
                        ));
                    }
                } else {
                    if self.side_budget == 0 {
                        return Err(Failure::new(
                            DNS_TRACE_MAX_DEPTH_EXCEEDED,
                            "too many queries resolving name servers without glue",
                        ));
                    }
                    self.side_budget -= 1;
                }
                let mut set = SetResult::default();
                let mut last_bad: Option<(ResponseCode, IpAddr)> = None;
                let mut reply: Option<Exchange> = None;
                for (ns_name, ip) in &servers {
                    let addr = SocketAddr::new(*ip, self.opts.port);
                    match query_one(addr, &name, rtype, &self.cfg).await {
                        Ok(ex) => {
                            if record {
                                let hop = self.hop(&zone, &name, rtype, ns_name, &ex);
                                self.hops.push(hop);
                            }
                            match ex.rcode() {
                                ResponseCode::NoError | ResponseCode::NXDomain => {
                                    reply = Some(ex);
                                    break;
                                }
                                other => {
                                    self.warnings.push(format!(
                                        "{ip} answered {} for {name} {rtype}",
                                        rcode_mnemonic(other)
                                    ));
                                    last_bad = Some((other, *ip));
                                }
                            }
                        }
                        Err(e) => {
                            self.warnings.push(format!("server {ip}: {}", e.message));
                            set.failures.push(e);
                        }
                    }
                }
                let Some(ex) = reply else {
                    if let Some((rcode, ip)) = last_bad {
                        return Err(rcode_failure_trace(rcode, ip));
                    }
                    return Err(transport_failure(
                        &set,
                        [
                            DNS_TRACE_TIMEOUT,
                            DNS_TRACE_NETWORK_ERROR,
                            DNS_TRACE_ALL_SERVERS_FAILED,
                        ],
                        &format!("zone {zone}"),
                    ));
                };
                if ex.rcode() == ResponseCode::NXDomain {
                    return Ok(WalkEnd::NxDomain);
                }
                let msg = &ex.message;
                let answers = msg.answers();
                if has_type(answers, &name, rtype) {
                    return Ok(WalkEnd::Answer(answers.to_vec()));
                }
                if let Some(_) = cname_of(answers, &name).filter(|_| rtype != RecordType::CNAME) {
                    let (end, chain) = chain_end(answers, &name, 16);
                    if has_type(answers, &end, rtype) || !self.opts.follow_cname {
                        return Ok(WalkEnd::Answer(answers.to_vec()));
                    }
                    for target in chain {
                        if cnames.contains(&target) || cnames.len() >= 16 {
                            return Err(Failure::new(
                                DNS_TRACE_LOOP_DETECTED,
                                format!("CNAME loop or chain too long at {target}"),
                            ));
                        }
                        cnames.push(target);
                    }
                    // Start again from the root for the CNAME target.
                    name = end;
                    zone = Name::root();
                    servers = self.roots.clone();
                    continue;
                }
                // A referral: NS records for a zone between the current zone
                // and the name.
                let referral: Vec<&Record> = msg
                    .name_servers()
                    .iter()
                    .filter(|r| r.record_type() == RecordType::NS)
                    .collect();
                if referral.is_empty() {
                    // No data (typically an SOA in the authority section).
                    return Ok(WalkEnd::Answer(answers.to_vec()));
                }
                let child = referral[0].name().clone();
                if !child.zone_of(&name) || !zone.zone_of(&child) || child == zone {
                    return Err(Failure::new(
                        DNS_TRACE_LOOP_DETECTED,
                        format!(
                            "{} sent a referral to {child}, which is not below {zone} on the way to {name}",
                            ex.server.ip()
                        ),
                    ));
                }
                let ns: Vec<Name> = referral
                    .iter()
                    .filter(|r| r.name() == &child)
                    .filter_map(|r| match r.data() {
                        Some(RData::NS(n)) => Some(n.0.clone()),
                        _ => None,
                    })
                    .collect();
                let mut next = self.glue(msg, &ns);
                if next.is_empty() {
                    // No glue: resolve the name server names with their own
                    // walks from the root. Names inside the delegated zone
                    // cannot be resolved without glue.
                    let family = if self.opts.prefer_ipv6 {
                        RecordType::AAAA
                    } else {
                        RecordType::A
                    };
                    for n in &ns {
                        if child.zone_of(n) {
                            self.warnings.push(format!(
                                "name server {n} for {child} has no glue and is inside the zone"
                            ));
                            continue;
                        }
                        match self.walk(n.clone(), family, false).await {
                            Ok(WalkEnd::Answer(records)) => {
                                let (end, _) = chain_end(&records, n, 16);
                                for r in records.iter().filter(|r| r.name() == &end) {
                                    match r.data() {
                                        Some(RData::A(a)) => {
                                            next.push((Some(n.to_string()), IpAddr::V4(a.0)))
                                        }
                                        Some(RData::AAAA(a)) => {
                                            next.push((Some(n.to_string()), IpAddr::V6(a.0)))
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            Ok(WalkEnd::NxDomain) => self
                                .warnings
                                .push(format!("name server {n} for {child} does not exist")),
                            Err(f) => self.warnings.push(format!(
                                "cannot resolve name server {n} for {child}: [{}] {}",
                                f.code, f.message
                            )),
                        }
                        if !next.is_empty() {
                            break;
                        }
                    }
                }
                if next.is_empty() {
                    return Err(Failure::new(
                        DNS_TRACE_NO_NS,
                        format!("no usable name server address for zone {child}"),
                    ));
                }
                zone = child;
                servers = next;
            }
        })
    }
}

/// The starting servers: `root_servers`, or the built-in root hints of the
/// preferred family.
pub(super) fn trace_roots(opts: &DnsTraceOptions) -> Vec<(Option<String>, IpAddr)> {
    if !opts.root_servers.is_empty() {
        return opts
            .root_servers
            .iter()
            .filter_map(|s| s.parse().ok().map(|ip| (None, ip)))
            .collect();
    }
    get_root_hints()
        .into_iter()
        .filter_map(|(n, ip)| ip.parse::<IpAddr>().ok().map(|ip| (Some(n), ip)))
        .filter(|(_, ip)| ip.is_ipv6() == opts.prefer_ipv6)
        .collect()
}

pub(super) async fn perform_dns_trace(opts: &DnsTraceOptions) -> DnsTraceResponse {
    let mut response = DnsTraceResponse::new(opts);
    let name = match parse_name(&opts.name) {
        Ok(n) => n,
        Err(e) => {
            response.error = Some((DNS_TRACE_INVALID_NAME.to_string(), e));
            return response;
        }
    };
    let rtype = opts.rtype.to_trust_dns();
    let mut walker = Walker {
        opts,
        cfg: query_config(
            opts.use_tcp,
            opts.timeout_ms,
            opts.retries,
            opts.dnssec,
            false,
        ),
        roots: trace_roots(opts),
        hops: Vec::new(),
        warnings: Vec::new(),
        side_budget: u32::from(opts.max_depth) * 4,
    };
    let result = walker.walk(name.clone(), rtype, true).await;
    let hops = std::mem::take(&mut walker.hops);
    response.warnings = std::mem::take(&mut walker.warnings);
    let last = hops.last();
    let summary = DnsTraceSummary {
        name: name.to_string(),
        rtype: opts.rtype.as_str().to_string(),
        final_rcode: last.map(|h| h.rcode.clone()),
        final_authoritative: last.map(|h| h.authoritative).unwrap_or(false),
        final_answers: last.map(|h| h.answers.clone()).unwrap_or_default(),
        cname_chain: extract_cname_chain(&hops, &name.to_string()),
        depth: hops.len() as u32,
        hops,
    };
    response.trace = Some(summary);
    match result {
        Ok(WalkEnd::Answer(_)) => response.ok = true,
        Ok(WalkEnd::NxDomain) => {
            response.error = Some((
                DNS_TRACE_NXDOMAIN.to_string(),
                format!("{} does not exist (NXDOMAIN)", opts.name),
            ));
        }
        Err(f) => {
            response.timed_out = f.timed_out;
            response.error = Some((f.code.to_string(), f.message));
        }
    }
    response
}
