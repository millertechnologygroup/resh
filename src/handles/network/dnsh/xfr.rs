//! `zone.fetch`: AXFR and IXFR (RFC 5936, RFC 1995) over TCP, optionally
//! TSIG-signed, with every signed reply message verified under the
//! multi-message rules of RFC 8945 section 5.3.1.

use super::client::{QueryConfig, parse_name, query_servers, system_nameservers};
use super::query::to_dns_record;
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use trust_dns_proto::rr::{Name, Record, RecordType};

/// RFC 8945 section 5.3.1: at most 99 unsigned messages between signed ones.
const MAX_UNSIGNED_RUN: usize = 99;

/// Verifies the TSIG records of a multi-message reply.
pub(super) struct TsigStream<'a> {
    key: &'a TsigKey,
    /// The MAC the next signed message chains from (the request MAC first).
    prior_mac: Vec<u8>,
    /// Unsigned messages since the last signed one, concatenated.
    pending: Vec<u8>,
    pending_count: usize,
    first: bool,
}

impl<'a> TsigStream<'a> {
    pub(super) fn new(key: &'a TsigKey, request_mac: Vec<u8>) -> Self {
        Self {
            key,
            prior_mac: request_mac,
            pending: Vec::new(),
            pending_count: 0,
            first: true,
        }
    }

    /// Feeds one reply message (its TSIG removed, as `stripped`).
    pub(super) fn feed(
        &mut self,
        stripped: &[u8],
        tsig: Option<&TsigRecord>,
        now: u64,
    ) -> std::result::Result<(), String> {
        match tsig {
            None => {
                if self.first {
                    return Err("the first reply message is not TSIG-signed".to_string());
                }
                self.pending.extend_from_slice(stripped);
                self.pending_count += 1;
                if self.pending_count > MAX_UNSIGNED_RUN {
                    return Err(format!(
                        "more than {MAX_UNSIGNED_RUN} unsigned reply messages in a row"
                    ));
                }
                Ok(())
            }
            Some(t) => {
                verify_tsig(
                    stripped,
                    t,
                    self.key,
                    &self.prior_mac,
                    &self.pending,
                    !self.first,
                    now,
                )?;
                self.prior_mac = t.mac.clone();
                self.pending.clear();
                self.pending_count = 0;
                self.first = false;
                Ok(())
            }
        }
    }

    /// The last message of the reply must be signed.
    pub(super) fn finish(&self) -> std::result::Result<(), String> {
        if self.first || self.pending_count > 0 {
            return Err("the last reply message is not TSIG-signed".to_string());
        }
        Ok(())
    }
}

/// A failure of one transfer attempt.
#[derive(Debug, Clone)]
struct XfrError {
    code: &'static str,
    message: String,
    /// A timeout or network error: worth another attempt.
    transport: bool,
    timeout: bool,
}

impl XfrError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            transport: false,
            timeout: false,
        }
    }
    fn timeout(message: impl Into<String>) -> Self {
        Self {
            code: DNS_ZONE_FETCH_TIMEOUT,
            message: message.into(),
            transport: true,
            timeout: true,
        }
    }
    fn network(message: impl Into<String>) -> Self {
        Self {
            code: DNS_ZONE_FETCH_NETWORK_ERROR,
            message: message.into(),
            transport: true,
            timeout: false,
        }
    }
}

/// What one successful transfer produced.
struct Transfer {
    soa: ZoneSoa,
    records: Vec<ZoneRecord>,
    changes: Option<ZoneChanges>,
    raw: Option<Value>,
    warnings: Vec<String>,
}

fn zone_record(r: &Record) -> ZoneRecord {
    let d = to_dns_record(r);
    ZoneRecord {
        name: d.name,
        rtype: d.rtype,
        class: d.class,
        ttl: d.ttl,
        data: d.data,
    }
}

fn soa_of(r: &Record) -> Option<ZoneSoa> {
    match r.data() {
        Some(RData::SOA(s)) => Some(ZoneSoa {
            mname: s.mname().to_string(),
            rname: s.rname().to_string(),
            serial: s.serial(),
            refresh: s.refresh() as u32,
            retry: s.retry() as u32,
            expire: s.expire() as u32,
            minimum: s.minimum(),
        }),
        _ => None,
    }
}

fn same_record(a: &ZoneRecord, b: &ZoneRecord) -> bool {
    a.name.eq_ignore_ascii_case(&b.name)
        && a.rtype == b.rtype
        && a.class == b.class
        && a.data == b.data
}

/// Where the reader is in the transfer stream.
enum Phase {
    /// Nothing read yet.
    Start,
    /// One SOA read (serial `n`); the next record decides AXFR or IXFR.
    AfterFirst,
    Axfr,
    /// In the deletions of a difference sequence.
    Deleting,
    /// In the additions of a difference sequence that leads to `serial`.
    Adding(u32),
    Done,
}

struct Reader {
    ixfr: bool,
    requested_serial: Option<u32>,
    phase: Phase,
    soa: Option<ZoneSoa>,
    records: Vec<ZoneRecord>,
    old_serial: Option<u32>,
    added: Vec<ZoneRecord>,
    deleted: Vec<ZoneRecord>,
    incremental: bool,
    count: u64,
    max_records: u64,
}

impl Reader {
    fn new_serial(&self) -> u32 {
        self.soa.as_ref().map(|s| s.serial).unwrap_or(0)
    }

    fn push(&mut self, r: &Record) -> std::result::Result<(), XfrError> {
        // The SOA record that closes the transfer is not counted.
        self.count += 1;
        if self.count > self.max_records.saturating_add(1) {
            return Err(XfrError::new(
                DNS_ZONE_FETCH_MAX_RECORDS_EXCEEDED,
                format!(
                    "the transfer has more than max_records={} records",
                    self.max_records
                ),
            ));
        }
        let soa = soa_of(r);
        match self.phase {
            Phase::Start => {
                let Some(soa) = soa else {
                    return Err(XfrError::new(
                        DNS_ZONE_FETCH_INVALID_AXFR_STREAM,
                        format!(
                            "the transfer does not start with an SOA record (got {})",
                            r.record_type()
                        ),
                    ));
                };
                self.soa = Some(soa);
                self.records.push(zone_record(r));
                self.phase = Phase::AfterFirst;
            }
            Phase::AfterFirst => match soa {
                Some(s) if s.serial == self.new_serial() => self.phase = Phase::Done,
                Some(s) if self.ixfr => {
                    self.incremental = true;
                    self.old_serial = Some(s.serial);
                    self.phase = Phase::Deleting;
                }
                Some(_) => {
                    return Err(XfrError::new(
                        DNS_ZONE_FETCH_INVALID_AXFR_STREAM,
                        "the transfer has an SOA record with another serial",
                    ));
                }
                None => {
                    self.records.push(zone_record(r));
                    self.phase = Phase::Axfr;
                }
            },
            Phase::Axfr => {
                if soa.is_some() {
                    self.phase = Phase::Done;
                } else {
                    self.records.push(zone_record(r));
                }
            }
            Phase::Deleting => match soa {
                Some(s) => self.phase = Phase::Adding(s.serial),
                None => {
                    let rec = zone_record(r);
                    if let Some(i) = self.added.iter().position(|a| same_record(a, &rec)) {
                        self.added.remove(i);
                    } else {
                        self.deleted.push(rec);
                    }
                }
            },
            Phase::Adding(serial) => match soa {
                Some(s) if s.serial == self.new_serial() && serial == self.new_serial() => {
                    self.phase = Phase::Done
                }
                Some(_) => self.phase = Phase::Deleting,
                None => {
                    let rec = zone_record(r);
                    if let Some(i) = self.deleted.iter().position(|d| same_record(d, &rec)) {
                        self.deleted.remove(i);
                    } else {
                        self.added.push(rec);
                    }
                }
            },
            Phase::Done => {
                return Err(XfrError::new(
                    DNS_ZONE_FETCH_INVALID_AXFR_STREAM,
                    "records after the end of the transfer",
                ));
            }
        }
        Ok(())
    }

    /// Called at the end of each message: a lone SOA no newer than the
    /// requested IXFR serial means the zone is up to date.
    fn end_of_message(&mut self) {
        if let (Phase::AfterFirst, true, Some(req)) =
            (&self.phase, self.ixfr, self.requested_serial)
        {
            if serial_at_least(req, self.new_serial()) {
                self.incremental = true;
                self.old_serial = Some(req);
                self.phase = Phase::Done;
            }
        }
    }
}

fn rcode_error(rcode: ResponseCode) -> XfrError {
    let m = rcode_mnemonic(rcode);
    let code = match rcode {
        ResponseCode::Refused => DNS_ZONE_FETCH_REFUSED,
        ResponseCode::NXDomain => DNS_ZONE_FETCH_NXDOMAIN,
        ResponseCode::ServFail => DNS_ZONE_FETCH_SERVFAIL,
        ResponseCode::FormErr => DNS_ZONE_FETCH_FORMERR,
        _ => DNS_ZONE_FETCH_RCODE_ERROR,
    };
    XfrError::new(code, format!("the server answered {m}"))
}

fn build_request(
    zone: &Name,
    opts: &DnsZoneFetchOptions,
    key: Option<&TsigKey>,
) -> std::result::Result<PreparedRequest, XfrError> {
    let mut message = Message::new();
    let id: u16 = rand::random();
    let qtype = match opts.transfer {
        ZoneTransferType::Axfr => RecordType::AXFR,
        ZoneTransferType::Ixfr => RecordType::IXFR,
    };
    message
        .set_id(id)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(false)
        .add_query(Query::query(zone.clone(), qtype));
    if let (ZoneTransferType::Ixfr, Some(serial)) = (&opts.transfer, opts.serial) {
        // RFC 1995 section 3: the client's SOA goes in the authority section.
        message.add_name_server(ProtoRecord::from_rdata(
            zone.clone(),
            0,
            ProtoRData::SOA(SOA::new(Name::root(), Name::root(), serial, 0, 0, 0, 0)),
        ));
    }
    if opts.dnssec {
        let mut edns = trust_dns_proto::op::Edns::new();
        edns.set_dnssec_ok(true).set_max_payload(1232);
        message.set_edns(edns);
    }
    let mut wire = message.to_vec().map_err(|e| {
        XfrError::new(
            DNS_ZONE_FETCH_INTERNAL_ERROR,
            format!("cannot encode the request: {e}"),
        )
    })?;
    let mac = key.map(|k| tsig_sign(&mut wire, k, unix_now()));
    Ok(PreparedRequest { wire, id, mac })
}

/// One transfer attempt from `addr`.
async fn transfer_once(
    addr: SocketAddr,
    zone: &Name,
    opts: &DnsZoneFetchOptions,
    key: Option<&TsigKey>,
) -> std::result::Result<Transfer, XfrError> {
    let timeout = Duration::from_millis(opts.timeout_ms);
    let request = build_request(zone, opts, key)?;
    let mut stream = match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await
    {
        Err(_) => {
            return Err(XfrError::timeout(format!(
                "TCP connect to {addr} timed out after {} ms",
                opts.timeout_ms
            )));
        }
        Ok(Err(e)) => return Err(XfrError::network(format!("TCP connect to {addr}: {e}"))),
        Ok(Ok(s)) => s,
    };
    let mut framed = (request.wire.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&request.wire);
    match tokio::time::timeout(timeout, stream.write_all(&framed)).await {
        Err(_) => return Err(XfrError::timeout(format!("sending to {addr} timed out"))),
        Ok(Err(e)) => return Err(XfrError::network(format!("TCP {addr}: {e}"))),
        Ok(Ok(())) => {}
    }

    let mut reader = Reader {
        ixfr: opts.transfer == ZoneTransferType::Ixfr,
        requested_serial: opts.serial,
        phase: Phase::Start,
        soa: None,
        records: Vec::new(),
        old_serial: None,
        added: Vec::new(),
        deleted: Vec::new(),
        incremental: false,
        count: 0,
        max_records: opts.max_records,
    };
    let mut tsig_stream = key.map(|k| TsigStream::new(k, request.mac.clone().unwrap_or_default()));
    let mut raw_messages: Vec<String> = Vec::new();
    let mut warnings = Vec::new();

    while !matches!(reader.phase, Phase::Done) {
        let mut len = [0u8; 2];
        let read = async {
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
            stream.read_exact(&mut buf).await?;
            Ok::<_, std::io::Error>(buf)
        };
        let wire = match tokio::time::timeout(timeout, read).await {
            Err(_) => {
                return Err(XfrError::timeout(format!(
                    "no data from {addr} within {} ms",
                    opts.timeout_ms
                )));
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                if matches!(reader.phase, Phase::Start) {
                    return Err(XfrError::network(format!(
                        "{addr} closed the connection without answering"
                    )));
                }
                return Err(XfrError::new(
                    DNS_ZONE_FETCH_INVALID_AXFR_STREAM,
                    format!("{addr} closed the connection before the transfer ended"),
                ));
            }
            Ok(Err(e)) => return Err(XfrError::network(format!("TCP {addr}: {e}"))),
            Ok(Ok(w)) => w,
        };
        if opts.include_raw {
            raw_messages.push(hex::encode(&wire));
        }
        let (stripped, tsig) = split_trailing_tsig(&wire)
            .map_err(|e| XfrError::new(DNS_ZONE_FETCH_INVALID_AXFR_STREAM, e))?;
        let message = Message::from_vec(&stripped).map_err(|e| {
            XfrError::new(
                DNS_ZONE_FETCH_INVALID_AXFR_STREAM,
                format!("unparsable reply message: {e}"),
            )
        })?;
        if message.id() != request.id || message.message_type() != MessageType::Response {
            return Err(XfrError::new(
                DNS_ZONE_FETCH_INVALID_AXFR_STREAM,
                "a reply message does not match the request",
            ));
        }
        if message.response_code() != ResponseCode::NoError {
            // An error answer: report a TSIG problem first, else the RCODE.
            if let (Some(k), Some(t)) = (key, tsig.as_ref()) {
                let request_mac = request.mac.clone().unwrap_or_default();
                if let Err(e) = verify_response_tsig(&stripped, t, k, &request_mac, unix_now()) {
                    return Err(XfrError::new(DNS_ZONE_FETCH_TSIG_FAILED, e));
                }
            } else if key.is_some() {
                warnings.push("the server's error reply is not TSIG-signed".to_string());
            }
            let mut e = rcode_error(message.response_code());
            if !warnings.is_empty() {
                e.message = format!("{} ({})", e.message, warnings.join("; "));
            }
            return Err(e);
        }
        if let Some(ts) = tsig_stream.as_mut() {
            ts.feed(&stripped, tsig.as_ref(), unix_now())
                .map_err(|e| XfrError::new(DNS_ZONE_FETCH_TSIG_FAILED, e))?;
        } else if tsig.is_some() {
            if !warnings.iter().any(|w: &String| w.contains("not verified")) {
                warnings.push(
                    "the server's reply carries TSIG records that were not verified (no key given)"
                        .to_string(),
                );
            }
        }
        for r in message.answers() {
            reader.push(r)?;
        }
        reader.end_of_message();
    }
    if let Some(ts) = &tsig_stream {
        ts.finish()
            .map_err(|e| XfrError::new(DNS_ZONE_FETCH_TSIG_FAILED, e))?;
    }
    let soa = reader.soa.clone().ok_or_else(|| {
        XfrError::new(
            DNS_ZONE_FETCH_INVALID_AXFR_STREAM,
            "no SOA record in the transfer",
        )
    })?;
    let changes = reader.incremental.then(|| ZoneChanges {
        old_serial: reader.old_serial.unwrap_or(soa.serial),
        new_serial: soa.serial,
        deleted: std::mem::take(&mut reader.deleted),
        added: std::mem::take(&mut reader.added),
    });
    let records = if reader.incremental {
        Vec::new()
    } else {
        reader.records
    };
    let raw = opts.include_raw.then(|| {
        json!({
            "request_hex": hex::encode(&request.wire),
            "response_hex": raw_messages,
        })
    });
    Ok(Transfer {
        soa,
        records,
        changes,
        raw,
        warnings,
    })
}

/// The authoritative servers of `zone` (their addresses), found by asking
/// `resolvers` for the zone's NS records and then each name's addresses.
pub(super) async fn discover_servers(
    zone: &Name,
    resolvers: &[SocketAddr],
    cfg: &QueryConfig,
    prefer_ipv6: bool,
    warnings: &mut Vec<String>,
) -> std::result::Result<Vec<String>, String> {
    let set = query_servers(resolvers, zone, RecordType::NS, cfg).await;
    warnings.extend(set.warnings.iter().cloned());
    let Some(ex) = set.reply else {
        return Err(format!(
            "cannot look up the NS records of {zone}: {}",
            set.failures
                .first()
                .map(|f| f.message.clone())
                .unwrap_or_else(|| "no resolver answered".to_string())
        ));
    };
    if ex.rcode() != ResponseCode::NoError {
        return Err(format!(
            "the NS lookup for {zone} returned {}",
            rcode_mnemonic(ex.rcode())
        ));
    }
    let names: Vec<Name> = ex
        .message
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            Some(RData::NS(n)) if r.name() == zone => Some(n.0.clone()),
            _ => None,
        })
        .collect();
    if names.is_empty() {
        return Err(format!("{zone} has no NS records"));
    }
    let families = if prefer_ipv6 {
        [RecordType::AAAA, RecordType::A]
    } else {
        [RecordType::A, RecordType::AAAA]
    };
    let mut out: Vec<String> = Vec::new();
    for family in families {
        for n in &names {
            let set = query_servers(resolvers, n, family, cfg).await;
            warnings.extend(set.warnings.iter().cloned());
            let Some(ex) = set.reply else { continue };
            for r in ex.message.answers() {
                let ip = match r.data() {
                    Some(RData::A(a)) => a.to_string(),
                    Some(RData::AAAA(a)) => a.to_string(),
                    _ => continue,
                };
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }
    if out.is_empty() {
        return Err(format!("no addresses found for the name servers of {zone}"));
    }
    Ok(out)
}

/// Discovery through the host's resolvers.
pub(super) async fn discover_with_system(
    zone: &Name,
    timeout_ms: u64,
    prefer_ipv6: bool,
    warnings: &mut Vec<String>,
) -> std::result::Result<Vec<String>, String> {
    let resolvers: Vec<SocketAddr> = system_nameservers()
        .map_err(|e| format!("{e:#}"))?
        .into_iter()
        .map(|ip| SocketAddr::new(ip, 53))
        .collect();
    let cfg = QueryConfig {
        use_tcp: false,
        timeout: Duration::from_millis(timeout_ms),
        retries: 1,
        dnssec: false,
        recursion_desired: true,
    };
    discover_servers(zone, &resolvers, &cfg, prefer_ipv6, warnings).await
}

pub(super) async fn perform_zone_fetch(
    opts: &DnsZoneFetchOptions,
    key: Option<&TsigKey>,
) -> DnsZoneFetchResponse {
    let mut response = DnsZoneFetchResponse::new(opts);
    response.ok = false;
    let zone = match parse_name(&opts.zone) {
        Ok(z) => z,
        Err(e) => {
            response.error = Some((DNS_ZONE_FETCH_INVALID_ZONE.to_string(), e));
            return response;
        }
    };
    let servers = if opts.servers.is_empty() {
        let mut warnings = Vec::new();
        let found =
            discover_with_system(&zone, opts.timeout_ms, opts.prefer_ipv6, &mut warnings).await;
        response.warnings.extend(warnings);
        match found {
            Ok(s) => s,
            Err(e) => {
                response.error = Some((DNS_ZONE_FETCH_ALL_SERVERS_FAILED.to_string(), e));
                return response;
            }
        }
    } else {
        opts.servers.clone()
    };

    let mut failures: Vec<XfrError> = Vec::new();
    for server in &servers {
        let Ok(ip) = server.parse::<IpAddr>() else {
            let e = XfrError::new(
                DNS_ZONE_FETCH_INVALID_SERVER,
                format!("invalid server IP: {server}"),
            );
            response
                .warnings
                .push(format!("server {server}: {}", e.message));
            failures.push(e);
            continue;
        };
        let addr = SocketAddr::new(ip, opts.port);
        let mut outcome = Err(XfrError::network("no attempt was made"));
        for _ in 0..=opts.retries {
            outcome = transfer_once(addr, &zone, opts, key).await;
            match &outcome {
                Err(e) if e.transport => continue,
                _ => break,
            }
        }
        match outcome {
            Ok(t) => {
                response.ok = true;
                response.warnings.extend(t.warnings);
                response.raw = t.raw;
                let incremental = t.changes.is_some();
                response.zone = Some(ZoneSummary {
                    name: zone.to_string(),
                    transfer_requested: opts.transfer.as_str().to_string(),
                    transfer_used: if incremental { "IXFR" } else { "AXFR" }.to_string(),
                    server_used: server.clone(),
                    serial: t.soa.serial,
                    soa: t.soa,
                    record_count: t.records.len() as u64,
                    records: t.records,
                });
                if opts.transfer == ZoneTransferType::Ixfr && !incremental {
                    response.warnings.push(format!(
                        "{server} answered the IXFR request with a full zone transfer"
                    ));
                }
                response.changes = t.changes;
                return response;
            }
            Err(e) => {
                response
                    .warnings
                    .push(format!("server {server}: {}", e.message));
                failures.push(e);
            }
        }
    }
    response.timed_out = !failures.is_empty() && failures.iter().all(|f| f.timeout);
    response.error = Some(match failures.len() {
        1 => {
            let e = failures.remove(0);
            (e.code.to_string(), e.message)
        }
        n => (
            DNS_ZONE_FETCH_ALL_SERVERS_FAILED.to_string(),
            format!("all {n} servers failed (see warnings)"),
        ),
    });
    response
}
