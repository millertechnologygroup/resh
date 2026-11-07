use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose};
use rand::seq::SliceRandom;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use trust_dns_proto::error::ProtoResult;
use trust_dns_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use trust_dns_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, NULL, PTR, SOA, SRV, TXT};
use trust_dns_proto::rr::{
    RData as ProtoRData, Record as ProtoRecord, RecordType as ProtoRecordType,
};
use trust_dns_proto::serialize::binary::{BinDecodable, BinDecoder};
use trust_dns_resolver::error::ResolveErrorKind;
use trust_dns_resolver::proto::rr::{DNSClass, Name, RData, RecordType as TrustDnsRecordType};
use trust_dns_resolver::{
    TokioAsyncResolver,
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
};
use url::Url;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::Status,
};

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("dns", |u| Ok(Box::new(DnsHandle::from_url(u)?)));
}

/// Metadata for `resh dns --help` and `resh dns <verb> --help`.
static DNS_HELP: HandleHelp = HandleHelp {
    description: "The dns handle queries DNS through the trust-dns resolver, covering record \
        lookups, host, mail, service, and reverse resolution, and delegation traces from \
        the root servers. It can also transfer a zone with AXFR and validate dynamic zone \
        updates. The URL target is always dns:// with an empty host, and the query name \
        and options are passed as arguments, such as dns://.lookup name=example.com.",
    usage: "resh dns://.<verb> [name=<name>|zone=<zone>] [key=value ...]",
    verbs: &[
        VerbHelp {
            name: "lookup",
            definition: "Queries one DNS record type for a name and prints the answer records \
                as JSON or text.",
            detail: Some(VerbDetail {
                usage: "resh dns://.lookup name=<name> [rtype=<type>] [servers=<ip,...>]\n  \
                    [port=<n>] [use_tcp=true|false] [timeout_ms=<ms>] [retries=<n>]\n  \
                    [dnssec=true|false] [format=json|text] [<option>=<value> ...]",
                example: "resh dns://.lookup name=example.com rtype=MX",
                example_output: Some(
                    r#"{
  "additional": [],
  "answers": [
    {
      "class": "IN",
      "data": {
        "exchange": "mail.example.com.",
        "preference": 10
      },
      "name": "example.com.",
      "rtype": "MX",
      "ttl": 3600
    }
  ],
  "authority": [],
  "error": null,
  "ok": true,
  "query": {
    "dnssec": false,
    "name": "example.com",
    "port": 53,
    "retries": 1,
    "rtype": "MX",
    "servers": [],
    "timeout_ms": 2000,
    "use_tcp": false
  },
  "response": {
    "authoritative": false,
    "dnssec_validated": null,
    "rcode": "NOERROR",
    "round_trip_time_ms": 24,
    "server_used": null,
    "truncated": false
  },
  "timestamp_unix_ms": 1792142364512,
  "warnings": []
}

Shown with --json-pretty. The authority and additional arrays are always
empty with the current resolver backend."#,
                ),
            }),
        },
        VerbHelp {
            name: "resolve",
            definition: "Resolves a host name to addresses after following CNAMEs, or \
                resolves mail, service, or reverse records depending on mode.",
            detail: Some(VerbDetail {
                usage: "resh dns://.resolve name=<name> [mode=host|mail|service|reverse]\n  \
                    [family=any|ipv4|ipv6] [servers=<ip,...>] [timeout_ms=<ms>]\n  \
                    [max_cname_depth=<n>] [format=json|text] [<option>=<value> ...]",
                example: "resh dns://.resolve name=example.com family=ipv4",
                example_output: Some(
                    r#"{
  "error": null,
  "ok": true,
  "query": {
    "dnssec": false,
    "family": "ipv4",
    "follow_srv": true,
    "max_cname_depth": 8,
    "mode": "host",
    "name": "example.com",
    "port": 53,
    "retries": 1,
    "servers": [],
    "timeout_ms": 2000,
    "use_tcp": false,
    "validate_reverse": false,
    "want_raw": false
  },
  "raw": null,
  "resolution": {
    "addresses": [
      {
        "family": "ipv4",
        "ip": "192.0.2.10",
        "ttl": 300
      }
    ],
    "canonical_name": "example.com",
    "family": "ipv4",
    "forward_addresses": [],
    "mode": "host",
    "mx": [],
    "ptr_name": null,
    "round_trip_time_ms": 31,
    "source_server": null,
    "srv": []
  },
  "timestamp_unix_ms": 1792142364512,
  "warnings": []
}

Shown for mode=host with --json-pretty. Other modes fill the mx, srv, or
ptr_name and forward_addresses fields."#,
                ),
            }),
        },
        VerbHelp {
            name: "trace",
            definition: "Asks the given root_servers, or the system resolvers, for a name and \
                reports the answer, without following referrals or filling authority.",
            detail: Some(VerbDetail {
                usage: "resh dns://.trace name=<name> [rtype=<type>] [root_servers=<ip,...>]\n  \
                    [timeout_ms=<ms>] [max_depth=<n>] [prefer_ipv6=true|false]\n  \
                    [format=json|text] [<option>=<value> ...]",
                example: "resh dns://.trace name=www.example.com rtype=A",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "zone.fetch",
            definition: "Transfers a full zone with AXFR over TCP from the given or \
                authoritative name servers and prints its records.",
            detail: Some(VerbDetail {
                usage: "resh dns://.zone.fetch zone=<zone> [servers=<ip>] [port=<n>]\n  \
                    [transfer=AXFR|IXFR] [serial=<n>] [timeout_ms=<ms>]\n  \
                    [max_records=<n>] [format=json|text] [<option>=<value> ...]",
                example: "resh dns://.zone.fetch zone=example.com servers=192.0.2.53",
                example_output: Some(
                    r#"{
  "changes": null,
  "error": null,
  "ok": true,
  "query": {
    "dnssec": false,
    "max_records": 1000000,
    "port": 53,
    "retries": 1,
    "serial": null,
    "servers": [
      "192.0.2.53"
    ],
    "timeout_ms": 5000,
    "transfer": "AXFR",
    "tsig_algorithm": null,
    "tsig_key_name": null,
    "use_tcp": true,
    "zone": "example.com"
  },
  "raw": null,
  "timestamp_unix_ms": 1792142364512,
  "warnings": [],
  "zone": {
    "name": "example.com.",
    "record_count": 24,
    "records": [
      {
        "class": "IN",
        "data": {
          "nsdname": "ns1.example.com."
        },
        "name": "example.com.",
        "rtype": "NS",
        "ttl": 3600
      }
    ],
    "serial": 2026101601,
    "server_used": "192.0.2.53",
    "soa": {
      "expire": 1209600,
      "minimum": 3600,
      "mname": "ns1.example.com.",
      "refresh": 7200,
      "retry": 3600,
      "rname": "hostmaster.example.com.",
      "serial": 2026101601
    },
    "transfer_requested": "AXFR",
    "transfer_used": "AXFR"
  }
}

Shown with --json-pretty and the records array cut to one entry. IXFR
requests are currently performed as AXFR."#,
                ),
            }),
        },
        VerbHelp {
            name: "zone.update",
            definition: "Sends an RFC 2136 dynamic DNS UPDATE (prerequisites, deletes and adds) \
                to the zone's server, optionally TSIG-signed, and reports the server's RCODE.",
            detail: Some(VerbDetail {
                usage: "resh dns://.zone.update zone=<zone> [adds=<json>] [deletes=<json>]\n  \
                    [prerequisites=<json>] [servers=<ip>] [port=<n>] [use_tcp=true|false]\n  \
                    [timeout_ms=<n>] [retries=<n>] [dry_run=true|false] [include_raw=true|false]\n  \
                    [tsig_key_name=<name>] [tsig_secret=<base64>] [tsig_algorithm=<alg>]\n  \
                    [<option>=<value> ...]",
                example: "resh dns://.zone.update zone=example.com servers=192.0.2.53 dry_run=true",
                example_output: Some(
                    r#"{
  "details": {
    "adds": [],
    "deletes": [],
    "prerequisites": []
  },
  "ok": true,
  "query": {
    "dry_run": true,
    "max_changes": 1000,
    "port": 53,
    "retries": 1,
    "servers": [
      "192.0.2.53"
    ],
    "timeout_ms": 3000,
    "tsig_algorithm": null,
    "tsig_key_name": null,
    "use_tcp": true,
    "zone": "example.com"
  },
  "summary": {
    "applied_adds": 0,
    "applied_deletes": 0,
    "dry_run": true,
    "tsig_used": false,
    "zone": "example.com."
  },
  "timestamp_unix_ms": 1792142364512,
  "warnings": []
}

Shown with --json-pretty. The adds argument is a JSON array of objects
with name, rtype, ttl, and data fields; data uses the same fields that
lookup prints for that record type. dry_run builds (and signs) the message
but sends nothing."#,
                ),
            }),
        },
    ],
};

pub struct DnsHandle {
    _url: Url,
}

impl DnsHandle {
    pub fn from_url(url: &Url) -> Result<Self> {
        Ok(DnsHandle { _url: url.clone() })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DnsRecordType {
    A,
    AAAA,
    TXT,
    CNAME,
    MX,
    NS,
    SRV,
    PTR,
    SOA,
    CAA,
    ANY,
}

impl DnsRecordType {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "A" => Ok(Self::A),
            "AAAA" => Ok(Self::AAAA),
            "TXT" => Ok(Self::TXT),
            "CNAME" => Ok(Self::CNAME),
            "MX" => Ok(Self::MX),
            "NS" => Ok(Self::NS),
            "SRV" => Ok(Self::SRV),
            "PTR" => Ok(Self::PTR),
            "SOA" => Ok(Self::SOA),
            "CAA" => Ok(Self::CAA),
            "ANY" => Ok(Self::ANY),
            _ => bail!("Unknown record type: {}", s),
        }
    }

    fn to_trust_dns(&self) -> TrustDnsRecordType {
        match self {
            Self::A => TrustDnsRecordType::A,
            Self::AAAA => TrustDnsRecordType::AAAA,
            Self::TXT => TrustDnsRecordType::TXT,
            Self::CNAME => TrustDnsRecordType::CNAME,
            Self::MX => TrustDnsRecordType::MX,
            Self::NS => TrustDnsRecordType::NS,
            Self::SRV => TrustDnsRecordType::SRV,
            Self::PTR => TrustDnsRecordType::PTR,
            Self::SOA => TrustDnsRecordType::SOA,
            Self::CAA => TrustDnsRecordType::CAA,
            Self::ANY => TrustDnsRecordType::ANY,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::A => "A",
            Self::AAAA => "AAAA",
            Self::TXT => "TXT",
            Self::CNAME => "CNAME",
            Self::MX => "MX",
            Self::NS => "NS",
            Self::SRV => "SRV",
            Self::PTR => "PTR",
            Self::SOA => "SOA",
            Self::CAA => "CAA",
            Self::ANY => "ANY",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    Json,
    Text,
}

impl OutputFormat {
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "text" => Ok(Self::Text),
            _ => bail!("Invalid format: {}. Must be 'json' or 'text'", s),
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ResolveMode {
    Host,
    Mail,
    Service,
    Reverse,
}

impl ResolveMode {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "host" => Ok(Self::Host),
            "mail" => Ok(Self::Mail),
            "service" => Ok(Self::Service),
            "reverse" => Ok(Self::Reverse),
            _ => bail!(
                "Invalid mode: {}. Must be 'host', 'mail', 'service', or 'reverse'",
                s
            ),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Mail => "mail",
            Self::Service => "service",
            Self::Reverse => "reverse",
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum AddressFamily {
    Any,
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "any" => Ok(Self::Any),
            "ipv4" => Ok(Self::Ipv4),
            "ipv6" => Ok(Self::Ipv6),
            _ => bail!("Invalid family: {}. Must be 'any', 'ipv4', or 'ipv6'", s),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsResolveOptions {
    pub name: String,
    pub mode: ResolveMode,
    pub family: AddressFamily,
    pub servers: Vec<String>,
    pub port: u16,
    pub use_tcp: bool,
    pub timeout_ms: u64,
    pub retries: u32,
    pub dnssec: bool,
    pub max_cname_depth: u8,
    pub want_raw: bool,
    pub follow_srv: bool,
    pub validate_reverse: bool,
    pub format: OutputFormat,
}

impl DnsResolveOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let name = args
            .get("name")
            .ok_or_else(|| anyhow::anyhow!("Missing required parameter: name"))?
            .clone();

        if name.is_empty() {
            bail!("Parameter 'name' cannot be empty");
        }

        let mode_str = args.get("mode").unwrap_or(&"host".to_string()).clone();
        let mode = ResolveMode::from_str(&mode_str)
            .with_context(|| format!("Invalid mode: {}", mode_str))?;

        let family_str = args.get("family").unwrap_or(&"any".to_string()).clone();
        let family = AddressFamily::from_str(&family_str)
            .with_context(|| format!("Invalid family: {}", family_str))?;

        let servers = if let Some(servers_str) = args.get("servers") {
            if servers_str.trim().is_empty() || servers_str == "[]" {
                Vec::new()
            } else {
                // Parse as JSON array or comma-separated list
                if servers_str.trim().starts_with('[') {
                    serde_json::from_str::<Vec<String>>(servers_str)
                        .with_context(|| format!("Invalid servers JSON array: {}", servers_str))?
                } else {
                    servers_str
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect()
                }
            }
        } else {
            Vec::new()
        };

        // Validate server IPs
        for server in &servers {
            if server.parse::<IpAddr>().is_err() {
                bail!("Invalid server IP address: {}", server);
            }
        }

        let port = if let Some(port_str) = args.get("port") {
            let port: u16 = port_str
                .parse()
                .with_context(|| format!("Invalid port: {}", port_str))?;
            if port == 0 {
                bail!("Port cannot be 0");
            }
            port
        } else {
            53
        };

        let use_tcp = args
            .get("use_tcp")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);

        let timeout_ms = if let Some(timeout_str) = args.get("timeout_ms") {
            let timeout: u64 = timeout_str
                .parse()
                .with_context(|| format!("Invalid timeout_ms: {}", timeout_str))?;
            if timeout == 0 {
                bail!("timeout_ms must be greater than 0");
            }
            timeout
        } else {
            2000
        };

        let retries = if let Some(retries_str) = args.get("retries") {
            let retries: u32 = retries_str
                .parse()
                .with_context(|| format!("Invalid retries: {}", retries_str))?;
            retries
        } else {
            1
        };

        let dnssec = args
            .get("dnssec")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);

        let max_cname_depth = if let Some(depth_str) = args.get("max_cname_depth") {
            let depth: u8 = depth_str
                .parse()
                .with_context(|| format!("Invalid max_cname_depth: {}", depth_str))?;
            depth
        } else {
            8
        };

        let want_raw = args
            .get("want_raw")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);
        let follow_srv = args
            .get("follow_srv")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(true);
        let validate_reverse = args
            .get("validate_reverse")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);

        let format_str = args.get("format").unwrap_or(&"json".to_string()).clone();
        let format = OutputFormat::from_str(&format_str)
            .with_context(|| format!("Invalid format: {}", format_str))?;

        Ok(DnsResolveOptions {
            name,
            mode,
            family,
            servers,
            port,
            use_tcp,
            timeout_ms,
            retries,
            dnssec,
            max_cname_depth,
            want_raw,
            follow_srv,
            validate_reverse,
            format,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResolvedAddress {
    pub ip: String,
    pub family: AddressFamily,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResolvedMx {
    pub preference: u16,
    pub exchange: String,
    pub addresses: Vec<ResolvedAddress>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResolvedSrv {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
    pub addresses: Vec<ResolvedAddress>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsResolution {
    pub canonical_name: String,
    pub mode: ResolveMode,
    pub family: AddressFamily,
    pub addresses: Vec<ResolvedAddress>,
    pub mx: Vec<ResolvedMx>,
    pub srv: Vec<ResolvedSrv>,
    pub ptr_name: Option<String>,
    pub forward_addresses: Vec<ResolvedAddress>,
    pub source_server: Option<String>,
    pub round_trip_time_ms: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsResolveResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,
    pub query: Value,
    pub resolution: Option<DnsResolution>,
    pub raw: Option<Value>,
    pub error: Option<(String, String)>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DnsLookupOptions {
    pub name: String,
    pub rtype: DnsRecordType,
    pub servers: Vec<String>,
    pub port: u16,
    pub use_tcp: bool,
    pub timeout_ms: u64,
    pub retries: u32,
    pub dnssec: bool,
    pub follow_cname: bool,
    pub include_authority: bool,
    pub include_additional: bool,
    pub randomize_servers: bool,
    pub format: OutputFormat,
}

impl DnsLookupOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let name = args
            .get("name")
            .ok_or_else(|| anyhow::anyhow!("Missing required parameter: name"))?
            .clone();

        if name.is_empty() {
            bail!("Parameter 'name' cannot be empty");
        }

        let rtype_str = args.get("rtype").unwrap_or(&"A".to_string()).clone();
        let rtype = DnsRecordType::from_str(&rtype_str)
            .with_context(|| format!("Invalid record type: {}", rtype_str))?;

        let servers = if let Some(servers_str) = args.get("servers") {
            if servers_str.trim().is_empty() || servers_str == "[]" {
                Vec::new()
            } else {
                // Parse as JSON array or comma-separated list
                if servers_str.trim().starts_with('[') {
                    serde_json::from_str::<Vec<String>>(servers_str)
                        .with_context(|| format!("Invalid servers JSON array: {}", servers_str))?
                } else {
                    servers_str
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect()
                }
            }
        } else {
            Vec::new()
        };

        // Validate server IPs
        for server in &servers {
            if server.parse::<IpAddr>().is_err() {
                bail!("Invalid server IP address: {}", server);
            }
        }

        let port = if let Some(port_str) = args.get("port") {
            let port: u16 = port_str
                .parse()
                .with_context(|| format!("Invalid port: {}", port_str))?;
            if port == 0 {
                bail!("Port cannot be 0");
            }
            port
        } else {
            53
        };

        let use_tcp = args
            .get("use_tcp")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);

        let timeout_ms = if let Some(timeout_str) = args.get("timeout_ms") {
            let timeout: u64 = timeout_str
                .parse()
                .with_context(|| format!("Invalid timeout_ms: {}", timeout_str))?;
            if timeout == 0 {
                bail!("timeout_ms must be greater than 0");
            }
            timeout
        } else {
            2000
        };

        let retries = if let Some(retries_str) = args.get("retries") {
            let retries: u32 = retries_str
                .parse()
                .with_context(|| format!("Invalid retries: {}", retries_str))?;
            retries
        } else {
            1
        };

        let dnssec = args
            .get("dnssec")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);
        let follow_cname = args
            .get("follow_cname")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(true);
        let include_authority = args
            .get("include_authority")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(true);
        let include_additional = args
            .get("include_additional")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(true);
        let randomize_servers = args
            .get("randomize_servers")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(true);

        let format_str = args.get("format").unwrap_or(&"json".to_string()).clone();
        let format = OutputFormat::from_str(&format_str)
            .with_context(|| format!("Invalid format: {}", format_str))?;

        Ok(DnsLookupOptions {
            name,
            rtype,
            servers,
            port,
            use_tcp,
            timeout_ms,
            retries,
            dnssec,
            follow_cname,
            include_authority,
            include_additional,
            randomize_servers,
            format,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: String,
    pub class: String,
    pub ttl: u32,
    pub data: Value,
}

#[derive(Debug, Clone)]
pub struct DnsResponseMeta {
    pub rcode: String,
    pub authoritative: bool,
    pub truncated: bool,
    pub dnssec_validated: Option<bool>,
    pub server_used: Option<String>,
    pub round_trip_time_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct DnsLookupResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,
    pub query: Value,
    pub response: DnsResponseMeta,
    pub answers: Vec<DnsRecord>,
    pub authority: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
    pub error: Option<(String, String)>, // (code, message)
    pub warnings: Vec<String>,
}

impl DnsLookupResponse {
    fn new(opts: &DnsLookupOptions) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            ok: false,
            timestamp_unix_ms: timestamp,
            query: json!({
                "name": opts.name,
                "rtype": opts.rtype.as_str(),
                "servers": opts.servers,
                "port": opts.port,
                "use_tcp": opts.use_tcp,
                "timeout_ms": opts.timeout_ms,
                "retries": opts.retries,
                "dnssec": opts.dnssec
            }),
            response: DnsResponseMeta {
                rcode: "".to_string(),
                authoritative: false,
                truncated: false,
                dnssec_validated: None,
                server_used: None,
                round_trip_time_ms: None,
            },
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            error: None,
            warnings: Vec::new(),
        }
    }

    fn to_json(&self) -> Value {
        let result = json!({
            "ok": self.ok,
            "timestamp_unix_ms": self.timestamp_unix_ms,
            "query": self.query,
            "response": {
                "rcode": self.response.rcode,
                "authoritative": self.response.authoritative,
                "truncated": self.response.truncated,
                "dnssec_validated": self.response.dnssec_validated,
                "server_used": self.response.server_used,
                "round_trip_time_ms": self.response.round_trip_time_ms
            },
            "answers": self.answers.iter().map(|r| json!({
                "name": r.name,
                "rtype": r.rtype,
                "class": r.class,
                "ttl": r.ttl,
                "data": r.data
            })).collect::<Vec<_>>(),
            "authority": self.authority.iter().map(|r| json!({
                "name": r.name,
                "rtype": r.rtype,
                "class": r.class,
                "ttl": r.ttl,
                "data": r.data
            })).collect::<Vec<_>>(),
            "additional": self.additional.iter().map(|r| json!({
                "name": r.name,
                "rtype": r.rtype,
                "class": r.class,
                "ttl": r.ttl,
                "data": r.data
            })).collect::<Vec<_>>(),
            "error": if let Some((code, msg)) = &self.error {
                Some(json!({
                    "code": code,
                    "message": msg
                }))
            } else {
                None
            },
            "warnings": self.warnings
        });

        result
    }

    fn to_text(&self) -> String {
        let mut output = String::new();

        output.push_str("DNS Lookup Result\n");
        output.push_str("=================\n\n");

        // Query section
        output.push_str("Query:\n");
        output.push_str(&format!(
            "  Name     : {}\n",
            self.query["name"].as_str().unwrap_or("")
        ));
        output.push_str(&format!(
            "  Type     : {}\n",
            self.query["rtype"].as_str().unwrap_or("")
        ));

        let servers = if self.query["servers"]
            .as_array()
            .unwrap_or(&vec![])
            .is_empty()
        {
            "system defaults".to_string()
        } else {
            self.query["servers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap_or(""))
                .collect::<Vec<_>>()
                .join(", ")
        };
        output.push_str(&format!("  Servers  : {}\n", servers));
        output.push_str(&format!(
            "  Timeout  : {} ms\n",
            self.query["timeout_ms"].as_u64().unwrap_or(0)
        ));
        output.push_str(&format!(
            "  Retries  : {}\n",
            self.query["retries"].as_u64().unwrap_or(0)
        ));

        let dnssec_status = if self.query["dnssec"].as_bool().unwrap_or(false) {
            "enabled"
        } else {
            "disabled"
        };
        output.push_str(&format!("  DNSSEC   : {}\n\n", dnssec_status));

        // Response section
        output.push_str("Response:\n");
        output.push_str(&format!("  RCODE    : {}\n", self.response.rcode));
        output.push_str(&format!(
            "  Auth     : {}\n",
            if self.response.authoritative {
                "yes"
            } else {
                "no"
            }
        ));
        output.push_str(&format!(
            "  Trunc    : {}\n",
            if self.response.truncated { "yes" } else { "no" }
        ));

        if let Some(server) = &self.response.server_used {
            output.push_str(&format!("  Server   : {}\n", server));
        }
        if let Some(rtt) = self.response.round_trip_time_ms {
            output.push_str(&format!("  RTT      : {} ms\n", rtt));
        }
        output.push('\n');

        // Answers section
        output.push_str("Answers:\n");
        if self.answers.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for record in &self.answers {
                output.push_str(&format!(
                    "  {}  {}  {}  {}      ",
                    record.name, record.ttl, record.class, record.rtype
                ));

                // Format data based on record type
                match record.rtype.as_str() {
                    "A" | "AAAA" => {
                        if let Some(address) = record.data.get("address") {
                            output.push_str(&format!("{}\n", address.as_str().unwrap_or("")));
                        }
                    }
                    "MX" => {
                        if let (Some(pref), Some(exchange)) =
                            (record.data.get("preference"), record.data.get("exchange"))
                        {
                            output.push_str(&format!(
                                "{} {}\n",
                                pref.as_u64().unwrap_or(0),
                                exchange.as_str().unwrap_or("")
                            ));
                        }
                    }
                    "TXT" => {
                        if let Some(texts) = record.data.get("text").and_then(|t| t.as_array()) {
                            let text_values: Vec<String> = texts
                                .iter()
                                .map(|v| format!("\"{}\"", v.as_str().unwrap_or("")))
                                .collect();
                            output.push_str(&format!("{}\n", text_values.join(" ")));
                        }
                    }
                    "CNAME" => {
                        if let Some(cname) = record.data.get("cname") {
                            output.push_str(&format!("{}\n", cname.as_str().unwrap_or("")));
                        }
                    }
                    "NS" => {
                        if let Some(ns) = record.data.get("nsdname") {
                            output.push_str(&format!("{}\n", ns.as_str().unwrap_or("")));
                        }
                    }
                    "PTR" => {
                        if let Some(ptr) = record.data.get("ptrdname") {
                            output.push_str(&format!("{}\n", ptr.as_str().unwrap_or("")));
                        }
                    }
                    "SRV" => {
                        if let (Some(pri), Some(weight), Some(port), Some(target)) = (
                            record.data.get("priority"),
                            record.data.get("weight"),
                            record.data.get("port"),
                            record.data.get("target"),
                        ) {
                            output.push_str(&format!(
                                "{} {} {} {}\n",
                                pri.as_u64().unwrap_or(0),
                                weight.as_u64().unwrap_or(0),
                                port.as_u64().unwrap_or(0),
                                target.as_str().unwrap_or("")
                            ));
                        }
                    }
                    _ => {
                        output.push_str(&format!(
                            "{}\n",
                            serde_json::to_string(&record.data).unwrap_or_default()
                        ));
                    }
                }
            }
        }
        output.push('\n');

        // Authority section (if not empty)
        if !self.authority.is_empty() {
            output.push_str("Authority:\n");
            for record in &self.authority {
                output.push_str(&format!(
                    "  {}  {}  {}  {}      ",
                    record.name, record.ttl, record.class, record.rtype
                ));

                match record.rtype.as_str() {
                    "NS" => {
                        if let Some(ns) = record.data.get("nsdname") {
                            output.push_str(&format!("{}\n", ns.as_str().unwrap_or("")));
                        }
                    }
                    _ => {
                        output.push_str(&format!(
                            "{}\n",
                            serde_json::to_string(&record.data).unwrap_or_default()
                        ));
                    }
                }
            }
            output.push('\n');
        }

        // Error section
        if let Some((code, message)) = &self.error {
            output.push_str("Error:\n");
            output.push_str(&format!("  [{}] {}\n\n", code, message));
        }

        // Warnings section
        output.push_str("Warnings:\n");
        if self.warnings.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for warning in &self.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        }

        output
    }
}

impl DnsResolveResponse {
    pub fn new(opts: &DnsResolveOptions) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            ok: false,
            timestamp_unix_ms: timestamp,
            query: json!({
                "name": opts.name,
                "mode": opts.mode.as_str(),
                "family": opts.family.as_str(),
                "servers": opts.servers,
                "port": opts.port,
                "use_tcp": opts.use_tcp,
                "timeout_ms": opts.timeout_ms,
                "retries": opts.retries,
                "dnssec": opts.dnssec,
                "max_cname_depth": opts.max_cname_depth,
                "want_raw": opts.want_raw,
                "follow_srv": opts.follow_srv,
                "validate_reverse": opts.validate_reverse
            }),
            resolution: None,
            raw: None,
            error: None,
            warnings: Vec::new(),
        }
    }

    fn to_json(&self) -> Value {
        let result = json!({
            "ok": self.ok,
            "timestamp_unix_ms": self.timestamp_unix_ms,
            "query": self.query,
            "resolution": self.resolution.as_ref().map(|r| json!({
                "canonical_name": r.canonical_name,
                "mode": r.mode.as_str(),
                "family": r.family.as_str(),
                "addresses": r.addresses.iter().map(|a| json!({
                    "ip": a.ip,
                    "family": a.family.as_str(),
                    "ttl": a.ttl
                })).collect::<Vec<_>>(),
                "mx": r.mx.iter().map(|m| json!({
                    "preference": m.preference,
                    "exchange": m.exchange,
                    "addresses": m.addresses.iter().map(|a| json!({
                        "ip": a.ip,
                        "family": a.family.as_str(),
                        "ttl": a.ttl
                    })).collect::<Vec<_>>()
                })).collect::<Vec<_>>(),
                "srv": r.srv.iter().map(|s| json!({
                    "priority": s.priority,
                    "weight": s.weight,
                    "port": s.port,
                    "target": s.target,
                    "addresses": s.addresses.iter().map(|a| json!({
                        "ip": a.ip,
                        "family": a.family.as_str(),
                        "ttl": a.ttl
                    })).collect::<Vec<_>>()
                })).collect::<Vec<_>>(),
                "ptr_name": r.ptr_name,
                "forward_addresses": r.forward_addresses.iter().map(|a| json!({
                    "ip": a.ip,
                    "family": a.family.as_str(),
                    "ttl": a.ttl
                })).collect::<Vec<_>>(),
                "source_server": r.source_server,
                "round_trip_time_ms": r.round_trip_time_ms
            })),
            "raw": self.raw,
            "error": if let Some((code, msg)) = &self.error {
                Some(json!({
                    "code": code,
                    "message": msg
                }))
            } else {
                None
            },
            "warnings": self.warnings
        });

        result
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();

        if let Some(resolution) = &self.resolution {
            match resolution.mode {
                ResolveMode::Host => {
                    output.push_str("DNS Resolution\n");
                    output.push_str("==============\n\n");

                    output.push_str("Query:\n");
                    output.push_str(&format!(
                        "  Name     : {}\n",
                        self.query["name"].as_str().unwrap_or("")
                    ));
                    output.push_str(&format!("  Mode     : {}\n", resolution.mode.as_str()));
                    output.push_str(&format!("  Family   : {}\n", resolution.family.as_str()));

                    let servers = if self.query["servers"]
                        .as_array()
                        .unwrap_or(&vec![])
                        .is_empty()
                    {
                        "system defaults".to_string()
                    } else {
                        self.query["servers"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|s| s.as_str().unwrap_or(""))
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    output.push_str(&format!("  Servers  : {}\n", servers));
                    output.push_str(&format!(
                        "  Timeout  : {} ms\n",
                        self.query["timeout_ms"].as_u64().unwrap_or(0)
                    ));
                    output.push_str(&format!(
                        "  Retries  : {}\n\n",
                        self.query["retries"].as_u64().unwrap_or(0)
                    ));

                    output.push_str("Result:\n");
                    output.push_str(&format!(
                        "  Canonical Name : {}\n",
                        resolution.canonical_name
                    ));
                    output.push_str("  Addresses      :\n");
                    if resolution.addresses.is_empty() {
                        output.push_str("    (none)\n");
                    } else {
                        for addr in &resolution.addresses {
                            if let Some(ttl) = addr.ttl {
                                output.push_str(&format!(
                                    "    - {} ({}, TTL={})\n",
                                    addr.ip,
                                    addr.family.as_str(),
                                    ttl
                                ));
                            } else {
                                output.push_str(&format!(
                                    "    - {} ({})\n",
                                    addr.ip,
                                    addr.family.as_str()
                                ));
                            }
                        }
                    }
                }
                ResolveMode::Mail => {
                    output.push_str("Mail Resolution\n");
                    output.push_str("===============\n\n");

                    output.push_str(&format!(
                        "Domain   : {}\n",
                        self.query["name"].as_str().unwrap_or("")
                    ));
                    output.push_str("MX Hosts :\n");

                    if resolution.mx.is_empty() {
                        output.push_str("  (none)\n");
                    } else {
                        for mx in &resolution.mx {
                            output.push_str(&format!(
                                "  - pref={} host={}\n",
                                mx.preference, mx.exchange
                            ));
                            output.push_str("    addresses:\n");
                            for addr in &mx.addresses {
                                if let Some(ttl) = addr.ttl {
                                    output.push_str(&format!(
                                        "      - {} ({}, TTL={})\n",
                                        addr.ip,
                                        addr.family.as_str(),
                                        ttl
                                    ));
                                } else {
                                    output.push_str(&format!(
                                        "      - {} ({})\n",
                                        addr.ip,
                                        addr.family.as_str()
                                    ));
                                }
                            }
                        }
                    }

                    output.push_str("\nAll Addresses:\n");
                    if resolution.addresses.is_empty() {
                        output.push_str("  (none)\n");
                    } else {
                        for addr in &resolution.addresses {
                            if let Some(ttl) = addr.ttl {
                                output.push_str(&format!(
                                    "  - {} ({}, TTL={})\n",
                                    addr.ip,
                                    addr.family.as_str(),
                                    ttl
                                ));
                            } else {
                                output.push_str(&format!(
                                    "  - {} ({})\n",
                                    addr.ip,
                                    addr.family.as_str()
                                ));
                            }
                        }
                    }
                }
                ResolveMode::Service => {
                    output.push_str("Service Resolution\n");
                    output.push_str("==================\n\n");

                    output.push_str(&format!(
                        "Service  : {}\n",
                        self.query["name"].as_str().unwrap_or("")
                    ));
                    output.push_str("SRV Records:\n");

                    if resolution.srv.is_empty() {
                        output.push_str("  (none)\n");
                    } else {
                        for srv in &resolution.srv {
                            output.push_str(&format!(
                                "  - pri={} weight={} port={} target={}\n",
                                srv.priority, srv.weight, srv.port, srv.target
                            ));
                            output.push_str("    addresses:\n");
                            for addr in &srv.addresses {
                                if let Some(ttl) = addr.ttl {
                                    output.push_str(&format!(
                                        "      - {} ({}, TTL={})\n",
                                        addr.ip,
                                        addr.family.as_str(),
                                        ttl
                                    ));
                                } else {
                                    output.push_str(&format!(
                                        "      - {} ({})\n",
                                        addr.ip,
                                        addr.family.as_str()
                                    ));
                                }
                            }
                        }
                    }
                }
                ResolveMode::Reverse => {
                    output.push_str("Reverse Resolution\n");
                    output.push_str("==================\n\n");

                    output.push_str(&format!(
                        "IP Address : {}\n",
                        self.query["name"].as_str().unwrap_or("")
                    ));
                    output.push_str(&format!(
                        "PTR Name   : {}\n",
                        resolution
                            .ptr_name
                            .as_ref()
                            .unwrap_or(&"(none)".to_string())
                    ));

                    if !resolution.forward_addresses.is_empty() {
                        output.push_str("Forward Confirmation:\n");
                        for addr in &resolution.forward_addresses {
                            if let Some(ttl) = addr.ttl {
                                output.push_str(&format!(
                                    "  - {} ({}, TTL={})\n",
                                    addr.ip,
                                    addr.family.as_str(),
                                    ttl
                                ));
                            } else {
                                output.push_str(&format!(
                                    "  - {} ({})\n",
                                    addr.ip,
                                    addr.family.as_str()
                                ));
                            }
                        }
                    }
                }
            }

            output.push_str("\nMX Records:\n");
            if resolution.mx.is_empty() {
                output.push_str("  (none)\n");
            } else {
                for mx in &resolution.mx {
                    output.push_str(&format!(
                        "  - pref={} exchange={}\n",
                        mx.preference, mx.exchange
                    ));
                }
            }

            output.push_str("\nSRV Records:\n");
            if resolution.srv.is_empty() {
                output.push_str("  (none)\n");
            } else {
                for srv in &resolution.srv {
                    output.push_str(&format!(
                        "  - pri={} weight={} port={} target={}\n",
                        srv.priority, srv.weight, srv.port, srv.target
                    ));
                }
            }

            output.push_str("\nPTR Name:\n");
            output.push_str(&format!(
                "  {}\n",
                resolution
                    .ptr_name
                    .as_ref()
                    .unwrap_or(&"(none)".to_string())
            ));

            if let Some(server) = &resolution.source_server {
                output.push_str(&format!("\nSource Server : {}\n", server));
            }
            if let Some(rtt) = resolution.round_trip_time_ms {
                output.push_str(&format!("RTT           : {} ms\n", rtt));
            }
        }

        output.push_str("\nWarnings:\n");
        if self.warnings.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for warning in &self.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        }

        output
    }
}

// ========== DNS Trace Structures ==========

#[derive(Debug, Clone)]
pub struct DnsTraceOptions {
    pub name: String,
    pub rtype: DnsRecordType,
    pub root_servers: Vec<String>,
    pub port: u16,
    pub use_tcp: bool,
    pub timeout_ms: u64,
    pub retries: u32,
    pub dnssec: bool,
    pub max_depth: u8,
    pub follow_cname: bool,
    pub prefer_ipv6: bool,
    pub want_raw: bool,
    pub include_additional: bool,
    pub format: OutputFormat,
}

impl DnsTraceOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let name = args
            .get("name")
            .ok_or_else(|| anyhow::anyhow!("Missing required parameter: name"))?
            .clone();

        if name.is_empty() {
            bail!("Parameter 'name' cannot be empty");
        }

        let rtype_str = args.get("rtype").unwrap_or(&"A".to_string()).clone();
        let rtype = DnsRecordType::from_str(&rtype_str)
            .with_context(|| format!("Invalid record type: {}", rtype_str))?;

        let root_servers = if let Some(servers_str) = args.get("root_servers") {
            if servers_str.trim().is_empty() || servers_str == "[]" {
                Vec::new()
            } else {
                // Parse as JSON array or comma-separated list
                if servers_str.trim().starts_with('[') {
                    serde_json::from_str::<Vec<String>>(servers_str).with_context(|| {
                        format!("Invalid root_servers JSON array: {}", servers_str)
                    })?
                } else {
                    servers_str
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect()
                }
            }
        } else {
            Vec::new()
        };

        // Validate root server IPs
        for server in &root_servers {
            if server.parse::<IpAddr>().is_err() {
                bail!("Invalid root server IP address: {}", server);
            }
        }

        let port = if let Some(port_str) = args.get("port") {
            let port: u16 = port_str
                .parse()
                .with_context(|| format!("Invalid port: {}", port_str))?;
            if port == 0 {
                bail!("Port cannot be 0");
            }
            port
        } else {
            53
        };

        let use_tcp = args
            .get("use_tcp")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);

        let timeout_ms = if let Some(timeout_str) = args.get("timeout_ms") {
            let timeout: u64 = timeout_str
                .parse()
                .with_context(|| format!("Invalid timeout_ms: {}", timeout_str))?;
            if timeout == 0 {
                bail!("timeout_ms must be greater than 0");
            }
            timeout
        } else {
            3000
        };

        let retries = if let Some(retries_str) = args.get("retries") {
            let retries: u32 = retries_str
                .parse()
                .with_context(|| format!("Invalid retries: {}", retries_str))?;
            retries
        } else {
            1
        };

        let dnssec = args
            .get("dnssec")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);

        let max_depth = if let Some(depth_str) = args.get("max_depth") {
            let depth: u8 = depth_str
                .parse()
                .with_context(|| format!("Invalid max_depth: {}", depth_str))?;
            if depth == 0 {
                bail!("max_depth must be greater than 0");
            }
            depth
        } else {
            15
        };

        let follow_cname = args
            .get("follow_cname")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);
        let prefer_ipv6 = args
            .get("prefer_ipv6")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);
        let want_raw = args
            .get("want_raw")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);
        let include_additional = args
            .get("include_additional")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(true);

        let format_str = args.get("format").unwrap_or(&"json".to_string()).clone();
        let format = OutputFormat::from_str(&format_str)
            .with_context(|| format!("Invalid format: {}", format_str))?;

        Ok(DnsTraceOptions {
            name,
            rtype,
            root_servers,
            port,
            use_tcp,
            timeout_ms,
            retries,
            dnssec,
            max_depth,
            follow_cname,
            prefer_ipv6,
            want_raw,
            include_additional,
            format,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsTraceNsAddress {
    pub name: String,
    pub ip: String,
    pub family: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsTraceRecordData {
    #[serde(flatten)]
    pub json: Value,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsTraceRecord {
    pub name: String,
    pub rtype: String,
    pub ttl: u32,
    pub data: Value,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsTraceDnssec {
    pub requested: bool,
    pub do_bit: bool,
    pub ad_bit: bool,
    pub validated: Option<bool>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsTraceHop {
    pub hop_index: u32,
    pub zone: String,
    pub query_name: String,
    pub query_rtype: String,
    pub server_ip: String,
    pub server_name: Option<String>,
    pub rtt_ms: Option<u64>,
    pub rcode: String,
    pub authoritative: bool,
    pub truncated: bool,
    pub dnssec: DnsTraceDnssec,
    pub ns_names: Vec<String>,
    pub ns_addresses: Vec<DnsTraceNsAddress>,
    pub answers: Vec<DnsTraceRecord>,
    pub authority: Vec<DnsTraceRecord>,
    pub additional: Vec<DnsTraceRecord>,
    pub raw: Option<Value>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsTraceSummary {
    pub name: String,
    pub rtype: String,
    pub final_rcode: Option<String>,
    pub final_authoritative: bool,
    pub hops: Vec<DnsTraceHop>,
    pub final_answers: Vec<DnsTraceRecord>,
    pub cname_chain: Vec<String>,
    pub depth: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsTraceResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,
    pub query: Value,
    pub trace: Option<DnsTraceSummary>,
    pub error: Option<(String, String)>,
    pub warnings: Vec<String>,
}

impl DnsTraceResponse {
    pub fn new(opts: &DnsTraceOptions) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            ok: false,
            timestamp_unix_ms: timestamp,
            query: json!({
                "name": opts.name,
                "rtype": opts.rtype.as_str(),
                "root_servers": opts.root_servers,
                "port": opts.port,
                "use_tcp": opts.use_tcp,
                "timeout_ms": opts.timeout_ms,
                "retries": opts.retries,
                "dnssec": opts.dnssec,
                "max_depth": opts.max_depth,
                "follow_cname": opts.follow_cname,
                "prefer_ipv6": opts.prefer_ipv6,
                "want_raw": opts.want_raw,
                "include_additional": opts.include_additional
            }),
            trace: None,
            error: None,
            warnings: Vec::new(),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "ok": self.ok,
            "timestamp_unix_ms": self.timestamp_unix_ms,
            "query": self.query,
            "trace": self.trace,
            "error": if let Some((code, msg)) = &self.error {
                Some(json!({
                    "code": code,
                    "message": msg
                }))
            } else {
                None
            },
            "warnings": self.warnings
        })
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();

        output.push_str("DNS Trace\n");
        output.push_str("=========\n\n");

        // Query section
        output.push_str("Query:\n");
        output.push_str(&format!(
            "  Name     : {}\n",
            self.query["name"].as_str().unwrap_or("")
        ));
        output.push_str(&format!(
            "  Type     : {}\n",
            self.query["rtype"].as_str().unwrap_or("")
        ));
        output.push_str(&format!(
            "  Timeout  : {} ms\n",
            self.query["timeout_ms"].as_u64().unwrap_or(0)
        ));
        output.push_str(&format!(
            "  Retries  : {}\n",
            self.query["retries"].as_u64().unwrap_or(0)
        ));

        let dnssec_status = if self.query["dnssec"].as_bool().unwrap_or(false) {
            "enabled"
        } else {
            "disabled"
        };
        output.push_str(&format!("  DNSSEC   : {}\n\n", dnssec_status));

        // Hops
        if let Some(trace) = &self.trace {
            for hop in &trace.hops {
                output.push_str(&format!("Hop {}:\n", hop.hop_index));
                output.push_str(&format!("  Zone     : {}\n", hop.zone));
                output.push_str(&format!("  Server   : {}", hop.server_ip));
                if let Some(name) = &hop.server_name {
                    output.push_str(&format!(" ({})", name));
                }
                output.push('\n');
                output.push_str(&format!("  RCODE    : {}\n", hop.rcode));
                output.push_str(&format!(
                    "  Auth     : {}\n",
                    if hop.authoritative { "yes" } else { "no" }
                ));
                if let Some(rtt) = hop.rtt_ms {
                    output.push_str(&format!("  RTT      : {} ms\n", rtt));
                }

                if !hop.ns_names.is_empty() {
                    output.push_str("  NS       :\n");
                    for ns in &hop.ns_names {
                        output.push_str(&format!("    - {}\n", ns));
                    }
                }

                if !hop.answers.is_empty() {
                    output.push_str("  Answer   :\n");
                    for record in &hop.answers {
                        output.push_str(&format!(
                            "    {}  {}  {}  ",
                            record.name, record.ttl, record.rtype
                        ));

                        // Format data based on record type
                        match record.rtype.as_str() {
                            "A" | "AAAA" => {
                                if let Some(address) = record.data.get("address") {
                                    output
                                        .push_str(&format!("{}\n", address.as_str().unwrap_or("")));
                                }
                            }
                            _ => {
                                output.push_str(&format!(
                                    "{}\n",
                                    serde_json::to_string(&record.data).unwrap_or_default()
                                ));
                            }
                        }
                    }
                }
                output.push('\n');
            }

            // Final result
            output.push_str("Final Result:\n");
            if let Some(rcode) = &trace.final_rcode {
                output.push_str(&format!("  RCODE    : {}\n", rcode));
            }
            output.push_str(&format!(
                "  Authoritative: {}\n",
                if trace.final_authoritative {
                    "yes"
                } else {
                    "no"
                }
            ));

            if !trace.final_answers.is_empty() {
                output.push_str("  Answers  :\n");
                for record in &trace.final_answers {
                    output.push_str(&format!(
                        "    {}  {}  {}  ",
                        record.name, record.ttl, record.rtype
                    ));

                    match record.rtype.as_str() {
                        "A" | "AAAA" => {
                            if let Some(address) = record.data.get("address") {
                                output.push_str(&format!("{}\n", address.as_str().unwrap_or("")));
                            }
                        }
                        _ => {
                            output.push_str(&format!(
                                "{}\n",
                                serde_json::to_string(&record.data).unwrap_or_default()
                            ));
                        }
                    }
                }
            }
            output.push('\n');
        }

        // Error section
        if let Some((code, message)) = &self.error {
            output.push_str("Error:\n");
            output.push_str(&format!("  [{}] {}\n\n", code, message));
        }

        // Warnings section
        output.push_str("Warnings:\n");
        if self.warnings.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for warning in &self.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        }

        output
    }
}

// DNS Error codes
pub const DNS_LOOKUP_INVALID_NAME: &str = "dns.lookup_invalid_name";
pub const DNS_LOOKUP_INVALID_TYPE: &str = "dns.lookup_invalid_type";
pub const DNS_LOOKUP_INVALID_SERVER: &str = "dns.lookup_invalid_server";
pub const DNS_LOOKUP_INVALID_PORT: &str = "dns.lookup_invalid_port";
pub const DNS_LOOKUP_INVALID_RETRIES: &str = "dns.lookup_invalid_retries";
pub const DNS_LOOKUP_INVALID_TIMEOUT: &str = "dns.lookup_invalid_timeout";
pub const DNS_LOOKUP_NXDOMAIN: &str = "dns.lookup_nxdomain";
pub const DNS_LOOKUP_SERVFAIL: &str = "dns.lookup_servfail";
pub const DNS_LOOKUP_REFUSED: &str = "dns.lookup_refused";
pub const DNS_LOOKUP_FORMERR: &str = "dns.lookup_formerr";
pub const DNS_LOOKUP_RCODE_ERROR: &str = "dns.lookup_rcode_error";
pub const DNS_LOOKUP_TIMEOUT: &str = "dns.lookup_timeout";
pub const DNS_LOOKUP_NETWORK_ERROR: &str = "dns.lookup_network_error";
pub const DNS_LOOKUP_ALL_SERVERS_FAILED: &str = "dns.lookup_all_servers_failed";
pub const DNS_LOOKUP_INTERNAL_ERROR: &str = "dns.lookup_internal_error";

// DNS Resolve error codes
pub const DNS_RESOLVE_INVALID_NAME: &str = "dns.resolve_invalid_name";
pub const DNS_RESOLVE_INVALID_MODE: &str = "dns.resolve_invalid_mode";
pub const DNS_RESOLVE_INVALID_FAMILY: &str = "dns.resolve_invalid_family";
pub const DNS_RESOLVE_INVALID_SERVER: &str = "dns.resolve_invalid_server";
pub const DNS_RESOLVE_INVALID_PORT: &str = "dns.resolve_invalid_port";
pub const DNS_RESOLVE_INVALID_TIMEOUT: &str = "dns.resolve_invalid_timeout";
pub const DNS_RESOLVE_INVALID_RETRIES: &str = "dns.resolve_invalid_retries";
pub const DNS_RESOLVE_HOST_NOT_FOUND: &str = "dns.resolve_host_not_found";
pub const DNS_RESOLVE_NO_MX: &str = "dns.resolve_no_mx";
pub const DNS_RESOLVE_NO_SRV: &str = "dns.resolve_no_srv";
pub const DNS_RESOLVE_NO_PTR: &str = "dns.resolve_no_ptr";
pub const DNS_RESOLVE_LOOKUP_ERROR: &str = "dns.resolve_lookup_error";
pub const DNS_RESOLVE_TIMEOUT: &str = "dns.resolve_timeout";
pub const DNS_RESOLVE_NETWORK_ERROR: &str = "dns.resolve_network_error";
pub const DNS_RESOLVE_ALL_SERVERS_FAILED: &str = "dns.resolve_all_servers_failed";
pub const DNS_RESOLVE_INTERNAL_ERROR: &str = "dns.resolve_internal_error";
pub const DNS_RESOLVE_CNAME_LOOP: &str = "dns.resolve_cname_loop";

// DNS Trace error codes
pub const DNS_TRACE_INVALID_NAME: &str = "dns.trace_invalid_name";
pub const DNS_TRACE_INVALID_TYPE: &str = "dns.trace_invalid_type";
pub const DNS_TRACE_INVALID_ROOT_SERVER: &str = "dns.trace_invalid_root_server";
pub const DNS_TRACE_INVALID_PORT: &str = "dns.trace_invalid_port";
pub const DNS_TRACE_INVALID_TIMEOUT: &str = "dns.trace_invalid_timeout";
pub const DNS_TRACE_INVALID_RETRIES: &str = "dns.trace_invalid_retries";
pub const DNS_TRACE_INVALID_MAX_DEPTH: &str = "dns.trace_invalid_max_depth";
pub const DNS_TRACE_NXDOMAIN: &str = "dns.trace_nxdomain";
pub const DNS_TRACE_SERVFAIL: &str = "dns.trace_servfail";
pub const DNS_TRACE_REFUSED: &str = "dns.trace_refused";
pub const DNS_TRACE_RCODE_ERROR: &str = "dns.trace_rcode_error";
pub const DNS_TRACE_NO_NS: &str = "dns.trace_no_ns";
pub const DNS_TRACE_LOOP_DETECTED: &str = "dns.trace_loop_detected";
pub const DNS_TRACE_MAX_DEPTH_EXCEEDED: &str = "dns.trace_max_depth_exceeded";
pub const DNS_TRACE_TIMEOUT: &str = "dns.trace_timeout";
pub const DNS_TRACE_NETWORK_ERROR: &str = "dns.trace_network_error";
pub const DNS_TRACE_ALL_SERVERS_FAILED: &str = "dns.trace_all_servers_failed";
pub const DNS_TRACE_INTERNAL_ERROR: &str = "dns.trace_internal_error";

// DNS Zone Fetch Error Codes
pub const DNS_ZONE_FETCH_INVALID_ZONE: &str = "dns.zone_fetch_invalid_zone";
pub const DNS_ZONE_FETCH_INVALID_TRANSFER_TYPE: &str = "dns.zone_fetch_invalid_transfer_type";
pub const DNS_ZONE_FETCH_MISSING_SERIAL: &str = "dns.zone_fetch_missing_serial";
pub const DNS_ZONE_FETCH_INVALID_SERVER: &str = "dns.zone_fetch_invalid_server";
pub const DNS_ZONE_FETCH_INVALID_PORT: &str = "dns.zone_fetch_invalid_port";
pub const DNS_ZONE_FETCH_INVALID_TIMEOUT: &str = "dns.zone_fetch_invalid_timeout";
pub const DNS_ZONE_FETCH_INVALID_RETRIES: &str = "dns.zone_fetch_invalid_retries";
pub const DNS_ZONE_FETCH_INVALID_MAX_RECORDS: &str = "dns.zone_fetch_invalid_max_records";
pub const DNS_ZONE_FETCH_INVALID_TSIG_CONFIG: &str = "dns.zone_fetch_invalid_tsig_config";
pub const DNS_ZONE_FETCH_INVALID_TSIG_SECRET: &str = "dns.zone_fetch_invalid_tsig_secret";
pub const DNS_ZONE_FETCH_UNSUPPORTED_TSIG_ALGORITHM: &str =
    "dns.zone_fetch_unsupported_tsig_algorithm";
pub const DNS_ZONE_FETCH_REFUSED: &str = "dns.zone_fetch_refused";
pub const DNS_ZONE_FETCH_NXDOMAIN: &str = "dns.zone_fetch_nxdomain";
pub const DNS_ZONE_FETCH_SERVFAIL: &str = "dns.zone_fetch_servfail";
pub const DNS_ZONE_FETCH_FORMERR: &str = "dns.zone_fetch_formerr";
pub const DNS_ZONE_FETCH_RCODE_ERROR: &str = "dns.zone_fetch_rcode_error";
pub const DNS_ZONE_FETCH_INVALID_AXFR_STREAM: &str = "dns.zone_fetch_invalid_axfr_stream";
pub const DNS_ZONE_FETCH_IXFR_UNSUPPORTED: &str = "dns.zone_fetch_ixfr_unsupported";
pub const DNS_ZONE_FETCH_TIMEOUT: &str = "dns.zone_fetch_timeout";
pub const DNS_ZONE_FETCH_NETWORK_ERROR: &str = "dns.zone_fetch_network_error";
pub const DNS_ZONE_FETCH_ALL_SERVERS_FAILED: &str = "dns.zone_fetch_all_servers_failed";
pub const DNS_ZONE_FETCH_TSIG_FAILED: &str = "dns.zone_fetch_tsig_failed";
pub const DNS_ZONE_FETCH_MAX_RECORDS_EXCEEDED: &str = "dns.zone_fetch_max_records_exceeded";
pub const DNS_ZONE_FETCH_TCP_REQUIRED: &str = "dns.zone_fetch_tcp_required";
pub const DNS_ZONE_FETCH_INTERNAL_ERROR: &str = "dns.zone_fetch_internal_error";

// DNS Zone Update Error Codes
pub const DNS_ZONE_UPDATE_INVALID_ZONE: &str = "dns.zone_update_invalid_zone";
pub const DNS_ZONE_UPDATE_INVALID_SERVER: &str = "dns.zone_update_invalid_server";
pub const DNS_ZONE_UPDATE_INVALID_PORT: &str = "dns.zone_update_invalid_port";
pub const DNS_ZONE_UPDATE_INVALID_TIMEOUT: &str = "dns.zone_update_invalid_timeout";
pub const DNS_ZONE_UPDATE_INVALID_RETRIES: &str = "dns.zone_update_invalid_retries";
pub const DNS_ZONE_UPDATE_INVALID_MAX_CHANGES: &str = "dns.zone_update_invalid_max_changes";
pub const DNS_ZONE_UPDATE_INVALID_RECORD_TYPE: &str = "dns.zone_update_invalid_record_type";
pub const DNS_ZONE_UPDATE_INVALID_ADD_RECORD: &str = "dns.zone_update_invalid_add_record";
pub const DNS_ZONE_UPDATE_INVALID_DELETE_SPEC: &str = "dns.zone_update_invalid_delete_spec";
pub const DNS_ZONE_UPDATE_INVALID_PREREQUISITE: &str = "dns.zone_update_invalid_prerequisite";
pub const DNS_ZONE_UPDATE_INVALID_TSIG_CONFIG: &str = "dns.zone_update_invalid_tsig_config";
pub const DNS_ZONE_UPDATE_INVALID_TSIG_SECRET: &str = "dns.zone_update_invalid_tsig_secret";
pub const DNS_ZONE_UPDATE_UNSUPPORTED_TSIG_ALGORITHM: &str =
    "dns.zone_update_unsupported_tsig_algorithm";
pub const DNS_ZONE_UPDATE_REFUSED: &str = "dns.zone_update_refused";
pub const DNS_ZONE_UPDATE_NXDOMAIN: &str = "dns.zone_update_nxdomain";
pub const DNS_ZONE_UPDATE_SERVFAIL: &str = "dns.zone_update_servfail";
pub const DNS_ZONE_UPDATE_FORMERR: &str = "dns.zone_update_formerr";
pub const DNS_ZONE_UPDATE_NOTAUTH: &str = "dns.zone_update_notauth";
pub const DNS_ZONE_UPDATE_NOTZONE: &str = "dns.zone_update_notzone";
pub const DNS_ZONE_UPDATE_PRECONDITION_FAILED: &str = "dns.zone_update_precondition_failed";
pub const DNS_ZONE_UPDATE_RCODE_ERROR: &str = "dns.zone_update_rcode_error";
pub const DNS_ZONE_UPDATE_TIMEOUT: &str = "dns.zone_update_timeout";
pub const DNS_ZONE_UPDATE_NETWORK_ERROR: &str = "dns.zone_update_network_error";
pub const DNS_ZONE_UPDATE_ALL_SERVERS_FAILED: &str = "dns.zone_update_all_servers_failed";
pub const DNS_ZONE_UPDATE_TSIG_FAILED: &str = "dns.zone_update_tsig_failed";
pub const DNS_ZONE_UPDATE_INTERNAL_ERROR: &str = "dns.zone_update_internal_error";

// Helper function to determine if a string is an IP address
pub fn is_ip_address(name: &str) -> bool {
    name.parse::<IpAddr>().is_ok()
}

// Helper function to construct PTR query name from IP address
pub fn ip_to_ptr_name(ip: &str) -> Result<String> {
    let addr: IpAddr = ip.parse()?;
    match addr {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            Ok(format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            ))
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            let mut chars = Vec::new();
            for segment in segments.iter().rev() {
                chars.push(format!("{:x}", segment & 0xf));
                chars.push(format!("{:x}", (segment >> 4) & 0xf));
                chars.push(format!("{:x}", (segment >> 8) & 0xf));
                chars.push(format!("{:x}", (segment >> 12) & 0xf));
            }
            Ok(format!("{}.ip6.arpa", chars.join(".")))
        }
    }
}

// Helper function to convert lookup response to resolved addresses
pub fn lookup_response_to_addresses(
    response: &DnsLookupResponse,
    family: &AddressFamily,
) -> Vec<ResolvedAddress> {
    let mut addresses = Vec::new();

    for record in &response.answers {
        match record.rtype.as_str() {
            "A" => {
                if matches!(family, AddressFamily::Any | AddressFamily::Ipv4) {
                    if let Some(ip) = record.data.get("address").and_then(|v| v.as_str()) {
                        addresses.push(ResolvedAddress {
                            ip: ip.to_string(),
                            family: AddressFamily::Ipv4,
                            ttl: Some(record.ttl),
                        });
                    }
                }
            }
            "AAAA" => {
                if matches!(family, AddressFamily::Any | AddressFamily::Ipv6) {
                    if let Some(ip) = record.data.get("address").and_then(|v| v.as_str()) {
                        addresses.push(ResolvedAddress {
                            ip: ip.to_string(),
                            family: AddressFamily::Ipv6,
                            ttl: Some(record.ttl),
                        });
                    }
                }
            }
            _ => {}
        }
    }

    addresses
}

// Core DNS resolve function
pub async fn perform_dns_resolve(opts: DnsResolveOptions) -> Result<DnsResolveResponse> {
    let mut response = DnsResolveResponse::new(&opts);
    let start_time = std::time::Instant::now();

    match opts.mode {
        ResolveMode::Host => {
            let result = resolve_host(&opts).await;
            match result {
                Ok(mut resolution) => {
                    resolution.round_trip_time_ms = Some(start_time.elapsed().as_millis() as u64);
                    response.ok = true;
                    response.resolution = Some(resolution);
                }
                Err(e) => {
                    response.ok = false;
                    response.error = Some((DNS_RESOLVE_LOOKUP_ERROR.to_string(), e.to_string()));
                }
            }
        }
        ResolveMode::Mail => {
            let result = resolve_mail(&opts).await;
            match result {
                Ok(mut resolution) => {
                    resolution.round_trip_time_ms = Some(start_time.elapsed().as_millis() as u64);
                    response.ok = true;
                    response.resolution = Some(resolution);
                }
                Err(e) => {
                    response.ok = false;
                    response.error = Some((DNS_RESOLVE_LOOKUP_ERROR.to_string(), e.to_string()));
                }
            }
        }
        ResolveMode::Service => {
            let result = resolve_service(&opts).await;
            match result {
                Ok(mut resolution) => {
                    resolution.round_trip_time_ms = Some(start_time.elapsed().as_millis() as u64);
                    response.ok = true;
                    response.resolution = Some(resolution);
                }
                Err(e) => {
                    response.ok = false;
                    response.error = Some((DNS_RESOLVE_LOOKUP_ERROR.to_string(), e.to_string()));
                }
            }
        }
        ResolveMode::Reverse => {
            let result = resolve_reverse(&opts).await;
            match result {
                Ok(mut resolution) => {
                    resolution.round_trip_time_ms = Some(start_time.elapsed().as_millis() as u64);
                    response.ok = true;
                    response.resolution = Some(resolution);
                }
                Err(e) => {
                    response.ok = false;
                    response.error = Some((DNS_RESOLVE_LOOKUP_ERROR.to_string(), e.to_string()));
                }
            }
        }
    }

    Ok(response)
}

async fn resolve_host(opts: &DnsResolveOptions) -> Result<DnsResolution> {
    let mut canonical_name = opts.name.clone();
    let mut visited_names = HashSet::new();
    let mut cname_depth = 0;

    // Follow CNAME chain
    loop {
        if visited_names.contains(&canonical_name) {
            bail!("CNAME loop detected");
        }

        if cname_depth >= opts.max_cname_depth {
            bail!("Maximum CNAME depth exceeded");
        }

        visited_names.insert(canonical_name.clone());

        // Lookup CNAME
        let cname_lookup_opts = DnsLookupOptions {
            name: canonical_name.clone(),
            rtype: DnsRecordType::CNAME,
            servers: opts.servers.clone(),
            port: opts.port,
            use_tcp: opts.use_tcp,
            timeout_ms: opts.timeout_ms,
            retries: opts.retries,
            dnssec: opts.dnssec,
            follow_cname: false,
            include_authority: false,
            include_additional: false,
            randomize_servers: true,
            format: OutputFormat::Json,
        };

        let cname_response = perform_dns_lookup(cname_lookup_opts).await?;

        if cname_response.ok && !cname_response.answers.is_empty() {
            // Found CNAME, follow it
            if let Some(cname_record) = cname_response.answers.first() {
                if let Some(target) = cname_record.data.get("cname").and_then(|v| v.as_str()) {
                    canonical_name = target.to_string();
                    cname_depth += 1;
                    continue;
                }
            }
        }

        // No more CNAMEs to follow
        break;
    }

    // Now resolve A and AAAA records for the canonical name
    let mut all_addresses = Vec::new();

    // Resolve A records if needed
    if matches!(opts.family, AddressFamily::Any | AddressFamily::Ipv4) {
        let a_lookup_opts = DnsLookupOptions {
            name: canonical_name.clone(),
            rtype: DnsRecordType::A,
            servers: opts.servers.clone(),
            port: opts.port,
            use_tcp: opts.use_tcp,
            timeout_ms: opts.timeout_ms,
            retries: opts.retries,
            dnssec: opts.dnssec,
            follow_cname: false,
            include_authority: false,
            include_additional: false,
            randomize_servers: true,
            format: OutputFormat::Json,
        };

        let a_response = perform_dns_lookup(a_lookup_opts).await?;
        if a_response.ok {
            let mut a_addresses = lookup_response_to_addresses(&a_response, &AddressFamily::Ipv4);
            all_addresses.append(&mut a_addresses);
        }
    }

    // Resolve AAAA records if needed
    if matches!(opts.family, AddressFamily::Any | AddressFamily::Ipv6) {
        let aaaa_lookup_opts = DnsLookupOptions {
            name: canonical_name.clone(),
            rtype: DnsRecordType::AAAA,
            servers: opts.servers.clone(),
            port: opts.port,
            use_tcp: opts.use_tcp,
            timeout_ms: opts.timeout_ms,
            retries: opts.retries,
            dnssec: opts.dnssec,
            follow_cname: false,
            include_authority: false,
            include_additional: false,
            randomize_servers: true,
            format: OutputFormat::Json,
        };

        let aaaa_response = perform_dns_lookup(aaaa_lookup_opts).await?;
        if aaaa_response.ok {
            let mut aaaa_addresses =
                lookup_response_to_addresses(&aaaa_response, &AddressFamily::Ipv6);
            all_addresses.append(&mut aaaa_addresses);
        }
    }

    if all_addresses.is_empty() {
        bail!("No addresses found for host");
    }

    // Sort addresses: IPv6 first if "any", otherwise respect family preference
    if opts.family == AddressFamily::Any {
        all_addresses.sort_by(|a, b| match (&a.family, &b.family) {
            (AddressFamily::Ipv6, AddressFamily::Ipv4) => std::cmp::Ordering::Less,
            (AddressFamily::Ipv4, AddressFamily::Ipv6) => std::cmp::Ordering::Greater,
            _ => std::cmp::Ordering::Equal,
        });
    }

    Ok(DnsResolution {
        canonical_name,
        mode: ResolveMode::Host,
        family: opts.family.clone(),
        addresses: all_addresses,
        mx: Vec::new(),
        srv: Vec::new(),
        ptr_name: None,
        forward_addresses: Vec::new(),
        source_server: opts.servers.first().cloned(),
        round_trip_time_ms: None,
    })
}

async fn resolve_mail(opts: &DnsResolveOptions) -> Result<DnsResolution> {
    // Lookup MX records
    let mx_lookup_opts = DnsLookupOptions {
        name: opts.name.clone(),
        rtype: DnsRecordType::MX,
        servers: opts.servers.clone(),
        port: opts.port,
        use_tcp: opts.use_tcp,
        timeout_ms: opts.timeout_ms,
        retries: opts.retries,
        dnssec: opts.dnssec,
        follow_cname: false,
        include_authority: false,
        include_additional: false,
        randomize_servers: true,
        format: OutputFormat::Json,
    };

    let mx_response = perform_dns_lookup(mx_lookup_opts).await?;

    if !mx_response.ok || mx_response.answers.is_empty() {
        bail!("No MX records found");
    }

    let mut mx_records = Vec::new();
    let mut all_addresses = Vec::new();

    for mx_record in &mx_response.answers {
        if let (Some(preference), Some(exchange)) = (
            mx_record.data.get("preference").and_then(|v| v.as_u64()),
            mx_record.data.get("exchange").and_then(|v| v.as_str()),
        ) {
            // Resolve A/AAAA for this MX target
            let host_opts = DnsResolveOptions {
                name: exchange.to_string(),
                mode: ResolveMode::Host,
                family: opts.family.clone(),
                servers: opts.servers.clone(),
                port: opts.port,
                use_tcp: opts.use_tcp,
                timeout_ms: opts.timeout_ms,
                retries: opts.retries,
                dnssec: opts.dnssec,
                max_cname_depth: opts.max_cname_depth,
                want_raw: false,
                follow_srv: false,
                validate_reverse: false,
                format: OutputFormat::Json,
            };

            let host_resolution = resolve_host(&host_opts).await?;
            let mx_addresses = host_resolution.addresses.clone();

            mx_records.push(ResolvedMx {
                preference: preference as u16,
                exchange: exchange.to_string(),
                addresses: mx_addresses.clone(),
            });

            // Add to flattened address list
            for addr in mx_addresses {
                if !all_addresses
                    .iter()
                    .any(|a: &ResolvedAddress| a.ip == addr.ip)
                {
                    all_addresses.push(addr);
                }
            }
        }
    }

    // Sort MX records by preference
    mx_records.sort_by_key(|mx| mx.preference);

    Ok(DnsResolution {
        canonical_name: opts.name.clone(),
        mode: ResolveMode::Mail,
        family: opts.family.clone(),
        addresses: all_addresses,
        mx: mx_records,
        srv: Vec::new(),
        ptr_name: None,
        forward_addresses: Vec::new(),
        source_server: opts.servers.first().cloned(),
        round_trip_time_ms: None,
    })
}

async fn resolve_service(opts: &DnsResolveOptions) -> Result<DnsResolution> {
    // Lookup SRV records
    let srv_lookup_opts = DnsLookupOptions {
        name: opts.name.clone(),
        rtype: DnsRecordType::SRV,
        servers: opts.servers.clone(),
        port: opts.port,
        use_tcp: opts.use_tcp,
        timeout_ms: opts.timeout_ms,
        retries: opts.retries,
        dnssec: opts.dnssec,
        follow_cname: false,
        include_authority: false,
        include_additional: false,
        randomize_servers: true,
        format: OutputFormat::Json,
    };

    let srv_response = perform_dns_lookup(srv_lookup_opts).await?;

    if !srv_response.ok || srv_response.answers.is_empty() {
        bail!("No SRV records found");
    }

    let mut srv_records = Vec::new();
    let mut all_addresses = Vec::new();

    for srv_record in &srv_response.answers {
        if let (Some(priority), Some(weight), Some(port), Some(target)) = (
            srv_record.data.get("priority").and_then(|v| v.as_u64()),
            srv_record.data.get("weight").and_then(|v| v.as_u64()),
            srv_record.data.get("port").and_then(|v| v.as_u64()),
            srv_record.data.get("target").and_then(|v| v.as_str()),
        ) {
            let mut srv_addresses = Vec::new();

            if opts.follow_srv {
                // Resolve A/AAAA for this SRV target
                let host_opts = DnsResolveOptions {
                    name: target.to_string(),
                    mode: ResolveMode::Host,
                    family: opts.family.clone(),
                    servers: opts.servers.clone(),
                    port: opts.port,
                    use_tcp: opts.use_tcp,
                    timeout_ms: opts.timeout_ms,
                    retries: opts.retries,
                    dnssec: opts.dnssec,
                    max_cname_depth: opts.max_cname_depth,
                    want_raw: false,
                    follow_srv: false,
                    validate_reverse: false,
                    format: OutputFormat::Json,
                };

                let host_resolution = resolve_host(&host_opts).await?;
                srv_addresses = host_resolution.addresses.clone();

                // Add to flattened address list
                for addr in &srv_addresses {
                    if !all_addresses
                        .iter()
                        .any(|a: &ResolvedAddress| a.ip == addr.ip)
                    {
                        all_addresses.push(addr.clone());
                    }
                }
            }

            srv_records.push(ResolvedSrv {
                priority: priority as u16,
                weight: weight as u16,
                port: port as u16,
                target: target.to_string(),
                addresses: srv_addresses,
            });
        }
    }

    // Sort SRV records by priority, then by weight
    srv_records.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| a.weight.cmp(&b.weight))
    });

    Ok(DnsResolution {
        canonical_name: opts.name.clone(),
        mode: ResolveMode::Service,
        family: opts.family.clone(),
        addresses: all_addresses,
        mx: Vec::new(),
        srv: srv_records,
        ptr_name: None,
        forward_addresses: Vec::new(),
        source_server: opts.servers.first().cloned(),
        round_trip_time_ms: None,
    })
}

async fn resolve_reverse(opts: &DnsResolveOptions) -> Result<DnsResolution> {
    // Check if name is an IP address
    if !is_ip_address(&opts.name) {
        bail!("Name is not a valid IP address for reverse lookup");
    }

    // Convert IP to PTR query name
    let ptr_name = ip_to_ptr_name(&opts.name)?;

    // Lookup PTR record
    let ptr_lookup_opts = DnsLookupOptions {
        name: ptr_name,
        rtype: DnsRecordType::PTR,
        servers: opts.servers.clone(),
        port: opts.port,
        use_tcp: opts.use_tcp,
        timeout_ms: opts.timeout_ms,
        retries: opts.retries,
        dnssec: opts.dnssec,
        follow_cname: false,
        include_authority: false,
        include_additional: false,
        randomize_servers: true,
        format: OutputFormat::Json,
    };

    let ptr_response = perform_dns_lookup(ptr_lookup_opts).await?;

    let mut ptr_hostname = None;
    let mut forward_addresses = Vec::new();

    if ptr_response.ok && !ptr_response.answers.is_empty() {
        if let Some(ptr_record) = ptr_response.answers.first() {
            if let Some(hostname) = ptr_record.data.get("ptrdname").and_then(|v| v.as_str()) {
                ptr_hostname = Some(hostname.to_string());

                // If validation requested, resolve the hostname back to addresses
                if opts.validate_reverse {
                    let host_opts = DnsResolveOptions {
                        name: hostname.to_string(),
                        mode: ResolveMode::Host,
                        family: opts.family.clone(),
                        servers: opts.servers.clone(),
                        port: opts.port,
                        use_tcp: opts.use_tcp,
                        timeout_ms: opts.timeout_ms,
                        retries: opts.retries,
                        dnssec: opts.dnssec,
                        max_cname_depth: opts.max_cname_depth,
                        want_raw: false,
                        follow_srv: false,
                        validate_reverse: false,
                        format: OutputFormat::Json,
                    };

                    if let Ok(host_resolution) = resolve_host(&host_opts).await {
                        forward_addresses = host_resolution.addresses;
                    }
                }
            }
        }
    }

    if ptr_hostname.is_none() {
        bail!("No PTR record found");
    }

    Ok(DnsResolution {
        canonical_name: opts.name.clone(),
        mode: ResolveMode::Reverse,
        family: opts.family.clone(),
        addresses: if opts.validate_reverse {
            forward_addresses.clone()
        } else {
            Vec::new()
        },
        mx: Vec::new(),
        srv: Vec::new(),
        ptr_name: ptr_hostname,
        forward_addresses,
        source_server: opts.servers.first().cloned(),
        round_trip_time_ms: None,
    })
}

fn rdata_to_json(rdata: &RData, rtype: &str) -> Value {
    match rdata {
        RData::A(ipv4) => json!({ "address": ipv4.to_string() }),
        RData::AAAA(ipv6) => json!({ "address": ipv6.to_string() }),
        RData::CNAME(name) => json!({ "cname": name.to_string() }),
        RData::MX(mx) => json!({
            "preference": mx.preference(),
            "exchange": mx.exchange().to_string()
        }),
        RData::TXT(txt) => {
            let texts: Vec<String> = txt
                .txt_data()
                .iter()
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                .collect();
            json!({ "text": texts })
        }
        RData::NS(ns) => json!({ "nsdname": ns.to_string() }),
        RData::SRV(srv) => json!({
            "priority": srv.priority(),
            "weight": srv.weight(),
            "port": srv.port(),
            "target": srv.target().to_string()
        }),
        RData::PTR(ptr) => json!({ "ptrdname": ptr.to_string() }),
        RData::SOA(soa) => json!({
            "mname": soa.mname().to_string(),
            "rname": soa.rname().to_string(),
            "serial": soa.serial(),
            "refresh": soa.refresh(),
            "retry": soa.retry(),
            "expire": soa.expire(),
            "minimum": soa.minimum()
        }),
        RData::CAA(caa) => json!({
            "flags": caa.issuer_critical() as u8,
            "tag": caa.tag().to_string(),
            "value": caa.value().to_string()
        }),
        _ => json!({ "raw": format!("Unsupported record type: {}", rtype) }),
    }
}

// Root DNS servers (a subset for quick reference)
pub fn get_root_hints() -> Vec<(String, String)> {
    vec![
        ("a.root-servers.net.".to_string(), "198.41.0.4".to_string()),
        (
            "a.root-servers.net.".to_string(),
            "2001:503:ba3e::2:30".to_string(),
        ),
        (
            "b.root-servers.net.".to_string(),
            "170.247.170.2".to_string(),
        ),
        (
            "b.root-servers.net.".to_string(),
            "2801:1b8:10::b".to_string(),
        ),
        ("c.root-servers.net.".to_string(), "192.33.4.12".to_string()),
        (
            "c.root-servers.net.".to_string(),
            "2001:500:2::c".to_string(),
        ),
        ("d.root-servers.net.".to_string(), "199.7.91.13".to_string()),
        (
            "d.root-servers.net.".to_string(),
            "2001:500:2d::d".to_string(),
        ),
        (
            "e.root-servers.net.".to_string(),
            "192.203.230.10".to_string(),
        ),
        (
            "e.root-servers.net.".to_string(),
            "2001:500:a8::e".to_string(),
        ),
        ("f.root-servers.net.".to_string(), "192.5.5.241".to_string()),
        (
            "f.root-servers.net.".to_string(),
            "2001:500:2f::f".to_string(),
        ),
    ]
}

// Extract label chain from a domain name
fn extract_label_chain(name: &str) -> Vec<String> {
    let normalized = if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{}.", name)
    };

    let mut labels = Vec::new();
    let parts: Vec<&str> = normalized.trim_end_matches('.').split('.').collect();

    // Build from root to most specific
    labels.push(".".to_string());

    for i in 0..parts.len() {
        let zone = parts[parts.len() - i - 1..].join(".") + ".";
        labels.push(zone);
    }

    labels
}

// Extract CNAME chain from DNS trace hops
fn extract_cname_chain(hops: &[DnsTraceHop], query_name: &str) -> Vec<String> {
    let mut cname_chain = Vec::new();
    let mut current_name = query_name.to_lowercase();

    // Iterate through all hops and collect CNAME records in order
    for hop in hops {
        for answer in &hop.answers {
            if answer.rtype == "CNAME" {
                let answer_name = answer.name.to_lowercase();

                // Check if this CNAME is for the current name we're following
                if answer_name == current_name {
                    // Extract the CNAME target from the data
                    if let Some(cname_target) = answer.data.get("cname").and_then(|v| v.as_str()) {
                        cname_chain.push(cname_target.to_string());
                        current_name = cname_target.to_lowercase();
                    }
                }
            }
        }
    }

    cname_chain
}

// Perform a DNS trace (delegation walk)
pub async fn perform_dns_trace(opts: DnsTraceOptions) -> Result<DnsTraceResponse> {
    let mut response = DnsTraceResponse::new(&opts);

    // Normalize the query name
    let normalized_name = if opts.name.ends_with('.') {
        opts.name.clone()
    } else {
        format!("{}.", opts.name)
    };

    // Build label chain
    let label_chain = extract_label_chain(&normalized_name);

    // Initialize NS set (root servers)
    let mut current_ns_ips: Vec<(Option<String>, String)> = if !opts.root_servers.is_empty() {
        opts.root_servers
            .iter()
            .map(|ip| (None, ip.clone()))
            .collect()
    } else {
        // Use built-in root hints, prefer IPv4 unless prefer_ipv6 is set
        let hints = get_root_hints();
        hints
            .into_iter()
            .filter(|(_, ip)| {
                if opts.prefer_ipv6 {
                    ip.contains(':')
                } else {
                    !ip.contains(':')
                }
            })
            .map(|(name, ip)| (Some(name), ip))
            .take(3) // Limit to a few root servers
            .collect()
    };

    if current_ns_ips.is_empty() {
        response.error = Some((
            DNS_TRACE_NO_NS.to_string(),
            "No root servers available".to_string(),
        ));
        return Ok(response);
    }

    let mut hops = Vec::new();
    let mut visited_zones = HashSet::new();
    let mut hop_index = 1;

    // Walk through the label chain
    for (zone_idx, current_zone) in label_chain.iter().enumerate() {
        // Check max depth
        if hop_index > opts.max_depth as u32 {
            response.error = Some((
                DNS_TRACE_MAX_DEPTH_EXCEEDED.to_string(),
                "Maximum delegation depth exceeded".to_string(),
            ));
            break;
        }

        // Check for loops
        if visited_zones.contains(current_zone) {
            response.error = Some((
                DNS_TRACE_LOOP_DETECTED.to_string(),
                format!("Loop detected at zone: {}", current_zone),
            ));
            break;
        }
        visited_zones.insert(current_zone.clone());

        // Determine what to query:
        // - If this is not the last zone in chain, query NS for next zone
        // - If this is the last zone, query for the actual rtype
        let is_final_zone = zone_idx == label_chain.len() - 1;
        let query_name = if is_final_zone {
            normalized_name.clone()
        } else {
            label_chain[zone_idx + 1].clone()
        };
        let query_rtype = if is_final_zone {
            opts.rtype.clone()
        } else {
            DnsRecordType::NS
        };

        // Try to query the current NS set
        let mut query_succeeded = false;

        for (ns_name, ns_ip) in &current_ns_ips {
            let start_time = std::time::Instant::now();

            // Perform lookup
            let lookup_opts = DnsLookupOptions {
                name: query_name.clone(),
                rtype: query_rtype.clone(),
                servers: vec![ns_ip.clone()],
                port: opts.port,
                use_tcp: opts.use_tcp,
                timeout_ms: opts.timeout_ms,
                retries: opts.retries,
                dnssec: opts.dnssec,
                follow_cname: false,
                include_authority: true,
                include_additional: opts.include_additional,
                randomize_servers: false,
                format: OutputFormat::Json,
            };

            let lookup_result = perform_dns_lookup(lookup_opts).await;

            let elapsed = start_time.elapsed();

            match lookup_result {
                Ok(lookup_response) => {
                    // Build hop
                    let mut hop = DnsTraceHop {
                        hop_index,
                        zone: current_zone.clone(),
                        query_name: query_name.clone(),
                        query_rtype: query_rtype.as_str().to_string(),
                        server_ip: ns_ip.clone(),
                        server_name: ns_name.clone(),
                        rtt_ms: Some(elapsed.as_millis() as u64),
                        rcode: lookup_response.response.rcode.clone(),
                        authoritative: lookup_response.response.authoritative,
                        truncated: lookup_response.response.truncated,
                        dnssec: DnsTraceDnssec {
                            requested: opts.dnssec,
                            do_bit: opts.dnssec,
                            ad_bit: false,
                            validated: lookup_response.response.dnssec_validated,
                        },
                        ns_names: Vec::new(),
                        ns_addresses: Vec::new(),
                        answers: Vec::new(),
                        authority: Vec::new(),
                        additional: Vec::new(),
                        raw: if opts.want_raw {
                            Some(lookup_response.to_json())
                        } else {
                            None
                        },
                    };

                    // Convert records
                    for record in &lookup_response.answers {
                        hop.answers.push(DnsTraceRecord {
                            name: record.name.clone(),
                            rtype: record.rtype.clone(),
                            ttl: record.ttl,
                            data: record.data.clone(),
                        });
                    }

                    for record in &lookup_response.authority {
                        hop.authority.push(DnsTraceRecord {
                            name: record.name.clone(),
                            rtype: record.rtype.clone(),
                            ttl: record.ttl,
                            data: record.data.clone(),
                        });
                    }

                    for record in &lookup_response.additional {
                        hop.additional.push(DnsTraceRecord {
                            name: record.name.clone(),
                            rtype: record.rtype.clone(),
                            ttl: record.ttl,
                            data: record.data.clone(),
                        });
                    }

                    // Extract NS records from answer/authority sections
                    let mut ns_names = Vec::new();
                    let mut ns_addresses: Vec<DnsTraceNsAddress> = Vec::new();

                    for record in lookup_response
                        .answers
                        .iter()
                        .chain(lookup_response.authority.iter())
                    {
                        if record.rtype == "NS" {
                            if let Some(nsdname) =
                                record.data.get("nsdname").and_then(|v| v.as_str())
                            {
                                ns_names.push(nsdname.to_string());
                            }
                        }
                    }

                    hop.ns_names = ns_names.clone();

                    // Extract glue records (A/AAAA in additional section)
                    for record in &lookup_response.additional {
                        if record.rtype == "A" || record.rtype == "AAAA" {
                            if let Some(address) =
                                record.data.get("address").and_then(|v| v.as_str())
                            {
                                ns_addresses.push(DnsTraceNsAddress {
                                    name: record.name.clone(),
                                    ip: address.to_string(),
                                    family: if record.rtype == "A" { "ipv4" } else { "ipv6" }
                                        .to_string(),
                                });
                            }
                        }
                    }

                    hop.ns_addresses = ns_addresses.clone();

                    // Handle different RCODE outcomes
                    if lookup_response.response.rcode == "NOERROR" {
                        query_succeeded = true;
                        hops.push(hop);

                        // Update NS set for next iteration if not final
                        if !is_final_zone {
                            // Build next NS set from NS records + glue
                            let mut next_ns_ips = Vec::new();

                            for ns_name in &ns_names {
                                // Look for glue first
                                let glue_ips: Vec<_> = ns_addresses
                                    .iter()
                                    .filter(|addr| addr.name.eq_ignore_ascii_case(ns_name))
                                    .map(|addr| (Some(ns_name.clone()), addr.ip.clone()))
                                    .collect();

                                if !glue_ips.is_empty() {
                                    next_ns_ips.extend(glue_ips);
                                } else {
                                    // No glue, need to resolve NS name
                                    // For simplicity, we'll attempt to use current resolver or skip
                                    // In a full implementation, we'd recursively resolve the NS name
                                    // For now, we'll try a simple A lookup
                                    let ns_lookup_opts = DnsLookupOptions {
                                        name: ns_name.clone(),
                                        rtype: DnsRecordType::A,
                                        servers: vec![], // Use system resolver
                                        port: 53,
                                        use_tcp: false,
                                        timeout_ms: opts.timeout_ms,
                                        retries: opts.retries,
                                        dnssec: false,
                                        follow_cname: false,
                                        include_authority: false,
                                        include_additional: false,
                                        randomize_servers: false,
                                        format: OutputFormat::Json,
                                    };

                                    if let Ok(ns_lookup) = perform_dns_lookup(ns_lookup_opts).await
                                    {
                                        for record in &ns_lookup.answers {
                                            if record.rtype == "A" {
                                                if let Some(ip) = record
                                                    .data
                                                    .get("address")
                                                    .and_then(|v| v.as_str())
                                                {
                                                    next_ns_ips.push((
                                                        Some(ns_name.clone()),
                                                        ip.to_string(),
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            if next_ns_ips.is_empty() {
                                response.error = Some((
                                    DNS_TRACE_NO_NS.to_string(),
                                    format!(
                                        "No usable NS records found for zone: {}",
                                        label_chain.get(zone_idx + 1).unwrap_or(&"?".to_string())
                                    ),
                                ));
                                break;
                            }

                            current_ns_ips = next_ns_ips;
                        }

                        break; // Successfully queried this NS, move to next zone
                    } else if lookup_response.response.rcode == "NXDOMAIN" {
                        hops.push(hop.clone());
                        response.error = Some((
                            DNS_TRACE_NXDOMAIN.to_string(),
                            "The domain name does not exist (NXDOMAIN).".to_string(),
                        ));
                        query_succeeded = true;
                        break;
                    } else if lookup_response.response.rcode == "SERVFAIL" {
                        hops.push(hop.clone());
                        // Try next NS, but record the hop
                        continue;
                    } else {
                        hops.push(hop.clone());
                        response.error = Some((
                            DNS_TRACE_RCODE_ERROR.to_string(),
                            format!("DNS error: {}", lookup_response.response.rcode),
                        ));
                        query_succeeded = true;
                        break;
                    }
                }
                Err(e) => {
                    // Network error, try next NS
                    response
                        .warnings
                        .push(format!("Failed to query {}: {}", ns_ip, e));
                    continue;
                }
            }
        }

        if !query_succeeded {
            response.error = Some((
                DNS_TRACE_ALL_SERVERS_FAILED.to_string(),
                format!("All name servers failed for zone: {}", current_zone),
            ));
            break;
        }

        if response.error.is_some() {
            break;
        }

        hop_index += 1;
    }

    // Build final trace summary
    let mut final_answers = Vec::new();
    let mut final_rcode = None;
    let mut final_authoritative = false;

    if let Some(last_hop) = hops.last() {
        final_rcode = Some(last_hop.rcode.clone());
        final_authoritative = last_hop.authoritative;
        final_answers = last_hop.answers.clone();
    }

    // Extract CNAME chain from all hops
    let cname_chain = extract_cname_chain(&hops, &normalized_name);

    response.trace = Some(DnsTraceSummary {
        name: normalized_name.clone(),
        rtype: opts.rtype.as_str().to_string(),
        final_rcode,
        final_authoritative,
        hops,
        final_answers,
        cname_chain,
        depth: hop_index - 1,
    });

    // Set ok=true only if we got through without errors
    if response.error.is_none() {
        response.ok = true;
    }

    Ok(response)
}

pub async fn perform_dns_lookup(opts: DnsLookupOptions) -> Result<DnsLookupResponse> {
    let mut response = DnsLookupResponse::new(&opts);
    let start_time = std::time::Instant::now();

    // Build resolver configuration
    let (config, resolver_opts) = if opts.servers.is_empty() {
        // Use system configuration
        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.timeout = Duration::from_millis(opts.timeout_ms);
        resolver_opts.attempts = opts.retries as usize + 1;

        if opts.dnssec {
            resolver_opts.edns0 = true;
            // Enable DNSSEC validation if available
            resolver_opts.validate = true;
        }

        (system_resolver_config()?, resolver_opts)
    } else {
        // Use custom servers
        let mut config = ResolverConfig::new();
        let mut servers = opts.servers.clone();

        if opts.randomize_servers {
            servers.shuffle(&mut rand::thread_rng());
        }

        for server_str in servers {
            if let Ok(ip) = server_str.parse::<IpAddr>() {
                let socket_addr = SocketAddr::new(ip, opts.port);
                let protocol = if opts.use_tcp {
                    Protocol::Tcp
                } else {
                    Protocol::Udp
                };
                let nameserver = NameServerConfig::new(socket_addr, protocol);
                config.add_name_server(nameserver);
            }
        }

        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.timeout = Duration::from_millis(opts.timeout_ms);
        resolver_opts.attempts = opts.retries as usize + 1;

        if opts.dnssec {
            resolver_opts.edns0 = true;
            resolver_opts.validate = true;
        }

        (config, resolver_opts)
    };

    // Create resolver
    let resolver = TokioAsyncResolver::tokio(config, resolver_opts);

    // Perform the DNS lookup using generic lookup for all types
    let lookup_result = resolver
        .lookup(&opts.name, opts.rtype.to_trust_dns())
        .await
        .map(|lookup| {
            let answers = lookup.records().to_vec();
            // For now, authority and additional are empty since trust-dns doesn't expose them easily
            let authority: Vec<trust_dns_resolver::proto::rr::Record> = Vec::new();
            let additional: Vec<trust_dns_resolver::proto::rr::Record> = Vec::new();
            (answers, authority, additional)
        });

    let elapsed = start_time.elapsed();
    response.response.round_trip_time_ms = Some(elapsed.as_millis() as u64);

    match lookup_result {
        Ok((records, authority_records, additional_records)) => {
            response.ok = true;
            response.response.rcode = "NOERROR".to_string();

            // Set server used (first configured server for now)
            if !opts.servers.is_empty() {
                response.response.server_used = Some(opts.servers[0].clone());
            }

            // Process answer records
            for record in records {
                if let Some(rdata) = record.data() {
                    let dns_record = DnsRecord {
                        name: record.name().to_string(),
                        rtype: opts.rtype.as_str().to_string(),
                        class: "IN".to_string(),
                        ttl: record.ttl(),
                        data: rdata_to_json(rdata, opts.rtype.as_str()),
                    };
                    response.answers.push(dns_record);
                }
            }

            // Process authority records if requested
            if opts.include_authority {
                for record in authority_records {
                    if let Some(rdata) = record.data() {
                        let dns_record = DnsRecord {
                            name: record.name().to_string(),
                            rtype: format!("{:?}", record.record_type()),
                            class: "IN".to_string(),
                            ttl: record.ttl(),
                            data: rdata_to_json(rdata, &format!("{:?}", record.record_type())),
                        };
                        response.authority.push(dns_record);
                    }
                }
            }

            // Process additional records if requested
            if opts.include_additional {
                for record in additional_records {
                    if let Some(rdata) = record.data() {
                        let dns_record = DnsRecord {
                            name: record.name().to_string(),
                            rtype: format!("{:?}", record.record_type()),
                            class: "IN".to_string(),
                            ttl: record.ttl(),
                            data: rdata_to_json(rdata, &format!("{:?}", record.record_type())),
                        };
                        response.additional.push(dns_record);
                    }
                }
            }

            // Add DNSSEC warning if requested but not supported by the underlying resolver
            if opts.dnssec {
                response.warnings.push(
                    "DNSSEC validation status not available from resolver backend".to_string(),
                );
            }
        }
        Err(e) => {
            // Map DNS errors to our error codes
            let (error_code, error_message) = match e.kind() {
                ResolveErrorKind::NoRecordsFound { response_code, .. } => {
                    response.response.rcode = format!("{:?}", response_code);
                    match response_code {
                        trust_dns_resolver::proto::op::ResponseCode::NXDomain => (
                            DNS_LOOKUP_NXDOMAIN,
                            "The domain name does not exist (NXDOMAIN).".to_string(),
                        ),
                        trust_dns_resolver::proto::op::ResponseCode::ServFail => (
                            DNS_LOOKUP_SERVFAIL,
                            "Server failure (SERVFAIL).".to_string(),
                        ),
                        trust_dns_resolver::proto::op::ResponseCode::Refused => {
                            (DNS_LOOKUP_REFUSED, "Query refused (REFUSED).".to_string())
                        }
                        trust_dns_resolver::proto::op::ResponseCode::FormErr => {
                            (DNS_LOOKUP_FORMERR, "Format error (FORMERR).".to_string())
                        }
                        _ => (
                            DNS_LOOKUP_RCODE_ERROR,
                            format!("DNS error: {:?}", response_code),
                        ),
                    }
                }
                ResolveErrorKind::Timeout => {
                    (DNS_LOOKUP_TIMEOUT, "DNS query timed out.".to_string())
                }
                _ => {
                    if e.to_string().contains("network") || e.to_string().contains("connection") {
                        (DNS_LOOKUP_NETWORK_ERROR, format!("Network error: {}", e))
                    } else {
                        (
                            DNS_LOOKUP_ALL_SERVERS_FAILED,
                            format!("All DNS servers failed: {}", e),
                        )
                    }
                }
            };

            response.error = Some((error_code.to_string(), error_message));
        }
    }

    Ok(response)
}

// ==================== DNS Help Implementation ====================

impl DnsHandle {
    /// Check if help was requested. Matches whole tokens only: `help`,
    /// `--help`, `-h`, `--help=<verb>`, or a `help`/`h` argument.
    fn should_show_help(&self, verb: &str, args: &Args) -> bool {
        crate::core::help::HELP_ALIASES.contains(&verb)
            || verb.starts_with("--help=")
            || ["help", "h", "--help", "-h"]
                .iter()
                .any(|k| args.contains_key(*k))
    }

    /// Display the approved dns help (same text as `resh dns [<verb>] --help`).
    fn display_help(&self, io: &mut IoStreams, verb_specific: Option<&str>) -> Result<Status> {
        let text = crate::core::help::render_legacy("dns", &DNS_HELP, self.verbs(), verb_specific);
        write!(io.stdout, "{}", text)?;
        Ok(Status::ok())
    }
}

impl Handle for DnsHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &[
            "lookup",
            "resolve",
            "trace",
            "zone.fetch",
            "zone.update",
            "help",
            "--help",
            "-h",
        ]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&DNS_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check for help requests before normal verb processing
        if self.should_show_help(verb, args) {
            // Extract verb name for specific help if requested (e.g., --help=lookup)
            let verb_specific = if verb.starts_with("--help=") {
                verb.strip_prefix("--help=")
            } else {
                // Check if help is requested for a specific verb via arguments
                args.get("verb").map(|s| s.as_str())
            };

            return self.display_help(io, verb_specific);
        }

        match verb {
            "lookup" => self.verb_lookup(args, io),
            "resolve" => self.verb_resolve(args, io),
            "trace" => self.verb_trace(args, io),
            "zone.fetch" => self.verb_zone_fetch(args, io),
            "zone.update" => self.verb_zone_update(args, io),
            _ => bail!(
                "unknown verb for dns://: {} (available: lookup, resolve, trace, zone.fetch, zone.update, --help, -h, help)",
                verb
            ),
        }
    }
}

impl DnsHandle {
    fn verb_lookup(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments
        let opts = match DnsLookupOptions::from_args(args) {
            Ok(opts) => opts,
            Err(e) => {
                let error_msg = if e.to_string().contains("Invalid record type") {
                    format!("[{}] {}", DNS_LOOKUP_INVALID_TYPE, e)
                } else if e.to_string().contains("Invalid server IP") {
                    format!("[{}] {}", DNS_LOOKUP_INVALID_SERVER, e)
                } else if e.to_string().contains("Invalid port") {
                    format!("[{}] {}", DNS_LOOKUP_INVALID_PORT, e)
                } else if e.to_string().contains("timeout_ms must be greater than 0") {
                    format!("[{}] {}", DNS_LOOKUP_INVALID_TIMEOUT, e)
                } else if e.to_string().contains("name") && e.to_string().contains("empty") {
                    format!("[{}] {}", DNS_LOOKUP_INVALID_NAME, e)
                } else {
                    format!("[{}] {}", DNS_LOOKUP_INVALID_NAME, e)
                };
                return Ok(Status::err(1, error_msg));
            }
        };

        // Create Tokio runtime for async DNS operations
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                let error_msg = format!(
                    "[{}] Failed to create async runtime: {}",
                    DNS_LOOKUP_INTERNAL_ERROR, e
                );
                return Ok(Status::err(1, error_msg));
            }
        };

        // Perform DNS lookup
        let result = rt.block_on(perform_dns_lookup(opts.clone()));
        let response = match result {
            Ok(resp) => resp,
            Err(e) => {
                let error_msg = format!("[{}] Internal error: {}", DNS_LOOKUP_INTERNAL_ERROR, e);
                return Ok(Status::err(1, error_msg));
            }
        };

        // Output response
        let output = match opts.format {
            OutputFormat::Json => serde_json::to_string_pretty(&response.to_json())?,
            OutputFormat::Text => response.to_text(),
        };

        writeln!(io.stdout, "{}", output)?;

        if response.ok {
            Ok(Status::ok())
        } else {
            if let Some((code, message)) = &response.error {
                Ok(Status::err(1, format!("[{}] {}", code, message)))
            } else {
                Ok(Status::err(1, "DNS lookup failed"))
            }
        }
    }

    fn verb_resolve(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Only a reverse lookup has anything to validate.
        if args.get("validate_reverse").is_some_and(|v| v == "true")
            && args.get("mode").map(String::as_str) != Some("reverse")
        {
            return Ok(Status::err(
                2,
                "validate_reverse=true needs mode=reverse; nothing was done",
            ));
        }

        // Parse arguments
        let opts = match DnsResolveOptions::from_args(args) {
            Ok(opts) => opts,
            Err(e) => {
                let error_msg = if e.to_string().contains("Invalid mode") {
                    format!("[{}] {}", DNS_RESOLVE_INVALID_MODE, e)
                } else if e.to_string().contains("Invalid family") {
                    format!("[{}] {}", DNS_RESOLVE_INVALID_FAMILY, e)
                } else if e.to_string().contains("Invalid server IP") {
                    format!("[{}] {}", DNS_RESOLVE_INVALID_SERVER, e)
                } else if e.to_string().contains("Invalid port") {
                    format!("[{}] {}", DNS_RESOLVE_INVALID_PORT, e)
                } else if e.to_string().contains("timeout_ms must be greater than 0") {
                    format!("[{}] {}", DNS_RESOLVE_INVALID_TIMEOUT, e)
                } else if e.to_string().contains("name") && e.to_string().contains("empty") {
                    format!("[{}] {}", DNS_RESOLVE_INVALID_NAME, e)
                } else {
                    format!("[{}] {}", DNS_RESOLVE_INVALID_NAME, e)
                };
                return Ok(Status::err(1, error_msg));
            }
        };

        // Validate name based on mode
        match opts.mode {
            ResolveMode::Reverse => {
                if !is_ip_address(&opts.name) {
                    let error_msg = format!(
                        "[{}] Name must be a valid IP address for reverse mode",
                        DNS_RESOLVE_INVALID_NAME
                    );
                    return Ok(Status::err(1, error_msg));
                }
            }
            _ => {
                // Basic hostname validation
                if opts.name.is_empty() || opts.name.contains("..") {
                    let error_msg =
                        format!("[{}] Invalid hostname format", DNS_RESOLVE_INVALID_NAME);
                    return Ok(Status::err(1, error_msg));
                }
            }
        }

        // Create Tokio runtime for async DNS operations
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                let error_msg = format!(
                    "[{}] Failed to create async runtime: {}",
                    DNS_RESOLVE_INTERNAL_ERROR, e
                );
                return Ok(Status::err(1, error_msg));
            }
        };

        // Perform DNS resolution
        let result = rt.block_on(perform_dns_resolve(opts.clone()));
        let response = match result {
            Ok(resp) => resp,
            Err(e) => {
                let error_msg = if e.to_string().contains("CNAME loop") {
                    format!("[{}] CNAME loop detected", DNS_RESOLVE_CNAME_LOOP)
                } else if e.to_string().contains("Maximum CNAME depth") {
                    format!("[{}] Maximum CNAME depth exceeded", DNS_RESOLVE_CNAME_LOOP)
                } else if e.to_string().contains("No addresses found") {
                    format!("[{}] Host not found", DNS_RESOLVE_HOST_NOT_FOUND)
                } else if e.to_string().contains("No MX records") {
                    format!("[{}] No MX records found", DNS_RESOLVE_NO_MX)
                } else if e.to_string().contains("No SRV records") {
                    format!("[{}] No SRV records found", DNS_RESOLVE_NO_SRV)
                } else if e.to_string().contains("No PTR record") {
                    format!("[{}] No PTR record found", DNS_RESOLVE_NO_PTR)
                } else {
                    format!("[{}] Internal error: {}", DNS_RESOLVE_INTERNAL_ERROR, e)
                };
                return Ok(Status::err(1, error_msg));
            }
        };

        // Output response
        let output = match opts.format {
            OutputFormat::Json => serde_json::to_string_pretty(&response.to_json())?,
            OutputFormat::Text => response.to_text(),
        };

        writeln!(io.stdout, "{}", output)?;

        if response.ok {
            Ok(Status::ok())
        } else {
            if let Some((code, message)) = &response.error {
                Ok(Status::err(1, format!("[{}] {}", code, message)))
            } else {
                Ok(Status::err(1, "DNS resolution failed"))
            }
        }
    }

    fn verb_trace(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments
        let opts = match DnsTraceOptions::from_args(args) {
            Ok(opts) => opts,
            Err(e) => {
                let error_msg = if e.to_string().contains("Invalid record type") {
                    format!("[{}] {}", DNS_TRACE_INVALID_TYPE, e)
                } else if e.to_string().contains("Invalid root server IP") {
                    format!("[{}] {}", DNS_TRACE_INVALID_ROOT_SERVER, e)
                } else if e.to_string().contains("Invalid port") {
                    format!("[{}] {}", DNS_TRACE_INVALID_PORT, e)
                } else if e.to_string().contains("timeout_ms must be greater than 0") {
                    format!("[{}] {}", DNS_TRACE_INVALID_TIMEOUT, e)
                } else if e.to_string().contains("max_depth must be greater than 0") {
                    format!("[{}] {}", DNS_TRACE_INVALID_MAX_DEPTH, e)
                } else if e.to_string().contains("name") && e.to_string().contains("empty") {
                    format!("[{}] {}", DNS_TRACE_INVALID_NAME, e)
                } else {
                    format!("[{}] {}", DNS_TRACE_INVALID_NAME, e)
                };
                return Ok(Status::err(1, error_msg));
            }
        };

        // Basic name validation
        if opts.name.is_empty() || opts.name.contains("..") {
            let error_msg = format!("[{}] Invalid domain name format", DNS_TRACE_INVALID_NAME);
            return Ok(Status::err(1, error_msg));
        }

        // Create Tokio runtime for async DNS operations
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                let error_msg = format!(
                    "[{}] Failed to create async runtime: {}",
                    DNS_TRACE_INTERNAL_ERROR, e
                );
                return Ok(Status::err(1, error_msg));
            }
        };

        // Perform DNS trace
        let result = rt.block_on(perform_dns_trace(opts.clone()));
        let response = match result {
            Ok(resp) => resp,
            Err(e) => {
                let error_msg = format!("[{}] Internal error: {}", DNS_TRACE_INTERNAL_ERROR, e);
                return Ok(Status::err(1, error_msg));
            }
        };

        // Output response
        let output = match opts.format {
            OutputFormat::Json => serde_json::to_string_pretty(&response.to_json())?,
            OutputFormat::Text => response.to_text(),
        };

        writeln!(io.stdout, "{}", output)?;

        if response.ok {
            Ok(Status::ok())
        } else {
            if let Some((code, message)) = &response.error {
                Ok(Status::err(1, format!("[{}] {}", code, message)))
            } else {
                Ok(Status::err(1, "DNS trace failed"))
            }
        }
    }
}

// ==================== DNS Zone Fetch Implementation ====================

#[derive(Debug, Clone, PartialEq)]
pub enum ZoneTransferType {
    Axfr,
    Ixfr,
}

impl ZoneTransferType {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "AXFR" => Ok(Self::Axfr),
            "IXFR" => Ok(Self::Ixfr),
            _ => bail!("Invalid transfer type: {}", s),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Axfr => "AXFR",
            Self::Ixfr => "IXFR",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsZoneFetchOptions {
    pub zone: String,
    pub transfer: ZoneTransferType,
    pub serial: Option<u32>,

    pub servers: Vec<String>,
    pub port: u16,
    pub use_tcp: bool,
    pub timeout_ms: u64,
    pub retries: u32,
    pub dnssec: bool,

    pub tsig_key_name: Option<String>,
    pub tsig_secret: Option<String>,
    pub tsig_algorithm: Option<String>,

    pub max_records: u64,
    pub include_raw: bool,
    pub prefer_ipv6: bool,

    pub format: OutputFormat,
}

impl DnsZoneFetchOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let zone = args
            .get("zone")
            .ok_or_else(|| anyhow::anyhow!("Missing required parameter: zone"))?
            .clone();

        // Validate zone name
        if zone.is_empty() {
            bail!("Zone name cannot be empty");
        }

        let transfer_str = args.get("transfer").map(|s| s.as_str()).unwrap_or("AXFR");
        let transfer = ZoneTransferType::from_str(transfer_str)?;

        let serial = if let Some(s) = args.get("serial") {
            Some(s.parse::<u32>().context("Invalid serial number")?)
        } else {
            None
        };

        // Validate IXFR requires serial
        if matches!(transfer, ZoneTransferType::Ixfr) && serial.is_none() {
            bail!("IXFR transfer requires serial parameter");
        }

        let servers = if let Some(servers_str) = args.get("servers") {
            serde_json::from_str::<Vec<String>>(servers_str)
                .unwrap_or_else(|_| vec![servers_str.clone()])
        } else {
            vec![]
        };

        let port = if let Some(p) = args.get("port") {
            let port_val = p.parse::<u16>().context("Invalid port number")?;
            if port_val == 0 {
                bail!("Port must be between 1 and 65535");
            }
            port_val
        } else {
            53
        };

        let use_tcp = if let Some(tcp) = args.get("use_tcp") {
            tcp.parse::<bool>().unwrap_or(true)
        } else {
            true
        };

        let timeout_ms = if let Some(t) = args.get("timeout_ms") {
            let timeout = t.parse::<u64>().context("Invalid timeout_ms")?;
            if timeout == 0 {
                bail!("timeout_ms must be greater than 0");
            }
            timeout
        } else {
            5000
        };

        let retries = if let Some(r) = args.get("retries") {
            let retry_val = r.parse::<u32>().context("Invalid retries")?;
            if retry_val > 100 {
                bail!("retries must be <= 100");
            }
            retry_val
        } else {
            1
        };

        let dnssec = args
            .get("dnssec")
            .and_then(|s| s.parse::<bool>().ok())
            .unwrap_or(false);

        let tsig_key_name = args.get("tsig_key_name").cloned();
        let tsig_secret = args.get("tsig_secret").cloned();
        let tsig_algorithm = args.get("tsig_algorithm").cloned();

        // Validate TSIG config
        let tsig_fields_set = [tsig_key_name.is_some(), tsig_secret.is_some()];
        let tsig_count = tsig_fields_set.iter().filter(|&&x| x).count();
        if tsig_count > 0 && tsig_count < 2 {
            bail!("TSIG requires both tsig_key_name and tsig_secret");
        }

        // Validate TSIG secret is valid base64
        if let Some(ref secret) = tsig_secret {
            general_purpose::STANDARD
                .decode(secret)
                .context("TSIG secret must be valid base64")?;
        }

        let max_records = if let Some(m) = args.get("max_records") {
            let max = m.parse::<u64>().context("Invalid max_records")?;
            if max == 0 {
                bail!("max_records must be greater than 0");
            }
            max
        } else {
            1_000_000
        };

        let include_raw = args
            .get("include_raw")
            .and_then(|s| s.parse::<bool>().ok())
            .unwrap_or(false);

        let prefer_ipv6 = args
            .get("prefer_ipv6")
            .and_then(|s| s.parse::<bool>().ok())
            .unwrap_or(false);

        let format = if let Some(fmt) = args.get("format") {
            OutputFormat::from_str(fmt)?
        } else {
            OutputFormat::Json
        };

        Ok(DnsZoneFetchOptions {
            zone,
            transfer,
            serial,
            servers,
            port,
            use_tcp,
            timeout_ms,
            retries,
            dnssec,
            tsig_key_name,
            tsig_secret,
            tsig_algorithm,
            max_records,
            include_raw,
            prefer_ipv6,
            format,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZoneSoa {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZoneRecord {
    pub name: String,
    pub rtype: String,
    pub class: String,
    pub ttl: u32,
    pub data: Value,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZoneChanges {
    pub old_serial: u32,
    pub new_serial: u32,
    pub deleted: Vec<ZoneRecord>,
    pub added: Vec<ZoneRecord>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZoneSummary {
    pub name: String,
    pub transfer_requested: String,
    pub transfer_used: String,
    pub server_used: String,
    pub soa: ZoneSoa,
    pub serial: u32,
    pub record_count: u64,
    pub records: Vec<ZoneRecord>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsZoneFetchResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,
    pub query: Value,
    pub zone: Option<ZoneSummary>,
    pub changes: Option<ZoneChanges>,
    pub raw: Option<Value>,
    pub error: Option<(String, String)>,
    pub warnings: Vec<String>,
}

impl DnsZoneFetchResponse {
    pub fn new(opts: &DnsZoneFetchOptions) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let query = json!({
            "zone": opts.zone,
            "transfer": opts.transfer.as_str(),
            "serial": opts.serial,
            "servers": opts.servers,
            "port": opts.port,
            "use_tcp": opts.use_tcp,
            "timeout_ms": opts.timeout_ms,
            "retries": opts.retries,
            "dnssec": opts.dnssec,
            "max_records": opts.max_records,
            "tsig_key_name": opts.tsig_key_name,
            "tsig_algorithm": opts.tsig_algorithm,
        });

        Self {
            ok: true,
            timestamp_unix_ms: timestamp,
            query,
            zone: None,
            changes: None,
            raw: None,
            error: None,
            warnings: vec![],
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();
        output.push_str("Zone Fetch\n");
        output.push_str("==========\n\n");

        if let Some(ref zone) = self.zone {
            output.push_str(&format!("Zone        : {}\n", zone.name));
            output.push_str(&format!("Transfer    : {}\n", zone.transfer_used));
            output.push_str(&format!("Server Used : {}\n", zone.server_used));
            output.push_str(&format!("Serial      : {}\n", zone.serial));
            output.push_str(&format!("Records     : {}\n\n", zone.record_count));

            output.push_str("SOA:\n");
            output.push_str(&format!("  MNAME   : {}\n", zone.soa.mname));
            output.push_str(&format!("  RNAME   : {}\n", zone.soa.rname));
            output.push_str(&format!("  Serial  : {}\n", zone.soa.serial));
            output.push_str(&format!("  Refresh : {}\n", zone.soa.refresh));
            output.push_str(&format!("  Retry   : {}\n", zone.soa.retry));
            output.push_str(&format!("  Expire  : {}\n", zone.soa.expire));
            output.push_str(&format!("  Minimum : {}\n\n", zone.soa.minimum));

            // Show NS records
            let ns_records: Vec<&ZoneRecord> =
                zone.records.iter().filter(|r| r.rtype == "NS").collect();
            if !ns_records.is_empty() {
                output.push_str("NS Records:\n");
                for rec in ns_records.iter().take(10) {
                    output.push_str(&format!(
                        "  {}  {} IN {}  {}\n",
                        rec.name,
                        rec.ttl,
                        rec.rtype,
                        rec.data
                            .get("nsdname")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?")
                    ));
                }
                output.push_str("\n");
            }

            // Show sample records (first 10 non-SOA, non-NS)
            let other_records: Vec<&ZoneRecord> = zone
                .records
                .iter()
                .filter(|r| r.rtype != "SOA" && r.rtype != "NS")
                .take(10)
                .collect();
            if !other_records.is_empty() {
                output.push_str("Sample Records:\n");
                for rec in other_records {
                    let data_str = match rec.rtype.as_str() {
                        "A" => rec
                            .data
                            .get("address")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?")
                            .to_string(),
                        "AAAA" => rec
                            .data
                            .get("address")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?")
                            .to_string(),
                        "CNAME" => rec
                            .data
                            .get("cname")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?")
                            .to_string(),
                        "MX" => {
                            let pref = rec
                                .data
                                .get("preference")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);
                            let exch = rec
                                .data
                                .get("exchange")
                                .and_then(|v| v.as_str())
                                .unwrap_or("?");
                            format!("{} {}", pref, exch)
                        }
                        "TXT" => {
                            if let Some(text_arr) = rec.data.get("text").and_then(|v| v.as_array())
                            {
                                let texts: Vec<String> = text_arr
                                    .iter()
                                    .filter_map(|v| v.as_str().map(|s| format!("\"{}\"", s)))
                                    .collect();
                                texts.join(" ")
                            } else {
                                "?".to_string()
                            }
                        }
                        _ => serde_json::to_string(&rec.data).unwrap_or_else(|_| "?".to_string()),
                    };
                    output.push_str(&format!(
                        "  {}  {} IN {}  {}\n",
                        rec.name, rec.ttl, rec.rtype, data_str
                    ));
                }
                output.push_str("\n");
            }

            if let Some(ref changes) = self.changes {
                output.push_str(&format!(
                    "Changes ({} -> {}):\n",
                    changes.old_serial, changes.new_serial
                ));
                output.push_str(&format!("  Deleted: {}\n", changes.deleted.len()));
                output.push_str(&format!("  Added: {}\n\n", changes.added.len()));
            }
        } else if let Some((ref code, ref message)) = self.error {
            output.push_str(&format!("Error:\n  [{}] {}\n\n", code, message));
        }

        if !self.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &self.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        } else {
            output.push_str("Warnings:\n  (none)\n");
        }

        output
    }
}

// Helper function to normalize DNS name to FQDN
fn normalize_zone_name(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{}.", name)
    }
}

// NOTE: Full zone transfer implementation (AXFR/IXFR) requires low-level DNS protocol
// handling not available in trust-dns-resolver. This is a placeholder that demonstrates
// the architecture. A production implementation would need:
// 1. Direct TCP connection to DNS server
// 2. Manual DNS message construction for AXFR/IXFR queries
// 3. Streaming response parsing
// 4. TSIG signing/verification
//
// For now, this returns an error indicating the feature needs trust-dns-client integration
async fn perform_zone_fetch(opts: DnsZoneFetchOptions) -> Result<DnsZoneFetchResponse> {
    let mut response = DnsZoneFetchResponse::new(&opts);

    // Normalize zone name to FQDN
    let zone_fqdn = normalize_zone_name(&opts.zone);

    // Resolve NS servers if opts.servers is empty
    let servers = if opts.servers.is_empty() {
        // Query for NS records to find authoritative servers
        match resolve_authoritative_servers(&zone_fqdn, opts.prefer_ipv6).await {
            Ok(ns_servers) if !ns_servers.is_empty() => ns_servers,
            Ok(_) => {
                response.ok = false;
                response.error = Some((
                    DNS_ZONE_FETCH_ALL_SERVERS_FAILED.to_string(),
                    format!(
                        "No authoritative name servers found for zone: {}",
                        zone_fqdn
                    ),
                ));
                return Ok(response);
            }
            Err(e) => {
                response.ok = false;
                response.error = Some((
                    DNS_ZONE_FETCH_NETWORK_ERROR.to_string(),
                    format!("Failed to resolve authoritative servers: {}", e),
                ));
                return Ok(response);
            }
        }
    } else {
        opts.servers.clone()
    };

    // Try each server until one succeeds
    let mut last_error = None;

    for server_ip in &servers {
        // Parse server IP
        let ip_addr = match server_ip.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => {
                response
                    .warnings
                    .push(format!("Invalid server IP: {}", server_ip));
                continue;
            }
        };

        let socket_addr = SocketAddr::new(ip_addr, opts.port);

        // Attempt zone transfer
        match perform_zone_transfer_from_server(&zone_fqdn, socket_addr, &opts).await {
            Ok((soa, records)) => {
                // Build zone summary
                let record_count = records.len() as u64;

                let zone_summary = ZoneSummary {
                    name: zone_fqdn.clone(),
                    transfer_requested: opts.transfer.as_str().to_string(),
                    transfer_used: "AXFR".to_string(), // Currently only AXFR is implemented
                    server_used: server_ip.clone(),
                    soa: soa.clone(),
                    serial: soa.serial,
                    record_count,
                    records,
                };

                response.zone = Some(zone_summary);
                response.ok = true;
                return Ok(response);
            }
            Err(e) => {
                let error_msg = format!("Server {} failed: {}", server_ip, e);
                response.warnings.push(error_msg.clone());
                last_error = Some(e);
                continue;
            }
        }
    }

    // All servers failed
    response.ok = false;
    response.error = Some((
        DNS_ZONE_FETCH_ALL_SERVERS_FAILED.to_string(),
        format!(
            "All servers failed. Last error: {}",
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "Unknown error".to_string())
        ),
    ));

    Ok(response)
}

/// The host's own resolvers. There is no fallback: a query sent to a public
/// resolver instead would leak the name and answer for a different view.
pub(crate) fn system_resolver_config() -> Result<ResolverConfig> {
    let (config, _) = trust_dns_resolver::system_conf::read_system_conf()
        .context("failed to read the system resolver configuration")?;
    Ok(config)
}

// Helper function to resolve authoritative servers for a zone
async fn resolve_authoritative_servers(zone: &str, prefer_ipv6: bool) -> Result<Vec<String>> {
    let resolver = TokioAsyncResolver::tokio(system_resolver_config()?, ResolverOpts::default());

    // Query for NS records
    let zone_name = Name::from_str(zone)?;
    let ns_lookup = resolver
        .lookup(zone_name.clone(), TrustDnsRecordType::NS)
        .await?;

    let mut server_ips = Vec::new();

    // Extract NS names and resolve to IPs
    for record in ns_lookup.records() {
        if let Some(RData::NS(ns_name)) = record.data() {
            // Convert NS name to Name for lookup
            let ns_name_for_lookup = ns_name.0.clone();

            // Try A or AAAA lookup based on preference
            if prefer_ipv6 {
                if let Ok(aaaa_lookup) = resolver
                    .lookup(ns_name_for_lookup.clone(), TrustDnsRecordType::AAAA)
                    .await
                {
                    for aaaa_rec in aaaa_lookup.records() {
                        if let Some(RData::AAAA(ipv6)) = aaaa_rec.data() {
                            server_ips.push(ipv6.to_string());
                        }
                    }
                }
            }

            // Always try A records as fallback or primary
            if let Ok(a_lookup) = resolver
                .lookup(ns_name_for_lookup.clone(), TrustDnsRecordType::A)
                .await
            {
                for a_rec in a_lookup.records() {
                    if let Some(RData::A(ipv4)) = a_rec.data() {
                        server_ips.push(ipv4.to_string());
                    }
                }
            }
        }
    }

    Ok(server_ips)
}

// Perform zone transfer from a specific server
async fn perform_zone_transfer_from_server(
    zone: &str,
    server: SocketAddr,
    opts: &DnsZoneFetchOptions,
) -> Result<(ZoneSoa, Vec<ZoneRecord>)> {
    use tokio::net::TcpStream;
    use trust_dns_proto::serialize::binary::BinDecodable;
    use trust_dns_proto::serialize::binary::{BinEncodable, BinEncoder};

    // Connect to server via TCP
    let tcp_stream = tokio::time::timeout(
        Duration::from_millis(opts.timeout_ms),
        TcpStream::connect(server),
    )
    .await
    .context("Connection timeout")?
    .context("Failed to connect to server")?;

    // Create AXFR query message
    let zone_name = Name::from_str(zone)?;
    let mut message = Message::new();
    message.set_id(rand::random::<u16>());
    message.set_message_type(MessageType::Query);
    message.set_op_code(OpCode::Query);

    let query_type = match opts.transfer {
        ZoneTransferType::Axfr => ProtoRecordType::AXFR,
        ZoneTransferType::Ixfr => {
            // IXFR implementation would require additional SOA record in authority section
            // For now, fall back to AXFR
            ProtoRecordType::AXFR
        }
    };

    let query = Query::query(zone_name.clone(), query_type);
    message.add_query(query);

    // Encode message
    let mut buffer = Vec::new();
    {
        let mut encoder = BinEncoder::new(&mut buffer);
        message.emit(&mut encoder)?;
    }

    // Send message with length prefix (TCP DNS format)
    let msg_len = buffer.len() as u16;
    let mut tcp_buffer = Vec::new();
    tcp_buffer.extend_from_slice(&msg_len.to_be_bytes());
    tcp_buffer.extend_from_slice(&buffer);

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut reader, mut writer) = tcp_stream.into_split();

    writer.write_all(&tcp_buffer).await?;
    writer.flush().await?;

    // Read responses - AXFR can return multiple messages
    let mut all_records = Vec::new();
    let mut soa_record: Option<ZoneSoa> = None;
    let mut soa_count = 0;

    loop {
        // Read length prefix
        let mut len_bytes = [0u8; 2];
        match tokio::time::timeout(
            Duration::from_millis(opts.timeout_ms),
            reader.read_exact(&mut len_bytes),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Ok(Err(e)) => bail!("Failed to read response length: {}", e),
            Err(_) => bail!("Timeout reading response"),
        }

        let msg_len = u16::from_be_bytes(len_bytes) as usize;

        // Read message
        let mut msg_buffer = vec![0u8; msg_len];
        tokio::time::timeout(
            Duration::from_millis(opts.timeout_ms),
            reader.read_exact(&mut msg_buffer),
        )
        .await??;

        // Decode message
        let response_msg = Message::from_bytes(&msg_buffer)?;

        // Check RCODE
        match response_msg.response_code() {
            ResponseCode::NoError => {}
            ResponseCode::Refused => bail!("Zone transfer refused by server"),
            ResponseCode::NXDomain => bail!("Zone does not exist (NXDOMAIN)"),
            ResponseCode::ServFail => bail!("Server failure (SERVFAIL)"),
            ResponseCode::FormErr => bail!("Format error (FORMERR)"),
            other => bail!("DNS error: {:?}", other),
        }

        // Process answers
        for record in response_msg.answers() {
            // Convert record to ZoneRecord
            let zone_record = proto_record_to_zone_record(record)?;

            // Track SOA records
            if zone_record.rtype == "SOA" {
                soa_count += 1;
                if soa_count == 1 {
                    // First SOA - extract SOA data
                    soa_record = Some(extract_soa_from_record(&zone_record)?);
                } else if soa_count == 2 {
                    // Second SOA marks end of AXFR
                    all_records.push(zone_record);
                    break;
                }
            }

            all_records.push(zone_record);

            // Check max_records limit
            if all_records.len() as u64 >= opts.max_records {
                bail!("Maximum record limit ({}) exceeded", opts.max_records);
            }
        }

        // If we saw 2 SOA records, we're done
        if soa_count >= 2 {
            break;
        }
    }

    // Validate we got proper AXFR format (should have at least 2 SOA records)
    if soa_count < 2 {
        bail!("Invalid AXFR stream: expected SOA records at start and end");
    }

    let soa = soa_record.ok_or_else(|| anyhow::anyhow!("No SOA record found in zone transfer"))?;

    Ok((soa, all_records))
}

// Convert protocol record to zone record
fn proto_record_to_zone_record(record: &ProtoRecord) -> Result<ZoneRecord> {
    let name = record.name().to_string();
    let rtype = format!("{:?}", record.record_type());
    let ttl = record.ttl();
    let class = format!("{:?}", record.dns_class());

    let data = match record.data() {
        Some(rdata) => rdata_to_json(rdata, &rtype),
        None => json!({}),
    };

    Ok(ZoneRecord {
        name,
        rtype,
        class,
        ttl,
        data,
    })
}

// Extract SOA data from zone record
fn extract_soa_from_record(record: &ZoneRecord) -> Result<ZoneSoa> {
    let mname = record
        .data
        .get("mname")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing mname in SOA record"))?
        .to_string();

    let rname = record
        .data
        .get("rname")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing rname in SOA record"))?
        .to_string();

    let serial = record
        .data
        .get("serial")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("Missing serial in SOA record"))? as u32;

    let refresh = record
        .data
        .get("refresh")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("Missing refresh in SOA record"))? as u32;

    let retry = record
        .data
        .get("retry")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("Missing retry in SOA record"))? as u32;

    let expire = record
        .data
        .get("expire")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("Missing expire in SOA record"))? as u32;

    let minimum = record
        .data
        .get("minimum")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("Missing minimum in SOA record"))? as u32;

    Ok(ZoneSoa {
        mname,
        rname,
        serial,
        refresh,
        retry,
        expire,
        minimum,
    })
}

impl DnsHandle {
    fn verb_zone_fetch(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments with detailed error mapping
        let opts = match DnsZoneFetchOptions::from_args(args) {
            Ok(opts) => opts,
            Err(e) => {
                let error_msg = {
                    let err_str = e.to_string();
                    if err_str.contains("Missing required parameter: zone") {
                        format!("[{}] {}", DNS_ZONE_FETCH_INVALID_ZONE, err_str)
                    } else if err_str.contains("Invalid transfer type") {
                        format!("[{}] {}", DNS_ZONE_FETCH_INVALID_TRANSFER_TYPE, err_str)
                    } else if err_str.contains("IXFR transfer requires serial") {
                        format!("[{}] {}", DNS_ZONE_FETCH_MISSING_SERIAL, err_str)
                    } else if err_str.contains("Port must be between") {
                        format!("[{}] {}", DNS_ZONE_FETCH_INVALID_PORT, err_str)
                    } else if err_str.contains("timeout_ms must be") {
                        format!("[{}] {}", DNS_ZONE_FETCH_INVALID_TIMEOUT, err_str)
                    } else if err_str.contains("retries must be") {
                        format!("[{}] {}", DNS_ZONE_FETCH_INVALID_RETRIES, err_str)
                    } else if err_str.contains("max_records must be") {
                        format!("[{}] {}", DNS_ZONE_FETCH_INVALID_MAX_RECORDS, err_str)
                    } else if err_str.contains("TSIG requires both") {
                        format!("[{}] {}", DNS_ZONE_FETCH_INVALID_TSIG_CONFIG, err_str)
                    } else if err_str.contains("TSIG secret must be valid base64") {
                        format!("[{}] {}", DNS_ZONE_FETCH_INVALID_TSIG_SECRET, err_str)
                    } else {
                        format!("[{}] {}", DNS_ZONE_FETCH_INTERNAL_ERROR, err_str)
                    }
                };
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        // Create async runtime and perform zone fetch
        let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;

        let result = rt.block_on(perform_zone_fetch(opts.clone()));

        let response = match result {
            Ok(resp) => resp,
            Err(e) => {
                let error_msg =
                    format!("[{}] Internal error: {}", DNS_ZONE_FETCH_INTERNAL_ERROR, e);
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        // Format output
        let output = match opts.format {
            OutputFormat::Json => response.to_json(),
            OutputFormat::Text => response.to_text(),
        };

        writeln!(io.stdout, "{}", output)?;

        if response.ok {
            Ok(Status::ok())
        } else {
            Ok(Status::err(1, "Zone fetch failed"))
        }
    }
}

// ==================== DNS Zone Update Implementation ====================

#[derive(Debug, Clone, PartialEq)]
pub enum ZoneUpdatePrerequisiteKind {
    RecordExists,
    RecordNotExists,
    NameInUse,
    NameNotInUse,
    ZoneSerialAtLeast,
}

impl ZoneUpdatePrerequisiteKind {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "record_exists" => Ok(Self::RecordExists),
            "record_not_exists" => Ok(Self::RecordNotExists),
            "name_in_use" => Ok(Self::NameInUse),
            "name_not_in_use" => Ok(Self::NameNotInUse),
            "zone_serial_at_least" => Ok(Self::ZoneSerialAtLeast),
            _ => bail!("Invalid prerequisite kind: {}", s),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RecordExists => "record_exists",
            Self::RecordNotExists => "record_not_exists",
            Self::NameInUse => "name_in_use",
            Self::NameNotInUse => "name_not_in_use",
            Self::ZoneSerialAtLeast => "zone_serial_at_least",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZoneUpdateRecordData {
    #[serde(flatten)]
    pub json: Value,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZoneUpdateAdd {
    pub name: String,
    pub rtype: String,
    pub ttl: u32,
    pub data: ZoneUpdateRecordData,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZoneUpdateDelete {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete_all: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<ZoneUpdateRecordData>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZoneUpdatePrerequisite {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<ZoneUpdateRecordData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct DnsZoneUpdateOptions {
    pub zone: String,

    pub servers: Vec<String>,
    pub port: u16,
    pub use_tcp: bool,
    pub timeout_ms: u64,
    pub retries: u32,

    pub tsig_key_name: Option<String>,
    pub tsig_secret: Option<String>,
    pub tsig_algorithm: Option<String>,

    pub prerequisites: Vec<ZoneUpdatePrerequisite>,
    pub adds: Vec<ZoneUpdateAdd>,
    pub deletes: Vec<ZoneUpdateDelete>,

    pub max_changes: u32,
    pub dry_run: bool,
    pub include_raw: bool,

    pub format: OutputFormat,
}

impl DnsZoneUpdateOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let zone = args
            .get("zone")
            .ok_or_else(|| anyhow::anyhow!("Missing required parameter: zone"))?
            .clone();

        // Validate zone name
        if zone.is_empty() {
            bail!("Zone name cannot be empty");
        }

        let servers = if let Some(servers_str) = args.get("servers") {
            serde_json::from_str::<Vec<String>>(servers_str)
                .unwrap_or_else(|_| vec![servers_str.clone()])
        } else {
            vec![]
        };

        // Validate servers if provided
        for server in &servers {
            if server.is_empty() {
                bail!("Server address cannot be empty");
            }
        }

        let port = if let Some(p) = args.get("port") {
            let port_val = p.parse::<u16>().context("Invalid port number")?;
            if port_val == 0 {
                bail!("Port must be between 1 and 65535");
            }
            port_val
        } else {
            53
        };

        let use_tcp = if let Some(tcp) = args.get("use_tcp") {
            tcp.parse::<bool>().unwrap_or(true)
        } else {
            true
        };

        let timeout_ms = if let Some(t) = args.get("timeout_ms") {
            let timeout = t.parse::<u64>().context("Invalid timeout_ms")?;
            if timeout == 0 {
                bail!("timeout_ms must be greater than 0");
            }
            timeout
        } else {
            3000
        };

        let retries = if let Some(r) = args.get("retries") {
            let retry_val = r.parse::<u32>().context("Invalid retries")?;
            if retry_val > 100 {
                bail!("retries must be <= 100");
            }
            retry_val
        } else {
            1
        };

        let tsig_key_name = args.get("tsig_key_name").cloned();
        let tsig_secret = args.get("tsig_secret").cloned();
        let tsig_algorithm = args.get("tsig_algorithm").cloned();

        // Validate TSIG config
        let tsig_fields_set = [tsig_key_name.is_some(), tsig_secret.is_some()];
        let tsig_count = tsig_fields_set.iter().filter(|&&x| x).count();
        if tsig_count > 0 && tsig_count < 2 {
            bail!("TSIG requires both tsig_key_name and tsig_secret");
        }

        // Validate TSIG secret is valid base64
        if let Some(ref secret) = tsig_secret {
            general_purpose::STANDARD
                .decode(secret)
                .context("TSIG secret must be valid base64")?;
        }

        // Parse prerequisites
        let prerequisites = if let Some(prereq_str) = args.get("prerequisites") {
            serde_json::from_str::<Vec<ZoneUpdatePrerequisite>>(prereq_str)
                .context("Invalid prerequisites JSON")?
        } else {
            vec![]
        };

        // Validate prerequisites
        for prereq in &prerequisites {
            let _kind = ZoneUpdatePrerequisiteKind::from_str(&prereq.kind)
                .context("Invalid prerequisite kind")?;

            // Validate prerequisite has required fields based on kind
            match prereq.kind.as_str() {
                "zone_serial_at_least" => {
                    if prereq.serial.is_none() {
                        bail!("Prerequisite 'zone_serial_at_least' requires 'serial' field");
                    }
                }
                _ => {
                    if prereq.name.is_none() {
                        bail!("Prerequisite '{}' requires 'name' field", prereq.kind);
                    }
                }
            }
        }

        // Parse adds
        let adds = if let Some(adds_str) = args.get("adds") {
            serde_json::from_str::<Vec<ZoneUpdateAdd>>(adds_str).context("Invalid adds JSON")?
        } else {
            vec![]
        };

        // Validate adds
        for add in &adds {
            if add.name.is_empty() {
                bail!("Add record name cannot be empty");
            }
            // Validate record type
            DnsRecordType::from_str(&add.rtype).context("Invalid record type in add")?;
            // TTL validated by u32 type
        }

        // Parse deletes
        let deletes = if let Some(deletes_str) = args.get("deletes") {
            serde_json::from_str::<Vec<ZoneUpdateDelete>>(deletes_str)
                .context("Invalid deletes JSON")?
        } else {
            vec![]
        };

        // Validate deletes
        for delete in &deletes {
            if delete.name.is_empty() {
                bail!("Delete record name cannot be empty");
            }

            let delete_all = delete.delete_all.unwrap_or(false);

            if delete_all {
                // delete_all=true: data must not be present
                if delete.data.is_some() {
                    bail!("Delete with delete_all=true must not specify data");
                }
            } else {
                // delete_all=false or absent: must have rtype and data
                if delete.rtype.is_none() {
                    bail!("Delete without delete_all must specify rtype");
                }
                if delete.data.is_none() {
                    bail!("Delete without delete_all must specify data");
                }
            }

            // Validate record type if present
            if let Some(ref rtype) = delete.rtype {
                DnsRecordType::from_str(rtype).context("Invalid record type in delete")?;
            }
        }

        let max_changes = if let Some(m) = args.get("max_changes") {
            let max = m.parse::<u32>().context("Invalid max_changes")?;
            if max == 0 {
                bail!("max_changes must be greater than 0");
            }
            max
        } else {
            1000
        };

        // Check total changes against max_changes
        let total_changes = adds.len() + deletes.len();
        if total_changes > max_changes as usize {
            bail!(
                "Total changes ({}) exceeds max_changes ({})",
                total_changes,
                max_changes
            );
        }

        let dry_run = crate::core::lenient::dry_run(args)?;

        let include_raw = args
            .get("include_raw")
            .and_then(|s| s.parse::<bool>().ok())
            .unwrap_or(false);

        let format = if let Some(fmt) = args.get("format") {
            OutputFormat::from_str(fmt)?
        } else {
            OutputFormat::Json
        };

        Ok(DnsZoneUpdateOptions {
            zone,
            servers,
            port,
            use_tcp,
            timeout_ms,
            retries,
            tsig_key_name,
            tsig_secret,
            tsig_algorithm,
            prerequisites,
            adds,
            deletes,
            max_changes,
            dry_run,
            include_raw,
            format,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZoneUpdateSummary {
    pub zone: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_used: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rcode: Option<String>,
    pub tsig_used: bool,
    pub applied_adds: u32,
    pub applied_deletes: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub round_trip_time_ms: Option<u64>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZoneUpdateDetails {
    pub prerequisites: Vec<ZoneUpdatePrerequisite>,
    pub adds: Vec<ZoneUpdateAdd>,
    pub deletes: Vec<ZoneUpdateDelete>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsZoneUpdateResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,
    pub query: Value,
    pub summary: ZoneUpdateSummary,
    pub details: ZoneUpdateDetails,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<(String, String)>,
    pub warnings: Vec<String>,
}

impl DnsZoneUpdateResponse {
    pub fn new(opts: &DnsZoneUpdateOptions) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let zone_fqdn = normalize_zone_name(&opts.zone);

        let query = json!({
            "zone": opts.zone,
            "servers": opts.servers,
            "port": opts.port,
            "use_tcp": opts.use_tcp,
            "timeout_ms": opts.timeout_ms,
            "retries": opts.retries,
            "tsig_key_name": opts.tsig_key_name,
            "tsig_algorithm": opts.tsig_algorithm,
            "max_changes": opts.max_changes,
            "dry_run": opts.dry_run,
        });

        let summary = ZoneUpdateSummary {
            zone: zone_fqdn,
            server_used: None,
            rcode: None,
            tsig_used: opts.tsig_key_name.is_some(),
            applied_adds: 0,
            applied_deletes: 0,
            round_trip_time_ms: None,
            dry_run: opts.dry_run,
        };

        let details = ZoneUpdateDetails {
            prerequisites: opts.prerequisites.clone(),
            adds: opts.adds.clone(),
            deletes: opts.deletes.clone(),
        };

        Self {
            ok: true,
            timestamp_unix_ms: timestamp,
            query,
            summary,
            details,
            raw: None,
            error: None,
            warnings: vec![],
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();
        output.push_str("DNS Zone Update\n");
        output.push_str("===============\n\n");

        output.push_str(&format!("Zone        : {}\n", self.summary.zone));

        if let Some(ref server) = self.summary.server_used {
            output.push_str(&format!("Server Used : {}\n", server));
        }

        if let Some(ref rcode) = self.summary.rcode {
            output.push_str(&format!("RCODE       : {}\n", rcode));
        }

        output.push_str(&format!(
            "TSIG Used   : {}\n",
            if self.summary.tsig_used { "yes" } else { "no" }
        ));
        output.push_str(&format!("Adds        : {}\n", self.summary.applied_adds));
        output.push_str(&format!("Deletes     : {}\n", self.summary.applied_deletes));

        if let Some(rtt) = self.summary.round_trip_time_ms {
            output.push_str(&format!("RTT         : {} ms\n", rtt));
        }

        if self.summary.dry_run {
            output.push_str("\n** DRY RUN - No changes were applied **\n");
        }

        output.push_str("\n");

        if !self.details.prerequisites.is_empty() {
            output.push_str("Prerequisites:\n");
            for prereq in &self.details.prerequisites {
                output.push_str(&format!("  - {}", prereq.kind));
                if let Some(ref name) = prereq.name {
                    output.push_str(&format!(": {}", name));
                    if let Some(ref rtype) = prereq.rtype {
                        output.push_str(&format!(" {}", rtype));
                    }
                }
                if let Some(serial) = prereq.serial {
                    output.push_str(&format!(": serial >= {}", serial));
                }
                output.push_str("\n");
            }
            output.push_str("\n");
        }

        if !self.details.adds.is_empty() {
            output.push_str("Adds:\n");
            for add in &self.details.adds {
                output.push_str(&format!("  - {} {} IN {}", add.name, add.ttl, add.rtype));

                // Format data based on type
                let data_str = match add.rtype.as_str() {
                    "A" | "AAAA" => {
                        if let Some(addr) = add.data.json.get("address") {
                            format!(" {}", addr.as_str().unwrap_or(""))
                        } else {
                            String::new()
                        }
                    }
                    "MX" => {
                        let pref = add
                            .data
                            .json
                            .get("preference")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let exchange = add
                            .data
                            .json
                            .get("exchange")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        format!(" {} {}", pref, exchange)
                    }
                    "TXT" => {
                        if let Some(text_arr) = add.data.json.get("text") {
                            if let Some(texts) = text_arr.as_array() {
                                let text_strs: Vec<String> = texts
                                    .iter()
                                    .filter_map(|v| v.as_str())
                                    .map(|s| format!("\"{}\"", s))
                                    .collect();
                                format!(" {}", text_strs.join(" "))
                            } else {
                                String::new()
                            }
                        } else {
                            String::new()
                        }
                    }
                    "CNAME" => {
                        if let Some(cname) = add.data.json.get("cname") {
                            format!(" {}", cname.as_str().unwrap_or(""))
                        } else {
                            String::new()
                        }
                    }
                    _ => format!(" {}", add.data.json),
                };

                output.push_str(&data_str);
                output.push_str("\n");
            }
            output.push_str("\n");
        } else {
            output.push_str("Adds:\n  (none)\n\n");
        }

        if !self.details.deletes.is_empty() {
            output.push_str("Deletes:\n");
            for delete in &self.details.deletes {
                if delete.delete_all.unwrap_or(false) {
                    if let Some(ref rtype) = delete.rtype {
                        output.push_str(&format!("  - {} (all {} records)\n", delete.name, rtype));
                    } else {
                        output.push_str(&format!("  - {} (all records)\n", delete.name));
                    }
                } else {
                    let rtype = delete.rtype.as_ref().map(|s| s.as_str()).unwrap_or("?");
                    output.push_str(&format!("  - {} {}", delete.name, rtype));

                    if let Some(ref data) = delete.data {
                        // Format data similar to adds
                        let data_str = match rtype {
                            "A" | "AAAA" => {
                                if let Some(addr) = data.json.get("address") {
                                    format!(" {}", addr.as_str().unwrap_or(""))
                                } else {
                                    String::new()
                                }
                            }
                            _ => String::new(),
                        };
                        output.push_str(&data_str);
                    }

                    output.push_str("\n");
                }
            }
            output.push_str("\n");
        } else {
            output.push_str("Deletes:\n  (none)\n\n");
        }

        if let Some((ref code, ref message)) = self.error {
            output.push_str("Error:\n");
            output.push_str(&format!("  [{}] {}\n\n", code, message));
        }

        if !self.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &self.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        } else {
            output.push_str("Warnings:\n  (none)\n");
        }

        output
    }
}

// RFC 2136 DNS UPDATE: validate, build (and TSIG-sign) the message, then send
// it to the first server that answers.
pub async fn perform_zone_update(opts: DnsZoneUpdateOptions) -> Result<DnsZoneUpdateResponse> {
    let mut response = DnsZoneUpdateResponse::new(&opts);

    if let Err(e) = validate_zone_update_options(&opts) {
        response.ok = false;
        response.error = Some(e);
        return Ok(response);
    }

    // The message is built and signed for dry runs too, so that bad record
    // data or a bad key is reported without contacting any server.
    let tsig_key = match TsigKey::from_options(&opts) {
        Ok(key) => key,
        Err(e) => {
            response.ok = false;
            response.error = Some(e);
            return Ok(response);
        }
    };

    let prepared = match build_update_message(&opts)
        .and_then(|mut message| finalize_request(&mut message, tsig_key.as_ref()))
    {
        Ok(prepared) => prepared,
        Err(e) => {
            response.ok = false;
            response.error = Some(e);
            return Ok(response);
        }
    };

    if opts.include_raw {
        response.raw = Some(json!({ "request_hex": hex::encode(&prepared.wire) }));
    }

    if opts.dry_run {
        response.ok = true;
        response.summary.dry_run = true;
        response.summary.applied_adds = opts.adds.len() as u32;
        response.summary.applied_deletes = opts.deletes.len() as u32;
        return Ok(response);
    }

    // Determine target servers
    let servers = match resolve_target_servers(&opts).await {
        Ok(servers) => servers,
        Err(e) => {
            response.ok = false;
            response.error = Some((
                DNS_ZONE_UPDATE_ALL_SERVERS_FAILED.to_string(),
                e.to_string(),
            ));
            return Ok(response);
        }
    };

    // Try each server in order. Only transport failures (timeouts, network
    // errors, unparsable replies) move on to the next server; any DNS answer
    // ends the operation.
    let mut failures: Vec<ExchangeError> = Vec::new();
    for server in &servers {
        let start_time = Instant::now();

        match attempt_zone_update(&opts, server, &prepared, tsig_key.as_ref()).await {
            Ok(outcome) => {
                let rtt = start_time.elapsed().as_millis() as u64;
                response.summary.server_used = Some(server.to_string());
                response.summary.round_trip_time_ms = Some(rtt);
                response.warnings.extend(outcome.warnings);
                if let Some(rcode) = outcome.rcode {
                    response.summary.rcode = Some(rcode_mnemonic(rcode));
                }
                if opts.include_raw {
                    let mut raw = json!({ "request_hex": hex::encode(&prepared.wire) });
                    if let Some(ref wire) = outcome.response_wire {
                        raw["response_hex"] = json!(hex::encode(wire));
                    }
                    response.raw = Some(raw);
                }

                match outcome.error {
                    None => {
                        response.ok = true;
                        response.summary.applied_adds = opts.adds.len() as u32;
                        response.summary.applied_deletes = opts.deletes.len() as u32;
                    }
                    Some(err) => {
                        response.ok = false;
                        response.error = Some(err);
                    }
                }
                return Ok(response);
            }
            Err(e) => {
                response
                    .warnings
                    .push(format!("server {}: {}", server, e.message));
                failures.push(e);
            }
        }
    }

    // All servers failed at the transport level
    response.ok = false;
    response.error = Some(match failures.len() {
        0 => (
            DNS_ZONE_UPDATE_ALL_SERVERS_FAILED.to_string(),
            "No target servers".to_string(),
        ),
        1 => {
            let e = failures.remove(0);
            (e.code.to_string(), e.message)
        }
        n => (
            DNS_ZONE_UPDATE_ALL_SERVERS_FAILED.to_string(),
            format!("All {} target servers failed (see warnings)", n),
        ),
    });

    Ok(response)
}

// Validate zone update options
fn validate_zone_update_options(
    opts: &DnsZoneUpdateOptions,
) -> std::result::Result<(), (String, String)> {
    // Validate zone
    if opts.zone.is_empty() {
        return Err((
            DNS_ZONE_UPDATE_INVALID_ZONE.to_string(),
            "Zone name cannot be empty".to_string(),
        ));
    }

    // Validate max changes
    let total_changes = opts.adds.len() + opts.deletes.len();
    if total_changes > opts.max_changes as usize {
        return Err((
            DNS_ZONE_UPDATE_INVALID_MAX_CHANGES.to_string(),
            format!(
                "Total changes ({}) exceeds max_changes ({})",
                total_changes, opts.max_changes
            ),
        ));
    }

    // Validate TSIG configuration
    if opts.tsig_key_name.is_some() || opts.tsig_secret.is_some() {
        if opts.tsig_key_name.is_none() || opts.tsig_secret.is_none() {
            return Err((
                DNS_ZONE_UPDATE_INVALID_TSIG_CONFIG.to_string(),
                "TSIG requires both key_name and secret".to_string(),
            ));
        }

        // Validate base64 secret
        if let Some(ref secret) = opts.tsig_secret {
            if general_purpose::STANDARD.decode(secret).is_err() {
                return Err((
                    DNS_ZONE_UPDATE_INVALID_TSIG_SECRET.to_string(),
                    "TSIG secret must be valid base64".to_string(),
                ));
            }
        }

        // Validate algorithm
        if let Some(ref alg) = opts.tsig_algorithm {
            match alg.as_str() {
                "hmac-sha1" | "hmac-sha256" | "hmac-sha384" | "hmac-sha512" => {}
                _ => {
                    return Err((
                        DNS_ZONE_UPDATE_UNSUPPORTED_TSIG_ALGORITHM.to_string(),
                        format!("Unsupported TSIG algorithm: {}", alg),
                    ));
                }
            }
        }
    }

    // Validate record types in adds (ANY cannot be added)
    for add in &opts.adds {
        if DnsRecordType::from_str(&add.rtype).is_err() || add.rtype.eq_ignore_ascii_case("ANY") {
            return Err((
                DNS_ZONE_UPDATE_INVALID_RECORD_TYPE.to_string(),
                format!("Invalid record type: {}", add.rtype),
            ));
        }
    }

    // Validate delete specifications
    for delete in &opts.deletes {
        if delete.delete_all == Some(true) {
            // Valid delete_all operation
            continue;
        }

        if delete.data.is_none() {
            return Err((
                DNS_ZONE_UPDATE_INVALID_DELETE_SPEC.to_string(),
                "Delete operation must specify either delete_all=true or include data for specific record".to_string()
            ));
        }

        match delete.rtype {
            Some(ref rtype) if rtype.eq_ignore_ascii_case("ANY") => {
                return Err((
                    DNS_ZONE_UPDATE_INVALID_DELETE_SPEC.to_string(),
                    "Deleting a single record needs a concrete rtype, not ANY".to_string(),
                ));
            }
            Some(ref rtype) => {
                if DnsRecordType::from_str(rtype).is_err() {
                    return Err((
                        DNS_ZONE_UPDATE_INVALID_RECORD_TYPE.to_string(),
                        format!("Invalid record type in delete: {}", rtype),
                    ));
                }
            }
            None => {
                return Err((
                    DNS_ZONE_UPDATE_INVALID_DELETE_SPEC.to_string(),
                    "Delete without delete_all must specify rtype".to_string(),
                ));
            }
        }
    }

    // Validate prerequisites
    for prereq in &opts.prerequisites {
        let kind = match ZoneUpdatePrerequisiteKind::from_str(&prereq.kind) {
            Ok(k) => k,
            Err(_) => {
                return Err((
                    DNS_ZONE_UPDATE_INVALID_PREREQUISITE.to_string(),
                    format!("Invalid prerequisite kind: {}", prereq.kind),
                ));
            }
        };

        match kind {
            ZoneUpdatePrerequisiteKind::RecordExists
            | ZoneUpdatePrerequisiteKind::RecordNotExists => {
                if prereq.name.is_none() {
                    return Err((
                        DNS_ZONE_UPDATE_INVALID_PREREQUISITE.to_string(),
                        format!("Prerequisite {} requires name field", prereq.kind),
                    ));
                }
                if let Some(ref rtype) = prereq.rtype {
                    if DnsRecordType::from_str(rtype).is_err() {
                        return Err((
                            DNS_ZONE_UPDATE_INVALID_RECORD_TYPE.to_string(),
                            format!("Invalid record type in prerequisite: {}", rtype),
                        ));
                    }
                }
                if prereq.data.is_some() {
                    if kind == ZoneUpdatePrerequisiteKind::RecordNotExists {
                        return Err((
                            DNS_ZONE_UPDATE_INVALID_PREREQUISITE.to_string(),
                            "Prerequisite record_not_exists does not take data".to_string(),
                        ));
                    }
                    match prereq.rtype {
                        Some(ref rtype) if !rtype.eq_ignore_ascii_case("ANY") => {}
                        _ => {
                            return Err((
                                DNS_ZONE_UPDATE_INVALID_PREREQUISITE.to_string(),
                                "Prerequisite record_exists with data requires a concrete rtype"
                                    .to_string(),
                            ));
                        }
                    }
                }
            }
            ZoneUpdatePrerequisiteKind::NameInUse | ZoneUpdatePrerequisiteKind::NameNotInUse => {
                if prereq.name.is_none() {
                    return Err((
                        DNS_ZONE_UPDATE_INVALID_PREREQUISITE.to_string(),
                        format!("Prerequisite {} requires name field", prereq.kind),
                    ));
                }
            }
            ZoneUpdatePrerequisiteKind::ZoneSerialAtLeast => {
                if prereq.serial.is_none() {
                    return Err((
                        DNS_ZONE_UPDATE_INVALID_PREREQUISITE.to_string(),
                        "Prerequisite zone_serial_at_least requires serial field".to_string(),
                    ));
                }
            }
        }
    }

    Ok(())
}

// Resolve target servers for the zone
async fn resolve_target_servers(opts: &DnsZoneUpdateOptions) -> Result<Vec<String>> {
    if !opts.servers.is_empty() {
        return Ok(opts.servers.clone());
    }

    // Auto-discover authoritative nameservers for the zone
    let resolver = TokioAsyncResolver::tokio(system_resolver_config()?, ResolverOpts::default());

    let zone_name = normalize_zone_name(&opts.zone);
    let zone_name = Name::from_str(&zone_name)?;

    let ns_response = resolver.ns_lookup(zone_name).await?;
    let mut servers = Vec::new();

    for ns_record in ns_response.iter() {
        // ns_record is of type trust_dns_resolver::proto::rr::rdata::NS
        // Access the domain name directly
        let ns_name = ns_record.0.clone();

        // Resolve the NS name to IP addresses
        match resolver.lookup_ip(ns_name.clone()).await {
            Ok(ip_lookup) => {
                for ip in ip_lookup.iter() {
                    servers.push(ip.to_string());
                }
            }
            Err(_) => {
                // If we can't resolve the NS, add it as-is (might be an IP already)
                servers.push(ns_name.to_string());
            }
        }
    }

    if servers.is_empty() {
        bail!(
            "Could not resolve any authoritative nameservers for zone {}",
            opts.zone
        );
    }

    Ok(servers)
}

// A request message in wire format, ready to send.
#[derive(Debug, Clone)]
struct PreparedRequest {
    wire: Vec<u8>,
    id: u16,
    // MAC of the request when it is TSIG-signed (needed to verify the reply).
    mac: Option<Vec<u8>>,
}

// A transport-level failure: the next server (if any) is tried.
#[derive(Debug)]
struct ExchangeError {
    code: &'static str,
    message: String,
}

impl ExchangeError {
    fn timeout(message: impl Into<String>) -> Self {
        Self {
            code: DNS_ZONE_UPDATE_TIMEOUT,
            message: message.into(),
        }
    }

    fn network(message: impl Into<String>) -> Self {
        Self {
            code: DNS_ZONE_UPDATE_NETWORK_ERROR,
            message: message.into(),
        }
    }
}

// The result of one server answering (successfully or not).
#[derive(Debug, Default)]
struct AttemptOutcome {
    rcode: Option<ResponseCode>,
    response_wire: Option<Vec<u8>>,
    error: Option<(String, String)>,
    warnings: Vec<String>,
}

// Turn a server string into a socket address. Accepts "ip", "ip:port",
// "[v6]:port", or a host name (resolved with the system resolver).
async fn server_socket_addr(server: &str, port: u16) -> Result<SocketAddr, ExchangeError> {
    if let Ok(addr) = server.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = server
        .trim_matches(|c| c == '[' || c == ']')
        .parse::<IpAddr>()
    {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addrs = tokio::net::lookup_host((server, port))
        .await
        .map_err(|e| ExchangeError::network(format!("cannot resolve server {}: {}", server, e)))?;
    addrs
        .next()
        .ok_or_else(|| ExchangeError::network(format!("cannot resolve server {}", server)))
}

// Attempt zone update against a specific server
async fn attempt_zone_update(
    opts: &DnsZoneUpdateOptions,
    server: &str,
    prepared: &PreparedRequest,
    tsig_key: Option<&TsigKey>,
) -> Result<AttemptOutcome, ExchangeError> {
    let addr = server_socket_addr(server, opts.port).await?;
    let mut outcome = AttemptOutcome::default();

    // zone_serial_at_least is not an RFC 2136 prerequisite: read the zone's
    // SOA from the same server first and refuse to send the update if the
    // serial is lower than required.
    let required_serials: Vec<u32> = opts
        .prerequisites
        .iter()
        .filter(|p| {
            ZoneUpdatePrerequisiteKind::from_str(&p.kind).ok()
                == Some(ZoneUpdatePrerequisiteKind::ZoneSerialAtLeast)
        })
        .filter_map(|p| p.serial)
        .collect();
    if !required_serials.is_empty() {
        match query_zone_serial(opts, addr, tsig_key).await? {
            Ok(current) => {
                for required in required_serials {
                    if !serial_at_least(current, required) {
                        outcome.error = Some((
                            DNS_ZONE_UPDATE_PRECONDITION_FAILED.to_string(),
                            format!(
                                "Prerequisites failed: zone serial {} is lower than required {}",
                                current, required
                            ),
                        ));
                        return Ok(outcome);
                    }
                }
            }
            Err(err) => {
                outcome.error = Some(err);
                return Ok(outcome);
            }
        }
    }

    let wire = exchange(opts, addr, prepared).await?;
    let checked = match check_response(&wire, prepared, tsig_key, OpCode::Update) {
        Ok(checked) => checked,
        Err(ResponseCheckError::Tsig(msg)) => {
            outcome.rcode = parse_rcode(&wire);
            outcome.response_wire = Some(wire);
            outcome.error = Some((DNS_ZONE_UPDATE_TSIG_FAILED.to_string(), msg));
            return Ok(outcome);
        }
        Err(ResponseCheckError::Malformed(msg)) => return Err(ExchangeError::network(msg)),
    };

    let rcode = checked.message.response_code();
    outcome.rcode = Some(rcode);
    outcome.response_wire = Some(wire);
    outcome.warnings = checked.warnings;
    if rcode != ResponseCode::NoError {
        outcome.error = Some(map_rcode_to_error(rcode));
    }
    Ok(outcome)
}

// Query the zone's SOA serial from `addr`. The outer error is a transport
// failure; the inner error is an answer that does not give a usable serial.
async fn query_zone_serial(
    opts: &DnsZoneUpdateOptions,
    addr: SocketAddr,
    tsig_key: Option<&TsigKey>,
) -> Result<std::result::Result<u32, (String, String)>, ExchangeError> {
    let zone_name = Name::from_str(&normalize_zone_name(&opts.zone))
        .map_err(|e| ExchangeError::network(format!("invalid zone name: {}", e)))?;

    let mut message = Message::new();
    message.set_message_type(MessageType::Query);
    message.set_op_code(OpCode::Query);
    message.set_recursion_desired(false);
    message.add_query(Query::query(zone_name.clone(), ProtoRecordType::SOA));
    let prepared =
        finalize_request(&mut message, tsig_key).map_err(|(_, msg)| ExchangeError::network(msg))?;

    let wire = exchange(opts, addr, &prepared).await?;
    let checked = match check_response(&wire, &prepared, tsig_key, OpCode::Query) {
        Ok(checked) => checked,
        Err(ResponseCheckError::Tsig(msg)) => {
            return Ok(Err((
                DNS_ZONE_UPDATE_TSIG_FAILED.to_string(),
                format!("SOA query: {}", msg),
            )));
        }
        Err(ResponseCheckError::Malformed(msg)) => return Err(ExchangeError::network(msg)),
    };

    let rcode = checked.message.response_code();
    if rcode != ResponseCode::NoError {
        return Ok(Err((
            DNS_ZONE_UPDATE_PRECONDITION_FAILED.to_string(),
            format!(
                "Prerequisites failed: SOA query for {} returned {}",
                zone_name,
                rcode_mnemonic(rcode)
            ),
        )));
    }
    let serial = checked.message.answers().iter().find_map(|record| {
        if record.name() != &zone_name {
            return None;
        }
        match record.data() {
            Some(ProtoRData::SOA(soa)) => Some(soa.serial()),
            _ => None,
        }
    });
    Ok(serial.ok_or_else(|| {
        (
            DNS_ZONE_UPDATE_PRECONDITION_FAILED.to_string(),
            format!(
                "Prerequisites failed: no SOA record for {} in the server's answer",
                zone_name
            ),
        )
    }))
}

// RFC 1982 serial number arithmetic: is `current` >= `required`?
// Serials exactly 2^31 apart are incomparable and treated as "not at least".
fn serial_at_least(current: u32, required: u32) -> bool {
    current == required || serial_lt(required, current)
}

fn serial_lt(a: u32, b: u32) -> bool {
    const HALF: u32 = 1 << 31;
    (a < b && b - a < HALF) || (a > b && a - b > HALF)
}

// Send a request and return the raw reply. UDP replies with the TC bit set
// are retried over TCP. Each of the `retries + 1` attempts gets `timeout_ms`.
async fn exchange(
    opts: &DnsZoneUpdateOptions,
    addr: SocketAddr,
    request: &PreparedRequest,
) -> Result<Vec<u8>, ExchangeError> {
    let timeout = Duration::from_millis(opts.timeout_ms);
    // Plain DNS over UDP is limited to 512 bytes without EDNS.
    let tcp_only = opts.use_tcp || request.wire.len() > 512;
    let mut last_error = None;

    for _ in 0..=opts.retries {
        let result = if tcp_only {
            tcp_exchange(addr, request, timeout).await
        } else {
            match udp_exchange(addr, request, timeout).await {
                Ok(reply) if reply.len() > 2 && reply[2] & 0x02 != 0 => {
                    tcp_exchange(addr, request, timeout).await
                }
                other => other,
            }
        };
        match result {
            Ok(reply) => return Ok(reply),
            Err(e) => last_error = Some(e),
        }
    }

    Err(last_error.unwrap_or_else(|| ExchangeError::network("no attempt was made")))
}

fn reply_matches(reply: &[u8], id: u16) -> bool {
    reply.len() >= 12 && u16::from_be_bytes([reply[0], reply[1]]) == id && reply[2] & 0x80 != 0
}

async fn udp_exchange(
    addr: SocketAddr,
    request: &PreparedRequest,
    timeout: Duration,
) -> Result<Vec<u8>, ExchangeError> {
    let bind_addr: SocketAddr = if addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let net_err = |e: std::io::Error| ExchangeError::network(format!("UDP {}: {}", addr, e));
    let socket = tokio::net::UdpSocket::bind(bind_addr)
        .await
        .map_err(net_err)?;
    socket.connect(addr).await.map_err(net_err)?;
    socket.send(&request.wire).await.map_err(net_err)?;

    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = vec![0u8; 65535];
    loop {
        let len = match tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await {
            Err(_) => {
                return Err(ExchangeError::timeout(format!(
                    "no UDP reply from {} within {} ms",
                    addr,
                    timeout.as_millis()
                )));
            }
            Ok(Err(e)) => return Err(net_err(e)),
            Ok(Ok(len)) => len,
        };
        // Ignore stray datagrams whose ID does not match the request.
        if reply_matches(&buf[..len], request.id) {
            return Ok(buf[..len].to_vec());
        }
    }
}

async fn tcp_exchange(
    addr: SocketAddr,
    request: &PreparedRequest,
    timeout: Duration,
) -> Result<Vec<u8>, ExchangeError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let exchange = async {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        let mut framed = Vec::with_capacity(request.wire.len() + 2);
        framed.extend_from_slice(&(request.wire.len() as u16).to_be_bytes());
        framed.extend_from_slice(&request.wire);
        stream.write_all(&framed).await?;
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let mut reply = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        stream.read_exact(&mut reply).await?;
        Ok::<_, std::io::Error>(reply)
    };

    let reply = match tokio::time::timeout(timeout, exchange).await {
        Err(_) => {
            return Err(ExchangeError::timeout(format!(
                "no TCP reply from {} within {} ms",
                addr,
                timeout.as_millis()
            )));
        }
        Ok(Err(e)) => return Err(ExchangeError::network(format!("TCP {}: {}", addr, e))),
        Ok(Ok(reply)) => reply,
    };
    if !reply_matches(&reply, request.id) {
        return Err(ExchangeError::network(format!(
            "TCP {}: reply does not match request ID {}",
            addr, request.id
        )));
    }
    Ok(reply)
}

enum ResponseCheckError {
    // The reply could not be parsed or does not answer the request.
    Malformed(String),
    // The reply failed TSIG verification (or the server rejected our TSIG).
    Tsig(String),
}

struct CheckedResponse {
    message: Message,
    warnings: Vec<String>,
}

fn parse_rcode(wire: &[u8]) -> Option<ResponseCode> {
    if wire.len() < 4 {
        return None;
    }
    Some(ResponseCode::from_low(wire[3] & 0x0F))
}

// Parse a reply, check that it answers `request`, and verify its TSIG.
fn check_response(
    wire: &[u8],
    request: &PreparedRequest,
    tsig_key: Option<&TsigKey>,
    op_code: OpCode,
) -> std::result::Result<CheckedResponse, ResponseCheckError> {
    let (stripped, tsig) = split_trailing_tsig(wire).map_err(ResponseCheckError::Malformed)?;
    let message = Message::from_vec(&stripped)
        .map_err(|e| ResponseCheckError::Malformed(format!("unparsable reply: {}", e)))?;
    if message.id() != request.id || message.message_type() != MessageType::Response {
        return Err(ResponseCheckError::Malformed(
            "reply does not match the request".to_string(),
        ));
    }
    if message.op_code() != op_code {
        return Err(ResponseCheckError::Malformed(format!(
            "reply has opcode {:?}, expected {:?}",
            message.op_code(),
            op_code
        )));
    }

    let mut warnings = Vec::new();
    match (tsig_key, tsig) {
        (Some(key), Some(tsig)) => {
            let request_mac = request.mac.as_deref().unwrap_or(&[]);
            verify_response_tsig(&stripped, &tsig, key, request_mac, unix_now())
                .map_err(ResponseCheckError::Tsig)?;
        }
        (Some(_), None) => {
            // An unsigned success cannot be trusted. An unsigned error is
            // still reported with its RCODE.
            if message.response_code() == ResponseCode::NoError {
                return Err(ResponseCheckError::Tsig(
                    "the server's reply is not TSIG-signed".to_string(),
                ));
            }
            warnings.push("the server's reply is not TSIG-signed".to_string());
        }
        (None, Some(_)) => {
            warnings.push(
                "the server's reply carries a TSIG record that was not verified (no key given)"
                    .to_string(),
            );
        }
        (None, None) => {}
    }

    Ok(CheckedResponse { message, warnings })
}

fn rcode_mnemonic(rcode: ResponseCode) -> String {
    match rcode {
        ResponseCode::NoError => "NOERROR".to_string(),
        ResponseCode::FormErr => "FORMERR".to_string(),
        ResponseCode::ServFail => "SERVFAIL".to_string(),
        ResponseCode::NXDomain => "NXDOMAIN".to_string(),
        ResponseCode::NotImp => "NOTIMP".to_string(),
        ResponseCode::Refused => "REFUSED".to_string(),
        ResponseCode::YXDomain => "YXDOMAIN".to_string(),
        ResponseCode::YXRRSet => "YXRRSET".to_string(),
        ResponseCode::NXRRSet => "NXRRSET".to_string(),
        ResponseCode::NotAuth => "NOTAUTH".to_string(),
        ResponseCode::NotZone => "NOTZONE".to_string(),
        other => format!("RCODE{}", u16::from(other)),
    }
}

// Build DNS UPDATE message from options (RFC 2136 section 2): the zone
// section is the question section, prerequisites go in the answer section
// and updates in the authority section. TSIG is added later on the wire.
fn build_update_message(
    opts: &DnsZoneUpdateOptions,
) -> std::result::Result<Message, (String, String)> {
    let zone_name = Name::from_str(&normalize_zone_name(&opts.zone)).map_err(|e| {
        (
            DNS_ZONE_UPDATE_INVALID_ZONE.to_string(),
            format!("Invalid zone name {}: {}", opts.zone, e),
        )
    })?;

    let mut message = Message::new();
    message.set_message_type(MessageType::Query);
    message.set_op_code(OpCode::Update);
    message.set_recursion_desired(false);

    // Zone section: ZNAME, ZTYPE=SOA, ZCLASS=IN
    message.add_query(Query::query(zone_name, ProtoRecordType::SOA));

    for prereq in &opts.prerequisites {
        let record = build_prerequisite_record(prereq).map_err(|e| {
            (
                DNS_ZONE_UPDATE_INVALID_PREREQUISITE.to_string(),
                format!("Invalid prerequisite {}: {}", prereq.kind, e),
            )
        })?;
        if let Some(record) = record {
            message.add_answer(record);
        }
    }

    for delete in &opts.deletes {
        let record = build_delete_record(delete).map_err(|e| {
            (
                DNS_ZONE_UPDATE_INVALID_DELETE_SPEC.to_string(),
                format!("Invalid delete for {}: {}", delete.name, e),
            )
        })?;
        message.add_name_server(record);
    }

    for add in &opts.adds {
        let record = build_add_record(add).map_err(|e| {
            (
                DNS_ZONE_UPDATE_INVALID_ADD_RECORD.to_string(),
                format!("Invalid add for {}: {}", add.name, e),
            )
        })?;
        message.add_name_server(record);
    }

    Ok(message)
}

// Give the message a random ID, encode it and TSIG-sign it if a key is set.
fn finalize_request(
    message: &mut Message,
    tsig_key: Option<&TsigKey>,
) -> std::result::Result<PreparedRequest, (String, String)> {
    let id: u16 = rand::random();
    message.set_id(id);
    let mut wire = message.to_vec().map_err(|e| {
        (
            DNS_ZONE_UPDATE_INTERNAL_ERROR.to_string(),
            format!("Failed to encode DNS message: {}", e),
        )
    })?;
    let mac = tsig_key.map(|key| tsig_sign(&mut wire, key, unix_now()));
    Ok(PreparedRequest { wire, id, mac })
}

// A record with no RDATA (RDLENGTH 0), TTL 0 and the given class.
fn empty_record(name: Name, rtype: ProtoRecordType, class: DNSClass) -> ProtoRecord {
    let mut record = ProtoRecord::new();
    record.set_name(name);
    record.set_record_type(rtype);
    record.set_dns_class(class);
    record.set_ttl(0);
    record
}

fn required_name(field: &Option<String>) -> Result<Name> {
    let name = field
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("'name' is required"))?;
    Ok(Name::from_str(&normalize_dns_name(name))?)
}

// Build a prerequisite record (RFC 2136 section 2.4). zone_serial_at_least
// is checked with a separate SOA query and has no record (returns None).
fn build_prerequisite_record(prereq: &ZoneUpdatePrerequisite) -> Result<Option<ProtoRecord>> {
    let kind = ZoneUpdatePrerequisiteKind::from_str(&prereq.kind)?;

    let record = match kind {
        ZoneUpdatePrerequisiteKind::RecordExists => {
            let name = required_name(&prereq.name)?;
            match (&prereq.rtype, &prereq.data) {
                // RRset exists (value dependent): class IN, TTL 0, RDATA
                (Some(rtype), Some(data)) => {
                    let rdata = build_proto_rdata(rtype, &data.json)?;
                    ProtoRecord::from_rdata(name, 0, rdata)
                }
                (None, Some(_)) => bail!("'rtype' is required when 'data' is given"),
                // RRset exists (value independent): class ANY, TTL 0, no RDATA
                (Some(rtype), None) => {
                    empty_record(name, string_to_proto_record_type(rtype)?, DNSClass::ANY)
                }
                (None, None) => empty_record(name, ProtoRecordType::ANY, DNSClass::ANY),
            }
        }
        ZoneUpdatePrerequisiteKind::RecordNotExists => {
            // RRset does not exist: class NONE, TTL 0, no RDATA
            let name = required_name(&prereq.name)?;
            if prereq.data.is_some() {
                bail!("'data' is not allowed (RFC 2136 has no value-dependent form)");
            }
            let rtype = match prereq.rtype {
                Some(ref rt) => string_to_proto_record_type(rt)?,
                None => ProtoRecordType::ANY,
            };
            empty_record(name, rtype, DNSClass::NONE)
        }
        ZoneUpdatePrerequisiteKind::NameInUse => {
            // Name is in use: class ANY, type ANY
            empty_record(
                required_name(&prereq.name)?,
                ProtoRecordType::ANY,
                DNSClass::ANY,
            )
        }
        ZoneUpdatePrerequisiteKind::NameNotInUse => {
            // Name is not in use: class NONE, type ANY
            empty_record(
                required_name(&prereq.name)?,
                ProtoRecordType::ANY,
                DNSClass::NONE,
            )
        }
        ZoneUpdatePrerequisiteKind::ZoneSerialAtLeast => return Ok(None),
    };
    Ok(Some(record))
}

// Build an update-section delete record (RFC 2136 section 2.5.2-2.5.4)
fn build_delete_record(delete: &ZoneUpdateDelete) -> Result<ProtoRecord> {
    let name = Name::from_str(&normalize_dns_name(&delete.name))?;

    if delete.delete_all == Some(true) {
        // Delete an RRset (class ANY, type T) or all RRsets (class ANY, type ANY)
        let rtype = match delete.rtype {
            Some(ref rtype) => string_to_proto_record_type(rtype)?,
            None => ProtoRecordType::ANY,
        };
        return Ok(empty_record(name, rtype, DNSClass::ANY));
    }

    // Delete an RR from an RRset: class NONE, TTL 0, RDATA
    let rtype = delete
        .rtype
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("'rtype' is required"))?;
    let data = delete
        .data
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("'data' is required"))?;
    let rdata = build_proto_rdata(rtype, &data.json)?;
    let mut record = ProtoRecord::from_rdata(name, 0, rdata);
    record.set_dns_class(DNSClass::NONE);
    Ok(record)
}

// Build an update-section add record (RFC 2136 section 2.5.1): class IN
fn build_add_record(add: &ZoneUpdateAdd) -> Result<ProtoRecord> {
    let name = Name::from_str(&normalize_dns_name(&add.name))?;
    let rdata = build_proto_rdata(&add.rtype, &add.data.json)?;

    Ok(ProtoRecord::from_rdata(name, add.ttl, rdata))
}

fn data_str<'a>(data: &'a Value, field: &str, rtype: &str) -> Result<&'a str> {
    data.get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("{} record requires string field '{}'", rtype, field))
}

fn data_name(data: &Value, field: &str, rtype: &str) -> Result<Name> {
    let s = data_str(data, field, rtype)?;
    Name::from_str(&normalize_dns_name(s))
        .with_context(|| format!("{} record field '{}' is not a valid name", rtype, field))
}

fn data_uint<T: TryFrom<u64>>(data: &Value, field: &str, rtype: &str) -> Result<T> {
    let value = data
        .get(field)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("{} record requires integer field '{}'", rtype, field))?;
    T::try_from(value)
        .map_err(|_| anyhow::anyhow!("{} record field '{}' is out of range", rtype, field))
}

// Build protocol RData from JSON. The JSON fields are the ones `lookup`
// prints for each record type.
fn build_proto_rdata(rtype: &str, data: &Value) -> Result<ProtoRData> {
    let rtype_upper = rtype.to_uppercase();
    let rt = rtype_upper.as_str();
    match rt {
        "A" => {
            let addr: std::net::Ipv4Addr = data_str(data, "address", rt)?
                .parse()
                .context("A record 'address' is not an IPv4 address")?;
            Ok(ProtoRData::A(A(addr)))
        }
        "AAAA" => {
            let addr: std::net::Ipv6Addr = data_str(data, "address", rt)?
                .parse()
                .context("AAAA record 'address' is not an IPv6 address")?;
            Ok(ProtoRData::AAAA(AAAA(addr)))
        }
        "CNAME" => Ok(ProtoRData::CNAME(CNAME(data_name(data, "cname", rt)?))),
        "NS" => Ok(ProtoRData::NS(NS(data_name(data, "nsdname", rt)?))),
        "PTR" => Ok(ProtoRData::PTR(PTR(data_name(data, "ptrdname", rt)?))),
        "MX" => Ok(ProtoRData::MX(MX::new(
            data_uint(data, "preference", rt)?,
            data_name(data, "exchange", rt)?,
        ))),
        "SRV" => Ok(ProtoRData::SRV(SRV::new(
            data_uint(data, "priority", rt)?,
            data_uint(data, "weight", rt)?,
            data_uint(data, "port", rt)?,
            data_name(data, "target", rt)?,
        ))),
        "SOA" => Ok(ProtoRData::SOA(SOA::new(
            data_name(data, "mname", rt)?,
            data_name(data, "rname", rt)?,
            data_uint(data, "serial", rt)?,
            data_uint(data, "refresh", rt)?,
            data_uint(data, "retry", rt)?,
            data_uint(data, "expire", rt)?,
            data_uint(data, "minimum", rt)?,
        ))),
        "TXT" => {
            let text_array = data
                .get("text")
                .and_then(|v| v.as_array())
                .ok_or_else(|| anyhow::anyhow!("TXT record requires 'text' array field"))?;
            if text_array.is_empty() {
                bail!("TXT record 'text' array must not be empty");
            }
            let mut strings = Vec::with_capacity(text_array.len());
            for value in text_array {
                let s = value
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("TXT text array elements must be strings"))?;
                if s.len() > 255 {
                    bail!("TXT strings are limited to 255 bytes each");
                }
                strings.push(s.to_string());
            }
            Ok(ProtoRData::TXT(TXT::new(strings)))
        }
        "CAA" => {
            // RFC 8659: flags (1 octet), tag length, tag, value. Encoded as raw
            // RDATA so the value is sent exactly as given.
            let flags: u8 = match data.get("flags") {
                None => 0,
                Some(_) => data_uint(data, "flags", rt)?,
            };
            let tag = data_str(data, "tag", rt)?;
            if tag.is_empty() || tag.len() > 255 || !tag.bytes().all(|b| b.is_ascii_alphanumeric())
            {
                bail!("CAA record 'tag' must be 1-255 ASCII letters or digits");
            }
            let value = data_str(data, "value", rt)?;
            let mut raw = Vec::with_capacity(2 + tag.len() + value.len());
            raw.push(flags);
            raw.push(tag.len() as u8);
            raw.extend_from_slice(tag.as_bytes());
            raw.extend_from_slice(value.as_bytes());
            Ok(ProtoRData::Unknown {
                code: u16::from(ProtoRecordType::CAA),
                rdata: NULL::with(raw),
            })
        }
        "ANY" => bail!("ANY cannot carry record data"),
        _ => bail!("Unsupported record type for UPDATE: {}", rtype),
    }
}

// Convert string record type to protocol record type
fn string_to_proto_record_type(rtype: &str) -> Result<ProtoRecordType> {
    match rtype.to_uppercase().as_str() {
        "A" => Ok(ProtoRecordType::A),
        "AAAA" => Ok(ProtoRecordType::AAAA),
        "CNAME" => Ok(ProtoRecordType::CNAME),
        "MX" => Ok(ProtoRecordType::MX),
        "TXT" => Ok(ProtoRecordType::TXT),
        "NS" => Ok(ProtoRecordType::NS),
        "SRV" => Ok(ProtoRecordType::SRV),
        "PTR" => Ok(ProtoRecordType::PTR),
        "SOA" => Ok(ProtoRecordType::SOA),
        "CAA" => Ok(ProtoRecordType::CAA),
        "ANY" => Ok(ProtoRecordType::ANY),
        _ => bail!("Unsupported record type: {}", rtype),
    }
}

// Normalize DNS name to FQDN with trailing dot
fn normalize_dns_name(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{}.", name)
    }
}

// ==================== TSIG (RFC 8945) ====================

const TSIG_RR_TYPE: u16 = 250;
const DNS_CLASS_ANY: u16 = 255;
const TSIG_FUDGE: u16 = 300;

#[derive(Debug, Clone, Copy, PartialEq)]
enum TsigAlgorithm {
    HmacSha1,
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl TsigAlgorithm {
    fn from_option(name: &str) -> Option<Self> {
        match name {
            "hmac-sha1" => Some(Self::HmacSha1),
            "hmac-sha256" => Some(Self::HmacSha256),
            "hmac-sha384" => Some(Self::HmacSha384),
            "hmac-sha512" => Some(Self::HmacSha512),
            _ => None,
        }
    }

    // Algorithm name as it appears in the TSIG RDATA (RFC 8945 section 6)
    fn wire_name(self) -> &'static str {
        match self {
            Self::HmacSha1 => "hmac-sha1.",
            Self::HmacSha256 => "hmac-sha256.",
            Self::HmacSha384 => "hmac-sha384.",
            Self::HmacSha512 => "hmac-sha512.",
        }
    }

    fn mac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        fn run<M: Mac + hmac::digest::KeyInit>(key: &[u8], data: &[u8]) -> Vec<u8> {
            let mut mac = <M as hmac::digest::KeyInit>::new_from_slice(key)
                .expect("HMAC accepts keys of any length");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        match self {
            Self::HmacSha1 => run::<Hmac<sha1::Sha1>>(key, data),
            Self::HmacSha256 => run::<Hmac<sha2::Sha256>>(key, data),
            Self::HmacSha384 => run::<Hmac<sha2::Sha384>>(key, data),
            Self::HmacSha512 => run::<Hmac<sha2::Sha512>>(key, data),
        }
    }
}

#[derive(Debug, Clone)]
struct TsigKey {
    // Lowercased, fully qualified key name
    name: Name,
    algorithm: TsigAlgorithm,
    secret: Vec<u8>,
}

impl TsigKey {
    // The default algorithm is hmac-sha256.
    fn from_options(
        opts: &DnsZoneUpdateOptions,
    ) -> std::result::Result<Option<Self>, (String, String)> {
        let (key_name, secret) = match (&opts.tsig_key_name, &opts.tsig_secret) {
            (Some(name), Some(secret)) => (name, secret),
            _ => return Ok(None),
        };
        let secret = general_purpose::STANDARD.decode(secret).map_err(|_| {
            (
                DNS_ZONE_UPDATE_INVALID_TSIG_SECRET.to_string(),
                "TSIG secret must be valid base64".to_string(),
            )
        })?;
        let name = Name::from_str(&normalize_dns_name(key_name)).map_err(|e| {
            (
                DNS_ZONE_UPDATE_INVALID_TSIG_CONFIG.to_string(),
                format!("Invalid TSIG key name {}: {}", key_name, e),
            )
        })?;
        let algorithm_name = opts.tsig_algorithm.as_deref().unwrap_or("hmac-sha256");
        let algorithm = TsigAlgorithm::from_option(algorithm_name).ok_or_else(|| {
            (
                DNS_ZONE_UPDATE_UNSUPPORTED_TSIG_ALGORITHM.to_string(),
                format!("Unsupported TSIG algorithm: {}", algorithm_name),
            )
        })?;
        Ok(Some(TsigKey {
            name: name.to_lowercase(),
            algorithm,
            secret,
        }))
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// Uncompressed, lowercased wire form of a name (RFC 4034 canonical form)
fn canonical_name_wire(name: &Name, out: &mut Vec<u8>) {
    for label in name.to_lowercase().iter() {
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
}

// The "TSIG variables" part of the MAC input (RFC 8945 section 4.3.3)
fn tsig_variables(
    key: &TsigKey,
    time_signed: u64,
    fudge: u16,
    error: u16,
    other: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    canonical_name_wire(&key.name, &mut out);
    out.extend_from_slice(&DNS_CLASS_ANY.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes()); // TTL
    canonical_name_wire(
        &Name::from_ascii(key.algorithm.wire_name()).expect("static algorithm name"),
        &mut out,
    );
    out.extend_from_slice(&time_signed.to_be_bytes()[2..8]); // 48-bit
    out.extend_from_slice(&fudge.to_be_bytes());
    out.extend_from_slice(&error.to_be_bytes());
    out.extend_from_slice(&(other.len() as u16).to_be_bytes());
    out.extend_from_slice(other);
    out
}

// Sign a request in place: compute the MAC over the message and the TSIG
// variables, append the TSIG RR and increment ARCOUNT. Returns the MAC.
fn tsig_sign(wire: &mut Vec<u8>, key: &TsigKey, time_signed: u64) -> Vec<u8> {
    let mut mac_input = wire.clone();
    mac_input.extend_from_slice(&tsig_variables(key, time_signed, TSIG_FUDGE, 0, &[]));
    let mac = key.algorithm.mac(&key.secret, &mac_input);

    let mut rdata = Vec::new();
    canonical_name_wire(
        &Name::from_ascii(key.algorithm.wire_name()).expect("static algorithm name"),
        &mut rdata,
    );
    rdata.extend_from_slice(&time_signed.to_be_bytes()[2..8]);
    rdata.extend_from_slice(&TSIG_FUDGE.to_be_bytes());
    rdata.extend_from_slice(&(mac.len() as u16).to_be_bytes());
    rdata.extend_from_slice(&mac);
    rdata.extend_from_slice(&wire[0..2]); // original ID
    rdata.extend_from_slice(&0u16.to_be_bytes()); // error
    rdata.extend_from_slice(&0u16.to_be_bytes()); // other len

    canonical_name_wire(&key.name, wire);
    wire.extend_from_slice(&TSIG_RR_TYPE.to_be_bytes());
    wire.extend_from_slice(&DNS_CLASS_ANY.to_be_bytes());
    wire.extend_from_slice(&0u32.to_be_bytes());
    wire.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    wire.extend_from_slice(&rdata);

    let arcount = u16::from_be_bytes([wire[10], wire[11]]) + 1;
    wire[10..12].copy_from_slice(&arcount.to_be_bytes());
    mac
}

#[derive(Debug, Clone)]
struct TsigRecord {
    key_name: Name,
    algorithm: Name,
    time_signed: u64,
    fudge: u16,
    mac: Vec<u8>,
    original_id: u16,
    error: u16,
    other: Vec<u8>,
}

fn skip_wire_name(wire: &[u8], mut pos: usize) -> std::result::Result<usize, String> {
    loop {
        let len = *wire.get(pos).ok_or("truncated name in reply")? as usize;
        match len & 0xC0 {
            0xC0 => {
                if pos + 2 > wire.len() {
                    return Err("truncated name in reply".to_string());
                }
                return Ok(pos + 2);
            }
            0x00 if len == 0 => return Ok(pos + 1),
            0x00 => pos += 1 + len,
            _ => return Err("bad label in reply".to_string()),
        }
    }
}

// If the last additional record is a TSIG RR, remove it (decrementing
// ARCOUNT) and return it parsed.
fn split_trailing_tsig(wire: &[u8]) -> std::result::Result<(Vec<u8>, Option<TsigRecord>), String> {
    if wire.len() < 12 {
        return Err("reply shorter than a DNS header".to_string());
    }
    let count = |i: usize| u16::from_be_bytes([wire[i], wire[i + 1]]) as usize;
    let (qd, an, ns, ar) = (count(4), count(6), count(8), count(10));

    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_wire_name(wire, pos)? + 4;
    }
    let total = an + ns + ar;
    let mut last = None;
    for _ in 0..total {
        let start = pos;
        pos = skip_wire_name(wire, pos)?;
        if pos + 10 > wire.len() {
            return Err("truncated record in reply".to_string());
        }
        let rtype = u16::from_be_bytes([wire[pos], wire[pos + 1]]);
        let rdlen = u16::from_be_bytes([wire[pos + 8], wire[pos + 9]]) as usize;
        pos += 10 + rdlen;
        if pos > wire.len() {
            return Err("truncated record in reply".to_string());
        }
        last = Some((start, rtype));
    }

    match last {
        Some((start, TSIG_RR_TYPE)) if ar > 0 => {
            let tsig = parse_tsig_record(wire, start)
                .map_err(|e| format!("malformed TSIG record in reply: {}", e))?;
            let mut stripped = wire[..start].to_vec();
            stripped[10..12].copy_from_slice(&((ar - 1) as u16).to_be_bytes());
            Ok((stripped, Some(tsig)))
        }
        _ => Ok((wire.to_vec(), None)),
    }
}

fn parse_tsig_record(wire: &[u8], start: usize) -> ProtoResult<TsigRecord> {
    let mut decoder = BinDecoder::new(wire);
    decoder.read_slice(start)?;
    let key_name = Name::read(&mut decoder)?;
    decoder.read_slice(8)?; // type, class, TTL
    decoder.read_u16()?; // RDLENGTH (already bounds-checked)
    let algorithm = Name::read(&mut decoder)?;
    let time_hi = decoder.read_u16()?.unverified() as u64;
    let time_lo = decoder.read_u32()?.unverified() as u64;
    let fudge = decoder.read_u16()?.unverified();
    let mac_len = decoder.read_u16()?.unverified() as usize;
    let mac = decoder.read_vec(mac_len)?.unverified();
    let original_id = decoder.read_u16()?.unverified();
    let error = decoder.read_u16()?.unverified();
    let other_len = decoder.read_u16()?.unverified() as usize;
    let other = decoder.read_vec(other_len)?.unverified();
    Ok(TsigRecord {
        key_name,
        algorithm,
        time_signed: (time_hi << 32) | time_lo,
        fudge,
        mac,
        original_id,
        error,
        other,
    })
}

fn tsig_error_name(error: u16) -> String {
    match error {
        16 => "BADSIG".to_string(),
        17 => "BADKEY".to_string(),
        18 => "BADTIME".to_string(),
        22 => "BADTRUNC".to_string(),
        other => format!("TSIG error {}", other),
    }
}

// Verify the TSIG of a reply (RFC 8945 section 5.3): the MAC covers the
// request MAC, the reply without its TSIG (original ID restored) and the
// reply's TSIG variables.
fn verify_response_tsig(
    stripped: &[u8],
    tsig: &TsigRecord,
    key: &TsigKey,
    request_mac: &[u8],
    now: u64,
) -> std::result::Result<(), String> {
    if tsig.key_name != key.name {
        return Err(format!(
            "reply is signed with key {}, expected {}",
            tsig.key_name, key.name
        ));
    }
    if tsig.error != 0 {
        return Err(format!(
            "server rejected the request signature ({})",
            tsig_error_name(tsig.error)
        ));
    }
    let expected_alg = Name::from_ascii(key.algorithm.wire_name()).expect("static algorithm name");
    if tsig.algorithm != expected_alg {
        return Err(format!(
            "reply is signed with algorithm {}, expected {}",
            tsig.algorithm, expected_alg
        ));
    }

    let mut message = stripped.to_vec();
    message[0..2].copy_from_slice(&tsig.original_id.to_be_bytes());
    let mut mac_input = Vec::with_capacity(message.len() + request_mac.len() + 64);
    mac_input.extend_from_slice(&(request_mac.len() as u16).to_be_bytes());
    mac_input.extend_from_slice(request_mac);
    mac_input.extend_from_slice(&message);
    mac_input.extend_from_slice(&tsig_variables(
        key,
        tsig.time_signed,
        tsig.fudge,
        tsig.error,
        &tsig.other,
    ));
    let expected = key.algorithm.mac(&key.secret, &mac_input);

    // A truncated MAC must keep at least half the bits and 10 octets
    // (RFC 8945 section 5.2.2.1).
    let len = tsig.mac.len();
    if len == 0
        || len > expected.len()
        || (len < expected.len() && (len < 10 || len * 2 < expected.len()))
    {
        return Err(format!("reply TSIG MAC has invalid length {}", len));
    }
    let diff = expected[..len]
        .iter()
        .zip(&tsig.mac)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if diff != 0 {
        return Err("reply TSIG MAC does not verify".to_string());
    }
    if now.abs_diff(tsig.time_signed) > u64::from(tsig.fudge) {
        return Err(format!(
            "reply TSIG time {} is outside the {} s fudge window",
            tsig.time_signed, tsig.fudge
        ));
    }
    Ok(())
}

// Map ResponseCode to error
fn map_rcode_to_error(rcode: ResponseCode) -> (String, String) {
    match rcode {
        ResponseCode::Refused => (
            DNS_ZONE_UPDATE_REFUSED.to_string(),
            "Server refused the update".to_string(),
        ),
        ResponseCode::NXDomain => (
            DNS_ZONE_UPDATE_NXDOMAIN.to_string(),
            "Domain does not exist".to_string(),
        ),
        ResponseCode::ServFail => (
            DNS_ZONE_UPDATE_SERVFAIL.to_string(),
            "Server failure".to_string(),
        ),
        ResponseCode::FormErr => (
            DNS_ZONE_UPDATE_FORMERR.to_string(),
            "Format error in update message".to_string(),
        ),
        ResponseCode::NotAuth => (
            DNS_ZONE_UPDATE_NOTAUTH.to_string(),
            "Server not authoritative for zone".to_string(),
        ),
        ResponseCode::NotZone => (
            DNS_ZONE_UPDATE_NOTZONE.to_string(),
            "Name not in zone".to_string(),
        ),
        ResponseCode::YXRRSet => (
            DNS_ZONE_UPDATE_PRECONDITION_FAILED.to_string(),
            "Prerequisites failed: RRSet exists".to_string(),
        ),
        ResponseCode::NXRRSet => (
            DNS_ZONE_UPDATE_PRECONDITION_FAILED.to_string(),
            "Prerequisites failed: RRSet does not exist".to_string(),
        ),
        ResponseCode::YXDomain => (
            DNS_ZONE_UPDATE_PRECONDITION_FAILED.to_string(),
            "Prerequisites failed: Name exists".to_string(),
        ),
        _ => (
            DNS_ZONE_UPDATE_RCODE_ERROR.to_string(),
            format!("Update failed with RCODE: {:?}", rcode),
        ),
    }
}

impl DnsHandle {
    fn verb_zone_update(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments with detailed error mapping
        let opts = match DnsZoneUpdateOptions::from_args(args) {
            Ok(opts) => opts,
            Err(e) => {
                let error_msg = {
                    let err_str = e.to_string();
                    if err_str.contains("Missing required parameter: zone") {
                        format!("[{}] {}", DNS_ZONE_UPDATE_INVALID_ZONE, err_str)
                    } else if err_str.contains("Zone name cannot be empty") {
                        format!("[{}] {}", DNS_ZONE_UPDATE_INVALID_ZONE, err_str)
                    } else if err_str.contains("Server address cannot be empty") {
                        format!("[{}] {}", DNS_ZONE_UPDATE_INVALID_SERVER, err_str)
                    } else if err_str.contains("Port must be between") {
                        format!("[{}] {}", DNS_ZONE_UPDATE_INVALID_PORT, err_str)
                    } else if err_str.contains("timeout_ms must be") {
                        format!("[{}] {}", DNS_ZONE_UPDATE_INVALID_TIMEOUT, err_str)
                    } else if err_str.contains("retries must be") {
                        format!("[{}] {}", DNS_ZONE_UPDATE_INVALID_RETRIES, err_str)
                    } else if err_str.contains("max_changes") {
                        format!("[{}] {}", DNS_ZONE_UPDATE_INVALID_MAX_CHANGES, err_str)
                    } else if err_str.contains("Invalid record type") {
                        format!("[{}] {}", DNS_ZONE_UPDATE_INVALID_RECORD_TYPE, err_str)
                    } else if err_str.contains("Add record") || err_str.contains("Invalid adds") {
                        format!("[{}] {}", DNS_ZONE_UPDATE_INVALID_ADD_RECORD, err_str)
                    } else if err_str.contains("Delete") && !err_str.contains("prerequisite") {
                        format!("[{}] {}", DNS_ZONE_UPDATE_INVALID_DELETE_SPEC, err_str)
                    } else if err_str.contains("prerequisite") || err_str.contains("Prerequisite") {
                        format!("[{}] {}", DNS_ZONE_UPDATE_INVALID_PREREQUISITE, err_str)
                    } else if err_str.contains("TSIG requires both") {
                        format!("[{}] {}", DNS_ZONE_UPDATE_INVALID_TSIG_CONFIG, err_str)
                    } else if err_str.contains("TSIG secret must be valid base64") {
                        format!("[{}] {}", DNS_ZONE_UPDATE_INVALID_TSIG_SECRET, err_str)
                    } else {
                        format!("[{}] {}", DNS_ZONE_UPDATE_INTERNAL_ERROR, err_str)
                    }
                };
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        // Create async runtime and perform zone update
        let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;

        let result = rt.block_on(perform_zone_update(opts.clone()));

        let response = match result {
            Ok(resp) => resp,
            Err(e) => {
                let error_msg =
                    format!("[{}] Internal error: {}", DNS_ZONE_UPDATE_INTERNAL_ERROR, e);
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        // Format output
        let output = match opts.format {
            OutputFormat::Json => response.to_json(),
            OutputFormat::Text => response.to_text(),
        };

        writeln!(io.stdout, "{}", output)?;

        if response.ok {
            Ok(Status::ok())
        } else {
            Ok(Status::err(1, "Zone update failed"))
        }
    }
}

// Mock resolver for testing
#[cfg(test)]
pub struct MockDnsResolver {
    pub records: Vec<DnsRecord>,
    pub should_error: bool,
    pub error_code: String,
    pub error_message: String,
    pub rcode: String,
    pub authoritative: bool,
    pub truncated: bool,
    pub round_trip_time_ms: u64,
}

#[cfg(test)]
impl MockDnsResolver {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            should_error: false,
            error_code: DNS_LOOKUP_INTERNAL_ERROR.to_string(),
            error_message: "Mock error".to_string(),
            rcode: "NOERROR".to_string(),
            authoritative: false,
            truncated: false,
            round_trip_time_ms: 10,
        }
    }

    pub fn with_a_record(mut self, name: &str, ip: &str, ttl: u32) -> Self {
        self.records.push(DnsRecord {
            name: name.to_string(),
            rtype: "A".to_string(),
            class: "IN".to_string(),
            ttl,
            data: json!({ "address": ip }),
        });
        self
    }

    pub fn with_mx_record(mut self, name: &str, preference: u16, exchange: &str, ttl: u32) -> Self {
        self.records.push(DnsRecord {
            name: name.to_string(),
            rtype: "MX".to_string(),
            class: "IN".to_string(),
            ttl,
            data: json!({ "preference": preference, "exchange": exchange }),
        });
        self
    }

    pub fn with_txt_record(mut self, name: &str, text: &[&str], ttl: u32) -> Self {
        let text_values: Vec<String> = text.iter().map(|s| s.to_string()).collect();
        self.records.push(DnsRecord {
            name: name.to_string(),
            rtype: "TXT".to_string(),
            class: "IN".to_string(),
            ttl,
            data: json!({ "text": text_values }),
        });
        self
    }

    pub fn with_error(mut self, error_code: &str, error_message: &str) -> Self {
        self.should_error = true;
        self.error_code = error_code.to_string();
        self.error_message = error_message.to_string();
        self
    }

    pub fn with_nxdomain(mut self) -> Self {
        self.should_error = true;
        self.error_code = DNS_LOOKUP_NXDOMAIN.to_string();
        self.error_message = "The domain name does not exist (NXDOMAIN).".to_string();
        self.rcode = "NXDOMAIN".to_string();
        self
    }

    pub fn with_timeout(mut self) -> Self {
        self.should_error = true;
        self.error_code = DNS_LOOKUP_TIMEOUT.to_string();
        self.error_message = "DNS query timed out.".to_string();
        self
    }

    pub fn build_response(&self, opts: &DnsLookupOptions) -> DnsLookupResponse {
        let mut response = DnsLookupResponse::new(opts);

        if self.should_error {
            response.ok = false;
            response.error = Some((self.error_code.clone(), self.error_message.clone()));
            response.response.rcode = self.rcode.clone();
        } else {
            response.ok = true;
            response.answers = self.records.clone();
            response.response.rcode = self.rcode.clone();
            response.response.authoritative = self.authoritative;
            response.response.truncated = self.truncated;
            response.response.round_trip_time_ms = Some(self.round_trip_time_ms);
        }

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn args(kv: &[(&str, &str)]) -> Args {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn help_detection_is_exact() {
        let h = DnsHandle::from_url(&Url::parse("dns://--help").unwrap()).unwrap();
        assert!(h.should_show_help("help", &args(&[])));
        assert!(h.should_show_help("--help", &args(&[])));
        assert!(h.should_show_help("-h", &args(&[])));
        assert!(h.should_show_help("--help=lookup", &args(&[])));
        assert!(h.should_show_help("lookup", &args(&[("help", "")])));
        assert!(!h.should_show_help("lookup", &args(&[("name", "my-hosts.example")])));
        assert!(!h.should_show_help("x-h", &args(&[])));
    }

    #[test]
    fn display_help_renders_approved_help() {
        let h = DnsHandle::from_url(&Url::parse("dns://--help").unwrap()).unwrap();
        let render = |verb: Option<&str>| {
            let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
            let mut io = IoStreams::new(&mut i, &mut o, &mut e);
            h.display_help(&mut io, verb).unwrap();
            String::from_utf8(o).unwrap()
        };
        let all = render(None);
        assert!(all.starts_with("Handle: dns\n"), "{all}");
        let lookup = render(Some("lookup"));
        assert_ne!(all, lookup);
        assert_eq!(render(Some("nosuchverb")), all);
    }

    // Helper function to create a DnsTraceHop with answers
    fn create_hop_with_answers(hop_index: u32, answers: Vec<DnsTraceRecord>) -> DnsTraceHop {
        DnsTraceHop {
            hop_index,
            zone: "test.com.".to_string(),
            query_name: "www.test.com.".to_string(),
            query_rtype: "A".to_string(),
            server_ip: "1.2.3.4".to_string(),
            server_name: Some("ns1.test.com.".to_string()),
            rtt_ms: Some(10),
            rcode: "NOERROR".to_string(),
            authoritative: false,
            truncated: false,
            dnssec: DnsTraceDnssec {
                requested: false,
                do_bit: false,
                ad_bit: false,
                validated: Some(false),
            },
            ns_names: Vec::new(),
            ns_addresses: Vec::new(),
            answers,
            authority: Vec::new(),
            additional: Vec::new(),
            raw: None,
        }
    }

    #[test]
    fn test_extract_cname_chain_empty_hops() {
        let hops: Vec<DnsTraceHop> = Vec::new();
        let result = extract_cname_chain(&hops, "www.example.com.");
        assert_eq!(
            result.len(),
            0,
            "Empty hops should return empty CNAME chain"
        );
    }

    #[test]
    fn test_extract_cname_chain_no_cnames() {
        let answers = vec![DnsTraceRecord {
            name: "www.example.com.".to_string(),
            rtype: "A".to_string(),
            ttl: 300,
            data: json!({"address": "93.184.216.34"}),
        }];
        let hops = vec![create_hop_with_answers(1, answers)];

        let result = extract_cname_chain(&hops, "www.example.com.");
        assert_eq!(
            result.len(),
            0,
            "No CNAME records should return empty chain"
        );
    }

    #[test]
    fn test_extract_cname_chain_single_cname() {
        let answers = vec![
            DnsTraceRecord {
                name: "www.example.com.".to_string(),
                rtype: "CNAME".to_string(),
                ttl: 300,
                data: json!({"cname": "cdn.example.com."}),
            },
            DnsTraceRecord {
                name: "cdn.example.com.".to_string(),
                rtype: "A".to_string(),
                ttl: 300,
                data: json!({"address": "93.184.216.34"}),
            },
        ];
        let hops = vec![create_hop_with_answers(1, answers)];

        let result = extract_cname_chain(&hops, "www.example.com.");
        assert_eq!(result.len(), 1, "Should find one CNAME");
        assert_eq!(result[0], "cdn.example.com.", "CNAME should match target");
    }

    #[test]
    fn test_extract_cname_chain_multiple_cnames() {
        let answers = vec![
            DnsTraceRecord {
                name: "www.example.com.".to_string(),
                rtype: "CNAME".to_string(),
                ttl: 300,
                data: json!({"cname": "cdn.example.com."}),
            },
            DnsTraceRecord {
                name: "cdn.example.com.".to_string(),
                rtype: "CNAME".to_string(),
                ttl: 300,
                data: json!({"cname": "edge.example.net."}),
            },
            DnsTraceRecord {
                name: "edge.example.net.".to_string(),
                rtype: "CNAME".to_string(),
                ttl: 300,
                data: json!({"cname": "server.example.org."}),
            },
            DnsTraceRecord {
                name: "server.example.org.".to_string(),
                rtype: "A".to_string(),
                ttl: 300,
                data: json!({"address": "93.184.216.34"}),
            },
        ];
        let hops = vec![create_hop_with_answers(1, answers)];

        let result = extract_cname_chain(&hops, "www.example.com.");
        assert_eq!(result.len(), 3, "Should find three CNAMEs in chain");
        assert_eq!(
            result[0], "cdn.example.com.",
            "First CNAME should be cdn.example.com."
        );
        assert_eq!(
            result[1], "edge.example.net.",
            "Second CNAME should be edge.example.net."
        );
        assert_eq!(
            result[2], "server.example.org.",
            "Third CNAME should be server.example.org."
        );
    }

    #[test]
    fn test_extract_cname_chain_across_multiple_hops() {
        let hop1_answers = vec![DnsTraceRecord {
            name: "www.example.com.".to_string(),
            rtype: "CNAME".to_string(),
            ttl: 300,
            data: json!({"cname": "cdn.example.com."}),
        }];

        let hop2_answers = vec![
            DnsTraceRecord {
                name: "cdn.example.com.".to_string(),
                rtype: "CNAME".to_string(),
                ttl: 300,
                data: json!({"cname": "edge.example.net."}),
            },
            DnsTraceRecord {
                name: "edge.example.net.".to_string(),
                rtype: "A".to_string(),
                ttl: 300,
                data: json!({"address": "93.184.216.34"}),
            },
        ];

        let hops = vec![
            create_hop_with_answers(1, hop1_answers),
            create_hop_with_answers(2, hop2_answers),
        ];

        let result = extract_cname_chain(&hops, "www.example.com.");
        assert_eq!(result.len(), 2, "Should find two CNAMEs across hops");
        assert_eq!(
            result[0], "cdn.example.com.",
            "First CNAME should be cdn.example.com."
        );
        assert_eq!(
            result[1], "edge.example.net.",
            "Second CNAME should be edge.example.net."
        );
    }

    #[test]
    fn test_extract_cname_chain_case_insensitive() {
        let answers = vec![
            DnsTraceRecord {
                name: "WWW.EXAMPLE.COM.".to_string(),
                rtype: "CNAME".to_string(),
                ttl: 300,
                data: json!({"cname": "cdn.example.com."}),
            },
            DnsTraceRecord {
                name: "cdn.example.com.".to_string(),
                rtype: "A".to_string(),
                ttl: 300,
                data: json!({"address": "93.184.216.34"}),
            },
        ];
        let hops = vec![create_hop_with_answers(1, answers)];

        let result = extract_cname_chain(&hops, "www.example.com.");
        assert_eq!(
            result.len(),
            1,
            "Should find CNAME with case-insensitive matching"
        );
        assert_eq!(result[0], "cdn.example.com.", "CNAME should match target");
    }

    #[test]
    fn test_extract_cname_chain_unrelated_cnames() {
        let answers = vec![
            DnsTraceRecord {
                name: "www.example.com.".to_string(),
                rtype: "CNAME".to_string(),
                ttl: 300,
                data: json!({"cname": "cdn.example.com."}),
            },
            DnsTraceRecord {
                name: "other.example.com.".to_string(),
                rtype: "CNAME".to_string(),
                ttl: 300,
                data: json!({"cname": "unrelated.example.com."}),
            },
            DnsTraceRecord {
                name: "cdn.example.com.".to_string(),
                rtype: "A".to_string(),
                ttl: 300,
                data: json!({"address": "93.184.216.34"}),
            },
        ];
        let hops = vec![create_hop_with_answers(1, answers)];

        let result = extract_cname_chain(&hops, "www.example.com.");
        assert_eq!(result.len(), 1, "Should only follow relevant CNAME chain");
        assert_eq!(
            result[0], "cdn.example.com.",
            "Should only include CNAMEs in the chain"
        );
    }

    #[test]
    fn test_extract_cname_chain_with_mixed_record_types() {
        let answers = vec![
            DnsTraceRecord {
                name: "www.example.com.".to_string(),
                rtype: "CNAME".to_string(),
                ttl: 300,
                data: json!({"cname": "cdn.example.com."}),
            },
            DnsTraceRecord {
                name: "example.com.".to_string(),
                rtype: "MX".to_string(),
                ttl: 300,
                data: json!({"preference": 10, "exchange": "mail.example.com."}),
            },
            DnsTraceRecord {
                name: "cdn.example.com.".to_string(),
                rtype: "TXT".to_string(),
                ttl: 300,
                data: json!({"text": ["v=spf1 include:example.com ~all"]}),
            },
            DnsTraceRecord {
                name: "cdn.example.com.".to_string(),
                rtype: "A".to_string(),
                ttl: 300,
                data: json!({"address": "93.184.216.34"}),
            },
        ];
        let hops = vec![create_hop_with_answers(1, answers)];

        let result = extract_cname_chain(&hops, "www.example.com.");
        assert_eq!(
            result.len(),
            1,
            "Should find CNAME ignoring other record types"
        );
        assert_eq!(result[0], "cdn.example.com.", "CNAME should match target");
    }

    // Zone Transfer Tests
    #[test]
    fn test_normalize_zone_name_with_dot() {
        let result = normalize_zone_name("example.com.");
        assert_eq!(
            result, "example.com.",
            "Zone name with trailing dot should remain unchanged"
        );
    }

    #[test]
    fn test_normalize_zone_name_without_dot() {
        let result = normalize_zone_name("example.com");
        assert_eq!(
            result, "example.com.",
            "Zone name without trailing dot should have one added"
        );
    }

    #[test]
    fn test_extract_soa_from_record_valid() {
        let record = ZoneRecord {
            name: "example.com.".to_string(),
            rtype: "SOA".to_string(),
            class: "IN".to_string(),
            ttl: 3600,
            data: json!({
                "mname": "ns1.example.com.",
                "rname": "admin.example.com.",
                "serial": 2024010101,
                "refresh": 7200,
                "retry": 3600,
                "expire": 1209600,
                "minimum": 3600
            }),
        };

        let result = extract_soa_from_record(&record);
        assert!(result.is_ok(), "Should successfully extract SOA data");

        let soa = result.unwrap();
        assert_eq!(soa.mname, "ns1.example.com.", "mname should match");
        assert_eq!(soa.rname, "admin.example.com.", "rname should match");
        assert_eq!(soa.serial, 2024010101, "serial should match");
        assert_eq!(soa.refresh, 7200, "refresh should match");
        assert_eq!(soa.retry, 3600, "retry should match");
        assert_eq!(soa.expire, 1209600, "expire should match");
        assert_eq!(soa.minimum, 3600, "minimum should match");
    }

    #[test]
    fn test_extract_soa_from_record_missing_mname() {
        let record = ZoneRecord {
            name: "example.com.".to_string(),
            rtype: "SOA".to_string(),
            class: "IN".to_string(),
            ttl: 3600,
            data: json!({
                "rname": "admin.example.com.",
                "serial": 2024010101,
                "refresh": 7200,
                "retry": 3600,
                "expire": 1209600,
                "minimum": 3600
            }),
        };

        let result = extract_soa_from_record(&record);
        assert!(result.is_err(), "Should fail when mname is missing");
        assert!(
            result.unwrap_err().to_string().contains("Missing mname"),
            "Error should mention missing mname"
        );
    }

    #[test]
    fn test_extract_soa_from_record_missing_serial() {
        let record = ZoneRecord {
            name: "example.com.".to_string(),
            rtype: "SOA".to_string(),
            class: "IN".to_string(),
            ttl: 3600,
            data: json!({
                "mname": "ns1.example.com.",
                "rname": "admin.example.com.",
                "refresh": 7200,
                "retry": 3600,
                "expire": 1209600,
                "minimum": 3600
            }),
        };

        let result = extract_soa_from_record(&record);
        assert!(result.is_err(), "Should fail when serial is missing");
        assert!(
            result.unwrap_err().to_string().contains("Missing serial"),
            "Error should mention missing serial"
        );
    }

    #[test]
    fn test_zone_transfer_type_from_str_axfr() {
        let result = ZoneTransferType::from_str("AXFR");
        assert!(result.is_ok(), "Should parse AXFR");
        assert_eq!(result.unwrap(), ZoneTransferType::Axfr);
    }

    #[test]
    fn test_zone_transfer_type_from_str_ixfr() {
        let result = ZoneTransferType::from_str("IXFR");
        assert!(result.is_ok(), "Should parse IXFR");
        assert_eq!(result.unwrap(), ZoneTransferType::Ixfr);
    }

    #[test]
    fn test_zone_transfer_type_from_str_case_insensitive() {
        let result1 = ZoneTransferType::from_str("axfr");
        assert!(result1.is_ok(), "Should parse lowercase axfr");

        let result2 = ZoneTransferType::from_str("Axfr");
        assert!(result2.is_ok(), "Should parse mixed case Axfr");
    }

    #[test]
    fn test_zone_transfer_type_from_str_invalid() {
        let result = ZoneTransferType::from_str("INVALID");
        assert!(result.is_err(), "Should fail on invalid transfer type");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid transfer type"),
            "Error should mention invalid type"
        );
    }

    #[test]
    fn test_zone_transfer_type_as_str() {
        assert_eq!(ZoneTransferType::Axfr.as_str(), "AXFR");
        assert_eq!(ZoneTransferType::Ixfr.as_str(), "IXFR");
    }

    #[test]
    fn test_dns_zone_fetch_response_new() {
        let opts = DnsZoneFetchOptions {
            zone: "example.com".to_string(),
            transfer: ZoneTransferType::Axfr,
            serial: None,
            servers: vec!["1.2.3.4".to_string()],
            port: 53,
            use_tcp: true,
            timeout_ms: 5000,
            retries: 1,
            dnssec: false,
            tsig_key_name: None,
            tsig_secret: None,
            tsig_algorithm: None,
            max_records: 1000000,
            include_raw: false,
            prefer_ipv6: false,
            format: OutputFormat::Json,
        };

        let response = DnsZoneFetchResponse::new(&opts);
        assert!(response.ok, "Response should be ok by default");
        assert!(response.zone.is_none(), "Zone should be None initially");
        assert!(response.error.is_none(), "Error should be None initially");
        assert_eq!(response.warnings.len(), 0, "Warnings should be empty");
    }

    #[test]
    fn test_zone_soa_structure() {
        let soa = ZoneSoa {
            mname: "ns1.example.com.".to_string(),
            rname: "admin.example.com.".to_string(),
            serial: 2024010101,
            refresh: 7200,
            retry: 3600,
            expire: 1209600,
            minimum: 3600,
        };

        assert_eq!(soa.mname, "ns1.example.com.");
        assert_eq!(soa.rname, "admin.example.com.");
        assert_eq!(soa.serial, 2024010101);
        assert_eq!(soa.refresh, 7200);
        assert_eq!(soa.retry, 3600);
        assert_eq!(soa.expire, 1209600);
        assert_eq!(soa.minimum, 3600);
    }

    #[test]
    fn test_zone_record_structure() {
        let record = ZoneRecord {
            name: "www.example.com.".to_string(),
            rtype: "A".to_string(),
            class: "IN".to_string(),
            ttl: 300,
            data: json!({"address": "93.184.216.34"}),
        };

        assert_eq!(record.name, "www.example.com.");
        assert_eq!(record.rtype, "A");
        assert_eq!(record.class, "IN");
        assert_eq!(record.ttl, 300);
        assert_eq!(
            record.data.get("address").and_then(|v| v.as_str()),
            Some("93.184.216.34")
        );
    }

    #[test]
    fn test_zone_summary_structure() {
        let soa = ZoneSoa {
            mname: "ns1.example.com.".to_string(),
            rname: "admin.example.com.".to_string(),
            serial: 2024010101,
            refresh: 7200,
            retry: 3600,
            expire: 1209600,
            minimum: 3600,
        };

        let records = vec![
            ZoneRecord {
                name: "example.com.".to_string(),
                rtype: "SOA".to_string(),
                class: "IN".to_string(),
                ttl: 3600,
                data: json!({}),
            },
            ZoneRecord {
                name: "www.example.com.".to_string(),
                rtype: "A".to_string(),
                class: "IN".to_string(),
                ttl: 300,
                data: json!({"address": "93.184.216.34"}),
            },
        ];

        let summary = ZoneSummary {
            name: "example.com.".to_string(),
            transfer_requested: "AXFR".to_string(),
            transfer_used: "AXFR".to_string(),
            server_used: "1.2.3.4".to_string(),
            soa: soa.clone(),
            serial: soa.serial,
            record_count: 2,
            records: records.clone(),
        };

        assert_eq!(summary.name, "example.com.");
        assert_eq!(summary.transfer_requested, "AXFR");
        assert_eq!(summary.transfer_used, "AXFR");
        assert_eq!(summary.server_used, "1.2.3.4");
        assert_eq!(summary.serial, 2024010101);
        assert_eq!(summary.record_count, 2);
        assert_eq!(summary.records.len(), 2);
    }

    #[test]
    fn test_zone_changes_structure() {
        let changes = ZoneChanges {
            old_serial: 2024010100,
            new_serial: 2024010101,
            deleted: vec![],
            added: vec![ZoneRecord {
                name: "new.example.com.".to_string(),
                rtype: "A".to_string(),
                class: "IN".to_string(),
                ttl: 300,
                data: json!({"address": "93.184.216.35"}),
            }],
        };

        assert_eq!(changes.old_serial, 2024010100);
        assert_eq!(changes.new_serial, 2024010101);
        assert_eq!(changes.deleted.len(), 0);
        assert_eq!(changes.added.len(), 1);
        assert_eq!(changes.added[0].name, "new.example.com.");
    }
}

#[cfg(test)]
mod zone_update_tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use std::net::{TcpListener, UdpSocket};
    use std::sync::{Arc, Mutex};

    // ---------- fake DNS server on 127.0.0.1 (UDP and TCP, same port) ----------

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Transport {
        Udp,
        Tcp,
    }

    // Returns the datagrams/frames to send back (possibly none).
    type Responder = Arc<dyn Fn(Transport, &[u8], usize) -> Vec<Vec<u8>> + Send + Sync>;

    struct FakeServer {
        port: u16,
        requests: Arc<Mutex<Vec<(Transport, Vec<u8>)>>>,
    }

    impl FakeServer {
        fn start(responder: Responder) -> Self {
            let (udp, tcp) = loop {
                let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
                let port = udp.local_addr().unwrap().port();
                if let Ok(tcp) = TcpListener::bind(("127.0.0.1", port)) {
                    break (udp, tcp);
                }
            };
            let port = udp.local_addr().unwrap().port();
            let requests: Arc<Mutex<Vec<(Transport, Vec<u8>)>>> = Arc::default();

            let (reqs, resp) = (requests.clone(), responder.clone());
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 65535];
                while let Ok((len, peer)) = udp.recv_from(&mut buf) {
                    let req = buf[..len].to_vec();
                    let n = {
                        let mut r = reqs.lock().unwrap();
                        r.push((Transport::Udp, req.clone()));
                        r.len() - 1
                    };
                    for reply in resp(Transport::Udp, &req, n) {
                        let _ = udp.send_to(&reply, peer);
                    }
                }
            });

            let (reqs, resp) = (requests.clone(), responder);
            std::thread::spawn(move || {
                use std::io::{Read, Write};
                for stream in tcp.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let mut len = [0u8; 2];
                    if stream.read_exact(&mut len).is_err() {
                        continue;
                    }
                    let mut req = vec![0u8; u16::from_be_bytes(len) as usize];
                    if stream.read_exact(&mut req).is_err() {
                        continue;
                    }
                    let n = {
                        let mut r = reqs.lock().unwrap();
                        r.push((Transport::Tcp, req.clone()));
                        r.len() - 1
                    };
                    for reply in resp(Transport::Tcp, &req, n) {
                        let mut framed = (reply.len() as u16).to_be_bytes().to_vec();
                        framed.extend_from_slice(&reply);
                        let _ = stream.write_all(&framed);
                    }
                }
            });

            FakeServer { port, requests }
        }

        fn requests(&self) -> Vec<(Transport, Vec<u8>)> {
            self.requests.lock().unwrap().clone()
        }
    }

    fn responder(
        f: impl Fn(Transport, &[u8], usize) -> Vec<Vec<u8>> + Send + Sync + 'static,
    ) -> Responder {
        Arc::new(f)
    }

    // Parse a captured request (TSIG removed) with trust-dns.
    fn parse_request(wire: &[u8]) -> (Message, Option<TsigRecord>) {
        let (stripped, tsig) = split_trailing_tsig(wire).unwrap();
        (Message::from_vec(&stripped).unwrap(), tsig)
    }

    // A reply echoing the request's ID, opcode and zone/question section.
    fn reply(req: &[u8], rcode: ResponseCode) -> Vec<u8> {
        let (m, _) = parse_request(req);
        let mut r = Message::new();
        r.set_id(m.id());
        r.set_message_type(MessageType::Response);
        r.set_op_code(m.op_code());
        r.set_response_code(rcode);
        r.add_queries(m.queries().to_vec());
        r.to_vec().unwrap()
    }

    fn soa_reply(req: &[u8], serial: u32) -> Vec<u8> {
        let (m, _) = parse_request(req);
        let mut r = Message::new();
        r.set_id(m.id());
        r.set_message_type(MessageType::Response);
        r.set_op_code(OpCode::Query);
        r.set_authoritative(true);
        r.add_queries(m.queries().to_vec());
        let zone = m.queries()[0].name().clone();
        r.add_answer(ProtoRecord::from_rdata(
            zone,
            300,
            ProtoRData::SOA(SOA::new(
                Name::from_ascii("ns1.example.com.").unwrap(),
                Name::from_ascii("hostmaster.example.com.").unwrap(),
                serial,
                7200,
                3600,
                1209600,
                300,
            )),
        ));
        r.to_vec().unwrap()
    }

    fn is_update(req: &[u8]) -> bool {
        (req[2] >> 3) & 0x0F == 5
    }

    // ---------- independent TSIG (hmac-sha256, key tsig-key.example.) ----------

    const KEY_B64: &str = "c2VjcmV0LWtleS1ieXRlcy0xMjM0NTY3ODkwYWJjZGVm";
    const KEY_WIRE: &[u8] = b"\x08tsig-key\x07example\x00";
    const ALG_WIRE: &[u8] = b"\x0bhmac-sha256\x00";

    fn hmac256(data: &[u8]) -> Vec<u8> {
        let secret = general_purpose::STANDARD.decode(KEY_B64).unwrap();
        let mut m = <Hmac<sha2::Sha256> as hmac::digest::KeyInit>::new_from_slice(&secret).unwrap();
        m.update(data);
        m.finalize().into_bytes().to_vec()
    }

    // Byte layout written out by hand from RFC 8945 section 4.3.3.
    fn test_variables(time: u64, error: u16) -> Vec<u8> {
        let mut v = KEY_WIRE.to_vec();
        v.extend_from_slice(&[0x00, 0xFF, 0, 0, 0, 0]); // class ANY, TTL 0
        v.extend_from_slice(ALG_WIRE);
        v.extend_from_slice(&time.to_be_bytes()[2..]);
        v.extend_from_slice(&[0x01, 0x2C]); // fudge 300
        v.extend_from_slice(&error.to_be_bytes());
        v.extend_from_slice(&[0, 0]); // other len
        v
    }

    // Verify a request's TSIG the way a server would; returns its MAC.
    fn server_verify_request(req: &[u8]) -> Vec<u8> {
        let (stripped, tsig) = split_trailing_tsig(req).unwrap();
        let tsig = tsig.expect("request must be TSIG-signed");
        assert_eq!(
            tsig.key_name,
            Name::from_ascii("tsig-key.example.").unwrap()
        );
        assert_eq!(tsig.algorithm, Name::from_ascii("hmac-sha256.").unwrap());
        assert_eq!(tsig.fudge, 300);
        assert_eq!(tsig.error, 0);
        assert_eq!(tsig.original_id, u16::from_be_bytes([req[0], req[1]]));
        assert!(unix_now().abs_diff(tsig.time_signed) < 5);
        let mut data = stripped.clone();
        data.extend_from_slice(&test_variables(tsig.time_signed, 0));
        assert_eq!(hmac256(&data), tsig.mac, "request MAC does not verify");
        tsig.mac
    }

    // Sign a reply as a server would (RFC 8945 section 5.3).
    fn server_sign_reply(reply: &mut Vec<u8>, request_mac: &[u8], error: u16, corrupt: bool) {
        let time = unix_now();
        let mut data = (request_mac.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(request_mac);
        data.extend_from_slice(reply);
        data.extend_from_slice(&test_variables(time, error));
        let mut mac = if error == 0 { hmac256(&data) } else { vec![] };
        if corrupt {
            mac[0] ^= 1;
        }
        let mut rdata = ALG_WIRE.to_vec();
        rdata.extend_from_slice(&time.to_be_bytes()[2..]);
        rdata.extend_from_slice(&[0x01, 0x2C]);
        rdata.extend_from_slice(&(mac.len() as u16).to_be_bytes());
        rdata.extend_from_slice(&mac);
        rdata.extend_from_slice(&reply[0..2]);
        rdata.extend_from_slice(&error.to_be_bytes());
        rdata.extend_from_slice(&[0, 0]);
        let mut rr = KEY_WIRE.to_vec();
        rr.extend_from_slice(&[0x00, 0xFA, 0x00, 0xFF, 0, 0, 0, 0]);
        rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        rr.extend_from_slice(&rdata);
        reply.extend_from_slice(&rr);
        reply[11] += 1;
    }

    // ---------- running the verb ----------

    struct VerbRun {
        status: Status,
        json: Option<Value>,
        stderr: String,
    }

    fn run_verb(kv: &[(&str, &str)]) -> VerbRun {
        let h = DnsHandle::from_url(&Url::parse("dns://localhost").unwrap()).unwrap();
        let args: Args = kv
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
        let status = {
            let mut io = IoStreams::new(&mut i, &mut o, &mut e);
            h.call("zone.update", &args, &mut io).unwrap()
        };
        VerbRun {
            status,
            json: serde_json::from_slice(&o).ok(),
            stderr: String::from_utf8_lossy(&e).into_owned(),
        }
    }

    fn error_code(run: &VerbRun) -> String {
        run.json.as_ref().unwrap()["error"][0]
            .as_str()
            .unwrap()
            .to_string()
    }

    const ADDS: &str = r#"[
        {"name":"www.example.com","rtype":"A","ttl":300,"data":{"address":"203.0.113.10"}},
        {"name":"www.example.com","rtype":"AAAA","ttl":300,"data":{"address":"2001:db8::10"}},
        {"name":"alias.example.com","rtype":"CNAME","ttl":60,"data":{"cname":"www.example.com"}},
        {"name":"example.com","rtype":"MX","ttl":3600,"data":{"preference":10,"exchange":"mail.example.com"}},
        {"name":"t.example.com","rtype":"TXT","ttl":60,"data":{"text":["v=spf1 -all","second"]}},
        {"name":"sub.example.com","rtype":"NS","ttl":60,"data":{"nsdname":"ns.sub.example.com"}},
        {"name":"_sip._tcp.example.com","rtype":"SRV","ttl":60,"data":{"priority":10,"weight":5,"port":5060,"target":"sip.example.com"}},
        {"name":"10.113.0.203.in-addr.arpa","rtype":"PTR","ttl":60,"data":{"ptrdname":"www.example.com"}},
        {"name":"example.com","rtype":"CAA","ttl":60,"data":{"flags":128,"tag":"issue","value":"letsencrypt.org"}}
    ]"#;
    const DELETES: &str = r#"[
        {"name":"old.example.com","rtype":"A","data":{"address":"192.0.2.9"}},
        {"name":"mx.example.com","rtype":"MX","delete_all":true},
        {"name":"gone.example.com","delete_all":true}
    ]"#;
    const PREREQS: &str = r#"[
        {"kind":"record_exists","name":"old.example.com","rtype":"A","data":{"address":"192.0.2.9"}},
        {"kind":"record_exists","name":"mx.example.com","rtype":"MX"},
        {"kind":"record_not_exists","name":"www.example.com","rtype":"A"},
        {"kind":"name_in_use","name":"old.example.com"},
        {"kind":"name_not_in_use","name":"new.example.com"}
    ]"#;

    fn rec_shape(r: &ProtoRecord) -> (String, ProtoRecordType, DNSClass, u32, bool) {
        (
            r.name().to_string(),
            r.record_type(),
            r.dns_class(),
            r.ttl(),
            r.data().is_some(),
        )
    }

    // ---------- verb tests ----------

    #[test]
    fn verb_sends_rfc2136_update_over_udp_and_reports_success() {
        let server = FakeServer::start(responder(|_, req, _| {
            vec![reply(req, ResponseCode::NoError)]
        }));
        let port = server.port.to_string();
        let run = run_verb(&[
            ("zone", "example.com"),
            ("servers", "127.0.0.1"),
            ("port", &port),
            ("use_tcp", "false"),
            ("adds", ADDS),
            ("deletes", DELETES),
            ("prerequisites", PREREQS),
        ]);
        assert_eq!(run.status.exit_code(), 0, "{:?} {}", run.json, run.stderr);
        let json = run.json.unwrap();
        assert_eq!(json["ok"], true);
        assert_eq!(json["summary"]["rcode"], "NOERROR");
        assert_eq!(json["summary"]["applied_adds"], 9);
        assert_eq!(json["summary"]["applied_deletes"], 3);
        assert_eq!(json["summary"]["server_used"], "127.0.0.1");
        assert_eq!(json["summary"]["tsig_used"], false);
        assert!(json.get("raw").is_none());

        let reqs = server.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].0, Transport::Udp);
        let (m, tsig) = parse_request(&reqs[0].1);
        assert!(tsig.is_none());
        assert_eq!(m.op_code(), OpCode::Update);
        assert_eq!(m.message_type(), MessageType::Query);
        // Zone section
        assert_eq!(m.queries().len(), 1);
        assert_eq!(m.queries()[0].name().to_string(), "example.com.");
        assert_eq!(m.queries()[0].query_type(), ProtoRecordType::SOA);
        assert_eq!(m.queries()[0].query_class(), DNSClass::IN);
        // Prerequisite section (answer section), RFC 2136 2.4
        let pre: Vec<_> = m.answers().iter().map(rec_shape).collect();
        assert_eq!(
            pre,
            vec![
                (
                    "old.example.com.".to_string(),
                    ProtoRecordType::A,
                    DNSClass::IN,
                    0,
                    true
                ),
                (
                    "mx.example.com.".to_string(),
                    ProtoRecordType::MX,
                    DNSClass::ANY,
                    0,
                    false
                ),
                (
                    "www.example.com.".to_string(),
                    ProtoRecordType::A,
                    DNSClass::NONE,
                    0,
                    false
                ),
                (
                    "old.example.com.".to_string(),
                    ProtoRecordType::ANY,
                    DNSClass::ANY,
                    0,
                    false
                ),
                (
                    "new.example.com.".to_string(),
                    ProtoRecordType::ANY,
                    DNSClass::NONE,
                    0,
                    false
                ),
            ]
        );
        // Update section (authority section), RFC 2136 2.5: deletes then adds
        let upd: Vec<_> = m.name_servers().iter().map(rec_shape).collect();
        assert_eq!(upd.len(), 12);
        assert_eq!(
            upd[0],
            (
                "old.example.com.".to_string(),
                ProtoRecordType::A,
                DNSClass::NONE,
                0,
                true
            )
        );
        assert_eq!(
            upd[1],
            (
                "mx.example.com.".to_string(),
                ProtoRecordType::MX,
                DNSClass::ANY,
                0,
                false
            )
        );
        assert_eq!(
            upd[2],
            (
                "gone.example.com.".to_string(),
                ProtoRecordType::ANY,
                DNSClass::ANY,
                0,
                false
            )
        );
        for add in &upd[3..] {
            assert_eq!(add.2, DNSClass::IN);
            assert!(add.4);
        }
        let types: Vec<_> = upd[3..].iter().map(|r| r.1).collect();
        assert_eq!(
            types,
            vec![
                ProtoRecordType::A,
                ProtoRecordType::AAAA,
                ProtoRecordType::CNAME,
                ProtoRecordType::MX,
                ProtoRecordType::TXT,
                ProtoRecordType::NS,
                ProtoRecordType::SRV,
                ProtoRecordType::PTR,
                ProtoRecordType::CAA,
            ]
        );
        assert_eq!(upd[3].3, 300);
        assert_eq!(upd[6].3, 3600);
        assert!(m.additionals().is_empty());

        // Spot-check RDATA
        let rdata = |i: usize| m.name_servers()[i].data().unwrap().clone();
        assert_eq!(rdata(3), ProtoRData::A(A("203.0.113.10".parse().unwrap())));
        assert_eq!(rdata(0), ProtoRData::A(A("192.0.2.9".parse().unwrap())));
        match rdata(9) {
            ProtoRData::SRV(srv) => {
                assert_eq!((srv.priority(), srv.weight(), srv.port()), (10, 5, 5060));
                assert_eq!(srv.target().to_string(), "sip.example.com.");
            }
            other => panic!("{other:?}"),
        }
        match rdata(7) {
            ProtoRData::TXT(txt) => {
                assert_eq!(txt.txt_data().len(), 2);
                assert_eq!(&*txt.txt_data()[0], b"v=spf1 -all");
            }
            other => panic!("{other:?}"),
        }
        // CAA RDATA as raw RFC 8659 bytes: flags, tag length, tag, value
        let caa = b"\x80\x05issueletsencrypt.org";
        assert!(reqs[0].1.windows(caa.len()).any(|w| w == caa));
    }

    #[test]
    fn verb_uses_tcp_by_default() {
        let server = FakeServer::start(responder(|_, req, _| {
            vec![reply(req, ResponseCode::NoError)]
        }));
        let port = server.port.to_string();
        let run = run_verb(&[
            ("zone", "example.com"),
            ("servers", "127.0.0.1"),
            ("port", &port),
            (
                "adds",
                r#"[{"name":"a.example.com","rtype":"A","ttl":60,"data":{"address":"192.0.2.1"}}]"#,
            ),
        ]);
        assert_eq!(run.status.exit_code(), 0, "{:?}", run.json);
        let reqs = server.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].0, Transport::Tcp);
    }

    #[test]
    fn verb_falls_back_to_tcp_when_udp_reply_is_truncated() {
        let server = FakeServer::start(responder(|t, req, _| {
            let mut r = reply(req, ResponseCode::NoError);
            if t == Transport::Udp {
                r[2] |= 0x02; // TC
            }
            vec![r]
        }));
        let port = server.port.to_string();
        let run = run_verb(&[
            ("zone", "example.com"),
            ("servers", "127.0.0.1"),
            ("port", &port),
            ("use_tcp", "false"),
            (
                "adds",
                r#"[{"name":"a.example.com","rtype":"A","ttl":60,"data":{"address":"192.0.2.1"}}]"#,
            ),
        ]);
        assert_eq!(run.status.exit_code(), 0, "{:?}", run.json);
        let reqs = server.requests();
        let transports: Vec<_> = reqs.iter().map(|r| r.0).collect();
        assert_eq!(transports, vec![Transport::Udp, Transport::Tcp]);
        assert_eq!(reqs[0].1, reqs[1].1, "same message is resent over TCP");
    }

    #[test]
    fn verb_maps_each_error_rcode() {
        let cases = [
            (ResponseCode::Refused, "REFUSED", DNS_ZONE_UPDATE_REFUSED),
            (
                ResponseCode::NXRRSet,
                "NXRRSET",
                DNS_ZONE_UPDATE_PRECONDITION_FAILED,
            ),
            (
                ResponseCode::YXRRSet,
                "YXRRSET",
                DNS_ZONE_UPDATE_PRECONDITION_FAILED,
            ),
            (
                ResponseCode::YXDomain,
                "YXDOMAIN",
                DNS_ZONE_UPDATE_PRECONDITION_FAILED,
            ),
            (ResponseCode::NXDomain, "NXDOMAIN", DNS_ZONE_UPDATE_NXDOMAIN),
            (ResponseCode::ServFail, "SERVFAIL", DNS_ZONE_UPDATE_SERVFAIL),
            (ResponseCode::FormErr, "FORMERR", DNS_ZONE_UPDATE_FORMERR),
            (ResponseCode::NotAuth, "NOTAUTH", DNS_ZONE_UPDATE_NOTAUTH),
            (ResponseCode::NotZone, "NOTZONE", DNS_ZONE_UPDATE_NOTZONE),
            (ResponseCode::NotImp, "NOTIMP", DNS_ZONE_UPDATE_RCODE_ERROR),
        ];
        for (rcode, mnemonic, code) in cases {
            let server = FakeServer::start(responder(move |_, req, _| vec![reply(req, rcode)]));
            let port = server.port.to_string();
            let run = run_verb(&[
                ("zone", "example.com"),
                ("servers", "127.0.0.1"),
                ("port", &port),
                ("use_tcp", "false"),
                ("deletes", r#"[{"name":"a.example.com","delete_all":true}]"#),
            ]);
            assert_eq!(run.status.exit_code(), 1, "{mnemonic}");
            let json = run.json.as_ref().unwrap();
            assert_eq!(json["ok"], false);
            assert_eq!(json["summary"]["rcode"], mnemonic);
            assert_eq!(json["summary"]["applied_deletes"], 0);
            assert_eq!(error_code(&run), code, "{mnemonic}");
            // A DNS answer ends the operation: no retries.
            assert_eq!(server.requests().len(), 1);
        }
    }

    #[test]
    fn verb_tsig_signs_request_and_verifies_reply() {
        let server = FakeServer::start(responder(|_, req, _| {
            let mac = server_verify_request(req);
            let mut r = reply(req, ResponseCode::NoError);
            server_sign_reply(&mut r, &mac, 0, false);
            vec![r]
        }));
        let port = server.port.to_string();
        let run = run_verb(&[
            ("zone", "example.com"),
            ("servers", "127.0.0.1"),
            ("port", &port),
            ("use_tcp", "false"),
            ("tsig_key_name", "TSIG-Key.Example"),
            ("tsig_secret", KEY_B64),
            ("tsig_algorithm", "hmac-sha256"),
            ("include_raw", "true"),
            (
                "adds",
                r#"[{"name":"a.example.com","rtype":"A","ttl":60,"data":{"address":"192.0.2.1"}}]"#,
            ),
        ]);
        assert_eq!(run.status.exit_code(), 0, "{:?} {}", run.json, run.stderr);
        let json = run.json.unwrap();
        assert_eq!(json["summary"]["tsig_used"], true);
        assert_eq!(json["warnings"], json!([]));
        let reqs = server.requests();
        assert_eq!(reqs.len(), 1);
        // include_raw: request and reply in hex
        assert_eq!(json["raw"]["request_hex"], hex::encode(&reqs[0].1));
        assert!(json["raw"]["response_hex"].as_str().unwrap().len() > 24);
    }

    #[test]
    fn verb_tsig_default_algorithm_is_hmac_sha256() {
        let server = FakeServer::start(responder(|_, req, _| {
            let mac = server_verify_request(req);
            let mut r = reply(req, ResponseCode::NoError);
            server_sign_reply(&mut r, &mac, 0, false);
            vec![r]
        }));
        let port = server.port.to_string();
        let run = run_verb(&[
            ("zone", "example.com"),
            ("servers", "127.0.0.1"),
            ("port", &port),
            ("tsig_key_name", "tsig-key.example."),
            ("tsig_secret", KEY_B64),
        ]);
        assert_eq!(run.status.exit_code(), 0, "{:?}", run.json);
    }

    #[test]
    fn verb_tsig_rejects_bad_unsigned_or_refused_replies() {
        // (reply kind, expected error code, expected message fragment)
        let cases: [(&str, &str, &str); 4] = [
            ("corrupt", DNS_ZONE_UPDATE_TSIG_FAILED, "does not verify"),
            (
                "unsigned-ok",
                DNS_ZONE_UPDATE_TSIG_FAILED,
                "not TSIG-signed",
            ),
            ("badkey", DNS_ZONE_UPDATE_TSIG_FAILED, "BADKEY"),
            ("unsigned-refused", DNS_ZONE_UPDATE_REFUSED, "refused"),
        ];
        for (kind, code, fragment) in cases {
            let server = FakeServer::start(responder(move |_, req, _| {
                let mac = server_verify_request(req);
                let r = match kind {
                    "corrupt" => {
                        let mut r = reply(req, ResponseCode::NoError);
                        server_sign_reply(&mut r, &mac, 0, true);
                        r
                    }
                    "unsigned-ok" => reply(req, ResponseCode::NoError),
                    "badkey" => {
                        let mut r = reply(req, ResponseCode::NotAuth);
                        server_sign_reply(&mut r, &mac, 17, false);
                        r
                    }
                    _ => reply(req, ResponseCode::Refused),
                };
                vec![r]
            }));
            let port = server.port.to_string();
            let run = run_verb(&[
                ("zone", "example.com"),
                ("servers", "127.0.0.1"),
                ("port", &port),
                ("tsig_key_name", "tsig-key.example"),
                ("tsig_secret", KEY_B64),
            ]);
            assert_eq!(run.status.exit_code(), 1, "{kind}");
            assert_eq!(error_code(&run), code, "{kind}");
            let msg = run.json.as_ref().unwrap()["error"][1]
                .as_str()
                .unwrap()
                .to_lowercase();
            assert!(msg.contains(&fragment.to_lowercase()), "{kind}: {msg}");
            assert_eq!(server.requests().len(), 1, "{kind}");
        }
    }

    #[test]
    fn verb_dry_run_builds_and_signs_but_sends_nothing() {
        let server = FakeServer::start(responder(|_, req, _| {
            vec![reply(req, ResponseCode::NoError)]
        }));
        let port = server.port.to_string();
        let run = run_verb(&[
            ("zone", "example.com"),
            ("servers", "127.0.0.1"),
            ("port", &port),
            ("dry_run", "true"),
            ("include_raw", "true"),
            ("tsig_key_name", "tsig-key.example"),
            ("tsig_secret", KEY_B64),
            ("adds", ADDS),
            ("deletes", DELETES),
            ("prerequisites", PREREQS),
        ]);
        assert_eq!(run.status.exit_code(), 0, "{:?}", run.json);
        let json = run.json.unwrap();
        assert_eq!(json["summary"]["dry_run"], true);
        assert!(json["summary"].get("rcode").is_none());
        assert!(json["summary"].get("server_used").is_none());
        std::thread::sleep(Duration::from_millis(100));
        assert!(server.requests().is_empty(), "dry run must not send");

        // The built message is reported and is TSIG-signed.
        let wire = hex::decode(json["raw"]["request_hex"].as_str().unwrap()).unwrap();
        server_verify_request(&wire);
        let (m, _) = parse_request(&wire);
        assert_eq!(m.answers().len(), 5);
        assert_eq!(m.name_servers().len(), 12);

        // Bad record data is reported in a dry run.
        let run = run_verb(&[
            ("zone", "example.com"),
            ("dry_run", "true"),
            (
                "adds",
                r#"[{"name":"a.example.com","rtype":"SRV","ttl":60,"data":{"priority":70000,"weight":0,"port":1,"target":"x.example.com"}}]"#,
            ),
        ]);
        assert_eq!(run.status.exit_code(), 1);
        assert_eq!(error_code(&run), DNS_ZONE_UPDATE_INVALID_ADD_RECORD);
        assert!(
            run.json.unwrap()["error"][1]
                .as_str()
                .unwrap()
                .contains("out of range")
        );
    }

    #[test]
    fn verb_retries_after_timeout_then_reports_timeout() {
        // Drops the first two requests, answers the third.
        let server = FakeServer::start(responder(|_, req, n| {
            if n < 2 {
                vec![]
            } else {
                vec![reply(req, ResponseCode::NoError)]
            }
        }));
        let port = server.port.to_string();
        let base = [
            ("zone", "example.com"),
            ("servers", "127.0.0.1"),
            ("port", port.as_str()),
            ("use_tcp", "false"),
            ("timeout_ms", "200"),
        ];
        let mut args = base.to_vec();
        args.push(("retries", "2"));
        let run = run_verb(&args);
        assert_eq!(run.status.exit_code(), 0, "{:?}", run.json);
        assert_eq!(server.requests().len(), 3);

        // Never answers: retries + 1 attempts, then a timeout error.
        let silent = FakeServer::start(responder(|_, _, _| vec![]));
        let port = silent.port.to_string();
        let started = Instant::now();
        let run = run_verb(&[
            ("zone", "example.com"),
            ("servers", "127.0.0.1"),
            ("port", &port),
            ("use_tcp", "false"),
            ("timeout_ms", "200"),
            ("retries", "1"),
        ]);
        let elapsed = started.elapsed();
        assert_eq!(run.status.exit_code(), 1);
        assert_eq!(error_code(&run), DNS_ZONE_UPDATE_TIMEOUT);
        assert_eq!(silent.requests().len(), 2);
        assert!(elapsed >= Duration::from_millis(400) && elapsed < Duration::from_secs(3));
    }

    #[test]
    fn verb_ignores_udp_reply_with_wrong_id_and_rejects_it_over_tcp() {
        let server = FakeServer::start(responder(|t, req, _| {
            let good = reply(req, ResponseCode::NoError);
            let mut bad = reply(req, ResponseCode::Refused);
            bad[0] ^= 0xFF;
            match t {
                Transport::Udp => vec![bad, good],
                Transport::Tcp => vec![bad],
            }
        }));
        let port = server.port.to_string();
        let run = run_verb(&[
            ("zone", "example.com"),
            ("servers", "127.0.0.1"),
            ("port", &port),
            ("use_tcp", "false"),
        ]);
        assert_eq!(run.status.exit_code(), 0, "{:?}", run.json);
        assert_eq!(run.json.unwrap()["summary"]["rcode"], "NOERROR");

        let run = run_verb(&[
            ("zone", "example.com"),
            ("servers", "127.0.0.1"),
            ("port", &port),
            ("retries", "0"),
        ]);
        assert_eq!(run.status.exit_code(), 1);
        assert_eq!(error_code(&run), DNS_ZONE_UPDATE_NETWORK_ERROR);
    }

    #[test]
    fn verb_tries_next_server_after_transport_failure() {
        let silent = FakeServer::start(responder(|_, _, _| vec![]));
        let good = FakeServer::start(responder(|_, req, _| {
            vec![reply(req, ResponseCode::NoError)]
        }));
        let servers = format!(r#"["127.0.0.1:{}","127.0.0.1:{}"]"#, silent.port, good.port);
        let run = run_verb(&[
            ("zone", "example.com"),
            ("servers", &servers),
            ("use_tcp", "false"),
            ("timeout_ms", "150"),
            ("retries", "0"),
        ]);
        assert_eq!(run.status.exit_code(), 0, "{:?}", run.json);
        let json = run.json.unwrap();
        assert_eq!(
            json["summary"]["server_used"],
            format!("127.0.0.1:{}", good.port)
        );
        assert_eq!(json["warnings"].as_array().unwrap().len(), 1);

        // Both silent: all servers failed.
        let silent2 = FakeServer::start(responder(|_, _, _| vec![]));
        let servers = format!(
            r#"["127.0.0.1:{}","127.0.0.1:{}"]"#,
            silent.port, silent2.port
        );
        let run = run_verb(&[
            ("zone", "example.com"),
            ("servers", &servers),
            ("use_tcp", "false"),
            ("timeout_ms", "150"),
            ("retries", "0"),
        ]);
        assert_eq!(run.status.exit_code(), 1);
        assert_eq!(error_code(&run), DNS_ZONE_UPDATE_ALL_SERVERS_FAILED);
    }

    #[test]
    fn verb_zone_serial_at_least_queries_soa_first() {
        // serial 5 on the server; 4294967290 + 11 wraps to 5 (RFC 1982)
        let server = FakeServer::start(responder(|_, req, _| {
            if is_update(req) {
                vec![reply(req, ResponseCode::NoError)]
            } else {
                vec![soa_reply(req, 5)]
            }
        }));
        let port = server.port.to_string();
        for (required, ok) in [
            ("5", true),
            ("4294967290", true),
            ("6", false),
            ("2147483653", false),
        ] {
            let before = server.requests().len();
            let prereq = format!(
                r#"[{{"kind":"zone_serial_at_least","serial":{}}}]"#,
                required
            );
            let run = run_verb(&[
                ("zone", "example.com"),
                ("servers", "127.0.0.1"),
                ("port", &port),
                ("prerequisites", &prereq),
            ]);
            let reqs = server.requests()[before..].to_vec();
            let (soa_query, _) = parse_request(&reqs[0].1);
            assert_eq!(soa_query.op_code(), OpCode::Query);
            assert_eq!(soa_query.queries()[0].query_type(), ProtoRecordType::SOA);
            if ok {
                assert_eq!(run.status.exit_code(), 0, "{required}: {:?}", run.json);
                assert_eq!(reqs.len(), 2);
                let (update, _) = parse_request(&reqs[1].1);
                assert_eq!(update.op_code(), OpCode::Update);
                // zone_serial_at_least is not sent as an RFC 2136 prerequisite
                assert!(update.answers().is_empty());
            } else {
                assert_eq!(run.status.exit_code(), 1, "{required}");
                assert_eq!(error_code(&run), DNS_ZONE_UPDATE_PRECONDITION_FAILED);
                assert_eq!(reqs.len(), 1, "no UPDATE after a failed serial check");
            }
        }
    }

    #[test]
    fn verb_rejects_invalid_input() {
        // Argument errors: no JSON, [code] on stderr, exit 1
        let cases: [(&[(&str, &str)], &str); 5] = [
            (&[], DNS_ZONE_UPDATE_INVALID_ZONE),
            (
                &[("zone", "example.com"), ("port", "0")],
                DNS_ZONE_UPDATE_INVALID_PORT,
            ),
            (
                &[
                    ("zone", "example.com"),
                    (
                        "adds",
                        r#"[{"name":"a.example.com","rtype":"BOGUS","ttl":1,"data":{}}]"#,
                    ),
                ],
                DNS_ZONE_UPDATE_INVALID_RECORD_TYPE,
            ),
            (
                &[("zone", "example.com"), ("tsig_key_name", "k")],
                DNS_ZONE_UPDATE_INVALID_TSIG_CONFIG,
            ),
            (
                &[
                    ("zone", "example.com"),
                    ("max_changes", "1"),
                    (
                        "deletes",
                        r#"[{"name":"a.example.com","delete_all":true},{"name":"b.example.com","delete_all":true}]"#,
                    ),
                ],
                DNS_ZONE_UPDATE_INVALID_MAX_CHANGES,
            ),
        ];
        for (args, code) in cases {
            let run = run_verb(args);
            assert_eq!(run.status.exit_code(), 1, "{code}");
            assert!(run.json.is_none(), "{code}");
            assert!(
                run.stderr.contains(&format!("[{}]", code)),
                "{code}: {}",
                run.stderr
            );
        }

        // Validation errors: JSON with ok=false, exit 1, nothing sent
        let server = FakeServer::start(responder(|_, req, _| {
            vec![reply(req, ResponseCode::NoError)]
        }));
        let port = server.port.to_string();
        let cases: [(&str, &str, &str); 6] = [
            (
                "adds",
                r#"[{"name":"a.example.com","rtype":"ANY","ttl":1,"data":{}}]"#,
                DNS_ZONE_UPDATE_INVALID_RECORD_TYPE,
            ),
            (
                "adds",
                r#"[{"name":"a.example.com","rtype":"A","ttl":1,"data":{"address":"not-an-ip"}}]"#,
                DNS_ZONE_UPDATE_INVALID_ADD_RECORD,
            ),
            (
                "adds",
                r#"[{"name":"a.example.com","rtype":"CAA","ttl":1,"data":{"tag":"bad tag","value":"x"}}]"#,
                DNS_ZONE_UPDATE_INVALID_ADD_RECORD,
            ),
            (
                "deletes",
                r#"[{"name":"a.example.com","rtype":"MX","data":{"preference":10}}]"#,
                DNS_ZONE_UPDATE_INVALID_DELETE_SPEC,
            ),
            (
                "prerequisites",
                r#"[{"kind":"record_not_exists","name":"a.example.com","rtype":"A","data":{"address":"192.0.2.1"}}]"#,
                DNS_ZONE_UPDATE_INVALID_PREREQUISITE,
            ),
            (
                "tsig_algorithm",
                "hmac-md5",
                DNS_ZONE_UPDATE_UNSUPPORTED_TSIG_ALGORITHM,
            ),
        ];
        for (key, value, code) in cases {
            let run = run_verb(&[
                ("zone", "example.com"),
                ("servers", "127.0.0.1"),
                ("port", &port),
                ("tsig_key_name", "tsig-key.example"),
                ("tsig_secret", KEY_B64),
                (key, value),
            ]);
            assert_eq!(run.status.exit_code(), 1, "{code}");
            assert_eq!(run.json.as_ref().unwrap()["ok"], false);
            assert_eq!(error_code(&run), code, "{value}");
        }
        assert!(server.requests().is_empty());
    }

    // ---------- known-answer and helper tests ----------

    // Captured from BIND's `nsupdate -y <alg>:tsig-key.example:<KEY_B64>`
    // sending "prereq nxrrset www.example.com A", "update delete
    // old.example.com A 192.0.2.9", "update add www.example.com 300 A
    // 203.0.113.10" for zone example.com.
    const NSUPDATE_CAPTURES: [(&str, &str); 4] = [
        (
            "hmac-sha1",
            "3a4e28000001000100020001076578616d706c6503636f6d000006000103777777c00c000100fe000000000000036f6c64c00c000100fe000000000004c0000209c01d000100010000012c0004cb00710a08747369672d6b6579076578616d706c650000fa00ff00000000002f09686d61632d736861310000006aef1369012c0014cdec7a61b1e8fe21bbdc25861d12007d79c26e583a4e00000000",
        ),
        (
            "hmac-sha256",
            "34d128000001000100020001076578616d706c6503636f6d000006000103777777c00c000100fe000000000000036f6c64c00c000100fe000000000004c0000209c01d000100010000012c0004cb00710a08747369672d6b6579076578616d706c650000fa00ff00000000003d0b686d61632d7368613235360000006aef1369012c00204691c31ce88b40ef4266ef575a3e947b4bd88142cf472f132b27d15360e097ba34d100000000",
        ),
        (
            "hmac-sha384",
            "6d8728000001000100020001076578616d706c6503636f6d000006000103777777c00c000100fe000000000000036f6c64c00c000100fe000000000004c0000209c01d000100010000012c0004cb00710a08747369672d6b6579076578616d706c650000fa00ff00000000004d0b686d61632d7368613338340000006aef1369012c00307e0a6b5da6f29b61e70fc79111da5e0f7869cffe38a5e09f5317ba4c31642688ddfd0641bd6fc356150683f8b9c8719c6d8700000000",
        ),
        (
            "hmac-sha512",
            "b3ce28000001000100020001076578616d706c6503636f6d000006000103777777c00c000100fe000000000000036f6c64c00c000100fe000000000004c0000209c01d000100010000012c0004cb00710a08747369672d6b6579076578616d706c650000fa00ff00000000005d0b686d61632d7368613531320000006aef1369012c00403b84c56f6001dafb7104281a1877672829f48cca59fbaa307ace662c5c1165097bf2755753d0724c8cc53b6e7b432f0e005ebf5d0b0c09e217b996ec3425081bb3ce00000000",
        ),
    ];

    // dnspython 2.9 `make_response` to the hmac-sha256 capture above, signed
    // with the same key at time 0x6aef1387.
    const DNSPYTHON_SHA256_REPLY: &str = "34d1a8000001000000000001076578616d706c6503636f6d000006000108747369672d6b6579076578616d706c650000fa00ff00000000003d0b686d61632d7368613235360000006aef1387012c00203e2ddfeef2158ce227b0e8b248f79fdbf09779795da6586ac2acb1299626887434d100000000";

    fn test_key(alg: &str) -> TsigKey {
        TsigKey {
            name: Name::from_ascii("tsig-key.example.").unwrap(),
            algorithm: TsigAlgorithm::from_option(alg).unwrap(),
            secret: general_purpose::STANDARD.decode(KEY_B64).unwrap(),
        }
    }

    #[test]
    fn tsig_signing_matches_nsupdate_byte_for_byte() {
        for (alg, hex_wire) in NSUPDATE_CAPTURES {
            let captured = hex::decode(hex_wire).unwrap();
            let (unsigned, tsig) = split_trailing_tsig(&captured).unwrap();
            let tsig = tsig.unwrap();
            let mut ours = unsigned.clone();
            let mac = tsig_sign(&mut ours, &test_key(alg), tsig.time_signed);
            assert_eq!(mac, tsig.mac, "{alg}");
            assert_eq!(ours, captured, "{alg}");
        }
    }

    #[test]
    fn tsig_reply_verification_matches_dnspython() {
        let request = hex::decode(NSUPDATE_CAPTURES[1].1).unwrap();
        let request_mac = split_trailing_tsig(&request).unwrap().1.unwrap().mac;
        let reply = hex::decode(DNSPYTHON_SHA256_REPLY).unwrap();
        let key = test_key("hmac-sha256");
        let (stripped, tsig) = split_trailing_tsig(&reply).unwrap();
        let tsig = tsig.unwrap();
        let signed_at = 0x6aef1387;
        assert_eq!(tsig.time_signed, signed_at);
        assert_eq!(
            verify_response_tsig(&stripped, &tsig, &key, &request_mac, signed_at),
            Ok(())
        );
        assert_eq!(
            verify_response_tsig(&stripped, &tsig, &key, &request_mac, signed_at + 300),
            Ok(())
        );
        // Outside the fudge window
        assert!(
            verify_response_tsig(&stripped, &tsig, &key, &request_mac, signed_at + 301)
                .unwrap_err()
                .contains("fudge")
        );
        // Wrong request MAC, tampered reply, wrong key
        let mut other_mac = request_mac.clone();
        other_mac[0] ^= 1;
        assert!(verify_response_tsig(&stripped, &tsig, &key, &other_mac, signed_at).is_err());
        let mut tampered = stripped.clone();
        tampered[3] |= 0x05;
        assert!(verify_response_tsig(&tampered, &tsig, &key, &request_mac, signed_at).is_err());
        let mut wrong_key = key.clone();
        wrong_key.secret[0] ^= 1;
        assert!(
            verify_response_tsig(&stripped, &tsig, &wrong_key, &request_mac, signed_at).is_err()
        );
        // Truncated MAC: 16 of 32 octets is allowed, 8 is not
        let mut truncated = tsig.clone();
        truncated.mac.truncate(16);
        assert_eq!(
            verify_response_tsig(&stripped, &truncated, &key, &request_mac, signed_at),
            Ok(())
        );
        truncated.mac.truncate(8);
        assert!(
            verify_response_tsig(&stripped, &truncated, &key, &request_mac, signed_at).is_err()
        );
    }

    #[test]
    fn built_message_matches_nsupdate_structure() {
        let opts = DnsZoneUpdateOptions::from_args(
            &[
                ("zone", "example.com"),
                ("prerequisites", r#"[{"kind":"record_not_exists","name":"www.example.com","rtype":"A"}]"#),
                ("deletes", r#"[{"name":"old.example.com","rtype":"A","data":{"address":"192.0.2.9"}}]"#),
                ("adds", r#"[{"name":"www.example.com","rtype":"A","ttl":300,"data":{"address":"203.0.113.10"}}]"#),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        )
        .unwrap();
        let mut message = build_update_message(&opts).unwrap();
        let ours = finalize_request(&mut message, None).unwrap().wire;
        let captured = hex::decode(NSUPDATE_CAPTURES[1].1).unwrap();
        let (mut theirs, _) = split_trailing_tsig(&captured).unwrap();
        // Same message apart from the random ID
        theirs[0..2].copy_from_slice(&ours[0..2]);
        assert_eq!(ours, theirs);
    }

    #[test]
    fn serial_arithmetic_follows_rfc1982() {
        assert!(serial_at_least(10, 10));
        assert!(serial_at_least(11, 10));
        assert!(!serial_at_least(9, 10));
        assert!(serial_at_least(5, u32::MAX - 5)); // wrapped forward
        assert!(!serial_at_least(u32::MAX - 5, 5));
        assert!(!serial_at_least(1 << 31, 0)); // incomparable
        assert!(!serial_at_least(0, 1 << 31));
        assert!(serial_at_least((1 << 31) - 1, 0));
    }
}
