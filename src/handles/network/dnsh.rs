use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose};
use rand::seq::SliceRandom;
use serde_json::{Value, json};
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
use trust_dns_resolver::config::ResolverConfig;
use trust_dns_resolver::proto::rr::{DNSClass, Name, RData, RecordType as TrustDnsRecordType};
use url::Url;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::{Status, exit},
};

mod args;
mod client;
mod query;
#[cfg(test)]
mod test_server;
#[cfg(test)]
mod verb_tests;
mod xfr;

pub use args::verb_options;
use args::{
    ArgError, ArgResult, DNS_INVALID_ARGUMENT, bool_opt, check_unknown, format_opt, ip_list,
    required_str, server_list, uint_opt,
};

/// (De)serializes an `(code, message)` error as `{"code": ..., "message": ...}`.
mod error_object {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct ErrorObject {
        code: String,
        message: String,
    }

    pub fn serialize<S: Serializer>(
        error: &Option<(String, String)>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        error
            .as_ref()
            .map(|(code, message)| ErrorObject {
                code: code.clone(),
                message: message.clone(),
            })
            .serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<(String, String)>, D::Error> {
        Ok(Option::<ErrorObject>::deserialize(d)?.map(|e| (e.code, e.message)))
    }
}

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("dns", |u| Ok(Box::new(DnsHandle::from_url(u)?)));
}

/// Metadata for `resh dns --help` and `resh dns <verb> --help`.
static DNS_HELP: HandleHelp = HandleHelp {
    description: "The dns handle sends DNS queries itself over UDP or TCP, covering record \
        lookups, host, mail, service, and reverse resolution, and delegation traces from the \
        root servers. It also transfers zones with AXFR or IXFR and sends RFC 2136 dynamic \
        updates, both optionally TSIG-signed. The URL target is always dns:// with an empty \
        host, and the name and options are arguments, such as dns://.lookup name=example.com.",
    usage: "resh dns://.<verb> [name=<name>|zone=<zone>] [key=value ...]",
    verbs: &[
        VerbHelp {
            name: "lookup",
            definition: "Queries one DNS record type for a name and prints the answer, \
                authority and additional records as JSON or text.",
            detail: Some(VerbDetail {
                usage: "resh dns://.lookup name=<name> [rtype=<type>] [servers=<ip,...>]\n  \
                    [port=<n>] [use_tcp=true|false] [timeout_ms=<ms>] [retries=<n>]\n  \
                    [dnssec=true|false] [follow_cname=true|false]\n  \
                    [include_authority=true|false] [include_additional=true|false]\n  \
                    [randomize_servers=true|false] [format=json|text]",
                example: "resh dns://.lookup name=example.com rtype=MX",
                example_output: Some(
                    r#"{
  "additional": [
    {
      "class": "IN",
      "data": {
        "address": "192.0.2.25"
      },
      "name": "mail.example.com.",
      "rtype": "A",
      "ttl": 3600
    }
  ],
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
    "server_used": "192.0.2.53",
    "truncated": false
  },
  "timestamp_unix_ms": 1792142364512,
  "warnings": []
}

Without servers the name servers in /etc/resolv.conf are asked."#,
                ),
            }),
        },
        VerbHelp {
            name: "resolve",
            definition: "Resolves a host name to addresses after following CNAMEs, or \
                resolves mail, service, or reverse records depending on mode.",
            detail: Some(VerbDetail {
                usage: "resh dns://.resolve name=<name> [mode=host|mail|service|reverse]\n  \
                    [family=any|ipv4|ipv6] [servers=<ip,...>] [port=<n>]\n  \
                    [use_tcp=true|false] [timeout_ms=<ms>] [retries=<n>]\n  \
                    [dnssec=true|false] [max_cname_depth=<n>] [follow_srv=true|false]\n  \
                    [validate_reverse=true|false] [want_raw=true|false]\n  \
                    [format=json|text]",
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
    "source_server": "192.0.2.53",
    "srv": []
  },
  "timestamp_unix_ms": 1792142364512,
  "warnings": []
}

Shown for mode=host. Other modes fill the mx, srv, or ptr_name and
forward_addresses fields."#,
                ),
            }),
        },
        VerbHelp {
            name: "trace",
            definition: "Walks the delegation from the root servers (or root_servers) to the \
                name, following referrals, and reports every server asked.",
            detail: Some(VerbDetail {
                usage: "resh dns://.trace name=<name> [rtype=<type>] [root_servers=<ip,...>]\n  \
                    [prefer_ipv6=true|false] [port=<n>] [use_tcp=true|false]\n  \
                    [timeout_ms=<ms>] [retries=<n>] [dnssec=true|false] [max_depth=<n>]\n  \
                    [follow_cname=true|false] [include_additional=true|false]\n  \
                    [want_raw=true|false] [format=json|text]",
                example: "resh dns://.trace name=www.example.com rtype=A",
                example_output: Some(
                    r#"{
  "error": null,
  "ok": true,
  "query": {
    "dnssec": false,
    "follow_cname": false,
    "include_additional": true,
    "max_depth": 15,
    "name": "www.example.com",
    "port": 53,
    "prefer_ipv6": false,
    "retries": 1,
    "root_servers": [],
    "rtype": "A",
    "timeout_ms": 3000,
    "use_tcp": false,
    "want_raw": false
  },
  "timestamp_unix_ms": 1792142364512,
  "trace": {
    "cname_chain": [],
    "depth": 3,
    "final_answers": [
      {
        "data": {
          "address": "192.0.2.10"
        },
        "name": "www.example.com.",
        "rtype": "A",
        "ttl": 300
      }
    ],
    "final_authoritative": true,
    "final_rcode": "NOERROR",
    "hops": [
      {
        "additional": [
          {
            "data": {
              "address": "192.0.2.1"
            },
            "name": "a.gtld-servers.net.",
            "rtype": "A",
            "ttl": 172800
          }
        ],
        "answers": [],
        "authoritative": false,
        "authority": [
          {
            "data": {
              "nsdname": "a.gtld-servers.net."
            },
            "name": "com.",
            "rtype": "NS",
            "ttl": 172800
          }
        ],
        "dnssec": {
          "ad_bit": false,
          "do_bit": false,
          "requested": false,
          "validated": null
        },
        "hop_index": 1,
        "ns_addresses": [
          {
            "family": "ipv4",
            "ip": "192.0.2.1",
            "name": "a.gtld-servers.net."
          }
        ],
        "ns_names": [
          "a.gtld-servers.net."
        ],
        "query_name": "www.example.com.",
        "query_rtype": "A",
        "raw": null,
        "rcode": "NOERROR",
        "rtt_ms": 12,
        "server_ip": "198.41.0.4",
        "server_name": "a.root-servers.net.",
        "truncated": false,
        "zone": "."
      }
    ],
    "name": "www.example.com.",
    "rtype": "A"
  },
  "warnings": []
}

The hops array is cut to the first (root) hop; the next hops ask the com.
and example.com. servers the referrals named."#,
                ),
            }),
        },
        VerbHelp {
            name: "zone.fetch",
            definition: "Transfers a zone with AXFR, or its changes since a serial with IXFR, \
                over TCP from the given or authoritative name servers.",
            detail: Some(VerbDetail {
                usage: "resh dns://.zone.fetch zone=<zone> [servers=<ip,...>] [port=<n>]\n  \
                    [transfer=AXFR|IXFR] [serial=<n>] [use_tcp=true]\n  \
                    [timeout_ms=<ms>] [retries=<n>] [dnssec=true|false]\n  \
                    [max_records=<n>] [prefer_ipv6=true|false]\n  \
                    [tsig_key_name=<name>] [tsig_secret=<base64>]\n  \
                    [tsig_algorithm=<alg>] [include_raw=true|false]\n  \
                    [format=json|text]",
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

The records array is cut to one entry. With transfer=IXFR an incremental
answer fills changes (old_serial, new_serial, deleted, added) instead."#,
                ),
            }),
        },
        VerbHelp {
            name: "zone.update",
            definition: "Sends an RFC 2136 dynamic DNS UPDATE (prerequisites, deletes and adds) \
                to the zone's server, optionally TSIG-signed, and reports the server's RCODE.",
            detail: Some(VerbDetail {
                usage: "resh dns://.zone.update zone=<zone> [adds=<json>] [deletes=<json>]\n  \
                    [prerequisites=<json>] [max_changes=<n>] [servers=<server,...>]\n  \
                    [port=<n>] [use_tcp=true|false] [timeout_ms=<ms>] [retries=<n>]\n  \
                    [tsig_key_name=<name>] [tsig_secret=<base64>]\n  \
                    [tsig_algorithm=<alg>] [dry_run=true|false]\n  \
                    [include_raw=true|false] [format=json|text]",
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

The adds argument is a JSON array of objects with name, rtype, ttl, and
data fields; data uses the same fields that lookup prints for that record
type. dry_run builds (and signs) the message but sends nothing."#,
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
    pub fn from_args(args: &Args) -> ArgResult<Self> {
        check_unknown("resolve", args)?;
        let name = required_str(args, "name", DNS_RESOLVE_INVALID_NAME)?.to_string();
        let mode = match args.get("mode") {
            None => ResolveMode::Host,
            Some(m) => ResolveMode::from_str(m).map_err(|_| {
                ArgError::new(
                    DNS_RESOLVE_INVALID_MODE,
                    format!("invalid mode: {m:?} (expected host, mail, service or reverse)"),
                )
            })?,
        };
        if mode == ResolveMode::Reverse {
            if !is_ip_address(&name) {
                return Err(ArgError::new(
                    DNS_RESOLVE_INVALID_NAME,
                    format!("mode=reverse needs an IP address as name, not {name:?}"),
                ));
            }
        } else {
            client::parse_name(&name).map_err(|e| ArgError::new(DNS_RESOLVE_INVALID_NAME, e))?;
        }
        let family = match args.get("family") {
            None => AddressFamily::Any,
            Some(f) => AddressFamily::from_str(f).map_err(|_| {
                ArgError::new(
                    DNS_RESOLVE_INVALID_FAMILY,
                    format!("invalid family: {f:?} (expected any, ipv4 or ipv6)"),
                )
            })?,
        };
        let validate_reverse = bool_opt(args, "validate_reverse", false)?;
        if validate_reverse && mode != ResolveMode::Reverse {
            return Err(ArgError::new(
                DNS_INVALID_ARGUMENT,
                "validate_reverse=true needs mode=reverse; nothing was done",
            ));
        }
        Ok(DnsResolveOptions {
            servers: ip_list(args, "servers", DNS_RESOLVE_INVALID_SERVER)?,
            port: uint_opt(args, "port", 53u16, 1, 65535, DNS_RESOLVE_INVALID_PORT)?,
            use_tcp: bool_opt(args, "use_tcp", false)?,
            timeout_ms: uint_opt(
                args,
                "timeout_ms",
                2000u64,
                1,
                MAX_TIMEOUT_MS,
                DNS_RESOLVE_INVALID_TIMEOUT,
            )?,
            retries: uint_opt(
                args,
                "retries",
                1u32,
                0,
                MAX_RETRIES,
                DNS_RESOLVE_INVALID_RETRIES,
            )?,
            dnssec: bool_opt(args, "dnssec", false)?,
            max_cname_depth: uint_opt(args, "max_cname_depth", 8u8, 0, 64, DNS_INVALID_ARGUMENT)?,
            want_raw: bool_opt(args, "want_raw", false)?,
            follow_srv: bool_opt(args, "follow_srv", true)?,
            validate_reverse,
            format: format_opt(args)?,
            name,
            mode,
            family,
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
    /// The failure was a timeout (exit 124). Not part of the output.
    #[serde(skip)]
    pub timed_out: bool,
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
    pub fn from_args(args: &Args) -> ArgResult<Self> {
        check_unknown("lookup", args)?;
        let name = required_str(args, "name", DNS_LOOKUP_INVALID_NAME)?.to_string();
        client::parse_name(&name).map_err(|e| ArgError::new(DNS_LOOKUP_INVALID_NAME, e))?;
        Ok(DnsLookupOptions {
            rtype: rtype_opt(args, DNS_LOOKUP_INVALID_TYPE)?,
            servers: ip_list(args, "servers", DNS_LOOKUP_INVALID_SERVER)?,
            port: uint_opt(args, "port", 53u16, 1, 65535, DNS_LOOKUP_INVALID_PORT)?,
            use_tcp: bool_opt(args, "use_tcp", false)?,
            timeout_ms: uint_opt(
                args,
                "timeout_ms",
                2000u64,
                1,
                MAX_TIMEOUT_MS,
                DNS_LOOKUP_INVALID_TIMEOUT,
            )?,
            retries: uint_opt(
                args,
                "retries",
                1u32,
                0,
                MAX_RETRIES,
                DNS_LOOKUP_INVALID_RETRIES,
            )?,
            dnssec: bool_opt(args, "dnssec", false)?,
            follow_cname: bool_opt(args, "follow_cname", true)?,
            include_authority: bool_opt(args, "include_authority", true)?,
            include_additional: bool_opt(args, "include_additional", true)?,
            randomize_servers: bool_opt(args, "randomize_servers", true)?,
            format: format_opt(args)?,
            name,
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
    /// The failure was a timeout (exit 124). Not part of the output.
    pub timed_out: bool,
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
            timed_out: false,
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
            timed_out: false,
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
    pub fn from_args(args: &Args) -> ArgResult<Self> {
        check_unknown("trace", args)?;
        let name = required_str(args, "name", DNS_TRACE_INVALID_NAME)?.to_string();
        client::parse_name(&name).map_err(|e| ArgError::new(DNS_TRACE_INVALID_NAME, e))?;
        Ok(DnsTraceOptions {
            rtype: rtype_opt(args, DNS_TRACE_INVALID_TYPE)?,
            root_servers: ip_list(args, "root_servers", DNS_TRACE_INVALID_ROOT_SERVER)?,
            port: uint_opt(args, "port", 53u16, 1, 65535, DNS_TRACE_INVALID_PORT)?,
            use_tcp: bool_opt(args, "use_tcp", false)?,
            timeout_ms: uint_opt(
                args,
                "timeout_ms",
                3000u64,
                1,
                MAX_TIMEOUT_MS,
                DNS_TRACE_INVALID_TIMEOUT,
            )?,
            retries: uint_opt(
                args,
                "retries",
                1u32,
                0,
                MAX_RETRIES,
                DNS_TRACE_INVALID_RETRIES,
            )?,
            dnssec: bool_opt(args, "dnssec", false)?,
            max_depth: uint_opt(args, "max_depth", 15u8, 1, 255, DNS_TRACE_INVALID_MAX_DEPTH)?,
            follow_cname: bool_opt(args, "follow_cname", false)?,
            prefer_ipv6: bool_opt(args, "prefer_ipv6", false)?,
            want_raw: bool_opt(args, "want_raw", false)?,
            include_additional: bool_opt(args, "include_additional", true)?,
            format: format_opt(args)?,
            name,
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
    /// The failure was a timeout (exit 124). Not part of the output.
    #[serde(skip)]
    pub timed_out: bool,
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
            timed_out: false,
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
/// A verb the handle does not have (exit 2).
pub const DNS_UNKNOWN_VERB: &str = "dns.unknown_verb";
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

fn rdata_to_json(rdata: &RData, _rtype: &str) -> Value {
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
            "flags": if caa.issuer_critical() { 128 } else { 0 },
            "tag": caa.tag().to_string(),
            "value": caa.value().to_string()
        }),
        // Other types (DNSKEY, RRSIG, NSEC, TLSA, ...): presentation format.
        other => json!({ "rdata": other.to_string() }),
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
                // `verb=<v>`, or the verb itself: `dns://.lookup(help=1)`.
                args.get("verb")
                    .map(|s| s.as_str())
                    .or_else(|| verb_options(verb).map(|_| verb))
            };

            return self.display_help(io, verb_specific);
        }

        match verb {
            "lookup" => self.verb_lookup(args, io),
            "resolve" => self.verb_resolve(args, io),
            "trace" => self.verb_trace(args, io),
            "zone.fetch" => self.verb_zone_fetch(args, io),
            "zone.update" => self.verb_zone_update(args, io),
            _ => Ok(Status::coded(
                crate::core::status::exit::USAGE,
                DNS_UNKNOWN_VERB,
                format!(
                    "unknown verb for dns://: {verb} (verbs: lookup, resolve, trace, zone.fetch, zone.update); nothing was done"
                ),
            )),
        }
    }
}

/// The status for a usage error: nothing was done (exit 2). The handle
/// does not write stderr itself; the shell prints `Error: [code] message`.
fn arg_status(e: ArgError) -> Status {
    Status::coded(exit::USAGE, e.code, e.message)
}

/// The status after a verb ran: 0 on success, 124 when it failed because
/// of a timeout (the outcome is unknown), 1 otherwise.
fn run_status(ok: bool, error: &Option<(String, String)>, timed_out: bool) -> Status {
    if ok {
        return Status::ok();
    }
    let exit = if timed_out {
        exit::TIMEOUT
    } else {
        exit::FAILED
    };
    match error {
        Some((code, message)) => Status::coded(exit, code, message),
        None => Status::err(exit, "the dns operation failed"),
    }
}

/// Runs a future on a single-threaded runtime.
fn run_async<F: std::future::Future>(f: F) -> Result<F::Output> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;
    Ok(rt.block_on(f))
}

impl DnsHandle {
    fn verb_lookup(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let opts = match DnsLookupOptions::from_args(args) {
            Ok(o) => o,
            Err(e) => return Ok(arg_status(e)),
        };
        let response = run_async(query::perform_dns_lookup(&opts))?;
        let output = match opts.format {
            OutputFormat::Json => serde_json::to_string_pretty(&response.to_json())?,
            OutputFormat::Text => response.to_text(),
        };
        writeln!(io.stdout, "{}", output)?;
        Ok(run_status(response.ok, &response.error, response.timed_out))
    }

    fn verb_resolve(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let opts = match DnsResolveOptions::from_args(args) {
            Ok(o) => o,
            Err(e) => return Ok(arg_status(e)),
        };
        let response = run_async(query::perform_dns_resolve(&opts))?;
        let output = match opts.format {
            OutputFormat::Json => serde_json::to_string_pretty(&response.to_json())?,
            OutputFormat::Text => response.to_text(),
        };
        writeln!(io.stdout, "{}", output)?;
        Ok(run_status(response.ok, &response.error, response.timed_out))
    }

    fn verb_trace(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let opts = match DnsTraceOptions::from_args(args) {
            Ok(o) => o,
            Err(e) => return Ok(arg_status(e)),
        };
        let response = run_async(query::perform_dns_trace(&opts))?;
        let output = match opts.format {
            OutputFormat::Json => serde_json::to_string_pretty(&response.to_json())?,
            OutputFormat::Text => response.to_text(),
        };
        writeln!(io.stdout, "{}", output)?;
        Ok(run_status(response.ok, &response.error, response.timed_out))
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
    pub fn from_args(args: &Args) -> ArgResult<Self> {
        check_unknown("zone.fetch", args)?;
        let zone = required_str(args, "zone", DNS_ZONE_FETCH_INVALID_ZONE)?.to_string();
        client::parse_name(&zone).map_err(|e| ArgError::new(DNS_ZONE_FETCH_INVALID_ZONE, e))?;
        let transfer = match args.get("transfer") {
            None => ZoneTransferType::Axfr,
            Some(t) => ZoneTransferType::from_str(t).map_err(|_| {
                ArgError::new(
                    DNS_ZONE_FETCH_INVALID_TRANSFER_TYPE,
                    format!("invalid transfer: {t:?} (expected AXFR or IXFR)"),
                )
            })?,
        };
        let serial = match args.get("serial") {
            None => None,
            Some(_) => Some(uint_opt(
                args,
                "serial",
                0u32,
                0,
                u64::from(u32::MAX),
                DNS_INVALID_ARGUMENT,
            )?),
        };
        match (&transfer, serial) {
            (ZoneTransferType::Ixfr, None) => {
                return Err(ArgError::new(
                    DNS_ZONE_FETCH_MISSING_SERIAL,
                    "transfer=IXFR needs serial=<n> (the serial the client already has)",
                ));
            }
            (ZoneTransferType::Axfr, Some(_)) => {
                return Err(ArgError::new(
                    DNS_INVALID_ARGUMENT,
                    "serial is only used with transfer=IXFR",
                ));
            }
            _ => {}
        }
        if !bool_opt(args, "use_tcp", true)? {
            return Err(ArgError::new(
                DNS_ZONE_FETCH_TCP_REQUIRED,
                "zone transfers always use TCP; use_tcp=false is not supported",
            ));
        }
        let (tsig_key_name, tsig_secret, tsig_algorithm) = tsig_args(
            args,
            DNS_ZONE_FETCH_INVALID_TSIG_CONFIG,
            DNS_ZONE_FETCH_INVALID_TSIG_SECRET,
            DNS_ZONE_FETCH_UNSUPPORTED_TSIG_ALGORITHM,
        )?;
        Ok(DnsZoneFetchOptions {
            servers: ip_list(args, "servers", DNS_ZONE_FETCH_INVALID_SERVER)?,
            port: uint_opt(args, "port", 53u16, 1, 65535, DNS_ZONE_FETCH_INVALID_PORT)?,
            use_tcp: true,
            timeout_ms: uint_opt(
                args,
                "timeout_ms",
                5000u64,
                1,
                MAX_TIMEOUT_MS,
                DNS_ZONE_FETCH_INVALID_TIMEOUT,
            )?,
            retries: uint_opt(
                args,
                "retries",
                1u32,
                0,
                MAX_RETRIES,
                DNS_ZONE_FETCH_INVALID_RETRIES,
            )?,
            dnssec: bool_opt(args, "dnssec", false)?,
            max_records: uint_opt(
                args,
                "max_records",
                1_000_000u64,
                1,
                u64::MAX,
                DNS_ZONE_FETCH_INVALID_MAX_RECORDS,
            )?,
            include_raw: bool_opt(args, "include_raw", false)?,
            prefer_ipv6: bool_opt(args, "prefer_ipv6", false)?,
            format: format_opt(args)?,
            tsig_key_name,
            tsig_secret,
            tsig_algorithm,
            zone,
            transfer,
            serial,
        })
    }
}

/// Upper bound for `timeout_ms` (one hour).
const MAX_TIMEOUT_MS: u64 = 3_600_000;
/// Upper bound for `retries`.
const MAX_RETRIES: u64 = 100;

/// `rtype=` (default A).
fn rtype_opt(args: &Args, code: &'static str) -> ArgResult<DnsRecordType> {
    match args.get("rtype") {
        None => Ok(DnsRecordType::A),
        Some(t) => DnsRecordType::from_str(t).map_err(|_| {
            ArgError::new(
                code,
                format!(
                    "invalid rtype: {t:?} (expected A, AAAA, TXT, CNAME, MX, NS, SRV, PTR, \
                     SOA, CAA or ANY)"
                ),
            )
        }),
    }
}

/// The TSIG options: key name and secret together or neither, a non-empty
/// base64 secret, a known algorithm (and no algorithm without a key).
fn tsig_args(
    args: &Args,
    config_code: &'static str,
    secret_code: &'static str,
    algorithm_code: &'static str,
) -> ArgResult<(Option<String>, Option<String>, Option<String>)> {
    let name = args.get("tsig_key_name").cloned();
    let secret = args.get("tsig_secret").cloned();
    let algorithm = args.get("tsig_algorithm").cloned();
    match (&name, &secret) {
        (Some(_), None) | (None, Some(_)) => {
            return Err(ArgError::new(
                config_code,
                "TSIG requires both tsig_key_name and tsig_secret",
            ));
        }
        (None, None) if algorithm.is_some() => {
            return Err(ArgError::new(
                config_code,
                "tsig_algorithm needs tsig_key_name and tsig_secret",
            ));
        }
        _ => {}
    }
    if let Some(n) = &name {
        client::parse_name(n)
            .map_err(|e| ArgError::new(config_code, format!("invalid tsig_key_name: {e}")))?;
    }
    if let Some(s) = &secret {
        match general_purpose::STANDARD.decode(s) {
            Ok(bytes) if !bytes.is_empty() => {}
            _ => {
                return Err(ArgError::new(
                    secret_code,
                    "TSIG secret must be valid, non-empty base64",
                ));
            }
        }
    }
    if let Some(a) = &algorithm {
        if TsigAlgorithm::from_option(a).is_none() {
            return Err(ArgError::new(
                algorithm_code,
                format!(
                    "unsupported tsig_algorithm: {a:?} (expected hmac-sha1, hmac-sha256, \
                     hmac-sha384 or hmac-sha512)"
                ),
            ));
        }
    }
    Ok((name, secret, algorithm))
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
    #[serde(with = "error_object")]
    pub error: Option<(String, String)>,
    pub warnings: Vec<String>,
    /// The failure was a timeout (exit 124). Not part of the output.
    #[serde(skip)]
    pub timed_out: bool,
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
            timed_out: false,
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

/// The host's own resolvers. There is no fallback: a query sent to a public
/// resolver instead would leak the name and answer for a different view.
pub(crate) fn system_resolver_config() -> Result<ResolverConfig> {
    let (config, _) = trust_dns_resolver::system_conf::read_system_conf()
        .context("failed to read the system resolver configuration")?;
    Ok(config)
}

impl DnsHandle {
    fn verb_zone_fetch(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let opts = match DnsZoneFetchOptions::from_args(args) {
            Ok(o) => o,
            Err(e) => return Ok(arg_status(e)),
        };
        let key = match TsigKey::from_parts(
            opts.tsig_key_name.as_deref(),
            opts.tsig_secret.as_deref(),
            opts.tsig_algorithm.as_deref(),
            [
                DNS_ZONE_FETCH_INVALID_TSIG_CONFIG,
                DNS_ZONE_FETCH_INVALID_TSIG_SECRET,
                DNS_ZONE_FETCH_UNSUPPORTED_TSIG_ALGORITHM,
            ],
        ) {
            Ok(k) => k,
            Err((code, message)) => return Ok(Status::coded(exit::USAGE, &code, message)),
        };
        let response = run_async(xfr::perform_zone_fetch(&opts, key.as_ref()))?;
        let output = match opts.format {
            OutputFormat::Json => response.to_json(),
            OutputFormat::Text => response.to_text(),
        };
        writeln!(io.stdout, "{}", output)?;
        Ok(run_status(response.ok, &response.error, response.timed_out))
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
    pub fn from_args(args: &Args) -> ArgResult<Self> {
        check_unknown("zone.update", args)?;
        let zone = required_str(args, "zone", DNS_ZONE_UPDATE_INVALID_ZONE)?.to_string();
        client::parse_name(&zone).map_err(|e| ArgError::new(DNS_ZONE_UPDATE_INVALID_ZONE, e))?;
        let servers = server_list(args, "servers", DNS_ZONE_UPDATE_INVALID_SERVER)?;
        for s in &servers {
            let bare = s.trim_start_matches('[').trim_end_matches(']');
            let ok = s.parse::<SocketAddr>().is_ok()
                || bare.parse::<IpAddr>().is_ok()
                || (s
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                    && client::parse_name(s).is_ok());
            if !ok {
                return Err(ArgError::new(
                    DNS_ZONE_UPDATE_INVALID_SERVER,
                    format!("invalid servers entry: {s:?} (expected an IP, IP:port or host name)"),
                ));
            }
        }
        let (tsig_key_name, tsig_secret, tsig_algorithm) = tsig_args(
            args,
            DNS_ZONE_UPDATE_INVALID_TSIG_CONFIG,
            DNS_ZONE_UPDATE_INVALID_TSIG_SECRET,
            DNS_ZONE_UPDATE_UNSUPPORTED_TSIG_ALGORITHM,
        )?;
        let json_list = |key: &str, code: &'static str| -> ArgResult<Option<&String>> {
            match args.get(key) {
                Some(v) if v.trim().is_empty() => {
                    Err(ArgError::new(code, format!("{key} must be a JSON array")))
                }
                other => Ok(other),
            }
        };
        let prerequisites: Vec<ZoneUpdatePrerequisite> =
            match json_list("prerequisites", DNS_ZONE_UPDATE_INVALID_PREREQUISITE)? {
                None => Vec::new(),
                Some(v) => serde_json::from_str(v).map_err(|e| {
                    ArgError::new(
                        DNS_ZONE_UPDATE_INVALID_PREREQUISITE,
                        format!("invalid prerequisites JSON: {e}"),
                    )
                })?,
            };
        for prereq in &prerequisites {
            let kind = ZoneUpdatePrerequisiteKind::from_str(&prereq.kind).map_err(|_| {
                ArgError::new(
                    DNS_ZONE_UPDATE_INVALID_PREREQUISITE,
                    format!("invalid prerequisite kind: {:?}", prereq.kind),
                )
            })?;
            match kind {
                ZoneUpdatePrerequisiteKind::ZoneSerialAtLeast if prereq.serial.is_none() => {
                    return Err(ArgError::new(
                        DNS_ZONE_UPDATE_INVALID_PREREQUISITE,
                        "prerequisite zone_serial_at_least requires a serial field",
                    ));
                }
                ZoneUpdatePrerequisiteKind::ZoneSerialAtLeast => {}
                _ if prereq.name.as_deref().is_none_or(|n| n.trim().is_empty()) => {
                    return Err(ArgError::new(
                        DNS_ZONE_UPDATE_INVALID_PREREQUISITE,
                        format!("prerequisite {} requires a name field", prereq.kind),
                    ));
                }
                _ => {}
            }
        }
        let adds: Vec<ZoneUpdateAdd> = match json_list("adds", DNS_ZONE_UPDATE_INVALID_ADD_RECORD)?
        {
            None => Vec::new(),
            Some(v) => serde_json::from_str(v).map_err(|e| {
                ArgError::new(
                    DNS_ZONE_UPDATE_INVALID_ADD_RECORD,
                    format!("invalid adds JSON: {e}"),
                )
            })?,
        };
        for add in &adds {
            if add.name.trim().is_empty() {
                return Err(ArgError::new(
                    DNS_ZONE_UPDATE_INVALID_ADD_RECORD,
                    "add record name cannot be empty",
                ));
            }
            DnsRecordType::from_str(&add.rtype).map_err(|_| {
                ArgError::new(
                    DNS_ZONE_UPDATE_INVALID_RECORD_TYPE,
                    format!("invalid record type in add: {:?}", add.rtype),
                )
            })?;
        }
        let deletes: Vec<ZoneUpdateDelete> =
            match json_list("deletes", DNS_ZONE_UPDATE_INVALID_DELETE_SPEC)? {
                None => Vec::new(),
                Some(v) => serde_json::from_str(v).map_err(|e| {
                    ArgError::new(
                        DNS_ZONE_UPDATE_INVALID_DELETE_SPEC,
                        format!("invalid deletes JSON: {e}"),
                    )
                })?,
            };
        for delete in &deletes {
            let bad = |m: &str| Err(ArgError::new(DNS_ZONE_UPDATE_INVALID_DELETE_SPEC, m));
            if delete.name.trim().is_empty() {
                return bad("delete record name cannot be empty");
            }
            if delete.delete_all.unwrap_or(false) {
                if delete.data.is_some() {
                    return bad("a delete with delete_all=true must not specify data");
                }
            } else {
                if delete.rtype.is_none() {
                    return bad("a delete without delete_all must specify rtype");
                }
                if delete.data.is_none() {
                    return bad("a delete without delete_all must specify data");
                }
            }
            if let Some(rtype) = &delete.rtype {
                DnsRecordType::from_str(rtype).map_err(|_| {
                    ArgError::new(
                        DNS_ZONE_UPDATE_INVALID_RECORD_TYPE,
                        format!("invalid record type in delete: {rtype:?}"),
                    )
                })?;
            }
        }
        let max_changes = uint_opt(
            args,
            "max_changes",
            1000u32,
            1,
            u64::from(u32::MAX),
            DNS_ZONE_UPDATE_INVALID_MAX_CHANGES,
        )?;
        let total = adds.len() + deletes.len();
        if total > max_changes as usize {
            return Err(ArgError::new(
                DNS_ZONE_UPDATE_INVALID_MAX_CHANGES,
                format!("total changes ({total}) exceed max_changes ({max_changes})"),
            ));
        }
        let dry_run = crate::core::lenient::dry_run(args)
            .map_err(|e| ArgError::new(DNS_INVALID_ARGUMENT, e.to_string()))?;
        Ok(DnsZoneUpdateOptions {
            port: uint_opt(args, "port", 53u16, 1, 65535, DNS_ZONE_UPDATE_INVALID_PORT)?,
            use_tcp: bool_opt(args, "use_tcp", true)?,
            timeout_ms: uint_opt(
                args,
                "timeout_ms",
                3000u64,
                1,
                MAX_TIMEOUT_MS,
                DNS_ZONE_UPDATE_INVALID_TIMEOUT,
            )?,
            retries: uint_opt(
                args,
                "retries",
                1u32,
                0,
                MAX_RETRIES,
                DNS_ZONE_UPDATE_INVALID_RETRIES,
            )?,
            include_raw: bool_opt(args, "include_raw", false)?,
            format: format_opt(args)?,
            zone,
            servers,
            tsig_key_name,
            tsig_secret,
            tsig_algorithm,
            prerequisites,
            adds,
            deletes,
            max_changes,
            dry_run,
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
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "error_object",
        default
    )]
    pub error: Option<(String, String)>,
    pub warnings: Vec<String>,
    /// The failure was a timeout (exit 124). Not part of the output.
    #[serde(skip)]
    pub timed_out: bool,
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
            timed_out: false,
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
    let mut discovery_warnings = Vec::new();
    let found = resolve_target_servers(&opts, &mut discovery_warnings).await;
    response.warnings.extend(discovery_warnings);
    let servers = match found {
        Ok(servers) => servers,
        Err(e) => {
            response.ok = false;
            response.error = Some((DNS_ZONE_UPDATE_ALL_SERVERS_FAILED.to_string(), e));
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
    response.timed_out = !failures.is_empty() && failures.iter().all(|f| f.timeout);
    response.error = Some(match failures.len() {
        0 => (
            DNS_ZONE_UPDATE_ALL_SERVERS_FAILED.to_string(),
            "No target servers".to_string(),
        ),
        1 => {
            let e = failures.remove(0);
            (e.update_code().to_string(), e.message)
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

// The servers to send the update to: the given ones, or the zone's
// authoritative servers found through the system resolvers.
async fn resolve_target_servers(
    opts: &DnsZoneUpdateOptions,
    warnings: &mut Vec<String>,
) -> std::result::Result<Vec<String>, String> {
    if !opts.servers.is_empty() {
        return Ok(opts.servers.clone());
    }
    let zone = client::parse_name(&opts.zone)?;
    xfr::discover_with_system(&zone, opts.timeout_ms, false, warnings).await
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
    timeout: bool,
    message: String,
}

impl ExchangeError {
    fn timeout(message: impl Into<String>) -> Self {
        Self {
            timeout: true,
            message: message.into(),
        }
    }

    fn network(message: impl Into<String>) -> Self {
        Self {
            timeout: false,
            message: message.into(),
        }
    }

    fn update_code(&self) -> &'static str {
        if self.timeout {
            DNS_ZONE_UPDATE_TIMEOUT
        } else {
            DNS_ZONE_UPDATE_NETWORK_ERROR
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
        Self::from_parts(
            opts.tsig_key_name.as_deref(),
            opts.tsig_secret.as_deref(),
            opts.tsig_algorithm.as_deref(),
            [
                DNS_ZONE_UPDATE_INVALID_TSIG_CONFIG,
                DNS_ZONE_UPDATE_INVALID_TSIG_SECRET,
                DNS_ZONE_UPDATE_UNSUPPORTED_TSIG_ALGORITHM,
            ],
        )
    }

    // A key from its name, base64 secret and algorithm option. `codes` are
    // the verb's codes for a bad key name, a bad secret and an unsupported
    // algorithm. No name and no secret means no key.
    fn from_parts(
        key_name: Option<&str>,
        secret: Option<&str>,
        algorithm: Option<&str>,
        codes: [&'static str; 3],
    ) -> std::result::Result<Option<Self>, (String, String)> {
        let [config_code, secret_code, algorithm_code] = codes;
        let (key_name, secret) = match (key_name, secret) {
            (Some(name), Some(secret)) => (name, secret),
            (None, None) => return Ok(None),
            _ => {
                return Err((
                    config_code.to_string(),
                    "TSIG requires both tsig_key_name and tsig_secret".to_string(),
                ));
            }
        };
        let secret = match general_purpose::STANDARD.decode(secret) {
            Ok(s) if !s.is_empty() => s,
            _ => {
                return Err((
                    secret_code.to_string(),
                    "TSIG secret must be valid, non-empty base64".to_string(),
                ));
            }
        };
        let name = Name::from_str(&normalize_dns_name(key_name)).map_err(|e| {
            (
                config_code.to_string(),
                format!("Invalid TSIG key name {}: {}", key_name, e),
            )
        })?;
        let algorithm_name = algorithm.unwrap_or("hmac-sha256");
        let algorithm = TsigAlgorithm::from_option(algorithm_name).ok_or_else(|| {
            (
                algorithm_code.to_string(),
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
    verify_tsig(stripped, tsig, key, request_mac, &[], false, now)
}

// Verify one signed reply message. The MAC input is the prior MAC (the
// request MAC for the first message), `unsigned_before` (the unsigned
// messages since the last signed one in a multi-message reply), this
// message with its original ID, and either the full TSIG variables (first
// message) or only the timers (later messages, RFC 8945 section 5.3.1).
fn verify_tsig(
    stripped: &[u8],
    tsig: &TsigRecord,
    key: &TsigKey,
    prior_mac: &[u8],
    unsigned_before: &[u8],
    timers_only: bool,
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
    if stripped.len() < 12 {
        return Err("reply shorter than a DNS header".to_string());
    }
    let mut message = stripped.to_vec();
    message[0..2].copy_from_slice(&tsig.original_id.to_be_bytes());
    let mut mac_input =
        Vec::with_capacity(message.len() + unsigned_before.len() + prior_mac.len() + 64);
    mac_input.extend_from_slice(&(prior_mac.len() as u16).to_be_bytes());
    mac_input.extend_from_slice(prior_mac);
    mac_input.extend_from_slice(unsigned_before);
    mac_input.extend_from_slice(&message);
    if timers_only {
        mac_input.extend_from_slice(&tsig.time_signed.to_be_bytes()[2..8]);
        mac_input.extend_from_slice(&tsig.fudge.to_be_bytes());
    } else {
        mac_input.extend_from_slice(&tsig_variables(
            key,
            tsig.time_signed,
            tsig.fudge,
            tsig.error,
            &tsig.other,
        ));
    }
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
        let opts = match DnsZoneUpdateOptions::from_args(args) {
            Ok(o) => o,
            Err(e) => return Ok(arg_status(e)),
        };
        let response = run_async(perform_zone_update(opts.clone()))??;
        let output = match opts.format {
            OutputFormat::Json => response.to_json(),
            OutputFormat::Text => response.to_text(),
        };
        writeln!(io.stdout, "{}", output)?;
        let mut status = run_status(response.ok, &response.error, response.timed_out);
        // Input found invalid while building the message: nothing was sent.
        if let Some((code, _)) = &response.error {
            if is_zone_update_input_error(code) {
                status.code = Some(exit::USAGE);
            }
        }
        Ok(status)
    }
}

/// Error codes of `zone.update` that mean the input was invalid (exit 2).
fn is_zone_update_input_error(code: &str) -> bool {
    [
        DNS_ZONE_UPDATE_INVALID_ZONE,
        DNS_ZONE_UPDATE_INVALID_MAX_CHANGES,
        DNS_ZONE_UPDATE_INVALID_RECORD_TYPE,
        DNS_ZONE_UPDATE_INVALID_ADD_RECORD,
        DNS_ZONE_UPDATE_INVALID_DELETE_SPEC,
        DNS_ZONE_UPDATE_INVALID_PREREQUISITE,
        DNS_ZONE_UPDATE_INVALID_TSIG_CONFIG,
        DNS_ZONE_UPDATE_INVALID_TSIG_SECRET,
        DNS_ZONE_UPDATE_UNSUPPORTED_TSIG_ALGORITHM,
    ]
    .contains(&code)
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
        run.json.as_ref().unwrap()["error"]["code"]
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
            let msg = run.json.as_ref().unwrap()["error"]["message"]
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
        assert_eq!(run.status.exit_code(), 2);
        assert_eq!(error_code(&run), DNS_ZONE_UPDATE_INVALID_ADD_RECORD);
        assert!(
            run.json.unwrap()["error"]["message"]
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
        assert_eq!(run.status.exit_code(), 124);
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
        assert_eq!(run.status.exit_code(), 124);
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
            assert_eq!(run.status.exit_code(), 2, "{code}");
            assert!(run.json.is_none(), "{code}");
            let reason = run.status.reason.clone().unwrap_or_default();
            assert!(
                reason.starts_with(&format!("[{}] ", code)),
                "{code}: {reason}"
            );
        }
        let run = run_verb(&[
            ("zone", "example.com"),
            ("tsig_key_name", "tsig-key.example"),
            ("tsig_secret", KEY_B64),
            ("tsig_algorithm", "hmac-md5"),
        ]);
        assert_eq!(run.status.exit_code(), 2);
        assert!(
            run.status
                .reason
                .unwrap()
                .starts_with(&format!("[{}]", DNS_ZONE_UPDATE_UNSUPPORTED_TSIG_ALGORITHM))
        );

        // Validation errors: JSON with ok=false, exit 2, nothing sent
        let server = FakeServer::start(responder(|_, req, _| {
            vec![reply(req, ResponseCode::NoError)]
        }));
        let port = server.port.to_string();
        let cases: [(&str, &str, &str); 5] = [
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
            assert_eq!(run.status.exit_code(), 2, "{code}");
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
