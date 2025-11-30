use anyhow::{Context, Result, bail};
use if_addrs;
use serde_json::json;
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs, SocketAddr, IpAddr};
use std::process::Command;
use std::time::{Duration, Instant};
use std::sync::{Arc, mpsc, Mutex};
use std::thread;
use url::Url;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol},
    TokioAsyncResolver
};
use trust_dns_resolver::proto::rr::{RData, RecordType as TrustDnsRecordType};

use crate::core::{
    registry::{Args, Handle, IoStreams},
    status::Status,
};

// DNS-related types and traits

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
            _ => bail!("Unknown record type: {}", s),
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
    MX { priority: u16, exchange: String },
    TXT(String),
    NS(String),
    SRV { priority: u16, weight: u16, port: u16, target: String },
    PTR(String),
}

pub type ResolvedRecords = Vec<ResolvedRecord>;

pub trait DnsResolver: Send + Sync {
    fn lookup(&self, name: &str, rtype: RecordType, server: Option<SocketAddr>, timeout: Duration) -> Result<ResolvedRecords>;
}

// System DNS resolver implementation
pub struct SystemDnsResolver;

impl SystemDnsResolver {
    pub fn new() -> Self {
        Self
    }
}

impl DnsResolver for SystemDnsResolver {
    fn lookup(&self, name: &str, rtype: RecordType, server: Option<SocketAddr>, timeout: Duration) -> Result<ResolvedRecords> {
        let rt = tokio::runtime::Runtime::new()
            .context("Failed to create Tokio runtime")?;

        rt.block_on(async {
            let resolver = if let Some(server_addr) = server {
                // Create resolver with custom server
                let nameserver = NameServerConfig::new(server_addr, Protocol::Udp);
                let mut config = ResolverConfig::new();
                config.add_name_server(nameserver);
                let mut opts = ResolverOpts::default();
                opts.timeout = timeout;
                TokioAsyncResolver::tokio(config, opts)
            } else {
                // Use system resolver
                let mut opts = ResolverOpts::default();
                opts.timeout = timeout;
                TokioAsyncResolver::tokio(ResolverConfig::default(), opts)
            };

            self.perform_lookup(&resolver, name, rtype).await
        })
    }
}

impl SystemDnsResolver {
    async fn perform_lookup(&self, resolver: &TokioAsyncResolver, name: &str, rtype: RecordType) -> Result<ResolvedRecords> {
        match rtype {
            RecordType::A => {
                let response = resolver.ipv4_lookup(name).await
                    .context("A record lookup failed")?;
                Ok(response.iter().map(|ip| ResolvedRecord {
                    name: name.to_string(),
                    ttl: 300, // Default TTL fallback
                    kind: ResolvedKind::A(ip.to_string()),
                }).collect())
            },
            RecordType::AAAA => {
                let response = resolver.ipv6_lookup(name).await
                    .context("AAAA record lookup failed")?;
                Ok(response.iter().map(|ip| ResolvedRecord {
                    name: name.to_string(),
                    ttl: 300, // Default TTL fallback
                    kind: ResolvedKind::AAAA(ip.to_string()),
                }).collect())
            },
            RecordType::CNAME => {
                let response = resolver.lookup(name, rtype.to_trust_dns()).await
                    .context("CNAME record lookup failed")?;
                let mut records = Vec::new();
                for record in response.records() {
                    if let Some(RData::CNAME(cname)) = record.data() {
                        records.push(ResolvedRecord {
                            name: record.name().to_string(),
                            ttl: record.ttl(),
                            kind: ResolvedKind::CNAME(cname.to_string()),
                        });
                    }
                }
                Ok(records)
            },
            RecordType::MX => {
                let response = resolver.mx_lookup(name).await
                    .context("MX record lookup failed")?;
                Ok(response.iter().map(|mx| ResolvedRecord {
                    name: name.to_string(),
                    ttl: 300, // Default TTL fallback
                    kind: ResolvedKind::MX {
                        priority: mx.preference(),
                        exchange: mx.exchange().to_string(),
                    },
                }).collect())
            },
            RecordType::TXT => {
                let response = resolver.txt_lookup(name).await
                    .context("TXT record lookup failed")?;
                Ok(response.iter().map(|txt| ResolvedRecord {
                    name: name.to_string(),
                    ttl: 300, // Default TTL fallback
                    kind: ResolvedKind::TXT(
                        txt.txt_data().iter()
                           .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                           .collect::<Vec<_>>()
                           .join("")
                    ),
                }).collect())
            },
            RecordType::NS => {
                let response = resolver.lookup(name, rtype.to_trust_dns()).await
                    .context("NS record lookup failed")?;
                let mut records = Vec::new();
                for record in response.records() {
                    if let Some(RData::NS(ns)) = record.data() {
                        records.push(ResolvedRecord {
                            name: record.name().to_string(),
                            ttl: record.ttl(),
                            kind: ResolvedKind::NS(ns.to_string()),
                        });
                    }
                }
                Ok(records)
            },
            RecordType::SRV => {
                let response = resolver.lookup(name, rtype.to_trust_dns()).await
                    .context("SRV record lookup failed")?;
                let mut records = Vec::new();
                for record in response.records() {
                    if let Some(RData::SRV(srv)) = record.data() {
                        records.push(ResolvedRecord {
                            name: record.name().to_string(),
                            ttl: record.ttl(),
                            kind: ResolvedKind::SRV {
                                priority: srv.priority(),
                                weight: srv.weight(),
                                port: srv.port(),
                                target: srv.target().to_string(),
                            },
                        });
                    }
                }
                Ok(records)
            },
            RecordType::PTR => {
                // For PTR records, try to parse as IP and do reverse lookup
                if let Ok(ip) = name.parse::<IpAddr>() {
                    let response = resolver.reverse_lookup(ip).await
                        .context("PTR record lookup failed")?;
                    Ok(response.iter().map(|ptr| ResolvedRecord {
                        name: name.to_string(),
                        ttl: 300, // Default TTL fallback
                        kind: ResolvedKind::PTR(ptr.to_string()),
                    }).collect())
                } else {
                    bail!("PTR lookup requires a valid IP address, got: {}", name);
                }
            },
        }
    }
}

pub struct NetHandle {
    resource: String, // e.g., "if", "interfaces", or host for ping/tcp_check
    host: Option<String>,
    port: Option<u16>,
    resolver: Arc<dyn DnsResolver>,
}

impl NetHandle {
    pub fn from_url(u: &Url) -> Result<Self> {
        // Extract host from URL
        let host = u.host_str()
            .ok_or_else(|| anyhow::anyhow!("net:// URL missing host"))?
            .to_string();
        let port = u.port();
        
        // For backwards compatibility with existing functionality:
        // If host looks like a special resource name, treat it as such
        let (resource, actual_host) = if host == "if" || host == "interfaces" || host == "iface" {
            (host.clone(), None)
        } else {
            // This is a host specification for ping/tcp_check/dns
            (host.clone(), Some(host.clone()))
        };

        Ok(NetHandle { 
            resource, 
            host: actual_host, 
            port, 
            resolver: Arc::new(SystemDnsResolver::new()) 
        })
    }

    // Constructor for tests with custom resolver
    #[allow(dead_code)]
    pub fn with_resolver(target: String, resolver: Arc<dyn DnsResolver>) -> Self {
        NetHandle {
            resource: target.clone(),
            host: Some(target),
            port: None,
            resolver,
        }
    }

    fn target(&self) -> String {
        if let (Some(host), Some(port)) = (&self.host, self.port) {
            format!("{}:{}", host, port)
        } else if let Some(host) = &self.host {
            host.clone()
        } else {
            self.resource.clone()
        }
    }

    // Extract domain name from URL for DNS queries
    fn extract_dns_query_name(&self) -> Result<String> {
        // For DNS queries, we use the resource as the query name
        // but we need to handle the case where the resource ends with .dns
        let query_name = if self.resource.ends_with(".dns") {
            self.resource.strip_suffix(".dns").unwrap_or(&self.resource)
        } else {
            &self.resource
        };

        if query_name.is_empty() || query_name == "if" || query_name == "interfaces" {
            bail!("No valid domain name or IP provided for DNS query");
        }

        Ok(query_name.to_string())
    }
}

impl Handle for NetHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["list", "ping", "tcp_check", "scan", "dns", "route.list"]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        match verb {
            "list" => list_interfaces(args, io),
            "ping" => self.verb_ping(args, io),
            "tcp_check" => self.verb_tcp_check(args, io),
            "scan" => self.scan(args, io),
            "dns" => self.call_dns(args, io),
            "route.list" => self.route_list(args, io),
            _ => bail!("unknown verb for net://: {}", verb),
        }
    }
}

impl NetHandle {
    fn call_dns(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let query_name = match self.extract_dns_query_name() {
            Ok(name) => name,
            Err(e) => {
                let error_json = json!({
                    "query": self.resource,
                    "error": "invalid_query",
                    "detail": format!("{}", e)
                });
                writeln!(io.stdout, "{}", error_json)?;
                return Ok(Status::err(2, format!("Invalid query: {}", e)));
            }
        };

        // Parse record type
        let rtype = match args.get("type").map(|s| s.as_str()).unwrap_or("A") {
            type_str => match RecordType::from_str(type_str) {
                Ok(rt) => rt,
                Err(e) => {
                    let error_json = json!({
                        "query": query_name,
                        "rtype": type_str,
                        "error": "invalid_type",
                        "detail": format!("{}", e)
                    });
                    writeln!(io.stdout, "{}", error_json)?;
                    return Ok(Status::err(2, format!("Invalid record type: {}", e)));
                }
            }
        };

        // Parse timeout
        let timeout = match args.get("timeout_ms") {
            Some(timeout_str) => match timeout_str.parse::<u64>() {
                Ok(ms) if ms > 0 => Duration::from_millis(ms),
                Ok(_) => {
                    let error_json = json!({
                        "query": query_name,
                        "rtype": rtype.as_str(),
                        "error": "invalid_timeout",
                        "detail": "Timeout must be positive"
                    });
                    writeln!(io.stdout, "{}", error_json)?;
                    return Ok(Status::err(2, "Timeout must be positive"));
                }
                Err(e) => {
                    let error_json = json!({
                        "query": query_name,
                        "rtype": rtype.as_str(),
                        "error": "invalid_timeout",
                        "detail": format!("Cannot parse timeout: {}", e)
                    });
                    writeln!(io.stdout, "{}", error_json)?;
                    return Ok(Status::err(2, format!("Invalid timeout: {}", e)));
                }
            },
            None => Duration::from_millis(3000), // Default 3 seconds
        };

        // Parse DNS server
        let server = match args.get("server") {
            Some(server_str) => {
                match server_str.parse::<IpAddr>() {
                    Ok(ip) => {
                        let port = match args.get("port") {
                            Some(port_str) => match port_str.parse::<u16>() {
                                Ok(p) => p,
                                Err(e) => {
                                    let error_json = json!({
                                        "query": query_name,
                                        "rtype": rtype.as_str(),
                                        "error": "invalid_port",
                                        "detail": format!("Cannot parse port: {}", e)
                                    });
                                    writeln!(io.stdout, "{}", error_json)?;
                                    return Ok(Status::err(2, format!("Invalid port: {}", e)));
                                }
                            },
                            None => 53, // Default DNS port
                        };
                        Some(SocketAddr::new(ip, port))
                    },
                    Err(e) => {
                        let error_json = json!({
                            "query": query_name,
                            "rtype": rtype.as_str(),
                            "error": "invalid_server",
                            "detail": format!("Cannot parse server IP: {}", e)
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        return Ok(Status::err(2, format!("Invalid server IP: {}", e)));
                    }
                }
            },
            None => None,
        };

        // Perform DNS lookup
        match self.resolver.lookup(&query_name, rtype.clone(), server, timeout) {
            Ok(records) => {
                let server_info = server.map(|s| s.to_string()).unwrap_or_else(|| "system".to_string());
                let output = json!({
                    "query": query_name,
                    "rtype": rtype.as_str(),
                    "server": server_info,
                    "records": records.into_iter().map(|record| {
                        match record.kind {
                            ResolvedKind::A(ip) => json!({
                                "name": record.name,
                                "ttl": record.ttl,
                                "data": ip
                            }),
                            ResolvedKind::AAAA(ip) => json!({
                                "name": record.name,
                                "ttl": record.ttl,
                                "data": ip
                            }),
                            ResolvedKind::CNAME(cname) => json!({
                                "name": record.name,
                                "ttl": record.ttl,
                                "data": cname
                            }),
                            ResolvedKind::NS(ns) => json!({
                                "name": record.name,
                                "ttl": record.ttl,
                                "data": ns
                            }),
                            ResolvedKind::PTR(ptr) => json!({
                                "name": record.name,
                                "ttl": record.ttl,
                                "data": ptr
                            }),
                            ResolvedKind::MX { priority, exchange } => json!({
                                "name": record.name,
                                "ttl": record.ttl,
                                "data": {
                                    "priority": priority,
                                    "exchange": exchange
                                }
                            }),
                            ResolvedKind::TXT(text) => json!({
                                "name": record.name,
                                "ttl": record.ttl,
                                "data": text
                            }),
                            ResolvedKind::SRV { priority, weight, port, target } => json!({
                                "name": record.name,
                                "ttl": record.ttl,
                                "data": {
                                    "priority": priority,
                                    "weight": weight,
                                    "port": port,
                                    "target": target
                                }
                            }),
                        }
                    }).collect::<Vec<_>>()
                });
                writeln!(io.stdout, "{}", output)?;
                Ok(Status::ok())
            },
            Err(e) => {
                let error_json = json!({
                    "query": query_name,
                    "rtype": rtype.as_str(),
                    "error": "lookup_failed",
                    "detail": format!("{}", e)
                });
                writeln!(io.stdout, "{}", error_json)?;
                Ok(Status::err(1, format!("DNS lookup failed: {}", e)))
            }
        }
    }

    fn verb_ping(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        if self.host.is_none() {
            return Ok(Status::err(3, "net:// URL missing host"));
        }
        
        let host = self.host.as_ref().unwrap();
        
        // Parse arguments with validation
        let count = match self.parse_ping_count(args) {
            Ok(c) => c,
            Err(e) => {
                writeln!(io.stderr, "bad argument: {}", e)?;
                return Ok(Status::err(2, format!("bad argument: {}", e)));
            },
        };
        
        let timeout_ms = match self.parse_ping_timeout_ms(args) {
            Ok(t) => t,
            Err(e) => {
                writeln!(io.stderr, "bad argument: {}", e)?;
                return Ok(Status::err(2, format!("bad argument: {}", e)));
            },
        };
        
        let port_override = match self.parse_ping_port(args) {
            Ok(p) => p,
            Err(e) => {
                writeln!(io.stderr, "bad argument: {}", e)?;
                return Ok(Status::err(2, format!("bad argument: {}", e)));
            },
        };
        
        let family = match self.parse_ping_family(args) {
            Ok(f) => f,
            Err(e) => {
                writeln!(io.stderr, "bad argument: {}", e)?;
                return Ok(Status::err(2, format!("bad argument: {}", e)));
            },
        };
        
        let raw_output = match self.parse_ping_raw(args) {
            Ok(r) => r,
            Err(e) => {
                writeln!(io.stderr, "bad argument: {}", e)?;
                return Ok(Status::err(2, format!("bad argument: {}", e)));
            },
        };
        
        // Determine the port to use for TCP fallback
        let fallback_port = port_override.unwrap_or(self.port.unwrap_or(80));
        
        // Try system ping first
        match self.try_system_ping(host, count, timeout_ms, &family, raw_output, io) {
            Ok(result) => {
                let json_obj = json!({
                    "host": host,
                    "port": fallback_port,
                    "backend": "system_ping",
                    "sent": result.sent,
                    "received": result.received,
                    "loss": result.loss,
                    "avg_rtt_ms": result.avg_rtt_ms,
                    "timeout_ms": timeout_ms,
                    "reachable": result.reachable
                });
                writeln!(io.stdout, "{}", json_obj)?;
                return Ok(Status::ok());
            }
            Err(_) => {
                // Fall back to TCP ping
                match self.try_tcp_fallback(host, fallback_port, count, timeout_ms, io) {
                    Ok(result) => {
                        let json_obj = json!({
                            "host": host,
                            "port": fallback_port,
                            "backend": "tcp_fallback",
                            "sent": result.sent,
                            "received": result.received,
                            "loss": result.loss,
                            "avg_rtt_ms": result.avg_rtt_ms,
                            "timeout_ms": timeout_ms,
                            "reachable": result.reachable
                        });
                        writeln!(io.stdout, "{}", json_obj)?;
                        return Ok(Status::ok());
                    }
                    Err(e) => {
                        return Ok(Status::err(1, format!("Both ping and TCP fallback failed: {}", e)));
                    }
                }
            }
        }
    }

    fn parse_ping_count(&self, args: &Args) -> Result<u32> {
        let count_str = args.get("count").map(String::as_str).unwrap_or("3");
        let count: u32 = count_str.parse()
            .with_context(|| format!("count must be a number, got: {}", count_str))?;
        
        if count < 1 {
            bail!("count must be >= 1, got: {}", count);
        }
        
        Ok(count)
    }

    fn parse_ping_timeout_ms(&self, args: &Args) -> Result<u64> {
        let timeout_str = args.get("timeout_ms").map(String::as_str).unwrap_or("3000");
        let timeout_ms: u64 = timeout_str.parse()
            .with_context(|| format!("timeout_ms must be a number, got: {}", timeout_str))?;
        
        if timeout_ms < 100 {
            bail!("timeout_ms must be >= 100, got: {}", timeout_ms);
        }
        
        Ok(timeout_ms)
    }

    fn parse_ping_port(&self, args: &Args) -> Result<Option<u16>> {
        if let Some(port_str) = args.get("port") {
            let port: u16 = port_str.parse()
                .with_context(|| format!("port must be a number, got: {}", port_str))?;
            Ok(Some(port))
        } else {
            Ok(None)
        }
    }

    fn parse_ping_family(&self, args: &Args) -> Result<String> {
        let family = args.get("family").map(String::as_str).unwrap_or("auto");
        match family {
            "auto" | "ipv4" | "ipv6" => Ok(family.to_string()),
            _ => bail!("family must be 'auto', 'ipv4', or 'ipv6', got: {}", family),
        }
    }

    fn parse_ping_raw(&self, args: &Args) -> Result<bool> {
        if let Some(raw_str) = args.get("raw") {
            match raw_str.to_lowercase().as_str() {
                "true" | "1" | "yes" => Ok(true),
                "false" | "0" | "no" => Ok(false),
                _ => bail!("raw must be 'true' or 'false', got: {}", raw_str),
            }
        } else {
            Ok(false)
        }
    }

    fn try_system_ping(&self, host: &str, count: u32, timeout_ms: u64, family: &str, raw: bool, io: &mut IoStreams) -> Result<PingResult> {
        let ping_cmd = match family {
            "ipv6" => {
                // Try ping6 first, then ping -6
                if which::which("ping6").is_ok() {
                    "ping6"
                } else if which::which("ping").is_ok() {
                    "ping"
                } else {
                    bail!("No ping binary available");
                }
            }
            _ => {
                if which::which("ping").is_err() {
                    bail!("No ping binary available");
                }
                "ping"
            }
        };

        let per_packet_timeout_s = std::cmp::max(1, timeout_ms / 1000);
        let mut cmd = Command::new(ping_cmd);
        
        cmd.arg("-c").arg(count.to_string());
        cmd.arg("-W").arg(per_packet_timeout_s.to_string());
        
        if family == "ipv6" && ping_cmd == "ping" {
            cmd.arg("-6");
        }
        
        cmd.arg(host);
        
        let output = cmd.output()
            .with_context(|| format!("Failed to execute ping command"))?;

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let stderr_str = String::from_utf8_lossy(&output.stderr);
        
        if raw {
            write!(io.stderr, "Raw ping output:\nSTDOUT:\n{}\nSTDERR:\n{}\n", stdout_str, stderr_str)?;
        }

        // Parse the output
        let parsed = self.parse_system_ping_output(&stdout_str, output.status.success());
        
        Ok(PingResult {
            sent: count,
            received: parsed.received,
            loss: 1.0 - (parsed.received as f64 / count as f64),
            avg_rtt_ms: parsed.avg_rtt_ms,
            reachable: parsed.received > 0,
        })
    }

    fn parse_system_ping_output(&self, stdout: &str, _success: bool) -> ParsedOutput {
        let mut received = 0u32;
        let mut avg_rtt_ms: Option<f64> = None;
        
        for line in stdout.lines() {
            // Count replies - look for lines like "64 bytes from" or "icmp_seq="
            if line.contains("bytes from") || line.contains("icmp_seq=") {
                received += 1;
            }
            
            // Parse RTT statistics from lines like "rtt min/avg/max/mdev = 12.345/23.456/34.567/5.678 ms"
            if let Some(rtt_pos) = line.find("rtt min/avg/max") {
                if let Some(eq_pos) = line[rtt_pos..].find(" = ") {
                    let stats_part = &line[rtt_pos + eq_pos + 3..];
                    if let Some(ms_pos) = stats_part.find(" ms") {
                        let numbers_part = &stats_part[..ms_pos];
                        let values: Vec<&str> = numbers_part.split('/').collect();
                        if values.len() >= 2 {
                            if let Ok(avg) = values[1].parse::<f64>() {
                                avg_rtt_ms = Some(avg);
                            }
                        }
                    }
                }
            }
        }
        
        ParsedOutput {
            received,
            avg_rtt_ms,
        }
    }

    fn try_tcp_fallback(&self, host: &str, port: u16, count: u32, timeout_ms: u64, _io: &mut IoStreams) -> Result<PingResult> {
        let per_attempt_timeout = std::cmp::max(200, timeout_ms / count as u64);
        let timeout_duration = Duration::from_millis(per_attempt_timeout);
        
        let mut successes = 0u32;
        let mut total_rtt = 0.0f64;
        let mut rtt_count = 0;
        
        for _ in 0..count {
            let start = Instant::now();
            
            match std::net::TcpStream::connect_timeout(&format!("{}:{}", host, port).parse()?, timeout_duration) {
                Ok(_) => {
                    let elapsed = start.elapsed();
                    total_rtt += elapsed.as_millis() as f64;
                    rtt_count += 1;
                    successes += 1;
                }
                Err(_) => {
                    // Connection failed, this is expected for unreachable hosts
                }
            }
        }
        
        let avg_rtt_ms = if rtt_count > 0 {
            Some(total_rtt / rtt_count as f64)
        } else {
            None
        };
        
        Ok(PingResult {
            sent: count,
            received: successes,
            loss: 1.0 - (successes as f64 / count as f64),
            avg_rtt_ms,
            reachable: successes > 0,
        })
    }
    
    // Keep legacy parsing functions for backwards compatibility with other functions
    fn parse_count(&self, args: &Args) -> Result<u32> {
        let count_str = args.get("count").map(String::as_str).unwrap_or("4");
        let count: u32 = count_str.parse()
            .with_context(|| format!("Invalid count value: {}", count_str))?;
        
        if count == 0 || count > 100 {
            bail!("count must be between 1 and 100, got: {}", count);
        }
        
        Ok(count)
    }

    fn parse_timeout_ms(&self, args: &Args) -> Result<u64> {
        let timeout_str = args.get("timeout_ms").map(String::as_str).unwrap_or("2000");
        let timeout_ms: u64 = timeout_str.parse()
            .with_context(|| format!("Invalid timeout_ms value: {}", timeout_str))?;
        
        if timeout_ms == 0 {
            bail!("timeout_ms must be greater than 0, got: {}", timeout_ms);
        }
        
        Ok(timeout_ms)
    }

    fn parse_ipv(&self, args: &Args) -> Result<String> {
        if let Some(ipv_str) = args.get("ipv") {
            match ipv_str.as_str() {
                "4" => Ok("4".to_string()),
                "6" => Ok("6".to_string()),
                _ => bail!("ipv must be '4' or '6', got: {}", ipv_str),
            }
        } else {
            Ok("auto".to_string())
        }
    }

    fn parse_size(&self, args: &Args) -> Result<Option<u32>> {
        if let Some(size_str) = args.get("size") {
            let size: u32 = size_str.parse()
                .with_context(|| format!("Invalid size value: {}", size_str))?;
            
            if size < 8 || size > 65507 {
                bail!("size must be between 8 and 65507 bytes, got: {}", size);
            }
            
            Ok(Some(size))
        } else {
            Ok(None)
        }
    }

    fn verb_tcp_check(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        if self.host.is_none() {
            bail!("No target host/IP specified for tcp_check. Use net://hostname:port.tcp_check");
        }
        
        // Resolve port from args or URL
        let port = match self.resolve_port(args) {
            Ok(p) => p,
            Err(e) => {
                writeln!(io.stderr, "Error: {}", e)?;
                return Ok(Status::err(2, format!("Port resolution failed: {}", e)));
            }
        };

        // Parse other arguments with defaults and validation
        let timeout_ms = match self.parse_tcp_timeout_ms(args) {
            Ok(t) => t,
            Err(e) => {
                writeln!(io.stderr, "Error: {}", e)?;
                return Ok(Status::err(2, format!("Invalid timeout: {}", e)));
            }
        };

        let retries = match self.parse_retries(args) {
            Ok(r) => r,
            Err(e) => {
                writeln!(io.stderr, "Error: {}", e)?;
                return Ok(Status::err(2, format!("Invalid retries: {}", e)));
            }
        };

        let backoff_ms = match self.parse_backoff_ms(args) {
            Ok(b) => b,
            Err(e) => {
                writeln!(io.stderr, "Error: {}", e)?;
                return Ok(Status::err(2, format!("Invalid backoff: {}", e)));
            }
        };

        let _expect_tls = match self.parse_expect_tls(args) {
            Ok(t) => t,
            Err(e) => {
                writeln!(io.stderr, "Error: {}", e)?;
                return Ok(Status::err(2, format!("Invalid expect_tls: {}", e)));
            }
        };

        // Execute TCP check
        match self.execute_tcp_check(port, timeout_ms, retries, backoff_ms) {
            Ok((success, json_output)) => {
                writeln!(io.stdout, "{}", json_output)?;
                if success {
                    Ok(Status::ok())
                } else {
                    Ok(Status::err(111, "connection failed"))
                }
            }
            Err(e) => {
                writeln!(io.stderr, "Error: {}", e)?;
                Ok(Status::err(1, format!("TCP check execution failed: {}", e)))
            }
        }
    }

    fn resolve_port(&self, args: &Args) -> Result<u16> {
        // Args port takes precedence over URL port
        if let Some(port_str) = args.get("port") {
            let port: u16 = port_str.parse()
                .with_context(|| format!("Invalid port value: {}", port_str))?;
            if port == 0 {
                bail!("port must be greater than 0, got: {}", port);
            }
            return Ok(port);
        }

        // Fall back to URL port
        if let Some(port) = self.port {
            return Ok(port);
        }

        bail!("Port is required - specify in URL (net://host:port) or as argument (port=N)");
    }

    fn parse_tcp_timeout_ms(&self, args: &Args) -> Result<u64> {
        let timeout_str = args.get("timeout_ms").map(String::as_str).unwrap_or("3000");
        let timeout_ms: u64 = timeout_str.parse()
            .with_context(|| format!("Invalid timeout_ms value: {}", timeout_str))?;
        
        if timeout_ms == 0 {
            bail!("timeout_ms must be greater than 0, got: {}", timeout_ms);
        }
        
        Ok(timeout_ms)
    }

    fn parse_retries(&self, args: &Args) -> Result<u32> {
        let retries_str = args.get("retries").map(String::as_str).unwrap_or("1");
        let retries: u32 = retries_str.parse()
            .with_context(|| format!("Invalid retries value: {}", retries_str))?;
        
        if retries == 0 {
            bail!("retries must be greater than 0, got: {}", retries);
        }
        
        Ok(retries)
    }

    fn parse_backoff_ms(&self, args: &Args) -> Result<u64> {
        let backoff_str = args.get("backoff_ms").map(String::as_str).unwrap_or("0");
        let backoff_ms: u64 = backoff_str.parse()
            .with_context(|| format!("Invalid backoff_ms value: {}", backoff_str))?;
        
        Ok(backoff_ms)
    }

    fn parse_expect_tls(&self, args: &Args) -> Result<bool> {
        let expect_tls_str = args.get("expect_tls").map(String::as_str).unwrap_or("false");
        match expect_tls_str {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => bail!("expect_tls must be 'true' or 'false', got: {}", expect_tls_str),
        }
    }

    fn execute_tcp_check(&self, port: u16, timeout_ms: u64, retries: u32, backoff_ms: u64) -> Result<(bool, serde_json::Value)> {
        let timeout = Duration::from_millis(timeout_ms);
        let mut last_error = None;

        for attempt in 1..=retries {
            let start_time = Instant::now();
            
            // Resolve hostname to socket addresses
            let target = self.target();
            let addr = match target.to_socket_addrs() {
                Ok(mut addrs) => {
                    match addrs.next() {
                        Some(addr) => addr,
                        None => {
                            last_error = Some(std::io::Error::new(
                                std::io::ErrorKind::NotFound,
                                "No addresses found for hostname"
                            ));
                            continue;
                        }
                    }
                }
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            };
            
            match TcpStream::connect_timeout(&addr, timeout) {
                Ok(_stream) => {
                    // Connection successful
                    let latency_ms = start_time.elapsed().as_millis() as u64;
                    
                    let json_output = json!({
                        "host": self.host.as_deref().unwrap_or(&self.resource),
                        "port": port,
                        "ok": true,
                        "attempts": attempt,
                        "latency_ms": latency_ms,
                        "timeout_ms": timeout_ms,
                        "retries": retries,
                        "backend": "tcp",
                        "tls_checked": false
                    });
                    
                    return Ok((true, json_output));
                }
                Err(e) => {
                    last_error = Some(e);
                    
                    // If not the last attempt and we have backoff, sleep
                    if attempt < retries && backoff_ms > 0 {
                        std::thread::sleep(Duration::from_millis(backoff_ms));
                    }
                }
            }
        }

        // All attempts failed
        let error_msg = match last_error {
            Some(e) => format!("{}", e),
            None => "unknown error".to_string(),
        };

        let json_output = json!({
            "host": self.host.as_deref().unwrap_or(&self.resource),
            "port": port,
            "ok": false,
            "attempts": retries,
            "timeout_ms": timeout_ms,
            "retries": retries,
            "backend": "tcp",
            "error": error_msg,
            "tls_checked": false
        });

        Ok((false, json_output))
    }

    /// Implements the scan verb for TCP port scanning
    /// 
    /// Supported arguments:
    /// - ports: comma-separated list of ports and ranges (e.g., "80,443,8000-8005")
    /// - timeout_ms: timeout per port in milliseconds (default: 500)
    /// - concurrency: max concurrent connections (default: 32, max: 256) 
    /// - protocol: only "tcp" supported (default: "tcp")
    /// - host: override URL host for scanning target
    ///
    /// Output JSON schema:
    /// {
    ///   "target": "example.com",
    ///   "protocol": "tcp", 
    ///   "ports": [
    ///     { "port": 80, "state": "open" },
    ///     { "port": 22, "state": "closed", "error": "connection refused" }
    ///   ],
    ///   "scan": {
    ///     "timeout_ms": 500,
    ///     "concurrency": 32,
    ///     "started_at": "2025-11-15T12:34:56Z",
    ///     "duration_ms": 42
    ///   }
    /// }
    fn scan(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let start_time = Instant::now();
        let started_at = chrono::Utc::now().to_rfc3339();

        // 1. Determine target host
        let target_host = if let Some(host) = args.get("host") {
            host.clone()
        } else if let Some(host) = &self.host {
            host.clone()
        } else if !self.resource.is_empty() && self.resource != "if" && self.resource != "interfaces" {
            self.resource.clone()
        } else {
            writeln!(io.stderr, "missing host")?;
            return Ok(Status::err(1, "missing host"));
        };

        // 2. Parse protocol
        let protocol = args.get("protocol").map(String::as_str).unwrap_or("tcp");
        if protocol != "tcp" {
            writeln!(io.stderr, "unsupported protocol; only tcp is supported")?;
            return Ok(Status::err(6, "unsupported protocol; only tcp is supported"));
        }

        // 3. Parse timeout
        let timeout_ms = match args.get("timeout_ms") {
            Some(timeout_str) => match timeout_str.parse::<u64>() {
                Ok(t) => t,
                Err(_) => {
                    writeln!(io.stderr, "invalid timeout_ms")?;
                    return Ok(Status::err(5, "invalid timeout_ms"));
                }
            },
            None => 500, // default
        };

        // 4. Parse concurrency
        let concurrency = match args.get("concurrency") {
            Some(concurrency_str) => match concurrency_str.parse::<usize>() {
                Ok(c) => c.max(1).min(256),
                Err(_) => 32, // default on parse error
            },
            None => 32, // default
        };

        // 5. Parse ports
        let port_list = match self.parse_ports(args) {
            Ok(ports) => ports,
            Err(e) => {
                writeln!(io.stderr, "invalid ports specification: {}", e)?;
                return Ok(Status::err(3, format!("invalid ports specification: {}", e)));
            }
        };

        // 6. Check port list size limit
        if port_list.len() > 4096 {
            writeln!(io.stderr, "port range too large; max 4096 ports")?;
            return Ok(Status::err(4, "port range too large; max 4096 ports"));
        }

        // 7. Perform the scan
        let scan_results = self.perform_scan(&target_host, &port_list, timeout_ms, concurrency)?;

        // 8. Build output JSON
        let duration_ms = start_time.elapsed().as_millis() as u64;
        let output = serde_json::json!({
            "target": target_host,
            "protocol": protocol,
            "ports": scan_results,
            "scan": {
                "timeout_ms": timeout_ms,
                "concurrency": concurrency,
                "started_at": started_at,
                "duration_ms": duration_ms
            }
        });

        writeln!(io.stdout, "{}", serde_json::to_string(&output)?)?;
        Ok(Status::ok())
    }

    /// Parse ports argument into a list of port numbers
    /// Supports:
    /// - Single ports: "80"
    /// - Comma-separated: "80,443,8080"
    /// - Ranges: "8000-8005" 
    /// - Mixed: "80,443,8000-8005"
    fn parse_ports(&self, args: &Args) -> Result<Vec<u16>> {
        let ports_str = args.get("ports").map(String::as_str).unwrap_or("80,443");
        
        let mut ports = Vec::new();
        
        for token in ports_str.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            
            if token.contains('-') {
                // Parse range: "8000-8005"
                let parts: Vec<&str> = token.split('-').collect();
                if parts.len() != 2 {
                    bail!("invalid range format: {}", token);
                }
                
                let start = parts[0].trim().parse::<u16>()
                    .with_context(|| format!("invalid start port in range: {}", parts[0]))?;
                let end = parts[1].trim().parse::<u16>()
                    .with_context(|| format!("invalid end port in range: {}", parts[1]))?;
                
                if start == 0 || end == 0 {
                    bail!("port numbers must be in range 1-65535");
                }
                
                if start > end {
                    bail!("invalid range: start port {} > end port {}", start, end);
                }
                
                for port in start..=end {
                    ports.push(port);
                }
            } else {
                // Parse single port
                let port = token.parse::<u16>()
                    .with_context(|| format!("invalid port number: {}", token))?;
                
                if port == 0 {
                    bail!("port numbers must be in range 1-65535");
                }
                
                ports.push(port);
            }
        }
        
        Ok(ports)
    }

    /// Perform the actual TCP port scan
    /// Returns a list of port scan results in JSON format
    fn perform_scan(&self, host: &str, ports: &[u16], timeout_ms: u64, concurrency: usize) -> Result<Vec<serde_json::Value>> {
        let timeout = Duration::from_millis(timeout_ms);
        
        // Ensure reasonable concurrency limits
        let concurrency = concurrency.max(1).min(256);
        
        // If there are fewer ports than concurrency limit or very few ports, scan sequentially
        if ports.len() <= 4 || concurrency == 1 {
            return self.perform_sequential_scan(host, ports, timeout);
        }

        // Create channels for work distribution and result collection
        let (port_tx, port_rx) = mpsc::channel::<u16>();
        let port_rx = Arc::new(Mutex::new(port_rx));
        let (result_tx, result_rx) = mpsc::channel::<(usize, serde_json::Value)>();
        
        // Clone host string for threads
        let host = host.to_string();
        
        // Start worker threads
        let mut handles = Vec::new();
        for _ in 0..concurrency {
            let port_rx = Arc::clone(&port_rx);
            let result_tx = result_tx.clone();
            let host = host.clone();
            
            let handle = thread::spawn(move || {
                loop {
                    let port = {
                        let receiver = port_rx.lock().unwrap();
                        match receiver.try_recv() {
                            Ok(port) => port,
                            Err(_) => break, // Channel is empty or disconnected
                        }
                    };
                    
                    let result = Self::scan_port_static(&host, port, timeout);
                    if let Err(_) = result_tx.send((port as usize, result)) {
                        break; // Channel closed
                    }
                }
            });
            handles.push(handle);
        }
        
        // Send ports to worker threads
        for &port in ports {
            if port_tx.send(port).is_err() {
                break; // Channel closed
            }
        }
        drop(port_tx); // Signal no more work
        
        // Collect results
        let mut results_map = std::collections::HashMap::new();
        drop(result_tx); // Close sender so receiver will eventually close
        
        for (port, result) in result_rx {
            results_map.insert(port, result);
        }
        
        // Wait for all threads to finish
        for handle in handles {
            let _ = handle.join();
        }
        
        // Reconstruct results in original port order
        let mut results = Vec::new();
        for &port in ports {
            if let Some(result) = results_map.remove(&(port as usize)) {
                results.push(result);
            } else {
                // Fallback if somehow a result was lost
                results.push(serde_json::json!({
                    "port": port,
                    "state": "error",
                    "error": "scan result lost"
                }));
            }
        }
        
        Ok(results)
    }
    
    /// Fallback sequential implementation for small port lists or single-threaded operation
    fn perform_sequential_scan(&self, host: &str, ports: &[u16], timeout: Duration) -> Result<Vec<serde_json::Value>> {
        let mut results = Vec::new();
        
        for &port in ports {
            let result = self.scan_port(host, port, timeout);
            results.push(result);
        }
        
        Ok(results)
    }
    
    /// Static version of scan_port for use in threads
    fn scan_port_static(host: &str, port: u16, timeout: Duration) -> serde_json::Value {
        let addr_str = format!("{}:{}", host, port);
        
        // Try to resolve the address first
        let socket_addrs: Vec<_> = match addr_str.to_socket_addrs() {
            Ok(addrs) => addrs.collect(),
            Err(e) => {
                return serde_json::json!({
                    "port": port,
                    "state": "error",
                    "error": format!("dns resolution failed: {}", e)
                });
            }
        };

        if socket_addrs.is_empty() {
            return serde_json::json!({
                "port": port,
                "state": "error", 
                "error": "no addresses resolved"
            });
        }

        // Try connecting to each resolved address
        let last_addr = socket_addrs.last().cloned();
        for addr in socket_addrs {
            match TcpStream::connect_timeout(&addr, timeout) {
                Ok(_) => {
                    return serde_json::json!({
                        "port": port,
                        "state": "open"
                    });
                }
                Err(e) => {
                    use std::io::ErrorKind;
                    let state_and_error = match e.kind() {
                        ErrorKind::ConnectionRefused => ("closed", Some("connection refused".to_string())),
                        ErrorKind::TimedOut => ("timeout", None),
                        _ => ("error", Some(format!("{}", e))),
                    };
                    
                    // Continue to next address, but save this result as fallback
                    // If no address works, we'll use the last error
                    if Some(addr) == last_addr {
                        // This was the last address, return the error
                        let mut result = serde_json::json!({
                            "port": port,
                            "state": state_and_error.0
                        });
                        if let Some(error_msg) = state_and_error.1 {
                            result["error"] = serde_json::Value::String(error_msg);
                        }
                        return result;
                    }
                }
            }
        }

        // Fallback (shouldn't reach here)
        serde_json::json!({
            "port": port,
            "state": "error",
            "error": "unknown error"
        })
    }

    /// Scan a single port and return the result as JSON
    fn scan_port(&self, host: &str, port: u16, timeout: Duration) -> serde_json::Value {
        let addr_str = format!("{}:{}", host, port);
        
        // Try to resolve the address first
        let socket_addrs: Vec<_> = match addr_str.to_socket_addrs() {
            Ok(addrs) => addrs.collect(),
            Err(e) => {
                return serde_json::json!({
                    "port": port,
                    "state": "error",
                    "error": format!("dns resolution failed: {}", e)
                });
            }
        };

        if socket_addrs.is_empty() {
            return serde_json::json!({
                "port": port,
                "state": "error", 
                "error": "no addresses resolved"
            });
        }

        // Try connecting to each resolved address
        let last_addr = socket_addrs.last().cloned();
        for addr in socket_addrs {
            match TcpStream::connect_timeout(&addr, timeout) {
                Ok(_) => {
                    return serde_json::json!({
                        "port": port,
                        "state": "open"
                    });
                }
                Err(e) => {
                    use std::io::ErrorKind;
                    let state_and_error = match e.kind() {
                        ErrorKind::ConnectionRefused => ("closed", Some("connection refused".to_string())),
                        ErrorKind::TimedOut => ("timeout", None),
                        _ => ("error", Some(format!("{}", e))),
                    };
                    
                    // Continue to next address, but save this result as fallback
                    // If no address works, we'll use the last error
                    if Some(addr) == last_addr {
                        // This was the last address, return the error
                        let mut result = serde_json::json!({
                            "port": port,
                            "state": state_and_error.0
                        });
                        if let Some(error_msg) = state_and_error.1 {
                            result["error"] = serde_json::Value::String(error_msg);
                        }
                        return result;
                    }
                }
            }
        }

        // Fallback (shouldn't reach here)
        serde_json::json!({
            "port": port,
            "state": "error",
            "error": "unknown error"
        })
    }
}

struct PingResult {
    sent: u32,
    received: u32,
    loss: f64,
    avg_rtt_ms: Option<f64>,
    reachable: bool,
}

struct ParsedOutput {
    received: u32,
    avg_rtt_ms: Option<f64>,
}

impl NetHandle {
    /// Implement route.list verb to enumerate system routing table as JSON.
    /// 
    /// Arguments:
    /// - family (optional): "ipv4", "ipv6", or "all" (default: "ipv4")
    /// - table (optional): routing table filter (e.g. "main", "default")
    /// 
    /// Returns JSON array of route entries on stdout or error JSON on failure.
    fn route_list(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Handle unsupported platforms first
        #[cfg(not(target_os = "linux"))]
        {
            let error_json = json!({
                "backend": "net",
                "verb": "route.list",
                "error": "route.list not supported on this platform"
            });
            writeln!(io.stdout, "{}", error_json)?;
            return Ok(Status::err(1, "route.list not supported on this platform"));
        }

        #[cfg(target_os = "linux")]
        {
            use std::fs;
            use std::collections::HashMap;

            // Parse arguments
            let family = args.get("family").map(|s| s.as_str()).unwrap_or("ipv4");
            let _table_filter = args.get("table"); // For future use if needed

            // Validate family argument
            match family {
                "ipv4" | "ipv6" | "all" => {},
                _ => {
                    let error_json = json!({
                        "backend": "net",
                        "verb": "route.list",
                        "error": "invalid family",
                        "detail": format!("family must be ipv4, ipv6, or all, got: {}", family)
                    });
                    writeln!(io.stdout, "{}", error_json)?;
                    return Ok(Status::err(2, "invalid family argument"));
                }
            }

            let mut all_routes = Vec::new();

            // Try IPv4 routes if requested
            if family == "ipv4" || family == "all" {
                match self.get_ipv4_routes() {
                    Ok(mut routes) => all_routes.append(&mut routes),
                    Err(e) => {
                        writeln!(io.stderr, "Failed to get IPv4 routes: {}", e)?;
                        let error_json = json!({
                            "backend": "net",
                            "verb": "route.list",
                            "error": "failed to read IPv4 routing table",
                            "detail": format!("{}", e)
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        return Ok(Status::err(2, "failed to read routing table"));
                    }
                }
            }

            // Try IPv6 routes if requested  
            if family == "ipv6" || family == "all" {
                match self.get_ipv6_routes() {
                    Ok(mut routes) => all_routes.append(&mut routes),
                    Err(e) => {
                        // IPv6 failure is non-fatal if IPv4 succeeded
                        if family == "ipv6" {
                            writeln!(io.stderr, "Failed to get IPv6 routes: {}", e)?;
                            let error_json = json!({
                                "backend": "net",
                                "verb": "route.list",
                                "error": "failed to read IPv6 routing table",
                                "detail": format!("{}", e)
                            });
                            writeln!(io.stdout, "{}", error_json)?;
                            return Ok(Status::err(2, "failed to read routing table"));
                        } else {
                            // Just log to stderr if IPv6 fails but IPv4 succeeded
                            writeln!(io.stderr, "Warning: Failed to get IPv6 routes: {}", e)?;
                        }
                    }
                }
            }

            // Output the routes as JSON array
            let json_output = serde_json::to_string_pretty(&all_routes)?;
            writeln!(io.stdout, "{}", json_output)?;
            Ok(Status::ok())
        }
    }

    #[cfg(target_os = "linux")]
    fn get_ipv4_routes(&self) -> Result<Vec<serde_json::Value>> {
        use std::net::Ipv4Addr;
        use std::str::FromStr;

        // Try ip command first (preferred)
        if let Ok(ip_path) = which::which("ip") {
            match self.try_ip_command_ipv4(&ip_path) {
                Ok(routes) => return Ok(routes),
                Err(e) => {
                    // Log warning but continue to proc fallback
                    eprintln!("ip command failed, falling back to /proc: {}", e);
                }
            }
        }

        // Fallback to /proc/net/route
        self.parse_proc_net_route()
    }

    #[cfg(target_os = "linux")]
    fn get_ipv6_routes(&self) -> Result<Vec<serde_json::Value>> {
        // Try ip command first (preferred) 
        if let Ok(ip_path) = which::which("ip") {
            match self.try_ip_command_ipv6(&ip_path) {
                Ok(routes) => return Ok(routes),
                Err(e) => {
                    // Log warning but continue to proc fallback
                    eprintln!("ip -6 command failed, falling back to /proc: {}", e);
                }
            }
        }

        // Fallback to /proc/net/ipv6_route
        self.parse_proc_net_ipv6_route()
    }

    #[cfg(target_os = "linux")]
    fn try_ip_command_ipv4(&self, ip_path: &std::path::Path) -> Result<Vec<serde_json::Value>> {
        let output = Command::new(ip_path)
            .args(&["-j", "route", "show"])
            .output()
            .context("Failed to execute ip -j route show")?;

        if !output.status.success() {
            bail!("ip command failed with status: {}", output.status);
        }

        let stdout = String::from_utf8(output.stdout)
            .context("ip command output is not valid UTF-8")?;

        if stdout.trim().is_empty() {
            return Ok(Vec::new());
        }

        let ip_routes: serde_json::Value = serde_json::from_str(&stdout)
            .context("Failed to parse ip command JSON output")?;

        let routes_array = ip_routes.as_array()
            .ok_or_else(|| anyhow::anyhow!("ip command output is not an array"))?;

        let mut normalized_routes = Vec::new();
        for route in routes_array {
            normalized_routes.push(self.normalize_ip_route_ipv4(route)?);
        }

        Ok(normalized_routes)
    }

    #[cfg(target_os = "linux")]
    fn try_ip_command_ipv6(&self, ip_path: &std::path::Path) -> Result<Vec<serde_json::Value>> {
        let output = Command::new(ip_path)
            .args(&["-j", "-6", "route", "show"])
            .output()
            .context("Failed to execute ip -j -6 route show")?;

        if !output.status.success() {
            bail!("ip -6 command failed with status: {}", output.status);
        }

        let stdout = String::from_utf8(output.stdout)
            .context("ip -6 command output is not valid UTF-8")?;

        if stdout.trim().is_empty() {
            return Ok(Vec::new());
        }

        let ip_routes: serde_json::Value = serde_json::from_str(&stdout)
            .context("Failed to parse ip -6 command JSON output")?;

        let routes_array = ip_routes.as_array()
            .ok_or_else(|| anyhow::anyhow!("ip -6 command output is not an array"))?;

        let mut normalized_routes = Vec::new();
        for route in routes_array {
            normalized_routes.push(self.normalize_ip_route_ipv6(route)?);
        }

        Ok(normalized_routes)
    }

    #[cfg(target_os = "linux")]
    fn normalize_ip_route_ipv4(&self, route: &serde_json::Value) -> Result<serde_json::Value> {
        // Extract fields from ip command JSON output and normalize to our schema
        let dst = route.get("dst").and_then(|v| v.as_str()).unwrap_or("0.0.0.0/0");
        let gateway = route.get("gateway").and_then(|v| v.as_str());
        let dev = route.get("dev").and_then(|v| v.as_str()).unwrap_or("unknown");
        let metric = route.get("metric").and_then(|v| v.as_u64()).unwrap_or(0);
        let table = route.get("table").and_then(|v| v.as_str()).unwrap_or("main");
        let protocol = route.get("protocol").and_then(|v| v.as_str());
        let scope = route.get("scope").and_then(|v| v.as_str());

        let mut flags = Vec::new();
        if gateway.is_some() {
            flags.push("gateway");
        }
        // Add other flags based on route properties
        if scope == Some("link") {
            flags.push("link");
        }
        if scope == Some("host") {
            flags.push("host");  
        }

        Ok(json!({
            "family": "ipv4",
            "dst": dst,
            "gateway": gateway,
            "iface": dev,
            "metric": metric,
            "table": table,
            "protocol": protocol,
            "scope": scope,
            "flags": flags
        }))
    }

    #[cfg(target_os = "linux")]
    fn normalize_ip_route_ipv6(&self, route: &serde_json::Value) -> Result<serde_json::Value> {
        // Extract fields from ip -6 command JSON output and normalize to our schema
        let dst = route.get("dst").and_then(|v| v.as_str()).unwrap_or("::/0");
        let gateway = route.get("gateway").and_then(|v| v.as_str());
        let dev = route.get("dev").and_then(|v| v.as_str()).unwrap_or("unknown");
        let metric = route.get("metric").and_then(|v| v.as_u64()).unwrap_or(0);
        let table = route.get("table").and_then(|v| v.as_str()).unwrap_or("main");
        let protocol = route.get("protocol").and_then(|v| v.as_str());
        let scope = route.get("scope").and_then(|v| v.as_str());

        let mut flags = Vec::new();
        if gateway.is_some() {
            flags.push("gateway");
        }
        if scope == Some("link") {
            flags.push("link");
        }
        if scope == Some("host") {
            flags.push("host");
        }

        Ok(json!({
            "family": "ipv6",
            "dst": dst,
            "gateway": gateway,
            "iface": dev,
            "metric": metric,
            "table": table,
            "protocol": protocol,
            "scope": scope,
            "flags": flags
        }))
    }

    #[cfg(target_os = "linux")]
    fn parse_proc_net_route(&self) -> Result<Vec<serde_json::Value>> {
        use std::net::Ipv4Addr;
        use std::str::FromStr;
        use std::fs;

        let contents = fs::read_to_string("/proc/net/route")
            .context("Failed to read /proc/net/route")?;

        let mut routes = Vec::new();
        let lines: Vec<&str> = contents.lines().collect();
        
        // Skip header line
        for line in lines.iter().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 11 {
                continue; // Skip malformed lines
            }

            let iface = fields[0];
            let dest_hex = fields[1];
            let gateway_hex = fields[2];
            let flags_hex = fields[3];
            let _refcnt = fields[4];
            let _use = fields[5];
            let metric = fields[6];
            let mask_hex = fields[7];
            let _mtu = fields[8];
            let _window = fields[9];
            let _irtt = fields[10];

            // Convert hex values to IP addresses
            let dest_addr = self.hex_to_ipv4(dest_hex)?;
            let gateway_addr = self.hex_to_ipv4(gateway_hex)?;
            let mask_addr = self.hex_to_ipv4(mask_hex)?;

            // Calculate prefix length from netmask
            let prefix_len = self.mask_to_prefix_len(mask_addr);
            let dst = if dest_addr.is_unspecified() && prefix_len == 0 {
                "0.0.0.0/0".to_string()
            } else {
                format!("{}/{}", dest_addr, prefix_len)
            };

            let gateway = if gateway_addr.is_unspecified() {
                None
            } else {
                Some(gateway_addr.to_string())
            };

            // Parse flags
            let flags_val = u32::from_str_radix(flags_hex, 16).unwrap_or(0);
            let flags = self.parse_route_flags(flags_val);

            let metric_val = metric.parse::<u64>().unwrap_or(0);

            routes.push(json!({
                "family": "ipv4",
                "dst": dst,
                "gateway": gateway,
                "iface": iface,
                "metric": metric_val,
                "table": "main", // /proc/net/route doesn't provide table info
                "protocol": null,
                "scope": null,
                "flags": flags
            }));
        }

        Ok(routes)
    }

    #[cfg(target_os = "linux")]
    fn parse_proc_net_ipv6_route(&self) -> Result<Vec<serde_json::Value>> {
        use std::fs;

        let contents = fs::read_to_string("/proc/net/ipv6_route")
            .context("Failed to read /proc/net/ipv6_route")?;

        let mut routes = Vec::new();
        
        for line in contents.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue; // Skip malformed lines
            }

            let dest_net = fields[0];
            let dest_prefix_len = fields[1];
            let _src_net = fields[2];
            let _src_prefix_len = fields[3];
            let next_hop = fields[4];
            let metric = fields[5];
            let _refcnt = fields[6];
            let _use = fields[7];
            let flags = fields[8];
            let dev_name = fields[9];

            // Format IPv6 destination
            let dest_formatted = self.format_ipv6_from_hex(dest_net)?;
            let prefix_len = u32::from_str_radix(dest_prefix_len, 16).unwrap_or(128);
            let dst = format!("{}/{}", dest_formatted, prefix_len);

            // Format IPv6 gateway
            let gateway = if next_hop == "00000000000000000000000000000000" {
                None
            } else {
                Some(self.format_ipv6_from_hex(next_hop)?)
            };

            let metric_val = u32::from_str_radix(metric, 16).unwrap_or(0) as u64;

            // Parse IPv6 route flags (simplified)
            let flags_val = u32::from_str_radix(flags, 16).unwrap_or(0);
            let route_flags = self.parse_ipv6_route_flags(flags_val);

            routes.push(json!({
                "family": "ipv6",
                "dst": dst,
                "gateway": gateway,
                "iface": dev_name,
                "metric": metric_val,
                "table": "main", // /proc/net/ipv6_route doesn't provide table info  
                "protocol": null,
                "scope": null,
                "flags": route_flags
            }));
        }

        Ok(routes)
    }

    #[cfg(target_os = "linux")]
    fn hex_to_ipv4(&self, hex_str: &str) -> Result<std::net::Ipv4Addr> {
        use std::net::Ipv4Addr;
        
        if hex_str.len() != 8 {
            bail!("Invalid hex string length for IPv4: {}", hex_str);
        }
        
        let val = u32::from_str_radix(hex_str, 16)
            .context("Failed to parse hex string as u32")?;
        
        // /proc/net/route stores addresses in little-endian format
        let bytes = val.to_le_bytes();
        Ok(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    }

    #[cfg(target_os = "linux")]  
    fn mask_to_prefix_len(&self, mask: std::net::Ipv4Addr) -> u8 {
        let mask_val = u32::from(mask);
        mask_val.leading_ones() as u8
    }

    #[cfg(target_os = "linux")]
    fn parse_route_flags(&self, flags: u32) -> Vec<&'static str> {
        let mut flag_names = Vec::new();
        
        // Linux route flags from include/uapi/linux/route.h
        if flags & 0x0001 != 0 { flag_names.push("up"); }        // RTF_UP
        if flags & 0x0002 != 0 { flag_names.push("gateway"); }   // RTF_GATEWAY  
        if flags & 0x0004 != 0 { flag_names.push("host"); }      // RTF_HOST
        if flags & 0x0008 != 0 { flag_names.push("reinstate"); } // RTF_REINSTATE
        if flags & 0x0010 != 0 { flag_names.push("dynamic"); }   // RTF_DYNAMIC
        if flags & 0x0020 != 0 { flag_names.push("modified"); }  // RTF_MODIFIED
        
        flag_names
    }

    #[cfg(target_os = "linux")]
    fn format_ipv6_from_hex(&self, hex_str: &str) -> Result<String> {
        if hex_str.len() != 32 {
            bail!("Invalid hex string length for IPv6: {}", hex_str);
        }
        
        let mut parts = Vec::new();
        for i in 0..8 {
            let start = i * 4;
            let end = start + 4;
            let part = &hex_str[start..end];
            let val = u16::from_str_radix(part, 16)
                .with_context(|| format!("Failed to parse IPv6 part: {}", part))?;
            parts.push(format!("{:x}", val));
        }
        
        Ok(parts.join(":"))
    }

    #[cfg(target_os = "linux")]
    fn parse_ipv6_route_flags(&self, flags: u32) -> Vec<&'static str> {
        let mut flag_names = Vec::new();
        
        // Simplified IPv6 route flags
        if flags & 0x0001 != 0 { flag_names.push("up"); }
        if flags & 0x0002 != 0 { flag_names.push("gateway"); }
        if flags & 0x0004 != 0 { flag_names.push("host"); }
        
        flag_names
    }
}

fn list_interfaces(args: &Args, io: &mut IoStreams) -> Result<Status> {
    // Get all network interfaces
    let interfaces = match if_addrs::get_if_addrs() {
        Ok(interfaces) => interfaces,
        Err(e) => {
            writeln!(io.stderr, "Failed to get network interfaces: {}", e)?;
            return Ok(Status::err(50, format!("Failed to get network interfaces: {}", e)));
        }
    };

    // Parse filtering arguments
    let up_filter = args.get("up").map(|v| v.to_lowercase() == "true");
    let family_filter = args.get("family").map(|v| v.to_lowercase());
    
    // Validate arguments first
    if let Some(family) = args.get("family") {
        match family.to_lowercase().as_str() {
            "ipv4" | "ipv6" | "all" => {}, // valid
            _ => {
                let error_json = json!({
                    "error": "Invalid family argument",
                    "detail": format!("family must be 'ipv4', 'ipv6', or 'all', got '{}'", family)
                });
                writeln!(io.stderr, "{}", error_json)?;
                return Ok(Status::err(1, format!("Invalid family: {}", family)));
            }
        }
    }
    
    if let Some(up) = args.get("up") {
        match up.to_lowercase().as_str() {
            "true" | "false" => {}, // valid
            _ => {
                let error_json = json!({
                    "error": "Invalid up argument", 
                    "detail": format!("up must be 'true' or 'false', got '{}'", up)
                });
                writeln!(io.stderr, "{}", error_json)?;
                return Ok(Status::err(1, format!("Invalid up: {}", up)));
            }
        }
    }

    // Group interfaces by name and collect their addresses
    let mut interface_map: std::collections::BTreeMap<String, InterfaceData> = std::collections::BTreeMap::new();
    
    for iface in interfaces {
        let name = iface.name.clone();
        let is_loopback = iface.is_loopback();
        let is_up = !is_loopback; // Basic approximation - if-addrs doesn't provide detailed up/down status
        
        // Apply up/down filtering
        if let Some(up_required) = up_filter {
            if up_required && is_loopback {
                // Skip loopback interfaces when looking for "up" interfaces
                continue;
            }
            if !up_required && !is_loopback {
                // Skip non-loopback when looking for "down" interfaces  
                continue;
            }
        }
        
        // Apply family filtering on the address
        let addr = iface.ip();
        let (family, addr_str, scope) = match addr {
            std::net::IpAddr::V4(ipv4) => {
                if let Some(ref filter) = family_filter {
                    if filter == "ipv6" {
                        continue;
                    }
                }
                let scope = if is_loopback { "host" } else { "global" };
                ("ipv4", ipv4.to_string(), scope)
            }
            std::net::IpAddr::V6(ipv6) => {
                if let Some(ref filter) = family_filter {
                    if filter == "ipv4" {
                        continue;
                    }
                }
                let scope = if is_loopback {
                    "host"
                } else if ipv6.segments()[0] & 0xffc0 == 0xfe80 {
                    "link"
                } else {
                    "global"
                };
                ("ipv6", ipv6.to_string(), scope)
            }
        };
        
        let entry = interface_map.entry(name.clone()).or_insert_with(|| InterfaceData {
            name: name.clone(),
            index: None, // if-addrs doesn't provide interface index
            mac: None,   // if-addrs doesn't provide MAC address
            flags: build_flags(is_up, is_loopback),
            mtu: None,   // if-addrs doesn't provide MTU
            addresses: Vec::new(),
        });
        
        // Create address entry
        let address_entry = json!({
            "family": family,
            "addr": addr_str,
            "scope": scope
        });
        
        // Note: if-addrs doesn't provide prefix length information
        // We could enhance this with platform-specific code in the future
        
        entry.addresses.push(address_entry);
    }
    
    // Convert to sorted array
    let mut result: Vec<serde_json::Value> = interface_map
        .into_values()
        .map(|iface| {
            json!({
                "name": iface.name,
                "index": iface.index,
                "mac": iface.mac,
                "flags": iface.flags,
                "mtu": iface.mtu,
                "addresses": iface.addresses
            })
        })
        .collect();
    
    // Sort by name
    result.sort_by(|a, b| {
        let name_a = a["name"].as_str().unwrap_or("");
        let name_b = b["name"].as_str().unwrap_or("");
        name_a.cmp(name_b)
    });
    
    // Output JSON object with interfaces array (as required by spec)
    let json_output = json!({
        "interfaces": result
    });
    
    writeln!(io.stdout, "{}", json_output)?;
    
    Ok(Status::ok())
}

#[derive(Debug, Clone, PartialEq)]
enum AddressFamily {
    IPv4,
    IPv6,
}

fn parse_bool_arg(args: &Args, key: &str) -> Option<bool> {
    args.get(key).and_then(|v| {
        match v.to_lowercase().as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        }
    })
}



#[derive(Debug)]
struct InterfaceData {
    name: String,
    index: Option<u32>,
    mac: Option<String>,
    flags: Vec<String>,
    mtu: Option<u32>,
    addresses: Vec<serde_json::Value>,
}

fn build_flags(is_up: bool, is_loopback: bool) -> Vec<String> {
    let mut flags = Vec::new();
    if is_up {
        flags.push("up".to_string());
    }
    if is_loopback {
        flags.push("loopback".to_string());
    }
    // Assume running and multicast for non-loopback interfaces
    if !is_loopback {
        flags.push("running".to_string());
        flags.push("multicast".to_string());
    }
    flags
}

fn ipv4_netmask_from_prefix(prefix_len: u8) -> String {
    let mask = if prefix_len == 0 {
        0u32
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    };
    format!("{}.{}.{}.{}", 
        (mask >> 24) & 0xff,
        (mask >> 16) & 0xff,
        (mask >> 8) & 0xff,
        mask & 0xff)
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
            error_message: String::new() 
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
    fn lookup(&self, _name: &str, _rtype: RecordType, _server: Option<SocketAddr>, _timeout: Duration) -> Result<ResolvedRecords> {
        if self.should_error {
            bail!("{}", self.error_message);
        }
        Ok(self.records.clone())
    }
}

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("net", |u| Ok(Box::new(NetHandle::from_url(u)?)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::registry::Args;

    #[test]
    fn test_dns_invalid_query_name() {
        let mock_resolver = Arc::new(MockResolver::new(vec![]));
        let handle = NetHandle::with_resolver("".into(), mock_resolver);
        
        let args = Args::new();
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        let mut io = IoStreams {
            stdin: &mut &[][..],
            stdout: &mut stdout_buf,
            stderr: &mut stderr_buf,
        };

        let status = handle.call_dns(&args, &mut io).unwrap();
        
        assert!(!status.ok);
        assert_eq!(status.code, Some(2));
        
        let output = String::from_utf8(stdout_buf).unwrap();
        assert!(output.contains("\"error\":\"invalid_query\""));
    }

    #[test]
    fn test_dns_invalid_record_type() {
        let mock_resolver = Arc::new(MockResolver::new(vec![]));
        let handle = NetHandle::with_resolver("example.com".into(), mock_resolver);
        
        let mut args = Args::new();
        args.insert("type".into(), "FOO".into());
        
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        let mut io = IoStreams {
            stdin: &mut &[][..],
            stdout: &mut stdout_buf,
            stderr: &mut stderr_buf,
        };

        let status = handle.call_dns(&args, &mut io).unwrap();
        
        assert!(!status.ok);
        assert_eq!(status.code, Some(2));
        
        let output = String::from_utf8(stdout_buf).unwrap();
        assert!(output.contains("\"error\":\"invalid_type\""));
        assert!(output.contains("Unknown record type: FOO"));
    }

    #[test]
    fn test_dns_invalid_timeout() {
        let mock_resolver = Arc::new(MockResolver::new(vec![]));
        let handle = NetHandle::with_resolver("example.com".into(), mock_resolver);
        
        let mut args = Args::new();
        args.insert("timeout_ms".into(), "-1".into());
        
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        let mut io = IoStreams {
            stdin: &mut &[][..],
            stdout: &mut stdout_buf,
            stderr: &mut stderr_buf,
        };

        let status = handle.call_dns(&args, &mut io).unwrap();
        
        assert!(!status.ok);
        assert_eq!(status.code, Some(2));
        
        let output = String::from_utf8(stdout_buf).unwrap();
        assert!(output.contains("\"error\":\"invalid_timeout\""));
    }

    #[test]
    fn test_dns_invalid_server() {
        let mock_resolver = Arc::new(MockResolver::new(vec![]));
        let handle = NetHandle::with_resolver("example.com".into(), mock_resolver);
        
        let mut args = Args::new();
        args.insert("server".into(), "not-an-ip".into());
        
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        let mut io = IoStreams {
            stdin: &mut &[][..],
            stdout: &mut stdout_buf,
            stderr: &mut stderr_buf,
        };

        let status = handle.call_dns(&args, &mut io).unwrap();
        
        assert!(!status.ok);
        assert_eq!(status.code, Some(2));
        
        let output = String::from_utf8(stdout_buf).unwrap();
        assert!(output.contains("\"error\":\"invalid_server\""));
    }

    #[test]
    fn test_dns_successful_a_record() {
        let records = vec![
            ResolvedRecord {
                name: "example.com.".into(),
                ttl: 300,
                kind: ResolvedKind::A("93.184.216.34".into()),
            }
        ];
        let mock_resolver = Arc::new(MockResolver::new(records));
        let handle = NetHandle::with_resolver("example.com".into(), mock_resolver);
        
        let args = Args::new();
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        let mut io = IoStreams {
            stdin: &mut &[][..],
            stdout: &mut stdout_buf,
            stderr: &mut stderr_buf,
        };

        let status = handle.call_dns(&args, &mut io).unwrap();
        
        assert!(status.ok);
        assert_eq!(status.code, Some(0));
        
        let output = String::from_utf8(stdout_buf).unwrap();
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();
        
        assert_eq!(json["query"], "example.com");
        assert_eq!(json["rtype"], "A");
        assert_eq!(json["server"], "system");
        assert_eq!(json["records"][0]["name"], "example.com.");
        assert_eq!(json["records"][0]["ttl"], 300);
        assert_eq!(json["records"][0]["data"], "93.184.216.34");
    }

    #[test]
    fn test_dns_successful_mx_record() {
        let records = vec![
            ResolvedRecord {
                name: "example.com.".into(),
                ttl: 3600,
                kind: ResolvedKind::MX {
                    priority: 10,
                    exchange: "mail.example.com.".into(),
                },
            }
        ];
        let mock_resolver = Arc::new(MockResolver::new(records));
        let handle = NetHandle::with_resolver("example.com".into(), mock_resolver);
        
        let mut args = Args::new();
        args.insert("type".into(), "MX".into());
        
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        let mut io = IoStreams {
            stdin: &mut &[][..],
            stdout: &mut stdout_buf,
            stderr: &mut stderr_buf,
        };

        let status = handle.call_dns(&args, &mut io).unwrap();
        
        assert!(status.ok);
        
        let output = String::from_utf8(stdout_buf).unwrap();
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();
        
        assert_eq!(json["rtype"], "MX");
        assert_eq!(json["records"][0]["data"]["priority"], 10);
        assert_eq!(json["records"][0]["data"]["exchange"], "mail.example.com.");
    }

    #[test]
    fn test_dns_successful_srv_record() {
        let records = vec![
            ResolvedRecord {
                name: "_sip._tcp.example.com.".into(),
                ttl: 300,
                kind: ResolvedKind::SRV {
                    priority: 10,
                    weight: 20,
                    port: 5060,
                    target: "sip.example.com.".into(),
                },
            }
        ];
        let mock_resolver = Arc::new(MockResolver::new(records));
        let handle = NetHandle::with_resolver("_sip._tcp.example.com".into(), mock_resolver);
        
        let mut args = Args::new();
        args.insert("type".into(), "SRV".into());
        
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        let mut io = IoStreams {
            stdin: &mut &[][..],
            stdout: &mut stdout_buf,
            stderr: &mut stderr_buf,
        };

        let status = handle.call_dns(&args, &mut io).unwrap();
        
        assert!(status.ok);
        
        let output = String::from_utf8(stdout_buf).unwrap();
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();
        
        assert_eq!(json["rtype"], "SRV");
        assert_eq!(json["records"][0]["data"]["priority"], 10);
        assert_eq!(json["records"][0]["data"]["weight"], 20);
        assert_eq!(json["records"][0]["data"]["port"], 5060);
        assert_eq!(json["records"][0]["data"]["target"], "sip.example.com.");
    }

    #[test]
    fn test_dns_lookup_failed() {
        let mock_resolver = Arc::new(MockResolver::with_error("NXDOMAIN".into()));
        let handle = NetHandle::with_resolver("nonexistent.example.com".into(), mock_resolver);
        
        let args = Args::new();
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        let mut io = IoStreams {
            stdin: &mut &[][..],
            stdout: &mut stdout_buf,
            stderr: &mut stderr_buf,
        };

        let status = handle.call_dns(&args, &mut io).unwrap();
        
        assert!(!status.ok);
        assert_eq!(status.code, Some(1));
        
        let output = String::from_utf8(stdout_buf).unwrap();
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();
        
        assert_eq!(json["error"], "lookup_failed");
        assert!(json["detail"].as_str().unwrap().contains("NXDOMAIN"));
    }

    #[test]
    fn test_dns_with_custom_server_and_port() {
        let records = vec![
            ResolvedRecord {
                name: "example.com.".into(),
                ttl: 300,
                kind: ResolvedKind::A("1.2.3.4".into()),
            }
        ];
        let mock_resolver = Arc::new(MockResolver::new(records));
        let handle = NetHandle::with_resolver("example.com".into(), mock_resolver);
        
        let mut args = Args::new();
        args.insert("server".into(), "8.8.8.8".into());
        args.insert("port".into(), "53".into());
        args.insert("timeout_ms".into(), "5000".into());
        
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        let mut io = IoStreams {
            stdin: &mut &[][..],
            stdout: &mut stdout_buf,
            stderr: &mut stderr_buf,
        };

        let status = handle.call_dns(&args, &mut io).unwrap();
        
        assert!(status.ok);
        
        let output = String::from_utf8(stdout_buf).unwrap();
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();
        
        assert_eq!(json["server"], "8.8.8.8:53");
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
        let url = url::Url::parse("net://example.com.dns").unwrap();
        let handle = NetHandle::from_url(&url).unwrap();
        assert_eq!(handle.extract_dns_query_name().unwrap(), "example.com");

        let url = url::Url::parse("net://8.8.8.8.dns").unwrap();
        let handle = NetHandle::from_url(&url).unwrap();
        assert_eq!(handle.extract_dns_query_name().unwrap(), "8.8.8.8");
    }
}