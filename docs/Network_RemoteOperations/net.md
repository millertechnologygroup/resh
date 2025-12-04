# Net Handle Documentation

The net handle provides network utilities including interface listing, connectivity testing, DNS lookups, port scanning, and routing table inspection.

## Verbs

### list

Lists network interfaces on the system.

**URL Format:** `net://if.list` or `net://iface.list` or `net://interfaces.list`

**Arguments:**
- `family` (optional): Filter by address family. Valid values: `ipv4`, `ipv6`, `all`. Default: all families
- `up` (optional): Filter by interface status. Valid values: `true`, `false`. Default: all interfaces

**Output:** JSON object containing an array of network interfaces.

**Example:**
```bash
net://iface.list
```

**Expected Output:**
```json
{
  "interfaces": [
    {
      "name": "lo",
      "index": null,
      "mac": null,
      "flags": ["up", "loopback"],
      "mtu": null,
      "addresses": [
        {
          "family": "ipv4",
          "addr": "127.0.0.1",
          "scope": "host"
        }
      ]
    }
  ]
}
```

**Example with family filter:**
```bash
net://iface.list(family=ipv4)
```

### ping

Tests network connectivity to a host using ICMP ping or TCP fallback.

**URL Format:** `net://host.ping`

**Arguments:**
- `count` (optional): Number of ping packets to send. Must be ≥ 1. Default: 3
- `timeout_ms` (optional): Timeout per packet in milliseconds. Must be ≥ 100. Default: 3000
- `port` (optional): Port for TCP fallback. Default: 80 or from URL
- `family` (optional): IP family preference. Valid values: `auto`, `ipv4`, `ipv6`. Default: `auto`
- `raw` (optional): Show raw ping output. Valid values: `true`, `false`. Default: `false`

**Output:** JSON object with ping results.

**Example:**
```bash
net://127.0.0.1.ping(count=1,timeout_ms=1000)
```

**Expected Output:**
```json
{
  "host": "127.0.0.1",
  "port": 80,
  "backend": "system_ping",
  "sent": 1,
  "received": 1,
  "loss": 0.0,
  "avg_rtt_ms": 0.1,
  "timeout_ms": 1000,
  "reachable": true
}
```

**Example with unreachable host:**
```bash
net://192.0.2.1.ping(count=1,timeout_ms=500)
```

**Expected Output:**
```json
{
  "host": "192.0.2.1", 
  "port": 80,
  "backend": "tcp_fallback",
  "sent": 1,
  "received": 0,
  "loss": 1.0,
  "avg_rtt_ms": null,
  "timeout_ms": 500,
  "reachable": false
}
```

### tcp_check

Tests TCP connectivity to a specific host and port.

**URL Format:** `net://host:port.tcp_check` or `net://host.tcp_check`

**Arguments:**
- `port` (optional): Target port number. Required if not in URL
- `timeout_ms` (optional): Connection timeout in milliseconds. Must be > 0. Default: 3000
- `retries` (optional): Number of retry attempts. Must be > 0. Default: 1
- `backoff_ms` (optional): Delay between retries in milliseconds. Default: 0
- `expect_tls` (optional): Whether to expect TLS. Valid values: `true`, `false`. Default: `false`

**Output:** JSON object with connection results.

**Example successful connection:**
```bash
net://127.0.0.1:80.tcp_check(timeout_ms=5000,retries=1)
```

**Expected Output:**
```json
{
  "host": "127.0.0.1",
  "port": 80,
  "ok": true,
  "attempts": 1,
  "latency_ms": 1,
  "timeout_ms": 5000,
  "retries": 1,
  "backend": "tcp",
  "tls_checked": false
}
```

**Example failed connection:**
```bash
net://127.0.0.1:65534.tcp_check(timeout_ms=200,retries=1)
```

**Expected Output:**
```json
{
  "host": "127.0.0.1",
  "port": 65534,
  "ok": false,
  "attempts": 1,
  "timeout_ms": 200,
  "retries": 1,
  "backend": "tcp",
  "error": "Connection refused (os error 111)",
  "tls_checked": false
}
```

### scan

Performs TCP port scanning on a target host.

**URL Format:** `net://host.scan`

**Arguments:**
- `ports` (optional): Port specification. Can be single ports, ranges, or comma-separated. Default: `80,443`
  - Single port: `80`
  - Multiple ports: `80,443,8080`
  - Port range: `8000-8005`
  - Mixed: `80,443,8000-8005`
- `timeout_ms` (optional): Timeout per port in milliseconds. Default: 500
- `concurrency` (optional): Maximum concurrent connections (1-256). Default: 32
- `protocol` (optional): Protocol to scan. Only `tcp` supported. Default: `tcp`
- `host` (optional): Override target host from URL

**Output:** JSON object with scan results.

**Example:**
```bash
net://127.0.0.1.scan(ports=80)
```

**Expected Output:**
```json
{
  "target": "127.0.0.1",
  "protocol": "tcp",
  "ports": [
    {
      "port": 80,
      "state": "open"
    }
  ],
  "scan": {
    "timeout_ms": 500,
    "concurrency": 32,
    "started_at": "2025-11-15T12:34:56Z",
    "duration_ms": 42
  }
}
```

**Example with port range:**
```bash
net://127.0.0.1.scan(ports=80-82)
```

**Expected Output:**
```json
{
  "target": "127.0.0.1",
  "protocol": "tcp",
  "ports": [
    {
      "port": 80,
      "state": "closed",
      "error": "connection refused"
    },
    {
      "port": 81,
      "state": "timeout"
    },
    {
      "port": 82,
      "state": "closed",
      "error": "connection refused"
    }
  ],
  "scan": {
    "timeout_ms": 500,
    "concurrency": 32,
    "started_at": "2025-11-15T12:34:56Z",
    "duration_ms": 128
  }
}
```

### dns

Performs DNS lookups for various record types.

**URL Format:** `net://domain.dns` or `net://ip.dns`

**Arguments:**
- `type` (optional): DNS record type. Valid values: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SRV`, `PTR`. Default: `A`
- `server` (optional): Custom DNS server IP address
- `port` (optional): Custom DNS server port. Default: 53
- `timeout_ms` (optional): Query timeout in milliseconds. Must be > 0. Default: 3000

**Output:** JSON object with DNS query results.

**Example A record lookup:**
```bash
net://example.com.dns
```

**Expected Output:**
```json
{
  "query": "example.com",
  "rtype": "A",
  "server": "system",
  "records": [
    {
      "name": "example.com.",
      "ttl": 300,
      "data": "93.184.216.34"
    }
  ]
}
```

**Example MX record lookup:**
```bash
net://example.com.dns(type=MX)
```

**Expected Output:**
```json
{
  "query": "example.com",
  "rtype": "MX",
  "server": "system",
  "records": [
    {
      "name": "example.com.",
      "ttl": 3600,
      "data": {
        "priority": 10,
        "exchange": "mail.example.com."
      }
    }
  ]
}
```

**Example SRV record lookup:**
```bash
net://_sip._tcp.example.com.dns(type=SRV)
```

**Expected Output:**
```json
{
  "query": "_sip._tcp.example.com",
  "rtype": "SRV",
  "server": "system",
  "records": [
    {
      "name": "_sip._tcp.example.com.",
      "ttl": 300,
      "data": {
        "priority": 10,
        "weight": 20,
        "port": 5060,
        "target": "sip.example.com."
      }
    }
  ]
}
```

**Example PTR (reverse DNS) lookup:**
```bash
net://8.8.8.8.dns(type=PTR)
```

**Expected Output:**
```json
{
  "query": "8.8.8.8",
  "rtype": "PTR",
  "server": "system",
  "records": [
    {
      "name": "8.8.8.8",
      "ttl": 300,
      "data": "dns.google."
    }
  ]
}
```

**Example with custom DNS server:**
```bash
net://example.com.dns(server=8.8.8.8)
```

**Expected Output:**
```json
{
  "query": "example.com",
  "rtype": "A", 
  "server": "8.8.8.8:53",
  "records": [
    {
      "name": "example.com.",
      "ttl": 300,
      "data": "93.184.216.34"
    }
  ]
}
```

### route.list

Lists the system routing table. Only supported on Linux systems.

**URL Format:** `net://host.route.list`

**Arguments:**
- `family` (optional): Route family filter. Valid values: `ipv4`, `ipv6`, `all`. Default: `ipv4`
- `table` (optional): Routing table filter. Currently not implemented

**Output:** JSON array of routing entries.

**Example:**
```bash
net://host.route.list
```

**Expected Output:**
```json
[
  {
    "family": "ipv4",
    "dst": "0.0.0.0/0",
    "gateway": "192.168.1.1",
    "iface": "eth0",
    "metric": 100,
    "table": "main",
    "protocol": "dhcp",
    "scope": null,
    "flags": ["up", "gateway"]
  },
  {
    "family": "ipv4", 
    "dst": "192.168.1.0/24",
    "gateway": null,
    "iface": "eth0",
    "metric": 100,
    "table": "main",
    "protocol": "kernel",
    "scope": "link",
    "flags": ["up", "link"]
  }
]
```

**Example with IPv6 family:**
```bash
net://host.route.list(family=ipv6)
```

**Expected Output:**
```json
[
  {
    "family": "ipv6",
    "dst": "::/0",
    "gateway": "fe80::1",
    "iface": "eth0",
    "metric": 1024,
    "table": "main",
    "protocol": "ra",
    "scope": null,
    "flags": ["up", "gateway"]
  }
]
```

## Error Handling

All verbs return appropriate error codes and JSON error messages when operations fail:

- **Exit Code 1**: General failure
- **Exit Code 2**: Invalid arguments
- **Exit Code 3**: Missing required parameters
- **Exit Code 50**: System error (e.g., failed to get interfaces)
- **Exit Code 111**: Connection failed (tcp_check)

Error responses include structured JSON with error details:

```json
{
  "error": "invalid_type",
  "detail": "Unknown record type: FOO",
  "query": "example.com",
  "rtype": "FOO"
}
```

## Platform Support

- **list**: All platforms
- **ping**: All platforms (with TCP fallback)
- **tcp_check**: All platforms 
- **scan**: All platforms
- **dns**: All platforms
- **route.list**: Linux only

## Notes

1. The ping verb tries system ping first, then falls back to TCP connectivity checks if ping fails
2. DNS lookups use the system resolver by default but can use custom DNS servers
3. Port scanning respects concurrency limits to avoid overwhelming target systems
4. All timeouts are configurable to accommodate different network conditions
5. Route listing requires appropriate system permissions on some platforms