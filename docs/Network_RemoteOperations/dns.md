# DNS Handle

The DNS handle in Resource Shell provides powerful DNS lookup, resolution, tracing, and zone management capabilities. This handle supports all standard DNS record types and advanced features like DNSSEC, zone transfers, and dynamic updates.

## URL Format

```
dns://
```

## Verbs

The DNS handle supports five main verbs:

- `lookup` - Perform DNS record lookups
- `resolve` - Intelligent DNS resolution for hosts, mail, and services  
- `trace` - Trace DNS resolution from root servers
- `zone.fetch` - Perform DNS zone transfers (AXFR/IXFR)
- `zone.update` - Perform dynamic DNS zone updates

---

## lookup

Perform DNS record lookups for specific record types.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `name` | string | Yes | - | Domain name to look up |
| `rtype` | string | No | `A` | DNS record type (A, AAAA, TXT, CNAME, MX, NS, SRV, PTR, SOA, CAA, ANY) |
| `servers` | string/array | No | System default | DNS servers to query (JSON array or comma-separated) |
| `port` | number | No | `53` | DNS server port |
| `use_tcp` | boolean | No | `false` | Use TCP instead of UDP |
| `timeout_ms` | number | No | `2000` | Query timeout in milliseconds |
| `retries` | number | No | `1` | Number of retries on failure |
| `dnssec` | boolean | No | `false` | Request DNSSEC validation |
| `follow_cname` | boolean | No | `true` | Follow CNAME records |
| `include_authority` | boolean | No | `true` | Include authority section in response |
| `include_additional` | boolean | No | `true` | Include additional section in response |
| `randomize_servers` | boolean | No | `true` | Randomize server order |
| `format` | string | No | `json` | Output format (json or text) |

### Examples

#### Basic A Record Lookup

```bash
# Look up A records for example.com
dns:// lookup name=example.com rtype=A format=json
```

**Expected Output (JSON):**
```json
{
  "ok": true,
  "query": {
    "name": "example.com",
    "rtype": "A",
    "servers": ["1.1.1.1"],
    "port": 53,
    "use_tcp": false,
    "timeout_ms": 2000,
    "retries": 1,
    "dnssec": false
  },
  "answers": [
    {
      "name": "example.com",
      "rtype": "A",
      "class": "IN",
      "ttl": 3600,
      "data": {
        "address": "93.184.216.34"
      }
    }
  ],
  "response": {
    "rcode": "NOERROR",
    "authoritative": false,
    "truncated": false,
    "recursion_desired": true,
    "recursion_available": true,
    "round_trip_time_ms": 10
  }
}
```

#### MX Record Lookup

```bash
# Look up mail exchange records
dns:// lookup name=example.com rtype=MX servers=8.8.8.8
```

#### TXT Record Lookup with Custom Settings

```bash
# Look up TXT records with custom settings
dns:// lookup name=_dmarc.example.com rtype=TXT timeout_ms=5000 use_tcp=true
```

### Error Handling

Common error codes:
- `DNS_LOOKUP_INVALID_NAME` - Empty or invalid domain name
- `DNS_LOOKUP_INVALID_TYPE` - Unknown DNS record type
- `DNS_LOOKUP_INVALID_SERVER` - Invalid server IP address
- `DNS_LOOKUP_INVALID_PORT` - Port cannot be 0
- `DNS_LOOKUP_NXDOMAIN` - Domain does not exist
- `DNS_LOOKUP_TIMEOUT` - Query timed out

---

## resolve

Intelligent DNS resolution that adapts based on the resolution mode and address family.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `name` | string | Yes | - | Name to resolve |
| `mode` | string | No | `host` | Resolution mode (host, mail, service, reverse) |
| `family` | string | No | `any` | Address family (any, ipv4, ipv6) |
| `servers` | string/array | No | System default | DNS servers to use |
| `port` | number | No | `53` | DNS server port |
| `use_tcp` | boolean | No | `false` | Use TCP instead of UDP |
| `timeout_ms` | number | No | `2000` | Query timeout in milliseconds |
| `retries` | number | No | `1` | Number of retries |
| `dnssec` | boolean | No | `false` | Request DNSSEC validation |
| `max_cname_depth` | number | No | `8` | Maximum CNAME chain depth |
| `want_raw` | boolean | No | `false` | Include raw DNS responses |
| `follow_srv` | boolean | No | `true` | Follow SRV records for service mode |
| `validate_reverse` | boolean | No | `false` | Validate reverse DNS matches forward |
| `format` | string | No | `json` | Output format (json or text) |

### Examples

#### Host Resolution (IPv4 only)

```bash
# Resolve host to IPv4 addresses
dns:// resolve name=example.com mode=host family=ipv4
```

**Expected Output:**
```json
{
  "ok": true,
  "query": {
    "name": "example.com",
    "mode": "host",
    "family": "ipv4"
  },
  "resolution": {
    "canonical_name": "example.com.",
    "mode": "host",
    "family": "ipv4", 
    "addresses": [
      {
        "ip": "93.184.216.34",
        "family": "ipv4",
        "ttl": 3600
      }
    ]
  }
}
```

#### Mail Server Resolution

```bash
# Resolve mail servers for domain
dns:// resolve name=example.com mode=mail family=any
```

#### Service Resolution

```bash
# Resolve service endpoints
dns:// resolve name=_http._tcp.example.com mode=service
```

#### Reverse DNS Resolution

```bash
# Reverse resolve IP address
dns:// resolve name=192.0.2.1 mode=reverse
```

### Error Handling

Common error codes:
- `DNS_RESOLVE_INVALID_MODE` - Invalid resolution mode
- `DNS_RESOLVE_INVALID_FAMILY` - Invalid address family
- `DNS_RESOLVE_HOST_NOT_FOUND` - No addresses found
- `DNS_RESOLVE_NO_MX` - No MX records found
- `DNS_RESOLVE_NO_SRV` - No SRV records found
- `DNS_RESOLVE_NO_PTR` - No PTR record found
- `DNS_RESOLVE_CNAME_LOOP` - CNAME loop detected

---

## trace

Trace DNS resolution from root servers to show the complete resolution path.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `name` | string | Yes | - | Domain name to trace |
| `rtype` | string | No | `A` | DNS record type to trace |
| `root_servers` | string/array | No | Built-in list | Root servers to start from |
| `port` | number | No | `53` | DNS server port |
| `use_tcp` | boolean | No | `false` | Use TCP instead of UDP |
| `timeout_ms` | number | No | `3000` | Query timeout in milliseconds |
| `retries` | number | No | `1` | Number of retries per query |
| `max_depth` | number | No | `15` | Maximum trace depth |
| `dnssec` | boolean | No | `false` | Request DNSSEC validation |
| `follow_cname` | boolean | No | `false` | Follow CNAME records |
| `prefer_ipv6` | boolean | No | `false` | Prefer IPv6 when contacting servers |
| `want_raw` | boolean | No | `false` | Include raw DNS responses |
| `include_additional` | boolean | No | `true` | Include additional section |
| `format` | string | No | `json` | Output format (json or text) |

### Examples

#### Basic Trace

```bash
# Trace A record resolution for example.com
dns:// trace name=example.com rtype=A
```

#### Trace with Custom Root Servers

```bash
# Trace using specific root servers
dns:// trace name=test.example.com root_servers=198.41.0.4,192.5.5.241
```

#### NS Record Trace

```bash
# Trace NS records with custom settings
dns:// trace name=test.example.com rtype=NS max_depth=10 use_tcp=true
```

### Error Handling

Common error codes:
- `DNS_TRACE_INVALID_TYPE` - Invalid record type
- `DNS_TRACE_INVALID_ROOT_SERVER` - Invalid root server IP
- `DNS_TRACE_INVALID_MAX_DEPTH` - max_depth must be greater than 0
- `DNS_TRACE_INVALID_TIMEOUT` - timeout_ms must be greater than 0

---

## zone.fetch

Perform DNS zone transfers (AXFR or IXFR) to retrieve zone data.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `zone` | string | Yes | - | Zone name to transfer |
| `transfer` | string | No | `AXFR` | Transfer type (AXFR or IXFR) |
| `serial` | number | No | - | Starting serial for IXFR (required for IXFR) |
| `servers` | string/array | No | Empty | Authoritative servers for the zone |
| `port` | number | No | `53` | DNS server port |
| `use_tcp` | boolean | No | `true` | Use TCP (recommended for zone transfers) |
| `timeout_ms` | number | No | `5000` | Query timeout in milliseconds |
| `retries` | number | No | `1` | Number of retries |
| `dnssec` | boolean | No | `false` | Request DNSSEC validation |
| `max_records` | number | No | `1000000` | Maximum records to transfer |
| `include_raw` | boolean | No | `false` | Include raw DNS responses |
| `prefer_ipv6` | boolean | No | `false` | Prefer IPv6 servers |
| `tsig_key_name` | string | No | - | TSIG key name for authentication |
| `tsig_secret` | string | No | - | TSIG secret (base64 encoded) |
| `tsig_algorithm` | string | No | - | TSIG algorithm |
| `format` | string | No | `json` | Output format (json or text) |

### Examples

#### Basic AXFR Zone Transfer

```bash
# Transfer entire zone using AXFR
dns:// zone.fetch zone=example.com transfer=AXFR servers=["192.0.2.53"]
```

#### IXFR Incremental Transfer

```bash
# Incremental zone transfer from serial number
dns:// zone.fetch zone=example.com transfer=IXFR serial=2025112501 servers=["192.0.2.53"]
```

#### Zone Transfer with TSIG Authentication

```bash
# Authenticated zone transfer using TSIG
dns:// zone.fetch zone=example.com servers=["192.0.2.53"] tsig_key_name=axfr-key.example.com. tsig_secret=YWJjZDEyMzQ= tsig_algorithm=hmac-sha256
```

### Error Handling

Common error codes:
- `DNS_ZONE_FETCH_INVALID_ZONE` - Missing or empty zone name
- `DNS_ZONE_FETCH_INVALID_TRANSFER_TYPE` - Invalid transfer type
- `DNS_ZONE_FETCH_MISSING_SERIAL` - IXFR requires serial parameter
- `DNS_ZONE_FETCH_INVALID_TSIG_CONFIG` - TSIG requires both key name and secret
- `DNS_ZONE_FETCH_INVALID_TSIG_SECRET` - TSIG secret must be valid base64

---

## zone.update

Perform dynamic DNS zone updates to modify zone records.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `zone` | string | Yes | - | Zone name to update |
| `prerequisites` | array | No | Empty | Prerequisites that must be met |
| `adds` | array | No | Empty | Records to add |
| `deletes` | array | No | Empty | Records or names to delete |
| `servers` | string/array | No | Empty | Authoritative servers for the zone |
| `port` | number | No | `53` | DNS server port |
| `use_tcp` | boolean | No | `true` | Use TCP (recommended for updates) |
| `timeout_ms` | number | No | `3000` | Query timeout in milliseconds |
| `retries` | number | No | `1` | Number of retries |
| `max_changes` | number | No | `1000` | Maximum changes in single update |
| `dry_run` | boolean | No | `false` | Validate update without applying |
| `include_raw` | boolean | No | `false` | Include raw DNS responses |
| `tsig_key_name` | string | No | - | TSIG key name for authentication |
| `tsig_secret` | string | No | - | TSIG secret (base64 encoded) |
| `tsig_algorithm` | string | No | - | TSIG algorithm |
| `format` | string | No | `json` | Output format (json or text) |

### Examples

#### Add New A Record

```bash
# Add a new A record to the zone
dns:// zone.update zone=example.com adds='[{"name":"www.example.com","rtype":"A","ttl":300,"data":{"address":"203.0.113.10"}}]'
```

#### Add MX Record

```bash
# Add mail exchange record
dns:// zone.update zone=example.com adds='[{"name":"mail.example.com","rtype":"MX","ttl":3600,"data":{"preference":10,"exchange":"mx.example.com."}}]'
```

#### Delete Specific Record

```bash
# Delete a specific A record
dns:// zone.update zone=example.com deletes='[{"name":"www.example.com","rtype":"A","data":{"address":"203.0.113.10"}}]'
```

#### Delete All Records of Type

```bash
# Delete all A records for a name
dns:// zone.update zone=example.com deletes='[{"name":"www.example.com","rtype":"A","delete_all":true}]'
```

#### Delete All Records for Name

```bash
# Delete all records for a name
dns:// zone.update zone=example.com deletes='[{"name":"www.example.com","delete_all":true}]'
```

#### Update with Prerequisites

```bash
# Update with prerequisite check
dns:// zone.update zone=example.com prerequisites='[{"kind":"record_exists","name":"www.example.com","rtype":"A"}]' adds='[{"name":"www.example.com","rtype":"A","ttl":300,"data":{"address":"203.0.113.11"}}]'
```

### Prerequisites

Available prerequisite types:
- `record_exists` - Specific record must exist
- `record_not_exists` - Specific record must not exist
- `name_in_use` - Name must have any records
- `name_not_in_use` - Name must have no records
- `zone_serial_at_least` - Zone serial must be at least specified value

### Error Handling

Common error codes:
- `DNS_ZONE_UPDATE_INVALID_ZONE` - Missing or empty zone name
- `DNS_ZONE_UPDATE_INVALID_ADD_RECORD` - Invalid record in adds array
- `DNS_ZONE_UPDATE_INVALID_DELETE_SPEC` - Invalid delete specification
- `DNS_ZONE_UPDATE_INVALID_PREREQUISITE` - Invalid prerequisite
- `DNS_ZONE_UPDATE_INVALID_TSIG_CONFIG` - TSIG requires both key name and secret

---

## Common Parameters

### Record Types

Supported DNS record types:
- `A` - IPv4 address record
- `AAAA` - IPv6 address record  
- `CNAME` - Canonical name record
- `MX` - Mail exchange record
- `TXT` - Text record
- `NS` - Name server record
- `SRV` - Service record
- `PTR` - Pointer record
- `SOA` - Start of authority record
- `CAA` - Certification authority authorization record
- `ANY` - Any record type (for queries)

### Output Formats

- `json` - Structured JSON output (default)
- `text` - Human-readable text output

### Server Specification

DNS servers can be specified as:
- JSON array: `["1.1.1.1", "8.8.8.8"]`
- Comma-separated: `"1.1.1.1,8.8.8.8"`
- Single server: `"1.1.1.1"`

### TSIG Authentication

For authenticated operations (zone transfers and updates):
- `tsig_key_name` - The TSIG key identifier
- `tsig_secret` - Base64-encoded secret key
- `tsig_algorithm` - Algorithm (e.g., "hmac-sha256")

All TSIG parameters must be provided together for authentication to work.

---

## Usage Tips

1. **Network Connectivity**: DNS operations require network access. Tests may fail in isolated environments.

2. **Performance**: Use TCP (`use_tcp=true`) for large responses like zone transfers.

3. **Security**: Use DNSSEC validation (`dnssec=true`) when security is important.

4. **Authentication**: Zone transfers and updates often require TSIG authentication.

5. **Error Handling**: Check the `ok` field in JSON responses or the exit code for success/failure.

6. **Timeouts**: Adjust `timeout_ms` and `retries` for slow or unreliable networks.

7. **Rate Limiting**: Be respectful when making many DNS queries; some servers implement rate limiting.