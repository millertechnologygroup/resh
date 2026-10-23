# Resource Shell (resh): DNS Handle

## 1. Overview

The `dns` handle queries DNS through the trust-dns (0.23) resolver library. It
covers single record lookups, host, mail, service and reverse resolution,
delegation traces from the root servers, and full zone transfers (AXFR). It
also validates dynamic zone updates, but it **does not send them**: see
[zone.update](#55-zoneupdate-simulated).

Each verb prints one JSON document (or a text summary with `format=text`) and
exits 0 on success and 1 on failure. Linux is the only supported and verified
platform.

Built-in help is always available and matches the code:

```bash
resh dns --help
resh dns lookup --help
```

## 2. Command syntax

The URL target is always empty: write `dns://` followed by a dot and the verb.
The name to query is an argument, not part of the URL.

```text
resh dns://.<verb> key=value ...
resh 'dns://.<verb>(key=value,...)'
```

```bash
resh dns://.lookup name=example.com rtype=MX
resh 'dns://.lookup(name=example.com,rtype=MX)'
```

`dns:// lookup` (with a space) does not parse. A host in the URL, as in
`dns://example.com.lookup`, is ignored: the name must still be given as
`name=`. The dotted verbs `zone.fetch` and `zone.update` are recognized as a whole:
`dns://.zone.fetch`.

Each `resh` run is a separate process; there is no resolver cache or session
shared between invocations.

## 3. Verbs

| Verb          | What it does                                                                 | Network traffic |
| ------------- | ---------------------------------------------------------------------------- | --------------- |
| `lookup`      | Queries one record type for a name and prints the answer records.            | Yes             |
| `resolve`     | Resolves a host (following CNAMEs), or mail, service or reverse records.     | Yes             |
| `trace`       | Walks delegation from the root servers toward a name and reports each hop.   | Yes             |
| `zone.fetch`  | Transfers a full zone with AXFR over TCP and prints its records.             | Yes             |
| `zone.update` | Validates a dynamic update and reports it as applied. **Simulated.**         | Only for name server discovery when `servers` is not given |

## 4. Which resolver is used

When `servers=` is not given, `lookup`, `resolve` and `trace` (for name
servers without glue) do **not** read `/etc/resolv.conf`. They use the
trust-dns default configuration, which is Google Public DNS (8.8.8.8,
8.8.4.4 and their IPv6 equivalents). `zone.fetch` and `zone.update` use the
same default resolver to find a zone's authoritative servers when `servers=`
is not given.

To query your own resolver, pass it explicitly, for example
`servers=192.0.2.53`. In that case `port` and `use_tcp` apply. Without
`servers=` they are recorded in the `query` echo but have no effect.

## 5. Verb reference

Common rules:

* Boolean options of `lookup`, `resolve` and `trace` are true only for the
  value `true` (any case). Any other value, including `yes` or `1`, means
  false. `zone.fetch` and `zone.update` use Rust's strict `true`/`false` parse
  and fall back to the default for other values. `dry_run` is the exception:
  it accepts true/false/1/0/yes/no/on/off and rejects anything else.
* Record types accepted by `rtype` (any case): A, AAAA, TXT, CNAME, MX, NS,
  SRV, PTR, SOA, CAA, ANY.
* `servers=` for `lookup` and `resolve` takes a comma-separated list or a JSON
  array of IP addresses. Host names are rejected.

### 5.1 lookup

```bash
resh dns://.lookup name=example.com rtype=MX
resh dns://.lookup name=example.com rtype=A servers=192.0.2.53 use_tcp=true timeout_ms=1500
resh dns://.lookup name=example.com format=text
```

| Argument             | Default | Notes |
| -------------------- | ------- | ----- |
| `name`               | (required) | Name to query. |
| `rtype`              | `A`     | Record type. |
| `servers`            | (none: Google Public DNS) | IP list. Order is shuffled before use. |
| `port`               | `53`    | Only with `servers`. `0` is rejected. |
| `use_tcp`            | `false` | Only with `servers`. |
| `timeout_ms`         | `2000`  | Per query attempt. `0` is rejected. |
| `retries`            | `1`     | Extra attempts (attempts = retries + 1). |
| `dnssec`             | `false` | Turns on EDNS0 and the resolver's validate flag. Validation status is not reported: `dnssec_validated` is always null and a warning is added. |
| `format`             | `json`  | `json` or `text`. |

`follow_cname`, `include_authority`, `include_additional` and
`randomize_servers` are parsed but have no visible effect: the resolver
backend never exposes authority or additional records, so those arrays are
always empty.

Output (JSON, printed indented): `ok`, `timestamp_unix_ms`, `query` (echo of
the options), `response` (`rcode`, `authoritative`, `truncated`,
`dnssec_validated`, `server_used`, `round_trip_time_ms`), `answers`,
`authority`, `additional`, `error`, `warnings`. Each answer has `name`,
`rtype`, `class`, `ttl` and a type-specific `data` object (for example
`{"address": "192.0.2.10"}` for A, `{"preference": 10, "exchange": "..."}` for
MX).

```json
{
  "ok": true,
  "query": { "name": "example.com", "rtype": "MX", "servers": [], "port": 53, "use_tcp": false, "timeout_ms": 2000, "retries": 1, "dnssec": false },
  "response": { "rcode": "NOERROR", "authoritative": false, "truncated": false, "dnssec_validated": null, "server_used": null, "round_trip_time_ms": 24 },
  "answers": [
    { "name": "example.com.", "rtype": "MX", "class": "IN", "ttl": 3600, "data": { "exchange": "mail.example.com.", "preference": 10 } }
  ],
  "authority": [],
  "additional": [],
  "error": null,
  "warnings": []
}
```

(Abbreviated: `timestamp_unix_ms` omitted.) `authoritative` is always false
and `server_used` is the first configured server, not necessarily the one that
answered.

On failure the JSON is still printed with `ok: false` and
`error: {"code": "...", "message": "..."}` (codes such as
`dns.lookup_nxdomain`, `dns.lookup_servfail`, `dns.lookup_timeout`), and the
command exits 1. Argument errors (for example `dns.lookup_invalid_type`) print
no JSON; the message goes to stderr as `Error: [code] message`.

### 5.2 resolve

```bash
resh dns://.resolve name=example.com family=ipv4
resh dns://.resolve name=example.com mode=mail
resh dns://.resolve name=_sip._tcp.example.com mode=service
resh dns://.resolve name=192.0.2.10 mode=reverse validate_reverse=true
```

| Argument           | Default | Notes |
| ------------------ | ------- | ----- |
| `name`             | (required) | Host name, or an IP address for `mode=reverse`. |
| `mode`             | `host`  | `host` (A/AAAA after CNAMEs), `mail` (MX plus target addresses), `service` (SRV plus target addresses), `reverse` (PTR). |
| `family`           | `any`   | `any`, `ipv4`, `ipv6`. With `any`, IPv6 addresses are listed first. |
| `servers`, `port`, `use_tcp`, `retries`, `dnssec` | as for `lookup` | |
| `timeout_ms`       | `2000`  | Per query; a resolve can run several queries. `0` is rejected. |
| `max_cname_depth`  | `8`     | Host mode: maximum CNAME hops. |
| `follow_srv`       | `true`  | Service mode: resolve SRV targets to addresses. |
| `validate_reverse` | `false` | Reverse mode: look up the PTR name forward and report `forward_addresses`. |
| `format`           | `json`  | `json` or `text`. |

`want_raw` is accepted but `raw` is always null.

Output: `ok`, `timestamp_unix_ms`, `query`, `resolution` (`canonical_name`,
`mode`, `family`, `addresses`, `mx`, `srv`, `ptr_name`, `forward_addresses`,
`source_server`, `round_trip_time_ms`), `raw`, `error`, `warnings`. Run
`resh dns resolve --help` for a full sample.

### 5.3 trace

```bash
resh dns://.trace name=www.example.com rtype=A
resh dns://.trace name=example.com root_servers=198.41.0.4 max_depth=10
```

| Argument             | Default | Notes |
| -------------------- | ------- | ----- |
| `name`               | (required) | |
| `rtype`              | `A`     | Type asked of the final zone. |
| `root_servers`       | built-in root hints (3 used) | IP list, comma-separated or JSON array. |
| `prefer_ipv6`        | `false` | Use IPv6 root hints instead of IPv4. |
| `timeout_ms`         | `3000`  | Per query. `0` is rejected. |
| `retries`            | `1`     | |
| `max_depth`          | `15`    | `0` is rejected. |
| `port`, `use_tcp`, `dnssec` | as for `lookup` | Applied to each hop's query. |
| `format`             | `json`  | |

Output: `ok`, `timestamp_unix_ms`, `query`, `trace` (`name`, `rtype`,
`final_rcode`, `final_authoritative`, `hops`, `final_answers`, `cname_chain`,
`depth`), `error`, `warnings`. Each hop reports the zone, the server queried,
`rcode`, `rtt_ms`, NS names and addresses, and answers.

Limitation: each hop is queried through the same stub resolver as `lookup`,
which exposes only the answer section. Referral data (authority and glue in
the additional section) is not available, so the walk depends on answer
records and may stop early. Name servers without glue are looked up through the
default resolver described in section 4. Treat `trace` as a best-effort
diagnostic, not a reimplementation of `dig +trace`. `follow_cname` and
`want_raw` are echoed but not used.

### 5.4 zone.fetch

```bash
resh dns://.zone.fetch zone=example.com servers=192.0.2.53
resh dns://.zone.fetch zone=example.com servers='["192.0.2.53","192.0.2.54"]' max_records=50000
```

| Argument      | Default | Notes |
| ------------- | ------- | ----- |
| `zone`        | (required) | |
| `servers`     | discovered NS addresses | A single IP, or a JSON array of IPs. A comma-separated string is **not** split. Servers are tried in order until one succeeds. |
| `port`        | `53`    | `0` is rejected. |
| `transfer`    | `AXFR`  | `AXFR` or `IXFR`. `IXFR` requires `serial` but is performed as AXFR (`transfer_used` reports `AXFR`). |
| `serial`      | (none)  | Required with `transfer=IXFR`. |
| `timeout_ms`  | `5000`  | Applied to the TCP connect and to each read. `0` is rejected. |
| `max_records` | `1000000` | The transfer fails if reached. `0` is rejected. |
| `format`      | `json`  | |

The transfer always uses TCP. `use_tcp`, `retries`, `dnssec` and
`include_raw` are parsed but not used. `prefer_ipv6` only affects server
discovery.

**TSIG is not supported.** `tsig_key_name`, `tsig_secret` and `tsig_algorithm`
are validated (both name and secret must be given, the secret must be base64)
and echoed in `query`, but the AXFR request is **never signed**. A server that
requires TSIG will refuse the transfer.

Output: `ok`, `timestamp_unix_ms`, `query`, `zone` (`name`,
`transfer_requested`, `transfer_used`, `server_used`, `soa`, `serial`,
`record_count`, `records`), `changes` (always null), `raw`, `error`,
`warnings`. In this verb `error` is a two-element array `["code", "message"]`
rather than an object. Per-server failures are listed in `warnings`.

### 5.5 zone.update (simulated)

```bash
resh dns://.zone.update zone=example.com servers=192.0.2.53 dry_run=true
resh dns://.zone.update zone=example.com servers=192.0.2.53 dry_run adds='[{"name":"www.example.com","rtype":"A","ttl":300,"data":{"address":"203.0.113.10"}}]'
```

**This verb does not change any zone.** No DNS UPDATE message is ever sent,
with or without `dry_run`. The code validates the input, then (without
`dry_run`) waits about 10 ms and reports success: `ok: true`, `rcode`
`NOERROR` and `applied_adds`/`applied_deletes` equal to the number of
requested changes. Do not rely on its output as evidence that a record was
changed. Use a real tool such as `nsupdate` for dynamic updates.

What it does validate:

| Argument        | Notes |
| --------------- | ----- |
| `zone`          | Required. |
| `adds`          | JSON array of `{"name", "rtype", "ttl", "data"}`. `rtype` must be a supported type. |
| `deletes`       | JSON array of `{"name", "rtype", "data"}` or `{"name", "delete_all": true}` (no `data` then). |
| `prerequisites` | JSON array of `{"kind", ...}` with kind `record_exists`, `record_not_exists`, `name_in_use`, `name_not_in_use` (need `name`) or `zone_serial_at_least` (needs `serial`). |
| `max_changes`   | Default `1000`; adds plus deletes may not exceed it. |
| `servers`       | Single IP or JSON array. Without it the zone's NS records are looked up (real DNS queries to the default resolver). |
| `port`          | Default `53`. |
| `timeout_ms`, `retries` | Validated (`timeout_ms=0` and `retries>100` are rejected) and echoed, otherwise unused. |
| `tsig_key_name`, `tsig_secret`, `tsig_algorithm` | Must be given together; secret must be base64; algorithm `hmac-sha1`, `hmac-sha256` or `hmac-sha512`. **No signing is performed.** `summary.tsig_used` reports true whenever a key name is given, even though nothing was signed. |
| `dry_run`       | Skips server discovery and returns the validated plan. |
| `format`        | `json` or `text`. |

Output: `ok`, `timestamp_unix_ms`, `query`, `summary` (`zone`, `server_used`,
`rcode`, `tsig_used`, `applied_adds`, `applied_deletes`,
`round_trip_time_ms`, `dry_run`), `details` (the parsed prerequisites, adds
and deletes), `error` (`["code", "message"]` when present), `warnings`.

## 6. Timeouts

| Verb          | `timeout_ms` |
| ------------- | ------------ |
| `lookup`      | Enforced per query attempt (default 2000). `0` or non-numeric is rejected. |
| `resolve`     | Enforced per underlying query (default 2000); a resolve may run several. `0` rejected. |
| `trace`       | Enforced per hop query (default 3000). `0` rejected. |
| `zone.fetch`  | Enforced on the TCP connect and each read (default 5000). Name server discovery without `servers` uses the resolver's own default timeout. `0` rejected. |
| `zone.update` | Validated (`0` rejected) and echoed, but there is no network operation to time out. |

## 7. Errors and exit codes

* Success exits 0. Every failure exits 1.
* Failures after the query starts print the JSON response (with `ok: false`)
  to stdout and `Error: [code] message` to stderr.
* Argument errors print only the error. For `zone.fetch` and `zone.update` the
  `[code] message` line is written to stderr directly.
* Error codes are strings such as `dns.lookup_timeout`,
  `dns.resolve_invalid_mode`, `dns.zone_fetch_invalid_transfer_type`,
  `dns.zone_update_invalid_prerequisite`.

## 8. Summary of limitations

* No `servers=` means Google Public DNS, not the system resolver.
* `authority` and `additional` are always empty; `authoritative` is always
  false; `dnssec_validated` is always null.
* `trace` cannot see referrals and glue; it is best effort.
* `zone.fetch`: no TSIG, no IXFR (falls back to AXFR), always TCP.
* `zone.update`: simulated end to end; TSIG never applied.
* Linux only.
