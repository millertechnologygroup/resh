# Resource Shell (resh): DNS Handle

## 1. Overview

The `dns` handle queries DNS through the trust-dns (0.23) resolver library. It
covers single record lookups, host, mail, service and reverse resolution,
delegation traces from the root servers, full zone transfers (AXFR), and
RFC 2136 dynamic updates with optional TSIG signing: see
[zone.update](#55-zoneupdate).

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
| `zone.update` | Sends an RFC 2136 dynamic UPDATE, optionally TSIG-signed.                     | Yes (none with `dry_run`) |

## 4. Which resolver is used

When `servers=` is not given, `lookup`, `resolve` and `trace` (for name
servers without glue) do **not** read `/etc/resolv.conf`. They use the
trust-dns default configuration, which is Google Public DNS (8.8.8.8,
8.8.4.4 and their IPv6 equivalents). `zone.fetch` and `zone.update` use the
same default resolver to find a zone's authoritative servers when `servers=`
is not given.

To query your own resolver, pass it explicitly, for example
`servers=192.0.2.53`. For `lookup`, `resolve` and `trace`, `port` and
`use_tcp` then apply; without `servers=` they are recorded in the `query`
echo but have no effect. `zone.update` always applies `port` and `use_tcp`,
also to the discovered name servers.

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

### 5.5 zone.update

```bash
resh dns://.zone.update zone=example.com servers=192.0.2.53 dry_run=true
resh dns://.zone.update zone=example.com servers=192.0.2.53 \
  tsig_key_name=update-key tsig_secret=c2VjcmV0 tsig_algorithm=hmac-sha256 \
  adds='[{"name":"www.example.com","rtype":"A","ttl":300,"data":{"address":"203.0.113.10"}}]' \
  deletes='[{"name":"old.example.com","rtype":"A","data":{"address":"192.0.2.9"}}]' \
  prerequisites='[{"kind":"record_not_exists","name":"www.example.com","rtype":"A"}]'
```

Builds one RFC 2136 UPDATE message for the zone, sends it to a server and
reports the server's RCODE. The zone section is `<zone> IN SOA`, the
prerequisites go in the prerequisite (answer) section, and the deletes and
then the adds go in the update (authority) section. The server applies the
whole message or nothing.

| Argument        | Default | Notes |
| --------------- | ------- | ----- |
| `zone`          | (required) | The zone to update. |
| `adds`          | `[]`    | JSON array of `{"name", "rtype", "ttl", "data"}`. Added with class IN and the given TTL. |
| `deletes`       | `[]`    | JSON array. `{"name", "rtype", "data"}` deletes one record. `{"name", "rtype", "delete_all": true}` deletes the whole RRset of that type. `{"name", "delete_all": true}` deletes every record at the name. |
| `prerequisites` | `[]`    | JSON array of `{"kind", ...}`, see below. |
| `max_changes`   | `1000`  | Adds plus deletes may not exceed it. `0` is rejected. |
| `servers`       | discovered NS addresses | A single IP, `IP:port`, or a JSON array of them. A comma-separated string is **not** split. Without it the zone's NS records are looked up through the default resolver (section 4). |
| `port`          | `53`    | Used for every server given without its own port. `0` is rejected. |
| `use_tcp`       | `true`  | `false` sends over UDP; a reply with the TC (truncated) bit is retried over TCP, and a message over 512 bytes always goes over TCP. |
| `timeout_ms`    | `3000`  | Per attempt (one UDP exchange, or one TCP connect, send and receive). `0` is rejected. |
| `retries`       | `1`     | Extra attempts per server after a timeout or network error (attempts = retries + 1). At most `100`. |
| `tsig_key_name`, `tsig_secret` | (none) | Must be given together. The secret is the base64 key. The message is then TSIG-signed (RFC 8945). |
| `tsig_algorithm` | `hmac-sha256` | `hmac-sha1`, `hmac-sha256`, `hmac-sha384` or `hmac-sha512`. |
| `dry_run`       | `false` | Validates, builds and (with a key) signs the message, then stops. Nothing is sent and no servers are discovered. |
| `include_raw`   | `false` | Adds `raw` with `request_hex` (the message as sent, TSIG included) and, when a server answered, `response_hex`. |
| `format`        | `json`  | `json` or `text`. |

Record `data` uses the same fields that `lookup` prints for the type:

| `rtype` | `data` |
| ------- | ------ |
| A, AAAA | `{"address": "192.0.2.10"}` |
| CNAME   | `{"cname": "target.example.com"}` |
| NS      | `{"nsdname": "ns1.example.com"}` |
| PTR     | `{"ptrdname": "host.example.com"}` |
| MX      | `{"preference": 10, "exchange": "mail.example.com"}` |
| TXT     | `{"text": ["string", ...]}` (each string at most 255 bytes) |
| SRV     | `{"priority": 10, "weight": 5, "port": 5060, "target": "sip.example.com"}` |
| SOA     | `{"mname", "rname", "serial", "refresh", "retry", "expire", "minimum"}` |
| CAA     | `{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}` (`flags` defaults to 0; `value` is sent as given) |

`ANY` is accepted only where no data is involved: in `delete_all` deletes and
in prerequisites without `data`. Names are taken as absolute (a trailing dot
is added), so write them in full, for example `www.example.com`, not `www`.

Prerequisites (RFC 2136 section 2.4):

| `kind` | Fields | Meaning |
| ------ | ------ | ------- |
| `record_exists` | `name`, optional `rtype`, optional `data` | Without `data`: an RRset of `rtype` exists at `name` (any type if `rtype` is omitted). With `data` (needs a concrete `rtype`): that exact record exists. |
| `record_not_exists` | `name`, optional `rtype` | No RRset of `rtype` exists at `name` (no records at all if `rtype` is omitted). `data` is rejected. |
| `name_in_use` | `name` | The name owns at least one record. |
| `name_not_in_use` | `name` | The name owns no records. |
| `zone_serial_at_least` | `serial` | Not an RFC 2136 prerequisite. Before the update, resh queries the zone's SOA from the same server (TSIG-signed when a key is set) and does not send the update if the serial is lower than `serial` (RFC 1982 serial arithmetic). The check and the update are two separate messages, so a change in between is not detected. |

Servers are tried in order. Only a timeout, a network error or an unusable
reply moves on to the next server (and is listed in `warnings`); any DNS
answer ends the operation. The reply must carry the request's message ID
(UDP replies with another ID are ignored).

With TSIG, the reply's signature is verified. A reply with a bad signature,
a TSIG error from the server (BADSIG, BADKEY, BADTIME) or an unsigned NOERROR
fails with `dns.zone_update_tsig_failed`. An unsigned error reply is reported
with its RCODE and a warning.

Output: `ok`, `timestamp_unix_ms`, `query`, `summary` (`zone`, `server_used`,
`rcode`, `tsig_used`, `applied_adds`, `applied_deletes`,
`round_trip_time_ms`, `dry_run`), `details` (the parsed prerequisites, adds
and deletes), `raw` (only with `include_raw`), `error` (`["code", "message"]`
when present), `warnings`. `rcode` is the mnemonic (`NOERROR`, `REFUSED`,
`NXRRSET`, ...). `applied_adds` and `applied_deletes` are the requested
counts when the server returned NOERROR (or in a dry run) and 0 otherwise.
`tsig_used` is true when the message was signed.

Error codes once the input has been parsed:

| Condition | `error` code |
| --------- | ------------ |
| REFUSED | `dns.zone_update_refused` |
| NXRRSET, YXRRSET, YXDOMAIN, or a failed `zone_serial_at_least` check | `dns.zone_update_precondition_failed` |
| NXDOMAIN, SERVFAIL, FORMERR, NOTAUTH, NOTZONE | `dns.zone_update_nxdomain`, `dns.zone_update_servfail`, `dns.zone_update_formerr`, `dns.zone_update_notauth`, `dns.zone_update_notzone` |
| Any other RCODE | `dns.zone_update_rcode_error` |
| TSIG verification failure | `dns.zone_update_tsig_failed` |
| Bad record data, delete or prerequisite (also in a dry run) | `dns.zone_update_invalid_add_record`, `dns.zone_update_invalid_delete_spec`, `dns.zone_update_invalid_prerequisite` |
| The only server timed out, or had a network error | `dns.zone_update_timeout`, `dns.zone_update_network_error` |
| Several servers, all failed | `dns.zone_update_all_servers_failed` |

## 6. Timeouts

| Verb          | `timeout_ms` |
| ------------- | ------------ |
| `lookup`      | Enforced per query attempt (default 2000). `0` or non-numeric is rejected. |
| `resolve`     | Enforced per underlying query (default 2000); a resolve may run several. `0` rejected. |
| `trace`       | Enforced per hop query (default 3000). `0` rejected. |
| `zone.fetch`  | Enforced on the TCP connect and each read (default 5000). Name server discovery without `servers` uses the resolver's own default timeout. `0` rejected. |
| `zone.update` | Enforced per attempt (default 3000), for the update and for the `zone_serial_at_least` SOA query. Name server discovery without `servers` uses the resolver's own default timeout. `0` rejected. |

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
* `zone.update`: `zone_serial_at_least` is checked with a separate SOA query,
  not atomically with the update. No EDNS, so UDP messages over 512 bytes go
  over TCP.
* Linux only.
