# Resource Shell (resh): DNS Handle

## 1. Overview

The `dns` handle sends DNS messages itself, over UDP or TCP, and reports the
whole reply. It covers single record lookups, host, mail, service and
reverse resolution, iterative delegation traces from the root servers, zone
transfers (AXFR and IXFR, optionally TSIG-signed) and RFC 2136 dynamic
updates with optional TSIG signing.

Each verb prints one JSON document (or a text summary with `format=text`).
Linux is the only supported and verified platform.

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

A host in the URL, as in `dns://example.com.lookup`, is ignored: the name
must still be given as `name=`. The dotted verbs `zone.fetch` and
`zone.update` are recognized as a whole: `dns://.zone.fetch`.

Each `resh` run is a separate process; there is no cache shared between
invocations.

## 3. Verbs

| Verb          | What it does                                                                 | Network traffic |
| ------------- | ---------------------------------------------------------------------------- | --------------- |
| `lookup`      | Queries one record type for a name and prints the answer, authority and additional records. | Yes |
| `resolve`     | Resolves a host (following CNAMEs), or mail, service or reverse records.     | Yes             |
| `trace`       | Walks the delegation from the root servers to the name, following referrals. | Yes             |
| `zone.fetch`  | Transfers a zone with AXFR, or its changes with IXFR, over TCP.              | Yes             |
| `zone.update` | Sends an RFC 2136 dynamic UPDATE, optionally TSIG-signed.                     | Yes (none with `dry_run`) |

## 4. Which servers are asked

`lookup` and `resolve` ask the servers in `servers=`. Without it they ask the
name servers listed in the host's `/etc/resolv.conf`. In both cases `port`
and `use_tcp` apply to every server. `zone.fetch` and `zone.update` without
`servers=` look up the zone's NS records and their addresses through the
`/etc/resolv.conf` name servers (port 53, `timeout_ms` per query) and then
use those addresses with `port`.

`trace` does not use `/etc/resolv.conf`: it starts at `root_servers=` or the
built-in root hints and follows referrals (section 5.3).

## 5. Verb reference

Common rules for every verb:

* Arguments are checked before anything is sent. An argument the verb does
  not take is refused with `dns.unknown_argument` (with a "did you mean"
  hint for a likely typo); this includes `dry_run` on every verb except
  `zone.update`.
* Boolean options accept `true|false|1|0|yes|no|on|off` (any case); any
  other value is refused with `dns.invalid_argument`.
* `format` is `json` (default) or `text`; anything else is
  `dns.invalid_argument`.
* `timeout_ms` is 1 to 3600000 and `retries` 0 to 100 on every verb.
* Names are absolute; a trailing dot is optional. A name with an empty label
  (`a..b`) or starting with `-` is refused.
* Record types accepted by `rtype` (any case): A, AAAA, TXT, CNAME, MX, NS,
  SRV, PTR, SOA, CAA, ANY.
* `servers=` and `root_servers=` take a comma-separated list or a JSON
  array. For `lookup`, `resolve`, `trace` and `zone.fetch` each entry must be
  an IP address.
* Record `data` objects: A/AAAA `{"address"}`, CNAME `{"cname"}`, NS
  `{"nsdname"}`, PTR `{"ptrdname"}`, MX `{"preference","exchange"}`, TXT
  `{"text": [...]}`, SRV `{"priority","weight","port","target"}`, SOA
  `{"mname","rname","serial","refresh","retry","expire","minimum"}`, CAA
  `{"flags","tag","value"}`. Any other type (DNSKEY, RRSIG, ...) is
  `{"rdata": "<presentation format>"}`.

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
| `servers`            | `/etc/resolv.conf` name servers | IP list. |
| `port`               | `53`    | 1 to 65535. |
| `use_tcp`            | `false` | `false`: UDP, and a reply with the TC bit is asked again over TCP. |
| `timeout_ms`         | `2000`  | Per attempt. |
| `retries`            | `1`     | Extra attempts per server after a timeout or network error. |
| `dnssec`             | `false` | Sends EDNS0 with the DO bit; `dnssec_validated` then reports the AD bit of the reply (resh does not check signatures itself). |
| `follow_cname`       | `true`  | When the answer ends in a CNAME whose target has no records of `rtype` in the reply, query the target too (at most 8 extra queries). Not done for `rtype=CNAME` or `ANY`. |
| `include_authority`  | `true`  | Report the authority section. |
| `include_additional` | `true`  | Report the additional section (the EDNS OPT record is never listed). |
| `randomize_servers`  | `true`  | Shuffle the server list; `false` keeps the given order. |
| `format`             | `json`  | |

Servers are tried in turn: a timeout, a network error, or a SERVFAIL,
REFUSED, NOTIMP or FORMERR answer moves on to the next server (noted in
`warnings`). Any other answer ends the lookup. If every server failed, the
last error answer is reported, or, with no answer at all, the transport
failure.

Output (JSON, indented): `ok`, `timestamp_unix_ms`, `query` (echo of the
options), `response` (`rcode`, `authoritative` (AA bit), `truncated` (TC
bit), `dnssec_validated` (null unless `dnssec=true`), `server_used` (the
server that answered), `round_trip_time_ms`), `answers`, `authority`,
`additional`, `error`, `warnings`. Each record has `name`, `rtype`, `class`,
`ttl` and `data`. With `follow_cname`, `answers` holds the answers of every
query made, in order; the other sections come from the last reply.

NOERROR without records of `rtype` (no data) is a success with an empty or
CNAME-only `answers` and a warning.

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
| `servers`, `port`, `use_tcp`, `timeout_ms`, `retries`, `dnssec` | as for `lookup` | A resolve can run several queries; each attempt gets `timeout_ms`. |
| `max_cname_depth`  | `8`     | 0 to 64. Host mode: more CNAME hops than this fail with `dns.resolve_cname_loop`. |
| `follow_srv`       | `true`  | Service mode: resolve SRV targets to addresses. |
| `validate_reverse` | `false` | Reverse mode only (refused otherwise): look up the PTR name forward and report `forward_addresses`; a warning says when they do not include the address. |
| `want_raw`         | `false` | Fill `raw` with `{"exchanges": [{"server","name","rtype","rcode","response_hex"}]}`, one per query. |
| `format`           | `json`  | |

Output: `ok`, `timestamp_unix_ms`, `query`, `resolution` (`canonical_name`
(the end of the CNAME chain, or the name as given), `mode`, `family`,
`addresses`, `mx`, `srv`, `ptr_name`, `forward_addresses`, `source_server`
(the server that answered the first query), `round_trip_time_ms`), `raw`,
`error`, `warnings`. MX records are sorted by preference, SRV records by
priority then descending weight. A null MX (`.`) or a `.` SRV target is
listed with a warning and no addresses. An MX, SRV or PTR target that cannot
be resolved gets a warning and no addresses; it does not fail the verb.

### 5.3 trace

```bash
resh dns://.trace name=www.example.com rtype=A
resh dns://.trace name=example.com root_servers=198.41.0.4 max_depth=10
```

| Argument             | Default | Notes |
| -------------------- | ------- | ----- |
| `name`               | (required) | |
| `rtype`              | `A`     | |
| `root_servers`       | built-in root hints | IP list to start from (any servers that answer iteratively, for example a lab root). |
| `prefer_ipv6`        | `false` | Use the IPv6 root hints, and IPv6 glue before IPv4 glue. |
| `port`               | `53`    | Used for every server asked. |
| `use_tcp`            | `false` | |
| `timeout_ms`         | `3000`  | Per attempt. |
| `retries`            | `1`     | |
| `dnssec`             | `false` | EDNS0 with DO on every query; each hop reports the AD bit. |
| `max_depth`          | `15`    | 1 to 255: the most queries in the walk. |
| `follow_cname`       | `false` | On a CNAME to a name whose data is not in the reply, start a new walk from the root for the target. |
| `include_additional` | `true`  | Report each hop's additional section (glue is used either way). |
| `want_raw`           | `false` | Each hop's `raw` is `{"response_hex": ...}`. |
| `format`             | `json`  | |

The walk sends non-recursive queries (RD clear) for the name and type,
starting at the root servers. A referral (NS records in the authority
section for a zone between the current zone and the name) moves on to that
zone's servers, using glue from the additional section. A name server
without glue is resolved by a separate walk from the same root servers;
one inside the delegated zone cannot be, and is skipped with a warning. The
walk ends at an answer, at no data (NOERROR without answer or referral), or
at NXDOMAIN. Within one zone, servers are tried in order; SERVFAIL, REFUSED,
NOTIMP and FORMERR answers move on to the next server.

Output: `ok`, `timestamp_unix_ms`, `query`, `trace` (`name`, `rtype`,
`final_rcode`, `final_authoritative`, `hops`, `final_answers`, `cname_chain`,
`depth`), `error`, `warnings`. Each hop has `hop_index`, `zone` (the zone the
server was asked as authoritative for), `query_name`, `query_rtype`,
`server_ip`, `server_name`, `rtt_ms`, `rcode`, `authoritative`, `truncated`,
`dnssec` (`requested`, `do_bit`, `ad_bit`, `validated`), `ns_names`,
`ns_addresses` (glue), `answers`, `authority`, `additional`, `raw`. Every
answered query is a hop, including error answers; transport failures are
warnings. `trace` is still returned (with the hops so far) when the walk
fails.

### 5.4 zone.fetch

```bash
resh dns://.zone.fetch zone=example.com servers=192.0.2.53
resh dns://.zone.fetch zone=example.com servers=192.0.2.53 \
  tsig_key_name=xfr-key tsig_secret=c2VjcmV0 tsig_algorithm=hmac-sha256
resh dns://.zone.fetch zone=example.com servers=192.0.2.53 transfer=IXFR serial=2026010101
```

| Argument      | Default | Notes |
| ------------- | ------- | ----- |
| `zone`        | (required) | |
| `servers`     | discovered (section 4) | IP list. Servers are tried in order until one succeeds. |
| `port`        | `53`    | |
| `transfer`    | `AXFR`  | `AXFR` or `IXFR` (any case). |
| `serial`      | (none)  | Required with `transfer=IXFR` (the serial the client has), refused with AXFR. |
| `use_tcp`     | `true`  | Transfers always use TCP; `use_tcp=false` is refused with `dns.zone_fetch_tcp_required`. |
| `timeout_ms`  | `5000`  | Applied to the TCP connect, the send and each read. |
| `retries`     | `1`     | Extra attempts per server after a timeout or network error. |
| `dnssec`      | `false` | Sends EDNS0 with the DO bit. |
| `max_records` | `1000000` | The transfer fails if it holds more records (the closing SOA is not counted). |
| `prefer_ipv6` | `false` | Discovery lists IPv6 server addresses first. |
| `tsig_key_name`, `tsig_secret` | (none) | Must be given together; the secret is the base64 key. The request is then TSIG-signed (RFC 8945) and every signed reply message is verified. |
| `tsig_algorithm` | `hmac-sha256` | `hmac-sha1`, `hmac-sha256`, `hmac-sha384` or `hmac-sha512`; only with a key. |
| `include_raw` | `false` | `raw` is `{"request_hex", "response_hex": [one per reply message]}`. |
| `format`      | `json`  | |

TSIG: the first reply message must be signed (MAC over the request MAC, the
message and the TSIG variables); later messages may be unsigned, at most 99
in a row, and each signed one is verified over the prior MAC, the unsigned
messages since it and its timers (RFC 8945 section 5.3.1). The last message
must be signed. Any failure, a TSIG error from the server (BADSIG, BADKEY,
BADTIME), or an unsigned NOERROR reply fails with `dns.zone_fetch_tsig_failed`
and no records are reported. Without a key, a signed reply is accepted with
a warning that it was not verified.

IXFR (RFC 1995): the request carries the client's SOA. An incremental answer
fills `changes` (`old_serial`, `new_serial`, `deleted`, `added`: the net
changes over all difference sequences) and leaves `zone.records` empty with
`transfer_used: "IXFR"`. A single SOA no newer than `serial` means the zone
is up to date (`changes` with empty lists). A server may answer with a full
transfer instead; then `transfer_used` is `"AXFR"`, `changes` is null and a
warning says so.

Output: `ok`, `timestamp_unix_ms`, `query`, `zone` (`name`,
`transfer_requested`, `transfer_used`, `server_used`, `soa`, `serial`,
`record_count`, `records` (the zone's records, SOA first, without the closing
SOA)), `changes`, `raw`, `error`, `warnings`. Per-server failures are listed
in `warnings`. With one server its error code is reported; with several that
all failed, `dns.zone_fetch_all_servers_failed`.

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
| `servers`       | discovered (section 4) | IPs, `IP:port`, `[v6]:port` or host names, comma-separated or a JSON array. |
| `port`          | `53`    | Used for every server given without its own port. |
| `use_tcp`       | `true`  | `false` sends over UDP; a reply with the TC (truncated) bit is retried over TCP, and a message over 512 bytes always goes over TCP. |
| `timeout_ms`    | `3000`  | Per attempt (one UDP exchange, or one TCP connect, send and receive). |
| `retries`       | `1`     | Extra attempts per server after a timeout or network error. |
| `tsig_key_name`, `tsig_secret` | (none) | Must be given together. The secret is the base64 key. The message is then TSIG-signed (RFC 8945). |
| `tsig_algorithm` | `hmac-sha256` | `hmac-sha1`, `hmac-sha256`, `hmac-sha384` or `hmac-sha512`; only with a key. |
| `dry_run`       | `false` | Validates, builds and (with a key) signs the message, then stops. Nothing is sent and no servers are discovered. |
| `include_raw`   | `false` | Adds `raw` with `request_hex` (the message as sent, TSIG included) and, when a server answered, `response_hex`. |
| `format`        | `json`  | `json` or `text`. |

Record `data` uses the same fields that `lookup` prints for the type (section
5); CAA `flags` defaults to 0 and `value` is sent as given. `ANY` is accepted
only where no data is involved: in `delete_all` deletes and in prerequisites
without `data`. Names are taken as absolute (a trailing dot is added), so
write them in full, for example `www.example.com`, not `www`.

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
and deletes), `raw` (only with `include_raw`), `error` (only on failure),
`warnings`. `rcode` is the mnemonic (`NOERROR`, `REFUSED`, `NXRRSET`, ...).
`applied_adds` and `applied_deletes` are the requested counts when the
server returned NOERROR (or in a dry run) and 0 otherwise.

## 6. Timeouts

| Verb          | `timeout_ms` |
| ------------- | ------------ |
| `lookup`      | Per attempt (default 2000). |
| `resolve`     | Per attempt (default 2000); a resolve may run several queries. |
| `trace`       | Per attempt (default 3000); a trace runs at most `max_depth` queries plus the walks for name servers without glue. |
| `zone.fetch`  | TCP connect, send and each read (default 5000), and each discovery query. |
| `zone.update` | Per attempt (default 3000), for the update, the `zone_serial_at_least` SOA query and each discovery query. |

A verb that failed because its last server attempts timed out exits 124: the
outcome is unknown (for `zone.update`, the server may have applied the
update).

## 7. Errors and exit codes

* Exit 0: success.
* Exit 1: the operation failed (an error RCODE, NXDOMAIN, a network error,
  a TSIG failure, a broken transfer).
* Exit 2: invalid arguments; nothing was sent. Only the error line is
  printed, except for `zone.update` input found invalid while building the
  message (bad record data, deletes or prerequisites, `ANY` in an add),
  which also prints the JSON result.
* Exit 124: timeout (every failure was a timeout).

Failures print `Error: [<code>] <message>` on stderr. When a verb has run,
its JSON result is printed too, with `ok: false` and
`"error": {"code": "...", "message": "..."}`.

Codes for any verb:

| Code | Meaning |
| ---- | ------- |
| `dns.unknown_argument` | An argument the verb does not take (exit 2). |
| `dns.invalid_argument` | A bad boolean, `format`, `max_cname_depth` or `serial` value, `validate_reverse` without `mode=reverse`, or `serial` with AXFR (exit 2). |

lookup: `dns.lookup_invalid_name`, `dns.lookup_invalid_type`,
`dns.lookup_invalid_server`, `dns.lookup_invalid_port`,
`dns.lookup_invalid_timeout`, `dns.lookup_invalid_retries` (exit 2);
`dns.lookup_nxdomain`, `dns.lookup_servfail`, `dns.lookup_refused`,
`dns.lookup_formerr`, `dns.lookup_rcode_error` (other RCODEs),
`dns.lookup_network_error` (also: no name servers in `/etc/resolv.conf`),
`dns.lookup_all_servers_failed` (several servers, none answered) (exit 1, or
124 when every failure was a timeout); `dns.lookup_timeout` (exit 124).

resolve: `dns.resolve_invalid_name`, `dns.resolve_invalid_mode`,
`dns.resolve_invalid_family`, `dns.resolve_invalid_server`,
`dns.resolve_invalid_port`, `dns.resolve_invalid_timeout`,
`dns.resolve_invalid_retries` (exit 2); `dns.resolve_host_not_found`,
`dns.resolve_no_mx`, `dns.resolve_no_srv`, `dns.resolve_no_ptr` (the name
does not exist or has no such records), `dns.resolve_cname_loop` (a CNAME
loop or more than `max_cname_depth` hops), `dns.resolve_lookup_error` (an
error RCODE other than NXDOMAIN), `dns.resolve_network_error`,
`dns.resolve_all_servers_failed` (exit 1, or 124 when every failure was a
timeout); `dns.resolve_timeout` (exit 124).

trace: `dns.trace_invalid_name`, `dns.trace_invalid_type`,
`dns.trace_invalid_root_server`, `dns.trace_invalid_port`,
`dns.trace_invalid_timeout`, `dns.trace_invalid_retries`,
`dns.trace_invalid_max_depth` (exit 2); `dns.trace_nxdomain`,
`dns.trace_servfail`, `dns.trace_refused`, `dns.trace_rcode_error`,
`dns.trace_no_ns` (no usable address for a delegated zone's servers),
`dns.trace_loop_detected` (a referral that does not lead closer to the name,
or a CNAME loop), `dns.trace_max_depth_exceeded`, `dns.trace_network_error`,
`dns.trace_all_servers_failed` (exit 1, or 124 when every failure was a
timeout); `dns.trace_timeout` (exit 124).

zone.fetch: `dns.zone_fetch_invalid_zone`,
`dns.zone_fetch_invalid_transfer_type`, `dns.zone_fetch_missing_serial`,
`dns.zone_fetch_invalid_server`, `dns.zone_fetch_invalid_port`,
`dns.zone_fetch_invalid_timeout`, `dns.zone_fetch_invalid_retries`,
`dns.zone_fetch_invalid_max_records`, `dns.zone_fetch_invalid_tsig_config`,
`dns.zone_fetch_invalid_tsig_secret`,
`dns.zone_fetch_unsupported_tsig_algorithm`, `dns.zone_fetch_tcp_required`
(exit 2); `dns.zone_fetch_refused`, `dns.zone_fetch_nxdomain`,
`dns.zone_fetch_servfail`, `dns.zone_fetch_formerr`,
`dns.zone_fetch_rcode_error`, `dns.zone_fetch_tsig_failed`,
`dns.zone_fetch_invalid_axfr_stream` (a reply that does not start with an
SOA, ends early, or does not match the request),
`dns.zone_fetch_max_records_exceeded`, `dns.zone_fetch_network_error`,
`dns.zone_fetch_all_servers_failed` (also: discovery failed),
`dns.zone_fetch_internal_error` (the request could not be encoded) (exit 1,
or 124 when every failure was a timeout); `dns.zone_fetch_timeout` (exit
124).

zone.update:

| Condition | `error` code | Exit |
| --------- | ------------ | ---- |
| Bad argument | `dns.zone_update_invalid_zone`, `dns.zone_update_invalid_server`, `dns.zone_update_invalid_port`, `dns.zone_update_invalid_timeout`, `dns.zone_update_invalid_retries`, `dns.zone_update_invalid_max_changes`, `dns.zone_update_invalid_tsig_config`, `dns.zone_update_invalid_tsig_secret`, `dns.zone_update_unsupported_tsig_algorithm` | 2 |
| Bad record data, delete or prerequisite (also in a dry run) | `dns.zone_update_invalid_record_type`, `dns.zone_update_invalid_add_record`, `dns.zone_update_invalid_delete_spec`, `dns.zone_update_invalid_prerequisite` | 2 |
| REFUSED | `dns.zone_update_refused` | 1 |
| NXRRSET, YXRRSET, YXDOMAIN, or a failed `zone_serial_at_least` check | `dns.zone_update_precondition_failed` | 1 |
| NXDOMAIN, SERVFAIL, FORMERR, NOTAUTH, NOTZONE | `dns.zone_update_nxdomain`, `dns.zone_update_servfail`, `dns.zone_update_formerr`, `dns.zone_update_notauth`, `dns.zone_update_notzone` | 1 |
| Any other RCODE | `dns.zone_update_rcode_error` | 1 |
| TSIG verification failure | `dns.zone_update_tsig_failed` | 1 |
| The only server had a network error | `dns.zone_update_network_error` | 1 |
| The only server timed out | `dns.zone_update_timeout` | 124 |
| Several servers, all failed (or discovery failed) | `dns.zone_update_all_servers_failed` | 1, or 124 when every failure was a timeout |
| The message could not be encoded | `dns.zone_update_internal_error` | 1 |

## 8. Limitations

* `dnssec_validated` and `ad_bit` repeat the server's AD flag; resh does not
  validate DNSSEC signatures itself.
* `zone.update`: `zone_serial_at_least` is checked with a separate SOA query,
  not atomically with the update. No EDNS, so UDP messages over 512 bytes go
  over TCP.
* Discovery for `zone.fetch` and `zone.update` always queries
  `/etc/resolv.conf` name servers on port 53.
* Linux only.
