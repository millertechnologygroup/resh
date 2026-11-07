# Resource Shell (resh): Net Handle

## 1. Overview

The `net` handle lists local network interfaces and routes, and probes remote
hosts with ping, TCP connection checks (optionally with a TLS handshake), TCP
port scans and simple DNS queries. It uses the system `ping` and `ip`
commands where available, with TCP and `/proc` fallbacks.

Linux is the only supported and verified platform (`route.list` refuses to run
on other systems). Each `resh` invocation is a separate process.

```bash
resh net --help
resh net ping --help
```

## 2. Command syntax

The URL host names the target; the verb follows the last dot:

```text
resh net://<host>[:<port>].<verb> key=value ...
resh 'net://<host>[:<port>].<verb>(key=value,...)'
```

```bash
resh net://192.0.2.10.ping count=3
resh net://192.0.2.10:22.tcp_check
resh net://if.list
```

`net://if` (also `net://interfaces`, `net://iface`) is the conventional
target for `list`. `list` and `route.list` ignore the target, but the URL
still needs a host, for example `net://localhost.route.list`. IPv6 literals
go in brackets: `net://[2001:db8::1]:443.tcp_check`.

There are no per-interface verbs such as `net://eth0.status`: the registered
verbs are exactly those in section 3.

Every verb accepts exactly the arguments listed for it below. Any other
argument (including `dry_run`, and `timeout_ms` on `list`) is refused with
exit 2 before anything is done, with a "did you mean" hint for likely typos.
A host that starts with `-` or contains spaces is refused the same way.
Booleans accept `true|false`, `1|0`, `yes|no` and `on|off`.

## 3. Verbs

| Verb         | What it does | Network traffic |
| ------------ | ------------ | --------------- |
| `list`       | Lists local interfaces with flags, index, MAC, MTU and IP addresses. | No |
| `route.list` | Lists the routing table (from `ip -j route`, or `/proc/net/route`). | No |
| `dns`        | Looks up one record type for the URL host. | Yes |
| `ping`       | Pings the host with the system `ping`, or falls back to TCP connects. | Yes |
| `tcp_check`  | Tests whether a TCP connection (and optionally a TLS handshake) to host:port succeeds, with retries. | Yes |
| `scan`       | Tries a list of TCP ports and reports each as open, closed, timeout or error. | Yes |

## 4. Verb reference

### list

```bash
resh net://if.list
resh net://if.list family=ipv4 up=true
```

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `family` | all     | `ipv4`, `ipv6` or `all`. With `ipv4`/`ipv6`, only interfaces that have an address of that family are listed, with only those addresses. |
| `up`     | (no filter) | `true` keeps interfaces that are administratively up (`IFF_UP`), `false` those that are down. |

Output: `{"interfaces": [{"name", "index", "mac", "flags", "mtu", "addresses"}]}`,
sorted by name, each address being `{"family", "addr", "scope"}`.

The data comes from `getifaddrs(3)`, so interfaces without an IP address are
listed too (with `addresses: []`) unless a family is given. `flags` are the
kernel interface flags, in this order when set: `up`, `broadcast`,
`loopback`, `pointopoint`, `running`, `noarp`, `promisc`, `allmulti`,
`multicast`, `lower_up`, `dormant`. `mac` is the link-layer address
(`00:00:00:00:00:00` for loopback) and null when the interface has none;
`mtu` comes from `/sys/class/net/<name>/mtu`. `scope` is `host` for loopback
addresses, `link` for 169.254.0.0/16 and fe80::/10, otherwise `global`.
Prefix lengths are not reported. `list` takes no `timeout_ms`: it does not
wait on anything.

### route.list

```bash
resh net://localhost.route.list
resh net://localhost.route.list family=all
resh net://localhost.route.list table=local
```

| Argument     | Default | Notes |
| ------------ | ------- | ----- |
| `family`     | `ipv4`  | `ipv4`, `ipv6` or `all`. With `all`, an unreadable IPv6 table is only a warning on stderr. |
| `table`      | `main`  | `main`, `local`, `default`, `all` or a table number. Other tables than `main` need the `ip` command. |
| `timeout_ms` | `5000`  | Limit for the `ip` command; past it, `ip` is stopped and the verb exits 124. |

Output: a JSON array (indented) of
`{"dst", "family", "gateway", "iface", "metric", "protocol", "scope", "table", "flags"}`.
`dst` is `default` for a default route. `flags` holds `gateway` (the route
has a gateway), `link` or `host` (its scope) and the flags `ip` reports
(such as `onlink`, `linkdown`). `iface` is null for routes without a device
(for example `unreachable` routes).

When `ip` is not installed, routes come from `/proc/net/route` (main table)
and `/proc/net/ipv6_route` with `protocol` and `scope` null and the kernel
route flags (`up`, `gateway`, `host`, ...). `/proc/net/ipv6_route` does not
say which table a route is in, so IPv6 routes read from it list every table
with `table: null`. When `ip` is installed but fails, a warning is printed
on stderr and `/proc` is read instead.

### dns

```bash
resh net://example.com.dns
resh net://example.com.dns type=MX server=192.0.2.53
resh net://192.0.2.10.dns type=PTR
```

| Argument     | Default | Notes |
| ------------ | ------- | ----- |
| `type`       | `A`     | A, AAAA, CNAME, MX, TXT, NS, SRV, PTR (case-insensitive). PTR needs an IP address as the URL host. |
| `server`     | (none)  | IP address of the server to ask (UDP). Without it, the system resolver configuration (`/etc/resolv.conf`) is used and `server` is reported as `"system"`. |
| `port`       | `53`    | Only together with `server` (refused without it). |
| `timeout_ms` | `3000`  | Limit for the whole lookup, retries included. Past it the verb exits 124. |

Output: `{"query", "rtype", "server", "records": [{"name", "ttl", "data"}]}`.
`ttl` is the TTL of the answer record. MX and SRV records report `data` as
an object (`{"priority", "exchange"}`, `{"priority", "weight", "port",
"target"}`). For A, AAAA, MX, TXT and PTR, `name` is the query as given; for
CNAME, NS and SRV it is the record owner name (fully qualified, with a
trailing dot). A name that does not exist, or has no record of that type,
fails with `net.lookup_failed` (exit 1). For anything beyond a quick check,
use the `dns` handle (`resh dns://.lookup name=...`).

### ping

```bash
resh net://192.0.2.10.ping
resh net://192.0.2.10.ping count=5 timeout_ms=6000
resh net://example.com.ping family=ipv4
```

| Argument     | Default | Notes |
| ------------ | ------- | ----- |
| `count`      | `3`     | Number of replies wanted, at least 1. |
| `timeout_ms` | `3000`  | Limit for the whole ping, at least 100; rounded up to whole seconds for the system `ping`. |
| `family`     | `auto`  | `auto`, `ipv4` (`ping -4`), `ipv6` (`ping6`, or `ping -6`). |
| `port`       | URL port, else 80 | TCP port for the fallback. |
| `raw`        | `false` | `true` also writes the raw ping output (and why the fallback was used) to stderr. |

Output:

```json
{"host":"192.0.2.10","port":80,"backend":"system_ping","sent":3,"received":3,"loss":0.0,"avg_rtt_ms":0.412,"timeout_ms":3000,"reachable":true}
```

How it works:

* It runs `ping [-4|-6] -c <count> -w <seconds> <host>`: ping stops when
  `count` replies came back or after `timeout_ms` (whole seconds). `sent`
  and `received` are read from ping's summary line, so ICMP error lines such
  as `Destination Host Unreachable` are not counted as replies. `sent` can
  differ from `count`: some ping implementations keep probing an
  unanswering host until the deadline.
* **Exit codes:** 0 when at least one reply came back; 1 with
  `"reachable": false` and `error.code` `net.unreachable` when none did
  (the JSON is still printed); 1 with `net.resolve_failed` when the host
  name does not resolve; 124 with `net.timeout` when `ping` does not end on
  its own and is stopped.
* The TCP fallback (`backend: "tcp_fallback"`) is used when the `ping`
  command is missing or cannot run (for example `socket: Operation not
  permitted`). It makes up to `count` TCP connects to `port` (host names and
  IPv4/IPv6 addresses are accepted; `family` selects the address family),
  each with a timeout of `max(200, timeout_ms / count)` ms, all within
  `timeout_ms`. A connect that succeeds is a reply; a refused connection is
  not. If the fallback cannot run at all (no address for the host), the
  verb fails with `net.ping_failed` (exit 1).

### tcp_check

```bash
resh net://192.0.2.10:22.tcp_check
resh net://db.example.com:5432.tcp_check timeout_ms=1000 retries=3 backoff_ms=500
resh net://example.com.tcp_check port=443 expect_tls=true
```

| Argument     | Default | Notes |
| ------------ | ------- | ----- |
| `port`       | URL port | Port to connect to; overrides the URL port. One of the two is required. |
| `timeout_ms` | `3000`  | Per attempt: name resolution, connect and (with `expect_tls`) the TLS handshake. |
| `retries`    | `1`     | **Total** number of attempts (not extra attempts), 1-1000. |
| `backoff_ms` | `0`     | Pause between attempts. |
| `expect_tls` | `false` | `true` also completes a TLS handshake and verifies the certificate chain and the host name (or IP address) against the CA bundle. |

The whole check takes at most `retries` x (`timeout_ms` + `backoff_ms`). Each
attempt resolves the host and tries its addresses in turn until one
connects.

With `expect_tls=true`, the trusted CAs are read from the file named by the
`SSL_CERT_FILE` environment variable, else from the system bundle
(`/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`,
`/etc/ssl/ca-bundle.pem`, `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`
or `/etc/ssl/cert.pem`). TLS 1.2 and 1.3 are supported. A server that does
not speak TLS, presents a certificate for another name, or one signed by an
untrusted CA fails the check (`net.tls_failed`).

Output on success:

```json
{"host":"192.0.2.10","port":22,"ok":true,"attempts":1,"latency_ms":2,"timeout_ms":3000,"retries":1,"backend":"tcp","tls_checked":false}
```

`tls_checked` is true when a TLS handshake was made. On failure the JSON has
`ok: false` and `"error": {"code", "message"}` instead of `latency_ms`; the
code is the one of the last attempt: `net.connect_failed` (refused,
unreachable; exit 1), `net.resolve_failed` (exit 1), `net.tls_failed`
(exit 1) or `net.timeout` (exit 124: no answer, the outcome is unknown).

### scan

```bash
resh net://192.0.2.10.scan
resh net://192.0.2.10.scan ports=22,80,443,8000-8010 timeout_ms=300 concurrency=64
```

| Argument      | Default | Notes |
| ------------- | ------- | ----- |
| `ports`       | `80,443` | Comma-separated ports and ranges (1-65535), at most 4096 distinct ports. Duplicates are scanned once; the order is kept. |
| `timeout_ms`  | `500`   | Per port connection attempt. |
| `concurrency` | `32`    | Clamped to 1-256 (the clamped value is reported). |
| `host`        | URL host | Overrides the target. |
| `protocol`    | `tcp`   | Only `tcp`. |

Output: `{"target", "protocol", "ports": [{"port", "state", "error"}], "scan": {"timeout_ms", "concurrency", "started_at", "duration_ms"}}`.
`state` is `open`, `closed` (connection refused), `timeout`, or `error`
(including name resolution failures). The host name is resolved once (with
a limit of `max(timeout_ms, 5000)` ms). A scan takes at most about
`ceil(ports / concurrency)` x `timeout_ms` per address of the host.

The command exits 0 whatever the port states are, unless no port could be
probed at all (every state is `error`, for example a name that does not
resolve): then it exits 1 with `net.scan_failed` (the port list is still
printed).

Only scan hosts you are authorized to test.

## 5. Timeouts

| Verb         | `timeout_ms` |
| ------------ | ------------ |
| `list`       | Refused (exit 2): it does not wait. |
| `route.list` | Limit for the `ip` command, default 5000; exit 124 when exceeded. |
| `dns`        | Limit for the whole lookup, default 3000; exit 124 when exceeded. |
| `ping`       | Limit for the whole ping, default 3000 (whole seconds for the system `ping`, which stops itself; it is stopped 2 s later if it does not). |
| `tcp_check`  | Per attempt, default 3000. Exit 124 when the last attempt timed out. |
| `scan`       | Per port connect, default 500. |

Every `timeout_ms` and `backoff_ms` is an integer from 1 (0 for
`backoff_ms`) to 86400000; `ping` needs at least 100.

## 6. Errors and exit codes

| Exit | Meaning |
| ---- | ------- |
| 0    | Success. |
| 1    | The operation failed (not found, refused, unreachable, tool error). |
| 2    | Invalid usage or arguments; nothing was done. |
| 124  | Timeout, or the outcome is unknown. |

Every failure prints `Error: [<code>] <message>` on stderr and a JSON object
on stdout whose `error` is `{"code", "message"}`. For argument and setup
failures the object is `{"verb", "error"}` (plus `query`/`rtype` for `dns`,
`host` for `ping` and `tcp_check`, `backend` for `route.list`); `ping`,
`tcp_check` and `scan` failures that have a result print the result with an
`error` field added.

| Code | Exit | When |
| ---- | ---- | ---- |
| `net.invalid_argument` | 2 | Unknown argument, invalid value, missing host or port, `port` without `server` (dns), PTR for a name, unknown verb. |
| `net.lookup_failed` | 1 | `dns`: the lookup failed (no such name, no record of that type, server error). |
| `net.resolve_failed` | 1 | `ping`, `tcp_check`: the host name does not resolve. |
| `net.timeout` | 124 | `dns`, `ping`, `route.list`, `tcp_check`: the time limit was reached. |
| `net.unreachable` | 1 | `ping`: no reply came back. |
| `net.ping_failed` | 1 | `ping`: the system ping could not run and the TCP fallback could not either. |
| `net.connect_failed` | 1 | `tcp_check`: the connection was refused or the network is unreachable. |
| `net.tls_failed` | 1 | `tcp_check expect_tls=true`: no usable CA bundle, or the TLS handshake or certificate check failed. |
| `net.scan_failed` | 1 | `scan`: no port could be probed. |
| `net.route_read_failed` | 1 | `route.list`: neither `ip` nor `/proc` could give the routes (or a table other than `main` without `ip`). |
| `net.interfaces_failed` | 1 | `list`: `getifaddrs` failed. |
| `net.unsupported_platform` | 1 | `route.list` on a system other than Linux. |

## 7. Limitations

* `list` does not report prefix lengths.
* `route.list` without the `ip` command reads only the main IPv4 table, and
  IPv6 routes without table information.
* `dns` with `server=` asks that server over UDP only; answers over 512
  bytes are not retried over TCP.
* `scan` and `tcp_check` use TCP only; there is no UDP scan.
* `tcp_check expect_tls=true` has no option to skip certificate
  verification or to choose the CA bundle other than `SSL_CERT_FILE`.
* Linux only.
