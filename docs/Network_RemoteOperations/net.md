# Resource Shell (resh): Net Handle

## 1. Overview

The `net` handle lists local network interfaces and routes, and probes remote
hosts with ping, TCP connection checks, TCP port scans and simple DNS
queries. It uses the system `ping` and `ip` commands where available, with
TCP and `/proc` fallbacks.

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
still needs a host, for example `net://localhost.route.list`.

There are no per-interface verbs such as `net://eth0.status`: the registered
verbs are exactly those in section 3.

## 3. Verbs

| Verb         | What it does | Network traffic |
| ------------ | ------------ | --------------- |
| `list`       | Lists local interfaces and their IP addresses. | No |
| `route.list` | Lists the routing table (from `ip -j route`, or `/proc/net/route`). | No |
| `dns`        | Looks up one record type for the URL host. | Yes |
| `ping`       | Pings the host with the system `ping`, or falls back to TCP connects. | Yes |
| `tcp_check`  | Tests whether a TCP connection to host:port succeeds, with retries. | Yes |
| `scan`       | Tries a list of TCP ports and reports each as open, closed, timeout or error. | Yes |

## 4. Verb reference

### list

```bash
resh net://if.list
resh net://if.list family=ipv4 up=true
```

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `family` | all     | `ipv4`, `ipv6` or `all`. |
| `up`     | (no filter) | `true` excludes loopback interfaces; `false` shows only loopback. It does **not** test whether an interface is administratively or operationally up. |

Output: `{"interfaces": [{"name", "index", "mac", "flags", "mtu", "addresses"}]}`,
each address being `{"family", "addr", "scope"}`.

Limitations: the interface library reports only interfaces that have an IP
address. `index`, `mac` and `mtu` are always null. `flags` are not read from
the kernel: every non-loopback interface is reported as
`["up", "running", "multicast"]` and loopback as `["loopback"]`, even when the
link is down. Prefix lengths are not reported.

### route.list

```bash
resh net://localhost.route.list
resh net://localhost.route.list family=all
```

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `family` | `ipv4`  | `ipv4`, `ipv6` or `all`. With `all`, an IPv6 failure is only a warning on stderr. |

Output: a JSON array (indented) of
`{"dst", "family", "gateway", "iface", "metric", "protocol", "scope", "table", "flags"}`.
When `ip` is not available, routes come from `/proc/net/route` (and
`/proc/net/ipv6_route`) with `protocol` and `scope` null. A `table` argument
is accepted and ignored.

### dns

```bash
resh net://example.com.dns
resh net://example.com.dns type=MX server=192.0.2.53
```

| Argument     | Default | Notes |
| ------------ | ------- | ----- |
| `type`       | `A`     | A, AAAA, CNAME, MX, TXT, NS, SRV, PTR. |
| `server`     | (none)  | IP address of the server to ask (UDP). |
| `port`       | `53`    | Only with `server`. |
| `timeout_ms` | `3000`  | Resolver timeout. `0` or non-numeric is rejected (exit 2). |

Output: `{"query", "rtype", "server", "records": [{"name", "ttl", "data"}]}`.
MX and SRV records report `data` as an object.

Limitations: without `server=`, the query goes to the trust-dns default
resolvers (Google Public DNS), **not** the system resolver, even though
`server` is reported as `"system"`. A, AAAA, MX, TXT and PTR records always
report a TTL of 300. For anything beyond a quick check, use the `dns` handle
(`resh dns://.lookup name=...`).

### ping

```bash
resh net://192.0.2.10.ping
resh net://192.0.2.10.ping count=5 timeout_ms=2000
resh net://example.com.ping family=ipv4
```

| Argument     | Default | Notes |
| ------------ | ------- | ----- |
| `count`      | `3`     | At least 1. |
| `timeout_ms` | `3000`  | At least 100. See below for how it is applied. |
| `family`     | `auto`  | `auto`, `ipv4`, `ipv6` (`ipv6` uses `ping6` or `ping -6`). |
| `port`       | URL port, else 80 | TCP port for the fallback. |
| `raw`        | `false` | `true` also writes the raw ping output to stderr. |

Output:

```json
{"host":"192.0.2.10","port":80,"backend":"system_ping","sent":3,"received":3,"loss":0.0,"avg_rtt_ms":0.412,"timeout_ms":3000,"reachable":true}
```

How it works and what to watch for:

* It runs `ping -c <count> -W <seconds> <host>`, where the per-reply wait is
  `timeout_ms / 1000` seconds (at least 1). `timeout_ms` is therefore **not** a
  limit on the whole command, which can take about `count` times that long.
* `received` counts output lines containing `bytes from` or `icmp_seq=`.
  ICMP error lines such as `From 192.0.2.1 icmp_seq=1 Destination Host
  Unreachable` also contain `icmp_seq=` and are **counted as replies**, so an
  unreachable host can be reported with `received > 0` and
  `reachable: true`.
* **The command exits 0 whenever `ping` could be run**, even if no reply came
  back. Check `reachable` in the JSON.
* The TCP fallback (`backend: "tcp_fallback"`) is used only when the `ping`
  binary is missing or cannot be started. It makes `count` TCP connects to
  `port`, each with a timeout of `max(200, timeout_ms / count)` ms. It accepts
  only a literal **IPv4 address** as host; a host name (or IPv6 address) makes
  it fail with exit 1.

Invalid arguments print `bad argument: ...` on stderr and exit 2.

### tcp_check

```bash
resh net://192.0.2.10:22.tcp_check
resh net://db.example.com:5432.tcp_check timeout_ms=1000 retries=3 backoff_ms=500
```

| Argument     | Default | Notes |
| ------------ | ------- | ----- |
| port (in URL)| (required) | Put the port in the URL: `net://host:port.tcp_check`. |
| `timeout_ms` | `3000`  | Per connection attempt. `0` is rejected. |
| `retries`    | `1`     | **Total** number of attempts (not extra attempts). `0` is rejected. |
| `backoff_ms` | `0`     | Pause between attempts. |

Output on success:

```json
{"host":"192.0.2.10","port":22,"ok":true,"attempts":1,"latency_ms":2,"timeout_ms":3000,"retries":1,"backend":"tcp","tls_checked":false}
```

On failure the JSON has `ok: false` and an `error` string instead of
`latency_ms`, and the command exits **111**. Argument errors exit 2.

Limitations:

* A `port=` argument does not choose the port that is connected to: the
  connection always goes to the URL port, while the output reports the
  `port=` value. With `port=` and no port in the URL the check fails.
  Always give the port in the URL.
* The host name is resolved and only the first address is tried.
* There is no TLS check. `expect_tls` is accepted (it must be `true` or
  `false`) but ignored, and `tls_checked` is always false.

### scan

```bash
resh net://192.0.2.10.scan
resh net://192.0.2.10.scan ports=22,80,443,8000-8010 timeout_ms=300 concurrency=64
```

| Argument      | Default | Notes |
| ------------- | ------- | ----- |
| `ports`       | `80,443` | Comma-separated ports and ranges, at most 4096 ports. |
| `timeout_ms`  | `500`   | Per port connection attempt. Non-numeric is rejected (exit 5). |
| `concurrency` | `32`    | Clamped to 1-256; a non-numeric value means 32. |
| `host`        | URL host | Overrides the target. |
| `protocol`    | `tcp`   | Only `tcp` (anything else exits 6). |

Output: `{"target", "protocol", "ports": [{"port", "state", "error"}], "scan": {"timeout_ms", "concurrency", "started_at", "duration_ms"}}`.
`state` is `open`, `closed` (connection refused), `timeout`, or `error`
(including name resolution failures). The command exits 0 whatever the port
states are; an invalid port list exits 3 and too many ports exits 4.

Only scan hosts you are authorized to test.

## 5. Timeouts

| Verb         | `timeout_ms` |
| ------------ | ------------ |
| `list`       | Ignored (local). |
| `route.list` | Ignored (local). |
| `dns`        | Enforced as the resolver timeout, default 3000. `0`/non-numeric rejected. |
| `ping`       | Converted to the per-reply `-W` value in whole seconds (and the per-connect timeout of the TCP fallback); not a total limit. Values below 100 rejected. |
| `tcp_check`  | Enforced per connect attempt, default 3000. `0` rejected. |
| `scan`       | Enforced per port connect, default 500. Non-numeric rejected. |

## 6. Exit codes

Verified in the code: 0 on success; `ping` 2 for bad arguments and 1 when both
ping and the TCP fallback fail; `tcp_check` 111 when the connection fails and
2 for bad arguments; `scan` 3 (bad ports), 4 (too many ports), 5 (bad
timeout), 6 (protocol); `dns` 2 for bad arguments and 1 for a failed lookup;
`route.list` 2 for a bad family or an unreadable routing table; `list` 1 for a
bad argument. On failure resh prints `Error: <reason>` on stderr unless the
handle already wrote to stderr.

## 7. Limitations

* `ping` counts ICMP error lines as replies and exits 0 for unreachable
  hosts.
* `ping` TCP fallback accepts only IPv4 address literals.
* `tcp_check` connects to the URL port only; `expect_tls` is ignored.
* `list` flags are synthesized; `index`, `mac`, `mtu` are always null.
* `dns` uses Google Public DNS when no `server` is given and fixes some TTLs
  at 300.
* Linux only.
