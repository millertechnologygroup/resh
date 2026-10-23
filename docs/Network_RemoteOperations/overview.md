# Resource Shell (resh): Network and Remote Operations

## 1. Overview

This category groups the handles that talk to other machines or inspect the
local network:

| Handle             | Purpose | Details |
| ------------------ | ------- | ------- |
| `dns://`           | DNS lookups, resolution, delegation traces, zone transfers (AXFR). `zone.update` is simulated. | [dns.md](dns.md) |
| `http://`, `https://` | HTTP requests (one handle serves both schemes). | [http.md](http.md) |
| `mail://`          | Sending email over SMTP, built-in templates, SMTP checks, stored profiles. | [mail.md](mail.md) |
| `net://`           | Local interfaces and routes, ping, TCP checks, port scans, simple DNS queries. | [net.md](net.md) |
| `ssh://`           | Remote commands and file copies through the system `ssh` client; client config inspection. Tunnels and key management are stubs. | [ssh.md](ssh.md) |

Every handle has built-in help that matches the code:

```bash
resh dns --help
resh ssh exec --help
```

Linux is the only supported and verified platform. Nothing in these handles
has been built or tested on macOS or Windows.

## 2. Command syntax

The general form is `resh <scheme>://<target>.<verb> key=value ...`, with the
verb after the last dot (dotted verbs such as `zone.fetch`, `route.list`,
`config.get` are recognized as a whole). The function-call form
`resh '<scheme>://<target>.<verb>(key=value,...)'` also works; quote it for the
shell. The target means something different for each handle:

| Handle | Target | Example |
| ------ | ------ | ------- |
| dns    | Always empty: the name is an argument. Note the dot after `//`. | `resh dns://.lookup name=example.com rtype=MX` |
| http(s)| The request URL. | `resh https://api.example.com/health.get` |
| mail   | None: the verb is the first path segment. | `resh mail://send to=ops@example.com subject=Alert 'text_body=Disk full'` |
| net    | The host (and port) to probe; `if` for interface listing. | `resh net://192.0.2.10:22.tcp_check` |
| ssh    | `[user@]host[:port]`. | `resh ssh://alice@192.0.2.10.exec command=uptime` |

More examples, one per handle:

```bash
resh dns://.resolve name=example.com mode=mail
resh http://service.internal:8080/health.get accept=json
resh mail://send_template template=welcome to=bob@example.com dry_run=true
resh net://if.list family=ipv4
resh net://192.0.2.10.ping count=3
resh ssh://deploy@web01.test
```

Global flags go before the stage: `--json-pretty` re-indents (and sorts) JSON
output; `resh --list-schemas` lists all registered schemes.

## 3. Output and exit codes

There is no shared response envelope. Each verb prints its own output, as
documented in the handle pages and in `resh <handle> <verb> --help`:

* `dns`, `mail`, `net` and `ssh` print JSON. Most
  `dns`, `mail` and `ssh` responses contain an `ok` field; `net` responses
  differ per verb (for example `tcp_check` has `ok`, `ping` has `reachable`).
* `http` prints the response body for `get`, `post`, `put`, `patch` and
  `delete` by default, and JSON for `head`, `headers`, `options`, `preflight`
  and `json`.

Exit status: 0 on success; on failure the handle's code if it is 1-255,
otherwise 1, with the reason on stderr (`Error: <reason>` when the handle did
not already write to stderr). Notable cases, all verified in the code:

* `http`: a non-2xx status exits 1 for most verbs, but `head`, `headers` and
  `json` exit 0 for any HTTP status.
* `net ping` exits 0 whenever the system `ping` ran, even if the host did not
  answer; check `reachable`. `net tcp_check` exits 111 when the connection
  fails.
* `ssh exec` exits with the remote command's exit code.

Each `resh` invocation is a separate process. No connection, session, cache
or SMTP transport is kept between invocations. The only state written to disk
by these handles is the mail profile file (see below) and files that
`ssh download` writes where you ask it to.

## 4. Timeouts

`timeout_ms` is not handled uniformly. Summary (see each page for details):

| Handle | Enforces `timeout_ms` | Ignores it |
| ------ | --------------------- | ---------- |
| dns    | `lookup`, `resolve`, `trace` (per query), `zone.fetch` (connect and each read) | `zone.update` (validated, but simulated) |
| http   | `get`, `post`, `put`, `delete`, `options`, `preflight`, `json`, `headers` | `head` (fixed 10 s), `patch` (fixed 30 s) |
| mail   | `send`, `send_template` (SMTP transport), `test` only when a test message is sent | `config` |
| net    | `dns`, `tcp_check` (per attempt), `scan` (per port); `ping` turns it into a per-reply wait in seconds | `list`, `route.list` |
| ssh    | none: use `connect_timeout_ms`, `command_timeout_ms`, `transfer_timeout_ms` and the `test` timeouts | `timeout_ms` everywhere |

Some verbs reject `timeout_ms=0` or a non-numeric value; several `http` verbs
silently fall back to their default instead.

## 5. What is not implemented

These features are visible in arguments or help but do not do real work:

* `dns zone.update`: validates the input and reports success; no UPDATE is
  sent. TSIG is never applied, for zone updates or zone transfers.
* `ssh tunnel`, `ssh keys.list`, `ssh key.add`: only `dry_run=true` succeeds;
  without it they exit 1 and change nothing.
* `ssh test`: the `sftp` and `hostkey` checks always fail.
* `mail send`: has no dry-run mode; a `dry_run` request is refused (exit 2)
  and nothing is sent. `mail test` does not contact the server unless it sends a test
  message.
* Stored mail profiles are never used for sending.

## 6. Security summary

* `http`: TLS certificates are verified. Only `put` honors
  `allow_insecure=true`, which disables verification.
* `mail`: `use_tls=none` sends credentials in clear text.
  `tls_accept_invalid_certs` does not accept invalid certificates; in `test`
  it allows a plain-text fallback. Stored SMTP passwords are base64-encoded,
  **not encrypted**, in an owner-only (`0600`) file.
* `ssh`: host keys are checked strictly by default (`known_hosts_mode` values
  are `strict`, `accept-new`, `insecure`). Remote command arguments are not
  safely quoted; never pass untrusted input. Passwords given on the command
  line or in the URL are visible in the process list.
* DNS queries without `servers=`/`server=` go to Google Public DNS, not the
  system resolver.
* Only probe or scan hosts you are authorized to test.
