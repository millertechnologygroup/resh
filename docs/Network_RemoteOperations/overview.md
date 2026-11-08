# Resource Shell (resh): Network and Remote Operations

## 1. Overview

This category groups the handles that talk to other machines or inspect the
local network:

| Handle             | Purpose | Details |
| ------------------ | ------- | ------- |
| `dns://`           | DNS lookups, resolution, delegation traces, zone transfers (AXFR and IXFR, optionally TSIG-signed), RFC 2136 dynamic updates (`zone.update`, optional TSIG), all sent by resh's own DNS client. | [dns.md](dns.md) |
| `http://`, `https://` | HTTP requests (one handle serves both schemes). | [http.md](http.md) |
| `mail://`          | Sending email over SMTP, built-in templates, real SMTP session checks, stored profiles (passwords in the OS keyring). | [mail.md](mail.md) |
| `net://`           | Local interfaces and routes, ping, TCP checks, port scans, simple DNS queries. | [net.md](net.md) |
| `ssh://`           | Remote commands, file copies, connection checks, port forwarding (`tunnel`) and remote public keys (`keys.list`, `key.add`) through the system `ssh` client; client config inspection. | [ssh.md](ssh.md) |

Every handle has built-in help that matches the code (also `-h`, `help`, or
`resh help <handle> [verb]`):

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

All five handles follow the shared conventions in
[resh_overview.md 3.5](../resh_overview.md#35-shared-conventions). Every
verb refuses unknown arguments and invalid values (including `dry_run` on a
verb without a dry run) before anything is sent, with exit 2 and a "did you
mean" hint for a likely typo. Exit status: 0 success, 1 the operation
failed, 2 invalid usage (nothing was sent), 124 timeout or outcome unknown.
Every failure prints `Error: [<handle>.<code>] <message>` on stderr, and a
JSON result carries `"error": {"code", "message"}`. Notable cases:

* `http`: every verb exits 0 for a 2xx status (and a 3xx with
  `follow_redirects=false`) and 1 for any other status
  (`http.status_error`); the body or JSON is still printed.
* `net ping` exits 1 (`net.unreachable`) when no reply comes back, and
  `net tcp_check` exits 1 (`net.connect_failed`) when the connection fails.
* `ssh exec` exits 1 (`ssh.remote_exit_nonzero`) when the remote command
  exits non-zero; the remote code is in `result.exit_code`.
* Exit 124 means the outcome may be unknown: an `http` server may have
  acted on the request, `mail send` may have delivered the message, and
  `dns zone.update` may have been applied.

Each `resh` invocation is a separate process. No connection, session, cache
or SMTP transport is kept between invocations. The only state written to disk
by these handles is the mail profile file (see below) and files that
`ssh download` writes where you ask it to.

## 4. Timeouts

Every verb that waits on the network takes `timeout_ms`; verbs that do not
wait refuse it (exit 2). A malformed or out-of-range value is refused
(exit 2). Summary (see each page for details):

| Handle | Enforces `timeout_ms` | Does not take it |
| ------ | --------------------- | ---------------- |
| dns    | `lookup`, `resolve` (per attempt, default 2000), `trace` (per attempt, default 3000), `zone.fetch` (connect, send and each read, default 5000), `zone.update` (per attempt, default 3000) | none |
| http   | every verb: a deadline for the whole request, body included (default 5000 for `preflight`, 30000 for `put`, `patch` and `delete`, 10000 for the others) | none |
| mail   | `send`, `send_template` (whole command, default 10000), `test` (default 10000) | `config` |
| net    | `route.list` (default 5000), `dns` and `ping` (whole operation, default 3000), `tcp_check` (per attempt, default 3000), `scan` (per port, default 500) | `list` |
| ssh    | every connecting verb: one deadline for all of its ssh runs (no default), combined with the verb's own limits (`command_timeout_ms`, `transfer_timeout_ms`, the `test` and `keys` timeouts; `tunnel_timeout_ms` and `idle_timeout_ms` end a tunnel normally, exit 0) | `config.get` |

## 5. Limitations

The handle pages list all limitations. The ones most likely to matter:

* `dns`: `dnssec_validated` repeats the server's AD flag; resh does not
  validate DNSSEC signatures itself. `zone.update` checks
  `zone_serial_at_least` with a separate SOA query, not atomically.
* `ssh`: `identity_passphrase` needs OpenSSH 8.4 or later; in `exec`'s
  cmd/powershell modes a timed-out remote command cannot be stopped (a
  warning says so); `config.get` skips `Match exec`, `localnetwork` and
  `tagged` blocks with a warning.
* `mail send` has no dry-run mode; a `dry_run` request is refused (exit 2)
  and nothing is sent. Use `send_template ... dry_run=true` to preview a
  message. Storing a profile password needs an OS keyring.
* `http` holds the whole response body in memory, and `headers=` values
  cannot contain `;`.
* `net list` does not report prefix lengths.

## 6. Security summary

* `http`: TLS certificates are verified by every verb. `ca_file=<pem>`
  trusts a private CA with verification on; `allow_insecure=true` disables
  verification for that stage (every verb) and cannot be combined with
  `ca_file`.
* `mail`: `use_tls=none` sends credentials in clear text. STARTTLS is
  required in `starttls` mode and never falls back to plain text.
  `tls_accept_invalid_certs=true` disables certificate verification and is
  insecure; prefer `ca_file`. Stored SMTP passwords are kept in the OS
  keyring; the owner-only (`0600`) profile file holds only a reference.
* `ssh`: host keys are checked strictly by default (`known_hosts_mode` values
  are `strict`, `accept-new`, `insecure`; `test` also needs
  `allow_insecure_hostkey=true` for `insecure`). Treat `command`,
  `command_args`, `cwd`, `env` and `shell_mode` as code (see the quoting
  rules in [ssh.md](ssh.md)). Passwords given on the command line or in the
  URL are visible in the process list of `resh`; ssh gets them through the
  environment.
* `net tcp_check expect_tls=true` performs a verified TLS handshake;
  `ca_file=` adds a private CA.
* DNS queries without `servers=` go to the name servers in
  `/etc/resolv.conf`; `trace` starts at the root servers.
* Only probe or scan hosts you are authorized to test.
