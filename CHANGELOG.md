# Changelog

All notable changes to resh will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Changes since v1.0.6-beta. Every one of resh's 28 handles (29 URL schemes:
`http` and `https` are one handle) was audited against its help and its
documentation page, fixed where it did not do what they say, and given tests
for every verb. All handles now follow one set of conventions, described in
`docs/resh_overview.md` 3.5. Many of the changes below are **breaking** for
scripts: read "Breaking changes" before upgrading. Per-handle details are in
the handle pages and in `docs/known_issues.md` ("Unreleased").

### Highlights
- **One contract for every handle.** Exit codes are 0 success, 1 failed,
  2 invalid usage (nothing was done) and 124 timeout or unknown outcome.
  Every failure prints `Error: [<handle>.<code>] <message>` on stderr, and
  JSON results carry `"error": {"code", "message"}`.
- **Strict arguments.** Every verb refuses unknown arguments, invalid values,
  options of another mode or backend, and `dry_run`/`timeout_ms` where it
  does not support them (exit 2, with a "did you mean" hint), before doing
  anything. Options that were accepted and ignored now work or are refused.
- **Timeouts that hold.** Every verb whose work can be long takes
  `timeout_ms` and stops cleanly at the deadline, child processes included.
  Watch and follow verbs end normally (exit 0) at it.
- **No more stubs or simulations.** `ssh tunnel`, `keys.list` and `key.add`,
  `secret` vault scope and `rotate`, `dns zone.update` and `trace`, signed
  zone transfers, `mail test`, `backup schedule`, `proc limits.set` on the
  target process, `cert` CMS signatures, encrypted keys and `chain.info`,
  `event` hooks, and `user` password hashing now do real work.
- **Secrets and files.** Stored secrets (`secret://local`, mail profile
  passwords) live in the OS keyring. Files that may hold secrets or
  configuration are owner-only (0600/0700), writes never follow a planted
  symbolic link, and TLS-verifying verbs take `ca_file=` for a private CA.
- **Help everywhere.** `--help`, `-h`, `help`, `resh help <handle> [verb]`,
  `<scheme>://help`, `<stage> --help` and `?help` / `?help=<verb>` in a
  stage URL; an unknown handle or verb is an error (exit 2) with a
  suggestion.
- **Tested end to end.** Every verb has unit/dispatch and binary tests;
  verbs that change the host or talk to servers are also tested against real
  tools and services in throwaway Docker containers (see "Testing").

### Breaking changes

All handles and the CLI:
- Unknown arguments, misspelled arguments and invalid values are refused with
  exit 2 instead of being ignored; booleans accept only
  `true/false/1/0/yes/no/on/off`.
- Exit codes are 0/1/2/124 everywhere (handle-specific codes such as 3, 4, 7,
  111 or a backend's own exit status are gone; see the handles below).
- Every error line is `Error: [<handle>.<code>] <message>`. JSON errors are
  `{"code", "message"}` objects (some handles printed a string, an array or
  separate fields). Errors raised before a handle runs use
  `resh.invalid_stage`, `resh.unknown_handle`, `<handle>.invalid_target` and
  `<handle>.invalid_argument` with exit 2 (were ad-hoc messages with exit 1).
- A help request for an unknown handle or verb exits 2 with a suggestion (it
  printed the global help and exited 0). A bare handle name used as a stage
  (`resh file`) is refused with exit 2.
- `key=value` values are passed exactly as given; they were trimmed.
- Stage output is streamed to stdout as it is written (only `--json-pretty`
  buffers).

archive:
- The error line gained the `Error: ` prefix; the JSON `error` is a
  `{"code", "message"}` object (was a `[code, message]` array); `test`
  entries carry an `error` object instead of `error_code`/`error_message`.
- An invalid `max_file_bytes`/`max_total_bytes` on `extract` exits 2 (was 1).
- Extract size limits report `archive.extract_max_size_exceeded` /
  `extract_max_file_size_exceeded`, and the tar header-data limit
  `archive.<verb>_archive_read_error` (instead of
  `extract_archive_read_error`).
- Globs are shell-style: `*` and `?` no longer cross `/`; `**` does.
- `add` stores uid/gid 0 unless `preserve_owner=true`; `extract
  follow_symlinks=true` is refused; the `remove` backup is
  `<archive>.<suffix>` and is a copy; `test` fails when `max_entries` is
  exceeded.

backup:
- A backend failure exits 1 (was the backend's own exit status), with that
  status in `error.details.exit_code`; a missing required argument exits 2
  with an envelope. The envelope gained `error.code` (`error.kind` is kept).
- `list` and `verify` refuse `dry_run`; `keep_*` must be at least 1;
  `password=` warns on stderr.
- `schedule` installs the job instead of only reporting it; its `runner` and
  `definition_path` were removed.

cache:
- The per-verb codes (`cache.get_timeout`, ...) are replaced by the set in
  `cache.md`; the JSON error is `{"alias","backend","error":{"code","message"}}`.
- `value=` is stored exactly as typed; memcached TTLs round up to whole
  seconds (500 ms no longer means "never expires"); a `#insecure` URL
  fragment is refused.

cert:
- Exit codes are 0/1/2/124 (verbs used 1-7; a failed `verify` exited 7, now
  1). Unknown arguments are refused and unexpected boolean spellings are no
  longer read as `false`.
- `timeout_ms` is refused by `info`, `verify`, `chain.info` and `csr.sign`,
  and `dry_run` by every verb.
- `verify disallow_weak_signatures` was removed and is refused; SHA-1 and MD5
  signatures are always rejected.
- `info` fingerprints changed: they are now digests of the whole certificate
  (they were wrong); an unrecognised DER file is an error.

config:
- Errors are coded (`Error: [config.not_found] not found`, was
  `Error: not found`).
- Exit codes follow the convention: I/O errors exit 1 (were 3), a corrupt
  stored value exits 1 with `config.corrupt_value` (was 2), `set` without
  `value` and an empty key exit 2 (were 1).
- Targets with a `.` or `..` segment are refused (`..` used to resolve above
  the config directory); `timeout_ms` is refused by `get`, `set` and `ls`.

cron:
- Usage errors exit 2 with `cron.<verb>_invalid_argument` (were 1); empty
  values and values with control characters are refused; options of the
  backend that does not run are refused.
- Booleans other than `dry_run` were true only for the exact value `true`.
- `rm`, `enable` and `disable` require every selector given to match (AND).
- Next-run times use the host's local zone (were UTC) and follow cron's
  weekday rules (numeric weekdays were a day early).
- `add backend=auto` follows the options given and, with none, uses systemd
  only when systemd is the running init system (a `systemctl` binary alone no
  longer counts).
- `add timezone=` with the cron backend is refused unless the cron is cronie
  (`cron.add_timezone_unsupported`).

db:
- Remote hosts default to `tls_mode=verify_full` (without `tls_mode`, an SSL
  mode in the DSN or `PGSSLMODE`); `prefer` stays the default only for
  localhost and Unix sockets. A remote server with a self-signed certificate
  needs `ca_file=` or an explicit `tls_mode`.
- Each verb uses one connection: pool options, `tx_id` and `transaction
  action=begin|commit|rollback` are refused; `return_last_insert_id` is
  refused on PostgreSQL; `sql=` must be one statement.
- `db.connection_not_found` is now `db.dsn_missing`.
- NUMERIC/DECIMAL values are exact strings; unsupported column types fail
  with `db.unsupported_column_type` instead of becoming null.
- A SQLite database (or its `-journal`, `-wal`, `-shm` file) that is a
  symbolic link is refused.

dns:
- Without `servers=`, `lookup` and `resolve` ask the name servers in
  `/etc/resolv.conf` (they asked Google Public DNS).
- JSON errors are objects for every verb; strict arguments.

event:
- The old `event.emit_*`, `event.subscribe_*` and `event.list_topics_*`
  codes are replaced (see `event.md` 3.5); invalid arguments exit 2 (were 1).
- `tags`/`match_tags` must be JSON arrays; `list-topics sources` other than
  `event` are refused (the built-in sample catalogues are gone).
- No state directory is an error (`event.store_unavailable`) instead of a
  silent per-process in-memory bus.
- Hooks are off by default and do real work; the `proc` hook was removed.

file:
- Errors print `Error: [file.<code>] <message>` with lower-case codes (was
  `Error: <CODE>: <message>`, for example `NOT_FOUND` is now
  `file.not_found`); `verify` reports `error` as an object.
- `find` no longer descends into hidden directories, and its `name=` globs
  are shell-style.
- `append` refuses a symbolic link at the path instead of writing through it.

firewall:
- Input-validation refusals (invalid port, protocol, CIDR, field,
  unsupported option) exit 2 instead of 1. Several codes were renamed or
  merged (see `firewall.md`).
- `timeout_ms` is one deadline for the whole verb (was per command).
- `backend=auto` prefers a running firewalld and an active ufw over
  nftables; failed listings are errors instead of empty lists.

fs:
- Errors are coded (were `Error: <message>`); `unmount` `errors` entries
  carry `error: {code, message}`. `fs.unknown_error` became `fs.failed`;
  `fs.profile_not_found` and `fs.unmount_option_unsupported` were removed.
- Unknown arguments are refused, and `mount`/`unmount` no longer read an
  unrecognised boolean as false. `max_pass` is refused; mount targets that
  are symbolic links are refused; a repair of a mounted xfs/btrfs is refused
  instead of silently only checking.

git:
- Errors print `Error: [git.<code>] <message>` (was `Error: git.<code>:
  <message>`); every verb refuses unknown arguments.
- `pull` and `sync` merge or rebase diverged history (`sync` rebases by
  default) instead of refusing anything but a fast-forward.

http / https:
- Every verb exits 1 (`http.status_error`) for a status other than 2xx (or
  3xx with `follow_redirects=false`); `head`, `headers` and `json` exited 0
  for any status. Network failures exit 1 (`delete` used 2); timeouts exit
  124.
- `dry_run`, malformed `headers`, and `body` with `body_file` are refused
  (exit 2).

log:
- "Not found", "not a file" and a failing `journalctl` exit 1 (were 2 or
  `journalctl`'s own status); a relative path is reported as `./x`.

mail:
- `tls_accept_invalid_certs=true` disables certificate verification (it used
  to switch the TLS mode or fall back to plain text); STARTTLS is always
  required in `starttls` mode.
- `test` opens a real SMTP session; `send`, `send_template` and `test` use the
  active stored profile when no host is given.
- `mail://` arguments are no longer rewritten into `send`; `config` refuses
  `timeout_ms`.
- Profile passwords move to the OS keyring (legacy base64 passwords are read
  with a warning and moved on the next write); without a keyring, storing a
  password is refused.

mq:
- `get`/`peek` on an empty queue exit 1 with `mq.empty` (was 2).
- Queue names must be 1-120 letters, digits, `.`, `-`, `_` (not starting with
  `.`); other targets such as `mq://team/a` are refused instead of being
  rewritten to a shared name.
- `len`, `peek` and `create` refuse `timeout_ms`; `len`/`peek`/`get`/`purge`
  no longer create missing queues; there is no `/tmp` fallback.

net:
- `ping` exits 1 (`net.unreachable`) when the host does not answer (was 0);
  `tcp_check` exits 1 (`net.connect_failed`) when the connection fails (was
  111).
- `list up=` means the interface is administratively up (`IFF_UP`).
- `dry_run` is refused by every verb and `timeout_ms` by `list`.

pkg:
- Every verb reads only `input=<json>`: any other argument, an unknown JSON
  key (also in package entries), a wrong type or an invalid value is refused
  (exit 2, `pkg.invalid_argument`). Options a manager cannot honor are
  refused (`pkg.unsupported_option`) instead of being ignored.
- Errors are `Error: [pkg.<code>] ...` with exit 0/1/2/124 (were uncoded,
  exit 1).
- `restore` defaults to `mode: exact` and installs, upgrades and downgrades to
  the locked versions (it reinstalled missing packages by name).
- `info` and `search` `repository` is the suite/component (such as
  `noble/main`); the source URL moved to the new `repository_url` field.
- apt lockfiles from earlier releases recorded the `apt-cache policy` priority
  as the repository, so every package reports a repository mismatch; take a
  new snapshot.
- A package `source` (install, remove) is refused; `info include_repo: false`
  and `list_installed include_versions: false` set `repository` / `version`
  to null.

plugin:
- Registry artifacts must be signed (Ed25519) by a trusted publisher key.
  Unsigned or untrusted artifacts are refused before download
  (`plugin.signature_required` / `plugin.signature_invalid`) unless
  `allow_unsigned=true`. No official key is built in yet: trust registry keys
  with `plugin://keys.add` or `trust_key=`.
- The registry SHA-256 is required; registry, index and artifact URLs must be
  `https://`. JSON errors are `{"code", "message"}`.
- Plugin verbs refuse store directories that are symbolic links, belong to
  another user or are writable by others (`plugin.unsafe_path`), so running
  them as root with another user's HOME is refused.
- `disable` refuses while the plugin runs unless `force=true`;
  `available.list` uses a catalog built into resh.

proc:
- "Process not found" and permission errors exit 1 (`proc.not_found`,
  `proc.permission_denied`; were 3 and 4); invalid `nice`/`class` values and
  an invalid PID exit 2 (were 3).
- Every verb but `nice.get` refuses the resh process itself (`self`, its PID,
  or `limits.set pid=`) with exit 2; `self` was accepted by every verb.
- `setPriority nice=` outside -20..19 is refused (was clamped);
  `nice.inc`/`nice.dec` take `delta=0..39`; signal numbers must be
  0..SIGRTMAX; USR1/USR2 are 10/12.
- `nice.set`, `nice.inc`, `nice.dec` and `setPriority` change every thread of
  the process and report a `threads` array; a partial change exits 1 with
  `proc.partial_failure`.
- `timeout_ms` is refused by every verb, and `dry_run` by every verb but
  `limits.set`.

secret:
- `local` values are stored in the OS keyring; `local.json` becomes a
  names-only index. Without a keyring, writes are refused (exit 1,
  `secret.keyring_unavailable`). Legacy plaintext files are read with a
  warning and migrated on the next write.
- `env` writes exit 2 (`secret.read_only`); `redact` takes the shared boolean
  spellings; `value=` with `from_env=`, or an empty value, is refused
  (exit 2); the JSON `error` is an object.

snapshot:
- Errors print `Error: [snapshot.<code>] <message>`; the JSON `error` is an
  object and the top-level `message` field is gone. An unknown verb exits 2
  (was 1).
- `dry_run` is refused by `create`, `diff` and `ls`. New snapshots store the
  copy under `content/` next to `meta.json` (earlier layouts are still read).

ssh:
- `exec` exits 1 (`ssh.remote_exit_nonzero`) for a non-zero remote exit; the
  remote code is in `result.exit_code` (resh used to exit with the remote
  code).
- Unknown arguments, invalid values and options of another mode are refused
  (exit 2); `test`, `tunnel`, `keys.list` and `key.add` require a user name;
  `known_hosts_mode=accept_new` is refused (use `accept-new`).

svc:
- An unknown verb and a bad `count`, `state`, `lines` or `level` exit 2;
  service names may contain only letters, digits, `_`, `.`, `@`, `-` and
  `\`.
- `start` and `restart` exit 1 (`svc.not_active`) when the unit does not keep
  running for `settle_ms` (default 1000) after its job; a failed systemd job
  exits 1 (`svc.job_failed`).
- `enable` and `mask` no longer replace conflicting links unless
  `force=true` (`svc.link_conflict`, exit 1).
- Names ending in a unit type (`.socket`, `.timer`, ...) are used as given;
  verbs that do not apply to the type are refused. `is-enabled` reports
  errors instead of `false`. OpenRC refuses `mask`/`unmask`, `stop
  force=true` and `logs since/until/level` (exit 2, `svc.unsupported`).

system:
- `disk` `used_pct` is now `df`'s Use% (used / (used + avail), rounded up);
  the old used / total value is `used_of_total_pct`.
- Unknown options and bad values are refused (exit 2,
  `system.invalid_argument`); `timeout_ms` is accepted only by `disk` and
  `info`. `kernel.machine` is the hardware name.

template:
- Errors print `Error: [template.<code>] <message>` (were a bare kind or
  phrase such as `Error: render`); every failed result carries
  `"error": {"code", "message"}` (`test` reported a string); a bad `cases=`
  list is `template.invalid_cases`; an unknown verb exits 2 (was 1).

user:
- Exit codes are 0/1/2/124 (every failure exited 1); with `format=json` the
  error object is printed on stdout.
- Unknown arguments, options of another mode and invalid values are refused
  with exit 2 before anything is looked up.
- `passwd` refuses accounts with a UID below 1000, root included
  (`user.protected_account`, exit 2) unless `force=true`; `delete` refuses
  `remove_from_all_groups=false`; a change without root is refused before any
  tool runs.

### Added
- CLI: `-h` and `help` work like `--help`; `resh help <handle> [verb]`,
  `<scheme>://help`, `<stage> --help` and `?help` / `?help=<verb>` in a stage
  URL print help.
- `backup`: `schedule` installs a systemd timer or crontab line through the
  cron handle (`scheduler=auto|cron|systemd`, `enabled=false`, duplicate
  detection); `restore dry_run=true`; `progress=true` on `create` and
  `restore` (restic, borg); `restore include=` for tar, rsync and borg;
  `verify snapshot_id=`; new code `backup.schedule_failed`.
- `cache`: `rediss://` with verified TLS (rustls) and `ca_file=`; memcached
  `keys` (LRU crawler metadump, memcached 1.4.31+).
- `cert`: encrypted PKCS#8 keys (PBES2 with PBKDF2 and AES-CBC) with
  `key_passphrase`, `signer_key_passphrase`, `existing_key_passphrase` and
  `new_key_passphrase`, each also as `<name>_env=` or `<name>_stdin=true`;
  `verify ca_file=`; CMS signatures (`signature_format=cms_detached|
  cms_attached`) and RSA PKCS#1 v1.5 SHA-256/384 in `sign`.
- `cron`: `add timezone=` (systemd `OnCalendar=` zone, cron `CRON_TZ=` on
  cronie); `list timezone=`; `now_unix=` on `list` and `add`;
  `next_run_timezone`; `cron_file=` on `rm` and `enable`; `match_comment`;
  `include_raw`; `@reboot` and day-of-month plus weekday schedules on the
  systemd backend; `timeout_ms` on every verb (default 60000).
- `db`: `ca_file=`; `log_queries=true`; `query` streams rows; `schema` fills
  indexes, foreign keys, unique constraints, checks and triggers; MySQL
  `isolation=` and `read_only=`; `connect` reports server version, database,
  user and `tls`.
- `dns`: resh's own DNS client (authority, additional and `raw` sections,
  server failover, TCP fallback); `trace` follows referrals from the root;
  `zone.fetch` IXFR and TSIG-signed AXFR/IXFR with every reply verified;
  `zone.update` sends a real RFC 2136 UPDATE with TSIG (hmac-sha1/256/384/512).
- `event`: `subscribe follow=true` (one JSON line per event, `max_events`);
  `manual_commit_offset`, `include_raw`, `ttl_ms`; real `log`, `fs` and `mq`
  hooks whose state persists in `_hooks.json`.
- `file`: `timeout_ms` on every long verb; `copy preserve_times`; `rename
  atomic` (copy across filesystems under a temporary name, then rename).
- `firewall`: NAT rules (`action=dnat|snat` with `to=<addr>[:port]`; ufw
  refuses NAT and firewalld refuses `snat`), with `to` in listings and as a
  filter;
  `log_prefix` with `action=log`; progress reports (`error.details.applied`,
  `stopped_at`, `not_applied`, `backup_path`) when a change fails or times
  out; new codes such as `permission_denied`, `tool_not_found`,
  `chain_not_found`, `invalid_snapshot`, `already_enabled`, `timeout`.
- `fs`: `quota all_subjects`; `resize` honors `force` and uses each
  filesystem's native size.
- `git`: `timeout_ms` on every verb (network verbs default to 600 s);
  `clone` of `file://`, `git://` and local paths, `recursive=true` and
  shallow clones (`depth=`); `known_hosts_path` for strict SSH host-key
  checking (following `insteadOf`/`pushInsteadOf`).
- `http`: `ca_file=` on every verb.
- `log`: `follow=true` (files with rotation and truncation, journal with
  `journalctl --follow`); `follow=true mode=json` streams objects;
  `log://svc/<service>`.
- `mail`: `test` opens a real session (TLS, AUTH, NOOP); `header_<Name>`
  headers are sent; a Message-ID is generated; `ca_file=` on `send`,
  `send_template` and `test`.
- `mq`: `get wait=true` (inotify, bounded by `timeout_ms`); at-least-once
  redelivery of messages whose consumer has exited; `timeout_ms` on `put`,
  `get` and `purge`.
- `net`: `tcp_check expect_tls` performs a verified TLS handshake, with
  `ca_file=`; `route.list table=`; real interface flags, MAC and MTU; real
  DNS TTLs.
- `pkg`: `restore mode: exact`, `include_versions: minimal` lockfiles,
  `install allow_downgrade` (`pkg.downgrade_refused`), `repository_url`,
  restore `warnings`, `on_repo_mismatch` and `include_dependencies` that
  work; dnf 5 support.
- `plugin`: Ed25519 publisher signatures with `keys.add`, `keys.list`,
  `keys.delete` and `trust_key=`; `rollback` to the previous version
  (`previous_version` in `installed.list`); `progress=true` on `install` and
  `update`; `ca_file=`; `timeout_ms` as a whole-verb deadline.
- `proc`: `limits.set` changes the target process through `prlimit` (the URL
  PID or `pid=`), checks every value first, has a real dry run and reports
  each resource.
- `secret`: `vault` scope (HashiCorp Vault KV v2: `VAULT_ADDR`,
  `VAULT_TOKEN` or `~/.vault-token`, `VAULT_NAMESPACE`, `mount=`, `field=`,
  `ca_file=` or `VAULT_CACERT`, check-and-set writes, `destroy=true`);
  `rotate` (`strategy=random|uuid|aes|rsa`, `length=`, `encoding=`,
  `expose_value=true`); `set from_stdin=true`; `timeout_ms` on `local` and
  `vault`.
- `snapshot`: `tags=`, `timeout_ms` on every verb, `ttl` enforced when
  snapshots are accessed.
- `ssh`: real `tunnel`, `keys.list` and `key.add`; real `sftp` and `hostkey`
  checks in `test`; `identity_data`, `identity_passphrase`, `env` (exported
  remotely), `allocate_pty`; `timeout_ms` on every connecting verb.
- `svc`: changing verbs wait for the systemd job and report `job_result`; at
  `timeout_ms` the job is cancelled (`job_canceled`); `settle_ms`;
  `force=true` for `enable`/`mask`; `is-enabled` adds `unit_file_state`;
  `timeout_ms` on every verb.
- `system`: `cpu` `cgroup_utilization_pct`; `disk` `used_of_total_pct`;
  `timeout_ms` on `disk` and `info`; cgroup v1 and v2 figures with
  hierarchical limits.
- `template`: `timeout_ms` on `render`, `validate` and `test`.
- `user`: `new_password_env=`, `new_password_stdin=true` and
  `old_password_env=`; `require_old_password` checks hashes with the system
  crypt library (yescrypt included); `timeout_ms` (default 60000) on every
  changing verb.
- Cargo feature `e2e-docker` for the container-based end-to-end tests.

### Fixed
Security-relevant fixes:
- **user: fake password hashing.** `passwd` produced PBKDF2 stand-ins instead
  of real crypt hashes. resh now hashes passwords itself (real sha512-crypt
  and bcrypt on the system backend) and passes the hash to `chpasswd -e` on
  stdin; every shadow-utils command takes its operands after `--`.
- **plugin: unchecked deletion.** `remove` deleted the binary path recorded in
  the plugin's `metadata.json`; it now deletes only the plugin's store
  directory and its own data directories.
- **plugin: no signature verification.** Registry artifacts are verified
  against an Ed25519 publisher signature and a required SHA-256 before
  unpacking; artifacts are limited to 512 MiB, 100,000 entries and 2 GiB
  unpacked; archive entries with `..`, absolute paths or links are refused; a
  failed or timed-out install never leaves a half-installed plugin.
- **mq: lost and duplicated messages under concurrency.** Messages are
  written in `.tmp/` and numbered under a lock, so concurrent producers and
  consumers no longer lose messages, read partial ones or take the same
  message twice; FIFO order no longer depends on the clock.
- **event: concurrent processes.** `emit` numbers and appends under a store
  lock, and a consumer group's read and commit are atomic, so consumers of
  one group never get the same event.
- **snapshot: overwriting its own metadata.** The copy of a target is stored
  under `content/`, so a target's own `meta.json` or files no longer collide
  with the snapshot's metadata; an overwrite keeps the old snapshot until the
  new one is in place.
- **file: data loss on rename.** `rename`/`move` over an existing destination
  never lose it (it is set aside and restored on failure); recursive `chown`
  never follows links; `write`, `copy` and `replace` replace a symbolic link
  instead of writing through it.
- **firewall: `rules.save` permissions.** Saved rule files are written 0600
  and never through a symbolic link; `rules.reload` keeps its temporary files
  out of `/tmp`.
- **db: MySQL identifier injection.** Table and schema names are always bound;
  MySQL `tables` was injectable. DSNs and passwords never appear in output.
- **secret: plaintext store.** `local` values were kept in a plaintext JSON
  file; they are now in the OS keyring.
- **mail: passwords and TLS.** Stored SMTP passwords were base64-encoded in
  the profile file; they are now in the OS keyring. STARTTLS never falls back
  to plain text.
- **cache: memcached command injection.** resh's own memcached text-protocol
  client keeps keys from injecting commands.
- **dns: unsigned transfers and simulated updates.** `zone.fetch` validated
  TSIG options but never signed the transfer; `zone.update` validated its
  input and reported NOERROR without sending anything. Both are real now.
- **git: host keys.** `known_hosts_path` was stored but never read; SSH host
  keys are now checked strictly against it, also after `insteadOf`
  rewrites.
- **Owner-only files.** `config` values, `mq` queues, `snapshot` metadata,
  `backup` repositories and restore destinations, and `cert` keys are
  written owner-only; `mq` no longer falls back to `/tmp`, and a
  symbolic link `backup dest` or SQLite database is refused.

Other fixes:
- `backup`: a second backup in the same second no longer overwrites the
  first; a stopped or failed `create` removes its partial tar archive or
  rsync directory; restic gets `--host` instead of the deprecated
  `--hostname`.
- `cache`: memcached `exists`/`ttl` no longer report missing keys as present;
  `incr` no longer overwrites non-numeric values; Redis `incr` values are
  exact 64-bit integers.
- `cert`: `csr.create` writes key usage and extended key usage into the CSR
  and writes PKCS#1/SEC1 keys correctly; `verify` validates the chain with
  rustls-webpki; `chain.info` builds every path and reports `trusted` only
  when it validates.
- `cron`: the systemd translation keeps each schedule's meaning
  (`* * * * *` ran every second, `@weekly` on Monday, hour ranges gave
  invalid expressions); `list` no longer shows commented sentences as
  disabled jobs; failed writes and `systemctl` calls are errors, not
  warnings; `add` never replaces a crontab it could not read.
- `fs`: fsck/scrub failures are no longer reported as success; tools are
  stopped at `timeout_ms` (they kept running); quota output is parsed
  correctly.
- `git`: `commit amend` works; `push` reports server rejections; a fast-forward `merge` updates the
  working tree; `pull` no longer overwrites local changes; `sync` handles a
  detached HEAD and bare repositories; a failed clone removes what it
  created; RSA-only known_hosts files work (rsa-sha2-256/512).
- `http`: `head` and `patch` ignored `timeout_ms`; `allow_insecure`,
  `follow_redirects` and `query` now work on every verb, and `timeout_ms`
  also bounds reading the body.
- `log`: invalid UTF-8 no longer fails small files; the large-file scan no
  longer cuts the first line; lines over 1 MiB are cut with a warning; a
  FIFO target is refused.
- `net`: `tcp_check` honors `port=`.
- `pkg`: apt upgrades no longer install packages that were not installed
  (`--only-upgrade`); config-files packages are no longer listed as
  installed; `snapshot format: yaml` produced JSON and text lockfiles could
  not be restored; `extra_args` and `env` reach every restore command;
  options that were parsed and ignored (`info include_repo`,
  `list_installed include_versions`, restore `on_repo_mismatch` and
  `include_dependencies`) work.
- `proc`: nice changes applied only to the main thread.
- `ssh`: a timed-out `exec` stops the remote command; `config.get` uses
  OpenSSH's first-match rule and the URL host.
- `svc`: `enable` and `mask` reported a failure after succeeding; systemd is
  reloaded after unit-file changes.
- `system`: CPU percentages no longer count guest time twice or iowait as
  busy; `disk` no longer panics on non-ASCII mount names and lists `overlay`.
- `template`: a macro that recursed without end overflowed the stack and
  aborted resh; calls are now limited to 200 levels.
- core: a tool not started at the deadline no longer claims that nothing was
  done.

### Changed
- `rust-toolchain.toml` pins the stable toolchain (rustix 0.37, through zbus 3,
  does not compile on current nightly).
- reqwest and lettre use rustls only (native-tls is no longer pulled in);
  git2 still links OpenSSL for SSH and HTTPS remotes, so building needs the
  OpenSSL development headers and `pkg-config`.
- The keyring store behind mail profile passwords moved to a shared core
  module used by `mail` and `secret`.
- All compiler warnings were cleaned up; the binary uses the library crate
  instead of compiling every module twice.

### Removed
- `proc io.peek` (it read log files that nothing writes); it is now an
  unknown verb (`proc.unknown_verb`).
- `cert verify disallow_weak_signatures` (refused; weak signatures are always
  rejected).
- `pkg snapshot inline` (refused) and the package `source` field (refused).
- `backup schedule` `runner` and `definition_path`.
- `db` pool options, `tx_id` and `transaction action=begin|commit|rollback`.
- The `event` `proc` hook and the sample `list-topics` catalogues for the
  mq, log, proc and fs_watch sources.
- `fs` codes `fs.unknown_error`, `fs.profile_not_found` and
  `fs.unmount_option_unsupported`.
- The `memcache` and `cron` crates, and the old redis/memcached
  integration-test cargo features.

### Dependencies
- redis 0.25 -> 1.8 (TLS through rustls, `tokio-rustls-comp`; clears its
  future-incompatibility warning; tokio is now 1.54).
- git2 0.18 -> 0.21 (libgit2 1.9), with the `https` feature.
- New: keyring 2.3.3 (Secret Service over the zbus 3 already in the tree;
  Keychain on macOS), cms 0.2 (CMS signatures), rustls 0.23 as a direct
  dependency (ring provider), rustls-webpki 0.103, chrono-tz 0.9, hmac 0.12,
  cbc 0.1.2, futures-util 0.3. Most were already in `Cargo.lock` through other
  crates.
- sha2 gains the `oid` feature; reqwest drops its default features; lettre
  uses rustls.
- Removed: memcache 0.17, cron 0.12.

### Testing
Tests are organized in three tiers:
- **Unit and dispatch tests** (plain `cargo test`): every verb is called
  through its handle and checked for success, each documented option, each
  error code and exit code, and edge cases. Host-changing verbs use mocks and
  fake tools; network verbs use in-process fake servers on 127.0.0.1. No
  Docker and no internet access.
- **Binary tests** (also plain `cargo test`): `tests/<handle>_verbs.rs` run
  the built `resh` binary for every verb that is safe to run on the host
  (temporary directories only); help goldens (`tests/golden/`) and
  `tests/help_*.rs` check every help form, the 80-column limit and that every
  help example runs.
- **End-to-end tests** (`--features e2e-docker`): `tests/*_e2e_docker.rs`
  and `tests/fs_docker.rs` run resh against real tools and services in
  throwaway Docker containers, never on the host: OpenSSH, git daemons,
  PostgreSQL, MySQL and MariaDB with TLS, Redis and memcached, BIND, mailpit,
  HashiCorp Vault and gnome-keyring, systemd, cron implementations,
  shadow-utils, nftables, iptables, ufw and firewalld, apt, dnf, yum, pacman
  and apk, restic, borg, rsync and tar, and real filesystems on loop devices
  in a privileged container.

How to run them:

```bash
# unit, dispatch and binary tests
env -u SSH_AUTH_SOCK cargo test
# end-to-end tests (needs Docker, no sudo), one file at a time
env -u SSH_AUTH_SOCK cargo test --features e2e-docker --test <handle>_e2e_docker
```

Unset `SSH_AUTH_SOCK` when running the tests: with an SSH agent in the
environment, one ssh authentication test fails.

### Planned for v1.1 (not yet scheduled)
- webhook:// handle - Webhook receiver for event-driven automation
- lock:// handle - Distributed locking mechanisms (Redis, etcd, Consul)
- Enhanced integration test suite (85%+ coverage)
- Performance optimization and benchmarking
- Shell completion scripts (bash, zsh, fish)
- Improved error messages with actionable suggestions

### Planned for v1.0 Stable (not yet scheduled)
- API stability guarantee (semver compliance)
- Complete test coverage (95%+)
- Binary releases for major distributions
- Production hardening and security audit
- Comprehensive documentation polish
- Community infrastructure (Discord)

---

## [1.0.6-beta] - 2026-11-03

Published as a GitHub pre-release on 2026-11-05. The date above is the
release freeze date.

Security hotfix built directly on v1.0.5-beta. It is a narrowly scoped
security maintenance release: it changes only the firewall handle and the
external-tool execution path, adds no dependencies, and leaves the public
CLI syntax and the `firewall://.rules.list` JSON schema unchanged. Upgrading
is recommended for anyone who uses `firewall://` to add or delete rules, or
who relies on operation timeouts to stop external tools. v1.0.5-beta and,
for the firewall and timeout issues, earlier versions are affected.

### Security
- **firewall command injection (R4-02):** every rule field is now validated
  as a single token before any backend command is built, and a rule a
  backend cannot express in full is refused rather than silently narrowed.
  Previously a crafted field value (for example an address, table, chain or
  comment) could inject additional `nft`/`firewalld` statements at the
  privilege of the caller.
- **ambiguous numeric parsing (R5-03):** ports, numeric protocols and CIDR
  prefix lengths must be written as unambiguous decimal. A leading-zero value
  such as `dport=022` or `saddr=10.0.0.0/010` is now refused rather than
  validated as decimal and then applied by the backend as octal (port 18, a
  /8 prefix), which previously widened or shifted the rule from what was
  requested and reported.
- **incorrect rule deletion (R5-02):** a rule's action is read from the rule
  itself, not from its free-text comment, so `rules.delete action=accept` can
  no longer select and remove a `drop` rule whose comment happens to contain
  the word "accept".
- **incorrect idempotence (R5-01):** an `idempotent` add no longer treats a
  rule narrowed by an unmodeled match (for example `conntrack --ctstate NEW`
  or `multiport`) as satisfying a broader request, so the broader rule the
  operator asked for is actually added instead of silently skipped.
- **timeout containment (R4-01):** external tools run in a contained process
  group bounded by the operation deadline; the whole tool tree, including
  descendants that call `setsid`, is stopped at the deadline, captured output
  is bounded, and an operation whose outcome cannot be confirmed reports exit
  code 124 instead of a possibly false success. This covers external tools;
  the service-manager completion-verification limitation is tracked as a
  known issue (see `docs/known_issues.md`).

### Notes
- No dependency changes (`Cargo.lock` is identical to v1.0.5-beta except this
  package's version).
- Behavioural changes are safety tightenings: malformed, injection-shaped,
  ambiguous-numeric or unexpressible firewall inputs that earlier versions
  accepted are now refused with a `firewall.*` error code and a non-zero exit.

---

## [1.0.5-beta] - 2026-10-29

Security and stabilization release. Upgrading is recommended for everyone
who lists, tests, inspects or extracts archives from untrusted sources, or
installs plugins from untrusted `.tar.gz` artifacts. Versions v1.0.4-beta
and earlier are affected by both archive issues below.

### Security
- archive extract: `max_file_bytes` and `max_total_bytes` are enforced on the
  bytes each entry actually produces while it is decompressed, for zip, tar
  and raw streams, instead of on the sizes the archive records. Writing stops
  at the limit. Previously a crafted archive could write past both limits
  and fill the destination filesystem, and a raw stream was written in full
  before the limits were checked. The error code
  (`archive.extract_archive_read_error`) and exit code are unchanged.
- archive extract: each file is written to a temporary name and renamed into
  place only when complete. A failed entry (size limit, corrupt or truncated
  data) leaves no partial file, and an existing file of the same name is
  left unchanged. Entries completed before the failure are kept.
  `summary.bytes_written` and manifest sizes report the bytes written.
- archive extract: `max_file_bytes` and `max_total_bytes` must be a whole
  number of bytes (digits only). Any other value, such as `1e6`, `1.5`, `-1`,
  `10MB` or an empty value, is refused before extraction with exit code 1
  and `archive.extract_invalid_max_file_size` or
  `archive.extract_invalid_max_size`. Previously such a value silently meant
  no limit.
- archive (all verbs that read tar archives) and plugin install: a member
  preceded by more than 1 MiB of tar header data (PAX extended headers, GNU
  long name and long link headers, GNU sparse extension blocks), counted
  after decompression, is refused. Previously that header data was read into
  memory up to the size the archive declared, so a small compressed archive
  could make `list`, `test`, `info`, `extract`, `add`, `remove` or
  `plugin install` use gigabytes of memory, and `test` reported such an
  archive as valid. `max_file_bytes` and `max_total_bytes` did not cover it.
  The command fails with its existing archive read error and exit code 1.
  Ordinary archives, including long names, extended attributes and sparse
  files, are unaffected.
- fs mount: `source` and `target` values that start with `-` are refused, and
  `mount`/`umount` receive their operands after `--`. Dry-run plans show the
  separator.
- user add: a `primary_group` that starts with `-` is refused
  (`user.group_name_invalid`), and `useradd`, `groupadd` and `usermod -a -G`
  receive their operands after `--`. `planned_commands` show the separator.
  No other naming rule was added; existing group names keep working.

### Dependencies
- libz-sys 1.1.23 -> 1.1.31 (RUSTSEC-2026-0418). The advisory concerns the
  libz-sys build script, which could write the build environment into
  cargo's `target/` directory when compiled with cc 1.6.0 or later; it does
  not affect the resh executable at runtime. resh's locked dependencies use
  an earlier cc, and still link the system zlib. Other accepted dependency
  advisories and warnings are unchanged (see `.cargo/audit.toml`).

### Removed
- The unused `handles::automation::backup` helper module (crate-private, not
  compiled into any command).

### Documentation
- backup prune: a restic or borg `dry_run=true` removes nothing, but takes a
  repository lock (exclusive for borg), writes the backend's local cache and
  needs credentials; remote repositories were not tested. See `backup.md` 4.5.
- archive and plugin: the extraction limits, temporary-file behaviour and
  the tar header data limit are described in `archive.md` 3.2 and 6 and in
  `plugin.md` 2.3.
- `.cargo/audit.toml`: corrected three accepted-advisory rationales
  (quick-xml, crypto-bigint, h2). No accepted advisory was added or removed.

### Fixed (tests and CI)
- Firewall, package and security test fixtures that wrote and then executed
  mock tools could fail with "Text file busy" under parallel test runs.
- The CI security job runs the new archive and tar header regression tests.

---

## [1.0.4-beta] - 2026-10-27

Security release. Upgrading is recommended for everyone, and especially for
anyone who passes values from scripts, templates or AI agents into
`backup`, `cron add` or `ssh exec`, or who runs resh as root. Versions
v1.0.3-beta and earlier are affected; there is no configuration workaround
other than not passing untrusted values to the affected arguments.

### Security
- backup: argument values (`src`, `snapshot_id`, `dest`, `repo_url`) are
  validated before anything runs, including dry runs. Backend command lines
  attach option values with `=`, put positional values after `--`, run tar
  with `--force-local`, and give rsync local relative paths a `./` prefix,
  so a value can no longer be read as a backend option or a remote
  location. For borg and restic, a remote repository whose host part starts
  with `-` is refused. Refused values give `INVALID_ARGS` with
  `details.field`.
- backup prune: arguments are validated before restic or borg run in their
  own dry-run mode.
- cron add: every job field is checked against the syntax of the crontab or
  unit file it is written to (no line breaks or control characters; valid
  ids, user names, unit names, paths and time spans). `cron_file` is limited
  to `/etc/crontab` and `/etc/cron.d/<name>`, also for `disable`. systemd
  unit values are escaped, and the timer is enabled with
  `systemctl enable --now -- <unit>`. Refused values give
  `cron.add_invalid_argument` with `error.field`.
- cron: crontab and unit files are replaced atomically, through a hidden
  temporary file that cron ignores, and are never read or written through
  symbolic links. An existing file keeps its permission bits. An existing
  system cron file that cannot be read is no longer replaced by the new
  line alone; `add` fails instead.
- ssh exec: each `command_args` element reaches the remote program as
  exactly one argument, quoted for POSIX login shells. `shell_mode=cmd` and
  `powershell` refuse arguments and `cwd` values that would need quoting,
  and ssh receives `--` before the destination.
- cert sign: `signature_algorithm=ecdsa_sha512` with a P-384 key now
  produces a SHA-512 signature; previously it silently produced a SHA-384
  signature. Unsupported key and algorithm pairs are refused and no file is
  written.

### Changed (may affect scripts)
- backup: the result has a new `dry_run_mode` field: `plan` means no
  program ran; `backend` means restic or borg ran with its own `--dry-run`
  (prune only). `backend.command` shows the new argument forms
  (`--exclude=<p>`, `--`, `--force-local`, `./` prefixes).
- cron add: six-field (seconds) schedules, `cron_file` outside the cron
  locations, an unescaped `%` in a cron-backend command (write `\%`), and
  systemd commands that start with an `ExecStart=` prefix character are
  refused. `%` in systemd unit values is written as `%%`.
- ssh exec: `command_args` are no longer subject to remote shell expansion
  (globs, variables); put shell syntax in `command`. An unknown `shell_mode`
  is an error (`PARSE_ERROR`) instead of meaning `none`. `command.raw` is
  now the exact string sent, including the `cd` prefix for `cwd`.
- ssh: error envelopes report the requested `dry_run` instead of always
  `false`; an exec request refused before ssh starts also reports
  `result.executed: false`.
- cert sign: ECDSA P-384 signatures made earlier with `ecdsa_sha512` are
  SHA-384 signatures and should be re-created.

### Documentation
- backup: a restic/borg `prune dry_run=true` runs the backend. It opens and
  authenticates to the repository, connects over the network for a remote
  repository, may create and remove a repository lock (a write that can
  delay or fail a concurrent backup), and may update the backend's cache
  and logs. These effects are expected from upstream behaviour, not
  verified by resh's tests. Do not use it where a dry run must start no
  program.
- ssh: argument quoting is tested with sh, dash and bash. fish, csh and
  tcsh login shells quote differently and are not supported for
  `command_args`; `command` is always a command line, run by the remote
  shell as written.
- Platform requirements are unchanged: the prebuilt binary is Linux x86_64
  and needs glibc 2.39 or later plus OpenSSL 3 (for example Ubuntu 24.04,
  Debian 13, Fedora 40); older distributions must build from source with
  Rust 1.88 or later.

---

## [1.0.3-beta] - 2026-10-26

Fixes for the release blockers found by the v1.0.2-beta release gate
(`docs/reviews/resh-cli-v1.0.2-beta-release-gate.md`). v1.0.2-beta was
tagged but not published as a release; use this version instead.

### Security
- cert: private keys (`generate`, `renew key_strategy=rekey`,
  `csr.create key_strategy=generate`) are created with mode 0600 from the
  start instead of being chmod'ed after the write, so another local user
  can no longer open them in between. A symlink at the key path is refused,
  and a dangling symlink no longer bypasses `overwrite=false`.
- file `replace backup=<suffix>` and archive `add backup_suffix=` no longer
  write through a symlink planted at the backup name (which overwrote and
  re-moded the symlink's target); the backup is written to a new temporary
  file and renamed into place.
- backup: the `/tmp` default repositories are removed. They left archives
  readable by every local user and accepted directories another user had
  created first.
- docs: a real MySQL connection string was removed from
  `MYSQL_CONNECTION_GUIDE.md`.

### Changed (compatibility)
- backup: tar, rsync and borg require `repo_url`; without it every verb,
  including a dry run, fails with `INVALID_ARGS` before anything runs.
  restic still falls back to `RESTIC_REPOSITORY`.
- cert: `csr.create` refuses an existing `new_key_output_path` unless
  `overwrite=true`; a symlink at a key path is an error even with
  `overwrite=true`.
- file `replace backup=` and archive `add backup_suffix=` fail when the
  backup name is a symlink.

### Documentation
- Platform requirements: Linux x86_64; OpenSSL 3 shared libraries from the
  OS (libssh2 and libgit2 are bundled and updated through resh releases);
  Rust 1.88 or later to build. A prebuilt binary built on a current
  distribution needs glibc 2.39 or later.
- pkg/fs timeouts: a timed-out tool either keeps running or is killed by
  SIGPIPE part-way through; check system state afterwards.
- plugin: do not run plugin verbs as root with another user's
  `HOME`/`XDG_*`.
- `docs/known_issues.md` lists the remaining accepted beta risks (backup
  argument option injection, cron newlines, ssh `command_args` quoting,
  archive extraction into shared directories, SMTP passwords stored
  base64-encoded).
- README: systemd and brew are marked as not yet verified live.

---

## [1.0.2-beta] - 2026-10-23

Release-candidate stabilization: security, correctness and documentation
fixes on top of the help-system work below. Details and evidence:
`docs/reviews/`.

### Security
- archive: extraction can no longer write outside the destination
  (symlinks, hard links, absolute and `..` paths, device nodes); an unsafe
  entry fails the extraction.
- plugin: ids and versions must be single safe path components; registries
  and artifact URLs must use HTTPS; registry artifacts need a SHA-256
  checksum (`source=url` requires an explicit `verify=none`); artifacts may
  contain only regular files and directories.
- proc: PIDs above 2147483647 are rejected (previously `4294967295` became
  `kill(-1)`).
- pkg: package managers run without a shell; names, versions and lockfile
  entries are validated.
- `dry_run`: one strict parser (`true/false/1/0/yes/no/on/off`); malformed
  values are errors and a bare `dry_run` means true.
- Dependencies: rustls 0.23.46, rustls-webpki 0.103.16, webpki-roots
  1.0.10, bytes 1.11.1, h2 0.4.16, tar 0.4.45 (security patches).
  `Cargo.lock` is now tracked; minimum Rust version is 1.88.

### Fixed (stabilization)
- Failures always exit non-zero and print a reason on stderr.
- firewall enable/disable write a real backup before changing rules;
  firewall `timeout_ms` is enforced.
- git sync is fast-forward only and fails on divergent history instead of
  reporting a merge/rebase it did not do.
- backup timeouts are enforced; `backup://<profile>` is honored.
- cron enable no longer uncomments ordinary comments.
- svc instance units (`getty@tty1`) target the right unit.
- file relative directories work; snapshot `diff from=<name>` works.
- PostgreSQL integer/float decoding and the MySQL `tables` panic.
- Stage 4: `pkg security_only` is refused where it cannot be honored
  (it ran a full upgrade); `backup create/prune` and `fs mount/unmount`
  reject malformed `dry_run`; `backup restore` and `mail send` refuse
  `dry_run=true` (they performed the real operation); ext3/ext4 resize uses
  the requested size (it asked for a quarter); `file rename/copy/move`
  accept bare destination names and rename no longer deletes the
  destination before failing; `archive add/remove` on `.tar.zst` no longer
  truncates the archive.
- Stage 4 (independent review): `dry_run=true` on a verb that has no dry-run
  mode is refused instead of being ignored (it made the real change), and
  unknown bare words and misspelled `dry_run` keys are errors instead of
  being dropped (also a top-level `dry_run` next to pkg's `input=`);
  `archive add` keeps the headers of existing tar entries (modes, owners,
  times and symlinks were lost) and the mode, time and compression of
  existing ZIP entries; archive and file-copy
  rewrites use unpredictable, non-following temporary files; SMTP profiles
  are written 0600; firewall `rules.reload` no longer writes a predictable
  `/tmp` file; `fs resize` runs LVM tools without a shell; `resh` with no
  stage exits 2 instead of panicking.

### Changed (compatibility)
- A zip `password=` is refused (encrypted creation is not supported).
- git `timeout_ms` is refused (git steps cannot be interrupted).
- `http://` plugin registries and plugin artifacts containing links are
  refused.
- The documentation under `docs/` was rewritten against the code; every
  `resh` example is checked by `tests/doc_examples.rs`.
- The unused `sevenz-rust` dependency is removed (it carried an unfixed
  path-traversal advisory).
- CI: GitHub Actions workflow (`.github/workflows/ci.yml`): locked MSRV
  build, tests on Rust 1.88 and 1.98.1, security-regression tests, rustfmt
  and `cargo audit` gates, advisory Clippy. The code base is now
  rustfmt-formatted.

### Added
- Contextual help for every handle and verb: `resh <handle> --help` and
  `resh <handle> <verb> --help`, with definition, usage, example and example
  output for all 28 handles and 229 verbs (this entry originally said 239;
  corrected after a recount of the registered verbs)
- In-URL help forms (for example `svc://--help`, `--help=<verb>`) show the
  same help
- CLI string arguments now fill typed options (booleans, numbers, lists) in
  fs, git, db and system
- `db transaction action=run` runs a whole transaction in one invocation
- cache and db verbs connect on demand with `url=` / `dsn=`
- Events persist across invocations under the resh state directory
- `log://svc/<service>` reads journalctl logs

### Fixed
- backup: removed hard-coded restic/borg passwords; corrected backend
  commands; successful restic/borg/rsync backups are no longer reported as
  failures
- firewall: `rules.*` verbs are reachable; `rules.delete` removes exactly the
  matched rule; `family=any` adds both IPv4 and IPv6 rules
- secret: local store is created with 0600 permissions atomically, with no
  `/tmp` fallback
- cert: `verify` performs real chain, hostname, purpose and keypair checks;
  `renew` and CSR signing issue real certificates
- ssh: `download` and `upload` perform real transfers instead of simulating
- mail: `mail://test` and `mail://config` are no longer rewritten into `send`
- user: changes are executed (dry runs list planned commands); `user://alice`
  targets alice
- plugin: `install`/`update` no longer panic; `plugin://<id>.enable` and
  `plugin://available.list` work
- cron: `enable`/`disable` match jobs by id
- Targets containing `-h` (for example `my-hosts`) are no longer treated as
  help requests
- `file://dir/x` relative paths, pkg text-lockfile restore, `.tgz` archives

### Changed
- restic and borg backups require a password (`password=`, `password_file=`
  or the tools' environment variables)
- `firewall rules.delete` defaults to `match_mode=exact` and refuses a delete
  with no criteria
- Invalid typed option values are errors instead of silently using defaults
- `archive create` uses `format_output=` for the report format

### Removed
- Stale built-in help texts, replaced by the new help metadata
- Unused `src/backends` module

See `docs/known_issues.md` for details and remaining open issues.

---

## [1.0.0-beta] - 2026-01-29

### Added
- **Production-ready beta release** with 28 functional handles
- Comprehensive documentation for all handle categories
- Individual documentation files for each of the 28 implemented handles
- Organized documentation structure with category overviews
- Complete resh overview documentation
- Examples and usage patterns for all core functionality
- Professional README with before/after comparisons
- Updated roadmap aligned with production timeline
- Enhanced automation utilities documentation

### Changed
- Version strategy: moved from v0.9 alpha to v1.0-beta to reflect production-ready quality
- Updated all documentation to reflect v1.0-beta status
- Improved README with clear value proposition and AI-native positioning
- Refined development timeline and milestones
- Enhanced FAQ section with updated production readiness information

### Improved
- Documentation clarity and completeness across all 28 handles
- Better examples showing structured output advantages
- Clearer positioning against traditional tools (Ansible, Terraform)
- More accurate timeline and release planning

### Status
- ✅ 28 of 30 handles production-ready (25 core + 3 automation utilities)
- ✅ Complete documentation for all handles
- ✅ JSON, table, and log output formats operational
- ✅ URI-based resource model fully functional
- ⚠️ Testing coverage ~80% (expanding to 95%+ for v1.0 stable)
- ⚠️ Performance optimization in progress
- ⚠️ 2 additional handles (webhook://, lock://) planned for v1.1

---

## [0.9.2] - 2025-12-28

### Fixed
- ssh:// handle: fixed using credentials with password authentication
  - Now supports: `ssh://<username>:<passwd>@<host>.exec command=whoami`
  - Also supports: `ssh://<username>@<host>.exec password=<passwd> command=whoami`
- system:// handle: fixed env.list verb to properly list system environment variables
- dns:// handle: fixed dns verbs documentation and verb command line options
- mail:// handle: fixed mail verbs documentation and verb command line options

---

## [0.9.0] - 2025-12-15

### Added
- **Automation Utilities** - 3 new comprehensive handles
  - backup:// handle - Complete backup lifecycle management (create, list, restore, verify, prune, schedule)
  - plugin:// handle - Full plugin ecosystem management (install, update, remove, search, enable, disable)
  - template:// handle - Powerful template rendering system with Tera engine
- 28 of 30 production handles now implemented (25 core + 3 automation utilities)
- Multiple backend support for backups (restic, borg, rsync, tar)
- Plugin registry support with security verification
- Template validation and testing capabilities
- Enhanced documentation for automation utilities

### Improved
- Documentation organization with clear category structure
- Examples for automation workflows
- Error handling across all handles

---

## [0.7.0] - 2025-11-30

### Added
- **Core Platform** - 25 production handles implemented

#### Filesystem & Storage (4 handles)
- file:// handle - File operations (read, write, copy, move, delete, chmod, hash)
- fs:// handle - Filesystem management (mount, quota, usage, resize)
- snapshot:// handle - Snapshot and versioning (create, restore, diff, list)
- archive:// handle - Archive management (tar, zip, 7z, gzip, xz, zstd)

#### Process & Service Management (3 handles)
- proc:// handle - Process control (signal, nice, setPriority, limits)
- svc:// handle - Service management (systemd + OpenRC support)
- cron:// handle - Job scheduler (systemd timers + cron)

#### Network & Remote Operations (5 handles)
- ssh:// handle - Remote execution and file transfer
- http:// handle - HTTP client operations (get, post, put, delete, patch)
- net:// handle - Network diagnostics (ping, tcp_check, scan)
- dns:// handle - DNS operations (lookup, resolve, zone management)
- mail:// handle - Email/SMTP (send, templates, attachments)

#### Security & Secrets (4 handles)
- secret:// handle - Secret management (env, keystore, Vault integration)
- cert:// handle - Certificate management (X.509, TLS, Let's Encrypt)
- firewall:// handle - Firewall management (iptables, nftables, ufw, firewalld)
- user:// handle - User management (add, del, passwd, groups, exists)

#### Data & State Management (6 handles)
- db:// handle - Database operations (PostgreSQL, MySQL, SQLite)
- cache:// handle - Cache operations (Redis, Memcached)
- config:// handle - Configuration store (get, set, watch, remove)
- mq:// handle - Message queue operations (create, put, get, purge)
- log:// handle - Logging and log management
- event:// handle - Event pipeline (publish, subscribe, filter)

#### System & Software (3 handles)
- system:// handle - System information (CPU, memory, disk, network, uptime)
- pkg:// handle - Package manager (apt, yum, dnf, pacman, apk)
- git:// handle - Git operations (clone, pull, commit, push, status)

### Features
- JSON, table, and log output formatters
- URI-based resource addressing
- Basic CLI with clap argument parsing
- Initial documentation and examples

### Known Issues
- Documentation incomplete for some handles
- Limited test coverage (~60%, expanding in v0.9+)
- Performance not yet optimized
- Error messages need improvement
- Some edge cases not fully handled

---

## [0.1.0] - 2025-09-12

### Added
- Initial project structure and foundation
- Core URI parsing engine
- Handle framework and dispatcher
- Basic output formatting (JSON, table, log)
- Project scaffolding and build configuration
- Initial development tooling

### Technical Foundation
- Rust-based implementation for safety and performance
- Modular architecture for handle extensibility
- URI-based resource addressing model
- Output format abstraction layer

---

## Version Strategy

**Alpha (v0.1 - v0.9):** Rapid development, feature implementation, breaking changes allowed

**Beta (v1.0-beta):** Production-ready core, API approaching stability, community testing

**Stable (v1.0):** API stability guarantee, production-grade quality, long-term support

**Enhanced (v1.1+):** Additional features, performance improvements, ecosystem growth

For detailed plans, see [ROADMAP.md](ROADMAP.md)