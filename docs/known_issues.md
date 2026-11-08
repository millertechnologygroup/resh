# Known Issues

These issues were found while writing the per-verb `--help` metadata, and each
one was then checked against the code by a separate read-only review.

## Unreleased (after v1.0.6-beta)

Fixes and behavior changes since v1.0.6-beta, grouped by handle.

### All handles and the CLI

- Errors use one format: `Error: [<handle>.<code>] <message>` on stderr and
  `"error": {"code", "message"}` in JSON results. Exit codes are 0 success,
  1 failed, 2 invalid usage (nothing done), 124 timeout or unknown outcome.
  Errors raised before a handle runs use `resh.invalid_stage`,
  `resh.unknown_handle`, `<handle>.invalid_target` and
  `<handle>.invalid_argument`. Handles not yet aligned (backup, plugin) still print their own formats until they are.
- Help: `-h` and `help` work like `--help`, and `resh help <handle> [verb]`;
  an unknown handle or verb is an error (exit 2) with a suggestion.
- Stage output is streamed as it is written (`--json-pretty` still buffers).
- `key=value` command-line values are passed exactly, without trimming.

### ssh

- Every verb refuses unknown arguments and invalid values (exit 2,
  `ssh.invalid_argument`), takes `timeout_ms` (except `config.get`) and exits
  0/1/2/124 with `ssh.*` error codes. `exec` exits 1 for a non-zero remote
  exit; the remote code is in `result.exit_code`.
- `tunnel`, `keys.list` and `key.add` are implemented. The `test` verb's
  `sftp` and `hostkey` checks are real. `identity_data`,
  `identity_passphrase`, `env` (exported remotely), `allocate_pty` and every
  `test` timeout now work. A timed-out `exec` stops the remote command.
- `config.get` uses OpenSSH's first-match rule and the URL host.
- Remaining limits: the `identity_passphrase` helper needs OpenSSH 8.4+;
  in `exec`'s cmd/powershell modes a timed-out remote command cannot be
  stopped (a warning says so); `config.get` skips `Match exec`,
  `localnetwork` and `tagged` blocks with a warning.

### git

- Strict arguments, exit codes 0/1/2/124 and `[git.<code>]` errors on all
  13 verbs; `timeout_ms` is enforced (network verbs default to 600 s).
- The known_hosts check follows `insteadOf`/`pushInsteadOf` rewrites (an
  unexpected SSH connection is refused) and steers the SSH library to the
  key types the file lists; mismatches name the offered and listed types.
- `clone` accepts `file://`, `git://` and local paths and `recursive=true`;
  a failed clone removes what it created. `pull` and `sync` merge or rebase
  diverged history (sync rebases by default); on a conflict
  `abort_on_conflict=true` (default) restores the exact previous state.
  Shallow clones (`depth=`) work over network remotes. git2 0.21 / libgit2
  1.9.7: RSA-only known_hosts files work (rsa-sha2-256/512). `commit amend` works, `push`
  reports server rejections, a fast-forward `merge` updates the working
  tree, `pull` no longer overwrites local changes, `sync` handles a detached
  HEAD and bare repositories.

### secret

- `local` values move to the OS keyring (`local.json` becomes a names-only
  index; legacy plaintext is read with a warning and migrated on the next
  write; no keyring = refused, exit 1, `secret.keyring_unavailable`).
- `vault` scope works (HashiCorp Vault KV v2: VAULT_ADDR, VAULT_TOKEN or
  ~/.vault-token, VAULT_NAMESPACE, `mount=`, `field=`, `ca_file=` or
  VAULT_CACERT; check-and-set writes).
- `rotate` works: `strategy=random|uuid|aes|rsa`, `length=`, `encoding=`;
  the new value is never printed.
- Strict arguments, exit codes 0/1/2/124, `[secret.<code>]` errors with a
  JSON `error` object; `timeout_ms` on local and vault; writes are locked.
  Breaking: env writes exit 2 (`secret.read_only`); `redact` takes the shared
  boolean spellings; `value=` with `from_env=`, or an empty value, is
  refused (exit 2); the JSON `error` is an object.
- `set from_stdin=true` reads the secret from stdin (one trailing newline
  removed; empty input refused); exactly one of `value=`, `from_env=`,
  `from_stdin=true` is required.
- `rotate expose_value=true` prints the new value once in the result
  (sensitive; off by default).
- vault `rm` soft-deletes the latest version (recoverable with Vault's
  undelete); `destroy=true` deletes every version and the metadata.
- `?help` and `?help=<verb>` in a stage URL show help (all handles).

### cache

- Every verb refuses unknown arguments and invalid values (exit 2,
  `cache.invalid_argument`) before contacting the server, and exits
  0/1/2/124 with `Error: [cache.<code>]`; the JSON error is
  `{"alias","backend","error":{"code","message"}}`. Per-verb codes
  (`cache.get_timeout`, ...) are replaced by the set documented in cache.md.
- Values are text: `key=123`, `namespace=2024`, `cursor=17` work, and
  `value=` is stored exactly as typed (`encode=json` validates and stores
  compact JSON).
- `rediss://` works: TLS (rustls) with certificate-chain and host-name
  verification against SSL_CERT_FILE or the system CA bundle;
  `ca_file=<pem>` adds a private CA for the call (refused for redis://,
  Unix sockets and memcached). There is no option to skip verification
  (a `#insecure` URL fragment is refused). TLS failures are
  `cache.tls_failed`. Client certificates and memcached TLS are not
  supported.
- Memcached uses resh's own text-protocol client (keys cannot inject
  commands): `keys` works (LRU crawler metadump, memcached 1.4.31+);
  `exists`/`ttl` no longer report missing keys as present; `incr` no longer
  overwrites non-numeric values and applies `ttl_ms` on every call; TTLs
  round up to whole seconds (500 ms no longer means "never expires").
- Redis `incr` values are exact 64-bit integers. The redis crate moved from
  0.25 to 1.8.0 (TLS through rustls; clears its future-incompatibility
  warning; tokio is now 1.54); the `memcache` crate is no longer used.

### db

- Every verb refuses unknown arguments and invalid values before connecting
  (exit 2, `db.invalid_argument`), exits 0/1/2/124 and reports
  `Error: [db.<code>]` with a JSON error object. DSNs and passwords never
  appear in output.
- `timeout_ms` covers connecting and the work; at the deadline the running
  statement is cancelled on the server (PostgreSQL `pg_cancel_backend`,
  MySQL/MariaDB `KILL QUERY`, SQLite interrupt), exit 124. A timed-out
  transaction commits nothing.
- `ca_file=<pem>` trusts a private CA (implies `verify_full`). `prefer`,
  `allow` and `require` do not check certificates and are documented as
  insecure. `log_queries=true` writes each statement to stderr.
- Breaking: without `tls_mode=` (or an SSL mode in the DSN, or
  `PGSSLMODE`), remote hosts now use `verify_full`; `prefer` is the default
  only for `localhost`, 127.0.0.0/8, `::1` and Unix sockets (names are not
  resolved). A remote server with a self-signed certificate needs
  `ca_file=` or an explicit `tls_mode`.
- A SQLite database (or its `-journal`, `-wal` or `-shm` file) that is a
  symbolic link is refused (`db.invalid_argument`).
- Breaking: each verb uses one connection; pool options, `tx_id` and
  `transaction action=begin|commit|rollback` are refused; `return_last_insert_id`
  is refused on PostgreSQL; `connect` reports
  server version, database, user and `tls`; `db.connection_not_found` is now
  `db.dsn_missing`; `sql=` must be one statement.
- `query` streams rows; NUMERIC/DECIMAL are exact strings; unsupported types
  fail with `db.unsupported_column_type` instead of null. `schema` fills
  indexes, foreign keys, unique constraints, checks and triggers. Table and
  schema names are always bound (MySQL `tables` was injectable). MySQL
  `isolation=` and `read_only=` work.
- Remaining limits: `tls_mode=verify_ca` also checks the host name (sqlx
  0.8.6 with rustls 0.23; fails closed); PostgreSQL binds strings as `text`,
  so placeholders need casts; MySQL shows binary-collation text and binary
  data alike (UTF-8 as text, else base64).

### mq

- Strict arguments (exit 2, `mq.invalid_argument`), exit codes 0/1/2/124 and
  `[mq.<code>]` errors. Breaking: `get`/`peek` on an empty queue exit 1 with
  `mq.empty` (was 2). Queue names must be 1-120 letters, digits, '.', '-',
  '_' (not starting with '.'); other targets such as `mq://team/a` are
  refused (`mq.invalid_target`) instead of being rewritten to a shared name.
- Concurrent producers and consumers are safe: messages are written in
  `.tmp/` and numbered under an flock, so no partial reads or lost
  messages, and no two running consumers take the same message; FIFO order
  no longer depends on the clock. `get` puts a message back if it cannot
  write it to stdout.
- `put`, `get` and `purge` take `timeout_ms` (wait for the queue lock;
  default no limit; exit 124); `len`, `peek` and `create` refuse it.
- Queue files are owner-only (0700/0600); no `/tmp` fallback; symlinks are
  refused. `len`/`peek`/`get`/`purge` no longer create missing queues.
- `get wait=true` waits for a message (inotify, with a 500 ms check),
  bounded by `timeout_ms` (default 30000 when waiting; exit 124
  `mq.timeout`). Without `wait`, an empty queue is exit 1 `mq.empty`.
- Delivery is at-least-once: a message claimed by a `get` whose process has
  since exited (checked by PID and start time) is moved back to the head of
  the queue by the next `get` (and by `len`/`peek` when the lock is free). A
  consumer killed after printing a message but before deleting its in-flight
  copy gets that message delivered again.

### event

- Strict arguments on all six verbs (exit 2, `event.invalid_argument`), exit
  codes 0/1/2/124 and `[event.<code>]` errors; the old `event.emit_*`,
  `event.subscribe_*` and `event.list_topics_*` codes are replaced (see
  `event.md` 3.5). `tags`/`match_tags` must be JSON arrays.
- The store is safe for concurrent resh processes: `emit` numbers and appends
  events under a store lock, readers use a shared lock, events are ordered by
  store sequence number, and a consumer group's read and commit are atomic,
  so consumers of one group never get the same event.
- `subscribe follow=true` streams one JSON line per event (`max_events`,
  `timeout_ms`); `timeout_ms` is enforced on `emit`, `subscribe` and
  `list-topics` (exit 124). `manual_commit_offset` works, `include_raw`
  returns the stored record, and `ttl_ms` hides expired events.
- `list-topics` lists the real store; `sources` other than `event` are
  refused. `hooks.enable`/`hooks.disable` persist in `_hooks.json` and refuse
  unknown hooks. No state directory is an error (`event.store_unavailable`)
  instead of a silent per-process in-memory bus.
- Hooks are real and off by default: `log` appends each event as a JSON line
  to `<state>/resh/events/hooks/log/<topic>.log`, `fs` keeps the topic's
  latest event in `hooks/fs/<topic>.json`, and `mq` puts the whole stored
  event (the same JSON line the log hook writes) on the mq queue named after
  the topic. A hook failure is a warning in the
  emit result (`hooks: [{name, ok, warning}]`), never a failed emit. The
  `proc` hook was removed; old `_hooks.json` files migrate silently.

### log

- `tail` refuses unknown arguments and invalid values (exit 2), exits
  0/1/2/124 with `[log.<code>]` errors and a JSON `error` object. Breaking:
  not found / not a file and a failing journalctl exit 1 (were 2 or
  journalctl's own code); a relative path is reported as `./x`.
- `timeout_ms` is enforced (default 600000; journalctl is stopped at the
  deadline, exit 124). `follow=true` streams new lines (files: rotation and
  truncation handled; journal: `journalctl --follow`).
- Invalid UTF-8 no longer fails small files, the large-file scan no longer
  cuts the first line, lines over 1 MiB are cut with a warning, paths are
  percent-decoded, a FIFO target is refused, `log://svc/<service>` works and
  service names are validated (no shell, no leading `-`).

### proc

- Every verb refuses unknown arguments, `timeout_ms` and (except
  `limits.set`) `dry_run` (exit 2, `proc.invalid_argument`) and exits 0/1/2
  with `[proc.<code>]` errors and a JSON `error` object. Breaking: "process
  not found" and permission errors exit 1 (`proc.not_found`,
  `proc.permission_denied`; were 3 and 4); an invalid PID exits 2
  (`proc.invalid_target`); `setPriority nice=` outside -20..19 is refused
  (was clamped); `nice.inc`/`nice.dec` take `delta=0..39`; signal numbers
  must be 0..SIGRTMAX; USR1/USR2 are 10/12.
- `limits.set` changes the target process with `prlimit` (the URL PID or
  `pid=`), checks every value before changing anything, has a real dry run,
  and reports `changed`, `error` or `skipped` per resource.
- `io.peek` was removed (it read log files that nothing writes); it is now
  an unknown verb (exit 2, `proc.unknown_verb`).
- Verbs other than `nice.get` refuse the resh process itself (`self`, its
  PID, or `limits.set pid=`): exit 2, `proc.invalid_target`. Breaking:
  `self` was accepted by every verb.
- `nice.set`, `nice.inc`, `nice.dec` and `setPriority` change every thread
  of the process (they changed only the main thread, like `renice`) and
  report a `threads` array; when some threads fail and others change, the
  call exits 1 with `proc.partial_failure`.

### svc

- Every verb refuses unknown arguments and invalid values (exit 2,
  `svc.invalid_argument`), takes `timeout_ms` (`stop`/`wait` keep the older
  `timeout`) and exits 0/1/2/124 with `[svc.<code>]` errors; JSON results
  carry an `error` object on failure. Breaking: an unknown verb, a bad
  `count`, `state`, `lines` or `level` are now usage errors (exit 2); service
  names may contain only letters, digits, `_`, `.`, `@`, `-` and `\`.
- `start`, `stop`, `restart`, `reload` and `scale` wait for the systemd job
  and report its result (`job_result`; a failed job exits 1,
  `svc.job_failed`). At `timeout_ms` the job is cancelled and resh exits 124
  (`job_canceled` says whether the cancel worked).
- `enable` and `mask` reported a failure after succeeding (wrong D-Bus reply
  types); fixed, and systemd is reloaded after unit-file changes.
- `is-enabled` reports errors instead of `false`, and adds `unit_file_state`.
- Without a reachable system bus, every verb uses `systemctl
  --no-ask-password`. OpenRC refuses `mask`/`unmask`, `stop force=true` and
  `logs since/until/level` (exit 2, `svc.unsupported`).
- `start` and `restart` also check that the unit keeps running for
  `settle_ms` (default 1000) after its job is done; a unit that died, waits
  in `auto-restart` or did not start (failed condition) exits 1 with
  `svc.not_active`.
- `enable` and `mask` no longer replace conflicting links by default (as
  `systemctl`); `force=true` does. A conflict exits 1 with
  `svc.link_conflict`.
- Names ending in a systemd unit type (`.socket`, `.timer`, `.path`,
  `.target`, `.mount`, ...) are used as given; only bare names get
  `.service`. Verbs that do not apply to a type are refused with exit 2.
- Remaining limits: a job queued through `systemctl` (no D-Bus) cannot be
  cancelled at the deadline (exit 124, outcome unknown); OpenRC is tested
  only with fake tools.

### cron

- Every verb refuses unknown arguments, empty values, control characters and
  invalid values with exit 2 (`cron.<verb>_invalid_argument`) before reading
  anything; `disable` checks `scope`, `users` and `unit_scope` like `rm` and
  `enable`; options of the backend that does not run are refused.
- Errors are `[cron.<code>]` with exits 0/1/2/124 (usage errors were 1).
  Booleans take the shared spellings. Every verb takes `timeout_ms`
  (default 60000); a hung `crontab` or `systemctl` is stopped (exit 124).
- Schedules follow cron's rules (weekdays 0-7, the day-of-month/weekday OR
  rule, `@midnight`); next runs for numeric weekdays were a day early. The
  systemd translation keeps each schedule's meaning (`* * * * *` ran every
  second, `@weekly` on Monday, hour ranges gave invalid expressions).
- `list` no longer shows commented sentences as disabled jobs;
  `match_comment` matches the comment line above a job; `include_raw`
  returns each source's text.
- `rm`, `enable` and `disable`: every selector given must match (AND);
  disabled timers no longer loaded by systemd are found; failed writes and
  systemctl calls are errors, not warnings. `add` never replaces a crontab
  it could not read, and non-root `add` works on cronie. The `cron` crate is
  no longer used.
- `add backend=auto` follows the options given: cron-only options (`scope`,
  `user`, `cron_file`) select cron, systemd-only options (`unit_name`,
  `unit_scope`, `persistent`, `accuracy_sec`, `random_delay_sec`,
  `service_user`, `service_working_dir`, `env`, `env_<KEY>`) select
  systemd, and both kinds together are refused (exit 2). With neither,
  systemd is used when `systemctl` runs, as before.
- The systemd backend supports `@reboot` (`OnBootSec=0`; the timer is
  enabled but not started, so the job runs once at each boot) and schedules
  restricting both the day of month and the weekday (two `OnCalendar=`
  lines, which systemd ORs as cron does).

### firewall

- Every verb refuses unknown arguments and invalid values (exit 2,
  `firewall.invalid_argument`) and exits 0/1/2/124 with `firewall.*` codes.
  Input-validation refusals (invalid port, protocol, CIDR, field,
  unsupported option) now exit 2 instead of 1; the v1.0.6-beta refusals
  themselves are unchanged. Several codes were renamed or merged (see
  `firewall.md`); new: `permission_denied`, `tool_not_found`,
  `chain_not_found`, `invalid_snapshot`, `already_enabled`,
  `already_disabled`, `timeout`, `unknown_verb`.
- `status` honors `family` and `include_rules_summary`, counts nftables
  `inet` rules and reads policies correctly. `enable`/`disable` honor
  `source_format` and really validate with `validate_only`; dry runs read
  the real state; firewalld `enable` runs `systemctl enable` and `start`.
- `rules.reload` runs iptables-restore under the deadline, applies snapshots
  per family (gzip too), replaces the nft ruleset and keeps temporary files
  out of /tmp. `rules.save` writes 0600 (never through a symlink) and saves
  both iptables families.
- `rules.add` on nftables uses the live chain hooked on the direction (inet
  first); `log_prefix` works with `action=log`.
- `rules.add` supports NAT: `action=dnat|snat` with `to=<addr>[:port]` (one
  address, optional plain-decimal port or range; anything else exit 2).
  iptables writes DNAT/SNAT in the nat table; nftables uses the NAT chain
  hooked on the direction and otherwise creates `inet resh` with one;
  firewalld writes dnat as a forward-port rich rule and masquerade as a rich
  rule and refuses snat; ufw refuses NAT. Listed rules have a `to` field;
  `rules.list` and `rules.delete` filter on `to=`, and idempotence compares
  it.
- `timeout_ms` is one deadline for the whole verb (was per command);
  defaults are 30000 ms (`status`, `rules.*`) and 60000 ms (`rules.reload`,
  `enable`, `disable`). A change that fails or times out part-way reports
  `error.details.applied`, `stopped_at`, `not_applied` and, for
  enable/disable/rules.reload, `backup_taken` and `backup_path`.
- `backend=auto` prefers a running firewalld and an active ufw over
  nftables; failed listings are errors, not empty lists.
- Not tested: iptables-legacy (the test host kernel has no legacy tables).

### user

- Every verb refuses unknown arguments, options of another mode and invalid
  values with exit 2 before looking anything up. Errors are `[user.<code>]`
  with exits 0/1/2/124 (all failures were 1); with `format=json` the error
  object is printed on stdout.
- `passwd` hashes passwords itself (real sha512-crypt, bcrypt and argon2id;
  the previous "hashes" were PBKDF2 stand-ins) and passes the hash to
  `chpasswd -e` on stdin. `new_password_env=`, `new_password_stdin=true` and
  `old_password_env=` keep passwords off the command line;
  `new_password_plain=` still works but prints a warning on stderr every
  time. `require_old_password` checks hashes with the system crypt library
  (loaded at run time; yescrypt included), falling back to built-in
  sha512/sha256-crypt, bcrypt and argon2 verifiers.
- `passwd` refuses accounts with a UID below 1000, root included, with exit 2
  (`user.protected_account`) unless `force=true`, like `delete`, `lock` and
  `unlock`.
- `add`: `create_home` and `password_hash` work; everything is checked
  before the first change; uid/gid conflicts are reported; a group created
  for a failed `useradd` is removed again. `delete` reports partial
  failures and refuses `remove_from_all_groups=false`. `lock`/`unlock`
  check the state after the change.
- Every shadow-utils command takes its operands after `--`, runs under
  `timeout_ms` (default 60000; exit 124), and a change without root is
  refused before any tool runs.

### system

- Every verb refuses unknown options and bad values (exit 2,
  `system.invalid_argument`) and reports `[system.<code>]` errors;
  `memory` options all have defaults. `timeout_ms` is accepted by `disk`
  and `info` (exit 124 with partial results on a hung mount).
- cgroup figures come from the process's own v1 or v2 group with
  hierarchical limits; CPU percentages no longer count guest time twice or
  iowait as busy; per-CPU ids are the kernel's CPU numbers.
- `include_swap`, `info fields`/`include_raw`/`include_paths`/
  `max_process_classes` work; `env.list include_raw` is masked; no
  subprocesses are run (`kernel.machine` is the hardware name); `disk` lists
  `overlay`, decodes mount escapes and no longer panics on non-ASCII names.

### cert

- Every verb refuses unknown arguments, invalid values and options of another
  mode (exit 2, `cert.invalid_argument`); exit codes are 0/1/2/124 with
  `[cert.<code>]` errors (verify failures exit 1, not 7). `timeout_ms` is
  enforced on generate, csr.create, sign and renew (default 300 s; at the
  deadline nothing is written) and refused elsewhere.
- Encrypted private keys work: PKCS#8 `ENCRYPTED PRIVATE KEY` (PBES2 with
  PBKDF2 and AES-CBC) is read and written. `key_kdf=argon2id` is refused.
  Legacy `Proc-Type: 4,ENCRYPTED` keys are refused with a conversion hint.
- `verify` validates the chain with rustls-webpki and accepts `ca_file=`;
  `chain.info` builds every path and reports `trusted` only when webpki
  validates it.
- `csr.create` writes key usage and extended key usage into the CSR and
  writes PKCS#1/SEC1 keys correctly (SEC1 with the named curve).
- `info` fingerprints are now digests of the whole certificate (they were
  wrong before); an unrecognised DER file is an error.
- No cert output is written through a symlink; certificates, CSRs and
  signatures are 0644, keys 0600.

### pkg

- Every verb reads only `input=<json>`; any other argument, an unknown JSON
  key (also in package entries), a wrong type or an invalid value is refused
  with exit 2 (`pkg.invalid_argument`). Options a manager cannot honor are
  refused (`pkg.unsupported_option`) instead of being ignored. Exit codes are
  0/1/2/124 with `pkg.*` codes.
- `timeout_ms` stops the package manager and everything it started and
  exits 124; `pkg.md` 3.3 lists what each manager may leave behind.
- restore `mode: exact` installs, upgrades and downgrades to the locked
  versions and fails a package left at another version (pacman only to what
  its repositories carry; brew refuses); `best_effort` falls back with a
  warning. Versions are ordered by each manager's own algorithm.
  `extra_args` and `env` reach every restore command.
- snapshot `format: yaml` produced JSON and text lockfiles could not be
  restored; both round-trip now. `exclude_patterns` are shell globs.
- apt: package upgrades no longer install packages that were not installed
  (`--only-upgrade`); config-files packages are no longer listed as
  installed. dnf 5 is supported.
- Tested end to end in Docker against apt (Debian 13, Ubuntu 24.04), dnf
  (Fedora 42), yum (Rocky 9), pacman (Arch) and apk (Alpine).

### http and https

- 4xx/5xx statuses exit 1 (`http.status_error`) on every verb; `timeout_ms`
  is a whole-request deadline on every verb (exit 124); `allow_insecure`
  works on every verb; strict arguments.

### dns

- lookup/resolve/trace use resh's own DNS client: authority, additional and
  `raw` are filled, `trace` follows referrals, `servers=` is honored.
  `zone.fetch` signs AXFR/IXFR with TSIG and verifies every reply message;
  IXFR is real. Strict arguments; JSON errors are objects for every verb.

### net

- `ping` exits 1 when the host is unreachable; `tcp_check` honors `port=` and
  `expect_tls` performs a verified TLS handshake; `list` reports real
  interface flags, MAC and MTU (`up` means the interface is up);
  `route.list` honors `table=`; DNS TTLs are real.

### mail

- `test` opens a real SMTP session (TLS, AUTH, NOOP); `send`,
  `send_template` and `test` use the active stored profile when no host is
  given; `tls_accept_invalid_certs=true` disables certificate verification
  and STARTTLS never falls back to plain text; `header_<Name>` headers are
  sent; `mail://` arguments are no longer rewritten into `send`.
- Profile passwords live in the OS keyring, never in the file; `ca_file=<pem>`
  on send, send_template and test trusts a private CA with verification on.

### archive

- archive: every verb refuses unknown arguments and malformed values (exit 2,
  did-you-mean); exit codes are 0/1/2/124 (timeout_ms is enforced); invalid
  max_*_bytes on extract exits 2; glob patterns are shell-style (* and ? do
  not cross '/', ** does); the tar header-data limit is reported as
  archive.<verb>_archive_read_error (list now prints a JSON report for it),
  and extract size limits as extract_max_size_exceeded /
  extract_max_file_size_exceeded instead of extract_archive_read_error; test
  fails when max_entries is exceeded; add stores uid/gid 0 unless
  preserve_owner=true; extract follow_symlinks=true is refused; the remove
  backup is <archive>.<suffix> (leading dot optional) and is a copy;
  add/remove do not rewrite when nothing changes; create can write tar.xz and
  tar.zst.

### file

- `file`: strict arguments (exit 2, did-you-mean), coded errors, exit 124
  timeouts, copy preserve_times and rename atomic implemented, renames that
  never lose an existing destination, recursive chown that never follows
  links, find skips hidden directories and uses shell-style globs.

### fs

- `fs`: strict arguments (exit 2, did-you-mean) and exit codes 0/1/2/124.
  Every tool runs under the operation deadline and is stopped at
  `timeout_ms` (exit 124); previously fs timeouts left the tool running.
  fsck/scrub failures are no longer reported as success; repair on a mounted
  xfs/btrfs is refused instead of silently only checking; `resize` uses the
  filesystem's native size and honors `force`; quota output is parsed
  correctly and `all_subjects` is implemented; `max_pass` is refused; mount
  targets that are symlinks are refused. mount, unmount, resize, check and
  quota are tested as root against real ext4/xfs/btrfs/vfat images and loop
  devices in a privileged container (`tests/fs_docker.rs`).

### cron and pkg

These options were parsed and then ignored. Each one now does what its name
and help define, or is refused with an error where nothing defines it. Unit
tests drive each verb through the handle (`option_tests` in `cronh.rs` and
`pkgh.rs`), and `tests/option_wiring.rs` runs the `resh` binary against fake
`crontab`, `systemctl` and apt tools.

- **cron `add timezone=`** was ignored. systemd timers now get the zone on
  `OnCalendar=`. The cron backend writes a `CRON_TZ=` line in a time-zone
  block at the end of the file, so other jobs keep their zone. Only cronie
  honors `CRON_TZ`, so the cron backend refuses `timezone` unless
  `crontab -V` identifies cronie (`cron.add_timezone_unsupported`). Unknown
  zone names are refused. `rm` removes a job's `CRON_TZ` line with it.
  `list`, `rm`, `enable` and `disable` report each job's zone. See
  `cron.md` 3.3.
- **cron `list timezone=`** was ignored. It is now the zone used for
  next-run times of entries without their own `CRON_TZ`.
- **cron next-run times** ignored `now_unix` and always counted from the
  current time, and were computed in UTC. `list now_unix=` and `add now_unix=`
  (which was also ignored) are now the reference time (Unix seconds
  0-253402300799). A malformed or out-of-range value is refused. Without
  `timezone=`, next runs use the host's local zone (TZ, else the zone
  /etc/localtime links to, else a matching /etc/timezone). If no name is
  found, the current offset is used and a warning says so. The zone used is
  reported as `next_run_timezone`.
- **cron `rm cron_file=` and `enable cron_file=`** were ignored, so the verbs
  acted on the crontabs chosen by `scope`. They now act on that file only,
  with the same restriction as `disable` (`/etc/crontab` or
  `/etc/cron.d/<name>`; anything else gives `cron.<verb>_invalid_argument`).
- **pkg `info include_repo: false`** and **`list_installed include_versions:
  false`** were ignored. They now set `repository` and `version` to null.
- **pkg `restore on_repo_mismatch`** and **`include_dependencies`** had no
  effect. They now compare locked and host repositories (fail, warn or
  ignore) and leave locked dependencies out of the plan, as described in
  `pkg.md` 3.4. Restore output has a new `warnings` list.
- **pkg package `source`** (install and remove) was silently ignored. No
  manager defines it, so a request that sets it is now refused before
  anything runs.
- **pkg `snapshot inline`** was accepted and ignored. It is removed: a
  request with `inline` is refused before anything runs (exit 2).
- **pkg apt repository** (snapshot, restore `on_repo_mismatch`) recorded the
  `apt-cache policy` priority (`500`) instead of the installed version's
  suite/component (`noble/main`). It now records the suite/component, or none
  for a package known only from `/var/lib/dpkg/status`. apt lockfiles from
  earlier releases report every package as a repository mismatch; take a new
  snapshot.
- **Exit codes:** pkg is aligned: every error is `Error: [pkg.<code>] ...`
  with exit 0/1/2/124; codes are listed in `pkg.md` 3.6.

## v1.0.6-beta security release (2026-11-03)

Security hotfix on top of v1.0.5-beta, scoped to the `firewall://` handle and
the external-tool execution path. Each fix has regression tests (unit tests in
`firewallh`, `tests/process_containment.rs`) and was validated against real
nftables, iptables and ufw backends. No dependencies changed.

- **firewall command injection (R4-02):** rule fields are validated as single
  tokens before any backend command is built, and a rule a backend cannot
  express in full is refused. A crafted field value could previously inject
  extra `nft`/`firewalld` statements.
- **ambiguous numeric parsing (R5-03):** ports, numeric protocols and CIDR
  prefix lengths must be unambiguous decimal; leading-zero (octal) forms such
  as `022` or `/010` are refused instead of being applied by the backend as
  octal.
- **incorrect rule deletion (R5-02):** an nftables rule's action is read from
  the rule, not from its comment, so a delete by action cannot select a rule
  whose comment merely mentions that action.
- **incorrect idempotence (R5-01):** an idempotent iptables add no longer
  treats a rule narrowed by an unmodeled match as satisfying a broader
  request.
- **timeout containment (R4-01):** external tools and their `setsid`
  descendants are stopped at the operation deadline; an unconfirmed outcome
  reports exit 124 rather than a false success.

Limitations that remain in v1.0.6-beta:

- **firewalld** shares the validated field-acceptance path with nftables,
  iptables and ufw (so injection and numeric rejection apply equally). Its
  rule rendering and read-back were checked only against firewalld running in
  a container, not on a full systemd host.
- **Install script.** `get.reshshell.dev` has not been updated for this
  release and installs an older version. Install from the GitHub release (see
  the README).

## v1.0.5-beta security release (2026-10-29)

These fixes are in v1.0.5-beta, each with regression tests
(`tests/stage7a_security.rs`, `tests/stage7b_security.rs` and unit tests in
the affected handles). They are not in v1.0.4-beta or earlier.

- **archive extract size limits** were checked against the sizes a zip or tar
  archive records, not the bytes written, and a raw stream was written in
  full before they were checked, so a crafted archive could write past
  `max_file_bytes` and `max_total_bytes`. Limits now apply to the bytes
  written, files are written to a temporary name first, and a limit that is
  not a whole number of bytes is refused instead of meaning no limit. See
  `archive.md` 3.2.
- **tar header data** (PAX extended headers, GNU long name and long link
  headers) was read into memory up to the size the archive declared, so a
  small compressed tar archive could make `archive list`, `test`, `info`,
  `extract`, `add`, `remove` or `plugin install` use gigabytes of memory.
  More than 1 MiB of header data for one member is now refused. See
  `archive.md` 3.2 and 6.
- **fs `mount` `source`/`target` and user `add` `primary_group`** values
  starting with `-` could be read as options by `mount`, `umount`,
  `useradd`, `groupadd` or `usermod`. They are now refused and operands are
  passed after `--`.

Limitations that remain in v1.0.5-beta:

- **Accepted dependency advisories.** `cargo audit` passes only with the
  advisories listed in `.cargo/audit.toml`, each with its assessment, and it
  still reports warnings for unmaintained, unsound and yanked crates. None
  of these is removed by this release.
- **Remote restic and borg dry runs** (`backup prune dry_run=true`) were not
  tested; see `backup.md` 4.5.
- **Concurrent changes to the filesystem.** Archive extraction and other
  path checks protect against malicious input, not against another process
  changing the tree at the same time; never extract as root into a directory
  other users can write.
- **Release artifacts** carry a SHA-256 checksum (`SHA256SUMS`) but no
  signature or build provenance attestation. The checksum detects corruption
  in transit, not a compromised release.
- **Platforms.** The prebuilt binary is Linux x86_64 only and needs glibc
  2.39 or later plus OpenSSL 3; other systems must build from source with
  Rust 1.88 or later.

## v1.0.4-beta security release (2026-10-27)

These fixes are in v1.0.4-beta, each with regression tests
(`tests/stage6b_security.rs` and unit tests in the affected handles). They
are not in v1.0.3-beta or earlier.

- **backup argument handling.** Values from `src`, `snapshot_id`, `dest` and
  `repo_url` could be read by tar, rsync, borg or restic as options or as
  remote locations, which could run commands. Values are now validated before
  anything runs (including dry runs), option values are attached with `=`,
  positional values follow `--`, tar runs with `--force-local`, and rsync
  gets local relative paths with a `./` prefix. See `backup.md` 3.3.
- **backup `prune dry_run=true`** validated nothing before running restic or
  borg in their own dry-run mode. Validation now comes first, and the result
  states which kind of dry run ran (`dry_run_mode`: `plan` or `backend`).
- **cron `add`** wrote line breaks in job fields into crontabs and unit
  files (extra jobs or unit directives), used `unit_name` in file paths
  unchecked, accepted any file as `cron_file` for `scope=system` (and
  `disable cron_file=` rewrote any file), and wrote six-field schedules that
  cron misreads. Every field is now checked against its own syntax before
  anything is written or previewed, `cron_file` is limited to `/etc/crontab`
  and `/etc/cron.d/<name>`, unit values are escaped, and crontab and unit
  files are never written through symbolic links. See `cron.md` 3.3.
- **ssh `exec`** passed `command_args` to the remote shell mostly unquoted.
  Each argument is now quoted for POSIX login shells; cmd/PowerShell modes
  refuse arguments that would need quoting; an unknown `shell_mode` is an
  error; and `command.raw` is the exact remote string. ssh error envelopes
  now report the requested `dry_run` instead of always `false`. See `ssh.md`.
- **cert `sign signature_algorithm=ecdsa_sha512`** with a P-384 key produced
  a SHA-384 signature. It now signs a SHA-512 digest; unsupported key and
  algorithm pairs are refused.

## v1.0.3-beta release gate (2026-10-23)

The v1.0.2-beta release gate
(`docs/reviews/resh-cli-v1.0.2-beta-release-gate.md`) re-assessed the
remaining Medium risks and found three that are release blockers. They are
fixed in v1.0.3-beta, each with regression tests:

- **cert private keys** (`generate`, `renew key_strategy=rekey`,
  `csr.create key_strategy=generate`) were written with the umask mode and
  then changed to 0600, so another local user could open the key in between;
  the write also followed a symlink at the key path, and a dangling symlink
  bypassed `overwrite=false`. Keys are now created 0600 from the start and a
  symlink at the key path is refused. `csr.create` no longer replaces an
  existing `new_key_output_path` without `overwrite=true`.
- **`file replace backup=<suffix>` and `archive add backup_suffix=`** copied
  through a symlink planted at the backup name, overwriting its target and
  changing its mode. The backup is now written to a new temporary file and
  renamed into place; a symlink at the backup name is refused.
- **backup default repositories** under `/tmp` (`/tmp/resh_backup_<profile>`,
  `/tmp/rsync_backup`, `/tmp/borg_repo`) left archives readable by every
  local user and were accepted when another user had created them first.
  The defaults are removed: tar, rsync and borg now require `repo_url`.

Also corrected: a real MySQL connection string with a password was removed
from `MYSQL_CONNECTION_GUIDE.md`. It is still in earlier tags and in the
repository history, so it must be treated as compromised.

## Release-candidate status (2026-10-23)

This section supersedes the test counts and "Still open" list in the
2026-10-16 status below. The full evidence is in `docs/reviews/`
(Stage 1-3 remediation reports and the Stage 4 release assessment).

- **Tests:** `cargo test --locked` passes: 1,181 lib and 1,185 bin unit
  tests, plus the help, documentation-example and CLI regression suites; 11
  infrastructure tests are `#[ignore]`d and pass against disposable git,
  PostgreSQL and MariaDB with `--ignored`.
- **Fixed in Stage 4 (release-candidate verification):**
  - `pkg update/upgrade security_only=true` silently ran a full upgrade on
    apt, pacman, apk and brew (and yum for upgrade). It is now refused
    before anything runs where resh cannot restrict the upgrade.
  - `backup create/prune` treated a malformed `dry_run` as false and ran
    for real; `backup restore dry_run=true` performed a real restore. Both
    are now refused.
  - `mail://send` ignored `dry_run` (including the bare word) and sent the
    message. A dry-run request is now refused before any SMTP connection.
  - `fs mount/unmount` treated a malformed `dry_run` as false; it is now an
    error.
  - `fs resize` on ext3/ext4 asked `resize2fs` for a quarter of the
    requested size; the size argument is now correct.
  - `file rename to=<bare name> overwrite=true` deleted the destination and
    then failed; bare destination names now work for rename, copy and move,
    and the parent is checked before anything is deleted.
  - `archive add/remove` on `.tar.zst` wrote a truncated archive; the zstd
    stream is now finished.
  - `mail://config` wrote SMTP profiles (with base64 passwords) using the
    umask, typically world-readable; the file is now 0600.
  - `firewall rules.reload` from a normalized JSON snapshot wrote the rules to
    a predictable `/tmp` name that a local user could pre-create as a
    symlink; it now uses a securely created temporary file.
  - `resh` with no stage panicked (exit 101); it now prints an error and
    exits 2.
  - A verb without a dry-run mode ignored `dry_run=true` and made the real
    change (for example `file delete dry_run=true` deleted the file), and
    misspelled dry-run words and keys (`dry-run`, `DRY_RUN=true`) were
    dropped. A top-level `dry_run=true` was also ignored by `pkg`, which
    reads it only from `input=`. The dispatcher now refuses all of these
    before the handle runs.
  - `archive add` rebuilt existing tar entries without their headers (mode
    0, owner 0, mtime 0, symlinks became empty files); it now keeps the
    original headers. Archive rewrites use unpredictable, non-following
    temporary files with the original permissions, and compression errors
    at the end of the stream fail the operation.
  - `fs resize` ran `lvextend`/`lvreduce` through `sh -c`; it now runs them
    without a shell.
  - TLS dependencies patched (rustls 0.23.46, rustls-webpki 0.103.16,
    webpki-roots 1.0.10), plus bytes 1.11.1 and h2 0.4.16.
- **Significant limitations that remain** (each is documented in its
  handle's page under `docs/`):
  - Unsupported by design in this release: encrypted ZIP creation, backup
    `schedule` installation, cert
    encrypted keys. (dns `zone.update`
    and cert CMS signatures were added after v1.0.6-beta.)
  - SMTP profile passwords are kept in the OS keyring (Secret Service /
    Keychain); the profile file holds only a reference. Without a keyring,
    storing a password is refused (pass it per call or via
    MAIL_SMTP_PASSWORD). Legacy base64 passwords are still read, with a
    warning, and moved to the keyring on the next config change. The macOS
    Keychain path is not tested.
  - `secret://local` values are kept in the OS keyring (service
    `resh-secret`); `local.json` is an index of names only. Without a
    keyring, local reads and writes are refused (use `env` or `vault`).
    The plaintext store of earlier releases is still read, with a warning,
    and moved to the keyring on the next write. The macOS Keychain path is
    not tested.
  - No dry-run mode for svc, proc (except `limits.set`), file writes (except `file replace`),
    cache/db writes, mq, mail send and backup restore; for
    these `dry_run=true` is refused before anything runs; git enforces
    `timeout_ms` on every verb (exit 124; network verbs default to 600 s); `file` enforces `timeout_ms` on every verb whose work can be
    long (exit 124) and refuses it on instant verbs.
  - Option-injection hardening (`--` separators) for backup argv, cron job
    fields and ssh `command_args` is in v1.0.4-beta (see the section
    above); in v1.0.3-beta and earlier, never pass untrusted input in
    backup `src`, `snapshot_id`, `dest` or `repo_url`, in cron job fields,
    or in ssh `command_args`. User `primary_group` and fs `mount`
    `source`/`target` are refused when they start with `-` and passed after
    a `--` separator from v1.0.5-beta; in v1.0.4-beta and earlier, never
    pass untrusted input in them.
  - Archive extraction checks paths but not against a concurrent process
    changing the destination tree; never extract as root into a directory
    other users can write.
  - Do not run plugin verbs as root with another user's `HOME`/`XDG_*`
    (for example `sudo -E`): `remove` and `remove purge=true` then act on a
    store that user controls and can be made to delete files outside it.
  - Existing tar or rsync repository directories are used as they are:
    resh does not check their owner or mode. Use a directory only you can
    write.
  - Plugin enabled state is written and read from different files, so
    `installed.list` reports enabled plugins as disabled.

## Status (2026-10-16, historical)

All **Critical**, **High** and **Low** issues below have been fixed. Each fix
has unit tests, and the help metadata was updated to match the new behavior.
These **Medium** items were also fixed:

- archive: `.tgz` handling, duplicate entries, and the `format` key.
- fs `usage` warnings and the `DEBUG` lines.
- The cron selectors and paths.
- proc signal names.
- backup prune dry run and untagged restic snapshots.
- plugin targets.
- template strict mode.
- config: `..` targets, ls recursion and prefixes, strict argument checking,
  and get no longer creating directories.
- template: `timeout_ms` is enforced, and validate reads `template=` and
  `context_file`.
- config: value files are 0600 and created directories 0700; template: macro
  recursion is limited to 200 levels instead of overflowing the stack.
- db `tls_mode` and `log_queries`.
- cert info, fingerprints, generate and curves.
- The firewall status text.
- The system memory defaults.
- ssh `exec cwd=`, upload, `key.add` and test.

Every other Medium entry below is still open.

Not verified against real systems: the fixes involving root, network or real
devices (firewall, user, ssh, cache/db servers, restic/borg repositories) were tested through unit tests on the exact commands they
build, plus dry runs. They have not been run against live systems.

Test suite at that time: 1044 passed, 15 failed (all 15 were fixed in
Stages 1 and 3; see the release-candidate status above).

### Fixed

| ID | Fix |
|---|---|
| C1 | backup: the password comes from `password=`, `password_file=`, or the restic/borg password environment variables. With none, the command fails with `MISSING_PASSWORD` before running anything. |
| C2 | firewall `rules.delete`: iptables rules are deleted by full rule spec. Rule ids follow each backend's own numbering. Default `match_mode=exact`. A delete with no criteria is refused. |
| C3 | firewall `rules.add family=any`: adds both the IPv4 and IPv6 rule. With an address, the family follows the address, and a mismatch is an error. |
| C4 | ssh `download` and `upload`: real transfers over the system `ssh`. Writes go to a temp file that is renamed into place. Checksums are reported only when actually compared. |
| C5 | cert `verify`: real chain signature checks (ring), trust anchors, hostname, purpose and keypair checks. A check that was not performed is reported as `not_checked` or `unsupported`, never as a pass. |
| C6 | secret: values are in the OS keyring, never in a file; `local.json` holds only names and keyring references (0600 from creation, 0700 directory, atomic, symlinks refused, writers locked). No `/tmp` or file fallback: without a keyring, writes are refused. Legacy plaintext stores are read with a warning and migrated on the next write. |
| H1 | plugin `install` and `update` really install, and `dry_run` returns the plan. Nothing panics. |
| H2 | In-URL help detection is exact everywhere (`help::is_help_flag`, `parse.rs` `is_help_request`). |
| H3 | cron: `extract_job_id` uses the right offset. `match_comment`, `/etc/cron.d` paths, path reporting and `list` arguments are also fixed. |
| H4 | backup: every command runs the right program. tar and rsync list and prune use direct file access. |
| H5 | backup `create`: restic, borg and rsync output is parsed, and a successful backup is reported as success. |
| H6 | user: changes run for real (dry run lists `planned_commands`). Passwords go to `chpasswd` on stdin. Lock state and groups come from real lookups. JSON output is clean. `user://alice` targets alice. |
| H7 | `core::lenient` converts CLI strings into typed options. Used by fs, git and db; system also accepts plain key=value arguments. |
| H8 | file (and snapshot): the URL host and path are joined, so `file://dir/x` is `dir/x`. |
| H9 | cert `renew` uses the signer and the reused or new key, and reports the real certificate. `csr.sign` and `sign mode=csr` issue real certificates from the CSR. |
| H10 | pkg: a text lockfile restores using the requested or detected package manager. |
| H11 | cache and db verbs connect on demand (`url=`, `dsn=`). `db transaction action=run` runs a transaction in one call. Events are stored in files under the state directory. |
| L1 | The old `*_HELP_TEXT` constants are deleted. Every in-URL help form prints the approved help (`help::render_legacy`). |
| L2 | `plugin://<id>.enable` and `plugin://available.list` now work. README and docs match the real syntax. |
| L3 | `.gitignore` ignores only root-level `/test*` scratch files, so `tests/` is tracked. |
| L4 | cert tests use temp directories, db tests no longer race, and the template strict-mode bug is fixed. |
| L5 | `src/backends` is removed, along with the `pub use backends::*` re-export in `src/lib.rs`. |

### Behavior changes users will notice

- backup:
  - restic and borg now require a password.
  - A failed list, restore, verify or prune now returns an error instead of
    success.
- firewall `rules.delete`:
  - With the default `match_mode=exact`, a rule matches only if all its
    conditions match. Use `match_mode=subset` for the old behavior.
  - A delete with no criteria is refused.
- user commands now change the system. Previously they only printed what
  they would do.
- `archive create`: `format` means only the archive format. The report
  format is set with `format_output=`.
- fs, git and db: an invalid typed value (for example `timeout_ms=soon`) is
  now an error instead of being silently replaced by the default.
- `plugin://install` (no plugin id) is now an error.
- cert:
  - `key_passphrase` now fails, because key encryption is not supported. It
    used to write an unencrypted key and report it as encrypted.
  - `cert:///abs` stays an absolute path.
- On http, net and dns, `--help=<unknown verb>` now shows the full handle
  help and exits 0. Before, net exited with status 2.

### Still open

These were found during the fixes, or are Medium items that were not fixed:

- **Timeouts:** fixed in Stage 2 (FUNC-08). Backup timeouts now kill the
  backend at the deadline and fail with a `TIMEOUT` error. Stage 3: firewall
  `timeout_ms` is enforced the same way. (Git rejected `timeout_ms` at that
  stage; it is now enforced, see Unreleased: a stalled SSH server or a long
  local libgit2 call is reported as outcome unknown, exit 124.)
- **cert:** revocation (CRL/OCSP) is not checked; webpki does not accept a
  CA certificate as the end-entity of `verify`.
- **backup `schedule`:** installs nothing.
- **Pre-existing test failures (15):** all fixed. `archiveh::test_path_sanitization`
  in Stage 1; the 11 `userh` and 3 `gith` tests in Stage 3 (details in
  `docs/reviews/resh-cli-stage3-build-test-security.md`). Tests that need a
  database server or a git remote are marked `#[ignore]` and run with
  `--ignored` against disposable infrastructure.

---

## Critical

### C1. `backup`: restic and borg passwords are hard-coded

- **Where:** `src/handles/automation/backuph.rs:1476, 1580, 1630, 1675, 1721`
  set `RESTIC_PASSWORD`, and `:1507, 1594, 1648, 1688, 1746` set
  `BORG_PASSPHRASE`. Both are set to `"backup123"`, with the comment
  `// Default for demo`.
- **Impact:** every restic or borg repository that resh creates is encrypted
  with a password anyone can read in the source.
- **Fix:** take the secret from an argument, an environment variable, or the
  `secret://` handle, and fail if none is provided.
- **Note:** `src/backends/backup/*` has a configurable `repo_password`, but
  that code is never used (see L5).

### C2. `firewall rules.delete` on iptables can delete the wrong rule

- **Where:** `src/handles/security/firewallh.rs`.
  - `:4695-4725` resets the rule counter for each table and increments it for
    every rule in that table, across all chains.
  - `:7362-7363` builds `rule_id` as `CHAIN:<counter>`.
  - `:7435` emits `-t <table> -D <chain> <N>`.
- **Impact:** for any chain after the first one in a table, `N` is not the
  rule's line number within its chain, so a different rule, or no rule, is
  deleted. The fallback at `:7366` uses the index within the filtered list,
  which is also wrong.
- **Also:** `rule_id` and `match_mode` are used for matching (fixed;
  `zone` applies to firewalld only).
- **Exposure:** `rules.*` verbs were unreachable from the CLI until the
  scheme-aware dotted-verb fix in `src/core/parse.rs`. This bug is now live.
  Gate `rules.delete` behind `dry_run`, or fix it, before release.

### C3. `firewall rules.add family=any` never adds an IPv4 rule

- **Where:** `firewallh.rs:6751` chooses `ip6tables` for any family other
  than `ipv4`.
- **Impact:**
  - `family=any` creates an IPv6 rule only.
  - The reported rule shows `saddr`/`daddr` `0.0.0.0/0` (set at `:6641`,
    then dropped from the command at `:6777, 6784`).
  - An explicit IPv4 `saddr` with `family=any` is passed to `ip6tables`.
- **Exposure:** like C2, this verb became reachable with the parser fix.

### C4. `ssh download` overwrites the destination with placeholder data

- **Where:** `src/handles/network/sshh.rs:5481` writes
  `b"key: value\ndata: test\n"`, then `:5522-5530` renames that over `dest`.
- **Impact:** with `overwrite=true`, a real local file is replaced by fixed
  junk. The response still reports success, a fake size of 2048 bytes, and
  `checksum_verified: true` (`:5471-5473, 5565`).
- **Fix:** fail with "not implemented" until SFTP transfer exists.

### C5. `cert verify` reports success for checks it does not perform

**Status: fixed (Unreleased).**

- **Where:** `src/handles/security/certh.rs`.
  - The chain check (`:4147`) passes any certificate that is not
    self-signed.
  - The usage check (`:4202`) and the keypair check (`:4211`) always pass.
  - `verify_hostname` (`:4180-4184`) accepts any hostname whenever a SAN
    extension is present.
  - Soft revocation (`:4217`) reports a pass even though it is not
    implemented.
  - The `trust`, `trust_paths`, `trust_pem`, `max_chain_depth` and
    `min_rsa_bits` options are parsed but never applied.
- **Impact:** automation that relies on `verify` accepts untrusted or
  mismatched certificates.

### C6. `secret` local store is plaintext and briefly world-readable

**Status: fixed (Unreleased).** Values are in the OS keyring; see the
Unreleased `secret` section. The description below is kept for reference.

- **Where:** `src/handles/security/secreth.rs`.
  - `:1403-1406` writes plain JSON to
    `<state_dir>/resh/secrets/local.json`, falling back to `/tmp` when there
    is no state directory (`:1367-1369`).
  - Permissions are set to 0600 only after the write (`:1410-1418`).
- **Impact:** secrets sit unencrypted on disk, readable under the default
  umask during the window before permissions are tightened, and possibly in
  `/tmp`. The old `SECRET_HELP_TEXT` calls the store "encrypted"
  (`:25, 27, 44, 47`).
- **Fix:**
  - Create the file with 0600 from the start (`OpenOptions` plus `mode`).
  - Never fall back to `/tmp`.
  - Encrypt the store, or stop calling it encrypted.

---

## High

### H1. `plugin install` and `plugin update` panic on `todo!()`

- **Where:** `src/handles/pluginh/plugin/engine.rs:121, 124`.
- **When:** resolve and plan succeed with an Install or Update decision.
  `dry_run` is not checked first, and nothing catches the panic.
- **Fix:** return a "not implemented" error, and honor `dry_run` before
  reaching that code.

### H2. Any target containing "-h" is treated as a help request

Each of these uses a substring check instead of an exact match, so targets
such as `/home/x/my-hosts`, `my-httpd`, `pre-hotfix` or `plugin://my-helper`
print help instead of running.

| Handle | Location |
|---|---|
| file | `src/handles/filesystem/fileh.rs` (`from_url`, `call`) |
| cert | `src/handles/security/certh.rs:2488-2489` |
| snapshot | `src/handles/filesystem/snapshot.rs` (`SnapshotHandle::from_url`, `Handle::call`; search `HELP_ALIASES`) |
| svc | `src/handles/processes/svch.rs:2181-2183` |
| proc | `src/handles/processes/proch.rs:2297` |
| db | `src/handles/data/dbh/mod.rs` (`DbHandle::help_topic`)` |
| plugin | `src/core/parse.rs:88`; `src/handles/automation/pluginh.rs:1224` |
| parser | `src/core/parse.rs:272` (only a fallback when no verb is split off) |

- **Fix:** match whole tokens (`== "--help"`, `== "-h"`), or rely on the new
  `resh <handle> --help` path.

### H3. `cron enable` and `cron disable` cannot match a job by id

- **Where:** `src/handles/processes/cronh.rs:4743` (enable) and `:5259`
  (disable) slice `&line[start + 8..]` after finding `"job-id="`, which is
  7 characters.
- **Impact:**
  - The first character of the id is dropped, so `target_id == entry_id`
    (`:4941, 5398`) never matches.
  - A line ending exactly in `job-id=` makes the slice panic.
- **Note:** `rm` is correct (`:5519`).
- **Fix:** use `start + "job-id=".len()`.

### H4. Several `backup` commands run the wrong program

- **Where:** `execute_backend_command` (`backuph.rs:661-669`) always runs
  `Command::new(<backend>)`, but some argument lists start with a different
  program's name:

| Operation | Command actually run | Location |
|---|---|---|
| tar list | `tar ls -la <repo>` | `:1615` |
| tar verify | `tar find <repo> -name *.tar.gz -exec tar -tzf {} ;` | `:1706` |
| rsync list | `rsync ls -la` | `:1604` |
| rsync verify | `rsync find ... -exec test -r {} ;` | `:1220-1224` |
| rsync restore | `rsync rsync -av src dest` | `:1144` |
| tar and rsync prune | `tar find ...` / `rsync find ... -mtime +30` | `:1302` |

### H5. `backup create` reports failure after a restic, borg or rsync backup succeeds

- **Where:** `parse_create_output` (`backuph.rs:1770-1786`) handles only tar;
  every other backend hits `bail!("Backend not yet implemented")` (`:1785`).
- **Impact:** `verb_create` has already run the backup (`:965`), then turns
  that error into a `PARSE` error envelope (`:985-994`). Scripts see a
  failure for a backup that completed.

### H6. `user` changes are simulated, and their log lines corrupt the JSON

- **Where:** the default `UserBackend::System` in
  `src/handles/security/userh.rs`. For example: useradd `:2781`, userdel
  `:3123`, lock/unlock `:3549, 3595`.
- **Simulated:** every change (useradd, groupadd, usermod, userdel, groupdel,
  gpasswd, password, lock, unlock) only prints `Would execute: ...`.
- **Always-false stubs:** `is_locked` and `verify_password` always return
  false (`:3502, 3396`).
- **Partial lookup:** the group lookup returns only the primary group
  (`:3267-3297`).
- **Output corruption:** those `println!` lines go to process stdout, not
  `io.stdout`, so they corrupt JSON output.
- **Target bug:** `UserHandle::from_url` (`:3983-3987`) reads only the URL
  path.
  - `user://alice` targets a user named "default".
  - `user://group/admins` targets "admins" as if it were a user.
  - `UserTarget::from_url` (`:2266`) handles the host form correctly, but it
    is used only in tests.

### H7. Typed options cannot be passed from the command line

CLI arguments are always strings (`Args = HashMap<String, String>`,
`src/core/registry.rs:42`). Several handles deserialize them straight into
typed structs:

- **fs**: fixed; every option is parsed strictly and unknown arguments are
  refused (exit 2).
- **db query** (`src/handles/data/dbh.rs:4577-4597`, `:319-325`):
  `timeout_ms` and `max_rows` are silently ignored, so the defaults of
  5000 ms and 1000 rows always apply. `exec` converts its options correctly.
- **Fix:** add one shared helper that converts string values (`"true"`, or
  numbers as text) before deserializing, or use lenient `deserialize_with`
  functions.

### H8. `file://` relative paths resolve to the wrong file

- **Where:** `fileh.rs:1745-1750` uses the URL host alone whenever it is
  non-empty and discards the path.
- **Impact:**
  - `file://./x` resolves to `.`.
  - `file://dir/x` resolves to `dir`.
  - Only `file://name` and absolute `file:///path` work.
  - The global `--help` example in `src/main.rs:130` is
    `file://./foo.txt.read`, which hits this bug.

### H9. `cert renew` and `cert csr.sign` produce invalid certificates

**Status: fixed (Unreleased).**

- **renew** (`certh.rs:7350-7394`):
  - The `signer` parameter is never read; renew always self-signs with a
    fresh key.
  - That key is never saved. With `key_strategy=rekey`, a different,
    unrelated key is saved (`:3829`).
  - Validity settings are ignored (`:7380`).
  - The reported details are placeholders: `CN=renewed-cert`,
    `"dummy-fingerprint"` (`:7457-7486`).
- **csr.sign** (`certh.rs:5916-6051`):
  - Writes a mock certificate (`MOCK_CERTIFICATE_DATA_FOR_DEMONSTRATION`) with
    hard-coded subject, issuer, serial and fingerprints, and reports
    `ok: true`.
  - Is unreachable from the CLI: `cert://x.csr.sign` parses as the `sign`
    verb. This is intentional so that `cert://req.csr.sign` keeps working;
    see `UNREACHABLE` in `tests/help_coverage.rs`.

### H10. `pkg restore` with a text lockfile can never succeed

- **Fixed:** a text lockfile restores with the manager it records
  (`# manager: <name>`) or the requested/detected one.

- **Where:** `src/handles/system/pkgh.rs:8416` hard-codes the lockfile's
  manager as `"auto"`.
- **Impact:** `resolve_restore_manager` (`:8472-8503`) then fails either way:
  `manager=auto` gives `ManagerNotFound`, and any explicit manager gives
  `RestoreManagerMismatch`.

### H11. Connection-based handles cannot be used across separate commands

- **cache:** fixed. Connections last one process; every verb connects on demand
  with url=, and connect is a connectivity check.
- **db:** the connection and transaction registries exist only in memory
  (`dbh.rs:779, 961`).
  - `tables`, `schema`, `ping` and `transaction` always fail from a fresh CLI
    invocation.
  - A `tx_id` can never carry over to a later commit or rollback.
  - Only `query` and `exec` work, by connecting on demand with `dsn=`.
- **event:** fixed. Events are files under the state directory, shared by all
  resh processes of the user (store lock, sequence numbers, atomic
  consumer-group commits); hook state persists too.

---

## Medium

### Network

- **dns limits.**
  - `dnssec_validated`/`ad_bit` repeat the server's AD flag; resh does not
    validate DNSSEC signatures itself.
  - `zone.update`'s `zone_serial_at_least` is a separate SOA query before the
    update, not atomic with it. No EDNS for updates: UDP messages over 512
    bytes go over TCP.
  - Server discovery for `zone.fetch`/`zone.update` (no `servers=`) always
    asks the /etc/resolv.conf name servers on port 53.
- **net list** ignores the URL host (`net://if` is the convention).

### Filesystem

- **archive.** 7z is not supported, and raw .xz/.zst streams cannot be
  created (archive.md 1 and 6). Rewriting a tar with add/remove drops PAX
  extended attributes of kept entries; add/remove fail on zip archives whose
  kept entries are encrypted.
- **log.** `tail follow=true` polls files every 100 ms (no inotify); a file
  truncated and refilled past its previous size between two polls is not
  seen as truncated. With `follow=true`, `journalctl --follow` shows only
  the current boot's entries. Service names cannot be glob patterns; there
  are no time-range or priority filters.

### Processes


### Automation

- **backup.**
  - `schedule` installs nothing (`backuph.rs:1359-1425`).
  - A `prune` dry run never calls the backend, so `would_prune` is always 0
    (`:1308-1326`).
  - restic snapshots without tags or paths are dropped from `list`
    (`:1794-1808`).
- **plugin.**
  - `enable` and `disable` cannot target a named plugin: `plugin://aws.enable`
    parses as verb `aws.enable`.
  - The `available.*` verbs need doubled targets such as
    `plugin://available.available.list` (`src/core/parse.rs:34, 82-158`;
    `pluginh.rs:572, 676`).

### Data and system

- **event.** Hook log files and mq queues filled by the hooks are never
  trimmed (by design; read or delete them).
- **cert.** All items below were fixed after v1.0.6-beta (P-521 and secp256k1
  are refused up front, exit 2).
- **git.**
  - `known_hosts_path` enforces strict SSH host-key checking on the URL
    libgit2 really connects to (after insteadOf/pushInsteadOf), steering the
    SSH library to the key types the file lists. Remaining limit:
    `@cert-authority` (CA-signed host keys) is not supported. See `git.md` 4.4.
  - `clone depth=<n>` works over network remotes only; libgit2's local
    transport cannot make shallow clones, so file:// URLs and local paths are
    refused (exit 2).
- **system.** `/proc`-based figures (system memory, CPU utilization, load,
  uptime) describe the whole host inside a container; a `statvfs` hung past
  `timeout_ms` leaves a worker thread behind.
- **pkg.** Every verb needs `manager` in `input`, but the `PKG_HELP_TEXT`
  examples omit it. Fixed: every example sets manager (tested).

---

## Low

### L1. The old embedded help texts are out of date

The per-handle `*_HELP_TEXT` constants (shown by forms like `svc://--help`)
disagree with the code in many places, including wrong argument names,
wrong defaults and non-working URL forms. Examples:

- **pkg:** the examples omit `manager`. Fixed: every example sets manager
  (tested).
- **plugin:** the examples use `plugin://aws.enable()`.

The new `Handle::help()` metadata follows the code. Consider removing the old
constants, or generating them from the new metadata.

### L2. README and docs show plugin commands that don't work

- `README.md:153`: `plugin://security-scanner.enable`
- `docs/Automation_Utilities/plugin.md:127, 139`
- `docs/Automation_Utilities/overview.md:113, 269, 270`
- `docs/resh_overview.md:174`

### L3. `.gitignore` keeps the test suite out of git

- `.gitignore:223` (`/tests/*`) and `:236` (`test*`) ignore `tests/`, so
  `tests/help_cli.rs`, `tests/help_coverage.rs` and `tests/golden/` are not
  tracked.
- `test*` also matches any file whose name starts with "test" anywhere in the
  tree.
- **Fix:** add exceptions such as `!/tests/` and `!/tests/**`, and narrow
  `test*`.

### L4. Some existing unit tests fail or are flaky

- **cert:** the 9 `create_csr` tests in `certh.rs` all write a shared
  `test.csr` in the crate root and never clean it up (`:9757, 6494`). Once
  the file exists, later tests fail with "already exists". It was deleted
  manually on 2026-10-16, but the next test run recreates it. Fixed: those
  tests were replaced by tests in temporary directories.
- **db:** the sqlite tests share the global `CONNECTION_REGISTRY` and
  `TRANSACTION_REGISTRY` and clear them (`dbh.rs:7320` and others), so they
  race under the parallel test runner.

### L5. Dead backup backend code

`src/backends/backup/*` is never referenced. The live `backup` handle is
`src/handles/automation/backuph.rs`.
