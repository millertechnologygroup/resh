# Changelog

All notable changes to resh will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned for v1.1 (March 2026)
- webhook:// handle - Webhook receiver for event-driven automation
- lock:// handle - Distributed locking mechanisms (Redis, etcd, Consul)
- Enhanced integration test suite (85%+ coverage)
- Performance optimization and benchmarking
- Shell completion scripts (bash, zsh, fish)
- Improved error messages with actionable suggestions

### Planned for v1.0 Stable (Q2 2026)
- API stability guarantee (semver compliance)
- Complete test coverage (95%+)
- Binary releases for major distributions
- Production hardening and security audit
- Comprehensive documentation polish
- Community infrastructure (Discord, Discussions)

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
  output for all 28 handles and 239 verbs
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