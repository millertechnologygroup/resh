# Changelog

All notable changes to resh will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Release-candidate stabilization (not yet versioned)

Security, correctness and documentation fixes on top of 1.0.2-beta. Details
and evidence: `docs/reviews/`.

#### Security
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

#### Fixed
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

#### Changed (compatibility)
- A zip `password=` is refused (encrypted creation is not supported).
- git `timeout_ms` is refused (git steps cannot be interrupted).
- `http://` plugin registries and plugin artifacts containing links are
  refused.
- The documentation under `docs/` was rewritten against the code; every
  `resh` example is checked by `tests/doc_examples.rs`.

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

## [1.0.2-beta] - 2026-10-16

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