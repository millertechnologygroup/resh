# resh Roadmap

**AI-Native Automation Platform - Development Timeline**

This roadmap covers the open-source resh command-line tool in this repository. Completed releases are listed with their dates. Everything after the current release is a plan: items marked *planned* are intended for the named milestone, items marked *proposed* are candidates that have not been approved for implementation, and no future release has a date until it is published.

---

## Current Status (November 2026)

**Current release: [v1.0.6-beta](https://github.com/millertechnologygroup/resh/releases/tag/v1.0.6-beta)**, a security maintenance release, published as a GitHub pre-release on November 5, 2026.

- 28 handles with 229 verbs, each with built-in help (`resh <handle> --help`)
- Linux x86_64 only; the prebuilt binary needs glibc 2.39 or later (see the [README](README.md#installation))
- Beta quality: known limitations are listed in [docs/known_issues.md](docs/known_issues.md)

**Next milestone: v1.0.7-beta**, a CLI maintenance release (see [below](#next-v107-beta-cli-maintenance)). It has no release date.

---

## Release History

| Release | Date | Summary |
| ------- | ---- | ------- |
| v0.1.0 | September 2025 | First development version |
| v0.7.0 | November 2025 | 25 handles |
| v0.9.x | December 2025 | Automation utilities (backup, plugin, template) |
| v1.0.0-beta | January 2026 | 28 handles, including the backup, plugin and template utilities |
| v1.0.1-beta | February 2026 | Beta maintenance |
| v1.0.2-beta | October 2026 | Tagged, not published as a release: built-in help for every handle and verb, fixes |
| v1.0.3-beta | October 2026 | Security and correctness fixes from the release gate |
| v1.0.4-beta | October 2026 | Security release |
| v1.0.5-beta | October 2026 | Security release |
| v1.0.6-beta | November 2026 | Security release: `firewall://` input validation and rule matching, containment of external tools at their deadline |

Details are in [CHANGELOG.md](CHANGELOG.md).

---

## v1.0 Beta - Core Handles ✅ Released

**v1.0.0-beta released January 2026.** 28 handles, documented by category under [docs/](docs/). Each handle's page lists its verbs and its known limitations.

### Filesystem & Storage (4 handles)
- [x] `file://` - File operations (read, write, copy, move, delete, etc.)
- [x] `fs://` - Mounted filesystems (list mounts, usage, quota, mount, unmount, resize, check)
- [x] `snapshot://` - Full local copies of a file or directory
- [x] `archive://` - Archives (create tar, tar.gz, zip, gzip; read tar.xz and tar.zst; no 7z)

### Process & Service Management (3 handles)
- [x] `proc://` - Process control (signal, nice, limits)
- [x] `svc://` - Service management (systemd + OpenRC)
- [x] `cron://` - Job scheduler (systemd timers + cron)

### Network & Remote Operations (5 handles)
- [x] `net://` - Network diagnostics (ping, scan, dns)
- [x] `http://` - HTTP client (get, post, put, delete, etc.)
- [x] `ssh://` - Remote execution and file transfer
- [x] `dns://` - DNS operations (lookup, resolve, trace, zone transfer)
- [x] `mail://` - Email/SMTP (send, templates, attachments)

### Security & Secrets (4 handles)
- [x] `secret://` - Secrets (environment lookup, local keystore; Vault not implemented)
- [x] `cert://` - X.509 certificates, keys and CSRs in local files (no ACME)
- [x] `firewall://` - Firewall management (iptables, nftables, ufw, firewalld)
- [x] `user://` - User management (add, del, passwd, groups)

### Data & State Management (6 handles)
- [x] `db://` - Database operations (PostgreSQL, MySQL, SQLite)
- [x] `cache://` - Cache operations (Redis, Memcached)
- [x] `config://` - Configuration store
- [x] `mq://` - Local message queue
- [x] `log://` - Log files and service journals
- [x] `event://` - Local event topics

### Packages & Software (2 handles)
- [x] `pkg://` - Package manager (apt, yum, dnf, pacman, apk)
- [x] `git://` - Git operations (clone, pull, commit, push)

### System Information (1 handle)
- [x] `system://` - System information (CPU, memory, disk, uptime)

### Automation Utilities (3 handles)
- [x] `backup://` - Backup lifecycle (create, list, restore, verify, prune) through restic, borg, rsync or tar
- [x] `plugin://` - Plugin lifecycle (install, update, remove, search, enable, disable) with registry checksum verification
- [x] `template://` - Tera template rendering, validation and testing

### Done since v1.0.0-beta
- [x] Built-in help for all 28 handles and 229 verbs (v1.0.2-beta)
- [x] Four security releases (v1.0.3-beta to v1.0.6-beta); see [CHANGELOG.md](CHANGELOG.md)
- [x] CI with build and test on the minimum supported Rust version (1.88) and a current stable toolchain, formatting, and `cargo audit`
- [x] Release archives with a published SHA-256 checksum

---

## Next: v1.0.7-beta (CLI Maintenance)

**Status: planned. No release date.**

v1.0.7-beta is the next CLI maintenance milestone. The areas below are its candidate priorities, in order. They are not all approved for implementation; each change is scoped and approved before work on it starts, and an item may move to a later release.

1. **Parser and input-validation hardening** - extend the strict validation that v1.0.6-beta added to `firewall://` to the remaining handle arguments.
2. **Service start/restart outcome** - `svc://<unit>.start` and `.restart` currently report that the service manager accepted the job, not that the unit became active (see [known_issues.md](docs/known_issues.md)).
3. **Deferred fixes** - security and functional regression fixes that were kept out of the narrowly scoped v1.0.6-beta release.
4. **Dependency and advisory maintenance** - refresh dependencies and reduce the advisory exceptions recorded in `.cargo/audit.toml`.
5. **Clippy correctness findings** - resolve the correctness lints reported for existing code; clippy is advisory in CI today.
6. **Linux binary compatibility** - decide how to support systems with glibc older than 2.39 (for example, building against an older glibc or a static build).
7. **Release engineering and distribution** - an install script that installs the current release and verifies its checksum, signed release assets, and repeatable release packaging.

---

## Later Milestones (Proposed)

These milestones are proposals carried over from earlier plans. They have no dates, and their scope may change.

### v1.1 - Feature Complete
- [ ] `webhook://` - Webhook receiver for event-driven automation
- [ ] `lock://` - Distributed locking (Redis, etcd, Consul)
- [ ] Integration test suite expansion
- [ ] Performance benchmarks and optimization
- [ ] Error messages with actionable suggestions
- [ ] Shell completion scripts (bash, zsh, fish)

**Goal:** all 30 planned handles.

### v1.0 Stable - Production Release
- [ ] API stability guarantee (semver compliance)
- [ ] Production-grade error handling and broader test coverage
- [ ] Security review of all handles
- [ ] Testing across major Linux distributions
- [ ] Distribution packages (.deb, .rpm, AUR) and container images
- [ ] Man pages and a plugin development guide
- [ ] Contribution guidelines finalized and pull requests opened (see [CONTRIBUTING.md](CONTRIBUTING.md))

### v1.2 - Enhanced Operations
- [ ] Interactive shell mode (REPL)
- [ ] Pipelines and chaining within resh
- [ ] SSH connection reuse
- [ ] Advanced template features (includes, inheritance, macros)
- [ ] Batch and parallel operations across multiple resources
- [ ] Plugin developer toolkit and community plugin registry

### Longer-term ideas
- Cloud and container handles (for example `k8s://`, `docker://`, cloud providers)
- AI-assisted operations: natural-language parsing, suggested remediation, anomaly detection
- Drift detection and workflow orchestration
- Plugins in other languages

Commercial and enterprise offerings are planned separately and are not part of this roadmap.

---

## Release Principles

These are goals for how resh is released; the support commitments that apply today are in [SECURITY.md](SECURITY.md).

- **Correctness first.** A verb should report success only when the operation succeeded, and limitations are documented on each handle's page.
- **Security releases stay narrow.** A security release changes only what the fix needs, so it can be reviewed and adopted quickly.
- **Breaking changes are documented.** Before v1.0 stable, a beta release may change behavior; any change is described in [CHANGELOG.md](CHANGELOG.md).
- **Stable APIs from v1.0 stable.** Semver compatibility applies from the first stable release.

---

## How to Influence the Roadmap

- **Issues:** Report bugs and request features in [GitHub Issues](https://github.com/millertechnologygroup/resh/issues)
- **Discussions:** Propose ideas in [GitHub Discussions](https://github.com/millertechnologygroup/resh/discussions)
- **Testing:** Run the current beta in your environment and report what breaks
- **Security:** Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in public issues

---

## Commitment to Open Source

The resh CLI is open source under the Apache License 2.0, and its core features stay free and open.

---

**Last Updated:** November 2026 (after v1.0.6-beta)\
**Next Review:** at the v1.0.7-beta release
