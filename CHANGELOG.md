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