# resh - Resource Shell

**AI-native automation platform with structured outputs**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-in%20development-orange.svg)]()
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)]()
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)]()

---

## 📢 Project Status

**Currently in Active Development**

resh is being built towards a v0.8 feature-complete release in Q1 2026. All 27 core handles are being implemented, with production release (v1.0) targeted for Q3 2026.

**Next Milestone:** v0.8 Feature Complete (Q1 2026)  
**Production Release:** v1.0 (Q3 2026)

⭐ **Star this repository** to follow development progress and be notified of the v0.8 alpha release!

---

## Overview

resh (Resource Shell) is a next-generation automation platform designed from the ground up for the AI era. While traditional tools like Ansible and Terraform were built for humans writing YAML, resh provides **structured, typed outputs** that both AI agents and human operators can reliably consume.

### The Problem We're Solving

Traditional infrastructure automation tools face critical limitations in the AI era:

**Unstructured Outputs**
- Text-based responses require fragile regex parsing
- Output formats change between versions, breaking automation
- Error messages are inconsistent and unparseable
- AI agents spend more time parsing than operating

**Configuration Complexity**
- YAML configuration files become unmaintainable at scale
- Idempotency logic is complex and error-prone
- Debugging failures requires deep tool-specific knowledge
- Learning curves prevent rapid adoption

**Limited Composability**
- Operations don't chain cleanly
- Different tools for different tasks (Ansible + Terraform + custom scripts)
- No standard interface across infrastructure resources
- Building complex workflows requires extensive glue code

**Not AI-Ready**
- Current tools weren't designed for autonomous AI agents
- Unreliable outputs make AI automation brittle
- No type safety or schema validation
- AI agents can't reason about operations reliably
  
## Roadmap

### v0.8 - Feature Complete (Q1 2026)
**Target: January-March 2026**

All 27 core handles implemented and functional:

**Filesystem & Storage (4 handles):**
- [x] file:// - File operations (read, write, copy, move, delete, etc.)
- [x] fs:// - Filesystem management (mount, quota, snapshot)
- [x] snapshot:// - Snapshot and versioning
- [x] archive:// - Archive management (tar, zip, 7z, gzip, xz, zstd)

**Process & Service Management (3 handles):**
- [x] proc:// - Process control (signal, nice, limits)
- [x] svc:// - Service management (systemd + OpenRC)
- [x] cron:// - Job scheduler (systemd timers + cron)

**Network & Remote Operations (5 handles):**
- [x] net:// - Network diagnostics (ping, scan, dns)
- [x] http:// - HTTP client (get, post, put, delete, etc.)
- [x] ssh:// - Remote execution and file transfer ⭐
- [x] dns:// - DNS operations (lookup, resolve, zone management)
- [x] mail:// - Email/SMTP (send, templates, attachments)

**Security & Secrets (4 handles):**
- [x] secret:// - Secret management (env, keystore, Vault)
- [x] cert:// - Certificate management (X.509, TLS, Let's Encrypt)
- [x] firewall:// - Firewall management (iptables, nftables, ufw, firewalld)
- [x] user:// - User management (add, del, passwd, groups)

**Data & State Management (6 handles):**
- [x] db:// - Database operations (PostgreSQL, MySQL, SQLite)
- [x] cache:// - Cache operations (Redis, Memcached)
- [x] config:// - Configuration store
- [x] mq:// - Message queue operations
- [x] log:// - Logging and log management
- [x] event:// - Event pipeline

**Packages & Software (2 handles):**
- [x] pkg:// - Package manager (apt, yum, dnf, pacman, apk)
- [x] git:// - Git operations (clone, pull, commit, push)

**System Information (1 handle):**
- [x] system:// - System information (CPU, memory, disk, uptime)

**Automation Utilities (3 handles):**
- [x] template:// - Template rendering (Tera engine) ⭐
- [x] plugin:// - Plugin management and ecosystem ⭐
- [x] backup:// - Backup operations (restic backend)

**Status at v0.8:**
- ✅ All 27 handles functional
- ✅ Basic CLI and URI parser complete
- ✅ JSON, table, and log output formats working
- ⚠️ Documentation incomplete
- ⚠️ Testing coverage partial
- ⚠️ Known bugs and edge cases

---

### v0.9 - Beta Release (Q2 2026)
**Target: April-June 2026**

**Focus: Polish, Testing & Documentation**

- [ ] Comprehensive documentation for all 27 handles
- [ ] Complete API reference with examples
- [ ] Integration test suite (80%+ coverage)
- [ ] Performance benchmarks and optimization
- [ ] Error message improvements
- [ ] Shell completion scripts (bash, zsh, fish)
- [ ] Bug fixes from community feedback
- [ ] Security audit of handle implementations
- [ ] Cross-platform testing (Ubuntu, Debian, RHEL, Arch)
- [ ] Binary releases for major Linux distributions
- [ ] Migration guides (from Ansible, Terraform, scripts)
- [ ] Video tutorials and demos

**Community Engagement:**
- [ ] Public beta testing program
- [ ] GitHub issue triage and response
- [ ] Community feedback integration
- [ ] Early adopter case studies

**Deliverables:**
- Beta releases every 2 weeks
- Comprehensive documentation site
- Installation packages (.deb, .rpm, binary)
- Tutorial videos and blog posts

---

### v1.0 - Production Release (Q3 2026)
**Target: July-September 2026**

**Focus: Production-Ready, Stable API**

- [ ] API stability guarantee (semver compliance)
- [ ] Production-grade error handling
- [ ] Complete test coverage (90%+)
- [ ] Performance optimization complete
- [ ] Security hardening and audit complete
- [ ] Documentation complete and reviewed
- [ ] Man pages for all handles
- [ ] Professional website and branding
- [ ] Release announcement and PR campaign
- [ ] Conference talks submitted (DevOpsDays, KubeCon)
- [ ] Enterprise evaluation program

**Success Criteria:**
- All handles production-tested
- Zero critical bugs
- <100ms latency for local operations
- Comprehensive security review passed
- 1000+ GitHub stars
- 50+ contributors
- Active community (Discord/Discussions)

**Marketing Push:**
- Hacker News launch
- Product Hunt launch
- LinkedIn thought leadership campaign
- Conference presentations
- Technical blog post series
- Comparison guides vs. Ansible/Terraform

---

### v1.1 - Enhanced Operations (Q4 2026)
**Target: October-December 2026**

**New Features:**
- [ ] webhook:// - Webhook receiver for event-driven automation
- [ ] lock:// - Distributed locking (Redis, etcd, Consul)
- [ ] Interactive shell mode (REPL)
- [ ] Pipeline/chaining operations within resh
- [ ] Improved SSH performance (connection pooling, multiplexing)
- [ ] Advanced template features (includes, inheritance)
- [ ] Plugin marketplace/registry
- [ ] Enhanced error recovery and retry logic
- [ ] Batch operations across multiple resources
- [ ] Real-time streaming operations

**Quality of Life:**
- [ ] Better tab completion
- [ ] Improved help system
- [ ] Interactive configuration wizard
- [ ] Built-in update mechanism
- [ ] Telemetry (opt-in) for usage patterns

---

### v1.2 - Enterprise Features (Q1 2027)
**Target: January-March 2027**

**Enterprise Edition (Source Available or Proprietary):**
- [ ] RBAC (Role-Based Access Control)
- [ ] Audit logging and compliance
- [ ] LDAP/SAML integration
- [ ] Multi-tenancy support
- [ ] Advanced monitoring and alerting
- [ ] Policy-as-code enforcement
- [ ] Compliance reporting (SOC2, HIPAA, PCI-DSS)
- [ ] Enterprise support contracts

**Platform Features:**
- [ ] Web UI for monitoring and control
- [ ] REST API server mode
- [ ] Centralized configuration management
- [ ] Fleet management dashboard
- [ ] Scheduled operations UI
- [ ] Historical analytics and reporting

---

### v2.0 - Advanced Automation (Q2-Q3 2027)
**Target: April-September 2027**

**AI-Native Enhancements:**
- [ ] Natural language operation parsing
- [ ] AI-suggested remediation actions
- [ ] Anomaly detection and alerting
- [ ] Predictive maintenance operations
- [ ] Auto-scaling based on patterns
- [ ] Self-optimization of operations

**Infrastructure:**
- [ ] Cloud provider handles (aws://, gcp://, azure://)
- [ ] Kubernetes integration (k8s://)
- [ ] Container operations (docker://, podman://)
- [ ] CI/CD pipeline integration
- [ ] Infrastructure-as-code state management
- [ ] Drift detection and remediation

**Advanced Features:**
- [ ] Distributed execution engine
- [ ] State management system
- [ ] Workflow orchestration
- [ ] Visual workflow designer
- [ ] Plugin SDK and API improvements
- [ ] Multi-language plugin support

---

### Long-Term Vision (2027+)

**Ecosystem Growth:**
- Community-contributed handles
- Third-party plugin marketplace
- Managed resh hosting (SaaS)
- Enterprise training and certification program
- Partner integrations (monitoring tools, ticketing systems)
- Established as industry standard for AI-native automation

**Platform Evolution:**
- resh-as-a-service (managed platform)
- Global handle registry
- Collaborative automation workflows
- Real-time collaboration features
- Mobile monitoring apps
- Integration with major platforms (Slack, Teams, PagerDuty)

---

## Release Philosophy

**Quality Over Speed:**
- Each release is production-tested
- Breaking changes only in major versions
- Comprehensive migration guides
- Backwards compatibility within major versions

**Community-Driven:**
- Public roadmap with community input
- Feature voting and prioritization
- Regular community calls
- Transparent development process

**Enterprise-Ready:**
- Stable APIs
- Long-term support (LTS) releases
- Security patches and updates
- Professional support available

---

## Version Strategy

- **v0.8-0.9:** Alpha/Beta (feature complete → stable)
- **v1.x:** Production-ready, community edition
- **v2.x:** Advanced features, enterprise capabilities
- **LTS releases:** Every major version gets 2 years of support
