# resh - Resource Shell

**AI-Native Automation Platform for Modern Infrastructure**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-early%20development-orange.svg)]()

---

## 🚧 Early Development - Building in Public

**resh is currently in early development.** This repository is being built in public as we work toward a v0.8 feature-complete release in Q1 2026.

⭐ **Star this repo** to follow along and be notified when v0.8 alpha is ready for testing!

---

## What is resh?

resh (Resource Shell) is a next-generation automation platform designed for the AI era. While traditional tools like Ansible and Terraform were built for humans writing YAML, resh provides **structured, typed outputs** that both AI agents and human operators can reliably consume.

### The Problem

Current infrastructure automation tools face critical limitations:

- **Unstructured outputs** - Text-based responses require fragile regex parsing
- **Inconsistent errors** - AI agents can't reliably handle failures
- **YAML complexity** - Configuration files become unmaintainable at scale
- **Not composable** - Different tools for different tasks, extensive glue code

### The resh Solution

Three core principles:

**1. Structured Outputs, Always**
```bash
$ resh svc://nginx status --format json
{
  "name": "nginx",
  "status": "active",
  "uptime_seconds": 86400,
  "pid": 1234,
  "memory_mb": 45.2
}
```

**2. URI-Based Resources**
```bash
# Local operations
resh file:///etc/nginx/nginx.conf read
resh svc://postgresql restart

# Remote operations via SSH
resh ssh://prod-server/svc://nginx status
resh ssh://prod-server/file:///var/log/app.log tail --lines 100
```

**3. Comprehensive Operations**
27 handles covering: files, processes, services, databases, secrets, certificates, networking, and more.

---

## Vision

```bash
# Service management
resh svc://nginx status --format json
resh ssh://prod-01/svc://nginx restart

# Database operations
resh db://postgres/users query "SELECT * FROM users LIMIT 5" --format table

# Certificate management
resh cert:///etc/nginx/ssl/cert.pem info
resh cert:///etc/nginx/ssl/cert.pem renew

# File operations
resh file:///config.json read --format json
resh ssh://server/file:///backup.tar.gz extract

# System information
resh system://cpu info --format table
resh system://disk usage --format json
```

**Every operation returns predictable, structured data. Every time.**

---

## Planned Features (v0.8 - Q1 2026)

### Filesystem & Storage
- `file://` - File operations (read, write, copy, move, delete)
- `fs://` - Filesystem management (mount, quota, snapshot)
- `snapshot://` - Snapshot and versioning
- `archive://` - Archive management (tar, zip, 7z)

### Process & Service Management
- `proc://` - Process control (signal, nice, limits)
- `svc://` - Service management (systemd + OpenRC)
- `cron://` - Job scheduler (systemd timers + cron)

### Network & Remote Operations
- `ssh://` - Remote execution and file transfer
- `http://` - HTTP client operations
- `net://` - Network diagnostics
- `dns://` - DNS operations
- `mail://` - Email/SMTP

### Security & Secrets
- `secret://` - Secret management (Vault integration)
- `cert://` - Certificate management (X.509, TLS)
- `firewall://` - Firewall management (iptables, nftables, ufw)
- `user://` - User management

### Data & State
- `db://` - Database operations (PostgreSQL, MySQL, SQLite)
- `cache://` - Cache operations (Redis, Memcached)
- `config://` - Configuration store
- `mq://` - Message queue operations
- `log://` - Logging
- `event://` - Event pipeline

### System & Software
- `system://` - System information (CPU, memory, disk)
- `pkg://` - Package manager (apt, yum, dnf, pacman)
- `git://` - Git operations

### Automation Utilities
- `template://` - Template rendering
- `plugin://` - Plugin management
- `backup://` - Backup operations

**Total: 27 production-ready handles**

---

## Why resh?

### For DevOps Teams
- Faster, more reliable automation
- Single tool replaces Ansible + Terraform + scripts
- Predictable outputs eliminate debugging nightmares

### For SRE Teams
- Better observability with structured data
- Reliable fleet operations via SSH
- Self-healing infrastructure capabilities

### For AI/ML Engineers
- AI-native design from the ground up
- Type-safe operations for autonomous agents
- Foundation for self-managing infrastructure

---

## Development Timeline

| Milestone | Target | Status |
|-----------|--------|--------|
| v0.8 Feature Complete | Q1 2026 | 🚧 In Progress |
| v0.9 Beta Release | Q2 2026 | ⏱️ Planned |
| v1.0 Production | Q3 2026 | ⏱️ Planned |

See [ROADMAP.md](ROADMAP.md) for detailed timeline.

---

## Current Status

**What's working:**
- 🚧 Core architecture design
- 🚧 URI parser prototype
- 🚧 Initial handle implementations

**What's next:**
- Complete all 27 core handles
- Implement output formatters (JSON, table, log)
- Build comprehensive test suite
- Write documentation

**Following development:**
- Watch this repo for updates
- Check back in Q1 2026 for v0.8 alpha
- Join discussions when available

---

## Building from Source

**Note:** resh is in early development. The build may be incomplete or broken.

```bash
git clone https://github.com/yourusername/resh.git
cd resh
cargo build --release
./target/release/resh --version
```

---

## Contributing

resh is in early development. We're not accepting pull requests yet, but we welcome:

- ⭐ Stars to show interest
- 👀 Watching the repo for updates
- 💡 Ideas and feedback via Discussions (when available)

Formal contribution guidelines will be published with v0.8 alpha.

---

## Philosophy

**Structured Over Unstructured**  
Every operation returns typed, predictable data. No parsing. No surprises.

**Simple Over Complex**  
URI-based addressing works like the web. If you understand URLs, you understand resh.

**Composable Over Monolithic**  
Build complex workflows from simple, reliable primitives.

**AI-Native Over AI-Compatible**  
Designed for autonomous agents from the ground up, not bolted on later.

**Fast Over Slow**  
Single binary, zero dependencies, native performance.

---

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

---

## About

**Created by:** Scott Miller  
**Company:** Miller Technology Group LLC  
**Experience:** 30+ years in software engineering and infrastructure automation

Built with frustration from years of fragile automation tools and excitement about AI-native infrastructure.

**Why I'm building this:** After three decades of writing deployment scripts, Ansible playbooks, and custom automation, I've learned that our tools weren't designed for the world we're entering—where AI agents become infrastructure operators. resh is automation rebuilt for that future.

---

## Stay Updated

- **GitHub:** Star and watch this repository
- **LinkedIn:** [Your LinkedIn Profile] for development updates
- **Twitter:** [@YourHandle] for daily progress

---

## FAQ

**Q: When can I use resh?**  
A: v0.8 alpha will be available in Q1 2026. Production release (v1.0) is planned for Q3 2026.

**Q: Can I contribute?**  
A: Not yet. We'll open contributions with v0.8 alpha. For now, starring the repo helps us gauge interest.

**Q: What about Windows/macOS?**  
A: Initial focus is Linux. Other platforms may come post-v1.0.

**Q: How is this different from Ansible?**  
A: Ansible uses YAML playbooks with unstructured output. resh uses URIs with structured output. Ansible is for configuration management. resh is for real-time AI-native automation.

**Q: Is this production-ready?**  
A: No. resh is in early development. Check back in Q1 2026 for v0.8 alpha.

---

**Building in public. Follow along!** 🚀
