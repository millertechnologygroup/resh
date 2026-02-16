# resh - Resource Shell

**AI-Native Automation Platform for Modern Infrastructure**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-v1.0.0--beta-blue.svg)](https://github.com/millertechnologygroup/resh/releases)
[![Status](https://img.shields.io/badge/status-beta-blue.svg)]()

---

## 🎉 v1.0 Beta Released - 28 Production-Ready Handles

**resh v1.0-beta is ready for testing!** This release includes 28 production-ready handles plus comprehensive automation utilities for backup management, plugin operations, and template rendering.

⭐ **Star this repo** to follow development and be notified of updates!

**Current Status:**
- ✅ 28 handles implemented and functional
- ✅ JSON, table, and log output formats working
- ✅ URI-based resource model operational
- ⏱️ 2 additional handles coming in v1.1 (March 2026)
- ⚠️ Beta quality - expect bugs and rough edges

---

## What is resh?

resh (Resource Shell) is a next-generation automation platform designed for the AI era. While traditional tools like Ansible and Terraform were built for humans writing YAML, resh provides **structured, typed outputs** that both AI agents and human operators can reliably consume.

**v1.0 Beta demonstrates the enhanced automation vision with 28 working handles plus comprehensive automation utilities.**

### The Problem

Current infrastructure automation tools face critical limitations:

- **Unstructured outputs** - Text-based responses require fragile regex parsing
- **Inconsistent errors** - AI agents can't reliably handle failures  
- **YAML complexity** - Configuration files become unmaintainable at scale
- **Not composable** - Different tools for different tasks, extensive glue code

**When AI agents try to use traditional tools, error rates spike 10-15x higher than human-operated workflows.**

### The Difference

**Traditional approach (brittle, AI-unfriendly):**
```bash
# Check if service is running (fragile parsing)
systemctl status nginx | grep "active (running)" && echo "UP" || echo "DOWN"

# Get disk usage (inconsistent output)
df -h / | tail -1 | awk '{print $5}' | sed 's/%//'

# Read database (tool-specific syntax)
mysql -u root -p -e "SELECT COUNT(*) FROM users;" mydb
```

**resh approach (structured, AI-ready):**
```bash
# Check service status (structured JSON)
resh svc://nginx.status --json
# {"status": "active", "uptime_seconds": 86400, "pid": 1234}

# Get disk usage (consistent format)
resh system://.disk --json
# {"root": {"used_percent": 45, "available_gb": 120}}

# Read database (unified syntax)
resh db://mydb.query --sql "SELECT COUNT(*) FROM users" --json
# {"rows": [{"count": 1523}], "affected": 0}
```

**Why this matters for AI agents:**
- No regex parsing needed
- Predictable error handling
- Same patterns across all operations
- Type-safe outputs

**3. Comprehensive Operations**
28 handles operational in v1.0-beta, including automation utilities (backup, plugin, template) plus files, processes, services, databases, secrets, certificates, networking, and more.

---

## Why Test v1.0 Beta?

### For DevOps Engineers
- Test AI-native automation in your environment
- Compare structured outputs vs traditional tools
- Provide feedback on handle design
- Influence v1.1 feature priorities

### For SRE Teams
- Evaluate for fleet management use cases
- Test reliability at scale
- Assess SSH remote execution performance
- Validate database operation workflows

### For AI/ML Engineers
- Build AI agents using structured outputs
- Test autonomous infrastructure operations
- Develop self-healing systems
- Pioneer AI-native automation patterns

### For Early Adopters
- Shape the future of infrastructure automation
- Join a community building something new
- Get recognition as an early contributor
- Influence roadmap and priorities

### What to Expect
- ✅ Functional 28 handles you can use today
- ⚠️ Bugs and rough edges (it's beta!)
- ⚠️ API may change before v1.0 stable
- ✅ Responsive maintainer (issues answered within 24h)
- ✅ Rapid iteration and improvements
- ✅ Your feedback directly shapes development

---

## New in v1.0: Automation Utilities

### Data Protection & Backup Management
- ✅ `backup://` - Complete backup lifecycle management
  - Create backups with multiple backend support (restic, borg, rsync, tar)
  - List, restore, and verify backup integrity
  - Automated retention policies and scheduled backups

### Plugin & Extension Management  
- ✅ `plugin://` - Full plugin lifecycle operations
  - Install from registry, URL, or local files
  - Search, update, and remove plugins
  - Security verification and dependency management

### Template & Content Generation
- ✅ `template://` - Powerful template rendering system
  - Tera template engine with data injection
  - Template validation and testing
  - Multiple output formats (file, stdout, structured)

**Why These Matter for AI Agents:**
- **Predictable Operations:** Every automation returns structured JSON envelopes
- **Complete Lifecycle:** From installation through execution to cleanup
- **Error Handling:** Detailed status reporting for autonomous decision-making
- **Security First:** Built-in verification and safe defaults

```bash
# Example: Complete backup workflow
resh backup://daily.create --data-source /home/user --destination s3://mybucket
resh backup://daily.list --json-pretty
resh backup://daily.verify --backup-id latest

# Example: Plugin management
resh plugin://security-scanner.install --source registry
resh plugin://security-scanner.enable
resh plugin://security-scanner.update

# Example: Template rendering
resh template://config.yml.render --data-file vars.json --output /etc/myapp/
```

---

## Implemented in v1.0 Beta (28 Handles)

### Automation Utilities
- ✅ `template://` - Template operations (render, validate, test)
- ✅ `backup://` - Backup operations (create, list, restore, verify, prune, size, schedule)
- ✅ `plugin://` - Full plugin lifecycle operations (install, update, remove, enable, disable, available.list, available.search, available.info)

### Filesystem & Storage ✅
- ✅ `file://` - File operations (read, write, copy, move, delete, chmod, hash)
- ✅ `fs://` - Filesystem management (mount, quota, usage, resize)
- ✅ `snapshot://` - Snapshot and versioning (create, restore, diff, list)
- ✅ `archive://` - Archive management (tar, zip, 7z, gzip, xz, zstd)

### Process & Service Management ✅
- ✅ `proc://` - Process control (signal, nice, setPriority, limits)
- ✅ `svc://` - Service management (systemd + OpenRC support)
- ✅ `cron://` - Job scheduler (systemd timers + cron)

### Network & Remote Operations ✅
- ✅ `ssh://` - Remote execution and file transfer
- ✅ `http://` - HTTP client operations (get, post, put, delete, patch)
- ✅ `net://` - Network diagnostics (ping, tcp_check, scan, dns)
- ✅ `dns://` - DNS operations (lookup, resolve, zone management)
- ✅ `mail://` - Email/SMTP (send, templates, attachments)

### Security & Secrets ✅
- ✅ `secret://` - Secret management (env, keystore, Vault integration)
- ✅ `cert://` - Certificate management (X.509, TLS, Let's Encrypt)
- ✅ `firewall://` - Firewall management (iptables, nftables, ufw, firewalld)
- ✅ `user://` - User management (add, del, passwd, groups, exists)

### Data & State Management ✅
- ✅ `db://` - Database operations (PostgreSQL, MySQL, SQLite)
- ✅ `cache://` - Cache operations (Redis, Memcached)
- ✅ `config://` - Configuration store (get, set, watch, remove)
- ✅ `mq://` - Message queue operations (create, put, get, purge)
- ✅ `log://` - Logging and log management
- ✅ `event://` - Event pipeline (publish, subscribe, filter)

### System & Software ✅
- ✅ `system://` - System information (CPU, memory, disk, network, uptime)
- ✅ `pkg://` - Package manager (apt, yum, dnf, pacman, apk)
- ✅ `git://` - Git operations (clone, pull, commit, push, status)

**Total: 28 handles production-ready** (25 core + 3 automation utilities)

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
| v0.7 Alpha (25 handles) | November 2025 | ✅ **Completed** |
| v0.8 Alpha (27 handles) | December 2025 | ✅ **Completed** |
| v1.0 Beta (28 handles) | January 2026 | ✅ **Released** |
| v1.1 (30 handles) | March 2026 | ⏱️ In Progress |
| v1.0 Stable | Q2 2026 | ⏱️ Planned |

See [ROADMAP.md](ROADMAP.md) for detailed timeline.

---

## Current Status

**What's working in v1.0-beta:**
- ✅ 28 handles implemented and functional
- ✅ Complete automation utilities (backup, plugin, template)
- ✅ URI parser and resource dispatcher
- ✅ JSON, table, and log output formatters
- ✅ Basic CLI with argument parsing
- ✅ SSH remote execution
- ✅ Database operations (PostgreSQL, MySQL, SQLite)
- ✅ Service management (systemd + OpenRC)
- ✅ Template rendering with Tera engine
- ✅ Full plugin system with registry support
- ✅ Comprehensive backup lifecycle management
- ✅ Complete documentation for all handles
- ✅ Organized documentation structure by category

**What's next:**
- ⏱️ webhook:// and lock:// handles (v1.1 - March 2026)
- ⏱️ Enhanced integration test suite (v1.1)
- ⏱️ Performance optimization (v1.1)
- ⏱️ Binary releases for major distributions (v1.0 stable)
- ⏱️ Production hardening and polish (v1.0 stable)

**Beta limitations:**
- ✅ Documentation complete for all 28 handles
- ⚠️ Test coverage ~80% (expanding to 95%+ in v1.0 stable)
- ⚠️ Performance not yet optimized
- ⚠️ Error messages need improvement
- ⚠️ Some edge cases not fully handled

**Try it out:**
- Download and build from source
- Report bugs and feedback via GitHub Issues
- Join early testing community

---

## Installation

### Prerequisites

- **Rust 1.70 or later** - Install from [rustup.rs](https://rustup.rs)
- **Git** - For cloning the repository
- **Linux/Unix** - Currently Linux-focused (Ubuntu, Debian, RHEL, Arch, Alpine tested)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/millertechnologygroup/resh.git
cd resh

# Checkout v1.0-beta release
git checkout v1.0.1-beta

# Build in release mode
cargo build --release

# Binary will be at: ./target/release/resh
./target/release/resh --version
```

### Quick Installation

```bash
# Install to /usr/local/bin (requires sudo)
cargo build --release
sudo cp target/release/resh /usr/local/bin/
sudo chmod +x /usr/local/bin/resh

# Verify installation
resh --version
```

### Development Build

```bash
# Build for development (faster compile, slower runtime)
cargo build

# Run directly
cargo run -- svc://nginx status --format json

# Run tests
cargo test
```

### Using the Installation Script

```bash
# Quick install (downloads and builds latest release)
curl -fsSL https://get.reshshell.dev | sh
```

### Binary Releases

**Coming in v1.0 stable** - Pre-built binaries for:
- Ubuntu/Debian (.deb)
- RHEL/Fedora/CentOS (.rpm)
- Arch Linux (AUR)
- Generic Linux (tar.gz)
- macOS (Homebrew - post v1.0)

---

## Contributing

**resh v1.0 beta is now available for testing!** We welcome:

### How You Can Help Now

**1. 🐛 Test and Report Bugs**
- Try resh in your environment
- Report issues via [GitHub Issues](https://github.com/millertechnologygroup/resh/issues)
- Include: OS, resh version, command run, expected vs actual output

**2. 💡 Provide Feedback**
- Which handles do you use most?
- What features are missing?
- What documentation would help?
- Share your use cases

**3. ⭐ Star and Watch**
- Star the repository to show support
- Watch for updates and new releases
- Share with your network

**4. 📝 Documentation**
- Report unclear documentation
- Suggest examples
- Request tutorials for specific use cases

**5. 🧪 Early Testing**
- Test in your infrastructure
- Try different Linux distributions
- Test edge cases
- Share your automation workflows

### Code Contributions

**Not accepting pull requests yet** - We'll open contributions with v1.0 stable (Q2 2026).

Formal contribution guidelines coming with v1.0 stable.

### Community

- **GitHub Issues:** Bug reports and feature requests
- **GitHub Discussions:** Questions and ideas (coming soon)
- **Discord:** Real-time community (coming with v1.1)

See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

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
- **LinkedIn:** [Scott Miller](https://www.linkedin.com/in/cscottmiller/) for development updates

---

## FAQ

**Q: Can I use resh now?**  
A: Yes! v1.0-beta is available for testing. All 28 handles are functional and stable enough for experimentation and feedback.

**Q: Is v1.0-beta production-ready?**  
A: Not yet. This is a beta release with 28 stable handles. We recommend testing in non-production environments. Full production release (v1.0 stable) planned for Q2 2026.

**Q: What's missing before v1.0 stable?**  
A: 2 additional handles (webhook://, lock://), performance optimization, comprehensive testing, and production hardening. Target: Q2 2026.

**Q: Can I contribute code?**  
A: Not yet. We'll open for code contributions with v1.0 stable (Q2 2026). For now, please test, report bugs, and provide feedback.

**Q: What about Windows/macOS?**  
A: Initial focus is Linux. macOS support likely post-v1.0. Windows support is being evaluated.

**Q: How is this different from Ansible?**  
A: Ansible uses YAML playbooks with unstructured output designed for humans. resh uses URIs with structured output (JSON/table/log) designed for both humans and AI agents. Ansible is for configuration management. resh is for real-time operations and AI-native automation.

**Q: How is this different from Terraform?**  
A: Terraform is for infrastructure-as-code with state management. resh is for real-time operations and automation without state files. They solve different problems and can be complementary.

**Q: Why 28 handles instead of 30?**  
A: We focused on delivering comprehensive core functionality and automation utilities (backup, plugin, template) that provide immediate value. The remaining 2 handles (webhook://, lock://) are advanced features planned for v1.1.

**Q: Where should I report bugs?**  
A: [GitHub Issues](https://github.com/millertechnologygroup/resh/issues) - Please include your OS, resh version, command, and output.

**Q: Can I use resh in my company?**  
A: Yes, it's Apache 2.0 licensed. However, being beta, we recommend testing in non-production environments first.

**Q: What's the performance like?**  
A: Functional but not yet optimized. Performance improvements coming in v1.1. Current focus is correctness and features.

---

**v1.0 Beta available now. Test it. Break it. Help us build the future of infrastructure automation.** 🚀

[Download v1.0-beta](https://github.com/millertechnologygroup/resh/releases/tag/v1.0.1-beta) • [Report Issues](https://github.com/millertechnologygroup/resh/issues) • [Read Docs](docs/) • [View Roadmap](ROADMAP.md)