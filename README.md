# resh - Resource Shell

**AI-Native Automation Platform for Modern Infrastructure**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-v1.0.2--beta-blue.svg)](https://github.com/millertechnologygroup/resh/releases)
[![Status](https://img.shields.io/badge/status-beta-blue.svg)]()

---

## v1.0.2-beta - 28 Handles (Beta)

**resh v1.0.2-beta is available for testing.** This beta release includes 28 handles, among them automation utilities for backups, plugins and template rendering. It is beta software: some verbs are stubs or have known limitations, listed in each handle's documentation and in [docs/known_issues.md](docs/known_issues.md).

⭐ **Star this repo** to follow development and be notified of updates!

**Current Status:**
- ✅ 28 handles registered, each with built-in help (`resh <handle> --help`)
- ✅ Most verbs print JSON; some also offer a text format (see each handle's docs)
- ✅ URI-based resource model
- ⏱️ 2 additional handles planned for v1.1
- ⚠️ Beta quality - expect bugs and rough edges; see [docs/known_issues.md](docs/known_issues.md)

---

## What is resh?

resh (Resource Shell) is a command-line tool that runs operations on resources named by URLs (`svc://nginx.status`, `file:///etc/hosts.read`) and prints structured results, mostly JSON, that both scripts and AI agents can consume without text parsing.

**v1.0.2-beta has 28 handles, including the backup, plugin and template automation utilities.**

### The Problem

Current infrastructure automation tools face critical limitations:

- **Unstructured outputs** - Text-based responses require fragile regex parsing
- **Inconsistent errors** - AI agents can't reliably handle failures  
- **YAML complexity** - Configuration files become unmaintainable at scale
- **Not composable** - Different tools for different tasks, extensive glue code

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
# Check service status (structured JSON: active_state, sub_state, pid, ...)
resh --json-pretty svc://nginx.status

# Get disk usage for the root filesystem (capacity, inodes, I/O per mount)
resh --json-pretty system://.disk 'input={"mount_points":["/"]}'

# Query a database (rows plus column metadata)
resh db://sqlite/app.query 'sql=SELECT COUNT(*) AS n FROM users' dsn=sqlite:app.db
```

**Why this matters for AI agents:**
- No regex parsing needed: fields have names
- One failure contract: exit code 0 on success; on failure the handle's code (1-255) or 1, with `Error: <reason>` on stderr
- One command form across all handles: `resh <handle>://<target>.<verb> key=value ...`
- Each handle documents its real output fields (there is no single shared response envelope)

**Broad coverage**
28 handles in v1.0.2-beta: automation utilities (backup, plugin, template) plus files, processes, services, databases, secrets, certificates, networking, and more.

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
- ✅ Active development and iteration
- ✅ Your feedback directly shapes development

---

## New in v1.0: Automation Utilities

### Data Protection & Backup Management
- ✅ `backup://` - Backup lifecycle by running restic, borg, rsync or tar
  - Create, list, restore, verify and prune backups (`keep_*` retention rules)
  - `create` and `prune` support `dry_run`; `restore` has no dry run and refuses `dry_run=true`
  - `schedule` only reports a schedule definition; it installs no cron job or timer (run `create` from cron or a systemd timer yourself)
  - Encryption and deduplication are whatever the backend provides (restic and borg encrypt; tar and rsync do not)

### Plugin & Extension Management  
- ✅ `plugin://` - Plugin lifecycle in a local plugin store
  - Install from an HTTPS registry (default), a direct HTTPS URL, or a local file
  - Registry installs require a SHA-256 checksum from the registry by default (`verify=sha256`); `source=url` has no checksum and needs an explicit `verify=none`
  - Plain `http://` is always refused
  - Search catalogs, update, enable, disable and remove plugins, with `dry_run` plans

### Template & Content Generation
- ✅ `template://` - Tera template rendering
  - Render with a JSON context (`context=` or `context_file=`)
  - Validate and test templates
  - Output formats for `render`: `text`, `html`, `json`, `bytes` (printed to stdout; rendering never writes files)

**Why These Matter for AI Agents:**
- **Structured results:** each verb prints JSON (the shape is specific to each handle; see its docs)
- **Failures are never silent:** non-zero exit code plus `Error: <reason>` on stderr
- **Plans before changes:** `dry_run` where a verb supports it (not every verb does; see the handle docs)
- **Verification by default:** plugin registry installs are checksum-verified

```bash
# Example: Complete backup workflow
resh backup://daily.create src=/home/user backend=restic repo_url=/srv/restic password_file=/etc/resh/restic.pass
resh --json-pretty backup://daily.list backend=restic repo_url=/srv/restic password_file=/etc/resh/restic.pass
resh backup://daily.verify backend=restic repo_url=/srv/restic password_file=/etc/resh/restic.pass

# Example: Plugin management (registry= must be an HTTPS registry you trust;
# a registry dry run still contacts the registry to resolve the version)
resh plugin://installed.list format=names
resh plugin://aws.install registry=https://plugins.example.org version=1.2.3 dry_run=true
resh plugin://aws.install registry=https://plugins.example.org version=1.2.3
resh plugin://demo.install source=file path=/home/alice/demo.tar.gz
resh plugin://aws.enable
resh plugin://aws.update registry=https://plugins.example.org dry_run=true

# Example: Template rendering
resh template://config.yml.render context_file=vars.json
```

---

## Implemented in v1.0.2-beta (28 Handles)

Each handle's page under [docs/](docs/) lists its registered verbs, arguments, real output fields and known limitations. `resh <handle> --help` prints the same verb list.

### Automation Utilities
- ✅ `template://` - Tera templates (render, validate, test)
- ✅ `backup://` - Backups through restic, borg, rsync or tar (create, list, restore, verify, prune; `schedule` reports a definition only and installs nothing)
- ✅ `plugin://` - Plugin lifecycle (install, update, remove, enable, disable, available.list, available.search, available.info, installed.list)

### Filesystem & Storage ✅
- ✅ `file://` - File operations (read, write, copy, move, delete, chmod, hash, grep, find, extended attributes, and more)
- ✅ `fs://` - Mounted filesystems (list-mounts, usage, quota, mount, unmount, resize, check)
- ✅ `snapshot://` - Full local copies of a file or directory (create, restore, diff, ls)
- ✅ `archive://` - Archives: create tar, tar.gz, zip and single-file gzip; read tar.xz and tar.zst; no 7z support and no password-protected archives
  (see [archive.md](docs/Filesystem_Storage/archive.md))

### Process & Service Management ✅
- ✅ `proc://` - Signals and nice values for a process (signal, nice.get/set, setPriority; `limits.set` only affects the resh process itself)
- ✅ `svc://` - Service management (systemd and OpenRC)
- ✅ `cron://` - Scheduled jobs as crontab entries or systemd timers (list, add, enable, disable, rm)

### Network & Remote Operations ✅
- ✅ `ssh://` - Remote commands and file upload/download through the system `ssh` client; `tunnel`, `keys.list` and `key.add` are stubs (dry run only)
- ✅ `http://` - HTTP client (get, head, headers, options, preflight, json, post, put, patch, delete)
- ✅ `net://` - Network diagnostics (interfaces, routes, ping, tcp_check, scan, dns)
- ✅ `dns://` - DNS lookup, resolve, trace and zone transfer (`zone.fetch`); `zone.update` is simulated and sends nothing
- ✅ `mail://` - Email over SMTP (send, send_template, attachments, test, config); `send` has no dry run (use `send_template ... dry_run=true` to preview)

### Security & Secrets ✅
- ✅ `secret://` - Local keystore file (mode 0600, **not encrypted**) and read-only environment lookup; the `vault` scope and `rotate` are not implemented
- ✅ `cert://` - X.509 certificates, keys and CSRs in local files (info, verify, chain.info, generate, csr.create, sign, renew)
- ✅ `firewall://` - Firewall rules and state (iptables, nftables, ufw, firewalld)
- ✅ `user://` - User management (exists, groups, add, delete, passwd, lock, unlock)

### Data & State Management ✅
- ✅ `db://` - Database operations (PostgreSQL, MySQL/MariaDB, SQLite)
- ✅ `cache://` - Cache operations (Redis, Memcached)
- ✅ `config://` - Local JSON configuration store (get, set, ls, watch; no delete verb)
- ✅ `mq://` - Local, single-host file-based FIFO queue (create, put, get, peek, len, purge)
- ✅ `log://` - Tail log files or a systemd service journal
- ✅ `event://` - Local event topics (emit, subscribe, list-topics, hooks)

### System & Software ✅
- ✅ `system://` - System information (info, uptime, load, memory, cpu, disk, env.list)
- ✅ `pkg://` - Package manager (apt, dnf, yum, pacman, apk, brew): install, remove, update, upgrade, search, info, snapshot; `restore` is best effort and does not pin locked versions; `security_only` works only for dnf/yum `update` and dnf `upgrade` and is refused elsewhere
- ✅ `git://` - Git through libgit2 (clone, pull, push, commit, status, diff, branch, tag, merge, rebase, sync); `pull` and `sync` fast-forward only

**Total: 28 handles** (25 core + 3 automation utilities), beta quality. See [docs/known_issues.md](docs/known_issues.md) for open issues.

---

## Why resh?

### For DevOps Teams
- One command form for many tasks that otherwise need separate tools and scripts
- Named JSON fields instead of text parsing

### For SRE Teams
- Structured data for observability and health checks
- Remote commands over SSH (`ssh://host.exec`)

### For AI/ML Engineers
- Designed with AI agents as consumers from the start
- Documented output fields and a consistent exit-code contract

---

## Development Timeline

| Milestone | Target | Status |
|-----------|--------|--------|
| v0.7 Alpha (25 handles) | November 2025 | ✅ **Completed** |
| v0.8 Alpha (27 handles) | December 2025 | ✅ **Completed** |
| v1.0 Beta (28 handles) | January 2026 | ✅ **Released** (v1.0.0-beta) |
| v1.0.2-beta (28 handles) | - | Current beta |
| v1.1 (30 handles) | Not yet scheduled | ⏱️ Planned |
| v1.0 Stable | Not yet scheduled | ⏱️ Planned |

Planned milestones are intentions, not commitments. See [ROADMAP.md](ROADMAP.md).

---

## Current Status

**What's working in v1.0.2-beta:**
- ✅ 28 handles registered, with per-handle and per-verb `--help`
- ✅ Automation utilities (backup, plugin, template)
- ✅ URI parser and resource dispatcher
- ✅ JSON output (`--json-pretty` to indent); some verbs also offer text output
- ✅ SSH remote execution through the system `ssh` client
- ✅ Database operations (PostgreSQL, MySQL/MariaDB, SQLite)
- ✅ Service management (systemd and OpenRC)
- ✅ Template rendering with the Tera engine
- ✅ Plugin installs from HTTPS registries with SHA-256 verification
- ✅ Backup create/list/restore/verify/prune through restic, borg, rsync or tar
- ✅ Documentation for all handles, organized by category

**What's next:**
- ⏱️ webhook:// and lock:// handles (planned for v1.1)
- ⏱️ Enhanced integration test suite (v1.1)
- ⏱️ Performance optimization (v1.1)
- ⏱️ Binary releases for major distributions (v1.0 stable)
- ⏱️ Production hardening and polish (v1.0 stable)

**Beta limitations:**
- ⚠️ Some verbs are stubs or simulated (for example `ssh tunnel`, `dns zone.update`, `secret rotate`); each handle page says so
- ⚠️ The test suite still has known failures; see [docs/known_issues.md](docs/known_issues.md)
- ⚠️ Fixes involving root, real devices or remote servers were tested with unit tests and dry runs, not against live systems
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

- **Rust 1.88 or later** - Install from [rustup.rs](https://rustup.rs)
- **Git** - For cloning the repository
- **Linux x86_64** - The only supported platform. macOS and Windows are not supported.

What has been verified: resh builds and its tests run on Gentoo Linux x86_64 (an OpenRC host). The `pkg://` handle was exercised against apt (Debian bookworm), dnf (Fedora 42), yum (Amazon Linux 2), pacman (Arch) and apk (Alpine 3.20) in unprivileged sandboxes. brew and systemd hosts have not been exercised.

### Building from Source

```bash
# Clone the repository
git clone https://github.com/millertechnologygroup/resh.git
cd resh

# Checkout the v1.0.2-beta release
git checkout v1.0.2-beta

# Build in release mode, using the dependency versions in Cargo.lock
cargo build --release --locked

# Binary will be at: ./target/release/resh
./target/release/resh --version
```

### Quick Installation

```bash
# Install to /usr/local/bin (requires sudo)
cargo build --release --locked
sudo cp target/release/resh /usr/local/bin/
sudo chmod +x /usr/local/bin/resh

# Verify installation
resh --version
```

### Development Build

```bash
# Build for development (faster compile, slower runtime)
cargo build

# Run directly (read-only example)
cargo run -- svc://sshd.status

# Run tests
cargo test
```

### Binary Releases

**Coming in v1.0 stable** - Pre-built binaries for:
- Ubuntu/Debian (.deb)
- RHEL/Fedora/CentOS (.rpm)
- Arch Linux (AUR)
- Generic Linux (tar.gz)

These are plans; no binary packages are published yet.

---

## Contributing

**resh v1.0.2-beta is available for testing.** We welcome:

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

**Not accepting pull requests yet** - We plan to open contributions with v1.0 stable.

Formal contribution guidelines coming with v1.0 stable.

### Community

- **GitHub Issues:** Bug reports and feature requests
- **GitHub Discussions:** Questions and ideas (coming soon)
- **Discord:** Real-time community (coming with v1.1)

See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

---

## Philosophy

**Structured Over Unstructured**  
Operations return named fields (mostly JSON) instead of free text.

**Simple Over Complex**  
URI-based addressing works like the web. If you understand URLs, you understand resh.

**Composable Over Monolithic**  
Build complex workflows from simple, reliable primitives.

**AI-Native Over AI-Compatible**  
Designed for autonomous agents from the ground up, not bolted on later.

**Native Over Interpreted**  
A single Rust binary. Many handles drive existing system tools (systemctl, rc-service, package managers, restic, ssh, and so on), which must be installed for those handles to work.

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
A: Yes. v1.0.2-beta is available for testing and feedback. Some verbs are stubs or have known limitations; check the handle's page and [docs/known_issues.md](docs/known_issues.md).

**Q: Is v1.0-beta production-ready?**  
A: No. This is a beta release with 28 handles. Test it in non-production environments. A stable release (v1.0 stable) is planned but not yet scheduled.

**Q: What's missing before v1.0 stable?**  
A: 2 additional handles (webhook://, lock://), the open items in [docs/known_issues.md](docs/known_issues.md), performance optimization, broader testing, and hardening.

**Q: Can I contribute code?**  
A: Not yet. We plan to open for code contributions with v1.0 stable. For now, please test, report bugs, and provide feedback.

**Q: What about Windows/macOS?**  
A: Not supported. resh is Linux-only: the code uses Unix-only system calls, and nothing has been built or tested on macOS or Windows.

**Q: How is this different from Ansible?**  
A: Ansible uses YAML playbooks with output designed for humans. resh uses URIs with structured output (mostly JSON) designed for both humans and AI agents. Ansible is for configuration management. resh is for real-time operations and AI-native automation.

**Q: How is this different from Terraform?**  
A: Terraform is for infrastructure-as-code with state management. resh is for real-time operations and automation without state files. They solve different problems and can be complementary.

**Q: Why 28 handles instead of 30?**  
A: We focused on delivering comprehensive core functionality and automation utilities (backup, plugin, template) that provide immediate value. The remaining 2 handles (webhook://, lock://) are advanced features planned for v1.1.

**Q: Where should I report bugs?**  
A: [GitHub Issues](https://github.com/millertechnologygroup/resh/issues) - Please include your OS, resh version, command, and output.

**Q: Can I use resh in my company?**  
A: Yes, it's Apache 2.0 licensed. However, being beta, we recommend testing in non-production environments first.

**Q: What's the performance like?**  
A: Functional but not yet optimized. Current focus is correctness.

---

**v1.0.2-beta available now. Test it. Break it. Help us build the future of infrastructure automation.** 🚀

[Download v1.0.2-beta](https://github.com/millertechnologygroup/resh/releases/tag/v1.0.2-beta) • [Report Issues](https://github.com/millertechnologygroup/resh/issues) • [Read Docs](docs/) • [View Roadmap](ROADMAP.md)