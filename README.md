# resh - Resource Shell

**AI-Native Automation Platform for Modern Infrastructure**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-v1.0.6--beta-blue.svg)](https://github.com/millertechnologygroup/resh/releases)
[![Status](https://img.shields.io/badge/status-beta-blue.svg)]()

---

## v1.0.6-beta - 28 Handles (Beta)

**resh v1.0.6-beta is available for testing.** It is a security release that hardens the `firewall://` handle and how resh stops external tools at a timeout (see [Security](#security)). resh has 28 handles, among them automation utilities for backups, plugins and template rendering. It is beta software: some verbs are stubs or have known limitations, listed in each handle's documentation and in [docs/known_issues.md](docs/known_issues.md).

⭐ **Star this repo** to follow development and be notified of updates!

**Current Status:**
- ✅ 28 handles and 229 verbs registered, each with built-in help (`resh <handle> --help`)
- ✅ Most verbs print JSON; some also offer a text format (see each handle's docs)
- ✅ URI-based resource model
- ⏱️ 2 additional handles planned for v1.1
- ⚠️ Beta quality - expect bugs and rough edges; see [docs/known_issues.md](docs/known_issues.md)

---

## What is resh?

resh (Resource Shell) is a command-line tool that runs operations on resources named by URLs (`svc://nginx.status`, `file:///etc/hosts.read`) and prints structured results, mostly JSON, that both scripts and AI agents can consume without text parsing.

**v1.0.6-beta has 28 handles, including the backup, plugin and template automation utilities.**

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
28 handles in v1.0.6-beta: automation utilities (backup, plugin, template) plus files, processes, services, databases, secrets, certificates, networking, and more.

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

## Implemented in v1.0.6-beta (28 Handles, 229 Verbs)

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
- ✅ `svc://` - Service management (systemd and OpenRC; systemd has not yet been verified on a live host)
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
- ✅ `firewall://` - Firewall rules and state (iptables, nftables, ufw, firewalld); rule fields are validated before any backend command is built (see [firewall.md](docs/Security_Secrets/firewall.md))
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
- ✅ `pkg://` - Package manager (apt, dnf, yum, pacman, apk; brew is supported but not yet verified): install, remove, update, upgrade, search, info, snapshot; `restore` is best effort and does not pin locked versions; `security_only` works only for dnf/yum `update` and dnf `upgrade` and is refused elsewhere
- ✅ `git://` - Git through libgit2 (clone, pull, push, commit, status, diff, branch, tag, merge, rebase, sync); `pull` and `sync` fast-forward only

**Total: 28 handles** (25 core + 3 automation utilities) with 229 verbs, beta quality. See [docs/known_issues.md](docs/known_issues.md) for open issues.

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
| v1.0.6-beta (28 handles) | November 2026 | Current beta (security release) |
| v1.1 (30 handles) | Not yet scheduled | ⏱️ Planned |
| v1.0 Stable | Not yet scheduled | ⏱️ Planned |

Planned milestones are intentions, not commitments. See [ROADMAP.md](ROADMAP.md).

---

## Current Status

**What's working in v1.0.6-beta:**
- ✅ 28 handles and 229 verbs registered, with per-handle and per-verb `--help`
- ✅ Automation utilities (backup, plugin, template)
- ✅ URI parser and resource dispatcher
- ✅ JSON output (`--json-pretty` to indent); some verbs also offer text output
- ✅ SSH remote execution through the system `ssh` client
- ✅ Database operations (PostgreSQL, MySQL/MariaDB, SQLite)
- ✅ Service management (OpenRC verified; systemd not yet verified on a live host)
- ✅ Template rendering with the Tera engine
- ✅ Plugin installs from HTTPS registries with SHA-256 verification
- ✅ Backup create/list/restore/verify/prune through restic, borg, rsync or tar
- ✅ Documentation for all handles, organized by category

**What's next:**
- ⏱️ webhook:// and lock:// handles (planned for v1.1)
- ⏱️ Enhanced integration test suite (v1.1)
- ⏱️ Performance optimization (v1.1)
- ⏱️ Distribution packages: .deb, .rpm, AUR (v1.0 stable)
- ⏱️ Production hardening and polish (v1.0 stable)

**Beta limitations:**
- ⚠️ Some verbs are stubs or simulated (for example `ssh tunnel`, `dns zone.update`, `secret rotate`); each handle page says so
- ⚠️ The default test suite passes, but integrations (systemd, real root, SMTP/SSH/DNS servers, brew) are not verified live; see [docs/known_issues.md](docs/known_issues.md)
- ⚠️ Fixes involving root, real devices or remote servers were tested with unit tests and dry runs, not against live systems
- ⚠️ Performance not yet optimized
- ⚠️ Error messages need improvement
- ⚠️ Some edge cases not fully handled

**Try it out:**
- Download the prebuilt binary or build from source (see [Installation](#installation))
- Report bugs and feedback via GitHub Issues
- Join early testing community

---

## Installation

resh runs on **Linux x86_64 only**. Install the prebuilt binary from the GitHub release, or build from source.

> **Install script.** The install script at `get.reshshell.dev` has not been updated for v1.0.6-beta and installs an older release. Until this notice is removed, install from the GitHub release as described below.

### Supported platforms

| | Prebuilt binary | Build from source |
| --- | --- | --- |
| Architecture | Linux x86_64 | Linux x86_64 |
| glibc | **2.39 or later** | The system's glibc (CI builds and tests on Debian 12, glibc 2.36) |
| Run-time libraries | OpenSSL 3 (`libssl.so.3`, `libcrypto.so.3`), `libz.so.1`, `liblzma.so.5`, `libgcc_s.so.1` | Same |
| Verified | Ubuntu 24.04, Debian 13, Fedora 40 | Debian 12 (CI), Gentoo |
| Does not run | Ubuntu 22.04, Debian 12 and Fedora 39 (tested); RHEL 8/9 (glibc 2.28/2.34, not tested) and any other system with glibc older than 2.39 | Not tested on systems other than those above |

macOS, Windows, BSD, ARM and musl are not supported, and no binaries are provided for them. resh uses the system OpenSSL, so its security updates come from your distribution. libssh2 and libgit2 are compiled into resh and are updated through resh releases.

Many handles drive system tools (`systemctl` or `rc-service`, `nft`/`iptables`, package managers, `ssh`, `restic`, and so on). A handle works only where its tools are installed; see each handle's page.

### Install the prebuilt binary

Release page: [v1.0.6-beta](https://github.com/millertechnologygroup/resh/releases/tag/v1.0.6-beta) (pre-release, published November 5, 2026). It has two assets: `resh-v1.0.6-beta-linux-x86_64.tar.gz` and `SHA256SUMS`.

```bash
VERSION=v1.0.6-beta
BASE=https://github.com/millertechnologygroup/resh/releases/download/$VERSION
curl -fLO "$BASE/resh-$VERSION-linux-x86_64.tar.gz"
curl -fLO "$BASE/SHA256SUMS"

# Verify before unpacking; this must print "...: OK"
sha256sum -c SHA256SUMS

tar -xzf "resh-$VERSION-linux-x86_64.tar.gz"
"./resh-$VERSION-linux-x86_64/resh" --version    # resh 1.0.6-beta

# Install to /usr/local/bin (requires sudo)
sudo install -m 0755 "resh-$VERSION-linux-x86_64/resh" /usr/local/bin/resh
resh --version
```

The SHA-256 of `resh-v1.0.6-beta-linux-x86_64.tar.gz` is:

```text
ada3337201f3a4b3d44cde372dbc8ec239219098e41577978674853a4be8d8c9
```

Release assets are checksummed but **not signed**. A matching checksum shows that the download is intact, not who published it, so download both files from the GitHub release page over HTTPS.

The archive contains the `resh` executable, `LICENSE`, `README.md`, `CHANGELOG.md` and `docs/known_issues.md`.

### Build from source

Prerequisites:

- **Rust 1.88 or later** - Install from [rustup.rs](https://rustup.rs)
- **Git**
- A C compiler, `pkg-config` and the OpenSSL 3 development headers (`libssl-dev` on Debian and Ubuntu, `openssl-devel` on Fedora)

```bash
git clone https://github.com/millertechnologygroup/resh.git
cd resh

# Check out the v1.0.6-beta release
git checkout v1.0.6-beta

# Build in release mode, using the dependency versions in Cargo.lock
cargo build --release --locked
./target/release/resh --version    # resh 1.0.6-beta

# Install to /usr/local/bin (requires sudo)
sudo install -m 0755 target/release/resh /usr/local/bin/resh
```

A source build links against the system's own glibc, so it is the option for systems with glibc older than 2.39. Source builds have been tested only on the systems listed under *Verified* above.

### Development Build

```bash
# Build for development (faster compile, slower runtime)
cargo build

# Run directly (read-only example)
cargo run -- svc://sshd.status

# Run tests
cargo test
```

### Upgrading from v1.0.5-beta

Replace the binary. The CLI syntax and output formats are unchanged, with two intended tightenings:

- `firewall://` refuses rule values that earlier versions accepted: malformed or injection-shaped fields, numbers with a leading zero (`dport=022`, `saddr=10.0.0.0/010`), and options the chosen backend cannot write. The command exits 1 with a `firewall.*` error code. Write numbers in plain decimal (`22`, `/10`).
- When an external tool reaches its deadline, resh stops it and its child processes and exits **124** with `Error: outcome unknown: ...`. The tool may already have made changes, so check the state before retrying.

See [CHANGELOG.md](CHANGELOG.md) for details.

### Troubleshooting installation

| Symptom | Cause and fix |
| --- | --- |
| `version 'GLIBC_2.39' not found` | The system's glibc is older than 2.39. Build from source. |
| `libssl.so.3: cannot open shared object file` | OpenSSL 3 is missing. Install it (`libssl3` or `libssl3t64` on Debian and Ubuntu, `openssl-libs` on Fedora), or use a distribution that ships OpenSSL 3. |
| `sha256sum: WARNING: 1 computed checksum did NOT match` | The download is corrupt or not the published file. Delete it and download both assets again from the release page. Do not run it. |
| A handle reports that a tool or backend is not available | Install the tool the handle drives (for example `nft`, `systemctl`, `restic`). |
| Exit code 124 | An operation reached its deadline; see [docs/resh_overview.md](docs/resh_overview.md) 3.3. |

### Distribution packages

Distribution packages (.deb, .rpm, AUR) are planned for v1.0 stable. None are published yet.

---

## Security

v1.0.6-beta is a security release. It fixes these issues:

- **firewall command injection:** every rule field is validated as a single token before any backend command is built, and a rule that a backend cannot write in full is refused instead of being silently narrowed.
- **ambiguous numbers in firewall rules:** ports, protocol numbers and CIDR prefix lengths must be plain decimal. A leading-zero value is refused instead of being applied by the backend as octal.
- **wrong firewall rule deleted:** a rule's action is read from the rule itself, not from its comment.
- **broader firewall rule skipped:** an `idempotent` add no longer treats an existing, narrower rule as satisfying the request.
- **timeouts:** for the `firewall`, `pkg`, `ssh`, `net`, `system` and `log` handles, external tools, including descendants that call `setsid`, are stopped at the operation deadline, and an unconfirmed outcome exits 124 instead of possibly reporting success. Other handles are not yet covered (see below).

v1.0.5-beta is affected by all of these, and earlier versions by the firewall and timeout issues. Upgrading is recommended for anyone who uses `firewall://` to add or delete rules, or who relies on timeouts to stop external tools. Earlier security fixes are listed in [CHANGELOG.md](CHANGELOG.md).

Limitations that remain are listed in [docs/known_issues.md](docs/known_issues.md), including:

- Timeout containment is incomplete: it does not cover `backup`, `fs` (for example mount, resize and check), `cron`, `user`, `svc` (including its `systemctl` fallback), `firewall` reload from a file on the iptables backend, and `net route.list`. After a timeout or failure of one of these operations, check the resource before retrying.
- `svc://<unit>.start` and `.restart` report that the service manager accepted the job, not that the unit became active. Confirm with `svc://<unit>.status` or `svc://<unit>.wait`.
- `cargo audit` passes only with the advisory exceptions in `.cargo/audit.toml`, each with its assessment. A dependency refresh is planned for v1.0.7-beta.

These fixes do not make resh free of vulnerabilities. To report one, follow [SECURITY.md](SECURITY.md); do not open a public issue.

---

## Contributing

**resh v1.0.6-beta is available for testing.** We welcome:

### How You Can Help Now

**1. 🐛 Test and Report Bugs**
- Try resh in your environment
- Report issues via [GitHub Issues](https://github.com/millertechnologygroup/resh/issues) (security vulnerabilities: see [SECURITY.md](SECURITY.md))
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
- **[GitHub Discussions](https://github.com/millertechnologygroup/resh/discussions):** Questions, ideas and general support (not for security reports; see [SECURITY.md](SECURITY.md))
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
A: Yes. v1.0.6-beta is available for testing and feedback. Some verbs are stubs or have known limitations; check the handle's page and [docs/known_issues.md](docs/known_issues.md).

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

**v1.0.6-beta available now. Test it. Break it. Help us build the future of infrastructure automation.** 🚀

[Download v1.0.6-beta](https://github.com/millertechnologygroup/resh/releases/tag/v1.0.6-beta) • [Report Issues](https://github.com/millertechnologygroup/resh/issues) • [Read Docs](docs/) • [View Roadmap](ROADMAP.md)