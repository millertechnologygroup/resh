# Resource Shell (resh) – Technical Help Documentation

## 1. Overview

Resource Shell (resh) is a command-line tool that runs one operation on one resource per invocation. The resource is named by a URL, the operation is a verb, and the result is printed on stdout, mostly as JSON.

resh addresses common problems of shell-based automation:

* Every tool has its own syntax and its own text output
* Scripts depend on fragile text parsing (`grep`, `awk`, `sed`)
* Failures are reported inconsistently, which makes them hard to handle in scripts and AI-driven workflows

resh gives these operations one command form:

```text
resh <handle>://<target>.<verb> key=value ...
```

Status: the latest release is v1.0.6-beta. This page describes the current source, which adds the unreleased changes listed in the [CHANGELOG](../CHANGELOG.md) (every handle audited, fixed and tested, and the shared conventions in 3.5). resh has 28 handles (29 URL schemes, because `http` and `https` are one handle) with 232 verbs. Linux x86_64 is the only supported platform; installation is described in the [README](../README.md#installation). Known limitations are listed in each handle's page and in [known_issues.md](known_issues.md).

---

## 2. Design Principles

### One Command Form

All operations use the same URL-style stage. Only the meaning of the target and the set of arguments differ per handle.

### Structured Output

Most verbs print one JSON object on stdout, so scripts read named fields instead of parsing text. There is **no shared response envelope**: each handle prints its own shape, documented on its page and in the `Example Output` of `resh <handle> <verb> --help`. Some verbs print other things by design, for example `file read` prints the file content, `log tail` prints raw lines (JSON with `mode=json`), and `svc logs` prints plain log lines. Some verbs print nothing on success (for example `svc reload`).

### Consistent Failure Reporting

Every handle uses the same exit codes (0, 1, 2, 124) and the same error line, `Error: [<handle>.<code>] <message>` (see 3.3). A failure is never reported with exit code 0.

### Safety Features (Per Handle)

Every handle checks all of its arguments before it does anything (see 3.5). Several handles add their own safeguards, such as `dry_run` plans, refusing to overwrite files unless `overwrite=true`, protecting system accounts, or taking firewall backups before changes. These are handle-specific, not global; read the handle's page before running changing verbs.

### Use by AI Agents and Automation

The uniform command form, documented output fields and the exit-code contract make resh usable as a tool interface for scripts and AI agents. resh does not add guarantees beyond what each handle documents.

---

## 3. Command Syntax and Execution Model

### 3.1 Stage Grammar

```text
resh [--json-pretty] <handle>://<target>.<verb> [key=value ...]
resh '<handle>://<target>.<verb>(key=value,...)'     alternative form; quote it for the shell
resh <handle> --help                                 also -h, help, resh help <handle>
resh <handle> <verb> --help                          also -h, help, resh help <handle> <verb>
resh <handle>://help                                 handle help from a stage URL
resh <handle>://<target>.<verb> --help               help for the stage's verb
resh --list-schemas
```

| Component | Description |
| --------- | ----------- |
| `handle`  | The URL scheme, which selects the handle (`file`, `svc`, `system`, ...). `resh --list-schemas` lists all registered schemes. An unknown scheme is refused with `resh.unknown_handle` (exit 2) and a suggestion |
| `target`  | What the handle operates on. Its meaning differs per handle: a path (`file`), a service name (`svc`), a queue name (`mq`), an alias echoed back (`fs`, `pkg`), or empty (`dns`, `event`, `archive`, `firewall`, `system`) |
| `verb`    | The operation. It is the text after the **last** dot of the URL; dotted verbs such as `rules.add`, `chain.info`, `zone.fetch` and `nice.get` are recognized as a whole |
| `key=value` | Arguments. Trailing `key=value` words are the common form. Quote values that contain spaces or shell characters. Values are passed exactly as the shell gives them (they are not trimmed) |

A URL with no target still needs the dot before the verb: `system://.memory`, `dns://.lookup`, `archive://.create`. `archive://create` (no dot) does not parse.

`--json-pretty` goes before the stage and re-indents JSON output (non-JSON output is printed unchanged).

#### Examples

File operations:

```bash
resh file:///etc/hostname.read
resh --json-pretty file:///etc/hosts.stat
```

Service management:

```bash
resh --json-pretty svc://nginx.status
resh svc://nginx.restart
```

System inspection:

```bash
resh system://.memory
resh system://.info
```

Secret retrieval:

```bash
resh secret://local/db_password.get redact=true
```

Function-call form:

```bash
resh 'svc://nginx.restart(timeout_ms=5000)'
```

### 3.2 Execution Semantics

* **One stage per process.** Each `resh` invocation parses one stage, runs it and exits. Nothing in memory (connections, database transactions, sessions) survives between invocations. State persists only where a handle writes it to disk, for example `config` (under `$XDG_CONFIG_HOME/resh/`), `event`, `mq` and `snapshot` (under `$XDG_STATE_HOME/resh/`), and the plugin store (under `$XDG_DATA_HOME/resh/plugins`). The handle pages give the exact locations.
* **Help never touches the resource.** Every help form (3.1, and `?help` or `?help=<verb>` in a stage URL) prints built-in help without running anything. An unknown handle or verb in a help request is an error (exit 2) with a "did you mean" suggestion. The format is described in [cli_help_format.md](cli_help_format.md).
* **Output is streamed.** A stage's output goes to stdout as it is written, so watch, follow and progress output appears while the verb runs. Only `--json-pretty` buffers, because it re-indents the whole output.
* **Timeouts.** Every verb whose work can take long accepts `timeout_ms`; verbs that finish at once refuse it (exit 2). See 3.5 and the table in each category overview.
* **External tools are contained.** Where a handle runs an external tool under a deadline (for example `firewall`, `pkg`, `ssh`, `net`, `log`, `cron`, `user`, `backup`, `fs`), the tool runs in its own process group. At the deadline resh stops the tool and every process it started, including ones that call `setsid`, and exits 124 (see 3.3). Stopping a tool does not undo what it already did. A systemd job that `svc` started over D-Bus is cancelled at the deadline; a job already queued through `systemctl` keeps running in systemd.

### 3.3 Exit Codes and Errors

Every handle uses the same exit codes:

| Exit code | Meaning |
| --------- | ------- |
| 0 | Success |
| 1 | The operation failed: not found, refused by the system, a backend or tool error, a partial failure |
| 2 | Invalid usage: an unknown argument, an invalid value, an unknown handle or verb. Nothing was done |
| 124 | A timeout, or the outcome is unknown (for example an external tool reached its deadline and was stopped, or could not be stopped). The work may be partly done, so check the resource before retrying |

Every failure prints one line on stderr in the same format, with an error code that starts with the handle's name:

```text
Error: [git.repository_not_found] repository not found: /srv/project
```

Verbs that print a JSON result on failure carry the same code and message in it as `"error": {"code": "<handle>.<code>", "message": "..."}` (some handles add fields such as `details`). Errors raised before a handle runs use `resh.invalid_stage` (the stage cannot be parsed), `resh.unknown_handle`, `<handle>.invalid_target` and `<handle>.invalid_argument` (all exit 2). Each handle's page lists its codes and which exit code each one has.

### 3.4 Dry Run

* A bare `dry_run` word means `dry_run=true`. Any other bare word (for example `dry-run` or `dryrun`) and any misspelled key (`dry-run=true`, `DRY_RUN=true`, `dryRun=1`) is an error (exit 2) and nothing runs.
* **A dry-run request never runs a verb that has no dry-run mode.** If a verb's usage (`resh <handle> <verb> --help`) does not list `dry_run`, then `dry_run=true` (or a bare `dry_run`, or a malformed value) is refused before the handle runs: `Error: <handle> <verb> does not support dry_run; nothing was done`, exit 2. `dry_run=false` is accepted everywhere.
* `dry_run`, like every boolean, accepts `true/false/1/0/yes/no/on/off` (any case). Any other value (such as `dry_run=maybe` or `dry_run=ture`) is an error and nothing runs.
* **Not every verb has a dry run.** Examples:
  * `svc` has no dry run; `dry_run=true` is refused and nothing runs.
  * `mail send` refuses `dry_run` (exit 2, nothing sent); use `mail://send_template ... dry_run=true` to preview a message.
  * `backup restore dry_run=true` reports the destination and what would be restored, from the backend's read-only listing; `backup list` and `verify` refuse `dry_run`.
  * `backup prune dry_run=true` with restic or borg runs the backend's own dry run. It removes nothing, but it takes a repository lock (exclusive for borg), writes the backend's local cache and needs the repository credentials. See `backup.md` 4.5.
  * Every `ssh` verb takes `dry_run=true`: arguments and local inputs are checked and the plan is reported, but no connection is made.
  * `pkg` reads `dry_run` inside its `input=` JSON. A top-level `dry_run=true` next to `input=` is refused (exit 2) instead of being ignored.
* Check the handle's page before relying on a dry run.

### 3.5 Shared Conventions

These rules hold for every handle. The category overviews and handle pages link here and describe only what is specific to them.

* **Strict arguments.** Each verb accepts exactly the arguments shown in its usage (`resh <handle> <verb> --help`). An unknown argument, a misspelled one, an option of another mode or backend, `dry_run` or `timeout_ms` on a verb that does not support it, and an invalid value are refused before anything is done: exit 2, a message naming the argument and, for a likely typo, a "did you mean" hint. Earlier releases ignored unknown arguments in most handles.
* **Booleans** accept `true/false`, `1/0`, `yes/no`, `on/off` in any case; any other value is refused (exit 2).
* **Exit codes and errors** are the same everywhere (3.3): 0, 1, 2, 124 and `Error: [<handle>.<code>] <message>`, with `"error": {"code", "message"}` in JSON results.
* **Timeouts.** Every verb whose work can take long (unbounded data, tree walks, external tools, network) accepts `timeout_ms` and stops at the deadline with exit 124. Child processes are stopped and partial work is removed or reported, as the handle's page describes. Verbs that finish at once refuse `timeout_ms` (exit 2). For watch and follow verbs (`config watch`, `file watch`, `file tail follow=true`, `log tail follow=true`, `event subscribe follow=true`, `svc logs follow=true`) `timeout_ms` is the run time: reaching it is a normal end with exit 0. Per-verb defaults are on each handle's page.
* **Owner-only files.** Files that may hold secrets or configuration are written with mode 0600 in directories created with mode 0700 (for example `config` values, the `secret` index, `mail` profiles, `mq` queues, `snapshot` metadata, `backup` repositories created by resh, `firewall rules.save` files and `cert` private keys). `mq` and `backup` do not fall back to `/tmp`.
* **No writes through symbolic links.** A write never follows a symbolic link planted at the target path: the handle replaces the link or refuses the write.
* **Shell-style globs.** In glob arguments (for example `archive` include/exclude patterns, `file find name=`, `pkg snapshot exclude_patterns`) `*` and `?` do not match `/`, and `**` matches across directories.
* **TLS.** Every verb that verifies TLS certificates accepts `ca_file=<pem>` to trust a private CA for that call, with verification still on (`cache` over `rediss://`, `db`, `http`/`https`, `mail`, `net tcp_check`, `plugin`, `secret` vault scope, `cert verify`). Options that turn verification off are explicit and documented as insecure (`http allow_insecure`, `mail tls_accept_invalid_certs`, `db tls_mode=prefer|allow|require`).
* **Stored secrets** (`secret://local` values, `mail` profile passwords) are kept in the OS keyring; files keep only a reference. Without a keyring, storing is refused (exit 1); values stored in files by earlier releases are still read, with a warning, and moved to the keyring by the next write.
* **Secrets on the command line.** Arguments are visible in the process list and shell history. Where a verb takes a password or secret, prefer its environment, stdin or file form (for example `secret set from_env=` or `from_stdin=true`, `user passwd new_password_env=`, `cert ... key_passphrase_env=`, `backup password_file=`); the plain forms of `user` and `cert` passwords print a warning every time.

---

## 4. Functional Domains

resh groups its 28 handles into eight categories. Each category has an overview page, and each handle has its own page with the registered verbs, arguments, output fields and limitations.

---

### 4.1 Automation Utilities

**Handles:** `backup`, `plugin`, `template` ([overview](Automation_Utilities/overview.md))

* `backup`: runs restic, borg, rsync or tar to create, list, restore, verify and prune backups. `schedule` installs a systemd timer or crontab line through the `cron` handle.
* `plugin`: manages a local plugin store; installs from an HTTPS registry (SHA-256 and Ed25519 publisher signature checked), a direct HTTPS URL (needs `verify=none`) or a local file; keeps one previous version for `rollback`.
* `template`: renders, validates and tests Tera templates; rendering never writes files.

```bash
resh backup://mydata.create src=/srv/app/data backend=tar repo_url=/srv/backups dry_run=true
resh template://nginx.conf.render context_file=/srv/vars/prod.json
resh plugin://installed.list format=names
```

---

### 4.2 Data & State Management

**Handles:** `cache`, `config`, `db`, `event`, `log`, `mq` ([overview](Data_StateManagement/overview.md))

* `cache`: Redis or Memcached keys (`url=` on every command).
* `config`: local JSON values, one owner-only file per key (get, set, ls, watch; no delete verb).
* `db`: SQL on SQLite, PostgreSQL or MySQL/MariaDB (`dsn=` on every command; one connection per command, transactions run within one command; remote servers use verified TLS by default).
* `event`: local event topics stored as JSON Lines files, safe for concurrent resh processes, with optional log, file and mq hooks.
* `log`: tail or follow a log file or a systemd service journal.
* `mq`: local, single-host file-based FIFO queue, safe for concurrent producers and consumers (not a distributed queue).

```bash
resh config://app/theme.get
resh db://sqlite/app.query 'sql=SELECT id, email FROM users' dsn=sqlite:app.db
resh log:///var/log/syslog.tail lines=10
resh mq://tasks.put data=hello
```

---

### 4.3 Filesystem & Storage

**Handles:** `file`, `archive`, `fs`, `snapshot` ([overview](Filesystem_Storage/overview.md))

* `file`: read, write, inspect, hash, search, copy, move and delete files; permissions, extended attributes, tags.
* `archive`: create, list, test, extract and modify tar, tar.gz, tar.xz, tar.zst, zip and gzip archives (no 7z; no password-protected archives).
* `fs`: mounted filesystems: list, usage, quotas, mount/unmount, resize, check.
* `snapshot`: full local copies of a file or directory, with diff, list and restore.

```bash
resh file:///etc/hostname.read
resh archive://.extract archive=backup.tar.gz destination=restore
resh --json-pretty fs://local.usage mode=aggregate
resh snapshot:///etc/nginx.create name=pre-change
```

---

### 4.4 Network & Remote Operations

**Handles:** `ssh`, `http`/`https`, `mail`, `dns`, `net` ([overview](Network_RemoteOperations/overview.md))

* `ssh`: remote commands, file upload/download, connection tests, port forwarding (`tunnel`) and remote public keys (`keys.list`, `key.add`) through the system `ssh` client.
* `http`/`https`: HTTP requests (get, head, headers, options, preflight, json, post, put, patch, delete).
* `mail`: SMTP sending, built-in templates, real SMTP session checks, stored profiles (passwords in the OS keyring). `send` has no dry run.
* `dns`: resh's own DNS client: lookups, resolution, delegation traces, zone transfers (AXFR and IXFR, optionally TSIG-signed), RFC 2136 dynamic updates (`zone.update`, optional TSIG).
* `net`: local interfaces and routes, ping, TCP checks, port scans, simple DNS queries.

```bash
resh ssh://alice@192.0.2.10.exec command=uptime
resh http://api.example.com/v1/users/42.get accept=json
resh dns://.lookup name=example.com rtype=MX
resh net://192.0.2.10:22.tcp_check
```

---

### 4.5 Packages & Software

**Handles:** `pkg`, `git` ([overview](Packages_Software/overview.md))

* `pkg`: runs the host package manager (apt, dnf, yum, pacman, apk, brew) to install, remove, update, upgrade, search, snapshot and restore packages. Arguments are passed as one `input=` JSON object. `restore` installs, upgrades and downgrades to the locked versions by default (`mode: exact`; pacman and brew are limited, see `pkg.md`). `security_only=true` is supported only for `update` with dnf or yum and `upgrade` with dnf; elsewhere it is refused before anything runs.
* `git`: Git through libgit2 (clone, pull, push, commit, status, diff, branch, tag, merge, rebase, sync). `pull` and `sync` merge or rebase diverged history; every verb takes `timeout_ms`.

```bash
resh pkg://system.install 'input={"manager":"auto","packages":[{"name":"curl"}],"dry_run":true}'
resh git://default.clone url=https://github.com/user/repo.git path=/tmp/repo
```

---

### 4.6 Process & Service Management

**Handles:** `cron`, `proc`, `svc` ([overview](Process_ServiceManagement/overview.md))

* `cron`: scheduled jobs as crontab entries or systemd timers (list, add, enable, disable, rm).
* `proc`: signals, nice values (for every thread) and resource limits (`limits.set`, through `prlimit`) for one process. There is no process status verb, and no verb but `nice.get` acts on the resh process itself.
* `svc`: services through systemd or OpenRC (status, start, stop, restart, reload, enable, disable, mask, unmask, wait, logs, scale). Changing verbs wait for the systemd job, and `start`/`restart` check that the unit keeps running. No dry run.

```bash
resh cron://local.list
resh proc://1234.signal sig=HUP
resh svc://nginx.restart
```

---

### 4.7 Security & Secrets

**Handles:** `user`, `secret`, `cert`, `firewall` ([overview](Security_Secrets/overview.md))

* `user`: local users and groups (exists, groups, add, delete, passwd, lock, unlock), with real password hashing and protection for system accounts.
* `secret`: secrets in the OS keyring (`local`; a names-only index file, nothing in plaintext) or in HashiCorp Vault KV v2 (`vault`), and read-only environment lookup (`env`); `rotate` generates random, UUID, AES or RSA secrets.
* `cert`: X.509 certificates, keys (also passphrase-encrypted PKCS#8) and CSRs in local files (info, verify, chain.info, generate, csr.create, sign, renew), with raw or CMS signatures. There is no ACME / Let's Encrypt support.
* `firewall`: rules (NAT included) and state for iptables, nftables, ufw and firewalld.

```bash
resh user://alice.exists
resh secret://env/DATABASE_URL.get
resh --json-pretty cert:///etc/ssl/certs/server.pem.info
resh firewall://.rules.add proto=tcp dport=22 dry_run=true
```

---

### 4.8 System Information

**Handle:** `system` ([overview](SystemInformation/overview.md), [system.md](SystemInformation/system.md))

Read-only information about the local Linux host: info, uptime, load, memory, cpu, disk, env.list.

```bash
resh system://.memory
resh system://.cpu
resh system://.disk 'input={"mount_points":["/"]}'
```

---

## 5. Platform Support

| Platform | Support |
| -------- | ------- |
| Linux x86_64 | Supported. The prebuilt v1.0.6-beta binary needs glibc 2.39 or later and OpenSSL 3 (verified on Ubuntu 24.04, Debian 13, Fedora 40). Builds from source are tested in CI on Debian 12 and on Gentoo Linux (OpenRC) |
| macOS, BSD, Windows | Not supported. The code uses Unix-only system calls and Linux interfaces such as `/proc`; nothing has been built or tested on these systems |

Many handles drive system tools (`systemctl` or `rc-service`, package managers, `ssh`, `restic`, `iptables`, and so on). A handle works only where its tools are installed. Verbs that change the host or talk to servers are tested end to end against real tools and services in throwaway Docker containers (for example `pkg` against apt, dnf, yum, pacman and apk; `svc` against systemd; `firewall` against nftables, iptables and ufw, and firewalld); brew and a live OpenRC host have not been exercised. See each handle's page for its requirements and what was tested.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Read the handle's page (or `resh <handle> <verb> --help`) before running a changing verb.
* Use `dry_run=true` where the verb supports it, and check that it does (see 3.4).
* Test in a non-production environment first; this is a beta release.
* Use explicit targets and arguments rather than relying on defaults (for example, pass `repo_url` to `backup`).

### Automation Considerations

* Gate scripts on the exit code (3.3), then read the JSON fields documented for that handle.
* Exit codes and the error format are shared; output shapes and error codes are per handle, so do not assume one handle's output fields apply to another.
* Remember that each invocation is independent; pass connection arguments (`url=`, `dsn=`) every time.

### CI/CD Integration

* Use `--json-pretty` only for people; scripts can read the compact output.
* Capture stderr: it carries the `Error: [<handle>.<code>] <message>` line on failure.

### Production Environment Recommendations

* Keep automation scripts under version control.
* Restrict who can run handles that change the system (`user`, `firewall`, `pkg`, `svc`, `fs`); resh does not elevate privileges itself.
* Do not pass secrets as command-line arguments where a file, environment or stdin option exists (see 3.5).

---

## 7. Use Cases by Role

### DevOps Engineers

* Run service, package and file operations with one command form.
* Add structured system checks to CI/CD.

### SRE Engineers

* Check host health with `system`, `svc` and `fs` and read named fields.
* Restart services and confirm their state with `svc wait`.

### Network Administrators

* Inspect and change firewall rules (with `dry_run` first).
* Run DNS lookups, ping, TCP checks and port scans.

### AI/Automation Engineers

* Use resh as a tool interface whose verbs, arguments and outputs are documented per handle.
* Use the exit code and the coded `Error: [<handle>.<code>]` line to detect and classify failures.

---

## 8. Technical Foundation

resh is a single binary written in Rust.

* Rust's memory safety and compile-time type checking remove whole classes of bugs, though they do not guarantee that every operation behaves correctly; see [known_issues.md](known_issues.md).
* Each handle is a module under `src/handles/<category>/` that registers its verbs; built-in help lives with the handle (see [cli_help_format.md](cli_help_format.md)).
* Performance has not yet been optimized or benchmarked.
