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

Status: v1.0.3-beta, 28 handles. Linux is the only supported platform. Known limitations are listed in each handle's page and in [known_issues.md](known_issues.md).

---

## 2. Design Principles

### One Command Form

All operations use the same URL-style stage. Only the meaning of the target and the set of arguments differ per handle.

### Structured Output

Most verbs print one JSON object on stdout, so scripts read named fields instead of parsing text. There is **no shared response envelope**: each handle prints its own shape, documented on its page and in the `Example Output` of `resh <handle> <verb> --help`. Some verbs print other things by design, for example `file read` prints the file content, `log tail` prints raw lines (JSON with `mode=json`), and `svc logs` prints plain log lines. Some verbs print nothing on success (for example `svc reload`).

### Consistent Failure Reporting

Every failure produces a non-zero exit code and a reason (see 3.3). A failure is never reported with exit code 0.

### Safety Features (Per Handle)

Several handles add safeguards, such as `dry_run` plans, refusing to overwrite files unless `overwrite=true`, protecting system accounts, or taking firewall backups before changes. These are handle-specific, not global; read the handle's page before running changing verbs.

### Use by AI Agents and Automation

The uniform command form, documented output fields and the exit-code contract make resh usable as a tool interface for scripts and AI agents. resh does not add guarantees beyond what each handle documents.

---

## 3. Command Syntax and Execution Model

### 3.1 Stage Grammar

```text
resh [--json-pretty] <handle>://<target>.<verb> [key=value ...]
resh '<handle>://<target>.<verb>(key=value,...)'     alternative form; quote it for the shell
resh <handle> --help
resh <handle> <verb> --help
resh --list-schemas
```

| Component | Description |
| --------- | ----------- |
| `handle`  | The URL scheme, which selects the handle (`file`, `svc`, `system`, ...). `resh --list-schemas` lists all registered schemes |
| `target`  | What the handle operates on. Its meaning differs per handle: a path (`file`), a service name (`svc`), a queue name (`mq`), an alias echoed back (`fs`, `pkg`), or empty (`dns`, `event`, `archive`, `firewall`, `system`) |
| `verb`    | The operation. It is the text after the **last** dot of the URL; dotted verbs such as `rules.add`, `chain.info`, `zone.fetch` and `nice.get` are recognized as a whole |
| `key=value` | Arguments. Trailing `key=value` words are the common form. Quote values that contain spaces or shell characters |

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
* **Help never touches the resource.** `resh <handle> --help` and `resh <handle> <verb> --help` print built-in help without running anything. The format is described in [cli_help_format.md](cli_help_format.md).
* **Timeouts are per handle.** `timeout_ms` is enforced by some verbs and ignored by others; each category overview has a table.

### 3.3 Exit Codes and Errors

| Situation | Exit code | stderr |
| --------- | --------- | ------ |
| Success | 0 | (handle-specific, usually nothing) |
| Failure, handle sets a code in 1-255 | that code | `Error: <reason>`, unless the handle already wrote to stderr |
| Failure, no code or a code outside 1-255 | 1 | `Error: <reason>`, unless the handle already wrote to stderr |

Some handles also describe the failure in their JSON output (for example an `ok`, `error` or `code` field). The per-handle codes and error fields are documented on each handle's page; do not assume a code means the same thing in two handles.

Example of a failure on stderr:

```text
Error: git.repository_not_found: repository not found: /srv/project
```

### 3.4 Dry Run

* A bare `dry_run` word means `dry_run=true`. Any other bare word (for example `dry-run` or `dryrun`) and any misspelled key (`dry-run=true`, `DRY_RUN=true`, `dryRun=1`) is an error (exit 2) and nothing runs.
* **A dry-run request never runs a verb that has no dry-run mode.** If a verb's usage (`resh <handle> <verb> --help`) does not list `dry_run`, then `dry_run=true` (or a bare `dry_run`, or a malformed value) is refused before the handle runs: `Error: <handle> <verb> does not support dry_run; nothing was done`, exit 2. `dry_run=false` is accepted everywhere.
* Where a handle uses the shared argument parser, `dry_run` accepts `true/false/1/0/yes/no/on/off` (any case). Any other value (such as `dry_run=maybe` or `dry_run=ture`) is an error and nothing runs. This applies, for example, to `backup create` and `prune`, `fs mount` and `unmount`, `plugin` lifecycle verbs, `user` and `firewall`.
* **Not every verb has a dry run.** Examples:
  * `svc` has no dry run; `dry_run=true` is refused and nothing runs.
  * `mail send` refuses `dry_run` (exit 2, nothing sent); use `mail://send_template ... dry_run=true` to preview a message.
  * `backup restore` has no dry run and refuses `dry_run=true`.
  * `backup prune dry_run=true` with restic or borg runs the backend's own dry run. It removes nothing, but it takes a repository lock (exclusive for borg), writes the backend's local cache and needs the repository credentials. See `backup.md` 4.5.
  * `ssh tunnel`, `keys.list` and `key.add` are stubs that only succeed with `dry_run=true`.
  * `pkg` reads `dry_run` inside its `input=` JSON. A top-level `dry_run=true` next to `input=` is refused (exit 2) instead of being ignored.
* Check the handle's page before relying on a dry run.

---

## 4. Functional Domains

resh groups its 28 handles into eight categories. Each category has an overview page, and each handle has its own page with the registered verbs, arguments, output fields and limitations.

---

### 4.1 Automation Utilities

**Handles:** `backup`, `plugin`, `template` ([overview](Automation_Utilities/overview.md))

* `backup`: runs restic, borg, rsync or tar to create, list, restore, verify and prune backups. `schedule` only reports a definition; it installs no cron job or timer.
* `plugin`: manages a local plugin store; installs from an HTTPS registry (checksum-verified by default), a direct HTTPS URL (needs `verify=none`) or a local file.
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
* `config`: local JSON values, one file per key (get, set, ls, watch; no delete verb).
* `db`: SQL on SQLite, PostgreSQL or MySQL/MariaDB (`dsn=` on every command; transactions run within one command).
* `event`: local event topics stored as JSON Lines files.
* `log`: tail a log file or a systemd service journal.
* `mq`: local, single-host file-based FIFO queue (not a distributed queue).

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
* `archive`: create, list, test, extract and modify tar, tar.gz, zip and gzip archives (tar.xz and tar.zst are read-only; no 7z; no password-protected archives).
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

* `ssh`: remote commands and file upload/download through the system `ssh` client. `tunnel`, `keys.list` and `key.add` are stubs.
* `http`/`https`: HTTP requests (get, head, headers, options, preflight, json, post, put, patch, delete).
* `mail`: SMTP sending, built-in templates, SMTP checks. `send` has no dry run.
* `dns`: lookups, resolution, delegation traces, zone transfers. `zone.update` is simulated and sends nothing.
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

* `pkg`: runs the host package manager (apt, dnf, yum, pacman, apk, brew) to install, remove, update, upgrade, search and snapshot packages. Arguments are passed as one `input=` JSON object. `restore` is best effort and does not pin locked versions. `security_only=true` is supported only for `update` with dnf or yum and `upgrade` with dnf; elsewhere it is refused before anything runs.
* `git`: Git through libgit2 (clone, pull, push, commit, status, diff, branch, tag, merge, rebase, sync). `pull` and `sync` fast-forward only. `timeout_ms` is rejected.

```bash
resh pkg://system.install 'input={"manager":"auto","packages":[{"name":"curl"}],"dry_run":true}'
resh git://default.clone url=https://github.com/user/repo.git path=/tmp/repo
```

---

### 4.6 Process & Service Management

**Handles:** `cron`, `proc`, `svc` ([overview](Process_ServiceManagement/overview.md))

* `cron`: scheduled jobs as crontab entries or systemd timers (list, add, enable, disable, rm).
* `proc`: signals and nice values for one process. There is no process status verb; `limits.set` only affects the resh process itself.
* `svc`: services through systemd or OpenRC (status, start, stop, restart, reload, enable, disable, mask, unmask, wait, logs, scale). No dry run.

```bash
resh cron://local.list
resh proc://1234.signal sig=HUP
resh svc://nginx.restart
```

---

### 4.7 Security & Secrets

**Handles:** `user`, `secret`, `cert`, `firewall` ([overview](Security_Secrets/overview.md))

* `user`: local users and groups (exists, groups, add, delete, passwd, lock, unlock), with protection for system accounts.
* `secret`: a local keystore file (mode 0600, **not encrypted**) and read-only environment lookup. The `vault` scope and `rotate` are not implemented.
* `cert`: X.509 certificates, keys and CSRs in local files (info, verify, chain.info, generate, csr.create, sign, renew). There is no ACME / Let's Encrypt support.
* `firewall`: rules and state for iptables, nftables, ufw and firewalld.

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
| Linux x86_64 | Supported. Built and tested on Gentoo Linux x86_64 (OpenRC) |
| macOS, BSD, Windows | Not supported. The code uses Unix-only system calls and Linux interfaces such as `/proc`; nothing has been built or tested on these systems |

Many handles drive system tools (`systemctl` or `rc-service`, package managers, `ssh`, `restic`, `iptables`, and so on). A handle works only where its tools are installed. The `pkg` handle was exercised against apt, dnf, yum, pacman and apk in unprivileged sandboxes; brew and systemd hosts have not been exercised. See each handle's page for its requirements.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Read the handle's page (or `resh <handle> <verb> --help`) before running a changing verb.
* Use `dry_run=true` where the verb supports it, and check that it does (see 3.4).
* Test in a non-production environment first; this is a beta release.
* Use explicit targets and arguments rather than relying on defaults (for example, pass `repo_url` to `backup`).

### Automation Considerations

* Gate scripts on the exit code, then read the JSON fields documented for that handle.
* Do not assume one handle's output shape or exit codes apply to another.
* Remember that each invocation is independent; pass connection arguments (`url=`, `dsn=`) every time.

### CI/CD Integration

* Use `--json-pretty` only for people; scripts can read the compact output.
* Capture stderr: it carries the `Error: <reason>` line on failure.

### Production Environment Recommendations

* Keep automation scripts under version control.
* Restrict who can run handles that change the system (`user`, `firewall`, `pkg`, `svc`, `fs`); resh does not elevate privileges itself.
* Do not pass secrets as command-line arguments where a file or environment option exists (for example `password_file=`, `from_env=`).

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
* Use the exit code and the `Error:` line to detect failures.

---

## 8. Technical Foundation

resh is a single binary written in Rust.

* Rust's memory safety and compile-time type checking remove whole classes of bugs, though they do not guarantee that every operation behaves correctly; see [known_issues.md](known_issues.md).
* Each handle is a module under `src/handles/<category>/` that registers its verbs; built-in help lives with the handle (see [cli_help_format.md](cli_help_format.md)).
* Performance has not yet been optimized or benchmarked.
