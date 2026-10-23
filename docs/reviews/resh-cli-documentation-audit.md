# Resource Shell (resh) — Documentation and Help Accuracy Audit (Stage 4, RC-03)

- **Date:** 2026-10-23
- **Base commit:** `277f996` (branch `help-system-and-fixes`), with the uncommitted Stage 1-4 changes
- **Scope:** README.md, CONTRIBUTING.md, CHANGELOG.md, every Markdown file under `docs/` except `docs/reviews/`, and the built-in CLI help.

## Summary

- **The prose documentation was rewritten against the code.**
  - All 38 Markdown files under `docs/` were reviewed, and README and CONTRIBUTING too.
  - 36 `docs/` files were substantially rewritten.
- **The source of truth was the code.** Each handle's `verbs()` and `call()` dispatch, its option parsers, and the built-in help, which the original review had already found accurate.
- **The examples are now checked automatically.** The new test `tests/doc_examples.rs` takes every `resh` command in a shell code block and parses it with the real stage parser and registry. It runs in the default `cargo test`.

| | Before Stage 4 | After Stage 4 |
|---|---|---|
| Examples checked | 569 | 609 |
| Failing | 145 (25%) | **0** |
| Needing manual review (shell substitution) | 1 | 1 |

- **Unsupported and stub behaviour is now stated plainly** where the docs used to present it as working. Examples: secret encryption, ssh tunnels, backup scheduling, pkg rollback, git sync merge/rebase, ZIP encryption, dns `zone.update`, cert CMS, and `proc limits.set`.
- **The built-in help format is unchanged** (`Handle:`, `Verb:`, `Definition:`, `Usage:`, `Example:`).
  - Two `pkg` usage lines gained a note about `security_only`.
  - The fs resize example output now shows the corrected `resize2fs` size.
  - `help_coverage` still passes: 29 schemes, 239 verb entries, every example parses.

## Method

1. **Reference data.**
   - For each handle, the registered verbs come from `Handle::verbs()`. The arguments come from the verb's option-parsing code, cross-checked against `resh <handle> <verb> --help`.
2. **Mechanical validation.** `tests/doc_examples.rs`:
   - **Scope:** README, CONTRIBUTING and `docs/**/*.md`, minus `docs/reviews/`. It reads only fences tagged `bash`, `sh`, `shell` or `console`, or untagged ones.
   - **What counts as an example:**
     - a line starting with `resh ` (an optional `$ ` prompt is allowed);
     - a bare stage starting with `<scheme>://`.
   - **Joining:** backslash continuations, open quotes and unclosed `(` join lines.
   - **Splitting:** the command is split like a POSIX shell and ends at `|`, `>`, `<`, `;`, `&&` or `#`.
   - **Checks:**
     - the scheme is registered;
     - the stage parses;
     - the verb is one the handle registers, or a help form;
     - trailing words are `key=value` or a bare `dry_run`.
   - **Nothing is executed.** Handles are built from their help probe URL only, to read `verbs()`.
   - **Limits:** lines that use `$VAR`, `$(...)` or globs cannot be checked statically. They are listed with `DOC_EXAMPLES_VERBOSE=1` for manual review. The test checks argument *names* only for the trailing `key=value` shape, so argument names were reviewed by hand against the parsers.
3. **Safe live confirmation.**
   - Where it was safe, reviewers ran the documented commands with the built binary.
   - Runs were limited to a scratch directory, with HOME and XDG paths redirected: read-only verbs, dry runs, and local-only workflows (archive, file, snapshot, secret, cert, template, sqlite db, event, mq, config, plugin `source=file`).
   - No command that mutates the host or contacts a remote service was run as part of the documentation audit.
   - One exception: a plugin `update dry_run` attempted an HTTPS registry lookup. It failed to resolve, and nothing was installed.
4. **Output samples** were replaced with real output, taken from the help's Example Output or from live runs. A sample that is shortened is labelled as abbreviated.

## Handle and verb coverage

29 schemes, 28 handle modules (`http` and `https` share one), 229 distinct verbs, and 239 verb entries in the help. Each handle's registered verbs are all documented in its page. The table lists what was removed or corrected.

| Handle | Verbs registered | Doc page | Main corrections |
|---|---|---|---|
| archive | 7 | Filesystem_Storage/archive.md | Every example used `archive://create` (no dot), which does not parse. There is now a per-format support matrix: create is tar, tar.gz, zip and gzip only. tar.xz and tar.zst are read-only; 7z is unsupported. ZIP `password=` is refused. The extraction-safety error codes are listed. Ignored options are named. |
| backup | 6 | Automation_Utilities/backup.md | The invented `op`/`status` envelope is replaced by the real `BackupEnvelope`. `schedule` only reports. Examples now include `repo_url` and a password source. The default `/tmp` repositories are stated. Per-verb timeouts are listed. The dry-run rules are stated (see the Stage 4 fixes below). |
| cache | 8 | Data_StateManagement/cache.md | `url=` is on every call, and nothing persists between invocations. Backend names are corrected. The numeric-key and memcached `exists`/`ttl` limitations are documented. |
| cert | 8 | Security_Secrets/cert.md | The claims about password-encrypted keys are removed. The CSR-signing example used the unreachable `csr.sign`, so it now uses `sign mode=csr`. The invented `ca_bundle` is now `trust_paths`. CMS, revocation and the `chain.info` stub are stated. |
| config | 4 | Data_StateManagement/config.md | Watch scope is described. There is no delete verb. The containment claim is removed, because `config://../x` escapes by one level. |
| cron | 5 | Process_ServiceManagement/cron.md | The invented 0-7 exit-code table is removed; every failure exits 1. The rules for which commented lines `enable` re-enables are stated. The weekday, OnCalendar and newline limitations are listed. |
| db | 7 | Data_StateManagement/db.md | Connections and transactions do not persist between invocations, so the docs use `transaction action=run`. `DB_<ALIAS>_DSN` and `?mode=rwc` are documented. NUMERIC decoding is a stated limitation. |
| dns | 5 | Network_RemoteOperations/dns.md | `dns:// lookup` is now `dns://.lookup`. `zone.update` is simulated and TSIG is never applied. With no `servers=`, queries go to Google Public DNS, not resolv.conf. |
| event | 6 | Data_StateManagement/event.md | `event://emit` is now `event://.emit`. The state-file backend is under the XDG state dir. `list-topics` returns sample data. Hooks are simulations. |
| file | 32 | Filesystem_Storage/file.md | The "absolute paths required" claim is removed. `max_count` is now `max`. Hash algorithm lists are corrected. `write` without `data=` reads stdin. The invented exit-code table is removed. |
| firewall | 8 | Security_Secrets/firewall.md | The exit-code table is removed. The backup-before-change behaviour (iptables/nftables) is documented, as is "no backup" for ufw/firewalld. `timeout_ms` is enforced, with one exception (`rules.reload` restore). |
| fs | 11 | Filesystem_Storage/fs.md | `fs:///.disk` is removed. Per-verb exit codes are listed. The unsupported options are stated: negative resize `delta`, `all_subjects`, yaml output. |
| git | 13 | Packages_Software/git.md | sync is fast-forward only (see below). The docs say libgit2, not the git binary or credential helpers. `timeout_ms` is rejected. depth and recursive are unsupported. `--json-pretty` has no effect. |
| http/https | 10 | Network_RemoteOperations/http.md | Per-verb exit codes are listed: head, headers and json exit 0 on 4xx/5xx. `allow_insecure` works for `put` only. Per-verb timeouts are listed. |
| log | 1 | Data_StateManagement/log.md | `log://help` examples are removed. Pattern and UTF-8 behaviour are documented. `log://svc/...` needs systemd. |
| mail | 4 | Network_RemoteOperations/mail.md | The `main.rs` argument rewriting is documented. The SMTP password is base64, **not encrypted**, in a file that gets the default umask. `send` has no dry run. `tls_accept_invalid_certs` semantics are explained. |
| mq | 6 | Data_StateManagement/mq.md | The storage path is corrected to the XDG state dir. The "no duplication, safe concurrent consumers" claims are replaced with the real behaviour. |
| net | 6 | Network_RemoteOperations/net.md | `net://eth0.status()` is removed. `ping` exits 0 when the host is unreachable. `expect_tls` is ignored. `list` flags are synthesized. |
| pkg | 10 | Packages_Software/pkg.md | `manager` is required. The rollback and exact-version restore claims are removed. Validation and argv-only execution are documented. Per-verb timeouts are listed. brew is untested. `security_only` is documented (Stage 4 fix). |
| plugin | 9 | Automation_Utilities/plugin.md | Security section: see below. Argument names for `available.list` and `available.info` are corrected. The default catalog path is CWD-relative. |
| proc | 16 | Process_ServiceManagement/proc.md | Signal numbers are now Linux, not macOS. Exit codes are listed per verb. `limits.set` and `io.peek` are documented as not functional for other processes. The PID range is stated. |
| secret | 5 | Security_Secrets/secret.md | The store is **plaintext** JSON (0600 file, 0700 dir), not "encrypted at rest". `rotate` and `vault` are not implemented. `expose_value` is removed. There is no locking. `value=` is visible in `ps`. |
| snapshot | 4 | Filesystem_Storage/snapshot.md | The real argument names are used. The store location is given. `ls` and `diff` need an absolute target. `ttl` is not enforced. |
| ssh | 8 | Network_RemoteOperations/ssh.md | `accept_new` is now `accept-new`. `tunnel`, `keys.list` and `key.add` are stubs. The real quoting behaviour of `exec` is documented, with a warning. `env=` is set on the local process only. |
| svc | 13 | Process_ServiceManagement/svc.md | `instances=` is now `count=`. Timeouts are in milliseconds (`timeout=`). The "generic init" and BSD backends are removed. Backend detection is described. Verified exit codes are listed. Instance names are covered. |
| system | 7 | SystemInformation/system.md | Nonexistent options are removed (`name_filter`, `mask_sensitive`, `max_variables`). The no-effect options are marked: `include_swap`, `max_process_classes`, `include_raw`, `include_paths`. |
| template | 3 | Automation_Utilities/template.md | `validate` reads `from=`/`inline=`, not `template=`. Encoding, URL parameters and inheritance claims are removed. Tera `get_env` exposure is documented. |
| user | 7 | Security_Secrets/user.md | The exit-code table is replaced: every failure exits 1, and `exists` for a missing user exits 0. `create_home` and `password_hash` are documented as ignored. `primary_group` is not validated. The system-account protection threshold is given. |

The category overviews (`docs/*/overview.md`) and `docs/resh_overview.md` used verbs that do not exist:

- `proc://1234.status`
- `backup://daily.run`
- `fs:///.disk`
- `net://eth0.status`
- `cron://backup.schedule`
- `user://deploy.create`
- `firewall://rule.add`
- `event://user.created.publish`
- `mq://jobs.enqueue`
- `secret://….list`

They also used argument names that do not exist (`cmd=`, `dest=`, `content=`, `label=`), a response envelope no handle emits (`op`, `status`, `resource`, `handle`), and macOS/Windows support claims. All of these were replaced.

## Required corrections (brief §6)

| Topic | Now documented |
|---|---|
| **Git synchronization** | `git sync` fast-forwards when behind, pushes when only ahead, and **fails before pushing anything** when histories have diverged:<br>• `git.sync_failed` for `pull_strategy=rebase`/`merge`;<br>• `git.sync_non_fast_forward` for `ff_only`.<br>It never merges or rebases; `pull_strategy` only selects the error. `remote_branch` must equal the local branch. A failed sync pops an auto-stash back. Verified live in Stage 4 with local repositories: divergent sync failed for all three strategies and the remote was unchanged; behind-only sync fast-forwarded. |
| **ZIP encryption** | Password-protected archive creation is not supported. Any `password=` value, even an empty one, fails with `archive.create_password_not_supported` before any file is written; an unencrypted archive is never produced. |
| **Plugin installation** | • Registries and artifact URLs must be HTTPS with a valid certificate. `http://` is refused before connecting, and a redirect to HTTP is refused.<br>• With the default `verify=sha256`, a registry artifact needs a 64-hex SHA-256, checked before extraction. A missing or malformed checksum fails with `PLUGIN_VERIFY_FAILED`.<br>• The checksum proves integrity in transit only. It comes from the same registry, so it does not prove publisher authenticity.<br>• Artifacts may contain only regular files and directories. Links, devices, FIFOs, absolute paths and `..` paths fail the install, and nothing is installed.<br>• Ids and versions must be single safe path components.<br>• `source=url` has no trusted checksum, so it needs an explicit `verify=none`. That installs an **unverified** artifact protected only by HTTPS; the docs do not present it as equivalent to verified installation.<br>• Malformed `verify=` values are errors. |
| **Timeouts** | Every handle page has a statement or table of which verbs enforce `timeout_ms`, which reject it, and which ignore it. A summary:<br>• **Enforced:** backup (backend killed); firewall (child killed, except the `rules.reload` restore step); db; cache; fs (resh stops waiting, the child is not killed); pkg (stops waiting, child not killed); http (some verbs; head and patch use fixed timeouts); plugin install/update (per request); config `watch`; file `watch`.<br>• **Rejected:** git (exit 2).<br>• **Ignored:** archive, cert, secret, user, template, event, log, mq, cron, proc, svc (which uses `timeout=` for stop/wait), ssh (it has its own options), system. |
| **Unsupported or stubbed** | • secret: encryption at rest, `rotate`, `vault`.<br>• ssh: `tunnel`, `keys.list`, `key.add`; the `test` sftp/hostkey checks.<br>• backup: `schedule` installs nothing.<br>• pkg: rollback, and version pinning on restore.<br>• dns: `zone.update` (simulated), TSIG.<br>• cert: CMS, encrypted keys, `chain.info` chain building.<br>• proc: `limits.set` and `io.peek` for other processes.<br>• fs: `all_subjects`.<br>• event: `list-topics` (sample data). |

## Corrections driven by Stage 4 code fixes

Stage 4 verification found defects whose code fix changed the documented behaviour. Each page was updated after the fix.

| Fix | Pages updated |
|---|---|
| `pkg` `security_only` is refused unless the manager's command can filter to security fixes (dnf/yum for `update`, dnf for `upgrade`) | pkg.md, built-in help usage, README |
| `backup restore` refuses `dry_run=true`. `backup create`/`prune` reject a malformed `dry_run` | backup.md, Automation overview |
| `mail send` refuses `dry_run` | mail.md, Network overview |
| `fs mount`/`unmount` reject a malformed `dry_run`; the ext3/ext4 resize size is corrected | fs.md, Filesystem overview, help example output |
| `file rename/copy/move` accept a bare destination name. `rename` checks the parent before deleting the destination | file.md, Filesystem overview |
| `archive add/remove` on `.tar.zst` no longer truncates the archive | archive.md |
| `archive add` keeps existing tar entries' headers; rewrites use private, unpredictable temp files | archive.md, Filesystem overview |
| The dispatcher refuses `dry_run=true` for verbs with no dry-run mode, and refuses misspelled dry-run words and keys | resh_overview.md (general rule); svc.md, proc.md, secret.md, template.md, mail.md, backup.md, Automation overview, known_issues (no longer "ignored") |
| SMTP profile file 0600; firewall reload temp file | mail.md, Network overview, firewall.md |

## Top-level documents

- **README.md**
  - "28 Production-Ready Handles" became "28 handles" (beta), with a link to `docs/known_issues.md`.
  - Removed:
    - the unverifiable `curl https://get.reshshell.dev | sh` installer;
    - "Let's Encrypt" (there is no ACME code);
    - the macOS/Windows support claims;
    - unsupported statistics and marketing claims.
  - Every build command uses `--locked`; the toolchain is Rust 1.88 or later.
  - `cargo run -- svc://nginx status --format json` (invalid) became `cargo run -- svc://sshd.status`.
  - The handle bullets now match the handle pages.
  - The platform line states what was verified.
- **CONTRIBUTING.md**
  - Locked build and test commands.
  - How to run the opt-in infrastructure tests.
  - The real CI gates and the Clippy baseline. `cargo clippy -- -D warnings` fails today because of documented pre-existing debt.
  - The hypothetical `newhandle://` example is moved to a text fence.
- **docs/resh_overview.md**
  - Rewritten with the same 8-section structure.
  - It covers the real grammar and the exit-code contract: 0 on success; on failure the handle's code if it is 1-255, otherwise 1; `Error: <reason>` on stderr.
  - It also covers `dry_run` semantics, one process per invocation, the XDG state locations, and a Linux-only platform table.
- **docs/cli_help_format.md:** the placeholder grammar moved to a text fence. The format description is unchanged.
- **docs/known_issues.md**
  - A dated release-candidate status section was added. It covers test counts, the Stage 4 fixes, and the significant open limitations.
  - The stale ssh entry (upload/download were said to be simulated; they are real) was corrected.
  - The old status section is labelled historical.
- **CHANGELOG.md:** an unversioned "Release-candidate stabilization" entry lists the Stage 1-4 security fixes, functional fixes and compatibility changes.

## Remaining documentation limitations

1. **Argument names are not machine-checked.** The validator checks scheme, verb and `key=value` shape only, and the handles silently ignore unknown option keys. Argument names were reviewed by hand against the parsers; a future misspelled key would not fail the test.
2. **Output samples are point-in-time.** They come from the code and from live runs on this host, but no test pins them except the help golden files.
3. **One example needs manual review:** `docs/Data_StateManagement/db.md:135` uses `$1` inside a SQL string. It was reviewed and is correct.
4. **Two README references are pending:**
   - `git checkout v1.0.2-beta` and the download link point to a tag that does not exist yet (only `v1.0.0-beta` and `v1.0.1-beta` exist). Tag at release time, or change the instruction.
   - The repository URLs point to GitHub, while the CI added in Stage 4 is GitLab CI. Owner decision.
5. **Some behaviour is documented from code reading only,** because exercising it would need a real system, root, or a remote service. That covers firewall mutations, user mutations, svc start/stop on systemd, real SMTP, real SSH, and DNS against a real server. The handle pages say where this applies.
6. **Several code defects found during the audit were documented as limitations rather than fixed,** because they are not release-blocking. They are listed in `docs/known_issues.md` and in the Stage 4 assessment.
