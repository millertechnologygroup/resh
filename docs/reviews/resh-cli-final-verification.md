# Resource Shell (resh) — Final CLI Verification Report

- **Review date:** 2026-10-16
- **Reviewed commit:** `277f996300089269640dc5a962d01942aa871ccc` (branch `help-system-and-fixes`)
- **Review type:** Verification only. No source, test, configuration or dependency files were changed. This report is the only file added.

## Evidence legend

Every finding is tagged with how it was established:

| Tag | Meaning |
|---|---|
| **[LIVE]** | Reproduced by running the built `resh` binary on this host. Runs were confined to a scratch directory, or were read-only. |
| **[PARSE]** | Reproduced by calling the real `resh` library parser and registry from a throwaway crate outside the repository. Nothing was executed. |
| **[TEST]** | Established by the existing automated test suite. |
| **[CODE]** | Established by reading the source. The cited `file:line` shows the path from CLI input to the behaviour. |
| **[UNVERIFIED]** | Assumed or suspected, not demonstrated. |

## Executive Summary

**Recommendation: NOT READY.** The reasons are in the [Final Recommendation](#final-recommendation).

What works well:

- **The core design holds together.**
  - All 28 handle modules are registered, with no duplicates; they expose 29 URL schemes.
  - Every handle's `verbs()` list matches its `call()` dispatch exactly.
  - Unknown schemes and unknown verbs are rejected.
- **The new help system works well.**
  - `resh <handle> --help` and `resh <handle> <verb> --help` cover all 28 handles and all 239 listed verb entries, and every entry has all the required fields.
  - 238 of 239 help examples parse to the documented handle and verb. The exception is the documented, unreachable `cert csr.sign`.
  - Help never runs the handle.
- **The build compiles.** All 18 integration tests pass.
- **Unit tests:** 1031 of 1046 pass, 15 fail, and 13 were deliberately skipped for safety. The same 15 failed on the previous commit, so the latest work did not cause them.

What blocks finalization:

- **Three confirmed critical defects:**
  - Extracting an untrusted archive can write outside the destination directory [LIVE].
  - A plugin registry entry can make resh delete and overwrite any directory the user can write [CODE].
  - `proc://4294967295.kill` becomes `kill(-1, SIGKILL)` [PARSE+CODE].
- **Many high-severity defects:**
  - Safety flags that are silently ignored, so `dry_run=1` performs the real change.
  - Shell injection in `pkg`.
  - Firewall backups that are reported but never written.
  - Failures reported as success, and failures that print nothing.
  - A fresh clone of the repository cannot resolve its dependencies.
- **Quality gates fail:**
  - `cargo fmt --check` fails.
  - `cargo clippy -D warnings` fails with 1818 lints.
- **The prose documentation under `docs/` contradicts the code widely.** The built-in help, by contrast, is accurate.

There is no central authorization or policy layer. Every safety control lives in the individual handle and is applied inconsistently.

## Repository Baseline

| Item | Value |
|---|---|
| Branch | `help-system-and-fixes` (main branch: `main`) |
| Commit | `277f996` "Bump version to 1.0.2-beta"; its parent `beafdc3` is "Add per-handle CLI help and fix critical, high and low issues" |
| Working tree | Clean at start; clean at end apart from this report |
| Toolchain | `rustc 1.98.1 (48a229cea 2026-09-01)`, `cargo 1.98.1` |
| Crate | One package, `resh 1.0.2-beta`, edition 2024 — not a workspace. Has both a lib target (`src/lib.rs`) and a bin target (`src/main.rs`). |
| Build quirk | `main.rs` declares its own `mod core; mod handles;` instead of using the lib crate, so every unit test is compiled and run twice. |
| Size | About 152k lines of Rust in `src/` |
| Entry point | `src/main.rs`: clap `Cli` with `--list-schemas`, `--json-pretty`, `STAGE` and `ARGS...` |
| Command parser | `src/core/parse.rs` `parse_stage`: dotted-verb lists, plugin and mail special cases, last-dot split, in-URL help |
| Handle registration | `src/handles/mod.rs` → per-category `register_*` → `Registry::register_scheme(scheme, ctor)` (`src/core/registry.rs`) |
| Verb dispatch | `core::dispatch_stage` → `Registry::resolve` (URL scheme → constructor) → `Handle::call(verb, args, io)`; each handle matches on the verb string |
| Help | `src/core/help.rs`, intercepted in `main.rs` before clap; metadata comes from `Handle::help()` |
| Providers | Inside each handle: shell-outs (systemctl, rc-service, crontab, useradd, iptables/nft, package managers, tar, restic, borg, rsync, ssh), libgit2, sqlx, redis/memcache, trust-dns, reqwest, lettre |
| Test suites | 1007 `#[test]` functions in `src/**`, plus `tests/help_cli.rs` (16) and `tests/help_coverage.rs` (2) with golden files in `tests/golden/` |

## Handle Coverage Matrix

**What every handle has in common:**

- **Registration:** every handle is registered once.
- **Constructor:** construction with the help probe URL succeeds and does no I/O [TEST `help_coverage`, CODE].
- **`verbs()` vs `call()`:** they match exactly for every handle [CODE].
- **Help:** handle-level and verb-level help render with every required field [LIVE: 239/239].
- **Examples:** the help examples parse to the documented verb [PARSE: 238/239].

**Statuses:** *Defect Found* means at least one confirmed defect of Medium severity or higher. *Partially Verified* means no defect above Low was found, but live execution was not possible.

| Handle | Scheme(s) | Registered verbs | Help | Status | Principal findings |
|---|---|---|---|---|---|
| archive | `archive` | list, info, test, create, extract, add, remove | Verified | **Defect Found** | Symlink escape on extract (C1) [LIVE]. Zip `password` ignored (H8) [LIVE]. `allow_absolute_paths` logic inverted [TEST]. `add` strips tar metadata. |
| backup | `backup` | list, verify, create, restore, prune, schedule | Verified | **Defect Found** | Timeout never fires. `backup://<profile>` ignored, so every profile is `default`. Default repositories in world-writable `/tmp`. `schedule` installs nothing. `create dry_run=true` verified [LIVE]. |
| cache | `cache` | connect, get, exists, ttl, keys, set, incr, del | Verified | **Defect Found** | `cursor=`/numeric keys dropped, so SCAN paging never advances. memcached `exists`/`ttl` report true for missing keys. Provider errors visible [LIVE]. |
| cert | `cert` | info, verify, chain.info, generate, csr.create, sign, csr.sign, renew | Verified (csr.sign documented as unreachable) | **Defect Found** | `csr.sign` is advertised but unreachable from the CLI; `cert://x.csr.sign` silently runs `sign`. Keys written before they are chmod'd 0600. |
| config | `config` | get, ls, watch, set | Verified | **Defect Found** | Most errors print nothing, e.g. `set` without `value`. Suspected `config://../x` escape of the config directory. |
| cron | `cron` | list, add, enable, disable, rm | Verified | **Defect Found** | Failures exit 0. `enable` can turn ordinary comments into crontab lines. systemd timer discovery never matches. Strict `dry_run`. Newline injection. Weekday off-by-one. `list` verified [LIVE]. |
| db | `db` | connect, ping, query, tables, schema, exec, transaction | Verified | **Defect Found** | `ping` exits 0 when every attempt fails. Suspected typed-row panics on MySQL/PostgreSQL `information_schema`. |
| dns | `dns` | lookup, resolve, trace, zone.fetch, zone.update | Verified | **Defect Found** | Validation failures print nothing [LIVE]. `zone.update` is simulated. TSIG is never applied. |
| event | `event` | list-topics, subscribe, emit, hooks.list, hooks.enable, hooks.disable | Verified | **Defect Found** | Built-in hooks `println!` to real stdout and corrupt JSON. Unknown verb is silent. `list-topics` returns sample data. |
| file | `file` | 32 verbs (read … tag.rm) | Verified | **Defect Found** | Relative directories rejected [LIVE]. Many errors silent: `stat` on a missing file and `grep` without a pattern [LIVE]. `rename overwrite=true` deletes the destination before renaming. `write` without `data=` reads stdin and truncates [LIVE, by design]. |
| firewall | `firewall` | status, rules.list, rules.add, rules.delete, rules.save, rules.reload, enable, disable | Verified | **Defect Found** | `enable`/`disable` exit 0 on failure. Reported backups never written (H3). `sh -c` with unquoted `path`. Predictable `/tmp` backups. Timeouts ineffective. |
| fs | `fs` | list-mounts, usage, snapshot, quota, quota_summary, mount, unmount, umount, resize, check, fsck | Verified | **Defect Found** | Every failure, including unknown verbs, prints nothing [LIVE]. Negative `delta` resize can never work. `all_subjects` is a stub. |
| git | `git` | status, status_summary, status_short, diff, branch, tag, commit, merge, rebase, clone, pull, push, sync | Verified | **Defect Found** | Output via `println!` bypasses `io.stdout` and `--json-pretty`. `timeout_ms` cannot fire. `sync` rebase/merge are placeholders reported as success, followed by a push. |
| http / https | `http`, `https` | get, head, headers, options, preflight, json, post, put, patch, delete | Verified | **Defect Found** | Network and argument failures print nothing. Process exit code = HTTP status mod 256 (404 → 148). `allow_insecure` honoured only by `put`. |
| log | `log` | tail | Verified | **Defect Found** (Medium) | URL path not percent-decoded. First line truncated in a boundary case. |
| mail | `mail` | test, config, send, send_template | Verified | **Defect Found** | `main.rs` argument rewriting wraps values in quotes without escaping (recipient injection, breaks on `(`). SMTP password stored base64 in a umask-permission file. |
| mq | `mq` | len, peek, create, put, get, purge | Verified | **Defect Found** (Medium) | Temp file matches the `.msg` filter, so concurrent `get` can read a partial message. Empty-queue and error results print nothing. |
| net | `net` | list, route.list, dns, ping, tcp_check, scan | Verified | **Defect Found** (Medium) | `ping` counts "Destination Host Unreachable" as replies. TCP fallback accepts only IPs. `expect_tls` unused. |
| pkg | `pkg` | info, search, list_installed, snapshot, install, remove, update, upgrade, restore, apply_lock | Verified | **Defect Found** | Package names interpolated into `sh -c`, even in dry run (H1). Partial failures exit 0. `restore` ignores locked versions. |
| plugin | `plugin` | available.list, available.search, available.info, installed.list, install, update, remove, enable, disable | Verified | **Defect Found** | Version path traversal leads to `remove_dir_all` (C2). sha256 "verification" passes with no checksum. Enabled state written to and read from different files. |
| proc | `proc` | 16 verbs (signal … limits.set) | Verified | **Defect Found** | PID `u32` → `pid_t` wrap gives `kill(-1)` (C3). `limits.set` affects only the exiting resh process. `io.peek` reads files nothing writes. |
| secret | `secret` | get, ls, set, rm, rotate | Verified | Partially Verified | Store is 0600/0700 with atomic writes [CODE]. No lock around load-modify-save. `rotate` returns not-implemented (documented in help). |
| snapshot | `snapshot` | ls, diff, create, restore | Verified | **Defect Found** | `diff from=<name>` always fails because it looks up by UUID. `ls` does not find snapshots created with relative targets. TTL overflow panic. |
| ssh | `ssh` | config.get, keys.list, test, exec, upload, download, key.add, tunnel | Verified | **Defect Found** | `exec` exits 0 when ssh fails or the remote exits non-zero. `command_args` under-quoted for the remote shell. `tunnel`/`keys.list` stubs (documented in help). |
| svc | `svc` | status, is-enabled, start, stop, restart, reload, enable, disable, mask, unmask, wait, logs, scale | Verified | **Defect Found** | `svc://getty@tty1.stop` acts on `tty1` [PARSE] (H9). A nonexistent service gives `status` exit 0 [LIVE]. `journalctl` errors discarded. |
| system | `system` | info, uptime, load, memory, cpu, disk, env.list | Verified | **Defect Found** (Medium) | Documented `info` options have no effect. Non-ASCII device name panics `disk`. `info` verified [LIVE]. |
| template | `template` | render, validate, test | Verified | **Defect Found** (Medium) | Unknown verb is silent. `validate` rejects `template=`, which the other verbs accept. `--help=<verb>` ignored. |
| user | `user` | exists, groups, add, delete, passwd, lock, unlock | Verified | **Defect Found** | Strict `dry_run` parse, so `dry_run=1` runs useradd/userdel (H2). `primary_group` not validated, which allows option injection into groupadd. `exists` always exits 0. |

The total is 239 verb entries (229 distinct, because http and https share one handle). The expected handle count of 28 is correct. The schemes number 29 because `http` and `https` share `HttpHandle`.

### Help system verification (prototype scope exceeded)

Help covers all handles, not a prototype subset.

- **Handle-level help** [LIVE]:
  - Exit code is 0 for all 29 schemes, and each starts with `Handle: <name>`.
  - Each has a Description, an Available Verbs list (one definition per verb) and a Usage line.
  - The verb list is filtered to registered, non-alias verbs [TEST `handle_help_lists_exactly_the_registered_verbs`].
- **Verb-level help** [LIVE]:
  - 239/239 contain `Handle:`, `Verb:`, `Definition:`, `Usage:` and `Example:`, in order.
  - Most also have `Example Output:`.
- **Example grammar** [PARSE]:
  - 238/239 examples, split as a shell would split them, resolve to the documented scheme and verb, and that verb is in `verbs()`.
  - The exception is `cert csr.sign`. Its example is `resh cert sign --help` because the verb cannot be reached; the help states this explicitly.
- **Fallback behaviour** [LIVE]: unknown handles and unknown verbs fall back to clap's global help with exit 0. `tests/help_cli.rs` asserts this as intended behaviour.
- **Line wrapping** [TEST]: lines are wrapped at 80 columns.
- **Help is side-effect free** [TEST `help_does_not_execute_or_need_external_tools`, `render_never_calls_handle`].
- **Exceptions:** three handles exit the process from inside their constructor when the host or path is a help word: `git://help`, `pkg://help` (`gith.rs:1914-1929`, `pkgh.rs:1196-1210`). A legitimate alias named `help` is therefore unusable. **Low.**

## Test Results

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | **FAILED** (exit 1): about 14,600 diff hunks. The code is not rustfmt-formatted. |
| `cargo check --all-targets` | **PASSED** (exit 0). 541 compiler warnings: unused variables and imports, dead code, deprecated `base64::encode`. Future-incompatibility warning for `redis v0.25.4`. |
| `cargo build --all-targets` | **PASSED** (exit 0). |
| `cargo clippy --all-targets -- -D warnings` | **FAILED** (exit 101): 1529 errors in the lib target and 1783 in the lib test target, 1818 distinct error sites in total. Most are style lints, e.g. 558 `collapsible_if` and 203 `needless_borrows`. Correctness-relevant ones are listed below this table. |
| `cargo test` (unit, lib target) | **1031 passed, 15 failed, 13 skipped** |
| `cargo test` (unit, bin target; same tests compiled again) | **1035 passed, 15 failed, 13 skipped** (the same 15) |
| `tests/help_cli.rs` | **16 passed, 0 failed** |
| `tests/help_coverage.rs` | **2 passed, 0 failed** |
| Doc tests | 0 |

**Correctness-relevant clippy findings** (style lints omitted):

- `absurd_extreme_comparisons` / type-limit comparisons at `dbh.rs:6929, 6963, 7013, 7060` (test code).
- `await_holding_lock` at `dbh.rs:1717, 1812`.
- 25 `if_same_then_else` sites, e.g. `archiveh.rs:544-546` and `firewallh.rs:5239`.
- `identity_op` at `fsh.rs:8035-8081`.
- 5 always-true assertions in `cacheh.rs` and `certh.rs` tests.

**Test command executed:**

```
env -u MAIL_SMTP_USERNAME -u MAIL_SMTP_PASSWORD -u TEST_POSTGRES_DSN -u TEST_MYSQL_DSN \
    -u TEST_REDIS_URL -u TEST_MEMCACHED_ADDR \
  cargo test --no-fail-fast -- --skip test_disable_verb_recognized \
    --skip gith::tests::test_timeout_functionality --skip https_ \
    --skip dbh::tests::test_postgres_ --skip dbh::tests::test_mysql_
```

**Pre-run safety review:** every test module was inspected before execution.

- Under `cfg(test)`, the user and ssh handles route system commands through stubs that refuse to run them.
- cron, pkg, firewall, fs and backup tests only build command strings.

**Tests skipped deliberately (13, blocked by safety or environment, not run):**

| Test(s) | Reason |
|---|---|
| `pluginh::tests::test_disable_verb_recognized` | **Unsafe:** writes the real `~/.local/share/resh/plugins` state (`pluginh.rs:3287`). |
| `gith::tests::test_timeout_functionality` | Real clone to the fixed `/tmp/timeout_test`. Can hang about 2 minutes because the timeout cannot fire. |
| 3 `gith` `*https*` integration tests | Need `TEST_GIT_*` env vars; one performs a real `git push`. |
| 8 `dbh` PostgreSQL/MySQL integration tests | Need live database servers and run DDL/DML. |

**Tests run that depend on the network or environment:**

- 6 `mailh::mail_dns_resolution_tests` (DNS lookups, TCP connect to localhost:587). They passed here, so they are environment-dependent rather than deterministic.
- `cacheh` memcached tests attempt `127.0.0.1:11211` and pass either way.

**The 15 failing tests:**

| Test | Assessment |
|---|---|
| `userh::tests::test_groups_verb_{exclude_primary,exclude_supplementary,exclude_system_groups,group_name_filter,no_groups_warning}` | Test defects: a `MockBackend` is built but never passed to the handle. |
| `userh::tests::test_groups_verb_includes_groups`, `test_unlock_verbs_includes_unlock` | Stale verb counts: the tests expect 6 and 5, but 7 verbs are now registered. |
| `userh::tests::test_unlock_{dry_run,force_system_user,protect_system_user,text_format_output}` | Mock not wired in. As a result, **system-user unlock protection is not verified** by any passing test. |
| `archiveh::tests::test_path_sanitization` (`archiveh.rs:5793`) | **Real defect:** with `allow_absolute_paths=false`, absolute entries are rebased instead of rejected (the logic is inverted). The live extract test confirmed the rebasing. |
| `gith::tests::test_connection_not_found`, `test_validate_tag_config_delete`, `test_status_integration_detached_head` | Unclassified. Not investigated deeply; they may be stale expectations or host-dependent. |

**Regression check:**

- The tree at the parent of `beafdc3` (`9d46f4b`) was exported with `git archive` to a scratch directory outside the repository.
- The same 15 tests were built and run there against the current `Cargo.lock`. **All 15 fail there too.** They are pre-existing, which matches the claim in `docs/known_issues.md`.

**Live CLI checks:** about 40 invocations, all read-only or confined to a scratch directory. Results are cited throughout this report.

## Security Findings

There is **no central authorization, policy, or read-vs-mutation layer**:

- `dispatch_stage` (`src/core/mod.rs:15-39`) only parses the stage, merges arguments and calls the handle.
- The `Handle` trait carries no mutation classification and no confirmation mechanism.
- The tool runs with the invoking user's privileges.

Findings below concern data crossing a trust boundary, or safety controls that do not behave as advertised.

### Confirmed vulnerabilities

**C1 — Critical. Archive extraction writes outside the destination through symlinks.** [LIVE + CODE]

- **Root cause:**
  - `allow_symlinks` defaults to `true` (`archiveh.rs:1318-1320`).
  - `sanitize_path` checks only path text (`:5614-5656`).
  - Entries are written with `create_dir_all(parent)` + `entry.unpack(&safe_path)` (`:5355-5360`). That `unpack` variant does not check link targets.
- **Live reproduction:** a tar containing `lnk -> ..` followed by `lnk/escaped_via_symlink.txt`, extracted with `archive://.extract archive=evil.tar.gz destination=dest`, wrote `escaped_via_symlink.txt` **outside** `dest`. The command reported `ok: true` with no warning.
- **Impact:** a symlink to `~/.ssh` or `/etc` (as root) allows arbitrary file writes. `../` entries were correctly rejected.

**C2 — Critical. Plugin install can delete and overwrite any directory via a registry-supplied version string.** [CODE]

- **Root cause:**
  - Version keys from the registry or catalog JSON are not validated (`pluginh/plugin/registry.rs:213-233`).
  - `plugin_version_dir` joins the version into a path (`store.rs:48-50`).
  - `install_plugin` runs `fs::remove_dir_all(version_dir)` and then copies the plugin contents there (`store.rs:126-138`).
- **Impact:** a version such as `../../../../.ssh` deletes and replaces a directory outside the plugin store.
- **Context:** `beafdc3` made plugin install functional, so this is now reachable.

**C3 — Critical. `proc` PID wrap-around signals every process.** [PARSE + CODE]

- **Root cause:** the PID is parsed as `u32` and cast to `libc::pid_t` (`proch.rs:392-410`), then passed to `libc::kill` (`:868`).
- **Parser output (via the library parser):**
  - `proc://4294967295.kill` → target host `4294967295` → `pid_t = -1` → `kill(-1, SIGKILL)`, which kills every process the user can signal.
  - Values ≥ 2^31 become negative, i.e. process-group kills.
- **Not executed live,** for obvious reasons.

**H1 — High. Shell injection in `pkg`, including in dry run.** [CODE]

- **Root cause:**
  - Package names, versions and `extra_args` are concatenated into `sh -c` strings (`pkgh.rs:1750-1762, 1801-1817, 1876-1881, 2201, 3079, 3319`).
  - The only name check is "non-empty" (`:1457-1468`).
- **Dry run is not safe:** `dry_run_install`/`dry_run_remove` still call `is_package_installed`, which runs `sh -c "dpkg -s <name>"`.
- **Impact:** a name such as `jq;cmd` executes `cmd`, typically as root. Package lists often come from lockfiles or generated input.

**H2 — High. `dry_run` and other safety booleans are silently ignored unless spelled exactly `true`.** [CODE]

- **Root cause:**
  - 33 sites use `dry_run.parse::<bool>().unwrap_or(false)` or `== "true"`: user (`userh.rs:2975, 3059, 3136, 3199, 3248`), cron, firewall, ssh, plugin, snapshot, file `replace`.
  - Other handles accept `1`/`yes` through `core::lenient`.
  - Separately, `dispatch_stage` silently drops any CLI word without `=` (`core/mod.rs:25-29`).
- **Impact:** `user://bob.delete dry_run=1`, `dry_run=yes`, `dry_run=True` or a bare `dry_run` **performs the real deletion**.

**H3 — High. Firewall `enable`/`disable` report a backup that is never written, then apply changes.** [CODE]

- **Root cause:** with `backup_before_apply=true` (the default), only a path string is produced. The code comment says "In a real implementation, we would call the rules.save function here" (`firewallh.rs:8536-8544`, also `:7896-7904, 8047-8053, 8666`).
- **Impact:** `disable` then flushes rules and sets policies to ACCEPT, and the operator is told a restore point exists when it does not.
- **Exit codes:** `handle_enable`/`handle_disable` return `Status::ok()` even when the response has `ok:false` (`:7369-7378`, `:8099-8108`).

**H13 — High. Plugin artifact verification is ineffective.** [CODE]

- **Root cause:**
  - `verify=sha256` is the default (`pluginh.rs:1193-1196`).
  - URL and file sources carry `sha256: None` (`registry.rs:122, 162`), and `verify_artifact` passes with "No checksum to verify" (`engine.rs:599-627`).
- **Supporting factors:**
  - There is no signature; registry checksums come from the same origin as the artifact.
  - `http://` registries are accepted.
  - `copy_directory` follows symlinks (`store.rs:400-414`), so a crafted tarball can copy a private key into the plugin directory with mode 0755.

**H14 — High. SMTP passwords are stored as base64.** [CODE]

- The value is base64-encoded, not encrypted (`mailh.rs:398-403, 1959-1960`).
- It is written to `smtp_profiles.json` with plain `fs::write`, so the file gets umask permissions, typically 0644 (`:817-843`).

### Potential risks

| Severity | Risk |
|---|---|
| Medium | **Mail argument rewriting:** `reconstruct_mail_command` (`main.rs:76-80`) wraps values in `"..."` without escaping. A subject such as `x",bcc=["a@evil"],z="` can add recipients [CODE]. CRLF header injection is blocked by lettre's typed builders. |
| Medium | **cron:** newlines in `description`/`id`/`command`/`env` are written into crontab lines and systemd units, which allows extra jobs or `ExecStartPre=` lines. `unit_name` is joined into a path unvalidated (`cronh.rs:3054-3082, 3200-3240, 3336`). `%` is not escaped. |
| Medium | **ssh exec:** `command_args` are quoted only if they contain a space or quote, so `;`, `$()` and `|` reach the remote shell (`sshh.rs:4940-4957`). |
| Medium | **backup:** `src`, `exclude`, `snapshot_id` and `dest` are passed to tar/rsync/restic/borg with no `--` (`backuph.rs:669-750`). `src=--checkpoint-action=exec=...` reaches tar. |
| Medium | **user add:** `primary_group` is not validated and is passed to `groupadd`/`useradd -g`, so a value starting with `-` is read as an option (`userh.rs:3487-3511, 1754-1777`). |
| Medium | **firewall enable (iptables):** `sh -c "<restore> < {path}"` with the user's `path` unquoted (`firewallh.rs:7916-7918`). |
| Medium | **Predictable `/tmp` paths written by root-oriented handles:** firewall reload/backup `/tmp/.resh-backup-*-<secs>.rules` (`firewallh.rs:6611-6693`; reload temp is written even in dry run). Backup default repositories `/tmp/resh_backup_<repo>`, `/tmp/rsync_backup`, `/tmp/borg_repo` are created with default permissions and accepted if pre-created by another user. `prune` then deletes inside them (`backuph.rs:541-542, 1249, 1574, 1934`). |
| Medium | **file write/replace/copy:** predictable temp files in the target directory, opened with `File::create` (no `O_EXCL`, follows symlinks) (`fileh.rs:3432-3473, 1815, 4445-4460`). |
| Medium | **Secrets on the command line:** `password=`, `token=`, `smtp_password=`, secret `value=` and `dsn=` appear in the process argument list (`ps`, shell history). Only backup (`password_file=`) and secret (`from_env=`) offer alternatives. |
| Medium | **cert:** private keys are written and then chmod'd 0600 (`certh.rs:2281-2293, 2800-2810`). Chmod errors are ignored at `:6165-6178`. |
| Medium | **pkg restore:** lockfile package names go to argv unvalidated. Local paths, URLs and leading-dash names are possible (`pkgh.rs:7494-7560`). |
| Low | **mail TLS:** `tls_accept_invalid_certs` turns STARTTLS into opportunistic mode, which permits plaintext fallback with credentials (`mailh.rs:2943-2953`). |
| Low | `config://../x` may escape the config directory by one level (`config.rs:234, 441`) [UNVERIFIED]. |
| Low | svc on OpenRC: an unvalidated name reaches the log path, so `svc://../x.logs` reads `/var/log/../x/current` (`svch.rs:890-892`). |
| Low | `db` `redact_dsn` misses `?password=` and key=value DSNs (`dbh.rs:4850-4858`). `secret get` prints plaintext unless `redact=true`. |

### Read-only verbs and dry-run

- **Read-only verbs:** none were found that start daemons or change system state.
- **Read-only verbs with filesystem side effects** [CODE]: `config get` and `watch` create directories. So do `mq len`/`peek`, mail config reads, the plugin catalog cache and `installed.list`. A `plugin` `dry_run` install still creates the plugins directory.
- **Dry-run checks that are correctly ordered before mutation** [CODE]: git sync, backup create/prune, cron, fs mount/resize, plugin engine, snapshot restore, archive remove. `backup create dry_run=true` was confirmed to create nothing [LIVE].
- **Verbs with no dry-run at all:** svc, proc signals, file write/rename/chmod, mq purge, and cache/db writes.

### Unverified security assumptions

- **No live mutations were performed.** That covers the user/firewall/svc/pkg/cron/fs mount and resize changes, real SSH, real SMTP, real package managers, and real plugin registries. Their safety rests on code reading and on unit tests of generated command lines.
- **Root execution was not tested.** Many risks above are worse as root.
- **System-user unlock protection** is not covered by any passing test.
- **Tera templates:** the built-in `get_env` function may expose environment variables to templates [UNVERIFIED].
- Hard-link entries in tar extraction may also escape the destination [UNVERIFIED].

## Functional Findings

### Command processing path (steps 1-12)

| Step | Finding |
|---|---|
| 1. Arg parsing | `resh` with no stage **panics** with `expect("No stage provided")` and exits 101 [LIVE] (`main.rs:165`). **Low.** |
| 2-3. Handle and verb resolution | Unknown scheme → `Error: Unknown scheme` (exit 1); unparseable stage → `Error: Cannot parse stage` (exit 1) [LIVE]. |
| | The global dotted-verb list (`parse.rs:50`) contains generic words (`config`, `test`, `update`, `install`, `config.get`…). Targets ending in them mis-split: `http://h/app.config.get`, `cert://./site.chain.info`, `cache://redis/app.config.get`. **Low.** |
| | URL userinfo: `svc://getty@tty1.stop` → service `tty1` [PARSE] (**H9**, High: acts on the wrong unit). `plugin://aws@1.2.0.remove` → plugin id `1.2.0`. |
| | Values containing `(` break `rfind('(')` parsing. Unquoted commas in the `(...)` form split values (`ports=22,80`, `groups=a,b`); the trailing `key=value` form works. **Medium.** |
| | Single-character help alias verbs (`h`) are unreachable. Harmless. |
| 4. Argument validation | Inconsistent across handles: strict typed parsing in fs/git/db/system (`core::lenient`); silent defaults elsewhere (archive limits, cache `ttl_ms`, svc `wait state=`, log `lines=abc` → 100, `allow_symlinks=no` stays `true`). Unknown option keys are silently ignored almost everywhere. **Medium.** |
| 5-6. Resource and provider resolution | Service-manager detection prefers systemd whenever `systemctl` is on `PATH` (`svch.rs:277`). OpenRC was correctly detected on this host [LIVE]. |
| 7. Authorization | None centrally; see Security Findings. |
| 8. Execution | Timeouts are ineffective in backup (mutex/`take()` before wait, `backuph.rs:1349-1375`), firewall (`tokio::time::timeout` around blocking `Command::output`, `firewallh.rs:8721-8743`) and git (blocking libgit2 with no yield points). **High** for backup, because a hung backend hangs resh forever. |
| 9-10. Result processing and output | git (25 sites), user, cache and event hooks write with `println!`, bypassing `IoStreams`. `--json-pretty` therefore has no effect on them, and event-hook text corrupts JSON on stdout. **High** for event, **Medium** otherwise. |
| 11. Error handling | **`main.rs` never prints `Status.reason`.** Handles returning `Ok(Status::err(..))` without writing a message fail silently (**H5**, High), confirmed [LIVE] for `dns://.lookup`, `fs://x.mount`, `fs://x.bogus` (exit 95), `file://<missing>.stat` (exit 2) and `file://x.grep` with no pattern (exit 2). The same pattern exists in config, http, template (unknown verb), event (unknown verb), mq and many file verbs [CODE]. |
| 12. Exit codes | Failures exit 0 (**H6**, High): cron (all failures), firewall enable/disable, ssh exec (connection failure or remote non-zero), pkg partial failures, db ping, user `exists` for a missing user, and `svc status` for a nonexistent service [LIVE: `"state":"stopped_or_unknown"`, exit 0]. http exits with the HTTP status mod 256. Signal-killed backup backends exit 255. |

### Other confirmed functional defects

| Severity | Finding |
|---|---|
| High | **H16.** `file://` rejects relative **directories**: `file://./sub.find` → `Error: "sub" is a directory` [LIVE], while absolute paths work. This also affects delete/move/rename/chmod/chown/ea/tag on relative directories (`fileh.rs:960-978`). It contradicts known_issues H8 "fixed". |
| High | **H8.** `archive create password=…` produces an **unencrypted** zip and reports `ok: true` [LIVE: encryption flag 0, plaintext readable]. |
| High | **H10.** `cron enable` treats any `#` comment line of ≥ 6 words as a disabled job and uncomments it into the crontab (`cronh.rs:3904-3929`). systemd timer discovery reads the NEXT column instead of UNIT, so rm/enable/disable never match timers (`cronh.rs:3480-3482, 2319-2321`). |
| High | **H11.** `git sync` with the default `pull_strategy=rebase` (or merge) calls placeholder functions that report "rebased"/"merged" (`gith.rs:7534-7556`), then pushes by default. |
| High | **H7.** `backup://<profile>` puts the profile in the URL host, but `from_url` reads only the path (`backuph.rs:1231`), so every documented profile becomes `default` and profiles share repositories. |
| High | **H15.** `snapshot diff from=<name>` looks up by UUID, so the help's own example `from=backup-v1` always fails (`snapshot.rs:593, 679`). |
| High | **H4.** **A fresh clone cannot resolve dependencies:** `Cargo.lock` is gitignored (`.gitignore:5`), and every `zip 0.6.x` release is yanked. Resolving without the local lockfile fails with "failed to select a version for the requirement `zip = "^0.6"`" [LIVE, in a scratch crate]. |
| High | **H12.** Event built-in hooks print to real stdout and corrupt JSON (`eventh.rs:108-195`). Known open issue. |
| Medium | **cache:** numeric CLI values become JSON numbers and are then read with `as_str()`, so `cursor=` never advances SCAN, `key=42` is rejected and `namespace=2024` is dropped. memcached `exists`/`ttl` report true for missing keys, and `incr` overwrites on any error. |
| Medium | **pkg:** `restore` ignores locked versions and compares versions as strings. `only_if_missing` defaults to true and conflicts with `upgrade`/`reinstall` without explanation. |
| Medium | **file:** `rename overwrite=true` deletes the destination (recursively for directories) before renaming (`fileh.rs:3584-3592`). `find include_hidden=false` descends into hidden directories. `preview`/`schema` allocate `max_bytes` unbounded. |
| Medium | **archive:** tar `add` rebuilds existing entries with `Header::new_gnu()`, losing mode, mtime, owner and type. `.gz`/`.xz`/`.zst` output names fail on create without `format=`. Raw decompression checks size limits only after writing. |
| Medium | **fs:** `resize delta=-<size>` can never succeed (`fsh.rs:5470-5513`). `quota`/`quota_summary all_subjects=true` are stubs. |
| Medium | **proc:** `limits.set` calls `setrlimit` on resh itself and ignores `pid`. `io.peek` reads log files nothing writes. Overflow panics in debug builds on extreme `delta` or limit suffixes. |
| Medium | **net:** `ping` counts ICMP error lines as replies (`neth.rs:954`). |
| Medium | **mq:** temp file `tmp-*.msg` matches the message filter, so `len`/`get`/`peek` race with `put`. |
| Medium | **system:** `info` options `max_process_classes`, `include_raw` and `include_paths` have no effect. `disk` panics on non-ASCII `/dev/sd*` names (`systemh.rs:2747`). `sample_duration_ms` is unbounded. |
| Medium | **cron:** weekday numbering is off by one against the `cron` crate (Sunday=1). `allow_duplicate` defaults to true. The `OnCalendar` translation is wrong for `@weekly`, `* * * * *` (every second) and ranges. |
| Low | **user:** `create_home` and `password_hash` are parsed but unused. Invalid `uid`/`gid` are silently auto-assigned. `delete` reports `was_present: true` for home and mail spool without checking (`userh.rs:3825-3842`); real deletion uses `userdel -r`. |
| Low | `file write` with no `data=` reads stdin to EOF. With empty stdin (cron or CI) it atomically truncates the file to 0 bytes [LIVE]. This is documented behaviour but easy to trigger by mistake. |
| Low | Error output channel is inconsistent: db, cache, cert, proc and system write JSON errors to stdout, while file, user, cron and others write to stderr. Shell pipelines receive error JSON as data. |
| Low | `archive` extract manifest reports the original absolute path for rebased entries [LIVE]. `allow_absolute_paths=true` rejects instead of allowing [TEST]. |

### Incomplete implementation scan

- **Markers:** `TODO` 6, `FIXME` 0, `todo!` 0, `#[ignore]` 0.
- **`unimplemented!`:** 28 sites, all in `systemh.rs` test mocks, so no impact.
- **User-reachable stubs advertised as verbs or options:**
  - firewall backup-before-apply
  - git `sync` rebase/merge, and `pull` on diverged branches
  - git `clone recursive`
  - ssh `tunnel`/`keys.list`/`key.add` without `dry_run`
  - secret `rotate`
  - fs quota `all_subjects`
  - archive create for 7z/xz/zst and 7z read operations
  - cert encrypted keys and CMS
  - dns `zone.update` (simulated) and TSIG
  - backup `schedule` (reports only)
  - event `list-topics` (sample data)
  - `copy preserve_times`
  - `rename atomic=`
- **Disclosure in help:** most of these are disclosed in the built-in help. Firewall backup, git `sync` rebase/merge, zip password and the archive `preserve_*` options are **not** disclosed.
- **Dead code:** `src/handles/automation/backup/{policy,tools,fs_snapshots}.rs` and `src/handles/filesystem/fs_atomic.rs` are compiled but unreferenced. `tmp-sample-plugin/` is tracked at the repository root and looks like scratch material.

## Documentation Findings

- **Built-in help is accurate.** It was written against the code and is honest about stubs (example parse rate 238/239).
- **The prose documentation under `docs/` is not.** Every handle document checked contains contradictions.

**Representative examples, by document:**

| Document | Discrepancy (severity) |
|---|---|
| `docs/*/overview.md` (all categories) | Examples use nonexistent verbs, for example:<br>• `proc://1234.status`, `proc://….renice`<br>• `fs:///.disk`<br>• `net://eth0.status()`<br>• `event://user.created.publish`, `mq://jobs.enqueue`<br>• `backup://….cleanup()`<br>• `firewall://.add` / `.list`, `secret://….list`<br><br>They use wrong argument names, for example:<br>• `dest=`, `content=`, `label=`, `src=`<br>• `cmd=` instead of `command=`, `type=` instead of `rtype=`, `device=`<br><br>They show response envelopes (`op`, `status`, `resource`, `handle`) that no handle emits. (High) |
| `archive.md` | Every CLI example uses `archive://create …` without the dot, so none parse. It claims tar.xz/tar.zst/7z creation and default size limits. (High) |
| `event.md`, `dns.md` | Examples use `event://emit` / `dns:// lookup`, which cannot parse. The required forms are `event://.emit` and `dns://.lookup`. (High) |
| `secret.md`, `Security_Secrets/overview.md` | Claim encryption at rest (the store is plaintext JSON), a working `rotate`, and an `expose_value` argument that doesn't exist. Claim macOS/Windows support, but `dirs::state_dir()` is `None` there. (High) |
| `ssh.md` | Presents tunnels and key management as working. Spells `accept_new` where the code takes `accept-new`, so the value silently falls back to strict. (High) |
| `cert.md` | Claims password-encrypted keys; `key_passphrase` is rejected. Its CSR signing example parses as `sign` with the wrong arguments. (High) |
| `svc.md` | Documents `instances=` where the code reads `count=`. Treats timeouts as seconds where the code uses milliseconds. Uses `@` instance names that are mis-parsed. Lists a "generic init" backend that doesn't exist. Invents exit codes. (High) |
| `proc.md` | Presents `limits.set` and `io.peek` as working. Gives macOS SIGUSR numbers. Exit codes are wrong. (High) |
| `pkg.md` | Most examples omit the required `manager` key. Promises an exact-version restore and rollback the code doesn't do. Claims exit codes reflect failure. (High) |
| `git.md` | Presents `sync pull_strategy=rebase` as working. The overview examples omit the required `path`. Claims the git binary and credential helpers are used (the code uses libgit2 and has neither). (High) |
| `backup.md` | Presents `schedule` as installing schedules and timeouts as enforced. Shows `op`/`status` envelopes. Examples need `repo_url` and a password. (High) |
| `cache.md`, `db.md` | Examples assume connections and transactions persist across separate `resh` invocations; they don't. (High) |
| `cron.md`, `firewall.md`, `user.md`, `file.md`, `snapshot.md` | Exit-code tables 2-7 don't match the code (mostly 1 or 0). `file.md` gives `max_count` (the argument is `max`) and claims absolute paths are required. `snapshot.md` diff and ls examples fail (H15, relative ls). (Medium) |
| `system.md` | Documents option names that are silently ignored: `name_filter`, `mask_sensitive`, `max_variables`, `include_swap`. (Medium) |
| Platform claims (multiple overviews) | macOS and Windows "supported" or "limited". Reasons this does not hold [CODE]:<br>• `fileh.rs`, `fsh.rs` and `fs_atomic.rs` import Unix-only modules ungated.<br>• `nix` is an unconditional dependency.<br>• `proch.rs` uses Linux-only `__errno_location` under `cfg(unix)`.<br>• `fsh.rs:2051` likely does not compile off Linux [UNVERIFIED]. |
| `README.md` | Version (`v1.0.2-beta`) and handle count (28) are correct. "28 handles production-ready" (`README.md:205`) is not supported by this review. |
| `CHANGELOG.md` | `[1.0.2-beta]` entry present. "Invalid typed option values are errors instead of silently using defaults" applies only to fs/git/db/system. "Events persist across invocations" holds only where `state_dir` exists, i.e. Linux. (Low) |
| `docs/known_issues.md` | The status header and "Still open" list are accurate for the items they cover: backup timeouts, event hooks, cache numeric keys, the 15 failing tests. Not listed there: C1-C3, H1-H4, H7-H11, H13-H16, and most Medium items above. The body sections L1-L5 still describe issues the status table marks as fixed. (Low) |

## Severity Classification

| ID | Severity | Summary | Evidence |
|---|---|---|---|
| C1 | **Critical** | Archive extraction symlink escape | LIVE, CODE |
| C2 | **Critical** | Plugin version path traversal leads to `remove_dir_all`/overwrite | CODE |
| C3 | **Critical** | `proc` PID wrap gives `kill(-1)` | PARSE, CODE |
| H1 | High | `pkg` shell injection, including in dry run | CODE |
| H2 | High | `dry_run=1`/`yes`/bare `dry_run` performs real mutations | CODE |
| H3 | High | Firewall reports backups never written; enable/disable exit 0 on failure | CODE |
| H4 | High | Fresh clone cannot resolve dependencies (lockfile ignored, `zip 0.6` yanked) | LIVE |
| H5 | High | Silent failures: `Status.reason` never printed | LIVE, CODE |
| H6 | High | Failures reported with exit 0 (cron, firewall, ssh exec, pkg, svc status, db ping) | LIVE, CODE |
| H7 | High | backup timeout never fires; profiles ignored; `/tmp` default repositories | CODE |
| H8 | High | Zip `password` ignored; output is plaintext | LIVE |
| H9 | High | `svc` `@` instance units target the wrong service | PARSE |
| H10 | High | cron `enable` corrupts crontab with comments; systemd timers never matched | CODE |
| H11 | High | git `sync` reports placeholder rebase/merge as success, then pushes | CODE |
| H12 | High | Event hooks corrupt JSON stdout | CODE (known) |
| H13 | High | Plugin checksum verification passes without a checksum | CODE |
| H14 | High | SMTP password stored base64 in a world-readable-by-umask file | CODE |
| H15 | High | `snapshot diff` by name always fails | CODE |
| H16 | High | `file://` relative directories rejected | LIVE |
| M | Medium | Every item marked Medium in Security, Functional and Documentation Findings | various |
| L | Low | Every item marked Low; plus `cargo fmt` failure, 541 compiler warnings, no-stage panic, help-word constructor `exit(0)`, clap fallback for unknown help targets | various |

**Quality gates:** `cargo fmt --check` and `cargo clippy -D warnings` failing would be Medium if they are intended release gates. The 15 failing unit tests are Medium, because they leave user-protection logic unverified.

## Final Recommendation

**NOT READY**

**Why:**

- Three confirmed **Critical** defects (C1-C3) and sixteen **High** defects remain.
- They are in code paths the CLI advertises and the help documents.
- Several fall squarely in the security checklist:
  - unintended execution during dry run (H1, H2)
  - path traversal (C1, C2)
  - unsafe argument handling (C3, H1)
  - mutating operations that misreport their safety measures (H3)
- Separately, the CLI's failure signalling is unreliable. Silent failures (H5) and false successes (H6) mean automation built on resh cannot trust exit codes, which undermines its stated purpose as an automation platform.

**What is sound and verified:**

- Handle registration and verb dispatch.
- The help system end to end.
- Rejection of unknown schemes and verbs.
- The read-only paths exercised live: file read/stat/hash, system info, cron list, svc status, cache provider errors.
- The `backup create` dry run.

**What these conclusions rest on (passing tests do not prove correctness):**

- Every mutating verb against a real system was verified only by code inspection and by unit tests of generated commands.
- Non-Linux platforms, systemd hosts (this host runs OpenRC), root execution, and external services (databases, Redis, SMTP, SSH, plugin registries) were not exercised.

### Recommended corrective actions

For the project owner to decide on; none were implemented.

1. **Archive extraction (C1):** default `allow_symlinks=false`. Validate symlink and hard-link targets against the destination, or extract with `Archive::unpack_in`/`Entry::unpack_in`. Fix the inverted `allow_absolute_paths`.
2. **Plugin store (C2):** validate plugin ids and versions as single safe path components before any join. Require a checksum, or a signature, for every source.
3. **proc (C3):** reject PIDs above `i32::MAX` (parse as `i32` > 0).
4. **pkg (H1):** replace every `sh -c` string with argv-based `Command`, insert `--` before package names, and validate names.
5. **Booleans (H2):** route every boolean, `dry_run` above all, through one shared lenient parser that rejects unrecognised values. Reject CLI words without `=` instead of dropping them.
6. **Firewall (H3):** call `rules.save` for backups, or stop reporting them, and propagate `response.ok` into the exit status.
7. **Error and exit-code contract (H5, H6):** in `main.rs`, print `Status.reason` to stderr when a handle wrote nothing. Audit the `Ok(json ok:false)` → `Status::ok()` paths.
8. **Build (H4):** track `Cargo.lock` for this binary crate and plan a move off the yanked `zip 0.6`. A dependency change is outside this review's scope.
9. Address the remaining High items, H7-H16.
10. **Docs and quality gates:** bring `docs/*.md` in line with the built-in help, or replace them with it. Decide whether `cargo fmt` and `clippy` are release gates. Fix or retire the 15 broken tests, especially the user unlock-protection tests.

*No corrective action has been taken. The decision on further work rests with the project owner.*
