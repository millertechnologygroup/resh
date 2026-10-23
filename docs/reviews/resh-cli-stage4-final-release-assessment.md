# Resource Shell (resh) — Stage 4: Release Candidate Preparation and Final Verification

- **Date:** 2026-10-23
- **Tree reviewed:** commit `277f996300089269640dc5a962d01942aa871ccc` (branch `help-system-and-fixes`), with the uncommitted Stage 1-4 changes.
- **State:** Nothing was committed, pushed, tagged or published. Stage 5 has not been started.
- **Companion reports:** `resh-cli-documentation-audit.md` (RC-03), `resh-cli-lint-baseline.md` (RC-04).

## Executive Summary

**Recommendation: CONDITIONALLY READY.** See the [Final Recommendation](#final-recommendation).

**Builds and tests are green and reproducible.**

- Clean locked builds succeed from an empty Cargo home on Rust **1.88.0** (the declared MSRV) and on **1.98.1**. `Cargo.lock` is byte-identical afterwards.
- The default suite passes on both toolchains: **1,181 lib and 1,185 bin unit tests, 0 failures.** The help, documentation-example and CLI-regression suites also pass.
- The **11 infrastructure tests** pass against disposable PostgreSQL 16.10, MariaDB 11.4.8 and a local bare git remote. They were checked for vacuous skips.

**TLS dependency advisories are closed.**

- Lockfile-only patch updates: rustls 0.23.46, rustls-webpki 0.103.16, webpki-roots 1.0.10, bytes 1.11.1, h2 0.4.16.
- `cargo audit` against the RustSec database of 2026-10-23 now exits 0.
- Every remaining advisory was assessed for reachability. Each is recorded, with its reason, in `.cargo/audit.toml`, which CI enforces.
- **Correction to Stage 3:**
  - The `http` handle and the plugin registry verify TLS with the **system OpenSSL** (reqwest's default `native-tls` backend), not rustls.
  - rustls secures the sqlx database connections only.
  - Certificate rejection was verified live on the patched build: self-signed, expired, wrong-host and untrusted-root certificates are all refused.

**Stage 4 found and fixed defects in two rounds.** Every fix is narrow and has a regression test, and 14 of those tests were mutation-checked: each fails when its fix is reverted.

*Found while verifying (RC-02 to RC-08):*

- **Unsafe execution, where the flag was silently not honored:**
  - `pkg update/upgrade security_only=true` silently ran a **full** upgrade on apt, pacman, apk and brew (and yum for `upgrade`). It is now refused where the manager's command cannot filter to security fixes.
  - `backup restore dry_run=true` performed a **real restore**. `backup create/prune` treated a malformed `dry_run` as false and **ran for real**.
  - `mail send dry_run` **sent the message**.
  - `fs mount/unmount` treated a malformed `dry_run` as false.
- **Data loss:**
  - ext3/ext4 `fs resize` asked `resize2fs` for **a quarter** of the requested size.
  - `file rename to=<bare name> overwrite=true` **deleted the destination** and then failed.
  - `archive add/remove` on `.tar.zst` **truncated** the archive.
- **Local exposure:**
  - SMTP profiles, which hold base64 passwords, were written with the umask (typically world-readable). They are now 0600.
  - `firewall rules.reload` wrote rules to a **predictable `/tmp` path**, a symlink-clobber vector as root.
- **Robustness:** `resh` with no arguments panicked.

*Found by the independent RC-09 review (each confirmed by reproduction, then re-verified by the reviewer after the fix):*

- **General dry-run bypass (High).** On any verb without a dry-run mode, `dry_run=true` was silently ignored and the **real change ran** with exit 0. Examples:
  - `file delete dry_run=true` deleted the file; svc, proc, file writes, db, cache, mq and others behaved the same.
  - Misspelled forms (`dry-run`, `dryrun`, `DRY_RUN=true`) were dropped.
  - A top-level `dry_run=true` was ignored by `pkg`, which reads it only from `input=`.

  The dispatcher now refuses all of these before the handle runs. It fails closed: a verb gets a dry run only if its help usage lists `dry_run`.
- **`archive add` destroyed existing entries' metadata (High).**
  - Tar: mode 0, owner 0, mtime 0, and symlinks became empty files.
  - ZIP: modes and times were reset.
  - Errors while finishing a compressed stream were swallowed.
- **Predictable temp files (Medium).** Archive rewrite, file `copy`, `write` and `replace` used guessable temp names opened with `File::create`, which follows symlinks. Rewritten archives also lost their permissions.
- **Smaller fixes:** `fs resize` passed the device path through `sh -c`, and `rename overwrite=true` deleted a destination file that `rename(2)` would have replaced atomically.

**Documentation now describes the CLI that exists.**

- All 38 docs pages, README and CONTRIBUTING were corrected against the code.
- 609 documented examples are machine-checked and **all parse to registered verbs**, down from 145 failures.
- Unsupported and stub behavior is stated plainly.

**CI is configured but has not run.** `.gitlab-ci.yml` defines:

- **Gates:** locked MSRV build, tests on 1.88.0 and 1.98.1, a named security-regression job, fmt, and `cargo audit`.
- **Advisory:** Clippy.
- **Manual:** the infrastructure-test job.

It was validated locally; no GitLab runner was used. The local `origin` remote is GitHub, so the CI platform needs an owner decision.

**Lint debt is documented and does not block.**

- **rustfmt:** a separate, verified formatting-only patch is ready to apply as its own commit.
- **Clippy:** 1,790 pre-existing sites (5 deny-level, in tests and display code). None is a security finding, and Stage 4 adds none.

**What still keeps this from "Ready":**

- verification gaps: systemd hosts, brew, root on a real host, non-x86_64, macOS;
- the CI platform choice and a first real pipeline run;
- the formatting commit;
- owner sign-off on several documented compatibility changes and residual Medium risks (listed below).

No known exploitable Critical or High defect remains open in supported use.

## Repository Baseline

| Item | Value |
|---|---|
| Branch / commit | `help-system-and-fixes` @ `277f996` ("Bump version to 1.0.2-beta"). Main branch: `main`. |
| Tags | `v1.0.0-beta`, `v1.0.1-beta`. **`v1.0.2-beta` does not exist yet**, but the README references it. |
| Remote | `origin` = `https://github.com/millertechnologygroup/resh.git` |
| Crate | One package, `resh 1.0.2-beta`, edition 2024, `rust-version = "1.88"`. lib and bin targets. Not a workspace. |
| Toolchains | rustc/cargo **1.98.1** (Gentoo system, no rustup). Rust **1.88.0**: the official standalone toolchain installed under a Stage 3 scratch directory (sha256-verified then), used read-only. |
| MSRV | 1.88 is confirmed as the floor of the locked dependency graph: `home` 0.5.12, `ignore` 0.4.32 and `time` declare 1.88. Edition 2024 alone needs 1.85. Verified by building and testing on 1.88.0. README and CONTRIBUTING both say "Rust 1.88 or later". |
| Lockfile | `Cargo.lock` is no longer ignored (`.gitignore` explains why). It is untracked and must be added to the release commit. |
| Release scripts | None in the repository. `.gitignore` ignores `build-release.sh`, `/scripts`, `/releases` and `/examples`; none of those paths exist locally. |
| CI before Stage 4 | None: no `.gitlab-ci.yml` and no `.github/`. |
| Tests at start of Stage 4 | `cargo test --locked`: lib 1171 passed / 0 failed / 11 ignored; bin 1175 / 0 / 11; help_cli 16; help_coverage 2. This matches the Stage 3 report exactly. |
| `.claude/` | Untracked `settings.json`; `settings.local.json` is ignored. **Not touched, not part of the release.** |

### Baseline file inventory, by stage

The attribution below comes from the Stage 1-3 reports and today's changes. Every Stage 1-3 file is still modified, and Stage 4 added to several of them.

| Stage | Files |
|---|---|
| Stage 1 (security) | `src/core/{lenient,mod,parse}.rs`, `src/main.rs`; `src/handles/` `filesystem/{archiveh,fileh,snapshot}.rs`, `pluginh/plugin/{store,engine}.rs`, `processes/{proch,cronh}.rs`, `system/pkgh.rs`, `security/{userh,firewallh}.rs`, `network/{sshh,mailh,dnsh}.rs`, `automation/pluginh.rs`; `docs/Filesystem_Storage/archive.md` |
| Stage 2 (functional) | `src/core/status.rs`, `src/main.rs`; `cronh`, `firewallh`, `sshh`, `pkgh`, `svch`, `dbh`, `gith`, `archiveh`, `backuph`, `fileh`, `snapshot`, `eventh`; `docs/Security_Secrets/firewall.md`, `docs/Packages_Software/git.md`, `docs/known_issues.md`; `tests/help_cli.rs` |
| Stage 3 (build/test/security) | `.gitignore`, `Cargo.toml` (`rust-version`), `Cargo.lock` (new; `tar` 0.4.45), `README.md`, `CONTRIBUTING.md`; `userh`, `gith`, `engine`, `store`, `registry.rs`, `pluginh`, `archiveh`, `fileh`, `snapshot`, `certh`, `httph`, `firewallh`, `backuph`, `pkgh`, `dbh`; docs `git.md`, `plugin.md`, `known_issues.md`; `docs/reviews/` (Stage 1-3 reports) |
| Stage 4 (this stage) | See [Stage 4 Change Summary](#stage-4-change-summary). |
| Unrelated / user-owned | `.claude/` (excluded). `tmp-sample-plugin/` is tracked at the repository root, looks like scratch material, and is unchanged. Whether to keep it is the owner's call. |

## Stage 4 Change Summary

### New files

| File | Why |
|---|---|
| `.gitlab-ci.yml` | RC-05: minimal GitLab CI (see [CI Readiness](#ci-readiness)). |
| `.cargo/audit.toml` | RC-02: the `cargo audit` ignore list. Each ignored advisory is listed with its reachability assessment, so any *new* advisory fails CI. |
| `tests/doc_examples.rs` | RC-03: the documentation example validator. It parses every `resh` example in the docs against the real parser and registry, and executes nothing. |
| `tests/stage4_regressions.rs` | RC-06/07: CLI-level regression tests (11) that run the real binary in a temporary working directory with redirected HOME/XDG paths. |
| `docs/reviews/resh-cli-documentation-audit.md` | RC-03 deliverable |
| `docs/reviews/resh-cli-lint-baseline.md` | RC-04 deliverable |
| `docs/reviews/resh-cli-stage4-final-release-assessment.md` | This report |

### Modified: dependencies

| File | Change |
|---|---|
| `Cargo.lock` | Only the `version`/`checksum` lines of rustls, rustls-webpki, webpki-roots, bytes and h2, plus the 4 dependency-edge strings that name the old versions. See [Dependency Security](#dependency-security). |

### Modified: source (defects found during Stage 4 verification)

| File | Change | Test |
|---|---|---|
| `src/handles/system/pkgh.rs` | `security_only` is refused unless the manager's command really filters to security fixes (dnf/yum for `update`, dnf for `upgrade`). It is checked before manager detection for an explicit manager, and after detection for `auto`. Two help usage lines state this. | `cmdline_safety_tests::security_only_is_refused_where_it_cannot_be_honored` (mutation-checked); CLI test |
| `src/handles/automation/backuph.rs` | `create`/`prune` read `dry_run` with the shared strict parser. `restore` (which has no dry-run mode) refuses `dry_run=true`. | `dry_run_tests` (2, mutation-checked); CLI test |
| `src/handles/network/mailh.rs` | `send` refuses a dry-run request before any SMTP connection, and points to `send_template dry_run=true`. SMTP profiles are written 0600 through `write_private_file` (create_new, O_NOFOLLOW, replaces a stale temp file, refuses symlinks). | `send_dry_run_tests` (mutation-checked), `private_file_tests`; CLI tests (permission test mutation-checked) |
| `src/handles/filesystem/fsh.rs` | `resize2fs_size_arg`: bytes/1024 with a `K` suffix. It was bytes/4096, a quarter of the size; the execution path, the dry-run plan and the help example are all fixed. Mount/unmount `dry_run` uses the strict parser. | `stage4_tests` (2, both mutation-checked) |
| `src/handles/filesystem/fileh.rs` | `dest_parent` maps a bare file name's empty parent to `.`. `rename` checks the parent **before** deleting an existing destination. copy and move use the same helper. Pre-existing nested ifs on the edited lines were collapsed. | CLI tests (rename test mutation-checked) |
| `src/handles/filesystem/archiveh.rs` | The zstd encoder is finished on `add` (`auto_finish`) and on `remove` (explicit `finish`). | `zstd_rewrite_tests` (mutation-checked for both sites) |
| `src/handles/security/firewallh.rs` | Normalized-JSON `rules.reload` uses a securely created temp file (random name, O_EXCL, 0600, removed on drop) instead of `/tmp/.resh-reload-<backend>-<secs>.rules`. | Live sandbox check (below) |
| `src/main.rs` | No stage given: `Error: no stage provided ...` with exit 2, instead of a panic with exit 101. | CLI test |
| `src/core/mod.rs` (RC-09 A1/A2) | New `dry_run_refusal`, called by `dispatch_stage` after the handle is resolved and before it is called. Help requests are skipped. It refuses: a key that is a misspelling of `dry_run`; a malformed `dry_run`; a top-level `dry_run=true` next to `input=` (pkg reads dry_run from the JSON); and `dry_run=true` for a verb whose help usage does not list `dry_run`, failing closed when there is no help entry. Bare CLI words other than `dry_run` are refused instead of dropped. A matrix built from every verb's help, cross-checked against the handles' code, confirmed that every verb that implements a dry run lists it. | `core::tests::dry_run_is_refused_where_the_verb_has_no_dry_run_mode` (mutation-checked), updated `bare_dry_run_cli_word_is_kept`; CLI test (mutation-checked) |
| `src/handles/filesystem/archiveh.rs` (RC-09 A3/A4/A5) | Existing tar entries keep their original header and link target (`fill_tar` with `append_data`/`append_link`). Existing ZIP entries keep their Unix mode, modification time and compression method. Every compressor is finished explicitly and the file synced (add and remove). Temporary archives get an unpredictable name (pid + UUID) and are opened `create_new` + `O_NOFOLLOW` with the original archive's mode. | `zstd_rewrite_tests::add_and_remove_keep_tar_entries_intact` (tar, tar.gz, tar.zst; mutation-checked); `zip_add_metadata_tests` (mutation-checked) |
| `src/handles/filesystem/fsh.rs` (RC-09 A6) | `lvextend`/`lvreduce` run as argv, not through `sh -c`. | Code review (needs LVM to execute) |
| `src/handles/filesystem/fileh.rs` (RC-09 A4/A8) | The temp files of `copy`, `write` and `replace` use UUID names, `create_new` and `O_NOFOLLOW` (`create_new_temp_file`). `rename overwrite=true` removes the destination first only when either side is a directory. | Existing file tests; CLI rename test |

### Modified: CI and documentation

- **`.gitlab-ci.yml` / CONTRIBUTING:** describe the gates.
- **Documentation:** README.md, CONTRIBUTING.md, CHANGELOG.md, and all of `docs/*/` plus `docs/resh_overview.md`, `docs/cli_help_format.md` and `docs/known_issues.md`. Details are in the documentation audit.

The handle and verb registration, the `Handle` trait, the dispatcher, the CLI grammar, the provider architecture and the help format are unchanged. No dependency was added; `tempfile` and `libc` were already dependencies.

## Dependency Security

**Tool:** `cargo-audit` 0.22.2, built from crates.io with `--locked` into the scratch directory. Advisory database: `rustsec/advisory-db` @ `f7b2f6bc` (2026-10-23), a fresh clone.

**Before Stage 4:** 31 vulnerability entries.

- Two are newer than the Stage 3 snapshot, and both are in the TLS trust path:
  - **RUSTSEC-2026-0382**: rustls-webpki accepts distrusted emSign intermediates.
  - **RUSTSEC-2026-0381**: webpki-roots bundles the emSign ECC root.

### Patched (lockfile only, semver-compatible, MSRV ≤ 1.88)

| Crate | From → To | Advisories closed | Reachability |
|---|---|---|---|
| rustls | 0.23.35 → **0.23.46** | RUSTSEC-2026-0285, -0346, -0348, -0349 | sqlx TLS to PostgreSQL/MySQL. (reqwest compiles rustls, but uses native-tls by default; see below.) |
| rustls-webpki | 0.103.8 → **0.103.16** | RUSTSEC-2026-0049, -0098, -0099, -0104, **-0382** | Same |
| webpki-roots | 1.0.4 → **1.0.10** | **RUSTSEC-2026-0381** | Roots for the rustls paths (via the webpki-roots 0.26.11 shim used by sqlx). |
| bytes | 1.11.0 → **1.11.1** | RUSTSEC-2026-0007 | hyper/h2/redis buffers. Peer-influenced sizes are plausible. |
| h2 | 0.4.12 → **0.4.16** | RUSTSEC-2026-0258 | reqwest HTTP/2 to a malicious server (DoS). |

**Method:**

- `cargo update -p … --precise` would also have changed unrelated edges (`socket2` 0.6.1 → 0.5.10 for hyper-util, and the `windows-sys` alternatives).
- So, as in Stage 3, only the five package blocks and the 4 edges naming the old versions were spliced into the lockfile. Their dependency lists are identical between the old and new versions.
- `cargo metadata --locked` accepts the result, and both clean `--locked` builds and test runs succeed.

**After:** `cargo audit` exits 0. 19 entries remain, and every one is assessed and listed in `.cargo/audit.toml`:

| Advisory (crate) | Why it is not applicable / not fixable in scope |
|---|---|
| RUSTSEC-2026-0204 (crossbeam-epoch 0.9.18) | The flaw is in a `fmt::Pointer` impl that resh never invokes. |
| RUSTSEC-2026-0258 (h2 0.3.27) | Dev-dependency mock servers only (hyper 0.14). Not in the release binary. |
| RUSTSEC-2024-0421 (idna 0.4.0, via trust-dns 0.23) | resh makes no trust decision on IDN equivalence. The fix needs the trust-dns → hickory migration. |
| RUSTSEC-2026-0141 (lettre 0.11.19) | boring-tls backend only. resh builds lettre with native-tls. |
| RUSTSEC-2026-0194/-0195 (quick-xml 0.18.1) | Build-dependency of email-address-parser, which parses a fixed grammar at build time. |
| RUSTSEC-2026-0037/-0185/-0338/-0339/-0340/-0342 (quinn-proto) | In `Cargo.lock` only. HTTP/3 is not enabled, so it is not compiled (`cargo tree -e all --target all` has no quinn). |
| RUSTSEC-2025-0009 (ring 0.16.20, via rcgen 0.12 / x509-parser 0.15) | A panic in AES with overflow checks on. resh does not use ring 0.16 AES, and release builds have no overflow checks. |
| RUSTSEC-2023-0071 (rsa 0.9.9, Marvin) | No fix exists. resh generates keys and signs; it exposes no RSA decryption oracle. sqlx-mysql only encrypts to the server key. |
| RUSTSEC-2026-0245 (sevenz-rust 0.5.4) | **Resolved after owner approval:** the unused dependency was removed from `Cargo.toml`. Only `sevenz-rust`, `lzma-rust`, `nt-time` and `filetime_creation` left the lockfile (618 crates); nothing was added or upgraded. The advisory and its `.cargo/audit.toml` entry are gone. |
| RUSTSEC-2026-0009 (time 0.3.44) | RFC 2822 *parsing* only. resh and its dependencies only *format* RFC 2822 (`x509-parser::to_rfc2822`). The fix needs a new `num-conv` major. |
| RUSTSEC-2026-0367/-0368/-0369 (zip 0.6.6) | `ZipArchive::extract` / `ZipStreamReader::extract` are never called. resh's own extractor writes regular files with `create_new`. The fix is zip ≥ 9, a major API migration. |

**Informational warnings** (unmaintained or unsound, not vulnerabilities; listed, not gated):

- unmaintained: async-std, derivative, instant, ring 0.16, trust-dns-proto, unsafe-libyaml, zbus_names / zvariant(_derive);
- unsound: anyhow 1.0.100 (`downcast_mut` after `context`; not used in `src/`), event-listener, git2 0.18.3 (3), rand 0.8.5/0.9.2 (custom logger case);
- yanked: spin 0.9.8.

**TLS backend facts (corrects Stage 3):**

- reqwest is built with both `default-tls` and `rustls-tls`. resh never calls `use_rustls_tls()`, and reqwest 0.12's `TlsBackend::default()` is `native-tls` when `default-tls` is enabled (`reqwest-0.12.26/src/tls.rs:589`).
- So the `http`/`https` handle and the plugin registry use **OpenSSL 3** (dynamically linked `libssl.so.3`; OpenSSL 3.5.8 on this host) with the system CA store.
- lettre (SMTP), git2/libssh2 and memcache also use OpenSSL.
- rustls (with webpki-roots) is used by sqlx's `runtime-tokio-rustls`.
- **Residual:** OpenSSL security fixes come from the host OS, not from `Cargo.lock`. Release notes should state the OpenSSL 3 runtime requirement.

**TLS and integrity verification on the patched build** (live):

| Check | Result |
|---|---|
| Local `openssl s_server` with a self-signed certificate | Plugin registry fetch and `https://….get` both refused. The server logged **TLS alert 48 (unknown CA)**. `curl -k` got 200 from the same server. |
| Public endpoints, read-only GETs | `https://index.crates.io/config.json` succeeds. `expired.badssl.com`, `wrong.host.badssl.com`, `self-signed.badssl.com` and `untrusted-root.badssl.com` all fail. curl confirmed each host was reachable: strict exit 60, `-k` gives 200. |
| `http://` registry | Refused before any connection (`scheme "http" is not allowed`). |
| `source=url` without `verify=none` | `PLUGIN_VERIFY_FAILED`, nothing downloaded |
| Malformed `verify=sha265` | Error |
| Plugin artifact integrity and extraction | Stage 3 tests (`artifact_security_tests`: valid, missing, malformed and mismatched checksum, link and special-file rejection) pass in the final suite. |

## Documentation Accuracy

Full details: `resh-cli-documentation-audit.md`.

- **Coverage:** 28 handle modules, 29 schemes and 229 distinct verbs (239 help entries). All are reviewed and documented in their handle pages; verbs that do not exist were removed.
- **Examples:** 609 extracted and checked. 0 fail; there were 145 failures before Stage 4. One example uses shell substitution and was reviewed by hand. The check runs in the default test suite.
- **Required topics are now documented accurately:**
  - git sync is fast-forward only, and divergent history fails with nothing pushed;
  - ZIP password creation is unsupported and a password request fails;
  - plugin installation: HTTPS only, checksum before extraction, integrity rather than authenticity, unsafe artifacts rejected, identifier rules, `verify=none` means unverified, `source=url` needs `verify=none`;
  - per-handle `timeout_ms` behavior: enforced, rejected or ignored;
  - the stubs: secret encryption and rotate, ssh tunnel/keys, backup schedule, pkg rollback, dns zone.update/TSIG, cert CMS, proc limits.set.
- **Help format unchanged.** `help_coverage` passes. A release-binary smoke test rendered handle help for all 29 schemes and verb help for all 239 verb entries, each with `Handle:`, `Verb:`, `Definition:`, `Usage:` and `Example:`.
- **Remaining limitations:**
  - argument names are not machine-checked (they were hand-reviewed);
  - output samples are point-in-time;
  - the README references the not-yet-created `v1.0.2-beta` tag;
  - some behavior is documented from code reading (root and remote services).

## Test Results

### Commands

```
# Default suite (also on 1.88.0 in the clean export)
env -u MAIL_SMTP_USERNAME -u MAIL_SMTP_PASSWORD -u TEST_POSTGRES_DSN -u TEST_MYSQL_DSN \
    -u TEST_REDIS_URL -u TEST_MEMCACHED_ADDR -u TEST_GIT_CLONE_HTTPS_URL \
    -u TEST_GIT_PULL_HTTPS_URL -u TEST_GIT_PUSH_HTTPS_URL \
  cargo test --locked --no-fail-fast

# Infrastructure tests, against disposable services (see below)
TEST_GIT_CLONE_HTTPS_URL=file://<scratch>/remote.git TEST_GIT_PULL_HTTPS_URL=… TEST_GIT_PULL_TEMP_DIR=… \
TEST_GIT_PUSH_HTTPS_URL=… TEST_GIT_PUSH_TEMP_DIR=… \
TEST_POSTGRES_DSN=postgres://resh_test@127.0.0.1:55432/postgres \
TEST_MYSQL_DSN=mysql://root@127.0.0.1:53306/resh_test \
  cargo test --locked --lib -- --ignored --nocapture

# CI security-regression job, run locally exactly as written in .gitlab-ci.yml
cargo test --locked --lib -- <39 module filters>   ;  cargo test --locked --test stage4_regressions
```

### Results (final tree)

| Suite | Start of Stage 4 | Final, Rust 1.98.1 | Final, Rust 1.88.0 (clean export) |
|---|---|---|---|
| Unit tests, lib | 1171 passed / 0 failed / 11 ignored | **1181 / 0 / 11** | **1181 / 0 / 11** |
| Unit tests, bin (same tests compiled into the bin) | 1175 / 0 / 11 | **1185 / 0 / 11** | **1185 / 0 / 11** |
| `tests/help_cli.rs` | 16 | **16** | **16** |
| `tests/help_coverage.rs` | 2 | **2** | **2** |
| `tests/doc_examples.rs` (new) | — | **2** | **2** |
| `tests/stage4_regressions.rs` (new) | — | **11** | **11** |
| Doc tests | 0 | 0 | 0 |
| Ignored infrastructure tests (`--ignored`) | 11 (Stage 3: passed) | **11 passed**; output checked for silent skips | — |
| CI security-regression job | — | **174 + 11 passed** | — |
| Formatted copy (rustfmt patch applied) | — | identical counts (1181/1185/2/16/2/11) | — |

**New tests:** 10 unit tests (core dispatcher 1, pkg 1, backup 2, mail 2, fs 2, archive 2), 2 validator tests and 11 CLI tests. One existing test that asserted the defective behaviour was updated to the corrected contract: `bare_dry_run_cli_word_is_kept` previously asserted that unknown bare words are silently ignored.

**Mutation checks:** each fix was reverted, its test failed, and the original was restored and byte-compared:

| Reverted fix | Result |
|---|---|
| pkg `security_only` refusal | 1 failure |
| backup dry-run parsing + restore refusal | 2 failures |
| zstd `add` finish | 1 failure |
| zstd `remove` finish | 1 failure |
| resize size | 1 failure |
| mount `dry_run` | 1 failure |
| bare-name parent | 1 failure (CLI) |
| mail send refusal | 1 failure |
| mail profile mode | 1 failure (CLI, mode 644) |
| dispatcher dry-run guard | 2 failures (unit + CLI) |
| archive add header preservation | 1 failure |
| ZIP add option preservation | 1 failure |
| pkg top-level dry_run refusal | 1 failure (CLI) |
| help-argument bypass removed | 2 failures (unit + CLI) |

**Disposable infrastructure:**

- PostgreSQL 16.10 and MariaDB 11.4.8, reusing the Stage 3 bundles that were checksum-verified then, with fresh data directories.
- They ran unprivileged in `bwrap`: host root read-only, private `/tmp`, PID and IPC namespaces, loopback-only listeners on ports 55432 and 53306, throwaway users.
- The git tests used a scratch bare repository over `file://`.
- No production system or credential was used.

**Environment-dependent tests in the default suite (unchanged):**

- 6 `mailh::mail_dns_resolution_tests` (DNS and localhost:587);
- the memcached `cacheh` tests, which pass either way;
- one firewall permission test that skips itself as root.

**Regression findings in this stage:** none in Stage 1-3 behavior. The Stage 4 defects are listed above.

### RC-06 live functional checks (release binary; scratch directories, sandboxes or local repositories only)

| Area | Result |
|---|---|
| Registration | `--list-schemas`: 29 schemes. Handle help for 29/29 and verb help for 239/239, each with all required sections. |
| JSON output | Valid JSON from: `file stat/sha256` (with `--json-pretty`), `system info/memory/uptime/disk`, `fs list-mounts/usage`, `net list/route.list`, `archive list/info`, `cron list`, `svc status`, `secret ls`, `config ls`, `snapshot ls`, `event list-topics`, `proc self.nice.get`, `user root.exists`, `git status`, `db ping` (sqlite). |
| Errors and exit codes | Missing file → exit 2 with `Error:`. Unknown scheme → 1. Unknown verb → 1 with the available verbs listed. Missing service → 1. Missing `dns` name → 1. Missing archive → 1. No stage → 2 (it was a panic). |
| git sync | Divergent history fails for `rebase`, `merge` and `ff_only`, the **remote is unchanged**, and the local commit is kept. A behind-only clone fast-forwards. |
| ZIP password | Refused before writing (Stage 2 test, passing). |
| Backup timeout | A mock `restic` sleeping 30 s with `timeout_ms=700` returns `TIMEOUT` after 705 ms, exit 1. **The child process is gone.** |
| Firewall backup-before-change | Run in a user namespace as uid 0 with a mock `nft`, no network, and a scratch dir bound at `/var/backups`. **Dry run:** only `list ruleset`, no backup written. **Real disable:** a 0600 backup in a 0700 dir is written before `nft flush ruleset`, and the reported path equals the written file. **Unwritable backup dir:** exit 1, and **no flush is executed**. |
| Firewall reload temp file | Same sandbox. `nft -f` receives `/tmp/.resh-reload-nftables-<random>.rules`, mode 600, regular file, and it is removed afterwards. |
| pkg argument safety | `jq;touch …` in a dry-run install is rejected, and the sentinel file is not created. Stage 3 exercised apt, dnf, yum, pacman and apk in sandboxes (58/60 scenarios). |

## Security Verification

Each finding was reassessed against the current code, the final test suite and, where marked LIVE, the release binary. The independent RC-09 review is summarized at the end of this section.

| Finding | Original severity | Current status | Evidence | Remaining risk | Release impact |
|---|---|---|---|---|---|
| C1 archive extraction escape (symlinks, hard links, absolute, `..`, devices) | Critical | **Closed** | `extract_safety_tests` (13) plus `test_path_sanitization` pass. **LIVE:** `lnk -> ..` and `lnk/x` refused; hard link to `/etc/hostname` refused; relative hard link `../../…` refused; absolute entry refused, or re-rooted under the destination with `allow_absolute_paths=true`; `../x` refused; a symlink chain resolving outside is removed and the run fails; internal symlink and hard link extract. Nothing was written outside the destination. | Check-then-use race (see TOCTOU below) | None for supported use |
| C2 plugin version/id path traversal → `remove_dir_all` | Critical | **Closed** | Store and engine tests pass. **LIVE:** id `..%2f..%2fx` refused. | Same-uid race inside the user's own store | None |
| C3 PID wrap → `kill(-1)` | Critical | **Closed** | PID tests pass. **LIVE** in a fresh PID namespace: `4294967295`, `2147483648`, `0`, `-1` and `abc` are all rejected before any signal. | None identified | None |
| H1 pkg shell injection (also in dry run) | High | **Closed** | No `sh -c` in `pkgh.rs`. `cmdline_safety_tests` pass, including the argv mock and the restore lockfile names. **LIVE:** hostile name rejected, sentinel absent. | Read-only verbs (`info`, `search`) do not validate names; argv only, no shell. | None |
| H2 / SEC-05 `dry_run` ignored or malformed → real mutation | High | **Closed.** Stage 4 fixed backup create/prune/restore, mail send and fs mount/unmount. The RC-09 review then found the general case: verbs without a dry-run mode ignored `dry_run=true`, and misspellings were dropped. That is now closed in the dispatcher. | lenient, cron, user, firewall, ssh, plugin, backup, mail, fs and dispatcher dry-run tests pass; mutation-checked. **LIVE (release binary):** `file delete dry_run=true` exits 2 and the file survives; `svc restart dry_run` exits 2; `dry-run`, `dryrun`, `dry-run=true` and `DRY_RUN=true` exit 2 with the file unchanged; `dry_run=maybe` is refused. | Several **non-dry_run** booleans (cron, user, svc, archive non-security options) still fall back silently. The `(...)` argument form still drops unknown bare words inside the parentheses; misspelled `dry_run` *keys* there are caught by the dispatcher. Both documented, Low/Medium. | None |
| H3 firewall backup reported but not written; enable/disable exit 0 on failure | High | **Closed** | `backup_tests` (9) pass. **LIVE** sandbox end to end: backup written before the flush, and a failed backup means no flush and exit 1. | ufw/firewalld take no backup (warned). The `rules.reload` restore step has no deadline. | None |
| H5/H6 silent failures; failures with exit 0 | High | **Closed** for the reported handles | `core::status` tests pass. **LIVE** error-exit matrix above. | `net ping` exits 0 when the host is unreachable; `http head/headers/json` exit 0 on 4xx/5xx. Documented, Medium. | Non-blocking: documented, and read-only operations |
| H13 / SEC-06 / SEC-07 plugin artifact links; missing checksums; plain HTTP | High | **Closed within the trust model** | `artifact_security_tests` pass. **LIVE:** TLS alert 48, `http://` refused, `source=url` needs `verify=none`. | No publisher signature (the registry is trusted). `available.search` uses a scheme-prefix check rather than `https_only`, and falls back to a CWD-relative fixture (search results only, never installed). Low. | None |
| H14 SMTP password base64 in a umask-permission file | High | **Partially closed (Stage 4).** The file is now 0600, written via create_new + O_NOFOLLOW. | `private_file_tests`; CLI test (mutation-checked: 644 without the fix) | The password is still only base64-**encoded**; encrypting it would be new functionality. Files written before this fix keep their old mode until the next save. Documented. | Non-blocking: owner-only file, same trust as `~/.config` |
| SEC-08 restore lockfile names; security booleans; timeouts | High/Medium | **Closed for the brief's items** | Tests pass. Firewall `timeout_ms` is enforced; git `timeout_ms` is rejected. | pkg and fs timeouts stop waiting but do not kill the child (no `kill_on_drop`). Documented, Medium. | None |
| Predictable `/tmp` writes by root-oriented handles | Medium | Firewall backups moved off `/tmp` (Stage 2). **Firewall reload temp: closed (Stage 4).** | **LIVE** sandbox: random name, 0600, removed afterwards | Backup default repositories under `/tmp` (`/tmp/resh_backup_<profile>`, `/tmp/rsync_backup`, `/tmp/borg_repo`) are accepted even if another user pre-created them. **Medium, open, documented**: always pass `repo_url` (backup.md says so). mq falls back to `/tmp` when there is no state dir. Low. | Non-blocking with the documented `repo_url` guidance |
| Option injection (missing `--`) | Medium | **Open** | backup backend argv (`src` and others); user `primary_group` to `groupadd`/`useradd -g` | The values come from the operator's own command line or input. Exploiting this needs an attacker to control those arguments. Documented. | Non-blocking; recommended for the next stage |
| cron newline injection; `unit_name` in paths | Medium | **Open** | Code reading (cronh.rs) | Operator-supplied fields. Documented. | Non-blocking |
| ext resize size | (new, Stage 4) data loss | **Closed** | `stage4_tests` (mutation-checked) | Negative `delta` still rejected (documented) | — |
| `file rename overwrite` data loss | (new, Stage 4) | **Closed** | CLI test (mutation-checked) | If the final `rename` itself fails after the removal (e.g. cross-device with `atomic=true`), the destination is not restored. Documented. Low. | — |
| tar.zst add/remove truncation | (new, Stage 4) | **Closed** | `zstd_rewrite_tests` (mutation-checked) | — | — |
| `archive add` destroys existing tar entries' metadata and symlinks (RC-09 A3); finish errors swallowed (A5) | High (RC-09) | **Closed** | `add_and_remove_keep_tar_entries_intact` across tar, tar.gz and tar.zst (mutation-checked). **LIVE:** after `add`, `run.sh` keeps `-rwxr-xr-x smiller/users`, `link -> run.sh` stays a symlink, and the archive stays 0600. | ZIP `add` still resets existing entries' mtimes (documented) | — |
| Predictable temp files in archive rewrite and file copy (RC-09 A4) | Medium (RC-09) | **Closed** | Code: UUID names, `create_new` + `O_NOFOLLOW`, original mode. Archive test asserts mode 0600 is kept and no temp file is left behind. | — | — |
| `sh -c` with a device path in `fs resize` LVM step (RC-09 A6) | Low (RC-09) | **Closed** | Code: argv execution | Not executed (needs LVM) | — |
| `rename overwrite=true` deleted the destination before a rename that could fail (RC-09 A8) | Low (RC-09) | **Closed for file-over-file** | Code; CLI rename tests | A directory on either side still requires removal first (documented) | — |
| cert key written before chmod 0600 | Medium | **Open** | certh.rs; documented in cert.md | Short window with umask permissions; a chmod failure is ignored on `csr.create`. Write keys only into private directories. | Non-blocking |
| TLS dependencies | High (Stage 3) | **Closed** | See [Dependency Security](#dependency-security) | OpenSSL comes from the host OS | None |

### Filesystem race conditions (TOCTOU), reassessed

- **Archive extraction.** The checks are path-based: parents are created one level at a time, existing symlinks are refused, and targets use `create_new`. A process that can write *inside the destination tree* while the extraction runs could swap a checked directory for a symlink between the check and the write.
  - **Supported use:** extracting into a directory that only the invoking user can write. There the attacker would already have the user's privileges, so there is no privilege boundary to cross.
  - **Where it is a real risk:** extracting **as root into a directory other users can write**, such as `/tmp` or a shared upload directory. There a local attacker who wins a narrow race could redirect a write as root.
  - **Rating: Medium, not release-blocking for supported use.** Required mitigation, documented in archive.md: do not extract into directories writable by other users, especially as root.
  - A complete fix needs `openat`/`O_NOFOLLOW` directory-relative extraction, which would mean reimplementing the tar crate's unpacking. That is out of scope.
- **Plugin store.** All operations are under `$XDG_DATA_HOME/resh/plugins`, owned by the user. Only a same-uid process can race, and it already has full access. **Low.**

### Unverified security assumptions

- **Not executed live:**
  - root on a real host;
  - real firewall, user, svc or cron mutations (only mock, sandbox and namespace runs);
  - real SMTP or SSH;
  - DNS zone transfers;
  - real plugin registries (only the loopback mock and local TLS server).
- systemd service management is verified at the parser and unit level only; the host runs OpenRC.

### RC-09 independent review

*(See the section of that name below.)*

## CI Readiness

**File:** `.gitlab-ci.yml`. The brief names GitLab, and no other CI configuration existed.

| Job | Stage | Image | Commands | Gate |
|---|---|---|---|---|
| `build:msrv` | build | `rust:1.88.0-bookworm` | `cargo metadata --locked`, `cargo build --locked --all-targets`, `cargo build --locked --release` | enforced |
| `test:msrv` | test | 1.88.0 | `cargo test --locked --no-fail-fast` (includes the help, doc-example and CLI suites) | enforced |
| `test:stable` | test | `rust:1.98.1-bookworm` | same | enforced |
| `test:security-regression` | test | 1.88.0 | 39 named Stage 1-4 security/correctness test modules, plus `--test stage4_regressions` | enforced |
| `test:infrastructure` | test | 1.88.0 | `cargo test --locked --lib -- --ignored` | **manual, allow_failure**. Needs the TEST_* variables pointing at **disposable** services. |
| `fmt` | lint | 1.98.1 | `cargo fmt --all -- --check` | enforced. **Fails until the formatting commit lands.** |
| `clippy` | lint | 1.98.1 | `cargo clippy --locked --workspace --all-targets`; report kept as an artifact | advisory (`allow_failure: true`) |
| `audit` | lint | 1.98.1 | `cargo install cargo-audit --locked --version 0.22.2` (cached), `cargo audit` with `.cargo/audit.toml` | enforced |

**Safety:**

- Every job only builds and tests inside a container.
- The default suite is hermetic: system commands are stubbed or mocked under `cfg(test)`, and the infrastructure tests are `#[ignore]`d.
- The `TEST_*` and `MAIL_SMTP_*` variables are explicitly unset for the default suites.
- No job installs packages on a host, changes users, the firewall or services, or contacts a database or plugin registry. The one exception is the manual job, against services you provide.

**What was verified, and what was not:**

| Check | Status |
|---|---|
| YAML syntax and structure | **Validated locally** with two parsers (PyYAML 6.0.3, Ruby Psych). Every job has a stage and a script; every `extends` target exists. |
| Image tags | `rust:1.88.0-bookworm` and `rust:1.98.1-bookworm` exist (Docker Hub registry API, HTTP 200). |
| Job commands | **Executed locally** with the same commands: the MSRV build and tests on 1.88.0 (clean export), stable tests on 1.98.1, the security-regression job (174 + 11 passed), `cargo audit` (exit 0), `cargo fmt --check` (fails as expected: pre-existing debt), Clippy (exit 101 as expected; advisory). |
| GitLab CI lint API / a real runner | **Not executed.** No GitLab project or runner was available, and nothing was pushed. **The pipeline has never run on GitLab.** |
| Container execution | Not possible on this host: the Docker daemon cannot start containers, as Stage 3 also found. The CI images were not run locally. Behaviour as root inside a container is untested: the suite has one test that skips as root, and the rest are expected to pass. |
| Platform mismatch | The local `origin` is **GitHub**. If the canonical repository is GitHub, this file does nothing there; an equivalent GitHub Actions workflow would be needed. **Owner decision.** |

## Release Artifact Verification

**Build:** `cargo build --release --locked` on 1.98.1 succeeds, in the working tree and in the clean export. The clean export also builds `--release` from an empty Cargo home.

| Property | Value |
|---|---|
| Binary | `target/release/resh`, 51,135,328 bytes, sha256 `75675bb5…fdaf74a4` (local build, not for distribution). ELF 64-bit PIE, x86-64, dynamically linked, **not stripped**. |
| Dynamic libraries | `libz.so.1`, `libssl.so.3`, `libcrypto.so.3`, `liblzma.so.5`, `libgcc_s.so.1`, `libm.so.6`, `libc.so.6` |
| ABI floor of this build | Highest referenced symbol versions: **GLIBC_2.39** and **OPENSSL_3.0.0**. A binary built on this host needs glibc ≥ 2.39 and OpenSSL 3, so older LTS distributions need a build on an older base. The CI `rust:*-bookworm` images (glibc 2.36) would produce a more portable binary. |
| Version | `resh --version` → `resh 1.0.2-beta`, matching `Cargo.toml`, README and CHANGELOG. |
| Smoke tests | Global help; `--list-schemas` (29); handle help (29/29); verb help (239/239); resource parsing; read-only commands with valid JSON; meaningful errors with non-zero exits; no-stage error with exit 2; dry-run refusal; `archive add` header preservation. All passed (see RC-06). |
| External tools | Many handles call system tools at runtime: systemctl/rc-service, package managers, iptables/nft, tar/restic/borg/rsync, ssh, journalctl, resize2fs and others. They are not bundled. Documented per handle. |

**Packaging conventions:**

- There is no packaging in the repository: no scripts, no `[profile.release]` tuning (no strip or LTO), and no `cargo-deb`/`rpm` metadata.
- README lists binary releases as plans.
- No new distribution system was created.

**Release candidate checklist (for the owner; nothing here was performed):**

1. Approve this assessment and the compatibility changes listed below.
2. Commit the release file set below as one commit. Do **not** include `.claude/`.
3. Commit the formatting pass separately (`cargo fmt --all`, or the prepared patch). Then confirm `cargo fmt --check` and `cargo test --locked`.
4. Decide the CI platform. Push to a branch and let the pipeline run; confirm every gate is green. The `clippy` job will stay red (advisory).
5. Decide the version. Either keep `1.0.2-beta` and create the tag that README already references, or bump the version, the README badge and CHANGELOG together. Then tag.
6. Build the release artifact on the oldest glibc you intend to support (for example in `rust:1.88.0-bookworm`). Consider `strip`. Record its sha256. Publish only after approval.
7. Release notes: summarize the CHANGELOG "Release-candidate stabilization" entry, the compatibility changes, the OpenSSL 3 and glibc requirements, and the platform matrix below.

## Compatibility Matrix

| Platform / integration | Status | Evidence |
|---|---|---|
| Linux x86_64, glibc (Gentoo, OpenRC host) | **VERIFIED** | Build, full test suite and live smoke on this host. Rust 1.88.0 and 1.98.1. |
| Linux / OpenRC | **PARTIALLY VERIFIED** | Host: read-only `status`/`is-enabled` (Stage 3 and Stage 4 smoke). Alpine sandbox: enable/disable really changed the runlevel (Stage 3). Successful start/stop not verified. |
| Linux / systemd | **NOT TESTED** live | Unit and parser tests only (instance names, `LoadState=not-found`). No systemd host was available. |
| apt (Debian bookworm) | **VERIFIED** in a sandbox (Stage 3) | 11/12 scenarios at the default timeout; `search` needs a larger `timeout_ms`. |
| dnf (Fedora 42) | **VERIFIED** in a sandbox (Stage 3) | 12/12 |
| yum (Amazon Linux 2) | **VERIFIED** in a sandbox (Stage 3) | 11/12; `search` timeout as for apt |
| pacman (Arch) | **VERIFIED** in a sandbox (Stage 3) | 12/12 |
| apk (Alpine 3.20) | **VERIFIED** in a sandbox (Stage 3) | 12/12 |
| Homebrew (Linux or macOS) | **NOT TESTED** | argv unit tests only |
| `security_only` upgrades | dnf/yum (`update`), dnf (`upgrade`) **only**; refused elsewhere | Stage 4 unit and CLI tests |
| PostgreSQL | **VERIFIED** (16.10, disposable) | 4 infrastructure tests (Stage 3, re-run in Stage 4) |
| MySQL-compatible | **PARTIALLY VERIFIED** | MariaDB 11.4.8: 4 tests pass. Oracle MySQL not run. |
| SQLite | **VERIFIED** | Unit tests; live `db ping` |
| Redis / memcached | **NOT TESTED** against servers | Unit tests; connection-error paths only |
| git remotes | **PARTIALLY VERIFIED** | `file://` bare remotes (clone, pull, push, sync). HTTPS/SSH remotes and credentials not tested; sync has no credential arguments (documented). |
| SMTP, SSH, DNS servers | **NOT TESTED** live | Unit tests and dry runs |
| Firewall (iptables / nftables) | **PARTIALLY VERIFIED** | Mock executables in a user-namespace sandbox (enable/disable/reload, backup ordering). Real kernel firewall not exercised. ufw/firewalld not tested. |
| Running as real root | **NOT TESTED** | Only namespace-root |
| Linux non-x86_64 (aarch64 …) | **NOT TESTED** | — |
| macOS | **UNSUPPORTED** | Not built or tested. Unix-only imports are ungated in several handles, and the state paths rely on XDG. Docs say Linux only. |
| Windows | **UNSUPPORTED** | Not built; the code does not target it. |

## Outstanding Technical Debt

### Release blockers

**None known**, subject to the RC-09 review below.

### Owner decisions and verification gaps (conditions)

1. **CI platform and a first real pipeline run.** GitLab CI is configured, but `origin` is GitHub; the pipeline has never run.
2. **Formatting commit** (prepared and verified) before the `fmt` gate can pass.
3. **Compatibility changes users will notice**, to acknowledge in the release notes:
   - **Stages 1-3:** zip `password=` refused; git `timeout_ms` refused; `http://` plugin registries refused; plugin artifacts with links refused; `source=url` needs `verify=none`; malformed booleans are errors; firewall backups now live in `/var/backups/firewall`; ssh exec exits with the remote code.
   - **Stage 4:**
     - `pkg security_only` is refused outside dnf/yum;
     - `backup restore dry_run=true` and `mail send dry_run` are refused;
     - a malformed `dry_run` fails backup create/prune and fs mount/unmount;
     - `resh` with no stage exits 2;
     - ext resize sizes change (they are now correct).
4. **Version and tag:** README references `v1.0.2-beta`, which does not exist yet.
5. ~~Remove the unused `sevenz-rust` dependency.~~ **Done** after owner approval.
6. **Verification gaps:** systemd hosts, real root, brew, Oracle MySQL, HTTPS/SSH git remotes, real SMTP/SSH/DNS servers, aarch64, and container (root) execution of the CI jobs.

### Deferred maintenance (non-blocking, documented)

- **Security hardening (Medium/Low), from the reviews:**
  - ssh `command_args` quoted only when they contain a space or a quote (A7);
  - stdout write errors ignored in `main.rs` (A10);
  - `backup_suffix` copies via `fs::copy` follow a planted symlink;
  - a failed cross-filesystem `rename overwrite=true` can lose the old destination;
  - ZIP symlink entries become regular files when rewritten by `add`;
  - unknown bare words inside the `(...)` argument form are still dropped;
  - no `--` before the device in the LVM tools;
  - `--` separators for backup backend argv and user `primary_group`;
  - cron newline and `unit_name` validation;
  - backup default `/tmp` repositories;
  - cert key write-then-chmod;
  - kill child processes on pkg/fs timeouts;
  - the `rules.reload` restore deadline;
  - `openat`-based archive extraction (TOCTOU);
  - encryption of stored SMTP passwords;
  - publisher signatures for plugins.
- **Functional (Medium/Low):**
  - `net ping` exit 0 when the host is unreachable;
  - `http head/headers/json` exit 0 on 4xx/5xx;
  - non-dry_run booleans that silently fall back;
  - plugin enabled-state split between `state.json` and `enabled.json` (`installed.list` reports enabled plugins as disabled);
  - plugin error kinds classified by substring;
  - tar `add` metadata loss;
  - snapshot `ls`/`diff` with relative targets;
  - cron weekday and OnCalendar translation;
  - git output bypassing `io.stdout`;
  - sync and `pull` cannot integrate divergent history (by design);
  - dns defaults to Google DNS;
  - PostgreSQL NUMERIC.
  - The full list is in `docs/known_issues.md` and the handle pages.
- **Quality:**
  - rustfmt commit;
  - 1,790 Clippy sites (5 deny-level: test assertions and a display branch);
  - 137 dead-code sites, including unreferenced backup modules and `fs_atomic.rs`;
  - undeclared `cfg` features in the cache tests;
  - `await_holding_lock` in db transactions;
  - unit tests compiled twice (lib and bin), because `main.rs` re-declares the modules.

## Proposed Release File Set

Include these files in the eventual release commit, and stage nothing else. Nothing was staged.

**Modified (73):**

- **Repository root:** `.gitignore`, `Cargo.toml`, `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`
- **`docs/`:**
  - `docs/resh_overview.md`, `docs/cli_help_format.md`, `docs/known_issues.md`
  - `docs/Automation_Utilities/`: `backup.md`, `overview.md`, `plugin.md`, `template.md`
  - `docs/Data_StateManagement/`: `cache.md`, `config.md`, `db.md`, `event.md`, `log.md`, `mq.md`, `overview.md`
  - `docs/Filesystem_Storage/`: `archive.md`, `file.md`, `fs.md`, `overview.md`, `snapshot.md`
  - `docs/Network_RemoteOperations/`: `dns.md`, `http.md`, `mail.md`, `net.md`, `overview.md`, `ssh.md`
  - `docs/Packages_Software/`: `git.md`, `overview.md`, `pkg.md`
  - `docs/Process_ServiceManagement/`: `cron.md`, `overview.md`, `proc.md`, `svc.md`
  - `docs/Security_Secrets/`: `cert.md`, `firewall.md`, `overview.md`, `secret.md`, `user.md`
  - `docs/SystemInformation/`: `overview.md`, `system.md`
- **`src/`:**
  - `src/main.rs`; `src/core/`: `lenient.rs`, `mod.rs`, `parse.rs`, `status.rs`
  - `src/handles/automation/`: `backuph.rs`, `pluginh.rs`
  - `src/handles/data/`: `dbh.rs`, `eventh.rs`
  - `src/handles/filesystem/`: `archiveh.rs`, `fileh.rs`, `fsh.rs`, `snapshot.rs`
  - `src/handles/network/`: `dnsh.rs`, `httph.rs`, `mailh.rs`, `sshh.rs`
  - `src/handles/pluginh/plugin/`: `engine.rs`, `registry.rs`, `store.rs`
  - `src/handles/processes/`: `cronh.rs`, `proch.rs`, `svch.rs`
  - `src/handles/security/`: `certh.rs`, `firewallh.rs`, `userh.rs`
  - `src/handles/system/`: `gith.rs`, `pkgh.rs`
- **`tests/`:** `tests/help_cli.rs`

**New (12):**

- `Cargo.lock`, `.gitlab-ci.yml`, `.cargo/audit.toml`
- `tests/doc_examples.rs`, `tests/stage4_regressions.rs`
- `docs/reviews/`: `resh-cli-final-verification.md`, `resh-cli-stage1-security-remediation.md`, `resh-cli-stage2-functional-remediation.md`, `resh-cli-stage3-build-test-security.md`, `resh-cli-documentation-audit.md`, `resh-cli-lint-baseline.md`, `resh-cli-stage4-final-release-assessment.md`

**Explicitly excluded:**

- `.claude/` (`settings.json`, `settings.local.json`): Claude Code settings, user-owned.
- `target/`: build output.
- The rustfmt patch and every scratch artifact: they live outside the repository. The formatting belongs in its own follow-up commit.

**Unchanged, owner's call:** `tmp-sample-plugin/` (tracked, looks like scratch material).

**Suggested staging, for the owner to run:**

```
git add .gitignore Cargo.toml Cargo.lock README.md CONTRIBUTING.md CHANGELOG.md \
        .gitlab-ci.yml .cargo/audit.toml docs src tests
git status --short | grep '^?? .claude/' && echo ".claude/ correctly left untracked"
```

Run `git status` before committing: `docs`, `src` and `tests` add only the files listed above.

## RC-09 Independent Review

**Process.** A separate reviewer, a fresh agent with no part in the Stage 4 changes, inspected the tree read-only. It was asked to review the Stage 4 diffs and to re-check the Stage 1-3 security claims from the code, as if reviewing another engineer's work. It built in its own scratch target directory and ran reproductions only in a scratch directory with HOME/XDG redirected.

- **Round 1:** full review.
- **Round 2:** re-verification of the fixes.
- **Round 3:** a check of the round-2 follow-ups.

The findings were fixed by the coordinating engineer. Every fix has a regression test, and the tests were mutation-checked.

### Round 1 findings and disposition

| ID | Finding (reviewer's severity) | Disposition |
|---|---|---|
| A1 | `dry_run=true` on a verb with no dry-run mode is ignored and the real change runs with exit 0. **Reproduced:** `file delete dry_run=true` deleted the file. (High, blocking) | **Fixed:** dispatcher guard (`src/core/mod.rs` `dry_run_refusal`). Re-verified by the reviewer. |
| A2 | Misspelled dry-run words and keys (`dry-run`, `dryrun`, `DRY_RUN=true`) are dropped, and the real change runs. **Reproduced.** (Medium, blocking with A1) | **Fixed:** unknown bare CLI words are refused; misspelled keys are refused. Re-verified. |
| A3 | `archive add` rewrites existing tar entries with blank headers: mode 0, owner 0, mtime 0, and symlinks become empty files. **Reproduced.** (High, blocking) | **Fixed:** original headers and link targets are kept. Re-verified, including pax, a hard link and 120-character paths. |
| A4 | Predictable temp names opened with `File::create` in archive rewrite and file copy; rewritten archives lose their mode. (Medium) | **Fixed** (round 2 found two more sites, `write` and `replace`, also fixed). Re-verified. |
| A5 | Errors while finishing a compressed stream are swallowed in `add`. (Medium) | **Fixed:** explicit finish and `sync_all` (`add` and `remove`). Re-verified. |
| A6 | `sh -c` with the device path in the LVM step of `fs resize`. (Low) | **Fixed:** argv only. Re-verified. |
| A7 | ssh `command_args` quoted only when they contain a space or a quote. (Low) | **Deferred**, documented in ssh.md |
| A8 | `rename overwrite=true` deleted the destination before a rename that could fail. (Low) | **Fixed** for file-over-file. Re-verified. The cross-filesystem failure path is still Low and deferred. |
| A9 | CI and packaging remarks: fmt gate red until the formatting commit; containers run as root; untracked files must be committed; `.claude/` not in `.gitignore`; crate compiled twice; unused `sevenz-rust`. | The CI comment was corrected. The rest are documented here as owner actions. |
| A10 | stdout write errors ignored in `main.rs`; the doc validator does not check argument keys. (Low) | **Deferred**, documented |

### Round 2 (re-verification)

- **Confirmed fixed:** A1/A2 for every non-`pkg` path (including the `(...)` form and mail rewriting; there is no bypass of `dispatch_stage`), A3, A5, A4 (the sites reported), A6, A8, A9.
- **Still open:** a top-level `dry_run=true` next to pkg's `input=` JSON was let through, and pkg ignored it. **Reproduced** with a mock `apk`: the real install commands ran. **Fixed:** refused, with a pointer to put `dry_run` inside `input=`.
- **Design note:** the guard failed open for a verb with no help entry. **Fixed:** it now fails closed.
- **New, Medium:** ZIP `add` rewrote existing entries with default options (modes and times lost). **Fixed:** the original options are kept.
- **New, Medium:** `file write` and `replace` temp files were predictable and opened with `File::create`. **Fixed.**

### Round 3

- **Confirmed fixed:** the pkg top-level dry run (mock re-run, no install call), fail-closed behaviour, ZIP metadata (mode, mtime, compression, directories, archive mode), and the `write`/`replace` temp files.
- **New, High, introduced by the round-2 change:** the guard skipped requests that carried a `help=`/`h=` argument. Most handles do not treat that as a help request, so `file delete dry_run=true help=1` **deleted the file**.
  - **Fixed** by removing the skip; refusing a dry run on such a request is harmless.
  - Regression tests: a unit test plus a CLI test. Both fail when the skip is reintroduced.
  - Reproduced fixed with the binary: `help=1`, `h=1` and `help=true` all exit 2, and the file is kept.
  - **Not re-reviewed by the independent reviewer after this last fix.** The fix only removes a condition, and the tests cover it.

### Remaining reviewer notes (Low, deferred, documented)

- ZIP symlink entries become regular files when an archive is rewritten by `add` (file-type bits are not carried over).
- `backup_suffix` copies (archive `add`, file `replace backup=`) use `fs::copy`, which follows a planted symlink at the backup name.
- A failed cross-filesystem `rename overwrite=true` can lose the old destination.
- A failed rewrite can leave its (unpredictably named) temp file behind.
- No `--` before the device in the LVM tools.
- The `(...)` argument form still drops unknown bare words inside the parentheses. Misspelled `dry_run` keys there are caught.

### Stage 1-3 security areas (reviewer's code re-check)

Each of these holds:

- archive extraction containment;
- plugin id/version validation and confined deletes;
- plugin HTTPS and checksum enforcement (fails closed; default `verify=sha256`);
- PID parsing;
- pkg argv execution (no `sh -c` outside test mocks);
- firewall backup-before-change;
- exit-code and error reporting.

The dry-run parsing gap was the A1/A2 class above, now closed. The predictable-`/tmp` area is partial: the backup default repositories under `/tmp` remain, documented with the `repo_url` guidance.

## Final Recommendation

**CONDITIONALLY READY**

**Evidence that the core requirements are met:**

1. **Clean locked builds:** an empty Cargo home with every crate fetched fresh, then `--locked` builds on Rust 1.88.0 (MSRV) and 1.98.1. `Cargo.lock` is byte-identical afterwards.
2. **Default suite passes on both toolchains,** with 0 failures. The 11 infrastructure tests pass against disposable PostgreSQL, MariaDB and git.
3. **Earlier work still holds.** All Stage 1-3 regression tests pass, the CI security-regression job passes, and the Stage 1-3 security areas were independently re-checked in the code.
4. **No known exploitable release-blocking defect remains.**
   - Every Critical and High finding from the original review and from Stage 4 is closed with tests: C1-C3, H1-H3, H5, H6, H13, and the Stage 4 and RC-09 findings.
   - H14 is closed for file permissions.
   - The remaining Medium items are documented and need local access or operator-supplied input: option injection without `--`, cron newlines, the archive TOCTOU when extracting into shared directories as root, the backup `/tmp` default repositories, the cert chmod window, and child processes not killed on timeout.
5. **Supported commands report accurately, and failures exit non-zero with a reason.** A dry-run request can no longer perform a real change: it is refused wherever the verb has no dry-run mode.
6. **Documentation and help match the code.** 609 checked examples, 0 failures; stubs and unsupported features are stated plainly.
7. **Toolchain:** MSRV 1.88 is documented and verified.
8. **Dependency advisories:** the TLS advisories are patched, and every other advisory is formally assessed and enforced by `cargo audit` in CI.
9. **Release binary:** smoke tests pass, and the platform limits (Linux x86_64, glibc ≥ 2.39 for this build, OpenRC verified, systemd not) are documented.
10. **Lint debt** is documented and classified, and a verified formatting-only patch is prepared.

**Conditions (owner decisions and verification gaps, none a known defect):**

1. **CI has never run.** `origin` is GitHub while the pipeline is GitLab CI. Choose the platform, push, and confirm that every gate except the advisory `clippy` is green after the formatting commit.
2. **Apply the formatting commit** separately, after the release commit.
3. **Accept the compatibility changes** listed under Outstanding Technical Debt in the release notes. The dispatcher-level dry-run refusal is the most visible: `dry_run=true` on a verb without a dry-run mode now exits 2 instead of running.
4. **Version and tag decision:** README references the non-existent `v1.0.2-beta` tag.
5. **Verification gaps to accept or close:** systemd hosts, real root, brew, Oracle MySQL, HTTPS/SSH git remotes, real SMTP/SSH/DNS servers, aarch64, and CI container (root) execution.
6. **Independent re-review of the last dispatcher change:** the removal of the help-argument skip was verified by tests and reproduction, not by the independent reviewer.

Nothing was committed, pushed, tagged or published. Stage 5 has not been started. **Awaiting project-owner approval.**
