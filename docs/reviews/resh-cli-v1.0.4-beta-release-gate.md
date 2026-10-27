# resh v1.0.4-beta — Release Gate

| | |
|---|---|
| Release | v1.0.4-beta (security release, pre-release) |
| Base | `main` @ `be9e1fc44754f1a36f6f010eefae9605a68153e1` (= `origin/main`) |
| Previous release | v1.0.3-beta, tag object `d42f7b6c…` → `dcce21ad0dbb749d2172a57c25841bb253a7bbd7` (unchanged) |
| Gate date | 2026-10-27 |
| Status | **Release candidate validated; release commit, tag and publication await owner approval** |

This document is public. Vulnerability detail beyond the CHANGELOG is kept
outside the repository.

## 1. Release scope

Changes since v1.0.3-beta, in addition to this release commit:

| Commit | Subject |
|---|---|
| `facd6aa` | docs: record resh v1.0.3-beta release verification (review documents only) |
| `1a0c3db` | fix(security): harden backup backend arguments |
| `69ef5be` | fix(security): prevent cron and systemd injection |
| `2edd30e` | fix(security): preserve ssh argument boundaries |
| `45aa917` | fix(cert): correct ecdsa sha512 signing |
| `e8ae231` | test(security): add stage6b regression coverage |
| `be9e1fc` | docs(security): update known limitations |

- Code changes are limited to `backuph.rs`, `cronh.rs`, `sshh.rs` and
  `certh.rs`.
- Tests: `tests/stage6b_security.rs` plus unit tests in those handlers.
- CI: the security job runs the new tests.
- There are no new features and no new handles or verbs.
- Dependencies are unchanged: `Cargo.lock` differs from v1.0.3-beta only in
  resh's own version.
- Exit-code meanings are unchanged. Newly refused input exits 1, like other
  refusals.

The release commit changes only release metadata:

| File | Change |
|---|---|
| `Cargo.toml`, `Cargo.lock` | `1.0.3-beta` → `1.0.4-beta` (resh package only) |
| `CHANGELOG.md` | `[1.0.4-beta]` entry: Security, Changed, Documentation |
| `README.md`, `CONTRIBUTING.md` | current-version strings |
| `docs/known_issues.md` | v1.0.4-beta section marked as released |
| `docs/reviews/resh-cli-v1.0.4-beta-release-gate.md` | this document |

Not included, by design:
- the five staged Stage 6A/Stage 5 documents in the main worktree, including
  a comment-only `.cargo/audit.toml` edit (pending separate review);
- the Stage 6B review report;
- the firewall test-fixture fix (deferred; §5).

## 2. Validation of the release candidate

The release candidate (RC) is the release worktree with the uncommitted
release metadata applied. All runs were sequential and `--locked`.

| Check | Result |
|---|---|
| `cargo fmt --check` | Pass |
| Stable build and full test suite (rustc 1.98.1, host) | **2502 passed, 0 failed**: lib 1221, bin 1225, doc_examples 2, help_cli 16, help_coverage 2, stage4_regressions 11, stage6b_security 25. 11 ignored per lib and bin target (MySQL ×4, PostgreSQL ×4, git remote ×3: infrastructure tests, not counted as passing) |
| Rust 1.88 (`rust:1.88-bookworm` container, RC source) | rustc 1.88.0 / cargo 1.88.0: `cargo metadata --locked` OK; full test suite **2502 passed, 0 failed** (same counts); `cargo build --locked --release` OK, prints `resh 1.0.4-beta`; `Cargo.lock` unchanged |
| CI on `be9e1fc` (code identical to the RC apart from metadata) | Run 40551985262 (branch) and 40554559549 (`main`): success. build-msrv (1.88.0), test-msrv, test-stable, test-security-regression (216 + stage4 11 + stage6b 25), fmt and audit passed. clippy is advisory and at the known baseline (1749 warnings vs 1750 on `facd6aa`). |
| Release binary harness (help sweep and behaviour checks) | 268/268 help checks; 52/52 behaviour and security checks. These are the 45 v1.0.3-beta checks plus 7 Stage 6B checks: backup option-shaped value, cron line break, `cron_file` location, ssh unknown `shell_mode`, ssh argument quoting, ssh cmd-mode refusal, and an OpenSSL-verified P-384 SHA-512 signature. All 7 new checks fail against the v1.0.3-beta binary, which confirms they detect the fixed behaviour |
| Archive | `resh-v1.0.4-beta-linux-x86_64.tar.gz`: 5 files and 2 directories, as in v1.0.3-beta; no absolute, `..`, `.git`, `.claude`, `.env` or `target` entries; reproducible repack; `gzip -t` OK; the extracted binary is identical, mode 0755, and prints `resh 1.0.4-beta` |
| SHA-256 | `SHA256SUMS` verifies with `sha256sum -c`; `openssl dgst` agrees. RC digests are recorded outside the repository, because the published artifact is rebuilt from the tag |
| Binary dependencies | NEEDED: `libz.so.1`, `libssl.so.3`, `libcrypto.so.3`, `liblzma.so.5`, `libgcc_s.so.1`, `libm.so.6`, `libc.so.6`. Maximum `GLIBC_2.39`, `OPENSSL_3.0.0`. Identical to v1.0.3-beta |
| Artifact privacy | Path-remapped build: 0 build-user home or build-directory strings, 0 host-name strings, no debug sections. Remaining `/home/alice` and `/home/bob` strings are help examples |
| Credential scan | No token or private-key shapes. The DSN-shaped strings are placeholders (`mysql://user:pass@host…`, `ssh://<username>:<passwd>@<host>`) |
| Linux compatibility (stock images, `--network none --read-only`, uid 65534) | **Runs:** Ubuntu 24.04 (glibc 2.39), Debian 13 (2.41), Fedora 40 (2.39). **Does not start:** Fedora 39 (2.38), Ubuntu 22.04 (2.35), Rocky Linux 9 (2.34) (`GLIBC_2.39 not found`); Debian 12 (`libssl.so.3` missing). Same as v1.0.3-beta |

## 3. Dependency audit

`cargo audit` on `main` @ `be9e1fc` (CI, cargo-audit 0.22.2, 1380
advisories, 618 crates) found **no vulnerability outside the ignore list**.

- `.cargo/audit.toml` lists 23 assessed exceptions, unchanged from
  v1.0.3-beta.
- The dependency set is identical to v1.0.3-beta.
- The exception reachable in principle is RUSTSEC-2026-0387 (crypto-bigint
  0.5.5 timing variability). resh reaches it through local ECDSA P-256/P-384
  key generation, key re-encoding and `cert sign` ECDSA signatures.
  Certificate generation signs through `ring`. resh exposes no network
  signing oracle. The v1.0.3-beta release notes said ECDSA signing goes
  through `ring`; that is true only for certificate generation, so the
  v1.0.4-beta notes state the scope correctly.
- cargo-audit also reports 36 **informational** warnings, which do not fail
  the audit: 26 unsound, 9 unmaintained, 1 yanked. They were not
  individually re-assessed for this release. A review is recommended before
  the next feature release.

## 4. Documented behaviour this release relies on

- restic/borg `backup prune dry_run=true` runs the backend's own dry run
  (`dry_run_mode: backend`). Its repository access, network, lock and cache
  effects are documented as expected and are not verified by tests. The
  dry-run contract is unchanged.
- ssh `exec`: `command_args` quoting is supported for POSIX login shells
  (tested with sh, dash and bash). fish, csh and tcsh are unsupported.
  cmd.exe and PowerShell modes refuse values that would need quoting.
  `command` is a command line by design.
- Linux binary: x86_64, glibc 2.39 or later, OpenSSL 3. Older distributions
  build from source with Rust 1.88 or later.

## 5. Outstanding risks

| Risk | Severity | Disposition |
|---|---|---|
| Intermittent `ETXTBSY` failure in `firewallh::timeout_tests::large_output_does_not_deadlock_before_the_deadline` (test-fixture race; pre-existing) | CI reliability | **Deferred by the owner.** If it fails on the tag CI run, re-run on the same SHA and record both runs; do not treat it as a pass by inference |
| restic/borg backend dry-run side effects are not verified | Low | Documented in backup.md, the CHANGELOG and the release notes |
| `user add primary_group`, `fs mount` `source`/`target` lack `--` | Low, open | Listed in known_issues.md; later release |
| `cron enable`/`rm` pass timer names read from `systemctl list-timers` without `--` | Low, pre-existing | Names come from installed units, not from caller input; later release |
| `src/handles/automation/backup/` helper module builds restic/borg commands without validation | Informational | Private to the crate and unreachable; remove in a later cleanup |
| 36 informational cargo-audit warnings not re-assessed | Low | Review before the next feature release |
| Release is unsigned | — | SHA-256 proves integrity only, as in v1.0.3-beta |
| Fixes are already public on `main` | Disclosure | Publish the release and the security advisory together |

## 6. Approval gates

| Gate | Action | Status |
|---|---|---|
| R1 | Commit the release metadata on top of `be9e1fc` | **Awaiting approval** |
| R2 | Push the release commit to `main` (fast-forward), then CI on that SHA | Awaiting approval |
| R3 | Create and push the annotated tag `v1.0.4-beta` on the release commit, then tag CI | Awaiting approval |
| R4 | Rebuild the artifact from the tag (clean clone, path remapping), repeat §2 artifact checks, and finalize the checksum in the release notes | After R3 |
| R5 | Publish the GitHub pre-release (not latest) with exactly the archive and `SHA256SUMS` | Awaiting approval |
| R6 | Publish the security advisory (drafted privately) | Awaiting approval; recommended immediately after R5 |
| R7 | Delete `security/v1.0.4-beta-remediation` | Deferred until the release is published and verified |
