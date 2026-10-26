# Resource Shell (resh) — v1.0.3-beta Release Execution

- **Date:** 2026-10-26
- **Candidate:** working tree on `help-system-and-fixes`, based on `971b0d5` (tag `v1.0.2-beta`, unchanged)
- **Inputs:** `resh-cli-v1.0.3-beta-release-candidate.md`, `resh-cli-v1.0.2-beta-release-gate.md`, the Stage 1–4 reports, and the repository itself. Every claim in those reports that this gate depends on was re-checked against the repository.
- **Stopped at:** Approval Gate A (release commit). **Nothing was staged, committed, pushed, tagged or published.** `.claude/` and the existing tags were not touched.
- **Gate A outcome (2026-10-26):** the owner approved the release commit and decisions 2a, 3 and 4. Credential rotation is **committed to but not yet confirmed**. See [Gate A Outcome](#gate-a-outcome). This report is part of the release commit, so the commit's SHA is recorded at Gate B, not here.

## Executive Summary

**Recommendation: BLOCKED — CREDENTIAL ROTATION REQUIRED.** In addition, **dependency audit approval is required** (see [Final Recommendation](#final-recommendation)).

Technically the candidate is sound:

- **Blocker fixes:** all four corrections (RB-1 to RB-4) were verified independently, both in the code and against a release build of this tree.
- **Tests:** the full default suite passes on Rust 1.88.0 and 1.98.1 with 0 failures.
- **Regression tests:** the 18 new release-blocker tests and the CI security-regression set (194 tests) pass.
- **Formatting:** `cargo fmt --check` is clean.
- **Dependencies:** `Cargo.lock` changes only in the `resh` version line.

Two items prevent the release commit from being recommended:

1. **Credential rotation is unconfirmed.** The exposed MySQL password is gone from the release tree. It remains in 22 public commits, in three public tags and in two published GitHub releases. The project owner has not confirmed that it was rotated or revoked.
2. **New advisories (found by this gate).** Today's RustSec database (2026-10-26) adds **5 advisories (6 findings)** against zstd, zstd-safe, zstd-sys and crypto-bigint. They were added to the database after the candidate's 2026-10-23 audit.
   - None of them is release-blocking on code-level analysis: four are unreachable and one has low practical exploitability.
   - However, `cargo audit` now **fails**, and CI's `audit` job is enforced. The release commit would therefore fail remote CI (Gate B) unless the owner approves documented exceptions or a dependency change.

## Credential Exposure Closure (RELEASE-01)

The secret is not reproduced in this report or in any terminal output. It was extracted from history into a mode-0600 file in a private scratch directory and used only as a search pattern (`grep -F -f`).

### Current release tree

| Check | Result |
|---|---|
| Exposed password (both forms found in history: literal and URL-encoded) in any tracked or to-be-added file, `.claude/` and `target/` excluded | **Not present** (131 files scanned) |
| Exposed account/host DSNs in `MYSQL_CONNECTION_GUIDE.md` | Replaced with placeholders (`appuser`, `pa$$word` / `pa%24%24word`, `db.example.com`) |
| URL-embedded credentials elsewhere | Only placeholder hosts (`host`, `localhost`, `example.com`, `db.example.com`) |
| Private-key PEM blocks | Only `certh.rs`: header-detection strings and test fixtures with dummy bodies |
| Cloud/API token patterns (AWS, GitHub, Slack, GitLab, Google, `sk-`) | None |
| `.env`, key, keystore or database files | None |
| CI workflow | References `secrets.TEST_*` names only; no values |

**Tooling limitation:** gitleaks, trufflehog and detect-secrets are not installed on this host. The scan therefore combined an exact-match search for the known secret with the pattern rules above. It is not a full secret-scanner sweep.

### Historical exposure

| Item | Finding |
|---|---|
| Affected file | `MYSQL_CONNECTION_GUIDE.md` |
| Introduced | `154961b8ae11a7b0e154eded18ed8aac17243f45` (2025-12-19) |
| Commits whose tree contains it | 22 of the 36 reachable commits: `154961b 73e9ed6 ba1a703 bf3ba35 b1f29c7 ead4351 ec61ce5 04d6fdf 0ea3ff1 7bb72c3 c31fc91 dce3638 5d736a4 9d46f4b c7e4500 277f996 beafdc3 8f9ed39 971b0d5 a54ba13 c647b53 eabce5d` |
| Affected tags | `v1.0.0-beta` (`dce3638`), `v1.0.1-beta` (`c7e4500`), `v1.0.2-beta` (`971b0d5`). The topic tags `ai`, `automation`, `cli`, `devops`, `infrastructure` and `rust` predate the file and are clean. |
| Affected branches | `main` (local and `origin`, HEAD `9d46f4b`), `help-system-and-fixes` (local and `origin`, HEAD `971b0d5`) |
| In the current release tree? | **No** |
| Still publicly accessible? | **Yes.** The repository is public (GitHub API: `visibility: public`, 13 stars, 0 forks listed). |
| Published GitHub releases | `v1.0.0-beta` and `v1.0.1-beta` (pre-releases). Their auto-generated source archives contain the file. |
| Default branch | `main` still serves the credential **at HEAD** until the release is merged into it. |

### Rotation status

**NOT CONFIRMED.** The project owner has not confirmed that the credential was rotated or revoked. No login was attempted with it, and no new password was requested.

→ **BLOCKED — CREDENTIAL ROTATION REQUIRED.** Publication must not proceed until the owner confirms.

### History-cleanup recommendation

**Do not rewrite history. Rotate instead.**

- The value has been public for more than 10 months, in three tags and two published releases.
- Clones, caches, GitHub's own archives and third-party mirrors cannot be recalled. A rewrite (`git filter-repo` plus a force-push) would not remove those copies.
- A rewrite would invalidate every published tag and commit SHA, including the release-gate evidence.
- The decisive control is to make the value worthless:
  - rotate or revoke the MySQL account;
  - confirm that the password is not reused anywhere else;
  - review the database host's access logs from 2025-12-19 onward.
- The host is an RFC 1918 private address, so exposure is limited to parties who can reach that network. That reduces urgency, but does not remove the need to rotate.
- Reconsider a rewrite only if the password cannot be rotated (for example, it is reused on a system you do not control) **and** the owner accepts the cost of re-tagging. Optionally, ask GitHub Support to purge cached views after rotation.

**Related, optional:** `docs/reviews/resh-cli-v1.0.2-beta-release-gate.md` (to be committed) names the account user and private host IP, but not the password. Both are already in public history. The owner may redact them before the commit (see Gate A, decision 3).

## Repository Verification (RELEASE-02)

`git diff --check`: clean. `git diff --stat`: 22 files, +617/−162. Untracked: 3 release files plus `.claude/`.

| File | Class | Notes |
|---|---|---|
| `src/core/secure_fs.rs` (new) | 1 Release correction + 2 tests | `write_private_file`, `copy_no_follow`, `entry_exists`; 5 tests |
| `src/core/mod.rs` | 1 | `pub mod secure_fs;` |
| `src/handles/security/certh.rs` | 1 + 2 | RB-1; `private_key_write_tests` (6) |
| `src/handles/filesystem/fileh.rs` | 1 + 2 | RB-2; `backup_symlink_tests` (3) |
| `src/handles/filesystem/archiveh.rs` | 1 + 2 | RB-2 (tar and zip); `backup_symlink_tests` (2) |
| `src/handles/automation/backuph.rs` | 1 + 2 | RB-3; `repo_url_required_tests` (2); 2 tests updated for the removed defaults |
| `.github/workflows/ci.yml` | 2 | The 5 new modules added to `test-security-regression` |
| `Cargo.toml`, `Cargo.lock` | 4 Release metadata | Version only (lockfile: the `resh` entry only) |
| `CHANGELOG.md` | 3 + 4 | `[1.0.3-beta]` entry. Its date reads 2026-10-23; see Gate A, decision 4. |
| `README.md`, `CONTRIBUTING.md`, `docs/resh_overview.md` | 3 + 4 | Version and platform statements |
| `MYSQL_CONNECTION_GUIDE.md` | 1 | RB-4 placeholders |
| `docs/Automation_Utilities/{backup,overview,plugin}.md`, `docs/Filesystem_Storage/{archive,file,fs}.md`, `docs/Packages_Software/pkg.md`, `docs/Security_Secrets/cert.md`, `docs/known_issues.md` | 3 Documentation | Corrected behaviour and risk disclosures |
| `docs/reviews/resh-cli-v1.0.2-beta-release-gate.md` (new) | 3 | Gate evidence |
| `docs/reviews/resh-cli-v1.0.3-beta-release-candidate.md` (new) | 3 | Candidate evidence |
| `docs/reviews/resh-cli-v1.0.3-beta-release-execution.md` (new, this report) | 3 | This gate |
| `.claude/` | 6 User-owned | **Excluded**; untouched |

No unrelated changes were found.

### RB-1 — Certificate private keys: VERIFIED

- **New key files are 0600 from creation.** `OpenOptions::create_new(true).mode(0o600)` plus `O_NOFOLLOW`. The umask can only remove bits, so there is no world-readable window. Release binary under `umask 022`: `srv-key.pem` is 600.
- **Symlinks are refused.**
  - `create_new` (O_EXCL) fails on any existing entry, a symlink included.
  - With `overwrite=true`, an explicit `symlink_metadata` check refuses the link. The key is written to a random `O_EXCL`/`O_NOFOLLOW` sibling temp file, and `rename` replaces the directory entry rather than following it.
  - Release binary: a dangling link gives exit 1, and a link with `overwrite=true` gives exit 2. No target file was created in either case.
- **No replacement without authorization.**
  - `generate` and `renew` already checked existence. That check now uses `entry_exists`, which sees dangling links.
  - `csr.create` now refuses an existing `new_key_output_path` unless `overwrite=true`.
- **No partial keys.**
  - On a write or sync failure, the new file (non-overwrite) or the temp file (overwrite) is removed.
  - Overwrite is atomic: the old key stays in place until the rename.
- **Coverage:** all three key-writing call sites (`generate`, `renew key_strategy=rekey`, `csr.create key_strategy=generate`) go through `write_private_file`. No other key write exists in `certh.rs`.
- **Residual (non-blocking):** certificate, CSR and signature writes (public data) still use `fs::write`. With `overwrite=true` they follow a symlink at the output path. `overwrite=false` is protected because the existence checks see dangling links.

### RB-2 — Backup symlink protection: VERIFIED

- **Secure temp files:** `copy_no_follow` writes to an unpredictable sibling (`.<name>.<pid>.<uuid>.tmp`), created `O_EXCL | O_NOFOLLOW` at mode 0600. It applies the source's permission bits (setuid, setgid and sticky stripped) after the copy, then calls `fsync`.
- **Existing symlinks are refused** at the backup name, dangling ones included.
- **Atomic:** `rename` over the destination.
- **Clean-up:** the temp file is removed on any error.
- **Errors propagate:**
  - `file replace` fails with "failed to create backup" **before** the main write;
  - `archive add` (tar and zip) fails before the archive is changed.
- **Release binary:** a planted `app.conf.bak` → `victim` gives exit 1. The victim's content and its mode (600) are unchanged, and `app.conf` is unchanged.
- **Coverage:** the three call sites (`fileh.rs:1785`, `archiveh.rs:5183`, `archiveh.rs:5462`). The remaining `fs::copy` calls are in `snapshot.rs`, inside the user's own XDG state store, which is outside RB-2's shared-directory threat.

### RB-3 — Backup repository requirements: VERIFIED

- **tar, rsync and borg require `repo_url`.** `repo_url_required` also rejects an empty value, whitespace and a bare `file://`.
- **restic is unchanged:** it falls back to `RESTIC_REPOSITORY`.
- **Validation runs before mutation.**
  - `repo_or_return!` runs straight after backend selection in `create`, `list`, `restore`, `verify` and `prune`;
  - that is before any command, directory creation or dry-run handling;
  - `schedule` writes nothing and is unchanged.
- **Dry run cannot bypass it.** Release binary: `create backend=tar dry_run=true` without `repo_url` gives `INVALID_ARGS`, exit 1.
- **No `/tmp` default.** The constants and `default_tar_repo` are removed, and `/tmp/resh_backup_rb3` was not created. With `repo_url=<dir>` the backup was written there, exit 0.
- **Cosmetic issue (non-blocking):** the new `repo_url_required_tests` module was inserted between the Stage 4 comment block and the `dry_run_tests` module that comment describes (`backuph.rs:3075-3080`).

### RB-4 — Credential removal: VERIFIED

Placeholders only. See [Credential Exposure Closure](#credential-exposure-closure-release-01).

## Security Verification (RELEASE-04)

### Dependency audit

- **Tool:** cargo-audit **0.22.2** (the CI-pinned version), built `--locked` into the scratch directory.
- **Database:** fresh clone of `rustsec/advisory-db` @ `a78282a` (2026-10-26 14:45 +0100), 1,358 advisories.
- **Input:** `Cargo.lock` sha256 `3c794872…cffaa4`, unchanged throughout the gate.
- **Dependency graph:** `git diff v1.0.2-beta -- Cargo.lock` changes only `resh`'s own version, so there are no new or changed dependencies. `.cargo/audit.toml` is unchanged since `v1.0.2-beta`.

| Run | Result |
|---|---|
| With `.cargo/audit.toml` | **exit 1: 6 vulnerabilities** (all new); 36 allowed warnings |
| Without the ignore list | 24 vulnerabilities: the 18 existing exceptions plus the 6 new findings. Every existing exception is still matched, so none is stale. |

**The 18 existing exceptions** are re-confirmed as applicable. The dependency graph, the crate versions and the calling code (all unchanged outside the 6 corrected files) are identical to those the v1.0.2-beta gate assessed advisory by advisory.

**New advisories.** All were added to the database in commit `a78282a` on 2026-10-26.

| Advisory | Crate @ locked | Path | Reachable? | Assessment |
|---|---|---|---|---|
| RUSTSEC-2026-0398 | zstd-safe 7.2.4 | zstd 0.13.3 ← resh | **No** | `Seekable::decompress` needs the `seekable` feature, which is not enabled (features: `arrays, legacy, std, zdict_builder`) |
| RUSTSEC-2026-0410 | zstd-sys 2.0.16 | zstd-safe 5/7 | **No** | WebAssembly allocator shim only; resh targets x86_64 Linux |
| RUSTSEC-2026-0391 | zstd 0.13.3 | resh (direct) | **No** | Affects only `raw::Encoder::with_context` / `raw::Decoder::with_context`. resh uses only `stream::read::Decoder` and `stream::write::Encoder`. |
| RUSTSEC-2026-0403 | zstd-safe 7.2.4 **and** 5.0.2 | zstd 0.13.3 ← resh; zstd 0.11.2 ← zip 0.6.6 | **No** (code-level) | Affects `DCtx::decompress_stream` through `stream::write::Decoder`. The advisory states that `read::Decoder`, `decode_all` and the bulk API are not affected. resh and zip 0.6.6 decompress only through `read::Decoder`. `legacy` is enabled, so this rests on that call-path analysis. |
| RUSTSEC-2026-0387 | crypto-bigint 0.5.5 | elliptic-curve 0.13 ← p256/p384 ← resh | **Yes, in principle** | ECDSA P-256/P-384 key generation and signing in `cert` operate on secret scalars. Exploitation needs a co-resident attacker able to measure timing or microarchitectural side channels across repeated signatures with the same key. resh is a short-lived local CLI with no network signing oracle, so practical risk is **low**. The only fix is crypto-bigint 0.7.6, via p256/p384 0.14 (a major upgrade). |

**Verdict:**

- No new advisory is release-blocking on code-level grounds.
- No semver-compatible fix exists for any of them (each needs zstd 0.14, zstd-safe 8.2 or crypto-bigint 0.7).
- **The enforced CI `audit` job will fail** against the current database.
- Under this assignment's rules, dependencies were not upgraded and `audit.toml` was not edited. **Owner decision required** (Gate A, decision 2).

**Proposed `.cargo/audit.toml` addition** (not applied):

```toml
    # zstd 0.13.3: context reuse leaks an abandoned stream. Only
    # raw::{Encoder,Decoder}::with_context are affected; resh uses
    # stream::read::Decoder and stream::write::Encoder only. Fix: zstd >= 0.14.3.
    "RUSTSEC-2026-0391",
    # zstd-safe 5.0.2 (zip 0.6.6) and 7.2.4: uninitialized memory on a failed
    # legacy-frame decompress through stream::write::Decoder. resh and zip
    # decompress only through stream::read::Decoder, which is not affected.
    "RUSTSEC-2026-0403",
    # zstd-safe 7.2.4: Seekable::decompress; the `seekable` feature is off.
    "RUSTSEC-2026-0398",
    # zstd-sys 2.0.16: WebAssembly allocator shim only; resh is x86_64 Linux.
    "RUSTSEC-2026-0410",
    # crypto-bigint 0.5.5 (p256/p384 via elliptic-curve 0.13): timing
    # variability in constant-time arithmetic. Reached by local ECDSA key
    # generation and signing in cert; no network signing oracle. Fix needs
    # p256/p384 0.14 (crypto-bigint 0.7.6), a major upgrade.
    "RUSTSEC-2026-0387",
```

### Other controls

| Control | Status | Evidence |
|---|---|---|
| TLS certificate verification | **Intact** | `httph.rs:495-512`: reqwest default verification. It is disabled only by an explicit `allow_insecure=true` on `https`, which is covered by `httph::allow_insecure_tests`. No other `danger_accept_*` call exists in `src/`. |
| Plugin HTTPS enforcement | **Intact** | `plugin/registry.rs:53` `require_https`. The loopback-HTTP exception is compiled only under `cfg(test)` (`registry.rs:40-48`). |
| Plugin checksum verification | **Intact** | `registry.rs:370` refuses a SHA-256 mismatch; `engine.rs` tests include `mismatched_checksum_downloads_but_never_extracts_or_installs` |
| Plugin and HTTP sources | Byte-identical to `v1.0.2-beta` | `git diff --quiet v1.0.2-beta -- src/handles/pluginh src/handles/network/httph.rs` |
| Clippy | **Not re-run** by this gate (advisory in CI) | The candidate report gives 1,783 sites and no new findings |

## Test Results (RELEASE-03)

- **Source:** every run used a copy of the exact proposed release tree (`git ls-files` plus the three new files; no `.claude/`), with `--locked`.
- **Environment:** no `TEST_*`, `MAIL_*` or database variables were set, so the 11 infrastructure tests remained `#[ignore]`d. **They are not counted as passing.**
- **Lockfile:** `Cargo.lock` was unchanged after every run.

**Toolchains:**

- Rust 1.98.1 (48a229cea 2026-09-01), the Gentoo system toolchain.
- Rust 1.88.0 (6b00bc388 2025-06-23), from the official tarball, sha256 `7b5437c1…e21bca` re-verified against `static.rust-lang.org`, installed in the scratch directory.

| Command | 1.98.1 | 1.88.0 |
|---|---|---|
| `cargo check --workspace --locked` | success | success |
| `cargo build --workspace --locked` | success | success |
| `cargo build --release --locked` | success | — |
| `cargo test --workspace --locked --no-fail-fast` | lib **1199** passed / 0 failed / 11 ignored; bin **1203** / 0 / 11; doc_examples 2/0; help_cli 16/0; help_coverage 2/0; stage4_regressions 11/0; doctests 0 | identical |
| `cargo fmt --all -- --check` | clean | — |
| CI `test-security-regression` command (verbatim from `ci.yml`) | — | **194 passed** / 0 failed (1,016 filtered); `stage4_regressions` 11/0 |
| The 5 new modules only | — | **18 passed** / 0 failed: secure_fs 5, certh 6, fileh 3, archiveh 2, backuph 2 |
| `cargo audit` | **exit 1** before Gate A (6 new advisories; see above); **exit 0** after the approved exceptions | — |

- Each of the 45 filters in the CI security command matches at least one test.
- The candidate report gives 193 for that command. The true count is 194 (176 + 18): the report predates the `csr.create` symlink test that was added afterwards. This is a documentation discrepancy only.
- **Stage 1–4 protections:** the full CI security set (archive extraction safety, plugin store/engine/artifact security, pid handling, pkg cmdline safety, dry-run refusal across handles, firewall backups, git sync, mail private files, and others) plus `stage4_regressions` pass on the MSRV.

**Release-binary smoke test** (Rust 1.98.1 build of this tree; scratch directory, redirected HOME/XDG, no root; **not a release artifact**):

| Check | Result |
|---|---|
| `--version` | `resh 1.0.3-beta`, exit 0 |
| `--help` | renders |
| No stage | exit 2 |
| Unknown scheme | exit 1 |
| JSON output | `file stat` and `--json-pretty system://.info` parse as JSON |
| RB-1, RB-2, RB-3 reproductions | all refused or corrected as described above |

## Compatibility (RELEASE-05)

The documentation (README, CHANGELOG `[1.0.3-beta]`, `known_issues.md`) was checked against the v1.0.2-beta gate's compatibility matrix:

| Statement | Documented? | Where |
|---|---|---|
| Linux x86_64 is the only supported platform; macOS and Windows are not supported | Yes | README:287, :453; CHANGELOG |
| Rust 1.88 minimum for source builds | Yes | README:285; `Cargo.toml` `rust-version`; CHANGELOG |
| OpenSSL 3 from the OS; libssh2 and libgit2 bundled | Yes | README:288; CHANGELOG |
| glibc ≥ 2.39 for a prebuilt binary; older distributions must build from source | Yes | README:342; CHANGELOG |
| systemd not verified live | Yes | README `svc://` line, "What's working" list, :268 |
| Homebrew not verified | Yes | README:206, :268 |
| Untested architectures (aarch64 and others) | Implicit only ("x86_64 is the only supported platform") | Stated explicitly in the release notes below |
| Known operational limitations and accepted beta risks | Yes | `known_issues.md` v1.0.3-beta section and the handle pages |

The glibc 2.39 floor is inferred from the v1.0.2-beta artifact's ELF version requirements. It must be re-confirmed on the tagged v1.0.3-beta artifact (RELEASE-07).

The **compatibility changes** are disclosed as breaking changes in CHANGELOG, README/handle docs and `known_issues.md`, and prominently in the proposed release notes:

1. `repo_url` is required for tar, rsync and borg;
2. `csr.create` overwrite rule;
3. symlink refusal;
4. 0600 key creation;
5. the earlier corrections remain active.

## Release Approval Gates

| Gate | Status | Evidence |
|---|---|---|
| Credential rotation | **PENDING** | The owner has stated they will rotate it (2026-10-26); completion is not yet confirmed. Removed from the tree; still in public history, 3 tags and 2 published releases. **Must be confirmed before Gate C (tag) and Gate D (publication).** |
| Source verification | **PASS** | RB-1 to RB-4 verified in code and on a release build; no unrelated changes; `diff --check` clean |
| Regression tests | **PASS** | 1.88.0 and 1.98.1: 0 failures; CI security set 194/0; 18/18 new tests |
| Security audit | **PASS** | 6 new findings (5 IDs) in the 2026-10-26 database; none code-level blocking. The owner approved the 5 documented exceptions (decision 2a). Re-run with the updated `.cargo/audit.toml` against advisory-db `a78282a`: **exit 0**, 23 exceptions. The 18 earlier exceptions remain valid. TLS and plugin controls are intact. |
| Release commit | **PENDING** (approved) | Owner approved at Gate A; it is created together with this report. Its SHA is recorded at Gate B. |
| Remote CI | **PENDING** | Not pushed |
| Release tag | **PENDING** | `v1.0.3-beta` does not exist locally or on `origin` |
| Tagged build | **PENDING** | — |
| Artifact checksum | **PENDING** | No release artifact built (the smoke binary is not one) |
| Publication | **PENDING** | — |

## Proposed Release Commit (RELEASE-06)

**Files to stage** (25 existing changes plus this report, plus `.cargo/audit.toml` if decision 2 is approved):

```
.github/workflows/ci.yml
CHANGELOG.md
CONTRIBUTING.md
Cargo.lock
Cargo.toml
MYSQL_CONNECTION_GUIDE.md
README.md
docs/Automation_Utilities/backup.md
docs/Automation_Utilities/overview.md
docs/Automation_Utilities/plugin.md
docs/Filesystem_Storage/archive.md
docs/Filesystem_Storage/file.md
docs/Filesystem_Storage/fs.md
docs/Packages_Software/pkg.md
docs/Security_Secrets/cert.md
docs/known_issues.md
docs/resh_overview.md
docs/reviews/resh-cli-v1.0.2-beta-release-gate.md
docs/reviews/resh-cli-v1.0.3-beta-release-candidate.md
docs/reviews/resh-cli-v1.0.3-beta-release-execution.md
src/core/mod.rs
src/core/secure_fs.rs
src/handles/automation/backuph.rs
src/handles/filesystem/archiveh.rs
src/handles/filesystem/fileh.rs
src/handles/security/certh.rs
.cargo/audit.toml            # decision 2a (approved)
```

Staging is done **by explicit path**, never with `git add -A`, `.` or a directory glob. Afterwards, `git status --short` must show only `?? .claude/`.

**Explicitly excluded:**

- `.claude/`;
- `target/` and every build output;
- the scratch directories under `/tmp/claude-1000/…` (toolchains, test trees, the secret search pattern file);
- no `.env` files, credentials or local databases exist in the tree.

**Commit message:**

```
release: prepare resh v1.0.3-beta

Fix the four v1.0.2-beta release-gate blockers:

- cert: create private keys 0600 with O_EXCL/O_NOFOLLOW; refuse symlinked
  key paths; csr.create no longer replaces an existing key without
  overwrite=true (RB-1)
- file replace backup= / archive add backup_suffix=: write the backup via
  a no-follow temp file and rename; refuse a symlink at the backup name (RB-2)
- backup: remove the /tmp default repositories; tar, rsync and borg require
  repo_url, checked before anything runs (RB-3)
- docs: replace a committed MySQL credential with placeholders (RB-4)

Adds 18 regression tests (in the CI security job), version 1.0.3-beta,
CHANGELOG, platform requirements and known-issues updates, and the
release-gate reports.

Breaking: tar/rsync/borg backups require repo_url; csr.create refuses an
existing new_key_output_path without overwrite=true; symlinked key and
backup paths are errors.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
```

**Tag (Gate C, not yet authorized):** annotated `v1.0.3-beta`, message `resh v1.0.3-beta: controlled public beta (fixes v1.0.2-beta release blockers RB-1 to RB-4)`.

**Proposed release notes** (to be completed with the commit, checksum and toolchain at Gate D):

> **resh v1.0.3-beta: controlled public beta**
>
> v1.0.2-beta was tagged but not released; this is its corrected replacement.
>
> **⚠ Breaking changes. Read before upgrading:**
> 1. **`backup` with tar, rsync or borg now requires `repo_url`.** Without it every verb, including `dry_run=true`, fails with `INVALID_ARGS` (exit 1). The former `/tmp` default repositories were removed. Use a directory only you can write, for example `install -d -m 0700 /var/backups/resh/<profile>`. restic still falls back to `RESTIC_REPOSITORY`.
> 2. **`cert csr.create key_strategy=generate` refuses an existing `new_key_output_path`** unless `overwrite=true`.
> 3. **Symlinks are refused** at certificate key paths (even with `overwrite=true`) and at `file replace backup=` / `archive add backup_suffix=` backup names.
> 4. **Private keys are created with mode 0600 from the start**, and an `overwrite=true` replacement is atomic.
> 5. All earlier security and dry-run corrections remain in force: dry-run refusal on verbs without a dry-run mode, malformed `dry_run` rejected, HTTPS-only plugin registries with SHA-256 verification, fast-forward-only `git sync`, and the rest of the 1.0.2-beta list in the CHANGELOG.
>
> **Security fixes:**
> - Private-key exposure window and symlink redirection in `cert` (RB-1).
> - Arbitrary file modification through a planted backup symlink (RB-2).
> - World-readable, hijackable `/tmp` backup repositories (RB-3).
> - A MySQL credential committed in `MYSQL_CONNECTION_GUIDE.md` was removed. It remains in earlier history and has been rotated *(state only once the owner has confirmed)*.
>
> **Supported platform:** Linux x86_64 only.
> - The prebuilt binary needs **glibc 2.39 or later** (for example Ubuntu 24.04, Debian 13, Fedora 40+) and the **OpenSSL 3** shared libraries from the OS.
> - libssh2 and libgit2 are bundled and are updated through resh releases.
> - RHEL/Rocky/Alma 8 and 9, Debian 12 and Ubuntu 22.04 must build from source: Rust 1.88 or later, `cargo build --release --locked`.
> - aarch64 and other architectures are untested. macOS and Windows are unsupported.
>
> **Install:** download `resh-1.0.3-beta-x86_64-unknown-linux-gnu` and `SHA256SUMS`, run `sha256sum -c SHA256SUMS`, then `install -m 0755 resh-1.0.3-beta-x86_64-unknown-linux-gnu /usr/local/bin/resh`.
>
> **Known limitations:**
> - Not verified live: systemd service and timer management, Homebrew, real-root operation on a host, Oracle MySQL, Redis/memcached servers, HTTPS/SSH git remotes, SMTP/SSH/DNS servers, and real kernel firewall rules.
> - Stub or unsupported features are listed in `docs/known_issues.md`.
> - Accepted beta risks:
>   - backup argv option injection;
>   - cron newline injection;
>   - ssh `command_args` quoting;
>   - the archive extraction race in shared directories;
>   - pkg/fs timeouts that do not stop the child process;
>   - SMTP passwords stored base64-encoded;
>   - plugin verbs run as root with another user's `HOME`.
> - Never pass untrusted input to backup, cron, ssh or user arguments.
>
> **Artifact:** `resh-1.0.3-beta-x86_64-unknown-linux-gnu`, SHA-256 `<checksum>`, built from `<commit>` with Rust `<version>`.

## Remaining Risks

Non-blocking, carried forward or found here:

- **Credential:** permanent historical exposure, mitigated only by rotation. `main` serves the file at HEAD until this release is merged into it.
- **Dependencies:**
  - 5 new advisories (above): one reachable (crypto-bigint timing, low practical risk) and four unreachable;
  - 18 existing exceptions;
  - the remedies are major upgrades (zstd 0.14, zip ≥ 9, p256/p384 0.14, hickory-dns).
- **Cert residual:** certificate, CSR and signature (public data) writes follow a symlink when `overwrite=true`.
- **Backup:** an existing tar or rsync repository directory is used without an owner or mode check. This is documented.
- **The v1.0.2-beta gate's accepted beta risks and deferred maintenance** are unchanged:
  - Node 20 action deprecation;
  - `ubuntu-latest` migration;
  - Clippy debt;
  - building on an older glibc base;
  - `.claude/` not in `.gitignore`.
- **Not re-verified in this gate:** Clippy, systemd, Homebrew, real-root operation and older-glibc execution.
- **Secret scanning:** done by exact match and pattern rules, without a dedicated scanner.

## Final Recommendation

**BLOCKED — CREDENTIAL ROTATION REQUIRED**

The candidate is technically sound:

- the four blocker corrections are correct, narrow and covered by regression tests;
- the full suite passes on the MSRV and on current stable;
- the release binary demonstrates each fix;
- the documentation discloses the breaking changes and the platform limits accurately.

It cannot be recommended for the release commit until both of the following are resolved:

1. **The owner confirms** that the exposed MySQL credential has been rotated or revoked. This is required by RELEASE-01 and has not been given.
2. **The owner decides** how to handle the 5 advisories published on 2026-10-26, which make the enforced `cargo audit` CI job fail. The options are in Gate A, decision 2.

Once both are resolved, the candidate becomes **READY FOR RELEASE COMMIT APPROVAL** with no further verification needed, apart from re-running `cargo audit` if `audit.toml` changes.

## Approval Gate A — Decisions Requested

1. **Credential rotation:** confirm that the MySQL credential formerly in `MYSQL_CONNECTION_GUIDE.md` has been rotated or revoked. Optionally also confirm that it is not reused elsewhere and that host access logs were reviewed. Do not send the new password.
2. **New advisories:** choose one:
   - **(a)** add the 5 documented exceptions above to `.cargo/audit.toml` and include it in the commit (recommended: no code or dependency change, consistent with the existing exception policy);
   - **(b)** authorize a dependency-upgrade workstream (zstd 0.14 / zip / p256 0.14). This is a development change and would need a new verification pass;
   - **(c)** another option the owner prefers.
3. **Optional redaction:** remove the MySQL account user and private host IP from `resh-cli-v1.0.2-beta-release-gate.md` before committing. They are already in history, so this is hygiene only.
4. **CHANGELOG date:** change `[1.0.3-beta] - 2026-10-23` to the actual release date at commit time.
5. **Release commit:** approve creating the commit above with exactly the listed files, on `help-system-and-fixes`, with no push.

## Gate A Outcome

Owner decisions, 2026-10-26:

| # | Decision | Action taken |
|---|---|---|
| 1 | "I will rotate the MySQL credential." | Recorded as a commitment. **Rotation is not confirmed as complete**, so the credential gate stays PENDING. It must be confirmed before the tag (Gate C) and publication (Gate D). |
| 2 | (a) Add the five drafted exceptions | Added verbatim to `.cargo/audit.toml`, with a pointer to this report. `cargo audit` (0.22.2, advisory-db `a78282a`): exit 0. `Cargo.lock` unchanged. |
| 3 | Redact the user name and IP from the v1.0.2-beta gate report | `resh-cli-v1.0.2-beta-release-gate.md` (RB-4 row) now describes them generically. No other release file contains them. |
| 4 | Update the CHANGELOG date | `## [1.0.3-beta] - 2026-10-26` |
| 5 | Approve the release commit | Commit created on `help-system-and-fixes`, not pushed. Files: the 26 listed above plus `.cargo/audit.toml` (decision 2a), **27 in total**. |

**Revised recommendation:** **CONDITIONALLY READY.**

- The candidate is technically verified, and the release commit is approved.
- Before Gate C, the push and remote CI (Gate B) still need separate authorization, and the owner must confirm the credential rotation.
- **CI caveat:** CI's `audit` job fetches the advisory database live. Any advisory published after `a78282a` would fail it again and has to be assessed at Gate B.
