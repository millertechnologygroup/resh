# Resource Shell (resh) — v1.0.3-beta Release Candidate

- **Date:** 2026-10-23
- **Base:** tag `v1.0.2-beta` (`971b0d500af21b43f61af0599d74a429078dbf96`). That tag is unchanged and was not moved.
- **Purpose:** correct the four release blockers recorded in `resh-cli-v1.0.2-beta-release-gate.md`, and ship them as `v1.0.3-beta` (owner decision).
- **State:** working-tree changes only. **Nothing was committed, pushed, tagged or published.** `.claude/` is untouched.

## Summary

| Blocker | Correction | Verified by |
|---|---|---|
| **RB-1** cert private keys created with umask mode and then chmod'ed; symlink-following; `overwrite=false` bypass | Keys are created 0600 with `O_EXCL`/`O_NOFOLLOW` (temp file plus rename for `overwrite=true`). A symlink at the key path is refused. Existence checks see dangling symlinks. `csr.create` honours `overwrite` for `new_key_output_path`. | 6 unit tests (mutation-checked); release-binary repro |
| **RB-2** `file replace backup=` / `archive add backup_suffix=` wrote through a planted symlink | The backup is copied to a fresh `O_EXCL`/`O_NOFOLLOW` temp file, given the source's permission bits (without setuid, setgid or sticky), and renamed into place. A symlink at the backup name is refused. | 5 unit tests (mutation-checked, all three call sites); release-binary repro |
| **RB-3** world-readable, hijackable `/tmp` default backup repositories | The defaults are removed. tar, rsync and borg require `repo_url`; every verb, dry run included, fails with `INVALID_ARGS` before anything runs. restic is unchanged and still uses `RESTIC_REPOSITORY`. | 2 unit tests (mutation-checked); release-binary repro |
| **RB-4** real MySQL credential in `MYSQL_CONNECTION_GUIDE.md` | Replaced with placeholders (`appuser`, `db.example.com`). **The credential remains in the history and in earlier tags. Rotating it is an owner action and has not been confirmed.** | `grep` for the user name and host: no matches |

## Changes

### Source

| File | Change |
|---|---|
| `src/core/secure_fs.rs` (new) | `write_private_file` (secret data: mode 0600 from creation, no symlink, `create_new` or temp file plus rename); `copy_no_follow` (backup copy through a fresh temp file plus rename, refusing a symlink); `entry_exists` (true for dangling symlinks). 5 unit tests. |
| `src/core/mod.rs` | `pub mod secure_fs;` |
| `src/handles/security/certh.rs` | `generate`, `renew` (rekey) and `csr.create` (generate) write keys through `write_private_file`. `check_target_exists` and `target_file_exists` use `entry_exists`. `csr.create` refuses an existing key output without `overwrite`. Tests: `private_key_write_tests` (6). |
| `src/handles/filesystem/fileh.rs` | `replace backup=` uses `copy_no_follow`. Tests: `backup_symlink_tests` (3). |
| `src/handles/filesystem/archiveh.rs` | `add backup_suffix=` (tar and zip paths) uses `copy_no_follow`. Tests: `backup_symlink_tests` (2, covering tar and zip). |
| `src/handles/automation/backuph.rs` | Removed `DEFAULT_RSYNC_REPO`, `DEFAULT_BORG_REPO` and `default_tar_repo`. Added `repo_url_required` and `repo_or_return!` to create, list, restore, verify and prune (schedule writes nothing and is unchanged). The `create` help example passes `repo_url`. Two existing tests that asserted the removed defaults were updated. Tests: `repo_url_required_tests` (2). |

### Version, CI and documentation

- **Version:** `Cargo.toml` and `Cargo.lock` (the resh package entry only), README, CONTRIBUTING, `docs/resh_overview.md` → `1.0.3-beta`.
- **CHANGELOG:** new `[1.0.3-beta]` entry, covering security fixes, compatibility changes and platform requirements.
- **CI:** `.github/workflows/ci.yml` adds the 5 new test modules to `test-security-regression`.
- **Documentation:**
  - `cert.md`, `file.md`, `archive.md`, `backup.md`, `Automation_Utilities/overview.md`: the corrected behaviour.
  - `pkg.md` and `fs.md`: a timed-out tool either keeps running or is killed by SIGPIPE.
  - `plugin.md`: do not run plugin verbs as root with another user's HOME/XDG.
  - `known_issues.md`: the v1.0.3-beta section plus the accepted beta risks.
  - `backup.md`: the option-injection wording is corrected.
  - README: OpenSSL 3 runtime requirement; glibc ≥ 2.39 for a prebuilt binary; systemd and brew marked as not verified live; the inaccurate "test suite has known failures" line is corrected.

### Compatibility changes introduced by this candidate

- `backup` with tar, rsync or borg and no `repo_url` now fails (`INVALID_ARGS`, exit 1). Previously it used `/tmp/...`.
- `cert csr.create key_strategy=generate` refuses an existing `new_key_output_path` unless `overwrite=true`.
- A symlink at a cert key path, or at a `backup=` / `backup_suffix=` name, is now an error.

## Verification

Every check below ran on a copy of the working tree exported from `git ls-files` (excluding `.claude/`), with `--locked`. `Cargo.lock` was unchanged by every run.

| Check | Rust 1.98.1 | Rust 1.88.0 (MSRV) |
|---|---|---|
| `cargo build --release --locked` | success | success |
| `cargo test --workspace --locked --no-fail-fast` | lib **1199**/0 failed (11 ignored); bin **1203**/0; doc_examples 2; help_cli 16; help_coverage 2; stage4_regressions 11 | identical |
| `cargo fmt --all -- --check` | clean | — |
| CI security-regression command (run locally) | **193 passed** (176 before, plus 17 new); all filters match tests | — |
| Clippy (`--workspace --all-targets`) | **1,783 sites** (5 deny-level), down from 1,790; **no new findings** compared with the v1.0.2-beta baseline | — |
| `cargo audit` (0.22.2, advisory-db 2026-10-23) | exit 0; same 18 justified exceptions; no new advisories | — |
| Help | 29 schemes, 239 verb help entries; `help_coverage` passes | — |

**Mutation checks.** Each fix was reverted, its tests run, and the file restored and byte-compared:

| Reverted fix | Result |
|---|---|
| `file replace` backup copy back to `fs::copy` | 2 tests fail |
| `archive add` backup copy back to `fs::copy` (both sites) | 1 test fails |
| cert key write back to `fs::write` plus chmod | 1 test fails |
| `repo_or_return!` removed from the backup verbs | 1 test fails |
| cert `target_file_exists` back to `Path::exists` | no failure: the write layer still refuses the symlink (defence in depth). A dedicated `csr.create` symlink test was added afterwards. |

**Release-binary reproductions** (Rust 1.98.1 build of this tree; scratch directory, redirected HOME/XDG, no root). These rerun the exact v1.0.2-beta gate reproductions:

| Blocker | v1.0.2-beta | This candidate |
|---|---|---|
| RB-1 race: a poller opens `srv-key.pem` during `cert generate` | opened at **0644** in 5/5 runs | opened at **0600** in 5/5 runs, so another uid would be refused |
| RB-1 dangling symlink, `overwrite=false` | key created at the link target, exit 0 | refused, exit 1, nothing created |
| RB-1 symlink, `overwrite=true` | — | refused, exit 2, nothing created |
| RB-2 `file replace backup=.bak` with a planted symlink | victim overwritten, mode 600 → 644, exit 0 | refused, exit 1; victim and source unchanged |
| RB-3 `backup://rb3.create backend=tar` without `repo_url` | archive under `/tmp/resh_backup_rb3` | `INVALID_ARGS: repo_url is required…`, exit 1; no `/tmp` directory |
| RB-3 with `repo_url=<dir>` | — | backup written to `<dir>`, exit 0 |

## Not yet done (requires owner action)

1. **Rotate the MySQL credential** (RB-4) and check that host for unauthorized access. This is independent of the release.
2. **Review and commit** the working-tree changes on `help-system-and-fixes`, leaving out `.claude/`. Suggested staging:

   ```
   git add .github/workflows/ci.yml CHANGELOG.md CONTRIBUTING.md Cargo.lock Cargo.toml \
           MYSQL_CONNECTION_GUIDE.md README.md docs src
   git status --short   # expect only "?? .claude/" left
   ```

3. **Push, and confirm the GitHub Actions run** on the new commit: every gating job green, Clippy advisory.
4. **Tag `v1.0.3-beta`** on that commit (annotated) and push the tag. Confirm that the tag's own CI run passes.
5. **Rebuild the artifact from a clean checkout of the tag**, record its SHA-256, and complete the release checklist (see the v1.0.2-beta gate report for the method). No binary built here is a release artifact.
6. **Publish** with the draft release notes in the appendix of `resh-cli-v1.0.2-beta-release-gate.md`, updated to 1.0.3-beta and this commit and checksum. Note that `repo_url` is now required for tar, rsync and borg.

The accepted beta risks, verification gaps and deferred maintenance in the v1.0.2-beta gate report are unchanged.
