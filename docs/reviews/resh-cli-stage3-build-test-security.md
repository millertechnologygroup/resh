# Resource Shell (resh) — Stage 3: Build Reproducibility, Test Reliability, and Release Security Closure

- **Date:** 2026-10-23
- **Scope:** BUILD-01, TEST-01, SEC-06, SEC-07, SEC-08, TEST-02, TEST-03, BUILD-02 and REVIEW-01 from the Stage 3 brief.
- **State:** All changes are uncommitted in the working tree, on top of the uncommitted Stage 1 and Stage 2 changes. Nothing was committed or pushed. Stage 4 has not been started.

## Executive Summary

**Recommendation: STAGE 3 CONDITIONALLY COMPLETE.** The implementation work is done and verified. The remaining gaps are verification gaps and owner decisions, not known exploitable defects in resh's own code. They are listed under [Remaining Release Risks](#remaining-release-risks).

- **Reproducible builds (BUILD-01).**
  - `Cargo.lock` is no longer ignored and is ready to be committed.
  - The H4 claim that `zip 0.6.x` is yanked no longer holds: crates.io currently lists every 0.6 release as available, and a fresh resolution of `zip = "0.6"` succeeds.
  - A clean export of the tree builds with `--locked` from an **empty** Cargo home, on Rust 1.98.1 and on Rust 1.88.0. 1.88 is the declared floor of the locked dependencies; it is now recorded as `rust-version` in `Cargo.toml`.
  - The only dependency change is a lockfile-only patch bump of `tar` from 0.4.44 to 0.4.45. It closes RUSTSEC-2026-0067 and RUSTSEC-2026-0068, which applied to plugin extraction.
- **The 14 failing tests pass (TEST-01).** 11 were test defects, 2 had stale expectations, and 1 exposed dead code in production. The system-user unlock protection is now actually exercised: a mutation check makes its test fail when the guard is removed.
- **Plugin artifact link traversal is closed (SEC-06).** Artifacts may contain only regular files and directories. Links, special files, absolute paths and `..` paths fail the install, and nothing is installed. The store copy no longer follows links. setuid and world-write bits are dropped.
- **Plugin transport and integrity (SEC-07).**
  - Remote registries and artifact URLs must use HTTPS with a valid certificate. Plain HTTP is refused before any connection is made, and so is a redirect to HTTP.
  - With the default `verify=sha256`, a registry artifact needs a well-formed SHA-256, checked before extraction. A direct `source=url` artifact has no trusted checksum, so it is refused unless the caller passes `verify=none`.
- **Input validation (SEC-08).**
  - `allow_symlinks=no` is now false.
  - The security-relevant booleans in the brief use the shared Stage 1 parser and reject malformed values.
  - Restore lockfile names are validated. Firewall `timeout_ms` is enforced. Git `timeout_ms` is rejected, because it cannot be enforced.
- **Skipped tests (TEST-02).**
  - 2 of the 13 skipped tests are converted to isolated tests and now run by default.
  - The other 11 are marked `#[ignore]` with a reason. They were all run in this stage against disposable infrastructure: a local bare git repository, PostgreSQL 16.10 and MariaDB 11.4.8.
  - The default suite no longer needs any `--skip` filters.
- **Compatibility (TEST-03).**
  - Docker cannot start containers on this host, so the real apt, dnf, yum, pacman and apk were run in unprivileged bwrap sandboxes built from official distribution images.
  - All five install, remove, query and report failures correctly through resh.
  - OpenRC was exercised on the host (read-only) and in a sandbox.
  - Three production defects were found and fixed:
    - apt `search` misparsed its results.
    - PostgreSQL integer and `FLOAT4` columns failed to decode, or silently became `null`.
    - `db tables` panicked on MySQL/MariaDB.
- **Tests:**
  - Lib unit tests: **1171 passed, 0 failed, 11 ignored, 0 filtered**. Before Stage 3: 1129 passed, 14 failed, 13 skipped.
  - Bin unit tests: 1175 passed, 0 failed, 11 ignored.
  - help_cli: 16 passed. help_coverage: 2 passed.
  - No new compiler warnings.

## Repository Baseline

| Item | Value |
|---|---|
| Branch | `help-system-and-fixes` |
| Commit | `277f996300089269640dc5a962d01942aa871ccc` ("Bump version to 1.0.2-beta") |
| Working tree at start | Uncommitted Stage 1 and Stage 2 changes in 29 files (4 docs, 24 sources, `tests/help_cli.rs`), plus `?? docs/reviews/` containing the three earlier reports. |
| Toolchain | rustc/cargo 1.98.1 (Gentoo system toolchain). No rustup. |
| Preservation | No reset, clean, stash, revert or reformat was run. Stage 1 and Stage 2 work is intact; the cross-stage regressions below confirm it. |
| Also present | `?? .claude/` (Claude Code `settings.json`/`settings.local.json`, written outside this work). It was not touched and should not be committed with this change. |

**Baseline tests, measured before any Stage 3 change.** The same safe command and skips as Stages 1 and 2 were used:

| Suite | Result |
|---|---|
| Unit tests, lib target | 1129 passed, 14 failed, 13 skipped |
| Unit tests, bin target | 1133 passed, 14 failed, 13 skipped |
| `tests/help_cli.rs` | 16 passed |
| `tests/help_coverage.rs` | 2 passed |

This matches the Stage 2 report exactly. The brief's "18 help CLI tests" are help_cli (16) plus help_coverage (2).

## Build Reproducibility

### Dependency resolution and the zip finding

| Question | Finding |
|---|---|
| Is resh a deployable binary? | Yes. It is one package with a `resh` bin target (and a lib target used by the bin). A tracked lockfile is the right policy. |
| ZIP dependency | `zip = "0.6"` resolves to **0.6.6** from crates.io (checksum `760394e2…`). It is used directly by `archiveh.rs` only. |
| Yank status | The live crates.io index (`index.crates.io/3/z/zip`) shows `yanked: false` for **every** 0.6.x release. The original H4 reproduction ("failed to select a version") does not reproduce: a fresh `cargo generate-lockfile` for `zip = "0.6"` in an empty crate selects 0.6.6. The releases appear to have been un-yanked since the review. |
| zip advisories | RUSTSEC-2026-0367, -0368 and -0369 affect `ZipArchive::extract()` and `ZipStreamReader::extract()`: SUID bits, symlinks and permissions through symlinks. **resh never calls them.** Its own extractor (`extract_zip_archive`) writes regular files only, with `create_new`, applies no entry modes and creates no symlinks. Not reachable. |
| Minimum safe change for zip | **None required.** Moving off zip 0.6 (the fixes are in ≥ 9.0) is a major API migration of the archive writer and reader. Under the stop conditions it needs approval, and it is not needed for a reproducible build. |
| Change made | `tar` 0.4.44 → **0.4.45**, a lockfile-only, semver-compatible patch. It fixes RUSTSEC-2026-0067 (`unpack_in` can chmod through symlinks) and RUSTSEC-2026-0068 (PAX size headers ignored). The plugin engine called `Archive::unpack`, so this was reachable before SEC-06. The diff is exactly the tar `version` and `checksum` lines, and `cargo metadata --locked` accepts it. `cargo update -p tar` would also have reshuffled unrelated Windows-only `windows-sys` edges, so it was not used. |

### Lockfile, toolchain and clean-checkout results

- **`.gitignore`:** the `Cargo.lock` line is removed, with a comment saying why. `Cargo.lock` now shows as untracked (`??`) and must be added in the commit. The index was not touched.
- **Toolchain:**
  - The highest `rust-version` declared by a locked dependency is **1.88** (`home` 0.5.12, `ignore` 0.4.32). Edition 2024 alone needs 1.85.
  - `rust-version = "1.88"` was added to `Cargo.toml`, after verification.
  - README and CONTRIBUTING said "Rust 1.70 or later". That was wrong, and both now say 1.88. The README build step now uses `--locked`.

**Clean-checkout verification.** The tree was exported with `git ls-files -co --exclude-standard`, so it contains exactly what a commit of this working tree would contain, including `Cargo.lock`.

| Run | Cargo home | Toolchain | Commands | Result |
|---|---|---|---|---|
| Fresh resolution | **empty**, new directory; every crate downloaded from crates.io | 1.98.1 | `cargo metadata --locked`, `check --locked --all-targets`, `build --locked --all-targets`, `test --locked --no-run` | all exit 0 |
| Toolchain floor | (crates already fetched by the run above) | **1.88.0** (official standalone tarball, sha256 verified, installed under the scratch directory only) | `build --locked --all-targets`, `test --locked --no-run` | all exit 0 |
| Final tree, re-exported after all Stage 3 edits | same | 1.98.1 and 1.88.0 | `build --locked --all-targets` | both exit 0; `Cargo.lock` byte-identical afterwards |

A disposable container build was attempted first (`rust:1.88-bookworm`). The host's Docker daemon cannot start any container (`failed to start shim: … unsupported protocol`), so the scratch-directory approach above was used instead. Fixing the daemon needs an administrator restart, which would also affect the long-running `n8n` containers on this host. It was not attempted.

### Remaining dependency risks

These come from matching `Cargo.lock` against the RustSec advisory database (snapshot `999ec89d`, 2026-10-17) with a small script. `cargo-audit` was not installed on the host. Only items with some relevance are listed:

| Crate (locked) | Advisories | Reachability in resh | Fix |
|---|---|---|---|
| rustls 0.23.35, rustls-webpki 0.103.8 | RUSTSEC-2026-0049, -0098, -0099, -0104 (certificate name constraints, CRL handling, CRL panic), -0285, -0346, -0348, -0349 | **Reachable.** This is the TLS stack for reqwest (plugin registry, `http`) and sqlx. Cross-checked against the advisory text: name-constraint and CRL defects weaken certificate validation in edge cases, but chain-of-trust validation is intact. The SEC-07 test with a self-signed certificate is correctly rejected. | Semver-compatible patch releases exist (rustls ≥ 0.23.46, webpki ≥ 0.103.13). **Not applied:** the brief forbids unrelated upgrades. **Recommended for approval.** |
| zip 0.6.6 | RUSTSEC-2026-0367/0368/0369 | Not reachable (see above) | Major migration; needs approval |
| sevenz-rust 0.5.4 | RUSTSEC-2026-0245 (path traversal, no fix), -0246 (unmaintained) | **Not reachable.** It is declared in `Cargo.toml` but never referenced in `src/`. | Removing the unused dependency is recommended. Not done: it is not needed for the build. |
| git2 0.18.3 | RUSTSEC-2026-0008, -0183, -0184 (unsound) | Partly reachable (libgit2 bindings) | Needs git2 ≥ 0.21, an API migration |
| time, bytes, quinn-proto, h2, crossbeam-epoch, anyhow, rand, event-listener, quick-xml, lettre | various DoS and unsound advisories | Mostly transitive, or specific to a server or feature | Patch bumps exist for most; not applied |
| ring 0.16.20, trust-dns-*, zbus 3, async-std, instant, derivative, unsafe-libyaml | unmaintained | n/a | Planned upgrades |

The full matched list is reproducible with the script recorded in the Regression Test Results section.

## Test Repair Matrix

Every test below was reproduced first, then corrected and re-run. In each case "Verification" means: the test passes in both the lib and bin builds, and the final full suite passes.

| # | Test | Original failure | Root cause | Correction |
|---|---|---|---|---|
| 1 | `userh::tests::test_groups_verb_exclude_system_groups` | expected 2 groups, got 0 | **Test defect.** It built a populated `MockBackend` and then called `handle.groups()`, which creates a **new, empty** backend. | Calls `groups_user(&target, &options, &backend)`. The filter now runs against the mock. |
| 2 | `…test_groups_verb_exclude_primary` | 0 ≠ 1 | Same | Same |
| 3 | `…test_groups_verb_exclude_supplementary` | 0 ≠ 1 | Same | Same |
| 4 | `…test_groups_verb_group_name_filter` | 0 ≠ 1 | Same | Same |
| 5 | `…test_groups_verb_no_groups_warning` | wrong warning ("did not exist") | Same: the user was missing from the empty backend | Same. Now asserts "no groups matching". |
| 6 | `…test_groups_verb_includes_groups` | 7 ≠ 6 verbs | Stale expectation: `exists` was added as a 7th verb | Asserts 7 verbs, including `exists` |
| 7 | `…test_unlock_verbs_includes_unlock` | 7 ≠ 5 verbs | Stale expectation | Asserts the exact verb list |
| 8 | `…test_unlock_protect_system_user` | "Expected SystemUserUnlockProtected error" | **Test defect.** The mock with a locked `root` was built but never used, so the empty backend reported the user as missing. **System-user protection was untested.** | Calls `unlock_user(…, &mut backend)`. Asserts the specific `SystemUserUnlockProtected("root", 0)` variant, that `root` is **still locked**, and that uid 999 is protected too. |
| 9 | `…test_unlock_force_system_user` | missing "system user" warning | Same | Mock wired in. Asserts the warning, `changed`, and that `force=true` really unlocks. |
| 10 | `…test_unlock_dry_run` | `was_locked` None | Same | Mock wired in. Asserts the account is **still locked** after the dry run. |
| 11 | `…test_unlock_text_format_output` | missing `"Existed     : yes"` | Stale expectation. The lock and unlock formatters deliberately share an 11-column layout, and the passing lock test asserts `"Existed    : yes"`. | Asserts the shared layout, plus the `Missing` line |
| 12 | `gith::tests::test_connection_not_found` | expected `ConnectionNotFound` | Stale expectation. Since the initial commit, an unregistered alias gets an empty default profile, and nothing in production registers aliases. The CLI would not work otherwise. | Asserts that an unregistered alias gets an **empty** profile and never another alias's credentials, and that a registered alias still gets its own |
| 13 | `gith::tests::test_status_integration_detached_head` | `working_tree.clean` false | Test defect in the fixture. `set_head_detached` ran **before** `checkout_head`, which left `file2.txt` staged. resh reported this correctly; confirmed with a diagnostic print. | The fixture does what `git checkout <sha>` does (`checkout_tree`, then `set_head_detached`) and asserts that `file2.txt` is gone |
| 14 | `gith::tests::test_validate_tag_config_delete` | wrong error message | **Production dead code.** The "names array cannot be empty" branch was unreachable, because `has_names` already implied non-empty. An empty array was still rejected, but with the generic message. | `validate_tag_config` checks an explicit empty `names` first. **Message only:** what is accepted and rejected is unchanged. |

**Meaningfulness check:** with the system-user guard temporarily disabled (`if false && …`), `test_unlock_protect_system_user` fails. The original code was restored and re-verified.

All user tests use `MockBackend`. Under `cfg(test)` the system backend refuses to run commands, so no real account can be modified. Git tests use temporary repositories only, and the Stage 2 fast-forward-only tests still pass.

## Security Closure Matrix

| ID | Finding | Status | Evidence | Remaining Risk |
|---|---|---|---|---|
| SEC-06 | Plugin artifact symlinks and hard links could copy host files into the store (with mode 0755) | **CLOSED, verified** | 6 new tests with a private sentinel file; mutation checks against the original code (6 failures); no sentinel bytes or stray links in the store | Check-then-use races inside the user's own store (unchanged from Stage 1). Artifacts that legitimately contain links are now refused. |
| SEC-07 | Unverified artifacts accepted; plain-HTTP registries accepted | **CLOSED within the existing trust model, verified** | 7 new tests using a loopback mock registry; mutation checks (3 failures); live check: a self-signed certificate is rejected with TLS alert 48 *unknown CA* | Registry checksums come from the same origin as the artifact, so authenticity rests on HTTPS and the registry operator; there is no publisher signature. `source=url` now needs `verify=none` (owner decision). The TLS-stack advisories need a patch bump. |
| SEC-08 | Package restore names, inconsistent booleans (`allow_symlinks=no`), ignored timeouts | **CLOSED for the items in the brief, verified** | 10 new tests (archive, file, plugin, user, http, pkg restore, firewall timeout, git timeout) | Non-security booleans elsewhere still use their own parsing. Git operations are not time-limited. `pkg info`/`search`/`list_installed` do not validate names (argv only, read-only). |

### SEC-06 — Plugin artifact link traversal

**Lifecycle reviewed:**

1. Download, or file read.
2. Optional SHA-256 verification.
3. `extract_artifact` into `<store>/<id>/.staging/<uuid>`.
4. `PluginStore::install_plugin`: remove the old version directory, `copy_directory` from staging, make the binary executable, write metadata.
5. `activate_version` (`current` link).
6. `cleanup_staging`.

**Root cause:**

- `extract_tar_gz` used `Archive::unpack`. Artifact symlinks were created in staging, and before tar 0.4.45 `unpack_in` could also chmod through them.
- `copy_directory` then used `is_dir()` and `fs::copy`, both of which **follow** symlinks. A `bin/plugin -> ~/.ssh/id_ed25519` entry therefore copied the private key into the store.
- `install_plugin` then ORed `0o755` onto the copy's mode, making it world-readable.
- A link to a directory was copied recursively.
- A failed install left staging behind.

**Correction** (`engine.rs`, `store.rs`; no new package format):

- **Extraction, entry by entry:**
  - Only `Regular` and `Directory` entries are accepted.
  - `Symlink`, `Link`, `Char`, `Block`, `Fifo` and any other type fail the whole extraction, with "symbolic and hard links are not allowed in plugin artifacts" or "unsupported entry type".
  - Paths go through `artifact_relative_path`: only normal components, `.` dropped. Absolute paths, `..` and prefixes are rejected, never rewritten.
  - Directories are created one level at a time, refusing any existing non-directory or symlink (`create_dirs_no_follow`).
  - Files are created with `create_new` plus `O_NOFOLLOW` (`create_new_no_follow`). Their mode is reduced by `sanitized_mode` to 0755 if any execute bit is set, otherwise 0644. setuid, setgid, sticky and group/other write bits are never kept.
- **`copy_directory` (defense in depth):**
  - It uses `DirEntry::file_type()`, which does not follow links.
  - Source files are opened with `O_NOFOLLOW` and destination files are created with `create_new` plus `O_NOFOLLOW`.
  - Any symlink or special file fails the copy, and the partially copied version directory is removed with the guarded `remove_tree`.
  - The source root must be a real directory.
- **Binary handling:** `find_binary_path` uses `symlink_metadata`, so a link is never taken as the binary. `install_plugin` refuses a binary that is not a regular file and sets exactly 0755.
- **Failure handling:**
  - A failed extraction or install calls `cleanup_staging`, which is confined by the Stage 1 `ensure_inside_store` and `remove_tree`.
  - The existing installed version is untouched, because `install_plugin`, the only code that removes a version directory, runs only after a successful extraction.
- **Reused from Stage 1:** `validate_path_component`, `ensure_inside_store` and `remove_tree`.

**Regression tests** (`engine::artifact_security_tests`). Each test uses its own `TempDir` store and a private sentinel at `secret/id_ed25519` (0600) outside the store.

| Test | Shows |
|---|---|
| `valid_artifact_installs_with_sanitized_modes` | A normal artifact installs. A `04755` binary becomes `0755`, and a `0666` file has no special or group/other-write bits. |
| `symlink_to_private_file_is_rejected_and_not_copied` | Absolute, relative-escaping and top-level links to the sentinel are all refused. No version or `current` link is created, staging is cleaned, no sentinel bytes are in the store, and the sentinel keeps mode 0600. |
| `hard_link_to_private_file_is_rejected` | Absolute, escaping and internal hard links are all refused |
| `escaping_paths_and_special_files_are_rejected` | `../../../x`, `bin/../../x`, an absolute path, char/block devices and a FIFO are refused, and nothing appears outside the store |
| `malicious_reinstall_leaves_existing_plugin_untouched` | A forced reinstall with a malicious artifact fails, and the installed binary, the `current` link and the contents are unchanged |
| `store_copy_refuses_links_in_staging` | Links planted directly in staging are refused by the store copy, and the version directory is removed |

**Mutation checks:**

- With both layers reverted to the original code (`unpack` plus the following copy), 6 of the SEC-06 tests fail.
- With only the extraction reverted, 4 fail: the copy layer alone still blocks the sentinel copy, but escaping paths and the error contract are no longer enforced.
- The originals were restored and byte-compared.

### SEC-07 — Registry transport and checksum integrity

**Existing trust model:**

- A registry is `GET {registry}/v1/plugins/{id}` returning versions and per-platform `sha256`. The artifact comes from `{registry}/v1/artifacts/{id}/{version}/{bin}`.
- `source=url` and `source=file` have no checksum.
- The default `verify=sha256` used to pass with "No checksum to verify".
- reqwest uses rustls with certificate verification on. Nothing in the plugin code disables it; checked by grep.
- reqwest followed redirects with no scheme restriction.

**Correction** (`registry.rs`, `engine.rs`, `pluginh.rs`; no protocol change, no signing framework):

- **`require_https`:**
  - The scheme must be `https` and a host must be present. `http`, `file`, `ftp`, and anything else are refused before any request.
  - It is applied to the registry URL, to `source=url`, and again in `download_artifact`. A registry given as a local file path is still allowed: there is no transport involved.
- **`https_only(true)`** is set on the HTTP client, so a redirect from HTTPS to HTTP is refused too. TLS verification stays on.
- **`parse_sha256`:** exactly 64 hex digits, normalised to lower case. `verify_checksum` compares only against a parsed value.
- **`check_integrity_metadata`** runs at resolve time, before any download and in dry run too. With `verify=sha256`:
  - A registry artifact must have a well-formed checksum. Empty, malformed or missing values give `PLUGIN_VERIFY_FAILED`.
  - A `source=url` artifact is refused, with a message pointing at `verify=none`.
  - A `source=file` artifact (local, no transport) is accepted.
- **`verify_artifact`** fails closed for a remote artifact without a checksum. Verification still runs **before** extraction.
- **Malformed `verify=`** values are an error. They used to silently become `sha256`.
- **Test seam:** plain HTTP to 127.0.0.1/localhost is allowed only under `#[cfg(test)]`, through a thread-local switch. Production builds have no development mode, and the brief's condition for one ("an explicitly documented existing development-only mode") did not exist.
- **Documentation:** `docs/Automation_Utilities/plugin.md` now describes the HTTPS, checksum and artifact-content rules, and states the limits of the checksum: from the same source, it proves integrity, not authenticity.

**Regression tests** (`engine::artifact_security_tests`, using an `httpmock` server on loopback; no real plugin is downloaded):

| Test | Shows |
|---|---|
| `plain_http_transport_is_refused_and_never_contacted` | `require_https` accepts and rejects the right URLs. Without the seam, an HTTP registry and an HTTP URL source (even with `verify=none`) are refused in dry and real runs. The mock records **0 hits**. |
| `valid_checksum_installs` | A valid upper-case checksum: downloaded once, "Checksum verified successfully", installed |
| `missing_or_malformed_checksum_fails_before_download` | `""`, whitespace, `"00"`, 63 hex digits and non-hex fail with `PLUGIN_VERIFY_FAILED` in dry and real runs, with **0 artifact downloads** and nothing installed |
| `mismatched_checksum_downloads_but_never_extracts_or_installs` | Downloaded, verification fails, no extract or install action, nothing installed, staging cleaned |
| `download_failure_installs_nothing` | HTTP 404 gives `PLUGIN_DOWNLOAD_FAILED` and nothing installed |
| `url_source_needs_explicit_verify_none` | Refused with `verify=sha256` and 0 downloads; installs with an explicit `verify=none` |
| `verify_checksum_parses_strictly` | Case, whitespace, length and mismatch handling |
| `pluginh::dry_run_tests::verify_mode_and_switches_parse_strictly` | `verify=sha265/md5/""/NONE/off` are rejected |

**Live checks** (built binary, `XDG_DATA_HOME` pointed at the scratch directory, local `openssl s_server` with a self-signed certificate):

- HTTPS download and HTTPS registry fail. On the server side, the client aborted with **TLS alert 48 (unknown CA)**, while `curl -k` against the same server returned HTTP 200.
- An `http://` registry is refused before any connection, with an explicit message.
- `source=url` without `verify=none` gives `PLUGIN_VERIFY_FAILED`, exit 4.
- `verify=sha265` gives an error.
- The real `~/.local/share/resh/plugins` was unchanged (timestamp 2026-10-16).

**Mutation check:** with `check_integrity_metadata`, the fail-closed branch and `require_https` disabled, 3 of the SEC-07 tests fail.

**Compatibility implications for the owner:**

1. **`source=url` installs** now fail under the default `verify=sha256`. The registry protocol offers no trusted checksum for a bare URL. The options are to document `verify=none`, which is what Stage 3 did, or to approve a new `sha256=` install argument, which would be a CLI addition. The second was not done.
2. **`http://` registries**, including local development registries, no longer work at all.
3. **Artifacts containing links** are refused. No in-repo plugin uses them.

### SEC-08 — Remaining unsafe input validation

**Package restore** (`pkgh.rs`):

- `validate_lockfile` runs before manager detection, the dry-run plan and any command. It now checks every lockfile package:
  - The name goes through `check_lockfile_pkg_name`: the Stage 1 `check_pkg_token` rules (no leading `-`, no shell characters), **plus** no `://`, no `..` segment, and no package-file suffix (`.rpm`, `.deb`, `.apk`, `.pkg.tar*`).
  - The version and arch go through `check_pkg_token`.
- Why the extra name rules: `check_pkg_token` deliberately allows `:` and `/` (epochs, Homebrew taps). That lets `https://evil/x.rpm` or `tmp/evil.rpm` through, and `dnf install` installs a URL or a local file.
- install and remove keep the Stage 1 rule unchanged, so their behavior is unchanged.
- **Tests:**
  - `restore_rejects_hostile_lockfile_names_before_running_anything`: shell syntax, leading dashes, URLs, absolute and relative package files, `..`, empty names and a bad version, in JSON and in text lockfiles. A sentinel file is never created.
  - `valid_lockfile_names_still_pass_restore_validation`.

**Security-relevant booleans.** These now use the shared Stage 1 `lenient::bool_arg`: `true/false/1/0/yes/no/on/off`, case-insensitive, anything else an error.

| Handle | Options | Old parsing | Old danger |
|---|---|---|---|
| archive | `allow_symlinks`, `allow_absolute_paths`, `allow_parent_traversal`, `overwrite`, `follow_symlinks` | `parse::<bool>().unwrap_or(default)` | **`allow_symlinks=no/0/off` → true** (weakened a control). Others silently fell back. |
| file | `follow_symlinks` (find), `overwrite` (copy, move, rename helper), `recursive` and `force` (delete), `recursive` (chown), `create_parents`/`atomic` (rename helper) | `== "true"`, or `true/1/yes` only | `on` read as false; malformed values silently ignored |
| plugin | `force`, `allow_downgrade`, `strict`, `purge`, enable/disable `force`; `verify` | `== "true"`; unknown verify became sha256 | silent fallback |
| user | `force` in all 5 option parsers (it overrides the system-account protection) | `parse().unwrap_or(false)` | silent fallback |
| snapshot | restore `force` | `== "true"` | silent fallback |
| cert | `overwrite` (5 parsers; private-key output) | `true/1/yes` | silent fallback |
| firewall | `rules.save` `overwrite` | `== "true"` | silent fallback |
| http | `allow_insecure` (disables TLS verification) | `== "true"` | silent fallback |

Only `allow_symlinks` was dangerous in the "more permissive" direction. The others ignored malformed or `on`/`yes` values in the safe direction, but violated "malformed values must fail explicitly". Non-security booleans (`preserve_*`, `create_home`, …) were not changed, so there was no repository-wide rewrite.

**Tests:**

- `archiveh::extract_safety_tests::allow_symlinks_false_spellings_are_honored` (end to end: no link extracted for `false/no/0/off/NO/Off`) and `…malformed_security_booleans_are_rejected`.
- `fileh::relative_dir_tests::destructive_switches_parse_strictly`: a malformed `recursive`/`force`/`overwrite` changes nothing, and `recursive=on` and `overwrite=on` work.
- `userh::dry_run_tests::force_parses_consistently_and_rejects_garbage`.
- `httph::allow_insecure_tests::allow_insecure_parses_strictly`.
- The plugin test listed under SEC-07.

**Timeouts:**

- **Firewall `timeout_ms`: enforced.**
  - `run_command_with_timeout` wrapped a blocking `Command::output()` in `tokio::time::timeout`, so it could never fire.
  - It now spawns the child (stdin null, pipes drained) and waits with the Stage 2 backup mechanism `backuph::wait_with_deadline`, made `pub(crate)`. That kills and reaps the child at the deadline. No new timeout subsystem was added.
  - Tests in `firewallh::timeout_tests`, using per-test mock executables through the Stage 2 seam:
    - a hung command is killed within 0.3–5 s and its pid no longer exists;
    - the exit code, stdout and stderr are kept;
    - 400 KB of output does not deadlock;
    - a missing command is an error.
  - The unused `tokio::time::timeout` import was removed.
- **Git `timeout_ms`: rejected.**
  - Every git verb wraps a fully blocking libgit2 call, so neither an explicit timeout nor the built-in defaults could fire.
  - The locked git2 0.18.3 has no connect or server timeout options, and push progress callbacks cannot abort. Real enforcement would need a git2 upgrade (an API migration, which is a stop condition) or abandoning a worker thread mid-operation. The second can leave `.git/index.lock` behind, or report a timeout for a push that then completes.
  - So, as the brief directs, `GitHandle::call` refuses any explicit `timeout_ms` with exit 2 and a stderr reason, before anything runs.
  - `[timeout_ms=<n>]` was removed from the 10 git usage strings. `help_coverage` still passes and no golden file changed.
  - `docs/Packages_Software/git.md` says git steps are not time-limited and suggests `timeout(1)`.
  - Test: `gith::timeout_rejection_tests::explicit_timeout_is_rejected_before_anything_runs`. Eight verbs are refused with exit 2 and no output, the repository HEAD and branches are unchanged, and `status` without `timeout_ms` still works.
  - **Compatibility:** scripts that pass `timeout_ms` to git, for example `status_short` in a prompt, now get exit 2. They must drop the argument.

## Skipped Test Assessment

The legacy command skipped 13 tests by name. Eleven of them were "skipped" only by that filter: when run without their environment variables they `return` early and are reported as **passed**. That is the vacuous-pass problem the brief warns about.

| # | Test | Original reason | Stage 3 strategy | Result in Stage 3 |
|---|---|---|---|---|
| 1 | `pluginh::tests::test_disable_verb_recognized` | Wrote the real `~/.local/share/resh/plugins` | **Converted.** New `#[cfg(test)]` per-thread seam `plugin::store::test_seam` redirects `PluginStore::default_plugins_dir()` to a `TempDir`. The test also asserts "not installed" and that the temporary store was used. | **Runs by default, passes.** The real plugin directory's mtime is unchanged after the full suite. |
| 2 | `gith::tests::test_timeout_functionality` | Real clone of `192.0.2.1` into fixed `/tmp/timeout_test`; could hang about 2 minutes | **Converted** to be hermetic: a nonexistent local `file://` source and a `TempDir` destination. It asserts a fast failure (under 10 s) and no `.git` left behind. The timeout aspect is covered by the new rejection test. | **Runs by default, passes** |
| 3 | `gith::tests::test_https_public_repo_integration` | Needs `TEST_GIT_CLONE_HTTPS_URL` | `#[ignore = "needs a real remote…"]` | Ran with `--ignored` against a **disposable local bare repository** (`file://`): passes |
| 4 | `gith::tests::test_pull_https_integration` | Needs `TEST_GIT_PULL_*` | `#[ignore]` | Same: passes |
| 5 | `gith::tests::test_push_https_integration` | Needs `TEST_GIT_PUSH_*`; performs a real push | `#[ignore = "performs a real git push…"]` | Same: passes; the push went only to the scratch bare repository |
| 6–9 | `dbh::tests::test_postgres_{integration, tables_integration, schema_integration, exec_integration}` | Need a live PostgreSQL; run DDL/DML | `#[ignore = "needs a disposable PostgreSQL server…"]` | Ran against a **disposable PostgreSQL 16.10**. Initially 3 of 4 failed; see below. After fixes: **4/4 pass**. |
| 10–13 | `dbh::tests::test_mysql_{integration, tables_integration, schema_integration, exec_integration}` | Need a live MySQL | `#[ignore = "needs a disposable MySQL server…"]` | Ran against a **disposable MariaDB 11.4.8**. Initially 1 of 4 failed with a panic; see below. After the fix: **4/4 pass**. |

**What running them for the first time found:**

- **Test defect (pg and mysql exec/schema):** `CREATE TEMP TABLE` followed by use in a later `exec`. Each call can get a different pooled connection, and temp tables are per session. The tests now `DROP TABLE IF EXISTS` and create ordinary tables in the disposable database.
- **Production defect (PostgreSQL):**
  - `SELECT 1` failed with "Rust type `Option<i64>` (INT8) is not compatible with SQL type INT4". Every INT2/INT4 column failed in `row_to_json_postgres`, and FLOAT4 likewise.
  - Worse, the second decoder (the column-by-index path) silently turned those values into JSON `null`.
  - Fixed with width-correct `pg_get_int` and `pg_get_float`, used in both places.
  - NUMERIC still cannot be decoded without an extra sqlx feature. That is documented, not changed.
- **Production defect (MySQL/MariaDB):** `db … tables table=<t>` **panicked**, because `describe_table_mysql` read the unsigned `information_schema.columns.ordinal_position` as `i32`. It now reads `u32`, as `schema_mysql` already did and as works on MariaDB. This confirms the original review's suspected typed-row panic.

**Disposable infrastructure used.** None of it is reachable from outside the host, and it was all torn down afterwards.

- **PostgreSQL:** official zonky `embedded-postgres-binaries` 16.10.0 jar from Maven Central (SHA-1 checked against Maven's published `.sha1`).
- **MariaDB:** official 11.4.8 bintar (SHA-256 checked against MariaDB's `sha256sums.txt`), with a 3-function no-op `libsystemd.so.0` stub compiled in the scratch directory, because the host has no libsystemd.
- **Isolation:** both ran unprivileged in `bwrap`, with the host root read-only, a private `/tmp`, PID/IPC namespaces and `--die-with-parent`. Only scratch data directories were writable. Each listened on 127.0.0.1 only (ports 55432 and 53306) with throwaway trust or empty-password users.
- **Not used:** no production credentials. The `n8n` PostgreSQL container on this host was not touched.

**Default suite after Stage 3:** `cargo test --locked` gives **0 filtered out, 11 ignored, 0 failed**. The `--skip` list is no longer needed. Ignored tests are listed by name, with their reasons, in the test output, so they are never counted as passing.

**Still environment-dependent, but run by default and passing** (unchanged from earlier stages): 6 `mailh::mail_dns_resolution_tests` (DNS and localhost:587) and the memcached `cacheh` tests, which try 127.0.0.1:11211 and pass either way.

## Compatibility Matrix

**Method:**

- The host Docker daemon cannot start containers, and no VM tooling is installed.
- Package managers were therefore exercised by running the **host-built `resh`** with a `PATH` of wrapper scripts.
- Each wrapper runs the requested tool (`apt-get`, `dpkg-query`, `dnf`, `rpm`, `yum`, `pacman`, `apk`, `rc-service`, …) inside an unprivileged `bwrap` user-namespace sandbox whose root is an **official distribution image**. Each image was pulled from the Docker Hub registry API with verified layer digests and extracted with Python's `tar` filter.
- Inside the sandbox the tool runs as namespace-root. Only the scratch rootfs and the host's `resolv.conf` are visible.
- **Nothing was installed or removed on the host, and no host service was changed.**
- The extraction filter refused one Arch Linux layer member that would have been written through an absolute symlink onto the host's `/usr/lib/os-release`. The pull script was adjusted to replace such links instead.

**Scenario per package manager:**

1. install `dry_run`
2. install with `update_cache`
3. repeat install (no-op)
4. `info`
5. `search`
6. `list_installed prefix`
7. install a nonexistent package
8. install a hostile name (`jq;id`)
9. remove `dry_run`
10. remove
11. remove a nonexistent package with `fail_if_missing`
12. `update check_only`

The installed state was checked independently after each step, with `dpkg -s`, `rpm -q`, `pacman -Q` or `apk info -e`.

| Environment | Test Type | Result | Limitations |
|---|---|---|---|
| apt (Debian bookworm-slim, apt 2.6.1) | Real package manager in a disposable sandbox | **11/12 correct at default settings**, after one fix; `search` succeeds only with a larger `timeout_ms` (see Limitations). dry runs changed nothing; install, remove and no-op were confirmed by `dpkg -s`; failures exited 1 with a reason; the hostile name was rejected before any command. **Defect found and fixed:** `search` ran `apt search`, whose 2-line output was misparsed, so summaries became package names. It now uses `apt-cache search`, and the results were re-verified (`jq | lightweight and flexible…`). | `search` with the default 5 s timeout timed out in the sandbox. It passed in 82 s with `timeout_ms=300000`, because resh runs `apt-cache policy`/`show` per match before applying `limit` (efficiency issue, recorded). Needed `APT::Sandbox::User "root"` (a user-namespace artifact). |
| dnf (Fedora 42, dnf5 5.2.18) | Same | **12/12 correct** | The first run failed for a sandbox reason: bwrap drops capabilities by default, and rpm could not write the 0555 `/usr/bin` (plain `dnf` failed the same way). Re-run with namespace-confined `--cap-add ALL`. |
| yum (Amazon Linux 2, yum 3.4.3 — real yum v3, not the dnf alias) | Same | **11/12 correct.** `search` timed out at the default 5 s; it passed in 15 s with a larger `timeout_ms`. Results contain the same name twice (one per architecture). | Needed sandbox-only settings: `/etc/yum/vars` (`awsregion`, `awsdomain`) and resolver timeouts. |
| pacman (Arch Linux latest, pacman 7.1.0) | Same | **12/12 correct** | `DisableSandbox` and no `CheckSpace` in the sandbox `pacman.conf` |
| apk (Alpine 3.20, apk-tools 2.14.4) | Same | **12/12 correct** | — |
| brew | — | **NOT EXECUTED** | Homebrew on Linux needs a large non-root prefix image (homebrew/brew, over 1 GB) and does not run as root. Not practical without Docker. Command construction is covered only by the Stage 1 argv unit tests. |
| systemd | Parser/helper level only | **NOT EXECUTED live.** Instance names (`getty@tty1` → `getty@tty1.service`) and `LoadState=not-found` handling are covered by the Stage 2 unit tests, which still pass. | This host runs OpenRC. A real systemd needs a booted, privileged container, which the brief forbids provisioning. |
| OpenRC (host, read-only) | Real host services, status queries only | `status` of a running service: exit 0, `running`. Missing service: exit 1 with a reason. `getty@tty1` (systemd-style): exit 1, "does not exist", which is correct for OpenRC. `-H`: exit 2. `is-enabled`: correct. | No mutation on the host |
| OpenRC (Alpine sandbox, openrc installed) | Real `rc-service`/`rc-update` with dummy services `resh-dummy` and `resh-dummy.inst1` | `enable`/`disable` really changed the sandbox runlevel. `is-enabled` was correct. The OpenRC dotted instance name was passed intact. Every failure exited 1 with the tool's reason. | **Successful start/stop not verified:** without a booted OpenRC (no sysinit runlevel), `rc-service start` refuses with "already starting" whatever the caller. No daemons were left behind. |
| PostgreSQL 16.10 (disposable) | 4 integration tests plus live CLI | **All pass after the fixes.** CLI: `ping` exit 0. A wrong port gives exit 1 "connection failed". A syntax error gives exit 1 `db.query_failed`. INT2/INT4/INT8/FLOAT4/FLOAT8 decode correctly. | NUMERIC decoding is unsupported (documented) |
| MySQL-compatible: MariaDB 11.4.8 (disposable) | 4 integration tests plus live CLI | **All pass after the fix.** CLI: `tables` works (it panicked before). A missing table gives exit 1 with error 1146. A wrong password gives exit 1 with error 1045. | Oracle MySQL itself was not run; MariaDB was used. MariaDB reports a nullable column's default as the string `"NULL"` (cosmetic). |
| SQLite | Existing unit tests | Pass (unchanged) | — |

## Regression Test Results

**Final default suite** (no skip filters needed any more):

```
env -u MAIL_SMTP_USERNAME -u MAIL_SMTP_PASSWORD -u TEST_POSTGRES_DSN -u TEST_MYSQL_DSN \
    -u TEST_REDIS_URL -u TEST_MEMCACHED_ADDR -u TEST_GIT_CLONE_HTTPS_URL \
    -u TEST_GIT_PULL_HTTPS_URL -u TEST_GIT_PUSH_HTTPS_URL \
  cargo test --locked --no-fail-fast
```

| Suite | Baseline (before Stage 3) | After Stage 3 |
|---|---|---|
| `cargo check` / `build --all-targets` (`--locked`) | pass | **pass** |
| Unit tests, lib target | 1129 passed, 14 failed, 13 skipped (filtered) | **1171 passed, 0 failed, 11 ignored, 0 filtered** |
| Unit tests, bin target | 1133 passed, 14 failed, 13 skipped | **1175 passed, 0 failed, 11 ignored, 0 filtered** |
| `tests/help_cli.rs` | 16 passed | **16 passed** |
| `tests/help_coverage.rs` | 2 passed | **2 passed** |
| Compiler warnings, lib / bin / lib test / bin test | 287 / 421 / 357 / 483 | **287 / 421 / 347 / 473** (no new warnings) |

**How the counts reconcile:** 1129 + 14 repaired + 2 converted + 26 new = **1171**. The 26 new tests by area:

| Area | New tests |
|---|---|
| SEC-06 | 6 |
| SEC-07 | 8 (7 engine, 1 plugin parser) |
| archive booleans | 2 |
| file | 1 |
| user | 1 |
| http | 1 |
| pkg restore | 2 |
| firewall timeout | 4 |
| git timeout | 1 |

**Opt-in infrastructure tests:**

```
TEST_GIT_CLONE_HTTPS_URL=file://…/remote.git … cargo test --lib -- --ignored gith::tests::       # 3 passed
TEST_POSTGRES_DSN=postgres://resh_test@127.0.0.1:55432/postgres \
TEST_MYSQL_DSN=mysql://root@127.0.0.1:53306/resh_test cargo test --lib -- --ignored dbh::tests:: # 8 passed
```

**Cross-stage regression:**

```
cargo test --locked --lib -- archiveh::extract_safety_tests plugin::store::tests plugin::engine::tests \
  proch::tests::pid proch::tests::proc_url proch::tests::resolve_pid proch::tests::kill_stage \
  pkgh::cmdline_safety_tests lenient::tests parse:: core::tests cronh::dry_run_tests userh::dry_run_tests \
  firewallh::dry_run_tests firewallh::backup_tests sshh::tests::exec pluginh::dry_run_tests \
  gith::sync_correctness_tests cronh::tests archiveh::zip_password_tests archiveh::tests::test_password_support \
  svch::tests backuph::timeout_tests backuph::profile_tests fileh::relative_dir_tests snapshot::diff_by_name_tests \
  core::status::tests pkgh::result_status_tests dbh::tests::failed_ping archiveh::tests::test_path_sanitization
→ 134 passed, 0 failed
```

This covers every area the brief lists: archive containment, plugin path containment, PID validation, package argument safety, dry-run enforcement, error reporting, exit codes, firewall backup, git fast-forward-only, cron comment preservation, ZIP password rejection, service identity, backup timeout, relative directories, backup profile isolation, JSON output integrity, and snapshot diff. The full suite has **0 failures**, so all 59 Stage 1 and 47 Stage 2 regression tests pass in both builds.

**Mutation checks** (originals restored and byte-compared each time):

| Change | Result |
|---|---|
| Unlock guard disabled | 1 failure |
| SEC-06, both layers reverted | 6 failures |
| SEC-06, extraction only reverted | 4 failures |
| SEC-07 rules disabled | 3 failures |

**Live checks** (built binary; scratch directory, `XDG_*` redirected, or disposable sandboxes only):

- the SEC-07 TLS and transport checks;
- the database CLI checks;
- the package-manager matrix (58 of 60 scenario runs correct at default settings; apt and yum `search` succeed only with a longer `timeout_ms`);
- the OpenRC checks.

**Advisory scan:** `python3 -I audit.py <advisory-db> Cargo.lock`. It is a short RustSec front-matter matcher kept in the session's scratch directory; `cargo-audit` was not installed on the host.

## Formatting and Clippy Assessment

| Check | Before Stage 3 (end of Stage 2) | After Stage 3 | Classification |
|---|---|---|---|
| `cargo fmt --all -- --check` | fails, 14,994 hunks | fails, **15,126 hunks** | **Pre-existing debt.** The code base has never been rustfmt-formatted. Running rustfmt on just the modified files would rewrite thousands of unrelated lines; `main.rs` alone gives 7,562 hunks because it pulls in every module. Per-hunk formatting (`--file-lines`) is nightly-only. **Not reformatted**, as the brief requires. New Stage 3 code is written in rustfmt style but is not machine-verified per hunk. |
| `cargo clippy --workspace --all-targets` | exit 101, about 1,812 sites | exit 101, **1,800 distinct sites** | Same 5 pre-existing **deny-level** errors (below) plus warnings |

**Deny-level errors** (all pre-existing):

- 4 × `absurd_extreme_comparisons` in `dbh.rs` test code (lines 7011–7142). These are always-true assertions in tests. Not a production defect.
- 1 × `ifs_same_cond` at `mailh.rs:1142`. An unreachable duplicate `else if` in the mail **text formatter**. Display only; not a safety or correctness defect.

**Findings on changed lines:** clippy's output was intersected with every line the working tree adds relative to `HEAD` (Stages 1–3).

- **New in Stage 3:** one `collapsible_if` in `store.rs` `find_binary_path`, on a line Stage 3 touched. **Fixed** with a let-chain, which is stable at the 1.88 floor. One new unused import (`tokio::time::timeout` in firewallh, left over after the timeout fix) was **removed**.
- **Pre-existing hits on changed lines:** the 3 cron `collapsible_if`, the firewall test `type_complexity` and the pkg `available_updates` warning. Stages 1 and 2 already documented all of them.
- **No security- or correctness-relevant clippy finding** was found in Stage 3 code.

**CI readiness.** The repository has **no CI configuration at all**: no `.github/workflows`, `.gitlab-ci.yml` or other config. The brief forbids introducing a new platform, so none was added. These are the release gates Stage 3 recommends, all now green except the two pre-existing lint gates:

```
cargo metadata --locked --format-version 1 >/dev/null
cargo build --locked --all-targets
cargo test  --locked --no-fail-fast            # safe by default; infra tests are #[ignore]
# optional, against disposable services:
TEST_POSTGRES_DSN=… TEST_MYSQL_DSN=… TEST_GIT_*=… cargo test --locked -- --ignored
```

For formatting and lint, adopt an incremental baseline rather than a global gate:

- Run `cargo fmt` once in a dedicated, behavior-free commit approved by the owner, then gate `cargo fmt --check`.
- Gate `cargo clippy -- -D warnings` only after the 5 deny-level errors are fixed, or allow them explicitly with a tracked issue.
- Do not lower lint levels to claim success.

## Remaining Release Risks

**Unresolved security items, none Critical:**

1. **TLS stack advisories:** rustls 0.23.35 and rustls-webpki 0.103.8 (certificate name constraints, CRL handling). These are used by plugin registry downloads, the `http` handle and sqlx. Semver-compatible patch releases exist. **Recommended: approve a lockfile-only bump** of `rustls` and `rustls-webpki`, plus the other patch-level advisories (bytes, time, quinn-proto, h2, crossbeam-epoch, anyhow, rand). **High priority.**
2. **Plugin authenticity:** the registry checksum and the artifact come from the same origin, so a compromised registry is not detected. Fixing that needs a signing scheme, which is out of scope.
3. **Unreachable but present:** `sevenz-rust` (unpatched path traversal; recommend removing the unused dependency) and `zip 0.6.6` (advisories in APIs resh does not call).
4. **git2 0.18.3:** unsound-API advisories and no timeout support. Upgrading needs an API migration.
5. **Unchanged from Stages 1 and 2:** check-then-use races in archive extraction and the plugin store (they need a concurrent local writer), and SMTP password storage (H14).

**Compatibility changes needing owner acknowledgement:**

1. `source=url` plugin installs need `verify=none`. Alternatively, approve a `sha256=` argument.
2. `http://` plugin registries are refused.
3. Plugin artifacts with links are refused.
4. Git `timeout_ms` gives exit 2.
5. Malformed values of the converted booleans are errors; `on` and `yes` are now honored.
6. apt `search` now returns real package names.

**Verification gaps:**

- **Not run at all:** brew, systemd, Oracle MySQL, and real HTTPS git remotes (the git integration tests used a `file://` remote).
- **OpenRC:** the successful start/stop path was not verified.
- **Root:** resh was not run as real root. All mutation tests used namespace-root.
- **Hardware and platforms:** not run on a non-x86_64 architecture or on macOS.

**Functional items found but not fixed** (not release-blocking):

- `pkg search` runs per-match follow-up queries before applying `limit`, so it needs more than the 5 s default on slow systems.
- yum `search` lists a name once per architecture.
- PostgreSQL NUMERIC columns cannot be decoded.
- `pkg info`, `search` and `list_installed` do not validate names (argv only, read-only).
- Plugin `timeout_ms` silently falls back on malformed values.

**Quality debt:** the repository-wide rustfmt and clippy failures described above, and no CI.

## Files Modified in Stage 3

| File | Change |
|---|---|
| `.gitignore` | `Cargo.lock` is no longer ignored |
| `Cargo.lock` (now untracked, to be added) | `tar` 0.4.44 → 0.4.45 only |
| `Cargo.toml` | `rust-version = "1.88"` |
| `README.md`, `CONTRIBUTING.md` | Toolchain 1.88; `--locked` release build |
| `src/handles/security/userh.rs` | TEST-01 (11 tests); SEC-08 `force`; new test |
| `src/handles/system/gith.rs` | TEST-01 (3 tests, including the `validate_tag_config` dead branch); git `timeout_ms` rejection and help usage; TEST-02 conversion and `#[ignore]`; new test |
| `src/handles/pluginh/plugin/engine.rs` | SEC-06 extraction; SEC-07 integrity rule; staging cleanup; 13 tests |
| `src/handles/pluginh/plugin/store.rs` | SEC-06 helpers, no-follow copy and binary handling; TEST-02 store seam |
| `src/handles/pluginh/plugin/registry.rs` | SEC-07 `require_https`, `parse_sha256`, `https_only`, test seam |
| `src/handles/automation/pluginh.rs` | SEC-07 `verify` parsing; SEC-08 booleans; TEST-02 conversion; new test |
| `src/handles/filesystem/archiveh.rs` | SEC-08 booleans (including `allow_symlinks`); 2 tests |
| `src/handles/filesystem/fileh.rs` | SEC-08 booleans; new test |
| `src/handles/filesystem/snapshot.rs`, `src/handles/security/certh.rs`, `src/handles/network/httph.rs` | SEC-08 booleans; new http test |
| `src/handles/security/firewallh.rs` | SEC-08 `overwrite`; enforced `timeout_ms`; 4 tests; unused import removed |
| `src/handles/automation/backuph.rs` | `wait_with_deadline` made `pub(crate)` for reuse |
| `src/handles/system/pkgh.rs` | SEC-08 restore lockfile validation and 2 tests; apt `search` uses `apt-cache` (TEST-03 finding) |
| `src/handles/data/dbh.rs` | PostgreSQL integer and float decoding (TEST-02/03 finding); MySQL `ordinal_position` panic; integration tests made pool-safe and `#[ignore]`d |
| `docs/Packages_Software/git.md`, `docs/Automation_Utilities/plugin.md`, `docs/known_issues.md` | Documentation of Stage 3 behavior |
| `docs/reviews/resh-cli-stage3-build-test-security.md` | This report |

**Unchanged:**

- the handle and verb registration;
- the `Handle` trait, the dispatcher and the provider architecture;
- every help golden file;
- every help text except the 10 git usage strings that no longer list `timeout_ms`.

No dependency was added. Stage 1 and Stage 2 security code was not weakened.

## Stage 3 Recommendation

**STAGE 3 CONDITIONALLY COMPLETE**

**Evidence:**

- **Reproducible build.** A tracked lockfile is ready to commit. Clean, locked builds succeeded from an empty Cargo home on 1.98.1 and on the verified floor 1.88.0. The yanked-zip blocker no longer exists. The only dependency change is a security patch to `tar`.
- **Reliable tests.**
  - All 14 failing tests pass, with meaningful assertions; the user-protection test is mutation-checked.
  - The default suite has 0 failures and needs no skip filters.
  - All 11 infrastructure tests were run against disposable services and pass.
  - The real plugin directory is untouched.
- **Security closure.**
  - SEC-06, SEC-07 and SEC-08 are corrected, with regression tests, mutation checks and live checks.
  - No exploitable defect in resh's own code is known to remain open.
- **Defects found during verification.** Three were found and fixed: apt search parsing, PostgreSQL decoding, and the MySQL `tables` panic.

**Conditions (noncritical):**

1. **Approve the TLS-stack patch bump** (rustls, rustls-webpki) and the other patch-level advisory updates. These are lockfile-only changes, but they are outside the "minimal" mandate.
2. **Acknowledge the compatibility changes** listed above, especially `source=url` with `verify=none`, and git `timeout_ms` rejection.
3. **Verification gaps remain visible:** brew, systemd, the OpenRC start/stop success path, Oracle MySQL, and real HTTPS git remotes.
4. **Quality gates:** decide on a formatting commit and an incremental clippy baseline, and choose a CI platform, or approve adding one.

Stage 4 has not been started. No commits or pushes were made. Awaiting project-owner approval.
