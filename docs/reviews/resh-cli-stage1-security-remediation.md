# Resource Shell (resh) — Stage 1 Security Remediation Report

- **Date:** 2026-10-16
- **Scope:** SEC-01 to SEC-05 from `docs/reviews/resh-cli-final-verification.md` (C1, C2, C3, H1, H2 there). Nothing else was changed.
- **State:** The changes are uncommitted in the working tree. Nothing was committed or pushed.

## Executive Summary

All five defect categories are corrected, and each one has regression tests that fail without the fix.

- **SEC-01 (archive extraction):** extraction can no longer write outside its destination.
  - Symlinks are never followed, whether the archive created them or they already existed in the destination.
  - Link targets are validated, and device nodes are rejected.
  - An unsafe entry now fails the operation with an error code. It is no longer skipped with `ok: true`.
- **SEC-02 (plugin store):** plugin ids and versions must be a single safe path component before they reach the filesystem. Deletes are confined to the store and refuse symlinked paths.
- **SEC-03 (proc PIDs):** PIDs are converted with checked conversions. `proc://4294967295.kill` is rejected before any system call.
- **SEC-04 (pkg):** `sh -c` is gone from the pkg handle. Every package-manager call is now an argv vector run with no shell. Package names, versions and architectures are validated.
- **SEC-05 (dry_run parsing):** every `dry_run` read goes through one shared parser, which rejects unrecognised values. A bare `dry_run` now means `dry_run=true`.

**Tests:**

- 50 new tests were added, and all of them pass.
- One test that was already failing (`archiveh::tests::test_path_sanitization`) now passes, because SEC-01 fixed the defect it tests.
- No new failures. The other 14 failures were already failing and are unchanged.
- No new compiler warnings.

**Recommendation: STAGE 1 CONDITIONALLY COMPLETE.** There are two verification gaps:

- Firewall dry-run is tested only at the option-parser level. The handle has no execution seam to mock.
- The pkg argv commands have not been run against real package managers.

## Repository Baseline

| Item | Value |
|---|---|
| Branch | `help-system-and-fixes` |
| Starting commit | `277f996300089269640dc5a962d01942aa871ccc` ("Bump version to 1.0.2-beta") |
| Working tree at start | `?? docs/reviews/`, containing the verification report. This was the only change already present. Nothing else was modified. |
| Toolchain | rustc/cargo 1.98.1 |
| Stage 1 changes | 18 source files and 1 doc file modified (listed below), plus this report. The verification report is untouched. |

## Defect Remediation Matrix

| ID | Original Severity | Status | Tests | Remaining Risk |
|---|---|---|---|---|
| SEC-01 | Critical | **VERIFIED FIXED** | 13 new, plus 1 existing test now passing; live reproduction re-run; mutation check | Race against a concurrent local writer in the destination (path-based checks, not `openat`) |
| SEC-02 | Critical | **VERIFIED FIXED** | 11 new (store and engine) | Same race class inside the user's own plugin store. Ids containing `/` are now refused for store operations. |
| SEC-03 | Critical | **VERIFIED FIXED** | 4 new (parse only, by design) | None identified. No live signal was sent, intentionally. |
| SEC-04 | **Reassessed: High** (was Critical/High) | **VERIFIED FIXED** (injection) | 7 new (mock executable, builders, end-to-end dry run); live check | Argv commands not run against real apt/dnf/pacman/apk/brew. `restore` and the read-only verbs pass lockfile names unvalidated (argv, so no shell). |
| SEC-05 | High | **PARTIALLY VERIFIED** | 15 new | Firewall tested at parser level only. archive/snapshot/file/dns/proc are covered through the shared helper's tests, not per-handle tests. |

**SEC-04 severity:**

- The reassessment rests on how the input reaches the shell. Untrusted text has to arrive through the `input=` JSON that the caller supplies, so the exploit needs influence over that JSON, for example a lockfile, CI input or generated package list.
- When that happens, it is arbitrary command execution, usually as root, and it works even in dry run. Approval flows that "only run the dry run" on untrusted input are fully exposed.
- It is not reachable from network data alone in the default configuration. **High** is therefore the appropriate rating, not Critical.

## Root Cause Analysis

### SEC-01 — Archive extraction destination escape

**Original behavior:**

- A tar containing `lnk -> ..` followed by `lnk/escaped_via_symlink.txt` wrote the file outside the destination and reported `ok: true`.
- `../` entries and absolute entries were skipped with a warning, and the result was still `ok: true`.
- Absolute entries were re-rooted when `allow_absolute_paths=false`, which is the reverse of the documented behavior.

**Root cause** (`src/handles/filesystem/archiveh.rs`):

1. `sanitize_path` validates only the path text. Its absolute-path branch was inverted.
2. Parents were created with `create_dir_all(parent)`, which follows any symlink in the path: one the archive just created, or one already present in the destination.
3. Tar entries were written with `Entry::unpack(path)`, which does no containment checks:
   - Symlink targets are written verbatim.
   - Hard links are resolved from the raw link name, relative to the working directory or as an absolute path.
   - `unpack_dir` and `set_perms` follow an existing symlink at the final component, so a planted directory link gets chmod'd.
4. Zip used `File::create`, which follows a final-component symlink. Raw decompression did the same.
5. Unsafe entries were `continue`d past, and the result still said `ok: true`.

The defect affects both tar (all compressions) and zip. Raw single-file decompression was affected only by a planted symlink at the output name.

**Correction:**

- **`sanitize_path`:**
  - Absolute paths are rejected unless `allow_absolute_paths=true`. With it, they are re-rooted under the destination and never written at their absolute location.
  - `..` can never climb above the destination, even with `allow_parent_traversal=true`.
  - Errors carry the existing error codes `archive.extract_absolute_path_rejected` and `archive.extract_path_traversal_detected`. Both were previously unused.
- **`prepare_parent_dirs`:** creates parents one level at a time with `create_dir`. Any existing component that is a symlink or a non-directory is refused, with `archive.extract_symlink_rejected`.
- **`clear_existing_target`:** an existing symlink or file at the final component is unlinked before writing (with `overwrite=true`), never followed. An existing real directory is kept for directory entries.
- **Symlink entries:**
  - The target must be relative and must resolve, by its text, inside the destination.
  - After extraction, `verify_symlinks_inside` resolves each created link physically. This catches link chains such as `sub/x -> ..` plus `y -> sub/x/..`. Offending links are removed, and the operation fails.
- **Hard links:** the link name is mapped like an entry path, including `strip_components`. It must name an existing regular file inside the destination, reached without symlinks. The link is then created with `fs::hard_link` from that validated source.
- **Device nodes:** char and block entries are rejected, with the new code `archive.extract_unsupported_entry_type`.
- **Link targets are validated before anything on disk changes.**
- **Zip and raw outputs** are opened with `create_new`, after a planted link is cleared.
- **Failure reporting:**
  - Any unsafe entry stops the extraction with `ok: false`, an error code, and no `summary` or `manifest`.
  - The message names the entry and says how many entries were already written.
  - The JSON shape is unchanged.

**Regression tests** (`archiveh::extract_safety_tests`, all in a per-test `TempDir` sandbox with a sentinel directory beside the destination):

- `normal_archive_with_nested_dirs_extracts`: nested directories, `./` paths, an internal symlink and an internal hard link.
- `parent_traversal_is_rejected`
- `absolute_paths_are_rejected_or_rerooted`
- `archive_symlink_cannot_redirect_later_entries`: the exact reproduction from the review, plus escaping targets.
- `in_destination_symlink_is_never_written_through`
- `symlink_chain_escaping_destination_is_removed`
- `preexisting_destination_symlink_is_not_followed`: a planted parent, a planted final component with overwrite, a dangling link, and a directory link not being chmod'd.
- `hard_link_targets_must_stay_inside`
- `device_nodes_are_rejected`
- `allow_symlinks_false_still_skips_links`
- `zip_extraction_is_contained`
- `raw_decompression_does_not_follow_planted_link`
- `sanitize_path_codes`
- The existing `test_path_sanitization` now passes.

**Further evidence:**

- **Mutation check:** I temporarily restored the old `create_dir_all` parent creation and accepted every symlink target. Four of the new tests then failed. The real code was then restored and re-verified byte for byte.
- **Live check:** I re-ran the review's reproduction with the built binary in a scratch directory. It now exits 1 with `archive.extract_symlink_rejected`, and no file appears outside `dest`.

**Remaining risk:**

- The checks are path-based. A concurrent local process that can write inside the destination could swap a checked directory for a symlink between the check and the write. Closing that needs `openat`/`O_NOFOLLOW` directory-relative extraction, which would mean reimplementing the tar crate's metadata handling. The threat addressed here is a malicious archive, not a concurrent attacker.
- `allow_symlinks=no` is still read as `true`, because that boolean was out of scope. Symlinks are now contained either way.

### SEC-02 — Plugin installation path traversal

**Original behavior:** a registry or catalog version string such as `../../../../.ssh` was joined into `versions/<version>` and passed to `remove_dir_all`. The plugin contents were then copied there.

**Root cause:**

- `PluginStore::plugin_version_dir` and `plugin_root` join untrusted strings without any validation (`src/handles/pluginh/plugin/store.rs`).
- `install_plugin`, `remove_plugin` and `cleanup_staging` call `remove_dir_all` on the joined paths.
- Nothing checks for symlinked components inside the store.

Untrusted input reaches the filesystem at these points:

- The plugin id (from the URL): `plugin_root`, staging, `current`, locks, and purge directories.
- The version (from registry or catalog JSON): `versions/<v>`, `metadata.json`, and the `current` link target.
- The version read back from the `current` symlink.

**Correction:**

- **`validate_path_component`:**
  - A value must be 1-128 ASCII characters from `[A-Za-z0-9._+-]`, starting with a letter or digit.
  - That excludes `/`, `\`, `.`, `..`, hidden names, a leading `-`, NUL, `%`-encoding and drive prefixes.
  - Unsafe values are rejected with an explicit error and are never rewritten.
  - The id `locks` is reserved, because it would collide with the locks directory.
- **`checked_plugin_root` and `checked_version_dir`** validate the id and version, then call `ensure_inside_store`. It requires the path to be strictly inside the store, never the store root itself, and every existing component below the root to be a non-symlink.
- **`remove_tree`** is the only recursive delete, and it applies the same checks. `install_plugin`, `activate_version`, `list_versions`, `cleanup_staging`, `remove_plugin`, `staging_dir`, `list_plugin_files`, `create_lock`/`remove_lock` and `purge_plugin_data` all use these checks.
- **Purge** refuses symlinked purge directories.
- **The engine** (`resolve_candidate`) validates the id, and the resolved version, before anything is downloaded. This applies in dry run too.

**Regression tests:**

- In `store::tests`:
  - `valid_components_are_accepted`
  - `unsafe_components_are_rejected`
  - `install_with_traversal_version_touches_nothing_outside`
  - `remove_and_cleanup_refuse_unsafe_targets`
  - `store_root_itself_is_never_removed`
  - `symlinked_plugin_root_is_not_followed`
  - `symlinked_version_dir_is_not_followed`
  - `valid_install_replace_and_remove_still_work`
  - `tampered_current_link_version_is_rejected`
- In `engine::tests`:
  - `registry_version_traversal_is_rejected_before_install`: a local registry file whose version is `../../../victim`, run in both dry-run and real mode, with a sentinel checked afterwards.
  - `unsafe_plugin_id_is_rejected_before_install`
- All store tests use `TempDir` stores. None touches `~/.local/share/resh/plugins`.

**Remaining risk:**

- The same check-then-use race as SEC-01, but inside the user-owned store.
- Compatibility change: ids containing `/` (for example `plugin://community/docker`) still parse, but store operations now refuse them.
- Not changed, because they are out of scope: `copy_directory` still follows symlinks found in a staged artifact (review item H13), and checksum verification still passes when no checksum is given.

### SEC-03 — Process PID overflow

**Original behavior:** `proc://4294967295.kill` parsed as `u32` and was cast to `pid_t` -1, which gives `kill(-1, SIGKILL)`. Every value of 2^31 or more became a negative process-group target.

**Root cause** (`src/handles/processes/proch.rs`):

- `from_url` and `resolve_pid` parsed the PID as `u32`, then cast with `as libc::pid_t`.
- `resolve_pid` feeds `kill`, `getpriority` and `setpriority`.
- `limits.set pid=` already used checked `i32 > 0` parsing.

**Correction:**

- A single `parse_pid` parses the value as `u64`, rejects 0, and converts with `libc::pid_t::try_from`. That gives an explicit "out of range (max 2147483647)" error.
- Both `from_url` and `resolve_pid` use it, so a handle built any other way still cannot produce -1.
- `self` also uses `try_from`.
- Valid PIDs behave exactly as before.

**Regression tests:**

- `pid_parsing_rejects_out_of_range_values`:
  - Rejected: 0, negative values, `2147483648`, `4294967295`, u64 overflow, the empty string, hex, decimals and leading whitespace.
  - Accepted: 1, 4242 and `pid_t::MAX`.
- `proc_url_rejects_wrapping_pids`
- `resolve_pid_rechecks_range_without_from_url`
- `kill_stage_with_wrapping_pid_fails_before_dispatch`

No test sends a signal.

### SEC-04 — Package command injection

**Original behavior:**

- Package names, versions, the architecture and `extra_args` were concatenated into `sh -c` strings.
- Dry-run install and remove still ran `sh -c "dpkg -s <name>"` to check status.
- So a name such as `jq;cmd` executed `cmd`, even in dry run.

**Root cause** (`src/handles/system/pkgh.rs`):

- Eleven `AsyncCommand::new("sh").arg("-c")` sites:
  - status query
  - cache update
  - single install
  - installed-version query (pipelines through `cut` and `grep`)
  - batch remove
  - autoremove
  - update listing and upgrade listing (`| tail`, `2>/dev/null`, `|| true`)
  - apply updates
  - apply upgrades
- The only name check was "non-empty".

**Correction:**

- **New type `CmdLine { env, argv }`:**
  - Fixed words come from literals (`CmdLine::lit`).
  - Caller values are added with `arg()` and always stay exactly one argv element.
  - Leading `NAME=value` words of a literal, such as `DEBIAN_FRONTEND=noninteractive`, are set in the child's environment.
  - `command()` builds `Command::new(argv[0]).args(..)`.
  - `Display` renders the text the handle always reported in dry-run `commands`, so the JSON output is unchanged. Tests pin this.
- **All 11 sites now execute argv.** There is no `sh` left in `pkgh.rs`.
- **The shell-only behaviors are kept, now in Rust:**
  - The `cut -d' ' -f2` field extraction.
  - The `grep -o` version match, using a regex.
  - Dropping the first line, as `tail -n +2` did.
  - Ignoring the exit status where the pipeline or `|| true` discarded it.
- **`check_pkg_token`** validates package names, versions and arch in the install, remove, update and upgrade configs, before any dry-run or real path:
  - A value must start with a letter or digit, so it cannot be read as an option.
  - It may use only `[A-Za-z0-9._+:~@/=-]`.
  - Real names such as `g++`, `homebrew/cask/firefox` and `1:2.3.4-1ubuntu1` still pass.

**Regression tests** (`pkgh::cmdline_safety_tests`):

- `package_tokens_accept_real_names_and_reject_shell_syntax`
- `hostile_names_versions_and_arch_fail_validation`
- `dry_run_with_hostile_names_runs_nothing`: install, remove, update and upgrade through `call()`, with a sentinel file.
- `install_command_keeps_display_text_and_single_arguments`
- `remove_and_upgrade_commands_keep_display_text`
- `execution_uses_argv_not_a_shell`: a mock package-manager script records the argv it receives. `$(...)`, backticks, `;`, `&&`, spaces and quotes all arrive literally, and the sentinel is never created.
- `execution_failures_are_reported`: a missing executable, and a non-zero exit with stderr.
- **Live check:** `resh pkg://system.install 'input={"manager":"apt","dry_run":true,"packages":[{"name":"jq;touch <scratch>/PWNED"}]}'` exits 1 with "contains invalid character ';'", and the file is never created.

No real package manager was invoked.

**Behavior changes to note:**

- Each `extra_args` element is now exactly one argument. The shell used to word-split and expand it.
- An explicit `DEBIAN_FRONTEND` in `env` now overrides the built-in value. The shell prefix used to take precedence.

**Remaining risk:**

- The argv commands are verified against expected argv and display text, not against real package managers.
- `restore`/`apply_lock` and the read-only verbs (`info`, `search`, `list_installed`) were already argv-based. They still do not validate lockfile names, so a leading-dash name could be read as an option. There is no shell, so this is not injection. It is the Medium item in the review.

### SEC-05 — Dry-run execution safety

**Original behavior:**

- 37 `dry_run` reads used `== "true"`, `parse::<bool>().unwrap_or(false)` or similar.
- So `dry_run=1`, `dry_run=yes` or `dry_run=True` performed the real change in user, cron, firewall, ssh, plugin, snapshot, file `replace`, archive, dns and proc.
- `dispatch_stage` and the `(...)` argument parser silently dropped a bare `dry_run`.
- `mail send` glued a bare `dry_run` onto the previous value, for example the subject, and sent for real.

**Root cause:**

- A lenient parser, `core::lenient::parse_bool`, already accepted `true/false/1/0/yes/no/on/off`, but it was private and unused by these handles.
- The bare-word drops are in `src/core/mod.rs`, `src/core/parse.rs` and `reconstruct_mail_command` in `src/main.rs`.

**Correction:**

- `parse_bool` is now public. Two new readers sit on top of it, with no second interpreter:
  - `bool_arg(args, key)` returns `None` when the key is absent and an error when the value is unrecognised.
  - `dry_run(args)` treats an absent key as `false`.
- All 37 sites now use them, keeping each handle's own default when the key is absent.
- Firewall `disable` keeps its own error type.
- Mail's `dry_run` uses the shared reader, and now accepts `on/off` too.
- A bare `dry_run` becomes `dry_run=true` in four places:
  - CLI words (`dispatch_stage`)
  - the `(...)` argument forms (dotted, plugin and fallback)
  - the mail function-call form
  - mail send reconstruction
- Other bare words keep their existing behavior.
- **pkg** takes typed JSON (`input=`), so a malformed `dry_run` there was already a hard error. It was not changed. Its dry-run side effects were the shell calls removed under SEC-04.

**Regression tests:**

- **Core:**
  - `lenient::tests::dry_run_spellings`: every true and false spelling in mixed case; `""`, `maybe`, `2`, `y`, `dry_run` and a quoted value are rejected; a missing key gives false.
  - `parse::…::bare_dry_run_in_parentheses_means_true`
  - `core::tests::bare_dry_run_cli_word_is_kept`: uses a recording handle in a test `Registry`.
- **cron** (`cronh::dry_run_tests`), with a recording `CronProvider` that does nothing:
  - Add, rm, enable and disable receive the requested `dry_run` for `true/1/yes/ON/false/0/missing`.
  - Malformed values never reach the provider.
- **user** (`userh::dry_run_tests`), against `MockBackend`:
  - A dry-run delete keeps the user; normal execution deletes it.
  - A dry-run add creates nothing; normal execution creates the user.
  - A dry-run lock leaves the account unlocked; normal execution locks it.
  - All five parsers accept the spellings and reject garbage.
  - `call()` fails on `dry_run=maybe`.
- **ssh** (`sshh::tests`), with the existing call-recording `mock_ssh`:
  - `exec` under each true spelling makes zero ssh invocations.
  - A malformed value is rejected, also with zero invocations.
  - `dry_run=false` makes exactly one.
  - All eight option parsers behave consistently.
- **firewall** (`firewallh::dry_run_tests`): the six mutating option parsers accept and reject consistently.
- **plugin** (`pluginh::dry_run_tests`):
  - The four parsers behave consistently.
  - An install with `dry_run=1/yes/on/true`, run through the real engine on a temporary store, installs nothing.
  - `dry_run=false` installs.

**Remaining risk:**

- **Firewall:** there is no mockable execution layer, so "no mutation under dry run" is not shown end to end. The parsed value feeds the existing dry-run branches, which were not changed.
- **archive `remove`, snapshot `restore`, file `replace`, dns `zone.update` and proc `limits.set`:** each is a one-line switch to the shared reader, covered by the helper's tests rather than per-handle tests.
- **Other booleans** (`force`, `purge`, `allow_symlinks`, and so on) still use their old parsing, as instructed.

## Files Modified

Every file in this list was changed by Stage 1. Line counts are from `git diff --stat` (insertions/deletions).

| File | Change |
|---|---|
| `src/handles/filesystem/archiveh.rs` | SEC-01 fix (`sanitize_path`, containment helpers, tar/zip/raw writers, error codes), SEC-05 one site, `extract_safety_tests` (+676 lines) |
| `src/handles/pluginh/plugin/store.rs` | SEC-02 validation and guarded deletes, tests |
| `src/handles/pluginh/plugin/engine.rs` | SEC-02 early validation, tests |
| `src/handles/processes/proch.rs` | SEC-03 `parse_pid`, SEC-05 one site, tests |
| `src/handles/system/pkgh.rs` | SEC-04 `CmdLine`, `check_pkg_token`, builders and executors, `cmdline_safety_tests` |
| `src/core/lenient.rs` | SEC-05 public `parse_bool`, `bool_arg`, `dry_run`, test |
| `src/core/mod.rs` | SEC-05 bare `dry_run` in `dispatch_stage`, test |
| `src/core/parse.rs` | SEC-05 `is_bare_dry_run` in the argument loops, test |
| `src/main.rs` | SEC-05 bare `dry_run` in mail reconstruction |
| `src/handles/processes/cronh.rs` | SEC-05 10 sites, `dry_run_tests` |
| `src/handles/security/userh.rs` | SEC-05 5 sites, `dry_run_tests` |
| `src/handles/security/firewallh.rs` | SEC-05 6 sites, `dry_run_tests` |
| `src/handles/network/sshh.rs` | SEC-05 8 sites, 2 tests |
| `src/handles/automation/pluginh.rs` | SEC-05 4 sites, `dry_run_tests` |
| `src/handles/network/mailh.rs` | SEC-05 1 site |
| `src/handles/filesystem/snapshot.rs`, `fileh.rs`, `src/handles/network/dnsh.rs` | SEC-05 1 site each |
| `docs/Filesystem_Storage/archive.md` | The "Safety-First Execution" list now describes the new extraction behavior and error codes |
| `docs/reviews/resh-cli-stage1-security-remediation.md` | This report |

**Unchanged:**

- The handle and verb registration.
- The help text and the golden files.
- The `Handle` trait, the dispatcher's structure, the provider interfaces and `Cargo.toml`.
- No dependencies were added.

## Test Results

**Test command** (the same safe command and skips as the verification review):

```
env -u MAIL_SMTP_USERNAME -u MAIL_SMTP_PASSWORD -u TEST_POSTGRES_DSN -u TEST_MYSQL_DSN \
    -u TEST_REDIS_URL -u TEST_MEMCACHED_ADDR \
  cargo test --no-fail-fast -- --skip test_disable_verb_recognized \
    --skip gith::tests::test_timeout_functionality --skip https_ \
    --skip dbh::tests::test_postgres_ --skip dbh::tests::test_mysql_
```

| Command / suite | Baseline (before Stage 1) | After Stage 1 |
|---|---|---|
| `cargo check --all-targets` | pass | **pass** (exit 0) |
| `cargo build --all-targets` | pass | **pass** (exit 0) |
| Unit tests, lib target | 1031 passed, 15 failed, 13 skipped | **1082 passed, 14 failed, 13 skipped** |
| Unit tests, bin target (same tests compiled again) | 1035 passed, 15 failed, 13 skipped | **1086 passed, 14 failed, 13 skipped** |
| `tests/help_cli.rs` | 16 passed | **16 passed** |
| `tests/help_coverage.rs` | 2 passed | **2 passed** |
| Compiler warnings, lib / bin / lib test / bin test | 288 / 426 / 358 / 488 | **288 / 422 / 358 / 484** (none new) |

- **New tests:** 50, all passing. By defect: SEC-01 13, SEC-02 11, SEC-03 4, SEC-04 7, SEC-05 15.
- **Fixed by Stage 1:** `archiveh::tests::test_path_sanitization`. The verification report listed it as a real defect, and it is the SEC-01 absolute-path inversion.
- **Already failing, unchanged (14):** these were not investigated, as instructed.
  - `userh::tests::test_groups_verb_*` (6)
  - `userh::tests::test_unlock_*` (5)
  - `gith::tests::{test_connection_not_found, test_status_integration_detached_head, test_validate_tag_config_delete}`
- **New failures:** none.
- **Skipped (13):** the same tests as the baseline, for the same safety and environment reasons.
- **`cargo fmt --check`:** this already failed repo-wide before Stage 1 and was not run as a gate. No reformatting was done.
- **Clippy:** the repo already had about 1,817 lint sites before Stage 1. I intersected clippy's output with the lines Stage 1 added and fixed every finding in new code. The one remaining hit on a changed line (`unused variable available_updates` in `build_upgrade_command`) already existed; Stage 1 only changed that signature's return type.

**Targeted runs used during the work:**

- `cargo test --lib archiveh::`
- `cargo test --lib pluginh::plugin`
- `cargo test --lib proch::`
- `cargo test --lib pkgh::`
- `cargo test --lib core::`
- `cargo test --lib cronh::dry_run_tests`
- `cargo test --lib userh::dry_run_tests`
- `cargo test --lib -- firewallh::dry_run_tests sshh::tests::exec_dry_run sshh::tests::every_ssh`
- `cargo test --lib pluginh::dry_run_tests`

**Live checks** (built binary, scratch directory only):

- The SEC-01 reproduction is blocked.
- The SEC-04 dry-run injection is rejected.
- No live check of SEC-03 or of mutating user/cron/firewall/ssh/plugin operations was run, by design.

## Regression Assessment

These are unchanged and verified:

- **Registration and help:** handle registration, verb lists and the help system, all confirmed by `help_cli` and `help_coverage`.
- **CLI grammar:** the only additions are that a bare `dry_run` is now honored, and malformed `dry_run` values and unsafe identifiers are rejected.
- **Authorization:** no authorization or policy code was touched. The project has no central layer.
- **JSON output:**
  - pkg `commands` text is pinned by tests.
  - Archive error responses keep the same `(code, message)` shape, with now-specific codes.
- **Legitimate behavior,** confirmed by the existing tests and the new positive cases:
  - Archive extraction of normal archives, including internal symlinks and hard links.
  - Plugin install, replace and remove.
  - Valid PIDs.
  - pkg command lines.
  - Normal (non-dry-run) execution in user, ssh, plugin and cron.

Intentional behavior changes:

1. **Archive extraction:**
   - An unsafe entry now fails the extraction. Previously it was skipped with a warning and `ok: true`.
   - `allow_absolute_paths` now matches its documented meaning: `false` rejects, `true` re-roots under the destination.
   - A `./` root entry is counted as skipped without a warning.
2. **Plugin store:** ids and versions outside the safe component rule are refused, including ids with `/`.
3. **pkg:**
   - Names, versions and arch must pass `check_pkg_token`.
   - Each `extra_args` element is one argument, with no shell splitting or expansion.
4. **`dry_run`:** `1/yes/on` now mean a dry run everywhere, and malformed values are errors. A bare `dry_run` is honored.

## Unresolved Issues

1. **SEC-05, firewall:** I did not show end to end that a firewall dry run makes no changes, because the handle has no seam for mocking command execution. Adding one would be an architectural change outside Stage 1.
2. **SEC-04, real package managers:** the new argv form has not been exercised against real package managers. Before release, run it in disposable VMs or containers for apt, dnf, yum, pacman, apk and brew.
3. **Check-then-use races** in archive extraction and in the plugin store. They need a concurrent local attacker who can write in the destination or store.
4. **Found but not fixed, because they are out of scope** (all were already in the verification report):
   - Plugin `copy_directory` follows symlinks in a staged artifact (H13).
   - Plugin checksum verification passes without a checksum (H13).
   - pkg `restore` and the read-only verbs do not validate lockfile names (Medium, argv only).
   - Non-`dry_run` booleans are still parsed inconsistently. For example, `allow_symlinks=no` is read as `true`.
   - Other bare CLI words are still dropped silently.
   - Raw decompression checks the size limits only after writing.

## Stage 1 Recommendation

**STAGE 1 CONDITIONALLY COMPLETE**

- All five defect categories are corrected, with targeted regression tests that fail without the fixes. For SEC-01 this was shown with a mutation check.
- No test regressions or new warnings were introduced. One test that was already failing now passes.
- The two original live reproductions, archive escape and pkg dry-run injection, are blocked.
- **Conditions:**
  - Firewall dry-run is verified only at the parser level (SEC-05 is PARTIALLY VERIFIED).
  - The pkg argv commands have not been exercised against real package managers.
  - Closing these needs either a test seam in the firewall handle or validation in disposable systems. Both are decisions for the project owner.

Stage 2 has not been started. No commits or pushes were made.
