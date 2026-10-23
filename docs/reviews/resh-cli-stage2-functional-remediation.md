# Resource Shell (resh) — Stage 2 Functional Correctness and Reliability Remediation

- **Date:** 2026-10-17
- **Scope:** FUNC-01 to FUNC-09 from the Stage 2 brief, which map to H5, H6, H3, H11, H10, H8, H9, H7 (timeouts) and H16 in `docs/reviews/resh-cli-final-verification.md`. Three further High functional findings from that report (H7 profiles, H12, H15) were also in scope and are fixed.
- **State:** All changes are uncommitted in the working tree, on top of the uncommitted Stage 1 changes. Nothing was committed or pushed. Stage 3 has not been started.

## Executive Summary

Stage 2 corrected all nine functional reliability defects in the brief, and three more High functional findings from the original review. Every fix has regression tests.

- **Failures are no longer silent (FUNC-01).** When a handle fails without writing to stderr, `main.rs` now prints the status reason there. All six silent failures the review reproduced live now print a reason.
- **Failures no longer exit 0 (FUNC-02).**
  - A failed status can never become exit code 0. Codes outside 1-255, including HTTP statuses, become 1.
  - cron, firewall enable/disable, ssh exec, pkg partial failures, svc status for a missing service, and db ping now fail when the operation fails. Where the result has a JSON `ok` field, it agrees with the exit status.
- **Firewall backups are real (FUNC-03).** enable/disable on iptables and nftables write the backup before changing anything, and report the path of the file actually written. If the backup fails, nothing is changed.
- **git sync no longer reports work it did not do (FUNC-04).**
  - The placeholder rebase/merge code is removed. sync fast-forwards or reports `up_to_date`.
  - Divergent history now fails explicitly before anything is pushed.
- **cron enable leaves ordinary comments alone (FUNC-05).** A commented line is treated as a disabled job only if it starts with a real cron schedule. systemd timer discovery now reads the UNIT column.
- **A zip password is rejected (FUNC-06).** The zip library in use cannot write encrypted archives. A request with a password now fails with `archive.create_password_not_supported` and writes no file.
- **svc instance units work (FUNC-07).** `svc://getty@tty1` now targets `getty@tty1.service`, not `tty1`. Names that could be misread as options or paths are rejected before any command runs.
- **Backup timeouts fire (FUNC-08).** The backend is killed and reaped at the deadline, and the command fails with `TIMEOUT`.
- **Relative file directories work (FUNC-09).** `file://./sub.find` behaves exactly as the absolute path does.
- **Also fixed:**
  - `backup://<profile>` is honored, so profiles no longer share a repository (H7).
  - `snapshot diff from=<name>` works (H15).
  - Event hook notes no longer corrupt JSON on stdout (H12).

**Tests:**

- 47 new regression tests, all passing. 3 existing tests were updated, because they asserted the defective behavior.
- The 14 failures that were already failing are unchanged.
- No new failures and no new compiler warnings.
- Lib unit tests went from 1082 to 1129 passing.

**Recommendation: STAGE 2 CONDITIONALLY COMPLETE.** The conditions are listed in the [Stage 2 Recommendation](#stage-2-recommendation).

## Repository Baseline

| Item | Value |
|---|---|
| Branch | `help-system-and-fixes` |
| Commit | `277f996300089269640dc5a962d01942aa871ccc` ("Bump version to 1.0.2-beta") |
| Working tree at start | The Stage 1 changes, uncommitted, plus `?? docs/reviews/` containing the two earlier reports. Modified: `docs/Filesystem_Storage/archive.md`, `src/core/{lenient,mod,parse}.rs`, `src/main.rs`, and `src/handles/` `automation/pluginh.rs`, `filesystem/{archiveh,fileh,snapshot}.rs`, `network/{dnsh,mailh,sshh}.rs`, `pluginh/plugin/{engine,store}.rs`, `processes/{cronh,proch}.rs`, `security/{firewallh,userh}.rs`, `system/pkgh.rs`. |
| Toolchain | rustc/cargo 1.98.1 |
| Stage 1 work | Preserved. Nothing was reset, reverted or reformatted. |

**Baseline tests, measured before any Stage 2 change** (same safe command as Stage 1):

| Suite | Result |
|---|---|
| Unit tests, lib target | 1082 passed, 14 failed, 13 skipped |
| Unit tests, bin target | 1086 passed, 14 failed, 13 skipped |
| `tests/help_cli.rs` | 16 passed |
| `tests/help_coverage.rs` | 2 passed |

This matches the Stage 1 report exactly.

## Defect Remediation Matrix

| ID | Defect | Status | Tests | Remaining Risk |
|---|---|---|---|---|
| FUNC-01 | Missing errors | **FIXED, verified live** | 2 new unit tests; 8 live reproductions | Some handles still write JSON errors to stdout rather than stderr (the review's Low item). They now also get a stderr line. |
| FUNC-02 | Incorrect exit codes | **FIXED** | 7 new tests across core, cron, ssh, svc, pkg and db; 2 updated (ssh, help_cli); firewall exit status covered by the FUNC-03 tests | pkg and db are verified at the helper level; neither handle has an execution seam for end-to-end mocks. `user exists` for a missing user stays exit 0 (documented query result). |
| FUNC-03 | Firewall backup | **FIXED** | 9 new tests through `call()` with mock executables, including dry run | Firewall timeouts are still ineffective (`tokio::time::timeout` around a blocking call). ufw/firewalld take no backup; they now say so. |
| FUNC-04 | Git synchronization | **FIXED by explicit rejection** | 9 new tests on temporary local repositories | sync cannot integrate divergent history; it refuses. Real rebase/merge would be new functionality. |
| FUNC-05 | Cron comments | **FIXED** | 5 new tests, plus a mutation check | A commented line that is a valid cron entry (for example a crontab template example) is still a disabled job by syntax. systemd timer paths are not exercised live (this host runs OpenRC). |
| FUNC-06 | ZIP encryption | **FIXED by explicit rejection** | 3 tests (1 updated, 2 new) | Encrypted archive creation is unavailable until the zip dependency changes (see H4). |
| FUNC-07 | Service identity | **FIXED, verified live** | 2 new tests; live status checks | systemd paths are verified at the parser level only; this host runs OpenRC. |
| FUNC-08 | Backup timeouts | **FIXED** | 4 new tests | Only the direct child is killed; a backend's own children may outlive it. |
| FUNC-09 | Relative paths | **FIXED, verified live** | 4 new tests; live checks | None identified. The file handle has no root boundary by design; that is unchanged. |
| H7 (extra) | backup profiles ignored | **FIXED** | 2 new tests | — |
| H15 (extra) | snapshot diff by name | **FIXED** | 1 new end-to-end test in an isolated store | — |
| H12 (extra) | event hooks corrupt JSON | **FIXED, verified live** | live check | The hooks are still simulations ("Would forward ..."). |

## Root Cause Analysis

### FUNC-01 — Missing error messages (H5)

**Original behavior:** `dns://.lookup`, `fs://x.bogus`, `file://<missing>.stat`, `file://x.grep` (no pattern) and others exited non-zero with no output at all.

**Root cause:** many handles return `Ok(Status::err(code, reason))` without writing anything, and `main.rs` never printed `Status.reason`. Errors returned as `Err` were already printed by `anyhow`.

**Files changed:** `src/core/status.rs`, `src/main.rs`.

**Correction:**

- **`TrackingWriter`** wraps stderr and records whether the handle wrote to it.
- **`report_failure`:** on failure, if the handle wrote nothing to stderr, it prints `Error: <reason>`. With no reason, it prints `Error: command failed (exit code N)`.
  - If the handle already explained itself on stderr, nothing is added, so there are no duplicates.
  - Successful output is untouched.
  - Structured JSON on stdout is unchanged.
- Reasons are the handles' own messages. No new secret-bearing text is introduced: a password is never echoed (tested for zip).

**Regression tests:** `core::status::tests::{failure_reason_reaches_stderr_once, tracking_writer_records_writes}`.

**Live verification** (built binary, read-only, scratch directory):

| Command | Before | After |
|---|---|---|
| `dns://.lookup` | silent, exit 1 | `Error: [dns.lookup_invalid_name] Missing required parameter: name`, exit 1 |
| `fs://x.bogus` | silent, exit 95 | `Error: unknown verb`, exit 95 |
| `file://./missing.txt.stat` | silent, exit 2 | `Error: stat "missing.txt": No such file or directory`, exit 2 |
| `file://./x.grep` | silent, exit 2 | `Error: missing arg: pattern`, exit 2 |
| `config://app.set key=a` | silent | `Error: missing arg: value`, exit 1 |
| `http://127.0.0.1:1/.get` | silent | `Error: Connection failed`, exit 1 |
| `template://x.bogus`, `mq://q.bogus` | silent | `Error: unknown verb ...`, exit 1 |

The eight scenario classes in the brief map as follows:

- **Missing resource:** stat, svc status.
- **Invalid argument:** grep, config set.
- **Provider failure:** http, cron provider, ssh.
- **Permission failure:** firewall backup directory test.
- **Invalid configuration:** dns.
- **Missing file:** stat.
- **Unsupported operation:** unknown verbs, zip password, git divergence.
- **Internal error:** `report_failure` with no reason.

**Remaining limitations:** db, cache, cert, proc and system still write JSON errors to stdout (the review's Low item). They now also get a stderr line, but the stdout channel is unchanged.

### FUNC-02 — Incorrect success exit codes (H6)

**Original behavior:**

- cron failures, firewall enable/disable failures, an ssh exec whose remote command failed (or whose ssh connection failed), pkg runs where some packages failed, `svc status` for a missing service and a db ping that failed every attempt all exited 0.
- A `Status` whose code was 0 or out of range exited with that value. HTTP 404 exited 148; a code of 256 or 512 would have exited 0.

**Root causes and corrections:**

| Where | Root cause | Correction |
|---|---|---|
| `main.rs` / `core::status` | `exit(status.code.unwrap_or(1))` | New `Status::exit_code()`: success is 0, a failure is its code when that is 1-255, otherwise 1. |
| `cronh.rs` | Every verb returned `Status::ok()` after rendering an `ok:false` JSON error. In `format=text`, provider-level failures were rendered as text with no failure marker. | A failure is always rendered as the JSON error object. `verb_status()` derives the exit status from `ok` and carries `error.message`. |
| `firewallh.rs` | `handle_enable`/`handle_disable` returned `Status::ok()` regardless of `response.ok`. | Same `if response.ok` idiom the other firewall verbs already use. The reason includes the nested error message. |
| `sshh.rs` | A completed ssh run was `ok: true` whatever its exit code. ssh's own 255 (cannot connect) counted as success. | `exec_failure()`: a non-zero exit, 255, a signal, a timeout or no exit code makes the result `ok:false`, with codes `REMOTE_EXIT_NONZERO`, `SSH_FAILED`, `EXEC_SIGNALED`, `EXEC_TIMEOUT` or `EXEC_NO_EXIT_CODE`. The process exits with the remote code, as `ssh` itself does. |
| `pkgh.rs` | install/remove/update/upgrade/restore returned success whatever `summary.failed` said. | `result_status()`: fails when `summary.failed > 0` or `summary.success == false`, with the reason "N of M package operations failed". |
| `svch.rs` | `systemctl show` succeeds for unknown units (`LoadState=not-found`). OpenRC's "does not exist" was folded into `stopped_or_unknown`. Status objects containing `error` returned `Status::ok()`. | `parse_systemctl_show` and `openrc_service_missing` turn an unknown service into an error, and `status_outcome()` makes that a failure. A *stopped* service is still a successful status query. |
| `dbh.rs` | `ping` returns `Ok({"status":"error",...})` after its retries, and `call()` mapped every `Ok` to success. | `value_status()` treats `"status":"error"` as a failure. |

**Files changed:** `src/core/status.rs`, `src/main.rs`, `src/handles/processes/cronh.rs`, `src/handles/security/firewallh.rs`, `src/handles/network/sshh.rs`, `src/handles/system/pkgh.rs`, `src/handles/processes/svch.rs`, `src/handles/data/dbh.rs`.

**Regression tests:**

- `core::status::tests::exit_code_is_nonzero_for_every_failure`
- `cronh::tests::verb_status_reflects_ok_field`
- `cronh::dry_run_tests::failed_cron_verbs_fail_through_call`: every verb through `call()` in text format, checking that the JSON `ok` and the exit status agree.
- `sshh::tests::exec_failure_classification`
- `sshh::tests::test_command_with_different_exit_codes`, **updated**. It previously asserted that a remote `false` exits 0 ("SSH exec itself succeeds"), which is the defect itself.
- `svch::tests::missing_services_are_failures`
- `pkgh::result_status_tests::partial_failures_fail_the_command`
- `dbh::tests::failed_ping_result_is_a_failure_status`
- Firewall: `backup_write_failure_prevents_any_change` and `mutation_failure_after_backup_is_a_failure` check both the exit status and the JSON.

**Live:** `svc://doesnotexist-xyz.status` now exits 1 with `Error: svc status doesnotexist-xyz: service 'doesnotexist-xyz' does not exist`. `svc://sshd.status` still exits 0.

**Intentional behavior changes:**

- ssh exec now exits with the remote exit code and reports `ok:false` when it is non-zero.
- An HTTP non-2xx status exits 1 instead of `status mod 256`. The http docs promise only "non-zero".
- cron in `format=text` prints the JSON error object on failure.

**Remaining limitations:**

- pkg and db have no execution seam, so their status helpers are tested directly rather than through a mocked package manager or database.
- `user exists` for a missing user stays exit 0 with `ok:true, exists:false`. That is the documented query contract in the built-in help, and JSON and exit status agree.

### FUNC-03 — Firewall backup reliability (H3)

**Original behavior:** with `backup_before_apply=true` (the default), enable/disable on iptables and nftables generated a backup *path string*, reported it in `actions` and `result.backup_path`, and wrote nothing. The code comment read "In a real implementation, we would call the rules.save function here". The rules were then flushed or replaced.

**Root cause:** enable/disable never called the existing `create_iptables_backup`/`create_nftables_backup`. Those helpers (used only by `rules.reload`) wrote with `fs::write` to predictable `/tmp/.resh-backup-*` names, which follows symlinks.

**Files changed:** `src/handles/security/firewallh.rs`, `docs/Security_Secrets/firewall.md`.

**Correction:**

- **Real backups, in order:**
  - enable/disable now call the real backup helpers *before* the first rule change.
  - On any backup error they return `ok:false` with `firewall.rules_save_failed` or `firewall.io_error`, a non-zero status, and no change.
  - iptables enable with `family=any` backs up both IPv4 and IPv6. `backup_path` is the IPv4 file, and every written file is listed in `actions`.
- **Safe writer `write_rules_backup`:**
  - Creates `/var/backups/firewall` with mode 0700 if missing, and refuses a symlinked or non-directory backup directory.
  - Writes a new 0600 file with `create_new` and `O_NOFOLLOW`, so it never overwrites and never follows a link.
  - Syncs the file and removes a partial file on error.
  - File names are unique: millisecond timestamp plus process id.
  - `rules.reload` uses the same writer, so its backups also moved from `/tmp` to `/var/backups/firewall`.
- **Reported path:** the path is the file actually written.
- **Dry run:** describes the backup as "new backup in /var/backups/firewall/ (not written in dry run)" instead of inventing a filename.
- **ufw/firewalld:** these take no backup. Dry run and real runs now add a warning saying so, instead of a dry-run action that claimed one.
- **`backup_before_apply` parsing:** the three parsers (`== "true"`, `parse().unwrap_or(true)`, strict) now use the shared Stage 1 `lenient::bool_arg`. `no` and `0` mean no backup, and garbage is an error.
- **No shell in enable:** iptables enable passed the rules path through `sh -c "<restore> < <path>"` with the path unquoted. It now passes the file as an argument, as disable already did. This is noted under [Stage 1 residual risks](#security-residual-risks): it was a Medium finding, fixed here because the mock tests cannot verify ordering through a shell.
- **Test seam:** `resolve_program` and `firewall_backup_dir` consult a `#[cfg(test)]` thread-local seam. In production they are exactly the command name and `/var/backups/firewall`. In tests, every firewall command for that thread resolves to a mock directory. A command without a mock fails; it never falls back to `PATH`.

**Regression tests** (`firewallh::backup_tests`, mocks log their argv; the host firewall is never touched):

- `nft_disable_writes_backup_before_flushing`: the file exists, is mode 0600, contains the captured ruleset, and is the reported path. The capture runs before `nft flush ruleset`.
- `iptables_enable_backs_up_then_restores_without_a_shell`
- `backup_write_failure_prevents_any_change`: for nftables and iptables, no `nft flush` or `iptables -F/-P` runs.
- `backup_directory_permission_failure_prevents_change`: skipped automatically when running as root.
- `symlinked_backup_directory_is_refused`
- `mutation_failure_after_backup_is_a_failure`: the backup is kept, `ok:false`, and the exit is non-zero.
- `no_backup_requested_means_none_reported`
- `dry_run_writes_no_backup_and_changes_nothing`: enable and disable, iptables and nftables, `dry_run=true/1/yes`.
- `write_rules_backup_never_overwrites`

**Remaining limitations:**

- `run_command_with_timeout` wraps a blocking `Command::output` in `tokio::time::timeout`, so firewall timeouts still cannot fire. This is a separate review finding, not in the Stage 2 list.
- The nftables status parser recognises only `table ip`/`table ip6`, not `table inet`, so an inet-only ruleset reads as inactive. This is pre-existing and was found while writing the fixtures.

### FUNC-04 — Git synchronization correctness (H11)

**Original behavior:**

- `sync_fetch` called `pull`, which fetched and *also* fast-forwarded when possible.
- On divergent history it failed with "merge operation not yet implemented", which sync reported as "fetch failed".
- When `pull` succeeded, `sync_rebase`/`sync_merge` returned `{"status":"rebased"}`/`{"status":"merged"}` without doing anything, and sync then pushed by default.
- `remote_branch` differing from the local branch made `pull` integrate into the local branch named after the *remote* branch.

**Root cause:** placeholder integration functions, and a fetch step that silently performed the real integration.

**Files changed:** `src/handles/system/gith.rs`, `docs/Packages_Software/git.md`.

**Correction.** Full rebase/merge would be a new Git workflow, so the unsupported path is rejected explicitly, as the brief directs:

- **Fetch step:** `sync_fetch` asks `pull` for fast-forward only and returns its real result.
- **Divergence:**
  - Under `rebase`/`merge` it fails with `git.sync_failed`: "'main' and 'origin/main' have diverged; git sync can only fast-forward, so pull_strategy=merge was not performed and nothing was pushed. Rebase or merge manually, then run sync again."
  - Under `ff_only` it fails with `git.sync_non_fast_forward`, as before.
- **Reporting:** `integration` reports what happened: `fast_forward` (with the commit count) or `up_to_date`. `mode` is the requested strategy.
- **Removed code:** `sync_integrate`, `sync_rebase`, `sync_merge` and `sync_fast_forward`. The first three were the placeholders; the last became redundant.
- **Push only after integration:** fetch, integration and push run as one fallible block, so a failed step never reaches push.
- **Stash:** if sync fails after auto-stashing (`stash_uncommitted=true`), the stash is popped back before returning the error. Previously the user's uncommitted work was left in the stash.
- **Different remote branch:** `remote_branch` ≠ local branch is rejected (`git.sync_invalid_config`).
- **Help and docs:** the verb definition, the dry-run plan text and `git.md` now describe fast-forward-only behavior.

**Regression tests** (`gith::sync_correctness_tests`): a bare "remote" plus two clones in a `TempDir`, connected by local file paths. No network, no real remotes, and no user git config is required.

- `ahead_only_pushes_and_reports_no_integration`
- `behind_only_fast_forwards_for_every_strategy`
- `divergent_history_fails_and_pushes_nothing`: rebase, merge and ff_only. The remote ref is unchanged and the local commit is kept.
- `conflicting_divergence_is_rejected_without_touching_files`: the "merge conflict" and "rebase conflict" cases. The working tree is unchanged and the repository state is `Clean`.
- `failed_fetch_fails_without_push`
- `failed_push_is_an_error`
- `different_remote_branch_is_rejected`: the "unsupported integration mode" case.
- `stash_is_restored_when_sync_fails`
- `dry_run_describes_fast_forward_only`

**Remaining limitations:**

- sync never rebases or merges. The separate `git merge` and `git rebase` verbs are unchanged.
- sync's JSON still goes through `println!` rather than `io.stdout` (the review's Medium item).

### FUNC-05 — Cron comment preservation (H10)

**Original behavior:**

- Any `#` line of six or more words, or starting with `@`, parsed as a disabled job. `enable match_command=backup` would uncomment `# Runs the nightly backup for all the web servers` into the crontab as a live line.
- Separately, systemd timer discovery read the first word of each `systemctl list-timers` line. That word is part of the NEXT timestamp (for example `Sat`), so rm, enable and disable never matched a timer.

**Root cause:** `parse_potentially_disabled_cron_line` did not check that the commented content was a schedule. Timer discovery assumed UNIT was the first column.

**Files changed:** `src/handles/processes/cronh.rs`.

**Correction:**

- **Disabled-job detection:** a commented line is a disabled job only if `looks_like_cron_schedule` holds. That means five valid time fields (`*`, numbers, ranges, steps, lists, three-letter month and day names) followed by a command, or a known `@` keyword plus a command. Anything else stays a comment.
- **Timer discovery:** `timer_unit()` takes the word ending in `.timer` from each line. It is used at all four discovery sites.
- **`rm` on timers:** now that discovery matches, the previously unreachable `rm` timer path is reachable. It ignored `systemctl stop/disable` failures, so a timer that could not be disabled is now reported in `warnings` and not listed as removed.

**Regression tests** (`cronh::tests`). The fixture crontab contains the Debian header comment, `SHELL`/`MAILTO`, blank lines, a prose comment, an active job, disabled jobs with similar names, an `@daily` job, a comment with five digits, and malformed commented entries.

- `enable_never_uncomments_ordinary_comments`: exactly the three real disabled jobs change, and the line count, blank lines, env lines and comments are preserved.
- `enable_by_command_touches_only_the_matching_job`
- `disable_then_enable_round_trips_a_crontab`: the round trip is byte-identical.
- `cron_schedule_detection`
- `timer_unit_is_read_from_the_unit_column`

A **mutation check** (guard disabled) made two of these tests fail. The original code was then restored.

The host crontab was never read or written: these functions operate on strings.

**Remaining limitations:**

- A commented line that *is* a valid cron entry, such as the `# 0 5 * * 1 tar ...` example in Debian's template, is still a disabled job and can be enabled by a broad `match_command`. Telling a disabled job from an example would need a marker format change.
- The weekday off-by-one and `OnCalendar` translation issues in the review are Medium and not addressed.

### FUNC-06 — ZIP encryption correctness (H8)

**Original behavior:** `archive://.create format=zip password=...` produced a plaintext zip and reported `ok: true`.

**Root cause:** the password was parsed and never used. `supports_password()` returned true for zip and 7z, but no writer can encrypt: zip 0.6.6 keeps its ZipCrypto writer `pub(crate)` (`FileOptions::with_deprecated_encryption`), and 7z creation is unsupported.

**Files changed:** `src/handles/filesystem/archiveh.rs`.

**Correction:**

- Real encryption would need a dependency change or a new crypto implementation, so the request is rejected, as the brief directs.
- `supports_password()` is false for every format. A `password=` value, even an empty one, now fails during option validation, *before* any file is opened. The error is the existing, previously unused code `archive.create_password_not_supported`.
- There is no plaintext fallback. Ordinary zip creation is unchanged.
- The help usage no longer lists `password=`, and its definition says encrypted archives are not supported.

**Regression tests:**

- `zip_password_tests::plain_zip_creation_still_works`: the archive is created and read back.
- `zip_password_tests::password_request_is_rejected_and_writes_nothing`: checks the non-zero status, the error code, that no output file exists, and that the password is not echoed.
- `tests::test_password_support`, updated.

The "extraction without/with the password" tests do not apply, because encryption is not supported.

**Remaining limitations:** encrypted archive creation is unavailable until the zip dependency is upgraded (tied to H4).

### FUNC-07 — Service instance identity (H9)

**Original behavior:** `svc://getty@tty1.stop` acted on `tty1.service`.

**Root cause:** the URL parser reads `getty` as userinfo and `tty1` as the host. `SvcHandle::from_url` used only the host and path.

**Files changed:** `src/handles/processes/svch.rs`.

**Correction:**

- **Full name kept:** `from_url` keeps the userinfo, percent-decoded, so the name is `getty@tty1` and the unit is `getty@tty1.service`.
- **Name validation:** `validate_service_name` runs before any verb, and so before any `systemctl`/`rc-service` call. It rejects:
  - an empty name
  - a leading `-` (option injection)
  - `.` or `..` path segments (the review's OpenRC log path item)
  - whitespace or control characters
  - `:` (a `user:password@` form)
- Rejection is exit 2 with a stderr reason.

**Regression tests** (`svch::tests`; no real service is touched):

- `instance_unit_names_are_preserved`: through the real stage parser. Covers `getty@tty1`, `openvpn-client@work`, `container-getty@1.service`, `user@1000`, ordinary names, and similar names that stay distinct (`tty1`, `tty11`).
- `invalid_service_names_are_rejected_before_any_command`
- `missing_services_are_failures`

**Live:**

- `svc://-H.status` exits 2 with `invalid service name "-H": starts with '-'`.
- Status of an existing and of a missing service behaves as described under FUNC-02.

**Remaining limitations:** svc has no backend seam, so systemd behavior is verified at the parser and helper level only. This host runs OpenRC.

### FUNC-08 — Backup timeout enforcement (H7, timeout part)

**Original behavior:** `timeout_ms` never fired, so a hung backend hung resh forever.

**Root cause:** `execute_backend_command` put the child in an `Arc<Mutex<Option<Child>>>` for a timer thread to kill. The main thread immediately `take()`d it to call `wait_with_output()`, so the timer always found `None` and killed nothing.

**Files changed:** `src/handles/automation/backuph.rs`, `docs/known_issues.md`.

**Correction:**

- **`wait_with_deadline`:**
  - Drains stdout and stderr on reader threads, so a full pipe cannot block the child.
  - Polls `try_wait` until the deadline.
  - At the deadline it kills the child and reaps it, so no zombie is left, and returns a timeout.
- The verb then fails with the existing `TIMEOUT` error kind and a non-zero status.
- Fast commands are unaffected.

**Regression tests** (`backuph::timeout_tests`, using sub-second delays):

- `deadline_kills_and_reaps_a_hung_backend`: `sleep 5` with a 200 ms limit returns in under 2 s, and the pid is gone.
- `fast_commands_are_unaffected`: exit code and output are preserved.
- `large_output_does_not_deadlock`: 300 KB of output.
- `backend_command_timeout_is_an_error`

**Remaining limitations:**

- Only the direct child is killed, matching the original intent. A backend that forks workers may leave them running.
- Reader threads are not joined after a timeout, so they end when the pipes close.

### FUNC-09 — Relative file directory handling (H16)

**Original behavior:** `file://./sub.find` failed with `Error: "sub" is a directory`, while the absolute path worked. delete, move, rename, chmod, chown, ea and tag on relative directories failed the same way.

**Root cause:** `resolve_file_path` returned absolute paths unchanged but bailed on any *relative* path that was a directory. Its other branches resolve a relative path against the cwd, which is what the OS does anyway.

**Files changed:** `src/handles/filesystem/fileh.rs`.

**Correction:**

- A directory is passed through exactly as an absolute path already was, and each verb applies its own file/directory rules. `read` on a directory still fails ("Is a directory").
- Normalization, symlink behavior, and the Stage 1 archive protections are untouched.

**Regression tests** (`fileh::relative_dir_tests`):

- `relative_directories_are_accepted`: `src`, `./src`, `src/core`, nested, through `find` and `stat`.
- `relative_and_absolute_directories_agree`
- `missing_and_misused_paths_still_fail_with_a_reason`
- `traversal_and_symlinks_are_not_rewritten`: `..` is normalized lexically, and a symlinked directory is not canonicalized.

**Live** (scratch directory):

- `file://./sub.find`, `file://sub/nested.find` and the absolute form return the same entries.
- A missing directory gives `Error: path not found`, exit 2.
- `file://./sub.read` gives `Error: Is a directory`, exit 1.

**Remaining limitations:** none identified. The file handle has no root boundary by design (it acts with the user's permissions). That is unchanged.

### Additional High functional findings from the original review

**H7 — `backup://<profile>` ignored.**

- **Original behavior:** `from_url` read only the URL path, but the documented form `backup://db` puts the profile in the host. Every profile became `default`, so profiles shared default repositories and definitions.
- **Correction:** the profile comes from the host, from the path (`backup:///legacy`), or from both joined (`backup://db/nightly`). It is percent-decoded.
- **Tests:** `backuph::profile_tests` (2).

**H15 — `snapshot diff from=<name>` always failed.**

- **Original behavior:** `resolve_tree` looked snapshots up by UUID only, so the help's own example `from=backup-v1` failed.
- **Correction:** it now falls back to the snapshot name given at create. The error names both lookups.
- **Test:** `snapshot::diff_by_name_tests`. It creates a snapshot named `backup-v1`, edits a file, and checks that `diff from=backup-v1 to=live` reports 1 modified file. It runs in a `#[cfg(test)]` per-thread store, so the user's `~/.local/state/resh/snapshots` is never touched.

**H12 — Event hooks corrupted JSON.**

- **Original behavior:** the eight built-in hook notes used `println!` to the process stdout.
- **Correction:** they now go to stderr.
- **Live check:** with `XDG_STATE_HOME` pointed at the scratch directory, `event://.emit ... tags=["mq:jobs"]` produces valid JSON on stdout and the hook note on stderr.

**H4 — Fresh clone cannot resolve dependencies.** Not changed. Fixing it needs a lockfile policy and a dependency change, which this stage is not authorized to make.

## Test Results

**Test command:** the same safe command and skips as the verification review and Stage 1.

```
env -u MAIL_SMTP_USERNAME -u MAIL_SMTP_PASSWORD -u TEST_POSTGRES_DSN -u TEST_MYSQL_DSN \
    -u TEST_REDIS_URL -u TEST_MEMCACHED_ADDR \
  cargo test --no-fail-fast -- --skip test_disable_verb_recognized \
    --skip gith::tests::test_timeout_functionality --skip https_ \
    --skip dbh::tests::test_postgres_ --skip dbh::tests::test_mysql_
```

| Command / suite | Baseline (before Stage 2) | After Stage 2 |
|---|---|---|
| `cargo check --all-targets` | pass | **pass** (exit 0) |
| `cargo build --all-targets` | pass | **pass** (exit 0) |
| Unit tests, lib target | 1082 passed, 14 failed, 13 skipped | **1129 passed, 14 failed, 13 skipped** |
| Unit tests, bin target (same tests compiled again) | 1086 passed, 14 failed, 13 skipped | **1133 passed, 14 failed, 13 skipped** |
| `tests/help_cli.rs` | 16 passed | **16 passed** |
| `tests/help_coverage.rs` | 2 passed | **2 passed** |
| Compiler warnings, lib / bin / lib test / bin test | 288 / 422 / 358 / 484 | **287 / 421 / 357 / 483** (none new; the unused `Arc` import in backuph is gone) |
| `cargo fmt --all -- --check` | fails repo-wide (about 14,600 hunks at review time) | **still fails** (14,994 hunks across the whole unformatted tree). Not a gate; nothing was reformatted, as instructed. |
| `cargo clippy --all-targets` | fails (pre-existing deny-level lints in `dbh` tests and `mailh`, plus about 1,800 warnings) | **still fails, for the same pre-existing errors.** 1,812 sites. |

**Clippy on changed lines:** clippy's output was intersected with every line the working tree adds.

- Two findings were in Stage 2 code, and both are fixed: a collapsible `if` in `looks_like_cron_schedule`, and an `== false` in a firewall test.
- The other hits on changed lines are pre-existing patterns:
  - Three collapsible `if let` blocks in the cron timer loops, where Stage 2 changed only the condition.
  - The Stage 1 `type_complexity` in `firewallh::dry_run_tests`.
  - The already-reported unused `available_updates` in `pkgh.rs`.

**Classification of the results:**

- **New tests:** 47, all passing:

  | Area | New tests |
  |---|---|
  | core | 3 |
  | firewall | 9 |
  | cron | 7 |
  | ssh | 1 |
  | svc | 3 |
  | pkg | 1 |
  | db | 1 |
  | git | 9 |
  | archive | 2 |
  | backup | 6 |
  | file | 4 |
  | snapshot | 1 |

- **Tests changed to the corrected contract (3):**
  - `sshh::tests::test_command_with_different_exit_codes`: a remote non-zero exit is now a failure.
  - `archiveh::tests::test_password_support`: no format supports password creation.
  - `tests/help_cli.rs::normal_status_execution_unchanged`: status of a missing service now exits 1 with a reason on stderr. The test's purpose, that help interception does not change normal execution, is still asserted.
- **Help text:** the `archive create` and `git sync` definitions changed and still pass `help_coverage`'s one-sentence rule. No golden file changed.
- **Pre-existing failures:** 14, the identical set before and after (compared by name):
  - `userh::tests::test_groups_verb_*` (6)
  - `userh::tests::test_unlock_*` (5)
  - `gith::tests::{test_connection_not_found, test_status_integration_detached_head, test_validate_tag_config_delete}`
- **Introduced by Stage 2:** none. A first full run showed two integration failures caused by Stage 2: the help sentence rule and the pinned exit-0 test. Both were corrected, and the final run above is clean apart from the pre-existing 14.
- **Environmental:** the same as the baseline. The 6 mail DNS tests and the memcached tests depend on the host. The firewall permission test skips itself as root.
- **Skipped for safety:** the same 13 as the baseline.

**Mutation checks:**

- **FUNC-05:** with the comment guard disabled, 2 cron tests fail.
- **FUNC-03:** with the backup writer reporting a path without writing a file (the original defect), 7 of the 9 firewall backup tests fail.
- The originals were restored, and the suites were re-run green.
- After the two clippy fixes, the cron (21) and firewall (41) suites were re-run and pass.

**Live checks** (built binary; read-only or confined to the scratch directory):

- The FUNC-01 reproductions in the table above.
- `svc` status of a missing service, an existing service, and an invalid name.
- `file://` relative, nested and absolute directories, a missing directory, and `read` on a directory.
- `event://.emit` with `XDG_STATE_HOME` in the scratch directory.

No firewall, cron, package, service, ssh or git operation was run against the host or a real remote.

## Stage 1 Regression Verification

**All Stage 1 protections remain intact.**

- **Stage 1 tests:** every Stage 1 regression test still passes in the final run. Those are `archiveh::extract_safety_tests`, the plugin store and engine traversal tests, the `proch` PID tests, `pkgh::cmdline_safety_tests`, the `lenient`/`parse`/`core` dry-run tests, and the `cron`/`user`/`firewall`/`ssh`/`plugin` `dry_run_tests`, plus the previously fixed `test_path_sanitization`. That is 59 tests, each passing in both the lib and bin builds (118 passing executions, 0 failures).
- **Stage 1 security code** was not modified:
  - archive extraction containment
  - plugin id and version validation and guarded deletes
  - PID range checks
  - the pkg argv-only execution and `check_pkg_token`
  - the shared `dry_run` parser
- **Places where Stage 2 code touches Stage 1 areas:**
  - **Firewall:** `backup_before_apply` now uses the Stage 1 `lenient::bool_arg`. The Stage 1 dry-run parsing is unchanged, and is now also verified end to end for enable/disable.
  - **pkg:** only the exit status of the mutating verbs changed. Command building and validation are untouched.
  - **ssh:** only the result classification after execution changed. The dry-run path, with zero ssh invocations, is unchanged and its tests pass.
  - **cron:** `dry_run` reading is unchanged. The new `verb_status` only reads the rendered result.
- **Dry run stays non-mutating:**
  - Firewall enable/disable dry runs are now shown to run no rule-changing command and write no backup.
  - git sync dry run returns before fetching.
  - The zip password rejection happens before any file is opened.

## Security Residual Risks

Carried forward from Stage 1, with their status after Stage 2:

| Risk | Status after Stage 2 |
|---|---|
| Firewall dry-run lacked end-to-end verification | **Closed for enable/disable on iptables and nftables.** `firewallh::backup_tests::dry_run_writes_no_backup_and_changes_nothing` drives `call()` with `dry_run=true/1/yes` against mock executables and shows that no rule-changing command runs and no backup is written. rules.add/delete/reload dry runs are still verified at the parser level only. |
| Package-manager behavior needs disposable-VM testing | **Open.** Unchanged. The new partial-failure exit status is also not run against real package managers. |
| Archive and plugin filesystem race conditions | **Open.** Unchanged (path-based checks, not `openat`). |
| Plugin artifact symlinks may affect files outside the extraction boundary | **Open, assessed below: High, not a release-blocking Critical.** |
| Missing plugin checksums may be accepted | **Open, assessed below: High, not a release-blocking Critical.** |
| Package restore lacks package-name validation | **Open.** Unchanged (argv only, no shell). |
| Other booleans may parse inconsistently, including `allow_symlinks=no` | **Open, narrowed.** Firewall `backup_before_apply` now uses the shared parser, because it decides whether a required backup happens (FUNC-03). `allow_symlinks`, `force`, `purge` and others are unchanged. |

**Security-relevant corrections made inside Stage 2 fixes,** each narrowly necessary and documented above:

- **Firewall backup writer.** The `rules.reload` backups previously went to predictable `/tmp` names via `fs::write`, which follows symlinks. They now use the same 0600 `create_new`/`O_NOFOLLOW` writer in a 0700 directory.
- **Firewall iptables enable** no longer runs `sh -c` with an unquoted path.
- **svc** rejects names starting with `-`, names with `..`, and similar, before any command runs. This closes the review's Low OpenRC log-path item.
- **zip:** no plaintext archive is produced when a password is requested.

### Focused assessment: plugin artifact symlinks (H13 part)

- **Source path.** `engine.rs` `extract_tar_gz` calls `tar::Archive::unpack(staging_dir)`. In tar 0.4.44 (the locked version), `unpack` validates every entry against the destination (`validate_inside_dst` canonicalizes parents). Archive entries therefore **cannot write outside staging**, either directly or through a symlink created earlier in the archive.
- **The residual issue** is `store.rs` `copy_directory`, which copies staging into `versions/<v>`:
  - It uses `src_path.is_dir()` and `fs::copy`, both of which follow symlinks.
  - A crafted tarball containing `bin/plugin -> /home/user/.ssh/id_ed25519` makes install *read* the target and write a copy inside the user's own plugin store. `store.rs:245` then ORs `0o755` onto the binary's mode, making the copy world-readable.
  - A link to a large directory makes install copy it recursively (disk exhaustion). A link to `.` recurses until the path is too long, then fails.
- **What it cannot do:** it does **not** write outside the plugin store, and it does not escalate privilege. Installing a plugin already means trusting its publisher to run arbitrary code with the user's privileges.
- **Assessment:** local information disclosure and denial of service at install time, below the trust the user already extends to the plugin. **High, not Critical. Not a new release blocker** beyond H13 as already reported.

### Focused assessment: missing plugin checksums (H13 part)

- **Source path.** `engine.rs` `verify_artifact` adds the action "No checksum to verify" and returns `Ok` when the candidate has no `sha256`. URL and file sources always lack one (`registry.rs`).
- **Impact:**
  - Where a registry is fetched over `http://`, which is accepted, a network attacker can substitute the artifact. The result is code execution as the user when the plugin runs.
  - Over `https://`, the checksum comes from the same origin as the artifact, so it adds little beyond TLS.
- **Assessment:** exploitable only with an `http://` registry or URL source and a network-position attacker, or with control of the registry. **High, not a confirmed exploitable Critical** in the default configuration. It is reported, as Stage 1 did, for the security stage.

**Release blockers identified:** none new. The Critical and High items from the original review that are outside Stage 2's functional scope keep their original status: H1-H2 and C1-C3 were addressed in Stage 1; H13, H14 and H4 remain open.

## Remaining Functional Findings

These items from the original review were not changed in Stage 2, because they are Medium or Low, or outside the defect list:

- **Firewall:** timeouts are ineffective (blocking command inside `tokio::time::timeout`). The nftables status parser ignores `table inet`.
- **git:**
  - Output via `println!` bypasses `io.stdout` and `--json-pretty` (25 sites).
  - `timeout_ms` cannot fire.
  - `pull` on diverged branches still returns "not yet implemented".
- **cron:**
  - The weekday numbering is off by one against the `cron` crate.
  - `allow_duplicate` defaults to true.
  - The `OnCalendar` translation is wrong for `@weekly`, `* * * * *` and ranges.
  - Newline injection in `description`/`id`/`command`/`env` (a security Medium).
  - A commented valid cron entry, such as a template example, can still be enabled.
- **http:** `allow_insecure` is honored only by `put`.
- **cache:** numeric CLI values are dropped (SCAN paging never advances), and memcached `exists`/`ttl` report true for missing keys.
- **pkg:** `restore` ignores locked versions. install writes `eprintln!` to process stderr.
- **file:**
  - `rename overwrite=true` deletes the destination first.
  - `find include_hidden=false` descends into hidden directories.
  - `preview`/`schema` allocate `max_bytes` unbounded.
- **archive:** tar `add` loses metadata, `.gz`/`.xz`/`.zst` output names fail without `format=`, and raw decompression checks size limits after writing.
- **fs:** negative `resize delta` never works, and `all_subjects` is a stub.
- **proc:** `limits.set` affects resh itself, `io.peek` reads files nothing writes, and debug-build overflow panics are possible.
- **net:** `ping` counts ICMP errors as replies.
- **mq:** the temp file matches the message filter, so `get` can race with `put`.
- **system:** some documented `info` options are ignored, and `disk` panics on non-ASCII device names.
- **snapshot:** `ls` does not find snapshots created with relative targets, and the TTL can overflow and panic.
- **event:** `list-topics` returns sample data, and `hooks.disable` always reports success.
- **user:** `create_home` and `password_hash` are unused. `delete` reports `was_present` without checking.
- **Error channel:** db, cache, cert, proc and system write JSON errors to stdout (each now also gets a stderr line from FUNC-01).
- **CLI:** `resh` with no stage panics. The global dotted-verb list mis-splits targets ending in generic words.
- **Quality and documentation:** the prose documentation under `docs/` still contradicts the code widely. The 14 already-failing unit tests remain. `cargo fmt` and `clippy -D warnings` still fail repo-wide.

## Stage 2 Recommendation

**STAGE 2 CONDITIONALLY COMPLETE**

- All nine in-scope defects are corrected, and so are three further High functional findings (H7 profiles, H12, H15).
- Each fix has regression tests. Several run end to end through `call()` with mock executables or temporary repositories. Mutation checks were run for FUNC-03 and FUNC-05.
- No new test failures were introduced, and the Stage 1 protections are intact.
- Two defects were corrected by **explicit rejection** rather than new functionality, as the brief directs:
  - git sync refuses divergent history.
  - zip creation refuses a password.

**Conditions:**

1. **No live run on real systems.** pkg partial-failure, db ping and svc systemd status were verified through helper-level tests, not real package managers, databases or a systemd host. Disposable-VM or container validation is still recommended, together with the Stage 1 pkg condition.
2. **Explicit rejections need an owner decision.** git sync rebase/merge of divergent history and encrypted zip creation are now explicitly unsupported. Implementing them is new functionality and needs a decision.
3. **Known gaps remain out of scope.** Firewall and git timeouts, and the other Medium items above, were not in the Stage 2 list.

Stage 3 has not been started. No commits or pushes were made. Awaiting project-owner approval.
