# resh CLI — Stage 6B: Security Code Review, Controlled Commits, and CI Validation

| | |
|---|---|
| Release under preparation | v1.0.4-beta |
| Branch | `security/v1.0.4-beta-remediation` (worktree `resh-sec-v104`) |
| Base | `main` @ `facd6aa9376db5c7515d0c73d9f1514285e235d9` |
| Published release (unchanged) | v1.0.3-beta @ `dcce21ad0dbb749d2172a57c25841bb253a7bbd7` |
| Review date | 2026-10-27 |
| Status | **Gate B complete: CI green; awaiting merge approval** (branch pushed, not merged) |
| Security branch tip | `be9e1fc44754f1a36f6f010eefae9605a68153e1` (pushed to origin) |

## 1. Executive summary

The Stage 6B remediation for backup argument injection, cron/systemd injection,
ssh `exec` argument quoting and the `ecdsa_sha512` signing defect was reviewed
file by file against the code paths that actually execute. The fixes are sound
and cover every verb that reaches a subprocess or file write. The review found
no remaining High-severity path.

The review made five additional corrections, all inside the Stage 6B scope. The
largest is a cron `%` escape-parity gap. File-mode preservation and an
`O_NOFOLLOW` read were added to the atomic writer. A pre-existing path that
could replace an unreadable `/etc/crontab` with a single line was fixed. The
documentation was also made accurate where it over-claimed: shell coverage in
ssh.md and backend dry-run side effects in backup.md.

Local results: formatting is clean, the stable build passes, the full test suite
passes (0 failures), and the Stage 6B suites pass. Clippy shows no new findings.
MSRV 1.88 and `cargo audit` cannot be run locally and are left to CI.

Classification at this point: **CONDITIONALLY READY**. The code is complete;
owner approval for commits (Gate A), the push (Gate B) and a CI run are still
pending.

**Gate A update (2026-10-27).** The two open review findings are closed.
B-H1 (exported backup helpers) is **not reachable**: the helpers are private
to the crate, which a compile probe confirmed, so no code change was needed
(§13.1). S-H1 (ssh error metadata) is fixed (§13.2). The cron/systemd
filesystem re-check found one more Low issue: a leftover atomic-write
temporary file in `/etc/cron.d` would be loaded by cronie. It is fixed (§13.3).
The six commits are made locally (§6), and all local checks pass on the
committed tree (§13.6). Classification: **READY FOR PUSH APPROVAL** (§13.9).

## 2. Reviewed files

Exactly the expected set; no unexpected changes.

| File | Change |
|---|---|
| `src/handles/automation/backuph.rs` | Argument validation and argv hardening; `dry_run_mode` |
| `src/handles/processes/cronh.rs` | Field validation; unit escaping; `cron_file` restriction; atomic writer |
| `src/handles/network/sshh.rs` | POSIX quoting of `command_args`; Windows-mode refusal; unknown `shell_mode` refused; exact `command.raw` |
| `src/handles/security/certh.rs` | P-384 + `ecdsa_sha512` signs a SHA-512 digest; clearer refusal |
| `tests/stage6b_security.rs` (new) | 23 end-to-end tests through the real binary |
| `.github/workflows/ci.yml` | Security job runs the new unit modules and `stage6b_security` |
| `docs/Automation_Utilities/backup.md`, `docs/Process_ServiceManagement/cron.md`, `docs/Network_RemoteOperations/ssh.md`, `docs/Security_Secrets/cert.md`, `docs/known_issues.md` | Behaviour and limitation updates |

`Cargo.toml` and `Cargo.lock` are unchanged: no dependency was added or updated.

## 3. Security code-review findings

### 3.1 Backup (backuph.rs)

* **Validation is complete and runs first.** `validate_request` runs in all
  five verbs that build backend commands (`create`, `list`, `restore`,
  `verify`, `prune`). It runs after backend and repository selection and
  before any dry-run plan, password lookup or execution. `schedule` executes
  nothing and writes nothing.
* **Positionals cannot become options.** Every backend command puts sources,
  repository and snapshot after `--`, and option values are attached with
  `=`. The positionals also cannot start with `-`, which protects tar's `-C <dest>`
  and `-f <archive>`, where `--` does not apply.
* **Backend-specific syntax.** tar always runs with `--force-local`, so it never
  reads `host:file`. rsync gets local relative paths with a `./` prefix, so a path
  is never read as `host:path` or `rsync://`. Absolute paths cannot be remote,
  because the `:` comes after the first `/`.
* **Remote repositories.** For borg and restic, any `-` that follows `:`, `@`,
  `[` or `//` is refused. That covers the ssh, sftp and rclone forms and leaves
  `s3:https://…` alone. restic receives the repository through `RESTIC_REPOSITORY`,
  not argv.
* **Snapshot IDs.** For tar and rsync, a snapshot ID must be a single directory
  entry: no `/`, and not `.` or `..`. For restic, `id:subpath` stays a value
  after `--`. For borg, the ID is bound to `repo::id`.
* **Labels.** A label is sanitized to `[A-Za-z0-9._-]` before it becomes a file
  name; this was already the case.
* **Failures propagate.** A non-zero backend exit returns `BACKEND_FAILED` with
  the backend's exit code. A validation refusal returns `INVALID_ARGS`, exit 1,
  and names the field in `details.field`.
* **Alternate paths.** `src/handles/automation/backup/` (`ResticTool`,
  `BorgTool`, `ToolRunner`) builds restic and borg commands without this
  validation. No CLI verb references it. Gate A correction: it is **not**
  reachable through the library crate either, because `handles::automation`
  is a private module (§13.1).

### 3.2 Cron and systemd (cronh.rs)

* **Field-specific checks.** Checks run before any write and before any dry-run
  preview: control characters are refused everywhere; the schedule must be five
  crontab fields or an `@` keyword (six-field schedules are now refused); and
  `id`, user names, unit names, time spans, working directory and env names each
  have their own rule.
* **systemd values.** `%` is doubled, `Environment=` values are escaped, a
  trailing `\` continuation is refused, and `ExecStart=` prefix characters are
  refused. The timer is enabled with `systemctl enable --now -- <unit>`.
* **Destinations.** `cron_file` is limited to `/etc/crontab` and
  `/etc/cron.d/<name>` for `add` (system scope) and `disable`. `enable` and
  `rm` ignore `cron_file`: they only touch fixed paths and entries from a
  directory listing. This was verified.
* **TOCTOU.** The writer creates its temp file with `O_EXCL`, so it never follows
  a link planted at the temp name, and it then uses `rename(2)`. If a symlink is
  swapped in at the destination after the check, `rename` replaces the link
  rather than writing through it. A residual race exists only for an attacker
  who can write to the destination directory. For system scope that is root-only
  `/etc/cron.d`; for user units it is the user's own directory.

### 3.3 SSH `exec` (sshh.rs)

* **Argument boundaries.** Each `command_args` element is single-quoted unless
  it is entirely `[A-Za-z0-9_@%+:,./-]`. Tests confirm boundaries through `sh`
  (dash on CI) and `bash`; the zsh and ksh checks run only where those shells
  are installed, which is neither locally nor on CI. `command` is a command line
  by design and is documented as code.
* **Shell modes.** Unknown `shell_mode` values are now refused (`PARSE_ERROR`,
  exit 1). In cmd and PowerShell modes, arguments and `cwd` values that would
  need quoting are refused (`COMMAND_ERROR`, exit 1). fish, csh and tcsh login
  shells are documented as unsupported.
* **`command.raw`.** It equals the string passed to ssh, including the
  `cd '<cwd>' &&` prefix; v1.0.3-beta omitted the prefix. ssh gets `--` before
  `user@host`.
* **Policy authorization.** resh has no policy or audit subsystem: there is no
  policy engine in `src/core` and no audit code in `src`. The brief's policy
  and audit checks are therefore **not applicable**; they were not tested and
  are not counted as passed.

### 3.4 Certificate signing (certh.rs)

* **Algorithm handling.** P-384 with `ecdsa_sha512` now signs a SHA-512 digest
  through `sign_prehash`, which uses its leftmost 384 bits as FIPS 186-5
  specifies; before, it silently signed SHA-384. P-384 with `ecdsa_sha384` is
  unchanged.
* **Unsupported pairs.** P-256 with SHA-384 or SHA-512, and any cross-family
  pair, fail with an explicit error and write no file.
* **Independent verification.** OpenSSL verifies the SHA-512 signature with
  `-sha512` and rejects it with `-sha384`, and the reverse holds for SHA-384.
  This is covered by `cert_sign_p384_sha512_verifies_with_openssl`.
* **Earlier signatures.** cert.md and known_issues.md document that signatures
  made before this fix are mislabelled and need re-creating.

## 4. Additional corrections made in this review

| ID | File | Correction | Severity |
|---|---|---|---|
| C-1 | cronh.rs | The `%` check treated `\\%` as escaped, but cron reads `\\` as an escaped backslash, so that `%` still splits the line. The check now follows cron's escape state. Unit test added. | Low |
| C-2 | cronh.rs | The atomic writer now keeps an existing file's permission bits, creates new files 0644 less the umask, and `fsync`s before `rename`. Before, the umask could leave a cron.d file group-writable, which cronie ignores. Unit test added. | Low |
| C-3 | cronh.rs | `read_system_file` opens with `O_NOFOLLOW`, closing the gap between the symlink check and the read. | Low |
| C-4 | cronh.rs | `add` to a system cron file used `read(...).unwrap_or_default()`. An existing but unreadable file (bad UTF-8, `EACCES`) was therefore replaced by the new line alone. Only a missing file starts empty now. This was pre-existing. | Medium (data loss) |
| D-1 | ssh.md, sshh.rs comment | The shell-coverage claim is reduced to what is tested. | Docs |
| D-2 | backup.md, cron.md | Backend dry-run effects are split into verified and unverified (§10). C-1, C-2 and C-4 are documented. | Docs |
| T-1 | stage6b_security.rs | Dry-run classification now also covers restic (`backend`, `simulated:false`, `command` = the argv that ran, warning) and rsync (`plan`, no calls, no file changes). | Tests |

## 5. Regression-test results (local)

Environment: Gentoo Linux 6.18, system `rustc 1.98.1` / `cargo 1.98.1`, no
rustup. Runs were sequential in the security worktree with its own `target/`;
there was no stash and no overlapping runs.

| Check | Result |
|---|---|
| `cargo fmt --check` | Pass |
| `cargo build --locked` (stable 1.98.1) | Pass |
| `cargo test --locked --no-fail-fast` | Pass: lib 1217, bin 1221, doc_examples 2, help_cli 16, help_coverage 2, stage4_regressions 11, stage6b_security 23 = **2492 passed, 0 failed** |
| Ignored (infrastructure, not counted as passing) | 11 unique (MySQL ×4, PostgreSQL ×4, git remote ×3), listed once per lib and bin target |
| Stage 6B unit modules | 18 passed |
| Stage 6B integration (`stage6b_security`) | 23 passed (includes JSON error envelopes, exit codes, dry-run, OpenSSL verification) |
| CI security-regression filter set (50 filters) | 212 passed; **one pre-existing flaky failure on one of 9 runs** (§9) |
| Clippy `--workspace --all-targets` vs `facd6aa` | 1786 → 1785 warnings, 7 → 7 errors (all pre-existing deny lints). No new finding in touched files; 2 fewer. |
| MSRV 1.88 build/test | **Not run locally** (no 1.88 toolchain): CI only |
| `cargo audit` | **Not run locally** (not installed): CI only. The uncommitted `.cargo/audit.toml` change on `main` only edits comments, so the branch's ignore list is identical. |
| Policy / audit integration tests | **Not applicable**: no such subsystem exists |

Clippy limitation: in both trees, the lib fails clippy on the pre-existing
deny-level errors. Integration-test targets, including `stage6b_security.rs`,
are therefore not linted.

## 6. Local commit SHAs

Made at Gate A on `security/v1.0.4-beta-remediation`, parent `facd6aa`. Local only; nothing is pushed.

| # | SHA | Subject | Files |
|---|---|---|---|
| 1 | `1a0c3dbb4b16bd686cd77bcbcd83b342b1a9549e` | `fix(security): harden backup backend arguments` | `src/handles/automation/backuph.rs` |
| 2 | `69ef5bedef065bba44b95e30a9bc9123b6699da7` | `fix(security): prevent cron and systemd injection` | `src/handles/processes/cronh.rs` |
| 3 | `2edd30e505d7f97f5347645c008224a04ec7bde8` | `fix(security): preserve ssh argument boundaries` | `src/handles/network/sshh.rs` |
| 4 | `45aa917532a1b295944d48bf63eaa90255684210` | `fix(cert): correct ecdsa sha512 signing` | `src/handles/security/certh.rs` |
| 5 | `e8ae231e4e14df0f0f019fa30baf00742c52902b` | `test(security): add stage6b regression coverage` | `tests/stage6b_security.rs`, `.github/workflows/ci.yml` |
| 6 | `be9e1fc44754f1a36f6f010eefae9605a68153e1` | `docs(security): update known limitations` | `docs/Automation_Utilities/backup.md`, `docs/Process_ServiceManagement/cron.md`, `docs/Network_RemoteOperations/ssh.md`, `docs/Security_Secrets/cert.md`, `docs/known_issues.md` |

Branch tip: `be9e1fc44754f1a36f6f010eefae9605a68153e1`. Exactly the 11 files above
differ from `main`. Before each commit, the staged file list was checked,
`git diff --cached --check` passed, a credential-pattern scan found nothing,
and `.claude/` was confirmed excluded.

Each handler's in-file unit-test module ships with its fix (commits 1–4),
because Rust unit tests live in the same file.

## 7. Remote branch SHA

Pushed at Gate B (normal push, no force, explicit refspec, no tags):
`origin/security/v1.0.4-beta-remediation` = `be9e1fc44754f1a36f6f010eefae9605a68153e1`.
After the push: `origin/main` = `facd6aa`, and `v1.0.3-beta^{}` = `dcce21ad…`, both unchanged.

## 8. CI run

Run [40551985262](https://github.com/millertechnologygroup/resh/actions/runs/40551985262)
(push, `be9e1fc`): **success**.

| Job | Gate | Result | Detail |
|---|---|---|---|
| build-msrv | required | success | `rustc 1.88.0`; `--all-targets` and `--release` builds |
| test-msrv | required | success | 1.88: lib 1221, bin 1225, help_cli 16, help_coverage 2, doc_examples 2, stage4 11, stage6b 25; 0 failed; 11 ignored per lib/bin |
| test-stable | required | success | 1.98.1: same counts, 0 failed |
| test-security-regression | required | success | 1.88: filter set 216 passed (includes `firewallh::timeout_tests`; no flake this run), stage4 11, stage6b 25 |
| fmt | required | success | |
| audit | required | success | 1380 advisories, 618 crates; no vulnerabilities; 36 allowed warnings (unmaintained/informational, unchanged ignore list) |
| clippy | advisory | failure (expected) | Lib-test target: 1749 warnings, 5 errors, vs `main` @ `facd6aa` run 40426897709: 1750 warnings, 5 errors. Known baseline; one fewer warning |
| test-infrastructure | manual | skipped | Runs only on workflow_dispatch |

## 9. Remaining security risks

| Risk | Severity | Recommendation |
|---|---|---|
| `src/handles/automation/backup/` (`ResticTool`, `BorgTool`) is unvalidated command-building code. It is private to the crate and has no callers outside its own unit tests (§13.1). | Informational (latent; becomes reachable only if `handles::automation` is made public) | Remove the dead module, or route it through `validate_request`, in a separate change. |
| A flaky `ETXTBSY` failure in `firewallh::timeout_tests::large_output_does_not_deadlock_before_the_deadline` (write-then-exec mock race). It reproduces with the Stage 6B modules excluded. | CI reliability | It may fail the security job intermittently; fix the test fixture separately. |
| ~~The ssh error envelope always reports `"dry_run": false`.~~ | — | **Fixed at Gate A** (§13.2). |
| ssh quoting is tested against sh, dash and bash only; zsh and ksh are covered by analysis. fish, csh and tcsh are documented as unsupported. | Low | Optionally install zsh and ksh in the CI security job. |
| `command` (ssh, cron) is a command line by design. | By design | Documented as code. |
| tar/rsync `prune dry_run` reports `backend.simulated: false` with an empty command. This was pre-existing; `dry_run_mode: plan` is accurate. | Informational | Align in a later release. |
| `--force-local` is GNU tar-specific; bsdtar (macOS) rejects it. | Portability | Linux is the supported platform. |
| `primary_group` (user) and `fs mount` source/target lack a `--` separator (already in known_issues). | Open, pre-existing | Stage 6C candidate. |

## 10. Dry-run contract findings

| Verb / backend | `dry_run_mode` | Backend runs? | Verified by test |
|---|---|---|---|
| `create`, all backends | `plan` | No | Yes |
| `prune`, tar/rsync | `plan` | No; no files change | Yes (tar, rsync) |
| `prune`, restic/borg | `backend` | **Yes**, with the backend's own `--dry-run` | Yes (argv, label, warning, `simulated:false`) |
| `restore` | n/a | Refused before running | Pre-existing test |

The current contract represents the behaviour accurately. The output never
claims that nothing ran: it reports the `backend` mode, `simulated:false`, the
real argv and a warning. No owner decision is needed for v1.0.4-beta.

**Not verified** (restic and borg are not installed locally or in CI; based on
upstream behaviour): repository open and authentication; a network connection
for remote repositories; creating and removing a repository lock, which is a
write to the repository and can block concurrent backups; local cache and
security-metadata updates; and backend logs. backup.md now lists these as
expected effects and does not describe the backend dry run as free of side
effects.

## 11. Merge recommendation

Pending CI. If every required CI job passes, the recommendation is to merge
with owner approval. A failure of the known flaky firewall test should be
re-run on the same SHA and reported, not treated as a pass by inference.

## 12. Recommended v1.0.4-beta release sequence

1. Gate A: owner approves, then the six local commits are made.
2. Gate B: owner approves, then the security branch is pushed (no force) and CI runs on that SHA.
3. CI is reviewed and this report is updated with the run URL and job results.
4. Owner approves the merge into `main`. A fast-forward or merge commit is acceptable, as `main` has not moved since `facd6aa`.
5. A version bump, changelog and release-gate documentation follow in a separate release commit.
6. Tag `v1.0.4-beta`, then the GitHub release.
7. Decide whether to publish a security advisory. It should cover the v1.0.3-beta-and-earlier exposure in backup, cron and ssh `exec`, describe it at a high level, and include no reproduction steps.

## 13. Gate A closure (2026-10-27)

### 13.1 B-H1 — exported backup helpers: **A. Not reachable**

* `src/handles/automation/backup/mod.rs` declares `pub mod` items and
  `pub use` re-exports (`ResticTool`, `BorgTool`, `ToolRunner`,
  `RetentionPolicy`, `FilesystemSnapshots`, …). `ResticTool`/`BorgTool` build
  `restic`/`borg` commands from caller strings without `validate_request`.
* That module sits under `src/handles/mod.rs`, which declares
  `mod automation;` (private), and nothing re-exports it. The binary also
  declares `mod handles;` privately.
* No code outside `backup/` uses these types: the same-named
  `SnapshotInfo`/`RetentionPolicy` in `backuph.rs` are separate types. There
  are no plugins, examples or benches written in Rust. Plugins are external
  executables and cannot call crate items.
* Evidence: a throwaway external crate that depends on `resh` by path and
  calls `resh::handles::automation::backup::ResticTool::new` fails with
  `E0603: module automation is private`.
* Result: no callable security boundary remains, so no code change was made.
  The earlier note in §3.1 that it was reachable through the library was
  wrong and has been corrected. Recommendation: delete the dead module in a
  later cleanup, before anyone makes `automation` public.

### 13.2 S-H1 — ssh error metadata: **fixed** (commit 3)

* Before: the parse-error builder of every ssh verb (`exec`, `upload`,
  `download`, `tunnel`, `keys.list`), and the post-parse validation builders
  of `exec`, `upload` and `download`, hard-coded `"dry_run": false`. All of
  them run before the dry-run branch, so a refused `dry_run=true` request was
  reported as a normal-mode request.
* After: the parse-error builders report the requested mode
  (`requested_dry_run(args)`; a missing or malformed value reports `false`),
  and the validation builders use `options.dry_run`. Builders reached only
  after the dry-run branch were already correct by construction and are
  unchanged.
* `dry_run` (requested mode) and execution are now separate. An exec request
  refused before ssh starts also reports `result.executed: false`. When ssh
  could not be started or hit the command timeout, `result` stays omitted,
  because resh cannot know how much of the remote command ran, so it claims
  neither outcome.
* Exit codes are unchanged: 1 for refusals, the ssh or remote code otherwise.
  Refusal envelopes omit `command`. The cmd/PowerShell refusal message no
  longer echoes the refused argument value, only its field name
  (`command_args[N]`).
* Tests: the unit tests `sshh::remote_argument_tests` cover the requested
  mode, the JSON serialization of a refused envelope, and that the value is
  not echoed. The end-to-end tests `ssh_exec_refusals_report_the_requested_mode`
  (dry-run and normal validation failure, unsupported `shell_mode`) and
  `ssh_exec_subprocess_failures_are_reported` (ssh exit 255; ssh cannot be
  started) complete the coverage. A mutation check (forcing
  `requested_dry_run` to `false`) makes the end-to-end test fail.
* ssh.md and known_issues.md document the envelope fields.

### 13.3 Cron/systemd filesystem re-check

| Property | Result |
|---|---|
| Symlink-safe reads | `refuse_symlink` + `O_NOFOLLOW` open; verified |
| Symlink-safe writes | Destination link refused; temp created `O_CREAT\|O_EXCL` (never follows a planted link); `rename(2)` replaces, never writes through; covered by `writes_never_follow_links` |
| TOCTOU | Residual only for an attacker who can already write the destination directory (root for `/etc/cron.d`, `/etc/systemd/system`; the user for user units) |
| Atomic replacement | temp → `fsync` → `rename`; temp removed on failure |
| Permissions | Existing mode bits kept; new files 0644 less umask, never group- or world-writable |
| Ownership | The new inode belongs to the writer. Only root can write the system directories, which gives cron's required root ownership. Not preserved for a non-root writer; acceptable |
| Unreadable cron file | `add` fails instead of replacing it (C-4) |
| Destination escape | `cron_file` limited to `/etc/crontab` and `/etc/cron.d/<name>`; unit names validated; `rm` uses names from listings |
| **New, fixed (C-5, Low)** | The temp file was `<path>.tmp.<pid>` in the same directory. cronie loads every `/etc/cron.d` entry that does not start with `.`, so a temp file left by a crash would run as a second copy of the jobs (and one caught mid-write could be read). The temp file is now hidden (`.<name>.tmp.<pid>`). Test: `cronh::injection_tests::temporary_files_are_hidden_from_cron` |
| Informational, pre-existing | `rm remove_units=true` for `scope=user` with `HOME` unset falls back to `/.config/systemd/user`. This needs the caller's own environment, and `add` already refuses an unset `HOME`. Stage 6C candidate |

### 13.4 Flaky firewall test: CI reliability risk, pre-existing

`firewallh::timeout_tests::large_output_does_not_deadlock_before_the_deadline`
fails intermittently with `ETXTBSY`. Cause: `mock_tool` writes the script
with `fs::write` and then executes it. While another test thread forks a
child, that child inherits the still-open write descriptor until its own
`exec`. Running the script inside that window fails with "Text file busy"
(Rust issue 114554). The cause is concurrency inside the test process. It is
not a shared temporary path, because each test has its own `TempDir`, and it
is not a race between rewriting and executing the file. `firewallh.rs` is
untouched by Stage 6B, so this predates the stage. It can fail
`test-security-regression` (which runs `firewallh::timeout_tests`) and the
full test jobs even when the security code is correct.

Proposed fix, kept separate and **not applied**: `mock_tool` writes the
script through a child `sh -c 'cat > "$1" && chmod 755 "$1"'`, so the test
process never holds a write descriptor to a file it later executes. The test
is neither skipped nor weakened. It needs owner approval as its own commit.
Until then, a CI failure of this one test should be re-run on the same SHA
and reported, not treated as a pass.

### 13.5 Dry-run contract

Unchanged: `plan` for local plan generation, `backend` for restic/borg prune
running the backend's own `--dry-run`, with `simulated:false`, the argv that
ran and a warning. backup.md lists repository open and authentication,
network access, repository locks, and cache, security-metadata and log writes
as expected but unverified effects. Nothing is described as free of side
effects. Unresolved risk: those effects are not verified locally or in CI
(restic and borg are not installed).

### 13.6 Local results (Gate A, final tree)

Environment: Gentoo Linux 6.18, `rustc 1.98.1`, `cargo 1.98.1`,
`clippy 0.1.98`, `rustfmt 1.9.0`. No rustup, no 1.88 toolchain, no
`cargo-audit`. All runs were sequential and `--locked`, in the security
worktree, with no overlapping cargo commands.

| Check | Result |
|---|---|
| `cargo fmt --check` | Pass (before and after the commits) |
| `cargo build --locked` (stable 1.98.1) | Pass |
| `cargo test --locked --no-fail-fast` | **2502 passed, 0 failed**: lib 1221, bin 1225, doc_examples 2, help_cli 16, help_coverage 2, stage4_regressions 11, stage6b_security 25 |
| Ignored | 11 per lib and bin target (MySQL ×4, PostgreSQL ×4, git remote ×3); infrastructure, not counted as passing |
| CI security filter set (exact CI arguments) | 216 passed, 0 failed (the firewall flake did not occur in this run) |
| `stage4_regressions` / `stage6b_security` | 11 / 25 passed |
| backup/cron/ssh/cert modules (`backuph:: cronh:: sshh:: certh::`) | 281 passed |
| Stage 6B unit modules | 22 passed (18 earlier, plus 4 new) |
| JSON error, dry-run, OpenSSL verification | Included in stage6b_security; pass |
| Re-run against committed tip `be9e1fc` | fmt, stage6b 25, stage4 11, Stage 6B unit 22, all pass; clean worktree |
| Clippy `--workspace --all-targets` | 1785 warnings, 7 errors (identical to the earlier Stage 6B count; `facd6aa`: 1786/7). No findings on lines added at Gate A |
| MSRV 1.88 build and test | **Not run locally**; CI only |
| `cargo audit` | **Not run locally**; CI only |

### 13.7 Repository integrity

* `main` @ `facd6aa`, unchanged. Its five staged Stage 6A files are
  byte-identical to before (staged diff hash verified before and after the
  commits). `.claude/` and this report are untracked and not on the security
  branch.
* `v1.0.3-beta`: the tag object `d42f7b6c…` peels to `dcce21ad…`, locally and
  on `origin`. Unchanged.
* No push: `origin` has no `security/*` branch, and the local branch has no
  upstream. No merge, tag, release or advisory.

### 13.8 CI readiness

`.github/workflows/ci.yml` (commit 5) runs `backuph::argument_safety_tests`,
`cronh::injection_tests`, `sshh::remote_argument_tests` and
`certh::ecdsa_algorithm_tests` by name, plus `--test stage6b_security`, in
`test-security-regression` (Rust 1.88). The Gate A tests sit inside those
modules and that file, so they run. Still present and blocking:
`build-msrv` (1.88), `test-msrv` (1.88), `test-stable` (1.98.1),
`test-security-regression`, `fmt` and `audit`. Only `clippy` (the known
baseline) and the manual `test-infrastructure` job are `continue-on-error`,
the same as on `main`. The workflow diff is limited to the Stage 6B test
integration.

### 13.9 Classification and next action

**READY FOR PUSH APPROVAL.** Remaining risks: MSRV and audit are unverified
until CI runs; the pre-existing firewall flake (§13.4); restic/borg dry-run
side effects are documented but unverified; the dead `backup/` module; and
the §9 items carried forward.

Next action: the owner approves Gate B. Then push
`security/v1.0.4-beta-remediation` (no force) and review CI on
`be9e1fc44754f1a36f6f010eefae9605a68153e1`. Separately, decide on the firewall
fixture fix.

## 14. Gate B result (2026-10-27)

CI passed on `be9e1fc` (§8). MSRV 1.88 and `cargo audit` are now verified in
CI. The branch is **ready for merge approval**. Still open: the firewall
fixture fix proposed in §13.4, the release commit (version bump and
changelog), the tag, the release, and the advisory decision. Each needs its
own owner approval.

## 15. Merge into main (2026-10-27)

Approved by the owner: fast-forward, then a normal push of `main`.
`origin/main` was verified unchanged at `facd6aa` immediately before the
fast-forward and again before the push. `main` was then fast-forwarded
`facd6aa..be9e1fc`, with no merge commit, and pushed without force. The
staged Stage 6A files in the main worktree are byte-identical to before.

CI on `main` @ `be9e1fc`: run
[40554559549](https://github.com/millertechnologygroup/resh/actions/runs/40554559549),
**success**. build-msrv, test-msrv, test-stable, test-security-regression,
fmt and audit passed. clippy failed as expected (known advisory baseline), and
test-infrastructure was skipped (manual only). `v1.0.3-beta` is unchanged.
There is no new tag, release or advisory. The security branch is left in
place on origin.
