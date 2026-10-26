# Resource Shell (resh) — v1.0.2-beta Release Gate

- **Date:** 2026-10-23
- **Candidate:** tag `v1.0.2-beta` → commit `971b0d500af21b43f61af0599d74a429078dbf96`
- **Scope:** Verify the existing tagged release, then prepare publication materials for owner approval. No source, tag, dependency or CI file was changed. Nothing was committed, pushed or published.
- **Baseline:** `resh-cli-stage4-final-release-assessment.md`. Every release-critical claim in it was re-checked independently against the tag.

## Executive Summary

**Recommendation: DO NOT PUBLISH.** See [Final Recommendation](#final-recommendation).

The tag itself checks out:

- **Tag:** correct, and identical locally and on `origin`.
- **CI:** the GitHub Actions run on the tagged commit passed every gating job.
- **Builds:** clean locked builds of the tag succeed on Rust 1.88.0 (MSRV) and 1.98.1. The full default suite passes on both with 0 failures.
- **Release binary:** renders help for 28 handles, 29 schemes and 239 verb entries, and enforces dry-run safety.
- **Dependency audit:** passes, and all 18 advisory exceptions are still justified.
- **Clippy:** debt is exactly the documented baseline (1,790 sites).

This gate's independent re-assessment of the Medium risks that Stage 4 had accepted found **three confirmed release-blocking vulnerabilities**. Each was reproduced against the tagged release binary. A fourth blocker is a **committed credential** found during the tag inspection:

| ID | Blocker | Class |
|---|---|---|
| **RB-1** | `cert` private keys are created with umask permissions (0644) and only then chmod'ed to 0600. A local reader who opens the file in that window keeps the key. Key writes follow symlinks, including dangling ones, and that bypasses `overwrite=false`. | Sensitive-data exposure; arbitrary file write as root |
| **RB-2** | `file replace backup=<suffix>` and `archive add backup_suffix=` copy through a symlink planted at the backup name. The symlink's target is overwritten and its mode changed. | Arbitrary file modification (root privilege escalation when root edits a file in a directory another account can write) |
| **RB-3** | The default backup repositories (`/tmp/resh_backup_<profile>`, `/tmp/rsync_backup`, `/tmp/borg_repo`) are created with default permissions. A pre-existing directory is accepted whoever owns it. A default `tar` backup run as root leaves a world-readable archive of the backed-up data. If another user pre-created the directory, a restore as root installs that user's content. | Sensitive-data exposure; privilege escalation |
| **RB-4** | `MYSQL_CONNECTION_GUIDE.md` (tracked at the repository root) contains a real-looking MySQL DSN with a password for a named user account at a private-network (RFC 1918) host. The user name and host are deliberately not repeated here. It has been in public history since 2025-12-19 (`v1.0.0-beta`, `v1.0.1-beta`, `main`). | Secret committed to a public repository |

RB-1 through RB-3 need narrow source corrections. Under the rules of this assignment, a correction requires owner authorization and a **new release candidate version**, because the existing tag must not be moved. RB-4 needs immediate credential rotation, whatever is decided about publication.

## Git Tag Verification (RELEASE-01)

| Check | Result | Evidence |
|---|---|---|
| Tag exists locally | **PASS** | `git tag -l` lists `v1.0.0-beta`, `v1.0.1-beta`, `v1.0.2-beta` |
| Tag exists on the remote | **PASS** | `git ls-remote origin`: `refs/tags/v1.0.2-beta` = `62043aaf…`, peeled `^{}` = `971b0d50…` |
| Local and remote resolve to the same commit | **PASS** | Both peel to `971b0d500af21b43f61af0599d74a429078dbf96` |
| Tag type | Annotated | Tag object `62043aaf50bcb471146374a84290c76c341dd73a`; tagger Scott Miller; message "resh v1.0.2-beta …" |
| Remote | — | `origin` = `https://github.com/millertechnologygroup/resh.git` (public; GitHub API `visibility: public`) |
| Tag points to the expected tree | **PASS** | HEAD of `help-system-and-fixes` = tag = `origin/help-system-and-fixes`. `git diff v1.0.2-beta HEAD` is empty. |
| Stage 1-4 corrections included | **PASS** | `a54ba13` holds the 85-file release set (73 modified, 12 added), which matches the Stage 4 proposed file set. This was followed by `8f9ed39` (rustfmt), `eabce5d` (sevenz-rust removal), `c647b53` (GitHub Actions) and `971b0d5` (release prep). Spot checks at the tag found `dry_run_refusal` (core/mod.rs), `write_private_file` (mailh.rs), `resize2fs_size_arg` (fsh.rs), `create_new_temp_file` (fileh.rs), the pkg `security_only` refusal, `tests/stage4_regressions.rs` and `tests/doc_examples.rs`. |
| `Cargo.lock` tracked | **PASS** | `git ls-files Cargo.lock`; unchanged by every build, test and audit in this gate (sha256 verified) |
| Intended documentation included | **PASS** | `docs/reviews/` (7 reports), `docs/known_issues.md`, all handle pages, README, CHANGELOG, CONTRIBUTING |
| No secrets or dev-only files | **FAIL** | **RB-4** (credential in `MYSQL_CONNECTION_GUIDE.md`). The other PEM hits are test fixtures or detection strings in `certh.rs` with dummy bodies. Dev-looking files that are tracked: `tmp-sample-plugin/` (scratch sample; the owner's call), `PLUGIN_SYSTEM_RESULTS.md`, and the placeholder checksums in `assets/plugins/catalog.json` (sample catalog). |
| `.claude/` excluded | **PASS** | No tracked file and no history under `.claude/`. It is untracked in the working tree and was left untouched. |
| No relevant uncommitted changes omitted | **PASS** | `git status --short` shows only `?? .claude/` |

## CI Verification (RELEASE-02)

**Platform:** GitHub Actions, workflow `.github/workflows/ci.yml`. No other CI platform exists.

**Run on the tag:** run `39999568581`, event `push`, ref `v1.0.2-beta`, head SHA `971b0d500af21b43f61af0599d74a429078dbf96`. Status **completed**, conclusion **success**.
<https://github.com/millertechnologygroup/resh/actions/runs/39999568581>

| Job | Gate | Result | Window (UTC) |
|---|---|---|---|
| build-msrv (rust:1.88.0-bookworm) | enforced | **success** | 17:59:18 – 18:16:45 |
| test-msrv (1.88.0) | enforced | **success** | 18:08:54 – 18:20:25 |
| test-stable (1.98.1) | enforced | **success** | 17:59:18 – 18:09:56 |
| test-security-regression (1.88.0) | enforced | **success** | 18:02:43 – 18:10:18 |
| fmt (1.98.1) | enforced | **success** | 17:59:18 – 17:59:46 |
| audit (cargo-audit 0.22.2) | enforced | **success** | 17:59:18 – 18:02:40 |
| clippy (1.98.1) | advisory (`continue-on-error: true`) | failure (expected) | 17:59:18 – 18:02:00 |
| test-infrastructure | manual only | skipped (by design: `workflow_dispatch` only) | — |

- Every job ran against `971b0d5`. The workflow header and Stage 4 policy classify Clippy as advisory, so its failure does not fail the run.
- **Clippy new findings:** the job log and the `clippy-report` artifact (131,811 bytes) need an authenticated GitHub session, so they could not be read here.
  - Instead, Clippy 0.1.98 (the CI toolchain version) was run locally on the clean tag checkout.
  - Result: **1,790 distinct sites (5 errors, 1,785 warnings)**, identical to `resh-cli-lint-baseline.md`. No new findings.
- **Annotations on the run:** Node.js 20 action deprecation, and the `ubuntu-latest` → Ubuntu 26 label migration. Both are informational and will need maintenance (see Deferred Maintenance).
- A second run (`39999568492`, push to the branch, same SHA) was still running its build-msrv job at the last check. The GitHub API rate limit was then exhausted, so its final status was not recorded. It tests the same commit and is not needed for this gate.

**Gate status: PASS.** Every required job passed on the tagged commit.

## Security Risk Acceptance Matrix (RELEASE-03)

**Method:**

- Each risk was reassessed from the tagged source by an independent read-only reviewer.
- Each confirmed issue was reproduced with the clean-tag release binary, using a scratch directory, a redirected HOME/XDG and mock system tools. Nothing ran as root, and nothing touched real services.
- RB-1 and RB-2 were then reproduced a second time by the release auditor.
- File and line references are to the tag.

### Summary

| # | Risk | Stage 4 rating | Gate disposition |
|---|---|---|---|
| 1 | Backup argument option injection; user `primary_group` | Medium, non-blocking | **ACCEPT FOR BETA** |
| 2 | Cron newline injection; `unit_name` in paths | Medium, non-blocking | **ACCEPT FOR BETA** |
| 3 | Backup default repositories under `/tmp` | Medium, non-blocking | **BLOCKER (RB-3)** |
| 4 | Certificate private-key creation | Medium, non-blocking | **BLOCKER (RB-1)** |
| 5 | pkg/fs timeout handling | Medium | **ACCEPT FOR BETA** (documentation correction required) |
| 6 | Archive extraction race (TOCTOU) | Medium | **ACCEPT FOR BETA** |
| 7 | Plugin store races, plus two new containment defects | Low | **ACCEPT FOR BETA** (documentation required) |
| 8 | SSH `command_args` quoting | Low/Medium | **ACCEPT FOR BETA** |
| 9 | `backup_suffix` / `backup=` symlink following | Low (deferred) | **BLOCKER (RB-2)** |
| 10 | SMTP password storage | High → partially closed | **ACCEPT FOR BETA** |

### 1. Backup argument option injection; user `primary_group` — ACCEPT FOR BETA

1. **Preconditions:** a value beginning with `-` in backup `src` (tar, restic, borg and rsync create), restic `snapshot_id`, rsync restore `dest`, or borg `repo_url`. These are positionals with no `--`: `backuph.rs:741-787`, `:796`, `:806-807`, `:838`, `:853`, `:876`.
2. **Attacker control:** control over one of those argument values. They come only from the operator's own command line (`main.rs:179-214`); no profile, config or plugin path fills them.
3. **Reachable in supported use:** only when untrusted data is passed. `backup.md:183`, `user.md:174` and `known_issues.md:72-74` warn against that.
4. **Normal privileges:** command execution as the invoking user. Demonstrated with real GNU tar (`--checkpoint-action=exec=`) and real rsync (`--rsh` with a host-style source). Also source deletion (`--remove-files`, `--remove-source-files`) and exfiltration (restic `--repo=` outranks `RESTIC_REPOSITORY`).
5. **Elevated privileges:** the same, as root.
6. **Existing mitigations:** none in code. argv is used with no shell. Values that follow a flag (`--exclude`, `-f`, `-C`, `--target`) are not injectable. `primary_group` reaches `groupadd` as its only positional, so an option-shaped value only causes a usage error, and in `useradd -g` it is consumed as the flag's argument.
7. **Exploitability:** trivial once the attacker controls the value; unreachable otherwise. The operator already chooses which commands run.
8. **Release impact:** a hardening gap, not a privilege boundary that resh claims to enforce.
9. **Disposition: ACCEPT FOR BETA.**
   - Post-beta: insert `--` before positionals, reject leading `-` in `src`, `snapshot_id`, `dest` and `repo_url`, and validate `primary_group` with `validate_group_name`.
   - Doc fix: `backup.md:183` should say "arbitrary command execution", drop `exclude` and add `repo_url`.

### 2. Cron newline injection; `unit_name` in paths — ACCEPT FOR BETA

1. **Preconditions:** CR or LF in any job field (`command`, `description`, `user`, `env`, `service_user`, `service_working_dir`, `accuracy_sec`, `random_delay_sec`), or `/` / `..` in `unit_name` or in `id` (which is used as the unit-name fallback).
2. **Attacker control:** one such field, from the operator's command line.
3. **Reachable in supported use:** only with untrusted input. `cron.md:292`, `:326` and `known_issues.md:73` warn, but the field list in `cron.md` is incomplete.
4. **Normal privileges:**
   - Reproduced: extra entries in the user's crontab, extra directives in user units, and unit files written under `../` paths.
   - Separately, system-scope crontab and unit writes use a predictable `<path>.tmp.<pid>` written with `fs::write`, which follows symlinks (`cronh.rs:2494-2500`, `:2523-2530`).
5. **Elevated privileges:** extra root cron jobs or unit directives, which amounts to root command execution. Unit files written to arbitrary `*.service`/`*.timer` paths.
6. **Existing mitigations:** schedule parsing (`cronh.rs:1738`) and a non-empty command check (`:1757`). There are no control-character checks.
7. **Exploitability:** trivial once a field is controlled.
8. **Release impact:** documented, operator-supplied input. The operator can already add any job directly.
9. **Disposition: ACCEPT FOR BETA.**
   - Post-beta: reject `\n`, `\r` and `\0` in every field; restrict `unit_name`/`id` to `[A-Za-z0-9@_.:-]`; escape `Environment=`; use the `create_new` + `O_NOFOLLOW` temp helper for system crontab and unit writes.
   - Doc fix: complete the field list in `cron.md:292`.

### 3. Backup default repositories under `/tmp` — **BLOCKER (RB-3)**

1. **Preconditions:** `repo_url` is omitted, which is the default.
   - **Leak:** no further precondition.
   - **Tampering:** a local user pre-creates the predictable directory (`backuph.rs:586-587`, `:1430-1432`).
2. **Attacker control:** any local account. No control over resh's arguments is needed.
3. **Reachable in supported use:** **yes, it is the default.**
   - `backup.md:52-61` says "always pass `repo_url`".
   - The binary's own `backup create` help example (`backuph.rs:198-206`) omits it, and its sample output shows the wrong path.
   - No document says the resulting archives are world-readable.
4. **Normal privileges:** another user can read, replace or delete the victim's backups, and can feed the victim a malicious restore.
5. **Elevated privileges:**
   - **No attacker action needed:** `create_dir_all` creates the repository 0755 under root's usual umask, and GNU tar writes the archive 0644. So `backup://x.create src=/etc backend=tar` makes the contents of `/etc` (including `/etc/shadow` and private keys) readable by every local user.
   - **If the directory was pre-created:**
     - the attacker can plant symlinks at the predictable `backup_<timestamp>.tar.gz` names, so root's tar clobbers an arbitrary file;
     - a root `tar` restore of an attacker archive preserves owners and modes;
     - a root `rsync` restore copies attacker content into the destination.

     Both restore paths are privilege escalation.
6. **Existing mitigations:** documentation only. `fs::create_dir_all` (`backuph.rs:1842-1847`) accepts an existing directory owned by anyone, including through a symlink.
7. **Exploitability:** the leak is deterministic; the pre-creation attacks need only predictable names. Borg's repository checks probably block most of the borg variant, but that is NEEDS VERIFICATION.
8. **Release impact:** sensitive-data exposure and privilege escalation reachable from the default configuration, and from the example the binary itself prints.
9. **Disposition: BLOCKER.**
   - **Recommended narrow correction:** remove the `/tmp` defaults and require `repo_url` for tar, rsync and borg. Fail with `INVALID_ARGS` before anything runs. Update the help examples at `backuph.rs:198-206` and `:268`, and `backup.md`.
   - **Alternative:** a per-user 0700 state directory, refusing a repository that is a symlink or not owned by the effective uid.

### 4. Certificate private-key creation — **BLOCKER (RB-1)**

1. **Preconditions:** `cert generate` (any mode), `renew key_strategy=rekey`, or `csr.create key_strategy=generate` writes a key into a directory another local user can search (`x`). The 0755 default is enough; the key path is predictable (`<base>-key.pem`). For the symlink variant, the attacker can write into the key's directory.
2. **Attacker control:** a local unprivileged account that polls the path. No control over resh arguments is needed.
3. **Reachable in supported use:** **yes.** This is the verbs' primary function, under default umask and directory modes.
   - `cert.md:233` calls it "a short window" and advises directories "other users cannot read". That is inaccurate: search permission is what matters, and the window is reliably won.
   - `known_issues.md` does not list it.
4. **Normal privileges:** another user obtains the TLS or CA private key, which allows impersonating the service and, for `is_ca=true`, issuing certificates.
5. **Elevated privileges:**
   - The same theft applies to root-generated keys.
   - Through a planted symlink, root writes the PEM to any path: `overwrite=true` truncates an existing file, and `overwrite=false` creates a new one, because the `Path::exists()` checks treat a dangling symlink as absent (`certh.rs:2326-2359`, `:7952-7962`).
   - Sticky world-writable directories are protected by `fs.protected_symlinks`; group- or service-writable directories are not.
6. **Existing mitigations:** a post-write chmod. Failure is propagated at `certh.rs:2365-2372` and `:3062-3070`, but **ignored** at `:6876-6891`.
   - Separately, `csr.create` never checks `new_key_output_path` against `overwrite`, so it silently replaces an existing key.
   - A correct helper already exists in the tree: `write_private_file`, `mailh.rs:855-875`.
7. **Exploitability — reproduced:**
   - **Permission window:** a poller that opened `srv-key.pem` while `cert://./srv.generate mode=key` ran found the file at mode **0644** in **5 of 5** runs, and after resh's chmod to 0600 it read the complete key (1,704-1,708 bytes, "PRIVATE KEY") through the fd it already had open. The poller ran as the same uid; the 0644 mode at open time and the 0755 directory show that any other uid would have been allowed the same open. The cross-uid case itself was not executed.
   - **Symlink:** with a dangling symlink at `srv-key.pem` and `overwrite=false`, resh returned success and created the key at the symlink's target.
   - The independent reviewer saw the same result in 29 of 30 runs.
8. **Release impact:** confirmed private-key exposure in the primary function under default settings, and arbitrary file write as root.
9. **Disposition: BLOCKER.**
   - **Recommended narrow correction:** route the three key writes (`certh.rs:2361-2375`, `:3060`, `:6872`) through a create-private helper modelled on `mailh.rs:855-875` (`create_new`, `mode(0o600)`, `O_NOFOLLOW`; temp file plus rename for `overwrite=true`). Use `symlink_metadata` in the overwrite checks. Make permission failures fatal and remove partial files. Check `new_key_output_path` against `overwrite`.
   - Add a regression test that asserts the key's mode at creation and refuses a planted symlink.

### 5. pkg/fs timeout handling — ACCEPT FOR BETA (documentation correction required)

1. **Preconditions:** a mutating `pkg` verb (install, remove, update, upgrade, restore, snapshot) or `fs` verb (mount, unmount, snapshot, resize, check) runs longer than `timeout_ms`.
2. **Attacker control:** none needed. A network attacker who can slow mirrors or NFS makes it more likely.
3. **Reachable in supported use:** yes.
4. **Normal privileges:** mostly limited by the lack of privilege.
5. **Elevated privileges:**
   - **Reproduced with mocks:** after `TIMEOUT` (pkg exit 1, fs exit 62), a child that does not write output **keeps running and completes**. A child that writes output after the timeout is **killed by SIGPIPE at an arbitrary point**, because the pipe's read end is dropped.
   - Possible consequences: a package transaction that continues after a reported failure, an interrupted dpkg/rpm transaction, or a `fs resize` that leaves the LV and the filesystem out of step.
6. **Existing mitigations:**
   - Long default timeouts.
   - The docs mention it (`pkg.md:144`, `fs.md:75-77`, `known_issues.md:68-69`), but describe only "continues", not the SIGPIPE termination.
   - The error message does not say the operation may still be running or may have been interrupted.
7. **Exploitability:** not an attacker primitive; low-to-moderate likelihood of leaving undefined system state.
8. **Release impact:** integrity and reliability, not confidentiality or privilege. Documented, but imprecisely.
9. **Disposition: ACCEPT FOR BETA**, provided the release notes and docs state both outcomes and tell users to check package-manager and filesystem state after a timeout.
   - Post-beta: run the child in its own process group, send SIGTERM then SIGKILL to the group, keep draining its output, and reap it. `kill_on_drop` alone would not reach dpkg.

### 6. Archive extraction race (TOCTOU) — ACCEPT FOR BETA

1. **Preconditions:** a concurrent process that can write inside the destination tree during extraction.
2. **Attacker control:** write access to the destination, plus winning a narrow race on a predictable nested path.
3. **Reachable in supported use:** no. `archive.md:200-203` states the limitation and forbids extracting into directories other users can write, especially as root.
4. **Normal privileges:** no boundary is crossed; a same-uid attacker already has the user's rights.
5. **Elevated privileges:** when root extracts into a shared directory, an attacker who wins the race can make root create a root-owned file, or apply a `0o777`-range chmod, at a location of the attacker's choosing.
6. **Existing mitigations:**
   - Path checks: `sanitize_path` (`archiveh.rs:6145`), symlink-refusing parent creation (`:6211`, `:6225`), `clear_existing_target` (`:6253`), lexical and physical symlink checks (`:6277`, `:6300-6346`), hard-link source validation (`:6360`), device refusal (`:5703`).
   - The tar crate's defaults: `preserve_permissions=false` masks off setuid and setgid, `preserve_ownerships=false` means no chown, and file data is written with `create_new`.
   - Plugin artifacts use separate, stricter code (no links at all, `O_NOFOLLOW`, a fresh UUID staging directory).
7. **Exploitability:** low-to-moderate, and only in a configuration the docs prohibit.
8. **Release impact:** none for supported use.
9. **Disposition: ACCEPT FOR BETA.** The documentation guidance is accurate and sufficient.
   - Post-beta: `openat`/`O_NOFOLLOW` directory-relative extraction, or refuse root extraction into group- or other-writable destinations.

### 7. Plugin store races — ACCEPT FOR BETA (new findings recorded)

**New findings.** These are not in Stage 4; both were confirmed in code by the auditor and reproduced by the reviewer.

- **P-A:** `remove_binary` deletes the `bin_path` read from `<store>/<id>/versions/<ver>/metadata.json` with no containment check (`engine.rs:1382-1385`). Reproduced: an edited `bin_path` made `plugin remove` delete a file outside the store.
- **P-B:** `purge_plugin_data` lstat-checks only the final component of `$XDG_{STATE,CACHE,CONFIG}_HOME/resh/plugins/<id>` before `remove_dir_all` (`store.rs:544-556`). Reproduced: a symlinked parent made `purge` delete an external directory tree.

**Nine items:**

1. **Preconditions:** the attacker can write the store or the XDG directories of the identity that runs resh.
2. **Attacker control:** write access to the victim's `$XDG_DATA_HOME`, or to its state, cache or config directories.
3. **Reachable in supported use:** for the documented single-user model, these directories are the user's own, so no boundary is crossed (`plugin.md:19-27`).
4. **Normal privileges:** self-inflicted only.
5. **Elevated privileges:** if root runs plugin operations with a preserved HOME or XDG environment (for example `sudo -E`, or `env_keep` HOME), the store resolves into an unprivileged user's tree. That user can then make root delete an arbitrary file (P-A) or directory tree (P-B).
   - In that same configuration, the user already controls which plugin binaries root will later run. The configuration is unsafe by construction, whatever P-A and P-B do.
6. **Existing mitigations:**
   - Store-internal operations are symlink-safe: `ensure_inside_store` (`store.rs:197`), `remove_tree` (`:230`), and the no-follow create helpers (`:72`, `:98`).
   - The store directory is created with the umask (0755), not 0700.
   - There is no euid or ownership guard.
7. **Exploitability:** low in supported use. Under the elevated configuration it is a deletion primitive only: no code execution and no write-through.
8. **Release impact:** none for documented use. The elevated-use hazard is undocumented.
9. **Disposition: ACCEPT FOR BETA.** Considered as a blocker and rejected, because the privilege crossing needs an unsupported, non-default way of running resh that is already unsafe through the plugins themselves.
   - **Condition:** release notes and `plugin.md` must say that plugin operations must not run as root against another user's HOME/XDG.
   - Post-beta: contain `bin_path` with `ensure_inside_store`, walk the purge parents with the no-follow helper, create the store 0700, and refuse a store not owned by the effective uid.

### 8. SSH `command_args` quoting — ACCEPT FOR BETA

1. **Preconditions:** a caller with a fixed `command` builds `command_args` from data it does not fully control.
2. **Attacker control:** one `command_args` element. Space-free metacharacters are enough (`;`, `$()`, backticks, `|`, `${IFS}`).
3. **Reachable in supported use:**
   - `shell_mode=none` (the default) joins arguments with no quoting (`sshh.rs:5265-5274`).
   - `sh`/`bash` quote an argument only when it contains a space or a quote (`:5285-5293`).
   - `cmd`/`powershell` do no quoting, including `cwd` (`:5303-5330`).
   - All of this is **documented accurately** in `ssh.md:108-125` and `:318-319` ("never build `command` or `command_args` from untrusted input").
4. **Normal privileges:** command execution on the remote host as the ssh user. Confirmed in dry-run output (`command.raw`).
5. **Elevated privileges:** remote root if the remote account is root or has passwordless sudo. The local side is unaffected (argv, no local shell).
6. **Existing mitigations:** documentation; `dry_run` shows the raw command; `cwd` (none/sh/bash) and transfer paths are quoted (`:5296`, `:2913-2917`); the password goes through `SSHPASS`, not argv.
7. **Exploitability:** trivial if untrusted data reaches `command_args`, which the docs forbid. The operator already has full remote execution through `command`.
8. **Release impact:** a documented design limitation.
9. **Disposition: ACCEPT FOR BETA.**
   - Post-beta: `shell_escape` every argument in POSIX modes; reject or escape in `cmd`/`powershell`; add a `known_issues.md` entry.

### 9. `backup_suffix` / `backup=` symlink following — **BLOCKER (RB-2)**

1. **Preconditions:** `file replace … backup=<suffix>` (`fileh.rs:1680`, `:1780-1786`) or `archive add … backup_suffix=` (`archiveh.rs:5173-5183`, `:5450-5460`) runs on a file in a directory that another account can write and that is not sticky and world-writable. Examples: a service account's or user's directory, or a group-writable deploy directory.
2. **Attacker control:** write access to that directory, to plant a symlink at the predictable backup name.
   - For `file replace`, if the attacker also owns the file being edited, they choose both the bytes written and the resulting mode.
3. **Reachable in supported use:** **yes.**
   - The docs recommend `backup=` before editing configuration (`file.md:234`) and `backup_suffix` for `add`/`remove` (`archive.md:249`, `:360`).
   - No user document warns about this; it appears only in the Stage 4 review.
4. **Normal privileges:** overwrite or chmod any file the victim can write, for example `~/.bashrc` or `~/.ssh/authorized_keys`.
5. **Elevated privileges:** create or overwrite any file as root, with attacker-chosen content and mode in the `file replace` case (for example under `/etc/sudoers.d/` or `/etc/cron.d/`), which is local root privilege escalation. At minimum, a denial of service by clobbering a system file.
6. **Existing mitigations:** none at these sites.
   - `fs::copy` opens the destination with `O_CREAT|O_TRUNC`, follows symlinks (dangling ones included) and copies the source's mode.
   - The neighbouring temp files were hardened in Stage 4; these backup copies were not.
7. **Exploitability:** deterministic, with no race. **Reproduced by the auditor:**
   - Setup: a 0600 file `victim` behind a planted `shared/app.conf.bak` symlink.
   - `file://…/shared/app.conf.replace pattern=ORIGINAL replacement=NEW backup=.bak` returned exit 0.
   - `victim` then contained `ORIGINAL CONTENT` and its mode had changed to **644**.
   - The reviewer also reproduced dangling-symlink creation and the `archive add` variant.
8. **Release impact:** confirmed arbitrary file modification, undocumented for users.
9. **Disposition: BLOCKER.**
   - **Recommended narrow correction:** refuse a backup path that exists as a symlink. Write the backup to a random `create_new` + `O_NOFOLLOW` temp file in the same directory, set the mode on that file descriptor, then `rename` it to the backup name. Apply this at the four call sites.
   - Add a planted-symlink regression test.

### 10. SMTP password storage — ACCEPT FOR BETA

1. **Preconditions:** a profile was saved with `smtp_password=`.
2. **Attacker control:** read access to the profile file, or the ability to see the `config set` process's argv.
3. **Reachable in supported use:** yes.
   - Storage: `smtp_password_encrypted` is plain **base64** (`mailh.rs:362`, `:401-416`) in `$XDG_CONFIG_HOME/resh/mail/smtp_profiles.json` (`:776-790`).
   - **Nothing reads it:** `decrypt_password` has no callers; send and test take `password=` or `MAIL_SMTP_PASSWORD`.
4. **Normal privileges:**
   - New files are written 0600 through `write_private_file`, then atomically renamed (`:820-875`).
   - **Files from older versions keep their old mode** (reproduced: a 0644 file stayed 0644 after `list`) until the next save.
   - `config set` accepts the password only on the command line, so it is visible in `/proc/<pid>/cmdline` and in shell history.
5. **Elevated privileges:** root, backups and support bundles can decode the file trivially, as for any plaintext-equivalent store.
6. **Existing mitigations:** 0600 with `create_new` and `O_NOFOLLOW`; output shows only `has_password`; `MAIL_SMTP_PASSWORD` for send and test; documentation (`mail.md:94-95`, `:265-282`; `known_issues.md:64-65`).
7. **Exploitability:** low for files created by this version; moderate for legacy files and the argv window.
8. **Release impact:** limited. The actual confidentiality guarantee is **"an owner-only file holding a plaintext-equivalent value"**, and the docs state that honestly.
9. **Disposition: ACCEPT FOR BETA.**
   - Post-beta: tighten or warn on a group- or other-readable file at load time, accept the password from a file or environment variable, create the directory 0700, or stop storing an unused password.

## Dependency Advisory Review (RELEASE-04)

**Audit run:**

- Tool: cargo-audit **0.22.2**, the version CI pins, built `--locked` into the scratch directory.
- Advisory database: a fresh clone of `rustsec/advisory-db` @ `84d943a6` (2026-10-23 16:42 +0200), 1,351 advisories.
- Input: the tag's `Cargo.lock`, 618 crates. The lockfile's sha256 was unchanged afterwards.

| Run | Result |
|---|---|
| With `.cargo/audit.toml` | exit **0**; 18 allowed informational warnings |
| Without the ignore list (`--file`, from outside the repository) | **18 vulnerabilities**: exactly the 18 IDs in `audit.toml`. No stale exception and no unlisted vulnerability. |

An exit code of 0 here means "every remaining advisory is one we chose to accept". It does not mean the dependency graph is free of vulnerabilities.

| Advisory | Crate @ locked | In release binary? | Vulnerable code invoked? | Basis | Verdict |
|---|---|---|---|---|---|
| RUSTSEC-2026-0204 | crossbeam-epoch 0.9.18 | Yes (rayon, ignore) | No `fmt::Pointer` use in dependents or src | Code-level | Justified; fixed in 0.9.20 (semver-compatible) |
| RUSTSEC-2026-0258 | h2 0.3.27 | **No**: dev-only, via hyper 0.14 ← httpmock, httptest | — | Code-level (graph) | Justified. The comment wrongly names mockito. |
| RUSTSEC-2024-0421 | idna 0.4.0 | Yes (trust-dns-proto 0.23) | Name parsing of operator input; no trust decision on IDN equivalence (`dnsh.rs:2879` compares names within one response) | Code-level plus an **operator-input assumption** | Justified with caveat; real fix is hickory-dns |
| RUSTSEC-2026-0141 | lettre 0.11.19 | Yes | Features `builder,default,hostname,native-tls,pool,smtp-transport`; no boring-tls | Code-level (features) | Justified; fixed in 0.11.22 (semver-compatible) |
| RUSTSEC-2026-0194, -0195 | quick-xml 0.18.1 | No | email-address-parser 2.0.0 publishes **no** `build.rs`, so quick-xml is never compiled | Code-level | Justified, more strongly than the comment says (the comment says it runs at build time) |
| RUSTSEC-2026-0037, -0185, -0338, -0339, -0340, -0342 | quinn-proto 0.11.13 | **No**: lockfile only; `cargo tree -e all --target all` is empty; http3 is off | — | Code-level | Justified |
| RUSTSEC-2025-0009 | ring 0.16.20 | Yes (x509-parser 0.15 ← rcgen 0.12) | Only `ring::signature` is used (CSR verification); no AES/QUIC | Code-level. The comment's "overflow checks off" clause is a **build-configuration assumption** and is unnecessary: debug builds and `-C overflow-checks` turn checks on. | Justified |
| RUSTSEC-2023-0071 | rsa 0.9.9 | Yes (direct; sqlx-mysql) | No RSA decryption; sqlx-mysql only uses OAEP *encrypt*; resh signs locally (PSS, blinded) | Code-level | Justified with caveat (no fixed release exists) |
| RUSTSEC-2026-0009 | time 0.3.44 | Yes (parsing feature compiled) | No RFC 2822 parse call in src or dependents; only `format` (x509-parser `time.rs:66`) | Code-level | Justified; fixed in 0.3.47 (semver-compatible) |
| RUSTSEC-2026-0367, -0368, -0369 | zip 0.6.6 | Yes (direct) | No `extract`/`ZipStreamReader` call; resh's extractor (`archiveh.rs:5838-5940`) uses `create_new` and never `set_permissions` | Code-level | Justified; the fix is zip ≥ 9 (major) |

**Informational (not gated):**

- unmaintained: async-std, derivative, instant, ring 0.16, trust-dns-proto, unsafe-libyaml, zbus_names, zvariant, zvariant_derive;
- unsound: anyhow, event-listener, git2 (3), rand 0.8/0.9, and **tokio 1.48.0 RUSTSEC-2026-0386** (`AsyncFd::new` I/O safety, new since Stage 4);
- yanked: spin 0.9.8.

**OpenSSL:**

- **Linkage:**
  - openssl-sys is **not vendored**: features `[]`, and the build script emits `rustc-link-lib=ssl`/`crypto` dynamically.
  - The release binary links `libssl.so.3` and `libcrypto.so.3` (`OPENSSL_3.0.0` symbol version).
  - It is used by native-tls (reqwest's `http`/`https` handle and the plugin registry, lettre SMTP), memcache, git2 and libssh2.
- **reqwest backend:** reqwest 0.12.26 defaults to native-tls when `default-tls` is enabled (`tls.rs:589-603`), and resh never selects rustls.
- **Conclusion:** OpenSSL security maintenance is correctly described as an **operating-system responsibility**.
- **Correction needed in the release notes:** **libssh2 (bundled "1.11.1_DEV" via libssh2-sys 0.3.1) and libgit2 1.7.2 (libgit2-sys 0.16.2) are compiled from bundled C sources and linked statically.** Their security fixes arrive through resh crate updates, not from the OS.
- rustls 0.23.46 (sqlx database TLS only) is maintained through `Cargo.lock`.

**Gate status: PASS.** All exceptions are justified, none blocks the release, and the comment inaccuracies are documentation-only.

## Release Artifact Manifest (RELEASE-05)

**Build environment:** a fresh `git clone --no-local` of the repository, checked out at `v1.0.2-beta`, with no working-tree changes before or after. Separate target directories. The shared host Cargo registry cache was used, with all crates checksum-verified against `Cargo.lock` by Cargo.

| Build | Toolchain | Command | Result |
|---|---|---|---|
| Candidate | rustc/cargo **1.98.1** (Gentoo system) | `cargo build --release --locked` | success |
| Tests | 1.98.1 | `cargo test --workspace --locked --no-fail-fast` | lib **1181**/0/11 ignored; bin **1185**/0/11; doc_examples 2; help_cli 16; help_coverage 2; stage4_regressions 11. **0 failures.** |
| MSRV | rustc **1.88.0**: official standalone tarball, sha256 verified against static.rust-lang.org, installed in the scratch directory | `cargo build --release --locked`; `cargo test --workspace --locked --no-fail-fast` | success; identical test counts, 0 failures |
| CI (independent) | rust:1.88.0-bookworm / 1.98.1-bookworm | as in `ci.yml` | success (see CI Verification) |

The test environment was not scrubbed of the `TEST_*` and `MAIL_*` variables. None was set, so the 11 infrastructure tests stayed ignored.

**Proposed artifact.** Not for publication while the blockers stand.

| Field | Value |
|---|---|
| Filename | `resh-1.0.2-beta-x86_64-unknown-linux-gnu` |
| OS / architecture | Linux / x86_64 (ELF 64-bit LSB PIE, `for GNU/Linux 3.2.0`) |
| Binary version | `resh 1.0.2-beta` |
| Source commit | `971b0d500af21b43f61af0599d74a429078dbf96` (tag `v1.0.2-beta`) |
| Rust version | rustc 1.98.1 (48a229cea 2026-09-01) |
| Build command | `cargo build --release --locked` (default release profile; not stripped; no LTO) |
| Build host | Gentoo Linux, glibc 2.43, OpenSSL 3.5.8, kernel 6.18.35 |
| **SHA-256** | `6d6a084fe8f6fa14e1b80785df50c718dba6f55cabaa4e14de13cbb8841e0adb` (verified with `sha256sum -c` against the staged copy) |
| Size | 51,132,904 bytes |
| GNU build ID | `bcfdae800113beaa6e298e7325a5a878279c0861` |
| Runtime libraries | `libc.so.6`, `libm.so.6`, `libgcc_s.so.1`, `libz.so.1`, `liblzma.so.5`, `libssl.so.3`, `libcrypto.so.3`, `ld-linux-x86-64.so.2` |
| ABI floor | **glibc ≥ 2.39** (`GLIBC_2.39` version need is non-weak; `__isoc23_strtol@GLIBC_2.38` is a strong reference from bundled C code); **OpenSSL ≥ 3.0** (`OPENSSL_3.0.0`) |
| External tools | Not bundled. Handles call systemctl/rc-service, package managers, iptables/nft, tar/restic/borg/rsync, ssh, journalctl, resize2fs, and others. |

The MSRV build (1.88.0, same host) is 49,676,640 bytes with sha256 `8b763acd9576e14c8dddd7119d17f8f6718e5944e400103fc27392f72cac550c`, and the same glibc 2.39 floor. It is not the proposed artifact.

**Reproducibility:** **not tested.** No claim of byte-for-byte reproducible builds is made. Different toolchains and hosts produce different bytes.

**Binary validation** (scratch directory, redirected HOME/XDG, no host mutation):

| Check | Result |
|---|---|
| Starts; `--version` | `resh 1.0.2-beta`, exit 0 |
| Top-level `--help` | renders |
| No stage | `Error: no stage provided …`, exit 2 |
| `--list-schemas` | 29 schemes (28 handles plus the `https` alias of `http`) |
| Handle help | **29/29** render with `Handle:` and `Available Verbs:` |
| Verb help | **239/239** entries (229 for the 28 handles plus 10 for `https`), each with `Handle:`, `Verb:`, `Definition:`, `Usage:`, `Example:` |
| Invalid input | unknown scheme exits 1; unknown verb exits 1 with the available verbs listed; missing file exits 1 with the OS error |
| JSON validity | Valid JSON from `file stat`, `file sha256 --json-pretty`, `file find`, `system info/memory/uptime`, `fs list-mounts`, `net if.list`, `net route.list`, `proc self.nice.get`, `user root.exists`, `cron list`, `snapshot ls`, `secret local ls`, `config ls`, `event list-topics`, `svc status` (missing unit, exit 1), `db sqlite ping` (exit 1, structured) |
| Dry-run safety | Each of the following exits **2**, says "nothing was done", and leaves the target file unchanged: `file delete dry_run=true`, `dry-run`, `DRY_RUN=true`, `dry_run=maybe`, `dry_run=true help=1`, `svc restart dry_run=true`, `mail send dry_run=true`, `backup restore dry_run=true`, and a top-level `dry_run` next to pkg `input=`. |
| Unsupported features | ZIP `password=` is refused (`archive.create_password_not_supported`) and no archive is written |
| Read-only commands | `file read`, `archive create` (tar.gz into scratch) and the commands above behave as documented |

**Gate status:** build, test and binary validation **PASS**. The artifact must not be published (see the blockers).

## Compatibility Matrix (RELEASE-06)

**Requirements, distinguished:**

| Requirement | Value | How established |
|---|---|---|
| Minimum Rust to **compile from source** | **1.88** (`rust-version = "1.88"`; edition 2024) | Clean locked build and full test suite on 1.88.0, locally and in CI |
| Minimum glibc to **run the proposed binary** | **2.39** | ELF version requirements (`GLIBC_2.39` non-weak version need; `GLIBC_2.38` strong symbol). **Inferred from the ELF; not executed on an older glibc** (Docker on this host cannot start containers). |
| OpenSSL runtime | **OpenSSL 3.x** shared libraries (`libssl.so.3`, `libcrypto.so.3`), maintained by the OS | `ldd`, symbol versions, openssl-sys build output |
| Other runtime libraries | zlib, liblzma, libgcc_s | `ldd` |
| Statically bundled C | libssh2 1.11.1_DEV, libgit2 1.7.2 (updated only through resh releases) | crate build configuration |

**Likely behaviour on common distributions.** This is inferred from the glibc and OpenSSL floors only; none of these was executed.

| Distribution | glibc / OpenSSL | Proposed binary |
|---|---|---|
| RHEL/Alma/Rocky 8 | 2.28 / 1.1.1 | will not run (glibc and OpenSSL) |
| RHEL/Alma/Rocky 9 | 2.34 / 3.0 | will not run (glibc) |
| Debian 12 | 2.36 / 3.0 | will not run (glibc) |
| Ubuntu 22.04 | 2.35 / 3.0 | will not run (glibc) |
| Ubuntu 24.04 | 2.39 / 3.0 | expected to load (NOT TESTED) |
| Debian 13, Fedora ≥ 40, current Arch/Gentoo | ≥ 2.39 / 3.x | expected to load (NOT TESTED, except Gentoo) |

Most enterprise LTS distributions therefore need a source build, or a future binary built on an older base. The CI `rust:*-bookworm` images (glibc 2.36) would give a lower floor, but RHEL 9 would still need ≤ 2.34. The distribution strategy was not changed (see Deferred Maintenance).

| Platform / integration | Status | Evidence |
|---|---|---|
| Linux x86_64, glibc 2.43, Gentoo/OpenRC (build host) | **VERIFIED** | Builds (1.88.0, 1.98.1), full suite, binary smoke (this gate) |
| Debian bookworm container (CI) | **VERIFIED** for build and test | CI run 39999568581 (as root in the container) |
| OpenRC service management | **PARTIALLY VERIFIED** | Stage 3/4: read-only status on the host; enable/disable in an Alpine sandbox |
| systemd service and timer management | **NOT TESTED** live | Unit and parser tests only. No systemd host was used. |
| apt / dnf / yum / pacman / apk | **PARTIALLY VERIFIED** | Stage 3 sandboxes (58/60 scenarios); not re-run in this gate |
| Homebrew | **NOT TESTED** | argv unit tests only |
| PostgreSQL 16 / MariaDB 11.4 | **PARTIALLY VERIFIED** | Stage 3/4 disposable instances; not re-run in this gate; CI infrastructure job is manual and was not run |
| Oracle MySQL, Redis, memcached servers | **NOT TESTED** | — |
| git: `file://` remotes / HTTPS and SSH remotes | **PARTIALLY VERIFIED** / **NOT TESTED** | Stage 4 |
| SMTP, SSH, DNS servers | **NOT TESTED** live | — |
| Firewall (iptables/nftables) | **PARTIALLY VERIFIED** | Mocks in a user namespace (Stage 4); no real kernel rules. ufw and firewalld not tested. |
| Running as real root on a host | **NOT TESTED** | Only namespace root and container root |
| Older-glibc distributions (RHEL 8/9, Debian 12, Ubuntu 22.04) | **UNSUPPORTED** for the proposed binary | glibc floor 2.39 |
| Linux non-x86_64 (aarch64 and others) | **NOT TESTED** | — |
| macOS | **UNSUPPORTED** | Not built; Unix-only code paths; XDG assumptions |
| Windows | **UNSUPPORTED** | Not built |

## Release Notes Review (RELEASE-07)

Inputs reviewed: `README.md`, `CHANGELOG.md` `[1.0.2-beta]`, `docs/known_issues.md` and the handle pages cited above.

**Accurate and adequate:**

- The CHANGELOG lists the Stage 1-4 security corrections.
- It lists the behaviour changes required for this release:
  - dry-run refusal on verbs without a dry-run mode;
  - malformed `dry_run` rejected;
  - git sync fast-forward only;
  - ZIP password refused;
  - HTTPS-only plugin registries;
  - plugin checksum and link rules, and `source=url` requiring `verify=none`;
  - git `timeout_ms` refused;
  - `pkg security_only` refused where it cannot be honoured;
  - backup restore and mail send dry runs refused;
  - no-stage exit 2;
  - ext resize size corrected.
- The README states Linux x86_64 only and Rust 1.88, and that macOS and Windows are unsupported.

**Corrections needed** (to apply in the next release candidate, or in the GitHub release text; the tagged files cannot be changed):

1. **Platform and runtime requirements are missing from the CHANGELOG:** glibc ≥ 2.39 for the distributed binary, OpenSSL 3 from the OS, bundled libssh2/libgit2, and Rust 1.88 for source builds.
2. **README "Binary Releases"** says no binaries are published until v1.0 stable. Publishing a binary for this beta contradicts that line.
3. **README** marks `svc://` "systemd and OpenRC" and `pkg://` "brew" with ✅. Neither systemd nor brew has been verified live. The release notes must say so.
4. **Undisclosed risks:**
   - `known_issues.md` does not list RB-1 to RB-3, the plugin root/HOME hazard (P-A/P-B), or the ssh quoting rule.
   - `cert.md:233` understates RB-1.
   - Nothing documents that default backup archives are world-readable (RB-3).
   - No user document warns about the backup-copy symlink issue (RB-2).
5. **Timeout disclosure:** `pkg.md:144`, `fs.md:75-77` and `known_issues.md:68-69` should say that a timed-out child either keeps running or is killed by SIGPIPE mid-operation, and that system state must be checked afterwards.
6. **Smaller inaccuracies:**
   - `backup.md:183`: the risk is command execution; `exclude` is not affected; `repo_url` is.
   - `cron.md:292`: the list of injectable fields is incomplete.
   - The `backup create` help example and its sample output path (`backuph.rs:198-206`).
   - `.cargo/audit.toml` comments (h2/mockito, quick-xml build script, ring overflow checks).
7. **CHANGELOG** has no `[1.0.1-beta]` entry, although the tag exists. This is cosmetic.
8. **`MYSQL_CONNECTION_GUIDE.md`:** remove or redact it (RB-4). It also documents a private host, so it is not useful to users.

A draft GitHub release text, to be used **only after** the blockers are resolved, is in the [Appendix](#appendix-draft-release-notes).

## Release Checklist (RELEASE-08)

| # | Gate | Status | Evidence |
|---|---|---|---|
| 1 | Correct Git tag | **PASS** | Annotated tag `62043aaf…`, identical locally and remotely |
| 2 | Correct source commit | **PASS** | `971b0d50…`; release set `a54ba13` plus 4 follow-ups; HEAD = tag; clean tree |
| 3 | No secrets or dev-only files in the release | **FAIL** | RB-4: `MYSQL_CONNECTION_GUIDE.md` |
| 4 | Clean tagged build | **PASS** | Clean clone at tag; `--locked` release builds on 1.88.0 and 1.98.1 |
| 5 | Passing default tests | **PASS** | 1181/1185/2/16/2/11, 0 failures, on both toolchains |
| 6 | Passing security regression tests | **PASS** | CI `test-security-regression` success; included in the local full suite |
| 7 | Completed remote CI | **PASS** | Run 39999568581 on the tag: all 6 gating jobs succeeded; Clippy advisory |
| 8 | Dependency advisory review | **PASS** | 18 found = 18 excepted; all justified (comment fixes deferred) |
| 9 | Security risk acceptance | **FAIL** | RB-1, RB-2, RB-3 confirmed and reproduced; 7 other risks ACCEPT FOR BETA |
| 10 | Documentation accuracy | **FAIL** | Release Notes Review items 1-6 (undisclosed RB-1 to RB-3, understated cert risk, README binary and systemd/brew claims) |
| 11 | Release binary verification | **PASS** | Smoke matrix above: 29/29 handle help, 239/239 verb help, errors, JSON, dry-run |
| 12 | SHA-256 checksum | **PASS** (recorded) | `6d6a084f…0adb`, verified with `sha256sum -c`. The artifact is not to be published from this tag. |
| 13 | Platform compatibility disclosure | **PENDING** | Matrix prepared here; not yet in the release notes or CHANGELOG |
| 14 | Known-issues disclosure | **FAIL** | `known_issues.md` omits RB-1 to RB-3, P-A/P-B and ssh quoting |
| 15 | Release notes | **PENDING** | Draft in the Appendix, conditional on the blockers |
| 16 | Owner approval | **PENDING** | Awaiting the project owner |

## Outstanding Blockers

| ID | What | Affected files and operations | Recommended narrow correction | Needs |
|---|---|---|---|---|
| **RB-1** | cert private key written with umask mode, then chmod; follows symlinks; `overwrite=false` bypass via a dangling symlink; `csr.create` replaces an existing key | `src/handles/security/certh.rs:2361-2375` (generate), `:3058-3070` (renew rekey), `:6868-6891` (csr.create), `:2326-2359` and `:7952-7962` (existence checks); `docs/Security_Secrets/cert.md:233` | A shared create-private helper (`create_new`, mode 0600, `O_NOFOLLOW`, temp file plus rename for overwrite), modelled on `mailh.rs:855-875`; `symlink_metadata` in the existence checks; fatal permission errors; check `new_key_output_path` against `overwrite`; regression test | Owner authorization to change source; new RC version |
| **RB-2** | Backup copies follow a planted symlink and overwrite the target's content and mode | `src/handles/filesystem/fileh.rs:1680`, `:1780-1786` (`file replace backup=`); `src/handles/filesystem/archiveh.rs:5173-5183`, `:5450-5460` (`archive add backup_suffix=`) | Refuse an existing symlink; copy to a random `create_new` + `O_NOFOLLOW` temp file, set the mode on its fd, then `rename`; regression test | Same |
| **RB-3** | Default backup repositories in `/tmp`: world-readable archives; pre-created directories accepted (tampering, malicious restore as root) | `src/handles/automation/backuph.rs:586-587`, `:683-695`, `:1430-1432`, `:1842-1847`; help example `:198-206`, `:268`; `docs/Automation_Utilities/backup.md:52-61` | Require `repo_url` for tar, rsync and borg (fail before running); fix the help examples and docs. Alternatively, a per-user 0700 state directory with owner and symlink checks. | Same |
| **RB-4** | Real-looking MySQL credential in a public, tracked file (present since `v1.0.0-beta`) | `MYSQL_CONNECTION_GUIDE.md` (lines 23, 40, 45, 70, 75) | **Rotate the password now** and check the database host for unauthorized access. Remove or redact the file in the next RC. Rewriting history is optional: rotation is the real remedy, because the value is already public in three tags. | Owner action (rotation); owner decision (history) |

**Process after correction:** fix the blockers on a branch with owner approval. **Owner decision (2026-10-23): the corrections ship as `v1.0.3-beta`.** Do not move or reuse `v1.0.2-beta`. Re-run this gate: CI, clean build, suite, the new regression tests, a re-test of RB-1 to RB-3, and a new artifact checksum.

## Deferred Maintenance

Non-blocking; appropriate after the beta.

- **Security hardening:**
  - `--` separators and leading-dash rejection in backup argv; `primary_group` validation;
  - cron control-character and `unit_name` validation; no-follow temp files for system crontab and unit writes;
  - killing the process group on pkg/fs timeouts while still draining output;
  - `openat`-based archive extraction;
  - plugin `bin_path` containment, no-follow purge, store directory 0700, and an euid/ownership guard;
  - ssh `shell_escape` for every argument;
  - SMTP: tighten legacy file modes, a non-argv password input, directory 0700;
  - the remaining Stage 4 items (rules.reload restore deadline, ZIP symlink entries on rewrite, unknown bare words in `(...)`, `--` for the LVM tools, `net ping` and `http` exit codes).
- **Dependencies:**
  - semver-compatible bumps that retire exceptions: lettre 0.11.22, time 0.3.47, crossbeam-epoch 0.9.20, quinn-proto 0.11.18 (lockfile only);
  - trust-dns → hickory-dns; zip ≥ 9;
  - redis 0.25.4 future-incompatibility warning;
  - track tokio RUSTSEC-2026-0386 (informational).
- **CI:**
  - Node.js 20 action deprecation (move to the next major versions of `actions/checkout`, `actions/cache` and `actions/upload-artifact`);
  - `ubuntu-latest` → Ubuntu 26 migration;
  - Clippy debt: 1,790 sites, 5 deny-level.
- **Distribution:** build release binaries on an older glibc base (bookworm at 2.36, or an EL9-compatible base at 2.34), or consider a static or musl build. Strip the binary. Add an aarch64 build, and publish checksums (and optionally signatures) with every artifact.
- **Repository hygiene:** decide on `tmp-sample-plugin/` and `PLUGIN_SYSTEM_RESULTS.md`; add `.claude/` to `.gitignore`; add the CHANGELOG `[1.0.1-beta]` entry.

## Final Recommendation

**DO NOT PUBLISH**

The release engineering of `v1.0.2-beta` is sound:

- the tag is correct and complete;
- remote CI passed on the tagged commit;
- clean locked builds and the full suite pass on the MSRV and on current stable;
- the binary behaves as documented;
- every dependency advisory exception is justified.

The candidate nevertheless fails the security gate. Three Medium risks that Stage 4 had accepted turned out, on independent re-assessment and reproduction, to be confirmed vulnerabilities in supported, default or documented-as-recommended use:

- **RB-1:** private-key exposure in `cert generate`, plus arbitrary file write through symlinks;
- **RB-2:** arbitrary file modification, and so root privilege escalation, through `backup=` / `backup_suffix=`;
- **RB-3:** world-readable backups and root-restore tampering through the default `/tmp` repositories, which the binary's own help example uses.

These fall squarely within the categories this gate must treat as blockers: sensitive-data exposure, arbitrary file modification, and unintended privileged effects. Separately, **RB-4** (a committed credential) fails the release-content check, and the credential must be rotated whatever is decided about the release.

Each blocker has a narrow, local correction. None needs a redesign or a new feature. Fixing them changes the tagged source, so the result must be a **new release candidate version** that goes through this gate again. `v1.0.2-beta` must not be moved or republished with different content.

Nothing was committed, pushed, tagged or published. **Awaiting project-owner direction.**

## Appendix: Draft Release Notes

*For use only after RB-1 to RB-4 are resolved. Update the version, commit and checksum to the new candidate.*

> **resh vX.Y.Z-beta: controlled public beta**
>
> **Supported platform.** Linux x86_64 only.
> - The prebuilt binary needs **glibc 2.39 or later** (for example Ubuntu 24.04, Debian 13, Fedora 40+). RHEL/Rocky/Alma 8 and 9, Debian 12 and Ubuntu 22.04 must build from source.
> - It needs **OpenSSL 3** shared libraries from the OS. Keep OpenSSL updated through your distribution: resh does not bundle it. libssh2 and libgit2 *are* bundled and are updated through resh releases.
> - Building from source needs **Rust 1.88 or later**: `cargo build --release --locked`.
> - macOS and Windows are not supported.
>
> **Security fixes since 1.0.1-beta:**
> - Archive extraction can no longer write outside the destination.
> - Plugin ids and versions are path-safe; HTTPS registries are required; artifacts must match a SHA-256 checksum; links are refused in artifacts.
> - PID wrap-around (`kill(-1)`) is fixed.
> - Package managers run without a shell.
> - Firewall changes take a real backup first.
> - Temporary files are unpredictable and do not follow symlinks.
> - SMTP profiles are written 0600.
> - TLS dependencies are patched.
> - *(Add the RB-1 to RB-3 fixes.)*
>
> **Behaviour changes you may notice:**
> - `dry_run=true` on a verb with no dry-run mode is refused (exit 2) instead of running.
> - Malformed `dry_run` values and misspellings (`dry-run`, `DRY_RUN`) are errors.
> - `git sync` is fast-forward only.
> - Creating password-protected ZIPs is unsupported.
> - Plugin registries must be HTTPS.
> - `source=url` installs need `verify=none`.
> - Plugin artifacts with links are refused.
> - git `timeout_ms` is refused.
> - `pkg security_only` is refused except on dnf/yum.
> - `backup restore` and `mail send` refuse `dry_run=true`.
> - `resh` with no command exits 2.
> - ext3/ext4 resize uses the requested size.
> - *(If RB-3 is fixed by requiring it: backups require `repo_url`.)*
>
> **Known limitations:**
> - systemd service and timer management, Homebrew, real-root operation on a host, Oracle MySQL, Redis/memcached servers, HTTPS/SSH git remotes, SMTP/SSH/DNS servers, real kernel firewall rules and aarch64 have **not** been verified live.
> - Stub or unsupported features: secret encryption and rotate, ssh tunnel and keys, backup schedule installation, pkg rollback, dns zone.update and TSIG, cert CMS, proc limits.set.
> - Accepted beta risks (documented on the handle pages):
>   - backup argv option injection;
>   - cron fields are not checked for newlines;
>   - ssh `command_args` are not fully quoted;
>   - the archive extraction race in shared directories;
>   - pkg/fs timeouts do not reliably stop the child: it may keep running or be killed mid-operation, so check system state;
>   - SMTP passwords are stored base64-encoded (owner-only file);
>   - do not run plugin operations as root with another user's HOME.
> - Never pass untrusted input to backup, cron, ssh or user arguments.
> - 1,790 pre-existing Clippy findings remain (none is security-relevant).
>
> **Artifact:** `resh-X.Y.Z-beta-x86_64-unknown-linux-gnu`, SHA-256 `<checksum>`, built from `<commit>` with Rust `<version>`.
