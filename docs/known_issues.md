# Known Issues

These issues were found while writing the per-verb `--help` metadata, and each
one was then checked against the code by a separate read-only review.

## v1.0.4-beta security release (2026-10-27)

These fixes are in v1.0.4-beta, each with regression tests
(`tests/stage6b_security.rs` and unit tests in the affected handles). They
are not in v1.0.3-beta or earlier.

- **backup argument handling.** Values from `src`, `snapshot_id`, `dest` and
  `repo_url` could be read by tar, rsync, borg or restic as options or as
  remote locations, which could run commands. Values are now validated before
  anything runs (including dry runs), option values are attached with `=`,
  positional values follow `--`, tar runs with `--force-local`, and rsync
  gets local relative paths with a `./` prefix. See `backup.md` 3.3.
- **backup `prune dry_run=true`** validated nothing before running restic or
  borg in their own dry-run mode. Validation now comes first, and the result
  states which kind of dry run ran (`dry_run_mode`: `plan` or `backend`).
- **cron `add`** wrote line breaks in job fields into crontabs and unit
  files (extra jobs or unit directives), used `unit_name` in file paths
  unchecked, accepted any file as `cron_file` for `scope=system` (and
  `disable cron_file=` rewrote any file), and wrote six-field schedules that
  cron misreads. Every field is now checked against its own syntax before
  anything is written or previewed, `cron_file` is limited to `/etc/crontab`
  and `/etc/cron.d/<name>`, unit values are escaped, and crontab and unit
  files are never written through symbolic links. See `cron.md` 3.3.
- **ssh `exec`** passed `command_args` to the remote shell mostly unquoted.
  Each argument is now quoted for POSIX login shells; cmd/PowerShell modes
  refuse arguments that would need quoting; an unknown `shell_mode` is an
  error; and `command.raw` is the exact remote string. ssh error envelopes
  now report the requested `dry_run` instead of always `false`. See `ssh.md`.
- **cert `sign signature_algorithm=ecdsa_sha512`** with a P-384 key produced
  a SHA-384 signature. It now signs a SHA-512 digest; unsupported key and
  algorithm pairs are refused.

## v1.0.3-beta release gate (2026-10-23)

The v1.0.2-beta release gate
(`docs/reviews/resh-cli-v1.0.2-beta-release-gate.md`) re-assessed the
remaining Medium risks and found three that are release blockers. They are
fixed in v1.0.3-beta, each with regression tests:

- **cert private keys** (`generate`, `renew key_strategy=rekey`,
  `csr.create key_strategy=generate`) were written with the umask mode and
  then changed to 0600, so another local user could open the key in between;
  the write also followed a symlink at the key path, and a dangling symlink
  bypassed `overwrite=false`. Keys are now created 0600 from the start and a
  symlink at the key path is refused. `csr.create` no longer replaces an
  existing `new_key_output_path` without `overwrite=true`.
- **`file replace backup=<suffix>` and `archive add backup_suffix=`** copied
  through a symlink planted at the backup name, overwriting its target and
  changing its mode. The backup is now written to a new temporary file and
  renamed into place; a symlink at the backup name is refused.
- **backup default repositories** under `/tmp` (`/tmp/resh_backup_<profile>`,
  `/tmp/rsync_backup`, `/tmp/borg_repo`) left archives readable by every
  local user and were accepted when another user had created them first.
  The defaults are removed: tar, rsync and borg now require `repo_url`.

Also corrected: a real MySQL connection string with a password was removed
from `MYSQL_CONNECTION_GUIDE.md`. It is still in earlier tags and in the
repository history, so it must be treated as compromised.

## Release-candidate status (2026-10-23)

This section supersedes the test counts and "Still open" list in the
2026-10-16 status below. The full evidence is in `docs/reviews/`
(Stage 1-3 remediation reports and the Stage 4 release assessment).

- **Tests:** `cargo test --locked` passes: 1,181 lib and 1,185 bin unit
  tests, plus the help, documentation-example and CLI regression suites; 11
  infrastructure tests are `#[ignore]`d and pass against disposable git,
  PostgreSQL and MariaDB with `--ignored`.
- **Fixed in Stage 4 (release-candidate verification):**
  - `pkg update/upgrade security_only=true` silently ran a full upgrade on
    apt, pacman, apk and brew (and yum for upgrade). It is now refused
    before anything runs where resh cannot restrict the upgrade.
  - `backup create/prune` treated a malformed `dry_run` as false and ran
    for real; `backup restore dry_run=true` performed a real restore. Both
    are now refused.
  - `mail://send` ignored `dry_run` (including the bare word) and sent the
    message. A dry-run request is now refused before any SMTP connection.
  - `fs mount/unmount` treated a malformed `dry_run` as false; it is now an
    error.
  - `fs resize` on ext3/ext4 asked `resize2fs` for a quarter of the
    requested size; the size argument is now correct.
  - `file rename to=<bare name> overwrite=true` deleted the destination and
    then failed; bare destination names now work for rename, copy and move,
    and the parent is checked before anything is deleted.
  - `archive add/remove` on `.tar.zst` wrote a truncated archive; the zstd
    stream is now finished.
  - `mail://config` wrote SMTP profiles (with base64 passwords) using the
    umask, typically world-readable; the file is now 0600.
  - `firewall rules.reload` from a normalized JSON snapshot wrote the rules to
    a predictable `/tmp` name that a local user could pre-create as a
    symlink; it now uses a securely created temporary file.
  - `resh` with no stage panicked (exit 101); it now prints an error and
    exits 2.
  - A verb without a dry-run mode ignored `dry_run=true` and made the real
    change (for example `file delete dry_run=true` deleted the file), and
    misspelled dry-run words and keys (`dry-run`, `DRY_RUN=true`) were
    dropped. A top-level `dry_run=true` was also ignored by `pkg`, which
    reads it only from `input=`. The dispatcher now refuses all of these
    before the handle runs.
  - `archive add` rebuilt existing tar entries without their headers (mode
    0, owner 0, mtime 0, symlinks became empty files); it now keeps the
    original headers. Archive rewrites use unpredictable, non-following
    temporary files with the original permissions, and compression errors
    at the end of the stream fail the operation.
  - `fs resize` ran `lvextend`/`lvreduce` through `sh -c`; it now runs them
    without a shell.
  - TLS dependencies patched (rustls 0.23.46, rustls-webpki 0.103.16,
    webpki-roots 1.0.10), plus bytes 1.11.1 and h2 0.4.16.
- **Significant limitations that remain** (each is documented in its
  handle's page under `docs/`):
  - Unsupported by design in this release: encrypted ZIP creation, git sync
    merge/rebase (fast-forward only), secret encryption at rest and
    `rotate`, ssh `tunnel`/`keys.list`/`key.add`, backup `schedule`
    installation, pkg restore version pinning/rollback, dns `zone.update`
    (simulated) and TSIG, cert CMS and encrypted keys, `proc limits.set` on
    other processes.
  - SMTP profile passwords are base64-encoded, not encrypted. Since Stage 4
    the profile file is written owner-only (0600).
  - No dry-run mode for svc, proc, file writes, cache/db writes, mq, ssh
    (except exec), mail send and backup restore; for these `dry_run=true` is
    refused before anything runs; git `timeout_ms` is rejected; pkg and fs timeouts stop waiting
    but do not kill the child process: it either keeps running and finishes
    after the timeout is reported, or is killed by `SIGPIPE` part-way through
    when it next writes output. Check package-manager or filesystem state
    after a timeout.
  - `net ping` exits 0 even when the host is unreachable; `http head`,
    `headers` and `json` exit 0 for 4xx/5xx statuses.
  - Option-injection hardening (`--` separators) for backup argv, cron job
    fields and ssh `command_args` is in v1.0.4-beta (see the section
    above); in v1.0.3-beta and earlier, never pass untrusted input in
    backup `src`, `snapshot_id`, `dest` or `repo_url`, in cron job fields,
    or in ssh `command_args`. User `primary_group` and fs `mount`
    `source`/`target` are refused when they start with `-` and passed after
    a `--` separator from v1.0.5-beta; in v1.0.4-beta and earlier, never
    pass untrusted input in them.
  - Archive extraction checks paths but not against a concurrent process
    changing the destination tree; never extract as root into a directory
    other users can write.
  - Do not run plugin verbs as root with another user's `HOME`/`XDG_*`
    (for example `sudo -E`): `remove` and `remove purge=true` then act on a
    store that user controls and can be made to delete files outside it.
  - Existing tar or rsync repository directories are used as they are:
    resh does not check their owner or mode. Use a directory only you can
    write.
  - Plugin enabled state is written and read from different files, so
    `installed.list` reports enabled plugins as disabled.

## Status (2026-10-16, historical)

All **Critical**, **High** and **Low** issues below have been fixed. Each fix
has unit tests, and the help metadata was updated to match the new behavior.
These **Medium** items were also fixed:

- archive: `.tgz` handling, duplicate entries, and the `format` key.
- fs `usage` warnings and the `DEBUG` lines.
- The cron selectors and paths.
- proc signal names.
- backup prune dry run and untagged restic snapshots.
- plugin targets.
- template strict mode.
- db `tls_mode` and `log_queries`.
- cert info, fingerprints, generate and curves.
- The firewall status text.
- The system memory defaults.
- ssh `exec cwd=`, upload, `key.add` and test.

Every other Medium entry below is still open.

Not verified against real systems: the fixes involving root, network or real
devices (firewall, user, ssh, cache/db servers, restic/borg repositories, fs
resize/check) were tested through unit tests on the exact commands they
build, plus dry runs. They have not been run against live systems.

Test suite at that time: 1044 passed, 15 failed (all 15 were fixed in
Stages 1 and 3; see the release-candidate status above).

### Fixed

| ID | Fix |
|---|---|
| C1 | backup: the password comes from `password=`, `password_file=`, or the restic/borg password environment variables. With none, the command fails with `MISSING_PASSWORD` before running anything. |
| C2 | firewall `rules.delete`: iptables rules are deleted by full rule spec. Rule ids follow each backend's own numbering. Default `match_mode=exact`. A delete with no criteria is refused. |
| C3 | firewall `rules.add family=any`: adds both the IPv4 and IPv6 rule. With an address, the family follows the address, and a mismatch is an error. |
| C4 | ssh `download` and `upload`: real transfers over the system `ssh`. Writes go to a temp file that is renamed into place. Checksums are reported only when actually compared. |
| C5 | cert `verify`: real chain signature checks (ring), trust anchors, hostname, purpose and keypair checks. A check that was not performed is reported as `not_checked` or `unsupported`, never as a pass. |
| C6 | secret: the store file is created with 0600 and its directory with 0700. Writes are atomic (temp file then rename). There is no `/tmp` fallback, and the help says the store is unencrypted. |
| C7 | main.rs: `mail://test` and `mail://config` are never rewritten, and the rewrite into `send` matches whole argument keys only. |
| H1 | plugin `install` and `update` really install, and `dry_run` returns the plan. Nothing panics. |
| H2 | In-URL help detection is exact everywhere (`help::is_help_flag`, `parse.rs` `is_help_request`). |
| H3 | cron: `extract_job_id` uses the right offset. `match_comment`, `/etc/cron.d` paths, path reporting and `list` arguments are also fixed. |
| H4 | backup: every command runs the right program. tar and rsync list and prune use direct file access. |
| H5 | backup `create`: restic, borg and rsync output is parsed, and a successful backup is reported as success. |
| H6 | user: changes run for real (dry run lists `planned_commands`). Passwords go to `chpasswd` on stdin. Lock state and groups come from real lookups. JSON output is clean. `user://alice` targets alice. |
| H7 | `core::lenient` converts CLI strings into typed options. Used by fs, git and db; system also accepts plain key=value arguments. |
| H8 | file (and snapshot): the URL host and path are joined, so `file://dir/x` is `dir/x`. |
| H9 | cert `renew` uses the signer and the reused or new key, and reports the real certificate. `csr.sign` and `sign mode=csr` issue real certificates from the CSR. |
| H10 | pkg: a text lockfile restores using the requested or detected package manager. |
| H11 | cache and db verbs connect on demand (`url=`, `dsn=`). `db transaction action=run` runs a transaction in one call. Events are stored in files under the state directory. |
| L1 | The old `*_HELP_TEXT` constants are deleted. Every in-URL help form prints the approved help (`help::render_legacy`). |
| L2 | `plugin://<id>.enable` and `plugin://available.list` now work. README and docs match the real syntax. |
| L3 | `.gitignore` ignores only root-level `/test*` scratch files, so `tests/` is tracked. |
| L4 | cert tests use temp directories, db tests no longer race, and the template strict-mode bug is fixed. |
| L5 | `src/backends` is removed, along with the `pub use backends::*` re-export in `src/lib.rs`. |

### Behavior changes users will notice

- backup:
  - restic and borg now require a password.
  - A failed list, restore, verify or prune now returns an error instead of
    success.
- firewall `rules.delete`:
  - With the default `match_mode=exact`, a rule matches only if all its
    conditions match. Use `match_mode=subset` for the old behavior.
  - A delete with no criteria is refused.
- user commands now change the system. Previously they only printed what
  they would do.
- `archive create`: `format` means only the archive format. The report
  format is set with `format_output=`.
- fs, git and db: an invalid typed value (for example `timeout_ms=soon`) is
  now an error instead of being silently replaced by the default.
- `plugin://install` (no plugin id) is now an error.
- cert:
  - `key_passphrase` now fails, because key encryption is not supported. It
    used to write an unencrypted key and report it as encrypted.
  - `cert:///abs` stays an absolute path.
- On http, net and dns, `--help=<unknown verb>` now shows the full handle
  help and exits 0. Before, net exited with status 2.

### Still open

These were found during the fixes, or are Medium items that were not fixed:

- **Timeouts:** fixed in Stage 2 (FUNC-08). Backup timeouts now kill the
  backend at the deadline and fail with a `TIMEOUT` error. Stage 3: firewall
  `timeout_ms` is enforced the same way. Git operations cannot be
  interrupted (blocking libgit2 calls), so git now rejects `timeout_ms`
  instead of ignoring it.
- **Event hooks:** the built-in hook notes now go to stderr, so JSON on
  stdout stays valid (Stage 2). `list-topics` still returns mock catalogs,
  and `hooks.disable` still always reports success.
- **cache key parsing:** a numeric key such as `key=123` is rejected as a
  missing key.
- **cache test speed:** the existing cache tests try `127.0.0.1:11211` with
  no timeout, so they are slow when memcached isn't running.
- **secret `?help=<verb>`:** `secret://local/x?help=get` is rejected by the
  stage parser before it reaches the handle.
- **cert:**
  - `chain.info` is simplified.
  - Encrypted private keys and CMS signatures are not supported.
  - `csr.create` cannot put key usage into a CSR (an rcgen limitation).
- **ssh `exec env=`:** sets variables on the local ssh process, not on the
  remote host.
- **backup `schedule`:** installs nothing.
- **Pre-existing test failures (15):** all fixed. `archiveh::test_path_sanitization`
  in Stage 1; the 11 `userh` and 3 `gith` tests in Stage 3 (details in
  `docs/reviews/resh-cli-stage3-build-test-security.md`). Tests that need a
  database server or a git remote are marked `#[ignore]` and run with
  `--ignored` against disposable infrastructure.

---

## Critical

### C1. `backup`: restic and borg passwords are hard-coded

- **Where:** `src/handles/automation/backuph.rs:1476, 1580, 1630, 1675, 1721`
  set `RESTIC_PASSWORD`, and `:1507, 1594, 1648, 1688, 1746` set
  `BORG_PASSPHRASE`. Both are set to `"backup123"`, with the comment
  `// Default for demo`.
- **Impact:** every restic or borg repository that resh creates is encrypted
  with a password anyone can read in the source.
- **Fix:** take the secret from an argument, an environment variable, or the
  `secret://` handle, and fail if none is provided.
- **Note:** `src/backends/backup/*` has a configurable `repo_password`, but
  that code is never used (see L5).

### C2. `firewall rules.delete` on iptables can delete the wrong rule

- **Where:** `src/handles/security/firewallh.rs`.
  - `:4695-4725` resets the rule counter for each table and increments it for
    every rule in that table, across all chains.
  - `:7362-7363` builds `rule_id` as `CHAIN:<counter>`.
  - `:7435` emits `-t <table> -D <chain> <N>`.
- **Impact:** for any chain after the first one in a table, `N` is not the
  rule's line number within its chain, so a different rule, or no rule, is
  deleted. The fallback at `:7366` uses the index within the filtered list,
  which is also wrong.
- **Also:** `rule_id` and `match_mode` are echoed back in `query` but never
  used for matching (`find_matching_rules`, `:7294-7356`). `zone` is used only
  by firewalld (`:7494`).
- **Exposure:** `rules.*` verbs were unreachable from the CLI until the
  scheme-aware dotted-verb fix in `src/core/parse.rs`. This bug is now live.
  Gate `rules.delete` behind `dry_run`, or fix it, before release.

### C3. `firewall rules.add family=any` never adds an IPv4 rule

- **Where:** `firewallh.rs:6751` chooses `ip6tables` for any family other
  than `ipv4`.
- **Impact:**
  - `family=any` creates an IPv6 rule only.
  - The reported rule shows `saddr`/`daddr` `0.0.0.0/0` (set at `:6641`,
    then dropped from the command at `:6777, 6784`).
  - An explicit IPv4 `saddr` with `family=any` is passed to `ip6tables`.
- **Exposure:** like C2, this verb became reachable with the parser fix.

### C4. `ssh download` overwrites the destination with placeholder data

- **Where:** `src/handles/network/sshh.rs:5481` writes
  `b"key: value\ndata: test\n"`, then `:5522-5530` renames that over `dest`.
- **Impact:** with `overwrite=true`, a real local file is replaced by fixed
  junk. The response still reports success, a fake size of 2048 bytes, and
  `checksum_verified: true` (`:5471-5473, 5565`).
- **Fix:** fail with "not implemented" until SFTP transfer exists.

### C5. `cert verify` reports success for checks it does not perform

- **Where:** `src/handles/security/certh.rs`.
  - The chain check (`:4147`) passes any certificate that is not
    self-signed.
  - The usage check (`:4202`) and the keypair check (`:4211`) always pass.
  - `verify_hostname` (`:4180-4184`) accepts any hostname whenever a SAN
    extension is present.
  - Soft revocation (`:4217`) reports a pass even though it is not
    implemented.
  - The `trust`, `trust_paths`, `trust_pem`, `max_chain_depth` and
    `min_rsa_bits` options are parsed but never applied.
- **Impact:** automation that relies on `verify` accepts untrusted or
  mismatched certificates.

### C6. `secret` local store is plaintext and briefly world-readable

- **Where:** `src/handles/security/secreth.rs`.
  - `:1403-1406` writes plain JSON to
    `<state_dir>/resh/secrets/local.json`, falling back to `/tmp` when there
    is no state directory (`:1367-1369`).
  - Permissions are set to 0600 only after the write (`:1410-1418`).
- **Impact:** secrets sit unencrypted on disk, readable under the default
  umask during the window before permissions are tightened, and possibly in
  `/tmp`. The old `SECRET_HELP_TEXT` calls the store "encrypted"
  (`:25, 27, 44, 47`).
- **Fix:**
  - Create the file with 0600 from the start (`OpenOptions` plus `mode`).
  - Never fall back to `/tmp`.
  - Encrypt the store, or stop calling it encrypted.

### C7. Some `mail://test` and `mail://config` commands run `send` instead

- **Where:** `src/main.rs:89-107` (`reconstruct_mail_command`).
  - If no `to=`, `subject=`, `from=`, `cc=`, `bcc=`, `text_body=` or
    `html_body=` argument is present, but the joined text contains `=` and
    any of `@`, `to` or `subject` (plain substring matches), the stage is
    rewritten to `mail://send(...)`.
- **Impact:**
  - `mail://test smtp_username=alice@example.com` parses as verb `send`, with
    a mangled argument key `"test smtp_username"` (confirmed through
    `parse_stage`).
  - Any argument value containing the letters "to" also triggers the rewrite.
- **Fix:** only rewrite when the stage has no explicit verb, and match whole
  keys, not substrings.

---

## High

### H1. `plugin install` and `plugin update` panic on `todo!()`

- **Where:** `src/handles/pluginh/plugin/engine.rs:121, 124`.
- **When:** resolve and plan succeed with an Install or Update decision.
  `dry_run` is not checked first, and nothing catches the panic.
- **Fix:** return a "not implemented" error, and honor `dry_run` before
  reaching that code.

### H2. Any target containing "-h" is treated as a help request

Each of these uses a substring check instead of an exact match, so targets
such as `/home/x/my-hosts`, `my-httpd`, `pre-hotfix` or `plugin://my-helper`
print help instead of running.

| Handle | Location |
|---|---|
| file | `src/handles/filesystem/fileh.rs:1757` (`from_url`), `:5005` (`call`) |
| cert | `src/handles/security/certh.rs:2488-2489` |
| config | `src/handles/data/config.rs:1284-1285` |
| snapshot | `src/handles/filesystem/snapshot.rs:1285`, `:2619` |
| svc | `src/handles/processes/svch.rs:2181-2183` |
| proc | `src/handles/processes/proch.rs:2297` |
| db | `src/handles/data/dbh.rs:1038-1039` |
| system | `src/handles/system/systemh.rs:2858` (checks `input`) |
| plugin | `src/core/parse.rs:88`; `src/handles/automation/pluginh.rs:1224` |
| parser | `src/core/parse.rs:272` (only a fallback when no verb is split off) |

- **Fix:** match whole tokens (`== "--help"`, `== "-h"`), or rely on the new
  `resh <handle> --help` path.

### H3. `cron enable` and `cron disable` cannot match a job by id

- **Where:** `src/handles/processes/cronh.rs:4743` (enable) and `:5259`
  (disable) slice `&line[start + 8..]` after finding `"job-id="`, which is
  7 characters.
- **Impact:**
  - The first character of the id is dropped, so `target_id == entry_id`
    (`:4941, 5398`) never matches.
  - A line ending exactly in `job-id=` makes the slice panic.
- **Note:** `rm` is correct (`:5519`).
- **Fix:** use `start + "job-id=".len()`.

### H4. Several `backup` commands run the wrong program

- **Where:** `execute_backend_command` (`backuph.rs:661-669`) always runs
  `Command::new(<backend>)`, but some argument lists start with a different
  program's name:

| Operation | Command actually run | Location |
|---|---|---|
| tar list | `tar ls -la <repo>` | `:1615` |
| tar verify | `tar find <repo> -name *.tar.gz -exec tar -tzf {} ;` | `:1706` |
| rsync list | `rsync ls -la` | `:1604` |
| rsync verify | `rsync find ... -exec test -r {} ;` | `:1220-1224` |
| rsync restore | `rsync rsync -av src dest` | `:1144` |
| tar and rsync prune | `tar find ...` / `rsync find ... -mtime +30` | `:1302` |

### H5. `backup create` reports failure after a restic, borg or rsync backup succeeds

- **Where:** `parse_create_output` (`backuph.rs:1770-1786`) handles only tar;
  every other backend hits `bail!("Backend not yet implemented")` (`:1785`).
- **Impact:** `verb_create` has already run the backup (`:965`), then turns
  that error into a `PARSE` error envelope (`:985-994`). Scripts see a
  failure for a backup that completed.

### H6. `user` changes are simulated, and their log lines corrupt the JSON

- **Where:** the default `UserBackend::System` in
  `src/handles/security/userh.rs`. For example: useradd `:2781`, userdel
  `:3123`, lock/unlock `:3549, 3595`.
- **Simulated:** every change (useradd, groupadd, usermod, userdel, groupdel,
  gpasswd, password, lock, unlock) only prints `Would execute: ...`.
- **Always-false stubs:** `is_locked` and `verify_password` always return
  false (`:3502, 3396`).
- **Partial lookup:** the group lookup returns only the primary group
  (`:3267-3297`).
- **Output corruption:** those `println!` lines go to process stdout, not
  `io.stdout`, so they corrupt JSON output.
- **Target bug:** `UserHandle::from_url` (`:3983-3987`) reads only the URL
  path.
  - `user://alice` targets a user named "default".
  - `user://group/admins` targets "admins" as if it were a user.
  - `UserTarget::from_url` (`:2266`) handles the host form correctly, but it
    is used only in tests.

### H7. Typed options cannot be passed from the command line

CLI arguments are always strings (`Args = HashMap<String, String>`,
`src/core/registry.rs:42`). Several handles deserialize them straight into
typed structs:

- **fs** (`src/handles/filesystem/fsh.rs`):
  - `snapshot :3528`, `resize :6007`, `check :6811` and `list-mounts :7400`
    fail on any bool, list or number option (`dry_run=true`,
    `include_pseudo=true`, `allow_shrink`, `allow_repair`, `timeout_ms`).
  - `quota` and `usage` silently ignore those options. `usage mode=paths`
    always fails (`:5586`).
  - Consequence: `resize` cannot shrink and `check` cannot repair.
- **git** (`src/handles/system/gith.rs`):
  - `clone :2362`, `pull :2370`, `push :2378`, `status :2602`,
    `branch :2645`, `commit :2755`, `sync :7235`, `status_summary :7298` and
    `status_short :8212` fail with "invalid type: string".
  - `merge` and `rebase` silently ignore bool and number values
    (`:3206, 3404`).
  - Consequence: `commit` cannot use `all` or `paths`, so it only commits
    changes that are already staged.
- **db query** (`src/handles/data/dbh.rs:4577-4597`, `:319-325`):
  `timeout_ms` and `max_rows` are silently ignored, so the defaults of
  5000 ms and 1000 rows always apply. `exec` converts its options correctly.
- **Fix:** add one shared helper that converts string values (`"true"`, or
  numbers as text) before deserializing, or use lenient `deserialize_with`
  functions.

### H8. `file://` relative paths resolve to the wrong file

- **Where:** `fileh.rs:1745-1750` uses the URL host alone whenever it is
  non-empty and discards the path.
- **Impact:**
  - `file://./x` resolves to `.`.
  - `file://dir/x` resolves to `dir`.
  - Only `file://name` and absolute `file:///path` work.
  - The global `--help` example in `src/main.rs:130` is
    `file://./foo.txt.read`, which hits this bug.

### H9. `cert renew` and `cert csr.sign` produce invalid certificates

- **renew** (`certh.rs:7350-7394`):
  - The `signer` parameter is never read; renew always self-signs with a
    fresh key.
  - That key is never saved. With `key_strategy=rekey`, a different,
    unrelated key is saved (`:3829`).
  - Validity settings are ignored (`:7380`).
  - The reported details are placeholders: `CN=renewed-cert`,
    `"dummy-fingerprint"` (`:7457-7486`).
- **csr.sign** (`certh.rs:5916-6051`):
  - Writes a mock certificate (`MOCK_CERTIFICATE_DATA_FOR_DEMONSTRATION`) with
    hard-coded subject, issuer, serial and fingerprints, and reports
    `ok: true`.
  - Is unreachable from the CLI: `cert://x.csr.sign` parses as the `sign`
    verb. This is intentional so that `cert://req.csr.sign` keeps working;
    see `UNREACHABLE` in `tests/help_coverage.rs`.

### H10. `pkg restore` with a text lockfile can never succeed

- **Where:** `src/handles/system/pkgh.rs:8416` hard-codes the lockfile's
  manager as `"auto"`.
- **Impact:** `resolve_restore_manager` (`:8472-8503`) then fails either way:
  `manager=auto` gives `ManagerNotFound`, and any explicit manager gives
  `RestoreManagerMismatch`.

### H11. Connection-based handles cannot be used across separate commands

- **cache:** `connect` is a stub (`src/handles/data/cacheh.rs:1728-1742`)
  that never writes `CONNECTION_REGISTRY`. Every other verb therefore returns
  `cache.connection_not_found`.
- **db:** the connection and transaction registries exist only in memory
  (`dbh.rs:779, 961`).
  - `tables`, `schema`, `ping` and `transaction` always fail from a fresh CLI
    invocation.
  - A `tx_id` can never carry over to a later commit or rollback.
  - Only `query` and `exec` work, by connecting on demand with `dsn=`.
- **event:** each handle object gets a new in-memory event store
  (`src/handles/data/eventh.rs:1884-1888`), so `subscribe` returns no events
  even within the same process.

---

## Medium

### Network

- **dns `zone.update` is simulated.**
  - `attempt_zone_update` (`src/handles/network/dnsh.rs:5796-5820`) sleeps
    and returns `NoError`.
  - `build_update_message` is never called, so TSIG signing (also a stub) is
    never reached.
  - The response still reports `tsig_used` (`:5366`).
- **dns resolver and options.**
  - With no `servers=`, lookups use `ResolverConfig::default()` (fixed public
    resolvers) instead of the system resolver (`:2715`).
  - Lookup `authority` and `additional` are always empty (`:2754-2755`).
  - The resolve `raw` field is always null (`:1021`).
  - `zone.fetch` falls back from IXFR to AXFR (`:4744-4748`) and ignores
    `use_tcp`, `retries`, `dnssec` and the TSIG options.
- **net `tcp_check` ignores `port=`.**
  - It connects to the URL port (`src/handles/network/neth.rs:2427`) but
    reports the `port=` value (`:2362-2368`).
  - `port=` alone fails address resolution.
  - `expect_tls` is unused, and `tls_checked` is always false
    (`:2335, 2462, 2493`).
- **net other.**
  - `list` ignores the URL host (`:1786`).
  - The `up` filter really means "not loopback" (`:3423`).
  - A, AAAA, MX, TXT and PTR records always report a TTL of 300.
  - `net dns` reports server `"system"` while using `ResolverConfig::default()`
    (`:1363, 1896`).
- **http.**
  - `head` and `patch` ignore `timeout_ms` (fixed at 10 s and 30 s,
    `src/handles/network/httph.rs:1895, 2445`).
  - `allow_insecure` is honored only by `put` (`:2258`), although the help
    advertises it for every verb.
  - `post` and `put` prefer `body_file` over `body`, while `patch` and
    `delete` prefer `body`.
  - The doc comment on `json` (`:3181`) claims it sets
    `Accept: application/json`; it doesn't.
- **ssh simulated or stubbed verbs** (`src/handles/network/sshh.rs`).
  Updated 2026-10-23: `upload` and `download` perform real transfers
  (fixed, C4). Still stubs: `tunnel`, `keys.list` and `key.add` fail with
  `ssh.not_implemented` unless `dry_run`; in `test`, the `sftp` and
  `hostkey` checks always fail.
- **ssh `exec` with `cwd=`.**
  - The SSH arguments are added twice (`:6318, 6329-6330`).
  - For sh and bash, the `cd` is also applied twice (`:5722`).
  - With password auth, `cwd` is dropped (`:6346`).
- **ssh `config.get`.** A later matching entry overrides an earlier one
  (`:8452, 8496`); OpenSSH uses the first match.
- **mail `test`.**
  - It never opens an SMTP session: `tls_established` and `auth_succeeded`
    are set from configuration (`src/handles/network/mailh.rs:3841-3858`).
  - `send` and `test` never read the stored profiles.

### Filesystem

- **archive.**
  - `.tgz` files are detected as uncompressed by the verbs that read
    archives: list, test, extract, add and remove
    (`src/handles/filesystem/archiveh.rs:626-636`). `info` works.
  - tar and tar.gz `create` writes each file in a directory source more than
    once (`:3401-3406, 3510-3516`).
  - `create` reads `format` both as the archive format and as the output
    format (`:1115, 1193`), so `format=json` or `format=text` is rejected.
  - tar.xz, tar.zst, 7z, and `.gz` with format auto return "not yet
    implemented" (`:3483-3489, 543`).
- **fs.**
  - `usage` fails the whole call (exit 32) if any one mount fails statvfs
    (`fsh.rs:5626-5628, 5775`).
  - `snapshot format=yaml` returns JSON (`:4068-4073`).
  - `list-mounts` prints `DEBUG:` lines to stderr (`:7399, 7402`).
- **file.**
  - `copy preserve_times` is not implemented; it only prints a warning
    (`fileh.rs:5226-5231`).
  - The `rename atomic` option has no effect (`:4357-4362`).
- **snapshot.**
  - Snapshots made by `create` have no state or tags, so the `ls` `state=`
    and `tag=` filters never match them (`snapshot.rs:1226-1235`).
  - "Target not empty" exits with 3, not the documented 4 (`:2153`).
  - `restore` by name picks the first match across all targets, in
    filesystem order (`:2017-2041`).
- **log.** `log://svc/<service>` is unreachable, because `from_url` always
  builds a file source (`src/handles/data/logh.rs:484-502`).

### Processes

- **cron.**
  - `match_comment` counts as a selector but is never used for crontab
    matching (`cronh.rs:4939-4962, 5396-5419`).
  - `rm` and `enable` pass bare `/etc/cron.d` filenames (`:4359, 4536`).
  - `add` reports `/var/spool/cron/crontabs/<user>` while the other verbs
    report `/var/spool/cron/<user>` (`:3991, 5483`).
  - `list` ignores all arguments (`:1280-1300`).
- **proc.**
  - `limits.set` changes the resh process's own limits; `pid` is only
    echoed back (`proch.rs:2077-2085`).
  - The signal-name labels are wrong: 17 and 19 both map to STOP, 30/31 to
    USR1/USR2, and 10/12 map to UNKNOWN (`:2245-2259`). The signal number
    actually sent is correct.
  - `io.peek` reads log files that nothing writes (`:1783-1847`).

### Automation

- **backup.**
  - `schedule` installs nothing (`backuph.rs:1359-1425`).
  - A `prune` dry run never calls the backend, so `would_prune` is always 0
    (`:1308-1326`).
  - restic snapshots without tags or paths are dropped from `list`
    (`:1794-1808`).
- **plugin.**
  - `enable` and `disable` cannot target a named plugin: `plugin://aws.enable`
    parses as verb `aws.enable`.
  - The `available.*` verbs need doubled targets such as
    `plugin://available.available.list` (`src/core/parse.rs:34, 82-158`;
    `pluginh.rs:572, 676`).
- **template.** With `strict=false`, a missing variable is still reported
  as a render error. Tera's display text doesn't contain "Variable"; that
  wording is in the error's source chain (`templateh.rs:1063-1066`).

### Data and system

- **db.**
  - `tls_mode` and `log_queries` are validated but never applied
    (`dbh.rs:1185-1253, 1348-1386`).
  - The help lists `allow` as a TLS mode, but the validator rejects it.
  - The PostgreSQL and MySQL `schema` index, foreign key and constraint lists
    are always empty (`:4226-4245, 4342-4355`).
- **event.**
  - `list-topics` returns mock catalogs (`eventh.rs:1006+`).
  - `include_backends` and `summarize` are unused.
  - `hooks.disable` always reports success (`:3424-3437`).
- **config.** `watch` with neither `key` nor `prefix` watches the whole
  namespace, but the old help says one of them is required.
- **cert.**
  - `info` always reports a public key algorithm of "Unknown", empty
    extensions, and `is_ca: false`.
  - `info` rejects CSRs and parses only the first certificate in a bundle.
  - `sha512` fingerprints are advertised but rejected (`certh.rs:2559, 3944`).
  - `generate mode=leaf_cert` is not implemented (`:3487`).
  - P-521 and secp256k1 keys are accepted but fail to generate (`:2966`).
  - `mode=csr` writes the CSR only if `output` contains `"write_csr":true`.
  - `DEBUG` `eprintln!` lines are left in key generation (`:3150`).
- **firewall.**
  - The iptables status `details` text is inverted (`firewallh.rs:8312`).
  - The old help shows `rules.list(backend=all)`, which `rules.list` rejects
    (`:74, 2163`).
- **git.**
  - `pull` with diverged branches fails: merge and rebase are not
    implemented (`gith.rs:4217-4231`).
  - `MERGE_HELP` documents a `branch` argument, but the code reads `source`.
  - `REBASE_HELP` documents `onto`, but the code reads `upstream`.
- **system.** `memory` input must list every option, because
  `SystemMemoryOptions` lacks `#[serde(default)]` (`systemh.rs:1929`).
  Trailing arguments such as `format=text` are ignored, since only
  `input=<json>` is read.
- **pkg.** Every verb needs `manager` in `input`, but the `PKG_HELP_TEXT`
  examples omit it.
- **secret.**
  - `rotate` is not implemented (`secreth.rs:1718`).
  - The `vault` scope is accepted, but every verb returns "not implemented".

---

## Low

### L1. The old embedded help texts are out of date

The per-handle `*_HELP_TEXT` constants (shown by forms like `svc://--help`)
disagree with the code in many places, including wrong argument names,
wrong defaults and non-working URL forms. Examples:

- **user:** the examples use the `user://alice` host form.
- **event:** the examples use `event://VERB(...)` with no dot.
- **cron:** `rm` documents `user=`; the code reads `users=`.
- **proc:** USR1 and USR2 are documented as 30 and 31.
- **pkg:** the examples omit `manager`.
- **plugin:** the examples use `plugin://aws.enable()`.

The new `Handle::help()` metadata follows the code. Consider removing the old
constants, or generating them from the new metadata.

### L2. README and docs show plugin commands that don't work

- `README.md:153`: `plugin://security-scanner.enable`
- `docs/Automation_Utilities/plugin.md:127, 139`
- `docs/Automation_Utilities/overview.md:113, 269, 270`
- `docs/resh_overview.md:174`

### L3. `.gitignore` keeps the test suite out of git

- `.gitignore:223` (`/tests/*`) and `:236` (`test*`) ignore `tests/`, so
  `tests/help_cli.rs`, `tests/help_coverage.rs` and `tests/golden/` are not
  tracked.
- `test*` also matches any file whose name starts with "test" anywhere in the
  tree.
- **Fix:** add exceptions such as `!/tests/` and `!/tests/**`, and narrow
  `test*`.

### L4. Some existing unit tests fail or are flaky

- **cert:** the 9 `create_csr` tests in `certh.rs` all write a shared
  `test.csr` in the crate root and never clean it up (`:9757, 6494`). Once
  the file exists, later tests fail with "already exists". It was deleted
  manually on 2026-10-16, but the next test run recreates it.
- **db:** the sqlite tests share the global `CONNECTION_REGISTRY` and
  `TRANSACTION_REGISTRY` and clear them (`dbh.rs:7320` and others), so they
  race under the parallel test runner.
- **template:** `validate_with_data_missing_variable_non_strict` fails
  because of the `strict=false` bug under Automation.

### L5. Dead backup backend code

`src/backends/backup/*` is never referenced. The live `backup` handle is
`src/handles/automation/backuph.rs`.
