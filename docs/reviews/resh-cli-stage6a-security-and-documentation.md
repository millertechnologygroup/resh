# resh — Stage 6A: Repository Security and Documentation Closure

Date: 2026-10-27
Baseline: `v1.0.3-beta` (tag object `d42f7b6cf92530bb936022f1b7cb961ba1ce8665`, commit `dcce21ad0dbb749d2172a57c25841bb253a7bbd7`); `main` = `facd6aa9376db5c7515d0c73d9f1514285e235d9`
Classification: **CONDITIONALLY READY**

Published with the documentation commit that closes the v1.0.3-beta post-release findings. Stage 6A changed no repository setting, Rust source, dependency or workflow. The security findings in sections 8 and 11 were re-verified and extended by the Stage 6B security release assessment, which supersedes them. Exploit payloads are deliberately not included.

## 1. Executive summary

- The Stage 5 baseline is confirmed against the remote. `origin/main` is `facd6aa`, the release commit is in its history, the tag has not moved, and both release assets keep their published digests and timestamps.
- **DOC-1A** (audit exception count) is confirmed and corrected. `.cargo/audit.toml` has **23** effective exceptions, not 22. Gate D left RUSTSEC-2026-0387 out of its count.
- **DOC-1B was raised the wrong way round.** The Stage 5 report called the `audit.toml` comment wrong because Gate D said crypto-bigint does no signing. The code shows the reverse. `cert sign` in data mode signs with `p256`/`p384` `SigningKey`, which runs crypto-bigint on the private scalar and nonce; this was confirmed on a disposable key. The comment was correct, and Gate D's "correction" was the error. Both documents now describe the verified usage. The exception and its justification are unchanged. The advisory remains accepted, but the threat model has to cover automation that runs `cert sign` repeatedly over untrusted data (section 11, R-1).
- The Stage 5 report was sanitized: credential-part hash prefixes, a commit/occurrence pointer, a username hint and a local token-scope detail were removed. Factual errors were also fixed. It is ready to publish.
- The repository has **no branch or tag protection, immutable releases are off, Dependabot alerts are off, private vulnerability reporting is off, and there is no `SECURITY.md`**. Secret scanning and push protection are on, and the workflow token is read-only. Section 6 ranks the decisions for S-1 to S-9.
- The SEC-1 option-injection review (section 8) found **High**-severity paths. Hostile `backup create` sources become tar, restic, borg or rsync options, which allows local code execution, typically as root. A newline in `cron add` metadata injects a crontab or unit-file line, which gives root execution with scope=system. Separately, `backup prune dry_run=true` still spawns the backend. Nothing is rated Critical, because every path needs untrusted input routed into a privileged verb.
- Several automation-correctness defects were reproduced in isolation: `http head`/`json` exit 0 on HTTP 404, `--help` for an unknown verb or handle exits 0, and unknown option keys are silently ignored. Misspelled `dry_run` keys are refused safely.
- **Classification: CONDITIONALLY READY.** The documentation changes are verified and ready for Gate A. The repository-setting decisions (Gate B) and the owner's acknowledgement of the DOC-1B reversal are still open.

## 2. Stage 5 verification

| # | Check | Evidence | Result |
|---|---|---|---|
| 1 | `origin/main` contains the release commit | `git ls-remote`: `refs/heads/main` = `facd6aa9376db5c7515d0c73d9f1514285e235d9`; `merge-base --is-ancestor dcce21ad… origin/main` true | PASS |
| 2 | Documentation commit `facd6aa` present | `origin/main` tip; parent `dcce21a` | PASS |
| 3 | Six required CI jobs passed | Run 40426897709, push, `headSha` `facd6aa9376d…`: build-msrv, test-msrv, test-stable, test-security-regression, fmt, audit = success | PASS |
| 4 | Advisory clippy failure documented | Same run: clippy = failure (`continue-on-error`); documented in Stage 5 §3 and `ci.yml` | PASS |
| 5 | Infrastructure tests skipped by design | Same run: test-infrastructure = skipped (only on `workflow_dispatch` with `infrastructure=true`) | PASS |
| 6 | Published release unchanged | Remote tag `v1.0.3-beta` → `d42f7b6…` → `dcce21ad…`; prerelease, not draft, published 2026-10-26T20:18:30Z; archive 17,291,346 bytes `sha256:3838022f…7175dd` (updated 20:18:29Z), `SHA256SUMS` 103 bytes (updated 20:18:27Z) | PASS |
| 7 | Three prior release reports tracked | `git ls-files`: release-gates-addendum, gate-d, publication | PASS |
| 8 | Stage 5 report pending publication | Untracked (`??`) | PASS |

There is no repository drift since Stage 5: local `HEAD` = `origin/main` = `facd6aa`, and the only untracked items are `.claude/` and the Stage 5 report. The `main` run for `dcce21a` (40426480412) still shows **cancelled**, as Stage 5 recorded (RE-4).

## 3. DOC-1 corrections

### DOC-1A: advisory exception count

Each entry was counted independently with `tomllib`, which parses the file as `cargo audit` does:

| Group | Entries | IDs |
|---|---|---|
| Stage 4 | 18 | RUSTSEC-2026-0204, 2026-0258, 2024-0421, 2026-0141, 2026-0194, 2026-0195, 2026-0037, 2026-0185, 2026-0338, 2026-0339, 2026-0340, 2026-0342, 2025-0009, 2023-0071, 2026-0009, 2026-0367, 2026-0368, 2026-0369 |
| v1.0.3-beta zstd | 4 | RUSTSEC-2026-0391, 2026-0403, 2026-0398, 2026-0410 |
| v1.0.3-beta crypto-bigint | 1 | RUSTSEC-2026-0387 |
| **Total** | **23** (23 unique; one `[advisories] ignore` key; no other keys) | |

The working-tree file was byte-identical to the tag before editing (SHA-256 `d6e78cc0…3a7c`). Gate D's "22" counts the Stage 4 and zstd groups and omits RUSTSEC-2026-0387. This matches `resh-cli-v1.0.3-beta-release-execution.md` ("exit 0, 23 exceptions"). **Correction:** Gate D now says 23 and gives the breakdown.

### DOC-1B: crypto-bigint usage

**Dependency path** (`cargo tree --offline -i crypto-bigint@0.5.5 -e normal`): `resh → p256 0.13.2 / p384 0.13.1 → ecdsa 0.16.9 / primeorder 0.13.6 → elliptic-curve 0.13.8 → crypto-bigint 0.5.5`. resh is the only dependent of p256 and p384. `rcgen 0.12.1` depends on `ring 0.17`, not on p256 or p384.

**Call sites** (`src/handles/security/certh.rs`):

| Use | Site | Through crypto-bigint? |
|---|---|---|
| Key generation | `generate_ecdsa_key`, `P256SigningKey::random` / `P384SigningKey::random` (around line 2076) | Yes |
| Key parsing and re-encoding | `SigningKey::from_bytes`, `from_pkcs8_der`, `to_pkcs8_der`, `to_sec1_der` (around lines 2181–2203 and 2704–2714) | Yes |
| **Raw data signatures** | `sign` → `load_private_key` → `sign_data` → `create_signature`: `ecdsa_key.sign(data)` for P-256 / P-384 (around lines 6070–6082, 7632, 7984–7995) | **Yes** |
| Certificate and CSR signatures | `rcgen::KeyPair::from_der` → ring `EcdsaKeyPair` | No (ring) |
| Signature verification | `ring::signature::UnparsedPublicKey::verify` (around line 9704) | No (ring) |

**Isolated verification.** In a scratch directory, the current tree's debug build:
1. generated a P-256 key with `cert … generate mode=key algorithm=ecdsa`;
2. signed a fixture file with `cert … sign signer_key=… data_source=…`, which returned `ok: true`, algorithm `EcdsaSha256` and exit 0;
3. produced a DER signature that `openssl dgst -sha256 -verify` accepted.

No production key or resource was used.

**Finding.** The Stage 5 premise was that the comment's "and signing" was wrong. That premise is false: the original comment was accurate. Gate D's statement that "crypto-bigint never runs a signature in resh" was wrong. It holds only for certificate and CSR issuance.

**Corrections made:**
- **`.cargo/audit.toml` (comment only).** The comment now lists the three verified uses: key generation, parsing and re-encoding, and `cert sign` data-mode signatures. It also notes that certificates and CSRs are signed by rcgen with ring. The entry, its position and "no network signing oracle" are unchanged.
- **Gate D.** A dated correction banner was added. The executive-summary sentence, the "operations that invoke it" row (adds item 3), the former "Correction to earlier reports" row (now "Signing paths", saying it was corrected), and the secret-dependence, attacker-input, timing and conclusion rows were updated. The conclusion is unchanged: **accepted, not a release blocker**. The residual-risk text now names automated repeated `cert sign` over attacker-submitted data.
- **Gates addendum.** "no signing oracle" → "no network signing oracle". `cert sign` is a local signing function, so the bare claim was inaccurate.
- **Stage 5 report.** The known-inaccuracies item 2 and the DOC-1 backlog row are updated.

**Left as written, deliberately:** `resh-cli-v1.0.3-beta-release-execution.md` lines 175 and 199–202 already say "key generation and signing", which is accurate.

### Regression verification

| Check | Result |
|---|---|
| Parsed `audit.toml` before vs after | **Identical** (`HEAD` version vs working tree, compared as parsed TOML); 23 entries, same order |
| Changed lines in `audit.toml` | Comment lines only (`git diff -U0`: every `+`/`-` line starts with `#`) |
| `cargo audit` run locally | **Not run.** `cargo-audit` is not installed on this host, and installing it needs approval. The CI `audit` job (cargo-audit 0.22.2) will run on the push and is the authoritative check. Because the parsed configuration is identical, its result cannot change because of this edit. |
| Rust source or `Cargo.*` changed | No (`git diff --name-only` = Markdown + `.cargo/audit.toml`) |
| Executable behaviour | Unchanged: `.cargo/audit.toml` is read only by `cargo audit`, not by `cargo build` |

## 4. Documentation sanitization results

Scope: `docs/reviews/resh-cli-stage5-post-release-maintenance.md`. Scanned for IPv4 addresses, home and user paths, credential-shaped strings and DSNs, token prefixes, private-key headers, private hostname suffixes, credential pointers, token scopes and authentication details.

| Finding | Action |
|---|---|
| SHA-256 prefixes of the two credential parts (§5) | **Removed.** 48-bit hash prefixes of a password let anyone confirm offline guesses and add nothing for readers. |
| "4 occurrences … at `9d46f4b`, `v1.0.0-beta` …" (§5 row 2) | **Generalized** to "present in `main`'s history and in tags `v1.0.0-beta` to `v1.0.2-beta`, as `docs/known_issues.md` already discloses". The file name stays, because `known_issues.md` and `CHANGELOG.md` already name it publicly. |
| "Located by diffing … between `9d46f4b` and `dcce21a`" | Commit pair replaced with "the previous `main` tip and the release commit". `9d46f4b` stays in §3, where it is needed as alignment evidence and does not point to the credential. |
| "The database username alone matches the project author's public name" | **Removed.** It disclosed part of the credential. |
| S-8 "Reduce the local `gh` login to the scopes publication needs … broader than needed" | **Generalized** to "use a least-privilege credential for release publication". It described the scope of a local credential. |
| `/home/alice`, `/home/bob`, `/root/` (§7) | Kept. These are documented help-example paths and privacy-scan patterns, not real paths. |
| `user:pass@host` (§4) | Kept. It is a placeholder. |
| IPs, private hostnames, tokens, keys, DSNs | None found |

**Accuracy corrections in the same file:**
- The status banner no longer says "local and uncommitted".
- "see backlog RE-6" → **RE-4**, which is the actual backlog ID.
- "except for one error listed below" → "the items listed below" (three are listed).
- "would have caught this generic DSN" → "is designed to detect generic credentials such as this DSN". Detection was not demonstrated.
- Inaccuracy item 2 and the DOC-1 row are updated for DOC-1B (section 3).

**Completed vs proposed.** §§2–5 describe completed, verified operations. §§6–11 are labelled as recommendations, design-only work or backlog. No claim of a performed setting change or implemented workflow was found. The classification "COMPLETE" refers to the Stage 5 maintenance operations and is accurate.

**Already-committed residue (not changed):** `resh-cli-v1.0.3-beta-publication.md` line 276 says "Narrow the `gh` token scopes, or log out". It is low sensitivity, was published in `facd6aa`, and changing it is not needed for factual consistency. It can be generalized in a later documentation pass if the owner wishes.

## 5. Proposed documentation commit

Message: `docs: close resh v1.0.3-beta post-release findings`

| File | Change |
|---|---|
| `.cargo/audit.toml` | RUSTSEC-2026-0387 comment describes the verified usage (comment only) |
| `docs/reviews/resh-cli-v1.0.3-beta-gate-d.md` | Count 22 → 23; crypto-bigint signing statements corrected; dated correction banner |
| `docs/reviews/resh-cli-v1.0.3-beta-release-gates-addendum.md` | "no signing oracle" → "no network signing oracle" |
| `docs/reviews/resh-cli-stage5-post-release-maintenance.md` | New file, sanitized and corrected |
| `docs/reviews/resh-cli-stage6a-security-and-documentation.md` | New file (this report), **only if the owner includes it in Gate A** |

Pre-commit checks performed:

| Check | Result |
|---|---|
| `git diff --check` (tracked) and trailing-whitespace scan of new files | clean |
| Sensitive-content scan of every file in the commit | No credentials, credential fingerprints, home paths, IPs, private hosts, tokens or token scopes |
| Audit exception set unchanged | Parsed identical, 23 entries |
| No Rust source or behaviour change | Confirmed |
| `.claude/` excluded | Confirmed: it would be staged by explicit path only, never `git add -A` |
| Push type | Normal fast-forward of `main`; no force, no tag or release change |

**Not included:** the `MYSQL_CONNECTION_GUIDE.md` "textbook DSN" part of DOC-1. It is scanner noise, not a factual inconsistency. It stays open as **DOC-1C**, to be handled after S-1 so that the scanner's reaction to it can be observed.

## 6. Security decision matrix (S-1 to S-9)

The Stage 5 report (§6) defines **nine** controls, S-1 to S-9, not seven. They are kept with their original identifiers and descriptions. S-1 to S-7 are the main set. S-8 and S-9 are the low-priority items Stage 5 also listed.

Repository facts (read-only API, 2026-10-27): public repository; user-owned (personal account); rulesets: none; branch protection: none; legacy tag protection: not present; Actions `allowed_actions: all`, `sha_pinning_required: false`; default workflow permissions `read`; Actions cannot approve PRs; no repository secrets; no environments; code scanning not configured (languages detected: actions, rust).

| Control ID | Current state | Proposed state | Risk addressed | Operational impact | Rollback | Prerequisites | Recommendation | Approval |
|---|---|---|---|---|---|---|---|---|
| **S-1** Non-provider-pattern secret scanning | disabled (API: `secret_scanning_non_provider_patterns: disabled`) | enabled | Generic passwords, DSNs and private keys committed in the future. The v1.0.0-beta exposure was this class. | None for pushes (alerts only, not push protection). Expect alerts for the historical DSN and possibly the textbook example (DOC-1C). Close them as revoked or false positive, with reasons. Alert details show the secret to repository admins only. | Disable the setting; existing alerts remain | Admin. Availability for user-owned public repositories is not confirmed: the API reports a configurable state, and an error on enable would mean it is not available. | **Enable now** | Pending |
| **S-2** Branch ruleset for `main` | no protection, no rulesets | Ruleset "main" (target `~DEFAULT_BRANCH`, active). **Phase a:** block force-push (`non_fast_forward`) and deletion. **Phase b:** require the status checks `build-msrv`, `test-msrv`, `test-stable`, `test-security-regression`, `fmt`, `audit` (integration: GitHub Actions) and require a PR with 0 approvals. Bypass actor: Repository admin, mode `always`. | History rewrite or deletion of `main`; unverified commits reaching `main` | **a:** none for normal fast-forward pushes. **b:** direct pushes need admin bypass (recorded in the ruleset insights) or a PR. A solo maintainer can self-merge a PR once checks pass. Required checks must match job names exactly; renaming a job blocks merges until the rule is updated. | Set the ruleset to `disabled`, or delete it | Admin; rulesets are free for public repositories | **a: enable now. b: enable now with admin bypass**, and record the emergency procedure (below) | Pending (a and b separately) |
| **S-3** Tag ruleset `v*` | none (rulesets empty; legacy tag protection not present) | Tag ruleset, include `refs/tags/v*`: restrict update, restrict deletion, restrict creation; bypass: Repository admin | Moving or deleting a published tag, which would invalidate checksums and provenance; tag creation by non-admins | The owner can still create tags through bypass. A mistaken tag cannot be deleted without temporarily disabling the rule, which is intended. CI runs triggered by tags are unaffected. | Disable or delete the ruleset | Admin | **Enable now** | Pending |
| **S-4** Immutable releases | disabled (`enabled: false, enforced_by_owner: false`); setting available | enabled, after the release workflow (RE-2) creates **drafts** first | Silent replacement of published assets; deletion or move of the release tag | Once published, a release's assets and tag cannot change. A fix means a new version (for example `-beta.1`), not a re-upload. Drafts stay editable, which fits the draft-then-publish design. **Existing releases:** per GitHub's documentation, the setting applies to releases published after it is enabled, so `v1.0.3-beta` would stay mutable and is protected only by S-3. Re-verify this when enabling. | Disable the setting. Releases published while it was on keep their immutability, so that part is irreversible per release. | Admin | **Defer** until RE-2 exists and one throwaway pre-release has been published as a test, so that an accidental publication cannot lock a bad artifact | Pending |
| **S-5** Dependabot alerts (security-update PRs optional) | alerts disabled; security updates disabled; dependency graph is on (public repository) | Alerts **enabled**; security updates **disabled**; dependency-review action **deferred** | Advisories published after release go unnoticed between CI runs (`cargo audit` runs only on push) | Expect alerts for the accepted advisories in `.cargo/audit.toml`, as many as 23. Dependabot does not read `audit.toml`, so each must be dismissed with the matching reason ("vulnerable code not used" / "tolerable risk"), referencing the assessment. No automatic PRs. | Disable alerts | Admin | **Enable alerts now; defer security-update PRs.** Automatic PRs would run CI on `pull_request`, but they would bump major versions (zip, p256) that need manual review, and would conflict with the audited exception list. | Pending |
| **S-6** Private vulnerability reporting + `SECURITY.md` | PVR disabled; no `SECURITY.md` | PVR enabled; `SECURITY.md` (Appendix A) committed after the owner sets the response goals | Reporters disclosing in public issues; no private channel | Reports arrive as draft security advisories, visible to admins only. The owner must watch notifications. | Disable PVR; remove the file | Admin; owner decision on response goals | **Enable PVR now; commit `SECURITY.md`** once the placeholders are filled (separate docs commit) | Pending |
| **S-7** Pin Actions to commit SHAs | tag-pinned (`actions/checkout@v4`, `actions/cache@v4`, `actions/upload-artifact@v4`); `sha_pinning_required: false` | Each `uses:` pinned to a full 40-character SHA with a `# v4.x.y` comment. Then enable the repository setting **`sha_pinning_required: true`**. Optionally restrict `allowed_actions` to GitHub-owned. | A compromised or moved upstream tag executing in CI | Updates become manual or Dependabot-driven (github-actions ecosystem). Enabling `sha_pinning_required` **before** pinning would fail every workflow run. | Revert the workflow commit; disable the setting | Workflow change, so this is **v1.0.4-beta (Phase 4)**, outside Stage 6A | **Defer** to Phase 4; then enable the setting immediately after the pinning commit passes CI | Pending |
| **S-8** Least-privilege publication credential | not least-privilege (local) | Fine-grained or minimal-scope credential for publication; sign out between releases. Made obsolete by RE-2, where CI uses only `GITHUB_TOKEN`. | Theft of a broad local token | Re-authentication before each manual release | n/a | Owner workstation | **Defer** (resolved by RE-2) | Pending |
| **S-9** Secret validity checks; CodeQL | disabled / not configured | CodeQL default setup (actions + rust); validity checks optional | Workflow injection patterns; some Rust bug classes | CodeQL adds a few minutes per PR or push and may raise false positives | Disable default setup | Admin; CodeQL for Rust availability to be confirmed | **Defer** to after S-2 | Pending |

**Ranking (risk reduction ÷ effort):**
1. S-3 (tags): one ruleset, protects the immutable baseline.
2. S-2a (force-push and deletion): zero friction.
3. S-1 (generic secrets): one toggle.
4. S-6 (PVR, then `SECURITY.md`).
5. S-5 (alerts only).
6. S-2b (required checks with bypass).
7. S-7 (Phase 4, then the setting).
8. S-4 (after RE-2).
9. S-9.
10. S-8 (resolved by RE-2).

**Emergency maintenance procedure (S-2/S-3).**
1. The owner, as Repository admin, may bypass a ruleset only to fix a broken `main` or a failed release step.
2. The bypass is visible in Rules → Insights.
3. Record each bypass in the next review report.
4. Never use a bypass to move or delete a published tag. A bad release gets a new version.

**Gate B application protocol (per approved item):**
1. Record the original value through the API.
2. Apply only that change.
3. Read it back.
4. Verify the effective rules (`GET /repos/…/rules/branches/main`, or a tag-ref check).
5. Run safe operations: a normal fast-forward push still succeeds; a `--dry-run` force push is not used. Rule enforcement is verified by reading the rules back, not by attempting to force-push.
6. Record the outcome.

Stop if release publishing or normal development is affected.

## 7. Repository security observations

- **Workflow permissions:** good. Workflow-level `permissions: contents: read`; the repository default is `read`; no secrets; no environments. The `test-infrastructure` job references `TEST_*` secrets that do not exist, so a dispatch with `infrastructure=true` would fail harmlessly.
- **Third-party Actions:** only GitHub-owned actions are used (`checkout`, `cache`, `upload-artifact`), all tag-pinned (S-7). `allowed_actions: all` permits any action. Restricting to GitHub-owned and verified creators is a low-cost follow-up to S-7.
- **Release workflow privileges:** there is no release workflow; releases are manual. The RE-2 design (Stage 5 §7) keeps `contents: write` in a single job behind a `release` environment with a required reviewer. That environment does not exist yet.
- **Cache poisoning:** caches are keyed on `Cargo.lock` and include `target/` and, for audit, the `cargo-audit` binary. Any branch push can populate caches that other branches restore. The risk is low for a solo-maintainer repository. The Phase 4 release workflow should build without restoring caches.
- **Concurrency (RE-4):** `group: ci-${{ github.ref }}` with `cancel-in-progress: true` cancelled the `main` run for `dcce21a`. Recommendation for Phase 4:
  ```yaml
  concurrency:
    group: ci-${{ github.workflow }}-${{ github.event_name == 'pull_request' && github.event.pull_request.number || github.sha }}
    cancel-in-progress: ${{ github.event_name == 'pull_request' }}
  ```
  Pull requests still cancel superseded runs. Every `main` and tag commit gets its own complete run, keyed by SHA. A release workflow should use `group: release-${{ github.ref }}` with `cancel-in-progress: false`, so that it queues and is never cancelled.
- **Dependency security:** `cargo audit` runs on every push and fails on unlisted advisories, which is good. There is no scheduled audit, so an advisory published after a release goes unseen until the next push. S-5 alerts, or a weekly `schedule:` trigger for the audit job (Phase 4), close this gap. Dependency review (`actions/dependency-review-action`) only applies to PRs and becomes useful after S-2b.
- **Secret scanning:** 0 open and 0 resolved alerts (counts only; no alert content was retrieved). Generic (AI-based) password detection is assumed to need a paid Secret Protection licence and is not expected to be available on this personal public repository; this is unverified. S-1 non-provider patterns are the meaningful increment.

## 8. Argument-injection assessment (G1)

Method: read-only code review of every `std::process::Command` site that takes user values. The only command run was one `backup create … dry_run=true` in a scratch directory, which printed the planned argv and executed nothing. The threat model is untrusted input (an AI agent, or templated script values) reaching resh arguments while the operator runs resh with privilege, often as root. **Argument injection** means an argv element is parsed as an option by the external program. **Shell-command injection** means a string reaches a shell. Crontab and unit-file injection are file-format injection.

| # | Handle / verbs | Command site | Class | `--` today | Dry run prevents execution? | Severity |
|---|---|---|---|---|---|---|
| B1 | `backup create` (tar, restic, borg, rsync): `src` | `backuph.rs` builders around lines 759–805 → `execute_backend_command` around 1535 | Argument injection → **local code execution as the invoking user (typically root)** | No | Yes (returns before spawning); no validation runs first | **High** |
| B2 | `backup restore`: restic `snapshot_id`, rsync `dest` | `build_restic_restore` around 817, rsync restore around 852 | Argument injection (restic: code execution; rsync: arbitrary file write) | No | Refused (dry run unsupported) | **High** (restic) |
| B3 | `backup list/verify/prune`: borg `repo_url` | `borg_repo` around 689; builders around 813–895 | Argument injection (code execution only via an ssh remote) | No | **No for `prune`**: `dry_run=true` passes the backend's own `--dry-run` but still spawns borg or restic (around 2240–2249) | Medium |
| C1 | `cron add`, cron backend: `id`, `description`, `user` (system scope) | `build_cron_lines` around 3381; written by `crontab -u U -` or a system file | Crontab-file injection via newline → **root code execution with scope=system** | n/a | Yes | **High** |
| C2 | `cron add`, systemd backend: `unit_name`/`id`, description, service_user, working_dir, env | Unit path around 3700; content around 3538–3590; `systemctl enable --now` around 2586 | Unit-file directive injection (newline), path traversal (`../`), weak systemctl option injection | No | Yes | **High** (system scope) |
| S1 | `ssh exec`: `command_args`, `cwd` (cmd/PowerShell modes) | `sshh.rs` command builder around 5260–5330 | **Remote shell-command injection**: arguments are quoted only when they contain a space or quote, so command separators and command substitution in a space-free argument pass through. No local option injection, because `--` precedes `user@host`. | Yes (host) | Yes | Medium (no local privilege boundary crossed) |
| U1 | `user add`: `primary_group` | `create_group` → `groupadd -g <gid> <pg>` (`userh.rs` around 1866) | Argument injection without an execution path: a single element cannot be both an option and the group name, so groupadd fails with a usage error | No | Yes | Low |
| O1 | `fs mount`: `source`, `target` | `fsh.rs` around 2283–2303 | Argument injection | No | Yes | Low (the verb already accepts arbitrary `type`/`options`, which is root-equivalent) |

**Vector classes.** Each of tar, restic, borg and rsync has long options that run a command, or that write to a file named in the option. Any of them supplied as a positional value reaches the tool as an option. For cron, a newline in a metadata field followed by a complete crontab line becomes a second job. Specific payloads are deliberately omitted from this public report until v1.0.4-beta ships. They are recorded only in the owner's private notes or a draft security advisory.

`exclude`, `include`, `tag` and `label` are safe because each follows a flag that consumes it. restic `repo_url` is passed through the environment. `svc` (validated name), `log`, `firewall`, `net`, `system`, `pkg` and the plugin engine's `pgrep` were checked and found safe.

**Policy and dry-run effectiveness.** Dry run blocks execution for every site except **B3 `prune`**, where "dry run" delegates to the backend's own dry-run flag. A hostile `repo_url` is therefore executed even under `dry_run=true`. No site validates hostile values **before** the dry-run return, so a dry run reports success on input that the real run would turn into an injection. Phase 1 must validate first.

**Severity rationale.** Nothing is rated Critical. Every High needs an operator to route untrusted input into a specific field of a privileged verb, and resh exposes no network surface. Under the agent-driven threat model this routing is plausible, so B1, B2 (restic) and C1/C2 sit at the upper end of High.

**Required fixes (Phase 1).** A validation helper should reject a leading `-`, NUL, `\n` and `\r` in every positional or identifier value. Insert `--` before positionals for tar, restic, borg, rsync, groupadd and mount, all of which accept it. Validate `primary_group` with the existing `validate_group_name`. Use an allowlist `[A-Za-z0-9_.@-]` for unit names, with no leading `-` and no `/`. Reject newlines in every cron and unit field. Always `shell_escape` ssh arguments in None/Sh/Bash modes, and add quoting for cmd/PowerShell or refuse those modes for untrusted input. Make `prune dry_run=true` plan-only, or document it explicitly as "backend dry run" and validate before spawning. The argv-array API is already in use (`CmdSpec`, `Command::args`); no site needs a shell removed locally.

**Regression tests (reuse existing patterns):**
- backup: a hostile-value table through the `dry_run=true` `call()` helper and the builder tests, asserting `INVALID_ARGS` and that no spec is built;
- user: `SystemUserBackend::recording()` with the refusing `cfg(test)` executor;
- cron: validation placed before backend dispatch and tested through `dry_run=true`, plus `build_cron_lines` and `build_service_unit` directly;
- ssh: `build_command` unit tests and the `MOCK_SSH` runner, asserting single-quoted metacharacters;
- CLI level: the `pkgh` `cmdline_safety_tests` hostile-plus-sentinel pattern and the `stage4_regressions.rs` temp-HOME harness.

Line numbers are approximate, from the current tree.

## 9. Exit-code correctness assessment (G2)

**Current mechanism.** `main.rs` converts a handle's `Status` to the process exit code. `Status::exit_code` never returns 0 for a failure (`core::status` test `exit_code_is_nonzero_for_every_failure`). A dispatch `Err` exits 1, and clap errors and a missing stage exit 2. Defects therefore occur only where a handler returns `Status::ok()` for an unsuccessful operation, or where the help path bypasses dispatch.

**Reproduced in isolation** (scratch directory; local `python -m http.server` on 127.0.0.1; current-tree debug build):

| Case | Exit | Correct? |
|---|---|---|
| No stage | 2 | yes |
| Unknown CLI flag (clap) | 2 | yes |
| Unknown scheme | 1 | yes |
| Unknown verb (`file://./x.bogusverb`) | 1, lists valid verbs | yes |
| **`resh file bogusverb --help`** | **0**, prints top-level help | **no** (FUN-3) |
| **`resh nosuchhandle --help`** | **0**, prints top-level help | **no** (FUN-3, wider than recorded) |
| Missing file (`file read`) | 1 | yes |
| **Unknown option key (`bogus_option=1`, `format=nonsense`)** | **0**, option ignored | **no** (new: N-2) |
| `dry_run` on a verb without dry-run support | 2, "nothing was done" | yes |
| Misspelled `dry_run` (`dryrun`, `dry-run`, `dry_run=ture`) on `file delete` | 2, file kept | yes (fails closed) |
| Missing required parameter (`archive extract`) | 1 | yes |
| Service not found (`svc status`) | 1 | yes |
| **`http …head` on HTTP 404** | **0** | **no** (FUN-1) |
| **`http …json` on HTTP 404** | **0** | **no** (FUN-1) |
| `http …get` on HTTP 404 | 1 | yes |
| Connection refused (`http get`) | 1 | yes |
| `cert sign` with a missing key or missing data (JSON `ok:false`) | 1 | yes |
| `net ping` unreachable host | not re-tested (needs external packets); FUN-1 records exit 0 | (no) |

There is no separate policy-denial layer in `core`. "Policy" refusals are the dry-run refusals above and the per-handle validation errors, which exit non-zero. Partial failures (multi-item operations) were not exercised. They should be part of the Phase 2 test inventory.

**Proposed exit-code contract (v1.0.4-beta):**

| Code | Meaning | Notes |
|---|---|---|
| 0 | The requested operation succeeded completely. For queries, the query ran, even if the answer is "false" (for example `exists` → `false`). | `--help` exits 0 only for a known handle or verb |
| 1 | The operation ran and failed: provider error, subprocess non-zero, remote error (HTTP ≥ 400 for `head`/`json`/`get` alike; ping with no replies), timeout | The JSON envelope has `ok: false` with an error code |
| 2 | Usage error, nothing attempted: CLI parse error, unknown handle or verb (including with `--help`), invalid or unknown option, unsupported `dry_run`, validation refusal | Existing behaviour for clap and dry-run refusals |
| 3 | Partial failure: some items succeeded | Only for multi-item verbs; the envelope lists per-item results |
| other 1–255 | Handler-specific codes already documented (passed through by `Status::exit_code`) | Preserved |

**Compatibility:**
- FUN-1 (HTTP status) is a documented breaking change. Offer `allow_http_error=true` to restore exit 0.
- Unknown-option rejection (N-2) can break scripts that pass extra keys. Introduce it as a warning on stderr in v1.0.4-beta and make it an error in the next minor release, or gate it on a `strict` flag.

## 10. Minor functional defects (G3) and v1.0.4-beta plan

### G3 inventory

| Item | Verified pointer | Regression test |
|---|---|---|
| Unknown-verb or unknown-handle help fallback (FUN-3) | `main.rs`: `core::help::render` returns `None` → falls through to clap → top-level help, exit 0 | `tests/help_cli.rs`: unknown verb + `--help` and unknown handle + `--help` → exit 2; stderr names the token and lists valid verbs or handles |
| Archive backup suffix (COS-1) | `archiveh.rs` add paths use `with_extension(format!(…))` (around 5174, 5453); removal uses `format!("{}{}", archive, suffix)` (around 7247) | Table test: {add-tar, add-zip, remove, file replace} × {`.bak`, `bak`, `~`} → document and assert one rule |
| Compiler warnings (LINT-3) | 285 lib / 419 bin (Stage 5 count) | Existing suite; deny new warnings by baseline |
| Five blocking clippy diagnostics (LINT-1) | four `assert!(latency >= 0)` on unsigned values in `src/handles/data/dbh.rs` tests (lines 7725, 7757, 7804, 7853); one unreachable `else if` in `src/handles/network/mailh.rs` (Stage 5 cited line 1175; the code has since shifted, so re-locate it with `cargo clippy --all-targets`) | `cargo clippy --locked --all-targets` completes and reaches every target |

### Phased plan (no phase starts in Stage 6A)

Each phase has its own stop gate: owner approval to start, and owner review of the phase report before the next one begins.

**Phase 1: Security remediation (SEC-1 and the verified G1 findings).**
- Work:
  - argv-only external commands (no `sh -c` built from user values);
  - `--` before positional user values where the tool supports it;
  - reject a leading `-`, NUL or newline in identifiers (users, groups, units, repositories, paths passed as options);
  - strict cron field grammar;
  - quote or refuse ssh remote commands.
- Acceptance:
  - each G1 site has a negative test using the existing `cfg(test)` command stubs;
  - validation runs **before** the dry-run return, so `dry_run=true` with a hostile value also fails with exit 2;
  - `stage4_regressions` and the CI security subset are extended;
  - no behaviour change for valid input (full suite green).
- Stop if any fix needs a new dependency or changes a documented valid input.

**Phase 2: Automation correctness (FUN-1, FUN-3, N-2, FUN-2, FUN-4).**
- Work: implement the section 9 contract.
- Acceptance:
  - a CLI-level integration test file asserts exit codes for every row of the section 9 table, using local mock servers (`httpmock`, already a dev-dependency) and a closed local port;
  - the CHANGELOG lists the breaking changes;
  - help-sweep behaviour is unchanged for valid verbs (239/239).
- Stop if a contract change breaks the documented examples' tests.

**Phase 3: Linux compatibility (COMPAT-1), prototype only.**
- Work:
  - build in a disposable `almalinux:8` container with `git2/vendored-openssl` + `openssl/vendored`, on a branch;
  - check the trust store with a custom-CA TLS fetch per distro;
  - check NSS/SSSD account lookups (`user`/`proc` owner names) on EL8/EL9.
- Acceptance:
  - ABI gate GLIBC ≤ 2.28, with no `libssl`/`libcrypto` in NEEDED;
  - smoke matrix green on Rocky/Alma 8 and 9, Ubuntu 22.04, Debian 12 (slim) and Ubuntu 24.04;
  - TLS check passes;
  - size and startup within an agreed budget.
- Stop before merging: vendoring adds feature flags, which needs explicit approval because it changes the dependency build.

**Phase 4: Release engineering (RE-1, RE-2, RE-4, S-7, then S-4).**
- Work:
  - SHA-pin actions and enable `sha_pinning_required`;
  - the concurrency change (section 7);
  - a scheduled weekly audit;
  - `release.yml` per the Stage 5 §7 design: clean tagged build, `--remap-path-prefix` and `-ffile-prefix-map`, privacy scan, ABI gate, `SHA256SUMS`, `attest-build-provenance`, optional signing, and a `release` environment with a required reviewer that creates a **draft**.
- Acceptance:
  - a dry run on a throwaway pre-release tag produces an artifact that `gh attestation verify` accepts;
  - the draft needs manual publication;
  - two quick `main` pushes both complete CI.
- Then decide S-4.
- Stop if the workflow needs any secret beyond `GITHUB_TOKEN`.

## 11. Open risks

| ID | Risk | Severity | Disposition |
|---|---|---|---|
| R-1 | RUSTSEC-2026-0387 reaches **`cert sign` ECDSA signing**, a wider surface than Gate D stated. Automation that signs attacker-submitted data repeatedly with one key on a shared host is a local timing oracle. | Low–Medium (unchanged; local co-resident attacker only) | Remains accepted. Recommend the owner decide whether DEP-1 (p256/p384 0.14) moves from v1.1.0-beta into v1.0.4-beta. Interim: document in `known_issues.md` that `cert sign` with ECDSA keys should not be exposed as a service on shared hosts. |
| R-2 | Unknown option keys are silently ignored (N-2). A misspelled safety option other than `dry_run`, such as `overwrite`, `backup`, `timeout_ms` or `recursive`, falls back to its default without warning. | Low–Medium for automation | Phase 2 |
| R-3 | No branch or tag protection: a mistaken force push or tag move is currently possible | Medium | S-2a, S-3 (Gate B) |
| R-4 | Dependabot alerts will surface up to 23 accepted advisories as open alerts, which is triage noise | Low | Dismiss each with a reason that references `audit.toml` |
| R-5 | Historical credential in pre-1.0.3 history and tags (rotation owner-reported, not independently verified) | Low (residual) | Accepted in Stage 5; optional access-log review |
| R-6 | Option and file-format injection: backup argv (B1/B2), cron/systemd fields (C1/C2), ssh remote quoting (S1) | High (B1, B2, C1, C2); Medium (B3, S1) | Phase 1. Interim: add `known_issues.md` guidance not to pass untrusted values to `backup` or `cron add` (needs a docs commit) |
| R-7 | `backup prune dry_run=true` spawns the backend, which is inconsistent with resh's dry-run guarantee elsewhere | Medium | Phase 1 |

## 12. Approval requests

**Gate A (documentation):** approve committing the files in section 5 to `main` as `docs: close resh v1.0.3-beta post-release findings`, with a normal push and CI verification. Also confirm:
- (a) the DOC-1B correction direction: Gate D corrected, and the `audit.toml` comment refined rather than having "signing" removed;
- (b) whether this Stage 6A report is included in the same commit.

**Gate B (repository settings):** each item is approved separately. These are the candidates:
1. S-3 tag ruleset `v*`
2. S-2a `main`: block force-push and deletion
3. S-2b `main`: required checks + PR, admin bypass
4. S-1 non-provider patterns
5. S-6 private vulnerability reporting
6. S-5 Dependabot alerts (no security-update PRs)

S-4, S-7, S-8 and S-9 are recommended for deferral.

**Owner decisions:**
- `SECURITY.md` response goals and supported-version policy (Appendix A placeholders);
- whether DEP-1 moves into v1.0.4-beta (R-1);
- start of v1.0.4-beta Phase 1 (a separate authorization).

## 13. Recommended next action

1. Approve Gate A, so CI verifies the documentation commit.
2. Approve S-3 and S-2a, which have zero workflow friction, then S-1, S-6 and S-5.
3. Fill in the `SECURITY.md` response goals for a follow-up docs commit.
4. Authorize Phase 1 (security remediation) as the first v1.0.4-beta work item.

## Appendix A: Proposed `SECURITY.md` (not committed)

```markdown
# Security Policy

## Supported versions

resh is beta software. Security fixes are made only in the latest published
release. Older releases do not receive fixes; upgrade to the latest release.

| Version | Supported |
|---|---|
| Latest `v1.0.x-beta` release | Yes |
| Earlier releases | No |

## Reporting a vulnerability

Please do **not** open a public issue, discussion or pull request for a
security problem.

Report it privately through GitHub: open the repository's **Security** tab
and choose **Report a vulnerability**. If that is not available, email the
maintainer at the address listed in `Cargo.toml` (`authors`) with
"resh security" in the subject.

Include the resh version (`resh --version`), the handle and verb involved, the
exact command or input, what happened and what you expected, and whether the
issue needs particular privileges (for example running as root).

Please do not include real credentials or data from production systems.

## What to expect

These are goals, not guarantees. resh is maintained by a single maintainer.

- Acknowledgement of your report: goal of <OWNER TO CONFIRM> business days.
- Initial assessment: goal of <OWNER TO CONFIRM>.
- Status updates while a fix is prepared.

## Coordinated disclosure

Please give the maintainer a reasonable chance to release a fix before you
disclose details publicly. We will agree a disclosure date with you; the
default goal is <OWNER TO CONFIRM> days after the report, or the release of a
fix if sooner. Reporters are credited in the release notes and advisory
unless they prefer otherwise.

## Scope

In scope: the `resh` binary and the source in this repository. Out of scope:
vulnerabilities in third-party services that resh connects to, and issues that
need an attacker who can already run commands as the operator. Known accepted
risks are listed in `docs/known_issues.md`, and accepted dependency advisories
are listed in `.cargo/audit.toml`.
```

The "Report a vulnerability" instruction only works once S-6 enables private vulnerability reporting. Until then, the `Cargo.toml` author address is the only verified contact. It is already public, so no address is invented.
