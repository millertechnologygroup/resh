# resh — Stage 5: Post-Release Repository Maintenance

Date: 2026-10-26
Release: `v1.0.3-beta` (tag object `d42f7b6`, commit `dcce21ad0dbb749d2172a57c25841bb253a7bbd7`)
Classification: **COMPLETE**

Published with the Stage 6A documentation commit. Sensitive details were removed before publication (see `resh-cli-stage6a-security-and-documentation.md`), and two statements are corrected below.

## 1. Executive summary

- The published prerelease `v1.0.3-beta` is intact. Its tag, commit, assets and asset digests are unchanged. An unauthenticated re-download matches SHA-256 `3838022fa6fa45a64b48c8fe7cb89d28dae2eae3ff0b1df09babfee1e47175dd`.
- `main` was fast-forwarded from `9d46f4b` to the release commit `dcce21a` (8 commits). The push was normal, with no force and no history change.
- The three release-evidence reports were reviewed, sanitized and committed to `main` as `facd6aa` (documentation only, 3 files). CI on `facd6aa`: **success**: build-msrv, test-msrv, test-stable, test-security-regression, fmt and audit passed; clippy failed as an advisory check (pre-existing); test-infrastructure skipped (manual dispatch only).
- **Historical credential:**
  - The old database password and host are absent from `main`, from the release tree, from the published archive and from every report.
  - They remain in history and in tags `v1.0.0-beta` to `v1.0.2-beta`.
  - The owner reports that the credential was rotated or revoked. No history rewrite was performed or is recommended.
- GitHub secret scanning and push protection are already enabled, with no alerts ever raised. Non-provider-pattern scanning, which is designed to detect generic credentials such as this DSN, is disabled. Several other repository hardening settings are also off (section 6). No settings were changed.
- **Recommended next milestone:** v1.0.4-beta, focused on hardening and portability. It would contain:
  - the documented option-injection gaps;
  - exit-code correctness for automation;
  - an owner-gated GitHub Actions release pipeline with provenance;
  - a glibc 2.28 baseline build with vendored OpenSSL, which brings RHEL/Rocky/Alma 8 and 9, Ubuntu 22.04 and Debian 12 into scope.

## 2. Published release verification

| Check | Result |
|---|---|
| Release page | public, prerelease, not draft, `publishedAt` 2026-10-26T20:18:30Z |
| Tag | `v1.0.3-beta` → tag object `d42f7b6` → commit `dcce21a`; local and remote match. Rechecked before and after every push in this stage. |
| Assets | exactly two: the archive (17,291,346 bytes, digest `sha256:3838022f…7175dd`) and `SHA256SUMS` (103 bytes). Asset `updatedAt` timestamps are unchanged from publication (20:18:27–29Z). |
| Independent download | `gh release download` → `sha256sum -c SHA256SUMS`: OK |
| Archive scan | 0 occurrences of the historical password or host; 0 home-directory paths in the binary |
| `target_commitish: main` | GitHub metadata only. The tag already existed and has not moved, so moving `main` does not affect the release. |

## 3. Main branch alignment results

| Step | Result |
|---|---|
| Pre-check | `origin/main` = `9d46f4b`; `v1.0.3-beta..origin/main` empty; `merge-base --is-ancestor origin/main v1.0.3-beta` true |
| Diff reviewed | 8 commits, 132 files (24 A, 7 D, 101 M); the expected v1.0.2-beta and v1.0.3-beta history. Owner-approved (Gate 1). |
| Remote recheck | `origin/main` still `9d46f4b` immediately before the push |
| Push | `git push origin dcce21a:refs/heads/main`: `9d46f4b..dcce21a`, fast-forward, no force |
| Local `main` | updated with `git fetch origin main:main` (fast-forward only); working tree untouched |
| Documentation commit | `facd6aa` on `main` (Gate 2 approved): `dcce21a..facd6aa`, fast-forward, no force |
| Final refs | `main` = `origin/main` = `facd6aa9376db5c7515d0c73d9f1514285e235d9`; `help-system-and-fixes` = tag = `dcce21a` |
| CI on `dcce21a` | branch run 40379972569 and tag run 40384455996: success. The `main` run 40426480412 was **cancelled** by the workflow's `cancel-in-progress` concurrency when `facd6aa` was pushed. It was not a failure (see backlog RE-4). |
| CI on `facd6aa` | run 40426897709: **success**: build-msrv, test-msrv, test-stable, test-security-regression, fmt and audit passed; clippy failed as an advisory check (pre-existing); test-infrastructure skipped (manual dispatch only) |
| `.claude/` | never staged or modified; still untracked |

## 4. Release documentation status

Committed in `facd6aa`:
- `docs/reviews/resh-cli-v1.0.3-beta-release-gates-addendum.md` (Gate C)
- `docs/reviews/resh-cli-v1.0.3-beta-gate-d.md` (Gate D)
- `docs/reviews/resh-cli-v1.0.3-beta-publication.md` (final publication)

**Accuracy.** The reports were checked against the live release: identity, digests, CI job results, test counts (2,433 passed / 0 failed / 22 ignored, where 22 is 11 tests compiled twice) and container results. They are accurate, except for the items listed below.

**Sanitization performed before commit:**

| Item removed or generalized | Where |
|---|---|
| Home-directory paths (12) → `<release workspace>` / "the build user's home directory" | Gate D, publication |
| Build-host CPU model | Gate D |
| `gh` token scopes, keyring storage, publisher account, credential-helper and policy details | publication |
| Commit hash that introduced the credential (a direct pointer to the value) | addendum, publication |
| "Internal incident record (not for public notes)" section → public-safe summary | publication |

The final rescan found no credential parts, tokens, home paths, private hosts or DSNs, apart from the `user:pass@host` placeholder. The remaining identity string is the public author contact from `Cargo.toml`.

**Consistency of required distinctions:**

| Distinction | Status |
|---|---|
| Gate D superseded artifact vs final artifact | Explicit banner added to Gate D; the publication manifest marks `d91693b1…`/`d531fea4…` as not published |
| Actual CI results | Every report lists the per-job results; clippy is consistently marked as advisory and failing |
| Ignored integration tests | 11 (×2 targets), never counted as passing |
| Accepted advisory exceptions | Listed; **count error, see below** |
| Confirmed vs unverified runtime compatibility | Tested images are listed separately from platforms inferred from published glibc versions |

**Known inaccuracies, left as committed and recorded here instead:**
1. Gate D (D-02) says "22 ignore entries" in `.cargo/audit.toml`. The tag has **23**. All 23 are covered by the Stage 4 and v1.0.3-beta assessments.
2. The `.cargo/audit.toml` comment for RUSTSEC-2026-0387 says "key generation and signing", and Gate D said crypto-bigint performs no signing in resh. **Corrected in Stage 6A:** Gate D was wrong. `cert sign` (data mode) signs with p256/p384 and so reaches crypto-bigint; only certificates and CSRs are signed through rcgen and ring. Gate D and the comment now describe the verified usage.
3. The 43 checks (Gate D) and 45 checks (publication) differ only in how the two version checks are counted. A note was added to the publication report.

Items 1 and 2 are backlog item DOC-1.

## 5. Historical credential assessment

The credential was located by comparing `MYSQL_CONNECTION_GUIDE.md` between the previous `main` tip and the release commit. Its parts were extracted into a private, mode-0600 scratch file and searched for without being displayed. The credential was never printed or used.

| # | Check | Result |
|---|---|---|
| 1 | Absent from current `main` tip | **Confirmed.** Password and host: 0 matches at `dcce21a` and `facd6aa`, and 0 in the working tree, including all reports. |
| 2 | Remains in history and earlier tags | **Confirmed.** Present in `main`'s history and in tags `v1.0.0-beta` to `v1.0.2-beta`, as `docs/known_issues.md` already discloses. Earlier releases had no binary assets. |
| 3 | Reported revoked or rotated | **Owner-reported**, 2026-10-26. This was not independently verified, and no authentication was attempted. |
| 4 | Not in the published release | **Confirmed.** 0 matches in the downloaded, checksum-verified archive, including the binary. |
| 5 | Documentation reflects the exposure | **Confirmed.** `docs/known_issues.md` (tagged) says the value "must be treated as compromised". The release notes and reports state that it remains in history, and the reports no longer point to its location. |

**GitHub status (read-only API):**

| Setting | State |
|---|---|
| Secret scanning | enabled |
| Push protection | enabled |
| Secret scanning alerts | **none ever** (open or closed) |
| Non-provider-pattern scanning (generic passwords, DSNs, private keys) | **disabled** |
| Validity checks | disabled |

Provider patterns do not cover a bare MySQL DSN, so the absence of alerts is not evidence of absence.

**Assessment.** The value is public in history and in any clone or fork made before today. Rewriting history would break the published tags and could not recall existing copies. Rotation is the effective control. Recommendation: **accept the residual historical exposure** (already disclosed) and do not rewrite. If the owner wants additional assurance, the database's access logs since the commit date should be reviewed for use of the old account.

## 6. Repository security recommendations

No settings were changed. Each item needs owner approval.

| # | Recommendation | Current | Priority |
|---|---|---|---|
| S-1 | Enable **non-provider-pattern secret scanning** (catches generic passwords, DSNs, keys) | disabled | High |
| S-2 | Add a **branch ruleset for `main`**: block force-push and deletion; require status checks `build-msrv`, `test-msrv`, `test-stable`, `test-security-regression`, `fmt`, `audit`. Admin bypass is acceptable for a solo maintainer. | no protection, no rulesets | High |
| S-3 | Add a **tag ruleset for `v*`**: block update (move) and deletion; restrict creation to admins | none | High |
| S-4 | Enable **immutable releases**, so published assets and tags cannot be replaced. Confirm how it applies to the existing `v1.0.3-beta` before relying on it. | disabled | Medium |
| S-5 | Enable **Dependabot alerts** (complements `cargo audit`); security-update PRs optional | alerts disabled | Medium |
| S-6 | Enable **private vulnerability reporting** and add `SECURITY.md` with a disclosure contact | disabled; no `SECURITY.md` | Medium |
| S-7 | Pin GitHub Actions (`actions/checkout`, `cache`, `upload-artifact`) to commit SHAs | tag-pinned (`@v4`) | Medium |
| S-8 | Use a least-privilege credential for release publication, or sign out between releases | not least-privilege | Low |
| S-9 | Optional: secret-scanning validity checks; CodeQL code scanning (Rust supported) | disabled / none | Low |

Already good: the default workflow token is read-only, `ci.yml` declares `permissions: contents: read`, and Actions cannot approve pull requests.

## 7. Release engineering improvements (design only, not implemented)

Goal: every future release is built from a clean tagged checkout by CI, in the documented environment, with privacy and compatibility gates, checksums and provenance. A human approves before anything becomes public.

### Proposed `.github/workflows/release.yml`

```
on:   push: tags ['v*']           # plus workflow_dispatch(tag) for re-runs
permissions: {}                   # nothing by default; each job opts in

jobs:
  verify-tag      contents: read
  build           contents: read                   container: almalinux:8 (section 8)
  privacy-scan    contents: read
  smoke-matrix    contents: read                   one container per target distro
  attest          id-token: write, attestations: write
  publish-draft   contents: write   environment: release (required reviewer: owner)
```

| Element | Design |
|---|---|
| **Clean tagged source** | `actions/checkout` at `refs/tags/${tag}`, `fetch-depth: 0`. Fail unless the tag is annotated, peels to a commit reachable from `main` (`merge-base --is-ancestor`) and `Cargo.toml` version = tag. `git status --porcelain` must be empty before and after the build. |
| **Locked dependencies** | `cargo fetch --locked`, then `cargo build --release --locked --offline`. Record the `Cargo.lock` SHA-256 in the build log. Toolchain pinned by an explicit `rustup` version (for example a release `rust-toolchain.toml`) and recorded. |
| **Rust path remapping** | `RUSTFLAGS="--remap-path-prefix=$CARGO_HOME=/cargo --remap-path-prefix=$GITHUB_WORKSPACE=/build"`, the recipe already proven in the publication build |
| **C path remapping** | `CFLAGS`/`CXXFLAGS="-ffile-prefix-map=$CARGO_HOME=/cargo -ffile-prefix-map=$GITHUB_WORKSPACE=/build"`; required for libgit2, libssh2, zstd, ring and vendored OpenSSL |
| **Determinism inputs** | `SOURCE_DATE_EPOCH` = tag commit time; tar `--sort=name --owner=0 --group=0 --numeric-owner --mtime=@$SOURCE_DATE_EPOCH`; `gzip -n -9` |
| **Binary privacy scan** | Fail on: `/home/`, `/root/`, `/github/`, `/__w/`, `/runner/`, the runner hostname, `$GITHUB_WORKSPACE`. Allowlist the documented help examples (`/home/alice`, `/home/bob`). Run gitleaks (or equivalent) on the tagged tree and the archive contents. |
| **ABI gate** | `objdump -T` max `GLIBC_` ≤ 2.28; `readelf -d` NEEDED ⊆ {libc, libm, libgcc_s, ld-linux, libz, liblzma} (no `libssl`/`libcrypto` once vendored) |
| **Checksums** | `sha256sum` → `SHA256SUMS`, generated in CI and verified in a separate job after re-download of the uploaded artifact |
| **Smoke tests** | Matrix of stock images (rockylinux:8, almalinux:8, rockylinux:9, almalinux:9, ubuntu:22.04, debian:12, ubuntu:24.04, debian:13) with `--network none --read-only`, uid 65534. Run the existing harness subset: version, help sweep (29 schemes / 239 verbs), `file read`, `system info` JSON and exit codes, plus a TLS trust-store check (section 8). |
| **Provenance** | `actions/attest-build-provenance` over the archive and `SHA256SUMS` (SLSA build provenance via Sigstore, no long-lived key). Users verify with `gh attestation verify <file> --repo millertechnologygroup/resh`. |
| **Optional signing** | Sigstore keyless `cosign sign-blob --bundle` in the attest job (same OIDC identity), or minisign with a key held only in the `release` environment secrets. Provenance alone already authenticates the publisher, so signing is optional. |
| **Publication** | `publish-draft` runs only after the `release` environment's **required-reviewer approval** (the owner). It runs `gh release create --draft --verify-tag --prerelease`, attaching only the CI-built artifacts. The owner then reviews the draft and publishes it manually, so there are two human checkpoints before anything is public. |
| **Least privilege** | Only `GITHUB_TOKEN`, with no PATs. `contents: write` exists only in `publish-draft`, behind the environment. The environment is restricted to `v*` tags. Third-party actions are SHA-pinned (S-7). Tag ruleset S-3 prevents moving a released tag. |

**Rollout:** first land the workflow with `publish-draft` removed and run it on a throwaway pre-release tag. Compare its output against the manual v1.0.3-beta process, then add the gated publish job.

## 8. Enterprise Linux compatibility recommendation

### Why the current binary fails

| Target | glibc | OpenSSL 3 (`libssl.so.3`) | libz / liblzma | v1.0.3-beta binary |
|---|---|---|---|---|
| RHEL/Rocky/Alma 8 | 2.28 | **No** (OpenSSL 1.1.1 only) | yes | fails: glibc + libssl (inferred) |
| RHEL/Rocky/Alma 9 | 2.34 | yes (3.0.x) | yes | fails: glibc (**tested**, Rocky 9) |
| Ubuntu 22.04 | 2.35 | yes (3.0.2) | yes | fails: glibc (**tested**) |
| Debian 12 | 2.36 | in standard installs; **absent in slim images** | yes | fails: glibc + libssl in slim (**tested**) |
| Ubuntu 24.04 | 2.39 | yes (3.0.13) | yes | works (**tested**) |

The floor (GLIBC_2.39/2.38) comes from building on a glibc 2.43 host: `__isoc23_strtol` comes from C dependencies compiled against new headers, and the `pidfd_*` version needs come from std. Neither is required by resh's functionality.

**OpenSSL consumers** (`cargo tree -i openssl-sys`):
- `git2` → libgit2 (HTTPS) and libssh2 (crypto backend);
- `reqwest` (its default `native-tls` feature is still enabled alongside `rustls-tls`);
- `lettre` (native-tls);
- `memcache` (openssl).

### Options assessed

| Option | Assessment |
|---|---|
| **Older glibc baseline (2.28)** | Build inside an EL8 userland. Rust std and the C dependencies then link only against ≤ 2.28 symbol versions, which work forward on all five targets. **Not sufficient alone:** EL8 has no OpenSSL 3 and slim Debian 12 lacks `libssl3`, so OpenSSL must be handled separately. Kernel ABI is fine (EL8's 4.18 is above Rust's 3.2 minimum). Std falls back when `pidfd` syscalls are absent. |
| **OpenSSL compatibility** | Dynamic OpenSSL cannot cover EL8 and EL9 with one binary (1.1 vs 3 sonames). Building against 3.0 headers is fine for every OpenSSL 3 target, because the binary only needs `OPENSSL_3.0.0`. |
| **Vendored native dependencies** | `git2` feature `vendored-openssl` plus `openssl` feature `vendored` link OpenSSL 3.x statically and remove `libssl`/`libcrypto` from NEEDED. Costs: resh must rebuild and re-release for OpenSSL CVEs (`cargo audit` tracks `openssl-src`); the build needs perl (`perl-IPC-Cmd`, `perl-FindBin` on EL); the binary grows by about 5 MB. **Trust-store risk:** a vendored OpenSSL has a compiled-in cert directory. `native-tls` and `git2` use `openssl-probe` to find `/etc/pki/tls` or `/etc/ssl/certs`, but `memcache`'s direct OpenSSL use must be verified. Add a per-distro TLS verification smoke test. `libz` and `liblzma` can stay dynamic (present on every target), or be made static via `libz-sys`/`xz2` features. |
| **Rustls** | Reduces but **cannot remove** OpenSSL, because libgit2 and libssh2 on Linux require it. Worth doing separately for reqwest (`default-features = false`) and lettre (`rustls-tls`). Must use `rustls-native-certs` or a platform verifier, **not** only `webpki-roots`, so enterprise private CAs in the system store keep working. Behaviour change, needs its own tests. |
| **musl static** | One fully static binary that runs everywhere. **Not recommended as the main artifact:** musl does not use NSS, so `user`/`proc`/`file` owner lookups would not see SSSD, LDAP or AD accounts, which are common on enterprise hosts. musl's allocator is also slow under the tokio runtime, and getaddrinfo behaviour differs. It is acceptable only as an additional, clearly labelled artifact. |
| **Containerized builds** | The natural fit for a 2.28 baseline: `almalinux:8` (or `rockylinux:8`) with `gcc-toolset`, `perl` and rustup-installed pinned Rust. Official rustup toolchains need only glibc 2.17. This is deterministic and matches the target ABI exactly. |
| **Cross-compilation** | `cargo-zigbuild --target x86_64-unknown-linux-gnu.2.28` gives the same symbol floor from any host. It is generally reliable, but less proven for this exact mix (ring assembly, openssl-src `Configure`, libgit2 via `cc`). It needs its own validation. |
| **Distribution runtime differences** | These are independent of ABI and must be tested per distro: systemd 239 (EL8) vs 252–255, which affects D-Bus properties used by `svc`; `dnf` vs `apt`; firewalld/nftables (EL) vs nftables/ufw (Debian/Ubuntu); CA bundle paths; SELinux enforcing on EL. The ABI gate proves the binary *starts*, not that each handle works. |

### Recommendation

- **Primary:** a containerized native build on **AlmaLinux 8 (glibc 2.28)**, with **vendored static OpenSSL 3** (`git2/vendored-openssl` + `openssl/vendored`) and dynamic `libz`/`liblzma`/`libgcc_s`. Add the CI ABI gate (GLIBC ≤ 2.28; NEEDED allowlist without libssl) and the five-target smoke matrix, including a TLS verification check on each distro. One artifact then covers all five targets plus Debian 13 and Fedora.
- **Fallback:** `cargo-zigbuild` targeting `x86_64-unknown-linux-gnu.2.28` from a standard Ubuntu runner, with the same vendoring and the same gates. Use it if the EL8 container toolchain proves impractical (for example, if a future dependency needs a newer C compiler than gcc-toolset provides).
- **Separately (not required for compatibility):** move reqwest and lettre to rustls with native roots to shrink the OpenSSL surface. Offer musl only as an optional extra artifact with the NSS limitation documented.

**Validation before claiming support:** full harness and container matrix on all five targets; `svc`/`pkg`/`firewall` read-only verbs on each distro family; a TLS fetch with a custom CA installed in the system store; size and startup-time comparison with v1.0.3-beta.

## 9. Prioritized technical debt backlog

Effort: S ≤ 1 day, M 2–5 days, L > 1 week.

| ID | Item | Class | Severity | User impact | Effort | Regression tests | Target |
|---|---|---|---|---|---|---|---|
| SEC-1 | Option injection: backup backend argv and `user primary_group` lack `--`/leading-dash rejection; cron accepts newlines in job fields and an unrestricted `unit_name`; ssh `command_args` quoting lets shell metacharacters through (documented in `known_issues.md`) | Security-critical | **High** | Arbitrary command execution when untrusted input (for example from an AI agent or script) reaches these arguments | M | Per-site tests: leading `-` refused, newline refused, metacharacters quoted; extend `stage4_regressions` | **v1.0.4-beta** |
| SEC-2 | Plaintext local secret store; SMTP passwords base64-encoded (files are 0600) | Security-critical (documented) | Medium | Secrets readable by root/backup tools; no defence in depth | L | Encryption round-trip, file-mode, migration tests | v1.1.0-beta |
| SEC-3 | Documented local-attacker limitations: archive-extraction TOCTOU against concurrent tree changes; plugin verbs under `sudo -E`; tar/rsync repo ownership not checked | Security (documented) | Low–Medium | Only on multi-user hosts with misuse (root with another user's HOME) | M | Owner/mode check tests; `openat`-based extraction tests | v1.1.0-beta |
| DEP-1 | RUSTSEC-2026-0387 crypto-bigint timing (reachable, local only): upgrade p256/p384 to 0.14 | Security (accepted) | Low–Medium | Local co-resident timing attacker only | M | cert generate/parse/self-sign suite; P-256/P-384 interop | v1.1.0-beta |
| DEP-2 | Other accepted advisories by upgrade path: zip 0.6 → ≥ 9 (3 IDs); trust-dns → hickory (idna); rcgen 0.12/x509-parser 0.15 → current (ring 0.16); zstd → ≥ 0.14.3; quinn/h2/quick-xml/time are lockfile- or dev-only. rsa has no fix. | Security (accepted) | Low | None in supported use (not reachable) | L (staged) | Archive, DNS and cert suites; remove each `audit.toml` entry with its upgrade | v1.1.0-beta onward |
| FUN-1 | `net ping` exits 0 when the host is unreachable; `http head/headers/json` exit 0 on 4xx/5xx | Functional defect | **Medium** | Scripts and automation treat failures as success | S | Exit-code tests against a closed port and a mock 404/500 | **v1.0.4-beta** (breaking: changelog) |
| FUN-2 | `pkg`/`fs` timeouts report failure but do not kill the child process | Functional defect | Medium | Package-manager or filesystem operations continue after "timeout" | M | Timeout test kills the process group | v1.0.4-beta |
| FUN-3 | Unknown-verb help: `resh <handle> <bad-verb> --help` prints top-level help and exits 0. Cause: `core::help::render` returns `None` for an unregistered verb and `main.rs` falls through to clap. | Functional defect | Low | Typos look like success in scripts | S | `help_cli.rs`: unknown verb + `--help` → non-zero exit, stderr names the verb and lists valid verbs | **v1.0.4-beta** |
| FUN-4 | Plugin enabled state written and read from different files (`installed.list` shows enabled plugins as disabled) | Functional defect | Low | Misleading status | S | enable → list round-trip | v1.0.4-beta |
| COS-1 | Backup suffix inconsistency: `archive add` (tar `add_to_tar_archive`, zip `add_to_zip_archive`) produces `<archive>.<suffix>`, while `archive remove` (`perform_archive_removal`) and `file replace backup=` produce `<path><suffix>`. `backup_suffix=.orig` gives `arc.tar..orig`. | Cosmetic (behaviour change if fixed) | Low | Odd file names; inconsistent docs | S | Table test over add/remove/replace × suffix with and without a leading dot | v1.0.4-beta (document the chosen rule) |
| LINT-1 | Clippy deny-level errors (5): four `assert!(latency >= 0)` on unsigned values in `dbh.rs` tests; one unreachable `else if` branch in `mailh.rs:1175`. Not product defects, but they abort linting of the `lib test` target. | Cosmetic / tooling | Low | None directly; hides lints | S | `cargo clippy --all-targets` reaches all targets | v1.0.4-beta |
| LINT-2 | Clippy backlog: 1,783 distinct sites (1,412 Clippy, 371 rustc). Mostly `collapsible_if` (551) and `needless_borrows_for_generic_args` (201). After LINT-1, make clippy blocking with a baseline (`-D warnings` on new code only, or a `[lints]` table) instead of mass-fixing. | Cosmetic | Low | None | M (incremental) | Existing suite unchanged | Ongoing; no big-bang refactor |
| LINT-3 | Compiler warnings: 285 lib / 419 bin (dead code 137, unused variables 93, unused imports 72, deprecations). Remove dead code only where it is clearly unused; treat deprecations first. | Cosmetic | Low | None | M | Existing suite | Ongoing |
| COMPAT-1 | Prebuilt binary needs glibc ≥ 2.39 and OpenSSL 3, which excludes RHEL/Rocky/Alma 8 and 9, Ubuntu 22.04 and Debian 12 (section 8) | Compatibility | **High** | Most enterprise fleets must build from source | M | ABI gate + five-distro smoke matrix + TLS trust check | **v1.0.4-beta** |
| COMPAT-2 | `redis 0.25.4` future-incompatibility warning (will become a hard error in a future Rust) | Compatibility | Low–Medium | Future toolchains fail to build | S–M | Redis-backed cache/mq tests | v1.1.0-beta |
| TEST-1 | Untested infrastructure integrations: 11 ignored DB/git tests (manual dispatch only); systemd, firewall, pkg, user, cron, mount, SMTP, SSH, Redis and memcached never exercised live | Release engineering / functional risk | Medium | Defects in real environments go undetected | M–L | CI service containers for PostgreSQL, MariaDB, Redis, memcached and an SMTP sink; a privileged systemd container job for svc, cron and firewall read paths | v1.0.4-beta (DB/Redis); v1.1.0-beta (systemd/firewall) |
| RE-1 | Release artifact signing and provenance: no signature; checksum gives integrity only | Release engineering | Medium | Users cannot authenticate the publisher | S (with RE-2) | `gh attestation verify` step in the release workflow | **v1.0.4-beta** |
| RE-2 | Owner-gated GitHub Actions release workflow (section 7) | Release engineering | Medium | Manual releases are slow and error-prone (Gate D needed a rebuild) | M | Dry run on a throwaway tag; compare with the manual process | **v1.0.4-beta** |
| RE-3 | Repository settings S-1 to S-7 (section 6) | Release engineering / security | Medium | Prevents tag moves, force pushes and missed secrets | S | n/a (settings) | Now (owner approval) |
| RE-4 | `ci.yml` `cancel-in-progress: true` also cancels `main` runs, so a quick follow-up push leaves a `main` commit without a completed run (happened to `dcce21a` on `main`). Restrict cancellation to pull requests (`cancel-in-progress: ${{ github.event_name == 'pull_request' }}`). | Release engineering | Low | Gaps in `main` CI history | S | Observe two quick pushes | v1.0.4-beta |
| DOC-1 | Gate D says 22 audit exceptions (actual 23); Gate D wrongly says crypto-bigint does no signing (the `audit.toml` comment is correct, closed in Stage 6A); the `MYSQL_CONNECTION_GUIDE.md` textbook DSN (`admin`/`prod-server`/`P@ssw0rd`-style) looks like a credential to scanners | Documentation | Low | Audit trail accuracy; scanner noise | S | n/a | Next docs commit |
| DOC-2 | README/release notes must state per-distro support once COMPAT-1 lands; add `SECURITY.md` (S-6) | Documentation | Low | Clarity of support policy | S | n/a | v1.0.4-beta |

## 10. Remaining approvals and blockers

There are **no blockers**.

| # | Pending item | Needs |
|---|---|---|
| 1 | Commit this report (`docs/reviews/resh-cli-stage5-post-release-maintenance.md`) | owner approval |
| 2 | Repository settings S-1 to S-7 | owner approval for each change |
| 3 | DOC-1 corrections (Gate D count, `audit.toml` comment, example DSN) | approval of a docs-only commit |
| 4 | Start of v1.0.4-beta development (any Rust or workflow change) | separate development authorization |
| 5 | Optional: database access-log review for the rotated account | owner action |

## 11. Recommended next development milestone

**v1.0.4-beta: hardening and portability.** This keeps the scope small and user-facing. There is no broad refactor.

1. **SEC-1**: option-injection and newline hardening, with regression tests.
2. **FUN-1, FUN-3**: exit codes that automation can trust. FUN-1 is a documented breaking change.
3. **LINT-1, RE-4**: the trivial fixes that unblock full clippy coverage and reliable `main` CI.
4. **COMPAT-1**: AlmaLinux 8 baseline build with vendored OpenSSL, ABI gate, five-distro smoke matrix.
5. **RE-1, RE-2**: owner-gated release workflow with build provenance; first exercised on a throwaway tag.
6. **TEST-1 (first half)**: database and Redis service containers in CI.

These are the exit criteria for the milestone:
- all required CI jobs green;
- clippy runs to completion;
- the binary starts on all five target distributions, with the TLS check passing;
- the release is produced by the gated workflow, with an attestation that `gh attestation verify` accepts.
