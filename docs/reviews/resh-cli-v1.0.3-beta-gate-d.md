# resh v1.0.3-beta — Gate D: Release Artifact Preparation

Date: 2026-10-26
Outcome: **READY FOR PUBLICATION APPROVAL**

> **Superseded artifact.** The archive (`d91693b1…3087`) and binary (`d531fea4…`) described in this report were **never published**. They were rebuilt with build-path remapping before publication. The published artifact is `resh-v1.0.3-beta-linux-x86_64.tar.gz`, SHA-256 `3838022fa6fa45a64b48c8fe7cb89d28dae2eae3ff0b1df09babfee1e47175dd` (binary `38740f05…1edb`). See `resh-cli-v1.0.3-beta-publication.md`. The tests, behaviour checks and container results below were repeated on the final binary with identical results.

At the time of this gate, nothing had been uploaded, published, committed, pushed, merged or tagged, and this report was untracked. Local paths have been generalized for publication.

## Executive summary

The official Linux x86_64 artifact was built from a fresh clone of the GitHub repository at `refs/tags/v1.0.3-beta`, in a directory separate from the development working tree. It was built with `cargo build --release --locked` into a clean target directory.

All identity checks pass. On the tagged source, the full test suite passes with 2,433 passed, 0 failed and 22 ignored. The release binary passes these checks:
- a help sweep of all 29 schemes and 239 verbs (268 of 268);
- 43 behavioural and security checks;
- clean-container runs on Ubuntu 24.04, Debian 13 and Fedora 40.

A second clean build on the same host produced a byte-identical binary. The archive was packaged deterministically, checked against the tag and build output, and given a SHA-256 checksum.

The one reachable advisory, RUSTSEC-2026-0387 in crypto-bigint, was re-assessed against the code. resh's real exposure is narrower than earlier reports stated: crypto-bigint does **no ECDSA signing** in resh. It is **not a release blocker**.

There are no blockers. The only gate not passed is the owner's publication approval, which is PENDING.

| Item | Value |
|---|---|
| Artifact | `resh-v1.0.3-beta-linux-x86_64.tar.gz` |
| Size | 17,291,837 bytes |
| SHA-256 | `d91693b151ccccb860dfaf3accf698b936131fb5d8d320a24d6e86299bdb3087` |
| Binary SHA-256 | `d531fea4bf69448e423b7bf32a9a31bb22a60f4ffb627787e2f0652583a41880` (51,150,512 bytes) |

## D-01 Tag and commit identity

| Check | Evidence | Result |
|---|---|---|
| Annotated tag exists locally | `git cat-file -t v1.0.3-beta` → `tag` | PASS |
| Tag exists remotely | `git ls-remote origin refs/tags/v1.0.3-beta*` | PASS |
| Local = remote tag object | both `d42f7b6cf92530bb936022f1b7cb961ba1ce8665` | PASS |
| Tag → approved commit | `v1.0.3-beta^{}` = `dcce21ad0dbb749d2172a57c25841bb253a7bbd7`, local and remote | PASS |
| Tag CI tested this commit | run 40384455996 `head_sha` = `dcce21ad…`, ref `v1.0.3-beta`, event `push` | PASS |
| Tag unchanged | identical to Gate C record, rechecked at the end of Gate D | PASS |
| `v1.0.2-beta` unchanged | `62043aaf…` → `971b0d50…` (local and remote) | PASS |
| No modifications needed to build | clean clone: `git status --porcelain` empty before and after build and tests | PASS |

The tag is annotated but not GPG-signed (`git verify-tag`: no signature found). The tagger is Scott Miller, and the message is "Resource Shell v1.0.3-beta — security and functional stabilization release".

Repository: `https://github.com/millertechnologygroup/resh`

## CI evidence

Tag CI run `40384455996` (workflow `CI`, `.github/workflows/ci.yml`) completed 2026-10-26 19:11–19:28Z with conclusion **success**. The job list was verified through the public GitHub REST API.

| Job | Result |
|---|---|
| build-msrv (Rust 1.88: locked build, all targets and release) | success |
| test-msrv (`cargo test --locked --no-fail-fast`) | success |
| test-stable (Rust 1.98.1) | success |
| test-security-regression (CI security subset and `stage4_regressions`) | success |
| fmt | success |
| audit (`cargo audit`, cargo-audit 0.22.2) | success |
| clippy | failure, advisory (`continue-on-error: true`; pre-existing lint baseline) |
| test-infrastructure | skipped (manual dispatch only) |

The advisory database (`rustsec/advisory-db`) has had no commits since 2026-10-26 19:00Z (checked through the GitHub API), so the tag CI audit result is still current. `cargo-audit` is not installed on the build host and was not installed, because that would need approval.

## D-02 Security release review

### Credential

The project owner confirmed on 2026-10-26 that the MySQL credential formerly in `MYSQL_CONNECTION_GUIDE.md` was rotated or revoked. This is recorded in the Gate C addendum. No replacement was requested, no authentication was attempted and no historical value is reproduced here.

The credential remains in the history of `main` and of the tags `v1.0.0-beta`, `v1.0.1-beta` and `v1.0.2-beta`. The release notes disclose this without details.

### Release-tree secret scan (clean clone at the tag)

| Scan | Finding | Disposition |
|---|---|---|
| PEM private-key headers | 18 hits, all in `src/handles/security/certh.rs` | Header literals used by the key parser, plus fixtures inside `#[cfg(test)] mod tests` (line 10539 to the end of the file) whose bodies are literally `dummydata` / `dummyEncryptedDataHere`. They are not compiled into the release binary. |
| Cloud/API token shapes (AWS, GitHub, Slack, Stripe, Google) | none | — |
| DSNs with inline passwords | 1, `MYSQL_CONNECTION_GUIDE.md:119` | A generic textbook example: user `admin`, host `prod-server`, a stock "P@ssw0rd"-style password. It has been present since the guide was created and was not part of the exposed credential, which RB-4 replaced. It is not a live credential. **Hygiene note:** it resembles a real credential and may trigger secret scanners, so consider a placeholder in a later docs change. |
| RFC 1918 addresses | firewall CIDR examples (`10.0.0.0/8`, `192.168.1.0/24`), a Windows version string | Not sensitive |
| Sensitive files (`.env`, `*.pem`, `*.key`, `*.sqlite`, `*.db`, `id_rsa`, `*.p12`) | none tracked | — |
| Release binary | 3 private-key header strings | Parser literals, including libssh2's `BEGIN OPENSSH PRIVATE KEY`. No key bodies follow them. |

**Result: no known live credentials or private keys in the release tree, the binary or the archive.**

### Advisory exceptions

There are 22 ignore entries in `.cargo/audit.toml` at the tag. The Stage 4 entries and the four zstd entries keep the dispositions recorded in earlier gates, and the tag CI audit passed with this list. The reachable advisory was re-assessed from the code instead of relying on the earlier "low risk" label:

#### RUSTSEC-2026-0387: crypto-bigint timing variability

| Item | Finding |
|---|---|
| Advisory | RUSTSEC-2026-0387, published 2026-10-23, category `crypto-failure`. Branches that depend on secret values in subtraction, zero counting, division and Montgomery multiplication, plus early-exit `UintRef` equality and `BoxedMontyForm::invert`. Patched in `>= 0.7.6`. |
| Affected crate | `crypto-bigint 0.5.5` (Cargo.lock) |
| Dependency path | `resh → p256 0.13.2 / p384 0.13.1 → (ecdsa 0.16.9, primeorder 0.13.6) → elliptic-curve 0.13.8 → crypto-bigint 0.5.5`. `cargo tree -i p256` shows **resh is the only dependent** of p256 and p384. |
| Resh operations that invoke it | Only `cert` (`src/handles/security/certh.rs`): (1) `generate_ecdsa_key`, `SigningKey::random` for new P-256/P-384 keys (`generate`, `renew key_strategy=rekey`, `csr.create key_strategy=generate`); (2) `SigningKey::from_bytes` / `from_pkcs8_der` / `from_pkcs8_pem` / `from_sec1_der` and `to_pkcs8_der` / `to_sec1_der`, which parse and re-encode a local ECDSA key and derive its public point by scalar multiplication. |
| **Correction to earlier reports** | Earlier reports said "key generation **and signing**". In fact **all ECDSA signatures are made by `rcgen 0.12` with the `ring` backend**. Keys are converted to an `rcgen::KeyPair` (ring `EcdsaKeyPair`) before certificates and CSRs are signed, and rcgen does not depend on p256 or p384. **crypto-bigint never runs a signature in resh.** |
| Secret-dependent? | Yes. The ECDSA private scalar is processed during generation, parsing and public-key derivation. |
| Can an attacker influence the inputs? | No. The scalar comes from the OS RNG (`rand::thread_rng`) or from a key file the operator names. resh exposes no network service, daemon or API, and it does not process attacker-supplied ECDSA keys on anyone else's behalf. |
| Are timing observations realistic? | Only to a co-resident local attacker measuring timing or microarchitectural effects during a short-lived CLI run. Each new key is handled a few times in one process, and an existing key once per invocation. There is no oracle that lets an attacker trigger thousands of operations on one key. Published exploitation of this kind of leak needs many observations under attacker control. |
| Conclusion | **Acceptable for this beta.** There is no credible path to expose a secret under supported deployment, which is an operator running a local CLI. Residual risk: an attacker who already has local code execution on a shared host and can watch repeated key operations. That is a weaker position than simply reading the key file, which resh creates with mode 0600. The fix (p256/p384 0.14 → crypto-bigint 0.7.6) is a major upgrade for a later release. **Not a release blocker.** |

## D-03 Build environment and clean build

| Item | Value |
|---|---|
| Source | `git clone --no-local https://github.com/millertechnologygroup/resh.git`, then `git checkout refs/tags/v1.0.3-beta`. HEAD verified as `dcce21ad…` before compiling. |
| Location | `<release workspace>/src`, a dedicated directory separate from the development tree |
| Command | `CARGO_TARGET_DIR=…/resh-release-v1.0.3-beta/target cargo build --release --locked` (new, empty target directory) |
| Environment | No `RUSTFLAGS`, `CARGO_*` or `RUSTC*` overrides. No user or project `.cargo/config.toml` (the project `.cargo/` holds only `audit.toml`). |
| Build host | Gentoo Linux, kernel 6.18.35, x86_64; glibc 2.43; GCC 16.2.1 (C dependencies); OpenSSL 3.5.8 |
| rustc | 1.98.1 (48a229cea 2026-09-01), LLVM 22.1.8 |
| cargo | 1.98.1 (797e8a9bc 2026-08-05) |
| Target triple | `x86_64-unknown-linux-gnu` |
| Package version | `resh 1.0.3-beta`, `rust-version = "1.88"` |
| Cargo.lock SHA-256 | `3c7948721d141b486536ca3b8db6ff9b78cde728ea1a3acf3b5893c191cffaa4` |
| Result | exit 0, `Finished release profile [optimized]` in 1m 43s |
| Warnings | 285 for the lib target; 419 for the bin target, of which 283 duplicate the lib warnings. All are existing unused-code and deprecation lint debt. There are no errors. One future-incompatibility notice applies to dependency `redis v0.25.4`. |
| Source tree after build | unmodified |

**Same-host determinism.** A second build into another new target directory (`target-rebuild`) produced the identical binary SHA-256 `d531fea4…`. This shows determinism for the same host, path and toolchain. It is **not** a claim of byte-for-byte reproducibility across environments: the binary embeds absolute build paths (see Observations).

## D-04 Release binary verification

All checks ran against the frozen release binary (`validated/resh`, SHA-256 `d531fea4…`). Each run used a temporary directory with `HOME` and `XDG_*` redirected into it. Nothing ran as root, and no destructive operation touched the host.

### Version and help

| Command | Expected | Actual | Exit | Result |
|---|---|---|---|---|
| `resh --version` / `resh -V` | `resh 1.0.3-beta` | `resh 1.0.3-beta` | 0 | PASS |
| `resh --help` | usage text | usage text | 0 | PASS |
| `resh --list-schemas` | 28 handles | 29 schemes: the 28 handles plus `https`, which shares the http handle | 0 | PASS |
| `resh <h> --help` for every scheme | `Available Verbs:` section | 29/29 | 0 | PASS |
| `resh <h> <verb> --help` for every listed verb | help text, no error | 239/239 | 0 | PASS |

The help sweep made 268 checks, with 268 PASS and 0 FAIL.

### Behaviour and security corrections (43 checks)

| ID | Check | Expected | Exit | Result |
|---|---|---|---|---|
| U1–U3 | `file://./a.txt.read`, absolute path, multi-dot filename | contents printed | 0 | PASS |
| U4 | `svc://--help` (in-URL help) | svc help | 0 | PASS |
| E1 | `resh` (no stage) | exit 2 | 2 | PASS |
| E2–E5 | unparseable stage, unknown scheme, unknown verb, missing file | non-zero and stderr reason | 1 | PASS |
| E6 | unknown CLI flag | non-zero | 2 | PASS |
| J1–J2 | `--json-pretty system://.info`, `fs://local.usage` | valid JSON | 0 | PASS |
| J3 | `file replace … dry_run=true` with JSON | `"dry_run": true`, file unchanged | 0 | PASS |
| R1–R2 | `proc://<own pid>.nice.get`, scoped `system://.info` | read-only success | 0 | PASS |
| D1 | `file delete dry_run=true` (verb has no dry-run mode) | refused, file kept | 2 | PASS |
| D2 | `dry_run=maybe` | error, file unchanged | 2 | PASS |
| D3–D4 | stray bare word, misspelled `dryrun=` | error, file kept | 2 | PASS |
| D5 | `backup restore dry_run=true` | refused, nothing restored | 2 | PASS |
| D6 | `mail send dry_run=true` (pointed at a closed local port) | refused | 2 | PASS |
| S-ARC ×4 | extract tar with `../` entry, absolute path, symlink escape, hard link to `/etc/hostname` | refused, nothing written outside destination | 1 | PASS |
| S-ZIP | zip create `password=` | refused, no archive | 1 | PASS |
| S-PLG1 | plugin `registry=http://…` | refused, mentions HTTPS | 1 | PASS |
| S-PLG2 | plugin id `../evil` | refused | 1 | PASS |
| S-PID | `proc://4294967295.nice.get` (read-only verb; `kill` deliberately not run) | refused | 1 | PASS |
| S-PKG1–2 | package name `jq;id`, name `-oAPT::…` (option injection), `dry_run` | refused | 1 | PASS |
| S-BK1–3 | tar, rsync and borg `create dry_run=true` without `repo_url` | `INVALID_ARGS` | 1 | PASS |
| S-BK4 | tar `create dry_run=true` with `repo_url` | plan only, repository empty | 0 | PASS |
| S-GIT | git `clone timeout_ms=1000` | refused | 2 | PASS |
| S-CRT1 | `cert generate mode=key algorithm=ecdsa` | key created with mode 0600 | 0 | PASS |
| S-CRT2 | regenerate over an existing key | refused, key unchanged | 1 | PASS |
| S-CRT3 | key path is a symlink, `overwrite=true` | refused, target unchanged | 2 | PASS |
| S-CRT4–5 | P-384 key; ECDSA self-signed certificate | success | 0 | PASS |
| S-BKL1 | `file replace backup=.bak` with a symlink planted at `f.txt.bak` | refused, target unchanged | 1 | PASS |
| S-BKL2 | `archive add backup_suffix=` with a symlink planted at the backup name | refused (`archive.add_archive_write_error: Failed to create backup`); target and archive unchanged | 1 | PASS (re-run, see note) |

Note on S-BKL2: the first run failed **because of a mistake in the test harness**. The symlink was planted at `arc.tar.orig`, but `archive add` builds the backup name as `<archive>.<suffix>`, so `backup_suffix=.orig` wrote `arc.tar..orig`, and the symlink target was never involved. With the symlink at the real backup name, resh refused the operation as expected. No product defect was found.

The Stages 1–4 corrections and the four v1.0.3-beta blocker fixes were exercised directly against the binary:
- RB-1 key mode 0600: S-CRT1–3.
- RB-2 backup symlink: S-BKL1–2.
- RB-3 `repo_url` requirement: S-BK1–4.
- RB-4 is a documentation fix, checked under D-02.

### Automated tests (tagged clean clone)

Command: `CARGO_TARGET_DIR=…/target-test cargo test --workspace --locked --no-fail-fast`, exit 0.

| Suite | Passed | Failed | Ignored |
|---|---|---|---|
| lib unit tests | 1199 | 0 | 11 |
| bin unit tests | 1203 | 0 | 11 |
| `tests/doc_examples.rs` | 2 | 0 | 0 |
| `tests/help_cli.rs` | 16 | 0 | 0 |
| `tests/help_coverage.rs` | 2 | 0 | 0 |
| `tests/stage4_regressions.rs` | 11 | 0 | 0 |
| doctests | 0 | 0 | 0 |

The 11 ignored tests (each counted twice above) are **not counted as passing**. They are 8 MySQL/PostgreSQL integration tests that need disposable servers and 3 git HTTPS tests that need real remotes, one of which pushes. They were skipped by design. The CI security-regression subset is included in this run, and it also passed separately in tag CI.

### Skipped verification

- systemd, firewall, user, cron, svc, mount and package changes on a live host. These are destructive or need root, so they were not run, per the gate restrictions.
- Network integrations: SMTP, SSH, DNS, HTTP to external hosts, real git remotes, databases, Redis and memcached.
- `proc` signal verbs, which were deliberately not run.

## D-05 Linux runtime compatibility

### Artifact inspection

| Item | Value |
|---|---|
| ELF | ELF64, x86-64, PIE (`DYN`), not stripped, BuildID `b843caa0…` |
| Interpreter | `/lib64/ld-linux-x86-64.so.2` |
| NEEDED | `libc.so.6`, `libm.so.6`, `ld-linux-x86-64.so.2`, `libgcc_s.so.1`, `libssl.so.3`, `libcrypto.so.3`, `libz.so.1`, `liblzma.so.5` |
| glibc versions | Highest are **GLIBC_2.39** (`pidfd_spawnp` and `pidfd_getpid`, weak symbols, but the version-need entry is not flagged weak, so the loader enforces it) and **GLIBC_2.38** (`__isoc23_strtol`/`strtoul`, strong). libm needs GLIBC_2.29. |
| OpenSSL | `OPENSSL_3.0.0` from both `libssl.so.3` and `libcrypto.so.3` |
| Other | `XZ_5.0` (liblzma); `GCC_3.0`, `GCC_3.3` and `GCC_4.2.0` (libgcc_s) |
| Bundled | libgit2 1.7.2, libssh2 1.11.1 |

**Runtime requirements:** Linux x86_64, glibc ≥ 2.39, OpenSSL 3 (`libssl.so.3`, `libcrypto.so.3`), `libz.so.1`, `liblzma.so.5` and `libgcc_s.so.1`. **Build-time requirements:** Rust ≥ 1.88 (verified by CI build-msrv), a C toolchain, and OpenSSL 3 development headers. libgit2 and libssh2 are built from bundled sources.

The README and CHANGELOG already state the glibc and OpenSSL requirements. They do not list `libz` and `liblzma`. Those libraries are present on every image tested, and the release notes now list them.

### Clean-environment tests

Disposable Docker containers ran from stock public images with no extra packages. Each ran with `--network none`, a read-only root filesystem, a tmpfs `/tmp` and uid 65534. The binary was mounted read-only.

| Image | glibc | Result |
|---|---|---|
| ubuntu:24.04 | 2.39 | **PASS**: version, help (29 schemes), handle and verb help, `file read`, `system info` JSON, bad scheme exits 1, no stage exits 2 |
| debian:trixie-slim (13) | 2.41 | **PASS** (same checks) |
| fedora:40 | 2.39 | **PASS** (same checks) |
| fedora:39 | 2.38 | Fails to start: `version 'GLIBC_2.39' not found`. This confirms the floor. |
| ubuntu:22.04 | 2.35 | Fails to start: `GLIBC_2.38` and `GLIBC_2.39` not found |
| rockylinux:9-minimal | 2.34 | Fails to start: `GLIBC_2.38` and `GLIBC_2.39` not found |
| debian:bookworm-slim (12) | 2.36 | Fails to start: `libssl.so.3: cannot open shared object file` (exit 127); glibc is also too old |

Missing-library and glibc failures produce the standard, readable dynamic-loader messages, with exit 127 and 1.

The **packaged archive** was also extracted inside a clean ubuntu:24.04 container (no network, uid 65534), and the extracted binary passed the same checks.

### Enterprise compatibility assessment

These platforms do not meet the glibc 2.39 floor. Only Ubuntu 22.04, Debian 12 and RHEL-family 9 (via Rocky 9) were tested; the rest are known from their published glibc versions:
- RHEL, Rocky and AlmaLinux 8 (2.28) and 9 (2.34);
- Ubuntu 20.04 and 22.04 LTS;
- Debian 11 and 12;
- Amazon Linux 2 and 2023;
- SUSE Linux Enterprise 15.

Most enterprise fleets today therefore **cannot run the prebuilt binary** and must build from source, which the README already says. RHEL 10 and other glibc ≥ 2.39 distributions were not tested and are not claimed.

**Future improvement (not done in this gate):** build the release on an older-glibc baseline, such as a RHEL 8 / glibc 2.28 container with OpenSSL 3 available, or the oldest supported Debian. Another option is a static musl build with vendored OpenSSL. Either would need its own validation.

## D-06 Artifact manifest

The archive is `resh-v1.0.3-beta-linux-x86_64.tar.gz` (GNU tar 1.35 format, `gzip -9 -n`). Entries are sorted by name, owned by uid/gid 0, and stamped with the commit time (`@1793039275`).

| Path | Mode | Size | Source | Verification |
|---|---|---|---|---|
| `resh-v1.0.3-beta-linux-x86_64/resh` | 0755 | 51,150,512 | validated build output | `cmp` identical to `validated/resh` |
| `…/LICENSE` | 0644 | 11,357 | `git archive refs/tags/v1.0.3-beta` | blob hash = tag blob |
| `…/README.md` | 0644 | 21,130 | same | blob hash = tag blob |
| `…/CHANGELOG.md` | 0644 | 15,508 | same | blob hash = tag blob |
| `…/docs/known_issues.md` | 0644 | 36,903 | same | blob hash = tag blob |

Archive checks:
- **Contents.** Only regular files (5) and directories (2). There are no absolute paths or `..` entries, and none of `.claude`, `.env`, `.git` or `target`.
- **Integrity.** `gzip -t` passes.
- **Extraction.** Extraction with `--no-same-owner` gives a binary with mode 0755 that is byte-identical to the validated binary and prints `resh 1.0.3-beta`.
- **Repackaging.** Running the packaging step again gives the same archive SHA-256.

The release notes and this report are **not** in the archive, because they are not from the tagged source.

## D-07 Artifact integrity

| Field | Value |
|---|---|
| Artifact | `resh-v1.0.3-beta-linux-x86_64.tar.gz` |
| Size | 17,291,837 bytes |
| SHA-256 | `d91693b151ccccb860dfaf3accf698b936131fb5d8d320a24d6e86299bdb3087` |
| Checksum file | `SHA256SUMS` (103 bytes, one line, `sha256sum` format) |
| Independent verification | `sha256sum -c SHA256SUMS` → OK; Python `hashlib.sha256` gives the same digest |
| Source commit / tag | `dcce21ad0dbb749d2172a57c25841bb253a7bbd7` / `v1.0.3-beta` (`d42f7b6c…`) |
| Target | `x86_64-unknown-linux-gnu` |
| Rust | 1.98.1 |
| Build environment | Gentoo Linux, glibc 2.43, GCC 16.2.1, OpenSSL 3.5.8 (see D-03) |
| Runtime requirements | Linux x86_64, glibc ≥ 2.39, OpenSSL 3, libz, liblzma, libgcc_s |

**Signing:** the project has no signing infrastructure. There is no cosign, minisign, GPG or Sigstore configuration in the repository or CI, the tag is unsigned, and earlier GitHub releases had no binary assets. No signing identity was created. The checksum detects corruption, but **it does not authenticate the publisher**, because anyone who can replace the archive on the release page can replace `SHA256SUMS` too. The release notes say this.

**Reproducibility:** the binary was byte-identical across two clean builds on this host. It has not been shown reproducible on any other host.

## D-08 Release-note review

The file is `release-notes-v1.0.3-beta.md`. It was reviewed against CHANGELOG 1.0.3-beta and 1.0.2-beta (v1.0.2-beta was never published, so its changes are included), and against the evidence above.

| Requirement | Covered |
|---|---|
| Summary: security and functional stabilization | Yes |
| The 12 required correction areas | Yes. "Build reproducibility" is worded as *reproducible dependency resolution* (locked Cargo.lock), not byte-for-byte reproducibility. |
| The 8 required breaking changes | Yes, plus restic/borg password, `security_only`, `rules.delete` defaults, PID limit, typed-option errors and `format_output=` |
| Supported platform | Linux x86_64, glibc ≥ 2.39, OpenSSL 3, libz, liblzma; tested images named; failing distributions named |
| Known limitations | Beta; systemd unverified; untested integrations; Clippy advisory; supported vs unsupported platforms; accepted risks from `known_issues.md`; RUSTSEC-2026-0387 |
| No unsupported claims | Checked. Claims are limited to tested images. No signing or reproducibility claims. "28 handles / 239 verbs" was verified by the help sweep. |
| No credentials or sensitive details | Checked. The credential is mentioned by file name only, with no value, user, host or address. |

**Owner decision:** whether to keep the "Repository history" disclosure paragraph. I recommend keeping it.

## D-09 GitHub release draft

The draft was prepared locally in `GITHUB_RELEASE_DRAFT.md`. **Nothing was created remotely.** The `gh` CLI is not installed, and a remote draft would be persistent state that needs approval.

- Tag `v1.0.3-beta` (existing), target `dcce21ad…`.
- Title `Resource Shell v1.0.3-beta`.
- Pre-release yes, `make_latest=false`.
- Assets: the archive and `SHA256SUMS`.
- The prepared command uses `--verify-tag` so that no tag can be created by accident.

## D-10 Final publication checklist

| Gate | Status |
|---|---|
| Tag identity verified | PASS |
| Tag CI passed | PASS (clippy failure is advisory and pre-existing) |
| Credential rotation confirmed | PASS (owner confirmation, 2026-10-26, Gate C) |
| Security advisory review accepted | PASS (engineering review; RUSTSEC-2026-0387 not a blocker) |
| Clean tagged build passed | PASS |
| Binary smoke tests passed | PASS |
| Runtime dependencies verified | PASS |
| Artifact packaged | PASS |
| Archive contents verified | PASS |
| SHA-256 checksum verified | PASS |
| Release notes reviewed | PASS (engineering review; owner review is part of approval) |
| Breaking changes disclosed | PASS |
| Known limitations disclosed | PASS |
| Prerelease designation prepared | PASS (in local draft) |
| Owner publication approval | **PENDING** |

## Observations (non-blocking)

1. **Embedded build paths.** The binary has 926 strings with absolute paths under the build user's home directory (`$HOME/.cargo/registry/…` and `<release workspace>/src/…`), used in panic locations. They reveal the build username and directory layout, but no secrets. This gate kept the specified build command unchanged. **Resolved before publication:** the published binary was rebuilt with `--remap-path-prefix` and `-ffile-prefix-map` and contains 0 home-directory paths (see the publication report).
2. **Unstripped binary.** Symbols are included, which makes the binary about 51 MB. That is acceptable. Stripping would change the validated artifact.
3. **`resh <handle> <unknown-verb> --help`** prints the top-level help and exits 0 instead of reporting the unknown verb. This is cosmetic. Unknown verbs without `--help` correctly exit 1.
4. **`archive add backup_suffix=`** adds its own dot (`.orig` → `<archive>..orig`), while `file replace backup=` uses the suffix as given. The inconsistency is cosmetic.
5. **Example DSN** in `MYSQL_CONNECTION_GUIDE.md:119` looks like a credential (see D-02). It is not live.
6. **Future-incompatibility warning** from dependency `redis v0.25.4`.
7. **First binary release.** Earlier GitHub releases had no assets, so this will be the first published `resh` binary.

## Remaining risks

- The glibc ≥ 2.39 floor excludes most current enterprise Linux. This is disclosed, and building from source is documented.
- Live verification has not been done for systemd, root operation, network services, databases and real firewall rules.
- Accepted beta risks are listed in `docs/known_issues.md`. Accepted dependency advisories are listed in `.cargo/audit.toml`.
- Historical credential exposure in earlier tags and in the history of `main`, mitigated by rotation. At the time of this gate, `main` still served the old guide at HEAD. **Post-publication:** `main` was fast-forwarded to `dcce21a` on 2026-10-26, so the credential is no longer at the tip of `main`. It remains in history.
- The release is not authenticated by signature; only a checksum is provided.

## Deliverables (local, not published)

| Deliverable | Path |
|---|---|
| This assessment | `docs/reviews/resh-cli-v1.0.3-beta-gate-d.md` |
| Release notes | `<release workspace>/release-notes-v1.0.3-beta.md` |
| GitHub draft | `<release workspace>/GITHUB_RELEASE_DRAFT.md` |
| Archive (superseded, not published) | `<release workspace>/dist/resh-v1.0.3-beta-linux-x86_64.tar.gz` |
| Checksums (superseded) | `<release workspace>/dist/SHA256SUMS` |
| Evidence logs | `<release workspace>/evidence/` (build, rebuild, tests, help sweep, behaviour checks, container runs) |

`<release workspace>` is a local directory outside the repository. These files are not part of the repository.

## Publication recommendation

**READY FOR PUBLICATION APPROVAL.**

Every required gate passes on direct evidence:
- The identity chain is verified locally, remotely and in CI.
- The tagged clean build passes.
- Tests and binary checks pass.
- The runtime floor is confirmed empirically.
- The archive is verified against its sources and its checksum.
- The reachable advisory was re-assessed and is not exploitable in supported use.
- The release notes are accurate.

The only open item is the owner's explicit publication approval. The observations above are disclosed or cosmetic and do not block publication.
