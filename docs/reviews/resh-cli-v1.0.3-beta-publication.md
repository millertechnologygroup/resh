# resh v1.0.3-beta — Final Publication

Date: 2026-10-26
Final status: **PUBLISHED AND VERIFIED**

At the time of publication, this report was untracked. Apart from the GitHub release itself, nothing was committed, pushed, merged, tagged or moved. Local paths and authentication details have been generalized for publication.

## Publication Summary

The GitHub prerelease **was published** on 2026-10-26 at 20:18:30 UTC:
**https://github.com/millertechnologygroup/resh/releases/tag/v1.0.3-beta**

- **First attempt (Gate D recovery, same day): stopped.** No authorized GitHub API mechanism was available.
- **Authentication was resolved.** The GitHub CLI (`gh` 2.102.0) was installed from the distribution's package repository. The project owner then authenticated `gh` interactively. Claude Code never handled, printed or stored a token.
- **Authenticated publisher:** the repository owner's GitHub account. No repository permissions were changed.
- **Publication approved.** The project owner gave explicit approval ("publish") after reviewing the approval summary. Installing and logging in were not treated as approval to publish.
- **Command:** the exact command reviewed in `final/PUBLISH.md`. It ran once and succeeded:

```bash
gh release create v1.0.3-beta --repo millertechnologygroup/resh --verify-tag \
  --title "Resource Shell v1.0.3-beta" --notes-file release-notes-v1.0.3-beta.md \
  --prerelease --latest=false \
  dist/resh-v1.0.3-beta-linux-x86_64.tar.gz dist/SHA256SUMS
```

Before publication (D-R1), all of these were rechecked and passed:
- Archive size and SHA-256.
- `SHA256SUMS` content.
- Archive listing.
- The binary is identical to `validated/resh`.
- Release notes are present.
- The tag still points to `dcce21ad…`, locally and on the remote.
- Tag CI run 40384455996 is success.
- No existing `v1.0.3-beta` release (404).

## Release Identity

| Item | Value | Verified |
|---|---|---|
| Repository | `https://github.com/millertechnologygroup/resh` | — |
| Tag | `v1.0.3-beta` (annotated, unsigned) | — |
| Tag object | `d42f7b6cf92530bb936022f1b7cb961ba1ce8665` | local and `git ls-remote`, unchanged |
| Commit | `dcce21ad0dbb749d2172a57c25841bb253a7bbd7` | local and remote `^{}` |
| Tag CI | run `40384455996`: completed/success, `head_sha` = `dcce21ad…`, attempt 1 | public REST API, rechecked before publication |
| GitHub release URL | `https://github.com/millertechnologygroup/resh/releases/tag/v1.0.3-beta` | public, HTTP 200 without authentication |
| Published | 2026-10-26T20:18:30Z by `millertechnologygroup` | REST API |

Tag CI jobs: build-msrv, test-msrv, test-stable, test-security-regression, fmt and audit all succeeded. clippy failed as an advisory check (`continue-on-error`, pre-existing). test-infrastructure was skipped (manual dispatch only).

## Artifact Privacy

**Result: embedded local build paths were removed.** The remapped build introduced no new path disclosure.

### Method (build-time configuration only)

The build used a fresh `git clone --no-local` of `refs/tags/v1.0.3-beta` into `<release workspace>/final/src`, a local directory outside the repository. HEAD was `dcce21ad…` and `git status --porcelain` was empty before and after the build. Cargo.lock SHA-256 was `3c794872…ffaa4` before and after, matching Gate D.

```
RUSTFLAGS="--remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=<build root>=/build"
CFLAGS / CXXFLAGS="-ffile-prefix-map=$HOME/.cargo=/cargo -ffile-prefix-map=<build root>=/build"
CARGO_TARGET_DIR=<build root>/target cargo build --release --locked
```

- `CFLAGS` was needed in addition to `--remap-path-prefix`, because the bundled C code (libgit2, libssh2, zstd, ring) embeds `__FILE__` paths.
- These settings did not change features, target, profile, lockfile, source or security checks.
- There is no project or user `.cargo/config.toml`, and no other `RUSTFLAGS`/`CARGO_*` overrides were present.
- The build exited 0 in 1m 43s, with the same pre-existing warnings and the same `redis v0.25.4` future-incompatibility notice as Gate D.

### Binary inspection

| Check | Gate D binary | Final binary |
|---|---|---|
| Strings containing the build user's home directory | 926 | **0** (`grep -a` on raw bytes: 0) |
| `development/rust` (build directory) | — | **0** |
| Host name | — | **0** |
| Remapped `/cargo/registry/src/…` panic locations | — | 926 |
| Other `/home/…` strings | `alice`, `bob` | same: help-text examples only |
| `.comment` section | — | toolchain IDs only (LLD 22.1.8, rustc 1.98.1, GCC 14.3.1/16.2.1) |
| Debug sections | none | none (default release profile, no debuginfo) |

**Residual identity string (not a build path):** the author contact `Scott Miller <smiller@millertechnologygroupllc.com>` appears once, in clap's `--help` metadata. It comes from the `authors` field of the tagged `Cargo.toml` and is intentional public project metadata. Removing it would require a source change, so it was left as is.

### Equivalence with the approved build

| Check | Result |
|---|---|
| `.text` size | identical (28,524,592 bytes) |
| All function symbols with sizes, after normalizing addresses and mangling hashes | identical (85,593 symbols) |
| `.rodata` | 16,384 bytes smaller, consistent with the shortened path strings |
| `.text` bytes | 134,854 differing positions, consistent with RIP-relative displacements to the relocated `.rodata` strings |
| NEEDED libraries and GLIBC version needs | identical (max `GLIBC_2.39`) |
| Behaviour harness (below) | output identical to the Gate D binary |

**Same-host determinism.** A second clean remapped build (`target-rebuild`) produced the identical binary SHA-256 `38740f05…`.

## Artifact Verification

The harness (`final/evidence/verify.sh`) was first run against the **Gate D binary** to validate the harness itself. Three harness bugs were found and fixed this way:
- a wrong `subject` syntax;
- verb parsing that overran the verb list;
- a camelCase verb (`setPriority`) that was missed.

The harness was then run against the **final binary**.

| Check | Gate D binary | Final binary |
|---|---|---|
| Help sweep (29 schemes, 239 verbs) | 268/268 | **268/268** |
| Behaviour and security checks | 45/45 | **45/45** |
| Result diff | — | **identical** |

The 45 checks are the 43 behaviour and security checks in the Gate D report plus the 2 version checks (`--version`, `-V`), which Gate D listed in its version and help table.

The 45 checks are:
- version and `-V` (2);
- URL parsing (U1–U4);
- exit codes (E1–E6);
- JSON output (J1–J3);
- read-only verbs (R1–R2);
- dry-run enforcement (D1–D6);
- archive extraction with `..`, absolute, symlink and hard-link entries;
- zip password refusal;
- plugin HTTP registry and id traversal;
- PID above `i32::MAX`;
- pkg metacharacter and option injection;
- tar, rsync and borg without `repo_url`, plus a tar dry-run plan;
- git `timeout_ms`;
- cert key mode 0600, no overwrite, symlinked key path, P-384, ECDSA self-signed;
- backup symlink for `file replace` and `archive add`.

All runs used an isolated `HOME`/`XDG_*`, ran unprivileged and made no destructive host changes.

### Clean containers

Images were run with `--pull=never --network none --read-only`, uid 65534, using the binary extracted from the final archive.

| Image | glibc | Result |
|---|---|---|
| ubuntu:24.04 | 2.39 | PASS: version, 29 schemes, help, `file read`, `system info` JSON, bad scheme exits 1, no stage exits 2 |
| debian:trixie-slim (13) | 2.41 | PASS (same) |
| fedora:40 | 2.39 | PASS (same) |
| fedora:39 | 2.38 | does not start: `GLIBC_2.39 not found` |
| ubuntu:22.04 | 2.35 | does not start: `GLIBC_2.38`/`2.39 not found` |
| debian:bookworm-slim (12) | 2.36 | does not start: `libssl.so.3` missing |
| rockylinux:9-minimal | 2.34 | does not start: `GLIBC_2.38`/`2.39 not found` |

These results are identical to Gate D.

## Artifact Manifest

| Field | Value |
|---|---|
| Artifact | `resh-v1.0.3-beta-linux-x86_64.tar.gz` |
| Size | **17,291,346 bytes** |
| SHA-256 | **`3838022fa6fa45a64b48c8fe7cb89d28dae2eae3ff0b1df09babfee1e47175dd`** |
| Checksum file | `SHA256SUMS`, 103 bytes, one `sha256sum` line |
| Checksum verification | `sha256sum -c` OK; Python `hashlib` and `openssl dgst -sha256` give the same digest |
| Binary | `resh`, 51,134,824 bytes, SHA-256 `38740f05f1473bd9c5a48638f39b4d36f4142e53a2fb0d56d599981d51eb1edb`, mode 0755, ELF64 PIE, not stripped |
| Superseded | Gate D archive `d91693b1…3087` and binary `d531fea4…` are **not** to be published |
| Build toolchain | rustc 1.98.1 (48a229cea 2026-09-01), LLVM 22.1.8; cargo 1.98.1; GCC 16.2.1 for the C dependencies |
| Build host | Gentoo Linux, kernel 6.18.35, glibc 2.43, OpenSSL 3.5.8 |
| Target architecture | `x86_64-unknown-linux-gnu` |
| Runtime requirements | Linux x86_64, glibc ≥ 2.39, OpenSSL 3 (`libssl.so.3`, `libcrypto.so.3`), `libz.so.1`, `liblzma.so.5`, `libgcc_s.so.1` |
| Build from source | Rust ≥ 1.88 |

The archive was packaged with GNU tar 1.35 (`--sort=name`, owner and group 0, mtime `@1793039275`, gnu format) and `gzip -9 -n`. Repackaging produces the same SHA-256.

| Entry | Mode | Size | Source and check |
|---|---|---|---|
| `resh-v1.0.3-beta-linux-x86_64/resh` | 0755 | 51,134,824 | tested binary; extracted copy is `cmp`-identical |
| `…/LICENSE` | 0644 | 11,357 | `git archive` of the tag; blob `261eeb9e…` = tag blob |
| `…/README.md` | 0644 | 21,130 | blob `b3420b75…` = tag blob |
| `…/CHANGELOG.md` | 0644 | 15,508 | blob `c2d7231c…` = tag blob |
| `…/docs/known_issues.md` | 0644 | 36,903 | blob `7d2bda70…` = tag blob |

Archive integrity:
- `gzip -t` passes.
- The archive holds 5 regular files and 2 directories.
- There are no absolute paths, no `..` entries, and none of `.git`, `.claude`, `.env` or `target`.
- Extraction with `--no-same-owner` keeps the binary at mode 0755, and the extracted binary prints `resh 1.0.3-beta`.

**Credential scan of the archive contents:**
- 0 cloud or API token shapes.
- PEM header strings only (parser literals, no key bodies).
- The one DSN-shaped string is the placeholder `mysql://user:pass@host:3306/db`.
- 0 home-directory paths.

## Release Notes

The final notes are `<release workspace>/final/release-notes-v1.0.3-beta.md`, based on the Gate D notes. Their published text is the body of the GitHub release. Changes from Gate D:
- A prominent **Platform compatibility** block at the top. It lists all runtime libraries, the verified distributions (Ubuntu 24.04, Debian 13, Fedora 40), the ones that do not run (Ubuntu 22.04, Debian 12, Rocky Linux 9) and Rust 1.88. It says explicitly that the binary is not compatible with all Linux distributions.
- An explicit "not production-certified" statement.
- The new SHA-256 and the archive contents.
- **Historical credential:** the public text is reduced to "earlier documentation contained a credential; not in this release; revoked; history and earlier tags not rewritten". The file name, service and other details were removed. The notes make no claim of history sanitization.

All other sections were kept: summary, security and functional corrections, breaking changes, install, checksum verification, supported platform, known limitations and beta designation.

Release classification:
- Title: `Resource Shell v1.0.3-beta`
- Tag: existing `v1.0.3-beta`
- **Pre-release: YES**
- **Latest: NO**

### Historical credential record

- A database credential formerly appeared in documentation (`MYSQL_CONNECTION_GUIDE.md`). It was replaced with placeholders in `dcce21a` (RB-4) and is absent from the release.
- It remains in Git history and in tags `v1.0.0-beta`, `v1.0.1-beta` and `v1.0.2-beta`. At publication it was also at the tip of `main`. `main` was fast-forwarded to `dcce21a` afterwards.
- The owner confirmed rotation or revocation on 2026-10-26.
- No history rewrite was performed.

The tagged `CHANGELOG.md` and `docs/known_issues.md` shipped in the archive name the guide file but contain no credential values.

## Publication Preconditions

| # | Check | Result |
|---|---|---|
| 1 | Tag still points to the approved commit | PASS |
| 2 | Tag CI remains successful | PASS |
| 3 | Final artifact passed verification | PASS |
| 4 | Checksum matches the final archive | PASS |
| 5 | No live credentials included | PASS |
| 6 | Release notes match the artifact (checksum, file list, platforms) | PASS |
| 7 | Runtime limitations disclosed | PASS |
| 8 | Prerelease configuration prepared | PASS (in `PUBLISH.md`) |
| 9 | Exactly two files selected | PASS (`final/dist/` holds only the two) |
| 10 | Authorized publication mechanism available | FAIL on the first attempt; PASS after `gh` install and interactive owner login |

## Publication Verification

**Result: `RESULT: 0 failure(s)`.** The verifier `final/verify-published.sh` was inspected before it was run. It is unauthenticated and read-only:
- `curl` GETs;
- `git ls-remote`;
- extraction into a fresh `mktemp` directory;
- `resh --version` with an isolated `HOME`.

It was run twice, with identical results. The second run's log is `final/evidence/verify-published.log`.

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | Publicly accessible | PASS | REST API without authentication; release page HTTP 200 |
| 2 | Marked prerelease | PASS | `prerelease: true`, `draft: false` |
| 3 | Not latest stable | PASS | `/releases/latest` returns 404 (there are no non-prerelease releases) |
| 4 | Tag correct | PASS | `tag_name: v1.0.3-beta`; title `Resource Shell v1.0.3-beta` |
| 5 | Tag resolves to approved commit | PASS | remote `refs/tags/v1.0.3-beta^{}` = `dcce21ad…`; tag object still `d42f7b6c…` |
| 6 | Release notes present | PASS | body is **byte-identical** to `release-notes-v1.0.3-beta.md`; not auto-generated |
| 7 | Both files downloadable | PASS | unauthenticated `releases/download/…` |
| 8 | No unexpected assets | PASS | assets are exactly `SHA256SUMS` (103 bytes) and the archive (17,291,346 bytes), both `uploaded` |
| 9 | Downloaded archive SHA-256 | PASS | `3838022f…175dd`; `sha256sum -c SHA256SUMS` OK; the GitHub asset digest field agrees |
| 10 | Extracts | PASS | `tar -xzf --no-same-owner` |
| 11 | Binary executable | PASS | mode 0755; SHA-256 `38740f05…1edb` = tested binary |
| 12 | Version | PASS | `resh 1.0.3-beta` |
| 13 | Platform notice prominent | PASS | "Platform compatibility" block within the first 1,200 characters; all platform and library strings present |
| 14 | No production-certification claim | PASS | says "not production-certified"; no "production-ready" or "certified" claim |

Note: the API reports `target_commitish: main`. This is GitHub's default metadata and only applies when GitHub has to create a tag. Here the tag already existed (`--verify-tag`) and was not moved, as check 5 confirms.

## Known Limitations

These are the accepted beta limitations, as disclosed in the release notes:
- Beta, not production-certified.
- Prebuilt binary is Linux x86_64 only, with glibc ≥ 2.39. Most enterprise distributions must build from source.
- systemd not verified live. Network, database, root-operation and firewall integrations are untested against real systems.
- Clippy advisory failure; pre-existing compiler warnings.
- Accepted risks in `docs/known_issues.md`. Accepted advisories are in `.cargo/audit.toml`, including RUSTSEC-2026-0387 (crypto-bigint timing, local key operations only).
- No signature. The checksum proves integrity only.
- Cosmetic: `resh <handle> <unknown-verb> --help` prints the top-level help; `archive add backup_suffix=` adds its own dot.

## Remaining Repository Maintenance

Each item needs separate approval. None has been started.
1. **Fast-forward `main` to `dcce21a`.** `origin/main` (`9d46f4b`) is an ancestor of `dcce21a`, so this is a pure fast-forward of 8 commits. At publication, `main` still served the old guide at HEAD. **Done 2026-10-26** (Stage 5, approved, fast-forward only).
2. **Commit release evidence documentation** separately from the tagged commit: the Gate D report, the Gate C addendum and this report.
3. **Historical credential exposure review.** Decide between rewriting history and accepting the exposure, given that the credential was rotated.
4. **Path remapping in the official build recipe or CI.**
5. **Enterprise Linux (older glibc) build strategy.**
6. **Clippy debt and the minor behavioural issues** listed under Known Limitations.
7. **Optional:** artifact signing. Narrow the `gh` token scopes, or log out, when not publishing.

## Final Status

**PUBLISHED AND VERIFIED.**

Evidence:
- The release is public at https://github.com/millertechnologygroup/resh/releases/tag/v1.0.3-beta. It is a prerelease, not latest, on tag `v1.0.3-beta` → `dcce21ad0dbb749d2172a57c25841bb253a7bbd7`.
- It contains exactly the two approved files.
- An unauthenticated download matches SHA-256 `3838022fa6fa45a64b48c8fe7cb89d28dae2eae3ff0b1df09babfee1e47175dd`, extracts, and runs as `resh 1.0.3-beta`.
- `verify-published.sh` reports `RESULT: 0 failure(s)`. All 14 checks were also confirmed independently.

Local deliverables are under `<release workspace>/final/`, outside the repository. They are unchanged, except that `evidence/verify-published.log` was added.
