# resh v1.0.3-beta — Release Gates Addendum (Gate C)

Date: 2026-10-26
Outcome: **GATE C COMPLETE**

> **Post-publication status (2026-10-26).** v1.0.3-beta was published from this
> tag. The published artifact SHA-256 is
> `3838022fa6fa45a64b48c8fe7cb89d28dae2eae3ff0b1df09babfee1e47175dd` (see
> `resh-cli-v1.0.3-beta-publication.md`). `main` has since been
> fast-forwarded to `dcce21a`. The "Remaining conditions" below record the
> state at the time of Gate C.

## Release identity

| Item | Value |
|---|---|
| Tag | `v1.0.3-beta` (annotated) |
| Tag object | `d42f7b6cf92530bb936022f1b7cb961ba1ce8665` |
| Target commit | `dcce21ad0dbb749d2172a57c25841bb253a7bbd7` |
| Branch | `help-system-and-fixes` |
| Annotation | `Resource Shell v1.0.3-beta — security and functional stabilization release` |
| Tagger | Scott Miller |

## Gate B push result

`971b0d5..dcce21a` pushed to `origin/help-system-and-fixes`. Local HEAD and
the remote branch both resolve to `dcce21a`. The only working-tree change is
the untracked `.claude/`.

## Branch CI

Run `40379972569` (event `push`, head `dcce21a`), conclusion **success**,
verified through the GitHub REST API.

| Job | Result |
|---|---|
| build-msrv | success |
| test-msrv | success |
| test-stable | success |
| test-security-regression | success |
| fmt | success |
| audit | success |
| clippy | failure (advisory; `continue-on-error: true`) |
| test-infrastructure | skipped (manual dispatch only) |

## Credential rotation (GATE-C-02)

The project owner confirmed on 2026-10-26 that the MySQL credential formerly
committed in `MYSQL_CONNECTION_GUIDE.md` has been rotated or revoked.

Historical exposure remains. At the time of Gate C, the credential was still
present at the tip of `origin/main` and in tags `v1.0.0-beta`, `v1.0.1-beta`
and `v1.0.2-beta`. It is absent from `dcce21a`. Rotating the credential does
not remove it from Git history. No history rewrite was performed, and any
cleanup would need separate approval.

## Advisory exceptions (GATE-C-03)

The five exceptions added in `dcce21a` were assessed in
`resh-cli-v1.0.3-beta-release-execution.md`. A code spot-check confirmed that
`src/` uses only `zstd::stream::read::Decoder` and
`zstd::stream::write::Encoder`.

| Advisory | Crate @ locked | Reachable | Disposition |
|---|---|---|---|
| RUSTSEC-2026-0391 | zstd 0.13.3 | No | Accepted |
| RUSTSEC-2026-0403 | zstd-safe 7.2.4 / 5.0.2 | No (code-level) | Accepted |
| RUSTSEC-2026-0398 | zstd-safe 7.2.4 | No (`seekable` off) | Accepted |
| RUSTSEC-2026-0410 | zstd-sys 2.0.16 | No (WASM only) | Accepted |
| RUSTSEC-2026-0387 | crypto-bigint 0.5.5 | In principle (cert ECDSA) | Accepted, low risk: local timing side channel only, no signing oracle; fix needs p256/p384 0.14 |

None of these conceals a reachable vulnerability that should block the
release.

## Main / release branch relationship (GATE-C-04)

- `origin/main` has 0 commits that are not on the release branch, which is 8
  commits ahead (merge base `9d46f4b`).
- `dcce21a` is not on `main`. `v1.0.2-beta` was also tagged from this branch.
- The tag was created on the release commit, with no merge. A fast-forward of
  `main` is possible and is a separate decision.

## Local tag (Gate C1)

The tag was confirmed absent locally and remotely before creation, then
created with an explicit SHA. It is an annotated `tag` object that peels to
`dcce21a`, and the message is correct. The only tag ref change was the
addition of `v1.0.3-beta`.

## Remote tag (Gate C2)

The tag was pushed with `git push origin refs/tags/v1.0.3-beta`, with no force
and no `--tags`. `git ls-remote` before and after shows that only
`refs/tags/v1.0.3-beta` (`d42f7b6`, peeled `dcce21a`) was added. The local and
remote tags match. `v1.0.2-beta` is unchanged (`62043aa` → `971b0d5`).

## Tag CI (GATE-C-07)

Run `40384455996` (event `push`, ref `v1.0.3-beta`, head `dcce21a`),
conclusion **success**. Job results are identical to the branch run: all six
required jobs passed, clippy failed as an advisory, and test-infrastructure
was skipped. The workflow has no release-specific jobs.

## Remaining conditions

- Historical credential exposure in `main` and in earlier tags. It is
  mitigated by rotation, and any history cleanup would need separate
  approval.
- Clippy advisory failure (non-blocking lint baseline).
- Infrastructure tests were not run on this release.
- `main` has not been updated to include the release. (Resolved after
  publication: `main` was fast-forwarded to `dcce21a`.)
- No binaries, checksums or GitHub Release have been produced. That is Gate D,
  which awaits owner approval. (Resolved: published 2026-10-26.)
- This addendum is uncommitted. A separate documentation commit is
  recommended.
