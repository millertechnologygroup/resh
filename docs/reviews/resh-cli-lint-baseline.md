# Resource Shell (resh) — Formatting and Lint Baseline (Stage 4, RC-04)

- **Date:** 2026-10-23
- **Tree:** commit `277f996` plus the uncommitted Stage 1-4 changes

## Toolchain and commands

| Item | Value |
|---|---|
| Rust | rustc / cargo 1.98.1 (Gentoo system toolchain), clippy 1.98.1, rustfmt 1.9.0 |
| Clippy command | `cargo clippy --locked --workspace --all-targets --message-format=json` |
| Formatting command | `cargo fmt --all -- --check` |
| Lint configuration | None: no `clippy.toml`, `rustfmt.toml` or `[lints]` table, so the defaults apply. No lint was suppressed globally to get this result. |
| Counting rule | Distinct `(lint, file, line, column)` sites. Each unit test is compiled for both the lib and the bin target, so raw counts double many sites; those duplicates are removed. |

## Formatting

**Result:** `cargo fmt --all -- --check` fails with **15,188 diff hunks in 61 files**. The code base has never been rustfmt-formatted. This is pre-existing debt.

**Why it was not applied to the working tree:** Stages 1-4 are uncommitted and touch the same files. Formatting in place would mix about 32,000 changed lines of formatting into the functional diff, so neither change could be reviewed. The brief requires the formatting pass to be separable, so it was prepared as a **separate, verified patch** and not applied.

**Preparation and verification:**

1. The release file set (`git ls-files -co --exclude-standard`, without `.claude/`) was exported to a scratch copy, and `cargo fmt --all` was run there. `cargo fmt --all -- --check` is then clean.
2. Result:
   - 61 files changed, all `.rs`: the same 61 files `--check` reports.
   - Patch: `resh-rustfmt.patch`, 96,820 lines, sha256 prefix `b3b319fd3febdf25`.
   - The patch applies cleanly to the working tree (`git apply --check -p1`; it was checked, not applied).
3. **Formatting-only check by syntax tree.** Every changed file was parsed before and after with `syn` and re-printed with `prettyplease`. Comments are dropped; doc comments are kept as attributes. Rewrites that rustfmt is known to make and that do not change meaning were normalized:
   - sorting of `use` items;
   - merging of `#[derive]` attributes;
   - a single-expression closure or match-arm body wrapped in `{ }`;
   - trailing commas;
   - token spacing inside macros.

   Result: 53 files have identical trees. The other 8 differ only in out-of-line `mod` declaration order, `continue` versus `continue;`, a `return` arm wrapped in a block, and token spacing inside macros, all of which are equivalent.
   - The only `macro_rules!` in the affected modules is local to `core/lenient.rs`, and there is no `#[macro_use]`, so module order cannot change macro resolution.
4. **Behaviour check.** The formatted copy was built and tested. It gives the same results as the unformatted tree:
   - lib 1181 passed, bin 1185 passed, 11 ignored, 0 failed;
   - doc_examples 2, help_cli 16, help_coverage 2, stage4_regressions 11.

**Recommendation:** apply the formatting as its own commit, immediately after the release commit:

```
cargo fmt --all        # rustfmt 1.9.0; or apply resh-rustfmt.patch with git apply -p1
cargo fmt --all -- --check
cargo test --locked
```

Until then, the `fmt` CI job fails. That is expected, and the CI documentation says so. New Stage 4 files (`tests/doc_examples.rs`, `tests/stage4_regressions.rs`) are already rustfmt-clean.

## Clippy

**Result:** exit 101, with **1,790 distinct sites: 5 errors (deny-level) and 1,785 warnings**.

- By origin: 1,419 Clippy lints and 371 compiler lints (unused code, deprecated APIs and similar).
- At the end of Stage 3 there were 1,800 sites; at the start of Stage 4, 1,799.

**Coverage caveat:** the 5 deny-level errors abort compilation of the `lib test` target. Lints that would appear only later in that target are not counted. The lib, bin and bin-test targets were linted completely.

### Findings by category

| Category | Sites | Content |
|---|---|---|
| Security | **0** | No Clippy finding indicates a security defect. The security-relevant correctness candidates below were each read and cleared. |
| Correctness | 61 | `if_same_then_else` 25, `unused_assignments` 7, `assertions_on_constants` 5 (tests), `wildcard_in_or_patterns` 4, `absurd_extreme_comparisons` 4 (deny, tests), `unused_comparisons` 4 (tests), `identity_op` 3, `unexpected_cfgs` 2, `ifs_same_cond` 1 (deny), and 6 others |
| Reliability | 31 | `deprecated` 9 (`base64::encode/decode`, chrono), `unnecessary_unwrap` 9, `implicit_saturating_sub` 5, `mismatched_lifetime_syntaxes` 4, `await_holding_lock` 2, `unnecessary_fallible_conversions` 2 |
| Performance | 82 | `useless_vec` 13, `unnecessary_lazy_evaluations` 9, `map_flatten` 8, `useless_format` 7, `unnecessary_cast` 7, `trim_split_whitespace` 7, `cloned_ref_to_slice_refs` 7, `manual_inspect` 6, and others |
| Maintainability | 502 | `dead_code` 137, `unused_variables` 94, `unused_imports` 72, `unused_mut` 41, `field_reassign_with_default` 39, `should_implement_trait` 24, `derivable_impls` 21, and others |
| Style | 1,114 | `collapsible_if` 551, `needless_borrows_for_generic_args` 203, `bool_assert_comparison` 84, `manual_strip` 65, `single_char_add_str` 39, `needless_borrow` 31, and others |

### Correctness and reliability review

Every correctness candidate in security-relevant code was read.

| Finding | Assessment | Action |
|---|---|---|
| `if_same_then_else` at `pkgh.rs` (apt upgrade with `security_only`) | **Real defect.** Both branches build `apt-get upgrade`, so `security_only=true` silently ran a full upgrade. The same was true for other managers in other builders. | **Fixed in Stage 4.** The request is now refused where it cannot be honored, with a mutation-checked test. |
| `if_same_then_else` in `archiveh.rs` format detection and error mapping, `firewallh.rs:5238` CIDR prefix check, `certh.rs`, `dnsh.rs`, `pluginh.rs:1565` | Identical branches by design: several extensions map to the same kind, error strings map to the same code, and the IPv4/IPv6 prefix limit errors are the same. `pluginh.rs:1565` rejects `url:` catalog sources explicitly. | None. Not defects. |
| `ifs_same_cond` `mailh.rs:1142` (deny) | An unreachable duplicate branch in the mail **text formatter**. Display only. | Deferred (cosmetic). |
| `absurd_extreme_comparisons` / `unused_comparisons` in `dbh.rs` tests (deny) | Always-true assertions on unsigned values in test code. They weaken those test assertions; they are not a production defect. | Deferred. These make `-D warnings` and the lib-test lint target fail. |
| `assertions_on_constants` (cacheh, certh tests) | `assert!(true)`-style placeholders in tests. | Deferred. |
| `unused_assignments` `pkgh.rs:2625/2715/2778`, `dnsh.rs` trace, `systemh.rs:3734` | Values overwritten before use. pkg `summary` is rebuilt on each path, and the Stage 2 `result_status` reads the final value. No wrong result was found. | Deferred. |
| `identity_op` `fsh.rs:8035-8081` | `x * 1` in test constants. | Deferred. |
| `unexpected_cfgs` `cacheh.rs:4407/4445` | `cfg(feature = "redis-integration-tests")` and the memcached equivalent are not declared, so those test modules never compile. Missing coverage, not a runtime defect. | Deferred. Declare the features or remove the modules. |
| `await_holding_lock` `dbh.rs:1717/1812` | A `std::sync::Mutex` guard held across `.await` in transaction helpers. Each CLI invocation runs one task on its own runtime, so nothing contends for the lock. It is a latent deadlock if this code is ever used concurrently. | Deferred (reliability debt). |
| `ineffective_open_options` `fileh.rs:3486` | `.write(true)` combined with `.append(true)`. Redundant, no effect. | Deferred. |
| `unnecessary_unwrap`, `implicit_saturating_sub`, `manual_checked_ops`, `get_last_with_len` | Guarded unwraps and manual saturating arithmetic. No panic path was found. | Deferred. |
| `deprecated` (`base64::encode`, chrono) | Deprecated APIs, still correct. | Deferred. |

### Newly introduced findings

Clippy's output was intersected with every line the working tree adds relative to `HEAD`, which covers Stages 1-4. The two new test files were counted as entirely new.

- **Stage 4 code:** **no new findings.**
  - Stage 4 edits had touched 5 pre-existing nested `if` blocks in `fileh.rs`, which were already flagged as `collapsible_if`. They were collapsed with let-chains, which are stable at the 1.88 minimum.
  - Total sites fell from 1,799 to 1,790. One `useless_borrows_in_formatting` hit on a line edited in Stage 4 was fixed as well.
- **Pre-existing hits on changed lines (5),** all recorded in Stages 1-3:
  - `unused_variables` `pkgh.rs:3017` (`available_updates`);
  - 3 `collapsible_if` in `cronh.rs` (3545, 3735, 4232);
  - `type_complexity` in a `firewallh.rs` test (9857).
- **Compiler warnings:** lib 285 and bin 419, down from 287 and 421 at the start of Stage 4. No new warnings.

### Release-blocking findings

**None.** No lint indicates a security defect, false success, or unsafe execution path that is still open. The one real defect found through the lint review, pkg `security_only`, was fixed.

### Deferred, non-blocking debt

1. The 5 deny-level errors: 4 test assertions in `dbh.rs` and 1 display branch in `mailh.rs`. Fix them first; they are the only thing stopping the lib-test target from being linted completely.
2. 137 `dead_code` sites, including the unreferenced `src/handles/automation/backup/{policy,tools,fs_snapshots}.rs` and `src/handles/filesystem/fs_atomic.rs`. There are also 72 unused imports and 94 unused variables.
3. `await_holding_lock` in `dbh.rs`, and the undeclared `cfg` features in `cacheh.rs` tests.
4. About 1,114 style lints, half of them `collapsible_if`. Most can be fixed mechanically with `cargo clippy --fix`, but that should be a separate change, like the formatting pass.

## Gate policy (as configured in `.gitlab-ci.yml`)

| Check | Gate | Reason |
|---|---|---|
| `cargo fmt --all -- --check` | **Enforced** | It fails until the formatting commit lands; after that, it keeps the tree formatted. |
| `cargo clippy --workspace --all-targets` | **Advisory** (`allow_failure: true`, report kept as an artifact) | Pre-existing debt. Keeping it visible instead of hidden. Do not add new warnings; check new code against this baseline. |
| Path to a strict gate | — | (1) Fix the 5 deny-level errors. (2) Apply `clippy --fix` in a separate change. (3) Add `-D warnings` with any remaining exceptions listed by name in `[lints.clippy]`, each with a reason. |
