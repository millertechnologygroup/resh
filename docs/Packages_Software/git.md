# Resource Shell (resh) – Git Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using structured URI-based commands. The `git://` handle works with local Git repositories through the **libgit2** library (the `git2` Rust crate). It does not run the `git` binary and does not use Git credential helpers.

### Purpose

The Git handle provides:

* Repository cloning (`clone`)
* Branch listing, creation, deletion, renaming and checkout (`branch`)
* Tag listing, creation and deletion (`tag`)
* Commits (`commit`) and diffs (`diff`)
* Status reporting (`status`, `status_summary`, `status_short`)
* Explicit merges (`merge`) and rebases (`rebase`), run only when you call those verbs
* Remote operations: `pull` (fast-forward only), `push`, and `sync` (fast-forward plus push)

Every verb prints a JSON object on success.

### Resource-Oriented URI Model

Git operations follow:

```text
resh git://<alias>.<verb> path=<repo-dir> [key=value ...]
```

* **handle**: `git://`
* **alias**: a free-form label (for example `main` or `default`). It is echoed as `alias` in the output. It does not select a repository.
* **verb**: one of the 13 registered verbs listed below
* **path**: the repository directory. It is required by every verb (for `clone` it is the destination directory).

Example:

```bash
resh git://default.clone url=https://github.com/user/repo.git path=/tmp/repo
```

---

## 2. Verbs

| Verb | What it does |
| ---- | ------------ |
| `status` | Current branch and upstream, staged / unstaged / untracked / conflicted files, operations in progress |
| `status_summary` | File counts, a sync state and a recommended next action |
| `status_short` | Compact one-line status string for shell prompts |
| `diff` | Changed files with hunks and lines between working tree, index, HEAD or commits |
| `branch` | `action=list` (default), `create`, `delete`, `rename`, `checkout` |
| `tag` | `action=list` (default), `create`, `delete` |
| `commit` | Commit staged changes (`all=true` stages tracked changes first; `paths=` stages listed paths) |
| `merge` | Merge `source` into the current branch: fast-forward when possible, otherwise a merge commit (or `squash=true`) |
| `rebase` | `operation=start` (default), `continue`, `abort` |
| `clone` | Clone `url` into a new or empty directory `path` |
| `pull` | Fetch and fast-forward the local branch. Merging or rebasing during pull is not implemented |
| `push` | Push the current branch (or `branch=` / `branches=`), optionally tags |
| `sync` | Fetch, fast-forward if behind, then push. Never merges or rebases |

Built-in help lists every argument and an example output for each verb:

```bash
resh git --help
resh git sync --help
```

---

## 3. Command Syntax and Execution Model

### 3.1 Example Commands

#### Clone Repository

```bash
resh git://default.clone url=https://github.com/user/repo.git path=/tmp/repo
```

#### Check Repository Status

```bash
resh git://default.status path=/tmp/repo
```

#### Create Feature Branch

```bash
resh git://default.branch path=/tmp/repo action=create name=feature/login
```

#### Commit Changes

```bash
resh git://default.commit path=/tmp/repo 'message=feat(auth): add OAuth2 support' all=true
```

#### Merge a Branch

```bash
resh git://default.merge path=/tmp/repo source=feature/login
```

#### Sync with Remote

```bash
resh git://default.sync path=/tmp/repo pull_strategy=ff_only push=true
```

---

### 3.2 Remote Synchronization Semantics

#### `sync`

`sync` supports **fast-forward synchronization only**:

* If the local branch is **behind** its remote branch, it is fast-forwarded.
* If it is **only ahead**, nothing is integrated and the branch is pushed (when `push=true`, the default).
* If both sides have new commits (**diverged history**), `sync` fails **before pushing anything**: with `pull_strategy=ff_only` the error code is `git.sync_non_fast_forward`; with `pull_strategy=rebase` (the default) or `pull_strategy=merge` it is `git.sync_failed`, with a message asking you to rebase or merge manually and run `sync` again.

`sync` never merges or rebases. The `pull_strategy` value is accepted and echoed in the output (`pull_strategy`, `mode`, `integration.mode`), but `rebase` and `merge` do **not** perform a rebase or merge. `abort_on_conflict` is accepted but has no effect, because a fast-forward cannot conflict.

Other rules:

* `remote_branch`, if given, must equal the local branch name; a different name is rejected.
* With uncommitted changes, `sync` fails unless `allow_uncommitted=true` or `stash_uncommitted=true`. With `stash_uncommitted=true` the changes are stashed first and popped back afterwards, including when the sync fails.
* `dry_run=true` reports the planned actions (`status: "dry_run"`, `actions: [...]`) without fetching or pushing.
* `sync` takes no credential arguments (`ssh_key`, `username`, `password`, `token` are not read by `sync`). Use `pull` and `push` for remotes that need credentials.
* The result's `integration.status` is `fast_forward` or `up_to_date`.

#### `pull`

`pull` fetches and fast-forwards when the local branch is behind. When the branches have diverged, `ff_only=true` fails with `git.pull_non_fast_forward`; otherwise it fails with `merge operation not yet implemented`. Merging or rebasing during `pull` is not implemented.

#### `merge` and `rebase`

These verbs perform real local integrations with libgit2, but only when called explicitly:

* `merge source=<rev>` fast-forwards when possible; otherwise it creates a merge commit (`no_ff=true` forces one; `squash=true` squashes; `ff_only=true` fails with `git.merge_non_fast_forward` instead). On conflicts it fails with `git.merge_conflict`; with `abort_on_conflict=true` (the default) the working tree is reset to HEAD first.
* `rebase upstream=<rev>` replays the branch onto `upstream`. `operation=continue` and `operation=abort` act on a rebase in progress. On conflicts it fails with `git.rebase_conflict`; with `abort_on_conflict=true` (the default) the rebase is aborted, otherwise it is left in progress for manual resolution. `preserve_merges` and `autosquash` are accepted but **not supported** by libgit2: a warning is logged and a normal rebase is performed.
* Both require a clean working tree unless `allow_uncommitted=true`.

---

### 3.3 Timeouts

Git operations are **not time-limited**. They run as blocking libgit2 calls that cannot be interrupted, so every git verb **rejects** a `timeout_ms` argument with exit code 2 (`git <verb>: timeout_ms is not supported ...`) instead of silently ignoring it. To bound a git step in automation, run `resh` under an external timeout such as `timeout(1)`.

---

### 3.4 Output

Representative example (`status`, from a repository with an upstream):

```json
{
  "alias": "default",
  "backend": "git",
  "branch": {
    "detached": false,
    "head": "e04b8198bc2515e2e86f9b4316f71f2e970c22ba",
    "name": "main",
    "upstream": {
      "name": "origin/main",
      "remote": "origin",
      "ahead_by": 1,
      "behind_by": 0
    }
  },
  "in_progress": {
    "bisect": false,
    "cherry_pick": false,
    "merge": false,
    "rebase": false,
    "revert": false
  },
  "path": "/tmp/repo",
  "working_tree": {
    "clean": false,
    "conflicts": [],
    "ignored": [],
    "staged": [],
    "unstaged": [
      { "path": "README.md", "status": "modified" }
    ],
    "untracked": []
  }
}
```

Counts such as `staged_count` and `unstaged_count` are reported by `status_summary`, not by `status`.

Git output is always printed as pretty-printed JSON written directly to standard output; the global `--json-pretty` flag makes no difference for this handle.

---

### 3.5 Errors

On failure, resh prints a single line to standard error with the error code and message, and exits with status 1:

```text
Error: git.repository_not_found: repository not found: /tmp/repo
```

A rejected `timeout_ms` exits with status 2. No JSON error object is printed.

---

## 4. Functional Domains

### 4.1 Automation Utilities

**Use Cases**

* Automated repository cloning
* Branch creation in pipelines
* Version tagging during release
* Fast-forward sync during deployment

---

### 4.2 Data & State Management

**Use Cases**

* Detecting uncommitted changes
* Checking ahead/behind counts
* Determining merge conflict state
* Reviewing diffs programmatically

Example:

```bash
resh git://default.status_summary path=/repo
```

---

### 4.3 Filesystem & Storage

**Use Cases**

* Managing working directory changes
* Performing staged commits
* Inspecting file-level diffs

Example:

```bash
resh git://default.diff path=/repo mode=index_vs_head
```

---

### 4.4 Network & Remote Operations

**Operations**

* `clone`
* `pull`
* `push`
* `sync`

Authentication, for `clone`, `pull` and `push`, uses the arguments you pass:

* `ssh_key=<file>`: an SSH private key file (no passphrase support; ssh-agent is not used)
* `username=<user>` with `password=<pass>`: HTTPS user/password
* `token=<token>`: HTTPS token, sent as the password

If none of these applies, libgit2's default credential (used for NTLM/Negotiate) is tried. The `git` credential helpers and the system `ssh` binary are not used. `sync` takes no credential arguments (see 3.2).

Example:

```bash
resh git://default.pull path=/repo ssh_key=/home/user/.ssh/id_ed25519
```

---

### 4.5 Packages & Software

The Git handle can be used for:

* Source code retrieval
* Version tracking
* Release tagging
* Repository cloning for software deployment

---

### 4.6 Security & Secrets

* Prefer SSH key or token authentication over passwords.
* Arguments such as `password=` and `token=` appear in the process list and shell history; avoid putting long-lived secrets on the command line.
* Use least-privilege, expiring tokens.

---

### 4.7 System Information

Structured metadata includes:

* Branch information and upstream ahead/behind counts
* Commit OIDs
* File change counts (`status_summary`)
* Conflict indicators
* Merge/rebase/cherry-pick/revert/bisect in-progress state
* Tag metadata

---

## 5. Platform Support

* Linux is the only supported and tested platform.
* The handle uses libgit2 linked into resh; a `git` binary is not required.

---

## 6. Limitations

* `timeout_ms` is rejected for every git verb (see 3.3).
* `clone depth=<n>`: shallow clone is **not supported**; a warning is logged and a full clone is made.
* `clone recursive=true`: submodule cloning is **not implemented**; a warning is logged and submodules are not cloned. The output still echoes `"recursive": true`.
* `pull` cannot merge or rebase diverged branches.
* `sync` only fast-forwards and pushes; it never merges or rebases, and has no credential arguments.
* `rebase preserve_merges=true` and `autosquash=true` have no effect.
* `--json-pretty` has no effect; output is always pretty-printed.
* Each `resh` invocation is a separate process; nothing is kept between invocations.

---

## 7. Operational Best Practices

### Safe Usage Guidelines

* Avoid force push in shared branches.
* Use annotated tags for releases.
* Use `status_summary` before destructive operations.
* Verify a clean working tree before rebase or merge.

### Automation Considerations

* Use the JSON output for CI decision logic.
* Check ahead/behind counts before push.
* Treat a `sync` failure on diverged history as a signal to rebase or merge explicitly (for example with the `rebase` or `merge` verb), then run `sync` again.
* Wrap long network operations in an external `timeout(1)`.

### CI/CD Integration

Typical pipeline sequence:

1. `clone`
2. `status`
3. `commit` (if build artifacts are tracked)
4. `sync` or `push`
5. `tag` for release

Example:

```bash
resh git://default.clone url=https://github.com/user/repo.git path=/repo
resh git://default.sync path=/repo pull_strategy=ff_only
resh git://default.tag path=/repo action=create name=v1.2.0
```

---

## 8. Use Cases by Role

### DevOps Engineers

* Automate repository cloning.
* Manage deployment branches.
* Create and push release tags.
* Integrate Git state checks into CI pipelines.

### SRE Engineers

* Audit repository state before release.
* Detect conflict or divergence conditions.
* Roll back via branch or tag selection.

### AI / Automation Engineers

* Interpret structured repository metadata.
* Use the recommended actions from `status_summary`.
* Trigger workflows based on ahead/behind counts.
* Validate a clean working tree before deployment.

---

## 9. Technical Foundation

* Implemented in Rust on top of libgit2 (`git2` crate); no Git subprocesses are started.
* Fixed verb set; arguments are validated per verb.
* Errors carry a stable code such as `git.sync_non_fast_forward`.
