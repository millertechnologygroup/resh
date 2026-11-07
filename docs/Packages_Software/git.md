# Resource Shell (resh) – Git Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using structured URI-based commands. The `git://` handle works with Git repositories through the **libgit2** library (the `git2` Rust crate). It does not run the `git` binary and does not use Git credential helpers.

### Purpose

The Git handle provides:

* Repository cloning (`clone`), including local repositories and submodules
* Branch listing, creation, deletion, renaming and checkout (`branch`)
* Tag listing, creation and deletion (`tag`)
* Commits (`commit`) and diffs (`diff`)
* Status reporting (`status`, `status_summary`, `status_short`)
* Explicit merges (`merge`) and rebases (`rebase`), run only when you call those verbs
* Remote operations: `pull` (fast-forward only), `push`, and `sync` (fast-forward plus push)

Every verb prints a JSON object on success.

### Resource-Oriented URI Model

```text
resh git://<alias>.<verb> path=<repo-dir> [key=value ...]
```

* **handle**: `git://`
* **alias**: a free-form label (for example `main` or `default`). It is echoed as `alias` in the output. It does not select a repository or credentials.
* **verb**: one of the 13 verbs listed below
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

### 2.1 Arguments

Every verb refuses an argument it does not accept (exit status 2, with a "did you mean" hint for a likely typo), and refuses invalid values (a boolean other than `true|false|1|0|yes|no|on|off`, a non-number where a number is expected, an unknown enum value). Nothing is done in either case. Booleans default to `false` unless stated. List values are comma-separated (`a,b`) or a JSON array.

| Verb | Arguments (defaults in parentheses) |
| ---- | --------- |
| `status` | `path`, `include_untracked` (true), `include_ignored` (false), `include_staged` (true), `include_branch` (true), `include_remote` (true), `timeout_ms` |
| `status_summary` | `path`, `remote` (origin), `branch` (current), `include_untracked` (true), `include_ignored` (false), `include_remote` (true), `compute_diffstats` (false), `max_files` (500, for the diffstats), `timeout_ms` |
| `status_short` | `path`, `branch`, `remote`, `include_remote` (true), `include_dirty` (true), `include_conflicts` (true), `symbols` (JSON object with `detached`, `ahead`, `behind`, `dirty`, `conflict`, `no_upstream`), `timeout_ms` |
| `diff` | `path`, `mode` (`workdir_vs_index`; also `index_vs_head`, `head_vs_workdir`, `commit_vs_commit`, `commit_vs_workdir`, `commit_vs_index`), `from`, `to`, `paths`, `unified` (3), `ignore_whitespace`, `ignore_whitespace_change`, `ignore_whitespace_eol`, `detect_renames` (true), `rename_threshold` (50, 0-100), `binary` (false: binary files are listed without lines), `max_files` (1000), `max_hunks` (10000), `timeout_ms` |
| `branch` | `path`, `action`, `name`, `new_name`, `start_point` (HEAD), `track`, `remote` (origin, with `track=true` only), `local_only`, `remote_only`, `all`, `force`, `timeout_ms` |
| `tag` | `path`, `action`, `name`, `names`, `pattern`, `sort` (`name`; also `version`, `taggerdate`, `committerdate`), `annotated`, `message`, `target` (HEAD), `force`, `author_name`, `author_email`, `timestamp`, `timeout_ms` |
| `commit` | `path`, `message`, `all`, `paths`, `allow_empty`, `amend`, `no_edit`, `signoff`, `author_name`, `author_email`, `committer_name`, `committer_email`, `timestamp`, `timeout_ms` |
| `merge` | `path`, `source`, `target`, `commit_message`, `author_name`, `author_email`, `committer_name`, `committer_email`, `ff_only`, `no_ff`, `squash`, `allow_uncommitted`, `abort_on_conflict` (true), `timeout_ms` |
| `rebase` | `path`, `upstream`, `operation`, `branch`, `author_name`, `author_email`, `committer_name`, `committer_email`, `ff_only`, `preserve_merges` (only `false`), `autosquash` (only `false`), `allow_uncommitted`, `abort_on_conflict` (true), `timeout_ms` |
| `clone` | `url`, `path`, `branch`, `recursive`, `ssh_key`, `known_hosts_path`, `username`, `password`, `token`, `timeout_ms` |
| `pull` | `path`, `remote` (origin), `branch` (current), `ff_only`, `prune`, `ssh_key`, `known_hosts_path`, `username`, `password`, `token`, `timeout_ms` |
| `push` | `path`, `remote` (origin), `branch`, `branches`, `tags`, `force`, `ff_only`, `set_upstream`, `ssh_key`, `known_hosts_path`, `username`, `password`, `token`, `timeout_ms` |
| `sync` | `path`, `remote` (origin), `branch`, `remote_branch`, `pull_strategy` (`rebase`; also `merge`, `ff_only`), `push` (true), `push_tags`, `force_push`, `allow_uncommitted`, `stash_uncommitted`, `abort_on_conflict`, `dry_run`, `known_hosts_path`, `timeout_ms` |

Per-action rules:

* `branch`: `action=list` takes `local_only`, `remote_only` and `all` (at most one of them `true`; with none, local branches are listed; `local_only=false` alone lists local and remote branches). `create` takes `name`, `start_point`, `track`, `remote`, `force` (`force=true` replaces an existing branch that is not checked out). `delete` takes `name`, `force`; without `force` the branch must be merged into its upstream (or into HEAD when it has none), otherwise `git.branch_delete_unmerged`; the checked-out branch is never deleted. `rename` takes `name`, `new_name`, `force`. `checkout` takes `name`, `force`; the working tree is updated with a safe checkout first, so local changes the switch would overwrite fail with `git.branch_checkout_conflict` and HEAD does not move (`force=true` discards them). Any other argument for the action is refused. With `track=true` the remote-tracking branch `<remote>/<name>` must already exist; otherwise nothing is created.
* `tag`: `action=list` takes `pattern` and `sort`; `create` takes `name`, `annotated`, `target`, `force`, and with `annotated=true` also `message` (required), `author_name`, `author_email`, `timestamp`; `delete` takes `name` or `names`.
* `commit` / `tag` `timestamp`: RFC 3339 (`2024-01-02T03:04:05+01:00`) or Unix seconds. `commit amend=true` may reword without new changes.
* `rebase`: `operation=continue` and `operation=abort` do not take `upstream`, `branch`, `ff_only` or `allow_uncommitted`. `author_name` and `author_email` go together and set the author of every rebased commit (without them the original authors are kept). `ff_only=true` only fast-forwards the branch to `upstream` (`git.rebase_non_fast_forward` otherwise).
* `merge` / `rebase` identity: the arguments, then `GIT_AUTHOR_*` / `GIT_COMMITTER_*`, then `user.name` / `user.email` from the repository configuration.

---

## 3. Command Syntax and Execution Model

### 3.1 Example Commands

```bash
resh git://default.clone url=https://github.com/user/repo.git path=/tmp/repo
resh git://default.status path=/tmp/repo
resh git://default.branch path=/tmp/repo action=create name=feature/login
resh git://default.commit path=/tmp/repo 'message=feat(auth): add OAuth2 support' all=true
resh git://default.merge path=/tmp/repo source=feature/login
resh git://default.sync path=/tmp/repo pull_strategy=ff_only push=true
```

---

### 3.2 Remote Synchronization Semantics

#### `sync`

`sync` supports **fast-forward synchronization only**, on the checked-out branch:

* If the local branch is **behind** its remote branch, it is fast-forwarded.
* If it is **only ahead**, nothing is integrated and the branch is pushed (when `push=true`, the default).
* If both sides have new commits (**diverged history**), `sync` fails **before pushing anything**: with `pull_strategy=ff_only` the error code is `git.sync_non_fast_forward`; with `pull_strategy=rebase` (the default) or `pull_strategy=merge` it is `git.sync_failed`, with a message asking you to rebase or merge manually and run `sync` again.

`sync` never merges or rebases. The `pull_strategy` value is accepted and echoed in the output (`pull_strategy`, `mode`, `integration.mode`), but `rebase` and `merge` do **not** perform a rebase or merge. `abort_on_conflict` is accepted and checked but changes nothing, because a fast-forward cannot conflict.

Other rules:

* `branch`, if given, must be the checked-out branch (`git.sync_failed` otherwise; `git.sync_branch_not_found` when it does not exist). A detached HEAD fails with `git.sync_detached_head`.
* `remote_branch`, if given, must equal the local branch name; a different name is rejected (exit 2).
* A missing remote fails with `git.sync_remote_not_found` before anything changes.
* With uncommitted changes, `sync` fails with `git.sync_dirty_worktree` unless `allow_uncommitted=true` or `stash_uncommitted=true`. With `stash_uncommitted=true` the changes (untracked files included) are stashed first and popped back afterwards, including when the sync fails; `stash.conflicts_on_apply` reports a stash that could not be re-applied (it is then kept).
* `dry_run=true` reports the planned actions (`status: "dry_run"`, `actions: [...]`) without stashing, fetching or pushing.
* `sync` takes no credential arguments (`ssh_key`, `username`, `password`, `token` are refused). Use `pull` and `push` for remotes that need credentials. It does accept `known_hosts_path=<file>` (see 4.4), which applies to both its fetch and its push.
* The result's `integration.status` is `fast_forward` or `up_to_date`.

#### `pull`

`pull` fetches the remote (with its configured refspecs; `prune=true` also deletes remote-tracking branches that no longer exist on the remote) and fast-forwards the local branch when it is behind. When the branch is the checked-out one, the working tree is updated with a safe checkout: a local change that the update would overwrite fails with `git.pull_dirty_worktree` and nothing moves; other local changes are kept. When the branches have diverged, `ff_only=true` fails with `git.pull_non_fast_forward`; otherwise it fails with `git.pull_failed` (`merge operation not yet implemented`). Merging or rebasing during `pull` is not implemented.

#### `push`

`push` pushes `refs/heads/<branch>` for each branch (`force=true` forces), and with `tags=true` every local tag. A reference the remote refuses (for example a non-fast-forward update) fails with `git.push_rejected`, even though libgit2 reports the push itself as complete. `ff_only=true` fails with `git.push_non_fast_forward` before pushing when the remote-tracking branch has commits the local one lacks. `set_upstream=true` sets `<remote>/<branch>` as the upstream of each pushed branch.

#### `merge` and `rebase`

These verbs perform real local integrations with libgit2, but only when called explicitly:

* `merge source=<rev>` fast-forwards when possible; otherwise it creates a merge commit (`no_ff=true` forces one; `squash=true` squashes; `ff_only=true` fails with `git.merge_non_fast_forward` instead). On conflicts it fails with `git.merge_conflict`; with `abort_on_conflict=true` (the default) the working tree is reset to HEAD first.
* `rebase upstream=<rev>` replays the branch onto `upstream`. `operation=continue` and `operation=abort` act on a rebase in progress. On conflicts it fails with `git.rebase_conflict`; with `abort_on_conflict=true` (the default) the rebase is aborted, otherwise it is left in progress for manual resolution. `preserve_merges=true` (`git.rebase_preserve_merges_unsupported`) and `autosquash=true` (`git.invalid_rebase_config`) are refused with exit status 2: libgit2 cannot do either.
* Both require a clean working tree unless `allow_uncommitted=true` (`git.merge_dirty_worktree`, `git.rebase_dirty_worktree`).

---

### 3.3 Timeouts

Every verb accepts `timeout_ms` (1 to 2147483647). Defaults:

| Verbs | Default |
| ----- | ------- |
| `clone`, `pull`, `push`, `sync` | 600000 ms (10 minutes) |
| all other verbs | no limit |

The verb runs on a worker thread under the deadline. For remote verbs, every libgit2 transfer callback checks the deadline, and libgit2's connect and read timeouts are set from it, so a slow or silent HTTP(S) or `git://` server is stopped at the deadline. At the deadline the verb fails with `git.<verb>_timeout` and exit status **124**; the message says whether the operation was **stopped** (it ended; a failed clone has removed its directory and any parent directories it created) or **could not be stopped** (outcome unknown, for example an SSH server that stalls inside the SSH library, or a long local operation such as a status walk). The error details carry `timeout_ms` and `outcome` (`stopped` or `unknown`). Check the repository before retrying.

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

Counts such as `staged_count` and `unstaged_count` are reported by `status_summary`, not by `status`. Output is always pretty-printed JSON.

---

### 3.5 Errors and exit status

On failure, resh prints one line to standard error and nothing to standard output:

```text
Error: [git.repository_not_found] repository not found: /tmp/repo
```

| Exit status | Meaning |
| ----------- | ------- |
| 0 | success |
| 1 | the operation failed (not found, refused, libgit2 or remote error) |
| 2 | invalid usage or arguments; nothing was done (`git.invalid_*`, `git.sync_invalid_config`, `git.rebase_preserve_merges_unsupported`) |
| 124 | `timeout_ms` passed (`git.<verb>_timeout`) |

Error codes:

| Code | Exit | When |
| ---- | ---- | ---- |
| `git.invalid_verb` | 2 | unknown verb |
| `git.invalid_status_config`, `git.invalid_status_summary_config`, `git.invalid_status_short_config`, `git.invalid_diff_config`, `git.invalid_branch_config`, `git.invalid_tag_config`, `git.invalid_commit_config`, `git.invalid_merge_config`, `git.invalid_rebase_config`, `git.invalid_clone_config`, `git.invalid_pull_config`, `git.invalid_push_config`, `git.sync_invalid_config` | 2 | unknown argument, missing or invalid value, conflicting options |
| `git.rebase_preserve_merges_unsupported` | 2 | `preserve_merges=true` |
| `git.status_timeout`, `git.status_summary_timeout`, `git.status_short_timeout`, `git.diff_timeout`, `git.branch_timeout`, `git.tag_timeout`, `git.commit_timeout`, `git.merge_timeout`, `git.rebase_timeout`, `git.clone_timeout`, `git.pull_timeout`, `git.push_timeout`, `git.sync_timeout` | 124 | `timeout_ms` passed |
| `git.repository_not_found` | 1 | `path` is not a repository |
| `git.remote_not_found` | 1 | `pull` / `push`: no such remote |
| `git.host_key_verification_failed` | 1 | SSH host key refused (see 4.4) |
| `git.status_failed`, `git.status_summary_failed`, `git.status_short_failed`, `git.diff_failed`, `git.branch_failed`, `git.tag_failed`, `git.commit_failed`, `git.merge_failed`, `git.rebase_failed`, `git.clone_failed`, `git.pull_failed`, `git.push_failed`, `git.sync_failed` | 1 | other failure of the verb (libgit2 error, diverged `pull`, branch not checked out for `sync`) |
| `git.status_summary_branch_not_found`, `git.status_short_branch_not_found` | 1 | `branch=` does not exist |
| `git.diff_ref_not_found`, `git.diff_head_not_found` | 1 | a revision does not resolve; the repository has no commits |
| `git.branch_not_found`, `git.branch_already_exists`, `git.branch_startpoint_not_found` | 1 | branch lookups |
| `git.branch_delete_current`, `git.branch_delete_unmerged`, `git.branch_delete_failed` | 1 | `action=delete` |
| `git.branch_rename_failed`, `git.branch_set_upstream_failed` | 1 | `action=rename`; `track=true` without `<remote>/<name>` |
| `git.branch_checkout_conflict`, `git.branch_checkout_failed` | 1 | `action=checkout` |
| `git.tag_already_exists`, `git.tag_not_found`, `git.tag_target_not_found`, `git.tag_identity_missing` | 1 | tag lookups; no tagger identity |
| `git.tag_list_failed`, `git.tag_create_failed`, `git.tag_delete_failed` | 1 | libgit2 error for the action |
| `git.commit_nothing_to_commit`, `git.commit_identity_missing` | 1 | nothing staged (and `allow_empty=false`); no author identity |
| `git.commit_amend_without_head`, `git.commit_amend_failed` | 1 | `amend=true` without a commit; amend failed |
| `git.merge_source_not_found`, `git.merge_source_not_commit`, `git.merge_target_not_found`, `git.merge_detached_head` | 1 | merge lookups |
| `git.merge_dirty_worktree`, `git.merge_non_fast_forward`, `git.merge_conflict`, `git.merge_identity_missing` | 1 | merge refused |
| `git.rebase_in_progress`, `git.rebase_not_in_progress`, `git.rebase_detached_head` | 1 | rebase state |
| `git.rebase_branch_not_found`, `git.rebase_upstream_not_found`, `git.rebase_upstream_not_commit` | 1 | rebase lookups |
| `git.rebase_dirty_worktree`, `git.rebase_non_fast_forward`, `git.rebase_conflict`, `git.rebase_identity_missing` | 1 | rebase refused |
| `git.clone_target_not_empty`, `git.clone_auth_failed` | 1 | clone refused; credentials rejected |
| `git.pull_detached_head`, `git.pull_remote_branch_not_found`, `git.pull_fetch_failed`, `git.pull_auth_failed` | 1 | pull |
| `git.pull_dirty_worktree`, `git.pull_non_fast_forward` | 1 | pull refused |
| `git.push_detached_head`, `git.push_local_branch_not_found`, `git.push_non_fast_forward`, `git.push_rejected`, `git.push_auth_failed` | 1 | push |
| `git.sync_detached_head`, `git.sync_branch_not_found`, `git.sync_remote_not_found`, `git.sync_dirty_worktree`, `git.sync_non_fast_forward` | 1 | sync refused |
| `git.sync_pull_failed`, `git.sync_push_failed`, `git.sync_push_rejected`, `git.sync_stash_apply_conflict` | 1 | sync fetch or push failed; the stash could not be restored |

---

## 4. Functional Domains

### 4.1 Automation Utilities

* Automated repository cloning
* Branch creation in pipelines
* Version tagging during release
* Fast-forward sync during deployment

### 4.2 Data & State Management

* Detecting uncommitted changes
* Checking ahead/behind counts
* Determining merge conflict state
* Reviewing diffs programmatically

```bash
resh git://default.status_summary path=/repo
```

### 4.3 Filesystem & Storage

* Managing working directory changes
* Performing staged commits
* Inspecting file-level diffs

```bash
resh git://default.diff path=/repo mode=index_vs_head
```

---

### 4.4 Network & Remote Operations

**Operations**: `clone`, `pull`, `push`, `sync`.

**Clone URLs.** `clone` accepts `https://`, `http://`, `ssh://`, `git+ssh://`, `ssh+git://`, `git://` and `file://` URLs, the scp-like `[user@]host:path` SSH form, and the path of an existing local repository directory. Anything else (another scheme, a value starting with `-`, a path that does not exist) is refused with exit status 2 before anything is created. `depth=<n>` is refused with exit status 2 (`git.invalid_clone_config`): the linked libgit2 1.7 cannot make shallow clones that current git servers accept, so a full clone is the only kind. `recursive=true` also clones every submodule, recursively, with the same credentials and host-key checking. `path` must be missing or an empty directory (`git.clone_target_not_empty`); missing parent directories are created and removed again if the clone fails.

**Authentication**, for `clone`, `pull` and `push`, uses the arguments you pass (at most one method):

* `ssh_key=<file>`: an SSH private key file (no passphrase support; ssh-agent is not used)
* `username=<user>` with `password=<pass>`: HTTPS user/password
* `token=<token>`: HTTPS token, sent as the password (with `username` when given)

If none of these applies, libgit2's default credential (used for NTLM/Negotiate) is tried. After three rejected attempts the operation fails with `git.<verb>_auth_failed`. The `git` credential helpers and the system `ssh` binary are not used. `sync` takes no credential arguments (see 3.2).

```bash
resh git://default.pull path=/repo ssh_key=/home/user/.ssh/id_ed25519
```

#### SSH host-key checking (`known_hosts_path`)

`clone`, `pull`, `push` and `sync` accept `known_hosts_path=<file>`, an OpenSSH `known_hosts` file. The check applies when the URL libgit2 **actually connects to** uses SSH (`ssh://`, `git+ssh://`, `ssh+git://` or the scp-like `user@host:path` form). That is the URL after `url.<base>.insteadOf` rewriting (and `url.<base>.pushInsteadOf` for `push`) from the repository, global and system configuration, so an `https://` remote that a rewrite turns into SSH is checked too. As a last safeguard, an SSH connection to a remote that was not recognized as SSH is refused. The check is **strict**:

* Before connecting, the file is read and the host must have at least one plain key entry. A missing or unreadable file, or a host that is not listed, is refused without connecting.
* The SSH library is told to ask the server only for the **key types listed for that host** in the file (for example only `ecdsa-sha2-nistp256` when that is the only listed type), so a file that lists only some of the host's key types works.
* During the SSH handshake the server's host key (key type and key data) must equal one of the keys listed for that host. Any other key is refused; nothing is ever added to the file.
* A key listed for the host under `@revoked` is refused, even when it is also listed as a plain entry.
* `@cert-authority` lines are not supported and are never used to accept a key. A host covered only by `@cert-authority` lines is refused with a message saying that CA-signed host keys are not supported.

Every refusal fails with the error code `git.host_key_verification_failed`; the message names the host (as `host`, or `[host]:port` for ports other than 22) and the reason, and the error details carry `host` and `known_hosts_path`. Nothing is fetched, pushed or cloned. When the server offers none of the listed key types, the message names the host key types the server offers and the types the file lists, and suggests the `ssh-keyscan -t <type>` command for the missing key. When the server presents a key type the file does not list, the message names both as well.

The SSH library can only be steered to `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521` and `ssh-rsa`. An `ssh-rsa` entry makes it ask for the legacy `ssh-rsa` (SHA-1) signature, which current OpenSSH servers no longer offer; list the host's ed25519 or ECDSA key instead (the error message says so).

Supported file syntax: plain host names and IP addresses, comma-separated lists, `[host]:port` for ports other than 22, hashed entries (`|1|salt|hash`, as written by `ssh-keygen -H` or `HashKnownHosts yes`), `*` and `?` wildcards, `!` negation (a matching negated pattern excludes the host), and `#` comments. Host names are compared case-insensitively. Malformed lines and unknown `@` markers are skipped, not treated as errors. The port comes from the remote URL.

For remotes that do not use SSH (`https://`, `http://`, `git://`, `file://`, local paths) the option has no meaning and is ignored, whether or not the file exists. For `pull` and `push` the remote's configured URL (for `push`, its push URL when set) after rewriting decides.

Without `known_hosts_path`, host keys are handled by libgit2's own default (on Linux, `~/.ssh/known_hosts`).

To build the file, record the host's keys over a trusted network path and compare their fingerprints with the ones the hosting provider publishes:

```bash
ssh-keyscan -p 22 git.example.com > /etc/resh/git_known_hosts
ssh-keygen -lf /etc/resh/git_known_hosts
resh git://default.pull path=/repo ssh_key=/home/user/.ssh/id_ed25519 known_hosts_path=/etc/resh/git_known_hosts
```

---

### 4.5 Packages & Software

* Source code retrieval
* Version tracking
* Release tagging
* Repository cloning for software deployment

### 4.6 Security & Secrets

* Prefer SSH key or token authentication over passwords.
* For SSH remotes, pass `known_hosts_path=<file>` to pin the server's host keys (see 4.4).
* Arguments such as `password=` and `token=` appear in the process list and shell history; avoid putting long-lived secrets on the command line.
* Use least-privilege, expiring tokens.

### 4.7 System Information

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

* `pull` and `sync` only fast-forward; they never merge or rebase. `sync` has no credential arguments; its `pull_strategy=rebase|merge` and `abort_on_conflict` are accepted but change nothing (see 3.2).
* `rebase preserve_merges=true` and `autosquash=true` are refused (libgit2 supports neither).
* `clone depth=<n>` (shallow clone) is refused: libgit2 1.7's shallow fetch fails against current git servers.
* `known_hosts_path` does not support `@cert-authority` (CA-signed host keys); the host's own keys must be listed. An RSA-only entry does not work with current OpenSSH servers (see 4.4).
* A timeout cannot interrupt an SSH server that stalls inside the SSH library, or a long local libgit2 call; the verb then reports exit 124 with outcome unknown (see 3.3).
* Each `resh` invocation is a separate process; nothing is kept between invocations.

---

## 7. Operational Best Practices

* Avoid force push in shared branches.
* Use annotated tags for releases.
* Use `status_summary` before destructive operations.
* Verify a clean working tree before rebase or merge.
* Use the JSON output for CI decision logic; check ahead/behind counts before push.
* Treat a `sync` failure on diverged history as a signal to rebase or merge explicitly (with the `rebase` or `merge` verb), then run `sync` again.
* Set `timeout_ms` for network operations in automation.

Typical pipeline:

```bash
resh git://default.clone url=https://github.com/user/repo.git path=/repo
resh git://default.sync path=/repo pull_strategy=ff_only
resh git://default.tag path=/repo action=create name=v1.2.0
```

---

## 8. Technical Foundation

* Implemented in Rust on top of libgit2 (`git2` crate); no Git subprocesses are started.
* Fixed verb set; arguments are validated per verb against one list in the source, which the help and tests check.
* Errors carry a stable code such as `git.sync_non_fast_forward`.
