use anyhow::Result;
use chrono;
use git2::{
    BranchType, Commit, FetchOptions, Index, Oid, RemoteCallbacks, Repository, Signature,
    Status as GitStatus, Time,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use thiserror::Error;
use url::Url;

mod args;
mod integrate;
mod known_hosts;
mod net;
#[cfg(test)]
mod verb_tests;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::Status,
};

/// Metadata for `resh git --help` and `resh git <verb> --help`.
static GIT_HELP: HandleHelp = HandleHelp {
    description: "The git handle works with Git repositories through libgit2, covering \
        status queries, branches, tags, diffs, commits, merges, rebases, and remote clone, \
        pull, push, and sync, in the directory given with path (the URL host, such as \
        git://main, is a free-form alias that labels the output). Unknown arguments are \
        refused, and boolean, numeric, and list options take text values such as true, \
        5000, or a,b. Every verb takes timeout_ms (clone, pull, push, and sync default to \
        600000 ms, the other verbs have no limit), and the exit status is 0 on success, \
        1 on failure, 2 for invalid arguments, and 124 on timeout.",
    usage: "resh git://<alias>.<verb> path=<repo-dir> [key=value ...]",
    verbs: &[
        VerbHelp {
            name: "status",
            definition: "Reports the current branch and upstream, the staged, unstaged, \
                untracked, and conflicted files, and any operation in progress.",
            detail: Some(VerbDetail {
                usage: "resh git://<alias>.status path=<repo-dir>\n  \
                    [include_untracked=true|false] [include_ignored=true|false]\n  \
                    [include_staged=true|false] [include_branch=true|false]\n  \
                    [include_remote=true|false] [timeout_ms=<ms>]",
                example: "resh --json-pretty git://main.status path=/srv/app",
                example_output: Some(
                    r#"{
  "alias": "main",
  "backend": "git",
  "branch": {
    "detached": false,
    "head": "e04b8198bc2515e2e86f9b4316f71f2e970c22ba",
    "name": "main",
    "upstream": null
  },
  "in_progress": {
    "bisect": false,
    "cherry_pick": false,
    "merge": false,
    "rebase": false,
    "revert": false
  },
  "path": "/srv/app",
  "working_tree": {
    "clean": false,
    "conflicts": [],
    "ignored": [],
    "staged": [],
    "unstaged": [
      {
        "path": "README.md",
        "status": "modified"
      }
    ],
    "untracked": [
      {
        "path": "notes.txt",
        "status": "untracked"
      }
    ]
  }
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "status_summary",
            definition: "Summarizes repository state as file counts, a sync state, and a \
                recommended next action.",
            detail: Some(VerbDetail {
                usage: "resh git://<alias>.status_summary path=<repo-dir> [remote=<name>]\n  \
                    [branch=<name>] [include_untracked=true|false]\n  \
                    [include_ignored=true|false] [include_remote=true|false]\n  \
                    [compute_diffstats=true|false] [max_files=<n>] [timeout_ms=<ms>]",
                example: "resh --json-pretty git://main.status_summary path=/srv/app",
                example_output: Some(
                    r#"{
  "action": "status_summary",
  "alias": "main",
  "backend": "git",
  "branch": {
    "detached": false,
    "has_commits": true,
    "head": "e04b8198bc2515e2e86f9b4316f71f2e970c22ba",
    "name": "main",
    "upstream": null
  },
  "diffstats": null,
  "path": "/srv/app",
  "recommendation": {
    "actions": [
      "commit_changes",
      "sync_with_remote"
    ],
    "description": "Commit your local changes and sync with remote.",
    "primary_action": "commit"
  },
  "summary": {
    "blocked_by_conflicts": false,
    "can_commit": false,
    "has_uncommitted_changes": true,
    "needs_pull": false,
    "needs_push": false,
    "state": "local_changes_only"
  },
  "working_tree": {
    "clean": false,
    "conflicts_count": 0,
    "ignored_count": 0,
    "in_progress": {
      "bisect": false,
      "cherry_pick": false,
      "merge": false,
      "rebase": false,
      "revert": false
    },
    "staged_count": 0,
    "unstaged_count": 1,
    "untracked_count": 1
  }
}

Shown for a branch without an upstream with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "status_short",
            definition: "Builds a compact one-line status string for shell prompts from the \
                branch name, ahead and behind counts, and dirty and conflict markers.",
            detail: Some(VerbDetail {
                usage: "resh git://<alias>.status_short path=<repo-dir> [branch=<name>]\n  \
                    [remote=<name>] [include_remote=true|false]\n  \
                    [include_dirty=true|false] [include_conflicts=true|false]\n  \
                    [symbols=<json-object>] [timeout_ms=<ms>]",
                example: "resh --json-pretty git://main.status_short path=/srv/app",
                example_output: Some(
                    r#"{
  "action": "status_short",
  "alias": "main",
  "backend": "git",
  "components": {
    "ahead": 0,
    "behind": 0,
    "branch": "main",
    "clean": false,
    "detached": false,
    "has_conflicts": false,
    "has_upstream": true
  },
  "path": "/srv/app",
  "summary": "main*"
}

Shown for a modified branch level with its upstream, with --json-pretty.
The ahead, behind, conflict, and no-upstream markers are Unicode symbols."#,
                ),
            }),
        },
        VerbHelp {
            name: "diff",
            definition: "Compares the working tree, index, HEAD, or commits and reports each \
                changed file with its hunks and lines.",
            detail: Some(VerbDetail {
                usage: "resh git://<alias>.diff path=<repo-dir> [mode=<mode>] [from=<rev>]\n  \
                    [to=<rev>] [paths=<p1,p2,...>] [unified=<n>]\n  \
                    [ignore_whitespace=true|false] [ignore_whitespace_change=true|false]\n  \
                    [ignore_whitespace_eol=true|false] [detect_renames=true|false]\n  \
                    [rename_threshold=<0-100>] [binary=true|false] [max_files=<n>]\n  \
                    [max_hunks=<n>] [timeout_ms=<ms>]\n  \
                    mode: workdir_vs_index (default), index_vs_head, head_vs_workdir,\n  \
                    commit_vs_commit, commit_vs_workdir, commit_vs_index",
                example: "resh --json-pretty git://main.diff path=/srv/app mode=head_vs_workdir",
                example_output: Some(
                    r##"{
  "alias": "main",
  "backend": "git",
  "files": [
    {
      "hunks": [
        {
          "lines": [
            {
              "content": "# app",
              "type": "context"
            },
            {
              "content": "Run make to build.",
              "type": "add"
            }
          ],
          "new_lines": 2,
          "new_start": 1,
          "old_lines": 1,
          "old_start": 1
        }
      ],
      "is_binary": false,
      "new_path": "README.md",
      "old_path": "README.md",
      "status": "modified"
    }
  ],
  "from": "HEAD",
  "mode": "head_vs_workdir",
  "path": "/srv/app",
  "summary": {
    "deletions": 0,
    "files_changed": 1,
    "insertions": 1,
    "truncated": false
  },
  "to": "WORKDIR"
}

Shown with --json-pretty."##,
                ),
            }),
        },
        VerbHelp {
            name: "branch",
            definition: "Lists, creates, deletes, renames, or checks out branches, listing \
                local branches when no action is given.",
            detail: Some(VerbDetail {
                usage: "resh git://<alias>.branch path=<repo-dir>\n  \
                    [action=list|create|delete|rename|checkout] [name=<branch>]\n  \
                    [new_name=<branch>] [start_point=<rev>] [track=true|false]\n  \
                    [remote=<name>] [local_only=true|false] [remote_only=true|false]\n  \
                    [all=true|false] [force=true|false] [timeout_ms=<ms>]",
                example: "resh --json-pretty git://main.branch path=/srv/app",
                example_output: Some(
                    r#"{
  "action": "list",
  "alias": "main",
  "backend": "git",
  "branches": [
    {
      "full_ref": "refs/heads/main",
      "head": "e04b8198bc2515e2e86f9b4316f71f2e970c22ba",
      "is_current": true,
      "is_remote": false,
      "name": "main",
      "upstream": null
    }
  ],
  "path": "/srv/app"
}

Shown for action=list with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "tag",
            definition: "Lists, creates, or deletes tags, listing all tags sorted by name \
                when no action is given.",
            detail: Some(VerbDetail {
                usage: "resh git://<alias>.tag path=<repo-dir> [action=list|create|delete]\n  \
                    [name=<tag>] [names=<t1,t2,...>] [pattern=<glob>]\n  \
                    [sort=name|version|taggerdate|committerdate]\n  \
                    [annotated=true|false] [message=<text>] [target=<rev>]\n  \
                    [force=true|false] [author_name=<name>] [author_email=<email>]\n  \
                    [timestamp=<iso8601|unix-seconds>] [timeout_ms=<ms>]",
                example: "resh --json-pretty git://main.tag path=/srv/app",
                example_output: Some(
                    r#"{
  "action": "list",
  "alias": "main",
  "backend": "git",
  "count": 1,
  "path": "/srv/app",
  "pattern": null,
  "sort": "name",
  "tags": [
    {
      "annotated": false,
      "message": null,
      "name": "v1.0.0",
      "tagger": null,
      "target": {
        "oid": "e04b8198bc2515e2e86f9b4316f71f2e970c22ba",
        "type": "commit"
      }
    }
  ]
}

Shown for action=list with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "commit",
            definition: "Creates a commit from the staged changes, first staging tracked \
                changes when all=true and the listed paths when paths is given.",
            detail: Some(VerbDetail {
                usage: "resh git://<alias>.commit path=<repo-dir> message=<text>\n  \
                    [all=true|false] [paths=<p1,p2,...>] [allow_empty=true|false]\n  \
                    [amend=true|false] [no_edit=true|false] [signoff=true|false]\n  \
                    [author_name=<name>] [author_email=<email>]\n  \
                    [committer_name=<name>] [committer_email=<email>]\n  \
                    [timestamp=<iso8601|unix-seconds>] [timeout_ms=<ms>]",
                example: "resh --json-pretty git://main.commit path=/srv/app 'message=Fix typo'",
                example_output: Some(
                    r#"{
  "action": "commit",
  "alias": "main",
  "backend": "git",
  "commit": {
    "allow_empty": false,
    "amend": false,
    "author": {
      "email": "alice@example.com",
      "name": "Alice"
    },
    "committer": {
      "email": "alice@example.com",
      "name": "Alice"
    },
    "message": "Fix typo",
    "oid": "9f3c2a1b7d4e5f60718293a4b5c6d7e8f9012345"
  },
  "path": "/srv/app",
  "stats": {
    "deletions": null,
    "insertions": null,
    "staged_files": 0
  }
}

Shown with --json-pretty. staged_files counts only files staged by this call."#,
                ),
            }),
        },
        VerbHelp {
            name: "merge",
            definition: "Merges a source branch or commit into the current or target branch, \
                fast-forwarding when possible.",
            detail: Some(VerbDetail {
                usage: "resh git://<alias>.merge path=<repo-dir> source=<rev>\n  \
                    [target=<branch>] [commit_message=<text>] [author_name=<name>]\n  \
                    [author_email=<email>] [committer_name=<name>]\n  \
                    [committer_email=<email>] [ff_only=true|false] [no_ff=true|false]\n  \
                    [squash=true|false] [allow_uncommitted=true|false]\n  \
                    [abort_on_conflict=true|false] [timeout_ms=<ms>]",
                example: "resh --json-pretty git://main.merge path=/srv/app source=feature",
                example_output: Some(
                    r#"{
  "action": "merge",
  "alias": "main",
  "backend": "git",
  "commit": {
    "message": null,
    "oid": "9f3c2a1b7d4e5f60718293a4b5c6d7e8f9012345"
  },
  "ff_only": false,
  "mode": "fast_forward",
  "no_ff": false,
  "path": "/srv/app",
  "source": "feature",
  "squash": false,
  "status": "fast_forward",
  "target": "main"
}

Shown for a fast-forward merge with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "rebase",
            definition: "Rebases a branch onto an upstream revision, or continues or aborts \
                a rebase in progress.",
            detail: Some(VerbDetail {
                usage: "resh git://<alias>.rebase path=<repo-dir> upstream=<rev>\n  \
                    [operation=start|continue|abort] [branch=<branch>]\n  \
                    [author_name=<name>] [author_email=<email>]\n  \
                    [committer_name=<name>] [committer_email=<email>]\n  \
                    [ff_only=true|false] [preserve_merges=false] [autosquash=false]\n  \
                    [allow_uncommitted=true|false] [abort_on_conflict=true|false]\n  \
                    [timeout_ms=<ms>]",
                example: "resh --json-pretty git://main.rebase path=/srv/app upstream=main",
                example_output: Some(
                    r#"{
  "action": "rebase",
  "alias": "main",
  "autosquash": false,
  "backend": "git",
  "branch": "feature",
  "ff_only": false,
  "mode": "normal",
  "operation": "start",
  "path": "/srv/app",
  "preserve_merges": false,
  "status": "rebased",
  "summary": {
    "commits_rebased": 2,
    "new_base": "7a1d9e0c3b5f4a2e8d6c1b0a9f8e7d6c5b4a3f21",
    "old_base": "e04b8198bc2515e2e86f9b4316f71f2e970c22ba"
  },
  "upstream": "main"
}

Shown for operation=start with --json-pretty. upstream is not required for
operation=continue or operation=abort."#,
                ),
            }),
        },
        VerbHelp {
            name: "clone",
            definition: "Clones a remote repository into a new or empty local directory.",
            detail: Some(VerbDetail {
                usage: "resh git://<alias>.clone url=<repo-url> path=<dir> [branch=<name>]\n  \
                    [depth=<n>] [recursive=true|false] [ssh_key=<file>]\n  \
                    [known_hosts_path=<file>] [username=<user>] [password=<pass>]\n  \
                    [token=<token>] [timeout_ms=<ms>]",
                example: "resh git://main.clone url=https://example.com/app.git path=/srv/app",
                example_output: Some(
                    r#"{
  "alias": "main",
  "backend": "git",
  "branch": null,
  "depth": null,
  "path": "/srv/app",
  "recursive": false,
  "status": "cloned",
  "url": "https://example.com/app.git"
}"#,
                ),
            }),
        },
        VerbHelp {
            name: "pull",
            definition: "Fetches from a remote and fast-forwards the local branch, or \
                integrates diverged history with a merge commit (or a rebase with \
                rebase=true), restoring the repository on conflicts.",
            detail: Some(VerbDetail {
                usage: "resh git://<alias>.pull path=<repo-dir> [remote=<name>]\n  \
                    [branch=<name>] [ff_only=true|false] [rebase=true|false]\n  \
                    [abort_on_conflict=true|false] [author_name=<name>]\n  \
                    [author_email=<email>] [prune=true|false]\n  \
                    [ssh_key=<file>] [known_hosts_path=<file>] [username=<user>]\n  \
                    [password=<pass>] [token=<token>] [timeout_ms=<ms>]",
                example: "resh --json-pretty git://main.pull path=/srv/app remote=origin",
                example_output: Some(
                    r#"{
  "ahead_by": 0,
  "alias": "main",
  "backend": "git",
  "behind_by": 3,
  "branch": "main",
  "commits_fetched": 3,
  "ff_only": false,
  "path": "/srv/app",
  "rebase": false,
  "remote": "origin",
  "status": "updated"
}

Shown for a fast-forward pull with --json-pretty. An up-to-date branch
reports status up_to_date; diverged history reports merged or rebased
and the new commit."#,
                ),
            }),
        },
        VerbHelp {
            name: "push",
            definition: "Pushes the named branch, or the current branch by default, to a \
                remote and reports each branch's ahead and behind counts.",
            detail: Some(VerbDetail {
                usage: "resh git://<alias>.push path=<repo-dir> [remote=<name>]\n  \
                    [branch=<name>] [branches=<b1,b2,...>] [tags=true|false]\n  \
                    [force=true|false] [ff_only=true|false]\n  \
                    [set_upstream=true|false] [ssh_key=<file>]\n  \
                    [known_hosts_path=<file>] [username=<user>] [password=<pass>]\n  \
                    [token=<token>] [timeout_ms=<ms>]",
                example: "resh --json-pretty git://main.push path=/srv/app branch=main",
                example_output: Some(
                    r#"{
  "alias": "main",
  "backend": "git",
  "branches": [
    {
      "ahead_by": 2,
      "behind_by": 0,
      "name": "main",
      "status": "pushed"
    }
  ],
  "path": "/srv/app",
  "remote": "origin",
  "tags_pushed": false
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "sync",
            definition: "Fetches from a remote, brings the current branch up to date by \
                fast-forward or, when the histories have diverged, by the pull_strategy \
                (rebase, merge, or ff_only), and then pushes it, pushing nothing when that \
                fails.",
            detail: Some(VerbDetail {
                usage: "resh git://<alias>.sync path=<repo-dir> [remote=<name>]\n  \
                    [branch=<name>] [remote_branch=<name>]\n  \
                    [pull_strategy=rebase|merge|ff_only] [push=true|false]\n  \
                    [push_tags=true|false] [force_push=true|false]\n  \
                    [allow_uncommitted=true|false] [stash_uncommitted=true|false]\n  \
                    [abort_on_conflict=true|false] [author_name=<name>]\n  \
                    [author_email=<email>] [dry_run=true|false]\n  \
                    [known_hosts_path=<file>] [timeout_ms=<ms>]",
                example: "resh --json-pretty git://main.sync path=/srv/app pull_strategy=rebase",
                example_output: None,
            }),
        },
    ],
};

/// Git handle implementation
#[derive(Debug)]
pub struct GitHandle {
    alias: String,
}

/// Clone configuration structure
#[derive(Debug, Clone, Deserialize)]
pub struct CloneConfig {
    pub url: String,
    pub path: String,
    pub branch: Option<String>,
    pub depth: Option<u32>,
    pub recursive: Option<bool>,
    pub ssh_key: Option<String>,
    pub known_hosts_path: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
    pub timeout_ms: Option<u32>,
}

/// Pull configuration structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PullConfig {
    pub path: String,
    pub remote: Option<String>,
    pub branch: Option<String>,
    pub rebase: Option<bool>,
    pub ff_only: Option<bool>,
    pub abort_on_conflict: Option<bool>,
    pub author_name: Option<String>,
    pub author_email: Option<String>,
    pub prune: Option<bool>,
    pub ssh_key: Option<String>,
    pub known_hosts_path: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
    pub timeout_ms: Option<u64>,
}

/// Push configuration structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PushConfig {
    pub path: String,
    pub remote: Option<String>,
    pub branch: Option<String>,
    pub branches: Option<Vec<String>>,
    pub tags: Option<bool>,
    pub force: Option<bool>,
    pub ff_only: Option<bool>,
    pub set_upstream: Option<bool>,
    pub ssh_key: Option<String>,
    pub known_hosts_path: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
    pub timeout_ms: Option<u64>,
}

/// Status configuration structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StatusConfig {
    pub path: String,
    pub include_ignored: Option<bool>,
    pub include_untracked: Option<bool>,
    pub include_staged: Option<bool>,
    pub include_branch: Option<bool>,
    pub include_remote: Option<bool>,
    pub timeout_ms: Option<u64>,
}

/// Status short configuration structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StatusShortConfig {
    pub path: String,
    pub branch: Option<String>,
    pub remote: Option<String>,
    pub include_remote: Option<bool>,
    pub include_dirty: Option<bool>,
    pub include_conflicts: Option<bool>,
    pub symbols: Option<StatusShortSymbols>,
    pub timeout_ms: Option<u64>,
}

/// Status short symbols configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StatusShortSymbols {
    pub detached: Option<String>,
    pub ahead: Option<String>,
    pub behind: Option<String>,
    pub dirty: Option<String>,
    pub conflict: Option<String>,
    pub no_upstream: Option<String>,
}

/// Branch action enumeration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BranchAction {
    List,
    Create,
    Delete,
    Rename,
    Checkout,
}

impl Default for BranchAction {
    fn default() -> Self {
        BranchAction::List
    }
}

/// Branch configuration structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BranchConfig {
    pub path: String,
    pub action: Option<BranchAction>,
    pub name: Option<String>,
    pub new_name: Option<String>,
    pub start_point: Option<String>,
    pub local_only: Option<bool>,
    pub remote_only: Option<bool>,
    pub all: Option<bool>,
    pub force: Option<bool>,
    pub track: Option<bool>,
    pub remote: Option<String>,
    pub timeout_ms: Option<u64>,
}

/// Timestamp for commit operations
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CommitTimestamp {
    Iso8601(String),
    UnixSeconds(u64),
}

/// Diff mode enumeration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffMode {
    WorkdirVsIndex,
    IndexVsHead,
    HeadVsWorkdir,
    CommitVsCommit,
    CommitVsWorkdir,
    CommitVsIndex,
}

impl Default for DiffMode {
    fn default() -> Self {
        DiffMode::WorkdirVsIndex
    }
}

/// Commit configuration structure
#[derive(Debug, Clone, Deserialize)]
pub struct CommitConfig {
    pub path: String,
    pub message: Option<String>,
    pub all: Option<bool>,
    pub paths: Option<Vec<String>>,
    pub allow_empty: Option<bool>,
    pub author_name: Option<String>,
    pub author_email: Option<String>,
    pub committer_name: Option<String>,
    pub committer_email: Option<String>,
    pub signoff: Option<bool>,
    pub amend: Option<bool>,
    pub no_edit: Option<bool>,
    pub timestamp: Option<CommitTimestamp>,
    pub timeout_ms: Option<u64>,
}

/// Diff configuration structure
#[derive(Debug, Clone, Deserialize)]
pub struct DiffConfig {
    pub path: String,
    pub mode: Option<DiffMode>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub paths: Option<Vec<String>>,
    pub unified: Option<i32>,
    pub ignore_whitespace: Option<bool>,
    pub ignore_whitespace_change: Option<bool>,
    pub ignore_whitespace_eol: Option<bool>,
    pub detect_renames: Option<bool>,
    pub rename_threshold: Option<u8>,
    pub binary: Option<bool>,
    pub max_files: Option<u32>,
    pub max_hunks: Option<u32>,
    pub timeout_ms: Option<u64>,
}

/// Tag action enumeration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TagAction {
    List,
    Create,
    Delete,
}

impl Default for TagAction {
    fn default() -> Self {
        TagAction::List
    }
}

/// Tag sort enumeration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TagSort {
    Name,
    Version,
    TaggerDate,
    CommitterDate,
}

impl Default for TagSort {
    fn default() -> Self {
        TagSort::Name
    }
}

/// Timestamp for tag operations
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TagTimestamp {
    Iso8601(String),
    UnixSeconds(u64),
}

/// Tag configuration structure
#[derive(Debug, Clone, Deserialize)]
pub struct TagConfig {
    pub path: String,
    pub action: Option<TagAction>,
    pub name: Option<String>,
    pub names: Option<Vec<String>>,
    pub pattern: Option<String>,
    pub sort: Option<TagSort>,
    pub annotated: Option<bool>,
    pub message: Option<String>,
    pub target: Option<String>,
    pub force: Option<bool>,
    pub author_name: Option<String>,
    pub author_email: Option<String>,
    pub timestamp: Option<TagTimestamp>,
    pub timeout_ms: Option<u64>,
}

/// Author/committer information
#[derive(Debug, Serialize, Deserialize)]
pub struct CommitIdentity {
    pub name: String,
    pub email: String,
}

/// Commit information in result
#[derive(Debug, Serialize, Deserialize)]
pub struct CommitInfo {
    pub oid: String,
    pub message: String,
    pub author: CommitIdentity,
    pub committer: CommitIdentity,
    pub amend: bool,
    pub allow_empty: bool,
}

/// Commit statistics
#[derive(Debug, Serialize, Deserialize)]
pub struct CommitStats {
    pub staged_files: usize,
    pub insertions: Option<usize>,
    pub deletions: Option<usize>,
}

/// Commit result structure
#[derive(Debug, Serialize, Deserialize)]
pub struct CommitResult {
    pub backend: String,
    pub alias: String,
    pub path: String,
    pub action: String,
    pub commit: CommitInfo,
    pub stats: CommitStats,
}

/// Diff line structure
#[derive(Debug, Serialize, Deserialize)]
pub struct DiffLine {
    #[serde(rename = "type")]
    pub line_type: String, // "context" | "add" | "delete"
    pub content: String,
}

/// Diff hunk structure
#[derive(Debug, Serialize, Deserialize)]
pub struct DiffHunk {
    pub old_start: u32,
    pub old_lines: u32,
    pub new_start: u32,
    pub new_lines: u32,
    pub lines: Vec<DiffLine>,
}

/// Diff file structure
#[derive(Debug, Serialize, Deserialize)]
pub struct DiffFile {
    pub old_path: Option<String>,
    pub new_path: Option<String>,
    pub status: String, // "added" | "deleted" | "modified" | "renamed" | "copied" | "typechange"
    pub is_binary: bool,
    pub hunks: Vec<DiffHunk>,
}

/// Diff summary structure
#[derive(Debug, Serialize, Deserialize)]
pub struct DiffSummary {
    pub files_changed: u32,
    pub insertions: u32,
    pub deletions: u32,
    pub truncated: bool,
}

/// Diff result structure
#[derive(Debug, Serialize, Deserialize)]
pub struct DiffResult {
    pub backend: String,
    pub alias: String,
    pub path: String,
    pub mode: String,
    pub from: String,
    pub to: String,
    pub summary: DiffSummary,
    pub files: Vec<DiffFile>,
}

/// Clone result structure
#[derive(Debug, Serialize)]
pub struct CloneResult {
    pub backend: String,
    pub alias: String,
    pub url: String,
    pub path: String,
    pub branch: Option<String>,
    pub depth: Option<u32>,
    pub recursive: bool,
    pub status: String,
}

/// Pull result structure
#[derive(Debug, Serialize, Deserialize)]
pub struct PullResult {
    pub backend: String,
    pub alias: String,
    pub path: String,
    pub remote: String,
    pub branch: String,
    pub status: String, // "updated" | "up_to_date"
    pub rebase: bool,
    pub ff_only: bool,
    pub ahead_by: Option<usize>,
    pub behind_by: Option<usize>,
    pub commits_fetched: Option<usize>,
}

/// Branch status for push operation
#[derive(Debug, Serialize, Deserialize)]
pub struct PushBranchStatus {
    pub name: String,
    pub status: String, // "pushed" | "up_to_date"
    pub ahead_by: usize,
    pub behind_by: usize,
}

/// Push result structure
#[derive(Debug, Serialize, Deserialize)]
pub struct PushResult {
    pub backend: String,
    pub alias: String,
    pub path: String,
    pub remote: String,
    pub branches: Vec<PushBranchStatus>,
    pub tags_pushed: bool,
}

/// File status entry for status operation
#[derive(Debug, Serialize, Deserialize)]
pub struct FileStatus {
    pub path: String,
    pub status: String,
}

/// Upstream information for a branch
#[derive(Debug, Serialize, Deserialize)]
pub struct UpstreamInfo {
    pub name: String,
    pub remote: String,
    pub ahead_by: usize,
    pub behind_by: usize,
}

/// Branch information for status operation
#[derive(Debug, Serialize, Deserialize)]
pub struct BranchInfo {
    pub name: Option<String>,
    pub detached: bool,
    pub head: String,
    pub upstream: Option<UpstreamInfo>,
}

/// Working tree status information
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkingTreeStatus {
    pub clean: bool,
    pub staged: Vec<FileStatus>,
    pub unstaged: Vec<FileStatus>,
    pub untracked: Vec<FileStatus>,
    pub ignored: Vec<FileStatus>,
    pub conflicts: Vec<FileStatus>,
}

/// In-progress operation flags
#[derive(Debug, Serialize, Deserialize)]
pub struct InProgressFlags {
    pub merge: bool,
    pub rebase: bool,
    pub cherry_pick: bool,
    pub revert: bool,
    pub bisect: bool,
}

/// Status result structure
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResult {
    pub backend: String,
    pub alias: String,
    pub path: String,
    pub branch: Option<BranchInfo>,
    pub working_tree: WorkingTreeStatus,
    pub in_progress: InProgressFlags,
}

/// Branch upstream information for branch operation
#[derive(Debug, Serialize, Deserialize)]
pub struct BranchUpstreamInfo {
    pub remote: String,
    pub name: String,
    pub full_ref: String,
}

/// Individual branch information for branch list
#[derive(Debug, Serialize, Deserialize)]
pub struct BranchListEntry {
    pub name: String,
    pub full_ref: String,
    pub is_remote: bool,
    pub is_current: bool,
    pub upstream: Option<BranchUpstreamInfo>,
    pub head: String,
}

/// Branch list result structure
#[derive(Debug, Serialize, Deserialize)]
pub struct BranchListResult {
    pub backend: String,
    pub alias: String,
    pub path: String,
    pub action: String,
    pub branches: Vec<BranchListEntry>,
}

/// Branch operation result structure (for create/delete/rename/checkout)
#[derive(Debug, Serialize, Deserialize)]
pub struct BranchOpResult {
    pub backend: String,
    pub alias: String,
    pub path: String,
    pub action: String,
    pub status: String,
    pub branch: serde_json::Value,
}

/// Tag target information
#[derive(Debug, Serialize, Deserialize)]
pub struct TagTarget {
    pub oid: String,
    #[serde(rename = "type")]
    pub object_type: String, // "commit" | "tag" | "tree" | "blob"
}

/// Tag tagger information
#[derive(Debug, Serialize, Deserialize)]
pub struct TagTagger {
    pub name: String,
    pub email: String,
    pub timestamp: String,
}

/// Tag entry in results
#[derive(Debug, Serialize, Deserialize)]
pub struct TagEntry {
    pub name: String,
    pub annotated: bool,
    pub message: Option<String>,
    pub target: TagTarget,
    pub tagger: Option<TagTagger>,
}

/// Tag list result structure
#[derive(Debug, Serialize, Deserialize)]
pub struct TagListResult {
    pub backend: String,
    pub alias: String,
    pub path: String,
    pub action: String,
    pub pattern: Option<String>,
    pub sort: String,
    pub tags: Vec<TagEntry>,
    pub count: usize,
}

/// Tag create result structure
#[derive(Debug, Serialize, Deserialize)]
pub struct TagCreateResult {
    pub backend: String,
    pub alias: String,
    pub path: String,
    pub action: String,
    pub tag: TagEntry,
    pub status: String, // "created" | "overwritten"
    pub force: bool,
}

/// Tag delete result structure
#[derive(Debug, Serialize, Deserialize)]
pub struct TagDeleteResult {
    pub backend: String,
    pub alias: String,
    pub path: String,
    pub action: String,
    pub requested: Vec<String>,
    pub deleted: Vec<String>,
    pub missing: Vec<String>,
    pub force: bool,
}

/// Merge configuration structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MergeConfig {
    pub path: String,
    pub source: String,
    pub target: Option<String>,
    pub ff_only: Option<bool>,
    pub no_ff: Option<bool>,
    pub squash: Option<bool>,
    pub commit_message: Option<String>,
    pub author_name: Option<String>,
    pub author_email: Option<String>,
    pub committer_name: Option<String>,
    pub committer_email: Option<String>,
    pub allow_uncommitted: Option<bool>,
    pub abort_on_conflict: Option<bool>,
    pub timeout_ms: Option<u64>,
}

/// Rebase operation type
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RebaseOperation {
    Start,
    Continue,
    Abort,
}

impl Default for RebaseOperation {
    fn default() -> Self {
        RebaseOperation::Start
    }
}

/// Rebase configuration structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RebaseConfig {
    pub path: String,
    pub operation: Option<RebaseOperation>,
    pub branch: Option<String>,
    pub upstream: Option<String>,
    pub ff_only: Option<bool>,
    pub preserve_merges: Option<bool>,
    pub autosquash: Option<bool>,
    pub allow_uncommitted: Option<bool>,
    pub abort_on_conflict: Option<bool>,
    pub author_name: Option<String>,
    pub author_email: Option<String>,
    pub committer_name: Option<String>,
    pub committer_email: Option<String>,
    pub timeout_ms: Option<u64>,
}

/// Pull strategy for sync operations
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PullStrategy {
    Rebase,
    Merge,
    FfOnly,
}

fn pull_strategy_name(strategy: &PullStrategy) -> &'static str {
    match strategy {
        PullStrategy::Rebase => "rebase",
        PullStrategy::Merge => "merge",
        PullStrategy::FfOnly => "ff_only",
    }
}

/// The integration actually performed during sync, from the pull result:
/// a fast-forward or nothing. `mode` is the requested pull_strategy.
fn sync_integration_report(fetched: &Value, pull_strategy: &PullStrategy) -> Value {
    let pulled = fetched.get("status").and_then(Value::as_str);
    let updated = pulled == Some("updated");
    let status = match pulled {
        Some("updated") => "fast_forward",
        Some("merged") => "merged",
        Some("rebased") => "rebased",
        _ => "up_to_date",
    };
    json!({
        "status": status,
        "mode": pull_strategy_name(pull_strategy),
        "commits_fast_forwarded": if updated { fetched.get("behind_by").cloned().unwrap_or(json!(0)) } else { json!(0) },
        "local_commits_ahead": fetched.get("ahead_by").cloned().unwrap_or(json!(0)),
        "commit": fetched.get("commit").cloned().unwrap_or(Value::Null),
    })
}

impl Default for PullStrategy {
    fn default() -> Self {
        PullStrategy::Rebase
    }
}

/// Sync configuration structure
#[derive(Debug, Clone, Deserialize)]
pub struct SyncConfig {
    pub path: String,
    pub remote: Option<String>,
    pub branch: Option<String>,
    pub remote_branch: Option<String>,
    pub pull_strategy: Option<PullStrategy>,
    pub ff_only: Option<bool>,
    pub allow_uncommitted: Option<bool>,
    pub stash_uncommitted: Option<bool>,
    pub abort_on_conflict: Option<bool>,
    pub author_name: Option<String>,
    pub author_email: Option<String>,
    pub push: Option<bool>,
    pub push_tags: Option<bool>,
    pub force_push: Option<bool>,
    pub dry_run: Option<bool>,
    pub known_hosts_path: Option<String>,
    pub timeout_ms: Option<u64>,
}

/// Status summary configuration structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StatusSummaryConfig {
    pub path: String,
    pub remote: Option<String>,
    pub branch: Option<String>,
    pub include_untracked: Option<bool>,
    pub include_ignored: Option<bool>,
    pub include_remote: Option<bool>,
    pub compute_diffstats: Option<bool>,
    pub max_files: Option<u32>,
    pub timeout_ms: Option<u64>,
}

/// Git-specific error types
#[derive(Error, Debug)]
pub enum GitError {
    /// The verb is not one of the git handle's verbs.
    #[error("{message}")]
    InvalidVerb { message: String },

    /// `timeout_ms` passed before the verb finished. `still_running` is
    /// true when the operation could not be stopped; otherwise it stopped
    /// at the deadline.
    #[error("{verb} timed out after {timeout_ms} ms; {}", if *still_running {
        "the operation could not be stopped and its outcome is unknown"
    } else {
        "the operation was stopped; check the repository before retrying"
    })]
    Timeout {
        verb: String,
        timeout_ms: u64,
        still_running: bool,
    },

    /// The SSH server's host key could not be verified against the
    /// `known_hosts_path` file (unknown host, changed or revoked key,
    /// unreadable file); the connection was refused.
    #[error("SSH host key verification failed for {host}: {reason}")]
    HostKeyVerificationFailed {
        host: String,
        known_hosts_path: String,
        reason: String,
    },

    #[error("invalid clone config: {message}")]
    InvalidCloneConfig { message: String },

    #[error("clone failed: {message}")]
    CloneFailed { message: String },

    #[error("authentication failed: {message}")]
    CloneAuthFailed { message: String },

    #[error("clone target directory is not empty: {path}")]
    CloneTargetNotEmpty { path: String },

    // Pull-specific errors
    #[error("invalid pull config: {message}")]
    InvalidPullConfig { message: String },

    #[error("repository not found: {path}")]
    RepositoryNotFound { path: String },

    #[error("remote not found: {remote}")]
    RemoteNotFound { remote: String },

    #[error("remote branch not found: {branch}")]
    PullRemoteBranchNotFound { branch: String },

    #[error("pull from detached HEAD state requires explicit branch")]
    PullDetachedHead,

    #[error("pull fetch failed: {message}")]
    PullFetchFailed { message: String },

    #[error("pull authentication failed: {message}")]
    PullAuthFailed { message: String },

    #[error("dirty working tree prevents safe pull")]
    PullDirtyWorktree,

    #[error("non-fast-forward pull refused with ff_only=true")]
    PullNonFastForward,

    /// Diverged history could not be merged or rebased without conflicts.
    #[error("{}", conflict_message("pull", paths, *in_progress))]
    PullConflict {
        paths: Vec<String>,
        in_progress: bool,
    },

    #[error("pull operation failed: {message}")]
    PullFailed { message: String },

    // Push-specific errors
    #[error("invalid push config: {message}")]
    InvalidPushConfig { message: String },

    #[error("push from detached HEAD state requires explicit branch")]
    PushDetachedHead,

    #[error("push local branch not found: {branch}")]
    PushLocalBranchNotFound { branch: String },

    #[error("push would not be fast-forward and ff_only=true")]
    PushNonFastForward,

    #[error("push authentication failed: {message}")]
    PushAuthFailed { message: String },

    #[error("push rejected by remote: {message}")]
    PushRejected { message: String },

    #[error("push operation failed: {message}")]
    PushFailed { message: String },

    // Status-specific errors
    #[error("invalid status config: {message}")]
    InvalidStatusConfig { message: String },

    #[error("status operation failed: {message}")]
    StatusFailed { message: String },

    // Status short-specific errors
    #[error("invalid status_short config: {message}")]
    InvalidStatusShortConfig { message: String },

    #[error("status_short branch not found: {branch}")]
    StatusShortBranchNotFound { branch: String },

    #[error("status_short operation failed: {message}")]
    StatusShortFailed { message: String },

    // Branch-specific errors
    #[error("invalid branch config: {message}")]
    InvalidBranchConfig { message: String },

    #[error("branch not found: {name}")]
    BranchNotFound { name: String },

    #[error("branch already exists: {name}")]
    BranchAlreadyExists { name: String },

    #[error("branch start point not found: {start_point}")]
    BranchStartpointNotFound { start_point: String },

    #[error("cannot delete current branch: {name}")]
    BranchDeleteCurrent { name: String },

    #[error("cannot delete unmerged branch: {name}")]
    BranchDeleteUnmerged { name: String },

    #[error("branch delete operation failed: {message}")]
    BranchDeleteFailed { message: String },

    #[error("branch rename operation failed: {message}")]
    BranchRenameFailed { message: String },

    #[error("failed to set upstream tracking: {message}")]
    BranchSetUpstreamFailed { message: String },

    #[error("checkout would overwrite local changes")]
    BranchCheckoutConflict,

    #[error("branch checkout failed: {message}")]
    BranchCheckoutFailed { message: String },

    #[error("branch operation failed: {message}")]
    BranchFailed { message: String },

    // Commit-specific errors
    #[error("invalid commit config: {message}")]
    InvalidCommitConfig { message: String },

    #[error("no valid author identity found")]
    CommitIdentityMissing,

    #[error("no changes to commit and allow_empty is false")]
    CommitNothingToCommit { path: String },

    #[error("cannot amend without existing HEAD commit")]
    CommitAmendWithoutHead,

    #[error("amend operation failed: {message}")]
    CommitAmendFailed { message: String },

    #[error("commit operation failed: {message}")]
    CommitFailed { message: String },

    // Diff-specific errors
    #[error("invalid diff config: {message}")]
    InvalidDiffConfig { message: String },

    #[error("diff reference not found: {reference}")]
    DiffRefNotFound { reference: String },

    #[error("diff HEAD not found: repository has no commits")]
    DiffHeadNotFound,

    #[error("diff operation failed: {message}")]
    DiffFailed { message: String },

    // Tag-specific errors
    #[error("invalid tag config: {message}")]
    InvalidTagConfig { message: String },

    #[error("tag target not found: {target}")]
    TagTargetNotFound { target: String },

    #[error("tag identity missing")]
    TagIdentityMissing,

    #[error("tag already exists: {name}")]
    TagAlreadyExists { name: String },

    #[error("tag not found: {name}")]
    TagNotFound { name: String },

    #[error("tag delete operation failed: {message}")]
    TagDeleteFailed { message: String },

    #[error("tag list operation failed: {message}")]
    TagListFailed { message: String },

    #[error("tag create operation failed: {message}")]
    TagCreateFailed { message: String },

    #[error("tag operation failed: {message}")]
    TagFailed { message: String },

    // Merge-specific errors
    #[error("invalid merge config: {message}")]
    InvalidMergeConfig { message: String },

    #[error("merge from detached HEAD requires explicit target")]
    MergeDetachedHead,

    #[error("merge source not found: {0}")]
    MergeSourceNotFound(String),

    #[error("merge source is not a commit: {0}")]
    MergeSourceNotCommit(String),

    #[error("merge target branch not found: {0}")]
    MergeTargetNotFound(String),

    #[error("dirty working tree prevents merge")]
    MergeDirtyWorktree,

    #[error("non-fast-forward merge refused with ff_only=true")]
    MergeNonFastForward,

    #[error("no valid merge identity found")]
    MergeIdentityMissing,

    #[error("merge conflicts detected")]
    MergeConflict,

    #[error("merge operation failed: {message}")]
    MergeFailed { message: String },

    // Rebase-specific errors
    #[error("invalid rebase config: {message}")]
    InvalidRebaseConfig { message: String },

    #[error("rebase operation already in progress")]
    RebaseInProgress,

    #[error("no rebase operation in progress")]
    RebaseNotInProgress,

    #[error("rebase from detached HEAD requires explicit branch")]
    RebaseDetachedHead,

    #[error("rebase branch not found: {branch}")]
    RebaseBranchNotFound { branch: String },

    #[error("rebase upstream not found: {upstream}")]
    RebaseUpstreamNotFound { upstream: String },

    #[error("rebase upstream is not a commit: {upstream}")]
    RebaseUpstreamNotCommit { upstream: String },

    #[error("non-fast-forward rebase refused with ff_only=true")]
    RebaseNonFastForward,

    #[error("dirty working tree prevents rebase")]
    RebaseDirtyWorktree,

    #[error("no valid rebase identity found")]
    RebaseIdentityMissing,

    #[error("rebase conflicts detected")]
    RebaseConflict,

    #[error("preserve merges option is not supported")]
    RebasePreserveMergesUnsupported,

    #[error("rebase operation failed: {message}")]
    RebaseFailed { message: String },

    // Sync-specific errors
    #[error("invalid sync config: {message}")]
    InvalidSyncConfig { message: String },

    #[error("sync from detached HEAD state requires explicit branch")]
    SyncDetachedHead,

    #[error("sync branch not found: {branch}")]
    SyncBranchNotFound { branch: String },

    #[error("sync remote not found: {remote}")]
    SyncRemoteNotFound { remote: String },

    #[error("dirty working tree prevents sync")]
    SyncDirtyWorktree,

    #[error("non-fast-forward sync refused with ff_only strategy")]
    SyncNonFastForward,

    /// Diverged history could not be merged or rebased without conflicts;
    /// nothing was pushed.
    #[error("{}", conflict_message("sync", paths, *in_progress))]
    SyncConflict {
        paths: Vec<String>,
        in_progress: bool,
    },

    #[error("sync pull failed: {message}")]
    SyncPullFailed { message: String },

    #[error("sync push rejected: {message}")]
    SyncPushRejected { message: String },

    #[error("sync push failed: {message}")]
    SyncPushFailed { message: String },

    #[error("restoring the stashed changes failed ({message}); they are kept in the stash")]
    SyncStashApplyConflict { message: String },

    #[error("sync operation failed: {message}")]
    SyncFailed { message: String },

    // Status Summary-specific errors
    #[error("invalid status summary config: {message}")]
    InvalidStatusSummaryConfig { message: String },

    #[error("status summary branch not found: {name}")]
    StatusSummaryBranchNotFound { name: String },

    #[error("status summary operation failed: {message}")]
    StatusSummaryFailed { message: String },
}

impl GitError {
    /// The generic failure of `verb` (exit status 1).
    pub fn failed_for(verb: &str, message: String) -> GitError {
        match verb {
            "clone" => GitError::CloneFailed { message },
            "pull" => GitError::PullFailed { message },
            "push" => GitError::PushFailed { message },
            "status" => GitError::StatusFailed { message },
            "status_short" => GitError::StatusShortFailed { message },
            "status_summary" => GitError::StatusSummaryFailed { message },
            "branch" => GitError::BranchFailed { message },
            "commit" => GitError::CommitFailed { message },
            "diff" => GitError::DiffFailed { message },
            "tag" => GitError::TagFailed { message },
            "merge" => GitError::MergeFailed { message },
            "rebase" => GitError::RebaseFailed { message },
            _ => GitError::SyncFailed { message },
        }
    }

    /// The invalid-arguments error of `verb` (exit status 2).
    pub fn invalid_for(verb: &str, message: String) -> GitError {
        match verb {
            "clone" => GitError::InvalidCloneConfig { message },
            "pull" => GitError::InvalidPullConfig { message },
            "push" => GitError::InvalidPushConfig { message },
            "status" => GitError::InvalidStatusConfig { message },
            "status_short" => GitError::InvalidStatusShortConfig { message },
            "status_summary" => GitError::InvalidStatusSummaryConfig { message },
            "branch" => GitError::InvalidBranchConfig { message },
            "commit" => GitError::InvalidCommitConfig { message },
            "diff" => GitError::InvalidDiffConfig { message },
            "tag" => GitError::InvalidTagConfig { message },
            "merge" => GitError::InvalidMergeConfig { message },
            "rebase" => GitError::InvalidRebaseConfig { message },
            _ => GitError::InvalidSyncConfig { message },
        }
    }

    /// The process exit status for this error: 2 for invalid arguments
    /// (nothing was done), 124 for a timeout, 1 for every other failure.
    pub fn exit_code(&self) -> i32 {
        let code = self.code();
        if code.ends_with("_timeout") {
            124
        } else if code.starts_with("git.invalid_")
            || code == "git.sync_invalid_config"
            || code.ends_with("_unsupported")
        {
            2
        } else {
            1
        }
    }

    /// The error code, such as `git.repository_not_found`.
    pub fn code(&self) -> String {
        let code = match self {
            GitError::Timeout { verb, .. } => return format!("git.{verb}_timeout"),
            GitError::InvalidVerb { .. } => "git.invalid_verb",
            GitError::HostKeyVerificationFailed { .. } => "git.host_key_verification_failed",
            GitError::InvalidCloneConfig { .. } => "git.invalid_clone_config",
            GitError::CloneFailed { .. } => "git.clone_failed",
            GitError::CloneAuthFailed { .. } => "git.clone_auth_failed",
            GitError::CloneTargetNotEmpty { .. } => "git.clone_target_not_empty",
            GitError::InvalidPullConfig { .. } => "git.invalid_pull_config",
            GitError::RepositoryNotFound { .. } => "git.repository_not_found",
            GitError::RemoteNotFound { .. } => "git.remote_not_found",
            GitError::PullRemoteBranchNotFound { .. } => "git.pull_remote_branch_not_found",
            GitError::PullDetachedHead => "git.pull_detached_head",
            GitError::PullFetchFailed { .. } => "git.pull_fetch_failed",
            GitError::PullAuthFailed { .. } => "git.pull_auth_failed",
            GitError::PullDirtyWorktree => "git.pull_dirty_worktree",
            GitError::PullNonFastForward => "git.pull_non_fast_forward",
            GitError::PullConflict { .. } => "git.pull_conflict",
            GitError::SyncConflict { .. } => "git.sync_conflict",
            GitError::PullFailed { .. } => "git.pull_failed",
            GitError::InvalidPushConfig { .. } => "git.invalid_push_config",
            GitError::PushDetachedHead => "git.push_detached_head",
            GitError::PushLocalBranchNotFound { .. } => "git.push_local_branch_not_found",
            GitError::PushNonFastForward => "git.push_non_fast_forward",
            GitError::PushAuthFailed { .. } => "git.push_auth_failed",
            GitError::PushRejected { .. } => "git.push_rejected",
            GitError::PushFailed { .. } => "git.push_failed",
            GitError::InvalidStatusConfig { .. } => "git.invalid_status_config",
            GitError::StatusFailed { .. } => "git.status_failed",
            GitError::InvalidBranchConfig { .. } => "git.invalid_branch_config",
            GitError::BranchNotFound { .. } => "git.branch_not_found",
            GitError::BranchAlreadyExists { .. } => "git.branch_already_exists",
            GitError::BranchStartpointNotFound { .. } => "git.branch_startpoint_not_found",
            GitError::BranchDeleteCurrent { .. } => "git.branch_delete_current",
            GitError::BranchDeleteUnmerged { .. } => "git.branch_delete_unmerged",
            GitError::BranchDeleteFailed { .. } => "git.branch_delete_failed",
            GitError::BranchRenameFailed { .. } => "git.branch_rename_failed",
            GitError::BranchSetUpstreamFailed { .. } => "git.branch_set_upstream_failed",
            GitError::BranchCheckoutConflict => "git.branch_checkout_conflict",
            GitError::BranchCheckoutFailed { .. } => "git.branch_checkout_failed",
            GitError::BranchFailed { .. } => "git.branch_failed",
            GitError::InvalidCommitConfig { .. } => "git.invalid_commit_config",
            GitError::CommitIdentityMissing => "git.commit_identity_missing",
            GitError::CommitNothingToCommit { .. } => "git.commit_nothing_to_commit",
            GitError::CommitAmendWithoutHead => "git.commit_amend_without_head",
            GitError::CommitAmendFailed { .. } => "git.commit_amend_failed",
            GitError::CommitFailed { .. } => "git.commit_failed",
            GitError::InvalidDiffConfig { .. } => "git.invalid_diff_config",
            GitError::DiffRefNotFound { .. } => "git.diff_ref_not_found",
            GitError::DiffHeadNotFound => "git.diff_head_not_found",
            GitError::DiffFailed { .. } => "git.diff_failed",
            GitError::InvalidTagConfig { .. } => "git.invalid_tag_config",
            GitError::TagTargetNotFound { .. } => "git.tag_target_not_found",
            GitError::TagIdentityMissing => "git.tag_identity_missing",
            GitError::TagAlreadyExists { .. } => "git.tag_already_exists",
            GitError::TagNotFound { .. } => "git.tag_not_found",
            GitError::TagDeleteFailed { .. } => "git.tag_delete_failed",
            GitError::TagListFailed { .. } => "git.tag_list_failed",
            GitError::TagCreateFailed { .. } => "git.tag_create_failed",
            GitError::TagFailed { .. } => "git.tag_failed",
            GitError::InvalidMergeConfig { .. } => "git.invalid_merge_config",
            GitError::MergeDetachedHead => "git.merge_detached_head",
            GitError::MergeSourceNotFound(..) => "git.merge_source_not_found",
            GitError::MergeSourceNotCommit(..) => "git.merge_source_not_commit",
            GitError::MergeTargetNotFound(..) => "git.merge_target_not_found",
            GitError::MergeDirtyWorktree => "git.merge_dirty_worktree",
            GitError::MergeNonFastForward => "git.merge_non_fast_forward",
            GitError::MergeIdentityMissing => "git.merge_identity_missing",
            GitError::MergeConflict => "git.merge_conflict",
            GitError::MergeFailed { .. } => "git.merge_failed",
            GitError::InvalidRebaseConfig { .. } => "git.invalid_rebase_config",
            GitError::RebaseInProgress => "git.rebase_in_progress",
            GitError::RebaseNotInProgress => "git.rebase_not_in_progress",
            GitError::RebaseDetachedHead => "git.rebase_detached_head",
            GitError::RebaseBranchNotFound { .. } => "git.rebase_branch_not_found",
            GitError::RebaseUpstreamNotFound { .. } => "git.rebase_upstream_not_found",
            GitError::RebaseUpstreamNotCommit { .. } => "git.rebase_upstream_not_commit",
            GitError::RebaseNonFastForward => "git.rebase_non_fast_forward",
            GitError::RebaseDirtyWorktree => "git.rebase_dirty_worktree",
            GitError::RebaseIdentityMissing => "git.rebase_identity_missing",
            GitError::RebaseConflict => "git.rebase_conflict",
            GitError::RebasePreserveMergesUnsupported => "git.rebase_preserve_merges_unsupported",
            GitError::RebaseFailed { .. } => "git.rebase_failed",
            GitError::InvalidSyncConfig { .. } => "git.sync_invalid_config",
            GitError::SyncDetachedHead => "git.sync_detached_head",
            GitError::SyncBranchNotFound { .. } => "git.sync_branch_not_found",
            GitError::SyncRemoteNotFound { .. } => "git.sync_remote_not_found",
            GitError::SyncDirtyWorktree => "git.sync_dirty_worktree",
            GitError::SyncNonFastForward => "git.sync_non_fast_forward",
            GitError::SyncPullFailed { .. } => "git.sync_pull_failed",
            GitError::SyncPushRejected { .. } => "git.sync_push_rejected",
            GitError::SyncPushFailed { .. } => "git.sync_push_failed",
            GitError::SyncStashApplyConflict { .. } => "git.sync_stash_apply_conflict",
            GitError::SyncFailed { .. } => "git.sync_failed",
            // Status Summary error codes
            GitError::InvalidStatusSummaryConfig { .. } => "git.invalid_status_summary_config",
            GitError::StatusSummaryBranchNotFound { .. } => "git.status_summary_branch_not_found",
            GitError::StatusSummaryFailed { .. } => "git.status_summary_failed",
            // Status short error codes
            GitError::InvalidStatusShortConfig { .. } => "git.invalid_status_short_config",
            GitError::StatusShortBranchNotFound { .. } => "git.status_short_branch_not_found",
            GitError::StatusShortFailed { .. } => "git.status_short_failed",
        };
        code.to_string()
    }
}

impl From<GitError> for crate::core::status::ShellError {
    fn from(err: GitError) -> Self {
        let code = err.code();
        let details = match &err {
            GitError::InvalidVerb { .. } => json!({}),
            GitError::PullConflict { paths, in_progress }
            | GitError::SyncConflict { paths, in_progress } => {
                json!({ "paths": paths, "in_progress": in_progress })
            }
            GitError::Timeout {
                timeout_ms,
                still_running,
                ..
            } => json!({
                "timeout_ms": timeout_ms,
                "outcome": if *still_running { "unknown" } else { "stopped" },
            }),
            GitError::HostKeyVerificationFailed {
                host,
                known_hosts_path,
                ..
            } => {
                json!({ "host": host, "known_hosts_path": known_hosts_path })
            }
            GitError::InvalidCloneConfig { .. } => json!({}),
            GitError::CloneFailed { .. } => json!({}),
            GitError::CloneAuthFailed { .. } => json!({}),
            GitError::CloneTargetNotEmpty { path } => {
                json!({ "path": path })
            }
            GitError::InvalidPullConfig { .. } => json!({}),
            GitError::RepositoryNotFound { path } => {
                json!({ "path": path })
            }
            GitError::RemoteNotFound { remote } => {
                json!({ "remote": remote })
            }
            GitError::PullRemoteBranchNotFound { branch } => {
                json!({ "branch": branch })
            }
            GitError::PullDetachedHead => json!({}),
            GitError::PullFetchFailed { .. } => json!({}),
            GitError::PullAuthFailed { .. } => json!({}),
            GitError::PullDirtyWorktree => json!({}),
            GitError::PullNonFastForward => json!({}),
            GitError::PullFailed { .. } => json!({}),
            GitError::InvalidPushConfig { .. } => json!({}),
            GitError::PushDetachedHead => json!({}),
            GitError::PushLocalBranchNotFound { branch } => {
                json!({ "branch": branch })
            }
            GitError::PushNonFastForward => json!({}),
            GitError::PushAuthFailed { .. } => json!({}),
            GitError::PushRejected { .. } => json!({}),
            GitError::PushFailed { .. } => json!({}),
            GitError::InvalidStatusConfig { .. } => json!({}),
            GitError::StatusFailed { .. } => json!({}),
            GitError::InvalidBranchConfig { .. } => json!({}),
            GitError::BranchNotFound { name } => {
                json!({ "name": name })
            }
            GitError::BranchAlreadyExists { name } => {
                json!({ "name": name })
            }
            GitError::BranchStartpointNotFound { start_point } => {
                json!({ "start_point": start_point })
            }
            GitError::BranchDeleteCurrent { name } => {
                json!({ "name": name })
            }
            GitError::BranchDeleteUnmerged { name } => {
                json!({ "name": name })
            }
            GitError::BranchDeleteFailed { .. } => json!({}),
            GitError::BranchRenameFailed { .. } => json!({}),
            GitError::BranchSetUpstreamFailed { .. } => json!({}),
            GitError::BranchCheckoutConflict => json!({}),
            GitError::BranchCheckoutFailed { .. } => json!({}),
            GitError::BranchFailed { .. } => json!({}),
            GitError::InvalidCommitConfig { .. } => json!({}),
            GitError::CommitIdentityMissing => json!({}),
            GitError::CommitNothingToCommit { path } => {
                json!({ "path": path })
            }
            GitError::CommitAmendWithoutHead => json!({}),
            GitError::CommitAmendFailed { .. } => json!({}),
            GitError::CommitFailed { .. } => json!({}),
            GitError::InvalidDiffConfig { .. } => json!({}),
            GitError::DiffRefNotFound { reference } => {
                json!({ "reference": reference })
            }
            GitError::DiffHeadNotFound => json!({}),
            GitError::DiffFailed { .. } => json!({}),
            GitError::InvalidTagConfig { .. } => json!({}),
            GitError::TagTargetNotFound { target } => {
                json!({ "target": target })
            }
            GitError::TagIdentityMissing => json!({}),
            GitError::TagAlreadyExists { name } => {
                json!({ "name": name })
            }
            GitError::TagNotFound { name } => {
                json!({ "name": name })
            }
            GitError::TagDeleteFailed { .. } => json!({}),
            GitError::TagListFailed { .. } => json!({}),
            GitError::TagCreateFailed { .. } => json!({}),
            GitError::TagFailed { .. } => json!({}),
            GitError::InvalidMergeConfig { .. } => json!({}),
            GitError::MergeDetachedHead => json!({}),
            GitError::MergeSourceNotFound(source) => {
                json!({ "source": source })
            }
            GitError::MergeSourceNotCommit(source) => {
                json!({ "source": source })
            }
            GitError::MergeTargetNotFound(target) => {
                json!({ "target": target })
            }
            GitError::MergeDirtyWorktree => json!({}),
            GitError::MergeNonFastForward => json!({}),
            GitError::MergeIdentityMissing => json!({}),
            GitError::MergeConflict => json!({}),
            GitError::MergeFailed { .. } => json!({}),
            GitError::InvalidRebaseConfig { .. } => json!({}),
            GitError::RebaseInProgress => json!({}),
            GitError::RebaseNotInProgress => json!({}),
            GitError::RebaseDetachedHead => json!({}),
            GitError::RebaseBranchNotFound { branch } => {
                json!({ "branch": branch })
            }
            GitError::RebaseUpstreamNotFound { upstream } => {
                json!({ "upstream": upstream })
            }
            GitError::RebaseUpstreamNotCommit { upstream } => {
                json!({ "upstream": upstream })
            }
            GitError::RebaseNonFastForward => json!({}),
            GitError::RebaseDirtyWorktree => json!({}),
            GitError::RebaseIdentityMissing => json!({}),
            GitError::RebaseConflict => json!({}),
            GitError::RebasePreserveMergesUnsupported => json!({}),
            GitError::RebaseFailed { .. } => json!({}),
            GitError::InvalidSyncConfig { .. } => json!({}),
            GitError::SyncDetachedHead => json!({}),
            GitError::SyncBranchNotFound { branch } => {
                json!({ "branch": branch })
            }
            GitError::SyncRemoteNotFound { remote } => {
                json!({ "remote": remote })
            }
            GitError::SyncDirtyWorktree => json!({}),
            GitError::SyncNonFastForward => json!({}),
            GitError::SyncPullFailed { .. } => json!({}),
            GitError::SyncPushRejected { .. } => json!({}),
            GitError::SyncPushFailed { .. } => json!({}),
            GitError::SyncStashApplyConflict { .. } => json!({}),
            GitError::SyncFailed { .. } => json!({}),
            // Status Summary error details
            GitError::InvalidStatusSummaryConfig { .. } => json!({}),
            GitError::StatusSummaryBranchNotFound { name } => {
                json!({ "name": name })
            }
            GitError::StatusSummaryFailed { .. } => json!({}),
            // Status short error details
            GitError::InvalidStatusShortConfig { .. } => json!({}),
            GitError::StatusShortBranchNotFound { branch } => {
                json!({ "branch": branch })
            }
            GitError::StatusShortFailed { .. } => json!({}),
        };

        crate::core::status::ShellError::new(&code, &err.to_string(), details)
    }
}

/// Convert git2::Error to GitError
impl From<git2::Error> for GitError {
    fn from(err: git2::Error) -> Self {
        GitError::StatusSummaryFailed {
            message: format!("git operation failed: {}", err),
        }
    }
}

/// Verbs registered by the git handle (shared by `Handle::verbs` and the
/// in-URL help forms).
const GIT_VERBS: &[&str] = &[
    "clone",
    "pull",
    "push",
    "status",
    "branch",
    "commit",
    "diff",
    "tag",
    "merge",
    "rebase",
    "sync",
    "status_summary",
    "status_short",
];

/// True for the in-URL help forms `git://--help`, `git://-h` and `git://help`.
fn is_git_help_word(s: &str) -> bool {
    crate::core::help::is_help_flag(s) || s == "help"
}

/// Renders the approved git help, for one verb when `verb` names a registered verb.
fn git_help_text(verb: Option<&str>) -> String {
    crate::core::help::render_legacy("git", &GIT_HELP, GIT_VERBS, verb)
}

impl GitHandle {
    /// Create new GitHandle from URL
    pub fn from_url(url: Url) -> Result<Self> {
        // For git:// URLs, the alias can be in the host or path
        let alias = if let Some(host) = url.host_str() {
            // Check if host is a help request
            if is_git_help_word(host) {
                print!("{}", git_help_text(None));
                std::process::exit(0);
            }
            // If we have a host, that's our alias (git://main)
            host.to_string()
        } else if url.path() == "/" || url.path().is_empty() {
            // No host and empty path means default
            "default".to_string()
        } else {
            // Path-based alias (git:///main)
            let path_alias = url.path().trim_start_matches('/').to_string();
            if is_git_help_word(&path_alias) {
                print!("{}", git_help_text(None));
                std::process::exit(0);
            }
            path_alias
        };

        if alias.is_empty() {
            return Err(anyhow::anyhow!("git:// URLs must specify an alias"));
        }

        Ok(GitHandle { alias })
    }

    /// Runs one verb with already-checked arguments. The deadline, if any,
    /// is the calling thread's ([`net::set_deadline`]).
    pub async fn run_verb(&self, verb: &str, args: Value) -> Result<Value, GitError> {
        match verb {
            "clone" => self.clone(args).await,
            "pull" => self.pull(args).await,
            "push" => self.push(args).await,
            "status" => self.status(args).await,
            "branch" => self.branch(args).await,
            "commit" => self.commit(args).await,
            "diff" => self.diff(args).await,
            "tag" => self.tag(args).await,
            "merge" => self.merge(args).await,
            "rebase" => self.rebase(args).await,
            "sync" => self.sync(args).await,
            "status_summary" => self.status_summary(args).await,
            "status_short" => self.status_short(args).await,
            other => Err(GitError::invalid_for(
                other,
                format!("unknown verb for git://: {other}"),
            )),
        }
    }

    /// Clone verb implementation
    pub async fn clone(&self, args: Value) -> Result<Value, GitError> {
        let config = self.parse_clone_config(args)?;
        self.validate_clone_config(&config)?;
        self.execute_clone(&config).await
    }

    /// Pull verb implementation
    pub async fn pull(&self, args: Value) -> Result<Value, GitError> {
        let config = self.parse_pull_config(args)?;
        self.validate_pull_config(&config)?;
        self.execute_pull(&config).await
    }

    /// Push verb implementation
    pub async fn push(&self, args: Value) -> Result<Value, GitError> {
        let config = self.parse_push_config(args)?;
        self.validate_push_config(&config)?;
        self.execute_push(&config).await
    }

    /// Status verb implementation
    pub async fn status(&self, args: Value) -> Result<Value, GitError> {
        let config = self.parse_status_config(args)?;
        self.validate_status_config(&config)?;
        self.execute_status(&config).await
    }

    /// Branch verb implementation
    pub async fn branch(&self, args: Value) -> Result<Value, GitError> {
        let config = self.parse_branch_config(args)?;
        self.validate_branch_config(&config)?;
        self.execute_branch(&config).await
    }

    /// Commit verb implementation
    pub async fn commit(&self, args: Value) -> Result<Value, GitError> {
        let config = self.parse_commit_config(args)?;
        self.validate_commit_config(&config)?;
        self.execute_commit(&config).await
    }

    /// Diff verb implementation
    pub async fn diff(&self, args: Value) -> Result<Value, GitError> {
        let config = self.parse_diff_config(args)?;
        self.validate_diff_config(&config)?;
        self.execute_diff(&config).await
    }

    /// Tag verb implementation
    pub async fn tag(&self, args: Value) -> Result<Value, GitError> {
        let config = self.parse_tag_config(args)?;
        self.validate_tag_config(&config)?;
        self.execute_tag(&config).await
    }

    /// Merge verb implementation
    pub async fn merge(&self, args: Value) -> Result<Value, GitError> {
        let config = self.parse_merge_config(args)?;
        self.validate_merge_config(&config)?;
        self.execute_merge(&config).await
    }

    /// Rebase verb implementation
    pub async fn rebase(&self, args: Value) -> Result<Value, GitError> {
        let config = self.parse_rebase_config(args)?;
        self.validate_rebase_config(&config)?;
        self.execute_rebase(&config).await
    }

    /// Parse clone configuration from arguments
    fn parse_clone_config(&self, args: Value) -> Result<CloneConfig, GitError> {
        crate::core::lenient::from_value(args).map_err(|e| GitError::InvalidCloneConfig {
            message: format!("failed to parse clone config: {}", e),
        })
    }

    /// Parse pull configuration from arguments
    fn parse_pull_config(&self, args: Value) -> Result<PullConfig, GitError> {
        crate::core::lenient::from_value(args).map_err(|e| GitError::InvalidPullConfig {
            message: format!("failed to parse pull config: {}", e),
        })
    }

    /// Parse push configuration from arguments
    fn parse_push_config(&self, args: Value) -> Result<PushConfig, GitError> {
        crate::core::lenient::from_value(args).map_err(|e| GitError::InvalidPushConfig {
            message: format!("failed to parse push config: {}", e),
        })
    }

    /// Validate clone configuration
    fn validate_clone_config(&self, config: &CloneConfig) -> Result<(), GitError> {
        // Check required fields
        if config.url.is_empty() {
            return Err(GitError::InvalidCloneConfig {
                message: "url cannot be empty".to_string(),
            });
        }

        if config.path.is_empty() {
            return Err(GitError::InvalidCloneConfig {
                message: "path cannot be empty".to_string(),
            });
        }

        // Check depth constraint
        if let Some(depth) = config.depth {
            if depth == 0 {
                return Err(GitError::InvalidCloneConfig {
                    message: "depth must be greater than 0".to_string(),
                });
            }
        }

        // Check timeout constraint
        if let Some(timeout_ms) = config.timeout_ms {
            if timeout_ms == 0 {
                return Err(GitError::InvalidCloneConfig {
                    message: "timeout_ms must be greater than 0".to_string(),
                });
            }
        }

        check_clone_url(&config.url).map_err(|message| GitError::InvalidCloneConfig { message })?;
        if config.depth.is_some() && net::is_local_url(&config.url) {
            return Err(GitError::InvalidCloneConfig {
                message: "depth needs a network remote: libgit2's local transport (file:// URLs \
                          and local paths) cannot make shallow clones"
                    .to_string(),
            });
        }
        if config.path.starts_with('-') {
            return Err(GitError::InvalidCloneConfig {
                message: format!("path {:?} must not start with '-'", config.path),
            });
        }

        // known_hosts_path is only read when the remote uses SSH, but an
        // empty value is never meaningful.
        if config.known_hosts_path.as_deref() == Some("") {
            return Err(GitError::InvalidCloneConfig {
                message: "known_hosts_path cannot be empty".to_string(),
            });
        }

        // Check for multiple auth methods
        let auth_methods = [
            config.ssh_key.is_some(),
            (config.username.is_some() && config.password.is_some()),
            config.token.is_some(),
        ];
        let auth_count = auth_methods.iter().filter(|&&x| x).count();

        if auth_count > 1 {
            return Err(GitError::InvalidCloneConfig {
                message: "multiple authentication methods specified".to_string(),
            });
        }

        Ok(())
    }

    /// Validate pull configuration
    fn validate_pull_config(&self, config: &PullConfig) -> Result<(), GitError> {
        // Check required fields
        if config.path.is_empty() {
            return Err(GitError::InvalidPullConfig {
                message: "path cannot be empty".to_string(),
            });
        }

        // Check timeout constraint
        if let Some(timeout_ms) = config.timeout_ms {
            if timeout_ms == 0 {
                return Err(GitError::InvalidPullConfig {
                    message: "timeout_ms must be greater than 0".to_string(),
                });
            }
        }

        // Validate remote and branch names if provided
        if let Some(ref remote) = config.remote {
            if remote.is_empty() {
                return Err(GitError::InvalidPullConfig {
                    message: "remote cannot be empty string".to_string(),
                });
            }
        }

        if let Some(ref branch) = config.branch {
            if branch.is_empty() {
                return Err(GitError::InvalidPullConfig {
                    message: "branch cannot be empty string".to_string(),
                });
            }
        }

        // known_hosts_path is only read when the remote uses SSH, but an
        // empty value is never meaningful.
        if config.known_hosts_path.as_deref() == Some("") {
            return Err(GitError::InvalidPullConfig {
                message: "known_hosts_path cannot be empty".to_string(),
            });
        }

        // Check for multiple auth methods
        let auth_methods = [
            config.ssh_key.is_some(),
            (config.username.is_some() && config.password.is_some()),
            config.token.is_some(),
        ];
        let auth_count = auth_methods.iter().filter(|&&x| x).count();

        if auth_count > 1 {
            return Err(GitError::InvalidPullConfig {
                message: "multiple authentication methods specified".to_string(),
            });
        }

        // Check path exists and is a directory
        let path = Path::new(&config.path);
        if !path.exists() {
            return Err(GitError::RepositoryNotFound {
                path: config.path.clone(),
            });
        }

        if !path.is_dir() {
            return Err(GitError::InvalidPullConfig {
                message: "path must be a directory".to_string(),
            });
        }

        Ok(())
    }

    /// Validate push configuration
    fn validate_push_config(&self, config: &PushConfig) -> Result<(), GitError> {
        // Check required fields
        if config.path.is_empty() {
            return Err(GitError::InvalidPushConfig {
                message: "path cannot be empty".to_string(),
            });
        }

        // Check timeout constraint
        if let Some(timeout_ms) = config.timeout_ms {
            if timeout_ms == 0 {
                return Err(GitError::InvalidPushConfig {
                    message: "timeout_ms must be greater than 0".to_string(),
                });
            }
        }

        // Check that both branch and branches are not provided
        if config.branch.is_some() && config.branches.is_some() {
            return Err(GitError::InvalidPushConfig {
                message: "cannot specify both branch and branches".to_string(),
            });
        }

        // Check that branches is not empty if provided
        if let Some(ref branches) = config.branches {
            if branches.is_empty() {
                return Err(GitError::InvalidPushConfig {
                    message: "branches array cannot be empty".to_string(),
                });
            }
        }

        // Check mutually exclusive force and ff_only
        if config.force.unwrap_or(false) && config.ff_only.unwrap_or(false) {
            return Err(GitError::InvalidPushConfig {
                message: "force and ff_only are mutually exclusive".to_string(),
            });
        }

        // Validate remote name if provided
        if let Some(ref remote) = config.remote {
            if remote.is_empty() {
                return Err(GitError::InvalidPushConfig {
                    message: "remote cannot be empty string".to_string(),
                });
            }
        }

        // known_hosts_path is only read when the remote uses SSH, but an
        // empty value is never meaningful.
        if config.known_hosts_path.as_deref() == Some("") {
            return Err(GitError::InvalidPushConfig {
                message: "known_hosts_path cannot be empty".to_string(),
            });
        }

        // Check for multiple auth methods
        let auth_methods = [
            config.ssh_key.is_some(),
            (config.username.is_some() && config.password.is_some()),
            config.token.is_some(),
        ];
        let auth_count = auth_methods.iter().filter(|&&x| x).count();

        if auth_count > 1 {
            return Err(GitError::InvalidPushConfig {
                message: "multiple authentication methods specified".to_string(),
            });
        }

        // Check path exists and is a directory
        let path = Path::new(&config.path);
        if !path.exists() {
            return Err(GitError::RepositoryNotFound {
                path: config.path.clone(),
            });
        }

        if !path.is_dir() {
            return Err(GitError::InvalidPushConfig {
                message: "path must be a directory".to_string(),
            });
        }

        Ok(())
    }

    /// Parse status configuration from arguments
    fn parse_status_config(&self, args: Value) -> Result<StatusConfig, GitError> {
        crate::core::lenient::from_value(args).map_err(|e| GitError::InvalidStatusConfig {
            message: format!("failed to parse status config: {}", e),
        })
    }

    /// Validate status configuration
    fn validate_status_config(&self, config: &StatusConfig) -> Result<(), GitError> {
        // Check required fields
        if config.path.is_empty() {
            return Err(GitError::InvalidStatusConfig {
                message: "path cannot be empty".to_string(),
            });
        }

        // Check timeout constraint
        if let Some(timeout_ms) = config.timeout_ms {
            if timeout_ms == 0 {
                return Err(GitError::InvalidStatusConfig {
                    message: "timeout_ms must be greater than 0".to_string(),
                });
            }
        }

        // Check path exists and is a directory
        let path = Path::new(&config.path);
        if !path.exists() {
            return Err(GitError::RepositoryNotFound {
                path: config.path.clone(),
            });
        }

        if !path.is_dir() {
            return Err(GitError::InvalidStatusConfig {
                message: "path must be a directory".to_string(),
            });
        }

        Ok(())
    }

    /// Parse branch configuration from arguments
    fn parse_branch_config(&self, args: Value) -> Result<BranchConfig, GitError> {
        crate::core::lenient::from_value(args).map_err(|e| GitError::InvalidBranchConfig {
            message: format!("failed to parse branch config: {}", e),
        })
    }

    /// Validate branch configuration
    fn validate_branch_config(&self, config: &BranchConfig) -> Result<(), GitError> {
        // Check required fields
        if config.path.is_empty() {
            return Err(GitError::InvalidBranchConfig {
                message: "path cannot be empty".to_string(),
            });
        }

        // Check timeout constraint
        if let Some(timeout_ms) = config.timeout_ms {
            if timeout_ms == 0 {
                return Err(GitError::InvalidBranchConfig {
                    message: "timeout_ms must be greater than 0".to_string(),
                });
            }
        }

        // Get action (default to List if not provided)
        let action = config.action.as_ref().unwrap_or(&BranchAction::List);

        // Options that only some actions use are refused for the others,
        // instead of being silently ignored.
        let (action_name, used): (&str, &[&str]) = match action {
            BranchAction::List => ("list", &["local_only", "remote_only", "all"]),
            BranchAction::Create => (
                "create",
                &["name", "start_point", "track", "remote", "force"],
            ),
            BranchAction::Delete => ("delete", &["name", "force"]),
            BranchAction::Rename => ("rename", &["name", "new_name", "force"]),
            BranchAction::Checkout => ("checkout", &["name", "force"]),
        };
        let given = [
            ("name", config.name.is_some()),
            ("new_name", config.new_name.is_some()),
            ("start_point", config.start_point.is_some()),
            ("track", config.track.is_some()),
            ("remote", config.remote.is_some()),
            ("local_only", config.local_only.is_some()),
            ("remote_only", config.remote_only.is_some()),
            ("all", config.all.is_some()),
            ("force", config.force.is_some()),
        ];
        if let Some((key, _)) = given.iter().find(|(k, set)| *set && !used.contains(k)) {
            return Err(GitError::InvalidBranchConfig {
                message: format!(
                    "{key} does not apply to action={action_name} (it uses: {})",
                    used.join(", ")
                ),
            });
        }
        if config.remote.is_some() && config.track != Some(true) {
            return Err(GitError::InvalidBranchConfig {
                message: "remote is only used with track=true".to_string(),
            });
        }

        if matches!(action, BranchAction::Create | BranchAction::Rename) {
            let new = if matches!(action, BranchAction::Create) {
                &config.name
            } else {
                &config.new_name
            };
            if let Some(n) = new.as_deref().filter(|n| !n.is_empty()) {
                if n.starts_with('-') || !git2::Branch::name_is_valid(n).unwrap_or(false) {
                    return Err(GitError::InvalidBranchConfig {
                        message: format!("invalid branch name {n:?}"),
                    });
                }
            }
        }

        // List flags: at most one of all, local_only and remote_only may be
        // true; with none, local branches are listed.
        if matches!(action, BranchAction::List) {
            let set = [config.all, config.local_only, config.remote_only]
                .iter()
                .filter(|f| **f == Some(true))
                .count();
            if set > 1 {
                return Err(GitError::InvalidBranchConfig {
                    message: "invalid list flags combination: set at most one of all=true, local_only=true or remote_only=true".to_string(),
                });
            }
        }

        // Action-specific validation
        match action {
            BranchAction::Create => {
                if config.name.is_none() || config.name.as_ref().unwrap().is_empty() {
                    return Err(GitError::InvalidBranchConfig {
                        message: "name is required for create action".to_string(),
                    });
                }
            }
            BranchAction::Delete => {
                if config.name.is_none() || config.name.as_ref().unwrap().is_empty() {
                    return Err(GitError::InvalidBranchConfig {
                        message: "name is required for delete action".to_string(),
                    });
                }
            }
            BranchAction::Rename => {
                if config.name.is_none() || config.name.as_ref().unwrap().is_empty() {
                    return Err(GitError::InvalidBranchConfig {
                        message: "name is required for rename action".to_string(),
                    });
                }
                if config.new_name.is_none() || config.new_name.as_ref().unwrap().is_empty() {
                    return Err(GitError::InvalidBranchConfig {
                        message: "new_name is required for rename action".to_string(),
                    });
                }
                if config.name == config.new_name {
                    return Err(GitError::InvalidBranchConfig {
                        message: "name and new_name cannot be the same".to_string(),
                    });
                }
            }
            BranchAction::Checkout => {
                if config.name.is_none() || config.name.as_ref().unwrap().is_empty() {
                    return Err(GitError::InvalidBranchConfig {
                        message: "name is required for checkout action".to_string(),
                    });
                }
            }
            BranchAction::List => {
                // Already validated above
            }
        }

        // Check path exists and is a directory
        let path = Path::new(&config.path);
        if !path.exists() {
            return Err(GitError::RepositoryNotFound {
                path: config.path.clone(),
            });
        }

        if !path.is_dir() {
            return Err(GitError::InvalidBranchConfig {
                message: "path must be a directory".to_string(),
            });
        }

        Ok(())
    }

    /// Parse commit configuration from arguments
    fn parse_commit_config(&self, args: Value) -> Result<CommitConfig, GitError> {
        let mut config: CommitConfig =
            crate::core::lenient::from_value(args).map_err(|e| GitError::InvalidCommitConfig {
                message: format!("invalid commit arguments: {}", e),
            })?;
        // A CLI value is always text: digits are Unix seconds.
        if let Some(CommitTimestamp::Iso8601(text)) = &config.timestamp {
            if let Ok(secs) = text.trim().parse::<u64>() {
                config.timestamp = Some(CommitTimestamp::UnixSeconds(secs));
            }
        }
        Ok(config)
    }

    /// Parse diff configuration from arguments
    fn parse_diff_config(&self, args: Value) -> Result<DiffConfig, GitError> {
        crate::core::lenient::from_value(args).map_err(|e| GitError::InvalidDiffConfig {
            message: format!("invalid diff arguments: {}", e),
        })
    }

    /// Parse tag configuration from arguments
    fn parse_tag_config(&self, args: Value) -> Result<TagConfig, GitError> {
        let mut config: TagConfig =
            crate::core::lenient::from_value(args).map_err(|e| GitError::InvalidTagConfig {
                message: format!("invalid tag arguments: {}", e),
            })?;
        // A CLI value is always text: digits are Unix seconds.
        if let Some(TagTimestamp::Iso8601(text)) = &config.timestamp {
            if let Ok(secs) = text.trim().parse::<u64>() {
                config.timestamp = Some(TagTimestamp::UnixSeconds(secs));
            } else if chrono::DateTime::parse_from_rfc3339(text).is_err() {
                return Err(GitError::InvalidTagConfig {
                    message: format!("invalid ISO8601 timestamp: {}", text),
                });
            }
        }
        Ok(config)
    }

    /// Validate tag configuration
    fn validate_tag_config(&self, config: &TagConfig) -> Result<(), GitError> {
        // Validate required fields
        if config.path.is_empty() {
            return Err(GitError::InvalidTagConfig {
                message: "path is required".to_string(),
            });
        }

        if let Some(timeout_ms) = config.timeout_ms {
            if timeout_ms == 0 {
                return Err(GitError::InvalidTagConfig {
                    message: "timeout_ms must be greater than 0".to_string(),
                });
            }
        }

        let action = config.action.as_ref().unwrap_or(&TagAction::List);

        // Options that only some actions use are refused for the others.
        let annotated = config.annotated.unwrap_or(false);
        let (action_name, used): (&str, Vec<&str>) = match action {
            TagAction::List => ("list", vec!["pattern", "sort"]),
            TagAction::Create if annotated => (
                "create",
                vec![
                    "name",
                    "annotated",
                    "message",
                    "target",
                    "force",
                    "author_name",
                    "author_email",
                    "timestamp",
                ],
            ),
            TagAction::Create => ("create", vec!["name", "annotated", "target", "force"]),
            TagAction::Delete => ("delete", vec!["name", "names"]),
        };
        let given = [
            ("name", config.name.is_some()),
            ("names", config.names.is_some()),
            ("pattern", config.pattern.is_some()),
            ("sort", config.sort.is_some()),
            ("annotated", config.annotated.is_some()),
            ("message", config.message.is_some()),
            ("target", config.target.is_some()),
            ("force", config.force.is_some()),
            ("author_name", config.author_name.is_some()),
            ("author_email", config.author_email.is_some()),
            ("timestamp", config.timestamp.is_some()),
        ];
        if let Some((key, _)) = given.iter().find(|(k, set)| *set && !used.contains(k)) {
            let why = if matches!(action, TagAction::Create) {
                " (message, author_name, author_email and timestamp need annotated=true)"
            } else {
                ""
            };
            return Err(GitError::InvalidTagConfig {
                message: format!(
                    "{key} does not apply to action={action_name}{why}; it uses: {}",
                    used.join(", ")
                ),
            });
        }
        for name in config.name.iter().chain(config.names.iter().flatten()) {
            if name.starts_with('-')
                || !git2::Reference::is_valid_name(&format!("refs/tags/{name}"))
            {
                return Err(GitError::InvalidTagConfig {
                    message: format!("invalid tag name {name:?}"),
                });
            }
        }

        match action {
            TagAction::List => {
                // No additional validation needed for list
            }
            TagAction::Create => {
                if config.name.is_none() || config.name.as_ref().unwrap().is_empty() {
                    return Err(GitError::InvalidTagConfig {
                        message: "name is required for create action".to_string(),
                    });
                }

                let annotated = config.annotated.unwrap_or(false);
                if annotated
                    && (config.message.is_none() || config.message.as_ref().unwrap().is_empty())
                {
                    return Err(GitError::InvalidTagConfig {
                        message: "message is required for annotated tags".to_string(),
                    });
                }
            }
            TagAction::Delete => {
                let has_name = config.name.is_some() && !config.name.as_ref().unwrap().is_empty();
                let has_names =
                    config.names.is_some() && !config.names.as_ref().unwrap().is_empty();

                if !has_name && config.names.as_ref().is_some_and(|n| n.is_empty()) {
                    return Err(GitError::InvalidTagConfig {
                        message: "names array cannot be empty".to_string(),
                    });
                }

                if !has_name && !has_names {
                    return Err(GitError::InvalidTagConfig {
                        message: "either name or names is required for delete action".to_string(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Parse merge configuration from arguments
    fn parse_merge_config(&self, args: Value) -> Result<MergeConfig, GitError> {
        crate::core::lenient::from_value(args).map_err(|e| GitError::InvalidMergeConfig {
            message: format!("invalid merge arguments: {}", e),
        })
    }

    /// Validate merge configuration
    fn validate_merge_config(&self, config: &MergeConfig) -> Result<(), GitError> {
        // Validate required fields
        if config.path.is_empty() {
            return Err(GitError::InvalidMergeConfig {
                message: "path is required".to_string(),
            });
        }

        if config.source.is_empty() {
            return Err(GitError::InvalidMergeConfig {
                message: "source is required".to_string(),
            });
        }

        // Check timeout constraint
        if let Some(timeout_ms) = config.timeout_ms {
            if timeout_ms == 0 {
                return Err(GitError::InvalidMergeConfig {
                    message: "timeout_ms must be greater than 0".to_string(),
                });
            }
        }

        // Check mutually exclusive options
        let ff_only = config.ff_only.unwrap_or(false);
        let no_ff = config.no_ff.unwrap_or(false);

        if ff_only && no_ff {
            return Err(GitError::InvalidMergeConfig {
                message: "ff_only and no_ff cannot both be true".to_string(),
            });
        }

        // Validate target if provided
        if let Some(target) = &config.target {
            if target.is_empty() {
                return Err(GitError::InvalidMergeConfig {
                    message: "target cannot be empty string".to_string(),
                });
            }
        }

        // Validate identity fields if provided
        if let Some(name) = &config.author_name {
            if name.is_empty() {
                return Err(GitError::InvalidMergeConfig {
                    message: "author_name cannot be empty string".to_string(),
                });
            }
        }

        if let Some(email) = &config.author_email {
            if email.is_empty() {
                return Err(GitError::InvalidMergeConfig {
                    message: "author_email cannot be empty string".to_string(),
                });
            }
        }

        if let Some(name) = &config.committer_name {
            if name.is_empty() {
                return Err(GitError::InvalidMergeConfig {
                    message: "committer_name cannot be empty string".to_string(),
                });
            }
        }

        if let Some(email) = &config.committer_email {
            if email.is_empty() {
                return Err(GitError::InvalidMergeConfig {
                    message: "committer_email cannot be empty string".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Parse rebase configuration from arguments
    fn parse_rebase_config(&self, args: Value) -> Result<RebaseConfig, GitError> {
        crate::core::lenient::from_value(args).map_err(|e| GitError::InvalidRebaseConfig {
            message: format!("invalid rebase arguments: {}", e),
        })
    }

    /// Validate rebase configuration
    fn validate_rebase_config(&self, config: &RebaseConfig) -> Result<(), GitError> {
        // Validate required fields
        if config.path.is_empty() {
            return Err(GitError::InvalidRebaseConfig {
                message: "path is required".to_string(),
            });
        }

        // Check timeout constraint
        if let Some(timeout_ms) = config.timeout_ms {
            if timeout_ms == 0 {
                return Err(GitError::InvalidRebaseConfig {
                    message: "timeout_ms must be greater than 0".to_string(),
                });
            }
        }

        // Validate operation-specific requirements
        let operation = config.operation.as_ref().unwrap_or(&RebaseOperation::Start);
        match operation {
            RebaseOperation::Start => {
                // For start operation, upstream is required
                if config.upstream.is_none() || config.upstream.as_ref().unwrap().is_empty() {
                    return Err(GitError::InvalidRebaseConfig {
                        message: "upstream is required for start operation".to_string(),
                    });
                }
            }
            RebaseOperation::Continue | RebaseOperation::Abort => {
                // For continue/abort, upstream is ignored but operation should be valid
            }
        }

        // Validate branch name if provided
        if let Some(ref branch) = config.branch {
            if branch.is_empty() {
                return Err(GitError::InvalidRebaseConfig {
                    message: "branch cannot be empty string".to_string(),
                });
            }
        }

        // Validate identity fields if provided
        if let Some(ref name) = config.author_name {
            if name.is_empty() {
                return Err(GitError::InvalidRebaseConfig {
                    message: "author_name cannot be empty string".to_string(),
                });
            }
        }

        if let Some(ref email) = config.author_email {
            if email.is_empty() {
                return Err(GitError::InvalidRebaseConfig {
                    message: "author_email cannot be empty string".to_string(),
                });
            }
        }

        if let Some(ref name) = config.committer_name {
            if name.is_empty() {
                return Err(GitError::InvalidRebaseConfig {
                    message: "committer_name cannot be empty string".to_string(),
                });
            }
        }

        if let Some(ref email) = config.committer_email {
            if email.is_empty() {
                return Err(GitError::InvalidRebaseConfig {
                    message: "committer_email cannot be empty string".to_string(),
                });
            }
        }

        if config.author_name.is_some() != config.author_email.is_some() {
            return Err(GitError::InvalidRebaseConfig {
                message: "author_name and author_email must be given together".to_string(),
            });
        }

        // libgit2 can neither keep merge commits nor reorder fixup!/squash!
        // commits; asking for either is refused instead of performing a
        // plain rebase the caller did not ask for.
        if config.preserve_merges == Some(true) {
            return Err(GitError::RebasePreserveMergesUnsupported);
        }
        if config.autosquash == Some(true) {
            return Err(GitError::InvalidRebaseConfig {
                message: "autosquash=true is not supported (libgit2 cannot reorder fixup!/squash! commits); rebase without it".to_string(),
            });
        }

        // operation=continue and operation=abort act on the rebase in
        // progress: the start options do not apply.
        if !matches!(operation, RebaseOperation::Start) {
            let given = [
                ("upstream", config.upstream.is_some()),
                ("branch", config.branch.is_some()),
                ("ff_only", config.ff_only.is_some()),
                ("allow_uncommitted", config.allow_uncommitted.is_some()),
            ];
            if let Some((key, _)) = given.iter().find(|(_, set)| *set) {
                return Err(GitError::InvalidRebaseConfig {
                    message: format!("{key} only applies to operation=start"),
                });
            }
        }

        Ok(())
    }

    /// Validate commit configuration
    fn validate_commit_config(&self, config: &CommitConfig) -> Result<(), GitError> {
        // Check required fields
        if config.path.is_empty() {
            return Err(GitError::InvalidCommitConfig {
                message: "path cannot be empty".to_string(),
            });
        }

        // Check timeout constraint
        if let Some(timeout_ms) = config.timeout_ms {
            if timeout_ms == 0 {
                return Err(GitError::InvalidCommitConfig {
                    message: "timeout_ms must be greater than 0".to_string(),
                });
            }
        }

        // Check message requirement based on amend and no_edit flags
        let amend = config.amend.unwrap_or(false);
        let no_edit = config.no_edit.unwrap_or(false);

        if no_edit && !amend {
            return Err(GitError::InvalidCommitConfig {
                message: "no_edit can only be used with amend=true".to_string(),
            });
        }

        if !(amend && no_edit)
            && (config.message.is_none() || config.message.as_ref().unwrap().is_empty())
        {
            return Err(GitError::InvalidCommitConfig {
                message: "message cannot be empty unless amend=true and no_edit=true".to_string(),
            });
        }

        // Check paths is not empty if provided
        if let Some(ref paths) = config.paths {
            if paths.is_empty() {
                return Err(GitError::InvalidCommitConfig {
                    message: "paths cannot be an empty array".to_string(),
                });
            }
        }

        // Validate timestamp format if provided
        if let Some(ref timestamp) = config.timestamp {
            match timestamp {
                CommitTimestamp::Iso8601(iso) => {
                    if chrono::DateTime::parse_from_rfc3339(iso).is_err() {
                        return Err(GitError::InvalidCommitConfig {
                            message: format!("invalid ISO8601 timestamp: {}", iso),
                        });
                    }
                }
                CommitTimestamp::UnixSeconds(_) => {
                    // Unix timestamps are always valid as u64
                }
            }
        }

        // Check path exists and is a directory
        let path = Path::new(&config.path);
        if !path.exists() {
            return Err(GitError::RepositoryNotFound {
                path: config.path.clone(),
            });
        }

        if !path.is_dir() {
            return Err(GitError::InvalidCommitConfig {
                message: "path must be a directory".to_string(),
            });
        }

        Ok(())
    }

    /// Validate diff configuration
    fn validate_diff_config(&self, config: &DiffConfig) -> Result<(), GitError> {
        // Check required fields
        if config.path.is_empty() {
            return Err(GitError::InvalidDiffConfig {
                message: "path cannot be empty".to_string(),
            });
        }

        // Check timeout constraint
        if let Some(timeout_ms) = config.timeout_ms {
            if timeout_ms == 0 {
                return Err(GitError::InvalidDiffConfig {
                    message: "timeout_ms must be greater than 0".to_string(),
                });
            }
        }

        // Check unified context lines
        if let Some(unified) = config.unified {
            if unified < 0 {
                return Err(GitError::InvalidDiffConfig {
                    message: "unified context lines cannot be negative".to_string(),
                });
            }
        }

        // Check rename threshold
        if let Some(threshold) = config.rename_threshold {
            if threshold > 100 {
                return Err(GitError::InvalidDiffConfig {
                    message: "rename_threshold cannot exceed 100".to_string(),
                });
            }
        }

        // Check max_files and max_hunks
        if let Some(max_files) = config.max_files {
            if max_files == 0 {
                return Err(GitError::InvalidDiffConfig {
                    message: "max_files must be greater than 0".to_string(),
                });
            }
        }

        if let Some(max_hunks) = config.max_hunks {
            if max_hunks == 0 {
                return Err(GitError::InvalidDiffConfig {
                    message: "max_hunks must be greater than 0".to_string(),
                });
            }
        }

        // Check mode and from/to requirements
        let mode = config.mode.as_ref().unwrap_or(&DiffMode::WorkdirVsIndex);
        match mode {
            DiffMode::CommitVsCommit => {
                if config.from.is_none() {
                    return Err(GitError::InvalidDiffConfig {
                        message: "from is required for commit_vs_commit mode".to_string(),
                    });
                }
                if config.to.is_none() {
                    return Err(GitError::InvalidDiffConfig {
                        message: "to is required for commit_vs_commit mode".to_string(),
                    });
                }
            }
            DiffMode::CommitVsWorkdir | DiffMode::CommitVsIndex => {
                if config.from.is_none() {
                    return Err(GitError::InvalidDiffConfig {
                        message: "from is required for commit-based modes".to_string(),
                    });
                }
            }
            _ => {} // Other modes don't require from/to
        }

        // Check paths is not empty if provided
        if let Some(ref paths) = config.paths {
            if paths.is_empty() {
                return Err(GitError::InvalidDiffConfig {
                    message: "paths cannot be an empty array".to_string(),
                });
            }
        }

        // Check path exists and is a directory
        let path = Path::new(&config.path);
        if !path.exists() {
            return Err(GitError::RepositoryNotFound {
                path: config.path.clone(),
            });
        }

        if !path.is_dir() {
            return Err(GitError::InvalidDiffConfig {
                message: "path must be a directory".to_string(),
            });
        }

        Ok(())
    }

    /// Stage files based on 'all' flag and 'paths' list
    fn stage_commit_files(
        &self,
        repo: &Repository,
        config: &CommitConfig,
    ) -> Result<usize, GitError> {
        let mut index = repo.index().map_err(|e| GitError::CommitFailed {
            message: format!("failed to get repository index: {}", e),
        })?;

        let mut staged_count = 0;

        // Stage files based on 'all' flag
        if config.all.unwrap_or(false) {
            staged_count += self.stage_all_tracked_changes(repo, &mut index)?;
        }

        // Stage specific paths if provided
        if let Some(ref paths) = config.paths {
            for path in paths {
                staged_count += self.stage_specific_path(repo, &mut index, path)?;
            }
        }

        // Write the index
        index.write().map_err(|e| GitError::CommitFailed {
            message: format!("failed to write index: {}", e),
        })?;

        Ok(staged_count)
    }

    /// Stage all tracked modified/deleted files (equivalent to git commit -a)
    fn stage_all_tracked_changes(
        &self,
        repo: &Repository,
        index: &mut Index,
    ) -> Result<usize, GitError> {
        let statuses = repo.statuses(None).map_err(|e| GitError::CommitFailed {
            message: format!("failed to get repository status: {}", e),
        })?;

        let mut staged_count = 0;

        for status_entry in statuses.iter() {
            let status = status_entry.status();
            let path = status_entry
                .path()
                .ok()
                .ok_or_else(|| GitError::CommitFailed {
                    message: "invalid file path in status".to_string(),
                })?;

            // Only stage tracked files that have working tree changes
            if status.contains(GitStatus::WT_MODIFIED) || status.contains(GitStatus::WT_DELETED) {
                if status.contains(GitStatus::WT_DELETED) {
                    // Remove deleted file from index
                    index
                        .remove_path(Path::new(path))
                        .map_err(|e| GitError::CommitFailed {
                            message: format!("failed to remove path from index: {}", e),
                        })?;
                } else {
                    // Add modified file to index
                    index
                        .add_path(Path::new(path))
                        .map_err(|e| GitError::CommitFailed {
                            message: format!("failed to add path to index: {}", e),
                        })?;
                }
                staged_count += 1;
            }
        }

        Ok(staged_count)
    }

    /// Stage a specific path
    fn stage_specific_path(
        &self,
        repo: &Repository,
        index: &mut Index,
        path: &str,
    ) -> Result<usize, GitError> {
        // Index paths are relative to the work tree, so resolve the given path
        // against it rather than the process's current directory. Absolute
        // paths inside the work tree are accepted too.
        let workdir = repo.workdir().ok_or_else(|| GitError::CommitFailed {
            message: "cannot stage paths in a bare repository".to_string(),
        })?;
        let given = Path::new(path);
        let rel_path: PathBuf = if given.is_absolute() {
            given
                .strip_prefix(workdir)
                .map(Path::to_path_buf)
                .map_err(|_| GitError::CommitFailed {
                    message: format!("path '{}' is outside the repository work tree", path),
                })?
        } else {
            given.to_path_buf()
        };

        if workdir.join(&rel_path).exists() {
            // Add the file to index
            index
                .add_path(&rel_path)
                .map_err(|e| GitError::CommitFailed {
                    message: format!("failed to add path '{}' to index: {}", path, e),
                })?;
            Ok(1)
        } else {
            // File might be deleted, try to remove from index
            match index.remove_path(&rel_path) {
                Ok(_) => Ok(1),
                Err(e) => Err(GitError::CommitFailed {
                    message: format!("failed to stage path '{}': {}", path, e),
                }),
            }
        }
    }

    /// Check if there are changes to commit by comparing index with HEAD
    fn has_changes_to_commit(
        &self,
        repo: &Repository,
        allow_empty: bool,
    ) -> Result<bool, GitError> {
        if allow_empty {
            return Ok(true);
        }

        let mut index = repo.index().map_err(|e| GitError::CommitFailed {
            message: format!("failed to get repository index: {}", e),
        })?;

        // Write index tree to get current staged state
        let index_tree_oid = index.write_tree().map_err(|e| GitError::CommitFailed {
            message: format!("failed to write index tree: {}", e),
        })?;

        // Compare with HEAD tree if it exists
        match repo.head() {
            Ok(head_ref) => {
                // HEAD exists, compare trees
                let head_commit =
                    head_ref
                        .peel_to_commit()
                        .map_err(|e| GitError::CommitFailed {
                            message: format!("failed to get HEAD commit: {}", e),
                        })?;
                let head_tree_oid = head_commit.tree_id();

                Ok(index_tree_oid != head_tree_oid)
            }
            Err(_) => {
                // No HEAD (empty repository), check if index has any entries
                Ok(index.len() > 0)
            }
        }
    }

    /// Resolve commit author identity with fallback chain
    fn resolve_commit_author(
        &self,
        repo: &Repository,
        config: &CommitConfig,
    ) -> Result<(String, String), GitError> {
        // Priority: config fields -> alias profile -> git config

        let name = config
            .author_name
            .clone()
            .or_else(|| self.get_git_config_value(repo, "user.name"))
            .ok_or(GitError::CommitIdentityMissing)?;

        let email = config
            .author_email
            .clone()
            .or_else(|| self.get_git_config_value(repo, "user.email"))
            .ok_or(GitError::CommitIdentityMissing)?;

        Ok((name, email))
    }

    /// Resolve commit committer identity with fallback to author
    fn resolve_commit_committer(
        &self,
        repo: &Repository,
        config: &CommitConfig,
        author: &(String, String),
    ) -> Result<(String, String), GitError> {
        // Priority: config fields -> author identity

        let name = config
            .committer_name
            .clone()
            .or_else(|| config.author_name.clone())
            .or_else(|| self.get_git_config_value(repo, "user.name"))
            .unwrap_or_else(|| author.0.clone());

        let email = config
            .committer_email
            .clone()
            .or_else(|| config.author_email.clone())
            .or_else(|| self.get_git_config_value(repo, "user.email"))
            .unwrap_or_else(|| author.1.clone());

        Ok((name, email))
    }

    /// Get a value from Git configuration
    fn get_git_config_value(&self, repo: &Repository, key: &str) -> Option<String> {
        repo.config().and_then(|config| config.get_string(key)).ok()
    }

    /// Create a Git signature from name, email and timestamp
    fn create_signature(
        &self,
        name: &str,
        email: &str,
        config: &CommitConfig,
    ) -> Result<Signature<'_>, GitError> {
        match &config.timestamp {
            Some(CommitTimestamp::Iso8601(iso)) => {
                let dt = chrono::DateTime::parse_from_rfc3339(iso).map_err(|e| {
                    GitError::InvalidCommitConfig {
                        message: format!("invalid ISO8601 timestamp: {}", e),
                    }
                })?;
                let timestamp = dt.timestamp() as i64;
                let offset = dt.offset().local_minus_utc() / 60; // offset in minutes

                Signature::new(name, email, &Time::new(timestamp, offset)).map_err(|e| {
                    GitError::CommitFailed {
                        message: format!("failed to create signature: {}", e),
                    }
                })
            }
            Some(CommitTimestamp::UnixSeconds(secs)) => {
                let timestamp = *secs as i64;
                Signature::new(name, email, &Time::new(timestamp, 0)).map_err(|e| {
                    GitError::CommitFailed {
                        message: format!("failed to create signature: {}", e),
                    }
                })
            }
            None => Signature::now(name, email).map_err(|e| GitError::CommitFailed {
                message: format!("failed to create signature: {}", e),
            }),
        }
    }

    /// Build final commit message with signoff logic
    fn build_commit_message(
        &self,
        repo: &Repository,
        config: &CommitConfig,
        author: &(String, String),
    ) -> Result<String, GitError> {
        let base_message = if config.amend.unwrap_or(false) && config.no_edit.unwrap_or(false) {
            // Use existing HEAD commit message
            match repo.head() {
                Ok(head_ref) => {
                    let head_commit =
                        head_ref
                            .peel_to_commit()
                            .map_err(|e| GitError::CommitAmendFailed {
                                message: format!("failed to get HEAD commit: {}", e),
                            })?;
                    head_commit.message().unwrap_or("").to_string()
                }
                Err(_) => return Err(GitError::CommitAmendWithoutHead),
            }
        } else {
            config.message.clone().unwrap_or_default()
        };

        let mut final_message = base_message;

        // Add signoff if requested
        if config.signoff.unwrap_or(false) {
            let signoff_line = format!("Signed-off-by: {} <{}>", author.0, author.1);

            // Check if signoff already exists to avoid duplicates
            if !final_message.contains(&signoff_line) {
                if !final_message.ends_with('\n') {
                    final_message.push('\n');
                }
                if !final_message.is_empty() {
                    final_message.push('\n');
                }
                final_message.push_str(&signoff_line);
            }
        }

        Ok(final_message)
    }

    /// Execute the actual clone operation
    async fn execute_clone(&self, config: &CloneConfig) -> Result<Value, GitError> {
        let path = Path::new(&config.path);

        // The target must be missing or an empty directory.
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(GitError::InvalidCloneConfig {
                    message: format!("path '{}' is a symbolic link", config.path),
                });
            }
            Ok(meta) if !meta.is_dir() => {
                return Err(GitError::CloneTargetNotEmpty {
                    path: config.path.clone(),
                });
            }
            Ok(_) => {
                let mut entries = path.read_dir().map_err(|e| GitError::CloneFailed {
                    message: format!("cannot read target directory '{}': {}", config.path, e),
                })?;
                if entries.next().is_some() {
                    return Err(GitError::CloneTargetNotEmpty {
                        path: config.path.clone(),
                    });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(GitError::CloneFailed {
                    message: format!("cannot inspect target '{}': {}", config.path, e),
                });
            }
        }

        // Parent directories created here are removed again if the clone
        // fails; libgit2 removes the clone directory itself.
        let created = create_missing_parents(path).map_err(|e| GitError::CloneFailed {
            message: format!("failed to create parent directories: {}", e),
        })?;

        let result = self.clone_into(config, path);
        if result.is_err() {
            for dir in created.iter().rev() {
                let _ = std::fs::remove_dir(dir);
            }
        }
        let repo = result?;

        // Validate the result
        self.validate_clone_result(&repo, path)?;

        let result = CloneResult {
            backend: "git".to_string(),
            alias: self.alias.clone(),
            url: config.url.clone(),
            path: config.path.clone(),
            branch: config.branch.clone(),
            depth: config.depth,
            recursive: config.recursive.unwrap_or(false),
            status: "cloned".to_string(),
        };

        log::info!("Successfully cloned {} to {}", config.url, config.path);
        Ok(json!(result))
    }

    /// Runs the libgit2 clone (and submodule update) for `config`.
    fn clone_into(&self, config: &CloneConfig, path: &Path) -> Result<Repository, GitError> {
        let creds = net::Credentials {
            ssh_key: config.ssh_key.clone(),
            username: config.username.clone(),
            password: config.password.clone(),
            token: config.token.clone(),
        };
        let policy = net::HostKeyPolicy::new(config.known_hosts_path.as_deref());
        let mut callbacks = RemoteCallbacks::new();
        creds.install(&mut callbacks);
        policy.install(&mut callbacks);
        let mut fetch_options = FetchOptions::new();
        fetch_options.remote_callbacks(callbacks);
        if let Some(depth) = config.depth {
            fetch_options.depth(i32::try_from(depth).unwrap_or(i32::MAX));
        }

        let mut builder = git2::build::RepoBuilder::new();
        builder.fetch_options(fetch_options);
        if let Some(branch) = &config.branch {
            builder.branch(branch);
        }
        // libgit2 creates the remote with the URL rewritten by
        // url.<base>.insteadOf from the configuration; host-key checking is
        // decided on that URL, before anything connects.
        let prepare = policy.clone();
        builder.remote_create(move |repo, name, url| {
            let remote = repo.remote(name, url)?;
            let effective = remote.url().unwrap_or(url).to_string();
            prepare.prepare(&effective).map_err(|e| {
                git2::Error::new(
                    git2::ErrorCode::Certificate,
                    git2::ErrorClass::Ssh,
                    e.to_string(),
                )
            })?;
            Ok(remote)
        });

        let cloned = {
            let _timeouts = net::apply_server_timeouts(&config.url);
            builder.clone(&config.url, path)
        };
        let repo = cloned.map_err(|e| {
            if let Some(err) = policy.explain(&e) {
                return err;
            }
            let message = format!("git clone failed: {}", e.message());
            if net::is_auth_error(&e) {
                GitError::CloneAuthFailed { message }
            } else {
                GitError::CloneFailed { message }
            }
        })?;

        if config.recursive.unwrap_or(false) {
            self.update_submodules(&repo, config, &policy)?;
        }
        Ok(repo)
    }

    /// Initializes and clones every submodule of `repo`, recursively, with
    /// the clone's credentials and host-key policy.
    fn update_submodules(
        &self,
        repo: &Repository,
        config: &CloneConfig,
        policy: &net::HostKeyPolicy,
    ) -> Result<(), GitError> {
        let failed = |e: git2::Error| GitError::CloneFailed {
            message: format!("submodule update failed: {}", e.message()),
        };
        for mut sm in repo.submodules().map_err(failed)? {
            let url = sm.url().ok().flatten().unwrap_or_default().to_string();
            policy.prepare(&url)?;
            let creds = net::Credentials {
                ssh_key: config.ssh_key.clone(),
                username: config.username.clone(),
                password: config.password.clone(),
                token: config.token.clone(),
            };
            let mut callbacks = RemoteCallbacks::new();
            creds.install(&mut callbacks);
            policy.install(&mut callbacks);
            let mut fetch_options = FetchOptions::new();
            fetch_options.remote_callbacks(callbacks);
            let mut opts = git2::SubmoduleUpdateOptions::new();
            opts.fetch(fetch_options);
            let updated = {
                let _timeouts = net::apply_server_timeouts(&url);
                sm.update(true, Some(&mut opts))
            };
            updated.map_err(|e| {
                policy.explain(&e).unwrap_or_else(|| GitError::CloneFailed {
                    message: format!(
                        "submodule '{}' update failed: {}",
                        sm.name().unwrap_or("?"),
                        e.message()
                    ),
                })
            })?;
            let sub = sm.open().map_err(failed)?;
            self.update_submodules(&sub, config, policy)?;
        }
        Ok(())
    }

    /// Validate that the clone was successful
    fn validate_clone_result(&self, repo: &Repository, path: &Path) -> Result<(), GitError> {
        if !path.exists() {
            return Err(GitError::CloneFailed {
                message: "clone target directory does not exist".to_string(),
            });
        }
        // An empty remote clones to an unborn HEAD, which is a valid clone.
        match repo.head() {
            Ok(_) => Ok(()),
            Err(e) if e.code() == git2::ErrorCode::UnbornBranch => Ok(()),
            Err(e) => Err(GitError::CloneFailed {
                message: format!("cloned repository HEAD does not resolve: {}", e),
            }),
        }
    }

    /// Execute the actual pull operation
    async fn execute_pull(&self, config: &PullConfig) -> Result<Value, GitError> {
        let path = Path::new(&config.path);
        let repo = open_repo(path, &config.path, |message| GitError::PullFailed {
            message,
        })?;

        // Determine the target branch
        let target_branch = if let Some(ref branch) = config.branch {
            branch.clone()
        } else {
            let head = repo.head().map_err(|e| GitError::PullFailed {
                message: format!(
                    "cannot read HEAD ({}); give the branch to pull with branch=",
                    e.message()
                ),
            })?;
            if !head.is_branch() {
                return Err(GitError::PullDetachedHead);
            }
            head.shorthand()
                .ok()
                .ok_or_else(|| GitError::PullFailed {
                    message: "the current branch name is not valid UTF-8".to_string(),
                })?
                .to_string()
        };

        let remote_name = config.remote.as_deref().unwrap_or("origin");
        let local_ref_name = format!("refs/heads/{}", target_branch);
        if repo.find_reference(&local_ref_name).is_err() {
            return Err(GitError::PullFailed {
                message: format!("local branch '{}' not found", target_branch),
            });
        }

        let creds = net::Credentials {
            ssh_key: config.ssh_key.clone(),
            username: config.username.clone(),
            password: config.password.clone(),
            token: config.token.clone(),
        };
        fetch_remote(
            &repo,
            remote_name,
            &creds,
            config.known_hosts_path.as_deref(),
            config.prune.unwrap_or(false),
            |message, auth| {
                if auth {
                    GitError::PullAuthFailed { message }
                } else {
                    GitError::PullFetchFailed { message }
                }
            },
        )?;

        // Find the local and remote tracking branch references
        let remote_ref_name = format!("refs/remotes/{}/{}", remote_name, target_branch);
        let local_oid = repo
            .find_reference(&local_ref_name)
            .ok()
            .and_then(|r| r.target())
            .ok_or_else(|| GitError::PullFailed {
                message: format!("local branch '{}' not found", target_branch),
            })?;
        let remote_oid = repo
            .find_reference(&remote_ref_name)
            .ok()
            .and_then(|r| r.target())
            .ok_or_else(|| GitError::PullRemoteBranchNotFound {
                branch: format!("{}/{}", remote_name, target_branch),
            })?;

        let ff_only = config.ff_only.unwrap_or(false);
        let report = |status: &str, ahead: usize, behind: usize| {
            json!(PullResult {
                backend: "git".to_string(),
                alias: self.alias.clone(),
                path: config.path.clone(),
                remote: remote_name.to_string(),
                branch: target_branch.clone(),
                status: status.to_string(),
                rebase: config.rebase.unwrap_or(false),
                ff_only,
                ahead_by: Some(ahead),
                behind_by: Some(behind),
                commits_fetched: Some(if status == "updated" { behind } else { 0 }),
            })
        };

        if local_oid == remote_oid {
            return Ok(report("up_to_date", 0, 0));
        }
        let (ahead, behind) = repo
            .graph_ahead_behind(local_oid, remote_oid)
            .map_err(|e| GitError::PullFailed {
                message: format!("failed to compute ahead/behind: {}", e),
            })?;
        if behind == 0 {
            return Ok(report("up_to_date", ahead, 0));
        }
        if ahead > 0 {
            if ff_only {
                return Err(GitError::PullNonFastForward);
            }
            return self.pull_integrate(
                &repo,
                config,
                remote_name,
                &target_branch,
                remote_oid,
                (ahead, behind),
            );
        }
        self.do_fast_forward(&repo, &local_ref_name, remote_oid, &target_branch)?;
        log::info!(
            "Fast-forwarded {} by {} commit(s) from {}/{}",
            target_branch,
            behind,
            remote_name,
            target_branch
        );
        Ok(report("updated", 0, behind))
    }

    /// Integrates diverged history for `pull`: a merge commit, or with
    /// `rebase=true` the local commits replayed onto the upstream. Needs the
    /// branch checked out and no changes to tracked files; a conflict
    /// restores the repository (or, with `abort_on_conflict=false`, leaves
    /// the merge or rebase in progress) and fails with `git.pull_conflict`.
    fn pull_integrate(
        &self,
        repo: &Repository,
        config: &PullConfig,
        remote_name: &str,
        branch: &str,
        remote_oid: Oid,
        (ahead, behind): (usize, usize),
    ) -> Result<Value, GitError> {
        let on_branch = repo
            .head()
            .map(|h| h.is_branch() && h.shorthand().ok() == Some(branch))
            .unwrap_or(false);
        if !on_branch {
            return Err(GitError::PullFailed {
                message: format!(
                    "'{branch}' and '{remote_name}/{branch}' have diverged; merging or rebasing \
                     needs '{branch}' checked out"
                ),
            });
        }
        let dirty = integrate::has_tracked_changes(repo).map_err(|e| GitError::PullFailed {
            message: format!("cannot read the working tree status: {}", e.message()),
        })?;
        if dirty {
            return Err(GitError::PullDirtyWorktree);
        }
        let (name, email) = identity(
            repo,
            config.author_name.as_deref(),
            config.author_email.as_deref(),
            "AUTHOR",
        )
        .ok_or_else(|| GitError::PullFailed {
            message: "no identity for the merge or rebased commits: set user.name and \
                      user.email, or give author_name and author_email"
                .to_string(),
        })?;
        let sig = Signature::now(&name, &email).map_err(|e| GitError::PullFailed {
            message: format!("invalid identity: {}", e.message()),
        })?;
        let rebase = config.rebase.unwrap_or(false);
        let mode = if rebase {
            integrate::Mode::Rebase
        } else {
            integrate::Mode::Merge
        };
        let upstream_name = format!("{remote_name}/{branch}");
        let outcome = integrate::integrate(
            repo,
            branch,
            &upstream_name,
            remote_oid,
            mode,
            config.abort_on_conflict.unwrap_or(true),
            &sig,
        )
        .map_err(|f| match f {
            integrate::Failure::Conflict { paths, in_progress } => {
                GitError::PullConflict { paths, in_progress }
            }
            integrate::Failure::Dirty => GitError::PullDirtyWorktree,
            integrate::Failure::Failed(message) => GitError::PullFailed { message },
        })?;
        let (status, commit, replayed) = match outcome {
            integrate::Outcome::Merged(oid) => ("merged", oid, 0),
            integrate::Outcome::Rebased { head, commits } => ("rebased", head, commits),
        };
        let mut result = json!(PullResult {
            backend: "git".to_string(),
            alias: self.alias.clone(),
            path: config.path.clone(),
            remote: remote_name.to_string(),
            branch: branch.to_string(),
            status: status.to_string(),
            rebase,
            ff_only: false,
            ahead_by: Some(ahead),
            behind_by: Some(behind),
            commits_fetched: Some(behind),
        });
        result["commit"] = json!(commit.to_string());
        result["commits_rebased"] = json!(replayed);
        Ok(result)
    }

    /// Fast-forwards `local_ref_name` to `remote_oid`. When it is the
    /// checked-out branch, the working tree is updated first with a safe
    /// checkout, so local changes are never overwritten: a change that the
    /// update would touch fails with `git.pull_dirty_worktree` and nothing
    /// moves.
    fn do_fast_forward(
        &self,
        repo: &Repository,
        local_ref_name: &str,
        remote_oid: git2::Oid,
        branch_name: &str,
    ) -> Result<(), GitError> {
        let failed = |what: &str, e: git2::Error| GitError::PullFailed {
            message: format!("{what}: {}", e.message()),
        };
        let on_branch = repo
            .head()
            .map(|h| h.is_branch() && h.shorthand().ok() == Some(branch_name))
            .unwrap_or(false);
        if on_branch {
            let commit = repo
                .find_commit(remote_oid)
                .map_err(|e| failed("failed to find commit", e))?;
            let mut checkout = git2::build::CheckoutBuilder::new();
            checkout.safe();
            repo.checkout_tree(commit.as_object(), Some(&mut checkout))
                .map_err(|e| {
                    if e.code() == git2::ErrorCode::Conflict {
                        GitError::PullDirtyWorktree
                    } else {
                        failed("failed to update the working tree", e)
                    }
                })?;
        }
        let mut local = repo
            .find_reference(local_ref_name)
            .map_err(|e| failed("failed to find local branch", e))?;
        local
            .set_target(remote_oid, &format!("pull: fast-forward to {}", remote_oid))
            .map_err(|e| failed("failed to update local branch", e))?;
        Ok(())
    }

    /// Execute the actual push operation
    async fn execute_push(&self, config: &PushConfig) -> Result<Value, GitError> {
        let path = Path::new(&config.path);
        let repo = open_repo(path, &config.path, |message| GitError::PushFailed {
            message,
        })?;

        let remote_name = config.remote.as_deref().unwrap_or("origin");
        let mut remote = repo
            .find_remote(remote_name)
            .map_err(|_| GitError::RemoteNotFound {
                remote: remote_name.to_string(),
            })?;

        let branches_to_push = self.resolve_push_branches(&repo, config)?;

        // Ahead/behind counts against the remote-tracking branches, for the
        // ff_only check and the report.
        let mut branch_statuses = Vec::new();
        for branch_name in &branches_to_push {
            let (ahead_by, behind_by) =
                self.compute_ahead_behind(&repo, branch_name, remote_name)?;
            if config.ff_only.unwrap_or(false) && behind_by > 0 {
                return Err(GitError::PushNonFastForward);
            }
            branch_statuses.push((branch_name.clone(), ahead_by, behind_by));
        }

        let creds = net::Credentials {
            ssh_key: config.ssh_key.clone(),
            username: config.username.clone(),
            password: config.password.clone(),
            token: config.token.clone(),
        };
        let policy = net::HostKeyPolicy::new(config.known_hosts_path.as_deref());
        let rejections = net::PushRejections::default();
        let mut callbacks = RemoteCallbacks::new();
        creds.install(&mut callbacks);
        policy.install(&mut callbacks);
        rejections.install(&mut callbacks);
        // The push URL after url.<base>.pushInsteadOf / insteadOf rewriting
        // (libgit2 applies both when it reads the remote).
        let push_url = remote
            .pushurl()
            .ok()
            .flatten()
            .or_else(|| remote.url().ok())
            .unwrap_or_default()
            .to_string();
        policy.prepare(&push_url)?;

        let force = config.force.unwrap_or(false);
        let mut refspecs: Vec<String> = branches_to_push
            .iter()
            .map(|b| {
                format!(
                    "{}refs/heads/{b}:refs/heads/{b}",
                    if force { "+" } else { "" }
                )
            })
            .collect();
        let tags_pushed = config.tags.unwrap_or(false);
        if tags_pushed {
            // Every local tag, by name: libgit2 does not expand wildcards
            // in push refspecs.
            let tags = repo.tag_names(None).map_err(|e| GitError::PushFailed {
                message: format!("failed to list tags: {}", e.message()),
            })?;
            for tag in tags.iter().filter_map(|t| t.ok().flatten()) {
                refspecs.push(format!(
                    "{}refs/tags/{tag}:refs/tags/{tag}",
                    if force { "+" } else { "" }
                ));
            }
        }
        let refspec_strs: Vec<&str> = refspecs.iter().map(String::as_str).collect();

        let mut push_options = git2::PushOptions::new();
        push_options.remote_callbacks(callbacks);
        let _timeouts = net::apply_server_timeouts(&push_url);
        remote
            .push(&refspec_strs, Some(&mut push_options))
            .map_err(|e| {
                if let Some(err) = policy.explain(&e) {
                    return err;
                }
                let message = format!("push failed: {}", e.message());
                if net::is_auth_error(&e) {
                    GitError::PushAuthFailed { message }
                } else if e.code() == git2::ErrorCode::NotFastForward
                    || e.message().contains("non-fast-forward")
                    || e.message().contains("not present locally")
                    || e.message().contains("rejected")
                {
                    GitError::PushRejected { message }
                } else {
                    GitError::PushFailed { message }
                }
            })?;
        if let Some(message) = rejections.message() {
            return Err(GitError::PushRejected { message });
        }

        if config.set_upstream.unwrap_or(false) {
            self.set_upstream_branches(&repo, &branches_to_push, remote_name)?;
        }

        let branches = branch_statuses
            .into_iter()
            .map(|(name, ahead_by, behind_by)| PushBranchStatus {
                name,
                status: if ahead_by == 0 && behind_by == 0 {
                    "up_to_date".to_string()
                } else {
                    "pushed".to_string()
                },
                ahead_by,
                behind_by,
            })
            .collect::<Vec<_>>();

        log::info!("Pushed {} branch(es) to {}", branches.len(), remote_name);
        Ok(json!(PushResult {
            backend: "git".to_string(),
            alias: self.alias.clone(),
            path: config.path.clone(),
            remote: remote_name.to_string(),
            branches,
            tags_pushed,
        }))
    }

    /// Execute the actual status operation
    async fn execute_status(&self, config: &StatusConfig) -> Result<Value, GitError> {
        let path = Path::new(&config.path);

        // Open the repository
        let repo = Repository::open(path).map_err(|e| {
            if e.code() == git2::ErrorCode::NotFound {
                GitError::RepositoryNotFound {
                    path: config.path.clone(),
                }
            } else {
                GitError::StatusFailed {
                    message: format!("failed to open repository: {}", e),
                }
            }
        })?;

        // Get branch information
        let branch = if config.include_branch.unwrap_or(true) {
            Some(self.get_branch_info(&repo, config.include_remote.unwrap_or(true))?)
        } else {
            None
        };

        // Get working tree status
        let working_tree = self.get_working_tree_status(&repo, config)?;

        // Get in-progress operation flags
        let in_progress = self.get_in_progress_flags(&repo)?;

        let result = StatusResult {
            backend: "git".to_string(),
            alias: self.alias.clone(),
            path: config.path.clone(),
            branch,
            working_tree,
            in_progress,
        };

        log::info!(
            "Successfully retrieved status for repository at {}",
            config.path
        );
        Ok(serde_json::to_value(result).unwrap())
    }

    /// Execute the actual branch operation
    async fn execute_branch(&self, config: &BranchConfig) -> Result<Value, GitError> {
        let path = Path::new(&config.path);

        // Open the repository
        let repo = Repository::open(path).map_err(|e| {
            if e.code() == git2::ErrorCode::NotFound {
                GitError::RepositoryNotFound {
                    path: config.path.clone(),
                }
            } else {
                GitError::BranchFailed {
                    message: format!("failed to open repository: {}", e),
                }
            }
        })?;

        // Get action (default to List if not provided)
        let action = config.action.as_ref().unwrap_or(&BranchAction::List);

        // Dispatch to appropriate operation
        match action {
            BranchAction::List => self.list_branches(&repo, config).await,
            BranchAction::Create => self.create_branch(&repo, config).await,
            BranchAction::Delete => self.delete_branch(&repo, config).await,
            BranchAction::Rename => self.rename_branch(&repo, config).await,
            BranchAction::Checkout => self.checkout_branch(&repo, config).await,
        }
    }

    /// Execute the actual commit operation
    async fn execute_commit(&self, config: &CommitConfig) -> Result<Value, GitError> {
        let path = Path::new(&config.path);

        // Open the repository
        let repo = Repository::open(path).map_err(|e| {
            if e.code() == git2::ErrorCode::NotFound {
                GitError::RepositoryNotFound {
                    path: config.path.clone(),
                }
            } else {
                GitError::CommitFailed {
                    message: format!("failed to open repository: {}", e),
                }
            }
        })?;

        // Check for amend without HEAD
        if config.amend.unwrap_or(false) {
            if repo.head().is_err() {
                return Err(GitError::CommitAmendWithoutHead);
            }
        }

        // Stage files based on config
        let staged_files = self.stage_commit_files(&repo, config)?;

        // Check if there are changes to commit (amend may only reword)
        let allow_empty = config.allow_empty.unwrap_or(false);
        if !config.amend.unwrap_or(false) && !self.has_changes_to_commit(&repo, allow_empty)? {
            return Err(GitError::CommitNothingToCommit {
                path: config.path.clone(),
            });
        }

        // Resolve author and committer identity
        let author = self.resolve_commit_author(&repo, config)?;
        let committer = self.resolve_commit_committer(&repo, config, &author)?;

        // Build final commit message
        let message = self.build_commit_message(&repo, config, &author)?;

        // Create signatures
        let author_sig = self.create_signature(&author.0, &author.1, config)?;
        let committer_sig = self.create_signature(&committer.0, &committer.1, config)?;

        // Create or amend commit
        let commit_oid = if config.amend.unwrap_or(false) {
            self.amend_commit(&repo, &message, &author_sig, &committer_sig)?
        } else {
            self.create_new_commit(&repo, &message, &author_sig, &committer_sig)?
        };

        // Build and return result
        let result = CommitResult {
            backend: "git".to_string(),
            alias: self.alias.clone(),
            path: config.path.clone(),
            action: "commit".to_string(),
            commit: CommitInfo {
                oid: commit_oid.to_string(),
                message: message.clone(),
                author: CommitIdentity {
                    name: author.0,
                    email: author.1,
                },
                committer: CommitIdentity {
                    name: committer.0,
                    email: committer.1,
                },
                amend: config.amend.unwrap_or(false),
                allow_empty,
            },
            stats: CommitStats {
                staged_files,
                insertions: None, // Optional: could be computed from diff
                deletions: None,  // Optional: could be computed from diff
            },
        };

        log::info!(
            "Successfully created commit {} in repository {}",
            commit_oid,
            config.path
        );
        Ok(serde_json::to_value(result).unwrap())
    }

    /// Execute diff operation
    async fn execute_diff(&self, config: &DiffConfig) -> Result<Value, GitError> {
        let path = Path::new(&config.path);

        // Open the repository
        let repo = Repository::open(path).map_err(|e| {
            if e.code() == git2::ErrorCode::NotFound {
                GitError::RepositoryNotFound {
                    path: config.path.clone(),
                }
            } else {
                GitError::DiffFailed {
                    message: format!("failed to open repository: {}", e),
                }
            }
        })?;

        let mode = config.mode.as_ref().unwrap_or(&DiffMode::WorkdirVsIndex);

        // Build diff options
        let mut diff_opts = git2::DiffOptions::new();
        if let Some(unified) = config.unified {
            diff_opts.context_lines(unified as u32);
        } else {
            diff_opts.context_lines(3);
        }

        // Set whitespace flags
        if config.ignore_whitespace.unwrap_or(false) {
            diff_opts.ignore_whitespace(true);
        }
        if config.ignore_whitespace_change.unwrap_or(false) {
            diff_opts.ignore_whitespace_change(true);
        }
        if config.ignore_whitespace_eol.unwrap_or(false) {
            diff_opts.ignore_whitespace_eol(true);
        }

        // Set path filters
        if let Some(ref paths) = config.paths {
            for path in paths {
                diff_opts.pathspec(path.as_str());
            }
        }

        // Create diff based on mode
        let mut diff = match mode {
            DiffMode::WorkdirVsIndex => {
                let index = repo.index().map_err(|e| GitError::DiffFailed {
                    message: format!("failed to get index: {}", e),
                })?;
                repo.diff_index_to_workdir(Some(&index), Some(&mut diff_opts))
                    .map_err(|e| GitError::DiffFailed {
                        message: format!("failed to create workdir vs index diff: {}", e),
                    })?
            }
            DiffMode::IndexVsHead => {
                let head_tree = self.get_head_tree(&repo)?;
                repo.diff_tree_to_index(Some(&head_tree), None, Some(&mut diff_opts))
                    .map_err(|e| GitError::DiffFailed {
                        message: format!("failed to create index vs HEAD diff: {}", e),
                    })?
            }
            DiffMode::HeadVsWorkdir => {
                let head_tree = self.get_head_tree(&repo)?;
                repo.diff_tree_to_workdir_with_index(Some(&head_tree), Some(&mut diff_opts))
                    .map_err(|e| GitError::DiffFailed {
                        message: format!("failed to create HEAD vs workdir diff: {}", e),
                    })?
            }
            DiffMode::CommitVsCommit => {
                let from_tree = self.resolve_commit_tree(&repo, config.from.as_ref().unwrap())?;
                let to_tree = self.resolve_commit_tree(&repo, config.to.as_ref().unwrap())?;
                repo.diff_tree_to_tree(Some(&from_tree), Some(&to_tree), Some(&mut diff_opts))
                    .map_err(|e| GitError::DiffFailed {
                        message: format!("failed to create commit vs commit diff: {}", e),
                    })?
            }
            DiffMode::CommitVsWorkdir => {
                let from_tree = self.resolve_commit_tree(&repo, config.from.as_ref().unwrap())?;
                repo.diff_tree_to_workdir_with_index(Some(&from_tree), Some(&mut diff_opts))
                    .map_err(|e| GitError::DiffFailed {
                        message: format!("failed to create commit vs workdir diff: {}", e),
                    })?
            }
            DiffMode::CommitVsIndex => {
                let from_tree = self.resolve_commit_tree(&repo, config.from.as_ref().unwrap())?;
                repo.diff_tree_to_index(Some(&from_tree), None, Some(&mut diff_opts))
                    .map_err(|e| GitError::DiffFailed {
                        message: format!("failed to create commit vs index diff: {}", e),
                    })?
            }
        };

        // Enable rename detection if requested
        if config.detect_renames.unwrap_or(true) {
            let threshold = config.rename_threshold.unwrap_or(50);
            let mut find_opts = git2::DiffFindOptions::new();
            find_opts.rename_threshold(threshold as u16);
            diff.find_similar(Some(&mut find_opts))
                .map_err(|e| GitError::DiffFailed {
                    message: format!("failed to detect renames: {}", e),
                })?;
        }

        // Parse diff and build result
        let max_files = config.max_files.unwrap_or(1000);
        let max_hunks = config.max_hunks.unwrap_or(10000);
        self.parse_diff_to_json(&diff, config, max_files, max_hunks)
            .await
    }

    /// Execute tag operations (list, create, delete)
    async fn execute_tag(&self, config: &TagConfig) -> Result<Value, GitError> {
        let path = Path::new(&config.path);

        // Open the repository
        let repo = Repository::open(path).map_err(|e| {
            if e.code() == git2::ErrorCode::NotFound {
                GitError::RepositoryNotFound {
                    path: config.path.clone(),
                }
            } else {
                GitError::TagFailed {
                    message: format!("failed to open repository: {}", e),
                }
            }
        })?;

        let action = config.action.as_ref().unwrap_or(&TagAction::List);

        match action {
            TagAction::List => self.list_tags(&repo, config).await,
            TagAction::Create => self.create_tag(&repo, config).await,
            TagAction::Delete => self.delete_tags(&repo, config).await,
        }
    }

    /// List tags operation
    async fn list_tags(&self, repo: &Repository, config: &TagConfig) -> Result<Value, GitError> {
        let pattern = config.pattern.as_ref().map(|p| p.as_str());

        // Get tag names from repository
        let tag_names = repo
            .tag_names(pattern)
            .map_err(|e| GitError::TagListFailed {
                message: format!("failed to list tags: {}", e),
            })?;

        let mut tags = Vec::new();

        // Process each tag
        for i in 0..tag_names.len() {
            if let Ok(Some(name)) = tag_names.get(i) {
                match self.get_tag_info(&repo, name) {
                    Ok(tag_entry) => tags.push(tag_entry),
                    Err(e) => {
                        log::warn!("Failed to get info for tag '{}': {}", name, e);
                        continue;
                    }
                }
            }
        }

        // Sort tags
        let sort = config.sort.as_ref().unwrap_or(&TagSort::Name);
        self.sort_tags(&mut tags, sort);

        let result = TagListResult {
            backend: "git".to_string(),
            alias: self.alias.clone(),
            path: config.path.clone(),
            action: "list".to_string(),
            pattern: config.pattern.clone(),
            sort: format!("{:?}", sort).to_lowercase(),
            count: tags.len(),
            tags,
        };

        Ok(serde_json::to_value(result).unwrap())
    }

    /// Create tag operation
    async fn create_tag(&self, repo: &Repository, config: &TagConfig) -> Result<Value, GitError> {
        let name = config.name.as_ref().unwrap(); // Already validated
        let default_target = "HEAD".to_string();
        let target_str = config.target.as_ref().unwrap_or(&default_target);
        let force = config.force.unwrap_or(false);
        let annotated = config.annotated.unwrap_or(false);

        // Resolve target object
        let target = repo
            .revparse_single(target_str)
            .map_err(|_| GitError::TagTargetNotFound {
                target: target_str.clone(),
            })?;

        // Check if tag already exists
        if !force {
            if repo.find_reference(&format!("refs/tags/{}", name)).is_ok() {
                return Err(GitError::TagAlreadyExists { name: name.clone() });
            }
        }

        let _tag_oid = if annotated {
            // Create annotated tag
            let message = config.message.as_ref().unwrap(); // Already validated
            let tagger = self.resolve_tag_identity(config, repo)?;

            repo.tag(name, &target, &tagger, message, force)
                .map_err(|e| GitError::TagCreateFailed {
                    message: format!("failed to create annotated tag: {}", e),
                })?
        } else {
            // Create lightweight tag
            repo.tag_lightweight(name, &target, force)
                .map_err(|e| GitError::TagCreateFailed {
                    message: format!("failed to create lightweight tag: {}", e),
                })?
        };

        // Get the created tag info
        let tag_entry = self.get_tag_info(&repo, name)?;

        let status = if force && repo.find_reference(&format!("refs/tags/{}", name)).is_ok() {
            "overwritten"
        } else {
            "created"
        };

        let result = TagCreateResult {
            backend: "git".to_string(),
            alias: self.alias.clone(),
            path: config.path.clone(),
            action: "create".to_string(),
            tag: tag_entry,
            status: status.to_string(),
            force,
        };

        Ok(serde_json::to_value(result).unwrap())
    }

    /// Delete tags operation
    async fn delete_tags(&self, repo: &Repository, config: &TagConfig) -> Result<Value, GitError> {
        let force = config.force.unwrap_or(false);

        // Determine which tags to delete
        let names_to_delete = if let Some(names) = &config.names {
            names.clone()
        } else if let Some(name) = &config.name {
            vec![name.clone()]
        } else {
            return Err(GitError::InvalidTagConfig {
                message: "either name or names must be provided for delete".to_string(),
            });
        };

        let mut deleted = Vec::new();
        let mut missing = Vec::new();

        for name in &names_to_delete {
            let refname = format!("refs/tags/{}", name);
            match repo.find_reference(&refname) {
                Ok(mut tag_ref) => match tag_ref.delete() {
                    Ok(_) => deleted.push(name.clone()),
                    Err(e) => {
                        return Err(GitError::TagDeleteFailed {
                            message: format!("failed to delete tag '{}': {}", name, e),
                        });
                    }
                },
                Err(_) => {
                    if force {
                        missing.push(name.clone());
                    } else {
                        return Err(GitError::TagNotFound { name: name.clone() });
                    }
                }
            }
        }

        let result = TagDeleteResult {
            backend: "git".to_string(),
            alias: self.alias.clone(),
            path: config.path.clone(),
            action: "delete".to_string(),
            requested: names_to_delete,
            deleted,
            missing,
            force,
        };

        Ok(serde_json::to_value(result).unwrap())
    }

    /// Get detailed information about a specific tag
    fn get_tag_info(&self, repo: &Repository, name: &str) -> Result<TagEntry, GitError> {
        let refname = format!("refs/tags/{}", name);

        // First try to find it as an annotated tag by finding the tag object
        if let Ok(oid) = repo.refname_to_id(&refname) {
            if let Ok(obj) = repo.find_object(oid, None) {
                match obj.kind().unwrap() {
                    git2::ObjectType::Tag => {
                        // This is an annotated tag
                        let tag = obj.as_tag().unwrap();
                        let target_obj = tag.target().map_err(|e| GitError::TagFailed {
                            message: format!("failed to get tag target: {}", e),
                        })?;

                        let tagger = if let Some(sig) = tag.tagger() {
                            Some(TagTagger {
                                name: sig.name().unwrap_or("").to_string(),
                                email: sig.email().unwrap_or("").to_string(),
                                timestamp: self.format_time(&sig.when()),
                            })
                        } else {
                            None
                        };

                        return Ok(TagEntry {
                            name: name.to_string(),
                            annotated: true,
                            message: Some(tag.message().ok().flatten().unwrap_or("").to_string()),
                            target: TagTarget {
                                oid: target_obj.id().to_string(),
                                object_type: match target_obj.kind().unwrap() {
                                    git2::ObjectType::Commit => "commit".to_string(),
                                    git2::ObjectType::Tag => "tag".to_string(),
                                    git2::ObjectType::Tree => "tree".to_string(),
                                    git2::ObjectType::Blob => "blob".to_string(),
                                    _ => "unknown".to_string(),
                                },
                            },
                            tagger,
                        });
                    }
                    _ => {
                        // This is a lightweight tag pointing directly to an object
                        return Ok(TagEntry {
                            name: name.to_string(),
                            annotated: false,
                            message: None,
                            target: TagTarget {
                                oid: obj.id().to_string(),
                                object_type: match obj.kind().unwrap() {
                                    git2::ObjectType::Commit => "commit".to_string(),
                                    git2::ObjectType::Tag => "tag".to_string(),
                                    git2::ObjectType::Tree => "tree".to_string(),
                                    git2::ObjectType::Blob => "blob".to_string(),
                                    _ => "unknown".to_string(),
                                },
                            },
                            tagger: None,
                        });
                    }
                }
            }
        }

        Err(GitError::TagNotFound {
            name: name.to_string(),
        })
    }

    /// Sort tags according to the specified sort method
    fn sort_tags(&self, tags: &mut Vec<TagEntry>, sort: &TagSort) {
        match sort {
            TagSort::Name => {
                tags.sort_by(|a, b| a.name.cmp(&b.name));
            }
            TagSort::Version => {
                tags.sort_by(|a, b| self.compare_versions(&a.name, &b.name));
            }
            TagSort::TaggerDate => {
                tags.sort_by(|a, b| {
                    let a_time = a.tagger.as_ref().map(|t| &t.timestamp);
                    let b_time = b.tagger.as_ref().map(|t| &t.timestamp);
                    a_time.cmp(&b_time)
                });
            }
            TagSort::CommitterDate => {
                // For commit dates, we would need to resolve the target commits
                // For now, fall back to name sorting
                tags.sort_by(|a, b| a.name.cmp(&b.name));
            }
        }
    }

    /// Compare version strings for semantic version sorting
    fn compare_versions(&self, a: &str, b: &str) -> std::cmp::Ordering {
        // Extract numeric parts from version strings
        let extract_version_parts = |s: &str| -> Vec<u32> {
            // Remove common prefixes like 'v' and extract numbers
            let clean = s.strip_prefix('v').unwrap_or(s);
            clean
                .split('.')
                .filter_map(|part| part.parse::<u32>().ok())
                .collect()
        };

        let a_parts = extract_version_parts(a);
        let b_parts = extract_version_parts(b);

        // Compare version parts
        let max_len = a_parts.len().max(b_parts.len());
        for i in 0..max_len {
            let a_part = a_parts.get(i).unwrap_or(&0);
            let b_part = b_parts.get(i).unwrap_or(&0);

            match a_part.cmp(b_part) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
            }
        }

        // If all numeric parts are equal, fall back to string comparison
        a.cmp(b)
    }

    /// Resolve tag identity (author/tagger) from config, profile, and repo config
    fn resolve_tag_identity(
        &self,
        config: &TagConfig,
        repo: &Repository,
    ) -> Result<Signature<'_>, GitError> {
        let name = if let Some(name) = &config.author_name {
            name.clone()
        } else {
            // Try to get from git config
            self.get_repo_config_string(repo, "user.name")
                .or_else(|| self.get_global_config_string("user.name"))
                .ok_or_else(|| GitError::TagIdentityMissing)?
        };

        let email = if let Some(email) = &config.author_email {
            email.clone()
        } else {
            // Try to get from git config
            self.get_repo_config_string(repo, "user.email")
                .or_else(|| self.get_global_config_string("user.email"))
                .ok_or_else(|| GitError::TagIdentityMissing)?
        };

        let time = if let Some(timestamp) = &config.timestamp {
            match timestamp {
                TagTimestamp::Iso8601(iso_str) => {
                    // Parse ISO8601 timestamp
                    chrono::DateTime::parse_from_rfc3339(iso_str)
                        .map(|dt| Time::new(dt.timestamp(), dt.offset().local_minus_utc() / 60))
                        .map_err(|_| GitError::InvalidTagConfig {
                            message: format!("invalid ISO8601 timestamp: {}", iso_str),
                        })?
                }
                TagTimestamp::UnixSeconds(unix_secs) => Time::new(*unix_secs as i64, 0),
            }
        } else {
            // Use current time
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            Time::new(now, 0)
        };

        Signature::new(&name, &email, &time).map_err(|_| GitError::TagIdentityMissing)
    }

    /// Format git time to ISO8601 string
    fn format_time(&self, time: &Time) -> String {
        let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(time.seconds(), 0)
            .unwrap_or_else(|| chrono::Utc::now());
        dt.to_rfc3339()
    }

    /// Get string value from repository config
    fn get_repo_config_string(&self, repo: &Repository, key: &str) -> Option<String> {
        repo.config()
            .ok()
            .and_then(|config| config.get_string(key).ok())
    }

    /// Get string value from global git config
    fn get_global_config_string(&self, key: &str) -> Option<String> {
        git2::Config::open_default()
            .ok()
            .and_then(|config| config.get_string(key).ok())
    }

    /// Get HEAD tree for diff operations
    fn get_head_tree<'a>(&self, repo: &'a Repository) -> Result<git2::Tree<'a>, GitError> {
        let head = repo.head().map_err(|_| GitError::DiffHeadNotFound)?;
        let commit = head
            .peel_to_commit()
            .map_err(|_| GitError::DiffHeadNotFound)?;
        commit.tree().map_err(|e| GitError::DiffFailed {
            message: format!("failed to get HEAD tree: {}", e),
        })
    }

    /// Resolve commit-ish string to tree
    fn resolve_commit_tree<'a>(
        &self,
        repo: &'a Repository,
        commit_ish: &str,
    ) -> Result<git2::Tree<'a>, GitError> {
        let object = repo
            .revparse_single(commit_ish)
            .map_err(|_| GitError::DiffRefNotFound {
                reference: commit_ish.to_string(),
            })?;

        let commit = object
            .peel_to_commit()
            .map_err(|_| GitError::DiffRefNotFound {
                reference: commit_ish.to_string(),
            })?;

        commit.tree().map_err(|e| GitError::DiffFailed {
            message: format!("failed to get tree for {}: {}", commit_ish, e),
        })
    }

    /// Parse libgit2 diff to JSON structure
    async fn parse_diff_to_json(
        &self,
        diff: &git2::Diff<'_>,
        config: &DiffConfig,
        max_files: u32,
        max_hunks: u32,
    ) -> Result<Value, GitError> {
        let mut files = Vec::new();
        let mut total_insertions = 0u32;
        let mut total_deletions = 0u32;
        let mut file_count = 0u32;
        let mut hunk_count = 0u32;
        let mut truncated = false;

        // Process each file in the diff
        let _num_deltas = diff.deltas().count();
        for (delta_idx, delta) in diff.deltas().enumerate() {
            if file_count >= max_files {
                truncated = true;
                break;
            }

            let old_path = delta
                .old_file()
                .path()
                .map(|p: &std::path::Path| p.to_string_lossy().to_string());
            let new_path = delta
                .new_file()
                .path()
                .map(|p: &std::path::Path| p.to_string_lossy().to_string());

            let status = match delta.status() {
                git2::Delta::Added => "added",
                git2::Delta::Deleted => "deleted",
                git2::Delta::Modified => "modified",
                git2::Delta::Renamed => "renamed",
                git2::Delta::Copied => "copied",
                git2::Delta::Typechange => "typechange",
                _ => "modified", // Default fallback
            };

            let is_binary = delta.old_file().is_binary() || delta.new_file().is_binary();

            let mut hunks = Vec::new();
            let mut actual_is_binary = is_binary;

            // Process hunks for non-binary files or if binary is enabled
            if !is_binary || config.binary.unwrap_or(false) {
                let patch =
                    git2::Patch::from_diff(diff, delta_idx).map_err(|e| GitError::DiffFailed {
                        message: format!("failed to create patch: {}", e),
                    })?;

                if let Some(patch) = patch {
                    // Check if the patch itself indicates binary content
                    if patch.num_hunks() == 0 && !is_binary {
                        // This might be a binary file that git2 didn't detect as binary
                        // Try to read the file content to check for null bytes
                        if let Some(new_file_path) = new_path.as_ref() {
                            if let Ok(content) =
                                std::fs::read(Path::new(&config.path).join(new_file_path))
                            {
                                actual_is_binary = content.contains(&0);
                            }
                        } else if let Some(old_file_path) = old_path.as_ref() {
                            if let Ok(content) =
                                std::fs::read(Path::new(&config.path).join(old_file_path))
                            {
                                actual_is_binary = content.contains(&0);
                            }
                        }
                    }

                    if !actual_is_binary {
                        for hunk_idx in 0..patch.num_hunks() {
                            if hunk_count >= max_hunks {
                                truncated = true;
                                break;
                            }

                            let (hunk, _) =
                                patch.hunk(hunk_idx).map_err(|e| GitError::DiffFailed {
                                    message: format!("failed to get hunk: {}", e),
                                })?;

                            let mut lines = Vec::new();
                            let num_lines = patch.num_lines_in_hunk(hunk_idx).map_err(|e| {
                                GitError::DiffFailed {
                                    message: format!("failed to get hunk line count: {}", e),
                                }
                            })?;

                            for line_idx in 0..num_lines {
                                let line = patch.line_in_hunk(hunk_idx, line_idx).map_err(|e| {
                                    GitError::DiffFailed {
                                        message: format!("failed to get line: {}", e),
                                    }
                                })?;

                                let line_type = match line.origin() {
                                    '+' => "add",
                                    '-' => "delete",
                                    ' ' => "context",
                                    _ => "context", // Default fallback
                                };

                                // Remove trailing newline from content
                                let content = String::from_utf8_lossy(line.content());
                                let content = content.trim_end_matches('\n').to_string();

                                lines.push(DiffLine {
                                    line_type: line_type.to_string(),
                                    content,
                                });

                                // Count insertions/deletions
                                match line.origin() {
                                    '+' => total_insertions += 1,
                                    '-' => total_deletions += 1,
                                    _ => {}
                                }
                            }

                            hunks.push(DiffHunk {
                                old_start: hunk.old_start(),
                                old_lines: hunk.old_lines(),
                                new_start: hunk.new_start(),
                                new_lines: hunk.new_lines(),
                                lines,
                            });

                            hunk_count += 1;
                        }
                    }
                }
            }

            files.push(DiffFile {
                old_path,
                new_path,
                status: status.to_string(),
                is_binary: actual_is_binary,
                hunks,
            });

            file_count += 1;
        }

        // Determine from/to strings for result
        let mode = config.mode.as_ref().unwrap_or(&DiffMode::WorkdirVsIndex);
        let (from_str, to_str) = match mode {
            DiffMode::WorkdirVsIndex => ("INDEX".to_string(), "WORKDIR".to_string()),
            DiffMode::IndexVsHead => ("HEAD".to_string(), "INDEX".to_string()),
            DiffMode::HeadVsWorkdir => ("HEAD".to_string(), "WORKDIR".to_string()),
            DiffMode::CommitVsCommit => (
                config.from.clone().unwrap_or_default(),
                config.to.clone().unwrap_or_default(),
            ),
            DiffMode::CommitVsWorkdir => (
                config.from.clone().unwrap_or_default(),
                "WORKDIR".to_string(),
            ),
            DiffMode::CommitVsIndex => {
                (config.from.clone().unwrap_or_default(), "INDEX".to_string())
            }
        };

        let mode_string = match mode {
            DiffMode::WorkdirVsIndex => "workdir_vs_index",
            DiffMode::IndexVsHead => "index_vs_head",
            DiffMode::HeadVsWorkdir => "head_vs_workdir",
            DiffMode::CommitVsCommit => "commit_vs_commit",
            DiffMode::CommitVsWorkdir => "commit_vs_workdir",
            DiffMode::CommitVsIndex => "commit_vs_index",
        };

        let result = DiffResult {
            backend: "git".to_string(),
            alias: self.alias.clone(),
            path: config.path.clone(),
            mode: mode_string.to_string(),
            from: from_str,
            to: to_str,
            summary: DiffSummary {
                files_changed: file_count,
                insertions: total_insertions,
                deletions: total_deletions,
                truncated,
            },
            files,
        };

        Ok(serde_json::to_value(result).unwrap())
    }

    /// Create a new commit
    fn create_new_commit(
        &self,
        repo: &Repository,
        message: &str,
        author: &Signature,
        committer: &Signature,
    ) -> Result<Oid, GitError> {
        let mut index = repo.index().map_err(|e| GitError::CommitFailed {
            message: format!("failed to get index: {}", e),
        })?;

        let tree_oid = index.write_tree().map_err(|e| GitError::CommitFailed {
            message: format!("failed to write tree: {}", e),
        })?;

        let tree = repo
            .find_tree(tree_oid)
            .map_err(|e| GitError::CommitFailed {
                message: format!("failed to find tree: {}", e),
            })?;

        // Determine parents
        let parents: Vec<Commit> = match repo.head() {
            Ok(head_ref) => {
                vec![
                    head_ref
                        .peel_to_commit()
                        .map_err(|e| GitError::CommitFailed {
                            message: format!("failed to get HEAD commit: {}", e),
                        })?,
                ]
            }
            Err(_) => vec![], // No parents for initial commit
        };

        let parent_refs: Vec<&Commit> = parents.iter().collect();

        // Create commit
        let commit_oid = repo
            .commit(
                Some("HEAD"),
                author,
                committer,
                message,
                &tree,
                &parent_refs,
            )
            .map_err(|e| GitError::CommitFailed {
                message: format!("failed to create commit: {}", e),
            })?;

        Ok(commit_oid)
    }

    /// Amend the existing HEAD commit
    fn amend_commit(
        &self,
        repo: &Repository,
        message: &str,
        author: &Signature,
        committer: &Signature,
    ) -> Result<Oid, GitError> {
        let mut index = repo.index().map_err(|e| GitError::CommitAmendFailed {
            message: format!("failed to get index: {}", e),
        })?;

        let tree_oid = index
            .write_tree()
            .map_err(|e| GitError::CommitAmendFailed {
                message: format!("failed to write tree: {}", e),
            })?;

        let tree = repo
            .find_tree(tree_oid)
            .map_err(|e| GitError::CommitAmendFailed {
                message: format!("failed to find tree: {}", e),
            })?;

        // Get current HEAD commit
        let head_commit = repo
            .head()
            .and_then(|head_ref| head_ref.peel_to_commit())
            .map_err(|e| GitError::CommitAmendFailed {
                message: format!("failed to get HEAD commit: {}", e),
            })?;

        // Replace HEAD's commit: same parents, new tree, message and
        // identities; HEAD's branch moves to the new commit.
        let commit_oid = head_commit
            .amend(
                Some("HEAD"),
                Some(author),
                Some(committer),
                None,
                Some(message),
                Some(&tree),
            )
            .map_err(|e| GitError::CommitAmendFailed {
                message: format!("failed to amend commit: {}", e),
            })?;

        Ok(commit_oid)
    }

    /// Resolve which branches to push based on configuration
    fn resolve_push_branches(
        &self,
        repo: &Repository,
        config: &PushConfig,
    ) -> Result<Vec<String>, GitError> {
        if let Some(ref branches) = config.branches {
            // Use provided branches list
            for branch_name in branches {
                // Verify branch exists
                let branch_ref_name = format!("refs/heads/{}", branch_name);
                repo.find_reference(&branch_ref_name).map_err(|_| {
                    GitError::PushLocalBranchNotFound {
                        branch: branch_name.clone(),
                    }
                })?;
            }
            Ok(branches.clone())
        } else if let Some(ref branch) = config.branch {
            // Use single branch
            let branch_ref_name = format!("refs/heads/{}", branch);
            repo.find_reference(&branch_ref_name).map_err(|_| {
                GitError::PushLocalBranchNotFound {
                    branch: branch.clone(),
                }
            })?;
            Ok(vec![branch.clone()])
        } else {
            // Use current branch
            let head = repo.head().map_err(|e| GitError::PushFailed {
                message: format!("failed to get HEAD: {}", e),
            })?;

            if !head.is_branch() {
                return Err(GitError::PushDetachedHead);
            }

            let branch_name = head.shorthand().unwrap_or("main").to_string();
            Ok(vec![branch_name])
        }
    }

    /// List branches operation
    async fn list_branches(
        &self,
        repo: &Repository,
        config: &BranchConfig,
    ) -> Result<Value, GitError> {
        use git2::BranchType;

        let remote_only = config.remote_only.unwrap_or(false);
        // local_only=false alone means "not only local": list everything.
        let all = config.all.unwrap_or(false) || (config.local_only == Some(false) && !remote_only);

        let mut branches = Vec::new();

        // Determine which branch types to list
        let branch_types = if all {
            vec![BranchType::Local, BranchType::Remote]
        } else if remote_only {
            vec![BranchType::Remote]
        } else {
            vec![BranchType::Local] // local_only is default
        };

        // Get current branch for comparison
        let current_branch_name = match repo.head() {
            Ok(head) if head.is_branch() => head.shorthand().ok().map(|s| s.to_string()),
            _ => None,
        };

        for branch_type in branch_types {
            let branch_iter =
                repo.branches(Some(branch_type))
                    .map_err(|e| GitError::BranchFailed {
                        message: format!("failed to list branches: {}", e),
                    })?;

            for branch_result in branch_iter {
                let (branch, _branch_type) = branch_result.map_err(|e| GitError::BranchFailed {
                    message: format!("failed to iterate branches: {}", e),
                })?;

                let branch_info = self.extract_branch_info(&branch, &current_branch_name)?;
                branches.push(branch_info);
            }
        }

        let result = BranchListResult {
            backend: "git".to_string(),
            alias: self.alias.clone(),
            path: config.path.clone(),
            action: "list".to_string(),
            branches,
        };

        log::info!("Successfully listed {} branches", result.branches.len());
        Ok(serde_json::to_value(result).unwrap())
    }

    /// Create branch operation
    async fn create_branch(
        &self,
        repo: &Repository,
        config: &BranchConfig,
    ) -> Result<Value, GitError> {
        let name = config.name.as_deref().unwrap_or_default();
        let start_point = config.start_point.as_deref().unwrap_or("HEAD");
        let force = config.force.unwrap_or(false);

        // force=true replaces an existing branch, except the checked-out one.
        if let Ok(existing) = repo.find_branch(name, git2::BranchType::Local) {
            if !force {
                return Err(GitError::BranchAlreadyExists {
                    name: name.to_string(),
                });
            }
            if existing.is_head() {
                return Err(GitError::BranchFailed {
                    message: format!("cannot replace '{name}': it is the checked-out branch"),
                });
            }
        }

        // Resolve start point to a commit
        let target_commit = self.resolve_start_point(repo, start_point)?;

        // With track=true the upstream must exist before anything changes.
        let remote_name = config.remote.as_deref().unwrap_or("origin");
        if config.track.unwrap_or(false) {
            let upstream = format!("refs/remotes/{}/{}", remote_name, name);
            if repo.find_reference(&upstream).is_err() {
                return Err(GitError::BranchSetUpstreamFailed {
                    message: format!(
                        "remote-tracking branch '{remote_name}/{name}' does not exist (fetch it first)"
                    ),
                });
            }
        }

        let mut branch =
            repo.branch(name, &target_commit, force)
                .map_err(|e| GitError::BranchFailed {
                    message: format!("failed to create branch '{}': {}", name, e.message()),
                })?;

        let tracked_remote = if config.track.unwrap_or(false) {
            match self.set_branch_upstream(&mut branch, remote_name, name) {
                Ok(upstream) => Some(upstream),
                Err(e) => {
                    // Leave nothing half-done.
                    let _ = branch.delete();
                    return Err(e);
                }
            }
        } else {
            None
        };

        let branch_data = json!({
            "name": name,
            "start_point": start_point,
            "tracked_remote": tracked_remote
        });

        let result = BranchOpResult {
            backend: "git".to_string(),
            alias: self.alias.clone(),
            path: config.path.clone(),
            action: "create".to_string(),
            status: "created".to_string(),
            branch: branch_data,
        };

        log::info!("Successfully created branch '{}'", name);
        Ok(serde_json::to_value(result).unwrap())
    }

    /// Delete branch operation
    async fn delete_branch(
        &self,
        repo: &Repository,
        config: &BranchConfig,
    ) -> Result<Value, GitError> {
        let name = config.name.as_ref().unwrap();

        // Find the branch
        let mut branch = repo
            .find_branch(name, git2::BranchType::Local)
            .map_err(|_| GitError::BranchNotFound { name: name.clone() })?;

        // The checked-out branch is never deleted, even with force=true.
        if branch.is_head() {
            return Err(GitError::BranchDeleteCurrent { name: name.clone() });
        }

        // Without force, the branch must be merged: into its upstream when
        // it has one, otherwise into HEAD (as `git branch -d` does).
        if !config.force.unwrap_or(false) {
            if let Some(tip) = branch.get().target() {
                let base = branch
                    .upstream()
                    .ok()
                    .and_then(|u| u.get().target())
                    .or_else(|| repo.head().ok().and_then(|h| h.target()));
                let merged = match base {
                    Some(base) => {
                        base == tip
                            || repo.graph_descendant_of(base, tip).map_err(|e| {
                                GitError::BranchDeleteFailed {
                                    message: format!(
                                        "cannot check whether '{name}' is merged: {e}"
                                    ),
                                }
                            })?
                    }
                    None => false,
                };
                if !merged {
                    return Err(GitError::BranchDeleteUnmerged { name: name.clone() });
                }
            }
        }

        // Delete the branch
        branch.delete().map_err(|e| GitError::BranchDeleteFailed {
            message: format!("failed to delete branch '{}': {}", name, e),
        })?;

        let branch_data = json!({
            "name": name
        });

        let result = BranchOpResult {
            backend: "git".to_string(),
            alias: self.alias.clone(),
            path: config.path.clone(),
            action: "delete".to_string(),
            status: "deleted".to_string(),
            branch: branch_data,
        };

        log::info!("Successfully deleted branch '{}'", name);
        Ok(serde_json::to_value(result).unwrap())
    }

    /// Rename branch operation
    async fn rename_branch(
        &self,
        repo: &Repository,
        config: &BranchConfig,
    ) -> Result<Value, GitError> {
        let old_name = config.name.as_ref().unwrap();
        let new_name = config.new_name.as_ref().unwrap();

        // Find the old branch
        let mut branch = repo
            .find_branch(old_name, git2::BranchType::Local)
            .map_err(|_| GitError::BranchNotFound {
                name: old_name.clone(),
            })?;

        // Check if target name already exists
        if !config.force.unwrap_or(false)
            && repo.find_branch(new_name, git2::BranchType::Local).is_ok()
        {
            return Err(GitError::BranchAlreadyExists {
                name: new_name.clone(),
            });
        }

        // Rename the branch
        branch
            .rename(new_name, config.force.unwrap_or(false))
            .map_err(|e| GitError::BranchRenameFailed {
                message: format!(
                    "failed to rename branch '{}' to '{}': {}",
                    old_name, new_name, e
                ),
            })?;

        let branch_data = json!({
            "old_name": old_name,
            "new_name": new_name
        });

        let result = BranchOpResult {
            backend: "git".to_string(),
            alias: self.alias.clone(),
            path: config.path.clone(),
            action: "rename".to_string(),
            status: "renamed".to_string(),
            branch: branch_data,
        };

        log::info!(
            "Successfully renamed branch '{}' to '{}'",
            old_name,
            new_name
        );
        Ok(serde_json::to_value(result).unwrap())
    }

    /// Checkout branch operation
    async fn checkout_branch(
        &self,
        repo: &Repository,
        config: &BranchConfig,
    ) -> Result<Value, GitError> {
        let name = config.name.as_ref().unwrap();

        // Find the branch
        let branch = repo
            .find_branch(name, git2::BranchType::Local)
            .map_err(|_| GitError::BranchNotFound { name: name.clone() })?;

        // Check if already current
        let was_current = branch.is_head();

        if !was_current {
            // Update the working tree first: a safe checkout refuses to
            // overwrite local changes (force=true discards them), and HEAD
            // only moves once the tree is in place.
            let target =
                branch
                    .get()
                    .peel_to_commit()
                    .map_err(|e| GitError::BranchCheckoutFailed {
                        message: format!("cannot read the tip of '{}': {}", name, e.message()),
                    })?;
            let mut checkout_opts = git2::build::CheckoutBuilder::new();
            if config.force.unwrap_or(false) {
                checkout_opts.force();
            } else {
                checkout_opts.safe();
            }
            repo.checkout_tree(target.as_object(), Some(&mut checkout_opts))
                .map_err(|e| {
                    if e.code() == git2::ErrorCode::Conflict {
                        GitError::BranchCheckoutConflict
                    } else {
                        GitError::BranchCheckoutFailed {
                            message: format!(
                                "failed to check out the working tree: {}",
                                e.message()
                            ),
                        }
                    }
                })?;
            let ref_name = format!("refs/heads/{}", name);
            repo.set_head(&ref_name)
                .map_err(|e| GitError::BranchCheckoutFailed {
                    message: format!("failed to set HEAD: {}", e.message()),
                })?;
        }

        let branch_data = json!({
            "name": name,
            "was_current": was_current
        });

        let result = BranchOpResult {
            backend: "git".to_string(),
            alias: self.alias.clone(),
            path: config.path.clone(),
            action: "checkout".to_string(),
            status: "checked_out".to_string(),
            branch: branch_data,
        };

        log::info!("Successfully checked out branch '{}'", name);
        Ok(serde_json::to_value(result).unwrap())
    }

    /// Extract branch information for list operation
    fn extract_branch_info(
        &self,
        branch: &git2::Branch,
        current_branch_name: &Option<String>,
    ) -> Result<BranchListEntry, GitError> {
        let branch_ref = branch.get();
        let name = branch
            .name()
            .map_err(|e| GitError::BranchFailed {
                message: format!("failed to get branch name: {}", e),
            })?
            .unwrap_or("")
            .to_string();

        let full_ref = branch_ref.name().unwrap_or("").to_string();
        let is_remote = branch_ref.is_remote();
        let is_current = if let Some(current) = current_branch_name {
            &name == current
        } else {
            false
        };

        // Get commit SHA
        let head = branch_ref
            .target()
            .map(|oid| oid.to_string())
            .unwrap_or_else(|| "".to_string());

        // Get upstream information for local branches
        let upstream = if !is_remote {
            match branch.upstream() {
                Ok(upstream_branch) => {
                    let upstream_ref = upstream_branch.get();
                    let upstream_name = upstream_branch
                        .name()
                        .unwrap_or(None)
                        .unwrap_or("")
                        .to_string();
                    let upstream_full_ref = upstream_ref.name().unwrap_or("").to_string();

                    // Extract remote name from upstream reference
                    let remote_name = if upstream_full_ref.starts_with("refs/remotes/") {
                        upstream_full_ref
                            .strip_prefix("refs/remotes/")
                            .and_then(|s| s.split('/').next())
                            .unwrap_or("origin")
                            .to_string()
                    } else {
                        "origin".to_string()
                    };

                    Some(BranchUpstreamInfo {
                        remote: remote_name,
                        name: upstream_name,
                        full_ref: upstream_full_ref,
                    })
                }
                Err(_) => None,
            }
        } else {
            None
        };

        Ok(BranchListEntry {
            name,
            full_ref,
            is_remote,
            is_current,
            upstream,
            head,
        })
    }

    /// Resolve start point to a commit
    fn resolve_start_point<'a>(
        &self,
        repo: &'a Repository,
        start_point: &str,
    ) -> Result<git2::Commit<'a>, GitError> {
        // Try to resolve as reference, tag, or commit SHA
        let obj =
            repo.revparse_single(start_point)
                .map_err(|_| GitError::BranchStartpointNotFound {
                    start_point: start_point.to_string(),
                })?;

        // Convert to commit
        let commit = obj
            .peel_to_commit()
            .map_err(|_| GitError::BranchStartpointNotFound {
                start_point: start_point.to_string(),
            })?;

        Ok(commit)
    }

    /// Set upstream tracking for a branch
    fn set_branch_upstream(
        &self,
        branch: &mut git2::Branch,
        remote_name: &str,
        branch_name: &str,
    ) -> Result<String, GitError> {
        let upstream_ref = format!("refs/remotes/{}/{}", remote_name, branch_name);

        // Set upstream reference
        branch.set_upstream(Some(&upstream_ref)).map_err(|e| {
            GitError::BranchSetUpstreamFailed {
                message: format!("failed to set upstream '{}': {}", upstream_ref, e),
            }
        })?;

        Ok(format!("{}/{}", remote_name, branch_name))
    }

    /// Compute ahead/behind counts for a local branch against its remote tracking branch
    fn compute_ahead_behind(
        &self,
        repo: &Repository,
        branch_name: &str,
        remote_name: &str,
    ) -> Result<(usize, usize), GitError> {
        let local_ref_name = format!("refs/heads/{}", branch_name);
        let remote_ref_name = format!("refs/remotes/{}/{}", remote_name, branch_name);

        let local_ref = repo.find_reference(&local_ref_name).map_err(|_| {
            GitError::PushLocalBranchNotFound {
                branch: branch_name.to_string(),
            }
        })?;

        let local_oid = local_ref.target().ok_or_else(|| GitError::PushFailed {
            message: "local reference has no target".to_string(),
        })?;

        // Try to find remote tracking branch
        let remote_oid = match repo.find_reference(&remote_ref_name) {
            Ok(remote_ref) => remote_ref.target().ok_or_else(|| GitError::PushFailed {
                message: "remote reference has no target".to_string(),
            })?,
            Err(_) => {
                // Remote tracking branch doesn't exist - this is ok for first push
                // Return 1 ahead (local has commits), 0 behind
                return Ok((1, 0));
            }
        };

        // Compute ahead/behind counts
        let (ahead, behind) = repo
            .graph_ahead_behind(local_oid, remote_oid)
            .map_err(|e| GitError::PushFailed {
                message: format!("failed to compute ahead/behind: {}", e),
            })?;

        Ok((ahead, behind))
    }

    /// Sets `<remote>/<branch>` as the upstream of each pushed branch.
    fn set_upstream_branches(
        &self,
        repo: &Repository,
        branches: &[String],
        remote_name: &str,
    ) -> Result<(), GitError> {
        for branch_name in branches {
            let upstream = format!("{}/{}", remote_name, branch_name);
            let mut branch = repo
                .find_branch(branch_name, BranchType::Local)
                .and_then(|mut b| b.set_upstream(Some(&upstream)).map(|()| b))
                .map_err(|e| GitError::PushFailed {
                    message: format!(
                        "the push succeeded, but setting the upstream of '{}' to '{}' failed: {}",
                        branch_name,
                        upstream,
                        e.message()
                    ),
                })?;
            let _ = &mut branch;
        }
        Ok(())
    }

    /// Get branch information for status operation
    fn get_branch_info(
        &self,
        repo: &Repository,
        include_remote: bool,
    ) -> Result<BranchInfo, GitError> {
        let head = repo.head().map_err(|e| GitError::StatusFailed {
            message: format!("failed to get HEAD: {}", e),
        })?;

        let (name, detached) = if head.is_branch() {
            let name = head.shorthand().ok().map(|s| s.to_string());
            (name, false)
        } else {
            (None, true)
        };

        let head_oid = head.target().ok_or_else(|| GitError::StatusFailed {
            message: "HEAD has no target".to_string(),
        })?;

        let upstream = if include_remote && !detached {
            if let Some(branch_name) = &name {
                self.get_upstream_info(repo, branch_name)?
            } else {
                None
            }
        } else {
            None
        };

        Ok(BranchInfo {
            name,
            detached,
            head: head_oid.to_string(),
            upstream,
        })
    }

    /// Get upstream information for a branch
    fn get_upstream_info(
        &self,
        repo: &Repository,
        branch_name: &str,
    ) -> Result<Option<UpstreamInfo>, GitError> {
        let local_branch = match repo.find_branch(branch_name, git2::BranchType::Local) {
            Ok(branch) => branch,
            Err(_) => return Ok(None),
        };

        let upstream_branch = match local_branch.upstream() {
            Ok(branch) => branch,
            Err(_) => return Ok(None),
        };

        let upstream_name = upstream_branch
            .name()
            .map_err(|e| GitError::StatusFailed {
                message: format!("failed to get upstream branch name: {}", e),
            })?
            .unwrap_or("unknown");

        // Extract remote name from upstream reference
        let remote_name = if let Ok(upstream_ref) = upstream_branch.get().name() {
            if upstream_ref.starts_with("refs/remotes/") {
                let parts: Vec<&str> = upstream_ref["refs/remotes/".len()..]
                    .splitn(2, '/')
                    .collect();
                if parts.len() == 2 {
                    parts[0].to_string()
                } else {
                    "origin".to_string()
                }
            } else {
                "origin".to_string()
            }
        } else {
            "origin".to_string()
        };

        // Calculate ahead/behind counts
        let (ahead_by, behind_by) = if let (Ok(local_oid), Ok(upstream_oid)) = (
            local_branch.get().target().ok_or("no local target"),
            upstream_branch.get().target().ok_or("no upstream target"),
        ) {
            repo.graph_ahead_behind(local_oid, upstream_oid)
                .map_err(|e| GitError::StatusFailed {
                    message: format!("failed to calculate ahead/behind counts: {}", e),
                })?
        } else {
            (0, 0)
        };

        Ok(Some(UpstreamInfo {
            name: upstream_name.to_string(),
            remote: remote_name,
            ahead_by,
            behind_by,
        }))
    }

    /// Get working tree status for status operation
    fn get_working_tree_status(
        &self,
        repo: &Repository,
        config: &StatusConfig,
    ) -> Result<WorkingTreeStatus, GitError> {
        let mut opts = git2::StatusOptions::new();

        if config.include_untracked.unwrap_or(true) {
            opts.include_untracked(true);
        }

        if config.include_ignored.unwrap_or(false) {
            opts.include_ignored(true);
        }

        let statuses = repo
            .statuses(Some(&mut opts))
            .map_err(|e| GitError::StatusFailed {
                message: format!("failed to get repository status: {}", e),
            })?;

        let mut staged = Vec::new();
        let mut unstaged = Vec::new();
        let mut untracked = Vec::new();
        let mut ignored = Vec::new();
        let mut conflicts = Vec::new();

        for entry in statuses.iter() {
            let path = entry.path().unwrap_or("unknown").to_string();
            let status_flags = entry.status();

            if status_flags.contains(git2::Status::CONFLICTED) {
                conflicts.push(FileStatus {
                    path: path.clone(),
                    status: "conflicted".to_string(),
                });
            }

            if config.include_staged.unwrap_or(true) {
                if status_flags.intersects(
                    git2::Status::INDEX_NEW
                        | git2::Status::INDEX_MODIFIED
                        | git2::Status::INDEX_DELETED
                        | git2::Status::INDEX_RENAMED
                        | git2::Status::INDEX_TYPECHANGE,
                ) {
                    let status_name = if status_flags.contains(git2::Status::INDEX_NEW) {
                        "added"
                    } else if status_flags.contains(git2::Status::INDEX_MODIFIED) {
                        "modified"
                    } else if status_flags.contains(git2::Status::INDEX_DELETED) {
                        "deleted"
                    } else if status_flags.contains(git2::Status::INDEX_RENAMED) {
                        "renamed"
                    } else if status_flags.contains(git2::Status::INDEX_TYPECHANGE) {
                        "typechange"
                    } else {
                        "unknown"
                    };

                    staged.push(FileStatus {
                        path: path.clone(),
                        status: status_name.to_string(),
                    });
                }
            }

            if status_flags.intersects(
                git2::Status::WT_MODIFIED
                    | git2::Status::WT_DELETED
                    | git2::Status::WT_TYPECHANGE
                    | git2::Status::WT_RENAMED,
            ) {
                let status_name = if status_flags.contains(git2::Status::WT_MODIFIED) {
                    "modified"
                } else if status_flags.contains(git2::Status::WT_DELETED) {
                    "deleted"
                } else if status_flags.contains(git2::Status::WT_RENAMED) {
                    "renamed"
                } else if status_flags.contains(git2::Status::WT_TYPECHANGE) {
                    "typechange"
                } else {
                    "unknown"
                };

                unstaged.push(FileStatus {
                    path: path.clone(),
                    status: status_name.to_string(),
                });
            }

            if config.include_untracked.unwrap_or(true)
                && status_flags.contains(git2::Status::WT_NEW)
            {
                untracked.push(FileStatus {
                    path: path.clone(),
                    status: "untracked".to_string(),
                });
            }

            if config.include_ignored.unwrap_or(false)
                && status_flags.contains(git2::Status::IGNORED)
            {
                ignored.push(FileStatus {
                    path: path.clone(),
                    status: "ignored".to_string(),
                });
            }
        }

        let clean = staged.is_empty()
            && unstaged.is_empty()
            && untracked.is_empty()
            && conflicts.is_empty();

        Ok(WorkingTreeStatus {
            clean,
            staged,
            unstaged,
            untracked,
            ignored,
            conflicts,
        })
    }

    /// Get in-progress operation flags for status operation
    fn get_in_progress_flags(&self, repo: &Repository) -> Result<InProgressFlags, GitError> {
        let git_dir = repo.path();

        let merge = git_dir.join("MERGE_HEAD").exists();
        let cherry_pick = git_dir.join("CHERRY_PICK_HEAD").exists();
        let revert = git_dir.join("REVERT_HEAD").exists();
        let bisect = git_dir.join("BISECT_LOG").exists();

        // Check for rebase (multiple possible locations)
        let rebase = git_dir.join("rebase-apply").exists() || git_dir.join("rebase-merge").exists();

        Ok(InProgressFlags {
            merge,
            rebase,
            cherry_pick,
            revert,
            bisect,
        })
    }

    /// Execute merge operation
    async fn execute_merge(&self, config: &MergeConfig) -> Result<Value, GitError> {
        let path = Path::new(&config.path);

        // Open the repository
        let repo = Repository::open(path).map_err(|e| {
            if e.code() == git2::ErrorCode::NotFound {
                GitError::RepositoryNotFound {
                    path: config.path.clone(),
                }
            } else {
                GitError::MergeFailed {
                    message: format!("failed to open repository: {}", e),
                }
            }
        })?;

        // Save current HEAD OID for potential abort
        let head_ref = repo.head().map_err(|e| {
            if e.code() == git2::ErrorCode::UnbornBranch {
                GitError::MergeFailed {
                    message: "repository has no commits".to_string(),
                }
            } else {
                GitError::MergeFailed {
                    message: format!("failed to get HEAD: {}", e),
                }
            }
        })?;

        let head_commit_oid = head_ref.target().ok_or_else(|| GitError::MergeFailed {
            message: "HEAD is not a direct reference".to_string(),
        })?;

        // Resolve target branch
        let (target_branch_name, _target_commit) = self.resolve_target_branch(&repo, config)?;

        // Check for dirty working tree if required
        if !config.allow_uncommitted.unwrap_or(false) {
            self.check_working_tree_clean(&repo)?;
        }

        // Resolve source commit
        let source_commit = self.resolve_source_commit(&repo, config)?;

        // Create annotated commit for merge analysis
        let source_annotated = repo
            .find_annotated_commit(source_commit.id())
            .map_err(|e| GitError::MergeFailed {
                message: format!("failed to create annotated commit: {}", e),
            })?;

        // Perform merge analysis
        let merge_analysis =
            repo.merge_analysis(&[&source_annotated])
                .map_err(|e| GitError::MergeFailed {
                    message: format!("merge analysis failed: {}", e),
                })?;

        let ff_only = config.ff_only.unwrap_or(false);
        let no_ff = config.no_ff.unwrap_or(false);
        let squash = config.squash.unwrap_or(false);
        let abort_on_conflict = config.abort_on_conflict.unwrap_or(true);

        // Handle different merge scenarios
        if merge_analysis.0.is_up_to_date() {
            // Already up to date
            return Ok(json!({
                "backend": "git",
                "alias": self.alias,
                "path": config.path,
                "action": "merge",
                "source": config.source,
                "target": target_branch_name,
                "mode": "up_to_date",
                "status": "up_to_date",
                "ff_only": ff_only,
                "no_ff": no_ff,
                "squash": squash,
                "commit": null
            }));
        } else if merge_analysis.0.is_fast_forward() && !no_ff && !squash {
            // Fast-forward merge
            return self
                .perform_fast_forward_merge(&repo, &source_commit, config, &target_branch_name)
                .await;
        } else if merge_analysis.0.is_normal() || no_ff {
            // Normal merge or forced non-fast-forward
            if ff_only {
                return Err(GitError::MergeNonFastForward);
            }

            if squash {
                return self
                    .perform_squash_merge(&repo, &source_commit, config, &target_branch_name)
                    .await;
            } else {
                return self
                    .perform_normal_merge(
                        &repo,
                        &source_commit,
                        config,
                        &target_branch_name,
                        head_commit_oid,
                        abort_on_conflict,
                    )
                    .await;
            }
        } else {
            return Err(GitError::MergeFailed {
                message: "unsupported merge analysis result".to_string(),
            });
        }
    }

    /// Execute rebase operation
    async fn execute_rebase(&self, config: &RebaseConfig) -> Result<Value, GitError> {
        let path = Path::new(&config.path);

        // Open the repository
        let repo = Repository::open(path).map_err(|e| {
            if e.code() == git2::ErrorCode::NotFound {
                GitError::RepositoryNotFound {
                    path: config.path.clone(),
                }
            } else {
                GitError::RebaseFailed {
                    message: format!("failed to open repository: {}", e),
                }
            }
        })?;

        let operation = config.operation.as_ref().unwrap_or(&RebaseOperation::Start);

        // Check for existing rebase state
        let rebase_in_progress = self.is_rebase_in_progress(&repo)?;

        match operation {
            RebaseOperation::Start => {
                if rebase_in_progress {
                    return Err(GitError::RebaseInProgress);
                }
                self.execute_rebase_start(&repo, config).await
            }
            RebaseOperation::Continue => {
                if !rebase_in_progress {
                    return Err(GitError::RebaseNotInProgress);
                }
                self.execute_rebase_continue(&repo, config).await
            }
            RebaseOperation::Abort => {
                if !rebase_in_progress {
                    return Err(GitError::RebaseNotInProgress);
                }
                self.execute_rebase_abort(&repo, config).await
            }
        }
    }

    /// Check if a rebase operation is currently in progress
    fn is_rebase_in_progress(&self, repo: &Repository) -> Result<bool, GitError> {
        let git_dir = repo.path();

        // Check for rebase-apply directory (used by git am and git rebase)
        let rebase_apply = git_dir.join("rebase-apply");
        if rebase_apply.exists() {
            log::debug!("Found rebase-apply directory, rebase in progress");
            return Ok(true);
        }

        // Check for rebase-merge directory (used by interactive rebase)
        let rebase_merge = git_dir.join("rebase-merge");
        if rebase_merge.exists() {
            log::debug!("Found rebase-merge directory, rebase in progress");
            return Ok(true);
        }

        // Also check repository state
        let repo_state = repo.state();
        match repo_state {
            git2::RepositoryState::Rebase
            | git2::RepositoryState::RebaseInteractive
            | git2::RepositoryState::RebaseMerge => {
                log::debug!(
                    "Repository state indicates rebase in progress: {:?}",
                    repo_state
                );
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Execute rebase start operation
    async fn execute_rebase_start(
        &self,
        repo: &Repository,
        config: &RebaseConfig,
    ) -> Result<Value, GitError> {
        let rebase_author = self.resolve_rebase_author(config)?;
        // Resolve branch (source) and upstream
        let (branch_name, branch_commit) = self.resolve_rebase_branch(repo, config)?;
        let upstream_commit = self.resolve_rebase_upstream(repo, config)?;

        // Check for clean working tree if required
        if !config.allow_uncommitted.unwrap_or(false) {
            self.check_working_tree_clean(repo).map_err(|e| match e {
                GitError::MergeDirtyWorktree => GitError::RebaseDirtyWorktree,
                other => other,
            })?;
        }

        // Check for fast-forward scenario
        if config.ff_only.unwrap_or(false) {
            return self.handle_fast_forward_rebase(
                repo,
                &branch_commit,
                &upstream_commit,
                config,
                &branch_name,
            );
        }

        // Start the actual rebase operation
        let abort_on_conflict = config.abort_on_conflict.unwrap_or(true);

        // Use git2 rebase API
        let branch_annotated = repo
            .find_annotated_commit(branch_commit.id())
            .map_err(|e| GitError::RebaseFailed {
                message: format!("failed to create annotated commit for branch: {}", e),
            })?;

        let upstream_annotated = repo
            .find_annotated_commit(upstream_commit.id())
            .map_err(|e| GitError::RebaseFailed {
                message: format!("failed to create annotated commit for upstream: {}", e),
            })?;

        // Initialize rebase
        let mut rebase = repo
            .rebase(
                Some(&branch_annotated),
                Some(&upstream_annotated),
                None, // onto (same as upstream)
                None, // options
            )
            .map_err(|e| GitError::RebaseFailed {
                message: format!("failed to start rebase: {}", e),
            })?;

        let mut commits_rebased = 0;
        let old_base = branch_commit.id().to_string();

        // Process each rebase operation
        loop {
            match rebase.next() {
                Some(Ok(op)) => {
                    log::debug!("Processing rebase operation for commit: {:?}", op.id());

                    // Apply the operation to the working tree and index
                    // The git2 library handles this automatically when we call next()

                    // Check if there are any conflicts after applying the operation
                    let index = repo.index().map_err(|e| GitError::RebaseFailed {
                        message: format!("failed to get repository index: {}", e),
                    })?;

                    if index.has_conflicts() {
                        log::warn!("Conflicts detected during rebase operation");
                        if abort_on_conflict {
                            // Abort the rebase
                            rebase.abort().map_err(|e| GitError::RebaseFailed {
                                message: format!("failed to abort rebase: {}", e),
                            })?;
                            return Err(GitError::RebaseConflict);
                        } else {
                            // Leave in conflicted state for manual resolution
                            return Err(GitError::RebaseConflict);
                        }
                    }

                    // Commit the rebased changes
                    let committer_sig = self.resolve_rebase_committer_signature(repo, config)?;
                    rebase
                        .commit(rebase_author.as_ref(), &committer_sig, None)
                        .map_err(|e| GitError::RebaseFailed {
                            message: format!("failed to commit during rebase: {}", e),
                        })?;

                    commits_rebased += 1;
                }
                Some(Err(e)) => {
                    return Err(GitError::RebaseFailed {
                        message: format!("rebase operation failed: {}", e),
                    });
                }
                None => {
                    // No more operations, rebase is complete
                    break;
                }
            }
        }

        // Finish the rebase
        let committer_sig = self.resolve_rebase_committer_signature(repo, config)?;
        rebase
            .finish(Some(&committer_sig))
            .map_err(|e| GitError::RebaseFailed {
                message: format!("failed to finish rebase: {}", e),
            })?;

        // Get new HEAD
        let new_head = repo.head().map_err(|e| GitError::RebaseFailed {
            message: format!("failed to get new HEAD after rebase: {}", e),
        })?;
        let new_base = new_head.target().unwrap().to_string();

        Ok(json!({
            "backend": "git",
            "alias": self.alias,
            "path": config.path,
            "action": "rebase",
            "operation": "start",
            "branch": branch_name,
            "upstream": config.upstream.as_ref().unwrap(),
            "status": "rebased",
            "mode": "normal",
            "ff_only": config.ff_only.unwrap_or(false),
            "preserve_merges": config.preserve_merges.unwrap_or(false),
            "autosquash": config.autosquash.unwrap_or(false),
            "summary": {
                "commits_rebased": commits_rebased,
                "old_base": old_base,
                "new_base": new_base
            }
        }))
    }

    /// Execute rebase continue operation
    async fn execute_rebase_continue(
        &self,
        repo: &Repository,
        config: &RebaseConfig,
    ) -> Result<Value, GitError> {
        let abort_on_conflict = config.abort_on_conflict.unwrap_or(true);
        let committer_sig = self.resolve_rebase_committer_signature(repo, config)?;
        let rebase_author = self.resolve_rebase_author(config)?;

        // Open the existing rebase - git2 can resume from rebase state files
        let mut rebase = repo.open_rebase(None).map_err(|e| GitError::RebaseFailed {
            message: format!("failed to open existing rebase: {}", e),
        })?;

        let mut commits_rebased = 0;

        // Continue processing rebase operations from where we left off
        loop {
            match rebase.next() {
                Some(Ok(op)) => {
                    log::debug!("Continuing rebase operation for commit: {:?}", op.id());

                    // Check if there are any conflicts after applying the operation
                    let index = repo.index().map_err(|e| GitError::RebaseFailed {
                        message: format!("failed to get repository index: {}", e),
                    })?;

                    if index.has_conflicts() {
                        log::warn!("Conflicts detected during rebase continue");
                        if abort_on_conflict {
                            // Abort the rebase
                            rebase.abort().map_err(|e| GitError::RebaseFailed {
                                message: format!("failed to abort rebase: {}", e),
                            })?;
                            return Err(GitError::RebaseConflict);
                        } else {
                            // Leave in conflicted state for manual resolution
                            return Err(GitError::RebaseConflict);
                        }
                    }

                    // Commit the rebased changes
                    rebase
                        .commit(rebase_author.as_ref(), &committer_sig, None)
                        .map_err(|e| GitError::RebaseFailed {
                            message: format!("failed to commit during rebase continue: {}", e),
                        })?;

                    commits_rebased += 1;
                }
                Some(Err(e)) => {
                    return Err(GitError::RebaseFailed {
                        message: format!("rebase continue operation failed: {}", e),
                    });
                }
                None => {
                    // No more operations, rebase is complete
                    break;
                }
            }
        }

        // Finish the rebase
        rebase
            .finish(Some(&committer_sig))
            .map_err(|e| GitError::RebaseFailed {
                message: format!("failed to finish rebase: {}", e),
            })?;

        Ok(json!({
            "backend": "git",
            "alias": self.alias,
            "path": config.path,
            "action": "rebase",
            "operation": "continue",
            "status": "rebased",
            "summary": {
                "commits_rebased": commits_rebased
            }
        }))
    }

    /// Execute rebase abort operation  
    async fn execute_rebase_abort(
        &self,
        repo: &Repository,
        config: &RebaseConfig,
    ) -> Result<Value, GitError> {
        // Open the existing rebase to access its state
        let mut rebase = repo.open_rebase(None).map_err(|e| GitError::RebaseFailed {
            message: format!("failed to open existing rebase for abort: {}", e),
        })?;

        // Abort the rebase - this restores the repository to its pre-rebase state
        rebase.abort().map_err(|e| GitError::RebaseFailed {
            message: format!("failed to abort rebase: {}", e),
        })?;

        log::info!("Rebase aborted, repository restored to original state");

        Ok(json!({
            "backend": "git",
            "alias": self.alias,
            "path": config.path,
            "action": "rebase",
            "operation": "abort",
            "status": "aborted"
        }))
    }

    /// Resolve the branch to be rebased
    fn resolve_rebase_branch<'a>(
        &self,
        repo: &'a Repository,
        config: &RebaseConfig,
    ) -> Result<(String, Commit<'a>), GitError> {
        if let Some(ref branch_name) = config.branch {
            // Use specified branch
            let branch = repo
                .find_branch(branch_name, BranchType::Local)
                .map_err(|_| GitError::RebaseBranchNotFound {
                    branch: branch_name.clone(),
                })?;

            let commit = branch
                .get()
                .peel_to_commit()
                .map_err(|e| GitError::RebaseFailed {
                    message: format!("failed to get commit from branch '{}': {}", branch_name, e),
                })?;

            Ok((branch_name.clone(), commit))
        } else {
            // Use current HEAD
            let head_ref = repo.head().map_err(|e| {
                if e.code() == git2::ErrorCode::UnbornBranch {
                    GitError::RebaseFailed {
                        message: "repository has no commits".to_string(),
                    }
                } else {
                    GitError::RebaseFailed {
                        message: format!("failed to get HEAD: {}", e),
                    }
                }
            })?;

            if head_ref.is_branch() {
                let branch_name = head_ref.shorthand().unwrap_or("HEAD").to_string();
                let commit = head_ref
                    .peel_to_commit()
                    .map_err(|e| GitError::RebaseFailed {
                        message: format!("failed to get commit from HEAD: {}", e),
                    })?;
                Ok((branch_name, commit))
            } else {
                Err(GitError::RebaseDetachedHead)
            }
        }
    }

    /// Resolve the upstream commit for rebase
    fn resolve_rebase_upstream<'a>(
        &self,
        repo: &'a Repository,
        config: &RebaseConfig,
    ) -> Result<Commit<'a>, GitError> {
        let upstream_spec = config.upstream.as_ref().unwrap(); // Should be validated already

        let upstream_obj =
            repo.revparse_single(upstream_spec)
                .map_err(|_| GitError::RebaseUpstreamNotFound {
                    upstream: upstream_spec.clone(),
                })?;

        let upstream_commit =
            upstream_obj
                .peel_to_commit()
                .map_err(|_| GitError::RebaseUpstreamNotCommit {
                    upstream: upstream_spec.clone(),
                })?;

        Ok(upstream_commit)
    }

    /// Handle fast-forward only rebase
    fn handle_fast_forward_rebase(
        &self,
        repo: &Repository,
        branch_commit: &Commit,
        upstream_commit: &Commit,
        config: &RebaseConfig,
        branch_name: &str,
    ) -> Result<Value, GitError> {
        // Compare the branch (not HEAD) with the upstream.
        let descends = |a: Oid, b: Oid| {
            repo.graph_descendant_of(a, b)
                .map_err(|e| GitError::RebaseFailed {
                    message: format!("cannot compare '{branch_name}' with the upstream: {e}"),
                })
        };
        let (b, u) = (branch_commit.id(), upstream_commit.id());
        let up_to_date = b == u || descends(b, u)?;
        let fast_forward = !up_to_date && descends(u, b)?;

        if up_to_date {
            Ok(json!({
                "backend": "git",
                "alias": self.alias,
                "path": config.path,
                "action": "rebase",
                "operation": "start",
                "branch": branch_name,
                "upstream": config.upstream.as_ref().unwrap(),
                "status": "rebased",
                "mode": "up_to_date",
                "ff_only": true,
                "preserve_merges": config.preserve_merges.unwrap_or(false),
                "autosquash": config.autosquash.unwrap_or(false),
                "summary": {
                    "commits_rebased": 0,
                    "old_base": branch_commit.id().to_string(),
                    "new_base": branch_commit.id().to_string()
                }
            }))
        } else if fast_forward {
            // Update the working tree first with a safe checkout (local
            // changes are never overwritten), then move the branch.
            let mut checkout = git2::build::CheckoutBuilder::new();
            checkout.safe();
            repo.checkout_tree(upstream_commit.as_object(), Some(&mut checkout))
                .map_err(|e| {
                    if e.code() == git2::ErrorCode::Conflict {
                        GitError::RebaseDirtyWorktree
                    } else {
                        GitError::RebaseFailed {
                            message: format!("failed to checkout after fast-forward: {}", e),
                        }
                    }
                })?;
            let ref_name = format!("refs/heads/{branch_name}");
            let mut reference =
                repo.find_reference(&ref_name)
                    .map_err(|e| GitError::RebaseFailed {
                        message: format!("failed to find '{branch_name}': {}", e),
                    })?;
            reference
                .set_target(upstream_commit.id(), "Fast-forward rebase")
                .map_err(|e| GitError::RebaseFailed {
                    message: format!("failed to fast-forward '{branch_name}': {}", e),
                })?;
            // As git rebase does, the rebased branch ends up checked out.
            repo.set_head(&ref_name)
                .map_err(|e| GitError::RebaseFailed {
                    message: format!("failed to check out '{branch_name}': {}", e),
                })?;

            Ok(json!({
                "backend": "git",
                "alias": self.alias,
                "path": config.path,
                "action": "rebase",
                "operation": "start",
                "branch": branch_name,
                "upstream": config.upstream.as_ref().unwrap(),
                "status": "rebased",
                "mode": "fast_forward",
                "ff_only": true,
                "preserve_merges": config.preserve_merges.unwrap_or(false),
                "autosquash": config.autosquash.unwrap_or(false),
                "summary": {
                    "commits_rebased": 0,
                    "old_base": branch_commit.id().to_string(),
                    "new_base": upstream_commit.id().to_string()
                }
            }))
        } else {
            Err(GitError::RebaseNonFastForward)
        }
    }

    /// Resolve committer signature for rebase operations
    fn resolve_rebase_committer_signature(
        &self,
        repo: &Repository,
        config: &RebaseConfig,
    ) -> Result<Signature<'static>, GitError> {
        let (name, email) = identity(
            repo,
            config.committer_name.as_deref(),
            config.committer_email.as_deref(),
            "COMMITTER",
        )
        .ok_or(GitError::RebaseIdentityMissing)?;
        Signature::now(&name, &email).map_err(|_| GitError::RebaseIdentityMissing)
    }

    /// The author given with author_name and author_email, which then
    /// replaces the author of every rebased commit; None keeps the authors.
    fn resolve_rebase_author(
        &self,
        config: &RebaseConfig,
    ) -> Result<Option<Signature<'static>>, GitError> {
        match (&config.author_name, &config.author_email) {
            (Some(n), Some(e)) => Signature::now(n, e)
                .map(Some)
                .map_err(|_| GitError::RebaseIdentityMissing),
            _ => Ok(None),
        }
    }

    /// Resolve target branch for merge
    fn resolve_target_branch<'a>(
        &self,
        repo: &'a Repository,
        config: &MergeConfig,
    ) -> Result<(String, Commit<'a>), GitError> {
        if let Some(target_name) = &config.target {
            // Explicit target branch specified
            let target_branch = repo
                .find_branch(target_name, BranchType::Local)
                .map_err(|_| GitError::MergeTargetNotFound(target_name.clone()))?;

            let target_commit =
                target_branch
                    .get()
                    .peel_to_commit()
                    .map_err(|e| GitError::MergeFailed {
                        message: format!("failed to get target commit: {}", e),
                    })?;

            // Ensure we're on the target branch
            let head = repo.head().map_err(|e| GitError::MergeFailed {
                message: format!("failed to get HEAD: {}", e),
            })?;

            if let Ok(current_branch) = head.shorthand() {
                if current_branch != target_name {
                    // Need to checkout target branch
                    self.checkout_merge_branch(repo, target_name)?;
                }
            } else {
                return Err(GitError::MergeDetachedHead);
            }

            Ok((target_name.clone(), target_commit))
        } else {
            // Use current branch
            let head = repo.head().map_err(|e| GitError::MergeFailed {
                message: format!("failed to get HEAD: {}", e),
            })?;

            if !head.is_branch() {
                return Err(GitError::MergeDetachedHead);
            }

            let target_branch_name = head.shorthand().unwrap_or("HEAD").to_string();
            let target_commit = head.peel_to_commit().map_err(|e| GitError::MergeFailed {
                message: format!("failed to get target commit: {}", e),
            })?;

            Ok((target_branch_name, target_commit))
        }
    }

    /// Check if working tree is clean
    fn check_working_tree_clean(&self, repo: &Repository) -> Result<(), GitError> {
        let statuses = repo.statuses(None).map_err(|e| GitError::MergeFailed {
            message: format!("failed to check working tree status: {}", e),
        })?;

        for status in statuses.iter() {
            if !status.status().is_ignored() {
                return Err(GitError::MergeDirtyWorktree);
            }
        }

        Ok(())
    }

    /// Resolve source commit
    fn resolve_source_commit<'a>(
        &self,
        repo: &'a Repository,
        config: &MergeConfig,
    ) -> Result<Commit<'a>, GitError> {
        let source_object = repo
            .revparse_single(&config.source)
            .map_err(|_| GitError::MergeSourceNotFound(config.source.clone()))?;

        // Peel to commit
        let source_commit = source_object
            .peel_to_commit()
            .map_err(|_| GitError::MergeSourceNotCommit(config.source.clone()))?;

        Ok(source_commit)
    }

    /// Perform fast-forward merge
    async fn perform_fast_forward_merge(
        &self,
        repo: &Repository,
        source_commit: &Commit<'_>,
        config: &MergeConfig,
        target_branch_name: &str,
    ) -> Result<Value, GitError> {
        // Update the working tree first with a safe checkout (local changes
        // are never overwritten), then move the branch.
        let mut checkout = git2::build::CheckoutBuilder::new();
        checkout.safe();
        repo.checkout_tree(source_commit.as_object(), Some(&mut checkout))
            .map_err(|e| {
                if e.code() == git2::ErrorCode::Conflict {
                    GitError::MergeDirtyWorktree
                } else {
                    GitError::MergeFailed {
                        message: format!("failed to update working tree: {}", e),
                    }
                }
            })?;
        let refname = format!("refs/heads/{}", target_branch_name);
        repo.reference(&refname, source_commit.id(), true, "fast-forward merge")
            .map_err(|e| GitError::MergeFailed {
                message: format!("failed to update branch reference: {}", e),
            })?;

        Ok(json!({
            "backend": "git",
            "alias": self.alias,
            "path": config.path,
            "action": "merge",
            "source": config.source,
            "target": target_branch_name,
            "mode": "fast_forward",
            "status": "fast_forward",
            "ff_only": config.ff_only.unwrap_or(false),
            "no_ff": config.no_ff.unwrap_or(false),
            "squash": config.squash.unwrap_or(false),
            "commit": {
                "oid": source_commit.id().to_string(),
                "message": null
            }
        }))
    }

    /// Perform squash merge
    async fn perform_squash_merge(
        &self,
        repo: &Repository,
        source_commit: &Commit<'_>,
        config: &MergeConfig,
        target_branch_name: &str,
    ) -> Result<Value, GitError> {
        // Get current HEAD commit
        let head_commit =
            repo.head()
                .unwrap()
                .peel_to_commit()
                .map_err(|e| GitError::MergeFailed {
                    message: format!("failed to get HEAD commit: {}", e),
                })?;

        // Apply changes from source to index
        let mut merge_opts = git2::MergeOptions::new();
        let source_annotated = repo
            .find_annotated_commit(source_commit.id())
            .map_err(|e| GitError::MergeFailed {
                message: format!("failed to create annotated commit: {}", e),
            })?;
        repo.merge(&[&source_annotated], Some(&mut merge_opts), None)
            .map_err(|e| GitError::MergeFailed {
                message: format!("squash merge failed: {}", e),
            })?;

        // Check for conflicts
        let mut index = repo.index().map_err(|e| GitError::MergeFailed {
            message: format!("failed to get index: {}", e),
        })?;

        if index.has_conflicts() {
            if config.abort_on_conflict.unwrap_or(true) {
                // Abort merge
                repo.checkout_head(Some(git2::build::CheckoutBuilder::default().force()))
                    .map_err(|e| GitError::MergeFailed {
                        message: format!("failed to abort conflicted merge: {}", e),
                    })?;
            }
            return Err(GitError::MergeConflict);
        }

        // Create commit with squashed changes
        let tree_id = index.write_tree().map_err(|e| GitError::MergeFailed {
            message: format!("failed to write tree: {}", e),
        })?;
        let tree = repo.find_tree(tree_id).map_err(|e| GitError::MergeFailed {
            message: format!("failed to find tree: {}", e),
        })?;

        let (author_sig, committer_sig) = self.resolve_merge_identity(repo, config)?;

        let default_message = format!(
            "Squash merge '{}' into '{}'",
            config.source, target_branch_name
        );
        let message = config.commit_message.as_deref().unwrap_or(&default_message);

        let commit_id = repo
            .commit(
                Some("HEAD"),
                &author_sig,
                &committer_sig,
                message,
                &tree,
                &[&head_commit],
            )
            .map_err(|e| GitError::MergeFailed {
                message: format!("failed to create squash commit: {}", e),
            })?;

        Ok(json!({
            "backend": "git",
            "alias": self.alias,
            "path": config.path,
            "action": "merge",
            "source": config.source,
            "target": target_branch_name,
            "mode": "squash",
            "status": "squashed",
            "ff_only": config.ff_only.unwrap_or(false),
            "no_ff": config.no_ff.unwrap_or(false),
            "squash": config.squash.unwrap_or(false),
            "commit": {
                "oid": commit_id.to_string(),
                "message": message,
                "author": {
                    "name": author_sig.name().unwrap_or(""),
                    "email": author_sig.email().unwrap_or("")
                },
                "committer": {
                    "name": committer_sig.name().unwrap_or(""),
                    "email": committer_sig.email().unwrap_or("")
                }
            }
        }))
    }

    /// Perform normal merge
    async fn perform_normal_merge(
        &self,
        repo: &Repository,
        source_commit: &Commit<'_>,
        config: &MergeConfig,
        target_branch_name: &str,
        _head_commit_oid: Oid,
        abort_on_conflict: bool,
    ) -> Result<Value, GitError> {
        let head_commit =
            repo.head()
                .unwrap()
                .peel_to_commit()
                .map_err(|e| GitError::MergeFailed {
                    message: format!("failed to get HEAD commit: {}", e),
                })?;

        // Perform merge
        let mut merge_opts = git2::MergeOptions::new();
        let source_annotated = repo
            .find_annotated_commit(source_commit.id())
            .map_err(|e| GitError::MergeFailed {
                message: format!("failed to create annotated commit: {}", e),
            })?;
        repo.merge(&[&source_annotated], Some(&mut merge_opts), None)
            .map_err(|e| GitError::MergeFailed {
                message: format!("merge failed: {}", e),
            })?;

        // Check for conflicts
        let mut index = repo.index().map_err(|e| GitError::MergeFailed {
            message: format!("failed to get index: {}", e),
        })?;

        if index.has_conflicts() {
            if abort_on_conflict {
                // Abort merge
                repo.checkout_head(Some(git2::build::CheckoutBuilder::default().force()))
                    .map_err(|e| GitError::MergeFailed {
                        message: format!("failed to abort conflicted merge: {}", e),
                    })?;
            }
            return Err(GitError::MergeConflict);
        }

        // Create merge commit
        let tree_id = index.write_tree().map_err(|e| GitError::MergeFailed {
            message: format!("failed to write tree: {}", e),
        })?;
        let tree = repo.find_tree(tree_id).map_err(|e| GitError::MergeFailed {
            message: format!("failed to find tree: {}", e),
        })?;

        let (author_sig, committer_sig) = self.resolve_merge_identity(repo, config)?;

        let default_message = format!(
            "Merge branch '{}' into '{}'",
            config.source, target_branch_name
        );
        let message = config.commit_message.as_deref().unwrap_or(&default_message);

        let commit_id = repo
            .commit(
                Some("HEAD"),
                &author_sig,
                &committer_sig,
                message,
                &tree,
                &[&head_commit, source_commit],
            )
            .map_err(|e| GitError::MergeFailed {
                message: format!("failed to create merge commit: {}", e),
            })?;

        Ok(json!({
            "backend": "git",
            "alias": self.alias,
            "path": config.path,
            "action": "merge",
            "source": config.source,
            "target": target_branch_name,
            "mode": "normal",
            "status": "merged",
            "ff_only": config.ff_only.unwrap_or(false),
            "no_ff": config.no_ff.unwrap_or(false),
            "squash": config.squash.unwrap_or(false),
            "commit": {
                "oid": commit_id.to_string(),
                "message": message,
                "author": {
                    "name": author_sig.name().unwrap_or(""),
                    "email": author_sig.email().unwrap_or("")
                },
                "committer": {
                    "name": committer_sig.name().unwrap_or(""),
                    "email": committer_sig.email().unwrap_or("")
                }
            }
        }))
    }

    /// Resolve merge identity (author and committer)
    fn resolve_merge_identity(
        &self,
        repo: &Repository,
        config: &MergeConfig,
    ) -> Result<(Signature<'static>, Signature<'static>), GitError> {
        let (author_name, author_email) = identity(
            repo,
            config.author_name.as_deref(),
            config.author_email.as_deref(),
            "AUTHOR",
        )
        .ok_or(GitError::MergeIdentityMissing)?;
        let committer_name = config.committer_name.clone().unwrap_or(author_name.clone());
        let committer_email = config
            .committer_email
            .clone()
            .unwrap_or(author_email.clone());
        let author_sig = Signature::now(&author_name, &author_email)
            .map_err(|_| GitError::MergeIdentityMissing)?;
        let committer_sig = Signature::now(&committer_name, &committer_email)
            .map_err(|_| GitError::MergeIdentityMissing)?;
        Ok((author_sig, committer_sig))
    }

    /// Checkout a specific branch for merge (different from branch checkout)
    fn checkout_merge_branch(&self, repo: &Repository, branch_name: &str) -> Result<(), GitError> {
        let branch = repo
            .find_branch(branch_name, BranchType::Local)
            .map_err(|_| GitError::MergeTargetNotFound(branch_name.to_string()))?;

        let commit = branch
            .get()
            .peel_to_commit()
            .map_err(|e| GitError::MergeFailed {
                message: format!("failed to get branch commit: {}", e),
            })?;

        repo.checkout_tree(commit.as_object(), None)
            .map_err(|e| GitError::MergeFailed {
                message: format!("failed to checkout branch: {}", e),
            })?;

        repo.set_head(&format!("refs/heads/{}", branch_name))
            .map_err(|e| GitError::MergeFailed {
                message: format!("failed to set HEAD: {}", e),
            })?;

        Ok(())
    }

    /// Sync verb implementation - orchestrates pull + integration + push
    pub async fn sync(&self, args: Value) -> Result<Value, GitError> {
        let config = self.parse_sync_config(args)?;
        self.validate_sync_config(&config)?;
        self.execute_sync(&config).await
    }

    /// Parse sync configuration from arguments
    fn parse_sync_config(&self, args: Value) -> Result<SyncConfig, GitError> {
        crate::core::lenient::from_value(args).map_err(|e| GitError::InvalidSyncConfig {
            message: format!("failed to parse sync config: {}", e),
        })
    }

    /// Validate sync configuration
    fn validate_sync_config(&self, config: &SyncConfig) -> Result<(), GitError> {
        // Check required fields
        if config.path.is_empty() {
            return Err(GitError::InvalidSyncConfig {
                message: "path cannot be empty".to_string(),
            });
        }

        // Check timeout constraint
        if let Some(timeout_ms) = config.timeout_ms {
            if timeout_ms == 0 {
                return Err(GitError::InvalidSyncConfig {
                    message: "timeout_ms must be greater than 0".to_string(),
                });
            }
        }

        // Check remote constraint
        if let Some(ref remote) = config.remote {
            if remote.is_empty() {
                return Err(GitError::InvalidSyncConfig {
                    message: "remote cannot be empty string".to_string(),
                });
            }
        }

        // Check branch constraint
        if let Some(ref branch) = config.branch {
            if branch.is_empty() {
                return Err(GitError::InvalidSyncConfig {
                    message: "branch cannot be empty string".to_string(),
                });
            }
        }

        // Check remote_branch constraint
        if let Some(ref remote_branch) = config.remote_branch {
            if remote_branch.is_empty() {
                return Err(GitError::InvalidSyncConfig {
                    message: "remote_branch cannot be empty string".to_string(),
                });
            }
        }

        if config.known_hosts_path.as_deref() == Some("") {
            return Err(GitError::InvalidSyncConfig {
                message: "known_hosts_path cannot be empty".to_string(),
            });
        }

        // Check contradictory safety options
        if config.force_push.unwrap_or(false) && config.ff_only.unwrap_or(false) {
            return Err(GitError::InvalidSyncConfig {
                message: "force_push and ff_only are contradictory options".to_string(),
            });
        }

        Ok(())
    }

    /// Parse status summary configuration from arguments
    fn parse_status_summary_config(&self, args: Value) -> Result<StatusSummaryConfig, GitError> {
        let config: StatusSummaryConfig = crate::core::lenient::from_value(args).map_err(|e| {
            GitError::InvalidStatusSummaryConfig {
                message: format!("failed to parse status summary config: {}", e),
            }
        })?;

        self.validate_status_summary_config(&config)?;
        Ok(config)
    }

    /// Validate status summary configuration
    fn validate_status_summary_config(&self, config: &StatusSummaryConfig) -> Result<(), GitError> {
        // Check required fields
        if config.path.is_empty() {
            return Err(GitError::InvalidStatusSummaryConfig {
                message: "path cannot be empty".to_string(),
            });
        }

        // Check timeout constraint
        if let Some(timeout_ms) = config.timeout_ms {
            if timeout_ms == 0 {
                return Err(GitError::InvalidStatusSummaryConfig {
                    message: "timeout_ms must be greater than 0".to_string(),
                });
            }
        }

        // Check max_files constraint
        if let Some(max_files) = config.max_files {
            if max_files == 0 {
                return Err(GitError::InvalidStatusSummaryConfig {
                    message: "max_files must be greater than 0".to_string(),
                });
            }
        }

        // Check branch constraint
        if let Some(ref branch) = config.branch {
            if branch.is_empty() {
                return Err(GitError::InvalidStatusSummaryConfig {
                    message: "branch cannot be empty string".to_string(),
                });
            }
        }

        // Check remote constraint
        if let Some(ref remote) = config.remote {
            if remote.is_empty() {
                return Err(GitError::InvalidStatusSummaryConfig {
                    message: "remote cannot be empty string".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Execute the sync operation
    async fn execute_sync(&self, config: &SyncConfig) -> Result<Value, GitError> {
        log::info!("Starting sync operation for path: {}", config.path);

        let mut repo = open_repo(Path::new(&config.path), &config.path, |message| {
            GitError::SyncFailed { message }
        })?;
        if repo.is_bare() {
            return Err(GitError::SyncFailed {
                message: format!(
                    "'{}' is a bare repository; sync needs a working tree",
                    config.path
                ),
            });
        }

        let remote_name = config
            .remote
            .clone()
            .unwrap_or_else(|| "origin".to_string());
        let pull_strategy = config.pull_strategy.clone().unwrap_or_default();
        let allow_uncommitted = config.allow_uncommitted.unwrap_or(false);
        let stash_uncommitted = config.stash_uncommitted.unwrap_or(false);
        let push = config.push.unwrap_or(true);
        let push_tags = config.push_tags.unwrap_or(false);
        let force_push = config.force_push.unwrap_or(false);
        let dry_run = config.dry_run.unwrap_or(false);

        // sync works on the checked-out branch.
        let current = match repo.head() {
            Ok(head) if head.is_branch() => head.shorthand().ok().map(str::to_string),
            Ok(_) => None,
            Err(e) if e.code() == git2::ErrorCode::UnbornBranch => {
                return Err(GitError::SyncFailed {
                    message: "the current branch has no commits yet".to_string(),
                });
            }
            Err(_) => None,
        };
        let local_branch = match (&config.branch, current) {
            (Some(branch), current) => {
                if repo.find_branch(branch, BranchType::Local).is_err() {
                    return Err(GitError::SyncBranchNotFound {
                        branch: branch.clone(),
                    });
                }
                if current.as_deref() != Some(branch.as_str()) {
                    return Err(GitError::SyncFailed {
                        message: format!(
                            "branch '{branch}' is not checked out; sync works on the current \
                             branch, so check it out first (for example with the branch verb, \
                             action=checkout)"
                        ),
                    });
                }
                branch.clone()
            }
            (None, Some(current)) => current,
            (None, None) => return Err(GitError::SyncDetachedHead),
        };

        // The fetch/fast-forward step integrates `<remote>/<branch>` into the
        // same-named local branch; a different remote branch would be
        // integrated into the wrong local branch.
        let remote_branch = config
            .remote_branch
            .clone()
            .unwrap_or_else(|| local_branch.clone());
        if remote_branch != local_branch {
            return Err(GitError::InvalidSyncConfig {
                message: format!(
                    "remote_branch '{}' differs from the local branch '{}'; git sync only supports syncing a branch with the same-named remote branch",
                    remote_branch, local_branch
                ),
            });
        }

        if repo.find_remote(&remote_name).is_err() {
            return Err(GitError::SyncRemoteNotFound {
                remote: remote_name.clone(),
            });
        }

        if dry_run {
            let actions = self.analyze_sync_actions(
                &remote_name,
                &local_branch,
                &remote_branch,
                &pull_strategy,
                push,
                push_tags,
            );
            return Ok(json!({
                "backend": "git",
                "alias": self.alias,
                "path": config.path,
                "action": "sync",
                "remote": remote_name,
                "branch": local_branch,
                "remote_branch": remote_branch,
                "pull_strategy": pull_strategy,
                "status": "dry_run",
                "mode": pull_strategy,
                "actions": actions
            }));
        }

        // Check working tree cleanliness and stash if asked to.
        let stashed = self.handle_sync_worktree(&mut repo, allow_uncommitted, stash_uncommitted)?;

        // Fetch and integrate, then push. Nothing is pushed unless the
        // integration really completed.
        let known_hosts = config.known_hosts_path.as_deref();
        let outcome: Result<(Value, Option<Value>), GitError> = async {
            let fetched = self
                .sync_fetch(
                    &config.path,
                    &remote_name,
                    &local_branch,
                    &pull_strategy,
                    config,
                )
                .await?;
            let integration = sync_integration_report(&fetched, &pull_strategy);
            let pushed = if push {
                Some(
                    self.sync_push(
                        &config.path,
                        &remote_name,
                        &local_branch,
                        push_tags,
                        force_push,
                        known_hosts,
                    )
                    .await?,
                )
            } else {
                None
            };
            Ok((integration, pushed))
        }
        .await;

        // Give back the user's uncommitted changes, also when the sync failed.
        let stash_conflicts = if stashed {
            match (self.sync_restore_stash(&mut repo), &outcome) {
                (Ok(conflicts), _) => conflicts,
                (Err(e), Ok(_)) => return Err(e),
                (Err(e), Err(_)) => {
                    log::warn!("restoring the stashed changes failed: {e}");
                    true
                }
            }
        } else {
            false
        };
        let (integration, push_result) = outcome?;

        let push_info = push_result.unwrap_or_else(|| {
            json!({
                "attempted": false,
                "status": "skipped"
            })
        });

        Ok(json!({
            "backend": "git",
            "alias": self.alias,
            "path": config.path,
            "action": "sync",
            "remote": remote_name,
            "branch": local_branch,
            "remote_branch": remote_branch,
            "pull_strategy": pull_strategy,
            "mode": pull_strategy,
            "status": "success",
            "integration": integration,
            "push_result": push_info,
            "stash": {
                "used": stashed,
                "conflicts_on_apply": stash_conflicts
            }
        }))
    }

    /// Checks the working tree before sync. Returns true when the changes
    /// were stashed (to be popped back afterwards).
    fn handle_sync_worktree(
        &self,
        repo: &mut Repository,
        allow_uncommitted: bool,
        stash_uncommitted: bool,
    ) -> Result<bool, GitError> {
        let is_dirty = {
            let statuses = repo.statuses(None).map_err(|e| GitError::SyncFailed {
                message: format!("failed to get repository status: {}", e),
            })?;
            statuses.iter().any(|entry| {
                let status = entry.status();
                status.is_wt_modified()
                    || status.is_wt_new()
                    || status.is_wt_deleted()
                    || status.is_wt_renamed()
                    || status.is_wt_typechange()
                    || status.is_index_modified()
                    || status.is_index_new()
                    || status.is_index_deleted()
                    || status.is_index_renamed()
                    || status.is_index_typechange()
            })
        };
        if !is_dirty || allow_uncommitted && !stash_uncommitted {
            return Ok(false);
        }
        if !stash_uncommitted {
            return Err(GitError::SyncDirtyWorktree);
        }
        let sig = repo
            .signature()
            .or_else(|_| Signature::now("resh", "resh@localhost"))
            .map_err(|e| GitError::SyncFailed {
                message: format!("failed to create a signature for the stash: {}", e),
            })?;
        repo.stash_save(
            &sig,
            "resh sync auto-stash",
            Some(git2::StashFlags::INCLUDE_UNTRACKED),
        )
        .map_err(|e| GitError::SyncFailed {
            message: format!("failed to stash the uncommitted changes: {}", e),
        })?;
        Ok(true)
    }

    /// Describes what sync would do (for dry-run).
    fn analyze_sync_actions(
        &self,
        remote: &str,
        local_branch: &str,
        remote_branch: &str,
        pull_strategy: &PullStrategy,
        push: bool,
        push_tags: bool,
    ) -> Vec<String> {
        let mut actions = vec![
            format!("Would fetch from {}/{}", remote, remote_branch),
            format!(
                "Would fast-forward '{}' to '{}/{}' if behind, and integrate diverged history with pull_strategy={} (a conflict fails without pushing)",
                local_branch,
                remote,
                remote_branch,
                pull_strategy_name(pull_strategy)
            ),
        ];
        if push {
            actions.push(format!(
                "Would push '{}' to {}/{}",
                local_branch, remote, remote_branch
            ));
            if push_tags {
                actions.push("Would push tags".to_string());
            }
        }
        actions
    }

    /// Fetches `<remote>/<branch>` and fast-forwards the local branch when
    /// it is behind. Returns the pull result (`status` "updated" or
    /// "up_to_date", `ahead_by`, `behind_by`).
    ///
    /// sync does not rebase or merge divergent history: when both sides
    /// have new commits it fails before anything is pushed, for every
    /// pull_strategy, instead of reporting an integration that never ran.
    async fn sync_fetch(
        &self,
        path: &str,
        remote: &str,
        branch: &str,
        pull_strategy: &PullStrategy,
        config: &SyncConfig,
    ) -> Result<Value, GitError> {
        let mut pull_value = json!({
            "path": path,
            "remote": remote,
            "branch": branch,
            "ff_only": *pull_strategy == PullStrategy::FfOnly,
            "rebase": *pull_strategy == PullStrategy::Rebase,
            "abort_on_conflict": config.abort_on_conflict.unwrap_or(true),
        });
        for (key, value) in [
            ("known_hosts_path", &config.known_hosts_path),
            ("author_name", &config.author_name),
            ("author_email", &config.author_email),
        ] {
            if let Some(v) = value {
                pull_value[key] = json!(v);
            }
        }

        self.pull(pull_value).await.map_err(|e| match e {
            GitError::PullNonFastForward => GitError::SyncNonFastForward,
            GitError::PullConflict { paths, in_progress } => {
                GitError::SyncConflict { paths, in_progress }
            }
            GitError::PullDirtyWorktree => GitError::SyncDirtyWorktree,
            GitError::RemoteNotFound { remote } => GitError::SyncRemoteNotFound { remote },
            e @ GitError::HostKeyVerificationFailed { .. } => e,
            other => GitError::SyncPullFailed {
                message: other.to_string(),
            },
        })
    }

    /// Pushes the branch (and tags when asked).
    async fn sync_push(
        &self,
        path: &str,
        remote: &str,
        local_branch: &str,
        push_tags: bool,
        force_push: bool,
        known_hosts_path: Option<&str>,
    ) -> Result<Value, GitError> {
        let mut push_value = json!({
            "path": path,
            "remote": remote,
            "branch": local_branch,
            "tags": push_tags,
            "force": force_push,
        });
        if let Some(kh) = known_hosts_path {
            push_value["known_hosts_path"] = json!(kh);
        }

        self.push(push_value).await.map_err(|e| match e {
            GitError::PushRejected { message } => GitError::SyncPushRejected { message },
            e @ GitError::HostKeyVerificationFailed { .. } => e,
            other => GitError::SyncPushFailed {
                message: other.to_string(),
            },
        })?;

        Ok(json!({
            "attempted": true,
            "status": "pushed",
            "force": force_push,
            "tags_pushed": push_tags
        }))
    }

    /// Pops the sync auto-stash. Returns true when it could not be applied
    /// cleanly (the stash is then kept, as `git stash pop` does).
    fn sync_restore_stash(&self, repo: &mut Repository) -> Result<bool, GitError> {
        // The fetch and integration ran through another handle: reload the
        // index from disk before applying the stash on top of it.
        if let Ok(mut index) = repo.index() {
            let _ = index.read(true);
        }
        match repo.stash_pop(0, None) {
            Ok(()) => Ok(false),
            Err(e) if e.code() == git2::ErrorCode::Conflict => Ok(true),
            Err(e) => Err(GitError::SyncStashApplyConflict {
                message: e.message().to_string(),
            }),
        }
    }

    /// Determine the focus branch (either from config or current HEAD)
    fn determine_focus_branch(
        &self,
        repo: &Repository,
        config_branch: &Option<String>,
    ) -> Result<(Option<String>, bool, Option<String>), GitError> {
        if let Some(branch_name) = config_branch {
            // Use specified branch
            let branch = repo
                .find_branch(branch_name, git2::BranchType::Local)
                .map_err(|_| GitError::StatusSummaryBranchNotFound {
                    name: branch_name.clone(),
                })?;

            let head_oid = branch.get().target().map(|oid| oid.to_string());
            Ok((Some(branch_name.clone()), false, head_oid))
        } else {
            // Use current HEAD
            match repo.head() {
                Ok(head_ref) => {
                    let head_oid = head_ref.target().map(|oid| oid.to_string());

                    if head_ref.is_branch() {
                        let branch_name = head_ref.shorthand().ok().map(|s| s.to_string());
                        Ok((branch_name, false, head_oid))
                    } else {
                        // Detached HEAD
                        Ok((None, true, head_oid))
                    }
                }
                Err(_) => {
                    // No commits yet (unborn branch)
                    Ok((Some("main".to_string()), false, None))
                }
            }
        }
    }

    /// Compute working tree status counts
    fn compute_working_tree_status(
        &self,
        repo: &Repository,
        config: &StatusSummaryConfig,
    ) -> Result<Value, GitError> {
        let mut opts = git2::StatusOptions::new();
        opts.include_ignored(config.include_ignored.unwrap_or(false));
        opts.include_untracked(config.include_untracked.unwrap_or(true));

        let statuses =
            repo.statuses(Some(&mut opts))
                .map_err(|e| GitError::StatusSummaryFailed {
                    message: format!("failed to get repository status: {}", e),
                })?;

        let mut staged_count = 0;
        let mut unstaged_count = 0;
        let mut untracked_count = 0;
        let mut ignored_count = 0;
        let mut conflicts_count = 0;

        for entry in statuses.iter() {
            let flags = entry.status();

            if flags.contains(GitStatus::CONFLICTED) {
                conflicts_count += 1;
            } else {
                // Check for staged changes
                if flags.intersects(
                    GitStatus::INDEX_NEW
                        | GitStatus::INDEX_MODIFIED
                        | GitStatus::INDEX_DELETED
                        | GitStatus::INDEX_RENAMED
                        | GitStatus::INDEX_TYPECHANGE,
                ) {
                    staged_count += 1;
                }

                // Check for unstaged changes
                if flags.intersects(
                    GitStatus::WT_MODIFIED
                        | GitStatus::WT_DELETED
                        | GitStatus::WT_TYPECHANGE
                        | GitStatus::WT_RENAMED,
                ) {
                    unstaged_count += 1;
                }

                // Check for untracked files
                if flags.contains(GitStatus::WT_NEW) {
                    untracked_count += 1;
                }

                // Check for ignored files
                if flags.contains(GitStatus::IGNORED) {
                    ignored_count += 1;
                }
            }
        }

        // Check for operations in progress
        let in_progress = self.detect_operations_in_progress(repo)?;

        // Determine if clean
        let include_untracked_in_clean = config.include_untracked.unwrap_or(true);
        let clean = staged_count == 0
            && unstaged_count == 0
            && conflicts_count == 0
            && (!include_untracked_in_clean || untracked_count == 0);

        Ok(json!({
            "clean": clean,
            "staged_count": staged_count,
            "unstaged_count": unstaged_count,
            "untracked_count": untracked_count,
            "ignored_count": ignored_count,
            "conflicts_count": conflicts_count,
            "in_progress": in_progress
        }))
    }

    /// Detect operations in progress (merge, rebase, etc.)
    fn detect_operations_in_progress(&self, repo: &Repository) -> Result<Value, GitError> {
        let git_dir = repo.path();

        let merge = git_dir.join("MERGE_HEAD").exists();
        let rebase = git_dir.join("rebase-merge").exists() || git_dir.join("rebase-apply").exists();
        let cherry_pick = git_dir.join("CHERRY_PICK_HEAD").exists();
        let revert = git_dir.join("REVERT_HEAD").exists();
        let bisect = git_dir.join("BISECT_LOG").exists();

        Ok(json!({
            "merge": merge,
            "rebase": rebase,
            "cherry_pick": cherry_pick,
            "revert": revert,
            "bisect": bisect
        }))
    }

    /// Compute upstream status and sync state
    fn compute_upstream_status(
        &self,
        repo: &Repository,
        branch_name: &Option<String>,
        config_remote: &Option<String>,
        head_commit_oid: Option<&String>,
    ) -> Result<(Option<Value>, String, usize, usize), GitError> {
        // If no commits, cannot have upstream
        if head_commit_oid.is_none() {
            return Ok((None, "no_upstream".to_string(), 0, 0));
        }

        let branch_name = match branch_name {
            Some(name) => name,
            None => return Ok((None, "no_upstream".to_string(), 0, 0)), // Detached HEAD
        };

        // Try to find upstream
        let upstream_ref = self.resolve_upstream_ref(repo, branch_name, config_remote)?;

        if let Some((upstream_name, upstream_oid)) = upstream_ref {
            let (ahead_by, behind_by) = match head_commit_oid {
                Some(oid) => {
                    let local_oid =
                        git2::Oid::from_str(oid).map_err(|e| GitError::StatusSummaryFailed {
                            message: format!("invalid head commit OID: {}", e),
                        })?;
                    repo.graph_ahead_behind(local_oid, upstream_oid)
                        .map_err(|e| GitError::StatusSummaryFailed {
                            message: format!("failed to compute ahead/behind: {}", e),
                        })?
                }
                // An unborn branch is behind by every upstream commit.
                None => {
                    let mut walk = repo.revwalk().map_err(|e| GitError::StatusSummaryFailed {
                        message: format!("failed to walk the upstream history: {}", e),
                    })?;
                    walk.push(upstream_oid)
                        .map_err(|e| GitError::StatusSummaryFailed {
                            message: format!("failed to walk the upstream history: {}", e),
                        })?;
                    (0, walk.count())
                }
            };

            let sync_state = match (ahead_by, behind_by) {
                (0, 0) => "in_sync",
                (a, 0) if a > 0 => "ahead_only",
                (0, b) if b > 0 => "behind_only",
                (a, b) if a > 0 && b > 0 => "diverged",
                _ => "unknown",
            }
            .to_string();

            let upstream_info = json!({
                "name": upstream_name,
                "remote": config_remote.as_ref().unwrap_or(&"origin".to_string()),
                "head": upstream_oid.to_string(),
                "ahead_by": ahead_by,
                "behind_by": behind_by,
                "sync_state": sync_state
            });

            Ok((Some(upstream_info), sync_state, ahead_by, behind_by))
        } else {
            Ok((None, "no_upstream".to_string(), 0, 0))
        }
    }

    /// Resolve upstream reference for a branch
    fn resolve_upstream_ref(
        &self,
        repo: &Repository,
        branch_name: &str,
        config_remote: &Option<String>,
    ) -> Result<Option<(String, git2::Oid)>, GitError> {
        // First try the configured upstream for the branch
        if let Ok(local_branch) = repo.find_branch(branch_name, git2::BranchType::Local) {
            if let Ok(upstream_branch) = local_branch.upstream() {
                if let Some(upstream_name) = upstream_branch.name()? {
                    if let Some(upstream_oid) = upstream_branch.get().target() {
                        return Ok(Some((upstream_name.to_string(), upstream_oid)));
                    }
                }
            }
        }

        // If no configured upstream, try to construct one
        let default_remote = "origin".to_string();
        let remote_name = config_remote.as_ref().unwrap_or(&default_remote);
        let upstream_ref_name = format!("refs/remotes/{}/{}", remote_name, branch_name);

        if let Ok(upstream_ref) = repo.find_reference(&upstream_ref_name) {
            if let Some(upstream_oid) = upstream_ref.target() {
                return Ok(Some((upstream_ref_name, upstream_oid)));
            }
        }

        Ok(None)
    }

    /// Compute optional diffstats
    fn compute_diffstats(&self, repo: &Repository, max_files: u32) -> Result<Value, GitError> {
        let head_commit =
            repo.head()?
                .peel_to_commit()
                .map_err(|e| GitError::StatusSummaryFailed {
                    message: format!("failed to get HEAD commit: {}", e),
                })?;

        let head_tree = head_commit
            .tree()
            .map_err(|e| GitError::StatusSummaryFailed {
                message: format!("failed to get HEAD tree: {}", e),
            })?;

        let diff = repo
            .diff_tree_to_workdir_with_index(Some(&head_tree), None)
            .map_err(|e| GitError::StatusSummaryFailed {
                message: format!("failed to create diff: {}", e),
            })?;

        let mut changed_files = 0;
        let mut insertions = 0;
        let mut deletions = 0;
        let mut truncated = false;

        diff.foreach(
            &mut |_delta, _progress| {
                changed_files += 1;
                if changed_files > max_files {
                    truncated = true;
                    return false; // Stop processing
                }
                true
            },
            None,
            Some(&mut |_delta, _hunk| true),
            Some(&mut |_delta, _hunk, line| {
                match line.origin() {
                    '+' => insertions += 1,
                    '-' => deletions += 1,
                    _ => {}
                }
                true
            }),
        )
        .map_err(|e| GitError::StatusSummaryFailed {
            message: format!("failed to process diff: {}", e),
        })?;

        Ok(json!({
            "enabled": true,
            "changed_files": std::cmp::min(changed_files, max_files),
            "insertions": insertions,
            "deletions": deletions,
            "truncated": truncated
        }))
    }

    /// Compute summary flags based on working tree and sync state
    fn compute_summary_flags(
        &self,
        working_tree: &Value,
        sync_state: &str,
    ) -> Result<Value, GitError> {
        let staged_count = working_tree["staged_count"].as_u64().unwrap_or(0);
        let unstaged_count = working_tree["unstaged_count"].as_u64().unwrap_or(0);
        let conflicts_count = working_tree["conflicts_count"].as_u64().unwrap_or(0);
        let untracked_count = working_tree["untracked_count"].as_u64().unwrap_or(0);
        let clean = working_tree["clean"].as_bool().unwrap_or(false);

        let has_uncommitted_changes =
            staged_count > 0 || unstaged_count > 0 || conflicts_count > 0 || untracked_count > 0;
        let can_commit = staged_count > 0 && conflicts_count == 0;
        let needs_pull = sync_state == "behind_only" || sync_state == "diverged";
        let needs_push = sync_state == "ahead_only" || sync_state == "diverged";
        let blocked_by_conflicts = conflicts_count > 0
            || working_tree["in_progress"]["merge"]
                .as_bool()
                .unwrap_or(false)
            || working_tree["in_progress"]["rebase"]
                .as_bool()
                .unwrap_or(false)
            || working_tree["in_progress"]["cherry_pick"]
                .as_bool()
                .unwrap_or(false)
            || working_tree["in_progress"]["revert"]
                .as_bool()
                .unwrap_or(false);

        // Derive overall state
        let state = if blocked_by_conflicts {
            "conflicts_present"
        } else if has_uncommitted_changes {
            "local_changes_only"
        } else if sync_state == "ahead_only" {
            "committed_but_ahead"
        } else if sync_state == "behind_only" {
            "behind_remote"
        } else if sync_state == "diverged" {
            "diverged"
        } else if sync_state == "no_upstream" {
            "no_upstream"
        } else if clean && sync_state == "in_sync" {
            "clean_and_synced"
        } else {
            "unknown"
        };

        Ok(json!({
            "state": state,
            "has_uncommitted_changes": has_uncommitted_changes,
            "can_commit": can_commit,
            "needs_pull": needs_pull,
            "needs_push": needs_push,
            "blocked_by_conflicts": blocked_by_conflicts
        }))
    }

    /// Compute recommendations based on summary and state
    fn compute_recommendations(
        &self,
        summary: &Value,
        _sync_state: &str,
        _working_tree: &Value,
    ) -> Result<Value, GitError> {
        let state = summary["state"].as_str().unwrap_or("unknown");
        let _blocked_by_conflicts = summary["blocked_by_conflicts"].as_bool().unwrap_or(false);
        let _has_uncommitted_changes = summary["has_uncommitted_changes"]
            .as_bool()
            .unwrap_or(false);

        let (primary_action, actions, description) = match state {
            "conflicts_present" => (
                "resolve_conflicts",
                vec!["resolve_conflicts", "continue_merge_or_rebase"],
                "Resolve conflicts before proceeding with other operations.",
            ),
            "local_changes_only" => (
                "commit",
                vec!["commit_changes", "sync_with_remote"],
                "Commit your local changes and sync with remote.",
            ),
            "committed_but_ahead" => (
                "push",
                vec!["push_branch"],
                "Push your commits to the remote repository.",
            ),
            "behind_remote" => (
                "pull",
                vec!["pull_or_sync"],
                "Pull the latest changes from remote.",
            ),
            "diverged" => (
                "sync",
                vec!["sync_with_remote"],
                "Sync to integrate remote changes with your local commits.",
            ),
            "no_upstream" => (
                "setup_upstream",
                vec!["set_upstream", "sync_with_remote"],
                "Configure upstream tracking for this branch.",
            ),
            "clean_and_synced" => ("none", vec![], "Repository is clean and synchronized."),
            _ => ("none", vec![], "Repository state analysis complete."),
        };

        Ok(json!({
            "primary_action": primary_action,
            "actions": actions,
            "description": description
        }))
    }

    /// Execute status summary operation
    async fn execute_status_summary(
        &self,
        config: &StatusSummaryConfig,
    ) -> Result<Value, GitError> {
        log::info!("Executing status summary for path: {}", config.path);

        // Open repository
        let repo = Repository::open(&config.path).map_err(|_e| GitError::RepositoryNotFound {
            path: config.path.clone(),
        })?;

        // Determine focus branch
        let (branch_name, branch_detached, head_commit_oid) =
            self.determine_focus_branch(&repo, &config.branch)?;

        // Get working tree status
        let working_tree = self.compute_working_tree_status(&repo, config)?;

        // Get upstream and sync info if requested
        let (upstream, sync_state, _ahead_by, _behind_by) = if config.include_remote.unwrap_or(true)
        {
            self.compute_upstream_status(
                &repo,
                &branch_name,
                &config.remote,
                head_commit_oid.as_ref(),
            )?
        } else {
            (None, "no_upstream".to_string(), 0, 0)
        };

        // Compute diffstats if requested
        let diffstats = if config.compute_diffstats.unwrap_or(false) && head_commit_oid.is_some() {
            Some(self.compute_diffstats(&repo, config.max_files.unwrap_or(500))?)
        } else {
            None
        };

        // Derive summary flags and state
        let summary = self.compute_summary_flags(&working_tree, &sync_state)?;

        // Compute recommendations
        let recommendation = self.compute_recommendations(&summary, &sync_state, &working_tree)?;

        // Build response
        Ok(json!({
            "backend": "git",
            "alias": self.alias,
            "path": config.path,
            "action": "status_summary",
            "branch": {
                "name": branch_name,
                "detached": branch_detached,
                "head": head_commit_oid,
                "has_commits": head_commit_oid.is_some(),
                "upstream": upstream
            },
            "working_tree": working_tree,
            "diffstats": diffstats,
            "summary": summary,
            "recommendation": recommendation
        }))
    }

    /// Status summary verb implementation - provides comprehensive repository state analysis
    pub async fn status_summary(&self, args: Value) -> Result<Value, GitError> {
        let config = self.parse_status_summary_config(args)?;
        self.validate_status_summary_config(&config)?;
        self.execute_status_summary(&config).await
    }

    /// Status short verb implementation - single compact string for shell prompts
    pub async fn status_short(&self, args: Value) -> Result<Value, GitError> {
        let config = self.parse_status_short_config(args)?;
        self.validate_status_short_config(&config)?;
        self.execute_status_short(&config).await
    }

    /// Parse status_short configuration from arguments
    fn parse_status_short_config(&self, args: Value) -> Result<StatusShortConfig, GitError> {
        crate::core::lenient::from_value(args).map_err(|e| GitError::InvalidStatusShortConfig {
            message: format!("failed to parse status_short config: {}", e),
        })
    }

    /// Validate status_short configuration
    fn validate_status_short_config(&self, config: &StatusShortConfig) -> Result<(), GitError> {
        if config.path.is_empty() {
            return Err(GitError::InvalidStatusShortConfig {
                message: "path cannot be empty".to_string(),
            });
        }

        if let Some(timeout_ms) = config.timeout_ms {
            if timeout_ms == 0 {
                return Err(GitError::InvalidStatusShortConfig {
                    message: "timeout_ms must be greater than 0".to_string(),
                });
            }
        }

        if let Some(ref branch) = config.branch {
            if branch.is_empty() {
                return Err(GitError::InvalidStatusShortConfig {
                    message: "branch cannot be empty string".to_string(),
                });
            }
        }

        if let Some(ref remote) = config.remote {
            if remote.is_empty() {
                return Err(GitError::InvalidStatusShortConfig {
                    message: "remote cannot be empty string".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Execute status_short operation
    async fn execute_status_short(&self, config: &StatusShortConfig) -> Result<Value, GitError> {
        let repo = Repository::open(&config.path).map_err(|_| GitError::RepositoryNotFound {
            path: config.path.clone(),
        })?;

        // Resolve symbols with defaults
        let symbols = self.resolve_status_short_symbols(&config.symbols);

        // Determine focus branch and detached state
        let (branch_name, detached, head_oid) = self.resolve_head_state(&repo, &config.branch)?;

        // Compute local status
        let (clean, has_conflicts) = self.compute_local_status(&repo, config)?;

        // Compute remote status if requested
        let (ahead, behind, has_upstream) = if config.include_remote.unwrap_or(true) {
            self.compute_remote_status(&repo, &branch_name, &config.remote, head_oid, detached)?
        } else {
            (0, 0, false)
        };

        // Build summary string
        let summary = self.build_summary_string(
            &branch_name,
            detached,
            ahead,
            behind,
            has_upstream,
            clean,
            has_conflicts,
            &symbols,
            config,
        );

        // Build response
        Ok(json!({
            "backend": "git",
            "alias": self.alias,
            "path": config.path,
            "action": "status_short",
            "summary": summary,
            "components": {
                "branch": branch_name,
                "detached": detached,
                "ahead": ahead,
                "behind": behind,
                "has_upstream": has_upstream,
                "clean": clean,
                "has_conflicts": has_conflicts
            }
        }))
    }

    /// Resolve symbols with defaults
    fn resolve_status_short_symbols(
        &self,
        symbols: &Option<StatusShortSymbols>,
    ) -> StatusShortSymbols {
        let defaults = StatusShortSymbols {
            detached: Some("!".to_string()),
            ahead: Some("↑".to_string()),
            behind: Some("↓".to_string()),
            dirty: Some("*".to_string()),
            conflict: Some("✖".to_string()),
            no_upstream: Some("·".to_string()),
        };

        match symbols {
            None => defaults,
            Some(custom) => StatusShortSymbols {
                detached: custom.detached.clone().or(defaults.detached),
                ahead: custom.ahead.clone().or(defaults.ahead),
                behind: custom.behind.clone().or(defaults.behind),
                dirty: custom.dirty.clone().or(defaults.dirty),
                conflict: custom.conflict.clone().or(defaults.conflict),
                no_upstream: custom.no_upstream.clone().or(defaults.no_upstream),
            },
        }
    }

    /// Resolve HEAD state - branch name, detached status, and commit OID
    fn resolve_head_state(
        &self,
        repo: &Repository,
        branch_override: &Option<String>,
    ) -> Result<(String, bool, Oid), GitError> {
        match branch_override {
            Some(branch_name) => {
                // Use specified branch
                let branch = repo
                    .find_branch(branch_name, BranchType::Local)
                    .map_err(|_| GitError::StatusShortBranchNotFound {
                        branch: branch_name.clone(),
                    })?;

                let target = branch
                    .get()
                    .target()
                    .ok_or_else(|| GitError::StatusShortFailed {
                        message: "branch has no target commit".to_string(),
                    })?;

                Ok((branch_name.clone(), false, target))
            }
            None => {
                // Use current HEAD
                let head = repo.head().map_err(|e| GitError::StatusShortFailed {
                    message: format!("failed to get HEAD: {}", e),
                })?;

                if head.is_branch() {
                    let branch_name = head
                        .shorthand()
                        .ok()
                        .ok_or_else(|| GitError::StatusShortFailed {
                            message: "failed to get branch name".to_string(),
                        })?
                        .to_string();

                    let target = head.target().ok_or_else(|| GitError::StatusShortFailed {
                        message: "HEAD has no target commit".to_string(),
                    })?;

                    Ok((branch_name, false, target))
                } else {
                    // Detached HEAD
                    let target = head.target().ok_or_else(|| GitError::StatusShortFailed {
                        message: "detached HEAD has no target commit".to_string(),
                    })?;

                    // Use short hash or "HEAD"
                    let short_name = format!("{:.7}", target);
                    Ok((short_name, true, target))
                }
            }
        }
    }

    /// Compute local status - clean/dirty and conflicts
    fn compute_local_status(
        &self,
        repo: &Repository,
        config: &StatusShortConfig,
    ) -> Result<(bool, bool), GitError> {
        let include_dirty = config.include_dirty.unwrap_or(true);
        let include_conflicts = config.include_conflicts.unwrap_or(true);

        if !include_dirty && !include_conflicts {
            return Ok((true, false)); // Assume clean if not checking
        }

        let statuses = repo
            .statuses(None)
            .map_err(|e| GitError::StatusShortFailed {
                message: format!("failed to get repository status: {}", e),
            })?;

        let mut clean = true;
        let mut has_conflicts = false;

        for status_entry in statuses.iter() {
            let status = status_entry.status();

            if include_conflicts && status.contains(GitStatus::CONFLICTED) {
                has_conflicts = true;
            }

            if include_dirty && (!status.is_empty() && !status.contains(GitStatus::IGNORED)) {
                clean = false;
            }

            // Early exit if we have both answers
            if (!include_dirty || !clean) && (!include_conflicts || has_conflicts) {
                break;
            }
        }

        Ok((clean, has_conflicts))
    }

    /// Compute remote status - ahead/behind counts and upstream existence
    fn compute_remote_status(
        &self,
        repo: &Repository,
        branch_name: &str,
        remote_override: &Option<String>,
        local_oid: Oid,
        detached: bool,
    ) -> Result<(usize, usize, bool), GitError> {
        // Try to find upstream reference
        let upstream_ref = self.find_upstream_ref(repo, branch_name, remote_override, detached)?;

        match upstream_ref {
            Some(upstream_oid) => {
                let (ahead, behind) =
                    repo.graph_ahead_behind(local_oid, upstream_oid)
                        .map_err(|e| GitError::StatusShortFailed {
                            message: format!("failed to compute ahead/behind: {}", e),
                        })?;

                Ok((ahead, behind, true))
            }
            None => Ok((0, 0, false)),
        }
    }

    /// Find upstream reference OID
    fn find_upstream_ref(
        &self,
        repo: &Repository,
        branch_name: &str,
        remote_override: &Option<String>,
        detached: bool,
    ) -> Result<Option<Oid>, GitError> {
        if detached {
            // For detached HEAD, no upstream tracking
            return Ok(None);
        }

        // Try branch's configured upstream first
        if let Ok(branch) = repo.find_branch(branch_name, BranchType::Local) {
            if let Ok(upstream_branch) = branch.upstream() {
                if let Some(target) = upstream_branch.get().target() {
                    return Ok(Some(target));
                }
            }
        }

        // Try specified remote
        let remote_name = remote_override.as_deref().unwrap_or("origin");
        let upstream_ref_name = format!("refs/remotes/{}/{}", remote_name, branch_name);

        if let Ok(upstream_ref) = repo.find_reference(&upstream_ref_name) {
            if let Some(target) = upstream_ref.target() {
                return Ok(Some(target));
            }
        }

        Ok(None)
    }

    /// Build summary string following the specified format
    fn build_summary_string(
        &self,
        branch_name: &str,
        detached: bool,
        ahead: usize,
        behind: usize,
        has_upstream: bool,
        clean: bool,
        has_conflicts: bool,
        symbols: &StatusShortSymbols,
        config: &StatusShortConfig,
    ) -> String {
        let mut summary = String::new();

        // 1. Branch name or detached indicator
        summary.push_str(branch_name);
        if detached {
            if let Some(ref detached_symbol) = symbols.detached {
                summary.push_str(detached_symbol);
            }
        }

        // 2. Remote part (arrows)
        if config.include_remote.unwrap_or(true) {
            if has_upstream {
                if ahead > 0 {
                    if let Some(ref ahead_symbol) = symbols.ahead {
                        summary.push_str(ahead_symbol);
                        summary.push_str(&ahead.to_string());
                    }
                }
                if behind > 0 {
                    if let Some(ref behind_symbol) = symbols.behind {
                        summary.push_str(behind_symbol);
                        summary.push_str(&behind.to_string());
                    }
                }
            } else {
                // No upstream - show no_upstream symbol
                if let Some(ref no_upstream_symbol) = symbols.no_upstream {
                    summary.push_str(no_upstream_symbol);
                }
            }
        }

        // 3. Dirty part
        if config.include_dirty.unwrap_or(true) && !clean {
            if let Some(ref dirty_symbol) = symbols.dirty {
                summary.push_str(dirty_symbol);
            }
        }

        // 4. Conflict part
        if config.include_conflicts.unwrap_or(true) && has_conflicts {
            if let Some(ref conflict_symbol) = symbols.conflict {
                summary.push_str(conflict_symbol);
            }
        }

        summary
    }
}

impl Handle for GitHandle {
    fn verbs(&self) -> &'static [&'static str] {
        GIT_VERBS
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&GIT_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // In-URL help forms: help=<verb>, --help[=<verb>], -h, or a help verb.
        let help_arg = ["help", "--help", "-h"].iter().find_map(|k| args.get(*k));
        if help_arg.is_some() || is_git_help_word(verb) {
            let wanted = help_arg.map(|v| v.as_str()).filter(|v| !v.is_empty());
            write!(io.stdout, "{}", git_help_text(wanted))?;
            return Ok(Status::success());
        }

        let result = self.dispatch(verb, args);
        match result {
            Ok(value) => {
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&value)?)?;
                io.stdout.flush()?;
                Ok(Status::success())
            }
            Err(err) => {
                let code = err.code();
                let message = err.to_string();
                writeln!(
                    io.stderr,
                    "{}",
                    crate::core::status::error_line(&code, &message)
                )?;
                Ok(Status::coded(err.exit_code(), &code, message))
            }
        }
    }
}

/// Time a stopped operation gets to wind down after its deadline before it
/// is reported as still running.
const STOP_GRACE: Duration = Duration::from_secs(3);

impl GitHandle {
    /// Checks the arguments of `verb` and runs it on a worker thread under
    /// its deadline (`timeout_ms`, or the network default for clone, pull,
    /// push and sync).
    fn dispatch(&self, verb: &str, args: &Args) -> Result<Value, GitError> {
        if args::options_for(verb).is_none() {
            let hint = args::suggest(verb, GIT_VERBS)
                .map(|s| format!(" (did you mean {s:?}?)"))
                .unwrap_or_default();
            return Err(GitError::InvalidVerb {
                message: format!(
                    "unknown verb {verb:?} for git://{hint}; verbs: {}",
                    GIT_VERBS.join(", ")
                ),
            });
        }
        args::check_known(verb, &mut args.keys().map(String::as_str))
            .map_err(|m| GitError::invalid_for(verb, m))?;
        let timeout_ms = args::timeout_ms(args.get("timeout_ms").map(String::as_str))
            .map_err(|m| GitError::invalid_for(verb, m))?;
        let limit = timeout_ms.map(Duration::from_millis).or_else(|| {
            args::NETWORK_VERBS
                .contains(&verb)
                .then_some(args::NETWORK_DEFAULT_TIMEOUT)
        });
        let args_value = serde_json::to_value(args)
            .map_err(|e| GitError::invalid_for(verb, format!("cannot read arguments: {e}")))?;

        let started = Instant::now();
        let deadline = limit.map(|l| started + l);
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = GitHandle {
            alias: self.alias.clone(),
        };
        let verb_name = verb.to_string();
        std::thread::Builder::new()
            .name(format!("git-{verb}"))
            .spawn(move || {
                net::set_deadline(deadline);
                let result = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt.block_on(worker.run_verb(&verb_name, args_value)),
                    Err(e) => Err(GitError::failed_for(
                        &verb_name,
                        format!("cannot start the operation: {e}"),
                    )),
                };
                let _ = tx.send(result);
            })
            .map_err(|e| GitError::failed_for(verb, format!("cannot start the operation: {e}")))?;

        let timed_out = |still_running: bool| GitError::Timeout {
            verb: verb.to_string(),
            timeout_ms: limit.map_or(0, |l| l.as_millis() as u64),
            still_running,
        };
        let result = match deadline {
            None => rx.recv().map_err(|_| {
                GitError::failed_for(verb, "the operation ended unexpectedly".to_string())
            })?,
            Some(d) => {
                let wait = d.saturating_duration_since(Instant::now()) + STOP_GRACE;
                match rx.recv_timeout(wait) {
                    Ok(r) => r,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        return Err(timed_out(true));
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(GitError::failed_for(
                            verb,
                            "the operation ended unexpectedly".to_string(),
                        ));
                    }
                }
            }
        };
        match result {
            // A failure once the deadline has passed is the deadline's doing:
            // the callbacks and libgit2's timeouts stop the operation there.
            Err(e) if deadline.is_some_and(|d| Instant::now() >= d) && e.exit_code() != 2 => {
                log::debug!("git {verb} stopped at its deadline: {e}");
                Err(timed_out(false))
            }
            other => other,
        }
    }
}

/// A name and email for a new commit: the arguments first, then
/// `GIT_<role>_NAME` / `GIT_<role>_EMAIL`, then `user.name` / `user.email`
/// from the repository configuration (which includes the global one).
fn identity(
    repo: &Repository,
    name: Option<&str>,
    email: Option<&str>,
    role: &str,
) -> Option<(String, String)> {
    let cfg = repo.config().ok();
    let from_cfg = |key: &str| cfg.as_ref().and_then(|c| c.get_string(key).ok());
    let name = name
        .map(str::to_string)
        .or_else(|| std::env::var(format!("GIT_{role}_NAME")).ok())
        .or_else(|| from_cfg("user.name"))?;
    let email = email
        .map(str::to_string)
        .or_else(|| std::env::var(format!("GIT_{role}_EMAIL")).ok())
        .or_else(|| from_cfg("user.email"))?;
    Some((name, email))
}

/// The message of a pull or sync conflict.
fn conflict_message(verb: &str, paths: &[String], in_progress: bool) -> String {
    let list = if paths.is_empty() {
        "(unknown paths)".to_string()
    } else {
        paths.join(", ")
    };
    if in_progress {
        format!(
            "{verb} stopped on conflicts in {list}; the merge or rebase is left in progress: \
             resolve the files and commit (merge) or use the rebase verb with \
             operation=continue or operation=abort"
        )
    } else {
        format!(
            "{verb} stopped on conflicts in {list}; the repository was restored to its previous \
             state and nothing was pushed"
        )
    }
}

/// URL schemes `clone` accepts.
const CLONE_SCHEMES: &[&str] = &["https", "http", "ssh", "git+ssh", "ssh+git", "git", "file"];

/// Checks a clone URL: a URL with a supported scheme, the scp-like
/// `[user@]host:path` SSH form, or the path of an existing local
/// directory. Anything else is refused before anything is created.
fn check_clone_url(url: &str) -> Result<(), String> {
    if url.starts_with('-') {
        return Err(format!("url {url:?} must not start with '-'"));
    }
    if url.chars().any(char::is_control) {
        return Err(format!("url {url:?} contains a control character"));
    }
    if let Some(idx) = url.find("://") {
        let scheme = url[..idx].to_ascii_lowercase();
        if !CLONE_SCHEMES.contains(&scheme.as_str()) {
            return Err(format!(
                "unsupported url scheme '{scheme}'; supported: {}, scp-like user@host:path, or a \
                 local repository path",
                CLONE_SCHEMES
                    .iter()
                    .map(|s| format!("{s}://"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if url.len() == idx + 3 {
            return Err(format!("url {url:?} has nothing after '://'"));
        }
        return Ok(());
    }
    if known_hosts::ssh_endpoint(url).is_some() {
        return Ok(());
    }
    if Path::new(url).is_dir() {
        return Ok(());
    }
    Err(format!(
        "url {url:?} is neither a supported URL nor an existing local repository directory"
    ))
}

/// Opens the repository at `path`: `git.repository_not_found` when there
/// is none, otherwise `failed(message)`.
fn open_repo(
    path: &Path,
    display: &str,
    failed: impl Fn(String) -> GitError,
) -> Result<Repository, GitError> {
    Repository::open(path).map_err(|e| {
        if e.code() == git2::ErrorCode::NotFound {
            GitError::RepositoryNotFound {
                path: display.to_string(),
            }
        } else {
            failed(format!("failed to open repository: {}", e.message()))
        }
    })
}

/// Creates the missing ancestors of `path` (not `path` itself) and returns
/// the directories it created, outermost first.
fn create_missing_parents(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut missing = Vec::new();
    let mut cur = path.parent();
    while let Some(dir) = cur {
        if dir.as_os_str().is_empty() || dir.exists() {
            break;
        }
        missing.push(dir.to_path_buf());
        cur = dir.parent();
    }
    missing.reverse();
    for dir in &missing {
        std::fs::create_dir(dir)?;
    }
    Ok(missing)
}

/// Fetches `remote_name` with its configured refspecs, under the calling
/// thread's deadline, with `creds` and strict host-key checking when
/// `known_hosts_path` is given. Errors are built with `fail(message,
/// is_auth)`, except host-key refusals and a missing remote.
fn fetch_remote(
    repo: &Repository,
    remote_name: &str,
    creds: &net::Credentials,
    known_hosts_path: Option<&str>,
    prune: bool,
    fail: impl Fn(String, bool) -> GitError,
) -> Result<(), GitError> {
    let mut remote = repo
        .find_remote(remote_name)
        .map_err(|_| GitError::RemoteNotFound {
            remote: remote_name.to_string(),
        })?;
    let policy = net::HostKeyPolicy::new(known_hosts_path);
    let mut callbacks = RemoteCallbacks::new();
    creds.install(&mut callbacks);
    policy.install(&mut callbacks);
    // The fetch URL after url.<base>.insteadOf rewriting (libgit2 applies it
    // when it reads the remote).
    policy.prepare(remote.url().unwrap_or_default())?;
    let mut fetch_options = FetchOptions::new();
    fetch_options.remote_callbacks(callbacks);
    if prune {
        fetch_options.prune(git2::FetchPrune::On);
    }
    let refspecs = remote
        .fetch_refspecs()
        .map_err(|e| fail(format!("failed to read refspecs: {}", e.message()), false))?;
    let refspecs: Vec<String> = refspecs
        .iter()
        .filter_map(|r| r.ok().flatten())
        .map(str::to_string)
        .collect();
    let _timeouts = net::apply_server_timeouts(remote.url().unwrap_or_default());
    remote
        .fetch(&refspecs, Some(&mut fetch_options), None)
        .map_err(|e| {
            if let Some(err) = policy.explain(&e) {
                return err;
            }
            fail(
                format!("fetch failed: {}", e.message()),
                net::is_auth_error(&e),
            )
        })
}

/// Register git:// scheme with the registry
pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("git", |u| Ok(Box::new(GitHandle::from_url(u.clone())?)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // Helper to create test arguments
    #[test]
    fn test_git_handle_from_url() {
        let url = Url::parse("git://main").unwrap();
        println!("Parsed URL: {:?}, path: {:?}", url, url.path());
        let handle = GitHandle::from_url(url).unwrap();
        assert_eq!(handle.alias, "main");

        let url = Url::parse("git://deploy_bot").unwrap();
        println!("Parsed URL: {:?}, path: {:?}", url, url.path());
        let handle = GitHandle::from_url(url).unwrap();
        assert_eq!(handle.alias, "deploy_bot");

        // For a URL like git:// with no host or path, we should get default
        let url = Url::parse("git:///").unwrap();
        println!("Parsed URL: {:?}, path: {:?}", url, url.path());
        let handle = GitHandle::from_url(url).unwrap();
        assert_eq!(handle.alias, "default");

        // For a path-based alias
        let url = Url::parse("git:///my_alias").unwrap();
        println!("Parsed URL: {:?}, path: {:?}", url, url.path());
        let handle = GitHandle::from_url(url).unwrap();
        assert_eq!(handle.alias, "my_alias");
    }

    #[test]
    fn test_invalid_url() {
        let url = Url::parse("git:///").unwrap();
        let handle = GitHandle::from_url(url).unwrap();
        assert_eq!(handle.alias, "default");
    }

    #[test]
    fn test_clone_config_validation() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // Valid configuration
        let config = CloneConfig {
            url: "https://github.com/test/repo.git".to_string(),
            path: "/tmp/test".to_string(),
            branch: None,
            depth: None,
            recursive: None,
            ssh_key: None,
            known_hosts_path: None,
            username: None,
            password: None,
            token: None,
            timeout_ms: None,
        };
        assert!(handle.validate_clone_config(&config).is_ok());

        // Empty URL
        let mut config = config.clone();
        config.url = "".to_string();
        assert!(matches!(
            handle.validate_clone_config(&config),
            Err(GitError::InvalidCloneConfig { .. })
        ));

        // Empty path
        let config = CloneConfig {
            url: "https://github.com/test/repo.git".to_string(),
            path: "".to_string(),
            branch: None,
            depth: None,
            recursive: None,
            ssh_key: None,
            known_hosts_path: None,
            username: None,
            password: None,
            token: None,
            timeout_ms: None,
        };
        assert!(matches!(
            handle.validate_clone_config(&config),
            Err(GitError::InvalidCloneConfig { .. })
        ));

        // Invalid depth
        let config = CloneConfig {
            url: "https://github.com/test/repo.git".to_string(),
            path: "/tmp/test".to_string(),
            branch: None,
            depth: Some(0),
            recursive: None,
            ssh_key: None,
            known_hosts_path: None,
            username: None,
            password: None,
            token: None,
            timeout_ms: None,
        };
        assert!(matches!(
            handle.validate_clone_config(&config),
            Err(GitError::InvalidCloneConfig { .. })
        ));

        // Invalid timeout
        let config = CloneConfig {
            url: "https://github.com/test/repo.git".to_string(),
            path: "/tmp/test".to_string(),
            branch: None,
            depth: None,
            recursive: None,
            ssh_key: None,
            known_hosts_path: None,
            username: None,
            password: None,
            token: None,
            timeout_ms: Some(0),
        };
        assert!(matches!(
            handle.validate_clone_config(&config),
            Err(GitError::InvalidCloneConfig { .. })
        ));

        // Multiple auth methods
        let config = CloneConfig {
            url: "https://github.com/test/repo.git".to_string(),
            path: "/tmp/test".to_string(),
            branch: None,
            depth: None,
            recursive: None,
            ssh_key: Some("key".to_string()),
            known_hosts_path: None,
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            token: None,
            timeout_ms: None,
        };
        assert!(matches!(
            handle.validate_clone_config(&config),
            Err(GitError::InvalidCloneConfig { .. })
        ));

        // Invalid URL protocol
        let config = CloneConfig {
            url: "ftp://invalid.git".to_string(),
            path: "/tmp/test".to_string(),
            branch: None,
            depth: None,
            recursive: None,
            ssh_key: None,
            known_hosts_path: None,
            username: None,
            password: None,
            token: None,
            timeout_ms: None,
        };
        assert!(matches!(
            handle.validate_clone_config(&config),
            Err(GitError::InvalidCloneConfig { .. })
        ));
    }

    #[test]
    fn test_clone_config_parsing() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        let args = json!({
            "url": "https://github.com/test/repo.git",
            "path": "/tmp/test",
            "branch": "main",
            "depth": 1,
            "recursive": true,
            "timeout_ms": 30000
        });

        let config = handle.parse_clone_config(args).unwrap();
        assert_eq!(config.url, "https://github.com/test/repo.git");
        assert_eq!(config.path, "/tmp/test");
        assert_eq!(config.branch, Some("main".to_string()));
        assert_eq!(config.depth, Some(1));
        assert_eq!(config.recursive, Some(true));
        assert_eq!(config.timeout_ms, Some(30000));
    }

    #[test]
    fn test_auth_validation_single_methods() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // SSH key only
        let config = CloneConfig {
            url: "git@github.com:test/repo.git".to_string(),
            path: "/tmp/test".to_string(),
            branch: None,
            depth: None,
            recursive: None,
            ssh_key: Some("/path/to/key".to_string()),
            known_hosts_path: None,
            username: None,
            password: None,
            token: None,
            timeout_ms: None,
        };
        assert!(handle.validate_clone_config(&config).is_ok());

        // Username/password only
        let config = CloneConfig {
            url: "https://github.com/test/repo.git".to_string(),
            path: "/tmp/test".to_string(),
            branch: None,
            depth: None,
            recursive: None,
            ssh_key: None,
            known_hosts_path: None,
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            token: None,
            timeout_ms: None,
        };
        assert!(handle.validate_clone_config(&config).is_ok());

        // Token only
        let config = CloneConfig {
            url: "https://github.com/test/repo.git".to_string(),
            path: "/tmp/test".to_string(),
            branch: None,
            depth: None,
            recursive: None,
            ssh_key: None,
            known_hosts_path: None,
            username: None,
            password: None,
            token: Some("token123".to_string()),
            timeout_ms: None,
        };
        assert!(handle.validate_clone_config(&config).is_ok());
    }

    #[test]
    fn test_pull_config_validation() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // Valid configuration
        let config = PullConfig {
            path: "/tmp/test".to_string(),
            remote: None,
            branch: None,
            rebase: None,
            ff_only: None,
            abort_on_conflict: None,
            author_name: None,
            author_email: None,
            prune: None,
            ssh_key: None,
            known_hosts_path: None,
            username: None,
            password: None,
            token: None,
            timeout_ms: None,
        };
        // Note: This will fail because path doesn't exist - that's expected for this validation test
        let result = handle.validate_pull_config(&config);
        assert!(matches!(result, Err(GitError::RepositoryNotFound { .. })));

        // Empty path
        let mut config = config.clone();
        config.path = "".to_string();
        assert!(matches!(
            handle.validate_pull_config(&config),
            Err(GitError::InvalidPullConfig { .. })
        ));

        // Invalid timeout
        let config = PullConfig {
            path: "/tmp/test".to_string(),
            remote: None,
            branch: None,
            rebase: None,
            ff_only: None,
            abort_on_conflict: None,
            author_name: None,
            author_email: None,
            prune: None,
            ssh_key: None,
            known_hosts_path: None,
            username: None,
            password: None,
            token: None,
            timeout_ms: Some(0),
        };
        assert!(matches!(
            handle.validate_pull_config(&config),
            Err(GitError::InvalidPullConfig { .. })
        ));

        // Empty remote string
        let config = PullConfig {
            path: "/tmp/test".to_string(),
            remote: Some("".to_string()),
            branch: None,
            rebase: None,
            ff_only: None,
            abort_on_conflict: None,
            author_name: None,
            author_email: None,
            prune: None,
            ssh_key: None,
            known_hosts_path: None,
            username: None,
            password: None,
            token: None,
            timeout_ms: None,
        };
        assert!(matches!(
            handle.validate_pull_config(&config),
            Err(GitError::InvalidPullConfig { .. })
        ));

        // Empty branch string
        let config = PullConfig {
            path: "/tmp/test".to_string(),
            remote: None,
            branch: Some("".to_string()),
            rebase: None,
            ff_only: None,
            abort_on_conflict: None,
            author_name: None,
            author_email: None,
            prune: None,
            ssh_key: None,
            known_hosts_path: None,
            username: None,
            password: None,
            token: None,
            timeout_ms: None,
        };
        assert!(matches!(
            handle.validate_pull_config(&config),
            Err(GitError::InvalidPullConfig { .. })
        ));

        // Multiple auth methods
        let config = PullConfig {
            path: "/tmp/test".to_string(),
            remote: None,
            branch: None,
            rebase: None,
            ff_only: None,
            abort_on_conflict: None,
            author_name: None,
            author_email: None,
            prune: None,
            ssh_key: Some("key".to_string()),
            known_hosts_path: None,
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            token: None,
            timeout_ms: None,
        };
        assert!(matches!(
            handle.validate_pull_config(&config),
            Err(GitError::InvalidPullConfig { .. })
        ));
    }

    #[test]
    fn test_pull_config_parsing() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        let args = json!({
            "path": "/tmp/test",
            "remote": "origin",
            "branch": "main",
            "rebase": true,
            "ff_only": false,
            "depth": 5,
            "prune": true,
            "timeout_ms": 30000
        });

        let config = handle.parse_pull_config(args).unwrap();
        assert_eq!(config.path, "/tmp/test");
        assert_eq!(config.remote, Some("origin".to_string()));
        assert_eq!(config.branch, Some("main".to_string()));
        assert_eq!(config.rebase, Some(true));
        assert_eq!(config.ff_only, Some(false));
        assert_eq!(config.prune, Some(true));
        assert_eq!(config.timeout_ms, Some(30000));
    }

    #[test]
    fn test_pull_auth_validation_single_methods() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // SSH key only
        let config = PullConfig {
            path: "/tmp/test".to_string(),
            remote: None,
            branch: None,
            rebase: None,
            ff_only: None,
            abort_on_conflict: None,
            author_name: None,
            author_email: None,
            prune: None,
            ssh_key: Some("/path/to/key".to_string()),
            known_hosts_path: None,
            username: None,
            password: None,
            token: None,
            timeout_ms: None,
        };
        let result = handle.validate_pull_config(&config);
        // Should fail due to path not existing, not auth validation
        assert!(matches!(result, Err(GitError::RepositoryNotFound { .. })));

        // Username/password only
        let config = PullConfig {
            path: "/tmp/test".to_string(),
            remote: None,
            branch: None,
            rebase: None,
            ff_only: None,
            abort_on_conflict: None,
            author_name: None,
            author_email: None,
            prune: None,
            ssh_key: None,
            known_hosts_path: None,
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            token: None,
            timeout_ms: None,
        };
        let result = handle.validate_pull_config(&config);
        assert!(matches!(result, Err(GitError::RepositoryNotFound { .. })));

        // Token only
        let config = PullConfig {
            path: "/tmp/test".to_string(),
            remote: None,
            branch: None,
            rebase: None,
            ff_only: None,
            abort_on_conflict: None,
            author_name: None,
            author_email: None,
            prune: None,
            ssh_key: None,
            known_hosts_path: None,
            username: None,
            password: None,
            token: Some("token123".to_string()),
            timeout_ms: None,
        };
        let result = handle.validate_pull_config(&config);
        assert!(matches!(result, Err(GitError::RepositoryNotFound { .. })));
    }

    #[test]
    fn test_push_config_validation() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // Valid configuration
        let config = PushConfig {
            path: "/tmp/test".to_string(),
            remote: None,
            branch: None,
            branches: None,
            tags: None,
            force: None,
            ff_only: None,
            set_upstream: None,
            ssh_key: None,
            known_hosts_path: None,
            username: None,
            password: None,
            token: None,
            timeout_ms: None,
        };
        // Note: This will fail because path doesn't exist - that's expected for this validation test
        let result = handle.validate_push_config(&config);
        assert!(matches!(result, Err(GitError::RepositoryNotFound { .. })));

        // Empty path
        let mut config = config.clone();
        config.path = "".to_string();
        assert!(matches!(
            handle.validate_push_config(&config),
            Err(GitError::InvalidPushConfig { .. })
        ));

        // Invalid timeout
        let config = PushConfig {
            path: "/tmp/test".to_string(),
            remote: None,
            branch: None,
            branches: None,
            tags: None,
            force: None,
            ff_only: None,
            set_upstream: None,
            ssh_key: None,
            known_hosts_path: None,
            username: None,
            password: None,
            token: None,
            timeout_ms: Some(0),
        };
        assert!(matches!(
            handle.validate_push_config(&config),
            Err(GitError::InvalidPushConfig { .. })
        ));

        // Both branch and branches provided
        let config = PushConfig {
            path: "/tmp/test".to_string(),
            remote: None,
            branch: Some("main".to_string()),
            branches: Some(vec!["main".to_string(), "develop".to_string()]),
            tags: None,
            force: None,
            ff_only: None,
            set_upstream: None,
            ssh_key: None,
            known_hosts_path: None,
            username: None,
            password: None,
            token: None,
            timeout_ms: None,
        };
        assert!(matches!(
            handle.validate_push_config(&config),
            Err(GitError::InvalidPushConfig { .. })
        ));

        // Empty branches array
        let config = PushConfig {
            path: "/tmp/test".to_string(),
            remote: None,
            branch: None,
            branches: Some(vec![]),
            tags: None,
            force: None,
            ff_only: None,
            set_upstream: None,
            ssh_key: None,
            known_hosts_path: None,
            username: None,
            password: None,
            token: None,
            timeout_ms: None,
        };
        assert!(matches!(
            handle.validate_push_config(&config),
            Err(GitError::InvalidPushConfig { .. })
        ));

        // force and ff_only both true
        let config = PushConfig {
            path: "/tmp/test".to_string(),
            remote: None,
            branch: None,
            branches: None,
            tags: None,
            force: Some(true),
            ff_only: Some(true),
            set_upstream: None,
            ssh_key: None,
            known_hosts_path: None,
            username: None,
            password: None,
            token: None,
            timeout_ms: None,
        };
        assert!(matches!(
            handle.validate_push_config(&config),
            Err(GitError::InvalidPushConfig { .. })
        ));

        // Empty remote string
        let config = PushConfig {
            path: "/tmp/test".to_string(),
            remote: Some("".to_string()),
            branch: None,
            branches: None,
            tags: None,
            force: None,
            ff_only: None,
            set_upstream: None,
            ssh_key: None,
            known_hosts_path: None,
            username: None,
            password: None,
            token: None,
            timeout_ms: None,
        };
        assert!(matches!(
            handle.validate_push_config(&config),
            Err(GitError::InvalidPushConfig { .. })
        ));

        // Multiple auth methods
        let config = PushConfig {
            path: "/tmp/test".to_string(),
            remote: None,
            branch: None,
            branches: None,
            tags: None,
            force: None,
            ff_only: None,
            set_upstream: None,
            ssh_key: Some("key".to_string()),
            known_hosts_path: None,
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            token: None,
            timeout_ms: None,
        };
        assert!(matches!(
            handle.validate_push_config(&config),
            Err(GitError::InvalidPushConfig { .. })
        ));
    }

    #[test]
    fn test_push_config_parsing() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        let args = json!({
            "path": "/tmp/test",
            "remote": "origin",
            "branch": "main",
            "tags": true,
            "force": false,
            "ff_only": true,
            "set_upstream": true,
            "timeout_ms": 30000
        });

        let config = handle.parse_push_config(args).unwrap();
        assert_eq!(config.path, "/tmp/test");
        assert_eq!(config.remote, Some("origin".to_string()));
        assert_eq!(config.branch, Some("main".to_string()));
        assert_eq!(config.branches, None);
        assert_eq!(config.tags, Some(true));
        assert_eq!(config.force, Some(false));
        assert_eq!(config.ff_only, Some(true));
        assert_eq!(config.set_upstream, Some(true));
        assert_eq!(config.timeout_ms, Some(30000));
    }

    #[test]
    fn test_push_auth_validation_single_methods() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // SSH key only
        let config = PushConfig {
            path: "/tmp/test".to_string(),
            remote: None,
            branch: None,
            branches: None,
            tags: None,
            force: None,
            ff_only: None,
            set_upstream: None,
            ssh_key: Some("/path/to/key".to_string()),
            known_hosts_path: None,
            username: None,
            password: None,
            token: None,
            timeout_ms: None,
        };
        let result = handle.validate_push_config(&config);
        // Should fail due to path not existing, not auth validation
        assert!(matches!(result, Err(GitError::RepositoryNotFound { .. })));

        // Username/password only
        let config = PushConfig {
            path: "/tmp/test".to_string(),
            remote: None,
            branch: None,
            branches: None,
            tags: None,
            force: None,
            ff_only: None,
            set_upstream: None,
            ssh_key: None,
            known_hosts_path: None,
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            token: None,
            timeout_ms: None,
        };
        let result = handle.validate_push_config(&config);
        assert!(matches!(result, Err(GitError::RepositoryNotFound { .. })));

        // Token only
        let config = PushConfig {
            path: "/tmp/test".to_string(),
            remote: None,
            branch: None,
            branches: None,
            tags: None,
            force: None,
            ff_only: None,
            set_upstream: None,
            ssh_key: None,
            known_hosts_path: None,
            username: None,
            password: None,
            token: Some("token123".to_string()),
            timeout_ms: None,
        };
        let result = handle.validate_push_config(&config);
        assert!(matches!(result, Err(GitError::RepositoryNotFound { .. })));
    }

    #[test]
    fn test_parse_status_config() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // Valid config with all fields
        let args = json!({
            "path": "/tmp/test_repo",
            "include_ignored": true,
            "include_untracked": false,
            "include_staged": true,
            "include_branch": true,
            "include_remote": true,
            "timeout_ms": 10000
        });

        let config = handle.parse_status_config(args).unwrap();
        assert_eq!(config.path, "/tmp/test_repo");
        assert_eq!(config.include_ignored, Some(true));
        assert_eq!(config.include_untracked, Some(false));
        assert_eq!(config.include_staged, Some(true));
        assert_eq!(config.include_branch, Some(true));
        assert_eq!(config.include_remote, Some(true));
        assert_eq!(config.timeout_ms, Some(10000));

        // Minimal config with only required fields
        let args = json!({
            "path": "/tmp/test_repo"
        });

        let config = handle.parse_status_config(args).unwrap();
        assert_eq!(config.path, "/tmp/test_repo");
        assert_eq!(config.include_ignored, None);
        assert_eq!(config.include_untracked, None);
        assert_eq!(config.include_staged, None);
        assert_eq!(config.include_branch, None);
        assert_eq!(config.include_remote, None);
        assert_eq!(config.timeout_ms, None);
    }

    #[test]
    fn test_status_config_validation() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // Test missing path
        let config = StatusConfig {
            path: "".to_string(),
            include_ignored: None,
            include_untracked: None,
            include_staged: None,
            include_branch: None,
            include_remote: None,
            timeout_ms: None,
        };

        let result = handle.validate_status_config(&config);
        assert!(matches!(result, Err(GitError::InvalidStatusConfig { .. })));

        // Test zero timeout
        let config = StatusConfig {
            path: "/tmp/test".to_string(),
            include_ignored: None,
            include_untracked: None,
            include_staged: None,
            include_branch: None,
            include_remote: None,
            timeout_ms: Some(0),
        };

        let result = handle.validate_status_config(&config);
        assert!(matches!(result, Err(GitError::InvalidStatusConfig { .. })));

        // Test nonexistent path
        let config = StatusConfig {
            path: "/nonexistent/path/that/should/not/exist".to_string(),
            include_ignored: None,
            include_untracked: None,
            include_staged: None,
            include_branch: None,
            include_remote: None,
            timeout_ms: Some(5000),
        };

        let result = handle.validate_status_config(&config);
        assert!(matches!(result, Err(GitError::RepositoryNotFound { .. })));
    }

    #[test]
    fn test_status_config_parsing_errors() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // Test invalid JSON structure
        let args = json!({
            "timeout_ms": "not_a_number"
        });

        let result = handle.parse_status_config(args);
        assert!(matches!(result, Err(GitError::InvalidStatusConfig { .. })));

        // Test missing required path field when it becomes empty after parsing
        let args = json!({});

        // This should parse fine but validation should catch empty path
        if let Ok(config) = handle.parse_status_config(args) {
            // The config should have an empty path since it's required but not provided
            // Let's see what serde does with missing required fields
            assert!(config.path.is_empty());
        }
    }

    #[test]
    fn test_file_status_serialization() {
        let file_status = FileStatus {
            path: "src/main.rs".to_string(),
            status: "modified".to_string(),
        };

        let json = serde_json::to_value(&file_status).unwrap();
        assert_eq!(json["path"], "src/main.rs");
        assert_eq!(json["status"], "modified");

        // Test round-trip
        let deserialized: FileStatus = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.path, "src/main.rs");
        assert_eq!(deserialized.status, "modified");
    }

    #[test]
    fn test_branch_info_serialization() {
        let upstream = UpstreamInfo {
            name: "origin/main".to_string(),
            remote: "origin".to_string(),
            ahead_by: 2,
            behind_by: 1,
        };

        let branch_info = BranchInfo {
            name: Some("main".to_string()),
            detached: false,
            head: "abc123def456".to_string(),
            upstream: Some(upstream),
        };

        let json = serde_json::to_value(&branch_info).unwrap();
        assert_eq!(json["name"], "main");
        assert_eq!(json["detached"], false);
        assert_eq!(json["head"], "abc123def456");
        assert_eq!(json["upstream"]["name"], "origin/main");
        assert_eq!(json["upstream"]["remote"], "origin");
        assert_eq!(json["upstream"]["ahead_by"], 2);
        assert_eq!(json["upstream"]["behind_by"], 1);

        // Test detached head case
        let detached_branch = BranchInfo {
            name: None,
            detached: true,
            head: "abc123def456".to_string(),
            upstream: None,
        };

        let json = serde_json::to_value(&detached_branch).unwrap();
        assert!(json["name"].is_null());
        assert_eq!(json["detached"], true);
        assert!(json["upstream"].is_null());
    }

    #[test]
    fn test_working_tree_status_serialization() {
        let status = WorkingTreeStatus {
            clean: false,
            staged: vec![FileStatus {
                path: "file1.rs".to_string(),
                status: "modified".to_string(),
            }],
            unstaged: vec![FileStatus {
                path: "file2.rs".to_string(),
                status: "modified".to_string(),
            }],
            untracked: vec![FileStatus {
                path: "newfile.txt".to_string(),
                status: "untracked".to_string(),
            }],
            ignored: vec![],
            conflicts: vec![],
        };

        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["clean"], false);
        assert_eq!(json["staged"].as_array().unwrap().len(), 1);
        assert_eq!(json["unstaged"].as_array().unwrap().len(), 1);
        assert_eq!(json["untracked"].as_array().unwrap().len(), 1);
        assert_eq!(json["ignored"].as_array().unwrap().len(), 0);
        assert_eq!(json["conflicts"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_in_progress_flags_serialization() {
        let flags = InProgressFlags {
            merge: true,
            rebase: false,
            cherry_pick: false,
            revert: false,
            bisect: false,
        };

        let json = serde_json::to_value(&flags).unwrap();
        assert_eq!(json["merge"], true);
        assert_eq!(json["rebase"], false);
        assert_eq!(json["cherry_pick"], false);
        assert_eq!(json["revert"], false);
        assert_eq!(json["bisect"], false);
    }

    #[test]
    fn test_status_result_complete_serialization() {
        let upstream = UpstreamInfo {
            name: "origin/main".to_string(),
            remote: "origin".to_string(),
            ahead_by: 1,
            behind_by: 0,
        };

        let branch_info = BranchInfo {
            name: Some("main".to_string()),
            detached: false,
            head: "abc123def456".to_string(),
            upstream: Some(upstream),
        };

        let working_tree = WorkingTreeStatus {
            clean: false,
            staged: vec![FileStatus {
                path: "src/app.rs".to_string(),
                status: "modified".to_string(),
            }],
            unstaged: vec![],
            untracked: vec![FileStatus {
                path: "notes.txt".to_string(),
                status: "untracked".to_string(),
            }],
            ignored: vec![],
            conflicts: vec![],
        };

        let in_progress = InProgressFlags {
            merge: false,
            rebase: false,
            cherry_pick: false,
            revert: false,
            bisect: false,
        };

        let result = StatusResult {
            backend: "git".to_string(),
            alias: "default".to_string(),
            path: "/srv/app".to_string(),
            branch: Some(branch_info),
            working_tree,
            in_progress,
        };

        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["backend"], "git");
        assert_eq!(json["alias"], "default");
        assert_eq!(json["path"], "/srv/app");
        assert_eq!(json["branch"]["name"], "main");
        assert_eq!(json["branch"]["detached"], false);
        assert_eq!(json["branch"]["upstream"]["ahead_by"], 1);
        assert_eq!(json["working_tree"]["clean"], false);
        assert_eq!(json["working_tree"]["staged"].as_array().unwrap().len(), 1);
        assert_eq!(
            json["working_tree"]["untracked"].as_array().unwrap().len(),
            1
        );
        assert_eq!(json["in_progress"]["merge"], false);

        // Test round-trip serialization
        let pretty_json = serde_json::to_string_pretty(&result).unwrap();
        println!("Status result JSON:\n{}", pretty_json);

        let deserialized: StatusResult = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.backend, "git");
        assert_eq!(deserialized.alias, "default");
    }

    // Integration tests with real git repositories
    #[test]
    fn test_branch_config_parsing() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // Test basic list action parsing
        let args = json!({
            "path": "/tmp/test_repo",
            "action": "list",
            "local_only": true
        });
        let config = handle.parse_branch_config(args).unwrap();
        assert_eq!(config.path, "/tmp/test_repo");
        assert_eq!(config.action, Some(BranchAction::List));
        assert_eq!(config.local_only, Some(true));

        // Test create action parsing
        let args = json!({
            "path": "/tmp/test_repo",
            "action": "create",
            "name": "feature/test",
            "start_point": "main"
        });
        let config = handle.parse_branch_config(args).unwrap();
        assert_eq!(config.action, Some(BranchAction::Create));
        assert_eq!(config.name, Some("feature/test".to_string()));
        assert_eq!(config.start_point, Some("main".to_string()));

        // Test defaults
        let args = json!({
            "path": "/tmp/test_repo"
        });
        let config = handle.parse_branch_config(args).unwrap();
        assert_eq!(config.action, None); // Should default to List
        assert_eq!(config.local_only, None); // Should default to true
        assert_eq!(config.remote_only, None); // Should default to false
        assert_eq!(config.all, None); // Should default to false
    }

    #[test]
    fn test_branch_config_validation() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // Test missing path
        let config = BranchConfig {
            path: "".to_string(),
            action: Some(BranchAction::List),
            name: None,
            new_name: None,
            start_point: None,
            local_only: Some(true),
            remote_only: Some(false),
            all: Some(false),
            force: Some(false),
            track: Some(false),
            remote: None,
            timeout_ms: Some(5000),
        };
        let result = handle.validate_branch_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("path cannot be empty")
        );

        // Test invalid list flags
        let mut config = BranchConfig {
            path: "/tmp".to_string(),
            action: Some(BranchAction::List),
            name: None,
            new_name: None,
            start_point: None,
            local_only: Some(true),
            remote_only: Some(true), // Invalid: both local_only and remote_only
            all: Some(false),
            force: None,
            track: None,
            remote: None,
            timeout_ms: Some(5000),
        };
        let result = handle.validate_branch_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid list flags")
        );

        // Test missing name for create action
        config = BranchConfig {
            path: "/tmp".to_string(),
            action: Some(BranchAction::Create),
            name: None, // Missing required name
            new_name: None,
            start_point: None,
            local_only: None,
            remote_only: None,
            all: None,
            force: Some(false),
            track: None,
            remote: None,
            timeout_ms: Some(5000),
        };
        let result = handle.validate_branch_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("name is required for create")
        );

        // Test missing new_name for rename action
        config = BranchConfig {
            path: "/tmp".to_string(),
            action: Some(BranchAction::Rename),
            name: Some("old".to_string()),
            new_name: None, // Missing required new_name
            start_point: None,
            local_only: None,
            remote_only: None,
            all: None,
            force: Some(false),
            track: None,
            remote: None,
            timeout_ms: Some(5000),
        };
        let result = handle.validate_branch_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("new_name is required for rename")
        );

        // Test same name and new_name for rename action
        config = BranchConfig {
            path: "/tmp".to_string(),
            action: Some(BranchAction::Rename),
            name: Some("same".to_string()),
            new_name: Some("same".to_string()), // Same as name
            start_point: None,
            local_only: None,
            remote_only: None,
            all: None,
            force: Some(false),
            track: None,
            remote: None,
            timeout_ms: Some(5000),
        };
        let result = handle.validate_branch_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("name and new_name cannot be the same")
        );
    }

    #[test]
    fn test_branch_action_serialization() {
        // Test that BranchAction can be serialized and deserialized properly
        let list_action = BranchAction::List;
        let json_str = serde_json::to_string(&list_action).unwrap();
        assert_eq!(json_str, "\"list\"");

        let create_action: BranchAction = serde_json::from_str("\"create\"").unwrap();
        assert_eq!(create_action, BranchAction::Create);

        // Test default
        let default_action = BranchAction::default();
        assert_eq!(default_action, BranchAction::List);
    }

    #[test]
    fn test_tag_action_serialization() {
        // Test that TagAction can be serialized and deserialized properly
        let list_action = TagAction::List;
        let json_str = serde_json::to_string(&list_action).unwrap();
        assert_eq!(json_str, "\"list\"");

        let create_action: TagAction = serde_json::from_str("\"create\"").unwrap();
        assert_eq!(create_action, TagAction::Create);

        let delete_action: TagAction = serde_json::from_str("\"delete\"").unwrap();
        assert_eq!(delete_action, TagAction::Delete);

        // Test default
        let default_action = TagAction::default();
        assert_eq!(default_action, TagAction::List);
    }

    #[test]
    fn test_tag_sort_serialization() {
        // Test that TagSort can be serialized and deserialized properly
        let name_sort = TagSort::Name;
        let json_str = serde_json::to_string(&name_sort).unwrap();
        assert_eq!(json_str, "\"name\"");

        let version_sort: TagSort = serde_json::from_str("\"version\"").unwrap();
        assert_eq!(version_sort, TagSort::Version);

        let tagger_sort: TagSort = serde_json::from_str("\"taggerdate\"").unwrap();
        assert_eq!(tagger_sort, TagSort::TaggerDate);

        let committer_sort: TagSort = serde_json::from_str("\"committerdate\"").unwrap();
        assert_eq!(committer_sort, TagSort::CommitterDate);

        // Test default
        let default_sort = TagSort::default();
        assert_eq!(default_sort, TagSort::Name);
    }

    #[test]
    fn test_parse_tag_config_validation() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // Test missing path
        let args = json!({});
        let err = handle.parse_tag_config(args).unwrap_err();
        assert!(err.to_string().contains("missing field `path`"), "{err}");

        // Test timeout_ms = 0
        let args = json!({
            "path": "/tmp/test",
            "timeout_ms": 0
        });
        let result = handle.parse_tag_config(args).unwrap();
        let validation = handle.validate_tag_config(&result);
        assert!(validation.is_err());
        assert!(
            validation
                .unwrap_err()
                .to_string()
                .contains("timeout_ms must be greater than 0")
        );

        // Test invalid action
        let args = json!({
            "path": "/tmp/test",
            "action": "invalid"
        });
        let result = handle.parse_tag_config(args);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unknown variant `invalid`")
        );
    }

    #[test]
    fn test_validate_tag_config_create() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // Test create action without name
        let mut config = TagConfig {
            path: "/tmp/test".to_string(),
            action: Some(TagAction::Create),
            name: None,
            names: None,
            pattern: None,
            sort: None,
            annotated: None,
            message: None,
            target: None,
            force: None,
            author_name: None,
            author_email: None,
            timestamp: None,
            timeout_ms: None,
        };
        let result = handle.validate_tag_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("name is required for create")
        );

        // Test create annotated tag without message
        config.name = Some("v1.0.0".to_string());
        config.annotated = Some(true);
        let result = handle.validate_tag_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("message is required for annotated")
        );

        // Test valid annotated tag
        config.message = Some("Release 1.0.0".to_string());
        let result = handle.validate_tag_config(&config);
        assert!(result.is_ok());

        // Test valid lightweight tag
        config.annotated = Some(false);
        config.message = None;
        let result = handle.validate_tag_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_tag_config_delete() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // Test delete action without name or names
        let mut config = TagConfig {
            path: "/tmp/test".to_string(),
            action: Some(TagAction::Delete),
            name: None,
            names: None,
            pattern: None,
            sort: None,
            annotated: None,
            message: None,
            target: None,
            force: None,
            author_name: None,
            author_email: None,
            timestamp: None,
            timeout_ms: None,
        };
        let result = handle.validate_tag_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("either name or names is required")
        );

        // Test delete with empty names array
        config.names = Some(vec![]);
        let result = handle.validate_tag_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("names array cannot be empty")
        );

        // Test valid delete with name
        config.names = None;
        config.name = Some("v1.0.0".to_string());
        let result = handle.validate_tag_config(&config);
        assert!(result.is_ok());

        // Test valid delete with names
        config.name = None;
        config.names = Some(vec!["v1.0.0".to_string(), "v1.1.0".to_string()]);
        let result = handle.validate_tag_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compare_versions() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // Test semantic version sorting
        assert_eq!(
            handle.compare_versions("v1.0.0", "v1.0.1"),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            handle.compare_versions("v1.0.1", "v1.0.0"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            handle.compare_versions("v1.0.0", "v1.0.0"),
            std::cmp::Ordering::Equal
        );

        // Test major version differences
        assert_eq!(
            handle.compare_versions("v1.9.9", "v2.0.0"),
            std::cmp::Ordering::Less
        );

        // Test minor version differences
        assert_eq!(
            handle.compare_versions("v1.1.0", "v1.2.0"),
            std::cmp::Ordering::Less
        );

        // Test version without 'v' prefix
        assert_eq!(
            handle.compare_versions("1.0.0", "1.0.1"),
            std::cmp::Ordering::Less
        );

        // Test versions with different lengths
        assert_eq!(
            handle.compare_versions("1.0", "1.0.1"),
            std::cmp::Ordering::Less
        );

        // Test non-numeric versions (fallback to string comparison)
        assert_eq!(
            handle.compare_versions("alpha", "beta"),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn test_tag_timestamp_parsing() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // Test ISO8601 timestamp parsing
        let args = json!({
            "path": "/tmp/test",
            "action": "create",
            "name": "v1.0.0",
            "annotated": true,
            "message": "Release",
            "timestamp": "2025-03-18T12:34:56Z"
        });
        let config = handle.parse_tag_config(args).unwrap();
        match config.timestamp {
            Some(TagTimestamp::Iso8601(ref iso_str)) => {
                assert_eq!(iso_str, "2025-03-18T12:34:56Z");
            }
            _ => panic!("Expected ISO8601 timestamp"),
        }

        // Test Unix timestamp parsing
        let args = json!({
            "path": "/tmp/test",
            "action": "create",
            "name": "v1.0.0",
            "annotated": true,
            "message": "Release",
            "timestamp": 1710759296
        });
        let config = handle.parse_tag_config(args).unwrap();
        match config.timestamp {
            Some(TagTimestamp::UnixSeconds(unix_secs)) => {
                assert_eq!(unix_secs, 1710759296);
            }
            _ => panic!("Expected Unix timestamp"),
        }
    }

    // Sync verb tests
    #[test]
    fn test_sync_config_validation() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // Valid configuration
        let config = SyncConfig {
            path: "/tmp/test".to_string(),
            remote: Some("origin".to_string()),
            branch: Some("main".to_string()),
            remote_branch: None,
            pull_strategy: Some(PullStrategy::Rebase),
            ff_only: Some(false),
            allow_uncommitted: Some(false),
            stash_uncommitted: Some(false),
            abort_on_conflict: Some(true),
            author_name: None,
            author_email: None,
            push: Some(true),
            push_tags: Some(false),
            force_push: Some(false),
            dry_run: Some(false),
            known_hosts_path: None,
            timeout_ms: Some(60000),
        };
        assert!(handle.validate_sync_config(&config).is_ok());

        // Empty path
        let mut config = config.clone();
        config.path = "".to_string();
        assert!(matches!(
            handle.validate_sync_config(&config),
            Err(GitError::InvalidSyncConfig { .. })
        ));

        // Zero timeout
        let config = SyncConfig {
            path: "/tmp/test".to_string(),
            remote: Some("origin".to_string()),
            branch: Some("main".to_string()),
            remote_branch: None,
            pull_strategy: Some(PullStrategy::Rebase),
            ff_only: Some(false),
            allow_uncommitted: Some(false),
            stash_uncommitted: Some(false),
            abort_on_conflict: Some(true),
            author_name: None,
            author_email: None,
            push: Some(true),
            push_tags: Some(false),
            force_push: Some(false),
            dry_run: Some(false),
            known_hosts_path: None,
            timeout_ms: Some(0),
        };
        assert!(matches!(
            handle.validate_sync_config(&config),
            Err(GitError::InvalidSyncConfig { .. })
        ));

        // Empty remote
        let config = SyncConfig {
            path: "/tmp/test".to_string(),
            remote: Some("".to_string()),
            branch: Some("main".to_string()),
            remote_branch: None,
            pull_strategy: Some(PullStrategy::Rebase),
            ff_only: Some(false),
            allow_uncommitted: Some(false),
            stash_uncommitted: Some(false),
            abort_on_conflict: Some(true),
            author_name: None,
            author_email: None,
            push: Some(true),
            push_tags: Some(false),
            force_push: Some(false),
            dry_run: Some(false),
            known_hosts_path: None,
            timeout_ms: Some(60000),
        };
        assert!(matches!(
            handle.validate_sync_config(&config),
            Err(GitError::InvalidSyncConfig { .. })
        ));

        // Empty branch
        let config = SyncConfig {
            path: "/tmp/test".to_string(),
            remote: Some("origin".to_string()),
            branch: Some("".to_string()),
            remote_branch: None,
            pull_strategy: Some(PullStrategy::Rebase),
            ff_only: Some(false),
            allow_uncommitted: Some(false),
            stash_uncommitted: Some(false),
            abort_on_conflict: Some(true),
            author_name: None,
            author_email: None,
            push: Some(true),
            push_tags: Some(false),
            force_push: Some(false),
            dry_run: Some(false),
            known_hosts_path: None,
            timeout_ms: Some(60000),
        };
        assert!(matches!(
            handle.validate_sync_config(&config),
            Err(GitError::InvalidSyncConfig { .. })
        ));

        // Contradictory force_push and ff_only
        let config = SyncConfig {
            path: "/tmp/test".to_string(),
            remote: Some("origin".to_string()),
            branch: Some("main".to_string()),
            remote_branch: None,
            pull_strategy: Some(PullStrategy::Rebase),
            ff_only: Some(true),
            allow_uncommitted: Some(false),
            stash_uncommitted: Some(false),
            abort_on_conflict: Some(true),
            author_name: None,
            author_email: None,
            push: Some(true),
            push_tags: Some(false),
            force_push: Some(true),
            dry_run: Some(false),
            known_hosts_path: None,
            timeout_ms: Some(60000),
        };
        assert!(matches!(
            handle.validate_sync_config(&config),
            Err(GitError::InvalidSyncConfig { .. })
        ));
    }

    #[test]
    fn test_sync_config_parsing() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // Test parsing from JSON
        let args = json!({
            "path": "/tmp/test",
            "remote": "origin",
            "branch": "main",
            "pull_strategy": "rebase",
            "push": true,
            "timeout_ms": 60000
        });

        let config = handle.parse_sync_config(args).unwrap();
        assert_eq!(config.path, "/tmp/test");
        assert_eq!(config.remote, Some("origin".to_string()));
        assert_eq!(config.branch, Some("main".to_string()));
        assert_eq!(config.pull_strategy, Some(PullStrategy::Rebase));
        assert_eq!(config.push, Some(true));
        assert_eq!(config.timeout_ms, Some(60000));
    }

    #[test]
    fn test_pull_strategy_default() {
        assert_eq!(PullStrategy::default(), PullStrategy::Rebase);
    }

    #[test]
    fn test_pull_strategy_serde() {
        // Test serialization/deserialization
        let rebase = PullStrategy::Rebase;
        let merge = PullStrategy::Merge;
        let ff_only = PullStrategy::FfOnly;

        // Test JSON serialization
        assert_eq!(serde_json::to_string(&rebase).unwrap(), "\"rebase\"");
        assert_eq!(serde_json::to_string(&merge).unwrap(), "\"merge\"");
        assert_eq!(serde_json::to_string(&ff_only).unwrap(), "\"ff_only\"");

        // Test JSON deserialization
        assert_eq!(
            serde_json::from_str::<PullStrategy>("\"rebase\"").unwrap(),
            PullStrategy::Rebase
        );
        assert_eq!(
            serde_json::from_str::<PullStrategy>("\"merge\"").unwrap(),
            PullStrategy::Merge
        );
        assert_eq!(
            serde_json::from_str::<PullStrategy>("\"ff_only\"").unwrap(),
            PullStrategy::FfOnly
        );
    }

    #[test]
    fn test_sync_error_conversion() {
        // Test that sync errors are properly converted to shell errors
        let sync_error = GitError::InvalidSyncConfig {
            message: "test message".to_string(),
        };
        let shell_error: crate::core::status::ShellError = sync_error.into();
        assert_eq!(shell_error.code, "git.sync_invalid_config");
        assert!(shell_error.message.contains("test message"));

        let sync_error = GitError::SyncDetachedHead;
        let shell_error: crate::core::status::ShellError = sync_error.into();
        assert_eq!(shell_error.code, "git.sync_detached_head");

        let sync_error = GitError::SyncDirtyWorktree;
        let shell_error: crate::core::status::ShellError = sync_error.into();
        assert_eq!(shell_error.code, "git.sync_dirty_worktree");

        let sync_error = GitError::Timeout {
            verb: "sync".into(),
            timeout_ms: 60000,
            still_running: false,
        };
        let shell_error: crate::core::status::ShellError = sync_error.into();
        assert_eq!(shell_error.code, "git.sync_timeout");
        assert_eq!(shell_error.details["timeout_ms"], 60000);
    }

    // Status summary tests
    #[test]
    fn test_status_summary_config_validation() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // Valid configuration
        let config = StatusSummaryConfig {
            path: "/tmp/test".to_string(),
            remote: None,
            branch: None,
            include_untracked: Some(true),
            include_ignored: Some(false),
            include_remote: Some(true),
            compute_diffstats: Some(false),
            max_files: Some(500),
            timeout_ms: Some(5000),
        };
        assert!(handle.validate_status_summary_config(&config).is_ok());

        // Empty path
        let mut config = config.clone();
        config.path = "".to_string();
        assert!(matches!(
            handle.validate_status_summary_config(&config),
            Err(GitError::InvalidStatusSummaryConfig { .. })
        ));

        // Zero timeout
        let config = StatusSummaryConfig {
            path: "/tmp/test".to_string(),
            remote: None,
            branch: None,
            include_untracked: Some(true),
            include_ignored: Some(false),
            include_remote: Some(true),
            compute_diffstats: Some(false),
            max_files: Some(500),
            timeout_ms: Some(0),
        };
        assert!(matches!(
            handle.validate_status_summary_config(&config),
            Err(GitError::InvalidStatusSummaryConfig { .. })
        ));

        // Zero max_files
        let config = StatusSummaryConfig {
            path: "/tmp/test".to_string(),
            remote: None,
            branch: None,
            include_untracked: Some(true),
            include_ignored: Some(false),
            include_remote: Some(true),
            compute_diffstats: Some(false),
            max_files: Some(0),
            timeout_ms: Some(5000),
        };
        assert!(matches!(
            handle.validate_status_summary_config(&config),
            Err(GitError::InvalidStatusSummaryConfig { .. })
        ));

        // Empty branch string
        let config = StatusSummaryConfig {
            path: "/tmp/test".to_string(),
            remote: None,
            branch: Some("".to_string()),
            include_untracked: Some(true),
            include_ignored: Some(false),
            include_remote: Some(true),
            compute_diffstats: Some(false),
            max_files: Some(500),
            timeout_ms: Some(5000),
        };
        assert!(matches!(
            handle.validate_status_summary_config(&config),
            Err(GitError::InvalidStatusSummaryConfig { .. })
        ));

        // Empty remote string
        let config = StatusSummaryConfig {
            path: "/tmp/test".to_string(),
            remote: Some("".to_string()),
            branch: None,
            include_untracked: Some(true),
            include_ignored: Some(false),
            include_remote: Some(true),
            compute_diffstats: Some(false),
            max_files: Some(500),
            timeout_ms: Some(5000),
        };
        assert!(matches!(
            handle.validate_status_summary_config(&config),
            Err(GitError::InvalidStatusSummaryConfig { .. })
        ));
    }

    #[test]
    fn test_status_summary_state_classification() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // Test clean and synced state
        let working_tree = json!({
            "clean": true,
            "staged_count": 0,
            "unstaged_count": 0,
            "conflicts_count": 0,
            "in_progress": {
                "merge": false,
                "rebase": false,
                "cherry_pick": false,
                "revert": false,
                "bisect": false
            }
        });
        let sync_state = "in_sync";
        let summary = handle
            .compute_summary_flags(&working_tree, sync_state)
            .unwrap();
        assert_eq!(summary["state"], "clean_and_synced");
        assert_eq!(summary["has_uncommitted_changes"], false);
        assert_eq!(summary["blocked_by_conflicts"], false);

        // Test local changes only
        let working_tree = json!({
            "clean": false,
            "staged_count": 2,
            "unstaged_count": 1,
            "conflicts_count": 0,
            "in_progress": {
                "merge": false,
                "rebase": false,
                "cherry_pick": false,
                "revert": false,
                "bisect": false
            }
        });
        let sync_state = "in_sync";
        let summary = handle
            .compute_summary_flags(&working_tree, sync_state)
            .unwrap();
        assert_eq!(summary["state"], "local_changes_only");
        assert_eq!(summary["has_uncommitted_changes"], true);
        assert_eq!(summary["can_commit"], true);

        // Test ahead only state
        let working_tree = json!({
            "clean": true,
            "staged_count": 0,
            "unstaged_count": 0,
            "conflicts_count": 0,
            "in_progress": {
                "merge": false,
                "rebase": false,
                "cherry_pick": false,
                "revert": false,
                "bisect": false
            }
        });
        let sync_state = "ahead_only";
        let summary = handle
            .compute_summary_flags(&working_tree, sync_state)
            .unwrap();
        assert_eq!(summary["state"], "committed_but_ahead");
        assert_eq!(summary["needs_push"], true);

        // Test conflicts present
        let working_tree = json!({
            "clean": false,
            "staged_count": 0,
            "unstaged_count": 0,
            "conflicts_count": 3,
            "in_progress": {
                "merge": true,
                "rebase": false,
                "cherry_pick": false,
                "revert": false,
                "bisect": false
            }
        });
        let sync_state = "in_sync";
        let summary = handle
            .compute_summary_flags(&working_tree, sync_state)
            .unwrap();
        assert_eq!(summary["state"], "conflicts_present");
        assert_eq!(summary["blocked_by_conflicts"], true);

        // Test diverged state
        let working_tree = json!({
            "clean": true,
            "staged_count": 0,
            "unstaged_count": 0,
            "conflicts_count": 0,
            "in_progress": {
                "merge": false,
                "rebase": false,
                "cherry_pick": false,
                "revert": false,
                "bisect": false
            }
        });
        let sync_state = "diverged";
        let summary = handle
            .compute_summary_flags(&working_tree, sync_state)
            .unwrap();
        assert_eq!(summary["state"], "diverged");
        assert_eq!(summary["needs_pull"], true);
        assert_eq!(summary["needs_push"], true);
    }

    #[test]
    fn test_status_summary_recommendations() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // Test conflicts present recommendation
        let summary = json!({
            "state": "conflicts_present",
            "blocked_by_conflicts": true,
            "has_uncommitted_changes": true
        });
        let working_tree = json!({});
        let sync_state = "in_sync";
        let rec = handle
            .compute_recommendations(&summary, sync_state, &working_tree)
            .unwrap();
        assert_eq!(rec["primary_action"], "resolve_conflicts");
        assert_eq!(rec["actions"].as_array().unwrap().len(), 2);

        // Test local changes recommendation
        let summary = json!({
            "state": "local_changes_only",
            "blocked_by_conflicts": false,
            "has_uncommitted_changes": true
        });
        let rec = handle
            .compute_recommendations(&summary, sync_state, &working_tree)
            .unwrap();
        assert_eq!(rec["primary_action"], "commit");
        assert_eq!(rec["actions"].as_array().unwrap()[0], "commit_changes");

        // Test ahead only recommendation
        let summary = json!({
            "state": "committed_but_ahead",
            "blocked_by_conflicts": false,
            "has_uncommitted_changes": false
        });
        let rec = handle
            .compute_recommendations(&summary, sync_state, &working_tree)
            .unwrap();
        assert_eq!(rec["primary_action"], "push");

        // Test behind remote recommendation
        let summary = json!({
            "state": "behind_remote",
            "blocked_by_conflicts": false,
            "has_uncommitted_changes": false
        });
        let rec = handle
            .compute_recommendations(&summary, sync_state, &working_tree)
            .unwrap();
        assert_eq!(rec["primary_action"], "pull");

        // Test clean and synced recommendation
        let summary = json!({
            "state": "clean_and_synced",
            "blocked_by_conflicts": false,
            "has_uncommitted_changes": false
        });
        let rec = handle
            .compute_recommendations(&summary, sync_state, &working_tree)
            .unwrap();
        assert_eq!(rec["primary_action"], "none");
        assert_eq!(rec["actions"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_status_summary_error_conversion() {
        // Test status summary error conversion to shell errors
        let error = GitError::InvalidStatusSummaryConfig {
            message: "test message".to_string(),
        };
        let shell_error: crate::core::status::ShellError = error.into();
        assert_eq!(shell_error.code, "git.invalid_status_summary_config");
        assert!(shell_error.message.contains("test message"));

        let error = GitError::StatusSummaryBranchNotFound {
            name: "feature-branch".to_string(),
        };
        let shell_error: crate::core::status::ShellError = error.into();
        assert_eq!(shell_error.code, "git.status_summary_branch_not_found");
        assert_eq!(shell_error.details["name"], "feature-branch");

        let error = GitError::Timeout {
            verb: "status_summary".into(),
            timeout_ms: 5000,
            still_running: true,
        };
        let shell_error: crate::core::status::ShellError = error.into();
        assert_eq!(shell_error.code, "git.status_summary_timeout");
        assert_eq!(shell_error.details["timeout_ms"], 5000);

        let error = GitError::StatusSummaryFailed {
            message: "git operation failed".to_string(),
        };
        let shell_error: crate::core::status::ShellError = error.into();
        assert_eq!(shell_error.code, "git.status_summary_failed");
    }

    #[test]
    fn test_status_short_config_validation() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // Valid configuration
        let config = StatusShortConfig {
            path: "/tmp/test".to_string(),
            branch: None,
            remote: None,
            include_remote: Some(true),
            include_dirty: Some(true),
            include_conflicts: Some(true),
            symbols: None,
            timeout_ms: Some(1000),
        };
        assert!(handle.validate_status_short_config(&config).is_ok());

        // Empty path
        let mut config = config.clone();
        config.path = "".to_string();
        assert!(matches!(
            handle.validate_status_short_config(&config),
            Err(GitError::InvalidStatusShortConfig { .. })
        ));

        // Zero timeout
        let config = StatusShortConfig {
            path: "/tmp/test".to_string(),
            branch: None,
            remote: None,
            include_remote: Some(true),
            include_dirty: Some(true),
            include_conflicts: Some(true),
            symbols: None,
            timeout_ms: Some(0),
        };
        assert!(matches!(
            handle.validate_status_short_config(&config),
            Err(GitError::InvalidStatusShortConfig { .. })
        ));

        // Empty branch string
        let config = StatusShortConfig {
            path: "/tmp/test".to_string(),
            branch: Some("".to_string()),
            remote: None,
            include_remote: Some(true),
            include_dirty: Some(true),
            include_conflicts: Some(true),
            symbols: None,
            timeout_ms: Some(1000),
        };
        assert!(matches!(
            handle.validate_status_short_config(&config),
            Err(GitError::InvalidStatusShortConfig { .. })
        ));

        // Empty remote string
        let config = StatusShortConfig {
            path: "/tmp/test".to_string(),
            branch: None,
            remote: Some("".to_string()),
            include_remote: Some(true),
            include_dirty: Some(true),
            include_conflicts: Some(true),
            symbols: None,
            timeout_ms: Some(1000),
        };
        assert!(matches!(
            handle.validate_status_short_config(&config),
            Err(GitError::InvalidStatusShortConfig { .. })
        ));
    }

    #[test]
    fn test_status_short_symbols_resolution() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        // Test default symbols
        let symbols = handle.resolve_status_short_symbols(&None);
        assert_eq!(symbols.detached.as_ref().unwrap(), "!");
        assert_eq!(symbols.ahead.as_ref().unwrap(), "↑");
        assert_eq!(symbols.behind.as_ref().unwrap(), "↓");
        assert_eq!(symbols.dirty.as_ref().unwrap(), "*");
        assert_eq!(symbols.conflict.as_ref().unwrap(), "✖");
        assert_eq!(symbols.no_upstream.as_ref().unwrap(), "·");

        // Test partial custom symbols
        let custom = Some(StatusShortSymbols {
            detached: None,
            ahead: Some(">".to_string()),
            behind: None,
            dirty: Some("+".to_string()),
            conflict: None,
            no_upstream: None,
        });
        let symbols = handle.resolve_status_short_symbols(&custom);
        assert_eq!(symbols.detached.as_ref().unwrap(), "!"); // default
        assert_eq!(symbols.ahead.as_ref().unwrap(), ">"); // custom
        assert_eq!(symbols.behind.as_ref().unwrap(), "↓"); // default
        assert_eq!(symbols.dirty.as_ref().unwrap(), "+"); // custom
        assert_eq!(symbols.conflict.as_ref().unwrap(), "✖"); // default
        assert_eq!(symbols.no_upstream.as_ref().unwrap(), "·"); // default
    }

    #[test]
    fn test_status_short_summary_string_building() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };
        let symbols = StatusShortSymbols {
            detached: Some("!".to_string()),
            ahead: Some("↑".to_string()),
            behind: Some("↓".to_string()),
            dirty: Some("*".to_string()),
            conflict: Some("✖".to_string()),
            no_upstream: Some("·".to_string()),
        };

        let config = StatusShortConfig {
            path: "/tmp/test".to_string(),
            branch: None,
            remote: None,
            include_remote: Some(true),
            include_dirty: Some(true),
            include_conflicts: Some(true),
            symbols: None,
            timeout_ms: Some(1000),
        };

        // Clean branch, in sync
        let summary =
            handle.build_summary_string("main", false, 0, 0, true, true, false, &symbols, &config);
        assert_eq!(summary, "main");

        // Dirty branch, in sync
        let summary =
            handle.build_summary_string("main", false, 0, 0, true, false, false, &symbols, &config);
        assert_eq!(summary, "main*");

        // Clean branch, ahead by 1
        let summary =
            handle.build_summary_string("main", false, 1, 0, true, true, false, &symbols, &config);
        assert_eq!(summary, "main↑1");

        // Clean branch, behind by 2
        let summary =
            handle.build_summary_string("main", false, 0, 2, true, true, false, &symbols, &config);
        assert_eq!(summary, "main↓2");

        // Dirty branch, diverged
        let summary =
            handle.build_summary_string("main", false, 1, 2, true, false, false, &symbols, &config);
        assert_eq!(summary, "main↑1↓2*");

        // Detached head, clean, no upstream
        let summary =
            handle.build_summary_string("HEAD", true, 0, 0, false, true, false, &symbols, &config);
        assert_eq!(summary, "HEAD!·");

        // Clean branch with conflicts
        let summary =
            handle.build_summary_string("main", false, 0, 0, true, true, true, &symbols, &config);
        assert_eq!(summary, "main✖");

        // Dirty branch with conflicts
        let summary =
            handle.build_summary_string("main", false, 0, 0, true, false, true, &symbols, &config);
        assert_eq!(summary, "main*✖");

        // Test with include flags disabled
        let mut config_no_remote = config.clone();
        config_no_remote.include_remote = Some(false);
        let summary = handle.build_summary_string(
            "main",
            false,
            1,
            2,
            true,
            false,
            true,
            &symbols,
            &config_no_remote,
        );
        assert_eq!(summary, "main*✖"); // No arrows

        let mut config_no_dirty = config.clone();
        config_no_dirty.include_dirty = Some(false);
        let summary = handle.build_summary_string(
            "main",
            false,
            1,
            2,
            true,
            false,
            true,
            &symbols,
            &config_no_dirty,
        );
        assert_eq!(summary, "main↑1↓2✖"); // No dirty marker

        let mut config_no_conflicts = config.clone();
        config_no_conflicts.include_conflicts = Some(false);
        let summary = handle.build_summary_string(
            "main",
            false,
            1,
            2,
            true,
            false,
            true,
            &symbols,
            &config_no_conflicts,
        );
        assert_eq!(summary, "main↑1↓2*"); // No conflict marker
    }

    #[test]
    fn test_status_short_error_conversion() {
        // Test status_short error conversion to shell errors
        let error = GitError::InvalidStatusShortConfig {
            message: "test message".to_string(),
        };
        let shell_error: crate::core::status::ShellError = error.into();
        assert_eq!(shell_error.code, "git.invalid_status_short_config");
        assert!(shell_error.message.contains("test message"));

        let error = GitError::StatusShortBranchNotFound {
            branch: "feature-branch".to_string(),
        };
        let shell_error: crate::core::status::ShellError = error.into();
        assert_eq!(shell_error.code, "git.status_short_branch_not_found");
        assert_eq!(shell_error.details["branch"], "feature-branch");

        let error = GitError::Timeout {
            verb: "status_short".into(),
            timeout_ms: 1000,
            still_running: false,
        };
        let shell_error: crate::core::status::ShellError = error.into();
        assert_eq!(shell_error.code, "git.status_short_timeout");
        assert_eq!(shell_error.details["timeout_ms"], 1000);

        let error = GitError::StatusShortFailed {
            message: "git operation failed".to_string(),
        };
        let shell_error: crate::core::status::ShellError = error.into();
        assert_eq!(shell_error.code, "git.status_short_failed");
    }

    /// CLI args as the registry delivers them: every value is a string.
    fn cli_args(pairs: &[(&str, &str)]) -> Value {
        let args: Args = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        serde_json::to_value(args).unwrap()
    }

    #[test]
    fn test_parse_commit_config_from_cli_strings() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };
        let config = handle
            .parse_commit_config(cli_args(&[
                ("path", "/repo"),
                ("message", "msg"),
                ("all", "true"),
                ("paths", "a.txt,b.txt"),
                ("allow_empty", "false"),
                ("timeout_ms", "5000"),
            ]))
            .unwrap();
        assert_eq!(config.all, Some(true));
        assert_eq!(
            config.paths,
            Some(vec!["a.txt".to_string(), "b.txt".to_string()])
        );
        assert_eq!(config.allow_empty, Some(false));
        assert_eq!(config.timeout_ms, Some(5000));

        let config = handle
            .parse_commit_config(cli_args(&[("path", "/repo"), ("paths", r#"["x y.txt"]"#)]))
            .unwrap();
        assert_eq!(config.paths, Some(vec!["x y.txt".to_string()]));

        assert!(
            handle
                .parse_commit_config(cli_args(&[("path", "/repo"), ("all", "maybe")]))
                .is_err()
        );
    }

    #[test]
    fn test_parse_typed_configs_from_cli_strings() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        let pull = handle
            .parse_pull_config(cli_args(&[
                ("path", "/r"),
                ("ff_only", "true"),
                ("timeout_ms", "100"),
            ]))
            .unwrap();
        assert_eq!(pull.ff_only, Some(true));
        assert_eq!(pull.timeout_ms, Some(100));

        let push = handle
            .parse_push_config(cli_args(&[
                ("path", "/r"),
                ("tags", "yes"),
                ("branches", "main,dev"),
            ]))
            .unwrap();
        assert_eq!(push.tags, Some(true));
        assert_eq!(
            push.branches,
            Some(vec!["main".to_string(), "dev".to_string()])
        );

        let status = handle
            .parse_status_config(cli_args(&[("path", "/r"), ("include_ignored", "1")]))
            .unwrap();
        assert_eq!(status.include_ignored, Some(true));

        let branch = handle
            .parse_branch_config(cli_args(&[
                ("path", "/r"),
                ("action", "list"),
                ("all", "true"),
            ]))
            .unwrap();
        assert_eq!(branch.action, Some(BranchAction::List));
        assert_eq!(branch.all, Some(true));

        let sync = handle
            .parse_sync_config(cli_args(&[
                ("path", "/r"),
                ("pull_strategy", "ff_only"),
                ("dry_run", "true"),
            ]))
            .unwrap();
        assert_eq!(sync.pull_strategy, Some(PullStrategy::FfOnly));
        assert_eq!(sync.dry_run, Some(true));

        let summary = handle
            .parse_status_summary_config(cli_args(&[("path", "/r"), ("max_files", "10")]))
            .unwrap();
        assert_eq!(summary.max_files, Some(10));

        let short = handle
            .parse_status_short_config(cli_args(&[("path", "/r"), ("include_dirty", "false")]))
            .unwrap();
        assert_eq!(short.include_dirty, Some(false));
    }

    #[test]
    fn test_parse_merge_and_rebase_config_from_cli_strings() {
        let handle = GitHandle {
            alias: "test".to_string(),
        };

        let merge = handle
            .parse_merge_config(cli_args(&[
                ("path", "/r"),
                ("source", "feature"),
                ("ff_only", "true"),
                ("squash", "false"),
                ("timeout_ms", "250"),
            ]))
            .unwrap();
        assert_eq!(merge.ff_only, Some(true));
        assert_eq!(merge.squash, Some(false));
        assert_eq!(merge.timeout_ms, Some(250));
        assert!(
            handle
                .parse_merge_config(cli_args(&[
                    ("path", "/r"),
                    ("source", "f"),
                    ("no_ff", "maybe")
                ]))
                .is_err()
        );

        let rebase = handle
            .parse_rebase_config(cli_args(&[
                ("path", "/r"),
                ("upstream", "main"),
                ("autosquash", "yes"),
                ("timeout_ms", "300"),
            ]))
            .unwrap();
        assert_eq!(rebase.autosquash, Some(true));
        assert_eq!(rebase.timeout_ms, Some(300));
        assert!(
            handle
                .parse_rebase_config(cli_args(&[("path", "/r"), ("timeout_ms", "soon")]))
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_commit_all_true_from_cli_strings_stages_tracked_changes() {
        let temp_dir = TempDir::new().unwrap();
        let repo = Repository::init(temp_dir.path()).unwrap();
        let file = temp_dir.path().join("a.txt");
        std::fs::write(&file, "one\n").unwrap();
        {
            let mut index = repo.index().unwrap();
            index.add_path(Path::new("a.txt")).unwrap();
            index.write().unwrap();
            let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
            let sig = Signature::now("T", "t@example.com").unwrap();
            repo.commit(Some("HEAD"), &sig, &sig, "init", &tree, &[])
                .unwrap();
        }
        std::fs::write(&file, "two\n").unwrap();

        let handle = GitHandle {
            alias: "test".to_string(),
        };
        let path = temp_dir.path().to_string_lossy().to_string();
        let result = handle
            .commit(cli_args(&[
                ("path", &path),
                ("message", "update"),
                ("all", "true"),
                ("author_name", "T"),
                ("author_email", "t@example.com"),
            ]))
            .await
            .unwrap();
        assert_eq!(result["stats"]["staged_files"], 1);

        let statuses = repo.statuses(None).unwrap();
        assert!(
            statuses
                .iter()
                .all(|e| !e.status().contains(GitStatus::WT_MODIFIED))
        );
        let head = repo.head().unwrap().peel_to_commit().unwrap();
        assert_eq!(head.message().ok(), Some("update"));

        // paths= is resolved against the work tree, not the current directory.
        std::fs::write(temp_dir.path().join("b.txt"), "new\n").unwrap();
        std::fs::write(temp_dir.path().join("c.txt"), "new\n").unwrap();
        let result = handle
            .commit(cli_args(&[
                ("path", &path),
                ("message", "add b"),
                ("paths", "b.txt"),
                ("author_name", "T"),
                ("author_email", "t@example.com"),
            ]))
            .await
            .unwrap();
        assert_eq!(result["stats"]["staged_files"], 1);
        let head = repo.head().unwrap().peel_to_commit().unwrap();
        let tree = head.tree().unwrap();
        assert!(tree.get_name("b.txt").is_some());
        assert!(tree.get_name("c.txt").is_none());
    }

    #[test]
    fn test_in_url_help_uses_approved_metadata() {
        assert!(git_help_text(None).starts_with("Handle: git"));
        let verb = git_help_text(Some("commit"));
        assert!(verb.starts_with("Handle: git"));
        assert!(verb.contains("Verb: commit"));
        assert!(is_git_help_word("--help"));
        assert!(is_git_help_word("help"));
        assert!(!is_git_help_word("my-helper"));
    }
}

// FUNC-04: sync never reports an integration that did not happen and never
// pushes after a failed integration. Local temporary repositories only.
#[cfg(test)]
mod sync_correctness_tests {
    use super::*;
    use git2::{RepositoryInitOptions, Signature};
    use tempfile::TempDir;

    struct World {
        _dir: TempDir,
        remote: std::path::PathBuf,
        a: Repository,
        b: Repository,
    }

    fn sig() -> Signature<'static> {
        Signature::now("Resh Test", "test@example.invalid").unwrap()
    }

    fn commit(repo: &Repository, file: &str, content: &str) -> Oid {
        let workdir = repo.workdir().unwrap();
        std::fs::write(workdir.join(file), content).unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(Path::new(file)).unwrap();
        index.write().unwrap();
        let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
        let parents: Vec<git2::Commit> = repo
            .head()
            .ok()
            .and_then(|h| h.peel_to_commit().ok())
            .into_iter()
            .collect();
        let parent_refs: Vec<&git2::Commit> = parents.iter().collect();
        repo.commit(Some("HEAD"), &sig(), &sig(), content, &tree, &parent_refs)
            .unwrap()
    }

    fn push_main(repo: &Repository) {
        repo.find_remote("origin")
            .unwrap()
            .push(&["refs/heads/main:refs/heads/main"], None)
            .unwrap();
    }

    fn remote_main(w: &World) -> Oid {
        Repository::open_bare(&w.remote)
            .unwrap()
            .refname_to_id("refs/heads/main")
            .unwrap()
    }

    fn head(repo: &Repository) -> Oid {
        repo.head().unwrap().target().unwrap()
    }

    /// A bare remote with one commit on main, cloned as `a` and `b`.
    fn world() -> World {
        let dir = TempDir::new().unwrap();
        let remote = dir.path().join("remote.git");
        Repository::init_opts(
            &remote,
            RepositoryInitOptions::new().bare(true).initial_head("main"),
        )
        .unwrap();

        let open = |name: &str| {
            let path = dir.path().join(name);
            let repo =
                Repository::init_opts(&path, RepositoryInitOptions::new().initial_head("main"))
                    .unwrap();
            repo.remote("origin", remote.to_str().unwrap()).unwrap();
            let mut cfg = repo.config().unwrap();
            cfg.set_str("user.name", "Resh Test").unwrap();
            cfg.set_str("user.email", "test@example.invalid").unwrap();
            repo
        };
        let a = open("a");
        commit(&a, "base.txt", "base");
        push_main(&a);

        let b = open("b");
        b.find_remote("origin")
            .unwrap()
            .fetch(&["refs/heads/main:refs/remotes/origin/main"], None, None)
            .unwrap();
        let base = b.refname_to_id("refs/remotes/origin/main").unwrap();
        b.reference("refs/heads/main", base, true, "test").unwrap();
        b.set_head("refs/heads/main").unwrap();
        b.checkout_head(Some(git2::build::CheckoutBuilder::default().force()))
            .unwrap();
        World {
            _dir: dir,
            remote,
            a,
            b,
        }
    }

    fn sync(repo: &Repository, extra: &[(&str, &str)]) -> Result<Value, GitError> {
        let mut args = json!({ "path": repo.workdir().unwrap().to_string_lossy() });
        for (k, v) in extra {
            args[*k] = json!(v);
        }
        let h = GitHandle {
            alias: "sync-test".to_string(),
        };
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(h.sync(args))
    }

    #[test]
    fn ahead_only_pushes_and_reports_no_integration() {
        let w = world();
        let local = commit(&w.b, "b.txt", "local work");
        let out = sync(&w.b, &[]).unwrap();
        assert_eq!(out["status"], "success");
        assert_eq!(out["integration"]["status"], "up_to_date");
        assert_eq!(out["integration"]["mode"], "rebase");
        assert_eq!(out["push_result"]["status"], "pushed");
        assert_eq!(remote_main(&w), local);
    }

    #[test]
    fn behind_only_fast_forwards_for_every_strategy() {
        for strategy in ["rebase", "merge", "ff_only"] {
            let w = world();
            let upstream = commit(&w.a, "a.txt", "upstream work");
            push_main(&w.a);
            let out = sync(&w.b, &[("pull_strategy", strategy)]).unwrap();
            assert_eq!(out["integration"]["status"], "fast_forward", "{strategy}");
            assert_eq!(out["integration"]["mode"], strategy);
            assert_eq!(head(&w.b), upstream);
            assert!(w.b.workdir().unwrap().join("a.txt").exists());
            assert_eq!(remote_main(&w), upstream);
        }
    }

    #[test]
    fn divergent_history_is_integrated_by_strategy() {
        for strategy in ["rebase", "merge", "ff_only"] {
            let w = world();
            let upstream = commit(&w.a, "a.txt", "upstream work");
            push_main(&w.a);
            let local = commit(&w.b, "b.txt", "local work");

            let result = sync(&w.b, &[("pull_strategy", strategy)]);
            if strategy == "ff_only" {
                assert!(
                    matches!(result, Err(GitError::SyncNonFastForward)),
                    "{result:?}"
                );
                assert_eq!(remote_main(&w), upstream, "remote unchanged");
                assert_eq!(head(&w.b), local, "local commit kept");
                continue;
            }
            let v = result.unwrap();
            let want = if strategy == "merge" {
                "merged"
            } else {
                "rebased"
            };
            assert_eq!(v["integration"]["status"], want, "{v}");
            let new_head = head(&w.b);
            assert_eq!(remote_main(&w), new_head, "{strategy}: pushed");
            assert!(w.b.graph_descendant_of(new_head, upstream).unwrap());
            let tip = w.b.find_commit(new_head).unwrap();
            assert_eq!(tip.parent_count(), if strategy == "merge" { 2 } else { 1 });
            assert!(w.b.workdir().unwrap().join("a.txt").exists());
            assert!(w.b.workdir().unwrap().join("b.txt").exists());
        }
    }

    #[test]
    fn conflicting_divergence_is_rejected_without_touching_files() {
        for strategy in ["merge", "rebase"] {
            let w = world();
            let upstream = commit(&w.a, "base.txt", "upstream edit");
            push_main(&w.a);
            let local = commit(&w.b, "base.txt", "local edit");
            let err = sync(&w.b, &[("pull_strategy", strategy)]).unwrap_err();
            match &err {
                GitError::SyncConflict { paths, in_progress } => {
                    assert_eq!(paths, &["base.txt".to_string()], "{strategy}");
                    assert!(!in_progress);
                }
                other => panic!("{strategy}: {other:?}"),
            }
            assert_eq!(
                std::fs::read_to_string(w.b.workdir().unwrap().join("base.txt")).unwrap(),
                "local edit"
            );
            assert_eq!(w.b.state(), git2::RepositoryState::Clean, "{strategy}");
            assert_eq!(head(&w.b), local, "{strategy}");
            assert_eq!(remote_main(&w), upstream, "{strategy}: nothing pushed");
            assert!(w.b.statuses(None).unwrap().is_empty(), "{strategy}");
        }
    }

    #[test]
    fn failed_fetch_fails_without_push() {
        let w = world();
        let local = commit(&w.b, "b.txt", "local work");
        let before = remote_main(&w);
        w.b.remote_set_url("origin", "/nonexistent/resh-test-remote.git")
            .unwrap();
        let err = sync(&w.b, &[]).unwrap_err();
        assert!(matches!(err, GitError::SyncPullFailed { .. }), "{err:?}");
        assert_eq!(remote_main(&w), before);
        assert_eq!(head(&w.b), local);
    }

    #[test]
    fn failed_push_is_an_error() {
        let w = world();
        commit(&w.b, "b.txt", "local work");
        let before = remote_main(&w);
        w.b.remote_set_pushurl("origin", Some("/nonexistent/resh-test-remote.git"))
            .unwrap();
        let err = sync(&w.b, &[]).unwrap_err();
        assert!(
            matches!(
                err,
                GitError::SyncPushFailed { .. } | GitError::SyncPushRejected { .. }
            ),
            "{err:?}"
        );
        assert_eq!(remote_main(&w), before);
    }

    #[test]
    fn different_remote_branch_is_rejected() {
        let w = world();
        commit(&w.b, "b.txt", "local work");
        let before = remote_main(&w);
        let err = sync(&w.b, &[("remote_branch", "release")]).unwrap_err();
        assert!(matches!(err, GitError::InvalidSyncConfig { .. }), "{err:?}");
        assert_eq!(remote_main(&w), before);
    }

    #[test]
    fn stash_is_restored_when_sync_fails() {
        let w = world();
        commit(&w.a, "a.txt", "upstream work");
        push_main(&w.a);
        commit(&w.b, "b.txt", "local work");
        let dirty = w.b.workdir().unwrap().join("base.txt");
        std::fs::write(&dirty, "uncommitted edit").unwrap();

        assert!(
            sync(
                &w.b,
                &[("stash_uncommitted", "true"), ("pull_strategy", "ff_only")]
            )
            .is_err()
        );
        assert_eq!(std::fs::read_to_string(&dirty).unwrap(), "uncommitted edit");
        let mut stashes = 0;
        let mut b = Repository::open(w.b.workdir().unwrap()).unwrap();
        b.stash_foreach(|_, _, _| {
            stashes += 1;
            true
        })
        .unwrap();
        assert_eq!(stashes, 0, "stash was popped back");
    }

    #[test]
    fn dry_run_describes_fast_forward_only() {
        let w = world();
        let out = sync(&w.b, &[("dry_run", "true"), ("pull_strategy", "merge")]).unwrap();
        let actions = out["actions"].to_string();
        assert!(
            actions.contains("fast-forward") && actions.contains("pull_strategy=merge"),
            "{actions}"
        );
        assert!(!actions.contains("Would merge") && !actions.contains("Would rebase"));
    }
}

/// Stage 3 (SEC-08): an explicit git `timeout_ms` is refused, because the
/// blocking libgit2 call it would bound cannot be interrupted. Runs against
/// a temporary local repository only.
#[cfg(test)]
mod known_hosts_dispatch_tests {
    use super::*;
    use git2::RepositoryInitOptions;
    use tempfile::TempDir;

    const UNREACHABLE_SSH: &str = "ssh://git@127.0.0.1:1/repo.git";
    const ED25519_BLOB: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    /// Runs `verb` through `Handle::call`. On failure returns the error code
    /// and message the CLI would print.
    fn call(alias: &str, verb: &str, pairs: &[(&str, &str)]) -> Result<Status, (String, String)> {
        let h = GitHandle {
            alias: alias.to_string(),
        };
        let args: Args = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let mut i: &[u8] = &[];
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let mut io = IoStreams {
            stdin: &mut i,
            stdout: &mut o,
            stderr: &mut e,
        };
        let st = h
            .call(verb, &args, &mut io)
            .unwrap_or_else(|e| panic!("{verb}: {e:#}"));
        if st.ok {
            return Ok(st);
        }
        // Failures are reported as `[<code>] <message>`.
        let reason = st.reason.clone().unwrap_or_default();
        let rest = reason.strip_prefix('[').expect("coded failure");
        let (code, msg) = rest.split_once("] ").expect("coded failure");
        Err((code.to_string(), msg.to_string()))
    }

    fn commit(repo: &Repository, file: &str) {
        let workdir = repo.workdir().unwrap();
        std::fs::write(workdir.join(file), file).unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(Path::new(file)).unwrap();
        index.write().unwrap();
        let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
        let sig = git2::Signature::now("Resh Test", "test@example.invalid").unwrap();
        let parent = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
        let parents: Vec<&git2::Commit> = parent.iter().collect();
        repo.commit(Some("HEAD"), &sig, &sig, file, &tree, &parents)
            .unwrap();
    }

    struct Fixture {
        dir: TempDir,
        work: PathBuf,
    }

    impl Fixture {
        fn work_str(&self) -> String {
            self.work.to_string_lossy().to_string()
        }
        fn path(&self, name: &str) -> String {
            self.dir.path().join(name).to_string_lossy().to_string()
        }
    }

    /// A working repository on `main` with one commit whose `origin` is
    /// `origin_url`, or, when None, a local bare repository reached through a
    /// file:// URL (already holding `main`).
    fn fixture(origin_url: Option<&str>) -> Fixture {
        let dir = TempDir::new().unwrap();
        let work = dir.path().join("work");
        let repo = Repository::init_opts(&work, RepositoryInitOptions::new().initial_head("main"))
            .unwrap();
        let mut cfg = repo.config().unwrap();
        cfg.set_str("user.name", "Resh Test").unwrap();
        cfg.set_str("user.email", "test@example.invalid").unwrap();
        commit(&repo, "base.txt");
        match origin_url {
            Some(url) => {
                repo.remote("origin", url).unwrap();
            }
            None => {
                let bare = dir.path().join("remote.git");
                Repository::init_opts(
                    &bare,
                    RepositoryInitOptions::new().bare(true).initial_head("main"),
                )
                .unwrap();
                let url = format!("file://{}", bare.display());
                let mut remote = repo.remote("origin", &url).unwrap();
                remote
                    .push(&["refs/heads/main:refs/heads/main"], None)
                    .unwrap();
            }
        }
        Fixture { dir, work }
    }

    /// Every verb that reaches a remote, with the arguments to reach the
    /// fixture's origin (clone gets `clone_url`).
    fn remote_verbs<'a>(
        f: &Fixture,
        clone_url: &'a str,
    ) -> Vec<(&'static str, Vec<(&'a str, String)>)> {
        vec![
            (
                "clone",
                vec![("url", clone_url.to_string()), ("path", f.path("clone"))],
            ),
            ("pull", vec![("path", f.work_str())]),
            (
                "push",
                vec![("path", f.work_str()), ("branch", "main".into())],
            ),
            ("sync", vec![("path", f.work_str())]),
        ]
    }

    fn run_with(
        alias: &str,
        verb: &str,
        base: &[(&str, String)],
        known_hosts: Option<&str>,
    ) -> Result<Status, (String, String)> {
        let mut pairs: Vec<(&str, &str)> = base.iter().map(|(k, v)| (*k, v.as_str())).collect();
        if let Some(kh) = known_hosts {
            pairs.push(("known_hosts_path", kh));
        }
        call(alias, verb, &pairs)
    }

    #[test]
    fn empty_known_hosts_path_is_an_invalid_argument() {
        let f = fixture(Some(UNREACHABLE_SSH));
        let expected = [
            ("clone", "git.invalid_clone_config"),
            ("pull", "git.invalid_pull_config"),
            ("push", "git.invalid_push_config"),
            ("sync", "git.sync_invalid_config"),
        ];
        for ((verb, base), (_, code)) in remote_verbs(&f, UNREACHABLE_SSH).iter().zip(expected) {
            let (got, msg) = run_with("kh-empty", verb, base, Some("")).unwrap_err();
            assert_eq!(got, code, "{verb}: {msg}");
            assert!(
                msg.contains("known_hosts_path cannot be empty"),
                "{verb}: {msg}"
            );
        }
    }

    #[test]
    fn missing_file_refuses_every_ssh_verb() {
        let f = fixture(Some(UNREACHABLE_SSH));
        let missing = f.path("no-such-known_hosts");
        for (verb, base) in remote_verbs(&f, UNREACHABLE_SSH) {
            let (code, msg) = run_with("kh-missing", verb, &base, Some(&missing)).unwrap_err();
            assert_eq!(code, "git.host_key_verification_failed", "{verb}: {msg}");
            assert!(
                msg.contains("cannot read known_hosts file"),
                "{verb}: {msg}"
            );
            assert!(msg.contains("[127.0.0.1]:1"), "{verb}: {msg}");
        }
        assert!(
            !Path::new(&f.path("clone")).exists(),
            "clone created its target"
        );
    }

    #[test]
    fn unreadable_file_refuses_every_ssh_verb() {
        let f = fixture(Some(UNREACHABLE_SSH));
        // A directory cannot be read as a file, even by root.
        let unreadable = f.path("kh-dir");
        std::fs::create_dir(&unreadable).unwrap();
        for (verb, base) in remote_verbs(&f, UNREACHABLE_SSH) {
            let (code, msg) =
                run_with("kh-unreadable", verb, &base, Some(&unreadable)).unwrap_err();
            assert_eq!(code, "git.host_key_verification_failed", "{verb}: {msg}");
            assert!(
                msg.contains("cannot read known_hosts file"),
                "{verb}: {msg}"
            );
        }
    }

    #[test]
    fn unknown_host_is_refused_before_connecting() {
        let f = fixture(Some(UNREACHABLE_SSH));
        let kh = f.path("known_hosts");
        // Port 22 entry and a CA line only: neither covers [127.0.0.1]:1.
        std::fs::write(
            &kh,
            format!(
                "127.0.0.1 ssh-ed25519 {ED25519_BLOB}\n@cert-authority * ssh-ed25519 {ED25519_BLOB}\n"
            ),
        )
        .unwrap();
        for (verb, base) in remote_verbs(&f, UNREACHABLE_SSH) {
            let (code, msg) = run_with("kh-unknown", verb, &base, Some(&kh)).unwrap_err();
            assert_eq!(code, "git.host_key_verification_failed", "{verb}: {msg}");
            assert!(
                msg.contains("CA-signed host keys are not supported"),
                "{verb}: {msg}"
            );
        }
        std::fs::write(&kh, format!("other.example ssh-ed25519 {ED25519_BLOB}\n")).unwrap();
        for (verb, base) in remote_verbs(&f, UNREACHABLE_SSH) {
            let (code, msg) = run_with("kh-unknown", verb, &base, Some(&kh)).unwrap_err();
            assert_eq!(code, "git.host_key_verification_failed", "{verb}: {msg}");
            assert!(msg.contains("is not listed"), "{verb}: {msg}");
        }
    }

    #[test]
    fn listed_host_proceeds_to_connect() {
        let f = fixture(Some(UNREACHABLE_SSH));
        let kh = f.path("known_hosts");
        std::fs::write(&kh, format!("[127.0.0.1]:1 ssh-ed25519 {ED25519_BLOB}\n")).unwrap();
        let expected = [
            ("clone", "git.clone_failed"),
            ("pull", "git.pull_fetch_failed"),
            ("push", "git.push_failed"),
            ("sync", "git.sync_pull_failed"),
        ];
        for ((verb, base), (_, want)) in remote_verbs(&f, UNREACHABLE_SSH).iter().zip(expected) {
            // Nothing listens on port 1, so the connection itself fails; the
            // known_hosts check did not refuse it.
            let (code, msg) = run_with("kh-listed", verb, base, Some(&kh)).unwrap_err();
            assert_eq!(code, want, "{verb}: {msg}");
            assert!(!msg.contains("host key"), "{verb}: {msg}");
        }
    }

    #[test]
    fn option_is_ignored_for_file_remotes() {
        let f = fixture(None);
        let missing = f.path("no-such-known_hosts");
        let work = Repository::open(&f.work).unwrap();
        for known_hosts in [None, Some(missing.as_str())] {
            commit(
                &work,
                if known_hosts.is_some() {
                    "with.txt"
                } else {
                    "without.txt"
                },
            );
            let base = [("path", f.work_str()), ("branch", "main".to_string())];
            for verb in ["push", "pull", "sync"] {
                let status = run_with("kh-file", verb, &base, known_hosts)
                    .unwrap_or_else(|e| panic!("{verb} with {known_hosts:?}: {e:?}"));
                assert!(status.ok, "{verb} with {known_hosts:?}");
            }
        }
        // Both commits reached the file:// remote.
        let bare = Repository::open_bare(f.dir.path().join("remote.git")).unwrap();
        assert_eq!(
            bare.refname_to_id("refs/heads/main").unwrap(),
            work.head().unwrap().target().unwrap()
        );
    }

    #[test]
    fn option_is_ignored_for_https_clone() {
        let f = fixture(Some(UNREACHABLE_SSH));
        let missing = f.path("no-such-known_hosts");
        // Nothing listens on port 1: the failure is the connection, not the
        // (missing) known_hosts file, which https never reads.
        let (code, msg) = call(
            "kh-https",
            "clone",
            &[
                ("url", "https://127.0.0.1:1/repo.git"),
                ("path", &f.path("clone")),
                ("known_hosts_path", &missing),
            ],
        )
        .unwrap_err();
        assert_eq!(code, "git.clone_failed", "{msg}");
        assert!(!msg.contains("known_hosts"), "{msg}");
    }
}
