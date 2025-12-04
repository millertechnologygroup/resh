# Git Handle Documentation

The Git handle provides tools for managing Git repositories in Resource Shell. This handle supports common Git operations like cloning, pulling, pushing, branching, and more.

## URL Format

Use the Git handle with this format:
```
git://alias.verb
```

Where:
- `alias` is your chosen name for the Git connection (e.g., "default", "main", "deploy")
- `verb` is the operation you want to perform

## Available Verbs

The Git handle supports these operations:

- **clone** - Clone a remote repository
- **pull** - Pull changes from remote
- **push** - Push changes to remote
- **status** - Get detailed repository status
- **branch** - Manage branches
- **commit** - Create commits
- **diff** - Show differences between commits, branches, or working tree
- **tag** - Manage tags
- **merge** - Merge branches
- **rebase** - Rebase branches
- **sync** - Synchronize with remote (fetch + merge/rebase + push)
- **status_summary** - Get summary of repository state
- **status_short** - Get compact status string for shell prompts

## Branch Operations

### List Branches

List all branches in the repository:

**Example:**
```bash
resh "git://default.branch" "path=/tmp/test_repo" "action=list"
```

**Output:**
```json
{
  "backend": "git",
  "alias": "default",
  "action": "list",
  "branches": [
    {
      "name": "main",
      "is_current": true,
      "is_remote": false,
      "head": "abc123def456..."
    }
  ]
}
```

### Create Branch

Create a new branch:

**Example:**
```bash
resh "git://default.branch" "path=/tmp/test_repo" "action=create" "name=feature-test"
```

**Output:**
```json
{
  "backend": "git",
  "action": "create",
  "status": "created",
  "branch": {
    "name": "feature-test"
  }
}
```

### Checkout Branch

Switch to an existing branch:

**Example:**
```bash
resh "git://default.branch" "path=/tmp/test_repo" "action=checkout" "name=feature-test"
```

**Output:**
```json
{
  "action": "checkout",
  "status": "checked_out",
  "branch": {
    "name": "feature-test",
    "was_current": false
  }
}
```

### Delete Branch

Remove a branch:

**Example:**
```bash
resh "git://default.branch" "path=/tmp/test_repo" "action=delete" "name=feature-test"
```

**Output:**
```json
{
  "action": "delete",
  "status": "deleted",
  "branch": {
    "name": "feature-test"
  }
}
```

### Rename Branch

Rename an existing branch:

**Example:**
```bash
resh "git://default.branch" "path=/tmp/test_repo" "action=rename" "name=old-name" "new_name=new-name"
```

**Output:**
```json
{
  "action": "rename",
  "status": "renamed",
  "branch": {
    "old_name": "old-name",
    "new_name": "new-name"
  }
}
```

## Diff Operations

### Working Directory vs Index

Show differences between working directory and staging area (default):

**Example:**
```bash
resh "git://default.diff" "path=/tmp/test_repo"
```

**Output:**
```json
{
  "backend": "git",
  "path": "/tmp/test_repo",
  "mode": "workdir_vs_index",
  "from": "INDEX",
  "to": "WORKDIR",
  "summary": {
    "files_changed": 1,
    "insertions": 5,
    "deletions": 2,
    "truncated": false
  },
  "files": [
    {
      "status": "modified",
      "old_path": "README.md",
      "new_path": "README.md",
      "is_binary": false,
      "hunks": [
        {
          "old_start": 1,
          "old_lines": 1,
          "new_start": 1,
          "new_lines": 1,
          "lines": [
            {
              "type": "delete",
              "content": "Initial content"
            },
            {
              "type": "add",
              "content": "Modified content"
            }
          ]
        }
      ]
    }
  ]
}
```

## Tag Operations

### List Tags

List all tags in the repository:

**Example:**
```bash
resh "git://test.tag" "path=/tmp/test_repo" "action=list"
```

**Output:**
```json
{
  "count": 0,
  "tags": []
}
```

### Create Lightweight Tag

Create a lightweight tag:

**Example:**
```bash
resh "git://test.tag" "path=/tmp/test_repo" "action=create" "name=v1.0.0" "annotated=false"
```

**Output:**
```json
{
  "status": "created",
  "name": "v1.0.0",
  "annotated": false
}
```

### Create Annotated Tag

Create an annotated tag with a message:

**Example:**
```bash
resh "git://test.tag" "path=/tmp/test_repo" "action=create" "name=v1.1.0" "annotated=true" "message=Release 1.1.0"
```

**Output:**
```json
{
  "status": "created",
  "name": "v1.1.0",
  "annotated": true,
  "message": "Release 1.1.0"
}
```

## Status Operations

### Status Short

Get a compact status string suitable for shell prompts:

**Example:**
```bash
resh "git://default.status_short" "path=/tmp/test_repo"
```

**Basic usage with clean repository:**
```bash
resh "git://default.status_short" "path=/tmp/test_repo"
```

**With custom symbols:**
```bash
resh "git://default.status_short" "path=/tmp/test_repo" 'symbols={"dirty":"+","ahead":">>","behind":"<<","no_upstream":"?"}'
```

**With include flags disabled:**
```bash
resh "git://default.status_short" "path=/tmp/test_repo" "include_dirty=false" "include_remote=false"
```

**With timeout:**
```bash
resh "git://default.status_short" "path=/tmp/test_repo" "timeout_ms=500"
```

**Output:**
```json
{
  "backend": "git",
  "alias": "default",
  "path": "/tmp/test_repo",
  "action": "status_short",
  "summary": "main",
  "components": {
    "branch": "main",
    "detached": false,
    "ahead": 0,
    "behind": 0,
    "has_upstream": false,
    "clean": true,
    "has_conflicts": false
  }
}
```

## Clone Operations

### Clone Repository

Clone a remote repository to a local directory:

**Example:**
```bash
resh "git://default.clone" "url=https://github.com/user/repo.git" "path=/tmp/cloned_repo"
```

**With branch specification:**
```bash
resh "git://default.clone" "url=https://github.com/user/repo.git" "path=/tmp/cloned_repo" "branch=develop"
```

**With depth (shallow clone):**
```bash
resh "git://default.clone" "url=https://github.com/user/repo.git" "path=/tmp/cloned_repo" "depth=1"
```

**Output:**
```json
{
  "backend": "git",
  "alias": "default",
  "url": "https://github.com/user/repo.git",
  "path": "/tmp/cloned_repo",
  "branch": "main",
  "status": "cloned"
}
```

## Pull Operations

### Pull Changes

Pull changes from the remote repository:

**Example:**
```bash
resh "git://default.pull" "path=/tmp/repo"
```

**With specific remote and branch:**
```bash
resh "git://default.pull" "path=/tmp/repo" "remote=origin" "branch=main"
```

**With rebase:**
```bash
resh "git://default.pull" "path=/tmp/repo" "rebase=true"
```

**Output:**
```json
{
  "backend": "git",
  "alias": "default",
  "path": "/tmp/repo",
  "remote": "origin",
  "branch": "main",
  "status": "updated",
  "rebase": false,
  "ff_only": false,
  "ahead_by": 0,
  "behind_by": 3,
  "commits_fetched": 3
}
```

## Push Operations

### Push Changes

Push local changes to the remote repository:

**Example:**
```bash
resh "git://default.push" "path=/tmp/repo"
```

**Push specific branch:**
```bash
resh "git://default.push" "path=/tmp/repo" "branch=feature-branch"
```

**Force push:**
```bash
resh "git://default.push" "path=/tmp/repo" "force=true"
```

**Push and set upstream:**
```bash
resh "git://default.push" "path=/tmp/repo" "set_upstream=true"
```

**Output:**
```json
{
  "backend": "git",
  "alias": "default",
  "path": "/tmp/repo",
  "remote": "origin",
  "status": "pushed",
  "branches": [
    {
      "name": "main",
      "status": "pushed",
      "ahead_by": 0,
      "behind_by": 0
    }
  ]
}
```

## Status Operations

### Detailed Status

Get comprehensive repository status information:

**Example:**
```bash
resh "git://default.status" "path=/tmp/repo"
```

**With specific options:**
```bash
resh "git://default.status" "path=/tmp/repo" "include_ignored=true" "include_untracked=true"
```

**Output:**
```json
{
  "backend": "git",
  "alias": "default",
  "path": "/tmp/repo",
  "branch": {
    "name": "main",
    "detached": false,
    "upstream": {
      "name": "origin/main",
      "ahead_by": 1,
      "behind_by": 0
    }
  },
  "working_tree": {
    "clean": false,
    "staged_count": 2,
    "unstaged_count": 1,
    "untracked_count": 0,
    "conflicts_count": 0,
    "files": [
      {
        "path": "README.md",
        "status": "modified",
        "staged": true,
        "unstaged": false
      }
    ]
  },
  "in_progress": {
    "merge": false,
    "rebase": false,
    "cherry_pick": false,
    "revert": false,
    "bisect": false
  }
}
```

## Commit Operations

### Create Commit

Create a new commit with staged changes:

**Example:**
```bash
resh "git://default.commit" "path=/tmp/repo" "message=Fix bug in user authentication"
```

**Commit all tracked files:**
```bash
resh "git://default.commit" "path=/tmp/repo" "message=Update documentation" "all=true"
```

**Commit specific files:**
```bash
resh "git://default.commit" "path=/tmp/repo" "message=Fix typos" 'paths=["README.md","docs/guide.md"]'
```

**With custom author:**
```bash
resh "git://default.commit" "path=/tmp/repo" "message=Initial commit" "author_name=John Doe" "author_email=john@example.com"
```

**Output:**
```json
{
  "backend": "git",
  "alias": "default",
  "path": "/tmp/repo",
  "action": "commit",
  "commit": {
    "oid": "abc123def456...",
    "message": "Fix bug in user authentication",
    "author": {
      "name": "John Doe",
      "email": "john@example.com"
    },
    "committer": {
      "name": "John Doe",
      "email": "john@example.com"
    },
    "amend": false,
    "allow_empty": false
  },
  "stats": {
    "staged_files": 2,
    "insertions": 15,
    "deletions": 8
  }
}
```

## Merge Operations

### Merge Branch

Merge another branch into the current branch:

**Example:**
```bash
resh "git://default.merge" "path=/tmp/repo" "branch=feature-branch"
```

**With specific strategy:**
```bash
resh "git://default.merge" "path=/tmp/repo" "branch=feature-branch" "strategy=recursive"
```

**Fast-forward only:**
```bash
resh "git://default.merge" "path=/tmp/repo" "branch=feature-branch" "ff_only=true"
```

**Output:**
```json
{
  "backend": "git",
  "alias": "default",
  "path": "/tmp/repo",
  "action": "merge",
  "source_branch": "feature-branch",
  "target_branch": "main",
  "status": "merged",
  "merge_commit": "def456abc789...",
  "fast_forward": false,
  "conflicts": []
}
```

## Rebase Operations

### Rebase Branch

Rebase current branch onto another branch:

**Example:**
```bash
resh "git://default.rebase" "path=/tmp/repo" "onto=main"
```

**Interactive rebase:**
```bash
resh "git://default.rebase" "path=/tmp/repo" "onto=main" "interactive=true"
```

**Continue rebase:**
```bash
resh "git://default.rebase" "path=/tmp/repo" "operation=continue"
```

**Abort rebase:**
```bash
resh "git://default.rebase" "path=/tmp/repo" "operation=abort"
```

**Output:**
```json
{
  "backend": "git",
  "alias": "default",
  "path": "/tmp/repo",
  "action": "rebase",
  "onto": "main",
  "status": "completed",
  "commits_rebased": 3,
  "conflicts": []
}
```

## Sync Operations

### Synchronize Repository

Synchronize local repository with remote (fetch + merge/rebase + optional push):

**Example:**
```bash
resh "git://default.sync" "path=/tmp/repo"
```

**With push:**
```bash
resh "git://default.sync" "path=/tmp/repo" "push=true"
```

**With rebase strategy:**
```bash
resh "git://default.sync" "path=/tmp/repo" "pull_strategy=rebase" "push=true"
```

**Output:**
```json
{
  "backend": "git",
  "alias": "default",
  "path": "/tmp/repo",
  "action": "sync",
  "remote": "origin",
  "branch": "main",
  "remote_branch": "main",
  "pull_strategy": "merge",
  "status": "success",
  "integration": {
    "status": "merged",
    "commits_rebased": 0
  },
  "push": {
    "attempted": true,
    "status": "pushed",
    "ahead_by": 0
  },
  "stash": {
    "created": false,
    "restored": false,
    "conflicts": false
  }
}
```

### Status Summary

Get high-level repository state summary with recommendations:

**Example:**
```bash
resh "git://default.status_summary" "path=/tmp/repo"
```

**With specific branch:**
```bash
resh "git://default.status_summary" "path=/tmp/repo" "branch=develop"
```

**Output:**
```json
{
  "backend": "git",
  "alias": "default",
  "path": "/tmp/repo",
  "action": "status_summary",
  "branch": {
    "name": "main",
    "detached": false,
    "head": "abc123def456..."
  },
  "working_tree": {
    "clean": false,
    "staged_count": 1,
    "unstaged_count": 2,
    "conflicts_count": 0,
    "untracked_count": 1
  },
  "sync": {
    "state": "ahead_only",
    "ahead_by": 2,
    "behind_by": 0,
    "has_upstream": true
  },
  "summary": {
    "state": "committed_but_ahead",
    "has_uncommitted_changes": true,
    "can_commit": true,
    "needs_pull": false,
    "needs_push": true,
    "blocked_by_conflicts": false
  },
  "recommendations": {
    "primary_action": "push",
    "actions": ["commit_changes", "push_commits"],
    "description": "Push your commits to the remote repository."
  }
}
```

## Configuration Parameters

### Common Parameters

- **path** (required) - Path to the Git repository
- **timeout_ms** (optional) - Operation timeout in milliseconds

### Branch Parameters

- **action** - Operation to perform: `list`, `create`, `delete`, `rename`, `checkout`
- **name** - Branch name for create, delete, checkout, or rename operations
- **new_name** - New name for rename operations
- **start_point** (optional) - Starting commit for new branch
- **local_only** (optional) - Show only local branches when listing
- **remote_only** (optional) - Show only remote branches when listing
- **all** (optional) - Show all branches (local and remote) when listing
- **force** (optional) - Force branch operations
- **track** (optional) - Set up tracking for new branch
- **remote** (optional) - Remote name for tracking

### Diff Parameters

- **mode** (optional) - Diff mode: `workdir_vs_index` (default), `index_vs_head`, `head_vs_workdir`, `commit_vs_commit`, `commit_vs_workdir`, `commit_vs_index`
- **from** (optional) - Source commit/reference for comparison
- **to** (optional) - Target commit/reference for comparison
- **paths** (optional) - Specific file paths to diff
- **unified** (optional) - Number of context lines
- **ignore_whitespace** (optional) - Ignore whitespace changes
- **ignore_whitespace_change** (optional) - Ignore whitespace amount changes
- **ignore_whitespace_eol** (optional) - Ignore end-of-line whitespace
- **detect_renames** (optional) - Detect file renames
- **rename_threshold** (optional) - Rename detection threshold (0-100)
- **binary** (optional) - Include binary file diffs
- **max_files** (optional) - Maximum number of files to process
- **max_hunks** (optional) - Maximum number of hunks per file

### Tag Parameters

- **action** - Operation to perform: `list`, `create`, `delete`
- **name** - Tag name for create or delete operations
- **names** (optional) - Multiple tag names for batch operations
- **pattern** (optional) - Pattern for filtering tags when listing
- **sort** (optional) - Sort order: `name` (default), `version`, `tagger_date`, `committer_date`
- **annotated** (optional) - Create annotated tag (true) or lightweight tag (false)
- **message** (optional) - Message for annotated tags
- **target** (optional) - Target commit for tag
- **force** (optional) - Force tag creation (overwrite existing)
- **author_name** (optional) - Author name for annotated tags
- **author_email** (optional) - Author email for annotated tags
- **timestamp** (optional) - Custom timestamp for tag

### Status Short Parameters

- **branch** (optional) - Focus on specific branch
- **remote** (optional) - Remote name to compare against
- **include_remote** (optional) - Include remote tracking information
- **include_dirty** (optional) - Include working tree dirty state
- **include_conflicts** (optional) - Include merge conflict indicators
- **symbols** (optional) - Custom symbols for status indicators:
  - **detached** - Symbol for detached HEAD state
  - **ahead** - Symbol for ahead commits
  - **behind** - Symbol for behind commits  
  - **dirty** - Symbol for dirty working tree
  - **conflict** - Symbol for merge conflicts
  - **no_upstream** - Symbol for no upstream branch

### Clone Parameters

- **url** (required) - Remote repository URL
- **path** (required) - Local directory path for cloning
- **branch** (optional) - Specific branch to clone
- **depth** (optional) - Shallow clone depth (number of commits)
- **recursive** (optional) - Clone submodules recursively
- **ssh_key** (optional) - SSH private key path for authentication
- **username** (optional) - Username for HTTPS authentication
- **password** (optional) - Password for HTTPS authentication
- **token** (optional) - Personal access token for HTTPS authentication

### Pull Parameters

- **path** (required) - Repository path
- **remote** (optional) - Remote name (default: origin)
- **branch** (optional) - Branch name to pull
- **rebase** (optional) - Use rebase instead of merge
- **ff_only** (optional) - Only allow fast-forward merges
- **depth** (optional) - Limit fetch depth
- **prune** (optional) - Remove tracking branches that no longer exist
- **ssh_key** (optional) - SSH private key path
- **username** (optional) - Username for HTTPS authentication
- **password** (optional) - Password for HTTPS authentication
- **token** (optional) - Personal access token

### Push Parameters

- **path** (required) - Repository path
- **remote** (optional) - Remote name (default: origin)
- **branch** (optional) - Specific branch to push
- **branches** (optional) - Multiple branches to push
- **tags** (optional) - Push tags along with commits
- **force** (optional) - Force push (overwrite remote)
- **ff_only** (optional) - Only allow fast-forward pushes
- **set_upstream** (optional) - Set upstream tracking for branch
- **ssh_key** (optional) - SSH private key path
- **username** (optional) - Username for HTTPS authentication
- **password** (optional) - Password for HTTPS authentication
- **token** (optional) - Personal access token

### Status Parameters

- **path** (required) - Repository path
- **include_ignored** (optional) - Include ignored files in status
- **include_untracked** (optional) - Include untracked files
- **include_staged** (optional) - Include staged changes
- **include_branch** (optional) - Include branch information
- **include_remote** (optional) - Include remote tracking info

### Commit Parameters

- **path** (required) - Repository path
- **message** (optional) - Commit message
- **all** (optional) - Stage and commit all tracked files
- **paths** (optional) - Specific file paths to commit
- **allow_empty** (optional) - Allow empty commits
- **author_name** (optional) - Override author name
- **author_email** (optional) - Override author email
- **committer_name** (optional) - Override committer name
- **committer_email** (optional) - Override committer email
- **signoff** (optional) - Add signed-off-by line
- **amend** (optional) - Amend the last commit
- **no_edit** (optional) - Don't invoke editor for commit message
- **timestamp** (optional) - Custom timestamp for commit

### Merge Parameters

- **path** (required) - Repository path
- **branch** (required) - Branch to merge into current branch
- **strategy** (optional) - Merge strategy (recursive, octopus, ours, subtree)
- **ff_only** (optional) - Only allow fast-forward merges
- **no_commit** (optional) - Don't automatically commit merge
- **squash** (optional) - Squash merge (don't create merge commit)
- **message** (optional) - Custom merge commit message
- **abort_on_conflict** (optional) - Abort merge if conflicts occur

### Rebase Parameters

- **path** (required) - Repository path
- **operation** (optional) - Rebase operation: `start` (default), `continue`, `abort`
- **onto** (required for start) - Target branch or commit to rebase onto
- **upstream** (optional) - Upstream branch for rebase
- **interactive** (optional) - Enable interactive rebase
- **preserve_merges** (optional) - Preserve merge commits during rebase
- **force** (optional) - Force rebase even if branch is up to date
- **abort_on_conflict** (optional) - Abort rebase if conflicts occur

### Sync Parameters

- **path** (required) - Repository path
- **remote** (optional) - Remote name (default: origin)
- **branch** (optional) - Local branch name
- **remote_branch** (optional) - Remote branch name
- **pull_strategy** (optional) - Strategy for integrating changes: `merge` (default), `rebase`, `ff_only`
- **push** (optional) - Push changes after successful pull
- **push_tags** (optional) - Push tags along with commits
- **force_push** (optional) - Force push after sync
- **set_upstream** (optional) - Set upstream tracking
- **allow_uncommitted** (optional) - Allow sync with uncommitted changes
- **stash_uncommitted** (optional) - Stash uncommitted changes before sync
- **abort_on_conflict** (optional) - Abort sync if conflicts occur
- **dry_run** (optional) - Show what would be done without executing

### Status Summary Parameters

- **path** (required) - Repository path
- **branch** (optional) - Focus on specific branch
- **remote** (optional) - Remote name to compare against
- **include_remote** (optional) - Include remote sync information
- **include_recommendations** (optional) - Include recommended actions

## Authentication

For operations requiring authentication (clone, pull, push), you can provide:

- **ssh_key** - Path to SSH private key file
- **username** - Username for HTTPS authentication
- **password** - Password for HTTPS authentication
- **token** - Personal access token for HTTPS authentication

## Error Handling

The Git handle provides detailed error messages for common issues:

- Repository not found
- Authentication failures
- Network timeouts
- Merge conflicts
- Invalid configurations
- Permission errors

All operations return structured JSON responses with clear error codes and descriptive messages.

## Best Practices

1. **Use absolute paths** for repository paths to avoid confusion
2. **Set timeouts** for network operations to prevent hanging
3. **Use SSH keys** for automated operations instead of passwords
4. **Check status** before performing destructive operations
5. **Use status_short** in shell prompts for quick repository state
6. **Validate configurations** with dry-run operations when available

## Examples by Use Case

### Shell Prompt Integration

Use `status_short` to show Git status in your shell prompt:

```bash
# Basic status
resh "git://default.status_short" "path=$(pwd)"

# Custom symbols for better visibility
resh "git://default.status_short" "path=$(pwd)" 'symbols={"dirty":"*","ahead":"↑","behind":"↓"}'
```

### Development Workflow

```bash
# Check repository status
resh "git://default.status" "path=/project"

# Create and switch to feature branch
resh "git://default.branch" "path=/project" "action=create" "name=feature/new-feature"
resh "git://default.branch" "path=/project" "action=checkout" "name=feature/new-feature"

# Review changes before committing
resh "git://default.diff" "path=/project"

# Synchronize with remote
resh "git://default.sync" "path=/project" "push=true"
```

### Release Management

```bash
# Create release tag
resh "git://default.tag" "path=/project" "action=create" "name=v1.2.0" "annotated=true" "message=Release 1.2.0"

# List all tags
resh "git://default.tag" "path=/project" "action=list" "sort=version"
```