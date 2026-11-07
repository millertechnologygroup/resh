//! Integrating diverged history into the checked-out branch, for `pull`
//! and `sync`: a merge commit, or local commits replayed onto the upstream.
//!
//! The caller makes sure the branch is checked out and the tracked files
//! are unchanged. On a conflict with `abort_on_conflict` the repository is
//! left exactly as it was (HEAD, index and working tree); without it, the
//! merge or rebase is left in progress with the conflicts in the index and
//! the working tree.

use git2::{Oid, Repository, Signature};

/// How diverged history is integrated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Merge,
    Rebase,
}

/// What an integration produced.
#[derive(Debug)]
pub enum Outcome {
    /// A merge commit.
    Merged(Oid),
    /// The branch now ends at `head`; `commits` local commits were replayed.
    Rebased { head: Oid, commits: usize },
}

/// Why an integration did not complete.
#[derive(Debug)]
pub enum Failure {
    /// Conflicting changes in `paths`. `in_progress` is true when the merge
    /// or rebase was left in progress for manual resolution; otherwise the
    /// repository was restored.
    Conflict {
        paths: Vec<String>,
        in_progress: bool,
    },
    /// Untracked or local files would be overwritten; nothing changed.
    Dirty,
    /// Any other error, after the repository was restored as far as possible.
    Failed(String),
}

fn failed(what: &str, e: git2::Error) -> Failure {
    Failure::Failed(format!("{what}: {}", e.message()))
}

/// The paths of the conflict entries in `index`, sorted.
pub fn conflict_paths(index: &git2::Index) -> Vec<String> {
    let mut paths: Vec<String> = match index.conflicts() {
        Ok(conflicts) => conflicts
            .flatten()
            .filter_map(|c| {
                c.our
                    .or(c.their)
                    .or(c.ancestor)
                    .map(|e| String::from_utf8_lossy(&e.path).into_owned())
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    paths.sort();
    paths.dedup();
    paths
}

/// True when tracked files differ from HEAD (in the index or the working
/// tree). Untracked files do not count.
pub fn has_tracked_changes(repo: &Repository) -> Result<bool, git2::Error> {
    let mut opts = git2::StatusOptions::new();
    opts.include_untracked(false).include_ignored(false);
    Ok(repo
        .statuses(Some(&mut opts))?
        .iter()
        .any(|e| !e.status().is_ignored() && e.status() != git2::Status::CURRENT))
}

/// Integrates `upstream` (named `upstream_name` in messages) into the
/// checked-out `branch`.
pub fn integrate(
    repo: &Repository,
    branch: &str,
    upstream_name: &str,
    upstream: Oid,
    mode: Mode,
    abort_on_conflict: bool,
    sig: &Signature<'_>,
) -> Result<Outcome, Failure> {
    match mode {
        Mode::Merge => merge(
            repo,
            branch,
            upstream_name,
            upstream,
            abort_on_conflict,
            sig,
        ),
        Mode::Rebase => rebase(repo, branch, upstream, abort_on_conflict, sig),
    }
}

fn merge(
    repo: &Repository,
    branch: &str,
    upstream_name: &str,
    upstream: Oid,
    abort_on_conflict: bool,
    sig: &Signature<'_>,
) -> Result<Outcome, Failure> {
    let local = repo
        .head()
        .and_then(|h| h.peel_to_commit())
        .map_err(|e| failed("cannot read HEAD", e))?;
    let theirs = repo
        .find_commit(upstream)
        .map_err(|e| failed("cannot read the upstream commit", e))?;
    // Merge in memory first: a conflict found here has changed nothing.
    let mut index = repo
        .merge_commits(&local, &theirs, None)
        .map_err(|e| failed("merge failed", e))?;
    if index.has_conflicts() {
        let paths = conflict_paths(&index);
        if abort_on_conflict {
            return Err(Failure::Conflict {
                paths,
                in_progress: false,
            });
        }
        let annotated = repo
            .find_annotated_commit(upstream)
            .map_err(|e| failed("merge failed", e))?;
        let mut checkout = git2::build::CheckoutBuilder::new();
        checkout
            .safe()
            .allow_conflicts(true)
            .conflict_style_merge(true);
        repo.merge(&[&annotated], None, Some(&mut checkout))
            .map_err(|e| {
                if e.code() == git2::ErrorCode::Conflict {
                    Failure::Dirty
                } else {
                    failed("merge failed", e)
                }
            })?;
        return Err(Failure::Conflict {
            paths,
            in_progress: true,
        });
    }
    let tree_id = index
        .write_tree_to(repo)
        .map_err(|e| failed("cannot write the merged tree", e))?;
    let tree = repo
        .find_tree(tree_id)
        .map_err(|e| failed("cannot read the merged tree", e))?;
    let mut checkout = git2::build::CheckoutBuilder::new();
    checkout.safe();
    repo.checkout_tree(tree.as_object(), Some(&mut checkout))
        .map_err(|e| {
            if e.code() == git2::ErrorCode::Conflict {
                Failure::Dirty
            } else {
                failed("cannot update the working tree", e)
            }
        })?;
    let message = format!("Merge remote-tracking branch '{upstream_name}' into {branch}");
    match repo.commit(Some("HEAD"), sig, sig, &message, &tree, &[&local, &theirs]) {
        Ok(oid) => Ok(Outcome::Merged(oid)),
        Err(e) => {
            // Put the working tree and index back to HEAD.
            let _ = repo.reset(
                local.as_object(),
                git2::ResetType::Hard,
                Some(git2::build::CheckoutBuilder::new().force()),
            );
            Err(failed("cannot create the merge commit", e))
        }
    }
}

fn rebase(
    repo: &Repository,
    branch: &str,
    upstream: Oid,
    abort_on_conflict: bool,
    sig: &Signature<'_>,
) -> Result<Outcome, Failure> {
    let branch_ref = repo
        .find_reference(&format!("refs/heads/{branch}"))
        .map_err(|e| failed("cannot read the branch", e))?;
    let branch_ann = repo
        .reference_to_annotated_commit(&branch_ref)
        .map_err(|e| failed("cannot read the branch", e))?;
    let upstream_ann = repo
        .find_annotated_commit(upstream)
        .map_err(|e| failed("cannot read the upstream commit", e))?;
    let mut rebase = repo
        .rebase(Some(&branch_ann), Some(&upstream_ann), None, None)
        .map_err(|e| {
            if e.code() == git2::ErrorCode::Conflict {
                Failure::Dirty
            } else {
                failed("cannot start the rebase", e)
            }
        })?;
    let mut commits = 0;
    while let Some(op) = rebase.next() {
        if let Err(e) = op {
            let _ = rebase.abort();
            return Err(failed("rebase failed", e));
        }
        let index = match repo.index() {
            Ok(i) => i,
            Err(e) => {
                let _ = rebase.abort();
                return Err(failed("cannot read the index", e));
            }
        };
        if index.has_conflicts() {
            let paths = conflict_paths(&index);
            if abort_on_conflict {
                rebase
                    .abort()
                    .map_err(|e| failed("cannot abort the rebase", e))?;
            }
            return Err(Failure::Conflict {
                paths,
                in_progress: !abort_on_conflict,
            });
        }
        match rebase.commit(None, sig, None) {
            Ok(_) => commits += 1,
            // The change is already upstream: nothing to replay.
            Err(e) if e.code() == git2::ErrorCode::Applied => {}
            Err(e) => {
                let _ = rebase.abort();
                return Err(failed("cannot commit a rebased change", e));
            }
        }
    }
    rebase
        .finish(Some(sig))
        .map_err(|e| failed("cannot finish the rebase", e))?;
    let head = repo
        .refname_to_id(&format!("refs/heads/{branch}"))
        .map_err(|e| failed("cannot read the rebased branch", e))?;
    Ok(Outcome::Rebased { head, commits })
}
