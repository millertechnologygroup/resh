//! The arguments each git verb accepts, and the strict checks applied to
//! them before anything runs.
//!
//! [`options_for`] is the single list per verb. The dispatcher refuses any
//! other key (exit 2, with a "did you mean" hint for likely typos), and the
//! help tests check that each verb's usage text lists exactly these options.

use std::time::Duration;

const STATUS: &[&str] = &[
    "path",
    "include_untracked",
    "include_ignored",
    "include_staged",
    "include_branch",
    "include_remote",
    "timeout_ms",
];

const STATUS_SUMMARY: &[&str] = &[
    "path",
    "remote",
    "branch",
    "include_untracked",
    "include_ignored",
    "include_remote",
    "compute_diffstats",
    "max_files",
    "timeout_ms",
];

const STATUS_SHORT: &[&str] = &[
    "path",
    "branch",
    "remote",
    "include_remote",
    "include_dirty",
    "include_conflicts",
    "symbols",
    "timeout_ms",
];

const DIFF: &[&str] = &[
    "path",
    "mode",
    "from",
    "to",
    "paths",
    "unified",
    "ignore_whitespace",
    "ignore_whitespace_change",
    "ignore_whitespace_eol",
    "detect_renames",
    "rename_threshold",
    "binary",
    "max_files",
    "max_hunks",
    "timeout_ms",
];

const BRANCH: &[&str] = &[
    "path",
    "action",
    "name",
    "new_name",
    "start_point",
    "track",
    "remote",
    "local_only",
    "remote_only",
    "all",
    "force",
    "timeout_ms",
];

const TAG: &[&str] = &[
    "path",
    "action",
    "name",
    "names",
    "pattern",
    "sort",
    "annotated",
    "message",
    "target",
    "force",
    "author_name",
    "author_email",
    "timestamp",
    "timeout_ms",
];

const COMMIT: &[&str] = &[
    "path",
    "message",
    "all",
    "paths",
    "allow_empty",
    "amend",
    "no_edit",
    "signoff",
    "author_name",
    "author_email",
    "committer_name",
    "committer_email",
    "timestamp",
    "timeout_ms",
];

const MERGE: &[&str] = &[
    "path",
    "source",
    "target",
    "commit_message",
    "author_name",
    "author_email",
    "committer_name",
    "committer_email",
    "ff_only",
    "no_ff",
    "squash",
    "allow_uncommitted",
    "abort_on_conflict",
    "timeout_ms",
];

const REBASE: &[&str] = &[
    "path",
    "upstream",
    "operation",
    "branch",
    "author_name",
    "author_email",
    "committer_name",
    "committer_email",
    "ff_only",
    "preserve_merges",
    "autosquash",
    "allow_uncommitted",
    "abort_on_conflict",
    "timeout_ms",
];

const CLONE: &[&str] = &[
    "url",
    "path",
    "branch",
    "depth",
    "recursive",
    "ssh_key",
    "known_hosts_path",
    "username",
    "password",
    "token",
    "timeout_ms",
];

const PULL: &[&str] = &[
    "path",
    "remote",
    "branch",
    "ff_only",
    "rebase",
    "abort_on_conflict",
    "author_name",
    "author_email",
    "prune",
    "ssh_key",
    "known_hosts_path",
    "username",
    "password",
    "token",
    "timeout_ms",
];

const PUSH: &[&str] = &[
    "path",
    "remote",
    "branch",
    "branches",
    "tags",
    "force",
    "ff_only",
    "set_upstream",
    "ssh_key",
    "known_hosts_path",
    "username",
    "password",
    "token",
    "timeout_ms",
];

const SYNC: &[&str] = &[
    "path",
    "remote",
    "branch",
    "remote_branch",
    "pull_strategy",
    "push",
    "push_tags",
    "force_push",
    "allow_uncommitted",
    "stash_uncommitted",
    "abort_on_conflict",
    "author_name",
    "author_email",
    "dry_run",
    "known_hosts_path",
    "timeout_ms",
];

/// Verbs that talk to a remote. They default to [`NETWORK_DEFAULT_TIMEOUT`].
pub const NETWORK_VERBS: &[&str] = &["clone", "pull", "push", "sync"];

/// The deadline of a network verb when `timeout_ms` is not given.
pub const NETWORK_DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);

/// The options `verb` accepts, or `None` for an unknown verb.
pub fn options_for(verb: &str) -> Option<&'static [&'static str]> {
    Some(match verb {
        "status" => STATUS,
        "status_summary" => STATUS_SUMMARY,
        "status_short" => STATUS_SHORT,
        "diff" => DIFF,
        "branch" => BRANCH,
        "tag" => TAG,
        "commit" => COMMIT,
        "merge" => MERGE,
        "rebase" => REBASE,
        "clone" => CLONE,
        "pull" => PULL,
        "push" => PUSH,
        "sync" => SYNC,
        _ => return None,
    })
}

/// The accepted option closest to `key` when it is a likely typo: at most
/// two edits away, or one of the two contains the other.
pub fn suggest(key: &str, allowed: &[&'static str]) -> Option<&'static str> {
    let key = key.to_ascii_lowercase();
    allowed
        .iter()
        .map(|a| (edit_distance(&key, a), *a))
        .filter(|(d, a)| {
            *d <= 2 || (key.len() >= 4 && (a.contains(key.as_str()) || key.contains(a)))
        })
        .min_by_key(|(d, _)| *d)
        .map(|(_, a)| a)
}

fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != *cb);
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        prev = cur;
    }
    prev[b.len()]
}

/// Refuses keys that `verb` does not accept. The message names the first
/// unknown key (in sorted order), suggests a likely intended option and
/// lists the accepted ones.
pub fn check_known(verb: &str, keys: &mut dyn Iterator<Item = &str>) -> Result<(), String> {
    let allowed = options_for(verb).unwrap_or(&[]);
    let mut unknown: Vec<&str> = keys.filter(|k| !allowed.contains(k)).collect();
    unknown.sort_unstable();
    let Some(first) = unknown.first() else {
        return Ok(());
    };

    let hint = suggest(first, allowed)
        .map(|s| format!(" (did you mean {s:?}?)"))
        .unwrap_or_default();
    Err(format!(
        "unknown argument {first:?} for git {verb}{hint}; accepted arguments: {}",
        allowed.join(", ")
    ))
}

/// Reads `timeout_ms`: absent is `None`; otherwise a whole number of
/// milliseconds from 1 to 2^31-1 (the largest value libgit2 can take).
pub fn timeout_ms(value: Option<&str>) -> Result<Option<u64>, String> {
    let Some(raw) = value else {
        return Ok(None);
    };
    match raw.trim().parse::<u64>() {
        Ok(ms) if (1..=i32::MAX as u64).contains(&ms) => Ok(Some(ms)),
        _ => Err(format!(
            "invalid timeout_ms value {raw:?}: expected a whole number of milliseconds from 1 to {}",
            i32::MAX
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_verb_has_a_list_and_accepts_timeout_and_path() {
        for verb in super::super::GIT_VERBS {
            let opts = options_for(verb).unwrap_or_else(|| panic!("{verb}"));
            assert!(opts.contains(&"timeout_ms"), "{verb}");
            assert!(opts.contains(&"path"), "{verb}");
        }
        assert!(options_for("fetch").is_none());
    }

    #[test]
    fn unknown_keys_are_refused_with_a_suggestion() {
        let e = check_known("status", &mut ["path", "include_untrackd"].into_iter()).unwrap_err();
        assert!(e.contains("\"include_untrackd\""), "{e}");
        assert!(e.contains("did you mean \"include_untracked\"?"), "{e}");
        assert!(check_known("status", &mut ["path"].into_iter()).is_ok());
        let e = check_known("sync", &mut ["ssh_key"].into_iter()).unwrap_err();
        assert!(e.contains("accepted arguments: path"), "{e}");
    }

    #[test]
    fn credentials_are_accepted_by_clone_pull_and_push_only() {
        for key in ["ssh_key", "username", "password", "token"] {
            assert!(CLONE.contains(&key) && PULL.contains(&key) && PUSH.contains(&key));
            assert!(!SYNC.contains(&key));
        }
        assert!(SYNC.contains(&"known_hosts_path"));
    }

    #[test]
    fn timeout_values() {
        assert_eq!(timeout_ms(None), Ok(None));
        assert_eq!(timeout_ms(Some("250")), Ok(Some(250)));
        for bad in ["0", "-1", "soon", "", "1.5", "99999999999"] {
            assert!(timeout_ms(Some(bad)).is_err(), "{bad}");
        }
    }
}
