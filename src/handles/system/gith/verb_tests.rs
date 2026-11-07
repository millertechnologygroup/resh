//! Dispatch tests: every git verb called through `Handle::call` with CLI
//! string arguments, against repositories in temporary directories and
//! bare `file://` remotes. Nothing leaves the temporary directories and
//! nothing touches the network except 127.0.0.1 listeners started here.

use super::*;
use crate::core::registry::Args;
use git2::RepositoryInitOptions;
use std::net::TcpListener;
use tempfile::TempDir;

struct Out {
    status: Status,
    stdout: String,
    stderr: String,
}

impl Out {
    fn json(&self) -> Value {
        assert!(
            self.status.ok,
            "expected success, got {:?}\nstderr: {}",
            self.status, self.stderr
        );
        serde_json::from_str(&self.stdout).expect("stdout is JSON")
    }

    /// Asserts a failure with `code` and `exit`, the standard stderr line
    /// and nothing on stdout. Returns the message.
    fn fails(&self, code: &str, exit: i32) -> String {
        assert!(
            !self.status.ok,
            "expected {code}, got success: {}",
            self.stdout
        );
        assert_eq!(self.status.exit_code(), exit, "{code}: {}", self.stderr);
        let prefix = format!("Error: [{code}] ");
        assert!(
            self.stderr.starts_with(&prefix),
            "expected {prefix:?}, got {:?}",
            self.stderr
        );
        assert!(self.stdout.is_empty(), "stdout: {}", self.stdout);
        assert!(crate::core::status::is_valid_error_code(code));
        self.stderr[prefix.len()..].trim_end().to_string()
    }
}

fn run(verb: &str, pairs: &[(&str, &str)]) -> Out {
    let h = GitHandle {
        alias: "t".to_string(),
    };
    let args: Args = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let mut i: &[u8] = &[];
    let (mut o, mut e) = (Vec::new(), Vec::new());
    let status = {
        let mut io = IoStreams {
            stdin: &mut i,
            stdout: &mut o,
            stderr: &mut e,
        };
        h.call(verb, &args, &mut io).expect("call never errors")
    };
    Out {
        status,
        stdout: String::from_utf8(o).unwrap(),
        stderr: String::from_utf8(e).unwrap(),
    }
}

fn sig() -> Signature<'static> {
    Signature::now("Resh Test", "test@example.invalid").unwrap()
}

fn init(path: &Path, bare: bool) -> Repository {
    let repo = Repository::init_opts(
        path,
        RepositoryInitOptions::new().bare(bare).initial_head("main"),
    )
    .unwrap();
    let mut cfg = repo.config().unwrap();
    cfg.set_str("user.name", "Resh Test").unwrap();
    cfg.set_str("user.email", "test@example.invalid").unwrap();
    repo
}

fn commit_file(repo: &Repository, file: &str, content: &str) -> Oid {
    let wd = repo.workdir().unwrap();
    if let Some(parent) = Path::new(file).parent() {
        std::fs::create_dir_all(wd.join(parent)).unwrap();
    }
    std::fs::write(wd.join(file), content).unwrap();
    let mut index = repo.index().unwrap();
    // The verbs under test change the index on disk through their own
    // handle: never write back a stale copy.
    index.read(true).unwrap();
    index.add_path(Path::new(file)).unwrap();
    index.write().unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
    let parent = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
    let parents: Vec<&git2::Commit> = parent.iter().collect();
    repo.commit(Some("HEAD"), &sig(), &sig(), file, &tree, &parents)
        .unwrap()
}

/// A temp dir with `work` (main, one commit, pushed) and its bare
/// `origin.git` remote.
struct World {
    dir: TempDir,
    work: Repository,
}

impl World {
    fn new() -> World {
        let dir = TempDir::new().unwrap();
        let work = init(&dir.path().join("work"), false);
        commit_file(&work, "a.txt", "a\n");
        init(&dir.path().join("origin.git"), true);
        work.remote(
            "origin",
            &format!("file://{}", dir.path().join("origin.git").display()),
        )
        .unwrap();
        let w = World { dir, work };
        w.push_main(&w.work);
        w.work
            .find_branch("main", BranchType::Local)
            .unwrap()
            .set_upstream(Some("origin/main"))
            .unwrap();
        w
    }

    fn p(&self, name: &str) -> String {
        self.dir.path().join(name).display().to_string()
    }

    fn work_path(&self) -> String {
        self.p("work")
    }

    fn origin_url(&self) -> String {
        format!("file://{}", self.p("origin.git"))
    }

    fn push_main(&self, repo: &Repository) {
        repo.find_remote("origin")
            .unwrap()
            .push(&["refs/heads/main:refs/heads/main"], None)
            .unwrap();
    }

    /// A second clone that pushes one more commit to origin.
    fn advance_origin(&self, file: &str) -> Oid {
        let other = self.dir.path().join(format!("other-{file}"));
        let repo = Repository::clone(&self.origin_url(), &other).unwrap();
        let mut cfg = repo.config().unwrap();
        cfg.set_str("user.name", "Other").unwrap();
        cfg.set_str("user.email", "other@example.invalid").unwrap();
        let oid = commit_file(&repo, file, "theirs\n");
        self.push_main(&repo);
        oid
    }

    fn origin_main(&self) -> Oid {
        Repository::open_bare(self.p("origin.git"))
            .unwrap()
            .refname_to_id("refs/heads/main")
            .unwrap()
    }
}

/// Serializes the tests that rely on libgit2's process-wide read timeout.
static SLOW_SERVER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A listener on 127.0.0.1 that accepts connections and never answers.
fn silent_server() -> (TcpListener, u16) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let l2 = l.try_clone().unwrap();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for s in l2.incoming().flatten() {
            held.push(s);
        }
    });
    (l, port)
}

// ---------------------------------------------------------------- strict args

#[test]
fn every_verb_refuses_unknown_arguments_with_a_suggestion() {
    let w = World::new();
    for verb in GIT_VERBS {
        let out = run(verb, &[("path", &w.work_path()), ("timout_ms", "5")]);
        let code = GitError::invalid_for(verb, String::new()).code();
        let msg = out.fails(&code, 2);
        assert!(msg.contains("\"timout_ms\""), "{verb}: {msg}");
        assert!(
            msg.contains("did you mean \"timeout_ms\"?"),
            "{verb}: {msg}"
        );
    }
}

#[test]
fn every_verb_refuses_an_invalid_timeout() {
    let w = World::new();
    for verb in GIT_VERBS {
        for bad in ["0", "soon", "-5"] {
            let out = run(verb, &[("path", &w.work_path()), ("timeout_ms", bad)]);
            let code = GitError::invalid_for(verb, String::new()).code();
            assert!(out.fails(&code, 2).contains("timeout_ms"), "{verb} {bad}");
        }
    }
}

#[test]
fn invalid_booleans_are_refused() {
    let w = World::new();
    let out = run(
        "status",
        &[("path", &w.work_path()), ("include_untracked", "maybe")],
    );
    out.fails("git.invalid_status_config", 2);
    let out = run(
        "diff",
        &[("path", &w.work_path()), ("binary", "yes please")],
    );
    out.fails("git.invalid_diff_config", 2);
}

#[test]
fn unknown_verb_is_invalid_usage() {
    let out = run("fetch", &[("path", "/tmp")]);
    assert!(out.fails("git.invalid_verb", 2).contains("verbs: clone"));
}

#[test]
fn missing_path_is_invalid_usage() {
    for verb in GIT_VERBS {
        let out = run(verb, &[]);
        let code = GitError::invalid_for(verb, String::new()).code();
        out.fails(&code, 2);
    }
}

#[test]
fn missing_repository_is_not_found() {
    let dir = TempDir::new().unwrap();
    let nowhere = dir.path().join("nope").display().to_string();
    for verb in [
        "status",
        "status_short",
        "status_summary",
        "diff",
        "branch",
        "tag",
        "pull",
        "push",
        "sync",
    ] {
        let out = run(verb, &[("path", &nowhere)]);
        assert_eq!(out.status.exit_code(), 1, "{verb}: {}", out.stderr);
        assert!(
            out.stderr.contains("[git.repository_not_found]")
                || out.stderr.contains("[git.status_summary_failed]")
                || out.stderr.contains("[git.status_short_failed]"),
            "{verb}: {}",
            out.stderr
        );
    }
}

// ---------------------------------------------------------------- status

#[test]
fn status_reports_branch_and_changes() {
    let w = World::new();
    std::fs::write(w.dir.path().join("work/a.txt"), "changed\n").unwrap();
    std::fs::write(w.dir.path().join("work/new.txt"), "n\n").unwrap();
    let v = run("status", &[("path", &w.work_path())]).json();
    assert_eq!(v["branch"]["name"], "main");
    assert_eq!(v["branch"]["upstream"]["name"], "origin/main");
    assert_eq!(v["working_tree"]["unstaged"][0]["path"], "a.txt");
    assert_eq!(v["working_tree"]["untracked"][0]["path"], "new.txt");
    assert_eq!(v["working_tree"]["clean"], false);

    let v = run(
        "status",
        &[
            ("path", &w.work_path()),
            ("include_untracked", "false"),
            ("include_branch", "no"),
            ("timeout_ms", "5000"),
        ],
    )
    .json();
    assert_eq!(v["working_tree"]["untracked"], json!([]));
    assert!(v["branch"].is_null());
}

#[test]
fn status_summary_and_short() {
    let w = World::new();
    std::fs::write(w.dir.path().join("work/a.txt"), "changed\n").unwrap();
    let v = run(
        "status_summary",
        &[("path", &w.work_path()), ("compute_diffstats", "true")],
    )
    .json();
    assert_eq!(v["working_tree"]["unstaged_count"], 1);
    assert_eq!(v["summary"]["has_uncommitted_changes"], true);
    let v = run("status_short", &[("path", &w.work_path())]).json();
    let summary = v["summary"].as_str().unwrap_or_default().to_string();
    assert!(summary.contains("main"), "{v}");
    let out = run(
        "status_summary",
        &[("path", &w.work_path()), ("branch", "nope")],
    );
    out.fails("git.status_summary_branch_not_found", 1);
    let out = run(
        "status_short",
        &[("path", &w.work_path()), ("branch", "nope")],
    );
    out.fails("git.status_short_branch_not_found", 1);
}

// ---------------------------------------------------------------- diff

#[test]
fn diff_modes() {
    let w = World::new();
    let first = w.work.head().unwrap().target().unwrap().to_string();
    commit_file(&w.work, "b.txt", "b\n");
    std::fs::write(w.dir.path().join("work/a.txt"), "a2\n").unwrap();
    let v = run("diff", &[("path", &w.work_path())]).json();
    assert_eq!(v["files"][0]["new_path"], "a.txt", "{v}");
    let v = run(
        "diff",
        &[
            ("path", &w.work_path()),
            ("mode", "commit_vs_commit"),
            ("from", &first),
            ("to", "HEAD"),
            ("paths", "b.txt"),
            ("unified", "1"),
        ],
    )
    .json();
    assert_eq!(v["files"][0]["new_path"], "b.txt", "{v}");
    let out = run(
        "diff",
        &[
            ("path", &w.work_path()),
            ("mode", "commit_vs_commit"),
            ("from", &first),
        ],
    );
    out.fails("git.invalid_diff_config", 2);
    let out = run("diff", &[("path", &w.work_path()), ("mode", "sideways")]);
    out.fails("git.invalid_diff_config", 2);
    let out = run(
        "diff",
        &[
            ("path", &w.work_path()),
            ("mode", "commit_vs_workdir"),
            ("from", "nope"),
        ],
    );
    out.fails("git.diff_ref_not_found", 1);
    let out = run(
        "diff",
        &[("path", &w.work_path()), ("rename_threshold", "101")],
    );
    out.fails("git.invalid_diff_config", 2);
}

// ---------------------------------------------------------------- branch

#[test]
fn branch_actions() {
    let w = World::new();
    let p = w.work_path();
    let v = run("branch", &[("path", &p)]).json();
    assert_eq!(v["branches"][0]["name"], "main");
    let v = run("branch", &[("path", &p), ("remote_only", "true")]).json();
    assert_eq!(v["branches"][0]["name"], "origin/main", "{v}");
    let v = run("branch", &[("path", &p), ("local_only", "false")]).json();
    assert_eq!(v["branches"].as_array().unwrap().len(), 2, "{v}");
    run(
        "branch",
        &[("path", &p), ("all", "true"), ("remote_only", "true")],
    )
    .fails("git.invalid_branch_config", 2);

    let v = run(
        "branch",
        &[("path", &p), ("action", "create"), ("name", "feature")],
    )
    .json();
    assert_eq!(v["status"], "created");
    run(
        "branch",
        &[("path", &p), ("action", "create"), ("name", "feature")],
    )
    .fails("git.branch_already_exists", 1);
    run(
        "branch",
        &[("path", &p), ("action", "create"), ("name", "bad..name")],
    )
    .fails("git.invalid_branch_config", 2);
    run(
        "branch",
        &[
            ("path", &p),
            ("action", "create"),
            ("name", "x"),
            ("start_point", "nope"),
        ],
    )
    .fails("git.branch_startpoint_not_found", 1);
    run(
        "branch",
        &[
            ("path", &p),
            ("action", "create"),
            ("name", "x"),
            ("new_name", "y"),
        ],
    )
    .fails("git.invalid_branch_config", 2);
    let v = run(
        "branch",
        &[
            ("path", &p),
            ("action", "create"),
            ("name", "main2"),
            ("track", "true"),
            ("remote", "origin"),
        ],
    );
    // origin/main2 does not exist: nothing is created.
    v.fails("git.branch_set_upstream_failed", 1);
    assert!(w.work.find_branch("main2", BranchType::Local).is_err());

    let v = run(
        "branch",
        &[
            ("path", &p),
            ("action", "rename"),
            ("name", "feature"),
            ("new_name", "feat"),
        ],
    )
    .json();
    assert_eq!(v["status"], "renamed");
    run(
        "branch",
        &[
            ("path", &p),
            ("action", "rename"),
            ("name", "nope"),
            ("new_name", "z"),
        ],
    )
    .fails("git.branch_not_found", 1);

    let v = run(
        "branch",
        &[("path", &p), ("action", "checkout"), ("name", "feat")],
    )
    .json();
    assert_eq!(v["status"], "checked_out");
    commit_file(&w.work, "f.txt", "on feat\n");
    // back to main; feat now has an unmerged commit
    run(
        "branch",
        &[("path", &p), ("action", "checkout"), ("name", "main")],
    )
    .json();
    run(
        "branch",
        &[("path", &p), ("action", "delete"), ("name", "main")],
    )
    .fails("git.branch_delete_current", 1);
    run(
        "branch",
        &[("path", &p), ("action", "delete"), ("name", "feat")],
    )
    .fails("git.branch_delete_unmerged", 1);
    let v = run(
        "branch",
        &[
            ("path", &p),
            ("action", "delete"),
            ("name", "feat"),
            ("force", "true"),
        ],
    )
    .json();
    assert_eq!(v["status"], "deleted");
}

#[test]
fn checkout_never_overwrites_local_changes() {
    let w = World::new();
    let p = w.work_path();
    run(
        "branch",
        &[("path", &p), ("action", "create"), ("name", "other")],
    )
    .json();
    run(
        "branch",
        &[("path", &p), ("action", "checkout"), ("name", "other")],
    )
    .json();
    commit_file(&w.work, "a.txt", "other version\n");
    run(
        "branch",
        &[("path", &p), ("action", "checkout"), ("name", "main")],
    )
    .json();
    std::fs::write(w.dir.path().join("work/a.txt"), "local edit\n").unwrap();
    run(
        "branch",
        &[("path", &p), ("action", "checkout"), ("name", "other")],
    )
    .fails("git.branch_checkout_conflict", 1);
    assert_eq!(
        std::fs::read_to_string(w.dir.path().join("work/a.txt")).unwrap(),
        "local edit\n"
    );
    assert_eq!(w.work.head().unwrap().shorthand(), Some("main"));
    // An untracked file the switch does not touch is no obstacle.
    std::fs::write(w.dir.path().join("work/a.txt"), "a\n").unwrap();
    std::fs::write(w.dir.path().join("work/scratch.txt"), "x\n").unwrap();
    run(
        "branch",
        &[("path", &p), ("action", "checkout"), ("name", "other")],
    )
    .json();
    assert_eq!(w.work.head().unwrap().shorthand(), Some("other"));
}

// ---------------------------------------------------------------- tag

#[test]
fn tag_actions() {
    let w = World::new();
    let p = w.work_path();
    let v = run(
        "tag",
        &[("path", &p), ("action", "create"), ("name", "v1.0.0")],
    )
    .json();
    assert_eq!(v["status"], "created");
    let v = run(
        "tag",
        &[
            ("path", &p),
            ("action", "create"),
            ("name", "v1.1.0"),
            ("annotated", "true"),
            ("message", "release"),
            ("author_name", "Rel"),
            ("author_email", "rel@example.invalid"),
            ("timestamp", "1700000000"),
        ],
    )
    .json();
    assert_eq!(v["tag"]["tagger"]["name"], "Rel", "{v}");
    run(
        "tag",
        &[("path", &p), ("action", "create"), ("name", "v1.0.0")],
    )
    .fails("git.tag_already_exists", 1);
    run(
        "tag",
        &[
            ("path", &p),
            ("action", "create"),
            ("name", "v2"),
            ("message", "m"),
        ],
    )
    .fails("git.invalid_tag_config", 2);
    run(
        "tag",
        &[
            ("path", &p),
            ("action", "create"),
            ("name", "v2"),
            ("target", "nope"),
        ],
    )
    .fails("git.tag_target_not_found", 1);
    run(
        "tag",
        &[("path", &p), ("action", "create"), ("name", "bad tag")],
    )
    .fails("git.invalid_tag_config", 2);
    let v = run(
        "tag",
        &[("path", &p), ("sort", "version"), ("pattern", "v1.*")],
    )
    .json();
    assert_eq!(v["tags"].as_array().unwrap().len(), 2, "{v}");
    let v = run(
        "tag",
        &[
            ("path", &p),
            ("action", "delete"),
            ("names", "v1.0.0,v1.1.0"),
        ],
    )
    .json();
    assert_eq!(v["deleted"], json!(["v1.0.0", "v1.1.0"]), "{v}");
    run(
        "tag",
        &[("path", &p), ("action", "delete"), ("name", "v1.0.0")],
    )
    .fails("git.tag_not_found", 1);
}

// ---------------------------------------------------------------- commit

#[test]
fn commit_options() {
    let w = World::new();
    let p = w.work_path();
    run("commit", &[("path", &p), ("message", "nothing")]).fails("git.commit_nothing_to_commit", 1);
    std::fs::write(w.dir.path().join("work/a.txt"), "edited\n").unwrap();
    let v = run(
        "commit",
        &[
            ("path", &p),
            ("message", "edit"),
            ("all", "true"),
            ("signoff", "true"),
            ("author_name", "Ann"),
            ("author_email", "ann@example.invalid"),
            ("timestamp", "2024-01-02T03:04:05+01:00"),
        ],
    )
    .json();
    assert_eq!(v["commit"]["author"]["name"], "Ann", "{v}");
    let head = w.work.head().unwrap().peel_to_commit().unwrap();
    assert!(head.message().unwrap().contains("Signed-off-by:"));
    assert_eq!(head.author().when().seconds(), 1704161045);

    std::fs::write(w.dir.path().join("work/c.txt"), "c\n").unwrap();
    let v = run(
        "commit",
        &[("path", &p), ("message", "add c"), ("paths", "c.txt")],
    )
    .json();
    assert_eq!(v["stats"]["staged_files"], 1, "{v}");
    let v = run(
        "commit",
        &[("path", &p), ("amend", "true"), ("no_edit", "true")],
    )
    .json();
    assert!(v["commit"]["oid"].is_string(), "{v}");
    let v = run(
        "commit",
        &[("path", &p), ("message", "empty"), ("allow_empty", "true")],
    )
    .json();
    assert!(v["commit"]["oid"].is_string());
    run(
        "commit",
        &[("path", &p), ("no_edit", "true"), ("message", "x")],
    )
    .fails("git.invalid_commit_config", 2);
    run(
        "commit",
        &[("path", &p), ("message", "x"), ("timestamp", "yesterday")],
    )
    .fails("git.invalid_commit_config", 2);
}

// ---------------------------------------------------------------- merge / rebase

fn diverge(w: &World) {
    let p = w.work_path();
    run(
        "branch",
        &[("path", &p), ("action", "create"), ("name", "topic")],
    )
    .json();
    run(
        "branch",
        &[("path", &p), ("action", "checkout"), ("name", "topic")],
    )
    .json();
    commit_file(&w.work, "topic.txt", "t\n");
    run(
        "branch",
        &[("path", &p), ("action", "checkout"), ("name", "main")],
    )
    .json();
    commit_file(&w.work, "main.txt", "m\n");
}

#[test]
fn merge_options() {
    let w = World::new();
    let p = w.work_path();
    run("merge", &[("path", &p), ("source", "nope")]).fails("git.merge_source_not_found", 1);
    diverge(&w);
    run(
        "merge",
        &[("path", &p), ("source", "topic"), ("ff_only", "true")],
    )
    .fails("git.merge_non_fast_forward", 1);
    std::fs::write(w.dir.path().join("work/a.txt"), "dirty\n").unwrap();
    run("merge", &[("path", &p), ("source", "topic")]).fails("git.merge_dirty_worktree", 1);
    std::fs::write(w.dir.path().join("work/a.txt"), "a\n").unwrap();
    let v = run(
        "merge",
        &[
            ("path", &p),
            ("source", "topic"),
            ("commit_message", "merge topic"),
        ],
    )
    .json();
    let head = w.work.head().unwrap().peel_to_commit().unwrap();
    assert_eq!(head.parent_count(), 2, "{v}");
    run("merge", &[("path", &p)]).fails("git.invalid_merge_config", 2);
}

#[test]
fn rebase_ff_only_and_dirty_tree() {
    let w = World::new();
    let p = w.work_path();
    run(
        "branch",
        &[("path", &p), ("action", "create"), ("name", "topic")],
    )
    .json();
    run(
        "branch",
        &[("path", &p), ("action", "checkout"), ("name", "topic")],
    )
    .json();
    let ahead = commit_file(&w.work, "t.txt", "t\n");
    run(
        "branch",
        &[("path", &p), ("action", "checkout"), ("name", "main")],
    )
    .json();
    std::fs::write(w.dir.path().join("work/a.txt"), "dirty\n").unwrap();
    run("rebase", &[("path", &p), ("upstream", "topic")]).fails("git.rebase_dirty_worktree", 1);
    std::fs::write(w.dir.path().join("work/a.txt"), "a\n").unwrap();
    let v = run(
        "rebase",
        &[("path", &p), ("upstream", "topic"), ("ff_only", "true")],
    )
    .json();
    assert_eq!(v["mode"], "fast_forward", "{v}");
    assert_eq!(w.work.head().unwrap().target(), Some(ahead));
    let v = run(
        "rebase",
        &[("path", &p), ("upstream", "topic"), ("ff_only", "true")],
    )
    .json();
    assert_eq!(v["mode"], "up_to_date", "{v}");
    commit_file(&w.work, "m.txt", "m\n");
    run(
        "branch",
        &[("path", &p), ("action", "checkout"), ("name", "topic")],
    )
    .json();
    commit_file(&w.work, "t2.txt", "t2\n");
    run(
        "rebase",
        &[("path", &p), ("upstream", "main"), ("ff_only", "true")],
    )
    .fails("git.rebase_non_fast_forward", 1);
    run(
        "rebase",
        &[("path", &p), ("upstream", "main"), ("author_name", "Only")],
    )
    .fails("git.invalid_rebase_config", 2);
    let v = run(
        "rebase",
        &[
            ("path", &p),
            ("upstream", "main"),
            ("author_name", "Re Author"),
            ("author_email", "re@example.invalid"),
        ],
    )
    .json();
    let head = w.work.head().unwrap().peel_to_commit().unwrap();
    assert_eq!(head.author().name(), Some("Re Author"), "{v}");
}

#[test]
fn rebase_options() {
    let w = World::new();
    let p = w.work_path();
    diverge(&w);
    run(
        "rebase",
        &[
            ("path", &p),
            ("upstream", "topic"),
            ("preserve_merges", "true"),
        ],
    )
    .fails("git.rebase_preserve_merges_unsupported", 2);
    run(
        "rebase",
        &[("path", &p), ("upstream", "topic"), ("autosquash", "true")],
    )
    .fails("git.invalid_rebase_config", 2);
    run(
        "rebase",
        &[("path", &p), ("operation", "abort"), ("upstream", "topic")],
    )
    .fails("git.invalid_rebase_config", 2);
    run("rebase", &[("path", &p), ("operation", "continue")])
        .fails("git.rebase_not_in_progress", 1);
    run("rebase", &[("path", &p), ("upstream", "nope")]).fails("git.rebase_upstream_not_found", 1);
    run("rebase", &[("path", &p)]).fails("git.invalid_rebase_config", 2);
    let v = run("rebase", &[("path", &p), ("upstream", "topic")]).json();
    let head = w.work.head().unwrap().peel_to_commit().unwrap();
    assert_eq!(head.parent_count(), 1, "{v}");
    assert!(
        w.work
            .graph_descendant_of(head.id(), w.work.refname_to_id("refs/heads/topic").unwrap())
            .unwrap()
    );
}

// ---------------------------------------------------------------- clone

#[test]
fn clone_local_path_and_file_url() {
    let w = World::new();
    let dest = w.p("c1");
    let v = run("clone", &[("url", &w.origin_url()), ("path", &dest)]).json();
    assert_eq!(v["status"], "cloned");
    assert!(Path::new(&dest).join("a.txt").exists());
    // a plain local path, into a new nested directory
    let dest = w.p("deep/er/c2");
    run(
        "clone",
        &[
            ("url", &w.p("origin.git")),
            ("path", &dest),
            ("branch", "main"),
        ],
    )
    .json();
    assert!(Path::new(&dest).join("a.txt").exists());
    // target not empty
    run(
        "clone",
        &[("url", &w.origin_url()), ("path", &w.work_path())],
    )
    .fails("git.clone_target_not_empty", 1);
}

#[test]
fn clone_refuses_bad_urls_without_side_effects() {
    let w = World::new();
    let dest = w.p("never");
    for url in [
        "ftp://example.invalid/r.git",
        "-oProxyCommand=x",
        "/no/such/repo",
        "https://",
    ] {
        run("clone", &[("url", url), ("path", &dest)]).fails("git.invalid_clone_config", 2);
    }
    run(
        "clone",
        &[("url", &w.origin_url()), ("path", &dest), ("depth", "1")],
    )
    .fails("git.invalid_clone_config", 2);
    run(
        "clone",
        &[
            ("url", &w.origin_url()),
            ("path", &dest),
            ("ssh_key", "/k"),
            ("token", "t"),
        ],
    )
    .fails("git.invalid_clone_config", 2);
    assert!(!Path::new(&dest).exists());
}

#[test]
fn failed_clone_removes_created_directories() {
    let w = World::new();
    let dest = w.p("made/for/clone");
    run(
        "clone",
        &[
            ("url", &w.origin_url()),
            ("path", &dest),
            ("branch", "nope"),
        ],
    )
    .fails("git.clone_failed", 1);
    assert!(!w.dir.path().join("made").exists());
}

#[test]
fn clone_recursive_clones_submodules() {
    let w = World::new();
    // A repository with a submodule pointing at origin.git.
    let sup = init(&w.dir.path().join("super"), false);
    commit_file(&sup, "s.txt", "s\n");
    let mut sm = sup
        .submodule(&w.origin_url(), Path::new("sub"), true)
        .unwrap();
    sm.clone(None).unwrap();
    sm.add_finalize().unwrap();
    let mut index = sup.index().unwrap();
    index.write().unwrap();
    let tree = sup.find_tree(index.write_tree().unwrap()).unwrap();
    let parent = sup.head().unwrap().peel_to_commit().unwrap();
    sup.commit(Some("HEAD"), &sig(), &sig(), "add sub", &tree, &[&parent])
        .unwrap();

    let dest = w.p("rec");
    let url = format!("file://{}", w.p("super"));
    let v = run(
        "clone",
        &[("url", &url), ("path", &dest), ("recursive", "true")],
    )
    .json();
    assert_eq!(v["recursive"], true);
    assert!(Path::new(&dest).join("sub/a.txt").exists());
    let dest = w.p("flat");
    run("clone", &[("url", &url), ("path", &dest)]).json();
    assert!(!Path::new(&dest).join("sub/a.txt").exists());
}

// ---------------------------------------------------------------- pull

#[test]
fn pull_fast_forwards_and_reports() {
    let w = World::new();
    let p = w.work_path();
    let v = run("pull", &[("path", &p)]).json();
    assert_eq!(v["status"], "up_to_date");
    let theirs = w.advance_origin("b.txt");
    let v = run(
        "pull",
        &[("path", &p), ("remote", "origin"), ("branch", "main")],
    )
    .json();
    assert_eq!(v["status"], "updated");
    assert_eq!(v["behind_by"], 1);
    assert_eq!(w.work.head().unwrap().target(), Some(theirs));
    assert!(w.dir.path().join("work/b.txt").exists());
}

#[test]
fn pull_keeps_local_changes() {
    let w = World::new();
    w.advance_origin("a.txt");
    std::fs::write(w.dir.path().join("work/a.txt"), "mine\n").unwrap();
    run("pull", &[("path", &w.work_path())]).fails("git.pull_dirty_worktree", 1);
    assert_eq!(
        std::fs::read_to_string(w.dir.path().join("work/a.txt")).unwrap(),
        "mine\n"
    );
    // A change the update does not touch survives the fast-forward.
    std::fs::write(w.dir.path().join("work/a.txt"), "a\n").unwrap();
    w.advance_origin("b.txt");
    std::fs::write(w.dir.path().join("work/local.txt"), "keep\n").unwrap();
    run("pull", &[("path", &w.work_path())]).json();
    assert!(w.dir.path().join("work/local.txt").exists());
}

#[test]
fn pull_errors() {
    let w = World::new();
    let p = w.work_path();
    run("pull", &[("path", &p), ("remote", "nope")]).fails("git.remote_not_found", 1);
    run("pull", &[("path", &p), ("branch", "nope")]).fails("git.pull_failed", 1);
    run(
        "branch",
        &[("path", &p), ("action", "create"), ("name", "local-only")],
    )
    .json();
    run("pull", &[("path", &p), ("branch", "local-only")])
        .fails("git.pull_remote_branch_not_found", 1);
    w.advance_origin("b.txt");
    commit_file(&w.work, "c.txt", "mine\n");
    run("pull", &[("path", &p), ("ff_only", "true")]).fails("git.pull_non_fast_forward", 1);
    let msg = run("pull", &[("path", &p)]).fails("git.pull_failed", 1);
    assert!(msg.contains("diverged"), "{msg}");
    let head = w.work.head().unwrap().target().unwrap();
    w.work.set_head_detached(head).unwrap();
    run("pull", &[("path", &p)]).fails("git.pull_detached_head", 1);
    let bad = w.dir.path().join("broken");
    let r = init(&bad, false);
    commit_file(&r, "x", "x");
    r.remote("origin", &format!("file://{}", w.p("missing.git")))
        .unwrap();
    run("pull", &[("path", &bad.display().to_string())]).fails("git.pull_fetch_failed", 1);
}

#[test]
fn pull_prune_removes_deleted_remote_branches() {
    let w = World::new();
    let p = w.work_path();
    w.work
        .find_remote("origin")
        .unwrap()
        .push(&["refs/heads/main:refs/heads/gone"], None)
        .unwrap();
    run("pull", &[("path", &p)]).json();
    assert!(w.work.find_reference("refs/remotes/origin/gone").is_ok());
    Repository::open_bare(w.p("origin.git"))
        .unwrap()
        .find_reference("refs/heads/gone")
        .unwrap()
        .delete()
        .unwrap();
    run("pull", &[("path", &p)]).json();
    assert!(w.work.find_reference("refs/remotes/origin/gone").is_ok());
    run("pull", &[("path", &p), ("prune", "true")]).json();
    assert!(w.work.find_reference("refs/remotes/origin/gone").is_err());
}

#[test]
fn pull_stops_at_the_deadline() {
    let _serial = SLOW_SERVER_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let w = World::new();
    let (_l, port) = silent_server();
    w.work
        .remote("slow", &format!("http://127.0.0.1:{port}/r.git"))
        .unwrap();
    let start = Instant::now();
    let out = run(
        "pull",
        &[
            ("path", &w.work_path()),
            ("remote", "slow"),
            ("timeout_ms", "400"),
        ],
    );
    let msg = out.fails("git.pull_timeout", 124);
    assert!(
        msg.contains("400 ms") && msg.contains("was stopped"),
        "{msg}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(4),
        "{:?}",
        start.elapsed()
    );
}

#[test]
fn clone_stops_at_the_deadline_and_cleans_up() {
    let _serial = SLOW_SERVER_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let w = World::new();
    let (_l, port) = silent_server();
    let dest = w.p("slow/clone");
    let out = run(
        "clone",
        &[
            ("url", &format!("http://127.0.0.1:{port}/r.git")),
            ("path", &dest),
            ("timeout_ms", "400"),
        ],
    );
    let msg = out.fails("git.clone_timeout", 124);
    assert!(msg.contains("was stopped"), "{msg}");
    assert!(!w.dir.path().join("slow").exists());
}

// ---------------------------------------------------------------- push

#[test]
fn push_options() {
    let w = World::new();
    let p = w.work_path();
    let v = run("push", &[("path", &p)]).json();
    assert_eq!(v["branches"][0]["status"], "up_to_date");
    let mine = commit_file(&w.work, "b.txt", "b\n");
    run(
        "branch",
        &[("path", &p), ("action", "create"), ("name", "topic")],
    )
    .json();
    run("tag", &[("path", &p), ("action", "create"), ("name", "v1")]).json();
    let v = run(
        "push",
        &[
            ("path", &p),
            ("branches", "main,topic"),
            ("tags", "true"),
            ("set_upstream", "true"),
        ],
    )
    .json();
    assert_eq!(v["branches"][0]["status"], "pushed", "{v}");
    assert_eq!(v["tags_pushed"], true);
    assert_eq!(w.origin_main(), mine);
    let origin = Repository::open_bare(w.p("origin.git")).unwrap();
    assert!(origin.find_reference("refs/tags/v1").is_ok());
    assert!(origin.find_reference("refs/heads/topic").is_ok());
    let topic = w.work.find_branch("topic", BranchType::Local).unwrap();
    assert_eq!(
        topic.upstream().unwrap().name().unwrap(),
        Some("origin/topic")
    );

    run("push", &[("path", &p), ("branch", "nope")]).fails("git.push_local_branch_not_found", 1);
    run("push", &[("path", &p), ("remote", "nope")]).fails("git.remote_not_found", 1);
    run(
        "push",
        &[("path", &p), ("branch", "main"), ("branches", "topic")],
    )
    .fails("git.invalid_push_config", 2);
    run(
        "push",
        &[("path", &p), ("force", "true"), ("ff_only", "true")],
    )
    .fails("git.invalid_push_config", 2);
}

#[test]
fn rejected_push_is_an_error() {
    let w = World::new();
    let p = w.work_path();
    w.advance_origin("theirs.txt");
    commit_file(&w.work, "mine.txt", "mine\n");
    let before = w.origin_main();
    // The remote-tracking ref is stale, so only the server can refuse it.
    run("push", &[("path", &p)]).fails("git.push_rejected", 1);
    assert_eq!(w.origin_main(), before);
    run("pull", &[("path", &p), ("ff_only", "false")]).fails("git.pull_failed", 1);
    run("push", &[("path", &p), ("ff_only", "true")]).fails("git.push_non_fast_forward", 1);
    run("push", &[("path", &p), ("force", "true")]).json();
    assert_ne!(w.origin_main(), before);
}

// ---------------------------------------------------------------- sync

#[test]
fn sync_fast_forwards_then_pushes() {
    let w = World::new();
    let p = w.work_path();
    w.advance_origin("b.txt");
    let v = run("sync", &[("path", &p)]).json();
    assert_eq!(v["integration"]["status"], "fast_forward", "{v}");
    let mine = commit_file(&w.work, "c.txt", "c\n");
    let v = run(
        "sync",
        &[
            ("path", &p),
            ("pull_strategy", "ff_only"),
            ("push_tags", "true"),
        ],
    )
    .json();
    assert_eq!(v["push_result"]["status"], "pushed", "{v}");
    assert_eq!(w.origin_main(), mine);
    let v = run(
        "sync",
        &[("path", &p), ("push", "false"), ("dry_run", "true")],
    )
    .json();
    assert_eq!(v["status"], "dry_run");
}

#[test]
fn sync_errors() {
    let w = World::new();
    let p = w.work_path();
    std::fs::write(w.dir.path().join("work/a.txt"), "dirty\n").unwrap();
    run("sync", &[("path", &p)]).fails("git.sync_dirty_worktree", 1);
    let v = run("sync", &[("path", &p), ("stash_uncommitted", "true")]).json();
    assert_eq!(v["stash"]["used"], true);
    assert_eq!(
        std::fs::read_to_string(w.dir.path().join("work/a.txt")).unwrap(),
        "dirty\n"
    );
    std::fs::write(w.dir.path().join("work/a.txt"), "a\n").unwrap();
    run("sync", &[("path", &p), ("remote", "nope")]).fails("git.sync_remote_not_found", 1);
    run("sync", &[("path", &p), ("branch", "nope")]).fails("git.sync_branch_not_found", 1);
    run("sync", &[("path", &p), ("remote_branch", "other")]).fails("git.sync_invalid_config", 2);
    run("sync", &[("path", &p), ("pull_strategy", "octopus")]).fails("git.sync_invalid_config", 2);
    w.advance_origin("b.txt");
    commit_file(&w.work, "c.txt", "c\n");
    run("sync", &[("path", &p), ("pull_strategy", "ff_only")])
        .fails("git.sync_non_fast_forward", 1);
    run("sync", &[("path", &p)]).fails("git.sync_failed", 1);
    let head = w.work.head().unwrap().target().unwrap();
    w.work.set_head_detached(head).unwrap();
    run("sync", &[("path", &p)]).fails("git.sync_detached_head", 1);
}

// ---------------------------------------------------------------- host keys and insteadOf

#[test]
fn insteadof_rewrite_to_ssh_is_checked_for_pull_and_push() {
    let w = World::new();
    let p = w.work_path();
    let kh = w.dir.path().join("known_hosts");
    std::fs::write(&kh, "# nothing listed\n").unwrap();
    // origin itself is https; the rewrite makes it SSH on 127.0.0.1:1.
    w.work
        .remote_set_url("origin", "https://example.invalid/r.git")
        .unwrap();
    let mut cfg = w.work.config().unwrap();
    cfg.set_str(
        "url.ssh://git@127.0.0.1:1/.insteadOf",
        "https://example.invalid/",
    )
    .unwrap();
    let khs = kh.display().to_string();
    for verb in ["pull", "push", "sync"] {
        let msg = run(verb, &[("path", &p), ("known_hosts_path", &khs)])
            .fails("git.host_key_verification_failed", 1);
        assert!(msg.contains("[127.0.0.1]:1"), "{verb}: {msg}");
    }
    // pushInsteadOf applies to push only.
    cfg.remove("url.ssh://git@127.0.0.1:1/.insteadOf").unwrap();
    cfg.set_str(
        "url.ssh://git@127.0.0.1:1/.pushInsteadOf",
        "https://example.invalid/",
    )
    .unwrap();
    let msg = run("push", &[("path", &p), ("known_hosts_path", &khs)])
        .fails("git.host_key_verification_failed", 1);
    assert!(msg.contains("[127.0.0.1]:1"), "{msg}");
}

#[test]
fn error_codes_are_valid_and_documented() {
    let doc = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/Packages_Software/git.md"
    ))
    .unwrap();
    let src = include_str!("../gith.rs");
    let mut codes: Vec<&str> = src
        .match_indices("=> \"git.")
        .map(|(i, _)| {
            let rest = &src[i + 4..];
            &rest[..rest.find('"').unwrap()]
        })
        .collect();
    for verb in GIT_VERBS {
        codes.push(Box::leak(format!("git.{verb}_timeout").into_boxed_str()));
    }
    codes.sort_unstable();
    codes.dedup();
    assert!(codes.len() > 50, "{codes:?}");
    for code in codes {
        assert!(crate::core::status::is_valid_error_code(code), "{code}");
        assert!(
            doc.contains(&format!("`{code}`")),
            "{code} is not documented in git.md"
        );
    }
}
