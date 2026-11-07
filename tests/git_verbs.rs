//! Every git verb through the built `resh` binary, in temporary directories
//! with HOME (and so the global git configuration) pointed inside them.
//! Remotes are bare `file://` repositories, or SSH URLs on 127.0.0.1 port 1
//! (nothing listens) for the host-key checks that refuse before connecting.

use assert_cmd::Command;
use git2::{BranchType, Repository, RepositoryInitOptions, Signature};
use serde_json::Value;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

struct World {
    dir: TempDir,
}

impl World {
    fn new() -> World {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("home")).unwrap();
        let work = Repository::init_opts(
            dir.path().join("work"),
            RepositoryInitOptions::new().initial_head("main"),
        )
        .unwrap();
        let mut cfg = work.config().unwrap();
        cfg.set_str("user.name", "Resh Test").unwrap();
        cfg.set_str("user.email", "test@example.invalid").unwrap();
        commit(&work, "a.txt", "a\n");
        Repository::init_opts(
            dir.path().join("origin.git"),
            RepositoryInitOptions::new().bare(true).initial_head("main"),
        )
        .unwrap();
        let w = World { dir };
        work.remote("origin", &w.origin_url()).unwrap();
        work.find_remote("origin")
            .unwrap()
            .push(&["refs/heads/main:refs/heads/main"], None)
            .unwrap();
        work.find_branch("main", BranchType::Local)
            .unwrap()
            .set_upstream(Some("origin/main"))
            .unwrap();
        w
    }

    fn p(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn work(&self) -> Repository {
        Repository::open(self.p("work")).unwrap()
    }

    fn path_arg(&self) -> String {
        format!("path={}", self.p("work").display())
    }

    fn origin_url(&self) -> String {
        format!("file://{}", self.p("origin.git").display())
    }

    fn resh(&self) -> Command {
        let home = self.p("home");
        let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
        cmd.current_dir(self.dir.path())
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", home.join(".gitconfig"))
            .env_remove("SSH_AUTH_SOCK");
        cmd
    }

    /// Runs `git://t.<verb>` with `args`; returns (exit, stdout, stderr).
    fn run(&self, verb: &str, args: &[&str]) -> (i32, String, String) {
        let out = self
            .resh()
            .arg(format!("git://t.{verb}"))
            .args(args)
            .output()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8(out.stdout).unwrap(),
            String::from_utf8(out.stderr).unwrap(),
        )
    }

    fn ok(&self, verb: &str, args: &[&str]) -> Value {
        let (code, out, err) = self.run(verb, args);
        assert_eq!(code, 0, "{verb} {args:?}: {err}");
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("{verb}: {e}: {out}"))
    }

    fn fails(&self, verb: &str, args: &[&str], code: &str, exit: i32) -> String {
        let (got, out, err) = self.run(verb, args);
        assert_eq!(got, exit, "{verb} {args:?}: {err}");
        assert_eq!(out, "", "{verb}");
        let prefix = format!("Error: [{code}] ");
        assert!(
            err.starts_with(&prefix),
            "{verb}: want {prefix:?}, got {err:?}"
        );
        assert_eq!(err.lines().count(), 1, "{verb}: {err}");
        err
    }
}

fn commit(repo: &Repository, file: &str, content: &str) {
    let wd = repo.workdir().unwrap();
    std::fs::write(wd.join(file), content).unwrap();
    let mut index = repo.index().unwrap();
    index.read(true).unwrap();
    index.add_path(Path::new(file)).unwrap();
    index.write().unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
    let sig = Signature::now("Resh Test", "test@example.invalid").unwrap();
    let parent = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
    let parents: Vec<&git2::Commit> = parent.iter().collect();
    repo.commit(Some("HEAD"), &sig, &sig, file, &tree, &parents)
        .unwrap();
}

#[test]
fn status_verbs() {
    let w = World::new();
    std::fs::write(w.p("work/a.txt"), "changed\n").unwrap();
    let v = w.ok("status", &[&w.path_arg()]);
    assert_eq!(v["working_tree"]["unstaged"][0]["path"], "a.txt");
    let v = w.ok("status_summary", &[&w.path_arg()]);
    assert_eq!(v["working_tree"]["unstaged_count"], 1);
    let v = w.ok("status_short", &[&w.path_arg(), "include_dirty=true"]);
    assert!(v["summary"].as_str().unwrap().contains("main"), "{v}");
    w.fails(
        "status",
        &["path=/nonexistent/x"],
        "git.repository_not_found",
        1,
    );
    w.fails(
        "status",
        &[&w.path_arg(), "colour=1"],
        "git.invalid_status_config",
        2,
    );
}

#[test]
fn diff_verb() {
    let w = World::new();
    std::fs::write(w.p("work/a.txt"), "changed\n").unwrap();
    let v = w.ok("diff", &[&w.path_arg(), "mode=head_vs_workdir"]);
    assert_eq!(v["summary"]["files_changed"], 1, "{v}");
    w.fails(
        "diff",
        &[&w.path_arg(), "mode=nope"],
        "git.invalid_diff_config",
        2,
    );
}

#[test]
fn branch_and_tag_verbs() {
    let w = World::new();
    let v = w.ok("branch", &[&w.path_arg(), "action=create", "name=feature"]);
    assert_eq!(v["status"], "created");
    w.fails(
        "branch",
        &[&w.path_arg(), "action=create", "name=feature"],
        "git.branch_already_exists",
        1,
    );
    let v = w.ok("tag", &[&w.path_arg(), "action=create", "name=v1"]);
    assert_eq!(v["status"], "created");
    let v = w.ok("tag", &[&w.path_arg()]);
    assert_eq!(v["tags"][0]["name"], "v1", "{v}");
}

#[test]
fn commit_merge_rebase_verbs() {
    let w = World::new();
    std::fs::write(w.p("work/a.txt"), "edited\n").unwrap();
    let v = w.ok("commit", &[&w.path_arg(), "message=edit a", "all=true"]);
    assert!(v["commit"]["oid"].is_string());
    w.ok("branch", &[&w.path_arg(), "action=create", "name=topic"]);
    w.ok("branch", &[&w.path_arg(), "action=checkout", "name=topic"]);
    commit(&w.work(), "t.txt", "t\n");
    w.ok("branch", &[&w.path_arg(), "action=checkout", "name=main"]);
    let v = w.ok("merge", &[&w.path_arg(), "source=topic"]);
    assert_eq!(v["mode"], "fast_forward", "{v}");
    let v = w.ok("rebase", &[&w.path_arg(), "upstream=topic"]);
    assert_eq!(v["action"], "rebase", "{v}");
    w.fails(
        "rebase",
        &[&w.path_arg(), "upstream=topic", "autosquash=true"],
        "git.invalid_rebase_config",
        2,
    );
}

#[test]
fn clone_pull_push_sync_verbs() {
    let w = World::new();
    let dest = format!("path={}", w.p("copy").display());
    let v = w.ok(
        "clone",
        &[
            &format!("url={}", w.origin_url()),
            &dest,
            "timeout_ms=60000",
        ],
    );
    assert_eq!(v["status"], "cloned");
    // a plain local path works too
    let dest2 = format!("path={}", w.p("copy2").display());
    w.ok(
        "clone",
        &[&format!("url={}", w.p("origin.git").display()), &dest2],
    );

    commit(&w.work(), "b.txt", "b\n");
    let v = w.ok("push", &[&w.path_arg()]);
    assert_eq!(v["branches"][0]["status"], "pushed");
    let copy = format!("path={}", w.p("copy").display());
    let v = w.ok("pull", &[&copy]);
    assert_eq!(v["status"], "updated");
    commit(&w.work(), "c.txt", "c\n");
    let v = w.ok("sync", &[&w.path_arg()]);
    assert_eq!(v["push_result"]["status"], "pushed");
    w.fails(
        "sync",
        &[&w.path_arg(), "token=x"],
        "git.sync_invalid_config",
        2,
    );
    w.fails(
        "clone",
        &[
            "url=ftp://example.invalid/r",
            &format!("path={}", w.p("x").display()),
        ],
        "git.invalid_clone_config",
        2,
    );
}

/// A global `url.<base>.insteadOf` turns an https clone URL into SSH: the
/// host-key check applies to the rewritten URL and refuses before
/// connecting.
#[test]
fn clone_checks_the_insteadof_rewritten_url() {
    let w = World::new();
    std::fs::write(
        w.p("home/.gitconfig"),
        "[url \"ssh://git@127.0.0.1:1/\"]\n\tinsteadOf = https://example.invalid/\n",
    )
    .unwrap();
    let kh = w.p("known_hosts");
    std::fs::write(&kh, "# empty\n").unwrap();
    let err = w.fails(
        "clone",
        &[
            "url=https://example.invalid/r.git",
            &format!("path={}", w.p("c").display()),
            &format!("known_hosts_path={}", kh.display()),
        ],
        "git.host_key_verification_failed",
        1,
    );
    assert!(err.contains("[127.0.0.1]:1"), "{err}");
    assert!(err.contains("is not listed"), "{err}");
    assert!(!w.p("c").exists());
}

#[test]
fn timeout_is_enforced_and_reported_with_124() {
    let w = World::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for s in listener.incoming().flatten() {
            held.push(s);
        }
    });
    let start = std::time::Instant::now();
    let err = w.fails(
        "clone",
        &[
            &format!("url=http://127.0.0.1:{port}/r.git"),
            &format!("path={}", w.p("slow").display()),
            "timeout_ms=500",
        ],
        "git.clone_timeout",
        124,
    );
    assert!(err.contains("was stopped"), "{err}");
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
    assert!(!w.p("slow").exists());
}
