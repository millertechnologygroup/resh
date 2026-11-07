//! `known_hosts_path` on the git handle, through the real `resh` binary.
//!
//! Each test runs in its own temporary directory (HOME and the XDG
//! directories inside it). Remotes are local file:// repositories or an SSH
//! URL on 127.0.0.1 port 1, where nothing listens, so nothing reaches the
//! network.

use assert_cmd::Command;
use git2::{Repository, RepositoryInitOptions, Signature};
use std::path::Path;
use tempfile::TempDir;

const UNREACHABLE_SSH: &str = "ssh://git@127.0.0.1:1/repo.git";

fn resh(dir: &Path) -> Command {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
    cmd.current_dir(dir)
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("XDG_DATA_HOME", dir.join("data"))
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("XDG_CACHE_HOME", dir.join("cache"))
        .env_remove("SSH_AUTH_SOCK");
    cmd
}

fn commit(repo: &Repository, file: &str) {
    std::fs::write(repo.workdir().unwrap().join(file), file).unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(Path::new(file)).unwrap();
    index.write().unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
    let sig = Signature::now("Resh Test", "test@example.invalid").unwrap();
    let parent = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
    let parents: Vec<&git2::Commit> = parent.iter().collect();
    repo.commit(Some("HEAD"), &sig, &sig, file, &tree, &parents)
        .unwrap();
}

/// A working repository `work` on main whose origin is `origin`, or a bare
/// file:// repository `remote.git` when `origin` is None.
fn work_repo(dir: &Path, origin: Option<&str>) -> Repository {
    let repo = Repository::init_opts(
        dir.join("work"),
        RepositoryInitOptions::new().initial_head("main"),
    )
    .unwrap();
    commit(&repo, "base.txt");
    let url = match origin {
        Some(url) => url.to_string(),
        None => {
            let bare = dir.join("remote.git");
            Repository::init_opts(
                &bare,
                RepositoryInitOptions::new().bare(true).initial_head("main"),
            )
            .unwrap();
            format!("file://{}", bare.display())
        }
    };
    repo.remote("origin", &url).unwrap();
    repo
}

/// push and pull against a file:// remote work the same with and without
/// known_hosts_path (here a file that does not exist): the option only
/// applies to SSH remotes.
#[test]
fn file_remote_ignores_known_hosts_path() {
    let tmp = TempDir::new().unwrap();
    let repo = work_repo(tmp.path(), None);
    let work = tmp.path().join("work");
    let work = work.to_str().unwrap();
    let missing = tmp.path().join("missing_known_hosts");
    let missing_arg = format!("known_hosts_path={}", missing.display());
    let path_arg = format!("path={}", work);

    for extra in [None, Some(missing_arg.as_str())] {
        commit(
            &repo,
            if extra.is_some() {
                "with.txt"
            } else {
                "without.txt"
            },
        );
        for verb in ["push", "pull"] {
            let mut args = vec![
                format!("git://kh.{verb}"),
                path_arg.clone(),
                "branch=main".into(),
            ];
            args.extend(extra.map(str::to_string));
            resh(tmp.path()).args(&args).assert().success();
        }
    }
    let bare = Repository::open_bare(tmp.path().join("remote.git")).unwrap();
    assert_eq!(
        bare.refname_to_id("refs/heads/main").unwrap(),
        repo.head().unwrap().target().unwrap()
    );
}

/// For an SSH remote a missing known_hosts file refuses the operation with
/// git.host_key_verification_failed before any connection is attempted;
/// without the option the same command fails only when connecting.
#[test]
fn ssh_remote_with_missing_known_hosts_is_refused() {
    let tmp = TempDir::new().unwrap();
    work_repo(tmp.path(), Some(UNREACHABLE_SSH));
    let work = tmp.path().join("work");
    let path_arg = format!("path={}", work.display());
    let missing = format!(
        "known_hosts_path={}",
        tmp.path().join("missing_known_hosts").display()
    );
    let clone_path = format!("path={}", tmp.path().join("clone").display());
    let clone_url = format!("url={UNREACHABLE_SSH}");

    let cases: [(&str, Vec<&str>); 2] = [
        ("git://kh.clone", vec![&clone_url, &clone_path]),
        ("git://kh.pull", vec![&path_arg]),
    ];
    for (target, args) in &cases {
        let out = resh(tmp.path())
            .arg(target)
            .args(args)
            .arg(&missing)
            .assert()
            .failure()
            .code(1)
            .get_output()
            .clone();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("git.host_key_verification_failed"),
            "{target}: {stderr}"
        );
        assert!(
            stderr.contains("cannot read known_hosts file"),
            "{target}: {stderr}"
        );

        // Without known_hosts_path: a connection failure, not a host key one.
        let out = resh(tmp.path())
            .arg(target)
            .args(args)
            .assert()
            .failure()
            .get_output()
            .clone();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains("host_key_verification_failed"),
            "{target}: {stderr}"
        );
    }
}
