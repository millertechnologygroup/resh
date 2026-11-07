//! End-to-end tests for the git handle's remote verbs against real servers
//! in a throwaway container: OpenSSH (key authentication, strict
//! `known_hosts_path` checking, including the insteadOf and key-type cases)
//! and `git daemon` (git:// clone, shallow clone, push, pull, sync, and
//! merging or rebasing diverged history). The host's
//! `resh` binary talks to the container's ports published on 127.0.0.1;
//! HOME points into a temporary directory, so the real ~/.gitconfig and
//! ~/.ssh are never read or written.
//!
//! Run with `cargo test --features e2e-docker --test git_e2e_docker`. The
//! image `resh-git-e2e:1` (debian:13-slim + openssh-server + git) is built
//! on first use.

#![cfg(feature = "e2e-docker")]

use assert_cmd::Command;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command as Proc;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const IMAGE: &str = "resh-git-e2e:1";
const DOCKERFILE: &str = "FROM debian:13-slim\n\
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
--no-install-recommends openssh-server git ca-certificates && rm -rf /var/lib/apt/lists/*\n";

const SERVER_SCRIPT: &str = r#"
set -e
ssh-keygen -A >/dev/null
useradd -m -s /usr/bin/git-shell git
usermod -p '*' git
mkdir -p /home/git/.ssh
printf '%s\n' "$PUBKEY" > /home/git/.ssh/authorized_keys
chmod 700 /home/git/.ssh && chmod 600 /home/git/.ssh/authorized_keys
chown -R git:git /home/git/.ssh
mkdir -p /srv/git /tmp/seed
git init -q --bare -b main /srv/git/repo.git
cd /tmp/seed && git init -q -b main && git config user.name Seed && git config user.email seed@example.invalid
echo seed > seed.txt && git add seed.txt && git commit -q -m seed
git push -q /srv/git/repo.git main
chown -R git:git /srv/git
mkdir -p /run/sshd
git daemon --reuseaddr --export-all --enable=receive-pack --base-path=/srv/git --user=git --detach
exec /usr/sbin/sshd -D -e
"#;

fn docker(args: &[&str]) -> String {
    let out = Proc::new("docker")
        .args(args)
        .output()
        .expect("docker is required for e2e-docker tests");
    assert!(
        out.status.success(),
        "docker {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn ensure_image() {
    let ok = Proc::new("docker")
        .args(["image", "inspect", IMAGE])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if ok {
        return;
    }
    let mut child = Proc::new("docker")
        .args(["build", "-q", "-t", IMAGE, "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(DOCKERFILE.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success(), "image build failed");
}

/// One server container, removed on drop.
struct Server {
    id: String,
    ssh_port: u16,
    git_port: u16,
    dir: TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = Proc::new("docker").args(["rm", "-f", &self.id]).output();
    }
}

fn port_of(id: &str, inner: &str) -> u16 {
    let out = docker(&["port", id, inner]);
    out.lines()
        .find_map(|l| l.rsplit_once(':').and_then(|(_, p)| p.trim().parse().ok()))
        .unwrap_or_else(|| panic!("no port for {inner}: {out}"))
}

impl Server {
    fn start() -> Server {
        ensure_image();
        let dir = TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("home")).unwrap();
        let key = dir.path().join("id_ed25519");
        let st = Proc::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "resh-e2e", "-f"])
            .arg(&key)
            .status()
            .expect("ssh-keygen is required");
        assert!(st.success());
        let pubkey = std::fs::read_to_string(key.with_extension("pub")).unwrap();
        let env = format!("PUBKEY={}", pubkey.trim());
        let id = docker(&[
            "run",
            "-d",
            "-p",
            "127.0.0.1::22",
            "-p",
            "127.0.0.1::9418",
            "-e",
            &env,
            IMAGE,
            "sh",
            "-c",
            SERVER_SCRIPT,
        ])
        .trim()
        .to_string();
        let mut s = Server {
            id,
            ssh_port: 0,
            git_port: 0,
            dir,
        };
        s.ssh_port = port_of(&s.id, "22/tcp");
        s.git_port = port_of(&s.id, "9418/tcp");
        s.wait_ready();
        s
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let ssh_ok = std::net::TcpStream::connect(("127.0.0.1", self.ssh_port))
                .ok()
                .and_then(|mut c| {
                    c.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
                    let mut b = [0u8; 4];
                    c.read_exact(&mut b).ok()?;
                    (&b == b"SSH-").then_some(())
                })
                .is_some();
            let daemon_ok = Proc::new("docker")
                .args([
                    "exec",
                    &self.id,
                    "sh",
                    "-c",
                    "pgrep -f 'git daemon' >/dev/null || pgrep git-daemon >/dev/null",
                ])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if ssh_ok && daemon_ok {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "server did not start: {}",
                docker(&["logs", &self.id])
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn p(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn key(&self) -> String {
        format!("ssh_key={}", self.p("id_ed25519").display())
    }

    fn ssh_url(&self) -> String {
        format!("ssh://git@127.0.0.1:{}/srv/git/repo.git", self.ssh_port)
    }

    fn git_url(&self) -> String {
        format!("git://127.0.0.1:{}/repo.git", self.git_port)
    }

    /// `[127.0.0.1]:<port> <type> <key>` for each of the server's host keys
    /// of the given types (`ed25519`, `ecdsa`, `rsa`).
    fn known_hosts(&self, types: &[&str]) -> PathBuf {
        let mut text = String::new();
        for t in types {
            let line = docker(&[
                "exec",
                &self.id,
                "cat",
                &format!("/etc/ssh/ssh_host_{t}_key.pub"),
            ]);
            let mut f = line.split_whitespace();
            let (kt, b64) = (f.next().unwrap(), f.next().unwrap());
            text.push_str(&format!("[127.0.0.1]:{} {kt} {b64}\n", self.ssh_port));
        }
        let path = self.p(&format!("kh-{}", types.join("-")));
        std::fs::write(&path, text).unwrap();
        path
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

    fn run(&self, verb: &str, args: &[&str]) -> (i32, String, String) {
        let out = self
            .resh()
            .arg(format!("git://e2e.{verb}"))
            .args(args)
            .output()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8(out.stdout).unwrap(),
            String::from_utf8(out.stderr).unwrap(),
        )
    }

    fn ok(&self, verb: &str, args: &[&str]) -> serde_json::Value {
        let (code, out, err) = self.run(verb, args);
        assert_eq!(code, 0, "{verb} {args:?}: {err}");
        serde_json::from_str(&out).unwrap()
    }

    fn refused(&self, verb: &str, args: &[&str]) -> String {
        let (code, out, err) = self.run(verb, args);
        assert_eq!(code, 1, "{verb} {args:?}: {err}");
        assert_eq!(out, "");
        assert!(
            err.starts_with("Error: [git.host_key_verification_failed] "),
            "{verb}: {err}"
        );
        err
    }

    /// The commit at refs/heads/main on the server.
    fn server_main(&self) -> String {
        docker(&[
            "exec",
            &self.id,
            "git",
            "--git-dir=/srv/git/repo.git",
            "rev-parse",
            "main",
        ])
        .trim()
        .to_string()
    }
}

fn path_arg(p: &Path) -> String {
    format!("path={}", p.display())
}

fn kh_arg(p: &Path) -> String {
    format!("known_hosts_path={}", p.display())
}

/// Adds a commit to the clone at `repo` and returns its id.
fn commit(repo: &Path, file: &str) -> String {
    let r = git2::Repository::open(repo).unwrap();
    std::fs::write(repo.join(file), file).unwrap();
    let mut index = r.index().unwrap();
    index.add_path(Path::new(file)).unwrap();
    index.write().unwrap();
    let tree = r.find_tree(index.write_tree().unwrap()).unwrap();
    let sig = git2::Signature::now("E2E", "e2e@example.invalid").unwrap();
    let parent = r.head().unwrap().peel_to_commit().unwrap();
    r.commit(Some("HEAD"), &sig, &sig, file, &tree, &[&parent])
        .unwrap()
        .to_string()
}

#[test]
fn ssh_clone_push_pull_with_key_auth_and_strict_known_hosts() {
    let s = Server::start();
    let kh = s.known_hosts(&["ed25519", "ecdsa", "rsa"]);
    let a = s.p("a");
    let v = s.ok(
        "clone",
        &[
            &format!("url={}", s.ssh_url()),
            &path_arg(&a),
            &s.key(),
            &kh_arg(&kh),
        ],
    );
    assert_eq!(v["status"], "cloned");
    assert!(a.join("seed.txt").exists());

    let mine = commit(&a, "from-a.txt");
    let v = s.ok("push", &[&path_arg(&a), &s.key(), &kh_arg(&kh)]);
    assert_eq!(v["branches"][0]["status"], "pushed");
    assert_eq!(s.server_main(), mine);

    let b = s.p("b");
    s.ok(
        "clone",
        &[
            &format!("url={}", s.ssh_url()),
            &path_arg(&b),
            &s.key(),
            &kh_arg(&kh),
        ],
    );
    let theirs = commit(&b, "from-b.txt");
    s.ok("push", &[&path_arg(&b), &s.key(), &kh_arg(&kh)]);
    let v = s.ok("pull", &[&path_arg(&a), &s.key(), &kh_arg(&kh)]);
    assert_eq!(v["status"], "updated");
    assert!(a.join("from-b.txt").exists());
    assert_eq!(s.server_main(), theirs);

    // Without a key the server refuses authentication.
    let (code, _, err) = s.run("pull", &[&path_arg(&a), &kh_arg(&kh)]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("[git.pull_"), "{err}");
}

#[test]
fn file_listing_only_some_key_types_is_accepted() {
    let s = Server::start();
    for types in [&["ecdsa"][..], &["ed25519"][..]] {
        let kh = s.known_hosts(types);
        let dest = s.p(&format!("c-{}", types[0]));
        let v = s.ok(
            "clone",
            &[
                &format!("url={}", s.ssh_url()),
                &path_arg(&dest),
                &s.key(),
                &kh_arg(&kh),
            ],
        );
        assert_eq!(v["status"], "cloned", "{types:?}");
    }
}

#[test]
fn rsa_only_file_is_accepted() {
    let s = Server::start();
    let kh = s.known_hosts(&["rsa"]);
    let dest = s.p("c");
    let v = s.ok(
        "clone",
        &[
            &format!("url={}", s.ssh_url()),
            &path_arg(&dest),
            &s.key(),
            &kh_arg(&kh),
        ],
    );
    assert_eq!(v["status"], "cloned");
}

/// The file lists only a key type the server does not have: the refusal
/// names the types the server offers and the type the file lists.
#[test]
fn key_type_the_server_lacks_names_offered_and_listed_types() {
    let s = Server::start();
    let key = s.p("p384");
    let st = Proc::new("ssh-keygen")
        .args(["-q", "-t", "ecdsa", "-b", "384", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(st.success());
    let public = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    let mut f = public.split_whitespace();
    let kh = s.p("kh-p384");
    std::fs::write(
        &kh,
        format!(
            "[127.0.0.1]:{} {} {}\n",
            s.ssh_port,
            f.next().unwrap(),
            f.next().unwrap()
        ),
    )
    .unwrap();
    let dest = s.p("c");
    let err = s.refused(
        "clone",
        &[
            &format!("url={}", s.ssh_url()),
            &path_arg(&dest),
            &s.key(),
            &kh_arg(&kh),
        ],
    );
    assert!(err.contains("ecdsa-sha2-nistp384"), "{err}");
    assert!(err.contains("ssh-ed25519"), "{err}");
    assert!(!dest.exists());
}

#[test]
fn wrong_unknown_and_revoked_keys_are_refused() {
    let s = Server::start();
    // A key that is not the server's.
    let other = s.p("other");
    let st = Proc::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&other)
        .status()
        .unwrap();
    assert!(st.success());
    let other_pub = std::fs::read_to_string(other.with_extension("pub")).unwrap();
    let mut f = other_pub.split_whitespace();
    let wrong = s.p("wrong");
    std::fs::write(
        &wrong,
        format!(
            "[127.0.0.1]:{} {} {}\n",
            s.ssh_port,
            f.next().unwrap(),
            f.next().unwrap()
        ),
    )
    .unwrap();
    let dest = s.p("c");
    let url = format!("url={}", s.ssh_url());
    let err = s.refused(
        "clone",
        &[&url, &path_arg(&dest), &s.key(), &kh_arg(&wrong)],
    );
    assert!(err.contains("does not match"), "{err}");

    let unknown = s.p("unknown");
    std::fs::write(&unknown, "otherhost ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n").unwrap();
    let err = s.refused(
        "clone",
        &[&url, &path_arg(&dest), &s.key(), &kh_arg(&unknown)],
    );
    assert!(err.contains("is not listed"), "{err}");

    let all = std::fs::read_to_string(s.known_hosts(&["ed25519", "ecdsa", "rsa"])).unwrap();
    let revoked = s.p("revoked");
    let rev: String = all
        .lines()
        .map(|l| format!("@revoked {l}\n{l}\n"))
        .collect();
    std::fs::write(&revoked, rev).unwrap();
    let err = s.refused(
        "clone",
        &[&url, &path_arg(&dest), &s.key(), &kh_arg(&revoked)],
    );
    assert!(err.contains("@revoked"), "{err}");
    assert!(!dest.exists());
}

/// An https URL rewritten to SSH by url.<base>.insteadOf (global config) or
/// pushInsteadOf (repository config) is checked against the file.
#[test]
fn insteadof_rewrites_to_ssh_are_checked() {
    let s = Server::start();
    std::fs::write(
        s.p("home/.gitconfig"),
        format!(
            "[url \"ssh://git@127.0.0.1:{}/srv/git/\"]\n\tinsteadOf = https://example.invalid/\n",
            s.ssh_port
        ),
    )
    .unwrap();
    let good = s.known_hosts(&["ed25519", "ecdsa", "rsa"]);
    let empty = s.p("empty");
    std::fs::write(&empty, "# nothing\n").unwrap();
    let url = "url=https://example.invalid/repo.git";

    let dest = s.p("refused");
    let err = s.refused("clone", &[url, &path_arg(&dest), &s.key(), &kh_arg(&empty)]);
    assert!(
        err.contains(&format!("[127.0.0.1]:{}", s.ssh_port)),
        "{err}"
    );
    assert!(!dest.exists());

    let dest = s.p("ok");
    s.ok("clone", &[url, &path_arg(&dest), &s.key(), &kh_arg(&good)]);
    assert!(dest.join("seed.txt").exists());
    // The clone's origin is the https URL; fetch and push use the rewrite.
    s.refused("pull", &[&path_arg(&dest), &s.key(), &kh_arg(&empty)]);
    commit(&dest, "x.txt");
    s.refused("push", &[&path_arg(&dest), &s.key(), &kh_arg(&empty)]);
    s.ok("push", &[&path_arg(&dest), &s.key(), &kh_arg(&good)]);

    // pushInsteadOf only: fetch goes to git://, push to SSH.
    std::fs::write(s.p("home/.gitconfig"), "").unwrap();
    let repo = git2::Repository::open(&dest).unwrap();
    repo.remote_set_url("origin", &s.git_url()).unwrap();
    repo.config()
        .unwrap()
        .set_str(
            &format!(
                "url.ssh://git@127.0.0.1:{}/srv/git/.pushInsteadOf",
                s.ssh_port
            ),
            &format!("git://127.0.0.1:{}/", s.git_port),
        )
        .unwrap();
    s.ok("pull", &[&path_arg(&dest), &kh_arg(&empty)]);
    s.refused("push", &[&path_arg(&dest), &s.key(), &kh_arg(&empty)]);
}

#[test]
fn git_daemon_clone_push_pull_and_sync() {
    let s = Server::start();
    let missing = s.p("no-such-known-hosts");
    let a = s.p("a");
    s.ok(
        "clone",
        &[
            &format!("url={}", s.git_url()),
            &path_arg(&a),
            &kh_arg(&missing),
        ],
    );
    let mine = commit(&a, "a.txt");
    s.ok("push", &[&path_arg(&a)]);
    assert_eq!(s.server_main(), mine);
    // A shallow clone over git:// has only the newest commit.
    let shallow = s.p("shallow");
    let v = s.ok(
        "clone",
        &[
            &format!("url={}", s.git_url()),
            &path_arg(&shallow),
            "depth=1",
        ],
    );
    assert_eq!(v["depth"], 1);
    assert!(shallow.join(".git/shallow").exists());
    let r = git2::Repository::open(&shallow).unwrap();
    let mut walk = r.revwalk().unwrap();
    walk.push_head().unwrap();
    assert_eq!(walk.count(), 1, "depth=1 keeps one commit");
    let b = s.p("b");
    s.ok("clone", &[&format!("url={}", s.git_url()), &path_arg(&b)]);
    let theirs = commit(&b, "b.txt");
    s.ok("sync", &[&path_arg(&b), "timeout_ms=60000"]);
    assert_eq!(s.server_main(), theirs);
    let v = s.ok("pull", &[&path_arg(&a), "prune=true"]);
    assert_eq!(v["status"], "updated");
}

#[test]
fn shallow_clone_over_ssh() {
    let s = Server::start();
    let kh = s.known_hosts(&["ed25519", "ecdsa", "rsa"]);
    let a = s.p("a");
    s.ok(
        "clone",
        &[
            &format!("url={}", s.ssh_url()),
            &path_arg(&a),
            &s.key(),
            &kh_arg(&kh),
        ],
    );
    commit(&a, "two.txt");
    s.ok("push", &[&path_arg(&a), &s.key(), &kh_arg(&kh)]);
    let shallow = s.p("shallow");
    s.ok(
        "clone",
        &[
            &format!("url={}", s.ssh_url()),
            &path_arg(&shallow),
            &s.key(),
            &kh_arg(&kh),
            "depth=1",
        ],
    );
    assert!(shallow.join(".git/shallow").exists());
    assert!(shallow.join("two.txt").exists());
}

/// pull and sync merge or rebase diverged history against a real server,
/// and a conflict leaves the clone exactly as it was.
#[test]
fn diverged_history_over_git_daemon() {
    let s = Server::start();
    let a = s.p("a");
    let b = s.p("b");
    s.ok("clone", &[&format!("url={}", s.git_url()), &path_arg(&a)]);
    s.ok("clone", &[&format!("url={}", s.git_url()), &path_arg(&b)]);
    for (dir, name) in [(&a, "A"), (&b, "B")] {
        let r = git2::Repository::open(dir).unwrap();
        let mut c = r.config().unwrap();
        c.set_str("user.name", name).unwrap();
        c.set_str("user.email", "e2e@example.invalid").unwrap();
    }
    commit(&a, "from-a.txt");
    s.ok("push", &[&path_arg(&a)]);
    commit(&b, "from-b.txt");
    let v = s.ok("pull", &[&path_arg(&b)]);
    assert_eq!(v["status"], "merged", "{v}");
    s.ok("push", &[&path_arg(&b)]);
    commit(&a, "again-a.txt");
    let v = s.ok("sync", &[&path_arg(&a), "pull_strategy=rebase"]);
    assert_eq!(v["integration"]["status"], "rebased", "{v}");
    let pushed = s.server_main();
    assert_eq!(
        git2::Repository::open(&a)
            .unwrap()
            .head()
            .unwrap()
            .target()
            .unwrap()
            .to_string(),
        pushed
    );

    // A conflicting edit: the clone is restored and nothing is pushed.
    std::fs::write(b.join("seed.txt"), "b side\n").unwrap();
    let rb = git2::Repository::open(&b).unwrap();
    let mut idx = rb.index().unwrap();
    idx.add_path(Path::new("seed.txt")).unwrap();
    idx.write().unwrap();
    let tree = rb.find_tree(idx.write_tree().unwrap()).unwrap();
    let sig = git2::Signature::now("B", "e2e@example.invalid").unwrap();
    let parent = rb.head().unwrap().peel_to_commit().unwrap();
    let local = rb
        .commit(Some("HEAD"), &sig, &sig, "b edit", &tree, &[&parent])
        .unwrap();
    std::fs::write(a.join("seed.txt"), "a side\n").unwrap();
    let ra = git2::Repository::open(&a).unwrap();
    let mut idx = ra.index().unwrap();
    idx.add_path(Path::new("seed.txt")).unwrap();
    idx.write().unwrap();
    let tree = ra.find_tree(idx.write_tree().unwrap()).unwrap();
    let parent = ra.head().unwrap().peel_to_commit().unwrap();
    ra.commit(Some("HEAD"), &sig, &sig, "a edit", &tree, &[&parent])
        .unwrap();
    s.ok("push", &[&path_arg(&a)]);
    let before_server = s.server_main();
    let (code, _, err) = s.run("sync", &[&path_arg(&b)]);
    assert_eq!(code, 1, "{err}");
    assert!(err.starts_with("Error: [git.sync_conflict] "), "{err}");
    assert!(err.contains("seed.txt"), "{err}");
    let rb = git2::Repository::open(&b).unwrap();
    assert_eq!(rb.head().unwrap().target(), Some(local));
    assert_eq!(rb.state(), git2::RepositoryState::Clean);
    assert_eq!(
        std::fs::read_to_string(b.join("seed.txt")).unwrap(),
        "b side\n"
    );
    assert_eq!(s.server_main(), before_server);
}
