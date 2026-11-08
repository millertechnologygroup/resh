//! End-to-end tests of `pkg://` against the real package managers, each in a
//! throwaway container: apt (Debian 13, Ubuntu 24.04), dnf (Fedora 42), yum
//! (Rocky Linux 9, where yum is dnf's compatibility command), pacman (Arch
//! Linux) and apk (Alpine). Nothing on the host is installed or removed. The
//! containers download packages from their distributions' mirrors, so these
//! tests need network access.
//!
//! The host-built `resh` runs inside each container with the host's dynamic
//! loader and libraries, mounted read-only from a bundle directory, so one
//! binary works on every distribution (Alpine's musl and Rocky's older glibc
//! included). The package managers it starts are the container's own.
//!
//! Run with `cargo test --features e2e-docker --test pkg_e2e_docker`.

#![cfg(feature = "e2e-docker")]

use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// The resh binary with its loader and libraries.
fn bundle() -> &'static Path {
    static BUNDLE: OnceLock<PathBuf> = OnceLock::new();
    BUNDLE.get_or_init(|| {
        let dir = tempfile::Builder::new()
            .prefix("resh-pkg-e2e-")
            .tempdir()
            .unwrap()
            .keep();
        let resh = assert_cmd::cargo::cargo_bin!("resh");
        std::fs::copy(resh, dir.join("resh")).unwrap();
        let ldd = Command::new("ldd").arg(resh).output().unwrap();
        for line in String::from_utf8_lossy(&ldd.stdout).lines() {
            let line = line.trim();
            if let Some((name, rest)) = line.split_once(" => ") {
                let path = rest.split_whitespace().next().unwrap();
                std::fs::copy(path, dir.join(name.trim())).unwrap();
            } else if line.contains("ld-linux") {
                let path = line.split_whitespace().next().unwrap();
                std::fs::copy(path, dir.join("ld.so")).unwrap();
            }
        }
        assert!(dir.join("ld.so").exists(), "no loader in ldd output");
        dir
    })
}

struct Container {
    name: String,
    manager: &'static str,
}

struct Run {
    code: i32,
    json: Value,
    stdout: String,
    stderr: String,
}

impl Run {
    fn ok(&self) -> &Value {
        assert_eq!(
            self.code, 0,
            "stdout: {}\nstderr: {}",
            self.stdout, self.stderr
        );
        &self.json
    }
}

impl Container {
    fn start(image: &str, manager: &'static str) -> Self {
        let name = format!("resh-pkg-e2e-{manager}-{}", std::process::id());
        let _ = Command::new("docker").args(["rm", "-f", &name]).output();
        let out = Command::new("docker")
            .args(["run", "-d", "--rm", "--name", &name, "-v"])
            .arg(format!("{}:/resh-rt:ro", bundle().display()))
            .args([image, "sleep", "infinity"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "docker run {image}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Container { name, manager }
    }

    /// Runs a shell script in the container: (exit, stdout).
    fn sh(&self, script: &str) -> (i32, String) {
        let out = Command::new("docker")
            .args(["exec", &self.name, "sh", "-c", script])
            .output()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
        )
    }

    fn sh_ok(&self, script: &str) -> String {
        let (code, out) = self.sh(script);
        assert_eq!(code, 0, "{script}: {out}");
        out
    }

    fn resh(&self, verb: &str, mut input: Value) -> Run {
        input["manager"] = json!(self.manager);
        let out = Command::new("docker")
            .args([
                "exec",
                &self.name,
                "/resh-rt/ld.so",
                "--library-path",
                "/resh-rt",
                "/resh-rt/resh",
            ])
            .arg(format!("pkg://system.{verb}"))
            .arg(format!("input={input}"))
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        Run {
            code: out.status.code().unwrap_or(-1),
            json: serde_json::from_str(&stdout).unwrap_or(Value::Null),
            stdout,
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// The installed version of `package` by the manager's own query.
    fn version(&self, package: &str) -> Option<String> {
        let script = match self.manager {
            "apt" => format!(
                "dpkg-query -W -f='${{db:Status-Status}} ${{Version}}' {package} 2>/dev/null \
                 | sed -n 's/^installed //p'"
            ),
            "dnf" | "yum" => format!(
                "rpm -q --qf '%|EPOCH?{{%{{EPOCH}}:}}:{{}}|%{{VERSION}}-%{{RELEASE}}' {package}"
            ),
            "pacman" => format!("pacman -Q {package} | cut -d' ' -f2"),
            "apk" => format!("apk info -e -v {package} | sed 's/^{package}-//'"),
            _ => unreachable!(),
        };
        let (code, out) = self.sh(&script);
        (code == 0 && !out.is_empty()).then_some(out)
    }

    /// No package-manager process is left running.
    fn assert_no_manager_running(&self) {
        let (_, ps) =
            self.sh("for p in /proc/[0-9]*; do tr '\\0' ' ' < $p/cmdline 2>/dev/null; echo; done");
        for tool in ["apt-get", "dpkg", "dnf", "yum", "rpm", "pacman", "apk"] {
            let running: Vec<&str> = ps
                .lines()
                .filter(|l| {
                    l.split_whitespace()
                        .next()
                        .is_some_and(|w| w.ends_with(tool))
                })
                .collect();
            assert!(running.is_empty(), "{tool} still runs: {running:?}");
        }
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

/// The common cycle: refresh, install, snapshot, remove, restore the
/// snapshot (mode exact), check-only update, upgrade, and a timeout that
/// stops the manager in the middle of an install of `big`.
fn cycle(c: &Container, small: &str, big: &str) -> Value {
    // Refresh the index only.
    let r = c.resh("update", json!({"upgrade": false}));
    r.ok();

    let r = c.resh(
        "install",
        json!({"packages": [{"name": small}], "update_cache": false}),
    );
    let json = r.ok();
    assert_eq!(json["packages"][0]["action"], "installed", "{json}");
    let version = c.version(small).expect("installed");
    assert_eq!(json["packages"][0]["installed_version"], version.as_str());

    // Installing again changes nothing.
    let r = c.resh(
        "install",
        json!({"packages": [{"name": small}], "update_cache": false}),
    );
    assert_eq!(r.ok()["packages"][0]["action"], "unchanged");

    let r = c.resh("info", json!({"packages": [small]}));
    let info = &r.ok()["packages"][0];
    assert_eq!(info["installed"], true, "{info}");
    if c.manager == "apt" {
        // suite/component as in snapshot; the URL separately.
        let repo = info["repository"].as_str().unwrap();
        assert!(repo.contains('/'), "{info}");
        assert!(
            info["repository_url"].as_str().unwrap().starts_with("http"),
            "{info}"
        );
    }
    let r = c.resh("info", json!({"packages": ["resh-no-such-package"]}));
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert!(r.stderr.contains("[pkg.not_found]"), "{}", r.stderr);

    let r = c.resh(
        "search",
        json!({"query": small, "limit": 5, "timeout_ms": 120000}),
    );
    assert!(
        r.ok()["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == small),
        "{}",
        r.stdout
    );

    let r = c.resh(
        "list_installed",
        json!({"prefix": small, "include_repo": false}),
    );
    assert!(
        r.ok()["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == small && p["version"] == version.as_str()),
        "{}",
        r.stdout
    );

    let r = c.resh("snapshot", json!({"timeout_ms": 300000}));
    let lockfile = r.ok()["lockfile"].as_str().unwrap().to_string();
    let lock: Value = serde_json::from_str(&lockfile).unwrap();
    assert_eq!(lock["manager"]["name"], c.manager);
    let locked = lock["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == small)
        .unwrap()
        .clone();
    assert!(
        locked["version"]
            .as_str()
            .unwrap()
            .ends_with(version.as_str()),
        "{locked} vs {version}"
    );

    let r = c.resh("remove", json!({"packages": [{"name": small}]}));
    assert_eq!(r.ok()["packages"][0]["action"], "removed");
    assert_eq!(c.version(small), None);

    // Restore: only the removed package is missing.
    let restore = json!({"lockfile": lockfile, "on_repo_mismatch": "ignore",
                         "timeout_ms": 600000});
    let mut dry = restore.clone();
    dry["dry_run"] = json!(true);
    let r = c.resh("restore", dry);
    let plan = r.ok()["plan"].clone();
    assert_eq!(plan["install"], json!([small]), "{plan}");
    let r = c.resh("restore", restore.clone());
    let json = r.ok().clone();
    let op = &json["results"]["install"][0];
    assert_eq!(op["status"], "success", "{json}");
    assert_eq!(c.version(small).as_deref(), Some(version.as_str()));

    // An upstream-only snapshot (include_versions: minimal) restores a
    // build of the same upstream version.
    let r = c.resh(
        "snapshot",
        json!({"include_versions": "minimal", "include_repo": false, "timeout_ms": 300000}),
    );
    let minimal = r.ok()["lockfile"].as_str().unwrap().to_string();
    let lock: Value = serde_json::from_str(&minimal).unwrap();
    assert_eq!(lock["manager"]["config"]["include_versions"], "minimal");
    let upstream = lock["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == small)
        .unwrap()["version"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(version.contains(&upstream), "{upstream} vs {version}");
    assert_ne!(upstream, version, "the build/revision is dropped");
    c.resh("remove", json!({"packages": [{"name": small}]}))
        .ok();
    let r = c.resh(
        "restore",
        json!({"lockfile": minimal, "on_repo_mismatch": "ignore", "timeout_ms": 600000}),
    );
    let restored = r.ok();
    assert_eq!(
        restored["results"]["install"][0]["status"], "success",
        "{restored}"
    );
    assert!(c.version(small).unwrap().contains(&upstream));

    let r = c.resh("update", json!({"check_only": true}));
    r.ok();
    let r = c.resh(
        "upgrade",
        json!({"packages": [small], "refresh_index": false}),
    );
    r.ok();

    // A timeout in the middle of an install: exit 124, nothing left running.
    let r = c.resh(
        "install",
        json!({"packages": [{"name": big}], "update_cache": false, "timeout_ms": 2500}),
    );
    assert_eq!(r.code, 124, "{}\n{}", r.stdout, r.stderr);
    assert!(r.stderr.contains("[pkg.timeout]"), "{}", r.stderr);
    c.assert_no_manager_running();
    json
}

/// Picks a package with two versions in the repositories: (name, older,
/// newer), by the manager's own listing.
fn two_versions(c: &Container, candidates: &[&str]) -> Option<(String, String, String)> {
    for name in candidates {
        let script = match c.manager {
            "apt" => format!("apt-cache madison {name} | cut -d'|' -f2 | tr -d ' '"),
            "dnf" | "yum" => format!(
                "{} -q list --showduplicates --available {name} 2>/dev/null \
                 | awk '$1 ~ /^{name}\\./ {{print $2}}' | sort -u",
                c.manager
            ),
            _ => return None,
        };
        let (_, out) = c.sh(&script);
        let versions: Vec<&str> = out.lines().filter(|l| !l.is_empty()).collect();
        if versions.len() >= 2 {
            let (a, b) = (versions[0], versions[versions.len() - 1]);
            // madison lists newest first; dnf sorted ascending.
            let (old, new) = if c.manager == "apt" { (b, a) } else { (a, b) };
            return Some((name.to_string(), old.to_string(), new.to_string()));
        }
    }
    None
}

/// Installs the older version, upgrades it, and restores the older one
/// with mode exact (a downgrade).
fn downgrade_cycle(c: &Container, candidates: &[&str]) {
    let Some((name, old, new)) = two_versions(c, candidates) else {
        // The archives decide: right after a point release no candidate
        // may have two versions. The other distributions still cover it.
        eprintln!(
            "{}: no package with two versions among {candidates:?}; downgrade cycle skipped",
            c.manager
        );
        return;
    };
    let r = c.resh(
        "install",
        json!({"packages": [{"name": name, "version": old}], "update_cache": false,
               "allow_downgrade": true}),
    );
    r.ok();
    let installed = c.version(&name).unwrap();
    assert!(
        installed.ends_with(&old) || old.ends_with(&installed),
        "{installed} vs {old}"
    );
    let lockfile = json!({
        "lockfile_version": "pkg-lock/v1", "generated_at": "x",
        "manager": {"name": c.manager, "alias": "system", "version": null, "config": null},
        "platform": {"os_family": null, "os_name": null, "os_version": null,
                     "kernel": null, "architecture": null},
        "scope": "all", "packages": [{"name": name, "version": installed}]
    })
    .to_string();

    let r = c.resh(
        "upgrade",
        json!({"packages": [name], "refresh_index": false}),
    );
    r.ok();
    let upgraded = c.version(&name).unwrap();
    assert_ne!(upgraded, installed, "{name} was not upgraded to {new}");
    // Asking for the older version again needs allow_downgrade.
    let r = c.resh(
        "install",
        json!({"packages": [{"name": name, "version": old}], "update_cache": false}),
    );
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert!(r.stderr.contains("[pkg.downgrade_refused]"), "{}", r.stderr);
    assert_eq!(c.version(&name).unwrap(), upgraded);

    // allow_newer (default) keeps the newer version.
    let r = c.resh(
        "restore",
        json!({"lockfile": lockfile, "on_repo_mismatch": "ignore", "dry_run": true}),
    );
    assert_eq!(r.ok()["plan"]["keep"], json!([name]));
    let r = c.resh(
        "restore",
        json!({"lockfile": lockfile, "on_repo_mismatch": "ignore", "allow_newer": false,
               "allow_downgrades": true, "timeout_ms": 600000}),
    );
    let json = r.ok();
    assert_eq!(json["plan"]["downgrade"], json!([name]), "{json}");
    assert_eq!(
        json["results"]["downgrade"][0]["status"], "success",
        "{json}"
    );
    assert_eq!(c.version(&name).unwrap(), installed);
}

#[test]
fn apt_debian() {
    let c = Container::start("debian:13-slim", "apt");
    cycle(&c, "tree", "gcc");
    // A killed apt leaves dpkg state to repair (pkg.md 3.3); report it.
    let (_, audit) = c.sh("dpkg --audit");
    eprintln!("dpkg --audit after the timeout: {audit:?}");
    c.sh_ok("dpkg --configure -a");
    downgrade_cycle(
        &c,
        &[
            "tzdata",
            "libcap2",
            "curl",
            "openssl",
            "libsqlite3-0",
            "libexpat1",
            "libxml2",
        ],
    );
}

#[test]
fn apt_ubuntu() {
    let c = Container::start("ubuntu:24.04", "apt");
    cycle(&c, "tree", "gcc");
    c.sh_ok("dpkg --configure -a");
    downgrade_cycle(
        &c,
        &[
            "tzdata",
            "libcap2",
            "curl",
            "openssl",
            "libsqlite3-0",
            "libexpat1",
            "libxml2",
        ],
    );
}

#[test]
fn dnf_fedora() {
    let c = Container::start("fedora:42", "dnf");
    cycle(&c, "tree", "gcc");
    downgrade_cycle(&c, &["tzdata", "curl", "libcap"]);
}

#[test]
fn yum_rocky() {
    let c = Container::start("rockylinux:9", "yum");
    cycle(&c, "tree", "gcc");
}

#[test]
fn pacman_arch() {
    let c = Container::start("archlinux:latest", "pacman");
    cycle(&c, "tree", "gcc");
    // A killed pacman keeps its lock file (pkg.md 3.3).
    let (code, _) = c.sh("test -e /var/lib/pacman/db.lck");
    eprintln!("pacman db.lck left after the timeout: {}", code == 0);
    c.sh("rm -f /var/lib/pacman/db.lck");
    // mode exact cannot pin a version with pacman: refused before anything.
    let lockfile = json!({
        "lockfile_version": "pkg-lock/v1", "generated_at": "x",
        "manager": {"name": "pacman", "alias": "system", "version": null, "config": null},
        "platform": {"os_family": null, "os_name": null, "os_version": null,
                     "kernel": null, "architecture": null},
        "scope": "all", "packages": [{"name": "nano", "version": "1.0-1"}]
    })
    .to_string();
    let r = c.resh(
        "restore",
        json!({"lockfile": lockfile, "on_repo_mismatch": "ignore"}),
    );
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(
        r.stderr.contains("[pkg.unsupported_option]"),
        "{}",
        r.stderr
    );
    assert_eq!(c.version("nano"), None);
    let r = c.resh(
        "restore",
        json!({"lockfile": lockfile, "on_repo_mismatch": "ignore", "mode": "best_effort",
               "timeout_ms": 600000}),
    );
    let json = r.ok();
    assert!(
        json["warnings"]
            .to_string()
            .contains("cannot install a given version")
    );
    assert!(c.version("nano").is_some());
}

#[test]
fn apk_alpine() {
    let c = Container::start("alpine:3", "apk");
    cycle(&c, "tree", "gcc");
    let r = c.resh(
        "install",
        json!({"packages": [{"name": "jq"}], "assume_yes": false}),
    );
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(r.stderr.contains("[pkg.unsupported_option]"));
}
