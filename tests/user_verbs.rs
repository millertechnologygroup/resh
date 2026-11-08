//! Integration tests for `user://` through the built `resh` binary. Only
//! lookups, dry runs, the in-memory mock backend and refusals run here; no
//! account on the host is changed (a real change without root is refused
//! before any tool runs, and these tests never ask for one as root). Real
//! changes are tested in containers: tests/user_e2e_docker.rs.

use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};

const VERBS: &[&str] = &[
    "exists", "groups", "add", "delete", "passwd", "lock", "unlock",
];

/// A user name that exists on no host.
const NOSUCH: &str = "resh-it-nosuchuser";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    json: Value,
}

impl Run {
    #[track_caller]
    fn ok(&self) -> &Value {
        assert_eq!(self.code, 0, "{}\n{}", self.stdout, self.stderr);
        assert_eq!(self.json["ok"], true, "{}", self.stdout);
        &self.json
    }

    #[track_caller]
    fn fails(&self, exit: i32, code: &str) {
        assert_eq!(self.code, exit, "{}\n{}", self.stdout, self.stderr);
        assert!(
            self.stderr.starts_with(&format!("Error: [{code}] ")),
            "{code}: {}",
            self.stderr
        );
        if !self.stdout.is_empty() {
            assert_eq!(self.json["ok"], false, "{}", self.stdout);
            assert_eq!(self.json["error"]["code"], code, "{}", self.stdout);
        }
    }
}

fn resh_in(args: &[&str], stdin: &str, env: &[(&str, &str)]) -> Run {
    let bin = assert_cmd::cargo::cargo_bin!("resh");
    let mut cmd = Command::new(bin);
    cmd.env_remove("SSH_AUTH_SOCK")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        json: serde_json::from_str(&stdout).unwrap_or(Value::Null),
        stdout,
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

fn resh(args: &[&str]) -> Run {
    resh_in(args, "", &[])
}

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

fn user_exists(name: &str) -> bool {
    nix::unistd::User::from_name(name).ok().flatten().is_some()
}

// ---------------------------------------------------------------------------
// One test per verb
// ---------------------------------------------------------------------------

#[test]
fn exists_verb() {
    let v = resh(&["user://root.exists"]);
    assert_eq!(v.ok()["user"]["uid"], 0);
    let v = resh(&[&format!("user://{NOSUCH}.exists")]);
    assert_eq!(v.ok()["user"]["exists"], false);
    resh(&["user://root.exists", "uid=1"]).fails(1, "user.exists_mismatch");
    let v = resh(&["user:///root.exists", "uid=0", "format=text"]);
    assert_eq!(v.code, 0);
    assert!(v.stdout.contains("root"));
    resh(&["user://root.exists", "uid=x"]).fails(2, "user.invalid_argument");
    resh(&["user://root.exists", "dry_run=true"]).fails(2, "user.invalid_argument");
    resh(&["user://root.exists", "timeout_ms=5"]).fails(2, "user.invalid_argument");
    resh(&["user://-x.exists"]).fails(2, "user.username_invalid");
    resh(&["user://group/root.exists"]).fails(2, "user.invalid_target");
    let r = resh(&["user://root.exists", "uidd=0"]);
    r.fails(2, "user.invalid_argument");
    assert!(r.stderr.contains("did you mean `uid`?"), "{}", r.stderr);
}

#[test]
fn groups_verb() {
    let v = resh(&["user://root.groups"]);
    let j = v.ok();
    assert_eq!(j["groups"][0]["name"], "root");
    assert_eq!(j["groups"][0]["primary"], true);
    let v = resh(&["user://root.groups", "include_system_groups=false"]);
    assert_eq!(v.ok()["groups"].as_array().unwrap().len(), 0);
    resh(&[
        &format!("user://{NOSUCH}.groups"),
        "ignore_if_missing=false",
    ])
    .fails(1, "user.not_found");
    resh(&["user://root.groups", "include_primary=maybe"]).fails(2, "user.invalid_argument");
}

#[test]
fn add_verb() {
    let target = format!("user://{NOSUCH}.add");
    let v = resh(&[&target, "supplementary_groups=root", "dry_run=true"]);
    let j = v.ok();
    let planned = j["planned_commands"].as_array().unwrap();
    assert!(planned[0].as_str().unwrap().starts_with("groupadd -g "));
    assert!(planned[1].as_str().unwrap().ends_with(&format!(
        "-G root -d /home/{NOSUCH} -m -s /bin/bash -- {NOSUCH}"
    )));
    assert!(!user_exists(NOSUCH));
    let v = resh(&[&target, "backend=mock", "mode=user"]);
    assert_eq!(v.ok()["user"]["created"], true);
    resh(&[&target, "shell=bash"]).fails(2, "user.invalid_argument");
    resh(&[&target, "primary_group=-probe", "dry_run=true"]).fails(2, "user.group_name_invalid");
    resh(&[
        &target,
        "supplementary_groups=resh-it-nosuchgroup",
        "dry_run=true",
    ])
    .fails(1, "user.group_not_found");
    resh(&["user://root.add", "ignore_if_exists=false", "dry_run=true"])
        .fails(1, "user.username_conflict");
    resh(&[&target, "mode=grp"]).fails(2, "user.invalid_mode");
    resh(&[&target, "backend=ldap"]).fails(2, "user.backend_not_supported");
    if !is_root() {
        // A real change without root is refused before anything runs.
        resh(&[&target]).fails(1, "user.permission_denied");
        assert!(!user_exists(NOSUCH));
    }
}

#[test]
fn delete_verb() {
    let r = resh(&["user://root.delete", "dry_run=true"]);
    r.fails(1, "user.system_user_protected");
    assert_eq!(r.json["error"]["details"]["uid"], 0);
    let v = resh(&[&format!("user://{NOSUCH}.delete")]);
    assert_eq!(v.ok()["user"]["missing"], true);
    resh(&[
        &format!("user://{NOSUCH}.delete"),
        "ignore_if_missing=false",
    ])
    .fails(1, "user.not_found");
    resh(&["user://group/root.delete", "mode=group", "dry_run=true"])
        .fails(1, "user.group_system_protected");
    resh(&[
        "user://membership/root.delete",
        "mode=membership",
        "groups=root",
        "dry_run=true",
    ])
    .fails(1, "user.primary_group_membership");
    resh(&["user://root.delete", "remove_from_all_groups=false"]).fails(2, "user.invalid_argument");
}

#[test]
fn passwd_verb_never_shows_the_password() {
    let secret = "Pl41n-S3cret";
    // From stdin, on root (a dry run reads the account but changes nothing).
    let r = resh_in(
        &[
            "user://root.passwd",
            "new_password_stdin=true",
            "dry_run=true",
        ],
        &format!("{secret}\n"),
        &[],
    );
    let j = r.ok();
    assert_eq!(j["planned_commands"][0], "chpasswd -e <<< (redacted)");
    assert_eq!(j["password"]["source"], "stdin");
    assert!(!r.stdout.contains(secret) && !r.stderr.contains(secret));
    // From the environment.
    let r = resh_in(
        &[
            "user://root.passwd",
            "new_password_env=RESH_IT_PW",
            "dry_run=true",
        ],
        "",
        &[("RESH_IT_PW", secret)],
    );
    assert_eq!(r.ok()["password"]["source"], "env");
    assert!(!r.stdout.contains(secret));
    resh(&["user://root.passwd", "new_password_env=RESH_IT_UNSET_VAR"])
        .fails(2, "user.invalid_argument");
    resh(&[
        "user://root.passwd",
        "hash_scheme=argon2id",
        "new_password_plain=x",
    ])
    .fails(2, "user.hash_scheme_unsupported");
    resh(&["user://root.passwd"]).fails(2, "user.passwd_missing_new_password");
    let v = resh(&[&format!("user://{NOSUCH}.passwd"), "new_password_plain=x"]);
    assert_eq!(v.ok()["user"]["missing"], true);
    // A failure message never holds the password either.
    let r = resh(&[
        "user://root.passwd",
        "new_password_plain=a\tb",
        "force=true",
    ]);
    r.fails(2, "user.invalid_argument");
    assert!(!r.stderr.contains("a\tb"));
}

#[test]
fn lock_and_unlock_verbs() {
    for verb in ["lock", "unlock"] {
        resh(&[&format!("user://root.{verb}"), "dry_run=true"])
            .fails(1, "user.system_user_protected");
        let v = resh(&[&format!("user://{NOSUCH}.{verb}")]);
        assert_eq!(v.ok()["user"]["missing"], true);
        resh(&[
            &format!("user://{NOSUCH}.{verb}"),
            "ignore_if_missing=false",
        ])
        .fails(1, "user.not_found");
        resh(&[&format!("user://root.{verb}"), "force=perhaps"]).fails(2, "user.invalid_argument");
        resh(&[&format!("user://root.{verb}"), "timeout_ms=0"]).fails(2, "user.invalid_argument");
    }
}

#[test]
fn a_text_format_failure_prints_only_the_error_line() {
    let r = resh(&["user://root.delete", "format=text"]);
    r.fails(1, "user.system_user_protected");
    assert!(r.stdout.is_empty());
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

fn golden(verb: &str) -> &'static str {
    match verb {
        "exists" => include_str!("golden/user_exists_help.txt"),
        "groups" => include_str!("golden/user_groups_help.txt"),
        "add" => include_str!("golden/user_add_help.txt"),
        "delete" => include_str!("golden/user_delete_help.txt"),
        "passwd" => include_str!("golden/user_passwd_help.txt"),
        "lock" => include_str!("golden/user_lock_help.txt"),
        "unlock" => include_str!("golden/user_unlock_help.txt"),
        _ => unreachable!(),
    }
}

#[test]
fn handle_help_matches_golden_in_every_form() {
    let want = include_str!("golden/user_help.txt");
    for args in [
        &["user", "--help"][..],
        &["user", "-h"][..],
        &["user", "help"][..],
        &["help", "user"][..],
        &["user://--help"][..],
    ] {
        let r = resh(args);
        assert_eq!(r.code, 0, "{args:?}: {}", r.stderr);
        assert_eq!(r.stdout, want, "{args:?}");
    }
    assert!(want.lines().all(|l| l.len() <= 80));
}

#[test]
fn verb_help_matches_golden() {
    for verb in VERBS {
        for args in [
            vec!["user", verb, "--help"],
            vec!["user", verb, "-h"],
            vec!["help", "user", verb],
        ] {
            let r = resh(&args);
            assert_eq!(r.code, 0, "{args:?}");
            assert_eq!(r.stdout, golden(verb), "{args:?}: help differs from golden");
        }
        assert!(golden(verb).lines().all(|l| l.len() <= 80), "{verb}");
    }
    let r = resh(&["user", "lokc", "--help"]);
    assert_eq!(r.code, 2);
    assert!(r.stderr.contains("lock"), "{}", r.stderr);
}

fn example(verb: &str) -> (Vec<String>, Value) {
    let text = golden(verb);
    let line = text
        .lines()
        .skip_while(|l| *l != "Example:")
        .nth(1)
        .unwrap()
        .trim();
    let words: Vec<String> = line.split_whitespace().map(String::from).collect();
    assert_eq!(words[0], "resh");
    let start = text.find("Example Output:").unwrap();
    let body: String = text[start..]
        .lines()
        .skip(1)
        .take_while(|l| !l.trim_start().starts_with("Shown"))
        .collect::<Vec<_>>()
        .join("\n");
    (words[1..].to_vec(), serde_json::from_str(&body).unwrap())
}

fn keys(v: &Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    k.sort();
    k
}

/// The examples that are safe on any host run here (the others change an
/// account and run in tests/user_e2e_docker.rs).
#[test]
fn host_safe_help_examples_run() {
    for verb in ["exists", "groups"] {
        let (args, sample) = example(verb);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let r = resh(&args);
        assert_eq!(r.code, 0, "{verb}: {}", r.stderr);
        let got: Value = serde_json::from_str(&r.stdout).unwrap();
        assert_eq!(keys(&got), keys(&sample), "{verb}");
        assert_eq!(got["user"], sample["user"], "{verb}");
    }
    // add with dry_run=true, when the example's user does not exist here.
    let (args, sample) = example("add");
    if !user_exists("alice") {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let r = resh(&args);
        assert_eq!(r.code, 0, "{}", r.stderr);
        let got: Value = serde_json::from_str(&r.stdout).unwrap();
        assert_eq!(keys(&got), keys(&sample));
        assert_eq!(keys(&got["user"]), keys(&sample["user"]));
    }
}
