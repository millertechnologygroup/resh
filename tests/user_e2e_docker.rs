//! End-to-end tests for `user://` against the real shadow-utils tools,
//! inside throwaway containers running as root. The host-built `resh`
//! binary is mounted read-only; every account, group, home directory and
//! password is created inside the container, and nothing on the host is
//! changed.
//!
//! Images (built on first use): `resh-user-debian:1` (Debian 13) and
//! `resh-user-fedora:1` (Fedora 42), each with perl, whose `crypt()` (the
//! system libxcrypt) checks the stored password hashes independently of
//! resh. Run with `cargo test --features e2e-docker --test user_e2e_docker`.

#![cfg(feature = "e2e-docker")]

use serde_json::Value;
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Once;

const DEBIAN: &str = "resh-user-debian:1";
const FEDORA: &str = "resh-user-fedora:1";

fn build(image: &str, dockerfile: &str) {
    let have = Command::new("docker")
        .args(["image", "inspect", image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    if have.success() {
        return;
    }
    let mut child = Command::new("docker")
        .args(["build", "-q", "-t", image, "-"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(dockerfile.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success(), "cannot build {image}");
}

fn ensure_images() {
    static BUILD: Once = Once::new();
    BUILD.call_once(|| {
        // Debian's base image has shadow-utils (passwd, login) and perl-base.
        build(DEBIAN, "FROM debian:13-slim\nRUN mkdir -p /var/mail\n");
        build(
            FEDORA,
            "FROM fedora:42\nRUN dnf install -y --setopt=install_weak_deps=False \
             shadow-utils passwd perl-interpreter util-linux && dnf clean all\n",
        );
    });
}

/// `r <tag> <command...>` prints `<tag>\t<exit>\t<stdout on one line>\t<stderr>`;
/// `check <name> <command...>` prints the command's output and status;
/// `crypt_ok <user> <password>` prints whether the system crypt() accepts
/// the password for the user's stored hash.
const PRELUDE: &str = r#"
r() {
  tag=$1; shift
  out=$("$@" 2>/tmp/err); code=$?
  printf '%s\t%s\t%s\t%s\n' "$tag" "$code" "$(printf '%s' "$out" | tr '\n' ' ')" "$(tr '\n' ' ' < /tmp/err)"
}
check() {
  name=$1; shift
  out=$("$@" 2>&1); code=$?
  printf 'check\t%s\t%s\n' "$name" "$(printf '%s|%s' "$code" "$out" | tr '\n' ' ')"
}
crypt_ok() {
  h=$(getent shadow "$1" | cut -d: -f2)
  perl -e '$h=shift; $p=shift; exit(crypt($p,$h) eq $h ? 0 : 1)' "$h" "$2"
}
"#;

struct Res {
    code: i32,
    json: Value,
    err: String,
}

struct Ctr {
    results: HashMap<String, Res>,
    checks: HashMap<String, String>,
    raw: String,
}

impl Ctr {
    fn parse(raw: String) -> Self {
        let mut results = HashMap::new();
        let mut checks = HashMap::new();
        for line in raw.lines() {
            let f: Vec<&str> = line.splitn(4, '\t').collect();
            if f[0] == "check" && f.len() >= 3 {
                checks.insert(f[1].to_string(), f[2].trim_end().to_string());
            } else if f.len() == 4 {
                results.insert(
                    f[0].to_string(),
                    Res {
                        code: f[1].parse().unwrap_or(-1),
                        json: serde_json::from_str(f[2]).unwrap_or(Value::Null),
                        err: f[3].to_string(),
                    },
                );
            }
        }
        Ctr {
            results,
            checks,
            raw,
        }
    }

    fn get(&self, tag: &str) -> &Res {
        self.results
            .get(tag)
            .unwrap_or_else(|| panic!("no result {tag}:\n{}", self.raw))
    }

    #[track_caller]
    fn ok(&self, tag: &str) -> &Value {
        let r = self.get(tag);
        assert_eq!(r.code, 0, "{tag}: {} {}", r.json, r.err);
        assert_eq!(r.json["ok"], true, "{tag}: {}", r.json);
        &r.json
    }

    #[track_caller]
    fn fails(&self, tag: &str, exit: i32, code: &str) -> &Value {
        let r = self.get(tag);
        assert_eq!(r.code, exit, "{tag}: {} {}", r.json, r.err);
        assert_eq!(r.json["error"]["code"], code, "{tag}: {}", r.json);
        assert!(r.err.contains(&format!("[{code}] ")), "{tag}: {}", r.err);
        &r.json
    }

    /// `(exit status, output)` of a check.
    #[track_caller]
    fn check(&self, name: &str) -> (i32, String) {
        let v = self
            .checks
            .get(name)
            .unwrap_or_else(|| panic!("no check {name}:\n{}", self.raw));
        let (code, out) = v.split_once('|').unwrap();
        (code.parse().unwrap(), out.to_string())
    }
}

fn mount() -> String {
    format!("{}:/usr/local/bin/resh:ro", env!("CARGO_BIN_EXE_resh"))
}

fn container(image: &str, script: &str) -> Ctr {
    ensure_images();
    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network=none",
            "-v",
            &mount(),
            image,
            "sh",
            "-c",
        ])
        .arg(format!("{PRELUDE}\n{script}"))
        .output()
        .unwrap();
    let raw = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "container failed: {raw}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ctr::parse(raw)
}

/// The account lifecycle: users, groups, memberships, passwords, lock
/// state, home directories, protections and failures.
const LIFECYCLE: &str = r#"
r add_alice     resh user://alice.add
check alice_pw  getent passwd alice
check alice_grp getent group alice
check alice_home test -d /home/alice
r add_again     resh user://alice.add
r add_conflict  resh user://alice.add ignore_if_exists=false
r add_group     resh user://group/dev.add mode=group gid=2000
r add_group2    resh user://group/ops.add mode=group
r gid_conflict  resh user://group/qa.add mode=group gid=2000
r add_bob       resh user://bob.add supplementary_groups=dev,ops shell=/bin/sh 'gecos=Bob Builder' create_home=false uid=3000 'password_hash=$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1'
check bob_pw    getent passwd bob
check bob_groups id -nG bob
check bob_nohome test -e /home/bob
check bob_crypt crypt_ok bob 'Hello world!'
r uid_conflict  resh user://carol.add uid=3000
r missing_sup   resh user://carol.add supplementary_groups=dev,nosuch
check carol_none getent group carol
r existing_pg   resh user://dave.add primary_group=dev
check dave_pw   getent passwd dave

# passwords
r pw_stdin      sh -c 'printf "Stdin-Pw1\n" | resh user://alice.passwd new_password_stdin=true'
check alice_crypt1 crypt_ok alice Stdin-Pw1
check alice_hash1 sh -c 'getent shadow alice | cut -d: -f2 | cut -c1-3'
r pw_bcrypt     env NEWPW='Bcrypt Pw 2' resh user://alice.passwd new_password_env=NEWPW hash_scheme=bcrypt
check alice_crypt2 crypt_ok alice 'Bcrypt Pw 2'
check alice_hash2 sh -c 'getent shadow alice | cut -d: -f2 | cut -c1-4'
r pw_old_ok     resh user://alice.passwd new_password_plain=Third-Pw3 require_old_password=true 'old_password_plain=Bcrypt Pw 2'
check alice_crypt3 crypt_ok alice Third-Pw3
r pw_old_bad    resh user://alice.passwd new_password_plain=Nope require_old_password=true old_password_plain=wrong
check alice_crypt4 crypt_ok alice Third-Pw3
r pw_argon      resh user://alice.passwd new_password_plain=x hash_scheme=argon2id
r pw_missing    resh user://nosuch.passwd new_password_plain=x ignore_if_missing=false
sh -c 'echo "dave:SysSha512" | chpasswd -c SHA512'
r pw_sys_sha    resh user://dave.passwd new_password_plain=After1 require_old_password=true old_password_plain=SysSha512
sh -c 'echo "dave:SysDefault" | chpasswd'
check dave_hash sh -c 'getent shadow dave | cut -d: -f2 | cut -c1-3'
r pw_sys_default_bad resh user://dave.passwd new_password_plain=After2 require_old_password=true old_password_plain=WrongOld
check dave_unchanged crypt_ok dave SysDefault
r pw_sys_default resh user://dave.passwd new_password_plain=After2 require_old_password=true old_password_plain=SysDefault
check dave_after crypt_ok dave After2
r pw_protected  env P=x resh user://daemon.passwd new_password_env=P
r pw_root_forced env P=RootPw9 resh user://root.passwd new_password_env=P force=true
check root_crypt crypt_ok root RootPw9

# lock / unlock
r lock          resh user://alice.lock
check locked_shadow sh -c 'getent shadow alice | cut -d: -f2 | cut -c1'
check locked_status passwd -S alice
r lock_again    resh user://alice.lock
r unlock        resh user://alice.unlock
check unlocked_crypt crypt_ok alice Third-Pw3
r unlock_again  resh user://alice.unlock
r add_erin      resh user://erin.add
r unlock_nopw   resh user://erin.unlock
r lock_root     resh user://root.lock
check root_shadow sh -c 'getent shadow root | cut -d: -f2 | cut -c1-2'
r lock_daemon_forced resh user://daemon.lock force=true
r unlock_daemon_forced resh user://daemon.unlock force=true

# memberships
r mem_add       resh user://membership/alice.add mode=membership groups=dev,ops
check alice_groups1 id -nG alice
r mem_again     resh user://membership/alice.add mode=membership groups=dev ignore_if_exists=false
r mem_del       resh user://membership/alice.delete mode=membership groups=dev
check alice_groups2 id -nG alice
r mem_primary   resh user://membership/alice.delete mode=membership groups=alice
r mem_all       resh user://membership/alice.delete mode=membership all_groups=true
check alice_groups3 id -nG alice

# groups and exists
r groups_bob    resh user://bob.groups
r exists_bob    resh user://bob.exists uid=3000
r exists_uid    resh user://.exists uid=3000

# deletes
r del_dev_nonempty resh user://group/dev.delete mode=group
r del_dev_forced   resh user://group/dev.delete mode=group force=true
check dev_gone  getent group dev
r del_root      resh user://root.delete
r del_sysgroup  resh user://group/root.delete mode=group
touch /var/mail/alice && chown alice /var/mail/alice
echo data > /home/alice/file
r del_alice     resh user://alice.delete remove_home=true
check alice_gone getent passwd alice
check alice_home_gone test -e /home/alice
check alice_mail_gone test -e /var/mail/alice
r del_again     resh user://alice.delete ignore_if_missing=false
touch /var/mail/dave
r del_dave_partial resh user://dave.delete remove_home=true
check dave_gone getent passwd dave
touch /var/mail/bob
r del_bob_mail  resh user://bob.delete remove_mail=true
check bob_gone  getent passwd bob
check bob_mail_gone test -e /var/mail/bob

# environment failures
r not_root      su nobody -s /bin/sh -c 'resh user://zed.add'
check zed_none  getent passwd zed
mkdir -p /tmp/slow && printf '#!/bin/sh\nsleep 30\n' > /tmp/slow/useradd && chmod +x /tmp/slow/useradd
start=$(date +%s)
r timeout       env PATH=/tmp/slow:/usr/sbin:/usr/bin:/sbin:/bin /usr/local/bin/resh user://slow.add timeout_ms=1000
end=$(date +%s)
check timeout_secs echo $((end - start))
check slow_none getent passwd slow
mkdir -p /tmp/empty
r no_tool       env PATH=/tmp/empty /usr/local/bin/resh user://notool.add
"#;

fn assert_lifecycle(c: &Ctr, image: &str) {
    let ctx = |s: &str| format!("{image}: {s}");
    // add
    let v = c.ok("add_alice");
    assert_eq!(v["user"]["created"], true);
    let uid = v["user"]["uid"].as_u64().unwrap();
    assert!(uid >= 1000, "{}", ctx("uid"));
    let (code, pw) = c.check("alice_pw");
    assert_eq!(code, 0);
    assert!(
        pw.starts_with(&format!("alice:x:{uid}:{uid}::/home/alice:/bin/bash")),
        "{pw}"
    );
    assert!(
        c.check("alice_grp")
            .1
            .starts_with(&format!("alice:x:{uid}:"))
    );
    assert_eq!(c.check("alice_home").0, 0);
    let v = c.ok("add_again");
    assert_eq!(v["user"]["existed"], true);
    assert_eq!(v["user"]["home"], "/home/alice");
    c.fails("add_conflict", 1, "user.username_conflict");
    assert_eq!(c.ok("add_group")["group"]["gid"], 2000);
    c.ok("add_group2");
    c.fails("gid_conflict", 1, "user.gid_conflict");
    let v = c.ok("add_bob");
    assert_eq!(v["password_set"], true);
    assert_eq!(
        c.check("bob_pw").1.trim(),
        "bob:x:3000:3000:Bob Builder:/home/bob:/bin/sh"
    );
    let groups = c.check("bob_groups").1;
    assert!(groups.contains("dev") && groups.contains("ops"), "{groups}");
    assert_ne!(c.check("bob_nohome").0, 0, "create_home=false");
    assert_eq!(
        c.check("bob_crypt").0,
        0,
        "{}",
        ctx("system crypt() accepts password_hash")
    );
    c.fails("uid_conflict", 1, "user.uid_conflict");
    c.fails("missing_sup", 1, "user.group_not_found");
    assert_ne!(c.check("carol_none").0, 0, "nothing was created");
    c.ok("existing_pg");
    assert!(
        c.check("dave_pw").1.contains(":2000:"),
        "{}",
        c.check("dave_pw").1
    );

    // passwords: the system crypt() checks each stored hash.
    let v = c.ok("pw_stdin");
    assert_eq!(v["password"]["source"], "stdin");
    assert_eq!(c.check("alice_crypt1").0, 0, "{}", ctx("sha512"));
    assert_eq!(c.check("alice_hash1").1.trim(), "$6$");
    c.ok("pw_bcrypt");
    assert_eq!(c.check("alice_crypt2").0, 0, "{}", ctx("bcrypt"));
    assert_eq!(c.check("alice_hash2").1.trim(), "$2b$");
    assert_eq!(c.ok("pw_old_ok")["password"]["old_password_verified"], true);
    assert_eq!(c.check("alice_crypt3").0, 0);
    c.fails("pw_old_bad", 1, "user.old_password_mismatch");
    assert_eq!(c.check("alice_crypt4").0, 0, "unchanged after a mismatch");
    c.fails("pw_argon", 2, "user.hash_scheme_unsupported");
    c.fails("pw_missing", 1, "user.not_found");
    // A hash made by the system's chpasswd is checked by resh.
    c.ok("pw_sys_sha");
    // chpasswd's default is yescrypt on both images; resh checks it
    // through the system crypt library.
    assert_eq!(c.check("dave_hash").1.trim(), "$y$", "{}", ctx("yescrypt"));
    c.fails("pw_sys_default_bad", 1, "user.old_password_mismatch");
    assert_eq!(c.check("dave_unchanged").0, 0, "unchanged after a mismatch");
    assert_eq!(
        c.ok("pw_sys_default")["password"]["old_password_verified"],
        true
    );
    assert_eq!(c.check("dave_after").0, 0);
    c.fails("pw_protected", 2, "user.protected_account");
    let v = c.ok("pw_root_forced");
    assert!(
        v["warnings"][0].as_str().unwrap().contains("force=true"),
        "{v}"
    );
    assert_eq!(c.check("root_crypt").0, 0);
    // new_password_plain always warns on stderr.
    assert!(
        c.get("pw_old_ok")
            .err
            .contains("Warning: new_password_plain="),
        "{}",
        c.get("pw_old_ok").err
    );

    // lock / unlock
    let v = c.ok("lock");
    assert_eq!(v["lock"]["changed"], true);
    assert_eq!(v["lock"]["is_locked"], true);
    assert_eq!(c.check("locked_shadow").1.trim(), "!");
    let status = c.check("locked_status").1;
    assert!(status.contains(" L") || status.contains(" LK"), "{status}");
    assert_eq!(c.ok("lock_again")["lock"]["changed"], false);
    let v = c.ok("unlock");
    assert_eq!(v["unlock"]["changed"], true);
    assert_eq!(c.check("unlocked_crypt").0, 0, "the password works again");
    assert_eq!(c.ok("unlock_again")["unlock"]["changed"], false);
    c.ok("add_erin");
    c.fails("unlock_nopw", 1, "user.unlock_backend_failure");
    c.fails("lock_root", 1, "user.system_user_protected");
    assert_ne!(c.check("root_shadow").1.trim(), "!$", "root untouched");
    c.ok("lock_daemon_forced");
    // daemon has no password (`*`), so it stays locked: unlocking fails.
    let r = c.get("unlock_daemon_forced");
    assert_ne!(r.code, 0);

    // memberships
    c.ok("mem_add");
    let g = c.check("alice_groups1").1;
    assert!(g.contains("dev") && g.contains("ops"), "{g}");
    c.fails("mem_again", 1, "user.membership_exists");
    c.ok("mem_del");
    let g = c.check("alice_groups2").1;
    assert!(!g.contains("dev") && g.contains("ops"), "{g}");
    c.fails("mem_primary", 1, "user.primary_group_membership");
    c.ok("mem_all");
    assert_eq!(c.check("alice_groups3").1.trim(), "alice");

    // lookups
    let v = c.ok("groups_bob");
    let names: Vec<&str> = v["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["name"].as_str().unwrap())
        .collect();
    assert_eq!(names[0], "bob");
    assert!(
        names.contains(&"dev") && names.contains(&"ops"),
        "{names:?}"
    );
    assert_eq!(c.ok("exists_bob")["user"]["exists"], true);
    assert_eq!(c.ok("exists_uid")["user"]["username"], "bob");

    // deletes
    c.fails("del_dev_nonempty", 1, "user.group_not_empty");
    // dev is dave's primary group: groupdel refuses even with force.
    c.fails("del_dev_forced", 1, "user.backend_operation_failed");
    assert_eq!(c.check("dev_gone").0, 0, "dev is still there");
    c.fails("del_root", 1, "user.system_user_protected");
    c.fails("del_sysgroup", 1, "user.group_system_protected");
    let v = c.ok("del_alice");
    assert_eq!(v["home"]["was_present"], true);
    assert_eq!(v["home"]["removed"], true);
    assert_eq!(v["mail"]["was_present"], true);
    assert_eq!(v["mail"]["removed"], true);
    assert_ne!(c.check("alice_gone").0, 0);
    assert_ne!(c.check("alice_home_gone").0, 0);
    assert_ne!(c.check("alice_mail_gone").0, 0);
    c.fails("del_again", 1, "user.not_found");
    // Debian's userdel deletes the account but refuses a spool another
    // user owns (exit 12): a partial failure. Fedora's removes it.
    if image == "debian" {
        let v = c.fails("del_dave_partial", 1, "user.partial_failure");
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap()
                .contains("was deleted"),
            "{v}"
        );
    } else {
        c.ok("del_dave_partial");
    }
    assert_ne!(c.check("dave_gone").0, 0);
    let v = c.ok("del_bob_mail");
    assert_eq!(v["mail"]["removed"], true);
    assert_ne!(c.check("bob_gone").0, 0);
    assert_ne!(c.check("bob_mail_gone").0, 0);

    // environment failures
    c.fails("not_root", 1, "user.permission_denied");
    assert_ne!(c.check("zed_none").0, 0);
    let r = c.get("timeout");
    assert_eq!(r.code, 124, "{}: {} {}", ctx("timeout"), r.json, r.err);
    assert!(r.err.contains("user.timeout"), "{}", r.err);
    let secs: u64 = c.check("timeout_secs").1.trim().parse().unwrap();
    assert!(secs < 15, "stopped at the deadline, took {secs}s");
    assert_ne!(c.check("slow_none").0, 0);
    c.fails("no_tool", 1, "user.tool_not_found");
}

#[test]
fn debian_account_lifecycle() {
    let c = container(DEBIAN, LIFECYCLE);
    assert_lifecycle(&c, "debian");
}

#[test]
fn fedora_account_lifecycle() {
    let c = container(FEDORA, LIFECYCLE);
    assert_lifecycle(&c, "fedora");
}

fn golden(verb: &str) -> &'static str {
    match verb {
        "delete" => include_str!("golden/user_delete_help.txt"),
        "passwd" => include_str!("golden/user_passwd_help.txt"),
        "lock" => include_str!("golden/user_lock_help.txt"),
        "unlock" => include_str!("golden/user_unlock_help.txt"),
        "add" => include_str!("golden/user_add_help.txt"),
        _ => unreachable!(),
    }
}

fn example(verb: &str) -> (String, Value) {
    let text = golden(verb);
    let line = text
        .lines()
        .skip_while(|l| *l != "Example:")
        .nth(1)
        .unwrap()
        .trim()
        .to_string();
    let start = text.find("Example Output:").unwrap();
    let body: String = text[start..]
        .lines()
        .skip(1)
        .take_while(|l| !l.trim_start().starts_with("Shown"))
        .collect::<Vec<_>>()
        .join("\n");
    (line, serde_json::from_str(&body).unwrap())
}

fn keys(v: &Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    k.sort();
    k
}

/// The help examples that change an account run against alice (uid 1001),
/// and give output of the documented shape.
#[test]
fn help_examples_run() {
    let mut script = String::from(
        "useradd -u 1000 filler\n\
         resh user://group/alice.add mode=group gid=1001 >/dev/null\n\
         resh user://alice.add uid=1001 >/dev/null\n\
         echo 'alice:pw' | chpasswd\n",
    );
    for verb in ["lock", "unlock", "passwd", "delete"] {
        let (line, _) = example(verb);
        script.push_str(&format!("r ex_{verb} env NEW_PW=S3cr3t {line}\n"));
    }
    // add's example user must not exist yet.
    script.push_str("resh user://alice.delete remove_home=true >/dev/null\n");
    script.push_str("resh user://group/alice.delete mode=group >/dev/null\n");
    let (line, _) = example("add");
    script.push_str(&format!("r ex_add {line}\n"));
    for image in [DEBIAN, FEDORA] {
        let c = container(image, &script);
        for verb in ["lock", "unlock", "passwd", "delete", "add"] {
            let (_, sample) = example(verb);
            let got = c.ok(&format!("ex_{verb}"));
            assert_eq!(keys(got), keys(&sample), "{image} {verb}: {got}");
            for k in keys(&sample) {
                if sample[&k].is_object() {
                    assert_eq!(keys(&got[&k]), keys(&sample[&k]), "{image} {verb}.{k}");
                }
            }
        }
        let v = c.ok("ex_delete");
        assert_eq!(v["planned_commands"][0], "userdel -r -- alice");
        let v = c.ok("ex_add");
        assert_eq!(
            v["planned_commands"][1],
            "useradd -u 1001 -g alice -d /home/alice -m -s /bin/zsh -- alice"
        );
    }
}
