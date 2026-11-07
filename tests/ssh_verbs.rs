//! Integration tests for `ssh://` through the built `resh` binary. A fake
//! `ssh` on PATH runs the remote command with the local `sh` inside a
//! temporary "remote" directory (and stands in for `-s sftp`, `ssh -v` and
//! `-L` forwards), so every verb runs end to end without a network. The
//! user's real ~/.ssh is never touched. Real sshd tests are in
//! tests/ssh_e2e_docker.rs.

mod common;

use resh::handles::network::sshh::{VERBS, options_for};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const ED: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEP31YpA0Imm4x6v+o1r0O2XM9fZkMEDQUNAn9WtLLqt bob@laptop";

const FAKE_SSH: &str = r#"#!/bin/sh
printf '%s\n' "$*" >> "$RESH_TEST_LOG"
v=0; s=0; L=
while [ $# -gt 0 ]; do
  case "$1" in
    --) shift; break;;
    -v) v=1;;
    -s) s=1;;
    -L) shift; L=$1;;
    -p|-o|-i|-D|-R) shift;;
  esac
  shift
done
if [ $v = 1 ]; then
  echo "debug1: Server host key: ssh-ed25519 SHA256:fake" >&2
  echo "debug1: Host 'h' is known and matches the ED25519 host key." >&2
  echo "u@h: Permission denied (none)." >&2
  exit 255
fi
if [ $s = 1 ]; then head -c 9 >/dev/null; printf '\000\000\000\005\002\000\000\000\003'; cat >/dev/null; exit 0; fi
if [ -n "$L" ]; then exec socat "UNIX-LISTEN:${L%%:*},fork" "TCP:${L#*:}"; fi
cd "$FAKE_REMOTE_DIR" || exit 255
exec sh -c "$2"
"#;

struct Fx {
    tmp: TempDir,
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    json: Value,
}

impl Fx {
    fn new() -> Fx {
        let fx = Fx {
            tmp: TempDir::new().unwrap(),
        };
        for d in ["bin", "remote", "home"] {
            fs::create_dir(fx.path().join(d)).unwrap();
        }
        common::write_executable(&fx.path().join("bin/ssh"), FAKE_SSH);
        fx
    }
    fn path(&self) -> &Path {
        self.tmp.path()
    }
    fn remote(&self) -> PathBuf {
        self.path().join("remote")
    }
    fn calls(&self) -> Vec<String> {
        fs::read_to_string(self.path().join("log"))
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect()
    }
    fn run(&self, args: &[&str]) -> Run {
        let out = assert_cmd::cargo::cargo_bin_cmd!("resh")
            .current_dir(self.path())
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.path().join("bin").display()),
            )
            .env("HOME", self.path().join("home"))
            .env("USER", "resh-test")
            .env("RESH_TEST_LOG", self.path().join("log"))
            .env("FAKE_REMOTE_DIR", self.remote())
            .env_remove("SSH_AUTH_SOCK")
            .args(args)
            .output()
            .unwrap();
        let stdout = String::from_utf8(out.stdout).unwrap();
        let last = stdout
            .find("\n{")
            .filter(|_| stdout.starts_with("{\"event\""))
            .map(|i| &stdout[i + 1..])
            .unwrap_or(&stdout);
        Run {
            code: out.status.code().unwrap_or(-1),
            json: serde_json::from_str(last).unwrap_or(Value::Null),
            stdout,
            stderr: String::from_utf8(out.stderr).unwrap(),
        }
    }
}

fn ok(r: &Run) -> &Value {
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(r.json["ok"], true, "{}", r.stdout);
    &r.json
}

fn failed(r: &Run, exit: i32, code: &str) {
    assert_eq!(r.code, exit, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(r.json["error"]["code"], code, "{}", r.stdout);
    assert!(
        r.stderr.starts_with(&format!("Error: [{code}] ")),
        "stderr: {}",
        r.stderr
    );
}

// ----------------------------------------------------------------- verbs --

#[test]
fn exec_runs_the_remote_command() {
    let fx = Fx::new();
    let r = fx.run(&[
        "ssh://alice@web01:2222.exec",
        "command=printf '%s|' ",
        "command_args=a b,c",
    ]);
    assert_eq!(ok(&r)["result"]["stdout"], "a b|c|");
    assert!(fx.calls()[0].contains("-p 2222"));
    assert!(fx.calls()[0].contains("alice@web01"));
    let r = fx.run(&["ssh://alice@web01.exec", "command=exit 7"]);
    failed(&r, 1, "ssh.remote_exit_nonzero");
    assert_eq!(r.json["result"]["exit_code"], 7);
    let r = fx.run(&[
        "ssh://alice@web01.exec",
        "command=sleep 20",
        "command_timeout_ms=300",
    ]);
    failed(&r, 124, "ssh.exec_timeout");
    let r = fx.run(&["ssh://alice@web01.exec", "comand=ls"]);
    failed(&r, 2, "ssh.invalid_argument");
    assert!(r.stderr.contains("did you mean `command`"));
    // Three runs plus the kill of the timed-out command; nothing for the
    // refused call.
    assert_eq!(fx.calls().len(), 4, "the refused call must not run ssh");
    assert!(fx.calls()[3].contains("kill -s TERM"), "{:?}", fx.calls());
}

#[test]
fn exec_without_ssh_installed() {
    let fx = Fx::new();
    fs::remove_file(fx.path().join("bin/ssh")).unwrap();
    let out = assert_cmd::cargo::cargo_bin_cmd!("resh")
        .env("PATH", fx.path().join("bin"))
        .args(["ssh://u@h.exec", "command=true"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["error"]["code"], "ssh.tool_not_found");
}

#[test]
fn upload_and_download_round_trip() {
    let fx = Fx::new();
    fs::write(fx.path().join("app.conf"), "key=value\n").unwrap();
    let r = fx.run(&[
        "ssh://alice@web01.upload",
        "source=app.conf",
        "dest=srv/app.conf",
        "file_mode=0640",
        "verify_checksum=true",
    ]);
    assert_eq!(ok(&r)["result"]["checksum_verified"], true);
    assert_eq!(
        fs::read_to_string(fx.remote().join("srv/app.conf")).unwrap(),
        "key=value\n"
    );
    let r = fx.run(&[
        "ssh://alice@web01.upload",
        "source=app.conf",
        "dest=srv/app.conf",
    ]);
    failed(&r, 1, "ssh.upload_dest_exists");
    let r = fx.run(&[
        "ssh://alice@web01.download",
        "source=srv/app.conf",
        "dest=copy/app.conf",
        "verify_checksum=true",
    ]);
    ok(&r);
    assert_eq!(
        fs::read_to_string(fx.path().join("copy/app.conf")).unwrap(),
        "key=value\n"
    );
    let r = fx.run(&[
        "ssh://alice@web01.download",
        "source=missing",
        "dest_mode=none",
    ]);
    failed(&r, 1, "ssh.download_source_not_found");
    let r = fx.run(&["ssh://alice@web01.download", "source=x"]);
    failed(&r, 2, "ssh.download_dest_missing");
}

#[test]
fn keys_list_and_key_add() {
    let fx = Fx::new();
    let ak = fx.remote().join("ak");
    fs::write(fx.path().join("id.pub"), format!("{ED}\n")).unwrap();
    let r = fx.run(&[
        "ssh://bob@web01.key.add",
        "public_key_path=id.pub",
        "scope=custom",
        &format!("custom_paths={}", ak.display()),
    ]);
    assert_eq!(ok(&r)["operation"]["status"], "added");
    assert_eq!(fs::read_to_string(&ak).unwrap(), format!("{ED}\n"));
    let r = fx.run(&[
        "ssh://bob@web01.key.add",
        "public_key_path=id.pub",
        "scope=custom",
        &format!("custom_paths={}", ak.display()),
        "on_duplicate=error",
    ]);
    failed(&r, 1, "ssh.key_add_duplicate");
    let r = fx.run(&[
        "ssh://bob@web01.keys.list",
        "scope=custom",
        &format!("custom_paths={}", ak.display()),
    ]);
    let j = ok(&r);
    assert_eq!(j["files"][0]["keys"][0]["type"], "ed25519");
    assert_eq!(j["summary"]["total_keys"], 1);
    let r = fx.run(&["ssh://web01.keys.list"]);
    failed(&r, 2, "ssh.username_required");
}

#[test]
fn test_verb_checks() {
    let fx = Fx::new();
    let r = fx.run(&[
        "ssh://alice@web01.test",
        "tests=connect,auth,exec,sftp,hostkey",
        "exec_command=true",
    ]);
    let j = ok(&r);
    assert_eq!(j["summary"]["tests_passed"], 5);
    assert_eq!(j["security"]["hostkey_fingerprint"], "SHA256:fake");
    let r = fx.run(&["ssh://alice@web01.test", "tests=exec", "exec_command=false"]);
    failed(&r, 1, "ssh.test_failed");
    let r = fx.run(&["ssh://alice@web01.test", "tests=ping"]);
    failed(&r, 2, "ssh.test_invalid_test_name");
}

#[test]
fn config_get_reads_local_files_only() {
    let fx = Fx::new();
    fs::write(
        fx.path().join("cfg"),
        "Host web01\n  User alice\n  Port 2222\n",
    )
    .unwrap();
    let r = fx.run(&[
        "ssh://web01.config.get",
        "user_config_path=cfg",
        "system_config_path=/dev/null",
    ]);
    assert_eq!(ok(&r)["effective"]["Port"]["value"], "2222");
    assert!(fx.calls().is_empty());
    let r = fx.run(&["ssh://web01.config.get", "timeout_ms=10"]);
    failed(&r, 2, "ssh.invalid_argument");
}

#[test]
fn tunnel_local_forward() {
    use std::io::{BufRead, Read, Write};
    if which::which("socat").is_err() {
        eprintln!("skipped: socat is not installed");
        return;
    }
    let fx = Fx::new();
    let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dest = echo.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in echo.incoming().flatten() {
            let mut r = c.try_clone().unwrap();
            let mut w = c;
            let _ = std::io::copy(&mut r, &mut w);
        }
    });
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_resh"))
        .current_dir(fx.path())
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", fx.path().join("bin").display()),
        )
        .env("HOME", fx.path().join("home"))
        .env("RESH_TEST_LOG", fx.path().join("log"))
        .env_remove("SSH_AUTH_SOCK")
        .args([
            "ssh://alice@bastion.tunnel",
            "mode=local",
            "remote_dest_host=127.0.0.1",
            &format!("remote_dest_port={dest}"),
            "tunnel_timeout_ms=20000",
        ])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut first = String::new();
    stdout.read_line(&mut first).unwrap();
    let ready: Value = serde_json::from_str(&first).unwrap();
    assert_eq!(ready["event"], "ready");
    let listen = ready["listen"].as_str().unwrap().to_string();
    let mut c = std::net::TcpStream::connect(&listen).unwrap();
    c.write_all(b"ping").unwrap();
    let mut buf = [0u8; 4];
    c.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ping");
    drop(c);
    // SIGTERM is the normal way to close an open-ended tunnel.
    unsafe {
        libc_kill(child.id() as i32, 15);
    }
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).unwrap();
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(0), "{rest}");
    let report: Value = serde_json::from_str(&rest).unwrap();
    assert_eq!(report["lifetime"]["closed_reason"], "interrupted");
    assert_eq!(report["stats"]["bytes_in"], 4);
    assert_eq!(report["stats"]["connections_accepted"], 1);
}

unsafe extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

// ------------------------------------------------------------------ help --

fn assert_plain(out: &str) {
    assert!(out.is_ascii(), "non-ASCII");
    for line in out.lines() {
        assert!(line.len() <= 80, "line over 80 columns: {line:?}");
        assert!(!line.ends_with(' '), "trailing space: {line:?}");
    }
}

fn golden(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("ssh_{name}help.txt"));
    if std::env::var_os("RESH_UPDATE_GOLDEN").is_some() {
        return String::new();
    }
    fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing golden {}", path.display()))
}

fn check_golden(name: &str, out: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("ssh_{name}help.txt"));
    if std::env::var_os("RESH_UPDATE_GOLDEN").is_some() {
        fs::write(path, out).unwrap();
        return;
    }
    assert_eq!(out, golden(name), "help differs from golden {name}");
}

#[test]
fn handle_help_matches_golden_and_lists_every_verb() {
    let fx = Fx::new();
    for spelling in [
        &["ssh", "--help"][..],
        &["ssh", "-h"],
        &["help", "ssh"],
        &["ssh://--help"],
    ] {
        let r = fx.run(spelling);
        assert_eq!(r.code, 0, "{spelling:?}");
        assert_plain(&r.stdout);
        check_golden("", &r.stdout);
        let listed: Vec<&str> = r
            .stdout
            .split("Available Verbs:\n")
            .nth(1)
            .unwrap()
            .split("\n\n")
            .next()
            .unwrap()
            .lines()
            .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
            .map(|l| l.split_whitespace().next().unwrap())
            .collect();
        assert_eq!(listed, VERBS);
    }
}

fn usage_options(out: &str) -> Vec<String> {
    let usage = out
        .split("Usage:\n")
        .nth(1)
        .unwrap()
        .split("\n\n")
        .next()
        .unwrap();
    let mut v: Vec<String> = usage
        .split(|c: char| c.is_whitespace() || c == '[' || c == ']')
        .filter_map(|w| w.split_once('=').map(|(k, _)| k.to_string()))
        .filter(|k| !k.is_empty() && !k.contains(':'))
        .collect();
    v.sort();
    v.dedup();
    v
}

#[test]
fn verb_help_matches_golden_and_lists_every_option() {
    let fx = Fx::new();
    for verb in VERBS {
        let r = fx.run(&["ssh", verb, "--help"]);
        assert_eq!(r.code, 0, "{verb}");
        assert_eq!(r.stderr, "");
        assert_plain(&r.stdout);
        assert!(
            r.stdout
                .starts_with(&format!("Handle: ssh\nVerb: {verb}\nDefinition: "))
        );
        for section in ["\nUsage:\n", "\nExample:\n", "\nExample Output:\n"] {
            assert!(r.stdout.contains(section), "{verb}: {section:?}");
        }
        check_golden(&format!("{verb}_"), &r.stdout);
        let mut want: Vec<String> = options_for(verb)
            .unwrap()
            .iter()
            .map(|s| s.to_string())
            .collect();
        want.sort();
        assert_eq!(usage_options(&r.stdout), want, "{verb}");
        for other in [
            vec!["ssh".to_string(), verb.to_string(), "-h".into()],
            vec!["help".into(), "ssh".into(), verb.to_string()],
            vec![format!("ssh://--help={verb}")],
        ] {
            let argv: Vec<&str> = other.iter().map(String::as_str).collect();
            assert_eq!(fx.run(&argv).stdout, r.stdout, "{other:?}");
        }
    }
}

fn shell_words(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in s.chars() {
        match c {
            '\'' => quoted = !quoted,
            ' ' if !quoted => {
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

fn keys(v: &Value, prefix: &str, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, v) in m {
                let p = format!("{prefix}.{k}");
                out.push(p.clone());
                keys(v, &p, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|v| keys(v, &format!("{prefix}[]"), out)),
        _ => {}
    }
}

fn shape(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    keys(v, "", &mut out);
    out.sort();
    out.dedup();
    out
}

/// Every help example runs against the fake remote and prints a report with
/// the same fields as its sample output.
#[test]
fn help_examples_run_and_match_their_sample_output() {
    let fx = Fx::new();
    fs::write(fx.path().join("app.conf"), "x=1\n").unwrap();
    fs::write(fx.path().join("id.pub"), format!("{ED}\n")).unwrap();
    fs::write(
        fx.path().join("cfg"),
        "Host web01\n  HostName 192.0.2.10\n  User alice\n",
    )
    .unwrap();
    // keys.list example: ~alice is not a local user, so the fake remote
    // shell keeps "~alice/..." as a relative path.
    let ak = fx.remote().join("~alice/.ssh");
    fs::create_dir_all(&ak).unwrap();
    fs::write(ak.join("authorized_keys"), format!("{ED}\n")).unwrap();
    for verb in VERBS {
        let help = fx.run(&["ssh", verb, "--help"]).stdout;
        let example = help
            .split("Example:\n")
            .nth(1)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .trim();
        let words = shell_words(example);
        assert_eq!(words[0], "resh");
        let argv: Vec<&str> = words[1..].iter().map(String::as_str).collect();
        let r = fx.run(&argv);
        assert_eq!(r.code, 0, "{verb}: {example}: {}\n{}", r.stdout, r.stderr);
        let sample: String = help
            .split("Example Output:\n")
            .nth(1)
            .unwrap()
            .split("\n\n")
            .next()
            .unwrap()
            .lines()
            .map(|l| l.strip_prefix("  ").unwrap_or(l))
            .collect::<Vec<_>>()
            .join("\n");
        let sample: Value = serde_json::from_str(&sample).unwrap();
        assert_eq!(shape(&r.json), shape(&sample), "{verb}");
    }
}
