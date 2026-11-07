//! End-to-end tests for `log://svc/<service>` against a real systemd
//! journal, inside throwaway containers. Journal entries for made-up units
//! are written with systemd-journal-remote (from journal export format), so
//! no systemd needs to run as PID 1 and the container needs no privileges;
//! the real `journalctl` then reads them. The host-built `resh` binary is
//! mounted read-only; nothing on the host is changed.
//!
//! Images: `resh-log-e2e:1` (debian:13-slim with systemd and
//! systemd-journal-remote, built on first use) and `debian:13-slim` (no
//! journalctl).
//!
//! Run with `cargo test --features e2e-docker --test log_e2e_docker`.

#![cfg(feature = "e2e-docker")]

use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Once;

const IMAGE: &str = "resh-log-e2e:1";
const SLIM: &str = "debian:13-slim";

fn ensure_image() {
    static BUILD: Once = Once::new();
    BUILD.call_once(|| {
        let have = Command::new("docker")
            .args(["image", "inspect", IMAGE])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        if have.success() {
            return;
        }
        let mut child = Command::new("docker")
            .args(["build", "-q", "-t", IMAGE, "-"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(
                b"FROM debian:13-slim\nRUN apt-get update && DEBIAN_FRONTEND=noninteractive \
                  apt-get install -y --no-install-recommends systemd systemd-journal-remote \
                  && rm -rf /var/lib/apt/lists/*\n",
            )
            .unwrap();
        assert!(child.wait().unwrap().success(), "cannot build {IMAGE}");
    });
}

/// Shell functions: `mk <unit> "<n> ..." <text>` adds one entry per number,
/// with the message `<text> <n>`, to the system journal. The entries carry
/// the container's boot ID (journalctl --follow shows the current boot).
const PRELUDE: &str = r#"
set -e
B=$(tr -d - < /proc/sys/kernel/random/boot_id)
mk() {
  T=$(( $(date +%s) * 1000000 ))
  for i in $2; do
    printf '__REALTIME_TIMESTAMP=%s\n__MONOTONIC_TIMESTAMP=%s\n_BOOT_ID=%s\n_SYSTEMD_UNIT=%s\n_HOSTNAME=box\nSYSLOG_IDENTIFIER=demo\n_PID=42\nMESSAGE=%s %s\n\n' \
      $((T+i)) $i "$B" "$1" "$3" $i
  done > /tmp/entries.export
  /lib/systemd/systemd-journal-remote --output=/var/log/journal/remote.journal \
    /tmp/entries.export 2>/dev/null
}
mkdir -p /var/log/journal
mk demo.service "1 2 3" hello
mk other.service "4" other
set +e
"#;

struct Run {
    code: i32,
    out: String,
    err: String,
}

impl Run {
    fn json(&self) -> Value {
        serde_json::from_str(self.out.trim()).unwrap_or_else(|_| json!(self.out))
    }
}

/// Runs `script` (after PRELUDE) in a fresh container of `image`.
fn container(image: &str, script: &str) -> Run {
    ensure_image();
    let bin = env!("CARGO_BIN_EXE_resh");
    let mount = format!("{bin}:/usr/local/bin/resh:ro");
    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network=none",
            "-v",
            &mount,
            image,
            "sh",
            "-c",
        ])
        .arg(format!("{PRELUDE}\n{script}"))
        .output()
        .unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&out.stdout).into_owned(),
        err: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn messages(out: &str) -> Vec<String> {
    out.lines()
        .map(|l| l.rsplit_once(": ").map_or(l, |(_, m)| m).to_string())
        .collect()
}

#[test]
fn tail_reads_the_service_journal() {
    let r = container(IMAGE, "resh log://svc/demo.service.tail lines=2");
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(messages(&r.out), ["hello 2", "hello 3"]);
    assert!(r.out.contains(" box demo[42]: hello 2"), "{}", r.out);

    let r = container(
        IMAGE,
        "resh log://svc/demo.service.tail mode=json 'pattern=hello 3'",
    );
    assert_eq!(r.code, 0, "{}", r.err);
    let v = r.json();
    assert_eq!(v["service"], "demo.service");
    assert_eq!(v["requested_lines"], 100);
    assert_eq!(v["returned_lines"], 1);
    assert_eq!(v["pattern"], "hello 3");
    assert!(v["lines"][0].as_str().unwrap().ends_with("hello 3"), "{v}");

    // Only the named unit's entries.
    let r = container(IMAGE, "resh log://svc/other.service.tail");
    assert_eq!(messages(&r.out), ["other 4"]);
}

#[test]
fn a_unit_without_entries_is_an_empty_result() {
    let r = container(IMAGE, "resh log://svc/none.service.tail mode=json");
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.json()["lines"], json!([]));
    assert_eq!(r.json()["returned_lines"], 0);
}

#[test]
fn follow_streams_new_entries_until_the_deadline() {
    let r = container(
        IMAGE,
        r#"resh log://svc/demo.service.tail follow=true lines=1 timeout_ms=4000 &
sleep 1.5
mk demo.service "7 8" later
mk other.service "9" other
wait $!
echo "exit=$?""#,
    );
    let msgs = messages(&r.out);
    assert_eq!(
        msgs,
        ["hello 3", "later 7", "later 8", "exit=124"],
        "{}",
        r.err
    );
    assert!(r.err.contains("Error: [log.timeout] "), "{}", r.err);
}

#[test]
fn a_user_outside_the_journal_groups_is_denied() {
    let r = container(
        IMAGE,
        // The entries are written as root; resh runs as nobody.
        "su -s /bin/sh nobody -c 'resh log://svc/demo.service.tail mode=json'",
    );
    assert_eq!(r.code, 1, "{}\n{}", r.out, r.err);
    assert_eq!(r.json()["error"]["code"], "log.journal_access_denied");
    assert!(
        r.err.starts_with("Error: [log.journal_access_denied] "),
        "{}",
        r.err
    );
}

#[test]
fn without_journalctl_the_tool_is_reported_missing() {
    let bin = env!("CARGO_BIN_EXE_resh");
    let mount = format!("{bin}:/usr/local/bin/resh:ro");
    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network=none",
            "-v",
            &mount,
            SLIM,
            "resh",
            "log://svc/demo.service.tail",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.starts_with("Error: [log.journalctl_not_found] "),
        "{err}"
    );
}

#[test]
fn file_follow_in_a_container_survives_logrotate_style_rotation() {
    let r = container(
        IMAGE,
        r#"printf 'a\n' > /tmp/app.log
resh log:///tmp/app.log.tail follow=true timeout_ms=3000 &
sleep 0.5
printf 'b\n' >> /tmp/app.log
mv /tmp/app.log /tmp/app.log.1
printf 'c\n' > /tmp/app.log
sleep 0.5
: > /tmp/app.log
sleep 0.5
printf 'd\n' >> /tmp/app.log
wait $!
echo "exit=$?""#,
    );
    assert_eq!(r.out, "a\nb\nc\nd\nexit=124\n", "{}", r.err);
}
