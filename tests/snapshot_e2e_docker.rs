//! End-to-end `snapshot://` tests that need root, run inside throwaway
//! Docker containers (never on the host). Run with
//! `cargo test --features e2e-docker --test snapshot_e2e_docker`.
//!
//! The host-built `resh` binary is bind-mounted read-only into a
//! `debian:13-slim` container (glibc 2.41, new enough for the binary). As
//! root, snapshot keeps file ownership on create and restore; that cannot
//! be checked on the host without root.
#![cfg(feature = "e2e-docker")]

use std::process::Command;

const IMAGE: &str = "debian:13-slim";

/// Runs `script` with `sh -eu` as root in a fresh container and returns
/// (exit code, stdout, stderr).
fn in_container(script: &str) -> (i32, String, String) {
    let bin = env!("CARGO_BIN_EXE_resh");
    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network=none",
            "-v",
            &format!("{bin}:/usr/local/bin/resh:ro"),
            "-e",
            "XDG_STATE_HOME=/var/lib/resh-state",
            IMAGE,
            "sh",
            "-euc",
            script,
        ])
        .output()
        .expect("docker is required for e2e-docker tests");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn root_create_and_restore_keep_ownership_modes_and_times() {
    let script = r#"
mkdir -p /srv/app/conf
echo v1 > /srv/app/conf/main.conf
echo secret > /srv/app/key
chown -R 1000:1000 /srv/app
chown 1234:2345 /srv/app/key
chmod 0640 /srv/app/key
chmod 0750 /srv/app/conf
touch -d '2001-09-09 01:46:40' /srv/app/conf/main.conf

resh snapshot:///srv/app.create name=pre-change tags=e2e > /tmp/create.json
grep -q '"ok":true' /tmp/create.json
C=/var/lib/resh-state/resh/snapshots/_srv_app/pre-change/content
echo "snap-key $(stat -c %u:%g:%a $C/key)"

# Break the live tree: content, owner and mode.
echo broken > /srv/app/conf/main.conf
chown -R 0:0 /srv/app
chmod 0777 /srv/app/key
echo extra > /srv/app/extra

resh snapshot:///srv/app.diff from=pre-change to=live format=summary

resh snapshot://pre-change.restore target=/srv/app force=true dry_run > /tmp/dry.json
grep -q '"dry_run": true' /tmp/dry.json
test -f /srv/app/extra

resh snapshot://pre-change.restore target=/srv/app force=true
echo "restored-key $(stat -c %u:%g:%a /srv/app/key)"
echo "restored-conf $(stat -c %u:%g:%a /srv/app/conf)"
echo "restored-main $(stat -c %u:%g:%Y /srv/app/conf/main.conf) $(cat /srv/app/conf/main.conf)"
test ! -e /srv/app/extra && echo "extra-removed"
ls -A /srv | tr '\n' ' '; echo
resh snapshot:///srv/app.ls tag=e2e state=complete
"#;
    let (code, out, err) = in_container(script);
    assert_eq!(code, 0, "stdout:\n{out}\nstderr:\n{err}");
    assert!(out.contains("snap-key 1234:2345:640"), "{out}");
    assert!(out.contains("modified: 2"), "{out}"); // main.conf content, key mode
    assert!(out.contains("added: 1"), "{out}");
    assert!(out.contains(r#""status":"ok""#), "{out}");
    assert!(out.contains("restored-key 1234:2345:640"), "{out}");
    assert!(out.contains("restored-conf 1000:1000:750"), "{out}");
    assert!(
        out.contains("restored-main 1000:1000:1000000000 v1"),
        "{out}"
    );
    assert!(out.contains("extra-removed"), "{out}");
    // No temporary or backup entries left beside the target.
    assert!(out.contains("\napp \n"), "{out}");
    assert!(out.contains(r#""name":"pre-change""#), "{out}");
}

#[test]
fn root_restore_of_system_file_with_errors_reported() {
    let script = r#"
printf '127.0.0.1 localhost\n' > /etc/hosts.resh
chmod 0644 /etc/hosts.resh
resh snapshot:///etc/hosts.resh.create name=hosts-1 > /dev/null
echo '10.0.0.1 bad' > /etc/hosts.resh

set +e
resh snapshot://hosts-1.restore target=/etc/hosts.resh; echo "no-force=$?"
resh snapshot://missing.restore target=/etc/hosts.resh force=true; echo "missing=$?"
resh snapshot://hosts-1.restore target=/etc/hosts.resh force=true mode=merge; echo "mode=$?"
set -e
grep -q bad /etc/hosts.resh && echo "unchanged"

resh snapshot://hosts-1.restore target=/etc/hosts.resh force=true > /dev/null
cat /etc/hosts.resh
"#;
    let (code, out, err) = in_container(script);
    assert_eq!(code, 0, "stdout:\n{out}\nstderr:\n{err}");
    assert!(out.contains("no-force=1"), "{out}");
    assert!(out.contains("missing=1"), "{out}");
    assert!(out.contains("mode=2"), "{out}");
    assert!(out.contains("unchanged"), "{out}");
    assert!(out.ends_with("127.0.0.1 localhost\n"), "{out}");
}
