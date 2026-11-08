//! End-to-end tests of the plugin verbs that need root or a second user:
//! root with another user's HOME is refused, `scope=system` writes
//! `/var/lib/resh/plugins`, and a normal user cannot. They run inside a
//! throwaway `debian:13-slim` container with the host-built `resh` binary
//! mounted read-only and no network; nothing on the host is changed.
//!
//! Run with `cargo test --features e2e-docker --test plugin_e2e_docker`.

#![cfg(feature = "e2e-docker")]

use std::process::Command;

const IMAGE: &str = "debian:13-slim";

fn in_container(script: &str) -> String {
    let bin = env!("CARGO_BIN_EXE_resh");
    let mount = format!("{bin}:/usr/local/bin/resh:ro");
    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network=none",
            "-v",
            &mount,
            IMAGE,
            "sh",
            "-ec",
            script,
        ])
        .output()
        .expect("docker is required for e2e-docker tests");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "container script failed ({:?})\nstdout:\n{stdout}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

#[test]
fn root_with_another_users_home_is_refused() {
    let out = in_container(
        r#"
        useradd -m -u 1500 alice
        printf '#!/bin/sh\necho hi\n' > /tmp/tool
        chmod 644 /tmp/tool
        # alice installs into her own store.
        su alice -s /bin/sh -c 'resh plugin://tool.install source=file path=/tmp/tool >/dev/null'
        echo "alice_store=$(stat -c %U /home/alice/.local/share/resh/plugins)"
        # root keeping alice's environment (sudo -E) is refused.
        set +e
        HOME=/home/alice resh plugin://tool.remove >/dev/null 2>/tmp/err1
        echo "remove_exit=$?"
        HOME=/home/alice XDG_DATA_HOME=/home/alice/.local/share resh plugin://x.install source=file path=/tmp/tool >/dev/null 2>/tmp/err2
        echo "install_exit=$?"
        HOME=/home/alice resh plugin://installed.list >/dev/null 2>/tmp/err3
        echo "list_exit=$?"
        set -e
        echo "err1=$(cat /tmp/err1)"
        echo "err2=$(cat /tmp/err2)"
        echo "err3=$(cat /tmp/err3)"
        test -x /home/alice/.local/share/resh/plugins/tool/versions/local/tool && echo still_installed
        test ! -e /home/alice/.local/share/resh/plugins/x && echo nothing_new
        # root with its own HOME works.
        HOME=/root resh plugin://tool.install source=file path=/tmp/tool >/dev/null
        echo "root_store=$(stat -c %U /root/.local/share/resh/plugins)"
        "#,
    );
    assert!(out.contains("alice_store=alice"), "{out}");
    assert!(out.contains("remove_exit=1"), "{out}");
    assert!(out.contains("install_exit=1"), "{out}");
    assert!(out.contains("list_exit=1"), "{out}");
    for e in [
        "err1=Error: [plugin.unsafe_path]",
        "err2=Error: [plugin.unsafe_path]",
        "err3=Error: [plugin.unsafe_path]",
    ] {
        assert!(out.contains(e), "{e}: {out}");
    }
    assert!(out.contains("still_installed"), "{out}");
    assert!(out.contains("nothing_new"), "{out}");
    assert!(out.contains("root_store=root"), "{out}");
}

#[test]
fn system_scope_needs_root() {
    let out = in_container(
        r#"
        useradd -m -u 1500 alice
        printf '#!/bin/sh\n' > /tmp/tool
        chmod 644 /tmp/tool
        su alice -s /bin/sh -c 'resh plugin://tool.install source=file path=/tmp/tool >/dev/null'
        set +e
        su alice -s /bin/sh -c 'resh plugin://tool.enable scope=system' >/dev/null 2>/tmp/err
        echo "alice_exit=$?"
        set -e
        echo "err=$(cat /tmp/err)"
        HOME=/root resh plugin://tool.install source=file path=/tmp/tool >/dev/null
        HOME=/root resh plugin://tool.enable scope=system reason=fleet >/dev/null
        echo "mode=$(stat -c %a /var/lib/resh/plugins/state.json)"
        echo "dirmode=$(stat -c %a /var/lib/resh/plugins)"
        # alice reads the system state: her plugin is enabled through it.
        su alice -s /bin/sh -c 'resh plugin://installed.list format=summary' | grep -o '"enabled":true' && echo alice_sees_system
        "#,
    );
    assert!(out.contains("alice_exit=1"), "{out}");
    assert!(
        out.contains("err=Error: [plugin.permission_denied]"),
        "{out}"
    );
    assert!(out.contains("mode=644"), "{out}");
    assert!(out.contains("dirmode=755"), "{out}");
    assert!(out.contains("alice_sees_system"), "{out}");
}
