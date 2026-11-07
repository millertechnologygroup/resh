//! End-to-end tests for file verbs that need root (changing ownership to
//! another user, trusted.* attributes, keeping a file's owner when root
//! rewrites it). They run inside a throwaway `debian:13-slim` container with
//! the host-built `resh` binary mounted read-only; nothing on the host is
//! changed.
//!
//! Run with `cargo test --features e2e-docker --test file_e2e_docker`.

#![cfg(feature = "e2e-docker")]

use std::process::Command;

const IMAGE: &str = "debian:13-slim";

/// Runs `script` with `sh -e` as root in a fresh container and returns its
/// stdout. The script fails the test when any command fails.
fn in_container(script: &str) -> String {
    in_container_with(&[], script)
}

fn in_container_with(extra: &[&str], script: &str) -> String {
    let bin = env!("CARGO_BIN_EXE_resh");
    let mount = format!("{bin}:/usr/local/bin/resh:ro");
    let mut args = vec!["run", "--rm", "--network=none", "-v", &mount];
    args.extend_from_slice(extra);
    args.extend_from_slice(&[IMAGE, "sh", "-ec", script]);
    let out = Command::new("docker")
        .args(&args)
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

/// The help example for chown, as written, against a real tree.
#[test]
fn chown_help_example_changes_owner_recursively_without_following_links() {
    let out = in_container(
        r#"
        groupadd -g 1600 www
        useradd -u 1500 -M alice
        mkdir -p /srv/www/css
        echo x > /srv/www/index.html
        echo y > /srv/www/css/site.css
        echo outside > /etc/outside
        ln -s /etc/outside /srv/www/escape
        resh file:///srv/www.chown user=alice group=www recursive=true
        echo "root=$(stat -c %u:%g /srv/www)"
        echo "file=$(stat -c %u:%g /srv/www/css/site.css)"
        echo "link=$(stat -c %u:%g /srv/www/escape)"
        echo "outside=$(stat -c %u:%g /etc/outside)"
        resh file:///srv/www/index.html.chown uid=0
        echo "uid_only=$(stat -c %u:%g /srv/www/index.html)"
        resh file:///srv/www.chown gid=0
        echo "gid_only=$(stat -c %u:%g /srv/www)"
        "#,
    );
    assert!(out.contains("root=1500:1600"), "{out}");
    assert!(out.contains("file=1500:1600"), "{out}");
    assert!(out.contains("link=1500:1600"), "{out}");
    assert!(out.contains("outside=0:0"), "{out}");
    assert!(out.contains("uid_only=0:1600"), "{out}");
    assert!(out.contains("gid_only=1500:0"), "{out}");
}

#[test]
fn chown_by_an_unprivileged_user_is_permission_denied() {
    let out = in_container(
        r#"
        useradd -u 1500 -M alice
        mkdir /work && chown alice /work
        su alice -s /bin/sh -c 'echo x > /work/f'
        set +e
        su alice -s /bin/sh -c 'resh file:///work/f.chown uid=0' 2>/tmp/err
        echo "code=$?"
        set -e
        echo "err=$(cat /tmp/err)"
        echo "owner=$(stat -c %u /work/f)"
        "#,
    );
    assert!(out.contains("code=1"), "{out}");
    assert!(
        out.contains("err=Error: PERMISSION_DENIED: chown /work/f"),
        "{out}"
    );
    assert!(out.contains("owner=1500"), "{out}");
}

#[test]
fn root_rewrite_keeps_the_owner_and_mode() {
    let out = in_container(
        r#"
        useradd -u 1500 -M alice
        echo 'port=8080' > /srv.conf
        chown alice /srv.conf
        chmod 640 /srv.conf
        resh file:///srv.conf.write data=port=1
        echo "write=$(stat -c %u:%a /srv.conf)"
        resh file:///srv.conf.replace pattern=1 replacement=2 >/dev/null
        echo "replace=$(stat -c %u:%a /srv.conf) $(cat /srv.conf)"
        resh file:///srv.conf.copy to=/copy.conf
        echo "copy=$(stat -c %u:%a /copy.conf)"
        "#,
    );
    assert!(out.contains("write=1500:640"), "{out}");
    assert!(out.contains("replace=1500:640 port=2"), "{out}");
    // copy creates a new file owned by the caller, with the mode preserved.
    assert!(out.contains("copy=0:640"), "{out}");
}

#[test]
fn trusted_attributes_work_as_root() {
    // trusted.* needs CAP_SYS_ADMIN, which only this container gets.
    let out = in_container_with(
        &["--cap-add", "SYS_ADMIN", "--tmpfs", "/data"],
        r#"
        echo x > /data/f
        resh file:///data/f.ea.set name=trusted.resh value=t1
        resh file:///data/f.ea.get name=trusted.resh
        set +e
        resh file:///data/f.ea.set name=trusted.resh value=t2 mode=create 2>/tmp/err
        echo "code=$?"
        set -e
        echo "err=$(cat /tmp/err)"
        "#,
    );
    assert!(out.contains(r#""value":"t1""#), "{out}");
    assert!(out.contains("code=1"), "{out}");
    assert!(out.contains("err=Error: ALREADY_EXISTS"), "{out}");
}

#[test]
fn delete_refuses_the_root_directory_even_as_root() {
    let out = in_container(
        r#"
        set +e
        resh 'file:///.delete' recursive=true 2>/tmp/err
        echo "code=$?"
        set -e
        echo "err=$(cat /tmp/err)"
        test -d /usr/local/bin && echo "intact=yes"
        "#,
    );
    assert!(out.contains("code=1"), "{out}");
    assert!(out.contains("REFUSED"), "{out}");
    assert!(out.contains("intact=yes"), "{out}");
}
