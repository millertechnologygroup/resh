//! Release-candidate regression tests that need the real `resh` binary: each
//! runs it in its own temporary directory (as the working directory) with
//! HOME and the XDG directories pointed inside it. Nothing outside the
//! temporary directory is touched, and nothing reaches the network.

use assert_cmd::Command;
use std::path::Path;
use tempfile::TempDir;

fn resh(dir: &Path) -> Command {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
    cmd.current_dir(dir)
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("XDG_DATA_HOME", dir.join("data"))
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("XDG_CACHE_HOME", dir.join("cache"));
    cmd
}

/// `rename to=<bare name> overwrite=true` used to delete the existing
/// destination and then fail ("destination parent does not exist"), losing
/// it. A bare name is relative to the working directory.
#[test]
fn rename_to_bare_name_with_overwrite_keeps_data() {
    let tmp = TempDir::new().unwrap();
    std::fs::write(tmp.path().join("src.txt"), "new").unwrap();
    std::fs::write(tmp.path().join("dst.txt"), "old").unwrap();
    resh(tmp.path())
        .args(["file://src.txt.rename", "to=dst.txt", "overwrite=true"])
        .assert()
        .success();
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("dst.txt")).unwrap(),
        "new"
    );
    assert!(!tmp.path().join("src.txt").exists());

    // Without overwrite an existing destination is refused and kept.
    std::fs::write(tmp.path().join("a.txt"), "a").unwrap();
    resh(tmp.path())
        .args(["file://a.txt.rename", "to=dst.txt"])
        .assert()
        .failure();
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("dst.txt")).unwrap(),
        "new"
    );

    // A missing parent fails before the existing destination is touched.
    resh(tmp.path())
        .args([
            "file://a.txt.rename",
            "to=missing/dst.txt",
            "overwrite=true",
        ])
        .assert()
        .failure();
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("a.txt")).unwrap(),
        "a"
    );
}

#[test]
fn copy_and_move_accept_bare_destination_names() {
    let tmp = TempDir::new().unwrap();
    std::fs::write(tmp.path().join("one.txt"), "1").unwrap();
    resh(tmp.path())
        .args(["file://one.txt.copy", "to=two.txt"])
        .assert()
        .success();
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("two.txt")).unwrap(),
        "1"
    );
    resh(tmp.path())
        .args(["file://two.txt.move", "to=three.txt"])
        .assert()
        .success();
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("three.txt")).unwrap(),
        "1"
    );
    assert!(!tmp.path().join("two.txt").exists());
}

/// `mail://send` has no dry run. Through the CLI (including main.rs's
/// rewrite of a bare `dry_run` word) a dry-run request is refused before any
/// SMTP connection is attempted.
#[test]
fn mail_send_dry_run_is_refused_through_the_cli() {
    let tmp = TempDir::new().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = format!("smtp_port={}", listener.local_addr().unwrap().port());
    for dry in ["dry_run", "dry_run=true", "dry_run=1"] {
        let out = resh(tmp.path())
            .args([
                "mail://send",
                "to=a@example.com",
                "subject=s",
                "text_body=b",
                "from=f@example.com",
                "smtp_host=127.0.0.1",
                &port,
                "use_tls=none",
                dry,
            ])
            .output()
            .unwrap();
        assert!(!out.status.success(), "{dry}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("does not support dry_run"), "{dry}: {err}");
        assert!(
            matches!(listener.accept(), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "{dry}: an SMTP connection was opened"
        );
    }
}

/// `backup restore` has no dry run; a dry-run request must not restore.
#[test]
fn backup_restore_dry_run_is_refused_through_the_cli() {
    let tmp = TempDir::new().unwrap();
    let dest = tmp.path().join("dest");
    std::fs::create_dir(&dest).unwrap();
    std::fs::write(dest.join("keep.txt"), "original").unwrap();
    let out = resh(tmp.path())
        .args([
            "backup://t.restore",
            "backend=tar",
            "repo_url=repo",
            "snapshot_id=x",
            "dest=dest",
            "dry_run",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("does not support dry_run"));
    assert_eq!(std::fs::read_dir(&dest).unwrap().count(), 1);
}

/// security_only must never widen into a full upgrade: refused before any
/// package-manager command, here in dry run with apt.
#[test]
fn pkg_security_only_is_refused_where_unsupported() {
    let tmp = TempDir::new().unwrap();
    let out = resh(tmp.path())
        .args([
            "pkg://system.upgrade",
            r#"input={"manager":"apt","security_only":true,"dry_run":true}"#,
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("security_only is not supported"));
}

/// Failures exit non-zero with a reason on stderr; successes print JSON.
#[test]
fn exit_codes_and_json_output() {
    let tmp = TempDir::new().unwrap();
    std::fs::write(tmp.path().join("f.txt"), "x").unwrap();
    let out = resh(tmp.path())
        .args(["file://f.txt.stat"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["exists"], true);

    let out = resh(tmp.path())
        .args(["file://missing.txt.stat"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("Error:"));

    resh(tmp.path())
        .args(["nosuch://x.read"])
        .assert()
        .failure();
    resh(tmp.path())
        .args(["file://f.txt.frobnicate"])
        .assert()
        .failure();
}

/// `resh` with no stage used to panic (exit 101).
#[test]
fn missing_stage_is_a_clean_error() {
    let tmp = TempDir::new().unwrap();
    let out = resh(tmp.path()).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.starts_with("Error: no stage provided"), "{err}");
    assert!(!err.contains("panicked"), "{err}");
}

/// H14: SMTP profiles store the password base64-encoded (not encrypted), so
/// the file must be owner-only rather than created with the umask.
#[test]
fn smtp_profile_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new().unwrap();
    resh(tmp.path())
        .args([
            "mail://config",
            "action=set",
            "profile=work",
            "smtp_host=smtp.example.com",
            "smtp_port=587",
            "smtp_username=u",
            "smtp_password=secret-value",
        ])
        .assert()
        .success();
    let file = tmp.path().join("config/resh/mail/smtp_profiles.json");
    let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{file:?} has mode {mode:o}");
    // A second save replaces the file and keeps the mode.
    resh(tmp.path())
        .args([
            "mail://config",
            "action=set",
            "profile=home",
            "smtp_host=h.example.com",
        ])
        .assert()
        .success();
    let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

/// A verb without a dry-run mode used to ignore `dry_run=true` and make the
/// real change; misspelled dry-run words were dropped the same way.
#[test]
fn dry_run_never_runs_a_verb_without_a_dry_run_mode() {
    let tmp = TempDir::new().unwrap();
    std::fs::write(tmp.path().join("g.txt"), "keep").unwrap();
    for w in ["dry_run", "dry_run=true", "dry_run=1"] {
        let out = resh(tmp.path())
            .args(["file://g.txt.delete", w])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{w}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("does not support dry_run"));
        assert!(tmp.path().join("g.txt").exists(), "{w}: file deleted");
    }
    std::fs::write(tmp.path().join("f.txt"), "hello").unwrap();
    for w in [
        "dry-run",
        "dryrun",
        "dry-run=true",
        "DRY_RUN=true",
        "dryRun=yes",
    ] {
        let out = resh(tmp.path())
            .args([
                "file://f.txt.replace",
                "pattern=hello",
                "replacement=bye",
                w,
            ])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{w}");
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("f.txt")).unwrap(),
            "hello",
            "{w}"
        );
    }
    // A verb with a dry-run mode still previews without changing anything.
    resh(tmp.path())
        .args([
            "file://f.txt.replace",
            "pattern=hello",
            "replacement=bye",
            "dry_run",
        ])
        .assert()
        .success();
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("f.txt")).unwrap(),
        "hello"
    );
}

/// pkg reads dry_run only inside its input= JSON; a top-level dry_run used to
/// be ignored and the real install ran.
#[test]
fn pkg_top_level_dry_run_is_refused() {
    let tmp = TempDir::new().unwrap();
    let out = resh(tmp.path())
        .args([
            "pkg://system.install",
            r#"input={"manager":"apk","packages":[{"name":"jq"}]}"#,
            "dry_run=true",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("inside input="));
}

/// A help-looking argument (`help=1`, `h=1`) must not bypass the dry-run
/// refusal: most handles do not treat it as a help request and would run.
#[test]
fn help_argument_does_not_bypass_dry_run_refusal() {
    let tmp = TempDir::new().unwrap();
    std::fs::write(tmp.path().join("g.txt"), "keep").unwrap();
    for h in ["help=1", "h=1", "help=true"] {
        let out = resh(tmp.path())
            .args(["file://g.txt.delete", "dry_run=true", h])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{h}");
        assert!(tmp.path().join("g.txt").exists(), "{h}: file deleted");
    }
}
