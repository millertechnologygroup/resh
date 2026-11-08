//! Unit and dispatch tests for `backup://`. Verbs run through
//! `Handle::call` with backend programs taken from a per-test directory:
//! recording fakes for restic and borg (and for failure cases), and links to
//! the host's real tar, gzip and rsync for local repositories. Everything
//! happens inside temporary directories.

use super::*;
use chrono::TimeZone;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

fn args(kv: &[(&str, &str)]) -> Args {
    kv.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn handle(url: &str) -> BackupHandle {
    BackupHandle::from_url(Url::parse(url).unwrap()).unwrap()
}

/// The outcome of one call.
struct R {
    status: Status,
    out: String,
    err: String,
}

impl R {
    /// The envelope: the last line (progress events come before it).
    fn json(&self) -> Value {
        let last = self.out.trim().lines().last().unwrap_or("");
        let text = if self.out.trim().starts_with("{\n") {
            self.out.trim()
        } else {
            last
        };
        serde_json::from_str(text).unwrap_or_else(|e| panic!("{e}: {}", self.out))
    }

    #[track_caller]
    fn ok(&self) -> Value {
        assert!(self.status.ok, "{} {}", self.out, self.err);
        let v = self.json();
        assert_eq!(v["ok"], true, "{v}");
        v
    }

    /// Asserts a failure with `code`, its exit status, the stderr line and
    /// the envelope's error object.
    #[track_caller]
    fn fails(&self, code: Code) -> Value {
        assert!(!self.status.ok, "{}", self.out);
        assert_eq!(
            self.status.exit_code(),
            code.exit(),
            "{} {}",
            self.out,
            self.err
        );
        let v = self.json();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["code"], code.code(), "{v}");
        assert_eq!(v["error"]["kind"], code.kind(), "{v}");
        if code != Code::Timeout {
            assert!(
                self.err
                    .lines()
                    .any(|l| l.starts_with(&format!("Error: [{}] ", code.code()))),
                "{}",
                self.err
            );
        }
        v
    }
}

fn run(h: &BackupHandle, verb: &str, a: &Args) -> R {
    let mut stdin = std::io::empty();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = {
        let mut io = IoStreams::new(&mut stdin, &mut out, &mut err);
        h.call(verb, a, &mut io).unwrap()
    };
    R {
        status,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    }
}

/// Writes an executable through a child process (see tests/common: a
/// write descriptor held by this process could make exec fail with ETXTBSY).
fn write_executable(path: &Path, contents: &str) {
    let mut child = std::process::Command::new("/bin/sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(path)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write as _;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(contents.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
}

/// A temporary directory with a `bin/` the handle takes its programs from.
struct Fx {
    tmp: TempDir,
    h: BackupHandle,
}

impl Fx {
    fn new() -> Self {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("bin")).unwrap();
        let mut h = handle("backup://db");
        h.bin_dir = Some(tmp.path().join("bin"));
        // Never the host's cron or systemd.
        h.cron_provider = Some(std::sync::Arc::new(MockCron::default()));
        Fx { tmp, h }
    }

    fn path(&self) -> &Path {
        self.tmp.path()
    }

    fn p(&self, rel: &str) -> String {
        self.path().join(rel).to_string_lossy().into_owned()
    }

    /// A fake `name` that records its argv and environment, then runs `body`.
    fn fake(&self, name: &str, body: &str) {
        let log = self.path().join("calls.log");
        let env = self.path().join(format!("{name}.env"));
        let script = format!(
            "#!/bin/sh\n{{ printf '%s\\037' {name}; for a in \"$@\"; do printf '%s\\037' \"$a\"; done; \
             printf '\\n'; }} >> '{}'\n/usr/bin/env > '{}'\n{body}\n",
            log.display(),
            env.display()
        );
        write_executable(&self.path().join("bin").join(name), &script);
    }

    /// Links the host's real `name` into bin/.
    fn real(&self, name: &str) {
        let target = which::which(name).unwrap_or_else(|_| panic!("{name} is required"));
        std::os::unix::fs::symlink(target, self.path().join("bin").join(name)).unwrap();
    }

    fn calls(&self) -> Vec<Vec<String>> {
        fs::read_to_string(self.path().join("calls.log"))
            .unwrap_or_default()
            .lines()
            .map(|l| {
                l.split('\u{1f}')
                    .filter(|a| !a.is_empty())
                    .map(String::from)
                    .collect()
            })
            .collect()
    }

    fn env_of(&self, name: &str) -> String {
        fs::read_to_string(self.path().join(format!("{name}.env"))).unwrap_or_default()
    }

    fn run(&self, verb: &str, kv: &[(&str, &str)]) -> R {
        run(&self.h, verb, &args(kv))
    }
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

const RESTIC_SUMMARY: &str = r#"echo '{"message_type":"summary","data_added":10,"total_bytes_processed":20,"snapshot_id":"4f2a9c1e0011"}'"#;

// ===========================================================================
// Command construction
// ===========================================================================

#[test]
fn create_commands_argv() {
    let src = s(&["/etc", "/home"]);
    let ex = s(&["*.tmp"]);
    assert_eq!(
        build_tar_create("/r/backup_1.tar.gz", &src, &ex).argv(),
        s(&[
            "tar",
            "--force-local",
            "-czf",
            "/r/backup_1.tar.gz",
            "--exclude=*.tmp",
            "--",
            "/etc",
            "/home"
        ])
    );
    let repo = "/srv/restic".to_string();
    let c = build_restic_create(Some(&repo), &src, &s(&["daily"]), Some("web01"), &ex);
    assert_eq!(
        c.argv(),
        s(&[
            "restic",
            "backup",
            "--tag=daily",
            "--host=web01",
            "--exclude=*.tmp",
            "--json",
            "--",
            "/etc",
            "/home"
        ])
    );
    assert_eq!(c.env.get("RESTIC_REPOSITORY"), Some(&repo));
    assert_eq!(
        build_borg_create("/srv/borg", "backup_1", &src, &ex).argv(),
        s(&[
            "borg",
            "create",
            "--json",
            "--compression",
            "lz4",
            "--exclude=*.tmp",
            "--",
            "/srv/borg::backup_1",
            "/etc",
            "/home"
        ])
    );
    assert_eq!(
        build_rsync_create("/r/backup_1/", &src, &ex).argv(),
        s(&[
            "rsync",
            "-a",
            "--stats",
            "--exclude=*.tmp",
            "--",
            "/etc",
            "/home",
            "/r/backup_1/"
        ])
    );
}

#[test]
fn list_restore_verify_prune_argv() {
    let repo = "/srv/restic".to_string();
    assert_eq!(
        build_restic_list(Some(&repo), &s(&["a"])).argv(),
        s(&["restic", "snapshots", "--json", "--tag=a"])
    );
    assert_eq!(
        build_borg_list("/b").argv(),
        s(&["borg", "list", "--json", "--", "/b"])
    );

    assert_eq!(
        build_restic_restore(None, "4f2a", "/tmp/r", &s(&["*.conf"]), &s(&["*.tmp"])).argv(),
        s(&[
            "restic",
            "restore",
            "--json",
            "--target=/tmp/r",
            "--include=*.conf",
            "--exclude=*.tmp",
            "--",
            "4f2a"
        ])
    );
    let b = build_borg_restore("/b", "backup_1", "/tmp/r", &[], &[]);
    assert_eq!(
        b.argv(),
        s(&["borg", "extract", "--list", "--", "/b::backup_1"])
    );
    assert_eq!(b.cwd.as_deref(), Some("/tmp/r"));
    let b = build_borg_restore("/b", "a", "/r", &s(&["etc/hosts"]), &s(&["*.tmp"]));
    assert_eq!(
        b.argv(),
        s(&[
            "borg",
            "extract",
            "--list",
            "--exclude=*.tmp",
            "--",
            "/b::a",
            "etc/hosts"
        ])
    );
    assert_eq!(
        build_tar_restore("/r/backup_1.tar.gz", "/tmp/r", &[], &[]).argv(),
        s(&[
            "tar",
            "--force-local",
            "-v",
            "-xzf",
            "/r/backup_1.tar.gz",
            "-C",
            "/tmp/r"
        ])
    );
    assert_eq!(
        build_tar_restore("/r/a.tar.gz", "/d", &s(&["etc/*.conf"]), &s(&["*.tmp"])).argv(),
        s(&[
            "tar",
            "--force-local",
            "-v",
            "-xzf",
            "/r/a.tar.gz",
            "--exclude=*.tmp",
            "-C",
            "/d",
            "--wildcards",
            "--no-wildcards-match-slash",
            "--",
            "etc/*.conf"
        ])
    );
    assert_eq!(
        build_rsync_restore("/r/backup_1/", "/tmp/r", &[], &[]).argv(),
        s(&["rsync", "-a", "--stats", "--", "/r/backup_1/", "/tmp/r"])
    );
    assert_eq!(
        build_rsync_restore("/r/b/", "d", &s(&["*.conf"]), &s(&["x"])).argv(),
        s(&[
            "rsync",
            "-a",
            "--stats",
            "--exclude=x",
            "--include=*/",
            "--include=*.conf",
            "--exclude=*",
            "--prune-empty-dirs",
            "--",
            "/r/b/",
            "./d"
        ])
    );

    assert_eq!(
        build_restic_verify(None, false).argv(),
        s(&["restic", "check"])
    );
    assert_eq!(
        build_restic_verify(None, true).argv(),
        s(&["restic", "check", "--read-data"])
    );
    assert_eq!(
        build_borg_verify("/b", None, true).argv(),
        s(&["borg", "check", "--verify-data", "--", "/b"])
    );
    assert_eq!(
        build_borg_verify("/b", Some("a1"), false).argv(),
        s(&["borg", "check", "--", "/b::a1"])
    );
    assert_eq!(
        build_tar_verify("/r/a.tar.gz").argv(),
        s(&["tar", "--force-local", "-tzf", "/r/a.tar.gz"])
    );

    let p = RetentionPolicy {
        keep_daily: Some(7),
        keep_monthly: Some(12),
        ..Default::default()
    };
    assert_eq!(
        build_restic_prune(None, &p, true).argv(),
        s(&[
            "restic",
            "forget",
            "--json",
            "--keep-daily",
            "7",
            "--keep-monthly",
            "12",
            "--dry-run"
        ])
    );
    assert_eq!(
        build_restic_prune(None, &p, false).argv(),
        s(&[
            "restic",
            "forget",
            "--json",
            "--keep-daily",
            "7",
            "--keep-monthly",
            "12",
            "--prune"
        ])
    );
    assert_eq!(
        build_borg_prune("/b", &p, true).argv(),
        s(&[
            "borg",
            "prune",
            "--list",
            "--keep-daily",
            "7",
            "--keep-monthly",
            "12",
            "--dry-run",
            "--",
            "/b"
        ])
    );
    assert_eq!(
        build_borg_prune("/b", &p, false).argv(),
        s(&[
            "borg",
            "prune",
            "--list",
            "--keep-daily",
            "7",
            "--keep-monthly",
            "12",
            "--stats",
            "--",
            "/b"
        ])
    );
}

#[test]
fn snapshot_name_sanitizes_label() {
    assert_eq!(
        snapshot_name(None, "20261016_091244"),
        "backup_20261016_091244"
    );
    assert_eq!(snapshot_name(Some("daily run"), "T"), "daily_run_T");
    assert_eq!(snapshot_name(Some("../etc"), "T"), ".._etc_T");
}

#[test]
fn local_repo_path_strips_file_scheme() {
    assert_eq!(
        local_repo_path(Some(&"file:///srv/b".to_string())),
        "/srv/b"
    );
    assert_eq!(local_repo_path(Some(&"/srv/b".to_string())), "/srv/b");
}

#[test]
fn shell_quote_keeps_words_intact() {
    assert_eq!(shell_quote("src=/etc"), "src=/etc");
    assert_eq!(shell_quote("src=/a b"), "'src=/a b'");
    assert_eq!(shell_quote("it's"), r"'it'\''s'");
    assert_eq!(shell_quote(""), "''");
}

// ===========================================================================
// Repository password
// ===========================================================================

fn no_env(_: &str) -> bool {
    false
}

fn no_file(_: &str) -> std::io::Result<String> {
    Err(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"))
}

fn some_file(_: &str) -> std::io::Result<String> {
    Ok("pw\n".to_string())
}

#[test]
fn restic_password_sources() {
    let r = resolve_repo_secret(
        &BackendType::Restic,
        &args(&[("password", "s3cr3t")]),
        no_env,
        no_file,
    )
    .unwrap();
    assert_eq!(
        r.set.get("RESTIC_PASSWORD").map(String::as_str),
        Some("s3cr3t")
    );
    assert!(r.remove.contains(&"RESTIC_PASSWORD_FILE".to_string()));

    let r = resolve_repo_secret(
        &BackendType::Restic,
        &args(&[("password_file", "/k")]),
        no_env,
        some_file,
    )
    .unwrap();
    assert_eq!(
        r.set.get("RESTIC_PASSWORD_FILE").map(String::as_str),
        Some("/k")
    );
    assert!(r.remove.contains(&"RESTIC_PASSWORD".to_string()));
    let e = resolve_repo_secret(
        &BackendType::Restic,
        &args(&[("password_file", "/k")]),
        no_env,
        no_file,
    )
    .unwrap_err();
    assert!(
        matches!(e, SecretError::Unreadable(ref m) if m.contains("/k")),
        "{e:?}"
    );

    let r = resolve_repo_secret(
        &BackendType::Restic,
        &args(&[]),
        |k| k == "RESTIC_PASSWORD_FILE",
        no_file,
    )
    .unwrap();
    assert!(r.set.is_empty());

    let e = resolve_repo_secret(&BackendType::Restic, &args(&[]), no_env, no_file).unwrap_err();
    assert!(
        matches!(e, SecretError::Missing(ref m) if m.contains("password=") && m.contains("RESTIC_PASSWORD")),
        "{e:?}"
    );
}

#[test]
fn borg_password_sources() {
    let r = resolve_repo_secret(
        &BackendType::Borg,
        &args(&[("password", "pw")]),
        no_env,
        no_file,
    )
    .unwrap();
    assert_eq!(r.set.get("BORG_PASSPHRASE").map(String::as_str), Some("pw"));

    let r = resolve_repo_secret(
        &BackendType::Borg,
        &args(&[("password_file", "/k")]),
        no_env,
        some_file,
    )
    .unwrap();
    assert_eq!(r.set.get("BORG_PASSPHRASE").map(String::as_str), Some("pw"));
    assert!(r.remove.contains(&"BORG_PASSCOMMAND".to_string()));

    let e = resolve_repo_secret(
        &BackendType::Borg,
        &args(&[("password_file", "/k")]),
        no_env,
        no_file,
    )
    .unwrap_err();
    assert!(
        matches!(e, SecretError::Unreadable(ref m) if m.contains("cannot read password_file /k")),
        "{e:?}"
    );

    let r = resolve_repo_secret(
        &BackendType::Borg,
        &args(&[]),
        |k| k == "BORG_PASSCOMMAND",
        no_file,
    )
    .unwrap();
    assert!(r.set.is_empty());

    assert!(matches!(
        resolve_repo_secret(&BackendType::Borg, &args(&[]), no_env, no_file),
        Err(SecretError::Missing(_))
    ));
    assert_eq!(
        resolve_repo_secret(&BackendType::Tar, &args(&[]), no_env, no_file).unwrap(),
        RepoSecret::default()
    );
}

#[test]
fn no_hard_coded_password_in_commands() {
    let repo = "/r".to_string();
    let p = RetentionPolicy {
        keep_daily: Some(1),
        ..Default::default()
    };
    for spec in [
        build_restic_create(Some(&repo), &s(&["/etc"]), &[], None, &[]),
        build_restic_list(Some(&repo), &[]),
        build_restic_restore(Some(&repo), "x", "/d", &[], &[]),
        build_restic_verify(Some(&repo), false),
        build_restic_prune(Some(&repo), &p, true),
        build_borg_create("/r", "a", &s(&["/etc"]), &[]),
        build_borg_list("/r"),
        build_borg_verify("/r", None, false),
        build_borg_prune("/r", &p, true),
    ] {
        assert!(!spec.env.keys().any(|k| k.contains("PASS")), "{:?}", spec);
    }
}

#[test]
fn backend_info_redacts_secrets() {
    let h = handle("backup://db");
    let mut spec = build_restic_list(Some(&"/r".to_string()), &[]);
    spec.env.insert("RESTIC_PASSWORD".into(), "hunter2".into());
    spec.env.insert("BORG_PASSPHRASE".into(), "hunter2".into());
    spec.env
        .insert("BORG_PASSCOMMAND".into(), "pass show hunter2".into());
    let info = h.backend_info(&BackendType::Restic, Some(&spec), 1, false);
    let text = serde_json::to_string(&info).unwrap();
    assert!(!text.contains("hunter2"), "{text}");
    assert_eq!(
        info.env_redacted
            .get("RESTIC_REPOSITORY")
            .map(String::as_str),
        Some("/r")
    );
    assert_eq!(
        info.env_redacted
            .get("BORG_PASSCOMMAND")
            .map(String::as_str),
        Some(REDACTED)
    );
}

/// The password reaches restic and borg only through their environment:
/// never in argv, never in the envelope, and password= warns on stderr.
#[test]
fn passwords_reach_the_backend_through_its_environment_only() {
    let f = Fx::new();
    f.fake("restic", RESTIC_SUMMARY);
    f.fake("borg", "echo '{}'");
    let repo = f.p("repo");
    let r = f.run(
        "create",
        &[
            ("src", "/etc"),
            ("backend", "restic"),
            ("repo_url", &repo),
            ("password", "hunter2"),
        ],
    );
    let v = r.ok();
    assert!(!r.out.contains("hunter2"), "{}", r.out);
    assert_eq!(v["backend"]["env_redacted"]["RESTIC_PASSWORD"], REDACTED);
    assert!(r.err.contains("Warning: password= puts"), "{}", r.err);
    assert!(f.env_of("restic").contains("RESTIC_PASSWORD=hunter2"));
    assert!(!f.calls().concat().iter().any(|a| a.contains("hunter2")));

    let pw = f.p("pw");
    fs::write(&pw, "s3cret\n").unwrap();
    let r = f.run(
        "list",
        &[
            ("backend", "borg"),
            ("repo_url", &repo),
            ("password_file", &pw),
        ],
    );
    // borg's `list` output here is not borg JSON with archives: an empty list.
    let v = r.ok();
    assert_eq!(v["result"]["total_count"], 0);
    assert!(r.err.is_empty(), "{}", r.err);
    assert!(f.env_of("borg").contains("BORG_PASSPHRASE=s3cret\n"));
    assert!(!r.out.contains("s3cret"));
}

#[test]
fn password_rules() {
    let f = Fx::new();
    f.fake("restic", "exit 0");
    f.real("tar");
    let repo = f.p("repo");
    // tar and rsync repositories are not encrypted: a password is refused.
    for key in ["password", "password_file"] {
        let r = f.run(
            "list",
            &[("backend", "tar"), ("repo_url", &repo), (key, "x")],
        );
        assert_eq!(
            r.fails(Code::InvalidArgument)["error"]["details"]["field"],
            key
        );
    }
    let r = f.run(
        "list",
        &[
            ("backend", "restic"),
            ("repo_url", &repo),
            ("password", "a"),
            ("password_file", "/b"),
        ],
    );
    r.fails(Code::InvalidArgument);
    let r = f.run(
        "list",
        &[
            ("backend", "restic"),
            ("repo_url", &repo),
            ("password_file", &f.p("missing")),
        ],
    );
    r.fails(Code::PasswordFileUnreadable);
    assert!(f.calls().is_empty());
}

#[test]
fn missing_password_fails_before_running() {
    if RESTIC_SECRET_ENV
        .iter()
        .chain(BORG_SECRET_ENV)
        .any(|k| std::env::var_os(k).is_some())
    {
        return; // the test environment supplies a password
    }
    let f = Fx::new();
    f.fake("restic", "exit 0");
    f.fake("borg", "exit 0");
    for backend in ["restic", "borg"] {
        let repo = f.p("repo");
        let r = f.run(
            "create",
            &[("src", "/etc"), ("backend", backend), ("repo_url", &repo)],
        );
        let v = r.fails(Code::MissingPassword);
        assert_eq!(v["backend"]["command"][0], backend);
    }
    assert!(f.calls().is_empty());
}

// ===========================================================================
// Output parsing
// ===========================================================================

#[test]
fn parses_restic_summary() {
    let out = concat!(
        r#"{"message_type":"status","percent_done":0.5}"#,
        "\n",
        r#"{"message_type":"summary","files_new":3,"data_added":1200,"total_bytes_processed":5000,"snapshot_id":"4f2a9c1e0011"}"#,
        "\n"
    );
    let snap =
        parse_create_output(&BackendType::Restic, out, None, &s(&["/etc"]), &[], None).unwrap();
    assert_eq!(snap.id, "4f2a9c1e0011");
    assert_eq!(snap.bytes_sent, Some(1200));
    assert_eq!(snap.bytes_total, Some(5000));
    assert!(parse_create_output(&BackendType::Restic, "garbage", None, &[], &[], None).is_none());
    assert_eq!(
        parse_restic_restored(
            "restoring <Snapshot> to x\nSummary: Restored 12 files/dirs (3 B) in 0:00\n"
        ),
        Some(12)
    );
    assert_eq!(parse_restic_restored("nothing"), None);
}

#[test]
fn parses_borg_json() {
    let out = r#"{"archive":{"name":"backup_1","start":"2026-10-16T02:00:04.000000","stats":{"original_size":9000,"deduplicated_size":100}},"repository":{}}"#;
    let snap =
        parse_create_output(&BackendType::Borg, out, Some("backup_1"), &[], &[], None).unwrap();
    assert_eq!(snap.id, "backup_1");
    assert_eq!(snap.created_at, "2026-10-16T02:00:04.000000");
    assert_eq!((snap.bytes_total, snap.bytes_sent), (Some(9000), Some(100)));
    let snap =
        parse_create_output(&BackendType::Borg, "", Some("backup_1"), &[], &[], None).unwrap();
    assert_eq!(snap.id, "backup_1");
}

#[test]
fn parses_rsync_stats() {
    let out = "\nNumber of files: 3 (reg: 2, dir: 1)\nTotal file size: 1,234,567 bytes\nTotal transferred file size: 2,048 bytes\n";
    assert_eq!(parse_rsync_stats(out), (Some(1_234_567), Some(2048)));
    let snap =
        parse_create_output(&BackendType::Rsync, out, Some("backup_1"), &[], &[], None).unwrap();
    assert_eq!(
        (snap.id.as_str(), snap.bytes_total),
        ("backup_1", Some(1_234_567))
    );
    assert_eq!(parse_rsync_stats("nothing"), (None, None));
}

#[test]
fn warning_exit_codes_count_as_success() {
    assert!(create_exit_warning(&BackendType::Restic, 3).is_some());
    assert!(create_exit_warning(&BackendType::Borg, 1).is_some());
    assert!(create_exit_warning(&BackendType::Rsync, 24).is_some());
    assert!(create_exit_warning(&BackendType::Tar, 1).is_some());
    assert!(create_exit_warning(&BackendType::Restic, 1).is_none());
    assert!(create_exit_warning(&BackendType::Borg, 2).is_none());
}

#[test]
fn restic_list_keeps_snapshots_without_tags_or_paths() {
    let out = r#"[{"short_id":"aa","time":"t1","hostname":"h","tags":["x"],"paths":["/etc"]},{"short_id":"bb","time":"t2"}]"#;
    let snaps = parse_list_output(&BackendType::Restic, out).unwrap();
    assert_eq!(snaps.len(), 2);
    assert!(snaps[1].tags.is_empty() && snaps[1].sources.is_empty());
    assert!(
        parse_list_output(&BackendType::Restic, "null")
            .unwrap()
            .is_empty()
    );
    assert!(parse_list_output(&BackendType::Restic, "not json").is_err());
    assert!(parse_list_output(&BackendType::Tar, "").is_err());
}

#[test]
fn counts_pruned_snapshots() {
    let restic = r#"[{"keep":[{}],"remove":[{},{}]},{"keep":[{}],"remove":null}]"#;
    assert_eq!(parse_prune_count(&BackendType::Restic, restic, ""), Some(2));
    assert_eq!(parse_prune_count(&BackendType::Restic, "text", ""), None);
    let borg = "Keeping archive: a\nWould prune:     b\nWould prune:     c\n";
    assert_eq!(parse_prune_count(&BackendType::Borg, "", borg), Some(2));
}

#[test]
fn select_prune_applies_policy() {
    let t = |d: u32, h: u32| Utc.with_ymd_and_hms(2026, 10, d, h, 0, 0).unwrap();
    let snaps = vec![
        ("d16b".to_string(), t(16, 12)),
        ("d16a".to_string(), t(16, 2)),
        ("d15".to_string(), t(15, 2)),
        ("d14".to_string(), t(14, 2)),
        ("d01".to_string(), t(1, 2)),
    ];
    let daily2 = RetentionPolicy {
        keep_daily: Some(2),
        ..Default::default()
    };
    let mut removed = select_prune(&snaps, &daily2);
    removed.sort();
    assert_eq!(removed, s(&["d01", "d14", "d16a"]));

    let monthly1 = RetentionPolicy {
        keep_monthly: Some(1),
        keep_daily: Some(1),
        ..Default::default()
    };
    let mut removed = select_prune(&snaps, &monthly1);
    removed.sort();
    assert_eq!(removed, s(&["d01", "d14", "d15", "d16a"]));
}

/// In-process walks stop at the deadline.
#[test]
fn in_process_walks_stop_at_the_deadline() {
    let tmp = TempDir::new().unwrap();
    fs::create_dir(tmp.path().join("snap")).unwrap();
    fs::write(tmp.path().join("snap/a"), "x").unwrap();
    let past = Instant::now();
    let later = Instant::now() + Duration::from_secs(60);
    assert_eq!(dir_size(tmp.path(), past), Err(DeadlinePassed));
    assert_eq!(dir_size(tmp.path(), later), Ok(1));
    assert!(check_files_readable(tmp.path(), true, past).is_err());
    assert_eq!(
        check_files_readable(tmp.path(), true, later).unwrap(),
        (1, vec![])
    );
    assert!(matches!(
        scan_local_snapshots(&BackendType::Rsync, tmp.path(), true, past),
        Err(ScanError::Deadline)
    ));
}

// ===========================================================================
// Strict arguments, help and error codes
// ===========================================================================

/// The `key=` options a usage text lists.
fn usage_options(usage: &str) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for word in usage.split(|c: char| !(c.is_ascii_lowercase() || c == '_' || c == '=')) {
        if let Some((k, _)) = word.split_once('=') {
            if !k.is_empty() {
                v.push(k.to_string());
            }
        }
    }
    v.sort();
    v.dedup();
    v
}

#[test]
fn help_usage_lists_exactly_the_accepted_arguments() {
    let h = handle("backup://db");
    for verb in h.verbs() {
        let meta = BACKUP_HELP.verbs.iter().find(|v| v.name == *verb).unwrap();
        let usage = meta.detail.as_ref().unwrap().usage;
        let mut want: Vec<String> = accepted_args(verb)
            .unwrap()
            .iter()
            .map(|s| s.to_string())
            .collect();
        want.sort();
        assert_eq!(usage_options(usage), want, "{verb}");
    }
    assert!(accepted_args("bogus").is_none());
}

#[test]
fn every_error_code_is_valid_and_documented() {
    let doc = include_str!("../../../docs/Automation_Utilities/backup.md");
    for c in Code::ALL {
        assert!(status::is_valid_error_code(c.code()), "{}", c.code());
        assert!(
            doc.contains(&format!("`{}`", c.code())),
            "{} undocumented",
            c.code()
        );
        assert!(doc.contains(c.kind()), "{} undocumented", c.kind());
    }
}

#[test]
fn unknown_arguments_are_refused_with_a_suggestion() {
    let f = Fx::new();
    f.fake("restic", "exit 0");
    let repo = f.p("repo");
    for verb in ["create", "list", "restore", "verify", "prune", "schedule"] {
        let r = f.run(
            verb,
            &[
                ("backend", "restic"),
                ("repo_url", &repo),
                ("tmeout_ms", "5"),
            ],
        );
        let v = r.fails(Code::InvalidArgument);
        assert_eq!(v["error"]["details"]["field"], "tmeout_ms", "{verb}");
        let msg = v["error"]["message"].as_str().unwrap();
        assert!(msg.contains("did you mean timeout_ms?"), "{verb}: {msg}");
    }
    // Verb-specific options are refused elsewhere.
    let r = f.run("list", &[("backend", "restic"), ("src", "/etc")]);
    r.fails(Code::InvalidArgument);
    assert!(f.calls().is_empty());
}

#[test]
fn dry_run_is_refused_where_a_verb_has_none() {
    let f = Fx::new();
    f.fake("restic", "exit 0");
    let repo = f.p("repo");
    for verb in ["list", "verify"] {
        for v in ["true", "false", "maybe"] {
            let r = f.run(
                verb,
                &[("backend", "restic"), ("repo_url", &repo), ("dry_run", v)],
            );
            let e = r.fails(Code::InvalidArgument);
            assert!(
                e["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("does not support dry_run"),
                "{e}"
            );
        }
    }
    assert!(f.calls().is_empty());
}

#[test]
fn malformed_values_are_refused() {
    let f = Fx::new();
    f.fake("restic", "exit 0");
    f.real("tar");
    let repo = f.p("repo");
    let base = [("backend", "restic"), ("repo_url", repo.as_str())];
    let cases: &[(&str, &[(&str, &str)], &str)] = &[
        ("list", &[("timeout_ms", "soon")], "timeout_ms"),
        ("list", &[("timeout_ms", "0")], "timeout_ms"),
        ("list", &[("timeout_ms", "-5")], "timeout_ms"),
        ("list", &[("json_pretty", "maybe")], "json_pretty"),
        (
            "create",
            &[("src", "/etc"), ("dry_run", "maybe")],
            "dry_run",
        ),
        ("prune", &[("keep_daily", "x")], "keep_daily"),
        ("prune", &[("keep_daily", "0")], "keep_daily"),
        ("prune", &[("keep_weekly", "-1")], "keep_weekly"),
        ("prune", &[], "keep_daily"),
        ("verify", &[("mode", "fast")], "mode"),
        ("verify", &[("snapshot_id", "abc")], "snapshot_id"),
        (
            "schedule",
            &[("src", "/etc"), ("when", "every day")],
            "when",
        ),
        (
            "schedule",
            &[("src", "/etc"), ("when", "@daily"), ("enabled", "perhaps")],
            "enabled",
        ),
        ("create", &[("src", "/etc"), ("backend", "tarr")], "backend"),
        ("create", &[], "src"),
        ("restore", &[("dest", "d")], "snapshot_id"),
        ("restore", &[("snapshot_id", "x")], "dest"),
        ("schedule", &[("src", "/etc")], "when"),
        ("schedule", &[("when", "@daily")], "src"),
        (
            "schedule",
            &[("src", "/etc"), ("when", "@daily"), ("timeout_ms", "0")],
            "timeout_ms",
        ),
        (
            "schedule",
            &[
                ("src", "/etc"),
                ("when", "@daily"),
                ("scheduler", "anacron"),
            ],
            "scheduler",
        ),
        (
            "restore",
            &[("snapshot_id", "x"), ("dest", "d"), ("dry_run", "maybe")],
            "dry_run",
        ),
        (
            "create",
            &[("src", "/etc"), ("progress", "lots")],
            "progress",
        ),
    ];
    for (verb, extra, field) in cases {
        let mut kv: Vec<(&str, &str)> = base.to_vec();
        for (k, v) in extra.iter() {
            kv.retain(|(bk, _)| bk != k);
            kv.push((k, v));
        }
        let r = f.run(verb, &kv);
        let v = r.fails(Code::InvalidArgument);
        assert_eq!(
            v["error"]["details"]["field"], *field,
            "{verb} {extra:?}: {v}"
        );
    }
    let r = f.run("create", &[("src", "/etc"), ("backend", "tarr")]);
    assert!(
        r.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("did you mean tar?")
    );
    // tag is restic only.
    let r = f.run(
        "create",
        &[
            ("src", "/etc"),
            ("backend", "tar"),
            ("repo_url", &repo),
            ("tag", "daily"),
        ],
    );
    assert_eq!(
        r.fails(Code::InvalidArgument)["error"]["details"]["field"],
        "tag"
    );
    assert!(f.calls().is_empty());
    assert!(!Path::new(&repo).exists());
}

#[test]
fn restic_needs_a_repository() {
    if RESTIC_REPO_ENV
        .iter()
        .any(|k| std::env::var_os(k).is_some())
    {
        return;
    }
    let f = Fx::new();
    f.fake("restic", "exit 0");
    let r = f.run("list", &[("backend", "restic"), ("password", "x")]);
    assert_eq!(
        r.fails(Code::InvalidArgument)["error"]["details"]["field"],
        "repo_url"
    );
    assert!(f.calls().is_empty());
}

#[test]
fn unknown_verb_is_a_usage_error() {
    let r = run(&handle("backup://db"), "lst", &Args::new());
    let v = r.fails(Code::UnknownVerb);
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("did you mean list?")
    );
}

#[test]
fn backend_selection() {
    let f = Fx::new();
    // Nothing installed: auto finds no backend.
    let r = f.run("list", &[("repo_url", &f.p("repo"))]);
    r.fails(Code::BackendNotFound);
    // A named backend that is not installed.
    let r = f.run(
        "list",
        &[
            ("backend", "borg"),
            ("repo_url", &f.p("r")),
            ("password", "x"),
        ],
    );
    r.fails(Code::BackendNotFound);
    // auto takes the first installed of restic, borg, rsync, tar.
    f.fake("borg", r#"echo '{"archives":[]}'"#);
    f.real("tar");
    let r = f.run("list", &[("repo_url", &f.p("r")), ("password", "x")]);
    assert_eq!(r.ok()["backend"]["id"], "borg");
}

#[test]
fn json_pretty_prints_an_indented_envelope() {
    let f = Fx::new();
    fs::create_dir(f.path().join("repo")).unwrap();
    let r = f.run(
        "list",
        &[
            ("backend", "tar"),
            ("repo_url", &f.p("repo")),
            ("json_pretty", "true"),
        ],
    );
    assert!(r.out.starts_with("{\n  \"ok\": true"), "{}", r.out);
    r.ok();
}

#[test]
fn help_detection_is_exact() {
    let none = Args::new();
    assert!(BackupHandle::should_show_help("help", &none));
    assert!(BackupHandle::should_show_help("--help", &none));
    assert!(BackupHandle::should_show_help("-h", &none));
    assert!(BackupHandle::should_show_help("--help=create", &none));
    assert!(!BackupHandle::should_show_help("create", &none));
    assert!(!BackupHandle::should_show_help("my-host", &none));
    assert!(!BackupHandle::should_show_help("pre-hotfix", &none));
}

#[test]
fn help_uses_approved_metadata() {
    let h = handle("backup://db");
    let r = run(&h, "help", &Args::new());
    assert!(r.out.starts_with("Handle: backup"), "{}", r.out);
    let r = run(&h, "help", &args(&[("verb", "prune")]));
    assert!(
        r.out.starts_with("Handle: backup\nVerb: prune"),
        "{}",
        r.out
    );
    let r = run(&h, "--help=create", &Args::new());
    assert!(r.out.contains("Verb: create"), "{}", r.out);
    let r = run(&h, "list", &args(&[("help", "")]));
    assert!(r.out.starts_with("Handle: backup\nVerb: list"), "{}", r.out);
}

// ===========================================================================
// create / list / restore / verify / prune with real tar
// ===========================================================================

/// A source tree: data/a.conf, data/b.txt, data/sub/c.conf.
fn source(f: &Fx) -> String {
    let d = f.path().join("data");
    fs::create_dir_all(d.join("sub")).unwrap();
    fs::write(d.join("a.conf"), "alpha").unwrap();
    fs::write(d.join("b.txt"), "bravo!").unwrap();
    fs::write(d.join("sub/c.conf"), "charlie").unwrap();
    d.to_string_lossy().into_owned()
}

#[test]
fn tar_round_trip() {
    let f = Fx::new();
    f.real("tar");
    f.real("gzip");
    let src = source(&f);
    let repo = f.p("repo");

    // Dry run: a plan, nothing written.
    let r = f.run(
        "create",
        &[
            ("src", &src),
            ("backend", "tar"),
            ("repo_url", &repo),
            ("dry_run", "true"),
        ],
    );
    let v = r.ok();
    assert_eq!(v["result"]["dry_run_mode"], "plan");
    assert_eq!(v["backend"]["simulated"], true);
    assert!(!Path::new(&repo).exists());

    let kv = [
        ("src", src.as_str()),
        ("backend", "tar"),
        ("repo_url", repo.as_str()),
        ("label", "web 01"),
        ("exclude", "*.txt"),
    ];
    let first = f.run("create", &kv).ok();
    let second = f.run("create", &kv).ok();
    let id1 = first["result"]["snapshot"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let id2 = second["result"]["snapshot"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(id1.starts_with("web_01_"), "{id1}");
    // Two backups in the same second never share a name.
    assert_ne!(id1, id2);
    assert_eq!(mode(Path::new(&repo)), 0o700);
    let archive = Path::new(&repo).join(format!("{id1}.tar.gz"));
    assert_eq!(mode(&archive), 0o600);
    assert!(first["result"]["snapshot"]["bytes_total"].as_u64().unwrap() > 0);

    let v = f
        .run("list", &[("backend", "tar"), ("repo_url", &repo)])
        .ok();
    assert_eq!(v["result"]["total_count"], 2);
    assert_eq!(v["backend"]["command"], json!([]));

    for m in ["quick", "thorough", "data"] {
        let v = f
            .run(
                "verify",
                &[("backend", "tar"), ("repo_url", &repo), ("mode", m)],
            )
            .ok();
        assert_eq!(
            v["result"]["verification"]["archives"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
    let v = f
        .run(
            "verify",
            &[
                ("backend", "tar"),
                ("repo_url", &repo),
                ("snapshot_id", &id1),
            ],
        )
        .ok();
    assert_eq!(
        v["result"]["verification"]["archives"][0]["id"],
        id1.as_str()
    );
    let r = f.run(
        "verify",
        &[
            ("backend", "tar"),
            ("repo_url", &repo),
            ("snapshot_id", "nope"),
        ],
    );
    r.fails(Code::SnapshotNotFound);

    // Restore everything (b.txt was excluded at backup time).
    let out = f.p("out");
    let v = f
        .run(
            "restore",
            &[
                ("backend", "tar"),
                ("repo_url", &repo),
                ("snapshot_id", &id1),
                ("dest", &out),
            ],
        )
        .ok();
    assert_eq!(mode(Path::new(&out)), 0o700);
    let restored = Path::new(&out).join(src.trim_start_matches('/'));
    assert_eq!(
        fs::read_to_string(restored.join("a.conf")).unwrap(),
        "alpha"
    );
    assert_eq!(
        fs::read_to_string(restored.join("sub/c.conf")).unwrap(),
        "charlie"
    );
    assert!(!restored.join("b.txt").exists());
    assert_eq!(v["result"]["restored"]["files_restored"], 2);
    assert_eq!(v["result"]["restored"]["bytes_restored"], 12);

    // include: only matching members; exclude: not those.
    let out2 = f.p("out2");
    let member = format!("{}/*.conf", src.trim_start_matches('/'));
    let v = f
        .run(
            "restore",
            &[
                ("backend", "tar"),
                ("repo_url", &repo),
                ("snapshot_id", &id1),
                ("dest", &out2),
                ("include", &member),
            ],
        )
        .ok();
    let restored = Path::new(&out2).join(src.trim_start_matches('/'));
    assert!(restored.join("a.conf").exists());
    assert!(!restored.join("sub/c.conf").exists(), "* does not cross /");
    assert_eq!(v["result"]["restored"]["files_restored"], 1);
    let out3 = f.p("out3");
    f.run(
        "restore",
        &[
            ("backend", "tar"),
            ("repo_url", &repo),
            ("snapshot_id", &id1),
            ("dest", &out3),
            ("exclude", "c.conf"),
        ],
    )
    .ok();
    let restored = Path::new(&out3).join(src.trim_start_matches('/'));
    assert!(restored.join("a.conf").exists() && !restored.join("sub/c.conf").exists());

    // A missing archive is the backend's failure, exit 1 with its status.
    let r = f.run(
        "restore",
        &[
            ("backend", "tar"),
            ("repo_url", &repo),
            ("snapshot_id", "nope"),
            ("dest", &out),
        ],
    );
    let v = r.fails(Code::BackendFailed);
    assert_eq!(v["error"]["details"]["exit_code"], 2);
    assert_eq!(v["error"]["details"]["partial_restore_possible"], true);

    // Prune: a dry run removes nothing, a real run keeps the newest of today.
    let v = f
        .run(
            "prune",
            &[
                ("backend", "tar"),
                ("repo_url", &repo),
                ("keep_daily", "1"),
                ("dry_run", "true"),
            ],
        )
        .ok();
    assert_eq!(v["result"]["would_prune"]["snapshots_removed"], 1);
    assert_eq!(v["result"]["dry_run_mode"], "plan");
    assert_eq!(fs::read_dir(&repo).unwrap().count(), 2);
    let v = f
        .run(
            "prune",
            &[("backend", "tar"), ("repo_url", &repo), ("keep_daily", "1")],
        )
        .ok();
    assert_eq!(v["result"]["pruned"]["snapshots_removed"], 1);
    assert_eq!(fs::read_dir(&repo).unwrap().count(), 1);
}

#[test]
fn tar_failures() {
    let f = Fx::new();
    f.real("tar");
    f.real("gzip");
    let repo = f.p("repo");
    // An empty repository has nothing to verify.
    fs::create_dir(&repo).unwrap();
    let v = f
        .run("verify", &[("backend", "tar"), ("repo_url", &repo)])
        .fails(Code::VerifyFailed);
    assert!(
        v["error"]["details"]["issues"][0]
            .as_str()
            .unwrap()
            .contains("no .tar.gz")
    );
    // A corrupt archive fails verification.
    fs::write(Path::new(&repo).join("bad.tar.gz"), "not a gzip stream").unwrap();
    let v = f
        .run("verify", &[("backend", "tar"), ("repo_url", &repo)])
        .fails(Code::VerifyFailed);
    assert_eq!(v["error"]["details"]["archives"][0]["ok"], false);
    // A missing repository directory cannot be listed.
    f.run("list", &[("backend", "tar"), ("repo_url", &f.p("nope"))])
        .fails(Code::Io);
    f.run(
        "prune",
        &[
            ("backend", "tar"),
            ("repo_url", &f.p("nope")),
            ("keep_daily", "1"),
        ],
    )
    .fails(Code::Io);
    // A failed backup leaves no partial archive behind.
    let r = f.run(
        "create",
        &[
            ("src", &f.p("does-not-exist")),
            ("backend", "tar"),
            ("repo_url", &repo),
        ],
    );
    let v = r.fails(Code::BackendFailed);
    assert_eq!(v["error"]["details"]["exit_code"], 2);
    assert_eq!(v["error"]["details"]["partial_snapshot_removed"], true);
    let names: Vec<String> = fs::read_dir(&repo)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["bad.tar.gz"]);
}

#[test]
fn restore_refuses_symlink_and_file_destinations() {
    let f = Fx::new();
    f.real("tar");
    let repo = f.p("repo");
    let elsewhere = f.p("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, f.path().join("link")).unwrap();
    fs::write(f.path().join("file"), "x").unwrap();
    for dest in ["link", "file"] {
        let r = f.run(
            "restore",
            &[
                ("backend", "tar"),
                ("repo_url", &repo),
                ("snapshot_id", "s"),
                ("dest", &f.p(dest)),
            ],
        );
        assert_eq!(
            r.fails(Code::InvalidArgument)["error"]["details"]["field"],
            "dest"
        );
    }
    assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
}

// ===========================================================================
// rsync with the host's rsync
// ===========================================================================

#[test]
fn rsync_round_trip() {
    if which::which("rsync").is_err() {
        eprintln!("rsync not installed; skipped");
        return;
    }
    let f = Fx::new();
    f.real("rsync");
    let src = source(&f);
    let repo = f.p("repo");
    let kv = [
        ("src", src.as_str()),
        ("backend", "rsync"),
        ("repo_url", repo.as_str()),
    ];
    let first = f.run("create", &kv).ok();
    let second = f.run("create", &kv).ok();
    let id1 = first["result"]["snapshot"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(id1, second["result"]["snapshot"]["id"].as_str().unwrap());
    assert_eq!(mode(&Path::new(&repo).join(&id1)), 0o700);
    assert_eq!(first["result"]["snapshot"]["bytes_total"], 18);

    let v = f
        .run("list", &[("backend", "rsync"), ("repo_url", &repo)])
        .ok();
    assert_eq!(v["result"]["total_count"], 2);
    for m in ["quick", "thorough"] {
        let v = f
            .run(
                "verify",
                &[("backend", "rsync"), ("repo_url", &repo), ("mode", m)],
            )
            .ok();
        assert_eq!(v["result"]["verification"]["files_checked"], 6);
    }
    let v = f
        .run(
            "verify",
            &[
                ("backend", "rsync"),
                ("repo_url", &repo),
                ("snapshot_id", &id1),
            ],
        )
        .ok();
    assert_eq!(v["result"]["verification"]["files_checked"], 3);
    f.run(
        "verify",
        &[
            ("backend", "rsync"),
            ("repo_url", &repo),
            ("snapshot_id", "nope"),
        ],
    )
    .fails(Code::SnapshotNotFound);

    let out = f.p("out");
    let v = f
        .run(
            "restore",
            &[
                ("backend", "rsync"),
                ("repo_url", &repo),
                ("snapshot_id", &id1),
                ("dest", &out),
                ("include", "*.conf"),
            ],
        )
        .ok();
    assert!(Path::new(&out).join("data/a.conf").exists());
    assert!(Path::new(&out).join("data/sub/c.conf").exists());
    assert!(!Path::new(&out).join("data/b.txt").exists());
    assert_eq!(v["result"]["restored"]["files_restored"], 2);
    assert_eq!(v["result"]["restored"]["bytes_restored"], 12);

    let v = f
        .run(
            "prune",
            &[
                ("backend", "rsync"),
                ("repo_url", &repo),
                ("keep_weekly", "1"),
            ],
        )
        .ok();
    assert_eq!(v["result"]["pruned"]["snapshots_removed"], 1);
    assert_eq!(v["result"]["pruned"]["bytes_freed"], 18);
    assert_eq!(fs::read_dir(&repo).unwrap().count(), 1);
}

// ===========================================================================
// restic and borg through recording fakes
// ===========================================================================

#[test]
fn restic_verbs_run_the_documented_commands() {
    let f = Fx::new();
    f.fake(
        "restic",
        &format!(
            r#"case "$1" in
  backup) {RESTIC_SUMMARY} ;;
  snapshots) echo '[{{"short_id":"4f2a9c1e","time":"t","hostname":"web01","tags":["daily"],"paths":["/etc"]}}]' ;;
  restore) echo 'Summary: Restored 7 files/dirs (1.2 KiB) in 0:00' ;;
  forget) echo '[{{"keep":[{{}}],"remove":[{{}},{{}}]}}]' ;;
esac"#
        ),
    );
    let repo = "/srv/restic";
    let base = [
        ("backend", "restic"),
        ("repo_url", repo),
        ("password", "pw"),
    ];
    let with = |extra: &[(&'static str, &'static str)]| -> Vec<(&str, &str)> {
        base.iter().chain(extra.iter()).copied().collect()
    };
    let v = f
        .run("create", &with(&[("src", "/etc"), ("tag", "daily")]))
        .ok();
    assert_eq!(v["result"]["snapshot"]["id"], "4f2a9c1e0011");
    let v = f.run("list", &with(&[("tag", "daily")])).ok();
    assert_eq!(v["result"]["snapshots"][0]["label"], "web01");
    let v = f
        .run("restore", &with(&[("snapshot_id", "4f2a"), ("dest", "")]))
        .json();
    assert_eq!(v["error"]["details"]["field"], "dest");
    let out = f.p("out");
    let mut kv = with(&[("snapshot_id", "4f2a"), ("include", "*.conf,/etc/hosts")]);
    kv.push(("dest", &out));
    let v = f.run("restore", &kv).ok();
    assert_eq!(v["result"]["restored"]["files_restored"], 7);
    assert_eq!(v["result"]["restored"]["bytes_restored"], Value::Null);
    let v = f.run("verify", &with(&[("mode", "thorough")])).ok();
    assert_eq!(v["result"]["verification"]["files_checked"], Value::Null);
    let v = f.run("prune", &with(&[("keep_daily", "7")])).ok();
    assert_eq!(v["result"]["pruned"]["snapshots_removed"], 2);

    let calls = f.calls();
    assert_eq!(
        calls,
        vec![
            s(&["restic", "backup", "--tag=daily", "--json", "--", "/etc"]),
            s(&["restic", "snapshots", "--json", "--tag=daily"]),
            vec![
                "restic".to_string(),
                "restore".to_string(),
                "--json".to_string(),
                format!("--target={out}"),
                "--include=*.conf".to_string(),
                "--include=/etc/hosts".to_string(),
                "--".to_string(),
                "4f2a".to_string()
            ],
            s(&["restic", "check", "--read-data"]),
            s(&["restic", "forget", "--json", "--keep-daily", "7", "--prune"]),
        ]
    );
    assert!(f.env_of("restic").contains("RESTIC_REPOSITORY=/srv/restic"));
}

#[test]
fn borg_verbs_run_the_documented_commands() {
    let f = Fx::new();
    f.fake(
        "borg",
        r#"case "$1" in
  create) echo '{"archive":{"name":"x","start":"2026-10-16T02:00:04","stats":{"original_size":9,"deduplicated_size":1}}}' ;;
  list) echo '{"archives":[{"name":"a1","start":"2026-10-16T02:00:04"}]}' ;;
  extract) mkdir -p etc && printf 'hello' > etc/hosts && echo etc >&2 && echo etc/hosts >&2 ;;
  prune) echo 'Would prune:     a0' >&2 ;;
esac"#,
    );
    let base = [
        ("backend", "borg"),
        ("repo_url", "/srv/borg"),
        ("password", "pw"),
    ];
    let with = |extra: &[(&'static str, &'static str)]| -> Vec<(&str, &str)> {
        base.iter().chain(extra.iter()).copied().collect()
    };
    let v = f
        .run("create", &with(&[("src", "/etc"), ("label", "db")]))
        .ok();
    assert_eq!(v["result"]["snapshot"]["bytes_total"], 9);
    let v = f.run("list", &[]).json();
    assert_eq!(v["ok"], false); // no repo_url
    let v = f.run("list", &with(&[])).ok();
    assert_eq!(v["result"]["snapshots"][0]["id"], "a1");
    let out = f.p("out");
    let mut kv = with(&[("snapshot_id", "a1"), ("include", "etc/hosts")]);
    kv.push(("dest", &out));
    let v = f.run("restore", &kv).ok();
    assert_eq!(v["result"]["restored"]["files_restored"], 1);
    assert_eq!(v["result"]["restored"]["bytes_restored"], 5);
    assert_eq!(v["backend"]["cwd"], out.as_str());
    f.run("verify", &with(&[("snapshot_id", "a1")])).ok();
    let v = f
        .run("prune", &with(&[("keep_daily", "7"), ("dry_run", "true")]))
        .ok();
    assert_eq!(v["result"]["would_prune"]["snapshots_removed"], 1);
    assert_eq!(v["result"]["dry_run_mode"], "backend");

    let calls = f.calls();
    assert!(calls[0][..5] == s(&["borg", "create", "--json", "--compression", "lz4"]));
    assert!(calls[0][6].starts_with("/srv/borg::db_"), "{:?}", calls[0]);
    assert_eq!(calls[1], s(&["borg", "list", "--json", "--", "/srv/borg"]));
    assert_eq!(
        calls[2],
        s(&[
            "borg",
            "extract",
            "--list",
            "--",
            "/srv/borg::a1",
            "etc/hosts"
        ])
    );
    assert_eq!(calls[3], s(&["borg", "check", "--", "/srv/borg::a1"]));
    assert_eq!(
        calls[4],
        s(&[
            "borg",
            "prune",
            "--list",
            "--keep-daily",
            "7",
            "--dry-run",
            "--",
            "/srv/borg"
        ])
    );
}

#[test]
fn backend_failures_exit_1_with_the_backend_status() {
    let f = Fx::new();
    f.fake("restic", "echo 'Fatal: wrong password' >&2; exit 12");
    let r = f.run(
        "list",
        &[("backend", "restic"), ("repo_url", "/r"), ("password", "x")],
    );
    let v = r.fails(Code::BackendFailed);
    assert_eq!(v["error"]["details"]["exit_code"], 12);
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("wrong password")
    );
    assert!(
        v["error"]["details"]["stderr_tail"]
            .as_str()
            .unwrap()
            .contains("Fatal")
    );

    // restic exit 3 on create: snapshot written without some files.
    let f = Fx::new();
    f.fake("restic", &format!("{RESTIC_SUMMARY}; exit 3"));
    let v = f
        .run(
            "create",
            &[
                ("src", "/etc"),
                ("backend", "restic"),
                ("repo_url", "/r"),
                ("password", "x"),
            ],
        )
        .ok();
    assert!(
        v["warnings"][0]
            .as_str()
            .unwrap()
            .contains("could not read")
    );

    // Unparseable list output.
    let f = Fx::new();
    f.fake("restic", "echo garbage");
    f.run(
        "list",
        &[("backend", "restic"), ("repo_url", "/r"), ("password", "x")],
    )
    .fails(Code::Parse);

    // A program that cannot be executed.
    let f = Fx::new();
    fs::write(f.path().join("bin/restic"), "not executable").unwrap();
    f.run(
        "list",
        &[("backend", "restic"), ("repo_url", "/r"), ("password", "x")],
    )
    .fails(Code::ExecutionFailed);
}

/// The deadline stops the backend and everything it started.
#[test]
fn timeouts_stop_the_backend_tree() {
    let f = Fx::new();
    let pid_file = f.p("grandchild.pid");
    f.fake(
        "restic",
        &format!("/bin/sleep 30 & echo $! > '{pid_file}'; wait"),
    );
    let start = Instant::now();
    let r = f.run(
        "list",
        &[
            ("backend", "restic"),
            ("repo_url", "/r"),
            ("password", "x"),
            ("timeout_ms", "300"),
        ],
    );
    assert!(start.elapsed() < Duration::from_secs(10));
    let v = r.fails(Code::Timeout);
    assert_eq!(r.status.exit_code(), 124);
    assert_eq!(v["error"]["details"]["timeout_ms"], 300);
    let pid: i32 = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(gone_soon(pid), "grandchild still running");
    let _ = process::take_lost();
}

#[test]
fn a_create_stopped_at_the_deadline_leaves_no_partial_snapshot() {
    let f = Fx::new();
    f.fake("tar", "/bin/sleep 30");
    let repo = f.p("repo");
    let r = f.run(
        "create",
        &[
            ("src", "/etc"),
            ("backend", "tar"),
            ("repo_url", &repo),
            ("timeout_ms", "300"),
        ],
    );
    let v = r.fails(Code::Timeout);
    assert_eq!(v["error"]["details"]["partial_snapshot_removed"], true);
    assert_eq!(fs::read_dir(&repo).unwrap().count(), 0);
    let _ = process::take_lost();
}

// ===========================================================================
// schedule
// ===========================================================================

/// A cron provider that records `add` and `disable` and changes nothing.
/// The cron handle in front of it still checks every argument itself.
#[derive(Debug, Default)]
struct MockCron {
    adds: std::sync::Mutex<Vec<crate::handles::processes::cronh::CronAddOptions>>,
    disables: std::sync::Mutex<Vec<Option<String>>>,
    /// Jobs `rm` reports as matching (another job of the profile).
    existing: std::sync::atomic::AtomicU32,
    /// `add` reports the job as already installed.
    duplicate: std::sync::atomic::AtomicBool,
}

impl crate::handles::processes::cronh::CronProvider for MockCron {
    fn list_cron_entries(
        &self,
        _: &crate::handles::processes::cronh::CronListOptions,
    ) -> anyhow::Result<crate::handles::processes::cronh::CronListResponse> {
        anyhow::bail!("not used")
    }
    fn add_cron_job(
        &self,
        o: &crate::handles::processes::cronh::CronAddOptions,
    ) -> anyhow::Result<crate::handles::processes::cronh::CronAddResponse> {
        use crate::handles::processes::cronh::*;
        self.adds.lock().unwrap().push(o.clone());
        let backend = if o.backend == "auto" {
            "cron".to_string()
        } else {
            o.backend.clone()
        };
        Ok(CronAddResponse {
            ok: true,
            timestamp_unix_ms: 0,
            backend_used: Some(backend.clone()),
            dry_run: o.dry_run,
            duplicate: self.duplicate.load(std::sync::atomic::Ordering::SeqCst),
            job: Some(CronAddJobInfo {
                id: o.id.clone(),
                backend,
                schedule: o.schedule.clone(),
                command: o.command.clone(),
                location: CronAddJobLocation {
                    scope: "current".to_string(),
                    file: None,
                    user: Some("tester".to_string()),
                    line_added: None,
                    unit_name: None,
                    timer_unit: None,
                    service_unit: None,
                    unit_dir: None,
                },
                next_run_unix: None,
                next_run_iso8601: None,
                next_run_timezone: None,
            }),
            preview: None,
            error: None,
            warnings: vec!["from cron".to_string()],
        })
    }
    fn remove_cron_jobs(
        &self,
        o: &crate::handles::processes::cronh::CronRmOptions,
    ) -> anyhow::Result<crate::handles::processes::cronh::CronRmResponse> {
        use crate::handles::processes::cronh::*;
        assert!(o.dry_run, "schedule only probes with rm");
        Ok(CronRmResponse {
            ok: true,
            timestamp_unix_ms: 0,
            dry_run: true,
            backend: o.backend.clone(),
            cron_modified_sources: vec![],
            systemd_scopes_touched: vec![],
            removed: CronRmRemovedSummary {
                cron: vec![],
                systemd: vec![],
            },
            matched_count: CronRmMatchedCount {
                cron: self.existing.load(std::sync::atomic::Ordering::SeqCst),
                systemd: 0,
            },
            error: None,
            warnings: vec![],
        })
    }
    fn enable_cron_jobs(
        &self,
        _: &crate::handles::processes::cronh::CronEnableOptions,
    ) -> anyhow::Result<crate::handles::processes::cronh::CronEnableResponse> {
        anyhow::bail!("not used")
    }
    fn disable_cron_jobs(
        &self,
        o: &crate::handles::processes::cronh::CronDisableOptions,
    ) -> anyhow::Result<crate::handles::processes::cronh::CronDisableResponse> {
        self.disables.lock().unwrap().push(o.id.clone());
        anyhow::bail!("mock: disabling is not possible here")
    }
}

/// A fixture whose `schedule` installs through `cron`.
fn with_cron(f: &mut Fx) -> std::sync::Arc<MockCron> {
    let cron = std::sync::Arc::new(MockCron::default());
    f.h.cron_provider = Some(cron.clone());
    cron
}

#[test]
fn schedule_installs_through_the_cron_handle() {
    let mut f = Fx::new();
    f.real("tar");
    let cron = with_cron(&mut f);
    let r = f.run(
        "schedule",
        &[
            ("when", "0 2 * * *"),
            ("src", "/etc;/srv/a b"),
            ("backend", "tar"),
            ("repo_url", "/srv/b"),
            ("scheduler", "cron"),
            ("timeout_ms", "5000"),
        ],
    );
    let v = r.ok();
    let sch = &v["result"]["schedule"];
    assert_eq!(sch["scheduler"], "cron");
    assert_eq!(sch["installed"], true);
    assert_eq!(sch["id"], "resh-backup-db");
    assert_eq!(
        sch["command"].as_array().unwrap()[1..],
        json!([
            "backup://db.create",
            "src=/etc;/srv/a b",
            "backend=tar",
            "repo_url=/srv/b"
        ])
        .as_array()
        .unwrap()[..]
    );
    assert_eq!(
        sch["remove_command"],
        json!([
            "resh",
            "cron://backup-db.rm",
            "id=resh-backup-db",
            "backend=cron"
        ])
    );
    assert_eq!(sch["job"]["id"], "resh-backup-db");
    assert!(v["warnings"].to_string().contains("from cron"));
    let adds = cron.adds.lock().unwrap();
    assert_eq!(adds.len(), 2, "cron's dry run, then the add");
    assert!(adds[0].dry_run);
    assert!(!adds[0].allow_duplicate);
    let add = &adds[1];
    assert_eq!(add.schedule, "0 2 * * *");
    assert_eq!(add.backend, "cron");
    assert_eq!(add.id.as_deref(), Some("resh-backup-db"));
    assert!(!add.dry_run);
    assert!(
        add.command
            .ends_with(" backup://db.create 'src=/etc;/srv/a b' backend=tar repo_url=/srv/b"),
        "{}",
        add.command
    );
    assert!(f.calls().is_empty(), "no backend ran");
}

#[test]
fn schedule_dry_run_and_disabled_jobs() {
    let mut f = Fx::new();
    f.real("tar");
    let cron = with_cron(&mut f);
    let base = [
        ("when", "@daily"),
        ("src", "/etc"),
        ("backend", "tar"),
        ("repo_url", "/srv/b"),
    ];
    let mut kv = base.to_vec();
    kv.push(("dry_run", "true"));
    let v = f.run("schedule", &kv).ok();
    assert_eq!(v["dry_run"], true);
    assert_eq!(v["result"]["schedule"]["installed"], false);
    assert_eq!(cron.adds.lock().unwrap().len(), 1, "only cron's dry run");
    assert!(cron.adds.lock().unwrap()[0].dry_run, "cron add got dry_run");

    // enabled=false installs and then disables through cron; a failing
    // disable is reported with the job left installed.
    let mut kv = base.to_vec();
    kv.push(("enabled", "false"));
    let v = f.run("schedule", &kv).fails(Code::ScheduleFailed);
    assert_eq!(v["error"]["details"]["installed"], true);
    assert_eq!(
        v["error"]["details"]["cron_error"]["code"],
        "cron.disable_error"
    );
    assert_eq!(
        cron.disables.lock().unwrap().as_slice(),
        [Some("resh-backup-db".to_string())]
    );

    // Already installed: nothing is added again.
    cron.adds.lock().unwrap().clear();
    cron.duplicate
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let v = f.run("schedule", &base).ok();
    assert_eq!(v["result"]["schedule"]["duplicate"], true);
    assert_eq!(cron.adds.lock().unwrap().len(), 1, "only cron's dry run");

    // Another job of the profile is installed: refused, nothing added.
    cron.adds.lock().unwrap().clear();
    cron.duplicate
        .store(false, std::sync::atomic::Ordering::SeqCst);
    cron.existing.store(1, std::sync::atomic::Ordering::SeqCst);
    let v = f.run("schedule", &base).fails(Code::ScheduleFailed);
    assert_eq!(
        v["error"]["details"]["remove_command"][1],
        "cron://backup-db.rm"
    );
    assert_eq!(cron.adds.lock().unwrap().len(), 1, "only cron's dry run");
}

#[test]
fn schedule_refusals() {
    let mut f = Fx::new();
    f.fake("restic", "exit 0");
    let cron = with_cron(&mut f);
    for kv in [
        vec![
            ("when", "@daily"),
            ("src", "-x"),
            ("backend", "tar"),
            ("repo_url", "/r"),
        ],
        vec![("when", "@daily"), ("src", "/etc"), ("backend", "tar")],
        vec![
            ("when", "@daily"),
            ("src", "/etc"),
            ("backend", "tar"),
            ("repo_url", "/r"),
            ("password_file", "/p"),
        ],
    ] {
        f.run("schedule", &kv).fails(Code::InvalidArgument);
    }
    // Schedules are checked by cron add itself: refused before the provider.
    let v = f
        .run(
            "schedule",
            &[
                ("when", "61 * * * *"),
                ("src", "/etc"),
                ("backend", "restic"),
                ("repo_url", "/r"),
            ],
        )
        .fails(Code::InvalidArgument);
    assert_eq!(v["error"]["details"]["field"], "when");
    assert_eq!(
        v["error"]["details"]["cron_error"]["code"],
        "cron.add_invalid_schedule"
    );
    assert!(cron.adds.lock().unwrap().is_empty());
    let mut h = handle("backup://my%20db");
    h.bin_dir = Some(f.path().join("bin"));
    h.cron_provider = Some(cron.clone());
    let r = run(
        &h,
        "schedule",
        &args(&[
            ("when", "@daily"),
            ("src", "/etc"),
            ("backend", "restic"),
            ("repo_url", "/r"),
        ]),
    );
    r.fails(Code::InvalidArgument);
    // restic without a password file warns that the job needs one.
    let v = f
        .run(
            "schedule",
            &[
                ("when", "@hourly"),
                ("src", "/etc"),
                ("backend", "restic"),
                ("repo_url", "/r"),
            ],
        )
        .ok();
    assert!(v["warnings"].to_string().contains("no password_file"));
}

// ===========================================================================
// Profiles, repository requirements, dry runs, argument safety
// ===========================================================================

#[test]
fn profile_comes_from_the_url_host() {
    let repo = |url: &str| handle(url).repo;
    assert_eq!(repo("backup://db"), "db");
    assert_eq!(repo("backup://web"), "web");
    assert_eq!(repo("backup://"), "default");
    assert_eq!(repo("backup:///legacy"), "legacy");
    assert_eq!(repo("backup://db/nightly"), "db/nightly");
    assert_eq!(repo("backup://my%20db"), "my db");
    let parsed = crate::core::parse::parse_stage("backup://db.list").unwrap();
    assert_eq!(repo(&parsed.target), "db");
}

#[test]
fn local_backends_require_repo_url() {
    for b in [BackendType::Tar, BackendType::Rsync, BackendType::Borg] {
        assert!(repo_url_required(&b, &args(&[])).is_some(), "{b}");
        assert!(
            repo_url_required(&b, &args(&[("repo_url", " ")])).is_some(),
            "{b}"
        );
        assert!(
            repo_url_required(&b, &args(&[("repo_url", "file://")])).is_some(),
            "{b}"
        );
        assert!(
            repo_url_required(&b, &args(&[("repo_url", "/srv/b")])).is_none(),
            "{b}"
        );
    }
    assert!(repo_url_required(&BackendType::Restic, &args(&[])).is_none());
}

#[test]
fn tar_without_repo_url_fails_before_running() {
    let f = Fx::new();
    f.real("tar");
    let src = source(&f);
    let dest = f.p("dest");
    for (verb, extra) in [
        ("create", vec![("src", src.as_str())]),
        ("create", vec![("src", src.as_str()), ("dry_run", "true")]),
        ("list", vec![]),
        ("verify", vec![]),
        ("prune", vec![("keep_daily", "1")]),
        (
            "restore",
            vec![("snapshot_id", "backup_1"), ("dest", dest.as_str())],
        ),
    ] {
        let mut kv = vec![("backend", "tar")];
        kv.extend(extra);
        let r = f.run(verb, &kv);
        let v = r.fails(Code::InvalidArgument);
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap()
                .contains("repo_url is required"),
            "{verb}: {v}"
        );
    }
    assert!(!Path::new(&dest).exists());
    assert!(!Path::new("/tmp/resh_backup_db").exists());
}

#[test]
fn malformed_dry_run_is_refused_and_nothing_runs() {
    let f = Fx::new();
    f.real("tar");
    f.real("gzip");
    let src = source(&f);
    let repo = f.p("repo");
    let entries = || fs::read_dir(&repo).map(|d| d.count()).unwrap_or(0);
    for bad in ["maybe", "2", "", "y", "treu"] {
        let base = [
            ("backend", "tar"),
            ("repo_url", repo.as_str()),
            ("dry_run", bad),
        ];
        let mut create = base.to_vec();
        create.push(("src", &src));
        f.run("create", &create).fails(Code::InvalidArgument);
        let mut prune = base.to_vec();
        prune.push(("keep_daily", "1"));
        f.run("prune", &prune).fails(Code::InvalidArgument);
        assert_eq!(entries(), 0, "dry_run={bad:?} wrote a backup");
    }
    for yes in ["true", "1", "yes", "ON"] {
        f.run(
            "create",
            &[
                ("backend", "tar"),
                ("repo_url", &repo),
                ("src", &src),
                ("dry_run", yes),
            ],
        )
        .ok();
        assert_eq!(entries(), 0, "dry_run={yes} wrote a backup");
    }
    f.run(
        "create",
        &[
            ("backend", "tar"),
            ("repo_url", &repo),
            ("src", &src),
            ("dry_run", "off"),
        ],
    )
    .ok();
    assert_eq!(entries(), 1);
}

fn field(backend: BackendType, verb: &str, kv: &[(&str, &str)]) -> Option<&'static str> {
    validate_request(&backend, verb, &args(kv))
        .err()
        .map(|e| e.field)
}

#[test]
fn option_shaped_and_control_values_are_refused() {
    use BackendType::*;
    let repo = ("repo_url", "/srv/repo");
    for b in [Tar, Rsync, Borg, Restic] {
        for src in ["-v", "--probe", "/etc;-x", "a\nb", "a\0b", ""] {
            assert_eq!(
                field(b.clone(), "create", &[repo, ("src", src)]),
                Some("src"),
                "{src:?}"
            );
        }
        assert_eq!(
            field(b.clone(), "create", &[("repo_url", "-r"), ("src", "/etc")]),
            Some("repo_url")
        );
        assert_eq!(
            field(
                b.clone(),
                "create",
                &[repo, ("src", "/etc"), ("exclude", "a\rb")]
            ),
            Some("exclude")
        );
        assert_eq!(
            field(
                b.clone(),
                "create",
                &[repo, ("src", "/etc"), ("label", "a\nb")]
            ),
            Some("label")
        );
        assert_eq!(
            field(b.clone(), "list", &[repo, ("tag", "a\nb")]),
            Some("tag")
        );
        assert_eq!(
            field(b.clone(), "list", &[repo, ("password_file", "-p")]),
            Some("password_file")
        );
        assert_eq!(
            field(
                b.clone(),
                "restore",
                &[repo, ("snapshot_id", "-x"), ("dest", "/d")]
            ),
            Some("snapshot_id")
        );
        assert_eq!(
            field(b.clone(), "verify", &[repo, ("snapshot_id", "-x")]),
            Some("snapshot_id")
        );
        assert_eq!(
            field(
                b.clone(),
                "restore",
                &[repo, ("snapshot_id", "s1"), ("dest", "-d")]
            ),
            Some("dest")
        );
        assert_eq!(
            field(
                b.clone(),
                "restore",
                &[
                    repo,
                    ("snapshot_id", "s1"),
                    ("dest", "/d"),
                    ("include", "a\nb")
                ]
            ),
            Some("include")
        );
        assert_eq!(
            field(
                b.clone(),
                "create",
                &[
                    repo,
                    ("src", "/etc;rel/dir;a:b"),
                    ("exclude", "-x;*.tmp"),
                    ("label", "web 01")
                ]
            ),
            None
        );
        assert_eq!(
            field(
                b.clone(),
                "restore",
                &[repo, ("snapshot_id", "backup_1"), ("dest", "./-d")]
            ),
            None
        );
    }
}

#[test]
fn local_snapshot_ids_stay_in_the_repository() {
    use BackendType::*;
    for b in [Tar, Rsync] {
        for id in ["../x", "a/b", "..", "."] {
            let kv = [("repo_url", "/r"), ("snapshot_id", id), ("dest", "/d")];
            assert_eq!(
                field(b.clone(), "restore", &kv),
                Some("snapshot_id"),
                "{id}"
            );
            assert_eq!(
                field(b.clone(), "verify", &kv[..2]),
                Some("snapshot_id"),
                "{id}"
            );
        }
    }
    let kv = [
        ("repo_url", "/r"),
        ("snapshot_id", "latest:/etc"),
        ("dest", "/d"),
    ];
    assert_eq!(field(Restic, "restore", &kv), None);
}

#[test]
fn remote_repository_hosts_cannot_be_options() {
    use BackendType::*;
    for repo in [
        "ssh://-oX/repo",
        "ssh://user@-oX/repo",
        "-oX:repo",
        "user@-oX:repo",
        "sftp:-oX:/repo",
        "sftp:user@-oX:/repo",
        "ssh://[-oX]/repo",
    ] {
        for b in [Borg, Restic] {
            assert_eq!(
                field(b, "list", &[("repo_url", repo)]),
                Some("repo_url"),
                "{repo}"
            );
        }
    }
    for repo in [
        "/srv/borg",
        "/srv/a-b/-c",
        "ssh://backup@host.example:2222/./repo",
        "backup@host.example:repo",
        "sftp:backup@host.example:/srv/restic",
        "s3:https://s3.example/bucket",
    ] {
        for b in [Borg, Restic] {
            assert_eq!(field(b, "list", &[("repo_url", repo)]), None, "{repo}");
        }
    }
    assert_eq!(field(Tar, "list", &[("repo_url", "/srv/a:-b")]), None);
}

#[test]
fn rsync_local_paths_never_look_remote() {
    assert_eq!(rsync_local("/abs/a:b"), "/abs/a:b");
    assert_eq!(rsync_local("host:path"), "./host:path");
    assert_eq!(rsync_local("rsync://host/x"), "./rsync://host/x");
    assert_eq!(rsync_local("./x"), "./x");
    let c = build_rsync_create("repo/backup_1/", &["data".to_string()], &[]);
    assert_eq!(
        c.argv(),
        ["rsync", "-a", "--stats", "--", "./data", "./repo/backup_1/"]
    );
}

#[test]
fn suggestions_are_for_likely_typos_only() {
    let allowed = ["timeout_ms", "repo_url", "snapshot_id"];
    assert_eq!(suggest("timeout", &allowed), Some("timeout_ms"));
    assert_eq!(suggest("repourl", &allowed), Some("repo_url"));
    assert_eq!(suggest("zzzz", &allowed), None);
}

// ===========================================================================
// restore dry run
// ===========================================================================

#[test]
fn restore_dry_run_lists_what_would_be_restored_and_writes_nothing() {
    let f = Fx::new();
    f.real("tar");
    f.real("gzip");
    let src = source(&f);
    let repo = f.p("repo");
    let id = f
        .run(
            "create",
            &[("src", &src), ("backend", "tar"), ("repo_url", &repo)],
        )
        .ok()["result"]["snapshot"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // A missing destination is reported as would-be-created, not created.
    let out = f.p("out");
    let v = f
        .run(
            "restore",
            &[
                ("backend", "tar"),
                ("repo_url", &repo),
                ("snapshot_id", &id),
                ("dest", &out),
                ("dry_run", "true"),
            ],
        )
        .ok();
    assert!(!Path::new(&out).exists());
    assert_eq!(v["dry_run"], true);
    let r = &v["result"];
    assert_eq!(r["dry_run_mode"], "backend");
    assert_eq!(r["destination"]["would_create"], true);
    assert_eq!(r["destination"]["writable"], true);
    assert_eq!(r["would_restore"], json!({"files": 3, "bytes": 18}));
    assert_eq!(v["backend"]["command"][1], "--force-local");
    assert_eq!(v["backend"]["command"][2], "-tvzf");

    // include narrows the plan; a non-empty dest warns and stays untouched.
    let busy = f.path().join("busy");
    fs::create_dir(&busy).unwrap();
    fs::write(busy.join("keep.txt"), "original").unwrap();
    let member = format!("{}/*.conf", src.trim_start_matches('/'));
    let v = f
        .run(
            "restore",
            &[
                ("backend", "tar"),
                ("repo_url", &repo),
                ("snapshot_id", &id),
                ("dest", busy.to_str().unwrap()),
                ("include", &member),
                ("dry_run", "1"),
            ],
        )
        .ok();
    assert_eq!(
        v["result"]["would_restore"],
        json!({"files": 1, "bytes": 5})
    );
    assert_eq!(v["result"]["destination"]["empty"], false);
    assert!(v["warnings"].to_string().contains("not empty"));
    assert_eq!(fs::read_dir(&busy).unwrap().count(), 1);
    assert_eq!(
        fs::read_to_string(busy.join("keep.txt")).unwrap(),
        "original"
    );

    // A snapshot that does not exist.
    f.run(
        "restore",
        &[
            ("backend", "tar"),
            ("repo_url", &repo),
            ("snapshot_id", "nope"),
            ("dest", &out),
            ("dry_run", "true"),
        ],
    )
    .fails(Code::SnapshotNotFound);
    // A symlink destination is refused in a dry run too.
    std::os::unix::fs::symlink(&busy, f.path().join("link")).unwrap();
    f.run(
        "restore",
        &[
            ("backend", "tar"),
            ("repo_url", &repo),
            ("snapshot_id", &id),
            ("dest", &f.p("link")),
            ("dry_run", "true"),
        ],
    )
    .fails(Code::InvalidArgument);
}

#[test]
fn restore_dry_run_for_rsync_restic_and_borg() {
    let f = Fx::new();
    if which::which("rsync").is_ok() {
        f.real("rsync");
        let src = source(&f);
        let repo = f.p("rrepo");
        let id = f
            .run(
                "create",
                &[("src", &src), ("backend", "rsync"), ("repo_url", &repo)],
            )
            .ok()["result"]["snapshot"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let out = f.p("rout");
        let v = f
            .run(
                "restore",
                &[
                    ("backend", "rsync"),
                    ("repo_url", &repo),
                    ("snapshot_id", &id),
                    ("dest", &out),
                    ("exclude", "*.txt"),
                    ("dry_run", "true"),
                ],
            )
            .ok();
        assert_eq!(
            v["result"]["would_restore"],
            json!({"files": 2, "bytes": 12})
        );
        assert!(!Path::new(&out).exists(), "rsync --dry-run created dest");
    }

    f.fake(
        "restic",
        r#"echo '{"message_type":"summary","total_files":4,"files_restored":4,"total_bytes":18,"bytes_restored":18}'"#,
    );
    f.fake(
        "borg",
        r#"echo '{"type": "d", "path": "data", "size": 0}'
echo '{"type": "-", "path": "data/a.conf", "size": 5}'
echo '{"type": "-", "path": "data/sub/c.conf", "size": 7}'"#,
    );
    let out = f.p("out");
    let v = f
        .run(
            "restore",
            &[
                ("backend", "restic"),
                ("repo_url", "/r"),
                ("password", "x"),
                ("snapshot_id", "latest"),
                ("dest", &out),
                ("dry_run", "true"),
            ],
        )
        .ok();
    assert_eq!(
        v["result"]["would_restore"],
        json!({"files": 4, "bytes": 18})
    );
    let v = f
        .run(
            "restore",
            &[
                ("backend", "borg"),
                ("repo_url", "/b"),
                ("password", "x"),
                ("snapshot_id", "a1"),
                ("dest", &out),
                ("include", "data"),
                ("dry_run", "true"),
            ],
        )
        .ok();
    assert_eq!(
        v["result"]["would_restore"],
        json!({"files": 2, "bytes": 12})
    );
    assert!(!Path::new(&out).exists());
    let calls = f.calls();
    let n = calls.len();
    assert_eq!(
        calls[n - 2],
        vec![
            "restic".to_string(),
            "restore".to_string(),
            "--json".to_string(),
            "--dry-run".to_string(),
            format!("--target={out}"),
            "--".to_string(),
            "latest".to_string()
        ]
    );
    assert_eq!(
        calls[n - 1],
        s(&["borg", "list", "--json-lines", "--", "/b::a1", "data"])
    );
}

// ===========================================================================
// progress
// ===========================================================================

#[test]
fn progress_streams_backend_events_before_the_envelope() {
    let f = Fx::new();
    f.fake(
        "restic",
        r#"echo '{"message_type":"status","percent_done":0.5}'
echo '{"message_type":"status","percent_done":1}'
echo '{"message_type":"summary","snapshot_id":"abc","files_restored":3,"bytes_restored":18}'"#,
    );
    f.fake(
        "borg",
        r#"echo '{"type": "archive_progress", "nfiles": 1, "finished": false}' >&2
echo '{"type": "log_message", "name": "borg.output.list", "message": "x"}' >&2
echo '{"type": "progress_percent", "finished": true}' >&2
echo '{"archive": {"name": "a1", "stats": {"original_size": 9}}}'"#,
    );
    let r = f.run(
        "create",
        &[
            ("src", "/etc"),
            ("backend", "restic"),
            ("repo_url", "/r"),
            ("password", "x"),
            ("progress", "true"),
        ],
    );
    let lines: Vec<Value> = r
        .out
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 3, "{}", r.out);
    assert_eq!(lines[0]["event"], "progress");
    assert_eq!(lines[0]["verb"], "create");
    assert_eq!(lines[0]["progress"]["percent_done"], 0.5);
    assert_eq!(lines[2]["ok"], true);
    assert_eq!(lines[2]["result"]["snapshot"]["id"], "abc");

    let r = f.run(
        "create",
        &[
            ("src", "/etc"),
            ("backend", "borg"),
            ("repo_url", "/b"),
            ("password", "x"),
            ("progress", "true"),
        ],
    );
    let lines: Vec<&str> = r.out.lines().collect();
    assert_eq!(lines.len(), 3, "{}", r.out);
    assert!(lines[0].contains("archive_progress") && lines[1].contains("progress_percent"));
    let v = r.ok();
    assert_eq!(v["result"]["snapshot"]["bytes_total"], 9);
    let borg = f.calls().pop().unwrap();
    assert_eq!(
        &borg[..4],
        &s(&["borg", "create", "--progress", "--log-json"])[..]
    );

    // restore streams too, and the summary still gives the counts.
    let r = f.run(
        "restore",
        &[
            ("backend", "restic"),
            ("repo_url", "/r"),
            ("password", "x"),
            ("snapshot_id", "latest"),
            ("dest", &f.p("out")),
            ("progress", "true"),
        ],
    );
    assert_eq!(r.out.lines().count(), 3, "{}", r.out);
    let v = r.ok();
    assert_eq!(v["result"]["restored"]["files_restored"], 3);
    assert_eq!(v["result"]["restored"]["bytes_restored"], 18);

    // Without progress nothing but the envelope is printed.
    let r = f.run(
        "create",
        &[
            ("src", "/etc"),
            ("backend", "restic"),
            ("repo_url", "/r"),
            ("password", "x"),
        ],
    );
    assert_eq!(r.out.lines().count(), 1);
}

#[test]
fn progress_runs_stop_at_the_deadline() {
    let f = Fx::new();
    let pid_file = f.p("grandchild.pid");
    f.fake(
        "restic",
        &format!(
            "echo '{{\"message_type\":\"status\",\"percent_done\":0}}'; /bin/sleep 30 & echo $! > '{pid_file}'; wait"
        ),
    );
    let start = Instant::now();
    let r = f.run(
        "create",
        &[
            ("src", "/etc"),
            ("backend", "restic"),
            ("repo_url", "/r"),
            ("password", "x"),
            ("progress", "true"),
            ("timeout_ms", "500"),
        ],
    );
    assert!(start.elapsed() < Duration::from_secs(10));
    let first: Value = serde_json::from_str(r.out.lines().next().unwrap()).unwrap();
    assert_eq!(first["event"], "progress", "{}", r.out);
    r.fails(Code::Timeout);
    let pid: i32 = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(gone_soon(pid), "grandchild still running");
    let _ = process::take_lost();
}

#[test]
fn progress_is_refused_for_local_backends() {
    let f = Fx::new();
    f.real("tar");
    let r = f.run(
        "create",
        &[
            ("src", "/etc"),
            ("backend", "tar"),
            ("repo_url", &f.p("r")),
            ("progress", "true"),
        ],
    );
    assert_eq!(
        r.fails(Code::InvalidArgument)["error"]["details"]["field"],
        "progress"
    );
    assert!(!f.path().join("r").exists());
}

#[test]
fn dry_run_listing_parsers() {
    let tar = "drwxr-xr-x root/root 0 2026-11-08 12:59 data/\n\
               -rw-r--r-- root/root 7 2026-11-08 12:59 data/sub/c.conf\n\
               -rw-r--r-- root/root 5 2026-11-08 12:59 data/a file.conf\n";
    assert_eq!(parse_tar_listing(tar), (2, 12));
    assert_eq!(
        parse_borg_listing("{\"type\":\"-\",\"size\":4}\n{\"type\":\"d\",\"size\":0}\nnoise\n"),
        (1, 4)
    );
    assert_eq!(
        parse_restic_restore_summary(
            "{\"message_type\":\"summary\",\"files_restored\":5,\"bytes_restored\":18}\n"
        ),
        (Some(5), Some(18))
    );
    assert_eq!(
        borg_listed(
            "",
            "{\"type\":\"log_message\",\"name\":\"borg.output.list\",\"message\":\"a/b\"}\nplain\n"
        ),
        "a/b\nplain\n"
    );
    assert!(progress_event(&BackendType::Restic, true, "{\"message_type\":\"status\"}").is_some());
    assert!(progress_event(&BackendType::Restic, false, "{\"message_type\":\"status\"}").is_none());
    assert!(progress_event(&BackendType::Borg, false, "{\"type\":\"progress_percent\"}").is_some());
    assert!(progress_event(&BackendType::Borg, false, "{\"type\":\"log_message\"}").is_none());
}

/// True once `pid` no longer exists, polling for up to 10 s: a killed
/// process may stay a zombie until init reaps it, longer on a busy machine.
fn gone_soon(pid: i32) -> bool {
    let end = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        // SAFETY: signal 0 only checks that the process exists.
        if unsafe { libc::kill(pid, 0) } == -1 {
            return true;
        }
        if std::time::Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
