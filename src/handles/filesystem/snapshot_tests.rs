//! Verb tests for `snapshot://`, run through `Handle::call` against a
//! per-test snapshot store in a temporary directory.

use super::*;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

struct Env {
    tmp: TempDir,
    _store: test_store::Guard,
}

struct Out {
    status: Status,
    out: String,
    err: String,
}

impl Out {
    fn json(&self) -> Value {
        serde_json::from_str(self.out.trim())
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {:?}", self.out))
    }

    fn ok(&self) -> &Self {
        assert!(
            self.status.ok,
            "expected success: {:?}\nstdout: {}\nstderr: {}",
            self.status.reason, self.out, self.err
        );
        self
    }

    /// Asserts a failure with this exit code and error code, reported on
    /// both stderr and stdout.
    fn fails(&self, exit: i32, code: &str) -> &Self {
        assert!(!self.status.ok, "expected failure, got: {}", self.out);
        assert_eq!(self.status.exit_code(), exit, "stderr: {}", self.err);
        let v = self.json();
        assert_eq!(v["error"], code, "{}", self.out);
        assert_eq!(v["ok"], false);
        assert!(v["message"].as_str().is_some_and(|m| !m.is_empty()));
        assert!(self.err.starts_with("Error: "), "stderr: {}", self.err);
        self
    }
}

impl Env {
    fn new() -> Self {
        let tmp = TempDir::new().unwrap();
        let store = test_store::install(tmp.path().join("store"));
        Self { tmp, _store: store }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.tmp.path().join(rel)
    }

    fn store(&self) -> PathBuf {
        self.tmp.path().join("store")
    }

    fn call(&self, target: &str, verb: &str, pairs: &[(&str, &str)]) -> Out {
        let url = Url::parse(&format!("snapshot://{target}")).unwrap();
        let h = SnapshotHandle::from_url(&url).unwrap();
        let args: Args = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let mut i: &[u8] = &[];
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let status = {
            let mut io = IoStreams {
                stdin: &mut i,
                stdout: &mut o,
                stderr: &mut e,
            };
            h.call(verb, &args, &mut io).unwrap()
        };
        Out {
            status,
            out: String::from_utf8(o).unwrap(),
            err: String::from_utf8(e).unwrap(),
        }
    }

    /// Calls a verb on an absolute target path.
    fn on(&self, target: &Path, verb: &str, pairs: &[(&str, &str)]) -> Out {
        self.call(&target.display().to_string(), verb, pairs)
    }

    /// A directory `app` with a nested file, a top-level file and a file
    /// named like the storage files.
    fn app(&self) -> PathBuf {
        let app = self.path("app");
        fs::create_dir_all(app.join("conf")).unwrap();
        fs::write(app.join("conf/main.conf"), "v1").unwrap();
        fs::write(app.join("README"), "readme").unwrap();
        fs::write(app.join("meta.json"), "{\"mine\":true}").unwrap();
        fs::write(app.join("content"), "not storage").unwrap();
        app
    }

    fn create(&self, target: &Path, name: &str) -> Value {
        let o = self.on(target, "create", &[("name", name)]);
        o.ok();
        o.json()
    }

    /// Store entries whose name starts with '.' (temporary leftovers).
    fn leftovers(&self) -> Vec<PathBuf> {
        let mut found = Vec::new();
        for e in WalkDir::new(self.store()).into_iter().flatten() {
            if e.file_name().to_string_lossy().starts_with('.') && e.depth() == 2 {
                found.push(e.path().to_path_buf());
            }
        }
        found
    }

    fn snapshot_names(&self) -> Vec<String> {
        let mut v = Vec::new();
        for e in WalkDir::new(self.store())
            .min_depth(2)
            .max_depth(2)
            .into_iter()
            .flatten()
        {
            v.push(e.file_name().to_string_lossy().into_owned());
        }
        v.sort();
        v
    }
}

fn root() -> bool {
    is_root()
}

fn mkfifo(p: &Path) {
    let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
}

fn many_files(dir: &Path, n: usize) {
    fs::create_dir_all(dir).unwrap();
    for i in 0..n {
        fs::write(dir.join(format!("f{i}")), "x".repeat(64)).unwrap();
    }
}

fn set_mtime(p: &Path, secs: i64) {
    filetime::set_file_mtime(p, filetime::FileTime::from_unix_time(secs, 0)).unwrap();
}

fn mtime(p: &Path) -> i64 {
    filetime::FileTime::from_last_modification_time(&fs::metadata(p).unwrap()).unix_seconds()
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o7777
}

// --- URL parsing and help -------------------------------------------------

fn target(u: &str) -> PathBuf {
    SnapshotHandle::from_url(&Url::parse(u).unwrap())
        .unwrap()
        .target
}

#[test]
fn from_url_keeps_host_and_path() {
    assert_eq!(target("snapshot:///srv/app"), PathBuf::from("/srv/app"));
    assert_eq!(target("snapshot://backup-v1"), PathBuf::from("backup-v1"));
    assert_eq!(target("snapshot://dir/app"), PathBuf::from("dir/app"));
    assert_eq!(
        target("snapshot:///srv/./a/../app"),
        PathBuf::from("/srv/app")
    );
}

#[test]
fn normalize_keeps_leading_parent_dirs_of_relative_paths() {
    assert_eq!(normalize_path(Path::new("../app")), PathBuf::from("../app"));
    assert_eq!(
        normalize_path(Path::new("a/../../b")),
        PathBuf::from("../b")
    );
    assert_eq!(normalize_path(Path::new("/../x")), PathBuf::from("/x"));
    assert_eq!(normalize_path(Path::new("")), PathBuf::from("."));
}

#[test]
fn help_detection_is_exact() {
    assert_eq!(target("snapshot://--help"), PathBuf::from(HELP_PATH));
    assert_eq!(target("snapshot://-h"), PathBuf::from(HELP_PATH));
    assert_eq!(target("snapshot://pre-hotfix"), PathBuf::from("pre-hotfix"));
    assert_eq!(
        target("snapshot:///home/x/my-hosts"),
        PathBuf::from("/home/x/my-hosts")
    );
}

#[test]
fn in_url_help_renders_approved_help() {
    let env = Env::new();
    let o = env.call("--help", "help", &[]);
    o.ok();
    assert!(o.out.starts_with("Handle: snapshot\n"));
    let o = env.call("--help", "help", &[("verb", "ls")]);
    assert!(o.out.starts_with("Handle: snapshot\nVerb: ls\n"));
}

/// Every option a verb accepts appears in its help usage, and the usage
/// lists no option the verb does not accept.
#[test]
fn help_usage_lists_exactly_the_accepted_options() {
    for (verb, opts) in [
        ("ls", LS_OPTIONS),
        ("diff", DIFF_OPTIONS),
        ("create", CREATE_OPTIONS),
        ("restore", RESTORE_OPTIONS),
    ] {
        let usage = SNAPSHOT_HELP
            .verbs
            .iter()
            .find(|v| v.name == verb)
            .and_then(|v| v.detail.as_ref())
            .unwrap()
            .usage;
        let mut listed: Vec<&str> = usage
            .split(|c: char| c.is_whitespace() || c == '[')
            .filter_map(|w| w.split_once('=').map(|(k, _)| k))
            .filter(|k| !k.is_empty() && !k.contains("://"))
            .collect();
        listed.sort_unstable();
        let mut expected = opts.to_vec();
        expected.sort_unstable();
        assert_eq!(listed, expected, "{verb} usage: {usage}");
    }
}

#[test]
fn unknown_verb_is_an_error() {
    let env = Env::new();
    let url = Url::parse("snapshot:///x").unwrap();
    let h = SnapshotHandle::from_url(&url).unwrap();
    let mut i: &[u8] = &[];
    let (mut o, mut e) = (Vec::new(), Vec::new());
    let mut io = IoStreams {
        stdin: &mut i,
        stdout: &mut o,
        stderr: &mut e,
    };
    let err = h.call("frobnicate", &Args::new(), &mut io).unwrap_err();
    assert!(err.to_string().contains("unknown verb"));
    drop(env);
}

// --- create ---------------------------------------------------------------

#[test]
fn create_directory_snapshot_records_metadata_and_content() {
    let env = Env::new();
    let app = env.app();
    fs::set_permissions(
        app.join("conf/main.conf"),
        fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    fs::set_permissions(app.join("conf"), fs::Permissions::from_mode(0o750)).unwrap();
    set_mtime(&app.join("conf/main.conf"), 1_000_000_000);
    set_mtime(&app.join("conf"), 1_100_000_000);

    let o = env.on(
        &app,
        "create",
        &[
            ("name", "v1"),
            ("description", "first"),
            ("tags", "nightly, pre-deploy"),
        ],
    );
    o.ok();
    let v = o.json();
    assert_eq!(v["ok"], true);
    assert_eq!(v["name"], "v1");
    assert_eq!(v["backend"], "local");
    assert_eq!(v["skipped"], false);
    assert_eq!(v["target"], app.to_string_lossy().as_ref());
    assert!(v["expires_at"].is_null());
    let dir = PathBuf::from(v["path"].as_str().unwrap());
    assert_eq!(dir, group_dir(&env.store(), &app).join("v1"));

    let meta: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("meta.json")).unwrap()).unwrap();
    assert_eq!(meta["id"], v["id"]);
    assert_eq!(meta["kind"], "dir");
    assert_eq!(meta["state"], "complete");
    assert_eq!(meta["tags"], json!(["nightly", "pre-deploy"]));
    assert_eq!(meta["description"], "first");
    assert_eq!(meta["size_bytes"], 2 + 6 + 13 + 11);

    let c = dir.join("content");
    assert_eq!(fs::read_to_string(c.join("conf/main.conf")).unwrap(), "v1");
    // The target's own meta.json and content files are content, not storage.
    assert_eq!(
        fs::read_to_string(c.join("meta.json")).unwrap(),
        "{\"mine\":true}"
    );
    assert_eq!(
        fs::read_to_string(c.join("content")).unwrap(),
        "not storage"
    );
    assert_eq!(mode(&c.join("conf/main.conf")), 0o640);
    assert_eq!(mode(&c.join("conf")), 0o750);
    assert_eq!(mtime(&c.join("conf/main.conf")), 1_000_000_000);
    assert_eq!(mtime(&c.join("conf")), 1_100_000_000);
    assert!(env.leftovers().is_empty());

    // The store, group and snapshot directories are owner-only, and so is
    // the metadata file.
    assert_eq!(mode(&env.store()), 0o700);
    assert_eq!(mode(dir.parent().unwrap()), 0o700);
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join("meta.json")), 0o600);
}

#[test]
fn create_file_snapshot() {
    let env = Env::new();
    let f = env.path("hosts");
    fs::write(&f, "127.0.0.1 localhost\n").unwrap();
    let v = env.create(&f, "h1");
    let dir = PathBuf::from(v["path"].as_str().unwrap());
    assert_eq!(
        fs::read_to_string(dir.join("content")).unwrap(),
        "127.0.0.1 localhost\n"
    );
    let meta = read_meta(&dir).unwrap();
    assert_eq!(meta.kind.as_deref(), Some("file"));
    assert_eq!(meta.size_bytes, Some(20));
}

#[test]
fn create_ttl_sets_expires_at() {
    let env = Env::new();
    let app = env.app();
    let o = env.on(&app, "create", &[("name", "t"), ("ttl", "86400")]);
    o.ok();
    let v = o.json();
    let c = DateTime::parse_from_rfc3339(v["created_at"].as_str().unwrap()).unwrap();
    let e = DateTime::parse_from_rfc3339(v["expires_at"].as_str().unwrap()).unwrap();
    assert_eq!((e - c).num_seconds(), 86400);
}

#[test]
fn create_if_exists_modes() {
    let env = Env::new();
    let app = env.app();
    // skip on a new name creates it, and reports skipped=false.
    let o = env.on(&app, "create", &[("name", "v1"), ("if_exists", "skip")]);
    o.ok();
    let first = o.json();
    assert_eq!(first["skipped"], false);

    // error (the default) refuses and leaves the snapshot alone.
    env.on(&app, "create", &[("name", "v1")])
        .fails(1, "snapshot_exists");
    env.on(&app, "create", &[("name", "v1"), ("if_exists", "error")])
        .fails(1, "snapshot_exists");

    // skip returns the existing snapshot.
    let o = env.on(&app, "create", &[("name", "v1"), ("if_exists", "skip")]);
    o.ok();
    let v = o.json();
    assert_eq!(v["skipped"], true);
    assert_eq!(v["id"], first["id"]);

    // overwrite replaces content and id.
    fs::write(app.join("conf/main.conf"), "v2").unwrap();
    let o = env.on(
        &app,
        "create",
        &[("name", "v1"), ("if_exists", "overwrite")],
    );
    o.ok();
    let v = o.json();
    assert_ne!(v["id"], first["id"]);
    let dir = PathBuf::from(v["path"].as_str().unwrap());
    assert_eq!(
        fs::read_to_string(dir.join("content/conf/main.conf")).unwrap(),
        "v2"
    );
    assert!(env.leftovers().is_empty(), "{:?}", env.leftovers());
}

#[test]
fn create_overwrite_replaces_unreadable_snapshot_dir() {
    let env = Env::new();
    let app = env.app();
    let broken = group_dir(&env.store(), &app).join("v1");
    fs::create_dir_all(&broken).unwrap();
    env.on(&app, "create", &[("name", "v1")])
        .fails(1, "snapshot_exists");
    env.on(&app, "create", &[("name", "v1"), ("if_exists", "skip")])
        .fails(1, "snapshot_exists");
    env.on(
        &app,
        "create",
        &[("name", "v1"), ("if_exists", "overwrite")],
    )
    .ok();
    assert!(read_meta(&broken).is_ok());
}

#[test]
fn create_argument_errors_have_no_side_effects() {
    let env = Env::new();
    let app = env.app();
    let cases: &[(&[(&str, &str)], &str)] = &[
        (&[], "missing_argument"),
        (&[("name", "  ")], "missing_argument"),
        (&[("name", "-rf")], "invalid_argument"),
        (&[("name", ".hidden")], "invalid_argument"),
        (&[("name", "a/b")], "invalid_argument"),
        (&[("name", "..")], "invalid_argument"),
        (&[("name", "has space")], "invalid_argument"),
        (&[("name", &"n".repeat(121))], "invalid_argument"),
        (&[("name", "v1"), ("ttl", "abc")], "invalid_argument"),
        (&[("name", "v1"), ("ttl", "-5")], "invalid_argument"),
        (
            &[("name", "v1"), ("ttl", "18446744073709551615")],
            "invalid_argument",
        ),
        (
            &[("name", "v1"), ("if_exists", "replace")],
            "invalid_argument",
        ),
        (&[("name", "v1"), ("backend", "zfs")], "unsupported_backend"),
        (&[("name", "v1"), ("tags", "a,,b")], "invalid_argument"),
        (&[("name", "v1"), ("tags", "")], "invalid_argument"),
        (
            &[("name", "v1"), ("timeout_ms", "soon")],
            "invalid_argument",
        ),
        (&[("name", "v1"), ("timeout_ms", "-1")], "invalid_argument"),
        (&[("name", "v1"), ("colour", "red")], "invalid_argument"),
    ];
    for (args, code) in cases {
        let o = env.on(&app, "create", args);
        o.fails(2, code);
        assert!(!env.store().join("x").exists());
        assert!(env.snapshot_names().is_empty(), "{args:?} left a snapshot");
    }
    // The longest valid name is accepted.
    env.on(&app, "create", &[("name", &"n".repeat(120))]).ok();
}

#[test]
fn create_unknown_argument_names_it() {
    let env = Env::new();
    let app = env.app();
    let o = env.on(&app, "create", &[("name", "v1"), ("nmae", "x")]);
    o.fails(2, "invalid_argument");
    assert_eq!(o.json()["argument"], "nmae");
}

#[test]
fn dry_run_is_refused_by_verbs_without_a_dry_run() {
    let env = Env::new();
    let app = env.app();
    env.create(&app, "v1");
    for (verb, extra) in [
        ("create", ("name", "v2")),
        ("diff", ("from", "v1")),
        ("ls", ("limit", "1")),
    ] {
        for value in ["false", "true"] {
            let o = env.on(&app, verb, &[extra, ("dry_run", value)]);
            o.fails(2, "invalid_argument");
            assert_eq!(o.json()["argument"], "dry_run", "{verb}");
        }
    }
    assert_eq!(env.snapshot_names(), vec!["v1".to_string()]);
}

#[test]
fn unknown_arguments_get_a_did_you_mean_hint() {
    let env = Env::new();
    let app = env.app();
    let o = env.on(&app, "create", &[("nmae", "v1")]);
    o.fails(2, "invalid_argument");
    assert!(o.err.contains("did you mean \"name\"?"), "{}", o.err);
    let o = env.on(&app, "ls", &[("tags", "x")]);
    assert!(o.err.contains("did you mean \"tag\"?"), "{}", o.err);
    let o = env.on(&app, "diff", &[("from", "v1"), ("timeout", "5")]);
    assert!(o.err.contains("did you mean \"timeout_ms\"?"), "{}", o.err);
    let o = env.call("v1", "restore", &[("target", "/x"), ("froce", "true")]);
    assert!(o.err.contains("did you mean \"force\"?"), "{}", o.err);
    // No hint for something unrelated.
    let o = env.on(&app, "ls", &[("zzzzzzzz", "1")]);
    o.fails(2, "invalid_argument");
    assert!(!o.err.contains("did you mean"), "{}", o.err);
}

#[test]
fn suggestion_and_distance() {
    assert_eq!(edit_distance("kitten", "sitting"), 3);
    assert_eq!(edit_distance("", "abc"), 3);
    assert_eq!(suggest("if-exists", CREATE_OPTIONS), Some("if_exists"));
    assert_eq!(suggest("descr", CREATE_OPTIONS), Some("description"));
    assert_eq!(suggest("qqqqqq", CREATE_OPTIONS), None);
}

#[test]
fn create_target_errors() {
    let env = Env::new();
    env.on(&env.path("missing"), "create", &[("name", "v1")])
        .fails(1, "target_not_found");

    let fifo = env.path("fifo");
    mkfifo(&fifo);
    env.on(&fifo, "create", &[("name", "v1")])
        .fails(2, "invalid_target");

    // A target inside the snapshot store.
    fs::create_dir_all(env.store().join("inner")).unwrap();
    env.on(&env.store().join("inner"), "create", &[("name", "v1")])
        .fails(2, "invalid_target");
    assert!(env.snapshot_names().is_empty());
}

#[test]
fn create_store_unwritable_is_write_failed() {
    let tmp = TempDir::new().unwrap();
    let blocker = tmp.path().join("file");
    fs::write(&blocker, "x").unwrap();
    let _g = test_store::install(blocker.join("store"));
    let app = tmp.path().join("app");
    fs::create_dir(&app).unwrap();
    let url = Url::parse(&format!("snapshot://{}", app.display())).unwrap();
    let h = SnapshotHandle::from_url(&url).unwrap();
    let args: Args = [("name".to_string(), "v1".to_string())]
        .into_iter()
        .collect();
    let mut i: &[u8] = &[];
    let (mut o, mut e) = (Vec::new(), Vec::new());
    let mut io = IoStreams {
        stdin: &mut i,
        stdout: &mut o,
        stderr: &mut e,
    };
    let s = h.call("create", &args, &mut io).unwrap();
    assert_eq!(s.exit_code(), 1);
    let v: Value = serde_json::from_slice(&o).unwrap();
    assert_eq!(v["error"], "write_failed");
}

#[test]
fn create_name_conflict_between_targets_sharing_a_group() {
    let env = Env::new();
    let a = env.path("a b");
    let b = env.path("a_b");
    fs::create_dir(&a).unwrap();
    fs::create_dir(&b).unwrap();
    assert_eq!(group_dir(&env.store(), &a), group_dir(&env.store(), &b));
    env.create(&a, "v1");
    for mode in ["error", "skip", "overwrite"] {
        env.on(&b, "create", &[("name", "v1"), ("if_exists", mode)])
            .fails(1, "name_conflict");
    }
    // The first target's snapshot is untouched and ls keeps them apart.
    env.create(&b, "v2");
    let la = env.on(&a, "ls", &[]).json();
    let lb = env.on(&b, "ls", &[]).json();
    assert_eq!(la.as_array().unwrap().len(), 1);
    assert_eq!(la[0]["name"], "v1");
    assert_eq!(lb.as_array().unwrap().len(), 1);
    assert_eq!(lb[0]["name"], "v2");
}

#[test]
fn create_unreadable_file_is_copy_failed_and_leaves_nothing() {
    if root() {
        return; // root reads everything; covered by the permission model only
    }
    let env = Env::new();
    let app = env.app();
    let secret = app.join("secret");
    fs::write(&secret, "s").unwrap();
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o000)).unwrap();
    let o = env.on(&app, "create", &[("name", "v1")]);
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
    o.fails(1, "copy_failed");
    assert!(o.json()["message"].as_str().unwrap().contains("secret"));
    assert!(
        env.snapshot_names().is_empty(),
        "{:?}",
        env.snapshot_names()
    );
}

#[test]
fn create_follows_symlinks_and_rejects_broken_ones() {
    let env = Env::new();
    let app = env.app();
    let outside = env.path("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("o.txt"), "o").unwrap();
    std::os::unix::fs::symlink(&outside, app.join("linkdir")).unwrap();
    std::os::unix::fs::symlink(app.join("README"), app.join("linkfile")).unwrap();
    let v = env.create(&app, "v1");
    let c = PathBuf::from(v["path"].as_str().unwrap()).join("content");
    assert_eq!(fs::read_to_string(c.join("linkdir/o.txt")).unwrap(), "o");
    assert!(
        !fs::symlink_metadata(c.join("linkfile"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_to_string(c.join("linkfile")).unwrap(), "readme");

    std::os::unix::fs::symlink(env.path("nowhere"), app.join("dangling")).unwrap();
    let o = env.on(&app, "create", &[("name", "v2")]);
    o.fails(1, "copy_failed");
    assert!(o.json()["message"].as_str().unwrap().contains("dangling"));
    assert_eq!(env.snapshot_names(), vec!["v1".to_string()]);
}

#[test]
fn create_skips_special_files_with_a_warning() {
    let env = Env::new();
    let app = env.app();
    mkfifo(&app.join("pipe"));
    let o = env.on(&app, "create", &[("name", "v1")]);
    o.ok();
    assert!(o.err.contains("skipped pipe"), "{}", o.err);
    let c = PathBuf::from(o.json()["path"].as_str().unwrap()).join("content");
    assert!(!c.join("pipe").exists());
}

#[test]
fn create_never_copies_the_snapshot_store_into_itself() {
    // Store inside the target (as ~/.local/state is inside $HOME).
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(home.join("docs")).unwrap();
    fs::write(home.join("docs/a"), "a").unwrap();
    let _g = test_store::install(home.join(".local/state/resh/snapshots"));
    let url = Url::parse(&format!("snapshot://{}", home.display())).unwrap();
    let h = SnapshotHandle::from_url(&url).unwrap();
    let args: Args = [("name".to_string(), "h".to_string())]
        .into_iter()
        .collect();
    let mut i: &[u8] = &[];
    let (mut o, mut e) = (Vec::new(), Vec::new());
    let mut io = IoStreams {
        stdin: &mut i,
        stdout: &mut o,
        stderr: &mut e,
    };
    assert!(h.call("create", &args, &mut io).unwrap().ok);
    let v: Value = serde_json::from_slice(&o).unwrap();
    let c = PathBuf::from(v["path"].as_str().unwrap()).join("content");
    assert!(c.join("docs/a").exists());
    assert!(c.join(".local/state/resh").exists());
    assert!(!c.join(".local/state/resh/snapshots").exists());
}

#[test]
fn create_timeout_leaves_no_snapshot() {
    let env = Env::new();
    let app = env.app();
    many_files(&app.join("bulk"), 3000);
    let o = env.on(&app, "create", &[("name", "v1"), ("timeout_ms", "1")]);
    o.fails(EXIT_TIMEOUT, "timeout");
    assert!(
        env.snapshot_names().is_empty(),
        "{:?}",
        env.snapshot_names()
    );
    // timeout_ms=0 means no limit.
    env.on(&app, "create", &[("name", "v1"), ("timeout_ms", "0")])
        .ok();
}

#[test]
fn copy_steps_honour_an_expired_deadline() {
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("src");
    many_files(&src, 2);
    let mut stats = CopyStats::default();
    assert!(matches!(
        copy_tree(
            &src,
            &tmp.path().join("dst"),
            None,
            false,
            Deadline::expired(),
            &mut stats
        ),
        Err(OpError::Timeout)
    ));
    assert!(matches!(
        copy_file(&src.join("f0"), &tmp.path().join("f"), Deadline::expired()),
        Err(OpError::Timeout)
    ));
    assert!(matches!(
        hash_file(&src.join("f0"), Deadline::expired()),
        Err(OpError::Timeout)
    ));
}

// --- ls -------------------------------------------------------------------

fn write_meta(dir: &Path, meta: Value) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("meta.json"), meta.to_string()).unwrap();
}

#[test]
fn ls_lists_newest_first_with_filters() {
    let env = Env::new();
    let app = env.app();
    let g = group_dir(&env.store(), &app);
    let t = app.to_string_lossy().to_string();
    write_meta(
        &g.join("a"),
        json!({"id":"1","name":"deploy-a","created_at":"2026-01-01T00:00:00Z","target":t,
               "state":"complete","tags":["Nightly"],"backend":"local","description":"first"}),
    );
    write_meta(
        &g.join("b"),
        json!({"id":"2","name":"deploy-b","created_at":"2026-02-01T00:00:00Z","target":t,
               "state":"complete","tags":[]}),
    );
    write_meta(
        &g.join("c"),
        json!({"id":"3","name":"manual","created_at":"2026-03-01T00:00:00Z","target":t,
               "state":"failed"}),
    );
    let names = |pairs: &[(&str, &str)]| -> Vec<String> {
        let o = env.on(&app, "ls", pairs);
        o.ok();
        o.json()
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["name"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(names(&[]), ["manual", "deploy-b", "deploy-a"]);
    assert_eq!(names(&[("limit", "2")]), ["manual", "deploy-b"]);
    assert_eq!(
        names(&[("name_prefix", "deploy-")]),
        ["deploy-b", "deploy-a"]
    );
    assert_eq!(
        names(&[("since", "2026-02-01T00:00:00Z")]),
        ["manual", "deploy-b"]
    );
    assert_eq!(
        names(&[("until", "2026-01-31T00:00:00+00:00")]),
        ["deploy-a"]
    );
    assert_eq!(names(&[("state", "COMPLETE")]), ["deploy-b", "deploy-a"]);
    assert_eq!(names(&[("tag", "nightly")]), ["deploy-a"]);

    let o = env.on(&app, "ls", &[("limit", "1"), ("json_pretty", "true")]);
    o.ok();
    assert!(o.out.starts_with("[\n  {\n"), "{}", o.out);
    let compact = env.on(&app, "ls", &[("json_pretty", "false")]);
    assert!(compact.out.starts_with("[{"));

    // Output fields; empty tags are omitted.
    let all = env.on(&app, "ls", &[]).json();
    assert_eq!(all[2]["description"], "first");
    assert_eq!(all[2]["tags"], json!(["Nightly"]));
    assert!(all[1].get("tags").is_none());
}

#[test]
fn ls_matches_snapshots_made_by_create_on_state_and_tag() {
    let env = Env::new();
    let app = env.app();
    env.on(&app, "create", &[("name", "v1"), ("tags", "nightly")])
        .ok();
    env.create(&app, "v2");
    let o = env.on(&app, "ls", &[("state", "complete"), ("tag", "nightly")]);
    o.ok();
    let v = o.json();
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert_eq!(v[0]["name"], "v1");
    assert_eq!(v[0]["state"], "complete");
    assert!(v[0]["size_bytes"].as_u64().unwrap() > 0);
}

#[test]
fn ls_unknown_target_is_empty() {
    let env = Env::new();
    let o = env.on(&env.path("nothing"), "ls", &[]);
    o.ok();
    assert_eq!(o.out, "[]\n");
}

#[test]
fn ls_skips_broken_metadata_with_a_warning() {
    let env = Env::new();
    let app = env.app();
    env.create(&app, "good");
    let g = group_dir(&env.store(), &app);
    fs::create_dir_all(g.join("nometa")).unwrap();
    fs::create_dir_all(g.join("badmeta")).unwrap();
    fs::write(g.join("badmeta/meta.json"), "{not json").unwrap();
    let o = env.on(&app, "ls", &[]);
    o.ok();
    assert_eq!(o.json().as_array().unwrap().len(), 1);
    assert!(o.err.contains("skipping nometa"), "{}", o.err);
    assert!(o.err.contains("skipping badmeta"), "{}", o.err);
}

#[test]
fn ls_argument_errors() {
    let env = Env::new();
    let app = env.app();
    for (k, v) in [
        ("limit", "0"),
        ("limit", "ten"),
        ("limit", "-1"),
        ("since", "yesterday"),
        ("until", "2026-13-01"),
        ("json_pretty", "maybe"),
        ("timeout_ms", "1.5"),
        ("sort", "name"),
    ] {
        let o = env.on(&app, "ls", &[(k, v)]);
        o.fails(2, "invalid_argument");
        assert_eq!(o.json()["argument"], k, "{k}={v}");
    }
}

#[test]
fn ls_unreadable_group_is_read_failed() {
    if root() {
        return;
    }
    let env = Env::new();
    let app = env.app();
    env.create(&app, "v1");
    let g = group_dir(&env.store(), &app);
    fs::set_permissions(&g, fs::Permissions::from_mode(0o000)).unwrap();
    let o = env.on(&app, "ls", &[]);
    fs::set_permissions(&g, fs::Permissions::from_mode(0o755)).unwrap();
    o.fails(1, "read_failed");
}

#[test]
fn listing_honours_an_expired_deadline() {
    let env = Env::new();
    let app = env.app();
    env.create(&app, "v1");
    let g = group_dir(&env.store(), &app);
    let e = snapshots_in_group(&g, Some(&app), Deadline::expired(), &mut Vec::new()).unwrap_err();
    assert_eq!(e.exit, EXIT_TIMEOUT);
    assert_eq!(e.code, "timeout");
}

// --- diff -----------------------------------------------------------------

fn entry<'a>(v: &'a Value, path: &str) -> &'a Value {
    v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["path"] == path)
        .unwrap_or_else(|| panic!("no entry {path} in {v}"))
}

#[test]
fn diff_snapshot_against_live() {
    let env = Env::new();
    let app = env.app();
    let id = env.create(&app, "v1")["id"].as_str().unwrap().to_string();
    fs::write(app.join("conf/main.conf"), "v2 changed").unwrap();
    fs::write(app.join("new.txt"), "n").unwrap();
    fs::remove_file(app.join("README")).unwrap();

    let o = env.on(&app, "diff", &[("from", "v1"), ("to", "live")]);
    o.ok();
    let v = o.json();
    assert_eq!(
        v["summary"],
        json!({"added":1,"removed":1,"modified":1,"unchanged":3})
    );
    assert_eq!(v["from"], "v1");
    assert_eq!(v["to"], "live");
    assert_eq!(v["from_kind"], "snapshot");
    assert_eq!(v["to_kind"], "live");
    assert_eq!(v["root"], app.to_string_lossy().as_ref());
    assert_eq!(v["name"], app.to_string_lossy().as_ref());
    assert_eq!(v["path"], "/");
    let m = entry(&v, "conf/main.conf");
    assert_eq!(m["status"], "modified");
    assert_eq!(m["type"], "file");
    assert_eq!(m["from"]["size"], 2);
    assert_eq!(m["to"]["size"], 10);
    assert!(m["from"]["hash"].as_str().unwrap().starts_with("sha256:"));
    assert_eq!(entry(&v, "new.txt")["status"], "added");
    assert_eq!(entry(&v, "new.txt")["from"]["exists"], false);
    assert_eq!(entry(&v, "README")["status"], "removed");

    // By id, and with `to` omitted (live).
    let by_id = env.on(&app, "diff", &[("from", &id)]);
    by_id.ok();
    assert_eq!(by_id.json()["summary"], v["summary"]);
    assert_eq!(by_id.json()["to"], "live");

    // With `from` omitted, live is the old side.
    let rev = env.on(&app, "diff", &[("to", "v1")]);
    rev.ok();
    let r = rev.json();
    assert_eq!(r["from_kind"], "live");
    assert_eq!(entry(&r, "new.txt")["status"], "removed");
    assert_eq!(entry(&r, "README")["status"], "added");
}

#[test]
fn diff_unchanged_tree_after_create_is_clean() {
    // Modes and times are kept, so nothing differs right after create,
    // including directories.
    let env = Env::new();
    let app = env.app();
    fs::set_permissions(app.join("conf"), fs::Permissions::from_mode(0o700)).unwrap();
    env.create(&app, "v1");
    let v = env.on(&app, "diff", &[("from", "v1")]).json();
    assert_eq!(v["summary"]["modified"], 0, "{v}");
    assert_eq!(v["summary"]["unchanged"], 5);
    assert!(v["entries"].as_array().unwrap().is_empty());
}

#[test]
fn diff_detects_mode_change() {
    let env = Env::new();
    let app = env.app();
    env.create(&app, "v1");
    fs::set_permissions(app.join("README"), fs::Permissions::from_mode(0o600)).unwrap();
    let v = env.on(&app, "diff", &[("from", "v1")]).json();
    assert_eq!(entry(&v, "README")["status"], "modified");
}

#[test]
fn diff_two_snapshots_and_summary_format() {
    let env = Env::new();
    let app = env.app();
    env.create(&app, "v1");
    fs::write(app.join("conf/main.conf"), "v2").unwrap(); // same size, new hash
    env.create(&app, "v2");
    let o = env.on(
        &app,
        "diff",
        &[("from", "v1"), ("to", "v2"), ("format", "summary")],
    );
    o.ok();
    let expected = format!(
        "snapshot: {a}\nfrom: v1 (snapshot)\nto:   v2 (snapshot)\nroot: {a}\npath: /\n\n\
         added: 0\nremoved: 0\nmodified: 1\nunchanged: 4\n",
        a = app.display()
    );
    assert_eq!(o.out, expected);
}

#[test]
fn diff_path_restricts_comparison() {
    let env = Env::new();
    let app = env.app();
    env.create(&app, "v1");
    fs::write(app.join("conf/main.conf"), "changed!").unwrap();
    fs::write(app.join("README"), "changed too").unwrap();
    for p in ["conf", "/conf", "conf/"] {
        let v = env.on(&app, "diff", &[("from", "v1"), ("path", p)]).json();
        assert_eq!(v["summary"]["modified"], 1, "path={p}: {v}");
        assert_eq!(v["path"], p);
        entry(&v, "main.conf");
    }
    // A path naming a file compares that file.
    let v = env
        .on(&app, "diff", &[("from", "v1"), ("path", "README")])
        .json();
    assert_eq!(entry(&v, "README")["status"], "modified");
    // A path missing on both sides compares nothing.
    let v = env
        .on(&app, "diff", &[("from", "v1"), ("path", "nope")])
        .json();
    assert_eq!(
        v["summary"],
        json!({"added":0,"removed":0,"modified":0,"unchanged":0})
    );
}

#[test]
fn diff_file_target() {
    let env = Env::new();
    let f = env.path("hosts");
    fs::write(&f, "a").unwrap();
    env.create(&f, "h1");
    let v = env.on(&f, "diff", &[("from", "h1")]).json();
    assert_eq!(v["summary"]["unchanged"], 1);
    fs::write(&f, "b").unwrap();
    let v = env.on(&f, "diff", &[("from", "h1")]).json();
    assert_eq!(entry(&v, "hosts")["status"], "modified");
    env.on(&f, "diff", &[("from", "h1"), ("path", "x")])
        .fails(2, "invalid_argument");
}

#[test]
fn diff_reads_legacy_layout_snapshots() {
    let env = Env::new();
    let app = env.path("legacy");
    fs::create_dir_all(app.join("sub")).unwrap();
    fs::write(app.join("a"), "a").unwrap();
    fs::write(app.join("sub/meta.json"), "nested").unwrap();
    // Legacy directory snapshot: content beside meta.json, no kind.
    let dir = group_dir(&env.store(), &app).join("old");
    fs::create_dir_all(dir.join("sub")).unwrap();
    fs::write(dir.join("a"), "a").unwrap();
    fs::write(dir.join("sub/meta.json"), "nested").unwrap();
    write_meta(
        &dir,
        json!({"id":"legacy-id","name":"old","target":app.to_string_lossy()}),
    );
    let v = env.on(&app, "diff", &[("from", "old")]).json();
    // Top-level meta.json is metadata, the nested one is content.
    assert_eq!(v["summary"]["added"], 0, "{v}");
    assert_eq!(v["summary"]["removed"], 0, "{v}");
    assert_eq!(v["summary"]["unchanged"], 3, "{v}");
}

#[test]
fn diff_argument_errors() {
    let env = Env::new();
    let app = env.app();
    let id = env.create(&app, "v1")["id"].as_str().unwrap().to_string();
    let cases: &[&[(&str, &str)]] = &[
        &[],
        &[("from", "live")],
        &[("from", "live"), ("to", "live")],
        &[("from", "v1"), ("format", "yaml")],
        &[("from", "v1"), ("path", "../etc")],
        &[("from", "v1"), ("path", "conf/../../x")],
        &[("from", "v1"), ("to", "v1")],
        &[("from", "v1"), ("to", &id)],
        &[("from", "v1"), ("timeout_ms", "x")],
        &[("from", "v1"), ("color", "auto")],
    ];
    for args in cases {
        env.on(&app, "diff", args).fails(2, "invalid_argument");
    }
}

#[test]
fn diff_not_found_errors() {
    let env = Env::new();
    let app = env.app();
    env.create(&app, "v1");
    let o = env.on(&app, "diff", &[("from", "nope"), ("to", "live")]);
    o.fails(1, "snapshot_not_found");
    assert_eq!(o.json()["snapshot"], "nope");
    // Another target's snapshot is not visible.
    let other = env.path("other");
    fs::create_dir(&other).unwrap();
    env.on(&other, "diff", &[("from", "v1")])
        .fails(1, "snapshot_not_found");
    // Live side missing.
    fs::remove_dir_all(&app).unwrap();
    env.on(&app, "diff", &[("from", "v1")])
        .fails(1, "target_not_found");
}

#[test]
fn diff_missing_content_is_content_not_found() {
    let env = Env::new();
    let app = env.app();
    let v = env.create(&app, "v1");
    fs::remove_dir_all(PathBuf::from(v["path"].as_str().unwrap()).join("content")).unwrap();
    env.on(&app, "diff", &[("from", "v1")])
        .fails(1, "content_not_found");
    let snap = PathBuf::from(v["path"].as_str().unwrap());
    write_meta(
        &snap,
        json!({"id":"k","name":"v1","kind":"zvol","target":app.to_string_lossy()}),
    );
    env.on(&app, "diff", &[("from", "v1")])
        .fails(1, "metadata_invalid");
}

#[test]
fn diff_unreadable_live_directory_is_read_failed() {
    if root() {
        return;
    }
    let env = Env::new();
    let app = env.app();
    env.create(&app, "v1");
    let locked = app.join("locked");
    fs::create_dir(&locked).unwrap();
    fs::write(locked.join("x"), "x").unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    let o = env.on(&app, "diff", &[("from", "v1")]);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    o.fails(1, "read_failed");
}

#[test]
fn diff_unreadable_live_file_warns_and_falls_back_to_mtime() {
    if root() {
        return;
    }
    let env = Env::new();
    let app = env.app();
    env.create(&app, "v1");
    fs::set_permissions(app.join("README"), fs::Permissions::from_mode(0o000)).unwrap();
    let o = env.on(&app, "diff", &[("from", "v1")]);
    fs::set_permissions(app.join("README"), fs::Permissions::from_mode(0o644)).unwrap();
    o.ok();
    assert!(
        o.err.contains("compared by size, mode and mtime"),
        "{}",
        o.err
    );
    // The mode changed, so it is reported as modified.
    assert_eq!(entry(&o.json(), "README")["status"], "modified");
}

#[test]
fn diff_timeout() {
    let env = Env::new();
    let app = env.app();
    many_files(&app.join("bulk"), 3000);
    env.create(&app, "v1");
    env.on(&app, "diff", &[("from", "v1"), ("timeout_ms", "1")])
        .fails(EXIT_TIMEOUT, "timeout");
}

// --- restore --------------------------------------------------------------

#[test]
fn restore_directory_to_new_path_keeps_modes_and_times() {
    let env = Env::new();
    let app = env.app();
    fs::set_permissions(
        app.join("conf/main.conf"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    set_mtime(&app.join("conf/main.conf"), 1_200_000_000);
    env.create(&app, "v1");
    let dest = env.path("restored/app");
    let o = env.call("v1", "restore", &[("target", dest.to_str().unwrap())]);
    o.ok();
    assert_eq!(
        o.json(),
        json!({"mode":"overwrite","snapshot":"v1","status":"ok","target":dest.to_str().unwrap()})
    );
    assert_eq!(
        fs::read_to_string(dest.join("conf/main.conf")).unwrap(),
        "v1"
    );
    assert_eq!(
        fs::read_to_string(dest.join("meta.json")).unwrap(),
        "{\"mine\":true}"
    );
    assert_eq!(
        fs::read_to_string(dest.join("content")).unwrap(),
        "not storage"
    );
    assert_eq!(mode(&dest.join("conf/main.conf")), 0o600);
    assert_eq!(mtime(&dest.join("conf/main.conf")), 1_200_000_000);
    // No temporary files next to the target.
    let names: Vec<_> = fs::read_dir(env.path("restored"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, vec![std::ffi::OsString::from("app")]);
}

#[test]
fn restore_with_force_replaces_directory_and_file() {
    let env = Env::new();
    let app = env.app();
    env.create(&app, "v1");
    fs::write(app.join("conf/main.conf"), "broken").unwrap();
    fs::write(app.join("extra"), "x").unwrap();
    env.call(
        "v1",
        "restore",
        &[("target", app.to_str().unwrap()), ("force", "true")],
    )
    .ok();
    assert_eq!(
        fs::read_to_string(app.join("conf/main.conf")).unwrap(),
        "v1"
    );
    assert!(!app.join("extra").exists());

    let f = env.path("hosts");
    fs::write(&f, "good").unwrap();
    env.create(&f, "h1");
    fs::write(&f, "bad").unwrap();
    env.call(
        "h1",
        "restore",
        &[("target", f.to_str().unwrap()), ("force", "yes")],
    )
    .ok();
    assert_eq!(fs::read_to_string(&f).unwrap(), "good");
    // No backup or temp files left beside the targets.
    for e in fs::read_dir(env.tmp.path()).unwrap() {
        let n = e.unwrap().file_name().to_string_lossy().into_owned();
        assert!(!n.starts_with(".resh-"), "leftover {n}");
    }
}

#[test]
fn restore_file_over_directory_and_into_empty_directory() {
    let env = Env::new();
    let app = env.app();
    env.create(&app, "v1");
    // An empty directory target needs no force.
    let empty = env.path("empty");
    fs::create_dir(&empty).unwrap();
    env.call("v1", "restore", &[("target", empty.to_str().unwrap())])
        .ok();
    assert!(empty.join("conf/main.conf").exists());
}

#[test]
fn restore_dangling_symlink_target_needs_force() {
    let env = Env::new();
    let f = env.path("hosts");
    fs::write(&f, "good").unwrap();
    env.create(&f, "h1");
    let link = env.path("link");
    std::os::unix::fs::symlink(env.path("nowhere"), &link).unwrap();
    env.call("h1", "restore", &[("target", link.to_str().unwrap())])
        .fails(1, "target_exists");
    env.call(
        "h1",
        "restore",
        &[("target", link.to_str().unwrap()), ("force", "true")],
    )
    .ok();
    assert_eq!(fs::read_to_string(&link).unwrap(), "good");
}

#[test]
fn restore_dry_run_changes_nothing() {
    let env = Env::new();
    let app = env.app();
    env.create(&app, "v1");
    fs::write(app.join("conf/main.conf"), "current").unwrap();
    let o = env.call(
        "v1",
        "restore",
        &[
            ("target", app.to_str().unwrap()),
            ("force", "true"),
            ("dry_run", "true"),
        ],
    );
    o.ok();
    let v = o.json();
    assert_eq!(v["dry_run"], true);
    assert_eq!(v["force"], true);
    assert_eq!(v["mode"], "overwrite");
    let actions = v["actions"].as_array().unwrap();
    assert!(actions[0].as_str().unwrap().starts_with("DELETE DIRECTORY"));
    assert!(actions[1].as_str().unwrap().starts_with("COPY"));
    assert_eq!(
        fs::read_to_string(app.join("conf/main.conf")).unwrap(),
        "current"
    );

    // A new target: only the copy is planned and nothing is created.
    let dest = env.path("new/place");
    let v = env
        .call(
            "v1",
            "restore",
            &[("target", dest.to_str().unwrap()), ("dry_run", "1")],
        )
        .json();
    assert_eq!(v["actions"].as_array().unwrap().len(), 1);
    assert!(!env.path("new").exists());

    // A dry run still refuses an existing target without force.
    env.call(
        "v1",
        "restore",
        &[("target", app.to_str().unwrap()), ("dry_run", "true")],
    )
    .fails(1, "target_not_empty");
}

#[test]
fn restore_by_id_and_ambiguous_names() {
    let env = Env::new();
    let a = env.path("a");
    let b = env.path("b");
    fs::create_dir(&a).unwrap();
    fs::create_dir(&b).unwrap();
    fs::write(a.join("f"), "A").unwrap();
    fs::write(b.join("f"), "B").unwrap();
    let ida = env.create(&a, "same")["id"].as_str().unwrap().to_string();
    let idb = env.create(&b, "same")["id"].as_str().unwrap().to_string();

    let dest = env.path("out");
    let o = env.call("same", "restore", &[("target", dest.to_str().unwrap())]);
    o.fails(2, "ambiguous_snapshot");
    let ids: Vec<String> = o.json()["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap().to_string())
        .collect();
    assert!(ids.contains(&ida) && ids.contains(&idb));
    assert!(!dest.exists());

    env.call(&idb, "restore", &[("target", dest.to_str().unwrap())])
        .ok();
    assert_eq!(fs::read_to_string(dest.join("f")).unwrap(), "B");
}

#[test]
fn restore_legacy_layout_snapshots() {
    let env = Env::new();
    // Legacy directory snapshot.
    let dir = env.store().join("_legacy").join("old");
    fs::create_dir_all(dir.join("sub")).unwrap();
    fs::write(dir.join("sub/x"), "x").unwrap();
    write_meta(&dir, json!({"id":"l1","name":"old","target":"/legacy"}));
    let dest = env.path("d");
    env.call("old", "restore", &[("target", dest.to_str().unwrap())])
        .ok();
    assert_eq!(fs::read_to_string(dest.join("sub/x")).unwrap(), "x");
    assert!(!dest.join("meta.json").exists());
    // Legacy file snapshot.
    let fdir = env.store().join("_legacy_f").join("oldf");
    fs::create_dir_all(&fdir).unwrap();
    fs::write(fdir.join("content"), "file").unwrap();
    write_meta(&fdir, json!({"id":"l2","name":"oldf","target":"/legacy/f"}));
    let fdest = env.path("f");
    env.call("oldf", "restore", &[("target", fdest.to_str().unwrap())])
        .ok();
    assert_eq!(fs::read_to_string(&fdest).unwrap(), "file");
}

#[test]
fn restore_argument_errors() {
    let env = Env::new();
    let app = env.app();
    env.create(&app, "v1");
    let dest = env.path("dest");
    let d = dest.to_str().unwrap();
    let cases: &[(&[(&str, &str)], &str)] = &[
        (&[], "missing_argument"),
        (&[("target", " ")], "missing_argument"),
        (&[("target", d), ("force", "maybe")], "invalid_argument"),
        (&[("target", d), ("dry_run", "perhaps")], "invalid_argument"),
        (&[("target", d), ("mode", "merge")], "unsupported_mode"),
        (
            &[("target", d), ("timeout_ms", "later")],
            "invalid_argument",
        ),
        (&[("target", d), ("verbose", "true")], "invalid_argument"),
        (&[("target", "/")], "invalid_target"),
    ];
    for (args, code) in cases {
        env.call("v1", "restore", args).fails(2, code);
        assert!(!dest.exists());
    }
    // Snapshot names that could leave the store or read as options.
    for name in ["-v1", ".v1"] {
        env.call(name, "restore", &[("target", d)])
            .fails(2, "invalid_argument");
    }
    env.call("x/../../v1", "restore", &[("target", d)])
        .fails(2, "invalid_argument");
}

#[test]
fn restore_refuses_targets_overlapping_the_snapshot() {
    let env = Env::new();
    let app = env.app();
    let v = env.create(&app, "v1");
    let snap = PathBuf::from(v["path"].as_str().unwrap());
    for t in [
        snap.join("content"),
        env.store(),
        env.tmp.path().to_path_buf(),
    ] {
        env.call(
            "v1",
            "restore",
            &[("target", t.to_str().unwrap()), ("force", "true")],
        )
        .fails(2, "invalid_target");
    }
    assert!(snap.join("content/conf/main.conf").exists());
}

#[test]
fn restore_not_found_errors() {
    let env = Env::new();
    let dest = env.path("dest");
    let d = dest.to_str().unwrap();
    // Empty store.
    env.call("v1", "restore", &[("target", d)])
        .fails(1, "snapshot_not_found");
    let app = env.app();
    let v = env.create(&app, "v1");
    env.call("v2", "restore", &[("target", d)])
        .fails(1, "snapshot_not_found");

    let snap = PathBuf::from(v["path"].as_str().unwrap());
    fs::remove_dir_all(snap.join("content")).unwrap();
    env.call("v1", "restore", &[("target", d)])
        .fails(1, "content_not_found");

    fs::write(snap.join("meta.json"), "{broken").unwrap();
    env.call("v1", "restore", &[("target", d)])
        .fails(1, "metadata_invalid");

    fs::remove_file(snap.join("meta.json")).unwrap();
    env.call("v1", "restore", &[("target", d)])
        .fails(1, "metadata_not_found");

    // Unknown kind.
    write_meta(&snap, json!({"id":"k","name":"v1","kind":"zvol"}));
    env.call("v1", "restore", &[("target", d)])
        .fails(1, "metadata_invalid");
    assert!(!dest.exists());
}

#[test]
fn restore_existing_target_without_force() {
    let env = Env::new();
    let app = env.app();
    env.create(&app, "v1");
    fs::write(app.join("conf/main.conf"), "live").unwrap();
    env.call("v1", "restore", &[("target", app.to_str().unwrap())])
        .fails(1, "target_not_empty");
    env.call(
        "v1",
        "restore",
        &[("target", app.to_str().unwrap()), ("force", "false")],
    )
    .fails(1, "target_not_empty");
    let f = env.path("file");
    fs::write(&f, "keep").unwrap();
    env.call("v1", "restore", &[("target", f.to_str().unwrap())])
        .fails(1, "target_exists");
    assert_eq!(fs::read_to_string(&f).unwrap(), "keep");
    assert_eq!(
        fs::read_to_string(app.join("conf/main.conf")).unwrap(),
        "live"
    );
}

#[test]
fn restore_uninspectable_target_is_read_failed() {
    if root() {
        return;
    }
    let env = Env::new();
    let app = env.app();
    env.create(&app, "v1");
    let locked = env.path("locked");
    fs::create_dir(&locked).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    let o = env.call(
        "v1",
        "restore",
        &[("target", locked.join("app").to_str().unwrap())],
    );
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    o.fails(1, "read_failed");
}

#[test]
fn restore_unwritable_parent_is_copy_failed() {
    if root() {
        return;
    }
    let env = Env::new();
    let app = env.app();
    env.create(&app, "v1");
    let locked = env.path("locked");
    fs::create_dir(&locked).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).unwrap();
    let o = env.call(
        "v1",
        "restore",
        &[("target", locked.join("app").to_str().unwrap())],
    );
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    o.fails(1, "copy_failed");
    assert_eq!(fs::read_dir(&locked).unwrap().count(), 0);
}

#[test]
fn restore_timeout_leaves_target_unchanged() {
    let env = Env::new();
    let app = env.app();
    many_files(&app.join("bulk"), 3000);
    env.create(&app, "v1");
    fs::remove_dir_all(app.join("bulk")).unwrap();
    fs::write(app.join("conf/main.conf"), "live").unwrap();
    env.call(
        "v1",
        "restore",
        &[
            ("target", app.to_str().unwrap()),
            ("force", "true"),
            ("timeout_ms", "1"),
        ],
    )
    .fails(EXIT_TIMEOUT, "timeout");
    assert_eq!(
        fs::read_to_string(app.join("conf/main.conf")).unwrap(),
        "live"
    );
    assert!(!app.join("bulk").exists());
    for e in fs::read_dir(env.tmp.path()).unwrap() {
        let n = e.unwrap().file_name().to_string_lossy().into_owned();
        assert!(!n.starts_with(".resh-"), "leftover {n}");
    }
}
