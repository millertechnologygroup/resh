//! Verb-level tests for the file handle. Every call goes through
//! `Handle::call` with `Args`, as the CLI does. Everything happens in
//! temporary directories.

use super::common::{Code, verb_options};
use super::{FileHandle, HELP_PATH, OPERATION_VERBS};
use crate::core::{Args, Handle, IoStreams, Status};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;
use url::Url;

// --- helpers ---------------------------------------------------------------

struct Out {
    st: Status,
    out: String,
    err: String,
}

impl Out {
    #[track_caller]
    fn ok(&self) -> &Self {
        assert!(
            self.st.ok,
            "expected success, got {:?} (stderr {:?})",
            self.st.reason, self.err
        );
        assert_eq!(self.st.exit_code(), 0);
        self
    }

    #[track_caller]
    fn fails(&self, code: Code) -> &Self {
        assert!(!self.st.ok, "expected {code:?}, got success: {}", self.out);
        let reason = self.st.reason.clone().unwrap_or_default();
        assert!(
            reason.starts_with(&format!("{}: ", code.name())),
            "expected {}, got {reason:?}",
            code.name()
        );
        assert_eq!(self.st.exit_code(), code.exit(), "{reason}");
        self
    }

    fn reason(&self) -> String {
        self.st.reason.clone().unwrap_or_default()
    }

    #[track_caller]
    fn json(&self) -> Value {
        serde_json::from_str(self.out.trim()).unwrap_or_else(|e| panic!("{e}: {:?}", self.out))
    }
}

fn handle(target: &str) -> FileHandle {
    FileHandle::from_url(Url::parse(target).unwrap()).unwrap()
}

fn url_of(p: &Path) -> String {
    format!("file://{}", p.display())
}

fn args(pairs: &[(&str, &str)]) -> Args {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn call_with_stdin(path: &Path, verb: &str, pairs: &[(&str, &str)], stdin: &[u8]) -> Out {
    let h = handle(&url_of(path));
    let mut input: &[u8] = stdin;
    let (mut o, mut e) = (Vec::new(), Vec::new());
    let st = {
        let mut io = IoStreams::new(&mut input, &mut o, &mut e);
        h.call(verb, &args(pairs), &mut io)
            .expect("file verbs never return Err")
    };
    Out {
        st,
        out: String::from_utf8_lossy(&o).into_owned(),
        err: String::from_utf8_lossy(&e).into_owned(),
    }
}

fn call(path: &Path, verb: &str, pairs: &[(&str, &str)]) -> Out {
    call_with_stdin(path, verb, pairs, b"")
}

fn call_url(target: &str, verb: &str, pairs: &[(&str, &str)]) -> Out {
    let h = handle(target);
    let mut input: &[u8] = b"";
    let (mut o, mut e) = (Vec::new(), Vec::new());
    let st = {
        let mut io = IoStreams::new(&mut input, &mut o, &mut e);
        h.call(verb, &args(pairs), &mut io).unwrap()
    };
    Out {
        st,
        out: String::from_utf8_lossy(&o).into_owned(),
        err: String::from_utf8_lossy(&e).into_owned(),
    }
}

fn tmp() -> TempDir {
    TempDir::new().unwrap()
}

fn file(dir: &TempDir, name: &str, content: &str) -> PathBuf {
    let p = dir.path().join(name);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&p, content).unwrap();
    p
}

fn mode_of(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o7777
}

fn chmod(p: &Path, m: u32) {
    fs::set_permissions(p, fs::Permissions::from_mode(m)).unwrap();
}

fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// Whether the temporary filesystem supports `user.*` attributes.
fn xattrs_supported(dir: &TempDir) -> bool {
    let p = dir.path().join(".probe");
    fs::write(&p, "").unwrap();
    let ok = xattr::set(&p, "user.resh_probe", b"1").is_ok();
    fs::remove_file(&p).unwrap();
    ok
}

fn mkfifo(p: &Path) {
    nix::unistd::mkfifo(p, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
}

/// A directory on a different filesystem from `/tmp`, when there is one
/// (the crate's target directory usually is). Removed when dropped.
fn other_fs_dir(than: &Path) -> Option<TempDir> {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
    fs::create_dir_all(&base).ok()?;
    let d = TempDir::new_in(&base).ok()?;
    let a = fs::metadata(than).ok()?.dev();
    let b = fs::metadata(d.path()).ok()?.dev();
    (a != b).then_some(d)
}

// --- dispatch, options, error codes ----------------------------------------

#[test]
fn every_failure_is_a_status_with_a_documented_code() {
    let docs = include_str!("../../../../docs/Filesystem_Storage/file.md");
    for c in Code::ALL {
        assert!(docs.contains(c.name()), "{} is not documented", c.name());
        let expected = if *c == Code::InvalidArg { 2 } else { 1 };
        assert_eq!(c.exit(), expected, "{c:?}");
    }
}

#[test]
fn unknown_verb_is_invalid_arg() {
    let d = tmp();
    let p = file(&d, "f", "x");
    call(&p, "frobnicate", &[]).fails(Code::InvalidArg);
    assert_eq!(fs::read_to_string(&p).unwrap(), "x");
}

#[test]
fn every_verb_rejects_unknown_arguments_without_side_effects() {
    for verb in OPERATION_VERBS {
        let d = tmp();
        let p = file(&d, "f", "content\n");
        let o = call(
            &p,
            verb,
            &[("no_such_option", "1"), ("to", "x"), ("data", "y")],
        );
        o.fails(Code::InvalidArg);
        assert!(
            o.reason().contains("unknown argument"),
            "{verb}: {}",
            o.reason()
        );
        assert_eq!(fs::read_to_string(&p).unwrap(), "content\n", "{verb}");
        assert!(o.out.is_empty(), "{verb} printed {:?}", o.out);
    }
}

#[test]
fn every_listed_option_is_accepted_by_its_verb() {
    for verb in OPERATION_VERBS {
        for opt in verb_options(verb) {
            let d = tmp();
            let p = file(&d, "f", "content\n");
            // A destination stays inside the temporary directory.
            let bad = if opt == "to" {
                d.path().join("\u{1}bad").to_string_lossy().into_owned()
            } else {
                "\u{1}bad".to_string()
            };
            let o = call(&p, verb, &[(opt, &bad)]);
            assert!(
                !o.reason().contains("unknown argument"),
                "{verb} rejected its own option {opt}: {}",
                o.reason()
            );
        }
    }
}

#[test]
fn option_lists_come_from_the_help_usage() {
    let expect: &[(&str, &[&str])] = &[
        ("read", &[]),
        ("stat", &["nofollow"]),
        (
            "preview",
            &[
                "max_bytes",
                "max_lines",
                "mode",
                "encoding",
                "include_metadata",
            ],
        ),
        ("tail", &["lines", "bytes", "follow", "timeout_ms"]),
        (
            "grep",
            &[
                "pattern",
                "regex",
                "ignore_case",
                "invert",
                "max",
                "before",
                "after",
                "format",
                "line_numbers",
            ],
        ),
        (
            "find",
            &[
                "name",
                "type",
                "max_depth",
                "limit",
                "include_hidden",
                "follow_symlinks",
            ],
        ),
        ("watch", &["timeout_ms", "max_events", "events"]),
        ("verify", &["algo", "expected", "expected_any", "size"]),
        ("write", &["data", "create", "mode"]),
        (
            "replace",
            &[
                "pattern",
                "replacement",
                "regex",
                "count",
                "dry_run",
                "backup",
            ],
        ),
        (
            "copy",
            &["to", "overwrite", "preserve_mode", "preserve_times"],
        ),
        ("rename", &["to", "overwrite", "create_parents", "atomic"]),
        ("chown", &["user", "uid", "group", "gid", "recursive"]),
        ("ea.set", &["name", "value", "mode"]),
        ("tag.rm", &["name"]),
    ];
    for (verb, opts) in expect {
        assert_eq!(verb_options(verb), *opts, "{verb}");
    }
}

#[test]
fn dry_run_and_timeout_are_refused_where_unsupported() {
    let d = tmp();
    let p = file(&d, "f", "x");
    call(&p, "read", &[("dry_run", "false")]).fails(Code::InvalidArg);
    call(&p, "delete", &[("dry_run", "false")]).fails(Code::InvalidArg);
    call(&p, "sha256", &[("timeout_ms", "100")]).fails(Code::InvalidArg);
    assert!(p.exists());
}

#[test]
fn unknown_arguments_get_a_suggestion() {
    let d = tmp();
    let p = file(&d, "f", "x");
    let o = call(&p, "grep", &[("pattern", "x"), ("ignorecase", "true")]);
    o.fails(Code::InvalidArg);
    assert!(
        o.reason().contains("did you mean ignore_case?"),
        "{}",
        o.reason()
    );
    let o = call(&p, "copy", &[("to", "y"), ("overwite", "true")]);
    assert!(
        o.reason().contains("did you mean overwrite?"),
        "{}",
        o.reason()
    );
    let o = call(&p, "tail", &[("line", "2")]);
    assert!(o.reason().contains("did you mean lines?"), "{}", o.reason());
    let o = call(&p, "find", &[("zzzzzz", "1")]);
    assert!(!o.reason().contains("did you mean"), "{}", o.reason());
    assert!(!d.path().join("y").exists());
}

#[test]
fn boolean_options_are_strict() {
    let d = tmp();
    let p = file(&d, "f", "x\n");
    for (verb, key) in [
        ("stat", "nofollow"),
        ("preview", "include_metadata"),
        ("tail", "follow"),
        ("grep", "regex"),
        ("find", "include_hidden"),
        ("write", "create"),
        ("append", "create"),
        ("replace", "regex"),
        ("copy", "preserve_mode"),
        ("rename", "atomic"),
        ("delete", "missing_ok"),
        ("chown", "recursive"),
        ("ea.get", "allow_missing"),
    ] {
        let mut a = vec![(key, "maybe")];
        if verb == "grep" || verb == "replace" {
            a.push(("pattern", "x"));
            a.push(("replacement", "y"));
        }
        if verb == "copy" || verb == "rename" {
            a.push(("to", "z"));
        }
        if verb == "chown" {
            a.push(("uid", "0"));
        }
        if verb == "ea.get" {
            a.push(("name", "user.x"));
        }
        let a: Vec<_> = if verb == "grep" {
            a.into_iter().filter(|(k, _)| *k != "replacement").collect()
        } else {
            a
        };
        call(&p, verb, &a).fails(Code::InvalidArg);
        assert_eq!(fs::read_to_string(&p).unwrap(), "x\n", "{verb}");
    }
    // All spellings are accepted.
    for v in ["true", "1", "yes", "on", "TRUE", "false", "0", "no", "off"] {
        call(&p, "stat", &[("nofollow", v)]).ok();
    }
}

// --- URL handling (kept from the original module) --------------------------

fn target(u: &str) -> PathBuf {
    handle(u).path
}

#[test]
fn from_url_joins_host_and_path() {
    assert_eq!(target("file://./x"), PathBuf::from("x"));
    assert_eq!(target("file://./dir/x.txt"), PathBuf::from("dir/x.txt"));
    assert_eq!(target("file://dir/x"), PathBuf::from("dir/x"));
    assert_eq!(
        target("file://dir/sub/x.txt"),
        PathBuf::from("dir/sub/x.txt")
    );
    assert_eq!(target("file://name"), PathBuf::from("name"));
    assert_eq!(target("file://name.txt"), PathBuf::from("name.txt"));
    assert_eq!(target("file:///abs"), PathBuf::from("/abs"));
    assert_eq!(
        target("file:///var/log/syslog"),
        PathBuf::from("/var/log/syslog")
    );
    assert_eq!(target("file://../up/x"), PathBuf::from("../up/x"));
    assert_eq!(target("file://."), PathBuf::from("."));
}

/// The url crate normalizes the host of a special-scheme URL. These cases
/// document the limitation described in FILE_HELP.
#[test]
fn from_url_host_is_normalized_by_url_crate() {
    assert_eq!(target("file://Dir/X.txt"), PathBuf::from("dir/X.txt"));
    assert_eq!(target("file://localhost/x"), PathBuf::from("/x"));
    assert_eq!(target("file://./Report.txt"), PathBuf::from("Report.txt"));
}

#[test]
fn help_detection_is_exact() {
    assert_eq!(target("file://--help"), PathBuf::from(HELP_PATH));
    assert_eq!(target("file://-h"), PathBuf::from(HELP_PATH));
    assert_eq!(
        target("file:///home/x/my-hosts"),
        PathBuf::from("/home/x/my-hosts")
    );
    assert_eq!(
        target("file://pre-hotfix.txt"),
        PathBuf::from("pre-hotfix.txt")
    );
    assert_eq!(
        target("file://my-httpd/conf"),
        PathBuf::from("my-httpd/conf")
    );
}

#[test]
fn hyphenated_file_is_read_not_help() {
    let d = tmp();
    let p = file(&d, "my-hosts", "127.0.0.1 localhost\n");
    let o = call(&p, "read", &[]);
    o.ok();
    assert_eq!(o.out, "127.0.0.1 localhost\n");
}

#[test]
fn in_url_help_renders_approved_help() {
    let o = call_url("file://--help", "help", &[]);
    assert!(o.out.starts_with("Handle: file\n"));
    let o = call_url("file://--help", "help", &[("verb", "read")]);
    assert!(o.out.starts_with("Handle: file\nVerb: read\n"));
    let o = call_url("file:///etc/hosts", "h", &[]);
    assert!(o.out.starts_with("Handle: file\n"));
}

#[test]
fn relative_directories_work_like_absolute_ones() {
    // Relative to the crate root (cargo's test working directory).
    let o = call_url("file://./src/core", "find", &[]);
    o.ok();
    assert!(o.out.contains("status.rs"), "{}", o.out);
    let rel = call_url("file://src/core", "find", &[]).json();
    let abs = std::env::current_dir().unwrap().join("src/core");
    let abs = call(&abs, "find", &[]).json();
    assert_eq!(rel, abs);
    let o = call_url("file://./src/core", "stat", &[]);
    assert_eq!(o.json()["file_type"], "dir");
    call_url("file://./src", "read", &[]).fails(Code::IsADirectory);
    call_url("file://./no-such-dir-resh-test", "find", &[]).fails(Code::NotFound);
}

#[test]
fn traversal_and_symlinks_are_not_rewritten() {
    assert_eq!(
        target("file://./src/../src/core"),
        PathBuf::from("src/core")
    );
    assert_eq!(target("file://../x"), PathBuf::from("../x"));
}

// --- read ------------------------------------------------------------------

#[test]
fn read_prints_raw_bytes() {
    let d = tmp();
    let p = d.path().join("bin");
    fs::write(&p, [0u8, 1, 2, 255, b'\n']).unwrap();
    let h = handle(&url_of(&p));
    let mut i: &[u8] = b"";
    let (mut o, mut e) = (Vec::new(), Vec::new());
    let st = h
        .call(
            "read",
            &Args::new(),
            &mut IoStreams::new(&mut i, &mut o, &mut e),
        )
        .unwrap();
    assert!(st.ok);
    assert_eq!(o, vec![0u8, 1, 2, 255, b'\n']);
}

#[test]
fn read_errors() {
    let d = tmp();
    call(&d.path().join("missing"), "read", &[]).fails(Code::NotFound);
    call(&d.path().join("missing/below"), "read", &[]).fails(Code::NotFound);
    call(d.path(), "read", &[]).fails(Code::IsADirectory);
    call(&file(&d, "f", "x"), "read", &[("x", "1")]).fails(Code::InvalidArg);
    if !is_root() {
        let p = file(&d, "secret", "x");
        chmod(&p, 0o000);
        call(&p, "read", &[]).fails(Code::PermissionDenied);
    }
}

// --- exists / stat ---------------------------------------------------------

#[test]
fn exists_reports_kind() {
    let d = tmp();
    let f = file(&d, "f", "x");
    symlink(&f, d.path().join("l")).unwrap();
    symlink(d.path().join("nowhere"), d.path().join("dangling")).unwrap();
    let kind = |p: &Path| {
        let o = call(p, "exists", &[]);
        o.ok();
        assert!(o.out.ends_with('\n'));
        let v = o.json();
        (
            v["exists"].as_bool().unwrap(),
            v["kind"].as_str().unwrap().to_string(),
        )
    };
    assert_eq!(kind(&f), (true, "file".into()));
    assert_eq!(kind(d.path()), (true, "dir".into()));
    assert_eq!(kind(&d.path().join("l")), (true, "symlink".into()));
    assert_eq!(kind(&d.path().join("dangling")), (true, "symlink".into()));
    assert_eq!(kind(&d.path().join("missing")), (false, "none".into()));
    assert_eq!(kind(&f.join("below")), (false, "none".into()));
}

#[test]
fn exists_permission_error() {
    if is_root() {
        return;
    }
    let d = tmp();
    let sub = d.path().join("sub");
    fs::create_dir(&sub).unwrap();
    file(&d, "sub/f", "x");
    chmod(&sub, 0o000);
    let o = call(&sub.join("f"), "exists", &[]);
    chmod(&sub, 0o755);
    o.fails(Code::PermissionDenied);
}

#[test]
fn stat_follows_unless_nofollow() {
    let d = tmp();
    let f = file(&d, "f", "hello");
    chmod(&f, 0o640);
    let l = d.path().join("l");
    symlink(&f, &l).unwrap();
    let v = call(&l, "stat", &[]).json();
    assert_eq!(v["file_type"], "file");
    assert_eq!(v["size"], 5);
    assert_eq!(v["mode"], "0640");
    assert_eq!(v["uid"], nix::unistd::geteuid().as_raw());
    for k in [
        "accessed", "modified", "created", "readonly", "gid", "exists", "path",
    ] {
        assert!(v.get(k).is_some(), "{k}");
    }
    let v = call(&l, "stat", &[("nofollow", "true")]).json();
    assert_eq!(v["file_type"], "symlink");
    assert_eq!(call(d.path(), "stat", &[]).json()["file_type"], "dir");
    call(&d.path().join("missing"), "stat", &[]).fails(Code::NotFound);
    call(&f, "stat", &[("nofollow", "x")]).fails(Code::InvalidArg);
}

// --- preview ---------------------------------------------------------------

#[test]
fn preview_text_and_limits() {
    let d = tmp();
    let p = file(&d, "t", "one\ntwo\nthree\n");
    let v = call(&p, "preview", &[]).json();
    assert_eq!(v["mode"], "text");
    assert_eq!(v["sample"], "one\ntwo\nthree\n");
    assert_eq!(v["line_count"], 3);
    assert_eq!(v["is_truncated"], false);
    assert_eq!(v["encoding"], "utf-8");
    assert_eq!(v["metadata"]["is_file"], true);

    let v = call(&p, "preview", &[("max_lines", "2")]).json();
    assert_eq!(v["sample"], "one\ntwo");
    assert_eq!(v["line_count"], 2);

    let v = call(&p, "preview", &[("max_bytes", "5")]).json();
    assert_eq!(v["sample"], "one\nt");
    assert_eq!(v["preview_len_bytes"], 5);
    assert_eq!(v["file_size_bytes"], 14);
    assert_eq!(v["is_truncated"], true);

    let v = call(&p, "preview", &[("include_metadata", "false")]).json();
    assert!(v.get("metadata").is_none());
}

#[test]
fn preview_binary_modes() {
    let d = tmp();
    let p = d.path().join("b");
    fs::write(&p, [0u8, 1, 2, 3, 0xff]).unwrap();
    let v = call(&p, "preview", &[]).json();
    assert_eq!(v["mode"], "binary");
    assert_eq!(v["encoding"], "base64");
    assert_eq!(v["sample"], "AAECA/8=");
    assert_eq!(v["line_count"], Value::Null);
    let v = call(&p, "preview", &[("encoding", "hex")]).json();
    assert_eq!(v["sample"], "00010203ff");
    let t = file(&d, "t", "abc");
    let v = call(&t, "preview", &[("mode", "binary"), ("encoding", "HEX")]).json();
    assert_eq!(v["sample"], "616263");
    let v = call(&p, "preview", &[("mode", "text")]).json();
    assert_eq!(v["mode"], "text");
}

#[test]
fn preview_errors() {
    let d = tmp();
    let p = file(&d, "t", "x");
    for (k, v) in [
        ("max_bytes", "0"),
        ("max_bytes", "abc"),
        ("max_bytes", "-1"),
        ("max_lines", "0"),
        ("mode", "hex"),
        ("encoding", "utf8"),
        ("include_metadata", "maybe"),
    ] {
        call(&p, "preview", &[(k, v)]).fails(Code::InvalidArg);
    }
    call(&d.path().join("missing"), "preview", &[]).fails(Code::NotFound);
    call(d.path(), "preview", &[]).fails(Code::IsADirectory);
    let fifo = d.path().join("fifo");
    mkfifo(&fifo);
    call(&fifo, "preview", &[]).fails(Code::NotAFile);
}

#[test]
fn preview_huge_max_bytes_does_not_allocate_it() {
    let d = tmp();
    let p = file(&d, "t", "small");
    let v = call(&p, "preview", &[("max_bytes", "18446744073709551615")]).json();
    assert_eq!(v["sample"], "small");
}

// --- summary / analyze / schema --------------------------------------------

const USERS_CSV: &str = "id,name,joined\n1,alice,2026-01-05\n2,bob,2026-02-11\n";

#[test]
fn summary_file_and_directory() {
    let d = tmp();
    let p = file(&d, "users.csv", USERS_CSV);
    let v = call(&p, "summary", &[]).json();
    assert_eq!(v["content_type"], "csv");
    assert_eq!(v["size"], 51);
    assert_eq!(v["line_count"], 3);
    assert_eq!(v["avg_line_length"], 16.0);
    assert_eq!(v["is_dir"], false);
    let v = call(&p, "summary", &[("max_bytes", "15")]).json();
    assert_eq!(v["line_count"], 1);
    assert_eq!(v["sample"], "id,name,joined\n");
    let v = call(d.path(), "summary", &[]).json();
    assert_eq!(v["is_dir"], true);
    assert_eq!(v["entry_count"], 1);
    let b = d.path().join("b");
    fs::write(&b, [0u8, 1]).unwrap();
    let v = call(&b, "summary", &[]).json();
    assert_eq!(v["content_type"], "binary");
    assert_eq!(v["line_count"], Value::Null);
    let j = file(&d, "j", "{\"a\":1}");
    assert_eq!(call(&j, "summary", &[]).json()["content_type"], "json");
}

#[test]
fn summary_errors() {
    let d = tmp();
    let p = file(&d, "f", "x");
    call(&p, "summary", &[("max_bytes", "0")]).fails(Code::InvalidArg);
    call(&p, "summary", &[("max_bytes", "x")]).fails(Code::InvalidArg);
    call(&d.path().join("missing"), "summary", &[]).fails(Code::NotFound);
    let fifo = d.path().join("fifo");
    mkfifo(&fifo);
    call(&fifo, "summary", &[]).fails(Code::NotAFile);
}

#[test]
fn analyze_classifies() {
    let d = tmp();
    let cases = [
        ("j", "{\"a\": [1, 2]}\n", "json"),
        ("c", USERS_CSV, "csv"),
        ("l", "2026-01-01 start\n2026-01-01 stop\n", "log"),
        ("t", "hello world\nplain\n", "text"),
    ];
    for (name, content, class) in cases {
        let p = file(&d, name, content);
        let v = call(&p, "analyze", &[]).json();
        assert_eq!(v["classification"], class, "{name}");
        assert_eq!(v["ascii_ratio"], 1.0);
        assert_eq!(v["null_byte_present"], false);
    }
    let b = d.path().join("b");
    fs::write(&b, [0u8, 200, 201, 202]).unwrap();
    let v = call(&b, "analyze", &[]).json();
    assert_eq!(v["classification"], "binary");
    assert_eq!(v["null_byte_present"], true);
    assert_eq!(v["entropy"], 2.0);
    let t = file(&d, "t2", "aaaa\nbbbb\n");
    let v = call(&t, "analyze", &[("max_bytes", "5")]).json();
    assert_eq!(v["sample_bytes"], 5);
    assert_eq!(v["size_bytes"], 10);
    assert_eq!(v["line_count"], 1);
}

#[test]
fn analyze_errors() {
    let d = tmp();
    let p = file(&d, "f", "x");
    call(&p, "analyze", &[("max_bytes", "0")]).fails(Code::InvalidArg);
    call(&d.path().join("missing"), "analyze", &[]).fails(Code::NotFound);
    call(d.path(), "analyze", &[]).fails(Code::IsADirectory);
}

#[test]
fn schema_detects_formats() {
    let d = tmp();
    let csv = file(&d, "users.csv", USERS_CSV);
    let v = call(&csv, "schema", &[]).json();
    assert_eq!(v["format"], "csv");
    assert_eq!(v["byte_sample"], 51);
    assert_eq!(v["detected"]["row_count_sampled"], 2);
    let cols = v["detected"]["columns"].as_array().unwrap();
    assert_eq!(cols[0]["name"], "id");
    assert_eq!(cols[0]["types"], serde_json::json!(["integer"]));
    assert_eq!(cols[2]["types"], serde_json::json!(["datetime"]));
    let v = call(&csv, "schema", &[("max_rows", "1")]).json();
    assert_eq!(v["detected"]["row_count_sampled"], 1);

    let j = file(&d, "a.json", r#"[{"a":1,"b":"x"},{"a":2.5}]"#);
    let v = call(&j, "schema", &[]).json();
    assert_eq!(v["format"], "json");
    assert_eq!(v["detected"]["json_type"], "array");
    assert_eq!(v["detected"]["record_count_sampled"], 2);
    assert_eq!(
        v["detected"]["fields"][0]["types"],
        serde_json::json!(["integer", "number"])
    );

    let nd = file(&d, "a.ndjson", "{\"a\":1}\n{\"a\":true}\n");
    let v = call(&nd, "schema", &[]).json();
    assert_eq!(v["format"], "ndjson");
    assert_eq!(v["detected"]["record_count_sampled"], 2);

    let tsv = file(&d, "a.tsv", "x\ty\n1\t2\n");
    assert_eq!(call(&tsv, "schema", &[]).json()["format"], "tsv");
    let txt = file(&d, "a.txt", "hello\nworld\n");
    let v = call(&txt, "schema", &[]).json();
    assert_eq!(v["format"], "text");
    assert_eq!(v["detected"]["line_count_sampled"], 2);

    let v = call(&csv, "schema", &[("format", "TEXT")]).json();
    assert_eq!(v["format"], "text");
    let v = call(&csv, "schema", &[("max_bytes", "15")]).json();
    assert_eq!(v["byte_sample"], 15);
    assert_eq!(v["detected"]["row_count_sampled"], 0);
}

#[test]
fn schema_errors() {
    let d = tmp();
    let txt = file(&d, "a.txt", "hello\n");
    call(&txt, "schema", &[("format", "xml")]).fails(Code::InvalidArg);
    call(&txt, "schema", &[("max_rows", "0")]).fails(Code::InvalidArg);
    call(&txt, "schema", &[("max_bytes", "z")]).fails(Code::InvalidArg);
    call(&txt, "schema", &[("format", "json")]).fails(Code::ParseError);
    call(&txt, "schema", &[("format", "ndjson")]).fails(Code::ParseError);
    let empty = file(&d, "e", "");
    call(&empty, "schema", &[("format", "csv")]).fails(Code::ParseError);
    call(&d.path().join("missing"), "schema", &[]).fails(Code::NotFound);
    call(d.path(), "schema", &[]).fails(Code::IsADirectory);
}

// --- tail ------------------------------------------------------------------

#[test]
fn tail_lines_and_bytes() {
    let d = tmp();
    let content: String = (1..=15).map(|i| format!("l{i}\n")).collect();
    let p = file(&d, "f", &content);
    let o = call(&p, "tail", &[]);
    o.ok();
    assert_eq!(
        o.out,
        (6..=15).map(|i| format!("l{i}\n")).collect::<String>()
    );
    assert_eq!(call(&p, "tail", &[("lines", "2")]).out, "l14\nl15\n");
    assert_eq!(call(&p, "tail", &[("bytes", "4")]).out, "l15\n");
    assert_eq!(call(&p, "tail", &[("lines", "100")]).out, content);
    let nonl = file(&d, "g", "a\nb\nc");
    assert_eq!(call(&nonl, "tail", &[("lines", "2")]).out, "b\nc");
    let empty = file(&d, "e", "");
    assert_eq!(call(&empty, "tail", &[]).ok().out, "");
}

#[test]
fn tail_errors() {
    let d = tmp();
    let p = file(&d, "f", "x\n");
    call(&p, "tail", &[("lines", "1"), ("bytes", "1")]).fails(Code::InvalidArg);
    call(&p, "tail", &[("lines", "0")]).fails(Code::InvalidArg);
    call(&p, "tail", &[("bytes", "0")]).fails(Code::InvalidArg);
    call(&p, "tail", &[("lines", "ten")]).fails(Code::InvalidArg);
    call(&p, "tail", &[("timeout_ms", "100")]).fails(Code::InvalidArg);
    call(&p, "tail", &[("follow", "true"), ("timeout_ms", "x")]).fails(Code::InvalidArg);
    call(&d.path().join("missing"), "tail", &[]).fails(Code::NotFound);
    call(d.path(), "tail", &[]).fails(Code::IsADirectory);
    let fifo = d.path().join("fifo");
    mkfifo(&fifo);
    call(&fifo, "tail", &[]).fails(Code::NotAFile);
}

#[test]
fn tail_follow_prints_appended_data_until_timeout() {
    let d = tmp();
    let p = file(&d, "f", "first\n");
    let p2 = p.clone();
    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        let mut f = fs::OpenOptions::new().append(true).open(&p2).unwrap();
        std::io::Write::write_all(&mut f, b"second\n").unwrap();
    });
    let start = std::time::Instant::now();
    let o = call(&p, "tail", &[("follow", "true"), ("timeout_ms", "1200")]);
    writer.join().unwrap();
    o.ok();
    assert_eq!(o.out, "first\nsecond\n");
    assert!(start.elapsed() >= Duration::from_millis(1100));
}

#[test]
fn tail_follow_rereads_a_truncated_file() {
    let d = tmp();
    let p = file(&d, "f", "old content\n");
    let p2 = p.clone();
    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        fs::write(&p2, "new\n").unwrap();
    });
    let o = call(&p, "tail", &[("follow", "true"), ("timeout_ms", "1000")]);
    writer.join().unwrap();
    assert_eq!(o.ok().out, "old content\nnew\n");
}

#[test]
fn tail_follow_fails_when_the_file_disappears() {
    let d = tmp();
    let p = file(&d, "f", "x\n");
    let p2 = p.clone();
    let remover = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        fs::remove_file(&p2).unwrap();
    });
    let o = call(&p, "tail", &[("follow", "true"), ("timeout_ms", "3000")]);
    remover.join().unwrap();
    o.fails(Code::NotFound);
}

// --- grep ------------------------------------------------------------------

const LOG: &str = "a\nERROR disk full\nb\nerror again\nc\nd\n";

#[test]
fn grep_matches_and_options() {
    let d = tmp();
    let p = file(&d, "log", LOG);
    assert_eq!(
        call(&p, "grep", &[("pattern", "error")]).ok().out,
        "4:error again\n"
    );
    assert_eq!(
        call(&p, "grep", &[("pattern", "error"), ("ignore_case", "true")]).out,
        "2:ERROR disk full\n4:error again\n"
    );
    assert_eq!(
        call(&p, "grep", &[("pattern", "^[a-d]$"), ("max", "2")]).out,
        "1:a\n3:b\n"
    );
    assert_eq!(
        call(
            &p,
            "grep",
            &[
                ("pattern", "r"),
                ("invert", "true"),
                ("ignore_case", "true")
            ]
        )
        .out,
        "1:a\n3:b\n5:c\n6:d\n"
    );
    assert_eq!(
        call(
            &p,
            "grep",
            &[("pattern", "again"), ("line_numbers", "false")]
        )
        .out,
        "error again\n"
    );
    let dots = file(&d, "dots", "a.c\nabc\n");
    assert_eq!(
        call(&dots, "grep", &[("pattern", "a.c")]).out,
        "1:a.c\n2:abc\n"
    );
    assert_eq!(
        call(&dots, "grep", &[("pattern", "a.c"), ("regex", "false")]).out,
        "1:a.c\n"
    );
    assert_eq!(
        call(
            &dots,
            "grep",
            &[("pattern", "A.C"), ("regex", "false"), ("ignore_case", "1")]
        )
        .out,
        "1:a.c\n"
    );
}

#[test]
fn grep_context_lines() {
    let d = tmp();
    let p = file(&d, "log", LOG);
    let o = call(
        &p,
        "grep",
        &[("pattern", "disk"), ("before", "1"), ("after", "1")],
    );
    assert_eq!(o.ok().out, "-1:a\n:2:ERROR disk full\n-3:b\n");
    // After-context still follows the last match allowed by max.
    let o = call(
        &p,
        "grep",
        &[
            ("pattern", "error"),
            ("ignore_case", "true"),
            ("max", "1"),
            ("after", "2"),
        ],
    );
    assert_eq!(o.out, ":2:ERROR disk full\n-3:b\n-4:error again\n");
    let o = call(
        &p,
        "grep",
        &[("pattern", "c"), ("before", "2"), ("line_numbers", "false")],
    );
    assert_eq!(o.out, "b\nerror again\nc\n");
}

#[test]
fn grep_json_format() {
    let d = tmp();
    let p = file(&d, "log", LOG);
    let v = call(
        &p,
        "grep",
        &[
            ("pattern", "error"),
            ("format", "json"),
            ("ignore_case", "true"),
        ],
    )
    .json();
    let a = v.as_array().unwrap();
    assert_eq!(a.len(), 2);
    assert_eq!(a[0]["line"], 2);
    assert_eq!(a[0]["text"], "ERROR disk full");
    assert_eq!(a[0]["matched"], true);
    assert_eq!(a[0]["path"], p.to_string_lossy().as_ref());
    for k in ["before", "after", "line_numbers"] {
        call(
            &p,
            "grep",
            &[("pattern", "e"), ("format", "json"), (k, "1")],
        )
        .fails(Code::InvalidArg);
    }
}

#[test]
fn grep_keeps_line_numbers_across_non_utf8_lines() {
    let d = tmp();
    let p = d.path().join("f");
    fs::write(&p, b"ok\n\xff\xfe bad\r\nneedle\n").unwrap();
    assert_eq!(
        call(&p, "grep", &[("pattern", "needle")]).ok().out,
        "3:needle\n"
    );
    assert_eq!(
        call(&p, "grep", &[("pattern", "bad$")]).ok().out,
        "2:\u{fffd}\u{fffd} bad\n"
    );
}

#[test]
fn grep_errors() {
    let d = tmp();
    let p = file(&d, "log", LOG);
    call(&p, "grep", &[]).fails(Code::InvalidArg);
    call(&p, "grep", &[("pattern", "(")]).fails(Code::InvalidArg);
    call(&p, "grep", &[("pattern", "a"), ("max", "0")]).fails(Code::InvalidArg);
    call(&p, "grep", &[("pattern", "a"), ("before", "-1")]).fails(Code::InvalidArg);
    call(&p, "grep", &[("pattern", "a"), ("format", "xml")]).fails(Code::InvalidArg);
    call(&p, "grep", &[("pattern", "a"), ("max_count", "1")]).fails(Code::InvalidArg);
    let o = call(&p, "grep", &[("pattern", "zzz")]);
    o.fails(Code::NoMatch);
    assert_eq!(o.st.exit_code(), 1);
    assert!(o.out.is_empty());
    call(&d.path().join("missing"), "grep", &[("pattern", "a")]).fails(Code::NotFound);
    call(d.path(), "grep", &[("pattern", "a")]).fails(Code::IsADirectory);
}

// --- find ------------------------------------------------------------------

fn tree() -> TempDir {
    let d = tmp();
    file(&d, "index.html", "x");
    file(&d, "about.html", "y");
    file(&d, "css/site.css", "z");
    file(&d, "css/deep/more.html", "w");
    file(&d, ".hidden.html", "h");
    file(&d, ".git/config", "c");
    symlink("index.html", d.path().join("link.html")).unwrap();
    d
}

fn names(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|e| {
            let p = e["path"].as_str().unwrap();
            p.rsplit('/').next().unwrap().to_string()
        })
        .collect()
}

#[test]
fn find_filters() {
    let d = tree();
    let all = call(d.path(), "find", &[]).json();
    let n = names(&all)[1..].to_vec();
    assert!(n.contains(&"site.css".to_string()));
    assert!(
        !n.iter().any(|x| x.starts_with('.') || x == "config"),
        "{n:?}"
    );
    let e = &all.as_array().unwrap()[0];
    assert_eq!(e["depth"], 0);
    assert_eq!(e["type"], "dir");
    assert!(e["path"].as_str().unwrap().starts_with('/'));
    for k in ["size", "mode", "mtime", "is_hidden"] {
        assert!(e.get(k).is_some());
    }

    let v = call(d.path(), "find", &[("name", "*.html"), ("type", "file")]).json();
    assert_eq!(names(&v), vec!["about.html", "more.html", "index.html"]);
    let v = call(d.path(), "find", &[("name", "*.html"), ("max_depth", "1")]).json();
    assert_eq!(names(&v), vec!["about.html", "index.html", "link.html"]);
    let v = call(d.path(), "find", &[("type", "symlink")]).json();
    assert_eq!(names(&v), vec!["link.html"]);
    assert_eq!(v[0]["type"], "symlink");
    let v = call(d.path(), "find", &[("type", "dir")]).json();
    assert_eq!(names(&v).len(), 3);
    let v = call(d.path(), "find", &[("limit", "2")]).json();
    assert_eq!(v.as_array().unwrap().len(), 2);
    let v = call(d.path(), "find", &[("include_hidden", "true")]).json();
    let n = names(&v);
    assert!(n.contains(&"config".to_string()) && n.contains(&".hidden.html".to_string()));
    let v = call(
        d.path(),
        "find",
        &[("follow_symlinks", "true"), ("name", "link.html")],
    )
    .json();
    assert_eq!(v[0]["type"], "file");
    let v = call(&d.path().join("index.html"), "find", &[]).json();
    assert_eq!(names(&v), vec!["index.html"]);
}

#[test]
fn find_hidden_root_is_walked() {
    let d = tmp();
    file(&d, ".cfg/a", "1");
    let v = call(&d.path().join(".cfg"), "find", &[("type", "file")]).json();
    assert_eq!(names(&v), vec!["a"]);
}

#[test]
fn find_errors() {
    let d = tree();
    call(d.path(), "find", &[("type", "socket")]).fails(Code::InvalidArg);
    call(d.path(), "find", &[("name", "[")]).fails(Code::InvalidArg);
    call(d.path(), "find", &[("max_depth", "x")]).fails(Code::InvalidArg);
    call(d.path(), "find", &[("limit", "-3")]).fails(Code::InvalidArg);
    call(&d.path().join("missing"), "find", &[]).fails(Code::NotFound);
    if !is_root() {
        let locked = d.path().join("css/deep");
        chmod(&locked, 0o000);
        let o = call(d.path(), "find", &[]);
        chmod(&locked, 0o755);
        o.fails(Code::Partial);
        assert!(names(&o.json()).contains(&"site.css".to_string()));
        assert!(o.err.contains("Warning:"), "{}", o.err);
    }
}

#[test]
fn find_symlink_loop_is_a_warning_only() {
    let d = tmp();
    file(&d, "a/f", "x");
    symlink("..", d.path().join("a/up")).unwrap();
    let o = call(d.path(), "find", &[("follow_symlinks", "true")]);
    o.ok();
    assert!(o.err.contains("Warning"), "{}", o.err);
}

// --- watch -----------------------------------------------------------------

fn after_ms(ms: u64, f: impl FnOnce() + Send + 'static) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(ms));
        f()
    })
}

#[test]
fn watch_reports_create() {
    let d = tmp();
    let dir = d.path().to_path_buf();
    let t = after_ms(400, move || fs::write(dir.join("new.txt"), "x").unwrap());
    let o = call(
        d.path(),
        "watch",
        &[("events", "create"), ("timeout_ms", "10000")],
    );
    t.join().unwrap();
    o.ok();
    let v = o.json();
    assert_eq!(v["event"], "create");
    assert!(v["path"].as_str().unwrap().ends_with("new.txt"));
    assert!(v.get("timestamp").is_some() && v.get("kind").is_some());
}

#[test]
fn watch_reports_modify_of_a_file() {
    let d = tmp();
    let p = file(&d, "conf", "a");
    let p2 = p.clone();
    let t = after_ms(400, move || fs::write(&p2, "b").unwrap());
    let o = call(
        &p,
        "watch",
        &[("events", "modify"), ("timeout_ms", "10000")],
    );
    t.join().unwrap();
    let v = o.ok().json();
    assert_eq!(v["event"], "modify");
    assert_eq!(v["kind"], "data_change");
}

#[test]
fn watch_reports_rename_and_remove() {
    let d = tmp();
    let a = file(&d, "a", "x");
    let dir = d.path().to_path_buf();
    let t = after_ms(400, move || {
        fs::rename(dir.join("a"), dir.join("b")).unwrap();
        fs::remove_file(dir.join("b")).unwrap();
    });
    let o = call(
        d.path(),
        "watch",
        &[
            ("events", "rename,remove"),
            ("max_events", "3"),
            ("timeout_ms", "10000"),
        ],
    );
    t.join().unwrap();
    o.ok();
    let events: Vec<String> = o
        .out
        .lines()
        .map(|l| {
            serde_json::from_str::<Value>(l).unwrap()["event"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(events, vec!["rename", "rename", "remove"], "{}", o.out);
    drop(a);
}

#[test]
fn watch_times_out_quietly() {
    let d = tmp();
    let start = std::time::Instant::now();
    let o = call(d.path(), "watch", &[("timeout_ms", "300")]);
    assert_eq!(o.ok().out, "");
    assert!(start.elapsed() < Duration::from_secs(3));
}

#[test]
fn watch_errors() {
    let d = tmp();
    call(d.path(), "watch", &[("events", "open")]).fails(Code::InvalidArg);
    call(d.path(), "watch", &[("events", ",")]).fails(Code::InvalidArg);
    call(d.path(), "watch", &[("max_events", "0")]).fails(Code::InvalidArg);
    call(d.path(), "watch", &[("timeout_ms", "soon")]).fails(Code::InvalidArg);
    call(&d.path().join("missing"), "watch", &[("timeout_ms", "100")]).fails(Code::NotFound);
}

// --- hashing ---------------------------------------------------------------

const ABC: [(&str, &str); 5] = [
    ("md5", "900150983cd24fb0d6963f7d28e17f72"),
    ("sha1", "a9993e364706816aba3e25717850c26c9cd0d89d"),
    (
        "sha256",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ),
    (
        "sha512",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    ),
    (
        "blake3",
        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
    ),
];

#[test]
fn fixed_hash_verbs() {
    let d = tmp();
    let p = file(&d, "abc", "abc");
    for (algo, hex) in &ABC[..4] {
        let v = call(&p, algo, &[]).json();
        assert_eq!(v["algorithm"], *algo);
        assert_eq!(v["hash"], *hex);
        assert_eq!(v["size"], 3);
        assert_eq!(v["path"], p.to_string_lossy().as_ref());
    }
}

#[test]
fn hash_verb_algorithms() {
    let d = tmp();
    let p = file(&d, "abc", "abc");
    let v = call(&p, "hash", &[]).json();
    assert_eq!(v["algo"], "sha256");
    assert_eq!(v["hash_hex"], ABC[2].1);
    assert_eq!(v["size_bytes"], 3);
    for (algo, hex) in ABC {
        let v = call(&p, "hash", &[("algo", &algo.to_uppercase())]).json();
        assert_eq!(v["algo"], algo);
        assert_eq!(v["hash_hex"], hex);
    }
}

#[test]
fn hash_errors() {
    let d = tmp();
    let p = file(&d, "abc", "abc");
    let o = call(&p, "hash", &[("algo", "crc32")]);
    o.fails(Code::InvalidArg);
    assert_eq!(o.st.exit_code(), 2);
    for verb in ["md5", "sha1", "sha256", "sha512", "hash"] {
        call(&d.path().join("missing"), verb, &[]).fails(Code::NotFound);
        call(d.path(), verb, &[]).fails(Code::IsADirectory);
        call(&p, verb, &[("bogus", "1")]).fails(Code::InvalidArg);
    }
    let fifo = d.path().join("fifo");
    mkfifo(&fifo);
    call(&fifo, "sha256", &[]).fails(Code::NotAFile);
}

#[test]
fn hashing_refuses_files_over_10_gib() {
    let d = tmp();
    let p = d.path().join("sparse");
    let f = fs::File::create(&p).unwrap();
    f.set_len(super::digest::MAX_HASH_SIZE + 1).unwrap();
    for verb in ["md5", "sha1", "sha256", "sha512", "hash"] {
        call(&p, verb, &[]).fails(Code::TooLarge);
    }
    let o = call(&p, "verify", &[]);
    o.fails(Code::TooLarge);
    assert_eq!(o.json()["verified"], false);
}

#[test]
fn verify_matches_and_mismatches() {
    let d = tmp();
    let p = file(&d, "abc", "abc");
    let sha = ABC[2].1;
    let v = call(&p, "verify", &[("expected", sha)]).json();
    assert_eq!(v["verified"], true);
    assert_eq!(v["match"], true);
    assert_eq!(v["digest"], sha);
    assert_eq!(v["error"], Value::Null);
    call(&p, "verify", &[("expected", &sha.to_uppercase())]).ok();
    call(&p, "verify", &[("size", "3"), ("algo", "md5")]).ok();
    call(&p, "verify", &[]).ok();
    for (algo, hex) in ABC {
        call(&p, "verify", &[("algo", algo), ("expected", hex)]).ok();
    }
    let other = "0".repeat(64);
    let any = format!("{other};{sha}");
    call(&p, "verify", &[("expected_any", &any)]).ok();
    call(
        &p,
        "verify",
        &[("expected", &other), ("expected_any", &any)],
    )
    .ok();

    let o = call(&p, "verify", &[("expected", &other)]);
    o.fails(Code::VerifyFailed);
    let v = o.json();
    assert_eq!(v["verified"], false);
    assert_eq!(v["match"], false);
    assert_eq!(v["size_match"], true);
    let o = call(&p, "verify", &[("size", "4")]);
    o.fails(Code::VerifyFailed);
    assert_eq!(o.json()["size_match"], false);
    call(&p, "verify", &[("expected_any", &other)]).fails(Code::VerifyFailed);
}

#[test]
fn verify_errors() {
    let d = tmp();
    let p = file(&d, "abc", "abc");
    for a in [
        ("algo", "crc32"),
        ("expected", "abc"),
        ("expected", &"z".repeat(64)),
        ("size", "-1"),
        ("size", "big"),
        ("expected_any", ";;"),
    ] {
        let o = call(&p, "verify", &[a]);
        o.fails(Code::InvalidArg);
        assert!(o.out.is_empty());
    }
    call(&p, "verify", &[("algo", "md5"), ("expected", ABC[2].1)]).fails(Code::InvalidArg);
    let o = call(&d.path().join("missing"), "verify", &[]);
    o.fails(Code::NotFound);
    let v = o.json();
    assert_eq!(v["verified"], false);
    assert!(v["error"].as_str().unwrap().starts_with("NOT_FOUND"));
    call(d.path(), "verify", &[]).fails(Code::IsADirectory);
}

// --- write / append --------------------------------------------------------

#[test]
fn write_creates_and_replaces() {
    let d = tmp();
    let p = d.path().join("out.txt");
    let v = call(&p, "write", &[("data", "hello world")]).json();
    assert_eq!(
        v,
        serde_json::json!({"written": true, "bytes": 11, "path": p.display().to_string()})
    );
    assert_eq!(fs::read_to_string(&p).unwrap(), "hello world");
    call(&p, "write", &[("data", "")]).ok();
    assert_eq!(fs::read_to_string(&p).unwrap(), "");
    let o = call_with_stdin(&p, "write", &[], b"from stdin");
    assert_eq!(o.ok().json()["bytes"], 10);
    assert_eq!(fs::read_to_string(&p).unwrap(), "from stdin");
    // No temporary files are left behind.
    assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1);
}

#[test]
fn write_modes() {
    let d = tmp();
    let p = d.path().join("m");
    call(&p, "write", &[("data", "x"), ("mode", "600")]).ok();
    assert_eq!(mode_of(&p), 0o600);
    // Replacing keeps the existing permissions unless mode= is given.
    chmod(&p, 0o640);
    call(&p, "write", &[("data", "y")]).ok();
    assert_eq!(mode_of(&p), 0o640);
    call(&p, "write", &[("data", "z"), ("mode", "0755")]).ok();
    assert_eq!(mode_of(&p), 0o755);
}

#[test]
fn write_create_false_and_parents() {
    let d = tmp();
    let p = d.path().join("missing");
    call(&p, "write", &[("data", "x"), ("create", "false")]).fails(Code::NotFound);
    assert!(!p.exists());
    let existing = file(&d, "e", "old");
    call(&existing, "write", &[("data", "new"), ("create", "false")]).ok();
    assert_eq!(fs::read_to_string(&existing).unwrap(), "new");
    let nested = d.path().join("a/b/c.txt");
    call(&nested, "write", &[("data", "x")]).ok();
    assert_eq!(fs::read_to_string(&nested).unwrap(), "x");
}

#[test]
fn write_errors_have_no_side_effects() {
    let d = tmp();
    let p = file(&d, "f", "keep");
    for a in [
        ("mode", "999"),
        ("mode", "abc"),
        ("mode", "17777"),
        ("mode", ""),
        ("create", "nah"),
    ] {
        call(&p, "write", &[("data", "x"), a]).fails(Code::InvalidArg);
        assert_eq!(fs::read_to_string(&p).unwrap(), "keep");
    }
    let o = call_with_stdin(&p, "write", &[("mode", "9")], b"stdin data");
    o.fails(Code::InvalidArg);
    assert_eq!(fs::read_to_string(&p).unwrap(), "keep");
    call(d.path(), "write", &[("data", "x")]).fails(Code::IsADirectory);
    call(&p.join("below"), "write", &[("data", "x")]).fails(Code::NotFound);
    let fifo = d.path().join("fifo");
    mkfifo(&fifo);
    call(&fifo, "write", &[("data", "x")]).fails(Code::NotAFile);
    if !is_root() {
        let ro = d.path().join("ro");
        fs::create_dir(&ro).unwrap();
        chmod(&ro, 0o555);
        let o = call(&ro.join("f"), "write", &[("data", "x")]);
        chmod(&ro, 0o755);
        o.fails(Code::PermissionDenied);
        assert_eq!(o.st.exit_code(), 1);
    }
}

#[test]
fn append_adds_data() {
    let d = tmp();
    let p = file(&d, "log", "a");
    let v = call(&p, "append", &[("data", "bc")]).json();
    assert_eq!(
        v,
        serde_json::json!({"appended": true, "bytes": 2, "path": p.display().to_string()})
    );
    assert_eq!(fs::read_to_string(&p).unwrap(), "abc");
    call_with_stdin(&p, "append", &[], b"\nd").ok();
    assert_eq!(fs::read_to_string(&p).unwrap(), "abc\nd");
    let n = d.path().join("sub/new");
    call(&n, "append", &[("data", "x")]).ok();
    assert_eq!(fs::read_to_string(&n).unwrap(), "x");
    call(&p, "append", &[("data", "e"), ("create", "false")]).ok();
    assert_eq!(fs::read_to_string(&p).unwrap(), "abc\nde");
}

#[test]
fn append_errors() {
    let d = tmp();
    let missing = d.path().join("missing");
    call(&missing, "append", &[("data", "x"), ("create", "false")]).fails(Code::NotFound);
    assert!(!missing.exists());
    let p = file(&d, "f", "keep");
    call(&p, "append", &[("data", "x"), ("create", "?")]).fails(Code::InvalidArg);
    assert_eq!(fs::read_to_string(&p).unwrap(), "keep");
    call(d.path(), "append", &[("data", "x")]).fails(Code::IsADirectory);
    if !is_root() {
        chmod(&p, 0o444);
        call(&p, "append", &[("data", "x")]).fails(Code::PermissionDenied);
        assert_eq!(fs::read_to_string(&p).unwrap(), "keep");
    }
}

// --- replace ---------------------------------------------------------------

#[test]
fn replace_literal_and_regex() {
    let d = tmp();
    let p = file(&d, "conf", "port=8080\nalt=8080\n");
    chmod(&p, 0o600);
    let v = call(
        &p,
        "replace",
        &[("pattern", "8080"), ("replacement", "9090")],
    )
    .json();
    assert_eq!(v["replacements"], 2);
    assert_eq!(v["changed"], true);
    assert_eq!(v["dry_run"], false);
    assert_eq!(v["regex"], false);
    assert_eq!(v["count_limit"], Value::Null);
    assert_eq!(v["original_bytes"], 19);
    assert_eq!(fs::read_to_string(&p).unwrap(), "port=9090\nalt=9090\n");
    assert_eq!(mode_of(&p), 0o600, "mode kept");

    let v = call(
        &p,
        "replace",
        &[
            ("pattern", r"(\w+)=(\d+)"),
            ("replacement", "$2=$1"),
            ("regex", "true"),
            ("count", "1"),
        ],
    )
    .json();
    assert_eq!(v["replacements"], 1);
    assert_eq!(v["count_limit"], 1);
    assert_eq!(fs::read_to_string(&p).unwrap(), "9090=port\nalt=9090\n");

    call(
        &p,
        "replace",
        &[("pattern", "=port"), ("replacement", r"\n\tX")],
    )
    .ok();
    assert_eq!(fs::read_to_string(&p).unwrap(), "9090\n\tX\nalt=9090\n");

    let v = call(
        &p,
        "replace",
        &[("pattern", "nothere"), ("replacement", "y")],
    )
    .json();
    assert_eq!(v["replacements"], 0);
    assert_eq!(v["changed"], false);
}

#[test]
fn replace_dry_run_and_backup() {
    let d = tmp();
    let p = file(&d, "conf", "a a a");
    let v = call(
        &p,
        "replace",
        &[("pattern", "a"), ("replacement", "b"), ("dry_run", "true")],
    )
    .json();
    assert_eq!(v["replacements"], 3);
    assert_eq!(v["changed"], false);
    assert_eq!(v["dry_run"], true);
    assert_eq!(fs::read_to_string(&p).unwrap(), "a a a");
    call(
        &p,
        "replace",
        &[
            ("pattern", "a"),
            ("replacement", "b"),
            ("count", "2"),
            ("backup", ".bak"),
        ],
    )
    .ok();
    assert_eq!(fs::read_to_string(&p).unwrap(), "b b a");
    assert_eq!(
        fs::read_to_string(d.path().join("conf.bak")).unwrap(),
        "a a a"
    );
}

#[test]
fn replace_backup_refuses_planted_symlink() {
    let d = tmp();
    let p = file(&d, "app.conf", "ORIGINAL CONTENT\n");
    let victim = file(&d, "victim", "victim secret\n");
    chmod(&victim, 0o600);
    symlink(&victim, d.path().join("app.conf.bak")).unwrap();
    let o = call(
        &p,
        "replace",
        &[
            ("pattern", "ORIGINAL"),
            ("replacement", "NEW"),
            ("backup", ".bak"),
        ],
    );
    assert!(!o.st.ok);
    assert!(o.out.is_empty(), "nothing reported as changed");
    assert_eq!(fs::read_to_string(&victim).unwrap(), "victim secret\n");
    assert_eq!(mode_of(&victim), 0o600);
    assert_eq!(fs::read_to_string(&p).unwrap(), "ORIGINAL CONTENT\n");
    // A dangling link is refused too and creates nothing.
    let d2 = tmp();
    let p2 = file(&d2, "app.conf", "ORIGINAL\n");
    let created = d2.path().join("created_by_follow");
    symlink(&created, d2.path().join("app.conf.bak")).unwrap();
    assert!(
        !call(
            &p2,
            "replace",
            &[
                ("pattern", "ORIGINAL"),
                ("replacement", "N"),
                ("backup", ".bak")
            ]
        )
        .st
        .ok
    );
    assert!(!created.exists());
}

#[test]
fn replace_errors_have_no_side_effects() {
    let d = tmp();
    let p = file(&d, "conf", "abc");
    for a in [
        vec![("replacement", "x")],
        vec![("pattern", "a")],
        vec![("pattern", ""), ("replacement", "x")],
        vec![("pattern", "("), ("replacement", "x"), ("regex", "true")],
        vec![("pattern", "a"), ("replacement", "x"), ("count", "0")],
        vec![("pattern", "a"), ("replacement", "x"), ("count", "x")],
        vec![("pattern", "a"), ("replacement", "x"), ("backup", "")],
        vec![
            ("pattern", "a"),
            ("replacement", "x"),
            ("backup", "/../evil"),
        ],
        vec![
            ("pattern", "a"),
            ("replacement", "x"),
            ("dry_run", "perhaps"),
        ],
    ] {
        let o = call(&p, "replace", &a);
        o.fails(Code::InvalidArg);
        assert!(o.out.is_empty());
        assert_eq!(fs::read_to_string(&p).unwrap(), "abc", "{a:?}");
    }
    let bin = d.path().join("bin");
    fs::write(&bin, b"a\xff").unwrap();
    call(&bin, "replace", &[("pattern", "a"), ("replacement", "b")]).fails(Code::NotUtf8);
    assert_eq!(fs::read(&bin).unwrap(), b"a\xff");
    call(
        &d.path().join("missing"),
        "replace",
        &[("pattern", "a"), ("replacement", "b")],
    )
    .fails(Code::NotFound);
    call(
        d.path(),
        "replace",
        &[("pattern", "a"), ("replacement", "b")],
    )
    .fails(Code::IsADirectory);
}

// --- copy ------------------------------------------------------------------

#[test]
fn copy_basic_and_overwrite() {
    let d = tmp();
    let src = file(&d, "src", "data");
    chmod(&src, 0o640);
    let dst = d.path().join("dst");
    let o = call(&src, "copy", &[("to", &dst.to_string_lossy())]);
    assert_eq!(o.ok().out, "");
    assert_eq!(fs::read_to_string(&dst).unwrap(), "data");
    assert_eq!(mode_of(&dst), 0o640);
    fs::write(&src, "new").unwrap();
    call(&src, "copy", &[("to", &dst.to_string_lossy())]).fails(Code::AlreadyExists);
    assert_eq!(fs::read_to_string(&dst).unwrap(), "data");
    call(
        &src,
        "copy",
        &[("to", &dst.to_string_lossy()), ("overwrite", "true")],
    )
    .ok();
    assert_eq!(fs::read_to_string(&dst).unwrap(), "new");
    assert_eq!(
        fs::read_dir(d.path()).unwrap().count(),
        2,
        "no temp files left"
    );
}

#[test]
fn copy_preserve_mode_and_times() {
    let d = tmp();
    let src = file(&d, "src", "data");
    chmod(&src, 0o604);
    let old = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    fs::File::options()
        .write(true)
        .open(&src)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(old).set_accessed(old))
        .unwrap();
    let a = d.path().join("a");
    call(
        &src,
        "copy",
        &[("to", &a.to_string_lossy()), ("preserve_mode", "false")],
    )
    .ok();
    assert_ne!(mode_of(&a), 0o604);
    assert_ne!(fs::metadata(&a).unwrap().modified().unwrap(), old);
    let b = d.path().join("b");
    call(
        &src,
        "copy",
        &[("to", &b.to_string_lossy()), ("preserve_times", "true")],
    )
    .ok();
    assert_eq!(mode_of(&b), 0o604);
    assert_eq!(fs::metadata(&b).unwrap().modified().unwrap(), old);
    assert_eq!(fs::metadata(&b).unwrap().accessed().unwrap(), old);
}

#[test]
fn copy_errors() {
    let d = tmp();
    let src = file(&d, "src", "data");
    let to = |p: &Path| p.to_string_lossy().into_owned();
    call(&src, "copy", &[]).fails(Code::InvalidArg);
    call(&src, "copy", &[("to", "")]).fails(Code::InvalidArg);
    call(&src, "copy", &[("to", "x"), ("preserve_times", "x")]).fails(Code::InvalidArg);
    call(
        &d.path().join("missing"),
        "copy",
        &[("to", &to(&d.path().join("x")))],
    )
    .fails(Code::NotFound);
    call(d.path(), "copy", &[("to", &to(&d.path().join("x")))]).fails(Code::IsADirectory);
    let sub = d.path().join("sub");
    fs::create_dir(&sub).unwrap();
    call(&src, "copy", &[("to", &to(&sub)), ("overwrite", "true")]).fails(Code::IsADirectory);
    call(&src, "copy", &[("to", &to(&d.path().join("no/x")))]).fails(Code::NotFound);
    let fifo = d.path().join("fifo");
    mkfifo(&fifo);
    call(&fifo, "copy", &[("to", &to(&d.path().join("y")))]).fails(Code::NotAFile);
    assert!(!d.path().join("x").exists() && !d.path().join("y").exists());
}

// --- rename / move ---------------------------------------------------------

#[test]
fn rename_file_and_json() {
    let d = tmp();
    let a = file(&d, "old.csv", "1");
    let b = d.path().join("new.csv");
    let v = call(&a, "rename", &[("to", &b.to_string_lossy())]).json();
    assert_eq!(v["renamed"], true);
    assert_eq!(v["from"], a.display().to_string());
    assert_eq!(v["to"], b.display().to_string());
    assert!(v.get("cross_filesystem").is_none());
    assert!(!a.exists());
    assert_eq!(fs::read_to_string(&b).unwrap(), "1");
}

#[test]
fn rename_overwrite_and_parents() {
    let d = tmp();
    let a = file(&d, "a", "A");
    let b = file(&d, "b", "B");
    call(&a, "rename", &[("to", &b.to_string_lossy())]).fails(Code::AlreadyExists);
    assert_eq!(fs::read_to_string(&b).unwrap(), "B");
    call(
        &a,
        "rename",
        &[("to", &b.to_string_lossy()), ("overwrite", "true")],
    )
    .ok();
    assert_eq!(fs::read_to_string(&b).unwrap(), "A");

    // Directory over an existing non-empty directory.
    file(&d, "srcdir/x", "new");
    file(&d, "dstdir/y", "old");
    let (s, t) = (d.path().join("srcdir"), d.path().join("dstdir"));
    call(&s, "rename", &[("to", &t.to_string_lossy())]).fails(Code::AlreadyExists);
    call(
        &s,
        "rename",
        &[("to", &t.to_string_lossy()), ("overwrite", "true")],
    )
    .ok();
    assert!(t.join("x").exists() && !t.join("y").exists() && !s.exists());
    // File over a directory.
    let f = file(&d, "f", "F");
    call(
        &f,
        "rename",
        &[("to", &t.to_string_lossy()), ("overwrite", "true")],
    )
    .ok();
    assert_eq!(fs::read_to_string(&t).unwrap(), "F");

    let deep = d.path().join("p/q/r");
    call(&b, "rename", &[("to", &deep.to_string_lossy())]).fails(Code::NotFound);
    assert!(b.exists() && !d.path().join("p").exists());
    call(
        &b,
        "rename",
        &[("to", &deep.to_string_lossy()), ("create_parents", "true")],
    )
    .ok();
    assert_eq!(fs::read_to_string(&deep).unwrap(), "A");
    let leftovers: Vec<_> = fs::read_dir(d.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".resh_"))
        .collect();
    assert!(leftovers.is_empty());
}

#[test]
fn rename_errors() {
    let d = tmp();
    let a = file(&d, "a", "A");
    call(&a, "rename", &[]).fails(Code::InvalidArg);
    call(&a, "rename", &[("to", "b"), ("atomic", "sure")]).fails(Code::InvalidArg);
    let missing = d.path().join("missing");
    call(&missing, "rename", &[("to", &missing.to_string_lossy())]).fails(Code::NotFound);
    call(&a, "rename", &[("to", &a.to_string_lossy())]).ok();
    assert!(a.exists());
    let dir = d.path().join("dir");
    fs::create_dir(&dir).unwrap();
    call(
        &dir,
        "rename",
        &[("to", &dir.join("sub").to_string_lossy())],
    )
    .fails(Code::Refused);
    call(&a, "rename", &[("to", &a.join("x").to_string_lossy())]).fails(Code::NotFound);
    assert!(dir.exists() && a.exists());
    if !is_root() {
        let ro = d.path().join("ro");
        fs::create_dir(&ro).unwrap();
        chmod(&ro, 0o555);
        let o = call(&a, "rename", &[("to", &ro.join("a").to_string_lossy())]);
        chmod(&ro, 0o755);
        o.fails(Code::PermissionDenied);
        assert!(a.exists());
    }
}

#[test]
fn rename_and_move_across_filesystems() {
    let d = tmp();
    let Some(other) = other_fs_dir(d.path()) else {
        eprintln!("skipped: no second filesystem available");
        return;
    };
    for atomic in ["true", "false"] {
        let src = file(&d, "tree/sub/f", "data");
        symlink("sub/f", d.path().join("tree/link")).unwrap();
        chmod(&d.path().join("tree/sub/f"), 0o640);
        let dest = other.path().join(format!("moved-{atomic}"));
        file(&other, &format!("moved-{atomic}/old"), "old");
        let v = call(
            &d.path().join("tree"),
            "rename",
            &[
                ("to", &dest.to_string_lossy()),
                ("overwrite", "true"),
                ("atomic", atomic),
            ],
        )
        .json();
        assert_eq!(v["cross_filesystem"], true);
        assert!(!d.path().join("tree").exists());
        assert_eq!(fs::read_to_string(dest.join("sub/f")).unwrap(), "data");
        assert_eq!(mode_of(&dest.join("sub/f")), 0o640);
        assert_eq!(
            fs::read_link(dest.join("link")).unwrap(),
            PathBuf::from("sub/f")
        );
        assert!(!dest.join("old").exists());
        drop(src);
    }
    let f = file(&d, "single", "s");
    call(&f, "move", &[("to", &other.path().to_string_lossy())]).ok();
    assert_eq!(
        fs::read_to_string(other.path().join("single")).unwrap(),
        "s"
    );
    assert!(!f.exists());
    let leftovers = fs::read_dir(other.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".resh_"))
        .count();
    assert_eq!(leftovers, 0);
}

#[test]
fn move_into_directory_and_to_path() {
    for verb in ["move", "mv"] {
        let d = tmp();
        let f = file(&d, "report.pdf", "r");
        let reports = d.path().join("reports");
        fs::create_dir(&reports).unwrap();
        let o = call(&f, verb, &[("to", &reports.to_string_lossy())]);
        assert_eq!(o.ok().out, "");
        let moved = reports.join("report.pdf");
        assert_eq!(fs::read_to_string(&moved).unwrap(), "r");
        let q3 = reports.join("q3.pdf");
        call(&moved, verb, &[("to", &q3.to_string_lossy())]).ok();
        assert!(q3.exists() && !moved.exists());
        let other = file(&d, "other", "o");
        call(&other, verb, &[("to", &q3.to_string_lossy())]).fails(Code::AlreadyExists);
        assert_eq!(fs::read_to_string(&q3).unwrap(), "r");
        call(
            &other,
            verb,
            &[("to", &q3.to_string_lossy()), ("overwrite", "yes")],
        )
        .ok();
        assert_eq!(fs::read_to_string(&q3).unwrap(), "o");
    }
}

#[test]
fn move_errors() {
    let d = tmp();
    let f = file(&d, "f", "x");
    call(&f, "move", &[]).fails(Code::InvalidArg);
    call(&f, "move", &[("to", "y"), ("overwrite", "x")]).fails(Code::InvalidArg);
    call(&f, "move", &[("to", "y"), ("create_parents", "true")]).fails(Code::InvalidArg);
    call(
        &d.path().join("missing"),
        "mv",
        &[("to", &d.path().join("z").to_string_lossy())],
    )
    .fails(Code::NotFound);
    call(
        &f,
        "mv",
        &[("to", &d.path().join("no/z").to_string_lossy())],
    )
    .fails(Code::NotFound);
    let dir = d.path().join("dir");
    fs::create_dir(&dir).unwrap();
    call(&dir, "move", &[("to", &dir.to_string_lossy())]).fails(Code::Refused);
    call_url("file://.", "move", &[("to", "/tmp")]).fails(Code::Refused);
    assert!(f.exists() && dir.exists());
}

// --- delete ----------------------------------------------------------------

#[test]
fn delete_files_dirs_and_links() {
    for verb in ["delete", "remove"] {
        let d = tmp();
        let f = file(&d, "f", "x");
        assert_eq!(call(&f, verb, &[]).ok().out, "");
        assert!(!f.exists());
        file(&d, "tree/a/b", "x");
        let t = d.path().join("tree");
        call(&t, verb, &[]).fails(Code::IsADirectory);
        assert!(t.exists());
        call(&t, verb, &[("recursive", "true")]).ok();
        assert!(!t.exists());
        // A symlink to a directory removes only the link.
        let target = d.path().join("target");
        file(&d, "target/keep", "k");
        let link = d.path().join("link");
        symlink(&target, &link).unwrap();
        call(&link, verb, &[]).ok();
        assert!(fs::symlink_metadata(&link).is_err());
        assert!(target.join("keep").exists());
        let dangling = d.path().join("dangling");
        symlink(d.path().join("none"), &dangling).unwrap();
        call(&dangling, verb, &[]).ok();
        assert!(fs::symlink_metadata(&dangling).is_err());
    }
}

#[test]
fn delete_missing_paths() {
    let d = tmp();
    let m = d.path().join("missing");
    call(&m, "delete", &[]).fails(Code::NotFound);
    call(&m, "delete", &[("missing_ok", "true")]).ok();
    call(&m, "delete", &[("force", "true")]).ok();
    call(&m, "delete", &[("missing_ok", "maybe")]).fails(Code::InvalidArg);
}

#[test]
fn delete_refuses_dangerous_paths() {
    for target in [
        "file:///",
        "file://.",
        "file://..",
        "file://../..",
        "file:///tmp/..",
    ] {
        call_url(target, "delete", &[("recursive", "true")]).fails(Code::Refused);
    }
}

#[test]
fn delete_permission_error() {
    if is_root() {
        return;
    }
    let d = tmp();
    let f = file(&d, "sub/f", "x");
    chmod(&d.path().join("sub"), 0o555);
    let o = call(&f, "delete", &[]);
    chmod(&d.path().join("sub"), 0o755);
    o.fails(Code::PermissionDenied);
    assert!(f.exists());
    file(&d, "t/locked/x", "x");
    chmod(&d.path().join("t/locked"), 0o555);
    let o = call(&d.path().join("t"), "delete", &[("recursive", "true")]);
    chmod(&d.path().join("t/locked"), 0o755);
    o.fails(Code::PermissionDenied);
    assert!(o.reason().contains("part of the tree"));
}

// --- chmod / chown ---------------------------------------------------------

#[test]
fn chmod_sets_mode() {
    let d = tmp();
    let f = file(&d, "f", "x");
    for (arg, m) in [("755", 0o755), ("0600", 0o600), ("4755", 0o4755), ("0", 0)] {
        call(&f, "chmod", &[("mode", arg)]).ok();
        assert_eq!(mode_of(&f), m);
    }
    call(d.path(), "chmod", &[("mode", "700")]).ok();
    assert_eq!(mode_of(d.path()), 0o700);
}

#[test]
fn chmod_errors() {
    let d = tmp();
    let f = file(&d, "f", "x");
    chmod(&f, 0o644);
    call(&f, "chmod", &[]).fails(Code::InvalidArg);
    for bad in ["8", "999", "77777", "-1", "rwx", "", "0o755"] {
        call(&f, "chmod", &[("mode", bad)]).fails(Code::InvalidArg);
    }
    assert_eq!(mode_of(&f), 0o644);
    call(&d.path().join("missing"), "chmod", &[("mode", "644")]).fails(Code::NotFound);
    if !is_root() {
        call(Path::new("/etc/hostname"), "chmod", &[("mode", "644")]).fails(Code::PermissionDenied);
    }
}

#[test]
fn chown_to_own_ids_succeeds() {
    let d = tmp();
    let f = file(&d, "f", "x");
    let (uid, gid) = (
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getegid().as_raw(),
    );
    call(&f, "chown", &[("uid", &uid.to_string())]).ok();
    call(
        &f,
        "chown",
        &[("gid", &gid.to_string()), ("recursive", "true")],
    )
    .ok();
    let me = nix::unistd::User::from_uid(nix::unistd::geteuid())
        .unwrap()
        .unwrap();
    call(
        d.path(),
        "chown",
        &[("user", &me.name), ("recursive", "true")],
    )
    .ok();
    assert_eq!(fs::metadata(&f).unwrap().uid(), uid);
}

#[test]
fn chown_errors() {
    let d = tmp();
    let f = file(&d, "f", "x");
    call(&f, "chown", &[]).fails(Code::InvalidArg);
    call(&f, "chown", &[("recursive", "true")]).fails(Code::InvalidArg);
    call(&f, "chown", &[("user", "root"), ("uid", "0")]).fails(Code::InvalidArg);
    call(&f, "chown", &[("group", "root"), ("gid", "0")]).fails(Code::InvalidArg);
    call(&f, "chown", &[("user", "no-such-user-resh")]).fails(Code::InvalidArg);
    call(&f, "chown", &[("group", "no-such-group-resh")]).fails(Code::InvalidArg);
    call(&f, "chown", &[("user", "-root")]).fails(Code::InvalidArg);
    call(&f, "chown", &[("uid", "abc")]).fails(Code::InvalidArg);
    call(&f, "chown", &[("gid", "-5")]).fails(Code::InvalidArg);
    call(&d.path().join("missing"), "chown", &[("uid", "0")]).fails(Code::NotFound);
    if !is_root() {
        let o = call(&f, "chown", &[("uid", "0")]);
        o.fails(Code::PermissionDenied);
        assert_eq!(o.st.exit_code(), 1);
        assert_eq!(
            fs::metadata(&f).unwrap().uid(),
            nix::unistd::geteuid().as_raw()
        );
    }
}

type Calls = Vec<(PathBuf, Option<u32>, Option<u32>, bool)>;

fn chown_mock(path: &Path, pairs: &[(&str, &str)], fail_at: Option<&str>) -> (Out, Calls) {
    let h = handle(&url_of(path));
    let a = args(pairs);
    let mut calls: Calls = Vec::new();
    let res = {
        let o = super::common::Opts::new("chown", &a).unwrap();
        let mut op = |p: &Path, u: Option<u32>, g: Option<u32>, follow: bool| {
            calls.push((p.to_path_buf(), u, g, follow));
            if fail_at.is_some_and(|f| p.ends_with(f)) {
                return Err(std::io::Error::from_raw_os_error(libc::EPERM));
            }
            Ok(())
        };
        h.chown_with(&o, &mut op)
    };
    let st = match res {
        Ok(s) => s,
        Err(e) => super::common::status_of(&e),
    };
    (
        Out {
            st,
            out: String::new(),
            err: String::new(),
        },
        calls,
    )
}

#[test]
fn chown_mock_changes_another_user_recursively_without_following_links() {
    let d = tmp();
    file(&d, "www/index.html", "x");
    file(&d, "www/css/site.css", "y");
    let outside = file(&d, "outside", "o");
    symlink(&outside, d.path().join("www/escape")).unwrap();
    let www = d.path().join("www");
    let (o, calls) = chown_mock(
        &www,
        &[("user", "root"), ("gid", "33"), ("recursive", "true")],
        None,
    );
    o.ok();
    assert_eq!(calls[0], (www.clone(), Some(0), Some(33), true));
    assert_eq!(calls.len(), 5);
    for (p, u, g, follow) in &calls[1..] {
        assert!(p.starts_with(&www));
        assert_eq!((*u, *g, *follow), (Some(0), Some(33), false));
    }
    assert!(calls.iter().any(|c| c.0.ends_with("escape")));
    assert!(!calls.iter().any(|c| c.0 == outside));

    let (_, calls) = chown_mock(&www, &[("uid", "1234")], None);
    assert_eq!(calls, vec![(www.clone(), Some(1234), None, true)]);
}

#[test]
fn chown_mock_reports_partial_failure() {
    let d = tmp();
    file(&d, "www/a", "x");
    file(&d, "www/b", "y");
    let www = d.path().join("www");
    let (o, calls) = chown_mock(&www, &[("uid", "0"), ("recursive", "true")], Some("b"));
    o.fails(Code::PermissionDenied);
    assert!(
        o.reason()
            .contains("2 entries were changed before this failure"),
        "{}",
        o.reason()
    );
    assert_eq!(calls.len(), 3);
}

// --- extended attributes and tags ------------------------------------------

#[test]
fn ea_set_and_get() {
    let d = tmp();
    if !xattrs_supported(&d) {
        eprintln!("skipped: no user xattrs");
        return;
    }
    let f = file(&d, "report.pdf", "x");
    let v = call(
        &f,
        "ea.set",
        &[("name", "user.comment"), ("value", "reviewed")],
    )
    .json();
    assert_eq!(v["mode"], "upsert");
    assert_eq!(v["previous"], Value::Null);
    assert_eq!(v["current"], "reviewed");
    assert_eq!(v["encoding"], "utf-8");
    let v = call(&f, "ea.get", &[("name", "user.comment")]).json();
    assert_eq!(
        v,
        serde_json::json!({"path": f.display().to_string(), "name": "user.comment", "exists": true, "value": "reviewed"})
    );
    let v = call(
        &f,
        "ea.set",
        &[
            ("name", "user.comment"),
            ("value", "final"),
            ("mode", "update"),
        ],
    )
    .json();
    assert_eq!(v["previous"], "reviewed");
    call(
        &f,
        "ea.set",
        &[("name", "user.comment"), ("value", "x"), ("mode", "create")],
    )
    .fails(Code::AlreadyExists);
    call(
        &f,
        "ea.set",
        &[("name", "user.new"), ("value", "x"), ("mode", "update")],
    )
    .fails(Code::AttrNotFound);
    assert!(xattr::get(&f, "user.new").unwrap().is_none());
    call(
        &f,
        "ea.set",
        &[("name", "user.new"), ("value", ""), ("mode", "CREATE")],
    )
    .ok();
    assert_eq!(xattr::get(&f, "user.new").unwrap().unwrap(), b"");
    assert_eq!(xattr::get(&f, "user.comment").unwrap().unwrap(), b"final");

    xattr::set(&f, "user.bin", &[0xff, 0x00]).unwrap();
    let v = call(&f, "ea.get", &[("name", "user.bin")]).json();
    assert_eq!(v["value"], "/wA=");
    assert_eq!(v["encoding"], "base64");
    let v = call(&f, "ea.set", &[("name", "user.bin"), ("value", "t")]).json();
    assert_eq!(v["previous"], "/wA=");
    assert_eq!(v["encoding"], "base64");

    call(&f, "ea.get", &[("name", "user.none")]).fails(Code::AttrNotFound);
    let v = call(
        &f,
        "ea.get",
        &[("name", "user.none"), ("allow_missing", "true")],
    )
    .json();
    assert_eq!(v["exists"], false);
    assert_eq!(v["value"], Value::Null);
}

#[test]
fn ea_errors() {
    let d = tmp();
    let f = file(&d, "f", "x");
    for name in ["", "comment", "user.", "bogus.x"] {
        call(&f, "ea.get", &[("name", name)]).fails(Code::InvalidArg);
        call(&f, "ea.set", &[("name", name), ("value", "v")]).fails(Code::InvalidArg);
    }
    call(&f, "ea.get", &[]).fails(Code::InvalidArg);
    call(&f, "ea.set", &[("name", "user.x")]).fails(Code::InvalidArg);
    call(
        &f,
        "ea.set",
        &[("name", "user.x"), ("value", "v"), ("mode", "replace")],
    )
    .fails(Code::InvalidArg);
    call(&d.path().join("missing"), "ea.get", &[("name", "user.x")]).fails(Code::NotFound);
    call(
        &d.path().join("missing"),
        "ea.set",
        &[("name", "user.x"), ("value", "v")],
    )
    .fails(Code::NotFound);
    // The system namespace has no such attribute handler.
    call(&f, "ea.get", &[("name", "system.resh_test")]).fails(Code::Unsupported);
    call(
        &f,
        "ea.set",
        &[("name", "system.resh_test"), ("value", "v")],
    )
    .fails(Code::Unsupported);
    if !is_root() && xattrs_supported(&d) {
        call(&f, "ea.set", &[("name", "trusted.x"), ("value", "v")]).fails(Code::PermissionDenied);
    }
}

#[test]
fn tags_add_and_remove() {
    let d = tmp();
    if !xattrs_supported(&d) {
        eprintln!("skipped: no user xattrs");
        return;
    }
    let f = file(&d, "report.pdf", "x");
    let v = call(&f, "tag.add", &[("name", "Work,q3")]).json();
    assert_eq!(v["tags"], serde_json::json!(["q3", "work"]));
    let v = call(&f, "tag.add", &[("name", "work,a-b.c_d")]).json();
    assert_eq!(v["tags"], serde_json::json!(["a-b.c_d", "q3", "work"]));
    assert_eq!(
        xattr::get(&f, "user.resh.tags").unwrap().unwrap(),
        b"a-b.c_d,q3,work"
    );
    let v = call(&f, "tag.rm", &[("name", "q3,unknown")]).json();
    assert_eq!(v["tags"], serde_json::json!(["a-b.c_d", "work"]));
    let v = call(&f, "tag.rm", &[("name", "work,a-b.c_d")]).json();
    assert_eq!(v["tags"], serde_json::json!([]));
    assert!(xattr::get(&f, "user.resh.tags").unwrap().is_none());
    call(&f, "tag.rm", &[("name", "x")]).ok();
}

#[test]
fn tag_errors() {
    let d = tmp();
    let f = file(&d, "f", "x");
    for verb in ["tag.add", "tag.rm"] {
        call(&f, verb, &[]).fails(Code::InvalidArg);
        call(&f, verb, &[("name", "a b")]).fails(Code::InvalidArg);
        call(&f, verb, &[("name", ",")]).fails(Code::InvalidArg);
        call(&d.path().join("missing"), verb, &[("name", "a")]).fails(Code::NotFound);
    }
    if xattrs_supported(&d) {
        xattr::set(&f, "user.resh.tags", &[0xff]).unwrap();
        call(&f, "tag.add", &[("name", "a")]).fails(Code::IoError);
        assert_eq!(
            xattr::get(&f, "user.resh.tags").unwrap().unwrap(),
            vec![0xff]
        );
    }
}
