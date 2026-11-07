//! Every file verb through the real `resh` binary: one success case and the
//! main error paths (exit code and `Error: <CODE>:` on stderr). Each test
//! runs in its own temporary directory as the working directory.

use serde_json::Value;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;
use tempfile::TempDir;

struct Run {
    code: i32,
    out: String,
    err: String,
}

impl Run {
    #[track_caller]
    fn ok(&self) -> &Self {
        assert_eq!(self.code, 0, "stderr: {}", self.err);
        self
    }

    #[track_caller]
    fn fails(&self, exit: i32, code: &str) -> &Self {
        assert_eq!(
            self.code, exit,
            "stdout {:?} stderr {:?}",
            self.out, self.err
        );
        assert!(
            self.err.contains(&format!("Error: {code}: ")),
            "expected {code}, stderr {:?}",
            self.err
        );
        self
    }

    #[track_caller]
    fn json(&self) -> Value {
        serde_json::from_str(self.out.trim()).unwrap_or_else(|e| panic!("{e}: {:?}", self.out))
    }
}

fn resh_in(dir: &Path, args: &[&str]) -> Run {
    let out = assert_cmd::cargo::cargo_bin_cmd!("resh")
        .current_dir(dir)
        .env("HOME", dir)
        .args(args)
        .timeout(Duration::from_secs(60))
        .output()
        .unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&out.stdout).into_owned(),
        err: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn setup() -> TempDir {
    let t = TempDir::new().unwrap();
    std::fs::write(t.path().join("users.csv"), "id,name\n1,alice\n2,bob\n").unwrap();
    std::fs::write(t.path().join("app.log"), "a\nERROR one\nb\nerror two\n").unwrap();
    std::fs::create_dir(t.path().join("dir")).unwrap();
    std::fs::write(t.path().join("dir/x.html"), "x").unwrap();
    t
}

fn xattrs_supported(dir: &Path) -> bool {
    let p = dir.join(".probe");
    std::fs::write(&p, "").unwrap();
    let ok = xattr::set(&p, "user.resh_probe", b"1").is_ok();
    std::fs::remove_file(&p).unwrap();
    ok
}

fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

#[test]
fn read() {
    let t = setup();
    let r = resh_in(t.path(), &["file://users.csv.read"]);
    assert_eq!(r.ok().out, "id,name\n1,alice\n2,bob\n");
    resh_in(t.path(), &["file://missing.read"]).fails(1, "NOT_FOUND");
    resh_in(t.path(), &["file://dir.read"]).fails(1, "IS_A_DIRECTORY");
    resh_in(t.path(), &["file://users.csv.read", "x=1"]).fails(2, "INVALID_ARG");
}

#[test]
fn exists_and_stat() {
    let t = setup();
    let v = resh_in(t.path(), &["file://users.csv.exists"]).json();
    assert_eq!(v["kind"], "file");
    let v = resh_in(t.path(), &["file://nope.exists"]).json();
    assert_eq!(v["exists"], false);
    let v = resh_in(t.path(), &["file://users.csv.stat"]).json();
    assert_eq!(v["file_type"], "file");
    resh_in(t.path(), &["file://nope.stat"]).fails(1, "NOT_FOUND");
    resh_in(t.path(), &["file://users.csv.stat", "nofollow=maybe"]).fails(2, "INVALID_ARG");
}

#[test]
fn preview_summary_analyze_schema() {
    let t = setup();
    let v = resh_in(t.path(), &["file://users.csv.preview", "max_lines=1"]).json();
    assert_eq!(v["sample"], "id,name");
    let v = resh_in(t.path(), &["file://users.csv.summary"]).json();
    assert_eq!(v["content_type"], "csv");
    let v = resh_in(t.path(), &["file://users.csv.analyze"]).json();
    assert_eq!(v["classification"], "csv");
    let v = resh_in(t.path(), &["file://users.csv.schema", "max_rows=1"]).json();
    assert_eq!(v["detected"]["row_count_sampled"], 1);
    resh_in(t.path(), &["file://users.csv.preview", "mode=hex"]).fails(2, "INVALID_ARG");
    resh_in(t.path(), &["file://users.csv.summary", "max_bytes=0"]).fails(2, "INVALID_ARG");
    resh_in(t.path(), &["file://dir.analyze"]).fails(1, "IS_A_DIRECTORY");
    resh_in(t.path(), &["file://app.log.schema", "format=json"]).fails(1, "PARSE_ERROR");
    resh_in(t.path(), &["file://nope.preview"]).fails(1, "NOT_FOUND");
}

#[test]
fn tail() {
    let t = setup();
    assert_eq!(
        resh_in(t.path(), &["file://app.log.tail", "lines=1"])
            .ok()
            .out,
        "error two\n"
    );
    assert_eq!(
        resh_in(t.path(), &["file://app.log.tail", "bytes=4"])
            .ok()
            .out,
        "two\n"
    );
    let r = resh_in(
        t.path(),
        &[
            "file://app.log.tail",
            "lines=1",
            "follow=true",
            "timeout_ms=300",
        ],
    );
    assert_eq!(r.ok().out, "error two\n");
    resh_in(t.path(), &["file://app.log.tail", "lines=1", "bytes=1"]).fails(2, "INVALID_ARG");
    resh_in(t.path(), &["file://app.log.tail", "timeout_ms=10"]).fails(2, "INVALID_ARG");
    resh_in(t.path(), &["file://nope.tail"]).fails(1, "NOT_FOUND");
}

#[test]
fn grep() {
    let t = setup();
    let r = resh_in(
        t.path(),
        &["file://app.log.grep", "pattern=error", "ignore_case=true"],
    );
    assert_eq!(r.ok().out, "2:ERROR one\n4:error two\n");
    let v = resh_in(
        t.path(),
        &["file://app.log.grep", "pattern=one", "format=json"],
    )
    .json();
    assert_eq!(v[0]["line"], 2);
    resh_in(t.path(), &["file://app.log.grep", "pattern=zzz"]).fails(1, "NO_MATCH");
    resh_in(t.path(), &["file://app.log.grep"]).fails(2, "INVALID_ARG");
    let r = resh_in(
        t.path(),
        &["file://app.log.grep", "pattern=x", "max_count=1"],
    );
    r.fails(2, "INVALID_ARG");
    assert!(r.err.contains("did you mean max?"), "{}", r.err);
}

#[test]
fn find() {
    let t = setup();
    let v = resh_in(t.path(), &["file://./.find", "name=*.html", "type=file"]).json();
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert!(v[0]["path"].as_str().unwrap().ends_with("/dir/x.html"));
    resh_in(t.path(), &["file://dir.find", "type=pipe"]).fails(2, "INVALID_ARG");
    resh_in(t.path(), &["file://nope.find"]).fails(1, "NOT_FOUND");
}

#[test]
fn watch() {
    let t = setup();
    let dir = t.path().join("dir");
    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(700));
        std::fs::write(dir.join("new.txt"), "n").unwrap();
    });
    let r = resh_in(
        t.path(),
        &["file://dir.watch", "events=create", "timeout_ms=20000"],
    );
    writer.join().unwrap();
    let v = r.ok().json();
    assert_eq!(v["event"], "create");
    let r = resh_in(t.path(), &["file://dir.watch", "timeout_ms=200"]);
    assert_eq!(r.ok().out, "");
    resh_in(t.path(), &["file://dir.watch", "events=open"]).fails(2, "INVALID_ARG");
    resh_in(t.path(), &["file://nope.watch"]).fails(1, "NOT_FOUND");
}

#[test]
fn fixed_hashes() {
    let t = setup();
    std::fs::write(t.path().join("abc"), "abc").unwrap();
    for (verb, prefix) in [
        ("md5", "900150983cd24fb0"),
        ("sha1", "a9993e364706816a"),
        ("sha256", "ba7816bf8f01cfea"),
        ("sha512", "ddaf35a193617aba"),
    ] {
        let v = resh_in(t.path(), &[&format!("file://abc.{verb}")]).json();
        assert!(v["hash"].as_str().unwrap().starts_with(prefix), "{verb}");
        assert_eq!(v["size"], 3);
        resh_in(t.path(), &[&format!("file://dir.{verb}")]).fails(1, "IS_A_DIRECTORY");
        resh_in(t.path(), &[&format!("file://nope.{verb}")]).fails(1, "NOT_FOUND");
    }
}

#[test]
fn hash_and_verify() {
    let t = setup();
    std::fs::write(t.path().join("abc"), "abc").unwrap();
    let v = resh_in(t.path(), &["file://abc.hash", "algo=blake3"]).json();
    assert!(v["hash_hex"].as_str().unwrap().starts_with("6437b3ac"));
    resh_in(t.path(), &["file://abc.hash", "algo=crc"]).fails(2, "INVALID_ARG");
    let sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let v = resh_in(
        t.path(),
        &["file://abc.verify", &format!("expected={sha}"), "size=3"],
    )
    .json();
    assert_eq!(v["verified"], true);
    let r = resh_in(t.path(), &["file://abc.verify", "size=4"]);
    r.fails(1, "VERIFY_FAILED");
    assert_eq!(r.json()["verified"], false);
    resh_in(t.path(), &["file://abc.verify", "expected=xyz"]).fails(2, "INVALID_ARG");
    resh_in(t.path(), &["file://nope.verify"]).fails(1, "NOT_FOUND");
}

#[test]
fn write_and_append() {
    let t = setup();
    let v = resh_in(
        t.path(),
        &["file://out.txt.write", "data=hello", "mode=600"],
    )
    .json();
    assert_eq!(v["bytes"], 5);
    let p = t.path().join("out.txt");
    assert_eq!(
        std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let v = resh_in(t.path(), &["file://out.txt.append", "data=_world"]).json();
    assert_eq!(v["appended"], true);
    assert_eq!(std::fs::read_to_string(&p).unwrap(), "hello_world");
    let out = assert_cmd::cargo::cargo_bin_cmd!("resh")
        .current_dir(t.path())
        .arg("file://piped.txt.write")
        .write_stdin("from stdin")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        std::fs::read_to_string(t.path().join("piped.txt")).unwrap(),
        "from stdin"
    );
    resh_in(t.path(), &["file://out.txt.write", "data=x", "mode=9"]).fails(2, "INVALID_ARG");
    resh_in(
        t.path(),
        &["file://new.txt.write", "data=x", "create=false"],
    )
    .fails(1, "NOT_FOUND");
    resh_in(
        t.path(),
        &["file://new.txt.append", "data=x", "create=false"],
    )
    .fails(1, "NOT_FOUND");
    assert!(!t.path().join("new.txt").exists());
    resh_in(t.path(), &["file://dir.append", "data=x"]).fails(1, "IS_A_DIRECTORY");
    if !is_root() {
        let ro = t.path().join("ro");
        std::fs::create_dir(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
        let r = resh_in(t.path(), &["file://ro/f.write", "data=x"]);
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755)).unwrap();
        r.fails(1, "PERMISSION_DENIED");
    }
}

#[test]
fn replace() {
    let t = setup();
    let v = resh_in(
        t.path(),
        &[
            "file://app.log.replace",
            "pattern=error",
            "replacement=warn",
            "dry_run",
        ],
    )
    .json();
    assert_eq!(v["replacements"], 1);
    assert_eq!(v["changed"], false);
    let v = resh_in(
        t.path(),
        &[
            "file://app.log.replace",
            "pattern=(?i)error",
            "replacement=W",
            "regex=true",
            "backup=.bak",
        ],
    )
    .json();
    assert_eq!(v["replacements"], 2);
    assert_eq!(
        std::fs::read_to_string(t.path().join("app.log")).unwrap(),
        "a\nW one\nb\nW two\n"
    );
    assert!(t.path().join("app.log.bak").exists());
    resh_in(t.path(), &["file://app.log.replace", "pattern=a"]).fails(2, "INVALID_ARG");
    std::fs::write(t.path().join("bin"), b"\xff").unwrap();
    resh_in(
        t.path(),
        &["file://bin.replace", "pattern=a", "replacement=b"],
    )
    .fails(1, "NOT_UTF8");
}

#[test]
fn copy() {
    let t = setup();
    let r = resh_in(
        t.path(),
        &[
            "file://users.csv.copy",
            "to=copy.csv",
            "preserve_times=true",
        ],
    );
    assert_eq!(r.ok().out, "");
    assert!(t.path().join("copy.csv").exists());
    resh_in(t.path(), &["file://users.csv.copy", "to=copy.csv"]).fails(1, "ALREADY_EXISTS");
    resh_in(
        t.path(),
        &["file://users.csv.copy", "to=copy.csv", "overwrite=true"],
    )
    .ok();
    resh_in(t.path(), &["file://dir.copy", "to=d2"]).fails(1, "IS_A_DIRECTORY");
    resh_in(t.path(), &["file://users.csv.copy", "to=no/x"]).fails(1, "NOT_FOUND");
    resh_in(t.path(), &["file://users.csv.copy"]).fails(2, "INVALID_ARG");
}

#[test]
fn rename() {
    let t = setup();
    let v = resh_in(
        t.path(),
        &[
            "file://users.csv.rename",
            "to=a/b/u.csv",
            "create_parents=true",
        ],
    )
    .json();
    assert_eq!(v["renamed"], true);
    assert!(t.path().join("a/b/u.csv").exists());
    resh_in(t.path(), &["file://app.log.rename", "to=a/b/u.csv"]).fails(1, "ALREADY_EXISTS");
    resh_in(t.path(), &["file://dir.rename", "to=dir/sub"]).fails(1, "REFUSED");
    resh_in(t.path(), &["file://nope.rename", "to=x"]).fails(1, "NOT_FOUND");
    resh_in(
        t.path(),
        &["file://app.log.rename", "to=x", "atomic=perhaps"],
    )
    .fails(2, "INVALID_ARG");
}

#[test]
fn move_and_mv() {
    let t = setup();
    resh_in(t.path(), &["file://users.csv.move", "to=dir"]).ok();
    assert!(t.path().join("dir/users.csv").exists());
    resh_in(t.path(), &["file://dir/users.csv.mv", "to=back.csv"]).ok();
    assert!(t.path().join("back.csv").exists());
    resh_in(t.path(), &["file://app.log.mv", "to=back.csv"]).fails(1, "ALREADY_EXISTS");
    resh_in(t.path(), &["file://nope.move", "to=x"]).fails(1, "NOT_FOUND");
    resh_in(t.path(), &["file://app.log.move"]).fails(2, "INVALID_ARG");
}

#[test]
fn delete_and_remove() {
    let t = setup();
    resh_in(t.path(), &["file://users.csv.delete"]).ok();
    assert!(!t.path().join("users.csv").exists());
    resh_in(t.path(), &["file://dir.remove"]).fails(1, "IS_A_DIRECTORY");
    resh_in(t.path(), &["file://dir.remove", "recursive=true"]).ok();
    resh_in(t.path(), &["file://nope.delete"]).fails(1, "NOT_FOUND");
    resh_in(t.path(), &["file://nope.delete", "missing_ok=true"]).ok();
    resh_in(t.path(), &["file://./.delete", "recursive=true"]).fails(1, "REFUSED");
    assert!(t.path().join("app.log").exists());
    let r = resh_in(t.path(), &["file://app.log.delete", "dry_run=true"]);
    assert_eq!(r.code, 2);
    assert!(t.path().join("app.log").exists());
}

#[test]
fn chmod_and_chown() {
    let t = setup();
    resh_in(t.path(), &["file://app.log.chmod", "mode=640"]).ok();
    let m = std::fs::metadata(t.path().join("app.log"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(m & 0o777, 0o640);
    resh_in(t.path(), &["file://app.log.chmod", "mode=8"]).fails(2, "INVALID_ARG");
    resh_in(t.path(), &["file://nope.chmod", "mode=644"]).fails(1, "NOT_FOUND");
    let uid = nix::unistd::geteuid().as_raw().to_string();
    resh_in(
        t.path(),
        &["file://dir.chown", &format!("uid={uid}"), "recursive=true"],
    )
    .ok();
    resh_in(t.path(), &["file://dir.chown"]).fails(2, "INVALID_ARG");
    resh_in(t.path(), &["file://dir.chown", "user=no-such-user-resh"]).fails(2, "INVALID_ARG");
    if !is_root() {
        resh_in(t.path(), &["file://app.log.chown", "uid=0"]).fails(1, "PERMISSION_DENIED");
    }
}

#[test]
fn extended_attributes_and_tags() {
    let t = setup();
    resh_in(t.path(), &["file://app.log.ea.get", "name=system.resh_x"]).fails(1, "UNSUPPORTED");
    resh_in(t.path(), &["file://app.log.ea.get", "name=nonamespace"]).fails(2, "INVALID_ARG");
    resh_in(t.path(), &["file://nope.tag.add", "name=a"]).fails(1, "NOT_FOUND");
    if !xattrs_supported(t.path()) {
        eprintln!("skipped: no user xattrs");
        return;
    }
    let v = resh_in(
        t.path(),
        &["file://app.log.ea.set", "name=user.note", "value=hi"],
    )
    .json();
    assert_eq!(v["current"], "hi");
    let v = resh_in(t.path(), &["file://app.log.ea.get", "name=user.note"]).json();
    assert_eq!(v["value"], "hi");
    resh_in(
        t.path(),
        &[
            "file://app.log.ea.set",
            "name=user.note",
            "value=x",
            "mode=create",
        ],
    )
    .fails(1, "ALREADY_EXISTS");
    resh_in(t.path(), &["file://app.log.ea.get", "name=user.none"]).fails(1, "ATTR_NOT_FOUND");
    let v = resh_in(t.path(), &["file://app.log.tag.add", "name=B,a"]).json();
    assert_eq!(v["tags"], serde_json::json!(["a", "b"]));
    let v = resh_in(t.path(), &["file://app.log.tag.rm", "name=a"]).json();
    assert_eq!(v["tags"], serde_json::json!(["b"]));
    resh_in(t.path(), &["file://app.log.tag.add", "name=bad tag"]).fails(2, "INVALID_ARG");
}

#[test]
fn unknown_verb() {
    let t = setup();
    resh_in(t.path(), &["file://app.log.frobnicate"]).fails(2, "INVALID_ARG");
}
