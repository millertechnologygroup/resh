//! Every file verb through the real `resh` binary: one success case and the
//! main error paths (exit code and `Error: [file.<code>]` on stderr). Each test
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
            self.err.contains(&format!("Error: [{code}] ")),
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
    resh_in(t.path(), &["file://missing.read"]).fails(1, "file.not_found");
    resh_in(t.path(), &["file://dir.read"]).fails(1, "file.is_a_directory");
    resh_in(t.path(), &["file://users.csv.read", "x=1"]).fails(2, "file.invalid_arg");
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
    resh_in(t.path(), &["file://nope.stat"]).fails(1, "file.not_found");
    resh_in(t.path(), &["file://users.csv.stat", "nofollow=maybe"]).fails(2, "file.invalid_arg");
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
    resh_in(t.path(), &["file://users.csv.preview", "mode=hex"]).fails(2, "file.invalid_arg");
    resh_in(t.path(), &["file://users.csv.summary", "max_bytes=0"]).fails(2, "file.invalid_arg");
    resh_in(t.path(), &["file://dir.analyze"]).fails(1, "file.is_a_directory");
    resh_in(t.path(), &["file://app.log.schema", "format=json"]).fails(1, "file.parse_error");
    resh_in(t.path(), &["file://nope.preview"]).fails(1, "file.not_found");
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
    resh_in(t.path(), &["file://app.log.tail", "lines=1", "bytes=1"]).fails(2, "file.invalid_arg");
    resh_in(t.path(), &["file://app.log.tail", "timeout_ms=soon"]).fails(2, "file.invalid_arg");
    assert_eq!(
        resh_in(
            t.path(),
            &["file://app.log.tail", "lines=1", "timeout_ms=60000"]
        )
        .ok()
        .out,
        "error two\n"
    );
    resh_in(t.path(), &["file://nope.tail"]).fails(1, "file.not_found");
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
    resh_in(t.path(), &["file://app.log.grep", "pattern=zzz"]).fails(1, "file.no_match");
    resh_in(t.path(), &["file://app.log.grep"]).fails(2, "file.invalid_arg");
    let r = resh_in(
        t.path(),
        &["file://app.log.grep", "pattern=x", "max_count=1"],
    );
    r.fails(2, "file.invalid_arg");
    assert!(r.err.contains("did you mean max?"), "{}", r.err);
}

#[test]
fn find() {
    let t = setup();
    let v = resh_in(t.path(), &["file://./.find", "name=*.html", "type=file"]).json();
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert!(v[0]["path"].as_str().unwrap().ends_with("/dir/x.html"));
    resh_in(t.path(), &["file://dir.find", "type=pipe"]).fails(2, "file.invalid_arg");
    resh_in(t.path(), &["file://nope.find"]).fails(1, "file.not_found");
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
    resh_in(t.path(), &["file://dir.watch", "events=open"]).fails(2, "file.invalid_arg");
    resh_in(t.path(), &["file://nope.watch"]).fails(1, "file.not_found");
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
        resh_in(t.path(), &[&format!("file://dir.{verb}")]).fails(1, "file.is_a_directory");
        resh_in(t.path(), &[&format!("file://nope.{verb}")]).fails(1, "file.not_found");
    }
}

#[test]
fn hash_and_verify() {
    let t = setup();
    std::fs::write(t.path().join("abc"), "abc").unwrap();
    let v = resh_in(t.path(), &["file://abc.hash", "algo=blake3"]).json();
    assert!(v["hash_hex"].as_str().unwrap().starts_with("6437b3ac"));
    resh_in(t.path(), &["file://abc.hash", "algo=crc"]).fails(2, "file.invalid_arg");
    let sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let v = resh_in(
        t.path(),
        &["file://abc.verify", &format!("expected={sha}"), "size=3"],
    )
    .json();
    assert_eq!(v["verified"], true);
    let r = resh_in(t.path(), &["file://abc.verify", "size=4"]);
    r.fails(1, "file.verify_failed");
    assert_eq!(r.json()["verified"], false);
    resh_in(t.path(), &["file://abc.verify", "expected=xyz"]).fails(2, "file.invalid_arg");
    resh_in(t.path(), &["file://nope.verify"]).fails(1, "file.not_found");
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
    resh_in(t.path(), &["file://out.txt.write", "data=x", "mode=9"]).fails(2, "file.invalid_arg");
    resh_in(
        t.path(),
        &["file://new.txt.write", "data=x", "create=false"],
    )
    .fails(1, "file.not_found");
    resh_in(
        t.path(),
        &["file://new.txt.append", "data=x", "create=false"],
    )
    .fails(1, "file.not_found");
    assert!(!t.path().join("new.txt").exists());
    resh_in(t.path(), &["file://dir.append", "data=x"]).fails(1, "file.is_a_directory");
    if !is_root() {
        let ro = t.path().join("ro");
        std::fs::create_dir(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
        let r = resh_in(t.path(), &["file://ro/f.write", "data=x"]);
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755)).unwrap();
        r.fails(1, "file.permission_denied");
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
    resh_in(t.path(), &["file://app.log.replace", "pattern=a"]).fails(2, "file.invalid_arg");
    std::fs::write(t.path().join("bin"), b"\xff").unwrap();
    resh_in(
        t.path(),
        &["file://bin.replace", "pattern=a", "replacement=b"],
    )
    .fails(1, "file.not_utf8");
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
    resh_in(t.path(), &["file://users.csv.copy", "to=copy.csv"]).fails(1, "file.already_exists");
    resh_in(
        t.path(),
        &["file://users.csv.copy", "to=copy.csv", "overwrite=true"],
    )
    .ok();
    resh_in(t.path(), &["file://dir.copy", "to=d2"]).fails(1, "file.is_a_directory");
    resh_in(t.path(), &["file://users.csv.copy", "to=no/x"]).fails(1, "file.not_found");
    resh_in(t.path(), &["file://users.csv.copy"]).fails(2, "file.invalid_arg");
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
    resh_in(t.path(), &["file://app.log.rename", "to=a/b/u.csv"]).fails(1, "file.already_exists");
    resh_in(t.path(), &["file://dir.rename", "to=dir/sub"]).fails(1, "file.refused");
    resh_in(t.path(), &["file://nope.rename", "to=x"]).fails(1, "file.not_found");
    resh_in(
        t.path(),
        &["file://app.log.rename", "to=x", "atomic=perhaps"],
    )
    .fails(2, "file.invalid_arg");
}

#[test]
fn move_and_mv() {
    let t = setup();
    resh_in(t.path(), &["file://users.csv.move", "to=dir"]).ok();
    assert!(t.path().join("dir/users.csv").exists());
    resh_in(t.path(), &["file://dir/users.csv.mv", "to=back.csv"]).ok();
    assert!(t.path().join("back.csv").exists());
    resh_in(t.path(), &["file://app.log.mv", "to=back.csv"]).fails(1, "file.already_exists");
    resh_in(t.path(), &["file://nope.move", "to=x"]).fails(1, "file.not_found");
    resh_in(t.path(), &["file://app.log.move"]).fails(2, "file.invalid_arg");
}

#[test]
fn delete_and_remove() {
    let t = setup();
    resh_in(t.path(), &["file://users.csv.delete"]).ok();
    assert!(!t.path().join("users.csv").exists());
    resh_in(t.path(), &["file://dir.remove"]).fails(1, "file.is_a_directory");
    resh_in(t.path(), &["file://dir.remove", "recursive=true"]).ok();
    resh_in(t.path(), &["file://nope.delete"]).fails(1, "file.not_found");
    resh_in(t.path(), &["file://nope.delete", "missing_ok=true"]).ok();
    resh_in(t.path(), &["file://./.delete", "recursive=true"]).fails(1, "file.refused");
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
    resh_in(t.path(), &["file://app.log.chmod", "mode=8"]).fails(2, "file.invalid_arg");
    resh_in(t.path(), &["file://nope.chmod", "mode=644"]).fails(1, "file.not_found");
    let uid = nix::unistd::geteuid().as_raw().to_string();
    resh_in(
        t.path(),
        &["file://dir.chown", &format!("uid={uid}"), "recursive=true"],
    )
    .ok();
    resh_in(t.path(), &["file://dir.chown"]).fails(2, "file.invalid_arg");
    resh_in(t.path(), &["file://dir.chown", "user=no-such-user-resh"]).fails(2, "file.invalid_arg");
    if !is_root() {
        resh_in(t.path(), &["file://app.log.chown", "uid=0"]).fails(1, "file.permission_denied");
    }
}

#[test]
fn extended_attributes_and_tags() {
    let t = setup();
    resh_in(t.path(), &["file://app.log.ea.get", "name=system.resh_x"])
        .fails(1, "file.unsupported");
    resh_in(t.path(), &["file://app.log.ea.get", "name=nonamespace"]).fails(2, "file.invalid_arg");
    resh_in(t.path(), &["file://nope.tag.add", "name=a"]).fails(1, "file.not_found");
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
    .fails(1, "file.already_exists");
    resh_in(t.path(), &["file://app.log.ea.get", "name=user.none"]).fails(1, "file.attr_not_found");
    let v = resh_in(t.path(), &["file://app.log.tag.add", "name=B,a"]).json();
    assert_eq!(v["tags"], serde_json::json!(["a", "b"]));
    let v = resh_in(t.path(), &["file://app.log.tag.rm", "name=a"]).json();
    assert_eq!(v["tags"], serde_json::json!(["b"]));
    resh_in(t.path(), &["file://app.log.tag.add", "name=bad tag"]).fails(2, "file.invalid_arg");
}

#[test]
fn unknown_verb() {
    let t = setup();
    resh_in(t.path(), &["file://app.log.frobnicate"]).fails(2, "file.invalid_arg");
}

// --- timeouts and streaming ----------------------------------------------------

fn sparse(dir: &Path, name: &str) {
    std::fs::File::create(dir.join(name))
        .unwrap()
        .set_len(1 << 30)
        .unwrap();
}

#[test]
fn long_verbs_exit_124_at_the_deadline() {
    let t = setup();
    sparse(t.path(), "big");
    for args in [
        vec!["file://big.sha256", "timeout_ms=1"],
        vec!["file://big.hash", "algo=blake3", "timeout_ms=1"],
        vec!["file://big.verify", "timeout_ms=1"],
        vec!["file://big.grep", "pattern=x", "timeout_ms=1"],
        vec!["file://big.analyze", "max_bytes=2000000000", "timeout_ms=1"],
        vec!["file://big.copy", "to=copy", "timeout_ms=1"],
        vec![
            "file://big.replace",
            "pattern=a",
            "replacement=b",
            "timeout_ms=1",
        ],
    ] {
        let r = resh_in(t.path(), &args);
        r.fails(124, "file.timeout");
        assert!(r.err.contains("timed out after timeout_ms=1"), "{}", r.err);
    }
    assert!(!t.path().join("copy").exists());
    let leftovers = std::fs::read_dir(t.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".resh_"))
        .count();
    assert_eq!(leftovers, 0);
    resh_in(t.path(), &["file://app.log.stat", "timeout_ms=100"]).fails(2, "file.invalid_arg");
}

#[test]
fn write_from_slow_stdin_times_out_and_changes_nothing() {
    use std::io::Write;
    let t = setup();
    std::fs::write(t.path().join("out"), "keep").unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_resh"))
        .current_dir(t.path())
        .args(["file://out.write", "timeout_ms=400"])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let feeder = std::thread::spawn(move || {
        for _ in 0..40 {
            if stdin.write_all(b"x").is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    let out = child.wait_with_output().unwrap();
    feeder.join().unwrap();
    assert_eq!(out.status.code(), Some(124));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Error: [file.timeout] "));
    assert_eq!(
        std::fs::read_to_string(t.path().join("out")).unwrap(),
        "keep"
    );
}

/// Reads one line from the child's stdout, failing after `secs`.
fn line_within(rx: &std::sync::mpsc::Receiver<String>, secs: u64) -> String {
    rx.recv_timeout(Duration::from_secs(secs))
        .expect("no output while the command was running")
}

fn spawn_lines(
    dir: &Path,
    args: &[&str],
) -> (std::process::Child, std::sync::mpsc::Receiver<String>) {
    use std::io::BufRead;
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_resh"))
        .current_dir(dir)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            match line {
                Ok(l) => {
                    if tx.send(l).is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });
    (child, rx)
}

#[test]
fn tail_follow_streams_while_running() {
    use std::io::Write;
    let t = setup();
    let (mut child, rx) = spawn_lines(t.path(), &["file://app.log.tail", "lines=1", "follow=true"]);
    assert_eq!(line_within(&rx, 20), "error two");
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(t.path().join("app.log"))
        .unwrap();
    f.write_all(b"appended\n").unwrap();
    assert_eq!(line_within(&rx, 20), "appended");
    assert!(child.try_wait().unwrap().is_none(), "still following");
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn watch_streams_each_event_while_running() {
    let t = setup();
    let (mut child, rx) = spawn_lines(
        t.path(),
        &[
            "file://dir.watch",
            "events=create",
            "max_events=2",
            "timeout_ms=60000",
        ],
    );
    // Give the watcher time to start, then create files until one is seen.
    let mut first = None;
    for i in 0..40 {
        std::fs::write(t.path().join(format!("dir/a{i}")), "").unwrap();
        if let Ok(l) = rx.recv_timeout(Duration::from_millis(250)) {
            first = Some(l);
            break;
        }
    }
    let first: Value = serde_json::from_str(&first.expect("no event streamed")).unwrap();
    assert_eq!(first["event"], "create");
    assert!(
        child.try_wait().unwrap().is_none(),
        "still watching for event 2"
    );
    std::fs::write(t.path().join("dir/second"), "").unwrap();
    let _ = line_within(&rx, 20);
    let status = child.wait().unwrap();
    assert!(status.success());
}

#[test]
fn read_streams_a_fifo_and_stops_at_the_deadline() {
    let t = setup();
    let fifo = t.path().join("fifo");
    nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
    let f2 = fifo.clone();
    let writer = std::thread::spawn(move || {
        use std::io::Write;
        let mut w = std::fs::OpenOptions::new().write(true).open(&f2).unwrap();
        for i in 0..100 {
            if writeln!(w, "line{i}").is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    let (mut child, rx) = spawn_lines(t.path(), &["file://fifo.read", "timeout_ms=1500"]);
    assert_eq!(line_within(&rx, 20), "line0");
    assert!(
        child.try_wait().unwrap().is_none(),
        "output arrived before the end"
    );
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(124));
    writer.join().unwrap();
}
