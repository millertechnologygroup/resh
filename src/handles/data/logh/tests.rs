//! Unit tests for `log://`: URL parsing, argument validation, the backward
//! scan and the line splitter, `tail` on files (including follow across
//! truncation and rotation), and the journal through a fake journalctl.

use super::scan::{self, LineSplitter, ScanError};
use super::*;
use crate::core::test_support::write_executable;
use std::io::{self, Cursor};
use std::os::unix::fs::PermissionsExt;

struct Out {
    st: Status,
    out: String,
    err: String,
}

fn handle(source: LogSourceKind) -> LogHandle {
    LogHandle::with_source(source)
}

fn file_handle(p: &Path) -> LogHandle {
    handle(LogSourceKind::File(p.to_path_buf()))
}

fn args(kv: &[(&str, &str)]) -> Args {
    kv.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn run(h: &LogHandle, verb: &str, a: &[(&str, &str)]) -> Out {
    let (mut i, mut o, mut e) = (
        Cursor::new(Vec::new()),
        Cursor::new(Vec::new()),
        Cursor::new(Vec::new()),
    );
    let mut io = IoStreams {
        stdin: &mut i,
        stdout: &mut o,
        stderr: &mut e,
    };
    let st = h.call(verb, &args(a), &mut io).unwrap();
    Out {
        st,
        out: String::from_utf8(o.into_inner()).unwrap(),
        err: String::from_utf8(e.into_inner()).unwrap(),
    }
}

impl Out {
    fn ok(self) -> Self {
        assert!(self.st.ok, "{:?}\n{}\n{}", self.st, self.out, self.err);
        self
    }
    fn fails(self, exit: i32, code: &str) -> Self {
        assert!(!self.st.ok, "{}", self.out);
        assert_eq!(self.st.exit_code(), exit, "{:?} {}", self.st, self.err);
        let reason = self.st.reason.clone().unwrap();
        assert!(reason.starts_with(&format!("[{code}] ")), "{reason}");
        assert!(
            self.err
                .lines()
                .any(|l| l.starts_with(&format!("Error: [{code}] "))),
            "{}",
            self.err
        );
        self
    }
    fn json(&self) -> Value {
        serde_json::from_str(self.out.trim()).unwrap()
    }
}

fn source(u: &str) -> LogSourceKind {
    LogHandle::from_url(&Url::parse(u).unwrap())
        .unwrap()
        .target
        .source
}

fn url_err(u: &str) -> String {
    match LogHandle::from_url(&Url::parse(u).unwrap()) {
        Ok(_) => panic!("{u} accepted"),
        Err(e) => e.to_string(),
    }
}

// --- targets ------------------------------------------------------------------------

#[test]
fn from_url_sources() {
    assert!(
        matches!(source("log:///var/log/syslog"), LogSourceKind::File(p) if p == Path::new("/var/log/syslog"))
    );
    assert!(
        matches!(source("log://./logs/app.log"), LogSourceKind::File(p) if p == Path::new("./logs/app.log"))
    );
    assert!(
        matches!(source("log://../app.log"), LogSourceKind::File(p) if p == Path::new("../app.log"))
    );
    assert!(matches!(source("log://svc/nginx"), LogSourceKind::Service(s) if s == "nginx"));
    assert!(
        matches!(source("log://svc/getty@tty1.service"), LogSourceKind::Service(s) if s == "getty@tty1.service")
    );
    // Percent-encoded names are decoded (a space is sent as %20).
    assert!(
        matches!(source("log:///tmp/my%20app.log"), LogSourceKind::File(p) if p == Path::new("/tmp/my app.log"))
    );
    assert!(
        matches!(source("log:///tmp/my app.log"), LogSourceKind::File(p) if p == Path::new("/tmp/my app.log"))
    );
    assert!(url_err("log://svc/").contains("cannot be empty"));
    assert!(url_err("log://var/log/syslog").contains("Unsupported log:// host"));
    assert!(url_err("log:///").contains("cannot be empty"));
    assert!(url_err("log:///a%00b").contains("NUL"));
}

#[test]
fn service_names_are_validated() {
    for ok in [
        "nginx",
        "nginx.service",
        "user@1000.service",
        "a:b_c-d",
        "mnt-x\\x2dy.mount",
    ] {
        assert!(valid_service(ok).is_ok(), "{ok}");
    }
    for bad in [
        "",
        "-f",
        "--since=x",
        ".hidden",
        "a b",
        "a;b",
        "a*",
        "a/b",
        "x$y",
    ] {
        assert!(valid_service(bad).is_err(), "{bad}");
    }
    assert!(valid_service(&"a".repeat(257)).is_err());
    assert!(url_err("log://svc/-n").contains("cannot start with '-'"));
    assert!(url_err("log://svc/a%20b").contains("not allowed"));
}

#[test]
fn journalctl_arguments_keep_each_value_separate() {
    assert_eq!(
        journal::args("nginx", 50, false),
        ["--unit=nginx", "--lines=50", "--no-pager", "--output=short"]
    );
    assert_eq!(
        journal::args("a@b.service", 1, true),
        [
            "--unit=a@b.service",
            "--lines=1",
            "--no-pager",
            "--output=short",
            "--follow"
        ]
    );
}

// --- arguments ----------------------------------------------------------------------

fn parse(a: &[(&str, &str)]) -> Result<TailOpts, Fail> {
    parse_tail_args(&args(a))
}

fn invalid(a: &[(&str, &str)]) -> String {
    let f = parse(a).unwrap_err();
    assert_eq!((f.exit, f.code), (2, "log.invalid_argument"), "{}", f.msg);
    f.msg
}

#[test]
fn defaults() {
    let o = parse(&[]).unwrap();
    assert_eq!(o.lines, 100);
    assert!(o.pattern.is_none() && !o.json && !o.follow);
    assert_eq!(o.timeout, Some(Duration::from_millis(600_000)));
    let o = parse(&[("follow", "yes")]).unwrap();
    assert!(o.follow);
    assert_eq!(o.timeout, None);
    let o = parse(&[("follow", "1"), ("timeout_ms", "250")]).unwrap();
    assert_eq!(o.timeout, Some(Duration::from_millis(250)));
    let o = parse(&[("lines", "1000000"), ("mode", "json"), ("pattern", "x")]).unwrap();
    assert!(o.json && o.lines == 1_000_000 && o.pattern.as_deref() == Some("x"));
    assert!(parse(&[("dry_run", "false")]).is_ok());
}

#[test]
fn invalid_arguments_are_refused() {
    assert!(invalid(&[("line", "3")]).contains("did you mean `lines`?"));
    assert!(invalid(&[("timeout", "3")]).contains("did you mean `timeout_ms`?"));
    assert!(invalid(&[("folow", "true")]).contains("did you mean `follow`?"));
    assert!(invalid(&[("zzz", "1")]).contains("unknown argument: zzz"));
    for v in ["0", "abc", "-1", "1000001", ""] {
        assert!(invalid(&[("lines", v)]).contains("lines"), "{v}");
    }
    assert!(invalid(&[("mode", "xml")]).contains("mode"));
    assert!(invalid(&[("pattern", "")]).contains("pattern"));
    assert!(invalid(&[("follow", "maybe")]).contains("follow"));
    assert!(parse(&[("follow", "true"), ("mode", "json")]).is_ok());
    for v in ["0", "x", "604800001"] {
        assert!(invalid(&[("timeout_ms", v)]).contains("timeout_ms"), "{v}");
    }
    assert!(invalid(&[("dry_run", "true")]).contains("dry_run"));
    assert!(invalid(&[("dry_run", "perhaps")]).contains("dry_run"));
}

#[test]
fn invalid_arguments_are_reported_before_reading() {
    // A missing file is not even looked at: the usage error wins.
    let h = file_handle(Path::new("/nonexistent/resh-log-test.log"));
    let r = run(&h, "tail", &[("lines", "abc"), ("mode", "json")]).fails(2, "log.invalid_argument");
    assert!(r.out.is_empty(), "{}", r.out);
}

#[test]
fn every_error_code_is_valid_and_documented() {
    let doc = include_str!("../../../../docs/Data_StateManagement/log.md");
    for code in ERROR_CODES {
        assert!(crate::core::status::is_valid_error_code(code), "{code}");
        assert!(doc.contains(&format!("`{code}`")), "{code} not documented");
    }
}

// --- help and verbs -----------------------------------------------------------------

#[test]
fn legacy_help_renders_approved_help() {
    let h = LogHandle::from_url(&Url::parse("log://--help").unwrap()).unwrap();
    let r = run(&h, "help", &[]).ok();
    assert!(r.out.starts_with("Handle: log"), "{}", r.out);
    let r = run(&h, "help", &[("verb", "tail")]).ok();
    assert!(r.out.contains("Verb: tail"), "{}", r.out);
    let r = run(&h, "--help=tail", &[]).ok();
    assert!(r.out.contains("Verb: tail"), "{}", r.out);
    run(&h, "--help=tial", &[]).fails(2, "log.unknown_verb");
}

#[test]
fn unknown_verb_is_a_usage_error() {
    let h = file_handle(Path::new("/x.log"));
    let r = run(&h, "tial", &[]).fails(2, "log.unknown_verb");
    assert!(r.err.contains("did you mean `tail`?"), "{}", r.err);
    run(&h, "read", &[]).fails(2, "log.unknown_verb");
}

// --- the backward scan --------------------------------------------------------------

/// What `tail -n` returns, computed the simple way.
fn naive(data: &[u8], n: usize) -> Vec<String> {
    let text = String::from_utf8_lossy(data);
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    lines[lines.len().saturating_sub(n)..].to_vec()
}

fn scan_bytes(data: &[u8], n: usize) -> scan::Tail {
    let dir = tempfile::TempDir::new().unwrap();
    let p = dir.path().join("f");
    std::fs::write(&p, data).unwrap();
    let f = File::open(&p).unwrap();
    scan::last_lines(&f, data.len() as u64, n, None).unwrap()
}

#[test]
fn scan_matches_a_simple_tail_at_every_size() {
    let mut cases: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"\n".to_vec(),
        b"\n\n\n".to_vec(),
        b"a".to_vec(),
        b"a\n".to_vec(),
        b"a\nb".to_vec(),
        b"a\n\nb\n".to_vec(),
        b"a\r\nb\r\n".to_vec(),
    ];
    // Lines that straddle the 64 KiB chunk boundary, with and without a
    // final newline, including the case the old scan cut short.
    for width in [1usize, 7, 100, 8191, 8192, 65_535, 65_536, 70_000] {
        let mut d = Vec::new();
        for i in 0..40 {
            d.extend(format!("{i:05}-").bytes());
            d.extend(std::iter::repeat_n(b'x', width % 9000 + i));
            d.push(b'\n');
        }
        cases.push(d.clone());
        d.extend(b"tail-without-newline");
        cases.push(d);
    }
    let mut big = Vec::new();
    for i in 0..20_000 {
        big.extend(format!("line {i}\n").bytes());
    }
    cases.push(big);
    for data in &cases {
        for n in [1, 2, 3, 5, 39, 40, 41, 1000, 100_000] {
            assert_eq!(
                scan_bytes(data, n).lines,
                naive(data, n),
                "n={n} len={}",
                data.len()
            );
        }
    }
}

#[test]
fn scan_handles_non_utf8_and_partial_lines() {
    let t = scan_bytes(b"ok\n\xff\xfebad\nlast", 3);
    assert_eq!(t.lines, ["ok", "\u{fffd}\u{fffd}bad", "last"]);
    assert_eq!(t.partial_start, Some(9));
    assert_eq!(scan_bytes(b"a\nb\n", 5).partial_start, None);
}

#[test]
fn scan_cuts_huge_lines_and_keeps_memory_bounded() {
    let mut data = b"first\n".to_vec();
    data.extend(std::iter::repeat_n(b'y', MAX_LINE_BYTES * 2 + 5));
    data.extend(b"\nlast\n");
    let t = scan_bytes(&data, 3);
    assert_eq!(t.cut, 1);
    assert_eq!(t.lines.len(), 3);
    assert_eq!(t.lines[0], "first");
    assert_eq!(t.lines[1].len(), MAX_LINE_BYTES);
    assert_eq!(t.lines[2], "last");
}

#[test]
fn scan_stops_at_the_deadline() {
    let dir = tempfile::TempDir::new().unwrap();
    let p = dir.path().join("f");
    std::fs::write(&p, "a\nb\n").unwrap();
    let f = File::open(&p).unwrap();
    let past = Instant::now();
    assert!(matches!(
        scan::last_lines(&f, 4, 1, Some(past)),
        Err(ScanError::Timeout)
    ));
}

#[test]
fn splitter_handles_chunks_crlf_and_huge_lines() {
    let mut s = LineSplitter::default();
    let mut got = Vec::new();
    for chunk in [&b"ab"[..], b"c\r\nd", b"e\n\xff\n", b"tail"] {
        s.push(chunk, |l| {
            got.push(l.to_string());
            Ok(())
        });
    }
    assert_eq!(got, ["abc", "de", "\u{fffd}"]);
    assert_eq!(s.finish().as_deref(), Some("tail"));
    assert_eq!(s.finish(), None);

    let mut got = Vec::new();
    let huge = vec![b'z'; MAX_LINE_BYTES + 10];
    s.push(&huge[..MAX_LINE_BYTES], |l| {
        got.push(l.len());
        Ok(())
    });
    s.push(&huge[MAX_LINE_BYTES..], |l| {
        got.push(l.len());
        Ok(())
    });
    s.push(b"\nnext\n", |l| {
        got.push(l.len());
        Ok(())
    });
    assert_eq!(got, [MAX_LINE_BYTES, 4]);
    assert_eq!(s.cut, 1);

    // A line of exactly the limit is not cut.
    let mut s = LineSplitter::default();
    let mut got = Vec::new();
    s.push(&huge[..MAX_LINE_BYTES], |l| {
        got.push(l.len());
        Ok(())
    });
    s.push(b"\n", |l| {
        got.push(l.len());
        Ok(())
    });
    assert_eq!((got, s.cut), (vec![MAX_LINE_BYTES], 0));

    // The first sink error is kept and stops output.
    let mut s = LineSplitter::default();
    let mut n = 0;
    s.push(b"a\nb\n", |_| {
        n += 1;
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "gone"))
    });
    assert_eq!(n, 1);
    assert_eq!(
        s.take_error().unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

// --- tail on files ------------------------------------------------------------------

fn log_file(content: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::TempDir::new().unwrap();
    let p = dir.path().join("app.log");
    std::fs::write(&p, content).unwrap();
    (dir, p)
}

#[test]
fn tail_raw_json_and_pattern() {
    let (_d, p) = log_file(b"a ok\nb ERROR one\nc ok\nd ERROR two\n");
    let h = file_handle(&p);
    let r = run(&h, "tail", &[("lines", "2")]).ok();
    assert_eq!(r.out, "c ok\nd ERROR two\n");
    assert!(r.err.is_empty());
    let r = run(&h, "tail", &[]).ok();
    assert_eq!(r.out.lines().count(), 4);
    let r = run(
        &h,
        "tail",
        &[("lines", "3"), ("pattern", "ERROR"), ("mode", "json")],
    )
    .ok();
    assert_eq!(
        r.json(),
        json!({"lines": ["b ERROR one", "d ERROR two"], "path": p.to_string_lossy(),
               "pattern": "ERROR", "requested_lines": 3, "returned_lines": 2})
    );
    // pattern applies to the last `lines` lines, and is case-sensitive.
    let r = run(&h, "tail", &[("lines", "1"), ("pattern", "ERROR one")]).ok();
    assert_eq!(r.out, "");
    let r = run(&h, "tail", &[("pattern", "error")]).ok();
    assert_eq!(r.out, "");
}

#[test]
fn tail_empty_crlf_and_non_utf8_files() {
    let (_d, p) = log_file(b"");
    let r = run(&file_handle(&p), "tail", &[("mode", "json")]).ok();
    assert_eq!(r.json()["lines"], json!([]));
    assert_eq!(r.json()["returned_lines"], 0);
    // A small file with invalid UTF-8 no longer fails.
    let (_d, p) = log_file(b"one\r\n\xc3\x28two\r\n");
    let r = run(&file_handle(&p), "tail", &[]).ok();
    assert_eq!(r.out, "one\n\u{fffd}(two\n");
}

#[test]
fn tail_warns_about_cut_lines() {
    let mut data = vec![b'q'; MAX_LINE_BYTES + 1];
    data.push(b'\n');
    let (_d, p) = log_file(&data);
    let r = run(&file_handle(&p), "tail", &[]).ok();
    assert_eq!(r.out.len(), MAX_LINE_BYTES + 1);
    assert!(
        r.err.contains("Warning: 1 line(s) longer than"),
        "{}",
        r.err
    );
}

#[test]
fn missing_file_fails_with_not_found() {
    let dir = tempfile::TempDir::new().unwrap();
    let p = dir.path().join("missing.log");
    let h = file_handle(&p);
    let r = run(&h, "tail", &[]).fails(1, "log.not_found");
    assert!(r.out.is_empty(), "raw errors go to stderr only: {}", r.out);
    let r = run(&h, "tail", &[("lines", "10"), ("mode", "json")]).fails(1, "log.not_found");
    let v = r.json();
    assert_eq!(v["error"]["code"], "log.not_found");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("missing.log")
    );
    assert_eq!(v["path"], p.to_string_lossy().as_ref());
    assert_eq!(v["requested_lines"], 10);
    assert_eq!(v["returned_lines"], 0);
}

#[test]
fn directories_and_fifos_are_not_files() {
    let dir = tempfile::TempDir::new().unwrap();
    run(&file_handle(dir.path()), "tail", &[]).fails(1, "log.not_a_file");
    let fifo = dir.path().join("fifo");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    // SAFETY: a valid C string and mode.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    // Opened non-blocking, so this returns instead of waiting for a writer.
    run(&file_handle(&fifo), "tail", &[]).fails(1, "log.not_a_file");
}

#[test]
fn unreadable_file_is_permission_denied() {
    // SAFETY: getuid has no preconditions.
    if unsafe { libc::getuid() } == 0 {
        return; // root reads anything
    }
    let (_d, p) = log_file(b"secret\n");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
    run(&file_handle(&p), "tail", &[]).fails(1, "log.permission_denied");
}

/// Runs `tail` with `a` on another thread while `writer` changes the file.
fn follow_while(
    p: &Path,
    a: &[(&str, &str)],
    writer: impl FnOnce() + Send + 'static,
) -> (Out, Duration) {
    let h = file_handle(p);
    let a: Vec<(String, String)> = a
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let t = std::thread::spawn(move || {
        let kv: Vec<(&str, &str)> = a.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let start = Instant::now();
        let r = run(&h, "tail", &kv);
        (r, start.elapsed())
    });
    writer();
    t.join().unwrap()
}

fn append(p: &Path, s: &str) {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new().append(true).open(p).unwrap();
    f.write_all(s.as_bytes()).unwrap();
}

fn pause() {
    std::thread::sleep(Duration::from_millis(300));
}

#[test]
fn follow_streams_new_lines_until_the_timeout() {
    let (_d, p) = log_file(b"old1\nold2\npart");
    let q = p.clone();
    let (r, took) = follow_while(
        &p,
        &[
            ("follow", "true"),
            ("lines", "5"),
            ("timeout_ms", "1500"),
            ("pattern", "o"),
        ],
        move || {
            pause();
            append(&q, "ial-one\nnew two\nskip\n");
            pause();
            append(&q, "no newline yet");
        },
    );
    let r = r.ok();
    assert_eq!(r.out, "old1\nold2\npartial-one\nnew two\nno newline yet\n");
    assert!(took >= Duration::from_millis(1500), "{took:?}");
    assert!(took < Duration::from_secs(10), "{took:?}");
}

#[test]
fn follow_reads_a_truncated_file_from_the_start() {
    let (_d, p) = log_file(b"before 1\nbefore 2\n");
    let q = p.clone();
    let (r, _) = follow_while(&p, &[("follow", "on"), ("timeout_ms", "1500")], move || {
        pause();
        std::fs::write(&q, "").unwrap();
        pause();
        append(&q, "after\n");
    });
    let r = r.ok();
    assert_eq!(r.out, "before 1\nbefore 2\nafter\n");
    assert!(r.err.contains("was truncated"), "{}", r.err);
}

#[test]
fn follow_continues_into_a_rotated_file() {
    let (d, p) = log_file(b"gen1 a\n");
    let q = p.clone();
    let rotated = d.path().join("app.log.1");
    let (r, _) = follow_while(
        &p,
        &[("follow", "true"), ("timeout_ms", "2000")],
        move || {
            pause();
            append(&q, "gen1 b\n");
            std::fs::rename(&q, &rotated).unwrap();
            // Written to the old file after the rename: still read.
            append(&rotated, "gen1 c\n");
            pause();
            std::fs::write(&q, "gen2 a\n").unwrap();
            pause();
            append(&q, "gen2 b\n");
        },
    );
    let r = r.ok();
    assert_eq!(r.out, "gen1 a\ngen1 b\ngen1 c\ngen2 a\ngen2 b\n");
    assert!(r.err.contains("was replaced"), "{}", r.err);
}

#[test]
fn follow_with_a_missing_file_fails_at_once() {
    let dir = tempfile::TempDir::new().unwrap();
    let h = file_handle(&dir.path().join("nope.log"));
    run(&h, "tail", &[("follow", "true")]).fails(1, "log.not_found");
}

// --- the journal through a fake journalctl -------------------------------------------

struct FakeJournal {
    dir: tempfile::TempDir,
}

impl FakeJournal {
    /// A journalctl that records its arguments, writes `stdout` and
    /// `stderr`, then runs `then` (for example `exit 3` or `sleep 30`).
    fn new(stdout: &str, stderr: &str, then: &str) -> Self {
        let dir = tempfile::TempDir::new().unwrap();
        let argv = dir.path().join("argv");
        let script = format!(
            "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > '{}'\n\
             printf '%s' '{}'\nprintf '%s' '{}' >&2\n{}\n",
            argv.display(),
            stdout,
            stderr,
            then
        );
        write_executable(&dir.path().join("journalctl"), &script);
        FakeJournal { dir }
    }

    fn handle(&self, service: &str) -> LogHandle {
        let mut h = handle(LogSourceKind::Service(service.to_string()));
        h.journalctl = self.dir.path().join("journalctl").into_os_string();
        h
    }

    fn argv(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.path().join("argv"))
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }
}

#[test]
fn journal_tail_raw_and_json() {
    let j = FakeJournal::new(
        "Nov 07 10:00:00 box web[1]: started\nNov 07 10:00:01 box web[1]: error x\n",
        "",
        "exit 0",
    );
    let h = j.handle("web@1.service");
    let r = run(&h, "tail", &[("lines", "7")]).ok();
    assert_eq!(r.out.lines().count(), 2);
    assert_eq!(
        j.argv(),
        [
            "--unit=web@1.service",
            "--lines=7",
            "--no-pager",
            "--output=short"
        ]
    );
    let r = run(&h, "tail", &[("mode", "json"), ("pattern", "error")]).ok();
    assert_eq!(
        r.json(),
        json!({"lines": ["Nov 07 10:00:01 box web[1]: error x"], "pattern": "error",
               "requested_lines": 100, "returned_lines": 1, "service": "web@1.service"})
    );
}

#[test]
fn journal_no_entries_is_an_empty_result() {
    let j = FakeJournal::new("-- No entries --\n", "", "exit 0");
    let r = run(&j.handle("none"), "tail", &[("mode", "json")]).ok();
    assert_eq!(r.json()["lines"], json!([]));
}

#[test]
fn journal_failures() {
    let j = FakeJournal::new("", "Failed to add filter: bad\n", "exit 3");
    let r = run(&j.handle("x"), "tail", &[("mode", "json")]).fails(1, "log.journal_failed");
    let v = r.json();
    assert_eq!(v["error"]["code"], "log.journal_failed");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Failed to add filter")
    );
    assert_eq!(v["service"], "x");

    let hint = "Hint: You are currently not seeing messages from other users and the system.";
    let j = FakeJournal::new("", hint, "exit 0");
    run(&j.handle("x"), "tail", &[]).fails(1, "log.journal_access_denied");

    let j = FakeJournal::new(
        "",
        "No journal files were opened due to insufficient permissions.",
        "exit 1",
    );
    run(&j.handle("x"), "tail", &[]).fails(1, "log.journal_access_denied");

    let mut h = handle(LogSourceKind::Service("x".into()));
    h.journalctl = "/nonexistent/resh-test/journalctl".into();
    run(&h, "tail", &[]).fails(1, "log.journalctl_not_found");
    run(&h, "tail", &[("follow", "true"), ("timeout_ms", "500")])
        .fails(1, "log.journalctl_not_found");
}

#[test]
fn journal_is_stopped_at_the_deadline() {
    let j = FakeJournal::new("early line\n", "", "sleep 30");
    let start = Instant::now();
    run(&j.handle("x"), "tail", &[("timeout_ms", "300")]).fails(124, "log.timeout");
    assert!(start.elapsed() < Duration::from_secs(10));
    // The loss is reported by the handle, not left for main as "unknown".
    assert!(!crate::core::process::has_lost());
}

#[test]
fn journal_follow_streams_until_the_deadline() {
    let j = FakeJournal::new("one\ntwo\n", "", "sleep 1; printf 'three\\n'; sleep 30");
    let start = Instant::now();
    let r = run(
        &j.handle("x"),
        "tail",
        &[("follow", "true"), ("timeout_ms", "2000"), ("lines", "3")],
    )
    .ok();
    assert_eq!(r.out, "one\ntwo\nthree\n");
    assert!(start.elapsed() < Duration::from_secs(10));
    assert!(!crate::core::process::has_lost());
    assert_eq!(
        j.argv(),
        [
            "--unit=x",
            "--lines=3",
            "--no-pager",
            "--output=short",
            "--follow"
        ]
    );
}

#[test]
fn journal_follow_ends_with_journalctl() {
    let j = FakeJournal::new("a\nb ERR\n", "", "exit 0");
    let r = run(
        &j.handle("x"),
        "tail",
        &[("follow", "true"), ("pattern", "ERR")],
    )
    .ok();
    assert_eq!(r.out, "b ERR\n");
    let j = FakeJournal::new("a\n", "boom\n", "exit 2");
    let r = run(&j.handle("x"), "tail", &[("follow", "true")]).fails(1, "log.journal_failed");
    assert!(r.err.contains("boom"), "{}", r.err);
    let j = FakeJournal::new(
        "",
        "Hint: You are currently not seeing messages from other users.\n",
        "sleep 30",
    );
    let start = Instant::now();
    run(&j.handle("x"), "tail", &[("follow", "true")]).fails(1, "log.journal_access_denied");
    assert!(start.elapsed() < Duration::from_secs(10));
}

/// Parses one streamed JSON object per line.
fn objects(out: &str) -> Vec<Value> {
    out.lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}")))
        .collect()
}

#[test]
fn follow_json_streams_one_object_per_line_and_events() {
    let (d, p) = log_file(b"old\n");
    let q = p.clone();
    let rotated = d.path().join("app.log.1");
    let before = now_ms();
    let (r, _) = follow_while(
        &p,
        &[("follow", "true"), ("mode", "json"), ("timeout_ms", "2000")],
        move || {
            pause();
            append(&q, "new \"quoted\"\n");
            pause();
            std::fs::write(&q, "").unwrap();
            pause();
            append(&q, "after truncation\n");
            pause();
            std::fs::rename(&q, &rotated).unwrap();
            std::fs::write(&q, "rotated in\n").unwrap();
        },
    );
    let r = r.ok();
    assert!(r.err.is_empty(), "events go to stdout in json: {}", r.err);
    let objs = objects(&r.out);
    let path = p.to_string_lossy();
    let shape: Vec<Value> = objs
        .iter()
        .map(|o| {
            let ts = o["ts"].as_u64().unwrap();
            assert!(ts >= before && ts <= now_ms(), "{o}");
            let mut o = o.clone();
            o.as_object_mut().unwrap().remove("ts");
            o
        })
        .collect();
    assert_eq!(
        shape,
        [
            json!({"source": "file", "path": path, "line": "old"}),
            json!({"source": "file", "path": path, "line": "new \"quoted\""}),
            json!({"event": "truncated", "source": "file", "path": path}),
            json!({"source": "file", "path": path, "line": "after truncation"}),
            json!({"event": "rotated", "source": "file", "path": path}),
            json!({"source": "file", "path": path, "line": "rotated in"}),
        ]
    );
}

#[test]
fn follow_json_journal_objects_and_errors() {
    let j = FakeJournal::new("one\n-- No entries --\ntwo ERR\n", "", "sleep 30");
    let r = run(
        &j.handle("web.service"),
        "tail",
        &[
            ("follow", "true"),
            ("mode", "json"),
            ("timeout_ms", "1000"),
            ("pattern", "ERR"),
        ],
    )
    .ok();
    let objs = objects(&r.out);
    assert_eq!(objs.len(), 1, "{}", r.out);
    assert_eq!(objs[0]["source"], "journal");
    assert_eq!(objs[0]["unit"], "web.service");
    assert_eq!(objs[0]["line"], "two ERR");
    assert!(objs[0]["ts"].is_u64());

    // A failure ends the stream with an object carrying the error.
    let j = FakeJournal::new("a\n", "boom\n", "exit 2");
    let r = run(
        &j.handle("x"),
        "tail",
        &[("follow", "true"), ("mode", "json")],
    )
    .fails(1, "log.journal_failed");
    let objs = objects(&r.out);
    assert_eq!(objs[0]["line"], "a");
    assert_eq!(objs[1]["error"]["code"], "log.journal_failed");
    assert_eq!(objs[1]["unit"], "x");
}

#[test]
fn follow_ends_normally_at_the_limit_but_plain_tail_times_out() {
    // A deadline that passes during the scan: follow ends (exit 0) ...
    let (_d, p) = log_file(b"x\n");
    let h = file_handle(&p);
    run(&h, "tail", &[("follow", "true"), ("timeout_ms", "1")]).ok();
    // ... while journalctl outliving a plain tail's deadline is exit 124.
    let j = FakeJournal::new("", "", "sleep 30");
    run(&j.handle("x"), "tail", &[("timeout_ms", "200")]).fails(124, "log.timeout");
}

#[test]
fn help_usage_lists_exactly_the_accepted_arguments() {
    assert_eq!(LOG_HELP.verbs.len(), 1);
    let usage = LOG_HELP.verbs[0].detail.as_ref().unwrap().usage;
    let mut accepted = TAIL_ARGS.to_vec();
    accepted.sort_unstable();
    assert_eq!(
        crate::core::test_support::usage_option_names(usage),
        accepted,
        "{usage}"
    );
}
