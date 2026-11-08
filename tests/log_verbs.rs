//! Integration tests for `log://` through the built `resh` binary: help
//! output (golden files) and its example run for real, every argument and
//! error path with its exit code and error line, follow mode streaming
//! through a pipe, and service journals through a fake `journalctl` put
//! first on PATH. Files live in temporary directories. The real journal is
//! queried in log_e2e_docker.rs.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The options `tail` accepts (src/handles/data/logh.rs `TAIL_ARGS`).
const TAIL_ARGS: &[&str] = &["follow", "lines", "mode", "pattern", "timeout_ms"];

struct Run {
    code: i32,
    out: String,
    err: String,
}

impl Run {
    fn json(&self) -> Value {
        serde_json::from_str(self.out.trim()).unwrap_or(Value::Null)
    }
    fn ok(self) -> Self {
        assert_eq!(self.code, 0, "{}\n{}", self.out, self.err);
        self
    }
    /// Exit status, and exactly one `Error: [code] ...` line on stderr.
    fn fails(self, exit: i32, code: &str) -> Self {
        assert_eq!(self.code, exit, "{}\n{}", self.out, self.err);
        let errors: Vec<&str> = self
            .err
            .lines()
            .filter(|l| l.starts_with("Error: "))
            .collect();
        assert_eq!(errors.len(), 1, "{}", self.err);
        assert!(
            errors[0].starts_with(&format!("Error: [{code}] ")),
            "{}",
            self.err
        );
        self
    }
}

struct Env {
    dir: tempfile::TempDir,
    path_var: Option<String>,
}

impl Env {
    fn new() -> Self {
        Env {
            dir: tempfile::TempDir::new().unwrap(),
            path_var: None,
        }
    }

    fn dir(&self) -> &Path {
        self.dir.path()
    }

    fn file(&self, name: &str, content: &[u8]) -> PathBuf {
        let p = self.dir().join(name);
        std::fs::write(&p, content).unwrap();
        p
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_resh"));
        cmd.env_remove("SSH_AUTH_SOCK")
            .env("HOME", self.dir())
            .current_dir(self.dir())
            .args(args);
        if let Some(p) = &self.path_var {
            cmd.env("PATH", p);
        }
        cmd
    }

    fn run(&self, args: &[&str]) -> Run {
        let out = self.cmd(args).stdin(Stdio::null()).output().unwrap();
        Run {
            code: out.status.code().unwrap_or(-1),
            out: String::from_utf8_lossy(&out.stdout).into_owned(),
            err: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// Puts a fake `journalctl` first on PATH: it records its arguments in
    /// `argv`, prints `stdout` and `stderr`, then runs `then`.
    fn fake_journalctl(&mut self, stdout: &str, stderr: &str, then: &str) {
        let bin = self.dir().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let script = format!(
            "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > '{}'\n\
             printf '%s' '{stdout}'\nprintf '%s' '{stderr}' >&2\n{then}\n",
            self.dir().join("argv").display()
        );
        let p = bin.join("journalctl");
        std::fs::write(&p, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        self.path_var = Some(format!("{}:/usr/bin:/bin", bin.display()));
    }

    /// A PATH with no journalctl on it.
    fn no_journalctl(&mut self) {
        let empty = self.dir().join("empty-bin");
        std::fs::create_dir_all(&empty).unwrap();
        self.path_var = Some(empty.display().to_string());
    }

    fn argv(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir().join("argv"))
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }
}

fn url(p: &Path, verb: &str) -> String {
    format!("log://{}.{verb}", p.display())
}

fn append(p: &Path, s: &str) {
    let mut f = std::fs::OpenOptions::new().append(true).open(p).unwrap();
    f.write_all(s.as_bytes()).unwrap();
}

// --- help ---------------------------------------------------------------------------

fn golden(verb: Option<&str>) -> &'static str {
    match verb {
        None => include_str!("golden/log_help.txt"),
        Some("tail") => include_str!("golden/log_tail_help.txt"),
        Some(v) => panic!("no golden for {v}"),
    }
}

fn assert_plain_text(out: &str) {
    assert!(out.is_ascii() && !out.contains('\x1b'));
    for l in out.lines() {
        assert!(l.len() <= 80, "line over 80 columns: {l:?}");
        assert!(!l.ends_with(' '), "trailing space: {l:?}");
    }
}

#[test]
fn handle_help_matches_golden_in_every_form() {
    let env = Env::new();
    for form in [
        vec!["log", "--help"],
        vec!["log", "-h"],
        vec!["log", "help"],
        vec!["help", "log"],
        vec!["log://--help"],
        vec!["log://-h"],
        vec!["log:///var/log/syslog.help"],
    ] {
        let r = env.run(&form).ok();
        assert_eq!(r.out, golden(None), "{form:?}");
    }
    let out = golden(None);
    assert_plain_text(out);
    let listed: Vec<&str> = out
        .split("Available Verbs:\n")
        .nth(1)
        .unwrap()
        .split("\n\n")
        .next()
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(listed, ["tail"]);
}

#[test]
fn tail_help_matches_golden_and_lists_exactly_the_accepted_options() {
    let env = Env::new();
    for form in [
        vec!["log", "tail", "--help"],
        vec!["log", "tail", "-h"],
        vec!["help", "log", "tail"],
        vec!["log://--help=tail"],
    ] {
        let r = env.run(&form).ok();
        assert_eq!(r.out, golden(Some("tail")), "{form:?}");
    }
    let out = golden(Some("tail"));
    assert_plain_text(out);
    for section in ["Usage:\n", "Example:\n", "Example Output:\n"] {
        assert!(out.contains(section), "{section}");
    }
    let usage = out
        .split("Usage:\n")
        .nth(1)
        .unwrap()
        .split("\n\n")
        .next()
        .unwrap();
    let mut listed: Vec<&str> = usage
        .split(['[', ' ', '\n'])
        .filter_map(|w| w.split_once('='))
        .map(|(k, _)| k.trim_start_matches('['))
        .filter(|k| !k.is_empty() && !k.contains('/'))
        .collect();
    listed.sort_unstable();
    listed.dedup();
    assert_eq!(listed, TAIL_ARGS, "{usage}");
}

#[test]
fn unknown_verb_help_is_an_error() {
    let env = Env::new();
    let r = env.run(&["log", "tial", "--help"]);
    assert_eq!(r.code, 2);
    assert!(r.err.contains("tail"), "{}", r.err);
    env.run(&["log://--help=tial"]).fails(2, "log.unknown_verb");
}

#[test]
fn help_example_runs() {
    // resh --json-pretty log:///var/log/syslog.tail lines=2 mode=json, on a
    // file with the example's lines at its end.
    let env = Env::new();
    let p = env.file(
        "syslog",
        b"Oct 16 09:12:40 host kernel: boot\n\
          Oct 16 09:12:44 host kernel: eth0: link up\n\
          Oct 16 09:13:02 host app[901]: error: disk quota exceeded\n",
    );
    let help = golden(Some("tail"));
    let example = help
        .split("Example:\n")
        .nth(1)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .trim();
    assert_eq!(
        example,
        "resh --json-pretty log:///var/log/syslog.tail lines=2 mode=json"
    );
    let shown = help
        .split("Example Output:\n")
        .nth(1)
        .unwrap()
        .split("\n\n")
        .next()
        .unwrap();
    let mut expected: Value = serde_json::from_str(shown).unwrap();
    expected["path"] = json!(p.to_string_lossy());
    let stage = url(&p, "tail");
    let r = env
        .run(&["--json-pretty", &stage, "lines=2", "mode=json"])
        .ok();
    assert_eq!(r.json(), expected);
    assert!(r.out.contains("\n  \"lines\": [\n"), "pretty: {}", r.out);
}

// --- files --------------------------------------------------------------------------

#[test]
fn tail_raw_json_pattern_and_function_call_form() {
    let env = Env::new();
    let p = env.file("app.log", b"a ok\nb ERROR one\nc ok\nd ERROR two\n");
    let r = env.run(&[&url(&p, "tail"), "lines=2"]).ok();
    assert_eq!(r.out, "c ok\nd ERROR two\n");
    let r = env
        .run(&[&url(&p, "tail"), "pattern=ERROR", "mode=json"])
        .ok();
    assert_eq!(
        r.json(),
        json!({"lines": ["b ERROR one", "d ERROR two"], "path": p.to_string_lossy(),
               "pattern": "ERROR", "requested_lines": 100, "returned_lines": 2})
    );
    let stage = format!("log://{}.tail(lines=1)", p.display());
    assert_eq!(env.run(&[&stage]).ok().out, "d ERROR two\n");
}

#[test]
fn relative_and_percent_encoded_paths() {
    let env = Env::new();
    env.file("rel.log", b"relative\n");
    assert_eq!(env.run(&["log://./rel.log.tail"]).ok().out, "relative\n");
    std::fs::create_dir(env.dir().join("sub")).unwrap();
    let mut cmd = env.cmd(&["log://../rel.log.tail"]);
    let out = cmd.current_dir(env.dir().join("sub")).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "relative\n");
    let p = env.file("my app.log", b"spaced\n");
    let stage = format!("log://{}.tail", p.display()).replace(' ', "%20");
    assert_eq!(env.run(&[&stage]).ok().out, "spaced\n");
}

#[test]
fn large_and_non_utf8_files() {
    let env = Env::new();
    let mut data = Vec::new();
    for i in 0..50_000 {
        data.extend(format!("line {i:06} {}\n", "x".repeat(i % 50)).bytes());
    }
    data.extend(b"\xff\xfe broken\n");
    let p = env.file("big.log", &data);
    let r = env.run(&[&url(&p, "tail"), "lines=3"]).ok();
    let lines: Vec<&str> = r.out.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].starts_with("line 049998"), "{}", lines[0]);
    assert_eq!(lines[2], "\u{fffd}\u{fffd} broken");
}

#[test]
fn invalid_arguments_exit_2_and_read_nothing() {
    let env = Env::new();
    let p = env.file("app.log", b"x\n");
    let stage = url(&p, "tail");
    for (arg, needle) in [
        ("line=5", "did you mean `lines`?"),
        ("lines=abc", "lines"),
        ("lines=0", "lines"),
        ("mode=xml", "mode"),
        ("pattern=", "pattern"),
        ("follow=maybe", "follow"),
        ("timeout_ms=0", "timeout_ms"),
        ("bogus=1", "unknown argument: bogus"),
    ] {
        let r = env.run(&[&stage, arg]).fails(2, "log.invalid_argument");
        assert!(r.err.contains(needle), "{arg}: {}", r.err);
        assert!(r.out.is_empty(), "{arg}: {}", r.out);
    }
    let r = env.run(&[&stage, "dry_run=true"]);
    assert_eq!(r.code, 2, "{}", r.err);
    assert!(r.err.contains("dry_run"), "{}", r.err);
    env.run(&[&stage, "dry_run=false"]).ok();
    // A missing file with a bad argument: the usage error, nothing read.
    env.run(&["log:///nonexistent/x.log.tail", "lines=abc"])
        .fails(2, "log.invalid_argument");
}

#[test]
fn invalid_targets_and_verbs_exit_2() {
    let env = Env::new();
    env.run(&["log://var/log/syslog.tail"])
        .fails(2, "log.invalid_target");
    for svc in ["-n", "a%20b", "x%3By"] {
        env.run(&[&format!("log://svc/{svc}.tail")])
            .fails(2, "log.invalid_target");
    }
    let r = env
        .run(&["log:///var/log/syslog.tial"])
        .fails(2, "log.unknown_verb");
    assert!(r.err.contains("did you mean `tail`?"), "{}", r.err);
}

#[test]
fn file_failures_exit_1_with_their_codes() {
    let env = Env::new();
    let missing = env.dir().join("missing.log");
    let r = env.run(&[&url(&missing, "tail")]).fails(1, "log.not_found");
    assert!(r.out.is_empty());
    let r = env
        .run(&[&url(&missing, "tail"), "mode=json", "lines=10"])
        .fails(1, "log.not_found");
    let v = r.json();
    assert_eq!(v["error"]["code"], "log.not_found");
    assert_eq!(v["path"], missing.to_string_lossy().as_ref());
    assert_eq!(v["returned_lines"], 0);
    env.run(&[&url(env.dir(), "tail")])
        .fails(1, "log.not_a_file");
    // SAFETY: getuid has no preconditions.
    if unsafe { libc::getuid() } != 0 {
        use std::os::unix::fs::PermissionsExt;
        let p = env.file("locked.log", b"x\n");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0)).unwrap();
        env.run(&[&url(&p, "tail")])
            .fails(1, "log.permission_denied");
    }
}

// --- follow -------------------------------------------------------------------------

/// Starts a follow, returning the child and a channel of its stdout lines.
fn spawn_follow(env: &Env, args: &[&str]) -> (std::process::Child, mpsc::Receiver<String>) {
    let mut child = env
        .cmd(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let out = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    (child, rx)
}

fn next(rx: &mpsc::Receiver<String>) -> String {
    rx.recv_timeout(Duration::from_secs(5))
        .expect("no line within 5 s")
}

#[test]
fn follow_streams_lines_as_they_are_written() {
    let env = Env::new();
    let p = env.file("app.log", b"first\n");
    let stage = url(&p, "tail");
    let start = Instant::now();
    let (mut child, rx) = spawn_follow(&env, &[&stage, "follow=true", "timeout_ms=4000"]);
    assert_eq!(next(&rx), "first");
    for i in 0..3 {
        append(&p, &format!("live {i}\n"));
        // Each line arrives while resh is still running: streamed, not
        // buffered until exit.
        assert_eq!(next(&rx), format!("live {i}"));
        assert!(child.try_wait().unwrap().is_none());
    }
    // timeout_ms is the follow duration: reaching it is a normal end.
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(0));
    assert!(start.elapsed() >= Duration::from_millis(4000));
    let mut err = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut err).unwrap();
    assert!(err.is_empty(), "{err}");
}

#[test]
fn follow_json_streams_one_object_per_line() {
    let env = Env::new();
    let p = env.file("app.log", b"first\n");
    let stage = url(&p, "tail");
    let (mut child, rx) = spawn_follow(
        &env,
        &[&stage, "follow=true", "mode=json", "timeout_ms=3000"],
    );
    let parse = |l: String| -> Value { serde_json::from_str(&l).unwrap() };
    let first = parse(next(&rx));
    assert_eq!(first["source"], "file");
    assert_eq!(first["path"], p.to_string_lossy().as_ref());
    assert_eq!(first["line"], "first");
    assert!(first["ts"].as_u64().unwrap() > 1_600_000_000_000);
    append(&p, "second\n");
    assert_eq!(parse(next(&rx))["line"], "second");
    assert!(child.try_wait().unwrap().is_none(), "streamed before exit");
    std::fs::write(&p, "").unwrap();
    std::thread::sleep(Duration::from_millis(400));
    append(&p, "third\n");
    let ev = parse(next(&rx));
    assert_eq!(ev["event"], "truncated");
    assert_eq!(parse(next(&rx))["line"], "third");
    assert_eq!(child.wait().unwrap().code(), Some(0));
}

#[test]
fn follow_ends_quietly_when_the_reader_goes_away() {
    let env = Env::new();
    let p = env.file("app.log", b"first\n");
    let stage = url(&p, "tail");
    let (mut child, rx) = spawn_follow(&env, &[&stage, "follow=true"]);
    assert_eq!(next(&rx), "first");
    drop(rx); // the reader thread ends at the next line, closing the pipe
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        append(&p, "more\n");
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(Instant::now() < deadline, "follow did not end");
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(status.code(), Some(0));
}

#[test]
fn follow_survives_rotation() {
    let env = Env::new();
    let p = env.file("app.log", b"one\n");
    let stage = url(&p, "tail");
    let (mut child, rx) = spawn_follow(&env, &[&stage, "follow=true", "timeout_ms=5000"]);
    assert_eq!(next(&rx), "one");
    std::fs::rename(&p, env.dir().join("app.log.1")).unwrap();
    std::fs::write(&p, "two\n").unwrap();
    assert_eq!(next(&rx), "two");
    std::fs::write(&p, "").unwrap();
    std::thread::sleep(Duration::from_millis(400));
    append(&p, "three\n");
    assert_eq!(next(&rx), "three");
    let _ = child.kill();
    let _ = child.wait();
}

// --- service journals ---------------------------------------------------------------

#[test]
fn journal_through_journalctl_on_path() {
    let mut env = Env::new();
    env.fake_journalctl(
        "Nov 07 10:00:00 box web[1]: up\nNov 07 10:00:01 box web[1]: error x\n",
        "",
        "exit 0",
    );
    let r = env.run(&["log://svc/web.service.tail", "lines=5"]).ok();
    assert_eq!(r.out.lines().count(), 2);
    assert_eq!(
        env.argv(),
        [
            "--unit=web.service",
            "--lines=5",
            "--no-pager",
            "--output=short"
        ]
    );
    let r = env
        .run(&["log://svc/web.tail", "mode=json", "pattern=error"])
        .ok();
    assert_eq!(
        r.json(),
        json!({"lines": ["Nov 07 10:00:01 box web[1]: error x"], "pattern": "error",
               "requested_lines": 100, "returned_lines": 1, "service": "web"})
    );
}

#[test]
fn journal_failures() {
    let mut env = Env::new();
    env.no_journalctl();
    env.run(&["log://svc/web.tail"])
        .fails(1, "log.journalctl_not_found");

    env.fake_journalctl("", "Failed to add match\n", "exit 5");
    let r = env
        .run(&["log://svc/web.tail", "mode=json"])
        .fails(1, "log.journal_failed");
    assert_eq!(r.json()["error"]["code"], "log.journal_failed");

    env.fake_journalctl(
        "",
        "Hint: You are currently not seeing messages from other users and the system.\n",
        "exit 0",
    );
    env.run(&["log://svc/web.tail"])
        .fails(1, "log.journal_access_denied");

    env.fake_journalctl("", "", "sleep 30");
    let start = Instant::now();
    env.run(&["log://svc/web.tail", "timeout_ms=300"])
        .fails(124, "log.timeout");
    assert!(start.elapsed() < Duration::from_secs(10));
}

#[test]
fn journal_follow_streams_and_stops_journalctl() {
    let mut env = Env::new();
    env.fake_journalctl("old\n", "", "sleep 1; printf 'new\\n'; exec sleep 30");
    let (mut child, rx) = spawn_follow(
        &env,
        &["log://svc/web.tail", "follow=true", "timeout_ms=3000"],
    );
    assert_eq!(next(&rx), "old");
    assert_eq!(next(&rx), "new");
    assert!(child.try_wait().unwrap().is_none());
    assert_eq!(child.wait().unwrap().code(), Some(0));
    assert_eq!(env.argv().last().map(String::as_str), Some("--follow"));
}
