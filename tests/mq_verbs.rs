//! Integration tests for `mq://` through the built `resh` binary, each in
//! its own temporary state directory (XDG_STATE_HOME): every verb, the
//! error format and exit codes, concurrent producer and consumer
//! processes, and help output (golden files).

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const VERBS: &[&str] = &["len", "peek", "create", "put", "get", "purge"];

/// The options each verb accepts (src/handles/data/mqh.rs `verb_args`).
fn options_for(verb: &str) -> Vec<&'static str> {
    match verb {
        "len" | "peek" | "create" => vec![],
        "put" => vec!["data", "timeout_ms"],
        "get" | "purge" => vec!["timeout_ms"],
        _ => unreachable!(),
    }
}

struct Run {
    code: i32,
    stdout: Vec<u8>,
    stderr: String,
}

impl Run {
    fn text(&self) -> String {
        String::from_utf8(self.stdout.clone()).unwrap()
    }
}

struct State {
    dir: tempfile::TempDir,
}

impl State {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }
    fn state_home(&self) -> PathBuf {
        self.dir.path().join("state")
    }
    fn queue_dir(&self, q: &str) -> PathBuf {
        self.state_home().join("resh").join("mq").join(q)
    }
    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_resh"));
        cmd.env_remove("SSH_AUTH_SOCK")
            .env("HOME", self.dir.path())
            .env("XDG_STATE_HOME", self.state_home())
            .args(args);
        cmd
    }
    fn run_in(&self, args: &[&str], stdin: &[u8]) -> Run {
        let mut child = self
            .cmd(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        let out = child.wait_with_output().unwrap();
        Run {
            code: out.status.code().unwrap_or(-1),
            stdout: out.stdout,
            stderr: String::from_utf8(out.stderr).unwrap(),
        }
    }
    fn run(&self, args: &[&str]) -> Run {
        self.run_in(args, b"")
    }
}

/// Asserts a failure: exit code and one `Error: [code] ...` line on stderr,
/// nothing on stdout.
fn assert_fail(r: &Run, exit: i32, code: &str) {
    assert_eq!(r.code, exit, "{}", r.stderr);
    assert!(
        r.stderr.starts_with(&format!("Error: [{code}] ")),
        "{}",
        r.stderr
    );
    assert_eq!(r.stderr.lines().count(), 1, "{}", r.stderr);
    assert!(r.stdout.is_empty(), "{:?}", r.text());
}

fn assert_ok(r: &Run) {
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stderr, "");
}

fn mode(p: &Path) -> u32 {
    std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}

#[test]
fn every_verb_works_through_the_binary() {
    let s = State::new();
    assert_ok(&s.run(&["mq://jobs.create"]));
    assert_eq!(mode(&s.queue_dir("jobs")), 0o700);
    let r = s.run(&["mq://jobs.put", "data=backup-db"]);
    assert_ok(&r);
    assert!(r.stdout.is_empty());
    assert_ok(&s.run_in(&["mq://jobs.put"], b"from stdin\n"));
    let r = s.run(&["mq://jobs.len"]);
    assert_ok(&r);
    assert_eq!(r.text(), "2");
    assert_eq!(s.run(&["mq://jobs.peek"]).text(), "backup-db");
    let r = s.run(&["mq://jobs.get"]);
    assert_ok(&r);
    assert_eq!(r.text(), "backup-db");
    assert_eq!(s.run(&["mq://jobs.get"]).text(), "from stdin\n");
    assert_fail(&s.run(&["mq://jobs.get"]), 1, "mq.empty");
    assert_fail(&s.run(&["mq://jobs.peek"]), 1, "mq.empty");
    // Arguments inside the stage work the same way.
    assert_ok(&s.run(&["mq://jobs.put(data=x)"]));
    assert_ok(&s.run(&["mq://jobs.purge"]));
    assert_eq!(s.run(&["mq://jobs.len"]).text(), "0");
}

#[test]
fn binary_messages_round_trip() {
    let s = State::new();
    let bytes: Vec<u8> = (0..=255u8).cycle().take(300_000).collect();
    assert_ok(&s.run_in(&["mq://bin.put"], &bytes));
    let r = s.run(&["mq://bin.get"]);
    assert_ok(&r);
    assert_eq!(r.stdout, bytes);
}

#[test]
fn messages_are_owner_only() {
    let s = State::new();
    assert_ok(&s.run(&["mq://sec.put", "data=token"]));
    let q = s.queue_dir("sec");
    for d in [
        q.parent().unwrap().to_path_buf(),
        q.clone(),
        q.join("_inflight"),
        q.join(".tmp"),
    ] {
        assert_eq!(mode(&d), 0o700, "{}", d.display());
    }
    for f in std::fs::read_dir(&q).unwrap().flatten() {
        if f.file_type().unwrap().is_file() {
            assert_eq!(mode(&f.path()), 0o600, "{}", f.path().display());
        }
    }
}

#[test]
fn invalid_usage_exits_2_and_does_nothing() {
    let s = State::new();
    for (args, needle) in [
        (vec!["mq://jobs.put", "dta=x"], "did you mean `data`?"),
        (
            vec!["mq://jobs.len", "timeout_ms=5"],
            "does not take timeout_ms",
        ),
        (
            vec!["mq://jobs.get", "timeout_ms=soon"],
            "timeout_ms must be",
        ),
        (vec!["mq://jobs.gte"], "did you mean `get`?"),
    ] {
        let r = s.run(&args);
        assert_fail(&r, 2, "mq.invalid_argument");
        assert!(r.stderr.contains(needle), "{args:?}: {}", r.stderr);
    }
    let r = s.run(&["mq://jobs.purge", "dry_run=true"]);
    assert_eq!(r.code, 2);
    assert!(
        r.stderr.contains("does not support dry_run"),
        "{}",
        r.stderr
    );
    for target in ["mq://team/a.len", "mq://a%20b.len", "mq://.hidden.len"] {
        let r = s.run(&[target]);
        assert_fail(&r, 2, "mq.invalid_target");
    }
    assert!(!s.state_home().join("resh").exists());
}

#[test]
fn queues_live_under_xdg_state_home_or_home() {
    // (No state directory at all cannot be arranged for a child process on
    // Linux; that error is unit-tested in src/handles/data/mqh/tests.rs.)
    let s = State::new();
    assert_ok(&s.run(&["mq://jobs.put", "data=x"]));
    assert!(s.queue_dir("jobs").join("_inflight").is_dir());
    // A relative XDG_STATE_HOME is ignored: ~/.local/state is used.
    let mut cmd = s.cmd(&["mq://other.put", "data=y"]);
    let out = cmd
        .env("XDG_STATE_HOME", "relative/state")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(
        s.dir
            .path()
            .join(".local/state/resh/mq/other")
            .join("_inflight")
            .is_dir()
    );
}

#[test]
fn a_held_lock_times_out_with_124() {
    let s = State::new();
    assert_ok(&s.run(&["mq://busy.put", "data=kept"]));
    // flock(1) is in util-linux; skip the check where it is missing.
    let lock = s.queue_dir("busy").join(".seq");
    // Its own process group, so the sleep that inherits the lock is
    // stopped with it.
    let Ok(mut holder) = Command::new("flock")
        .arg(&lock)
        .args(["sleep", "30"])
        .process_group(0)
        .spawn()
    else {
        eprintln!("flock(1) not available; skipped");
        return;
    };
    // Wait until the holder has the lock.
    let started = std::time::Instant::now();
    loop {
        let r = s.run(&["mq://busy.get", "timeout_ms=1"]);
        if r.code == 124 {
            break;
        }
        assert_eq!(r.code, 1, "{}", r.stderr);
        assert!(started.elapsed().as_secs() < 5, "lock never held");
        // The lock was free: put the message back for the next try.
        assert_ok(&s.run(&["mq://busy.put", "data=kept"]));
    }
    let r = s.run(&["mq://busy.put", "data=x", "timeout_ms=200"]);
    assert_fail(&r, 124, "mq.timeout");
    assert!(r.stderr.contains("nothing was done"), "{}", r.stderr);
    assert_eq!(s.run(&["mq://busy.len"]).text(), "1");
    // SAFETY: signals only the holder's own process group.
    unsafe { libc::kill(-(holder.id() as libc::pid_t), libc::SIGKILL) };
    holder.wait().unwrap();
    assert_eq!(s.run(&["mq://busy.get"]).text(), "kept");
}

#[test]
fn a_consumer_whose_stdout_closes_does_not_lose_the_message() {
    let s = State::new();
    // A large message, so the write to a closed pipe fails.
    let big = vec![b'x'; 4 * 1024 * 1024];
    assert_ok(&s.run_in(&["mq://p.put"], &big));
    let mut child = s
        .cmd(&["mq://p.get"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    assert_ne!(out.status.code(), Some(0));
    assert_eq!(s.run(&["mq://p.len"]).text(), "1");
    assert_eq!(s.run(&["mq://p.get"]).stdout.len(), big.len());
}

/// Producer and consumer processes run at the same time: every message is
/// taken exactly once and each producer's messages come out in order.
#[test]
fn parallel_processes_lose_and_duplicate_nothing() {
    const PRODUCERS: usize = 4;
    const PER: usize = 25;
    let s = Arc::new(State::new());
    assert_ok(&s.run(&["mq://par.create"]));
    let done = Arc::new(AtomicBool::new(false));
    let producers: Vec<_> = (0..PRODUCERS)
        .map(|p| {
            let s = s.clone();
            std::thread::spawn(move || {
                for i in 0..PER {
                    let data = format!("data={p}:{i}");
                    assert_ok(&s.run(&["mq://par.put", &data]));
                }
            })
        })
        .collect();
    let consumers: Vec<_> = (0..4)
        .map(|_| {
            let (s, done) = (s.clone(), done.clone());
            std::thread::spawn(move || {
                let mut got = Vec::new();
                loop {
                    let finished = done.load(Ordering::SeqCst);
                    let r = s.run(&["mq://par.get"]);
                    match r.code {
                        0 => got.push(r.text()),
                        1 if r.stderr.starts_with("Error: [mq.empty]") => {
                            if finished {
                                break;
                            }
                        }
                        _ => panic!("get failed: {}", r.stderr),
                    }
                }
                got
            })
        })
        .collect();
    for p in producers {
        p.join().unwrap();
    }
    done.store(true, Ordering::SeqCst);
    let mut per_consumer = Vec::new();
    for c in consumers {
        per_consumer.push(c.join().unwrap());
    }
    let mut all: Vec<String> = per_consumer.iter().flatten().cloned().collect();
    all.sort();
    let mut want: Vec<String> = (0..PRODUCERS)
        .flat_map(|p| (0..PER).map(move |i| format!("{p}:{i}")))
        .collect();
    want.sort();
    assert_eq!(all, want, "lost or duplicated messages");
    // Each consumer saw each producer's messages in increasing order.
    for got in &per_consumer {
        let mut last = [-1i64; PRODUCERS];
        for m in got {
            let (p, i) = m.split_once(':').unwrap();
            let (p, i): (usize, i64) = (p.parse().unwrap(), i.parse().unwrap());
            assert!(i > last[p], "out of order: {got:?}");
            last[p] = i;
        }
    }
    assert_eq!(s.run(&["mq://par.len"]).text(), "0");
    let q = s.queue_dir("par");
    assert_eq!(std::fs::read_dir(q.join("_inflight")).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(q.join(".tmp")).unwrap().count(), 0);
}

#[test]
fn every_error_code_is_documented() {
    let doc = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/Data_StateManagement/mq.md"),
    )
    .unwrap();
    for code in [
        "invalid_argument",
        "invalid_target",
        "empty",
        "timeout",
        "no_state_dir",
        "unsafe_path",
        "io_error",
    ] {
        assert!(doc.contains(&format!("`mq.{code}`")), "{code}");
    }
}

// ------------------------------------------------------------------ help --

fn assert_plain(out: &str) {
    assert!(out.is_ascii(), "non-ASCII");
    for line in out.lines() {
        assert!(line.len() <= 80, "line over 80 columns: {line:?}");
        assert!(!line.ends_with(' '), "trailing space: {line:?}");
    }
}

fn golden(verb: &str) -> &'static str {
    match verb {
        "len" => include_str!("golden/mq_len_help.txt"),
        "peek" => include_str!("golden/mq_peek_help.txt"),
        "create" => include_str!("golden/mq_create_help.txt"),
        "put" => include_str!("golden/mq_put_help.txt"),
        "get" => include_str!("golden/mq_get_help.txt"),
        "purge" => include_str!("golden/mq_purge_help.txt"),
        _ => unreachable!(),
    }
}

#[test]
fn handle_help_matches_golden() {
    let s = State::new();
    let r = s.run(&["mq", "--help"]);
    assert_ok(&r);
    let out = r.text();
    assert_plain(&out);
    assert_eq!(out, include_str!("golden/mq_help.txt"));
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
    let mut want = VERBS.to_vec();
    let mut got = listed.clone();
    want.sort();
    got.sort();
    assert_eq!(got, want);
    for alt in [
        &["mq", "-h"][..],
        &["mq", "help"][..],
        &["help", "mq"][..],
        &["mq://--help"][..],
        &["mq://jobs.help"][..],
    ] {
        assert_eq!(s.run(alt).text(), out, "{alt:?}");
    }
}

/// The `name=` options in a usage block.
fn usage_options(out: &str) -> Vec<String> {
    let usage = out
        .split("Usage:\n")
        .nth(1)
        .unwrap()
        .split("\n\n")
        .next()
        .unwrap();
    let mut v: Vec<String> = usage
        .split(|c: char| c.is_whitespace() || matches!(c, '[' | ']' | '|'))
        .filter_map(|w| w.split_once('=').map(|(k, _)| k.to_string()))
        .filter(|k| !k.is_empty() && !k.contains(':'))
        .collect();
    v.sort();
    v.dedup();
    v
}

#[test]
fn verb_help_matches_golden_and_lists_every_option() {
    let s = State::new();
    for verb in VERBS {
        let r = s.run(&["mq", verb, "--help"]);
        assert_ok(&r);
        let out = r.text();
        assert_plain(&out);
        assert!(out.starts_with(&format!("Handle: mq\nVerb: {verb}\nDefinition: ")));
        assert_eq!(out, golden(verb), "{verb}: help differs from golden");
        let mut want: Vec<String> = options_for(verb).iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(usage_options(&out), want, "{verb}");
        for alt in [
            vec!["mq".to_string(), verb.to_string(), "-h".into()],
            vec!["help".into(), "mq".into(), verb.to_string()],
            vec![format!("mq://--help={verb}")],
            vec![format!("mq://jobs.{verb}(help=1)")],
        ] {
            let argv: Vec<&str> = alt.iter().map(String::as_str).collect();
            assert_eq!(s.run(&argv).text(), out, "{alt:?}");
        }
    }
    // Help never creates a queue.
    assert!(!s.state_home().join("resh").exists());
}

/// Runs every verb's help example in one fresh state directory, in an
/// order where each prints its documented example output.
#[test]
fn help_examples_run_and_print_their_example_output() {
    let s = State::new();
    for verb in ["create", "put", "put", "len", "peek", "get", "purge"] {
        let help = s.run(&["mq", verb, "--help"]).text();
        let example = help
            .split("Example:\n  ")
            .nth(1)
            .unwrap()
            .lines()
            .next()
            .unwrap();
        let argv: Vec<&str> = example.split_whitespace().collect();
        assert_eq!(argv[0], "resh");
        let r = s.run(&argv[1..]);
        assert_ok(&r);
        match verb {
            "len" | "peek" | "get" => {
                let shown = help
                    .split("Example Output:\n")
                    .nth(1)
                    .unwrap()
                    .split("\n\n")
                    .next()
                    .unwrap()
                    .trim();
                assert_eq!(r.text(), shown, "{verb}");
            }
            _ => assert!(r.stdout.is_empty(), "{verb}"),
        }
    }
    assert_eq!(s.run(&["mq://jobs.len"]).text(), "0");
}
