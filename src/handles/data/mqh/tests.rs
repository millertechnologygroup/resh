//! Unit tests for mq://, run through `Handle::call` against queues in a
//! temporary state directory.

use super::*;
use std::collections::BTreeMap;
use std::io::Cursor;
use std::os::unix::fs::symlink;

struct Out {
    status: Status,
    stdout: Vec<u8>,
}

impl Out {
    fn text(&self) -> String {
        String::from_utf8(self.stdout.clone()).unwrap()
    }
    fn reason(&self) -> &str {
        self.status.reason.as_deref().unwrap_or("")
    }
    /// Asserts a coded failure.
    fn fails(&self, exit: i32, code: &str) -> &Self {
        assert!(!self.status.ok, "expected failure, got ok");
        assert_eq!(self.status.exit_code(), exit, "{}", self.reason());
        assert!(
            self.reason().starts_with(&format!("[{code}] ")),
            "{}",
            self.reason()
        );
        self
    }
    fn says(&self, text: &str) -> &Self {
        assert!(
            self.reason().contains(text),
            "{:?} lacks {text:?}",
            self.reason()
        );
        self
    }
    fn ok(&self) -> &Self {
        assert!(self.status.ok, "{}", self.reason());
        self
    }
}

fn call_in(h: &MQHandle, verb: &str, args: &[(&str, &str)], stdin: &[u8]) -> Out {
    let args: Args = args
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let mut i = Cursor::new(stdin.to_vec());
    let (mut o, mut e) = (Vec::new(), Vec::new());
    let status = {
        let mut io = IoStreams {
            stdin: &mut i,
            stdout: &mut o,
            stderr: &mut e,
        };
        h.call(verb, &args, &mut io).unwrap()
    };
    Out { status, stdout: o }
}

fn call(h: &MQHandle, verb: &str, args: &[(&str, &str)]) -> Out {
    call_in(h, verb, args, b"")
}

struct Env {
    dir: tempfile::TempDir,
    root: PathBuf,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("state").join("resh").join("mq");
    Env { dir, root }
}

impl Env {
    fn q(&self, name: &str) -> MQHandle {
        MQHandle::at(Some(self.root.clone()), name)
    }
    fn qdir(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

fn mode(p: &Path) -> u32 {
    fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}

fn get_text(h: &MQHandle) -> String {
    let r = call(h, "get", &[]);
    r.ok();
    r.text()
}

// --- help -------------------------------------------------------------------

fn help_out(verb: &str, args: &[(&str, &str)]) -> Option<String> {
    let h = MQHandle::at(Some(PathBuf::from("/nonexistent-resh-mq-test")), "t");
    let args: Args = args
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
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
    let r = h.check_and_display_help(verb, &args, &mut io).unwrap();
    r.map(|_| String::from_utf8(o.into_inner()).unwrap())
}

#[test]
fn legacy_help_forms_render_approved_help() {
    assert!(help_out("help", &[]).unwrap().starts_with("Handle: mq"));
    assert!(help_out("-h", &[]).unwrap().starts_with("Handle: mq"));
    assert!(
        help_out("help", &[("verb", "put")])
            .unwrap()
            .contains("Verb: put")
    );
    assert!(help_out("--help=get", &[]).unwrap().contains("Verb: get"));
    assert!(
        help_out("len", &[("help", "peek")])
            .unwrap()
            .contains("Verb: peek")
    );
}

#[test]
fn normal_verbs_are_not_help() {
    assert!(help_out("put", &[("data", "my-hosts")]).is_none());
    assert!(help_out("len", &[]).is_none());
}

#[test]
fn every_verb_has_its_arguments_in_the_help_usage() {
    for v in MQ_HELP.verbs {
        let usage = v.detail.as_ref().unwrap().usage;
        for a in verb_args(v.name).unwrap() {
            assert!(usage.contains(&format!("{a}=")), "{}: {a}", v.name);
        }
    }
}

// --- targets ----------------------------------------------------------------

#[test]
fn queue_names_are_checked_not_rewritten() {
    for ok in ["mq://jobs", "mq://Jobs-1.v2_x", "mq://jobs/", "mq://a"] {
        let u = Url::parse(ok).unwrap();
        assert!(queue_name(&u).is_ok(), "{ok}: {:?}", queue_name(&u));
    }
    assert_eq!(
        queue_name(&Url::parse("mq://Jobs").unwrap()).unwrap(),
        "Jobs"
    );
    let long = format!("mq://{}", "a".repeat(121));
    for bad in [
        "mq://",
        "mq://team/a",
        "mq://a%20b",
        "mq://.hidden",
        "mq://..",
        "mq://user@jobs",
        "mq://jobs:5",
        "mq://jobs?x=1",
        "mq://jobs#f",
        long.as_str(),
    ] {
        let Ok(u) = Url::parse(bad) else { continue };
        let e = queue_name(&u).unwrap_err();
        assert!(e.contains("queue"), "{bad}: {e}");
    }
    assert!(queue_name(&Url::parse(&format!("mq://{}", "a".repeat(120))).unwrap()).is_ok());
}

#[test]
fn no_state_dir_is_refused_without_a_tmp_fallback() {
    let h = MQHandle::at(None, "jobs");
    for verb in ["len", "peek", "create", "get", "purge"] {
        call(&h, verb, &[]).fails(1, "mq.no_state_dir");
    }
    call(&h, "put", &[("data", "x")]).fails(1, "mq.no_state_dir");
}

// --- arguments --------------------------------------------------------------

#[test]
fn unknown_arguments_are_refused_with_a_suggestion() {
    let e = env();
    let h = e.q("jobs");
    call(&h, "put", &[("dta", "x")])
        .fails(2, "mq.invalid_argument")
        .says("did you mean `data`?");
    call(&h, "get", &[("timeout", "5")])
        .fails(2, "mq.invalid_argument")
        .says("did you mean `timeout_ms`?");
    call(&h, "len", &[("x", "1")])
        .fails(2, "mq.invalid_argument")
        .says("takes no arguments");
    // Nothing was created by a refused call.
    assert!(!e.root.exists());
}

#[test]
fn timeout_ms_is_refused_where_nothing_waits() {
    let e = env();
    for verb in ["len", "peek", "create"] {
        call(&e.q("jobs"), verb, &[("timeout_ms", "100")])
            .fails(2, "mq.invalid_argument")
            .says("does not take timeout_ms");
    }
}

#[test]
fn timeout_ms_must_be_a_number() {
    let e = env();
    for bad in ["", "-1", "1.5", "soon"] {
        call(&e.q("jobs"), "get", &[("timeout_ms", bad)])
            .fails(2, "mq.invalid_argument")
            .says("timeout_ms must be");
    }
    // 0 means no limit.
    call(&e.q("jobs"), "put", &[("data", "a"), ("timeout_ms", "0")]).ok();
}

#[test]
fn dry_run_false_is_accepted_and_unknown_verbs_suggest() {
    let e = env();
    call(&e.q("jobs"), "put", &[("data", "a"), ("dry_run", "false")]).ok();
    call(&e.q("jobs"), "pop", &[])
        .fails(2, "mq.invalid_argument")
        .says("unknown mq verb");
    call(&e.q("jobs"), "gte", &[])
        .fails(2, "mq.invalid_argument")
        .says("did you mean `get`?");
}

// --- verbs ------------------------------------------------------------------

#[test]
fn put_get_is_fifo_and_len_peek_follow() {
    let e = env();
    let h = e.q("jobs");
    for m in ["one", "two", "three"] {
        let r = call(&h, "put", &[("data", m)]);
        r.ok();
        assert!(r.stdout.is_empty());
    }
    assert_eq!(call(&h, "len", &[]).text(), "3");
    assert_eq!(call(&h, "peek", &[]).text(), "one");
    assert_eq!(call(&h, "len", &[]).text(), "3");
    assert_eq!(get_text(&h), "one");
    assert_eq!(get_text(&h), "two");
    assert_eq!(call(&h, "len", &[]).text(), "1");
    assert_eq!(get_text(&h), "three");
    assert_eq!(call(&h, "len", &[]).text(), "0");
    call(&h, "get", &[])
        .fails(1, "mq.empty")
        .says("\"jobs\" is empty");
    call(&h, "peek", &[]).fails(1, "mq.empty");
    // Nothing is left in flight or half-written.
    let p = h.paths().unwrap();
    assert_eq!(fs::read_dir(&p.inflight).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&p.tmp).unwrap().count(), 0);
}

#[test]
fn put_reads_stdin_binary_safe_and_data_wins_over_stdin() {
    let e = env();
    let h = e.q("bin");
    let bytes: Vec<u8> = (0..=255u8).cycle().take(200_000).collect();
    call_in(&h, "put", &[], &bytes).ok();
    call_in(&h, "put", &[("data", "arg")], b"ignored").ok();
    call_in(&h, "put", &[], b"").ok();
    assert_eq!(call(&h, "get", &[]).stdout, bytes);
    assert_eq!(get_text(&h), "arg");
    let r = call(&h, "get", &[]);
    r.ok();
    assert!(r.stdout.is_empty(), "empty message");
    call(&h, "get", &[]).fails(1, "mq.empty");
}

#[test]
fn data_is_stored_exactly() {
    let e = env();
    let h = e.q("exact");
    call(&h, "put", &[("data", "  spaced \n")]).ok();
    assert_eq!(get_text(&h), "  spaced \n");
}

#[test]
fn read_only_verbs_do_not_create_a_queue() {
    let e = env();
    let h = e.q("ghost");
    assert_eq!(call(&h, "len", &[]).text(), "0");
    call(&h, "peek", &[]).fails(1, "mq.empty");
    call(&h, "get", &[]).fails(1, "mq.empty");
    call(&h, "purge", &[]).ok();
    assert!(!e.root.exists());
}

#[test]
fn create_is_idempotent_and_owner_only() {
    let e = env();
    let h = e.q("jobs");
    call(&h, "create", &[]).ok();
    call(&h, "create", &[]).ok();
    let q = e.qdir("jobs");
    for d in [
        e.root.clone(),
        q.clone(),
        q.join(".tmp"),
        q.join("_inflight"),
    ] {
        assert_eq!(mode(&d), 0o700, "{}", d.display());
    }
    call(&h, "put", &[("data", "secret")]).ok();
    let files: Vec<_> = fs::read_dir(&q)
        .unwrap()
        .flatten()
        .filter(|e| e.file_type().unwrap().is_file())
        .collect();
    assert_eq!(files.len(), 2, "message and .seq");
    for f in files {
        assert_eq!(mode(&f.path()), 0o600, "{}", f.path().display());
    }
}

#[test]
fn existing_permissive_directories_are_tightened() {
    let e = env();
    let q = e.qdir("old");
    fs::create_dir_all(q.join("_inflight")).unwrap();
    for d in [&e.root, &q, &q.join("_inflight")] {
        fs::set_permissions(d, fs::Permissions::from_mode(0o755)).unwrap();
    }
    call(&e.q("old"), "put", &[("data", "x")]).ok();
    for d in [&e.root, &q, &q.join("_inflight")] {
        assert_eq!(mode(d), 0o700, "{}", d.display());
    }
}

#[test]
fn messages_from_older_versions_keep_their_order() {
    let e = env();
    let q = e.qdir("legacy");
    fs::create_dir_all(q.join("_inflight")).unwrap();
    fs::write(q.join("01792761003306294654.msg"), "old-1").unwrap();
    fs::write(q.join("01792761003306294999.msg"), "old-2").unwrap();
    // A partial write of an older version: not a message.
    fs::write(q.join("tmp-1792761003306295000.msg"), "partial").unwrap();
    let h = e.q("legacy");
    assert_eq!(call(&h, "len", &[]).text(), "2");
    call(&h, "put", &[("data", "new")]).ok();
    assert_eq!(get_text(&h), "old-1");
    assert_eq!(get_text(&h), "old-2");
    assert_eq!(get_text(&h), "new");
    call(&h, "get", &[]).fails(1, "mq.empty");
    call(&h, "purge", &[]).ok();
    assert!(!q.join("tmp-1792761003306295000.msg").exists());
}

#[test]
fn a_damaged_counter_never_overwrites_a_message() {
    let e = env();
    let h = e.q("seq");
    call(&h, "put", &[("data", "a")]).ok();
    call(&h, "put", &[("data", "b")]).ok();
    // Counter reset to 1 (as if lost), then garbage.
    fs::write(e.qdir("seq").join(".seq"), "00000000000000000001\n").unwrap();
    call(&h, "put", &[("data", "c")]).ok();
    fs::write(e.qdir("seq").join(".seq"), "garbage").unwrap();
    call(&h, "put", &[("data", "d")]).ok();
    let got: Vec<String> = (0..4).map(|_| get_text(&h)).collect();
    assert_eq!(got, ["a", "b", "c", "d"]);
}

#[test]
fn purge_deletes_queued_and_in_flight_messages() {
    let e = env();
    let h = e.q("p");
    for m in ["a", "b"] {
        call(&h, "put", &[("data", m)]).ok();
    }
    let p = h.paths().unwrap();
    fs::write(p.inflight.join("00000000000000000099.msg"), "stuck").unwrap();
    // A temp file of a put whose process is gone, and one of a live put.
    fs::write(p.tmp.join("999999999-dead"), "x").unwrap();
    let live = p.tmp.join(format!("{}-live", std::process::id()));
    fs::write(&live, "x").unwrap();
    call(&h, "purge", &[]).ok();
    assert_eq!(call(&h, "len", &[]).text(), "0");
    assert_eq!(fs::read_dir(&p.inflight).unwrap().count(), 0);
    assert!(!p.tmp.join("999999999-dead").exists());
    assert!(live.exists());
    call(&h, "purge", &[]).ok();
    // The counter survives: numbers keep growing after a purge.
    call(&h, "put", &[("data", "c")]).ok();
    assert_eq!(get_text(&h), "c");
}

#[test]
fn symlinks_are_refused_or_ignored() {
    let e = env();
    let elsewhere = e.dir.path().join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    fs::create_dir_all(&e.root).unwrap();
    symlink(&elsewhere, e.qdir("evil")).unwrap();
    let h = e.q("evil");
    for verb in ["len", "peek", "create", "get", "purge"] {
        call(&h, verb, &[])
            .fails(1, "mq.unsafe_path")
            .says("symlink");
    }
    call(&h, "put", &[("data", "x")]).fails(1, "mq.unsafe_path");
    assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);

    // A symlink named like a message is not a message.
    let h = e.q("q");
    call(&h, "create", &[]).ok();
    let target = e.dir.path().join("target");
    fs::write(&target, "outside").unwrap();
    symlink(&target, e.qdir("q").join("00000000000000000001.msg")).unwrap();
    assert_eq!(call(&h, "len", &[]).text(), "0");
    call(&h, "get", &[]).fails(1, "mq.empty");

    // A planted symlink as the lock file is refused.
    let h = e.q("l");
    call(&h, "create", &[]).ok();
    symlink(&target, e.qdir("l").join(".seq")).unwrap();
    call(&h, "put", &[("data", "x")]).fails(1, "mq.unsafe_path");
    assert_eq!(fs::read_to_string(&target).unwrap(), "outside");
}

/// Holds the queue lock of `h` like another resh process would.
fn hold_lock(h: &MQHandle) -> File {
    call(h, "create", &[]).ok();
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(h.paths().unwrap().lock)
        .unwrap();
    // SAFETY: a valid descriptor.
    assert_eq!(unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) }, 0);
    f
}

#[test]
fn timeout_ms_bounds_the_wait_for_the_lock() {
    let e = env();
    let h = e.q("busy");
    call(&h, "put", &[("data", "kept")]).ok();
    let held = hold_lock(&h);
    let t = Instant::now();
    call(&h, "put", &[("data", "x"), ("timeout_ms", "100")])
        .fails(124, "mq.timeout")
        .says("nothing was done");
    assert!(t.elapsed() >= Duration::from_millis(100));
    assert!(t.elapsed() < Duration::from_secs(5));
    call(&h, "get", &[("timeout_ms", "50")]).fails(124, "mq.timeout");
    call(&h, "purge", &[("timeout_ms", "50")]).fails(124, "mq.timeout");
    // Reads take no lock.
    assert_eq!(call(&h, "len", &[]).text(), "1");
    assert_eq!(call(&h, "peek", &[]).text(), "kept");
    // The timed-out put left nothing behind.
    assert_eq!(fs::read_dir(h.paths().unwrap().tmp).unwrap().count(), 0);
    drop(held);
    assert_eq!(get_text(&h), "kept");
    call(&h, "get", &[]).fails(1, "mq.empty");
}

#[test]
fn without_timeout_ms_a_verb_waits_for_the_lock() {
    let e = env();
    let h = e.q("wait");
    let held = hold_lock(&h);
    let root = e.root.clone();
    let t = std::thread::spawn(move || {
        let h = MQHandle::at(Some(root), "wait");
        call(&h, "put", &[("data", "late")]).status.ok
    });
    std::thread::sleep(Duration::from_millis(150));
    assert!(!t.is_finished());
    assert_eq!(call(&h, "len", &[]).text(), "0");
    drop(held);
    assert!(t.join().unwrap());
    assert_eq!(get_text(&h), "late");
}

/// A stdout that fails every write.
struct Broken;
impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_message_that_cannot_be_written_out_goes_back_to_the_head() {
    let e = env();
    let h = e.q("pipe");
    call(&h, "put", &[("data", "first")]).ok();
    call(&h, "put", &[("data", "second")]).ok();
    let mut i = io::empty();
    let (mut o, mut err) = (Broken, Vec::new());
    let mut io = IoStreams {
        stdin: &mut i,
        stdout: &mut o,
        stderr: &mut err,
    };
    let st = h.call("get", &Args::new(), &mut io).unwrap();
    assert_eq!(st.exit_code(), 1);
    let reason = st.reason.unwrap();
    assert!(reason.starts_with("[mq.io_error] "), "{reason}");
    assert!(reason.contains("put back in the queue"), "{reason}");
    assert_eq!(call(&h, "len", &[]).text(), "2");
    assert_eq!(get_text(&h), "first");
}

#[test]
fn stdin_read_errors_queue_nothing() {
    struct BadIn;
    impl Read for BadIn {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("boom"))
        }
    }
    let e = env();
    let h = e.q("in");
    let mut i = BadIn;
    let (mut o, mut err) = (Vec::new(), Vec::new());
    let mut io = IoStreams {
        stdin: &mut i,
        stdout: &mut o,
        stderr: &mut err,
    };
    let st = h.call("put", &Args::new(), &mut io).unwrap();
    assert_eq!(st.exit_code(), 1);
    let reason = st.reason.unwrap();
    assert!(
        reason.starts_with("[mq.io_error] cannot read the message from stdin"),
        "{reason}"
    );
    assert_eq!(call(&h, "len", &[]).text(), "0");
    assert_eq!(fs::read_dir(h.paths().unwrap().tmp).unwrap().count(), 0);
}

#[test]
fn concurrent_producers_and_consumers_lose_and_duplicate_nothing() {
    const PRODUCERS: usize = 4;
    const PER: usize = 50;
    let e = env();
    call(&e.q("c"), "create", &[]).ok();
    let producers: Vec<_> = (0..PRODUCERS)
        .map(|p| {
            let h = e.q("c");
            std::thread::spawn(move || {
                for i in 0..PER {
                    let m = format!("{p}:{i}");
                    let r = call(&h, "put", &[("data", &m)]);
                    assert!(r.status.ok, "{}", r.reason());
                }
            })
        })
        .collect();
    let consumers: Vec<_> = (0..4)
        .map(|_| {
            let h = e.q("c");
            std::thread::spawn(move || {
                let mut got = Vec::new();
                let mut idle = 0;
                while idle < 100 {
                    let r = call(&h, "get", &[]);
                    if r.status.ok {
                        got.push(r.text());
                        idle = 0;
                    } else {
                        assert!(r.reason().starts_with("[mq.empty]"), "{}", r.reason());
                        idle += 1;
                        std::thread::sleep(Duration::from_millis(2));
                    }
                }
                got
            })
        })
        .collect();
    for p in producers {
        p.join().unwrap();
    }
    let mut all: Vec<String> = Vec::new();
    for c in consumers {
        all.extend(c.join().unwrap());
    }
    // Whatever the consumers did not get is still queued.
    let h = e.q("c");
    loop {
        let r = call(&h, "get", &[]);
        if !r.status.ok {
            break;
        }
        all.push(r.text());
    }
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for m in &all {
        *counts.entry(m.clone()).or_default() += 1;
    }
    assert!(counts.values().all(|c| *c == 1), "duplicates");
    assert_eq!(all.len(), PRODUCERS * PER, "lost messages");
}

#[test]
fn each_producer_s_messages_come_out_in_order() {
    let e = env();
    let producers: Vec<_> = (0..3)
        .map(|p| {
            let h = e.q("o");
            std::thread::spawn(move || {
                for i in 0..40 {
                    assert!(call(&h, "put", &[("data", &format!("{p}:{i}"))]).status.ok);
                }
            })
        })
        .collect();
    for p in producers {
        p.join().unwrap();
    }
    let h = e.q("o");
    let mut last = [-1i32; 3];
    for _ in 0..120 {
        let m = get_text(&h);
        let (p, i) = m.split_once(':').unwrap();
        let (p, i): (usize, i32) = (p.parse().unwrap(), i.parse().unwrap());
        assert_eq!(i, last[p] + 1, "{m}");
        last[p] = i;
    }
}

#[test]
fn error_codes_are_well_formed() {
    for c in ERROR_CODES {
        assert!(crate::core::status::is_valid_error_code(c), "{c}");
    }
}

#[test]
fn permission_errors_are_io_errors() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return; // root ignores directory permissions
    }
    let e = env();
    let parent = e.root.parent().unwrap().to_path_buf();
    fs::create_dir_all(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o500)).unwrap();
    call(&e.q("jobs"), "put", &[("data", "x")])
        .fails(1, "mq.io_error")
        .says("cannot create");
    call(&e.q("jobs"), "create", &[]).fails(1, "mq.io_error");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
}

// --- in-flight recovery -----------------------------------------------------

/// A PID that belonged to a process that has exited and been reaped.
fn dead_pid() -> u32 {
    let mut c = std::process::Command::new("true").spawn().unwrap();
    let pid = c.id();
    c.wait().unwrap();
    pid
}

fn plant_claim(h: &MQHandle, n: u64, claimer: Option<(u32, u64)>, body: &str) -> PathBuf {
    call(h, "create", &[]).ok();
    let name = match claimer {
        Some((pid, start)) => format!("{n:020}.{pid}.{start}.claim"),
        None => format!("{n:020}.msg"),
    };
    let path = h.paths().unwrap().inflight.join(name);
    fs::write(&path, body).unwrap();
    path
}

#[test]
fn claims_of_dead_or_reused_pids_are_redelivered_first_in_order() {
    let e = env();
    let h = e.q("r");
    call(&h, "put", &[("data", "queued")]).ok(); // number 1
    let (me, my_start) = self_identity();
    assert!(my_start > 0, "start time from /proc");
    // Move the queued message to number 50 so the claims (taken earlier,
    // lower numbers) come first.
    fs::rename(
        e.qdir("r").join(message_file_name(1)),
        e.qdir("r").join(message_file_name(50)),
    )
    .unwrap();
    fs::write(e.qdir("r").join(".seq"), "00000000000000000100\n").unwrap();
    let dead = plant_claim(&h, 5, Some((dead_pid(), 12345)), "dead");
    let reused = plant_claim(&h, 10, Some((me, my_start + 1)), "reused");
    let legacy = plant_claim(&h, 20, None, "legacy");
    let live = plant_claim(&h, 30, Some((me, my_start)), "live");
    assert_eq!(call(&h, "len", &[]).text(), "4");
    assert!(!dead.exists() && !reused.exists() && !legacy.exists());
    assert!(live.exists(), "a running claimer keeps its message");
    let got: Vec<String> = (0..4).map(|_| get_text(&h)).collect();
    assert_eq!(got, ["dead", "reused", "legacy", "queued"]);
    call(&h, "get", &[]).fails(1, "mq.empty");
    assert!(live.exists());
}

#[test]
fn claims_are_named_after_this_process() {
    let (pid, start) = self_identity();
    assert_eq!(pid, std::process::id());
    let name = claim_file_name(7);
    let c = parse_claim(&name).unwrap();
    assert_eq!((c.number, c.claimer), (7, Some((pid, start))));
    assert!(c.claimer_alive());
    for bad in ["x.claim", "1.2.3.claim", "00000000000000000001.a.3.claim"] {
        assert!(parse_claim(bad).is_none(), "{bad}");
    }
    assert!(matches!(proc_stat(dead_pid()), ProcState::Gone));
}

#[test]
fn peek_and_len_see_stale_messages_even_when_the_lock_is_busy() {
    let e = env();
    let h = e.q("busy");
    plant_claim(&h, 1, Some((dead_pid(), 1)), "stale");
    let held = hold_lock(&h);
    assert_eq!(call(&h, "len", &[]).text(), "1");
    drop(held);
    assert_eq!(call(&h, "peek", &[]).text(), "stale");
    assert_eq!(get_text(&h), "stale");
}

// --- get wait=true ----------------------------------------------------------

#[test]
fn wait_must_be_a_boolean_and_only_get_takes_it() {
    let e = env();
    call(&e.q("w"), "get", &[("wait", "maybe")])
        .fails(2, "mq.invalid_argument")
        .says("wait");
    call(&e.q("w"), "peek", &[("wait", "true")]).fails(2, "mq.invalid_argument");
    assert!(!e.root.exists());
}

#[test]
fn wait_defaults_to_30_seconds_and_timeout_ms_overrides_it() {
    let args = |kv: &[(&str, &str)]| -> Args {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    let d = deadline_arg(&args(&[]), true).unwrap().unwrap();
    let left = d.saturating_duration_since(Instant::now());
    assert!(left > Duration::from_secs(29) && left <= Duration::from_secs(30));
    assert!(deadline_arg(&args(&[]), false).unwrap().is_none());
    assert!(
        deadline_arg(&args(&[("timeout_ms", "0")]), true)
            .unwrap()
            .is_none()
    );
}

#[test]
fn get_wait_returns_a_message_put_later() {
    let e = env();
    let h = e.q("w");
    let producer = {
        let h = e.q("w");
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            assert!(call(&h, "put", &[("data", "late")]).status.ok);
        })
    };
    let t = Instant::now();
    let r = call(&h, "get", &[("wait", "true"), ("timeout_ms", "10000")]);
    r.ok();
    assert_eq!(r.text(), "late");
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    producer.join().unwrap();
}

#[test]
fn get_wait_times_out_with_124_and_creates_the_queue() {
    let e = env();
    let h = e.q("none");
    let t = Instant::now();
    call(&h, "get", &[("wait", "true"), ("timeout_ms", "150")])
        .fails(124, "mq.timeout")
        .says("no message arrived");
    assert!(t.elapsed() >= Duration::from_millis(150));
    assert!(e.qdir("none").is_dir());
    // wait=false keeps the old behaviour.
    call(&h, "get", &[("wait", "false")]).fails(1, "mq.empty");
}

#[test]
fn waiting_consumers_never_share_a_message() {
    let e = env();
    call(&e.q("ws"), "create", &[]).ok();
    let consumers: Vec<_> = (0..3)
        .map(|_| {
            let h = e.q("ws");
            std::thread::spawn(move || {
                let r = call(&h, "get", &[("wait", "true"), ("timeout_ms", "10000")]);
                assert!(r.status.ok, "{}", r.reason());
                r.text()
            })
        })
        .collect();
    std::thread::sleep(Duration::from_millis(100));
    let h = e.q("ws");
    for m in ["a", "b", "c"] {
        call(&h, "put", &[("data", m)]).ok();
    }
    let mut got: Vec<String> = consumers.into_iter().map(|c| c.join().unwrap()).collect();
    got.sort();
    assert_eq!(got, ["a", "b", "c"]);
    call(&h, "get", &[]).fails(1, "mq.empty");
}

#[test]
fn the_waker_uses_inotify_and_wakes_on_a_change() {
    let dir = tempfile::tempdir().unwrap();
    let mut w = Waker::new(dir.path());
    assert!(w.rx.is_some(), "inotify watcher");
    let path = dir.path().join("x");
    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        fs::write(path, "x").unwrap();
    });
    let t = Instant::now();
    // Far deadline: only the change (or the 500 ms poll) can end the wait.
    w.wait(Some(Instant::now() + Duration::from_secs(60)));
    assert!(t.elapsed() < Waker::POLL, "{:?}", t.elapsed());
    writer.join().unwrap();
    // The deadline bounds a wait with no change.
    let t = Instant::now();
    w.wait(Some(Instant::now() + Duration::from_millis(30)));
    assert!(t.elapsed() < Duration::from_millis(400));
}
