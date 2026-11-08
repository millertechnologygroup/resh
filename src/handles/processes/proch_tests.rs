//! Unit and dispatch tests for `proc://`. Every signal, nice and limit change
//! goes to a `sleep` child this test spawned and owns; nothing else on the
//! host is touched. A PID that cannot exist (2147483647 is above the kernel's
//! pid_max limit) stands in for a vanished process.

use super::*;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Above PID_MAX_LIMIT (4194304): never a live process.
const GONE: libc::pid_t = libc::pid_t::MAX;

/// A `sleep` child, killed and reaped on drop.
struct Kid(Child);

impl Kid {
    fn spawn() -> Self {
        let mut cmd = Command::new("sleep");
        cmd.arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // Default dispositions and no blocked signals, whatever the test
        // runner inherited (a background job ignores INT and QUIT).
        unsafe {
            cmd.pre_exec(|| {
                let (_, rt_max) = sys::sig_rt_range();
                for sig in 1..=rt_max {
                    if sig != libc::SIGKILL && sig != libc::SIGSTOP {
                        libc::signal(sig, libc::SIG_DFL);
                    }
                }
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
                // The kernel checks the target's RLIMIT_NICE: with 0 only
                // root may lower the child's nice value.
                let r = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                libc::setrlimit(libc::RLIMIT_NICE, &r);
                Ok(())
            });
        }
        Kid(cmd.spawn().expect("spawn sleep"))
    }
    fn pid(&self) -> libc::pid_t {
        self.0.id() as libc::pid_t
    }
    /// Waits (up to 10 s) for the child to end.
    fn wait(&mut self) -> ExitStatus {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(st) = self.0.try_wait().unwrap() {
                return st;
            }
            assert!(Instant::now() < end, "child did not end");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn alive(&mut self) -> bool {
        self.0.try_wait().unwrap().is_none()
    }
    /// The state letter of /proc/<pid>/stat.
    fn state(&self) -> char {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", self.pid())).unwrap();
        stat.rsplit_once(") ").unwrap().1.chars().next().unwrap()
    }
    /// (soft, hard) from /proc/<pid>/limits for the row starting `row`.
    fn limit(&self, row: &str) -> (String, String) {
        let text = std::fs::read_to_string(format!("/proc/{}/limits", self.pid())).unwrap();
        let line = text.lines().find(|l| l.starts_with(row)).unwrap();
        let mut f = line[row.len()..].split_whitespace();
        (f.next().unwrap().into(), f.next().unwrap().into())
    }
}

impl Drop for Kid {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn signal_of(st: ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    st.signal()
}

struct Out {
    status: Status,
    stdout: String,
    stderr: String,
}

impl Out {
    fn json(&self) -> Value {
        serde_json::from_str(self.stdout.trim()).unwrap_or(Value::Null)
    }
    fn code(&self) -> i32 {
        self.status.exit_code()
    }
    /// Asserts a coded failure, printed in both places.
    fn fails(&self, exit: i32, code: &str) -> &Self {
        assert_eq!(self.code(), exit, "{} / {:?}", self.stdout, self.status);
        let full = format!("proc.{code}");
        assert!(
            self.status
                .reason
                .as_deref()
                .unwrap()
                .starts_with(&format!("[{full}] ")),
            "{:?}",
            self.status
        );
        let j = self.json();
        assert_eq!(j["error"]["code"], full, "{}", self.stdout);
        assert_eq!(j["ok"], false, "{}", self.stdout);
        assert!(ERROR_CODES.contains(&code));
        self
    }
    fn message(&self) -> String {
        self.json()["error"]["message"]
            .as_str()
            .unwrap()
            .to_string()
    }
}

fn call(target: &str, verb: &str, args: &[(&str, &str)]) -> Out {
    let h = ProcHandle::from_url(&Url::parse(&format!("proc://{target}")).unwrap()).unwrap();
    let args: Args = args
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
    let status = {
        let mut io = IoStreams::new(&mut i, &mut o, &mut e);
        h.call(verb, &args, &mut io).unwrap()
    };
    Out {
        status,
        stdout: String::from_utf8(o).unwrap(),
        stderr: String::from_utf8(e).unwrap(),
    }
}

fn on(kid: &Kid, verb: &str, args: &[(&str, &str)]) -> Out {
    call(&kid.pid().to_string(), verb, args)
}

/// True if this process may lower a child's nice value (the children have
/// RLIMIT_NICE 0, so only root may).
fn may_lower_nice_to(_target: i32) -> bool {
    is_root()
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

// ---------------------------------------------------------------------------
// Arguments and help
// ---------------------------------------------------------------------------

#[test]
fn verb_args_match_help_usage() {
    let all = ProcHandle {
        name: "self".into(),
    };
    for verb in PROC_HELP.verbs {
        let usage = verb.detail.as_ref().unwrap().usage;
        let mut in_usage: Vec<&str> = usage
            .split(|c: char| c == '[' || c.is_whitespace())
            .filter_map(|w| w.split_once('=').map(|(k, _)| k))
            .filter(|k| !k.is_empty() && !k.starts_with('<'))
            .collect();
        if let Some(line) = usage
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("resources:"))
        {
            in_usage.extend(line["resources:".len()..].split_whitespace());
        }
        in_usage.sort();
        let mut parsed = verb_args(verb.name).unwrap().to_vec();
        parsed.sort();
        assert_eq!(in_usage, parsed, "usage of {} disagrees", verb.name);
    }
    let mut registered: Vec<&str> = all.verbs().to_vec();
    let mut helped: Vec<&str> = PROC_HELP.verbs.iter().map(|v| v.name).collect();
    registered.sort();
    helped.sort();
    assert_eq!(registered, helped);
    for v in all.verbs() {
        assert!(verb_args(v).is_some(), "{v}");
    }
    let mut res: Vec<&str> = RESOURCES.to_vec();
    res.extend(["pid", "dry_run"]);
    res.sort();
    let mut la = LIMITS_SET_ARGS.to_vec();
    la.sort();
    assert_eq!(res, la);
}

#[test]
fn every_error_code_is_valid_and_documented() {
    let doc = include_str!("../../../docs/Process_ServiceManagement/proc.md");
    for code in ERROR_CODES {
        let full = format!("proc.{code}");
        assert!(crate::core::status::is_valid_error_code(&full), "{full}");
        assert!(doc.contains(&format!("`{full}`")), "{full} not in proc.md");
    }
}

#[test]
fn unknown_arguments_are_refused_before_anything_happens() {
    let mut kid = Kid::spawn();
    let all = ProcHandle {
        name: "self".into(),
    };
    for verb in all.verbs() {
        let o = on(&kid, verb, &[("bogus", "1")]);
        o.fails(2, "invalid_argument");
        assert!(o.message().contains("bogus"), "{verb}: {}", o.message());
        let o = on(&kid, verb, &[("timeout_ms", "100")]);
        o.fails(2, "invalid_argument");
        assert!(o.message().contains("timeout_ms"), "{}", o.message());
        if *verb != "limits.set" {
            let o = on(&kid, verb, &[("dry_run", "true")]);
            o.fails(2, "invalid_argument");
            assert!(o.message().contains("dry_run"));
        }
        assert!(kid.alive(), "{verb} acted on invalid input");
        assert_ne!(kid.state(), 'T', "{verb}");
    }
    // A misspelled argument gets a suggestion; nothing is signalled.
    let o = on(&kid, "signal", &[("sgi", "KILL")]);
    o.fails(2, "invalid_argument");
    assert!(
        o.message().contains("did you mean `sig`"),
        "{}",
        o.message()
    );
    let o = on(&kid, "limits.set", &[("nofiles", "10")]);
    o.fails(2, "invalid_argument");
    assert!(
        o.message().contains("did you mean `nofile`"),
        "{}",
        o.message()
    );
    let o = on(&kid, "io.peek", &[("max_byte", "10")]);
    assert!(o.message().contains("did you mean `max_bytes`"));
    assert!(kid.alive());
    assert_eq!(kid.limit("Max open files").0, {
        let (s, _) = sys::get_limit(std::process::id() as i32, libc::RLIMIT_NOFILE as i32).unwrap();
        s.to_string()
    });
}

#[test]
fn unknown_verb_is_a_usage_error() {
    let o = call("self", "nice.gett", &[]);
    o.fails(2, "invalid_argument");
    assert!(
        o.message().contains("did you mean `nice.get`"),
        "{}",
        o.message()
    );
}

#[test]
fn handle_writes_nothing_to_stderr() {
    // The dispatcher prints the error line from the status.
    let o = call(&GONE.to_string(), "term", &[]);
    o.fails(1, "not_found");
    assert_eq!(o.stderr, "");
}

#[test]
fn help_detection_is_exact() {
    let none = Args::new();
    assert!(should_show_help("help", &none));
    assert!(should_show_help("--help", &none));
    assert!(should_show_help("-h", &none));
    assert!(!should_show_help("signal", &none));
    assert!(!should_show_help("pre-hotfix", &none));
    assert!(!should_show_help("x-help", &none));
    let mut a = Args::new();
    a.insert("help".into(), "1".into());
    assert!(should_show_help("signal", &a));
}

#[test]
fn help_url_forms_and_rendering() {
    let h = ProcHandle::from_url(&Url::parse("proc://--help").unwrap()).unwrap();
    let out = crate::core::help::render_legacy("proc", &PROC_HELP, h.verbs(), None);
    assert!(out.starts_with("Handle: proc"), "{out}");
    assert!(ProcHandle::from_url(&Url::parse("proc://my-hosts").unwrap()).is_err());
    let o = call("--help", "help", &[("verb", "kill")]);
    assert_eq!(o.code(), 0);
    assert!(
        o.stdout.starts_with("Handle: proc\nVerb: kill\n"),
        "{}",
        o.stdout
    );
}

// ---------------------------------------------------------------------------
// PIDs
// ---------------------------------------------------------------------------

// SEC-03: no PID may wrap into 0 or a negative pid_t on its way to kill().
// These tests only parse; no signal is ever sent.
#[test]
fn pid_parsing_rejects_out_of_range_values() {
    assert_eq!(parse_pid("1").unwrap(), 1);
    assert_eq!(parse_pid("4242").unwrap(), 4242);
    assert_eq!(
        parse_pid(&libc::pid_t::MAX.to_string()).unwrap(),
        libc::pid_t::MAX
    );
    for bad in [
        "0",
        "-1",
        "-4242",
        "2147483648",
        "4294967295",
        "4294967296",
        "18446744073709551615",
        "18446744073709551616",
        "99999999999999999999999",
        "",
        "12a",
        "0x10",
        "1.5",
        " 1",
        "+5",
    ] {
        assert!(parse_pid(bad).is_err(), "{bad:?} must be rejected");
    }
}

#[test]
fn proc_url_rejects_wrapping_pids() {
    for url in [
        "proc://4294967295",
        "proc://2147483648",
        "proc://0",
        "proc://-1",
    ] {
        assert!(
            ProcHandle::from_url(&Url::parse(url).unwrap()).is_err(),
            "{url}"
        );
    }
    let h = ProcHandle::from_url(&Url::parse("proc://2147483647").unwrap()).unwrap();
    assert_eq!(h.resolve_pid().unwrap(), 2147483647);
    let h = ProcHandle::from_url(&Url::parse("proc://self").unwrap()).unwrap();
    assert_eq!(h.resolve_pid().unwrap() as u32, std::process::id());
}

#[test]
fn resolve_pid_rechecks_range_without_from_url() {
    // A handle built without from_url must still never yield -1.
    for name in ["4294967295", "0"] {
        let h = ProcHandle { name: name.into() };
        assert!(h.resolve_pid().is_err());
        let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
        let mut io = IoStreams::new(&mut i, &mut o, &mut e);
        let st = h.call("kill", &Args::new(), &mut io).unwrap();
        assert_eq!(st.exit_code(), 2);
        assert!(st.reason.unwrap().starts_with("[proc.invalid_target] "));
    }
}

#[test]
fn kill_stage_with_wrapping_pid_fails_before_dispatch() {
    let p = crate::core::parse::parse_stage("proc://4294967295.kill").unwrap();
    assert_eq!(p.verb, "kill");
    let url = Url::parse(&p.target).unwrap();
    assert!(ProcHandle::from_url(&url).is_err());
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

#[test]
fn fixed_signal_verbs_deliver_their_signal() {
    for (verb, name, num) in [
        ("term", "TERM", libc::SIGTERM),
        ("int", "INT", libc::SIGINT),
        ("hup", "HUP", libc::SIGHUP),
        ("kill", "KILL", libc::SIGKILL),
        ("usr1", "USR1", libc::SIGUSR1),
        ("usr2", "USR2", libc::SIGUSR2),
    ] {
        let mut kid = Kid::spawn();
        let o = on(&kid, verb, &[]);
        assert_eq!(o.code(), 0, "{verb}: {}", o.stdout);
        assert_eq!(
            o.json(),
            json!({"pid": kid.pid(), "verb": verb, "signal": name,
                   "signal_num": num, "ok": true})
        );
        assert_eq!(signal_of(kid.wait()), Some(num), "{verb}");
    }
    // Linux numbering, as documented.
    assert_eq!((libc::SIGUSR1, libc::SIGUSR2), (10, 12));
}

#[test]
fn stop_and_cont_pause_and_resume() {
    let mut kid = Kid::spawn();
    let o = on(&kid, "stop", &[]);
    assert_eq!(o.code(), 0);
    assert_eq!(o.json()["signal_num"], libc::SIGSTOP);
    let wait_state = |kid: &Kid, want: char| {
        let end = Instant::now() + Duration::from_secs(5);
        while kid.state() != want {
            assert!(Instant::now() < end, "state {} != {want}", kid.state());
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    wait_state(&kid, 'T');
    let o = on(&kid, "cont", &[]);
    assert_eq!(o.code(), 0);
    assert_eq!(o.json()["signal"], "CONT");
    wait_state(&kid, 'S');
    assert!(kid.alive());
}

#[test]
fn signal_by_name_and_number() {
    for (sig, label, num) in [
        ("TERM", "TERM", libc::SIGTERM),
        ("sigterm", "TERM", libc::SIGTERM),
        ("SigHup", "HUP", libc::SIGHUP),
        ("ALRM", "ALRM", libc::SIGALRM),
        ("PIPE", "PIPE", libc::SIGPIPE),
        ("10", "USR1", 10),
        ("12", "USR2", 12),
        ("9", "KILL", 9),
    ] {
        let mut kid = Kid::spawn();
        let o = on(&kid, "signal", &[("sig", sig)]);
        assert_eq!(o.code(), 0, "{sig}: {}", o.stdout);
        assert_eq!(o.json()["signal"], label, "{sig}");
        assert_eq!(o.json()["signal_num"], num, "{sig}");
        assert_eq!(o.json()["verb"], "signal");
        assert_eq!(signal_of(kid.wait()), Some(num), "{sig}");
    }
    // CHLD is ignored by default; 0 sends nothing.
    let mut kid = Kid::spawn();
    for (sig, label) in [("CHLD", "CHLD"), ("0", "NULL")] {
        let o = on(&kid, "signal", &[("sig", sig)]);
        assert_eq!(o.code(), 0);
        assert_eq!(o.json()["signal"], label);
    }
    assert!(kid.alive());
    // A real-time signal by number terminates by default.
    let (rt_min, _) = sys::sig_rt_range();
    let o = on(&kid, "signal", &[("sig", &rt_min.to_string())]);
    assert_eq!(o.json()["signal"], "RTMIN+0");
    assert_eq!(signal_of(kid.wait()), Some(rt_min));
}

#[test]
fn signal_argument_errors() {
    let mut kid = Kid::spawn();
    let o = on(&kid, "signal", &[]);
    o.fails(2, "invalid_argument");
    assert!(o.message().contains("missing argument: sig"));
    for bad in ["", "BOGUS", "-1", "65", "999", "1.5", "SIGTREM", " 9"] {
        let o = on(&kid, "signal", &[("sig", bad)]);
        o.fails(2, "invalid_argument");
    }
    let o = on(&kid, "signal", &[("sig", "TREM")]);
    assert!(
        o.message().contains("did you mean `TERM`"),
        "{}",
        o.message()
    );
    assert!(kid.alive());
}

#[test]
fn signal_to_a_missing_process_is_not_found() {
    for verb in ["term", "kill", "usr1", "stop"] {
        let o = call(&GONE.to_string(), verb, &[]);
        o.fails(1, "not_found");
        assert_eq!(o.json()["pid"], GONE);
        assert!(o.json()["signal_num"].is_number());
    }
    call(&GONE.to_string(), "signal", &[("sig", "0")]).fails(1, "not_found");
}

#[test]
fn signal_labels_follow_platform_numbering() {
    for (num, name) in [
        (libc::SIGHUP, "HUP"),
        (libc::SIGKILL, "KILL"),
        (libc::SIGUSR1, "USR1"),
        (libc::SIGUSR2, "USR2"),
        (libc::SIGTERM, "TERM"),
        (libc::SIGCHLD, "CHLD"),
        (libc::SIGCONT, "CONT"),
        (libc::SIGSTOP, "STOP"),
    ] {
        assert_eq!(
            parse_signal_arg(&num.to_string()).unwrap(),
            (name.to_string(), num)
        );
    }
    let label = |n: i32| parse_signal_arg(&n.to_string()).unwrap().0;
    assert_eq!(label(10), "USR1");
    assert_eq!(label(12), "USR2");
    assert_eq!(label(17), "CHLD");
    assert_eq!(label(18), "CONT");
    assert_eq!(label(19), "STOP");
    assert_eq!(label(20), "TSTP");
    assert_eq!(label(16), "STKFLT");
    assert_eq!(label(30), "PWR");
    assert_eq!(label(31), "SYS");
    assert_eq!(label(32), "UNKNOWN");
    assert_eq!(label(0), "NULL");
    assert_eq!(label(64), "RTMIN+30");
    assert!(parse_signal_arg("65").is_err());
}

// ---------------------------------------------------------------------------
// Nice values
// ---------------------------------------------------------------------------

#[test]
fn nice_get_reports_the_child_value() {
    let kid = Kid::spawn();
    let own = sys::get_nice(std::process::id() as i32).unwrap();
    let o = on(&kid, "nice.get", &[]);
    assert_eq!(o.code(), 0);
    assert_eq!(o.json(), json!({"pid": kid.pid(), "nice": own}));
    let o = call("self", "nice.get", &[]);
    assert_eq!(o.json()["nice"], own);
    call(&GONE.to_string(), "nice.get", &[]).fails(1, "not_found");
}

#[test]
fn nice_set_changes_and_reports_changed() {
    let kid = Kid::spawn();
    let o = on(&kid, "nice.set", &[("value", "15")]);
    assert_eq!(o.code(), 0, "{}", o.stdout);
    assert_eq!(
        o.json(),
        json!({"pid": kid.pid(), "nice": 15, "changed": true})
    );
    assert_eq!(sys::get_nice(kid.pid()).unwrap(), 15);
    let o = on(&kid, "nice.set", &[("value", "15")]);
    assert_eq!(o.json()["changed"], false);
    // Lowering needs privilege.
    let o = on(&kid, "nice.set", &[("value", "5")]);
    if may_lower_nice_to(5) {
        assert_eq!(o.code(), 0);
        assert_eq!(sys::get_nice(kid.pid()).unwrap(), 5);
    } else {
        o.fails(1, "permission_denied");
        assert_eq!(sys::get_nice(kid.pid()).unwrap(), 15);
    }
}

#[test]
fn nice_set_argument_errors_change_nothing() {
    let kid = Kid::spawn();
    let before = sys::get_nice(kid.pid()).unwrap();
    for args in [
        vec![],
        vec![("value", "")],
        vec![("value", "x")],
        vec![("value", "20")],
        vec![("value", "-21")],
        vec![("value", "1.5")],
    ] {
        on(&kid, "nice.set", &args).fails(2, "invalid_argument");
    }
    assert_eq!(sys::get_nice(kid.pid()).unwrap(), before);
    call(&GONE.to_string(), "nice.set", &[("value", "5")]).fails(1, "not_found");
}

#[test]
fn nice_inc_and_dec() {
    let kid = Kid::spawn();
    let base = sys::get_nice(kid.pid()).unwrap();
    let o = on(&kid, "nice.inc", &[("delta", "2")]);
    assert_eq!(o.code(), 0, "{}", o.stdout);
    assert_eq!(
        o.json(),
        json!({"pid": kid.pid(), "nice_before": base, "nice_after": base + 2,
               "delta": 2, "changed": true})
    );
    let o = on(&kid, "nice.inc", &[("delta", "0")]);
    assert_eq!(o.json()["changed"], false);
    // Past 19: refused, nothing changed.
    let o = on(&kid, "nice.inc", &[("delta", "39")]);
    o.fails(2, "invalid_argument");
    assert!(o.message().contains("outside -20..19"));
    assert_eq!(sys::get_nice(kid.pid()).unwrap(), base + 2);
    let o = on(&kid, "nice.dec", &[("delta", "1")]);
    if may_lower_nice_to(base + 1) {
        assert_eq!(o.code(), 0);
        assert_eq!(o.json()["nice_after"], base + 1);
    } else {
        o.fails(1, "permission_denied");
        assert_eq!(sys::get_nice(kid.pid()).unwrap(), base + 2);
    }
    let o = on(&kid, "nice.dec", &[("delta", "39")]);
    o.fails(2, "invalid_argument");
    for verb in ["nice.inc", "nice.dec"] {
        for args in [
            vec![],
            vec![("delta", "x")],
            vec![("delta", "-1")],
            vec![("delta", "40")],
        ] {
            on(&kid, verb, &args).fails(2, "invalid_argument");
        }
        call(&GONE.to_string(), verb, &[("delta", "1")]).fails(1, "not_found");
    }
}

#[test]
fn set_priority_classes_and_nice() {
    let kid = Kid::spawn();
    let base = sys::get_nice(kid.pid()).unwrap();
    let o = on(&kid, "setPriority", &[("class", "background")]);
    if may_lower_nice_to(10) || base <= 10 {
        assert_eq!(o.code(), 0, "{}", o.stdout);
        assert_eq!(
            o.json(),
            json!({"pid": kid.pid(), "class": "background", "nice": 10,
                   "previous_nice": base, "backend": "linux-setpriority"})
        );
    }
    let o = on(&kid, "setPriority", &[("class", "idle")]);
    assert_eq!(o.code(), 0);
    assert_eq!(o.json()["nice"], 19);
    assert_eq!(sys::get_nice(kid.pid()).unwrap(), 19);
    // nice overrides class; a known value gets its class name.
    let o = on(&kid, "setPriority", &[("class", "idle"), ("nice", "19")]);
    assert_eq!(o.json()["class"], "idle");
    let o = on(&kid, "setPriority", &[("nice", "17")]);
    if may_lower_nice_to(17) {
        assert_eq!(o.json()["class"], "custom");
        assert_eq!(o.json()["previous_nice"], 19);
    } else {
        o.fails(1, "permission_denied");
    }
    // Default class is normal (0): lowering from 19 needs privilege.
    let o = on(&kid, "setPriority", &[]);
    if may_lower_nice_to(0) {
        assert_eq!(o.json()["class"], "normal");
        assert_eq!(o.json()["nice"], 0);
    } else {
        o.fails(1, "permission_denied");
        assert!(o.message().contains("permission denied"));
    }
}

#[test]
fn set_priority_argument_errors_change_nothing() {
    let kid = Kid::spawn();
    let before = sys::get_nice(kid.pid()).unwrap();
    for args in [
        vec![("class", "turbo")],
        vec![("class", "")],
        vec![("nice", "20")],
        vec![("nice", "-21")],
        vec![("nice", "x")],
        vec![("class", "turbo"), ("nice", "5")],
    ] {
        on(&kid, "setPriority", &args).fails(2, "invalid_argument");
    }
    let o = on(&kid, "setPriority", &[("class", "backgroud")]);
    assert!(o.message().contains("did you mean `background`"));
    assert_eq!(sys::get_nice(kid.pid()).unwrap(), before);
    call(&GONE.to_string(), "setPriority", &[("class", "idle")]).fails(1, "not_found");
}

// ---------------------------------------------------------------------------
// io.peek (the base directory is a temporary one)
// ---------------------------------------------------------------------------

fn peek(base: Option<&Path>, pid: libc::pid_t, args: &[(&str, &str)]) -> Out {
    let args: Args = args
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let mut o = Vec::new();
    let status = match check_args("io.peek", IO_PEEK_ARGS, &args)
        .map_err(Failure::from)
        .and_then(|_| verb_io_peek(pid, &args, base.map(Path::to_path_buf)))
    {
        Ok(Output::Json(v)) => {
            writeln!(o, "{v}").unwrap();
            Status::ok()
        }
        Ok(Output::Raw(s)) => {
            o.extend_from_slice(s.as_bytes());
            Status::ok()
        }
        Err(Failure { fail, extra }) => {
            let mut obj = extra;
            obj.insert("ok".into(), json!(false));
            obj.insert("error".into(), fail.error_obj());
            writeln!(o, "{}", Value::Object(obj)).unwrap();
            fail.status("io.peek")
        }
    };
    Out {
        status,
        stdout: String::from_utf8(o).unwrap(),
        stderr: String::new(),
    }
}

fn logs(stdout: Option<&[u8]>, stderr: Option<&[u8]>) -> tempfile::TempDir {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("resh/proc/4242");
    std::fs::create_dir_all(&dir).unwrap();
    if let Some(b) = stdout {
        std::fs::write(dir.join("stdout.log"), b).unwrap();
    }
    if let Some(b) = stderr {
        std::fs::write(dir.join("stderr.log"), b).unwrap();
    }
    t
}

#[test]
fn io_peek_reads_the_tail_of_each_stream() {
    let t = logs(Some(b"worker started\nprocessing\n"), Some(b"warn\n"));
    let o = peek(Some(t.path()), 4242, &[]);
    assert_eq!(o.code(), 0, "{}", o.stdout);
    assert_eq!(
        o.json(),
        json!({"pid": 4242, "stream": "stdout", "encoding": "utf8",
               "auto_fallback": false, "bytes_read": 26, "truncated": false,
               "data": "worker started\nprocessing\n"})
    );
    let o = peek(Some(t.path()), 4242, &[("stream", "stderr")]);
    assert_eq!(o.json()["data"], "warn\n");
    assert_eq!(o.json()["stream"], "stderr");
    let o = peek(Some(t.path()), 4242, &[("stream", "both")]);
    assert_eq!(o.code(), 0);
    assert_eq!(o.json()["streams"]["stdout"]["bytes_read"], 26);
    assert_eq!(o.json()["streams"]["stderr"]["data"], "warn\n");
    // max_bytes and tail: the last min(tail, max_bytes) bytes.
    let o = peek(Some(t.path()), 4242, &[("max_bytes", "11")]);
    assert_eq!(o.json()["data"], "processing\n");
    assert_eq!(o.json()["truncated"], true);
    let o = peek(Some(t.path()), 4242, &[("tail", "4"), ("max_bytes", "100")]);
    assert_eq!(o.json()["data"], "ing\n");
    let o = peek(Some(t.path()), 4242, &[("tail", "100"), ("max_bytes", "4")]);
    assert_eq!(o.json()["data"], "ing\n");
    // Raw mode prints the data alone.
    let o = peek(Some(t.path()), 4242, &[("json", "false")]);
    assert_eq!(o.stdout, "worker started\nprocessing\n");
    let o = peek(Some(t.path()), 4242, &[("json", "no"), ("max_bytes", "5")]);
    assert_eq!(o.stdout, "sing\n");
}

#[test]
fn io_peek_encodings() {
    let t = logs(Some(b"ab\xffcd"), Some(b""));
    let o = peek(Some(t.path()), 4242, &[]);
    assert_eq!(o.json()["encoding"], "base64");
    assert_eq!(o.json()["auto_fallback"], true);
    assert_eq!(o.json()["data"], "YWL/Y2Q=");
    let o = peek(Some(t.path()), 4242, &[("encoding", "utf8")]);
    assert_eq!(o.json()["data"], "ab\u{fffd}cd");
    assert_eq!(o.json()["auto_fallback"], false);
    let o = peek(Some(t.path()), 4242, &[("encoding", "base64")]);
    assert_eq!(o.json()["data"], "YWL/Y2Q=");
    assert_eq!(o.json()["auto_fallback"], false);
    // An empty file keeps the requested encoding.
    let o = peek(
        Some(t.path()),
        4242,
        &[("stream", "stderr"), ("encoding", "base64")],
    );
    assert_eq!(o.json()["encoding"], "base64");
    assert_eq!(o.json()["bytes_read"], 0);
    assert_eq!(o.json()["data"], "");
}

#[test]
fn io_peek_missing_logs() {
    let t = logs(Some(b"out\n"), None);
    let o = peek(Some(t.path()), 4242, &[("stream", "stderr")]);
    o.fails(1, "log_not_found");
    peek(Some(t.path()), 7, &[]).fails(1, "log_not_found");
    // both: what could be read is printed; the call fails.
    let o = peek(Some(t.path()), 4242, &[("stream", "both")]);
    o.fails(1, "log_not_found");
    assert_eq!(o.json()["streams"]["stdout"]["data"], "out\n");
    assert_eq!(
        o.json()["streams"]["stderr"]["error"]["code"],
        "proc.log_not_found"
    );
    // No state directory: never fall back to a shared one.
    let o = peek(None, 4242, &[]);
    o.fails(1, "failed");
    assert!(o.message().contains("state directory"));
}

#[test]
fn io_peek_refuses_fifos_and_directories_without_blocking() {
    let t = logs(None, None);
    let dir = t.path().join("resh/proc/4242");
    let fifo = dir.join("stdout.log");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    std::fs::create_dir(dir.join("stderr.log")).unwrap();
    let o = peek(Some(t.path()), 4242, &[]);
    o.fails(1, "failed");
    assert!(
        o.message().contains("not a regular file"),
        "{}",
        o.message()
    );
    peek(Some(t.path()), 4242, &[("stream", "stderr")]).fails(1, "failed");
}

#[test]
fn io_peek_unreadable_log_is_permission_denied() {
    if is_root() {
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let t = logs(Some(b"secret"), None);
    let f = t.path().join("resh/proc/4242/stdout.log");
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();
    peek(Some(t.path()), 4242, &[]).fails(1, "permission_denied");
}

#[test]
fn io_peek_argument_errors() {
    let t = logs(Some(b"x"), Some(b"y"));
    for args in [
        vec![("stream", "all")],
        vec![("encoding", "hex")],
        vec![("max_bytes", "0")],
        vec![("max_bytes", "-1")],
        vec![("max_bytes", "x")],
        vec![("max_bytes", "16777217")],
        vec![("tail", "0")],
        vec![("tail", "abc")],
        vec![("json", "maybe")],
        vec![("json", "false"), ("stream", "stderr")],
        vec![("json", "false"), ("stream", "both")],
    ] {
        peek(Some(t.path()), 4242, &args).fails(2, "invalid_argument");
    }
    let o = peek(Some(t.path()), 4242, &[("stream", "stdot")]);
    assert!(o.message().contains("did you mean `stdout`"));
    let o = peek(Some(t.path()), 4242, &[("max_bytes", "16777216")]);
    assert_eq!(o.code(), 0);
}

#[test]
fn io_peek_through_the_handle_uses_the_state_directory() {
    // A pid whose log directory does not exist anywhere.
    let o = call(&GONE.to_string(), "io.peek", &[]);
    assert_eq!(o.code(), 1, "{}", o.stdout);
    let code = o.json()["error"]["code"].as_str().unwrap().to_string();
    assert!(
        code == "proc.log_not_found" || code == "proc.failed",
        "{code}"
    );
}

// ---------------------------------------------------------------------------
// limits.set (on the test's own child, through prlimit)
// ---------------------------------------------------------------------------

#[test]
fn limits_set_changes_the_target_process() {
    let kid = Kid::spawn();
    let own = sys::get_limit(std::process::id() as i32, libc::RLIMIT_NOFILE as i32).unwrap();
    let (_, hard) = sys::get_limit(kid.pid(), libc::RLIMIT_NOFILE as i32).unwrap();
    let o = on(&kid, "limits.set", &[("nofile", "100")]);
    assert_eq!(o.code(), 0, "{}", o.stdout);
    let j = o.json();
    assert_eq!(j["pid"], kid.pid());
    assert_eq!(j["backend"], "prlimit");
    assert_eq!(j["dry_run"], false);
    assert_eq!(
        j["results"]["nofile"]["after"],
        json!({"soft": 100, "hard": hard})
    );
    assert_eq!(j["results"]["nofile"]["status"], "ok");
    assert_eq!(j["results"]["nofile"]["changed"], true);
    assert_eq!(j["results"]["nofile"]["requested"], "100");
    assert_eq!(kid.limit("Max open files").0, "100");
    // resh's own limits are not touched.
    assert_eq!(
        sys::get_limit(std::process::id() as i32, libc::RLIMIT_NOFILE as i32).unwrap(),
        own
    );
    // soft:hard, lowering the hard limit (allowed unprivileged).
    let o = on(&kid, "limits.set", &[("nofile", "50:200")]);
    assert_eq!(o.code(), 0, "{}", o.stdout);
    assert_eq!(kid.limit("Max open files"), ("50".into(), "200".into()));
    // An empty side keeps the current value.
    let o = on(&kid, "limits.set", &[("nofile", ":150")]);
    assert_eq!(o.code(), 0);
    assert_eq!(kid.limit("Max open files"), ("50".into(), "150".into()));
    let o = on(&kid, "limits.set", &[("nofile", "150:")]);
    assert_eq!(o.code(), 0);
    assert_eq!(kid.limit("Max open files"), ("150".into(), "150".into()));
    // Same value: unchanged.
    let o = on(&kid, "limits.set", &[("nofile", "150")]);
    assert_eq!(o.json()["results"]["nofile"]["changed"], false);
    // Several resources, suffixes.
    let o = on(
        &kid,
        "limits.set",
        &[
            ("cpu", "100s"),
            ("fsize", "2M"),
            ("core", "0"),
            ("as", "unlimited"),
        ],
    );
    assert_eq!(o.code(), 0, "{}", o.stdout);
    assert_eq!(kid.limit("Max cpu time").0, "100");
    assert_eq!(kid.limit("Max file size").0, "2000000");
    assert_eq!(kid.limit("Max core file size").0, "0");
}

#[test]
fn limits_set_dry_run_changes_nothing() {
    let kid = Kid::spawn();
    let before = kid.limit("Max open files");
    for dry in ["true", "1", "yes", "on"] {
        let o = on(&kid, "limits.set", &[("nofile", "64"), ("dry_run", dry)]);
        assert_eq!(o.code(), 0, "{}", o.stdout);
        assert_eq!(o.json()["dry_run"], true);
        assert_eq!(o.json()["results"]["nofile"]["after"]["soft"], 64);
        assert_eq!(o.json()["results"]["nofile"]["changed"], true);
        assert_eq!(kid.limit("Max open files"), before);
    }
    on(
        &kid,
        "limits.set",
        &[("nofile", "64"), ("dry_run", "maybe")],
    )
    .fails(2, "invalid_argument");
    assert_eq!(kid.limit("Max open files"), before);
}

#[test]
fn limits_set_pid_argument() {
    let kid = Kid::spawn();
    let own = sys::get_limit(std::process::id() as i32, libc::RLIMIT_NOFILE as i32).unwrap();
    let p = kid.pid().to_string();
    let o = call("self", "limits.set", &[("pid", &p), ("nofile", "77")]);
    assert_eq!(o.code(), 0, "{}", o.stdout);
    assert_eq!(o.json()["pid"], kid.pid());
    assert_eq!(kid.limit("Max open files").0, "77");
    assert_eq!(
        sys::get_limit(std::process::id() as i32, libc::RLIMIT_NOFILE as i32).unwrap(),
        own
    );
    // Same pid in both places is fine; a different one is refused.
    let o = call(&p, "limits.set", &[("pid", &p), ("nofile", "78")]);
    assert_eq!(o.code(), 0);
    let o = on(&kid, "limits.set", &[("pid", "1"), ("nofile", "79")]);
    o.fails(2, "invalid_argument");
    assert!(o.message().contains("disagrees"));
    for bad in ["0", "-1", "x", "4294967295"] {
        call("self", "limits.set", &[("pid", bad), ("nofile", "79")]).fails(2, "invalid_argument");
    }
    assert_eq!(kid.limit("Max open files").0, "78");
    let o = call(
        "self",
        "limits.set",
        &[("pid", &GONE.to_string()), ("nofile", "79")],
    );
    o.fails(1, "not_found");
    assert_eq!(o.json()["pid"], GONE);
}

#[test]
fn limits_set_argument_errors_change_nothing() {
    let kid = Kid::spawn();
    let before = kid.limit("Max open files");
    for args in [
        vec![],
        vec![("dry_run", "true")],
        vec![("nofile", "")],
        vec![("nofile", ":")],
        vec![("nofile", "abc")],
        vec![("nofile", "10s")],
        vec![("nofile", "-5")],
        vec![("nofile", "1:2:3")],
        vec![("nofile", "99999999999G")],
        vec![("nofile", "18446744073709551615")],
        vec![("nofile", "K")],
        vec![("nofile", "10k")],
        vec![("nofile", "200:100")],
        // One bad resource stops the good one too.
        vec![("cpu", "10"), ("nofile", "x")],
        vec![("rss", "10")],
    ] {
        let o = on(&kid, "limits.set", &args);
        o.fails(2, "invalid_argument");
        assert_eq!(kid.limit("Max open files"), before, "{args:?}");
    }
    assert_eq!(kid.limit("Max cpu time").0, "unlimited");
    // Soft above the current hard limit.
    let o = on(&kid, "limits.set", &[("nofile", "unlimited")]);
    if !is_root() && before.1 != "unlimited" {
        o.fails(2, "invalid_argument");
        assert!(o.message().contains("exceed the hard limit"));
    }
}

#[test]
fn limits_set_raising_a_hard_limit_needs_privilege() {
    if is_root() {
        return; // covered by the Docker tests
    }
    let kid = Kid::spawn();
    on(&kid, "limits.set", &[("core", "0:1000")]);
    assert_eq!(kid.limit("Max core file size"), ("0".into(), "1000".into()));
    // core fails; nofile, applied after it, is skipped.
    let o = on(&kid, "limits.set", &[("core", ":2000"), ("nofile", "10")]);
    o.fails(1, "permission_denied");
    let j = o.json();
    assert_eq!(j["pid"], kid.pid());
    assert_eq!(j["results"]["core"]["status"], "error");
    assert_eq!(
        j["results"]["core"]["error"]["code"],
        "proc.permission_denied"
    );
    assert_eq!(j["results"]["nofile"]["status"], "skipped");
    assert_eq!(kid.limit("Max core file size").1, "1000");
    assert_ne!(kid.limit("Max open files").0, "10");
    // cpu (before core) is applied, then core fails.
    let o = on(&kid, "limits.set", &[("cpu", "500"), ("core", ":3000")]);
    o.fails(1, "permission_denied");
    assert_eq!(o.json()["results"]["cpu"]["status"], "ok");
    assert_eq!(kid.limit("Max cpu time").0, "500");
}

#[test]
fn limit_value_parsing() {
    assert_eq!(parse_single_limit("nofile", "10"), Ok(10));
    assert_eq!(parse_single_limit("nofile", "unlimited"), Ok(sys::INFINITY));
    assert_eq!(parse_single_limit("fsize", "3K"), Ok(3_000));
    assert_eq!(parse_single_limit("fsize", "3M"), Ok(3_000_000));
    assert_eq!(parse_single_limit("fsize", "3G"), Ok(3_000_000_000));
    assert_eq!(parse_single_limit("cpu", "30s"), Ok(30));
    assert!(parse_single_limit("fsize", "30s").is_err());
    assert!(parse_single_limit("fsize", "18446744073709551615").is_err());
    assert!(parse_single_limit("fsize", "18446744073709552G").is_err());
    assert!(parse_single_limit("fsize", "+5").is_err());
    assert_eq!(
        parse_limit_spec("nofile", "1:2").unwrap(),
        (Some(1), Some(2))
    );
    assert_eq!(parse_limit_spec("nofile", ":2").unwrap(), (None, Some(2)));
    assert_eq!(parse_limit_spec("nofile", "1:").unwrap(), (Some(1), None));
    assert_eq!(parse_limit_spec("nofile", "1").unwrap(), (Some(1), None));
    assert!(parse_limit_spec("nofile", ":").is_err());
    assert!(parse_limit_spec("nofile", "").is_err());
}
