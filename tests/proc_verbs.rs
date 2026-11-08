//! Integration tests for `proc://`: every verb run through the built `resh`
//! binary against `sleep` children this test spawned and owns (no other
//! process on the host is signalled, reniced or limited); exit codes and the
//! error format; help output (golden files) and the help examples.
//!
//! Lowering nice values, raising hard limits and acting on another user's
//! process need root: see tests/proc_e2e_docker.rs.

use serde_json::{Value, json};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VERBS: &[&str] = &[
    "nice.get",
    "io.peek",
    "signal",
    "term",
    "int",
    "hup",
    "kill",
    "stop",
    "cont",
    "usr1",
    "usr2",
    "nice.set",
    "nice.inc",
    "nice.dec",
    "setPriority",
    "limits.set",
];

/// The options each verb accepts (src/handles/processes/proch.rs `verb_args`).
fn options_for(verb: &str) -> &'static [&'static str] {
    match verb {
        "signal" => &["sig"],
        "nice.set" => &["value"],
        "nice.inc" | "nice.dec" => &["delta"],
        "setPriority" => &["class", "nice"],
        "io.peek" => &["stream", "max_bytes", "tail", "encoding", "json"],
        "limits.set" => &[
            "pid", "dry_run", "cpu", "as", "data", "stack", "core", "nofile", "fsize", "memlock",
            "nproc",
        ],
        _ => &[],
    }
}

/// The error codes documented in docs/Process_ServiceManagement/proc.md.
const ERROR_CODES: &[&str] = &[
    "proc.invalid_argument",
    "proc.invalid_target",
    "proc.not_found",
    "proc.permission_denied",
    "proc.log_not_found",
    "proc.failed",
    "proc.unsupported_platform",
];

/// Above the kernel's PID_MAX_LIMIT: never a live process.
const GONE: &str = "2147483647";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    json: Value,
}

fn resh_env(args: &[&str], env: &[(&str, &str)]) -> Run {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
    cmd.env_remove("SSH_AUTH_SOCK").args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        json: serde_json::from_str(&stdout).unwrap_or(Value::Null),
        stdout,
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

fn resh(args: &[&str]) -> Run {
    resh_env(args, &[])
}

/// Asserts a failure with `exit` and `code` on stdout (JSON) and stderr.
fn assert_fail(r: &Run, exit: i32, code: &str) {
    assert_eq!(r.code, exit, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(r.json["error"]["code"], code, "{}", r.stdout);
    assert_eq!(r.json["ok"], false, "{}", r.stdout);
    assert!(r.json["error"]["message"].is_string(), "{}", r.stdout);
    assert_stderr(r, code);
}

fn assert_stderr(r: &Run, code: &str) {
    assert!(
        r.stderr.starts_with(&format!("Error: [{code}] ")),
        "{}",
        r.stderr
    );
    assert_eq!(r.stderr.lines().count(), 1, "{}", r.stderr);
    assert!(ERROR_CODES.contains(&code), "{code} is not documented");
}

/// A `sleep` child with default signal dispositions, killed on drop.
struct Kid(Child);

impl Kid {
    fn spawn() -> Self {
        let mut cmd = Command::new("sleep");
        cmd.arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            cmd.pre_exec(|| {
                for sig in 1..=libc::SIGRTMAX() {
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
        Kid(cmd.spawn().unwrap())
    }
    fn pid(&self) -> String {
        self.0.id().to_string()
    }
    fn url(&self, verb: &str) -> String {
        format!("proc://{}.{verb}", self.0.id())
    }
    fn signal(&mut self) -> Option<i32> {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(st) = self.0.try_wait().unwrap() {
                return st.signal();
            }
            assert!(Instant::now() < end, "child did not end");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn alive(&mut self) -> bool {
        self.0.try_wait().unwrap().is_none()
    }
    fn state(&self) -> char {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", self.0.id())).unwrap();
        stat.rsplit_once(") ").unwrap().1.chars().next().unwrap()
    }
    fn wait_state(&self, want: char) {
        let end = Instant::now() + Duration::from_secs(5);
        while self.state() != want {
            assert!(Instant::now() < end, "state {} != {want}", self.state());
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn nice(&self) -> i64 {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", self.0.id())).unwrap();
        // Field 19 is the nice value; fields after the command start at 3.
        let rest = stat.rsplit_once(") ").unwrap().1;
        rest.split_whitespace().nth(16).unwrap().parse().unwrap()
    }
    fn limit(&self, row: &str) -> (String, String) {
        let text = std::fs::read_to_string(format!("/proc/{}/limits", self.0.id())).unwrap();
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

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// True if this process may lower a child's nice value (the children have
/// RLIMIT_NICE 0, so only root may).
fn may_lower_nice_to(_target: i64) -> bool {
    is_root()
}

// ---------------------------------------------------------------------------
// Verbs
// ---------------------------------------------------------------------------

#[test]
fn signal_verbs_deliver_their_signals() {
    for (verb, name, num) in [
        ("term", "TERM", 15),
        ("int", "INT", 2),
        ("hup", "HUP", 1),
        ("kill", "KILL", 9),
        ("usr1", "USR1", 10),
        ("usr2", "USR2", 12),
    ] {
        let mut kid = Kid::spawn();
        let r = resh(&[&kid.url(verb)]);
        assert_eq!(r.code, 0, "{verb}: {}{}", r.stdout, r.stderr);
        assert_eq!(r.stderr, "");
        assert_eq!(
            r.json,
            json!({"ok": true, "pid": kid.0.id(), "signal": name,
                   "signal_num": num, "verb": verb})
        );
        assert_eq!(kid.signal(), Some(num), "{verb}");
    }
}

#[test]
fn stop_cont_and_signal() {
    let mut kid = Kid::spawn();
    let r = resh(&[&kid.url("stop")]);
    assert_eq!(r.code, 0);
    assert_eq!(r.json["signal_num"], 19);
    kid.wait_state('T');
    let r = resh(&[&kid.url("cont")]);
    assert_eq!(r.code, 0);
    assert_eq!(r.json["signal_num"], 18);
    kid.wait_state('S');
    let r = resh(&[&kid.url("signal"), "sig=0"]);
    assert_eq!(r.code, 0);
    assert_eq!(r.json["signal"], "NULL");
    let r = resh(&[&kid.url("signal"), "sig=SIGUSR2"]);
    assert_eq!(r.json["signal_num"], 12);
    assert_eq!(kid.signal(), Some(12));
}

#[test]
fn signal_errors() {
    let mut kid = Kid::spawn();
    for args in [vec![], vec!["sig=BOGUS"], vec!["sig=-9"], vec!["sig=65"]] {
        let mut argv = vec![kid.url("signal")];
        argv.extend(args.iter().map(|s| s.to_string()));
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        assert_fail(&resh(&argv), 2, "proc.invalid_argument");
    }
    let r = resh(&[&kid.url("signal"), "sig=TERN"]);
    assert!(r.stderr.contains("did you mean `TERM`"), "{}", r.stderr);
    assert!(kid.alive());
    for verb in ["term", "kill", "stop", "cont", "usr1"] {
        assert_fail(
            &resh(&[&format!("proc://{GONE}.{verb}")]),
            1,
            "proc.not_found",
        );
    }
    assert_fail(
        &resh(&[&format!("proc://{GONE}.signal"), "sig=0"]),
        1,
        "proc.not_found",
    );
}

#[test]
fn nice_verbs() {
    let kid = Kid::spawn();
    let base = kid.nice();
    let r = resh(&[&kid.url("nice.get")]);
    assert_eq!(r.code, 0);
    assert_eq!(r.json, json!({"nice": base, "pid": kid.0.id()}));
    let r = resh(&[&kid.url("nice.inc"), "delta=1"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.json["nice_after"], base + 1);
    assert_eq!(kid.nice(), base + 1);
    let r = resh(&[&kid.url("nice.set"), "value=15"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        r.json,
        json!({"changed": true, "nice": 15, "pid": kid.0.id()})
    );
    assert_eq!(kid.nice(), 15);
    let r = resh(&[&kid.url("setPriority"), "class=idle"]);
    assert_eq!(r.code, 0);
    assert_eq!(
        r.json,
        json!({"backend": "linux-setpriority", "class": "idle", "nice": 19,
               "pid": kid.0.id(), "previous_nice": 15})
    );
    let r = resh(&[&kid.url("nice.dec"), "delta=2"]);
    if may_lower_nice_to(17) {
        assert_eq!(r.code, 0);
        assert_eq!(kid.nice(), 17);
    } else {
        assert_fail(&r, 1, "proc.permission_denied");
        assert_eq!(kid.nice(), 19);
    }
    assert_eq!(resh(&[&format!("proc://{GONE}.nice.get")]).code, 1);
}

#[test]
fn nice_errors_change_nothing() {
    let kid = Kid::spawn();
    let base = kid.nice();
    for (verb, args) in [
        ("nice.set", vec![]),
        ("nice.set", vec!["value=20"]),
        ("nice.set", vec!["value=x"]),
        ("nice.inc", vec![]),
        ("nice.inc", vec!["delta=-1"]),
        ("nice.inc", vec!["delta=39"]),
        ("nice.dec", vec!["delta=x"]),
        ("setPriority", vec!["class=turbo"]),
        ("setPriority", vec!["nice=25"]),
        ("setPriority", vec!["nice=-21"]),
    ] {
        let mut argv = vec![kid.url(verb)];
        argv.extend(args.iter().map(|s| s.to_string()));
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        assert_fail(&resh(&argv), 2, "proc.invalid_argument");
    }
    assert_eq!(kid.nice(), base);
    for (verb, arg) in [
        ("nice.get", None),
        ("nice.set", Some("value=1")),
        ("nice.inc", Some("delta=1")),
        ("nice.dec", Some("delta=1")),
        ("setPriority", Some("class=idle")),
    ] {
        let url = format!("proc://{GONE}.{verb}");
        let mut argv = vec![url.as_str()];
        argv.extend(arg);
        assert_fail(&resh(&argv), 1, "proc.not_found");
    }
}

#[test]
fn io_peek_reads_logs_from_the_state_directory() {
    let state = tempfile::tempdir().unwrap();
    let dir = state.path().join("resh/proc/4242");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("stdout.log"), "worker started\nprocessing\n").unwrap();
    std::fs::write(dir.join("stderr.log"), b"\xff\xfe").unwrap();
    let env = [("XDG_STATE_HOME", state.path().to_str().unwrap())];
    let r = resh_env(&["proc://4242.io.peek"], &env);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.json["data"], "worker started\nprocessing\n");
    assert_eq!(r.json["truncated"], false);
    let r = resh_env(&["proc://4242.io.peek", "stream=stderr"], &env);
    assert_eq!(r.json["encoding"], "base64");
    assert_eq!(r.json["auto_fallback"], true);
    let r = resh_env(
        &["proc://4242.io.peek", "stream=both", "max_bytes=11"],
        &env,
    );
    assert_eq!(r.code, 0);
    assert_eq!(r.json["streams"]["stdout"]["data"], "processing\n");
    assert_eq!(r.json["streams"]["stdout"]["truncated"], true);
    let r = resh_env(&["proc://4242.io.peek", "json=false"], &env);
    assert_eq!(r.stdout, "worker started\nprocessing\n");
    // Missing logs, bad arguments.
    assert_fail(
        &resh_env(&["proc://4243.io.peek"], &env),
        1,
        "proc.log_not_found",
    );
    std::fs::remove_file(dir.join("stderr.log")).unwrap();
    let r = resh_env(&["proc://4242.io.peek", "stream=both"], &env);
    assert_fail(&r, 1, "proc.log_not_found");
    assert_eq!(r.json["streams"]["stdout"]["bytes_read"], 26);
    for bad in ["stream=x", "max_bytes=0", "json=false stream=both"] {
        let mut argv = vec!["proc://4242.io.peek"];
        argv.extend(bad.split(' '));
        assert_fail(&resh_env(&argv, &env), 2, "proc.invalid_argument");
    }
}

#[test]
fn limits_set_changes_the_target_not_resh() {
    let kid = Kid::spawn();
    let r = resh(&[&kid.url("limits.set"), "nofile=123", "core=0:0"]);
    assert_eq!(r.code, 0, "{}{}", r.stdout, r.stderr);
    assert_eq!(r.json["backend"], "prlimit");
    assert_eq!(r.json["pid"], kid.0.id());
    assert_eq!(r.json["results"]["nofile"]["after"]["soft"], 123);
    assert_eq!(kid.limit("Max open files").0, "123");
    assert_eq!(kid.limit("Max core file size"), ("0".into(), "0".into()));
    // pid= with proc://self.
    let r = resh(&[
        "proc://self.limits.set",
        &format!("pid={}", kid.pid()),
        "nofile=99",
    ]);
    assert_eq!(r.code, 0);
    assert_eq!(kid.limit("Max open files").0, "99");
    // dry run (also as a bare word).
    for dry in ["dry_run=true", "dry_run"] {
        let r = resh(&[&kid.url("limits.set"), "nofile=50", dry]);
        assert_eq!(r.code, 0, "{}", r.stderr);
        assert_eq!(r.json["dry_run"], true);
        assert_eq!(r.json["results"]["nofile"]["before"]["soft"], 99);
        assert_eq!(kid.limit("Max open files").0, "99");
    }
    // Raising the hard limit back needs privilege.
    let r = resh(&[&kid.url("limits.set"), "core=:1000"]);
    if is_root() {
        assert_eq!(r.code, 0);
    } else {
        assert_fail(&r, 1, "proc.permission_denied");
        assert_eq!(r.json["results"]["core"]["status"], "error");
        assert_eq!(kid.limit("Max core file size").1, "0");
    }
}

#[test]
fn limits_set_errors_change_nothing() {
    let kid = Kid::spawn();
    let before = kid.limit("Max open files");
    for args in [
        vec![],
        vec!["nofiles=10"],
        vec!["nofile=abc"],
        vec!["nofile=10s"],
        vec!["nofile=20:10"],
        vec!["nofile=10", "timeout_ms=5"],
        vec!["nofile=10", "dry_run=maybe"],
        vec!["nofile=10", "pid=0"],
        vec!["nofile=10", "pid=1"],
    ] {
        let mut argv = vec![kid.url("limits.set")];
        argv.extend(args.iter().map(|s| s.to_string()));
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        let r = resh(&argv);
        assert_eq!(r.code, 2, "{args:?}: {}", r.stderr);
        assert_stderr(&r, "proc.invalid_argument");
        assert_eq!(kid.limit("Max open files"), before, "{args:?}");
    }
    let r = resh(&[&kid.url("limits.set"), "nofiles=10"]);
    assert!(r.stderr.contains("did you mean `nofile`"), "{}", r.stderr);
    assert_fail(
        &resh(&[&format!("proc://{GONE}.limits.set"), "nofile=10"]),
        1,
        "proc.not_found",
    );
}

#[test]
fn strict_arguments_on_every_verb() {
    let mut kid = Kid::spawn();
    for verb in VERBS {
        let r = resh(&[&kid.url(verb), "bogus=1"]);
        assert_eq!(r.code, 2, "{verb}: {}", r.stderr);
        assert_stderr(&r, "proc.invalid_argument");
        assert!(r.stderr.contains("bogus"), "{}", r.stderr);
        let r = resh(&[&kid.url(verb), "timeout_ms=1000"]);
        assert_eq!(r.code, 2, "{verb}");
        assert_stderr(&r, "proc.invalid_argument");
        if *verb != "limits.set" {
            let r = resh(&[&kid.url(verb), "dry_run=true"]);
            assert_eq!(r.code, 2, "{verb}");
            assert_stderr(&r, "proc.invalid_argument");
            let r = resh(&[&kid.url(verb), "dry_run=false"]);
            assert_eq!(r.code, 2, "{verb}");
        }
        assert!(kid.alive(), "{verb}");
        assert_ne!(kid.state(), 'T', "{verb}");
    }
    let r = resh(&[&kid.url("sgnal")]);
    assert_eq!(r.code, 2);
    assert!(r.stderr.contains("did you mean `signal`"), "{}", r.stderr);
}

#[test]
fn invalid_targets_are_refused() {
    for target in ["0", "-1", "4294967295", "abc", "1x"] {
        let r = resh(&[&format!("proc://{target}.kill")]);
        assert_eq!(r.code, 2, "{target}: {}", r.stderr);
        assert_stderr(&r, "proc.invalid_target");
    }
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

fn assert_plain(out: &str) {
    for line in out.lines() {
        assert!(line.chars().count() <= 80, "line over 80 columns: {line:?}");
        assert!(!line.ends_with(' '), "trailing space: {line:?}");
    }
}

fn golden(verb: &str) -> &'static str {
    match verb {
        "signal" => include_str!("golden/proc_signal_help.txt"),
        "kill" => include_str!("golden/proc_kill_help.txt"),
        "term" => include_str!("golden/proc_term_help.txt"),
        "int" => include_str!("golden/proc_int_help.txt"),
        "hup" => include_str!("golden/proc_hup_help.txt"),
        "stop" => include_str!("golden/proc_stop_help.txt"),
        "cont" => include_str!("golden/proc_cont_help.txt"),
        "usr1" => include_str!("golden/proc_usr1_help.txt"),
        "usr2" => include_str!("golden/proc_usr2_help.txt"),
        "nice.get" => include_str!("golden/proc_nice.get_help.txt"),
        "nice.set" => include_str!("golden/proc_nice.set_help.txt"),
        "nice.inc" => include_str!("golden/proc_nice.inc_help.txt"),
        "nice.dec" => include_str!("golden/proc_nice.dec_help.txt"),
        "setPriority" => include_str!("golden/proc_setPriority_help.txt"),
        "io.peek" => include_str!("golden/proc_io.peek_help.txt"),
        "limits.set" => include_str!("golden/proc_limits.set_help.txt"),
        _ => unreachable!(),
    }
}

#[test]
fn handle_help_matches_golden() {
    let r = resh(&["proc", "--help"]);
    assert_eq!(r.code, 0);
    assert_eq!(r.stderr, "");
    assert_plain(&r.stdout);
    assert_eq!(r.stdout, include_str!("golden/proc_help.txt"));
    let listed: Vec<&str> = r
        .stdout
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
    assert_eq!(listed, VERBS);
    for alt in [
        &["proc", "-h"][..],
        &["proc", "help"][..],
        &["help", "proc"][..],
        &["proc://--help"][..],
    ] {
        assert_eq!(resh(alt).stdout, r.stdout, "{alt:?}");
    }
}

/// The `key=` options of a usage block; `<resource>=` stands for the names
/// on its `resources:` line.
fn usage_options(out: &str) -> Vec<String> {
    let usage = out
        .split("Usage:\n")
        .nth(1)
        .unwrap()
        .split("\n\n")
        .next()
        .unwrap();
    let mut v: Vec<String> = usage
        .split(|c: char| c.is_whitespace() || c == '[' || c == ']')
        .filter_map(|w| w.split_once('=').map(|(k, _)| k.to_string()))
        .filter(|k| !k.is_empty() && !k.starts_with('<'))
        .collect();
    if let Some(line) = usage.lines().find(|l| l.trim().starts_with("resources:")) {
        v.extend(
            line.trim()["resources:".len()..]
                .split_whitespace()
                .map(String::from),
        );
    }
    v.sort();
    v.dedup();
    v
}

#[test]
fn verb_help_matches_golden_and_lists_every_option() {
    for verb in VERBS {
        let r = resh(&["proc", verb, "--help"]);
        assert_eq!(r.code, 0, "{verb}");
        assert_eq!(r.stderr, "");
        assert_plain(&r.stdout);
        assert!(
            r.stdout
                .starts_with(&format!("Handle: proc\nVerb: {verb}\nDefinition: "))
        );
        for section in ["\nUsage:\n", "\nExample:\n", "\nExample Output:\n"] {
            assert!(r.stdout.contains(section), "{verb}: {section:?}");
        }
        assert_eq!(r.stdout, golden(verb), "{verb}: help differs from golden");
        let mut want: Vec<String> = options_for(verb).iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(usage_options(&r.stdout), want, "{verb}");
        for alt in [
            vec!["proc".to_string(), verb.to_string(), "-h".into()],
            vec!["help".into(), "proc".into(), verb.to_string()],
            vec![format!("proc://--help={verb}")],
            vec!["proc://--help.help".into(), format!("verb={verb}")],
            vec![format!("proc://self.{verb}(help=1)")],
            vec![format!("proc://self.{verb}"), "--help".into()],
        ] {
            let argv: Vec<&str> = alt.iter().map(String::as_str).collect();
            assert_eq!(resh(&argv).stdout, r.stdout, "{alt:?}");
        }
    }
}

/// The keys of a JSON value, recursively.
fn shape(v: &Value, prefix: &str, out: &mut Vec<String>) {
    if let Value::Object(m) = v {
        for (k, v) in m {
            let p = format!("{prefix}.{k}");
            out.push(p.clone());
            shape(v, &p, out);
        }
    }
}

fn shape_of(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    shape(v, "", &mut out);
    out.sort();
    out
}

/// Every help example runs against a child of this test (1234 is replaced
/// by its PID) and prints the fields of its sample output. `nice.dec` needs
/// root to lower a nice value; without it the refusal is checked instead
/// (the Docker test runs it as root).
#[test]
fn help_examples_run_and_match_their_sample_output() {
    for verb in VERBS {
        let help = resh(&["proc", verb, "--help"]).stdout;
        let example = help
            .split("Example:\n")
            .nth(1)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .trim()
            .to_string();
        let kid = Kid::spawn();
        let state = tempfile::tempdir().unwrap();
        let dir = state.path().join(format!("resh/proc/{}", kid.pid()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("stdout.log"), "worker started\nprocessing\n").unwrap();
        if *verb == "nice.dec" {
            assert_eq!(resh(&[&kid.url("nice.set"), "value=10"]).code, 0);
        }
        let local = example.replace("1234", &kid.pid());
        let mut argv: Vec<&str> = local.split_whitespace().collect();
        assert_eq!(argv.remove(0), "resh");
        let r = resh_env(&argv, &[("XDG_STATE_HOME", state.path().to_str().unwrap())]);
        if *verb == "nice.dec" && !may_lower_nice_to(5) {
            assert_fail(&r, 1, "proc.permission_denied");
            continue;
        }
        assert_eq!(r.code, 0, "{verb}: {local}: {}\n{}", r.stdout, r.stderr);
        let sample: String = help
            .split("Example Output:\n")
            .nth(1)
            .unwrap()
            .split("\n\n")
            .next()
            .unwrap()
            .to_string();
        let sample: Value = serde_json::from_str(&sample).unwrap();
        assert_eq!(shape_of(&r.json), shape_of(&sample), "{verb}");
    }
}

#[test]
fn lowering_nice_without_privilege_is_permission_denied() {
    if is_root() {
        return; // root has CAP_SYS_NICE; see tests/proc_e2e_docker.rs
    }
    let kid = Kid::spawn();
    assert_eq!(resh(&[&kid.url("nice.set"), "value=10"]).code, 0);
    for (verb, arg) in [
        ("nice.set", "value=5"),
        ("nice.dec", "delta=1"),
        ("setPriority", "class=normal"),
        ("setPriority", "nice=9"),
    ] {
        let r = resh(&[&kid.url(verb), arg]);
        assert_fail(&r, 1, "proc.permission_denied");
        assert_eq!(kid.nice(), 10, "{verb} {arg}");
    }
    // Raising it is still allowed.
    let r = resh(&[&kid.url("nice.inc"), "delta=1"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(kid.nice(), 11);
}
