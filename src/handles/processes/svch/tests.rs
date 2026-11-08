//! Unit tests: argument checking, names, help, and every systemd verb
//! against a scripted mock of the service manager (no D-Bus, nothing on the
//! host is touched). OpenRC and systemctl paths run fake tools from a
//! temporary directory.

use super::bus::{
    Bus, BusErrKind, BusError, FileChanges, FileOp, JobRemoved, JobWatch, SystemctlBus, UnitInfo,
    classify, classify_systemctl, parse_show,
};
use super::systemd::{JobEnd, run_jobs};
use super::*;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

fn url(s: &str) -> Url {
    Url::parse(s).unwrap()
}

fn args(pairs: &[(&str, &str)]) -> Args {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// ---------------------------------------------------------------------------
// Mock service manager

/// What a queued job does: finish with a result, or never finish.
#[derive(Clone)]
enum JobPlan {
    Finish(&'static str),
    /// The job is done, but the unit then shows this state/sub-state/result.
    DoneThen(&'static str, &'static str, &'static str),
    Hang,
    Refuse(BusErrKind),
}

struct Mock {
    units: RefCell<HashMap<String, UnitInfo>>,
    file_state: RefCell<HashMap<String, String>>,
    plans: RefCell<HashMap<(String, String), JobPlan>>,
    cancel_ok: bool,
    /// Result signalled for a cancelled job.
    cancel_signal: Option<&'static str>,
    unit_err: Option<BusErrKind>,
    files_err: Option<BusErrKind>,
    no_install: bool,
    reload_err: Option<BusErrKind>,
    calls: RefCell<Vec<String>>,
    queue: Rc<RefCell<VecDeque<JobRemoved>>>,
    jobs: RefCell<u32>,
}

impl Mock {
    fn new() -> Self {
        Mock {
            units: RefCell::new(HashMap::new()),
            file_state: RefCell::new(HashMap::new()),
            plans: RefCell::new(HashMap::new()),
            cancel_ok: true,
            cancel_signal: Some("canceled"),
            unit_err: None,
            files_err: None,
            no_install: false,
            reload_err: None,
            calls: RefCell::new(Vec::new()),
            queue: Rc::new(RefCell::new(VecDeque::new())),
            jobs: RefCell::new(0),
        }
    }
    fn with_unit(self, unit: &str, active: &str) -> Self {
        self.units.borrow_mut().insert(
            unit.to_string(),
            UnitInfo {
                load_state: "loaded".into(),
                active_state: active.into(),
                sub_state: if active == "active" {
                    "running"
                } else {
                    "dead"
                }
                .into(),
                description: format!("{unit} test"),
                pid: if active == "active" { 42 } else { 0 },
                active_enter_us: 1_760_000_000_000_000,
                ..UnitInfo::default()
            },
        );
        self
    }
    fn plan(self, method: &str, unit: &str, p: JobPlan) -> Self {
        self.plans
            .borrow_mut()
            .insert((method.to_string(), unit.to_string()), p);
        self
    }
    fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }
    fn err(kind: BusErrKind) -> BusError {
        BusError::new(kind, format!("mock {kind:?}"))
    }
}

struct MockWatch(Rc<RefCell<VecDeque<JobRemoved>>>);

impl JobWatch for MockWatch {
    fn next(&mut self, _until: Instant) -> Option<JobRemoved> {
        self.0.borrow_mut().pop_front()
    }
}

impl Bus for Mock {
    fn unit(&self, unit: &str) -> Result<UnitInfo, BusError> {
        if let Some(k) = self.unit_err {
            return Err(Mock::err(k));
        }
        Ok(self.units.borrow().get(unit).cloned().unwrap_or(UnitInfo {
            load_state: "not-found".into(),
            active_state: "inactive".into(),
            sub_state: "dead".into(),
            ..UnitInfo::default()
        }))
    }
    fn unit_file_state(&self, unit: &str) -> Result<String, BusError> {
        if let Some(k) = self.unit_err {
            return Err(Mock::err(k));
        }
        self.file_state
            .borrow()
            .get(unit)
            .cloned()
            .ok_or_else(|| Mock::err(BusErrKind::NotFound))
    }
    fn watch_jobs(&self) -> Result<Box<dyn JobWatch>, BusError> {
        self.calls.borrow_mut().push("watch".into());
        Ok(Box::new(MockWatch(self.queue.clone())))
    }
    fn enqueue(
        &self,
        method: &'static str,
        unit: &str,
        mode: &'static str,
    ) -> Result<String, BusError> {
        self.calls
            .borrow_mut()
            .push(format!("{method} {unit} {mode}"));
        let plan = self
            .plans
            .borrow()
            .get(&(method.to_string(), unit.to_string()))
            .cloned();
        let plan = match plan {
            Some(p) => p,
            None if self.units.borrow().contains_key(unit) || method == "StartUnit" => {
                JobPlan::Finish("done")
            }
            None => JobPlan::Refuse(BusErrKind::NotFound),
        };
        let id = {
            let mut n = self.jobs.borrow_mut();
            *n += 1;
            *n
        };
        let path = format!("/org/freedesktop/systemd1/job/{id}");
        match plan {
            JobPlan::Refuse(k) => return Err(Mock::err(k)),
            JobPlan::Hang => {}
            JobPlan::DoneThen(state, sub, result) => {
                let mut units = self.units.borrow_mut();
                let e = units.entry(unit.to_string()).or_default();
                e.load_state = "loaded".into();
                e.active_state = state.into();
                e.sub_state = sub.into();
                e.result = result.into();
                self.queue.borrow_mut().push_back(JobRemoved {
                    path: path.clone(),
                    result: "done".into(),
                });
            }
            JobPlan::Finish(r) => {
                if r == "done" {
                    let state = match method {
                        "StopUnit" => "inactive",
                        "ReloadUnit" => "active",
                        _ => "active",
                    };
                    let mut units = self.units.borrow_mut();
                    let e = units.entry(unit.to_string()).or_insert_with(|| UnitInfo {
                        load_state: "loaded".into(),
                        ..UnitInfo::default()
                    });
                    e.active_state = state.into();
                } else if r != "skipped"
                    && let Some(u) = self.units.borrow_mut().get_mut(unit)
                {
                    u.active_state = "failed".into();
                }
                self.queue.borrow_mut().push_back(JobRemoved {
                    path: path.clone(),
                    result: r.into(),
                });
            }
        }
        Ok(path)
    }
    fn cancel_job(&self, job: &str) -> Result<(), BusError> {
        self.calls.borrow_mut().push(format!("cancel {job}"));
        if !self.cancel_ok {
            return Err(Mock::err(BusErrKind::Other));
        }
        if let Some(r) = self.cancel_signal {
            self.queue.borrow_mut().push_back(JobRemoved {
                path: job.to_string(),
                result: r.into(),
            });
        }
        Ok(())
    }
    fn unit_files(&self, op: FileOp, unit: &str, force: bool) -> Result<FileChanges, BusError> {
        self.calls.borrow_mut().push(format!(
            "files {} {unit}{}",
            op.verb(),
            if force { " force" } else { "" }
        ));
        if let Some(k) = self.files_err {
            return Err(Mock::err(k));
        }
        if self.no_install {
            return Ok(FileChanges {
                carries_install_info: Some(false),
                changes: vec![],
            });
        }
        Ok(FileChanges {
            carries_install_info: (op == FileOp::Enable).then_some(true),
            changes: vec![("symlink".into(), "/etc/x".into(), "/lib/x".into())],
        })
    }
    fn daemon_reload(&self) -> Result<(), BusError> {
        self.calls.borrow_mut().push("daemon-reload".into());
        match self.reload_err {
            Some(k) => Err(Mock::err(k)),
            None => Ok(()),
        }
    }
    fn list_units(&self) -> Result<Vec<(String, String)>, BusError> {
        Ok(self
            .units
            .borrow()
            .iter()
            .map(|(n, i)| (n.clone(), i.active_state.clone()))
            .collect())
    }
}

/// Runs `verb args` on systemd through `mock`, as `execute` does: the
/// arguments are checked, the verb runs and its result is written.
fn on_mock(name: &str, verb: &str, a: &[(&str, &str)], mock: &Mock) -> Out {
    let h = SvcHandle::from_url(&url(&format!("svc://{name}"))).unwrap();
    let (mut o, mut e) = (Vec::new(), Vec::new());
    let mut i: &[u8] = &[];
    let mut io = IoStreams {
        stdin: &mut i,
        stdout: &mut o,
        stderr: &mut e,
    };
    let status = match parse_args(verb, &args(a)) {
        Err(f) => report(&mut io, None, f).unwrap(),
        Ok((op, ms)) => {
            let ms = ms.unwrap_or(0);
            let c = Ctx {
                name: h.name.clone(),
                unit: h.unit_name(),
                timeout_ms: ms,
                deadline: Instant::now() + Duration::from_millis(ms),
            };
            let mut warn = Vec::new();
            let reply = SvcHandle::on_systemd(mock, &c, &op, &mut warn);
            for w in warn {
                writeln!(io.stderr, "warning: {w}").unwrap();
            }
            emit(&mut io, reply).unwrap()
        }
    };
    Out {
        status,
        out: String::from_utf8(o).unwrap(),
        err: String::from_utf8(e).unwrap(),
    }
}

struct Out {
    status: Status,
    out: String,
    err: String,
}

impl Out {
    fn json(&self) -> Value {
        serde_json::from_str(self.out.trim()).unwrap_or(Value::Null)
    }
    fn ok(self) -> Self {
        assert!(self.status.ok, "{}\n{}", self.out, self.err);
        assert_eq!(self.err, "", "{}", self.err);
        self
    }
    fn fails(self, exit: i32, code: &str) -> Self {
        assert_eq!(self.status.exit_code(), exit, "{}\n{}", self.out, self.err);
        assert!(
            self.err.starts_with(&format!("Error: [{code}] ")),
            "{}",
            self.err
        );
        if let Some(e) = self.json().get("error") {
            assert_eq!(e["code"], code, "{}", self.out);
        }
        self
    }
}

/// Calls the handle the way the dispatcher does.
fn call(stage_target: &str, verb: &str, a: &[(&str, &str)]) -> Out {
    let h = SvcHandle::from_url(&url(stage_target)).unwrap();
    let (mut o, mut e) = (Vec::new(), Vec::new());
    let mut i: &[u8] = &[];
    let status = {
        let mut io = IoStreams {
            stdin: &mut i,
            stdout: &mut o,
            stderr: &mut e,
        };
        h.call(verb, &args(a), &mut io).unwrap()
    };
    Out {
        status,
        out: String::from_utf8(o).unwrap(),
        err: String::from_utf8(e).unwrap(),
    }
}

// ---------------------------------------------------------------------------
// Names, help and arguments

#[test]
fn help_detection_is_exact() {
    assert!(SvcHandle::should_show_help(&url("svc://--help")));
    assert!(SvcHandle::should_show_help(&url("svc://-h")));
    assert!(SvcHandle::should_show_help(&url("svc://x/--help")));
    assert!(SvcHandle::should_show_help(&url("svc://x?help")));
    assert!(!SvcHandle::should_show_help(&url("svc://my-httpd")));
    assert!(!SvcHandle::should_show_help(&url("svc://pre-hotfix")));
    assert!(!SvcHandle::should_show_help(&url("svc://x/my-hosts")));
    assert!(!SvcHandle::should_show_help(&url("svc://nginx")));
}

fn handle_of(stage: &str) -> SvcHandle {
    let parsed = crate::core::parse::parse_stage(stage).unwrap();
    SvcHandle::from_url(&url(&parsed.target)).unwrap()
}

// FUNC-07: instance units keep their full name through the CLI parser.
#[test]
fn instance_and_template_names_are_preserved() {
    for (stage, name, unit) in [
        ("svc://getty@tty1.stop", "getty@tty1", "getty@tty1.service"),
        (
            "svc://openvpn-client@work.restart",
            "openvpn-client@work",
            "openvpn-client@work.service",
        ),
        (
            "svc://container-getty@1.service.status",
            "container-getty@1.service",
            "container-getty@1.service",
        ),
        ("svc://nginx.status", "nginx", "nginx.service"),
        (
            "svc://NetworkManager.status",
            "NetworkManager",
            "NetworkManager.service",
        ),
        ("svc://user@1000.status", "user@1000", "user@1000.service"),
        (
            "svc://worker@.service.scale",
            "worker@.service",
            "worker@.service",
        ),
    ] {
        let h = handle_of(stage);
        assert_eq!(h.name, name, "{stage}");
        assert_eq!(h.unit_name(), unit, "{stage}");
        assert!(validate_service_name(&h.name).is_ok(), "{stage}");
    }
    assert_eq!(systemd::template_base("worker@.service"), Some("worker"));
    assert_eq!(systemd::template_base("worker@1.service"), None);
    assert_eq!(systemd::template_base("@.service"), None);
}

#[test]
fn invalid_service_names_are_rejected_before_any_command() {
    for name in [
        "",
        "-H",
        "--now",
        "../x",
        "a/b",
        ".hidden",
        "a b",
        "a\tb",
        "getty:x@tty1",
        "a;b",
        "a$b",
        &"x".repeat(257),
    ] {
        assert!(validate_service_name(name).is_err(), "{name:?}");
    }
    for name in ["nginx", "a-b_c.d", "getty@tty1", "x\\x2d", &"x".repeat(256)] {
        assert!(validate_service_name(name).is_ok(), "{name:?}");
    }
    // Through call(): rejected with exit 2 before anything runs, even with
    // no service manager to ask.
    for verb in VERBS {
        let o = call("svc://a:b@tty1", verb, &[]);
        assert_eq!(o.status.exit_code(), 2, "{verb}");
        assert!(
            o.err
                .starts_with("Error: [svc.invalid_target] invalid service name")
        );
        assert!(o.out.is_empty());
    }
}

#[test]
fn help_verbs_and_unknown_verbs() {
    let o = call("svc://nginx", "help", &[]).ok();
    assert!(o.out.starts_with("Handle: svc\n"), "{}", o.out);
    let o = call("svc://nginx", "help", &[("verb", "stop")]).ok();
    assert!(o.out.contains("Verb: stop"), "{}", o.out);
    let o = call("svc://nginx", "--help=wait", &[]).ok();
    assert!(o.out.contains("Verb: wait"), "{}", o.out);
    let o = call("svc://--help", "", &[]).ok();
    assert!(o.out.starts_with("Handle: svc\n"));
    call("svc://nginx", "help", &[("verb", "frob")]).fails(2, "svc.unknown_verb");

    let o = call("svc://nginx", "stauts", &[]).fails(2, "svc.unknown_verb");
    assert!(o.err.contains("did you mean `status`?"), "{}", o.err);
    let o = call("svc://nginx", "invalidverb", &[]).fails(2, "svc.unknown_verb");
    assert!(o.out.is_empty());
}

#[test]
fn every_documented_verb_has_help_and_an_argument_list() {
    let h = SvcHandle::from_url(&url("svc://x")).unwrap();
    for v in VERBS {
        assert!(h.verbs().contains(v), "{v}");
        let help = SVC_HELP.verbs.iter().find(|x| x.name == *v).unwrap();
        let usage = help.detail.as_ref().unwrap().usage;
        // Every option in the usage is accepted, and nothing else.
        let mut listed: Vec<&str> = usage
            .split(|c: char| c.is_whitespace() || c == '[' || c == ']')
            .filter_map(|w| w.split_once('=').map(|(k, _)| k))
            .collect();
        listed.sort_unstable();
        let mut accepted = verb_args(v).to_vec();
        accepted.sort_unstable();
        assert_eq!(listed, accepted, "{v}: {usage}");
    }
    assert_eq!(SVC_HELP.verbs.len(), VERBS.len());
}

#[test]
fn arguments_are_checked_strictly() {
    for v in VERBS {
        let e = parse_args(v, &args(&[("bogus", "1")])).unwrap_err();
        assert_eq!((e.exit, e.code), (2, "svc.invalid_argument"), "{v}");
        assert!(e.msg.contains("bogus"), "{}", e.msg);
        let e = parse_args(v, &args(&[("dry_run", "true")])).unwrap_err();
        assert!(e.msg.contains("no dry-run mode"), "{}", e.msg);
        let e = parse_args(v, &args(&[("dry_run", "maybe")])).unwrap_err();
        assert_eq!(e.code, "svc.invalid_argument");
        let extra = if *v == "scale" {
            vec![("count", "1")]
        } else {
            vec![]
        };
        let mut a = extra.clone();
        a.push(("dry_run", "false"));
        assert!(parse_args(v, &args(&a)).is_ok(), "{v}");
        let mut a = extra.clone();
        a.push(("timeout_ms", "0"));
        assert!(parse_args(v, &args(&a)).is_err(), "{v}");
        let mut a = extra.clone();
        a.push(("timeout_ms", "abc"));
        assert!(parse_args(v, &args(&a)).is_err(), "{v}");
        let mut a = extra;
        a.push(("timeout_ms", "1500"));
        assert_eq!(parse_args(v, &args(&a)).unwrap().1, Some(1500), "{v}");
    }
    let e = parse_args("status", &args(&[("timeout", "5")])).unwrap_err();
    assert!(e.msg.contains("did you mean `timeout_ms`?"), "{}", e.msg);
    let e = parse_args("logs", &args(&[("line", "5")])).unwrap_err();
    assert!(e.msg.contains("did you mean `lines`?"), "{}", e.msg);

    // Defaults.
    for (v, ms) in [
        ("status", 30_000),
        ("is-enabled", 30_000),
        ("start", 120_000),
        ("stop", 120_000),
        ("restart", 120_000),
        ("reload", 120_000),
        ("enable", 30_000),
        ("disable", 30_000),
        ("mask", 30_000),
        ("unmask", 30_000),
        ("wait", 10_000),
        ("logs", 600_000),
    ] {
        assert_eq!(parse_args(v, &Args::new()).unwrap().1, Some(ms), "{v}");
    }

    // stop
    assert_eq!(
        parse_args("stop", &args(&[("timeout", "500"), ("force", "yes")])).unwrap(),
        (Op::Stop { force: true }, Some(500))
    );
    assert!(parse_args("stop", &args(&[("timeout", "5"), ("timeout_ms", "5")])).is_err());
    assert!(parse_args("stop", &args(&[("timeout", "-1")])).is_err());
    let e = parse_args("stop", &args(&[("force", "please")])).unwrap_err();
    assert!(e.msg.contains("force"), "{}", e.msg);

    // wait
    assert_eq!(
        parse_args("wait", &args(&[("state", "stopped"), ("timeout", "700")])).unwrap(),
        (
            Op::Wait {
                active: false,
                state: "stopped".into()
            },
            Some(700)
        )
    );
    let e = parse_args("wait", &args(&[("state", "dead")])).unwrap_err();
    assert!(e.msg.contains("state"), "{}", e.msg);
    assert!(parse_args("wait", &args(&[("timeout", "soon")])).is_err());

    // logs
    let (op, ms) = parse_args(
        "logs",
        &args(&[
            ("lines", "5"),
            ("since", "-1h"),
            ("until", "now"),
            ("level", "error"),
            ("reverse", "true"),
        ]),
    )
    .unwrap();
    assert_eq!(ms, Some(600_000));
    let Op::Logs(o) = op else { panic!() };
    assert_eq!(
        logs::journal_args("x.service", &o),
        [
            "--unit=x.service",
            "--lines=5",
            "--no-pager",
            "--output=short-iso",
            "--since=-1h",
            "--until=now",
            "--priority=err",
            "--reverse"
        ]
    );
    let (op, ms) = parse_args("logs", &args(&[("follow", "on")])).unwrap();
    assert_eq!(ms, None);
    let Op::Logs(o) = op else { panic!() };
    assert!(o.follow && o.follow_for.is_none());
    assert_eq!(o.lines, 200);
    let (op, _) = parse_args("logs", &args(&[("follow", "1"), ("timeout_ms", "300")])).unwrap();
    let Op::Logs(o) = op else { panic!() };
    assert_eq!(o.follow_for, Some(Duration::from_millis(300)));
    for bad in [
        [("lines", "0")],
        [("lines", "x")],
        [("level", "loud")],
        [("since", "")],
        [("until", " ")],
        [("reverse", "maybe")],
        [("follow", "2")],
    ] {
        assert!(parse_args("logs", &args(&bad)).is_err(), "{bad:?}");
    }
    assert!(parse_args("logs", &args(&[("follow", "true"), ("reverse", "true")])).is_err());

    // scale
    assert_eq!(
        parse_args("scale", &args(&[("count", "0")])).unwrap().0,
        Op::Scale { count: 0 }
    );
    for bad in ["", "-1", "x", "1001"] {
        assert!(
            parse_args("scale", &args(&[("count", bad)])).is_err(),
            "{bad}"
        );
    }
    let e = parse_args("scale", &Args::new()).unwrap_err();
    assert!(e.msg.contains("count"), "{}", e.msg);
}

#[test]
fn every_error_code_is_valid_and_documented() {
    let doc = include_str!("../../../../docs/Process_ServiceManagement/svc.md");
    for code in ERROR_CODES {
        assert!(crate::core::status::is_valid_error_code(code), "{code}");
        assert!(doc.contains(&format!("`{code}`")), "{code} not in svc.md");
    }
    // Every svc.* code in the sources is in the list.
    for src in [
        include_str!("../svch.rs"),
        include_str!("systemd.rs"),
        include_str!("openrc.rs"),
        include_str!("logs.rs"),
    ] {
        for piece in src.split('"').filter(|p| p.starts_with("svc.")) {
            if piece
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c == '.')
            {
                assert!(ERROR_CODES.contains(&piece), "{piece}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// systemd verbs on the mock

#[test]
fn status_reports_the_unit_or_not_found() {
    let m = Mock::new().with_unit("nginx.service", "active");
    let v = on_mock("nginx", "status", &[], &m).ok().json();
    assert_eq!(v["name"], "nginx.service");
    assert_eq!(v["backend"], "systemd");
    assert_eq!(v["active_state"], "active");
    assert_eq!(v["sub_state"], "running");
    assert_eq!(v["pid"], 42);
    assert_eq!(v["timestamps"]["active_enter"], "2025-10-09T08:53:20+00:00");
    assert_eq!(v["timestamps"]["active_exit"], "");

    let o = on_mock("nosuch", "status", &[], &m).fails(1, "svc.not_found");
    assert_eq!(o.json()["name"], "nosuch.service");

    // A stopped unit is a successful query.
    let m = Mock::new().with_unit("x.service", "inactive");
    assert_eq!(
        on_mock("x", "status", &[], &m).ok().json()["active_state"],
        "inactive"
    );

    for (k, code, exit) in [
        (BusErrKind::Denied, "svc.permission_denied", 1),
        (BusErrKind::Timeout, "svc.timeout", 124),
        (BusErrKind::Unavailable, "svc.backend_unavailable", 1),
        (BusErrKind::Other, "svc.failed", 1),
        (BusErrKind::NotFound, "svc.not_found", 1),
    ] {
        let mut m = Mock::new();
        m.unit_err = Some(k);
        on_mock("x", "status", &[], &m).fails(exit, code);
    }
}

#[test]
fn is_enabled_reports_the_unit_file_state() {
    let m = Mock::new();
    for (state, enabled) in [
        ("enabled", true),
        ("static", true),
        ("indirect", true),
        ("disabled", false),
        ("masked", false),
    ] {
        m.file_state
            .borrow_mut()
            .insert("x.service".into(), state.into());
        let v = on_mock("x", "is-enabled", &[], &m).ok().json();
        assert_eq!(v["enabled"], enabled, "{state}");
        assert_eq!(v["unit_file_state"], state);
        assert_eq!(v["name"], "x");
    }
    // Could not tell is an error, not "false".
    let o = on_mock("nosuch", "is-enabled", &[], &m).fails(1, "svc.not_found");
    assert!(o.json().get("enabled").is_none());
    let mut m = Mock::new();
    m.unit_err = Some(BusErrKind::Denied);
    on_mock("x", "is-enabled", &[], &m).fails(1, "svc.permission_denied");
}

#[test]
fn start_waits_for_the_job_and_reports_its_result() {
    let m = Mock::new().with_unit("web.service", "inactive");
    let v = on_mock("web", "start", &[], &m).ok().json();
    assert_eq!(v["result"], "success");
    assert_eq!(v["job_result"], "done");
    assert_eq!(v["active_state"], "active");
    assert_eq!(v["action"], "start");
    assert_eq!(m.calls(), ["watch", "StartUnit web.service replace"]);

    // A job that fails is a failure (known issue: was reported as success).
    let m = Mock::new().with_unit("bad.service", "inactive").plan(
        "StartUnit",
        "bad.service",
        JobPlan::Finish("failed"),
    );
    let o = on_mock("bad", "start", &[], &m).fails(1, "svc.job_failed");
    let v = o.json();
    assert_eq!(v["result"], "failed");
    assert_eq!(v["job_result"], "failed");
    assert_eq!(v["active_state"], "failed");
    assert!(o.err.contains("'failed'"), "{}", o.err);
    for r in ["dependency", "timeout", "canceled", "assert"] {
        let m = Mock::new().plan("StartUnit", "x.service", JobPlan::Finish(r));
        on_mock("x", "start", &[], &m).fails(1, "svc.job_failed");
    }
    // skipped counts as success, as in systemctl.
    let m = Mock::new().with_unit("x.service", "active").plan(
        "StartUnit",
        "x.service",
        JobPlan::Finish("skipped"),
    );
    on_mock("x", "start", &[], &m).ok();

    // Refused before a job exists.
    for (k, code) in [
        (BusErrKind::NotFound, "svc.not_found"),
        (BusErrKind::Denied, "svc.permission_denied"),
        (BusErrKind::Masked, "svc.masked"),
        (BusErrKind::Other, "svc.failed"),
    ] {
        let m = Mock::new().plan("StartUnit", "x.service", JobPlan::Refuse(k));
        let o = on_mock("x", "start", &[], &m).fails(1, code);
        assert_eq!(o.json()["action"], "start");
    }
    let m = Mock::new().plan(
        "StartUnit",
        "x.service",
        JobPlan::Refuse(BusErrKind::Timeout),
    );
    let o = on_mock("x", "start", &[], &m).fails(124, "svc.timeout");
    assert!(
        o.err.contains("may or may not have been accepted"),
        "{}",
        o.err
    );
}

#[test]
fn a_job_still_running_at_the_deadline_is_cancelled() {
    let m = Mock::new().with_unit("slow.service", "inactive").plan(
        "StartUnit",
        "slow.service",
        JobPlan::Hang,
    );
    let o = on_mock("slow", "start", &[("timeout_ms", "50")], &m).fails(124, "svc.timeout");
    let v = o.json();
    assert_eq!(v["job_canceled"], true);
    assert_eq!(v["result"], "timeout");
    assert!(v["job_result"].is_null());
    assert!(o.err.contains("the job was cancelled"), "{}", o.err);
    assert_eq!(
        m.calls(),
        [
            "watch",
            "StartUnit slow.service replace",
            "cancel /org/freedesktop/systemd1/job/1"
        ]
    );

    // The cancel fails: the outcome is unknown.
    let mut m = Mock::new().plan("RestartUnit", "slow.service", JobPlan::Hang);
    m.cancel_ok = false;
    let o = on_mock("slow", "restart", &[("timeout_ms", "50")], &m).fails(124, "svc.timeout");
    assert_eq!(o.json()["job_canceled"], false);
    assert!(o.err.contains("outcome is unknown"), "{}", o.err);
}

#[test]
fn run_jobs_prefers_a_result_that_races_the_cancel() {
    let mut m = Mock::new().plan("StartUnit", "x.service", JobPlan::Hang);
    m.cancel_signal = Some("done");
    let mut w = m.watch_jobs().unwrap();
    let job = m.enqueue("StartUnit", "x.service", "replace").unwrap();
    let ends = run_jobs(&m, w.as_mut(), &[job], Instant::now());
    assert_eq!(ends, [JobEnd::Result("done".into())]);
    assert!(ends[0].succeeded());

    // No signal after the cancel: canceled as reported by the call.
    let mut m = Mock::new().plan("StartUnit", "x.service", JobPlan::Hang);
    m.cancel_signal = None;
    let mut w = m.watch_jobs().unwrap();
    let job = m.enqueue("StartUnit", "x.service", "replace").unwrap();
    let ends = run_jobs(&m, w.as_mut(), &[job], Instant::now());
    assert_eq!(ends, [JobEnd::TimedOut { canceled: true }]);
}

#[test]
fn restart_uses_restart_unit() {
    let m = Mock::new().with_unit("web.service", "active");
    let v = on_mock("web", "restart", &[], &m).ok().json();
    assert_eq!(v["action"], "restart");
    assert_eq!(v["result"], "success");
    assert_eq!(m.calls(), ["watch", "RestartUnit web.service replace"]);
    let m = Mock::new().plan("RestartUnit", "x.service", JobPlan::Finish("failed"));
    on_mock("x", "restart", &[], &m).fails(1, "svc.job_failed");
}

#[test]
fn stop_waits_for_inactive() {
    let m = Mock::new().with_unit("web.service", "active");
    let v = on_mock("web", "stop", &[("timeout", "5000")], &m)
        .ok()
        .json();
    assert_eq!(v["requested"], true);
    assert_eq!(v["previous_state"], "active");
    assert_eq!(v["final_state"], "inactive");
    assert_eq!(v["reached_inactive"], true);
    assert_eq!(v["timeout_ms"], 5000);
    assert_eq!(v["job_result"], "done");
    assert_eq!(v["note"], "stopped via StopUnit");
    assert_eq!(m.calls(), ["watch", "StopUnit web.service replace"]);

    let m = Mock::new().with_unit("web.service", "active");
    let v = on_mock("web", "stop", &[("force", "true")], &m).ok().json();
    assert!(v["note"].as_str().unwrap().contains("force"));
    assert_eq!(v["timeout_ms"], 120_000);
    assert_eq!(
        m.calls(),
        ["watch", "StopUnit web.service replace-irreversibly"]
    );

    // A missing unit: nothing is queued.
    let m = Mock::new();
    let o = on_mock("nosuch", "stop", &[], &m).fails(1, "svc.not_found");
    assert_eq!(o.json()["requested"], false);
    assert!(m.calls().is_empty());

    let m = Mock::new().with_unit("web.service", "active").plan(
        "StopUnit",
        "web.service",
        JobPlan::Hang,
    );
    let o = on_mock("web", "stop", &[("timeout_ms", "30")], &m).fails(124, "svc.timeout");
    assert_eq!(o.json()["reached_inactive"], false);
    assert_eq!(o.json()["requested"], true);

    let m = Mock::new().with_unit("web.service", "active").plan(
        "StopUnit",
        "web.service",
        JobPlan::Refuse(BusErrKind::Denied),
    );
    let o = on_mock("web", "stop", &[], &m).fails(1, "svc.permission_denied");
    assert_eq!(o.json()["requested"], false);
}

#[test]
fn reload_waits_for_the_job() {
    let m = Mock::new().with_unit("web.service", "active");
    let o = on_mock("web", "reload", &[], &m).ok();
    assert_eq!(o.out, "");
    assert_eq!(m.calls(), ["watch", "ReloadUnit web.service replace"]);
    let m = Mock::new().plan("ReloadUnit", "web.service", JobPlan::Finish("failed"));
    let o = on_mock("web", "reload", &[], &m).fails(1, "svc.job_failed");
    assert_eq!(o.out, "");
    let m = Mock::new().plan(
        "ReloadUnit",
        "web.service",
        JobPlan::Refuse(BusErrKind::Other),
    );
    on_mock("web", "reload", &[], &m).fails(1, "svc.failed");
    let m = Mock::new();
    on_mock("nosuch", "reload", &[], &m).fails(1, "svc.not_found");
    let m = Mock::new().plan("ReloadUnit", "web.service", JobPlan::Hang);
    on_mock("web", "reload", &[("timeout_ms", "20")], &m).fails(124, "svc.timeout");
}

#[test]
fn unit_file_verbs_change_files_and_reload_systemd() {
    for (verb, op) in [
        ("enable", "enable"),
        ("disable", "disable"),
        ("mask", "mask"),
        ("unmask", "unmask"),
    ] {
        let m = Mock::new();
        let o = on_mock("web", verb, &[], &m).ok();
        assert_eq!(o.out, "");
        assert_eq!(
            m.calls(),
            [format!("files {op} web.service"), "daemon-reload".into()]
        );

        let mut m = Mock::new();
        m.files_err = Some(BusErrKind::NotFound);
        on_mock("nosuch", verb, &[], &m).fails(1, "svc.not_found");
        assert_eq!(m.calls().len(), 1, "no reload after a refusal");
        let mut m = Mock::new();
        m.files_err = Some(BusErrKind::Denied);
        on_mock("web", verb, &[], &m).fails(1, "svc.permission_denied");
        let mut m = Mock::new();
        m.files_err = Some(BusErrKind::Timeout);
        let o = on_mock("web", verb, &[], &m).fails(124, "svc.timeout");
        assert!(
            o.err.contains("may or may not have been changed"),
            "{}",
            o.err
        );
        let mut m = Mock::new();
        m.reload_err = Some(BusErrKind::Other);
        let o = on_mock("web", verb, &[], &m).fails(1, "svc.failed");
        assert!(o.err.contains("reloading systemd failed"), "{}", o.err);
    }
    let mut m = Mock::new();
    m.no_install = true;
    let o = on_mock("web", "enable", &[], &m);
    assert!(o.status.ok);
    assert!(
        o.err
            .contains("warning: web.service has no [Install] section"),
        "{}",
        o.err
    );
}

#[test]
fn wait_polls_until_the_state_or_the_deadline() {
    let m = Mock::new().with_unit("web.service", "active");
    let v = on_mock("web", "wait", &[], &m).ok().json();
    assert_eq!(v["reached"], true);
    assert_eq!(v["state"], "active");
    assert_eq!(v["timeout_ms"], 10_000);
    assert_eq!(v["name"], "web");

    let m = Mock::new().with_unit("web.service", "failed");
    let v = on_mock("web", "wait", &[("state", "stopped")], &m)
        .ok()
        .json();
    assert_eq!(v["reached"], true);

    let m = Mock::new().with_unit("web.service", "inactive");
    let start = Instant::now();
    let o = on_mock("web", "wait", &[("timeout_ms", "300")], &m).fails(124, "svc.timeout");
    assert!(start.elapsed() >= Duration::from_millis(300));
    assert!(start.elapsed() < Duration::from_secs(3));
    assert_eq!(o.json()["reached"], false);
    assert_eq!(o.json()["active_state"], "inactive");

    on_mock("nosuch", "wait", &[], &Mock::new()).fails(1, "svc.not_found");
    let mut m = Mock::new();
    m.unit_err = Some(BusErrKind::Denied);
    on_mock("web", "wait", &[], &m).fails(1, "svc.permission_denied");
}

#[test]
fn scale_template_starts_and_stops_numbered_instances() {
    let m = Mock::new()
        .with_unit("worker@1.service", "active")
        .with_unit("worker@4.service", "active")
        .with_unit("worker@5.service", "inactive")
        .with_unit("other@9.service", "active");
    let v = on_mock("worker@.service", "scale", &[("count", "3")], &m)
        .ok()
        .json();
    assert_eq!(v["template"], true);
    assert_eq!(v["desired_count"], 3);
    assert_eq!(
        v["instances_started"],
        json!(["worker@2.service", "worker@3.service"])
    );
    assert_eq!(v["instances_stopped"], json!(["worker@4.service"]));
    assert_eq!(v["effective_count"], 3);
    assert!(
        m.calls()
            .contains(&"StopUnit worker@4.service replace".to_string())
    );
    assert!(!m.calls().iter().any(|c| c.contains("other@")));

    let m = Mock::new();
    let v = on_mock("worker@.service", "scale", &[("count", "1")], &m)
        .ok()
        .json();
    assert_eq!(v["name"], "worker@.service");
    assert_eq!(v["effective_count"], 1);

    let m = Mock::new().plan("StartUnit", "worker@2.service", JobPlan::Finish("failed"));
    let o =
        on_mock("worker@.service", "scale", &[("count", "2")], &m).fails(1, "svc.partial_failure");
    let v = o.json();
    assert_eq!(v["instances_started"], json!(["worker@1.service"]));
    assert_eq!(v["errors"].as_array().unwrap().len(), 1);

    let m = Mock::new().plan("StartUnit", "worker@1.service", JobPlan::Hang);
    let o = on_mock(
        "worker@.service",
        "scale",
        &[("count", "1"), ("timeout_ms", "20")],
        &m,
    )
    .fails(124, "svc.timeout");
    assert_eq!(o.json()["effective_count"], 0);
}

#[test]
fn scale_plain_starts_or_stops_the_service() {
    let m = Mock::new().with_unit("web.service", "active");
    let v = on_mock("web", "scale", &[("count", "0")], &m).ok().json();
    assert_eq!(v["effective_count"], 0);
    assert_eq!(v["template"], false);
    assert_eq!(v["note"], "non-template service scaled to 0");

    let m = Mock::new().with_unit("web.service", "inactive");
    let v = on_mock("web", "scale", &[("count", "4")], &m).ok().json();
    assert_eq!(v["effective_count"], 1);
    assert_eq!(v["desired_count"], 4);
    assert_eq!(v["note"], "non-template service scaled to 1");

    // Already in the wanted state: no job.
    let m = Mock::new().with_unit("web.service", "active");
    on_mock("web", "scale", &[("count", "1")], &m).ok();
    assert!(m.calls().is_empty());

    on_mock("nosuch", "scale", &[("count", "1")], &Mock::new()).fails(1, "svc.not_found");
    let m = Mock::new().with_unit("web.service", "inactive").plan(
        "StartUnit",
        "web.service",
        JobPlan::Finish("failed"),
    );
    let o = on_mock("web", "scale", &[("count", "1")], &m).fails(1, "svc.job_failed");
    assert_eq!(o.json()["effective_count"], 0);
}

// ---------------------------------------------------------------------------
// D-Bus and systemctl error mapping

#[test]
fn dbus_errors_are_classified() {
    for (name, kind) in [
        ("org.freedesktop.systemd1.NoSuchUnit", BusErrKind::NotFound),
        (
            "org.freedesktop.DBus.Error.FileNotFound",
            BusErrKind::NotFound,
        ),
        ("System.Error.ENOENT", BusErrKind::NotFound),
        (
            "org.freedesktop.DBus.Error.AccessDenied",
            BusErrKind::Denied,
        ),
        (
            "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired",
            BusErrKind::Denied,
        ),
        ("org.freedesktop.systemd1.UnitMasked", BusErrKind::Masked),
        (
            "org.freedesktop.DBus.Error.ServiceUnknown",
            BusErrKind::Unavailable,
        ),
        (
            "org.freedesktop.systemd1.JobTypeNotApplicable",
            BusErrKind::Other,
        ),
    ] {
        assert_eq!(classify(name, "d").kind, kind, "{name}");
    }
    assert_eq!(classify("a.B", "").msg, "a.B");
    assert_eq!(classify("a.B", "why").msg, "why (a.B)");

    for (text, kind) in [
        (
            "Failed to start x.service: Unit x.service not found.",
            BusErrKind::NotFound,
        ),
        (
            "Failed to stop x.service: Unit x.service not loaded.",
            BusErrKind::NotFound,
        ),
        (
            "Failed to start x.service: Access denied",
            BusErrKind::Denied,
        ),
        (
            "Failed to start x.service: Interactive authentication required.",
            BusErrKind::Denied,
        ),
        (
            "Failed to start x.service: Unit x.service is masked.",
            BusErrKind::Masked,
        ),
        (
            "System has not been booted with systemd as init system (PID 1).",
            BusErrKind::Unavailable,
        ),
        (
            "Job for x.service failed because the control process exited",
            BusErrKind::Other,
        ),
    ] {
        assert_eq!(classify_systemctl(text), kind, "{text}");
    }
    let info = parse_show(
        "LoadState=loaded\nActiveState=active\nSubState=running\nDescription=A=B\nExecMainPID=7\nExecMainStatus=3\n",
    );
    assert_eq!(
        (
            info.load_state.as_str(),
            info.active_state.as_str(),
            info.description.as_str()
        ),
        ("loaded", "active", "A=B")
    );
    assert_eq!((info.pid, info.exit_status), (7, 3));
}

/// A fake systemctl that records its arguments and answers by unit name.
fn fake_systemctl(dir: &std::path::Path) -> OsString {
    let p = dir.join("systemctl");
    let script = format!(
        r#"#!/bin/sh
echo "$@" >> {log}
for a; do last=$a; done
case "$*" in
  *show*nosuch*) printf 'LoadState=not-found\nActiveState=inactive\nSubState=dead\n' ;;
  *show*) printf 'LoadState=loaded\nActiveState=active\nSubState=running\nExecMainPID=9\n' ;;
  *is-enabled*nosuch*) echo "Failed to get unit file state for nosuch.service: No such file or directory" >&2; exit 1 ;;
  *is-enabled*) echo disabled; exit 1 ;;
  *start*bad*) echo "Job for bad.service failed because the control process exited with error code." >&2; exit 1 ;;
  *start*nosuch*) echo "Failed to start nosuch.service: Unit nosuch.service not found." >&2; exit 5 ;;
  *start*slow*) sleep 5 ;;
  *enable*nosuch*) echo "Failed to enable unit: Unit file nosuch.service does not exist." >&2; exit 1 ;;
  *enable*) echo "Created symlink /etc/systemd/system/multi-user.target.wants/$last → /x/$last." >&2 ;;
  *list-units*) printf 'w@1.service loaded active running W\nw@2.service loaded inactive dead W\n' ;;
esac
exit 0
"#,
        log = dir.join("log").display()
    );
    crate::core::test_support::write_executable(&p, &script);
    p.into_os_string()
}

#[test]
fn systemctl_route_maps_results() {
    let dir = tempfile::tempdir().unwrap();
    let sc = fake_systemctl(dir.path());
    let far = Instant::now() + Duration::from_secs(20);
    let b = SystemctlBus::new(sc.clone(), far);
    assert_eq!(b.unit("x.service").unwrap().active_state, "active");
    assert_eq!(b.unit("nosuch.service").unwrap().load_state, "not-found");
    assert_eq!(b.unit_file_state("x.service").unwrap(), "disabled");
    assert_eq!(
        b.unit_file_state("nosuch.service").unwrap_err().kind,
        BusErrKind::NotFound
    );
    let mut w = b.watch_jobs().unwrap();
    let j = b.enqueue("StartUnit", "x.service", "replace").unwrap();
    assert_eq!(
        w.next(far).unwrap(),
        JobRemoved {
            path: j,
            result: "done".into()
        }
    );
    let j = b.enqueue("StartUnit", "bad.service", "replace").unwrap();
    assert_eq!(w.next(far).unwrap().result, "failed");
    assert!(j.starts_with("systemctl-job-"));
    assert_eq!(
        b.enqueue("StartUnit", "nosuch.service", "replace")
            .unwrap_err()
            .kind,
        BusErrKind::NotFound
    );
    assert!(b.cancel_job("systemctl-job-1").is_err());
    let ch = b.unit_files(FileOp::Enable, "x.service", true).unwrap();
    assert_eq!(ch.carries_install_info, Some(true));
    assert_eq!(ch.changes.len(), 1);
    assert_eq!(
        b.unit_files(FileOp::Enable, "nosuch.service", false)
            .unwrap_err()
            .kind,
        BusErrKind::NotFound
    );
    assert_eq!(
        b.list_units().unwrap(),
        [
            ("w@1.service".to_string(), "active".to_string()),
            ("w@2.service".to_string(), "inactive".to_string())
        ]
    );
    b.enqueue("StopUnit", "x.service", "replace-irreversibly")
        .unwrap();
    let log = std::fs::read_to_string(dir.path().join("log")).unwrap();
    assert!(
        log.contains("--no-ask-password start -- x.service"),
        "{log}"
    );
    assert!(
        log.contains("--no-ask-password stop --job-mode=replace-irreversibly -- x.service"),
        "{log}"
    );
    assert!(
        log.contains("--no-ask-password enable --force -- x.service"),
        "{log}"
    );

    // At the deadline systemctl is stopped and the outcome is unknown.
    let b = SystemctlBus::new(sc, Instant::now() + Duration::from_millis(200));
    let e = b
        .enqueue("StartUnit", "slow.service", "replace")
        .unwrap_err();
    assert_eq!(e.kind, BusErrKind::Timeout);
    let missing = SystemctlBus::new(dir.path().join("none").into(), far);
    assert_eq!(
        missing.unit("x.service").unwrap_err().kind,
        BusErrKind::Unavailable
    );
}

#[test]
fn openrc_pid_and_missing_detection() {
    assert_eq!(openrc::parse_pid(" * status: started (pid 123)"), Some(123));
    assert_eq!(openrc::parse_pid("PID: 77"), Some(77));
    assert_eq!(openrc::parse_pid("rapid 5"), None);
    assert_eq!(openrc::parse_pid("no number"), None);
    assert!(openrc::service_missing(
        " * rc-service: service `nosuch' does not exist"
    ));
    assert!(!openrc::service_missing(" * status: stopped"));
}

#[test]
fn start_checks_the_unit_runs_after_its_job() {
    // A job that is done while the unit already died (Type=simple crash).
    for (state, sub) in [
        ("failed", "failed"),
        ("inactive", "dead"),
        ("activating", "auto-restart"),
        ("deactivating", "stop-sigterm"),
    ] {
        let m = Mock::new().plan(
            "StartUnit",
            "crash.service",
            JobPlan::DoneThen(state, sub, "exit-code"),
        );
        let o = on_mock("crash", "start", &[("settle_ms", "0")], &m).fails(1, "svc.not_active");
        let v = o.json();
        assert_eq!(v["result"], "not_active");
        assert_eq!(v["job_result"], "done");
        assert_eq!(v["active_state"], state);
        assert_eq!(v["sub_state"], sub);
        assert_eq!(v["unit_result"], "exit-code");
        assert!(o.err.contains("exit-code"), "{}", o.err);
    }
    let m = Mock::new().plan(
        "RestartUnit",
        "crash.service",
        JobPlan::DoneThen("failed", "failed", "signal"),
    );
    on_mock("crash", "restart", &[], &m).fails(1, "svc.not_active");
    // Running states: active, reloading, activating (still starting).
    for (state, sub) in [
        ("active", "running"),
        ("reloading", "reload"),
        ("activating", "start"),
    ] {
        let m = Mock::new().plan(
            "StartUnit",
            "x.service",
            JobPlan::DoneThen(state, sub, "success"),
        );
        let v = on_mock("x", "start", &[("settle_ms", "50")], &m)
            .ok()
            .json();
        assert_eq!(v["result"], "success");
        assert_eq!(v["active_state"], state);
    }
    // A oneshot without RemainAfterExit is inactive after a good run.
    let mut i = UnitInfo {
        load_state: "loaded".into(),
        active_state: "inactive".into(),
        sub_state: "dead".into(),
        result: "success".into(),
        service_type: "oneshot".into(),
        ..UnitInfo::default()
    };
    assert!(systemd::running_ok(&i));
    i.remain_after_exit = true;
    assert!(!systemd::running_ok(&i));
    i.remain_after_exit = false;
    i.result = "exit-code".into();
    assert!(!systemd::running_ok(&i));
    i.service_type = "simple".into();
    i.result = "success".into();
    assert!(!systemd::running_ok(&i));

    // The settle window lasts settle_ms, bounded by the deadline.
    let m = Mock::new();
    let t = Instant::now();
    on_mock("x", "start", &[("settle_ms", "300")], &m).ok();
    assert!(t.elapsed() >= Duration::from_millis(300));
    let t = Instant::now();
    on_mock(
        "x",
        "start",
        &[("settle_ms", "5000"), ("timeout_ms", "200")],
        &m,
    )
    .ok();
    assert!(t.elapsed() < Duration::from_secs(2));
    assert!(parse_args("start", &args(&[("settle_ms", "x")])).is_err());
    assert_eq!(
        parse_args("restart", &Args::new()).unwrap().0,
        Op::Restart {
            settle: Duration::from_millis(1000)
        }
    );
}

#[test]
fn enable_and_mask_force_only_on_request() {
    for verb in ["enable", "mask"] {
        let m = Mock::new();
        on_mock("web", verb, &[], &m).ok();
        assert_eq!(m.calls()[0], format!("files {verb} web.service"));
        let m = Mock::new();
        on_mock("web", verb, &[("force", "true")], &m).ok();
        assert_eq!(m.calls()[0], format!("files {verb} web.service force"));
        let mut m = Mock::new();
        m.files_err = Some(BusErrKind::Conflict);
        let o = on_mock("web", verb, &[], &m).fails(1, "svc.link_conflict");
        assert!(o.err.contains("force=true"), "{}", o.err);
    }
    for verb in ["disable", "unmask"] {
        let e = parse_args(verb, &args(&[("force", "true")])).unwrap_err();
        assert_eq!(e.code, "svc.invalid_argument");
    }
    assert!(parse_args("enable", &args(&[("force", "x")])).is_err());
    assert_eq!(
        classify("org.freedesktop.systemd1.UnitExists", "File exists").kind,
        BusErrKind::Conflict
    );
    assert_eq!(
        classify_systemctl("Failed to enable unit: File /etc/x already exists."),
        BusErrKind::Conflict
    );
}

#[test]
fn unit_types_are_kept_and_checked() {
    for (stage, unit) in [
        ("svc://docker.socket.status", "docker.socket"),
        ("svc://fstrim.timer.start", "fstrim.timer"),
        ("svc://multi-user.target.status", "multi-user.target"),
        ("svc://home.mount.reload", "home.mount"),
        ("svc://user.slice.status", "user.slice"),
        ("svc://net.eth0.status", "net.eth0.service"),
        ("svc://a.b.status", "a.b.service"),
    ] {
        assert_eq!(handle_of(stage).unit_name(), unit, "{stage}");
    }
    for (verb, unit) in [
        ("start", "dev-sda.device"),
        ("restart", "session-1.scope"),
        ("stop", "dev-sda.device"),
        ("enable", "session-1.scope"),
        ("mask", "dev-sda.device"),
        ("reload", "docker.socket"),
        ("reload", "fstrim.timer"),
        ("reload", "multi-user.target"),
        ("scale", "docker.socket"),
        ("scale", "fstrim.timer"),
    ] {
        let e = check_unit_type(verb, unit).unwrap_err();
        assert_eq!((e.exit, e.code), (2, "svc.unsupported"), "{verb} {unit}");
    }
    for (verb, unit) in [
        ("start", "docker.socket"),
        ("stop", "session-1.scope"),
        ("reload", "home.mount"),
        ("reload", "x.service"),
        ("scale", "w@.service"),
        ("status", "dev-sda.device"),
        ("wait", "session-1.scope"),
        ("logs", "docker.socket"),
        ("is-enabled", "fstrim.timer"),
        ("enable", "fstrim.timer"),
    ] {
        assert!(check_unit_type(verb, unit).is_ok(), "{verb} {unit}");
    }
}
