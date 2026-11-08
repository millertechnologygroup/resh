//! Integration tests for `svc://` through the built `resh` binary: help
//! output (golden files) in every form, strict arguments and names (exit 2,
//! nothing run), and every verb on the systemctl route and the OpenRC
//! backend with fake tools. Debug builds read the backend from
//! `RESH_TEST_SVC_BACKEND` and the tools from the directory in
//! `RESH_TEST_SVC_TOOLS` (never from PATH then), so no real service manager
//! is asked to change anything. The only host query is a read-only status
//! of a unit that does not exist. Real systemd runs in svc_e2e_docker.rs.

mod common;

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const VERBS: &[&str] = &[
    "status",
    "is-enabled",
    "start",
    "stop",
    "restart",
    "reload",
    "enable",
    "disable",
    "mask",
    "unmask",
    "wait",
    "logs",
    "scale",
];

/// The options each verb accepts (src/handles/processes/svch.rs `verb_args`).
fn accepted(verb: &str) -> Vec<&'static str> {
    let mut v = match verb {
        "stop" => vec!["timeout_ms", "timeout", "force"],
        "wait" => vec!["state", "timeout_ms", "timeout"],
        "logs" => vec![
            "lines",
            "since",
            "until",
            "level",
            "reverse",
            "follow",
            "timeout_ms",
        ],
        "scale" => vec!["count", "timeout_ms"],
        "start" | "restart" => vec!["timeout_ms", "settle_ms"],
        "enable" | "mask" => vec!["timeout_ms", "force"],
        _ => vec!["timeout_ms"],
    };
    v.sort_unstable();
    v
}

fn golden(verb: Option<&str>) -> &'static str {
    match verb {
        None => include_str!("golden/svc_help.txt"),
        Some("status") => include_str!("golden/svc_status_help.txt"),
        Some("is-enabled") => include_str!("golden/svc_is-enabled_help.txt"),
        Some("start") => include_str!("golden/svc_start_help.txt"),
        Some("stop") => include_str!("golden/svc_stop_help.txt"),
        Some("restart") => include_str!("golden/svc_restart_help.txt"),
        Some("reload") => include_str!("golden/svc_reload_help.txt"),
        Some("enable") => include_str!("golden/svc_enable_help.txt"),
        Some("disable") => include_str!("golden/svc_disable_help.txt"),
        Some("mask") => include_str!("golden/svc_mask_help.txt"),
        Some("unmask") => include_str!("golden/svc_unmask_help.txt"),
        Some("wait") => include_str!("golden/svc_wait_help.txt"),
        Some("logs") => include_str!("golden/svc_logs_help.txt"),
        Some("scale") => include_str!("golden/svc_scale_help.txt"),
        Some(v) => panic!("no golden for {v}"),
    }
}

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
    /// Exit status, exactly one `Error: [code] ...` line on stderr, and the
    /// same code in the JSON result when there is one.
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
        if let Some(e) = self.json().get("error") {
            assert_eq!(e["code"], code, "{}", self.out);
        }
        self
    }
}

const SYSTEMCTL: &str = r#"#!/bin/sh
echo "$*" >> "$D/systemctl.log"
for a; do last=$a; done
case "$*" in
  *" show "*)
    case "$last" in
      nosuch*) printf 'LoadState=not-found\nActiveState=inactive\nSubState=dead\n' ;;
      down*) printf 'LoadState=loaded\nActiveState=inactive\nSubState=dead\nDescription=Down\n' ;;
      crash*) printf 'LoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\nType=simple\n' ;;
      *) printf 'LoadState=loaded\nActiveState=active\nSubState=running\nDescription=Web test\nExecMainPID=4242\nExecMainStatus=0\n' ;;
    esac ;;
  *is-enabled*)
    case "$last" in
      nosuch*) echo not-found; exit 4 ;;
      web*) echo enabled ;;
      *) echo disabled; exit 1 ;;
    esac ;;
  *" start "*|*" restart "*|*" reload "*)
    case "$last" in
      bad*) echo "Job for $last failed because the control process exited with error code." >&2; exit 1 ;;
      nosuch*) echo "Failed to start $last: Unit $last not found." >&2; exit 5 ;;
      denied*) echo "Failed to start $last: Access denied" >&2; exit 4 ;;
      masked*) echo "Failed to start $last: Unit $last is masked." >&2; exit 1 ;;
      slow*) sleep 30 ;;
    esac ;;
  *" stop "*) ;;
  *enable*|*disable*|*mask*)
    case "$last" in
      nosuch*) echo "Failed to change unit: Unit file $last does not exist." >&2; exit 1 ;;
      conflict*)
        case "$*" in *--force*) ;; *) echo "Failed to enable unit: File /etc/systemd/system/$last already exists." >&2; exit 1 ;; esac ;;
      noinst*) echo "The unit files have no installation config (WantedBy=, RequiredBy=, ...)." >&2 ;;
      *) echo "Created symlink /etc/systemd/system/x.wants/$last -> /usr/lib/systemd/system/$last." >&2 ;;
    esac ;;
  *list-units*) printf 'w@1.service loaded active running W\nw@3.service loaded active running W\n' ;;
esac
exit 0
"#;

const JOURNALCTL: &str = r#"#!/bin/sh
echo "$*" >> "$D/journalctl.log"
case "$*" in
  *--unit=fail.service*) echo "Failed to parse timestamp: nope" >&2; exit 1 ;;
  *--unit=denied.service*) echo "Hint: You are currently not seeing messages from other users and the system." >&2; exit 0 ;;
  *--unit=slow.service*) sleep 30 ;;
  *--unit=empty.service*) echo "-- No entries --" ;;
  *--follow*) echo "line 1"; sleep 0.3; echo "line 2"; exec sleep 30 ;;
  *) echo "2026-10-16T09:12:44+00:00 web01 web[1]: hello"; echo "2026-10-16T09:12:45+00:00 web01 web[1]: world" ;;
esac
"#;

/// Stateful fake: `web` starts out started, every other service stopped.
const RC_SERVICE: &str = r#"#!/bin/sh
echo "$*" >> "$D/rc-service.log"
if [ "$1" = "--exists" ]; then
  case "$2" in nosuch*) exit 1 ;; *) exit 0 ;; esac
fi
name=$1; action=$2
case "$name" in nosuch*) echo " * rc-service: service \`$name' does not exist" >&2; exit 1 ;; esac
st="$D/state-$name"
[ -f "$st" ] || { case "$name" in web*) echo started > "$st" ;; *) echo stopped > "$st" ;; esac; }
case "$action" in
  status)
    if [ "$(cat "$st")" = started ]; then echo " * status: started (pid 77)"; exit 0; fi
    echo " * status: stopped"; exit 3 ;;
  start|restart)
    case "$name" in
      bad*) echo " * ERROR: $name failed to start" >&2; exit 1 ;;
      slow*) sleep 30 ;;
    esac
    echo started > "$st" ;;
  stop) echo stopped > "$st" ;;
  reload) case "$name" in bad*) echo " * ERROR: cannot reload" >&2; exit 1 ;; esac ;;
esac
exit 0
"#;

const RC_UPDATE: &str = r#"#!/bin/sh
echo "$*" >> "$D/rc-update.log"
case "$1" in
  show) echo "                web | default"; echo "               sshd | default" ;;
  add|del) case "$2" in bad*) echo " * rc-update: cannot change runlevel" >&2; exit 1 ;; esac ;;
esac
"#;

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        let env = Env {
            dir: tempfile::TempDir::new().unwrap(),
        };
        let d = env.dir.path();
        for (name, body) in [
            ("systemctl", SYSTEMCTL),
            ("journalctl", JOURNALCTL),
            ("rc-service", RC_SERVICE),
            ("rc-update", RC_UPDATE),
            ("tail", "#!/bin/sh\nexec tail \"$@\"\n"),
        ] {
            common::write_executable(&d.join(name), body);
        }
        std::fs::create_dir_all(d.join("root/var/log/web")).unwrap();
        std::fs::write(d.join("root/var/log/web/current"), "one\ntwo\nthree\n").unwrap();
        env
    }

    fn dir(&self) -> &Path {
        self.dir.path()
    }

    fn cmd(&self, backend: &str, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_resh"));
        c.args(args)
            .env("RESH_TEST_SVC_BACKEND", backend)
            .env("RESH_TEST_SVC_TOOLS", self.dir())
            .env("D", self.dir())
            .env_remove("SSH_AUTH_SOCK");
        c
    }

    fn run(&self, backend: &str, args: &[&str]) -> Run {
        let out = self.cmd(backend, args).output().unwrap();
        Run {
            code: out.status.code().unwrap_or(-1),
            out: String::from_utf8_lossy(&out.stdout).into_owned(),
            err: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// The fake tool's argument log (empty when it never ran).
    fn log(&self, tool: &str) -> String {
        std::fs::read_to_string(self.dir().join(format!("{tool}.log"))).unwrap_or_default()
    }

    fn ran_nothing(&self) {
        for t in ["systemctl", "journalctl", "rc-service", "rc-update"] {
            assert_eq!(self.log(t), "", "{t} ran");
        }
    }

    fn remove(&self, tool: &str) -> PathBuf {
        let p = self.dir().join(tool);
        std::fs::remove_file(&p).unwrap();
        p
    }
}

fn assert_plain_text(out: &str) {
    assert!(out.is_ascii() && !out.contains('\x1b'));
    for l in out.lines() {
        assert!(l.len() <= 80, "line over 80 columns: {l:?}");
        assert!(!l.ends_with(' '), "trailing space: {l:?}");
    }
}

// --- help ---------------------------------------------------------------------------

#[test]
fn handle_help_matches_golden_in_every_form() {
    let env = Env::new();
    for form in [
        vec!["svc", "--help"],
        vec!["svc", "-h"],
        vec!["svc", "help"],
        vec!["help", "svc"],
        vec!["svc://--help"],
        vec!["svc://-h"],
        vec!["svc://nginx.help"],
    ] {
        let r = env.run("none", &form).ok();
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
    assert_eq!(listed, VERBS);
    env.ran_nothing();
}

#[test]
fn verb_help_matches_golden_and_lists_exactly_the_accepted_options() {
    let env = Env::new();
    for verb in VERBS {
        let in_url = format!("svc://--help={verb}");
        let stage = format!("svc://nginx.{verb}");
        for form in [
            vec!["svc", verb, "--help"],
            vec!["svc", verb, "-h"],
            vec!["help", "svc", verb],
            vec![in_url.as_str()],
            vec![stage.as_str(), "--help"],
        ] {
            let r = env.run("none", &form).ok();
            assert_eq!(r.out, golden(Some(verb)), "{form:?}");
        }
        let out = golden(Some(verb));
        assert_plain_text(out);
        for section in ["Usage:\n", "Example:\n"] {
            assert!(out.contains(section), "{verb} {section}");
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
            .map(|(k, _)| k)
            .collect();
        listed.sort_unstable();
        listed.dedup();
        assert_eq!(listed, accepted(verb), "{verb}: {usage}");
    }
    env.ran_nothing();
}

#[test]
fn unknown_verbs_and_bad_names_exit_2() {
    let env = Env::new();
    let r = env.run("none", &["svc", "stauts", "--help"]);
    assert_eq!(r.code, 2);
    assert!(r.err.contains("status"), "{}", r.err);
    env.run("none", &["svc://--help=frob"])
        .fails(2, "svc.unknown_verb");
    let r = env
        .run("systemctl", &["svc://nginx.stauts"])
        .fails(2, "svc.unknown_verb");
    assert!(r.err.contains("did you mean `status`?"), "{}", r.err);
    env.run("systemctl", &["svc://nginx.is-active"])
        .fails(2, "svc.unknown_verb");
    for stage in [
        "svc://-x.status",
        "svc://a:b@tty1.status",
        "svc://a%20b.start",
        "svc://a%3Bb.stop",
        "svc://.x.status",
    ] {
        let r = env
            .run("systemctl", &[stage])
            .fails(2, "svc.invalid_target");
        assert!(r.out.is_empty(), "{stage}");
    }
    env.ran_nothing();
}

#[test]
fn invalid_arguments_exit_2_and_run_nothing() {
    let env = Env::new();
    for backend in ["systemctl", "openrc"] {
        for verb in VERBS {
            let stage = format!("svc://web.{verb}");
            let count: &[&str] = if *verb == "scale" { &["count=1"] } else { &[] };
            let with = |extra: &str| {
                let mut v = vec![stage.as_str()];
                v.extend_from_slice(count);
                v.push(extra);
                env.run(backend, &v)
            };
            let r = with("bogus=1").fails(2, "svc.invalid_argument");
            assert!(r.err.contains("bogus"), "{}", r.err);
            assert!(r.out.is_empty());
            let r = with("dry_run=true").fails(2, "svc.invalid_argument");
            assert!(r.err.contains("dry"), "{}", r.err);
            with("timeout_ms=0").fails(2, "svc.invalid_argument");
            with("timeout_ms=soon").fails(2, "svc.invalid_argument");
            let r = env.run(backend, &[&stage, "dry-run=true"]);
            assert_eq!(r.code, 2, "{}", r.err);
        }
        for args in [
            vec!["svc://web.stop", "force=perhaps"],
            vec!["svc://web.stop", "timeout=1", "timeout_ms=1"],
            vec!["svc://web.wait", "state=dead"],
            vec!["svc://web.wait", "timeout=x"],
            vec!["svc://web.logs", "lines=0"],
            vec!["svc://web.logs", "level=loud"],
            vec!["svc://web.logs", "since="],
            vec!["svc://web.logs", "follow=true", "reverse=true"],
            vec!["svc://web.logs", "reverse=maybe"],
            vec!["svc://web.scale"],
            vec!["svc://web.scale", "count=-1"],
            vec!["svc://web.scale", "count=1001"],
            vec!["svc://web.status", "timeout=5"],
        ] {
            env.run(backend, &args).fails(2, "svc.invalid_argument");
        }
    }
    let r = env
        .run("systemctl", &["svc://web.status", "timout_ms=5"])
        .fails(2, "svc.invalid_argument");
    assert!(r.err.contains("did you mean `timeout_ms`?"), "{}", r.err);
    env.ran_nothing();
}

// --- systemd through systemctl --------------------------------------------------------

#[test]
fn status_and_is_enabled_on_systemd() {
    let env = Env::new();
    let v = env.run("systemctl", &["svc://web.status"]).ok().json();
    assert_eq!(v["name"], "web.service");
    assert_eq!(v["active_state"], "active");
    assert_eq!(v["pid"], 4242);
    assert_eq!(v["description"], "Web test");
    let r = env
        .run("systemctl", &["--json-pretty", "svc://nosuch.status"])
        .fails(1, "svc.not_found");
    assert!(r.out.contains("\n  \"error\": {"), "{}", r.out);
    assert_eq!(r.json()["name"], "nosuch.service");

    let v = env.run("systemctl", &["svc://web.is-enabled"]).ok().json();
    assert_eq!(
        (v["enabled"].clone(), v["name"].clone()),
        (true.into(), "web".into())
    );
    let v = env.run("systemctl", &["svc://down.is-enabled"]).ok().json();
    assert_eq!(v["enabled"], false);
    assert_eq!(v["unit_file_state"], "disabled");
    env.run("systemctl", &["svc://nosuch.is-enabled"])
        .fails(1, "svc.not_found");
    let log = env.log("systemctl");
    assert!(log.contains("--no-ask-password show --property="), "{log}");
    assert!(log.contains("-- web.service"), "{log}");
}

#[test]
fn start_restart_reload_report_job_results() {
    let env = Env::new();
    for verb in ["start", "restart"] {
        let v = env
            .run("systemctl", &[&format!("svc://web.{verb}")])
            .ok()
            .json();
        assert_eq!(v["action"], verb);
        assert_eq!(v["result"], "success");
        assert_eq!(v["job_result"], "done");
        assert_eq!(v["active_state"], "active");
        let r = env
            .run("systemctl", &[&format!("svc://bad.{verb}")])
            .fails(1, "svc.job_failed");
        assert_eq!(r.json()["job_result"], "failed");
        env.run("systemctl", &[&format!("svc://nosuch.{verb}")])
            .fails(1, "svc.not_found");
        env.run("systemctl", &[&format!("svc://denied.{verb}")])
            .fails(1, "svc.permission_denied");
        env.run("systemctl", &[&format!("svc://masked.{verb}")])
            .fails(1, "svc.masked");
    }
    let r = env.run("systemctl", &["svc://web.reload"]).ok();
    assert_eq!(r.out, "");
    env.run("systemctl", &["svc://bad.reload"])
        .fails(1, "svc.job_failed");

    // The deadline stops systemctl: exit 124, the job not cancelled.
    let t = Instant::now();
    let r = env
        .run("systemctl", &["svc://slow.start", "timeout_ms=500"])
        .fails(124, "svc.timeout");
    assert!(t.elapsed() < Duration::from_secs(10));
    assert_eq!(r.json()["job_canceled"], false);
    let log = env.log("systemctl");
    assert!(
        log.contains("--no-ask-password start -- web.service"),
        "{log}"
    );
    assert!(
        log.contains("--no-ask-password restart -- web.service"),
        "{log}"
    );
    assert!(
        log.contains("--no-ask-password reload -- web.service"),
        "{log}"
    );
}

#[test]
fn stop_on_systemd() {
    let env = Env::new();
    let v = env
        .run("systemctl", &["svc://web.stop", "timeout=4000"])
        .ok()
        .json();
    assert_eq!(v["requested"], true);
    assert_eq!(v["previous_state"], "active");
    assert_eq!(v["timeout_ms"], 4000);
    assert_eq!(v["job_result"], "done");
    env.run("systemctl", &["svc://web.stop", "force=yes"]).ok();
    assert!(
        env.log("systemctl")
            .contains("stop --job-mode=replace-irreversibly -- web.service")
    );
    let r = env
        .run("systemctl", &["svc://nosuch.stop"])
        .fails(1, "svc.not_found");
    assert_eq!(r.json()["requested"], false);
    assert!(!env.log("systemctl").contains("stop -- nosuch"));
}

#[test]
fn unit_file_verbs_on_systemd() {
    let env = Env::new();
    for verb in ["enable", "disable", "mask", "unmask"] {
        let r = env.run("systemctl", &[&format!("svc://web.{verb}")]).ok();
        assert_eq!(r.out, "");
        env.run("systemctl", &[&format!("svc://nosuch.{verb}")])
            .fails(1, "svc.not_found");
    }
    let log = env.log("systemctl");
    for l in [
        "enable -- web.service",
        "disable -- web.service",
        "mask -- web.service",
        "unmask -- web.service",
    ] {
        assert!(log.contains(l), "{l}\n{log}");
    }
    for verb in ["enable", "mask"] {
        let r = env
            .run("systemctl", &[&format!("svc://conflict.{verb}")])
            .fails(1, "svc.link_conflict");
        assert!(r.err.contains("force=true"), "{}", r.err);
        env.run(
            "systemctl",
            &[&format!("svc://conflict.{verb}"), "force=true"],
        )
        .ok();
        assert!(
            env.log("systemctl")
                .contains(&format!("{verb} --force -- conflict.service"))
        );
        env.run("openrc", &[&format!("svc://web.{verb}"), "force=true"])
            .fails(2, "svc.unsupported");
    }
    let r = env.run("systemctl", &["svc://noinst.enable"]).ok();
    assert!(
        r.err
            .contains("warning: noinst.service has no [Install] section"),
        "{}",
        r.err
    );
}

#[test]
fn wait_and_scale_on_systemd() {
    let env = Env::new();
    let v = env
        .run("systemctl", &["svc://web.wait", "state=running"])
        .ok()
        .json();
    assert_eq!(v["reached"], true);
    assert_eq!(v["timeout_ms"], 10000);
    let t = Instant::now();
    let r = env
        .run("systemctl", &["svc://down.wait", "timeout=400"])
        .fails(124, "svc.timeout");
    assert!(t.elapsed() >= Duration::from_millis(400));
    assert_eq!(r.json()["reached"], false);
    env.run("systemctl", &["svc://down.wait", "state=inactive"])
        .ok();
    env.run("systemctl", &["svc://nosuch.wait"])
        .fails(1, "svc.not_found");

    let v = env
        .run("systemctl", &["svc://w@.service.scale", "count=2"])
        .ok()
        .json();
    assert_eq!(v["template"], true);
    assert_eq!(v["instances_started"], serde_json::json!(["w@2.service"]));
    assert_eq!(v["instances_stopped"], serde_json::json!(["w@3.service"]));
    let v = env
        .run("systemctl", &["svc://down.scale", "count=1"])
        .ok()
        .json();
    assert_eq!(v["template"], false);
    assert_eq!(v["desired_count"], 1);
    env.run("systemctl", &["svc://nosuch.scale", "count=1"])
        .fails(1, "svc.not_found");
}

#[test]
fn logs_on_systemd() {
    let env = Env::new();
    let r = env
        .run(
            "systemctl",
            &[
                "svc://web.logs",
                "lines=2",
                "level=error",
                "since=-1h",
                "until=now",
                "reverse=true",
            ],
        )
        .ok();
    assert_eq!(r.out.lines().count(), 2, "{}", r.out);
    assert_eq!(
        env.log("journalctl").trim(),
        "--unit=web.service --lines=2 --no-pager --output=short-iso --since=-1h \
         --until=now --priority=err --reverse"
    );
    assert_eq!(env.run("systemctl", &["svc://empty.logs"]).ok().out, "");
    env.run("systemctl", &["svc://fail.logs"])
        .fails(1, "svc.logs_failed");
    env.run("systemctl", &["svc://denied.logs"])
        .fails(1, "svc.permission_denied");
    let t = Instant::now();
    env.run("systemctl", &["svc://slow.logs", "timeout_ms=300"])
        .fails(124, "svc.timeout");
    assert!(t.elapsed() < Duration::from_secs(10));

    // follow: lines stream; timeout_ms ends it normally and stops journalctl.
    let t = Instant::now();
    let r = env
        .run(
            "systemctl",
            &["svc://web.logs", "follow=true", "timeout_ms=1200"],
        )
        .ok();
    assert!(t.elapsed() >= Duration::from_millis(1200));
    assert!(t.elapsed() < Duration::from_secs(10));
    assert_eq!(r.out, "line 1\nline 2\n");
    assert!(env.log("journalctl").contains("--follow"));

    env.remove("journalctl");
    env.run("systemctl", &["svc://web.logs"])
        .fails(1, "svc.tool_not_found");
}

#[test]
fn missing_backends_and_tools() {
    let env = Env::new();
    for verb in VERBS {
        let stage = format!("svc://web.{verb}");
        let mut args = vec![stage.as_str()];
        if *verb == "scale" {
            args.push("count=1");
        }
        env.run("none", &args).fails(1, "svc.no_backend");
    }
    env.remove("systemctl");
    for verb in ["status", "start", "enable", "is-enabled"] {
        env.run("systemctl", &[&format!("svc://web.{verb}")])
            .fails(1, "svc.backend_unavailable");
    }
    env.remove("rc-service");
    env.run("openrc", &["svc://web.status"])
        .fails(1, "svc.tool_not_found");
}

// --- OpenRC -------------------------------------------------------------------------

#[test]
fn openrc_verbs() {
    let env = Env::new();
    let v = env.run("openrc", &["svc://web.status"]).ok().json();
    assert_eq!(v["backend"], "openrc");
    assert_eq!(v["state"], "running");
    assert_eq!(v["pid"], 77);
    assert_eq!(v["name"], "web");
    let v = env.run("openrc", &["svc://down.status"]).ok().json();
    assert_eq!(v["state"], "stopped_or_unknown");
    env.run("openrc", &["svc://nosuch.status"])
        .fails(1, "svc.not_found");

    let v = env.run("openrc", &["svc://down.start"]).ok().json();
    assert_eq!(
        (v["result"].clone(), v["state"].clone()),
        ("success".into(), "running".into())
    );
    env.run("openrc", &["svc://bad.start"])
        .fails(1, "svc.failed");
    env.run("openrc", &["svc://nosuch.restart"])
        .fails(1, "svc.not_found");
    env.run("openrc", &["svc://web.restart"]).ok();
    env.run("openrc", &["svc://slow.start", "timeout_ms=300"])
        .fails(124, "svc.timeout");

    let v = env.run("openrc", &["svc://down.stop"]).ok().json();
    assert_eq!(v["final_state"], "stopped_or_unknown");
    assert_eq!(v["previous_state"], "running");
    assert_eq!(v["reached_inactive"], true);
    env.run("openrc", &["svc://web.stop", "force=true"])
        .fails(2, "svc.unsupported");

    assert_eq!(env.run("openrc", &["svc://web.reload"]).ok().out, "");
    env.run("openrc", &["svc://bad.reload"])
        .fails(1, "svc.failed");

    env.run("openrc", &["svc://web.enable"]).ok();
    env.run("openrc", &["svc://web.disable"]).ok();
    env.run("openrc", &["svc://bad.enable"])
        .fails(1, "svc.failed");
    env.run("openrc", &["svc://nosuch.enable"])
        .fails(1, "svc.not_found");
    for verb in ["mask", "unmask"] {
        env.run("openrc", &[&format!("svc://web.{verb}")])
            .fails(2, "svc.unsupported");
    }
    let log = env.log("rc-update");
    assert!(
        log.contains("add web default") && log.contains("del web default"),
        "{log}"
    );

    assert_eq!(
        env.run("openrc", &["svc://web.is-enabled"]).ok().json()["enabled"],
        true
    );
    assert_eq!(
        env.run("openrc", &["svc://other.is-enabled"]).ok().json()["enabled"],
        false
    );
    env.run("openrc", &["svc://nosuch.is-enabled"])
        .fails(1, "svc.not_found");

    env.run("openrc", &["svc://web.wait", "state=running"]).ok();
    env.run("openrc", &["svc://other.wait", "timeout_ms=300"])
        .fails(124, "svc.timeout");
    env.run("openrc", &["svc://nosuch.wait"])
        .fails(1, "svc.not_found");

    let v = env
        .run("openrc", &["svc://web.scale", "count=0"])
        .ok()
        .json();
    assert_eq!(v["effective_count"], 0);
    env.run("openrc", &["svc://w@.service.scale", "count=1"])
        .fails(2, "svc.unsupported");
}

#[test]
fn openrc_logs() {
    let env = Env::new();
    assert_eq!(
        env.run("openrc", &["svc://web.logs", "lines=2"]).ok().out,
        "two\nthree\n"
    );
    assert_eq!(
        env.run("openrc", &["svc://web.logs", "reverse=true"])
            .ok()
            .out,
        "three\ntwo\none\n"
    );
    for opt in ["since=-1h", "until=now", "level=err"] {
        env.run("openrc", &["svc://web.logs", opt])
            .fails(2, "svc.unsupported");
    }
    let r = env
        .run("openrc", &["svc://other.logs"])
        .fails(1, "svc.no_logs");
    assert!(r.err.contains("/var/log/other.log"), "{}", r.err);
    let r = env
        .run(
            "openrc",
            &["svc://web.logs", "follow=true", "timeout_ms=700"],
        )
        .ok();
    assert_eq!(r.out, "one\ntwo\nthree\n");
}

// --- the real host, read-only -------------------------------------------------------

#[test]
fn host_status_of_a_missing_unit_is_not_found() {
    if !Path::new("/run/systemd/system").exists() {
        return;
    }
    // Reads only: LoadUnit/GetUnitFileState of a unit that does not exist.
    let out = Command::new(env!("CARGO_BIN_EXE_resh"))
        .arg("svc://resh-test-nonexistent-unit.status")
        .env_remove("RESH_TEST_SVC_BACKEND")
        .env_remove("RESH_TEST_SVC_TOOLS")
        .output()
        .unwrap();
    let r = Run {
        code: out.status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&out.stdout).into_owned(),
        err: String::from_utf8_lossy(&out.stderr).into_owned(),
    };
    let r = r.fails(1, "svc.not_found");
    assert_eq!(r.json()["backend"], "systemd");
}

#[test]
fn start_requires_a_running_unit_and_unit_types_are_checked() {
    let env = Env::new();
    let r = env
        .run("systemctl", &["svc://crash.start", "settle_ms=0"])
        .fails(1, "svc.not_active");
    let v = r.json();
    assert_eq!(v["active_state"], "failed");
    assert_eq!(v["unit_result"], "exit-code");
    let v = env
        .run("systemctl", &["svc://web.socket.start", "settle_ms=0"])
        .ok()
        .json();
    assert_eq!(v["name"], "web.socket");
    assert!(env.log("systemctl").contains("start -- web.socket"));
    let before = env.log("systemctl");
    for (stage, extra) in [
        ("svc://web.socket.reload", None),
        ("svc://web.timer.scale", Some("count=1")),
        ("svc://sda.device.start", None),
        ("svc://s1.scope.enable", None),
    ] {
        let mut a = vec![stage];
        a.extend(extra);
        env.run("systemctl", &a).fails(2, "svc.unsupported");
    }
    assert_eq!(env.log("systemctl"), before, "nothing ran");
}
