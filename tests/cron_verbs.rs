//! Integration tests for `cron://`: every verb run through the built `resh`
//! binary in a temporary directory, with HOME and PATH pointed inside it and
//! fake `crontab` and `systemctl` tools that keep their state in that
//! directory and record their argv. No crontab, cron file, unit file or
//! timer on this host is read or changed. Help output is checked against
//! golden files, and every help example runs.
//!
//! Real cron daemons and systemd are exercised in containers:
//! tests/cron_e2e_docker.rs.

mod common;

use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const VERBS: &[&str] = &["list", "add", "rm", "enable", "disable"];

/// The error codes documented in docs/Process_ServiceManagement/cron.md.
const ERROR_CODES: &[&str] = &[
    "cron.invalid_argument",
    "cron.timeout",
    "cron.failed",
    "cron.list_invalid_argument",
    "cron.list_error",
    "cron.add_invalid_argument",
    "cron.add_missing_schedule",
    "cron.add_missing_command",
    "cron.add_invalid_schedule",
    "cron.add_timezone_unsupported",
    "cron.add_backend_unavailable",
    "cron.add_systemd_unavailable",
    "cron.add_error",
    "cron.rm_invalid_argument",
    "cron.rm_invalid_backend",
    "cron.rm_no_selector",
    "cron.rm_no_match",
    "cron.rm_error",
    "cron.enable_invalid_argument",
    "cron.enable_invalid_backend",
    "cron.enable_no_selector",
    "cron.enable_no_match",
    "cron.enable_error",
    "cron.disable_invalid_argument",
    "cron.disable_invalid_backend",
    "cron.disable_no_selector",
    "cron.disable_no_match",
    "cron.disable_error",
];

/// Appends `CALL\0<program>\0<arg>\0...END\0` to $RESH_TEST_LOG.
const RECORD: &str = r#"{ printf 'CALL\0%s\0' "$(basename "$0")"; for a in "$@"; do printf '%s\0' "$a"; done; printf 'END\0'; } >> "$RESH_TEST_LOG""#;

/// `crontab [-u user] -l` prints $FAKE_CRONTAB_DIR/<user> (or "no crontab
/// for <user>", exit 1), `crontab [-u user] -` replaces it from stdin,
/// `crontab -V` prints $FAKE_CRONTAB_VERSION when set. With
/// $FAKE_CRONTAB_SLEEP set every call first sleeps that long.
const FAKE_CRONTAB: &str = r#"
[ -n "$FAKE_CRONTAB_SLEEP" ] && sleep "$FAKE_CRONTAB_SLEEP"
user=$USER
[ "$1" = "-u" ] && { user=$2; shift 2; }
case "$1" in
  -l) [ -f "$FAKE_CRONTAB_DIR/$user" ] || { echo "no crontab for $user" >&2; exit 1; }
      cat "$FAKE_CRONTAB_DIR/$user"; exit 0 ;;
  -) [ -n "$FAKE_CRONTAB_REFUSE" ] && { echo "crontab: errors in crontab file" >&2; exit 1; }
     cat > "$FAKE_CRONTAB_DIR/$user"; exit 0 ;;
  -V) [ -n "$FAKE_CRONTAB_VERSION" ] || { echo "crontab: invalid option -- 'V'" >&2; exit 1; }
      echo "$FAKE_CRONTAB_VERSION"; exit 0 ;;
esac
exit 1
"#;

/// A systemd that keeps enabled/active timers as files in $FAKE_SD and
/// finds installed timers in the user unit directory.
const FAKE_SYSTEMCTL: &str = r#"
[ "$1" = "--user" ] && shift
cmd=$1; shift
for last in "$@"; do :; done
S=$FAKE_SD
U=$HOME/.config/systemd/user
case "$cmd" in
  --version) echo "systemd 257"; exit 0 ;;
  show) [ -n "$FAKE_SD_DOWN" ] && { echo "Failed to connect to bus" >&2; exit 1; }
        echo Version=257; exit 0 ;;
  list-timers) for f in "$S"/active/*.timer; do [ -e "$f" ] || continue; n=$(basename "$f")
                 echo "n/a n/a n/a n/a $n ${n%.timer}.service"; done; exit 0 ;;
  list-unit-files) for f in "$U"/*.timer; do [ -e "$f" ] || continue; n=$(basename "$f")
                     st=disabled; [ -e "$S/enabled/$n" ] && st=enabled
                     echo "$n $st enabled"; done; exit 0 ;;
  is-enabled) [ -e "$S/enabled/$last" ]; exit $? ;;
  is-active) [ -e "$S/active/$last" ]; exit $? ;;
  enable) [ -e "$U/$last" ] || { echo "Unit $last not found" >&2; exit 1; }
          touch "$S/enabled/$last"
          case " $* " in *" --now "*) touch "$S/active/$last" ;; esac; exit 0 ;;
  disable) rm -f "$S/enabled/$last"; exit 0 ;;
  stop) rm -f "$S/active/$last"; exit 0 ;;
  start) touch "$S/active/$last"; exit 0 ;;
  daemon-reload) exit 0 ;;
esac
exit 1
"#;

struct Fixture {
    tmp: TempDir,
}

struct Run {
    code: i32,
    json: Value,
    stdout: String,
    stderr: String,
}

impl Run {
    #[track_caller]
    fn ok(&self) -> &Value {
        assert_eq!(self.code, 0, "{}\n{}", self.stdout, self.stderr);
        assert_eq!(self.json["ok"], true, "{}", self.stdout);
        assert_eq!(self.stderr, "", "a success writes nothing to stderr");
        &self.json
    }

    /// A failure with `exit` and `code`, in the JSON and on stderr.
    #[track_caller]
    fn fails(&self, exit: i32, code: &str) -> &Self {
        assert_eq!(self.code, exit, "{}\n{}", self.stdout, self.stderr);
        assert_eq!(self.json["ok"], false, "{}", self.stdout);
        assert_eq!(self.json["error"]["code"], code, "{}", self.stdout);
        assert!(self.json["error"]["message"].is_string());
        self.stderr_is(code)
    }

    #[track_caller]
    fn stderr_is(&self, code: &str) -> &Self {
        assert!(
            self.stderr.starts_with(&format!("Error: [{code}] ")),
            "{}",
            self.stderr
        );
        assert_eq!(self.stderr.lines().count(), 1, "{}", self.stderr);
        assert!(ERROR_CODES.contains(&code), "{code} is not documented");
        self
    }
}

impl Fixture {
    fn new() -> Self {
        let f = Fixture {
            tmp: TempDir::new().unwrap(),
        };
        for dir in ["bin", "crontabs", "sd/enabled", "sd/active"] {
            std::fs::create_dir_all(f.path().join(dir)).unwrap();
        }
        for (name, body) in [("crontab", FAKE_CRONTAB), ("systemctl", FAKE_SYSTEMCTL)] {
            common::write_executable(
                &f.path().join("bin").join(name),
                &format!("#!/bin/sh\n{RECORD}\n{body}"),
            );
        }
        f
    }

    fn path(&self) -> &Path {
        self.tmp.path()
    }

    fn crontab(&self, user: &str) -> PathBuf {
        self.path().join("crontabs").join(user)
    }

    fn unit_dir(&self) -> PathBuf {
        self.path().join(".config/systemd/user")
    }

    fn timer_state(&self, name: &str) -> (bool, bool) {
        (
            self.path().join("sd/enabled").join(name).exists(),
            self.path().join("sd/active").join(name).exists(),
        )
    }

    fn cmd(&self, env: &[(&str, &str)]) -> assert_cmd::Command {
        let dir = self.path();
        let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
        cmd.current_dir(dir)
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", dir.join("bin").display()),
            )
            .env("HOME", dir)
            .env("USER", "resh-test")
            .env("TZ", "UTC")
            .env("XDG_CONFIG_HOME", dir.join("config"))
            .env("XDG_DATA_HOME", dir.join("data"))
            .env("XDG_STATE_HOME", dir.join("state"))
            .env("XDG_CACHE_HOME", dir.join("cache"))
            .env("RESH_TEST_LOG", dir.join("calls.log"))
            .env("FAKE_CRONTAB_DIR", dir.join("crontabs"))
            .env("FAKE_SD", dir.join("sd"))
            .env_remove("FAKE_CRONTAB_VERSION")
            .env_remove("FAKE_CRONTAB_SLEEP")
            .env_remove("SSH_AUTH_SOCK");
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd
    }

    fn run_env(&self, env: &[(&str, &str)], args: &[&str]) -> Run {
        let out = self.cmd(env).args(args).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        Run {
            code: out.status.code().unwrap_or(-1),
            json: serde_json::from_str(&stdout).unwrap_or(Value::Null),
            stdout,
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    fn run(&self, args: &[&str]) -> Run {
        self.run_env(&[], args)
    }

    /// Every recorded invocation of `program` as argv (program first).
    fn calls_to(&self, program: &str) -> Vec<Vec<String>> {
        let Ok(raw) = std::fs::read(self.path().join("calls.log")) else {
            return vec![];
        };
        let mut calls = Vec::new();
        let mut cur: Option<Vec<String>> = None;
        for field in raw.split(|b| *b == 0).filter(|f| !f.is_empty()) {
            let s = String::from_utf8_lossy(field).into_owned();
            match (s.as_str(), cur.as_mut()) {
                ("CALL", _) => cur = Some(Vec::new()),
                ("END", Some(_)) => calls.push(cur.take().unwrap()),
                (_, Some(c)) => c.push(s),
                (_, None) => panic!("malformed invocation log"),
            }
        }
        calls.into_iter().filter(|c| c[0] == program).collect()
    }

    fn crontab_writes(&self) -> usize {
        self.calls_to("crontab")
            .iter()
            .filter(|c| c.last().map(String::as_str) == Some("-"))
            .count()
    }
}

// ===========================================================================
// Verbs
// ===========================================================================

#[test]
fn add_list_disable_enable_rm_round_trip_through_crontab() {
    let f = Fixture::new();
    // A user without a crontab: an empty one, not an error.
    let r = f.run(&["cron://local.list"]);
    assert_eq!(r.ok()["entries"], json!([]));
    assert_eq!(r.json["warnings"], json!([]));

    let r = f.run(&[
        "cron://local.add",
        "backend=cron",
        "schedule=30 3 * * 1-5",
        "command=/opt/rotate.sh >/dev/null 2>&1",
        "id=rotate",
        "description=log rotation",
        "now_unix=1768435200",
    ]);
    let job = &r.ok()["job"];
    assert_eq!(job["location"]["user"], "resh-test");
    // 2026-01-15 is a Thursday: the next weekday run is that morning.
    assert_eq!(job["next_run_iso8601"], "2026-01-15T03:30:00+00:00");
    let content =
        "# job-id=rotate description=log rotation\n30 3 * * 1-5 /opt/rotate.sh >/dev/null 2>&1\n";
    assert_eq!(
        std::fs::read_to_string(f.crontab("resh-test")).unwrap(),
        content
    );

    let r = f.run(&[
        "cron://local.list",
        "match_comment=rotate",
        "include_next_run=yes",
        "now_unix=1768435200",
    ]);
    let e = &r.ok()["entries"][1];
    assert_eq!(e["command"], "/opt/rotate.sh >/dev/null 2>&1");
    assert_eq!(e["comment"], "job-id=rotate description=log rotation");
    assert_eq!(e["next_run_iso8601"], "2026-01-15T03:30:00+00:00");

    let r = f.run(&[
        "cron://local.disable",
        "id=rotate",
        "backend=cron",
        "scope=current",
    ]);
    assert_eq!(r.ok()["disabled"]["cron"][0]["line_number"], 2);
    assert!(
        std::fs::read_to_string(f.crontab("resh-test"))
            .unwrap()
            .contains("\n# 30 3 * * 1-5 /opt/rotate.sh")
    );
    let r = f.run(&["cron://local.list", "state=disabled"]);
    assert_eq!(r.ok()["entries_disabled"], 1);

    f.run(&[
        "cron://local.enable",
        "id=rotate",
        "backend=cron",
        "scope=current",
    ])
    .ok();
    assert_eq!(
        std::fs::read_to_string(f.crontab("resh-test")).unwrap(),
        content
    );

    let r = f.run(&[
        "cron://local.rm",
        "id=rotate",
        "backend=cron",
        "scope=current",
        "dry_run",
    ]);
    assert_eq!(r.ok()["removed"]["cron"][0]["id"], "rotate");
    assert_eq!(
        std::fs::read_to_string(f.crontab("resh-test")).unwrap(),
        content
    );
    f.run(&[
        "cron://local.rm",
        "id=rotate",
        "backend=cron",
        "scope=current",
    ])
    .ok();
    assert_eq!(
        std::fs::read_to_string(f.crontab("resh-test")).unwrap(),
        "\n"
    );
    f.run(&[
        "cron://local.rm",
        "id=rotate",
        "backend=cron",
        "scope=current",
    ])
    .fails(1, "cron.rm_no_match");
    // The crontab went through `crontab -u resh-test -` (USER is not the
    // user running the test, so -u names it).
    let writes: Vec<_> = f
        .calls_to("crontab")
        .into_iter()
        .filter(|c| c.last().map(String::as_str) == Some("-"))
        .collect();
    assert_eq!(writes.len(), 4);
    assert_eq!(writes[0], ["crontab", "-u", "resh-test", "-"]);
}

#[test]
fn the_invoking_user_runs_crontab_without_u() {
    let f = Fixture::new();
    let me = String::from_utf8(
        std::process::Command::new("id")
            .arg("-un")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    let r = f.run_env(
        &[("USER", &me)],
        &[
            "cron://local.add",
            "backend=cron",
            "schedule=@daily",
            "command=/bin/true",
        ],
    );
    r.ok();
    assert_eq!(
        std::fs::read_to_string(f.crontab(&me)).unwrap(),
        "@daily /bin/true\n"
    );
    for call in f.calls_to("crontab") {
        assert!(!call.contains(&"-u".to_string()), "{call:?}");
    }
}

#[test]
fn crontab_failures_are_reported_and_nothing_is_replaced() {
    let f = Fixture::new();
    std::fs::write(f.crontab("resh-test"), "0 1 * * * /keep\n").unwrap();
    let r = f.run_env(
        &[("FAKE_CRONTAB_REFUSE", "1")],
        &[
            "cron://local.add",
            "backend=cron",
            "schedule=@daily",
            "command=/x",
        ],
    );
    r.fails(1, "cron.add_error");
    assert!(
        r.json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("errors in crontab file")
    );
    assert_eq!(
        std::fs::read_to_string(f.crontab("resh-test")).unwrap(),
        "0 1 * * * /keep\n"
    );
    let r = f.run_env(
        &[("FAKE_CRONTAB_REFUSE", "1")],
        &[
            "cron://local.disable",
            "command=/keep",
            "backend=cron",
            "scope=current",
        ],
    );
    r.fails(1, "cron.disable_error");
    assert_eq!(r.json["disabled"]["cron"], json!([]));
    // No crontab tool at all.
    std::fs::remove_file(f.path().join("bin/crontab")).unwrap();
    f.run(&[
        "cron://local.add",
        "backend=cron",
        "schedule=@daily",
        "command=/x",
    ])
    .fails(1, "cron.add_backend_unavailable");
    let r = f.run(&["cron://local.list"]);
    assert!(
        r.ok()["warnings"][0]
            .as_str()
            .unwrap()
            .contains("not found"),
        "{}",
        r.stdout
    );
    f.run(&["cron://local.rm", "id=x", "backend=cron", "scope=current"])
        .fails(1, "cron.rm_error");
}

#[test]
fn systemd_timers_are_added_listed_disabled_enabled_and_removed() {
    let f = Fixture::new();
    let r = f.run(&[
        "cron://local.add",
        "backend=systemd",
        "unit_scope=user",
        "schedule=*/15 9-17 * * mon-fri",
        "command=/opt/poll.sh",
        "id=poll",
    ]);
    assert_eq!(
        r.ok()["job"]["schedule"],
        "OnCalendar=Mon,Tue,Wed,Thu,Fri *-*-* 9,10,11,12,13,14,15,16,17:0,15,30,45"
    );
    let timer = std::fs::read_to_string(f.unit_dir().join("poll.timer")).unwrap();
    assert!(
        timer.contains("Description=Timer for cron job [id=poll]\n"),
        "{timer}"
    );
    assert_eq!(f.timer_state("poll.timer"), (true, true));

    let r = f.run(&["cron://local.disable", "id=poll", "backend=systemd"]);
    let d = &r.ok()["disabled"]["systemd"][0];
    assert_eq!(d["timer_unit"], "poll.timer");
    assert_eq!(d["stopped_now"], true);
    assert_eq!(f.timer_state("poll.timer"), (false, false));

    // Disabled and stopped: found through list-unit-files.
    let r = f.run(&[
        "cron://local.enable",
        "match_command=poll.sh",
        "backend=systemd",
    ]);
    assert_eq!(r.ok()["enabled"]["systemd"][0]["id"], "poll");
    assert_eq!(f.timer_state("poll.timer"), (true, true));

    let r = f.run(&["cron://local.rm", "unit_name=poll.timer", "backend=systemd"]);
    assert_eq!(
        r.ok()["removed"]["systemd"][0]["service_unit"],
        "poll.service"
    );
    assert!(!f.unit_dir().join("poll.timer").exists());
    assert!(!f.unit_dir().join("poll.service").exists());
    assert_eq!(f.timer_state("poll.timer"), (false, false));
    let calls: Vec<String> = f
        .calls_to("systemctl")
        .iter()
        .map(|c| c[1..].join(" "))
        .filter(|c| {
            ["enable", "disable", "stop", "daemon-reload"]
                .iter()
                .any(|v| c.split_whitespace().nth(1) == Some(v))
        })
        .collect();
    assert_eq!(
        calls,
        [
            "--user daemon-reload",
            "--user enable --now -- poll.timer",
            "--user stop -- poll.timer",
            "--user disable -- poll.timer",
            "--user enable --now -- poll.timer",
            "--user stop -- poll.timer",
            "--user disable -- poll.timer",
            "--user daemon-reload",
        ]
    );
    // The user manager does not answer.
    f.run_env(
        &[("FAKE_SD_DOWN", "1")],
        &[
            "cron://local.add",
            "backend=systemd",
            "schedule=@daily",
            "command=/x",
        ],
    )
    .fails(1, "cron.add_systemd_unavailable");
    let r = f.run_env(
        &[("FAKE_SD_DOWN", "1")],
        &[
            "cron://local.disable",
            "id=x",
            "scope=current",
            "require_match=false",
        ],
    );
    assert!(
        r.ok()["warnings"][0]
            .as_str()
            .unwrap()
            .contains("systemd timers were skipped")
    );
}

#[test]
fn usage_errors_exit_2_and_change_nothing() {
    let f = Fixture::new();
    for (args, code) in [
        (
            &["cron://local.list", "bogus=1"][..],
            "cron.list_invalid_argument",
        ),
        (
            &["cron://local.list", "include_raw=maybe"][..],
            "cron.list_invalid_argument",
        ),
        (
            &["cron://local.add", "command=/x"][..],
            "cron.add_missing_schedule",
        ),
        (
            &["cron://local.add", "schedule=@daily"][..],
            "cron.add_missing_command",
        ),
        (
            &["cron://local.add", "schedule=0 0 * * 8", "command=/x"][..],
            "cron.add_invalid_schedule",
        ),
        (
            &[
                "cron://local.add",
                "backend=cron",
                "schedule=@daily",
                "command=/x",
                "unit_scope=user",
            ][..],
            "cron.add_invalid_argument",
        ),
        (
            &[
                "cron://local.add",
                "schedule=@daily",
                "command=/x",
                "scope=user",
                "unit_name=x",
            ][..],
            "cron.add_invalid_argument",
        ),
        (
            &[
                "cron://local.add",
                "backend=cron",
                "schedule=@daily",
                "command=/x",
                "timezone=UTC",
            ][..],
            "cron.add_timezone_unsupported",
        ),
        (
            &["cron://local.rm", "backend=cron"][..],
            "cron.rm_no_selector",
        ),
        (
            &["cron://local.enable", "id=x", "backend=anacron"][..],
            "cron.enable_invalid_backend",
        ),
        (
            &["cron://local.disable", "id=x", "scope=user"][..],
            "cron.disable_invalid_argument",
        ),
        (
            &["cron://local.disable", "id=x", "stop_now=perhaps"][..],
            "cron.disable_invalid_argument",
        ),
        (
            &["cron://local.rm", "id=x", "timeout_ms=0"][..],
            "cron.rm_invalid_argument",
        ),
        (&["cron://local.lst"][..], "cron.invalid_argument"),
    ] {
        f.run(args).fails(2, code);
    }
    // Errors resh reports before the handle runs: no JSON, same line.
    let r = f.run(&["cron://local.rm", "id=x", "dry_run=perhaps"]);
    assert_eq!(r.code, 2);
    r.stderr_is("cron.invalid_argument");
    let r = f.run(&["cron://local.list", "dry_run"]);
    assert_eq!(r.code, 2);
    r.stderr_is("cron.invalid_argument");
    assert_eq!(f.crontab_writes(), 0);
    assert!(f.calls_to("systemctl").iter().all(|c| c[1] == "--version"));
}

#[test]
fn timeout_ms_stops_a_hung_tool() {
    let f = Fixture::new();
    for args in [
        &["cron://local.list", "timeout_ms=300"][..],
        &[
            "cron://local.add",
            "backend=cron",
            "schedule=@daily",
            "command=/x",
            "timeout_ms=300",
        ][..],
        &[
            "cron://local.rm",
            "id=x",
            "backend=cron",
            "scope=current",
            "timeout_ms=300",
        ][..],
        &[
            "cron://local.enable",
            "id=x",
            "backend=cron",
            "scope=current",
            "timeout_ms=300",
        ][..],
        &[
            "cron://local.disable",
            "id=x",
            "backend=cron",
            "scope=current",
            "timeout_ms=300",
        ][..],
    ] {
        let started = Instant::now();
        let r = f.run_env(&[("FAKE_CRONTAB_SLEEP", "20")], args);
        assert!(started.elapsed() < Duration::from_secs(10), "{args:?}");
        assert_eq!(r.code, 124, "{args:?}: {}\n{}", r.stdout, r.stderr);
        r.stderr_is("cron.timeout");
        assert!(r.stderr.contains("crontab"), "{}", r.stderr);
    }
    assert_eq!(f.crontab_writes(), 0);
}

#[test]
fn text_format_and_system_files_through_the_binary() {
    let f = Fixture::new();
    std::fs::write(
        f.crontab("resh-test"),
        "# nightly\n0 2 * * * /opt/backup.sh\n",
    )
    .unwrap();
    let r = f.run(&["cron://local.list", "format=text"]);
    assert_eq!(r.code, 0);
    assert!(r.stdout.starts_with("Cron Jobs\n"), "{}", r.stdout);
    assert!(r.stdout.contains("Comment  : nightly"), "{}", r.stdout);
    // A system cron file that is only read (dry run): the user crontab is
    // not touched because cron_file replaces scope.
    let before = f.calls_to("crontab").len();
    let r = f.run(&[
        "cron://local.disable",
        "backend=cron",
        "match_command=/opt/backup.sh",
        "cron_file=/etc/cron.d/resh_cron_verbs_probe",
        "require_match=false",
        "dry_run=true",
    ]);
    assert_eq!(r.ok()["matched_count"]["cron"], 0);
    assert_eq!(f.calls_to("crontab").len(), before);
}

// ===========================================================================
// Help
// ===========================================================================

fn golden(verb: &str) -> &'static str {
    match verb {
        "list" => include_str!("golden/cron_list_help.txt"),
        "add" => include_str!("golden/cron_add_help.txt"),
        "rm" => include_str!("golden/cron_rm_help.txt"),
        "enable" => include_str!("golden/cron_enable_help.txt"),
        "disable" => include_str!("golden/cron_disable_help.txt"),
        _ => unreachable!(),
    }
}

#[test]
fn handle_help_matches_golden_in_every_form() {
    let f = Fixture::new();
    let want = include_str!("golden/cron_help.txt");
    for args in [
        &["cron", "--help"][..],
        &["cron", "-h"][..],
        &["cron", "help"][..],
        &["help", "cron"][..],
        &["cron://--help"][..],
    ] {
        let r = f.run(args);
        assert_eq!(r.code, 0, "{args:?}: {}", r.stderr);
        assert_eq!(r.stdout, want, "{args:?}");
    }
    assert!(want.lines().all(|l| l.len() <= 80));
}

#[test]
fn verb_help_matches_golden_and_lists_every_option() {
    let f = Fixture::new();
    for verb in VERBS {
        for args in [
            vec!["cron", verb, "--help"],
            vec!["cron", verb, "-h"],
            vec!["help", "cron", verb],
        ] {
            let r = f.run(&args);
            assert_eq!(r.code, 0, "{args:?}");
            assert_eq!(r.stdout, golden(verb), "{args:?}: help differs from golden");
        }
        assert!(golden(verb).lines().all(|l| l.len() <= 80), "{verb}");
        assert!(golden(verb).contains("[timeout_ms=<ms>]"), "{verb}");
    }
    let r = f.run(&["cron", "lst", "--help"]);
    assert_eq!(r.code, 2);
    assert!(r.stderr.contains("list"), "{}", r.stderr);
}

/// Every help example runs against the fake tools and gives output of the
/// documented shape (the fixture's crontab holds a job the examples match).
#[test]
fn help_examples_run() {
    for verb in VERBS {
        let f = Fixture::new();
        let job = if *verb == "enable" {
            "# 0 2 * * *"
        } else {
            "0 2 * * *"
        };
        std::fs::write(
            f.crontab("resh-test"),
            format!("# job-id=backup\n{job} /opt/backup.sh\n"),
        )
        .unwrap();
        let example = golden(verb)
            .lines()
            .skip_while(|l| *l != "Example:")
            .nth(1)
            .unwrap()
            .trim();
        let words: Vec<&str> = example.split_whitespace().collect();
        assert_eq!(words[0], "resh");
        let r = f.run(&words[1..]);
        let json = r.ok();
        let sample: Value = {
            let text = golden(verb);
            let start = text.find("Example Output:").unwrap();
            let body: String = text[start..]
                .lines()
                .skip(1)
                .take_while(|l| !l.trim_start().starts_with("Shown"))
                .collect::<Vec<_>>()
                .join("\n");
            serde_json::from_str(&body).unwrap()
        };
        let mut keys: Vec<&String> = json.as_object().unwrap().keys().collect();
        let mut want: Vec<&String> = sample.as_object().unwrap().keys().collect();
        keys.sort();
        want.sort();
        // `add` reports next_run fields in job, not at the top.
        assert_eq!(keys, want, "{verb}: {}", r.stdout);
    }
}
