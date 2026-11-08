//! Unit and dispatch tests for `cron://`. Every verb runs through
//! `CronHandle::call` against `MockHost`, an in-memory host: no crontab,
//! cron file, unit file or systemctl on this machine is read or changed.

use super::*;
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};

// ===========================================================================
// The in-memory host
// ===========================================================================

#[derive(Debug, Clone, Default)]
struct Timer {
    enabled: bool,
    active: bool,
    /// Installed outside the unit directory (a distribution timer).
    vendor: bool,
}

#[derive(Debug, Default)]
struct State {
    /// user -> crontab content
    crontabs: HashMap<String, String>,
    /// path -> content (/etc/crontab, /etc/cron.d/<name>, unit files)
    files: HashMap<String, String>,
    /// Users and paths whose read fails.
    unreadable: HashSet<String>,
    /// Users and paths whose write fails.
    unwritable: HashSet<String>,
    /// Every crontab read stops at the deadline.
    reads_time_out: bool,
    /// What `crontab -V` prints (None: no -V, as on Debian).
    crontab_version: Option<String>,
    no_crontab: bool,
    no_systemctl: bool,
    /// systemctl exists but systemd is not the running init (a container).
    not_booted: bool,
    /// "user" / "system": that service manager does not answer.
    managers_down: HashSet<String>,
    /// (scope, timer name) -> state
    timers: BTreeMap<(String, String), Timer>,
    /// systemctl verbs that fail.
    failing: HashSet<String>,
    crontab_writes: usize,
    /// "<scope>: <args>" for every systemctl call.
    systemctl: Vec<String>,
    /// The host's local zone (None: UTC).
    local_zone: Option<RunZone>,
}

#[derive(Debug, Clone)]
struct MockHost(Arc<Mutex<State>>);

impl MockHost {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap()
    }
    /// systemctl calls that change something.
    fn changes(&self) -> Vec<String> {
        self.state()
            .systemctl
            .iter()
            .filter(|c| {
                ["enable", "disable", "stop", "start", "daemon-reload"]
                    .iter()
                    .any(|v| c.split_whitespace().nth(1) == Some(v))
            })
            .cloned()
            .collect()
    }
    fn add_timer(&self, scope: &str, name: &str, enabled: bool, active: bool, vendor: bool) {
        self.state().timers.insert(
            (scope.into(), name.into()),
            Timer {
                enabled,
                active,
                vendor,
            },
        );
    }
    fn timer(&self, scope: &str, name: &str) -> Option<Timer> {
        self.state()
            .timers
            .get(&(scope.to_string(), name.to_string()))
            .cloned()
    }
}

fn timed_out() -> anyhow::Error {
    anyhow::Error::new(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "deadline",
    ))
    .context("crontab was stopped at the deadline")
}

impl CronEditor for MockHost {
    fn read_user_crontab(&self, user: &str) -> Result<String> {
        let st = self.state();
        if st.reads_time_out {
            return Err(timed_out());
        }
        if st.unreadable.contains(user) {
            anyhow::bail!("crontab -l for {user} failed: permission denied");
        }
        Ok(st.crontabs.get(user).cloned().unwrap_or_default())
    }
    fn write_user_crontab(&self, user: &str, content: &str) -> Result<()> {
        let mut st = self.state();
        if st.unwritable.contains(user) {
            anyhow::bail!("crontab refused the new crontab for {user}: disk full");
        }
        st.crontab_writes += 1;
        st.crontabs.insert(user.into(), content.into());
        Ok(())
    }
    fn read_system_file(&self, path: &str) -> Result<Option<String>> {
        let st = self.state();
        if st.unreadable.contains(path) {
            anyhow::bail!("Failed to read {path}: Permission denied");
        }
        Ok(st.files.get(path).cloned())
    }
    fn write_system_file(&self, path: &str, content: &str) -> Result<()> {
        let mut st = self.state();
        if st.unwritable.contains(path) {
            anyhow::bail!("Failed to create temp file for {path}: Permission denied");
        }
        st.files.insert(path.into(), content.into());
        Ok(())
    }
}

fn unit_dir_of(user_mode: bool) -> &'static str {
    if user_mode {
        "/units/user"
    } else {
        "/units/system"
    }
}

impl SystemdEditor for MockHost {
    fn systemctl(&self, user_mode: bool, args: &[&str]) -> Result<ToolOutput> {
        let scope = if user_mode { "user" } else { "system" };
        let mut st = self.state();
        st.systemctl.push(format!("{scope}: {}", args.join(" ")));
        let ok = |stdout: String| ToolOutput {
            success: true,
            stdout,
            stderr: String::new(),
        };
        let fail = |stderr: &str| ToolOutput {
            success: false,
            stdout: String::new(),
            stderr: stderr.to_string(),
        };
        if st.managers_down.contains(scope) {
            return Ok(fail("Failed to connect to bus: No medium found"));
        }
        if st.failing.contains(args[0]) {
            return Ok(fail("boom"));
        }
        let name = args.last().copied().unwrap_or_default().to_string();
        let key = (scope.to_string(), name.clone());
        let dir = unit_dir_of(user_mode);
        Ok(match args[0] {
            "show" => ok("Version=257\n".into()),
            "list-timers" => ok(st
                .timers
                .iter()
                .filter(|((s, _), t)| s == scope && (t.enabled || t.active))
                .map(|((_, n), _)| {
                    format!(
                        "n/a n/a n/a n/a {n} {}.service\n",
                        n.trim_end_matches(".timer")
                    )
                })
                .collect()),
            "list-unit-files" => ok(st
                .timers
                .iter()
                .filter(|((s, _), _)| s == scope)
                .map(|((_, n), t)| {
                    format!(
                        "{n} {} enabled\n",
                        if t.enabled { "enabled" } else { "disabled" }
                    )
                })
                .collect()),
            "is-enabled" => match st.timers.get(&key) {
                Some(t) if t.enabled => ok("enabled\n".into()),
                _ => fail("disabled"),
            },
            "is-active" => match st.timers.get(&key) {
                Some(t) if t.active => ok("active\n".into()),
                _ => fail("inactive"),
            },
            "daemon-reload" => {
                let files: Vec<String> = st
                    .files
                    .keys()
                    .filter_map(|p| p.strip_prefix(&format!("{dir}/")))
                    .filter(|n| n.ends_with(".timer"))
                    .map(String::from)
                    .collect();
                for n in &files {
                    st.timers.entry((scope.into(), n.clone())).or_default();
                }
                st.timers
                    .retain(|(s, n), t| s != scope || t.vendor || files.contains(n));
                ok(String::new())
            }
            "enable" | "disable" | "start" | "stop" => match st.timers.get_mut(&key) {
                None => fail("Unit not found"),
                Some(t) => {
                    match args[0] {
                        "enable" => {
                            t.enabled = true;
                            t.active |= args.contains(&"--now");
                        }
                        "disable" => t.enabled = false,
                        "start" => t.active = true,
                        _ => t.active = false,
                    }
                    ok(String::new())
                }
            },
            other => panic!("unexpected systemctl {other}"),
        })
    }
    fn unit_dir(&self, user_mode: bool) -> Result<String> {
        Ok(unit_dir_of(user_mode).into())
    }
    fn read_unit_file(&self, path: &str) -> Result<Option<String>> {
        Ok(self.state().files.get(path).cloned())
    }
    fn write_unit_file(&self, path: &str, content: &str) -> Result<()> {
        let mut st = self.state();
        if st.unwritable.contains(path) {
            anyhow::bail!("could not write {path}");
        }
        st.files.insert(path.into(), content.into());
        Ok(())
    }
    fn remove_unit_file(&self, path: &str) -> Result<bool> {
        Ok(self.state().files.remove(path).is_some())
    }
    fn create_directory(&self, _: &str) -> Result<()> {
        Ok(())
    }
}

impl CronHost for MockHost {
    fn editor(&self) -> &dyn CronEditor {
        self
    }
    fn systemd(&self) -> &dyn SystemdEditor {
        self
    }
    fn list_user_crontab(&self, user: &str) -> Result<String> {
        CronEditor::read_user_crontab(self, user)
    }
    fn read_system_crontab(&self) -> Result<String> {
        self.read_file("/etc/crontab")
    }
    fn read_cron_d_files(&self) -> Result<Vec<(String, String)>> {
        let mut files: Vec<(String, String)> = self
            .state()
            .files
            .iter()
            .filter_map(|(p, c)| {
                p.strip_prefix("/etc/cron.d/")
                    .map(|n| (n.to_string(), c.clone()))
            })
            .collect();
        files.sort();
        Ok(files)
    }
    fn read_file(&self, path: &str) -> Result<String> {
        let st = self.state();
        if st.unreadable.contains(path) {
            anyhow::bail!("could not read {path}: Permission denied");
        }
        st.files
            .get(path)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("could not read {path}: No such file"))
    }
    fn systemd_booted(&self) -> bool {
        !self.state().not_booted
    }

    fn command_runs(&self, program: &str, _: &str) -> bool {
        let st = self.state();
        match program {
            "crontab" => !st.no_crontab,
            "systemctl" => !st.no_systemctl,
            _ => false,
        }
    }
    fn crontab_version(&self) -> Option<String> {
        self.state().crontab_version.clone()
    }
    fn now(&self) -> DateTime<Utc> {
        // 2026-01-15T00:00:00Z (a Thursday)
        Utc.with_ymd_and_hms(2026, 1, 15, 0, 0, 0).unwrap()
    }
    fn local_zone(&self) -> RunZone {
        self.state().local_zone.unwrap_or(RunZone::Named(Tz::UTC))
    }
}

const CRONIE: Option<&str> = Some("cronie 1.7.2");

fn setup_as(user: &str, version: Option<&str>) -> (CronHandle, MockHost) {
    let host = MockHost(Arc::new(Mutex::new(State {
        crontab_version: version.map(String::from),
        ..State::default()
    })));
    let provider = SystemCronProvider::with_host(user.into(), Box::new(host.clone()));
    (CronHandle::new(Box::new(provider)), host)
}

fn setup(version: Option<&str>) -> (CronHandle, MockHost) {
    setup_as("alice", version)
}

/// What a verb printed and returned.
#[derive(Debug)]
struct Out {
    code: i32,
    json: Value,
    stdout: String,
    reason: String,
}

impl Out {
    #[track_caller]
    fn ok(&self) -> &Value {
        assert_eq!(self.code, 0, "{}", self.stdout);
        assert_eq!(self.json["ok"], true, "{}", self.stdout);
        &self.json
    }
    #[track_caller]
    fn fails(&self, exit: i32, code: &str) -> &Self {
        assert_eq!(self.code, exit, "{}\n{}", self.stdout, self.reason);
        assert_eq!(self.json["ok"], false, "{}", self.stdout);
        assert_eq!(self.json["error"]["code"], code, "{}", self.stdout);
        assert!(
            self.reason.starts_with(&format!("[{code}] ")),
            "{}",
            self.reason
        );
        assert_eq!(
            exit_for(code),
            exit,
            "{code} is not in ERROR_CODES as {exit}"
        );
        self
    }
    #[track_caller]
    fn field(&self, field: &str) -> &Self {
        assert_eq!(self.json["error"]["field"], field, "{}", self.stdout);
        self
    }
    fn message(&self) -> String {
        self.json["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }
}

/// Runs `verb` like `resh cron://local.<verb> k=v ...`.
fn run(h: &CronHandle, verb: &str, args: &[(&str, &str)]) -> Out {
    let args: Args = args
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let mut i: &[u8] = &[];
    let (mut o, mut e) = (Vec::new(), Vec::new());
    let status = {
        let mut io = IoStreams {
            stdin: &mut i,
            stdout: &mut o,
            stderr: &mut e,
        };
        h.call(verb, &args, &mut io).unwrap()
    };
    assert!(e.is_empty(), "the handle wrote to stderr");
    let stdout = String::from_utf8(o).unwrap();
    Out {
        code: status.exit_code(),
        json: serde_json::from_str(&stdout).unwrap_or(Value::Null),
        stdout,
        reason: status.reason.unwrap_or_default(),
    }
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

// ===========================================================================
// Arguments, help and error codes
// ===========================================================================

/// The `key=` names in a help usage (`env_<KEY>` is `add`'s prefix form).
fn usage_keys(usage: &str) -> Vec<&str> {
    let mut keys: Vec<&str> = usage
        .split(|c: char| c == '[' || c.is_whitespace())
        .filter_map(|w| w.split_once('=').map(|(k, _)| k))
        .filter(|k| !k.is_empty() && !k.starts_with('<') && *k != "env_<KEY>")
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

#[test]
fn verb_args_match_help_usage() {
    for verb in CRON_HELP.verbs {
        let usage = verb.detail.as_ref().unwrap().usage;
        let mut parsed = verb_args(verb.name).unwrap().to_vec();
        parsed.sort();
        assert_eq!(
            usage_keys(usage),
            parsed,
            "usage of {} disagrees",
            verb.name
        );
    }
    assert!(
        CRON_HELP.verbs[1]
            .detail
            .as_ref()
            .unwrap()
            .usage
            .contains("[env_<KEY>=<value>]")
    );
    let mut helped: Vec<&str> = CRON_HELP.verbs.iter().map(|v| v.name).collect();
    let mut registered = VERBS.to_vec();
    helped.sort();
    registered.sort();
    assert_eq!(helped, registered);
}

#[test]
fn every_error_code_is_valid_documented_and_listed() {
    let doc = include_str!("../../../docs/Process_ServiceManagement/cron.md");
    for (code, exit) in ERROR_CODES {
        assert!(crate::core::status::is_valid_error_code(code), "{code}");
        assert!(doc.contains(&format!("`{code}`")), "{code} not in cron.md");
        assert!([1, 2, 124].contains(exit), "{code}");
    }
    // Every code literal in the source is in the table.
    let src = include_str!("cronh.rs");
    for (i, _) in src.match_indices("\"cron.") {
        let code: String = src[i + 1..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.')
            .collect();
        if code == "cron." {
            continue; // format!("cron.{verb}_..."), checked below
        }
        assert!(
            ERROR_CODES.iter().any(|(c, _)| *c == code),
            "{code} is emitted but not in ERROR_CODES"
        );
    }
    // And every verb-prefixed code (`cron.{verb}_...`).
    for verb in ["rm", "enable", "disable"] {
        for suffix in [
            "invalid_argument",
            "invalid_backend",
            "no_selector",
            "no_match",
            "error",
        ] {
            let code = format!("cron.{verb}_{suffix}");
            assert!(ERROR_CODES.iter().any(|(c, _)| *c == code), "{code}");
        }
    }
    for suffix in ["invalid_argument", "error"] {
        assert!(
            ERROR_CODES
                .iter()
                .any(|(c, _)| *c == format!("cron.list_{suffix}"))
        );
    }
}

fn minimal_args(verb: &str) -> Vec<(&'static str, &'static str)> {
    match verb {
        "add" => vec![
            ("schedule", "0 2 * * *"),
            ("command", "/bin/true"),
            ("backend", "cron"),
        ],
        "list" => vec![],
        _ => vec![("id", "job"), ("backend", "cron"), ("scope", "current")],
    }
}

#[test]
fn unknown_arguments_are_refused_before_anything_happens() {
    for verb in VERBS {
        let (h, host) = setup(CRONIE);
        let mut args = minimal_args(verb);
        args.push(("bogus", "1"));
        let o = run(&h, verb, &args);
        o.fails(2, &format!("cron.{verb}_invalid_argument"))
            .field("bogus");
        assert!(
            o.message().contains("unknown argument for"),
            "{}",
            o.message()
        );
        let st = host.state();
        assert!(st.crontab_writes == 0 && st.systemctl.is_empty() && st.files.is_empty());
    }
    // A typo gets a suggestion.
    let (h, _) = setup(CRONIE);
    let o = run(&h, "rm", &[("id", "x"), ("schedul", "0 2 * * *")]);
    o.fails(2, "cron.rm_invalid_argument");
    assert!(
        o.message().contains("did you mean `schedule`"),
        "{}",
        o.message()
    );
    let o = run(&h, "list", &[("max_entrys", "3")]);
    assert!(
        o.message().contains("did you mean `max_entries`"),
        "{}",
        o.message()
    );
    // dry_run on list is refused with its own message.
    let o = run(&h, "list", &[("dry_run", "false")]);
    o.fails(2, "cron.list_invalid_argument").field("dry_run");
    assert!(o.message().contains("does not support dry_run"));
    // env_<KEY> is add's alone.
    let o = run(&h, "rm", &[("id", "x"), ("env_A", "1")]);
    o.fails(2, "cron.rm_invalid_argument").field("env_A");
}

#[test]
fn unknown_verb_is_a_usage_error_with_a_suggestion() {
    let (h, _) = setup(CRONIE);
    let o = run(&h, "lsit", &[]);
    o.fails(2, "cron.invalid_argument");
    assert!(
        o.message().contains("did you mean `list`"),
        "{}",
        o.message()
    );
}

#[test]
fn timeout_ms_is_checked_on_every_verb() {
    for verb in VERBS {
        for bad in ["0", "-1", "soon", "86400001", " 5"] {
            let (h, host) = setup(CRONIE);
            let mut args = minimal_args(verb);
            args.push(("timeout_ms", bad));
            run(&h, verb, &args)
                .fails(2, &format!("cron.{verb}_invalid_argument"))
                .field("timeout_ms");
            assert_eq!(host.state().crontab_writes, 0);
        }
        let (h, _) = setup(CRONIE);
        let mut args = minimal_args(verb);
        args.push(("timeout_ms", "5000"));
        args.push(("require_match", "false"));
        if *verb == "list" || *verb == "add" {
            args.pop();
        }
        assert_eq!(run(&h, verb, &args).code, 0, "{verb}");
    }
}

#[test]
fn booleans_take_the_cli_spellings_and_nothing_else() {
    let flags: &[(&str, &[&str])] = &[
        (
            "list",
            &[
                "include_system",
                "include_next_run",
                "include_raw",
                "include_paths",
            ],
        ),
        ("add", &["include_next_run", "allow_duplicate", "dry_run"]),
        ("rm", &["require_match", "dry_run"]),
        ("enable", &["require_match", "dry_run"]),
        ("disable", &["require_match", "dry_run"]),
    ];
    for (verb, keys) in flags {
        for key in *keys {
            for good in ["true", "FALSE", "1", "0", "yes", "No", "on", "off"] {
                let (h, _) = setup(CRONIE);
                let mut args = minimal_args(verb);
                args.push((key, good));
                let o = run(&h, verb, &args);
                assert!(
                    o.code == 0 || o.json["error"]["code"] == format!("cron.{verb}_no_match"),
                    "{verb} {key}={good}: {}",
                    o.stdout
                );
            }
            let (h, host) = setup(CRONIE);
            let mut args = minimal_args(verb);
            args.push((key, "maybe"));
            run(&h, verb, &args)
                .fails(2, &format!("cron.{verb}_invalid_argument"))
                .field(key);
            assert_eq!(host.state().crontab_writes, 0);
        }
    }
    // The verb-specific timer flags: valid with backend=both or systemd.
    for (verb, key) in [
        ("rm", "remove_units"),
        ("enable", "start_now"),
        ("disable", "stop_now"),
    ] {
        let (h, _) = setup(CRONIE);
        let o = run(
            &h,
            verb,
            &[("unit_name", "x"), ("backend", "systemd"), (key, "maybe")],
        );
        o.fails(2, &format!("cron.{verb}_invalid_argument"))
            .field(key);
        let o = run(
            &h,
            verb,
            &[
                ("unit_name", "x"),
                ("backend", "systemd"),
                (key, "OFF"),
                ("require_match", "no"),
            ],
        );
        o.ok();
    }
    // add's systemd booleans.
    let (h, _) = setup(CRONIE);
    let o = run(
        &h,
        "add",
        &[
            ("schedule", "0 2 * * *"),
            ("command", "/bin/true"),
            ("backend", "systemd"),
            ("persistent", "no"),
            ("dry_run", "yes"),
        ],
    );
    assert!(
        !o.ok()["preview"]["timer_unit"]
            .as_str()
            .unwrap()
            .contains("Persistent")
    );
    run(
        &h,
        "add",
        &[
            ("schedule", "0 2 * * *"),
            ("command", "/bin/true"),
            ("backend", "systemd"),
            ("persistent", "sometimes"),
        ],
    )
    .fails(2, "cron.add_invalid_argument")
    .field("persistent");
}

#[test]
fn empty_values_and_control_characters_are_refused() {
    for verb in VERBS {
        let (h, _) = setup(CRONIE);
        let key = match *verb {
            "list" => "match_command",
            "add" => "description",
            _ => "match_command",
        };
        for bad in ["", "  ", "a\nb", "a\tb"] {
            let mut args = minimal_args(verb);
            args.push((key, bad));
            run(&h, verb, &args)
                .fails(2, &format!("cron.{verb}_invalid_argument"))
                .field(key);
        }
    }
}

#[test]
fn help_forms_render_the_metadata() {
    let (h, _) = setup(CRONIE);
    for (verb, args) in [
        ("--help", vec![]),
        ("-h", vec![]),
        ("help", vec![]),
        ("help", vec![("verb", "rm")]),
        ("--help=rm", vec![]),
        ("rm", vec![("help", "true")]),
    ] {
        let o = run(&h, verb, &args);
        assert_eq!(o.code, 0);
        assert!(o.stdout.starts_with("Handle: cron"), "{}", o.stdout);
        if !args.is_empty() || verb.contains('=') {
            assert!(o.stdout.contains("Verb: rm"), "{verb}: {}", o.stdout);
        }
    }
    let empty = Args::new();
    assert_eq!(help_request("list", &empty), None);
    assert_eq!(help_request("my-helper", &empty), None);
    let mut args = Args::new();
    args.insert("match_command".into(), "run -h now".into());
    assert_eq!(help_request("list", &args), None);
}

#[test]
fn verb_status_maps_codes_to_exit_statuses() {
    assert!(verb_status("Cron Jobs\n=====").ok);
    assert!(verb_status(r#"{"ok": true}"#).ok);
    let st = verb_status(
        r#"{"ok": false, "error": {"code": "cron.add_invalid_schedule", "message": "x"}}"#,
    );
    assert_eq!(st.exit_code(), 2);
    assert_eq!(st.reason.as_deref(), Some("[cron.add_invalid_schedule] x"));
    let st = verb_status(r#"{"ok": false, "error": {"code": "cron.rm_no_match", "message": "y"}}"#);
    assert_eq!(st.exit_code(), 1);
    let st = verb_status(r#"{"ok": false, "error": {"code": "cron.timeout", "message": "z"}}"#);
    assert_eq!(st.exit_code(), 124);
}

#[test]
fn a_tool_stopped_at_the_deadline_is_a_timeout() {
    for verb in VERBS {
        let (h, host) = setup(CRONIE);
        host.state().reads_time_out = true;
        let mut args = minimal_args(verb);
        if *verb == "list" {
            args.push(("scope", "current"));
        }
        let o = run(&h, verb, &args);
        o.fails(124, "cron.timeout");
        assert!(o.message().contains("deadline"), "{}", o.message());
        assert_eq!(host.state().crontab_writes, 0);
    }
    assert!(is_timeout(&timed_out()));
    assert!(!is_timeout(&anyhow::anyhow!("other")));
}

// ===========================================================================
// Crontab parsing
// ===========================================================================

// A crontab with everything a verb must leave alone.
const MIXED_CRONTAB: &str = "\
# m h  dom mon dow   command
SHELL=/bin/sh
MAILTO=ops@example.com

# Runs the nightly backup for all the web servers
0 2 * * * /usr/bin/backup --full
# 30 3 * * * /usr/bin/backup --incremental

#0 4 * * 1-5 /usr/bin/backup-check --quiet
# @daily /usr/bin/backup-rotate
# backup notes: 1 2 3 4 5 keep these
# 99x * * * * /usr/bin/backup --broken
# @someday /usr/bin/backup --never
# Run the job and log it
";

fn user_source() -> CronSource {
    CronSource::User("alice".into())
}

fn sel_match_command(text: &str) -> Selectors {
    Selectors {
        match_command: Some(text.into()),
        ..Selectors::default()
    }
}

/// Lines of `after` that differ from `before` (same line count).
fn changed_lines(before: &str, after: &str) -> Vec<(String, String)> {
    let (b, a): (Vec<_>, Vec<_>) = (before.lines().collect(), after.lines().collect());
    assert_eq!(b.len(), a.len(), "line count changed:\n{after}");
    b.iter()
        .zip(a.iter())
        .filter(|(x, y)| x != y)
        .map(|(x, y)| (x.to_string(), y.to_string()))
        .collect()
}

#[test]
fn line_classification() {
    let job = |l: &str, system: bool| match classify(l, system) {
        LineKind::Job(j) => Some(j),
        _ => None,
    };
    let j = job("0 2 * * * /opt/x --a  b # nightly", false).unwrap();
    assert_eq!(j.schedule, "0 2 * * *");
    assert_eq!(j.command, "/opt/x --a  b");
    assert_eq!(j.inline_comment.as_deref(), Some("nightly"));
    assert!(!j.disabled);
    let j = job("#  17 * * * *  root  run-parts /etc/cron.hourly", true).unwrap();
    assert!(j.disabled);
    assert_eq!(j.user.as_deref(), Some("root"));
    assert_eq!(j.command, "run-parts /etc/cron.hourly");
    assert_eq!(
        job("@reboot root /bin/x", true).unwrap().user.as_deref(),
        Some("root")
    );
    assert_eq!(
        job("@MIDNIGHT /bin/x", false).unwrap().schedule,
        "@MIDNIGHT"
    );
    for comment in [
        "# m h  dom mon dow   command",
        "# Runs the nightly backup for all the web servers",
        "# Run the job and log it",
        "# backup notes: 1 2 3 4 5 keep these",
        "# 99x * * * * /usr/bin/x",
        "# @someday /x",
        "#",
        "# 0 2 * * *",
    ] {
        assert_eq!(classify(comment, false), LineKind::Comment, "{comment}");
    }
    assert_eq!(classify("SHELL=/bin/sh", false), LineKind::Env);
    assert_eq!(classify("CRON_TZ = UTC", false), LineKind::Env);
    assert_eq!(classify("garbage here", false), LineKind::Other);
    assert_eq!(classify("0 2 * * * root", true), LineKind::Other);
    assert_eq!(classify("   ", false), LineKind::Blank);
}

#[test]
fn enable_never_uncomments_ordinary_comments() {
    let rw = rewrite_crontab(
        MIXED_CRONTAB,
        &user_source(),
        &sel_match_command("backup"),
        Action::Enable,
    );
    assert_eq!(
        changed_lines(MIXED_CRONTAB, &rw.content),
        vec![
            (
                "# 30 3 * * * /usr/bin/backup --incremental".into(),
                "30 3 * * * /usr/bin/backup --incremental".into()
            ),
            (
                "#0 4 * * 1-5 /usr/bin/backup-check --quiet".into(),
                "0 4 * * 1-5 /usr/bin/backup-check --quiet".into()
            ),
            (
                "# @daily /usr/bin/backup-rotate".into(),
                "@daily /usr/bin/backup-rotate".into()
            ),
        ]
    );
    assert_eq!(rw.hits.len(), 3);
    assert_eq!(rw.already, 1, "the enabled --full job");
    // A comment that merely mentions the words matches nothing.
    let rw = rewrite_crontab(
        MIXED_CRONTAB,
        &user_source(),
        &sel_match_command("web servers"),
        Action::Enable,
    );
    assert!(rw.hits.is_empty());
    assert_eq!(rw.content, MIXED_CRONTAB);
}

#[test]
fn disable_then_enable_round_trips_a_crontab() {
    let sel = sel_match_command("backup --full");
    let off = rewrite_crontab(MIXED_CRONTAB, &user_source(), &sel, Action::Disable);
    assert_eq!(off.hits.len(), 1);
    let on = rewrite_crontab(&off.content, &user_source(), &sel, Action::Enable);
    assert_eq!(on.hits.len(), 1);
    assert_eq!(on.content, MIXED_CRONTAB);
}

#[test]
fn every_selector_given_must_match() {
    let content = "# job-id=a description=nightly\n0 2 * * * /opt/backup.sh\n\
                   # job-id=b\n0 3 * * * /opt/backup.sh\n5 4 * * * /opt/other.sh # nightly\n";
    let hits = |sel: Selectors| {
        rewrite_crontab(content, &user_source(), &sel, Action::Disable)
            .hits
            .iter()
            .map(|h| h.line_number)
            .collect::<Vec<_>>()
    };
    assert_eq!(hits(sel_match_command("backup")), vec![2, 4]);
    assert_eq!(
        hits(Selectors {
            match_command: Some("backup".into()),
            match_comment: Some("NIGHTLY".into()),
            ..Selectors::default()
        }),
        vec![2]
    );
    assert_eq!(
        hits(Selectors {
            match_comment: Some("nightly".into()),
            ..Selectors::default()
        }),
        vec![2, 5],
        "the comment line above and the inline comment both count"
    );
    assert_eq!(
        hits(Selectors {
            schedule: Some("0 3 * * *".into()),
            ..Selectors::default()
        }),
        vec![4],
        "schedule alone is a selector"
    );
    assert_eq!(
        hits(Selectors {
            schedule: Some("0 3 * * *".into()),
            command: Some("/opt/other.sh".into()),
            ..Selectors::default()
        }),
        Vec::<u32>::new()
    );
    assert_eq!(
        hits(Selectors {
            id: Some("b".into()),
            command: Some("/opt/backup.sh".into()),
            ..Selectors::default()
        }),
        vec![4]
    );
    assert_eq!(
        hits(Selectors {
            id: Some("ackup".into()),
            ..Selectors::default()
        }),
        Vec::<u32>::new()
    );
    // A timer selector: no crontab line matches.
    assert_eq!(
        hits(Selectors {
            match_command: Some("backup".into()),
            unit_name: Some("x".into()),
            ..Selectors::default()
        }),
        Vec::<u32>::new()
    );
}

#[test]
fn system_files_have_a_user_column() {
    let content = "# job-id=nightly\n0 2 * * * www-data /opt/backup.sh\n";
    let src = CronSource::System("/etc/cron.d/jobs".into());
    let sel = Selectors {
        command: Some("/opt/backup.sh".into()),
        ..Selectors::default()
    };
    let rw = rewrite_crontab(content, &src, &sel, Action::Disable);
    assert_eq!(rw.hits.len(), 1);
    assert_eq!(rw.hits[0].user.as_deref(), Some("www-data"));
    assert_eq!(rw.hits[0].id.as_deref(), Some("nightly"));
    assert_eq!(
        rw.content,
        "# job-id=nightly\n# 0 2 * * * www-data /opt/backup.sh\n"
    );
}

#[test]
fn rm_removes_disabled_jobs_and_their_id_comment() {
    let content = "*/5 * * * * /usr/bin/other\n# job-id=backup\n# 0 2 * * * /opt/backup.sh\n";
    let sel = Selectors {
        id: Some("backup".into()),
        ..Selectors::default()
    };
    let rw = rewrite_crontab(content, &user_source(), &sel, Action::Remove);
    assert_eq!(rw.hits.len(), 1);
    assert_eq!(rw.hits[0].schedule, "0 2 * * *");
    assert_eq!(rw.hits[0].command, "/opt/backup.sh");
    assert_eq!(rw.content, "*/5 * * * * /usr/bin/other\n");
    // An empty job-id comment is no id (and does not panic).
    let content = "# job-id=\n0 2 * * * /opt/backup.sh\n# job-id=";
    let rw = rewrite_crontab(content, &user_source(), &sel, Action::Remove);
    assert!(rw.hits.is_empty());
}

#[test]
fn extract_job_id_handles_full_empty_and_missing_ids() {
    assert_eq!(
        extract_job_id("# job-id=backup description=x"),
        Some("backup".into())
    );
    assert_eq!(extract_job_id("# job-id=backup"), Some("backup".into()));
    assert_eq!(extract_job_id("# job-id="), None);
    assert_eq!(extract_job_id("# job-id= description=x"), None);
    assert_eq!(extract_job_id("# nothing here"), None);
}

#[test]
fn timer_unit_is_read_from_the_unit_column() {
    let lines = [
        "Sat 2026-10-17 00:00:00 UTC 5h 3min left Fri 2026-10-16 00:00:01 UTC 18h ago resh-backup.timer resh-backup.service",
        "n/a n/a n/a n/a logrotate.timer logrotate.service",
        "fstrim.timer disabled enabled",
    ];
    assert_eq!(timer_unit(lines[0]), Some("resh-backup.timer"));
    assert_eq!(timer_unit(lines[1]), Some("logrotate.timer"));
    assert_eq!(timer_unit(lines[2]), Some("fstrim.timer"));
    assert_eq!(timer_unit("NEXT LEFT LAST PASSED UNIT ACTIVATES"), None);
    assert_eq!(timer_unit("3 timers listed."), None);
}

#[test]
fn unit_files_give_ids_descriptions_and_commands() {
    assert_eq!(
        unit_job_id("[Unit]\nDescription=Timer for nightly valid=1 [id=backup]\n"),
        Some("backup".into())
    );
    assert_eq!(unit_job_id("Description=no id here\n"), None);
    assert_eq!(unit_job_id("Description=x [id=]\n"), None);
    assert_eq!(
        unit_value("A=1\nExecStart=/bin/x %%d\n", "ExecStart").as_deref(),
        Some("/bin/x %%d")
    );
    assert_eq!(unescape_unit("/bin/x %%d"), "/bin/x %d");
    assert_eq!(exec_start_for("a | b"), "/bin/sh -c 'a | b'");
    assert_eq!(exec_start_for("/bin/x"), "/bin/x");
    assert_eq!(derive_unit_name_from_command("/opt/my backup.sh --x"), "my");
    assert_eq!(derive_unit_name_from_command("/opt/run_me.sh"), "run-me");
    assert_eq!(derive_unit_name_from_command("!!!"), "cron-job");
}

// ===========================================================================
// Schedules
// ===========================================================================

fn at(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, mo, d, h, mi, 0).unwrap()
}

fn next_utc(schedule: &str, after: DateTime<Utc>) -> Option<String> {
    compute_next_run(schedule, after, RunZone::Named(Tz::UTC)).map(|(_, iso)| iso)
}

#[test]
fn schedules_are_parsed_as_cron_reads_them() {
    for ok in [
        "0 4 * * *",
        "*/5 9-17 * * mon-fri",
        "30 3 1,15 * *",
        "0 0 * * 0",
        "0 0 * * 7",
        "0 0 1 jan,JUL *",
        "0-59/15 */2 1-31/10 * *",
        "@daily",
        "@midnight",
        "@reboot",
    ] {
        assert!(parse_schedule(ok).is_ok(), "{ok}");
    }
    for bad in [
        "60 * * * *",
        "* 24 * * *",
        "* * 0 * *",
        "* * 32 * *",
        "* * * 13 *",
        "* * * * 8",
        "5-1 * * * *",
        "*/0 * * * *",
        "1,,2 * * * *",
        "* * * foo *",
        "* * * * fri-mon",
        "0 4 * *",
        "0 0 4 * * *",
        "@someday",
    ] {
        assert!(parse_schedule(bad).is_err(), "{bad}");
    }
    // `N/step` is read as `N-max/step`; add refuses it, as cronie and
    // Debian cron both do.
    let spec = parse_schedule("5/20 * * * *").unwrap().unwrap();
    assert_eq!(spec.minutes, (1 << 5) | (1 << 25) | (1 << 45));
    assert!(parse_schedule_with("5/20 * * * *", true).is_err());
    assert!(parse_schedule_with("5-59/20 * * * *", true).is_ok());
}

#[test]
fn weekdays_are_numbered_as_in_crontab() {
    // 2026-01-15 is a Thursday.
    let after = at(2026, 1, 15, 0, 0);
    for (sched, want) in [
        ("0 0 * * 0", "2026-01-18T00:00:00+00:00"),
        ("0 0 * * 7", "2026-01-18T00:00:00+00:00"),
        ("0 0 * * sun", "2026-01-18T00:00:00+00:00"),
        ("0 0 * * 1", "2026-01-19T00:00:00+00:00"),
        ("0 0 * * 5", "2026-01-16T00:00:00+00:00"),
        ("0 0 * * 1-5", "2026-01-16T00:00:00+00:00"),
        ("@weekly", "2026-01-18T00:00:00+00:00"),
        ("@daily", "2026-01-16T00:00:00+00:00"),
        ("@hourly", "2026-01-15T01:00:00+00:00"),
        ("@monthly", "2026-02-01T00:00:00+00:00"),
        ("@yearly", "2027-01-01T00:00:00+00:00"),
        ("* * * * *", "2026-01-15T00:01:00+00:00"),
    ] {
        assert_eq!(next_utc(sched, after).as_deref(), Some(want), "{sched}");
    }
    assert_eq!(next_utc("@reboot", after), None);
    assert_eq!(next_utc("0 0 30 2 *", after), None, "never runs");
    assert_eq!(
        next_utc("0 0 29 2 *", after).as_deref(),
        Some("2028-02-29T00:00:00+00:00")
    );
}

#[test]
fn day_of_month_and_weekday_follow_crons_or_rule() {
    let after = at(2026, 1, 15, 0, 0);
    // Either the 20th or a Friday (the 16th): cron's OR.
    assert_eq!(
        next_utc("0 0 20 * 5", after).as_deref(),
        Some("2026-01-16T00:00:00+00:00")
    );
    // A day field starting with * makes both required: odd days that are
    // Mondays (the 19th).
    assert_eq!(
        next_utc("0 0 */2 * 1", after).as_deref(),
        Some("2026-01-19T00:00:00+00:00")
    );
}

#[test]
fn next_run_never_panics_on_extreme_times_or_dst_edges() {
    let zones = [
        RunZone::Named(Tz::UTC),
        RunZone::Named(Tz::Asia__Tokyo),
        RunZone::Named(Tz::America__Los_Angeles),
        RunZone::Named(Tz::Europe__Berlin),
        RunZone::Offset(FixedOffset::east_opt(14 * 3600).unwrap()),
        RunZone::Offset(FixedOffset::west_opt(12 * 3600).unwrap()),
    ];
    let times = [
        DateTime::<Utc>::MAX_UTC,
        DateTime::<Utc>::MIN_UTC,
        Utc.timestamp_opt(0, 0).unwrap(),
        Utc.timestamp_opt(-1, 0).unwrap(),
        Utc.timestamp_opt(253_402_300_799, 0).unwrap(),
        at(2026, 3, 29, 0, 0),
        at(2026, 10, 25, 0, 0),
    ];
    for zone in zones {
        for t in times {
            for sched in [
                "30 2 * * *",
                "@hourly",
                "@yearly",
                "0 0 29 2 *",
                "@reboot",
                "0 0 13 * 5",
            ] {
                let _ = compute_next_run(sched, t, zone);
            }
        }
    }
    // 02:30 does not exist in Berlin on 2026-03-29: the next run is the
    // following day.
    let r = compute_next_run(
        "30 2 * * *",
        at(2026, 3, 29, 0, 0),
        RunZone::Named(Tz::Europe__Berlin),
    );
    assert_eq!(r.unwrap().1, "2026-03-30T02:30:00+02:00");
    // 02:30 happens twice on 2026-10-25: the first one.
    let r = compute_next_run(
        "30 2 * * *",
        at(2026, 10, 24, 22, 0),
        RunZone::Named(Tz::Europe__Berlin),
    );
    assert_eq!(r.unwrap().1, "2026-10-25T02:30:00+02:00");
}

#[test]
fn systemd_calendar_translations() {
    for (sched, want) in [
        ("0 2 * * *", "2:0"),
        ("* * * * *", "*:*"),
        ("*/15 * * * *", "*:0,15,30,45"),
        ("0 9-17 * * *", "9,10,11,12,13,14,15,16,17:0"),
        ("0 * * * *", "hourly"),
        ("0 0 * * *", "daily"),
        ("0 0 1 * *", "monthly"),
        ("0 0 1 1 *", "yearly"),
        ("0 0 * * 0", "Sun *-*-* 0:0"),
        ("30 6 * * mon-fri", "Mon,Tue,Wed,Thu,Fri *-*-* 6:30"),
        ("0 3 1,15 * *", "*-*-1,15 3:0"),
        ("0 3 * 1,7 *", "*-1,7-* 3:0"),
        (
            "0 0 */2 * 1",
            "Mon *-*-1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31 0:0",
        ),
        ("@weekly", "Sun *-*-* 0:0"),
        ("@daily", "daily"),
        ("@midnight", "daily"),
        ("@hourly", "hourly"),
        ("@monthly", "monthly"),
        ("@annually", "yearly"),
    ] {
        assert_eq!(
            convert_cron_to_oncalendar(sched),
            Ok(vec![want.to_string()]),
            "{sched}"
        );
    }
    assert!(convert_cron_to_oncalendar("@reboot").is_err());
    // Both day fields restricted: cron's OR becomes two expressions.
    assert_eq!(
        convert_cron_to_oncalendar("0 0 13 * 5"),
        Ok(s(&["*-*-13 0:0", "Fri *-*-* 0:0"]))
    );
    assert_eq!(
        convert_cron_to_oncalendar("30 6 1,15 1-6 mon,sat"),
        Ok(s(&[
            "*-1,2,3,4,5,6-1,15 6:30",
            "Mon,Sat *-1,2,3,4,5,6-* 6:30"
        ]))
    );
    let mut o = add_options("systemd");
    o.schedule = "0 0 13 * 5".into();
    o.timezone = Some("UTC".into());
    let t = systemd_trigger(&o).unwrap();
    assert_eq!(
        t.label(),
        "OnCalendar=*-*-13 0:0 UTC; OnCalendar=Fri *-*-* 0:0 UTC"
    );
    assert_eq!(
        t.unit_lines(),
        "OnCalendar=*-*-13 0:0 UTC\nOnCalendar=Fri *-*-* 0:0 UTC\n"
    );
    o.schedule = "@REBOOT".into();
    let t = systemd_trigger(&o).unwrap();
    assert_eq!(t, TimerTrigger::Boot);
    assert_eq!(
        (t.label().as_str(), t.unit_lines().as_str()),
        ("OnBootSec=0", "OnBootSec=0\n")
    );
}

// ===========================================================================
// list
// ===========================================================================

fn entries(out: &Out) -> Vec<Value> {
    out.ok()["entries"].as_array().unwrap().clone()
}

#[test]
fn list_reports_jobs_and_comment_lines_but_no_fake_jobs() {
    let (h, host) = setup(CRONIE);
    host.state()
        .crontabs
        .insert("alice".into(), format!("{MIXED_CRONTAB}garbage line\n"));
    let o = run(&h, "list", &[]);
    let e = entries(&o);
    let jobs: Vec<(&str, bool)> = e
        .iter()
        .filter(|x| x["comment_only"] == false)
        .map(|x| {
            (
                x["command"].as_str().unwrap(),
                x["enabled"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        jobs,
        vec![
            ("/usr/bin/backup --full", true),
            ("/usr/bin/backup --incremental", false),
            ("/usr/bin/backup-check --quiet", false),
            ("/usr/bin/backup-rotate", false),
        ]
    );
    let comments: Vec<&str> = e
        .iter()
        .filter(|x| x["comment_only"] == true)
        .map(|x| x["comment"].as_str().unwrap())
        .collect();
    assert_eq!(
        comments,
        vec![
            "m h  dom mon dow   command",
            "Runs the nightly backup for all the web servers",
            "backup notes: 1 2 3 4 5 keep these",
            "99x * * * * /usr/bin/backup --broken",
            "@someday /usr/bin/backup --never",
            "Run the job and log it",
        ]
    );
    let json = o.ok();
    assert_eq!(json["entries_total"], 10);
    assert_eq!(
        json["entries_disabled"], 3,
        "comment lines are not disabled jobs"
    );
    assert_eq!(
        json["human"]["summary"],
        "10 cron entries (1 enabled, 3 disabled, 6 comment lines) from scope 'current'."
    );
    // The @daily job keeps its keyword in `special`.
    let daily = e.iter().find(|x| x["special"] == "@daily").unwrap();
    assert!(daily.get("schedule").is_none());
    // The job below a comment line carries that comment.
    assert_eq!(
        e.iter()
            .find(|x| x["command"] == "/usr/bin/backup --full")
            .unwrap()["comment"],
        "Runs the nightly backup for all the web servers"
    );
    assert!(
        json["warnings"][0]
            .as_str()
            .unwrap()
            .contains("line 15 is not a cron entry"),
        "{json}"
    );

    // state filters leave comment lines out.
    let o = run(&h, "list", &[("state", "disabled")]);
    assert_eq!(entries(&o).len(), 3);
    let o = run(&h, "list", &[("state", "enabled")]);
    assert_eq!(entries(&o).len(), 1);
}

#[test]
fn list_filters_sort_and_truncate() {
    let (h, host) = setup(CRONIE);
    host.state().crontabs.insert(
        "alice".into(),
        "# job-id=maint description=weekly maintenance\n0 3 * * 0 /opt/maint.sh\n\
         5 1 * * * /opt/backup.sh\n10 1 * * * /opt/alpha.sh # quick\n"
            .into(),
    );
    let cmds = |args: &[(&str, &str)]| {
        let o = run(&h, "list", args);
        entries(&o)
            .iter()
            .filter(|x| x["comment_only"] == false)
            .map(|x| x["command"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    // match_comment finds a job by the id comment above it.
    assert_eq!(cmds(&[("match_comment", "maint")]), s(&["/opt/maint.sh"]));
    assert_eq!(cmds(&[("match_comment", "QUICK")]), s(&["/opt/alpha.sh"]));
    assert_eq!(cmds(&[("match_command", "BACKUP")]), s(&["/opt/backup.sh"]));
    assert_eq!(cmds(&[("match_user", "bob")]), Vec::<String>::new());
    assert_eq!(cmds(&[("match_source", "user")]).len(), 3);
    assert_eq!(
        cmds(&[("sort_by", "command"), ("state", "enabled")]),
        s(&["/opt/alpha.sh", "/opt/backup.sh", "/opt/maint.sh"])
    );
    assert_eq!(
        cmds(&[
            ("sort_by", "command"),
            ("sort_order", "desc"),
            ("state", "enabled")
        ]),
        s(&["/opt/maint.sh", "/opt/backup.sh", "/opt/alpha.sh"])
    );
    // sort_by=schedule uses next runs when they are computed.
    assert_eq!(
        cmds(&[
            ("sort_by", "schedule"),
            ("include_next_run", "true"),
            ("state", "enabled")
        ]),
        s(&["/opt/backup.sh", "/opt/alpha.sh", "/opt/maint.sh"])
    );
    let o = run(&h, "list", &[("max_entries", "2")]);
    let json = o.ok();
    assert_eq!(json["truncated"], true);
    assert_eq!(json["entries_returned"], 2);
    assert_eq!(json["entries_total"], 4);
    for bad in ["-1", "x", "4294967296"] {
        run(&h, "list", &[("max_entries", bad)])
            .fails(2, "cron.list_invalid_argument")
            .field("max_entries");
    }
}

#[test]
fn list_scopes_users_and_files() {
    let (h, host) = setup(CRONIE);
    {
        let mut st = host.state();
        st.crontabs.insert("alice".into(), "0 1 * * * /a\n".into());
        st.crontabs.insert("bob".into(), "0 2 * * * /b\n".into());
        st.files.insert(
            "/etc/crontab".into(),
            "SHELL=/bin/sh\n17 * * * * root run-parts /etc/cron.hourly\n".into(),
        );
        st.files.insert(
            "/etc/cron.d/backup".into(),
            "0 4 * * * www-data /c\n".into(),
        );
        st.files
            .insert("/srv/extra.cron".into(), "0 5 * * * nobody /d\n".into());
        st.unreadable.insert("carol".into());
    }
    let users_and_cmds = |args: &[(&str, &str)]| {
        let o = run(&h, "list", args);
        entries(&o)
            .iter()
            .map(|x| {
                format!(
                    "{}:{}:{}",
                    x["source"].as_str().unwrap(),
                    x["user"].as_str().unwrap(),
                    x["command"].as_str().unwrap()
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(users_and_cmds(&[]), s(&["user:alice:/a"]));
    assert_eq!(
        users_and_cmds(&[("scope", "user"), ("users", "bob")]),
        s(&["user:bob:/b"])
    );
    assert_eq!(
        users_and_cmds(&[("scope", "system")]),
        s(&["system:root:run-parts /etc/cron.hourly", "file:www-data:/c"])
    );
    assert_eq!(
        users_and_cmds(&[
            ("scope", "all"),
            ("users", "bob"),
            ("include_system", "true")
        ]),
        s(&[
            "user:alice:/a",
            "user:bob:/b",
            "system:root:run-parts /etc/cron.hourly",
            "file:www-data:/c"
        ])
    );
    assert_eq!(
        users_and_cmds(&[("include_files", "/srv/extra.cron")]),
        s(&["user:alice:/a", "file:nobody:/d"])
    );
    // An unreadable crontab is a warning, not a failure.
    let o = run(&h, "list", &[("scope", "user"), ("users", "bob,carol")]);
    assert!(o.ok()["warnings"][0].as_str().unwrap().contains("carol"));
    // include_raw and include_paths.
    let o = run(
        &h,
        "list",
        &[
            ("scope", "system"),
            ("include_raw", "yes"),
            ("include_paths", "1"),
        ],
    );
    let json = o.ok();
    assert_eq!(json["raw"]["/etc/cron.d/backup"], "0 4 * * * www-data /c\n");
    assert_eq!(json["paths"]["cron_d_backup"], "/etc/cron.d/backup");
    assert_eq!(json["paths"]["system_crontab"], "/etc/crontab");
    let o = run(&h, "list", &[]);
    assert!(o.ok().get("raw").is_none() && o.ok().get("paths").is_none());
    // Argument errors.
    run(&h, "list", &[("scope", "user")])
        .fails(2, "cron.list_invalid_argument")
        .field("users");
    run(&h, "list", &[("scope", "system"), ("users", "bob")])
        .fails(2, "cron.list_invalid_argument")
        .field("users");
    run(&h, "list", &[("scope", "user"), ("users", "bob,-r")])
        .fails(2, "cron.list_invalid_argument")
        .field("users");
    run(&h, "list", &[("scope", "user"), ("users", "bob,")])
        .fails(2, "cron.list_invalid_argument")
        .field("users");
    run(&h, "list", &[("include_files", "relative.cron")])
        .fails(2, "cron.list_invalid_argument")
        .field("include_files");
    for (k, v) in [
        ("scope", "everyone"),
        ("state", "sometimes"),
        ("sort_by", "time"),
        ("sort_order", "up"),
        ("format", "xml"),
        ("timezone", "Not/AZone"),
        ("now_unix", "-1"),
        ("now_unix", "253402300800"),
        ("now_unix", "tomorrow"),
    ] {
        run(&h, "list", &[(k, v)])
            .fails(2, "cron.list_invalid_argument")
            .field(k);
    }
}

#[test]
fn list_text_format() {
    let (h, host) = setup(CRONIE);
    host.state().crontabs.insert(
        "alice".into(),
        "# a note\n0 2 * * * /opt/backup.sh\n".into(),
    );
    let o = run(&h, "list", &[("format", "text"), ("max_entries", "1")]);
    assert_eq!(o.code, 0);
    assert!(o.stdout.starts_with("Cron Jobs\n"), "{}", o.stdout);
    assert!(
        o.stdout.contains("Returned   : 1 (0 enabled, 0 disabled)"),
        "{}",
        o.stdout
    );
    assert!(o.stdout.contains("(comment line)"), "{}", o.stdout);
    assert!(o.stdout.contains("truncated"), "{}", o.stdout);
}

// ---- list time zones (CRON_TZ, timezone=, now_unix) ------------------------

fn zoned_crontab() -> String {
    format!(
        "0 2 * * * /opt/plain.sh\n{TZ_BLOCK_MARKER}\nCRON_TZ=Asia/Tokyo\n# job-id=jp\n0 2 * * * /opt/jp.sh\n"
    )
}

fn list_jobs(out: &Out) -> Vec<(String, Option<String>, Option<String>)> {
    entries(out)
        .iter()
        .filter(|e| e["comment_only"] == false)
        .map(|e| {
            (
                e["command"].as_str().unwrap().to_string(),
                e["timezone"].as_str().map(String::from),
                e["next_run_iso8601"].as_str().map(String::from),
            )
        })
        .collect()
}

fn march_first_noon() -> String {
    at(2026, 3, 1, 12, 0).timestamp().to_string()
}

#[test]
fn list_computes_next_runs_in_the_right_zone() {
    let now = march_first_noon();
    let (h, host) = setup(CRONIE);
    host.state()
        .crontabs
        .insert("alice".into(), zoned_crontab());
    let o = run(
        &h,
        "list",
        &[("include_next_run", "true"), ("now_unix", &now)],
    );
    assert_eq!(
        list_jobs(&o),
        vec![
            (
                "/opt/plain.sh".into(),
                None,
                Some("2026-03-02T02:00:00+00:00".into())
            ),
            (
                "/opt/jp.sh".into(),
                Some("Asia/Tokyo".into()),
                Some("2026-03-02T02:00:00+09:00".into())
            ),
        ]
    );
    let o = run(
        &h,
        "list",
        &[
            ("include_next_run", "true"),
            ("now_unix", &now),
            ("timezone", "America/New_York"),
        ],
    );
    let jobs = list_jobs(&o);
    assert_eq!(jobs[0].2.as_deref(), Some("2026-03-02T02:00:00-05:00"));
    assert_eq!(jobs[1].2.as_deref(), Some("2026-03-02T02:00:00+09:00"));
    let o = run(&h, "list", &[("timezone", "America/New_York")]);
    let jobs = list_jobs(&o);
    assert_eq!(jobs[1].1.as_deref(), Some("Asia/Tokyo"));
    assert!(jobs.iter().all(|e| e.2.is_none()));
    // Disabled jobs and comment lines get no next run; @ keywords do.
    host.state().crontabs.insert(
        "alice".into(),
        "# 0 2 * * * /off\n@daily /kw\n@reboot /boot\n".into(),
    );
    let o = run(
        &h,
        "list",
        &[("include_next_run", "true"), ("now_unix", &now)],
    );
    assert_eq!(
        list_jobs(&o),
        vec![
            ("/off".into(), None, None),
            ("/kw".into(), None, Some("2026-03-02T00:00:00+00:00".into())),
            ("/boot".into(), None, None),
        ]
    );
}

#[test]
fn list_ignores_cron_tz_where_cron_is_not_cronie() {
    let now = march_first_noon();
    let (h, host) = setup(None);
    host.state()
        .crontabs
        .insert("alice".into(), zoned_crontab());
    let o = run(
        &h,
        "list",
        &[("include_next_run", "true"), ("now_unix", &now)],
    );
    assert_eq!(
        list_jobs(&o)[1].2.as_deref(),
        Some("2026-03-02T02:00:00+00:00")
    );
    assert!(
        o.ok()["warnings"][0]
            .as_str()
            .unwrap()
            .contains("CRON_TZ lines were ignored")
    );
}

#[test]
fn next_runs_default_to_the_hosts_local_zone() {
    let now = march_first_noon();
    let (h, host) = setup(CRONIE);
    host.state().local_zone = Some(RunZone::Named(Tz::America__New_York));
    host.state()
        .crontabs
        .insert("alice".into(), zoned_crontab());
    let o = run(
        &h,
        "list",
        &[("include_next_run", "true"), ("now_unix", &now)],
    );
    assert_eq!(o.ok()["next_run_timezone"], "America/New_York");
    let jobs = list_jobs(&o);
    assert_eq!(jobs[0].2.as_deref(), Some("2026-03-02T02:00:00-05:00"));
    assert_eq!(jobs[1].2.as_deref(), Some("2026-03-02T02:00:00+09:00"));
    assert_eq!(o.ok()["warnings"], json!([]));
    let o = run(
        &h,
        "list",
        &[
            ("include_next_run", "true"),
            ("now_unix", &now),
            ("timezone", "UTC"),
        ],
    );
    assert_eq!(o.ok()["next_run_timezone"], "UTC");
    let o = run(&h, "list", &[]);
    assert!(o.ok().get("next_run_timezone").is_none());
    for backend in ["cron", "systemd"] {
        let mut args = vec![
            ("schedule", "0 2 * * *"),
            ("command", "/bin/true"),
            ("backend", backend),
            ("now_unix", now.as_str()),
            ("dry_run", "true"),
        ];
        let o = run(&h, "add", &args);
        assert_eq!(o.ok()["job"]["next_run_timezone"], "America/New_York");
        assert_eq!(
            o.ok()["job"]["next_run_iso8601"],
            "2026-03-02T02:00:00-05:00"
        );
        args.push(("timezone", "Asia/Tokyo"));
        let o = run(&h, "add", &args);
        assert_eq!(o.ok()["job"]["next_run_timezone"], "Asia/Tokyo");
        assert_eq!(
            o.ok()["job"]["next_run_iso8601"],
            "2026-03-02T02:00:00+09:00"
        );
    }
}

#[test]
fn a_local_zone_known_only_by_offset_is_reported_as_such() {
    let now = march_first_noon();
    let (h, host) = setup(CRONIE);
    host.state().local_zone = Some(RunZone::Offset(FixedOffset::east_opt(3 * 3600).unwrap()));
    host.state()
        .crontabs
        .insert("alice".into(), "0 2 * * * /opt/plain.sh\n".into());
    let o = run(
        &h,
        "list",
        &[("include_next_run", "true"), ("now_unix", &now)],
    );
    assert_eq!(o.ok()["next_run_timezone"], "+03:00");
    assert_eq!(
        list_jobs(&o)[0].2.as_deref(),
        Some("2026-03-02T02:00:00+03:00")
    );
    assert!(
        o.ok()["warnings"][0]
            .as_str()
            .unwrap()
            .contains("could not be identified by name")
    );
    let add = |extra: &[(&str, &str)]| {
        let mut args = vec![
            ("schedule", "0 2 * * *"),
            ("command", "/bin/true"),
            ("backend", "cron"),
            ("now_unix", now.as_str()),
            ("dry_run", "true"),
        ];
        args.extend_from_slice(extra);
        run(&h, "add", &args).json
    };
    let out = add(&[]);
    assert_eq!(out["job"]["next_run_timezone"], "+03:00");
    assert!(out["warnings"][0].as_str().unwrap().contains("+03:00"));
    assert_eq!(add(&[("timezone", "UTC")])["warnings"], json!([]));
    assert_eq!(add(&[("include_next_run", "false")])["warnings"], json!([]));
}

// ===========================================================================
// add
// ===========================================================================

fn add_cron(h: &CronHandle, extra: &[(&str, &str)]) -> Out {
    let mut args = vec![("backend", "cron")];
    args.extend_from_slice(extra);
    run(h, "add", &args)
}

#[test]
fn add_writes_crontab_lines() {
    let (h, host) = setup(CRONIE);
    host.state()
        .crontabs
        .insert("alice".into(), "MAILTO=me\n".into());
    let o = add_cron(
        &h,
        &[
            ("schedule", "0 2 * * *"),
            ("command", "/opt/backup.sh >/dev/null 2>&1"),
            ("id", "backup"),
            ("description", "nightly backup"),
        ],
    );
    let job = &o.ok()["job"];
    assert_eq!(job["location"]["scope"], "current");
    assert_eq!(job["location"]["user"], "alice");
    assert_eq!(job["location"]["line_added"], 3);
    assert_eq!(o.json["backend_used"], "cron");
    assert_eq!(
        host.state().crontabs["alice"],
        "MAILTO=me\n# job-id=backup description=nightly backup\n0 2 * * * /opt/backup.sh >/dev/null 2>&1\n"
    );
    // scope=user writes the named user's crontab.
    let o = add_cron(
        &h,
        &[
            ("schedule", "@daily"),
            ("command", "/b"),
            ("scope", "user"),
            ("user", "bob"),
        ],
    );
    assert_eq!(o.ok()["job"]["location"]["user"], "bob");
    assert_eq!(host.state().crontabs["bob"], "@daily /b\n");
    // scope=system writes a cron file with a user column (root by default).
    let o = add_cron(
        &h,
        &[
            ("schedule", "0 4 * * *"),
            ("command", "/c"),
            ("scope", "system"),
            ("cron_file", "/etc/cron.d/resh_jobs"),
        ],
    );
    assert_eq!(o.ok()["job"]["location"]["file"], "/etc/cron.d/resh_jobs");
    assert_eq!(
        host.state().files["/etc/cron.d/resh_jobs"],
        "0 4 * * * root /c\n"
    );
    let o = add_cron(
        &h,
        &[
            ("schedule", "0 5 * * *"),
            ("command", "/d"),
            ("scope", "system"),
            ("user", "www-data"),
        ],
    );
    o.ok();
    assert_eq!(
        host.state().files["/etc/crontab"],
        "0 5 * * * www-data /d\n"
    );
    // @midnight is accepted.
    add_cron(&h, &[("schedule", "@midnight"), ("command", "/e")]).ok();
}

#[test]
fn add_dry_run_and_duplicates_write_nothing() {
    let (h, host) = setup(CRONIE);
    let o = add_cron(
        &h,
        &[
            ("schedule", "0 2 * * *"),
            ("command", "/opt/backup.sh"),
            ("dry_run", "true"),
        ],
    );
    assert_eq!(o.ok()["preview"]["cron_line"], "0 2 * * * /opt/backup.sh");
    assert_eq!(host.state().crontab_writes, 0);
    add_cron(
        &h,
        &[("schedule", "0 2 * * *"), ("command", "/opt/backup.sh")],
    )
    .ok();
    // Same schedule and command (spacing aside): a duplicate.
    let o = add_cron(
        &h,
        &[
            ("schedule", "0 2  * * *"),
            ("command", "/opt/backup.sh"),
            ("allow_duplicate", "false"),
        ],
    );
    assert_eq!(o.ok()["duplicate"], true);
    assert_eq!(host.state().crontab_writes, 1);
    // allow_duplicate defaults to true.
    add_cron(
        &h,
        &[("schedule", "0 2 * * *"), ("command", "/opt/backup.sh")],
    )
    .ok();
    assert_eq!(host.state().crontab_writes, 2);
    // A disabled copy is not a duplicate.
    host.state()
        .crontabs
        .insert("alice".into(), "# 0 2 * * * /x\n".into());
    let o = add_cron(
        &h,
        &[
            ("schedule", "0 2 * * *"),
            ("command", "/x"),
            ("allow_duplicate", "no"),
        ],
    );
    assert_eq!(o.ok()["duplicate"], false);
}

#[test]
fn add_argument_errors_change_nothing() {
    let (h, host) = setup(CRONIE);
    run(&h, "add", &[("command", "/x")])
        .fails(2, "cron.add_missing_schedule")
        .field("schedule");
    run(&h, "add", &[("schedule", "@daily")])
        .fails(2, "cron.add_missing_command")
        .field("command");
    run(&h, "add", &[("schedule", "@daily"), ("command", "  ")])
        .fails(2, "cron.add_missing_command");
    for bad in [
        "0 0 4 * * *",
        "0 4 * * * 2027",
        "0 4 * *",
        "60 4 * * *",
        "5-1 * * * *",
        "5/10 * * * *",
        "@someday",
        "",
    ] {
        add_cron(
            &h,
            &[("schedule", bad), ("command", "/x"), ("dry_run", "true")],
        )
        .fails(2, "cron.add_invalid_schedule");
    }
    let base = [("schedule", "0 2 * * *"), ("command", "/bin/true")];
    for (backend, field, value) in [
        ("cron", "scope", "everyone"),
        ("systemd", "unit_scope", "global"),
        ("cron", "unit_scope", "both"),
        ("auto", "backend", "anacron"),
        ("cron", "timezone", "Not/AZone"),
        ("systemd", "timezone", "europe/berlin"),
        ("cron", "now_unix", "-5"),
        ("cron", "now_unix", "1.5"),
        ("cron", "id", "job id"),
        ("cron", "format", "yaml"),
        ("cron", "description", "a\nb"),
        ("cron", "command", "date +%F"),
        ("cron", "user", "-u"),
        ("systemd", "unit_name", "../x"),
        ("systemd", "service_user", "root\nGroup=x"),
        ("systemd", "service_working_dir", "rel"),
        ("systemd", "accuracy_sec", "soon"),
        ("systemd", "env", "NOEQUALS"),
        ("systemd", "env", "A=1,,B=2"),
        ("systemd", "env_", "x"),
        ("systemd", "env_BAD-KEY", "x"),
        ("systemd", "command", "+/bin/true"),
    ] {
        let mut args = base.to_vec();
        if field != "backend" {
            args.push(("backend", backend));
        }
        if field == "command" {
            args.retain(|(k, _)| *k != "command");
        }
        if field == "user" {
            args.push(("scope", "user"));
        }
        args.push((field, value));
        let want_field = if field.starts_with("env") {
            "env"
        } else {
            field
        };
        run(&h, "add", &args)
            .fails(2, "cron.add_invalid_argument")
            .field(want_field);
    }
    let st = host.state();
    assert!(st.crontab_writes == 0 && st.files.is_empty());
    assert!(st.systemctl.is_empty(), "{:?}", st.systemctl);
}

#[test]
fn add_refuses_options_of_the_other_backend() {
    let (h, host) = setup(CRONIE);
    let base = [("schedule", "0 2 * * *"), ("command", "/bin/true")];
    for (backend, field, value) in [
        ("cron", "unit_name", "x"),
        ("cron", "unit_scope", "user"),
        ("cron", "persistent", "false"),
        ("cron", "accuracy_sec", "1min"),
        ("cron", "random_delay_sec", "5min"),
        ("cron", "service_user", "bob"),
        ("cron", "service_working_dir", "/srv"),
        ("cron", "env", "A=1"),
        ("cron", "env_A", "1"),
        ("cron", "user", "bob"),
        ("cron", "cron_file", "/etc/cron.d/x"),
        ("systemd", "scope", "system"),
        ("systemd", "user", "bob"),
        ("systemd", "cron_file", "/etc/crontab"),
    ] {
        let mut args = base.to_vec();
        args.push(("backend", backend));
        args.push((field, value));
        let want = if field.starts_with("env") {
            "env"
        } else {
            field
        };
        let o = run(&h, "add", &args);
        o.fails(2, "cron.add_invalid_argument").field(want);
        assert!(o.message().contains("applies"), "{}", o.message());
    }
    // backend=auto without backend-specific options: cron where systemctl
    // is missing.
    host.state().no_systemctl = true;
    let o = run(
        &h,
        "add",
        &[
            ("schedule", "0 2 * * *"),
            ("command", "/x"),
            ("dry_run", "1"),
        ],
    );
    assert_eq!(o.ok()["backend_used"], "cron");
    assert!(
        o.json["warnings"][0]
            .as_str()
            .unwrap()
            .contains("systemd not available")
    );
    let st = host.state();
    assert_eq!(st.crontab_writes, 0);
}

#[test]
fn auto_backend_needs_a_running_systemd_not_just_systemctl() {
    // A container with a systemctl binary but no systemd as init: auto must
    // use cron, and an explicit systemd backend is unavailable.
    let (h, host) = setup(CRONIE);
    host.state().not_booted = true;
    let o = run(
        &h,
        "add",
        &[
            ("schedule", "0 2 * * *"),
            ("command", "/x"),
            ("dry_run", "1"),
        ],
    );
    assert_eq!(o.ok()["backend_used"], "cron");
    run(
        &h,
        "add",
        &[
            ("schedule", "0 2 * * *"),
            ("command", "/x"),
            ("backend", "systemd"),
            ("dry_run", "1"),
        ],
    )
    .fails(1, "cron.add_backend_unavailable");
}

#[test]
fn add_reports_missing_backends_and_host_failures() {
    let (h, host) = setup(CRONIE);
    host.state().no_crontab = true;
    add_cron(&h, &[("schedule", "@daily"), ("command", "/x")])
        .fails(1, "cron.add_backend_unavailable");
    host.state().no_systemctl = true;
    run(&h, "add", &[("schedule", "@daily"), ("command", "/x")])
        .fails(1, "cron.add_backend_unavailable");
    run(
        &h,
        "add",
        &[
            ("schedule", "@daily"),
            ("command", "/x"),
            ("backend", "systemd"),
        ],
    )
    .fails(1, "cron.add_backend_unavailable");

    // A crontab that cannot be read is never replaced.
    let (h, host) = setup(CRONIE);
    host.state().unreadable.insert("alice".into());
    let o = add_cron(&h, &[("schedule", "@daily"), ("command", "/x")]);
    o.fails(1, "cron.add_error");
    assert!(o.message().contains("permission denied"), "{}", o.message());
    assert_eq!(host.state().crontab_writes, 0);
    // A crontab that cannot be written.
    let (h, host) = setup(CRONIE);
    host.state().unwritable.insert("alice".into());
    add_cron(&h, &[("schedule", "@daily"), ("command", "/x")]).fails(1, "cron.add_error");
    // A system file that cannot be read.
    host.state().unreadable.insert("/etc/crontab".into());
    add_cron(
        &h,
        &[
            ("schedule", "@daily"),
            ("command", "/x"),
            ("scope", "system"),
        ],
    )
    .fails(1, "cron.add_error");
}

#[test]
fn add_text_format() {
    let (h, _) = setup(CRONIE);
    let o = add_cron(
        &h,
        &[
            ("schedule", "0 2 * * *"),
            ("command", "/x"),
            ("id", "j"),
            ("format", "text"),
            ("dry_run", "on"),
        ],
    );
    assert_eq!(o.code, 0);
    assert!(
        o.stdout.starts_with("Cron Job Added Successfully"),
        "{}",
        o.stdout
    );
    assert!(o.stdout.contains("Job ID     : j"));
    assert!(o.stdout.contains("[DRY RUN]"));
    // A failure in text mode is still the JSON error object.
    let o = add_cron(
        &h,
        &[("schedule", "x"), ("command", "/x"), ("format", "text")],
    );
    o.fails(2, "cron.add_invalid_schedule");
}

// ---- add: time zones --------------------------------------------------------

fn zones_of_jobs(content: &str) -> Vec<(String, Option<String>)> {
    let lines: Vec<&str> = content.lines().collect();
    lines
        .iter()
        .enumerate()
        .filter(|(_, l)| matches!(classify(l, false), LineKind::Job(_)))
        .map(|(i, l)| (l.to_string(), effective_cron_tz(&lines, i)))
        .collect()
}

#[test]
fn add_cron_timezone_is_refused_unless_the_daemon_is_cronie() {
    for version in [None, Some("cron (Debian) 3.0pl1"), Some("busybox")] {
        for dry in ["true", "false"] {
            let (h, host) = setup(version);
            let o = add_cron(
                &h,
                &[
                    ("schedule", "0 2 * * *"),
                    ("command", "/opt/backup.sh"),
                    ("timezone", "Europe/Berlin"),
                    ("dry_run", dry),
                ],
            );
            o.fails(2, "cron.add_timezone_unsupported")
                .field("timezone");
            assert_eq!(host.state().crontab_writes, 0);
        }
    }
    let (h, host) = setup(None);
    add_cron(
        &h,
        &[("schedule", "0 2 * * *"), ("command", "/opt/backup.sh")],
    )
    .ok();
    assert_eq!(host.state().crontabs["alice"], "0 2 * * * /opt/backup.sh\n");
}

#[test]
fn add_cron_timezone_keeps_other_jobs_in_their_zones() {
    let (h, host) = setup(CRONIE);
    host.state().crontabs.insert(
        "alice".into(),
        "MAILTO=ops@example.com\n*/5 * * * * /usr/bin/poll\n".into(),
    );
    let o = add_cron(
        &h,
        &[
            ("schedule", "0 2 * * *"),
            ("command", "/opt/backup.sh"),
            ("id", "backup"),
            ("timezone", "Europe/Berlin"),
            ("dry_run", "true"),
        ],
    );
    assert_eq!(
        o.ok()["preview"]["cron_line"],
        format!(
            "{TZ_BLOCK_MARKER}\nCRON_TZ=Europe/Berlin\n# job-id=backup\n0 2 * * * /opt/backup.sh"
        )
    );
    assert_eq!(host.state().crontab_writes, 0);
    add_cron(
        &h,
        &[
            ("schedule", "0 2 * * *"),
            ("command", "/opt/backup.sh"),
            ("id", "backup"),
            ("timezone", "Europe/Berlin"),
        ],
    )
    .ok();
    add_cron(
        &h,
        &[("schedule", "15 * * * *"), ("command", "/opt/hourly.sh")],
    )
    .ok();
    let o = add_cron(
        &h,
        &[
            ("schedule", "30 6 * * *"),
            ("command", "/opt/report.sh"),
            ("timezone", "America/New_York"),
        ],
    );
    let content = host.state().crontabs["alice"].clone();
    assert_eq!(
        content,
        format!(
            "MAILTO=ops@example.com\n*/5 * * * * /usr/bin/poll\n15 * * * * /opt/hourly.sh\n\
             {TZ_BLOCK_MARKER}\nCRON_TZ=Europe/Berlin\n# job-id=backup\n0 2 * * * /opt/backup.sh\n\
             CRON_TZ=America/New_York\n30 6 * * * /opt/report.sh\n"
        )
    );
    assert_eq!(o.ok()["job"]["location"]["line_added"], 9);
    assert_eq!(
        zones_of_jobs(&content),
        vec![
            ("*/5 * * * * /usr/bin/poll".to_string(), None),
            ("15 * * * * /opt/hourly.sh".to_string(), None),
            (
                "0 2 * * * /opt/backup.sh".to_string(),
                Some("Europe/Berlin".to_string())
            ),
            (
                "30 6 * * * /opt/report.sh".to_string(),
                Some("America/New_York".to_string())
            ),
        ]
    );
    let dup = |tz: &str| {
        add_cron(
            &h,
            &[
                ("schedule", "0 2 * * *"),
                ("command", "/opt/backup.sh"),
                ("timezone", tz),
                ("allow_duplicate", "false"),
                ("dry_run", "true"),
            ],
        )
        .json["duplicate"]
            .clone()
    };
    assert_eq!(dup("Europe/Berlin"), true);
    assert_eq!(dup("Asia/Tokyo"), false);
}

#[test]
fn add_cron_timezone_in_a_system_file() {
    let (h, host) = setup(CRONIE);
    host.state().files.insert(
        "/etc/cron.d/resh_jobs".into(),
        "0 1 * * * root /bin/a\n".into(),
    );
    add_cron(
        &h,
        &[
            ("schedule", "0 2 * * *"),
            ("command", "/bin/b"),
            ("scope", "system"),
            ("cron_file", "/etc/cron.d/resh_jobs"),
            ("timezone", "UTC"),
        ],
    )
    .ok();
    assert_eq!(
        host.state().files["/etc/cron.d/resh_jobs"],
        format!("0 1 * * * root /bin/a\n{TZ_BLOCK_MARKER}\nCRON_TZ=UTC\n0 2 * * * root /bin/b\n")
    );
}

#[test]
fn add_next_run_uses_now_unix_and_timezone() {
    let now = march_first_noon();
    let next = |extra: &[(&str, &str)]| {
        let (h, _) = setup(CRONIE);
        let mut args = vec![
            ("schedule", "0 2 * * *"),
            ("command", "/bin/true"),
            ("dry_run", "true"),
        ];
        args.extend_from_slice(extra);
        let o = add_cron(&h, &args);
        (
            o.ok()["job"]["next_run_unix"].as_i64(),
            o.json["job"]["next_run_iso8601"].as_str().map(String::from),
        )
    };
    assert_eq!(
        next(&[("now_unix", &now)]),
        (
            Some(at(2026, 3, 2, 2, 0).timestamp()),
            Some("2026-03-02T02:00:00+00:00".into())
        )
    );
    assert_eq!(
        next(&[("now_unix", &now), ("timezone", "Europe/Berlin")]),
        (
            Some(at(2026, 3, 2, 1, 0).timestamp()),
            Some("2026-03-02T02:00:00+01:00".into())
        )
    );
    assert_eq!(next(&[]).0, Some(at(2026, 1, 15, 2, 0).timestamp()));
    assert_eq!(next(&[("include_next_run", "false")]), (None, None));
}

// ---- add: systemd --------------------------------------------------------------

fn add_systemd(h: &CronHandle, extra: &[(&str, &str)]) -> Out {
    let mut args = vec![("backend", "systemd")];
    args.extend_from_slice(extra);
    run(h, "add", &args)
}

#[test]
fn add_systemd_writes_units_and_enables_the_timer() {
    let (h, host) = setup(None);
    let o = add_systemd(
        &h,
        &[
            ("schedule", "30 6 * * mon-fri"),
            ("command", "/opt/report.sh --day %d"),
            ("id", "report"),
            ("description", "Daily report (100%)"),
            ("service_user", "reporter"),
            ("service_working_dir", "/srv/app"),
            ("env", "A=1,B=x y"),
            ("env_C", "say \"hi\""),
            ("accuracy_sec", "1min"),
            ("random_delay_sec", "5min"),
        ],
    );
    let job = &o.ok()["job"];
    assert_eq!(job["schedule"], "OnCalendar=Mon,Tue,Wed,Thu,Fri *-*-* 6:30");
    assert_eq!(job["location"]["scope"], "user-unit");
    assert_eq!(job["location"]["unit_dir"], "/units/user");
    assert_eq!(job["location"]["timer_unit"], "report.timer");
    let st = host.state();
    let service = &st.files["/units/user/report.service"];
    assert!(
        service.contains("Description=Daily report (100%%) [id=report]\n"),
        "{service}"
    );
    assert!(
        service.contains("ExecStart=/opt/report.sh --day %%d\n"),
        "{service}"
    );
    assert!(service.contains("User=reporter\n"));
    assert!(service.contains("WorkingDirectory=/srv/app\n"));
    assert!(
        service.contains(
            "Environment=\"A=1\"\nEnvironment=\"B=x y\"\nEnvironment=\"C=say \\\"hi\\\"\"\n"
        ),
        "{service}"
    );
    let timer = &st.files["/units/user/report.timer"];
    for line in [
        "OnCalendar=Mon,Tue,Wed,Thu,Fri *-*-* 6:30\n",
        "Persistent=true\n",
        "AccuracySec=1min\n",
        "RandomizedDelaySec=5min\n",
    ] {
        assert!(timer.contains(line), "{timer}");
    }
    assert_eq!(
        st.systemctl
            .iter()
            .filter(|c| !c.contains("show"))
            .cloned()
            .collect::<Vec<_>>(),
        s(&["user: daemon-reload", "user: enable --now -- report.timer"])
    );
    drop(st);
    assert_eq!(
        host.timer("user", "report.timer")
            .map(|t| (t.enabled, t.active)),
        Some((true, true))
    );
}

#[test]
fn add_systemd_scopes_timezones_and_duplicates() {
    // root: system units.
    let (h, host) = setup_as("root", None);
    let o = add_systemd(
        &h,
        &[
            ("schedule", "0 2 * * *"),
            ("command", "/opt/backup.sh"),
            ("timezone", "Europe/Berlin"),
        ],
    );
    assert_eq!(o.ok()["job"]["schedule"], "OnCalendar=2:0 Europe/Berlin");
    assert_eq!(o.json["job"]["location"]["unit_name"], "backup");
    assert!(
        host.state().files["/units/system/backup.timer"]
            .contains("\nOnCalendar=2:0 Europe/Berlin\n")
    );
    // An existing unit is a duplicate with allow_duplicate=false.
    let o = add_systemd(
        &h,
        &[
            ("schedule", "0 3 * * *"),
            ("command", "/opt/backup.sh"),
            ("allow_duplicate", "false"),
        ],
    );
    assert_eq!(o.ok()["duplicate"], true);
    // Dry run: preview only.
    let (h, host) = setup(None);
    let o = add_systemd(
        &h,
        &[
            ("schedule", "@weekly"),
            ("command", "/x | /y"),
            ("unit_name", "pipe"),
            ("persistent", "false"),
            ("dry_run", "true"),
        ],
    );
    let preview = &o.ok()["preview"];
    assert!(
        preview["timer_unit"]
            .as_str()
            .unwrap()
            .contains("OnCalendar=Sun *-*-* 0:0\n")
    );
    assert!(
        !preview["timer_unit"]
            .as_str()
            .unwrap()
            .contains("Persistent")
    );
    assert!(
        preview["service_unit"]
            .as_str()
            .unwrap()
            .contains("ExecStart=/bin/sh -c '/x | /y'\n")
    );
    assert!(host.state().files.is_empty());
    assert!(host.changes().is_empty());
}

#[test]
fn add_systemd_reboot_and_either_day_schedules() {
    let (h, host) = setup(None);
    // @reboot: OnBootSec=0, enabled for the next boot but not started (a
    // started boot timer would run the job at once).
    let o = add_systemd(
        &h,
        &[
            ("schedule", "@reboot"),
            ("command", "/opt/boot.sh"),
            ("unit_name", "boot"),
        ],
    );
    let job = &o.ok()["job"];
    assert_eq!(job["schedule"], "OnBootSec=0");
    assert!(job.get("next_run_unix").is_none());
    let timer = host.state().files["/units/user/boot.timer"].clone();
    assert!(timer.contains("[Timer]\nOnBootSec=0\n"), "{timer}");
    assert!(
        !timer.contains("OnCalendar") && !timer.contains("Persistent"),
        "{timer}"
    );
    assert_eq!(
        host.changes(),
        s(&["user: daemon-reload", "user: enable -- boot.timer"])
    );
    assert_eq!(
        host.timer("user", "boot.timer")
            .map(|t| (t.enabled, t.active)),
        Some((true, false))
    );
    // enable after a disable: again not started, with a warning.
    run(
        &h,
        "disable",
        &[("unit_name", "boot"), ("backend", "systemd")],
    )
    .ok();
    let o = run(
        &h,
        "enable",
        &[("unit_name", "boot"), ("backend", "systemd")],
    );
    assert_eq!(o.ok()["enabled"]["systemd"][0]["started_now"], false);
    assert!(
        o.json["warnings"][0]
            .as_str()
            .unwrap()
            .contains("next boot")
    );
    assert_eq!(host.changes().last().unwrap(), "user: enable -- boot.timer");
    let o = run(
        &h,
        "enable",
        &[("unit_name", "boot"), ("backend", "systemd")],
    );
    assert_eq!(o.ok()["already_enabled_count"]["systemd"], 1);

    // Both day fields restricted: two OnCalendar= lines (systemd ORs them).
    let o = add_systemd(
        &h,
        &[
            ("schedule", "0 0 13 * fri"),
            ("command", "/opt/f13.sh"),
            ("unit_name", "f13"),
            ("now_unix", "1768435200"),
        ],
    );
    let job = &o.ok()["job"];
    assert_eq!(
        job["schedule"],
        "OnCalendar=*-*-13 0:0; OnCalendar=Fri *-*-* 0:0"
    );
    // cron's OR: Friday 2026-01-16 comes before the 13th.
    assert_eq!(job["next_run_iso8601"], "2026-01-16T00:00:00+00:00");
    let timer = host.state().files["/units/user/f13.timer"].clone();
    assert!(
        timer.contains("OnCalendar=*-*-13 0:0\nOnCalendar=Fri *-*-* 0:0\nPersistent=true\n"),
        "{timer}"
    );
}

#[test]
fn backend_auto_is_chosen_by_the_options_given() {
    let (h, host) = setup(None);
    let base = [
        ("schedule", "0 2 * * *"),
        ("command", "/x"),
        ("dry_run", "true"),
    ];
    let with = |extra: &[(&str, &str)]| {
        let mut a = base.to_vec();
        a.extend_from_slice(extra);
        run(&h, "add", &a)
    };
    // Neither kind: systemd wherever systemctl runs.
    assert_eq!(with(&[]).ok()["backend_used"], "systemd");
    for (k, v) in [
        ("scope", "user"),
        ("user", "bob"),
        ("cron_file", "/etc/cron.d/x"),
    ] {
        let mut extra = vec![(k, v)];
        if k != "scope" {
            extra.push(("scope", if k == "user" { "user" } else { "system" }));
        }
        assert_eq!(with(&extra).ok()["backend_used"], "cron", "{k}");
    }
    for (k, v) in [
        ("unit_scope", "user"),
        ("unit_name", "j"),
        ("persistent", "false"),
        ("accuracy_sec", "1min"),
        ("service_user", "bob"),
        ("env_A", "1"),
    ] {
        assert_eq!(with(&[(k, v)]).ok()["backend_used"], "systemd", "{k}");
    }
    // Both kinds: refused, naming the conflict.
    let o = with(&[("scope", "user"), ("unit_scope", "user")]);
    o.fails(2, "cron.add_invalid_argument").field("scope");
    assert!(o.message().contains("unit_scope"), "{}", o.message());
    // An explicit backend keeps refusing the other backend's options.
    let mut a = base.to_vec();
    a.extend([("backend", "systemd"), ("scope", "user")]);
    run(&h, "add", &a)
        .fails(2, "cron.add_invalid_argument")
        .field("scope");
    // A chosen backend that is missing is unavailable, not swapped.
    host.state().no_crontab = true;
    with(&[("scope", "user")]).fails(1, "cron.add_backend_unavailable");
    host.state().no_crontab = false;
    host.state().no_systemctl = true;
    with(&[("unit_name", "j")]).fails(1, "cron.add_backend_unavailable");
    assert_eq!(host.state().crontab_writes, 0);
}

#[test]
fn add_systemd_refusals_and_failures() {
    let (h, host) = setup(None);
    // Persistent= has no meaning for a boot timer.
    add_systemd(
        &h,
        &[
            ("schedule", "@reboot"),
            ("command", "/x"),
            ("persistent", "true"),
        ],
    )
    .fails(2, "cron.add_invalid_argument")
    .field("persistent");
    assert!(host.state().files.is_empty());
    // The service manager does not answer: nothing is written.
    host.state().managers_down.insert("user".into());
    let o = add_systemd(&h, &[("schedule", "@daily"), ("command", "/x")]);
    o.fails(1, "cron.add_systemd_unavailable");
    assert!(host.state().files.is_empty());
    // enable fails after the units were written: reported.
    let (h, host) = setup(None);
    host.state().failing.insert("enable".into());
    let o = add_systemd(
        &h,
        &[
            ("schedule", "@daily"),
            ("command", "/x"),
            ("unit_name", "j"),
        ],
    );
    o.fails(1, "cron.add_error");
    assert!(
        o.message()
            .contains("were written, but the timer was not enabled"),
        "{}",
        o.message()
    );
    assert!(o.message().contains("boom"), "{}", o.message());
    assert!(host.state().files.contains_key("/units/user/j.timer"));
}

// ===========================================================================
// rm, enable, disable: crontabs
// ===========================================================================

#[test]
fn selector_and_target_argument_errors_change_nothing() {
    for verb in ["rm", "enable", "disable"] {
        let (h, host) = setup(CRONIE);
        host.state()
            .crontabs
            .insert("alice".into(), "# job-id=job\n0 2 * * * /x\n".into());
        run(&h, verb, &[("backend", "cron")]).fails(2, &format!("cron.{verb}_no_selector"));
        run(&h, verb, &[("id", "job"), ("backend", "cronie")])
            .fails(2, &format!("cron.{verb}_invalid_backend"))
            .field("backend");
        for (args, field) in [
            (vec![("cron_file", "/etc/shadow")], "cron_file"),
            (vec![("cron_file", "/etc/cron.d/x\ny")], "cron_file"),
            (vec![("scope", "everyone")], "scope"),
            (vec![("scope", "user")], "users"),
            (vec![("scope", "user"), ("users", " , ")], "users"),
            (vec![("scope", "user"), ("users", "bob,-r")], "users"),
            (vec![("scope", "current"), ("users", "bob")], "users"),
            (vec![("unit_scope", "global")], "unit_scope"),
            (vec![("id", "job id")], "id"),
            (vec![("schedule", "61 * * * *")], "schedule"),
            (vec![("schedule", "0 0 4 * * *")], "schedule"),
            (vec![("unit_name", "../x")], "unit_name"),
            (vec![("match_command", "")], "match_command"),
            (vec![("command", "a\nb")], "command"),
            (vec![("format", "yaml")], "format"),
        ] {
            let mut all = vec![("id", "job"), ("backend", "both"), ("dry_run", "true")];
            all.retain(|(k, _)| !args.iter().any(|(a, _)| a == k));
            all.extend(args.iter().copied());
            run(&h, verb, &all)
                .fails(2, &format!("cron.{verb}_invalid_argument"))
                .field(field);
        }
        let flag = match verb {
            "rm" => "remove_units",
            "enable" => "start_now",
            _ => "stop_now",
        };
        // Options of the backend that does not run.
        for (backend, key, value) in [
            ("cron", "unit_name", "x"),
            ("cron", "match_unit", "x"),
            ("cron", "unit_scope", "user"),
            ("cron", flag, "false"),
            ("systemd", "schedule", "0 2 * * *"),
            ("systemd", "scope", "current"),
            ("systemd", "users", "bob"),
            ("systemd", "cron_file", "/etc/crontab"),
        ] {
            let o = run(
                &h,
                verb,
                &[("id", "job"), ("backend", backend), (key, value)],
            );
            o.fails(2, &format!("cron.{verb}_invalid_argument"))
                .field(key);
            assert!(o.message().contains("applies to"), "{}", o.message());
        }
        let st = host.state();
        assert_eq!(st.crontab_writes, 0, "{verb}");
        assert!(st.systemctl.is_empty(), "{verb}: {:?}", st.systemctl);
    }
}

const SYSTEM_FILE: &str = "/etc/cron.d/resh_jobs";

fn with_job_in_file_and_crontab(disabled: bool) -> (CronHandle, MockHost) {
    let (h, host) = setup(CRONIE);
    let job = if disabled { "# 0 2 * * *" } else { "0 2 * * *" };
    host.state().files.insert(
        SYSTEM_FILE.into(),
        format!("# job-id=backup\n{job} root /opt/backup.sh\n"),
    );
    host.state().crontabs.insert(
        "alice".into(),
        format!("# job-id=backup\n{job} /opt/backup.sh\n"),
    );
    (h, host)
}

#[test]
fn rm_enable_disable_act_only_on_cron_file() {
    for verb in ["rm", "enable", "disable"] {
        let (h, host) = with_job_in_file_and_crontab(verb == "enable");
        let crontab_before = host.state().crontabs["alice"].clone();
        let o = run(
            &h,
            verb,
            &[
                ("id", "backup"),
                ("backend", "cron"),
                ("scope", "all"),
                ("cron_file", SYSTEM_FILE),
            ],
        );
        assert_eq!(
            o.ok()["cron_modified_sources"],
            json!([SYSTEM_FILE]),
            "{verb}"
        );
        let st = host.state();
        assert_eq!(st.crontabs["alice"], crontab_before, "{verb}");
        assert_eq!(st.crontab_writes, 0, "{verb}");
        let file = &st.files[SYSTEM_FILE];
        match verb {
            "rm" => assert_eq!(file, "\n"),
            "enable" => assert_eq!(file, "# job-id=backup\n0 2 * * * root /opt/backup.sh\n"),
            _ => assert_eq!(file, "# job-id=backup\n# 0 2 * * * root /opt/backup.sh\n"),
        }
    }
}

#[test]
fn rm_enable_disable_without_cron_file_use_scope() {
    for verb in ["rm", "enable", "disable"] {
        let (h, host) = with_job_in_file_and_crontab(verb == "enable");
        let file_before = host.state().files[SYSTEM_FILE].clone();
        let o = run(
            &h,
            verb,
            &[("id", "backup"), ("backend", "cron"), ("scope", "current")],
        );
        o.ok();
        let st = host.state();
        assert_eq!(st.files[SYSTEM_FILE], file_before, "{verb}");
        assert_eq!(st.crontab_writes, 1, "{verb}");
    }
    // scope=all reaches the user's crontab, /etc/crontab and /etc/cron.d.
    let (h, host) = with_job_in_file_and_crontab(false);
    let o = run(&h, "disable", &[("id", "backup"), ("backend", "cron")]);
    assert_eq!(
        o.ok()["cron_modified_sources"],
        json!([user_crontab_path("alice"), SYSTEM_FILE])
    );
    assert_eq!(o.json["disabled"]["cron"][1]["user"], "root");
    assert_eq!(host.state().crontab_writes, 1);
    // users= adds other users' crontabs to scope=all.
    let (h, host) = with_job_in_file_and_crontab(false);
    host.state()
        .crontabs
        .insert("bob".into(), "0 9 * * * /opt/backup.sh\n".into());
    let o = run(
        &h,
        "disable",
        &[
            ("command", "/opt/backup.sh"),
            ("backend", "cron"),
            ("users", "bob"),
        ],
    );
    assert_eq!(o.ok()["matched_count"]["cron"], 3);
}

#[test]
fn dry_run_reports_and_changes_nothing() {
    for verb in ["rm", "enable", "disable"] {
        let (h, host) = with_job_in_file_and_crontab(verb == "enable");
        let before = {
            let st = host.state();
            (st.crontabs.clone(), st.files.clone())
        };
        let o = run(
            &h,
            verb,
            &[("id", "backup"), ("backend", "cron"), ("dry_run", "true")],
        );
        let json = o.ok();
        assert_eq!(json["dry_run"], true);
        assert_eq!(json["matched_count"]["cron"], 2, "{verb}");
        let st = host.state();
        assert_eq!((st.crontabs.clone(), st.files.clone()), before, "{verb}");
        assert_eq!(st.crontab_writes, 0);
    }
}

#[test]
fn no_match_already_and_require_match() {
    let (h, host) = setup(CRONIE);
    host.state()
        .crontabs
        .insert("alice".into(), "0 2 * * * /a\n# 0 3 * * * /b\n".into());
    let args = |sel: &'static str| {
        vec![
            ("match_command", sel),
            ("backend", "cron"),
            ("scope", "current"),
        ]
    };
    for verb in ["rm", "enable", "disable"] {
        run(&h, verb, &args("/nothing")).fails(1, &format!("cron.{verb}_no_match"));
        let mut a = args("/nothing");
        a.push(("require_match", "false"));
        assert_eq!(run(&h, verb, &a).ok()["matched_count"]["cron"], 0);
    }
    // Already in the wanted state counts as a match, without a write.
    let o = run(&h, "enable", &args("/a"));
    assert_eq!(o.ok()["already_enabled_count"]["cron"], 1);
    assert_eq!(o.json["matched_count"]["cron"], 1);
    let o = run(&h, "disable", &args("/b"));
    assert_eq!(o.ok()["already_disabled_count"]["cron"], 1);
    assert_eq!(host.state().crontab_writes, 0);
    // Schedule alone selects for enable and disable.
    let o = run(
        &h,
        "disable",
        &[
            ("schedule", "0  2 * * *"),
            ("backend", "cron"),
            ("scope", "current"),
        ],
    );
    assert_eq!(o.ok()["disabled"]["cron"][0]["command"], "/a");
    assert_eq!(
        host.state().crontabs["alice"],
        "# 0 2 * * * /a\n# 0 3 * * * /b\n"
    );
}

#[test]
fn read_and_write_failures() {
    // A crontab named by scope=current or users= that cannot be read fails.
    for verb in ["rm", "enable", "disable"] {
        let (h, host) = with_job_in_file_and_crontab(verb == "enable");
        host.state().unreadable.insert("alice".into());
        let o = run(
            &h,
            verb,
            &[("id", "backup"), ("backend", "cron"), ("scope", "current")],
        );
        o.fails(1, &format!("cron.{verb}_error"));
        assert!(o.message().contains("could not read"), "{}", o.message());
        // With scope=all it is a warning and the other sources still count.
        let o = run(&h, verb, &[("id", "backup"), ("backend", "cron")]);
        let json = o.ok();
        assert!(
            json["warnings"][0]
                .as_str()
                .unwrap()
                .contains("Failed to read"),
            "{json}"
        );
        assert_eq!(json["cron_modified_sources"], json!([SYSTEM_FILE]));
    }
    // A write that fails: an error, and the job is not reported as changed.
    let (h, host) = with_job_in_file_and_crontab(false);
    host.state().unwritable.insert(SYSTEM_FILE.into());
    let o = run(&h, "disable", &[("id", "backup"), ("backend", "cron")]);
    o.fails(1, "cron.disable_error");
    assert!(
        o.message()
            .contains("could not update /etc/cron.d/resh_jobs"),
        "{}",
        o.message()
    );
    assert_eq!(
        o.json["disabled"]["cron"].as_array().unwrap().len(),
        1,
        "the crontab one"
    );
    assert_eq!(host.state().crontab_writes, 1);
    // A cron.d file with a name resh does not rewrite.
    let (h, host) = setup(CRONIE);
    host.state()
        .files
        .insert("/etc/cron.d/odd.name".into(), "0 2 * * * root /x\n".into());
    let o = run(
        &h,
        "disable",
        &[("command", "/x"), ("backend", "cron"), ("scope", "system")],
    );
    o.fails(1, "cron.disable_error");
    assert!(
        o.message().contains("cannot be rewritten"),
        "{}",
        o.message()
    );
    // A missing system file is no match, not an error.
    let (h, _) = setup(CRONIE);
    run(
        &h,
        "rm",
        &[
            ("id", "x"),
            ("backend", "cron"),
            ("cron_file", "/etc/cron.d/none"),
        ],
    )
    .fails(1, "cron.rm_no_match");
}

#[test]
fn rm_takes_a_jobs_cron_tz_line_with_it_and_nothing_else() {
    let (h, host) = setup(CRONIE);
    add_cron(&h, &[("schedule", "0 1 * * *"), ("command", "/bin/plain")]).ok();
    add_cron(
        &h,
        &[
            ("schedule", "0 2 * * *"),
            ("command", "/bin/de"),
            ("id", "de"),
            ("timezone", "Europe/Berlin"),
        ],
    )
    .ok();
    add_cron(
        &h,
        &[
            ("schedule", "0 3 * * *"),
            ("command", "/bin/jp"),
            ("id", "jp"),
            ("timezone", "Asia/Tokyo"),
        ],
    )
    .ok();
    let before = host.state().crontabs["alice"].clone();
    let rm = |id: &str, dry: &str| {
        run(
            &h,
            "rm",
            &[
                ("id", id),
                ("backend", "cron"),
                ("scope", "current"),
                ("dry_run", dry),
            ],
        )
    };
    let o = rm("de", "true");
    assert_eq!(o.ok()["removed"]["cron"][0]["timezone"], "Europe/Berlin");
    assert_eq!(host.state().crontabs["alice"], before);
    rm("de", "false").ok();
    assert_eq!(
        host.state().crontabs["alice"],
        format!(
            "0 1 * * * /bin/plain\n{TZ_BLOCK_MARKER}\nCRON_TZ=Asia/Tokyo\n# job-id=jp\n0 3 * * * /bin/jp\n"
        )
    );
    rm("jp", "false").ok();
    assert_eq!(host.state().crontabs["alice"], "0 1 * * * /bin/plain\n");
}

#[test]
fn rm_keeps_a_cron_tz_line_another_job_still_depends_on() {
    let (h, host) = setup(CRONIE);
    host.state().crontabs.insert(
        "alice".into(),
        format!("{TZ_BLOCK_MARKER}\nCRON_TZ=Europe/Berlin\n# job-id=de\n0 2 * * * /bin/de\n5 5 * * * /bin/by-hand\n"),
    );
    run(
        &h,
        "rm",
        &[("id", "de"), ("backend", "cron"), ("scope", "current")],
    )
    .ok();
    assert_eq!(
        zones_of_jobs(&host.state().crontabs["alice"]),
        vec![(
            "5 5 * * * /bin/by-hand".to_string(),
            Some("Europe/Berlin".to_string())
        )]
    );
}

#[test]
fn disable_and_enable_leave_cron_tz_lines_in_place() {
    let (h, host) = setup(CRONIE);
    let content = format!(
        "0 1 * * * /bin/plain\n{TZ_BLOCK_MARKER}\nCRON_TZ=Europe/Berlin\n# job-id=de\n0 2 * * * /bin/de\n"
    );
    host.state()
        .crontabs
        .insert("alice".into(), content.clone());
    let args = [("id", "de"), ("backend", "cron"), ("scope", "current")];
    let o = run(&h, "disable", &args);
    assert_eq!(o.ok()["disabled"]["cron"][0]["timezone"], "Europe/Berlin");
    assert!(
        host.state().crontabs["alice"]
            .contains("CRON_TZ=Europe/Berlin\n# job-id=de\n# 0 2 * * * /bin/de\n")
    );
    let o = run(&h, "enable", &args);
    assert_eq!(o.ok()["enabled"]["cron"][0]["timezone"], "Europe/Berlin");
    assert_eq!(host.state().crontabs["alice"], content);
}

#[test]
fn text_formats_of_the_changing_verbs() {
    for (verb, title) in [
        ("rm", "Remove Scheduled Jobs"),
        ("enable", "Enable Scheduled Jobs"),
        ("disable", "Disable Scheduled Jobs"),
    ] {
        let (h, _) = with_job_in_file_and_crontab(verb == "enable");
        let o = run(
            &h,
            verb,
            &[
                ("id", "backup"),
                ("backend", "cron"),
                ("format", "text"),
                ("dry_run", "true"),
            ],
        );
        assert_eq!(o.code, 0);
        assert!(o.stdout.starts_with(title), "{}", o.stdout);
        assert!(o.stdout.contains("# id=backup"), "{}", o.stdout);
        assert!(o.stdout.contains("dry-run mode"), "{}", o.stdout);
    }
}

// ===========================================================================
// rm, enable, disable: systemd timers
// ===========================================================================

/// A resh-made timer `<name>.timer` in the user unit directory.
fn resh_timer(host: &MockHost, name: &str, id: &str, command: &str, enabled: bool, active: bool) {
    host.state().files.insert(
        format!("/units/user/{name}.timer"),
        format!("[Unit]\nDescription=Timer for nightly [id={id}]\n\n[Timer]\nOnCalendar=daily\n"),
    );
    host.state().files.insert(
        format!("/units/user/{name}.service"),
        format!(
            "[Unit]\nDescription=nightly job [id={id}]\n\n[Service]\nType=oneshot\nExecStart={}\n",
            unit_literal(&exec_start_for(command))
        ),
    );
    host.add_timer("user", &format!("{name}.timer"), enabled, active, false);
}

#[test]
fn enable_finds_disabled_timers_that_are_no_longer_loaded() {
    let (h, host) = setup(CRONIE);
    resh_timer(&host, "backup", "b1", "/opt/backup.sh", false, false);
    let o = run(
        &h,
        "enable",
        &[("unit_name", "backup"), ("backend", "systemd")],
    );
    let e = &o.ok()["enabled"]["systemd"][0];
    assert_eq!(e["timer_unit"], "backup.timer");
    assert_eq!(e["service_unit"], "backup.service");
    assert_eq!(e["id"], "b1");
    assert_eq!(e["was_enabled"], false);
    assert_eq!(e["started_now"], true);
    assert_eq!(o.json["systemd_scopes_touched"], json!(["user"]));
    assert_eq!(host.changes(), s(&["user: enable --now -- backup.timer"]));
    // Now enabled and active: already enabled.
    let o = run(
        &h,
        "enable",
        &[("unit_name", "backup.timer"), ("backend", "systemd")],
    );
    assert_eq!(o.ok()["already_enabled_count"]["systemd"], 1);
    assert_eq!(host.changes().len(), 1);
}

#[test]
fn enable_and_disable_honor_start_now_and_stop_now() {
    let (h, host) = setup(CRONIE);
    resh_timer(&host, "a", "a", "/a", false, false);
    let o = run(
        &h,
        "enable",
        &[
            ("unit_name", "a"),
            ("backend", "systemd"),
            ("start_now", "false"),
        ],
    );
    assert_eq!(o.ok()["enabled"]["systemd"][0]["started_now"], false);
    assert_eq!(
        host.timer("user", "a.timer").map(|t| (t.enabled, t.active)),
        Some((true, false))
    );
    // Enabled but stopped: with start_now=false that is already enabled.
    let o = run(
        &h,
        "enable",
        &[
            ("unit_name", "a"),
            ("backend", "systemd"),
            ("start_now", "false"),
        ],
    );
    assert_eq!(o.ok()["already_enabled_count"]["systemd"], 1);
    // With start_now it is started.
    run(&h, "enable", &[("unit_name", "a"), ("backend", "systemd")]).ok();
    assert_eq!(
        host.timer("user", "a.timer").map(|t| (t.enabled, t.active)),
        Some((true, true))
    );
    // disable stop_now=false keeps it running.
    let o = run(
        &h,
        "disable",
        &[
            ("unit_name", "a"),
            ("backend", "systemd"),
            ("stop_now", "false"),
        ],
    );
    let d = &o.ok()["disabled"]["systemd"][0];
    assert_eq!(
        (d["was_enabled"].clone(), d["stopped_now"].clone()),
        (json!(true), json!(false))
    );
    assert_eq!(
        host.timer("user", "a.timer").map(|t| (t.enabled, t.active)),
        Some((false, true))
    );
    // ... and stop_now (default) stops it.
    let o = run(&h, "disable", &[("unit_name", "a"), ("backend", "systemd")]);
    assert_eq!(o.ok()["disabled"]["systemd"][0]["stopped_now"], true);
    assert_eq!(
        host.timer("user", "a.timer").map(|t| (t.enabled, t.active)),
        Some((false, false))
    );
    let o = run(&h, "disable", &[("unit_name", "a"), ("backend", "systemd")]);
    assert_eq!(o.ok()["already_disabled_count"]["systemd"], 1);
    assert_eq!(
        host.changes(),
        s(&[
            "user: enable -- a.timer",
            "user: enable --now -- a.timer",
            "user: disable -- a.timer",
            "user: stop -- a.timer",
        ])
    );
}

#[test]
fn rm_stops_disables_and_deletes_timers() {
    let (h, host) = setup(CRONIE);
    resh_timer(&host, "backup", "b1", "/opt/backup.sh", true, true);
    resh_timer(&host, "other", "o1", "/opt/other.sh", true, true);
    // Dry run first.
    let o = run(
        &h,
        "rm",
        &[("id", "b1"), ("backend", "systemd"), ("dry_run", "true")],
    );
    assert_eq!(
        o.ok()["removed"]["systemd"][0]["timer_unit"],
        "backup.timer"
    );
    assert!(host.changes().is_empty());
    let o = run(&h, "rm", &[("id", "b1"), ("backend", "systemd")]);
    assert_eq!(o.ok()["matched_count"]["systemd"], 1);
    assert_eq!(
        host.changes(),
        s(&[
            "user: stop -- backup.timer",
            "user: disable -- backup.timer",
            "user: daemon-reload"
        ])
    );
    let st = host.state();
    assert!(!st.files.contains_key("/units/user/backup.timer"));
    assert!(!st.files.contains_key("/units/user/backup.service"));
    assert!(st.files.contains_key("/units/user/other.timer"));
    drop(st);
    assert!(host.timer("user", "backup.timer").is_none());
    // remove_units=false keeps the files.
    let o = run(
        &h,
        "rm",
        &[
            ("unit_name", "other"),
            ("backend", "systemd"),
            ("remove_units", "false"),
        ],
    );
    o.ok();
    assert!(host.state().files.contains_key("/units/user/other.timer"));
    assert_eq!(
        host.timer("user", "other.timer")
            .map(|t| (t.enabled, t.active)),
        Some((false, false))
    );
}

#[test]
fn timers_match_by_command_comment_and_unit() {
    let (h, host) = setup(CRONIE);
    resh_timer(
        &host,
        "backup",
        "b1",
        "/opt/backup.sh --at 5%",
        false,
        false,
    );
    resh_timer(&host, "pipe", "p1", "/x | /y", false, false);
    host.add_timer("user", "fstrim.timer", false, false, true);
    let timers = |args: &[(&str, &str)]| {
        let mut a = vec![
            ("backend", "systemd"),
            ("dry_run", "true"),
            ("require_match", "false"),
        ];
        a.extend_from_slice(args);
        run(&h, "enable", &a).ok()["enabled"]["systemd"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["timer_unit"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        timers(&[("command", "/opt/backup.sh --at 5%")]),
        s(&["backup.timer"])
    );
    assert_eq!(timers(&[("command", "/x | /y")]), s(&["pipe.timer"]));
    assert_eq!(timers(&[("match_command", "AT 5%")]), s(&["backup.timer"]));
    assert_eq!(
        timers(&[("match_comment", "nightly")]),
        s(&["backup.timer", "pipe.timer"])
    );
    assert_eq!(timers(&[("match_unit", "TRIM")]), s(&["fstrim.timer"]));
    assert_eq!(
        timers(&[("match_unit", "p"), ("id", "p1")]),
        s(&["pipe.timer"])
    );
    assert_eq!(
        timers(&[("match_unit", "fstrim"), ("id", "x")]),
        Vec::<String>::new()
    );
    assert!(host.changes().is_empty());
}

#[test]
fn both_backends_and_unit_scopes() {
    let (h, host) = setup_as("root", CRONIE);
    host.state().crontabs.insert(
        "root".into(),
        "# job-id=nightly\n0 2 * * * /opt/n.sh\n".into(),
    );
    resh_timer(&host, "nightly", "nightly", "/opt/n.sh", true, true);
    host.add_timer("system", "nightly.timer", true, true, true);
    // root, unit_scope=auto: system timers only.
    let o = run(
        &h,
        "disable",
        &[("id", "nightly"), ("scope", "current"), ("dry_run", "1")],
    );
    let json = o.ok();
    assert_eq!(
        json["matched_count"],
        json!({"cron": 1, "systemd": 0}),
        "vendor timers have no id"
    );
    let o = run(
        &h,
        "disable",
        &[
            ("match_command", "/opt/n"),
            ("scope", "current"),
            ("unit_scope", "both"),
            ("dry_run", "1"),
        ],
    );
    assert_eq!(o.ok()["matched_count"], json!({"cron": 1, "systemd": 1}));
    assert_eq!(o.json["systemd_scopes_touched"], json!(["user"]));
    // A service manager that does not answer: a warning with backend=both,
    // a failure with backend=systemd.
    host.state().managers_down.insert("system".into());
    let o = run(&h, "disable", &[("id", "nightly"), ("scope", "current")]);
    assert!(
        o.ok()["warnings"][0]
            .as_str()
            .unwrap()
            .contains("systemd timers were skipped")
    );
    assert_eq!(o.json["disabled"]["cron"].as_array().unwrap().len(), 1);
    let o = run(
        &h,
        "disable",
        &[("unit_name", "nightly"), ("backend", "systemd")],
    );
    o.fails(1, "cron.disable_error");
    assert!(
        o.message().contains("service manager is not available"),
        "{}",
        o.message()
    );
}

#[test]
fn systemctl_failures_are_errors() {
    for (verb, failing) in [("rm", "disable"), ("enable", "enable"), ("disable", "stop")] {
        let (h, host) = setup(CRONIE);
        resh_timer(&host, "j", "j", "/j", verb != "enable", verb != "enable");
        host.state().failing.insert(failing.into());
        let o = run(&h, verb, &[("unit_name", "j"), ("backend", "systemd")]);
        o.fails(1, &format!("cron.{verb}_error"));
        assert!(o.message().contains("boom"), "{verb}: {}", o.message());
        let list = match verb {
            "rm" => &o.json["removed"]["systemd"],
            "enable" => &o.json["enabled"]["systemd"],
            _ => &o.json["disabled"]["systemd"],
        };
        assert_eq!(
            list,
            &json!([]),
            "{verb}: a failed timer is not reported as changed"
        );
    }
}

// ===========================================================================
// Field checks, files and helpers carried over from earlier releases
// ===========================================================================

fn add_options(backend: &str) -> CronAddOptions {
    CronAddOptions {
        schedule: "0 4 * * *".to_string(),
        command: "/bin/true".to_string(),
        backend: backend.to_string(),
        id: None,
        description: None,
        allow_duplicate: true,
        dry_run: true,
        scope: None,
        user: None,
        cron_file: None,
        unit_name: None,
        unit_scope: Some("user".to_string()),
        persistent: None,
        accuracy_sec: None,
        random_delay_sec: None,
        service_working_dir: None,
        service_user: None,
        env: None,
        include_next_run: false,
        now_unix: None,
        timezone: None,
        format: OutputFormat::Json,
    }
}

fn field(o: &CronAddOptions, unit: Option<&str>) -> Option<&'static str> {
    validate_add_options(o, &o.backend, unit)
        .err()
        .map(|e| e.field)
}

#[test]
fn crontab_fields_are_single_line() {
    let mut o = add_options("cron");
    o.description = Some("a\nb".into());
    assert_eq!(field(&o, None), Some("description"));
    let mut o = add_options("cron");
    o.id = Some("job id".into());
    assert_eq!(field(&o, None), Some("id"));
    let mut o = add_options("cron");
    o.command = "/bin/true\r* * * * * x".into();
    assert_eq!(field(&o, None), Some("command"));
    let mut o = add_options("cron");
    o.command = "date +%F".into();
    assert_eq!(field(&o, None), Some("command"));
    o.command = r"date +\%F".into();
    assert_eq!(field(&o, None), None);
    o.command = r"printf '\\%s'".into();
    assert_eq!(field(&o, None), Some("command"));
    o.command = r"printf '\\\%s'".into();
    assert_eq!(field(&o, None), None);
}

#[test]
fn system_cron_files_are_limited_to_cron_directories() {
    for ok in ["/etc/crontab", "/etc/cron.d/resh_backup", "/etc/cron.d/a-b"] {
        assert!(check_system_cron_file(ok).is_ok(), "{ok}");
    }
    for bad in [
        "/etc/passwd",
        "/etc/cron.d/",
        "/etc/cron.d/../passwd",
        "/etc/cron.d/sub/x",
        "/etc/cron.d/has.dot",
        "etc/crontab",
        "/tmp/x",
    ] {
        assert!(check_system_cron_file(bad).is_err(), "{bad}");
    }
    let mut o = add_options("cron");
    o.scope = Some("system".into());
    o.cron_file = Some("/root/.bashrc".into());
    assert_eq!(field(&o, None), Some("cron_file"));
    o.cron_file = None;
    o.user = Some("-u".into());
    assert_eq!(field(&o, None), Some("user"));
    o.user = Some("www-data".into());
    assert_eq!(field(&o, None), None);
}

#[test]
fn unit_names_stay_in_the_unit_directory() {
    let o = add_options("systemd");
    for ok in ["nightly-report", "a.b_c:d", "inst@1"] {
        assert_eq!(field(&o, Some(ok)), None, "{ok}");
    }
    for bad in ["../x", "a/b", "-x", ".x", "", "x@", "a b", "é"] {
        assert!(field(&o, Some(bad)).is_some(), "{bad:?}");
    }
    let mut o = add_options("systemd");
    o.id = Some("ok-id".into());
    assert_eq!(field(&o, Some("..")), Some("id"));
    o.unit_name = Some("..".into());
    assert_eq!(field(&o, Some("..")), Some("unit_name"));
}

#[test]
fn unit_values_cannot_add_directives() {
    let check = |f: fn(&mut CronAddOptions)| {
        let mut o = add_options("systemd");
        f(&mut o);
        field(&o, Some("job"))
    };
    assert_eq!(
        check(|o| o.service_user = Some("root\nGroup=x".into())),
        Some("service_user")
    );
    assert_eq!(
        check(|o| o.service_working_dir = Some("/a\\".into())),
        Some("service_working_dir")
    );
    assert_eq!(
        check(|o| o.service_working_dir = Some("rel".into())),
        Some("service_working_dir")
    );
    assert_eq!(
        check(|o| o.accuracy_sec = Some("1s User=x".into())),
        Some("accuracy_sec")
    );
    assert_eq!(check(|o| o.command = "!/bin/true".into()), Some("command"));
    assert_eq!(
        check(|o| o.description = Some("x\\".into())),
        Some("description")
    );
    assert_eq!(
        check(|o| o.env = Some(HashMap::from([("A B".to_string(), "x".to_string())]))),
        Some("env")
    );
    assert_eq!(check(|o| o.accuracy_sec = Some("1h 30min".into())), None);
    assert_eq!(check(|o| o.service_working_dir = Some("~".into())), None);
}

#[test]
fn unit_values_are_serialized_literally() {
    assert_eq!(unit_literal("100% %h"), "100%% %%h");
    assert_eq!(
        unit_environment("K", r#"a "b" \c %d"#),
        "Environment=\"K=a \\\"b\\\" \\\\c %%d\"\n"
    );
    let (_, host) = setup(None);
    let p = SystemCronProvider::with_host("alice".into(), Box::new(host));
    let mut o = add_options("systemd");
    o.command = "/opt/run --at %H".into();
    o.description = Some("50%".into());
    let unit = p.build_service_unit(&o, "job").unwrap();
    assert!(unit.contains("ExecStart=/opt/run --at %%H\n"), "{unit}");
    assert!(unit.contains("Description=50%%\n"), "{unit}");
}

#[test]
fn writes_never_follow_links() {
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path().join("outside");
    fs::write(&outside, "keep").unwrap();
    let dest = dir.path().join("job.service");
    std::os::unix::fs::symlink(&outside, &dest).unwrap();
    assert!(write_file_atomically(dest.to_str().unwrap(), "x").is_err());
    assert_eq!(fs::read_to_string(&outside).unwrap(), "keep");
    let dest = dir.path().join("job.timer");
    let temp = atomic_temp_path(dest.to_str().unwrap());
    std::os::unix::fs::symlink(&outside, &temp).unwrap();
    assert!(write_file_atomically(dest.to_str().unwrap(), "x").is_err());
    assert_eq!(fs::read_to_string(&outside).unwrap(), "keep");
    assert!(!dest.exists());
    let dest = dir.path().join("plain");
    fs::write(&dest, "old").unwrap();
    write_file_atomically(dest.to_str().unwrap(), "new").unwrap();
    assert_eq!(fs::read_to_string(&dest).unwrap(), "new");
    // Reading a system file refuses a link and reports a missing file.
    let editor = SystemCronEditor {};
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    assert!(editor.read_system_file(link.to_str().unwrap()).is_err());
    assert_eq!(
        editor
            .read_system_file(dir.path().join("none").to_str().unwrap())
            .unwrap(),
        None
    );
    assert_eq!(
        editor
            .read_system_file(dest.to_str().unwrap())
            .unwrap()
            .as_deref(),
        Some("new")
    );
}

#[test]
fn temporary_files_are_hidden_from_cron_and_modes_kept() {
    use std::os::unix::fs::PermissionsExt;
    let pid = std::process::id();
    assert_eq!(
        atomic_temp_path("/etc/cron.d/resh_job"),
        format!("/etc/cron.d/.resh_job.tmp.{pid}")
    );
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("resh_job");
    fs::write(&dest, "old").unwrap();
    fs::set_permissions(&dest, fs::Permissions::from_mode(0o600)).unwrap();
    write_file_atomically(dest.to_str().unwrap(), "new").unwrap();
    assert_eq!(
        fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let names: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, vec![std::ffi::OsString::from("resh_job")]);
    let fresh = dir.path().join("fresh");
    write_file_atomically(fresh.to_str().unwrap(), "x").unwrap();
    assert_eq!(
        fs::metadata(&fresh).unwrap().permissions().mode() & 0o022,
        0
    );
}

#[test]
fn system_unit_editor_reads_writes_and_removes() {
    let dir = tempfile::tempdir().unwrap();
    let ed = SystemSystemdEditor {};
    let path = dir.path().join("a.timer");
    let p = path.to_str().unwrap();
    assert_eq!(ed.read_unit_file(p).unwrap(), None);
    ed.write_unit_file(p, "x").unwrap();
    assert_eq!(ed.read_unit_file(p).unwrap().as_deref(), Some("x"));
    assert!(ed.remove_unit_file(p).unwrap());
    assert!(!ed.remove_unit_file(p).unwrap());
}

#[test]
fn cron_tz_assignments_follow_cronie_syntax() {
    assert_eq!(cron_tz_assignment("CRON_TZ=UTC").as_deref(), Some("UTC"));
    assert_eq!(
        cron_tz_assignment(" CRON_TZ = 'Asia/Tokyo' ").as_deref(),
        Some("Asia/Tokyo")
    );
    assert_eq!(
        cron_tz_assignment("CRON_TZ=\"UTC\"").as_deref(),
        Some("UTC")
    );
    assert_eq!(cron_tz_assignment("CRON_TZ=").as_deref(), Some(""));
    assert_eq!(cron_tz_assignment("# CRON_TZ=UTC"), None);
    assert_eq!(cron_tz_assignment("TZ=UTC"), None);
    assert_eq!(cron_tz_assignment("0 2 * * * x=CRON_TZ"), None);
    let lines = ["CRON_TZ=UTC", "CRON_TZ=", "0 2 * * * x"];
    assert_eq!(effective_cron_tz(&lines, 2), None);
    assert_eq!(effective_cron_tz(&lines, 1).as_deref(), Some("UTC"));
}

#[test]
fn orphan_cron_tz_lines_are_dropped_only_when_harmless() {
    let v = |s: &[&str]| s.iter().map(|l| l.to_string()).collect::<Vec<_>>();
    assert_eq!(
        drop_orphaned_tz_lines(
            v(&[TZ_BLOCK_MARKER, "CRON_TZ=A", "CRON_TZ=B", "1 1 * * * b"]),
            &[1]
        ),
        v(&[TZ_BLOCK_MARKER, "CRON_TZ=B", "1 1 * * * b"])
    );
    for next in ["1 1 * * * b", "# 1 1 * * * b"] {
        let lines = v(&[TZ_BLOCK_MARKER, "CRON_TZ=A", next]);
        assert_eq!(drop_orphaned_tz_lines(lines.clone(), &[1]), lines);
    }
    assert_eq!(
        drop_orphaned_tz_lines(v(&["x", TZ_BLOCK_MARKER, "CRON_TZ=A", ""]), &[2]),
        v(&["x"])
    );
    let lines = v(&["CRON_TZ=A"]);
    assert_eq!(drop_orphaned_tz_lines(lines.clone(), &[]), lines);
}

#[test]
fn cronie_is_recognized_only_by_its_version_string() {
    let (_, host) = setup(CRONIE);
    assert!(cronie_detected(&host).is_ok());
    for other in [None, Some("cron 3.0pl1"), Some("")] {
        let (_, host) = setup(other);
        assert!(cronie_detected(&host).is_err(), "{other:?}");
    }
}

#[test]
fn crontab_is_run_without_u_for_the_invoking_user() {
    let me = invoking_user_name().unwrap();
    assert!(crontab_user_args(&me).is_empty());
    assert_eq!(
        crontab_user_args("someone-else-x"),
        s(&["-u", "someone-else-x"])
    );
    assert!(no_crontab(b"no crontab for alice\n"));
    assert!(!no_crontab(b"must be privileged to use -u\n"));
}

// ---- the host's local zone ------------------------------------------------------

fn jan15() -> DateTime<Utc> {
    at(2026, 1, 15, 0, 0)
}

fn plus(hours: i32) -> FixedOffset {
    FixedOffset::east_opt(hours * 3600).unwrap()
}

#[test]
fn tz_variable_wins_and_accepts_names_colons_and_paths() {
    let link = Some("/usr/share/zoneinfo/Europe/Berlin");
    for value in [
        "Asia/Tokyo",
        ":Asia/Tokyo",
        "/usr/share/zoneinfo/Asia/Tokyo",
        ":/usr/share/zoneinfo/posix/Asia/Tokyo",
    ] {
        assert_eq!(
            detect_local_zone(Some(value), link, None, jan15(), plus(1)),
            RunZone::Named(Tz::Asia__Tokyo),
            "{value}"
        );
    }
    assert_eq!(
        detect_local_zone(Some("XYZ-3"), link, None, jan15(), plus(3)),
        RunZone::Offset(plus(3))
    );
    assert_eq!(
        detect_local_zone(Some(" "), link, None, jan15(), plus(1)),
        RunZone::Named(Tz::Europe__Berlin)
    );
}

#[test]
fn localtime_link_and_etc_timezone() {
    for link in [
        "/usr/share/zoneinfo/Europe/Berlin",
        "../usr/share/zoneinfo/Europe/Berlin",
        "/usr/share/zoneinfo/right/Europe/Berlin",
    ] {
        assert_eq!(
            detect_local_zone(None, Some(link), None, jan15(), plus(1)),
            RunZone::Named(Tz::Europe__Berlin),
            "{link}"
        );
    }
    assert_eq!(
        detect_local_zone(None, None, Some("Europe/Berlin\n"), jan15(), plus(1)),
        RunZone::Named(Tz::Europe__Berlin)
    );
    assert_eq!(
        detect_local_zone(None, None, Some("Europe/Berlin\n"), jan15(), plus(9)),
        RunZone::Offset(plus(9))
    );
    assert_eq!(RunZone::Named(Tz::Europe__Berlin).label(), "Europe/Berlin");
    assert_eq!(RunZone::Offset(plus(-5)).label(), "-05:00");
    assert!(RunZone::Named(Tz::UTC).offset_warning().is_none());
    assert!(
        RunZone::Offset(plus(3))
            .offset_warning()
            .unwrap()
            .contains("current UTC offset +03:00")
    );
}

// ===========================================================================
// Dispatch: options reach the provider exactly as parsed
// ===========================================================================

#[derive(Debug, Default, Clone)]
struct Recording(Arc<Mutex<Vec<(&'static str, bool)>>>);

impl CronProvider for Recording {
    fn list_cron_entries(&self, _: &CronListOptions) -> Result<CronListResponse> {
        self.0.lock().unwrap().push(("list", false));
        anyhow::bail!("recording provider: nothing done")
    }
    fn add_cron_job(&self, o: &CronAddOptions) -> Result<CronAddResponse> {
        self.0.lock().unwrap().push(("add", o.dry_run));
        anyhow::bail!("recording provider: nothing done")
    }
    fn remove_cron_jobs(&self, o: &CronRmOptions) -> Result<CronRmResponse> {
        self.0.lock().unwrap().push(("rm", o.dry_run));
        anyhow::bail!("recording provider: nothing done")
    }
    fn enable_cron_jobs(&self, o: &CronEnableOptions) -> Result<CronEnableResponse> {
        self.0.lock().unwrap().push(("enable", o.dry_run));
        anyhow::bail!("recording provider: nothing done")
    }
    fn disable_cron_jobs(&self, o: &CronDisableOptions) -> Result<CronDisableResponse> {
        self.0.lock().unwrap().push(("disable", o.dry_run));
        anyhow::bail!("recording provider: nothing done")
    }
}

#[test]
fn provider_errors_fail_through_call_and_dry_run_is_passed_on() {
    for verb in VERBS {
        for (value, expected) in [
            (Some("true"), true),
            (Some("ON"), true),
            (Some("0"), false),
            (None, false),
        ] {
            if *verb == "list" && value.is_some() {
                continue;
            }
            let rec = Recording::default();
            let h = CronHandle::new(Box::new(rec.clone()));
            let mut args = minimal_args(verb);
            if let Some(v) = value {
                args.push(("dry_run", v));
            }
            args.push(("format", "text"));
            let o = run(&h, verb, &args);
            o.fails(1, &format!("cron.{verb}_error"));
            assert!(
                o.message().contains("recording provider"),
                "{}",
                o.message()
            );
            assert_eq!(
                *rec.0.lock().unwrap(),
                vec![(*verb, expected)],
                "{verb} {value:?}"
            );
        }
    }
}
