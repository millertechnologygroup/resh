//! Binary tests for every `config://` verb and its help. Each test runs the
//! real `resh` binary with HOME and XDG_CONFIG_HOME inside its own temporary
//! directory, so the real ~/.config is never touched.

use std::path::{Path, PathBuf};
use std::process::{Child, Command as StdCommand, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn resh(dir: &Path) -> assert_cmd::Command {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
    cmd.current_dir(dir)
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("xdg"))
        .env_remove("SSH_AUTH_SOCK");
    cmd
}

/// Runs resh in `dir`; returns (exit code, stdout, stderr).
fn run(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = resh(dir).args(args).output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn store(dir: &Path) -> PathBuf {
    dir.join("xdg").join("resh").join("config")
}

fn set(dir: &Path, url: &str, value: &str) {
    let (code, out, err) = run(
        dir,
        &[&format!("config://{url}.set"), &format!("value={value}")],
    );
    assert_eq!((code, out.as_str()), (0, ""), "{err}");
}

// --- get ---------------------------------------------------------------------

#[test]
fn get_prints_the_stored_value() {
    let tmp = TempDir::new().unwrap();
    set(
        tmp.path(),
        "app/db/url",
        "postgres://db.example.com:5432/app",
    );
    let (code, out, _) = run(tmp.path(), &["config://app/db/url.get"]);
    assert_eq!(code, 0);
    assert_eq!(out, r#""postgres://db.example.com:5432/app""#);
}

#[test]
fn get_errors() {
    let tmp = TempDir::new().unwrap();
    let (code, out, err) = run(tmp.path(), &["config://nope/k.get"]);
    assert_eq!((code, out.as_str()), (1, ""));
    assert!(
        err.contains("Error: [config.not_found] not found\n"),
        "{err}"
    );
    assert!(
        !store(tmp.path()).exists(),
        "get must not create directories"
    );

    std::fs::create_dir_all(store(tmp.path()).join("app")).unwrap();
    std::fs::write(store(tmp.path()).join("app/bad.json"), "{").unwrap();
    let (code, _, err) = run(tmp.path(), &["config://app/bad.get"]);
    assert_eq!(code, 1);
    assert!(
        err.contains("Error: [config.corrupt_value] invalid json"),
        "{err}"
    );

    let (code, _, err) = run(tmp.path(), &["config://app/bad.get", "timeout_ms=5"]);
    assert_eq!(code, 2);
    assert!(err.contains("does not take timeout_ms"), "{err}");
}

// --- set ---------------------------------------------------------------------

#[test]
fn set_stores_json_and_strings() {
    let tmp = TempDir::new().unwrap();
    set(tmp.path(), "app/timeout", "30");
    set(tmp.path(), "theme", "dark");
    let (code, _, _) = run(
        tmp.path(),
        &[
            "config://app/flags.set",
            r#"value={"beta":true}"#,
            "raw=true",
        ],
    );
    assert_eq!(code, 0);
    let read = |p: &str| std::fs::read_to_string(store(tmp.path()).join(p)).unwrap();
    assert_eq!(read("app/timeout.json"), "30");
    assert_eq!(read("default/theme.json"), r#""dark""#);
    assert_eq!(read("app/flags.json"), r#"{"beta":true}"#);
}

#[test]
fn set_errors_have_no_side_effects() {
    let tmp = TempDir::new().unwrap();
    for (args, code, msg) in [
        (&["config://app/k.set"][..], 2, "missing arg: value"),
        (
            &["config://app/k.set", "value=x", "raw=true"][..],
            2,
            "invalid json",
        ),
        (
            &["config://app/k.set", "value=1", "raw=maybe"][..],
            2,
            "invalid value for raw",
        ),
        (
            &["config://app/k.set", "value=1", "dry_run=true"][..],
            2,
            "does not support dry_run",
        ),
        (
            &["config://app/k.set", "value=1", "vlaue=2"][..],
            2,
            "unknown argument",
        ),
        (
            &["config://../escape.set", "value=1"][..],
            2,
            "'..' segments are not allowed",
        ),
    ] {
        let (c, _, err) = run(tmp.path(), args);
        assert_eq!(c, code, "{args:?}: {err}");
        assert!(err.contains(msg), "{args:?}: {err}");
    }
    assert!(!tmp.path().join("xdg").exists(), "nothing was written");
}

// --- ls ----------------------------------------------------------------------

#[test]
fn ls_matches_help_example_shape() {
    let tmp = TempDir::new().unwrap();
    set(tmp.path(), "app/db/url", "pg");
    set(tmp.path(), "app/theme", "dark");
    let (code, out, _) = run(tmp.path(), &["--json-pretty", "config://app.ls"]);
    assert_eq!(code, 0);
    let mut got: serde_json::Value = serde_json::from_str(&out).unwrap();
    // The timestamp is the only value that differs from the help example.
    let ts = &mut got["entries"][1]["meta"]["updated_at"];
    assert!(ts.as_str().unwrap().contains('T'));
    *ts = "2026-10-16T09:12:44.512309817+00:00".into();
    assert_eq!(got, help_example_output("ls"));
}

#[test]
fn ls_options_and_errors() {
    let tmp = TempDir::new().unwrap();
    set(tmp.path(), "app/db/url", "pg");
    set(tmp.path(), "app/theme", "dark");
    let (code, out, _) = run(
        tmp.path(),
        &[
            "config://app.ls",
            "recursive=true",
            "pattern=u*",
            "limit=5",
            "offset=0",
        ],
    );
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["entries"].as_array().unwrap().len(), 1);
    assert_eq!(v["entries"][0]["full_key"], "app/db/url");

    for (arg, msg) in [
        ("recursive=perhaps", "invalid value for recursive"),
        ("limit=x", "invalid limit value"),
        ("offset=-1", "invalid offset value"),
        ("pattern=[", "invalid pattern"),
        ("timeout_ms=1", "does not take timeout_ms"),
    ] {
        let (c, _, err) = run(tmp.path(), &["config://app.ls", arg]);
        assert_eq!(c, 2, "{arg}: {err}");
        assert!(err.contains(msg), "{arg}: {err}");
    }
}

// --- watch -------------------------------------------------------------------

fn spawn_watch(dir: &Path, args: &[&str]) -> Child {
    StdCommand::new(env!("CARGO_BIN_EXE_resh"))
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("xdg"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Keeps changing `key` until the watcher exits (it stops after its
/// max_events), bounded by 20 s; returns its exit code and stdout lines.
fn drive_watch(dir: &Path, mut child: Child, url: &str) -> (i32, Vec<serde_json::Value>) {
    let started = Instant::now();
    let mut n = 0;
    while child.try_wait().unwrap().is_none() {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "watch did not stop"
        );
        std::thread::sleep(Duration::from_millis(150));
        set(dir, url, &n.to_string());
        n += 1;
    }
    let out = child.wait_with_output().unwrap();
    let lines = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    (out.status.code().unwrap_or(-1), lines)
}

#[test]
fn watch_help_example_reports_changes() {
    let tmp = TempDir::new().unwrap();
    // The help example, exactly.
    let child = spawn_watch(
        tmp.path(),
        &[
            "config://app.watch",
            "prefix=app/db",
            "timeout_ms=10000",
            "max_events=5",
        ],
    );
    let (code, lines) = drive_watch(tmp.path(), child, "app/db/url");
    assert_eq!(code, 0);
    assert_eq!(lines.len(), 5);
    for (i, l) in lines.iter().enumerate() {
        assert_eq!(l["op"], "set");
        assert_eq!(l["key"], "app/db/url");
        assert_eq!(l["scope"], "app");
        assert_eq!(l["source"], "config");
        assert_eq!(l["version"], i as u64 + 1);
    }
}

#[test]
fn watch_initial_key_filter_and_timeout() {
    let tmp = TempDir::new().unwrap();
    set(tmp.path(), "app/db/url", "pg");
    set(tmp.path(), "app/theme", "dark");
    let started = Instant::now();
    let (code, out, _) = run(
        tmp.path(),
        &[
            "config://app/db.watch",
            "key=db/url",
            "initial=true",
            "timeout_ms=300",
        ],
    );
    assert_eq!(code, 0);
    assert!(started.elapsed() >= Duration::from_millis(300));
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(
        (v["op"].as_str(), v["key"].as_str()),
        (Some("snapshot"), Some("db/url"))
    );
    assert_eq!(v["value"], "pg");
}

#[test]
fn watch_errors() {
    let tmp = TempDir::new().unwrap();
    for (args, code, msg) in [
        (
            &["config://app.watch", "key=a", "prefix=b"][..],
            2,
            "key and prefix",
        ),
        (
            &["config://app.watch", "timeout_ms=abc"][..],
            2,
            "invalid timeout_ms value",
        ),
        (
            &["config://app.watch", "max_events=-1"][..],
            2,
            "invalid max_events value",
        ),
        (
            &["config://app.watch", "initial=perhaps"][..],
            2,
            "invalid value for initial",
        ),
        (
            &["config://app.watch", "pattern=x"][..],
            2,
            "unknown argument for config watch",
        ),
    ] {
        let (c, _, err) = run(tmp.path(), args);
        assert_eq!(c, code, "{args:?}: {err}");
        assert!(err.contains(msg), "{args:?}: {err}");
    }
    assert!(
        !tmp.path().join("xdg").exists(),
        "invalid input has no side effect"
    );
}

#[test]
fn set_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new().unwrap();
    set(tmp.path(), "app/db/url", "pg");
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&store(tmp.path()).join("app/db/url.json")), 0o600);
    assert_eq!(mode(&store(tmp.path()).join("app/db")), 0o700);
    assert_eq!(mode(&store(tmp.path()).join("app")), 0o700);
}

#[test]
fn io_errors_and_unknown_verbs_use_the_shared_exit_codes() {
    let tmp = TempDir::new().unwrap();
    std::fs::create_dir_all(store(tmp.path()).join("app/dir.json")).unwrap();
    let (code, _, err) = run(tmp.path(), &["config://app/dir.get"]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("Error: [config.io_error] I/O error"), "{err}");
    let (code, _, err) = run(tmp.path(), &["config://app/dir.set", "value=1"]);
    assert_eq!(code, 1, "{err}");
    let (code, _, err) = run(tmp.path(), &["config://app/k.delete"]);
    assert_eq!(code, 2, "{err}");
    assert!(
        err.contains("Error: [config.unknown_verb] unknown verb for config://: delete"),
        "{err}"
    );
    let (code, _, err) = run(tmp.path(), &["config://app/k.set", "valeu=1"]);
    assert_eq!(code, 2);
    assert!(
        err.contains("Error: [config.invalid_argument] unknown argument")
            && err.contains("did you mean `value`?"),
        "{err}"
    );
}

/// Each event is written as it happens (the stage output is streamed), so
/// a reader sees it before watch ends.
#[test]
fn watch_events_are_streamed_while_it_runs() {
    use std::io::{BufRead, BufReader};
    let tmp = TempDir::new().unwrap();
    let mut child = spawn_watch(
        tmp.path(),
        &["config://app.watch", "prefix=app/", "timeout_ms=20000"],
    );
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send(line);
    });
    let started = Instant::now();
    let line = loop {
        set(
            tmp.path(),
            "app/k",
            &started.elapsed().as_millis().to_string(),
        );
        if let Ok(line) = rx.recv_timeout(Duration::from_millis(200)) {
            break line;
        }
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "no event streamed"
        );
    };
    // The event arrived while watch was still running.
    assert!(child.try_wait().unwrap().is_none());
    let _ = child.kill();
    let _ = child.wait();
    let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(
        (v["op"].as_str(), v["key"].as_str()),
        (Some("set"), Some("app/k"))
    );
}

// --- help --------------------------------------------------------------------

const VERBS: [&str; 4] = ["get", "set", "ls", "watch"];

fn golden(name: &str) -> &'static str {
    match name {
        "config" => include_str!("golden/config_help.txt"),
        "get" => include_str!("golden/config_get_help.txt"),
        "set" => include_str!("golden/config_set_help.txt"),
        "ls" => include_str!("golden/config_ls_help.txt"),
        "watch" => include_str!("golden/config_watch_help.txt"),
        _ => unreachable!(),
    }
}

/// The options a verb parses (kept in step with `verb_args` in
/// src/handles/data/config.rs; a unit test there checks the usage text).
fn options(verb: &str) -> Vec<&'static str> {
    let mut v = match verb {
        "get" => vec![],
        "set" => vec!["value", "raw"],
        "ls" => vec!["recursive", "pattern", "limit", "offset"],
        "watch" => vec!["key", "prefix", "timeout_ms", "max_events", "initial"],
        _ => unreachable!(),
    };
    v.sort();
    v
}

fn section<'a>(help: &'a str, name: &str) -> &'a str {
    help.split(&format!("\n{name}:\n"))
        .nth(1)
        .unwrap_or_else(|| panic!("no {name} section"))
        .split("\n\n")
        .next()
        .unwrap()
}

/// The JSON in a verb's "Example Output:" section.
fn help_example_output(verb: &str) -> serde_json::Value {
    let help = golden(verb);
    let body = help.split("\nExample Output:\n").nth(1).unwrap();
    let json: String = body
        .lines()
        .take_while(|l| !l.is_empty())
        .map(|l| l.strip_prefix("  ").unwrap_or(l))
        .collect::<Vec<_>>()
        .join("\n");
    serde_json::from_str(&json).unwrap()
}

fn assert_plain(out: &str) {
    assert!(out.is_ascii() && !out.contains('\x1b'));
    for line in out.lines() {
        assert!(line.len() <= 80, "line over 80 columns: {line:?}");
        assert!(!line.ends_with(' '), "trailing space: {line:?}");
    }
}

#[test]
fn handle_help_matches_golden_and_lists_verbs() {
    let tmp = TempDir::new().unwrap();
    let (code, out, err) = run(tmp.path(), &["config", "--help"]);
    assert_eq!((code, err.as_str()), (0, ""));
    assert_eq!(out, golden("config"));
    assert_plain(&out);
    let mut listed: Vec<&str> = section(&out, "Available Verbs")
        .lines()
        .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    listed.sort();
    let mut verbs = VERBS.to_vec();
    verbs.sort();
    assert_eq!(listed, verbs);
    // The in-URL form shows the same text.
    let (code, out, _) = run(tmp.path(), &["config://--help"]);
    assert_eq!((code, out.as_str()), (0, golden("config")));
    assert!(
        !tmp.path()
            .join("xdg")
            .join("resh")
            .join("config")
            .join("app")
            .exists()
    );
}

#[test]
fn verb_help_matches_golden_and_lists_parsed_options() {
    let tmp = TempDir::new().unwrap();
    for verb in VERBS {
        let (code, out, err) = run(tmp.path(), &["config", verb, "--help"]);
        assert_eq!((code, err.as_str()), (0, ""), "{verb}");
        assert_eq!(out, golden(verb), "{verb}");
        assert_plain(&out);
        assert!(out.starts_with(&format!("Handle: config\nVerb: {verb}\nDefinition: ")));
        let usage = section(&out, "Usage");
        assert!(usage.contains(&format!(".{verb}")), "{verb}: {usage}");
        let mut listed: Vec<&str> = usage
            .split(|c: char| c == '[' || c.is_whitespace())
            .filter_map(|w| w.split_once('=').map(|(k, _)| k))
            .collect();
        listed.sort();
        assert_eq!(listed, options(verb), "{verb} usage options");
        let example = section(&out, "Example");
        assert!(example.trim_start().starts_with("resh "), "{verb}");
    }
}

#[test]
fn get_and_set_help_examples_run() {
    let tmp = TempDir::new().unwrap();
    // set example: resh config://app/db/url.set value=postgres://...
    let (code, out, _) = run(
        tmp.path(),
        &[
            "config://app/db/url.set",
            "value=postgres://db.example.com:5432/app",
        ],
    );
    assert_eq!((code, out.as_str()), (0, ""));
    // get example and its documented output.
    let (code, out, _) = run(tmp.path(), &["config://app/db/url.get"]);
    assert_eq!(code, 0);
    let expected = section(golden("get"), "Example Output").trim();
    assert_eq!(out, expected);
}
