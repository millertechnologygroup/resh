//! Binary tests for every `event://` verb and its help. Each test runs the
//! real `resh` binary with HOME and XDG_STATE_HOME inside its own temporary
//! directory, so the real ~/.local/state is never touched. Several tests run
//! resh processes concurrently to check that the store is shared safely.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn resh(dir: &Path) -> assert_cmd::Command {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
    cmd.current_dir(dir)
        .env("HOME", dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .env_remove("SSH_AUTH_SOCK");
    cmd
}

fn resh_std(dir: &Path) -> StdCommand {
    let mut cmd = StdCommand::new(env!("CARGO_BIN_EXE_resh"));
    cmd.current_dir(dir)
        .env("HOME", dir)
        .env("XDG_STATE_HOME", dir.join("state"))
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

fn json_of(s: &str) -> Value {
    serde_json::from_str(s).unwrap_or_else(|e| panic!("not JSON ({e}): {s}"))
}

fn store(dir: &Path) -> PathBuf {
    dir.join("state").join("resh").join("events")
}

fn emit(dir: &Path, topic: &str, data: &str) -> Value {
    let (code, out, err) = run(
        dir,
        &[
            "event://.emit",
            &format!("topic={topic}"),
            &format!("data={data}"),
        ],
    );
    assert_eq!(code, 0, "{err}");
    json_of(&out)["event"].clone()
}

fn datas(v: &Value) -> Vec<Value> {
    v["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["data"].clone())
        .collect()
}

/// Holds `lock` of the store exclusively until dropped (flock works across
/// processes).
fn hold_lock(dir: &Path, lock: &str) -> std::fs::File {
    std::fs::create_dir_all(store(dir)).unwrap();
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(store(dir).join(lock))
        .unwrap();
    use std::os::fd::AsRawFd;
    // SAFETY: flock on a file descriptor owned by `f`.
    assert_eq!(unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) }, 0);
    f
}

// --- emit and subscribe across processes -------------------------------------

#[test]
fn an_event_emitted_by_one_command_is_read_by_a_later_one() {
    let tmp = TempDir::new().unwrap();
    let evt = emit(
        tmp.path(),
        "jobs.backup.completed",
        r#"{"status":"success"}"#,
    );
    let (code, out, err) = run(
        tmp.path(),
        &["event://.subscribe", "topic=jobs.*", "offset=earliest"],
    );
    assert_eq!(code, 0, "{err}");
    let v = json_of(&out);
    assert_eq!(v["events"][0]["id"], evt["id"]);
    assert_eq!(datas(&v), [json!({"status": "success"})]);
    // The hooks print their notes on stderr only.
    assert!(
        err.contains("MQ hook processed subscription with 1 events"),
        "{err}"
    );

    use std::os::unix::fs::PermissionsExt;
    let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(store(tmp.path())), 0o700);
    assert_eq!(
        mode(store(tmp.path()).join("jobs.backup.completed.jsonl")),
        0o600
    );
}

#[test]
fn concurrent_emitters_and_group_consumers_lose_and_repeat_nothing() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    const EMITTERS: usize = 4;
    const PER: usize = 8;
    let total = EMITTERS * PER;

    // Consumers of one group, each a loop of separate resh processes, run
    // while the emitters are still writing; they stop once the emitters are
    // done and a read comes back empty.
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let consumers: Vec<_> = (0..3)
        .map(|_| {
            let dir = dir.clone();
            let done = done.clone();
            std::thread::spawn(move || {
                let mut got: Vec<i64> = Vec::new();
                let started = Instant::now();
                while started.elapsed() < Duration::from_secs(120) {
                    let finished = done.load(std::sync::atomic::Ordering::SeqCst);
                    let (code, out, err) = run(
                        &dir,
                        &[
                            "event://.subscribe",
                            "topic=load.*",
                            "offset=next",
                            "group_id=workers",
                            "limit=3",
                        ],
                    );
                    assert_eq!(code, 0, "{err}");
                    let batch: Vec<i64> = datas(&json_of(&out))
                        .iter()
                        .map(|d| d.as_i64().unwrap())
                        .collect();
                    if batch.is_empty() {
                        if finished {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    got.extend(batch);
                }
                got
            })
        })
        .collect();
    let emitters: Vec<_> = (0..EMITTERS)
        .map(|e| {
            let dir = dir.clone();
            std::thread::spawn(move || {
                for i in 0..PER {
                    let n = e * PER + i;
                    let topic = if n % 2 == 0 { "load.even" } else { "load.odd" };
                    emit(&dir, topic, &n.to_string());
                }
            })
        })
        .collect();
    for e in emitters {
        e.join().unwrap();
    }
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    let mut all: Vec<i64> = consumers
        .into_iter()
        .flat_map(|c| c.join().unwrap())
        .collect();
    all.sort();
    assert_eq!(all, (0..total as i64).collect::<Vec<_>>());

    // Every line is whole, and sequence numbers are unique.
    let mut seqs = Vec::new();
    for topic in ["load.even", "load.odd"] {
        let text = std::fs::read_to_string(store(&dir).join(format!("{topic}.jsonl"))).unwrap();
        for line in text.lines() {
            seqs.push(json_of(line)["seq"].as_u64().unwrap());
        }
    }
    seqs.sort();
    assert_eq!(seqs, (1..=total as u64).collect::<Vec<_>>());
}

#[test]
fn a_waiting_subscriber_receives_an_event_from_another_process() {
    let tmp = TempDir::new().unwrap();
    let child = resh_std(tmp.path())
        .args([
            "event://.subscribe",
            "topic=deploy.*",
            "wait=true",
            "wait_timeout_ms=20000",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // offset=latest: the subscriber must start before the event is stored.
    std::thread::sleep(Duration::from_millis(700));
    let started = Instant::now();
    emit(tmp.path(), "deploy.finished", r#"{"version":"1.4.2"}"#);
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let v = json_of(&String::from_utf8(out.stdout).unwrap());
    assert_eq!(datas(&v), [json!({"version": "1.4.2"})]);
    assert_eq!(v["timed_out"], false);
    assert!(started.elapsed() < Duration::from_secs(10));

    // With nothing to read, wait ends at timeout_ms with exit 0.
    let started = Instant::now();
    let (code, out, _) = run(
        tmp.path(),
        &[
            "event://.subscribe",
            "topic=none",
            "wait=true",
            "timeout_ms=300",
        ],
    );
    assert_eq!(code, 0);
    assert_eq!(json_of(&out)["timed_out"], true);
    assert!(started.elapsed() >= Duration::from_millis(300));
}

#[test]
fn follow_streams_events_while_it_runs() {
    let tmp = TempDir::new().unwrap();
    let mut child = resh_std(tmp.path())
        .args(["event://.subscribe", "topic=stream.*", "follow=true"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if tx.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    let started = Instant::now();
    let mut n = 0;
    let line = loop {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "no event was printed while follow was running"
        );
        emit(tmp.path(), "stream.x", &n.to_string());
        n += 1;
        if let Ok(line) = rx.recv_timeout(Duration::from_millis(400)) {
            break line;
        }
    };
    assert!(
        child.try_wait().unwrap().is_none(),
        "the event arrived only after follow exited"
    );
    let v = json_of(&line);
    assert_eq!(v["topic"], "stream.x");
    child.kill().unwrap();
    child.wait().unwrap();

    // max_events ends a follow with exit 0 (timeout_ms is only a safety
    // net: at least two events are stored).
    emit(tmp.path(), "stream.y", "99");
    let (code, out, _) = run(
        tmp.path(),
        &[
            "event://.subscribe",
            "topic=stream.*",
            "offset=earliest",
            "follow=true",
            "max_events=2",
            "timeout_ms=60000",
        ],
    );
    assert_eq!(code, 0);
    assert_eq!(out.lines().count(), 2);
    assert_eq!(json_of(out.lines().next().unwrap())["data"], 0);
}

// --- failures -------------------------------------------------------------------

#[test]
fn invalid_arguments_exit_2_with_coded_errors() {
    let tmp = TempDir::new().unwrap();
    let (code, out, err) = run(
        tmp.path(),
        &["event://.emit", "topic=t", "data={", "tgas=[]"],
    );
    assert_eq!(code, 2);
    assert_eq!(
        err,
        "Error: [event.invalid_argument] unknown argument for emit: tgas (did you mean `tags`?)\n"
    );
    assert_eq!(json_of(&out)["error"]["code"], "event.invalid_argument");

    let (code, out, err) = run(tmp.path(), &["event://.emit", "topic=t", "data={"]);
    assert_eq!(code, 2);
    assert!(
        err.starts_with("Error: [event.invalid_data] data is not valid JSON"),
        "{err}"
    );
    assert_eq!(json_of(&out)["ok"], false);

    let (code, _, err) = run(
        tmp.path(),
        &["event://.subscribe", "topic=t", "offset=next"],
    );
    assert_eq!(code, 2);
    assert!(
        err.starts_with("Error: [event.missing_argument] offset=next needs group_id"),
        "{err}"
    );

    let (code, out, err) = run(tmp.path(), &["event://.hooks.disable", "name=mqq"]);
    assert_eq!((code, out.as_str()), (2, ""));
    assert!(
        err.contains("[event.unknown_hook]") && err.contains("did you mean `mq`?"),
        "{err}"
    );

    let (code, _, err) = run(tmp.path(), &["event://.list-topics", "sources=mq"]);
    assert_eq!(code, 2);
    assert!(
        err.starts_with("Error: [event.invalid_argument] source \"mq\""),
        "{err}"
    );

    let (code, _, err) = run(tmp.path(), &["event://jobs.emit", "topic=t", "data=1"]);
    assert_eq!(code, 2);
    assert!(err.starts_with("Error: [event.invalid_target]"), "{err}");

    let (code, _, err) = run(
        tmp.path(),
        &["event://.emit", "topic=t", "data=1", "dry_run=true"],
    );
    assert_eq!(code, 2, "{err}");

    let (code, _, _) = run(tmp.path(), &["event://.hooks.list", "timeout_ms=5"]);
    assert_eq!(code, 2);
    assert!(!store(tmp.path()).exists(), "nothing may be written");
}

#[test]
fn a_held_lock_makes_emit_and_subscribe_time_out_with_124() {
    let tmp = TempDir::new().unwrap();
    emit(tmp.path(), "t", "1");
    let lock = hold_lock(tmp.path(), "_store.lock");
    let started = Instant::now();
    let (code, out, err) = run(
        tmp.path(),
        &["event://.emit", "topic=t", "data=2", "timeout_ms=300"],
    );
    assert_eq!(code, 124, "{err}");
    assert!(
        err.starts_with("Error: [event.timeout] timeout_ms passed"),
        "{err}"
    );
    assert_eq!(json_of(&out)["error"]["code"], "event.timeout");
    assert!(started.elapsed() < Duration::from_secs(10));
    let (code, _, _) = run(
        tmp.path(),
        &[
            "event://.subscribe",
            "topic=t",
            "offset=earliest",
            "timeout_ms=300",
        ],
    );
    assert_eq!(code, 124);
    let (code, _, _) = run(tmp.path(), &["event://.list-topics", "timeout_ms=300"]);
    assert_eq!(code, 124);
    drop(lock);
    let lines = std::fs::read_to_string(store(tmp.path()).join("t.jsonl")).unwrap();
    assert_eq!(lines.lines().count(), 1, "the timed-out emit wrote nothing");
}

#[test]
fn a_planted_symlink_is_never_written_through() {
    let tmp = TempDir::new().unwrap();
    emit(tmp.path(), "seed", "0");
    let victim = tmp.path().join("victim");
    std::fs::write(&victim, "keep").unwrap();
    std::os::unix::fs::symlink(&victim, store(tmp.path()).join("t.jsonl")).unwrap();
    let (code, _, err) = run(tmp.path(), &["event://.emit", "topic=t", "data=1"]);
    assert_eq!(code, 1);
    assert!(
        err.starts_with("Error: [event.store_error] refusing to write through a symlink"),
        "{err}"
    );
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
}

// --- list-topics and hooks ---------------------------------------------------------

#[test]
fn list_topics_lists_what_was_emitted() {
    let tmp = TempDir::new().unwrap();
    emit(tmp.path(), "jobs.a", r#"{"n":1}"#);
    emit(tmp.path(), "jobs.a", r#"{"n":2}"#);
    emit(tmp.path(), "other", "1");
    let (code, out, _) = run(
        tmp.path(),
        &[
            "event://.list-topics",
            "prefix=jobs.",
            "include_stats=true",
            "include_schema=true",
        ],
    );
    assert_eq!(code, 0);
    let v = json_of(&out);
    assert_eq!(v["topics_total"], 1);
    let t = &v["topics"][0];
    assert_eq!(t["name"], "jobs.a");
    assert_eq!(t["stats"]["approx_message_count"], 2);
    assert_eq!(
        t["schema"]["fields"],
        json!([{"name": "n", "type": "integer", "required": true}])
    );
}

#[test]
fn hooks_state_carries_over_to_later_commands() {
    let tmp = TempDir::new().unwrap();
    let (code, out, _) = run(tmp.path(), &["event://.hooks.disable", "name=mq"]);
    assert_eq!(
        (code, out.as_str()),
        (0, "{\"changed\":true,\"disabled\":true,\"hook\":\"mq\"}\n")
    );
    let (_, out, _) = run(tmp.path(), &["event://.hooks.list"]);
    assert_eq!(json_of(&out)["disabled"], json!(["mq"]));
    let (code, _, err) = run(
        tmp.path(),
        &[
            "event://.emit",
            "topic=t",
            "data=1",
            r#"tags=["mq:orders"]"#,
        ],
    );
    assert_eq!((code, err.as_str()), (0, ""));
    let (_, _, err) = run(tmp.path(), &["event://.subscribe", "topic=t"]);
    assert!(!err.contains("MQ hook"), "{err}");
    assert!(err.contains("Log hook"), "{err}");
    let (code, out, _) = run(tmp.path(), &["event://.hooks.enable", "name=mq"]);
    assert_eq!(
        (code, out.as_str()),
        (0, "{\"changed\":true,\"enabled\":true,\"hook\":\"mq\"}\n")
    );
    let (_, _, err) = run(
        tmp.path(),
        &[
            "event://.emit",
            "topic=t",
            "data=1",
            r#"tags=["mq:orders"]"#,
        ],
    );
    assert!(err.starts_with("MQ Hook: Would forward event"), "{err}");
}

// --- help ----------------------------------------------------------------------

const VERBS: [&str; 6] = [
    "list-topics",
    "subscribe",
    "emit",
    "hooks.list",
    "hooks.enable",
    "hooks.disable",
];

fn golden(name: &str) -> &'static str {
    match name {
        "event" => include_str!("golden/event_help.txt"),
        "emit" => include_str!("golden/event_emit_help.txt"),
        "subscribe" => include_str!("golden/event_subscribe_help.txt"),
        "list-topics" => include_str!("golden/event_list-topics_help.txt"),
        "hooks.list" => include_str!("golden/event_hooks.list_help.txt"),
        "hooks.enable" => include_str!("golden/event_hooks.enable_help.txt"),
        "hooks.disable" => include_str!("golden/event_hooks.disable_help.txt"),
        _ => unreachable!(),
    }
}

/// The options each verb accepts (kept in step with `verb_args` in
/// src/handles/data/eventh.rs; a unit test there checks the usage text).
fn options(verb: &str) -> Vec<&'static str> {
    let mut v = match verb {
        "emit" => vec![
            "topic",
            "data",
            "source",
            "key",
            "correlation_id",
            "causation_id",
            "tags",
            "priority",
            "mode",
            "ttl_ms",
            "summarize",
            "schema_version",
            "format",
            "timeout_ms",
        ],
        "subscribe" => vec![
            "topic",
            "offset",
            "limit",
            "group_id",
            "consumer_id",
            "auto_commit",
            "manual_commit_offset",
            "wait",
            "wait_timeout_ms",
            "follow",
            "max_events",
            "timeout_ms",
            "match_tags",
            "match_correlation_id",
            "match_source",
            "max_latency_ms",
            "include_data",
            "include_summary",
            "include_raw",
            "format",
        ],
        "list-topics" => vec![
            "prefix",
            "match",
            "sources",
            "limit",
            "include_hidden",
            "include_stats",
            "include_schema",
            "format",
            "timeout_ms",
        ],
        "hooks.list" => vec![],
        "hooks.enable" | "hooks.disable" => vec!["name"],
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
fn help_example_output(verb: &str) -> Value {
    let body = golden(verb).split("\nExample Output:\n").nth(1).unwrap();
    let text: String = body
        .lines()
        .take_while(|l| !l.is_empty())
        .map(|l| l.strip_prefix("  ").unwrap_or(l))
        .collect::<Vec<_>>()
        .join("\n");
    json_of(&text)
}

/// The example command of a verb, split like a shell would (the examples
/// use single quotes only).
fn help_example_args(verb: &str) -> Vec<String> {
    let line = section(golden(verb), "Example").trim();
    let mut words = Vec::new();
    let (mut cur, mut quoted) = (String::new(), false);
    for c in line.chars() {
        match c {
            '\'' => quoted = !quoted,
            ' ' if !quoted => {
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    words.push(cur);
    assert_eq!(words.remove(0), "resh");
    words
}

/// Asserts that `actual` has the shape of `expected`: the same keys, with
/// equal values except ids and timestamps.
fn same_shape(expected: &Value, actual: &Value, path: &str) {
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => {
            let mut ek: Vec<&String> = e.keys().collect();
            let mut ak: Vec<&String> = a.keys().collect();
            ek.sort();
            ak.sort();
            assert_eq!(ek, ak, "keys at {path}");
            for (k, v) in e {
                same_shape(v, &a[k], &format!("{path}.{k}"));
            }
        }
        (Value::Array(e), Value::Array(a)) => {
            assert_eq!(e.len(), a.len(), "length at {path}");
            for (i, (x, y)) in e.iter().zip(a).enumerate() {
                same_shape(x, y, &format!("{path}[{i}]"));
            }
        }
        _ if path.ends_with(".id")
            || path.ends_with("timestamp_unix_ms")
            || path.ends_with("_unix_ms") =>
        {
            assert_eq!(
                std::mem::discriminant(expected),
                std::mem::discriminant(actual),
                "{path}"
            );
        }
        _ => assert_eq!(expected, actual, "value at {path}"),
    }
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
    for form in [
        vec!["event", "--help"],
        vec!["event", "-h"],
        vec!["event", "help"],
        vec!["help", "event"],
        vec!["event://--help"],
    ] {
        let (code, out, err) = run(tmp.path(), &form);
        assert_eq!((code, err.as_str()), (0, ""), "{form:?}");
        assert_eq!(out, golden("event"), "{form:?}");
    }
    let out = golden("event");
    assert_plain(out);
    let mut listed: Vec<&str> = section(out, "Available Verbs")
        .lines()
        .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    listed.sort();
    let mut verbs = VERBS.to_vec();
    verbs.sort();
    assert_eq!(listed, verbs);
    assert!(!store(tmp.path()).exists());
}

#[test]
fn verb_help_matches_golden_and_lists_accepted_options() {
    let tmp = TempDir::new().unwrap();
    for verb in VERBS {
        for form in [vec!["event", verb, "--help"], vec!["help", "event", verb]] {
            let (code, out, err) = run(tmp.path(), &form);
            assert_eq!((code, err.as_str()), (0, ""), "{form:?}");
            assert_eq!(out, golden(verb), "{form:?}");
        }
        let out = golden(verb);
        assert_plain(out);
        assert!(out.starts_with(&format!("Handle: event\nVerb: {verb}\nDefinition: ")));
        let usage = section(out, "Usage");
        assert!(
            usage.contains(&format!("event://.{verb}")),
            "{verb}: {usage}"
        );
        let mut listed: Vec<&str> = usage
            .split(|c: char| c == '[' || c.is_whitespace())
            .filter_map(|w| w.split_once('=').map(|(k, _)| k))
            .collect();
        listed.sort();
        assert_eq!(listed, options(verb), "{verb} usage options");
        // Every listed option is accepted by the verb.
        for opt in options(verb) {
            let (code, _, err) = run(
                tmp.path(),
                &[&format!("event://.{verb}"), &format!("{opt}=")],
            );
            assert!(!err.contains("unknown argument"), "{verb} {opt}: {err}");
            let _ = code;
        }
    }
}

#[test]
fn help_examples_run_and_match_their_documented_output() {
    let tmp = TempDir::new().unwrap();
    // emit (run first: the other examples read its event).
    let args = help_example_args("emit");
    let (code, out, err) = run(
        tmp.path(),
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_eq!(code, 0, "{err}");
    same_shape(&help_example_output("emit"), &json_of(&out), "");

    for verb in ["subscribe", "list-topics", "hooks.list"] {
        let args = help_example_args(verb);
        let (code, out, err) = run(
            tmp.path(),
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        assert_eq!(code, 0, "{verb}: {err}");
        same_shape(&help_example_output(verb), &json_of(&out), verb);
    }
    // hooks.disable then hooks.enable, as documented.
    for verb in ["hooks.disable", "hooks.enable"] {
        let args = help_example_args(verb);
        let (code, out, _) = run(
            tmp.path(),
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        assert_eq!(code, 0);
        assert_eq!(json_of(&out), help_example_output(verb), "{verb}");
    }
}
