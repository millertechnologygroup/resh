//! Dispatch tests: every verb is called through `Handle::call` on a store in
//! a temporary directory.

use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
    reason: String,
}

impl Out {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {}", self.stdout))
    }
    /// Asserts a coded failure: exit code, error code in the reason and, if
    /// the verb prints JSON, in the JSON error object.
    fn fails(&self, exit: i32, code: &str) {
        assert_eq!(self.code, exit, "{} / {}", self.reason, self.stdout);
        assert!(
            self.reason.starts_with(&format!("[{code}] ")),
            "expected {code}: {}",
            self.reason
        );
        if !self.stdout.is_empty() {
            let v = self.json();
            assert_eq!(v["ok"], json!(false));
            assert_eq!(v["error"]["code"], json!(code), "{}", self.stdout);
        }
    }
}

fn args(pairs: &[(&str, &str)]) -> Args {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn call(h: &EventHandle, verb: &str, pairs: &[(&str, &str)]) -> Out {
    let (mut i, mut o, mut e) = (
        std::io::Cursor::new(Vec::new()),
        Vec::<u8>::new(),
        Vec::<u8>::new(),
    );
    let st = {
        let mut io = IoStreams {
            stdin: &mut i,
            stdout: &mut o,
            stderr: &mut e,
        };
        h.call(verb, &args(pairs), &mut io).unwrap()
    };
    Out {
        code: st.exit_code(),
        stdout: String::from_utf8(o).unwrap(),
        stderr: String::from_utf8(e).unwrap(),
        reason: st.reason.unwrap_or_default(),
    }
}

fn base(dir: &TempDir) -> PathBuf {
    dir.path().join("state").join("resh").join("events")
}

fn handle(dir: &TempDir) -> EventHandle {
    EventHandle::new(Store::new(base(dir)))
}

fn emit(h: &EventHandle, topic: &str, data: &str) -> Value {
    let o = call(h, "emit", &[("topic", topic), ("data", data)]);
    assert_eq!(o.code, 0, "{} {}", o.reason, o.stdout);
    o.json()["event"].clone()
}

fn emit_with(h: &EventHandle, pairs: &[(&str, &str)]) -> Out {
    call(h, "emit", pairs)
}

fn sub(h: &EventHandle, pairs: &[(&str, &str)]) -> Value {
    let o = call(h, "subscribe", pairs);
    assert_eq!(o.code, 0, "{} {}", o.reason, o.stdout);
    o.json()
}

fn datas(v: &Value) -> Vec<Value> {
    v["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["data"].clone())
        .collect()
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

/// Holds `lock` of the store in `dir` (exclusively) until dropped.
fn hold_lock(dir: &TempDir, lock: &str) -> fs::File {
    fs::create_dir_all(base(dir)).unwrap();
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(base(dir).join(lock))
        .unwrap();
    use std::os::fd::AsRawFd;
    // SAFETY: flock on a file descriptor owned by `f`.
    assert_eq!(unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) }, 0);
    f
}

fn files(dir: &TempDir) -> Vec<String> {
    let mut v: Vec<String> = match fs::read_dir(base(dir)) {
        Ok(rd) => rd
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => Vec::new(),
    };
    v.sort();
    v
}

// --- emit ---------------------------------------------------------------------

#[test]
fn emit_stores_an_event_with_private_modes() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    let o = call(
        &h,
        "emit",
        &[
            ("topic", "jobs.backup.completed"),
            ("data", r#"{"status":"success"}"#),
        ],
    );
    assert_eq!((o.code, o.stderr.as_str()), (0, ""));
    let v = o.json();
    assert_eq!(v["ok"], json!(true));
    assert_eq!(v["error"], Value::Null);
    let e = &v["event"];
    assert_eq!(e["topic"], "jobs.backup.completed");
    assert_eq!(e["data"], json!({"status": "success"}));
    assert_eq!(e["backend"], "state_file");
    assert_eq!(e["mode"], "fire_and_forget");
    assert_eq!(e["priority"], "normal");
    assert!(e["id"].as_str().unwrap().starts_with("evt_"));
    assert!(e.get("seq").is_none() && e.get("offset").is_none());

    let b = base(&dir);
    assert_eq!(mode(&b), 0o700);
    assert_eq!(mode(&b.join("jobs.backup.completed.jsonl")), 0o600);
    assert_eq!(mode(&b.join("_store.lock")), 0o600);
    let line = fs::read_to_string(b.join("jobs.backup.completed.jsonl")).unwrap();
    assert_eq!(line.lines().count(), 1);
    let stored: EventEnvelope = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(stored.seq, Some(1));
    emit(&h, "other", "2");
    assert_eq!(
        fs::read_to_string(b.join("_store.lock")).unwrap(),
        format!("{:020}", 2)
    );
}

#[test]
fn emit_records_every_option() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    let o = emit_with(
        &h,
        &[
            ("topic", "deploy.finished"),
            ("data", r#"{"service":"api","version":"1.4.2"}"#),
            ("source", "ci"),
            ("key", "api"),
            ("correlation_id", "run-881"),
            ("causation_id", "evt-1"),
            ("tags", r#"["deploy","prod"]"#),
            ("priority", "high"),
            ("mode", "wait_for_persist"),
            ("ttl_ms", "60000"),
            ("summarize", "true"),
            ("schema_version", "v2"),
            ("timeout_ms", "5000"),
        ],
    );
    assert_eq!(o.code, 0, "{}", o.reason);
    let e = &o.json()["event"];
    assert_eq!(e["source"], "ci");
    assert_eq!(e["key"], "api");
    assert_eq!(e["correlation_id"], "run-881");
    assert_eq!(e["causation_id"], "evt-1");
    assert_eq!(e["tags"], json!(["deploy", "prod"]));
    assert_eq!(e["priority"], "high");
    assert_eq!(e["mode"], "wait_for_persist");
    assert_eq!(e["mode_used"], "wait_for_persist");
    assert_eq!(e["ttl_ms"], 60000);
    assert_eq!(e["schema_version"], "v2");
    assert_eq!(
        e["summary"],
        "Event 'deploy.finished' with 2 fields: service, version"
    );
    // The stored copy has the same fields.
    let r = sub(&h, &[("topic", "deploy.finished"), ("offset", "earliest")]);
    for k in [
        "source",
        "key",
        "correlation_id",
        "tags",
        "ttl_ms",
        "summary",
    ] {
        assert_eq!(r["events"][0][k], e[k], "{k}");
    }

    let o = emit_with(&h, &[("topic", "t"), ("data", "\"x\""), ("format", "text")]);
    assert_eq!(o.code, 0);
    assert!(o.stdout.starts_with("Event Emitted\n"), "{}", o.stdout);
    assert!(o.stdout.contains("Topic     : t\n"));
    // timeout_ms=0 means no limit.
    let o = emit_with(&h, &[("topic", "t"), ("data", "1"), ("timeout_ms", "0")]);
    assert_eq!(o.code, 0);
}

#[test]
fn emit_refuses_invalid_input_before_writing() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    let long_tag = format!(r#"["{}"]"#, "x".repeat(65));
    let cases: Vec<(Vec<(&str, &str)>, &str)> = vec![
        (vec![("data", "1")], "event.missing_argument"),
        (vec![("topic", "t")], "event.missing_argument"),
        (vec![("topic", ""), ("data", "1")], "event.invalid_topic"),
        (vec![("topic", "a b"), ("data", "1")], "event.invalid_topic"),
        (vec![("topic", " a"), ("data", "1")], "event.invalid_topic"),
        (vec![("topic", "a/b"), ("data", "1")], "event.invalid_topic"),
        (
            vec![("topic", "jobs.*"), ("data", "1")],
            "event.invalid_topic",
        ),
        (
            vec![("topic", "jobs.?"), ("data", "1")],
            "event.invalid_topic",
        ),
        (vec![("topic", "t"), ("data", "{")], "event.invalid_data"),
        (
            vec![("topic", "t"), ("data", "plain")],
            "event.invalid_data",
        ),
        (
            vec![("topic", "t"), ("data", "1"), ("tags", "deploy")],
            "event.invalid_tags",
        ),
        (
            vec![("topic", "t"), ("data", "1"), ("tags", r#"[""]"#)],
            "event.invalid_tags",
        ),
        (
            vec![("topic", "t"), ("data", "1"), ("tags", &long_tag)],
            "event.invalid_tags",
        ),
        (
            vec![("topic", "t"), ("data", "1"), ("tags", "[\"a\u{e9}\"]")],
            "event.invalid_tags",
        ),
        (
            vec![("topic", "t"), ("data", "1"), ("priority", "urgent")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("data", "1"), ("mode", "sync")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("data", "1"), ("ttl_ms", "0")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("data", "1"), ("ttl_ms", "soon")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("data", "1"), ("summarize", "maybe")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("data", "1"), ("format", "yaml")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("data", "1"), ("timeout_ms", "-1")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("data", "1"), ("source", "")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("data", "1"), ("tgas", "[]")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("data", "1"), ("dry_run", "true")],
            "event.invalid_argument",
        ),
    ];
    for (pairs, code) in cases {
        let o = emit_with(&h, &pairs);
        o.fails(2, code);
        assert!(o.stdout.contains("\"event\": null"), "{pairs:?}");
    }
    assert!(files(&dir).is_empty(), "nothing may be written");

    let o = emit_with(&h, &[("topic", "t"), ("data", "1"), ("tgas", "[]")]);
    assert!(o.reason.contains("did you mean `tags`?"), "{}", o.reason);
    let o = emit_with(&h, &[("topic", "t"), ("data", "1"), ("dry_run", "false")]);
    assert_eq!(o.code, 0);
    // A failure with format=text prints nothing on stdout.
    let o = emit_with(&h, &[("topic", "t"), ("data", "{"), ("format", "text")]);
    assert_eq!((o.code, o.stdout.as_str()), (2, ""));
}

#[test]
fn emit_store_failures() {
    // No state directory.
    let h = EventHandle {
        store: None,
        target_error: None,
    };
    call(&h, "emit", &[("topic", "t"), ("data", "1")]).fails(1, "event.store_unavailable");

    // The store path is a file.
    let dir = TempDir::new().unwrap();
    fs::create_dir_all(base(&dir).parent().unwrap()).unwrap();
    fs::write(base(&dir), "x").unwrap();
    let h = handle(&dir);
    call(&h, "emit", &[("topic", "t"), ("data", "1")]).fails(1, "event.store_unavailable");

    // A symlink planted at the topic file is not followed.
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    emit(&h, "seed", "0");
    let victim = dir.path().join("victim");
    fs::write(&victim, "keep").unwrap();
    std::os::unix::fs::symlink(&victim, base(&dir).join("t.jsonl")).unwrap();
    let o = call(&h, "emit", &[("topic", "t"), ("data", "1")]);
    o.fails(1, "event.store_error");
    assert!(o.reason.contains("symlink"), "{}", o.reason);
    assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");

    // A corrupt sequence counter.
    fs::write(base(&dir).join("_store.lock"), "garbage").unwrap();
    call(&h, "emit", &[("topic", "u"), ("data", "1")]).fails(1, "event.store_corrupt");
    assert!(!base(&dir).join("u.jsonl").exists());
}

#[test]
fn emit_times_out_waiting_for_the_store_lock() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    let lock = hold_lock(&dir, "_store.lock");
    let started = Instant::now();
    let o = call(
        &h,
        "emit",
        &[("topic", "t"), ("data", "1"), ("timeout_ms", "200")],
    );
    o.fails(124, "event.timeout");
    assert!(started.elapsed() >= Duration::from_millis(200));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(!base(&dir).join("t.jsonl").exists(), "nothing written");
    drop(lock);
    emit(&h, "t", "1");
}

#[test]
fn subscribe_reads_by_offset_and_pattern() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    emit(&h, "jobs.backup.completed", r#"{"status":"success"}"#);
    emit(&h, "jobs.backup.failed", r#"{"status":"error"}"#);
    emit(&h, "other.topic", "1");

    // A separate handle (as in a later resh command) sees the events.
    let b = handle(&dir);
    let r = sub(
        &b,
        &[("topic", "jobs.backup.completed"), ("offset", "earliest")],
    );
    assert_eq!(r["events_returned"], 1);
    assert_eq!(datas(&r), [json!({"status": "success"})]);

    let r = sub(&b, &[("topic", "jobs.*"), ("offset", "earliest")]);
    assert_eq!(r["events_returned"], 2);
    assert_eq!(r["high_watermark"], "2");
    assert_eq!(r["offset_start"], "0");
    assert_eq!(r["offset_end"], "1");
    assert_eq!(r["next_offset"], "2");
    assert_eq!(r["effective_offset"], "earliest");
    assert_eq!(r["timed_out"], false);
    assert_eq!(r["events"][1]["offset"], "1");

    // ? matches one character; * any run.
    let r = sub(
        &b,
        &[("topic", "jobs.backup.f?iled"), ("offset", "earliest")],
    );
    assert_eq!(r["events_returned"], 1);
    let r = sub(&b, &[("topic", "*"), ("offset", "earliest")]);
    assert_eq!(r["events_returned"], 3);

    // Default offset=latest returns only new events.
    let r = sub(&b, &[("topic", "jobs.*")]);
    assert_eq!(
        (r["events_returned"].clone(), r["effective_offset"].clone()),
        (json!(0), json!("latest"))
    );
    assert_eq!(r["next_offset"], "2");

    // limit and explicit offsets, including one past the end.
    let r = sub(&b, &[("topic", "jobs.*"), ("offset", "1"), ("limit", "5")]);
    assert_eq!(r["events_returned"], 1);
    assert_eq!(r["events"][0]["topic"], "jobs.backup.failed");
    assert_eq!(r["effective_offset"], "1");
    let r = sub(
        &b,
        &[("topic", "jobs.*"), ("offset", "earliest"), ("limit", "1")],
    );
    assert_eq!(
        (r["events_returned"].clone(), r["next_offset"].clone()),
        (json!(1), json!("1"))
    );
    let r = sub(&b, &[("topic", "jobs.*"), ("offset", "99")]);
    assert_eq!(r["events_returned"], 0);
    assert_eq!(r["next_offset"], "2");

    // A missing store is empty and is not created.
    let empty = TempDir::new().unwrap();
    let r = sub(&handle(&empty), &[("topic", "x"), ("offset", "earliest")]);
    assert_eq!(r["events_returned"], 0);
    assert!(!base(&empty).exists());
}

#[test]
fn subscribe_orders_events_by_store_sequence_across_topics() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    // Events from before sequence numbers come first, by time.
    fs::create_dir_all(base(&dir)).unwrap();
    let legacy = |topic: &str, ts: i64, data: i64| {
        json!({"id": format!("old{data}"), "topic": topic, "timestamp_unix_ms": ts,
            "mode": "fire_and_forget", "mode_used": "fire_and_forget", "priority": "normal",
            "ttl_ms": null, "key": null, "correlation_id": null, "causation_id": null,
            "source": null, "tags": [], "schema_version": null, "data": data,
            "summary": null, "backend": "state_file", "offset": null, "raw": null})
        .to_string()
    };
    fs::write(
        base(&dir).join("q.b.jsonl"),
        format!("{}\n", legacy("q.b", 100, 0)),
    )
    .unwrap();
    fs::write(
        base(&dir).join("q.a.jsonl"),
        format!("{}\nnot json\n", legacy("q.a", 200, 1)),
    )
    .unwrap();
    // New events: z first, then a; the order is the order they were stored,
    // whatever their topic names or clocks.
    emit(&h, "q.z", "2");
    emit(&h, "q.a", "3");
    emit(&h, "q.b", "4");
    let r = sub(&h, &[("topic", "q.*"), ("offset", "earliest")]);
    assert_eq!(
        datas(&r),
        [json!(0), json!(1), json!(2), json!(3), json!(4)]
    );
    assert_eq!(
        r["warnings"],
        json!(["1 stored line(s) could not be parsed and were skipped"])
    );
}

#[test]
fn subscribe_consumer_groups_commit_and_resume() {
    let dir = TempDir::new().unwrap();
    let a = handle(&dir);
    for n in 0..3 {
        emit(&a, "q.work", &n.to_string());
    }
    let group = [
        ("topic", "q.work"),
        ("offset", "next"),
        ("group_id", "g1"),
        ("limit", "2"),
        ("consumer_id", "c1"),
    ];
    let r = sub(&handle(&dir), &group);
    assert_eq!(datas(&r), [json!(0), json!(1)]);
    assert_eq!(r["committed"], true);
    assert_eq!(r["committed_offset"], "2");
    assert_eq!(r["group_id"], "g1");
    assert_eq!(r["consumer_id"], "c1");
    assert_eq!(mode(&base(&dir).join("_offsets.json")), 0o600);
    let r = sub(&handle(&dir), &group);
    assert_eq!(datas(&r), [json!(2)]);
    let r = sub(&handle(&dir), &group);
    assert_eq!(r["events_returned"], 0);
    assert_eq!(r["committed"], false);

    // Another group starts from 0; auto_commit=false does not move it.
    let mut g2 = group.to_vec();
    g2[2] = ("group_id", "g2");
    g2.push(("auto_commit", "false"));
    let r = sub(&a, &g2);
    assert_eq!(datas(&r), [json!(0), json!(1)]);
    assert_eq!(r["committed"], false);
    let r = sub(&a, &g2);
    assert_eq!(datas(&r), [json!(0), json!(1)]);

    // manual_commit_offset commits and reads nothing.
    let r = sub(
        &a,
        &[
            ("topic", "q.work"),
            ("group_id", "g2"),
            ("manual_commit_offset", "2"),
        ],
    );
    assert_eq!(r["effective_offset"], "commit");
    assert_eq!(
        (r["committed"].clone(), r["committed_offset"].clone()),
        (json!(true), json!("2"))
    );
    assert_eq!(r["events_returned"], 0);
    let r = sub(&a, &g2);
    assert_eq!(datas(&r), [json!(2)]);
    let offsets: Value =
        serde_json::from_str(&fs::read_to_string(base(&dir).join("_offsets.json")).unwrap())
            .unwrap();
    assert_eq!(offsets, json!({"g1:q.work": 3, "g2:q.work": 2}));
}

#[test]
fn subscribe_group_skips_past_filtered_events() {
    // A window with no matching events must still advance the group, or the
    // group would read the same window forever.
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    for n in 0..5 {
        emit(&h, "f", &n.to_string());
    }
    emit_with(&h, &[("topic", "f"), ("data", "99"), ("source", "wanted")]);
    let q = [
        ("topic", "f"),
        ("offset", "next"),
        ("group_id", "g"),
        ("limit", "2"),
        ("match_source", "wanted"),
    ];
    let r = sub(&h, &q);
    assert_eq!(datas(&r), [json!(99)]);
    assert_eq!(r["next_offset"], "6");
    assert_eq!(r["committed_offset"], "6");
    assert_eq!(r["offset_start"], "5");
}

#[test]
fn subscribe_filters_and_include_options() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    emit_with(
        &h,
        &[
            ("topic", "f"),
            ("data", "1"),
            ("tags", r#"["a","b"]"#),
            ("correlation_id", "c1"),
            ("source", "s1"),
            ("summarize", "true"),
        ],
    );
    emit_with(&h, &[("topic", "f"), ("data", "2"), ("tags", r#"["a"]"#)]);
    let all = [("topic", "f"), ("offset", "earliest")];
    let with = |extra: &[(&str, &str)]| {
        let mut v = all.to_vec();
        v.extend_from_slice(extra);
        sub(&h, &v)
    };
    assert_eq!(datas(&with(&[("match_tags", r#"["a"]"#)])).len(), 2);
    assert_eq!(datas(&with(&[("match_tags", r#"["a","b"]"#)])), [json!(1)]);
    assert_eq!(datas(&with(&[("match_correlation_id", "c1")])), [json!(1)]);
    assert_eq!(datas(&with(&[("match_source", "s1")])), [json!(1)]);
    assert_eq!(datas(&with(&[("match_source", "nope")])).len(), 0);
    assert_eq!(datas(&with(&[("max_latency_ms", "60000")])).len(), 2);

    let r = with(&[("include_data", "false"), ("include_summary", "false")]);
    assert_eq!(r["events"][0]["data"], Value::Null);
    assert_eq!(r["events"][0]["summary"], Value::Null);
    let r = with(&[]);
    assert_eq!(r["events"][0]["summary"], "Event 'f' emitted");
    assert_eq!(r["events"][0]["raw"], Value::Null);
    let r = with(&[("include_raw", "true")]);
    let raw = &r["events"][0]["raw"];
    assert_eq!(raw["seq"], 1);
    assert_eq!(raw["data"], 1);
    assert!(raw.get("offset").is_none());

    let o = call(
        &h,
        "subscribe",
        &[("topic", "f"), ("offset", "earliest"), ("format", "text")],
    );
    assert_eq!(o.code, 0);
    assert!(
        o.stdout.starts_with("Event Subscription Result\n"),
        "{}",
        o.stdout
    );
    assert!(o.stdout.contains("Returned    : 2 event(s)\n"));
    assert!(o.stdout.contains("[0] f @ "), "{}", o.stdout);
}

#[test]
fn subscribe_skips_events_whose_ttl_has_passed() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    emit_with(&h, &[("topic", "t"), ("data", "1"), ("ttl_ms", "1")]);
    emit_with(&h, &[("topic", "t"), ("data", "2"), ("ttl_ms", "600000")]);
    std::thread::sleep(Duration::from_millis(20));
    let r = sub(&h, &[("topic", "t"), ("offset", "earliest")]);
    assert_eq!(datas(&r), [json!(2)]);
    assert_eq!(r["high_watermark"], "2");
}

#[test]
fn subscribe_wait_times_out_and_honors_timeout_ms() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    let started = Instant::now();
    let r = sub(
        &h,
        &[
            ("topic", "none"),
            ("wait", "true"),
            ("wait_timeout_ms", "250"),
        ],
    );
    assert_eq!(r["timed_out"], true);
    assert_eq!(r["events_returned"], 0);
    assert!(started.elapsed() >= Duration::from_millis(250));

    // timeout_ms shorter than wait_timeout_ms ends the wait.
    let started = Instant::now();
    let r = sub(
        &h,
        &[
            ("topic", "none"),
            ("wait", "true"),
            ("wait_timeout_ms", "60000"),
            ("timeout_ms", "300"),
        ],
    );
    assert_eq!(r["timed_out"], true);
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(300) && took < Duration::from_secs(5),
        "{took:?}"
    );

    // Without wait the result is immediate and not timed out.
    let r = sub(&h, &[("topic", "none")]);
    assert_eq!(r["timed_out"], false);
}

#[test]
fn subscribe_wait_returns_an_event_emitted_meanwhile() {
    let dir = TempDir::new().unwrap();
    let path = base(&dir);
    let emitter = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        let h = EventHandle::new(Store::new(path));
        emit(&h, "late.topic", r#""hello""#);
    });
    let h = handle(&dir);
    let started = Instant::now();
    let r = sub(
        &h,
        &[
            ("topic", "late.*"),
            ("wait", "true"),
            ("wait_timeout_ms", "10000"),
        ],
    );
    emitter.join().unwrap();
    assert_eq!(datas(&r), [json!("hello")]);
    assert_eq!(r["timed_out"], false);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn subscribe_follow_prints_lines_until_max_events_or_timeout() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    emit(&h, "f.a", "0");
    let path = base(&dir);
    let emitter = std::thread::spawn(move || {
        let h = EventHandle::new(Store::new(path));
        for n in 1..=3 {
            std::thread::sleep(Duration::from_millis(100));
            emit(&h, "f.b", &n.to_string());
        }
    });
    let o = call(
        &h,
        "subscribe",
        &[
            ("topic", "f.*"),
            ("offset", "earliest"),
            ("follow", "true"),
            ("max_events", "4"),
            ("timeout_ms", "20000"),
            ("group_id", "fg"),
        ],
    );
    emitter.join().unwrap();
    assert_eq!(o.code, 0, "{}", o.reason);
    let lines: Vec<Value> = o
        .stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let got: Vec<Value> = lines.iter().map(|e| e["data"].clone()).collect();
    assert_eq!(got, [json!(0), json!(1), json!(2), json!(3)]);
    assert_eq!(lines[0]["offset"], "0");
    // The group committed what was printed.
    let r = sub(
        &h,
        &[("topic", "f.*"), ("offset", "next"), ("group_id", "fg")],
    );
    assert_eq!(r["events_returned"], 0);
    assert_eq!(r["next_offset"], "4");

    // timeout_ms ends a follow normally; text format is one line per event.
    let started = Instant::now();
    let o = call(
        &h,
        "subscribe",
        &[
            ("topic", "f.*"),
            ("offset", "earliest"),
            ("follow", "true"),
            ("timeout_ms", "300"),
            ("format", "text"),
            ("limit", "1"),
        ],
    );
    assert_eq!(o.code, 0, "{}", o.reason);
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert_eq!(o.stdout.lines().count(), 4, "{}", o.stdout);
    assert!(o.stdout.starts_with("[0] f.a @ "), "{}", o.stdout);
}

#[test]
fn subscribe_refuses_invalid_input() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    let cases: Vec<(Vec<(&str, &str)>, &str)> = vec![
        (vec![], "event.missing_argument"),
        (vec![("topic", "a b")], "event.invalid_topic"),
        (
            vec![("topic", "t"), ("offset", "next")],
            "event.missing_argument",
        ),
        (
            vec![("topic", "t"), ("offset", "first")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("offset", "-1")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("limit", "0")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("limit", "10001")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("wait", "yes please")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("wait_timeout_ms", "10")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("wait", "true"), ("wait_timeout_ms", "0")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("max_events", "1")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("follow", "true"), ("wait", "true")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("auto_commit", "false")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("manual_commit_offset", "1")],
            "event.missing_argument",
        ),
        (
            vec![
                ("topic", "t"),
                ("group_id", "g"),
                ("manual_commit_offset", "1"),
                ("offset", "earliest"),
            ],
            "event.invalid_argument",
        ),
        (
            vec![
                ("topic", "t"),
                ("group_id", "g"),
                ("manual_commit_offset", "x"),
            ],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("group_id", "")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("match_tags", "a")],
            "event.invalid_tags",
        ),
        (
            vec![("topic", "t"), ("max_latency_ms", "0")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("include_raw", "2")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("format", "xml")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("timeout_ms", "x")],
            "event.invalid_argument",
        ),
        (
            vec![("topic", "t"), ("group", "g")],
            "event.invalid_argument",
        ),
    ];
    for (pairs, code) in cases {
        call(&h, "subscribe", &pairs).fails(2, code);
    }
    let o = call(&h, "subscribe", &[("topic", "t"), ("group", "g")]);
    assert!(
        o.reason.contains("did you mean `group_id`?"),
        "{}",
        o.reason
    );
    assert!(files(&dir).is_empty());
}

#[test]
fn subscribe_store_failures() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    emit(&h, "t", "1");
    // A corrupt offsets file is reported, not silently reset.
    fs::write(base(&dir).join("_offsets.json"), "{").unwrap();
    call(
        &h,
        "subscribe",
        &[("topic", "t"), ("offset", "next"), ("group_id", "g")],
    )
    .fails(1, "event.store_corrupt");
    fs::remove_file(base(&dir).join("_offsets.json")).unwrap();

    // A symlink at the offsets file is not written through.
    let victim = dir.path().join("victim");
    fs::write(&victim, "keep").unwrap();
    std::os::unix::fs::symlink(&victim, base(&dir).join("_offsets.json")).unwrap();
    call(
        &h,
        "subscribe",
        &[
            ("topic", "t"),
            ("group_id", "g"),
            ("manual_commit_offset", "1"),
        ],
    )
    .fails(1, "event.store_corrupt");
    assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
    fs::write(&victim, "{}").unwrap();
    let o = call(
        &h,
        "subscribe",
        &[
            ("topic", "t"),
            ("group_id", "g"),
            ("manual_commit_offset", "1"),
        ],
    );
    o.fails(1, "event.store_error");
    assert!(o.reason.contains("symlink"), "{}", o.reason);
    assert_eq!(fs::read_to_string(&victim).unwrap(), "{}");
    fs::remove_file(base(&dir).join("_offsets.json")).unwrap();

    // A group read waits for the offsets lock at most timeout_ms.
    let lock = hold_lock(&dir, "_offsets.lock");
    let started = Instant::now();
    let o = call(
        &h,
        "subscribe",
        &[
            ("topic", "t"),
            ("offset", "next"),
            ("group_id", "g"),
            ("timeout_ms", "200"),
        ],
    );
    o.fails(124, "event.timeout");
    assert_eq!(o.json()["timed_out"], true);
    assert!(started.elapsed() < Duration::from_secs(5));
    // A read without a group does not need that lock.
    sub(&h, &[("topic", "t"), ("offset", "earliest")]);
    drop(lock);
    // A reader waits for the store lock at most timeout_ms.
    let lock = hold_lock(&dir, "_store.lock");
    call(
        &h,
        "subscribe",
        &[
            ("topic", "t"),
            ("offset", "earliest"),
            ("timeout_ms", "200"),
        ],
    )
    .fails(124, "event.timeout");
    drop(lock);

    let h = EventHandle {
        store: None,
        target_error: None,
    };
    call(&h, "subscribe", &[("topic", "t")]).fails(1, "event.store_unavailable");
}

#[test]
fn group_consumers_in_parallel_never_share_an_event() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    for n in 0..60 {
        emit(&h, if n % 2 == 0 { "p.a" } else { "p.b" }, &n.to_string());
    }
    let workers: Vec<_> = (0..3)
        .map(|_| {
            let path = base(&dir);
            std::thread::spawn(move || {
                let h = EventHandle::new(Store::new(path));
                let mut got = Vec::new();
                loop {
                    let r = sub(
                        &h,
                        &[
                            ("topic", "p.*"),
                            ("offset", "next"),
                            ("group_id", "workers"),
                            ("limit", "3"),
                        ],
                    );
                    if r["events_returned"] == 0 {
                        return got;
                    }
                    got.extend(datas(&r).into_iter().map(|d| d.as_i64().unwrap()));
                }
            })
        })
        .collect();
    let mut all: Vec<i64> = workers
        .into_iter()
        .flat_map(|w| w.join().unwrap())
        .collect();
    all.sort();
    assert_eq!(all, (0..60).collect::<Vec<_>>());
}

// --- list-topics --------------------------------------------------------------

#[test]
fn list_topics_lists_the_store() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    // An empty store lists nothing and creates nothing.
    let o = call(&h, "list-topics", &[]);
    assert_eq!(o.code, 0);
    assert_eq!(o.json()["topics"], json!([]));
    assert!(!base(&dir).exists());

    emit_with(
        &h,
        &[
            ("topic", "jobs.backup.completed"),
            ("data", r#"{"status":"success","ms":5}"#),
            ("tags", r#"["b","a"]"#),
            ("schema_version", "v1"),
        ],
    );
    emit(&h, "jobs.backup.completed", r#"{"status":"error"}"#);
    emit_with(&h, &[("topic", "jobs.old"), ("data", "1"), ("ttl_ms", "1")]);
    emit(&h, "Deploy", "1");
    emit(&h, "_internal", "1");
    std::thread::sleep(Duration::from_millis(10));

    let v = call(&h, "list-topics", &[]).json();
    let names: Vec<&str> = v["topics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Deploy", "jobs.backup.completed", "jobs.old"]);
    assert_eq!(v["filters"]["sources"], json!(["event"]));
    let t = &v["topics"][1];
    assert_eq!(t["category"], "jobs");
    assert_eq!(t["tags"], json!(["a", "b"]));
    assert_eq!(t["stats"], Value::Null);
    assert_eq!(t["schema"], Value::Null);
    assert_eq!(t["backends"][0]["id"], "event:jobs.backup.completed");
    assert_eq!(v["topics"][0]["category"], Value::Null);

    let v = call(
        &h,
        "list-topics",
        &[
            ("prefix", "jobs."),
            ("include_stats", "true"),
            ("include_schema", "true"),
        ],
    )
    .json();
    let t = &v["topics"][0];
    assert_eq!(t["stats"]["approx_message_count"], 2);
    assert!(
        t["stats"]["last_event_unix_ms"].as_i64().unwrap()
            >= t["first_seen_unix_ms"].as_i64().unwrap()
    );
    assert_eq!(t["schema"]["example"], json!({"status": "error"}));
    assert_eq!(t["schema"]["schema_version"], Value::Null);
    assert_eq!(
        t["schema"]["fields"],
        json!([{"name": "status", "type": "string", "required": true}])
    );
    // Expired events are not counted.
    assert_eq!(v["topics"][1]["stats"]["approx_message_count"], 0);

    let v = call(&h, "list-topics", &[("match", "DEPLOY")]).json();
    assert_eq!(v["topics_total"], 1);
    let v = call(&h, "list-topics", &[("include_hidden", "true")]).json();
    assert_eq!(v["topics_total"], 4);
    assert_eq!(v["topics"][1]["name"], "_internal");
    assert_eq!(v["topics"][1]["is_hidden"], true);
    assert_eq!(v["topics"][0]["is_hidden"], false);
    let v = call(&h, "list-topics", &[("limit", "1"), ("sources", "event")]).json();
    assert_eq!(
        (
            v["topics_returned"].clone(),
            v["topics_total"].clone(),
            v["truncated"].clone()
        ),
        (json!(1), json!(3), json!(true))
    );
    assert_eq!(v["warnings"].as_array().unwrap().len(), 1);
    let v = call(&h, "list-topics", &[("sources", r#"["event"]"#)]).json();
    assert_eq!(v["topics_total"], 3);

    let o = call(
        &h,
        "list-topics",
        &[("format", "text"), ("include_stats", "true")],
    );
    assert!(o.stdout.starts_with("Event Topics\n"), "{}", o.stdout);
    assert!(
        o.stdout
            .contains("  jobs.backup.completed  events=2  last="),
        "{}",
        o.stdout
    );
}

#[test]
fn list_topics_errors() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    for pairs in [
        vec![("sources", "mq")],
        vec![("sources", "event,log")],
        vec![("sources", "nope")],
        vec![("sources", "[1]")],
        vec![("limit", "0")],
        vec![("include_stats", "y")],
        vec![("prefix", "")],
        vec![("format", "csv")],
        vec![("verbose", "true")],
        vec![("timeout_ms", "x")],
    ] {
        call(&h, "list-topics", &pairs).fails(2, "event.invalid_argument");
    }
    let o = call(&h, "list-topics", &[("sources", "mq")]);
    assert!(
        o.reason.contains("lists only the event store"),
        "{}",
        o.reason
    );

    emit(&h, "t", "1");
    let lock = hold_lock(&dir, "_store.lock");
    call(&h, "list-topics", &[("timeout_ms", "200")]).fails(124, "event.timeout");
    drop(lock);
    let h = EventHandle {
        store: None,
        target_error: None,
    };
    call(&h, "list-topics", &[]).fails(1, "event.store_unavailable");
}

// --- hooks --------------------------------------------------------------------

fn enable(h: &EventHandle, name: &str) {
    let o = call(h, "hooks.enable", &[("name", name)]);
    assert_eq!(o.code, 0, "{}", o.reason);
}

fn hooks_of(o: &Out) -> Value {
    o.json()["hooks"].clone()
}

fn mq_messages(dir: &TempDir, queue: &str) -> Vec<String> {
    let q = dir.path().join("state").join("resh").join("mq").join(queue);
    let mut names: Vec<PathBuf> = fs::read_dir(&q)
        .map(|rd| {
            rd.map(|e| e.unwrap().path())
                .filter(|p| p.extension().is_some_and(|x| x == "msg"))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
        .iter()
        .map(|p| fs::read_to_string(p).unwrap())
        .collect()
}

#[test]
fn hooks_are_off_by_default_and_persist_across_handles() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    let o = call(&h, "hooks.list", &[]);
    assert_eq!(
        o.stdout,
        "{\"disabled\":[\"fs\",\"log\",\"mq\"],\"global_hooks\":[],\"instance_hooks\":[],\"total\":0}\n"
    );
    assert!(!base(&dir).exists(), "hooks.list creates nothing");
    // Without enabled hooks emit runs none and writes nothing else.
    let o = emit_with(&h, &[("topic", "t"), ("data", "1")]);
    assert_eq!(hooks_of(&o), json!([]));
    assert_eq!(o.stderr, "");
    assert!(!base(&dir).join("hooks").exists());
    assert!(mq_messages(&dir, "t").is_empty());

    let o = call(&h, "hooks.enable", &[("name", "mq")]);
    assert_eq!(
        o.stdout,
        "{\"changed\":true,\"enabled\":true,\"hook\":\"mq\"}\n"
    );
    let o = call(&handle(&dir), "hooks.enable", &[("name", "mq")]);
    assert_eq!(
        o.stdout,
        "{\"changed\":false,\"enabled\":true,\"hook\":\"mq\"}\n"
    );
    assert_eq!(mode(&base(&dir).join("_hooks.json")), 0o600);

    // A later handle (a later resh command) sees the state.
    let later = handle(&dir);
    let v = call(&later, "hooks.list", &[]).json();
    assert_eq!(v["global_hooks"], json!(["mq"]));
    assert_eq!(v["disabled"], json!(["fs", "log"]));
    assert_eq!(v["total"], 1);

    let o = call(&later, "hooks.disable", &[("name", "mq")]);
    assert_eq!(
        o.stdout,
        "{\"changed\":true,\"disabled\":true,\"hook\":\"mq\"}\n"
    );
    let o = call(&later, "hooks.disable", &[("name", "mq")]);
    assert_eq!(
        o.stdout,
        "{\"changed\":false,\"disabled\":true,\"hook\":\"mq\"}\n"
    );
    assert_eq!(call(&later, "hooks.list", &[]).json()["total"], 0);
}

#[test]
fn old_hook_state_files_are_migrated_silently() {
    let dir = TempDir::new().unwrap();
    fs::create_dir_all(base(&dir)).unwrap();
    fs::write(
        base(&dir).join("_hooks.json"),
        r#"{"disabled":["proc","mq"]}"#,
    )
    .unwrap();
    let h = handle(&dir);
    let v = call(&h, "hooks.list", &[]).json();
    assert_eq!(v["global_hooks"], json!([]));
    assert_eq!(v["disabled"], json!(["fs", "log", "mq"]));
    enable(&h, "fs");
    let state: Value =
        serde_json::from_str(&fs::read_to_string(base(&dir).join("_hooks.json")).unwrap()).unwrap();
    assert_eq!(state, json!({"enabled": ["fs"], "disabled": ["mq"]}));
}

#[test]
fn log_hook_appends_each_event_as_a_json_line() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    enable(&h, "log");
    let o = emit_with(&h, &[("topic", "jobs.done"), ("data", r#"{"n":1}"#)]);
    assert_eq!(o.code, 0);
    assert_eq!(
        hooks_of(&o),
        json!([{"name": "log", "ok": true, "warning": null}])
    );
    assert_eq!(o.json()["warnings"], json!([]));
    emit(&h, "jobs.done", r#"{"n":2}"#);
    let path = hooks::log_path(&Store::new(base(&dir)), "jobs.done");
    let text = fs::read_to_string(&path).unwrap();
    let lines: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[1]["data"], json!({"n": 2}));
    assert_eq!(lines[1]["seq"], 2);
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&base(&dir).join("hooks")), 0o700);
    assert_eq!(mode(path.parent().unwrap()), 0o700);
}

#[test]
fn fs_hook_keeps_the_latest_event_per_topic() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    enable(&h, "fs");
    for n in 1..=3 {
        let o = emit_with(&h, &[("topic", "state.x"), ("data", &n.to_string())]);
        assert_eq!(
            hooks_of(&o),
            json!([{"name": "fs", "ok": true, "warning": null}])
        );
    }
    let path = hooks::fs_path(&Store::new(base(&dir)), "state.x");
    let v: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(v["data"], 3);
    assert_eq!(v["topic"], "state.x");
    assert_eq!(mode(&path), 0o600);
}

#[test]
fn mq_hook_queues_the_data_on_the_topic_queue() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    enable(&h, "mq");
    let o = emit_with(
        &h,
        &[
            ("topic", "orders.new"),
            ("data", r#"{"id": 7}"#),
            ("tags", r#"["shop"]"#),
            ("ttl_ms", "60000"),
        ],
    );
    assert_eq!(
        hooks_of(&o),
        json!([{"name": "mq", "ok": true, "warning": null}])
    );
    // The message is the whole stored event: the same line the log hook
    // writes.
    let msgs = mq_messages(&dir, "orders.new");
    assert_eq!(msgs.len(), 1);
    let m: Value = serde_json::from_str(&msgs[0]).unwrap();
    let e = &o.json()["event"];
    assert_eq!(m["data"], json!({"id": 7}));
    assert_eq!(m["topic"], "orders.new");
    assert_eq!(m["seq"], 1);
    assert_eq!(m["id"], e["id"]);
    assert_eq!(m["timestamp_unix_ms"], e["timestamp_unix_ms"]);
    assert_eq!(m["tags"], json!(["shop"]));
    assert_eq!(m["ttl_ms"], 60000);
    let stored = fs::read_to_string(base(&dir).join("orders.new.jsonl")).unwrap();
    assert_eq!(msgs[0], stored.trim_end());

    // A topic that is not a valid queue name is skipped with a warning.
    let o = emit_with(&h, &[("topic", "a:b"), ("data", "1")]);
    assert_eq!(o.code, 0);
    let r = &hooks_of(&o)[0];
    assert_eq!(r["ok"], false);
    assert!(
        r["warning"]
            .as_str()
            .unwrap()
            .contains("invalid queue name"),
        "{r}"
    );
    assert!(
        o.stderr.starts_with("Warning: mq hook: not forwarded"),
        "{}",
        o.stderr
    );
    assert_eq!(o.json()["warnings"].as_array().unwrap().len(), 1);
}

#[test]
fn hook_failures_are_warnings_and_symlinks_are_refused() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    for name in ["fs", "log", "mq"] {
        enable(&h, name);
    }
    let victim = dir.path().join("victim");
    fs::write(&victim, "keep").unwrap();
    fs::create_dir_all(base(&dir).join("hooks").join("log")).unwrap();
    std::os::unix::fs::symlink(&victim, base(&dir).join("hooks/log/t.log")).unwrap();
    std::os::unix::fs::symlink(dir.path(), base(&dir).join("hooks/fs")).unwrap();
    let o = emit_with(&h, &[("topic", "t"), ("data", "1")]);
    assert_eq!(o.code, 0, "{}", o.reason);
    let r = hooks_of(&o);
    assert_eq!(r[0]["name"], "fs");
    assert_eq!(r[0]["ok"], false);
    assert!(r[0]["warning"].as_str().unwrap().contains("symlink"), "{r}");
    assert_eq!(r[1]["name"], "log");
    assert_eq!(r[1]["ok"], false);
    assert!(r[1]["warning"].as_str().unwrap().contains("symlink"), "{r}");
    assert_eq!(r[2], json!({"name": "mq", "ok": true, "warning": null}));
    assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
    assert!(!dir.path().join("t.json").exists());
    // The event itself was stored.
    let s = sub(&h, &[("topic", "t"), ("offset", "earliest")]);
    assert_eq!(s["events_returned"], 1);
}

#[test]
fn hooks_respect_timeout_ms() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    enable(&h, "fs");
    emit(&h, "t", "0");
    let lock = hold_lock_at(&base(&dir).join("hooks").join("fs").join(".lock"));
    let started = Instant::now();
    let o = emit_with(&h, &[("topic", "t"), ("data", "1"), ("timeout_ms", "300")]);
    assert_eq!(o.code, 0);
    assert!(started.elapsed() < Duration::from_secs(5));
    let r = &hooks_of(&o)[0];
    assert_eq!(r["ok"], false);
    assert!(
        r["warning"].as_str().unwrap().contains("timeout_ms passed"),
        "{r}"
    );
    drop(lock);
}

fn hold_lock_at(path: &Path) -> fs::File {
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .unwrap();
    use std::os::fd::AsRawFd;
    // SAFETY: flock on a file descriptor owned by `f`.
    assert_eq!(unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) }, 0);
    f
}

#[test]
fn hooks_under_parallel_emits_keep_every_event() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    for name in ["fs", "log", "mq"] {
        enable(&h, name);
    }
    let threads: Vec<_> = (0..4)
        .map(|t| {
            let path = base(&dir);
            std::thread::spawn(move || {
                let h = EventHandle::new(Store::new(path));
                for i in 0..10 {
                    let o = emit_with(&h, &[("topic", "par"), ("data", &(t * 10 + i).to_string())]);
                    assert!(
                        hooks_of(&o)
                            .as_array()
                            .unwrap()
                            .iter()
                            .all(|r| r["ok"] == true),
                        "{}",
                        o.stdout
                    );
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let store = Store::new(base(&dir));
    let log = fs::read_to_string(hooks::log_path(&store, "par")).unwrap();
    let mut seen: Vec<i64> = log
        .lines()
        .map(|l| {
            serde_json::from_str::<Value>(l).unwrap()["data"]
                .as_i64()
                .unwrap()
        })
        .collect();
    seen.sort();
    assert_eq!(seen, (0..40).collect::<Vec<_>>());
    let latest: Value =
        serde_json::from_str(&fs::read_to_string(hooks::fs_path(&store, "par")).unwrap()).unwrap();
    assert_eq!(latest["seq"], 40);
    let mut queued: Vec<i64> = mq_messages(&dir, "par")
        .iter()
        .map(|m| {
            serde_json::from_str::<Value>(m).unwrap()["data"]
                .as_i64()
                .unwrap()
        })
        .collect();
    queued.sort();
    assert_eq!(queued, (0..40).collect::<Vec<_>>());
}

#[test]
fn hooks_errors() {
    let dir = TempDir::new().unwrap();
    let h = handle(&dir);
    for verb in ["hooks.enable", "hooks.disable"] {
        let o = call(&h, verb, &[("name", "mqq")]);
        o.fails(2, "event.unknown_hook");
        assert!(o.reason.contains("did you mean `mq`?"), "{}", o.reason);
        assert_eq!(o.stdout, "");
        let o = call(&h, verb, &[("name", "proc")]);
        o.fails(2, "event.unknown_hook");
        assert!(
            o.reason.contains("the proc hook was removed"),
            "{}",
            o.reason
        );
        call(&h, verb, &[]).fails(2, "event.missing_argument");
        call(&h, verb, &[("name", "mq"), ("timeout_ms", "5")]).fails(2, "event.invalid_argument");
        call(&h, verb, &[("nmae", "mq")]).fails(2, "event.invalid_argument");
    }
    let o = call(&h, "hooks.list", &[("timeout_ms", "5")]);
    o.fails(2, "event.invalid_argument");
    assert!(
        o.reason.contains("does not take timeout_ms"),
        "{}",
        o.reason
    );
    call(&h, "hooks.list", &[("name", "mq")]).fails(2, "event.invalid_argument");
    assert!(files(&dir).is_empty());

    // A corrupt state file: list and changes fail; emit still stores the
    // event, runs no hook and warns.
    fs::create_dir_all(base(&dir)).unwrap();
    fs::write(base(&dir).join("_hooks.json"), "[").unwrap();
    call(&h, "hooks.list", &[]).fails(1, "event.store_corrupt");
    call(&h, "hooks.disable", &[("name", "fs")]).fails(1, "event.store_corrupt");
    let o = emit_with(&h, &[("topic", "t"), ("data", "1")]);
    assert_eq!(o.code, 0);
    assert!(
        o.json()["warnings"][0]
            .as_str()
            .unwrap()
            .contains("not a valid hook state file"),
        "{}",
        o.stdout
    );
    assert!(
        o.stderr.starts_with("Warning: hooks did not run"),
        "{}",
        o.stderr
    );

    // A symlink at the state file is not written through.
    fs::remove_file(base(&dir).join("_hooks.json")).unwrap();
    let victim = dir.path().join("victim");
    fs::write(&victim, r#"{"disabled":[]}"#).unwrap();
    std::os::unix::fs::symlink(&victim, base(&dir).join("_hooks.json")).unwrap();
    call(&h, "hooks.disable", &[("name", "fs")]).fails(1, "event.store_error");
    assert_eq!(fs::read_to_string(&victim).unwrap(), r#"{"disabled":[]}"#);
    fs::remove_file(base(&dir).join("_hooks.json")).unwrap();

    let h = EventHandle {
        store: None,
        target_error: None,
    };
    call(&h, "hooks.list", &[]).fails(1, "event.store_unavailable");
    call(&h, "hooks.enable", &[("name", "fs")]).fails(1, "event.store_unavailable");
}

// --- dispatch, help and codes ---------------------------------------------------

#[test]
fn targets_and_unknown_verbs_are_refused() {
    for url in ["event://x", "event://x/y", "event:///y"] {
        let h = EventHandle::from_url(&Url::parse(url).unwrap()).unwrap();
        let o = call(&h, "hooks.list", &[]);
        o.fails(2, "event.invalid_target");
    }
    let h = EventHandle::from_url(&Url::parse("event://").unwrap()).unwrap();
    assert!(h.target_error.is_none());
    let dir = TempDir::new().unwrap();
    let o = call(&handle(&dir), "emitt", &[]);
    o.fails(2, "event.unknown_verb");
    assert!(o.reason.contains("did you mean `emit`?"), "{}", o.reason);
}

#[test]
fn topic_patterns_are_shell_globs() {
    assert!(topic_matches_pattern("jobs.backup", "jobs.*"));
    assert!(topic_matches_pattern("jobs.a", "jobs.?"));
    assert!(topic_matches_pattern("jobs.a.b", "jobs.*"));
    assert!(topic_matches_pattern("x", "*"));
    assert!(topic_matches_pattern("ab", "a*b"));
    assert!(topic_matches_pattern("axyb", "a*b"));
    assert!(topic_matches_pattern("jobs", "jobs"));
    assert!(!topic_matches_pattern("jobsXbackup", "jobs.backup"));
    assert!(!topic_matches_pattern("jobsxa", "jobs.?"));
    assert!(!topic_matches_pattern("jobs.ab", "jobs.?"));
    assert!(!topic_matches_pattern("xjobs", "jobs*"));
}

/// The options listed in a verb's help usage.
fn usage_options(verb: &str) -> Vec<&'static str> {
    let d = EVENT_HELP
        .verbs
        .iter()
        .find(|v| v.name == verb)
        .unwrap()
        .detail
        .as_ref()
        .unwrap();
    let mut v: Vec<&str> = d
        .usage
        .split(|c: char| c == '[' || c.is_whitespace())
        .filter_map(|w| w.split_once('=').map(|(k, _)| k))
        .collect();
    v.sort();
    v
}

#[test]
fn help_usage_lists_exactly_the_accepted_arguments() {
    let h = handle(&TempDir::new().unwrap());
    for verb in h.verbs().iter().filter(|v| !help::HELP_ALIASES.contains(v)) {
        let mut accepted = verb_args(verb).unwrap().to_vec();
        accepted.sort();
        assert_eq!(usage_options(verb), accepted, "{verb}");
    }
}

#[test]
fn error_codes_are_valid_documented_and_complete() {
    let doc = include_str!("../../../../docs/Data_StateManagement/event.md");
    for code in ERROR_CODES {
        assert!(crate::core::status::is_valid_error_code(code), "{code}");
        assert!(doc.contains(&format!("`{code}`")), "{code} not documented");
    }
    // Every code string in the source is in the list.
    let src = [include_str!("../eventh.rs"), include_str!("store.rs")];
    let re = regex::Regex::new(r#""(event\.[a-z_]+)""#).unwrap();
    for s in src {
        for c in re.captures_iter(s) {
            let code = c.get(1).unwrap().as_str();
            if code == "event.emit" {
                continue;
            }
            assert!(
                ERROR_CODES.contains(&code),
                "{code} missing from ERROR_CODES"
            );
        }
    }
}

#[test]
fn legacy_help_renders_approved_help() {
    let h = handle(&TempDir::new().unwrap());
    assert!(call(&h, "--help", &[]).stdout.starts_with("Handle: event"));
    assert!(
        call(&h, "help", &[("verb", "subscribe")])
            .stdout
            .contains("Verb: subscribe")
    );
    assert!(call(&h, "--help=emit", &[]).stdout.contains("Verb: emit"));
}

#[test]
fn a_group_read_on_a_missing_store_is_empty_and_creates_nothing() {
    let dir = TempDir::new().unwrap();
    let r = sub(
        &handle(&dir),
        &[("topic", "x.*"), ("offset", "next"), ("group_id", "g")],
    );
    assert_eq!(r["events_returned"], 0);
    assert_eq!(r["committed"], false);
    assert!(!base(&dir).exists());
}
