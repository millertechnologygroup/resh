//! Stage output is streamed to stdout as it is written, so a long-running
//! verb with no limit (here `config watch`) shows its events while it is
//! still running instead of only when it exits.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[test]
fn unbounded_watch_prints_events_while_running() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let resh = |args: &[&str]| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_resh"));
        c.args(args)
            .current_dir(dir)
            .env("HOME", dir)
            .env("XDG_CONFIG_HOME", dir.join("xdg"));
        c
    };

    // No timeout_ms and no max_events: runs until killed.
    let mut child = resh(&["config://app.watch", "prefix=app"])
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

    // Keep changing a value until an event line arrives (or 15 s pass).
    let started = Instant::now();
    let mut n = 0;
    let line = loop {
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "no event was printed while the watch was running"
        );
        let status = resh(&["config://app/key.set", &format!("value={n}")])
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        n += 1;
        if let Ok(line) = rx.recv_timeout(Duration::from_millis(300)) {
            break line;
        }
    };
    assert!(
        child.try_wait().unwrap().is_none(),
        "the event arrived only after the watch exited"
    );
    let _ = child.kill();
    let _ = child.wait();

    let event: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(event["op"], "set");
    assert_eq!(event["key"], "app/key");
}

#[test]
fn json_pretty_still_reformats_the_whole_output() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_resh"))
            .args(args)
            .current_dir(dir)
            .env("HOME", dir)
            .env("XDG_CONFIG_HOME", dir.join("xdg"))
            .output()
            .unwrap()
    };
    assert!(
        run(&["config://app/x.set", "value={\"a\":1}"])
            .status
            .success()
    );
    let plain = run(&["config://app/x.get"]);
    let pretty = run(&["--json-pretty", "config://app/x.get"]);
    assert!(plain.status.success() && pretty.status.success());
    let plain: serde_json::Value = serde_json::from_slice(&plain.stdout).unwrap();
    let pretty_text = String::from_utf8(pretty.stdout).unwrap();
    assert!(
        pretty_text.contains("\n  "),
        "not pretty-printed: {pretty_text}"
    );
    let pretty: serde_json::Value = serde_json::from_str(&pretty_text).unwrap();
    assert_eq!(plain, pretty);
}
