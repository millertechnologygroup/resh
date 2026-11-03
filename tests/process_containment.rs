//! The real helper against real process trees in a temporary directory. These
//! run in their own process because stopping a tree sweeps every descendant of
//! the calling process.

use resh::core::process::{Stopped, clear_limit, limit, run, take_lost};
use std::io;
use std::process::Command;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    clear_limit();
    take_lost();
    guard
}

fn sh(script: &str) -> Command {
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", script]);
    cmd
}

fn marks(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("m")).unwrap_or_default()
}

#[test]
fn completed_tools_keep_status_and_output() {
    let _g = serial();
    let out = run(&mut sh("echo out; echo err >&2; exit 3"), None).unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(out.stdout, b"out\n");
    assert_eq!(out.stderr, b"err\n");
    assert!(take_lost().is_none());
}

#[test]
fn a_timeout_stops_the_tool_and_its_descendants() {
    let _g = serial();
    let dir = tempfile::tempdir().unwrap();
    let m = dir.path().join("m");
    let script = format!(
        "(sleep 1; echo grandchild >> {m}) & (setsid sh -c 'sleep 1; echo escaped >> {m}') & sleep 1; echo child >> {m}",
        m = m.display()
    );
    let e = run(&mut sh(&script), Some(Duration::from_millis(200))).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    assert_eq!(take_lost().unwrap().stopped, Stopped::Terminated);
    std::thread::sleep(Duration::from_millis(1300));
    assert_eq!(marks(&dir), "");
}

#[test]
fn a_tool_that_ignores_sigterm_is_killed() {
    let _g = serial();
    let dir = tempfile::tempdir().unwrap();
    let script = format!(
        "trap '' TERM; (trap '' TERM; sleep 3; echo late >> {m}) & sleep 3; echo late >> {m}",
        m = dir.path().join("m").display()
    );
    let e = run(&mut sh(&script), Some(Duration::from_millis(100))).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    assert_eq!(take_lost().unwrap().stopped, Stopped::Terminated);
    std::thread::sleep(Duration::from_millis(1800));
    assert_eq!(marks(&dir), "");
}

#[test]
fn work_done_before_the_timeout_stays_done() {
    let _g = serial();
    let dir = tempfile::tempdir().unwrap();
    let script = format!(
        "echo before >> {m}; sleep 3; echo after >> {m}",
        m = dir.path().join("m").display()
    );
    run(&mut sh(&script), Some(Duration::from_millis(200))).unwrap_err();
    take_lost();
    assert_eq!(marks(&dir), "before\n");
}

#[test]
fn nothing_starts_past_the_operation_deadline() {
    let _g = serial();
    let dir = tempfile::tempdir().unwrap();
    limit(Duration::ZERO);
    let script = format!("echo x >> {}", dir.path().join("m").display());
    let e = run(&mut sh(&script), None).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    assert_eq!(take_lost().unwrap().stopped, Stopped::NotStarted);
    assert_eq!(marks(&dir), "");
    clear_limit();
}

#[test]
fn captured_output_is_bounded_and_exit_is_kept() {
    let _g = serial();
    let out = run(
        &mut sh("head -c 70000000 /dev/zero; exit 4"),
        Some(Duration::from_secs(30)),
    )
    .unwrap();
    assert_eq!(out.stdout.len(), 64 * 1024 * 1024);
    assert_eq!(out.status.code(), Some(4));
}

#[test]
fn a_descendant_holding_the_stream_does_not_block_a_finished_tool() {
    let _g = serial();
    let start = Instant::now();
    let out = run(&mut sh("sleep 20 & echo done"), None).unwrap();
    assert_eq!(out.stdout, b"done\n");
    assert!(start.elapsed() < Duration::from_secs(10));
}
