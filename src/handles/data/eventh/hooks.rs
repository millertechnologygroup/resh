//! The built-in hooks, run after `emit` stored an event:
//!
//! * `log`: appends the stored event as one JSON line to
//!   `<store>/hooks/log/<topic>.log`, readable with
//!   `resh log:///<that path>.tail`;
//! * `fs`: replaces `<store>/hooks/fs/<topic>.json` with the topic's latest
//!   event (the highest sequence number wins, also under parallel emits);
//! * `mq`: puts the stored event (the same JSON object the log hook writes)
//!   on the mq queue named
//!   after the topic, through the mq handle's own `put`.
//!
//! Directories are created 0700 and files 0600; a symlink at any path a
//! hook writes is refused. A hook never fails the emit: its failure is a
//! warning in the emit result.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::{EventEnvelope, Store};
use crate::core::secure_fs;

/// The built-in hooks, in the order they run.
pub(super) const HOOK_NAMES: &[&str] = &["fs", "log", "mq"];

/// Hooks enabled when the hook state file does not say otherwise. The hooks
/// write files and queue messages for every event, so none is on by
/// default.
pub(super) const DEFAULT_ENABLED: &[&str] = &[];

/// Hooks of earlier versions that no longer exist.
pub(super) const REMOVED_HOOKS: &[&str] = &["proc"];

/// What one hook did for one event.
pub(super) struct HookReport {
    pub name: &'static str,
    pub ok: bool,
    pub warning: Option<String>,
}

impl HookReport {
    pub fn json(&self) -> Value {
        json!({"name": self.name, "ok": self.ok, "warning": self.warning})
    }
}

/// Creates `dir` owner-only, or checks an existing one: a symlink or a
/// non-directory is refused.
fn private_dir(dir: &Path) -> Result<(), String> {
    match fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => Err(format!(
            "refusing to use {}: it is a symlink",
            dir.display()
        )),
        Ok(m) if !m.is_dir() => Err(format!("{} is not a directory", dir.display())),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(dir)
                .or_else(|e| {
                    // Another emit created it meanwhile.
                    if e.kind() == io::ErrorKind::AlreadyExists {
                        Ok(())
                    } else {
                        Err(e)
                    }
                })
                .and_then(|_| fs::set_permissions(dir, fs::Permissions::from_mode(0o700)))
                .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
            private_dir(dir)
        }
        Err(e) => Err(format!("cannot inspect {}: {e}", dir.display())),
    }
}

/// `<store>/hooks/<name>`, created owner-only.
fn hook_dir(store: &Store, name: &str) -> Result<PathBuf, String> {
    let hooks = store.base().join("hooks");
    let dir = hooks.join(name);
    private_dir(&hooks)?;
    private_dir(&dir)?;
    Ok(dir)
}

/// The path the log hook writes for `topic` in `store`.
pub(super) fn log_path(store: &Store, topic: &str) -> PathBuf {
    store
        .base()
        .join("hooks")
        .join("log")
        .join(format!("{topic}.log"))
}

/// The path the fs hook writes for `topic` in `store`.
pub(super) fn fs_path(store: &Store, topic: &str) -> PathBuf {
    store
        .base()
        .join("hooks")
        .join("fs")
        .join(format!("{topic}.json"))
}

/// The mq store next to the event store (`<state>/resh/mq`).
pub(super) fn mq_root(store: &Store) -> PathBuf {
    store
        .base()
        .parent()
        .map(|p| p.join("mq"))
        .unwrap_or_else(|| store.base().join("mq"))
}

fn stored_line(evt: &EventEnvelope) -> Result<String, String> {
    serde_json::to_string(evt).map_err(|e| format!("cannot encode the event: {e}"))
}

fn run_log(store: &Store, evt: &EventEnvelope) -> Result<(), String> {
    hook_dir(store, "log")?;
    let path = log_path(store, &evt.topic);
    if let Ok(m) = fs::symlink_metadata(&path)
        && !m.is_file()
    {
        return Err(format!(
            "refusing to write {}: it is a symlink or not a regular file",
            path.display()
        ));
    }
    let mut line = stored_line(evt)?;
    line.push('\n');
    let mut f = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    // One write of the whole line, so parallel emits do not interleave.
    f.write_all(line.as_bytes())
        .map_err(|e| format!("cannot append to {}: {e}", path.display()))
}

fn run_fs(store: &Store, evt: &EventEnvelope, deadline: Option<Instant>) -> Result<(), String> {
    let dir = hook_dir(store, "fs")?;
    // A lock, so a slower emit never replaces a newer event.
    let lock_path = dir.join(".lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)
        .map_err(|e| format!("cannot open {}: {e}", lock_path.display()))?;
    loop {
        // SAFETY: flock on a file descriptor owned by `lock`.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            break;
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::WouldBlock {
            return Err(format!("cannot lock {}: {e}", lock_path.display()));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Err("skipped: timeout_ms passed while waiting for the fs hook lock".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let path = fs_path(store, &evt.topic);
    if let Ok(text) = fs::read_to_string(&path)
        && let Ok(old) = serde_json::from_str::<EventEnvelope>(&text)
        && old.seq >= evt.seq
    {
        return Ok(());
    }
    let mut text = stored_line(evt)?;
    text.push('\n');
    secure_fs::write_private_file(&path, text.as_bytes(), true)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn run_mq(store: &Store, evt: &EventEnvelope, deadline: Option<Instant>) -> Result<(), String> {
    let record = stored_line(evt)?;
    super::super::mqh::put_data(&mq_root(store), &evt.topic, &record, deadline)
        .map_err(|e| format!("not forwarded to mq queue {:?}: {e}", evt.topic))
}

/// Runs the hooks `enabled` (in [`HOOK_NAMES`] order) for `evt`.
pub(super) fn run(
    store: &Store,
    enabled: &[&'static str],
    evt: &EventEnvelope,
    deadline: Option<Instant>,
) -> Vec<HookReport> {
    HOOK_NAMES
        .iter()
        .filter(|n| enabled.contains(n))
        .map(|&name| {
            let result = if deadline.is_some_and(|d| Instant::now() >= d) {
                Err("skipped: timeout_ms passed before the hook ran".to_string())
            } else {
                match name {
                    "log" => run_log(store, evt),
                    "fs" => run_fs(store, evt, deadline),
                    _ => run_mq(store, evt, deadline),
                }
            };
            HookReport {
                name,
                ok: result.is_ok(),
                warning: result.err(),
            }
        })
        .collect()
}
