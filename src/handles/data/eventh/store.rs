//! The on-disk event store shared by every resh process of the user.
//!
//! Layout of the store directory (normally `~/.local/state/resh/events`,
//! mode 0700; every file mode 0600):
//!
//! * `<topic>.jsonl`: one stored event per line, appended in order;
//! * `_store.lock`: `emit` holds an exclusive lock on it while it numbers
//!   and appends an event, readers hold a shared lock while they read the
//!   topic files, so a reader always sees a consistent set of events. The
//!   file also holds the last event sequence number;
//! * `_offsets.lock`: held exclusively while a consumer group reads,
//!   delivers and commits a batch, so consumers of one group never get the
//!   same events;
//! * `_offsets.json`: committed consumer-group offsets;
//! * `_hooks.json`: hooks enabled or disabled with hooks.enable/disable;
//! * `hooks/`: files written by the log and fs hooks (see `hooks`).
//!
//! Every lock wait is bounded by the caller's deadline. Writes never follow
//! a symlink planted at the target path.

use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::hooks::{DEFAULT_ENABLED, HOOK_NAMES};
use super::{EventEnvelope, Fail, topic_matches_pattern, valid_topic_name};
use crate::core::secure_fs;

pub(super) const STORE_LOCK: &str = "_store.lock";
pub(super) const OFFSETS_LOCK: &str = "_offsets.lock";
pub(super) const OFFSETS: &str = "_offsets.json";
pub(super) const HOOKS: &str = "_hooks.json";

/// How often a blocked lock is retried.
const LOCK_RETRY: Duration = Duration::from_millis(10);
/// How many lines are read between two deadline checks.
const LINES_PER_CHECK: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LockKind {
    Shared,
    Exclusive,
}

/// A held lock; dropping it releases the lock.
pub(super) struct Lock {
    file: File,
}

/// Events read from the store.
pub(super) struct Loaded {
    /// Matching events in store order, `offset` set to their index.
    pub events: Vec<EventEnvelope>,
    /// Lines that did not parse and were skipped.
    pub skipped: usize,
}

/// One topic file with its events.
pub(super) struct TopicFile {
    pub topic: String,
    pub events: Vec<EventEnvelope>,
    pub skipped: usize,
}

/// A cheap summary of the files a read depends on, to skip re-reading the
/// store while nothing changed.
pub(super) type Fingerprint = Vec<(String, u64, i64, i64)>;

#[derive(Debug, Clone)]
pub struct Store {
    base: PathBuf,
}

fn deadline_passed(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|d| Instant::now() >= d)
}

fn store_error(what: &str, path: &Path, e: io::Error) -> Fail {
    Fail::store(format!("cannot {what} {}: {e}", path.display()))
}

/// Refuses a symlink or other non-regular file at `path` (a missing entry is
/// fine).
fn refuse_non_regular(path: &Path) -> Result<(), Fail> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(Fail::store(format!(
            "refusing to write through a symlink: {}",
            path.display()
        ))),
        Ok(m) if !m.is_file() => Err(Fail::store(format!(
            "not a regular file: {}",
            path.display()
        ))),
        _ => Ok(()),
    }
}

impl Store {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    /// `<state_dir>/resh/events`, or None when there is no state directory.
    pub fn default_base() -> Option<PathBuf> {
        dirs::state_dir().map(|d| d.join("resh").join("events"))
    }

    pub fn base(&self) -> &Path {
        &self.base
    }

    fn path(&self, name: &str) -> PathBuf {
        self.base.join(name)
    }

    pub(super) fn topic_path(&self, topic: &str) -> PathBuf {
        self.base.join(format!("{topic}.jsonl"))
    }

    /// True if the store directory exists. Anything else at its path is an
    /// error.
    pub(super) fn exists(&self) -> Result<bool, Fail> {
        match fs::metadata(&self.base) {
            Ok(m) if m.is_dir() => Ok(true),
            Ok(_) => Err(Fail::unavailable(format!(
                "event store {} is not a directory",
                self.base.display()
            ))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Fail::unavailable(format!(
                "event store {} is not accessible: {e}",
                self.base.display()
            ))),
        }
    }

    /// Creates the store directory (mode 0700) if it is missing.
    fn ensure_dir(&self) -> Result<(), Fail> {
        if self.exists()? {
            return Ok(());
        }
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.base)
            .map_err(|e| {
                Fail::unavailable(format!(
                    "cannot create the event store {}: {e}",
                    self.base.display()
                ))
            })?;
        // DirBuilder's mode is reduced by the umask; set it exactly.
        fs::set_permissions(&self.base, fs::Permissions::from_mode(0o700)).map_err(|e| {
            Fail::unavailable(format!(
                "cannot set the mode of {}: {e}",
                self.base.display()
            ))
        })
    }

    /// Takes lock `name` (creating its file in an existing store), waiting
    /// at most until `deadline`.
    pub(super) fn lock(
        &self,
        name: &str,
        kind: LockKind,
        deadline: Option<Instant>,
    ) -> Result<Lock, Fail> {
        let path = self.path(name);
        refuse_non_regular(&path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| store_error("open the lock file", &path, e))?;
        let op = match kind {
            LockKind::Shared => libc::LOCK_SH,
            LockKind::Exclusive => libc::LOCK_EX,
        } | libc::LOCK_NB;
        loop {
            // SAFETY: flock on a file descriptor this function owns.
            let tried = if unsafe { libc::flock(file.as_raw_fd(), op) } == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            };
            match tried {
                Ok(()) => return Ok(Lock { file }),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if deadline_passed(deadline) {
                        return Err(Fail::timeout(format!(
                            "timeout_ms passed while waiting for {} (held by another \
                             resh process); nothing was changed",
                            path.display()
                        )));
                    }
                    std::thread::sleep(LOCK_RETRY);
                }
                Err(e) => return Err(store_error("lock", &path, e)),
            }
        }
    }

    /// Appends `evt` to its topic file and gives it the next sequence
    /// number. Either the whole event is written or nothing is.
    pub(super) fn append(
        &self,
        evt: &mut EventEnvelope,
        sync: bool,
        deadline: Option<Instant>,
    ) -> Result<(), Fail> {
        self.ensure_dir()?;
        let lock = self.lock(STORE_LOCK, LockKind::Exclusive, deadline)?;
        let path = self.topic_path(&evt.topic);
        refuse_non_regular(&path)?;
        let seq = read_counter(&lock.file, &self.path(STORE_LOCK))? + 1;
        evt.seq = Some(seq);
        evt.offset = None;
        evt.raw = None;
        let mut line = serde_json::to_string(&*evt)
            .map_err(|e| Fail::store(format!("cannot encode the event: {e}")))?;
        line.push('\n');
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| store_error("open", &path, e))?;
        f.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| store_error("set the mode of", &path, e))?;
        // The counter is written first: a crash in between leaves a gap in
        // the numbers, never two events with one number.
        write_counter(&lock.file, seq)
            .map_err(|e| store_error("update", &self.path(STORE_LOCK), e))?;
        // One write of the whole line.
        f.write_all(line.as_bytes())
            .map_err(|e| store_error("append to", &path, e))?;
        if sync {
            f.sync_data().map_err(|e| store_error("sync", &path, e))?;
        }
        drop(lock);
        Ok(())
    }

    /// Topic files whose topic matches `pattern`, sorted by topic.
    fn topic_files(&self, pattern: Option<&str>) -> Result<Vec<(String, PathBuf, u64)>, Fail> {
        let rd = match fs::read_dir(&self.base) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(store_error("read", &self.base, e)),
        };
        let mut out = Vec::new();
        for entry in rd {
            let entry = entry.map_err(|e| store_error("read", &self.base, e))?;
            let name = entry.file_name();
            let Some(topic) = name.to_str().and_then(|n| n.strip_suffix(".jsonl")) else {
                continue;
            };
            if !valid_topic_name(topic) || pattern.is_some_and(|p| !topic_matches_pattern(topic, p))
            {
                continue;
            }
            // Symlinks and other non-regular entries are not topic files.
            let Ok(meta) = fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if meta.is_file() {
                out.push((topic.to_string(), entry.path(), meta.len()));
            }
        }
        out.sort();
        Ok(out)
    }

    /// The fingerprint of the files a read of `pattern` depends on (plus the
    /// committed offsets when `offsets` is set).
    pub(super) fn fingerprint(&self, pattern: &str, offsets: bool) -> Result<Fingerprint, Fail> {
        let mut fp: Fingerprint = Vec::new();
        let mut add = |name: String, path: &Path| {
            if let Ok(m) = fs::symlink_metadata(path) {
                fp.push((name, m.len(), m.mtime(), m.mtime_nsec()));
            }
        };
        for (topic, path, _) in self.topic_files(Some(pattern))? {
            add(topic, &path);
        }
        if offsets {
            add(OFFSETS.to_string(), &self.path(OFFSETS));
        }
        Ok(fp)
    }

    /// Reads one topic file, checking `deadline` as it goes.
    fn read_topic_file(
        path: &Path,
        deadline: Option<Instant>,
    ) -> Result<(Vec<EventEnvelope>, usize), Fail> {
        let f = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
            Err(e) => return Err(store_error("open", path, e)),
        };
        let mut events = Vec::new();
        let mut skipped = 0;
        for (n, line) in BufReader::new(f).lines().enumerate() {
            if n % LINES_PER_CHECK == 0 && deadline_passed(deadline) {
                return Err(Fail::timeout(format!(
                    "timeout_ms passed while reading {}",
                    path.display()
                )));
            }
            let line = line.map_err(|e| store_error("read", path, e))?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<EventEnvelope>(&line) {
                Ok(e) => events.push(e),
                Err(_) => skipped += 1,
            }
        }
        Ok((events, skipped))
    }

    /// All stored events whose topic matches `pattern`, in store order
    /// (events from before sequence numbers first, by time; then by
    /// sequence number), with `offset` set to their index.
    pub(super) fn load(&self, pattern: &str, deadline: Option<Instant>) -> Result<Loaded, Fail> {
        if !self.exists()? {
            return Ok(Loaded {
                events: Vec::new(),
                skipped: 0,
            });
        }
        let _lock = self.lock(STORE_LOCK, LockKind::Shared, deadline)?;
        let mut events = Vec::new();
        let mut skipped = 0;
        for (_, path, _) in self.topic_files(Some(pattern))? {
            let (mut evts, bad) = Self::read_topic_file(&path, deadline)?;
            events.append(&mut evts);
            skipped += bad;
        }
        events.sort_by_key(|e| (e.seq.is_some(), e.seq.unwrap_or(0), e.timestamp_unix_ms));
        for (i, e) in events.iter_mut().enumerate() {
            e.offset = Some(i.to_string());
        }
        Ok(Loaded { events, skipped })
    }

    /// Every topic file with its events, sorted by topic.
    pub(super) fn topics(&self, deadline: Option<Instant>) -> Result<Vec<TopicFile>, Fail> {
        if !self.exists()? {
            return Ok(Vec::new());
        }
        let _lock = self.lock(STORE_LOCK, LockKind::Shared, deadline)?;
        let mut out = Vec::new();
        for (topic, path, _) in self.topic_files(None)? {
            let (events, skipped) = Self::read_topic_file(&path, deadline)?;
            out.push(TopicFile {
                topic,
                events,
                skipped,
            });
        }
        Ok(out)
    }

    /// Committed consumer-group offsets, keyed `<group>:<pattern>`.
    pub(super) fn read_offsets(&self) -> Result<HashMap<String, u64>, Fail> {
        let path = self.path(OFFSETS);
        match fs::read_to_string(&path) {
            Ok(t) => serde_json::from_str(&t).map_err(|e| {
                Fail::corrupt(format!(
                    "{} is not a valid offsets file ({e}); fix or remove it",
                    path.display()
                ))
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(HashMap::new()),
            Err(e) => Err(store_error("read", &path, e)),
        }
    }

    /// Commits `offset` under `key`. The caller holds the offsets lock.
    pub(super) fn commit_offset(&self, key: &str, offset: u64) -> Result<(), Fail> {
        self.ensure_dir()?;
        let mut offsets = self.read_offsets()?;
        offsets.insert(key.to_string(), offset);
        let path = self.path(OFFSETS);
        let text = serde_json::to_string(&offsets)
            .map_err(|e| Fail::store(format!("cannot encode offsets: {e}")))?;
        secure_fs::write_private_file(&path, text.as_bytes(), true)
            .map_err(|e| store_error("write", &path, e))
    }

    /// The hooks that are enabled, in run order: the defaults plus those
    /// enabled with hooks.enable, minus those disabled with hooks.disable.
    /// Names that are not built-in hooks (such as the removed `proc`) are
    /// ignored.
    pub(super) fn enabled_hooks(&self) -> Result<Vec<&'static str>, Fail> {
        let state = self.hook_state()?;
        Ok(HOOK_NAMES
            .iter()
            .copied()
            .filter(|n| state.is_enabled(n))
            .collect())
    }

    fn hook_state(&self) -> Result<HookState, Fail> {
        let path = self.path(HOOKS);
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(HookState::default()),
            Err(e) => return Err(store_error("read", &path, e)),
        };
        serde_json::from_str::<HookState>(&text).map_err(|e| {
            Fail::corrupt(format!(
                "{} is not a valid hook state file ({e}); fix or remove it",
                path.display()
            ))
        })
    }

    /// Enables or disables hook `name`; returns true if the state changed.
    pub(super) fn set_hook_enabled(
        &self,
        name: &str,
        enabled: bool,
        deadline: Option<Instant>,
    ) -> Result<bool, Fail> {
        self.ensure_dir()?;
        let _lock = self.lock(STORE_LOCK, LockKind::Exclusive, deadline)?;
        let mut state = self.hook_state()?;
        let before = state.is_enabled(name);
        // Only built-in hook names are kept (old files may name `proc`).
        state.enabled.retain(|n| HOOK_NAMES.contains(&n.as_str()));
        state.disabled.retain(|n| HOOK_NAMES.contains(&n.as_str()));
        if enabled {
            state.disabled.remove(name);
            state.enabled.insert(name.to_string());
        } else {
            state.enabled.remove(name);
            state.disabled.insert(name.to_string());
        }
        let path = self.path(HOOKS);
        let text =
            serde_json::json!({ "enabled": state.enabled, "disabled": state.disabled }).to_string();
        secure_fs::write_private_file(&path, text.as_bytes(), true)
            .map_err(|e| store_error("write", &path, e))?;
        Ok(before != enabled)
    }
}

/// `_hooks.json`: hooks switched on or off relative to the defaults.
#[derive(serde::Deserialize, Default)]
struct HookState {
    #[serde(default)]
    enabled: BTreeSet<String>,
    #[serde(default)]
    disabled: BTreeSet<String>,
}

impl HookState {
    fn is_enabled(&self, name: &str) -> bool {
        !self.disabled.contains(name)
            && (self.enabled.contains(name) || DEFAULT_ENABLED.contains(&name))
    }
}

/// The last sequence number, stored in the store lock file.
fn read_counter(mut file: &File, path: &Path) -> Result<u64, Fail> {
    let mut text = String::new();
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.read_to_string(&mut text))
        .map_err(|e| store_error("read", path, e))?;
    let text = text.trim();
    if text.is_empty() {
        return Ok(0);
    }
    text.parse().map_err(|_| {
        Fail::corrupt(format!(
            "{} does not hold a sequence number; nothing was written",
            path.display()
        ))
    })
}

/// Writes `seq` as 20 zero-padded digits at the start of the file: one
/// fixed-width positional write, so the old number is replaced in place.
fn write_counter(file: &File, seq: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(format!("{seq:020}").as_bytes(), 0)
}
