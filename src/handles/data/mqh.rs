//! `mq://<queue>`: a local, file-based FIFO message queue.
//!
//! Storage (under `$XDG_STATE_HOME/resh/mq`, owner-only):
//!
//! ```text
//! <queue>/                     0700
//!   .seq                       0600  queue lock (flock) and the next message number
//!   .tmp/<pid>-<uuid>          0600  messages being written by put
//!   _inflight/<n>.<pid>.<start>.claim  0600  messages being taken by get
//!   <n>.msg                    0600  queued messages, <n> = 20-digit number
//! ```
//!
//! Concurrency: `put` writes and syncs the message in `.tmp`, then, holding
//! the queue lock, takes the next number from `.seq` and renames the file
//! into place, so numbers follow the order in which puts finished and never
//! repeat. `get` and `purge` hold the lock while they choose and move or
//! delete messages, so two consumers never take the same message. A claim
//! names the claiming process (PID and start time); a claim whose process
//! is gone is moved back to the queue under its old number by the next get
//! (or by len/peek when the lock is free), so delivery is at-least-once.
//! `len` and `peek` never wait for the lock. The lock is an `flock` on
//! `.seq`, released by the kernel if a process dies.

use anyhow::Result;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use url::Url;

use crate::core::{
    help::{self, HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::{Status, exit},
};

#[cfg(test)]
mod tests;

/// Every error code the handle reports.
pub const ERROR_CODES: &[&str] = &[
    "mq.invalid_argument",
    "mq.invalid_target",
    "mq.empty",
    "mq.timeout",
    "mq.no_state_dir",
    "mq.unsafe_path",
    "mq.io_error",
];

/// Longest accepted queue name.
const MAX_NAME: usize = 120;

/// Metadata for `resh mq --help` and `resh mq <verb> --help`.
static MQ_HELP: HandleHelp = HandleHelp {
    description: "The mq handle provides a local, file-based FIFO message queue, storing each \
        message as an owner-only file under the user's state directory, normally \
        ~/.local/state/resh/mq/<queue>. The queue is named by the URL, such as mq://jobs, \
        using letters, digits, '.', '-' and '_'. Producers and consumers may run at the same \
        time: messages come out in the order the puts finished, and a message whose get was \
        killed before printing it is delivered again.",
    usage: "resh mq://<queue>.<verb>[(key=value,...)]",
    verbs: &[
        VerbHelp {
            name: "len",
            definition: "Prints the number of messages waiting in the queue, 0 if the queue \
                does not exist.",
            detail: Some(VerbDetail {
                usage: "resh mq://<queue>.len",
                example: "resh mq://jobs.len",
                example_output: Some("2"),
            }),
        },
        VerbHelp {
            name: "peek",
            definition: "Prints the oldest message without removing it, failing with exit \
                status 1 and the code mq.empty if the queue is empty.",
            detail: Some(VerbDetail {
                usage: "resh mq://<queue>.peek",
                example: "resh mq://jobs.peek",
                example_output: Some(
                    r#"backup-db

The message is printed exactly as stored, with no newline added."#,
                ),
            }),
        },
        VerbHelp {
            name: "create",
            definition: "Creates the queue's storage directories if they do not already exist.",
            detail: Some(VerbDetail {
                usage: "resh mq://<queue>.create",
                example: "resh mq://jobs.create",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "put",
            definition: "Appends a message to the queue, taken from the data argument or, if \
                it is absent, from standard input.",
            detail: Some(VerbDetail {
                usage: "resh mq://<queue>.put [data=<message>] [timeout_ms=<ms>]",
                example: "resh mq://jobs.put data=backup-db",
                example_output: Some(
                    r#"Prints nothing on success. Without data=, all of standard input is the
message, stored byte for byte. timeout_ms limits the wait for the queue lock
(0 or absent: no limit); past it the command exits 124 with mq.timeout and
nothing is queued."#,
                ),
            }),
        },
        VerbHelp {
            name: "get",
            definition: "Removes the oldest message from the queue and prints it; on an \
                empty queue it fails with exit status 1 and the code mq.empty, or with \
                wait=true waits for a message.",
            detail: Some(VerbDetail {
                usage: "resh mq://<queue>.get [wait=true|false] [timeout_ms=<ms>]",
                example: "resh mq://jobs.get",
                example_output: Some(
                    r#"backup-db

The message is printed exactly as stored, with no newline added; if it
cannot be written out it is put back at the head of the queue. With
wait=true (default false) get waits for a message to arrive. timeout_ms
limits the whole wait, for the queue lock and, with wait=true, for a message
(default: no limit, or 30000 with wait=true; 0: no limit); past it the
command exits 124 with mq.timeout and nothing is taken."#,
                ),
            }),
        },
        VerbHelp {
            name: "purge",
            definition: "Deletes every message in the queue, including any left in flight.",
            detail: Some(VerbDetail {
                usage: "resh mq://<queue>.purge [timeout_ms=<ms>]",
                example: "resh mq://jobs.purge",
                example_output: Some(
                    r#"Prints nothing on success. timeout_ms limits the wait for the queue lock and
the deletion (0 or absent: no limit); past it the command exits 124 with
mq.timeout, and messages not yet deleted stay queued."#,
                ),
            }),
        },
    ],
};

/// The arguments each verb accepts.
fn verb_args(verb: &str) -> Option<&'static [&'static str]> {
    Some(match verb {
        "len" | "peek" | "create" => &[],
        "put" => &["data", "timeout_ms"],
        "get" => &["wait", "timeout_ms"],
        "purge" => &["timeout_ms"],
        _ => return None,
    })
}

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("mq", |u| Ok(Box::new(MQHandle::from_url(u)?)));
}

// ---------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Failure {
    exit: i32,
    code: &'static str,
    message: String,
}

type R<T> = std::result::Result<T, Failure>;

impl Failure {
    fn new(exit: i32, code: &'static str, message: impl Into<String>) -> Self {
        debug_assert!(ERROR_CODES.contains(&code), "{code} not listed");
        Self {
            exit,
            code,
            message: message.into(),
        }
    }
    fn usage(message: impl Into<String>) -> Self {
        Self::new(exit::USAGE, "mq.invalid_argument", message)
    }
    fn io(what: impl std::fmt::Display, e: io::Error) -> Self {
        Self::new(exit::FAILED, "mq.io_error", format!("{what}: {e}"))
    }
    fn unsafe_path(path: &Path, why: &str) -> Self {
        Self::new(
            exit::FAILED,
            "mq.unsafe_path",
            format!("{} {why}; nothing was done", path.display()),
        )
    }
    fn into_status(self) -> Status {
        Status::coded(self.exit, self.code, self.message)
    }
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

/// Refuses an argument `verb` does not take (exit 2). `dry_run` is checked
/// by the dispatcher, which refuses `dry_run=true` for every mq verb, so
/// only `dry_run=false` reaches here and it changes nothing.
fn check_args(verb: &str, allowed: &[&str], args: &Args) -> R<()> {
    let mut keys: Vec<&String> = args.keys().collect();
    keys.sort();
    let Some(bad) = keys
        .into_iter()
        .find(|k| k.as_str() != "dry_run" && !allowed.contains(&k.as_str()))
    else {
        return Ok(());
    };
    if bad == "timeout_ms" {
        return Err(Failure::usage(format!(
            "mq {verb} does not take timeout_ms: it never waits for the queue lock \
             (only put, get and purge do); nothing was done"
        )));
    }
    let hint = suggest(bad, allowed)
        .map(|s| format!(" (did you mean `{s}`?)"))
        .unwrap_or_default();
    let accepted = if allowed.is_empty() {
        "it takes no arguments".to_string()
    } else {
        format!("accepted: {}", allowed.join(", "))
    };
    Err(Failure::usage(format!(
        "unknown argument for mq {verb}: {bad}{hint} ({accepted}); nothing was done"
    )))
}

/// The accepted argument closest to `bad` (edit distance at most 2, a
/// case-only difference, or one a prefix of the other), for a "did you
/// mean" hint.
fn suggest<'a>(bad: &str, allowed: &[&'a str]) -> Option<&'a str> {
    fn distance(a: &str, b: &str) -> usize {
        let b: Vec<char> = b.chars().collect();
        let mut prev: Vec<usize> = (0..=b.len()).collect();
        for (i, ca) in a.chars().enumerate() {
            let mut cur = vec![i + 1];
            for (j, cb) in b.iter().enumerate() {
                let cost = usize::from(ca != *cb);
                cur.push((prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1));
            }
            prev = cur;
        }
        prev[b.len()]
    }
    let lower = bad.to_ascii_lowercase().replace('-', "_");
    allowed
        .iter()
        .map(|a| (distance(&lower, a), *a))
        .filter(|(d, a)| {
            *d <= 2 || (lower.len() >= 3 && (a.starts_with(lower.as_str()) || lower.starts_with(a)))
        })
        .min_by_key(|(d, _)| *d)
        .map(|(_, a)| a)
}

/// How long `get wait=true` waits when timeout_ms is not given.
const DEFAULT_WAIT_MS: u64 = 30_000;

/// `timeout_ms`: a whole number of milliseconds; 0 means no limit. Absent
/// means no limit, except for `get wait=true` (DEFAULT_WAIT_MS).
fn deadline_arg(args: &Args, wait: bool) -> R<Option<Instant>> {
    let Some(raw) = args.get("timeout_ms") else {
        return Ok(wait.then(|| Instant::now() + Duration::from_millis(DEFAULT_WAIT_MS)));
    };
    let ms: u64 = raw.parse().map_err(|_| {
        Failure::usage(format!(
            "timeout_ms must be a whole number of milliseconds (0 = no limit), got {raw:?}; \
             nothing was done"
        ))
    })?;
    if ms == 0 {
        return Ok(None);
    }
    Ok(Some(Instant::now() + Duration::from_millis(ms)))
}

// ---------------------------------------------------------------------------
// Queue names and storage
// ---------------------------------------------------------------------------

/// Checks a queue name: 1-120 letters, digits, '.', '-' or '_', not
/// starting with '.'.
fn validate_name(name: &str) -> std::result::Result<(), String> {
    let rule = "a queue name is 1-120 letters, digits, '.', '-' or '_' and does not start \
                with '.'";
    if name.is_empty() {
        return Err(format!("missing queue name: use mq://<queue> ({rule})"));
    }
    if name.len() > MAX_NAME
        || name.starts_with('.')
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err(format!("invalid queue name {name:?}: {rule}"));
    }
    Ok(())
}

/// Parses `mq://<queue>`: the queue name is the URL host; anything else in
/// the URL (a path, port, user, query or fragment) is refused.
fn queue_name(u: &Url) -> std::result::Result<String, String> {
    if !u.username().is_empty()
        || u.password().is_some()
        || u.port().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || !(u.path().is_empty() || u.path() == "/")
    {
        let shown = u.as_str();
        return Err(format!(
            "invalid queue {shown:?}: use mq://<queue>, a single name without '/', ':', \
             '?', '#' or '@'"
        ));
    }
    let name = u.host_str().unwrap_or("").to_string();
    validate_name(&name)?;
    Ok(name)
}

/// The mq store root, `<state dir>/resh/mq`; None if the state directory
/// cannot be determined (there is no fallback to a shared directory).
fn store_root() -> Option<PathBuf> {
    dirs::state_dir().map(|d| d.join("resh").join("mq"))
}

/// True if `name` is a queued-message file name: 20 digits then `.msg`.
fn message_number(name: &str) -> Option<u64> {
    let digits = name.strip_suffix(".msg")?;
    if digits.len() != 20 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn message_file_name(n: u64) -> String {
    format!("{n:020}.msg")
}

/// Creates `dir` (owner-only) or checks an existing one: a symlink or a
/// non-directory is refused, and an existing directory is tightened to 0700.
fn private_dir(dir: &Path) -> R<()> {
    match fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(Failure::unsafe_path(dir, "is a symlink"));
        }
        Ok(m) if !m.is_dir() => return Err(Failure::unsafe_path(dir, "is not a directory")),
        Ok(m) => {
            if m.permissions().mode() & 0o777 != 0o700 {
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
                    Failure::io(format!("cannot set mode 0700 on {}", dir.display()), e)
                })?;
            }
            return Ok(());
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(Failure::io(format!("cannot inspect {}", dir.display()), e)),
    }
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        // Created by a concurrent resh: check it again.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return private_dir_existing(dir),
        Err(e) => return Err(Failure::io(format!("cannot create {}", dir.display()), e)),
    }
    // The umask can only remove bits from 0700; set it exactly anyway.
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| Failure::io(format!("cannot set mode 0700 on {}", dir.display()), e))
}

fn private_dir_existing(dir: &Path) -> R<()> {
    match fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => Err(Failure::unsafe_path(dir, "is a symlink")),
        Ok(m) if !m.is_dir() => Err(Failure::unsafe_path(dir, "is not a directory")),
        Ok(_) => Ok(()),
        Err(e) => Err(Failure::io(format!("cannot inspect {}", dir.display()), e)),
    }
}

/// Opens a file inside the queue for reading without following a symlink.
fn open_nofollow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

fn timed_out(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|d| Instant::now() >= d)
}

/// The exclusive queue lock: an `flock` on `.seq`, released when dropped
/// (or by the kernel when the process dies). The file also holds the next
/// message number.
struct QueueLock {
    file: File,
}

impl QueueLock {
    /// Reads the stored next message number, if the file holds a valid one.
    fn stored_next(&self) -> io::Result<Option<u64>> {
        let mut buf = [0u8; 32];
        let n = self.file.read_at(&mut buf, 0)?;
        Ok(std::str::from_utf8(&buf[..n])
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|n| *n > 0))
    }

    fn store_next(&self, next: u64) -> io::Result<()> {
        let text = format!("{next:020}\n");
        self.file.write_all_at(text.as_bytes(), 0)?;
        self.file.set_len(text.len() as u64)
    }
}

/// Puts `data` on queue `name` in the mq store at `root` (normally
/// `<state dir>/resh/mq`) through the same code path as `mq://<name>.put`,
/// waiting for the queue lock until `deadline`. Used by the event handle's
/// mq hook. The error is `[mq.<code>] <message>`.
pub(crate) fn put_data(
    root: &Path,
    name: &str,
    data: &str,
    deadline: Option<Instant>,
) -> std::result::Result<(), String> {
    validate_name(name)?;
    let h = MQHandle {
        name: name.to_string(),
        root: Some(root.to_path_buf()),
    };
    let mut args = Args::new();
    args.insert("data".to_string(), data.to_string());
    let (mut stdin, mut out, mut err) = (io::empty(), io::sink(), io::sink());
    let mut streams = IoStreams {
        stdin: &mut stdin,
        stdout: &mut out,
        stderr: &mut err,
    };
    h.put(&args, deadline, &mut streams)
        .map_err(|f| format!("[{}] {}", f.code, f.message))
}

// ---------------------------------------------------------------------------
// The handle
// ---------------------------------------------------------------------------

pub struct MQHandle {
    name: String,
    /// `<state dir>/resh/mq`, or None when there is no state directory.
    root: Option<PathBuf>,
}

/// Where a queue's files are.
struct Paths {
    queue: PathBuf,
    lock: PathBuf,
    tmp: PathBuf,
    inflight: PathBuf,
}

impl MQHandle {
    pub fn from_url(u: &Url) -> Result<Self> {
        let name = queue_name(u).map_err(anyhow::Error::msg)?;
        Ok(Self {
            name,
            root: store_root(),
        })
    }

    #[cfg(test)]
    fn at(root: Option<PathBuf>, name: &str) -> Self {
        Self {
            name: name.to_string(),
            root,
        }
    }

    fn paths(&self) -> R<Paths> {
        let Some(root) = &self.root else {
            return Err(Failure::new(
                exit::FAILED,
                "mq.no_state_dir",
                "cannot determine the state directory (set XDG_STATE_HOME to an absolute path \
                 or HOME); nothing was done",
            ));
        };
        let queue = root.join(&self.name);
        Ok(Paths {
            lock: queue.join(".seq"),
            tmp: queue.join(".tmp"),
            inflight: queue.join("_inflight"),
            queue,
        })
    }

    /// Creates (or checks) the store and the queue's directories.
    fn ensure(&self, p: &Paths) -> R<()> {
        let root = p.queue.parent().expect("queue has a parent");
        // The directories above the mq root are created owner-only too;
        // existing ones are left as they are.
        if let Some(parent) = root.parent()
            && !parent.exists()
        {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|e| Failure::io(format!("cannot create {}", parent.display()), e))?;
        }
        for dir in [root, &p.queue, &p.tmp, &p.inflight] {
            private_dir(dir)?;
        }
        Ok(())
    }

    /// True if the queue directory exists; a symlink in its place is refused.
    fn queue_exists(&self, p: &Paths) -> R<bool> {
        let root = p.queue.parent().expect("queue has a parent");
        for dir in [root, &p.queue] {
            match fs::symlink_metadata(dir) {
                Ok(m) if m.file_type().is_symlink() => {
                    return Err(Failure::unsafe_path(dir, "is a symlink"));
                }
                Ok(m) if !m.is_dir() => {
                    return Err(Failure::unsafe_path(dir, "is not a directory"));
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
                Err(e) => return Err(Failure::io(format!("cannot inspect {}", dir.display()), e)),
            }
        }
        Ok(true)
    }

    /// Takes the queue lock only if it is free now.
    fn try_lock(&self, p: &Paths) -> R<Option<QueueLock>> {
        let file = Self::open_lock(p)?;
        loop {
            // SAFETY: a valid open descriptor owned by `file`.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Some(QueueLock { file }));
            }
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EWOULDBLOCK) => return Ok(None),
                _ => return Err(Failure::io("cannot lock the queue", e)),
            }
        }
    }

    fn open_lock(p: &Paths) -> R<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&p.lock)
            .map_err(|e| {
                if e.raw_os_error() == Some(libc::ELOOP) {
                    Failure::unsafe_path(&p.lock, "is a symlink")
                } else {
                    Failure::io(
                        format!("cannot open the queue lock {}", p.lock.display()),
                        e,
                    )
                }
            })
    }

    /// Takes the queue lock, waiting until `deadline` (no limit if None).
    fn lock(&self, p: &Paths, deadline: Option<Instant>, verb: &str) -> R<QueueLock> {
        let file = Self::open_lock(p)?;
        let fd = file.as_raw_fd();
        let started = Instant::now();
        let mut pause = Duration::from_millis(1);
        loop {
            let flags = if deadline.is_some() {
                libc::LOCK_EX | libc::LOCK_NB
            } else {
                libc::LOCK_EX
            };
            // SAFETY: fd is a valid open descriptor owned by `file`.
            if unsafe { libc::flock(fd, flags) } == 0 {
                break;
            }
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EWOULDBLOCK) => {
                    if timed_out(deadline) {
                        return Err(Failure::new(
                            exit::TIMEOUT,
                            "mq.timeout",
                            format!(
                                "mq {verb}: timed out after {} ms waiting for the lock on \
                                 queue {:?} (another process holds it); nothing was done",
                                started.elapsed().as_millis(),
                                self.name
                            ),
                        ));
                    }
                    let left = deadline
                        .map(|d| d.saturating_duration_since(Instant::now()))
                        .unwrap_or(pause);
                    std::thread::sleep(pause.min(left));
                    pause = (pause * 2).min(Duration::from_millis(20));
                }
                _ => return Err(Failure::io("cannot lock the queue", e)),
            }
        }
        // Keep the lock file owner-only even if an older resh created it.
        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
        Ok(QueueLock { file })
    }

    /// Queued messages by number, oldest first.
    fn list_messages(dir: &Path) -> R<Vec<(u64, String)>> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(Failure::io(format!("cannot read {}", dir.display()), e)),
        };
        for entry in entries {
            let entry =
                entry.map_err(|e| Failure::io(format!("cannot read {}", dir.display()), e))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(n) = message_number(name) else {
                continue;
            };
            // Only regular files are messages (a planted symlink is not).
            match entry.file_type() {
                Ok(t) if t.is_file() => out.push((n, name.to_string())),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(Failure::io(format!("cannot read {}", dir.display()), e)),
            }
        }
        out.sort_unstable();
        Ok(out)
    }

    /// The next free message number: one past the highest number queued or
    /// in flight. Used when `.seq` is missing or damaged (a queue made by an
    /// older resh, whose numbers are put times in nanoseconds).
    fn recompute_next(p: &Paths) -> R<u64> {
        let mut max = 0;
        if let Some((n, _)) = Self::list_messages(&p.queue)?.last() {
            max = *n;
        }
        for c in list_claims(&p.inflight)? {
            max = max.max(c.number);
        }
        max.checked_add(1).ok_or_else(|| {
            Failure::new(exit::FAILED, "mq.io_error", "message numbers are exhausted")
        })
    }

    // -- verbs --------------------------------------------------------------

    fn create(&self) -> R<()> {
        let p = self.paths()?;
        self.ensure(&p)
    }

    /// Moves messages whose claiming `get` no longer runs back into the
    /// queue under their original numbers, so they are next in line.
    /// Must be called with the queue lock held. Returns how many moved.
    fn recover_stale(p: &Paths, _lock: &QueueLock) -> R<usize> {
        let mut moved = 0;
        for c in list_claims(&p.inflight)? {
            if c.claimer_alive() {
                continue;
            }
            let dest = p.queue.join(message_file_name(c.number));
            if fs::symlink_metadata(&dest).is_ok() {
                continue; // never overwrite a queued message
            }
            fs::rename(p.inflight.join(&c.name), &dest).map_err(|e| {
                Failure::io(
                    format!(
                        "cannot return the in-flight message {} to the queue",
                        c.name
                    ),
                    e,
                )
            })?;
            moved += 1;
        }
        if moved > 0 {
            sync_dir(&p.queue).map_err(|e| Failure::io("cannot sync the queue directory", e))?;
        }
        Ok(moved)
    }

    /// For the verbs that never wait (len, peek): returns stale in-flight
    /// messages to the queue if the lock is free now. Returns the stale
    /// claims that could not be returned because the lock was busy.
    fn recover_if_free(&self, p: &Paths) -> R<Vec<Claim>> {
        let stale: Vec<Claim> = list_claims(&p.inflight)?
            .into_iter()
            .filter(|c| !c.claimer_alive())
            .collect();
        if stale.is_empty() {
            return Ok(stale);
        }
        match self.try_lock(p)? {
            Some(lock) => {
                Self::recover_stale(p, &lock)?;
                Ok(Vec::new())
            }
            None => Ok(stale),
        }
    }

    fn len(&self, io: &mut IoStreams) -> R<()> {
        let p = self.paths()?;
        let n = if self.queue_exists(&p)? {
            // Messages of dead consumers count as waiting: they are
            // delivered again.
            let busy = self.recover_if_free(&p)?;
            Self::list_messages(&p.queue)?.len() + busy.len()
        } else {
            0
        };
        write!(io.stdout, "{n}").map_err(|e| Failure::io("cannot write to stdout", e))
    }

    fn empty(&self, verb: &str) -> Failure {
        Failure::new(
            exit::FAILED,
            "mq.empty",
            format!("mq {verb}: queue {:?} is empty", self.name),
        )
    }

    fn peek(&self, io: &mut IoStreams) -> R<()> {
        let p = self.paths()?;
        if !self.queue_exists(&p)? {
            return Err(self.empty("peek"));
        }
        // Only a quick, non-waiting lock to return stale in-flight
        // messages; otherwise no lock: a message taken by a get between
        // listing and opening is skipped and the listing repeated.
        let mut stale = self.recover_if_free(&p)?;
        loop {
            // A stale claim that could not be returned (the lock was busy)
            // is still the next message a get delivers when its number is
            // the lowest, as len counts it: peek shows it where it is.
            let queued = Self::list_messages(&p.queue)?
                .into_iter()
                .next()
                .map(|(n, name)| (n, p.queue.join(name)));
            let claimed = stale.first().map(|c| (c.number, p.inflight.join(&c.name)));
            let next = match (queued, claimed) {
                (Some(q), Some(c)) => Some(if c.0 < q.0 { c } else { q }),
                (q, c) => q.or(c),
            };
            let Some((_, path)) = next else {
                return Err(self.empty("peek"));
            };
            let mut f = match open_nofollow(&path) {
                Ok(f) => f,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    // Taken by a get, or returned to the queue meanwhile.
                    stale = list_claims(&p.inflight)?
                        .into_iter()
                        .filter(|c| !c.claimer_alive())
                        .collect();
                    continue;
                }
                Err(e) => return Err(Failure::io(format!("cannot read {}", path.display()), e)),
            };
            return copy_out(&mut f, io.stdout, &path);
        }
    }

    fn put(&self, args: &Args, deadline: Option<Instant>, io: &mut IoStreams) -> R<()> {
        let p = self.paths()?;
        self.ensure(&p)?;

        // 1. Write and sync the message under a private temporary name.
        let tmp = p.tmp.join(format!(
            "{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)
            .map_err(|e| Failure::io(format!("cannot create {}", tmp.display()), e))?;
        let written = match args.get("data") {
            Some(data) => f
                .write_all(data.as_bytes())
                .map_err(|e| Failure::io(format!("cannot write {}", tmp.display()), e)),
            None => copy_in(io.stdin, &mut f, &tmp),
        }
        .and_then(|_| {
            f.sync_all()
                .map_err(|e| Failure::io(format!("cannot sync {}", tmp.display()), e))
        });
        drop(f);
        if let Err(e) = written {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }

        // 2. Number it and move it into the queue, holding the lock.
        let result = (|| {
            let lock = self.lock(&p, deadline, "put")?;
            let mut n = match lock
                .stored_next()
                .map_err(|e| Failure::io("cannot read the queue's message counter", e))?
            {
                Some(n) => n,
                None => Self::recompute_next(&p)?,
            };
            // A counter that went backwards (damaged, or lost in a crash) must
            // never overwrite a message.
            if fs::symlink_metadata(p.queue.join(message_file_name(n))).is_ok()
                || fs::symlink_metadata(p.inflight.join(message_file_name(n))).is_ok()
            {
                n = n.max(Self::recompute_next(&p)?);
            }
            let next = n.checked_add(1).ok_or_else(|| {
                Failure::new(exit::FAILED, "mq.io_error", "message numbers are exhausted")
            })?;
            lock.store_next(next)
                .map_err(|e| Failure::io("cannot update the queue's message counter", e))?;
            let dest = p.queue.join(message_file_name(n));
            fs::rename(&tmp, &dest).map_err(|e| {
                Failure::io(format!("cannot move the message to {}", dest.display()), e)
            })?;
            sync_dir(&p.queue).map_err(|e| {
                Failure::io(
                    format!("message {n} was queued but the queue directory could not be synced"),
                    e,
                )
            })?;
            drop(lock);
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }

    fn get(&self, wait: bool, deadline: Option<Instant>, io: &mut IoStreams) -> R<()> {
        let p = self.paths()?;
        if !self.queue_exists(&p)? {
            if !wait {
                return Err(self.empty("get"));
            }
            // Waiting needs a directory to watch.
            self.ensure(&p)?;
        }
        private_dir(&p.inflight)?;
        let started = Instant::now();
        // Set up before the first look, so a put between the look and the
        // wait still wakes us.
        let mut waker = if wait {
            Some(Waker::new(&p.queue))
        } else {
            None
        };

        // Claim the oldest message: move it to _inflight under a name that
        // records this process, and open it, while holding the lock, so no
        // other get can take it.
        let (queued, claimed, mut f) = loop {
            let lock = self.lock(&p, deadline, "get")?;
            Self::recover_stale(&p, &lock)?;
            if let Some((n, name)) = Self::list_messages(&p.queue)?.into_iter().next() {
                let queued = p.queue.join(&name);
                let claimed = p.inflight.join(claim_file_name(n));
                fs::rename(&queued, &claimed)
                    .map_err(|e| Failure::io(format!("cannot claim {}", queued.display()), e))?;
                match open_nofollow(&claimed) {
                    Ok(f) => break (queued, claimed, f),
                    Err(e) => {
                        let _ = fs::rename(&claimed, &queued);
                        return Err(Failure::io(format!("cannot read {}", claimed.display()), e));
                    }
                }
            }
            drop(lock);
            let Some(w) = waker.as_mut() else {
                return Err(self.empty("get"));
            };
            if timed_out(deadline) {
                return Err(Failure::new(
                    exit::TIMEOUT,
                    "mq.timeout",
                    format!(
                        "mq get: no message arrived in queue {:?} within {} ms; nothing was \
                         taken",
                        self.name,
                        started.elapsed().as_millis()
                    ),
                ));
            }
            w.wait(deadline);
        };

        if let Err(e) = copy_out(&mut f, io.stdout, &claimed) {
            // Not delivered: put it back at the head of the queue.
            let back = self.lock(&p, None, "get").and_then(|_lock| {
                if fs::symlink_metadata(&queued).is_ok() {
                    return Err(Failure::io(
                        "cannot put the message back",
                        io::Error::from(io::ErrorKind::AlreadyExists),
                    ));
                }
                fs::rename(&claimed, &queued)
                    .map_err(|e| Failure::io("cannot put the message back", e))
            });
            return Err(match back {
                Ok(()) => Failure::new(
                    e.exit,
                    e.code,
                    format!("{}; the message was put back in the queue", e.message),
                ),
                Err(b) => Failure::new(
                    e.exit,
                    e.code,
                    format!(
                        "{}; {} - it is left in {}",
                        e.message,
                        b.message,
                        claimed.display()
                    ),
                ),
            });
        }
        match fs::remove_file(&claimed) {
            Ok(()) => {}
            // Deleted by a concurrent purge.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                // Delivered; the leftover copy is never returned again.
                let _ = writeln!(
                    io.stderr,
                    "Warning: message delivered, but its in-flight copy {} could not be \
                     deleted: {e}",
                    claimed.display()
                );
            }
        }
        Ok(())
    }

    fn purge(&self, deadline: Option<Instant>) -> R<()> {
        let p = self.paths()?;
        if !self.queue_exists(&p)? {
            return Ok(());
        }
        let lock = self.lock(&p, deadline, "purge")?;
        let mut deleted = 0usize;
        for dir in [&p.queue, &p.inflight] {
            let entries = match fs::read_dir(dir) {
                Ok(e) => e,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(Failure::io(format!("cannot read {}", dir.display()), e)),
            };
            for entry in entries {
                let entry =
                    entry.map_err(|e| Failure::io(format!("cannot read {}", dir.display()), e))?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                // Messages, claimed messages, and the partial `tmp-<ns>.msg`
                // files older resh versions could leave behind.
                if !(name.ends_with(".msg") || name.ends_with(".claim"))
                    || entry.file_type().is_ok_and(|t| t.is_dir())
                {
                    continue;
                }
                if timed_out(deadline) {
                    return Err(Failure::new(
                        exit::TIMEOUT,
                        "mq.timeout",
                        format!(
                            "mq purge: timed out after deleting {deleted} messages from queue \
                             {:?}; the rest are still queued",
                            self.name
                        ),
                    ));
                }
                match fs::remove_file(entry.path()) {
                    Ok(()) => deleted += 1,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => {
                        return Err(Failure::io(
                            format!("cannot delete {}", entry.path().display()),
                            e,
                        ));
                    }
                }
            }
        }
        remove_abandoned_temps(&p.tmp);
        drop(lock);
        Ok(())
    }

    /// Writes the approved help for `help`, `--help`, `-h`, `--help=<verb>`,
    /// `help(verb=<verb>)`, or a `help`/`h` argument; returns None otherwise.
    fn check_and_display_help(
        &self,
        verb: &str,
        args: &Args,
        io: &mut IoStreams,
    ) -> Result<Option<Status>> {
        let help_verb = if let Some(v) = verb.strip_prefix("--help=") {
            Some(v.to_string())
        } else if help::HELP_ALIASES.contains(&verb)
            || ["help", "h", "--help", "-h"]
                .iter()
                .any(|k| args.contains_key(*k))
        {
            let is_verb = |v: &str| MQ_HELP.verbs.iter().any(|h| h.name == v);
            args.get("verb")
                .cloned()
                .or_else(|| args.get("help").filter(|v| is_verb(v)).cloned())
                // `mq://q.put(help=1)`: help for the verb being called.
                .or_else(|| is_verb(verb).then(|| verb.to_string()))
        } else {
            return Ok(None);
        };
        write!(
            io.stdout,
            "{}",
            help::render_legacy("mq", &MQ_HELP, self.verbs(), help_verb.as_deref())
        )?;
        Ok(Some(Status::ok()))
    }

    fn run(&self, verb: &str, args: &Args, io: &mut IoStreams) -> R<()> {
        let Some(allowed) = verb_args(verb) else {
            let verbs = ["len", "peek", "create", "put", "get", "purge"];
            let hint = suggest(verb, &verbs)
                .map(|s| format!(" (did you mean `{s}`?)"))
                .unwrap_or_default();
            return Err(Failure::usage(format!(
                "unknown mq verb {verb:?}{hint}; verbs: {}",
                verbs.join(", ")
            )));
        };
        check_args(verb, allowed, args)?;
        let wait = if verb == "get" {
            crate::core::lenient::bool_arg(args, "wait")
                .map_err(|e| Failure::usage(format!("{e}; nothing was done")))?
                .unwrap_or(false)
        } else {
            false
        };
        let deadline = deadline_arg(args, wait)?;
        match verb {
            "len" => self.len(io),
            "peek" => self.peek(io),
            "create" => self.create(),
            "put" => self.put(args, deadline, io),
            "get" => self.get(wait, deadline, io),
            "purge" => self.purge(deadline),
            _ => unreachable!("verb_args lists every verb"),
        }
    }
}

/// Streams `src` to stdout and flushes it.
fn copy_out(src: &mut File, out: &mut dyn Write, path: &Path) -> R<()> {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Failure::io(format!("cannot read {}", path.display()), e)),
        };
        out.write_all(&buf[..n])
            .map_err(|e| Failure::io("cannot write the message to stdout", e))?;
    }
    out.flush()
        .map_err(|e| Failure::io("cannot write the message to stdout", e))
}

/// Streams stdin into the message file, so a large message is never held
/// in memory.
fn copy_in(stdin: &mut dyn Read, dest: &mut File, path: &Path) -> R<()> {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match stdin.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Failure::io("cannot read the message from stdin", e)),
        };
        dest.write_all(&buf[..n])
            .map_err(|e| Failure::io(format!("cannot write {}", path.display()), e))?;
    }
}

/// Deletes temporary files in `.tmp` whose writing process no longer
/// exists (a put that was killed). Files of running puts are kept.
fn remove_abandoned_temps(tmp: &Path) {
    let Ok(entries) = fs::read_dir(tmp) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|n| n.split_once('-'))
            .and_then(|(pid, _)| pid.parse::<libc::pid_t>().ok())
        else {
            continue;
        };
        // SAFETY: kill with signal 0 only checks that the process exists.
        let gone = unsafe { libc::kill(pid, 0) } != 0
            && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        if gone {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// The name of a claimed message in `_inflight`:
/// `<number>.<pid>.<start time>.claim`, recording the claiming process so a
/// later get can tell whether it still runs (the start time defeats PID
/// reuse).
fn claim_file_name(n: u64) -> String {
    let (pid, start) = self_identity();
    format!("{n:020}.{pid}.{start}.claim")
}

/// This process: PID and start time (clock ticks since boot, 0 if unknown).
fn self_identity() -> (u32, u64) {
    static ID: std::sync::OnceLock<(u32, u64)> = std::sync::OnceLock::new();
    *ID.get_or_init(|| {
        let pid = std::process::id();
        let start = match proc_stat(pid) {
            ProcState::Running(start) => start,
            _ => 0,
        };
        (pid, start)
    })
}

enum ProcState {
    /// Running (or stopped) with this start time.
    Running(u64),
    /// No such process, or a zombie that has already exited.
    Gone,
    /// /proc cannot be read: assume it runs.
    Unknown,
}

/// Reads state and start time (fields 3 and 22) from /proc/<pid>/stat.
fn proc_stat(pid: u32) -> ProcState {
    let text = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return ProcState::Gone,
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => return ProcState::Gone,
        Err(_) => return ProcState::Unknown,
    };
    // The command name (field 2) is in parentheses and may contain spaces.
    let Some(rest) = text.rfind(')').map(|i| &text[i + 1..]) else {
        return ProcState::Unknown;
    };
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // fields[0] is field 3 (state); field 22 is fields[19].
    match (fields.first(), fields.get(19).and_then(|s| s.parse().ok())) {
        (Some(&"Z") | Some(&"X") | Some(&"x"), _) => ProcState::Gone,
        (Some(_), Some(start)) => ProcState::Running(start),
        _ => ProcState::Unknown,
    }
}

/// A message in `_inflight`.
struct Claim {
    number: u64,
    name: String,
    /// The claiming process; None for a file an older resh left (`<n>.msg`),
    /// whose claimer is unknown.
    claimer: Option<(u32, u64)>,
}

impl Claim {
    fn claimer_alive(&self) -> bool {
        let Some((pid, start)) = self.claimer else {
            return false;
        };
        match proc_stat(pid) {
            ProcState::Gone => false,
            ProcState::Unknown => true,
            // A start time of 0 means the claimer could not read its own.
            ProcState::Running(now) => start == 0 || now == start,
        }
    }
}

fn parse_claim(name: &str) -> Option<Claim> {
    if let Some(n) = message_number(name) {
        return Some(Claim {
            number: n,
            name: name.to_string(),
            claimer: None,
        });
    }
    let stem = name.strip_suffix(".claim")?;
    let mut parts = stem.split('.');
    let (num, pid, start) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || num.len() != 20 || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(Claim {
        number: num.parse().ok()?,
        name: name.to_string(),
        claimer: Some((pid.parse().ok()?, start.parse().ok()?)),
    })
}

/// Claimed messages in `_inflight` (regular files only), oldest first.
fn list_claims(dir: &Path) -> R<Vec<Claim>> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(Failure::io(format!("cannot read {}", dir.display()), e)),
    };
    for entry in entries {
        let entry = entry.map_err(|e| Failure::io(format!("cannot read {}", dir.display()), e))?;
        let name = entry.file_name();
        let Some(c) = name.to_str().and_then(parse_claim) else {
            continue;
        };
        if entry.file_type().is_ok_and(|t| t.is_file()) {
            out.push(c);
        }
    }
    out.sort_unstable_by_key(|c| c.number);
    Ok(out)
}

/// Wakes a waiting get when the queue directory changes (inotify through
/// the notify crate), and in any case every POLL, which also catches
/// in-flight messages whose consumer died. Without a watcher it polls.
struct Waker {
    rx: Option<std::sync::mpsc::Receiver<()>>,
    _watcher: Option<notify::RecommendedWatcher>,
}

impl Waker {
    const POLL: Duration = Duration::from_millis(500);
    const POLL_WITHOUT_WATCHER: Duration = Duration::from_millis(50);

    fn new(dir: &Path) -> Self {
        use notify::Watcher;
        let (tx, rx) = std::sync::mpsc::channel();
        let watcher = notify::RecommendedWatcher::new(
            move |res: notify::Result<notify::Event>| {
                if res.is_ok() {
                    let _ = tx.send(());
                }
            },
            notify::Config::default(),
        )
        .and_then(|mut w| {
            w.watch(dir, notify::RecursiveMode::NonRecursive)
                .map(|()| w)
        });
        match watcher {
            Ok(w) => Self {
                rx: Some(rx),
                _watcher: Some(w),
            },
            Err(_) => Self {
                rx: None,
                _watcher: None,
            },
        }
    }

    /// Waits for a change, the poll interval, or the deadline.
    fn wait(&mut self, deadline: Option<Instant>) {
        let poll = if self.rx.is_some() {
            Self::POLL
        } else {
            Self::POLL_WITHOUT_WATCHER
        };
        let left = deadline
            .map(|d| d.saturating_duration_since(Instant::now()))
            .unwrap_or(poll)
            .min(poll);
        match &self.rx {
            Some(rx) => {
                if rx.recv_timeout(left).is_ok() {
                    while rx.try_recv().is_ok() {}
                }
            }
            None => std::thread::sleep(left),
        }
    }
}

impl Handle for MQHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &[
            "create", "put", "get", "len", "purge", "peek", "help", "--help", "-h",
        ]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&MQ_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        if let Some(status) = self.check_and_display_help(verb, args, io)? {
            return Ok(status);
        }
        Ok(match self.run(verb, args, io) {
            Ok(()) => Status::ok(),
            Err(f) => f.into_status(),
        })
    }
}
