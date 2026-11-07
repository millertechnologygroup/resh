//! Error codes, argument parsing and small helpers shared by the file verbs.
//!
//! Every failure of a file verb is reported as `<CODE>: <message>` in the
//! status reason, with an exit code that depends only on the code (see
//! [`Code::exit`]). Verbs return `anyhow::Result`; [`status_of`] turns any
//! error into that form, classifying I/O errors by their kind.

use super::FILE_HELP;
use crate::core::{Args, Status};
use percent_encoding::percent_decode_str;
use std::fmt;
use std::path::{Component, Path, PathBuf};

/// The documented error codes of the file handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Code {
    /// Missing, unknown, malformed or conflicting argument; unknown verb.
    InvalidArg,
    /// The path (or the source, or a path component) does not exist.
    NotFound,
    /// The extended attribute does not exist (`ea.get`, `ea.set mode=update`).
    AttrNotFound,
    /// The operating system refused the operation (EACCES, EPERM).
    PermissionDenied,
    /// The destination (or extended attribute) already exists.
    AlreadyExists,
    /// The verb needs a file but the path is a directory, or a directory
    /// needs `recursive=true`.
    IsADirectory,
    /// The path is not a regular file (a FIFO, socket or device).
    NotAFile,
    /// `grep` found no matching line.
    NoMatch,
    /// `verify` computed a digest or size different from the expected one.
    VerifyFailed,
    /// The file is larger than the 10 GiB hashing limit.
    TooLarge,
    /// `replace` needs a UTF-8 text file.
    NotUtf8,
    /// `schema` could not parse the sample in the requested format.
    ParseError,
    /// The filesystem does not support the operation (extended attributes).
    Unsupported,
    /// The operation is refused for safety (deleting `/`, `.` or `..`;
    /// moving a directory into itself).
    Refused,
    /// Part of the work was done before a failure; the message says what.
    Partial,
    /// Any other I/O failure.
    IoError,
    /// `timeout_ms` passed before the work was done; the message says what
    /// was done, and partial output files were removed.
    Timeout,
}

impl Code {
    #[cfg(test)]
    pub(crate) const ALL: &'static [Code] = &[
        Code::InvalidArg,
        Code::NotFound,
        Code::AttrNotFound,
        Code::PermissionDenied,
        Code::AlreadyExists,
        Code::IsADirectory,
        Code::NotAFile,
        Code::NoMatch,
        Code::VerifyFailed,
        Code::TooLarge,
        Code::NotUtf8,
        Code::ParseError,
        Code::Unsupported,
        Code::Refused,
        Code::Partial,
        Code::IoError,
        Code::Timeout,
    ];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Code::InvalidArg => "INVALID_ARG",
            Code::NotFound => "NOT_FOUND",
            Code::AttrNotFound => "ATTR_NOT_FOUND",
            Code::PermissionDenied => "PERMISSION_DENIED",
            Code::AlreadyExists => "ALREADY_EXISTS",
            Code::IsADirectory => "IS_A_DIRECTORY",
            Code::NotAFile => "NOT_A_FILE",
            Code::NoMatch => "NO_MATCH",
            Code::VerifyFailed => "VERIFY_FAILED",
            Code::TooLarge => "TOO_LARGE",
            Code::NotUtf8 => "NOT_UTF8",
            Code::ParseError => "PARSE_ERROR",
            Code::Unsupported => "UNSUPPORTED",
            Code::Refused => "REFUSED",
            Code::Partial => "PARTIAL",
            Code::IoError => "IO_ERROR",
            Code::Timeout => "TIMEOUT",
        }
    }

    /// Exit code, as for every handle: 2 for invalid usage (nothing was
    /// done), 124 for a timeout, 1 for every other operation failure.
    pub(crate) fn exit(self) -> i32 {
        match self {
            Code::InvalidArg => 2,
            Code::Timeout => 124,
            _ => 1,
        }
    }
}

/// A classified failure. Wrapped in `anyhow::Error` so verbs can use `?`.
#[derive(Debug)]
pub(crate) struct Fail {
    pub(crate) code: Code,
    pub(crate) msg: String,
}

impl fmt::Display for Fail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.name(), self.msg)
    }
}

impl std::error::Error for Fail {}

pub(crate) fn fail(code: Code, msg: impl Into<String>) -> anyhow::Error {
    Fail {
        code,
        msg: msg.into(),
    }
    .into()
}

pub(crate) fn invalid(msg: impl Into<String>) -> anyhow::Error {
    fail(Code::InvalidArg, msg)
}

/// The error code for an operating-system error.
pub(crate) fn io_code(e: &std::io::Error) -> Code {
    use std::io::ErrorKind as K;
    match e.raw_os_error() {
        Some(libc::ENODATA) => return Code::AttrNotFound,
        Some(libc::EOPNOTSUPP) => return Code::Unsupported,
        Some(libc::EPERM) | Some(libc::EACCES) => return Code::PermissionDenied,
        _ => {}
    }
    match e.kind() {
        K::NotFound | K::NotADirectory => Code::NotFound,
        K::PermissionDenied => Code::PermissionDenied,
        K::AlreadyExists => Code::AlreadyExists,
        K::IsADirectory => Code::IsADirectory,
        K::Unsupported => Code::Unsupported,
        K::TimedOut => Code::Timeout,
        _ => Code::IoError,
    }
}

/// A failure for an I/O error, with `what` naming the operation and path.
pub(crate) fn io_fail(what: impl fmt::Display, e: &std::io::Error) -> anyhow::Error {
    fail(io_code(e), format!("{what}: {e}"))
}

/// Converts any verb error into the failed status the CLI reports.
pub(crate) fn status_of(e: &anyhow::Error) -> Status {
    if let Some(f) = e.chain().find_map(|c| c.downcast_ref::<Fail>()) {
        return Status::err(f.code.exit(), f.to_string());
    }
    let code = e
        .chain()
        .find_map(|c| c.downcast_ref::<std::io::Error>())
        .map(io_code)
        .unwrap_or(Code::IoError);
    Status::err(code.exit(), format!("{}: {:#}", code.name(), e))
}

/// The options a verb accepts: every `name=` in its help usage. The help
/// text is the single list, so the usage and the parser cannot drift apart.
pub(crate) fn verb_options(verb: &str) -> Vec<&'static str> {
    let Some(usage) = FILE_HELP
        .verbs
        .iter()
        .find(|v| v.name == verb)
        .and_then(|v| v.detail.as_ref())
        .map(|d| d.usage)
    else {
        return Vec::new();
    };
    let bytes = usage.as_bytes();
    let mut out: Vec<&'static str> = Vec::new();
    for (i, b) in bytes.iter().enumerate() {
        if *b != b'=' {
            continue;
        }
        let mut start = i;
        while start > 0
            && (bytes[start - 1].is_ascii_lowercase()
                || bytes[start - 1].is_ascii_digit()
                || bytes[start - 1] == b'_')
        {
            start -= 1;
        }
        let preceded_ok = start == 0 || matches!(bytes[start - 1], b'[' | b' ' | b'\n');
        if start < i && preceded_ok {
            let name = &usage[start..i];
            if !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

/// The accepted option closest to a mistyped `key`: edit distance of at
/// most 2 (ignoring case, `-` and `_`), or one being a prefix of the other.
pub(crate) fn suggest(key: &str, known: &[&'static str]) -> Option<&'static str> {
    let norm = |s: &str| s.to_ascii_lowercase().replace(['-', '_'], "");
    let k = norm(key);
    known
        .iter()
        .map(|o| {
            let n = norm(o);
            let d = edit_distance(&k, &n);
            let prefix = k.len() >= 3 && (n.starts_with(&k) || k.starts_with(&n));
            (if prefix { d.min(1) } else { d }, *o)
        })
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, o)| o)
}

fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let sub = prev[j] + usize::from(ca != *cb);
            cur.push(sub.min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

/// The arguments of one verb call, checked against the verb's options.
pub(crate) struct Opts<'a> {
    verb: &'a str,
    args: &'a Args,
}

impl<'a> Opts<'a> {
    /// Rejects any argument the verb does not take (including `dry_run` and
    /// `timeout_ms` on verbs without them), suggesting the closest option.
    pub(crate) fn new(verb: &'a str, args: &'a Args) -> anyhow::Result<Self> {
        let known = verb_options(verb);
        let mut unknown: Vec<&String> = args
            .keys()
            .filter(|k| !known.contains(&k.as_str()))
            .collect();
        unknown.sort();
        if let Some(k) = unknown.first() {
            let hint = suggest(k, &known)
                .map(|s| format!(" (did you mean {s}?)"))
                .unwrap_or_default();
            let accepted = if known.is_empty() {
                format!("file {verb} takes no arguments")
            } else {
                format!("file {verb} accepts: {}", known.join(", "))
            };
            return Err(invalid(format!(
                "unknown argument {k:?}{hint}; {accepted}; nothing was done"
            )));
        }
        Ok(Opts { verb, args })
    }

    pub(crate) fn verb(&self) -> &'a str {
        self.verb
    }

    pub(crate) fn has(&self, key: &str) -> bool {
        self.args.contains_key(key)
    }

    pub(crate) fn get(&self, key: &str) -> Option<&'a str> {
        self.args.get(key).map(String::as_str)
    }

    pub(crate) fn required(&self, key: &str) -> anyhow::Result<&'a str> {
        self.get(key)
            .ok_or_else(|| invalid(format!("missing argument {key}=")))
    }

    pub(crate) fn required_nonempty(&self, key: &str) -> anyhow::Result<&'a str> {
        let v = self.required(key)?;
        if v.is_empty() {
            return Err(invalid(format!("{key}= must not be empty")));
        }
        Ok(v)
    }

    /// A boolean: `true|false|1|0|yes|no|on|off`, case-insensitive.
    pub(crate) fn flag(&self, key: &str, default: bool) -> anyhow::Result<bool> {
        match self.get(key) {
            None => Ok(default),
            Some(v) => crate::core::lenient::parse_bool(v).ok_or_else(|| {
                invalid(format!(
                    "invalid value for {key}: {v:?} (expected true/false, 1/0, yes/no or on/off)"
                ))
            }),
        }
    }

    /// A non-negative integer of at least `min`.
    pub(crate) fn number<T>(&self, key: &str, min: T) -> anyhow::Result<Option<T>>
    where
        T: std::str::FromStr + PartialOrd + fmt::Display + Copy,
    {
        let Some(v) = self.get(key) else {
            return Ok(None);
        };
        match v.trim().parse::<T>() {
            Ok(n) if n >= min => Ok(Some(n)),
            _ => Err(invalid(format!(
                "invalid value for {key}: {v:?} (expected an integer of at least {min})"
            ))),
        }
    }

    /// One of `allowed` (case-insensitive).
    pub(crate) fn choice(
        &self,
        key: &str,
        allowed: &[&'static str],
    ) -> anyhow::Result<Option<&'static str>> {
        let Some(v) = self.get(key) else {
            return Ok(None);
        };
        let lower = v.trim().to_ascii_lowercase();
        allowed
            .iter()
            .find(|a| **a == lower)
            .copied()
            .map(Some)
            .ok_or_else(|| {
                invalid(format!(
                    "invalid value for {key}: {v:?} (expected {})",
                    allowed.join("|")
                ))
            })
    }

    /// The deadline from `timeout_ms` (milliseconds; 0 or absent means no
    /// limit).
    pub(crate) fn deadline(&self) -> anyhow::Result<Deadline> {
        let ms = self.number::<u64>("timeout_ms", 0)?.unwrap_or(0);
        Ok(Deadline::after_ms(ms))
    }

    /// An octal permission mode (`644`, `0755`, at most `7777`).
    pub(crate) fn octal_mode(&self, key: &str) -> anyhow::Result<Option<u32>> {
        let Some(v) = self.get(key) else {
            return Ok(None);
        };
        let t = v.trim();
        let ok = !t.is_empty() && t.len() <= 5 && t.bytes().all(|b| (b'0'..=b'7').contains(&b));
        match u32::from_str_radix(t, 8) {
            Ok(m) if ok && m <= 0o7777 => Ok(Some(m)),
            _ => Err(invalid(format!(
                "invalid value for {key}: {v:?} (expected an octal mode such as 644 or 0755)"
            ))),
        }
    }
}

/// Undoes `\ `, `\\`, `\t` and `\n` escapes used in URLs and `to=` paths.
pub(crate) fn unescape_backslashes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.peek() {
                Some(' ') => {
                    it.next();
                    out.push(' ');
                }
                Some('\\') => {
                    it.next();
                    out.push('\\');
                }
                Some('t') => {
                    it.next();
                    out.push('\t');
                }
                Some('n') => {
                    it.next();
                    out.push('\n');
                }
                _ => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Lexical normalization: drops `.`, folds `name/..`, keeps a leading `..`
/// on relative paths. Symlinks are never resolved.
pub(crate) fn normalize_path(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => match out.components().next_back() {
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                Some(Component::RootDir) | Some(Component::Prefix(_)) => {}
                _ => out.push(".."),
            },
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        out
    }
}

/// The destination path of a `to=` argument (percent-decoded, unescaped,
/// normalized).
pub(crate) fn dest_from_arg(to: &str) -> PathBuf {
    let decoded = percent_decode_str(to).decode_utf8_lossy().to_string();
    normalize_path(Path::new(&unescape_backslashes(&decoded)))
}

/// The directory that will contain `dest`. A bare file name (`new.txt`) has
/// an empty `Path::parent()`, which means the current directory.
pub(crate) fn dest_parent(dest: &Path) -> &Path {
    match dest.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// A unique, unpredictable hidden name in `dir` for a temporary file or
/// directory.
pub(crate) fn temp_name_in(dir: &Path, tag: &str) -> PathBuf {
    dir.join(format!(
        ".resh_{tag}_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ))
}

/// Creates a new file for an atomic write: never an existing file, never
/// through a symlink planted at the name.
pub(crate) fn create_new_file(path: &Path, mode: u32) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// Removes a temporary path when dropped unless disarmed.
pub(crate) struct TempGuard {
    path: Option<PathBuf>,
}

impl TempGuard {
    pub(crate) fn new(path: &Path) -> Self {
        TempGuard {
            path: Some(path.to_path_buf()),
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if let Some(p) = &self.path {
            match std::fs::symlink_metadata(p) {
                Ok(m) if m.is_dir() => {
                    let _ = std::fs::remove_dir_all(p);
                }
                Ok(_) => {
                    let _ = std::fs::remove_file(p);
                }
                Err(_) => {}
            }
        }
    }
}

/// Flushes a directory's entries to disk (best effort: some filesystems do
/// not support fsync on directories).
pub(crate) fn sync_dir(dir: &Path) {
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
}

/// Writes one JSON value and a newline to stdout.
pub(crate) fn emit(
    io: &mut crate::core::IoStreams,
    value: &serde_json::Value,
) -> anyhow::Result<()> {
    writeln!(io.stdout, "{value}")?;
    Ok(())
}

/// The end of a verb's time budget (`timeout_ms`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Deadline {
    at: Option<std::time::Instant>,
    ms: u64,
}

impl Deadline {
    pub(crate) fn after_ms(ms: u64) -> Self {
        Deadline {
            at: (ms > 0).then(|| std::time::Instant::now() + std::time::Duration::from_millis(ms)),
            ms,
        }
    }

    pub(crate) fn expired(&self) -> bool {
        self.at.is_some_and(|d| std::time::Instant::now() >= d)
    }

    /// Time left, or `None` without a deadline.
    pub(crate) fn remaining(&self) -> Option<std::time::Duration> {
        self.at
            .map(|d| d.saturating_duration_since(std::time::Instant::now()))
    }

    /// A TIMEOUT failure when the deadline has passed; `done` says what was
    /// already done.
    pub(crate) fn check(&self, done: impl FnOnce() -> String) -> anyhow::Result<()> {
        if self.expired() {
            return Err(self.timeout(done()));
        }
        Ok(())
    }

    pub(crate) fn timeout(&self, done: String) -> anyhow::Error {
        fail(
            Code::Timeout,
            format!("timed out after timeout_ms={}; {done}", self.ms),
        )
    }

    pub(crate) fn io_error(&self) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("timed out after timeout_ms={}", self.ms),
        )
    }
}

/// A reader that fails with `TimedOut` once the deadline passes. With `fd`
/// set (a FIFO or other file that can block), each read first waits for
/// data no longer than the time left.
pub(crate) struct DeadlineReader<R> {
    inner: R,
    deadline: Deadline,
    fd: Option<std::os::fd::RawFd>,
}

impl<R: std::io::Read> DeadlineReader<R> {
    pub(crate) fn new(inner: R, deadline: Deadline) -> Self {
        DeadlineReader {
            inner,
            deadline,
            fd: None,
        }
    }

    pub(crate) fn polling(inner: R, deadline: Deadline, fd: std::os::fd::RawFd) -> Self {
        DeadlineReader {
            inner,
            deadline,
            fd: Some(fd),
        }
    }
}

impl<R: std::io::Read> std::io::Read for DeadlineReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.deadline.expired() {
            return Err(self.deadline.io_error());
        }
        if let (Some(fd), Some(left)) = (self.fd, self.deadline.remaining()) {
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let ms = left.as_millis().clamp(1, i32::MAX as u128) as i32;
            // SAFETY: one valid pollfd for the duration of the call.
            let n = unsafe { libc::poll(&mut pfd, 1, ms) };
            if n == 0 {
                return Err(self.deadline.io_error());
            }
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() != std::io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
        }
        self.inner.read(buf)
    }
}

/// Copies `src` to `dst` in 1 MiB chunks, checking the deadline between
/// chunks. Returns the number of bytes copied.
pub(crate) fn copy_with_deadline(
    src: &mut dyn std::io::Read,
    dst: &mut dyn std::io::Write,
    deadline: Deadline,
) -> std::io::Result<u64> {
    let mut buf = vec![0u8; 1024 * 1024];
    let mut total = 0u64;
    loop {
        if deadline.expired() {
            return Err(deadline.io_error());
        }
        let n = match src.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        dst.write_all(&buf[..n])?;
        total += n as u64;
    }
}
