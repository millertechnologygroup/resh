//! `log://`: the last lines of a plain-text log file or of a systemd
//! service's journal, optionally followed as they are written.
//!
//! Files are scanned backward from the end (see `scan`), so a large file is
//! not read in full and memory stays bounded however long a line is. A
//! service journal is read with `journalctl` (see `journal`), run directly
//! with each value as its own argument. Every failure is a coded status
//! (`Error: [log.<code>] ...` on stderr, and an `"error"` object in
//! `mode=json`), with exit 1 for failures, 2 for invalid usage and 124 when
//! `timeout_ms` passes.

mod journal;
mod scan;
#[cfg(test)]
mod tests;

use anyhow::{Result, bail};
use percent_encoding::percent_decode_str;
use serde_json::{Value, json};
use std::ffi::OsString;
use std::fs::File;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use url::Url;

use crate::core::{
    help::{self, HandleHelp, VerbDetail, VerbHelp},
    lenient,
    registry::{Args, Handle, IoStreams},
    status::{Status, error_json, error_line, exit},
};

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("log", |u| Ok(Box::new(LogHandle::from_url(u)?)));
    reg.set_probe_url("log", "log:///resh-help-probe");
}

/// Metadata for `resh log --help` and `resh log <verb> --help`.
static LOG_HELP: HandleHelp = HandleHelp {
    description: "The log handle reads the most recent lines of a plain-text log file or of \
        a systemd service's journal, and can follow them as they are written. A file is \
        named by the URL path, as in log:///var/log/syslog (absolute) or log://./logs/app.log \
        (relative), and log://svc/<service> reads the service's journal through journalctl.",
    usage: "resh log://{/<path>|./<path>|svc/<service>}.<verb>[(key=value,...)]",
    verbs: &[VerbHelp {
        name: "tail",
        definition: "Prints the last lines (default 100) of a log file or service journal, \
            optionally keeping only those that contain a pattern and following new lines.",
        detail: Some(VerbDetail {
            usage: "resh log://{<path>|svc/<service>}.tail [lines=<n>] [pattern=<text>]\n  \
                [mode=raw|json] [follow=true|false] [timeout_ms=<ms>]",
            example: "resh --json-pretty log:///var/log/syslog.tail lines=2 mode=json",
            example_output: Some(
                r#"{
  "lines": [
    "Oct 16 09:12:44 host kernel: eth0: link up",
    "Oct 16 09:13:02 host app[901]: error: disk quota exceeded"
  ],
  "path": "/var/log/syslog",
  "pattern": null,
  "requested_lines": 2,
  "returned_lines": 2
}

Shown with --json-pretty. The default mode=raw prints only the lines. For
log://svc/<service> the JSON object has "service" in place of "path".
lines is 1 to 1000000; pattern keeps the lines (among those) that contain
the text. follow=true keeps printing new lines, across rotation and
truncation, until interrupted or for timeout_ms (then exit 0); with mode=json
it prints one object per line, {"source", "path"|"unit", "line", "ts"}.
timeout_ms defaults to 600000 without follow (exit 124 when it passes) and
to no limit with it."#,
            ),
        }),
    }],
};

/// Every error code the handle reports, as documented in
/// docs/Data_StateManagement/log.md. `log.invalid_target` comes from the
/// dispatcher when `from_url` refuses a URL; `log.failed` from the
/// dispatcher when writing the output fails.
pub(crate) const ERROR_CODES: &[&str] = &[
    "log.invalid_argument",
    "log.invalid_target",
    "log.unknown_verb",
    "log.not_found",
    "log.not_a_file",
    "log.permission_denied",
    "log.read_failed",
    "log.journalctl_not_found",
    "log.journal_access_denied",
    "log.journal_failed",
    "log.timeout",
    "log.failed",
];

/// Arguments `tail` accepts (`dry_run=false` is also accepted: the
/// dispatcher refuses `dry_run=true`, as tail only reads).
pub(crate) const TAIL_ARGS: &[&str] = &["lines", "pattern", "mode", "follow", "timeout_ms"];

/// Lines read when `lines` is not given, and the most that may be asked for.
const DEFAULT_LINES: u64 = 100;
const MAX_LINES: u64 = 1_000_000;
/// `timeout_ms` without `follow`, and the longest accepted.
const DEFAULT_TIMEOUT_MS: u64 = 600_000;
const MAX_TIMEOUT_MS: u64 = 7 * 24 * 3600 * 1000;
/// A line longer than this is cut to this many bytes (and a warning says so).
pub(crate) const MAX_LINE_BYTES: usize = 1024 * 1024;
/// Time between checks for new data while following a file.
const FOLLOW_POLL: Duration = Duration::from_millis(100);

/// A failure with its exit status and error code.
#[derive(Debug)]
pub(crate) struct Fail {
    pub exit: i32,
    pub code: &'static str,
    pub msg: String,
}

impl Fail {
    pub fn new(exit: i32, code: &'static str, msg: impl Into<String>) -> Self {
        debug_assert!(ERROR_CODES.contains(&code), "undocumented code {code}");
        Fail {
            exit,
            code,
            msg: msg.into(),
        }
    }
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::new(exit::USAGE, "log.invalid_argument", msg)
    }
    pub fn timeout(timeout: Option<Duration>) -> Self {
        let ms = timeout.map(|t| t.as_millis()).unwrap_or_default();
        Self::new(
            exit::TIMEOUT,
            "log.timeout",
            format!("timeout_ms={ms} passed before tail finished"),
        )
    }
}

/// The parsed options of `tail`.
#[derive(Debug, Clone)]
pub(crate) struct TailOpts {
    pub lines: usize,
    pub pattern: Option<String>,
    pub json: bool,
    pub follow: bool,
    pub timeout: Option<Duration>,
    /// With `follow=true mode=json`: the fields naming the source in each
    /// streamed object (`source` and `path`, or `source` and `unit`).
    pub stream_source: serde_json::Map<String, Value>,
}

impl TailOpts {
    pub fn deadline(&self, start: Instant) -> Option<Instant> {
        self.timeout.and_then(|t| start.checked_add(t))
    }

    pub fn keeps(&self, line: &str) -> bool {
        self.pattern.as_deref().is_none_or(|p| line.contains(p))
    }
}

/// The accepted argument closest to `bad`, for a "did you mean" hint.
fn suggest<'a>(bad: &str, allowed: &[&'a str]) -> Option<&'a str> {
    fn distance(a: &str, b: &str) -> usize {
        let b: Vec<char> = b.chars().collect();
        let mut prev: Vec<usize> = (0..=b.len()).collect();
        for (i, ca) in a.chars().enumerate() {
            let mut cur = vec![i + 1; b.len() + 1];
            for (j, cb) in b.iter().enumerate() {
                let cost = usize::from(ca != *cb);
                cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
            }
            prev = cur;
        }
        prev[b.len()]
    }
    let lower = bad.to_ascii_lowercase().replace('-', "_");
    if lower.len() >= 3
        && let Some(a) = allowed.iter().find(|a| a.starts_with(lower.as_str()))
    {
        return Some(a);
    }
    allowed
        .iter()
        .map(|a| (distance(&lower, a), *a))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, a)| a)
}

fn u64_arg(args: &Args, key: &str, min: u64, max: u64) -> Result<Option<u64>, Fail> {
    let Some(raw) = args.get(key) else {
        return Ok(None);
    };
    match raw.trim().parse::<u64>() {
        Ok(v) if (min..=max).contains(&v) => Ok(Some(v)),
        _ => Err(Fail::invalid(format!(
            "invalid value for {key}: {raw:?} (expected an integer from {min} to {max})"
        ))),
    }
}

/// Validates every argument of `tail` before anything is read.
pub(crate) fn parse_tail_args(args: &Args) -> Result<TailOpts, Fail> {
    let mut keys: Vec<&String> = args.keys().collect();
    keys.sort();
    for k in keys {
        if TAIL_ARGS.contains(&k.as_str()) {
            continue;
        }
        if k == "dry_run" {
            match lenient::dry_run(args) {
                Ok(false) => continue,
                Ok(true) => {
                    return Err(Fail::invalid(
                        "log tail does not support dry_run; nothing was done",
                    ));
                }
                Err(e) => return Err(Fail::invalid(e.to_string())),
            }
        }
        return Err(Fail::invalid(format!(
            "unknown argument: {k}{}",
            suggest(k, TAIL_ARGS)
                .map(|s| format!(" (did you mean `{s}`?)"))
                .unwrap_or_default()
        )));
    }
    let lines = u64_arg(args, "lines", 1, MAX_LINES)?.unwrap_or(DEFAULT_LINES) as usize;
    let pattern = match args.get("pattern") {
        Some(p) if p.is_empty() => {
            return Err(Fail::invalid(
                "invalid value for pattern: it is empty (leave pattern out to keep every line)",
            ));
        }
        p => p.cloned(),
    };
    let json = match args.get("mode").map(String::as_str) {
        None | Some("raw") => false,
        Some("json") => true,
        Some(other) => {
            return Err(Fail::invalid(format!(
                "invalid value for mode: {other:?} (expected raw or json)"
            )));
        }
    };
    let follow = lenient::bool_arg(args, "follow")
        .map_err(|e| Fail::invalid(e.to_string()))?
        .unwrap_or(false);
    let timeout = match u64_arg(args, "timeout_ms", 1, MAX_TIMEOUT_MS)? {
        Some(ms) => Some(Duration::from_millis(ms)),
        None if follow => None,
        None => Some(Duration::from_millis(DEFAULT_TIMEOUT_MS)),
    };
    Ok(TailOpts {
        lines,
        pattern,
        json,
        follow,
        timeout,
        stream_source: serde_json::Map::new(),
    })
}

/// Checks a systemd unit name: `[A-Za-z0-9:_.@\-\\]`, at most 256 bytes,
/// not starting with `-` or `.` (it must never read as an option).
pub(crate) fn valid_service(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("service name cannot be empty for log://svc/<service> URLs".into());
    }
    if name.len() > 256 {
        return Err(format!(
            "service name is {} bytes long; a unit name has at most 256",
            name.len()
        ));
    }
    if name.starts_with('-') || name.starts_with('.') {
        return Err(format!(
            "invalid service name {name:?}: it cannot start with '-' or '.'"
        ));
    }
    if let Some(c) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || ":_.@-\\".contains(*c)))
    {
        return Err(format!(
            "invalid service name {name:?}: {c:?} is not allowed in a unit name \
             (letters, digits and : _ . @ - \\ are)"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub enum LogSourceKind {
    File(PathBuf),
    Service(String),
}

pub struct LogTarget {
    pub source: LogSourceKind,
}

pub struct LogHandle {
    target: LogTarget,
    /// The journalctl program (a test seam; `journalctl` from PATH).
    journalctl: OsString,
}

impl LogHandle {
    fn with_source(source: LogSourceKind) -> Self {
        LogHandle {
            target: LogTarget { source },
            journalctl: OsString::from("journalctl"),
        }
    }

    pub fn from_url(u: &Url) -> Result<Self> {
        // log:///var/log/syslog   -> absolute file path
        // log://./logs/app.log    -> path relative to the working directory
        // log://../app.log        -> path relative to the parent directory
        // log://svc/nginx         -> systemd journal of a service
        // log://--help[=<verb>]   -> in-URL help (no target)
        let host = u.host_str().unwrap_or("");
        let path = u.path();

        if help::is_help_flag(host.split('=').next().unwrap_or(host)) {
            return Ok(Self::with_source(LogSourceKind::File(PathBuf::new())));
        }

        let decoded: Vec<u8> = percent_decode_str(path).collect();
        if decoded.contains(&0) {
            bail!("the log:// path contains a NUL byte");
        }

        if host == "svc" {
            let Ok(service) = String::from_utf8(decoded) else {
                bail!("the service name in log://svc/<service> is not valid UTF-8");
            };
            let service = service.trim_matches('/');
            valid_service(service).map_err(anyhow::Error::msg)?;
            return Ok(Self::with_source(LogSourceKind::Service(
                service.to_string(),
            )));
        }

        if decoded.is_empty() || decoded == b"/" {
            bail!("File path cannot be empty for log:// URLs");
        }
        let decoded = PathBuf::from(OsString::from_vec(decoded));
        let path = match host {
            "" => decoded,
            "." | ".." => {
                let rel = decoded.strip_prefix("/").unwrap_or(&decoded).to_path_buf();
                Path::new(host).join(rel)
            }
            other => bail!(
                "Unsupported log:// host {:?}; use log:///<absolute path>, log://./<relative path> or log://svc/<service>",
                other
            ),
        };
        Ok(Self::with_source(LogSourceKind::File(path)))
    }

    /// Writes the approved help for `help`, `--help`, `-h` and `--help=<verb>`.
    fn check_and_display_help(
        &self,
        verb: &str,
        args: &Args,
        io: &mut IoStreams,
    ) -> Result<Option<Status>> {
        let help_verb = if help::HELP_ALIASES.contains(&verb) {
            args.get("verb").map(String::as_str)
        } else if let Some(v) = verb.strip_prefix("--help=") {
            Some(v)
        } else {
            return Ok(None);
        };
        if let Some(v) = help_verb
            && !self.verbs().contains(&v)
        {
            return self.fail(io, &None, unknown_verb(v)).map(Some);
        }
        write!(
            io.stdout,
            "{}",
            help::render_legacy("log", &LOG_HELP, self.verbs(), help_verb)
        )?;
        Ok(Some(Status::ok()))
    }

    /// The JSON fields that name the source.
    fn source_fields(&self) -> serde_json::Map<String, Value> {
        let mut m = serde_json::Map::new();
        match &self.target.source {
            LogSourceKind::File(p) => {
                m.insert("path".into(), json!(p.to_string_lossy()));
            }
            LogSourceKind::Service(s) => {
                m.insert("service".into(), json!(s));
            }
        }
        m
    }

    /// Reports `f`: the stderr line always, and with `mode=json` (when the
    /// options were valid) the error object on stdout.
    fn fail(&self, io: &mut IoStreams, opts: &Option<&TailOpts>, f: Fail) -> Result<Status> {
        if let Some(o) = opts
            && o.json
            && o.follow
        {
            // A stream of objects ends with an object carrying the error.
            let mut obj = o.stream_source.clone();
            obj.insert("error".into(), error_json(f.code, &f.msg));
            obj.insert("ts".into(), json!(now_ms()));
            writeln!(io.stdout, "{}", Value::Object(obj))?;
        } else if let Some(o) = opts
            && o.json
        {
            let mut obj = self.source_fields();
            obj.insert("error".into(), error_json(f.code, &f.msg));
            obj.insert("requested_lines".into(), json!(o.lines));
            obj.insert("returned_lines".into(), json!(0));
            writeln!(io.stdout, "{}", Value::Object(obj))?;
        }
        writeln!(io.stderr, "{}", error_line(f.code, &f.msg))?;
        Ok(Status::coded(f.exit, f.code, f.msg))
    }

    /// Prints the result of a tail without follow.
    fn print(&self, io: &mut IoStreams, o: &TailOpts, lines: Vec<String>) -> Result<()> {
        let kept: Vec<String> = lines.into_iter().filter(|l| o.keeps(l)).collect();
        if o.json {
            let mut obj = self.source_fields();
            obj.insert("lines".into(), json!(kept));
            obj.insert("pattern".into(), json!(o.pattern));
            obj.insert("requested_lines".into(), json!(o.lines));
            obj.insert("returned_lines".into(), json!(kept.len()));
            writeln!(io.stdout, "{}", Value::Object(obj))?;
        } else {
            for l in kept {
                writeln!(io.stdout, "{l}")?;
            }
        }
        io.stdout.flush()?;
        Ok(())
    }

    fn tail(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let start = Instant::now();
        let mut o = match parse_tail_args(args) {
            Ok(o) => o,
            Err(f) => return self.fail(io, &None, f),
        };
        o.stream_source = match &self.target.source {
            LogSourceKind::File(p) => {
                json!({"source": "file", "path": p.to_string_lossy()})
            }
            LogSourceKind::Service(s) => json!({"source": "journal", "unit": s}),
        }
        .as_object()
        .cloned()
        .unwrap_or_default();
        let result = match &self.target.source {
            LogSourceKind::File(path) => self.tail_file(path, &o, start, io),
            LogSourceKind::Service(service) => journal::tail(self, service, &o, start, io),
        };
        match result {
            Ok(Outcome::Done) => Ok(Status::ok()),
            Ok(Outcome::Failed(f)) => self.fail(io, &Some(&o), f),
            // The reader of the output went away while following: done.
            Err(e) if is_broken_pipe(&e) => Ok(Status::ok()),
            Err(e) => Err(e),
        }
    }

    fn tail_file(
        &self,
        path: &Path,
        o: &TailOpts,
        start: Instant,
        io: &mut IoStreams,
    ) -> Result<Outcome> {
        let file = match open_log(path) {
            Ok(f) => f,
            Err(f) => return Ok(Outcome::Failed(f)),
        };
        let end = match file.metadata() {
            Ok(m) => m.len(),
            Err(e) => return Ok(Outcome::Failed(io_fail(path, "read", &e))),
        };
        // Without follow the deadline bounds the scan; with follow it bounds
        // the whole command, and the scan of the existing lines is part of it.
        let deadline = o.deadline(start);
        let tail = match scan::last_lines(&file, end, o.lines, deadline) {
            Ok(t) => t,
            // Following ends normally at timeout_ms, even during the scan.
            Err(scan::ScanError::Timeout) if o.follow => return Ok(Outcome::Done),
            Err(scan::ScanError::Timeout) => return Ok(Outcome::Failed(Fail::timeout(o.timeout))),
            Err(scan::ScanError::Io(e)) => return Ok(Outcome::Failed(io_fail(path, "read", &e))),
        };
        if tail.cut > 0 {
            warn_cut(io, tail.cut)?;
        }
        let mut lines = tail.lines;
        let mut offset = end;
        // A last line still being written is printed whole once it is done.
        if o.follow
            && let Some(start) = tail.partial_start
        {
            lines.pop();
            offset = start;
        }
        if !o.follow {
            self.print(io, o, lines)?;
            return Ok(Outcome::Done);
        }
        for l in &lines {
            emit(io, o, l)?;
        }
        follow_file(path, file, offset, o, deadline, io)
    }
}

/// How a tail ended, when it did not fail to write its output.
pub(crate) enum Outcome {
    Done,
    Failed(Fail),
}

fn is_broken_pipe(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::BrokenPipe)
}

fn unknown_verb(verb: &str) -> Fail {
    Fail::new(
        exit::USAGE,
        "log.unknown_verb",
        format!(
            "unknown verb for log://: {verb}{}",
            suggest(verb, &["tail"])
                .map(|s| format!(" (did you mean `{s}`?)"))
                .unwrap_or_default()
        ),
    )
}

pub(crate) fn warn_cut(io: &mut IoStreams, cut: usize) -> Result<()> {
    writeln!(
        io.stderr,
        "Warning: {cut} line(s) longer than {MAX_LINE_BYTES} bytes were cut to that length"
    )?;
    Ok(())
}

/// The failure for an I/O error on `path`.
fn io_fail(path: &Path, what: &str, e: &std::io::Error) -> Fail {
    use std::io::ErrorKind;
    let shown = path.display();
    match e.kind() {
        ErrorKind::NotFound => Fail::new(
            exit::FAILED,
            "log.not_found",
            format!("log file does not exist: {shown}"),
        ),
        ErrorKind::PermissionDenied => Fail::new(
            exit::FAILED,
            "log.permission_denied",
            format!("permission denied: cannot {what} {shown}"),
        ),
        _ => Fail::new(
            exit::FAILED,
            "log.read_failed",
            format!("cannot {what} {shown}: {e}"),
        ),
    }
}

/// Opens `path` for reading, refusing anything that is not a regular file
/// (a FIFO is opened non-blocking so it can be refused instead of hanging).
pub(crate) fn open_log(path: &Path) -> Result<File, Fail> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| io_fail(path, "open", &e))?;
    let meta = file.metadata().map_err(|e| io_fail(path, "read", &e))?;
    if !meta.is_file() {
        return Err(Fail::new(
            exit::FAILED,
            "log.not_a_file",
            format!("{} is not a regular file", path.display()),
        ));
    }
    Ok(file)
}

/// Follows `path` from `offset` in the open `file`: new lines are printed
/// and flushed as they are written. A truncated file is read again from the
/// start; a replaced (rotated) file is read to its end and then the new file
/// at `path` is followed. Stops at `deadline` (exit 124).
fn follow_file(
    path: &Path,
    mut file: File,
    mut offset: u64,
    o: &TailOpts,
    deadline: Option<Instant>,
    io: &mut IoStreams,
) -> Result<Outcome> {
    let mut lines = scan::LineSplitter::default();
    let mut ident = file.metadata().map(|m| (m.dev(), m.ino())).ok();
    loop {
        match scan::read_from(&mut file, offset, |chunk| {
            lines.push(chunk, |l| emit(io, o, l))
        }) {
            Ok(n) => offset += n,
            Err(e) => return Ok(Outcome::Failed(io_fail(path, "read", &e))),
        }
        lines.take_error()?;
        if lines.cut > 0 {
            warn_cut(io, std::mem::take(&mut lines.cut))?;
        }
        let now = Instant::now();
        if let Some(d) = deadline
            && now >= d
        {
            if let Some(rest) = lines.finish() {
                emit(io, o, &rest)?;
            }
            // timeout_ms is how long to follow: reaching it is the normal end.
            return Ok(Outcome::Done);
        }
        let pause = deadline.map_or(FOLLOW_POLL, |d| FOLLOW_POLL.min(d - now));
        std::thread::sleep(pause);

        // Truncated in place: start again from the beginning.
        let len = file
            .metadata()
            .map(|m| m.len())
            .map_err(|e| io_fail(path, "read", &e));
        match len {
            Ok(len) if len < offset => {
                event(
                    io,
                    o,
                    "truncated",
                    &format!(
                        "{} was truncated; reading it from the start",
                        path.display()
                    ),
                )?;
                offset = 0;
            }
            Ok(_) => {}
            Err(f) => return Ok(Outcome::Failed(f)),
        }
        // Replaced (rotated): finish the old file, then follow the new one.
        // A missing path is waited for; the old file is still read meanwhile.
        if let Ok(m) = std::fs::metadata(path)
            && ident != Some((m.dev(), m.ino()))
            && let Ok(new) = open_log(path)
        {
            match scan::read_from(&mut file, offset, |chunk| {
                lines.push(chunk, |l| emit(io, o, l))
            }) {
                Ok(_) => {}
                Err(e) => return Ok(Outcome::Failed(io_fail(path, "read", &e))),
            }
            lines.take_error()?;
            if let Some(rest) = lines.finish() {
                emit(io, o, &rest)?;
            }
            event(
                io,
                o,
                "rotated",
                &format!("{} was replaced; following the new file", path.display()),
            )?;
            ident = new.metadata().map(|m| (m.dev(), m.ino())).ok();
            file = new;
            offset = 0;
        }
    }
}

/// Milliseconds since the Unix epoch, now.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Prints one followed line if it passes the pattern, and flushes it: the
/// line itself, or with `mode=json` one object
/// `{"source", "path"|"unit", "line", "ts"}` per line.
pub(crate) fn emit(io: &mut IoStreams, o: &TailOpts, line: &str) -> std::io::Result<()> {
    if !o.keeps(line) {
        return Ok(());
    }
    if o.json {
        let mut obj = o.stream_source.clone();
        obj.insert("line".into(), json!(line));
        obj.insert("ts".into(), json!(now_ms()));
        writeln!(io.stdout, "{}", Value::Object(obj))?;
    } else {
        writeln!(io.stdout, "{line}")?;
    }
    io.stdout.flush()
}

/// Reports a change to a followed file: with `mode=json` an object
/// `{"event", "source", "path", "ts"}` on stdout, otherwise a warning on
/// stderr.
fn event(io: &mut IoStreams, o: &TailOpts, name: &str, msg: &str) -> std::io::Result<()> {
    if o.json {
        let mut obj = serde_json::Map::new();
        obj.insert("event".into(), json!(name));
        obj.extend(o.stream_source.clone());
        obj.insert("ts".into(), json!(now_ms()));
        writeln!(io.stdout, "{}", Value::Object(obj))?;
        io.stdout.flush()
    } else {
        writeln!(io.stderr, "Warning: {msg}")
    }
}

impl Handle for LogHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["tail", "help", "--help", "-h"]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&LOG_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        if let Some(status) = self.check_and_display_help(verb, args, io)? {
            return Ok(status);
        }
        match verb {
            "tail" => self.tail(args, io),
            _ => self.fail(io, &None, unknown_verb(verb)),
        }
    }
}
