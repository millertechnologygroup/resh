//! Search and follow verbs: tail, grep, find, watch.

use super::FileHandle;
use super::common::{Code, Deadline, DeadlineReader, Opts, emit, fail, invalid};
use super::inspect::open_for_read;
use crate::core::{IoStreams, Status};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use globset::GlobBuilder;
use notify::{EventKind, RecursiveMode, Watcher};
use regex::RegexBuilder;
use serde_json::json;
use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};
use walkdir::WalkDir;

/// The watch event names accepted by `events=`.
pub(crate) const WATCH_EVENTS: &[&str] = &["create", "modify", "remove", "rename"];

/// How often `tail follow=true` checks the file for new data.
const FOLLOW_POLL: Duration = Duration::from_millis(100);

fn deadline_after(ms: u64) -> Option<Instant> {
    (ms > 0).then(|| Instant::now() + Duration::from_millis(ms))
}

impl FileHandle {
    pub(super) fn verb_tail(&self, o: &Opts, io: &mut IoStreams) -> Result<Status> {
        if o.has("lines") && o.has("bytes") {
            return Err(invalid("lines= and bytes= cannot be used together"));
        }
        let lines = o.number::<usize>("lines", 1)?;
        let bytes = o.number::<u64>("bytes", 1)?;
        let follow = o.flag("follow", false)?;
        let timeout_ms = o.number::<u64>("timeout_ms", 0)?.unwrap_or(0);
        let deadline = Deadline::after_ms(timeout_ms);

        let (mut file, meta) = open_for_read(&self.path, "tail")?;
        let size = meta.len();
        let out = match bytes {
            Some(n) => tail_bytes(&mut file, size, n, deadline),
            None => tail_lines(&mut file, size, lines.unwrap_or(10), deadline),
        };
        let out = match out {
            Ok(out) => out,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                return Err(deadline.timeout(format!(
                    "the end of {} was still being read; nothing was printed",
                    self.path.display()
                )));
            }
            Err(e) => return Err(e).with_context(|| format!("tail {}", self.path.display())),
        };
        io.stdout.write_all(&out)?;
        io.stdout.flush()?;

        if follow {
            // With follow=true, timeout_ms is how long to follow: reaching
            // it is the normal end.
            self.follow(size, deadline_after(timeout_ms), io)?;
        }
        Ok(Status::ok())
    }

    /// Prints data appended after `offset` until the deadline (or forever).
    /// A file that shrinks was truncated or replaced: it is read again from
    /// the start.
    fn follow(&self, mut offset: u64, deadline: Option<Instant>, io: &mut IoStreams) -> Result<()> {
        loop {
            let size = fs::metadata(&self.path)
                .with_context(|| format!("tail follow {}", self.path.display()))?
                .len();
            if size < offset {
                offset = 0;
            }
            if size > offset {
                let mut f = File::open(&self.path)
                    .with_context(|| format!("tail follow {}", self.path.display()))?;
                f.seek(SeekFrom::Start(offset))?;
                let mut buf = Vec::new();
                f.take(size - offset).read_to_end(&mut buf)?;
                offset += buf.len() as u64;
                io.stdout.write_all(&buf)?;
                io.stdout.flush()?;
            }
            match deadline {
                Some(d) if Instant::now() >= d => return Ok(()),
                Some(d) => std::thread::sleep(FOLLOW_POLL.min(d - Instant::now())),
                None => std::thread::sleep(FOLLOW_POLL),
            }
        }
    }

    pub(super) fn verb_grep(&self, o: &Opts, io: &mut IoStreams) -> Result<Status> {
        let pattern = o.required("pattern")?;
        let use_regex = o.flag("regex", true)?;
        let ignore_case = o.flag("ignore_case", false)?;
        let invert = o.flag("invert", false)?;
        let max = o.number::<usize>("max", 1)?;
        let before = o.number::<usize>("before", 0)?;
        let after = o.number::<usize>("after", 0)?;
        let json_out = o.choice("format", &["text", "json"])? == Some("json");
        if json_out {
            for k in ["before", "after", "line_numbers"] {
                if o.has(k) {
                    return Err(invalid(format!("{k}= applies only to format=text")));
                }
            }
        }
        let line_numbers = o.flag("line_numbers", true)?;
        let (before, after) = (before.unwrap_or(0), after.unwrap_or(0));
        let context = before > 0 || after > 0;

        let matcher: Box<dyn Fn(&str) -> bool> = if use_regex {
            let re = RegexBuilder::new(pattern)
                .case_insensitive(ignore_case)
                .build()
                .map_err(|e| invalid(format!("invalid regex pattern: {e}")))?;
            Box::new(move |l: &str| re.is_match(l))
        } else if ignore_case {
            let p = pattern.to_lowercase();
            Box::new(move |l: &str| l.to_lowercase().contains(&p))
        } else {
            let p = pattern.to_string();
            Box::new(move |l: &str| l.contains(&p))
        };

        let deadline = o.deadline()?;
        let (file, _) = open_for_read(&self.path, "grep")?;
        let mut reader = BufReader::new(DeadlineReader::new(file, deadline));
        let path_str = self.path.to_string_lossy().to_string();
        let mut raw = Vec::new();
        let mut lineno = 0usize;
        let mut matches = 0usize;
        let mut held: VecDeque<(usize, String)> = VecDeque::new();
        let mut after_left = 0usize;
        let mut results = Vec::new();

        let print = |out: &mut dyn Write, n: usize, text: &str, is_match: bool| {
            if !line_numbers {
                writeln!(out, "{text}")
            } else if context {
                writeln!(out, "{}{n}:{text}", if is_match { ":" } else { "-" })
            } else {
                writeln!(out, "{n}:{text}")
            }
        };

        loop {
            raw.clear();
            let n = match reader.read_until(b'\n', &mut raw) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    return Err(deadline.timeout(format!(
                        "{lineno} lines of {} were searched and {matches} matches found{}",
                        self.path.display(),
                        if json_out {
                            "; nothing was printed"
                        } else {
                            " (printed above)"
                        }
                    )));
                }
                Err(e) => return Err(e).with_context(|| format!("grep {}", self.path.display())),
            };
            if n == 0 {
                break;
            }
            lineno += 1;
            if raw.last() == Some(&b'\n') {
                raw.pop();
                if raw.last() == Some(&b'\r') {
                    raw.pop();
                }
            }
            // Lines that are not UTF-8 are matched and shown lossily.
            let text = String::from_utf8_lossy(&raw).into_owned();

            if max.is_some_and(|m| matches >= m) {
                if after_left == 0 {
                    break;
                }
                after_left -= 1;
                print(&mut *io.stdout, lineno, &text, false)?;
                continue;
            }
            if matcher(&text) != invert {
                matches += 1;
                if json_out {
                    results.push(
                        json!({"path": path_str, "line": lineno, "text": text, "matched": true}),
                    );
                } else {
                    for (n, t) in held.drain(..) {
                        print(&mut *io.stdout, n, &t, false)?;
                    }
                    print(&mut *io.stdout, lineno, &text, true)?;
                    after_left = after;
                }
            } else if !json_out && after_left > 0 {
                after_left -= 1;
                print(&mut *io.stdout, lineno, &text, false)?;
            } else if before > 0 {
                held.push_back((lineno, text));
                if held.len() > before {
                    held.pop_front();
                }
            }
        }

        if matches == 0 {
            return Err(fail(Code::NoMatch, "no matches"));
        }
        if json_out {
            emit(io, &json!(results))?;
        }
        Ok(Status::ok())
    }

    pub(super) fn verb_find(&self, o: &Opts, io: &mut IoStreams) -> Result<Status> {
        // Shell-style: `*` and `?` stay within one path component, `**`
        // crosses directories. A pattern with `/` is matched against the
        // path below the root, otherwise against the entry's name.
        let name = o.get("name");
        let glob = name
            .map(|p| {
                GlobBuilder::new(p)
                    .literal_separator(true)
                    .build()
                    .map(|g| g.compile_matcher())
                    .map_err(|e| invalid(format!("invalid name pattern: {e}")))
            })
            .transpose()?;
        let match_path = name.is_some_and(|p| p.contains('/'));
        let entry_type = o.choice("type", &["file", "dir", "symlink"])?;
        let max_depth = o.number::<usize>("max_depth", 0)?;
        let limit = o.number::<usize>("limit", 0)?;
        let include_hidden = o.flag("include_hidden", false)?;
        let follow_symlinks = o.flag("follow_symlinks", false)?;
        let deadline = o.deadline()?;

        let root = self.path.as_path();
        fs::symlink_metadata(root).with_context(|| format!("find {}", root.display()))?;

        let mut walker = WalkDir::new(root)
            .follow_links(follow_symlinks)
            .sort_by_file_name();
        if let Some(d) = max_depth {
            walker = walker.max_depth(d);
        }
        // The root is always walked; hidden entries below it (and everything
        // inside hidden directories) are skipped unless include_hidden=true.
        let walk = walker
            .into_iter()
            .filter_entry(|e| include_hidden || e.depth() == 0 || !is_hidden(e.path()));

        let mut results = Vec::new();
        let mut errors = 0usize;
        for entry in walk {
            if limit.is_some_and(|l| results.len() >= l) {
                break;
            }
            if deadline.expired() {
                emit(io, &json!(results))?;
                return Err(deadline.timeout(format!(
                    "the {} entries found so far under {} are listed above",
                    results.len(),
                    root.display()
                )));
            }
            let entry = match entry {
                Ok(e) => e,
                Err(err) => {
                    writeln!(io.stderr, "Warning: {err}")?;
                    // A symlink loop is reported but is not a failure.
                    if err.loop_ancestor().is_none() {
                        errors += 1;
                    }
                    continue;
                }
            };
            let ft = entry.file_type();
            let type_ok = match entry_type {
                Some("file") => ft.is_file(),
                Some("dir") => ft.is_dir(),
                Some("symlink") => ft.is_symlink(),
                _ => true,
            };
            let name_ok = glob.as_ref().is_none_or(|g| {
                if match_path {
                    entry
                        .path()
                        .strip_prefix(root)
                        .is_ok_and(|rel| g.is_match(rel))
                } else {
                    g.is_match(entry.file_name())
                }
            });
            if type_ok && name_ok {
                results.push(find_entry(entry.path(), entry.depth(), follow_symlinks));
            }
        }

        emit(io, &json!(results))?;
        if errors > 0 {
            let msg = format!(
                "{errors} entr{} under {} could not be read; the listing above is incomplete",
                if errors == 1 { "y" } else { "ies" },
                root.display()
            );
            writeln!(
                io.stderr,
                "{}",
                crate::core::status::error_line(Code::Partial.name(), &msg)
            )?;
            return Err(fail(Code::Partial, msg));
        }
        Ok(Status::ok())
    }

    pub(super) fn verb_watch(&self, o: &Opts, io: &mut IoStreams) -> Result<Status> {
        let timeout_ms = o.number::<u64>("timeout_ms", 0)?.unwrap_or(30000);
        let max_events = o.number::<u64>("max_events", 1)?.unwrap_or(1);
        let events: Vec<&str> = match o.get("events") {
            None => WATCH_EVENTS.to_vec(),
            Some(list) => {
                let mut v = Vec::new();
                for e in list.split(',').map(str::trim).filter(|e| !e.is_empty()) {
                    let e = e.to_ascii_lowercase();
                    let Some(known) = WATCH_EVENTS.iter().find(|k| **k == e) else {
                        return Err(invalid(format!(
                            "invalid event {e:?} in events= (expected {})",
                            WATCH_EVENTS.join(",")
                        )));
                    };
                    v.push(*known);
                }
                if v.is_empty() {
                    return Err(invalid("events= must name at least one event"));
                }
                v
            }
        };

        fs::symlink_metadata(&self.path)
            .with_context(|| format!("watch {}", self.path.display()))?;
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = notify::recommended_watcher(tx).context("create file watcher")?;
        watcher
            .watch(&self.path, RecursiveMode::NonRecursive)
            .map_err(|e| watch_error(&self.path, e))?;

        let deadline = deadline_after(timeout_ms);
        let mut count = 0u64;
        while count < max_events {
            let wait = match deadline {
                Some(d) => {
                    let now = Instant::now();
                    if now >= d {
                        break;
                    }
                    (d - now).min(Duration::from_millis(200))
                }
                None => Duration::from_millis(200),
            };
            let event = match rx.recv_timeout(wait) {
                Ok(Ok(ev)) => ev,
                Ok(Err(e)) => return Err(watch_error(&self.path, e)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            };
            // inotify reports a rename as From, To and then Both (with
            // both paths); Both would repeat the first two.
            if matches!(
                event.kind,
                EventKind::Modify(notify::event::ModifyKind::Name(
                    notify::event::RenameMode::Both
                ))
            ) {
                continue;
            }
            let Some(name) = event_name(&event.kind) else {
                continue;
            };
            if !events.contains(&name) {
                continue;
            }
            let kind = match event.kind {
                EventKind::Modify(notify::event::ModifyKind::Metadata(_)) => "metadata_change",
                EventKind::Modify(notify::event::ModifyKind::Name(_)) => "any",
                EventKind::Modify(_) => "data_change",
                _ => "any",
            };
            for p in &event.paths {
                if count >= max_events {
                    break;
                }
                let shown = p.canonicalize().unwrap_or_else(|_| p.clone());
                emit(
                    io,
                    &json!({
                        "event": name,
                        "path": shown.display().to_string(),
                        "kind": kind,
                        "timestamp": Utc::now().to_rfc3339()
                    }),
                )?;
                io.stdout.flush()?;
                count += 1;
            }
        }
        Ok(Status::ok())
    }
}

/// The documented event name for a notify event, or `None` to skip it
/// (access events and unclassified events).
fn event_name(kind: &EventKind) -> Option<&'static str> {
    match kind {
        EventKind::Create(_) => Some("create"),
        EventKind::Modify(notify::event::ModifyKind::Name(_)) => Some("rename"),
        EventKind::Modify(_) => Some("modify"),
        EventKind::Remove(_) => Some("remove"),
        EventKind::Access(_) | EventKind::Any | EventKind::Other => None,
    }
}

fn watch_error(path: &Path, e: notify::Error) -> anyhow::Error {
    match e.kind {
        notify::ErrorKind::Io(io) => {
            super::common::io_fail(format!("watch {}", path.display()), &io)
        }
        notify::ErrorKind::PathNotFound => fail(
            Code::NotFound,
            format!("watch {}: path not found", path.display()),
        ),
        other => fail(
            Code::IoError,
            format!("watch {}: {other:?}", path.display()),
        ),
    }
}

fn is_hidden(p: &Path) -> bool {
    p.file_name()
        .is_some_and(|n| n.to_string_lossy().starts_with('.'))
}

fn find_entry(path: &Path, depth: usize, follow: bool) -> serde_json::Value {
    let meta = if follow {
        fs::metadata(path).or_else(|_| fs::symlink_metadata(path))
    } else {
        fs::symlink_metadata(path)
    };
    let (type_str, size, mode, mtime) = match meta {
        Ok(m) => {
            let ft = m.file_type();
            let t = if ft.is_file() {
                "file"
            } else if ft.is_dir() {
                "dir"
            } else if ft.is_symlink() {
                "symlink"
            } else {
                "other"
            };
            (
                t,
                if ft.is_file() { m.len() } else { 0 },
                format!("{:04o}", m.permissions().mode() & 0o7777),
                m.modified()
                    .ok()
                    .map(|t| DateTime::<Utc>::from(t).to_rfc3339()),
            )
        }
        Err(_) => ("other", 0, "0000".to_string(), None),
    };
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|d| d.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    json!({
        "path": super::common::normalize_path(&abs).to_string_lossy(),
        "type": type_str,
        "size": size,
        "mode": mode,
        "mtime": mtime,
        "is_hidden": is_hidden(path),
        "depth": depth
    })
}

/// The last `n` bytes of the file.
fn tail_bytes(file: &mut File, size: u64, n: u64, deadline: Deadline) -> std::io::Result<Vec<u8>> {
    let start = size.saturating_sub(n);
    file.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    DeadlineReader::new(file, deadline)
        .take(size - start)
        .read_to_end(&mut buf)?;
    Ok(buf)
}

/// The last `n` lines of the file. A final line without a newline counts as
/// a line; the newline that ends the file does not start another one.
fn tail_lines(
    file: &mut File,
    size: u64,
    n: usize,
    deadline: Deadline,
) -> std::io::Result<Vec<u8>> {
    const CHUNK: u64 = 8192;
    let mut buf: Vec<u8> = Vec::new();
    let mut pos = size;
    loop {
        if deadline.expired() {
            return Err(deadline.io_error());
        }
        let start = pos.saturating_sub(CHUNK);
        if start < pos {
            file.seek(SeekFrom::Start(start))?;
            let mut chunk = Vec::with_capacity((pos - start) as usize);
            (&mut *file).take(pos - start).read_to_end(&mut chunk)?;
            chunk.extend_from_slice(&buf);
            buf = chunk;
            pos = start;
        }
        let body_len = if buf.last() == Some(&b'\n') {
            buf.len() - 1
        } else {
            buf.len()
        };
        let mut seen = 0;
        for i in (0..body_len).rev() {
            if buf[i] == b'\n' {
                seen += 1;
                if seen == n {
                    return Ok(buf.split_off(i + 1));
                }
            }
        }
        if pos == 0 {
            return Ok(buf);
        }
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    fn tail(content: &str, n: usize) -> String {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, content).unwrap();
        let mut f = File::open(&p).unwrap();
        String::from_utf8(
            tail_lines(&mut f, content.len() as u64, n, Deadline::after_ms(0)).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn tail_lines_counts_lines_not_newlines() {
        assert_eq!(tail("a\nb\nc\n", 2), "b\nc\n");
        assert_eq!(tail("a\nb\nc", 2), "b\nc");
        assert_eq!(tail("a\nb\nc", 5), "a\nb\nc");
        assert_eq!(tail("abc", 1), "abc");
        assert_eq!(tail("", 3), "");
        assert_eq!(tail("\n\n\n", 2), "\n\n");
    }

    #[test]
    fn tail_lines_across_chunks() {
        let line = "x".repeat(5000);
        let content = format!("{line}A\n{line}B\n{line}C\n");
        let out = tail(&content, 2);
        assert_eq!(out, format!("{line}B\n{line}C\n"));
        let out = tail(&content, 1);
        assert_eq!(out, format!("{line}C\n"));
    }

    #[test]
    fn event_names_follow_the_docs() {
        use notify::event::*;
        assert_eq!(
            event_name(&EventKind::Create(CreateKind::File)),
            Some("create")
        );
        assert_eq!(
            event_name(&EventKind::Modify(ModifyKind::Name(RenameMode::From))),
            Some("rename")
        );
        assert_eq!(
            event_name(&EventKind::Modify(ModifyKind::Data(DataChange::Any))),
            Some("modify")
        );
        assert_eq!(
            event_name(&EventKind::Remove(RemoveKind::File)),
            Some("remove")
        );
        assert_eq!(event_name(&EventKind::Access(AccessKind::Any)), None);
    }
}
