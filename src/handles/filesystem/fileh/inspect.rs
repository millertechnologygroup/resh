//! Read-only inspection verbs: read, exists, stat, preview, summary,
//! analyze, schema.

use super::FileHandle;
use super::common::{Code, Deadline, DeadlineReader, Opts, emit, fail};
use crate::core::{IoStreams, Status};
use anyhow::{Context, Result};
use base64::prelude::*;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// Largest sample `summary` reads, whatever `max_bytes` asks for.
pub(crate) const SUMMARY_MAX_SAMPLE: u64 = 1024 * 1024;

fn rfc3339(t: std::io::Result<std::time::SystemTime>) -> Option<String> {
    t.ok().map(|t| DateTime::<Utc>::from(t).to_rfc3339())
}

/// Opens `path` for reading its contents: a missing path is `file.not_found` and a
/// directory is `file.is_a_directory`. Verbs that sample or search a file need a
/// regular file (a FIFO or device could block or never end): anything else
/// is `file.not_a_file`. `read` streams any readable file.
pub(crate) fn open_for_read(path: &Path, verb: &str) -> Result<(File, fs::Metadata)> {
    let meta = fs::metadata(path).with_context(|| format!("{verb} {}", path.display()))?;
    if meta.is_dir() {
        return Err(fail(
            Code::IsADirectory,
            format!("{} is a directory", path.display()),
        ));
    }
    if verb != "read" && !meta.is_file() {
        return Err(fail(
            Code::NotAFile,
            format!("{} is not a regular file", path.display()),
        ));
    }
    let f = if meta.is_file() {
        File::open(path)
    } else {
        // A FIFO would block in open(2) until a writer appears; open it
        // non-blocking, then make reads blocking again (DeadlineReader polls
        // before each read).
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .inspect(|f| {
                use std::os::fd::AsRawFd;
                let fd = f.as_raw_fd();
                // SAFETY: fcntl on a descriptor we own.
                unsafe {
                    let flags = libc::fcntl(fd, libc::F_GETFL);
                    libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
                }
            })
    }
    .with_context(|| format!("{verb} {}", path.display()))?;
    Ok((f, meta))
}

/// Reads at most `max` bytes from the start of `f`, failing with `file.timeout`
/// at the deadline.
pub(crate) fn read_sample<R: Read>(
    f: R,
    max: u64,
    path: &Path,
    deadline: Deadline,
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut r = DeadlineReader::new(f, deadline).take(max);
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let n = match r.read(&mut chunk) {
            Ok(0) => return Ok(buf),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                return Err(deadline.timeout(format!(
                    "{} bytes of {} were read; nothing was printed",
                    buf.len(),
                    path.display()
                )));
            }
            Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
        };
        buf.extend_from_slice(&chunk[..n]);
    }
}

impl FileHandle {
    pub(super) fn verb_read(&self, o: &Opts, io: &mut IoStreams) -> Result<Status> {
        let deadline = o.deadline()?;
        let (f, meta) = open_for_read(&self.path, "read")?;
        let mut r = if meta.is_file() {
            DeadlineReader::new(f, deadline)
        } else {
            use std::os::fd::AsRawFd;
            let fd = f.as_raw_fd();
            DeadlineReader::polling(f, deadline, fd)
        };
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let n = match r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    io.stdout.flush()?;
                    return Err(deadline.timeout(format!(
                        "the first {total} bytes of {} were printed",
                        self.path.display()
                    )));
                }
                Err(e) => return Err(e).with_context(|| format!("read {}", self.path.display())),
            };
            io.stdout.write_all(&buf[..n])?;
            io.stdout.flush()?;
            total += n as u64;
        }
        Ok(Status::ok())
    }

    pub(super) fn verb_exists(&self, _o: &Opts, io: &mut IoStreams) -> Result<Status> {
        let kind = match fs::symlink_metadata(&self.path) {
            Ok(meta) => {
                let t = meta.file_type();
                if t.is_file() {
                    "file"
                } else if t.is_dir() {
                    "dir"
                } else if t.is_symlink() {
                    "symlink"
                } else {
                    "other"
                }
            }
            // A missing entry, or a parent that is not a directory, means
            // the path does not exist.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                "none"
            }
            Err(e) => {
                return Err(e).with_context(|| format!("exists {}", self.path.display()));
            }
        };
        emit(
            io,
            &json!({
                "path": self.path.to_string_lossy(),
                "exists": kind != "none",
                "kind": kind,
            }),
        )?;
        Ok(Status::ok())
    }

    pub(super) fn verb_stat(&self, o: &Opts, io: &mut IoStreams) -> Result<Status> {
        let nofollow = o.flag("nofollow", false)?;
        let meta = if nofollow {
            fs::symlink_metadata(&self.path)
        } else {
            fs::metadata(&self.path)
        }
        .with_context(|| format!("stat {}", self.path.display()))?;

        let file_type = if meta.file_type().is_symlink() {
            "symlink"
        } else if meta.is_file() {
            "file"
        } else if meta.is_dir() {
            "dir"
        } else {
            "other"
        };
        emit(
            io,
            &json!({
                "path": self.path.display().to_string(),
                "exists": true,
                "file_type": file_type,
                "size": meta.len(),
                "readonly": meta.permissions().readonly(),
                "created": rfc3339(meta.created()),
                "modified": rfc3339(meta.modified()),
                "accessed": rfc3339(meta.accessed()),
                "mode": format!("{:04o}", meta.mode() & 0o7777),
                "uid": meta.uid(),
                "gid": meta.gid(),
            }),
        )?;
        Ok(Status::ok())
    }

    pub(super) fn verb_preview(&self, o: &Opts, io: &mut IoStreams) -> Result<Status> {
        let max_bytes = o.number::<u64>("max_bytes", 1)?.unwrap_or(4096);
        let max_lines = o.number::<usize>("max_lines", 1)?.unwrap_or(40);
        let mode = o
            .choice("mode", &["auto", "text", "binary"])?
            .unwrap_or("auto");
        let encoding = o
            .choice("encoding", &["base64", "hex"])?
            .unwrap_or("base64");
        let include_metadata = o.flag("include_metadata", true)?;

        let deadline = o.deadline()?;
        let (f, meta) = open_for_read(&self.path, "preview")?;
        let buffer = read_sample(f, max_bytes, &self.path, deadline)?;
        let preview_len = buffer.len() as u64;

        let binary = match mode {
            "text" => false,
            "binary" => true,
            _ => is_binary_content(&buffer),
        };
        let (sample, line_count) = if binary {
            let encoded = match encoding {
                "hex" => buffer.iter().map(|b| format!("{b:02x}")).collect(),
                _ => BASE64_STANDARD.encode(&buffer),
            };
            (encoded, Value::Null)
        } else {
            let text = String::from_utf8_lossy(&buffer);
            let sample = first_lines(&text, max_lines).to_string();
            let n = sample.lines().count();
            (sample, json!(n))
        };

        let mut out = json!({
            "path": self.path.display().to_string(),
            "mode": if binary { "binary" } else { "text" },
            "preview_len_bytes": preview_len,
            "file_size_bytes": meta.len(),
            "is_truncated": meta.len() > preview_len,
            "sample": sample,
            "encoding": if binary { encoding } else { "utf-8" },
            "line_count": line_count,
        });
        if include_metadata {
            out["metadata"] = json!({
                "exists": true,
                "is_file": meta.is_file(),
                "is_dir": meta.is_dir(),
                "permissions": format!("{:04o}", meta.permissions().mode() & 0o777),
                "modified": rfc3339(meta.modified()),
            });
        }
        emit(io, &out)?;
        Ok(Status::ok())
    }

    pub(super) fn verb_summary(&self, o: &Opts, io: &mut IoStreams) -> Result<Status> {
        let max_bytes = o
            .number::<u64>("max_bytes", 1)?
            .unwrap_or(65536)
            .min(SUMMARY_MAX_SAMPLE);
        let deadline = o.deadline()?;
        let meta =
            fs::metadata(&self.path).with_context(|| format!("summary {}", self.path.display()))?;

        if meta.is_dir() {
            let mut entry_count = 0usize;
            for _ in fs::read_dir(&self.path)
                .with_context(|| format!("summary {}", self.path.display()))?
            {
                deadline
                    .check(|| format!("{entry_count} entries were counted; nothing was printed"))?;
                entry_count += 1;
            }
            emit(
                io,
                &json!({
                    "path": self.path.to_string_lossy(),
                    "exists": true,
                    "is_dir": true,
                    "entry_count": entry_count
                }),
            )?;
            return Ok(Status::ok());
        }

        let (f, _) = open_for_read(&self.path, "summary")?;
        let buffer = read_sample(f, max_bytes, &self.path, deadline)?;
        let content_type = classify_summary(&buffer);
        let sample_end = buffer.len().min(512);
        let mut summary = json!({
            "path": self.path.to_string_lossy(),
            "exists": true,
            "is_dir": false,
            "size": meta.len(),
            "modified": rfc3339(meta.modified()),
            "content_type": content_type,
            "sample": String::from_utf8_lossy(&buffer[..sample_end]),
        });
        if content_type == "binary" {
            summary["line_count"] = Value::Null;
            summary["avg_line_length"] = Value::Null;
        } else {
            let text = String::from_utf8_lossy(&buffer);
            let lines: Vec<&str> = text.lines().collect();
            let avg = if lines.is_empty() {
                0.0
            } else {
                lines.iter().map(|l| l.len()).sum::<usize>() as f64 / lines.len() as f64
            };
            summary["line_count"] = json!(lines.len());
            summary["avg_line_length"] = json!(avg);
        }
        emit(io, &summary)?;
        Ok(Status::ok())
    }

    pub(super) fn verb_analyze(&self, o: &Opts, io: &mut IoStreams) -> Result<Status> {
        let max_bytes = o.number::<u64>("max_bytes", 1)?.unwrap_or(65536);
        let deadline = o.deadline()?;
        let (f, meta) = open_for_read(&self.path, "analyze")?;
        let buffer = read_sample(f, max_bytes, &self.path, deadline)?;
        let sample_bytes = buffer.len();

        let line_count = buffer.iter().filter(|&&b| b == b'\n').count();
        let ascii_count = buffer
            .iter()
            .filter(|&&b| (0x20..=0x7E).contains(&b) || matches!(b, 0x09 | 0x0A | 0x0D))
            .count();
        let ascii_ratio = if sample_bytes == 0 {
            0.0
        } else {
            ascii_count as f64 / sample_bytes as f64
        };
        let null_byte_present = buffer.contains(&0);
        let (classification, hints) = classify_analyze(&buffer, ascii_ratio, null_byte_present);

        emit(
            io,
            &json!({
                "path": self.path.display().to_string(),
                "size_bytes": meta.len(),
                "sample_bytes": sample_bytes as u64,
                "line_count": line_count,
                "ascii_ratio": ascii_ratio,
                "null_byte_present": null_byte_present,
                "entropy": entropy(&buffer),
                "classification": classification,
                "format_hints": hints
            }),
        )?;
        Ok(Status::ok())
    }

    pub(super) fn verb_schema(&self, o: &Opts, io: &mut IoStreams) -> Result<Status> {
        let max_bytes = o.number::<u64>("max_bytes", 1)?.unwrap_or(65536);
        let max_rows = o.number::<usize>("max_rows", 1)?.unwrap_or(100);
        let format_override = o.choice("format", &["json", "ndjson", "csv", "tsv", "text"])?;

        let deadline = o.deadline()?;
        let (f, _) = open_for_read(&self.path, "schema")?;
        let buffer = read_sample(f, max_bytes, &self.path, deadline)?;
        let bytes_read = buffer.len();
        let content = String::from_utf8_lossy(&buffer);
        let format = format_override.unwrap_or_else(|| detect_format(&content));

        let result = match format {
            "json" => analyze_json(&content, &self.path, bytes_read, max_rows),
            "ndjson" => analyze_ndjson(&content, &self.path, bytes_read, max_rows),
            "csv" => analyze_delimited(&content, &self.path, bytes_read, max_rows, ',', "csv"),
            "tsv" => analyze_delimited(&content, &self.path, bytes_read, max_rows, '\t', "tsv"),
            _ => Ok(analyze_text(&content, &self.path, bytes_read)),
        };
        let schema = result.map_err(|e| {
            fail(
                Code::ParseError,
                format!("{} as {format}: {e}", self.path.display()),
            )
        })?;
        emit(io, &schema)?;
        Ok(Status::ok())
    }
}

/// The first `max_lines` lines of `text`. When text is cut, the line break
/// before the cut is dropped too.
fn first_lines(text: &str, max_lines: usize) -> &str {
    let mut count = 0;
    for (i, _) in text.match_indices('\n') {
        count += 1;
        if count == max_lines {
            return if i + 1 < text.len() { &text[..i] } else { text };
        }
    }
    text
}

/// Binary when more than 10% of the bytes are control characters other than
/// tab, CR and LF.
fn is_binary_content(data: &[u8]) -> bool {
    let control = data
        .iter()
        .filter(|&&b| b < 0x20 && !matches!(b, b'\n' | b'\r' | b'\t'))
        .count();
    control * 10 > data.len()
}

/// Content type for `summary`: binary, json, csv or text.
fn classify_summary(buffer: &[u8]) -> &'static str {
    if buffer.contains(&0) {
        return "binary";
    }
    let Ok(text) = std::str::from_utf8(buffer) else {
        return "binary";
    };
    let text = text.trim();
    if (text.starts_with('{') && text.ends_with('}'))
        || (text.starts_with('[') && text.ends_with(']'))
    {
        return "json";
    }
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() > 1 && lines.iter().take(3).all(|l| l.split(',').count() > 1) {
        return "csv";
    }
    "text"
}

/// Shannon entropy of the bytes, in bits per byte.
fn entropy(buffer: &[u8]) -> f64 {
    if buffer.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in buffer {
        counts[b as usize] += 1;
    }
    let len = buffer.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Classification and format hints for `analyze`.
fn classify_analyze(buffer: &[u8], ascii_ratio: f64, null_byte: bool) -> (&'static str, Value) {
    let hints = |j: bool, c: bool, l: bool| json!({"is_json": j, "is_csv": c, "is_log_like": l});
    if null_byte || ascii_ratio <= 0.9 {
        return ("binary", hints(false, false, false));
    }
    let Ok(text) = std::str::from_utf8(buffer) else {
        return ("text", hints(false, false, false));
    };
    let trimmed = text.trim();
    let is_json = ((trimmed.starts_with('{') && trimmed.ends_with('}'))
        || (trimmed.starts_with('[') && trimmed.ends_with(']')))
        && serde_json::from_str::<Value>(trimmed).is_ok();

    let lines: Vec<&str> = text.lines().collect();
    let mut is_csv = false;
    if let [first, rest @ ..] = lines.as_slice() {
        let commas = first.matches(',').count();
        is_csv = !rest.is_empty()
            && commas > 0
            && rest
                .iter()
                .take(10)
                .all(|l| l.matches(',').count() == commas);
    }

    let mut is_log_like = false;
    if !is_json && !is_csv {
        let indicators = lines
            .iter()
            .take(10)
            .filter(|line| {
                let t = line.trim();
                t.len() > 4
                    && ((t.starts_with("20") && t.as_bytes().get(4) == Some(&b'-'))
                        || t.starts_with("[20")
                        || (t.contains('T') && t.contains(':')))
            })
            .count();
        is_log_like = indicators > lines.len() / 3;
    }
    let class = if is_json {
        "json"
    } else if is_csv {
        "csv"
    } else if is_log_like {
        "log"
    } else {
        "text"
    };
    (class, hints(is_json, is_csv, is_log_like))
}

fn detect_format(content: &str) -> &'static str {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return "text";
    }
    if ((trimmed.starts_with('{') && trimmed.ends_with('}'))
        || (trimmed.starts_with('[') && trimmed.ends_with(']')))
        && serde_json::from_str::<Value>(trimmed).is_ok()
    {
        return "json";
    }
    let lines: Vec<&str> = trimmed.lines().take(5).collect();
    if lines.len() >= 2 {
        let json_lines = lines
            .iter()
            .map(|l| l.trim())
            .filter(|l| {
                l.starts_with('{') && l.ends_with('}') && serde_json::from_str::<Value>(l).is_ok()
            })
            .count();
        if json_lines >= 2 {
            return "ndjson";
        }
    }
    let first_line = trimmed.lines().next().unwrap_or("");
    if first_line.contains(',') {
        return "csv";
    }
    if first_line.contains('\t') {
        return "tsv";
    }
    "text"
}

fn analyze_json(content: &str, path: &Path, byte_sample: usize, max_rows: usize) -> Result<Value> {
    let value: Value = serde_json::from_str(content).context("invalid JSON")?;
    let mut schema = json!({
        "path": path.to_string_lossy(),
        "format": "json",
        "encoding": "utf-8",
        "byte_sample": byte_sample
    });
    schema["detected"] = match &value {
        Value::Array(arr) => json!({
            "json_type": "array",
            "record_count_sampled": arr.len().min(max_rows),
            "fields": infer_fields(arr.iter().take(max_rows))
        }),
        Value::Object(_) => json!({
            "json_type": "object",
            "record_count_sampled": 1,
            "fields": infer_fields(std::iter::once(&value))
        }),
        other => json!({
            "json_type": json_type(other),
            "record_count_sampled": 1
        }),
    };
    Ok(schema)
}

fn analyze_ndjson(
    content: &str,
    path: &Path,
    byte_sample: usize,
    max_rows: usize,
) -> Result<Value> {
    let objects: Vec<Value> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(Value::is_object)
        .take(max_rows)
        .collect();
    if objects.is_empty() {
        anyhow::bail!("no JSON object lines");
    }
    Ok(json!({
        "path": path.to_string_lossy(),
        "format": "ndjson",
        "encoding": "utf-8",
        "byte_sample": byte_sample,
        "detected": {
            "record_count_sampled": objects.len(),
            "fields": infer_fields(objects.iter())
        }
    }))
}

/// CSV/TSV structure: the first line is the header; `max_rows` data rows
/// after it are sampled.
fn analyze_delimited(
    content: &str,
    path: &Path,
    byte_sample: usize,
    max_rows: usize,
    delimiter: char,
    format: &str,
) -> Result<Value> {
    let mut lines = content.lines();
    let Some(header_line) = lines.next() else {
        anyhow::bail!("empty file");
    };
    let headers: Vec<String> = header_line
        .split(delimiter)
        .map(|s| s.trim().trim_matches('"').to_string())
        .collect();
    let rows: Vec<Vec<&str>> = lines
        .take(max_rows)
        .map(|l| l.split(delimiter).collect())
        .collect();
    let columns: Vec<Value> = headers
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let values: Vec<&str> = rows
                .iter()
                .filter_map(|r| r.get(i))
                .map(|v| v.trim().trim_matches('"'))
                .collect();
            json!({"name": name, "types": column_types(&values)})
        })
        .collect();
    Ok(json!({
        "path": path.to_string_lossy(),
        "format": format,
        "encoding": "utf-8",
        "byte_sample": byte_sample,
        "detected": {
            "delimiter": delimiter.to_string(),
            "has_header": true,
            "columns": columns,
            "row_count_sampled": rows.len()
        }
    }))
}

fn analyze_text(content: &str, path: &Path, byte_sample: usize) -> Value {
    let lines: Vec<&str> = content.lines().collect();
    let avg = if lines.is_empty() {
        0
    } else {
        lines.iter().map(|l| l.len()).sum::<usize>() / lines.len()
    };
    let nulls = content.bytes().filter(|&b| b == 0).count();
    let control = content
        .bytes()
        .filter(|&b| b < 32 && !matches!(b, 9 | 10 | 13))
        .count();
    json!({
        "path": path.to_string_lossy(),
        "format": "text",
        "encoding": "utf-8",
        "byte_sample": byte_sample,
        "detected": {
            "line_count_sampled": lines.len(),
            "avg_line_length": avg,
            "is_binary_like": nulls > 0 || (!content.is_empty() && control * 10 > content.len())
        }
    })
}

fn infer_fields<'a>(objects: impl Iterator<Item = &'a Value>) -> Vec<Value> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut fields: BTreeMap<String, BTreeSet<&'static str>> = BTreeMap::new();
    for obj in objects {
        if let Value::Object(map) = obj {
            for (k, v) in map {
                fields.entry(k.clone()).or_default().insert(value_type(v));
            }
        }
    }
    fields
        .into_iter()
        .map(|(name, types)| json!({"name": name, "types": types.into_iter().collect::<Vec<_>>()}))
        .collect()
}

fn value_type(v: &Value) -> &'static str {
    match v {
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::String(s) if is_datetime_like(s) => "datetime",
        other => json_type(other),
    }
}

fn json_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn column_types(values: &[&str]) -> Vec<&'static str> {
    use std::collections::BTreeSet;
    let mut types = BTreeSet::new();
    for &v in values {
        let lower = v.to_ascii_lowercase();
        let t = if v.is_empty() || lower == "null" {
            "null"
        } else if lower == "true" || lower == "false" {
            "boolean"
        } else if v.parse::<i64>().is_ok() {
            "integer"
        } else if v.parse::<f64>().is_ok() {
            "number"
        } else if is_datetime_like(v) {
            "datetime"
        } else {
            "string"
        };
        types.insert(t);
    }
    if types.is_empty() {
        types.insert("string");
    }
    types.into_iter().collect()
}

/// `YYYY-MM-...` dates and timestamps.
fn is_datetime_like(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() >= 10
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'-'
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn first_lines_cuts_and_keeps() {
        assert_eq!(first_lines("a\nb\nc\n", 2), "a\nb");
        assert_eq!(first_lines("a\nb\n", 2), "a\nb\n");
        assert_eq!(first_lines("a", 1), "a");
        assert_eq!(first_lines("", 3), "");
    }

    #[test]
    fn datetime_detection() {
        assert!(is_datetime_like("2026-01-05"));
        assert!(is_datetime_like("2026-01-05T10:00:00Z"));
        assert!(!is_datetime_like("2026-1-5"));
        assert!(!is_datetime_like("hello-world"));
        assert!(!is_datetime_like("ééééé-ééé"));
    }

    /// Yields one byte every 20 ms, forever.
    struct Slow;
    impl Read for Slow {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            std::thread::sleep(std::time::Duration::from_millis(20));
            buf[0] = b'x';
            Ok(1)
        }
    }

    #[test]
    fn read_sample_stops_at_the_deadline() {
        let err = read_sample(Slow, 1 << 20, Path::new("f"), Deadline::after_ms(150)).unwrap_err();
        let st = super::super::common::status_of(&err);
        assert_eq!(st.exit_code(), 124);
        let reason = st.reason.unwrap();
        assert!(
            reason.starts_with("[file.timeout] timed out after timeout_ms=150; "),
            "{reason}"
        );
        assert!(reason.contains("bytes of f were read"), "{reason}");
        // Without a deadline the sample is bounded by max.
        assert_eq!(
            read_sample(Slow, 3, Path::new("f"), Deadline::after_ms(0)).unwrap(),
            b"xxx"
        );
    }

    #[test]
    fn csv_max_rows_counts_data_rows() {
        let v =
            analyze_delimited("a,b\n1,x\n2,y\n3,z\n", Path::new("f"), 0, 2, ',', "csv").unwrap();
        assert_eq!(v["detected"]["row_count_sampled"], 2);
        let v = analyze_delimited("a,b\n1,x\n", Path::new("f"), 0, 1, ',', "csv").unwrap();
        assert_eq!(v["detected"]["row_count_sampled"], 1);
    }
}
