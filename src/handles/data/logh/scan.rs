//! Reading lines from the end of a file, and splitting a byte stream into
//! lines, with memory bounded by `MAX_LINE_BYTES` per line whatever the
//! input holds. Invalid UTF-8 is replaced with U+FFFD, and a `\r` before the
//! newline is dropped.

use super::MAX_LINE_BYTES;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::FileExt;
use std::time::Instant;

/// Bytes read per step of the backward scan.
const CHUNK: usize = 64 * 1024;
/// Most bytes `read_from` reads in one call, so a fast writer cannot keep a
/// follower from checking its deadline.
const MAX_READ_PER_CALL: u64 = 64 * 1024 * 1024;

/// The last lines of a file.
#[derive(Debug, Default)]
pub struct Tail {
    pub lines: Vec<String>,
    /// How many of `lines` were cut to `MAX_LINE_BYTES`.
    pub cut: usize,
    /// Where the last line starts when it has no newline yet (it is still
    /// being written), so a follower can read it again in full.
    pub partial_start: Option<u64>,
}

#[derive(Debug)]
pub enum ScanError {
    Timeout,
    Io(io::Error),
}

impl From<io::Error> for ScanError {
    fn from(e: io::Error) -> Self {
        ScanError::Io(e)
    }
}

fn check(deadline: Option<Instant>) -> Result<(), ScanError> {
    match deadline {
        Some(d) if Instant::now() >= d => Err(ScanError::Timeout),
        _ => Ok(()),
    }
}

/// Converts one line's bytes to text.
pub fn text(mut bytes: &[u8]) -> String {
    if let [rest @ .., b'\r'] = bytes {
        bytes = rest;
    }
    String::from_utf8_lossy(bytes).into_owned()
}

/// The last `n` lines of the first `end` bytes of `file`. Only newline
/// positions are kept while scanning backward, then each line is read (at
/// most `MAX_LINE_BYTES` of it), so neither a huge file nor a huge line is
/// held in memory.
pub fn last_lines(
    file: &File,
    end: u64,
    n: usize,
    deadline: Option<Instant>,
) -> Result<Tail, ScanError> {
    let mut tail = Tail::default();
    if end == 0 || n == 0 {
        return Ok(tail);
    }
    let mut last = [0u8; 1];
    file.read_exact_at(&mut last, end - 1)?;
    let content_end = if last[0] == b'\n' { end - 1 } else { end };

    // Line starts, newest first.
    let mut starts: Vec<u64> = Vec::new();
    let mut buf = vec![0u8; CHUNK];
    let mut pos = content_end;
    'scan: while pos > 0 {
        check(deadline)?;
        let lo = pos.saturating_sub(CHUNK as u64);
        let len = (pos - lo) as usize;
        file.read_exact_at(&mut buf[..len], lo)?;
        for i in (0..len).rev() {
            if buf[i] == b'\n' {
                starts.push(lo + i as u64 + 1);
                if starts.len() == n {
                    break 'scan;
                }
            }
        }
        pos = lo;
    }
    if starts.len() < n {
        starts.push(0);
    }
    starts.reverse();

    for (i, &start) in starts.iter().enumerate() {
        check(deadline)?;
        let stop = starts.get(i + 1).map_or(content_end, |next| next - 1);
        let len = stop - start;
        let take = len.min(MAX_LINE_BYTES as u64) as usize;
        let mut line = vec![0u8; take];
        file.read_exact_at(&mut line, start)?;
        if len > take as u64 {
            tail.cut += 1;
        }
        tail.lines.push(text(&line));
    }
    if content_end == end {
        tail.partial_start = starts.last().copied();
    }
    Ok(tail)
}

/// Reads `file` from `offset` to its end (at most `MAX_READ_PER_CALL`
/// bytes), handing each chunk to `f`. Returns the number of bytes read.
pub fn read_from(file: &mut File, offset: u64, mut f: impl FnMut(&[u8])) -> io::Result<u64> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    while total < MAX_READ_PER_CALL {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            // O_NONBLOCK on a regular file never blocks; treat it as EOF.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        };
        f(&buf[..n]);
        total += n as u64;
    }
    Ok(total)
}

/// Splits a byte stream into lines. A line longer than `MAX_LINE_BYTES` is
/// emitted cut to that length and the rest of it is skipped. The first
/// error from the line sink is kept and stops further output.
#[derive(Debug, Default)]
pub struct LineSplitter {
    buf: Vec<u8>,
    skipping: bool,
    /// Lines cut since this was last reset.
    pub cut: usize,
    error: Option<io::Error>,
}

impl LineSplitter {
    pub fn push(&mut self, mut chunk: &[u8], mut out: impl FnMut(&str) -> io::Result<()>) {
        while !chunk.is_empty() {
            match chunk.iter().position(|b| *b == b'\n') {
                Some(i) => {
                    if !self.skipping {
                        let seg = &chunk[..i];
                        let room = MAX_LINE_BYTES - self.buf.len();
                        if seg.len() > room {
                            self.buf.extend_from_slice(&seg[..room]);
                            self.cut += 1;
                        } else {
                            self.buf.extend_from_slice(seg);
                        }
                        self.emit(&mut out);
                    }
                    self.skipping = false;
                    self.buf.clear();
                    chunk = &chunk[i + 1..];
                }
                None => {
                    if !self.skipping {
                        let room = MAX_LINE_BYTES - self.buf.len();
                        if chunk.len() > room {
                            self.buf.extend_from_slice(&chunk[..room]);
                            self.cut += 1;
                            self.emit(&mut out);
                            self.buf.clear();
                            self.skipping = true;
                        } else {
                            self.buf.extend_from_slice(chunk);
                        }
                    }
                    chunk = &[];
                }
            }
        }
    }

    fn emit(&mut self, out: &mut impl FnMut(&str) -> io::Result<()>) {
        if self.error.is_none()
            && let Err(e) = out(&text(&self.buf))
        {
            self.error = Some(e);
        }
    }

    /// The first error the line sink returned, if any.
    pub fn take_error(&mut self) -> io::Result<()> {
        self.error.take().map_or(Ok(()), Err)
    }

    /// The unterminated last line, if there is one; the splitter is reset.
    pub fn finish(&mut self) -> Option<String> {
        let rest = (!self.skipping && !self.buf.is_empty()).then(|| text(&self.buf));
        self.buf.clear();
        self.skipping = false;
        rest
    }
}
