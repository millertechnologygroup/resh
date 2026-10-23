use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Status {
    pub ok: bool,
    pub code: Option<i32>,
    pub reason: Option<String>,
}

impl Status {
    pub fn ok() -> Self {
        Self {
            ok: true,
            code: Some(0),
            reason: None,
        }
    }
    pub fn success() -> Self {
        Self::ok()
    }
    pub fn err(code: i32, reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            code: Some(code),
            reason: Some(reason.into()),
        }
    }

    pub fn is_success(&self) -> bool {
        self.ok
    }

    /// The process exit code for this status. Success is 0. A failure is
    /// never 0: its code is used when it is a valid exit status (1-255),
    /// otherwise 1 (for example a missing code, 0, or an HTTP status).
    pub fn exit_code(&self) -> i32 {
        if self.ok {
            return 0;
        }
        match self.code {
            Some(c) if (1..=255).contains(&c) => c,
            _ => 1,
        }
    }
}

/// Wraps a writer and records whether anything was written to it.
pub struct TrackingWriter<W> {
    inner: W,
    pub written: bool,
}

impl<W> TrackingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            written: false,
        }
    }
}

impl<W: std::io::Write> std::io::Write for TrackingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        if n > 0 {
            self.written = true;
        }
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Makes sure a failed command leaves a human-readable diagnostic on
/// stderr. If the handle already wrote to stderr, nothing is added;
/// otherwise the status reason is printed (or a generic line naming the
/// exit code when the handle gave no reason). Successes print nothing.
pub fn report_failure(
    status: &Status,
    handle_wrote_stderr: bool,
    stderr: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    if status.ok || handle_wrote_stderr {
        return Ok(());
    }
    match status
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
    {
        Some(reason) => writeln!(stderr, "Error: {}", reason),
        None => writeln!(
            stderr,
            "Error: command failed (exit code {})",
            status.exit_code()
        ),
    }
}

/// Structured error type for shell operations
#[derive(Debug, Clone)]
pub struct ShellError {
    pub code: String,
    pub message: String,
    pub details: Value,
}

impl ShellError {
    pub fn new(code: &str, message: &str, details: Value) -> Self {
        Self {
            code: code.to_string(),
            message: message.to_string(),
            details,
        }
    }
}

impl std::fmt::Display for ShellError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ShellError {}

#[cfg(test)]
mod tests {
    use super::*;

    // FUNC-02: a failed status can never become exit code 0.
    #[test]
    fn exit_code_is_nonzero_for_every_failure() {
        assert_eq!(Status::ok().exit_code(), 0);
        assert_eq!(Status::err(2, "x").exit_code(), 2);
        assert_eq!(Status::err(255, "x").exit_code(), 255);
        for code in [0, -1, 256, 404, 512, i32::MIN] {
            assert_eq!(Status::err(code, "x").exit_code(), 1, "code {code}");
        }
        let no_code = Status {
            ok: false,
            code: None,
            reason: None,
        };
        assert_eq!(no_code.exit_code(), 1);
    }

    // FUNC-01: a failure is never silent.
    #[test]
    fn failure_reason_reaches_stderr_once() {
        let mut out = Vec::new();
        report_failure(&Status::err(2, "file not found: /x"), false, &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "Error: file not found: /x\n"
        );

        // The handle already explained itself: no duplicate.
        let mut out = Vec::new();
        report_failure(&Status::err(2, "file not found: /x"), true, &mut out).unwrap();
        assert!(out.is_empty());

        // No reason given: still a diagnostic, naming the exit code.
        let mut out = Vec::new();
        report_failure(
            &Status {
                ok: false,
                code: Some(0),
                reason: Some("  ".into()),
            },
            false,
            &mut out,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "Error: command failed (exit code 1)\n"
        );

        // Success prints nothing.
        let mut out = Vec::new();
        report_failure(&Status::ok(), false, &mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn tracking_writer_records_writes() {
        use std::io::Write;
        let mut t = TrackingWriter::new(Vec::new());
        assert!(!t.written);
        t.write_all(b"").unwrap();
        assert!(!t.written);
        t.write_all(b"x").unwrap();
        assert!(t.written);
    }
}
