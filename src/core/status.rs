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

    /// A failure with a stable error code, reported on stderr in the
    /// project-wide format `Error: [<handle>.<code>] <message>` (see
    /// [`error_line`]). `exit` follows the 0/1/2/124 convention.
    pub fn coded(exit: i32, code: &str, message: impl AsRef<str>) -> Self {
        Self::err(exit, format!("[{code}] {}", message.as_ref()))
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

/// Exit codes shared by every handle.
pub mod exit {
    /// The operation failed: not found, refused by the system, a backend or
    /// tool error, or a partial failure.
    pub const FAILED: i32 = 1;
    /// Invalid usage or arguments; nothing was done.
    pub const USAGE: i32 = 2;
    /// The deadline passed, or the outcome is unknown.
    pub const TIMEOUT: i32 = 124;
}

/// The project-wide stderr error line: `Error: [<handle>.<code>] <message>`.
/// Codes are lowercase snake_case, prefixed with the handle name
/// (`fs.not_mounted`, `file.not_found`), and documented per handle.
pub fn error_line(code: &str, message: &str) -> String {
    format!("Error: [{code}] {message}")
}

/// The project-wide JSON error object, `{"code": ..., "message": ...}`, for
/// results that report failures in their JSON output (as `"error"`).
pub fn error_json(code: &str, message: &str) -> Value {
    serde_json::json!({ "code": code, "message": message })
}

/// The handle name that prefixes error codes for a stage on `scheme`. A
/// scheme served by another handle uses that handle's codes: `https://` is
/// the http handle, documented with `http.` codes.
pub fn error_prefix(scheme: &str) -> &str {
    match scheme {
        "https" => "http",
        s => s,
    }
}

/// What is wrong with an argument resh refuses before the handle runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgProblem {
    /// The verb does not take it: `dry_run=true` without a dry-run mode, a
    /// misspelled `dry_run` key, a bare word that is not `key=value`.
    Unsupported,
    /// A malformed value, such as `dry_run=maybe`.
    Invalid,
}

/// The error code `handle` documents for `problem` with an argument of
/// `verb`, so that the refusals resh makes before the handle runs (the
/// `dry_run` guard and bare words) carry the same code as the handle's own
/// refusal of the same argument. `verb_known` is false for a verb the handle
/// does not have; then the generic `<handle>.invalid_argument` is used.
pub fn argument_error_code(
    handle: &str,
    verb: &str,
    verb_known: bool,
    problem: ArgProblem,
) -> String {
    let h = error_prefix(handle);
    match (h, verb_known, problem) {
        // Per-verb codes.
        ("archive" | "cron", true, _) => format!("{h}.{verb}_invalid_argument"),
        ("git", true, _) if verb == "sync" => "git.sync_invalid_config".to_string(),
        ("git", true, _) => format!("git.invalid_{verb}_config"),
        // Handles with their own spelling of the code.
        ("file", _, _) => "file.invalid_arg".to_string(),
        ("dns" | "http", _, ArgProblem::Unsupported) => format!("{h}.unknown_argument"),
        _ => format!("{h}.invalid_argument"),
    }
}

/// True if `code` has the required form: `<handle>.<name>`, both parts
/// lowercase ASCII letters, digits and underscores, starting with a letter.
pub fn is_valid_error_code(code: &str) -> bool {
    let part = |s: &str| {
        s.chars().next().is_some_and(|c| c.is_ascii_lowercase())
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    };
    match code.split_once('.') {
        Some((handle, name)) => part(handle) && !name.is_empty() && name.split('.').all(part),
        None => false,
    }
}

#[cfg(test)]
mod error_format_tests {
    use super::*;

    #[test]
    fn coded_status_prints_the_standard_line() {
        let st = Status::coded(exit::USAGE, "fs.invalid_argument", "bad by=x");
        assert_eq!(st.exit_code(), 2);
        let mut out = Vec::new();
        report_failure(&st, false, &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "Error: [fs.invalid_argument] bad by=x\n"
        );
        assert_eq!(
            error_line("fs.not_mounted", "nothing at /mnt"),
            "Error: [fs.not_mounted] nothing at /mnt"
        );
        assert_eq!(
            error_json("file.not_found", "x"),
            serde_json::json!({"code": "file.not_found", "message": "x"})
        );
    }

    #[test]
    fn https_stages_use_the_http_codes() {
        assert_eq!(error_prefix("https"), "http");
        assert_eq!(error_prefix("http"), "http");
        assert_eq!(error_prefix("file"), "file");
    }

    #[test]
    fn error_code_form() {
        for ok in [
            "fs.not_mounted",
            "archive.extract_max_size_exceeded",
            "dns.zone_update_timeout",
            "cert.signer_load_failed",
        ] {
            assert!(is_valid_error_code(ok), "{ok}");
        }
        for bad in [
            "NOT_FOUND",
            "fs",
            "fs.",
            ".x",
            "Fs.x",
            "fs.Not",
            "fs.not-mounted",
            "fs.1x",
        ] {
            assert!(!is_valid_error_code(bad), "{bad}");
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
