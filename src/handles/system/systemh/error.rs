//! The system handle's error codes. Every failure is reported as
//! `Error: [system.<code>] <message>` on stderr (and, for `format=json`, as
//! `"error": {"code", "message"}` in the JSON result) with the exit code
//! listed here.

use crate::core::status::exit;
use serde_json::{Value, json};
use std::fmt;

/// Every code the handle emits, with its exit code. The docs page lists the
/// same codes (a test checks it).
pub const ERROR_CODES: &[(&str, i32)] = &[
    ("system.invalid_argument", exit::USAGE),
    ("system.unknown_verb", exit::USAGE),
    ("system.timeout", exit::TIMEOUT),
    ("system.uptime_unavailable", exit::FAILED),
    ("system.uptime_parse_error", exit::FAILED),
    ("system.load_unavailable", exit::FAILED),
    ("system.load_parse_error", exit::FAILED),
    ("system.memory_meminfo_unavailable", exit::FAILED),
    ("system.memory_meminfo_parse_error", exit::FAILED),
    ("system.cpu_stat_unavailable", exit::FAILED),
    ("system.cpu_stat_parse_error", exit::FAILED),
    ("system.disk_mounts_unavailable", exit::FAILED),
    ("system.disk_mounts_parse_error", exit::FAILED),
    ("system.disk_mount_not_found", exit::FAILED),
    ("system.env_list_pid_not_found", exit::FAILED),
    ("system.env_list_permission_denied", exit::FAILED),
    ("system.env_list_unavailable", exit::FAILED),
];

/// The exit code for `code` (1 for a code not in the table).
pub fn exit_for(code: &str) -> i32 {
    ERROR_CODES
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, e)| *e)
        .unwrap_or(exit::FAILED)
}

/// A failure with its stable code.
#[derive(Debug, Clone, PartialEq)]
pub struct SysError {
    pub code: &'static str,
    pub message: String,
}

impl SysError {
    pub fn new(code: &'static str, message: impl Into<String>) -> SysError {
        debug_assert!(ERROR_CODES.iter().any(|(c, _)| *c == code), "{code}");
        SysError {
            code,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> SysError {
        SysError::new("system.invalid_argument", message)
    }

    pub fn exit(&self) -> i32 {
        exit_for(self.code)
    }

    pub fn to_json(&self) -> Value {
        json!({ "code": self.code, "message": self.message })
    }
}

impl fmt::Display for SysError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
