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


