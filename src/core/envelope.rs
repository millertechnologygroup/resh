use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::time::SystemTime;
use anyhow::{Result, anyhow};

/// Shared JSON envelope structure for all backup handle verbs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEnvelope {
    pub ok: bool,
    pub handle: String,
    pub verb: String,
    pub target: String,
    pub ts: String,
    pub duration_ms: u64,
    pub dry_run: bool,
    pub backend: BackendInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    pub events: Vec<BackupEvent>,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<BackupError>,
}

/// Backend execution information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendInfo {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub command: Vec<String>,
    pub env_redacted: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    pub timeout_ms: u64,
    pub simulated: bool,
}

/// Structured event for progress/events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEvent {
    pub ts: String,
    pub level: String,
    pub msg: String,
    pub phase: String,
}

/// Error information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupError {
    pub kind: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl BackupEnvelope {
    /// Create a new success envelope
    pub fn success(
        verb: &str,
        target: &str,
        backend: BackendInfo,
        result: serde_json::Value,
        dry_run: bool,
        duration_ms: u64,
    ) -> Self {
        Self {
            ok: true,
            handle: "backup".to_string(),
            verb: verb.to_string(),
            target: target.to_string(),
            ts: Utc::now().to_rfc3339(),
            duration_ms,
            dry_run,
            backend,
            result: Some(result),
            events: Vec::new(),
            warnings: Vec::new(),
            error: None,
        }
    }

    /// Create a new error envelope
    pub fn error(
        verb: &str,
        target: &str,
        backend: BackendInfo,
        error: BackupError,
        dry_run: bool,
        duration_ms: u64,
    ) -> Self {
        Self {
            ok: false,
            handle: "backup".to_string(),
            verb: verb.to_string(),
            target: target.to_string(),
            ts: Utc::now().to_rfc3339(),
            duration_ms,
            dry_run,
            backend,
            result: None,
            events: Vec::new(),
            warnings: Vec::new(),
            error: Some(error),
        }
    }

    /// Add an event to the envelope
    pub fn add_event(&mut self, level: &str, msg: &str, phase: &str) {
        self.events.push(BackupEvent {
            ts: Utc::now().to_rfc3339(),
            level: level.to_string(),
            msg: msg.to_string(),
            phase: phase.to_string(),
        });
    }

    /// Add a warning to the envelope
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    /// Serialize to JSON (pretty or compact)
    pub fn to_json(&self, pretty: bool) -> Result<String> {
        if pretty {
            serde_json::to_string_pretty(self).map_err(|e| anyhow!("JSON serialization error: {}", e))
        } else {
            serde_json::to_string(self).map_err(|e| anyhow!("JSON serialization error: {}", e))
        }
    }
}

impl BackendInfo {
    pub fn new(id: &str, timeout_ms: u64) -> Self {
        Self {
            id: id.to_string(),
            version: None,
            command: Vec::new(),
            env_redacted: HashMap::new(),
            cwd: None,
            timeout_ms,
            simulated: false,
        }
    }

    /// Set command with redaction of sensitive arguments
    pub fn set_command(&mut self, command: Vec<String>) {
        self.command = redact_command_args(&command);
    }

    /// Set environment variables with redaction of secrets
    pub fn set_env(&mut self, env: &HashMap<String, String>) {
        self.env_redacted = redact_env_vars(env);
    }
}

impl BackupError {
    pub fn new(kind: &str, message: &str) -> Self {
        Self {
            kind: kind.to_string(),
            message: message.to_string(),
            details: None,
        }
    }

    pub fn with_details(kind: &str, message: &str, details: serde_json::Value) -> Self {
        Self {
            kind: kind.to_string(),
            message: message.to_string(),
            details: Some(details),
        }
    }

    /// Map common exit codes to error kinds
    pub fn from_exit_code(code: i32, stderr: &str) -> Self {
        let (kind, message) = match code {
            1 => ("backend_error", "Generic backend failure"),
            2 => ("invalid_args", "Input validation error"),
            5 => ("not_found", "Backend not installed or not found"),
            124 => ("timeout", "Operation timed out"),
            126 => ("permission", "Permission or execution failure"),
            127 => ("backend_error", "Backend invocation error"),
            _ => ("backend_error", "Unknown backend error"),
        };
        
        let full_message = if stderr.is_empty() {
            message.to_string()
        } else {
            format!("{}: {}", message, stderr.lines().next().unwrap_or(stderr))
        };
        
        Self::new(kind, &full_message)
    }
}

/// Redact sensitive information from command arguments
pub fn redact_command_args(command: &[String]) -> Vec<String> {
    let mut redacted = Vec::new();
    let mut redact_next = false;
    
    let sensitive_flags = [
        "--password", "-p", "--key", "--secret", "--token", "--auth",
        "--aws-access-key-id", "--aws-secret-access-key",
        "--azure-account-name", "--azure-account-key",
        "--gcs-key-file", "--encryption-key", "--passphrase"
    ];
    
    for arg in command {
        if redact_next {
            redacted.push("***REDACTED***".to_string());
            redact_next = false;
        } else if sensitive_flags.iter().any(|&flag| arg.starts_with(flag)) {
            if arg.contains('=') {
                // Handle --flag=value format
                let parts: Vec<&str> = arg.splitn(2, '=').collect();
                redacted.push(format!("{}=***REDACTED***", parts[0]));
            } else {
                redacted.push(arg.clone());
                redact_next = true;
            }
        } else {
            redacted.push(arg.clone());
        }
    }
    
    redacted
}

/// Redact sensitive environment variables
pub fn redact_env_vars(env: &HashMap<String, String>) -> HashMap<String, String> {
    let mut redacted = HashMap::new();
    
    let sensitive_keys = [
        "PASSWORD", "SECRET", "KEY", "TOKEN", "AUTH", "PASSPHRASE",
        "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN",
        "AZURE_STORAGE_KEY", "AZURE_STORAGE_CONNECTION_STRING",
        "GCS_KEY_FILE", "GOOGLE_APPLICATION_CREDENTIALS",
        "RESTIC_PASSWORD", "BORG_PASSPHRASE", "ENCRYPTION_KEY"
    ];
    
    for (key, value) in env {
        if sensitive_keys.iter().any(|&sensitive| key.to_uppercase().contains(sensitive)) {
            redacted.insert(key.clone(), "***REDACTED***".to_string());
        } else {
            redacted.insert(key.clone(), value.clone());
        }
    }
    
    redacted
}

/// Utility to measure execution time
pub struct Timer {
    start: SystemTime,
}

impl Timer {
    pub fn new() -> Self {
        Self {
            start: SystemTime::now(),
        }
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.start
            .elapsed()
            .unwrap_or_default()
            .as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_envelope_success() {
        let backend = BackendInfo::new("restic", 600000);
        let result = json!({"snapshot_id": "abc123"});
        let envelope = BackupEnvelope::success("create", "backup://test", backend, result, false, 1000);
        
        assert!(envelope.ok);
        assert_eq!(envelope.verb, "create");
        assert_eq!(envelope.handle, "backup");
        assert!(!envelope.dry_run);
        assert_eq!(envelope.duration_ms, 1000);
    }

    #[test]
    fn test_envelope_error() {
        let backend = BackendInfo::new("restic", 600000);
        let error = BackupError::new("timeout", "Operation timed out after 10 minutes");
        let envelope = BackupEnvelope::error("create", "backup://test", backend, error, false, 10000);
        
        assert!(!envelope.ok);
        assert!(envelope.error.is_some());
        assert!(envelope.result.is_none());
    }

    #[test]
    fn test_redact_command_args() {
        let command = vec![
            "restic".to_string(),
            "--password".to_string(),
            "secret123".to_string(),
            "--repo".to_string(),
            "/backup".to_string(),
            "--key=private-key".to_string(),
        ];
        
        let redacted = redact_command_args(&command);
        assert_eq!(redacted[0], "restic");
        assert_eq!(redacted[1], "--password");
        assert_eq!(redacted[2], "***REDACTED***");
        assert_eq!(redacted[3], "--repo");
        assert_eq!(redacted[4], "/backup");
        assert_eq!(redacted[5], "--key=***REDACTED***");
    }

    #[test]
    fn test_redact_env_vars() {
        let mut env = HashMap::new();
        env.insert("PATH".to_string(), "/usr/bin".to_string());
        env.insert("RESTIC_PASSWORD".to_string(), "secret123".to_string());
        env.insert("AWS_SECRET_ACCESS_KEY".to_string(), "aws-secret".to_string());
        
        let redacted = redact_env_vars(&env);
        assert_eq!(redacted["PATH"], "/usr/bin");
        assert_eq!(redacted["RESTIC_PASSWORD"], "***REDACTED***");
        assert_eq!(redacted["AWS_SECRET_ACCESS_KEY"], "***REDACTED***");
    }

    #[test]
    fn test_error_from_exit_code() {
        let error = BackupError::from_exit_code(124, "Command timed out");
        assert_eq!(error.kind, "timeout");
        assert!(error.message.contains("timed out"));

        let error = BackupError::from_exit_code(2, "Invalid arguments provided");
        assert_eq!(error.kind, "invalid_args");
    }

    #[test]
    fn test_json_serialization() {
        let backend = BackendInfo::new("restic", 600000);
        let result = json!({"snapshot_id": "abc123"});
        let envelope = BackupEnvelope::success("create", "backup://test", backend, result, false, 1000);
        
        let json_str = envelope.to_json(false).unwrap();
        assert!(json_str.contains("\"ok\":true"));
        assert!(json_str.contains("\"handle\":\"backup\""));
        
        let pretty_json = envelope.to_json(true).unwrap();
        assert!(pretty_json.contains("\"ok\": true"));
        assert!(pretty_json.len() > json_str.len()); // Pretty format should be longer
    }
}