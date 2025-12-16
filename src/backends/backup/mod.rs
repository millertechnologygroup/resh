use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use serde_json::Value;
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};
use std::thread;
use std::sync::mpsc;

pub mod restic;
pub mod borg;
pub mod rsync;
pub mod tar;
pub mod stub;

pub use restic::ResticBackend;
pub use borg::BorgBackend;
pub use rsync::RsyncBackend;
pub use tar::TarBackend;
pub use stub::StubBackend;

/// Arguments for backup creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateArgs {
    pub backend: String,
    pub src: String, // semicolon-separated paths
    pub repo: String,
    pub tag: Option<String>,
    pub message: Option<String>,
    pub exclude: Option<String>, // semicolon-separated globs
    pub encrypt: Option<String>,
    pub key_ref: Option<String>,
    pub retention: Option<String>,
    pub timeout_ms: u64,
    pub dry_run: bool,
    pub emit_events: bool,
}

/// Arguments for backup listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListArgs {
    pub backend: String,
    pub repo: String,
    pub limit: Option<u32>,
    pub sort: Option<String>, // time_desc, time_asc
    pub filter_tag: Option<String>,
    pub timeout_ms: u64,
    pub dry_run: bool,
    pub emit_events: bool,
}

/// Arguments for backup restoration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreArgs {
    pub backend: String,
    pub repo: String,
    pub snapshot: String, // latest or ID
    pub target: String,
    pub include: Option<String>, // semicolon-separated globs
    pub exclude: Option<String>, // semicolon-separated globs
    pub overwrite: Option<String>, // skip or replace
    pub timeout_ms: u64,
    pub dry_run: bool,
    pub emit_events: bool,
}

/// Arguments for backup verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyArgs {
    pub backend: String,
    pub repo: String,
    pub snapshot: Option<String>, // latest, ID, or all
    pub mode: Option<String>, // quick or full
    pub timeout_ms: u64,
    pub dry_run: bool,
    pub emit_events: bool,
}

/// Arguments for backup pruning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruneArgs {
    pub backend: String,
    pub repo: String,
    pub policy: String,
    pub timeout_ms: u64,
    pub dry_run: bool,
    pub emit_events: bool,
}

/// Result of backend execution
#[derive(Debug, Clone)]
pub struct BackendOutcome {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub command: Vec<String>,
    pub env: HashMap<String, String>,
    pub cwd: Option<String>,
    pub duration_ms: u64,
    pub timed_out: bool,
}

/// Snapshot information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct SnapshotInfo {
    pub id: String,
    pub time: String, // RFC3339
    pub tags: Vec<String>,
    pub message: Option<String>,
    pub host: Option<String>,
    pub paths: Vec<String>,
    pub summary: SnapshotSummary,
}

/// Snapshot summary statistics
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct SnapshotSummary {
    pub files: u64,
    pub bytes: u64,
}

/// Backup creation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupStats {
    pub files_new: u64,
    pub files_changed: u64,
    pub bytes_added: u64,
    pub bytes_processed: u64,
}

/// Restore result information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreResult {
    pub target: String,
    pub snapshot: String,
    pub files: u64,
    pub bytes: u64,
}

/// Verification issue
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct VerificationIssue {
    pub kind: String, // corrupt, missing, mismatch
    pub item: String,
    pub message: String,
}

/// Verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub verified: bool,
    pub mode: String,
    pub checked_snapshots: u64,
    pub issues: Vec<VerificationIssue>,
}

/// Pruning result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruneResult {
    pub policy: String,
    pub candidates: Vec<String>,
    pub deleted: Vec<String>,
    pub kept: Vec<String>,
    pub reclaimed_bytes: u64,
}

/// Main trait for backup backends
pub trait BackupBackend: Send + Sync {
    /// Get backend ID
    fn id(&self) -> &str;
    
    /// Get backend version if available
    fn version(&self) -> Option<String> {
        None
    }
    
    /// Check if backend is available
    fn is_available(&self) -> bool;
    
    /// Create a new backup
    fn create(&self, args: &CreateArgs) -> Result<(BackendOutcome, Option<String>, Option<BackupStats>)>;
    
    /// List existing backups
    fn list(&self, args: &ListArgs) -> Result<(BackendOutcome, Vec<SnapshotInfo>)>;
    
    /// Restore a backup
    fn restore(&self, args: &RestoreArgs) -> Result<(BackendOutcome, Option<RestoreResult>)>;
    
    /// Verify backup integrity
    fn verify(&self, args: &VerifyArgs) -> Result<(BackendOutcome, Option<VerificationResult>)>;
    
    /// Prune old backups
    fn prune(&self, args: &PruneArgs) -> Result<(BackendOutcome, Option<PruneResult>)>;
}

/// Execute command with timeout and capture output
pub fn execute_with_timeout(
    mut command: Command,
    timeout_ms: u64,
) -> Result<BackendOutcome> {
    let start_time = SystemTime::now();
    
    // Set up command for execution
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    
    let mut child = command.spawn().map_err(|e| {
        anyhow!("Failed to spawn command: {}", e)
    })?;
    
    let timeout = Duration::from_millis(timeout_ms);
    let (sender, receiver) = mpsc::channel();
    
    // Spawn a thread to wait for the process
    thread::spawn(move || {
        let result = child.wait_with_output();
        let _ = sender.send(result);
    });
    
    // Wait for either completion or timeout
    let output = match receiver.recv_timeout(timeout) {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => return Err(anyhow!("Process execution failed: {}", e)),
        Err(_) => {
            // Timeout occurred, try to kill the process
            // Note: In a real implementation, we'd need to store child PID
            // and kill it properly. For now, we'll mark it as timed out.
            return Ok(BackendOutcome {
                exit_code: 124,
                stdout: String::new(),
                stderr: "Process timed out".to_string(),
                command: vec!["unknown".to_string()],
                env: HashMap::new(),
                cwd: None,
                duration_ms: timeout_ms,
                timed_out: true,
            });
        }
    };
    
    let duration_ms = start_time.elapsed()
        .unwrap_or_default()
        .as_millis() as u64;
    
    Ok(BackendOutcome {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        command: vec!["unknown".to_string()], // Will be filled by caller
        env: HashMap::new(), // Will be filled by caller
        cwd: None, // Will be filled by caller
        duration_ms,
        timed_out: false,
    })
}

/// Parse policy string into structured format
/// Format: "keep_last=7;keep_daily=14;keep_weekly=8;keep_monthly=12"
pub fn parse_retention_policy(policy: &str) -> Result<HashMap<String, u32>> {
    let mut parsed = HashMap::new();
    
    for part in policy.split(';') {
        let kv: Vec<&str> = part.trim().split('=').collect();
        if kv.len() != 2 {
            return Err(anyhow!("Invalid policy format: {}", part));
        }
        
        let key = kv[0].trim();
        let value = kv[1].trim().parse::<u32>()
            .map_err(|_| anyhow!("Invalid policy value: {}", kv[1]))?;
        
        parsed.insert(key.to_string(), value);
    }
    
    if parsed.is_empty() {
        return Err(anyhow!("Empty retention policy"));
    }
    
    Ok(parsed)
}

/// Get backend instance by ID
pub fn get_backend(backend_id: &str) -> Result<Box<dyn BackupBackend>> {
    match backend_id.to_lowercase().as_str() {
        "restic" => Ok(Box::new(ResticBackend::new())),
        "borg" => Ok(Box::new(BorgBackend::new())),
        "rsync" => Ok(Box::new(RsyncBackend::new())),
        "tar" => Ok(Box::new(TarBackend::new())),
        "stub" => Ok(Box::new(StubBackend::new())),
        _ => Err(anyhow!("Unsupported backend: {}", backend_id)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_retention_policy() {
        let policy = "keep_last=7;keep_daily=14;keep_weekly=8;keep_monthly=12";
        let parsed = parse_retention_policy(policy).unwrap();
        
        assert_eq!(parsed["keep_last"], 7);
        assert_eq!(parsed["keep_daily"], 14);
        assert_eq!(parsed["keep_weekly"], 8);
        assert_eq!(parsed["keep_monthly"], 12);
    }

    #[test]
    fn test_parse_retention_policy_invalid() {
        assert!(parse_retention_policy("invalid").is_err());
        assert!(parse_retention_policy("keep_last=abc").is_err());
        assert!(parse_retention_policy("").is_err());
    }

    #[test]
    fn test_get_backend() {
        assert!(get_backend("restic").is_ok());
        assert!(get_backend("borg").is_ok());
        assert!(get_backend("rsync").is_ok());
        assert!(get_backend("tar").is_ok());
        assert!(get_backend("stub").is_ok());
        assert!(get_backend("invalid").is_err());
    }

    #[test]
    fn test_snapshot_info_ordering() {
        let mut snapshots = vec![
            SnapshotInfo {
                id: "b".to_string(),
                time: "2023-12-01T10:00:00Z".to_string(),
                tags: vec![],
                message: None,
                host: None,
                paths: vec![],
                summary: SnapshotSummary { files: 0, bytes: 0 },
            },
            SnapshotInfo {
                id: "a".to_string(),
                time: "2023-12-01T09:00:00Z".to_string(),
                tags: vec![],
                message: None,
                host: None,
                paths: vec![],
                summary: SnapshotSummary { files: 0, bytes: 0 },
            },
        ];
        
        snapshots.sort();
        assert_eq!(snapshots[0].id, "a");
        assert_eq!(snapshots[1].id, "b");
    }
}