use anyhow::{Result, anyhow, Context};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};
use std::fs;
use regex::Regex;
use chrono::{DateTime, Utc};
use crate::handles::automation::backup::policy::RetentionPolicy;

/// Information about a backup snapshot to be pruned
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotInfo {
    pub id: String,
    pub time: String,
    pub reason: String,
}

/// Result of a pruning operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruneResult {
    pub items_considered: u32,
    pub items_to_delete: u32,
    pub deleted: u32,
    pub bytes_estimated_freed: Option<u64>,
    pub snapshots: Vec<SnapshotInfo>,
}

/// Tool runner with timeout and output capture
pub struct ToolRunner {
    timeout: Duration,
}

impl ToolRunner {
    pub fn new(timeout_ms: u64) -> Self {
        let timeout = if timeout_ms == 0 {
            Duration::from_secs(3600) // 1 hour default
        } else {
            Duration::from_millis(timeout_ms)
        };
        
        Self { timeout }
    }

    /// Execute a command with timeout and capture output
    pub fn execute(&self, command: &mut Command) -> Result<Output> {
        let start = Instant::now();
        
        let output = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("failed to execute command")?;

        if start.elapsed() > self.timeout {
            return Err(anyhow!("command timed out after {:?}", self.timeout));
        }

        Ok(output)
    }

    /// Check if a tool is available on PATH
    pub fn is_tool_available(tool: &str) -> bool {
        Command::new("which")
            .arg(tool)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
}

/// Restic backup tool wrapper
pub struct ResticTool {
    pub repo_url: String,
    pub repo_password: String,
    pub extra_env: HashMap<String, String>,
}

impl ResticTool {
    pub fn new(repo_url: String, repo_password: String) -> Self {
        Self {
            repo_url,
            repo_password,
            extra_env: HashMap::new(),
        }
    }

    pub fn with_env(mut self, key: String, value: String) -> Self {
        self.extra_env.insert(key, value);
        self
    }

    /// Execute restic forget with prune for retention policy
    pub fn prune(&self, policy: &RetentionPolicy, dry_run: bool, runner: &ToolRunner) -> Result<PruneResult> {
        let mut cmd = Command::new("restic");
        cmd.arg("forget")
            .arg("--prune")
            .arg("--repo")
            .arg(&self.repo_url)
            .env("RESTIC_PASSWORD", &self.repo_password);

        // Add extra environment variables
        for (key, value) in &self.extra_env {
            cmd.env(key, value);
        }

        // Add retention arguments
        for arg in policy.to_restic_args() {
            cmd.arg(arg);
        }

        if dry_run {
            cmd.arg("--dry-run");
        }

        cmd.arg("--json");

        let output = runner.execute(&mut cmd)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("restic forget failed: {}", stderr));
        }

        self.parse_restic_output(&output.stdout, dry_run)
    }

    /// Parse restic forget --json output
    fn parse_restic_output(&self, stdout: &[u8], dry_run: bool) -> Result<PruneResult> {
        let output_str = String::from_utf8_lossy(stdout);
        let mut snapshots = Vec::new();
        let mut items_considered = 0;
        let mut items_to_delete = 0;
        let mut bytes_freed = None;

        // Parse JSON lines from restic output
        for line in output_str.lines() {
            let line = line.trim();
            if line.is_empty() || !line.starts_with('{') {
                continue;
            }

            if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(message_type) = json_val.get("message_type").and_then(|v| v.as_str()) {
                    match message_type {
                        "summary" => {
                            if let Some(keep_reasons) = json_val.get("keep_reasons") {
                                items_considered = keep_reasons.as_object()
                                    .map(|obj| obj.len() as u32)
                                    .unwrap_or(0);
                            }
                            if let Some(remove_count) = json_val.get("remove").and_then(|v| v.as_u64()) {
                                items_to_delete = remove_count as u32;
                            }
                        }
                        "snapshot" => {
                            if let (Some(id), Some(time)) = (
                                json_val.get("short_id").and_then(|v| v.as_str()),
                                json_val.get("time").and_then(|v| v.as_str())
                            ) {
                                let reason = json_val.get("reasons")
                                    .and_then(|v| v.as_array())
                                    .map(|arr| arr.iter()
                                        .filter_map(|v| v.as_str())
                                        .collect::<Vec<_>>()
                                        .join(", "))
                                    .unwrap_or_else(|| "expired".to_string());

                                snapshots.push(SnapshotInfo {
                                    id: id.to_string(),
                                    time: time.to_string(),
                                    reason,
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(PruneResult {
            items_considered,
            items_to_delete,
            deleted: if dry_run { 0 } else { items_to_delete },
            bytes_estimated_freed: bytes_freed,
            snapshots,
        })
    }

    /// Check if repository exists and is accessible
    pub fn check_repository(&self, runner: &ToolRunner) -> Result<bool> {
        let mut cmd = Command::new("restic");
        cmd.arg("snapshots")
            .arg("--repo")
            .arg(&self.repo_url)
            .arg("--json")
            .env("RESTIC_PASSWORD", &self.repo_password);

        // Add extra environment variables
        for (key, value) in &self.extra_env {
            cmd.env(key, value);
        }

        let output = runner.execute(&mut cmd)?;
        Ok(output.status.success())
    }
}

/// Borg backup tool wrapper  
pub struct BorgTool {
    pub repo_path: String,
    pub repo_password: Option<String>,
    pub extra_env: HashMap<String, String>,
}

impl BorgTool {
    pub fn new(repo_path: String, repo_password: Option<String>) -> Self {
        Self {
            repo_path,
            repo_password,
            extra_env: HashMap::new(),
        }
    }

    pub fn with_env(mut self, key: String, value: String) -> Self {
        self.extra_env.insert(key, value);
        self
    }

    /// Execute borg prune for retention policy
    pub fn prune(&self, policy: &RetentionPolicy, dry_run: bool, runner: &ToolRunner) -> Result<PruneResult> {
        let mut cmd = Command::new("borg");
        cmd.arg("prune")
            .arg(&self.repo_path);

        // Add extra environment variables and password
        for (key, value) in &self.extra_env {
            cmd.env(key, value);
        }
        if let Some(password) = &self.repo_password {
            cmd.env("BORG_PASSPHRASE", password);
        }

        // Add retention arguments
        for arg in policy.to_borg_args() {
            cmd.arg(arg);
        }

        if dry_run {
            cmd.arg("--dry-run");
        }

        // Try to use JSON output if supported
        cmd.arg("--list")
            .arg("--stats");

        let output = runner.execute(&mut cmd)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("borg prune failed: {}", stderr));
        }

        self.parse_borg_output(&output.stdout, &output.stderr, dry_run)
    }

    /// Parse borg prune output (text-based, borg doesn't always have JSON for prune)
    fn parse_borg_output(&self, stdout: &[u8], stderr: &[u8], dry_run: bool) -> Result<PruneResult> {
        let stdout_str = String::from_utf8_lossy(stdout);
        let stderr_str = String::from_utf8_lossy(stderr);
        let combined = format!("{}\n{}", stdout_str, stderr_str);
        
        let mut snapshots = Vec::new();
        let mut items_considered = 0;
        let mut items_to_delete = 0;
        let mut bytes_freed = None;

        // Parse borg output for archive information
        let archive_regex = Regex::new(r"(.+?)\s+(.+?)\s+(.+)")?;
        for line in combined.lines() {
            let line = line.trim();
            
            // Look for "Pruning" or "Would prune" lines
            if line.contains("Pruning") || line.contains("Would prune") {
                if let Some(captures) = archive_regex.captures(line) {
                    items_to_delete += 1;
                    
                    // Extract archive name and create snapshot info
                    if captures.len() >= 2 {
                        let archive_name = captures.get(1)
                            .map(|m| m.as_str().trim())
                            .unwrap_or("unknown");
                        
                        snapshots.push(SnapshotInfo {
                            id: archive_name.to_string(),
                            time: "unknown".to_string(), // Borg doesn't always provide timestamp in this format
                            reason: "expired".to_string(),
                        });
                    }
                }
            }
            
            // Look for statistics
            if line.contains("archives") {
                // Try to extract number of archives considered
                let numbers: Vec<&str> = line.split_whitespace()
                    .filter(|s| s.parse::<u32>().is_ok())
                    .collect();
                if !numbers.is_empty() {
                    if let Ok(count) = numbers[0].parse::<u32>() {
                        items_considered = count;
                    }
                }
            }
            
            // Look for space savings
            if line.contains("freed") || line.contains("saved") {
                // Extract byte information if present
                if let Some(bytes_str) = line.split_whitespace()
                    .find(|s| s.ends_with("B") || s.ends_with("MB") || s.ends_with("GB")) {
                    bytes_freed = parse_size_string(bytes_str);
                }
            }
        }

        Ok(PruneResult {
            items_considered,
            items_to_delete,
            deleted: if dry_run { 0 } else { items_to_delete },
            bytes_estimated_freed: bytes_freed,
            snapshots,
        })
    }

    /// Check if repository exists and is accessible
    pub fn check_repository(&self, runner: &ToolRunner) -> Result<bool> {
        let mut cmd = Command::new("borg");
        cmd.arg("info")
            .arg(&self.repo_path);

        // Add extra environment variables and password
        for (key, value) in &self.extra_env {
            cmd.env(key, value);
        }
        if let Some(password) = &self.repo_password {
            cmd.env("BORG_PASSPHRASE", password);
        }

        let output = runner.execute(&mut cmd)?;
        Ok(output.status.success())
    }
}

/// Parse size strings like "1.2GB", "500MB", etc. to bytes
fn parse_size_string(size_str: &str) -> Option<u64> {
    let size_str = size_str.trim().to_uppercase();
    
    if let Some(pos) = size_str.find(|c: char| c.is_alphabetic()) {
        let (number_part, unit_part) = size_str.split_at(pos);
        
        if let Ok(number) = number_part.parse::<f64>() {
            let multiplier = match unit_part {
                "B" => 1,
                "KB" => 1_024,
                "MB" => 1_024 * 1_024,
                "GB" => 1_024 * 1_024 * 1_024,
                "TB" => 1_024_u64.pow(4),
                _ => return None,
            };
            
            return Some((number * multiplier as f64) as u64);
        }
    }
    
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_availability() {
        // Test with a command that should exist on most systems
        assert!(ToolRunner::is_tool_available("echo"));
        
        // Test with a command that should not exist
        assert!(!ToolRunner::is_tool_available("nonexistent_command_12345"));
    }

    #[test]
    fn test_parse_size_string() {
        assert_eq!(parse_size_string("100B"), Some(100));
        assert_eq!(parse_size_string("1KB"), Some(1024));
        assert_eq!(parse_size_string("1.5MB"), Some(1572864));
        assert_eq!(parse_size_string("2GB"), Some(2147483648));
        assert_eq!(parse_size_string("invalid"), None);
    }

    #[test]
    fn test_tool_runner_timeout() {
        let runner = ToolRunner::new(100); // 100ms timeout
        assert_eq!(runner.timeout, Duration::from_millis(100));

        let runner_default = ToolRunner::new(0); // Default timeout
        assert_eq!(runner_default.timeout, Duration::from_secs(3600));
    }

    #[test] 
    fn test_restic_tool_creation() {
        let tool = ResticTool::new(
            "local:/tmp/test-repo".to_string(),
            "test-password".to_string()
        );
        assert_eq!(tool.repo_url, "local:/tmp/test-repo");
        assert_eq!(tool.repo_password, "test-password");
        assert!(tool.extra_env.is_empty());
    }

    #[test]
    fn test_restic_tool_with_env() {
        let tool = ResticTool::new("repo".to_string(), "pass".to_string())
            .with_env("AWS_ACCESS_KEY_ID".to_string(), "key123".to_string())
            .with_env("AWS_SECRET_ACCESS_KEY".to_string(), "secret456".to_string());
        
        assert_eq!(tool.extra_env.len(), 2);
        assert_eq!(tool.extra_env.get("AWS_ACCESS_KEY_ID"), Some(&"key123".to_string()));
    }

    #[test]
    fn test_borg_tool_creation() {
        let tool = BorgTool::new(
            "/tmp/borg-repo".to_string(),
            Some("borg-password".to_string())
        );
        assert_eq!(tool.repo_path, "/tmp/borg-repo");
        assert_eq!(tool.repo_password, Some("borg-password".to_string()));
    }
}