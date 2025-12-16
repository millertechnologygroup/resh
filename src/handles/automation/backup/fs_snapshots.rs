use anyhow::{Result, anyhow, Context};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use chrono::{DateTime, Utc, NaiveDateTime};
use regex::Regex;
use crate::handles::automation::backup::policy::RetentionPolicy;
use crate::handles::automation::backup::tools::{PruneResult, SnapshotInfo};

/// Represents a filesystem-based snapshot directory
#[derive(Debug, Clone)]
pub struct SnapshotDirectory {
    pub path: PathBuf,
    pub name: String,
    pub timestamp: SystemTime,
    pub size_bytes: Option<u64>,
}

impl SnapshotDirectory {
    pub fn new(path: PathBuf) -> Result<Self> {
        let name = path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("invalid snapshot directory path: {:?}", path))?
            .to_string();

        let metadata = fs::metadata(&path)
            .with_context(|| format!("failed to read metadata for {:?}", path))?;
        
        let timestamp = metadata.modified()
            .or_else(|_| metadata.created())
            .unwrap_or(UNIX_EPOCH);

        let size_bytes = if metadata.is_dir() {
            calculate_directory_size(&path).ok()
        } else {
            Some(metadata.len())
        };

        Ok(Self {
            path,
            name,
            timestamp,
            size_bytes,
        })
    }

    /// Extract timestamp from directory name using common patterns
    pub fn extract_timestamp_from_name(&self) -> Option<SystemTime> {
        extract_timestamp_from_string(&self.name)
    }

    /// Get the age of this snapshot
    pub fn age(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.timestamp)
            .unwrap_or(Duration::from_secs(0))
    }

    /// Convert to SnapshotInfo for output
    pub fn to_snapshot_info(&self, reason: &str) -> SnapshotInfo {
        let timestamp_str = self.timestamp
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| {
                let naive = NaiveDateTime::from_timestamp_opt(d.as_secs() as i64, d.subsec_nanos())?;
                Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc).to_rfc3339())
            })
            .unwrap_or_else(|| "unknown".to_string());

        SnapshotInfo {
            id: self.name.clone(),
            time: timestamp_str,
            reason: reason.to_string(),
        }
    }
}

/// Configuration for filesystem snapshot management
#[derive(Debug, Clone)]
pub struct FilesystemConfig {
    pub base_path: PathBuf,
    pub naming_pattern: String,
    pub date_format: Option<String>,
    pub use_symlinks: bool,
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self {
            base_path: PathBuf::from("./backups"),
            naming_pattern: "*".to_string(),
            date_format: None,
            use_symlinks: false,
        }
    }
}

/// Filesystem snapshot manager for rsync/tar backups
pub struct FilesystemSnapshots {
    config: FilesystemConfig,
    lock_path: Option<PathBuf>,
}

impl FilesystemSnapshots {
    pub fn new(config: FilesystemConfig) -> Self {
        let lock_path = Some(config.base_path.join(".resh_prune.lock"));
        Self { config, lock_path }
    }

    /// Acquire a lock for safe concurrent operations
    pub fn acquire_lock(&self, timeout_ms: u64) -> Result<FilesystemLock> {
        if let Some(lock_path) = &self.lock_path {
            FilesystemLock::acquire(lock_path, Duration::from_millis(timeout_ms))
        } else {
            Ok(FilesystemLock::dummy())
        }
    }

    /// List all snapshot directories
    pub fn list_snapshots(&self) -> Result<Vec<SnapshotDirectory>> {
        let base_path = &self.config.base_path;
        if !base_path.exists() {
            return Ok(Vec::new());
        }

        let entries = fs::read_dir(base_path)
            .with_context(|| format!("failed to read snapshot directory: {:?}", base_path))?;

        let mut snapshots = Vec::new();
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() && self.matches_pattern(&path) {
                if let Ok(snapshot) = SnapshotDirectory::new(path) {
                    snapshots.push(snapshot);
                }
            }
        }

        // Sort by timestamp (oldest first)
        snapshots.sort_by_key(|s| s.timestamp);
        Ok(snapshots)
    }

    /// Check if a path matches the configured naming pattern
    fn matches_pattern(&self, path: &Path) -> bool {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if self.config.naming_pattern == "*" {
                return true;
            }
            
            // Simple glob-like matching
            let pattern = &self.config.naming_pattern;
            if pattern.contains('*') {
                let regex_pattern = pattern
                    .replace("*", ".*")
                    .replace("?", ".");
                if let Ok(regex) = Regex::new(&regex_pattern) {
                    return regex.is_match(name);
                }
            }
            
            name == pattern
        } else {
            false
        }
    }

    /// Apply retention policy to filesystem snapshots
    pub fn prune(&self, policy: &RetentionPolicy, dry_run: bool, _lock: &FilesystemLock) -> Result<PruneResult> {
        let snapshots = self.list_snapshots()?;
        let total_snapshots = snapshots.len() as u32;
        
        let to_delete = self.select_snapshots_for_deletion(&snapshots, policy)?;
        let delete_count = to_delete.len() as u32;
        
        let mut deleted = 0;
        let mut total_bytes_freed = 0u64;
        let mut snapshot_infos = Vec::new();

        for snapshot in &to_delete {
            snapshot_infos.push(snapshot.to_snapshot_info("expired"));
            
            if let Some(size) = snapshot.size_bytes {
                total_bytes_freed += size;
            }
            
            if !dry_run {
                self.delete_snapshot(snapshot)?;
                deleted += 1;
            }
        }

        Ok(PruneResult {
            items_considered: total_snapshots,
            items_to_delete: delete_count,
            deleted,
            bytes_estimated_freed: Some(total_bytes_freed),
            snapshots: snapshot_infos,
        })
    }

    /// Select snapshots for deletion based on retention policy
    fn select_snapshots_for_deletion(&self, snapshots: &[SnapshotDirectory], policy: &RetentionPolicy) -> Result<Vec<SnapshotDirectory>> {
        let mut snapshots = snapshots.to_vec();
        snapshots.sort_by(|a, b| b.timestamp.cmp(&a.timestamp)); // Sort newest first for retention logic

        let mut to_keep = Vec::new();
        let mut to_delete = Vec::new();

        // Apply keep-last policy
        if let Some(keep_last) = policy.keep_last {
            let keep_count = std::cmp::min(keep_last as usize, snapshots.len());
            to_keep.extend_from_slice(&snapshots[..keep_count]);
            to_delete.extend_from_slice(&snapshots[keep_count..]);
        } else {
            // If no keep-last, need to apply other policies
            let mut remaining = snapshots.clone();
            
            // Apply time-based retention policies
            if policy.keep_daily.is_some() || policy.keep_weekly.is_some() || 
               policy.keep_monthly.is_some() || policy.keep_yearly.is_some() {
                
                let (keep, delete) = self.apply_time_based_retention(&mut remaining, policy)?;
                to_keep.extend(keep);
                to_delete.extend(delete);
            } else {
                // No retention policy specified - keep everything
                to_keep = snapshots;
            }
        }

        // Remove duplicates and ensure we don't delete items marked to keep
        let keep_paths: std::collections::HashSet<_> = to_keep.iter()
            .map(|s| s.path.clone())
            .collect();
            
        to_delete.retain(|s| !keep_paths.contains(&s.path));
        
        Ok(to_delete)
    }

    /// Apply time-based retention policies (daily, weekly, monthly, yearly)
    fn apply_time_based_retention(&self, snapshots: &mut [SnapshotDirectory], policy: &RetentionPolicy) -> Result<(Vec<SnapshotDirectory>, Vec<SnapshotDirectory>)> {
        // This is a simplified implementation
        // In a full implementation, you would group snapshots by day/week/month/year
        // and keep the newest snapshot from each period according to the policy
        
        let mut to_keep = Vec::new();
        let mut to_delete = Vec::new();
        
        // For now, implement a simple approach - keep most recent snapshots
        // based on the sum of all retention periods
        let total_to_keep = policy.keep_daily.unwrap_or(0) 
            + policy.keep_weekly.unwrap_or(0) * 7
            + policy.keep_monthly.unwrap_or(0) * 30
            + policy.keep_yearly.unwrap_or(0) * 365;
            
        let keep_count = std::cmp::min(total_to_keep as usize, snapshots.len());
        
        to_keep.extend_from_slice(&snapshots[..keep_count]);
        to_delete.extend_from_slice(&snapshots[keep_count..]);
        
        Ok((to_keep, to_delete))
    }

    /// Delete a snapshot directory safely
    fn delete_snapshot(&self, snapshot: &SnapshotDirectory) -> Result<()> {
        let path = &snapshot.path;
        
        if !path.exists() {
            return Ok(()); // Already deleted
        }

        // Move to trash first, then delete (safer)
        let trash_dir = self.config.base_path.join(".trash");
        if !trash_dir.exists() {
            fs::create_dir_all(&trash_dir)?;
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let trash_path = trash_dir.join(format!("{}.{}", snapshot.name, timestamp));

        fs::rename(path, &trash_path)
            .with_context(|| format!("failed to move snapshot to trash: {:?}", path))?;

        // Actually delete from trash
        if trash_path.is_dir() {
            fs::remove_dir_all(&trash_path)
                .with_context(|| format!("failed to delete snapshot from trash: {:?}", trash_path))?;
        } else {
            fs::remove_file(&trash_path)
                .with_context(|| format!("failed to delete snapshot file from trash: {:?}", trash_path))?;
        }

        Ok(())
    }
}

/// Simple filesystem lock for coordinating prune operations
pub struct FilesystemLock {
    path: Option<PathBuf>,
    _is_dummy: bool,
}

impl FilesystemLock {
    pub fn acquire(lock_path: &Path, timeout: Duration) -> Result<Self> {
        let start = std::time::Instant::now();
        
        while start.elapsed() < timeout {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(lock_path) {
                Ok(_file) => {
                    return Ok(Self {
                        path: Some(lock_path.to_path_buf()),
                        _is_dummy: false,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(e) => {
                    return Err(anyhow!("failed to acquire lock: {}", e));
                }
            }
        }
        
        Err(anyhow!("failed to acquire lock within timeout"))
    }

    pub fn dummy() -> Self {
        Self {
            path: None,
            _is_dummy: true,
        }
    }
}

impl Drop for FilesystemLock {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = fs::remove_file(path);
        }
    }
}

/// Extract timestamp from filename using common patterns
fn extract_timestamp_from_string(name: &str) -> Option<SystemTime> {
    // Common backup naming patterns
    let patterns = vec![
        r"(\d{4})-(\d{2})-(\d{2})_(\d{2})-(\d{2})-(\d{2})", // YYYY-MM-DD_HH-MM-SS
        r"(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})",     // YYYYMMDD_HHMMSS
        r"(\d{4})-(\d{2})-(\d{2})",                         // YYYY-MM-DD
        r"(\d{10})",                                         // Unix timestamp
    ];

    for pattern in patterns {
        if let Ok(regex) = Regex::new(pattern) {
            if let Some(captures) = regex.captures(name) {
                // Try to parse as Unix timestamp first
                if captures.len() == 2 {
                    if let Ok(timestamp) = captures[1].parse::<u64>() {
                        return Some(UNIX_EPOCH + Duration::from_secs(timestamp));
                    }
                }
                
                // Try to parse as date components
                if captures.len() >= 4 {
                    if let (Ok(year), Ok(month), Ok(day)) = (
                        captures[1].parse::<i32>(),
                        captures[2].parse::<u32>(),
                        captures[3].parse::<u32>(),
                    ) {
                        let hour = captures.get(4).and_then(|m| m.as_str().parse::<u32>().ok()).unwrap_or(0);
                        let minute = captures.get(5).and_then(|m| m.as_str().parse::<u32>().ok()).unwrap_or(0);
                        let second = captures.get(6).and_then(|m| m.as_str().parse::<u32>().ok()).unwrap_or(0);
                        
                        if let Some(naive_date) = chrono::NaiveDate::from_ymd_opt(year, month, day)
                            .and_then(|d| d.and_hms_opt(hour, minute, second)) {
                            let datetime = DateTime::<Utc>::from_naive_utc_and_offset(naive_date, Utc);
                            return Some(UNIX_EPOCH + Duration::from_secs(datetime.timestamp() as u64));
                        }
                    }
                }
            }
        }
    }
    
    None
}

/// Calculate total size of a directory recursively
fn calculate_directory_size(path: &Path) -> Result<u64> {
    let mut total_size = 0;
    
    let entries = fs::read_dir(path)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        
        if metadata.is_dir() {
            total_size += calculate_directory_size(&path)?;
        } else {
            total_size += metadata.len();
        }
    }
    
    Ok(total_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_extract_timestamp_from_string() {
        // Test YYYY-MM-DD_HH-MM-SS format
        assert!(extract_timestamp_from_string("backup-2025-12-12_14-30-00").is_some());
        
        // Test YYYYMMDD_HHMMSS format
        assert!(extract_timestamp_from_string("backup_20251212_143000").is_some());
        
        // Test YYYY-MM-DD format
        assert!(extract_timestamp_from_string("backup-2025-12-12").is_some());
        
        // Test Unix timestamp
        assert!(extract_timestamp_from_string("backup_1702393800").is_some());
        
        // Test invalid format
        assert!(extract_timestamp_from_string("invalid_backup_name").is_none());
    }

    #[test]
    fn test_filesystem_config_default() {
        let config = FilesystemConfig::default();
        assert_eq!(config.base_path, PathBuf::from("./backups"));
        assert_eq!(config.naming_pattern, "*");
        assert_eq!(config.date_format, None);
        assert!(!config.use_symlinks);
    }

    #[test]
    fn test_snapshot_directory_creation() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let snapshot_path = temp_dir.path().join("test_snapshot");
        fs::create_dir(&snapshot_path)?;
        
        let snapshot = SnapshotDirectory::new(snapshot_path)?;
        assert_eq!(snapshot.name, "test_snapshot");
        assert!(snapshot.timestamp <= SystemTime::now());
        
        Ok(())
    }

    #[test]
    fn test_filesystem_lock() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let lock_path = temp_dir.path().join("test.lock");
        
        {
            let _lock1 = FilesystemLock::acquire(&lock_path, Duration::from_millis(100))?;
            
            // Second lock should fail
            let result = FilesystemLock::acquire(&lock_path, Duration::from_millis(100));
            assert!(result.is_err());
        }
        
        // After first lock is dropped, second should succeed
        let _lock2 = FilesystemLock::acquire(&lock_path, Duration::from_millis(100))?;
        
        Ok(())
    }

    #[test]
    fn test_retention_policy_simple() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = FilesystemConfig {
            base_path: temp_dir.path().to_path_buf(),
            ..FilesystemConfig::default()
        };

        let fs_snapshots = FilesystemSnapshots::new(config);
        
        // Create some test snapshot directories
        for i in 0..5 {
            let snapshot_dir = temp_dir.path().join(format!("snapshot_{}", i));
            fs::create_dir(&snapshot_dir)?;
        }

        let snapshots = fs_snapshots.list_snapshots()?;
        assert_eq!(snapshots.len(), 5);

        let policy = RetentionPolicy::from_string("keep-last:3")?;
        let to_delete = fs_snapshots.select_snapshots_for_deletion(&snapshots, &policy)?;
        assert_eq!(to_delete.len(), 2);

        Ok(())
    }
}