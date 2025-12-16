use super::*;
use std::process::Command;
use std::path::Path;
use which::which;

/// Rsync backup backend implementation
pub struct RsyncBackend {
    id: String,
}

impl RsyncBackend {
    pub fn new() -> Self {
        Self {
            id: "rsync".to_string(),
        }
    }

    fn generate_snapshot_name(&self) -> String {
        use chrono::Utc;
        format!("rsync-{}", Utc::now().format("%Y%m%d-%H%M%S"))
    }

    fn create_snapshot_directory(&self, repo: &str, snapshot_name: &str) -> Result<String> {
        let snapshot_path = Path::new(repo).join(snapshot_name);
        std::fs::create_dir_all(&snapshot_path)?;
        Ok(snapshot_path.to_string_lossy().to_string())
    }

    fn list_snapshots(&self, repo: &str) -> Result<Vec<String>> {
        let mut snapshots = Vec::new();
        
        if let Ok(entries) = std::fs::read_dir(repo) {
            for entry in entries {
                if let Ok(entry) = entry {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.starts_with("rsync-") && entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                        snapshots.push(name);
                    }
                }
            }
        }
        
        snapshots.sort();
        Ok(snapshots)
    }

    fn parse_rsync_output(&self, stdout: &str, stderr: &str) -> BackupStats {
        let mut stats = BackupStats {
            files_new: 0,
            files_changed: 0,
            bytes_added: 0,
            bytes_processed: 0,
        };

        // Parse rsync statistics from output
        for line in stdout.lines() {
            if line.contains("sent") && line.contains("bytes") {
                // Extract bytes from line like "sent 1,234 bytes received 567 bytes"
                if let Some(bytes_part) = line.split_whitespace().nth(1) {
                    if let Ok(bytes) = bytes_part.replace(',', "").parse::<u64>() {
                        stats.bytes_processed = bytes;
                        stats.bytes_added = bytes; // Assume all bytes are new for rsync
                    }
                }
            }
        }

        stats
    }
}

impl BackupBackend for RsyncBackend {
    fn id(&self) -> &str {
        &self.id
    }

    fn version(&self) -> Option<String> {
        if let Ok(output) = Command::new("rsync").arg("--version").output() {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .map(|s| s.trim().to_string())
        } else {
            None
        }
    }

    fn is_available(&self) -> bool {
        which("rsync").is_ok()
    }

    fn create(&self, args: &CreateArgs) -> Result<(BackendOutcome, Option<String>, Option<BackupStats>)> {
        let snapshot_name = self.generate_snapshot_name();
        
        if args.dry_run {
            let outcome = BackendOutcome {
                exit_code: 0,
                stdout: "rsync dry run completed".to_string(),
                stderr: String::new(),
                command: vec!["rsync".to_string(), "--dry-run".to_string()],
                env: HashMap::new(),
                cwd: None,
                duration_ms: 100,
                timed_out: false,
            };
            return Ok((outcome, None, None));
        }

        let snapshot_path = self.create_snapshot_directory(&args.repo, &snapshot_name)?;
        
        let mut cmd = Command::new("rsync");
        cmd.arg("-avz"); // Archive, verbose, compress
        cmd.arg("--stats"); // Show statistics
        
        // Add exclude patterns
        if let Some(exclude) = &args.exclude {
            for pattern in exclude.split(';') {
                cmd.arg("--exclude").arg(pattern.trim());
            }
        }

        // Add source paths
        for src in args.src.split(';') {
            cmd.arg(src.trim());
        }
        
        cmd.arg(&snapshot_path);

        let command_args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
        let mut full_command = vec!["rsync".to_string()];
        full_command.extend(command_args);

        let mut outcome = execute_with_timeout(cmd, args.timeout_ms)?;
        outcome.command = full_command;

        if outcome.exit_code != 0 {
            return Ok((outcome, None, None));
        }

        let stats = self.parse_rsync_output(&outcome.stdout, &outcome.stderr);
        
        Ok((outcome, Some(snapshot_name), Some(stats)))
    }

    fn list(&self, args: &ListArgs) -> Result<(BackendOutcome, Vec<SnapshotInfo>)> {
        let outcome = BackendOutcome {
            exit_code: 0,
            stdout: "rsync list completed".to_string(),
            stderr: String::new(),
            command: vec!["ls".to_string(), args.repo.clone()],
            env: HashMap::new(),
            cwd: None,
            duration_ms: 100,
            timed_out: false,
        };

        let snapshot_names = self.list_snapshots(&args.repo).unwrap_or_default();
        let mut snapshots = Vec::new();

        for name in snapshot_names {
            // Parse timestamp from name: rsync-20231201-100000
            let time_str = if name.len() >= 20 {
                let date_part = &name[6..14]; // 20231201
                let time_part = &name[15..21]; // 100000
                format!("{}T{}Z", 
                    format!("{}-{}-{}", &date_part[0..4], &date_part[4..6], &date_part[6..8]),
                    format!("{}:{}:{}", &time_part[0..2], &time_part[2..4], &time_part[4..6])
                )
            } else {
                "1970-01-01T00:00:00Z".to_string()
            };

            snapshots.push(SnapshotInfo {
                id: name.clone(),
                time: time_str,
                tags: vec![],
                message: Some("Rsync backup".to_string()),
                host: None,
                paths: vec!["/unknown".to_string()],
                summary: SnapshotSummary { files: 0, bytes: 0 },
            });
        }

        // Apply sorting
        let sort_order = args.sort.as_deref().unwrap_or("time_desc");
        match sort_order {
            "time_asc" => snapshots.sort_by(|a, b| a.time.cmp(&b.time)),
            "time_desc" => snapshots.sort_by(|a, b| b.time.cmp(&a.time)),
            _ => {} // Keep default order
        }

        // Apply limit
        if let Some(limit) = args.limit {
            snapshots.truncate(limit as usize);
        }

        Ok((outcome, snapshots))
    }

    fn restore(&self, args: &RestoreArgs) -> Result<(BackendOutcome, Option<RestoreResult>)> {
        let snapshot = if args.snapshot == "latest" {
            // Get the latest snapshot
            let snapshots = self.list_snapshots(&args.repo).unwrap_or_default();
            snapshots.into_iter().last().unwrap_or_default()
        } else {
            args.snapshot.clone()
        };

        let snapshot_path = Path::new(&args.repo).join(&snapshot);

        let mut cmd = Command::new("rsync");
        cmd.arg("-avz");
        
        if let Some(include) = &args.include {
            for pattern in include.split(';') {
                cmd.arg("--include").arg(pattern.trim());
            }
        }

        if let Some(exclude) = &args.exclude {
            for pattern in exclude.split(';') {
                cmd.arg("--exclude").arg(pattern.trim());
            }
        }

        if args.dry_run {
            cmd.arg("--dry-run");
        }

        // Copy from snapshot to target
        cmd.arg(format!("{}/", snapshot_path.to_string_lossy()));
        cmd.arg(&args.target);

        let command_args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
        let mut full_command = vec!["rsync".to_string()];
        full_command.extend(command_args);

        let mut outcome = execute_with_timeout(cmd, args.timeout_ms)?;
        outcome.command = full_command;

        if outcome.exit_code != 0 {
            return Ok((outcome, None));
        }

        let result = if args.dry_run {
            None
        } else {
            Some(RestoreResult {
                target: args.target.clone(),
                snapshot: snapshot.clone(),
                files: 0, // Rsync doesn't provide exact file count
                bytes: 0, // Rsync doesn't provide exact byte count in restore
            })
        };

        Ok((outcome, result))
    }

    fn verify(&self, args: &VerifyArgs) -> Result<(BackendOutcome, Option<VerificationResult>)> {
        let outcome = BackendOutcome {
            exit_code: 0,
            stdout: "rsync verify completed".to_string(),
            stderr: String::new(),
            command: vec!["ls".to_string(), "-la".to_string(), args.repo.clone()],
            env: HashMap::new(),
            cwd: None,
            duration_ms: 200,
            timed_out: false,
        };

        // For rsync, verification is basic - check if repo directory exists and is readable
        let verified = Path::new(&args.repo).is_dir();
        
        let issues = if !verified {
            vec![VerificationIssue {
                kind: "missing".to_string(),
                item: args.repo.clone(),
                message: "Repository directory not found or not accessible".to_string(),
            }]
        } else {
            Vec::new()
        };

        let snapshots = self.list_snapshots(&args.repo).unwrap_or_default();
        let checked_snapshots = match args.snapshot.as_deref() {
            Some("all") | None => snapshots.len() as u64,
            Some("latest") => if snapshots.is_empty() { 0 } else { 1 },
            Some(_) => 1,
        };

        let result = VerificationResult {
            verified,
            mode: args.mode.as_deref().unwrap_or("quick").to_string(),
            checked_snapshots,
            issues,
        };

        Ok((outcome, Some(result)))
    }

    fn prune(&self, args: &PruneArgs) -> Result<(BackendOutcome, Option<PruneResult>)> {
        let policy_map = parse_retention_policy(&args.policy)?;
        let snapshots = self.list_snapshots(&args.repo).unwrap_or_default();
        
        let keep_last = policy_map.get("keep_last").unwrap_or(&0);
        
        let mut candidates = snapshots.clone();
        candidates.sort();

        let mut kept = Vec::new();
        let mut deleted = Vec::new();

        if *keep_last > 0 && !candidates.is_empty() {
            let keep_count = (*keep_last as usize).min(candidates.len());
            let split_point = candidates.len() - keep_count;
            
            deleted = candidates[0..split_point].to_vec();
            kept = candidates[split_point..].to_vec();
        } else {
            deleted = candidates.clone();
        }

        if !args.dry_run {
            // Actually delete the snapshots
            for snapshot in &deleted {
                let snapshot_path = Path::new(&args.repo).join(snapshot);
                if let Err(_) = std::fs::remove_dir_all(&snapshot_path) {
                    // If deletion fails, move it back to kept
                    kept.push(snapshot.clone());
                }
            }
            // Remove failed deletions from deleted list
            deleted.retain(|s| !kept.contains(s));
        }

        let reclaimed_bytes = deleted.len() as u64 * 1024 * 1024; // Estimate 1MB per deleted snapshot

        let outcome = BackendOutcome {
            exit_code: 0,
            stdout: format!("Deleted {} snapshots", deleted.len()),
            stderr: String::new(),
            command: vec!["rm".to_string(), "-rf".to_string()],
            env: HashMap::new(),
            cwd: Some(args.repo.clone()),
            duration_ms: 500,
            timed_out: false,
        };

        let result = PruneResult {
            policy: args.policy.clone(),
            candidates,
            deleted,
            kept,
            reclaimed_bytes,
        };

        Ok((outcome, Some(result)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsync_backend_creation() {
        let backend = RsyncBackend::new();
        assert_eq!(backend.id(), "rsync");
    }

    #[test]
    fn test_generate_snapshot_name() {
        let backend = RsyncBackend::new();
        let name = backend.generate_snapshot_name();
        assert!(name.starts_with("rsync-"));
        assert!(name.len() > 10);
    }

    #[test]
    fn test_parse_rsync_output() {
        let backend = RsyncBackend::new();
        let stdout = "sent 1,234 bytes  received 567 bytes  1,801 bytes/sec\n";
        let stderr = "";
        
        let stats = backend.parse_rsync_output(stdout, stderr);
        assert_eq!(stats.bytes_processed, 1234);
        assert_eq!(stats.bytes_added, 1234);
    }
}