use super::*;
use std::process::Command;
use std::path::Path;
use which::which;

/// Tar backup backend implementation
pub struct TarBackend {
    id: String,
}

impl TarBackend {
    pub fn new() -> Self {
        Self {
            id: "tar".to_string(),
        }
    }

    fn generate_archive_name(&self) -> String {
        use chrono::Utc;
        format!("tar-{}.tar.gz", Utc::now().format("%Y%m%d-%H%M%S"))
    }

    fn list_archives(&self, repo: &str) -> Result<Vec<String>> {
        let mut archives = Vec::new();
        
        if let Ok(entries) = std::fs::read_dir(repo) {
            for entry in entries {
                if let Ok(entry) = entry {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.starts_with("tar-") && (name.ends_with(".tar.gz") || name.ends_with(".tar")) {
                        archives.push(name);
                    }
                }
            }
        }
        
        archives.sort();
        Ok(archives)
    }

    fn parse_tar_output(&self, stdout: &str, stderr: &str) -> BackupStats {
        let mut stats = BackupStats {
            files_new: 0,
            files_changed: 0,
            bytes_added: 0,
            bytes_processed: 0,
        };

        // Count files from tar verbose output
        for line in stdout.lines() {
            if !line.trim().is_empty() && !line.starts_with("tar:") {
                stats.files_new += 1;
            }
        }

        stats
    }

    fn extract_timestamp_from_name(&self, archive_name: &str) -> String {
        // Extract timestamp from name: tar-20231201-100000.tar.gz
        if archive_name.len() >= 24 && archive_name.starts_with("tar-") {
            let timestamp_part = &archive_name[4..19]; // 20231201-100000
            let date_part = &timestamp_part[0..8]; // 20231201
            let time_part = &timestamp_part[9..15]; // 100000
            
            format!("{}T{}Z", 
                format!("{}-{}-{}", &date_part[0..4], &date_part[4..6], &date_part[6..8]),
                format!("{}:{}:{}", &time_part[0..2], &time_part[2..4], &time_part[4..6])
            )
        } else {
            "1970-01-01T00:00:00Z".to_string()
        }
    }
}

impl BackupBackend for TarBackend {
    fn id(&self) -> &str {
        &self.id
    }

    fn version(&self) -> Option<String> {
        if let Ok(output) = Command::new("tar").arg("--version").output() {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .map(|s| s.trim().to_string())
        } else {
            None
        }
    }

    fn is_available(&self) -> bool {
        which("tar").is_ok()
    }

    fn create(&self, args: &CreateArgs) -> Result<(BackendOutcome, Option<String>, Option<BackupStats>)> {
        let archive_name = self.generate_archive_name();
        let archive_path = Path::new(&args.repo).join(&archive_name);
        
        // Ensure repository directory exists
        if let Some(parent) = archive_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut cmd = Command::new("tar");
        cmd.arg("-czf"); // Create, gzip, file
        cmd.arg(&archive_path);
        cmd.arg("-v"); // Verbose for file counting

        // Add exclude patterns
        if let Some(exclude) = &args.exclude {
            for pattern in exclude.split(';') {
                cmd.arg("--exclude").arg(pattern.trim());
            }
        }

        if args.dry_run {
            cmd.arg("--dry-run");
        }

        // Add source paths
        for src in args.src.split(';') {
            cmd.arg(src.trim());
        }

        let command_args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
        let mut full_command = vec!["tar".to_string()];
        full_command.extend(command_args);

        let mut outcome = execute_with_timeout(cmd, args.timeout_ms)?;
        outcome.command = full_command;

        if outcome.exit_code != 0 {
            return Ok((outcome, None, None));
        }

        let (snapshot_id, stats) = if args.dry_run {
            (None, None)
        } else {
            let stats = self.parse_tar_output(&outcome.stdout, &outcome.stderr);
            (Some(archive_name), Some(stats))
        };

        Ok((outcome, snapshot_id, stats))
    }

    fn list(&self, args: &ListArgs) -> Result<(BackendOutcome, Vec<SnapshotInfo>)> {
        let outcome = BackendOutcome {
            exit_code: 0,
            stdout: "tar list completed".to_string(),
            stderr: String::new(),
            command: vec!["ls".to_string(), args.repo.clone()],
            env: HashMap::new(),
            cwd: None,
            duration_ms: 100,
            timed_out: false,
        };

        let archive_names = self.list_archives(&args.repo).unwrap_or_default();
        let mut snapshots = Vec::new();

        for name in archive_names {
            let time_str = self.extract_timestamp_from_name(&name);
            
            // Get archive size if possible
            let archive_path = Path::new(&args.repo).join(&name);
            let bytes = std::fs::metadata(&archive_path)
                .map(|m| m.len())
                .unwrap_or(0);

            snapshots.push(SnapshotInfo {
                id: name.clone(),
                time: time_str,
                tags: vec![],
                message: Some("Tar archive backup".to_string()),
                host: None,
                paths: vec!["/unknown".to_string()],
                summary: SnapshotSummary { files: 0, bytes },
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
        let archive = if args.snapshot == "latest" {
            // Get the latest archive
            let archives = self.list_archives(&args.repo).unwrap_or_default();
            archives.into_iter().last().unwrap_or_default()
        } else {
            args.snapshot.clone()
        };

        let archive_path = Path::new(&args.repo).join(&archive);

        let mut cmd = Command::new("tar");
        cmd.arg("-xzf"); // Extract, gunzip, file
        cmd.arg(&archive_path);
        cmd.arg("-C").arg(&args.target); // Change to target directory
        cmd.arg("-v"); // Verbose

        if let Some(include) = &args.include {
            for pattern in include.split(';') {
                cmd.arg(pattern.trim());
            }
        }

        if args.dry_run {
            cmd.arg("--dry-run");
        }

        // Ensure target directory exists
        std::fs::create_dir_all(&args.target)?;

        let command_args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
        let mut full_command = vec!["tar".to_string()];
        full_command.extend(command_args);

        let mut outcome = execute_with_timeout(cmd, args.timeout_ms)?;
        outcome.command = full_command;
        outcome.cwd = Some(args.target.clone());

        if outcome.exit_code != 0 {
            return Ok((outcome, None));
        }

        let result = if args.dry_run {
            None
        } else {
            // Count extracted files from verbose output
            let file_count = outcome.stdout.lines()
                .filter(|line| !line.trim().is_empty() && !line.starts_with("tar:"))
                .count() as u64;

            Some(RestoreResult {
                target: args.target.clone(),
                snapshot: archive.clone(),
                files: file_count,
                bytes: 0, // Tar doesn't provide exact extracted size
            })
        };

        Ok((outcome, result))
    }

    fn verify(&self, args: &VerifyArgs) -> Result<(BackendOutcome, Option<VerificationResult>)> {
        let archives = self.list_archives(&args.repo).unwrap_or_default();
        let mut verified = true;
        let mut issues = Vec::new();
        let mut checked_count = 0;

        let archives_to_check = match args.snapshot.as_deref() {
            Some("all") | None => archives,
            Some("latest") => {
                if let Some(latest) = archives.into_iter().last() {
                    vec![latest]
                } else {
                    Vec::new()
                }
            },
            Some(specific) => vec![specific.to_string()],
        };

        for archive in &archives_to_check {
            let archive_path = Path::new(&args.repo).join(archive);
            
            let mut cmd = Command::new("tar");
            cmd.arg("-tzf"); // Test archive integrity
            cmd.arg(&archive_path);

            if let Ok(output) = cmd.output() {
                checked_count += 1;
                if output.status.code().unwrap_or(-1) != 0 {
                    verified = false;
                    issues.push(VerificationIssue {
                        kind: "corrupt".to_string(),
                        item: archive.clone(),
                        message: "Archive integrity check failed".to_string(),
                    });
                }
            } else {
                verified = false;
                issues.push(VerificationIssue {
                    kind: "missing".to_string(),
                    item: archive.clone(),
                    message: "Cannot access archive file".to_string(),
                });
            }
        }

        let outcome = BackendOutcome {
            exit_code: if verified { 0 } else { 1 },
            stdout: format!("Checked {} archives", checked_count),
            stderr: if issues.is_empty() { String::new() } else { 
                format!("Found {} issues", issues.len())
            },
            command: vec!["tar".to_string(), "-tzf".to_string()],
            env: HashMap::new(),
            cwd: Some(args.repo.clone()),
            duration_ms: checked_count * 200, // Estimate 200ms per archive
            timed_out: false,
        };

        let result = VerificationResult {
            verified,
            mode: args.mode.as_deref().unwrap_or("quick").to_string(),
            checked_snapshots: checked_count,
            issues,
        };

        Ok((outcome, Some(result)))
    }

    fn prune(&self, args: &PruneArgs) -> Result<(BackendOutcome, Option<PruneResult>)> {
        let policy_map = parse_retention_policy(&args.policy)?;
        let archives = self.list_archives(&args.repo).unwrap_or_default();
        
        let keep_last = policy_map.get("keep_last").unwrap_or(&0);
        
        let mut candidates = archives.clone();
        candidates.sort();

        let mut kept = Vec::new();
        let mut deleted = Vec::new();
        let mut reclaimed_bytes = 0;

        if *keep_last > 0 && !candidates.is_empty() {
            let keep_count = (*keep_last as usize).min(candidates.len());
            let split_point = candidates.len() - keep_count;
            
            deleted = candidates[0..split_point].to_vec();
            kept = candidates[split_point..].to_vec();
        } else {
            deleted = candidates.clone();
        }

        if !args.dry_run {
            // Actually delete the archives and calculate reclaimed bytes
            for archive in &deleted {
                let archive_path = Path::new(&args.repo).join(archive);
                if let Ok(metadata) = std::fs::metadata(&archive_path) {
                    reclaimed_bytes += metadata.len();
                    if let Err(_) = std::fs::remove_file(&archive_path) {
                        // If deletion fails, move it back to kept
                        kept.push(archive.clone());
                    }
                }
            }
            // Remove failed deletions from deleted list
            deleted.retain(|s| !kept.contains(s));
        } else {
            // For dry run, estimate reclaimed bytes
            for archive in &deleted {
                let archive_path = Path::new(&args.repo).join(archive);
                if let Ok(metadata) = std::fs::metadata(&archive_path) {
                    reclaimed_bytes += metadata.len();
                }
            }
        }

        let outcome = BackendOutcome {
            exit_code: 0,
            stdout: format!("Would delete {} archives, reclaim {} bytes", deleted.len(), reclaimed_bytes),
            stderr: String::new(),
            command: vec!["rm".to_string()],
            env: HashMap::new(),
            cwd: Some(args.repo.clone()),
            duration_ms: 300,
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
    fn test_tar_backend_creation() {
        let backend = TarBackend::new();
        assert_eq!(backend.id(), "tar");
    }

    #[test]
    fn test_generate_archive_name() {
        let backend = TarBackend::new();
        let name = backend.generate_archive_name();
        assert!(name.starts_with("tar-"));
        assert!(name.ends_with(".tar.gz"));
        assert!(name.len() > 15);
    }

    #[test]
    fn test_extract_timestamp_from_name() {
        let backend = TarBackend::new();
        let timestamp = backend.extract_timestamp_from_name("tar-20231201-100000.tar.gz");
        assert_eq!(timestamp, "2023-12-01T10:00:00Z");
    }

    #[test]
    fn test_extract_timestamp_from_invalid_name() {
        let backend = TarBackend::new();
        let timestamp = backend.extract_timestamp_from_name("invalid.tar.gz");
        assert_eq!(timestamp, "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_parse_tar_output() {
        let backend = TarBackend::new();
        let stdout = "file1.txt\nfile2.txt\ndir/file3.txt\n";
        let stderr = "";
        
        let stats = backend.parse_tar_output(stdout, stderr);
        assert_eq!(stats.files_new, 3);
    }
}