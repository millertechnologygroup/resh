use super::*;
use std::process::Command;
use which::which;

/// Borg backup backend implementation
pub struct BorgBackend {
    id: String,
}

impl BorgBackend {
    pub fn new() -> Self {
        Self {
            id: "borg".to_string(),
        }
    }

    fn build_base_command(&self, args_repo: &str) -> Command {
        let mut cmd = Command::new("borg");
        // Borg repo is typically first arg or via BORG_REPO env
        cmd.env("BORG_REPO", args_repo);
        cmd
    }

    fn parse_create_output(&self, stdout: &str, stderr: &str) -> Option<(String, BackupStats)> {
        let mut snapshot_id = None;
        let mut stats = BackupStats {
            files_new: 0,
            files_changed: 0,
            bytes_added: 0,
            bytes_processed: 0,
        };

        // Look for archive name in stderr (borg outputs to stderr)
        for line in stderr.lines() {
            if line.contains("Archive name:") {
                if let Some(name_start) = line.find("Archive name: ") {
                    let name_part = &line[name_start + 14..];
                    snapshot_id = Some(name_part.trim().to_string());
                }
            }
        }

        // Parse statistics from output
        for line in stdout.lines() {
            if line.contains("Number of files:") {
                // Extract numbers from statistics
                if let Some(num_str) = line.split(':').nth(1) {
                    if let Ok(num) = num_str.trim().parse::<u64>() {
                        stats.files_new = num;
                    }
                }
            }
        }

        snapshot_id.map(|id| (id, stats))
    }

    fn parse_list_output(&self, stdout: &str) -> Vec<SnapshotInfo> {
        let mut snapshots = Vec::new();

        for line in stdout.lines() {
            // Parse borg list output format: "archive-name time"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                snapshots.push(SnapshotInfo {
                    id: parts[0].to_string(),
                    time: format!("{}T00:00:00Z", parts[1]), // Approximate RFC3339
                    tags: vec![], // Borg doesn't have explicit tags
                    message: None,
                    host: None,
                    paths: vec![],
                    summary: SnapshotSummary { files: 0, bytes: 0 },
                });
            }
        }

        // Ensure deterministic ordering
        snapshots.sort_by(|a, b| a.time.cmp(&b.time).then(a.id.cmp(&b.id)));
        snapshots
    }

    fn generate_archive_name(&self) -> String {
        use chrono::Utc;
        format!("resh-{}", Utc::now().format("%Y%m%d-%H%M%S"))
    }
}

impl BackupBackend for BorgBackend {
    fn id(&self) -> &str {
        &self.id
    }

    fn version(&self) -> Option<String> {
        if let Ok(output) = Command::new("borg").arg("--version").output() {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .map(|s| s.trim().to_string())
        } else {
            None
        }
    }

    fn is_available(&self) -> bool {
        which("borg").is_ok()
    }

    fn create(&self, args: &CreateArgs) -> Result<(BackendOutcome, Option<String>, Option<BackupStats>)> {
        let archive_name = self.generate_archive_name();
        let mut cmd = self.build_base_command(&args.repo);
        cmd.arg("create");
        cmd.arg(&archive_name);

        // Add source paths
        for src in args.src.split(';') {
            cmd.arg(src.trim());
        }

        // Add optional arguments
        if let Some(exclude) = &args.exclude {
            for pattern in exclude.split(';') {
                cmd.arg("--exclude").arg(pattern.trim());
            }
        }

        if args.dry_run {
            cmd.arg("--dry-run");
        }

        // Add compression
        cmd.arg("--compression").arg("lz4");

        // Set up environment for encryption
        let mut env = HashMap::new();
        env.insert("BORG_REPO".to_string(), args.repo.clone());
        
        if let Some(key_ref) = &args.key_ref {
            env.insert("BORG_PASSPHRASE".to_string(), key_ref.clone());
        }

        // Capture command details for outcome
        let command_args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
        let mut full_command = vec!["borg".to_string()];
        full_command.extend(command_args);

        for (k, v) in &env {
            cmd.env(k, v);
        }

        let mut outcome = execute_with_timeout(cmd, args.timeout_ms)?;
        outcome.command = full_command;
        outcome.env = env;

        if outcome.exit_code != 0 {
            return Ok((outcome, None, None));
        }

        let (snapshot_id, stats) = if args.dry_run {
            (None, None)
        } else {
            self.parse_create_output(&outcome.stdout, &outcome.stderr)
                .map(|(id, stats)| (Some(id), Some(stats)))
                .unwrap_or((Some(archive_name), None))
        };

        Ok((outcome, snapshot_id, stats))
    }

    fn list(&self, args: &ListArgs) -> Result<(BackendOutcome, Vec<SnapshotInfo>)> {
        let mut cmd = self.build_base_command(&args.repo);
        cmd.arg("list");

        let command_args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
        let mut full_command = vec!["borg".to_string()];
        full_command.extend(command_args);

        let mut outcome = execute_with_timeout(cmd, args.timeout_ms)?;
        outcome.command = full_command;

        if outcome.exit_code != 0 {
            return Ok((outcome, Vec::new()));
        }

        let mut snapshots = self.parse_list_output(&outcome.stdout);

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
        let mut cmd = self.build_base_command(&args.repo);
        cmd.arg("extract");
        cmd.arg(&args.snapshot);

        if let Some(include) = &args.include {
            for pattern in include.split(';') {
                cmd.arg(pattern.trim());
            }
        }

        if args.dry_run {
            cmd.arg("--dry-run");
        }

        // Borg extracts to current directory, so we need to change directory
        if let Ok(target_path) = std::path::Path::new(&args.target).canonicalize() {
            cmd.current_dir(&target_path);
        }

        let command_args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
        let mut full_command = vec!["borg".to_string()];
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
            Some(RestoreResult {
                target: args.target.clone(),
                snapshot: args.snapshot.clone(),
                files: 0, // Borg doesn't always provide this info
                bytes: 0, // Borg doesn't always provide this info
            })
        };

        Ok((outcome, result))
    }

    fn verify(&self, args: &VerifyArgs) -> Result<(BackendOutcome, Option<VerificationResult>)> {
        let mut cmd = self.build_base_command(&args.repo);
        cmd.arg("check");

        let mode = args.mode.as_deref().unwrap_or("quick");
        if mode == "full" {
            cmd.arg("--verify-data");
        }

        if let Some(snapshot) = &args.snapshot {
            if snapshot != "all" {
                cmd.arg("--archives-only").arg(snapshot);
            }
        }

        let command_args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
        let mut full_command = vec!["borg".to_string()];
        full_command.extend(command_args);

        let mut outcome = execute_with_timeout(cmd, args.timeout_ms)?;
        outcome.command = full_command;

        let verified = outcome.exit_code == 0;
        let issues = if verified {
            Vec::new()
        } else {
            vec![VerificationIssue {
                kind: "corrupt".to_string(),
                item: "repository".to_string(),
                message: outcome.stderr.clone(),
            }]
        };

        let result = VerificationResult {
            verified,
            mode: mode.to_string(),
            checked_snapshots: 1, // Borg checks the whole repo
            issues,
        };

        Ok((outcome, Some(result)))
    }

    fn prune(&self, args: &PruneArgs) -> Result<(BackendOutcome, Option<PruneResult>)> {
        let policy_map = parse_retention_policy(&args.policy)?;
        
        let mut cmd = self.build_base_command(&args.repo);
        cmd.arg("prune");

        // Apply retention policy
        for (key, value) in &policy_map {
            match key.as_str() {
                "keep_last" => { cmd.arg("--keep-last").arg(value.to_string()); },
                "keep_daily" => { cmd.arg("--keep-daily").arg(value.to_string()); },
                "keep_weekly" => { cmd.arg("--keep-weekly").arg(value.to_string()); },
                "keep_monthly" => { cmd.arg("--keep-monthly").arg(value.to_string()); },
                "keep_yearly" => { cmd.arg("--keep-yearly").arg(value.to_string()); },
                _ => {} // Ignore unknown policy keys
            }
        }

        if args.dry_run {
            cmd.arg("--dry-run");
        }

        let command_args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
        let mut full_command = vec!["borg".to_string()];
        full_command.extend(command_args);

        let mut outcome = execute_with_timeout(cmd, args.timeout_ms)?;
        outcome.command = full_command;

        if outcome.exit_code != 0 {
            return Ok((outcome, None));
        }

        // Parse the output to extract prune results
        let mut candidates = Vec::new();
        let mut deleted = Vec::new();
        let mut kept = Vec::new();
        let mut reclaimed_bytes = 0;

        // Borg output parsing for prune results
        for line in outcome.stdout.lines() {
            if line.contains("Keeping archive:") {
                if let Some(archive_name) = line.split(':').nth(1) {
                    kept.push(archive_name.trim().to_string());
                }
            } else if line.contains("Pruning archive:") {
                if let Some(archive_name) = line.split(':').nth(1) {
                    deleted.push(archive_name.trim().to_string());
                }
            }
        }

        // Combine for candidates list
        candidates.extend(kept.iter().cloned());
        candidates.extend(deleted.iter().cloned());

        // Ensure deterministic ordering
        candidates.sort();
        deleted.sort();
        kept.sort();

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
    fn test_borg_backend_creation() {
        let backend = BorgBackend::new();
        assert_eq!(backend.id(), "borg");
    }

    #[test]
    fn test_generate_archive_name() {
        let backend = BorgBackend::new();
        let name = backend.generate_archive_name();
        assert!(name.starts_with("resh-"));
        assert!(name.len() > 10); // Should include timestamp
    }

    #[test]
    fn test_parse_list_output() {
        let backend = BorgBackend::new();
        let output = "archive1 2023-12-01\narchive2 2023-12-02\n";
        
        let snapshots = backend.parse_list_output(output);
        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].id, "archive1");
        assert_eq!(snapshots[1].id, "archive2");
        
        // Should be sorted by time
        assert!(snapshots[0].time <= snapshots[1].time);
    }

    #[test]
    fn test_parse_create_output() {
        let backend = BorgBackend::new();
        let stdout = "Number of files: 100\n";
        let stderr = "Archive name: test-archive-20231201\n";
        
        let result = backend.parse_create_output(stdout, stderr);
        assert!(result.is_some());
        
        let (snapshot_id, stats) = result.unwrap();
        assert_eq!(snapshot_id, "test-archive-20231201");
        assert_eq!(stats.files_new, 100);
    }
}