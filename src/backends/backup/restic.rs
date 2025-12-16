use super::*;
use std::process::Command;
use which::which;

/// Restic backup backend implementation
pub struct ResticBackend {
    id: String,
}

impl ResticBackend {
    pub fn new() -> Self {
        Self {
            id: "restic".to_string(),
        }
    }

    fn build_base_command(&self, args_repo: &str) -> Command {
        let mut cmd = Command::new("restic");
        cmd.arg("--repo").arg(args_repo);
        cmd.arg("--json"); // Enable JSON output where supported
        cmd
    }

    fn parse_create_output(&self, stdout: &str) -> Option<(String, BackupStats)> {
        // Try to parse JSON output first
        if let Ok(json) = serde_json::from_str::<Value>(stdout) {
            if let (Some(snapshot_id), Some(summary)) = (
                json["snapshot_id"].as_str(),
                json["summary"].as_object()
            ) {
                let stats = BackupStats {
                    files_new: summary.get("files_new")
                        .and_then(|v| v.as_u64()).unwrap_or(0),
                    files_changed: summary.get("files_changed")
                        .and_then(|v| v.as_u64()).unwrap_or(0),
                    bytes_added: summary.get("data_added")
                        .and_then(|v| v.as_u64()).unwrap_or(0),
                    bytes_processed: summary.get("total_bytes_processed")
                        .and_then(|v| v.as_u64()).unwrap_or(0),
                };
                return Some((snapshot_id.to_string(), stats));
            }
        }

        // Fallback: parse text output
        let mut snapshot_id = None;
        let mut stats = BackupStats {
            files_new: 0,
            files_changed: 0,
            bytes_added: 0,
            bytes_processed: 0,
        };

        for line in stdout.lines() {
            if line.contains("snapshot") && line.contains("saved") {
                // Extract snapshot ID from line like "snapshot 1a2b3c4d saved"
                if let Some(id_start) = line.find("snapshot ") {
                    let id_part = &line[id_start + 9..];
                    if let Some(id_end) = id_part.find(' ') {
                        snapshot_id = Some(id_part[..id_end].to_string());
                    }
                }
            }
        }

        snapshot_id.map(|id| (id, stats))
    }

    fn parse_list_output(&self, stdout: &str) -> Vec<SnapshotInfo> {
        let mut snapshots = Vec::new();

        // Try JSON format first
        if let Ok(json_snapshots) = serde_json::from_str::<Vec<Value>>(stdout) {
            for snapshot in json_snapshots {
                if let Some(info) = self.parse_snapshot_json(&snapshot) {
                    snapshots.push(info);
                }
            }
        } else {
            // Fallback to text parsing
            snapshots = self.parse_list_text(stdout);
        }

        // Ensure deterministic ordering
        snapshots.sort_by(|a, b| a.time.cmp(&b.time).then(a.id.cmp(&b.id)));
        snapshots
    }

    fn parse_snapshot_json(&self, json: &Value) -> Option<SnapshotInfo> {
        let id = json["short_id"].as_str().or_else(|| json["id"].as_str())?;
        let time = json["time"].as_str()?;
        
        let tags = json["tags"].as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
            .unwrap_or_default();
        
        let paths = json["paths"].as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
            .unwrap_or_default();

        Some(SnapshotInfo {
            id: id.to_string(),
            time: time.to_string(),
            tags,
            message: json["summary"].as_str().map(|s| s.to_string()),
            host: json["hostname"].as_str().map(|s| s.to_string()),
            paths,
            summary: SnapshotSummary {
                files: json["summary"].as_object()
                    .and_then(|s| s["total_file_count"].as_u64()).unwrap_or(0),
                bytes: json["summary"].as_object()
                    .and_then(|s| s["total_size"].as_u64()).unwrap_or(0),
            },
        })
    }

    fn parse_list_text(&self, stdout: &str) -> Vec<SnapshotInfo> {
        let mut snapshots = Vec::new();
        
        for line in stdout.lines() {
            // Parse text format: "ID       Time                 Host        Tags        Paths"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 && !line.starts_with("ID") {
                snapshots.push(SnapshotInfo {
                    id: parts[0].to_string(),
                    time: format!("{}T{}Z", parts[1], parts[2]), // Approximate RFC3339
                    tags: if parts.len() > 4 { vec![parts[4].to_string()] } else { vec![] },
                    message: None,
                    host: if parts.len() > 3 { Some(parts[3].to_string()) } else { None },
                    paths: vec![],
                    summary: SnapshotSummary { files: 0, bytes: 0 },
                });
            }
        }
        
        snapshots
    }
}

impl BackupBackend for ResticBackend {
    fn id(&self) -> &str {
        &self.id
    }

    fn version(&self) -> Option<String> {
        if let Ok(output) = Command::new("restic").arg("version").output() {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .map(|s| s.trim().to_string())
        } else {
            None
        }
    }

    fn is_available(&self) -> bool {
        which("restic").is_ok()
    }

    fn create(&self, args: &CreateArgs) -> Result<(BackendOutcome, Option<String>, Option<BackupStats>)> {
        let mut cmd = self.build_base_command(&args.repo);
        cmd.arg("backup");

        // Add source paths
        for src in args.src.split(';') {
            cmd.arg(src.trim());
        }

        // Add optional arguments
        if let Some(tag) = &args.tag {
            cmd.arg("--tag").arg(tag);
        }
        
        if let Some(exclude) = &args.exclude {
            for pattern in exclude.split(';') {
                cmd.arg("--exclude").arg(pattern.trim());
            }
        }

        if args.dry_run {
            cmd.arg("--dry-run");
        }

        // Set up environment for encryption
        let mut env = HashMap::new();
        if let Some(key_ref) = &args.key_ref {
            env.insert("RESTIC_PASSWORD".to_string(), key_ref.clone());
        }

        // Capture command details for outcome
        let command_args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
        let mut full_command = vec!["restic".to_string()];
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
            self.parse_create_output(&outcome.stdout)
                .map(|(id, stats)| (Some(id), Some(stats)))
                .unwrap_or((None, None))
        };

        Ok((outcome, snapshot_id, stats))
    }

    fn list(&self, args: &ListArgs) -> Result<(BackendOutcome, Vec<SnapshotInfo>)> {
        let mut cmd = self.build_base_command(&args.repo);
        cmd.arg("snapshots");

        if let Some(tag) = &args.filter_tag {
            cmd.arg("--tag").arg(tag);
        }

        let command_args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
        let mut full_command = vec!["restic".to_string()];
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
        cmd.arg("restore");
        cmd.arg(&args.snapshot);
        cmd.arg("--target").arg(&args.target);

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

        let command_args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
        let mut full_command = vec!["restic".to_string()];
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
                snapshot: args.snapshot.clone(),
                files: 0, // Restic doesn't always provide this
                bytes: 0, // Restic doesn't always provide this
            })
        };

        Ok((outcome, result))
    }

    fn verify(&self, args: &VerifyArgs) -> Result<(BackendOutcome, Option<VerificationResult>)> {
        let mut cmd = self.build_base_command(&args.repo);
        cmd.arg("check");

        let mode = args.mode.as_deref().unwrap_or("quick");
        if mode == "full" {
            cmd.arg("--read-data");
        }

        let command_args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
        let mut full_command = vec!["restic".to_string()];
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
            checked_snapshots: 1, // Restic checks the whole repo
            issues,
        };

        Ok((outcome, Some(result)))
    }

    fn prune(&self, args: &PruneArgs) -> Result<(BackendOutcome, Option<PruneResult>)> {
        let policy_map = parse_retention_policy(&args.policy)?;
        
        let mut cmd = self.build_base_command(&args.repo);
        cmd.arg("forget");

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

        if !args.dry_run {
            cmd.arg("--prune");
        }

        if args.dry_run {
            cmd.arg("--dry-run");
        }

        let command_args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
        let mut full_command = vec!["restic".to_string()];
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

        // Restic output parsing is complex, so for now provide minimal info
        for line in outcome.stdout.lines() {
            if line.contains("remove") && line.contains("snapshot") {
                if let Some(id) = line.split_whitespace().nth(2) {
                    deleted.push(id.to_string());
                }
            }
        }

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
    fn test_restic_backend_creation() {
        let backend = ResticBackend::new();
        assert_eq!(backend.id(), "restic");
    }

    #[test]
    fn test_parse_create_output() {
        let backend = ResticBackend::new();
        let json_output = r#"{"snapshot_id":"abc123","summary":{"files_new":10,"files_changed":5,"data_added":1024,"total_bytes_processed":2048}}"#;
        
        let result = backend.parse_create_output(json_output);
        assert!(result.is_some());
        
        let (snapshot_id, stats) = result.unwrap();
        assert_eq!(snapshot_id, "abc123");
        assert_eq!(stats.files_new, 10);
        assert_eq!(stats.files_changed, 5);
        assert_eq!(stats.bytes_added, 1024);
        assert_eq!(stats.bytes_processed, 2048);
    }

    #[test]
    fn test_parse_snapshot_json() {
        let backend = ResticBackend::new();
        let json = serde_json::json!({
            "short_id": "abc123",
            "time": "2023-12-01T10:00:00Z",
            "tags": ["daily", "test"],
            "hostname": "test-host",
            "paths": ["/home"],
            "summary": {
                "total_file_count": 100,
                "total_size": 1048576
            }
        });
        
        let result = backend.parse_snapshot_json(&json);
        assert!(result.is_some());
        
        let snapshot = result.unwrap();
        assert_eq!(snapshot.id, "abc123");
        assert_eq!(snapshot.time, "2023-12-01T10:00:00Z");
        assert_eq!(snapshot.tags, vec!["daily", "test"]);
        assert_eq!(snapshot.host, Some("test-host".to_string()));
        assert_eq!(snapshot.paths, vec!["/home"]);
        assert_eq!(snapshot.summary.files, 100);
        assert_eq!(snapshot.summary.bytes, 1048576);
    }
}