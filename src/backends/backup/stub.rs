use super::*;
use chrono::Utc;
use std::env;

/// Stub backend for testing that provides deterministic responses
/// without external dependencies
pub struct StubBackend {
    id: String,
}

impl StubBackend {
    pub fn new() -> Self {
        Self {
            id: "stub".to_string(),
        }
    }

    /// Check if we should use stub backend (for tests)
    pub fn should_use_stub() -> bool {
        env::var("BACKUPH_TEST_BACKEND").unwrap_or_default() == "stub"
    }

    fn create_fake_outcome(&self, command: Vec<String>, duration_ms: u64) -> BackendOutcome {
        BackendOutcome {
            exit_code: 0,
            stdout: "Stub backend output".to_string(),
            stderr: String::new(),
            command,
            env: HashMap::new(),
            cwd: Some("/tmp".to_string()),
            duration_ms,
            timed_out: false,
        }
    }
}

impl BackupBackend for StubBackend {
    fn id(&self) -> &str {
        &self.id
    }

    fn version(&self) -> Option<String> {
        Some("1.0.0-stub".to_string())
    }

    fn is_available(&self) -> bool {
        true
    }

    fn create(&self, args: &CreateArgs) -> Result<(BackendOutcome, Option<String>, Option<BackupStats>)> {
        // Check if error simulation is enabled for this verb
        if let Ok(force_error_verb) = std::env::var("BACKUPH_STUB_FORCE_ERROR") {
            if force_error_verb == "create" {
                return Err(anyhow!("Simulated error for create operation"));
            }
        }

        if args.dry_run {
            let outcome = self.create_fake_outcome(
                vec!["stub".to_string(), "backup".to_string(), "--dry-run".to_string()],
                100
            );
            return Ok((outcome, None, None));
        }

        let snapshot_id = format!("stub-{}", Utc::now().format("%Y%m%d-%H%M%S"));
        let stats = BackupStats {
            files_new: 42,
            files_changed: 7,
            bytes_added: 1024 * 1024, // 1MB
            bytes_processed: 5 * 1024 * 1024, // 5MB
        };

        let outcome = self.create_fake_outcome(
            vec!["stub".to_string(), "backup".to_string(), args.src.clone()],
            1000
        );

        Ok((outcome, Some(snapshot_id), Some(stats)))
    }

    fn list(&self, args: &ListArgs) -> Result<(BackendOutcome, Vec<SnapshotInfo>)> {
        let mut snapshots = vec![
            SnapshotInfo {
                id: "stub-20231201-100000".to_string(),
                time: "2023-12-01T10:00:00Z".to_string(),
                tags: vec!["daily".to_string()],
                message: Some("Stub backup 1".to_string()),
                host: Some("test-host".to_string()),
                paths: vec!["/home".to_string()],
                summary: SnapshotSummary {
                    files: 100,
                    bytes: 1024 * 1024, // 1MB
                },
            },
            SnapshotInfo {
                id: "stub-20231202-100000".to_string(),
                time: "2023-12-02T10:00:00Z".to_string(),
                tags: vec!["daily".to_string()],
                message: Some("Stub backup 2".to_string()),
                host: Some("test-host".to_string()),
                paths: vec!["/home".to_string()],
                summary: SnapshotSummary {
                    files: 105,
                    bytes: 1024 * 1024 + 512, // 1MB + 512B
                },
            },
            SnapshotInfo {
                id: "stub-20231203-100000".to_string(),
                time: "2023-12-03T10:00:00Z".to_string(),
                tags: vec!["daily".to_string()],
                message: Some("Stub backup 3".to_string()),
                host: Some("test-host".to_string()),
                paths: vec!["/home".to_string()],
                summary: SnapshotSummary {
                    files: 110,
                    bytes: 2 * 1024 * 1024, // 2MB
                },
            },
        ];

        // Apply filtering if specified
        if let Some(filter_tag) = &args.filter_tag {
            snapshots.retain(|s| s.tags.contains(filter_tag));
        }

        // Apply sorting (deterministic)
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

        let outcome = self.create_fake_outcome(
            vec!["stub".to_string(), "snapshots".to_string()],
            200
        );

        Ok((outcome, snapshots))
    }

    fn restore(&self, args: &RestoreArgs) -> Result<(BackendOutcome, Option<RestoreResult>)> {
        if args.dry_run {
            let outcome = self.create_fake_outcome(
                vec!["stub".to_string(), "restore".to_string(), "--dry-run".to_string()],
                100
            );
            return Ok((outcome, None));
        }

        let snapshot_id = if args.snapshot == "latest" {
            "stub-20231203-100000".to_string()
        } else {
            args.snapshot.clone()
        };

        let result = RestoreResult {
            target: args.target.clone(),
            snapshot: snapshot_id,
            files: 110,
            bytes: 2 * 1024 * 1024, // 2MB
        };

        let outcome = self.create_fake_outcome(
            vec!["stub".to_string(), "restore".to_string(), args.snapshot.clone()],
            2000
        );

        Ok((outcome, Some(result)))
    }

    fn verify(&self, args: &VerifyArgs) -> Result<(BackendOutcome, Option<VerificationResult>)> {
        let mode = args.mode.as_deref().unwrap_or("quick");
        let snapshot = args.snapshot.as_deref().unwrap_or("all");
        
        let checked_snapshots = match snapshot {
            "all" => 3,
            "latest" => 1,
            _ => 1,
        };

        // Simulate that verification passes
        let result = VerificationResult {
            verified: true,
            mode: mode.to_string(),
            checked_snapshots,
            issues: vec![], // No issues in stub
        };

        let outcome = self.create_fake_outcome(
            vec!["stub".to_string(), "check".to_string()],
            if mode == "full" { 5000 } else { 1000 }
        );

        Ok((outcome, Some(result)))
    }

    fn prune(&self, args: &PruneArgs) -> Result<(BackendOutcome, Option<PruneResult>)> {
        if args.dry_run {
            let outcome = self.create_fake_outcome(
                vec!["stub".to_string(), "prune".to_string(), "--dry-run".to_string()],
                100
            );
            return Ok((outcome, None));
        }

        // Parse the policy to determine what to keep/delete
        let _policy_map = parse_retention_policy(&args.policy)?;
        
        // For stub, always return deterministic results
        let mut candidates = vec![
            "stub-20231201-100000".to_string(),
            "stub-20231202-100000".to_string(),
            "stub-20231203-100000".to_string(),
        ];
        candidates.sort(); // Ensure deterministic order

        let mut deleted = vec!["stub-20231201-100000".to_string()];
        deleted.sort();

        let mut kept = vec![
            "stub-20231202-100000".to_string(),
            "stub-20231203-100000".to_string(),
        ];
        kept.sort();

        let result = PruneResult {
            policy: args.policy.clone(),
            candidates,
            deleted,
            kept,
            reclaimed_bytes: 1024 * 1024, // 1MB reclaimed
        };

        let outcome = self.create_fake_outcome(
            vec!["stub".to_string(), "prune".to_string()],
            3000
        );

        Ok((outcome, Some(result)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stub_backend_create() {
        let backend = StubBackend::new();
        let args = CreateArgs {
            backend: "stub".to_string(),
            src: "/test".to_string(),
            repo: "/backup".to_string(),
            tag: None,
            message: None,
            exclude: None,
            encrypt: None,
            key_ref: None,
            retention: None,
            timeout_ms: 60000,
            dry_run: false,
            emit_events: false,
        };

        let result = backend.create(&args);
        assert!(result.is_ok());
        
        let (outcome, snapshot_id, stats) = result.unwrap();
        assert_eq!(outcome.exit_code, 0);
        assert!(snapshot_id.is_some());
        assert!(stats.is_some());
        
        let snapshot_id = snapshot_id.unwrap();
        assert!(snapshot_id.starts_with("stub-"));
    }

    #[test]
    fn test_stub_backend_list() {
        let backend = StubBackend::new();
        let args = ListArgs {
            backend: "stub".to_string(),
            repo: "/backup".to_string(),
            limit: Some(2),
            sort: Some("time_desc".to_string()),
            filter_tag: None,
            timeout_ms: 60000,
            dry_run: false,
            emit_events: false,
        };

        let result = backend.list(&args);
        assert!(result.is_ok());
        
        let (outcome, snapshots) = result.unwrap();
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(snapshots.len(), 2); // Limited to 2
        
        // Should be sorted by time descending
        assert!(snapshots[0].time > snapshots[1].time);
    }

    #[test]
    fn test_stub_backend_list_with_filter() {
        let backend = StubBackend::new();
        let args = ListArgs {
            backend: "stub".to_string(),
            repo: "/backup".to_string(),
            limit: None,
            sort: None,
            filter_tag: Some("daily".to_string()),
            timeout_ms: 60000,
            dry_run: false,
            emit_events: false,
        };

        let result = backend.list(&args);
        assert!(result.is_ok());
        
        let (_, snapshots) = result.unwrap();
        assert_eq!(snapshots.len(), 3); // All have daily tag
        
        for snapshot in snapshots {
            assert!(snapshot.tags.contains(&"daily".to_string()));
        }
    }

    #[test]
    fn test_stub_backend_dry_run() {
        let backend = StubBackend::new();
        let args = CreateArgs {
            backend: "stub".to_string(),
            src: "/test".to_string(),
            repo: "/backup".to_string(),
            tag: None,
            message: None,
            exclude: None,
            encrypt: None,
            key_ref: None,
            retention: None,
            timeout_ms: 60000,
            dry_run: true,
            emit_events: false,
        };

        let result = backend.create(&args);
        assert!(result.is_ok());
        
        let (outcome, snapshot_id, stats) = result.unwrap();
        assert_eq!(outcome.exit_code, 0);
        assert!(snapshot_id.is_none()); // No snapshot in dry run
        assert!(stats.is_none()); // No stats in dry run
    }

    #[test]
    fn test_stub_backend_verify() {
        let backend = StubBackend::new();
        let args = VerifyArgs {
            backend: "stub".to_string(),
            repo: "/backup".to_string(),
            snapshot: Some("all".to_string()),
            mode: Some("full".to_string()),
            timeout_ms: 60000,
            dry_run: false,
            emit_events: false,
        };

        let result = backend.verify(&args);
        assert!(result.is_ok());
        
        let (outcome, verify_result) = result.unwrap();
        assert_eq!(outcome.exit_code, 0);
        
        let verify_result = verify_result.unwrap();
        assert!(verify_result.verified);
        assert_eq!(verify_result.mode, "full");
        assert_eq!(verify_result.checked_snapshots, 3);
        assert!(verify_result.issues.is_empty());
    }

    #[test]
    fn test_stub_backend_prune() {
        let backend = StubBackend::new();
        let args = PruneArgs {
            backend: "stub".to_string(),
            repo: "/backup".to_string(),
            policy: "keep_last=2".to_string(),
            timeout_ms: 60000,
            dry_run: false,
            emit_events: false,
        };

        let result = backend.prune(&args);
        assert!(result.is_ok());
        
        let (outcome, prune_result) = result.unwrap();
        assert_eq!(outcome.exit_code, 0);
        
        let prune_result = prune_result.unwrap();
        assert_eq!(prune_result.candidates.len(), 3);
        assert_eq!(prune_result.deleted.len(), 1);
        assert_eq!(prune_result.kept.len(), 2);
        assert!(prune_result.reclaimed_bytes > 0);
        
        // Check deterministic ordering
        assert!(prune_result.candidates.is_sorted());
        assert!(prune_result.deleted.is_sorted());
        assert!(prune_result.kept.is_sorted());
    }
}