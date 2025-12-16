use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::registry::RegistryClient;
use super::store::PluginStore;
use super::types::{
    action_types, error_codes, error_code_to_numeric, Action, ArtifactCandidate, Envelope,
    Mode, PlanDecision, PluginOpArgs, PluginResult, StructuredError, VerifyMode,
    ArtifactInfo, PathInfo, TargetInfo, ArgsInfo,
};

/// Shared execution engine for both install and update operations
pub struct ExecutionEngine {
    registry_client: RegistryClient,
    store: PluginStore,
}

impl ExecutionEngine {
    /// Create new execution engine
    pub fn new(timeout_ms: u64) -> Result<Self> {
        let registry_client = RegistryClient::new(timeout_ms)?;
        let store = PluginStore::new()?;

        Ok(Self {
            registry_client,
            store,
        })
    }

    /// Run plugin operation according to specification
    pub fn run_plugin_op(&mut self, args: PluginOpArgs) -> Envelope {
        let start_time = Instant::now();
        let started_at = Utc::now().to_rfc3339();
        
        let op = match args.mode {
            Mode::Install => "plugin.install".to_string(),
            Mode::Update => "plugin.update".to_string(),
            Mode::Remove => "plugin.remove".to_string(),
            Mode::Enable => "plugin.enable".to_string(),
            Mode::Disable => "plugin.disable".to_string(),
        };

        let target = format!("plugin://{}", args.plugin_id);

        // Execute the operation
        let execution_result = self.execute_operation(&args);
        
        let finished_at = Utc::now().to_rfc3339();

        // Build envelope based on result
        match execution_result {
            Ok((changed, result, actions, installed_metadata)) => {
                let (target_info, args_info) = self.build_envelope_metadata(&args, installed_metadata.as_ref());
                
                Envelope {
                    op,
                    ok: true,
                    code: 0,
                    target: target_info,
                    args: args_info,
                    actions,
                    result,
                    warnings: vec![], // TODO: collect warnings during execution
                    error: None,
                    ts: Utc::now().to_rfc3339(),
                }
            }
            Err(err) => {
                let (error_code, numeric_code, actions) = self.extract_error_info(&err);
                let (target_info, args_info) = self.build_envelope_metadata(&args, None);
                
                Envelope {
                    op,
                    ok: false,
                    code: numeric_code,
                    target: target_info,
                    args: args_info,
                    actions,
                    result: PluginResult {
                        removed: Some(false),
                        purged: Some(false),
                        installed: Some(false),
                        previous_version: None,
                        version: None,
                        enabled: None,
                        was_enabled: None,
                    },
                    warnings: vec![],
                    error: Some(StructuredError {
                        kind: error_code,
                        message: err.to_string(),
                        details: serde_json::json!({}),
                    }),
                    ts: Utc::now().to_rfc3339(),
                }
            }
        }
    }

    /// Execute the plugin operation with deterministic action ordering
    fn execute_operation(&mut self, args: &PluginOpArgs) -> Result<(bool, PluginResult, Vec<Action>, Option<super::types::InstalledPlugin>)> {
        let mut actions = Vec::new();

        match args.mode {
            Mode::Install | Mode::Update => {
                // Step 1: Resolve candidate
                let candidate = self.resolve_candidate(args, &mut actions)?;

                // Step 2: Check installed status
                let installed_metadata = self.check_installed(args, &mut actions)?;

                // Step 3: Compare versions and make plan decision
                let plan_decision = self.make_plan_decision(args, installed_metadata.as_ref(), &candidate, &mut actions)?;

                // Step 4: Execute plan
                match plan_decision {
                    PlanDecision::Install { version, artifact } => {
                        todo!("Install functionality not yet implemented")
                    }
                    PlanDecision::Update { from_version, to_version, artifact } => {
                        todo!("Update functionality not yet implemented")
                    }
                    PlanDecision::NoOp { reason } => {
                        self.add_action(&mut actions, "a1", action_types::INSTALL, "noop", true, Some(serde_json::json!({"reason": reason})));
                        let result = PluginResult {
                            removed: None,
                            purged: None,
                            installed: Some(true),
                            previous_version: None,
                            version: installed_metadata.as_ref().map(|m| m.version.clone()),
                            enabled: None,
                            was_enabled: None,
                        };
                        Ok((false, result, actions, installed_metadata))
                    }
                    PlanDecision::Error { code, message } => {
                        Err(self.create_error(&code, &message))
                    }
                }
            }
            Mode::Remove => {
                let (changed, result, installed_metadata) = self.execute_remove(args, &mut actions)?;
                Ok((changed, result, actions, installed_metadata))
            }
            Mode::Enable => {
                let (changed, result, installed_metadata) = self.execute_enable(args, &mut actions)?;
                Ok((changed, result, actions, installed_metadata))
            }
            Mode::Disable => {
                // Disable mode should not use this path - it uses the state manager directly
                Err(anyhow!("Disable should use PluginStateManager::set_enabled_state instead"))
            }
        }
    }

    /// Resolve plugin candidate from source
    fn resolve_candidate(&mut self, args: &PluginOpArgs, actions: &mut Vec<Action>) -> Result<ArtifactCandidate> {
        let result = self.registry_client.resolve_plugin(
            &args.plugin_id,
            &args.source,
            &args.requested_version,
            &args.verify,
        );

        match &result {
            Ok(candidate) => {
                let version = &candidate.manifest.version;
                self.add_action(
                    actions,
                    &format!("resolve-{}", actions.len()),
                    action_types::RESOLVE,
                    &format!("Resolved plugin version: {}", version),
                    true,
                    Some(serde_json::json!({ "version": version })),
                );
            }
            Err(err) => {
                self.add_action(
                    actions,
                    &format!("resolve-{}", actions.len()),
                    action_types::RESOLVE,
                    &format!("Failed to resolve plugin: {}", err),
                    false,
                    None,
                );
            }
        }

        result
    }

    /// Check if plugin is installed
    fn check_installed(&mut self, args: &PluginOpArgs, actions: &mut Vec<Action>) -> Result<Option<super::types::InstalledPlugin>> {
        let result = self.store.get_installed_metadata(&args.plugin_id);

        match &result {
            Ok(Some(metadata)) => {
                self.add_action(
                    actions,
                    &format!("check-{}", actions.len()),
                    action_types::CHECK_INSTALLED,
                    &format!("Plugin installed: version {}", metadata.version),
                    true,
                    Some(serde_json::json!({ "version": metadata.version })),
                );
            }
            Ok(None) => {
                self.add_action(
                    actions,
                    &format!("check-{}", actions.len()),
                    action_types::CHECK_INSTALLED,
                    "Plugin not installed",
                    true,
                    None,
                );
            }
            Err(err) => {
                self.add_action(
                    actions,
                    &format!("check-{}", actions.len()),
                    action_types::CHECK_INSTALLED,
                    &format!("Failed to check installation status: {}", err),
                    false,
                    None,
                );
            }
        }

        result.map_err(|e| self.create_error(error_codes::PLUGIN_IO_ERROR, &e.to_string()))
    }

    /// Make plan decision based on mode, installed version, and candidate
    fn make_plan_decision(
        &mut self,
        args: &PluginOpArgs,
        installed: Option<&super::types::InstalledPlugin>,
        candidate: &ArtifactCandidate,
        _actions: &mut Vec<Action>,
    ) -> Result<PlanDecision> {
        match args.mode {
            Mode::Install => self.plan_install(args, installed, candidate),
            Mode::Update => self.plan_update(args, installed, candidate),
            Mode::Remove => {
                // Remove doesn't need candidate resolution
                unreachable!("Remove mode should be handled separately")
            }
            Mode::Enable | Mode::Disable => {
                // Enable/Disable modes should not use this path
                unreachable!("Enable/Disable modes should be handled separately")
            }
        }
    }

    /// Plan install operation
    fn plan_install(
        &mut self,
        args: &PluginOpArgs,
        installed: Option<&super::types::InstalledPlugin>,
        candidate: &ArtifactCandidate,
    ) -> Result<PlanDecision> {
        if let Some(installed_meta) = installed {
            let comparison = self.registry_client.compare_versions(&installed_meta.version, &candidate.manifest.version);
            
            match comparison {
                std::cmp::Ordering::Equal => {
                    if args.force {
                        Ok(PlanDecision::Install {
                            version: candidate.manifest.version.clone(),
                            artifact: candidate.clone(),
                        })
                    } else {
                        Ok(PlanDecision::NoOp {
                            reason: format!("Plugin already installed with version {}", installed_meta.version),
                        })
                    }
                }
                std::cmp::Ordering::Greater => {
                    // Installed version is newer - this is a downgrade
                    if args.allow_downgrade || args.force {
                        Ok(PlanDecision::Install {
                            version: candidate.manifest.version.clone(),
                            artifact: candidate.clone(),
                        })
                    } else {
                        Ok(PlanDecision::Error {
                            code: error_codes::PLUGIN_ALREADY_INSTALLED.to_string(),
                            message: format!(
                                "Plugin already installed with newer version {} (requested: {})",
                                installed_meta.version,
                                candidate.manifest.version
                            ),
                        })
                    }
                }
                std::cmp::Ordering::Less => {
                    // Candidate is newer - this is an upgrade
                    Ok(PlanDecision::Install {
                        version: candidate.manifest.version.clone(),
                        artifact: candidate.clone(),
                    })
                }
            }
        } else {
            // Not installed - proceed with install
            Ok(PlanDecision::Install {
                version: candidate.manifest.version.clone(),
                artifact: candidate.clone(),
            })
        }
    }

    /// Plan update operation
    fn plan_update(
        &mut self,
        args: &PluginOpArgs,
        installed: Option<&super::types::InstalledPlugin>,
        candidate: &ArtifactCandidate,
    ) -> Result<PlanDecision> {
        let installed_meta = installed.ok_or_else(|| {
            self.create_error(error_codes::PLUGIN_NOT_INSTALLED, "Plugin not installed")
        })?;

        let comparison = self.registry_client.compare_versions(&installed_meta.version, &candidate.manifest.version);

        match comparison {
            std::cmp::Ordering::Less => {
                // Candidate is newer - this is an update
                Ok(PlanDecision::Update {
                    from_version: installed_meta.version.clone(),
                    to_version: candidate.manifest.version.clone(),
                    artifact: candidate.clone(),
                })
            }
            std::cmp::Ordering::Equal => {
                // Same version
                if args.strict {
                    Ok(PlanDecision::Error {
                        code: error_codes::PLUGIN_NO_UPDATE_AVAILABLE.to_string(),
                        message: format!("No update available (current version: {})", installed_meta.version),
                    })
                } else {
                    Ok(PlanDecision::NoOp {
                        reason: format!("Plugin up to date (version: {})", installed_meta.version),
                    })
                }
            }
            std::cmp::Ordering::Greater => {
                // Installed version is newer
                if args.strict {
                    Ok(PlanDecision::Error {
                        code: error_codes::PLUGIN_NO_UPDATE_AVAILABLE.to_string(),
                        message: format!(
                            "No update available - installed version {} is newer than available {}",
                            installed_meta.version,
                            candidate.manifest.version
                        ),
                    })
                } else {
                    Ok(PlanDecision::NoOp {
                        reason: format!(
                            "Plugin version {} is newer than available {}",
                            installed_meta.version,
                            candidate.manifest.version
                        ),
                    })
                }
            }
        }
    }

    /// Execute install operation
    fn execute_install(
        &mut self,
        args: &PluginOpArgs,
        version: &str,
        artifact: &ArtifactCandidate,
        actions: &mut Vec<Action>,
    ) -> Result<PluginResult> {
        // Download artifact
        let artifact_data = self.download_artifact(artifact, actions)?;

        // Verify artifact
        if matches!(args.verify, VerifyMode::Sha256) {
            self.verify_artifact(&artifact_data, artifact, actions)?;
        }

        // Extract artifact
        let extracted_path = self.extract_artifact(&artifact_data, args, artifact, actions)?;

        // Install plugin
        let installed_metadata = self.store.install_plugin(
            &args.plugin_id,
            version,
            artifact,
            &extracted_path,
            &self.source_to_string(&args.source),
        ).map_err(|e| self.create_error(error_codes::PLUGIN_INSTALL_FAILED, &e.to_string()))?;

        self.add_action(actions, &format!("install-{}", actions.len()), action_types::INSTALL, "Plugin installed successfully", true, None);

        // Activate plugin
        self.store.activate_version(&args.plugin_id, version)
            .map_err(|e| self.create_error(error_codes::PLUGIN_ACTIVATE_FAILED, &e.to_string()))?;

        self.add_action(actions, &format!("activate-{}", actions.len()), action_types::ACTIVATE, "Plugin activated successfully", true, None);

        // Cleanup
        let _ = self.store.cleanup_staging(&args.plugin_id);
        self.add_action(actions, &format!("cleanup-{}", actions.len()), action_types::CLEANUP, "Staging cleanup completed", true, None);

        // TODO: Implement this properly when updating install/update methods
        Ok(PluginResult {
            removed: None,
            purged: None,
            installed: Some(true),
            previous_version: None,
            version: Some("stub".to_string()),
            enabled: None,
            was_enabled: None,
        })
    }

    /// Execute update operation
    fn execute_update(
        &mut self,
        args: &PluginOpArgs,
        from_version: &str,
        to_version: &str,
        artifact: &ArtifactCandidate,
        actions: &mut Vec<Action>,
    ) -> Result<PluginResult> {
        // Execute install-like process for the new version
        let result = self.execute_install(args, to_version, artifact, actions);

        match result {
            Ok(success_result) => Ok(PluginResult {
                previous_version: Some(from_version.to_string()),
                ..success_result
            }),
            Err(install_error) => {
                // Attempt rollback
                if let Err(rollback_err) = self.store.rollback_to_previous(&args.plugin_id, to_version) {
                    self.add_action(
                        actions,
                        &format!("rollback-{}", actions.len()),
                        action_types::ROLLBACK,
                        &format!("Rollback failed: {}", rollback_err),
                        false,
                        None,
                    );
                } else {
                    self.add_action(
                        actions,
                        &format!("rollback-{}", actions.len()),
                        action_types::ROLLBACK,
                        &format!("Rolled back to version {}", from_version),
                        true,
                        None,
                    );
                }

                Err(install_error)
            }
        }
    }

    /// Download artifact from URL or read from file
    fn download_artifact(&mut self, artifact: &ArtifactCandidate, actions: &mut Vec<Action>) -> Result<Vec<u8>> {
        if let Some(url) = &artifact.url {
            let result = self.registry_client.download_artifact(url);
            match &result {
                Ok(data) => {
                    self.add_action(
                        actions,
                        &format!("download-{}", actions.len()),
                        action_types::DOWNLOAD,
                        &format!("Downloaded artifact ({} bytes)", data.len()),
                        true,
                        Some(serde_json::json!({ "url": url, "bytes": data.len() })),
                    );
                }
                Err(err) => {
                    self.add_action(
                        actions,
                        &format!("download-{}", actions.len()),
                        action_types::DOWNLOAD,
                        &format!("Download failed: {}", err),
                        false,
                        Some(serde_json::json!({ "url": url })),
                    );
                }
            }
            result.map_err(|e| self.create_error(error_codes::PLUGIN_DOWNLOAD_FAILED, &e.to_string()))
        } else if let Some(path) = &artifact.path {
            let result = self.registry_client.read_file_artifact(path);
            match &result {
                Ok(data) => {
                    self.add_action(
                        actions,
                        &format!("download-{}", actions.len()),
                        action_types::DOWNLOAD,
                        &format!("Read artifact file ({} bytes)", data.len()),
                        true,
                        Some(serde_json::json!({ "path": path, "bytes": data.len() })),
                    );
                }
                Err(err) => {
                    self.add_action(
                        actions,
                        &format!("download-{}", actions.len()),
                        action_types::DOWNLOAD,
                        &format!("File read failed: {}", err),
                        false,
                        Some(serde_json::json!({ "path": path })),
                    );
                }
            }
            result.map_err(|e| self.create_error(error_codes::PLUGIN_IO_ERROR, &e.to_string()))
        } else {
            Err(self.create_error(error_codes::PLUGIN_DOWNLOAD_FAILED, "No URL or path specified"))
        }
    }

    /// Verify artifact checksum
    fn verify_artifact(&mut self, data: &[u8], artifact: &ArtifactCandidate, actions: &mut Vec<Action>) -> Result<()> {
        if let Some(expected_sha256) = &artifact.sha256 {
            let result = self.registry_client.verify_checksum(data, expected_sha256);
            match &result {
                Ok(()) => {
                    self.add_action(
                        actions,
                        &format!("verify-{}", actions.len()),
                        action_types::VERIFY,
                        "Checksum verified successfully",
                        true,
                        Some(serde_json::json!({ "sha256": expected_sha256 })),
                    );
                }
                Err(err) => {
                    self.add_action(
                        actions,
                        &format!("verify-{}", actions.len()),
                        action_types::VERIFY,
                        &format!("Checksum verification failed: {}", err),
                        false,
                        Some(serde_json::json!({ "expected_sha256": expected_sha256 })),
                    );
                }
            }
            result.map_err(|e| self.create_error(error_codes::PLUGIN_VERIFY_FAILED, &e.to_string()))
        } else {
            self.add_action(actions, &format!("verify-{}", actions.len()), action_types::VERIFY, "No checksum to verify", true, None);
            Ok(())
        }
    }

    /// Extract artifact (tar.gz or binary)
    fn extract_artifact(
        &mut self,
        data: &[u8],
        args: &PluginOpArgs,
        artifact: &ArtifactCandidate,
        actions: &mut Vec<Action>,
    ) -> Result<std::path::PathBuf> {
        let staging_dir = self.store.staging_dir(&args.plugin_id)
            .map_err(|e| self.create_error(error_codes::PLUGIN_IO_ERROR, &e.to_string()))?;

        let extract_result = if artifact.kind == "tar.gz" {
            self.extract_tar_gz(data, &staging_dir)
        } else {
            self.extract_binary(data, &staging_dir, &args.plugin_id)
        };

        match &extract_result {
            Ok(path) => {
                self.add_action(
                    actions,
                    &format!("extract-{}", actions.len()),
                    action_types::EXTRACT,
                    &format!("Extracted artifact to: {}", path.display()),
                    true,
                    Some(serde_json::json!({ "path": path.to_string_lossy() })),
                );
            }
            Err(err) => {
                self.add_action(
                    actions,
                    &format!("extract-{}", actions.len()),
                    action_types::EXTRACT,
                    &format!("Extraction failed: {}", err),
                    false,
                    None,
                );
            }
        }

        extract_result.map_err(|e| self.create_error(error_codes::PLUGIN_EXTRACT_FAILED, &e.to_string()))
    }

    /// Extract tar.gz archive
    fn extract_tar_gz(&self, data: &[u8], staging_dir: &Path) -> Result<std::path::PathBuf> {
        use flate2::read::GzDecoder;
        use tar::Archive;
        use std::io::Cursor;

        let cursor = Cursor::new(data);
        let gz_decoder = GzDecoder::new(cursor);
        let mut archive = Archive::new(gz_decoder);

        archive.unpack(staging_dir)
            .context("Failed to extract tar.gz archive")?;

        Ok(staging_dir.to_path_buf())
    }

    /// Extract single binary file
    fn extract_binary(&self, data: &[u8], staging_dir: &Path, plugin_id: &str) -> Result<std::path::PathBuf> {
        let binary_path = staging_dir.join(plugin_id);
        fs::write(&binary_path, data)
            .with_context(|| format!("Failed to write binary to: {}", binary_path.display()))?;

        Ok(staging_dir.to_path_buf())
    }

    // TODO: Fix these helper methods for new envelope structure
    /*
    /// Build result for successful operation
    fn build_success_result(
        &self,
        args: &PluginOpArgs,
        previous_version: Option<&str>,
        version: Option<&str>,
        artifact: &ArtifactCandidate,
        installed_metadata: &super::types::InstalledPlugin,
    ) -> PluginResult {
        PluginResult {
            removed: None,
            purged: None,
            installed: Some(true),
            previous_version: previous_version.map(|s| s.to_string()),
            version: version.map(|s| s.to_string()),
        }
    }

    /// Build result for dry run
    fn build_dry_run_result(
        &self,
        args: &PluginOpArgs,
        previous_version: Option<&str>,
        version: Option<&str>,
        artifact: &ArtifactCandidate,
    ) -> PluginResult {
        PluginResult {
            removed: None,
            purged: None,
            installed: Some(false),
            previous_version: previous_version.map(|s| s.to_string()),
            version: version.map(|s| s.to_string()),
        }
    }

    /// Build result for no-op
    fn build_noop_result(
        &self,
        args: &PluginOpArgs,
        installed: Option<&super::types::InstalledPlugin>,
    ) -> PluginResult {
        PluginResult {
            removed: None,
            purged: None,
            installed: Some(installed.is_some()),
            previous_version: None,
            version: installed.map(|i| i.version.clone()),
        }
    }
    */

    /// Add action to actions list with deterministic ordering
    fn add_action(&self, actions: &mut Vec<Action>, id: &str, action_type: &str, name: &str, ok: bool, details: Option<serde_json::Value>) {
        actions.push(Action {
            id: id.to_string(),
            action_type: action_type.to_string(),
            name: name.to_string(),
            ok,
            details,
        });
    }

    /// Convert source spec to string
    fn source_to_string(&self, source: &super::types::SourceSpec) -> String {
        match source {
            super::types::SourceSpec::Registry { .. } => "registry".to_string(),
            super::types::SourceSpec::Url { .. } => "url".to_string(),
            super::types::SourceSpec::File { .. } => "file".to_string(),
        }
    }

    /// Extract error information from error
    fn extract_error_info(&self, error: &anyhow::Error) -> (String, i32, Vec<Action>) {
        let error_str = error.to_string();
        
        // Try to match known error patterns
        let error_code = if error_str.contains("not found") || error_str.contains("not in registry") {
            error_codes::PLUGIN_NOT_FOUND
        } else if error_str.contains("timeout") {
            error_codes::PLUGIN_TIMEOUT
        } else if error_str.contains("checksum") || error_str.contains("verification") {
            error_codes::PLUGIN_VERIFY_FAILED
        } else if error_str.contains("download") {
            error_codes::PLUGIN_DOWNLOAD_FAILED
        } else if error_str.contains("already installed") {
            error_codes::PLUGIN_ALREADY_INSTALLED
        } else if error_str.contains("not installed") {
            error_codes::PLUGIN_NOT_INSTALLED
        } else {
            "PLUGIN_UNKNOWN_ERROR"
        };

        let numeric_code = error_code_to_numeric(error_code);
        
        (error_code.to_string(), numeric_code, vec![])
    }

    /// Check if error is retryable
    fn is_retryable_error(&self, error_code: &str) -> bool {
        matches!(error_code, 
            error_codes::PLUGIN_REGISTRY_UNAVAILABLE |
            error_codes::PLUGIN_DOWNLOAD_FAILED |
            error_codes::PLUGIN_TIMEOUT
        )
    }

    /// Create structured error
    fn create_error(&self, code: &str, message: &str) -> anyhow::Error {
        anyhow!("{}: {}", code, message)
    }

    /// Build envelope metadata (target and args info)
    fn build_envelope_metadata(&self, args: &PluginOpArgs, installed: Option<&super::types::InstalledPlugin>) -> (TargetInfo, ArgsInfo) {
        let store = &self.store;
        let install_root = PluginStore::default_plugins_dir().unwrap_or_else(|_| PathBuf::from("/tmp/resh-plugins"));
        
        let target_info = TargetInfo {
            name: args.plugin_id.clone(),
            requested_name: args.plugin_id.clone(),
            version: installed.map(|i| i.version.clone()),
            install_root: install_root.to_string_lossy().to_string(),
            bin_path: installed.and_then(|i| i.bin_path.clone()),
        };

        let args_info = match args.mode {
            Mode::Remove => ArgsInfo {
                force: Some(args.force),
                purge: Some(args.purge),
                dry_run: Some(args.dry_run),
                timeout_ms: Some(args.timeout_ms),
            },
            _ => ArgsInfo {
                force: None,
                purge: None,
                dry_run: Some(args.dry_run),
                timeout_ms: Some(args.timeout_ms),
            },
        };

        (target_info, args_info)
    }

    /// Execute remove operation with deterministic action ordering
    fn execute_remove(&mut self, args: &PluginOpArgs, actions: &mut Vec<Action>) -> Result<(bool, PluginResult, Option<super::types::InstalledPlugin>)> {
        // Step 1: Resolve installation (check if plugin exists)
        let installed_metadata = self.resolve_installation(args, actions)?;

        // Step 2: Check version guard if specified
        self.check_version_guard(args, &installed_metadata, actions)?;

        // Step 3: Check if plugin is in use
        self.check_in_use(args, &installed_metadata, actions)?;

        if args.dry_run {
            // For dry run, simulate what would be removed
            self.add_action(actions, "a4", "fs", "remove_manifest", true, Some(serde_json::json!({"dry_run": true})));
            self.add_action(actions, "a5", "fs", "remove_bin", true, Some(serde_json::json!({"dry_run": true})));
            if args.purge {
                self.add_action(actions, "a7", "fs", "purge_state", true, Some(serde_json::json!({"dry_run": true})));
            }
            
            let result = PluginResult {
                removed: Some(false), // dry run, so not actually removed
                purged: Some(false),
                installed: Some(false),
                previous_version: Some(installed_metadata.version.clone()),
                version: None,
                enabled: None,
                was_enabled: None,
            };
            return Ok((false, result, Some(installed_metadata)));
        }

        // Acquire lock for atomic removal
        let _lock_guard = self.store.create_lock(&args.plugin_id)
            .map_err(|e| self.create_error(error_codes::PLUGIN_IO_ERROR, &format!("Failed to acquire lock: {}", e)))?;

        // Step 4: Remove manifest
        self.remove_manifest(args, &installed_metadata, actions)?;

        // Step 5: Remove binary
        self.remove_binary(args, &installed_metadata, actions)?;

        // Step 6: Remove support files
        self.remove_support_files(args, &installed_metadata, actions)?;

        // Step 7: Purge state if requested
        if args.purge {
            self.purge_state(args, actions)?;
        }

        // Step 8: Sync registry (cleanup locks, etc)
        self.sync_registry(args, actions)?;

        let result = PluginResult {
            removed: Some(true),
            purged: Some(args.purge),
            installed: Some(false),
            previous_version: Some(installed_metadata.version.clone()),
            version: None,
            enabled: None,
            was_enabled: None,
        };

        Ok((true, result, Some(installed_metadata)))
    }

    /// Step 1: Resolve installation
    fn resolve_installation(&mut self, args: &PluginOpArgs, actions: &mut Vec<Action>) -> Result<super::types::InstalledPlugin> {
        match self.store.get_installed_metadata(&args.plugin_id) {
            Ok(Some(metadata)) => {
                self.add_action(
                    actions,
                    "a1",
                    "check",
                    "resolve_installation",
                    true,
                    Some(serde_json::json!({
                        "version": metadata.version,
                        "install_path": metadata.install_path,
                    })),
                );
                Ok(metadata)
            }
            Ok(None) => {
                self.add_action(
                    actions,
                    "a1",
                    "check",
                    "resolve_installation",
                    false,
                    None,
                );
                Err(self.create_error(error_codes::PLUGIN_NOT_INSTALLED, "Plugin not installed"))
            }
            Err(err) => {
                self.add_action(
                    actions,
                    "a1",
                    "check",
                    "resolve_installation",
                    false,
                    None,
                );
                Err(self.create_error(error_codes::PLUGIN_IO_ERROR, &err.to_string()))
            }
        }
    }

    /// Step 2: Check version guard
    fn check_version_guard(
        &mut self, 
        args: &PluginOpArgs, 
        installed: &super::types::InstalledPlugin, 
        actions: &mut Vec<Action>
    ) -> Result<()> {
        if let super::types::RequestedVersion::Specific(requested_version) = &args.requested_version {
            if installed.version != *requested_version {
                if args.force {
                    self.add_action(
                        actions,
                        "a2",
                        "check",
                        "version_guard",
                        true,
                        Some(serde_json::json!({
                            "installed_version": installed.version,
                            "requested_version": requested_version,
                            "forced": true
                        })),
                    );
                    return Ok(());
                } else {
                    self.add_action(
                        actions,
                        "a2",
                        "check",
                        "version_guard",
                        false,
                        None,
                    );
                    return Err(self.create_error(
                        error_codes::PLUGIN_VERSION_CONFLICT, 
                        &format!("Installed version {} does not match requested version {}", 
                                installed.version, requested_version)
                    ));
                }
            }
        }
        
        self.add_action(
            actions,
            "a2",
            "check",
            "version_guard",
            true,
            None,
        );
        Ok(())
    }

    /// Step 3: Check if plugin is in use
    fn check_in_use(
        &mut self, 
        args: &PluginOpArgs, 
        installed: &super::types::InstalledPlugin, 
        actions: &mut Vec<Action>
    ) -> Result<()> {
        let in_use = self.is_plugin_in_use(&args.plugin_id, installed)?;
        
        if in_use {
            if args.force {
                self.add_action(
                    actions,
                    "a3",
                    "check",
                    "check_in_use",
                    true,
                    Some(serde_json::json!({"forced": true})),
                );
            } else {
                self.add_action(
                    actions,
                    "a3",
                    "check",
                    "check_in_use",
                    false,
                    None,
                );
                return Err(self.create_error(
                    error_codes::PLUGIN_IN_USE,
                    "Plugin is currently in use. Use force=true to remove anyway"
                ));
            }
        } else {
            self.add_action(
                actions,
                "a3",
                "check",
                "check_in_use",
                true,
                None,
            );
        }
        Ok(())
    }

    /// Check if plugin is currently in use
    fn is_plugin_in_use(&self, plugin_id: &str, installed: &super::types::InstalledPlugin) -> Result<bool> {
        // Check if binary is running (best effort)
        if let Some(ref bin_path) = installed.bin_path {
            // Use pgrep to check for running processes
            match std::process::Command::new("pgrep")
                .arg("-f")
                .arg(bin_path)
                .output()
            {
                Ok(output) => {
                    if output.status.success() && !output.stdout.is_empty() {
                        return Ok(true);
                    }
                }
                Err(_) => {
                    // pgrep not available, try /proc scan on Linux
                    #[cfg(target_os = "linux")]
                    {
                        if let Ok(entries) = fs::read_dir("/proc") {
                            for entry in entries.flatten() {
                                if let Ok(pid_str) = entry.file_name().into_string() {
                                    if let Ok(_pid) = pid_str.parse::<u32>() {
                                        let exe_path = format!("/proc/{}/exe", pid_str);
                                        if let Ok(target) = fs::read_link(&exe_path) {
                                            if target == PathBuf::from(bin_path) {
                                                return Ok(true);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Ok(false) // Not in use or couldn't determine
    }

    /// Step 4: Remove manifest
    fn remove_manifest(
        &mut self,
        args: &PluginOpArgs,
        installed: &super::types::InstalledPlugin,
        actions: &mut Vec<Action>
    ) -> Result<()> {
        // Remove the plugin using store
        match self.store.remove_plugin(&args.plugin_id, Some(&installed.version)) {
            Ok(removed_paths) => {
                let paths: Vec<String> = removed_paths
                    .iter()
                    .map(|p| p.to_string_lossy().to_string())
                    .collect();
                
                self.add_action(
                    actions,
                    "a4",
                    "fs",
                    "remove_manifest",
                    true,
                    Some(serde_json::json!({"paths": paths})),
                );
                Ok(())
            }
            Err(err) => {
                self.add_action(
                    actions,
                    "a4",
                    "fs",
                    "remove_manifest",
                    false,
                    None,
                );
                Err(self.create_error(error_codes::PLUGIN_REMOVE_FAILED, &err.to_string()))
            }
        }
    }

    /// Step 5: Remove binary
    fn remove_binary(
        &mut self,
        args: &PluginOpArgs,
        installed: &super::types::InstalledPlugin,
        actions: &mut Vec<Action>
    ) -> Result<()> {
        if let Some(ref bin_path) = installed.bin_path {
            let bin_pathbuf = PathBuf::from(bin_path);
            if bin_pathbuf.exists() {
                match fs::remove_file(&bin_pathbuf) {
                    Ok(_) => {
                        let metadata = fs::metadata(&bin_pathbuf).ok();
                        let size = metadata.map(|m| m.len()).unwrap_or(0);
                        
                        self.add_action(
                            actions,
                            "a5",
                            "fs",
                            "remove_bin",
                            true,
                            Some(serde_json::json!({
                                "path": bin_path,
                                "bytes": size
                            })),
                        );
                    }
                    Err(err) => {
                        self.add_action(
                            actions,
                            "a5",
                            "fs",
                            "remove_bin",
                            false,
                            None,
                        );
                        return Err(self.create_error(error_codes::PLUGIN_REMOVE_FAILED, &err.to_string()));
                    }
                }
            } else {
                self.add_action(
                    actions,
                    "a5",
                    "fs",
                    "remove_bin",
                    true,
                    Some(serde_json::json!({"skipped": true})),
                );
            }
        } else {
            self.add_action(
                actions,
                "a5",
                "fs",
                "remove_bin",
                true,
                Some(serde_json::json!({"skipped": true})),
            );
        }
        Ok(())
    }

    /// Step 6: Remove support files
    fn remove_support_files(
        &mut self,
        args: &PluginOpArgs,
        installed: &super::types::InstalledPlugin,
        actions: &mut Vec<Action>
    ) -> Result<()> {
        // List and remove any additional plugin files
        match self.store.list_plugin_files(&args.plugin_id, &installed.version) {
            Ok(files) => {
                let file_count = files.len();
                self.add_action(
                    actions,
                    "a6",
                    "fs",
                    "remove_support_files",
                    true,
                    Some(serde_json::json!({"file_count": file_count})),
                );
            }
            Err(_) => {
                // Non-critical error - files may already be removed
                self.add_action(
                    actions,
                    "a6",
                    "fs",
                    "remove_support_files",
                    true,
                    Some(serde_json::json!({"skipped": true})),
                );
            }
        }
        Ok(())
    }

    /// Step 7: Purge state
    fn purge_state(&mut self, args: &PluginOpArgs, actions: &mut Vec<Action>) -> Result<()> {
        match self.store.purge_plugin_data(&args.plugin_id) {
            Ok(purged_paths) => {
                let paths: Vec<String> = purged_paths
                    .iter()
                    .map(|p| p.to_string_lossy().to_string())
                    .collect();
                
                self.add_action(
                    actions,
                    "a7",
                    "fs",
                    "purge_state",
                    true,
                    Some(serde_json::json!({"paths": paths})),
                );
            }
            Err(err) => {
                self.add_action(
                    actions,
                    "a7",
                    "fs",
                    "purge_state",
                    false,
                    None,
                );
                return Err(self.create_error(error_codes::PLUGIN_REMOVE_FAILED, &err.to_string()));
            }
        }
        Ok(())
    }

    /// Step 8: Sync registry
    fn sync_registry(&mut self, args: &PluginOpArgs, actions: &mut Vec<Action>) -> Result<()> {
        // Remove lock file and cleanup
        match self.store.remove_lock(&args.plugin_id) {
            Ok(_) => {
                self.add_action(
                    actions,
                    "a8",
                    "internal",
                    "sync_registry",
                    true,
                    None,
                );
            }
            Err(err) => {
                // Non-critical error
                self.add_action(
                    actions,
                    "a8",
                    "internal",
                    "sync_registry",
                    true,
                    Some(serde_json::json!({"warning": err.to_string()})),
                );
            }
        }
        Ok(())
    }

    /// Execute enable operation with deterministic action ordering
    fn execute_enable(&mut self, args: &PluginOpArgs, _actions: &mut Vec<Action>) -> Result<(bool, PluginResult, Option<super::types::InstalledPlugin>)> {
        // This method is just a stub for the main execute_operation flow
        // The actual enable logic is in run_enable_operation
        Err(anyhow!("Enable should use run_enable_operation instead"))
    }

    /// Run enable operation and return enable-specific envelope
    pub fn run_enable_operation(&mut self, args: PluginOpArgs) -> super::types::EnableEnvelope {
        use super::types::{action_types, error_codes, EnableEnvelope, EnableTargetInfo, EnableResult, EnableAction, EnableError};
        
        let mut actions = Vec::new();
        
        // Step 1: Resolve plugin ID and validate
        self.add_enable_action(&mut actions, "resolve", None, "ok", Some("Validated plugin ID".to_string()));
        
        // Validate plugin ID format
        if args.plugin_id.is_empty() || args.plugin_id.contains("..") {
            return self.build_enable_error_envelope(args, actions, error_codes::INVALID_ARGUMENT, "Invalid plugin ID");
        }
        
        // Extract scope from args - default to "user"
        let scope = match &args.source {
            super::types::SourceSpec::Registry { url } if url == "system" => "system",
            _ => "user",
        };
        
        // Extract values before potentially moving args
        let plugin_id = args.plugin_id.clone();
        
        // Step 2: Load installed manifest
        let installed_metadata = match self.store.get_installed_metadata(&plugin_id) {
            Ok(Some(metadata)) => {
                self.add_enable_action(&mut actions, action_types::LOAD_MANIFEST, None, "ok", Some("Plugin manifest loaded".to_string()));
                metadata
            }
            Ok(None) => {
                self.add_enable_action(&mut actions, action_types::LOAD_MANIFEST, None, "failed", Some("Plugin not installed".to_string()));
                return self.build_enable_error_envelope(args, actions, error_codes::PLUGIN_NOT_INSTALLED, &format!("Plugin '{}' is not installed", plugin_id));
            }
            Err(err) => {
                self.add_enable_action(&mut actions, action_types::LOAD_MANIFEST, None, "failed", Some(format!("Error: {}", err)));
                return self.build_enable_error_envelope(args, actions, error_codes::PLUGIN_IO_ERROR, &format!("Failed to load plugin manifest: {}", err));
            }
        };
        
        // Step 3: Version check if requested
        if let super::types::RequestedVersion::Specific(ref requested_version) = args.requested_version {
            if installed_metadata.version != *requested_version {
                let requested_version_str = requested_version.clone();
                return self.build_enable_error_envelope(args, actions, error_codes::PLUGIN_VERSION_MISMATCH, 
                    &format!("Installed version {} does not match requested version {}", 
                             installed_metadata.version, requested_version_str));
            }
        }
        
        // Step 4: Validate entrypoint if requested
        if args.verify != super::types::VerifyMode::None {
            match self.validate_plugin_entrypoint(&installed_metadata) {
                Ok(_) => {
                    self.add_enable_action(&mut actions, action_types::VALIDATE_ENTRYPOINT, None, "ok", Some("Entrypoint validated".to_string()));
                }
                Err(err) => {
                    self.add_enable_action(&mut actions, action_types::VALIDATE_ENTRYPOINT, None, "failed", Some(format!("Error: {}", err)));
                    return self.build_enable_error_envelope(args, actions, error_codes::PLUGIN_INVALID, &format!("Plugin entrypoint validation failed: {}", err));
                }
            }
        }
        
        // Step 5: Load enabled registry
        let mut registry = match self.store.load_enabled_registry(scope) {
            Ok(registry) => {
                self.add_enable_action(&mut actions, action_types::LOAD_ENABLED_REGISTRY, None, "ok", 
                    Some(format!("Loaded registry for scope '{}'", scope)));
                registry
            }
            Err(err) => {
                self.add_enable_action(&mut actions, action_types::LOAD_ENABLED_REGISTRY, None, "failed", 
                    Some(format!("Error: {}", err)));
                return self.build_enable_error_envelope(args, actions, error_codes::PLUGIN_IO_ERROR, &format!("Failed to load enabled registry: {}", err));
            }
        };
        
        // Step 6: Check if already enabled
        let was_enabled = registry.is_enabled(&args.plugin_id);
        let changed = if was_enabled && !args.force {
            // Already enabled, idempotent operation
            self.add_enable_action(&mut actions, action_types::WRITE_ENABLED_REGISTRY, None, "ok", 
                Some("Plugin already enabled".to_string()));
            false
        } else {
            // Step 7: Enable plugin if not dry run
            if args.dry_run {
                self.add_enable_action(&mut actions, action_types::WRITE_ENABLED_REGISTRY, None, "planned", 
                    Some("Would enable plugin".to_string()));
                false
            } else {
                // Add/update plugin in enabled registry
                registry.enable_plugin(args.plugin_id.clone(), installed_metadata.version.clone());
                
                // Step 8: Save enabled registry atomically
                match self.store.save_enabled_registry(scope, &registry) {
                    Ok(_) => {
                        let registry_path = self.store.enabled_registry_path(scope).unwrap_or_default();
                        self.add_enable_action(&mut actions, "fs.write", Some(registry_path.to_string_lossy().to_string()), "ok", 
                            Some("Added plugin to enabled set".to_string()));
                        true
                    }
                    Err(err) => {
                        self.add_enable_action(&mut actions, "fs.write", None, "failed", 
                            Some(format!("Error: {}", err)));
                        return self.build_enable_error_envelope(args, actions, error_codes::PLUGIN_IO_ERROR, &format!("Failed to save enabled registry: {}", err));
                    }
                }
            }
        };
        
        // Build successful envelope
        EnableEnvelope {
            op: "plugin.enable".to_string(),
            target: EnableTargetInfo {
                id: args.plugin_id,
                scope: Some(scope.to_string()),
            },
            ok: true,
            changed,
            actions,
            result: EnableResult {
                enabled: true,
                was_enabled,
                installed: true,
                version: installed_metadata.version,
            },
            warnings: vec![],
            error: None,
        }
    }
    
    /// Add action to enable actions list
    fn add_enable_action(&self, actions: &mut Vec<super::types::EnableAction>, kind: &str, path: Option<String>, status: &str, detail: Option<String>) {
        actions.push(super::types::EnableAction {
            kind: kind.to_string(),
            path,
            status: status.to_string(),
            detail,
        });
    }
    
    /// Build error envelope for enable operation
    fn build_enable_error_envelope(&self, args: PluginOpArgs, actions: Vec<super::types::EnableAction>, error_code: &str, message: &str) -> super::types::EnableEnvelope {
        use super::types::{EnableEnvelope, EnableTargetInfo, EnableResult, EnableError, error_code_to_numeric};
        
        let scope = match &args.source {
            super::types::SourceSpec::Registry { url } if url == "system" => "system",
            _ => "user",
        };
        
        EnableEnvelope {
            op: "plugin.enable".to_string(),
            target: EnableTargetInfo {
                id: args.plugin_id,
                scope: Some(scope.to_string()),
            },
            ok: false,
            changed: false,
            actions,
            result: EnableResult {
                enabled: false,
                was_enabled: false,
                installed: false,
                version: "unknown".to_string(),
            },
            warnings: vec![],
            error: Some(EnableError {
                code: error_code.to_string(),
                message: message.to_string(),
                detail: Some(serde_json::json!({})),
            }),
        }
    }
    
    /// Validate plugin entrypoint exists and is executable
    fn validate_plugin_entrypoint(&self, metadata: &super::types::InstalledPlugin) -> Result<()> {
        if let Some(ref bin_path) = metadata.bin_path {
            let path = std::path::Path::new(bin_path);
            if !path.exists() {
                return Err(anyhow!("Plugin entrypoint does not exist: {}", bin_path));
            }
            
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let metadata_fs = std::fs::metadata(path)?;
                if metadata_fs.permissions().mode() & 0o111 == 0 {
                    return Err(anyhow!("Plugin entrypoint is not executable: {}", bin_path));
                }
            }
        } else {
            return Err(anyhow!("Plugin has no entrypoint defined"));
        }
        
        Ok(())
    }
}