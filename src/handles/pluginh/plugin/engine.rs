use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::registry::{RegistryClient, parse_sha256};
use super::store::{
    PluginStore, artifact_relative_path, create_dirs_no_follow, create_new_no_follow,
    sanitized_mode,
};
use super::types::{
    Action, ArgsInfo, ArtifactCandidate, ArtifactInfo, Envelope, Mode, PathInfo, PlanDecision,
    PluginOpArgs, PluginResult, SourceSpec, StructuredError, TargetInfo, VerifyMode, action_types,
    error_code_to_numeric, error_codes,
};

/// Integrity rule for a resolved artifact (SEC-07).
///
/// With `verify=sha256` (the default) a remote artifact must come with a
/// well-formed SHA-256 from its registry entry; there is no other trusted
/// place to get one, so a direct `source=url` artifact cannot be verified
/// and is refused. A local `source=file` artifact involves no transport and
/// is accepted without a checksum. `verify=none` is the explicit opt-out.
/// Transport rules (HTTPS only) are enforced by the registry client and
/// apply whatever `verify` says.
fn check_integrity_metadata(args: &PluginOpArgs, candidate: &ArtifactCandidate) -> Result<()> {
    if !matches!(args.verify, VerifyMode::Sha256) || matches!(args.source, SourceSpec::File { .. })
    {
        return Ok(());
    }
    match candidate.sha256.as_deref() {
        Some(sum) if !sum.trim().is_empty() => parse_sha256(sum).map(|_| ()),
        _ if matches!(args.source, SourceSpec::Url { .. }) => Err(anyhow!(
            "No trusted SHA-256 is available for a source=url artifact, so verify=sha256 cannot be satisfied; \
             install from a registry, or pass verify=none to install without integrity verification"
        )),
        _ => Err(anyhow!(
            "Registry entry has no SHA-256 for this artifact; refusing to install an unverifiable plugin"
        )),
    }
}

/// Shared execution engine for both install and update operations
pub struct ExecutionEngine {
    registry_client: RegistryClient,
    store: PluginStore,
}

impl ExecutionEngine {
    /// Create an execution engine that uses the given plugin store.
    pub fn with_store(timeout_ms: u64, store: PluginStore) -> Result<Self> {
        Ok(Self {
            registry_client: RegistryClient::new(timeout_ms)?,
            store,
        })
    }

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
                let (target_info, args_info) =
                    self.build_envelope_metadata(&args, installed_metadata.as_ref());

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
    fn execute_operation(
        &mut self,
        args: &PluginOpArgs,
    ) -> Result<(
        bool,
        PluginResult,
        Vec<Action>,
        Option<super::types::InstalledPlugin>,
    )> {
        let mut actions = Vec::new();

        match args.mode {
            Mode::Install | Mode::Update => {
                // Step 1: Resolve candidate
                let candidate = self.resolve_candidate(args, &mut actions)?;

                // Step 2: Check installed status
                let installed_metadata = self.check_installed(args, &mut actions)?;

                // Step 3: Compare versions and make plan decision
                let plan_decision = self.make_plan_decision(
                    args,
                    installed_metadata.as_ref(),
                    &candidate,
                    &mut actions,
                )?;

                // Step 4: Execute plan
                match plan_decision {
                    PlanDecision::Install { version, artifact } => {
                        let previous = installed_metadata.as_ref().map(|m| m.version.clone());
                        if args.dry_run {
                            self.add_plan_action(
                                &mut actions,
                                &artifact,
                                previous.as_deref(),
                                &version,
                            );
                            let result = PluginResult {
                                removed: None,
                                purged: None,
                                installed: Some(false),
                                previous_version: previous,
                                version: Some(version),
                                enabled: None,
                                was_enabled: None,
                            };
                            return Ok((false, result, actions, installed_metadata));
                        }
                        let (mut result, metadata) =
                            self.execute_install(args, &version, &artifact, &mut actions)?;
                        result.previous_version = previous;
                        Ok((true, result, actions, Some(metadata)))
                    }
                    PlanDecision::Update {
                        from_version,
                        to_version,
                        artifact,
                    } => {
                        if args.dry_run {
                            self.add_plan_action(
                                &mut actions,
                                &artifact,
                                Some(&from_version),
                                &to_version,
                            );
                            let result = PluginResult {
                                removed: None,
                                purged: None,
                                installed: Some(true),
                                previous_version: Some(from_version),
                                version: Some(to_version),
                                enabled: None,
                                was_enabled: None,
                            };
                            return Ok((false, result, actions, installed_metadata));
                        }
                        let (result, metadata) = self.execute_update(
                            args,
                            &from_version,
                            &to_version,
                            &artifact,
                            &mut actions,
                        )?;
                        Ok((true, result, actions, Some(metadata)))
                    }
                    PlanDecision::NoOp { reason } => {
                        self.add_action(
                            &mut actions,
                            "a1",
                            action_types::INSTALL,
                            "noop",
                            true,
                            Some(serde_json::json!({"reason": reason})),
                        );
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
                let (changed, result, installed_metadata) =
                    self.execute_remove(args, &mut actions)?;
                Ok((changed, result, actions, installed_metadata))
            }
            Mode::Enable => {
                let (changed, result, installed_metadata) =
                    self.execute_enable(args, &mut actions)?;
                Ok((changed, result, actions, installed_metadata))
            }
            Mode::Disable => {
                // Disable mode should not use this path - it uses the state manager directly
                Err(anyhow!(
                    "Disable should use PluginStateManager::set_enabled_state instead"
                ))
            }
        }
    }

    /// Resolve plugin candidate from source
    fn resolve_candidate(
        &mut self,
        args: &PluginOpArgs,
        actions: &mut Vec<Action>,
    ) -> Result<ArtifactCandidate> {
        // The id and the registry-supplied version become store path
        // components; reject unsafe values before anything is fetched.
        let result = super::store::validate_path_component("id", &args.plugin_id)
            .and_then(|_| {
                self.registry_client.resolve_plugin(
                    &args.plugin_id,
                    &args.source,
                    &args.requested_version,
                    &args.verify,
                )
            })
            .and_then(|c| {
                super::store::validate_path_component("version", &c.manifest.version)?;
                check_integrity_metadata(args, &c).map_err(|e| {
                    self.create_error(error_codes::PLUGIN_VERIFY_FAILED, &e.to_string())
                })?;
                Ok(c)
            });

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
    fn check_installed(
        &mut self,
        args: &PluginOpArgs,
        actions: &mut Vec<Action>,
    ) -> Result<Option<super::types::InstalledPlugin>> {
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
            let comparison = self
                .registry_client
                .compare_versions(&installed_meta.version, &candidate.manifest.version);

            match comparison {
                std::cmp::Ordering::Equal => {
                    if args.force {
                        Ok(PlanDecision::Install {
                            version: candidate.manifest.version.clone(),
                            artifact: candidate.clone(),
                        })
                    } else {
                        Ok(PlanDecision::NoOp {
                            reason: format!(
                                "Plugin already installed with version {}",
                                installed_meta.version
                            ),
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
                                installed_meta.version, candidate.manifest.version
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

        let comparison = self
            .registry_client
            .compare_versions(&installed_meta.version, &candidate.manifest.version);

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
                        message: format!(
                            "No update available (current version: {})",
                            installed_meta.version
                        ),
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
                            installed_meta.version, candidate.manifest.version
                        ),
                    })
                } else {
                    Ok(PlanDecision::NoOp {
                        reason: format!(
                            "Plugin version {} is newer than available {}",
                            installed_meta.version, candidate.manifest.version
                        ),
                    })
                }
            }
        }
    }

    /// Records the planned install or update for a dry run; nothing is
    /// downloaded, written, or activated.
    fn add_plan_action(
        &self,
        actions: &mut Vec<Action>,
        artifact: &ArtifactCandidate,
        from_version: Option<&str>,
        to_version: &str,
    ) {
        self.add_action(
            actions,
            &format!("plan-{}", actions.len()),
            action_types::INSTALL,
            "Dry run: no changes made",
            true,
            Some(serde_json::json!({
                "dry_run": true,
                "from_version": from_version,
                "to_version": to_version,
                "artifact_kind": artifact.kind,
                "artifact_url": artifact.url,
                "artifact_path": artifact.path,
                "sha256": artifact.sha256,
            })),
        );
    }

    /// Execute install operation
    fn execute_install(
        &mut self,
        args: &PluginOpArgs,
        version: &str,
        artifact: &ArtifactCandidate,
        actions: &mut Vec<Action>,
    ) -> Result<(PluginResult, super::types::InstalledPlugin)> {
        // Download artifact
        let artifact_data = self.download_artifact(artifact, actions)?;

        // Verify artifact (before anything is written to disk)
        if matches!(args.verify, VerifyMode::Sha256) {
            self.verify_artifact(&artifact_data, args, artifact, actions)?;
        }

        // Extract artifact; a rejected or failed extraction leaves no staging behind
        let extracted_path = match self.extract_artifact(&artifact_data, args, artifact, actions) {
            Ok(path) => path,
            Err(e) => {
                let _ = self.store.cleanup_staging(&args.plugin_id);
                return Err(e);
            }
        };

        // Install plugin
        let installed_metadata = match self.store.install_plugin(
            &args.plugin_id,
            version,
            artifact,
            &extracted_path,
            &self.source_to_string(&args.source),
        ) {
            Ok(metadata) => metadata,
            Err(e) => {
                let _ = self.store.cleanup_staging(&args.plugin_id);
                return Err(self.create_error(error_codes::PLUGIN_INSTALL_FAILED, &e.to_string()));
            }
        };

        self.add_action(
            actions,
            &format!("install-{}", actions.len()),
            action_types::INSTALL,
            "Plugin installed successfully",
            true,
            None,
        );

        // Activate plugin
        self.store
            .activate_version(&args.plugin_id, version)
            .map_err(|e| self.create_error(error_codes::PLUGIN_ACTIVATE_FAILED, &e.to_string()))?;

        self.add_action(
            actions,
            &format!("activate-{}", actions.len()),
            action_types::ACTIVATE,
            "Plugin activated successfully",
            true,
            None,
        );

        // Cleanup
        let _ = self.store.cleanup_staging(&args.plugin_id);
        self.add_action(
            actions,
            &format!("cleanup-{}", actions.len()),
            action_types::CLEANUP,
            "Staging cleanup completed",
            true,
            None,
        );

        Ok((
            PluginResult {
                removed: None,
                purged: None,
                installed: Some(true),
                previous_version: None,
                version: Some(installed_metadata.version.clone()),
                enabled: None,
                was_enabled: None,
            },
            installed_metadata,
        ))
    }

    /// Execute update operation
    fn execute_update(
        &mut self,
        args: &PluginOpArgs,
        from_version: &str,
        to_version: &str,
        artifact: &ArtifactCandidate,
        actions: &mut Vec<Action>,
    ) -> Result<(PluginResult, super::types::InstalledPlugin)> {
        // Execute install-like process for the new version
        let result = self.execute_install(args, to_version, artifact, actions);

        match result {
            Ok((success_result, metadata)) => Ok((
                PluginResult {
                    previous_version: Some(from_version.to_string()),
                    ..success_result
                },
                metadata,
            )),
            Err(install_error) => {
                // Attempt rollback
                if let Err(rollback_err) =
                    self.store.rollback_to_previous(&args.plugin_id, to_version)
                {
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
    fn download_artifact(
        &mut self,
        artifact: &ArtifactCandidate,
        actions: &mut Vec<Action>,
    ) -> Result<Vec<u8>> {
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
            result
                .map_err(|e| self.create_error(error_codes::PLUGIN_DOWNLOAD_FAILED, &e.to_string()))
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
            Err(self.create_error(
                error_codes::PLUGIN_DOWNLOAD_FAILED,
                "No URL or path specified",
            ))
        }
    }

    /// Verify artifact checksum
    fn verify_artifact(
        &mut self,
        data: &[u8],
        args: &PluginOpArgs,
        artifact: &ArtifactCandidate,
        actions: &mut Vec<Action>,
    ) -> Result<()> {
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
        } else if matches!(args.source, SourceSpec::File { .. }) {
            self.add_action(
                actions,
                &format!("verify-{}", actions.len()),
                action_types::VERIFY,
                "Local file source: no checksum to verify",
                true,
                None,
            );
            Ok(())
        } else {
            // Fail closed: a remote artifact is never installed unverified under verify=sha256
            self.add_action(
                actions,
                &format!("verify-{}", actions.len()),
                action_types::VERIFY,
                "No trusted checksum available",
                false,
                None,
            );
            Err(self.create_error(
                error_codes::PLUGIN_VERIFY_FAILED,
                "No trusted SHA-256 for a remote artifact; refusing to install",
            ))
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
        let staging_dir = self
            .store
            .staging_dir(&args.plugin_id)
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

        extract_result
            .map_err(|e| self.create_error(error_codes::PLUGIN_EXTRACT_FAILED, &e.to_string()))
    }

    /// Extract tar.gz archive into the (new, empty) staging directory.
    ///
    /// Plugin artifacts are untrusted. Only regular files and directories
    /// with plain relative paths are accepted; symbolic links, hard links,
    /// device nodes and FIFOs fail the whole extraction, so nothing in
    /// staging can point at a file outside the artifact. Files are created
    /// with `create_new` and `O_NOFOLLOW`, and their mode is reduced to
    /// 0644 or 0755 (no setuid/setgid/sticky, no group/other write).
    fn extract_tar_gz(&self, data: &[u8], staging_dir: &Path) -> Result<std::path::PathBuf> {
        use flate2::read::GzDecoder;
        use std::io::Cursor;
        use tar::{Archive, EntryType};

        let cursor = Cursor::new(data);
        let gz_decoder = GzDecoder::new(cursor);
        let mut archive = Archive::new(gz_decoder);

        let entries = archive.entries().context("Failed to read tar.gz archive")?;
        for entry in entries {
            let mut entry = entry.context("Failed to read tar.gz archive entry")?;
            let raw_path = entry
                .path()
                .context("Invalid entry path in plugin artifact")?
                .into_owned();
            let Some(rel) = artifact_relative_path(&raw_path)? else {
                continue; // "." / "./": the staging directory itself
            };
            let entry_type = entry.header().entry_type();
            match entry_type {
                EntryType::Directory => {
                    create_dirs_no_follow(staging_dir, &rel)?;
                }
                EntryType::Regular | EntryType::Continuous => {
                    if let Some(parent) = rel.parent() {
                        create_dirs_no_follow(staging_dir, parent)?;
                    }
                    let mode = entry.header().mode().unwrap_or(0o644);
                    let mut out =
                        create_new_no_follow(&staging_dir.join(&rel), sanitized_mode(mode))
                            .with_context(|| format!("Failed to create plugin file {:?}", rel))?;
                    std::io::copy(&mut entry, &mut out)
                        .with_context(|| format!("Failed to write plugin file {:?}", rel))?;
                }
                EntryType::Symlink | EntryType::Link => {
                    return Err(anyhow!(
                        "Refusing plugin artifact entry {:?}: symbolic and hard links are not allowed in plugin artifacts",
                        raw_path
                    ));
                }
                other => {
                    return Err(anyhow!(
                        "Refusing plugin artifact entry {:?}: unsupported entry type {:?}",
                        raw_path,
                        other
                    ));
                }
            }
        }

        Ok(staging_dir.to_path_buf())
    }

    /// Extract single binary file
    fn extract_binary(
        &self,
        data: &[u8],
        staging_dir: &Path,
        plugin_id: &str,
    ) -> Result<std::path::PathBuf> {
        let binary_path = staging_dir.join(plugin_id);
        fs::write(&binary_path, data)
            .with_context(|| format!("Failed to write binary to: {}", binary_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&binary_path, fs::Permissions::from_mode(0o755)).with_context(
                || {
                    format!(
                        "Failed to make binary executable: {}",
                        binary_path.display()
                    )
                },
            )?;
        }

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
    fn add_action(
        &self,
        actions: &mut Vec<Action>,
        id: &str,
        action_type: &str,
        name: &str,
        ok: bool,
        details: Option<serde_json::Value>,
    ) {
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
        let error_code = if error_str.contains("not found") || error_str.contains("not in registry")
        {
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
        matches!(
            error_code,
            error_codes::PLUGIN_REGISTRY_UNAVAILABLE
                | error_codes::PLUGIN_DOWNLOAD_FAILED
                | error_codes::PLUGIN_TIMEOUT
        )
    }

    /// Create structured error
    fn create_error(&self, code: &str, message: &str) -> anyhow::Error {
        anyhow!("{}: {}", code, message)
    }

    /// Build envelope metadata (target and args info)
    fn build_envelope_metadata(
        &self,
        args: &PluginOpArgs,
        installed: Option<&super::types::InstalledPlugin>,
    ) -> (TargetInfo, ArgsInfo) {
        let store = &self.store;
        let install_root = PluginStore::default_plugins_dir()
            .unwrap_or_else(|_| PathBuf::from("/tmp/resh-plugins"));

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
    fn execute_remove(
        &mut self,
        args: &PluginOpArgs,
        actions: &mut Vec<Action>,
    ) -> Result<(bool, PluginResult, Option<super::types::InstalledPlugin>)> {
        // Step 1: Resolve installation (check if plugin exists)
        let installed_metadata = self.resolve_installation(args, actions)?;

        // Step 2: Check version guard if specified
        self.check_version_guard(args, &installed_metadata, actions)?;

        // Step 3: Check if plugin is in use
        self.check_in_use(args, &installed_metadata, actions)?;

        if args.dry_run {
            // For dry run, simulate what would be removed
            self.add_action(
                actions,
                "a4",
                "fs",
                "remove_manifest",
                true,
                Some(serde_json::json!({"dry_run": true})),
            );
            self.add_action(
                actions,
                "a5",
                "fs",
                "remove_bin",
                true,
                Some(serde_json::json!({"dry_run": true})),
            );
            if args.purge {
                self.add_action(
                    actions,
                    "a7",
                    "fs",
                    "purge_state",
                    true,
                    Some(serde_json::json!({"dry_run": true})),
                );
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
        let _lock_guard = self.store.create_lock(&args.plugin_id).map_err(|e| {
            self.create_error(
                error_codes::PLUGIN_IO_ERROR,
                &format!("Failed to acquire lock: {}", e),
            )
        })?;

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
    fn resolve_installation(
        &mut self,
        args: &PluginOpArgs,
        actions: &mut Vec<Action>,
    ) -> Result<super::types::InstalledPlugin> {
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
                self.add_action(actions, "a1", "check", "resolve_installation", false, None);
                Err(self.create_error(error_codes::PLUGIN_NOT_INSTALLED, "Plugin not installed"))
            }
            Err(err) => {
                self.add_action(actions, "a1", "check", "resolve_installation", false, None);
                Err(self.create_error(error_codes::PLUGIN_IO_ERROR, &err.to_string()))
            }
        }
    }

    /// Step 2: Check version guard
    fn check_version_guard(
        &mut self,
        args: &PluginOpArgs,
        installed: &super::types::InstalledPlugin,
        actions: &mut Vec<Action>,
    ) -> Result<()> {
        if let super::types::RequestedVersion::Specific(requested_version) = &args.requested_version
        {
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
                    self.add_action(actions, "a2", "check", "version_guard", false, None);
                    return Err(self.create_error(
                        error_codes::PLUGIN_VERSION_CONFLICT,
                        &format!(
                            "Installed version {} does not match requested version {}",
                            installed.version, requested_version
                        ),
                    ));
                }
            }
        }

        self.add_action(actions, "a2", "check", "version_guard", true, None);
        Ok(())
    }

    /// Step 3: Check if plugin is in use
    fn check_in_use(
        &mut self,
        args: &PluginOpArgs,
        installed: &super::types::InstalledPlugin,
        actions: &mut Vec<Action>,
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
                self.add_action(actions, "a3", "check", "check_in_use", false, None);
                return Err(self.create_error(
                    error_codes::PLUGIN_IN_USE,
                    "Plugin is currently in use. Use force=true to remove anyway",
                ));
            }
        } else {
            self.add_action(actions, "a3", "check", "check_in_use", true, None);
        }
        Ok(())
    }

    /// Check if plugin is currently in use
    fn is_plugin_in_use(
        &self,
        plugin_id: &str,
        installed: &super::types::InstalledPlugin,
    ) -> Result<bool> {
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
        actions: &mut Vec<Action>,
    ) -> Result<()> {
        // Remove the plugin using store
        match self
            .store
            .remove_plugin(&args.plugin_id, Some(&installed.version))
        {
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
                self.add_action(actions, "a4", "fs", "remove_manifest", false, None);
                Err(self.create_error(error_codes::PLUGIN_REMOVE_FAILED, &err.to_string()))
            }
        }
    }

    /// Step 5: Remove binary
    fn remove_binary(
        &mut self,
        args: &PluginOpArgs,
        installed: &super::types::InstalledPlugin,
        actions: &mut Vec<Action>,
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
                        self.add_action(actions, "a5", "fs", "remove_bin", false, None);
                        return Err(
                            self.create_error(error_codes::PLUGIN_REMOVE_FAILED, &err.to_string())
                        );
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
        actions: &mut Vec<Action>,
    ) -> Result<()> {
        // List and remove any additional plugin files
        match self
            .store
            .list_plugin_files(&args.plugin_id, &installed.version)
        {
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
                self.add_action(actions, "a7", "fs", "purge_state", false, None);
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
                self.add_action(actions, "a8", "internal", "sync_registry", true, None);
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
    fn execute_enable(
        &mut self,
        args: &PluginOpArgs,
        _actions: &mut Vec<Action>,
    ) -> Result<(bool, PluginResult, Option<super::types::InstalledPlugin>)> {
        // This method is just a stub for the main execute_operation flow
        // The actual enable logic is in run_enable_operation
        Err(anyhow!("Enable should use run_enable_operation instead"))
    }

    /// Run enable operation and return enable-specific envelope
    pub fn run_enable_operation(&mut self, args: PluginOpArgs) -> super::types::EnableEnvelope {
        use super::types::{
            EnableAction, EnableEnvelope, EnableError, EnableResult, EnableTargetInfo,
            action_types, error_codes,
        };

        let mut actions = Vec::new();

        // Step 1: Resolve plugin ID and validate
        self.add_enable_action(
            &mut actions,
            "resolve",
            None,
            "ok",
            Some("Validated plugin ID".to_string()),
        );

        // Validate plugin ID format
        if args.plugin_id.is_empty() || args.plugin_id.contains("..") {
            return self.build_enable_error_envelope(
                args,
                actions,
                error_codes::INVALID_ARGUMENT,
                "Invalid plugin ID",
            );
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
                self.add_enable_action(
                    &mut actions,
                    action_types::LOAD_MANIFEST,
                    None,
                    "ok",
                    Some("Plugin manifest loaded".to_string()),
                );
                metadata
            }
            Ok(None) => {
                self.add_enable_action(
                    &mut actions,
                    action_types::LOAD_MANIFEST,
                    None,
                    "failed",
                    Some("Plugin not installed".to_string()),
                );
                return self.build_enable_error_envelope(
                    args,
                    actions,
                    error_codes::PLUGIN_NOT_INSTALLED,
                    &format!("Plugin '{}' is not installed", plugin_id),
                );
            }
            Err(err) => {
                self.add_enable_action(
                    &mut actions,
                    action_types::LOAD_MANIFEST,
                    None,
                    "failed",
                    Some(format!("Error: {}", err)),
                );
                return self.build_enable_error_envelope(
                    args,
                    actions,
                    error_codes::PLUGIN_IO_ERROR,
                    &format!("Failed to load plugin manifest: {}", err),
                );
            }
        };

        // Step 3: Version check if requested
        if let super::types::RequestedVersion::Specific(ref requested_version) =
            args.requested_version
        {
            if installed_metadata.version != *requested_version {
                let requested_version_str = requested_version.clone();
                return self.build_enable_error_envelope(
                    args,
                    actions,
                    error_codes::PLUGIN_VERSION_MISMATCH,
                    &format!(
                        "Installed version {} does not match requested version {}",
                        installed_metadata.version, requested_version_str
                    ),
                );
            }
        }

        // Step 4: Validate entrypoint if requested
        if args.verify != super::types::VerifyMode::None {
            match self.validate_plugin_entrypoint(&installed_metadata) {
                Ok(_) => {
                    self.add_enable_action(
                        &mut actions,
                        action_types::VALIDATE_ENTRYPOINT,
                        None,
                        "ok",
                        Some("Entrypoint validated".to_string()),
                    );
                }
                Err(err) => {
                    self.add_enable_action(
                        &mut actions,
                        action_types::VALIDATE_ENTRYPOINT,
                        None,
                        "failed",
                        Some(format!("Error: {}", err)),
                    );
                    return self.build_enable_error_envelope(
                        args,
                        actions,
                        error_codes::PLUGIN_INVALID,
                        &format!("Plugin entrypoint validation failed: {}", err),
                    );
                }
            }
        }

        // Step 5: Load enabled registry
        let mut registry = match self.store.load_enabled_registry(scope) {
            Ok(registry) => {
                self.add_enable_action(
                    &mut actions,
                    action_types::LOAD_ENABLED_REGISTRY,
                    None,
                    "ok",
                    Some(format!("Loaded registry for scope '{}'", scope)),
                );
                registry
            }
            Err(err) => {
                self.add_enable_action(
                    &mut actions,
                    action_types::LOAD_ENABLED_REGISTRY,
                    None,
                    "failed",
                    Some(format!("Error: {}", err)),
                );
                return self.build_enable_error_envelope(
                    args,
                    actions,
                    error_codes::PLUGIN_IO_ERROR,
                    &format!("Failed to load enabled registry: {}", err),
                );
            }
        };

        // Step 6: Check if already enabled
        let was_enabled = registry.is_enabled(&args.plugin_id);
        let changed = if was_enabled && !args.force {
            // Already enabled, idempotent operation
            self.add_enable_action(
                &mut actions,
                action_types::WRITE_ENABLED_REGISTRY,
                None,
                "ok",
                Some("Plugin already enabled".to_string()),
            );
            false
        } else {
            // Step 7: Enable plugin if not dry run
            if args.dry_run {
                self.add_enable_action(
                    &mut actions,
                    action_types::WRITE_ENABLED_REGISTRY,
                    None,
                    "planned",
                    Some("Would enable plugin".to_string()),
                );
                false
            } else {
                // Add/update plugin in enabled registry
                registry.enable_plugin(args.plugin_id.clone(), installed_metadata.version.clone());

                // Step 8: Save enabled registry atomically
                match self.store.save_enabled_registry(scope, &registry) {
                    Ok(_) => {
                        let registry_path =
                            self.store.enabled_registry_path(scope).unwrap_or_default();
                        self.add_enable_action(
                            &mut actions,
                            "fs.write",
                            Some(registry_path.to_string_lossy().to_string()),
                            "ok",
                            Some("Added plugin to enabled set".to_string()),
                        );
                        true
                    }
                    Err(err) => {
                        self.add_enable_action(
                            &mut actions,
                            "fs.write",
                            None,
                            "failed",
                            Some(format!("Error: {}", err)),
                        );
                        return self.build_enable_error_envelope(
                            args,
                            actions,
                            error_codes::PLUGIN_IO_ERROR,
                            &format!("Failed to save enabled registry: {}", err),
                        );
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
    fn add_enable_action(
        &self,
        actions: &mut Vec<super::types::EnableAction>,
        kind: &str,
        path: Option<String>,
        status: &str,
        detail: Option<String>,
    ) {
        actions.push(super::types::EnableAction {
            kind: kind.to_string(),
            path,
            status: status.to_string(),
            detail,
        });
    }

    /// Build error envelope for enable operation
    fn build_enable_error_envelope(
        &self,
        args: PluginOpArgs,
        actions: Vec<super::types::EnableAction>,
        error_code: &str,
        message: &str,
    ) -> super::types::EnableEnvelope {
        use super::types::{
            EnableEnvelope, EnableError, EnableResult, EnableTargetInfo, error_code_to_numeric,
        };

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
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn op_args(mode: Mode, path: &str, dry_run: bool) -> PluginOpArgs {
        PluginOpArgs {
            mode,
            plugin_id: "demo".to_string(),
            source: super::super::types::SourceSpec::File {
                path: path.to_string(),
            },
            requested_version: super::super::types::RequestedVersion::Latest,
            verify: VerifyMode::None,
            force: false,
            allow_downgrade: false,
            dry_run,
            strict: false,
            purge: false,
            timeout_ms: 1000,
        }
    }

    /// A local-file plugin artifact and an engine whose store lives in a
    /// temporary directory. Nothing touches the network or the real store.
    fn setup() -> (TempDir, String, ExecutionEngine) {
        let dir = TempDir::new().unwrap();
        let artifact = dir.path().join("demo-bin");
        fs::write(&artifact, b"#!/bin/sh\necho demo\n").unwrap();
        let store = PluginStore::with_dir(dir.path().join("plugins")).unwrap();
        let engine = ExecutionEngine::with_store(1000, store).unwrap();
        (dir, artifact.to_string_lossy().to_string(), engine)
    }

    #[test]
    fn install_dry_run_reports_plan_and_writes_nothing() {
        let (dir, artifact, mut engine) = setup();
        let env = engine.run_plugin_op(op_args(Mode::Install, &artifact, true));
        assert!(env.ok, "{:?}", env.error.as_ref().map(|e| &e.message));
        assert_eq!(env.result.installed, Some(false));
        assert_eq!(env.result.version.as_deref(), Some("local"));
        assert!(env.actions.iter().any(|a| a.id.starts_with("plan-")));
        assert!(!dir.path().join("plugins/demo/versions").exists());
        assert!(!dir.path().join("plugins/demo/current").exists());
    }

    #[test]
    fn install_from_local_file_into_temp_store() {
        let (dir, artifact, mut engine) = setup();
        let env = engine.run_plugin_op(op_args(Mode::Install, &artifact, false));
        assert!(env.ok, "{:?}", env.error.as_ref().map(|e| &e.message));
        assert_eq!(env.result.installed, Some(true));
        assert_eq!(env.result.version.as_deref(), Some("local"));
        let bin = dir.path().join("plugins/demo/versions/local/demo");
        assert!(bin.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_ne!(fs::metadata(&bin).unwrap().permissions().mode() & 0o111, 0);
        }
        assert!(
            dir.path()
                .join("plugins/demo/versions/local/metadata.json")
                .is_file()
        );
        assert!(fs::symlink_metadata(dir.path().join("plugins/demo/current")).is_ok());

        // Same version again is a no-op, and update finds nothing newer.
        let again = engine.run_plugin_op(op_args(Mode::Install, &artifact, false));
        assert!(again.ok);
        let update = engine.run_plugin_op(op_args(Mode::Update, &artifact, true));
        assert!(update.ok, "{:?}", update.error.as_ref().map(|e| &e.message));
    }

    /// SEC-02: a registry whose version key and manifest version try to
    /// climb out of the store. Resolution fails before any download, in
    /// both dry-run and real mode, and the sentinel outside the store stays.
    #[test]
    fn registry_version_traversal_is_rejected_before_install() {
        let (dir, _artifact, mut engine) = setup();
        let victim = dir.path().join("victim");
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("keep.txt"), b"sentinel").unwrap();
        let evil = "../../../victim";
        let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
        let registry = serde_json::json!({
            "demo": {
                "plugin_id": "demo",
                "versions": { evil: {
                    "name": "demo", "version": evil,
                    "description": null, "author": null, "license": null,
                    "homepage": null, "repository": null, "keywords": null,
                    "platforms": { platform: {
                        "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
                        "bin": "plugin", "sha256": "00"
                    }}
                }}
            }
        });
        let reg_path = dir.path().join("registry.json");
        fs::write(&reg_path, registry.to_string()).unwrap();
        for dry_run in [true, false] {
            let mut args = op_args(Mode::Install, "", dry_run);
            args.source = super::super::types::SourceSpec::Registry {
                url: reg_path.to_string_lossy().to_string(),
            };
            let env = engine.run_plugin_op(args);
            assert!(!env.ok, "dry_run={dry_run}");
            let msg = env.error.as_ref().unwrap().message.clone();
            assert!(msg.contains("Invalid plugin version"), "{msg}");
            assert_eq!(fs::read(victim.join("keep.txt")).unwrap(), b"sentinel");
            assert_eq!(fs::read_dir(&victim).unwrap().count(), 1);
        }
    }

    #[test]
    fn unsafe_plugin_id_is_rejected_before_install() {
        let (_dir, artifact, mut engine) = setup();
        for id in ["../escape", "a/b", "..", ""] {
            let mut args = op_args(Mode::Install, &artifact, false);
            args.plugin_id = id.to_string();
            let env = engine.run_plugin_op(args);
            assert!(!env.ok, "{id:?}");
        }
    }

    #[test]
    fn update_of_missing_plugin_is_an_error_not_a_panic() {
        let (_dir, artifact, mut engine) = setup();
        let env = engine.run_plugin_op(op_args(Mode::Update, &artifact, false));
        assert!(!env.ok);
    }
}

/// Stage 3 regression tests: plugin artifact link traversal (SEC-06) and
/// registry transport and checksum integrity (SEC-07). Every test uses a
/// temporary plugin store; network tests talk only to a loopback mock.
#[cfg(test)]
mod artifact_security_tests {
    use super::super::registry::allow_loopback_http_for_tests;
    use super::super::types::{RequestedVersion, SourceSpec};
    use super::*;
    use httpmock::prelude::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tar::{EntryType, Header};
    use tempfile::TempDir;

    const SENTINEL: &[u8] = b"PRIVATE-SENTINEL-do-not-copy";

    fn args(source: SourceSpec, verify: VerifyMode, force: bool, dry_run: bool) -> PluginOpArgs {
        PluginOpArgs {
            mode: Mode::Install,
            plugin_id: "demo".to_string(),
            source,
            requested_version: RequestedVersion::Latest,
            verify,
            force,
            allow_downgrade: false,
            dry_run,
            strict: false,
            purge: false,
            timeout_ms: 5000,
        }
    }

    /// A temp dir with a private sentinel file outside the plugin store, a
    /// store, and an engine. Set any HTTP seam before calling this.
    fn setup() -> (TempDir, PathBuf, ExecutionEngine) {
        let dir = TempDir::new().unwrap();
        let secret = dir.path().join("secret");
        fs::create_dir(&secret).unwrap();
        let sentinel = secret.join("id_ed25519");
        fs::write(&sentinel, SENTINEL).unwrap();
        fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
        let store = PluginStore::with_dir(dir.path().join("plugins")).unwrap();
        let engine = ExecutionEngine::with_store(5000, store).unwrap();
        (dir, sentinel, engine)
    }

    /// Append an entry with a raw name/link name, bypassing the tar
    /// builder's own path checks, as a hostile artifact would.
    fn raw(
        b: &mut tar::Builder<Vec<u8>>,
        name: &str,
        kind: EntryType,
        link: Option<&str>,
        mode: u32,
        data: &[u8],
    ) {
        let mut h = Header::new_gnu();
        {
            let old = h.as_old_mut();
            old.name[..name.len()].copy_from_slice(name.as_bytes());
            if let Some(l) = link {
                old.linkname[..l.len()].copy_from_slice(l.as_bytes());
            }
        }
        h.set_entry_type(kind);
        h.set_mode(mode);
        h.set_size(data.len() as u64);
        h.set_cksum();
        b.append(&h, data).unwrap();
    }

    fn tar_gz(build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        build(&mut b);
        let tar = b.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar).unwrap();
        gz.finish().unwrap()
    }

    fn valid_artifact() -> Vec<u8> {
        tar_gz(|b| {
            raw(b, "bin/", EntryType::Directory, None, 0o755, b"");
            raw(
                b,
                "bin/plugin",
                EntryType::Regular,
                None,
                0o4755,
                b"#!/bin/sh\necho ok\n",
            );
            raw(
                b,
                "./share/doc/README",
                EntryType::Regular,
                None,
                0o666,
                b"readme",
            );
        })
    }

    fn write_artifact(dir: &TempDir, name: &str, data: &[u8]) -> SourceSpec {
        let path = dir.path().join(name);
        fs::write(&path, data).unwrap();
        SourceSpec::File {
            path: path.to_string_lossy().to_string(),
        }
    }

    /// True if any regular file under `root` (links not followed) holds the
    /// sentinel bytes, or any symlink exists other than the `current` links.
    fn store_leaks(root: &Path) -> bool {
        walkdir::WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .flatten()
            .any(|e| {
                let ft = e.file_type();
                if ft.is_symlink() {
                    e.file_name() != "current"
                } else {
                    ft.is_file()
                        && fs::read(e.path())
                            .map(|d| d.windows(SENTINEL.len()).any(|w| w == SENTINEL))
                            .unwrap_or(false)
                }
            })
    }

    fn nothing_installed(dir: &TempDir) {
        let root = dir.path().join("plugins/demo");
        assert!(
            !root.join("versions").exists(),
            "a version directory was created"
        );
        assert!(
            fs::symlink_metadata(root.join("current")).is_err(),
            "a current link was created"
        );
        assert!(
            !root.join(".staging").exists(),
            "staging was not cleaned up"
        );
    }

    // ---------------------------------------------------------------- SEC-06

    #[test]
    fn valid_artifact_installs_with_sanitized_modes() {
        let (dir, _sentinel, mut engine) = setup();
        let src = write_artifact(&dir, "demo.tar.gz", &valid_artifact());
        let env = engine.run_plugin_op(args(src, VerifyMode::Sha256, false, false));
        assert!(env.ok, "{:?}", env.error.as_ref().map(|e| &e.message));
        let v = dir.path().join("plugins/demo/versions/local");
        let bin = fs::symlink_metadata(v.join("bin/plugin")).unwrap();
        assert!(bin.file_type().is_file());
        assert_eq!(
            bin.permissions().mode() & 0o7777,
            0o755,
            "setuid must be dropped"
        );
        let readme = fs::symlink_metadata(v.join("share/doc/README")).unwrap();
        assert_eq!(
            readme.permissions().mode() & 0o7022,
            0,
            "no special or group/other write bits"
        );
        assert_eq!(fs::read(v.join("share/doc/README")).unwrap(), b"readme");
        assert!(!dir.path().join("plugins/demo/.staging").exists());
    }

    #[test]
    fn symlink_to_private_file_is_rejected_and_not_copied() {
        let (dir, sentinel, mut engine) = setup();
        let target = sentinel.to_string_lossy().to_string();
        let relative = "../../../../../../../../../../../../../../../../..".to_string() + &target;
        for (name, link) in [
            ("bin/plugin", target.as_str()),
            ("bin/plugin", relative.as_str()),
            ("key", target.as_str()),
        ] {
            let data = tar_gz(|b| {
                raw(b, "bin/", EntryType::Directory, None, 0o755, b"");
                raw(b, name, EntryType::Symlink, Some(link), 0o777, b"");
            });
            let src = write_artifact(&dir, "evil.tar.gz", &data);
            let env = engine.run_plugin_op(args(src, VerifyMode::None, false, false));
            assert!(!env.ok, "{name} -> {link} was accepted");
            assert!(
                env.error
                    .as_ref()
                    .unwrap()
                    .message
                    .contains("links are not allowed"),
                "{:?}",
                env.error
            );
            nothing_installed(&dir);
            assert!(
                !store_leaks(&dir.path().join("plugins")),
                "sentinel reached the store"
            );
        }
        assert_eq!(fs::read(&sentinel).unwrap(), SENTINEL);
        assert_eq!(
            fs::metadata(&sentinel).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn hard_link_to_private_file_is_rejected() {
        let (dir, sentinel, mut engine) = setup();
        let target = sentinel.to_string_lossy().to_string();
        for link in [target.as_str(), "../../secret/id_ed25519", "bin/other"] {
            let data = tar_gz(|b| {
                raw(b, "bin/other", EntryType::Regular, None, 0o755, b"x");
                raw(b, "bin/plugin", EntryType::Link, Some(link), 0o755, b"");
            });
            let src = write_artifact(&dir, "evil.tar.gz", &data);
            let env = engine.run_plugin_op(args(src, VerifyMode::None, false, false));
            assert!(!env.ok, "hard link to {link} was accepted");
            nothing_installed(&dir);
            assert!(!store_leaks(&dir.path().join("plugins")));
        }
        assert_eq!(fs::read(&sentinel).unwrap(), SENTINEL);
    }

    #[test]
    fn escaping_paths_and_special_files_are_rejected() {
        let (dir, _sentinel, mut engine) = setup();
        let outside = dir.path().join("escaped");
        let abs = outside.to_string_lossy().to_string();
        let cases: Vec<(String, EntryType)> = vec![
            ("../../../escaped".to_string(), EntryType::Regular),
            ("bin/../../escaped".to_string(), EntryType::Regular),
            (abs.clone(), EntryType::Regular),
            ("dev".to_string(), EntryType::Char),
            ("blk".to_string(), EntryType::Block),
            ("fifo".to_string(), EntryType::Fifo),
        ];
        for (name, kind) in cases {
            let data = tar_gz(|b| {
                raw(
                    b,
                    &name,
                    kind,
                    None,
                    0o644,
                    if kind == EntryType::Regular {
                        b"x"
                    } else {
                        b""
                    },
                )
            });
            let src = write_artifact(&dir, "evil.tar.gz", &data);
            let env = engine.run_plugin_op(args(src, VerifyMode::None, false, false));
            assert!(!env.ok, "{name:?} ({kind:?}) was accepted");
            nothing_installed(&dir);
            assert!(!outside.exists(), "{name:?} wrote outside the store");
            assert!(
                walkdir::WalkDir::new(dir.path())
                    .into_iter()
                    .flatten()
                    .all(|e| e.file_name() != "escaped")
            );
        }
    }

    #[test]
    fn malicious_reinstall_leaves_existing_plugin_untouched() {
        let (dir, sentinel, mut engine) = setup();
        let good = write_artifact(&dir, "good.tar.gz", &valid_artifact());
        assert!(
            engine
                .run_plugin_op(args(good, VerifyMode::None, false, false))
                .ok
        );
        let bin = dir.path().join("plugins/demo/versions/local/bin/plugin");
        let before = fs::read(&bin).unwrap();

        let target = sentinel.to_string_lossy().to_string();
        let evil = tar_gz(|b| {
            raw(b, "bin/", EntryType::Directory, None, 0o755, b"");
            raw(
                b,
                "bin/plugin",
                EntryType::Symlink,
                Some(&target),
                0o777,
                b"",
            );
        });
        let src = write_artifact(&dir, "evil.tar.gz", &evil);
        let env = engine.run_plugin_op(args(src, VerifyMode::None, true, false)); // force reinstall
        assert!(!env.ok);
        assert_eq!(
            fs::read(&bin).unwrap(),
            before,
            "installed plugin was modified"
        );
        assert!(fs::symlink_metadata(&bin).unwrap().file_type().is_file());
        assert!(fs::symlink_metadata(dir.path().join("plugins/demo/current")).is_ok());
        assert!(!dir.path().join("plugins/demo/.staging").exists());
        assert!(!store_leaks(&dir.path().join("plugins")));
    }

    /// Defense in depth: even if a link reached staging some other way, the
    /// store copy refuses it instead of reading through it, and removes the
    /// partially copied version.
    #[test]
    fn store_copy_refuses_links_in_staging() {
        let (dir, sentinel, _engine) = setup();
        let store = PluginStore::with_dir(dir.path().join("plugins")).unwrap();
        let staging = store.staging_dir("demo").unwrap();
        fs::create_dir(staging.join("bin")).unwrap();
        std::os::unix::fs::symlink(&sentinel, staging.join("bin/plugin")).unwrap();
        std::os::unix::fs::symlink(sentinel.parent().unwrap(), staging.join("dirlink")).unwrap();
        let candidate = ArtifactCandidate {
            kind: "tar.gz".to_string(),
            url: None,
            path: None,
            sha256: None,
            manifest: super::super::types::PluginManifest {
                name: "demo".to_string(),
                version: "1.0.0".to_string(),
                description: None,
                author: None,
                license: None,
                homepage: None,
                repository: None,
                keywords: None,
                platforms: Default::default(),
            },
        };
        let err = store
            .install_plugin("demo", "1.0.0", &candidate, &staging, "test")
            .unwrap_err();
        assert!(format!("{err:#}").contains("symlinks"), "{err:#}");
        assert!(!dir.path().join("plugins/demo/versions/1.0.0").exists());
        assert!(!store_leaks(&dir.path().join("plugins/demo/versions")));
        assert_eq!(fs::read(&sentinel).unwrap(), SENTINEL);
    }

    // ---------------------------------------------------------------- SEC-07

    fn sha256_hex(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(data))
    }

    /// Serve a registry entry for `demo` 1.2.0 whose checksum is `sha` and
    /// whose artifact is `artifact` (or a 404 when `None`).
    fn registry<'a>(
        server: &'a MockServer,
        sha: &str,
        artifact: Option<&[u8]>,
    ) -> (httpmock::Mock<'a>, httpmock::Mock<'a>) {
        let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
        let entry = serde_json::json!({
            "plugin_id": "demo",
            "versions": { "1.2.0": {
                "name": "demo", "version": "1.2.0", "description": null, "author": null,
                "license": null, "homepage": null, "repository": null, "keywords": null,
                "platforms": { platform: {
                    "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
                    "bin": "demo.tar.gz", "sha256": sha
                }}
            }}
        });
        let index = server.mock(|when, then| {
            when.method(GET).path("/v1/plugins/demo");
            then.status(200)
                .header("content-type", "application/json")
                .body(entry.to_string());
        });
        let art = server.mock(|when, then| {
            when.method(GET)
                .path("/v1/artifacts/demo/1.2.0/demo.tar.gz");
            match artifact {
                Some(data) => then.status(200).body(data),
                None => then.status(404),
            };
        });
        (index, art)
    }

    struct LoopbackHttp;
    impl LoopbackHttp {
        fn on() -> Self {
            allow_loopback_http_for_tests(true);
            LoopbackHttp
        }
    }
    impl Drop for LoopbackHttp {
        fn drop(&mut self) {
            allow_loopback_http_for_tests(false);
        }
    }

    fn reg(server: &MockServer) -> SourceSpec {
        SourceSpec::Registry {
            url: server.base_url(),
        }
    }

    #[test]
    fn plain_http_transport_is_refused_and_never_contacted() {
        use super::super::registry::require_https;
        assert!(require_https("https://plugins.example.org").is_ok());
        assert!(require_https("https://plugins.example.org:8443/x").is_ok());
        for bad in [
            "http://plugins.example.org",
            "http://127.0.0.1:1/",
            "ftp://h/x",
            "file:///etc/passwd",
            "https://",
            "HTTPS",
        ] {
            assert!(require_https(bad).is_err(), "{bad} accepted");
        }

        // Without the test seam, a plain-HTTP registry or URL is refused
        // before any request reaches the server, in dry run too.
        let server = MockServer::start();
        let data = valid_artifact();
        let (index, art) = registry(&server, &sha256_hex(&data), Some(&data));
        let direct = server.mock(|when, then| {
            when.method(GET).path("/direct.tar.gz");
            then.status(200).body(&data);
        });
        let (dir, _s, mut engine) = setup();
        for dry_run in [true, false] {
            let env = engine.run_plugin_op(args(reg(&server), VerifyMode::Sha256, false, dry_run));
            assert!(!env.ok);
            assert!(
                env.error.as_ref().unwrap().message.contains("https"),
                "{:?}",
                env.error
            );
            let url = SourceSpec::Url {
                url: server.url("/direct.tar.gz"),
            };
            let env = engine.run_plugin_op(args(url, VerifyMode::None, false, dry_run));
            assert!(!env.ok, "http url source accepted with verify=none");
        }
        assert!(
            engine
                .registry_client
                .download_artifact(&server.url("/direct.tar.gz"))
                .is_err()
        );
        assert_eq!(
            index.hits() + art.hits() + direct.hits(),
            0,
            "plain HTTP was contacted"
        );
        nothing_installed(&dir);
    }

    #[test]
    fn valid_checksum_installs() {
        let _http = LoopbackHttp::on();
        let server = MockServer::start();
        let data = valid_artifact();
        let (_index, art) = registry(&server, &sha256_hex(&data).to_uppercase(), Some(&data));
        let (dir, _s, mut engine) = setup();
        let env = engine.run_plugin_op(args(reg(&server), VerifyMode::Sha256, false, false));
        assert!(env.ok, "{:?}", env.error.as_ref().map(|e| &e.message));
        assert_eq!(art.hits(), 1);
        assert!(
            env.actions
                .iter()
                .any(|a| a.name == "Checksum verified successfully")
        );
        assert!(
            dir.path()
                .join("plugins/demo/versions/1.2.0/bin/plugin")
                .is_file()
        );
    }

    #[test]
    fn missing_or_malformed_checksum_fails_before_download() {
        let _http = LoopbackHttp::on();
        let data = valid_artifact();
        let short = sha256_hex(&data)[..63].to_string();
        let non_hex = "z".repeat(64);
        for sha in ["", "   ", "00", short.as_str(), non_hex.as_str()] {
            for dry_run in [true, false] {
                let server = MockServer::start();
                let (_index, art) = registry(&server, sha, Some(&data));
                let (dir, _s, mut engine) = setup();
                let env =
                    engine.run_plugin_op(args(reg(&server), VerifyMode::Sha256, false, dry_run));
                assert!(!env.ok, "checksum {sha:?} accepted (dry_run={dry_run})");
                assert!(
                    env.error
                        .as_ref()
                        .unwrap()
                        .message
                        .contains(error_codes::PLUGIN_VERIFY_FAILED),
                    "{:?}",
                    env.error
                );
                assert_eq!(
                    art.hits(),
                    0,
                    "artifact downloaded despite unusable checksum {sha:?}"
                );
                nothing_installed(&dir);
            }
        }
    }

    #[test]
    fn mismatched_checksum_downloads_but_never_extracts_or_installs() {
        let _http = LoopbackHttp::on();
        let server = MockServer::start();
        let data = valid_artifact();
        let (_index, art) = registry(&server, &sha256_hex(b"something else"), Some(&data));
        let (dir, _s, mut engine) = setup();
        let env = engine.run_plugin_op(args(reg(&server), VerifyMode::Sha256, false, false));
        assert!(!env.ok);
        assert!(
            env.error
                .as_ref()
                .unwrap()
                .message
                .contains("Checksum verification failed"),
            "{:?}",
            env.error
        );
        assert_eq!(art.hits(), 1);
        assert!(
            !env.actions
                .iter()
                .any(|a| a.action_type == action_types::EXTRACT
                    || a.action_type == action_types::INSTALL)
        );
        nothing_installed(&dir);
    }

    #[test]
    fn download_failure_installs_nothing() {
        let _http = LoopbackHttp::on();
        let server = MockServer::start();
        let data = valid_artifact();
        let (_index, art) = registry(&server, &sha256_hex(&data), None);
        let (dir, _s, mut engine) = setup();
        let env = engine.run_plugin_op(args(reg(&server), VerifyMode::Sha256, false, false));
        assert!(!env.ok);
        assert!(
            env.error
                .as_ref()
                .unwrap()
                .message
                .contains(error_codes::PLUGIN_DOWNLOAD_FAILED),
            "{:?}",
            env.error
        );
        assert_eq!(art.hits(), 1);
        nothing_installed(&dir);
    }

    #[test]
    fn url_source_needs_explicit_verify_none() {
        let _http = LoopbackHttp::on();
        let server = MockServer::start();
        let data = valid_artifact();
        let direct = server.mock(|when, then| {
            when.method(GET).path("/demo.tar.gz");
            then.status(200).body(&data);
        });
        let (dir, _s, mut engine) = setup();
        let url = || SourceSpec::Url {
            url: server.url("/demo.tar.gz"),
        };
        let env = engine.run_plugin_op(args(url(), VerifyMode::Sha256, false, false));
        assert!(
            !env.ok,
            "unverifiable url artifact accepted under verify=sha256"
        );
        assert!(
            env.error.as_ref().unwrap().message.contains("verify=none"),
            "{:?}",
            env.error
        );
        assert_eq!(direct.hits(), 0);
        nothing_installed(&dir);

        // The documented opt-out still works (and SEC-06 still applies to it)
        let env = engine.run_plugin_op(args(url(), VerifyMode::None, false, false));
        assert!(env.ok, "{:?}", env.error.as_ref().map(|e| &e.message));
        assert_eq!(direct.hits(), 1);
    }

    #[test]
    fn verify_checksum_parses_strictly() {
        use super::super::registry::parse_sha256;
        let client = RegistryClient::new(1000).unwrap();
        let sum = sha256_hex(b"abc");
        assert!(client.verify_checksum(b"abc", &sum).is_ok());
        assert!(client.verify_checksum(b"abc", &sum.to_uppercase()).is_ok());
        assert!(client.verify_checksum(b"abd", &sum).is_err());
        assert!(client.verify_checksum(b"abc", &format!(" {sum}")).is_err());
        assert!(client.verify_checksum(b"abc", "").is_err());
        assert!(parse_sha256(&sum[..62]).is_err());
        assert!(parse_sha256(&format!("{sum}0")).is_err());
    }
}
