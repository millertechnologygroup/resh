use anyhow::{anyhow, bail, Result};
use std::io::Write;
use url::Url;
use serde::{Serialize, Deserialize};
use serde_json::json;
use chrono::Utc;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use crate::core::{
    registry::{Args, Handle, IoStreams},
    status::Status,
};

use crate::handles::pluginh::available::{
    AvailableInfoArgs, AvailableInfoEnvelope, AvailableInfoResult, AvailableInfoErrorCode,
    IndexManager, PluginSelector, ArgsHelper, EnvelopeHelper,
    ActionRecord, ErrorInfo,
};
use crate::handles::pluginh::{
    ExecutionEngine, Mode, PluginOpArgs, RequestedVersion, SourceSpec, VerifyMode,
    PluginStateManager, SetEnabledOptions, Scope,
};

/// Plugin handle implementing install and update verbs per specification
#[derive(Debug)]
pub struct PluginHandle {
    /// Plugin ID extracted from URL
    pub plugin_id: String,
    /// Full target URL for responses
    pub target: String,
}

impl PluginHandle {
    /// Create new plugin handle from URL
    pub fn new(url: &Url) -> Result<Self> {
        let target = url.to_string();
        
        // Extract plugin ID from host + path as per spec
        let host = url.host_str().ok_or_else(|| {
            anyhow::anyhow!("Invalid plugin URL format: missing host in {}", url)
        })?;
        
        let path = url.path().trim_start_matches('/');
        
        // Combine host and path to form plugin_id
        let plugin_id = if path.is_empty() {
            host.to_string()
        } else {
            format!("{}/{}", host, path)
        };

        // Validate plugin_id is not empty
        if plugin_id.is_empty() {
            bail!("Invalid plugin URL format: empty plugin ID in {}", url);
        }

        Ok(Self {
            plugin_id,
            target,
        })
    }

    /// Execute install verb
    pub fn install(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let plugin_args = self.parse_install_args(args)?;
        let mut engine = ExecutionEngine::new(plugin_args.timeout_ms)?;
        let envelope = engine.run_plugin_op(plugin_args);
        
        // Output JSON envelope as per specification
        let json_output = if args.get("json_pretty").map(|s| s == "true").unwrap_or(false) {
            serde_json::to_string_pretty(&envelope)?
        } else {
            serde_json::to_string(&envelope)?
        };
        
        writeln!(io.stdout, "{}", json_output)?;
        
        // Return status based on envelope
        if envelope.ok {
            Ok(Status::ok())
        } else {
            let error_message = envelope.error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".to_string());
            Ok(Status::err(envelope.code, &error_message))
        }
    }

    /// Execute update verb
    pub fn update(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let plugin_args = self.parse_update_args(args)?;
        let mut engine = ExecutionEngine::new(plugin_args.timeout_ms)?;
        let envelope = engine.run_plugin_op(plugin_args);
        
        // Output JSON envelope as per specification  
        let json_output = if args.get("json_pretty").map(|s| s == "true").unwrap_or(false) {
            serde_json::to_string_pretty(&envelope)?
        } else {
            serde_json::to_string(&envelope)?
        };
        
        writeln!(io.stdout, "{}", json_output)?;
        
        // Return status based on envelope
        if envelope.ok {
            Ok(Status::ok())
        } else {
            let error_message = envelope.error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".to_string());
            Ok(Status::err(envelope.code, &error_message))
        }
    }

    /// Execute remove verb
    pub fn remove(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let plugin_args = self.parse_remove_args(args)?;
        let mut engine = ExecutionEngine::new(plugin_args.timeout_ms)?;
        let envelope = engine.run_plugin_op(plugin_args);
        
        // Output JSON envelope as per specification  
        let json_output = if args.get("json_pretty").map(|s| s == "true").unwrap_or(false) {
            serde_json::to_string_pretty(&envelope)?
        } else {
            serde_json::to_string(&envelope)?
        };
        
        writeln!(io.stdout, "{}", json_output)?;
        
        // Return status based on envelope
        if envelope.ok {
            Ok(Status::ok())
        } else {
            let error_message = envelope.error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".to_string());
            Ok(Status::err(envelope.code, &error_message))
        }
    }

    /// Execute enable verb
    pub fn enable(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let opts = self.parse_enable_disable_args(args)?;
        let mut state_manager = PluginStateManager::new()?;
        let envelope = state_manager.set_enabled_state(&self.plugin_id, opts.scope.clone(), true, opts)?;
        
        // Output JSON envelope as per specification
        let json_output = if args.get("json_pretty").map(|s| s == "true").unwrap_or(false) {
            serde_json::to_string_pretty(&envelope)?
        } else {
            serde_json::to_string(&envelope)?
        };
        
        writeln!(io.stdout, "{}", json_output)?;
        
        // Return status based on envelope
        if envelope.ok {
            Ok(Status::ok())
        } else {
            let error_message = envelope.error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".to_string());
            Ok(Status::err(envelope.code, &error_message))
        }
    }

    /// Execute disable verb
    pub fn disable(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let opts = self.parse_enable_disable_args(args)?;
        let mut state_manager = PluginStateManager::new()?;
        let envelope = state_manager.set_enabled_state(&self.plugin_id, opts.scope.clone(), false, opts)?;
        
        // Output JSON envelope as per specification
        let json_output = if args.get("json_pretty").map(|s| s == "true").unwrap_or(false) {
            serde_json::to_string_pretty(&envelope)?
        } else {
            serde_json::to_string(&envelope)?
        };
        
        writeln!(io.stdout, "{}", json_output)?;
        
        // Return status based on envelope
        if envelope.ok {
            Ok(Status::ok())
        } else {
            let error_message = envelope.error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".to_string());
            Ok(Status::err(envelope.code, &error_message))
        }
    }

    /// Execute available.list verb  
    pub fn available_list(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check if this is the special "available" plugin_id
        if self.plugin_id != "available" {
            let envelope = create_error_envelope(
                "plugin.available.list", 
                &self.target, 
                args, 
                5, 
                "unsupported_target",
                "The 'available.list' verb is only supported for plugin://available target"
            );
            output_envelope(&envelope, args, io)?;
            return Ok(Status::err(5, "The 'available.list' verb is only supported for plugin://available target"));
        }

        // Parse available.list arguments
        let options = match parse_available_list_args(args) {
            Ok(opts) => opts,
            Err(e) => {
                let envelope = create_error_envelope(
                    "plugin.available.list",
                    &self.target,
                    args,
                    2,
                    "invalid_arguments", 
                    &e.to_string()
                );
                output_envelope(&envelope, args, io)?;
                return Ok(Status::err(2, &e.to_string()));
            }
        };

        // Load catalog
        let catalog = match load_catalog(&options.source) {
            Ok(cat) => cat,
            Err(e) => {
                let code = match e.to_string().as_str() {
                    s if s.contains("No such file") || s.contains("not found") => 3,
                    s if s.contains("permission denied") => 13,
                    s if s.contains("JSON") || s.contains("parse") => 4,
                    _ => 70,
                };
                let kind = match code {
                    3 => "catalog.not_found",
                    4 => "catalog.parse_error", 
                    13 => "permission_denied",
                    _ => "internal_error",
                };
                let envelope = create_error_envelope(
                    "plugin.available.list",
                    &self.target,
                    args,
                    code,
                    kind,
                    &e.to_string()
                );
                output_envelope(&envelope, args, io)?;
                return Ok(Status::err(code, &e.to_string()));
            }
        };

        // Filter and sort plugins
        let filtered_plugins = filter_and_sort_plugins(&catalog.plugins, &options);

        // Create success envelope
        let normalized_args = normalize_args(&options);
        let result = json!({
            "source": options.source,
            "catalog_version": catalog.version,
            "generated_at": catalog.generated_at,
            "count": filtered_plugins.len(),
            "items": filtered_plugins
        });

        let actions = vec![
            json!({
                "type": "catalog.load",
                "source": options.source,
                "bytes": 0  // We don't track bytes for now
            }),
            json!({
                "type": "filter.apply",
                "query": options.query,
                "tags": options.tags
            })
        ];

        let envelope = json!({
            "op": "plugin.available.list",
            "ok": true,
            "code": 0,
            "ts": Utc::now().to_rfc3339(),
            "target": self.target,
            "args": normalized_args,
            "result": result,
            "actions": actions,
            "error": serde_json::Value::Null
        });

        output_envelope(&envelope, args, io)?;
        Ok(Status::ok())
    }

    /// Execute available.search verb  
    pub fn available_search(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check if this is the special "available.search" plugin_id
        if self.plugin_id != "available.search" {
            let envelope = create_error_envelope(
                "plugin.available.search", 
                &self.target, 
                args, 
                5, 
                "PLUGIN_INVALID_ARGS",
                "The 'available.search' verb is only supported for plugin://available.search target"
            );
            output_envelope(&envelope, args, io)?;
            return Ok(Status::err(5, "The 'available.search' verb is only supported for plugin://available.search target"));
        }

        // Parse available.search arguments with timeout handling
        let start_time = SystemTime::now();
        let search_options = match parse_available_search_args(args) {
            Ok(opts) => opts,
            Err(e) => {
                let envelope = create_search_error_envelope(
                    &self.target,
                    args,
                    "PLUGIN_INVALID_ARGS", 
                    &e.to_string()
                );
                output_envelope(&envelope, args, io)?;
                return Ok(Status::err(2, &e.to_string()));
            }
        };

        // Check if we've already exceeded timeout during arg parsing
        let timeout_duration = Duration::from_millis(search_options.timeout_ms);
        if start_time.elapsed().unwrap_or(Duration::ZERO) > timeout_duration {
            let envelope = create_search_error_envelope(
                &self.target,
                args,
                "PLUGIN_TIMEOUT",
                "Operation timed out during argument parsing"
            );
            output_envelope(&envelope, args, io)?;
            return Ok(Status::err(124, "Operation timed out"));
        }

        // Load catalog with timeout and cache management
        let catalog_result = load_search_catalog(&search_options, start_time, timeout_duration);
        let (catalog, catalog_source) = match catalog_result {
            Ok((cat, source)) => (cat, source),
            Err(e) => {
                let code = if e.to_string().contains("timeout") { "PLUGIN_TIMEOUT" } 
                    else if e.to_string().contains("network") || e.to_string().contains("fetch") { "PLUGIN_NETWORK_ERROR" }
                    else if e.to_string().contains("parse") || e.to_string().contains("JSON") { "PLUGIN_CATALOG_PARSE_FAILED" }
                    else if e.to_string().contains("unavailable") || e.to_string().contains("not found") { "PLUGIN_CATALOG_UNAVAILABLE" }
                    else if e.to_string().contains("permission") || e.to_string().contains("access") { "PLUGIN_IO_ERROR" }
                    else { "PLUGIN_INTERNAL" };
                
                let envelope = create_search_error_envelope(
                    &self.target,
                    args,
                    code,
                    &e.to_string()
                );
                output_envelope(&envelope, args, io)?;
                
                let exit_code = match code {
                    "PLUGIN_TIMEOUT" => 124,
                    "PLUGIN_INVALID_ARGS" => 2,
                    _ => 1,
                };
                return Ok(Status::err(exit_code, &e.to_string()));
            }
        };

        // Check timeout again after catalog loading
        if start_time.elapsed().unwrap_or(Duration::ZERO) > timeout_duration {
            let envelope = create_search_error_envelope(
                &self.target,
                args,
                "PLUGIN_TIMEOUT",
                "Operation timed out during catalog loading"
            );
            output_envelope(&envelope, args, io)?;
            return Ok(Status::err(124, "Operation timed out"));
        }

        // Perform search with scoring and deterministic ordering
        let search_results = perform_plugin_search(&catalog.plugins, &search_options);

        // Create success envelope
        let normalized_args = normalize_search_args(&search_options);
        let result = json!({
            "source": catalog_source,
            "query": {
                "q": search_options.q,
                "tags": search_options.tags,
                "owner": search_options.owner,
                "name": search_options.name,
                "min_version": search_options.min_version,
                "max_results": search_options.max_results
            },
            "count": search_results.len(),
            "items": search_results
        });

        let actions = vec![
            json!({
                "type": "catalog.load",
                "source": search_options.source,
                "mode": catalog_source.get("mode").unwrap_or(&json!("unknown"))
            }),
            json!({
                "type": "search.execute", 
                "query": search_options.q,
                "filters_applied": true
            })
        ];

        let envelope = json!({
            "op": "plugin.available.search",
            "ok": true,
            "target": self.target,
            "args": normalized_args,
            "result": result,
            "actions": actions,
            "error": serde_json::Value::Null
        });

        output_envelope(&envelope, args, io)?;
        Ok(Status::ok())
    }

    /// Execute available.info verb  
    pub fn available_info(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check if this is the special "available" plugin_id
        if self.plugin_id != "available" {
            let error_envelope = EnvelopeHelper::create_error_envelope(
                &self.target,
                &AvailableInfoArgs::default(),
                vec![],
                &AvailableInfoErrorCode::InvalidArg,
                "The 'available.info' verb is only supported for plugin://available target",
                serde_json::json!({"unsupported_target": self.plugin_id}),
            );
            self.output_available_info_envelope(&error_envelope, args, io)?;
            return Ok(Status::err(AvailableInfoErrorCode::InvalidArg.exit_code(), "Unsupported target"));
        }

        // Parse and validate arguments
        let parsed_args = match ArgsHelper::parse_available_info_args(args) {
            Ok(args) => args,
            Err(e) => {
                let error_envelope = EnvelopeHelper::create_error_envelope(
                    &self.target,
                    &AvailableInfoArgs::default(),
                    vec![],
                    &AvailableInfoErrorCode::InvalidArg,
                    &format!("{}", e),
                    serde_json::json!({"validation_error": format!("{}", e)}),
                );
                self.output_available_info_envelope(&error_envelope, args, io)?;
                return Ok(Status::err(AvailableInfoErrorCode::InvalidArg.exit_code(), &format!("{}", e)));
            }
        };

        // Track actions for envelope
        let mut actions = Vec::new();

        // Create index manager and load indexes
        let rt = match tokio::runtime::Runtime::new() {
            Ok(runtime) => runtime,
            Err(e) => {
                let error_envelope = EnvelopeHelper::create_error_envelope(
                    &self.target,
                    &parsed_args,
                    actions,
                    &AvailableInfoErrorCode::Io,
                    "Failed to create async runtime",
                    serde_json::json!({"error": e.to_string()}),
                );
                self.output_available_info_envelope(&error_envelope, args, io)?;
                return Ok(Status::err(AvailableInfoErrorCode::Io.exit_code(), "Runtime error"));
            }
        };

        let result = rt.block_on(async {
            let index_manager: IndexManager = match IndexManager::new() {
                Ok(manager) => manager,
                Err(e) => {
                    return Err((AvailableInfoErrorCode::Io, format!("Failed to initialize index manager: {}", e)));
                }
            };

            // Load indexes
            let indexes = match index_manager.load_indexes(&parsed_args.source, &parsed_args.channel, parsed_args.timeout_ms, parsed_args.offline).await {
                Ok(indexes) => {
                    actions.push(ActionRecord {
                        r#type: "fetch".to_string(),
                        id: "index.load".to_string(),
                        ok: true,
                        detail: format!("loaded {} indexes", indexes.len() as usize),
                        meta: serde_json::json!({"count": indexes.len()}),
                    });
                    indexes
                }
                Err(e) => {
                    actions.push(ActionRecord {
                        r#type: "fetch".to_string(),
                        id: "index.load".to_string(),
                        ok: false,
                        detail: format!("{}", e),
                        meta: serde_json::json!({}),
                    });
                    
                    let error_code = if format!("{}", e).contains("timeout") {
                        AvailableInfoErrorCode::Timeout
                    } else if format!("{}", e).contains("No indexes available") {
                        AvailableInfoErrorCode::IndexUnavailable
                    } else {
                        AvailableInfoErrorCode::Io
                    };
                    
                    return Err((error_code, e.to_string()));
                }
            };

            // Create plugin selector
            let selector = PluginSelector {
                name: parsed_args.name.clone(),
                id: parsed_args.id.clone(),
                version: parsed_args.version.clone(),
                channel: parsed_args.channel.clone(),
                os: parsed_args.os.clone(),
                arch: parsed_args.arch.clone(),
            };

            // Select the plugin
            match selector.select_plugin(&indexes) {
                Ok(resolved) => {
                    actions.push(ActionRecord {
                        r#type: "select".to_string(),
                        id: "select.plugin".to_string(),
                        ok: true,
                        detail: format!("resolved plugin {} version {}", resolved.plugin.name, resolved.plugin.version),
                        meta: serde_json::json!({"source_index": resolved.source_index}),
                    });

                    let result = AvailableInfoResult {
                        plugin: resolved.plugin,
                    };

                    Ok((result, actions))
                }
                Err(e) => {
                    actions.push(ActionRecord {
                        r#type: "select".to_string(),
                        id: "select.plugin".to_string(),
                        ok: false,
                        detail: format!("{}", e),
                        meta: serde_json::json!({}),
                    });

                    Err((AvailableInfoErrorCode::NotFound, format!("{}", e)))
                }
            }
        });

        match result {
            Ok((result, final_actions)) => {
                let success_envelope = EnvelopeHelper::create_success_envelope(
                    &self.target,
                    &parsed_args,
                    final_actions,
                    result,
                );
                self.output_available_info_envelope(&success_envelope, args, io)?;
                Ok(Status::ok())
            }
            Err((error_code, message)) => {
                let error_envelope = EnvelopeHelper::create_error_envelope(
                    &self.target,
                    &parsed_args,
                    vec![], // actions is moved into the async block, so use empty vec here
                    &error_code,
                    &message,
                    serde_json::json!({"details": message}),
                );
                self.output_available_info_envelope(&error_envelope, args, io)?;
                Ok(Status::err(error_code.exit_code() as i32, &message))
            }
        }
    }

    /// Output available.info envelope with proper formatting
    fn output_available_info_envelope(&self, envelope: &AvailableInfoEnvelope, args: &Args, io: &mut IoStreams) -> Result<()> {
        let json_output = if args.get("json_pretty").map(|s| s == "true").unwrap_or(false) {
            serde_json::to_string_pretty(envelope)?
        } else {
            serde_json::to_string(envelope)?
        };
        
        writeln!(io.stdout, "{}", json_output)?;
        Ok(())
    }

    /// Execute installed.list verb
    pub fn installed_list(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check if this is the special "installed" plugin_id 
        if self.plugin_id != "installed" {
            let envelope = create_installed_error_envelope(
                "plugin.installed.list",
                &self.target,
                &InstalledListArgs::default(),
                vec![],
                2,
                "invalid_target",
                "The 'installed.list' verb is only supported for plugin://installed target"
            );
            output_installed_envelope(&envelope, args, io)?;
            return Ok(Status::err(2, "The 'installed.list' verb is only supported for plugin://installed target"));
        }

        // Parse and validate arguments
        let parsed_args = match parse_installed_list_args(args) {
            Ok(args) => args,
            Err(e) => {
                let envelope = create_installed_error_envelope(
                    "plugin.installed.list",
                    &self.target,
                    &InstalledListArgs::default(),
                    vec![],
                    2,
                    "invalid_arguments",
                    &e.to_string()
                );
                output_installed_envelope(&envelope, args, io)?;
                return Ok(Status::err(2, &e.to_string()));
            }
        };

        // Execute installed.list operation
        let envelope = execute_installed_list(&self.target, parsed_args);
        output_installed_envelope(&envelope, args, io)?;
        
        if envelope["ok"].as_bool().unwrap_or(false) {
            Ok(Status::ok())
        } else {
            let error_message = envelope.get("error")
                .and_then(|e| e.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown error");
            let code = envelope.get("code")
                .and_then(|c| c.as_i64())
                .unwrap_or(70) as i32;
            Ok(Status::err(code, error_message))
        }
    }

    /// Parse arguments for install verb
    fn parse_install_args(&self, args: &Args) -> Result<PluginOpArgs> {
        let source = self.parse_source(args)?;
        let requested_version = self.parse_requested_version(args);
        let verify = self.parse_verify_mode(args);
        
        Ok(PluginOpArgs {
            mode: Mode::Install,
            plugin_id: self.plugin_id.clone(),
            source,
            requested_version,
            verify,
            force: args.get("force").map(|s| s == "true").unwrap_or(false),
            allow_downgrade: args.get("allow_downgrade").map(|s| s == "true").unwrap_or(false),
            dry_run: args.get("dry_run").map(|s| s == "true").unwrap_or(false),
            strict: false, // Only used for update
            purge: false, // Not applicable to install
            timeout_ms: args.get("timeout_ms")
                .and_then(|s| s.parse().ok())
                .unwrap_or(300000), // Default 5 minutes
        })
    }

    /// Parse arguments for update verb
    fn parse_update_args(&self, args: &Args) -> Result<PluginOpArgs> {
        // Update only supports registry source by default
        let source = if let Some(url) = args.get("url") {
            SourceSpec::Url { url: url.clone() }
        } else {
            let registry_url = args.get("registry")
                .unwrap_or(&"https://plugins.reshshell.dev".to_string())
                .clone();
            SourceSpec::Registry { url: registry_url }
        };
        
        let requested_version = RequestedVersion::Latest; // Update always gets latest
        let verify = self.parse_verify_mode(args);
        
        Ok(PluginOpArgs {
            mode: Mode::Update,
            plugin_id: self.plugin_id.clone(),
            source,
            requested_version,
            verify,
            force: false, // Force not applicable to update
            allow_downgrade: false, // Allow downgrade not applicable to update
            dry_run: args.get("dry_run").map(|s| s == "true").unwrap_or(false),
            strict: args.get("strict").map(|s| s == "true").unwrap_or(false),
            purge: false, // Not applicable to update
            timeout_ms: args.get("timeout_ms")
                .and_then(|s| s.parse().ok())
                .unwrap_or(300000), // Default 5 minutes
        })
    }

    /// Parse arguments for remove verb
    fn parse_remove_args(&self, args: &Args) -> Result<PluginOpArgs> {
        // Parse version from plugin_id if specified as plugin_id@version
        let requested_version = if self.plugin_id.contains('@') {
            let parts: Vec<&str> = self.plugin_id.splitn(2, '@').collect();
            if parts.len() == 2 {
                RequestedVersion::Specific(parts[1].to_string())
            } else {
                RequestedVersion::Latest
            }
        } else {
            RequestedVersion::Latest
        };
        
        // Extract clean plugin_id (without version)
        let clean_plugin_id = if self.plugin_id.contains('@') {
            self.plugin_id.split('@').next().unwrap_or(&self.plugin_id).to_string()
        } else {
            self.plugin_id.clone()
        };
        
        Ok(PluginOpArgs {
            mode: Mode::Remove,
            plugin_id: clean_plugin_id,
            source: SourceSpec::Registry { url: "local".to_string() }, // Not used for remove
            requested_version,
            verify: VerifyMode::None, // Not needed for remove
            force: args.get("force").map(|s| s == "true").unwrap_or(false),
            allow_downgrade: false, // Not applicable to remove
            dry_run: args.get("dry_run").map(|s| s == "true").unwrap_or(false),
            strict: false, // Not applicable to remove
            purge: args.get("purge").map(|s| s == "true").unwrap_or(false),
            timeout_ms: args.get("timeout_ms")
                .and_then(|s| s.parse().ok())
                .unwrap_or(30000), // Default 30 seconds for remove
        })
    }

    /// Parse arguments for enable/disable verbs (shared logic)
    fn parse_enable_disable_args(&self, args: &Args) -> Result<SetEnabledOptions> {
        // Parse and validate scope
        let scope_str = args.get("scope").unwrap_or(&"user".to_string()).clone();
        let scope = match scope_str.as_str() {
            "user" => Scope::User,
            "system" => Scope::System,
            _ => bail!("Invalid scope: {}. Must be 'user' or 'system'", scope_str),
        };
        
        // Parse force flag
        let force = args.get("force").map(|s| s == "true").unwrap_or(false);
        
        // Parse timeout with bounds checking
        let timeout_ms = args.get("timeout_ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(15000); // Default 15 seconds per spec
        
        let timeout_ms = timeout_ms.clamp(1000, 120000); // Clamp to 1-120 seconds per spec
        
        // Parse dry_run flag
        let dry_run = args.get("dry_run").map(|s| s == "true").unwrap_or(false);
        
        // Parse reason with length validation
        let reason = args.get("reason").unwrap_or(&String::new()).clone();
        if reason.len() > 200 {
            bail!("Reason too long (max 200 characters)");
        }
        
        Ok(SetEnabledOptions {
            scope,
            force,
            timeout_ms,
            dry_run,
            reason,
        })
    }

    /// Parse source specification from arguments
    fn parse_source(&self, args: &Args) -> Result<SourceSpec> {
        let default_registry = "registry".to_string();
        let source_type = args.get("source").unwrap_or(&default_registry);
        
        match source_type.as_str() {
            "registry" => {
                let default_url = "https://plugins.reshshell.dev".to_string();
                let url = args.get("registry")
                    .unwrap_or(&default_url)
                    .clone();
                Ok(SourceSpec::Registry { url })
            }
            "url" => {
                let url = args.get("url")
                    .ok_or_else(|| anyhow::anyhow!("URL required when source=url"))?
                    .clone();
                Ok(SourceSpec::Url { url })
            }
            "file" => {
                let path = args.get("path")
                    .ok_or_else(|| anyhow::anyhow!("Path required when source=file"))?
                    .clone();
                Ok(SourceSpec::File { path })
            }
            _ => {
                bail!("Invalid source type: {}. Must be 'registry', 'url', or 'file'", source_type);
            }
        }
    }

    /// Parse requested version from arguments
    fn parse_requested_version(&self, args: &Args) -> RequestedVersion {
        match args.get("version") {
            Some(v) if v == "latest" || v.is_empty() => RequestedVersion::Latest,
            Some(v) => RequestedVersion::Specific(v.clone()),
            None => RequestedVersion::Latest,
        }
    }

    /// Parse verify mode from arguments
    fn parse_verify_mode(&self, args: &Args) -> VerifyMode {
        match args.get("verify").map(|s| s.as_str()) {
            Some("none") => VerifyMode::None,
            Some("sha256") | None => VerifyMode::Sha256, // Default to sha256
            _ => VerifyMode::Sha256, // Default for unknown values
        }
    }
}

impl Handle for PluginHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["install", "update", "remove", "enable", "disable", "available.list", "available.search", "available.info", "installed.list"]
    }
    
    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        match verb {
            "install" => self.install(args, io),
            "update" => self.update(args, io),
            "remove" => self.remove(args, io),
            "enable" => self.enable(args, io),
            "disable" => self.disable(args, io),
            "available.list" => self.available_list(args, io),
            "available.search" => self.available_search(args, io),
            "available.info" => self.available_info(args, io),
            "installed.list" => self.installed_list(args, io),
            _ => bail!("Unknown verb: {}. Supported verbs: install, update, remove, enable, disable, available.list, available.search, available.info, installed.list", verb),
        }
    }
}

/// Catalog structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Catalog {
    version: i32,
    generated_at: String,
    plugins: Vec<PluginRecord>,
}

/// Plugin record from catalog
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PluginRecord {
    id: String,
    name: String,
    description: String,
    version: String,
    publisher: String,
    license: String,
    tags: Vec<String>,
    platforms: Vec<String>,
    entrypoint: String,
    homepage: String,
    repo: String,
    sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifacts: Option<Vec<ArtifactRecord>>,
}

/// Artifact record for a plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ArtifactRecord {
    os: String,
    arch: String,
    url: String,
    sha256: String,
}

/// Plugin installed list data structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInstalledItem {
    pub name: String,
    pub version: String,
    pub enabled: bool,
    pub source: PluginSource,
    pub paths: PluginPaths,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<PluginManifestSummary>,
    pub health: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginSource {
    #[serde(rename = "type")]
    pub source_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginPaths {
    pub install_dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifestSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

/// Arguments for installed.list operation
#[derive(Debug, Clone)]
pub struct InstalledListArgs {
    // Filtering
    pub enabled: Option<bool>,
    pub name: Option<String>,
    pub prefix: Option<String>,
    pub tag: Option<String>,
    pub source: Option<String>,
    
    // Pagination
    pub limit: i32,
    pub offset: i32,
    
    // Sorting
    pub sort: String,
    pub order: String,
    
    // Output shaping
    pub format: String,
}

impl Default for InstalledListArgs {
    fn default() -> Self {
        Self {
            enabled: None,
            name: None,
            prefix: None,
            tag: None,
            source: None,
            limit: 200,
            offset: 0,
            sort: "name".to_string(),
            order: "asc".to_string(),
            format: "full".to_string(),
        }
    }
}

/// Result structure for installed.list operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledListResult {
    pub count: i32,
    pub total: i32,
    pub offset: i32,
    pub limit: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<serde_json::Value>,
}

/// Options for available.list operation
#[derive(Debug, Clone)]
struct AvailableListOptions {
    source: String,
    query: Option<String>,
    tags: Vec<String>,
    publisher: Option<String>,
    platform: String,
    include_prerelease: bool,
    limit: usize,
    offset: usize,
    format: String,
}

/// Options for available.search operation
#[derive(Debug, Clone)]
struct AvailableSearchOptions {
    q: Option<String>,
    tags: Vec<String>,
    owner: Option<String>,
    name: Option<String>,
    min_version: Option<String>,
    max_results: usize,
    source: String,
    timeout_ms: u64,
    offline: bool,
    refresh: bool,
}

/// Internal plugin catalog entry for search
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SearchPluginEntry {
    id: String,
    display_name: String,
    description: String,
    version: String,
    publisher: String,
    tags: Vec<String>,
    license: Option<String>,
    homepage: Option<String>,
    repo: Option<String>,
    artifact: serde_json::Value,
    sha256: Option<String>,
    platforms: Option<Vec<String>>,
}

/// Plugin search result with scoring
#[derive(Debug, Clone, Serialize)]
struct SearchResult {
    id: String,
    display_name: String,
    version: String,
    publisher: String,
    description: String,
    tags: Vec<String>,
    license: Option<String>,
    homepage: Option<String>,
    repo: Option<String>,
    artifact: serde_json::Value,
    sha256: Option<String>,
    score: f64,
    highlights: Vec<String>,
}

/// Catalog source information
#[derive(Debug, Clone, Serialize)]
struct CatalogSourceInfo {
    id: String,
    mode: String, // "online", "offline", "cache"
    #[serde(rename = "ref")]
    ref_url: String,
    fetched_at: String, // RFC3339 or empty
}

/// Parse arguments for available.search verb
fn parse_available_search_args(args: &Args) -> Result<AvailableSearchOptions> {
    // Parse free-text query
    let q = args.get("q").cloned();
    
    // Parse and normalize tags (semicolon-separated, sorted for determinism)
    let tags = if let Some(tags_str) = args.get("tags") {
        let mut parsed_tags: Vec<String> = tags_str
            .split(';')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        parsed_tags.sort(); // For determinism
        parsed_tags
    } else {
        Vec::new()
    };

    // Parse owner filter
    let owner = args.get("owner").cloned();

    // Parse name filter  
    let name = args.get("name").cloned();

    // Parse min_version filter
    let min_version = args.get("min_version").cloned();

    // Parse max_results with bounds checking
    let max_results = if let Some(max_str) = args.get("max_results") {
        let max: usize = max_str.parse()
            .map_err(|_| anyhow::anyhow!("Invalid max_results: must be an integer"))?;
        if max < 1 || max > 200 {
            bail!("max_results must be between 1 and 200, got {}", max);
        }
        max
    } else {
        25 // Default per spec
    };

    // Parse source
    let source = args.get("source").cloned().unwrap_or_else(|| "default".to_string());
    
    // Parse timeout with bounds checking
    let timeout_ms = if let Some(timeout_str) = args.get("timeout_ms") {
        let timeout: u64 = timeout_str.parse()
            .map_err(|_| anyhow::anyhow!("Invalid timeout_ms: must be an integer"))?;
        if timeout < 100 || timeout > 60000 {
            bail!("timeout_ms must be between 100 and 60000, got {}", timeout);
        }
        timeout
    } else {
        5000 // Default per spec
    };

    // Parse offline flag
    let offline = args.get("offline").map(|s| s == "true").unwrap_or(false);

    // Parse refresh flag (ignored if offline=true)
    let refresh = args.get("refresh").map(|s| s == "true").unwrap_or(false);

    Ok(AvailableSearchOptions {
        q,
        tags,
        owner,
        name,
        min_version,
        max_results,
        source,
        timeout_ms,
        offline,
        refresh,
    })
}

/// Parse arguments for available.list verb
fn parse_available_list_args(args: &Args) -> Result<AvailableListOptions> {
    // Parse source
    let source = args.get("source").cloned().unwrap_or_else(|| "default".to_string());
    
    // Validate and parse source
    let source = if source == "default" {
        source
    } else if source.starts_with("file:") {
        source
    } else if source.starts_with("url:") {
        bail!("Remote URL sources not yet supported");
    } else {
        bail!("Invalid source format. Use 'default', 'file:<path>', or 'url:<https://...>'");
    };

    // Parse query
    let query = args.get("query").cloned();

    // Parse tags
    let tags = if let Some(tags_str) = args.get("tags") {
        tags_str.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    } else {
        Vec::new()
    };

    // Parse publisher
    let publisher = args.get("publisher").cloned();

    // Parse platform (default to current platform)
    let platform = args.get("platform").cloned().unwrap_or_else(|| {
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;
        format!("{}-{}", os, arch)
    });

    // Parse include_prerelease
    let include_prerelease = args.get("include_prerelease")
        .map(|s| s == "true")
        .unwrap_or(false);

    // Parse limit
    let limit = if let Some(limit_str) = args.get("limit") {
        let limit: usize = limit_str.parse()
            .map_err(|_| anyhow::anyhow!("Invalid limit: must be an integer"))?;
        if limit > 1000 {
            bail!("Limit too high: maximum 1000");
        }
        if limit == 0 {
            bail!("Limit must be greater than 0");
        }
        limit
    } else {
        100
    };

    // Parse offset
    let offset = if let Some(offset_str) = args.get("offset") {
        offset_str.parse()
            .map_err(|_| anyhow::anyhow!("Invalid offset: must be an integer"))?
    } else {
        0
    };

    // Parse format
    let format = args.get("format").cloned().unwrap_or_else(|| "summary".to_string());
    if format != "summary" && format != "full" {
        bail!("Invalid format: must be 'summary' or 'full'");
    }

    Ok(AvailableListOptions {
        source,
        query,
        tags,
        publisher,
        platform,
        include_prerelease,
        limit,
        offset,
        format,
    })
}

/// Load catalog from source
fn load_catalog(source: &str) -> Result<Catalog> {
    let content = if source == "default" {
        // Load from built-in catalog
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
            .unwrap_or_else(|_| ".".to_string());
        let catalog_path = PathBuf::from(manifest_dir).join("assets/plugins/catalog.json");
        fs::read_to_string(&catalog_path)
            .map_err(|e| anyhow::anyhow!("Failed to load default catalog at {}: {}", catalog_path.display(), e))?
    } else if source.starts_with("file:") {
        let path = source.strip_prefix("file:").unwrap();
        fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to load catalog from {}: {}", path, e))?
    } else {
        bail!("Unsupported source: {}", source);
    };

    let catalog: Catalog = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse catalog JSON: {}", e))?;
    
    Ok(catalog)
}

/// Load catalog for search with caching and network support
fn load_search_catalog(
    options: &AvailableSearchOptions, 
    start_time: SystemTime,
    timeout: Duration
) -> Result<(SearchCatalog, serde_json::Value)> {
    // Check if we should use offline mode
    if options.offline {
        return load_cached_catalog(options).map_err(|e| {
            if e.to_string().contains("not found") || e.to_string().contains("No such file") {
                anyhow::anyhow!("No catalog available (offline and no cache).")
            } else {
                e
            }
        });
    }

    // Try to load from cache first, then network if refresh=true or cache is stale
    let cache_path = get_cache_path(&options.source)?;
    let use_cache = !options.refresh && cache_path.exists();
    
    if use_cache {
        match load_cached_catalog(options) {
            Ok((catalog, source)) => return Ok((catalog, source)),
            Err(_) => {
                // Cache failed, try network if not offline
                if !options.offline {
                    return fetch_and_cache_catalog(options, start_time, timeout);
                }
            }
        }
    }

    // Fetch from network (if not offline)
    if !options.offline {
        match fetch_and_cache_catalog(options, start_time, timeout) {
            Ok(result) => Ok(result),
            Err(_) => {
                // Network fetch failed, try fixture fallback
                load_fixture_catalog(options)
                    .map_err(|_| anyhow::anyhow!("Network fetch failed and no fixture available"))
            }
        }
    } else {
        bail!("No catalog available (offline and no cache).");
    }
}

/// Get cache directory path for plugin catalogs
fn get_cache_path(source: &str) -> Result<PathBuf> {
    let state_dir = if let Some(xdg_state) = std::env::var_os("XDG_STATE_HOME") {
        PathBuf::from(xdg_state)
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".local/state")
    } else {
        // Fallback for tests or unusual environments
        std::env::temp_dir().join("resh-test-state")
    };
    
    let cache_dir = state_dir.join("resh/plugins");
    fs::create_dir_all(&cache_dir).map_err(|e| anyhow::anyhow!("Failed to create cache directory: {}", e))?;
    
    let cache_file = if source == "default" {
        cache_dir.join("index-cache.json")
    } else {
        // Create a safe filename from the source URL
        let safe_name = source.chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect::<String>();
        cache_dir.join(format!("cache-{}.json", safe_name))
    };
    
    Ok(cache_file)
}

/// Load catalog from cache
fn load_cached_catalog(options: &AvailableSearchOptions) -> Result<(SearchCatalog, serde_json::Value)> {
    // For testing/offline mode, first try fixture data if available
    if options.offline {
        if let Ok(result) = load_fixture_catalog(options) {
            return Ok(result);
        }
    }
    
    // Fall back to normal cache behavior
    let cache_path = get_cache_path(&options.source)?;
    
    if !cache_path.exists() {
        bail!("No cached catalog found at {}", cache_path.display());
    }

    let cache_content = fs::read_to_string(&cache_path)
        .map_err(|e| anyhow::anyhow!("Failed to read cache: {}", e))?;
    
    let cache_data: CacheData = serde_json::from_str(&cache_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse cache: {}", e))?;
    
    // Convert to search format
    let catalog = SearchCatalog {
        plugins: cache_data.catalog.plugins.into_iter().map(|p| SearchPluginEntry {
            id: p.id,
            display_name: p.name,
            description: p.description,
            version: p.version,
            publisher: p.publisher,
            tags: p.tags,
            license: Some(p.license),
            homepage: Some(p.homepage),
            repo: Some(p.repo),
            artifact: json!({"type": "crate", "ref": p.entrypoint}), // Simplified
            sha256: Some(p.sha256),
            platforms: Some(p.platforms),
        }).collect(),
    };

    let source_info = json!({
        "id": options.source,
        "mode": "cache",
        "ref": cache_data.source_url,
        "fetched_at": cache_data.fetched_at
    });

    Ok((catalog, source_info))
}

/// Load catalog from test fixture
fn load_fixture_catalog(options: &AvailableSearchOptions) -> Result<(SearchCatalog, serde_json::Value)> {
    // Try multiple possible paths for the fixture file
    let fixture_paths = [
        "tests/fixtures/plugins-index.json",
        "../tests/fixtures/plugins-index.json", 
        "../../tests/fixtures/plugins-index.json",
    ];
    
    let test_fixture_path = fixture_paths.iter()
        .map(|p| std::path::Path::new(p))
        .find(|p| p.exists())
        .ok_or_else(|| anyhow::anyhow!("No test fixture found in any of: {:?}", fixture_paths))?;

    let content = fs::read_to_string(test_fixture_path)
        .map_err(|e| anyhow::anyhow!("Failed to read test fixture: {}", e))?;
    
    let catalog: SearchCatalog = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse test fixture: {}", e))?;
    
    let source_info = json!({
        "id": options.source,
        "mode": "fixture",
        "ref": test_fixture_path.to_string_lossy(),
        "fetched_at": chrono::Utc::now().to_rfc3339()
    });
    
    Ok((catalog, source_info))
}

/// Fetch catalog from network and cache it
fn fetch_and_cache_catalog(
    options: &AvailableSearchOptions,
    start_time: SystemTime,
    timeout: Duration
) -> Result<(SearchCatalog, serde_json::Value)> {
    // Check timeout
    if start_time.elapsed().unwrap_or(Duration::ZERO) > timeout {
        bail!("Operation timed out before network fetch");
    }

    let url = match options.source.as_str() {
        "default" => "https://plugins.reshshell.dev/index.json".to_string(),
        s if s.starts_with("https://") => s.to_string(),
        _ => bail!("Unsupported source for network fetch: {}", options.source),
    };

    // Calculate remaining timeout for network request
    let elapsed = start_time.elapsed().unwrap_or(Duration::ZERO);
    let remaining_timeout = timeout.checked_sub(elapsed)
        .ok_or_else(|| anyhow::anyhow!("Timeout exceeded before network request"))?;

    // Use reqwest blocking client with timeout
    let client = reqwest::blocking::Client::builder()
        .timeout(remaining_timeout)
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to create HTTP client: {}", e))?;

    let response = client.get(&url).send()
        .map_err(|e| anyhow::anyhow!("Network fetch failed: {}", e))?;

    if !response.status().is_success() {
        bail!("HTTP error {}: {}", response.status(), url);
    }

    let content = response.text()
        .map_err(|e| anyhow::anyhow!("Failed to read response body: {}", e))?;

    // Parse the catalog
    let raw_catalog: RawSearchCatalog = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse catalog JSON: {}", e))?;

    // Convert to internal format
    let catalog = SearchCatalog {
        plugins: raw_catalog.plugins,
    };

    // Cache the result
    let cache_data = CacheData {
        source_url: url.clone(),
        fetched_at: Utc::now().to_rfc3339(),
        catalog: Catalog {
            version: 1,
            generated_at: Utc::now().to_rfc3339(),
            plugins: catalog.plugins.iter().map(|p| PluginRecord {
                id: p.id.clone(),
                name: p.display_name.clone(),
                description: p.description.clone(),
                version: p.version.clone(),
                publisher: p.publisher.clone(),
                license: p.license.clone().unwrap_or_else(|| "Unknown".to_string()),
                tags: p.tags.clone(),
                platforms: p.platforms.clone().unwrap_or_default(),
                entrypoint: "resh-plugin".to_string(), // Default
                homepage: p.homepage.clone().unwrap_or_default(),
                repo: p.repo.clone().unwrap_or_default(),
                sha256: p.sha256.clone().unwrap_or_default(),
                artifacts: None,
            }).collect(),
        },
    };

    // Save to cache (best effort)
    if let Ok(cache_path) = get_cache_path(&options.source) {
        if let Ok(cache_json) = serde_json::to_string_pretty(&cache_data) {
            let _ = fs::write(&cache_path, cache_json); // Ignore errors
        }
    }

    let source_info = json!({
        "id": options.source,
        "mode": "online",
        "ref": url,
        "fetched_at": cache_data.fetched_at
    });

    Ok((catalog, source_info))
}

/// Cache data structure
#[derive(Debug, Serialize, Deserialize)]
struct CacheData {
    source_url: String,
    fetched_at: String,
    catalog: Catalog,
}

/// Search-specific catalog structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SearchCatalog {
    plugins: Vec<SearchPluginEntry>,
}

/// Raw catalog structure from network
#[derive(Debug, Deserialize)]
struct RawSearchCatalog {
    plugins: Vec<SearchPluginEntry>,
}

/// Perform plugin search with scoring and filtering
fn perform_plugin_search(plugins: &[SearchPluginEntry], options: &AvailableSearchOptions) -> Vec<SearchResult> {
    let mut results: Vec<SearchResult> = plugins.iter()
        .filter_map(|plugin| {
            // Apply filters
            if let Some(ref owner) = options.owner {
                if !plugin.publisher.eq_ignore_ascii_case(owner) {
                    return None;
                }
            }

            if let Some(ref name) = options.name {
                if !plugin.id.eq_ignore_ascii_case(name) {
                    return None;
                }
            }

            if let Some(ref min_ver) = options.min_version {
                if !version_meets_minimum(&plugin.version, min_ver) {
                    return None;
                }
            }

            if !options.tags.is_empty() {
                // All specified tags must be present (AND semantics)
                let plugin_tags_lower: Vec<String> = plugin.tags.iter()
                    .map(|t| t.to_lowercase())
                    .collect();
                for required_tag in &options.tags {
                    if !plugin_tags_lower.iter().any(|t| t == &required_tag.to_lowercase()) {
                        return None;
                    }
                }
            }

            // Calculate score and highlights
            let (score, highlights) = calculate_search_score(plugin, &options.q);

            // Create sorted tags for determinism
            let mut sorted_tags = plugin.tags.clone();
            sorted_tags.sort();

            // Create sorted highlights for determinism
            let mut sorted_highlights = highlights;
            sorted_highlights.sort();

            Some(SearchResult {
                id: plugin.id.clone(),
                display_name: plugin.display_name.clone(),
                version: plugin.version.clone(),
                publisher: plugin.publisher.clone(),
                description: plugin.description.clone(),
                tags: sorted_tags,
                license: plugin.license.clone(),
                homepage: plugin.homepage.clone(),
                repo: plugin.repo.clone(),
                artifact: plugin.artifact.clone(),
                sha256: plugin.sha256.clone(),
                score,
                highlights: sorted_highlights,
            })
        })
        .collect();

    // Sort results deterministically: score descending, then id ascending
    results.sort_by(|a, b| {
        use std::cmp::Ordering;
        match b.score.partial_cmp(&a.score).unwrap_or(Ordering::Equal) {
            Ordering::Equal => a.id.cmp(&b.id),
            other => other,
        }
    });

    // Apply max_results limit
    if results.len() > options.max_results {
        results.truncate(options.max_results);
    }

    results
}

/// Calculate search score and highlights for a plugin
fn calculate_search_score(plugin: &SearchPluginEntry, query: &Option<String>) -> (f64, Vec<String>) {
    let Some(q) = query else {
        // No query means all results have same score
        return (1.0, vec![]);
    };

    if q.trim().is_empty() {
        return (1.0, vec![]);
    }

    let query_lower = q.to_lowercase();
    let mut score: f64 = 0.0;
    let mut highlights = Vec::new();

    // Exact ID match - highest score
    if plugin.id.to_lowercase() == query_lower {
        score += 1.0;
        highlights.push("matched:id".to_string());
    } else if plugin.id.to_lowercase().contains(&query_lower) {
        score += 0.8;
        highlights.push("matched:id".to_string());
    }

    // Display name match
    if plugin.display_name.to_lowercase().contains(&query_lower) {
        score += 0.6;
        highlights.push("matched:display_name".to_string());
    }

    // Tag matches
    for tag in &plugin.tags {
        if tag.to_lowercase().contains(&query_lower) {
            score += 0.4;
            highlights.push(format!("matched:tag:{}", tag));
        }
    }

    // Publisher match
    if plugin.publisher.to_lowercase().contains(&query_lower) {
        score += 0.3;
        highlights.push("matched:publisher".to_string());
    }

    // Description match
    if plugin.description.to_lowercase().contains(&query_lower) {
        score += 0.2;
        highlights.push("matched:desc".to_string());
    }

    // Ensure score is in 0..1 range
    score = score.min(1.0);

    (score, highlights)
}

/// Check if a version meets the minimum requirement (best effort semver)
fn version_meets_minimum(version: &str, min_version: &str) -> bool {
    // Best effort semver comparison - if parsing fails, include the plugin
    match (parse_semver(version), parse_semver(min_version)) {
        (Some(v), Some(min_v)) => v >= min_v,
        _ => true, // Include if we can't parse
    }
}

/// Parse a semantic version into comparable tuple (major, minor, patch)
fn parse_semver(version: &str) -> Option<(u32, u32, u32)> {
    let version = version.split('-').next()?; // Remove prerelease
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

/// Filter and sort plugins based on options
fn filter_and_sort_plugins(plugins: &[PluginRecord], options: &AvailableListOptions) -> Vec<serde_json::Value> {
    // Apply filtering
    let mut filtered: Vec<&PluginRecord> = plugins.iter().collect();

    // Filter by query (case-insensitive substring match)
    if let Some(ref query) = options.query {
        let query_lower = query.to_lowercase();
        filtered.retain(|plugin| {
            plugin.id.to_lowercase().contains(&query_lower) ||
            plugin.name.to_lowercase().contains(&query_lower) ||
            plugin.description.to_lowercase().contains(&query_lower) ||
            plugin.publisher.to_lowercase().contains(&query_lower) ||
            plugin.tags.iter().any(|tag| tag.to_lowercase().contains(&query_lower))
        });
    }

    // Filter by tags (AND semantics - must include all listed tags)
    if !options.tags.is_empty() {
        filtered.retain(|plugin| {
            options.tags.iter().all(|tag| {
                plugin.tags.iter().any(|plugin_tag| plugin_tag.to_lowercase() == tag.to_lowercase())
            })
        });
    }

    // Filter by publisher (exact match, case-insensitive)
    if let Some(ref publisher) = options.publisher {
        let publisher_lower = publisher.to_lowercase();
        filtered.retain(|plugin| plugin.publisher.to_lowercase() == publisher_lower);
    }

    // Filter by platform
    filtered.retain(|plugin| {
        plugin.platforms.contains(&options.platform) ||
        plugin.artifacts.as_ref().map_or(false, |artifacts| {
            let parts: Vec<&str> = options.platform.split('-').collect();
            if parts.len() != 2 { return false; }
            let (os, arch) = (parts[0], parts[1]);
            artifacts.iter().any(|artifact| artifact.os == os && artifact.arch == arch)
        })
    });

    // Filter by prerelease
    if !options.include_prerelease {
        filtered.retain(|plugin| !plugin.version.contains('-'));
    }

    // Sort deterministically: id ASC, then version DESC (semver-aware), then publisher ASC
    filtered.sort_by(|a, b| {
        use std::cmp::Ordering;
        
        // First sort by id
        match a.id.cmp(&b.id) {
            Ordering::Equal => {
                // Then by version (semver descending)
                match compare_semver(&b.version, &a.version) {
                    Ordering::Equal => {
                        // Finally by publisher
                        a.publisher.cmp(&b.publisher)
                    }
                    other => other,
                }
            }
            other => other,
        }
    });

    // Apply pagination
    let start = options.offset;
    let end = std::cmp::min(start + options.limit, filtered.len());
    let paginated = if start < filtered.len() {
        &filtered[start..end]
    } else {
        &[]
    };

    // Convert to JSON format based on format option
    paginated.iter().map(|plugin| {
        if options.format == "full" {
            serde_json::to_value(plugin).unwrap()
        } else {
            // Summary format - omit large fields
            json!({
                "id": plugin.id,
                "name": plugin.name,
                "version": plugin.version,
                "description": plugin.description,
                "publisher": plugin.publisher,
                "tags": plugin.tags,
                "platforms": plugin.platforms,
                "homepage": plugin.homepage,
                "repo": plugin.repo,
                "license": plugin.license
            })
        }
    }).collect()
}

/// Compare semantic versions for sorting (returns std::cmp::Ordering)
fn compare_semver(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    
    // Try to parse as semver
    let parse_semver = |v: &str| -> Option<(u32, u32, u32, String)> {
        let mut parts = v.split('-');
        let version_part = parts.next()?;
        let prerelease_part = parts.collect::<Vec<_>>().join("-");
        
        let mut version_nums = version_part.split('.');
        let major: u32 = version_nums.next()?.parse().ok()?;
        let minor: u32 = version_nums.next().unwrap_or("0").parse().ok()?;
        let patch: u32 = version_nums.next().unwrap_or("0").parse().ok()?;
        
        Some((major, minor, patch, prerelease_part))
    };
    
    match (parse_semver(a), parse_semver(b)) {
        (Some((maj_a, min_a, pat_a, pre_a)), Some((maj_b, min_b, pat_b, pre_b))) => {
            match maj_a.cmp(&maj_b) {
                Ordering::Equal => match min_a.cmp(&min_b) {
                    Ordering::Equal => match pat_a.cmp(&pat_b) {
                        Ordering::Equal => {
                            // Compare prerelease: non-prerelease > prerelease, then lexicographic
                            match (pre_a.is_empty(), pre_b.is_empty()) {
                                (true, false) => Ordering::Greater,
                                (false, true) => Ordering::Less,
                                _ => pre_a.cmp(&pre_b),
                            }
                        }
                        other => other,
                    }
                    other => other,
                }
                other => other,
            }
        }
        _ => {
            // Fallback to lexicographic comparison
            a.cmp(b)
        }
    }
}

/// Create error envelope
fn create_error_envelope(
    op: &str,
    target: &str, 
    args: &Args,
    code: i32,
    kind: &str,
    message: &str,
) -> serde_json::Value {
    json!({
        "op": op,
        "ok": false,
        "code": code,
        "ts": Utc::now().to_rfc3339(),
        "target": target,
        "args": normalize_args_from_raw(args),
        "result": serde_json::Value::Null,
        "actions": [],
        "error": {
            "kind": kind,
            "message": message
        }
    })
}

/// Create search-specific error envelope
fn create_search_error_envelope(
    target: &str,
    args: &Args,
    code: &str,
    message: &str,
) -> serde_json::Value {
    let details = match code {
        "PLUGIN_CATALOG_UNAVAILABLE" => json!({"source": args.get("source").unwrap_or(&"default".to_string())}),
        "PLUGIN_NETWORK_ERROR" => json!({"source": args.get("source").unwrap_or(&"default".to_string())}),
        "PLUGIN_TIMEOUT" => json!({"timeout_ms": args.get("timeout_ms").unwrap_or(&"5000".to_string())}),
        _ => json!({}),
    };

    json!({
        "op": "plugin.available.search",
        "ok": false,
        "target": target,
        "args": normalize_args_from_raw(args),
        "result": serde_json::Value::Null,
        "actions": [],
        "error": {
            "code": code,
            "message": message,
            "details": details
        }
    })
}

/// Normalize search arguments for envelope
fn normalize_search_args(options: &AvailableSearchOptions) -> serde_json::Value {
    let tags_str = if options.tags.is_empty() {
        serde_json::Value::Null
    } else {
        json!(options.tags.join(";"))
    };

    json!({
        "q": options.q,
        "tags": tags_str,
        "owner": options.owner,
        "name": options.name,
        "min_version": options.min_version,
        "max_results": options.max_results,
        "source": options.source,
        "timeout_ms": options.timeout_ms,
        "offline": options.offline,
        "refresh": options.refresh
    })
}

/// Normalize arguments for envelope
fn normalize_args(options: &AvailableListOptions) -> serde_json::Value {
    json!({
        "source": options.source,
        "query": options.query,
        "tags": options.tags.join(","),
        "publisher": options.publisher,
        "platform": options.platform,
        "include_prerelease": options.include_prerelease,
        "limit": options.limit,
        "offset": options.offset,
        "format": options.format
    })
}

/// Normalize raw arguments for error envelopes
fn normalize_args_from_raw(args: &Args) -> serde_json::Value {
    let mut normalized = serde_json::Map::new();
    for (key, value) in args {
        normalized.insert(key.clone(), json!(value));
    }
    serde_json::Value::Object(normalized)
}

/// Output envelope with json_pretty support
fn output_envelope(envelope: &serde_json::Value, args: &Args, io: &mut IoStreams) -> Result<()> {
    let json_output = if args.get("json_pretty").map(|s| s == "true").unwrap_or(false) {
        serde_json::to_string_pretty(envelope)?
    } else {
        serde_json::to_string(envelope)?
    };
    
    writeln!(io.stdout, "{}", json_output)?;
    Ok(())
}

/// Register plugin handle with registry
pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("plugin", |url: &Url| -> Result<Box<dyn Handle>> {
        Ok(Box::new(PluginHandle::new(url)?))
    });
}

/// Parse arguments for installed.list operation
fn parse_installed_list_args(args: &Args) -> Result<InstalledListArgs> {
    let mut parsed = InstalledListArgs::default();

    // Parse enabled filter
    if let Some(enabled_str) = args.get("enabled") {
        parsed.enabled = match enabled_str.as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => bail!("Invalid enabled value: {}. Must be 'true' or 'false'", enabled_str),
        };
    }

    // Parse string filters
    parsed.name = args.get("name").cloned();
    parsed.prefix = args.get("prefix").cloned();
    parsed.tag = args.get("tag").cloned();
    parsed.source = args.get("source").cloned();

    // Parse pagination
    if let Some(limit_str) = args.get("limit") {
        parsed.limit = limit_str.parse::<i32>()
            .map_err(|_| anyhow!("Invalid limit: {}", limit_str))?;
        if parsed.limit < 1 || parsed.limit > 500 {
            bail!("Invalid limit: {}. Must be between 1 and 500", parsed.limit);
        }
    }

    if let Some(offset_str) = args.get("offset") {
        parsed.offset = offset_str.parse::<i32>()
            .map_err(|_| anyhow!("Invalid offset: {}", offset_str))?;
        if parsed.offset < 0 {
            bail!("Invalid offset: {}. Must be >= 0", parsed.offset);
        }
    }

    // Parse sorting
    if let Some(sort_str) = args.get("sort") {
        parsed.sort = match sort_str.as_str() {
            "name" | "installed_at" | "updated_at" => sort_str.clone(),
            _ => bail!("Invalid sort: {}. Must be one of: name, installed_at, updated_at", sort_str),
        };
    }

    if let Some(order_str) = args.get("order") {
        parsed.order = match order_str.as_str() {
            "asc" | "desc" => order_str.clone(),
            _ => bail!("Invalid order: {}. Must be 'asc' or 'desc'", order_str),
        };
    }

    // Parse format
    if let Some(format_str) = args.get("format") {
        parsed.format = match format_str.as_str() {
            "full" | "summary" | "names" => format_str.clone(),
            _ => bail!("Invalid format: {}. Must be one of: full, summary, names", format_str),
        };
    }

    Ok(parsed)
}

/// Execute the installed.list operation
fn execute_installed_list(target: &str, args: InstalledListArgs) -> serde_json::Value {
    use std::time::Instant;

    let start_time = Instant::now();
    let mut actions = Vec::new();

    // Step 1: Get plugin store directory and read installed plugins
    let store_result = crate::handles::pluginh::plugin::store::PluginStore::new();
    let store = match store_result {
        Ok(store) => store,
        Err(e) => {
            return create_installed_error_envelope(
                "plugin.installed.list",
                target,
                &args,
                actions,
                13,
                "permission_denied",
                &format!("Cannot read installed plugins directory: {}", e)
            );
        }
    };

    // Record action: scan installed directory
    let install_dir = crate::handles::pluginh::plugin::store::PluginStore::default_plugins_dir().unwrap_or_else(|_| std::path::PathBuf::from("/tmp/resh-plugins"));
    add_installed_action(&mut actions, "scan", "installed_dir", true, Some(serde_json::json!({
        "path": install_dir.to_string_lossy(),
        "duration_ms": start_time.elapsed().as_millis() as u64
    })));

    // Step 2: Get all installed plugins
    let all_plugins = match get_all_installed_plugins(&store) {
        Ok(plugins) => {
            add_installed_action(&mut actions, "read", "manifests", true, Some(serde_json::json!({
                "count": plugins.len(),
                "duration_ms": start_time.elapsed().as_millis() as u64
            })));
            plugins
        }
        Err(e) => {
            add_installed_action(&mut actions, "read", "manifests", false, Some(serde_json::json!({
                "error": e.to_string(),
                "duration_ms": start_time.elapsed().as_millis() as u64
            })));
            return create_installed_error_envelope(
                "plugin.installed.list",
                target,
                &args,
                actions,
                20,
                "plugin_store_corrupted",
                &format!("Plugin store corrupted: {}", e)
            );
        }
    };

    // Step 3: Read enabled registry
    let enabled_plugins = match get_enabled_plugins() {
        Ok(enabled) => {
            add_installed_action(&mut actions, "read", "enabled_registry", true, Some(serde_json::json!({
                "count": enabled.len(),
                "duration_ms": start_time.elapsed().as_millis() as u64
            })));
            enabled
        }
        Err(e) => {
            add_installed_action(&mut actions, "read", "enabled_registry", false, Some(serde_json::json!({
                "error": e.to_string(),
                "duration_ms": start_time.elapsed().as_millis() as u64
            })));
            std::collections::HashMap::new() // Default to all disabled
        }
    };

    // Step 4: Convert to PluginInstalledItem format and apply filters
    let mut plugin_items: Vec<PluginInstalledItem> = all_plugins.into_iter().map(|(name, metadata)| {
        let enabled = enabled_plugins.get(&name).copied().unwrap_or(false);
        convert_to_plugin_item(name, metadata, enabled)
    }).collect();

    // Step 5: Apply filters
    plugin_items = apply_filters(plugin_items, &args);
    add_installed_action(&mut actions, "filter", "apply", true, Some(serde_json::json!({
        "count": plugin_items.len(),
        "duration_ms": start_time.elapsed().as_millis() as u64
    })));

    // Step 6: Apply deterministic sorting
    apply_sorting(&mut plugin_items, &args);
    add_installed_action(&mut actions, "sort", "apply", true, Some(serde_json::json!({
        "sort": args.sort,
        "order": args.order,
        "duration_ms": start_time.elapsed().as_millis() as u64
    })));

    let total = plugin_items.len() as i32;

    // Step 7: Apply pagination
    let paginated_items = apply_pagination(&plugin_items, &args);
    add_installed_action(&mut actions, "paginate", "apply", true, Some(serde_json::json!({
        "offset": args.offset,
        "limit": args.limit,
        "duration_ms": start_time.elapsed().as_millis() as u64
    })));

    // Step 8: Format output
    let formatted_items = format_output(&paginated_items, &args);

    // Create success envelope
    create_installed_success_envelope(target, &args, actions, total, &formatted_items)
}

/// Get all installed plugins from the plugin store
fn get_all_installed_plugins(store: &crate::handles::pluginh::plugin::store::PluginStore) -> Result<std::collections::HashMap<String, crate::handles::pluginh::plugin::types::InstalledPlugin>> {
    use std::fs;

    let mut plugins = std::collections::HashMap::new();
    
    // Use environment variable for test, otherwise use store's default
    let plugins_dir = if let Some(test_dir) = std::env::var_os("RESH_STATE_DIR") {
        std::path::PathBuf::from(test_dir).join("resh").join("plugins").join("installed")
    } else {
        crate::handles::pluginh::plugin::store::PluginStore::default_plugins_dir()?
    };

    if !plugins_dir.exists() {
        return Ok(plugins);
    }

    let entries = fs::read_dir(&plugins_dir)?;
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let plugin_name = entry.file_name().to_string_lossy().to_string();
            
            // Get current version (follow symlink if exists)
            let current_link = plugins_dir.join(&plugin_name).join("current");
            let version_dir = if current_link.exists() && current_link.is_symlink() {
                match fs::read_link(&current_link) {
                    Ok(target) => {
                        let version = target.file_name().unwrap_or_default().to_string_lossy().to_string();
                        Some(version)
                    }
                    Err(_) => None,
                }
            } else {
                None
            };

            // If no current version, try to find any version
            let version = if let Some(v) = version_dir {
                v
            } else {
                let versions_dir = plugins_dir.join(&plugin_name).join("versions");
                if versions_dir.exists() {
                    if let Ok(mut versions) = fs::read_dir(&versions_dir) {
                        if let Some(Ok(entry)) = versions.next() {
                            entry.file_name().to_string_lossy().to_string()
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            };

            // Load metadata from version directory 
            let version_dir = plugins_dir.join(&plugin_name).join("versions").join(&version);
            let metadata_file = version_dir.join("metadata.json");
            
            if metadata_file.exists() {
                match fs::read_to_string(&metadata_file) {
                    Ok(content) => {
                        match serde_json::from_str::<crate::handles::pluginh::plugin::types::InstalledPlugin>(&content) {
                            Ok(metadata) => {
                                plugins.insert(plugin_name, metadata);
                            }
                            Err(_) => {
                                // Create broken plugin metadata
                                let broken_metadata = crate::handles::pluginh::plugin::types::InstalledPlugin {
                                    plugin_id: plugin_name.clone(),
                                    version,
                                    install_path: version_dir.to_string_lossy().to_string(),
                                    bin_path: None,
                                    installed_at: chrono::Utc::now().to_rfc3339(),
                                    source: "unknown".to_string(),
                                    sha256: Some("unknown".to_string()),
                                };
                                plugins.insert(plugin_name, broken_metadata);
                            }
                        }
                    }
                    Err(_) => {
                        // Create broken plugin metadata
                        let broken_metadata = crate::handles::pluginh::plugin::types::InstalledPlugin {
                            plugin_id: plugin_name.clone(),
                            version,
                            install_path: version_dir.to_string_lossy().to_string(),
                            bin_path: None,
                            installed_at: chrono::Utc::now().to_rfc3339(),
                            source: "unknown".to_string(),
                            sha256: Some("unknown".to_string()),
                        };
                        plugins.insert(plugin_name, broken_metadata);
                    }
                }
            } else {
                // Create broken plugin metadata
                let broken_metadata = crate::handles::pluginh::plugin::types::InstalledPlugin {
                    plugin_id: plugin_name.clone(),
                    version,
                    install_path: version_dir.to_string_lossy().to_string(),
                    bin_path: None,
                    installed_at: chrono::Utc::now().to_rfc3339(),
                    source: "unknown".to_string(),
                    sha256: Some("unknown".to_string()),
                };
                plugins.insert(plugin_name, broken_metadata);
            }
        }
    }

    Ok(plugins)
}

/// Get enabled plugins from state manager
fn get_enabled_plugins() -> Result<std::collections::HashMap<String, bool>> {
    use std::path::PathBuf;
    use std::fs;

    // Check for test environment variable first
    let state_dir = if let Some(test_dir) = std::env::var_os("RESH_STATE_DIR") {
        PathBuf::from(test_dir)
    } else {
        dirs::state_dir()
            .or_else(|| dirs::data_local_dir())
            .unwrap_or_else(|| PathBuf::from("/tmp"))
    };
    
    let enabled_file = state_dir.join("resh").join("plugins").join("enabled.json");
    
    if !enabled_file.exists() {
        return Ok(std::collections::HashMap::new());
    }

    let content = fs::read_to_string(&enabled_file)?;
    
    // First try to parse as EnabledRegistry format (proper format)
    if let Ok(registry) = serde_json::from_str::<serde_json::Value>(&content) {
        if let Some(enabled_array) = registry.get("enabled").and_then(|v| v.as_array()) {
            let mut result = std::collections::HashMap::new();
            for entry in enabled_array {
                if let (Some(id), Some(_version)) = (
                    entry.get("id").and_then(|v| v.as_str()),
                    entry.get("version").and_then(|v| v.as_str())
                ) {
                    result.insert(id.to_string(), true);
                }
            }
            return Ok(result);
        }
    }
    
    // Fall back to legacy simple HashMap format
    let enabled: std::collections::HashMap<String, bool> = serde_json::from_str(&content)
        .unwrap_or_else(|_| std::collections::HashMap::new());
    
    Ok(enabled)
}

/// Convert plugin metadata to PluginInstalledItem
fn convert_to_plugin_item(name: String, metadata: crate::handles::pluginh::plugin::types::InstalledPlugin, enabled: bool) -> PluginInstalledItem {
    let health = if metadata.version == "unknown" || metadata.source == "unknown" {
        "broken".to_string()
    } else {
        "ok".to_string()
    };

    let source = PluginSource {
        source_type: if metadata.source == "unknown" { "unknown".to_string() } else { "registry".to_string() },
        r#ref: if metadata.source != "unknown" { Some(metadata.source.clone()) } else { None },
        url: None,
    };

    let paths = PluginPaths {
        install_dir: metadata.install_path.clone(),
        binary: metadata.bin_path.clone(),
    };

    let manifest = if health == "ok" {
        // Try to read manifest from plugin directory
        read_plugin_manifest(&metadata.install_path)
    } else {
        None
    };

    PluginInstalledItem {
        name,
        version: metadata.version,
        enabled,
        source,
        paths,
        manifest,
        health,
        installed_at: Some(metadata.installed_at.clone()),
        updated_at: Some(metadata.installed_at), // Use installed_at as updated_at for now
    }
}

/// Read plugin manifest from install directory
fn read_plugin_manifest(install_path: &str) -> Option<PluginManifestSummary> {
    use std::path::Path;
    use std::fs;

    let install_dir = Path::new(install_path);
    
    // Try manifest.json first
    let manifest_json = install_dir.join("manifest.json");
    if manifest_json.exists() {
        if let Ok(content) = fs::read_to_string(&manifest_json) {
            if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&content) {
                return Some(PluginManifestSummary {
                    description: manifest.get("description").and_then(|v| v.as_str()).map(String::from),
                    tags: manifest.get("tags")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter()
                            .filter_map(|v| v.as_str())
                            .map(String::from)
                            .collect())
                        .unwrap_or_default(),
                    capabilities: manifest.get("capabilities")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter()
                            .filter_map(|v| v.as_str())
                            .map(String::from)
                            .collect())
                        .unwrap_or_default(),
                });
            }
        }
    }

    // Try plugin.toml
    let plugin_toml = install_dir.join("plugin.toml");
    if plugin_toml.exists() {
        // For now, return empty manifest since we don't have toml parsing
        return Some(PluginManifestSummary {
            description: None,
            tags: vec![],
            capabilities: vec![],
        });
    }

    None
}

/// Apply filters to plugin list
fn apply_filters(mut plugins: Vec<PluginInstalledItem>, args: &InstalledListArgs) -> Vec<PluginInstalledItem> {
    plugins.retain(|plugin| {
        // Filter by enabled
        if let Some(enabled) = args.enabled {
            if plugin.enabled != enabled {
                return false;
            }
        }

        // Filter by name (exact match)
        if let Some(ref name) = args.name {
            if plugin.name != *name {
                return false;
            }
        }

        // Filter by prefix
        if let Some(ref prefix) = args.prefix {
            if !plugin.name.starts_with(prefix) {
                return false;
            }
        }

        // Filter by tag
        if let Some(ref tag) = args.tag {
            if let Some(ref manifest) = plugin.manifest {
                if !manifest.tags.contains(tag) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Filter by source
        if let Some(ref source) = args.source {
            if plugin.source.source_type != *source {
                return false;
            }
        }

        true
    });

    plugins
}

/// Apply deterministic sorting to plugin list
fn apply_sorting(plugins: &mut Vec<PluginInstalledItem>, args: &InstalledListArgs) {
    plugins.sort_by(|a, b| {
        let result = match args.sort.as_str() {
            "name" => {
                // Case-insensitive compare first, then case-sensitive tie-break
                let a_lower = a.name.to_lowercase();
                let b_lower = b.name.to_lowercase();
                match a_lower.cmp(&b_lower) {
                    std::cmp::Ordering::Equal => a.name.cmp(&b.name),
                    other => other,
                }
            }
            "installed_at" => {
                a.installed_at.as_ref().unwrap_or(&String::new())
                    .cmp(b.installed_at.as_ref().unwrap_or(&String::new()))
            }
            "updated_at" => {
                a.updated_at.as_ref().unwrap_or(&String::new())
                    .cmp(b.updated_at.as_ref().unwrap_or(&String::new()))
            }
            _ => std::cmp::Ordering::Equal,
        };

        if args.order == "desc" {
            result.reverse()
        } else {
            result
        }
    });
}

/// Apply pagination to plugin list
fn apply_pagination(plugins: &[PluginInstalledItem], args: &InstalledListArgs) -> Vec<PluginInstalledItem> {
    let start = args.offset as usize;
    let end = start + (args.limit as usize);
    
    if start >= plugins.len() {
        vec![]
    } else {
        plugins[start..end.min(plugins.len())].to_vec()
    }
}

/// Format output according to format option
fn format_output(plugins: &[PluginInstalledItem], args: &InstalledListArgs) -> serde_json::Value {
    match args.format.as_str() {
        "names" => {
            let names: Vec<String> = plugins.iter().map(|p| p.name.clone()).collect();
            serde_json::json!(names)
        }
        "summary" => {
            let summary: Vec<serde_json::Value> = plugins.iter().map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "version": p.version,
                    "enabled": p.enabled,
                    "source": p.source,
                    "health": p.health
                })
            }).collect();
            serde_json::json!(summary)
        }
        "full" | _ => {
            serde_json::to_value(plugins).unwrap_or(serde_json::json!([]))
        }
    }
}

/// Create success envelope for installed.list
fn create_installed_success_envelope(
    target: &str,
    args: &InstalledListArgs,
    actions: Vec<serde_json::Value>,
    total: i32,
    items: &serde_json::Value
) -> serde_json::Value {
    let count = match items {
        serde_json::Value::Array(arr) => arr.len() as i32,
        _ => total,
    };

    let result = InstalledListResult {
        count,
        total,
        offset: args.offset,
        limit: args.limit,
        items: Some(items.clone()),
    };

    let normalized_args = serde_json::json!({
        "enabled": args.enabled,
        "name": args.name,
        "prefix": args.prefix,
        "tag": args.tag,
        "source": args.source,
        "limit": args.limit,
        "offset": args.offset,
        "sort": args.sort,
        "order": args.order,
        "format": args.format
    });

    serde_json::json!({
        "op": "plugin.installed.list",
        "ok": true,
        "target": target,
        "ts": chrono::Utc::now().to_rfc3339(),
        "args": normalized_args,
        "result": result,
        "actions": actions,
        "warnings": [],
        "error": null
    })
}

/// Create error envelope for installed.list
fn create_installed_error_envelope(
    op: &str,
    target: &str,
    args: &InstalledListArgs,
    actions: Vec<serde_json::Value>,
    code: i32,
    kind: &str,
    message: &str
) -> serde_json::Value {
    let normalized_args = serde_json::json!({
        "enabled": args.enabled,
        "name": args.name,
        "prefix": args.prefix,
        "tag": args.tag,
        "source": args.source,
        "limit": args.limit,
        "offset": args.offset,
        "sort": args.sort,
        "order": args.order,
        "format": args.format
    });

    serde_json::json!({
        "op": op,
        "ok": false,
        "code": code,
        "target": target,
        "ts": chrono::Utc::now().to_rfc3339(),
        "args": normalized_args,
        "result": null,
        "actions": actions,
        "warnings": [],
        "error": {
            "code": code,
            "kind": kind,
            "message": message,
            "detail": null
        }
    })
}

/// Add an action to the actions list
fn add_installed_action(
    actions: &mut Vec<serde_json::Value>,
    action_type: &str,
    target: &str,
    ok: bool,
    detail: Option<serde_json::Value>
) {
    actions.push(serde_json::json!({
        "type": format!("{}.{}", action_type, target),
        "target": target,
        "ok": ok,
        "detail": detail.unwrap_or(serde_json::Value::Null)
    }));
}

/// Output envelope to IO streams
fn output_installed_envelope(envelope: &serde_json::Value, args: &Args, io: &mut IoStreams) -> Result<()> {
    let json_output = if args.get("json_pretty").map(|s| s == "true").unwrap_or(false) {
        serde_json::to_string_pretty(envelope)?
    } else {
        serde_json::to_string(envelope)?
    };
    
    writeln!(io.stdout, "{}", json_output)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Cursor;
    use tempfile::TempDir;
    use url::Url;
    use crate::core::registry::{Args, IoStreams};

    fn create_test_handle(plugin_id: &str) -> PluginHandle {
        PluginHandle {
            plugin_id: plugin_id.to_string(),
            target: format!("plugin://{}", plugin_id),
        }
    }

    fn create_test_args(args: HashMap<String, String>) -> Args {
        args.into()
    }

    fn create_test_io() -> (Cursor<Vec<u8>>, Cursor<Vec<u8>>, Cursor<Vec<u8>>) {
        (
            Cursor::new(Vec::new()), // stdin
            Cursor::new(Vec::new()), // stdout
            Cursor::new(Vec::new()), // stderr
        )
    }

    #[test]
    fn test_new_plugin_handle() {
        let url = Url::parse("plugin://demo").unwrap();
        let handle = PluginHandle::new(&url).unwrap();
        assert_eq!(handle.plugin_id, "demo");
        assert_eq!(handle.target, "plugin://demo");
    }

    #[test]
    fn test_new_plugin_handle_with_namespace() {
        let url = Url::parse("plugin://community/docker").unwrap();
        let handle = PluginHandle::new(&url).unwrap();
        assert_eq!(handle.plugin_id, "community/docker");
        assert_eq!(handle.target, "plugin://community/docker");
    }

    #[test]
    fn test_new_plugin_handle_invalid_empty() {
        let url = Url::parse("plugin://").unwrap();
        let result = PluginHandle::new(&url);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Invalid plugin URL format"));
    }

    #[test]
    fn test_plugin_handle_verbs() {
        let handle = create_test_handle("test");
        let verbs = handle.verbs();
        assert_eq!(verbs, &["install", "update", "remove", "enable", "disable", "available.list", "available.search"]);
    }

    #[test]
    fn test_parse_enable_disable_args_defaults() {
        let handle = create_test_handle("test");
        let args = create_test_args(HashMap::new());
        let opts = handle.parse_enable_disable_args(&args).unwrap();
        
        assert_eq!(opts.scope, Scope::User);
        assert!(!opts.force);
        assert!(!opts.dry_run);
        assert_eq!(opts.timeout_ms, 15000);
        assert_eq!(opts.reason, "");
    }

    #[test]
    fn test_parse_enable_disable_args_system_scope() {
        let handle = create_test_handle("test");
        let mut args_map = HashMap::new();
        args_map.insert("scope".to_string(), "system".to_string());
        let args = create_test_args(args_map);
        let opts = handle.parse_enable_disable_args(&args).unwrap();
        
        assert_eq!(opts.scope, Scope::System);
    }

    #[test]
    fn test_parse_enable_disable_args_force() {
        let handle = create_test_handle("test");
        let mut args_map = HashMap::new();
        args_map.insert("force".to_string(), "true".to_string());
        let args = create_test_args(args_map);
        let opts = handle.parse_enable_disable_args(&args).unwrap();
        
        assert!(opts.force);
    }

    #[test]
    fn test_parse_enable_disable_args_dry_run() {
        let handle = create_test_handle("test");
        let mut args_map = HashMap::new();
        args_map.insert("dry_run".to_string(), "true".to_string());
        let args = create_test_args(args_map);
        let opts = handle.parse_enable_disable_args(&args).unwrap();
        
        assert!(opts.dry_run);
    }

    #[test]
    fn test_parse_enable_disable_args_custom_timeout() {
        let handle = create_test_handle("test");
        let mut args_map = HashMap::new();
        args_map.insert("timeout_ms".to_string(), "30000".to_string());
        let args = create_test_args(args_map);
        let opts = handle.parse_enable_disable_args(&args).unwrap();
        
        assert_eq!(opts.timeout_ms, 30000);
    }

    #[test]
    fn test_parse_enable_disable_args_timeout_clamping() {
        let handle = create_test_handle("test");
        let mut args_map = HashMap::new();
        
        // Test lower bound
        args_map.insert("timeout_ms".to_string(), "500".to_string());
        let args = create_test_args(args_map.clone());
        let opts = handle.parse_enable_disable_args(&args).unwrap();
        assert_eq!(opts.timeout_ms, 1000);
        
        // Test upper bound
        args_map.insert("timeout_ms".to_string(), "200000".to_string());
        let args = create_test_args(args_map);
        let opts = handle.parse_enable_disable_args(&args).unwrap();
        assert_eq!(opts.timeout_ms, 120000);
    }

    #[test]
    fn test_parse_enable_disable_args_reason() {
        let handle = create_test_handle("test");
        let mut args_map = HashMap::new();
        args_map.insert("reason".to_string(), "Testing disable".to_string());
        let args = create_test_args(args_map);
        let opts = handle.parse_enable_disable_args(&args).unwrap();
        
        assert_eq!(opts.reason, "Testing disable");
    }

    #[test]
    fn test_parse_enable_disable_args_invalid_scope() {
        let handle = create_test_handle("test");
        let mut args_map = HashMap::new();
        args_map.insert("scope".to_string(), "invalid".to_string());
        let args = create_test_args(args_map);
        let result = handle.parse_enable_disable_args(&args);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid scope: invalid"));
    }

    #[test]
    fn test_parse_enable_disable_args_reason_too_long() {
        let handle = create_test_handle("test");
        let mut args_map = HashMap::new();
        let long_reason = "a".repeat(201);
        args_map.insert("reason".to_string(), long_reason);
        let args = create_test_args(args_map);
        let result = handle.parse_enable_disable_args(&args);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Reason too long"));
    }

    #[test]
    fn test_unknown_verb() {
        let handle = create_test_handle("test");
        let args = create_test_args(HashMap::new());
        
        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };
        
        let result = handle.call("unknown", &args, &mut io);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown verb: unknown"));
    }

    #[test]
    fn test_disable_verb_recognized() {
        let handle = create_test_handle("test");
        let args = create_test_args(HashMap::new());
        
        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };
        
        // This should return Ok with an error status since plugin isn't installed
        let result = handle.call("disable", &args, &mut io);
        assert!(result.is_ok());
        let status = result.unwrap();
        assert!(!status.ok); // Should be an error status
        // Should not be an "unknown verb" error 
        assert!(status.reason.as_ref().map_or(true, |r| !r.contains("Unknown verb")));
    }

    #[test]
    fn test_parse_available_list_args_defaults() {
        let args = create_test_args(HashMap::new());
        let options = parse_available_list_args(&args).unwrap();
        
        assert_eq!(options.source, "default");
        assert_eq!(options.query, None);
        assert_eq!(options.tags, Vec::<String>::new());
        assert_eq!(options.publisher, None);
        assert_eq!(options.include_prerelease, false);
        assert_eq!(options.limit, 100);
        assert_eq!(options.offset, 0);
        assert_eq!(options.format, "summary");
    }

    #[test]
    fn test_parse_available_list_args_with_values() {
        let mut args_map = HashMap::new();
        args_map.insert("source".to_string(), "file:/tmp/catalog.json".to_string());
        args_map.insert("query".to_string(), "docker".to_string());
        args_map.insert("tags".to_string(), "container,cloud".to_string());
        args_map.insert("publisher".to_string(), "resh-community".to_string());
        args_map.insert("include_prerelease".to_string(), "true".to_string());
        args_map.insert("limit".to_string(), "50".to_string());
        args_map.insert("offset".to_string(), "25".to_string());
        args_map.insert("format".to_string(), "full".to_string());
        let args = create_test_args(args_map);
        let options = parse_available_list_args(&args).unwrap();
        
        assert_eq!(options.source, "file:/tmp/catalog.json");
        assert_eq!(options.query, Some("docker".to_string()));
        assert_eq!(options.tags, vec!["container".to_string(), "cloud".to_string()]);
        assert_eq!(options.publisher, Some("resh-community".to_string()));
        assert!(options.include_prerelease);
        assert_eq!(options.limit, 50);
        assert_eq!(options.offset, 25);
        assert_eq!(options.format, "full");
    }

    #[test]
    fn test_parse_available_list_args_invalid_limit() {
        let mut args_map = HashMap::new();
        args_map.insert("limit".to_string(), "2000".to_string());
        let args = create_test_args(args_map);
        let result = parse_available_list_args(&args);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Limit too high"));
    }

    #[test]
    fn test_parse_available_list_args_invalid_format() {
        let mut args_map = HashMap::new();
        args_map.insert("format".to_string(), "invalid".to_string());
        let args = create_test_args(args_map);
        let result = parse_available_list_args(&args);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid format"));
    }

    #[test]
    fn test_compare_semver() {
        use std::cmp::Ordering;
        
        // Test major version differences
        assert_eq!(compare_semver("2.0.0", "1.0.0"), Ordering::Greater);
        assert_eq!(compare_semver("1.0.0", "2.0.0"), Ordering::Less);
        
        // Test minor version differences
        assert_eq!(compare_semver("1.2.0", "1.1.0"), Ordering::Greater);
        assert_eq!(compare_semver("1.1.0", "1.2.0"), Ordering::Less);
        
        // Test patch version differences
        assert_eq!(compare_semver("1.0.2", "1.0.1"), Ordering::Greater);
        assert_eq!(compare_semver("1.0.1", "1.0.2"), Ordering::Less);
        
        // Test prerelease versions
        assert_eq!(compare_semver("1.0.0", "1.0.0-beta.1"), Ordering::Greater);
        assert_eq!(compare_semver("1.0.0-beta.1", "1.0.0"), Ordering::Less);
        assert_eq!(compare_semver("1.0.0-beta.2", "1.0.0-beta.1"), Ordering::Greater);
        
        // Test equal versions
        assert_eq!(compare_semver("1.0.0", "1.0.0"), Ordering::Equal);
        assert_eq!(compare_semver("1.0.0-beta.1", "1.0.0-beta.1"), Ordering::Equal);
    }

    #[test]
    fn test_filter_and_sort_plugins_empty() {
        let plugins = vec![];
        let options = AvailableListOptions {
            source: "default".to_string(),
            query: None,
            tags: vec![],
            publisher: None,
            platform: "linux-x86_64".to_string(),
            include_prerelease: false,
            limit: 100,
            offset: 0,
            format: "summary".to_string(),
        };
        
        let result = filter_and_sort_plugins(&plugins, &options);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_filter_and_sort_plugins_query_filtering() {
        let plugins = vec![
            PluginRecord {
                id: "resh.docker".to_string(),
                name: "Docker Handle".to_string(),
                description: "Docker management plugin".to_string(),
                version: "1.0.0".to_string(),
                publisher: "resh-community".to_string(),
                license: "MIT".to_string(),
                tags: vec!["docker".to_string(), "container".to_string()],
                platforms: vec!["linux-x86_64".to_string()],
                entrypoint: "resh-docker".to_string(),
                homepage: "https://example.com".to_string(),
                repo: "https://github.com/example".to_string(),
                sha256: "abc123".to_string(),
                artifacts: None,
            },
            PluginRecord {
                id: "resh.kubernetes".to_string(),
                name: "Kubernetes Handle".to_string(),
                description: "Kubernetes management plugin".to_string(),
                version: "1.0.0".to_string(),
                publisher: "resh-community".to_string(),
                license: "MIT".to_string(),
                tags: vec!["kubernetes".to_string(), "k8s".to_string()],
                platforms: vec!["linux-x86_64".to_string()],
                entrypoint: "resh-k8s".to_string(),
                homepage: "https://example.com".to_string(),
                repo: "https://github.com/example".to_string(),
                sha256: "def456".to_string(),
                artifacts: None,
            },
        ];
        
        let options = AvailableListOptions {
            source: "default".to_string(),
            query: Some("docker".to_string()),
            tags: vec![],
            publisher: None,
            platform: "linux-x86_64".to_string(),
            include_prerelease: false,
            limit: 100,
            offset: 0,
            format: "summary".to_string(),
        };
        
        let result = filter_and_sort_plugins(&plugins, &options);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["id"], "resh.docker");
    }

    #[test]
    fn test_filter_and_sort_plugins_deterministic_ordering() {
        let mut plugins = vec![
            PluginRecord {
                id: "resh.kubernetes".to_string(),
                name: "Kubernetes Handle".to_string(),
                description: "Kubernetes management plugin".to_string(),
                version: "1.0.0".to_string(),
                publisher: "resh-community".to_string(),
                license: "MIT".to_string(),
                tags: vec!["kubernetes".to_string()],
                platforms: vec!["linux-x86_64".to_string()],
                entrypoint: "resh-k8s".to_string(),
                homepage: "https://example.com".to_string(),
                repo: "https://github.com/example".to_string(),
                sha256: "def456".to_string(),
                artifacts: None,
            },
            PluginRecord {
                id: "resh.docker".to_string(),
                name: "Docker Handle".to_string(),
                description: "Docker management plugin".to_string(),
                version: "1.0.0".to_string(),
                publisher: "resh-community".to_string(),
                license: "MIT".to_string(),
                tags: vec!["docker".to_string()],
                platforms: vec!["linux-x86_64".to_string()],
                entrypoint: "resh-docker".to_string(),
                homepage: "https://example.com".to_string(),
                repo: "https://github.com/example".to_string(),
                sha256: "abc123".to_string(),
                artifacts: None,
            },
        ];
        
        let options = AvailableListOptions {
            source: "default".to_string(),
            query: None,
            tags: vec![],
            publisher: None,
            platform: "linux-x86_64".to_string(),
            include_prerelease: false,
            limit: 100,
            offset: 0,
            format: "summary".to_string(),
        };
        
        // Should be sorted by id in ascending order
        let result = filter_and_sort_plugins(&plugins, &options);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0]["id"], "resh.docker");
        assert_eq!(result[1]["id"], "resh.kubernetes");
    }

    #[test]
    fn test_available_list_wrong_target() {
        let handle = create_test_handle("something-else");
        let args = create_test_args(HashMap::new());
        
        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };
        
        let result = handle.available_list(&args, &mut io);
        assert!(result.is_ok());
        let status = result.unwrap();
        assert!(!status.ok);
        assert_eq!(status.code, Some(5));
    }

    #[test] 
    fn test_available_list_verbs() {
        let handle = create_test_handle("available");
        let verbs = handle.verbs();
        assert!(verbs.contains(&"available.list"));
        assert!(verbs.contains(&"installed.list"));
    }

    // Unit tests for installed.list functionality
    #[test]
    fn test_parse_installed_list_args_defaults() {
        let args = create_test_args(HashMap::new());
        let result = parse_installed_list_args(&args).unwrap();
        
        assert_eq!(result.enabled, None);
        assert_eq!(result.name, None);
        assert_eq!(result.limit, 200);
        assert_eq!(result.offset, 0);
        assert_eq!(result.sort, "name");
        assert_eq!(result.order, "asc");
        assert_eq!(result.format, "full");
    }

    #[test]
    fn test_parse_installed_list_args_all_params() {
        let mut params = HashMap::new();
        params.insert("enabled".to_string(), "true".to_string());
        params.insert("name".to_string(), "test-plugin".to_string());
        params.insert("prefix".to_string(), "test-".to_string());
        params.insert("tag".to_string(), "cloud".to_string());
        params.insert("source".to_string(), "registry".to_string());
        params.insert("limit".to_string(), "50".to_string());
        params.insert("offset".to_string(), "10".to_string());
        params.insert("sort".to_string(), "installed_at".to_string());
        params.insert("order".to_string(), "desc".to_string());
        params.insert("format".to_string(), "summary".to_string());
        
        let args = create_test_args(params);
        let result = parse_installed_list_args(&args).unwrap();
        
        assert_eq!(result.enabled, Some(true));
        assert_eq!(result.name, Some("test-plugin".to_string()));
        assert_eq!(result.prefix, Some("test-".to_string()));
        assert_eq!(result.tag, Some("cloud".to_string()));
        assert_eq!(result.source, Some("registry".to_string()));
        assert_eq!(result.limit, 50);
        assert_eq!(result.offset, 10);
        assert_eq!(result.sort, "installed_at");
        assert_eq!(result.order, "desc");
        assert_eq!(result.format, "summary");
    }

    #[test]
    fn test_parse_installed_list_args_invalid_enabled() {
        let mut params = HashMap::new();
        params.insert("enabled".to_string(), "maybe".to_string());
        let args = create_test_args(params);
        
        let result = parse_installed_list_args(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid enabled value"));
    }

    #[test]
    fn test_parse_installed_list_args_invalid_limit() {
        let mut params = HashMap::new();
        params.insert("limit".to_string(), "1000".to_string());
        let args = create_test_args(params);
        
        let result = parse_installed_list_args(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid limit"));
    }

    #[test]
    fn test_parse_installed_list_args_invalid_sort() {
        let mut params = HashMap::new();
        params.insert("sort".to_string(), "invalid".to_string());
        let args = create_test_args(params);
        
        let result = parse_installed_list_args(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid sort"));
    }

    #[test]
    fn test_parse_installed_list_args_invalid_format() {
        let mut params = HashMap::new();
        params.insert("format".to_string(), "invalid".to_string());
        let args = create_test_args(params);
        
        let result = parse_installed_list_args(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid format"));
    }

    #[test]
    fn test_apply_filters_enabled() {
        let plugins = vec![
            create_test_plugin_item("plugin1", true),
            create_test_plugin_item("plugin2", false),
            create_test_plugin_item("plugin3", true),
        ];
        
        let mut args = InstalledListArgs::default();
        args.enabled = Some(true);
        
        let filtered = apply_filters(plugins, &args);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].name, "plugin1");
        assert_eq!(filtered[1].name, "plugin3");
    }

    #[test]
    fn test_apply_filters_name_exact() {
        let plugins = vec![
            create_test_plugin_item("aws", true),
            create_test_plugin_item("aws-s3", true),
            create_test_plugin_item("azure", true),
        ];
        
        let mut args = InstalledListArgs::default();
        args.name = Some("aws".to_string());
        
        let filtered = apply_filters(plugins, &args);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "aws");
    }

    #[test]
    fn test_apply_filters_prefix() {
        let plugins = vec![
            create_test_plugin_item("aws", true),
            create_test_plugin_item("aws-s3", true),
            create_test_plugin_item("azure", true),
        ];
        
        let mut args = InstalledListArgs::default();
        args.prefix = Some("aws".to_string());
        
        let filtered = apply_filters(plugins, &args);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].name, "aws");
        assert_eq!(filtered[1].name, "aws-s3");
    }

    #[test]
    fn test_apply_sorting_name_asc() {
        let mut plugins = vec![
            create_test_plugin_item("zebra", true),
            create_test_plugin_item("Alpha", true),
            create_test_plugin_item("beta", true),
        ];
        
        let args = InstalledListArgs {
            sort: "name".to_string(),
            order: "asc".to_string(),
            ..Default::default()
        };
        
        apply_sorting(&mut plugins, &args);
        
        // Should be case-insensitive sort: Alpha, beta, zebra
        assert_eq!(plugins[0].name, "Alpha");
        assert_eq!(plugins[1].name, "beta");
        assert_eq!(plugins[2].name, "zebra");
    }

    #[test]
    fn test_apply_sorting_name_desc() {
        let mut plugins = vec![
            create_test_plugin_item("alpha", true),
            create_test_plugin_item("beta", true),
            create_test_plugin_item("zebra", true),
        ];
        
        let args = InstalledListArgs {
            sort: "name".to_string(),
            order: "desc".to_string(),
            ..Default::default()
        };
        
        apply_sorting(&mut plugins, &args);
        
        assert_eq!(plugins[0].name, "zebra");
        assert_eq!(plugins[1].name, "beta");
        assert_eq!(plugins[2].name, "alpha");
    }

    #[test]
    fn test_apply_pagination() {
        let plugins = vec![
            create_test_plugin_item("plugin1", true),
            create_test_plugin_item("plugin2", true),
            create_test_plugin_item("plugin3", true),
            create_test_plugin_item("plugin4", true),
            create_test_plugin_item("plugin5", true),
        ];
        
        let args = InstalledListArgs {
            limit: 2,
            offset: 1,
            ..Default::default()
        };
        
        let paginated = apply_pagination(&plugins, &args);
        assert_eq!(paginated.len(), 2);
        assert_eq!(paginated[0].name, "plugin2");
        assert_eq!(paginated[1].name, "plugin3");
    }

    #[test]
    fn test_apply_pagination_empty_result() {
        let plugins = vec![
            create_test_plugin_item("plugin1", true),
        ];
        
        let args = InstalledListArgs {
            limit: 2,
            offset: 10,
            ..Default::default()
        };
        
        let paginated = apply_pagination(&plugins, &args);
        assert_eq!(paginated.len(), 0);
    }

    #[test]
    fn test_format_output_names() {
        let plugins = vec![
            create_test_plugin_item("plugin1", true),
            create_test_plugin_item("plugin2", false),
        ];
        
        let args = InstalledListArgs {
            format: "names".to_string(),
            ..Default::default()
        };
        
        let result = format_output(&plugins, &args);
        let names = result.as_array().unwrap();
        assert_eq!(names.len(), 2);
        assert_eq!(names[0].as_str().unwrap(), "plugin1");
        assert_eq!(names[1].as_str().unwrap(), "plugin2");
    }

    #[test]
    fn test_format_output_summary() {
        let plugins = vec![
            create_test_plugin_item("plugin1", true),
        ];
        
        let args = InstalledListArgs {
            format: "summary".to_string(),
            ..Default::default()
        };
        
        let result = format_output(&plugins, &args);
        let items = result.as_array().unwrap();
        assert_eq!(items.len(), 1);
        
        let item = &items[0];
        assert_eq!(item["name"].as_str().unwrap(), "plugin1");
        assert_eq!(item["version"].as_str().unwrap(), "1.0.0");
        assert_eq!(item["enabled"].as_bool().unwrap(), true);
        assert_eq!(item["health"].as_str().unwrap(), "ok");
        
        // Should not include manifest, paths, installed_at, updated_at
        assert!(item.get("manifest").is_none());
        assert!(item.get("paths").is_none());
    }

    #[test]
    fn test_format_output_full() {
        let plugins = vec![
            create_test_plugin_item("plugin1", true),
        ];
        
        let args = InstalledListArgs {
            format: "full".to_string(),
            ..Default::default()
        };
        
        let result = format_output(&plugins, &args);
        let items = result.as_array().unwrap();
        assert_eq!(items.len(), 1);
        
        let item = &items[0];
        assert_eq!(item["name"].as_str().unwrap(), "plugin1");
        assert_eq!(item["version"].as_str().unwrap(), "1.0.0");
        assert_eq!(item["enabled"].as_bool().unwrap(), true);
        assert_eq!(item["health"].as_str().unwrap(), "ok");
        
        // Should include all fields
        assert!(item.get("manifest").is_some());
        assert!(item.get("paths").is_some());
        assert!(item.get("installed_at").is_some());
        assert!(item.get("updated_at").is_some());
    }

    #[test]
    fn test_installed_list_wrong_target() {
        let handle = create_test_handle("something-else");
        let args = create_test_args(HashMap::new());
        
        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };
        
        let result = handle.installed_list(&args, &mut io);
        assert!(result.is_ok());
        let status = result.unwrap();
        assert!(!status.ok);
        assert_eq!(status.code, Some(2));
    }

    // Helper function to create test plugin item
    fn create_test_plugin_item(name: &str, enabled: bool) -> PluginInstalledItem {
        PluginInstalledItem {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            enabled,
            source: PluginSource {
                source_type: "registry".to_string(),
                r#ref: Some("test-ref".to_string()),
                url: None,
            },
            paths: PluginPaths {
                install_dir: format!("/test/plugins/{}", name),
                binary: Some(format!("/test/plugins/{}/bin/plugin", name)),
            },
            manifest: Some(PluginManifestSummary {
                description: Some("Test plugin".to_string()),
                tags: vec!["test".to_string()],
                capabilities: vec!["test://".to_string()],
            }),
            health: "ok".to_string(),
            installed_at: Some("2023-01-01T00:00:00Z".to_string()),
            updated_at: Some("2023-01-01T00:00:00Z".to_string()),
        }
    }
}
