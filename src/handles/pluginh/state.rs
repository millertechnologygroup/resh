use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use super::plugin::types::{Action, PluginResult, StructuredError, error_codes, Envelope, TargetInfo, ArgsInfo};

/// Plugin state management with enable/disable operations following the unified envelope format
pub struct PluginStateManager {
    store: super::plugin::store::PluginStore,
}

/// Plugin state file structure (normalized across user/system scopes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginState {
    pub enabled_plugins: HashMap<String, bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_plugins: Option<HashMap<String, InstalledPluginInfo>>,
}

/// Cached installed plugin info for performance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPluginInfo {
    pub version: String,
    pub install_path: String,
}

/// Arguments for set_enabled_state helper
#[derive(Debug, Clone)]
pub struct SetEnabledOptions {
    pub scope: Scope,
    pub force: bool,
    pub timeout_ms: u64,
    pub dry_run: bool,
    pub reason: String,
}

/// Scope enumeration for type safety
#[derive(Debug, Clone, PartialEq)]
pub enum Scope {
    User,
    System,
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Scope::User => write!(f, "user"),
            Scope::System => write!(f, "system"),
        }
    }
}

impl PluginStateManager {
    /// Create new state manager
    pub fn new() -> Result<Self> {
        let store = super::plugin::store::PluginStore::new()?;
        Ok(Self { store })
    }

    /// Shared helper for enable/disable operations - uses same envelope format
    pub fn set_enabled_state(
        &mut self,
        plugin_name: &str,
        scope: Scope,
        enabled: bool,
        opts: SetEnabledOptions
    ) -> Result<Envelope> {
        let start_time = std::time::Instant::now();
        let mut actions = Vec::new();
        
        let op = if enabled { "plugin.enable" } else { "plugin.disable" };
        let target = format!("plugin://{}", plugin_name);
        
        // Step 1: Validate plugin name
        let action_id = format!("{}:validate:{}:{}", op, plugin_name, scope);
        if let Err(e) = self.validate_plugin_name(plugin_name) {
            self.add_action(&mut actions, &action_id, "validate", "validate plugin name", false, None);
            return Ok(self.build_error_envelope(op, &target, &opts, actions, error_codes::INVALID_ARGUMENT, &e.to_string()));
        }
        self.add_action(&mut actions, &action_id, "validate", "validate plugin name", true, Some(serde_json::json!({"name": plugin_name})));

        // Step 2: Check if plugin is installed
        let action_id = format!("{}:check_installed:{}:{}", op, plugin_name, scope);
        let installed_metadata = match self.store.get_installed_metadata(plugin_name) {
            Ok(Some(metadata)) => {
                self.add_action(&mut actions, &action_id, "check", "verify plugin installation", true, 
                    Some(serde_json::json!({"version": metadata.version, "path": metadata.install_path})));
                metadata
            }
            Ok(None) => {
                self.add_action(&mut actions, &action_id, "check", "verify plugin installation", false, None);
                return Ok(self.build_error_envelope(op, &target, &opts, actions, error_codes::PLUGIN_NOT_INSTALLED, 
                    &format!("Plugin '{}' is not installed", plugin_name)));
            }
            Err(e) => {
                self.add_action(&mut actions, &action_id, "check", "verify plugin installation", false, 
                    Some(serde_json::json!({"error": e.to_string()})));
                return Ok(self.build_error_envelope(op, &target, &opts, actions, error_codes::PLUGIN_IO_ERROR, 
                    &format!("Failed to check plugin installation: {}", e)));
            }
        };

        // Step 3: Check current state and permissions
        let action_id = format!("{}:state_read:{}:{}", op, plugin_name, scope);
        let (mut state, state_path) = match self.load_plugin_state(&scope) {
            Ok((state, path)) => {
                self.add_action(&mut actions, &action_id, "fs.read", "load plugin state", true, 
                    Some(serde_json::json!({"path": path.to_string_lossy()})));
                (state, path)
            }
            Err(e) => {
                self.add_action(&mut actions, &action_id, "fs.read", "load plugin state", false, 
                    Some(serde_json::json!({"error": e.to_string()})));
                
                // Check permission errors specifically
                if e.to_string().contains("Permission denied") || e.to_string().contains("Access is denied") {
                    return Ok(self.build_error_envelope(op, &target, &opts, actions, error_codes::PERMISSION_DENIED, 
                        &format!("Permission denied accessing {} scope state", scope)));
                }
                
                return Ok(self.build_error_envelope(op, &target, &opts, actions, error_codes::PLUGIN_IO_ERROR, 
                    &format!("Failed to load plugin state: {}", e)));
            }
        };

        // Step 4: Check current enabled state
        let was_enabled = state.enabled_plugins.get(plugin_name).copied().unwrap_or(false);
        
        // Step 5: Check for conflicts (when force=false)
        if !opts.force {
            if enabled && was_enabled {
                // Already enabled - idempotent operation
                let action_id = format!("{}:state_write:{}:{}", op, plugin_name, scope);
                self.add_action(&mut actions, &action_id, "state.change", "plugin already enabled", true, 
                    Some(serde_json::json!({"change": "none", "was_enabled": was_enabled})));
                
                return Ok(self.build_success_envelope(op, &target, &opts, actions, &installed_metadata, enabled, was_enabled, false));
            }
            
            if !enabled && !was_enabled {
                // Already disabled - idempotent operation  
                let action_id = format!("{}:state_write:{}:{}", op, plugin_name, scope);
                self.add_action(&mut actions, &action_id, "state.change", "plugin already disabled", true, 
                    Some(serde_json::json!({"change": "none", "was_enabled": was_enabled})));
                
                return Ok(self.build_success_envelope(op, &target, &opts, actions, &installed_metadata, enabled, was_enabled, false));
            }
        }

        // Step 6: Check if plugin is in use (optional, best effort)
        let action_id = format!("{}:check_in_use:{}:{}", op, plugin_name, scope);
        if let Err(conflict_reason) = self.check_plugin_in_use(plugin_name) {
            if !opts.force {
                self.add_action(&mut actions, &action_id, "check", "check if plugin is in use", false, 
                    Some(serde_json::json!({"reason": conflict_reason.to_string()})));
                return Ok(self.build_error_envelope(op, &target, &opts, actions, error_codes::PLUGIN_IN_USE, 
                    &format!("Plugin is in use: {}. Use force=true to override.", conflict_reason)));
            } else {
                self.add_action(&mut actions, &action_id, "check", "plugin in use but forced", true, 
                    Some(serde_json::json!({"reason": conflict_reason.to_string(), "forced": true})));
            }
        } else {
            self.add_action(&mut actions, &action_id, "check", "plugin not in use", true, None);
        }

        // Step 7: Apply state change (unless dry run)
        let action_id = format!("{}:state_write:{}:{}", op, plugin_name, scope);
        if opts.dry_run {
            self.add_action(&mut actions, &action_id, "fs.write", 
                &format!("would {} plugin", if enabled { "enable" } else { "disable" }), true,
                Some(serde_json::json!({"dry_run": true, "path": state_path.to_string_lossy()})));
            
            return Ok(self.build_success_envelope(op, &target, &opts, actions, &installed_metadata, enabled, was_enabled, false));
        }

        // Update state
        state.enabled_plugins.insert(plugin_name.to_string(), enabled);
        
        // Update installed plugins cache (best effort)
        if state.installed_plugins.is_none() {
            state.installed_plugins = Some(HashMap::new());
        }
        if let Some(ref mut installed) = state.installed_plugins {
            installed.insert(plugin_name.to_string(), InstalledPluginInfo {
                version: installed_metadata.version.clone(),
                install_path: installed_metadata.install_path.clone(),
            });
        }

        // Step 8: Atomic write of state
        match self.save_plugin_state(&scope, &state) {
            Ok(()) => {
                let action_summary = format!("{} plugin in {} scope", 
                    if enabled { "enabled" } else { "disabled" }, scope);
                self.add_action(&mut actions, &action_id, "fs.write", &action_summary, true,
                    Some(serde_json::json!({
                        "path": state_path.to_string_lossy(),
                        "enabled": enabled,
                        "was_enabled": was_enabled
                    })));
                
                Ok(self.build_success_envelope(op, &target, &opts, actions, &installed_metadata, enabled, was_enabled, true))
            }
            Err(e) => {
                self.add_action(&mut actions, &action_id, "fs.write", &format!("failed to save state: {}", e), false, 
                    Some(serde_json::json!({"error": e.to_string()})));
                Ok(self.build_error_envelope(op, &target, &opts, actions, error_codes::PLUGIN_IO_ERROR, 
                    &format!("Failed to save plugin state: {}", e)))
            }
        }
    }

    /// Validate plugin name according to spec requirements
    fn validate_plugin_name(&self, name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(anyhow!("Plugin name cannot be empty"));
        }
        
        if name.len() > 64 {
            return Err(anyhow!("Plugin name too long (max 64 characters)"));
        }
        
        if name.contains("..") || name.contains('/') {
            return Err(anyhow!("Plugin name contains invalid path separators"));
        }
        
        // Check allowed characters: [a-z0-9][a-z0-9._-]{0,63}
        let normalized = name.to_lowercase();
        if normalized != name {
            return Err(anyhow!("Plugin name must be lowercase"));
        }
        
        let chars: Vec<char> = normalized.chars().collect();
        if chars.is_empty() {
            return Err(anyhow!("Plugin name cannot be empty"));
        }
        
        // First character must be alphanumeric
        if !chars[0].is_ascii_alphanumeric() {
            return Err(anyhow!("Plugin name must start with alphanumeric character"));
        }
        
        // Remaining characters can include ._-
        for &c in &chars[1..] {
            if !(c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-') {
                return Err(anyhow!("Plugin name contains invalid character: '{}'", c));
            }
        }
        
        Ok(())
    }

    /// Check if plugin is currently in use (best effort detection)
    fn check_plugin_in_use(&self, _plugin_name: &str) -> Result<()> {
        // For now, implement minimal lock file check
        // Future: could check running resh daemon, active processes, etc.
        
        // TODO: Check for lock files or other in-use indicators
        // This is a placeholder that always succeeds for now
        Ok(())
    }

    /// Load plugin state from disk
    fn load_plugin_state(&self, scope: &Scope) -> Result<(PluginState, PathBuf)> {
        let state_path = self.get_state_path(scope)?;
        
        if !state_path.exists() {
            // Create default state
            let state = PluginState {
                enabled_plugins: HashMap::new(),
                installed_plugins: Some(HashMap::new()),
            };
            return Ok((state, state_path));
        }
        
        let contents = fs::read_to_string(&state_path)
            .with_context(|| format!("Failed to read state file: {}", state_path.display()))?;
        
        if contents.trim().is_empty() {
            let state = PluginState {
                enabled_plugins: HashMap::new(),
                installed_plugins: Some(HashMap::new()),
            };
            return Ok((state, state_path));
        }
        
        let state: PluginState = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse state file: {}", state_path.display()))?;
        
        Ok((state, state_path))
    }

    /// Save plugin state atomically
    fn save_plugin_state(&self, scope: &Scope, state: &PluginState) -> Result<()> {
        let state_path = self.get_state_path(scope)?;
        
        // Create parent directory if needed
        if let Some(parent) = state_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create state directory: {}", parent.display()))?;
        }
        
        // Serialize with stable ordering
        let json_content = serde_json::to_string_pretty(state)
            .context("Failed to serialize plugin state")?;
        
        // Atomic write: temp file + rename
        let temp_path = state_path.with_extension("state.json.tmp");
        fs::write(&temp_path, &json_content)
            .with_context(|| format!("Failed to write temp state file: {}", temp_path.display()))?;
        
        // Best effort fsync
        if let Ok(file) = std::fs::File::open(&temp_path) {
            let _ = file.sync_all();
        }
        
        fs::rename(&temp_path, &state_path)
            .with_context(|| format!("Failed to atomically update state file: {}", state_path.display()))?;
        
        Ok(())
    }

    /// Get state file path for scope
    fn get_state_path(&self, scope: &Scope) -> Result<PathBuf> {
        match scope {
            Scope::User => {
                // Use XDG_STATE_HOME if available, fallback to config dir
                let state_dir = std::env::var("XDG_STATE_HOME")
                    .map(PathBuf::from)
                    .or_else(|_| {
                        dirs::config_dir()
                            .map(|d| d.join("resh").join("state"))
                            .ok_or_else(|| anyhow!("Could not determine user home directory"))
                    })?;
                
                Ok(state_dir.join("resh").join("plugins").join("state.json"))
            }
            Scope::System => {
                Ok(PathBuf::from("/var/lib/resh/plugins/state.json"))
            }
        }
    }

    /// Add deterministic action
    fn add_action(
        &self,
        actions: &mut Vec<Action>,
        id: &str,
        kind: &str,
        summary: &str,
        ok: bool,
        details: Option<serde_json::Value>,
    ) {
        actions.push(Action {
            id: id.to_string(),
            action_type: kind.to_string(),
            name: summary.to_string(),
            ok,
            details,
        });
    }

    /// Build successful envelope response
    fn build_success_envelope(
        &self,
        op: &str,
        target: &str,
        opts: &SetEnabledOptions,
        actions: Vec<Action>,
        installed_metadata: &super::plugin::types::InstalledPlugin,
        enabled: bool,
        was_enabled: bool,
        changed: bool,
    ) -> Envelope {
        let target_info = TargetInfo {
            name: installed_metadata.plugin_id.clone(),
            requested_name: installed_metadata.plugin_id.clone(),
            version: Some(installed_metadata.version.clone()),
            install_root: installed_metadata.install_path.clone(),
            bin_path: installed_metadata.bin_path.clone(),
        };
        
        let args_info = ArgsInfo {
            force: if opts.force { Some(opts.force) } else { None },
            purge: None, // Not applicable
            dry_run: if opts.dry_run { Some(opts.dry_run) } else { None },
            timeout_ms: Some(opts.timeout_ms),
        };
        
        let result = PluginResult {
            removed: None,
            purged: None,
            installed: Some(true),
            previous_version: None,
            version: Some(installed_metadata.version.clone()),
            enabled: Some(enabled),
            was_enabled: Some(was_enabled),
        };
        
        Envelope {
            op: op.to_string(),
            ok: true,
            code: 0,
            target: target_info,
            args: args_info,
            actions,
            result,
            warnings: vec![],
            error: None,
            ts: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Build error envelope response
    fn build_error_envelope(
        &self,
        op: &str,
        target: &str,
        opts: &SetEnabledOptions,
        actions: Vec<Action>,
        error_kind: &str,
        message: &str,
    ) -> Envelope {
        use super::plugin::types::error_code_to_numeric;
        
        let target_info = TargetInfo {
            name: "".to_string(), // Unknown when error occurs
            requested_name: target.strip_prefix("plugin://").unwrap_or(target).to_string(),
            version: None,
            install_root: "".to_string(),
            bin_path: None,
        };
        
        let args_info = ArgsInfo {
            force: if opts.force { Some(opts.force) } else { None },
            purge: None,
            dry_run: if opts.dry_run { Some(opts.dry_run) } else { None },
            timeout_ms: Some(opts.timeout_ms),
        };
        
        let result = PluginResult {
            removed: None,
            purged: None,
            installed: Some(false),
            previous_version: None,
            version: None,
            enabled: Some(false),
            was_enabled: None,
        };
        
        let code = error_code_to_numeric(error_kind);
        
        Envelope {
            op: op.to_string(),
            ok: false,
            code,
            target: target_info,
            args: args_info,
            actions,
            result,
            warnings: vec![],
            error: Some(StructuredError {
                kind: error_kind.to_string(),
                message: message.to_string(),
                details: serde_json::json!({}),
            }),
            ts: chrono::Utc::now().to_rfc3339(),
        }
    }
}