use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Plugin operation envelope structure that matches specification exactly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub op: String,
    pub ok: bool,
    pub code: i32,
    pub target: TargetInfo,
    pub args: ArgsInfo,
    pub actions: Vec<Action>,
    pub result: PluginResult,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<StructuredError>,
    pub ts: String,
}

/// Enable-specific envelope structure that matches specification exactly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnableEnvelope {
    pub op: String,
    pub target: EnableTargetInfo,
    pub ok: bool,
    pub changed: bool,
    pub actions: Vec<EnableAction>,
    pub result: EnableResult,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<EnableError>,
}

/// Target information for plugin operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    pub name: String,
    pub requested_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub install_root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bin_path: Option<String>,
}

/// Target information for enable operations  
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnableTargetInfo {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Args information for plugin operations  
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgsInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purge: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// Action performed during plugin operation (deterministic ordering)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub id: String,
    #[serde(rename = "type")]
    pub action_type: String,
    pub name: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Action performed during enable operation (matches spec format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnableAction {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Plugin operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purged: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    // Enable-specific fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub was_enabled: Option<bool>,
}

/// Enable-specific result structure that matches specification exactly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnableResult {
    pub enabled: bool,
    pub was_enabled: bool,
    pub installed: bool,
    pub version: String,
}

/// Artifact information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactInfo {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// Path information for installed plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathInfo {
    pub root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bin: Option<String>,
}

/// Structured error with machine-readable codes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredError {
    pub kind: String,
    pub message: String,
    pub details: serde_json::Value,
}

/// Enable-specific error structure that matches specification exactly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnableError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

/// Error codes as specified in requirements
pub mod error_codes {
    pub const PLUGIN_INVALID_TARGET: &str = "PLUGIN_INVALID_TARGET";
    pub const PLUGIN_REGISTRY_UNAVAILABLE: &str = "PLUGIN_REGISTRY_UNAVAILABLE";
    pub const PLUGIN_NOT_FOUND: &str = "PLUGIN_NOT_FOUND";
    pub const PLUGIN_MANIFEST_INVALID: &str = "PLUGIN_MANIFEST_INVALID";
    pub const PLUGIN_PLATFORM_UNSUPPORTED: &str = "PLUGIN_PLATFORM_UNSUPPORTED";
    pub const PLUGIN_ALREADY_INSTALLED: &str = "PLUGIN_ALREADY_INSTALLED";
    pub const PLUGIN_NOT_INSTALLED: &str = "PLUGIN_NOT_INSTALLED";
    pub const PLUGIN_VERSION_INVALID: &str = "PLUGIN_VERSION_INVALID";
    pub const PLUGIN_NO_UPDATE_AVAILABLE: &str = "PLUGIN_NO_UPDATE_AVAILABLE";
    pub const PLUGIN_DOWNLOAD_FAILED: &str = "PLUGIN_DOWNLOAD_FAILED";
    pub const PLUGIN_VERIFY_FAILED: &str = "PLUGIN_VERIFY_FAILED";
    pub const PLUGIN_EXTRACT_FAILED: &str = "PLUGIN_EXTRACT_FAILED";
    pub const PLUGIN_INSTALL_FAILED: &str = "PLUGIN_INSTALL_FAILED";
    pub const PLUGIN_ACTIVATE_FAILED: &str = "PLUGIN_ACTIVATE_FAILED";
    pub const PLUGIN_IN_USE: &str = "PLUGIN_IN_USE";
    pub const PLUGIN_VERSION_CONFLICT: &str = "PLUGIN_VERSION_CONFLICT";
    pub const PLUGIN_REMOVE_FAILED: &str = "PLUGIN_REMOVE_FAILED";
    pub const PLUGIN_TIMEOUT: &str = "PLUGIN_TIMEOUT";
    pub const PLUGIN_IO_ERROR: &str = "PLUGIN_IO_ERROR";
    // Enable-specific error codes
    pub const PLUGIN_ALREADY_ENABLED: &str = "PLUGIN_ALREADY_ENABLED";
    pub const PLUGIN_VERSION_MISMATCH: &str = "PLUGIN_VERSION_MISMATCH";
    pub const PLUGIN_INVALID: &str = "PLUGIN_INVALID";
    pub const PERMISSION_DENIED: &str = "PERMISSION_DENIED";
    pub const INVALID_ARGUMENT: &str = "INVALID_ARGUMENT";
}

/// Map error codes to numeric exit codes as per specification
pub fn error_code_to_numeric(error_code: &str) -> i32 {
    match error_code {
        // Requirements spec error codes
        "not_found" => 2,
        "not_installed" => 3, 
        "invalid_name" => 10,
        "permission_denied" => 13,
        "timeout" => 24,
        "conflict" => 29,
        "io" => 74,
        "internal" => 70,
        
        // Legacy error codes (keep for compatibility)
        error_codes::INVALID_ARGUMENT => 10,
        error_codes::PLUGIN_INVALID_TARGET => 10,
        error_codes::PLUGIN_NOT_FOUND => 2,
        error_codes::PLUGIN_NOT_INSTALLED => 3,
        error_codes::PLUGIN_REGISTRY_UNAVAILABLE => 3,
        error_codes::PLUGIN_VERIFY_FAILED => 4,
        error_codes::PLUGIN_MANIFEST_INVALID => 4,
        error_codes::PLUGIN_PLATFORM_UNSUPPORTED => 4,
        error_codes::PLUGIN_INSTALL_FAILED => 5,
        error_codes::PLUGIN_ACTIVATE_FAILED => 5,
        error_codes::PLUGIN_EXTRACT_FAILED => 5,
        error_codes::PLUGIN_ALREADY_INSTALLED => 5,
        error_codes::PLUGIN_VERSION_INVALID => 5,
        error_codes::PLUGIN_NO_UPDATE_AVAILABLE => 5,
        error_codes::PLUGIN_DOWNLOAD_FAILED => 5,
        error_codes::PLUGIN_IN_USE => 29,
        error_codes::PLUGIN_VERSION_CONFLICT => 4,
        error_codes::PLUGIN_REMOVE_FAILED => 5,
        error_codes::PLUGIN_IO_ERROR => 74,
        error_codes::PLUGIN_TIMEOUT => 24,
        error_codes::PERMISSION_DENIED => 13,
        error_codes::PLUGIN_ALREADY_ENABLED => 5,
        error_codes::PLUGIN_VERSION_MISMATCH => 4,
        error_codes::PLUGIN_INVALID => 4,
        _ => 1,
    }
}

/// Plugin operation mode
#[derive(Debug, Clone, PartialEq)]
pub enum Mode {
    Install,
    Update,
    Remove,
    Enable,
    Disable,
}

/// Source specification for plugin acquisition
#[derive(Debug, Clone)]
pub enum SourceSpec {
    Registry { url: String },
    Url { url: String },
    File { path: String },
}

/// Requested version specification
#[derive(Debug, Clone)]
pub enum RequestedVersion {
    Latest,
    Specific(String),
}

/// Verification mode
#[derive(Debug, Clone, PartialEq)]
pub enum VerifyMode {
    Sha256,
    None,
}

/// Plugin operation arguments (unified for install/update/remove)
#[derive(Debug, Clone)]
pub struct PluginOpArgs {
    pub mode: Mode,
    pub plugin_id: String,
    pub source: SourceSpec,
    pub requested_version: RequestedVersion,
    pub verify: VerifyMode,
    pub force: bool,
    pub allow_downgrade: bool,
    pub dry_run: bool,
    pub strict: bool,
    pub purge: bool,
    pub timeout_ms: u64,
}

/// Plugin manifest structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub license: Option<String>,
    pub homepage: Option<String>,
    pub repository: Option<String>,
    pub keywords: Option<Vec<String>>,
    pub platforms: HashMap<String, PlatformSpec>,
}

/// Platform-specific specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformSpec {
    pub os: String,
    pub arch: String,
    pub bin: String,
    pub sha256: String,
}

/// Registry plugin entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub plugin_id: String,
    pub versions: HashMap<String, PluginManifest>,
}

/// Installed plugin metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPlugin {
    pub plugin_id: String,
    pub version: String,
    pub install_path: String,
    pub bin_path: Option<String>,
    pub installed_at: String,
    pub source: String,
    pub sha256: Option<String>,
}

/// Plan decision for plugin operation
#[derive(Debug, Clone)]
pub enum PlanDecision {
    Install {
        version: String,
        artifact: ArtifactCandidate,
    },
    Update {
        from_version: String,
        to_version: String,
        artifact: ArtifactCandidate,
    },
    NoOp {
        reason: String,
    },
    Error {
        code: String,
        message: String,
    },
}

/// Artifact candidate for installation
#[derive(Debug, Clone)]
pub struct ArtifactCandidate {
    pub kind: String,
    pub url: Option<String>,
    pub path: Option<String>,
    pub sha256: Option<String>,
    pub manifest: PluginManifest,
}

/// Action type constants for deterministic ordering
pub mod action_types {
    pub const RESOLVE: &str = "resolve";
    pub const CHECK_INSTALLED: &str = "check_installed";
    pub const CHECK_IN_USE: &str = "check_in_use";
    pub const DOWNLOAD: &str = "download";
    pub const VERIFY: &str = "verify";
    pub const EXTRACT: &str = "extract";
    pub const INSTALL: &str = "install";
    pub const ACTIVATE: &str = "activate";
    pub const REMOVE_MANIFEST: &str = "remove_manifest";
    pub const REMOVE_BIN: &str = "remove_bin";
    pub const REMOVE_SUPPORT_FILES: &str = "remove_support_files";
    pub const PURGE_STATE: &str = "purge_state";
    pub const SYNC_REGISTRY: &str = "sync_registry";
    pub const CLEANUP: &str = "cleanup";
    pub const ROLLBACK: &str = "rollback";
    // Enable-specific action types
    pub const LOAD_MANIFEST: &str = "load_manifest";
    pub const VALIDATE_ENTRYPOINT: &str = "validate_entrypoint";
    pub const LOAD_ENABLED_REGISTRY: &str = "load_enabled_registry";
    pub const WRITE_ENABLED_REGISTRY: &str = "write_enabled_registry";
}

/// Enabled plugin registry structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnabledRegistry {
    pub enabled: Vec<EnabledPlugin>,
}

impl EnabledRegistry {
    pub fn new() -> Self {
        Self {
            enabled: Vec::new(),
        }
    }
    
    pub fn is_enabled(&self, plugin_id: &str) -> bool {
        self.enabled.iter().any(|p| p.id == plugin_id)
    }
    
    pub fn get_enabled_version(&self, plugin_id: &str) -> Option<&str> {
        self.enabled.iter()
            .find(|p| p.id == plugin_id)
            .map(|p| p.version.as_str())
    }
    
    pub fn enable_plugin(&mut self, plugin_id: String, version: String) -> bool {
        // Remove existing entry if present
        self.enabled.retain(|p| p.id != plugin_id);
        
        // Add new entry
        self.enabled.push(EnabledPlugin {
            id: plugin_id,
            version,
        });
        
        // Sort by id for deterministic output
        self.enabled.sort_by(|a, b| a.id.cmp(&b.id));
        
        true
    }
    
    pub fn disable_plugin(&mut self, plugin_id: &str) -> bool {
        let initial_len = self.enabled.len();
        self.enabled.retain(|p| p.id != plugin_id);
        self.enabled.len() != initial_len
    }
}

/// Individual enabled plugin entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnabledPlugin {
    pub id: String,
    pub version: String,
}