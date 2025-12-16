use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Arguments for the available.info verb
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailableInfoArgs {
    pub name: Option<String>,
    pub id: Option<String>,
    pub version: Option<String>,
    pub channel: String,
    pub os: Option<String>,
    pub arch: Option<String>,
    pub include: String,
    pub timeout_ms: u32,
    pub source: String,
    pub offline: bool,
}

impl Default for AvailableInfoArgs {
    fn default() -> Self {
        Self {
            name: None,
            id: None,
            version: None,
            channel: "stable".to_string(),
            os: None,
            arch: None,
            include: "core".to_string(),
            timeout_ms: 5000,
            source: "default".to_string(),
            offline: false,
        }
    }
}

/// Action record for envelope actions array
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRecord {
    pub r#type: String,
    pub id: String,
    pub ok: bool,
    pub detail: String,
    pub meta: serde_json::Value,
}

/// Error structure for error envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorInfo {
    pub code: String,
    pub message: String,
    pub details: serde_json::Value,
}

/// Main envelope structure for available.info responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailableInfoEnvelope {
    pub op: String,
    pub ok: bool,
    pub target: String,
    pub ts: String,
    pub args: AvailableInfoArgs,
    pub actions: Vec<ActionRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<AvailableInfoResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorInfo>,
}

/// Result structure for successful available.info responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailableInfoResult {
    pub plugin: PluginInfo,
}

/// Detailed plugin information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub version: String,
    pub channel: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(default)]
    pub authors: Vec<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub handles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verbs: Option<HashMap<String, Vec<String>>>,
    pub compatibility: CompatibilityInfo,
    #[serde(default)]
    pub assets: Vec<AssetInfo>,
    #[serde(default)]
    pub dependencies: Vec<DependencyInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readme: Option<ReadmeInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<ReleaseInfo>,
}

/// Compatibility information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityInfo {
    pub resh_min: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resh_max: Option<String>,
    #[serde(default)]
    pub os: Vec<String>,
    #[serde(default)]
    pub arch: Vec<String>,
}

/// Asset information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetInfo {
    pub kind: String,
    pub os: String,
    pub arch: String,
    pub url: String,
    pub size: u64,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<SignatureInfo>,
}

/// Signature information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    pub r#type: String,
    pub value: String,
}

/// Dependency information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyInfo {
    pub name: String,
    pub version: String,
}

/// Readme information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadmeInfo {
    pub r#type: String,
    pub value: String,
}

/// Release information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseInfo {
    pub published_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Index snapshot containing plugin data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexSnapshot {
    pub id: String,
    pub kind: IndexKind,
    pub url: Option<String>,
    pub plugins: Vec<IndexPluginEntry>,
    pub fetched_at: DateTime<Utc>,
    pub ttl_seconds: u64,
}

/// Type of index
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IndexKind {
    Official,
    Community,
    Custom(String),
}

impl IndexKind {
    pub fn priority(&self) -> u32 {
        match self {
            IndexKind::Official => 0,
            IndexKind::Community => 1,
            IndexKind::Custom(_) => 2,
        }
    }
}

/// Plugin entry in an index
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexPluginEntry {
    pub id: String,
    pub name: String,
    pub versions: Vec<PluginVersion>,
}

/// Plugin version information from index
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginVersion {
    pub version: String,
    pub channel: String,
    pub plugin_info: PluginInfo,
}

/// Plugin selector for finding specific plugins
#[derive(Debug, Clone)]
pub struct PluginSelector {
    pub name: Option<String>,
    pub id: Option<String>,
    pub version: Option<String>,
    pub channel: String,
    pub os: Option<String>,
    pub arch: Option<String>,
}

/// Plugin resolution result
#[derive(Debug, Clone)]
pub struct PluginResolved {
    pub plugin: PluginInfo,
    pub source_index: String,
}

/// Error codes for available.info operations
#[derive(Debug, Clone)]
pub enum AvailableInfoErrorCode {
    InvalidArg,
    NotFound,
    Timeout,
    IndexUnavailable,
    Io,
}

impl AvailableInfoErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            AvailableInfoErrorCode::InvalidArg => "ERR_INVALID_ARG",
            AvailableInfoErrorCode::NotFound => "ERR_NOT_FOUND",
            AvailableInfoErrorCode::Timeout => "ERR_TIMEOUT",
            AvailableInfoErrorCode::IndexUnavailable => "ERR_INDEX_UNAVAILABLE",
            AvailableInfoErrorCode::Io => "ERR_IO",
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            AvailableInfoErrorCode::InvalidArg => 2,
            AvailableInfoErrorCode::NotFound => 3,
            AvailableInfoErrorCode::Timeout => 124,
            AvailableInfoErrorCode::IndexUnavailable => 69,
            AvailableInfoErrorCode::Io => 74,
        }
    }
}