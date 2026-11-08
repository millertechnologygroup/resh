use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::handles::pluginh::common::CaFile;

/// The JSON result of `install`, `update`, `remove`, `enable` and `disable`.
#[derive(Debug, Clone, Serialize)]
pub struct Envelope {
    pub op: String,
    pub ok: bool,
    /// The exit status: 0, 1, 2 or 124.
    pub code: i32,
    pub target: TargetInfo,
    pub args: serde_json::Value,
    pub actions: Vec<Action>,
    pub result: serde_json::Value,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// `{"code": "plugin.<name>", "message": ...}` on failure.
    pub error: Option<serde_json::Value>,
    pub ts: String,
}

/// The plugin a lifecycle verb acts on.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TargetInfo {
    pub name: String,
    pub requested_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub install_root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bin_path: Option<String>,
}

/// One step of a lifecycle verb, in the order the steps ran.
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

/// Steps recorded by a lifecycle verb.
#[derive(Debug, Default)]
pub struct Actions(pub Vec<Action>);

impl Actions {
    pub fn push(
        &mut self,
        action_type: &str,
        name: impl Into<String>,
        ok: bool,
        details: Option<serde_json::Value>,
    ) {
        let id = format!("{action_type}-{}", self.0.len());
        self.0.push(Action {
            id,
            action_type: action_type.to_string(),
            name: name.into(),
            ok,
            details,
        });
    }
}

/// Lifecycle verb.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Mode {
    Install,
    Update,
    Remove,
    Rollback,
}

/// Where an artifact comes from.
#[derive(Debug, Clone)]
pub enum SourceSpec {
    Registry { url: url::Url },
    Url { url: url::Url },
    File { path: String },
}

impl SourceSpec {
    pub fn kind(&self) -> &'static str {
        match self {
            SourceSpec::Registry { .. } => "registry",
            SourceSpec::Url { .. } => "url",
            SourceSpec::File { .. } => "file",
        }
    }
}

#[derive(Debug, Clone)]
pub enum RequestedVersion {
    Latest,
    Specific(String),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VerifyMode {
    Sha256,
    None,
}

impl VerifyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            VerifyMode::Sha256 => "sha256",
            VerifyMode::None => "none",
        }
    }
}

/// Parsed arguments of install, update and remove.
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
    pub ca_file: Option<CaFile>,
    /// Install a registry artifact without a trusted signature.
    pub allow_unsigned: bool,
    /// An extra trusted publisher key for this call.
    pub trust_key: Option<ed25519_dalek::VerifyingKey>,
    /// Stream progress events.
    pub progress: bool,
}

/// One version of a registry entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub platforms: HashMap<String, PlatformSpec>,
}

/// The artifact of one version for one `<os>-<arch>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformSpec {
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub arch: Option<String>,
    pub bin: String,
    #[serde(default)]
    pub sha256: Option<String>,
    /// Base64 Ed25519 signature (see `sign.rs` for the signed bytes).
    #[serde(default)]
    pub signature: Option<String>,
    /// Id of the signing key.
    #[serde(default)]
    pub key_id: Option<String>,
}

/// `GET <registry>/v1/plugins/<id>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub plugin_id: String,
    pub versions: HashMap<String, PluginManifest>,
}

/// `metadata.json` of an installed version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPlugin {
    pub plugin_id: String,
    pub version: String,
    pub install_path: String,
    pub bin_path: Option<String>,
    /// When the plugin was first installed (kept across updates).
    pub installed_at: String,
    /// When this version was installed.
    #[serde(default)]
    pub updated_at: Option<String>,
    /// `registry`, `url` or `file`.
    pub source: String,
    pub sha256: Option<String>,
}

/// A resolved artifact.
#[derive(Debug, Clone)]
pub struct ArtifactCandidate {
    /// `tar.gz` or `binary`.
    pub kind: String,
    pub url: Option<url::Url>,
    pub path: Option<String>,
    /// The trusted SHA-256 (lower-case hex) when one is known.
    pub sha256: Option<String>,
    pub version: String,
    pub signature: Option<String>,
    pub key_id: Option<String>,
}

/// What install or update will do.
#[derive(Debug, Clone)]
pub enum PlanDecision {
    Install { from: Option<String> },
    NoOp { reason: String },
}
