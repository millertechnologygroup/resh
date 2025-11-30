use anyhow::{Result, bail};
use chrono::{Utc, SecondsFormat};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::process::Stdio;
use std::time::Duration;
use thiserror::Error;
use tokio::process::Command as AsyncCommand;
use tokio::time::timeout;
use url::Url;
use which::which;

use crate::core::{
    registry::{Args, Handle, IoStreams},
    status::Status,
};

/// Package manager error types
#[derive(Error, Debug)]
pub enum PkgError {
    #[error("Invalid install configuration: {0}")]
    InvalidInstallConfig(String),
    #[error("Manager not found: {0}")]
    ManagerNotFound(String),
    #[error("Manager not available: {0}")]
    ManagerNotAvailable(String),
    #[error("Update cache failed: {0}")]
    UpdateCacheFailed(String),
    #[error("Package not found: {0}")]
    InstallNotFound(String),
    #[error("Dependency failure: {0}")]
    InstallDependencyFailure(String),
    #[error("Install conflict: {0}")]
    InstallConflict(String),
    #[error("Permission denied: {0}")]
    InstallPermissionDenied(String),
    #[error("Invalid version: {0}")]
    InstallInvalidVersion(String),
    #[error("Install timeout")]
    InstallTimeout,
    #[error("Install failed: {0}")]
    InstallFailed(String),
    // Remove errors
    #[error("Invalid remove configuration: {0}")]
    InvalidRemoveConfig(String),
    #[error("Package not found for removal: {0}")]
    RemoveNotFound(String),
    #[error("Package not installed: {0}")]
    RemoveNotInstalled(String),
    #[error("Remove dependency failure: {0}")]
    RemoveDependencyFailure(String),
    #[error("Remove permission denied: {0}")]
    RemovePermissionDenied(String),
    #[error("Remove timeout")]
    RemoveTimeout,
    #[error("Remove failed: {0}")]
    RemoveFailed(String),
    // Update errors
    #[error("Invalid update configuration: {0}")]
    InvalidUpdateConfig(String),
    #[error("Update index failed: {0}")]
    UpdateIndexFailed(String),
    #[error("Update check failed: {0}")]
    UpdateCheckFailed(String),
    #[error("Update permission denied: {0}")]
    UpdatePermissionDenied(String),
    #[error("Update timeout")]
    UpdateTimeout,
    #[error("Update failed: {0}")]
    UpdateFailed(String),
    // Upgrade errors
    #[error("Invalid upgrade configuration: {0}")]
    InvalidUpgradeConfig(String),
    #[error("Upgrade index failed: {0}")]
    UpgradeIndexFailed(String),
    #[error("Upgrade check failed: {0}")]
    UpgradeCheckFailed(String),
    #[error("Upgrade permission denied: {0}")]
    UpgradePermissionDenied(String),
    #[error("Upgrade timeout")]
    UpgradeTimeout,
    #[error("Upgrade failed: {0}")]
    UpgradeFailed(String),
    // Info errors
    #[error("Invalid info configuration: {0}")]
    InvalidInfoConfig(String),
    #[error("Info timeout")]
    InfoTimeout,
    #[error("Info query failed: {0}")]
    InfoQueryFailed(String),
    #[error("Info partial failure: {0}")]
    InfoPartialFailure(String),
    // Search errors
    #[error("Invalid search configuration: {0}")]
    InvalidSearchConfig(String),
    #[error("Search timeout")]
    SearchTimeout,
    #[error("Search failed: {0}")]
    SearchFailed(String),
    // List installed errors
    #[error("Invalid list installed configuration: {0}")]
    InvalidListInstalledConfig(String),
    #[error("List installed timeout")]
    ListInstalledTimeout,
    #[error("List installed failed: {0}")]
    ListInstalledFailed(String),
    // Snapshot errors
    #[error("Invalid snapshot configuration: {0}")]
    InvalidSnapshotConfig(String),
    #[error("Snapshot timeout")]
    SnapshotTimeout,
    #[error("Snapshot failed: {0}")]
    SnapshotFailed(String),
    #[error("Snapshot scope unsupported: {0}")]
    SnapshotScopeUnsupported(String),
    // Restore errors
    #[error("Invalid restore configuration: {0}")]
    InvalidRestoreConfig(String),
    #[error("Invalid lockfile: {0}")]
    RestoreInvalidLockfile(String),
    #[error("Manager mismatch: {0}")]
    RestoreManagerMismatch(String),
    #[error("Platform incompatible: {0}")]
    RestorePlatformIncompatible(String),
    #[error("Restore timeout")]
    RestoreTimeout,
    #[error("Restore apply failed: {0}")]
    RestoreApplyFailed(String),
    #[error("Downgrade not supported: {0}")]
    RestoreDowngradeNotSupported(String),
    #[error("Repository not available: {0}")]
    RestoreRepoNotAvailable(String),
}

/// Supported package managers
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum ManagerKind {
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "apt")]
    Apt,
    #[serde(rename = "yum")]
    Yum,
    #[serde(rename = "dnf")]
    Dnf,
    #[serde(rename = "pacman")]
    Pacman,
    #[serde(rename = "apk")]
    Apk,
    #[serde(rename = "brew")]
    Brew,
}

/// Package specification
#[derive(Debug, Clone, Deserialize)]
pub struct PackageSpec {
    pub name: String,
    pub version: Option<String>,
    pub source: Option<String>,
}

/// Install configuration
#[derive(Debug, Clone, Deserialize)]
pub struct InstallConfig {
    pub manager: ManagerKind,
    pub packages: Vec<PackageSpec>,
    #[serde(default = "default_true")]
    pub update_cache: bool,
    #[serde(default = "default_true")]
    pub assume_yes: bool,
    #[serde(default = "default_true")]
    pub only_if_missing: bool,
    #[serde(default)]
    pub reinstall: bool,
    #[serde(default)]
    pub upgrade: bool,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    pub arch: Option<String>,
    pub extra_args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
}

fn default_true() -> bool { true }
fn default_timeout() -> u64 { 600000 } // 10 minutes

/// Remove configuration
#[derive(Debug, Clone, Deserialize)]
pub struct RemoveConfig {
    pub manager: ManagerKind,
    pub packages: Vec<PackageSpec>,
    #[serde(default)]
    pub purge: bool,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default = "default_true")]
    pub assume_yes: bool,
    #[serde(default = "default_true")]
    pub only_if_installed: bool,
    #[serde(default)]
    pub fail_if_missing: bool,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    pub arch: Option<String>,
    pub extra_args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
}

/// Update configuration
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateConfig {
    pub manager: ManagerKind,
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default = "default_true")]
    pub refresh_index: bool,
    #[serde(default = "default_true")]
    pub upgrade: bool,
    #[serde(default = "default_true")]
    pub assume_yes: bool,
    #[serde(default)]
    pub security_only: bool,
    #[serde(default)]
    pub check_only: bool,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default = "default_long_timeout")]
    pub timeout_ms: u64,
    pub extra_args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
}

fn default_long_timeout() -> u64 { 900000 } // 15 minutes

/// Upgrade configuration
#[derive(Debug, Clone, Deserialize)]
pub struct UpgradeConfig {
    pub manager: ManagerKind,
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default = "default_true")]
    pub refresh_index: bool,
    #[serde(default = "default_true")]
    pub assume_yes: bool,
    #[serde(default)]
    pub security_only: bool,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub check_only: bool,
    #[serde(default = "default_long_timeout")]
    pub timeout_ms: u64,
    pub extra_args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
}

/// Info configuration
#[derive(Debug, Clone, Deserialize)]
pub struct InfoConfig {
    pub manager: ManagerKind,
    pub packages: Vec<String>,
    #[serde(default)]
    pub include_dependencies: bool,
    #[serde(default)]
    pub include_reverse_deps: bool,
    #[serde(default)]
    pub include_files: bool,
    #[serde(default = "default_true")]
    pub include_repo: bool,
    #[serde(default = "default_info_timeout")]
    pub timeout_ms: u64,
    pub extra_args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
}

fn default_info_timeout() -> u64 { 5000 } // 5 seconds

/// Search field enum for specifying what fields to search in
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum SearchField {
    #[serde(rename = "name")]
    Name,
    #[serde(rename = "description")]
    Description,
    #[serde(rename = "all")]
    All,
}

/// Search configuration
#[derive(Debug, Clone, Deserialize)]
pub struct SearchConfig {
    pub manager: ManagerKind,
    pub query: String,
    #[serde(default = "default_search_in")]
    pub search_in: Vec<SearchField>,
    #[serde(default)]
    pub exact: bool,
    #[serde(default)]
    pub case_sensitive: bool,
    #[serde(default = "default_search_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_true")]
    pub include_installed: bool,
    #[serde(default = "default_true")]
    pub include_versions: bool,
    #[serde(default = "default_true")]
    pub include_repo: bool,
    #[serde(default = "default_info_timeout")]
    pub timeout_ms: u64,
    pub extra_args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
}

fn default_search_in() -> Vec<SearchField> {
    vec![SearchField::Name, SearchField::Description]
}

fn default_search_limit() -> u32 { 50 }

/// Individual search result
#[derive(Debug, Clone, Serialize)]
pub struct SearchResult {
    pub name: String,
    pub version: Option<String>,
    pub installed: bool,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub repository: Option<String>,
    pub homepage: Option<String>,
    #[serde(default = "default_score")]
    pub score: f64,
}

fn default_score() -> f64 { 1.0 }

/// Search results container
#[derive(Debug, Clone, Serialize)]
pub struct SearchResults {
    pub backend: String,
    pub manager: String,
    pub alias: String,
    pub query: String,
    pub search_in: Vec<SearchField>,
    pub exact: bool,
    pub case_sensitive: bool,
    pub limit: u32,
    pub offset: u32,
    pub total_matches: u32,
    pub results: Vec<SearchResult>,
}

/// Package dependencies structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageDependencies {
    #[serde(default)]
    pub runtime: Vec<String>,
    #[serde(default)]
    pub build: Vec<String>,
    #[serde(default)]
    pub optional: Vec<String>,
}

/// Individual package info result
#[derive(Debug, Clone, Serialize)]
pub struct PackageInfo {
    pub name: String,
    pub found: bool,
    pub installed: bool,
    pub installed_version: Option<String>,
    pub candidate_version: Option<String>,
    pub architecture: Option<String>,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub homepage: Option<String>,
    pub license: Option<String>,
    pub repository: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<PackageDependencies>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverse_dependencies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
}

/// Command output structure for internal use
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub status: std::process::ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

/// Available update information
#[derive(Debug, Clone, Serialize)]
pub struct AvailableUpdate {
    pub name: String,
    pub current_version: Option<String>,
    pub candidate_version: String,
    #[serde(default)]
    pub security: bool,
}

/// Update result for a package
#[derive(Debug, Clone, Serialize)]
pub struct UpdateResult {
    pub name: String,
    pub previous_version: Option<String>,
    pub new_version: Option<String>,
    pub action: String, // "upgraded", "unchanged"
}

/// Update summary
#[derive(Debug, Clone, Serialize)]
pub struct UpdateSummary {
    pub upgraded: u32,
    pub unchanged: u32,
    pub failed: u32,
}

/// Upgrade result for a package
#[derive(Debug, Clone, Serialize)]
pub struct UpgradeResult {
    pub name: String,
    pub previous_version: Option<String>,
    pub new_version: Option<String>,
    pub action: String, // "upgraded", "unchanged"
}

/// Upgrade summary
#[derive(Debug, Clone, Serialize)]
pub struct UpgradeSummary {
    pub upgraded: u32,
    pub unchanged: u32,
    pub failed: u32,
}

/// Package action result
#[derive(Debug, Clone, Serialize)]
pub struct PackageResult {
    pub name: String,
    pub requested_version: Option<String>,
    pub installed_version: Option<String>,
    pub action: String, // "installed", "upgraded", "reinstalled", "unchanged", "would_install", "already_installed"
    #[serde(default)]
    pub from_cache: bool,
}

/// Install result summary
#[derive(Debug, Clone, Serialize)]
pub struct InstallSummary {
    pub installed: u32,
    pub upgraded: u32,
    pub reinstalled: u32,
    pub unchanged: u32,
    pub failed: u32,
}

/// Remove result summary
#[derive(Debug, Clone, Serialize)]
pub struct RemoveSummary {
    pub removed: u32,
    pub purged: u32,
    pub not_installed: u32,
    pub skipped: u32,
    pub failed: u32,
    pub autoremove_run: bool,
}

/// List installed configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ListInstalledConfig {
    pub manager: ManagerKind,
    pub filter: Option<String>,
    pub prefix: Option<String>,
    #[serde(default = "default_true")]
    pub include_versions: bool,
    #[serde(default = "default_true")]
    pub include_repo: bool,
    #[serde(default)]
    pub include_size: bool,
    #[serde(default)]
    pub include_install_reason: bool,
    #[serde(default = "default_list_installed_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    pub extra_args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
}

fn default_list_installed_limit() -> u32 { 500 }

/// Snapshot configuration
#[derive(Debug, Clone, Deserialize)]
pub struct SnapshotConfig {
    pub manager: ManagerKind,
    #[serde(default = "default_snapshot_scope")]
    pub scope: SnapshotScope,
    #[serde(default = "default_version_mode")]
    pub include_versions: SnapshotVersionMode,
    #[serde(default = "default_true")]
    pub include_repo: bool,
    #[serde(default = "default_true")]
    pub include_arch: bool,
    #[serde(default = "default_true")]
    pub include_install_reason: bool,
    #[serde(default = "default_true")]
    pub include_os_metadata: bool,
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    #[serde(default = "default_snapshot_format")]
    pub format: SnapshotFormat,
    #[serde(default = "default_true")]
    pub inline: bool,
    #[serde(default = "default_snapshot_timeout")]
    pub timeout_ms: u64,
    pub extra_args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
}

/// Snapshot scope enumeration
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum SnapshotScope {
    #[serde(rename = "all")]
    All,
    #[serde(rename = "manual")]
    Manual,
    #[serde(rename = "dependency")]
    Dependency,
}

/// Snapshot version mode
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum SnapshotVersionMode {
    #[serde(rename = "exact")]
    Exact,
    #[serde(rename = "minimal")]
    Minimal,
    #[serde(rename = "none")]
    None,
}

/// Snapshot format enumeration
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum SnapshotFormat {
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "yaml")]
    Yaml,
    #[serde(rename = "text")]
    Text,
}

fn default_snapshot_scope() -> SnapshotScope { SnapshotScope::All }
fn default_version_mode() -> SnapshotVersionMode { SnapshotVersionMode::Exact }
fn default_snapshot_format() -> SnapshotFormat { SnapshotFormat::Json }
fn default_snapshot_timeout() -> u64 { 15000 } // 15 seconds

/// Restore configuration
#[derive(Debug, Clone, Deserialize)]
pub struct RestoreConfig {
    pub manager: ManagerKind,
    pub lockfile: String,
    #[serde(default = "default_restore_format")]
    pub format: LockfileFormat,
    #[serde(default = "default_restore_mode")]
    pub mode: RestoreMode,
    #[serde(default)]
    pub allow_downgrades: bool,
    #[serde(default)]
    pub allow_removals: bool,
    #[serde(default = "default_true")]
    pub allow_newer: bool,
    #[serde(default = "default_missing_policy")]
    pub on_missing_package: MissingPolicy,
    #[serde(default = "default_repo_policy")]
    pub on_repo_mismatch: RepoPolicy,
    #[serde(default = "default_platform_policy")]
    pub on_platform_mismatch: PlatformPolicy,
    #[serde(default = "default_true")]
    pub include_dependencies: bool,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default = "default_restore_timeout")]
    pub timeout_ms: u64,
    pub extra_args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
}

/// Restore mode enumeration
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum RestoreMode {
    #[serde(rename = "exact")]
    Exact,
    #[serde(rename = "best_effort")]
    BestEffort,
}

/// Lockfile format enumeration (for parsing lockfiles)
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum LockfileFormat {
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "yaml")]
    Yaml,
    #[serde(rename = "text")]
    Text,
}

/// Policy for handling missing packages
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum MissingPolicy {
    #[serde(rename = "fail")]
    Fail,
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "ignore")]
    Ignore,
}

/// Policy for handling repository mismatches
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum RepoPolicy {
    #[serde(rename = "fail")]
    Fail,
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "ignore")]
    Ignore,
}

/// Policy for handling platform mismatches
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum PlatformPolicy {
    #[serde(rename = "fail")]
    Fail,
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "ignore")]
    Ignore,
}

fn default_restore_format() -> LockfileFormat { LockfileFormat::Auto }
fn default_restore_mode() -> RestoreMode { RestoreMode::Exact }
fn default_missing_policy() -> MissingPolicy { MissingPolicy::Fail }
fn default_repo_policy() -> RepoPolicy { RepoPolicy::Warn }
fn default_platform_policy() -> PlatformPolicy { PlatformPolicy::Warn }
fn default_restore_timeout() -> u64 { 180000 } // 3 minutes

/// Lockfile schema structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lockfile {
    pub lockfile_version: String,
    pub generated_at: String,
    pub manager: ManagerInfo,
    pub platform: PlatformInfo,
    pub scope: String,
    pub packages: Vec<LockfilePackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagerInfo {
    pub name: String,
    pub alias: String,
    pub version: Option<String>,
    pub config: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformInfo {
    pub os_family: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub kernel: Option<String>,
    pub architecture: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockfilePackage {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_spec: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_reason: Option<String>,
    #[serde(default)]
    pub pinned: bool,
}

/// Individual installed package result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub architecture: Option<String>,
    pub repository: Option<String>,
    pub installed_size_bytes: Option<u64>,
    pub install_reason: Option<String>, // "manual" | "dependency" | null
    pub manager_specific: Option<serde_json::Value>,
}

/// List installed results container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListInstalledResults {
    pub backend: String,
    pub manager: String,
    pub alias: String,
    pub limit: u32,
    pub offset: u32,
    pub total_installed: u32,
    pub results: Vec<InstalledPackage>,
}

/// Restore plan structure for dry runs and execution planning
#[derive(Debug, Clone, Serialize)]
pub struct RestorePlan {
    pub install: Vec<String>,
    pub upgrade: Vec<String>,
    pub downgrade: Vec<String>,
    pub remove: Vec<String>,
    pub keep: Vec<String>,
    pub extra: Vec<String>,
    pub unresolved: Vec<UnresolvedPackage>,
}

/// Unresolved package with reason
#[derive(Debug, Clone, Serialize)]
pub struct UnresolvedPackage {
    pub name: String,
    pub reason: String,
}

/// Package operation result
#[derive(Debug, Clone, Serialize)]
pub struct PackageOpResult {
    pub name: String,
    pub status: String, // "success" | "failed"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Restore operation results
#[derive(Debug, Clone, Serialize)]
pub struct RestoreResults {
    pub install: Vec<PackageOpResult>,
    pub upgrade: Vec<PackageOpResult>,
    pub downgrade: Vec<PackageOpResult>,
    pub remove: Vec<PackageOpResult>,
}

/// Restore summary information
#[derive(Debug, Clone, Serialize)]
pub struct RestoreSummary {
    pub installed: u32,
    pub upgraded: u32,
    pub downgraded: u32,
    pub removed: u32,
    pub kept: u32,
    pub extra: u32,
    pub unresolved: u32,
    pub failed: u32,
    pub mode: String,
    pub success: bool,
}

/// Package handle for managing system packages
#[derive(Debug)]
pub struct PkgHandle {
    pub alias: String,
}

impl PkgHandle {
    pub fn from_url(url: &Url) -> Result<Self> {
        let alias = url.host_str()
            .unwrap_or("default")
            .to_string();
        
        Ok(PkgHandle { alias })
    }
}

/// Register the pkg handle with the registry
pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("pkg", |u| Ok(Box::new(PkgHandle::from_url(u)?)));
}

impl Handle for PkgHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["install", "remove", "update", "upgrade", "info", "search", "list_installed", "snapshot", "restore", "apply_lock"]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        match verb {
            "install" => self.install_verb(args, io),
            "remove" => self.remove_verb(args, io),
            "update" => self.update_verb(args, io),
            "upgrade" => self.upgrade_verb(args, io),
            "info" => self.info_verb(args, io),
            "search" => self.search_verb(args, io),
            "list_installed" => self.list_installed_verb(args, io),
            "snapshot" => self.snapshot_verb(args, io),
            "restore" => self.restore_verb(args, io),
            "apply_lock" => self.restore_verb(args, io), // alias for restore
            _ => bail!("unknown verb for pkg://: {}", verb),
        }
    }
}

impl PkgHandle {
    fn install_verb(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments from JSON input
        let config_json = args.get("input")
            .ok_or_else(|| PkgError::InvalidInstallConfig("Missing input configuration".to_string()))?;
        
        let config: InstallConfig = serde_json::from_str(config_json)
            .map_err(|e| PkgError::InvalidInstallConfig(format!("Invalid JSON: {}", e)))?;
        
        // Run the install operation
        let result = tokio::runtime::Runtime::new()?
            .block_on(self.install_async(config))?;
        
        // Write result to stdout
        let result_json = serde_json::to_string_pretty(&result)?;
        writeln!(io.stdout, "{}", result_json)?;
        
        Ok(Status::success())
    }

    fn remove_verb(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments from JSON input
        let config_json = args.get("input")
            .ok_or_else(|| PkgError::InvalidRemoveConfig("Missing input configuration".to_string()))?;
        
        let config: RemoveConfig = serde_json::from_str(config_json)
            .map_err(|e| PkgError::InvalidRemoveConfig(format!("Invalid JSON: {}", e)))?;
        
        // Run the remove operation
        let result = tokio::runtime::Runtime::new()?
            .block_on(self.remove_async(config))?;
        
        // Write result to stdout
        let result_json = serde_json::to_string_pretty(&result)?;
        writeln!(io.stdout, "{}", result_json)?;
        
        Ok(Status::success())
    }

    fn update_verb(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments from JSON input
        let config_json = args.get("input")
            .ok_or_else(|| PkgError::InvalidUpdateConfig("Missing input configuration".to_string()))?;
        
        let config: UpdateConfig = serde_json::from_str(config_json)
            .map_err(|e| PkgError::InvalidUpdateConfig(format!("Invalid JSON: {}", e)))?;
        
        // Run the update operation
        let result = tokio::runtime::Runtime::new()?
            .block_on(self.update_async(config))?;
        
        // Write result to stdout
        let result_json = serde_json::to_string_pretty(&result)?;
        writeln!(io.stdout, "{}", result_json)?;
        
        Ok(Status::success())
    }

    fn upgrade_verb(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments from JSON input
        let config_json = args.get("input")
            .ok_or_else(|| PkgError::InvalidUpgradeConfig("Missing input configuration".to_string()))?;
        
        let config: UpgradeConfig = serde_json::from_str(config_json)
            .map_err(|e| PkgError::InvalidUpgradeConfig(format!("Invalid JSON: {}", e)))?;
        
        // Run the upgrade operation
        let result = tokio::runtime::Runtime::new()?
            .block_on(self.upgrade_async(config))?;
        
        // Write result to stdout
        let result_json = serde_json::to_string_pretty(&result)?;
        writeln!(io.stdout, "{}", result_json)?;
        
        Ok(Status::success())
    }

    fn info_verb(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments from JSON input
        let config_json = args.get("input")
            .ok_or_else(|| PkgError::InvalidInfoConfig("Missing input configuration".to_string()))?;
        
        let config: InfoConfig = serde_json::from_str(config_json)
            .map_err(|e| PkgError::InvalidInfoConfig(format!("Invalid JSON: {}", e)))?;
        
        // Run the info operation
        let result = tokio::runtime::Runtime::new()?
            .block_on(self.info_async(config))?;
        
        // Write result to stdout
        let result_json = serde_json::to_string_pretty(&result)?;
        writeln!(io.stdout, "{}", result_json)?;
        
        Ok(Status::success())
    }

    fn search_verb(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments from JSON input
        let config_json = args.get("input")
            .ok_or_else(|| PkgError::InvalidSearchConfig("Missing input configuration".to_string()))?;
        
        let config: SearchConfig = serde_json::from_str(config_json)
            .map_err(|e| PkgError::InvalidSearchConfig(format!("Invalid JSON: {}", e)))?;
        
        // Run the search operation
        let result = tokio::runtime::Runtime::new()?
            .block_on(self.search_async(config))?;
        
        // Write result to stdout
        let result_json = serde_json::to_string_pretty(&result)?;
        writeln!(io.stdout, "{}", result_json)?;
        
        Ok(Status::success())
    }

    fn list_installed_verb(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments from JSON input
        let config_json = args.get("input")
            .ok_or_else(|| PkgError::InvalidListInstalledConfig("Missing input configuration".to_string()))?;
        
        let config: ListInstalledConfig = serde_json::from_str(config_json)
            .map_err(|e| PkgError::InvalidListInstalledConfig(format!("Invalid JSON: {}", e)))?;
        
        // Run the list installed operation
        let result = tokio::runtime::Runtime::new()?
            .block_on(self.list_installed_async(config))?;
        
        // Write result to stdout
        let result_json = serde_json::to_string_pretty(&result)?;
        writeln!(io.stdout, "{}", result_json)?;
        
        Ok(Status::success())
    }

    fn snapshot_verb(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments from JSON input
        let config_json = args.get("input")
            .ok_or_else(|| PkgError::InvalidSnapshotConfig("Missing input configuration".to_string()))?;
        
        let config: SnapshotConfig = serde_json::from_str(config_json)
            .map_err(|e| PkgError::InvalidSnapshotConfig(format!("Invalid JSON: {}", e)))?;
        
        // Run the snapshot operation
        let result = tokio::runtime::Runtime::new()?
            .block_on(self.snapshot_async(config))?;
        
        // Write result to stdout
        let result_json = serde_json::to_string_pretty(&result)?;
        writeln!(io.stdout, "{}", result_json)?;
        
        Ok(Status::success())
    }

    fn restore_verb(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments from JSON input
        let config_json = args.get("input")
            .ok_or_else(|| PkgError::InvalidRestoreConfig("Missing input configuration".to_string()))?;
        
        let config: RestoreConfig = serde_json::from_str(config_json)
            .map_err(|e| PkgError::InvalidRestoreConfig(format!("Invalid JSON: {}", e)))?;
        
        // Run the restore operation
        let result = tokio::runtime::Runtime::new()?
            .block_on(self.restore_async(config))?;
        
        // Write result to stdout
        let result_json = serde_json::to_string_pretty(&result)?;
        writeln!(io.stdout, "{}", result_json)?;
        
        Ok(Status::success())
    }

    async fn install_async(&self, config: InstallConfig) -> Result<Value, PkgError> {
        // Validate configuration
        self.validate_config(&config)?;
        
        // Resolve manager
        let manager = self.resolve_manager(&config.manager).await?;
        
        // Check if dry run
        if config.dry_run {
            return self.dry_run_install(&config, &manager).await;
        }
        
        // Perform actual install with timeout
        let result = timeout(
            Duration::from_millis(config.timeout_ms),
            self.perform_install(&config, &manager)
        ).await
        .map_err(|_| PkgError::InstallTimeout)?;
        
        result
    }

    /// Validate install configuration
    fn validate_config(&self, config: &InstallConfig) -> Result<(), PkgError> {
        // Check packages is not empty
        if config.packages.is_empty() {
            return Err(PkgError::InvalidInstallConfig("packages cannot be empty".to_string()));
        }

        // Check package names are not empty
        for pkg in &config.packages {
            if pkg.name.trim().is_empty() {
                return Err(PkgError::InvalidInstallConfig("package name cannot be empty".to_string()));
            }
        }

        // Check timeout
        if config.timeout_ms == 0 {
            return Err(PkgError::InvalidInstallConfig("timeout_ms must be greater than 0".to_string()));
        }

        // Check extra_args if present
        if let Some(ref extra_args) = config.extra_args {
            if extra_args.iter().any(|arg| arg.is_empty()) {
                return Err(PkgError::InvalidInstallConfig("extra_args cannot contain empty strings".to_string()));
            }
        }

        // Check contradictory flags
        if config.only_if_missing && config.reinstall {
            return Err(PkgError::InvalidInstallConfig("only_if_missing and reinstall are contradictory".to_string()));
        }

        if config.only_if_missing && config.upgrade {
            return Err(PkgError::InvalidInstallConfig("only_if_missing and upgrade are contradictory".to_string()));
        }

        Ok(())
    }

    /// Validate info configuration
    fn validate_info_config(&self, config: &InfoConfig) -> Result<(), PkgError> {
        // Check packages is not empty
        if config.packages.is_empty() {
            return Err(PkgError::InvalidInfoConfig("packages cannot be empty".to_string()));
        }

        // Check package names are not empty
        for pkg in &config.packages {
            if pkg.trim().is_empty() {
                return Err(PkgError::InvalidInfoConfig("package name cannot be empty".to_string()));
            }
        }

        // Check timeout
        if config.timeout_ms == 0 {
            return Err(PkgError::InvalidInfoConfig("timeout_ms must be greater than 0".to_string()));
        }

        // Check extra_args if present
        if let Some(ref extra_args) = config.extra_args {
            if extra_args.iter().any(|arg| arg.is_empty()) {
                return Err(PkgError::InvalidInfoConfig("extra_args cannot contain empty strings".to_string()));
            }
        }

        // Check env if present
        if let Some(ref env) = config.env {
            for (key, value) in env {
                if key.is_empty() || value.is_empty() {
                    return Err(PkgError::InvalidInfoConfig("env keys and values cannot be empty".to_string()));
                }
            }
        }

        Ok(())
    }

    /// Resolve manager from config or auto-detect
    async fn resolve_manager(&self, manager: &ManagerKind) -> Result<ManagerKind, PkgError> {
        match manager {
            ManagerKind::Auto => self.detect_manager().await,
            _ => {
                // Check if specified manager is available
                if self.is_manager_available(manager).await? {
                    Ok(manager.clone())
                } else {
                    Err(PkgError::ManagerNotAvailable(format!("{:?}", manager)))
                }
            }
        }
    }

    /// Auto-detect available package manager
    async fn detect_manager(&self) -> Result<ManagerKind, PkgError> {
        // Detection order: apt, dnf/yum, pacman, apk, brew
        let managers = [
            (ManagerKind::Apt, "apt-get"),
            (ManagerKind::Dnf, "dnf"),
            (ManagerKind::Yum, "yum"),
            (ManagerKind::Pacman, "pacman"),
            (ManagerKind::Apk, "apk"),
            (ManagerKind::Brew, "brew"),
        ];

        for (manager, binary) in &managers {
            if which(binary).is_ok() {
                return Ok(manager.clone());
            }
        }

        Err(PkgError::ManagerNotAvailable("No supported package manager found".to_string()))
    }

    /// Check if manager is available on system
    async fn is_manager_available(&self, manager: &ManagerKind) -> Result<bool, PkgError> {
        let binary = match manager {
            ManagerKind::Auto => return Err(PkgError::InvalidInstallConfig("Auto should be resolved first".to_string())),
            ManagerKind::Apt => "apt-get",
            ManagerKind::Dnf => "dnf",
            ManagerKind::Yum => "yum", 
            ManagerKind::Pacman => "pacman",
            ManagerKind::Apk => "apk",
            ManagerKind::Brew => "brew",
        };

        Ok(which(binary).is_ok())
    }

    /// Perform dry run installation
    async fn dry_run_install(&self, config: &InstallConfig, manager: &ManagerKind) -> Result<Value, PkgError> {
        let mut commands = Vec::new();
        let mut packages = Vec::new();

        // Add cache update command if needed
        if config.update_cache {
            commands.push(self.build_update_cache_command(manager)?);
        }

        // Check package status and build install commands
        let install_command = self.build_install_command(config, manager).await?;
        commands.push(install_command);

        // Check which packages would be installed
        for pkg in &config.packages {
            let is_installed = self.is_package_installed(&pkg.name, manager).await.unwrap_or(false);
            let action = if is_installed {
                if config.reinstall {
                    "would_reinstall"
                } else if config.upgrade {
                    "would_upgrade" 
                } else {
                    "already_installed"
                }
            } else {
                "would_install"
            };

            packages.push(json!({
                "name": pkg.name,
                "action": action
            }));
        }

        Ok(json!({
            "backend": "pkg",
            "manager": format!("{:?}", manager).to_lowercase(),
            "alias": self.alias,
            "dry_run": true,
            "commands": commands,
            "packages": packages
        }))
    }

    /// Perform actual installation
    async fn perform_install(&self, config: &InstallConfig, manager: &ManagerKind) -> Result<Value, PkgError> {
        let mut results = Vec::new();
        let mut summary = InstallSummary {
            installed: 0,
            upgraded: 0,
            reinstalled: 0,
            unchanged: 0,
            failed: 0,
        };

        // Update cache if requested
        if config.update_cache {
            self.update_package_cache(manager).await?;
        }

        // Process packages
        for pkg in &config.packages {
            match self.install_single_package(pkg, config, manager).await {
                Ok(result) => {
                    match result.action.as_str() {
                        "installed" => summary.installed += 1,
                        "upgraded" => summary.upgraded += 1,
                        "reinstalled" => summary.reinstalled += 1,
                        "unchanged" => summary.unchanged += 1,
                        _ => {}
                    }
                    results.push(result);
                }
                Err(e) => {
                    summary.failed += 1;
                    results.push(PackageResult {
                        name: pkg.name.clone(),
                        requested_version: pkg.version.clone(),
                        installed_version: None,
                        action: "failed".to_string(),
                        from_cache: false,
                    });
                    // Log error but continue with other packages
                    eprintln!("Failed to install {}: {}", pkg.name, e);
                }
            }
        }

        Ok(json!({
            "backend": "pkg",
            "manager": format!("{:?}", manager).to_lowercase(),
            "alias": self.alias,
            "update_cache": config.update_cache,
            "dry_run": false,
            "packages": results,
            "summary": summary
        }))
    }

    /// Build cache update command for manager
    fn build_update_cache_command(&self, manager: &ManagerKind) -> Result<String, PkgError> {
        match manager {
            ManagerKind::Apt => Ok("apt-get update".to_string()),
            ManagerKind::Dnf => Ok("dnf makecache".to_string()),
            ManagerKind::Yum => Ok("yum makecache".to_string()),
            ManagerKind::Pacman => Ok("pacman -Sy".to_string()),
            ManagerKind::Apk => Ok("apk update".to_string()),
            ManagerKind::Brew => Ok("brew update".to_string()),
            _ => Err(PkgError::ManagerNotAvailable("Unsupported manager".to_string())),
        }
    }

    /// Build install command for manager and packages
    async fn build_install_command(&self, config: &InstallConfig, manager: &ManagerKind) -> Result<String, PkgError> {
        let mut cmd = match manager {
            ManagerKind::Apt => {
                let mut base = "DEBIAN_FRONTEND=noninteractive apt-get install".to_string();
                if config.assume_yes {
                    base.push_str(" -y");
                }
                if config.reinstall {
                    base.push_str(" --reinstall");
                }
                base
            },
            ManagerKind::Dnf => {
                let mut base = if config.reinstall { "dnf reinstall" } else { "dnf install" }.to_string();
                if config.assume_yes {
                    base.push_str(" -y");
                }
                base
            },
            ManagerKind::Yum => {
                let mut base = if config.reinstall { "yum reinstall" } else { "yum install" }.to_string();
                if config.assume_yes {
                    base.push_str(" -y");
                }
                base
            },
            ManagerKind::Pacman => {
                let mut base = "pacman -S".to_string();
                if config.assume_yes {
                    base.push_str(" --noconfirm");
                }
                if config.only_if_missing {
                    base.push_str(" --needed");
                }
                base
            },
            ManagerKind::Apk => {
                let mut base = "apk add --no-interactive".to_string();
                if config.reinstall {
                    base.push_str(" --force-reinstall");
                }
                base
            },
            ManagerKind::Brew => {
                if config.reinstall {
                    "brew reinstall".to_string()
                } else {
                    "brew install".to_string()
                }
            },
            _ => return Err(PkgError::ManagerNotAvailable("Unsupported manager".to_string())),
        };

        // Add packages to command
        for pkg in &config.packages {
            cmd.push(' ');
            cmd.push_str(&self.format_package_name(pkg, manager, config)?);
        }

        // Add extra args if specified
        if let Some(ref extra_args) = config.extra_args {
            for arg in extra_args {
                cmd.push(' ');
                cmd.push_str(arg);
            }
        }

        Ok(cmd)
    }

    /// Format package name for specific manager
    fn format_package_name(&self, pkg: &PackageSpec, manager: &ManagerKind, config: &InstallConfig) -> Result<String, PkgError> {
        let mut name = pkg.name.clone();

        // Add version if specified
        if let Some(ref version) = pkg.version {
            match manager {
                ManagerKind::Apt => name = format!("{}={}", name, version),
                ManagerKind::Dnf | ManagerKind::Yum => name = format!("{}-{}", name, version),
                ManagerKind::Apk => name = format!("{}={}", name, version),
                ManagerKind::Pacman => {
                    // Pacman version pinning is complex, often ignored
                    return Err(PkgError::InstallInvalidVersion("Version pinning not supported for pacman".to_string()));
                },
                ManagerKind::Brew => {
                    // Homebrew typically ignores version, warning logged elsewhere
                },
                _ => {}
            }
        }

        // Add architecture if specified
        if let Some(ref arch) = config.arch {
            match manager {
                ManagerKind::Apt => name = format!("{}:{}", name, arch),
                ManagerKind::Dnf | ManagerKind::Yum => name = format!("{}.{}", name, arch),
                _ => {} // Other managers don't commonly support arch specification
            }
        }

        Ok(name)
    }

    /// Check if package is installed
    async fn is_package_installed(&self, package_name: &str, manager: &ManagerKind) -> Result<bool, PkgError> {
        let cmd = match manager {
            ManagerKind::Apt => format!("dpkg -s {}", package_name),
            ManagerKind::Dnf | ManagerKind::Yum => format!("rpm -q {}", package_name),
            ManagerKind::Pacman => format!("pacman -Q {}", package_name),
            ManagerKind::Apk => format!("apk info -e {}", package_name),
            ManagerKind::Brew => format!("brew list --versions {}", package_name),
            _ => return Err(PkgError::ManagerNotAvailable("Unsupported manager".to_string())),
        };

        let output = AsyncCommand::new("sh")
            .arg("-c")
            .arg(&cmd)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map_err(|e| PkgError::InstallFailed(format!("Failed to check package status: {}", e)))?;

        Ok(output.success())
    }

    /// Update package cache
    async fn update_package_cache(&self, manager: &ManagerKind) -> Result<(), PkgError> {
        let cmd = self.build_update_cache_command(manager)?;
        
        let output = AsyncCommand::new("sh")
            .arg("-c")
            .arg(&cmd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| PkgError::UpdateCacheFailed(format!("Failed to update cache: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::UpdateCacheFailed(format!("Cache update failed: {}", stderr)));
        }

        Ok(())
    }

    /// Install single package
    async fn install_single_package(&self, pkg: &PackageSpec, config: &InstallConfig, manager: &ManagerKind) -> Result<PackageResult, PkgError> {
        // Check if already installed first
        let was_installed = self.is_package_installed(&pkg.name, manager).await.unwrap_or(false);
        
        // Handle only_if_missing logic
        if config.only_if_missing && was_installed && !config.upgrade && !config.reinstall {
            let installed_version = self.get_installed_version(&pkg.name, manager).await.ok();
            return Ok(PackageResult {
                name: pkg.name.clone(),
                requested_version: pkg.version.clone(),
                installed_version,
                action: "unchanged".to_string(),
                from_cache: false,
            });
        }

        // Build command for this specific package
        let temp_config = InstallConfig {
            manager: config.manager.clone(),
            packages: vec![pkg.clone()],
            update_cache: false, // Already handled
            assume_yes: config.assume_yes,
            only_if_missing: config.only_if_missing,
            reinstall: config.reinstall,
            upgrade: config.upgrade,
            dry_run: config.dry_run,
            timeout_ms: config.timeout_ms,
            arch: config.arch.clone(),
            extra_args: config.extra_args.clone(),
            env: config.env.clone(),
        };

        let cmd = self.build_install_command(&temp_config, manager).await?;
        
        // Execute command
        let mut command = AsyncCommand::new("sh");
        command.arg("-c").arg(&cmd);
        
        // Set environment variables if specified
        if let Some(ref env) = config.env {
            for (key, value) in env {
                command.env(key, value);
            }
        }

        let output = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| PkgError::InstallFailed(format!("Failed to execute install: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(self.map_install_error(&stderr, &output.status.code()));
        }

        // Determine action based on previous state and current result
        let action = if !was_installed {
            "installed"
        } else if config.reinstall {
            "reinstalled"
        } else if config.upgrade {
            "upgraded"
        } else {
            "unchanged"
        };

        let installed_version = self.get_installed_version(&pkg.name, manager).await.ok();

        Ok(PackageResult {
            name: pkg.name.clone(),
            requested_version: pkg.version.clone(),
            installed_version,
            action: action.to_string(),
            from_cache: false,
        })
    }

    /// Get installed version of package
    async fn get_installed_version(&self, package_name: &str, manager: &ManagerKind) -> Result<String, PkgError> {
        let cmd = match manager {
            ManagerKind::Apt => format!("dpkg-query -W -f='${{Version}}' {}", package_name),
            ManagerKind::Dnf | ManagerKind::Yum => format!("rpm -q --qf '%{{VERSION}}-%{{RELEASE}}' {}", package_name),
            ManagerKind::Pacman => format!("pacman -Q {} | cut -d' ' -f2", package_name),
            ManagerKind::Apk => format!("apk info {} | grep -o '[0-9][^[:space:]]*'", package_name),
            ManagerKind::Brew => format!("brew list --versions {} | cut -d' ' -f2", package_name),
            _ => return Err(PkgError::ManagerNotAvailable("Unsupported manager".to_string())),
        };

        let output = AsyncCommand::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()
            .await
            .map_err(|e| PkgError::InstallFailed(format!("Failed to get version: {}", e)))?;

        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Ok(version)
        } else {
            Err(PkgError::InstallFailed("Could not get package version".to_string()))
        }
    }

    /// Map install error from stderr and exit code
    fn map_install_error(&self, stderr: &str, exit_code: &Option<i32>) -> PkgError {
        let stderr_lower = stderr.to_lowercase();
        
        // Check for specific error patterns
        if stderr_lower.contains("package") && (stderr_lower.contains("not found") || stderr_lower.contains("no such package")) {
            PkgError::InstallNotFound(stderr.to_string())
        } else if stderr_lower.contains("permission denied") || stderr_lower.contains("not allowed") || exit_code == &Some(13) {
            PkgError::InstallPermissionDenied(stderr.to_string())
        } else if stderr_lower.contains("dependency") || stderr_lower.contains("broken") || stderr_lower.contains("unresolved") {
            PkgError::InstallDependencyFailure(stderr.to_string())
        } else if stderr_lower.contains("conflict") || stderr_lower.contains("already installed") && stderr_lower.contains("error") {
            PkgError::InstallConflict(stderr.to_string())
        } else if stderr_lower.contains("version") && stderr_lower.contains("invalid") {
            PkgError::InstallInvalidVersion(stderr.to_string())
        } else {
            PkgError::InstallFailed(stderr.to_string())
        }
    }

    // ===== REMOVE METHODS =====

    async fn remove_async(&self, config: RemoveConfig) -> Result<Value, PkgError> {
        // Validate configuration
        self.validate_remove_config(&config)?;
        
        // Resolve manager
        let manager = self.resolve_manager(&config.manager).await?;
        
        // Check if dry run
        if config.dry_run {
            return self.dry_run_remove(&config, &manager).await;
        }
        
        // Perform actual remove with timeout
        let result = timeout(
            Duration::from_millis(config.timeout_ms),
            self.perform_remove(&config, &manager)
        ).await
        .map_err(|_| PkgError::RemoveTimeout)?;
        
        result
    }

    /// Validate remove configuration
    pub fn validate_remove_config(&self, config: &RemoveConfig) -> Result<(), PkgError> {
        // Check packages is not empty
        if config.packages.is_empty() {
            return Err(PkgError::InvalidRemoveConfig("packages cannot be empty".to_string()));
        }

        // Check package names are not empty
        for pkg in &config.packages {
            if pkg.name.trim().is_empty() {
                return Err(PkgError::InvalidRemoveConfig("package name cannot be empty".to_string()));
            }
        }

        // Check timeout
        if config.timeout_ms == 0 {
            return Err(PkgError::InvalidRemoveConfig("timeout_ms must be greater than 0".to_string()));
        }

        // Check extra_args if present
        if let Some(ref extra_args) = config.extra_args {
            if extra_args.iter().any(|arg| arg.is_empty()) {
                return Err(PkgError::InvalidRemoveConfig("extra_args cannot contain empty strings".to_string()));
            }
        }

        // Check contradictory flags
        if config.only_if_installed && config.fail_if_missing {
            return Err(PkgError::InvalidRemoveConfig("only_if_installed and fail_if_missing are contradictory".to_string()));
        }

        Ok(())
    }

    /// Perform dry run removal
    async fn dry_run_remove(&self, config: &RemoveConfig, manager: &ManagerKind) -> Result<Value, PkgError> {
        let mut commands = Vec::new();
        let mut packages = Vec::new();

        // Check package status and build remove commands
        let mut remove_packages = Vec::new();
        
        for pkg in &config.packages {
            let is_installed = self.is_package_installed(&pkg.name, manager).await.unwrap_or(false);
            if is_installed || !config.only_if_installed {
                remove_packages.push(pkg);
            }
        }

        if !remove_packages.is_empty() {
            let remove_command = self.build_remove_command(&remove_packages, config, manager).await?;
            commands.push(remove_command);

            // Add autoremove command if recursive and supported
            if config.recursive {
                if let Ok(autoremove_cmd) = self.build_autoremove_command(manager) {
                    commands.push(autoremove_cmd);
                }
            }
        }

        // Check which packages would be removed
        for pkg in &config.packages {
            let is_installed = self.is_package_installed(&pkg.name, manager).await.unwrap_or(false);
            let action = if is_installed {
                if config.purge && self.supports_purge(manager) {
                    "would_purge"
                } else {
                    "would_remove"
                }
            } else {
                "not_installed"
            };

            packages.push(json!({
                "name": pkg.name,
                "action": action
            }));
        }

        Ok(json!({
            "backend": "pkg",
            "manager": format!("{:?}", manager).to_lowercase(),
            "alias": self.alias,
            "dry_run": true,
            "commands": commands,
            "packages": packages
        }))
    }

    /// Perform actual removal
    async fn perform_remove(&self, config: &RemoveConfig, manager: &ManagerKind) -> Result<Value, PkgError> {
        let mut results = Vec::new();
        let mut summary = RemoveSummary {
            removed: 0,
            purged: 0,
            not_installed: 0,
            skipped: 0,
            failed: 0,
            autoremove_run: false,
        };

        let mut packages_to_remove = Vec::new();
        let mut packages_to_fail = Vec::new();

        // First pass: check installed status and handle flags
        for pkg in &config.packages {
            let is_installed = self.is_package_installed(&pkg.name, manager).await.unwrap_or(false);
            
            if !is_installed {
                if config.fail_if_missing {
                    packages_to_fail.push(pkg);
                    summary.failed += 1;
                } else {
                    summary.not_installed += 1;
                    results.push(PackageResult {
                        name: pkg.name.clone(),
                        requested_version: pkg.version.clone(),
                        installed_version: None,
                        action: "not_installed".to_string(),
                        from_cache: false,
                    });
                }
            } else {
                packages_to_remove.push(pkg);
            }
        }

        // Add failed packages due to missing + fail_if_missing
        for pkg in packages_to_fail {
            results.push(PackageResult {
                name: pkg.name.clone(),
                requested_version: pkg.version.clone(),
                installed_version: None,
                action: "failed".to_string(),
                from_cache: false,
            });
        }

        // Remove packages that are actually installed
        if !packages_to_remove.is_empty() {
            match self.remove_packages_batch(&packages_to_remove, config, manager).await {
                Ok(batch_results) => {
                    for result in batch_results {
                        match result.action.as_str() {
                            "removed" => summary.removed += 1,
                            "purged" => {
                                summary.purged += 1;
                                summary.removed += 1; // purged counts as removed too
                            },
                            "skipped" => summary.skipped += 1,
                            _ => summary.failed += 1,
                        }
                        results.push(result);
                    }
                }
                Err(e) => {
                    // If batch fails, mark all as failed
                    summary.failed += packages_to_remove.len() as u32;
                    for pkg in packages_to_remove {
                        results.push(PackageResult {
                            name: pkg.name.clone(),
                            requested_version: pkg.version.clone(),
                            installed_version: None,
                            action: "failed".to_string(),
                            from_cache: false,
                        });
                    }
                    eprintln!("Failed to remove packages: {}", e);
                }
            }

            // Run autoremove if requested and some packages were removed
            if config.recursive && (summary.removed > 0 || summary.purged > 0) {
                if let Ok(_) = self.run_autoremove(manager).await {
                    summary.autoremove_run = true;
                }
            }
        }

        Ok(json!({
            "backend": "pkg",
            "manager": format!("{:?}", manager).to_lowercase(),
            "alias": self.alias,
            "dry_run": false,
            "purge": config.purge,
            "recursive": config.recursive,
            "packages": results,
            "summary": summary
        }))
    }

    /// Remove a batch of packages
    async fn remove_packages_batch(&self, packages: &[&PackageSpec], config: &RemoveConfig, manager: &ManagerKind) -> Result<Vec<PackageResult>, PkgError> {
        let mut results = Vec::new();
        
        // Get installed versions before removal
        let mut installed_versions = HashMap::new();
        for pkg in packages {
            if let Ok(version) = self.get_installed_version(&pkg.name, manager).await {
                installed_versions.insert(pkg.name.clone(), version);
            }
        }

        // Build and execute remove command
        let cmd = self.build_remove_command(packages, config, manager).await?;
        
        let mut command = AsyncCommand::new("sh");
        command.arg("-c").arg(&cmd);
        
        // Set environment variables if specified
        if let Some(ref env) = config.env {
            for (key, value) in env {
                command.env(key, value);
            }
        }

        let output = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| PkgError::RemoveFailed(format!("Failed to execute remove: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(self.map_remove_error(&stderr, &output.status.code()));
        }

        // Create results for each package
        for pkg in packages {
            let action = if config.purge && self.supports_purge(manager) {
                "purged"
            } else {
                "removed"
            };

            results.push(PackageResult {
                name: pkg.name.clone(),
                requested_version: pkg.version.clone(),
                installed_version: installed_versions.get(&pkg.name).cloned(),
                action: action.to_string(),
                from_cache: false,
            });
        }

        Ok(results)
    }

    /// Build remove command for manager and packages
    pub async fn build_remove_command(&self, packages: &[&PackageSpec], config: &RemoveConfig, manager: &ManagerKind) -> Result<String, PkgError> {
        let mut cmd = match manager {
            ManagerKind::Apt => {
                let base_cmd = if config.purge {
                    "DEBIAN_FRONTEND=noninteractive apt-get purge"
                } else {
                    "DEBIAN_FRONTEND=noninteractive apt-get remove"
                };
                let mut cmd = base_cmd.to_string();
                if config.assume_yes {
                    cmd.push_str(" -y");
                }
                cmd
            },
            ManagerKind::Dnf => {
                let mut cmd = "dnf remove".to_string();
                if config.assume_yes {
                    cmd.push_str(" -y");
                }
                cmd
            },
            ManagerKind::Yum => {
                let mut cmd = "yum remove".to_string();
                if config.assume_yes {
                    cmd.push_str(" -y");
                }
                cmd
            },
            ManagerKind::Pacman => {
                let mut cmd = "pacman -R".to_string();
                if config.assume_yes {
                    cmd.push_str(" --noconfirm");
                }
                if config.recursive {
                    cmd = cmd.replace("-R", "-Rs"); // Remove with dependencies
                }
                cmd
            },
            ManagerKind::Apk => {
                let mut cmd = "apk del --no-interactive".to_string();
                if config.purge {
                    cmd.push_str(" --purge");
                }
                cmd
            },
            ManagerKind::Brew => {
                "brew uninstall".to_string()
            },
            _ => return Err(PkgError::ManagerNotAvailable("Unsupported manager".to_string())),
        };

        // Add packages to command
        for pkg in packages {
            cmd.push(' ');
            cmd.push_str(&self.format_remove_package_name(pkg, manager, config)?);
        }

        // Add extra args if specified
        if let Some(ref extra_args) = config.extra_args {
            for arg in extra_args {
                cmd.push(' ');
                cmd.push_str(arg);
            }
        }

        Ok(cmd)
    }

    /// Build autoremove command if supported
    pub fn build_autoremove_command(&self, manager: &ManagerKind) -> Result<String, PkgError> {
        match manager {
            ManagerKind::Apt => Ok("DEBIAN_FRONTEND=noninteractive apt-get autoremove -y".to_string()),
            ManagerKind::Dnf => Ok("dnf autoremove -y".to_string()),
            ManagerKind::Yum => Ok("yum autoremove -y".to_string()),
            // Pacman recursive removal is handled in the main command
            // APK and Brew don't have explicit autoremove
            _ => Err(PkgError::ManagerNotAvailable("Autoremove not supported".to_string())),
        }
    }

    /// Run autoremove command
    async fn run_autoremove(&self, manager: &ManagerKind) -> Result<(), PkgError> {
        if let Ok(cmd) = self.build_autoremove_command(manager) {
            let output = AsyncCommand::new("sh")
                .arg("-c")
                .arg(&cmd)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await
                .map_err(|e| PkgError::RemoveFailed(format!("Failed to run autoremove: {}", e)))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(PkgError::RemoveFailed(format!("Autoremove failed: {}", stderr)));
            }
        }
        Ok(())
    }

    /// Format package name for removal
    pub fn format_remove_package_name(&self, pkg: &PackageSpec, manager: &ManagerKind, config: &RemoveConfig) -> Result<String, PkgError> {
        let mut name = pkg.name.clone();

        // Add architecture if specified (similar to install)
        if let Some(ref arch) = config.arch {
            match manager {
                ManagerKind::Apt => name = format!("{}:{}", name, arch),
                ManagerKind::Dnf | ManagerKind::Yum => name = format!("{}.{}", name, arch),
                _ => {} // Other managers don't commonly support arch specification for removal
            }
        }

        Ok(name)
    }

    /// Check if manager supports purge operation
    pub fn supports_purge(&self, manager: &ManagerKind) -> bool {
        matches!(manager, ManagerKind::Apt | ManagerKind::Apk)
    }

    /// Map remove error from stderr and exit code
    pub fn map_remove_error(&self, stderr: &str, exit_code: &Option<i32>) -> PkgError {
        let stderr_lower = stderr.to_lowercase();
        
        // Check for specific error patterns
        if stderr_lower.contains("package") && (stderr_lower.contains("not found") || stderr_lower.contains("not installed")) {
            PkgError::RemoveNotFound(stderr.to_string())
        } else if stderr_lower.contains("permission denied") || stderr_lower.contains("not allowed") || exit_code == &Some(13) {
            PkgError::RemovePermissionDenied(stderr.to_string())
        } else if stderr_lower.contains("dependency") || stderr_lower.contains("required by") || stderr_lower.contains("needed by") {
            PkgError::RemoveDependencyFailure(stderr.to_string())
        } else {
            PkgError::RemoveFailed(stderr.to_string())
        }
    }

    // ===== UPDATE METHODS =====

    async fn update_async(&self, config: UpdateConfig) -> Result<Value, PkgError> {
        // Validate configuration
        self.validate_update_config(&config)?;
        
        // Resolve manager
        let manager = self.resolve_manager(&config.manager).await?;
        
        // Check for check-only or dry-run modes
        if config.check_only || config.dry_run {
            return self.check_or_dry_run_update(&config, &manager).await;
        }
        
        // Perform actual update with timeout
        let result = timeout(
            Duration::from_millis(config.timeout_ms),
            self.perform_update(&config, &manager)
        ).await
        .map_err(|_| PkgError::UpdateTimeout)?;
        
        result
    }

    /// Validate update configuration
    fn validate_update_config(&self, config: &UpdateConfig) -> Result<(), PkgError> {
        // Check timeout
        if config.timeout_ms == 0 {
            return Err(PkgError::InvalidUpdateConfig("timeout_ms must be greater than 0".to_string()));
        }

        // Check extra_args if present
        if let Some(ref extra_args) = config.extra_args {
            if extra_args.iter().any(|arg| arg.is_empty()) {
                return Err(PkgError::InvalidUpdateConfig("extra_args cannot contain empty strings".to_string()));
            }
        }

        // Check that there's something to do
        if !config.refresh_index && !config.upgrade && !config.check_only {
            return Err(PkgError::InvalidUpdateConfig("Nothing to do: refresh_index, upgrade, and check_only are all false".to_string()));
        }

        Ok(())
    }

    /// Validate upgrade configuration
    fn validate_upgrade_config(&self, config: &UpgradeConfig) -> Result<(), PkgError> {
        // Check timeout
        if config.timeout_ms == 0 {
            return Err(PkgError::InvalidUpgradeConfig("timeout_ms must be greater than 0".to_string()));
        }

        // Check extra_args if present
        if let Some(ref extra_args) = config.extra_args {
            if extra_args.iter().any(|arg| arg.is_empty()) {
                return Err(PkgError::InvalidUpgradeConfig("extra_args cannot contain empty strings".to_string()));
            }
        }

        // Check packages if present
        if config.packages.iter().any(|pkg| pkg.trim().is_empty()) {
            return Err(PkgError::InvalidUpgradeConfig("package names cannot be empty".to_string()));
        }

        // Check for meaningless combination
        if config.dry_run && config.check_only && !config.refresh_index && config.packages.is_empty() {
            return Err(PkgError::InvalidUpgradeConfig("Nothing meaningful to do: dry_run and check_only are both true, no refresh_index, and no packages specified".to_string()));
        }

        Ok(())
    }

    /// Handle check-only or dry-run update modes
    async fn check_or_dry_run_update(&self, config: &UpdateConfig, manager: &ManagerKind) -> Result<Value, PkgError> {
        let mut commands = Vec::new();
        let mut available_updates = Vec::new();

        // Add refresh index command if requested
        if config.refresh_index {
            commands.push(self.build_update_cache_command(manager)?);
        }

        // Get available updates
        if config.upgrade || config.check_only {
            available_updates = self.get_available_updates(config, manager).await?;
            
            if config.upgrade && config.dry_run {
                // Add upgrade commands for dry-run
                let upgrade_cmd = self.build_upgrade_command(config, manager, &available_updates).await?;
                commands.push(upgrade_cmd);
            }
        }

        let packages_scope = if config.packages.is_empty() { "all" } else { "subset" };

        Ok(json!({
            "backend": "pkg",
            "manager": format!("{:?}", manager).to_lowercase(),
            "alias": self.alias,
            "refresh_index": config.refresh_index,
            "upgrade": config.upgrade,
            "check_only": config.check_only,
            "dry_run": config.dry_run,
            "packages_scope": packages_scope,
            "commands": commands,
            "available_updates": available_updates
        }))
    }

    /// Handle check-only or dry-run upgrade modes
    async fn check_or_dry_run_upgrade(&self, config: &UpgradeConfig, manager: &ManagerKind) -> Result<Value, PkgError> {
        let mut commands = Vec::new();
        let mut available_updates = Vec::new();

        // Add refresh index command if requested
        if config.refresh_index {
            commands.push(self.build_update_cache_command(manager)?);
        }

        // Get available upgrades
        available_updates = self.get_available_upgrades(config, manager).await?;
        
        if !config.check_only && config.dry_run {
            // Add upgrade commands for dry-run
            let upgrade_cmd = self.build_upgrade_command_for_dry_run(config, manager, &available_updates).await?;
            commands.push(upgrade_cmd);
        }

        let packages_scope = if config.packages.is_empty() { "all" } else { "subset" };

        Ok(json!({
            "backend": "pkg",
            "manager": format!("{:?}", manager).to_lowercase(),
            "alias": self.alias,
            "refresh_index": config.refresh_index,
            "dry_run": config.dry_run,
            "check_only": config.check_only,
            "packages_scope": packages_scope,
            "commands": commands,
            "available_upgrades": available_updates
        }))
    }

    async fn upgrade_async(&self, config: UpgradeConfig) -> Result<Value, PkgError> {
        // Validate configuration
        self.validate_upgrade_config(&config)?;
        
        // Resolve manager
        let manager = self.resolve_manager(&config.manager).await?;
        
        // Check for check-only or dry-run modes
        if config.check_only || config.dry_run {
            return self.check_or_dry_run_upgrade(&config, &manager).await;
        }
        
        // Perform actual upgrade with timeout
        let result = timeout(
            Duration::from_millis(config.timeout_ms),
            self.perform_upgrade(&config, &manager)
        ).await
        .map_err(|_| PkgError::UpgradeTimeout)?;
        
        result
    }

    /// Perform actual update operation
    async fn perform_update(&self, config: &UpdateConfig, manager: &ManagerKind) -> Result<Value, PkgError> {
        let mut results = Vec::new();
        let mut summary = UpdateSummary {
            upgraded: 0,
            unchanged: 0,
            failed: 0,
        };

        // Step 1: Refresh index if requested
        if config.refresh_index {
            self.update_package_cache(manager).await
                .map_err(|e| PkgError::UpdateIndexFailed(e.to_string()))?;
        }

        // Step 2: Get available updates if needed
        let available_updates = if config.upgrade {
            self.get_available_updates(config, manager).await
                .map_err(|e| PkgError::UpdateCheckFailed(e.to_string()))?
        } else {
            Vec::new()
        };

        // Step 3: Apply upgrades if requested
        if config.upgrade && !available_updates.is_empty() {
            match self.apply_updates(config, manager, &available_updates).await {
                Ok(update_results) => {
                    for result in update_results {
                        match result.action.as_str() {
                            "upgraded" => summary.upgraded += 1,
                            "unchanged" => summary.unchanged += 1,
                            _ => summary.failed += 1,
                        }
                        results.push(result);
                    }
                }
                Err(e) => {
                    summary.failed = available_updates.len() as u32;
                    for update in &available_updates {
                        results.push(UpdateResult {
                            name: update.name.clone(),
                            previous_version: update.current_version.clone(),
                            new_version: None,
                            action: "failed".to_string(),
                        });
                    }
                    return Err(PkgError::UpdateFailed(e.to_string()));
                }
            }
        }

        let packages_scope = if config.packages.is_empty() { "all" } else { "subset" };

        Ok(json!({
            "backend": "pkg",
            "manager": format!("{:?}", manager).to_lowercase(),
            "alias": self.alias,
            "refresh_index": config.refresh_index,
            "upgrade": config.upgrade,
            "check_only": config.check_only,
            "dry_run": config.dry_run,
            "packages_scope": packages_scope,
            "packages": results,
            "summary": summary
        }))
    }

    /// Perform actual upgrade operation
    async fn perform_upgrade(&self, config: &UpgradeConfig, manager: &ManagerKind) -> Result<Value, PkgError> {
        let mut results = Vec::new();
        let mut summary = UpgradeSummary {
            upgraded: 0,
            unchanged: 0,
            failed: 0,
        };

        // Step 1: Refresh index if requested
        if config.refresh_index {
            self.update_package_cache(manager).await
                .map_err(|e| PkgError::UpgradeIndexFailed(e.to_string()))?;
        }

        // Step 2: Get available upgrades
        let available_upgrades = self.get_available_upgrades(config, manager).await
            .map_err(|e| PkgError::UpgradeCheckFailed(e.to_string()))?;

        // Step 3: Apply upgrades if there are any
        if !available_upgrades.is_empty() {
            match self.apply_upgrades(config, manager, &available_upgrades).await {
                Ok(upgrade_results) => {
                    for result in upgrade_results {
                        match result.action.as_str() {
                            "upgraded" => summary.upgraded += 1,
                            "unchanged" => summary.unchanged += 1,
                            _ => summary.failed += 1,
                        }
                        results.push(result);
                    }
                }
                Err(e) => {
                    summary.failed = available_upgrades.len() as u32;
                    for upgrade in &available_upgrades {
                        results.push(UpgradeResult {
                            name: upgrade.name.clone(),
                            previous_version: upgrade.current_version.clone(),
                            new_version: None,
                            action: "failed".to_string(),
                        });
                    }
                    return Err(PkgError::UpgradeFailed(e.to_string()));
                }
            }
        }

        let packages_scope = if config.packages.is_empty() { "all" } else { "subset" };

        Ok(json!({
            "backend": "pkg",
            "manager": format!("{:?}", manager).to_lowercase(),
            "alias": self.alias,
            "refresh_index": config.refresh_index,
            "dry_run": config.dry_run,
            "check_only": config.check_only,
            "packages_scope": packages_scope,
            "packages": results,
            "summary": summary
        }))
    }

    /// Get available updates for packages
    async fn get_available_updates(&self, config: &UpdateConfig, manager: &ManagerKind) -> Result<Vec<AvailableUpdate>, PkgError> {
        let cmd = match manager {
            ManagerKind::Apt => {
                if config.packages.is_empty() {
                    "apt list --upgradable 2>/dev/null | tail -n +2".to_string()
                } else {
                    format!("apt list --upgradable {} 2>/dev/null | tail -n +2", config.packages.join(" "))
                }
            },
            ManagerKind::Dnf | ManagerKind::Yum => {
                let base_cmd = if matches!(manager, ManagerKind::Dnf) { "dnf" } else { "yum" };
                if config.packages.is_empty() {
                    format!("{} check-update 2>/dev/null || true", base_cmd)
                } else {
                    format!("{} check-update {} 2>/dev/null || true", base_cmd, config.packages.join(" "))
                }
            },
            ManagerKind::Pacman => {
                if config.packages.is_empty() {
                    "pacman -Qu".to_string()
                } else {
                    format!("pacman -Qu {}", config.packages.join(" "))
                }
            },
            ManagerKind::Apk => {
                if config.packages.is_empty() {
                    "apk list -u 2>/dev/null".to_string()
                } else {
                    format!("apk list -u {} 2>/dev/null", config.packages.join(" "))
                }
            },
            ManagerKind::Brew => {
                if config.packages.is_empty() {
                    "brew outdated".to_string()
                } else {
                    format!("brew outdated {}", config.packages.join(" "))
                }
            },
            _ => return Err(PkgError::ManagerNotAvailable("Unsupported manager".to_string())),
        };

        let output = AsyncCommand::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()
            .await
            .map_err(|e| PkgError::UpdateCheckFailed(format!("Failed to check for updates: {}", e)))?;

        if !output.status.success() && output.status.code() != Some(100) { // 100 is normal for yum/dnf when no updates
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::UpdateCheckFailed(format!("Update check failed: {}", stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_available_updates(&stdout, manager)
    }

    /// Parse available updates from command output
    fn parse_available_updates(&self, output: &str, manager: &ManagerKind) -> Result<Vec<AvailableUpdate>, PkgError> {
        let mut updates = Vec::new();

        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let update = match manager {
                ManagerKind::Apt => self.parse_apt_update_line(line),
                ManagerKind::Dnf | ManagerKind::Yum => self.parse_dnf_yum_update_line(line),
                ManagerKind::Pacman => self.parse_pacman_update_line(line),
                ManagerKind::Apk => self.parse_apk_update_line(line),
                ManagerKind::Brew => self.parse_brew_update_line(line),
                _ => continue,
            };

            if let Some(update) = update {
                updates.push(update);
            }
        }

        Ok(updates)
    }

    /// Parse APT update line
    fn parse_apt_update_line(&self, line: &str) -> Option<AvailableUpdate> {
        // Format: "package/source version arch [upgradable from: current_version]"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 && line.contains("[upgradable from:") {
            let package_name = parts[0].split('/').next()?.to_string();
            let new_version = parts[1].to_string();
            let current_version = line.split("[upgradable from: ")
                .nth(1)?
                .split(']')
                .next()?
                .to_string();
            
            Some(AvailableUpdate {
                name: package_name,
                current_version: Some(current_version),
                candidate_version: new_version,
                security: line.contains("security"),
            })
        } else {
            None
        }
    }

    /// Parse DNF/YUM update line
    fn parse_dnf_yum_update_line(&self, line: &str) -> Option<AvailableUpdate> {
        // Format: "package.arch version repo"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let package_name = parts[0].split('.').next()?.to_string();
            let new_version = parts[1].to_string();
            
            Some(AvailableUpdate {
                name: package_name,
                current_version: None, // DNF check-update doesn't show current version
                candidate_version: new_version,
                security: parts.len() > 3 && parts[2].contains("security"),
            })
        } else {
            None
        }
    }

    /// Parse Pacman update line
    fn parse_pacman_update_line(&self, line: &str) -> Option<AvailableUpdate> {
        // Format: "package current_version -> new_version"
        let parts: Vec<&str> = line.split(" -> ").collect();
        if parts.len() == 2 {
            let left_part = parts[0].trim();
            let new_version = parts[1].trim().to_string();
            
            let left_parts: Vec<&str> = left_part.split_whitespace().collect();
            if left_parts.len() >= 2 {
                let package_name = left_parts[0].to_string();
                let current_version = left_parts[1].to_string();
                
                Some(AvailableUpdate {
                    name: package_name,
                    current_version: Some(current_version),
                    candidate_version: new_version,
                    security: false, // Pacman doesn't typically indicate security updates in this output
                })
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Parse APK update line  
    fn parse_apk_update_line(&self, line: &str) -> Option<AvailableUpdate> {
        // Format varies, but typically: "package-version [available: new-version]"
        if line.contains("[available:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let package_part = parts.get(0)?;
            let package_name = package_part.split('-').next()?.to_string();
            
            if let Some(avail_part) = line.split("[available: ").nth(1) {
                let new_version = avail_part.split(']').next()?.to_string();
                
                Some(AvailableUpdate {
                    name: package_name,
                    current_version: None, // APK output parsing is complex for current version
                    candidate_version: new_version,
                    security: false,
                })
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Parse Brew update line
    fn parse_brew_update_line(&self, line: &str) -> Option<AvailableUpdate> {
        // Format: "package (current_version) < new_version"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let package_name = parts[0].to_string();
            let current_version = parts[1].trim_start_matches('(').trim_end_matches(')').to_string();
            let new_version = parts[3].to_string();
            
            Some(AvailableUpdate {
                name: package_name,
                current_version: Some(current_version),
                candidate_version: new_version,
                security: false,
            })
        } else {
            None
        }
    }

    /// Build upgrade command
    async fn build_upgrade_command(&self, config: &UpdateConfig, manager: &ManagerKind, available_updates: &[AvailableUpdate]) -> Result<String, PkgError> {
        let mut cmd = match manager {
            ManagerKind::Apt => {
                let base_cmd = if config.security_only {
                    "DEBIAN_FRONTEND=noninteractive apt-get upgrade"  // Best effort for security
                } else {
                    "DEBIAN_FRONTEND=noninteractive apt-get upgrade"
                };
                let mut cmd = base_cmd.to_string();
                if config.assume_yes {
                    cmd.push_str(" -y");
                }
                if config.dry_run {
                    cmd.push_str(" -s");
                }
                cmd
            },
            ManagerKind::Dnf => {
                let mut cmd = if config.security_only {
                    "dnf update --security".to_string()
                } else {
                    "dnf upgrade".to_string()
                };
                if config.assume_yes {
                    cmd.push_str(" -y");
                }
                if config.dry_run {
                    cmd.push_str(" --assumeno");
                }
                cmd
            },
            ManagerKind::Yum => {
                let mut cmd = if config.security_only {
                    "yum update --security".to_string()
                } else {
                    "yum update".to_string()
                };
                if config.assume_yes {
                    cmd.push_str(" -y");
                }
                if config.dry_run {
                    cmd.push_str(" --assumeno");
                }
                cmd
            },
            ManagerKind::Pacman => {
                let mut cmd = "pacman -Su".to_string();
                if config.assume_yes {
                    cmd.push_str(" --noconfirm");
                }
                // Pacman doesn't have built-in dry-run for upgrades
                cmd
            },
            ManagerKind::Apk => {
                let mut cmd = "apk upgrade".to_string();
                if !config.assume_yes {
                    cmd.push_str(" --interactive");
                } else {
                    cmd.push_str(" --no-interactive");
                }
                cmd
            },
            ManagerKind::Brew => {
                "brew upgrade".to_string()
            },
            _ => return Err(PkgError::ManagerNotAvailable("Unsupported manager".to_string())),
        };

        // Add specific packages if requested
        if !config.packages.is_empty() {
            for package in &config.packages {
                cmd.push(' ');
                cmd.push_str(package);
            }
        }

        // Add extra args if specified
        if let Some(ref extra_args) = config.extra_args {
            for arg in extra_args {
                cmd.push(' ');
                cmd.push_str(arg);
            }
        }

        Ok(cmd)
    }

    /// Get available upgrades for packages
    async fn get_available_upgrades(&self, config: &UpgradeConfig, manager: &ManagerKind) -> Result<Vec<AvailableUpdate>, PkgError> {
        let cmd = match manager {
            ManagerKind::Apt => {
                if config.packages.is_empty() {
                    "apt list --upgradable 2>/dev/null | tail -n +2".to_string()
                } else {
                    format!("apt list --upgradable {} 2>/dev/null | tail -n +2", config.packages.join(" "))
                }
            },
            ManagerKind::Dnf | ManagerKind::Yum => {
                let base_cmd = if matches!(manager, ManagerKind::Dnf) { "dnf" } else { "yum" };
                if config.packages.is_empty() {
                    format!("{} check-update 2>/dev/null || true", base_cmd)
                } else {
                    format!("{} check-update {} 2>/dev/null || true", base_cmd, config.packages.join(" "))
                }
            },
            ManagerKind::Pacman => {
                if config.packages.is_empty() {
                    "pacman -Qu".to_string()
                } else {
                    format!("pacman -Qu {}", config.packages.join(" "))
                }
            },
            ManagerKind::Apk => {
                if config.packages.is_empty() {
                    "apk list -u 2>/dev/null".to_string()
                } else {
                    format!("apk list -u {} 2>/dev/null", config.packages.join(" "))
                }
            },
            ManagerKind::Brew => {
                if config.packages.is_empty() {
                    "brew outdated".to_string()
                } else {
                    format!("brew outdated {}", config.packages.join(" "))
                }
            },
            _ => return Err(PkgError::ManagerNotAvailable("Unsupported manager".to_string())),
        };

        let output = AsyncCommand::new("sh")
            .arg("-c")
            .arg(&cmd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| PkgError::UpgradeCheckFailed(format!("Failed to spawn command: {}", e)))?
            .wait_with_output()
            .await
            .map_err(|e| PkgError::UpgradeCheckFailed(format!("Failed to execute command: {}", e)))?;

        self.parse_available_upgrades(&String::from_utf8_lossy(&output.stdout), manager)
    }

    /// Parse available upgrades from command output
    fn parse_available_upgrades(&self, output: &str, manager: &ManagerKind) -> Result<Vec<AvailableUpdate>, PkgError> {
        let mut upgrades = Vec::new();
        
        match manager {
            ManagerKind::Apt => {
                for line in output.lines() {
                    if let Some(update) = self.parse_apt_update_line(line) {
                        upgrades.push(update);
                    }
                }
            },
            ManagerKind::Dnf | ManagerKind::Yum => {
                for line in output.lines() {
                    if let Some(update) = self.parse_dnf_yum_update_line(line) {
                        upgrades.push(update);
                    }
                }
            },
            ManagerKind::Pacman => {
                for line in output.lines() {
                    if let Some(update) = self.parse_pacman_update_line(line) {
                        upgrades.push(update);
                    }
                }
            },
            ManagerKind::Apk => {
                for line in output.lines() {
                    if let Some(update) = self.parse_apk_update_line(line) {
                        upgrades.push(update);
                    }
                }
            },
            ManagerKind::Brew => {
                for line in output.lines() {
                    if let Some(update) = self.parse_brew_update_line(line) {
                        upgrades.push(update);
                    }
                }
            },
            _ => return Err(PkgError::ManagerNotAvailable("Unsupported manager".to_string())),
        }
        
        Ok(upgrades)
    }

    /// Apply upgrades
    async fn apply_upgrades(&self, config: &UpgradeConfig, manager: &ManagerKind, available_upgrades: &[AvailableUpdate]) -> Result<Vec<UpgradeResult>, PkgError> {
        let mut results = Vec::new();

        // Get current versions before upgrade
        let mut current_versions = HashMap::new();
        for upgrade in available_upgrades {
            current_versions.insert(upgrade.name.clone(), upgrade.current_version.clone());
        }

        // Build and execute upgrade command
        let cmd = self.build_upgrade_command_for_execution(config, manager, available_upgrades).await?;
        
        let mut command = AsyncCommand::new("sh");
        command.arg("-c");
        command.arg(&cmd);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        // Set environment if specified
        if let Some(ref env) = config.env {
            for (key, value) in env {
                command.env(key, value);
            }
        }

        let output = command
            .spawn()
            .map_err(|e| PkgError::UpgradeFailed(format!("Failed to spawn upgrade command: {}", e)))?
            .wait_with_output()
            .await
            .map_err(|e| PkgError::UpgradeFailed(format!("Failed to execute upgrade command: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::UpgradeFailed(format!("Upgrade command failed: {}", stderr)));
        }

        // Create results for each attempted upgrade
        for upgrade in available_upgrades {
            let result = UpgradeResult {
                name: upgrade.name.clone(),
                previous_version: upgrade.current_version.clone(),
                new_version: Some(upgrade.candidate_version.clone()),
                action: "upgraded".to_string(),
            };
            results.push(result);
        }

        Ok(results)
    }

    /// Build upgrade command for dry run
    async fn build_upgrade_command_for_dry_run(&self, config: &UpgradeConfig, manager: &ManagerKind, _available_upgrades: &[AvailableUpdate]) -> Result<String, PkgError> {
        match manager {
            ManagerKind::Apt => {
                let mut cmd = String::from("apt-get -s upgrade");
                if config.assume_yes {
                    cmd.push_str(" -y");
                }
                if !config.packages.is_empty() {
                    cmd.push_str(" && apt-get -s install");
                    if config.assume_yes {
                        cmd.push_str(" -y");
                    }
                    for package in &config.packages {
                        cmd.push(' ');
                        cmd.push_str(package);
                    }
                }
                Ok(cmd)
            },
            ManagerKind::Dnf => {
                let cmd = if config.packages.is_empty() {
                    "dnf upgrade -y --assumeno".to_string()
                } else {
                    format!("dnf upgrade -y --assumeno {}", config.packages.join(" "))
                };
                Ok(cmd)
            },
            ManagerKind::Yum => {
                let cmd = if config.packages.is_empty() {
                    "yum update -y --assumeno".to_string()
                } else {
                    format!("yum update -y --assumeno {}", config.packages.join(" "))
                };
                Ok(cmd)
            },
            ManagerKind::Pacman => {
                Ok("pacman -Su --print".to_string())
            },
            ManagerKind::Apk => {
                let mut cmd = "apk upgrade --simulate".to_string();
                if !config.packages.is_empty() {
                    cmd.push(' ');
                    cmd.push_str(&config.packages.join(" "));
                }
                Ok(cmd)
            },
            ManagerKind::Brew => {
                Ok("brew outdated".to_string()) // Brew doesn't have a real dry-run for upgrade
            },
            _ => Err(PkgError::ManagerNotAvailable("Unsupported manager".to_string())),
        }
    }

    /// Build upgrade command for actual execution  
    async fn build_upgrade_command_for_execution(&self, config: &UpgradeConfig, manager: &ManagerKind, _available_upgrades: &[AvailableUpdate]) -> Result<String, PkgError> {
        match manager {
            ManagerKind::Apt => {
                let mut cmd = String::new();
                if config.assume_yes {
                    cmd.push_str("DEBIAN_FRONTEND=noninteractive ");
                }
                
                if config.packages.is_empty() {
                    cmd.push_str("apt-get upgrade");
                    if config.assume_yes {
                        cmd.push_str(" -y");
                    }
                } else {
                    cmd.push_str("apt-get install");
                    if config.assume_yes {
                        cmd.push_str(" -y");
                    }
                    for package in &config.packages {
                        cmd.push(' ');
                        cmd.push_str(package);
                    }
                }
                
                if let Some(ref extra_args) = config.extra_args {
                    for arg in extra_args {
                        cmd.push(' ');
                        cmd.push_str(arg);
                    }
                }
                Ok(cmd)
            },
            ManagerKind::Dnf => {
                let mut cmd = if config.packages.is_empty() {
                    "dnf upgrade".to_string()
                } else {
                    format!("dnf upgrade {}", config.packages.join(" "))
                };
                
                if config.assume_yes {
                    cmd.push_str(" -y");
                }
                
                if config.security_only {
                    cmd.push_str(" --security");
                }
                
                if let Some(ref extra_args) = config.extra_args {
                    for arg in extra_args {
                        cmd.push(' ');
                        cmd.push_str(arg);
                    }
                }
                Ok(cmd)
            },
            ManagerKind::Yum => {
                let mut cmd = if config.packages.is_empty() {
                    "yum update".to_string()
                } else {
                    format!("yum update {}", config.packages.join(" "))
                };
                
                if config.assume_yes {
                    cmd.push_str(" -y");
                }
                
                if let Some(ref extra_args) = config.extra_args {
                    for arg in extra_args {
                        cmd.push(' ');
                        cmd.push_str(arg);
                    }
                }
                Ok(cmd)
            },
            ManagerKind::Pacman => {
                let mut cmd = if config.packages.is_empty() {
                    "pacman -Su".to_string()
                } else {
                    format!("pacman -S {}", config.packages.join(" "))
                };
                
                if config.assume_yes {
                    cmd.push_str(" --noconfirm");
                }
                
                if let Some(ref extra_args) = config.extra_args {
                    for arg in extra_args {
                        cmd.push(' ');
                        cmd.push_str(arg);
                    }
                }
                Ok(cmd)
            },
            ManagerKind::Apk => {
                let mut cmd = "apk upgrade".to_string();
                
                if config.assume_yes {
                    cmd.push_str(" --no-interactive");
                }
                
                if !config.packages.is_empty() {
                    cmd.push(' ');
                    cmd.push_str(&config.packages.join(" "));
                }
                
                if let Some(ref extra_args) = config.extra_args {
                    for arg in extra_args {
                        cmd.push(' ');
                        cmd.push_str(arg);
                    }
                }
                Ok(cmd)
            },
            ManagerKind::Brew => {
                let mut cmd = "brew upgrade".to_string();
                
                if !config.packages.is_empty() {
                    cmd.push(' ');
                    cmd.push_str(&config.packages.join(" "));
                }
                
                if let Some(ref extra_args) = config.extra_args {
                    for arg in extra_args {
                        cmd.push(' ');
                        cmd.push_str(arg);
                    }
                }
                Ok(cmd)
            },
            _ => Err(PkgError::ManagerNotAvailable("Unsupported manager".to_string())),
        }
    }

    /// Apply updates
    async fn apply_updates(&self, config: &UpdateConfig, manager: &ManagerKind, available_updates: &[AvailableUpdate]) -> Result<Vec<UpdateResult>, PkgError> {
        let mut results = Vec::new();

        // Get current versions before upgrade
        let mut current_versions = HashMap::new();
        for update in available_updates {
            current_versions.insert(update.name.clone(), update.current_version.clone());
        }

        // Build and execute upgrade command
        let cmd = self.build_upgrade_command(config, manager, available_updates).await?;
        
        let mut command = AsyncCommand::new("sh");
        command.arg("-c").arg(&cmd);
        
        // Set environment variables if specified
        if let Some(ref env) = config.env {
            for (key, value) in env {
                command.env(key, value);
            }
        }

        let output = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| PkgError::UpdateFailed(format!("Failed to execute upgrade: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(self.map_update_error(&stderr, &output.status.code()));
        }

        // Create results for packages
        for update in available_updates {
            // Check if package should be included based on config.packages filter
            if !config.packages.is_empty() && !config.packages.contains(&update.name) {
                continue;
            }

            // For simplicity, assume all available updates were applied successfully
            // In production, you might want to check actual final versions
            let action = "upgraded".to_string();
            
            results.push(UpdateResult {
                name: update.name.clone(),
                previous_version: update.current_version.clone(),
                new_version: Some(update.candidate_version.clone()),
                action,
            });
        }

        Ok(results)
    }

    /// Map update error from stderr and exit code
    fn map_update_error(&self, stderr: &str, exit_code: &Option<i32>) -> PkgError {
        let stderr_lower = stderr.to_lowercase();
        
        // Check for specific error patterns
        if stderr_lower.contains("permission denied") || stderr_lower.contains("not allowed") || exit_code == &Some(13) {
            PkgError::UpdatePermissionDenied(stderr.to_string())
        } else if stderr_lower.contains("index") || stderr_lower.contains("cache") || stderr_lower.contains("metadata") {
            PkgError::UpdateIndexFailed(stderr.to_string())
        } else if stderr_lower.contains("check") || stderr_lower.contains("available") {
            PkgError::UpdateCheckFailed(stderr.to_string())
        } else {
            PkgError::UpdateFailed(stderr.to_string())
        }
    }

    async fn info_async(&self, config: InfoConfig) -> Result<Value, PkgError> {
        // Validate configuration
        self.validate_info_config(&config)?;
        
        // Resolve manager
        let manager = self.resolve_manager(&config.manager).await?;
        
        // Perform info query with timeout
        let result = timeout(
            Duration::from_millis(config.timeout_ms),
            self.perform_info_query(&config, &manager)
        ).await
        .map_err(|_| PkgError::InfoTimeout)?;
        
        result
    }

    async fn perform_info_query(&self, config: &InfoConfig, manager: &ManagerKind) -> Result<Value, PkgError> {
        let mut packages = Vec::new();
        let mut partial_failures = 0;
        
        for package_name in &config.packages {
            match self.query_single_package(package_name, config, manager).await {
                Ok(package_info) => packages.push(package_info),
                Err(e) => {
                    eprintln!("Failed to query package {}: {}", package_name, e);
                    partial_failures += 1;
                    // Add a failed package result
                    packages.push(PackageInfo {
                        name: package_name.clone(),
                        found: false,
                        installed: false,
                        installed_version: None,
                        candidate_version: None,
                        architecture: None,
                        summary: None,
                        description: None,
                        homepage: None,
                        license: None,
                        repository: None,
                        dependencies: None,
                        reverse_dependencies: None,
                        files: None,
                        raw: Some(json!({ "error": e.to_string() })),
                    });
                }
            }
        }

        // If all packages failed, return error
        if partial_failures == config.packages.len() {
            return Err(PkgError::InfoQueryFailed("All packages failed to query".to_string()));
        }

        // If some packages failed, log but continue
        if partial_failures > 0 {
            eprintln!("Warning: {} out of {} packages failed to query", partial_failures, config.packages.len());
        }

        Ok(json!({
            "backend": "pkg",
            "manager": format!("{:?}", manager).to_lowercase(),
            "alias": self.alias,
            "packages": packages
        }))
    }

    async fn query_single_package(&self, package_name: &str, config: &InfoConfig, manager: &ManagerKind) -> Result<PackageInfo, PkgError> {
        match manager {
            ManagerKind::Apt => self.query_apt_package(package_name, config).await,
            ManagerKind::Yum | ManagerKind::Dnf => self.query_yum_dnf_package(package_name, config, manager).await,
            ManagerKind::Pacman => self.query_pacman_package(package_name, config).await,
            ManagerKind::Apk => self.query_apk_package(package_name, config).await,
            ManagerKind::Brew => self.query_brew_package(package_name, config).await,
            ManagerKind::Auto => unreachable!("Auto should have been resolved by now"),
        }
    }

    async fn query_apt_package(&self, package_name: &str, config: &InfoConfig) -> Result<PackageInfo, PkgError> {
        let mut package_info = PackageInfo {
            name: package_name.to_string(),
            found: false,
            installed: false,
            installed_version: None,
            candidate_version: None,
            architecture: None,
            summary: None,
            description: None,
            homepage: None,
            license: None,
            repository: None,
            dependencies: None,
            reverse_dependencies: None,
            files: None,
            raw: None,
        };

        // Check installed status with dpkg
        let dpkg_output = self.run_command("dpkg", &["-s", package_name], config.env.as_ref()).await;
        
        if let Ok(output) = dpkg_output {
            if output.status.success() {
                package_info.installed = true;
                // Parse dpkg output for version and architecture
                for line in output.stdout.lines() {
                    if line.starts_with("Version: ") {
                        package_info.installed_version = Some(line[9..].to_string());
                    } else if line.starts_with("Architecture: ") {
                        package_info.architecture = Some(line[14..].to_string());
                    }
                }
            }
        }

        // Get package information from apt-cache
        let show_output = self.run_command("apt-cache", &["show", package_name], config.env.as_ref()).await;
        
        if let Ok(output) = show_output {
            if output.status.success() && !output.stdout.trim().is_empty() {
                package_info.found = true;
                
                // Parse apt-cache show output
                let mut current_description = String::new();
                let mut in_description = false;
                
                for line in output.stdout.lines() {
                    if line.starts_with("Package: ") {
                        // Confirm package name
                    } else if line.starts_with("Version: ") && package_info.candidate_version.is_none() {
                        package_info.candidate_version = Some(line[9..].to_string());
                    } else if line.starts_with("Architecture: ") && package_info.architecture.is_none() {
                        package_info.architecture = Some(line[14..].to_string());
                    } else if line.starts_with("Maintainer: ") {
                        // Could be used for additional metadata
                    } else if line.starts_with("Homepage: ") {
                        package_info.homepage = Some(line[10..].to_string());
                    } else if line.starts_with("Section: ") {
                        // Could be used for categorization
                    } else if line.starts_with("Description: ") {
                        package_info.summary = Some(line[13..].to_string());
                        in_description = true;
                    } else if line.starts_with("Description-md5: ") {
                        in_description = false;
                    } else if in_description && line.starts_with(" ") {
                        if !current_description.is_empty() {
                            current_description.push('\n');
                        }
                        current_description.push_str(line.trim());
                    } else if line.starts_with("Depends: ") && config.include_dependencies {
                        let deps = self.parse_apt_dependencies(line);
                        package_info.dependencies = Some(PackageDependencies {
                            runtime: deps,
                            build: Vec::new(),
                            optional: Vec::new(),
                        });
                    }
                }
                
                if !current_description.is_empty() {
                    package_info.description = Some(current_description);
                }
            }
        }

        // Get candidate version and repository information
        let policy_output = self.run_command("apt-cache", &["policy", package_name], config.env.as_ref()).await;
        
        if let Ok(output) = policy_output {
            if output.status.success() {
                for line in output.stdout.lines() {
                    if line.trim().starts_with("Candidate: ") {
                        let candidate = line.trim()[11..].trim();
                        if candidate != "(none)" {
                            package_info.candidate_version = Some(candidate.to_string());
                        }
                    } else if line.trim().contains("http") && package_info.repository.is_none() {
                        // Parse repository info from lines like: " 500 http://archive.ubuntu.com/ubuntu focal/main amd64 Packages"
                        if let Some(repo_part) = line.trim().split_whitespace().nth(1) {
                            package_info.repository = Some(repo_part.to_string());
                        }
                    }
                }
            }
        }

        // Handle dependencies if requested
        if config.include_dependencies && package_info.dependencies.is_none() {
            if let Ok(deps_output) = self.run_command("apt-cache", &["depends", package_name], config.env.as_ref()).await {
                if deps_output.status.success() {
                    let deps = self.parse_apt_depends_output(&deps_output.stdout);
                    package_info.dependencies = Some(deps);
                }
            }
        }

        // Handle reverse dependencies if requested
        if config.include_reverse_deps {
            if let Ok(rdeps_output) = self.run_command("apt-cache", &["rdepends", package_name], config.env.as_ref()).await {
                if rdeps_output.status.success() {
                    let rdeps = self.parse_apt_rdepends_output(&rdeps_output.stdout);
                    package_info.reverse_dependencies = Some(rdeps);
                }
            }
        }

        // Handle files listing if requested and package is installed
        if config.include_files && package_info.installed {
            if let Ok(files_output) = self.run_command("dpkg", &["-L", package_name], config.env.as_ref()).await {
                if files_output.status.success() {
                    let files: Vec<String> = files_output.stdout.lines()
                        .map(|s| s.to_string())
                        .collect();
                    package_info.files = Some(files);
                }
            }
        }

        Ok(package_info)
    }

    async fn query_yum_dnf_package(&self, package_name: &str, config: &InfoConfig, manager: &ManagerKind) -> Result<PackageInfo, PkgError> {
        let mut package_info = PackageInfo {
            name: package_name.to_string(),
            found: false,
            installed: false,
            installed_version: None,
            candidate_version: None,
            architecture: None,
            summary: None,
            description: None,
            homepage: None,
            license: None,
            repository: None,
            dependencies: None,
            reverse_dependencies: None,
            files: None,
            raw: None,
        };

        let cmd = if manager == &ManagerKind::Dnf { "dnf" } else { "yum" };

        // Check installed status with rpm
        let rpm_output = self.run_command("rpm", &["-q", package_name], config.env.as_ref()).await;
        
        if let Ok(output) = rpm_output {
            if output.status.success() {
                package_info.installed = true;
                // Parse version from rpm output like "package-1.2.3-1.el8.x86_64"
                if let Some(version_part) = output.stdout.trim().strip_prefix(&format!("{}-", package_name)) {
                    if let Some(version_end) = version_part.rfind('.') {
                        let version_arch = &version_part[..version_end];
                        if let Some(arch_start) = version_arch.rfind('.') {
                            package_info.installed_version = Some(version_arch[..arch_start].to_string());
                            package_info.architecture = Some(version_arch[arch_start + 1..].to_string());
                        } else {
                            package_info.installed_version = Some(version_arch.to_string());
                        }
                    }
                }
            }
        }

        // Get package information
        let info_output = self.run_command(cmd, &["info", package_name], config.env.as_ref()).await;
        
        if let Ok(output) = info_output {
            if output.status.success() && !output.stdout.trim().is_empty() {
                package_info.found = true;
                
                let mut in_description = false;
                let mut current_description = String::new();
                
                for line in output.stdout.lines() {
                    if line.starts_with("Name         : ") {
                        // Confirm package name
                    } else if line.starts_with("Version      : ") && package_info.candidate_version.is_none() {
                        package_info.candidate_version = Some(line[15..].trim().to_string());
                    } else if line.starts_with("Architecture : ") && package_info.architecture.is_none() {
                        package_info.architecture = Some(line[15..].trim().to_string());
                    } else if line.starts_with("Summary      : ") {
                        package_info.summary = Some(line[15..].trim().to_string());
                    } else if line.starts_with("URL          : ") {
                        package_info.homepage = Some(line[15..].trim().to_string());
                    } else if line.starts_with("License      : ") {
                        package_info.license = Some(line[15..].trim().to_string());
                    } else if line.starts_with("Repository   : ") || line.starts_with("Repo         : ") {
                        let repo = if line.starts_with("Repository   : ") {
                            line[15..].trim()
                        } else {
                            line[15..].trim()
                        };
                        package_info.repository = Some(repo.to_string());
                    } else if line.starts_with("Description  : ") {
                        current_description = line[15..].trim().to_string();
                        in_description = true;
                    } else if in_description && line.starts_with("           : ") {
                        if !current_description.is_empty() {
                            current_description.push('\n');
                        }
                        current_description.push_str(line[13..].trim());
                    } else if line.trim().is_empty() || (!line.starts_with("           ") && in_description) {
                        if in_description && !current_description.is_empty() {
                            package_info.description = Some(current_description.clone());
                        }
                        in_description = false;
                    }
                }
                
                if in_description && !current_description.is_empty() {
                    package_info.description = Some(current_description);
                }
            }
        }

        // Handle files listing if requested and package is installed
        if config.include_files && package_info.installed {
            if let Ok(files_output) = self.run_command("rpm", &["-ql", package_name], config.env.as_ref()).await {
                if files_output.status.success() {
                    let files: Vec<String> = files_output.stdout.lines()
                        .map(|s| s.to_string())
                        .collect();
                    package_info.files = Some(files);
                }
            }
        }

        Ok(package_info)
    }

    async fn query_pacman_package(&self, package_name: &str, config: &InfoConfig) -> Result<PackageInfo, PkgError> {
        let mut package_info = PackageInfo {
            name: package_name.to_string(),
            found: false,
            installed: false,
            installed_version: None,
            candidate_version: None,
            architecture: None,
            summary: None,
            description: None,
            homepage: None,
            license: None,
            repository: None,
            dependencies: None,
            reverse_dependencies: None,
            files: None,
            raw: None,
        };

        // Check installed status
        let qi_output = self.run_command("pacman", &["-Qi", package_name], config.env.as_ref()).await;
        
        if let Ok(output) = qi_output {
            if output.status.success() {
                package_info.installed = true;
                package_info.found = true;
                
                // Parse pacman -Qi output
                for line in output.stdout.lines() {
                    if line.starts_with("Version         : ") {
                        package_info.installed_version = Some(line[18..].trim().to_string());
                        package_info.candidate_version = Some(line[18..].trim().to_string()); // Same as installed for local query
                    } else if line.starts_with("Architecture    : ") {
                        package_info.architecture = Some(line[18..].trim().to_string());
                    } else if line.starts_with("Description     : ") {
                        package_info.summary = Some(line[18..].trim().to_string());
                        package_info.description = Some(line[18..].trim().to_string());
                    } else if line.starts_with("URL             : ") {
                        package_info.homepage = Some(line[18..].trim().to_string());
                    } else if line.starts_with("Licenses        : ") {
                        package_info.license = Some(line[18..].trim().to_string());
                    } else if line.starts_with("Repository      : ") {
                        package_info.repository = Some(line[18..].trim().to_string());
                    } else if line.starts_with("Depends On      : ") && config.include_dependencies {
                        let deps = self.parse_pacman_dependencies(line[18..].trim());
                        package_info.dependencies = Some(PackageDependencies {
                            runtime: deps,
                            build: Vec::new(),
                            optional: Vec::new(),
                        });
                    }
                }
            }
        }

        // If not installed, check if available
        if !package_info.installed {
            let si_output = self.run_command("pacman", &["-Si", package_name], config.env.as_ref()).await;
            
            if let Ok(output) = si_output {
                if output.status.success() {
                    package_info.found = true;
                    
                    // Parse pacman -Si output
                    for line in output.stdout.lines() {
                        if line.starts_with("Version         : ") {
                            package_info.candidate_version = Some(line[18..].trim().to_string());
                        } else if line.starts_with("Architecture    : ") {
                            package_info.architecture = Some(line[18..].trim().to_string());
                        } else if line.starts_with("Description     : ") {
                            package_info.summary = Some(line[18..].trim().to_string());
                            package_info.description = Some(line[18..].trim().to_string());
                        } else if line.starts_with("URL             : ") {
                            package_info.homepage = Some(line[18..].trim().to_string());
                        } else if line.starts_with("Licenses        : ") {
                            package_info.license = Some(line[18..].trim().to_string());
                        } else if line.starts_with("Repository      : ") {
                            package_info.repository = Some(line[18..].trim().to_string());
                        } else if line.starts_with("Depends On      : ") && config.include_dependencies {
                            let deps = self.parse_pacman_dependencies(line[18..].trim());
                            package_info.dependencies = Some(PackageDependencies {
                                runtime: deps,
                                build: Vec::new(),
                                optional: Vec::new(),
                            });
                        }
                    }
                }
            }
        }

        // Handle files listing if requested and package is installed
        if config.include_files && package_info.installed {
            if let Ok(files_output) = self.run_command("pacman", &["-Ql", package_name], config.env.as_ref()).await {
                if files_output.status.success() {
                    let files: Vec<String> = files_output.stdout.lines()
                        .filter(|line| line.contains(' ')) // Filter out just the package name line
                        .map(|line| {
                            // pacman -Ql output format: "package_name /path/to/file"
                            if let Some(space_pos) = line.find(' ') {
                                line[space_pos + 1..].to_string()
                            } else {
                                line.to_string()
                            }
                        })
                        .collect();
                    package_info.files = Some(files);
                }
            }
        }

        Ok(package_info)
    }

    async fn query_apk_package(&self, package_name: &str, config: &InfoConfig) -> Result<PackageInfo, PkgError> {
        let mut package_info = PackageInfo {
            name: package_name.to_string(),
            found: false,
            installed: false,
            installed_version: None,
            candidate_version: None,
            architecture: None,
            summary: None,
            description: None,
            homepage: None,
            license: None,
            repository: None,
            dependencies: None,
            reverse_dependencies: None,
            files: None,
            raw: None,
        };

        // Check installed status
        let installed_output = self.run_command("apk", &["info", "-e", package_name], config.env.as_ref()).await;
        
        if let Ok(output) = installed_output {
            if output.status.success() && !output.stdout.trim().is_empty() {
                package_info.installed = true;
                package_info.found = true;
            }
        }

        // Get package information
        let info_output = self.run_command("apk", &["info", "-a", package_name], config.env.as_ref()).await;
        
        if let Ok(output) = info_output {
            if output.status.success() && !output.stdout.trim().is_empty() {
                package_info.found = true;
                
                // Parse apk info output
                for line in output.stdout.lines() {
                    if line.starts_with(&format!("{}-", package_name)) {
                        // Parse version from line like "package-1.2.3-r0"
                        if let Some(version_start) = line.find('-') {
                            let version_part = &line[version_start + 1..];
                            if let Some(release_start) = version_part.rfind('-') {
                                package_info.candidate_version = Some(version_part[..release_start].to_string());
                            } else {
                                package_info.candidate_version = Some(version_part.to_string());
                            }
                        }
                        if package_info.installed {
                            package_info.installed_version = package_info.candidate_version.clone();
                        }
                    } else if line.starts_with("description:") {
                        package_info.summary = Some(line[12..].trim().to_string());
                        package_info.description = Some(line[12..].trim().to_string());
                    } else if line.starts_with("webpage:") {
                        package_info.homepage = Some(line[8..].trim().to_string());
                    } else if line.starts_with("license:") {
                        package_info.license = Some(line[8..].trim().to_string());
                    }
                }
            }
        }

        // Handle files listing if requested and package is installed
        if config.include_files && package_info.installed {
            if let Ok(files_output) = self.run_command("apk", &["info", "-L", package_name], config.env.as_ref()).await {
                if files_output.status.success() {
                    let files: Vec<String> = files_output.stdout.lines()
                        .skip(1) // Skip the first line which is usually the package name
                        .filter(|line| !line.trim().is_empty())
                        .map(|s| s.to_string())
                        .collect();
                    package_info.files = Some(files);
                }
            }
        }

        Ok(package_info)
    }

    async fn query_brew_package(&self, package_name: &str, config: &InfoConfig) -> Result<PackageInfo, PkgError> {
        let mut package_info = PackageInfo {
            name: package_name.to_string(),
            found: false,
            installed: false,
            installed_version: None,
            candidate_version: None,
            architecture: None,
            summary: None,
            description: None,
            homepage: None,
            license: None,
            repository: None,
            dependencies: None,
            reverse_dependencies: None,
            files: None,
            raw: None,
        };

        // Check installed status
        let list_output = self.run_command("brew", &["list", "--versions", package_name], config.env.as_ref()).await;
        
        if let Ok(output) = list_output {
            if output.status.success() && !output.stdout.trim().is_empty() {
                package_info.installed = true;
                // Parse version from output like "package 1.2.3"
                if let Some(space_pos) = output.stdout.trim().find(' ') {
                    package_info.installed_version = Some(output.stdout.trim()[space_pos + 1..].trim().to_string());
                }
            }
        }

        // Get package information using JSON output
        let json_output = self.run_command("brew", &["info", "--json=v2", package_name], config.env.as_ref()).await;
        
        if let Ok(output) = json_output {
            if output.status.success() && !output.stdout.trim().is_empty() {
                if let Ok(json_data) = serde_json::from_str::<Value>(&output.stdout) {
                    if let Some(formulae) = json_data["formulae"].as_array() {
                        if let Some(formula) = formulae.first() {
                            package_info.found = true;
                            
                            if let Some(name) = formula["name"].as_str() {
                                package_info.name = name.to_string();
                            }
                            if let Some(desc) = formula["desc"].as_str() {
                                package_info.summary = Some(desc.to_string());
                            }
                            if let Some(homepage) = formula["homepage"].as_str() {
                                package_info.homepage = Some(homepage.to_string());
                            }
                            if let Some(versions) = formula["versions"].as_object() {
                                if let Some(stable) = versions["stable"].as_str() {
                                    package_info.candidate_version = Some(stable.to_string());
                                }
                            }
                            if let Some(license) = formula["license"].as_str() {
                                package_info.license = Some(license.to_string());
                            }
                            
                            // Handle dependencies
                            if config.include_dependencies {
                                let mut runtime_deps = Vec::new();
                                let mut build_deps = Vec::new();
                                let mut optional_deps = Vec::new();
                                
                                if let Some(deps) = formula["dependencies"].as_array() {
                                    for dep in deps {
                                        if let Some(dep_str) = dep.as_str() {
                                            runtime_deps.push(dep_str.to_string());
                                        }
                                    }
                                }
                                if let Some(build_deps_array) = formula["build_dependencies"].as_array() {
                                    for dep in build_deps_array {
                                        if let Some(dep_str) = dep.as_str() {
                                            build_deps.push(dep_str.to_string());
                                        }
                                    }
                                }
                                if let Some(optional_deps_array) = formula["optional_dependencies"].as_array() {
                                    for dep in optional_deps_array {
                                        if let Some(dep_str) = dep.as_str() {
                                            optional_deps.push(dep_str.to_string());
                                        }
                                    }
                                }
                                
                                package_info.dependencies = Some(PackageDependencies {
                                    runtime: runtime_deps,
                                    build: build_deps,
                                    optional: optional_deps,
                                });
                            }
                            
                            // Store raw JSON for debugging
                            package_info.raw = Some(formula.clone());
                        }
                    }
                    
                    // Also check casks
                    if !package_info.found {
                        if let Some(casks) = json_data["casks"].as_array() {
                            if let Some(cask) = casks.first() {
                                package_info.found = true;
                                
                                if let Some(name) = cask["token"].as_str() {
                                    package_info.name = name.to_string();
                                }
                                if let Some(desc) = cask["desc"].as_str() {
                                    package_info.summary = Some(desc.to_string());
                                }
                                if let Some(homepage) = cask["homepage"].as_str() {
                                    package_info.homepage = Some(homepage.to_string());
                                }
                                if let Some(version) = cask["version"].as_str() {
                                    package_info.candidate_version = Some(version.to_string());
                                }
                                
                                package_info.raw = Some(cask.clone());
                            }
                        }
                    }
                }
            }
        }

        // Handle reverse dependencies if requested
        if config.include_reverse_deps {
            if let Ok(rdeps_output) = self.run_command("brew", &["uses", package_name], config.env.as_ref()).await {
                if rdeps_output.status.success() {
                    let rdeps: Vec<String> = rdeps_output.stdout.lines()
                        .filter(|line| !line.trim().is_empty())
                        .map(|s| s.to_string())
                        .collect();
                    if !rdeps.is_empty() {
                        package_info.reverse_dependencies = Some(rdeps);
                    }
                }
            }
        }

        // Handle files listing if requested and package is installed
        if config.include_files && package_info.installed {
            if let Ok(files_output) = self.run_command("brew", &["list", package_name], config.env.as_ref()).await {
                if files_output.status.success() {
                    let files: Vec<String> = files_output.stdout.lines()
                        .filter(|line| !line.trim().is_empty())
                        .map(|s| s.to_string())
                        .collect();
                    package_info.files = Some(files);
                }
            }
        }

        Ok(package_info)
    }

    async fn search_async(&self, config: SearchConfig) -> Result<Value, PkgError> {
        // Validate configuration
        self.validate_search_config(&config)?;
        
        // Resolve manager
        let manager = self.resolve_manager(&config.manager).await?;
        
        // Perform search query with timeout
        let result = timeout(
            Duration::from_millis(config.timeout_ms),
            self.perform_search_query(&config, &manager)
        ).await
        .map_err(|_| PkgError::SearchTimeout)?;
        
        result
    }

    fn validate_search_config(&self, config: &SearchConfig) -> Result<(), PkgError> {
        if config.query.trim().is_empty() {
            return Err(PkgError::InvalidSearchConfig("Query cannot be empty".to_string()));
        }

        if config.timeout_ms == 0 {
            return Err(PkgError::InvalidSearchConfig("Timeout must be greater than 0".to_string()));
        }

        if config.limit == 0 {
            return Err(PkgError::InvalidSearchConfig("Limit must be greater than 0".to_string()));
        }

        // Validate search_in fields
        for field in &config.search_in {
            match field {
                SearchField::Name | SearchField::Description | SearchField::All => {},
            }
        }

        if let Some(extra_args) = &config.extra_args {
            for arg in extra_args {
                if arg.trim().is_empty() {
                    return Err(PkgError::InvalidSearchConfig("Extra args cannot contain empty strings".to_string()));
                }
            }
        }

        Ok(())
    }

    async fn perform_search_query(&self, config: &SearchConfig, manager: &ManagerKind) -> Result<Value, PkgError> {
        // Get raw search results from the package manager
        let raw_results = match manager {
            ManagerKind::Apt => self.search_apt(&config.query, config).await?,
            ManagerKind::Yum | ManagerKind::Dnf => self.search_yum_dnf(&config.query, config, manager).await?,
            ManagerKind::Pacman => self.search_pacman(&config.query, config).await?,
            ManagerKind::Apk => self.search_apk(&config.query, config).await?,
            ManagerKind::Brew => self.search_brew(&config.query, config).await?,
            ManagerKind::Auto => unreachable!("Auto should have been resolved by now"),
        };

        // Apply filters and sorting
        let filtered_results = self.filter_and_sort_results(raw_results, config);
        
        // Apply pagination
        let total_matches = filtered_results.len() as u32;
        let start = config.offset as usize;
        let end = std::cmp::min(start + config.limit as usize, filtered_results.len());
        
        let paginated_results = if start < filtered_results.len() {
            filtered_results[start..end].to_vec()
        } else {
            vec![]
        };

        Ok(json!(SearchResults {
            backend: "pkg".to_string(),
            manager: format!("{:?}", manager).to_lowercase(),
            alias: self.alias.clone(),
            query: config.query.clone(),
            search_in: config.search_in.clone(),
            exact: config.exact,
            case_sensitive: config.case_sensitive,
            limit: config.limit,
            offset: config.offset,
            total_matches,
            results: paginated_results,
        }))
    }

    async fn search_apt(&self, query: &str, config: &SearchConfig) -> Result<Vec<SearchResult>, PkgError> {
        let mut cmd_args = vec!["search", query];
        if let Some(extra_args) = &config.extra_args {
            cmd_args.extend(extra_args.iter().map(|s| s.as_str()));
        }

        let output = self.run_command("apt", &cmd_args, config.env.as_ref()).await
            .map_err(|e| PkgError::SearchFailed(format!("APT search command failed: {}", e)))?;

        if !output.status.success() {
            return Err(PkgError::SearchFailed(format!("APT search failed: {}", output.stderr)));
        }

        let mut results = Vec::new();
        let lines: Vec<&str> = output.stdout.lines().collect();
        
        for line in lines {
            if line.trim().is_empty() || line.starts_with("WARNING:") || line.starts_with("NOTE:") {
                continue;
            }
            
            // Parse APT search output: "package-name - description"
            if let Some(dash_pos) = line.find(" - ") {
                let name = line[..dash_pos].trim();
                let summary = line[dash_pos + 3..].trim();
                
                // Get additional metadata if requested
                let mut search_result = SearchResult {
                    name: name.to_string(),
                    version: None,
                    installed: false,
                    summary: Some(summary.to_string()),
                    description: None,
                    repository: None,
                    homepage: None,
                    score: 1.0,
                };

                if config.include_versions || config.include_installed {
                    if let Ok(policy_output) = self.run_command("apt-cache", &["policy", name], config.env.as_ref()).await {
                        if policy_output.status.success() {
                            for policy_line in policy_output.stdout.lines() {
                                if policy_line.trim().starts_with("Candidate:") && config.include_versions {
                                    let version = policy_line.trim().strip_prefix("Candidate:").unwrap_or("").trim();
                                    if version != "(none)" {
                                        search_result.version = Some(version.to_string());
                                    }
                                }
                                if policy_line.trim().starts_with("Installed:") && config.include_installed {
                                    let installed_version = policy_line.trim().strip_prefix("Installed:").unwrap_or("").trim();
                                    search_result.installed = installed_version != "(none)";
                                }
                            }
                        }
                    }
                }

                if config.include_repo {
                    if let Ok(show_output) = self.run_command("apt-cache", &["show", name], config.env.as_ref()).await {
                        if show_output.status.success() {
                            for show_line in show_output.stdout.lines() {
                                if show_line.starts_with("Filename:") {
                                    if let Some(repo_part) = show_line.split('/').nth(1) {
                                        search_result.repository = Some(repo_part.to_string());
                                    }
                                } else if show_line.starts_with("Homepage:") {
                                    search_result.homepage = Some(show_line[9..].trim().to_string());
                                }
                            }
                        }
                    }
                }

                results.push(search_result);
            }
        }

        Ok(results)
    }

    async fn search_yum_dnf(&self, query: &str, config: &SearchConfig, manager: &ManagerKind) -> Result<Vec<SearchResult>, PkgError> {
        let cmd = match manager {
            ManagerKind::Dnf => "dnf",
            ManagerKind::Yum => "yum",
            _ => unreachable!(),
        };

        let mut cmd_args = vec!["search", query];
        if let Some(extra_args) = &config.extra_args {
            cmd_args.extend(extra_args.iter().map(|s| s.as_str()));
        }

        let output = self.run_command(cmd, &cmd_args, config.env.as_ref()).await
            .map_err(|e| PkgError::SearchFailed(format!("{} search command failed: {}", cmd, e)))?;

        if !output.status.success() {
            return Err(PkgError::SearchFailed(format!("{} search failed: {}", cmd, output.stderr)));
        }

        let mut results = Vec::new();
        let lines: Vec<&str> = output.stdout.lines().collect();
        
        for line in lines {
            if line.trim().is_empty() || line.contains("==") || line.starts_with("Last metadata") {
                continue;
            }
            
            // Parse YUM/DNF search output: "package.arch : description"
            if let Some(colon_pos) = line.find(" : ") {
                let name_part = line[..colon_pos].trim();
                let summary = line[colon_pos + 3..].trim();
                
                // Extract just the package name (remove architecture)
                let name = if let Some(dot_pos) = name_part.find('.') {
                    &name_part[..dot_pos]
                } else {
                    name_part
                };
                
                let mut search_result = SearchResult {
                    name: name.to_string(),
                    version: None,
                    installed: false,
                    summary: Some(summary.to_string()),
                    description: None,
                    repository: None,
                    homepage: None,
                    score: 1.0,
                };

                if config.include_versions || config.include_installed {
                    if let Ok(info_output) = self.run_command(cmd, &["info", name], config.env.as_ref()).await {
                        if info_output.status.success() {
                            for info_line in info_output.stdout.lines() {
                                if info_line.starts_with("Version") && config.include_versions {
                                    if let Some(version) = info_line.split(':').nth(1) {
                                        search_result.version = Some(version.trim().to_string());
                                    }
                                }
                                if info_line.starts_with("Repository") && config.include_repo {
                                    if let Some(repo) = info_line.split(':').nth(1) {
                                        search_result.repository = Some(repo.trim().to_string());
                                    }
                                }
                                if info_line.starts_with("URL") {
                                    if let Some(url) = info_line.split(':').nth(1) {
                                        search_result.homepage = Some(url.trim().to_string());
                                    }
                                }
                            }
                        }
                    }
                }

                if config.include_installed {
                    if let Ok(list_output) = self.run_command(cmd, &["list", "installed", name], config.env.as_ref()).await {
                        search_result.installed = list_output.status.success() && !list_output.stdout.is_empty();
                    }
                }

                results.push(search_result);
            }
        }

        Ok(results)
    }

    async fn search_pacman(&self, query: &str, config: &SearchConfig) -> Result<Vec<SearchResult>, PkgError> {
        let mut cmd_args = vec!["-Ss", query];
        if let Some(extra_args) = &config.extra_args {
            cmd_args.extend(extra_args.iter().map(|s| s.as_str()));
        }

        let output = self.run_command("pacman", &cmd_args, config.env.as_ref()).await
            .map_err(|e| PkgError::SearchFailed(format!("Pacman search command failed: {}", e)))?;

        if !output.status.success() {
            return Err(PkgError::SearchFailed(format!("Pacman search failed: {}", output.stderr)));
        }

        let mut results = Vec::new();
        let lines: Vec<&str> = output.stdout.lines().collect();
        let mut i = 0;
        
        while i < lines.len() {
            let line = lines[i].trim();
            if line.is_empty() {
                i += 1;
                continue;
            }
            
            // Parse pacman output: "repo/package version [group] (arch)"
            if let Some(space_pos) = line.find(' ') {
                let name_part = &line[..space_pos];
                let rest = &line[space_pos + 1..];
                
                // Extract repository and package name
                let (repository, name) = if let Some(slash_pos) = name_part.find('/') {
                    (Some(name_part[..slash_pos].to_string()), &name_part[slash_pos + 1..])
                } else {
                    (None, name_part)
                };
                
                // Extract version
                let version = rest.split_whitespace().next().map(|s| s.to_string());
                
                // Check for description on next line
                let summary = if i + 1 < lines.len() && lines[i + 1].trim().starts_with(' ') {
                    Some(lines[i + 1].trim().to_string())
                } else {
                    None
                };
                
                let mut search_result = SearchResult {
                    name: name.to_string(),
                    version,
                    installed: false,
                    summary: summary.clone(),
                    description: None,
                    repository,
                    homepage: None,
                    score: 1.0,
                };

                if config.include_installed {
                    if let Ok(query_output) = self.run_command("pacman", &["-Qi", name], config.env.as_ref()).await {
                        search_result.installed = query_output.status.success();
                    }
                }

                results.push(search_result);
                
                // Skip description line if we processed it
                if summary.is_some() {
                    i += 2;
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }

        Ok(results)
    }

    async fn search_apk(&self, query: &str, config: &SearchConfig) -> Result<Vec<SearchResult>, PkgError> {
        let mut cmd_args = vec!["search", "-v", query];
        if let Some(extra_args) = &config.extra_args {
            cmd_args.extend(extra_args.iter().map(|s| s.as_str()));
        }

        let output = self.run_command("apk", &cmd_args, config.env.as_ref()).await
            .map_err(|e| PkgError::SearchFailed(format!("APK search command failed: {}", e)))?;

        if !output.status.success() {
            return Err(PkgError::SearchFailed(format!("APK search failed: {}", output.stderr)));
        }

        let mut results = Vec::new();
        
        for line in output.stdout.lines() {
            if line.trim().is_empty() {
                continue;
            }
            
            // Parse APK search output: "package-name-version - description"
            if let Some(dash_pos) = line.find(" - ") {
                let name_version = line[..dash_pos].trim();
                let summary = line[dash_pos + 3..].trim();
                
                // Extract package name (remove version)
                let name = if let Some(version_start) = name_version.rfind('-') {
                    let potential_name = &name_version[..version_start];
                    // Check if this looks like a version number
                    if name_version[version_start + 1..].chars().next().map_or(false, |c| c.is_ascii_digit()) {
                        potential_name
                    } else {
                        name_version
                    }
                } else {
                    name_version
                };
                
                let mut search_result = SearchResult {
                    name: name.to_string(),
                    version: None,
                    installed: false,
                    summary: Some(summary.to_string()),
                    description: None,
                    repository: None,
                    homepage: None,
                    score: 1.0,
                };

                if config.include_versions || config.include_installed {
                    if let Ok(info_output) = self.run_command("apk", &["info", "-a", name], config.env.as_ref()).await {
                        if info_output.status.success() {
                            for info_line in info_output.stdout.lines() {
                                if info_line.starts_with(&format!("{}-", name)) && config.include_versions {
                                    if let Some(version_part) = info_line.strip_prefix(&format!("{}-", name)) {
                                        search_result.version = Some(version_part.split_whitespace().next().unwrap_or(version_part).to_string());
                                    }
                                }
                                if info_line.starts_with("webpage:") {
                                    search_result.homepage = Some(info_line[8..].trim().to_string());
                                }
                            }
                        }
                    }
                }

                if config.include_installed {
                    if let Ok(installed_output) = self.run_command("apk", &["info", "-e", name], config.env.as_ref()).await {
                        search_result.installed = installed_output.status.success() && !installed_output.stdout.is_empty();
                    }
                }

                results.push(search_result);
            }
        }

        Ok(results)
    }

    async fn search_brew(&self, query: &str, config: &SearchConfig) -> Result<Vec<SearchResult>, PkgError> {
        let mut cmd_args = vec!["search", query];
        if let Some(extra_args) = &config.extra_args {
            cmd_args.extend(extra_args.iter().map(|s| s.as_str()));
        }

        let output = self.run_command("brew", &cmd_args, config.env.as_ref()).await
            .map_err(|e| PkgError::SearchFailed(format!("Brew search command failed: {}", e)))?;

        if !output.status.success() {
            return Err(PkgError::SearchFailed(format!("Brew search failed: {}", output.stderr)));
        }

        let mut results = Vec::new();
        
        for line in output.stdout.lines() {
            let name = line.trim();
            if name.is_empty() || name.starts_with("==>") {
                continue;
            }
            
            let mut search_result = SearchResult {
                name: name.to_string(),
                version: None,
                installed: false,
                summary: None,
                description: None,
                repository: None,
                homepage: None,
                score: 1.0,
            };

            // Get detailed information if requested
            if config.include_versions || config.include_installed || config.include_repo {
                if let Ok(info_output) = self.run_command("brew", &["info", "--json=v2", name], config.env.as_ref()).await {
                    if info_output.status.success() {
                        if let Ok(json_value) = serde_json::from_str::<Value>(&info_output.stdout) {
                            if let Some(formulae) = json_value.get("formulae").and_then(|f| f.as_array()) {
                                if let Some(formula) = formulae.first() {
                                    if config.include_versions {
                                        if let Some(versions) = formula.get("versions").and_then(|v| v.get("stable")) {
                                            if let Some(version_str) = versions.as_str() {
                                                search_result.version = Some(version_str.to_string());
                                            }
                                        }
                                    }
                                    
                                    if config.include_installed {
                                        if let Some(installed) = formula.get("installed").and_then(|i| i.as_array()) {
                                            search_result.installed = !installed.is_empty();
                                        }
                                    }
                                    
                                    if let Some(desc) = formula.get("desc").and_then(|d| d.as_str()) {
                                        search_result.summary = Some(desc.to_string());
                                    }
                                    
                                    if let Some(homepage) = formula.get("homepage").and_then(|h| h.as_str()) {
                                        search_result.homepage = Some(homepage.to_string());
                                    }
                                    
                                    if config.include_repo {
                                        if let Some(tap) = formula.get("tap").and_then(|t| t.as_str()) {
                                            search_result.repository = Some(tap.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            results.push(search_result);
        }

        Ok(results)
    }

    fn filter_and_sort_results(&self, mut results: Vec<SearchResult>, config: &SearchConfig) -> Vec<SearchResult> {
        let query_lower = config.query.to_lowercase();
        
        // Apply search_in filters
        results.retain(|result| {
            if config.search_in.contains(&SearchField::All) {
                return true;
            }
            
            let mut matches = false;
            
            if config.search_in.contains(&SearchField::Name) {
                if config.case_sensitive {
                    matches = if config.exact {
                        result.name == config.query
                    } else {
                        result.name.contains(&config.query)
                    };
                } else {
                    let name_lower = result.name.to_lowercase();
                    matches = if config.exact {
                        name_lower == query_lower
                    } else {
                        name_lower.contains(&query_lower)
                    };
                }
            }
            
            if !matches && config.search_in.contains(&SearchField::Description) {
                if let Some(ref summary) = result.summary {
                    if config.case_sensitive {
                        matches = summary.contains(&config.query);
                    } else {
                        let summary_lower = summary.to_lowercase();
                        matches = summary_lower.contains(&query_lower);
                    }
                }
                
                if !matches {
                    if let Some(ref description) = result.description {
                        if config.case_sensitive {
                            matches = description.contains(&config.query);
                        } else {
                            let description_lower = description.to_lowercase();
                            matches = description_lower.contains(&query_lower);
                        }
                    }
                }
            }
            
            matches
        });
        
        // Calculate scores and sort
        for result in &mut results {
            result.score = self.calculate_search_score(result, &config.query, config.case_sensitive);
        }
        
        // Sort by score (descending), then by name (ascending)
        results.sort_by(|a, b| {
            b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.name.cmp(&b.name))
        });
        
        results
    }
    
    fn calculate_search_score(&self, result: &SearchResult, query: &str, case_sensitive: bool) -> f64 {
        let query_to_use = if case_sensitive { query.to_string() } else { query.to_lowercase() };
        let name_to_use = if case_sensitive { result.name.clone() } else { result.name.to_lowercase() };
        
        // Exact name match gets highest score
        if name_to_use == query_to_use {
            return 1.0;
        }
        
        // Name starts with query gets high score
        if name_to_use.starts_with(&query_to_use) {
            return 0.9;
        }
        
        // Name contains query gets medium score
        if name_to_use.contains(&query_to_use) {
            return 0.7;
        }
        
        // Description/summary matches get lower score
        if let Some(ref summary) = result.summary {
            let summary_to_use = if case_sensitive { summary.clone() } else { summary.to_lowercase() };
            if summary_to_use.contains(&query_to_use) {
                return 0.5;
            }
        }
        
        if let Some(ref description) = result.description {
            let description_to_use = if case_sensitive { description.clone() } else { description.to_lowercase() };
            if description_to_use.contains(&query_to_use) {
                return 0.3;
            }
        }
        
        // Default score
        0.1
    }

    // Helper methods for parsing manager-specific output

    fn parse_apt_dependencies(&self, depends_line: &str) -> Vec<String> {
        let deps_str = if depends_line.starts_with("Depends: ") {
            &depends_line[9..]
        } else {
            depends_line
        };
        
        deps_str.split(',')
            .map(|dep| {
                // Remove version constraints like ">= 1.2.3" and alternatives
                let clean_dep = dep.trim().split_whitespace().next().unwrap_or(dep.trim());
                // Remove alternatives separated by |
                clean_dep.split('|').next().unwrap_or(clean_dep).trim().to_string()
            })
            .filter(|dep| !dep.is_empty())
            .collect()
    }

    fn parse_apt_depends_output(&self, output: &str) -> PackageDependencies {
        let mut runtime_deps = Vec::new();
        
        for line in output.lines() {
            if line.trim().starts_with("Depends: ") {
                let dep = line.trim()[9..].trim();
                if !dep.is_empty() {
                    runtime_deps.push(dep.to_string());
                }
            }
        }
        
        PackageDependencies {
            runtime: runtime_deps,
            build: Vec::new(),
            optional: Vec::new(),
        }
    }

    fn parse_apt_rdepends_output(&self, output: &str) -> Vec<String> {
        output.lines()
            .skip(1) // Skip header line
            .filter(|line| !line.trim().is_empty() && !line.starts_with("Reverse Depends:"))
            .map(|line| line.trim().to_string())
            .collect()
    }

    fn parse_pacman_dependencies(&self, deps_line: &str) -> Vec<String> {
        if deps_line == "None" {
            return Vec::new();
        }
        
        deps_line.split_whitespace()
            .map(|dep| {
                // Remove version constraints
                let mut name = dep;
                if let Some((pkg_name, _)) = name.split_once('=') {
                    name = pkg_name;
                }
                if let Some((pkg_name, _)) = name.split_once('>') {
                    name = pkg_name;
                }
                if let Some((pkg_name, _)) = name.split_once('<') {
                    name = pkg_name;
                }
                name.trim().to_string()
            })
            .filter(|dep| !dep.is_empty())
            .collect()
    }

    async fn run_command(&self, cmd: &str, args: &[&str], env: Option<&HashMap<String, String>>) -> Result<CommandOutput, PkgError> {
        let mut command = AsyncCommand::new(cmd);
        command.args(args);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        if let Some(env_vars) = env {
            for (key, value) in env_vars {
                command.env(key, value);
            }
        }

        let output = command.output().await
            .map_err(|e| PkgError::InfoQueryFailed(format!("Failed to run {}: {}", cmd, e)))?;

        Ok(CommandOutput {
            status: output.status,
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    // List installed packages implementation
    async fn list_installed_async(&self, config: ListInstalledConfig) -> Result<Value, PkgError> {
        // Validate configuration
        self.validate_list_installed_config(&config)?;
        
        // Resolve manager
        let manager = self.resolve_manager(&config.manager).await?;
        
        // Perform list installed operation with timeout
        let result = timeout(
            Duration::from_millis(config.timeout_ms),
            self.perform_list_installed(&config, &manager)
        ).await
        .map_err(|_| PkgError::ListInstalledTimeout)?;
        
        result
    }

    fn validate_list_installed_config(&self, config: &ListInstalledConfig) -> Result<(), PkgError> {
        if config.timeout_ms == 0 {
            return Err(PkgError::InvalidListInstalledConfig("timeout_ms must be greater than 0".to_string()));
        }

        if config.limit == 0 {
            return Err(PkgError::InvalidListInstalledConfig("limit must be greater than 0".to_string()));
        }

        // Validate extra_args if present
        if let Some(extra_args) = &config.extra_args {
            for arg in extra_args {
                if arg.trim().is_empty() {
                    return Err(PkgError::InvalidListInstalledConfig("extra_args cannot contain empty strings".to_string()));
                }
            }
        }

        Ok(())
    }

    async fn perform_list_installed(&self, config: &ListInstalledConfig, manager: &ManagerKind) -> Result<Value, PkgError> {
        // Get installed packages based on manager
        let mut packages = match manager {
            ManagerKind::Auto => unreachable!("Auto should be resolved"),
            ManagerKind::Apt => self.list_installed_apt(config).await?,
            ManagerKind::Dnf => self.list_installed_dnf(config).await?,
            ManagerKind::Yum => self.list_installed_yum(config).await?,
            ManagerKind::Pacman => self.list_installed_pacman(config).await?,
            ManagerKind::Apk => self.list_installed_apk(config).await?,
            ManagerKind::Brew => self.list_installed_brew(config).await?,
        };

        // Apply filtering
        self.filter_installed_packages(&mut packages, config);

        // Sort by name
        packages.sort_by(|a, b| a.name.cmp(&b.name));

        // Get total count after filtering but before pagination
        let total_installed = packages.len() as u32;

        // Apply pagination
        let start_idx = config.offset as usize;
        let end_idx = std::cmp::min(start_idx + config.limit as usize, packages.len());
        let paginated_packages = if start_idx < packages.len() {
            packages[start_idx..end_idx].to_vec()
        } else {
            vec![]
        };

        // Build result
        let results = ListInstalledResults {
            backend: "pkg".to_string(),
            manager: format!("{:?}", manager).to_lowercase(),
            alias: self.alias.clone(),
            limit: config.limit,
            offset: config.offset,
            total_installed,
            results: paginated_packages,
        };

        Ok(serde_json::to_value(results)
            .map_err(|e| PkgError::ListInstalledFailed(format!("Failed to serialize results: {}", e)))?)
    }

    fn filter_installed_packages(&self, packages: &mut Vec<InstalledPackage>, config: &ListInstalledConfig) {
        packages.retain(|pkg| {
            // Apply prefix filter if specified
            if let Some(prefix) = &config.prefix {
                if !pkg.name.to_lowercase().starts_with(&prefix.to_lowercase()) {
                    return false;
                }
            }

            // Apply name filter if specified  
            if let Some(filter) = &config.filter {
                if !pkg.name.to_lowercase().contains(&filter.to_lowercase()) {
                    return false;
                }
            }

            true
        });
    }

    async fn list_installed_apt(&self, config: &ListInstalledConfig) -> Result<Vec<InstalledPackage>, PkgError> {
        // Use dpkg-query to get installed packages
        let mut cmd = AsyncCommand::new("dpkg-query");
        cmd.arg("-W")
           .arg("-f")
           .arg("${Package}\\t${Version}\\t${Architecture}\\n");

        // Add environment variables if specified
        if let Some(ref env) = config.env {
            for (key, value) in env {
                cmd.env(key, value);
            }
        }

        let output = cmd.output().await
            .map_err(|e| PkgError::ListInstalledFailed(format!("dpkg-query command failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::ListInstalledFailed(format!("dpkg-query failed: {}", stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 3 {
                let mut package = InstalledPackage {
                    name: parts[0].to_string(),
                    version: parts[1].to_string(),
                    architecture: Some(parts[2].to_string()),
                    repository: None,
                    installed_size_bytes: None,
                    install_reason: None,
                    manager_specific: None,
                };

                // Get repository info if requested
                if config.include_repo {
                    if let Ok(repo) = self.get_apt_package_repo(&package.name).await {
                        package.repository = repo;
                    }
                }

                // Get size info if requested
                if config.include_size {
                    if let Ok(size) = self.get_apt_package_size(&package.name).await {
                        package.installed_size_bytes = size;
                    }
                }

                // Get install reason if requested
                if config.include_install_reason {
                    if let Ok(reason) = self.get_apt_install_reason(&package.name).await {
                        package.install_reason = reason;
                    }
                }

                packages.push(package);
            }
        }

        Ok(packages)
    }

    async fn get_apt_package_repo(&self, package_name: &str) -> Result<Option<String>, PkgError> {
        let mut cmd = AsyncCommand::new("apt-cache");
        cmd.arg("policy").arg(package_name);

        let output = cmd.output().await
            .map_err(|e| PkgError::ListInstalledFailed(format!("apt-cache policy failed: {}", e)))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.trim().starts_with("***") {
                    // Look for the origin line
                    if let Some(origin_line) = stdout.lines().find(|l| l.trim().starts_with("o=")) {
                        return Ok(Some(origin_line.trim().to_string()));
                    }
                }
            }
        }
        Ok(None)
    }

    async fn get_apt_package_size(&self, package_name: &str) -> Result<Option<u64>, PkgError> {
        let mut cmd = AsyncCommand::new("dpkg-query");
        cmd.arg("-W")
           .arg("-f")
           .arg("${Installed-Size}")
           .arg(package_name);

        let output = cmd.output().await
            .map_err(|e| PkgError::ListInstalledFailed(format!("dpkg-query size failed: {}", e)))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(size_kb) = stdout.trim().parse::<u64>() {
                return Ok(Some(size_kb * 1024)); // Convert from KB to bytes
            }
        }
        Ok(None)
    }

    async fn get_apt_install_reason(&self, package_name: &str) -> Result<Option<String>, PkgError> {
        let mut cmd = AsyncCommand::new("apt-mark");
        cmd.arg("showmanual");

        let output = cmd.output().await
            .map_err(|e| PkgError::ListInstalledFailed(format!("apt-mark showmanual failed: {}", e)))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.lines().any(|line| line.trim() == package_name) {
                return Ok(Some("manual".to_string()));
            } else {
                return Ok(Some("dependency".to_string()));
            }
        }
        Ok(None)
    }

    async fn list_installed_dnf(&self, config: &ListInstalledConfig) -> Result<Vec<InstalledPackage>, PkgError> {
        self.list_installed_rpm_based("dnf", config).await
    }

    async fn list_installed_yum(&self, config: &ListInstalledConfig) -> Result<Vec<InstalledPackage>, PkgError> {
        self.list_installed_rpm_based("yum", config).await
    }

    async fn list_installed_rpm_based(&self, manager_cmd: &str, config: &ListInstalledConfig) -> Result<Vec<InstalledPackage>, PkgError> {
        // Use rpm to get installed packages
        let mut cmd = AsyncCommand::new("rpm");
        cmd.arg("-qa")
           .arg("--qf")
           .arg("%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n");

        // Add environment variables if specified
        if let Some(ref env) = config.env {
            for (key, value) in env {
                cmd.env(key, value);
            }
        }

        let output = cmd.output().await
            .map_err(|e| PkgError::ListInstalledFailed(format!("rpm command failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::ListInstalledFailed(format!("rpm failed: {}", stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 3 {
                let mut package = InstalledPackage {
                    name: parts[0].to_string(),
                    version: parts[1].to_string(),
                    architecture: Some(parts[2].to_string()),
                    repository: None,
                    installed_size_bytes: None,
                    install_reason: None,
                    manager_specific: None,
                };

                // Get repository info if requested
                if config.include_repo {
                    if let Ok(repo) = self.get_rpm_package_repo(&package.name, manager_cmd).await {
                        package.repository = repo;
                    }
                }

                // Get size info if requested
                if config.include_size {
                    if let Ok(size) = self.get_rpm_package_size(&package.name).await {
                        package.installed_size_bytes = size;
                    }
                }

                // Get install reason if requested (DNF only)
                if config.include_install_reason && manager_cmd == "dnf" {
                    if let Ok(reason) = self.get_dnf_install_reason(&package.name).await {
                        package.install_reason = reason;
                    }
                }

                packages.push(package);
            }
        }

        Ok(packages)
    }

    async fn get_rpm_package_repo(&self, package_name: &str, manager_cmd: &str) -> Result<Option<String>, PkgError> {
        let mut cmd = AsyncCommand::new(manager_cmd);
        cmd.arg("repoquery")
           .arg("--installed")
           .arg("--qf")
           .arg("%{repoid}")
           .arg(package_name);

        let output = cmd.output().await
            .map_err(|e| PkgError::ListInstalledFailed(format!("{} repoquery failed: {}", manager_cmd, e)))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let repo = stdout.trim();
            if !repo.is_empty() {
                return Ok(Some(repo.to_string()));
            }
        }
        Ok(None)
    }

    async fn get_rpm_package_size(&self, package_name: &str) -> Result<Option<u64>, PkgError> {
        let mut cmd = AsyncCommand::new("rpm");
        cmd.arg("-qi").arg(package_name);

        let output = cmd.output().await
            .map_err(|e| PkgError::ListInstalledFailed(format!("rpm -qi failed: {}", e)))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.starts_with("Size") {
                    if let Some(size_str) = line.split(':').nth(1) {
                        if let Ok(size) = size_str.trim().parse::<u64>() {
                            return Ok(Some(size));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    async fn get_dnf_install_reason(&self, package_name: &str) -> Result<Option<String>, PkgError> {
        let mut cmd = AsyncCommand::new("dnf");
        cmd.arg("repoquery")
           .arg("--installed")
           .arg("--qf")
           .arg("%{installreason}")
           .arg(package_name);

        let output = cmd.output().await
            .map_err(|e| PkgError::ListInstalledFailed(format!("dnf repoquery installreason failed: {}", e)))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let reason = stdout.trim();
            match reason {
                "user" => Ok(Some("manual".to_string())),
                "dep" => Ok(Some("dependency".to_string())),
                _ if !reason.is_empty() => Ok(Some(reason.to_string())),
                _ => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    async fn list_installed_pacman(&self, config: &ListInstalledConfig) -> Result<Vec<InstalledPackage>, PkgError> {
        // Use pacman -Q to get installed packages
        let mut cmd = AsyncCommand::new("pacman");
        cmd.arg("-Q");

        // Add environment variables if specified
        if let Some(ref env) = config.env {
            for (key, value) in env {
                cmd.env(key, value);
            }
        }

        let output = cmd.output().await
            .map_err(|e| PkgError::ListInstalledFailed(format!("pacman -Q failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::ListInstalledFailed(format!("pacman -Q failed: {}", stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let mut package = InstalledPackage {
                    name: parts[0].to_string(),
                    version: parts[1].to_string(),
                    architecture: None,
                    repository: None,
                    installed_size_bytes: None,
                    install_reason: None,
                    manager_specific: None,
                };

                // Get detailed info if requested
                if config.include_repo || config.include_size || config.include_install_reason {
                    if let Ok(info) = self.get_pacman_package_info(&package.name).await {
                        if config.include_repo {
                            package.repository = info.repository;
                        }
                        if config.include_size {
                            package.installed_size_bytes = info.installed_size_bytes;
                        }
                        if config.include_install_reason {
                            package.install_reason = info.install_reason;
                        }
                    }
                }

                packages.push(package);
            }
        }

        Ok(packages)
    }

    async fn get_pacman_package_info(&self, package_name: &str) -> Result<InstalledPackage, PkgError> {
        let mut cmd = AsyncCommand::new("pacman");
        cmd.arg("-Qi").arg(package_name);

        let output = cmd.output().await
            .map_err(|e| PkgError::ListInstalledFailed(format!("pacman -Qi failed: {}", e)))?;

        if !output.status.success() {
            return Err(PkgError::ListInstalledFailed(format!("pacman -Qi failed for {}", package_name)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut repository = None;
        let mut installed_size_bytes = None;
        let mut install_reason = None;

        for line in stdout.lines() {
            if line.starts_with("Repository") {
                if let Some(repo) = line.split(':').nth(1) {
                    repository = Some(repo.trim().to_string());
                }
            } else if line.starts_with("Installed Size") {
                if let Some(size_str) = line.split(':').nth(1) {
                    let size_str = size_str.trim();
                    // Parse sizes like "123.45 KiB", "1.23 MiB"
                    if let Some((num_str, unit)) = size_str.split_once(' ') {
                        if let Ok(size) = num_str.parse::<f64>() {
                            let bytes = match unit {
                                "KiB" => (size * 1024.0) as u64,
                                "MiB" => (size * 1024.0 * 1024.0) as u64,
                                "GiB" => (size * 1024.0 * 1024.0 * 1024.0) as u64,
                                "B" => size as u64,
                                _ => continue,
                            };
                            installed_size_bytes = Some(bytes);
                        }
                    }
                }
            } else if line.starts_with("Install Reason") {
                if let Some(reason_str) = line.split(':').nth(1) {
                    let reason = reason_str.trim();
                    install_reason = match reason {
                        "Explicitly installed" => Some("manual".to_string()),
                        "Installed as a dependency for another package" => Some("dependency".to_string()),
                        _ => Some(reason.to_string()),
                    };
                }
            }
        }

        Ok(InstalledPackage {
            name: package_name.to_string(),
            version: "".to_string(), // Will be filled by caller
            architecture: None,
            repository,
            installed_size_bytes,
            install_reason,
            manager_specific: None,
        })
    }

    async fn list_installed_apk(&self, config: &ListInstalledConfig) -> Result<Vec<InstalledPackage>, PkgError> {
        // Use apk info -v to get installed packages
        let mut cmd = AsyncCommand::new("apk");
        cmd.arg("info").arg("-v");

        // Add environment variables if specified
        if let Some(ref env) = config.env {
            for (key, value) in env {
                cmd.env(key, value);
            }
        }

        let output = cmd.output().await
            .map_err(|e| PkgError::ListInstalledFailed(format!("apk info -v failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::ListInstalledFailed(format!("apk info -v failed: {}", stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        for line in stdout.lines() {
            // Parse lines like "busybox-1.35.0-r17"
            if let Some((name, version)) = Self::parse_apk_package_line(line) {
                let mut package = InstalledPackage {
                    name: name.to_string(),
                    version: version.to_string(),
                    architecture: None,
                    repository: None,
                    installed_size_bytes: None,
                    install_reason: None,
                    manager_specific: None,
                };

                // Get size info if requested
                if config.include_size {
                    if let Ok(size) = self.get_apk_package_size(&package.name).await {
                        package.installed_size_bytes = size;
                    }
                }

                packages.push(package);
            }
        }

        Ok(packages)
    }

    fn parse_apk_package_line(line: &str) -> Option<(&str, &str)> {
        // Parse lines like "busybox-1.35.0-r17"
        let line = line.trim();
        if let Some(dash_pos) = line.rfind('-') {
            if let Some(second_dash_pos) = line[..dash_pos].rfind('-') {
                let name = &line[..second_dash_pos];
                let version = &line[second_dash_pos + 1..];
                return Some((name, version));
            } else {
                // Single dash, split at first dash after excluding initial chars
                if let Some(version_start) = line.find('-') {
                    if version_start > 0 {
                        let name = &line[..version_start];
                        let version = &line[version_start + 1..];
                        return Some((name, version));
                    }
                }
            }
        }
        None
    }

    async fn get_apk_package_size(&self, package_name: &str) -> Result<Option<u64>, PkgError> {
        let mut cmd = AsyncCommand::new("apk");
        cmd.arg("info").arg("-s").arg(package_name);

        let output = cmd.output().await
            .map_err(|e| PkgError::ListInstalledFailed(format!("apk info -s failed: {}", e)))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.starts_with("installed size:") {
                    if let Some(size_str) = line.split(':').nth(1) {
                        let size_str = size_str.trim();
                        // Parse size (usually in bytes)
                        if let Ok(size) = size_str.parse::<u64>() {
                            return Ok(Some(size));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    async fn list_installed_brew(&self, config: &ListInstalledConfig) -> Result<Vec<InstalledPackage>, PkgError> {
        // Try to use JSON format first
        let json_output = self.get_brew_json_installed().await;
        
        match json_output {
            Ok(packages) => Ok(packages),
            Err(_) => {
                // Fallback to text format
                self.get_brew_text_installed(config).await
            }
        }
    }

    async fn get_brew_json_installed(&self) -> Result<Vec<InstalledPackage>, PkgError> {
        let mut cmd = AsyncCommand::new("brew");
        cmd.arg("info").arg("--json=v2").arg("--installed");

        let output = cmd.output().await
            .map_err(|e| PkgError::ListInstalledFailed(format!("brew info --json failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::ListInstalledFailed(format!("brew info --json failed: {}", stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: Value = serde_json::from_str(&stdout)
            .map_err(|e| PkgError::ListInstalledFailed(format!("Failed to parse brew JSON: {}", e)))?;

        let mut packages = Vec::new();

        if let Some(formulae) = json["formulae"].as_array() {
            for formula in formulae {
                if let (Some(name), Some(installed)) = (
                    formula["name"].as_str(),
                    formula["installed"].as_array()
                ) {
                    if let Some(version_obj) = installed.first() {
                        let version = version_obj["version"].as_str().unwrap_or("unknown");
                        let tap = formula["tap"].as_str();
                        
                        let package = InstalledPackage {
                            name: name.to_string(),
                            version: version.to_string(),
                            architecture: None,
                            repository: tap.map(|t| t.to_string()),
                            installed_size_bytes: None,
                            install_reason: version_obj["installed_on_request"]
                                .as_bool()
                                .map(|on_request| if on_request { "manual" } else { "dependency" })
                                .map(|s| s.to_string()),
                            manager_specific: Some(formula.clone()),
                        };
                        packages.push(package);
                    }
                }
            }
        }

        Ok(packages)
    }

    async fn get_brew_text_installed(&self, config: &ListInstalledConfig) -> Result<Vec<InstalledPackage>, PkgError> {
        let mut cmd = AsyncCommand::new("brew");
        cmd.arg("list").arg("--versions");

        // Add environment variables if specified
        if let Some(ref env) = config.env {
            for (key, value) in env {
                cmd.env(key, value);
            }
        }

        let output = cmd.output().await
            .map_err(|e| PkgError::ListInstalledFailed(format!("brew list --versions failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::ListInstalledFailed(format!("brew list --versions failed: {}", stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let package = InstalledPackage {
                    name: parts[0].to_string(),
                    version: parts[1].to_string(), // Take first version if multiple
                    architecture: None,
                    repository: Some("homebrew/core".to_string()), // Default tap
                    installed_size_bytes: None,
                    install_reason: None,
                    manager_specific: None,
                };
                packages.push(package);
            }
        }

        Ok(packages)
    }

    // ===============================
    // SNAPSHOT IMPLEMENTATION
    // ===============================
    // Restore (apply_lock) operations
    // ===============================

    async fn restore_async(&self, config: RestoreConfig) -> Result<Value, PkgError> {
        // Validate configuration
        self.validate_restore_config(&config)?;
        
        // Parse and validate lockfile
        let lockfile = self.parse_lockfile(&config.lockfile, &config.format)?;
        
        // Validate lockfile against policies
        self.validate_lockfile(&lockfile, &config).await?;
        
        // Resolve manager (from config or lockfile)
        let manager = self.resolve_restore_manager(&config.manager, &lockfile)?;
        
        // Perform restore operation with timeout
        let result = timeout(
            Duration::from_millis(config.timeout_ms),
            self.perform_restore(&config, &lockfile, &manager)
        ).await
        .map_err(|_| PkgError::RestoreTimeout)?;
        
        result
    }

    fn validate_restore_config(&self, config: &RestoreConfig) -> Result<(), PkgError> {
        if config.timeout_ms == 0 {
            return Err(PkgError::InvalidRestoreConfig("timeout_ms must be greater than 0".to_string()));
        }

        if config.lockfile.trim().is_empty() {
            return Err(PkgError::InvalidRestoreConfig("lockfile content cannot be empty".to_string()));
        }

        if let Some(ref extra_args) = config.extra_args {
            if extra_args.iter().any(|arg| arg.trim().is_empty()) {
                return Err(PkgError::InvalidRestoreConfig("extra_args cannot contain empty strings".to_string()));
            }
        }

        if let Some(ref env) = config.env {
            if env.iter().any(|(k, v)| k.trim().is_empty() || v.trim().is_empty()) {
                return Err(PkgError::InvalidRestoreConfig("env keys and values cannot be empty".to_string()));
            }
        }

        Ok(())
    }

    // ===============================
    // Snapshot operations
    // ===============================

    async fn snapshot_async(&self, config: SnapshotConfig) -> Result<Value, PkgError> {
        // Validate configuration
        self.validate_snapshot_config(&config)?;
        
        // Resolve manager
        let manager = self.resolve_manager(&config.manager).await?;
        
        // Perform snapshot operation with timeout
        let result = timeout(
            Duration::from_millis(config.timeout_ms),
            self.perform_snapshot(&config, &manager)
        ).await
        .map_err(|_| PkgError::SnapshotTimeout)?;
        
        result
    }

    fn validate_snapshot_config(&self, config: &SnapshotConfig) -> Result<(), PkgError> {
        if config.timeout_ms == 0 {
            return Err(PkgError::InvalidSnapshotConfig("timeout_ms must be greater than 0".to_string()));
        }

        // Validate extra_args if present
        if let Some(extra_args) = &config.extra_args {
            if extra_args.iter().any(|arg| arg.is_empty()) {
                return Err(PkgError::InvalidSnapshotConfig("extra_args cannot contain empty strings".to_string()));
            }
        }

        // Validate env if present
        if let Some(env) = &config.env {
            for (key, value) in env {
                if key.is_empty() || value.is_empty() {
                    return Err(PkgError::InvalidSnapshotConfig("env keys and values cannot be empty".to_string()));
                }
            }
        }

        Ok(())
    }

    async fn perform_snapshot(&self, config: &SnapshotConfig, manager: &ManagerKind) -> Result<Value, PkgError> {
        // Collect OS metadata if requested
        let platform_info = if config.include_os_metadata {
            self.collect_platform_info().await
        } else {
            PlatformInfo {
                os_family: None,
                os_name: None,
                os_version: None,
                kernel: None,
                architecture: None,
            }
        };

        // Collect manager metadata
        let manager_info = self.collect_manager_info(manager).await?;

        // Get installed packages
        let mut packages = match manager {
            ManagerKind::Auto => unreachable!("Auto should be resolved"),
            ManagerKind::Apt => self.snapshot_apt(config).await?,
            ManagerKind::Dnf => self.snapshot_dnf(config).await?,
            ManagerKind::Yum => self.snapshot_yum(config).await?,
            ManagerKind::Pacman => self.snapshot_pacman(config).await?,
            ManagerKind::Apk => self.snapshot_apk(config).await?,
            ManagerKind::Brew => self.snapshot_brew(config).await?,
        };

        // Apply filtering based on scope
        self.filter_snapshot_packages(&mut packages, config)?;

        // Apply exclude patterns
        self.apply_exclude_patterns(&mut packages, &config.exclude_patterns);

        // Sort packages deterministically
        packages.sort_by(|a, b| {
            a.name.cmp(&b.name)
                .then_with(|| a.architecture.cmp(&b.architecture))
                .then_with(|| a.version.cmp(&b.version))
        });

        // Build lockfile
        let lockfile = Lockfile {
            lockfile_version: "pkg-lock/v1".to_string(),
            generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            manager: ManagerInfo {
                name: format!("{:?}", manager).to_lowercase(),
                alias: self.alias.clone(),
                version: manager_info.version,
                config: manager_info.config,
            },
            platform: platform_info,
            scope: format!("{:?}", config.scope).to_lowercase(),
            packages,
        };

        // Serialize lockfile in the requested format
        let lockfile_content = match config.format {
            SnapshotFormat::Json => serde_json::to_string_pretty(&lockfile)
                .map_err(|e| PkgError::SnapshotFailed(format!("JSON serialization failed: {}", e)))?,
            SnapshotFormat::Yaml => self.serialize_lockfile_yaml(&lockfile)?,
            SnapshotFormat::Text => self.serialize_lockfile_text(&lockfile)?,
        };

        // Build response
        let response = json!({
            "backend": "pkg",
            "action": "snapshot",
            "manager": format!("{:?}", manager).to_lowercase(),
            "alias": self.alias,
            "format": format!("{:?}", config.format).to_lowercase(),
            "lockfile": lockfile_content,
            "parsed": {
                "lockfile_version": lockfile.lockfile_version,
                "manager": {
                    "name": lockfile.manager.name,
                    "version": lockfile.manager.version,
                    "alias": lockfile.manager.alias
                },
                "platform": lockfile.platform,
                "scope": lockfile.scope,
                "packages_count": lockfile.packages.len()
            }
        });

        Ok(response)
    }

    async fn collect_platform_info(&self) -> PlatformInfo {
        let mut platform_info = PlatformInfo {
            os_family: None,
            os_name: None,
            os_version: None,
            kernel: None,
            architecture: None,
        };

        // Get OS info - try different methods
        if let Ok(output) = AsyncCommand::new("uname").args(&["-s", "-r", "-m"]).output().await {
            if output.status.success() {
                let info = String::from_utf8_lossy(&output.stdout);
                let parts: Vec<&str> = info.trim().split_whitespace().collect();
                if parts.len() >= 3 {
                    platform_info.kernel = Some(format!("{} {}", parts[0], parts[1]));
                    platform_info.architecture = Some(parts[2].to_string());
                }
            }
        }

        // Try to get distribution info
        if let Ok(output) = AsyncCommand::new("lsb_release").args(&["-i", "-r"]).output().await {
            if output.status.success() {
                let info = String::from_utf8_lossy(&output.stdout);
                for line in info.lines() {
                    if line.contains("Distributor ID:") {
                        platform_info.os_name = line.split(':').nth(1).map(|s| s.trim().to_string());
                    } else if line.contains("Release:") {
                        platform_info.os_version = line.split(':').nth(1).map(|s| s.trim().to_string());
                    }
                }
            }
        }

        // Fallback: try /etc/os-release
        if platform_info.os_name.is_none() {
            if let Ok(output) = tokio::fs::read_to_string("/etc/os-release").await {
                for line in output.lines() {
                    if let Some((key, value)) = line.split_once('=') {
                        let value = value.trim_matches('"');
                        match key {
                            "NAME" => platform_info.os_name = Some(value.to_string()),
                            "VERSION" => platform_info.os_version = Some(value.to_string()),
                            _ => {}
                        }
                    }
                }
            }
        }

        // Determine OS family based on available package managers or OS name
        platform_info.os_family = self.determine_os_family(&platform_info.os_name).await;

        platform_info
    }

    async fn determine_os_family(&self, os_name: &Option<String>) -> Option<String> {
        if let Some(name) = os_name {
            let name_lower = name.to_lowercase();
            if name_lower.contains("ubuntu") || name_lower.contains("debian") {
                return Some("debian".to_string());
            } else if name_lower.contains("fedora") || name_lower.contains("rhel") || name_lower.contains("centos") {
                return Some("rhel".to_string());
            } else if name_lower.contains("arch") {
                return Some("arch".to_string());
            } else if name_lower.contains("alpine") {
                return Some("alpine".to_string());
            } else if name_lower.contains("darwin") || name_lower.contains("macos") {
                return Some("darwin".to_string());
            }
        }
        None
    }

    async fn collect_manager_info(&self, manager: &ManagerKind) -> Result<ManagerInfo, PkgError> {
        let (binary, version_arg) = match manager {
            ManagerKind::Auto => unreachable!("Auto should be resolved"),
            ManagerKind::Apt => ("apt", "--version"),
            ManagerKind::Dnf => ("dnf", "--version"),
            ManagerKind::Yum => ("yum", "--version"),
            ManagerKind::Pacman => ("pacman", "-V"),
            ManagerKind::Apk => ("apk", "--version"),
            ManagerKind::Brew => ("brew", "--version"),
        };

        let version = if let Ok(output) = AsyncCommand::new(binary).arg(version_arg).output().await {
            if output.status.success() {
                let version_str = String::from_utf8_lossy(&output.stdout);
                version_str.lines().next().map(|s| s.trim().to_string())
            } else {
                None
            }
        } else {
            None
        };

        Ok(ManagerInfo {
            name: format!("{:?}", manager).to_lowercase(),
            alias: self.alias.clone(),
            version,
            config: None, // Could be extended to include repo config
        })
    }

    fn filter_snapshot_packages(&self, packages: &mut Vec<LockfilePackage>, config: &SnapshotConfig) -> Result<(), PkgError> {
        match config.scope {
            SnapshotScope::All => {
                // Keep all packages
            },
            SnapshotScope::Manual => {
                packages.retain(|pkg| {
                    pkg.install_reason.as_deref() == Some("manual")
                });
                // Note: If install_reason is not available, we could log a warning
                // but continue with all packages rather than error
            },
            SnapshotScope::Dependency => {
                packages.retain(|pkg| {
                    pkg.install_reason.as_deref() == Some("dependency")
                });
            }
        }
        Ok(())
    }

    fn apply_exclude_patterns(&self, packages: &mut Vec<LockfilePackage>, patterns: &[String]) {
        if patterns.is_empty() {
            return;
        }

        packages.retain(|pkg| {
            for pattern in patterns {
                // Simple glob pattern matching - for now, just support * at the end
                if pattern.ends_with('*') {
                    let prefix = &pattern[..pattern.len() - 1];
                    if pkg.name.starts_with(prefix) {
                        return false;
                    }
                } else if pattern.starts_with('*') {
                    let suffix = &pattern[1..];
                    if pkg.name.ends_with(suffix) {
                        return false;
                    }
                } else if pkg.name == *pattern {
                    return false;
                }
            }
            true
        });
    }

    fn serialize_lockfile_yaml(&self, lockfile: &Lockfile) -> Result<String, PkgError> {
        // For now, return JSON as YAML is similar
        // In a real implementation, you'd use serde_yaml
        serde_json::to_string_pretty(lockfile)
            .map_err(|e| PkgError::SnapshotFailed(format!("YAML serialization failed: {}", e)))
    }

    fn serialize_lockfile_text(&self, lockfile: &Lockfile) -> Result<String, PkgError> {
        let mut output = String::new();
        
        output.push_str(&format!("# {}\n", lockfile.lockfile_version));
        output.push_str(&format!("manager: {} ({})\n", 
            lockfile.manager.name, 
            lockfile.manager.version.as_deref().unwrap_or("unknown")));
        
        if let (Some(os_name), Some(os_version)) = (&lockfile.platform.os_name, &lockfile.platform.os_version) {
            output.push_str(&format!("os: {} {} ({})\n", 
                os_name, 
                os_version,
                lockfile.platform.architecture.as_deref().unwrap_or("unknown")));
        }
        
        output.push_str(&format!("scope: {}\n\n", lockfile.scope));
        
        for pkg in &lockfile.packages {
            let mut line = pkg.name.clone();
            if let Some(version) = &pkg.version {
                line.push_str(&format!("={}", version));
            }
            if let Some(arch) = &pkg.architecture {
                line.push_str(&format!(" [{}]", arch));
            }
            if let Some(repo) = &pkg.repository {
                line.push_str(&format!(" @{}", repo));
            }
            if let Some(reason) = &pkg.install_reason {
                line.push_str(&format!(" ({})", reason));
            }
            if pkg.pinned {
                line.push_str(" [pinned]");
            }
            output.push_str(&format!("{}\n", line));
        }
        
        Ok(output)
    }

    // Manager-specific snapshot implementations
    async fn snapshot_apt(&self, config: &SnapshotConfig) -> Result<Vec<LockfilePackage>, PkgError> {
        let mut packages = Vec::new();

        // Get installed packages using dpkg-query
        let output = AsyncCommand::new("dpkg-query")
            .args(&["-W", "-f", "${Package}\\t${Version}\\t${Architecture}\\n"])
            .output()
            .await
            .map_err(|e| PkgError::SnapshotFailed(format!("dpkg-query failed: {}", e)))?;

        if !output.status.success() {
            return Err(PkgError::SnapshotFailed("dpkg-query command failed".to_string()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // Get manual packages if needed
        let manual_packages = if config.include_install_reason {
            self.get_apt_manual_packages().await.unwrap_or_default()
        } else {
            std::collections::HashSet::new()
        };

        // Get held packages if needed
        let held_packages = self.get_apt_held_packages().await.unwrap_or_default();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 3 {
                let name = parts[0].to_string();
                let version = parts[1].to_string();
                let architecture = parts[2].to_string();

                let install_reason = if config.include_install_reason {
                    if manual_packages.contains(&name) {
                        Some("manual".to_string())
                    } else {
                        Some("dependency".to_string())
                    }
                } else {
                    None
                };

                let repository = if config.include_repo {
                    self.get_apt_package_repository(&name).await
                } else {
                    None
                };

                let package = LockfilePackage {
                    name,
                    version: match config.include_versions {
                        SnapshotVersionMode::Exact => Some(version),
                        SnapshotVersionMode::Minimal => Some(version), // Could be simplified
                        SnapshotVersionMode::None => None,
                    },
                    version_spec: None,
                    architecture: if config.include_arch { Some(architecture) } else { None },
                    repository,
                    install_reason,
                    pinned: held_packages.contains(parts[0]),
                };

                packages.push(package);
            }
        }

        Ok(packages)
    }

    async fn get_apt_manual_packages(&self) -> Result<std::collections::HashSet<String>, PkgError> {
        let output = AsyncCommand::new("apt-mark")
            .arg("showmanual")
            .output()
            .await
            .map_err(|e| PkgError::SnapshotFailed(format!("apt-mark showmanual failed: {}", e)))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(stdout.lines().map(|line| line.trim().to_string()).collect())
        } else {
            Ok(std::collections::HashSet::new())
        }
    }

    async fn get_apt_held_packages(&self) -> Result<std::collections::HashSet<String>, PkgError> {
        let output = AsyncCommand::new("apt-mark")
            .arg("showhold")
            .output()
            .await
            .map_err(|e| PkgError::SnapshotFailed(format!("apt-mark showhold failed: {}", e)))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(stdout.lines().map(|line| line.trim().to_string()).collect())
        } else {
            Ok(std::collections::HashSet::new())
        }
    }

    async fn get_apt_package_repository(&self, package_name: &str) -> Option<String> {
        if let Ok(output) = AsyncCommand::new("apt-cache")
            .args(&["policy", package_name])
            .output()
            .await
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // Parse the policy output to extract repository info
                for line in stdout.lines() {
                    if line.trim().starts_with("***") || line.trim().starts_with("500") {
                        // Look for the repository line
                        if let Some(repo_part) = line.split_whitespace().nth(2) {
                            return Some(repo_part.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    async fn snapshot_dnf(&self, config: &SnapshotConfig) -> Result<Vec<LockfilePackage>, PkgError> {
        let mut packages = Vec::new();

        // Get installed packages using rpm -qa with format string
        // Format: name|epoch:version-release|architecture
        let output = AsyncCommand::new("rpm")
            .args(&["-qa", "--queryformat", "%{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}|%{ARCH}\\n"])
            .output()
            .await
            .map_err(|e| PkgError::SnapshotFailed(format!("rpm query failed: {}", e)))?;

        if !output.status.success() {
            return Err(PkgError::SnapshotFailed("rpm query command failed".to_string()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Get user-installed packages if needed
        let user_packages = if config.include_install_reason {
            self.get_dnf_user_packages().await.unwrap_or_default()
        } else {
            std::collections::HashSet::new()
        };

        // Get versionlocked (pinned) packages if needed
        let locked_packages = self.get_dnf_locked_packages().await.unwrap_or_default();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 3 {
                let name = parts[0].to_string();
                let mut version_str = parts[1].to_string();
                let architecture = parts[2].to_string();

                // Clean up epoch from version (0: prefix)
                if version_str.starts_with("0:") {
                    version_str = version_str[2..].to_string();
                } else if version_str.starts_with("(none):") {
                    version_str = version_str[7..].to_string();
                }

                let install_reason = if config.include_install_reason {
                    if user_packages.contains(&name) {
                        Some("manual".to_string())
                    } else {
                        Some("dependency".to_string())
                    }
                } else {
                    None
                };

                let repository = if config.include_repo {
                    self.get_dnf_package_repository(&name).await
                } else {
                    None
                };

                let package = LockfilePackage {
                    name: name.clone(),
                    version: match config.include_versions {
                        SnapshotVersionMode::Exact => Some(version_str),
                        SnapshotVersionMode::Minimal => Some(version_str), // Could be simplified
                        SnapshotVersionMode::None => None,
                    },
                    version_spec: None,
                    architecture: if config.include_arch { Some(architecture) } else { None },
                    repository,
                    install_reason,
                    pinned: locked_packages.contains(&name),
                };

                packages.push(package);
            }
        }

        Ok(packages)
    }

    async fn get_dnf_user_packages(&self) -> Result<std::collections::HashSet<String>, PkgError> {
        // DNF/YUM marks packages as userinstalled in the yumdb
        // We can query this using dnf history userinstalled or repoquery
        let output = AsyncCommand::new("dnf")
            .args(&["history", "userinstalled"])
            .output()
            .await
            .map_err(|e| PkgError::SnapshotFailed(format!("dnf history userinstalled failed: {}", e)))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut packages = std::collections::HashSet::new();

            // Skip header lines and collect package names
            for line in stdout.lines().skip_while(|l| !l.is_empty()) {
                let line = line.trim();
                if line.is_empty() || line.starts_with("Packages") || line.contains("---") {
                    continue;
                }

                // Package name is typically the first field
                if let Some(pkg_name) = line.split_whitespace().next() {
                    packages.insert(pkg_name.to_string());
                }
            }
            Ok(packages)
        } else {
            // Fallback: if dnf history fails, treat all as user-installed
            Ok(std::collections::HashSet::new())
        }
    }

    async fn get_dnf_locked_packages(&self) -> Result<std::collections::HashSet<String>, PkgError> {
        // Check for versionlock plugin configuration
        let versionlock_file = "/etc/dnf/plugins/versionlock.list";

        if let Ok(content) = tokio::fs::read_to_string(versionlock_file).await {
            let mut packages = std::collections::HashSet::new();
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                // Versionlock format: "epoch:name-version-release.arch"
                // or just "name-*"
                // Extract package name
                if let Some(name_part) = line.split(':').last() {
                    if let Some(pkg_name) = name_part.split('-').next() {
                        packages.insert(pkg_name.to_string());
                    }
                }
            }
            Ok(packages)
        } else {
            Ok(std::collections::HashSet::new())
        }
    }

    async fn get_dnf_package_repository(&self, package_name: &str) -> Option<String> {
        // Use dnf repoquery to get repository information
        if let Ok(output) = AsyncCommand::new("dnf")
            .args(&["repoquery", "--installed", "--queryformat", "%{REPOID}", package_name])
            .output()
            .await
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let repo = stdout.trim();
                if !repo.is_empty() && repo != "(null)" {
                    return Some(repo.to_string());
                }
            }
        }
        None
    }

    async fn snapshot_yum(&self, config: &SnapshotConfig) -> Result<Vec<LockfilePackage>, PkgError> {
        let mut packages = Vec::new();

        // YUM uses RPM backend, so we use rpm -qa just like DNF
        // Format: name|epoch:version-release|architecture
        let output = AsyncCommand::new("rpm")
            .args(&["-qa", "--queryformat", "%{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}|%{ARCH}\\n"])
            .output()
            .await
            .map_err(|e| PkgError::SnapshotFailed(format!("rpm query failed: {}", e)))?;

        if !output.status.success() {
            return Err(PkgError::SnapshotFailed("rpm query command failed".to_string()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Get user-installed packages if needed
        let user_packages = if config.include_install_reason {
            self.get_yum_user_packages().await.unwrap_or_default()
        } else {
            std::collections::HashSet::new()
        };

        // Get versionlocked (pinned) packages if needed
        let locked_packages = self.get_yum_locked_packages().await.unwrap_or_default();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 3 {
                let name = parts[0].to_string();
                let mut version_str = parts[1].to_string();
                let architecture = parts[2].to_string();

                // Clean up epoch from version (0: prefix)
                if version_str.starts_with("0:") {
                    version_str = version_str[2..].to_string();
                } else if version_str.starts_with("(none):") {
                    version_str = version_str[7..].to_string();
                }

                let install_reason = if config.include_install_reason {
                    if user_packages.contains(&name) {
                        Some("manual".to_string())
                    } else {
                        Some("dependency".to_string())
                    }
                } else {
                    None
                };

                let repository = if config.include_repo {
                    self.get_yum_package_repository(&name).await
                } else {
                    None
                };

                let package = LockfilePackage {
                    name: name.clone(),
                    version: match config.include_versions {
                        SnapshotVersionMode::Exact => Some(version_str),
                        SnapshotVersionMode::Minimal => Some(version_str), // Could be simplified
                        SnapshotVersionMode::None => None,
                    },
                    version_spec: None,
                    architecture: if config.include_arch { Some(architecture) } else { None },
                    repository,
                    install_reason,
                    pinned: locked_packages.contains(&name),
                };

                packages.push(package);
            }
        }

        Ok(packages)
    }

    async fn get_yum_user_packages(&self) -> Result<std::collections::HashSet<String>, PkgError> {
        // YUM doesn't have a direct "userinstalled" command like DNF
        // We can use yumdb to query the reason field
        // For packages installed by user, reason is typically "user" or "group"

        // Try using yumdb if available
        let output = AsyncCommand::new("yumdb")
            .args(&["search", "reason", "user"])
            .output()
            .await;

        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut packages = std::collections::HashSet::new();

                // Parse yumdb output - each package name appears in the output
                for line in stdout.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.contains("reason =") {
                        // Extract package name from various yumdb output formats
                        if let Some(pkg_name) = line.split_whitespace().next() {
                            // Remove any version info if present
                            let clean_name = pkg_name.split('-').next().unwrap_or(pkg_name);
                            if !clean_name.is_empty() && !clean_name.starts_with('#') {
                                packages.insert(clean_name.to_string());
                            }
                        }
                    }
                }

                return Ok(packages);
            }
        }

        // Fallback: try reading yumdb files directly
        // YUM stores package metadata in /var/lib/yum/yumdb/
        if let Ok(entries) = tokio::fs::read_dir("/var/lib/yum/yumdb").await {
            let mut packages = std::collections::HashSet::new();
            // This is a simplified approach - full implementation would recursively search
            // For now, return empty set if yumdb command fails
            return Ok(packages);
        }

        // If all fails, return empty set (all packages will be marked as dependencies)
        Ok(std::collections::HashSet::new())
    }

    async fn get_yum_locked_packages(&self) -> Result<std::collections::HashSet<String>, PkgError> {
        // YUM uses versionlock plugin similar to DNF
        // Check for versionlock configuration
        let versionlock_file = "/etc/yum/pluginconf.d/versionlock.list";

        if let Ok(content) = tokio::fs::read_to_string(versionlock_file).await {
            let mut packages = std::collections::HashSet::new();
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                // Versionlock format: "epoch:name-version-release.arch"
                // or just "name-*"
                // Extract package name
                if let Some(name_part) = line.split(':').last() {
                    if let Some(pkg_name) = name_part.split('-').next() {
                        packages.insert(pkg_name.to_string());
                    }
                }
            }
            Ok(packages)
        } else {
            Ok(std::collections::HashSet::new())
        }
    }

    async fn get_yum_package_repository(&self, package_name: &str) -> Option<String> {
        // Use yum to get repository information
        // YUM's repoquery command can show from which repo a package was installed
        if let Ok(output) = AsyncCommand::new("yum")
            .args(&["info", "installed", package_name])
            .output()
            .await
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);

                // Parse yum info output to find "From repo" line
                for line in stdout.lines() {
                    if line.starts_with("From repo") || line.starts_with("Repo") {
                        if let Some(repo) = line.split(':').nth(1) {
                            let repo_name = repo.trim();
                            if !repo_name.is_empty() && repo_name != "installed" {
                                return Some(repo_name.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Fallback: try repoquery if available (part of yum-utils)
        if let Ok(output) = AsyncCommand::new("repoquery")
            .args(&["--installed", "--queryformat", "%{REPOID}", package_name])
            .output()
            .await
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let repo = stdout.trim();
                if !repo.is_empty() && repo != "(null)" && repo != "installed" {
                    return Some(repo.to_string());
                }
            }
        }

        None
    }

    pub async fn snapshot_pacman(&self, config: &SnapshotConfig) -> Result<Vec<LockfilePackage>, PkgError> {
        // Pacman snapshot implementation for Arch Linux
        // Uses: pacman -Q (list packages), pacman -Qe (explicit packages), pacman -Qi (package info)

        // Get list of all installed packages
        let mut cmd = tokio::process::Command::new("pacman");
        cmd.arg("-Q");

        if config.include_versions == SnapshotVersionMode::None {
            cmd.arg("-q"); // Quiet mode, names only
        }

        // Apply timeout
        let output = tokio::time::timeout(
            tokio::time::Duration::from_millis(config.timeout_ms as u64),
            cmd.output()
        )
        .await
        .map_err(|_| PkgError::SnapshotTimeout)?
        .map_err(|e| PkgError::SnapshotFailed(format!("Failed to execute pacman: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::SnapshotFailed(format!("pacman -Q failed: {}", stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        // Get user-installed (explicit) packages
        let user_packages = if config.include_install_reason {
            self.get_pacman_explicit_packages().await.unwrap_or_default()
        } else {
            HashSet::new()
        };

        // Get pinned packages (HoldPkg from pacman.conf)
        let locked_packages = self.get_pacman_held_packages().await.unwrap_or_default();

        // Parse package list
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let (name, version) = if config.include_versions != SnapshotVersionMode::None {
                // Format: "package-name version"
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    (parts[0].to_string(), Some(parts[1].to_string()))
                } else {
                    continue;
                }
            } else {
                // Quiet mode: just package name
                (line.to_string(), None)
            };

            // Check exclude patterns
            if config.exclude_patterns.iter().any(|pattern| {
                if pattern.contains('*') {
                    // Simple wildcard matching
                    let pattern_regex = pattern.replace("*", ".*");
                    regex::Regex::new(&format!("^{}$", pattern_regex))
                        .map(|re| re.is_match(&name))
                        .unwrap_or(false)
                } else {
                    &name == pattern
                }
            }) {
                continue;
            }

            // Get repository information if needed
            let repository = if config.include_repo {
                self.get_pacman_package_repository(&name).await
            } else {
                None
            };

            // Get architecture if needed
            let architecture = if config.include_arch {
                self.get_pacman_package_architecture(&name).await
            } else {
                None
            };

            // Determine install reason
            let install_reason = if config.include_install_reason {
                if user_packages.contains(&name) {
                    Some("explicit".to_string())
                } else {
                    Some("dependency".to_string())
                }
            } else {
                None
            };

            // Check if package is pinned
            let pinned = locked_packages.contains(&name);

            packages.push(LockfilePackage {
                name,
                version,
                version_spec: None,
                architecture,
                repository,
                install_reason,
                pinned,
            });
        }

        Ok(packages)
    }

    pub async fn get_pacman_explicit_packages(&self) -> Result<HashSet<String>, PkgError> {
        // Get explicitly installed packages using pacman -Qe
        let output = tokio::process::Command::new("pacman")
            .args(&["-Qe", "-q"])
            .output()
            .await
            .map_err(|e| PkgError::SnapshotFailed(format!("Failed to execute pacman -Qe: {}", e)))?;

        if !output.status.success() {
            return Ok(HashSet::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = HashSet::new();

        for line in stdout.lines() {
            let line = line.trim();
            if !line.is_empty() {
                packages.insert(line.to_string());
            }
        }

        Ok(packages)
    }

    pub async fn get_pacman_held_packages(&self) -> Result<HashSet<String>, PkgError> {
        // Read HoldPkg entries from /etc/pacman.conf
        let config_path = "/etc/pacman.conf";
        let content = tokio::fs::read_to_string(config_path)
            .await
            .unwrap_or_default();

        let mut held_packages = HashSet::new();

        for line in content.lines() {
            let line = line.trim();

            // Look for HoldPkg directive
            if line.starts_with("HoldPkg") {
                if let Some(packages_part) = line.split('=').nth(1) {
                    for pkg in packages_part.split_whitespace() {
                        held_packages.insert(pkg.trim().to_string());
                    }
                }
            }
        }

        Ok(held_packages)
    }

    pub async fn get_pacman_package_repository(&self, package_name: &str) -> Option<String> {
        // Query package information using pacman -Qi
        let output = tokio::process::Command::new("pacman")
            .args(&["-Qi", package_name])
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse output for "Repository" field
        for line in stdout.lines() {
            if line.starts_with("Repository") {
                if let Some(repo) = line.split(':').nth(1) {
                    let repo = repo.trim();
                    if !repo.is_empty() && repo != "local" {
                        return Some(repo.to_string());
                    }
                }
            }
        }

        None
    }

    async fn get_pacman_package_architecture(&self, package_name: &str) -> Option<String> {
        // Query package architecture using pacman -Qi
        let output = tokio::process::Command::new("pacman")
            .args(&["-Qi", package_name])
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse output for "Architecture" field
        for line in stdout.lines() {
            if line.starts_with("Architecture") {
                if let Some(arch) = line.split(':').nth(1) {
                    let arch = arch.trim();
                    if !arch.is_empty() {
                        return Some(arch.to_string());
                    }
                }
            }
        }

        None
    }

    pub async fn snapshot_apk(&self, config: &SnapshotConfig) -> Result<Vec<LockfilePackage>, PkgError> {
        // APK snapshot implementation for Alpine Linux
        // Uses: apk info (list packages), apk policy (repository info)

        // Get list of all installed packages
        let mut cmd = tokio::process::Command::new("apk");
        cmd.arg("info");

        if config.include_versions == SnapshotVersionMode::None {
            // Just package names
        } else {
            cmd.arg("-v"); // Include version in output
        }

        // Apply timeout
        let output = tokio::time::timeout(
            tokio::time::Duration::from_millis(config.timeout_ms as u64),
            cmd.output()
        )
        .await
        .map_err(|_| PkgError::SnapshotTimeout)?
        .map_err(|e| PkgError::SnapshotFailed(format!("Failed to execute apk: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::SnapshotFailed(format!("apk info failed: {}", stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        // Get explicitly installed (user) packages
        let user_packages = if config.include_install_reason {
            self.get_apk_explicit_packages().await.unwrap_or_default()
        } else {
            HashSet::new()
        };

        // Get pinned packages
        let locked_packages = self.get_apk_pinned_packages().await.unwrap_or_default();

        // Parse package list
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let (name, version) = if config.include_versions != SnapshotVersionMode::None {
                // Format with -v: "package-name-version"
                // Version starts with first hyphen followed by digit
                let mut split_pos = None;
                let chars: Vec<char> = line.chars().collect();

                for i in 0..chars.len() {
                    if chars[i] == '-' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit() {
                        split_pos = Some(i);
                        break;
                    }
                }

                if let Some(pos) = split_pos {
                    let name = line[..pos].to_string();
                    let version = line[pos + 1..].to_string();
                    (name, Some(version))
                } else {
                    (line.to_string(), None)
                }
            } else {
                // Without -v: just package name
                (line.to_string(), None)
            };

            // Check exclude patterns
            if config.exclude_patterns.iter().any(|pattern| {
                if pattern.contains('*') {
                    // Simple wildcard matching
                    let pattern_regex = pattern.replace("*", ".*");
                    regex::Regex::new(&format!("^{}$", pattern_regex))
                        .map(|re| re.is_match(&name))
                        .unwrap_or(false)
                } else {
                    &name == pattern
                }
            }) {
                continue;
            }

            // Get repository information if needed
            let repository = if config.include_repo {
                self.get_apk_package_repository(&name).await
            } else {
                None
            };

            // Get architecture if needed
            let architecture = if config.include_arch {
                self.get_apk_package_architecture(&name).await
            } else {
                None
            };

            // Determine install reason
            let install_reason = if config.include_install_reason {
                if user_packages.contains(&name) {
                    Some("explicit".to_string())
                } else {
                    Some("dependency".to_string())
                }
            } else {
                None
            };

            // Check if package is pinned
            let pinned = locked_packages.contains(&name);

            packages.push(LockfilePackage {
                name,
                version,
                version_spec: None,
                architecture,
                repository,
                install_reason,
                pinned,
            });
        }

        Ok(packages)
    }

    pub async fn get_apk_explicit_packages(&self) -> Result<HashSet<String>, PkgError> {
        // Get explicitly installed packages from /etc/apk/world
        let world_path = "/etc/apk/world";
        let content = tokio::fs::read_to_string(world_path)
            .await
            .unwrap_or_default();

        let mut packages = HashSet::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse package name (may include version constraints)
            // Format can be: package, package=version, package>version, etc.
            let pkg_name = if let Some(pos) = line.find(|c| c == '=' || c == '>' || c == '<' || c == '~') {
                &line[..pos]
            } else {
                line
            };

            packages.insert(pkg_name.to_string());
        }

        Ok(packages)
    }

    pub async fn get_apk_pinned_packages(&self) -> Result<HashSet<String>, PkgError> {
        // Read pinned packages from /etc/apk/world (packages with version pins)
        let world_path = "/etc/apk/world";
        let content = tokio::fs::read_to_string(world_path)
            .await
            .unwrap_or_default();

        let mut pinned_packages = HashSet::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // If line contains version constraint, it's pinned
            if line.contains('=') {
                let pkg_name = if let Some(pos) = line.find('=') {
                    &line[..pos]
                } else {
                    continue;
                };
                pinned_packages.insert(pkg_name.to_string());
            }
        }

        Ok(pinned_packages)
    }

    pub async fn get_apk_package_repository(&self, package_name: &str) -> Option<String> {
        // Query package repository using apk policy
        let output = tokio::process::Command::new("apk")
            .args(&["policy", package_name])
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse output for repository information
        // Format:
        // package-name policy:
        //   @repo_tag http://url
        for line in stdout.lines() {
            let line = line.trim();
            if line.starts_with('@') {
                // Extract repository tag
                if let Some(space_pos) = line.find(' ') {
                    let repo = &line[1..space_pos]; // Skip '@' and take until space
                    if !repo.is_empty() {
                        return Some(repo.to_string());
                    }
                }
            }
        }

        None
    }

    pub async fn get_apk_package_architecture(&self, package_name: &str) -> Option<String> {
        // Query package architecture using apk info
        let output = tokio::process::Command::new("apk")
            .args(&["info", "-a", package_name])
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse output for architecture
        // Format includes: arch:x86_64
        for line in stdout.lines() {
            if line.starts_with("arch:") {
                if let Some(arch) = line.split(':').nth(1) {
                    let arch = arch.trim();
                    if !arch.is_empty() {
                        return Some(arch.to_string());
                    }
                }
            }
        }

        None
    }

    pub async fn snapshot_brew(&self, config: &SnapshotConfig) -> Result<Vec<LockfilePackage>, PkgError> {
        // Homebrew snapshot implementation for macOS and Linux
        // Uses: brew list (installed packages), brew info --json (package details)

        // Get list of all installed formulae and casks
        let mut cmd = tokio::process::Command::new("brew");
        cmd.arg("list");
        cmd.arg("--formula"); // List formulae only (not casks by default)

        // Apply timeout
        let output = tokio::time::timeout(
            tokio::time::Duration::from_millis(config.timeout_ms as u64),
            cmd.output()
        )
        .await
        .map_err(|_| PkgError::SnapshotTimeout)?
        .map_err(|e| PkgError::SnapshotFailed(format!("Failed to execute brew: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::SnapshotFailed(format!("brew list failed: {}", stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        // Get explicitly installed packages (leaves)
        let user_packages = if config.include_install_reason {
            self.get_brew_leaves().await.unwrap_or_default()
        } else {
            HashSet::new()
        };

        // Get pinned packages
        let locked_packages = self.get_brew_pinned_packages().await.unwrap_or_default();

        // Parse package list
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let name = line.to_string();

            // Check exclude patterns
            if config.exclude_patterns.iter().any(|pattern| {
                if pattern.contains('*') {
                    // Simple wildcard matching
                    let pattern_regex = pattern.replace("*", ".*");
                    regex::Regex::new(&format!("^{}$", pattern_regex))
                        .map(|re| re.is_match(&name))
                        .unwrap_or(false)
                } else {
                    &name == pattern
                }
            }) {
                continue;
            }

            // Get version information if needed
            let version = if config.include_versions != SnapshotVersionMode::None {
                self.get_brew_package_version(&name).await
            } else {
                None
            };

            // Get repository information (tap) if needed
            let repository = if config.include_repo {
                self.get_brew_package_tap(&name).await
            } else {
                None
            };

            // Get architecture if needed
            let architecture = if config.include_arch {
                self.get_brew_package_architecture(&name).await
            } else {
                None
            };

            // Determine install reason (leaf packages are explicitly installed)
            let install_reason = if config.include_install_reason {
                if user_packages.contains(&name) {
                    Some("explicit".to_string())
                } else {
                    Some("dependency".to_string())
                }
            } else {
                None
            };

            // Check if package is pinned
            let pinned = locked_packages.contains(&name);

            packages.push(LockfilePackage {
                name,
                version,
                version_spec: None,
                architecture,
                repository,
                install_reason,
                pinned,
            });
        }

        Ok(packages)
    }

    pub async fn get_brew_leaves(&self) -> Result<HashSet<String>, PkgError> {
        // Get leaf packages (explicitly installed, not dependencies)
        let output = tokio::process::Command::new("brew")
            .args(&["leaves"])
            .output()
            .await
            .map_err(|e| PkgError::SnapshotFailed(format!("Failed to execute brew leaves: {}", e)))?;

        if !output.status.success() {
            return Ok(HashSet::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = HashSet::new();

        for line in stdout.lines() {
            let line = line.trim();
            if !line.is_empty() {
                packages.insert(line.to_string());
            }
        }

        Ok(packages)
    }

    pub async fn get_brew_pinned_packages(&self) -> Result<HashSet<String>, PkgError> {
        // Get pinned packages using brew list --pinned
        let output = tokio::process::Command::new("brew")
            .args(&["list", "--pinned"])
            .output()
            .await
            .map_err(|e| PkgError::SnapshotFailed(format!("Failed to execute brew list --pinned: {}", e)))?;

        if !output.status.success() {
            return Ok(HashSet::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut pinned_packages = HashSet::new();

        for line in stdout.lines() {
            let line = line.trim();
            if !line.is_empty() {
                pinned_packages.insert(line.to_string());
            }
        }

        Ok(pinned_packages)
    }

    pub async fn get_brew_package_version(&self, package_name: &str) -> Option<String> {
        // Query package version using brew info --json
        let output = tokio::process::Command::new("brew")
            .args(&["info", "--json=v2", package_name])
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse JSON output
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            // Homebrew info --json=v2 format
            if let Some(formulae) = json.get("formulae").and_then(|f| f.as_array()) {
                if let Some(formula) = formulae.first() {
                    if let Some(versions) = formula.get("versions") {
                        if let Some(stable) = versions.get("stable").and_then(|v| v.as_str()) {
                            return Some(stable.to_string());
                        }
                    }
                }
            }
            // Also check installed version
            if let Some(formulae) = json.get("formulae").and_then(|f| f.as_array()) {
                if let Some(formula) = formulae.first() {
                    if let Some(installed) = formula.get("installed").and_then(|i| i.as_array()) {
                        if let Some(first_install) = installed.first() {
                            if let Some(version) = first_install.get("version").and_then(|v| v.as_str()) {
                                return Some(version.to_string());
                            }
                        }
                    }
                }
            }
        }

        None
    }

    pub async fn get_brew_package_tap(&self, package_name: &str) -> Option<String> {
        // Query package tap (repository) using brew info --json
        let output = tokio::process::Command::new("brew")
            .args(&["info", "--json=v2", package_name])
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse JSON output for tap
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            if let Some(formulae) = json.get("formulae").and_then(|f| f.as_array()) {
                if let Some(formula) = formulae.first() {
                    if let Some(tap) = formula.get("tap").and_then(|t| t.as_str()) {
                        // Convert "homebrew/core" to just "core" for brevity
                        if let Some(short_tap) = tap.strip_prefix("homebrew/") {
                            return Some(short_tap.to_string());
                        }
                        return Some(tap.to_string());
                    }
                }
            }
        }

        None
    }

    pub async fn get_brew_package_architecture(&self, _package_name: &str) -> Option<String> {
        // Get system architecture for Homebrew packages
        // Homebrew bottles are architecture-specific
        let output = tokio::process::Command::new("uname")
            .arg("-m")
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let arch = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Normalize architecture names
        match arch.as_str() {
            "x86_64" => Some("x86_64".to_string()),
            "arm64" => Some("arm64".to_string()),
            "aarch64" => Some("arm64".to_string()),
            _ => Some(arch),
        }
    }

    // ===============================
    // Restore implementation functions  
    // ===============================

    fn parse_lockfile(&self, content: &str, format: &LockfileFormat) -> Result<Lockfile, PkgError> {
        match format {
            LockfileFormat::Auto => {
                // Try JSON first
                if let Ok(lockfile) = serde_json::from_str::<Lockfile>(content) {
                    return Ok(lockfile);
                }
                
                // Try YAML next
                if let Ok(lockfile) = serde_yaml::from_str::<Lockfile>(content) {
                    return Ok(lockfile);
                }
                
                // Fall back to text format
                self.parse_text_lockfile(content)
            },
            LockfileFormat::Json => {
                serde_json::from_str::<Lockfile>(content)
                    .map_err(|e| PkgError::RestoreInvalidLockfile(format!("Invalid JSON lockfile: {}", e)))
            },
            LockfileFormat::Yaml => {
                serde_yaml::from_str::<Lockfile>(content)
                    .map_err(|e| PkgError::RestoreInvalidLockfile(format!("Invalid YAML lockfile: {}", e)))
            },
            LockfileFormat::Text => {
                self.parse_text_lockfile(content)
            },
        }
    }

    fn parse_text_lockfile(&self, content: &str) -> Result<Lockfile, PkgError> {
        // Simple text format parser - implement basic line-based parsing
        // This is a minimal implementation - can be extended based on requirements
        let mut packages = Vec::new();
        
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            // Parse simple format: "package_name=version"
            if let Some((name, version)) = line.split_once('=') {
                packages.push(LockfilePackage {
                    name: name.trim().to_string(),
                    version: Some(version.trim().to_string()),
                    version_spec: None,
                    architecture: None,
                    repository: None,
                    install_reason: None,
                    pinned: false,
                });
            } else {
                // Just package name
                packages.push(LockfilePackage {
                    name: line.to_string(),
                    version: None,
                    version_spec: None,
                    architecture: None,
                    repository: None,
                    install_reason: None,
                    pinned: false,
                });
            }
        }
        
        // Create minimal lockfile structure
        Ok(Lockfile {
            lockfile_version: "pkg-lock/v1".to_string(),
            generated_at: "unknown".to_string(),
            manager: ManagerInfo {
                name: "auto".to_string(),
                alias: "system".to_string(),
                version: None,
                config: None,
            },
            platform: PlatformInfo {
                os_family: None,
                os_name: None,
                os_version: None,
                kernel: None,
                architecture: None,
            },
            scope: "all".to_string(),
            packages,
        })
    }

    async fn validate_lockfile(&self, lockfile: &Lockfile, config: &RestoreConfig) -> Result<(), PkgError> {
        // Validate lockfile version
        if !lockfile.lockfile_version.starts_with("pkg-lock/v1") {
            return Err(PkgError::RestoreInvalidLockfile(
                format!("Unsupported lockfile version: {}", lockfile.lockfile_version)
            ));
        }

        // Validate platform compatibility
        if config.on_platform_mismatch == PlatformPolicy::Fail {
            let host_platform = self.get_platform_info().await.ok();
            if let Some(host) = host_platform {
                let lockfile_platform = &lockfile.platform;
                
                if let (Some(host_os), Some(lock_os)) = (&host.os_name, &lockfile_platform.os_name) {
                    if host_os != lock_os {
                        return Err(PkgError::RestorePlatformIncompatible(
                            format!("Host OS {} does not match lockfile OS {}", host_os, lock_os)
                        ));
                    }
                }
                
                if let (Some(host_arch), Some(lock_arch)) = (&host.architecture, &lockfile_platform.architecture) {
                    if host_arch != lock_arch {
                        return Err(PkgError::RestorePlatformIncompatible(
                            format!("Host architecture {} does not match lockfile architecture {}", host_arch, lock_arch)
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    fn resolve_restore_manager(&self, config_manager: &ManagerKind, lockfile: &Lockfile) -> Result<ManagerKind, PkgError> {
        match config_manager {
            ManagerKind::Auto => {
                // Use lockfile manager
                match lockfile.manager.name.as_str() {
                    "apt" => Ok(ManagerKind::Apt),
                    "yum" => Ok(ManagerKind::Yum),
                    "dnf" => Ok(ManagerKind::Dnf),
                    "pacman" => Ok(ManagerKind::Pacman),
                    "apk" => Ok(ManagerKind::Apk),
                    "brew" => Ok(ManagerKind::Brew),
                    _ => Err(PkgError::ManagerNotFound(lockfile.manager.name.clone())),
                }
            },
            other => {
                // Verify compatibility with lockfile
                let config_name = match other {
                    ManagerKind::Apt => "apt",
                    ManagerKind::Yum => "yum", 
                    ManagerKind::Dnf => "dnf",
                    ManagerKind::Pacman => "pacman",
                    ManagerKind::Apk => "apk",
                    ManagerKind::Brew => "brew",
                    ManagerKind::Auto => unreachable!(),
                };
                
                if config_name != lockfile.manager.name && 
                   !(config_name == "dnf" && lockfile.manager.name == "yum") && 
                   !(config_name == "yum" && lockfile.manager.name == "dnf") {
                    return Err(PkgError::RestoreManagerMismatch(
                        format!("Config manager {} does not match lockfile manager {}", 
                            config_name, lockfile.manager.name)
                    ));
                }
                
                Ok(other.clone())
            }
        }
    }

    async fn perform_restore(&self, config: &RestoreConfig, lockfile: &Lockfile, manager: &ManagerKind) -> Result<Value, PkgError> {
        // Get current installed packages
        let current_packages = self.get_current_packages(manager).await?;
        
        // Compute diff between lockfile and current state
        let plan = self.compute_restore_plan(lockfile, &current_packages, config)?;
        
        if config.dry_run {
            // Return dry-run plan
            return Ok(json!({
                "backend": "pkg",
                "action": "restore",
                "manager": format!("{:?}", manager).to_lowercase(),
                "alias": &self.alias,
                "mode": format!("{:?}", config.mode).to_lowercase(),
                "dry_run": true,
                "plan": plan,
                "commands": self.generate_restore_commands(&plan, manager, config)
            }));
        }
        
        // Execute the restore plan
        let results = self.execute_restore_plan(&plan, manager, config).await?;
        
        // Compute summary
        let summary = self.compute_restore_summary(&plan, &results, config);
        
        Ok(json!({
            "backend": "pkg",
            "action": "restore", 
            "manager": format!("{:?}", manager).to_lowercase(),
            "alias": &self.alias,
            "mode": format!("{:?}", config.mode).to_lowercase(),
            "dry_run": false,
            "plan": plan,
            "results": results,
            "summary": summary
        }))
    }

    async fn get_current_packages(&self, manager: &ManagerKind) -> Result<Vec<InstalledPackage>, PkgError> {
        // Reuse existing list_installed logic
        let list_config = ListInstalledConfig {
            manager: manager.clone(),
            filter: None,
            prefix: None,
            include_versions: true,
            include_repo: true,
            include_size: false,
            include_install_reason: true,
            limit: 10000, // Large limit to get all packages
            offset: 0,
            timeout_ms: 30000,
            extra_args: None,
            env: None,
        };
        
        let results = self.list_installed_async(list_config).await?;
        
        // Extract packages from the results JSON
        if let Ok(list_results) = serde_json::from_value::<ListInstalledResults>(results) {
            Ok(list_results.results)
        } else {
            Ok(Vec::new())
        }
    }

    // Platform detection helpers
    async fn get_platform_info(&self) -> Result<PlatformInfo, PkgError> {
        // Detect OS family using compile-time detection
        let os_family = detect_os_family();

        // Detect OS name and version
        let (os_name, os_version) = detect_os_name_and_version().await?;

        // Detect kernel version
        let kernel = detect_kernel_version().await;

        // Detect architecture
        let architecture = detect_architecture();

        Ok(PlatformInfo {
            os_family: Some(os_family),
            os_name,
            os_version,
            kernel,
            architecture: Some(architecture),
        })
    }

    fn compute_restore_plan(&self, lockfile: &Lockfile, current_packages: &[InstalledPackage], config: &RestoreConfig) -> Result<RestorePlan, PkgError> {
        let mut plan = RestorePlan {
            install: Vec::new(),
            upgrade: Vec::new(),
            downgrade: Vec::new(),
            remove: Vec::new(),
            keep: Vec::new(),
            extra: Vec::new(),
            unresolved: Vec::new(),
        };

        // Create lookup map of current packages
        let mut current_map = std::collections::HashMap::new();
        for pkg in current_packages {
            current_map.insert(&pkg.name, pkg);
        }

        // Process lockfile packages
        for lock_pkg in &lockfile.packages {
            match current_map.remove(&lock_pkg.name) {
                Some(current_pkg) => {
                    if let Some(ref lock_version) = lock_pkg.version {
                        let comparison = self.compare_versions(&current_pkg.version, lock_version);
                        match comparison {
                            std::cmp::Ordering::Equal => plan.keep.push(lock_pkg.name.clone()),
                            std::cmp::Ordering::Less => plan.upgrade.push(lock_pkg.name.clone()),
                            std::cmp::Ordering::Greater => {
                                if config.allow_newer {
                                    plan.keep.push(lock_pkg.name.clone());
                                } else if config.allow_downgrades {
                                    plan.downgrade.push(lock_pkg.name.clone());
                                } else {
                                    plan.unresolved.push(UnresolvedPackage {
                                        name: lock_pkg.name.clone(),
                                        reason: "newer_version_installed_downgrade_not_allowed".to_string(),
                                    });
                                }
                            }
                        }
                    } else {
                        // No version specified in lockfile, just keep
                        plan.keep.push(lock_pkg.name.clone());
                    }
                },
                None => {
                    // Package not installed, needs to be installed
                    plan.install.push(lock_pkg.name.clone());
                }
            }
        }

        // Handle extra packages (installed but not in lockfile)
        if config.allow_removals {
            for (name, _) in current_map {
                plan.remove.push(name.clone());
            }
        } else {
            for (name, _) in current_map {
                plan.extra.push(name.clone());
            }
        }

        Ok(plan)
    }

    fn compare_versions(&self, current: &str, target: &str) -> std::cmp::Ordering {
        // Simple version comparison - can be enhanced with proper semver logic
        current.cmp(target)
    }

    fn generate_restore_commands(&self, plan: &RestorePlan, manager: &ManagerKind, _config: &RestoreConfig) -> Vec<String> {
        let mut commands = Vec::new();

        match manager {
            ManagerKind::Apt => {
                if !plan.install.is_empty() || !plan.upgrade.is_empty() {
                    let mut install_cmd = "apt-get install -y".to_string();
                    for pkg in &plan.install {
                        install_cmd.push_str(&format!(" {}", pkg));
                    }
                    for pkg in &plan.upgrade {
                        install_cmd.push_str(&format!(" {}", pkg));
                    }
                    commands.push(install_cmd);
                }
                
                if !plan.downgrade.is_empty() {
                    let mut downgrade_cmd = "apt-get install --allow-downgrades -y".to_string();
                    for pkg in &plan.downgrade {
                        downgrade_cmd.push_str(&format!(" {}", pkg));
                    }
                    commands.push(downgrade_cmd);
                }
                
                if !plan.remove.is_empty() {
                    let mut remove_cmd = "apt-get remove -y".to_string();
                    for pkg in &plan.remove {
                        remove_cmd.push_str(&format!(" {}", pkg));
                    }
                    commands.push(remove_cmd);
                }
            },
            ManagerKind::Dnf | ManagerKind::Yum => {
                let manager_name = if matches!(manager, ManagerKind::Dnf) { "dnf" } else { "yum" };
                
                if !plan.install.is_empty() || !plan.upgrade.is_empty() {
                    let mut install_cmd = format!("{} install -y", manager_name);
                    for pkg in &plan.install {
                        install_cmd.push_str(&format!(" {}", pkg));
                    }
                    for pkg in &plan.upgrade {
                        install_cmd.push_str(&format!(" {}", pkg));
                    }
                    commands.push(install_cmd);
                }
                
                if !plan.remove.is_empty() {
                    let mut remove_cmd = format!("{} remove -y", manager_name);
                    for pkg in &plan.remove {
                        remove_cmd.push_str(&format!(" {}", pkg));
                    }
                    commands.push(remove_cmd);
                }
            },
            ManagerKind::Pacman => {
                if !plan.install.is_empty() || !plan.upgrade.is_empty() {
                    let mut install_cmd = "pacman -S --noconfirm".to_string();
                    for pkg in &plan.install {
                        install_cmd.push_str(&format!(" {}", pkg));
                    }
                    for pkg in &plan.upgrade {
                        install_cmd.push_str(&format!(" {}", pkg));
                    }
                    commands.push(install_cmd);
                }
                
                if !plan.remove.is_empty() {
                    let mut remove_cmd = "pacman -R --noconfirm".to_string();
                    for pkg in &plan.remove {
                        remove_cmd.push_str(&format!(" {}", pkg));
                    }
                    commands.push(remove_cmd);
                }
            },
            ManagerKind::Apk => {
                if !plan.install.is_empty() || !plan.upgrade.is_empty() {
                    let mut install_cmd = "apk add --no-interactive".to_string();
                    for pkg in &plan.install {
                        install_cmd.push_str(&format!(" {}", pkg));
                    }
                    for pkg in &plan.upgrade {
                        install_cmd.push_str(&format!(" {}", pkg));
                    }
                    commands.push(install_cmd);
                }
                
                if !plan.remove.is_empty() {
                    let mut remove_cmd = "apk del --no-interactive".to_string();
                    for pkg in &plan.remove {
                        remove_cmd.push_str(&format!(" {}", pkg));
                    }
                    commands.push(remove_cmd);
                }
            },
            ManagerKind::Brew => {
                if !plan.install.is_empty() {
                    for pkg in &plan.install {
                        commands.push(format!("brew install {}", pkg));
                    }
                }
                
                if !plan.remove.is_empty() {
                    for pkg in &plan.remove {
                        commands.push(format!("brew uninstall {}", pkg));
                    }
                }
            },
            _ => {}
        }

        commands
    }

    async fn execute_restore_plan(&self, plan: &RestorePlan, manager: &ManagerKind, config: &RestoreConfig) -> Result<RestoreResults, PkgError> {
        let mut results = RestoreResults {
            install: Vec::new(),
            upgrade: Vec::new(),
            downgrade: Vec::new(),
            remove: Vec::new(),
        };

        // Execute installs
        for pkg in &plan.install {
            let result = self.execute_package_install(pkg, manager, config).await;
            results.install.push(self.create_package_result(pkg, result, None));
        }

        // Execute upgrades  
        for pkg in &plan.upgrade {
            let result = self.execute_package_upgrade(pkg, manager, config).await;
            results.upgrade.push(self.create_package_result(pkg, result, None));
        }

        // Execute downgrades
        for pkg in &plan.downgrade {
            let result = self.execute_package_downgrade(pkg, manager, config).await;
            results.downgrade.push(self.create_package_result(pkg, result, None));
        }

        // Execute removes
        for pkg in &plan.remove {
            let result = self.execute_package_remove(pkg, manager, config).await;
            results.remove.push(self.create_package_result(pkg, result, None));
        }

        Ok(results)
    }

    async fn execute_package_install(&self, pkg: &str, manager: &ManagerKind, config: &RestoreConfig) -> Result<String, PkgError> {
        match manager {
            ManagerKind::Apt => {
                let mut cmd = AsyncCommand::new("apt-get");
                cmd.args(&["install", "-y", pkg]);
                self.execute_manager_command(cmd, config).await
            },
            ManagerKind::Dnf => {
                let mut cmd = AsyncCommand::new("dnf");
                cmd.args(&["install", "-y", pkg]);
                self.execute_manager_command(cmd, config).await
            },
            ManagerKind::Yum => {
                let mut cmd = AsyncCommand::new("yum");
                cmd.args(&["install", "-y", pkg]);
                self.execute_manager_command(cmd, config).await
            },
            ManagerKind::Pacman => {
                let mut cmd = AsyncCommand::new("pacman");
                cmd.args(&["-S", "--noconfirm", pkg]);
                self.execute_manager_command(cmd, config).await
            },
            ManagerKind::Apk => {
                let mut cmd = AsyncCommand::new("apk");
                cmd.args(&["add", "--no-interactive", pkg]);
                self.execute_manager_command(cmd, config).await
            },
            ManagerKind::Brew => {
                let mut cmd = AsyncCommand::new("brew");
                cmd.args(&["install", pkg]);
                self.execute_manager_command(cmd, config).await
            },
            ManagerKind::Auto => Err(PkgError::ManagerNotFound("auto".to_string())),
        }
    }

    async fn execute_package_upgrade(&self, pkg: &str, manager: &ManagerKind, config: &RestoreConfig) -> Result<String, PkgError> {
        // For most managers, upgrade is same as install
        self.execute_package_install(pkg, manager, config).await
    }

    async fn execute_package_downgrade(&self, pkg: &str, manager: &ManagerKind, config: &RestoreConfig) -> Result<String, PkgError> {
        match manager {
            ManagerKind::Apt => {
                let mut cmd = AsyncCommand::new("apt-get");
                cmd.args(&["install", "--allow-downgrades", "-y", pkg]);
                self.execute_manager_command(cmd, config).await
            },
            ManagerKind::Dnf => {
                let mut cmd = AsyncCommand::new("dnf");
                cmd.args(&["downgrade", "-y", pkg]);
                self.execute_manager_command(cmd, config).await
            },
            ManagerKind::Yum => {
                let mut cmd = AsyncCommand::new("yum");
                cmd.args(&["downgrade", "-y", pkg]);
                self.execute_manager_command(cmd, config).await
            },
            _ => Err(PkgError::RestoreDowngradeNotSupported(format!("{:?}", manager))),
        }
    }

    async fn execute_package_remove(&self, pkg: &str, manager: &ManagerKind, config: &RestoreConfig) -> Result<String, PkgError> {
        match manager {
            ManagerKind::Apt => {
                let mut cmd = AsyncCommand::new("apt-get");
                cmd.args(&["remove", "-y", pkg]);
                self.execute_manager_command(cmd, config).await
            },
            ManagerKind::Dnf => {
                let mut cmd = AsyncCommand::new("dnf");
                cmd.args(&["remove", "-y", pkg]);
                self.execute_manager_command(cmd, config).await
            },
            ManagerKind::Yum => {
                let mut cmd = AsyncCommand::new("yum");
                cmd.args(&["remove", "-y", pkg]);
                self.execute_manager_command(cmd, config).await
            },
            ManagerKind::Pacman => {
                let mut cmd = AsyncCommand::new("pacman");
                cmd.args(&["-R", "--noconfirm", pkg]);
                self.execute_manager_command(cmd, config).await
            },
            ManagerKind::Apk => {
                let mut cmd = AsyncCommand::new("apk");
                cmd.args(&["del", "--no-interactive", pkg]);
                self.execute_manager_command(cmd, config).await
            },
            ManagerKind::Brew => {
                let mut cmd = AsyncCommand::new("brew");
                cmd.args(&["uninstall", pkg]);
                self.execute_manager_command(cmd, config).await
            },
            ManagerKind::Auto => Err(PkgError::ManagerNotFound("auto".to_string())),
        }
    }

    async fn execute_manager_command(&self, mut cmd: AsyncCommand, config: &RestoreConfig) -> Result<String, PkgError> {
        if let Some(ref env) = config.env {
            for (key, value) in env {
                cmd.env(key, value);
            }
        }

        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = cmd.output().await
            .map_err(|e| PkgError::RestoreApplyFailed(format!("Command execution failed: {}", e)))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(PkgError::RestoreApplyFailed(
                format!("Command failed: {}", String::from_utf8_lossy(&output.stderr))
            ))
        }
    }

    fn create_package_result(&self, pkg: &str, result: Result<String, PkgError>, from_version: Option<String>) -> PackageOpResult {
        match result {
            Ok(_) => PackageOpResult {
                name: pkg.to_string(),
                status: "success".to_string(),
                from_version,
                to_version: None, // Could be enhanced to extract actual installed version
                error: None,
            },
            Err(e) => PackageOpResult {
                name: pkg.to_string(),
                status: "failed".to_string(),
                from_version,
                to_version: None,
                error: Some(e.to_string()),
            },
        }
    }

    fn compute_restore_summary(&self, plan: &RestorePlan, results: &RestoreResults, config: &RestoreConfig) -> RestoreSummary {
        let installed = results.install.iter().filter(|r| r.status == "success").count() as u32;
        let upgraded = results.upgrade.iter().filter(|r| r.status == "success").count() as u32;
        let downgraded = results.downgrade.iter().filter(|r| r.status == "success").count() as u32;
        let removed = results.remove.iter().filter(|r| r.status == "success").count() as u32;
        let failed = results.install.iter().chain(&results.upgrade).chain(&results.downgrade).chain(&results.remove)
            .filter(|r| r.status == "failed").count() as u32;

        let success = match config.on_missing_package {
            MissingPolicy::Fail => plan.unresolved.is_empty() && failed == 0,
            _ => failed == 0,
        };

        RestoreSummary {
            installed,
            upgraded,
            downgraded,
            removed,
            kept: plan.keep.len() as u32,
            extra: plan.extra.len() as u32,
            unresolved: plan.unresolved.len() as u32,
            failed,
            mode: format!("{:?}", config.mode).to_lowercase(),
            success,
        }
    }
}

// Platform detection helper functions

/// Detect OS family using compile-time configuration
fn detect_os_family() -> String {
    #[cfg(target_os = "linux")]
    return "linux".to_string();

    #[cfg(target_os = "macos")]
    return "darwin".to_string();

    #[cfg(target_os = "windows")]
    return "windows".to_string();

    #[cfg(target_os = "freebsd")]
    return "freebsd".to_string();

    #[cfg(target_os = "openbsd")]
    return "openbsd".to_string();

    #[cfg(target_os = "netbsd")]
    return "netbsd".to_string();

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    return "unknown".to_string();
}

/// Detect architecture using compile-time configuration
fn detect_architecture() -> String {
    #[cfg(target_arch = "x86_64")]
    return "x86_64".to_string();

    #[cfg(target_arch = "x86")]
    return "x86".to_string();

    #[cfg(target_arch = "aarch64")]
    return "aarch64".to_string();

    #[cfg(target_arch = "arm")]
    return "arm".to_string();

    #[cfg(target_arch = "riscv64")]
    return "riscv64".to_string();

    #[cfg(target_arch = "powerpc64")]
    return "powerpc64".to_string();

    #[cfg(target_arch = "s390x")]
    return "s390x".to_string();

    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64",
        target_arch = "powerpc64",
        target_arch = "s390x"
    )))]
    return "unknown".to_string();
}

/// Detect OS name and version from /etc/os-release or system commands
async fn detect_os_name_and_version() -> Result<(Option<String>, Option<String>), PkgError> {
    #[cfg(target_os = "linux")]
    {
        // Try reading /etc/os-release first (most modern Linux distributions)
        if let Ok(contents) = tokio::fs::read_to_string("/etc/os-release").await {
            let mut os_name = None;
            let mut os_version = None;

            for line in contents.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    let value = value.trim_matches('"');
                    match key {
                        "NAME" => os_name = Some(value.to_string()),
                        "VERSION" | "VERSION_ID" if os_version.is_none() => {
                            os_version = Some(value.to_string())
                        }
                        _ => {}
                    }
                }
            }

            if os_name.is_some() {
                return Ok((os_name, os_version));
            }
        }

        // Fallback to lsb_release command
        if let Ok(output) = AsyncCommand::new("lsb_release")
            .args(&["-si"])
            .output()
            .await
        {
            if output.status.success() {
                let os_name = String::from_utf8_lossy(&output.stdout).trim().to_string();

                // Get version
                let os_version = if let Ok(version_output) = AsyncCommand::new("lsb_release")
                    .args(&["-sr"])
                    .output()
                    .await
                {
                    if version_output.status.success() {
                        Some(String::from_utf8_lossy(&version_output.stdout).trim().to_string())
                    } else {
                        None
                    }
                } else {
                    None
                };

                return Ok((Some(os_name), os_version));
            }
        }

        // Fallback to uname
        if let Ok(output) = AsyncCommand::new("uname").args(&["-s"]).output().await {
            if output.status.success() {
                let os_name = String::from_utf8_lossy(&output.stdout).trim().to_string();
                return Ok((Some(os_name), None));
            }
        }

        Ok((Some("Linux".to_string()), None))
    }

    #[cfg(target_os = "macos")]
    {
        // Get macOS version from sw_vers
        let os_name = Some("macOS".to_string());
        let os_version = if let Ok(output) = AsyncCommand::new("sw_vers")
            .args(&["-productVersion"])
            .output()
            .await
        {
            if output.status.success() {
                Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
            } else {
                None
            }
        } else {
            None
        };

        Ok((os_name, os_version))
    }

    #[cfg(target_os = "windows")]
    {
        // Get Windows version from ver command or registry
        let os_name = Some("Windows".to_string());
        let os_version = if let Ok(output) = AsyncCommand::new("cmd")
            .args(&["/c", "ver"])
            .output()
            .await
        {
            if output.status.success() {
                let version_str = String::from_utf8_lossy(&output.stdout);
                // Extract version number from output like "Microsoft Windows [Version 10.0.19041.1234]"
                if let Some(start) = version_str.find("Version ") {
                    let version_part = &version_str[start + 8..];
                    if let Some(end) = version_part.find(']') {
                        Some(version_part[..end].trim().to_string())
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        Ok((os_name, os_version))
    }

    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    {
        // BSD systems
        if let Ok(output) = AsyncCommand::new("uname").args(&["-s"]).output().await {
            if output.status.success() {
                let os_name = Some(String::from_utf8_lossy(&output.stdout).trim().to_string());

                // Get version
                let os_version = if let Ok(version_output) = AsyncCommand::new("uname")
                    .args(&["-r"])
                    .output()
                    .await
                {
                    if version_output.status.success() {
                        Some(String::from_utf8_lossy(&version_output.stdout).trim().to_string())
                    } else {
                        None
                    }
                } else {
                    None
                };

                return Ok((os_name, os_version));
            }
        }

        Ok((None, None))
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    {
        Ok((None, None))
    }
}

/// Detect kernel version
async fn detect_kernel_version() -> Option<String> {
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        if let Ok(output) = AsyncCommand::new("uname").args(&["-r"]).output().await {
            if output.status.success() {
                return Some(String::from_utf8_lossy(&output.stdout).trim().to_string());
            }
        }
        None
    }

    #[cfg(target_os = "windows")]
    {
        // Windows kernel version is typically the same as OS version
        // Get from wmic or systeminfo
        if let Ok(output) = AsyncCommand::new("cmd")
            .args(&["/c", "ver"])
            .output()
            .await
        {
            if output.status.success() {
                let version_str = String::from_utf8_lossy(&output.stdout);
                if let Some(start) = version_str.find("Version ") {
                    let version_part = &version_str[start + 8..];
                    if let Some(end) = version_part.find(']') {
                        return Some(version_part[..end].trim().to_string());
                    }
                }
            }
        }
        None
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_update_config_validation_invalid_timeout() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = UpdateConfig {
            manager: ManagerKind::Auto,
            packages: vec![],
            refresh_index: true,
            upgrade: true,
            assume_yes: true,
            security_only: false,
            check_only: false,
            dry_run: false,
            timeout_ms: 0, // Invalid
            extra_args: None,
            env: None,
        };
        
        let result = handle.validate_update_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timeout_ms must be greater than 0"));
    }

    #[test]
    fn test_update_config_validation_nothing_to_do() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = UpdateConfig {
            manager: ManagerKind::Auto,
            packages: vec![],
            refresh_index: false,
            upgrade: false,
            assume_yes: true,
            security_only: false,
            check_only: false,
            dry_run: false,
            timeout_ms: 900000,
            extra_args: None,
            env: None,
        };
        
        let result = handle.validate_update_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Nothing to do"));
    }

    #[test]
    fn test_update_config_validation_valid() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = UpdateConfig {
            manager: ManagerKind::Auto,
            packages: vec![],
            refresh_index: true,
            upgrade: true,
            assume_yes: true,
            security_only: false,
            check_only: false,
            dry_run: false,
            timeout_ms: 900000,
            extra_args: None,
            env: None,
        };
        
        let result = handle.validate_update_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_apt_update_line() {
        let handle = PkgHandle { alias: "test".to_string() };
        let line = "curl/jammy-updates 7.81.0-1ubuntu1.15 amd64 [upgradable from: 7.81.0-1ubuntu1.14]";
        let result = handle.parse_apt_update_line(line);
        
        assert!(result.is_some());
        let update = result.unwrap();
        assert_eq!(update.name, "curl");
        assert_eq!(update.candidate_version, "7.81.0-1ubuntu1.15");
        assert_eq!(update.current_version, Some("7.81.0-1ubuntu1.14".to_string()));
    }

    #[test]
    fn test_parse_pacman_update_line() {
        let handle = PkgHandle { alias: "test".to_string() };
        let line = "linux 6.9.1.arch1-1 -> 6.9.2.arch1-1";
        let result = handle.parse_pacman_update_line(line);
        
        assert!(result.is_some());
        let update = result.unwrap();
        assert_eq!(update.name, "linux");
        assert_eq!(update.candidate_version, "6.9.2.arch1-1");
        assert_eq!(update.current_version, Some("6.9.1.arch1-1".to_string()));
    }

    #[test]
    fn test_parse_brew_update_line() {
        let handle = PkgHandle { alias: "test".to_string() };
        let line = "curl (7.85.0) < 7.86.0";
        let result = handle.parse_brew_update_line(line);
        
        assert!(result.is_some());
        let update = result.unwrap();
        assert_eq!(update.name, "curl");
        assert_eq!(update.candidate_version, "7.86.0");
        assert_eq!(update.current_version, Some("7.85.0".to_string()));
    }

    #[test]
    fn test_upgrade_config_validation_invalid_timeout() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = UpgradeConfig {
            manager: ManagerKind::Auto,
            packages: vec![],
            refresh_index: true,
            assume_yes: true,
            security_only: false,
            dry_run: false,
            check_only: false,
            timeout_ms: 0, // Invalid
            extra_args: None,
            env: None,
        };
        
        let result = handle.validate_upgrade_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timeout_ms must be greater than 0"));
    }

    #[test]
    fn test_upgrade_config_validation_empty_packages() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = UpgradeConfig {
            manager: ManagerKind::Auto,
            packages: vec!["curl".to_string(), "".to_string()], // Contains empty package name
            refresh_index: true,
            assume_yes: true,
            security_only: false,
            dry_run: false,
            check_only: false,
            timeout_ms: 900000,
            extra_args: None,
            env: None,
        };
        
        let result = handle.validate_upgrade_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("package names cannot be empty"));
    }

    #[test]
    fn test_upgrade_config_validation_meaningless_combination() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = UpgradeConfig {
            manager: ManagerKind::Auto,
            packages: vec![], // Empty packages
            refresh_index: false, // No index refresh
            assume_yes: true,
            security_only: false,
            dry_run: true, // Dry run
            check_only: true, // And check only
            timeout_ms: 900000,
            extra_args: None,
            env: None,
        };
        
        let result = handle.validate_upgrade_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Nothing meaningful to do"));
    }

    #[test]
    fn test_upgrade_config_validation_valid() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = UpgradeConfig {
            manager: ManagerKind::Auto,
            packages: vec!["curl".to_string(), "git".to_string()],
            refresh_index: true,
            assume_yes: true,
            security_only: false,
            dry_run: false,
            check_only: false,
            timeout_ms: 900000,
            extra_args: None,
            env: None,
        };
        
        let result = handle.validate_upgrade_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_upgrade_config_validation_valid_check_only() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = UpgradeConfig {
            manager: ManagerKind::Auto,
            packages: vec![], // Empty packages is OK with check_only
            refresh_index: true, // With refresh index
            assume_yes: true,
            security_only: false,
            dry_run: false,
            check_only: true,
            timeout_ms: 900000,
            extra_args: None,
            env: None,
        };
        
        let result = handle.validate_upgrade_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_update_verbs_list() {
        let handle = PkgHandle { alias: "test".to_string() };
        let verbs = handle.verbs();
        assert!(verbs.contains(&"update"));
        assert!(verbs.contains(&"install"));
        assert!(verbs.contains(&"remove"));
        assert!(verbs.contains(&"upgrade"));
        assert!(verbs.contains(&"info"));
    }

    #[test]
    fn test_info_config_validation_empty_packages() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = InfoConfig {
            manager: ManagerKind::Auto,
            packages: vec![], // Empty packages
            include_dependencies: false,
            include_reverse_deps: false,
            include_files: false,
            include_repo: true,
            timeout_ms: 5000,
            extra_args: None,
            env: None,
        };
        
        let result = handle.validate_info_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("packages cannot be empty"));
    }

    #[test]
    fn test_info_config_validation_empty_package_name() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = InfoConfig {
            manager: ManagerKind::Auto,
            packages: vec!["curl".to_string(), "".to_string()], // One empty package name
            include_dependencies: false,
            include_reverse_deps: false,
            include_files: false,
            include_repo: true,
            timeout_ms: 5000,
            extra_args: None,
            env: None,
        };
        
        let result = handle.validate_info_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("package name cannot be empty"));
    }

    #[test]
    fn test_info_config_validation_zero_timeout() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = InfoConfig {
            manager: ManagerKind::Auto,
            packages: vec!["curl".to_string()],
            include_dependencies: false,
            include_reverse_deps: false,
            include_files: false,
            include_repo: true,
            timeout_ms: 0, // Invalid timeout
            extra_args: None,
            env: None,
        };
        
        let result = handle.validate_info_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timeout_ms must be greater than 0"));
    }

    #[test]
    fn test_info_config_validation_empty_extra_args() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = InfoConfig {
            manager: ManagerKind::Auto,
            packages: vec!["curl".to_string()],
            include_dependencies: false,
            include_reverse_deps: false,
            include_files: false,
            include_repo: true,
            timeout_ms: 5000,
            extra_args: Some(vec!["--quiet".to_string(), "".to_string()]), // Empty argument
            env: None,
        };
        
        let result = handle.validate_info_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("extra_args cannot contain empty strings"));
    }

    #[test]
    fn test_info_config_validation_valid() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = InfoConfig {
            manager: ManagerKind::Apt,
            packages: vec!["curl".to_string(), "git".to_string()],
            include_dependencies: true,
            include_reverse_deps: true,
            include_files: true,
            include_repo: true,
            timeout_ms: 5000,
            extra_args: Some(vec!["--quiet".to_string()]),
            env: Some([("DEBIAN_FRONTEND".to_string(), "noninteractive".to_string())].into_iter().collect()),
        };
        
        let result = handle.validate_info_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_apt_dependencies_parsing() {
        let handle = PkgHandle { alias: "test".to_string() };
        let line = "Depends: libc6 (>= 2.27), libssl1.1 (>= 1.1.1), zlib1g (>= 1:1.1.4)";
        let deps = handle.parse_apt_dependencies(line);
        
        assert_eq!(deps.len(), 3);
        assert!(deps.contains(&"libc6".to_string()));
        assert!(deps.contains(&"libssl1.1".to_string()));
        assert!(deps.contains(&"zlib1g".to_string()));
    }

    #[test]
    fn test_pacman_dependencies_parsing() {
        let handle = PkgHandle { alias: "test".to_string() };
        let line = "glibc>=2.31 openssl>=1.1.1 zlib";
        let deps = handle.parse_pacman_dependencies(line);
        
        assert_eq!(deps.len(), 3);
        assert!(deps.contains(&"glibc".to_string()));
        assert!(deps.contains(&"openssl".to_string()));
        assert!(deps.contains(&"zlib".to_string()));
    }

    #[test]
    fn test_pacman_dependencies_parsing_none() {
        let handle = PkgHandle { alias: "test".to_string() };
        let line = "None";
        let deps = handle.parse_pacman_dependencies(line);
        
        assert!(deps.is_empty());
    }

    // Search configuration validation tests

    #[test]
    fn test_search_config_validation_valid() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = SearchConfig {
            manager: ManagerKind::Apt,
            query: "curl".to_string(),
            search_in: vec![SearchField::Name, SearchField::Description],
            exact: false,
            case_sensitive: false,
            limit: 50,
            offset: 0,
            include_installed: true,
            include_versions: true,
            include_repo: true,
            timeout_ms: 5000,
            extra_args: None,
            env: None,
        };
        
        let result = handle.validate_search_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_search_config_validation_empty_query() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = SearchConfig {
            manager: ManagerKind::Apt,
            query: "".to_string(),
            search_in: vec![SearchField::Name],
            exact: false,
            case_sensitive: false,
            limit: 50,
            offset: 0,
            include_installed: true,
            include_versions: true,
            include_repo: true,
            timeout_ms: 5000,
            extra_args: None,
            env: None,
        };
        
        let result = handle.validate_search_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Query cannot be empty"));
    }

    #[test]
    fn test_search_config_validation_zero_timeout() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = SearchConfig {
            manager: ManagerKind::Apt,
            query: "curl".to_string(),
            search_in: vec![SearchField::Name],
            exact: false,
            case_sensitive: false,
            limit: 50,
            offset: 0,
            include_installed: true,
            include_versions: true,
            include_repo: true,
            timeout_ms: 0,
            extra_args: None,
            env: None,
        };
        
        let result = handle.validate_search_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Timeout must be greater than 0"));
    }

    #[test]
    fn test_search_config_validation_zero_limit() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = SearchConfig {
            manager: ManagerKind::Apt,
            query: "curl".to_string(),
            search_in: vec![SearchField::Name],
            exact: false,
            case_sensitive: false,
            limit: 0,
            offset: 0,
            include_installed: true,
            include_versions: true,
            include_repo: true,
            timeout_ms: 5000,
            extra_args: None,
            env: None,
        };
        
        let result = handle.validate_search_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Limit must be greater than 0"));
    }

    // Search scoring tests

    #[test]
    fn test_calculate_search_score_exact_match() {
        let handle = PkgHandle { alias: "test".to_string() };
        let result = SearchResult {
            name: "curl".to_string(),
            version: Some("7.68.0".to_string()),
            installed: true,
            summary: Some("command line tool for transferring data".to_string()),
            description: None,
            repository: None,
            homepage: None,
            score: 0.0,
        };
        
        let score = handle.calculate_search_score(&result, "curl", false);
        assert_eq!(score, 1.0);
    }

    #[test]
    fn test_calculate_search_score_starts_with() {
        let handle = PkgHandle { alias: "test".to_string() };
        let result = SearchResult {
            name: "curl-dev".to_string(),
            version: Some("7.68.0".to_string()),
            installed: false,
            summary: Some("development files for curl".to_string()),
            description: None,
            repository: None,
            homepage: None,
            score: 0.0,
        };
        
        let score = handle.calculate_search_score(&result, "curl", false);
        assert_eq!(score, 0.9);
    }

    #[test]
    fn test_calculate_search_score_contains() {
        let handle = PkgHandle { alias: "test".to_string() };
        let result = SearchResult {
            name: "libcurl4".to_string(),
            version: Some("7.68.0".to_string()),
            installed: false,
            summary: Some("library for transferring data".to_string()),
            description: None,
            repository: None,
            homepage: None,
            score: 0.0,
        };
        
        let score = handle.calculate_search_score(&result, "curl", false);
        assert_eq!(score, 0.7);
    }

    #[test]
    fn test_calculate_search_score_description_match() {
        let handle = PkgHandle { alias: "test".to_string() };
        let result = SearchResult {
            name: "wget".to_string(),
            version: Some("1.20.3".to_string()),
            installed: false,
            summary: Some("retrieves files from the web using curl-like protocol".to_string()),
            description: None,
            repository: None,
            homepage: None,
            score: 0.0,
        };
        
        let score = handle.calculate_search_score(&result, "curl", false);
        assert_eq!(score, 0.5);
    }

    #[test]
    fn test_calculate_search_score_case_sensitive() {
        let handle = PkgHandle { alias: "test".to_string() };
        let result = SearchResult {
            name: "CURL".to_string(),
            version: Some("7.68.0".to_string()),
            installed: true,
            summary: Some("command line tool".to_string()),
            description: None,
            repository: None,
            homepage: None,
            score: 0.0,
        };
        
        let score = handle.calculate_search_score(&result, "curl", true);
        assert_eq!(score, 0.1); // Should not match exactly due to case sensitivity
        
        let score_exact = handle.calculate_search_score(&result, "CURL", true);
        assert_eq!(score_exact, 1.0); // Should match exactly
    }

    // Search filter tests

    #[test]
    fn test_filter_and_sort_results_exact_match() {
        let handle = PkgHandle { alias: "test".to_string() };
        let results = vec![
            SearchResult {
                name: "curl".to_string(),
                version: Some("7.68.0".to_string()),
                installed: true,
                summary: Some("command line tool".to_string()),
                description: None,
                repository: None,
                homepage: None,
                score: 0.0,
            },
            SearchResult {
                name: "curl-dev".to_string(),
                version: Some("7.68.0".to_string()),
                installed: false,
                summary: Some("development files".to_string()),
                description: None,
                repository: None,
                homepage: None,
                score: 0.0,
            },
        ];
        
        let config = SearchConfig {
            manager: ManagerKind::Apt,
            query: "curl".to_string(),
            search_in: vec![SearchField::Name],
            exact: true,
            case_sensitive: false,
            limit: 50,
            offset: 0,
            include_installed: true,
            include_versions: true,
            include_repo: true,
            timeout_ms: 5000,
            extra_args: None,
            env: None,
        };
        
        let filtered = handle.filter_and_sort_results(results, &config);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "curl");
    }

    #[test]
    fn test_filter_and_sort_results_fuzzy_match() {
        let handle = PkgHandle { alias: "test".to_string() };
        let results = vec![
            SearchResult {
                name: "curl-dev".to_string(),
                version: Some("7.68.0".to_string()),
                installed: false,
                summary: Some("development files".to_string()),
                description: None,
                repository: None,
                homepage: None,
                score: 0.0,
            },
            SearchResult {
                name: "curl".to_string(),
                version: Some("7.68.0".to_string()),
                installed: true,
                summary: Some("command line tool".to_string()),
                description: None,
                repository: None,
                homepage: None,
                score: 0.0,
            },
            SearchResult {
                name: "libcurl4".to_string(),
                version: Some("7.68.0".to_string()),
                installed: false,
                summary: Some("library for transferring data".to_string()),
                description: None,
                repository: None,
                homepage: None,
                score: 0.0,
            },
        ];
        
        let config = SearchConfig {
            manager: ManagerKind::Apt,
            query: "curl".to_string(),
            search_in: vec![SearchField::Name],
            exact: false,
            case_sensitive: false,
            limit: 50,
            offset: 0,
            include_installed: true,
            include_versions: true,
            include_repo: true,
            timeout_ms: 5000,
            extra_args: None,
            env: None,
        };
        
        let filtered = handle.filter_and_sort_results(results, &config);
        assert_eq!(filtered.len(), 3);
        // Results should be sorted by score: exact match first, then starts with, then contains
        assert_eq!(filtered[0].name, "curl");      // score: 1.0
        assert_eq!(filtered[1].name, "curl-dev");  // score: 0.9
        assert_eq!(filtered[2].name, "libcurl4");  // score: 0.7
    }

    #[test]
    fn test_filter_and_sort_results_description_only() {
        let handle = PkgHandle { alias: "test".to_string() };
        let results = vec![
            SearchResult {
                name: "wget".to_string(),
                version: Some("1.20.3".to_string()),
                installed: false,
                summary: Some("retrieves files from web using http protocol".to_string()),
                description: None,
                repository: None,
                homepage: None,
                score: 0.0,
            },
            SearchResult {
                name: "curl".to_string(),
                version: Some("7.68.0".to_string()),
                installed: true,
                summary: Some("command line tool".to_string()),
                description: None,
                repository: None,
                homepage: None,
                score: 0.0,
            },
        ];
        
        let config = SearchConfig {
            manager: ManagerKind::Apt,
            query: "http".to_string(),
            search_in: vec![SearchField::Description],
            exact: false,
            case_sensitive: false,
            limit: 50,
            offset: 0,
            include_installed: true,
            include_versions: true,
            include_repo: true,
            timeout_ms: 5000,
            extra_args: None,
            env: None,
        };
        
        let filtered = handle.filter_and_sort_results(results, &config);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "wget");
    }

    // ===============================
    // SNAPSHOT TESTS
    // ===============================

    #[test]
    fn test_snapshot_config_validation_invalid_timeout() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = SnapshotConfig {
            manager: ManagerKind::Auto,
            scope: SnapshotScope::All,
            include_versions: SnapshotVersionMode::Exact,
            include_repo: true,
            include_arch: true,
            include_install_reason: true,
            include_os_metadata: true,
            exclude_patterns: vec![],
            format: SnapshotFormat::Json,
            inline: true,
            timeout_ms: 0, // Invalid
            extra_args: None,
            env: None,
        };
        
        let result = handle.validate_snapshot_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timeout_ms must be greater than 0"));
    }

    #[test]
    fn test_snapshot_config_validation_valid() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = SnapshotConfig {
            manager: ManagerKind::Apt,
            scope: SnapshotScope::All,
            include_versions: SnapshotVersionMode::Exact,
            include_repo: true,
            include_arch: true,
            include_install_reason: true,
            include_os_metadata: true,
            exclude_patterns: vec![],
            format: SnapshotFormat::Json,
            inline: true,
            timeout_ms: 15000,
            extra_args: None,
            env: None,
        };
        
        let result = handle.validate_snapshot_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_snapshot_config_validation_invalid_extra_args() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = SnapshotConfig {
            manager: ManagerKind::Apt,
            scope: SnapshotScope::All,
            include_versions: SnapshotVersionMode::Exact,
            include_repo: true,
            include_arch: true,
            include_install_reason: true,
            include_os_metadata: true,
            exclude_patterns: vec![],
            format: SnapshotFormat::Json,
            inline: true,
            timeout_ms: 15000,
            extra_args: Some(vec!["valid".to_string(), "".to_string()]), // Empty string invalid
            env: None,
        };
        
        let result = handle.validate_snapshot_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("extra_args cannot contain empty strings"));
    }

    #[test]
    fn test_filter_snapshot_packages_all() {
        let handle = PkgHandle { alias: "test".to_string() };
        let mut packages = vec![
            LockfilePackage {
                name: "curl".to_string(),
                version: Some("7.68.0".to_string()),
                version_spec: None,
                architecture: Some("amd64".to_string()),
                repository: Some("ubuntu-focal/main".to_string()),
                install_reason: Some("manual".to_string()),
                pinned: false,
            },
            LockfilePackage {
                name: "libcurl4".to_string(),
                version: Some("7.68.0".to_string()),
                version_spec: None,
                architecture: Some("amd64".to_string()),
                repository: Some("ubuntu-focal/main".to_string()),
                install_reason: Some("dependency".to_string()),
                pinned: false,
            }
        ];

        let config = SnapshotConfig {
            manager: ManagerKind::Apt,
            scope: SnapshotScope::All,
            include_versions: SnapshotVersionMode::Exact,
            include_repo: true,
            include_arch: true,
            include_install_reason: true,
            include_os_metadata: true,
            exclude_patterns: vec![],
            format: SnapshotFormat::Json,
            inline: true,
            timeout_ms: 15000,
            extra_args: None,
            env: None,
        };

        let result = handle.filter_snapshot_packages(&mut packages, &config);
        assert!(result.is_ok());
        assert_eq!(packages.len(), 2); // Both packages should remain
    }

    #[test]
    fn test_filter_snapshot_packages_manual_only() {
        let handle = PkgHandle { alias: "test".to_string() };
        let mut packages = vec![
            LockfilePackage {
                name: "curl".to_string(),
                version: Some("7.68.0".to_string()),
                version_spec: None,
                architecture: Some("amd64".to_string()),
                repository: Some("ubuntu-focal/main".to_string()),
                install_reason: Some("manual".to_string()),
                pinned: false,
            },
            LockfilePackage {
                name: "libcurl4".to_string(),
                version: Some("7.68.0".to_string()),
                version_spec: None,
                architecture: Some("amd64".to_string()),
                repository: Some("ubuntu-focal/main".to_string()),
                install_reason: Some("dependency".to_string()),
                pinned: false,
            }
        ];

        let config = SnapshotConfig {
            manager: ManagerKind::Apt,
            scope: SnapshotScope::Manual,
            include_versions: SnapshotVersionMode::Exact,
            include_repo: true,
            include_arch: true,
            include_install_reason: true,
            include_os_metadata: true,
            exclude_patterns: vec![],
            format: SnapshotFormat::Json,
            inline: true,
            timeout_ms: 15000,
            extra_args: None,
            env: None,
        };

        let result = handle.filter_snapshot_packages(&mut packages, &config);
        assert!(result.is_ok());
        assert_eq!(packages.len(), 1); // Only manual package should remain
        assert_eq!(packages[0].name, "curl");
    }

    #[test]
    fn test_apply_exclude_patterns() {
        let handle = PkgHandle { alias: "test".to_string() };
        let mut packages = vec![
            LockfilePackage {
                name: "linux-image-generic".to_string(),
                version: Some("5.15.0".to_string()),
                version_spec: None,
                architecture: Some("amd64".to_string()),
                repository: None,
                install_reason: None,
                pinned: false,
            },
            LockfilePackage {
                name: "curl".to_string(),
                version: Some("7.68.0".to_string()),
                version_spec: None,
                architecture: Some("amd64".to_string()),
                repository: None,
                install_reason: None,
                pinned: false,
            },
            LockfilePackage {
                name: "wget".to_string(),
                version: Some("1.20.3".to_string()),
                version_spec: None,
                architecture: Some("amd64".to_string()),
                repository: None,
                install_reason: None,
                pinned: false,
            }
        ];

        let patterns = vec!["linux-*".to_string()];
        handle.apply_exclude_patterns(&mut packages, &patterns);
        
        assert_eq!(packages.len(), 2); // linux-image-generic should be excluded
        assert!(packages.iter().any(|p| p.name == "curl"));
        assert!(packages.iter().any(|p| p.name == "wget"));
        assert!(!packages.iter().any(|p| p.name.starts_with("linux")));
    }

    #[test]
    fn test_serialize_lockfile_text() {
        let handle = PkgHandle { alias: "test".to_string() };
        let lockfile = Lockfile {
            lockfile_version: "pkg-lock/v1".to_string(),
            generated_at: "2025-02-21T14:35:00Z".to_string(),
            manager: ManagerInfo {
                name: "apt".to_string(),
                alias: "system".to_string(),
                version: Some("2.4.10".to_string()),
                config: None,
            },
            platform: PlatformInfo {
                os_family: Some("debian".to_string()),
                os_name: Some("Ubuntu".to_string()),
                os_version: Some("22.04".to_string()),
                kernel: Some("Linux 5.15.0-94-generic".to_string()),
                architecture: Some("x86_64".to_string()),
            },
            scope: "all".to_string(),
            packages: vec![
                LockfilePackage {
                    name: "curl".to_string(),
                    version: Some("7.68.0-1ubuntu2.19".to_string()),
                    version_spec: None,
                    architecture: Some("amd64".to_string()),
                    repository: Some("ubuntu-focal/main".to_string()),
                    install_reason: Some("manual".to_string()),
                    pinned: false,
                }
            ],
        };

        let result = handle.serialize_lockfile_text(&lockfile);
        assert!(result.is_ok());
        
        let text = result.unwrap();
        assert!(text.contains("# pkg-lock/v1"));
        assert!(text.contains("manager: apt (2.4.10)"));
        assert!(text.contains("os: Ubuntu 22.04 (x86_64)"));
        assert!(text.contains("scope: all"));
        assert!(text.contains("curl=7.68.0-1ubuntu2.19 [amd64] @ubuntu-focal/main (manual)"));
    }

    #[test]
    fn test_determine_os_family() {
        let handle = PkgHandle { alias: "test".to_string() };
        
        // Test async function in sync context by creating a simple runtime
        let rt = tokio::runtime::Runtime::new().unwrap();
        
        // Test Ubuntu -> debian
        let ubuntu_result = rt.block_on(handle.determine_os_family(&Some("Ubuntu 22.04".to_string())));
        assert_eq!(ubuntu_result, Some("debian".to_string()));
        
        // Test Fedora -> rhel
        let fedora_result = rt.block_on(handle.determine_os_family(&Some("Fedora 38".to_string())));
        assert_eq!(fedora_result, Some("rhel".to_string()));
        
        // Test Arch -> arch
        let arch_result = rt.block_on(handle.determine_os_family(&Some("Arch Linux".to_string())));
        assert_eq!(arch_result, Some("arch".to_string()));
        
        // Test Alpine -> alpine
        let alpine_result = rt.block_on(handle.determine_os_family(&Some("Alpine Linux".to_string())));
        assert_eq!(alpine_result, Some("alpine".to_string()));
        
        // Test unknown -> None
        let unknown_result = rt.block_on(handle.determine_os_family(&Some("Unknown OS".to_string())));
        assert_eq!(unknown_result, None);
    }

    // ===============================
    // Restore (apply_lock) tests
    // ===============================

    #[test]
    fn test_restore_config_validation_empty_lockfile() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = RestoreConfig {
            manager: ManagerKind::Auto,
            lockfile: "".to_string(),
            format: LockfileFormat::Auto,
            mode: RestoreMode::Exact,
            allow_downgrades: false,
            allow_removals: false,
            allow_newer: true,
            on_missing_package: MissingPolicy::Fail,
            on_repo_mismatch: RepoPolicy::Warn,
            on_platform_mismatch: PlatformPolicy::Warn,
            include_dependencies: true,
            dry_run: false,
            timeout_ms: 180000,
            extra_args: None,
            env: None,
        };
        
        let result = handle.validate_restore_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("lockfile content cannot be empty"));
    }

    #[test]
    fn test_restore_config_validation_invalid_timeout() {
        let handle = PkgHandle { alias: "test".to_string() };
        let config = RestoreConfig {
            manager: ManagerKind::Auto,
            lockfile: "test content".to_string(),
            format: LockfileFormat::Auto,
            mode: RestoreMode::Exact,
            allow_downgrades: false,
            allow_removals: false,
            allow_newer: true,
            on_missing_package: MissingPolicy::Fail,
            on_repo_mismatch: RepoPolicy::Warn,
            on_platform_mismatch: PlatformPolicy::Warn,
            include_dependencies: true,
            dry_run: false,
            timeout_ms: 0, // Invalid
            extra_args: None,
            env: None,
        };
        
        let result = handle.validate_restore_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timeout_ms must be greater than 0"));
    }

    #[test]
    fn test_parse_json_lockfile() {
        let handle = PkgHandle { alias: "test".to_string() };
        let lockfile_json = json!({
            "lockfile_version": "pkg-lock/v1",
            "generated_at": "2023-01-01T00:00:00Z",
            "manager": {
                "name": "apt",
                "alias": "system",
                "version": "2.0.0",
                "config": null
            },
            "platform": {
                "os_family": "debian",
                "os_name": "Ubuntu",
                "os_version": "20.04",
                "kernel": "5.4.0",
                "architecture": "x86_64"
            },
            "scope": "all",
            "packages": [
                {
                    "name": "curl",
                    "version": "7.68.0-1ubuntu2.19",
                    "architecture": "amd64",
                    "repository": "ubuntu-focal/main",
                    "install_reason": "manual",
                    "pinned": false
                }
            ]
        }).to_string();

        let result = handle.parse_lockfile(&lockfile_json, &LockfileFormat::Json);
        assert!(result.is_ok());
        
        let lockfile = result.unwrap();
        assert_eq!(lockfile.lockfile_version, "pkg-lock/v1");
        assert_eq!(lockfile.manager.name, "apt");
        assert_eq!(lockfile.packages.len(), 1);
        assert_eq!(lockfile.packages[0].name, "curl");
    }

    #[test]
    fn test_parse_text_lockfile() {
        let handle = PkgHandle { alias: "test".to_string() };
        let lockfile_text = "curl=7.68.0-1ubuntu2.19\ngit\nvim=8.2.0716-3ubuntu2";

        let result = handle.parse_lockfile(lockfile_text, &LockfileFormat::Text);
        assert!(result.is_ok());
        
        let lockfile = result.unwrap();
        assert_eq!(lockfile.packages.len(), 3);
        assert_eq!(lockfile.packages[0].name, "curl");
        assert_eq!(lockfile.packages[0].version, Some("7.68.0-1ubuntu2.19".to_string()));
        assert_eq!(lockfile.packages[1].name, "git");
        assert_eq!(lockfile.packages[1].version, None);
        assert_eq!(lockfile.packages[2].name, "vim");
        assert_eq!(lockfile.packages[2].version, Some("8.2.0716-3ubuntu2".to_string()));
    }

    #[test]
    fn test_restore_manager_resolution() {
        let handle = PkgHandle { alias: "test".to_string() };
        let lockfile = Lockfile {
            lockfile_version: "pkg-lock/v1".to_string(),
            generated_at: "2023-01-01T00:00:00Z".to_string(),
            manager: ManagerInfo {
                name: "apt".to_string(),
                alias: "system".to_string(),
                version: None,
                config: None,
            },
            platform: PlatformInfo {
                os_family: None,
                os_name: None,
                os_version: None,
                kernel: None,
                architecture: None,
            },
            scope: "all".to_string(),
            packages: vec![],
        };

        // Test auto resolution
        let result = handle.resolve_restore_manager(&ManagerKind::Auto, &lockfile);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ManagerKind::Apt);

        // Test compatible explicit manager
        let result = handle.resolve_restore_manager(&ManagerKind::Apt, &lockfile);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ManagerKind::Apt);

        // Test incompatible manager
        let result = handle.resolve_restore_manager(&ManagerKind::Pacman, &lockfile);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not match"));
    }

    #[test] 
    fn test_compute_restore_plan() {
        let handle = PkgHandle { alias: "test".to_string() };
        let lockfile = Lockfile {
            lockfile_version: "pkg-lock/v1".to_string(),
            generated_at: "2023-01-01T00:00:00Z".to_string(),
            manager: ManagerInfo {
                name: "apt".to_string(),
                alias: "system".to_string(),
                version: None,
                config: None,
            },
            platform: PlatformInfo {
                os_family: None,
                os_name: None,
                os_version: None,
                kernel: None,
                architecture: None,
            },
            scope: "all".to_string(),
            packages: vec![
                LockfilePackage {
                    name: "curl".to_string(),
                    version: Some("7.68.0".to_string()),
                    version_spec: None,
                    architecture: None,
                    repository: None,
                    install_reason: None,
                    pinned: false,
                },
                LockfilePackage {
                    name: "git".to_string(),
                    version: Some("2.34.1".to_string()),
                    version_spec: None,
                    architecture: None,
                    repository: None,
                    install_reason: None,
                    pinned: false,
                },
                LockfilePackage {
                    name: "vim".to_string(),
                    version: Some("8.2.0".to_string()),
                    version_spec: None,
                    architecture: None,
                    repository: None,
                    install_reason: None,
                    pinned: false,
                },
            ],
        };

        let current_packages = vec![
            InstalledPackage {
                name: "curl".to_string(),
                version: "7.68.0".to_string(), // Same version
                architecture: None,
                repository: None,
                installed_size_bytes: None,
                install_reason: None,
                manager_specific: None,
            },
            InstalledPackage {
                name: "git".to_string(),
                version: "2.30.0".to_string(), // Older version
                architecture: None,
                repository: None,
                installed_size_bytes: None,
                install_reason: None,
                manager_specific: None,
            },
            InstalledPackage {
                name: "htop".to_string(), // Extra package not in lockfile
                version: "3.0.0".to_string(),
                architecture: None,
                repository: None,
                installed_size_bytes: None,
                install_reason: None,
                manager_specific: None,
            },
        ];

        let config = RestoreConfig {
            manager: ManagerKind::Apt,
            lockfile: "".to_string(),
            format: LockfileFormat::Json,
            mode: RestoreMode::Exact,
            allow_downgrades: false,
            allow_removals: true,
            allow_newer: true,
            on_missing_package: MissingPolicy::Fail,
            on_repo_mismatch: RepoPolicy::Warn,
            on_platform_mismatch: PlatformPolicy::Warn,
            include_dependencies: true,
            dry_run: false,
            timeout_ms: 180000,
            extra_args: None,
            env: None,
        };

        let result = handle.compute_restore_plan(&lockfile, &current_packages, &config);
        assert!(result.is_ok());
        
        let plan = result.unwrap();
        
        // vim should be installed (missing)
        assert_eq!(plan.install.len(), 1);
        assert!(plan.install.contains(&"vim".to_string()));
        
        // git should be upgraded (older version)
        assert_eq!(plan.upgrade.len(), 1);
        assert!(plan.upgrade.contains(&"git".to_string()));
        
        // curl should be kept (same version)
        assert_eq!(plan.keep.len(), 1);
        assert!(plan.keep.contains(&"curl".to_string()));
        
        // htop should be removed (extra package, allow_removals=true)
        assert_eq!(plan.remove.len(), 1);
        assert!(plan.remove.contains(&"htop".to_string()));
        
        assert_eq!(plan.downgrade.len(), 0);
        assert_eq!(plan.extra.len(), 0);
        assert_eq!(plan.unresolved.len(), 0);
    }

    #[test]
    fn test_generate_restore_commands_apt() {
        let handle = PkgHandle { alias: "test".to_string() };
        let plan = RestorePlan {
            install: vec!["curl".to_string(), "git".to_string()],
            upgrade: vec!["vim".to_string()],
            downgrade: vec!["nginx".to_string()],
            remove: vec!["htop".to_string()],
            keep: vec!["bash".to_string()],
            extra: vec![],
            unresolved: vec![],
        };

        let config = RestoreConfig {
            manager: ManagerKind::Apt,
            lockfile: "".to_string(),
            format: LockfileFormat::Json,
            mode: RestoreMode::Exact,
            allow_downgrades: true,
            allow_removals: true,
            allow_newer: true,
            on_missing_package: MissingPolicy::Fail,
            on_repo_mismatch: RepoPolicy::Warn,
            on_platform_mismatch: PlatformPolicy::Warn,
            include_dependencies: true,
            dry_run: true,
            timeout_ms: 180000,
            extra_args: None,
            env: None,
        };

        let commands = handle.generate_restore_commands(&plan, &ManagerKind::Apt, &config);
        
        // Should have install/upgrade command, downgrade command, and remove command
        assert!(commands.len() >= 2);
        
        // Check install/upgrade command
        let install_cmd = &commands[0];
        assert!(install_cmd.starts_with("apt-get install -y"));
        assert!(install_cmd.contains("curl"));
        assert!(install_cmd.contains("git"));
        assert!(install_cmd.contains("vim"));
        
        // Check for downgrade command
        let downgrade_cmd = commands.iter().find(|c| c.contains("--allow-downgrades"));
        assert!(downgrade_cmd.is_some());
        assert!(downgrade_cmd.unwrap().contains("nginx"));
        
        // Check for remove command
        let remove_cmd = commands.iter().find(|c| c.contains("apt-get remove"));
        assert!(remove_cmd.is_some());
        assert!(remove_cmd.unwrap().contains("htop"));
    }

    // Platform detection tests
    #[test]
    fn test_detect_os_family() {
        let os_family = detect_os_family();
        // Should return one of the known OS families or "unknown"
        assert!(
            os_family == "linux" ||
            os_family == "darwin" ||
            os_family == "windows" ||
            os_family == "freebsd" ||
            os_family == "openbsd" ||
            os_family == "netbsd" ||
            os_family == "unknown",
            "Unexpected OS family: {}",
            os_family
        );

        // On Linux systems, should return "linux"
        #[cfg(target_os = "linux")]
        assert_eq!(os_family, "linux", "Expected linux OS family");

        // On macOS, should return "darwin"
        #[cfg(target_os = "macos")]
        assert_eq!(os_family, "darwin", "Expected darwin OS family");

        // On Windows, should return "windows"
        #[cfg(target_os = "windows")]
        assert_eq!(os_family, "windows", "Expected windows OS family");
    }

    #[test]
    fn test_detect_architecture() {
        let arch = detect_architecture();
        // Should return one of the known architectures or "unknown"
        assert!(
            arch == "x86_64" ||
            arch == "x86" ||
            arch == "aarch64" ||
            arch == "arm" ||
            arch == "riscv64" ||
            arch == "powerpc64" ||
            arch == "s390x" ||
            arch == "unknown",
            "Unexpected architecture: {}",
            arch
        );

        // Most modern systems are x86_64 or aarch64
        #[cfg(target_arch = "x86_64")]
        assert_eq!(arch, "x86_64", "Expected x86_64 architecture");

        #[cfg(target_arch = "aarch64")]
        assert_eq!(arch, "aarch64", "Expected aarch64 architecture");
    }

    #[tokio::test]
    async fn test_detect_os_name_and_version() {
        let result = detect_os_name_and_version().await;
        assert!(result.is_ok(), "detect_os_name_and_version should not error");

        let (os_name, os_version) = result.unwrap();

        // On Linux, we should at least get an OS name
        #[cfg(target_os = "linux")]
        {
            assert!(os_name.is_some(), "Linux should have an OS name");
            let name = os_name.unwrap();
            assert!(!name.is_empty(), "OS name should not be empty");
        }

        // On macOS, we should get "macOS"
        #[cfg(target_os = "macos")]
        {
            assert!(os_name.is_some(), "macOS should have an OS name");
            assert_eq!(os_name.unwrap(), "macOS", "Expected macOS name");
            // Version is optional but usually available
        }

        // On Windows, we should get "Windows"
        #[cfg(target_os = "windows")]
        {
            assert!(os_name.is_some(), "Windows should have an OS name");
            assert_eq!(os_name.unwrap(), "Windows", "Expected Windows name");
        }
    }

    #[tokio::test]
    async fn test_detect_kernel_version() {
        let kernel = detect_kernel_version().await;

        // On Unix-like systems, kernel version should be available
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
        {
            // Kernel version might not be available in all test environments
            // but if it is, it should not be empty
            if let Some(version) = kernel {
                assert!(!version.is_empty(), "Kernel version should not be empty");
                // Should contain at least one digit
                assert!(version.chars().any(|c| c.is_ascii_digit()), "Kernel version should contain digits");
            }
        }
    }

    #[test]
    fn test_platform_info_structure() {
        let platform = PlatformInfo {
            os_family: Some("linux".to_string()),
            os_name: Some("Ubuntu".to_string()),
            os_version: Some("22.04".to_string()),
            kernel: Some("5.15.0-76-generic".to_string()),
            architecture: Some("x86_64".to_string()),
        };

        assert_eq!(platform.os_family.unwrap(), "linux");
        assert_eq!(platform.os_name.unwrap(), "Ubuntu");
        assert_eq!(platform.os_version.unwrap(), "22.04");
        assert_eq!(platform.kernel.unwrap(), "5.15.0-76-generic");
        assert_eq!(platform.architecture.unwrap(), "x86_64");
    }

    #[test]
    fn test_platform_info_optional_fields() {
        let platform = PlatformInfo {
            os_family: Some("linux".to_string()),
            os_name: None,
            os_version: None,
            kernel: None,
            architecture: Some("x86_64".to_string()),
        };

        assert!(platform.os_family.is_some());
        assert!(platform.os_name.is_none());
        assert!(platform.os_version.is_none());
        assert!(platform.kernel.is_none());
        assert!(platform.architecture.is_some());
    }

    #[test]
    fn test_platform_info_serialization() {
        let platform = PlatformInfo {
            os_family: Some("linux".to_string()),
            os_name: Some("Debian".to_string()),
            os_version: Some("11".to_string()),
            kernel: Some("5.10.0".to_string()),
            architecture: Some("x86_64".to_string()),
        };

        // Test JSON serialization
        let json = serde_json::to_value(&platform).unwrap();
        assert_eq!(json["os_family"], "linux");
        assert_eq!(json["os_name"], "Debian");
        assert_eq!(json["os_version"], "11");
        assert_eq!(json["kernel"], "5.10.0");
        assert_eq!(json["architecture"], "x86_64");

        // Test deserialization
        let deserialized: PlatformInfo = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.os_family, Some("linux".to_string()));
        assert_eq!(deserialized.os_name, Some("Debian".to_string()));
        assert_eq!(deserialized.os_version, Some("11".to_string()));
        assert_eq!(deserialized.kernel, Some("5.10.0".to_string()));
        assert_eq!(deserialized.architecture, Some("x86_64".to_string()));
    }

    #[test]
    fn test_platform_info_clone() {
        let platform = PlatformInfo {
            os_family: Some("darwin".to_string()),
            os_name: Some("macOS".to_string()),
            os_version: Some("13.0".to_string()),
            kernel: Some("22.1.0".to_string()),
            architecture: Some("aarch64".to_string()),
        };

        let cloned = platform.clone();
        assert_eq!(cloned.os_family, platform.os_family);
        assert_eq!(cloned.os_name, platform.os_name);
        assert_eq!(cloned.os_version, platform.os_version);
        assert_eq!(cloned.kernel, platform.kernel);
        assert_eq!(cloned.architecture, platform.architecture);
    }
}