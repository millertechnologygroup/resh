use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use std::io::Write;
use thiserror::Error;
use tokio::process::Command as AsyncCommand;
use tokio::time::timeout;
use url::Url;

use crate::core::{
    registry::{Args, Handle, IoStreams},
    status::Status,
};

/// Filesystem handle for mounting operations
#[derive(Debug)]
pub struct FsHandle {
    alias: String,
}

/// Mount configuration structure
#[derive(Debug, Clone, Deserialize)]
pub struct MountConfig {
    pub source: Option<String>,
    pub target: String,
    pub r#type: Option<String>,
    pub options: Vec<String>,
    pub read_only: bool,
    pub bind: bool,
    pub create_target: bool,
    pub make_parents: bool,
    pub fail_if_mounted: bool,
    pub remount: bool,
    pub network: bool,
    pub timeout_ms: u64,
    pub dry_run: bool,
    pub env: Option<HashMap<String, String>>,
}

/// Information about an existing mount
#[derive(Debug, Clone)]
pub struct ExistingMount {
    pub source: String,
    pub target: String,
    pub fs_type: String,
    pub options: Vec<String>,
}

/// Mount operation result
#[derive(Debug, Serialize)]
pub struct MountResult {
    pub backend: String,
    pub verb: String,
    pub alias: String,
    pub source: Option<String>,
    pub target: String,
    pub r#type: Option<String>,
    pub options: Vec<String>,
    pub read_only: bool,
    pub bind: bool,
    pub remount: bool,
    pub action: String, // "mounted" | "remounted" | "already_mounted"
    pub created_target: bool,
    pub details: MountDetails,
    pub dry_run: Option<bool>,
    pub plan: Option<MountPlan>,
}

/// Details about the mount operation
#[derive(Debug, Serialize)]
pub struct MountDetails {
    pub device: Option<String>,
    pub fs_type: Option<String>,
    pub mount_flags: Vec<String>,
    pub from_existing: bool,
}

/// Plan for dry-run operations
#[derive(Debug, Serialize)]
pub struct MountPlan {
    pub create_directory: Vec<String>,
    pub mount_commands: Vec<String>,
}

/// Unmount configuration structure
#[derive(Debug, Clone, Deserialize)]
pub struct UnmountConfig {
    pub target: String,
    pub by: UnmountTargetKind,
    pub force: bool,
    pub lazy: bool,
    pub detach_children: bool,
    pub fail_if_not_mounted: bool,
    pub timeout_ms: u64,
    pub dry_run: bool,
    pub env: Option<HashMap<String, String>>,
}

/// How to interpret the target field
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UnmountTargetKind {
    Target,
    Source,
    Auto,
}

/// Unmount operation result
#[derive(Debug, Serialize)]
pub struct UnmountResult {
    pub backend: String,
    pub verb: String,
    pub alias: String,
    pub target: String,
    pub by: String,
    pub force: bool,
    pub lazy: bool,
    pub detach_children: bool,
    pub action: String, // "unmounted" | "already_unmounted" | "partially_unmounted"
    pub unmounted: Vec<MountInfo>,
    pub skipped: Vec<MountInfo>,
    pub errors: Vec<UnmountError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<UnmountPlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_mounts: Option<Vec<MountInfo>>,
}

/// Information about a mount
#[derive(Debug, Clone, Serialize)]
pub struct MountInfo {
    pub source: String,
    pub target: String,
    #[serde(rename = "type")]
    pub fs_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
}

/// Unmount error information
#[derive(Debug, Serialize)]
pub struct UnmountError {
    pub target: String,
    pub code: String,
    pub message: String,
}

/// Plan for dry-run unmount operations
#[derive(Debug, Serialize)]
pub struct UnmountPlan {
    pub order: Vec<String>,
    pub commands: Vec<String>,
}

/// Filesystem-specific errors
#[derive(Error, Debug)]
pub enum FsError {
    #[error("Invalid mount configuration: {0}")]
    InvalidMountConfig(String),
    #[error("Invalid unmount configuration: {0}")]
    InvalidUnmountConfig(String),
    #[error("Profile not found: {0}")]
    ProfileNotFound(String),
    #[error("Mount operations are not supported on this platform")]
    MountUnsupported,
    #[error("Unmount operations are not supported on this platform")]
    UnmountUnsupported,
    #[error("Permission denied for mount operation")]
    MountPermissionDenied,
    #[error("Permission denied for unmount operation")]
    UnmountPermissionDenied,
    #[error("Target already mounted: {0}")]
    AlreadyMounted(String),
    #[error("Conflicting mount at target: {0}")]
    ConflictingMount(String),
    #[error("Mount operation failed: {0}")]
    MountFailure(String),
    #[error("Unmount operation failed: {0}")]
    UnmountFailure(String),
    #[error("Mount operation timed out")]
    MountTimeout,
    #[error("Unmount operation timed out")]
    UnmountTimeout,
    #[error("Failed to create target directory: {0}")]
    TargetCreationFailed(String),
    #[error("Target is not mounted: {0}")]
    NotMounted(String),
    #[error("Target is busy and cannot be unmounted: {0}")]
    UnmountBusy(String),
    #[error("Unmount option not supported on this platform: {0}")]
    UnmountOptionUnsupported(String),
    #[error("Invalid snapshot configuration: {0}")]
    InvalidSnapshotConfig(String),
    #[error("Snapshot operations are not supported on this platform")]
    SnapshotUnsupported,
    #[error("Snapshot operation timed out")]
    SnapshotTimeout,
    #[error("Snapshot operation failed: {0}")]
    SnapshotFailed(String),
    #[error("Invalid quota configuration: {0}")]
    InvalidQuotaConfig(String),
    #[error("Quota operations are not supported on this platform")]
    QuotaUnsupported,
    #[error("Quotas are not enabled on the target filesystem: {0}")]
    QuotaNotEnabled(String),
    #[error("Quota subject not found: {0}")]
    QuotaSubjectNotFound(String),
    #[error("Quota operation timed out")]
    QuotaTimeout,
    #[error("Quota operation failed: {0}")]
    QuotaFailed(String),
    #[error("Invalid quota summary configuration: {0}")]
    InvalidQuotaSummaryConfig(String),
    #[error("Quota summary operations are not supported on this platform")]
    QuotaSummaryUnsupported,
    #[error("No filesystems with quotas enabled found")]
    QuotaSummaryNoQuotaFilesystems,
    #[error("Quota summary operation timed out")]
    QuotaSummaryTimeout,
    #[error("Quota summary operation failed: {0}")]
    QuotaSummaryFailed(String),
    #[error("Invalid usage configuration: {0}")]
    InvalidUsageConfig(String),
    #[error("Usage operations are not supported on this platform")]
    UsageUnsupported,
    #[error("Usage operation timed out")]
    UsageTimeout,
    #[error("Usage operation failed: {0}")]
    UsageFailed(String),
    #[error("Path not found: {0}")]
    PathNotFound(String),
    #[error("No filesystems selected after applying filters")]
    UsageNothingSelected,
    #[error("Invalid resize configuration: {0}")]
    InvalidResizeConfig(String),
    #[error("Resize target not found: {0}")]
    ResizeTargetNotFound(String),
    #[error("Resize operations are not supported for filesystem type: {0}")]
    ResizeUnsupportedFilesystem(String),
    #[error("Shrink operations are not allowed (allow_shrink=false)")]
    ResizeShrinkNotAllowed,
    #[error("Shrink operations are not supported for filesystem type: {0}")]
    ResizeShrinkNotSupportedForFilesystem(String),
    #[error("Shrink operations require the filesystem to be unmounted: {0}")]
    ResizeShrinkRequiresUnmount(String),
    #[error("Resize would violate minimum free space requirement")]
    ResizeWouldViolateMinFree,
    #[error("Target size exceeds device capacity")]
    ResizeTargetExceedsDevice,
    #[error("Invalid target size specified: {0}")]
    ResizeInvalidTargetSize(String),
    #[error("Volume management operations are not supported")]
    ResizeVolumeManagementUnsupported,
    #[error("Resize operation timed out")]
    ResizeTimeout,
    #[error("Resize operation failed: {0}")]
    ResizeFailed(String),
    #[error("Invalid check configuration: {0}")]
    InvalidCheckConfig(String),
    #[error("Check target not found: {0}")]
    CheckTargetNotFound(String),
    #[error("Check operations are not supported for filesystem type: {0}")]
    CheckUnsupportedFilesystem(String),
    #[error("Repair requested but allow_repair=false")]
    CheckRepairNotAllowed,
    #[error("Repair requires filesystem to be unmounted: {0}")]
    CheckRequiresUnmountForRepair(String),
    #[error("Check operations must be performed offline but filesystem is mounted: {0}")]
    CheckMustBeOffline(String),
    #[error("Check tool not available: {0}")]
    CheckToolNotAvailable(String),
    #[error("Check operation timed out")]
    CheckTimeout,
    #[error("Check operation failed: {0}")]
    CheckFailed(String),
    #[error("Invalid list-mounts configuration: {0}")]
    InvalidListMountsConfig(String),
    #[error("List-mounts operations are not supported on this platform")]
    ListMountsUnsupported,
    #[error("List-mounts operation timed out")]
    ListMountsTimeout,
    #[error("List-mounts operation failed: {0}")]
    ListMountsFailed(String),
}

impl Default for FsQuotaConfig {
    fn default() -> Self {
        Self {
            path: None,
            subject: None,
            subject_type: SubjectType::Auto,
            resolve_uid_gid: true,
            include_space: true,
            include_inodes: true,
            include_grace: true,
            all_subjects: false,
            units: QuotaUnits::Auto,
            timeout_ms: 5000,
            env: None,
        }
    }
}

impl Default for FsQuotaSummaryConfig {
    fn default() -> Self {
        Self {
            subject: None,
            subject_type: SubjectType::Auto,
            resolve_uid_gid: true,
            include_mountpoints: Vec::new(),
            exclude_mountpoints: Vec::new(),
            include_types: Vec::new(),
            exclude_types: Vec::new(),
            include_sources: Vec::new(),
            exclude_sources: Vec::new(),
            include_space: true,
            include_inodes: true,
            include_grace: true,
            all_subjects: false,
            units: QuotaUnits::Auto,
            timeout_ms: 8000,
            env: None,
        }
    }
}

impl Default for FsUsageConfig {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            mode: UsageMode::Mounts,
            include_mountpoints: Vec::new(),
            exclude_mountpoints: Vec::new(),
            include_types: Vec::new(),
            exclude_types: Vec::new(),
            include_sources: Vec::new(),
            exclude_sources: Vec::new(),
            include_inodes: true,
            include_readonly: true,
            normalize_paths: true,
            units: UsageUnits::Auto,
            human_readable: false,
            threshold_used_percent_min: None,
            threshold_used_percent_max: None,
            timeout_ms: 5000,
            env: None,
        }
    }
}

impl Default for FsResizeConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            by: ResizeTargetKind::Auto,
            size: None,
            delta: None,
            size_units: SizeUnits::Auto,
            mode: ResizeMode::Grow,
            allow_shrink: false,
            min_free_space_percent: 5.0,
            manage_underlying_volume: false,
            volume_resize_only: false,
            filesystem_resize_only: false,
            require_unmounted_for_shrink: true,
            force: false,
            dry_run: false,
            timeout_ms: 600000, // 10 minutes
            env: None,
        }
    }
}

/// Check configuration structure
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FsCheckConfig {
    pub target: String,
    pub by: CheckTargetKind,
    pub filesystem_type: Option<String>,
    pub mode: CheckMode,
    pub aggressiveness: CheckAggressiveness,
    pub allow_repair: bool,
    pub allow_online_check: bool,
    pub require_unmounted_for_repair: bool,
    pub skip_if_mounted: bool,
    pub force: bool,
    pub max_pass: Option<u32>,
    pub btrfs_use_scrub: bool,
    pub btrfs_allow_offline_check: bool,
    pub dry_run: bool,
    pub timeout_ms: u64,
    pub env: Option<HashMap<String, String>>,
}

/// How to interpret the target field for check operations
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CheckTargetKind {
    Auto,
    Mountpoint,
    Device,
}

/// Check operation mode
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CheckMode {
    Check,
    Repair,
    Auto,
}

/// Check operation aggressiveness
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CheckAggressiveness {
    Safe,
    Normal,
    Aggressive,
}

/// Filesystem information for check operations
#[derive(Debug, Clone, Serialize)]
pub struct CheckFilesystemInfo {
    pub source: String,
    pub fstype: String,
    pub mounted: bool,
    pub readonly: bool,
}

/// Tool execution information
#[derive(Debug, Clone, Serialize)]
pub struct CheckTool {
    pub name: String,
    pub command: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Analysis of check results
#[derive(Debug, Clone, Serialize)]
pub struct CheckAnalysis {
    pub errors_found: bool,
    pub repaired: bool,
    pub needs_repair: bool,
    pub filesystem_state: String, // "clean" | "checked_with_warnings" | "errors_detected" | "repaired"
}

/// Summary of check operation
#[derive(Debug, Clone, Serialize)]
pub struct CheckSummary {
    pub status: String, // "success" | "skipped" | "failure"
    pub skipped_reason: Option<String>,
}

/// Plan for dry-run check operations
#[derive(Debug, Clone, Serialize)]
pub struct CheckPlan {
    pub tool: String,
    pub arguments: Vec<String>,
    pub requires_unmount_for_repair: bool,
    pub would_run: bool,
}

/// Check operation result
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub backend: String,
    pub verb: String,
    pub alias: Option<String>,
    pub target: String,
    pub by: String,
    pub filesystem: Option<CheckFilesystemInfo>,
    pub mode: String,
    pub allow_repair: bool,
    pub tool: Option<CheckTool>,
    pub analysis: Option<CheckAnalysis>,
    pub summary: CheckSummary,
    pub action: Option<String>,
    pub reason: Option<String>,
    pub dry_run: Option<bool>,
    pub plan: Option<CheckPlan>,
}

impl Default for FsCheckConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            by: CheckTargetKind::Auto,
            filesystem_type: None,
            mode: CheckMode::Check,
            aggressiveness: CheckAggressiveness::Safe,
            allow_repair: false,
            allow_online_check: true,
            require_unmounted_for_repair: true,
            skip_if_mounted: false,
            force: false,
            max_pass: None,
            btrfs_use_scrub: true,
            btrfs_allow_offline_check: false,
            dry_run: false,
            timeout_ms: 600000, // 10 minutes
            env: None,
        }
    }
}

impl Default for MountConfig {
    fn default() -> Self {
        Self {
            source: None,
            target: String::new(),
            r#type: None,
            options: Vec::new(),
            read_only: false,
            bind: false,
            create_target: true,
            make_parents: true,
            fail_if_mounted: false,
            remount: false,
            network: false,
            timeout_ms: 5000,
            dry_run: false,
            env: None,
        }
    }
}

impl Default for UnmountConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            by: UnmountTargetKind::Target,
            force: false,
            lazy: false,
            detach_children: false,
            fail_if_not_mounted: false,
            timeout_ms: 5000,
            dry_run: false,
            env: None,
        }
    }
}

/// Snapshot configuration structure
#[derive(Debug, Clone, Deserialize)]
pub struct SnapshotConfig {
    #[serde(default)]
    pub include_mountpoints: Vec<String>,
    #[serde(default)]
    pub exclude_mountpoints: Vec<String>,
    #[serde(default)]
    pub include_types: Vec<String>,
    #[serde(default)]
    pub exclude_types: Vec<String>,
    #[serde(default)]
    pub include_sources: Vec<String>,
    #[serde(default)]
    pub exclude_sources: Vec<String>,
    #[serde(default = "default_true")]
    pub include_usage: bool,
    #[serde(default)]
    pub include_inodes: bool,
    #[serde(default = "default_true")]
    pub include_fs_metadata: bool,
    #[serde(default = "default_true")]
    pub include_os_metadata: bool,
    #[serde(default = "default_true")]
    pub normalize_paths: bool,
    #[serde(default = "default_json_format")]
    pub format: SnapshotFormat,
    #[serde(default = "default_true")]
    pub inline: bool,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    pub env: Option<HashMap<String, String>>,
}

/// Snapshot format enum
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotFormat {
    Json,
    Yaml,
    Text,
}

/// Snapshot lockfile schema
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotLockfile {
    pub lockfile_version: String,
    pub generated_at: DateTime<Utc>,
    pub alias: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<HostInfo>,
    pub filters: FilterInfo,
    pub mounts: Vec<MountEntry>,
}

/// Host information
#[derive(Debug, Clone, Serialize)]
pub struct HostInfo {
    pub hostname: String,
    pub os_family: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel: String,
    pub architecture: String,
}

/// Filter information
#[derive(Debug, Clone, Serialize)]
pub struct FilterInfo {
    pub include_mountpoints: Vec<String>,
    pub exclude_mountpoints: Vec<String>,
    pub include_types: Vec<String>,
    pub exclude_types: Vec<String>,
    pub include_sources: Vec<String>,
    pub exclude_sources: Vec<String>,
}

/// Mount entry in the lockfile
#[derive(Debug, Clone, Serialize)]
pub struct MountEntry {
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub options: Vec<String>,
    pub dump: i32,
    pub pass: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<UsageInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inodes: Option<InodeInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs_metadata: Option<FsMetadata>,
}

/// Usage information
#[derive(Debug, Clone, Serialize)]
pub struct UsageInfo {
    pub size_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub used_percent: f64,
}

/// Inode information
#[derive(Debug, Clone, Serialize)]
pub struct InodeInfo {
    pub total: u64,
    pub used: u64,
    pub free: u64,
    pub used_percent: f64,
}

/// Filesystem metadata
#[derive(Debug, Clone, Serialize)]
pub struct FsMetadata {
    pub block_size: u64,
    pub blocks: u64,
    pub flags: Vec<String>,
    pub device: String,
}

/// Snapshot result
#[derive(Debug, Serialize)]
pub struct SnapshotResult {
    pub backend: String,
    pub action: String,
    pub alias: String,
    pub format: String,
    pub lockfile: String,
    pub parsed: SnapshotSummary,
}

/// Snapshot summary
#[derive(Debug, Serialize)]
pub struct SnapshotSummary {
    pub lockfile_version: String,
    pub mount_count: usize,
    pub filters_applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<HostInfo>,
}

/// Raw mount information from system
#[derive(Debug, Clone)]
pub struct RawMountInfo {
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub options: String,
    pub dump: i32,
    pub pass: i32,
}

// Helper functions for default values
fn default_true() -> bool { true }
fn default_json_format() -> SnapshotFormat { SnapshotFormat::Json }
fn default_timeout() -> u64 { 5000 }

/// Subject type for quota queries
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SubjectType {
    Auto,
    User,
    Group,
    Project,
}

/// Units for quota reporting
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum QuotaUnits {
    Auto,
    Blocks,
    Bytes,
}

/// Quota configuration structure
#[derive(Debug, Clone, Deserialize)]
pub struct FsQuotaConfig {
    pub path: Option<String>,
    pub subject: Option<String>,
    pub subject_type: SubjectType,
    pub resolve_uid_gid: bool,
    pub include_space: bool,
    pub include_inodes: bool,
    pub include_grace: bool,
    pub all_subjects: bool,
    pub units: QuotaUnits,
    pub timeout_ms: u64,
    pub env: Option<HashMap<String, String>>,
}

/// Quota summary configuration structure
#[derive(Debug, Clone, Deserialize)]
pub struct FsQuotaSummaryConfig {
    pub subject: Option<String>,
    pub subject_type: SubjectType,
    pub resolve_uid_gid: bool,
    pub include_mountpoints: Vec<String>,
    pub exclude_mountpoints: Vec<String>,
    pub include_types: Vec<String>,
    pub exclude_types: Vec<String>,
    pub include_sources: Vec<String>,
    pub exclude_sources: Vec<String>,
    pub include_space: bool,
    pub include_inodes: bool,
    pub include_grace: bool,
    pub all_subjects: bool,
    pub units: QuotaUnits,
    pub timeout_ms: u64,
    pub env: Option<HashMap<String, String>>,
}

/// Usage mode enum
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UsageMode {
    Mounts,
    Paths,
    Aggregate,
}

/// Usage units enum
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UsageUnits {
    Auto,
    Bytes,
    Kilobytes,
    Megabytes,
    Gigabytes,
    Blocks,
}

/// Filesystem usage configuration
#[derive(Debug, Clone, Deserialize)]
pub struct FsUsageConfig {
    pub paths: Vec<String>,
    pub mode: UsageMode,
    pub include_mountpoints: Vec<String>,
    pub exclude_mountpoints: Vec<String>,
    pub include_types: Vec<String>,
    pub exclude_types: Vec<String>,
    pub include_sources: Vec<String>,
    pub exclude_sources: Vec<String>,
    pub include_inodes: bool,
    pub include_readonly: bool,
    pub normalize_paths: bool,
    pub units: UsageUnits,
    pub human_readable: bool,
    pub threshold_used_percent_min: Option<f64>,
    pub threshold_used_percent_max: Option<f64>,
    pub timeout_ms: u64,
    pub env: Option<HashMap<String, String>>,
}

/// Target identification for resize operations
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ResizeTargetKind {
    Auto,
    Mountpoint,
    Device,
}

/// Resize operation mode
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ResizeMode {
    Grow,
    Shrink,
    Auto,
}

/// Size units for resize operations
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SizeUnits {
    Auto,
    Bytes,
    Kilobytes,
    Megabytes,
    Gigabytes,
    Terabytes,
}

/// Filesystem resize configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FsResizeConfig {
    pub target: String,
    pub by: ResizeTargetKind,
    pub size: Option<Value>,
    pub delta: Option<Value>,
    pub size_units: SizeUnits,
    pub mode: ResizeMode,
    pub allow_shrink: bool,
    pub min_free_space_percent: f64,
    pub manage_underlying_volume: bool,
    pub volume_resize_only: bool,
    pub filesystem_resize_only: bool,
    pub require_unmounted_for_shrink: bool,
    pub force: bool,
    pub dry_run: bool,
    pub timeout_ms: u64,
    pub env: Option<HashMap<String, String>>,
}

/// Filesystem information for resize operations
#[derive(Debug, Clone, Serialize)]
pub struct ResizeFilesystemInfo {
    pub source: String,
    pub fstype: String,
    pub mounted: bool,
    pub current_size_bytes: u64,
    pub requested_size_bytes: Option<u64>,
    pub delta_bytes: Option<i64>,
}

/// Resize action step
#[derive(Debug, Clone, Serialize)]
pub struct ResizeAction {
    pub r#type: String,
    pub tool: String,
    pub status: String,
    pub command: String,
}

/// Resize operation plan for dry-run
#[derive(Debug, Clone, Serialize)]
pub struct ResizePlan {
    pub steps: Vec<ResizeAction>,
}

/// Resize operation result
#[derive(Debug, Clone, Serialize)]
pub struct ResizeResult {
    pub backend: String,
    pub verb: String,
    pub alias: Option<String>,
    pub target: String,
    pub by: String,
    pub filesystem: ResizeFilesystemInfo,
    pub requested_size_bytes: Option<u64>,
    pub previous_size_bytes: Option<u64>,
    pub final_size_bytes: Option<u64>,
    pub delta_bytes: Option<i64>,
    pub mode: String,
    pub action: String,
    pub reason: Option<String>,
    pub actions: Option<Vec<ResizeAction>>,
    pub summary: Option<ResizeSummary>,
    pub dry_run: Option<bool>,
    pub plan: Option<ResizePlan>,
}

/// Resize operation summary
#[derive(Debug, Clone, Serialize)]
pub struct ResizeSummary {
    pub status: String,
    pub shrink: bool,
    pub grew: bool,
}

/// Filesystem information for quota queries
#[derive(Debug, Clone, Serialize)]
pub struct QuotaFilesystem {
    pub source: String,
    pub target: String,
    pub fstype: String,
}

/// Subject query information
#[derive(Debug, Clone, Serialize)]
pub struct QuotaSubjectQuery {
    pub subject: String,
    pub subject_type: String,
    pub resolved_uid: Option<u32>,
    pub resolved_gid: Option<u32>,
}

/// Space quota information
#[derive(Debug, Clone, Serialize)]
pub struct SpaceQuota {
    pub used: u64,
    pub soft_limit: Option<u64>,
    pub hard_limit: Option<u64>,
    pub grace_exceeded: bool,
    pub grace_time_remaining_sec: Option<u64>,
    pub used_percent_of_soft: Option<f64>,
}

/// Inode quota information
#[derive(Debug, Clone, Serialize)]
pub struct InodeQuota {
    pub used: u64,
    pub soft_limit: Option<u64>,
    pub hard_limit: Option<u64>,
    pub grace_exceeded: bool,
    pub grace_time_remaining_sec: Option<u64>,
    pub used_percent_of_soft: Option<f64>,
}

/// Subject quota information
#[derive(Debug, Clone, Serialize)]
pub struct QuotaSubject {
    pub subject: String,
    pub subject_type: String,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub space: Option<SpaceQuota>,
    pub inodes: Option<InodeQuota>,
}

/// Quota operation result
#[derive(Debug, Clone, Serialize)]
pub struct QuotaResult {
    pub backend: String,
    pub verb: String,
    pub alias: String,
    pub path: String,
    pub filesystem: QuotaFilesystem,
    pub subject_query: QuotaSubjectQuery,
    pub units: String,
    pub space_quota_enabled: bool,
    pub inode_quota_enabled: bool,
    pub subjects: Vec<QuotaSubject>,
}

/// Aggregated space quota summary
#[derive(Debug, Clone, Serialize)]
pub struct SpaceQuotaSummary {
    pub used: u64,
    pub soft_limit: Option<u64>,
    pub hard_limit: Option<u64>,
    pub used_percent_of_soft: Option<f64>,
    pub any_grace_exceeded: bool,
}

/// Aggregated inode quota summary
#[derive(Debug, Clone, Serialize)]
pub struct InodeQuotaSummary {
    pub used: u64,
    pub soft_limit: Option<u64>,
    pub hard_limit: Option<u64>,
    pub used_percent_of_soft: Option<f64>,
    pub any_grace_exceeded: bool,
}

/// Filesystem with quota information
#[derive(Debug, Clone, Serialize)]
pub struct QuotaSummaryFilesystem {
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub space_quota_enabled: bool,
    pub inode_quota_enabled: bool,
    pub space: Option<SpaceQuota>,
    pub inodes: Option<InodeQuota>,
}

/// Filesystem without quota support
#[derive(Debug, Clone, Serialize)]
pub struct FilesystemWithoutQuotas {
    pub source: String,
    pub target: String,
    pub fstype: String,
}

/// Partial failure information
#[derive(Debug, Clone, Serialize)]
pub struct PartialFailure {
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub error: PartialFailureError,
}

/// Partial failure error information
#[derive(Debug, Clone, Serialize)]
pub struct PartialFailureError {
    pub code: String,
    pub message: String,
}

/// Quota summary filters
#[derive(Debug, Clone, Serialize)]
pub struct QuotaSummaryFilters {
    pub include_mountpoints: Vec<String>,
    pub exclude_mountpoints: Vec<String>,
    pub include_types: Vec<String>,
    pub exclude_types: Vec<String>,
    pub include_sources: Vec<String>,
    pub exclude_sources: Vec<String>,
}

/// Subject summary for multi-subject aggregation
#[derive(Debug, Clone, Serialize)]
pub struct SubjectSummary {
    pub subject: String,
    pub subject_type: String,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub space: Option<SpaceQuotaSummary>,
    pub inodes: Option<InodeQuotaSummary>,
}

/// Quota summary operation result
#[derive(Debug, Clone, Serialize)]
pub struct QuotaSummaryResult {
    pub backend: String,
    pub verb: String,
    pub alias: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_query: Option<QuotaSubjectQuery>,
    pub filters: QuotaSummaryFilters,
    pub units: String,
    pub include_space: bool,
    pub include_inodes: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<QuotaSummaryData>,
    pub all_subjects: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subjects: Option<Vec<SubjectSummary>>,
    pub filesystems: Vec<QuotaSummaryFilesystem>,
    pub filesystems_without_quotas: Vec<FilesystemWithoutQuotas>,
    pub partial_failures: Vec<PartialFailure>,
}

/// Summary data for single subject
#[derive(Debug, Clone, Serialize)]
pub struct QuotaSummaryData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space: Option<SpaceQuotaSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inodes: Option<InodeQuotaSummary>,
}

/// Filesystem usage information with extended details
#[derive(Debug, Clone, Serialize)]
pub struct FilesystemUsage {
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub read_only: bool,
    pub size: u64,
    pub used: u64,
    pub free: u64,
    pub used_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_human: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_human: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_human: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inodes: Option<FilesystemInodes>,
}

/// Inode usage information for filesystems
#[derive(Debug, Clone, Serialize)]
pub struct FilesystemInodes {
    pub total: u64,
    pub used: u64,
    pub free: u64,
    pub used_percent: Option<f64>,
}

/// Aggregate usage information
#[derive(Debug, Clone, Serialize)]
pub struct AggregateUsage {
    pub size: u64,
    pub used: u64,
    pub free: u64,
    pub used_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_human: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_human: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_human: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inodes: Option<FilesystemInodes>,
}

/// Path to filesystem mapping
#[derive(Debug, Clone, Serialize)]
pub struct PathToFilesystem {
    pub path: String,
    pub target: String,
    pub source: String,
}

/// Usage filters applied
#[derive(Debug, Clone, Serialize)]
pub struct UsageFilters {
    pub include_mountpoints: Vec<String>,
    pub exclude_mountpoints: Vec<String>,
    pub include_types: Vec<String>,
    pub exclude_types: Vec<String>,
    pub include_sources: Vec<String>,
    pub exclude_sources: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold_used_percent_min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold_used_percent_max: Option<f64>,
}

/// Usage operation result
#[derive(Debug, Clone, Serialize)]
pub struct UsageResult {
    pub backend: String,
    pub verb: String,
    pub alias: String,
    pub mode: String,
    pub units: String,
    pub include_inodes: bool,
    pub filters: UsageFilters,
    pub filesystems: Vec<FilesystemUsage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate: Option<AggregateUsage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_to_filesystem: Option<Vec<PathToFilesystem>>,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            include_mountpoints: Vec::new(),
            exclude_mountpoints: Vec::new(),
            include_types: Vec::new(),
            exclude_types: Vec::new(),
            include_sources: Vec::new(),
            exclude_sources: Vec::new(),
            include_usage: true,
            include_inodes: false,
            include_fs_metadata: true,
            include_os_metadata: true,
            normalize_paths: true,
            format: SnapshotFormat::Json,
            inline: true,
            timeout_ms: 5000,
            env: None,
        }
    }
}

/// List-mounts configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ListMountsConfig {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub include_mountpoints: Vec<String>,
    #[serde(default)]
    pub exclude_mountpoints: Vec<String>,
    #[serde(default)]
    pub include_types: Vec<String>,
    #[serde(default)]
    pub exclude_types: Vec<String>,
    #[serde(default)]
    pub include_sources: Vec<String>,
    #[serde(default)]
    pub exclude_sources: Vec<String>,
    #[serde(default = "default_true")]
    pub include_readonly: bool,
    #[serde(default = "default_true")]
    pub include_readwrite: bool,
    #[serde(default = "default_false")]
    pub include_pseudo: bool,
    #[serde(default = "default_true")]
    pub include_loop: bool,
    #[serde(default = "default_true")]
    pub include_network: bool,
    #[serde(default = "default_true")]
    pub normalize_paths: bool,
    #[serde(default = "default_false")]
    pub resolve_labels: bool,
    #[serde(default = "default_false")]
    pub resolve_fs_features: bool,
    #[serde(default = "default_list_mounts_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,
}

/// Mount entry for list-mounts response
#[derive(Debug, Clone, Serialize)]
pub struct ListMountEntry {
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub options: Vec<String>,
    pub read_only: bool,
    pub pseudo: bool,
    pub network: bool,
    #[serde(rename = "loop")]
    pub loop_device: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs_features: Option<FsFeatures>,
}

/// Device metadata for mounted filesystems
#[derive(Debug, Clone, Serialize)]
pub struct DeviceMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partlabel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partuuid: Option<String>,
}

/// Filesystem features information
#[derive(Debug, Clone, Serialize)]
pub struct FsFeatures {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inode_size: Option<u64>,
}

/// Filters applied for list-mounts
#[derive(Debug, Clone, Serialize)]
pub struct ListMountsFilters {
    pub paths: Vec<String>,
    pub include_mountpoints: Vec<String>,
    pub exclude_mountpoints: Vec<String>,
    pub include_types: Vec<String>,
    pub exclude_types: Vec<String>,
    pub include_sources: Vec<String>,
    pub exclude_sources: Vec<String>,
    pub include_readonly: bool,
    pub include_readwrite: bool,
    pub include_pseudo: bool,
    pub include_loop: bool,
    pub include_network: bool,
}

/// List-mounts operation result
#[derive(Debug, Serialize)]
pub struct ListMountsResult {
    pub backend: String,
    pub verb: String,
    pub alias: String,
    pub filters: ListMountsFilters,
    pub mounts: Vec<ListMountEntry>,
}

// Helper functions for default values
fn default_false() -> bool { false }
fn default_list_mounts_timeout() -> u64 { 3000 }

impl FsHandle {
    pub fn from_url(url: Url) -> Result<Self> {
        let alias = url.host_str()
            .unwrap_or("default")
            .trim_end_matches(".mount")
            .to_string();

        Ok(Self { alias })
    }

    pub fn new_for_test(alias: String) -> Self {
        Self { alias }
    }

    /// Main mount operation implementation
    pub async fn mount(&self, args: Value) -> Result<Value, anyhow::Error> {
        // Parse and validate configuration
        let config = self.parse_mount_config(args)?;
        self.validate_mount_config(&config)?;

        // Check for existing mounts
        let existing_mounts = self.get_existing_mounts().await?;
        let existing_mount = self.find_existing_mount(&existing_mounts, &config);

        // Handle already mounted scenarios
        if let Some(existing) = &existing_mount {
            if config.fail_if_mounted {
                return Err(FsError::AlreadyMounted(config.target.clone()).into());
            }

            if !config.remount && !self.is_mount_compatible(existing, &config) {
                return Err(FsError::ConflictingMount(config.target.clone()).into());
            }

            if !config.remount {
                // Return success for idempotent operation
                return Ok(json!(MountResult {
                    backend: "fs".to_string(),
                    verb: "mount".to_string(),
                    alias: self.alias.clone(),
                    source: existing.source.clone().into(),
                    target: config.target.clone(),
                    r#type: existing.fs_type.clone().into(),
                    options: existing.options.clone(),
                    read_only: existing.options.contains(&"ro".to_string()),
                    bind: existing.options.iter().any(|opt| opt.contains("bind")),
                    remount: false,
                    action: "already_mounted".to_string(),
                    created_target: false,
                    details: MountDetails {
                        device: Some(existing.source.clone()),
                        fs_type: Some(existing.fs_type.clone()),
                        mount_flags: existing.options.clone(),
                        from_existing: true,
                    },
                    dry_run: None,
                    plan: None,
                }));
            }
        }

        // Handle dry run
        if config.dry_run {
            return Ok(json!(self.create_mount_plan(&config, existing_mount.is_some())?));
        }

        // Execute mount operation
        self.execute_mount(&config, existing_mount.is_some()).await
    }

    /// Parse mount configuration from arguments
    fn parse_mount_config(&self, args: Value) -> Result<MountConfig, anyhow::Error> {
        // First try to deserialize directly
        let mut config: MountConfig = match serde_json::from_value(args.clone()) {
            Ok(config) => config,
            Err(_) => {
                // If that fails, we need to manually convert string values to proper types
                let mut config = MountConfig::default();
                
                if let Some(obj) = args.as_object() {
                    for (key, value) in obj {
                        match key.as_str() {
                            "target" => {
                                config.target = value.as_str().unwrap_or_default().to_string();
                            }
                            "source" => {
                                config.source = value.as_str().map(|s| s.to_string());
                            }
                            "type" => {
                                config.r#type = value.as_str().map(|s| s.to_string());
                            }
                            "options" => {
                                if let Some(opts_str) = value.as_str() {
                                    config.options = opts_str.split(',').map(|s| s.trim().to_string()).collect();
                                }
                            }
                            "read_only" => {
                                config.read_only = self.parse_bool_value(value);
                            }
                            "bind" => {
                                config.bind = self.parse_bool_value(value);
                            }
                            "create_target" => {
                                config.create_target = self.parse_bool_value(value);
                            }
                            "make_parents" => {
                                config.make_parents = self.parse_bool_value(value);
                            }
                            "fail_if_mounted" => {
                                config.fail_if_mounted = self.parse_bool_value(value);
                            }
                            "remount" => {
                                config.remount = self.parse_bool_value(value);
                            }
                            "network" => {
                                config.network = self.parse_bool_value(value);
                            }
                            "dry_run" => {
                                config.dry_run = self.parse_bool_value(value);
                            }
                            "timeout_ms" => {
                                config.timeout_ms = value.as_str()
                                    .and_then(|s| s.parse::<u64>().ok())
                                    .unwrap_or(5000);
                            }
                            _ => {} // Ignore unknown fields
                        }
                    }
                }
                config
            }
        };

        // Apply defaults and normalize
        if config.timeout_ms == 0 {
            config.timeout_ms = 5000;
        }

        // Ensure read-only option is included in options if read_only is true
        if config.read_only && !config.options.contains(&"ro".to_string()) {
            config.options.push("ro".to_string());
        }

        Ok(config)
    }

    /// Helper to parse boolean values from JSON Value (handles string "true"/"false")
    fn parse_bool_value(&self, value: &Value) -> bool {
        match value {
            Value::Bool(b) => *b,
            Value::String(s) => {
                matches!(s.to_lowercase().as_str(), "true" | "1" | "yes" | "on")
            }
            Value::Number(n) => n.as_u64().unwrap_or(0) != 0,
            _ => false,
        }
    }

    /// Validate mount configuration
    fn validate_mount_config(&self, config: &MountConfig) -> Result<(), anyhow::Error> {
        // Required target
        if config.target.is_empty() || config.target.trim().is_empty() {
            return Err(FsError::InvalidMountConfig("target is required and cannot be empty".to_string()).into());
        }

        // Timeout validation
        if config.timeout_ms == 0 {
            return Err(FsError::InvalidMountConfig("timeout_ms must be greater than 0".to_string()).into());
        }

        // Bind mount requires source
        if config.bind && config.source.as_ref().map_or(true, |s| s.is_empty()) {
            return Err(FsError::InvalidMountConfig("bind mounts require a source path".to_string()).into());
        }

        // Contradictory flags
        if config.remount && config.fail_if_mounted {
            return Err(FsError::InvalidMountConfig("remount and fail_if_mounted are contradictory".to_string()).into());
        }

        // Target should be absolute path (warning level for flexibility)
        if !config.target.starts_with('/') {
            eprintln!("Warning: target path '{}' is not absolute", config.target);
        }

        Ok(())
    }

    /// Get existing mounts from /proc/mounts
    async fn get_existing_mounts(&self) -> Result<Vec<ExistingMount>, anyhow::Error> {
        let mut mounts = Vec::new();

        #[cfg(target_os = "linux")]
        {
            let content = tokio::fs::read_to_string("/proc/mounts").await
                .context("Failed to read /proc/mounts")?;

            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let source = parts[0].to_string();
                    let target = parts[1].to_string();
                    let fs_type = parts[2].to_string();
                    let options = parts[3].split(',').map(|s| s.to_string()).collect();

                    mounts.push(ExistingMount {
                        source,
                        target,
                        fs_type,
                        options,
                    });
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            // For non-Linux systems, try to use mount command
            let output = Command::new("mount")
                .output()
                .context("Failed to execute mount command")?;

            if output.status.success() {
                let content = String::from_utf8_lossy(&output.stdout);
                // Parse mount output (format varies by OS)
                // This is a simplified parser - real implementation would be more robust
                for line in content.lines() {
                    if let Some(caps) = regex::Regex::new(r"^(.+?) on (.+?) \((.+?)\)")
                        .unwrap()
                        .captures(line) 
                    {
                        let source = caps[1].to_string();
                        let target = caps[2].to_string();
                        let opts = caps[3].to_string();
                        let (fs_type, options) = if let Some(comma_idx) = opts.find(',') {
                            let fs_type = opts[..comma_idx].to_string();
                            let options = opts[comma_idx + 1..]
                                .split(',')
                                .map(|s| s.trim().to_string())
                                .collect();
                            (fs_type, options)
                        } else {
                            (opts, Vec::new())
                        };

                        mounts.push(ExistingMount {
                            source,
                            target,
                            fs_type,
                            options,
                        });
                    }
                }
            }
        }

        Ok(mounts)
    }

    /// Find existing mount for the given target
    fn find_existing_mount(&self, mounts: &[ExistingMount], config: &MountConfig) -> Option<ExistingMount> {
        mounts.iter()
            .find(|mount| mount.target == config.target)
            .cloned()
    }

    /// Check if existing mount is compatible with requested configuration
    fn is_mount_compatible(&self, existing: &ExistingMount, config: &MountConfig) -> bool {
        // Check source compatibility
        if let Some(ref source) = config.source {
            if existing.source != *source {
                return false;
            }
        }

        // Check filesystem type compatibility
        if let Some(ref fs_type) = config.r#type {
            if existing.fs_type != *fs_type {
                return false;
            }
        }

        true
    }

    /// Create a plan for dry-run mode
    fn create_mount_plan(&self, config: &MountConfig, already_mounted: bool) -> Result<MountResult, anyhow::Error> {
        let mut plan = MountPlan {
            create_directory: Vec::new(),
            mount_commands: Vec::new(),
        };

        // Directory creation plan
        if config.create_target && !Path::new(&config.target).exists() {
            if config.make_parents {
                plan.create_directory.push(format!("mkdir -p {}", config.target));
            } else {
                plan.create_directory.push(format!("mkdir {}", config.target));
            }
        }

        // Mount command plan
        if !already_mounted || config.remount {
            let mut cmd = Vec::new();
            cmd.push("mount".to_string());

            if config.remount {
                cmd.push("-o".to_string());
                cmd.push("remount".to_string());
            }

            if let Some(ref fs_type) = config.r#type {
                cmd.push("-t".to_string());
                cmd.push(fs_type.clone());
            }

            if config.bind {
                cmd.push("--bind".to_string());
            }

            if !config.options.is_empty() {
                cmd.push("-o".to_string());
                cmd.push(config.options.join(","));
            }

            if let Some(ref source) = config.source {
                cmd.push(source.clone());
            }

            cmd.push(config.target.clone());

            plan.mount_commands.push(cmd.join(" "));
        }

        Ok(MountResult {
            backend: "fs".to_string(),
            verb: "mount".to_string(),
            alias: self.alias.clone(),
            source: config.source.clone(),
            target: config.target.clone(),
            r#type: config.r#type.clone(),
            options: config.options.clone(),
            read_only: config.read_only,
            bind: config.bind,
            remount: config.remount,
            action: if already_mounted { "already_mounted" } else { "planned" }.to_string(),
            created_target: false,
            details: MountDetails {
                device: config.source.clone(),
                fs_type: config.r#type.clone(),
                mount_flags: config.options.clone(),
                from_existing: false,
            },
            dry_run: Some(true),
            plan: Some(plan),
        })
    }

    /// Execute the actual mount operation
    async fn execute_mount(&self, config: &MountConfig, is_remount: bool) -> Result<Value, anyhow::Error> {
        let mut created_target = false;

        // Create target directory if needed
        if config.create_target {
            let target_path = Path::new(&config.target);
            if !target_path.exists() {
                if config.make_parents {
                    tokio::fs::create_dir_all(&target_path).await
                        .with_context(|| format!("Failed to create target directory: {}", config.target))?;
                } else {
                    tokio::fs::create_dir(&target_path).await
                        .with_context(|| format!("Failed to create target directory: {}", config.target))?;
                }
                created_target = true;
            }
        }

        // Build mount command
        let mut cmd = AsyncCommand::new("mount");

        if config.remount || is_remount {
            cmd.arg("-o").arg("remount");
        }

        if let Some(ref fs_type) = config.r#type {
            cmd.arg("-t").arg(fs_type);
        }

        if config.bind {
            cmd.arg("--bind");
        }

        if !config.options.is_empty() {
            cmd.arg("-o").arg(config.options.join(","));
        }

        if let Some(ref source) = config.source {
            cmd.arg(source);
        }

        cmd.arg(&config.target);

        // Set environment variables if provided
        if let Some(ref env) = config.env {
            for (key, value) in env {
                cmd.env(key, value);
            }
        }

        // Configure process
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        // Execute with timeout
        let timeout_duration = Duration::from_millis(config.timeout_ms);
        let output = timeout(timeout_duration, cmd.output()).await
            .map_err(|_| FsError::MountTimeout)?
            .context("Failed to execute mount command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            // Map specific error patterns to appropriate error types
            let error_msg = format!("Mount failed: {} {}", stderr, stdout);
            
            if error_msg.contains("Permission denied") || error_msg.contains("Operation not permitted") {
                return Err(FsError::MountPermissionDenied.into());
            }
            
            return Err(FsError::MountFailure(error_msg).into());
        }

        // Determine action
        let action = if config.remount || is_remount {
            "remounted"
        } else {
            "mounted"
        };

        Ok(json!(MountResult {
            backend: "fs".to_string(),
            verb: "mount".to_string(),
            alias: self.alias.clone(),
            source: config.source.clone(),
            target: config.target.clone(),
            r#type: config.r#type.clone(),
            options: config.options.clone(),
            read_only: config.read_only,
            bind: config.bind,
            remount: config.remount || is_remount,
            action: action.to_string(),
            created_target,
            details: MountDetails {
                device: config.source.clone(),
                fs_type: config.r#type.clone(),
                mount_flags: config.options.clone(),
                from_existing: false,
            },
            dry_run: None,
            plan: None,
        }))
    }

    /// Main unmount operation implementation
    pub async fn unmount(&self, args: Value) -> Result<Value, anyhow::Error> {
        // Parse and validate configuration
        let config = self.parse_unmount_config(args)?;
        self.validate_unmount_config(&config)?;

        // Get current mount table
        let existing_mounts = self.get_existing_mounts().await?;
        
        // Find matching mounts based on `by` strategy
        let matched_mounts = self.find_mounts_to_unmount(&existing_mounts, &config)?;

        // Handle not mounted scenarios
        if matched_mounts.is_empty() {
            if config.fail_if_not_mounted {
                return Err(FsError::NotMounted(config.target.clone()).into());
            }

            return Ok(json!(UnmountResult {
                backend: "fs".to_string(),
                verb: "unmount".to_string(),
                alias: self.alias.clone(),
                target: config.target.clone(),
                by: format!("{:?}", config.by).to_lowercase(),
                force: config.force,
                lazy: config.lazy,
                detach_children: config.detach_children,
                action: "already_unmounted".to_string(),
                unmounted: vec![],
                skipped: vec![],
                errors: vec![],
                dry_run: if config.dry_run { Some(true) } else { None },
                plan: if config.dry_run { Some(UnmountPlan { order: vec![], commands: vec![] }) } else { None },
                matched_mounts: None,
            }));
        }

        // Compute unmount order (including children if requested)
        let unmount_order = self.compute_unmount_order(&matched_mounts, &existing_mounts, &config)?;

        // Handle dry run
        if config.dry_run {
            return Ok(json!(self.create_unmount_plan(&config, &unmount_order)?));
        }

        // Execute unmount operations
        self.execute_unmount(&config, &unmount_order).await
    }

    /// Parse unmount configuration from arguments
    fn parse_unmount_config(&self, args: Value) -> Result<UnmountConfig, anyhow::Error> {
        let mut config: UnmountConfig = match serde_json::from_value(args.clone()) {
            Ok(config) => config,
            Err(_) => {
                // Manual conversion for string-based inputs
                let mut config = UnmountConfig::default();
                
                if let Some(obj) = args.as_object() {
                    for (key, value) in obj {
                        match key.as_str() {
                            "target" => {
                                config.target = value.as_str().unwrap_or_default().to_string();
                            }
                            "by" => {
                                config.by = match value.as_str().unwrap_or("target") {
                                    "source" => UnmountTargetKind::Source,
                                    "auto" => UnmountTargetKind::Auto,
                                    _ => UnmountTargetKind::Target,
                                };
                            }
                            "force" => {
                                config.force = self.parse_bool_value(value);
                            }
                            "lazy" => {
                                config.lazy = self.parse_bool_value(value);
                            }
                            "detach_children" => {
                                config.detach_children = self.parse_bool_value(value);
                            }
                            "fail_if_not_mounted" => {
                                config.fail_if_not_mounted = self.parse_bool_value(value);
                            }
                            "dry_run" => {
                                config.dry_run = self.parse_bool_value(value);
                            }
                            "timeout_ms" => {
                                config.timeout_ms = value.as_str()
                                    .and_then(|s| s.parse::<u64>().ok())
                                    .or_else(|| value.as_u64())
                                    .unwrap_or(5000);
                            }
                            "env" => {
                                if let Some(env_obj) = value.as_object() {
                                    let mut env_map = HashMap::new();
                                    for (k, v) in env_obj {
                                        if let Some(v_str) = v.as_str() {
                                            env_map.insert(k.clone(), v_str.to_string());
                                        }
                                    }
                                    config.env = Some(env_map);
                                }
                            }
                            _ => {} // Ignore unknown fields
                        }
                    }
                }
                config
            }
        };

        // Apply defaults
        if config.timeout_ms == 0 {
            config.timeout_ms = 5000;
        }

        Ok(config)
    }

    /// Validate unmount configuration
    fn validate_unmount_config(&self, config: &UnmountConfig) -> Result<(), anyhow::Error> {
        // Required target
        if config.target.is_empty() || config.target.trim().is_empty() {
            return Err(FsError::InvalidUnmountConfig("target is required and cannot be empty".to_string()).into());
        }

        // Timeout validation
        if config.timeout_ms == 0 {
            return Err(FsError::InvalidUnmountConfig("timeout_ms must be greater than 0".to_string()).into());
        }

        // Platform compatibility checks
        if config.force && config.lazy {
            // On some platforms, -fl might not be supported together
            // For now, we'll allow it and let the underlying command handle it
        }

        // Validate env map if provided
        if let Some(ref env) = config.env {
            for (key, value) in env {
                if key.is_empty() {
                    return Err(FsError::InvalidUnmountConfig("environment variable keys cannot be empty".to_string()).into());
                }
                // Values can be empty, so no validation needed for value
            }
        }

        Ok(())
    }

    /// Find mounts to unmount based on the target and strategy
    fn find_mounts_to_unmount(&self, existing_mounts: &[ExistingMount], config: &UnmountConfig) -> Result<Vec<ExistingMount>, anyhow::Error> {
        let mut matched = Vec::new();

        match config.by {
            UnmountTargetKind::Target => {
                // Look for mounts with matching target path
                for mount in existing_mounts {
                    if mount.target == config.target {
                        matched.push(mount.clone());
                    }
                }
            }
            UnmountTargetKind::Source => {
                // Look for mounts with matching source
                for mount in existing_mounts {
                    if mount.source == config.target {
                        matched.push(mount.clone());
                    }
                }
            }
            UnmountTargetKind::Auto => {
                // First try as target, then as source
                for mount in existing_mounts {
                    if mount.target == config.target {
                        matched.push(mount.clone());
                        break; // Found as target, don't check as source
                    }
                }

                if matched.is_empty() {
                    for mount in existing_mounts {
                        if mount.source == config.target {
                            matched.push(mount.clone());
                        }
                    }
                }
            }
        }

        Ok(matched)
    }

    /// Compute the order of unmount operations, including children if requested
    fn compute_unmount_order(&self, matched_mounts: &[ExistingMount], all_mounts: &[ExistingMount], config: &UnmountConfig) -> Result<Vec<ExistingMount>, anyhow::Error> {
        let mut unmount_list = Vec::new();

        for matched_mount in matched_mounts {
            if config.detach_children {
                // Find child mounts under this target
                let mut children = Vec::new();
                for mount in all_mounts {
                    if mount.target != matched_mount.target && 
                       mount.target.starts_with(&format!("{}/", matched_mount.target)) {
                        children.push(mount.clone());
                    }
                }

                // Sort children by path depth (deepest first)
                children.sort_by(|a, b| {
                    let depth_a = a.target.matches('/').count();
                    let depth_b = b.target.matches('/').count();
                    depth_b.cmp(&depth_a) // Reverse order for deepest first
                });

                // Add children first, then parent
                unmount_list.extend(children);
            }

            unmount_list.push(matched_mount.clone());
        }

        Ok(unmount_list)
    }

    /// Create unmount plan for dry-run
    fn create_unmount_plan(&self, config: &UnmountConfig, unmount_order: &[ExistingMount]) -> Result<UnmountResult, anyhow::Error> {
        let mut order = Vec::new();
        let mut commands = Vec::new();

        for mount in unmount_order {
            order.push(mount.target.clone());

            let mut cmd_parts = vec!["umount".to_string()];
            
            if config.lazy {
                cmd_parts.push("-l".to_string());
            }
            
            if config.force {
                cmd_parts.push("-f".to_string());
            }
            
            cmd_parts.push(mount.target.clone());
            
            commands.push(cmd_parts.join(" "));
        }

        let matched_mounts: Vec<MountInfo> = unmount_order.iter().map(|mount| {
            MountInfo {
                source: mount.source.clone(),
                target: mount.target.clone(),
                fs_type: mount.fs_type.clone(),
                options: Some(mount.options.clone()),
            }
        }).collect();

        Ok(UnmountResult {
            backend: "fs".to_string(),
            verb: "unmount".to_string(),
            alias: self.alias.clone(),
            target: config.target.clone(),
            by: format!("{:?}", config.by).to_lowercase(),
            force: config.force,
            lazy: config.lazy,
            detach_children: config.detach_children,
            action: "planned".to_string(),
            unmounted: vec![],
            skipped: vec![],
            errors: vec![],
            dry_run: Some(true),
            plan: Some(UnmountPlan { order, commands }),
            matched_mounts: Some(matched_mounts),
        })
    }

    /// Execute the actual unmount operations
    async fn execute_unmount(&self, config: &UnmountConfig, unmount_order: &[ExistingMount]) -> Result<Value, anyhow::Error> {
        let mut unmounted = Vec::new();
        let mut skipped = Vec::new();
        let mut errors = Vec::new();

        for mount in unmount_order {
            match self.execute_single_unmount(config, mount).await {
                Ok(()) => {
                    unmounted.push(MountInfo {
                        source: mount.source.clone(),
                        target: mount.target.clone(),
                        fs_type: mount.fs_type.clone(),
                        options: Some(mount.options.clone()),
                    });
                }
                Err(e) => {
                    errors.push(UnmountError {
                        target: mount.target.clone(),
                        code: self.map_error_to_code(&e),
                        message: e.to_string(),
                    });
                }
            }
        }

        let action = if errors.is_empty() {
            "unmounted"
        } else if unmounted.is_empty() {
            "failed"
        } else {
            "partially_unmounted"
        };

        Ok(json!(UnmountResult {
            backend: "fs".to_string(),
            verb: "unmount".to_string(),
            alias: self.alias.clone(),
            target: config.target.clone(),
            by: format!("{:?}", config.by).to_lowercase(),
            force: config.force,
            lazy: config.lazy,
            detach_children: config.detach_children,
            action: action.to_string(),
            unmounted,
            skipped,
            errors,
            dry_run: None,
            plan: None,
            matched_mounts: None,
        }))
    }

    /// Execute a single unmount operation
    async fn execute_single_unmount(&self, config: &UnmountConfig, mount: &ExistingMount) -> Result<(), anyhow::Error> {
        let mut cmd = AsyncCommand::new("umount");

        // Add flags based on configuration
        if config.lazy {
            cmd.arg("-l");
        }

        if config.force {
            cmd.arg("-f");
        }

        cmd.arg(&mount.target);

        // Set environment variables if provided
        if let Some(ref env) = config.env {
            for (key, value) in env {
                cmd.env(key, value);
            }
        }

        // Configure process
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        // Execute with timeout
        let timeout_duration = Duration::from_millis(config.timeout_ms);
        let output = timeout(timeout_duration, cmd.output()).await
            .map_err(|_| FsError::UnmountTimeout)?
            .context("Failed to execute umount command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            // Map specific error patterns to appropriate error types
            let error_msg = format!("Unmount failed: {} {}", stderr, stdout);
            
            if error_msg.contains("Permission denied") || error_msg.contains("Operation not permitted") {
                return Err(FsError::UnmountPermissionDenied.into());
            } else if error_msg.contains("busy") || error_msg.contains("Device or resource busy") {
                return Err(FsError::UnmountBusy(mount.target.clone()).into());
            } else if error_msg.contains("not mounted") {
                return Err(FsError::NotMounted(mount.target.clone()).into());
            }
            
            return Err(FsError::UnmountFailure(error_msg).into());
        }

        Ok(())
    }

    /// Map errors to error codes for JSON responses
    fn map_error_to_code(&self, error: &anyhow::Error) -> String {
        if let Some(fs_err) = error.downcast_ref::<FsError>() {
            match fs_err {
                FsError::InvalidMountConfig(_) => "fs.invalid_mount_config",
                FsError::InvalidUnmountConfig(_) => "fs.invalid_unmount_config",
                FsError::InvalidSnapshotConfig(_) => "fs.invalid_snapshot_config",
                FsError::InvalidQuotaConfig(_) => "fs.invalid_quota_config",
                FsError::ProfileNotFound(_) => "fs.profile_not_found", 
                FsError::MountUnsupported => "fs.mount_unsupported",
                FsError::UnmountUnsupported => "fs.unmount_unsupported",
                FsError::SnapshotUnsupported => "fs.snapshot_unsupported",
                FsError::QuotaUnsupported => "fs.quota_unsupported",
                FsError::MountPermissionDenied => "fs.mount_permission_denied",
                FsError::UnmountPermissionDenied => "fs.unmount_permission_denied",
                FsError::AlreadyMounted(_) => "fs.already_mounted",
                FsError::ConflictingMount(_) => "fs.conflicting_mount",
                FsError::NotMounted(_) => "fs.not_mounted",
                FsError::QuotaNotEnabled(_) => "fs.quota_not_enabled",
                FsError::QuotaSubjectNotFound(_) => "fs.quota_subject_not_found",
                FsError::MountFailure(_) => "fs.mount_failure",
                FsError::UnmountFailure(_) => "fs.unmount_failure",
                FsError::SnapshotFailed(_) => "fs.snapshot_failed",
                FsError::QuotaFailed(_) => "fs.quota_failed",
                FsError::MountTimeout => "fs.mount_timeout",
                FsError::UnmountTimeout => "fs.unmount_timeout",
                FsError::SnapshotTimeout => "fs.snapshot_timeout",
                FsError::QuotaTimeout => "fs.quota_timeout",
                FsError::TargetCreationFailed(_) => "fs.target_creation_failed",
                FsError::UnmountBusy(_) => "fs.unmount_busy",
                FsError::UnmountOptionUnsupported(_) => "fs.unmount_option_unsupported",
                FsError::InvalidQuotaSummaryConfig(_) => "fs.invalid_quota_summary_config",
                FsError::QuotaSummaryUnsupported => "fs.quota_summary_unsupported",
                FsError::QuotaSummaryNoQuotaFilesystems => "fs.quota_summary_no_quota_filesystems",
                FsError::QuotaSummaryTimeout => "fs.quota_summary_timeout",
                FsError::QuotaSummaryFailed(_) => "fs.quota_summary_failed",
                FsError::InvalidUsageConfig(_) => "fs.invalid_usage_config",
                FsError::UsageUnsupported => "fs.usage_unsupported",
                FsError::UsageTimeout => "fs.usage_timeout",
                FsError::UsageFailed(_) => "fs.usage_failed",
                FsError::PathNotFound(_) => "fs.path_not_found",
                FsError::UsageNothingSelected => "fs.usage_nothing_selected",
                FsError::InvalidResizeConfig(_) => "fs.invalid_resize_config",
                FsError::ResizeTargetNotFound(_) => "fs.resize_target_not_found",
                FsError::ResizeUnsupportedFilesystem(_) => "fs.resize_unsupported_filesystem",
                FsError::ResizeShrinkNotAllowed => "fs.resize_shrink_not_allowed",
                FsError::ResizeShrinkNotSupportedForFilesystem(_) => "fs.resize_shrink_not_supported_for_filesystem",
                FsError::ResizeShrinkRequiresUnmount(_) => "fs.resize_shrink_requires_unmount",
                FsError::ResizeWouldViolateMinFree => "fs.resize_would_violate_min_free",
                FsError::ResizeTargetExceedsDevice => "fs.resize_target_exceeds_device",
                FsError::ResizeInvalidTargetSize(_) => "fs.resize_invalid_target_size",
                FsError::ResizeVolumeManagementUnsupported => "fs.resize_volume_management_unsupported",
                FsError::ResizeTimeout => "fs.resize_timeout",
                FsError::ResizeFailed(_) => "fs.resize_failed",
                FsError::InvalidCheckConfig(_) => "fs.invalid_check_config",
                FsError::CheckTargetNotFound(_) => "fs.check_target_not_found",
                FsError::CheckUnsupportedFilesystem(_) => "fs.check_unsupported_filesystem",
                FsError::CheckRepairNotAllowed => "fs.check_repair_not_allowed",
                FsError::CheckRequiresUnmountForRepair(_) => "fs.check_requires_unmount_for_repair",
                FsError::CheckMustBeOffline(_) => "fs.check_must_be_offline",
                FsError::CheckToolNotAvailable(_) => "fs.check_tool_not_available",
                FsError::CheckTimeout => "fs.check_timeout",
                FsError::CheckFailed(_) => "fs.check_failed",
                FsError::InvalidListMountsConfig(_) => "fs.invalid_list_mounts_config",
                FsError::ListMountsUnsupported => "fs.list_mounts_unsupported",
                FsError::ListMountsTimeout => "fs.list_mounts_timeout",
                FsError::ListMountsFailed(_) => "fs.list_mounts_failed",
                _ => "fs.unknown_error",
            }
        } else {
            "fs.unknown_error"
        }.to_string()
    }

    /// Main snapshot operation implementation
    pub async fn snapshot(&self, args: Value) -> Result<Value, anyhow::Error> {
        // Parse and validate configuration
        let config = self.parse_snapshot_config(args)?;
        self.validate_snapshot_config(&config)?;

        // Execute snapshot with timeout
        let timeout_duration = Duration::from_millis(config.timeout_ms);
        let snapshot_result = timeout(timeout_duration, self.execute_snapshot(&config)).await
            .map_err(|_| FsError::SnapshotTimeout)?;

        match snapshot_result {
            Ok(result) => Ok(result),
            Err(e) => Err(e),
        }
    }

    /// Parse snapshot configuration from arguments
    fn parse_snapshot_config(&self, args: Value) -> Result<SnapshotConfig, anyhow::Error> {
        let mut config: SnapshotConfig = serde_json::from_value(args)
            .context("Failed to parse snapshot configuration")?;

        // Set default timeout if not provided
        if config.timeout_ms == 0 {
            config.timeout_ms = 5000;
        }

        Ok(config)
    }

    /// Validate snapshot configuration
    fn validate_snapshot_config(&self, config: &SnapshotConfig) -> Result<(), anyhow::Error> {
        if config.timeout_ms == 0 {
            return Err(FsError::InvalidSnapshotConfig("timeout_ms must be greater than 0".to_string()).into());
        }

        Ok(())
    }

    /// Execute the actual snapshot operation
    async fn execute_snapshot(&self, config: &SnapshotConfig) -> Result<Value, anyhow::Error> {
        // 1. Read current mount table
        let raw_mounts = self.read_mount_table().await?;

        // 2. Apply filters
        let filtered_mounts = self.apply_snapshot_filters(&raw_mounts, config)?;

        // 3. Convert to mount entries with optional metadata
        let mut mount_entries = Vec::new();
        for raw_mount in filtered_mounts {
            let mut entry = MountEntry {
                source: raw_mount.source.clone(),
                target: if config.normalize_paths {
                    self.normalize_path(&raw_mount.target)
                } else {
                    raw_mount.target.clone()
                },
                fstype: raw_mount.fstype.clone(),
                options: self.parse_and_sort_options(&raw_mount.options),
                dump: raw_mount.dump,
                pass: raw_mount.pass,
                usage: None,
                inodes: None,
                fs_metadata: None,
            };

            // Add usage info if requested
            if config.include_usage {
                entry.usage = self.get_usage_info(&entry.target).await;
            }

            // Add inode info if requested
            if config.include_inodes {
                entry.inodes = self.get_inode_info(&entry.target).await;
            }

            // Add filesystem metadata if requested
            if config.include_fs_metadata {
                entry.fs_metadata = self.get_fs_metadata(&raw_mount).await;
            }

            mount_entries.push(entry);
        }

        // 4. Sort deterministically
        mount_entries.sort_by(|a, b| {
            a.target.cmp(&b.target)
                .then_with(|| a.source.cmp(&b.source))
                .then_with(|| a.fstype.cmp(&b.fstype))
        });

        // 5. Gather OS metadata if requested
        let host_info = if config.include_os_metadata {
            self.get_host_info().await
        } else {
            None
        };

        // 6. Build lockfile
        let lockfile = SnapshotLockfile {
            lockfile_version: "fs-lock/v1".to_string(),
            generated_at: Utc::now(),
            alias: self.alias.clone(),
            host: host_info.clone(),
            filters: FilterInfo {
                include_mountpoints: config.include_mountpoints.clone(),
                exclude_mountpoints: config.exclude_mountpoints.clone(),
                include_types: config.include_types.clone(),
                exclude_types: config.exclude_types.clone(),
                include_sources: config.include_sources.clone(),
                exclude_sources: config.exclude_sources.clone(),
            },
            mounts: mount_entries.clone(),
        };

        // 7. Serialize to requested format
        let lockfile_content = self.serialize_lockfile(&lockfile, &config.format)?;

        // 8. Build response
        let summary = SnapshotSummary {
            lockfile_version: lockfile.lockfile_version.clone(),
            mount_count: mount_entries.len(),
            filters_applied: self.has_filters(config),
            host: host_info,
        };

        let result = SnapshotResult {
            backend: "fs".to_string(),
            action: "snapshot".to_string(),
            alias: self.alias.clone(),
            format: match config.format {
                SnapshotFormat::Json => "json",
                SnapshotFormat::Yaml => "yaml",
                SnapshotFormat::Text => "text",
            }.to_string(),
            lockfile: lockfile_content,
            parsed: summary,
        };

        Ok(serde_json::to_value(result)?)
    }

    /// Read the system mount table
    async fn read_mount_table(&self) -> Result<Vec<RawMountInfo>, anyhow::Error> {
        // Try different sources for mount information
        if cfg!(target_os = "linux") {
            self.read_linux_mounts().await
        } else if cfg!(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")) {
            self.read_bsd_mounts().await
        } else {
            Err(FsError::SnapshotUnsupported.into())
        }
    }

    /// Read mounts on Linux systems
    async fn read_linux_mounts(&self) -> Result<Vec<RawMountInfo>, anyhow::Error> {
        // Try /proc/mounts first, fall back to mount command
        if Path::new("/proc/mounts").exists() {
            let content = fs::read_to_string("/proc/mounts")
                .context("Failed to read /proc/mounts")?;
            self.parse_proc_mounts(&content)
        } else {
            self.read_mount_command().await
        }
    }

    /// Parse /proc/mounts content
    fn parse_proc_mounts(&self, content: &str) -> Result<Vec<RawMountInfo>, anyhow::Error> {
        let mut mounts = Vec::new();
        
        eprintln!("DEBUG: Parsing {} lines from /proc/mounts", content.lines().count());
        for (i, line) in content.lines().enumerate() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let mount = RawMountInfo {
                    source: parts[0].to_string(),
                    target: parts[1].to_string(),
                    fstype: parts[2].to_string(),
                    options: parts[3].to_string(),
                    dump: parts.get(4).and_then(|s| s.parse().ok()).unwrap_or(0),
                    pass: parts.get(5).and_then(|s| s.parse().ok()).unwrap_or(0),
                };
                if i < 5 || mount.fstype == "proc" || mount.fstype == "tmpfs" {
                    eprintln!("DEBUG mount {}: {} {} {} {}", i, mount.source, mount.target, mount.fstype, mount.options);
                }
                mounts.push(mount);
            }
        }
        
        eprintln!("DEBUG: Parsed {} mounts total", mounts.len());
        Ok(mounts)
    }

    /// Read mounts on BSD/macOS systems
    async fn read_bsd_mounts(&self) -> Result<Vec<RawMountInfo>, anyhow::Error> {
        self.read_mount_command().await
    }

    /// Use mount command to get mount information
    async fn read_mount_command(&self) -> Result<Vec<RawMountInfo>, anyhow::Error> {
        let output = AsyncCommand::new("mount")
            .output()
            .await
            .context("Failed to execute mount command")?;

        if !output.status.success() {
            return Err(FsError::SnapshotFailed("Failed to read mount table".to_string()).into());
        }

        let content = String::from_utf8_lossy(&output.stdout);
        self.parse_mount_output(&content)
    }

    /// Parse mount command output
    fn parse_mount_output(&self, content: &str) -> Result<Vec<RawMountInfo>, anyhow::Error> {
        let mut mounts = Vec::new();
        
        for line in content.lines() {
            if let Some(mount) = self.parse_mount_line(line) {
                mounts.push(mount);
            }
        }
        
        Ok(mounts)
    }

    /// Parse a single mount line from mount command output
    fn parse_mount_line(&self, line: &str) -> Option<RawMountInfo> {
        // Example: /dev/disk1s1 on / (apfs, local, read-only, journaled, noatime)
        // Example: /dev/sda1 on /boot type ext2 (rw,relatime)
        
        if let Some(on_pos) = line.find(" on ") {
            let source = line[..on_pos].to_string();
            let rest = &line[on_pos + 4..];
            
            // Find the mount point and type/options
            if let Some(open_paren) = rest.find('(') {
                let target_and_type = &rest[..open_paren].trim();
                let options_part = &rest[open_paren + 1..];
                let options = options_part.trim_end_matches(')').to_string();
                
                // Try to separate target and type
                let (target, fstype) = if let Some(type_pos) = target_and_type.rfind(" type ") {
                    let target = target_and_type[..type_pos].trim().to_string();
                    let fstype = target_and_type[type_pos + 6..].trim().to_string();
                    (target, fstype)
                } else {
                    // No explicit type, try to extract from options or use unknown
                    let target = target_and_type.trim().to_string();
                    let fstype = self.extract_fstype_from_options(&options).unwrap_or("unknown".to_string());
                    (target, fstype)
                };
                
                return Some(RawMountInfo {
                    source,
                    target,
                    fstype,
                    options,
                    dump: 0,
                    pass: 0,
                });
            }
        }
        
        None
    }

    /// Extract filesystem type from options string
    fn extract_fstype_from_options(&self, options: &str) -> Option<String> {
        // Common patterns to extract fs type from options
        for opt in options.split(',') {
            let opt = opt.trim();
            if opt.starts_with("type=") {
                return Some(opt[5..].to_string());
            }
        }
        None
    }

    /// Apply filters to mount list
    fn apply_snapshot_filters(&self, mounts: &[RawMountInfo], config: &SnapshotConfig) -> Result<Vec<RawMountInfo>, anyhow::Error> {
        let mut filtered = mounts.to_vec();

        // Apply include_mountpoints filter
        if !config.include_mountpoints.is_empty() {
            filtered.retain(|mount| {
                config.include_mountpoints.iter().any(|prefix| mount.target.starts_with(prefix))
            });
        }

        // Apply exclude_mountpoints filter
        if !config.exclude_mountpoints.is_empty() {
            filtered.retain(|mount| {
                !config.exclude_mountpoints.iter().any(|prefix| mount.target.starts_with(prefix))
            });
        }

        // Apply include_types filter
        if !config.include_types.is_empty() {
            filtered.retain(|mount| config.include_types.contains(&mount.fstype));
        }

        // Apply exclude_types filter
        if !config.exclude_types.is_empty() {
            filtered.retain(|mount| !config.exclude_types.contains(&mount.fstype));
        }

        // Apply include_sources filter
        if !config.include_sources.is_empty() {
            filtered.retain(|mount| config.include_sources.contains(&mount.source));
        }

        // Apply exclude_sources filter
        if !config.exclude_sources.is_empty() {
            filtered.retain(|mount| !config.exclude_sources.contains(&mount.source));
        }

        Ok(filtered)
    }

    /// Normalize filesystem path
    fn normalize_path(&self, path: &str) -> String {
        // Basic path normalization
        let mut normalized = path.replace("//", "/");
        if normalized.len() > 1 && normalized.ends_with('/') {
            normalized.pop();
        }
        if normalized.is_empty() {
            "/".to_string()
        } else {
            normalized
        }
    }

    /// Parse and sort mount options
    fn parse_and_sort_options(&self, options_str: &str) -> Vec<String> {
        let mut options: Vec<String> = options_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        options.sort();
        options
    }

    /// Get filesystem usage information
    async fn get_usage_info(&self, path: &str) -> Option<UsageInfo> {
        match fs::metadata(path) {
            Ok(_) => {
                // Use statvfs syscall or df command
                self.get_statvfs_info(path).await
            }
            Err(_) => None,
        }
    }

    /// Get filesystem usage via statvfs or df
    async fn get_statvfs_info(&self, path: &str) -> Option<UsageInfo> {
        // Try df command as a portable fallback
        let output = AsyncCommand::new("df")
            .arg("-B1") // 1-byte blocks for exact numbers
            .arg(path)
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let content = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = content.lines().collect();
        
        if lines.len() < 2 {
            return None;
        }

        // Parse df output (skip header)
        let data_line = lines[1];
        let parts: Vec<&str> = data_line.split_whitespace().collect();
        
        if parts.len() >= 4 {
            if let (Ok(size), Ok(used), Ok(available)) = (
                parts[1].parse::<u64>(),
                parts[2].parse::<u64>(),
                parts[3].parse::<u64>()
            ) {
                let used_percent = if size > 0 {
                    (used as f64 / size as f64) * 100.0
                } else {
                    0.0
                };

                return Some(UsageInfo {
                    size_bytes: size,
                    used_bytes: used,
                    free_bytes: available,
                    used_percent,
                });
            }
        }

        None
    }

    /// Get inode usage information
    async fn get_inode_info(&self, path: &str) -> Option<InodeInfo> {
        // Use df -i command for inode information
        let output = AsyncCommand::new("df")
            .arg("-i")
            .arg(path)
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let content = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = content.lines().collect();
        
        if lines.len() < 2 {
            return None;
        }

        let data_line = lines[1];
        let parts: Vec<&str> = data_line.split_whitespace().collect();
        
        if parts.len() >= 4 {
            if let (Ok(total), Ok(used), Ok(available)) = (
                parts[1].parse::<u64>(),
                parts[2].parse::<u64>(),
                parts[3].parse::<u64>()
            ) {
                let used_percent = if total > 0 {
                    (used as f64 / total as f64) * 100.0
                } else {
                    0.0
                };

                return Some(InodeInfo {
                    total,
                    used,
                    free: available,
                    used_percent,
                });
            }
        }

        None
    }

    /// Get filesystem metadata
    async fn get_fs_metadata(&self, mount: &RawMountInfo) -> Option<FsMetadata> {
        // Try to get block size and other metadata
        let path = Path::new(&mount.target);
        if let Ok(metadata) = fs::metadata(path) {
            Some(FsMetadata {
                block_size: metadata.blksize(),
                blocks: metadata.blocks(),
                flags: Vec::new(), // Could be extended with mount flags
                device: format!("{}:{}", metadata.dev() >> 8, metadata.dev() & 0xff),
            })
        } else {
            None
        }
    }

    /// Get host system information
    async fn get_host_info(&self) -> Option<HostInfo> {
        let mut hostname = String::new();
        let mut os_family = String::new();
        let mut os_name = String::new();
        let mut os_version = String::new();
        let mut kernel = String::new();
        let mut architecture = String::new();

        // Get hostname
        if let Ok(output) = AsyncCommand::new("hostname").output().await {
            if output.status.success() {
                hostname = String::from_utf8_lossy(&output.stdout).trim().to_string();
            }
        }

        // Get uname information
        if let Ok(output) = AsyncCommand::new("uname").arg("-a").output().await {
            if output.status.success() {
                let uname_output = String::from_utf8_lossy(&output.stdout);
                let parts: Vec<&str> = uname_output.split_whitespace().collect();
                
                if parts.len() >= 3 {
                    os_family = parts[0].to_string(); // Linux, Darwin, etc.
                    kernel = parts[2].to_string();    // Kernel version
                }
                
                if parts.len() >= 13 {
                    architecture = parts[12].to_string(); // Architecture
                } else if let Some(last) = parts.last() {
                    architecture = last.to_string();
                }
            }
        }

        // Try to get OS name and version
        if cfg!(target_os = "linux") {
            if let Ok(content) = fs::read_to_string("/etc/os-release") {
                for line in content.lines() {
                    if line.starts_with("NAME=") {
                        os_name = line[5..].trim_matches('"').to_string();
                    } else if line.starts_with("VERSION=") {
                        os_version = line[8..].trim_matches('"').to_string();
                    }
                }
            }
        } else if cfg!(target_os = "macos") {
            os_name = "macOS".to_string();
            if let Ok(output) = AsyncCommand::new("sw_vers").arg("-productVersion").output().await {
                if output.status.success() {
                    os_version = String::from_utf8_lossy(&output.stdout).trim().to_string();
                }
            }
        }

        // Use defaults if we couldn't determine some values
        if os_family.is_empty() {
            os_family = std::env::consts::OS.to_string();
        }
        if architecture.is_empty() {
            architecture = std::env::consts::ARCH.to_string();
        }

        Some(HostInfo {
            hostname,
            os_family,
            os_name,
            os_version,
            kernel,
            architecture,
        })
    }

    /// Check if any filters are applied
    fn has_filters(&self, config: &SnapshotConfig) -> bool {
        !config.include_mountpoints.is_empty() ||
        !config.exclude_mountpoints.is_empty() ||
        !config.include_types.is_empty() ||
        !config.exclude_types.is_empty() ||
        !config.include_sources.is_empty() ||
        !config.exclude_sources.is_empty()
    }

    /// Serialize lockfile to requested format
    fn serialize_lockfile(&self, lockfile: &SnapshotLockfile, format: &SnapshotFormat) -> Result<String, anyhow::Error> {
        match format {
            SnapshotFormat::Json => {
                serde_json::to_string_pretty(lockfile)
                    .context("Failed to serialize lockfile to JSON")
            }
            SnapshotFormat::Yaml => {
                // For now, return JSON format as YAML serialization requires additional dependency
                // In a full implementation, you would add serde_yaml dependency
                serde_json::to_string_pretty(lockfile)
                    .context("Failed to serialize lockfile to YAML")
            }
            SnapshotFormat::Text => {
                self.serialize_lockfile_text(lockfile)
            }
        }
    }

    /// Serialize lockfile to human-readable text format
    fn serialize_lockfile_text(&self, lockfile: &SnapshotLockfile) -> Result<String, anyhow::Error> {
        let mut output = String::new();
        
        output.push_str(&format!("# {}\n", lockfile.lockfile_version));
        
        if let Some(host) = &lockfile.host {
            output.push_str(&format!("host: {} ({} {} {}, kernel {})\n", 
                host.hostname, host.os_name, host.os_version, host.architecture, host.kernel));
        }
        
        output.push_str("filters:\n");
        if !lockfile.filters.include_mountpoints.is_empty() {
            output.push_str(&format!("  include_mountpoints: {:?}\n", lockfile.filters.include_mountpoints));
        }
        if !lockfile.filters.exclude_mountpoints.is_empty() {
            output.push_str(&format!("  exclude_mountpoints: {:?}\n", lockfile.filters.exclude_mountpoints));
        }
        if !lockfile.filters.include_types.is_empty() {
            output.push_str(&format!("  include_types: {:?}\n", lockfile.filters.include_types));
        }
        if !lockfile.filters.exclude_types.is_empty() {
            output.push_str(&format!("  exclude_types: {:?}\n", lockfile.filters.exclude_types));
        }
        
        output.push_str("\n");
        
        for mount in &lockfile.mounts {
            output.push_str(&format!("{} on {} type={} opts={}", 
                mount.source, mount.target, mount.fstype, mount.options.join(",")));
            
            if let Some(usage) = &mount.usage {
                output.push_str(&format!(" size={}G used={}G", 
                    usage.size_bytes / (1024 * 1024 * 1024),
                    usage.used_bytes / (1024 * 1024 * 1024)));
            }
            
            output.push('\n');
        }
        
        Ok(output)
    }

    /// Main quota operation implementation
    pub async fn quota(&self, args: Value) -> Result<Value, anyhow::Error> {
        // Parse and validate configuration
        let config = self.parse_quota_config(args)?;
        self.validate_quota_config(&config)?;

        // Execute quota operation with timeout
        let timeout_duration = Duration::from_millis(config.timeout_ms);
        let quota_result = timeout(timeout_duration, self.execute_quota(&config)).await
            .map_err(|_| FsError::QuotaTimeout)?;

        match quota_result {
            Ok(result) => Ok(result),
            Err(e) => Err(e),
        }
    }

    /// Parse quota configuration from arguments
    fn parse_quota_config(&self, args: Value) -> Result<FsQuotaConfig, anyhow::Error> {
        let mut config: FsQuotaConfig = serde_json::from_value(args.clone())
            .unwrap_or_else(|_| {
                // Handle cases where some fields might be missing, using defaults
                FsQuotaConfig {
                    path: args.get("path").and_then(|v| v.as_str().map(String::from)),
                    subject: args.get("subject").and_then(|v| v.as_str().map(String::from)),
                    subject_type: args.get("subject_type")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or(SubjectType::Auto),
                    resolve_uid_gid: args.get("resolve_uid_gid")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    include_space: args.get("include_space")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    include_inodes: args.get("include_inodes")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    include_grace: args.get("include_grace")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    all_subjects: args.get("all_subjects")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    units: args.get("units")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or(QuotaUnits::Auto),
                    timeout_ms: args.get("timeout_ms")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(5000),
                    env: args.get("env")
                        .and_then(|v| serde_json::from_value(v.clone()).ok()),
                }
            });

        // Set default timeout if not provided
        if config.timeout_ms == 0 {
            config.timeout_ms = 5000;
        }

        Ok(config)
    }

    /// Validate quota configuration
    fn validate_quota_config(&self, config: &FsQuotaConfig) -> Result<(), anyhow::Error> {
        if config.timeout_ms == 0 {
            return Err(FsError::InvalidQuotaConfig("timeout_ms must be greater than 0".to_string()).into());
        }

        if !config.include_space && !config.include_inodes {
            return Err(FsError::InvalidQuotaConfig("Either include_space or include_inodes must be true".to_string()).into());
        }

        // Validate env is string->string map if present
        if let Some(env) = &config.env {
            for (key, value) in env {
                if key.is_empty() {
                    return Err(FsError::InvalidQuotaConfig("Environment variable key cannot be empty".to_string()).into());
                }
                // Value can be empty but must be a string (validated by type)
            }
        }

        Ok(())
    }

    /// Execute the actual quota operation
    async fn execute_quota(&self, config: &FsQuotaConfig) -> Result<Value, anyhow::Error> {
        // 1. Resolve target filesystem
        let target_path = config.path.as_deref().unwrap_or("/");
        let filesystem_info = self.resolve_filesystem(target_path).await?;

        // 2. Resolve subject(s)
        let subjects_to_query = if config.all_subjects {
            self.resolve_all_subjects(&filesystem_info, config).await?
        } else {
            vec![self.resolve_single_subject(config).await?]
        };

        // 3. Check if quotas are enabled on the filesystem
        let (space_quota_enabled, inode_quota_enabled) = self.check_quota_support(&filesystem_info).await?;

        if !space_quota_enabled && !inode_quota_enabled {
            return Err(FsError::QuotaNotEnabled(format!("Filesystem {} ({}) does not have quotas enabled", 
                filesystem_info.source, filesystem_info.target)).into());
        }

        // 4. Query quotas for each subject
        let mut quota_subjects = Vec::new();
        for subject_info in subjects_to_query {
            let quota_data = self.query_subject_quota(&subject_info, &filesystem_info, config).await?;
            quota_subjects.push(quota_data);
        }

        // 5. Build response
        let result = QuotaResult {
            backend: "fs".to_string(),
            verb: "quota".to_string(),
            alias: self.alias.clone(),
            path: target_path.to_string(),
            filesystem: filesystem_info.clone(),
            subject_query: if let Some(first_subject) = quota_subjects.first() {
                QuotaSubjectQuery {
                    subject: first_subject.subject.clone(),
                    subject_type: first_subject.subject_type.clone(),
                    resolved_uid: first_subject.uid,
                    resolved_gid: first_subject.gid,
                }
            } else {
                QuotaSubjectQuery {
                    subject: config.subject.clone().unwrap_or_else(|| "unknown".to_string()),
                    subject_type: format!("{:?}", config.subject_type).to_lowercase(),
                    resolved_uid: None,
                    resolved_gid: None,
                }
            },
            units: format!("{:?}", config.units).to_lowercase(),
            space_quota_enabled,
            inode_quota_enabled,
            subjects: quota_subjects,
        };

        Ok(serde_json::to_value(result)?)
    }

    /// Resolve filesystem information for a given path
    async fn resolve_filesystem(&self, path: &str) -> Result<QuotaFilesystem, anyhow::Error> {
        // Use 'df' command to get filesystem information
        let output = AsyncCommand::new("df")
            .arg("-P")  // POSIX format
            .arg(path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to execute df command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FsError::QuotaFailed(format!("Failed to resolve filesystem for path {}: {}", path, stderr)).into());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = stdout.trim().split('\n').collect();
        
        if lines.len() < 2 {
            return Err(FsError::QuotaFailed("Unexpected df output format".to_string()).into());
        }

        // Parse the second line (first line is header)
        let parts: Vec<&str> = lines[1].split_whitespace().collect();
        if parts.len() < 6 {
            return Err(FsError::QuotaFailed("Unexpected df output format".to_string()).into());
        }

        let filesystem_source = parts[0].to_string();
        let mount_point = parts[5].to_string();

        // Get filesystem type using 'stat -f' command
        let fstype = self.get_filesystem_type(&mount_point).await?;

        Ok(QuotaFilesystem {
            source: filesystem_source,
            target: mount_point,
            fstype,
        })
    }

    /// Get filesystem type for a mount point
    async fn get_filesystem_type(&self, mount_point: &str) -> Result<String, anyhow::Error> {
        let output = AsyncCommand::new("stat")
            .arg("-f")
            .arg("-c")
            .arg("%T")  // Filesystem type
            .arg(mount_point)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await;

        match output {
            Ok(output) if output.status.success() => {
                Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
            }
            _ => {
                // Fallback: try reading from /proc/mounts
                let proc_mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();
                for line in proc_mounts.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 && parts[1] == mount_point {
                        return Ok(parts[2].to_string());
                    }
                }
                Ok("unknown".to_string())
            }
        }
    }

    /// Resolve a single subject based on config
    async fn resolve_single_subject(&self, config: &FsQuotaConfig) -> Result<QuotaSubject, anyhow::Error> {
        let subject_name = match &config.subject {
            Some(s) => s.clone(),
            None => {
                // Default to current user
                self.get_current_username().await?
            }
        };

        let (resolved_uid, resolved_gid, resolved_subject_type) = match config.subject_type {
            SubjectType::Auto => {
                // Try to determine if it's a user or group
                if subject_name.chars().all(|c| c.is_ascii_digit()) {
                    // Numeric, try as UID first
                    if let Ok(uid) = subject_name.parse::<u32>() {
                        if let Some(username) = self.uid_to_username(uid).await {
                            (Some(uid), self.username_to_gid(&username).await, "user".to_string())
                        } else {
                            // Try as GID
                            (None, Some(uid), "group".to_string())
                        }
                    } else {
                        return Err(FsError::QuotaSubjectNotFound(subject_name).into());
                    }
                } else {
                    // String, try as username first
                    if let Some(uid) = self.username_to_uid(&subject_name).await {
                        let gid = self.username_to_gid(&subject_name).await;
                        (Some(uid), gid, "user".to_string())
                    } else if let Some(gid) = self.groupname_to_gid(&subject_name).await {
                        (None, Some(gid), "group".to_string())
                    } else {
                        return Err(FsError::QuotaSubjectNotFound(subject_name).into());
                    }
                }
            }
            SubjectType::User => {
                if subject_name.chars().all(|c| c.is_ascii_digit()) {
                    let uid = subject_name.parse::<u32>()
                        .map_err(|_| FsError::QuotaSubjectNotFound(subject_name.clone()))?;
                    let gid = self.uid_to_gid(uid).await;
                    (Some(uid), gid, "user".to_string())
                } else {
                    let uid = self.username_to_uid(&subject_name).await
                        .ok_or_else(|| FsError::QuotaSubjectNotFound(subject_name.clone()))?;
                    let gid = self.username_to_gid(&subject_name).await;
                    (Some(uid), gid, "user".to_string())
                }
            }
            SubjectType::Group => {
                if subject_name.chars().all(|c| c.is_ascii_digit()) {
                    let gid = subject_name.parse::<u32>()
                        .map_err(|_| FsError::QuotaSubjectNotFound(subject_name.clone()))?;
                    (None, Some(gid), "group".to_string())
                } else {
                    let gid = self.groupname_to_gid(&subject_name).await
                        .ok_or_else(|| FsError::QuotaSubjectNotFound(subject_name.clone()))?;
                    (None, Some(gid), "group".to_string())
                }
            }
            SubjectType::Project => {
                // For now, treat project IDs as numeric only
                if subject_name.chars().all(|c| c.is_ascii_digit()) {
                    let project_id = subject_name.parse::<u32>()
                        .map_err(|_| FsError::QuotaSubjectNotFound(subject_name.clone()))?;
                    (None, Some(project_id), "project".to_string())
                } else {
                    return Err(FsError::QuotaSubjectNotFound(format!("Project ID must be numeric: {}", subject_name)).into());
                }
            }
        };

        Ok(QuotaSubject {
            subject: subject_name,
            subject_type: resolved_subject_type,
            uid: resolved_uid,
            gid: resolved_gid,
            space: None,  // Will be filled in later
            inodes: None, // Will be filled in later
        })
    }

    /// Resolve all subjects (for all_subjects=true)
    async fn resolve_all_subjects(&self, _filesystem_info: &QuotaFilesystem, _config: &FsQuotaConfig) -> Result<Vec<QuotaSubject>, anyhow::Error> {
        // For now, return an error indicating this is not yet implemented
        Err(FsError::QuotaFailed("all_subjects=true is not yet implemented".to_string()).into())
    }

    /// Check if quotas are supported/enabled on filesystem
    async fn check_quota_support(&self, _filesystem_info: &QuotaFilesystem) -> Result<(bool, bool), anyhow::Error> {
        // This is a simplified check - in a real implementation, we'd check:
        // - If quota tools are installed
        // - If quotas are enabled on the filesystem
        // - What types of quotas are supported
        
        // For now, assume quotas are supported if quota command exists
        let output = AsyncCommand::new("which")
            .arg("quota")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await;

        match output {
            Ok(output) if output.status.success() => Ok((true, true)),
            _ => Err(FsError::QuotaUnsupported.into()),
        }
    }

    /// Query quota for a specific subject
    async fn query_subject_quota(&self, subject: &QuotaSubject, filesystem_info: &QuotaFilesystem, config: &FsQuotaConfig) -> Result<QuotaSubject, anyhow::Error> {
        let mut result = subject.clone();

        // Query space quotas if requested and enabled
        if config.include_space {
            result.space = self.query_space_quota(subject, filesystem_info, config).await.ok();
        }

        // Query inode quotas if requested and enabled  
        if config.include_inodes {
            result.inodes = self.query_inode_quota(subject, filesystem_info, config).await.ok();
        }

        Ok(result)
    }

    /// Query space quota for subject
    async fn query_space_quota(&self, subject: &QuotaSubject, _filesystem_info: &QuotaFilesystem, config: &FsQuotaConfig) -> Result<SpaceQuota, anyhow::Error> {
        let quota_arg = match subject.subject_type.as_str() {
            "user" => format!("-u {}", subject.uid.unwrap_or(0)),
            "group" => format!("-g {}", subject.gid.unwrap_or(0)),
            _ => return Err(FsError::QuotaFailed("Unsupported subject type for quota query".to_string()).into()),
        };

        let mut cmd = AsyncCommand::new("quota");
        cmd.arg("-p")  // Parseable output
            .args(quota_arg.split_whitespace())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Add environment overrides if specified
        if let Some(env) = &config.env {
            for (key, value) in env {
                cmd.env(key, value);
            }
        }

        let output = cmd.output().await
            .context("Failed to execute quota command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not found") || stderr.contains("No such user") {
                return Err(FsError::QuotaSubjectNotFound(subject.subject.clone()).into());
            }
            return Err(FsError::QuotaFailed(format!("Quota query failed: {}", stderr)).into());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_quota_output(&stdout, config)
    }

    /// Query inode quota for subject
    async fn query_inode_quota(&self, subject: &QuotaSubject, _filesystem_info: &QuotaFilesystem, config: &FsQuotaConfig) -> Result<InodeQuota, anyhow::Error> {
        // Similar to space quota but for inodes
        let quota_arg = match subject.subject_type.as_str() {
            "user" => format!("-u {}", subject.uid.unwrap_or(0)),
            "group" => format!("-g {}", subject.gid.unwrap_or(0)),
            _ => return Err(FsError::QuotaFailed("Unsupported subject type for quota query".to_string()).into()),
        };

        let mut cmd = AsyncCommand::new("quota");
        cmd.arg("-p")  // Parseable output
            .arg("-i")  // Inode information
            .args(quota_arg.split_whitespace())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Add environment overrides if specified
        if let Some(env) = &config.env {
            for (key, value) in env {
                cmd.env(key, value);
            }
        }

        let output = cmd.output().await
            .context("Failed to execute quota command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not found") || stderr.contains("No such user") {
                return Err(FsError::QuotaSubjectNotFound(subject.subject.clone()).into());
            }
            return Err(FsError::QuotaFailed(format!("Inode quota query failed: {}", stderr)).into());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_inode_quota_output(&stdout, config)
    }

    /// Parse grace time string into seconds
    /// Handles various formats like "7days", "23:59:59", "expired", "never", "none", etc.
    fn parse_grace_time(&self, grace_str: &str) -> Option<u64> {
        let grace_str = grace_str.trim().to_lowercase();
        
        // Handle special cases
        match grace_str.as_str() {
            "none" | "never" | "-" | "0" | "" => return None,
            "expired" | "exceeded" => return Some(0),
            _ => {}
        }
        
        // Try to parse different time formats
        
        // Format: "7days", "14days", etc.
        if grace_str.ends_with("days") || grace_str.ends_with("day") {
            let day_str = grace_str.replace("days", "").replace("day", "");
            if let Ok(days) = day_str.parse::<u64>() {
                return Some(days * 24 * 60 * 60); // Convert to seconds
            }
        }
        
        // Format: "2hours", "5hrs", etc.  
        if grace_str.ends_with("hours") || grace_str.ends_with("hour") || grace_str.ends_with("hrs") || grace_str.ends_with("hr") {
            let hour_str = grace_str
                .replace("hours", "")
                .replace("hour", "")
                .replace("hrs", "")
                .replace("hr", "");
            if let Ok(hours) = hour_str.parse::<u64>() {
                return Some(hours * 60 * 60); // Convert to seconds
            }
        }
        
        // Format: "30mins", "45min", etc.
        if grace_str.ends_with("minutes") {
            let min_str = grace_str.replace("minutes", "");
            if let Ok(mins) = min_str.parse::<u64>() {
                return Some(mins * 60); // Convert to seconds
            }
        } else if grace_str.ends_with("mins") {
            let min_str = grace_str.replace("mins", "");
            if let Ok(mins) = min_str.parse::<u64>() {
                return Some(mins * 60); // Convert to seconds
            }
        } else if grace_str.ends_with("min") {
            let min_str = grace_str.replace("min", "");
            if let Ok(mins) = min_str.parse::<u64>() {
                return Some(mins * 60); // Convert to seconds
            }
        }
        
        // Format: "HH:MM:SS" or "HH:MM"
        if grace_str.contains(':') {
            let parts: Vec<&str> = grace_str.split(':').collect();
            match parts.len() {
                3 => {
                    // HH:MM:SS format
                    if let (Ok(hours), Ok(minutes), Ok(seconds)) = (
                        parts[0].parse::<u64>(),
                        parts[1].parse::<u64>(),
                        parts[2].parse::<u64>(),
                    ) {
                        // Validate time ranges
                        if hours <= 23 && minutes <= 59 && seconds <= 59 {
                            return Some(hours * 3600 + minutes * 60 + seconds);
                        }
                    }
                }
                2 => {
                    // HH:MM format (assume seconds are 0)
                    if let (Ok(hours), Ok(minutes)) = (
                        parts[0].parse::<u64>(),
                        parts[1].parse::<u64>(),
                    ) {
                        // Validate time ranges
                        if hours <= 23 && minutes <= 59 {
                            return Some(hours * 3600 + minutes * 60);
                        }
                    }
                }
                _ => {}
            }
        }
        
        // Format: pure seconds
        if let Ok(seconds) = grace_str.parse::<u64>() {
            return Some(seconds);
        }
        
        // Could not parse - return None to indicate unknown format
        None
    }

    /// Parse quota command output
    fn parse_quota_output(&self, output: &str, config: &FsQuotaConfig) -> Result<SpaceQuota, anyhow::Error> {
        // This is a simplified parser - real implementation would handle various quota output formats
        // Expected format (simplified): "used soft_limit hard_limit grace"
        for line in output.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let used = parts[0].parse::<u64>().unwrap_or(0);
                let soft_limit = parts[1].parse::<u64>().ok();
                let hard_limit = parts[2].parse::<u64>().ok();
                let grace_info = parts.get(3).unwrap_or(&"");

                // Convert units if needed
                let (used_converted, soft_converted, hard_converted) = match config.units {
                    QuotaUnits::Bytes => {
                        // Assume input is in KB, convert to bytes
                        (used * 1024, soft_limit.map(|x| x * 1024), hard_limit.map(|x| x * 1024))
                    }
                    QuotaUnits::Blocks => {
                        (used, soft_limit, hard_limit)
                    }
                    QuotaUnits::Auto => {
                        // Default to bytes
                        (used * 1024, soft_limit.map(|x| x * 1024), hard_limit.map(|x| x * 1024))
                    }
                };

                let grace_exceeded = grace_info.contains("expired") || grace_info.contains("exceeded");
                
                // Parse grace time from the grace_info field
                let grace_time_remaining_sec = self.parse_grace_time(grace_info);
                
                let used_percent_of_soft = if let Some(soft) = soft_converted {
                    if soft > 0 {
                        Some((used_converted as f64 / soft as f64) * 100.0)
                    } else {
                        None
                    }
                } else {
                    None
                };

                return Ok(SpaceQuota {
                    used: used_converted,
                    soft_limit: soft_converted,
                    hard_limit: hard_converted,
                    grace_exceeded,
                    grace_time_remaining_sec,
                    used_percent_of_soft,
                });
            }
        }

        Err(FsError::QuotaFailed("Could not parse quota output".to_string()).into())
    }

    /// Parse inode quota command output
    fn parse_inode_quota_output(&self, output: &str, _config: &FsQuotaConfig) -> Result<InodeQuota, anyhow::Error> {
        // Similar to parse_quota_output but for inodes
        for line in output.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let used = parts[0].parse::<u64>().unwrap_or(0);
                let soft_limit = parts[1].parse::<u64>().ok();
                let hard_limit = parts[2].parse::<u64>().ok();
                let grace_info = parts.get(3).unwrap_or(&"");

                let grace_exceeded = grace_info.contains("expired") || grace_info.contains("exceeded");
                
                // Parse grace time from the grace_info field
                let grace_time_remaining_sec = self.parse_grace_time(grace_info);
                
                let used_percent_of_soft = if let Some(soft) = soft_limit {
                    if soft > 0 {
                        Some((used as f64 / soft as f64) * 100.0)
                    } else {
                        None
                    }
                } else {
                    None
                };

                return Ok(InodeQuota {
                    used,
                    soft_limit,
                    hard_limit,
                    grace_exceeded,
                    grace_time_remaining_sec,
                    used_percent_of_soft,
                });
            }
        }

        Err(FsError::QuotaFailed("Could not parse inode quota output".to_string()).into())
    }

    // Helper functions for user/group resolution
    async fn get_current_username(&self) -> Result<String, anyhow::Error> {
        let output = AsyncCommand::new("whoami")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to get current username")?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(FsError::QuotaFailed("Could not determine current username".to_string()).into())
        }
    }

    async fn username_to_uid(&self, username: &str) -> Option<u32> {
        let output = AsyncCommand::new("id")
            .arg("-u")
            .arg(username)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await;

        match output {
            Ok(output) if output.status.success() => {
                String::from_utf8_lossy(&output.stdout).trim().parse().ok()
            }
            _ => None,
        }
    }

    async fn username_to_gid(&self, username: &str) -> Option<u32> {
        let output = AsyncCommand::new("id")
            .arg("-g")
            .arg(username)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await;

        match output {
            Ok(output) if output.status.success() => {
                String::from_utf8_lossy(&output.stdout).trim().parse().ok()
            }
            _ => None,
        }
    }

    async fn uid_to_username(&self, uid: u32) -> Option<String> {
        let output = AsyncCommand::new("getent")
            .arg("passwd")
            .arg(uid.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await;

        match output {
            Ok(output) if output.status.success() => {
                let line = String::from_utf8_lossy(&output.stdout);
                line.split(':').next().map(String::from)
            }
            _ => None,
        }
    }

    async fn uid_to_gid(&self, uid: u32) -> Option<u32> {
        let output = AsyncCommand::new("getent")
            .arg("passwd")
            .arg(uid.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await;

        match output {
            Ok(output) if output.status.success() => {
                let line = String::from_utf8_lossy(&output.stdout);
                let parts: Vec<&str> = line.trim().split(':').collect();
                if parts.len() >= 4 {
                    parts[3].parse().ok()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    async fn groupname_to_gid(&self, groupname: &str) -> Option<u32> {
        let output = AsyncCommand::new("getent")
            .arg("group")
            .arg(groupname)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await;

        match output {
            Ok(output) if output.status.success() => {
                let line = String::from_utf8_lossy(&output.stdout);
                let parts: Vec<&str> = line.trim().split(':').collect();
                if parts.len() >= 3 {
                    parts[2].parse().ok()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Main quota summary operation implementation
    pub async fn quota_summary(&self, args: Value) -> Result<Value, anyhow::Error> {
        // Parse and validate configuration
        let config = self.parse_quota_summary_config(args)?;
        self.validate_quota_summary_config(&config)?;

        // Execute quota summary operation with timeout
        let timeout_duration = Duration::from_millis(config.timeout_ms);
        let summary_result = timeout(timeout_duration, self.execute_quota_summary(&config)).await
            .map_err(|_| FsError::QuotaSummaryTimeout)?;

        match summary_result {
            Ok(result) => Ok(result),
            Err(e) => Err(e),
        }
    }

    /// Parse quota summary configuration from arguments
    pub fn parse_quota_summary_config(&self, args: Value) -> Result<FsQuotaSummaryConfig, anyhow::Error> {
        let mut config: FsQuotaSummaryConfig = serde_json::from_value(args.clone())
            .unwrap_or_else(|_| {
                // Handle cases where some fields might be missing, using defaults
                FsQuotaSummaryConfig {
                    subject: args.get("subject").and_then(|v| v.as_str().map(String::from)),
                    subject_type: args.get("subject_type")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or(SubjectType::Auto),
                    resolve_uid_gid: args.get("resolve_uid_gid")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    include_mountpoints: args.get("include_mountpoints")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_else(Vec::new),
                    exclude_mountpoints: args.get("exclude_mountpoints")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_else(Vec::new),
                    include_types: args.get("include_types")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_else(Vec::new),
                    exclude_types: args.get("exclude_types")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_else(Vec::new),
                    include_sources: args.get("include_sources")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_else(Vec::new),
                    exclude_sources: args.get("exclude_sources")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_else(Vec::new),
                    include_space: args.get("include_space")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    include_inodes: args.get("include_inodes")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    include_grace: args.get("include_grace")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    all_subjects: args.get("all_subjects")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    units: args.get("units")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or(QuotaUnits::Auto),
                    timeout_ms: args.get("timeout_ms")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(8000),
                    env: args.get("env")
                        .and_then(|v| serde_json::from_value(v.clone()).ok()),
                }
            });

        // Set default timeout if not provided
        if config.timeout_ms == 0 {
            config.timeout_ms = 8000;
        }

        Ok(config)
    }

    /// Validate quota summary configuration
    pub fn validate_quota_summary_config(&self, config: &FsQuotaSummaryConfig) -> Result<(), anyhow::Error> {
        if config.timeout_ms == 0 {
            return Err(FsError::InvalidQuotaSummaryConfig("timeout_ms must be greater than 0".to_string()).into());
        }

        if !config.include_space && !config.include_inodes {
            return Err(FsError::InvalidQuotaSummaryConfig("Either include_space or include_inodes must be true".to_string()).into());
        }

        // Validate filter arrays are string arrays (type is enforced by serde)
        // Just check for sanity
        if config.include_mountpoints.iter().any(|s| s.is_empty()) ||
           config.exclude_mountpoints.iter().any(|s| s.is_empty()) ||
           config.include_types.iter().any(|s| s.is_empty()) ||
           config.exclude_types.iter().any(|s| s.is_empty()) ||
           config.include_sources.iter().any(|s| s.is_empty()) ||
           config.exclude_sources.iter().any(|s| s.is_empty()) {
            return Err(FsError::InvalidQuotaSummaryConfig("Filter entries cannot be empty strings".to_string()).into());
        }

        // Validate env is string->string map if present
        if let Some(env) = &config.env {
            for (key, _value) in env {
                if key.is_empty() {
                    return Err(FsError::InvalidQuotaSummaryConfig("Environment variable key cannot be empty".to_string()).into());
                }
            }
        }

        Ok(())
    }

    /// Execute the actual quota summary operation
    async fn execute_quota_summary(&self, config: &FsQuotaSummaryConfig) -> Result<Value, anyhow::Error> {
        // 1. Discover and filter filesystems
        let all_filesystems = self.discover_filesystems().await?;
        let filtered_filesystems = self.apply_filesystem_filters(&all_filesystems, config);

        if filtered_filesystems.is_empty() {
            return Err(FsError::QuotaSummaryFailed("No filesystems found after applying filters".to_string()).into());
        }

        // 2. Resolve subject(s)
        let subjects_to_query = if config.all_subjects {
            self.resolve_all_subjects_for_summary(&filtered_filesystems, config).await?
        } else {
            vec![self.resolve_single_subject_for_summary(config).await?]
        };

        // 3. Query quotas on each filesystem
        let (quota_filesystems, filesystems_without_quotas, partial_failures) = 
            self.query_quota_summary_on_filesystems(&filtered_filesystems, &subjects_to_query, config).await;

        if quota_filesystems.is_empty() {
            return Err(FsError::QuotaSummaryNoQuotaFilesystems.into());
        }

        // 4. Aggregate results
        let result = if config.all_subjects {
            self.build_multi_subject_summary_result(&subjects_to_query, &quota_filesystems, &filesystems_without_quotas, &partial_failures, config)
        } else {
            self.build_single_subject_summary_result(&subjects_to_query[0], &quota_filesystems, &filesystems_without_quotas, &partial_failures, config)
        };

        Ok(serde_json::to_value(result)?)
    }

    /// Discover all mounted filesystems (similar to snapshot operation)
    async fn discover_filesystems(&self) -> Result<Vec<QuotaFilesystem>, anyhow::Error> {
        let mut filesystems = Vec::new();

        // Read /proc/mounts to discover filesystems
        let mounts_content = fs::read_to_string("/proc/mounts")
            .context("Failed to read /proc/mounts")?;

        for line in mounts_content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let source = parts[0].to_string();
                let target = parts[1].to_string();
                let fstype = parts[2].to_string();

                filesystems.push(QuotaFilesystem {
                    source,
                    target,
                    fstype,
                });
            }
        }

        Ok(filesystems)
    }

    /// Apply filters to filesystem list
    pub fn apply_filesystem_filters(&self, filesystems: &[QuotaFilesystem], config: &FsQuotaSummaryConfig) -> Vec<QuotaFilesystem> {
        let mut filtered = filesystems.to_vec();

        // Apply include_mountpoints filter
        if !config.include_mountpoints.is_empty() {
            filtered.retain(|fs| {
                config.include_mountpoints.iter().any(|prefix| fs.target.starts_with(prefix))
            });
        }

        // Apply exclude_mountpoints filter
        filtered.retain(|fs| {
            !config.exclude_mountpoints.iter().any(|prefix| fs.target.starts_with(prefix))
        });

        // Apply include_types filter
        if !config.include_types.is_empty() {
            filtered.retain(|fs| config.include_types.contains(&fs.fstype));
        }

        // Apply exclude_types filter
        filtered.retain(|fs| !config.exclude_types.contains(&fs.fstype));

        // Apply include_sources filter
        if !config.include_sources.is_empty() {
            filtered.retain(|fs| config.include_sources.contains(&fs.source));
        }

        // Apply exclude_sources filter
        filtered.retain(|fs| !config.exclude_sources.contains(&fs.source));

        filtered
    }

    /// Resolve single subject for quota summary
    async fn resolve_single_subject_for_summary(&self, config: &FsQuotaSummaryConfig) -> Result<QuotaSubject, anyhow::Error> {
        // Reuse existing logic from regular quota operation
        let temp_quota_config = FsQuotaConfig {
            path: None,
            subject: config.subject.clone(),
            subject_type: config.subject_type.clone(),
            resolve_uid_gid: config.resolve_uid_gid,
            include_space: config.include_space,
            include_inodes: config.include_inodes,
            include_grace: config.include_grace,
            all_subjects: false,
            units: config.units.clone(),
            timeout_ms: config.timeout_ms,
            env: config.env.clone(),
        };

        self.resolve_single_subject(&temp_quota_config).await
    }

    /// Resolve all subjects for quota summary (multi-subject mode)
    pub async fn resolve_all_subjects_for_summary(&self, _filesystems: &[QuotaFilesystem], _config: &FsQuotaSummaryConfig) -> Result<Vec<QuotaSubject>, anyhow::Error> {
        // For now, return an error indicating this is not yet implemented
        // In a full implementation, this would enumerate all quota subjects across the filesystems
        Err(FsError::QuotaSummaryFailed("all_subjects=true is not yet implemented".to_string()).into())
    }

    /// Query quotas on all filtered filesystems
    async fn query_quota_summary_on_filesystems(
        &self, 
        filesystems: &[QuotaFilesystem], 
        subjects: &[QuotaSubject], 
        config: &FsQuotaSummaryConfig
    ) -> (Vec<QuotaSummaryFilesystem>, Vec<FilesystemWithoutQuotas>, Vec<PartialFailure>) {
        let mut quota_filesystems = Vec::new();
        let mut filesystems_without_quotas = Vec::new();
        let mut partial_failures = Vec::new();

        for filesystem in filesystems {
            match self.query_filesystem_quotas(filesystem, subjects, config).await {
                Ok(Some(quota_fs)) => quota_filesystems.push(quota_fs),
                Ok(None) => filesystems_without_quotas.push(FilesystemWithoutQuotas {
                    source: filesystem.source.clone(),
                    target: filesystem.target.clone(),
                    fstype: filesystem.fstype.clone(),
                }),
                Err(e) => partial_failures.push(PartialFailure {
                    source: filesystem.source.clone(),
                    target: filesystem.target.clone(),
                    fstype: filesystem.fstype.clone(),
                    error: PartialFailureError {
                        code: "fs.quota_failed".to_string(),
                        message: e.to_string(),
                    },
                }),
            }
        }

        (quota_filesystems, filesystems_without_quotas, partial_failures)
    }

    /// Query quotas for a single filesystem
    async fn query_filesystem_quotas(
        &self, 
        filesystem: &QuotaFilesystem, 
        subjects: &[QuotaSubject], 
        config: &FsQuotaSummaryConfig
    ) -> Result<Option<QuotaSummaryFilesystem>, anyhow::Error> {
        // Check if quotas are supported on this filesystem
        let (space_quota_enabled, inode_quota_enabled) = match self.check_quota_support(filesystem).await {
            Ok((space, inode)) => (space, inode),
            Err(_) => return Ok(None), // Filesystem doesn't support quotas
        };

        if !space_quota_enabled && !inode_quota_enabled {
            return Ok(None); // No quotas enabled
        }

        // For single subject mode, query the first (and only) subject
        if let Some(subject) = subjects.first() {
            let temp_quota_config = FsQuotaConfig {
                path: Some(filesystem.target.clone()),
                subject: Some(subject.subject.clone()),
                subject_type: config.subject_type.clone(),
                resolve_uid_gid: config.resolve_uid_gid,
                include_space: config.include_space && space_quota_enabled,
                include_inodes: config.include_inodes && inode_quota_enabled,
                include_grace: config.include_grace,
                all_subjects: false,
                units: config.units.clone(),
                timeout_ms: config.timeout_ms,
                env: config.env.clone(),
            };

            let quota_subject = self.query_subject_quota(subject, filesystem, &temp_quota_config).await?;

            Ok(Some(QuotaSummaryFilesystem {
                source: filesystem.source.clone(),
                target: filesystem.target.clone(),
                fstype: filesystem.fstype.clone(),
                space_quota_enabled,
                inode_quota_enabled,
                space: quota_subject.space,
                inodes: quota_subject.inodes,
            }))
        } else {
            Err(anyhow::anyhow!("No subjects to query"))
        }
    }

    /// Build result for single subject summary
    fn build_single_subject_summary_result(
        &self,
        subject: &QuotaSubject,
        quota_filesystems: &[QuotaSummaryFilesystem],
        filesystems_without_quotas: &[FilesystemWithoutQuotas],
        partial_failures: &[PartialFailure],
        config: &FsQuotaSummaryConfig,
    ) -> QuotaSummaryResult {
        // Aggregate quota data across all filesystems
        let (space_summary, inode_summary) = self.aggregate_quota_data(quota_filesystems, config);

        QuotaSummaryResult {
            backend: "fs".to_string(),
            verb: "quota_summary".to_string(),
            alias: self.alias.clone(),
            subject_query: Some(QuotaSubjectQuery {
                subject: subject.subject.clone(),
                subject_type: subject.subject_type.clone(),
                resolved_uid: subject.uid,
                resolved_gid: subject.gid,
            }),
            filters: QuotaSummaryFilters {
                include_mountpoints: config.include_mountpoints.clone(),
                exclude_mountpoints: config.exclude_mountpoints.clone(),
                include_types: config.include_types.clone(),
                exclude_types: config.exclude_types.clone(),
                include_sources: config.include_sources.clone(),
                exclude_sources: config.exclude_sources.clone(),
            },
            units: format!("{:?}", config.units).to_lowercase(),
            include_space: config.include_space,
            include_inodes: config.include_inodes,
            summary: Some(QuotaSummaryData {
                space: space_summary,
                inodes: inode_summary,
            }),
            all_subjects: false,
            subjects: None,
            filesystems: quota_filesystems.to_vec(),
            filesystems_without_quotas: filesystems_without_quotas.to_vec(),
            partial_failures: partial_failures.to_vec(),
        }
    }

    /// Build result for multi-subject summary
    fn build_multi_subject_summary_result(
        &self,
        subjects: &[QuotaSubject],
        quota_filesystems: &[QuotaSummaryFilesystem],
        filesystems_without_quotas: &[FilesystemWithoutQuotas],
        partial_failures: &[PartialFailure],
        config: &FsQuotaSummaryConfig,
    ) -> QuotaSummaryResult {
        // Aggregate quota data for each subject across all filesystems
        let subject_summaries = subjects.iter().map(|subject| {
            self.aggregate_subject_quota_across_filesystems(subject, quota_filesystems, config)
        }).collect();

        QuotaSummaryResult {
            backend: "fs".to_string(),
            verb: "quota_summary".to_string(),
            alias: self.alias.clone(),
            subject_query: None,
            filters: QuotaSummaryFilters {
                include_mountpoints: config.include_mountpoints.clone(),
                exclude_mountpoints: config.exclude_mountpoints.clone(),
                include_types: config.include_types.clone(),
                exclude_types: config.exclude_types.clone(),
                include_sources: config.include_sources.clone(),
                exclude_sources: config.exclude_sources.clone(),
            },
            units: format!("{:?}", config.units).to_lowercase(),
            include_space: config.include_space,
            include_inodes: config.include_inodes,
            summary: None,
            all_subjects: true,
            subjects: Some(subject_summaries),
            filesystems: quota_filesystems.to_vec(),
            filesystems_without_quotas: filesystems_without_quotas.to_vec(),
            partial_failures: partial_failures.to_vec(),
        }
    }

    /// Aggregate quota data across all filesystems for a single subject
    pub fn aggregate_quota_data(
        &self,
        quota_filesystems: &[QuotaSummaryFilesystem],
        config: &FsQuotaSummaryConfig,
    ) -> (Option<SpaceQuotaSummary>, Option<InodeQuotaSummary>) {
        let mut total_space_used = 0u64;
        let mut total_space_soft = 0u64;
        let mut total_space_hard = 0u64;
        let mut any_space_grace_exceeded = false;
        let mut has_space_data = false;

        let mut total_inode_used = 0u64;
        let mut total_inode_soft = 0u64;
        let mut total_inode_hard = 0u64;
        let mut any_inode_grace_exceeded = false;
        let mut has_inode_data = false;

        for fs in quota_filesystems {
            // Aggregate space data
            if config.include_space && fs.space_quota_enabled {
                if let Some(space) = &fs.space {
                    has_space_data = true;
                    total_space_used += space.used;
                    if let Some(soft) = space.soft_limit {
                        total_space_soft += soft;
                    }
                    if let Some(hard) = space.hard_limit {
                        total_space_hard += hard;
                    }
                    if space.grace_exceeded {
                        any_space_grace_exceeded = true;
                    }
                }
            }

            // Aggregate inode data
            if config.include_inodes && fs.inode_quota_enabled {
                if let Some(inodes) = &fs.inodes {
                    has_inode_data = true;
                    total_inode_used += inodes.used;
                    if let Some(soft) = inodes.soft_limit {
                        total_inode_soft += soft;
                    }
                    if let Some(hard) = inodes.hard_limit {
                        total_inode_hard += hard;
                    }
                    if inodes.grace_exceeded {
                        any_inode_grace_exceeded = true;
                    }
                }
            }
        }

        let space_summary = if has_space_data {
            let used_percent_of_soft = if total_space_soft > 0 {
                Some((total_space_used as f64 / total_space_soft as f64) * 100.0)
            } else {
                None
            };

            Some(SpaceQuotaSummary {
                used: total_space_used,
                soft_limit: if total_space_soft > 0 { Some(total_space_soft) } else { None },
                hard_limit: if total_space_hard > 0 { Some(total_space_hard) } else { None },
                used_percent_of_soft,
                any_grace_exceeded: any_space_grace_exceeded,
            })
        } else {
            None
        };

        let inode_summary = if has_inode_data {
            let used_percent_of_soft = if total_inode_soft > 0 {
                Some((total_inode_used as f64 / total_inode_soft as f64) * 100.0)
            } else {
                None
            };

            Some(InodeQuotaSummary {
                used: total_inode_used,
                soft_limit: if total_inode_soft > 0 { Some(total_inode_soft) } else { None },
                hard_limit: if total_inode_hard > 0 { Some(total_inode_hard) } else { None },
                used_percent_of_soft,
                any_grace_exceeded: any_inode_grace_exceeded,
            })
        } else {
            None
        };

        (space_summary, inode_summary)
    }

    /// Aggregate quota data for a single subject across all filesystems
    fn aggregate_subject_quota_across_filesystems(
        &self,
        subject: &QuotaSubject,
        quota_filesystems: &[QuotaSummaryFilesystem],
        config: &FsQuotaSummaryConfig,
    ) -> SubjectSummary {
        // In the current architecture, quota_filesystems contain quota data for the first subject only
        // For multi-subject mode, we would need a different data flow, but for now we'll work with
        // the existing single-subject data and just copy the subject information
        
        // Aggregate space quota data from all filesystems
        let space_summary = if config.include_space {
            let mut total_space_used = 0u64;
            let mut total_space_soft = 0u64;
            let mut total_space_hard = 0u64;
            let mut any_space_grace_exceeded = false;
            let mut has_space_data = false;

            for fs in quota_filesystems {
                if fs.space_quota_enabled {
                    if let Some(space) = &fs.space {
                        has_space_data = true;
                        total_space_used += space.used;
                        if let Some(soft) = space.soft_limit {
                            total_space_soft += soft;
                        }
                        if let Some(hard) = space.hard_limit {
                            total_space_hard += hard;
                        }
                        if space.grace_time_remaining_sec == Some(0) {
                            any_space_grace_exceeded = true;
                        }
                    }
                }
            }

            if has_space_data {
                let used_percent_of_soft = if total_space_soft > 0 {
                    Some((total_space_used as f64 / total_space_soft as f64) * 100.0)
                } else {
                    None
                };

                Some(SpaceQuotaSummary {
                    used: total_space_used,
                    soft_limit: if total_space_soft > 0 { Some(total_space_soft) } else { None },
                    hard_limit: if total_space_hard > 0 { Some(total_space_hard) } else { None },
                    used_percent_of_soft,
                    any_grace_exceeded: any_space_grace_exceeded,
                })
            } else {
                None
            }
        } else {
            None
        };

        // Aggregate inode quota data from all filesystems
        let inode_summary = if config.include_inodes {
            let mut total_inode_used = 0u64;
            let mut total_inode_soft = 0u64;
            let mut total_inode_hard = 0u64;
            let mut any_inode_grace_exceeded = false;
            let mut has_inode_data = false;

            for fs in quota_filesystems {
                if fs.inode_quota_enabled {
                    if let Some(inodes) = &fs.inodes {
                        has_inode_data = true;
                        total_inode_used += inodes.used;
                        if let Some(soft) = inodes.soft_limit {
                            total_inode_soft += soft;
                        }
                        if let Some(hard) = inodes.hard_limit {
                            total_inode_hard += hard;
                        }
                        if inodes.grace_time_remaining_sec == Some(0) {
                            any_inode_grace_exceeded = true;
                        }
                    }
                }
            }

            if has_inode_data {
                let used_percent_of_soft = if total_inode_soft > 0 {
                    Some((total_inode_used as f64 / total_inode_soft as f64) * 100.0)
                } else {
                    None
                };

                Some(InodeQuotaSummary {
                    used: total_inode_used,
                    soft_limit: if total_inode_soft > 0 { Some(total_inode_soft) } else { None },
                    hard_limit: if total_inode_hard > 0 { Some(total_inode_hard) } else { None },
                    used_percent_of_soft,
                    any_grace_exceeded: any_inode_grace_exceeded,
                })
            } else {
                None
            }
        } else {
            None
        };

        SubjectSummary {
            subject: subject.subject.clone(),
            subject_type: subject.subject_type.clone(),
            uid: subject.uid,
            gid: subject.gid,
            space: space_summary,
            inodes: inode_summary,
        }
    }

    /// Main usage operation implementation
    pub async fn usage(&self, args: Value) -> Result<Value, anyhow::Error> {
        // Parse and validate configuration
        let config = self.parse_usage_config(args)?;
        self.validate_usage_config(&config)?;

        // Execute usage operation with timeout
        let timeout_duration = Duration::from_millis(config.timeout_ms);
        let usage_result = timeout(timeout_duration, self.execute_usage(&config)).await
            .map_err(|_| FsError::UsageTimeout)?;

        match usage_result {
            Ok(result) => Ok(result),
            Err(e) => Err(e),
        }
    }

    /// Parse usage configuration from arguments
    fn parse_usage_config(&self, args: Value) -> Result<FsUsageConfig, anyhow::Error> {
        let mut config: FsUsageConfig = serde_json::from_value(args.clone())
            .unwrap_or_else(|_| {
                // Handle cases where some fields might be missing, using defaults
                FsUsageConfig {
                    paths: args.get("paths")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_else(Vec::new),
                    mode: args.get("mode")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or(UsageMode::Mounts),
                    include_mountpoints: args.get("include_mountpoints")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_else(Vec::new),
                    exclude_mountpoints: args.get("exclude_mountpoints")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_else(Vec::new),
                    include_types: args.get("include_types")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_else(Vec::new),
                    exclude_types: args.get("exclude_types")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_else(Vec::new),
                    include_sources: args.get("include_sources")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_else(Vec::new),
                    exclude_sources: args.get("exclude_sources")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_else(Vec::new),
                    include_inodes: args.get("include_inodes")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    include_readonly: args.get("include_readonly")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    normalize_paths: args.get("normalize_paths")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    units: args.get("units")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or(UsageUnits::Auto),
                    human_readable: args.get("human_readable")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    threshold_used_percent_min: args.get("threshold_used_percent_min")
                        .and_then(|v| v.as_f64()),
                    threshold_used_percent_max: args.get("threshold_used_percent_max")
                        .and_then(|v| v.as_f64()),
                    timeout_ms: args.get("timeout_ms")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(5000),
                    env: args.get("env")
                        .and_then(|v| serde_json::from_value(v.clone()).ok()),
                }
            });

        // Handle potential string values for enum fields
        if let Some(mode_str) = args.get("mode").and_then(|v| v.as_str()) {
            config.mode = match mode_str {
                "mounts" => UsageMode::Mounts,
                "paths" => UsageMode::Paths,
                "aggregate" => UsageMode::Aggregate,
                _ => config.mode,
            };
        }

        if let Some(units_str) = args.get("units").and_then(|v| v.as_str()) {
            config.units = match units_str {
                "auto" => UsageUnits::Auto,
                "bytes" => UsageUnits::Bytes,
                "kilobytes" => UsageUnits::Kilobytes,
                "megabytes" => UsageUnits::Megabytes,
                "gigabytes" => UsageUnits::Gigabytes,
                "blocks" => UsageUnits::Blocks,
                _ => config.units,
            };
        }

        Ok(config)
    }

    /// Validate usage configuration
    fn validate_usage_config(&self, config: &FsUsageConfig) -> Result<(), anyhow::Error> {
        if config.timeout_ms == 0 {
            return Err(FsError::InvalidUsageConfig("timeout_ms must be greater than 0".to_string()).into());
        }

        if let Some(min) = config.threshold_used_percent_min {
            if min < 0.0 || min > 100.0 {
                return Err(FsError::InvalidUsageConfig("threshold_used_percent_min must be between 0 and 100".to_string()).into());
            }
        }

        if let Some(max) = config.threshold_used_percent_max {
            if max < 0.0 || max > 100.0 {
                return Err(FsError::InvalidUsageConfig("threshold_used_percent_max must be between 0 and 100".to_string()).into());
            }
        }

        if let (Some(min), Some(max)) = (config.threshold_used_percent_min, config.threshold_used_percent_max) {
            if min > max {
                return Err(FsError::InvalidUsageConfig("threshold_used_percent_min cannot be greater than threshold_used_percent_max".to_string()).into());
            }
        }

        if config.mode == UsageMode::Paths && config.paths.is_empty() {
            return Err(FsError::InvalidUsageConfig("paths cannot be empty when mode is 'paths'".to_string()).into());
        }

        Ok(())
    }

    /// Execute the actual usage operation
    async fn execute_usage(&self, config: &FsUsageConfig) -> Result<Value, anyhow::Error> {
        // 1. Read current mount table
        let raw_mounts = self.read_mount_table().await?;

        // 2. Select filesystems based on mode and paths
        let mut selected_mounts = if config.mode == UsageMode::Paths && !config.paths.is_empty() {
            self.resolve_paths_to_filesystems(&raw_mounts, &config.paths).await?
        } else {
            raw_mounts
        };

        // 3. Apply filters
        selected_mounts = self.apply_usage_filters(&selected_mounts, config)?;

        // 4. Check if any filesystems remain after filtering
        if selected_mounts.is_empty() {
            return Ok(serde_json::to_value(UsageResult {
                backend: "fs".to_string(),
                verb: "usage".to_string(),
                alias: self.alias.clone(),
                mode: format!("{:?}", config.mode).to_lowercase(),
                units: format!("{:?}", config.units).to_lowercase(),
                include_inodes: config.include_inodes,
                filters: self.build_usage_filters(config),
                filesystems: Vec::new(),
                aggregate: None,
                path_to_filesystem: None,
            })?);
        }

        // 5. Collect usage statistics for each filesystem
        let mut filesystem_usages = Vec::new();
        for mount in selected_mounts {
            let usage = self.get_filesystem_usage(&mount, config).await?;
            filesystem_usages.push(usage);
        }

        // 6. Apply threshold filters
        if let Some(min_threshold) = config.threshold_used_percent_min {
            filesystem_usages.retain(|fs| {
                fs.used_percent.map_or(false, |pct| pct >= min_threshold)
            });
        }

        if let Some(max_threshold) = config.threshold_used_percent_max {
            filesystem_usages.retain(|fs| {
                fs.used_percent.map_or(true, |pct| pct <= max_threshold)
            });
        }

        // 7. Sort filesystems deterministically
        filesystem_usages.sort_by(|a, b| {
            a.target.cmp(&b.target)
                .then_with(|| a.source.cmp(&b.source))
                .then_with(|| a.fstype.cmp(&b.fstype))
        });

        // 8. Compute aggregate if requested
        let aggregate = if config.mode == UsageMode::Aggregate {
            Some(self.compute_aggregate_usage(&filesystem_usages, config))
        } else {
            None
        };

        // 9. Build path to filesystem mapping if mode is paths
        let path_to_filesystem = if config.mode == UsageMode::Paths {
            Some(self.build_path_to_filesystem_mapping(&config.paths, &filesystem_usages).await?)
        } else {
            None
        };

        // 10. Build result
        let result = UsageResult {
            backend: "fs".to_string(),
            verb: "usage".to_string(),
            alias: self.alias.clone(),
            mode: format!("{:?}", config.mode).to_lowercase(),
            units: format!("{:?}", config.units).to_lowercase(),
            include_inodes: config.include_inodes,
            filters: self.build_usage_filters(config),
            filesystems: filesystem_usages,
            aggregate,
            path_to_filesystem,
        };

        Ok(serde_json::to_value(result)?)
    }

    /// Resolve paths to their underlying filesystems
    async fn resolve_paths_to_filesystems(
        &self,
        mounts: &[RawMountInfo],
        paths: &[String],
    ) -> Result<Vec<RawMountInfo>, anyhow::Error> {
        let mut resolved_mounts = Vec::new();
        let mut seen_targets = std::collections::HashSet::new();

        for path in paths {
            // Check if path exists
            if !Path::new(path).exists() {
                return Err(FsError::PathNotFound(path.clone()).into());
            }

            // Find the mountpoint that contains this path
            let mut best_match: Option<&RawMountInfo> = None;
            let mut best_match_len = 0;

            for mount in mounts {
                if path.starts_with(&mount.target) && mount.target.len() > best_match_len {
                    best_match = Some(mount);
                    best_match_len = mount.target.len();
                }
            }

            if let Some(mount) = best_match {
                if seen_targets.insert(mount.target.clone()) {
                    resolved_mounts.push(mount.clone());
                }
            }
        }

        Ok(resolved_mounts)
    }

    /// Apply filters to mount list
    fn apply_usage_filters(
        &self,
        mounts: &[RawMountInfo],
        config: &FsUsageConfig,
    ) -> Result<Vec<RawMountInfo>, anyhow::Error> {
        let mut filtered = mounts.to_vec();

        // Apply include_mountpoints filter
        if !config.include_mountpoints.is_empty() {
            filtered.retain(|mount| {
                config.include_mountpoints.iter().any(|prefix| mount.target.starts_with(prefix))
            });
        }

        // Apply exclude_mountpoints filter
        if !config.exclude_mountpoints.is_empty() {
            filtered.retain(|mount| {
                !config.exclude_mountpoints.iter().any(|prefix| mount.target.starts_with(prefix))
            });
        }

        // Apply include_types filter
        if !config.include_types.is_empty() {
            filtered.retain(|mount| config.include_types.contains(&mount.fstype));
        }

        // Apply exclude_types filter
        if !config.exclude_types.is_empty() {
            filtered.retain(|mount| !config.exclude_types.contains(&mount.fstype));
        }

        // Apply include_sources filter
        if !config.include_sources.is_empty() {
            filtered.retain(|mount| config.include_sources.contains(&mount.source));
        }

        // Apply exclude_sources filter
        if !config.exclude_sources.is_empty() {
            filtered.retain(|mount| !config.exclude_sources.contains(&mount.source));
        }

        // Apply read-only filter
        if !config.include_readonly {
            filtered.retain(|mount| !mount.options.contains("ro"));
        }

        Ok(filtered)
    }

    /// Get filesystem usage statistics
    async fn get_filesystem_usage(
        &self,
        mount: &RawMountInfo,
        config: &FsUsageConfig,
    ) -> Result<FilesystemUsage, anyhow::Error> {
        // Use the existing statvfs-based implementation
        let usage_info = self.get_statvfs_info(&mount.target).await
            .ok_or_else(|| FsError::UsageFailed(format!("Failed to get usage info for {}", mount.target)))?;

        let inode_info = if config.include_inodes {
            self.get_inode_info(&mount.target).await.map(|info| FilesystemInodes {
                total: info.total,
                used: info.used,
                free: info.free,
                used_percent: Some(info.used_percent),
            })
        } else {
            None
        };

        // Convert units if requested
        let (size, used, free) = self.convert_usage_units(
            usage_info.size_bytes,
            usage_info.used_bytes,
            usage_info.free_bytes,
            &config.units,
        );

        // Generate human readable strings if requested
        let (size_human, used_human, free_human) = if config.human_readable {
            (
                Some(self.format_human_readable(usage_info.size_bytes)),
                Some(self.format_human_readable(usage_info.used_bytes)),
                Some(self.format_human_readable(usage_info.free_bytes)),
            )
        } else {
            (None, None, None)
        };

        Ok(FilesystemUsage {
            source: mount.source.clone(),
            target: if config.normalize_paths {
                self.normalize_path(&mount.target)
            } else {
                mount.target.clone()
            },
            fstype: mount.fstype.clone(),
            read_only: mount.options.contains("ro"),
            size,
            used,
            free,
            used_percent: Some(usage_info.used_percent),
            size_human,
            used_human,
            free_human,
            inodes: inode_info,
        })
    }

    /// Convert usage values according to specified units
    fn convert_usage_units(
        &self,
        size_bytes: u64,
        used_bytes: u64,
        free_bytes: u64,
        units: &UsageUnits,
    ) -> (u64, u64, u64) {
        match units {
            UsageUnits::Auto | UsageUnits::Bytes => (size_bytes, used_bytes, free_bytes),
            UsageUnits::Kilobytes => (size_bytes / 1024, used_bytes / 1024, free_bytes / 1024),
            UsageUnits::Megabytes => (size_bytes / (1024 * 1024), used_bytes / (1024 * 1024), free_bytes / (1024 * 1024)),
            UsageUnits::Gigabytes => (size_bytes / (1024 * 1024 * 1024), used_bytes / (1024 * 1024 * 1024), free_bytes / (1024 * 1024 * 1024)),
            UsageUnits::Blocks => {
                // Assume 512-byte blocks (traditional Unix block size)
                (size_bytes / 512, used_bytes / 512, free_bytes / 512)
            }
        }
    }

    /// Format bytes in human-readable format
    fn format_human_readable(&self, bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "K", "M", "G", "T", "P"];
        const THRESHOLD: u64 = 1024;

        if bytes < THRESHOLD {
            return format!("{}B", bytes);
        }

        let mut size = bytes as f64;
        let mut unit_index = 0;

        while size >= THRESHOLD as f64 && unit_index < UNITS.len() - 1 {
            size /= THRESHOLD as f64;
            unit_index += 1;
        }

        format!("{:.1}{}", size, UNITS[unit_index])
    }

    /// Compute aggregate usage across filesystems
    fn compute_aggregate_usage(
        &self,
        filesystems: &[FilesystemUsage],
        config: &FsUsageConfig,
    ) -> AggregateUsage {
        let total_size: u64 = filesystems.iter().map(|fs| fs.size).sum();
        let total_used: u64 = filesystems.iter().map(|fs| fs.used).sum();
        let total_free: u64 = filesystems.iter().map(|fs| fs.free).sum();

        let used_percent = if total_size > 0 {
            Some((total_used as f64 / total_size as f64) * 100.0)
        } else {
            None
        };

        let (size_human, used_human, free_human) = if config.human_readable {
            // Convert back to bytes for human readable formatting
            let (size_bytes, used_bytes, free_bytes) = match config.units {
                UsageUnits::Auto | UsageUnits::Bytes => (total_size, total_used, total_free),
                UsageUnits::Kilobytes => (total_size * 1024, total_used * 1024, total_free * 1024),
                UsageUnits::Megabytes => (total_size * 1024 * 1024, total_used * 1024 * 1024, total_free * 1024 * 1024),
                UsageUnits::Gigabytes => (total_size * 1024 * 1024 * 1024, total_used * 1024 * 1024 * 1024, total_free * 1024 * 1024 * 1024),
                UsageUnits::Blocks => (total_size * 512, total_used * 512, total_free * 512),
            };
            (
                Some(self.format_human_readable(size_bytes)),
                Some(self.format_human_readable(used_bytes)),
                Some(self.format_human_readable(free_bytes)),
            )
        } else {
            (None, None, None)
        };

        // Aggregate inode information if available
        let inodes = if config.include_inodes {
            let total_inodes: u64 = filesystems.iter()
                .filter_map(|fs| fs.inodes.as_ref())
                .map(|inodes| inodes.total)
                .sum();
            let used_inodes: u64 = filesystems.iter()
                .filter_map(|fs| fs.inodes.as_ref())
                .map(|inodes| inodes.used)
                .sum();
            let free_inodes: u64 = filesystems.iter()
                .filter_map(|fs| fs.inodes.as_ref())
                .map(|inodes| inodes.free)
                .sum();

            if total_inodes > 0 {
                Some(FilesystemInodes {
                    total: total_inodes,
                    used: used_inodes,
                    free: free_inodes,
                    used_percent: Some((used_inodes as f64 / total_inodes as f64) * 100.0),
                })
            } else {
                None
            }
        } else {
            None
        };

        AggregateUsage {
            size: total_size,
            used: total_used,
            free: total_free,
            used_percent,
            size_human,
            used_human,
            free_human,
            inodes,
        }
    }

    /// Build path to filesystem mapping
    async fn build_path_to_filesystem_mapping(
        &self,
        paths: &[String],
        filesystems: &[FilesystemUsage],
    ) -> Result<Vec<PathToFilesystem>, anyhow::Error> {
        let mut mapping = Vec::new();

        for path in paths {
            // Find the filesystem that contains this path
            let mut best_match: Option<&FilesystemUsage> = None;
            let mut best_match_len = 0;

            for fs in filesystems {
                if path.starts_with(&fs.target) && fs.target.len() > best_match_len {
                    best_match = Some(fs);
                    best_match_len = fs.target.len();
                }
            }

            if let Some(fs) = best_match {
                mapping.push(PathToFilesystem {
                    path: path.clone(),
                    target: fs.target.clone(),
                    source: fs.source.clone(),
                });
            }
        }

        Ok(mapping)
    }

    /// Build usage filters for result
    fn build_usage_filters(&self, config: &FsUsageConfig) -> UsageFilters {
        UsageFilters {
            include_mountpoints: config.include_mountpoints.clone(),
            exclude_mountpoints: config.exclude_mountpoints.clone(),
            include_types: config.include_types.clone(),
            exclude_types: config.exclude_types.clone(),
            include_sources: config.include_sources.clone(),
            exclude_sources: config.exclude_sources.clone(),
            threshold_used_percent_min: config.threshold_used_percent_min,
            threshold_used_percent_max: config.threshold_used_percent_max,
        }
    }

    /// Main resize operation implementation
    pub async fn resize(&self, args: Value) -> Result<Value, anyhow::Error> {
        // Parse and validate configuration
        let config = self.parse_resize_config(args)?;
        self.validate_resize_config(&config)?;

        // Execute resize operation with timeout
        let timeout_duration = Duration::from_millis(config.timeout_ms);
        timeout(timeout_duration, self.execute_resize(&config))
            .await
            .map_err(|_| FsError::ResizeTimeout)?
    }

    /// Parse resize configuration from input arguments
    fn parse_resize_config(&self, args: Value) -> Result<FsResizeConfig, anyhow::Error> {
        let mut config: FsResizeConfig = if args.is_null() {
            FsResizeConfig::default()
        } else {
            serde_json::from_value(args)
                .context("Failed to parse resize configuration")?
        };

        // Apply defaults if not provided
        if config.target.is_empty() {
            config.target = String::new();
        }

        Ok(config)
    }

    /// Validate resize configuration
    fn validate_resize_config(&self, config: &FsResizeConfig) -> Result<(), anyhow::Error> {
        // Basic field validation
        if config.target.is_empty() {
            return Err(FsError::InvalidResizeConfig("target is required and cannot be empty".to_string()).into());
        }

        if config.timeout_ms == 0 {
            return Err(FsError::InvalidResizeConfig("timeout_ms must be greater than 0".to_string()).into());
        }

        // Size/delta validation
        let size_provided = config.size.is_some();
        let delta_provided = config.delta.is_some();

        if !size_provided && !delta_provided {
            return Err(FsError::InvalidResizeConfig("exactly one of 'size' or 'delta' must be specified".to_string()).into());
        }

        if size_provided && delta_provided {
            return Err(FsError::InvalidResizeConfig("cannot specify both 'size' and 'delta'".to_string()).into());
        }

        // Min free space validation
        if config.min_free_space_percent < 0.0 || config.min_free_space_percent > 100.0 {
            return Err(FsError::InvalidResizeConfig("min_free_space_percent must be between 0 and 100".to_string()).into());
        }

        // Contradictory options validation
        if config.volume_resize_only && config.filesystem_resize_only {
            return Err(FsError::InvalidResizeConfig("volume_resize_only and filesystem_resize_only are mutually exclusive".to_string()).into());
        }

        // Shrink mode validation
        if config.mode == ResizeMode::Shrink && !config.allow_shrink {
            return Err(FsError::ResizeShrinkNotAllowed.into());
        }

        // Environment validation
        if let Some(env) = &config.env {
            for (key, _) in env {
                if key.is_empty() {
                    return Err(FsError::InvalidResizeConfig("environment variable keys cannot be empty".to_string()).into());
                }
            }
        }

        Ok(())
    }

    /// Execute the resize operation
    async fn execute_resize(&self, config: &FsResizeConfig) -> Result<Value, anyhow::Error> {
        // Discover filesystem information
        let fs_info = self.discover_filesystem(&config.target, &config.by).await?;
        
        // Validate filesystem type support
        self.validate_filesystem_support(&fs_info.fstype, config)?;

        // Parse and compute target size
        let current_size = self.get_current_filesystem_size(&fs_info).await?;
        let target_size = self.compute_target_size(config, current_size)?;

        // Determine operation type (grow/shrink/noop)
        let delta_bytes = target_size as i64 - current_size as i64;
        
        if delta_bytes == 0 {
            // No-op case
            return Ok(json!(ResizeResult {
                backend: "fs".to_string(),
                verb: "resize".to_string(),
                alias: Some(self.alias.clone()),
                target: config.target.clone(),
                by: format!("{:?}", config.by).to_lowercase(),
                filesystem: ResizeFilesystemInfo {
                    source: fs_info.source.clone(),
                    fstype: fs_info.fstype.clone(),
                    mounted: fs_info.mounted,
                    current_size_bytes: current_size,
                    requested_size_bytes: Some(target_size),
                    delta_bytes: Some(0),
                },
                requested_size_bytes: Some(target_size),
                previous_size_bytes: Some(current_size),
                final_size_bytes: Some(current_size),
                delta_bytes: Some(0),
                mode: format!("{:?}", config.mode).to_lowercase(),
                action: "noop".to_string(),
                reason: Some("requested size equals current filesystem size".to_string()),
                actions: None,
                summary: None,
                dry_run: Some(config.dry_run),
                plan: None,
            }));
        }

        // Determine actual operation mode and validate
        let is_shrink = delta_bytes < 0;
        if is_shrink {
            if config.mode == ResizeMode::Grow {
                return Err(FsError::InvalidResizeConfig("cannot shrink when mode is 'grow'".to_string()).into());
            }
            if !config.allow_shrink {
                return Err(FsError::ResizeShrinkNotAllowed.into());
            }
            
            // Check filesystem support for shrinking
            match fs_info.fstype.as_str() {
                "xfs" => {
                    return Err(FsError::ResizeShrinkNotSupportedForFilesystem(fs_info.fstype.clone()).into());
                }
                "ext3" | "ext4" => {
                    if config.require_unmounted_for_shrink && fs_info.mounted {
                        return Err(FsError::ResizeShrinkRequiresUnmount(config.target.clone()).into());
                    }
                }
                _ => {}
            }

            // Check min free space constraint
            self.validate_min_free_space(&fs_info, target_size, config.min_free_space_percent).await?;
        } else if config.mode == ResizeMode::Shrink {
            return Err(FsError::InvalidResizeConfig("cannot grow when mode is 'shrink'".to_string()).into());
        }

        // Check device capacity constraints for grow operations
        if !is_shrink && !config.filesystem_resize_only {
            let device_size = self.get_device_size(&fs_info.source).await?;
            if !config.manage_underlying_volume && target_size > device_size {
                return Err(FsError::ResizeTargetExceedsDevice.into());
            }
        }

        if config.dry_run {
            return self.build_resize_plan(config, &fs_info, current_size, target_size).await;
        }

        // Execute actual resize
        let mut actions = Vec::new();
        let previous_size = current_size;

        // Handle volume resize first for grow operations
        if !is_shrink && config.manage_underlying_volume && !config.filesystem_resize_only {
            let volume_action = self.resize_underlying_volume(&fs_info.source, target_size, false).await?;
            actions.push(volume_action);
        }

        // Handle filesystem resize
        if !config.volume_resize_only {
            let fs_action = self.resize_filesystem(&fs_info, target_size, config).await?;
            actions.push(fs_action);
        }

        // Handle volume resize after for shrink operations
        if is_shrink && config.manage_underlying_volume && !config.filesystem_resize_only {
            let volume_action = self.resize_underlying_volume(&fs_info.source, target_size, true).await?;
            actions.push(volume_action);
        }

        // Get final size
        let final_size = self.get_current_filesystem_size(&fs_info).await?;

        Ok(json!(ResizeResult {
            backend: "fs".to_string(),
            verb: "resize".to_string(),
            alias: Some(self.alias.clone()),
            target: config.target.clone(),
            by: format!("{:?}", config.by).to_lowercase(),
            filesystem: ResizeFilesystemInfo {
                source: fs_info.source,
                fstype: fs_info.fstype,
                mounted: fs_info.mounted,
                current_size_bytes: previous_size,
                requested_size_bytes: Some(target_size),
                delta_bytes: Some(delta_bytes),
            },
            requested_size_bytes: Some(target_size),
            previous_size_bytes: Some(previous_size),
            final_size_bytes: Some(final_size),
            delta_bytes: Some(delta_bytes),
            mode: format!("{:?}", config.mode).to_lowercase(),
            action: "success".to_string(),
            reason: None,
            actions: Some(actions),
            summary: Some(ResizeSummary {
                status: "success".to_string(),
                shrink: is_shrink,
                grew: !is_shrink,
            }),
            dry_run: Some(false),
            plan: None,
        }))
    }

    /// Discover filesystem information based on target and method
    async fn discover_filesystem(&self, target: &str, by: &ResizeTargetKind) -> Result<ResizeFilesystemInfo, anyhow::Error> {
        match by {
            ResizeTargetKind::Auto => {
                // Try mountpoint first, then device
                if let Ok(fs_info) = self.discover_by_mountpoint(target).await {
                    Ok(fs_info)
                } else {
                    self.discover_by_device(target).await
                }
            }
            ResizeTargetKind::Mountpoint => {
                self.discover_by_mountpoint(target).await
            }
            ResizeTargetKind::Device => {
                self.discover_by_device(target).await
            }
        }
    }

    /// Discover filesystem by mountpoint
    async fn discover_by_mountpoint(&self, mountpoint: &str) -> Result<ResizeFilesystemInfo, anyhow::Error> {
        let mounts = self.get_existing_mounts().await?;
        
        for mount in &mounts {
            if mount.target == mountpoint {
                let current_size = self.get_filesystem_size_by_mountpoint(mountpoint).await?;
                
                return Ok(ResizeFilesystemInfo {
                    source: mount.source.clone(),
                    fstype: mount.fs_type.clone(),
                    mounted: true,
                    current_size_bytes: current_size,
                    requested_size_bytes: None,
                    delta_bytes: None,
                });
            }
        }
        
        Err(FsError::ResizeTargetNotFound(format!("mountpoint not found: {}", mountpoint)).into())
    }

    /// Discover filesystem by device
    async fn discover_by_device(&self, device: &str) -> Result<ResizeFilesystemInfo, anyhow::Error> {
        let mounts = self.get_existing_mounts().await?;
        
        // Check if device is currently mounted
        let mount = mounts.iter().find(|m| m.source == device);
        let (mounted, fstype) = if let Some(mount) = mount {
            (true, mount.fs_type.clone())
        } else {
            (false, self.detect_filesystem_type(device).await
                .map_err(|_| FsError::ResizeTargetNotFound(format!("cannot determine filesystem type for: {}", device)))?)
        };

        let current_size = self.get_device_size(device).await?;
        
        Ok(ResizeFilesystemInfo {
            source: device.to_string(),
            fstype,
            mounted,
            current_size_bytes: current_size,
            requested_size_bytes: None,
            delta_bytes: None,
        })
    }

    /// Detect filesystem type for unmounted device
    async fn detect_filesystem_type(&self, device: &str) -> Result<String, anyhow::Error> {
        let output = AsyncCommand::new("blkid")
            .arg("-s")
            .arg("TYPE")
            .arg("-o")
            .arg("value")
            .arg(device)
            .output()
            .await;

        if let Ok(output) = output {
            if output.status.success() {
                let fstype = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !fstype.is_empty() {
                    return Ok(fstype);
                }
            }
        }

        // Fallback: try file command
        let output = AsyncCommand::new("file")
            .arg("-s")
            .arg(device)
            .output()
            .await;

        if let Ok(output) = output {
            if output.status.success() {
                let file_output = String::from_utf8_lossy(&output.stdout);
                if file_output.contains("ext4") {
                    return Ok("ext4".to_string());
                } else if file_output.contains("ext3") {
                    return Ok("ext3".to_string());
                } else if file_output.contains("ext2") {
                    return Ok("ext2".to_string());
                } else if file_output.contains("XFS") {
                    return Ok("xfs".to_string());
                } else if file_output.contains("BTRFS") {
                    return Ok("btrfs".to_string());
                }
            }
        }

        // Return generic error that can be handled by callers
        Err(anyhow::anyhow!("unable to detect filesystem type for: {}", device))
    }

    /// Validate filesystem type is supported for resize operations
    fn validate_filesystem_support(&self, fstype: &str, config: &FsResizeConfig) -> Result<(), anyhow::Error> {
        match fstype {
            "ext3" | "ext4" | "xfs" | "btrfs" => Ok(()),
            _ => Err(FsError::ResizeUnsupportedFilesystem(fstype.to_string()).into())
        }
    }

    /// Parse human-readable size string to bytes
    fn parse_size(&self, size_value: &Value, units: &SizeUnits) -> Result<u64, anyhow::Error> {
        match size_value {
            Value::Number(n) => {
                let bytes = n.as_u64().ok_or_else(|| {
                    FsError::InvalidResizeConfig("size must be a positive integer".to_string())
                })?;
                
                // Apply unit conversion if not auto/bytes
                match units {
                    SizeUnits::Auto | SizeUnits::Bytes => Ok(bytes),
                    SizeUnits::Kilobytes => Ok(bytes * 1024),
                    SizeUnits::Megabytes => Ok(bytes * 1024 * 1024),
                    SizeUnits::Gigabytes => Ok(bytes * 1024 * 1024 * 1024),
                    SizeUnits::Terabytes => Ok(bytes * 1024 * 1024 * 1024 * 1024),
                }
            }
            Value::String(s) => {
                self.parse_human_readable_size(s)
            }
            _ => Err(FsError::InvalidResizeConfig("size must be a number or string".to_string()).into())
        }
    }

    /// Parse human-readable size strings like "100G", "50GiB"
    fn parse_human_readable_size(&self, size_str: &str) -> Result<u64, anyhow::Error> {
        let size_str = size_str.trim();
        if size_str.is_empty() {
            return Err(FsError::InvalidResizeConfig("size string cannot be empty".to_string()).into());
        }

        // Handle delta prefixes
        let (multiplier, size_str) = if let Some(stripped) = size_str.strip_prefix('+') {
            (1, stripped)
        } else if let Some(stripped) = size_str.strip_prefix('-') {
            (-1, stripped)
        } else {
            (1, size_str)
        };

        // Extract numeric part and unit
        let (number_part, unit_part) = if size_str.chars().last().unwrap_or('0').is_ascii_digit() {
            (size_str, "")
        } else {
            let mut split_pos = size_str.len();
            for (i, ch) in size_str.char_indices().rev() {
                if ch.is_ascii_digit() || ch == '.' {
                    split_pos = i + ch.len_utf8();
                    break;
                }
            }
            (&size_str[..split_pos], &size_str[split_pos..])
        };

        let number: f64 = number_part.parse()
            .map_err(|_| FsError::InvalidResizeConfig(format!("invalid number format: {}", number_part)))?;

        if number < 0.0 && multiplier > 0 {
            return Err(FsError::InvalidResizeConfig("size cannot be negative".to_string()).into());
        }

        let base_bytes = match unit_part.to_uppercase().as_str() {
            "" | "B" => number,
            "K" | "KB" | "KIB" => number * 1024.0,
            "M" | "MB" | "MIB" => number * 1024.0 * 1024.0,
            "G" | "GB" | "GIB" => number * 1024.0 * 1024.0 * 1024.0,
            "T" | "TB" | "TIB" => number * 1024.0 * 1024.0 * 1024.0 * 1024.0,
            _ => return Err(FsError::InvalidResizeConfig(format!("unknown size unit: {}", unit_part)).into()),
        };

        let final_bytes = (base_bytes * multiplier as f64) as i64;
        if final_bytes < 0 {
            Err(FsError::InvalidResizeConfig("calculated size cannot be negative".to_string()).into())
        } else {
            Ok(final_bytes as u64)
        }
    }

    /// Compute target size from configuration
    fn compute_target_size(&self, config: &FsResizeConfig, current_size: u64) -> Result<u64, anyhow::Error> {
        if let Some(size_value) = &config.size {
            self.parse_size(size_value, &config.size_units)
        } else if let Some(delta_value) = &config.delta {
            let delta = self.parse_size(delta_value, &config.size_units)? as i64;
            let target = current_size as i64 + delta;
            if target < 0 {
                Err(FsError::ResizeInvalidTargetSize("target size cannot be negative".to_string()).into())
            } else {
                Ok(target as u64)
            }
        } else {
            Err(FsError::InvalidResizeConfig("either size or delta must be specified".to_string()).into())
        }
    }

    /// Get current filesystem size
    async fn get_current_filesystem_size(&self, fs_info: &ResizeFilesystemInfo) -> Result<u64, anyhow::Error> {
        if fs_info.mounted {
            self.get_filesystem_size_by_mountpoint(&fs_info.source).await
        } else {
            self.get_device_size(&fs_info.source).await
        }
    }

    /// Get filesystem size by mountpoint using statvfs
    async fn get_filesystem_size_by_mountpoint(&self, mountpoint: &str) -> Result<u64, anyhow::Error> {
        let output = AsyncCommand::new("df")
            .arg("-B")
            .arg("1")
            .arg(mountpoint)
            .output()
            .await?;

        if !output.status.success() {
            return Err(FsError::ResizeTargetNotFound(format!("cannot get size for mountpoint: {}", mountpoint)).into());
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = output_str.lines().collect();
        
        if lines.len() < 2 {
            return Err(FsError::ResizeTargetNotFound("invalid df output".to_string()).into());
        }

        let fields: Vec<&str> = lines[1].split_whitespace().collect();
        if fields.len() < 2 {
            return Err(FsError::ResizeTargetNotFound("invalid df output format".to_string()).into());
        }

        let size_str = fields[1];
        size_str.parse::<u64>()
            .map_err(|_| FsError::ResizeTargetNotFound("cannot parse filesystem size".to_string()).into())
    }

    /// Get device size using blockdev
    async fn get_device_size(&self, device: &str) -> Result<u64, anyhow::Error> {
        let output = AsyncCommand::new("blockdev")
            .arg("--getsize64")
            .arg(device)
            .output()
            .await?;

        if !output.status.success() {
            return Err(FsError::ResizeTargetNotFound(format!("cannot get size for device: {}", device)).into());
        }

        let size_str = String::from_utf8_lossy(&output.stdout);
        let size_str = size_str.trim();
        size_str.parse::<u64>()
            .map_err(|_| FsError::ResizeTargetNotFound("cannot parse device size".to_string()).into())
    }

    /// Validate minimum free space constraint for shrink operations
    async fn validate_min_free_space(&self, fs_info: &ResizeFilesystemInfo, target_size: u64, min_free_percent: f64) -> Result<(), anyhow::Error> {
        if !fs_info.mounted {
            // Can't check used space for unmounted filesystem - assume it's OK
            return Ok(());
        }

        let output = AsyncCommand::new("df")
            .arg("-B")
            .arg("1")
            .arg(&fs_info.source)
            .output()
            .await?;

        if !output.status.success() {
            // If we can't get usage info, proceed with caution
            return Ok(());
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = output_str.lines().collect();
        
        if lines.len() < 2 {
            return Ok(());
        }

        let fields: Vec<&str> = lines[1].split_whitespace().collect();
        if fields.len() < 3 {
            return Ok(());
        }

        let used_bytes: u64 = fields[2].parse().unwrap_or(0);
        let required_free_bytes = (min_free_percent / 100.0) * target_size as f64;
        let would_be_free = target_size as f64 - used_bytes as f64;

        if would_be_free < required_free_bytes {
            return Err(FsError::ResizeWouldViolateMinFree.into());
        }

        Ok(())
    }

    /// Resize the underlying volume (LVM)
    async fn resize_underlying_volume(&self, device: &str, target_size: u64, is_shrink: bool) -> Result<ResizeAction, anyhow::Error> {
        if !self.is_lvm_device(device).await? {
            return Err(FsError::ResizeVolumeManagementUnsupported.into());
        }

        let command = if is_shrink {
            format!("lvreduce -L {}b -f {}", target_size, device)
        } else {
            format!("lvextend -L {}b {}", target_size, device)
        };

        let output = AsyncCommand::new("sh")
            .arg("-c")
            .arg(&command)
            .output()
            .await?;

        let status = if output.status.success() {
            "success".to_string()
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(FsError::ResizeFailed(format!("volume resize failed: {}", error_msg)).into());
        };

        Ok(ResizeAction {
            r#type: "volume_resize".to_string(),
            tool: if is_shrink { "lvreduce" } else { "lvextend" }.to_string(),
            status,
            command,
        })
    }

    /// Check if device is an LVM logical volume
    async fn is_lvm_device(&self, device: &str) -> Result<bool, anyhow::Error> {
        // Simple check - LVM devices usually are under /dev/mapper or contain /dev/vg
        if device.starts_with("/dev/mapper/") {
            return Ok(true);
        }

        // Check with lsblk to see if it's LVM type
        let output = AsyncCommand::new("lsblk")
            .arg("-no")
            .arg("TYPE")
            .arg(device)
            .output()
            .await?;

        if !output.status.success() {
            return Ok(false);
        }

        let device_type = String::from_utf8_lossy(&output.stdout);
        let device_type = device_type.trim();
        Ok(device_type == "lvm")
    }

    /// Resize the filesystem itself
    async fn resize_filesystem(&self, fs_info: &ResizeFilesystemInfo, target_size: u64, config: &FsResizeConfig) -> Result<ResizeAction, anyhow::Error> {
        match fs_info.fstype.as_str() {
            "ext3" | "ext4" => self.resize_ext_filesystem(fs_info, target_size).await,
            "xfs" => self.resize_xfs_filesystem(fs_info).await,
            "btrfs" => self.resize_btrfs_filesystem(fs_info, target_size).await,
            _ => Err(FsError::ResizeUnsupportedFilesystem(fs_info.fstype.clone()).into())
        }
    }

    /// Resize ext3/ext4 filesystem
    async fn resize_ext_filesystem(&self, fs_info: &ResizeFilesystemInfo, target_size: u64) -> Result<ResizeAction, anyhow::Error> {
        // Calculate target in filesystem blocks (4KB blocks for ext)
        let block_size = 4096; // Default ext4 block size
        let target_blocks = target_size / block_size;
        
        let command = format!("resize2fs {} {}K", fs_info.source, target_blocks);
        
        let output = AsyncCommand::new("resize2fs")
            .arg(&fs_info.source)
            .arg(format!("{}K", target_blocks))
            .output()
            .await?;

        let status = if output.status.success() {
            "success".to_string()
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(FsError::ResizeFailed(format!("ext filesystem resize failed: {}", error_msg)).into());
        };

        Ok(ResizeAction {
            r#type: "filesystem_resize".to_string(),
            tool: "resize2fs".to_string(),
            status,
            command,
        })
    }

    /// Resize XFS filesystem (grow only)
    async fn resize_xfs_filesystem(&self, fs_info: &ResizeFilesystemInfo) -> Result<ResizeAction, anyhow::Error> {
        if !fs_info.mounted {
            return Err(FsError::ResizeFailed("XFS must be mounted to resize".to_string()).into());
        }

        // Find mount point for this device
        let mounts = self.get_existing_mounts().await?;
        let mount_point = mounts.iter()
            .find(|m| m.source == fs_info.source)
            .map(|m| &m.target)
            .ok_or_else(|| FsError::ResizeFailed("cannot find mount point for XFS filesystem".to_string()))?;

        let command = format!("xfs_growfs {}", mount_point);
        
        let output = AsyncCommand::new("xfs_growfs")
            .arg(mount_point)
            .output()
            .await?;

        let status = if output.status.success() {
            "success".to_string()
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(FsError::ResizeFailed(format!("XFS filesystem resize failed: {}", error_msg)).into());
        };

        Ok(ResizeAction {
            r#type: "filesystem_resize".to_string(),
            tool: "xfs_growfs".to_string(),
            status,
            command,
        })
    }

    /// Resize Btrfs filesystem
    async fn resize_btrfs_filesystem(&self, fs_info: &ResizeFilesystemInfo, target_size: u64) -> Result<ResizeAction, anyhow::Error> {
        // Find mount point for this device
        let mounts = self.get_existing_mounts().await?;
        let mount_point = mounts.iter()
            .find(|m| m.source == fs_info.source)
            .map(|m| &m.target)
            .ok_or_else(|| FsError::ResizeFailed("btrfs must be mounted to resize".to_string()))?;

        let command = format!("btrfs filesystem resize {} {}", target_size, mount_point);
        
        let output = AsyncCommand::new("btrfs")
            .arg("filesystem")
            .arg("resize")
            .arg(target_size.to_string())
            .arg(mount_point)
            .output()
            .await?;

        let status = if output.status.success() {
            "success".to_string()
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(FsError::ResizeFailed(format!("btrfs filesystem resize failed: {}", error_msg)).into());
        };

        Ok(ResizeAction {
            r#type: "filesystem_resize".to_string(),
            tool: "btrfs".to_string(),
            status,
            command,
        })
    }

    /// Build resize plan for dry-run
    async fn build_resize_plan(&self, config: &FsResizeConfig, fs_info: &ResizeFilesystemInfo, current_size: u64, target_size: u64) -> Result<Value, anyhow::Error> {
        let mut steps = Vec::new();
        let delta_bytes = target_size as i64 - current_size as i64;
        let is_shrink = delta_bytes < 0;

        // Add volume resize step for grow operations
        if !is_shrink && config.manage_underlying_volume && !config.filesystem_resize_only {
            if self.is_lvm_device(&fs_info.source).await? {
                steps.push(ResizeAction {
                    r#type: "volume_resize".to_string(),
                    tool: "lvextend".to_string(),
                    status: "planned".to_string(),
                    command: format!("lvextend -L {}b {}", target_size, fs_info.source),
                });
            }
        }

        // Add filesystem resize step
        if !config.volume_resize_only {
            let (tool, command) = match fs_info.fstype.as_str() {
                "ext3" | "ext4" => {
                    let target_blocks = target_size / 4096;
                    ("resize2fs".to_string(), format!("resize2fs {} {}K", fs_info.source, target_blocks))
                }
                "xfs" => {
                    let mount_point = if fs_info.mounted {
                        // Find mount point
                        let mounts = self.get_existing_mounts().await?;
                        mounts.iter()
                            .find(|m| m.source == fs_info.source)
                            .map(|m| m.target.clone())
                            .unwrap_or_else(|| "/unknown".to_string())
                    } else {
                        "/unknown".to_string()
                    };
                    ("xfs_growfs".to_string(), format!("xfs_growfs {}", mount_point))
                }
                "btrfs" => {
                    let mount_point = if fs_info.mounted {
                        // Find mount point
                        let mounts = self.get_existing_mounts().await?;
                        mounts.iter()
                            .find(|m| m.source == fs_info.source)
                            .map(|m| m.target.clone())
                            .unwrap_or_else(|| "/unknown".to_string())
                    } else {
                        "/unknown".to_string()
                    };
                    ("btrfs".to_string(), format!("btrfs filesystem resize {} {}", target_size, mount_point))
                }
                _ => ("unknown".to_string(), "unsupported filesystem".to_string())
            };

            steps.push(ResizeAction {
                r#type: "filesystem_resize".to_string(),
                tool,
                status: "planned".to_string(),
                command,
            });
        }

        // Add volume resize step for shrink operations
        if is_shrink && config.manage_underlying_volume && !config.filesystem_resize_only {
            if self.is_lvm_device(&fs_info.source).await? {
                steps.push(ResizeAction {
                    r#type: "volume_resize".to_string(),
                    tool: "lvreduce".to_string(),
                    status: "planned".to_string(),
                    command: format!("lvreduce -L {}b -f {}", target_size, fs_info.source),
                });
            }
        }

        Ok(json!(ResizeResult {
            backend: "fs".to_string(),
            verb: "resize".to_string(),
            alias: Some(self.alias.clone()),
            target: config.target.clone(),
            by: format!("{:?}", config.by).to_lowercase(),
            filesystem: ResizeFilesystemInfo {
                source: fs_info.source.clone(),
                fstype: fs_info.fstype.clone(),
                mounted: fs_info.mounted,
                current_size_bytes: current_size,
                requested_size_bytes: Some(target_size),
                delta_bytes: Some(delta_bytes),
            },
            requested_size_bytes: Some(target_size),
            previous_size_bytes: Some(current_size),
            final_size_bytes: Some(target_size),
            delta_bytes: Some(delta_bytes),
            mode: format!("{:?}", config.mode).to_lowercase(),
            action: "plan".to_string(),
            reason: None,
            actions: None,
            summary: None,
            dry_run: Some(true),
            plan: Some(ResizePlan { steps }),
        }))
    }

    /// Main check operation implementation
    pub async fn check(&self, args: Value) -> Result<Value, anyhow::Error> {
        // Parse and validate configuration
        let config = self.parse_check_config(args)?;
        self.validate_check_config(&config)?;

        // Execute check operation with timeout
        let timeout_duration = Duration::from_millis(config.timeout_ms);
        timeout(timeout_duration, self.execute_check(&config))
            .await
            .map_err(|_| FsError::CheckTimeout)?
    }

    /// Parse check configuration from input arguments
    fn parse_check_config(&self, args: Value) -> Result<FsCheckConfig, anyhow::Error> {
        let config: FsCheckConfig = serde_json::from_value(args)
            .context("Failed to parse check configuration")?;

        // Apply defaults
        if config.target.is_empty() {
            return Err(FsError::InvalidCheckConfig("target cannot be empty".to_string()).into());
        }

        Ok(config)
    }

    /// Validate check configuration
    fn validate_check_config(&self, config: &FsCheckConfig) -> Result<(), anyhow::Error> {
        // Validate target
        if config.target.is_empty() {
            return Err(FsError::InvalidCheckConfig("target cannot be empty".to_string()).into());
        }

        // Validate timeout
        if config.timeout_ms == 0 {
            return Err(FsError::InvalidCheckConfig("timeout_ms must be greater than 0".to_string()).into());
        }

        // Check repair permissions
        if config.mode == CheckMode::Repair && !config.allow_repair {
            return Err(FsError::CheckRepairNotAllowed.into());
        }

        // Validate environment variables if provided
        if let Some(ref env) = config.env {
            for (key, value) in env.iter() {
                if key.is_empty() || value.is_empty() {
                    return Err(FsError::InvalidCheckConfig(
                        "environment variable keys and values cannot be empty".to_string()
                    ).into());
                }
            }
        }

        Ok(())
    }

    /// Execute the check operation
    async fn execute_check(&self, config: &FsCheckConfig) -> Result<Value, anyhow::Error> {
        // Resolve target to get filesystem information
        let fs_info = self.resolve_check_target(config).await?;
        
        // Apply skip policies
        if let Some(skip_result) = self.apply_check_skip_policies(config, &fs_info)? {
            return Ok(serde_json::to_value(skip_result)?);
        }

        // Validate filesystem support
        self.validate_check_filesystem_support(&fs_info.fstype)?;

        // Enforce policy constraints
        self.enforce_check_policies(config, &fs_info)?;

        // Select appropriate tool and build command
        let (tool_name, args_vec) = self.select_check_tool(config, &fs_info)?;

        // Dry-run: return plan without execution
        if config.dry_run {
            return Ok(serde_json::to_value(CheckResult {
                backend: "fs".to_string(),
                verb: "check".to_string(),
                alias: Some(self.alias.clone()),
                target: config.target.clone(),
                by: format!("{:?}", config.by).to_lowercase(),
                filesystem: Some(fs_info.clone()),
                mode: format!("{:?}", config.mode).to_lowercase(),
                allow_repair: config.allow_repair,
                tool: None,
                analysis: None,
                summary: CheckSummary {
                    status: "success".to_string(),
                    skipped_reason: None,
                },
                action: None,
                reason: None,
                dry_run: Some(true),
                plan: Some(CheckPlan {
                    tool: tool_name.clone(),
                    arguments: args_vec.clone(),
                    requires_unmount_for_repair: config.require_unmounted_for_repair,
                    would_run: true,
                }),
            })?);
        }

        // Execute the check tool
        let tool_result = self.execute_check_tool(config, &tool_name, &args_vec).await?;

        // Analyze results
        let analysis = self.analyze_check_results(config, &fs_info, &tool_result)?;

        // Build final result
        Ok(serde_json::to_value(CheckResult {
            backend: "fs".to_string(),
            verb: "check".to_string(),
            alias: Some(self.alias.clone()),
            target: config.target.clone(),
            by: format!("{:?}", config.by).to_lowercase(),
            filesystem: Some(fs_info),
            mode: format!("{:?}", config.mode).to_lowercase(),
            allow_repair: config.allow_repair,
            tool: Some(tool_result),
            analysis: Some(analysis),
            summary: CheckSummary {
                status: "success".to_string(),
                skipped_reason: None,
            },
            action: None,
            reason: None,
            dry_run: None,
            plan: None,
        })?)
    }

    /// Resolve the check target to filesystem information
    async fn resolve_check_target(&self, config: &FsCheckConfig) -> Result<CheckFilesystemInfo, anyhow::Error> {
        match config.by {
            CheckTargetKind::Mountpoint => self.resolve_target_by_mountpoint(config).await,
            CheckTargetKind::Device => self.resolve_target_by_device(config).await,
            CheckTargetKind::Auto => {
                // Try mountpoint first, then device
                if let Ok(fs_info) = self.resolve_target_by_mountpoint(config).await {
                    Ok(fs_info)
                } else {
                    self.resolve_target_by_device(config).await
                }
            }
        }
    }

    /// Resolve target by mountpoint
    async fn resolve_target_by_mountpoint(&self, config: &FsCheckConfig) -> Result<CheckFilesystemInfo, anyhow::Error> {
        let mounts = self.get_existing_mounts().await?;
        
        for mount in mounts {
            if mount.target == config.target {
                let readonly = mount.options.iter().any(|opt| opt == "ro");
                return Ok(CheckFilesystemInfo {
                    source: mount.source,
                    fstype: config.filesystem_type.clone().unwrap_or(mount.fs_type),
                    mounted: true,
                    readonly,
                });
            }
        }
        
        Err(FsError::CheckTargetNotFound(format!("mountpoint not found: {}", config.target)).into())
    }

    /// Resolve target by device
    async fn resolve_target_by_device(&self, config: &FsCheckConfig) -> Result<CheckFilesystemInfo, anyhow::Error> {
        let device_path = config.target.clone();
        
        // Check if device exists
        if !tokio::fs::metadata(&device_path).await.is_ok() {
            return Err(FsError::CheckTargetNotFound(format!("device not found: {}", device_path)).into());
        }

        // Check if device is mounted
        let mounts = self.get_existing_mounts().await?;
        let mut mounted = false;
        let mut readonly = false;
        
        for mount in mounts {
            if mount.source == device_path {
                mounted = true;
                readonly = mount.options.iter().any(|opt| opt == "ro");
                break;
            }
        }

        // Determine filesystem type
        let fstype = if let Some(ref fs_type) = config.filesystem_type {
            fs_type.clone()
        } else {
            self.detect_filesystem_type(&device_path).await
                .map_err(|_| FsError::CheckUnsupportedFilesystem("unable to detect filesystem type".to_string()))?
        };

        Ok(CheckFilesystemInfo {
            source: device_path,
            fstype,
            mounted,
            readonly,
        })
    }

    /// Apply skip policies
    fn apply_check_skip_policies(&self, config: &FsCheckConfig, fs_info: &CheckFilesystemInfo) -> Result<Option<CheckResult>, anyhow::Error> {
        if config.skip_if_mounted && fs_info.mounted {
            return Ok(Some(CheckResult {
                backend: "fs".to_string(),
                verb: "check".to_string(),
                alias: Some(self.alias.clone()),
                target: config.target.clone(),
                by: format!("{:?}", config.by).to_lowercase(),
                filesystem: Some(fs_info.clone()),
                mode: format!("{:?}", config.mode).to_lowercase(),
                allow_repair: config.allow_repair,
                tool: None,
                analysis: None,
                summary: CheckSummary {
                    status: "skipped".to_string(),
                    skipped_reason: Some("Filesystem is mounted and skip_if_mounted=true".to_string()),
                },
                action: Some("skipped_mounted".to_string()),
                reason: Some("Filesystem is mounted and skip_if_mounted=true".to_string()),
                dry_run: None,
                plan: None,
            }));
        }

        Ok(None)
    }

    /// Validate filesystem support for check operations
    fn validate_check_filesystem_support(&self, fstype: &str) -> Result<(), anyhow::Error> {
        match fstype {
            "ext2" | "ext3" | "ext4" | "vfat" | "reiserfs" | "xfs" | "btrfs" => Ok(()),
            _ => Err(FsError::CheckUnsupportedFilesystem(fstype.to_string()).into()),
        }
    }

    /// Enforce check policies
    fn enforce_check_policies(&self, config: &FsCheckConfig, fs_info: &CheckFilesystemInfo) -> Result<(), anyhow::Error> {
        // Check if repair requires unmounting
        if config.mode == CheckMode::Repair && config.require_unmounted_for_repair && fs_info.mounted && !fs_info.readonly {
            return Err(FsError::CheckRequiresUnmountForRepair(fs_info.source.clone()).into());
        }

        // Check if online check is allowed
        if !config.allow_online_check && fs_info.mounted {
            // For some filesystems, we might not have offline tools available
            if fs_info.fstype == "btrfs" && !config.btrfs_allow_offline_check {
                return Err(FsError::CheckMustBeOffline(fs_info.source.clone()).into());
            }
        }

        Ok(())
    }

    /// Select appropriate tool for the filesystem
    fn select_check_tool(&self, config: &FsCheckConfig, fs_info: &CheckFilesystemInfo) -> Result<(String, Vec<String>), anyhow::Error> {
        match fs_info.fstype.as_str() {
            "ext2" | "ext3" | "ext4" | "vfat" | "reiserfs" => {
                self.build_fsck_command(config, fs_info)
            },
            "xfs" => {
                self.build_xfs_repair_command(config, fs_info)
            },
            "btrfs" => {
                self.build_btrfs_command(config, fs_info)
            },
            _ => Err(FsError::CheckUnsupportedFilesystem(fs_info.fstype.clone()).into()),
        }
    }

    /// Build fsck command for ext* and other fsck-supported filesystems
    fn build_fsck_command(&self, config: &FsCheckConfig, fs_info: &CheckFilesystemInfo) -> Result<(String, Vec<String>), anyhow::Error> {
        let tool_name = format!("fsck.{}", fs_info.fstype);
        let mut args = vec![];

        match config.mode {
            CheckMode::Check => {
                args.push("-n".to_string()); // no-op mode
                if config.aggressiveness == CheckAggressiveness::Aggressive {
                    args.push("-f".to_string()); // force check
                }
            },
            CheckMode::Repair => {
                if config.allow_repair {
                    args.push("-p".to_string()); // preen mode (safe auto-repair)
                } else {
                    args.push("-n".to_string()); // fallback to no-op
                }
            },
            CheckMode::Auto => {
                if config.allow_repair {
                    args.push("-p".to_string()); // preen mode
                } else {
                    args.push("-n".to_string()); // check only
                }
                if config.aggressiveness == CheckAggressiveness::Aggressive {
                    args.push("-f".to_string());
                }
            },
        }

        args.push(fs_info.source.clone());

        Ok((tool_name, args))
    }

    /// Build xfs_repair command
    fn build_xfs_repair_command(&self, config: &FsCheckConfig, fs_info: &CheckFilesystemInfo) -> Result<(String, Vec<String>), anyhow::Error> {
        let tool_name = "xfs_repair".to_string();
        let mut args = vec![];

        match config.mode {
            CheckMode::Check => {
                args.push("-n".to_string()); // no-modify mode
            },
            CheckMode::Repair => {
                if config.allow_repair && !fs_info.mounted {
                    // Don't add -n for actual repair
                } else {
                    args.push("-n".to_string()); // fallback to check-only
                }
            },
            CheckMode::Auto => {
                if config.allow_repair && !fs_info.mounted {
                    // Auto mode with repair allowed
                } else {
                    args.push("-n".to_string()); // check-only
                }
            },
        }

        args.push(fs_info.source.clone());

        Ok((tool_name, args))
    }

    /// Build btrfs command (scrub or check)
    fn build_btrfs_command(&self, config: &FsCheckConfig, fs_info: &CheckFilesystemInfo) -> Result<(String, Vec<String>), anyhow::Error> {
        let tool_name = "btrfs".to_string();
        let mut args = vec![];

        if fs_info.mounted && config.btrfs_use_scrub {
            // Online scrub
            args.push("scrub".to_string());
            args.push("start".to_string());
            args.push("-B".to_string()); // run in foreground
            args.push(config.target.clone()); // mountpoint for scrub
        } else if !fs_info.mounted || config.btrfs_allow_offline_check {
            // Offline check
            args.push("check".to_string());
            
            match config.mode {
                CheckMode::Check => {
                    args.push("--readonly".to_string());
                },
                CheckMode::Repair => {
                    if config.allow_repair && !fs_info.mounted {
                        args.push("--repair".to_string());
                    } else {
                        args.push("--readonly".to_string());
                    }
                },
                CheckMode::Auto => {
                    if config.allow_repair && !fs_info.mounted {
                        args.push("--repair".to_string());
                    } else {
                        args.push("--readonly".to_string());
                    }
                },
            }
            
            args.push(fs_info.source.clone());
        } else {
            return Err(FsError::CheckMustBeOffline(fs_info.source.clone()).into());
        }

        Ok((tool_name, args))
    }

    /// Execute the check tool
    async fn execute_check_tool(&self, config: &FsCheckConfig, tool_name: &str, args: &[String]) -> Result<CheckTool, anyhow::Error> {
        // Check if tool is available
        self.check_tool_available(tool_name).await?;

        let full_command = format!("{} {}", tool_name, args.join(" "));

        let mut cmd = AsyncCommand::new(tool_name);
        cmd.args(args)
           .stdout(Stdio::piped())
           .stderr(Stdio::piped());

        // Apply environment variables
        if let Some(ref env) = config.env {
            for (key, value) in env.iter() {
                cmd.env(key, value);
            }
        }

        let output = cmd.output().await
            .map_err(|e| FsError::CheckFailed(format!("Failed to execute {}: {}", tool_name, e)))?;

        Ok(CheckTool {
            name: tool_name.to_string(),
            command: full_command,
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    /// Check if a tool is available
    async fn check_tool_available(&self, tool_name: &str) -> Result<(), anyhow::Error> {
        let mut cmd = AsyncCommand::new("which");
        cmd.arg(tool_name)
           .stdout(Stdio::null())
           .stderr(Stdio::null());

        let output = cmd.output().await
            .map_err(|_| FsError::CheckToolNotAvailable(tool_name.to_string()))?;

        if !output.status.success() {
            return Err(FsError::CheckToolNotAvailable(tool_name.to_string()).into());
        }

        Ok(())
    }

    /// Analyze check results based on tool output and exit codes
    fn analyze_check_results(&self, config: &FsCheckConfig, fs_info: &CheckFilesystemInfo, tool: &CheckTool) -> Result<CheckAnalysis, anyhow::Error> {
        match fs_info.fstype.as_str() {
            "ext2" | "ext3" | "ext4" | "vfat" | "reiserfs" => {
                self.analyze_fsck_results(config, tool)
            },
            "xfs" => {
                self.analyze_xfs_repair_results(config, tool)
            },
            "btrfs" => {
                self.analyze_btrfs_results(config, tool)
            },
            _ => Ok(CheckAnalysis {
                errors_found: tool.exit_code != 0,
                repaired: false,
                needs_repair: tool.exit_code != 0,
                filesystem_state: if tool.exit_code == 0 { "clean".to_string() } else { "errors_detected".to_string() },
            }),
        }
    }

    /// Analyze fsck results based on exit codes
    fn analyze_fsck_results(&self, _config: &FsCheckConfig, tool: &CheckTool) -> Result<CheckAnalysis, anyhow::Error> {
        // fsck exit codes:
        // 0: No errors
        // 1: Errors corrected
        // 2: System should be rebooted  
        // 4: Errors left uncorrected
        // 8: Operational error
        // 16: Usage or syntax error
        // 32: Cancelled by user request
        // 128: Shared library error

        match tool.exit_code {
            0 => Ok(CheckAnalysis {
                errors_found: false,
                repaired: false,
                needs_repair: false,
                filesystem_state: "clean".to_string(),
            }),
            1 => Ok(CheckAnalysis {
                errors_found: true,
                repaired: true,
                needs_repair: false,
                filesystem_state: "repaired".to_string(),
            }),
            2 => Ok(CheckAnalysis {
                errors_found: true,
                repaired: true,
                needs_repair: false,
                filesystem_state: "repaired".to_string(),
            }),
            4 => Ok(CheckAnalysis {
                errors_found: true,
                repaired: false,
                needs_repair: true,
                filesystem_state: "errors_detected".to_string(),
            }),
            _ => Ok(CheckAnalysis {
                errors_found: true,
                repaired: false,
                needs_repair: true,
                filesystem_state: "errors_detected".to_string(),
            }),
        }
    }

    /// Analyze xfs_repair results
    fn analyze_xfs_repair_results(&self, _config: &FsCheckConfig, tool: &CheckTool) -> Result<CheckAnalysis, anyhow::Error> {
        // xfs_repair exit codes:
        // 0: No errors
        // 1: Errors found and repaired, or errors found in -n mode
        // 2: Operation error or corrupt filesystem

        match tool.exit_code {
            0 => Ok(CheckAnalysis {
                errors_found: false,
                repaired: false,
                needs_repair: false,
                filesystem_state: "clean".to_string(),
            }),
            1 => {
                // Check if it was in no-modify mode
                let repaired = !tool.command.contains("-n");
                Ok(CheckAnalysis {
                    errors_found: true,
                    repaired,
                    needs_repair: !repaired,
                    filesystem_state: if repaired { "repaired".to_string() } else { "errors_detected".to_string() },
                })
            },
            _ => Ok(CheckAnalysis {
                errors_found: true,
                repaired: false,
                needs_repair: true,
                filesystem_state: "errors_detected".to_string(),
            }),
        }
    }

    /// Analyze btrfs results
    fn analyze_btrfs_results(&self, _config: &FsCheckConfig, tool: &CheckTool) -> Result<CheckAnalysis, anyhow::Error> {
        // btrfs scrub/check exit codes:
        // 0: No errors or successful completion
        // 1: Errors found

        let is_scrub = tool.command.contains("scrub");
        let is_repair = tool.command.contains("--repair");

        match tool.exit_code {
            0 => Ok(CheckAnalysis {
                errors_found: false,
                repaired: false,
                needs_repair: false,
                filesystem_state: "clean".to_string(),
            }),
            1 => {
                if is_scrub {
                    // Scrub found and potentially corrected errors
                    Ok(CheckAnalysis {
                        errors_found: true,
                        repaired: true, // scrub auto-corrects when possible
                        needs_repair: false,
                        filesystem_state: "repaired".to_string(),
                    })
                } else if is_repair {
                    Ok(CheckAnalysis {
                        errors_found: true,
                        repaired: true,
                        needs_repair: false,
                        filesystem_state: "repaired".to_string(),
                    })
                } else {
                    Ok(CheckAnalysis {
                        errors_found: true,
                        repaired: false,
                        needs_repair: true,
                        filesystem_state: "errors_detected".to_string(),
                    })
                }
            },
            _ => Ok(CheckAnalysis {
                errors_found: true,
                repaired: false,
                needs_repair: true,
                filesystem_state: "errors_detected".to_string(),
            }),
        }
    }

    /// Main list-mounts operation implementation
    pub async fn list_mounts(&self, args: Value) -> Result<Value, anyhow::Error> {
        // Parse and validate configuration
        let config = self.parse_list_mounts_config(args)?;
        self.validate_list_mounts_config(&config)?;

        // Execute with timeout
        let timeout_duration = Duration::from_millis(config.timeout_ms);
        let result = timeout(timeout_duration, self.execute_list_mounts(&config)).await
            .map_err(|_| FsError::ListMountsTimeout)?;

        match result {
            Ok(result) => Ok(result),
            Err(e) => Err(e),
        }
    }

    /// Parse list-mounts configuration from arguments
    fn parse_list_mounts_config(&self, args: Value) -> Result<ListMountsConfig, anyhow::Error> {
        eprintln!("DEBUG: Input args: {}", args);
        let mut config: ListMountsConfig = serde_json::from_value(args)
            .context("Failed to parse list-mounts configuration")?;
        eprintln!("DEBUG: Parsed config: include_pseudo={}", config.include_pseudo);

        // Set default timeout if not provided or zero
        if config.timeout_ms == 0 {
            config.timeout_ms = 3000;
        }

        Ok(config)
    }

    /// Validate list-mounts configuration
    fn validate_list_mounts_config(&self, config: &ListMountsConfig) -> Result<(), anyhow::Error> {
        if config.timeout_ms == 0 {
            return Err(FsError::InvalidListMountsConfig("timeout_ms must be greater than 0".to_string()).into());
        }

        if !config.include_readonly && !config.include_readwrite {
            return Err(FsError::InvalidListMountsConfig("Both include_readonly=false and include_readwrite=false - nothing allowed".to_string()).into());
        }

        Ok(())
    }

    /// Execute the actual list-mounts operation
    async fn execute_list_mounts(&self, config: &ListMountsConfig) -> Result<Value, anyhow::Error> {
        // 1. Read mount table
        let raw_mounts = self.read_mount_table().await
            .map_err(|e| FsError::ListMountsFailed(format!("Failed to read mount table: {}", e)))?;

        // 2. Parse and classify mounts
        let mut mount_entries: Vec<ListMountEntry> = Vec::new();
        eprintln!("DEBUG: Processing {} raw mounts", raw_mounts.len());
        for (i, raw_mount) in raw_mounts.iter().enumerate() {
            if i < 5 || raw_mount.fstype == "proc" || raw_mount.fstype == "tmpfs" {
                eprintln!("DEBUG: Processing mount {}: {} {} {}", i, raw_mount.source, raw_mount.target, raw_mount.fstype);
            }
            let mut entry = ListMountEntry {
                source: raw_mount.source.clone(),
                target: if config.normalize_paths {
                    self.normalize_path(&raw_mount.target)
                } else {
                    raw_mount.target.clone()
                },
                fstype: raw_mount.fstype.clone(),
                options: self.parse_and_sort_options(&raw_mount.options),
                read_only: self.is_read_only(&raw_mount.options),
                pseudo: self.is_pseudo_filesystem(&raw_mount.fstype),
                network: self.is_network_filesystem(&raw_mount.fstype, &raw_mount.source),
                loop_device: self.is_loop_device(&raw_mount.source),
                device: None,
                fs_features: None,
            };

            // Optionally resolve labels
            if config.resolve_labels {
                entry.device = self.resolve_device_labels(&raw_mount.source).await;
            }

            // Optionally resolve filesystem features
            if config.resolve_fs_features {
                entry.fs_features = self.resolve_filesystem_features(&raw_mount.fstype, &raw_mount.source).await;
            }

            mount_entries.push(entry);
        }

        // 3. Apply path-based restriction if specified
        if !config.paths.is_empty() {
            mount_entries = self.filter_mounts_by_paths(&mount_entries, &config.paths)?;
        }

        // 4. Apply filters
        eprintln!("DEBUG: Before filtering: {} mount entries", mount_entries.len());
        mount_entries = self.apply_list_mounts_filters(mount_entries, config)?;
        eprintln!("DEBUG: After filtering: {} mount entries", mount_entries.len());

        // 5. Sort deterministically
        mount_entries.sort_by(|a, b| {
            a.target.cmp(&b.target)
                .then_with(|| a.source.cmp(&b.source))
                .then_with(|| a.fstype.cmp(&b.fstype))
        });

        // 6. Build response
        let filters = ListMountsFilters {
            paths: config.paths.clone(),
            include_mountpoints: config.include_mountpoints.clone(),
            exclude_mountpoints: config.exclude_mountpoints.clone(),
            include_types: config.include_types.clone(),
            exclude_types: config.exclude_types.clone(),
            include_sources: config.include_sources.clone(),
            exclude_sources: config.exclude_sources.clone(),
            include_readonly: config.include_readonly,
            include_readwrite: config.include_readwrite,
            include_pseudo: config.include_pseudo,
            include_loop: config.include_loop,
            include_network: config.include_network,
        };

        Ok(json!(ListMountsResult {
            backend: "fs".to_string(),
            verb: "list-mounts".to_string(),
            alias: self.alias.clone(),
            filters,
            mounts: mount_entries,
        }))
    }

    /// Check if mount options indicate read-only
    fn is_read_only(&self, options: &str) -> bool {
        options.split(',').any(|opt| opt.trim() == "ro")
    }

    /// Check if filesystem type is a pseudo filesystem
    fn is_pseudo_filesystem(&self, fstype: &str) -> bool {
        let is_pseudo = matches!(fstype, 
            "proc" | "sysfs" | "devtmpfs" | "devpts" | "tmpfs" | "cgroup" | 
            "cgroup2" | "pstore" | "securityfs" | "debugfs" | "tracefs" |
            "bpf" | "configfs" | "fusectl" | "mqueue" | "hugetlbfs"
        );
        if is_pseudo {
            eprintln!("DEBUG: {} is a pseudo filesystem", fstype);
        }
        is_pseudo
    }

    /// Check if filesystem is a network filesystem
    fn is_network_filesystem(&self, fstype: &str, source: &str) -> bool {
        // Check by filesystem type
        if matches!(fstype,
            "nfs" | "nfs4" | "cifs" | "smb" | "smbfs" | "sshfs" | 
            "glusterfs" | "fuse.sshfs" | "fuse.cifs" | "fuse.glusterfs"
        ) {
            return true;
        }

        // Check by source format (server:/path or //server/share)
        source.contains(":/") || source.starts_with("//")
    }

    /// Check if device is a loop device
    fn is_loop_device(&self, source: &str) -> bool {
        source.starts_with("/dev/loop") || source.contains("loop")
    }

    /// Filter mounts by paths - only include filesystems backing the specified paths
    fn filter_mounts_by_paths(&self, mounts: &[ListMountEntry], paths: &[String]) -> Result<Vec<ListMountEntry>, anyhow::Error> {
        let mut selected_mounts = Vec::new();
        let mut selected_targets = std::collections::HashSet::new();

        for path in paths {
            // Find the mount point that backs this path (longest prefix match)
            let mut best_match: Option<&ListMountEntry> = None;
            let mut best_match_len = 0;

            for mount in mounts {
                if path.starts_with(&mount.target) {
                    let match_len = mount.target.len();
                    if match_len > best_match_len {
                        best_match = Some(mount);
                        best_match_len = match_len;
                    }
                }
            }

            if let Some(mount) = best_match {
                if !selected_targets.contains(&mount.target) {
                    selected_targets.insert(mount.target.clone());
                    selected_mounts.push(mount.clone());
                }
            }
        }

        Ok(selected_mounts)
    }

    /// Apply all the include/exclude filters
    fn apply_list_mounts_filters(&self, mut mounts: Vec<ListMountEntry>, config: &ListMountsConfig) -> Result<Vec<ListMountEntry>, anyhow::Error> {
        eprintln!("DEBUG: Filter config: include_pseudo={}, include_readonly={}, include_readwrite={}", 
                 config.include_pseudo, config.include_readonly, config.include_readwrite);
        
        // Apply mountpoint filters
        if !config.include_mountpoints.is_empty() {
            mounts.retain(|mount| {
                config.include_mountpoints.iter().any(|prefix| mount.target.starts_with(prefix))
            });
        }

        if !config.exclude_mountpoints.is_empty() {
            mounts.retain(|mount| {
                !config.exclude_mountpoints.iter().any(|prefix| mount.target.starts_with(prefix))
            });
        }

        // Apply filesystem type filters
        if !config.include_types.is_empty() {
            mounts.retain(|mount| config.include_types.contains(&mount.fstype));
        }

        if !config.exclude_types.is_empty() {
            mounts.retain(|mount| !config.exclude_types.contains(&mount.fstype));
        }

        // Apply source filters
        if !config.include_sources.is_empty() {
            mounts.retain(|mount| config.include_sources.contains(&mount.source));
        }

        if !config.exclude_sources.is_empty() {
            mounts.retain(|mount| !config.exclude_sources.contains(&mount.source));
        }

        // Apply attribute filters
        if !config.include_readonly {
            mounts.retain(|mount| !mount.read_only);
        }

        if !config.include_readwrite {
            mounts.retain(|mount| mount.read_only);
        }

        if !config.include_pseudo {
            mounts.retain(|mount| !mount.pseudo);
        }

        if !config.include_loop {
            mounts.retain(|mount| !mount.loop_device);
        }

        if !config.include_network {
            mounts.retain(|mount| !mount.network);
        }

        Ok(mounts)
    }

    /// Resolve device labels using blkid
    async fn resolve_device_labels(&self, source: &str) -> Option<DeviceMeta> {
        // Only try to resolve labels for block devices
        if !source.starts_with("/dev/") || source.contains(":") || source.starts_with("//") {
            return None;
        }

        match AsyncCommand::new("blkid")
            .arg("-o")
            .arg("export")
            .arg(source)
            .output()
            .await
        {
            Ok(output) if output.status.success() => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                let mut meta = DeviceMeta {
                    label: None,
                    uuid: None,
                    partlabel: None,
                    partuuid: None,
                };

                for line in output_str.lines() {
                    if let Some((key, value)) = line.split_once('=') {
                        match key {
                            "LABEL" => meta.label = Some(value.to_string()),
                            "UUID" => meta.uuid = Some(value.to_string()),
                            "PARTLABEL" => meta.partlabel = Some(value.to_string()),
                            "PARTUUID" => meta.partuuid = Some(value.to_string()),
                            _ => {}
                        }
                    }
                }

                Some(meta)
            },
            _ => None,
        }
    }

    /// Resolve filesystem features
    async fn resolve_filesystem_features(&self, fstype: &str, source: &str) -> Option<FsFeatures> {
        // Only try for real filesystems and block devices
        if source.contains(":") || source.starts_with("//") || !source.starts_with("/dev/") {
            return None;
        }

        match fstype {
            "ext2" | "ext3" | "ext4" => self.resolve_ext_features(source).await,
            "xfs" => self.resolve_xfs_features(source).await,
            "btrfs" => self.resolve_btrfs_features(source).await,
            _ => None,
        }
    }

    /// Resolve ext filesystem features
    async fn resolve_ext_features(&self, source: &str) -> Option<FsFeatures> {
        match AsyncCommand::new("tune2fs")
            .arg("-l")
            .arg(source)
            .output()
            .await
        {
            Ok(output) if output.status.success() => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                let mut features = Vec::new();
                let mut block_size = None;
                let mut inode_size = None;

                for line in output_str.lines() {
                    if line.starts_with("Filesystem features:") {
                        if let Some(features_str) = line.split(':').nth(1) {
                            features = features_str.split_whitespace()
                                .map(|s| s.to_string())
                                .collect();
                        }
                    } else if line.starts_with("Block size:") {
                        if let Some(size_str) = line.split(':').nth(1) {
                            if let Ok(size) = size_str.trim().parse::<u64>() {
                                block_size = Some(size);
                            }
                        }
                    } else if line.starts_with("Inode size:") {
                        if let Some(size_str) = line.split(':').nth(1) {
                            if let Ok(size) = size_str.trim().parse::<u64>() {
                                inode_size = Some(size);
                            }
                        }
                    }
                }

                Some(FsFeatures {
                    features: if features.is_empty() { None } else { Some(features) },
                    block_size,
                    inode_size,
                })
            },
            _ => None,
        }
    }

    /// Resolve XFS filesystem features
    async fn resolve_xfs_features(&self, source: &str) -> Option<FsFeatures> {
        match AsyncCommand::new("xfs_info")
            .arg(source)
            .output()
            .await
        {
            Ok(output) if output.status.success() => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                let mut block_size = None;

                // Parse block size from first line: "meta-data=/dev/sda1 isize=512 agcount=4, agsize=6553344 blks"
                for line in output_str.lines() {
                    if line.contains("bsize=") {
                        if let Some(bsize_part) = line.split("bsize=").nth(1) {
                            if let Some(size_str) = bsize_part.split_whitespace().next() {
                                if let Ok(size) = size_str.parse::<u64>() {
                                    block_size = Some(size);
                                }
                            }
                        }
                    }
                }

                Some(FsFeatures {
                    features: Some(vec!["xfs".to_string()]),
                    block_size,
                    inode_size: None,
                })
            },
            _ => None,
        }
    }

    /// Resolve Btrfs filesystem features
    async fn resolve_btrfs_features(&self, _source: &str) -> Option<FsFeatures> {
        // For btrfs, we could use `btrfs filesystem show` but that requires
        // different handling. For now, return basic info.
        Some(FsFeatures {
            features: Some(vec!["btrfs".to_string(), "copy_on_write".to_string()]),
            block_size: None,
            inode_size: None,
        })
    }
}

impl Handle for FsHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["mount", "unmount", "umount", "snapshot", "quota", "quota_summary", "usage", "resize", "check", "fsck", "list-mounts"]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        match verb {
            "mount" => {
                // Convert Args to Value for async processing
                let args_value = serde_json::to_value(args)
                    .context("Failed to serialize mount arguments")?;
                
                // For the synchronous Handle trait, we need to use a runtime
                let rt = tokio::runtime::Runtime::new()
                    .context("Failed to create async runtime")?;
                
                match rt.block_on(self.mount(args_value)) {
                    Ok(result) => {
                        // Write JSON result to stdout
                        writeln!(io.stdout, "{}", serde_json::to_string(&result)
                            .map_err(|e| anyhow::anyhow!("Failed to serialize result: {}", e))?)?;
                        Ok(Status::ok())
                    },
                    Err(e) => {
                        // Map errors to appropriate status codes
                        if let Some(fs_err) = e.downcast_ref::<FsError>() {
                            match fs_err {
                                FsError::InvalidMountConfig(_) => Ok(Status::err(1, &e.to_string())),
                                FsError::ProfileNotFound(_) => Ok(Status::err(2, &e.to_string())),
                                FsError::MountUnsupported => Ok(Status::err(3, &e.to_string())),
                                FsError::MountPermissionDenied => Ok(Status::err(13, &e.to_string())),
                                FsError::AlreadyMounted(_) => Ok(Status::err(16, &e.to_string())),
                                FsError::ConflictingMount(_) => Ok(Status::err(17, &e.to_string())),
                                FsError::MountFailure(_) => Ok(Status::err(32, &e.to_string())),
                                FsError::MountTimeout => Ok(Status::err(62, &e.to_string())),
                                FsError::TargetCreationFailed(_) => Ok(Status::err(18, &e.to_string())),
                                FsError::NotMounted(_) => Ok(Status::err(19, &e.to_string())),
                                _ => Ok(Status::err(1, &e.to_string())),
                            }
                        } else {
                            Ok(Status::err(1, &e.to_string()))
                        }
                    }
                }
            }
            "unmount" | "umount" => {
                // Convert Args to Value for async processing
                let args_value = serde_json::to_value(args)
                    .context("Failed to serialize unmount arguments")?;
                
                // For the synchronous Handle trait, we need to use a runtime
                let rt = tokio::runtime::Runtime::new()
                    .context("Failed to create async runtime")?;
                
                match rt.block_on(self.unmount(args_value)) {
                    Ok(result) => {
                        // Write JSON result to stdout
                        writeln!(io.stdout, "{}", serde_json::to_string(&result)
                            .map_err(|e| anyhow::anyhow!("Failed to serialize result: {}", e))?)?;
                        Ok(Status::ok())
                    },
                    Err(e) => {
                        // Map errors to appropriate status codes
                        if let Some(fs_err) = e.downcast_ref::<FsError>() {
                            match fs_err {
                                FsError::InvalidUnmountConfig(_) => Ok(Status::err(1, &e.to_string())),
                                FsError::ProfileNotFound(_) => Ok(Status::err(2, &e.to_string())),
                                FsError::UnmountUnsupported => Ok(Status::err(3, &e.to_string())),
                                FsError::UnmountPermissionDenied => Ok(Status::err(13, &e.to_string())),
                                FsError::NotMounted(_) => Ok(Status::err(19, &e.to_string())),
                                FsError::UnmountBusy(_) => Ok(Status::err(16, &e.to_string())),
                                FsError::UnmountFailure(_) => Ok(Status::err(32, &e.to_string())),
                                FsError::UnmountTimeout => Ok(Status::err(62, &e.to_string())),
                                FsError::UnmountOptionUnsupported(_) => Ok(Status::err(95, &e.to_string())),
                                _ => Ok(Status::err(1, &e.to_string())),
                            }
                        } else {
                            Ok(Status::err(1, &e.to_string()))
                        }
                    }
                }
            }
            "snapshot" => {
                // Convert Args to Value for async processing
                let args_value = serde_json::to_value(args)
                    .context("Failed to serialize snapshot arguments")?;
                
                // For the synchronous Handle trait, we need to use a runtime
                let rt = tokio::runtime::Runtime::new()
                    .context("Failed to create async runtime")?;
                
                match rt.block_on(self.snapshot(args_value)) {
                    Ok(result) => {
                        // Write JSON result to stdout
                        writeln!(io.stdout, "{}", serde_json::to_string(&result)
                            .map_err(|e| anyhow::anyhow!("Failed to serialize result: {}", e))?)?;
                        Ok(Status::ok())
                    },
                    Err(e) => {
                        // Map errors to appropriate status codes
                        if let Some(fs_err) = e.downcast_ref::<FsError>() {
                            match fs_err {
                                FsError::InvalidSnapshotConfig(_) => Ok(Status::err(1, &e.to_string())),
                                FsError::ProfileNotFound(_) => Ok(Status::err(2, &e.to_string())),
                                FsError::SnapshotUnsupported => Ok(Status::err(3, &e.to_string())),
                                FsError::SnapshotTimeout => Ok(Status::err(62, &e.to_string())),
                                FsError::SnapshotFailed(_) => Ok(Status::err(32, &e.to_string())),
                                _ => Ok(Status::err(1, &e.to_string())),
                            }
                        } else {
                            Ok(Status::err(1, &e.to_string()))
                        }
                    }
                }
            }
            "quota" => {
                // Convert Args to Value for async processing
                let args_value = serde_json::to_value(args)
                    .context("Failed to serialize quota arguments")?;
                
                // For the synchronous Handle trait, we need to use a runtime
                let rt = tokio::runtime::Runtime::new()
                    .context("Failed to create async runtime")?;
                
                match rt.block_on(self.quota(args_value)) {
                    Ok(result) => {
                        // Write JSON result to stdout
                        writeln!(io.stdout, "{}", serde_json::to_string(&result)
                            .map_err(|e| anyhow::anyhow!("Failed to serialize result: {}", e))?)?;
                        Ok(Status::ok())
                    },
                    Err(e) => {
                        // Map errors to appropriate status codes
                        if let Some(fs_err) = e.downcast_ref::<FsError>() {
                            match fs_err {
                                FsError::InvalidQuotaConfig(_) => Ok(Status::err(1, &e.to_string())),
                                FsError::ProfileNotFound(_) => Ok(Status::err(2, &e.to_string())),
                                FsError::QuotaUnsupported => Ok(Status::err(3, &e.to_string())),
                                FsError::QuotaNotEnabled(_) => Ok(Status::err(4, &e.to_string())),
                                FsError::QuotaSubjectNotFound(_) => Ok(Status::err(5, &e.to_string())),
                                FsError::QuotaTimeout => Ok(Status::err(62, &e.to_string())),
                                FsError::QuotaFailed(_) => Ok(Status::err(32, &e.to_string())),
                                _ => Ok(Status::err(1, &e.to_string())),
                            }
                        } else {
                            Ok(Status::err(1, &e.to_string()))
                        }
                    }
                }
            }
            "quota_summary" => {
                // Convert Args to Value for async processing
                let args_value = serde_json::to_value(args)
                    .context("Failed to serialize quota summary arguments")?;
                
                // For the synchronous Handle trait, we need to use a runtime
                let rt = tokio::runtime::Runtime::new()
                    .context("Failed to create async runtime")?;
                
                match rt.block_on(self.quota_summary(args_value)) {
                    Ok(result) => {
                        // Write JSON result to stdout
                        writeln!(io.stdout, "{}", serde_json::to_string(&result)
                            .map_err(|e| anyhow::anyhow!("Failed to serialize result: {}", e))?)?;
                        Ok(Status::ok())
                    },
                    Err(e) => {
                        // Map errors to appropriate status codes
                        if let Some(fs_err) = e.downcast_ref::<FsError>() {
                            match fs_err {
                                FsError::InvalidQuotaSummaryConfig(_) => Ok(Status::err(1, &e.to_string())),
                                FsError::ProfileNotFound(_) => Ok(Status::err(2, &e.to_string())),
                                FsError::QuotaSummaryUnsupported => Ok(Status::err(3, &e.to_string())),
                                FsError::QuotaSummaryNoQuotaFilesystems => Ok(Status::err(4, &e.to_string())),
                                FsError::QuotaSubjectNotFound(_) => Ok(Status::err(5, &e.to_string())),
                                FsError::QuotaSummaryTimeout => Ok(Status::err(62, &e.to_string())),
                                FsError::QuotaSummaryFailed(_) => Ok(Status::err(32, &e.to_string())),
                                _ => Ok(Status::err(1, &e.to_string())),
                            }
                        } else {
                            Ok(Status::err(1, &e.to_string()))
                        }
                    }
                }
            }
            "usage" => {
                // Convert Args to Value for async processing
                let args_value = serde_json::to_value(args)
                    .context("Failed to serialize usage arguments")?;
                
                // For the synchronous Handle trait, we need to use a runtime
                let rt = tokio::runtime::Runtime::new()
                    .context("Failed to create async runtime")?;
                
                match rt.block_on(self.usage(args_value)) {
                    Ok(result) => {
                        // Write JSON result to stdout
                        writeln!(io.stdout, "{}", serde_json::to_string(&result)
                            .map_err(|e| anyhow::anyhow!("Failed to serialize result: {}", e))?)?;
                        Ok(Status::ok())
                    },
                    Err(e) => {
                        // Map errors to appropriate status codes
                        if let Some(fs_err) = e.downcast_ref::<FsError>() {
                            match fs_err {
                                FsError::InvalidUsageConfig(_) => Ok(Status::err(1, &e.to_string())),
                                FsError::ProfileNotFound(_) => Ok(Status::err(2, &e.to_string())),
                                FsError::UsageUnsupported => Ok(Status::err(3, &e.to_string())),
                                FsError::UsageTimeout => Ok(Status::err(62, &e.to_string())),
                                FsError::UsageFailed(_) => Ok(Status::err(32, &e.to_string())),
                                FsError::PathNotFound(_) => Ok(Status::err(2, &e.to_string())),
                                FsError::UsageNothingSelected => Ok(Status::err(4, &e.to_string())),
                                _ => Ok(Status::err(1, &e.to_string())),
                            }
                        } else {
                            Ok(Status::err(1, &e.to_string()))
                        }
                    }
                }
            }
            "resize" => {
                // Convert Args to Value for async processing
                let args_value = serde_json::to_value(args)
                    .context("Failed to serialize resize arguments")?;
                
                // For the synchronous Handle trait, we need to use a runtime
                let rt = tokio::runtime::Runtime::new()
                    .context("Failed to create async runtime")?;
                
                match rt.block_on(self.resize(args_value)) {
                    Ok(result) => {
                        // Write JSON result to stdout
                        writeln!(io.stdout, "{}", serde_json::to_string(&result)
                            .map_err(|e| anyhow::anyhow!("Failed to serialize result: {}", e))?)?;
                        Ok(Status::ok())
                    },
                    Err(e) => {
                        // Map errors to appropriate status codes
                        if let Some(fs_err) = e.downcast_ref::<FsError>() {
                            match fs_err {
                                FsError::InvalidResizeConfig(_) => Ok(Status::err(1, &e.to_string())),
                                FsError::ProfileNotFound(_) => Ok(Status::err(2, &e.to_string())),
                                FsError::ResizeTargetNotFound(_) => Ok(Status::err(2, &e.to_string())),
                                FsError::ResizeUnsupportedFilesystem(_) => Ok(Status::err(3, &e.to_string())),
                                FsError::ResizeShrinkNotAllowed => Ok(Status::err(4, &e.to_string())),
                                FsError::ResizeShrinkNotSupportedForFilesystem(_) => Ok(Status::err(5, &e.to_string())),
                                FsError::ResizeShrinkRequiresUnmount(_) => Ok(Status::err(6, &e.to_string())),
                                FsError::ResizeWouldViolateMinFree => Ok(Status::err(7, &e.to_string())),
                                FsError::ResizeTargetExceedsDevice => Ok(Status::err(8, &e.to_string())),
                                FsError::ResizeInvalidTargetSize(_) => Ok(Status::err(9, &e.to_string())),
                                FsError::ResizeVolumeManagementUnsupported => Ok(Status::err(10, &e.to_string())),
                                FsError::ResizeTimeout => Ok(Status::err(62, &e.to_string())),
                                FsError::ResizeFailed(_) => Ok(Status::err(32, &e.to_string())),
                                _ => Ok(Status::err(1, &e.to_string())),
                            }
                        } else {
                            Ok(Status::err(1, &e.to_string()))
                        }
                    }
                }
            }
            "check" | "fsck" => {
                // Convert Args to Value for async processing
                let args_value = serde_json::to_value(args)
                    .context("Failed to serialize check arguments")?;
                
                // For the synchronous Handle trait, we need to use a runtime
                let rt = tokio::runtime::Runtime::new()
                    .context("Failed to create async runtime")?;
                
                match rt.block_on(self.check(args_value)) {
                    Ok(result) => {
                        // Write JSON result to stdout
                        writeln!(io.stdout, "{}", serde_json::to_string(&result)
                            .map_err(|e| anyhow::anyhow!("Failed to serialize result: {}", e))?)?;
                        Ok(Status::ok())
                    },
                    Err(e) => {
                        // Map errors to appropriate status codes
                        if let Some(fs_err) = e.downcast_ref::<FsError>() {
                            match fs_err {
                                FsError::InvalidCheckConfig(_) => Ok(Status::err(1, &e.to_string())),
                                FsError::ProfileNotFound(_) => Ok(Status::err(2, &e.to_string())),
                                FsError::CheckTargetNotFound(_) => Ok(Status::err(2, &e.to_string())),
                                FsError::CheckUnsupportedFilesystem(_) => Ok(Status::err(3, &e.to_string())),
                                FsError::CheckRepairNotAllowed => Ok(Status::err(4, &e.to_string())),
                                FsError::CheckRequiresUnmountForRepair(_) => Ok(Status::err(5, &e.to_string())),
                                FsError::CheckMustBeOffline(_) => Ok(Status::err(6, &e.to_string())),
                                FsError::CheckToolNotAvailable(_) => Ok(Status::err(7, &e.to_string())),
                                FsError::CheckTimeout => Ok(Status::err(62, &e.to_string())),
                                FsError::CheckFailed(_) => Ok(Status::err(32, &e.to_string())),
                                _ => Ok(Status::err(1, &e.to_string())),
                            }
                        } else {
                            Ok(Status::err(1, &e.to_string()))
                        }
                    }
                }
            }
            "list-mounts" => {
                // Convert Args to Value for async processing
                let args_value = serde_json::to_value(args)
                    .context("Failed to serialize list-mounts arguments")?;
                
                // For the synchronous Handle trait, we need to use a runtime
                let rt = tokio::runtime::Runtime::new()
                    .context("Failed to create async runtime")?;
                
                match rt.block_on(self.list_mounts(args_value)) {
                    Ok(result) => {
                        // Write JSON result to stdout
                        writeln!(io.stdout, "{}", serde_json::to_string(&result)
                            .map_err(|e| anyhow::anyhow!("Failed to serialize result: {}", e))?)?;
                        Ok(Status::ok())
                    },
                    Err(e) => {
                        // Map errors to appropriate status codes
                        if let Some(fs_err) = e.downcast_ref::<FsError>() {
                            match fs_err {
                                FsError::InvalidListMountsConfig(_) => Ok(Status::err(1, &e.to_string())),
                                FsError::ProfileNotFound(_) => Ok(Status::err(2, &e.to_string())),
                                FsError::ListMountsUnsupported => Ok(Status::err(3, &e.to_string())),
                                FsError::ListMountsTimeout => Ok(Status::err(62, &e.to_string())),
                                FsError::ListMountsFailed(_) => Ok(Status::err(32, &e.to_string())),
                                _ => Ok(Status::err(1, &e.to_string())),
                            }
                        } else {
                            Ok(Status::err(1, &e.to_string()))
                        }
                    }
                }
            }
            _ => Ok(Status::err(95, "unknown verb")),
        }
    }
}

/// Register the filesystem handle with the registry
pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("fs", |u| Ok(Box::new(FsHandle::from_url(u.clone())?)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_mount_config_validation() {
        let handle = FsHandle { alias: "test".to_string() };

        // Test empty target
        let config = MountConfig {
            target: "".to_string(),
            ..Default::default()
        };
        assert!(handle.validate_mount_config(&config).is_err());

        // Test bind without source
        let config = MountConfig {
            target: "/mnt/test".to_string(),
            bind: true,
            source: None,
            ..Default::default()
        };
        assert!(handle.validate_mount_config(&config).is_err());

        // Test contradictory flags
        let config = MountConfig {
            target: "/mnt/test".to_string(),
            remount: true,
            fail_if_mounted: true,
            ..Default::default()
        };
        assert!(handle.validate_mount_config(&config).is_err());

        // Test valid config
        let config = MountConfig {
            target: "/mnt/test".to_string(),
            source: Some("/dev/sdb1".to_string()),
            r#type: Some("ext4".to_string()),
            ..Default::default()
        };
        assert!(handle.validate_mount_config(&config).is_ok());
    }

    #[test]
    fn test_mount_config_defaults() {
        let args = json!({
            "target": "/mnt/test",
            "source": "/dev/sdb1"
        });

        let handle = FsHandle { alias: "test".to_string() };
        let config = handle.parse_mount_config(args).unwrap();

        assert_eq!(config.target, "/mnt/test");
        assert_eq!(config.source, Some("/dev/sdb1".to_string()));
        assert_eq!(config.timeout_ms, 5000);
        assert_eq!(config.create_target, true);
        assert_eq!(config.make_parents, true);
        assert_eq!(config.read_only, false);
        assert_eq!(config.bind, false);
        assert_eq!(config.remount, false);
        assert_eq!(config.fail_if_mounted, false);
        assert_eq!(config.dry_run, false);
    }

    #[test]
    fn test_read_only_option_injection() {
        let args = json!({
            "target": "/mnt/test",
            "source": "/dev/sdb1",
            "read_only": true
        });

        let handle = FsHandle { alias: "test".to_string() };
        let config = handle.parse_mount_config(args).unwrap();

        assert!(config.read_only);
        assert!(config.options.contains(&"ro".to_string()));
    }

    #[test]
    fn test_mount_compatibility() {
        let handle = FsHandle { alias: "test".to_string() };
        
        let existing = ExistingMount {
            source: "/dev/sdb1".to_string(),
            target: "/mnt/test".to_string(),
            fs_type: "ext4".to_string(),
            options: vec!["rw".to_string(), "noatime".to_string()],
        };

        // Compatible config
        let config = MountConfig {
            target: "/mnt/test".to_string(),
            source: Some("/dev/sdb1".to_string()),
            r#type: Some("ext4".to_string()),
            ..Default::default()
        };
        assert!(handle.is_mount_compatible(&existing, &config));

        // Incompatible source
        let config = MountConfig {
            target: "/mnt/test".to_string(),
            source: Some("/dev/sdc1".to_string()),
            r#type: Some("ext4".to_string()),
            ..Default::default()
        };
        assert!(!handle.is_mount_compatible(&existing, &config));

        // Incompatible filesystem type
        let config = MountConfig {
            target: "/mnt/test".to_string(),
            source: Some("/dev/sdb1".to_string()),
            r#type: Some("xfs".to_string()),
            ..Default::default()
        };
        assert!(!handle.is_mount_compatible(&existing, &config));
    }

    #[tokio::test]
    async fn test_dry_run_plan() {
        let handle = FsHandle { alias: "test".to_string() };
        
        let config = MountConfig {
            target: "/mnt/test".to_string(),
            source: Some("/dev/sdb1".to_string()),
            r#type: Some("ext4".to_string()),
            options: vec!["noatime".to_string()],
            dry_run: true,
            ..Default::default()
        };

        let result = handle.create_mount_plan(&config, false).unwrap();
        
        assert_eq!(result.action, "planned");
        assert!(result.dry_run == Some(true));
        assert!(result.plan.is_some());
        
        let plan = result.plan.unwrap();
        assert!(plan.create_directory.len() > 0);
        assert!(plan.mount_commands.len() > 0);
        assert!(plan.mount_commands[0].contains("mount"));
        assert!(plan.mount_commands[0].contains("-t ext4"));
        assert!(plan.mount_commands[0].contains("-o noatime"));
        assert!(plan.mount_commands[0].contains("/dev/sdb1"));
        assert!(plan.mount_commands[0].contains("/mnt/test"));
    }

    #[test]
    fn test_unmount_config_validation() {
        let handle = FsHandle { alias: "test".to_string() };

        // Test empty target
        let config = UnmountConfig {
            target: "".to_string(),
            ..Default::default()
        };
        assert!(handle.validate_unmount_config(&config).is_err());

        // Test whitespace-only target
        let config = UnmountConfig {
            target: "   ".to_string(),
            ..Default::default()
        };
        assert!(handle.validate_unmount_config(&config).is_err());

        // Test zero timeout
        let config = UnmountConfig {
            target: "/mnt/test".to_string(),
            timeout_ms: 0,
            ..Default::default()
        };
        assert!(handle.validate_unmount_config(&config).is_err());

        // Valid config
        let config = UnmountConfig {
            target: "/mnt/test".to_string(),
            ..Default::default()
        };
        assert!(handle.validate_unmount_config(&config).is_ok());
    }

    #[test]
    fn test_parse_unmount_config() {
        let handle = FsHandle { alias: "test".to_string() };

        // Test JSON deserialization
        let args = json!({
            "target": "/mnt/test",
            "by": "target",
            "force": true,
            "lazy": false,
            "detach_children": true,
            "timeout_ms": 10000,
            "dry_run": true
        });

        let config = handle.parse_unmount_config(args).unwrap();
        assert_eq!(config.target, "/mnt/test");
        assert_eq!(config.by, UnmountTargetKind::Target);
        assert!(config.force);
        assert!(!config.lazy);
        assert!(config.detach_children);
        assert_eq!(config.timeout_ms, 10000);
        assert!(config.dry_run);

        // Test string-based parsing
        let args = json!({
            "target": "/mnt/test",
            "by": "source",
            "force": "true",
            "lazy": "false",
            "timeout_ms": "5000"
        });

        let config = handle.parse_unmount_config(args).unwrap();
        assert_eq!(config.by, UnmountTargetKind::Source);
        assert!(config.force);
        assert_eq!(config.timeout_ms, 5000);
    }

    #[test]
    fn test_find_mounts_to_unmount() {
        let handle = FsHandle { alias: "test".to_string() };

        let existing_mounts = vec![
            ExistingMount {
                source: "/dev/sdb1".to_string(),
                target: "/mnt/data".to_string(),
                fs_type: "ext4".to_string(),
                options: vec!["rw".to_string()],
            },
            ExistingMount {
                source: "tmpfs".to_string(),
                target: "/mnt/data/tmp".to_string(),
                fs_type: "tmpfs".to_string(),
                options: vec!["rw".to_string(), "size=1G".to_string()],
            },
            ExistingMount {
                source: "/dev/sdc1".to_string(),
                target: "/mnt/backup".to_string(),
                fs_type: "xfs".to_string(),
                options: vec!["rw".to_string()],
            },
        ];

        // Test by target
        let config = UnmountConfig {
            target: "/mnt/data".to_string(),
            by: UnmountTargetKind::Target,
            ..Default::default()
        };
        let matched = handle.find_mounts_to_unmount(&existing_mounts, &config).unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].target, "/mnt/data");

        // Test by source
        let config = UnmountConfig {
            target: "/dev/sdb1".to_string(),
            by: UnmountTargetKind::Source,
            ..Default::default()
        };
        let matched = handle.find_mounts_to_unmount(&existing_mounts, &config).unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].source, "/dev/sdb1");

        // Test auto (first tries target, then source)
        let config = UnmountConfig {
            target: "/mnt/data".to_string(),
            by: UnmountTargetKind::Auto,
            ..Default::default()
        };
        let matched = handle.find_mounts_to_unmount(&existing_mounts, &config).unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].target, "/mnt/data");

        // Test auto fallback to source
        let config = UnmountConfig {
            target: "/dev/sdc1".to_string(),
            by: UnmountTargetKind::Auto,
            ..Default::default()
        };
        let matched = handle.find_mounts_to_unmount(&existing_mounts, &config).unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].source, "/dev/sdc1");
    }

    #[test]
    fn test_compute_unmount_order() {
        let handle = FsHandle { alias: "test".to_string() };

        let all_mounts = vec![
            ExistingMount {
                source: "/dev/sdb1".to_string(),
                target: "/mnt/data".to_string(),
                fs_type: "ext4".to_string(),
                options: vec!["rw".to_string()],
            },
            ExistingMount {
                source: "tmpfs".to_string(),
                target: "/mnt/data/tmp".to_string(),
                fs_type: "tmpfs".to_string(),
                options: vec!["rw".to_string()],
            },
            ExistingMount {
                source: "/dev/loop0".to_string(),
                target: "/mnt/data/tmp/nested".to_string(),
                fs_type: "ext4".to_string(),
                options: vec!["rw".to_string()],
            },
            ExistingMount {
                source: "/dev/sdc1".to_string(),
                target: "/mnt/other".to_string(),
                fs_type: "xfs".to_string(),
                options: vec!["rw".to_string()],
            },
        ];

        let matched_mounts = vec![all_mounts[0].clone()]; // /mnt/data

        // Test without detach_children
        let config = UnmountConfig {
            target: "/mnt/data".to_string(),
            detach_children: false,
            ..Default::default()
        };
        let order = handle.compute_unmount_order(&matched_mounts, &all_mounts, &config).unwrap();
        assert_eq!(order.len(), 1);
        assert_eq!(order[0].target, "/mnt/data");

        // Test with detach_children
        let config = UnmountConfig {
            target: "/mnt/data".to_string(),
            detach_children: true,
            ..Default::default()
        };
        let order = handle.compute_unmount_order(&matched_mounts, &all_mounts, &config).unwrap();
        assert_eq!(order.len(), 3);
        // Should be deepest first: /mnt/data/tmp/nested, /mnt/data/tmp, /mnt/data
        assert_eq!(order[0].target, "/mnt/data/tmp/nested");
        assert_eq!(order[1].target, "/mnt/data/tmp");
        assert_eq!(order[2].target, "/mnt/data");
    }

    #[test]
    fn test_unmount_dry_run_plan() {
        let handle = FsHandle { alias: "test".to_string() };

        let unmount_order = vec![
            ExistingMount {
                source: "tmpfs".to_string(),
                target: "/mnt/data/tmp".to_string(),
                fs_type: "tmpfs".to_string(),
                options: vec!["rw".to_string()],
            },
            ExistingMount {
                source: "/dev/sdb1".to_string(),
                target: "/mnt/data".to_string(),
                fs_type: "ext4".to_string(),
                options: vec!["rw".to_string()],
            },
        ];

        let config = UnmountConfig {
            target: "/mnt/data".to_string(),
            force: true,
            lazy: false,
            detach_children: true,
            ..Default::default()
        };

        let result = handle.create_unmount_plan(&config, &unmount_order).unwrap();

        assert_eq!(result.action, "planned");
        assert_eq!(result.dry_run, Some(true));
        assert!(result.plan.is_some());
        assert!(result.matched_mounts.is_some());

        let plan = result.plan.unwrap();
        assert_eq!(plan.order.len(), 2);
        assert_eq!(plan.order[0], "/mnt/data/tmp");
        assert_eq!(plan.order[1], "/mnt/data");

        assert_eq!(plan.commands.len(), 2);
        assert!(plan.commands[0].contains("umount"));
        assert!(plan.commands[0].contains("-f"));
        assert!(plan.commands[0].contains("/mnt/data/tmp"));
        assert!(plan.commands[1].contains("-f"));
        assert!(plan.commands[1].contains("/mnt/data"));
    }

    #[test]
    fn test_unmount_error_mapping() {
        let handle = FsHandle { alias: "test".to_string() };

        // Test error code mapping
        let error = FsError::InvalidUnmountConfig("test".to_string());
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.invalid_unmount_config");

        let error = FsError::UnmountBusy("/mnt/test".to_string());
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.unmount_busy");

        let error = FsError::UnmountTimeout;
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.unmount_timeout");

        let error = FsError::NotMounted("/mnt/test".to_string());
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.not_mounted");
    }

    #[test]
    fn test_snapshot_config_validation() {
        let handle = FsHandle { alias: "test".to_string() };

        // Test zero timeout
        let config = SnapshotConfig {
            timeout_ms: 0,
            ..Default::default()
        };
        assert!(handle.validate_snapshot_config(&config).is_err());

        // Test valid config
        let config = SnapshotConfig {
            timeout_ms: 5000,
            include_usage: true,
            include_inodes: false,
            format: SnapshotFormat::Json,
            ..Default::default()
        };
        assert!(handle.validate_snapshot_config(&config).is_ok());
    }

    #[test]
    fn test_snapshot_filtering() {
        let handle = FsHandle { alias: "test".to_string() };

        let raw_mounts = vec![
            RawMountInfo {
                source: "/dev/sda1".to_string(),
                target: "/".to_string(),
                fstype: "ext4".to_string(),
                options: "rw,relatime".to_string(),
                dump: 0,
                pass: 1,
            },
            RawMountInfo {
                source: "proc".to_string(),
                target: "/proc".to_string(),
                fstype: "proc".to_string(),
                options: "rw,nosuid,nodev,noexec,relatime".to_string(),
                dump: 0,
                pass: 0,
            },
            RawMountInfo {
                source: "/dev/sda2".to_string(),
                target: "/mnt/data".to_string(),
                fstype: "ext4".to_string(),
                options: "rw,relatime".to_string(),
                dump: 0,
                pass: 2,
            },
        ];

        // Test include_mountpoints filter
        let config = SnapshotConfig {
            include_mountpoints: vec!["/mnt".to_string()],
            ..Default::default()
        };
        let filtered = handle.apply_snapshot_filters(&raw_mounts, &config).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].target, "/mnt/data");

        // Test exclude_types filter
        let config = SnapshotConfig {
            exclude_types: vec!["proc".to_string()],
            ..Default::default()
        };
        let filtered = handle.apply_snapshot_filters(&raw_mounts, &config).unwrap();
        assert_eq!(filtered.len(), 2);
        assert!(!filtered.iter().any(|m| m.fstype == "proc"));

        // Test include_types filter
        let config = SnapshotConfig {
            include_types: vec!["ext4".to_string()],
            ..Default::default()
        };
        let filtered = handle.apply_snapshot_filters(&raw_mounts, &config).unwrap();
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|m| m.fstype == "ext4"));
    }

    #[test]
    fn test_path_normalization() {
        let handle = FsHandle { alias: "test".to_string() };

        assert_eq!(handle.normalize_path("/mnt//data/"), "/mnt/data");
        assert_eq!(handle.normalize_path("/"), "/");
        assert_eq!(handle.normalize_path("//"), "/");
        assert_eq!(handle.normalize_path("/mnt/data"), "/mnt/data");
        assert_eq!(handle.normalize_path(""), "/");
    }

    #[test]
    fn test_options_parsing() {
        let handle = FsHandle { alias: "test".to_string() };

        let options = handle.parse_and_sort_options("rw,relatime,noatime");
        assert_eq!(options, vec!["noatime", "relatime", "rw"]);

        let options = handle.parse_and_sort_options("defaults");
        assert_eq!(options, vec!["defaults"]);

        let options = handle.parse_and_sort_options("");
        assert_eq!(options.len(), 0);
    }

    #[test]
    fn test_proc_mounts_parsing() {
        let handle = FsHandle { alias: "test".to_string() };

        let proc_content = "/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 1\nproc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n";
        
        let mounts = handle.parse_proc_mounts(proc_content).unwrap();
        assert_eq!(mounts.len(), 2);
        
        assert_eq!(mounts[0].source, "/dev/sda1");
        assert_eq!(mounts[0].target, "/");
        assert_eq!(mounts[0].fstype, "ext4");
        assert_eq!(mounts[0].options, "rw,relatime,errors=remount-ro");
        assert_eq!(mounts[0].dump, 0);
        assert_eq!(mounts[0].pass, 1);
        
        assert_eq!(mounts[1].source, "proc");
        assert_eq!(mounts[1].target, "/proc");
        assert_eq!(mounts[1].fstype, "proc");
    }

    #[test]
    fn test_mount_line_parsing() {
        let handle = FsHandle { alias: "test".to_string() };

        // Linux style
        let line = "/dev/sda1 on /boot type ext2 (rw,relatime)";
        let mount = handle.parse_mount_line(line).unwrap();
        assert_eq!(mount.source, "/dev/sda1");
        assert_eq!(mount.target, "/boot");
        assert_eq!(mount.fstype, "ext2");
        assert_eq!(mount.options, "rw,relatime");

        // macOS style
        let line = "/dev/disk1s1 on / (apfs, local, read-only, journaled, noatime)";
        let mount = handle.parse_mount_line(line).unwrap();
        assert_eq!(mount.source, "/dev/disk1s1");
        assert_eq!(mount.target, "/");
        assert_eq!(mount.options, "apfs, local, read-only, journaled, noatime");
    }

    #[test]
    fn test_has_filters() {
        let handle = FsHandle { alias: "test".to_string() };

        let config = SnapshotConfig::default();
        assert!(!handle.has_filters(&config));

        let config = SnapshotConfig {
            include_types: vec!["ext4".to_string()],
            ..Default::default()
        };
        assert!(handle.has_filters(&config));

        let config = SnapshotConfig {
            exclude_mountpoints: vec!["/proc".to_string()],
            ..Default::default()
        };
        assert!(handle.has_filters(&config));
    }

    #[test]
    fn test_snapshot_error_mapping() {
        let handle = FsHandle { alias: "test".to_string() };

        let error = FsError::InvalidSnapshotConfig("test".to_string());
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.invalid_snapshot_config");

        let error = FsError::SnapshotUnsupported;
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.snapshot_unsupported");

        let error = FsError::SnapshotTimeout;
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.snapshot_timeout");

        let error = FsError::SnapshotFailed("test".to_string());
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.snapshot_failed");
    }

    #[test]
    fn test_quota_config_validation() {
        let handle = FsHandle { alias: "test".to_string() };

        // Test zero timeout
        let config = FsQuotaConfig {
            timeout_ms: 0,
            ..Default::default()
        };
        assert!(handle.validate_quota_config(&config).is_err());

        // Test both space and inodes disabled
        let config = FsQuotaConfig {
            include_space: false,
            include_inodes: false,
            ..Default::default()
        };
        assert!(handle.validate_quota_config(&config).is_err());

        // Test empty environment variable key
        let mut env = HashMap::new();
        env.insert("".to_string(), "value".to_string());
        let config = FsQuotaConfig {
            env: Some(env),
            ..Default::default()
        };
        assert!(handle.validate_quota_config(&config).is_err());

        // Test valid config
        let config = FsQuotaConfig {
            timeout_ms: 5000,
            include_space: true,
            include_inodes: false,
            ..Default::default()
        };
        assert!(handle.validate_quota_config(&config).is_ok());
    }

    #[test]
    fn test_quota_config_defaults() {
        let args = json!({
            "path": "/home",
            "subject": "testuser"
        });

        let handle = FsHandle { alias: "test".to_string() };
        let config = handle.parse_quota_config(args).unwrap();

        assert_eq!(config.path, Some("/home".to_string()));
        assert_eq!(config.subject, Some("testuser".to_string()));
        assert_eq!(config.subject_type, SubjectType::Auto);
        assert_eq!(config.resolve_uid_gid, true);
        assert_eq!(config.include_space, true);
        assert_eq!(config.include_inodes, true);
        assert_eq!(config.include_grace, true);
        assert_eq!(config.all_subjects, false);
        assert_eq!(config.units, QuotaUnits::Auto);
        assert_eq!(config.timeout_ms, 5000);
        assert!(config.env.is_none());
    }

    #[test]
    fn test_quota_config_parsing() {
        let args = json!({
            "path": "/var/log",
            "subject": "1001",
            "subject_type": "user",
            "resolve_uid_gid": false,
            "include_space": true,
            "include_inodes": false,
            "include_grace": false,
            "all_subjects": true,
            "units": "bytes",
            "timeout_ms": 10000,
            "env": {
                "QUOTA_DEBUG": "1"
            }
        });

        let handle = FsHandle { alias: "test".to_string() };
        let config = handle.parse_quota_config(args).unwrap();

        assert_eq!(config.path, Some("/var/log".to_string()));
        assert_eq!(config.subject, Some("1001".to_string()));
        assert_eq!(config.subject_type, SubjectType::User);
        assert_eq!(config.resolve_uid_gid, false);
        assert_eq!(config.include_space, true);
        assert_eq!(config.include_inodes, false);
        assert_eq!(config.include_grace, false);
        assert_eq!(config.all_subjects, true);
        assert_eq!(config.units, QuotaUnits::Bytes);
        assert_eq!(config.timeout_ms, 10000);
        
        let env = config.env.unwrap();
        assert_eq!(env.get("QUOTA_DEBUG"), Some(&"1".to_string()));
    }

    #[test]
    fn test_quota_parse_output() {
        let handle = FsHandle { alias: "test".to_string() };
        
        // Test with bytes units
        let config = FsQuotaConfig {
            units: QuotaUnits::Bytes,
            ..Default::default()
        };
        
        let output = "1024 2048 4096 none";
        let result = handle.parse_quota_output(output, &config).unwrap();
        
        // Should convert KB to bytes
        assert_eq!(result.used, 1024 * 1024);
        assert_eq!(result.soft_limit, Some(2048 * 1024));
        assert_eq!(result.hard_limit, Some(4096 * 1024));
        assert_eq!(result.grace_exceeded, false);
        assert!(result.used_percent_of_soft.is_some());
        assert_eq!(result.used_percent_of_soft.unwrap(), 50.0);

        // Test with blocks units
        let config = FsQuotaConfig {
            units: QuotaUnits::Blocks,
            ..Default::default()
        };
        
        let result = handle.parse_quota_output(output, &config).unwrap();
        assert_eq!(result.used, 1024);
        assert_eq!(result.soft_limit, Some(2048));
        assert_eq!(result.hard_limit, Some(4096));
    }

    #[test]
    fn test_quota_parse_inode_output() {
        let handle = FsHandle { alias: "test".to_string() };
        
        let config = FsQuotaConfig::default();
        let output = "512 1024 2048 none";
        let result = handle.parse_inode_quota_output(output, &config).unwrap();
        
        assert_eq!(result.used, 512);
        assert_eq!(result.soft_limit, Some(1024));
        assert_eq!(result.hard_limit, Some(2048));
        assert_eq!(result.grace_exceeded, false);
        assert!(result.used_percent_of_soft.is_some());
        assert_eq!(result.used_percent_of_soft.unwrap(), 50.0);
    }

    #[test]
    fn test_quota_parse_output_grace_exceeded() {
        let handle = FsHandle { alias: "test".to_string() };
        
        let config = FsQuotaConfig {
            units: QuotaUnits::Bytes,
            ..Default::default()
        };
        
        let output = "3072 2048 4096 expired";
        let result = handle.parse_quota_output(output, &config).unwrap();
        
        assert_eq!(result.used, 3072 * 1024);
        assert_eq!(result.soft_limit, Some(2048 * 1024));
        assert_eq!(result.hard_limit, Some(4096 * 1024));
        assert_eq!(result.grace_exceeded, true);
        assert!(result.used_percent_of_soft.unwrap() > 100.0);
    }

    #[test]
    fn test_quota_parse_output_no_limits() {
        let handle = FsHandle { alias: "test".to_string() };
        
        let config = FsQuotaConfig {
            units: QuotaUnits::Bytes,
            ..Default::default()
        };
        
        let output = "1024 0 0 none";
        let result = handle.parse_quota_output(output, &config).unwrap();
        
        assert_eq!(result.used, 1024 * 1024);
        assert_eq!(result.soft_limit, Some(0));
        assert_eq!(result.hard_limit, Some(0));
        assert_eq!(result.grace_exceeded, false);
        assert!(result.used_percent_of_soft.is_none());  // Can't calculate percentage with 0 limit
    }

    #[test]
    fn test_grace_time_parsing_special_cases() {
        let handle = FsHandle { alias: "test".to_string() };
        
        // Test special case values that should return None
        assert_eq!(handle.parse_grace_time("none"), None);
        assert_eq!(handle.parse_grace_time("never"), None);
        assert_eq!(handle.parse_grace_time("-"), None);
        assert_eq!(handle.parse_grace_time("0"), None);
        assert_eq!(handle.parse_grace_time(""), None);
        assert_eq!(handle.parse_grace_time("  "), None);
        
        // Test expired/exceeded cases that should return Some(0)
        assert_eq!(handle.parse_grace_time("expired"), Some(0));
        assert_eq!(handle.parse_grace_time("exceeded"), Some(0));
        assert_eq!(handle.parse_grace_time("EXPIRED"), Some(0));
    }

    #[test]
    fn test_grace_time_parsing_days() {
        let handle = FsHandle { alias: "test".to_string() };
        
        // Test various day formats
        assert_eq!(handle.parse_grace_time("7days"), Some(7 * 24 * 60 * 60));
        assert_eq!(handle.parse_grace_time("1day"), Some(1 * 24 * 60 * 60));
        assert_eq!(handle.parse_grace_time("14days"), Some(14 * 24 * 60 * 60));
        assert_eq!(handle.parse_grace_time("30DAYS"), Some(30 * 24 * 60 * 60));
        
        // Test invalid day formats
        assert_eq!(handle.parse_grace_time("days"), None);
        assert_eq!(handle.parse_grace_time("xdays"), None);
    }

    #[test]
    fn test_grace_time_parsing_hours() {
        let handle = FsHandle { alias: "test".to_string() };
        
        // Test various hour formats
        assert_eq!(handle.parse_grace_time("2hours"), Some(2 * 60 * 60));
        assert_eq!(handle.parse_grace_time("1hour"), Some(1 * 60 * 60));
        assert_eq!(handle.parse_grace_time("24hrs"), Some(24 * 60 * 60));
        assert_eq!(handle.parse_grace_time("5hr"), Some(5 * 60 * 60));
        assert_eq!(handle.parse_grace_time("12HOURS"), Some(12 * 60 * 60));
        
        // Test invalid hour formats
        assert_eq!(handle.parse_grace_time("hours"), None);
        assert_eq!(handle.parse_grace_time("xhours"), None);
    }

    #[test]
    fn test_grace_time_parsing_minutes() {
        let handle = FsHandle { alias: "test".to_string() };
        
        // Test various minute formats
        assert_eq!(handle.parse_grace_time("30mins"), Some(30 * 60));
        assert_eq!(handle.parse_grace_time("45min"), Some(45 * 60));
        assert_eq!(handle.parse_grace_time("60minutes"), Some(60 * 60));
        assert_eq!(handle.parse_grace_time("15MINS"), Some(15 * 60));
        
        // Test invalid minute formats
        assert_eq!(handle.parse_grace_time("mins"), None);
        assert_eq!(handle.parse_grace_time("xmins"), None);
    }

    #[test]
    fn test_grace_time_parsing_time_format() {
        let handle = FsHandle { alias: "test".to_string() };
        
        // Test HH:MM:SS format
        assert_eq!(handle.parse_grace_time("23:59:59"), Some(23 * 3600 + 59 * 60 + 59));
        assert_eq!(handle.parse_grace_time("01:30:45"), Some(1 * 3600 + 30 * 60 + 45));
        assert_eq!(handle.parse_grace_time("00:00:30"), Some(30));
        
        // Test HH:MM format (seconds assumed to be 0)
        assert_eq!(handle.parse_grace_time("12:30"), Some(12 * 3600 + 30 * 60));
        assert_eq!(handle.parse_grace_time("00:45"), Some(45 * 60));
        
        // Test invalid time formats
        assert_eq!(handle.parse_grace_time("25:00:00"), None); // Invalid hour
        assert_eq!(handle.parse_grace_time("12:60:00"), None); // Invalid minute 
        assert_eq!(handle.parse_grace_time("12:30:60"), None); // Invalid second
        assert_eq!(handle.parse_grace_time("abc:def:ghi"), None); // Non-numeric
        assert_eq!(handle.parse_grace_time("12:30:45:00"), None); // Too many parts
    }

    #[test]
    fn test_grace_time_parsing_seconds() {
        let handle = FsHandle { alias: "test".to_string() };
        
        // Test pure seconds format
        assert_eq!(handle.parse_grace_time("3600"), Some(3600));
        assert_eq!(handle.parse_grace_time("60"), Some(60));
        assert_eq!(handle.parse_grace_time("1"), Some(1));
        
        // Test invalid number formats
        assert_eq!(handle.parse_grace_time("abc"), None);
        assert_eq!(handle.parse_grace_time("12.5"), None);
    }

    #[test]
    fn test_quota_parse_output_with_grace_time() {
        let handle = FsHandle { alias: "test".to_string() };
        
        let config = FsQuotaConfig {
            units: QuotaUnits::Bytes,
            ..Default::default()
        };
        
        // Test with days grace time
        let output = "3072 2048 4096 7days";
        let result = handle.parse_quota_output(output, &config).unwrap();
        assert_eq!(result.grace_time_remaining_sec, Some(7 * 24 * 60 * 60));
        assert_eq!(result.grace_exceeded, false);
        
        // Test with HH:MM:SS grace time
        let output = "3072 2048 4096 23:59:59";
        let result = handle.parse_quota_output(output, &config).unwrap();
        assert_eq!(result.grace_time_remaining_sec, Some(23 * 3600 + 59 * 60 + 59));
        
        // Test with expired grace
        let output = "3072 2048 4096 expired";
        let result = handle.parse_quota_output(output, &config).unwrap();
        assert_eq!(result.grace_time_remaining_sec, Some(0));
        assert_eq!(result.grace_exceeded, true);
        
        // Test with no grace time
        let output = "1024 2048 4096 none";
        let result = handle.parse_quota_output(output, &config).unwrap();
        assert_eq!(result.grace_time_remaining_sec, None);
        assert_eq!(result.grace_exceeded, false);
    }

    #[test]
    fn test_inode_quota_parse_output_with_grace_time() {
        let handle = FsHandle { alias: "test".to_string() };
        
        let config = FsQuotaConfig::default();
        
        // Test with hours grace time
        let output = "1500 1024 2048 5hours";
        let result = handle.parse_inode_quota_output(output, &config).unwrap();
        assert_eq!(result.grace_time_remaining_sec, Some(5 * 60 * 60));
        assert_eq!(result.grace_exceeded, false);
        
        // Test with minutes grace time
        let output = "1500 1024 2048 30mins";
        let result = handle.parse_inode_quota_output(output, &config).unwrap();
        assert_eq!(result.grace_time_remaining_sec, Some(30 * 60));
        
        // Test with expired grace
        let output = "1500 1024 2048 exceeded";
        let result = handle.parse_inode_quota_output(output, &config).unwrap();
        assert_eq!(result.grace_time_remaining_sec, Some(0));
        assert_eq!(result.grace_exceeded, true);
    }

    #[test]
    fn test_subject_type_enum() {
        // Test deserialization
        assert_eq!(serde_json::from_str::<SubjectType>("\"auto\"").unwrap(), SubjectType::Auto);
        assert_eq!(serde_json::from_str::<SubjectType>("\"user\"").unwrap(), SubjectType::User);
        assert_eq!(serde_json::from_str::<SubjectType>("\"group\"").unwrap(), SubjectType::Group);
        assert_eq!(serde_json::from_str::<SubjectType>("\"project\"").unwrap(), SubjectType::Project);
        
        // Test that invalid values fail
        assert!(serde_json::from_str::<SubjectType>("\"invalid\"").is_err());
    }

    #[test]
    fn test_quota_units_enum() {
        // Test deserialization
        assert_eq!(serde_json::from_str::<QuotaUnits>("\"auto\"").unwrap(), QuotaUnits::Auto);
        assert_eq!(serde_json::from_str::<QuotaUnits>("\"blocks\"").unwrap(), QuotaUnits::Blocks);
        assert_eq!(serde_json::from_str::<QuotaUnits>("\"bytes\"").unwrap(), QuotaUnits::Bytes);
        
        // Test that invalid values fail
        assert!(serde_json::from_str::<QuotaUnits>("\"invalid\"").is_err());
    }

    #[test]
    fn test_quota_config_default() {
        let config = FsQuotaConfig::default();
        
        assert!(config.path.is_none());
        assert!(config.subject.is_none());
        assert_eq!(config.subject_type, SubjectType::Auto);
        assert_eq!(config.resolve_uid_gid, true);
        assert_eq!(config.include_space, true);
        assert_eq!(config.include_inodes, true);
        assert_eq!(config.include_grace, true);
        assert_eq!(config.all_subjects, false);
        assert_eq!(config.units, QuotaUnits::Auto);
        assert_eq!(config.timeout_ms, 5000);
        assert!(config.env.is_none());
    }

    #[test]
    fn test_quota_error_mapping() {
        let handle = FsHandle { alias: "test".to_string() };

        let error = FsError::InvalidQuotaConfig("test".to_string());
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.invalid_quota_config");

        let error = FsError::QuotaUnsupported;
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.quota_unsupported");

        let error = FsError::QuotaNotEnabled("test".to_string());
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.quota_not_enabled");

        let error = FsError::QuotaSubjectNotFound("test".to_string());
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.quota_subject_not_found");

        let error = FsError::QuotaTimeout;
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.quota_timeout");

        let error = FsError::QuotaFailed("test".to_string());
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.quota_failed");
    }

    #[test]
    fn test_check_config_validation() {
        let handle = FsHandle { alias: "test".to_string() };

        // Test empty target
        let config = FsCheckConfig {
            target: "".to_string(),
            ..Default::default()
        };
        assert!(handle.validate_check_config(&config).is_err());

        // Test zero timeout
        let config = FsCheckConfig {
            target: "/dev/sdb1".to_string(),
            timeout_ms: 0,
            ..Default::default()
        };
        assert!(handle.validate_check_config(&config).is_err());

        // Test repair mode without allow_repair
        let config = FsCheckConfig {
            target: "/dev/sdb1".to_string(),
            mode: CheckMode::Repair,
            allow_repair: false,
            ..Default::default()
        };
        assert!(handle.validate_check_config(&config).is_err());

        // Test valid config
        let config = FsCheckConfig {
            target: "/dev/sdb1".to_string(),
            mode: CheckMode::Check,
            ..Default::default()
        };
        assert!(handle.validate_check_config(&config).is_ok());

        // Test valid repair config
        let config = FsCheckConfig {
            target: "/dev/sdb1".to_string(),
            mode: CheckMode::Repair,
            allow_repair: true,
            ..Default::default()
        };
        assert!(handle.validate_check_config(&config).is_ok());
    }

    #[test]
    fn test_check_config_defaults() {
        let config = FsCheckConfig::default();
        
        assert_eq!(config.target, "");
        assert_eq!(config.by, CheckTargetKind::Auto);
        assert_eq!(config.filesystem_type, None);
        assert_eq!(config.mode, CheckMode::Check);
        assert_eq!(config.aggressiveness, CheckAggressiveness::Safe);
        assert!(!config.allow_repair);
        assert!(config.allow_online_check);
        assert!(config.require_unmounted_for_repair);
        assert!(!config.skip_if_mounted);
        assert!(!config.force);
        assert_eq!(config.max_pass, None);
        assert!(config.btrfs_use_scrub);
        assert!(!config.btrfs_allow_offline_check);
        assert!(!config.dry_run);
        assert_eq!(config.timeout_ms, 600000);
        assert_eq!(config.env, None);
    }

    #[test]
    fn test_check_parse_config() {
        let handle = FsHandle { alias: "test".to_string() };

        // Test basic config
        let input = json!({
            "target": "/dev/sdb1",
            "mode": "check"
        });
        let config = handle.parse_check_config(input).unwrap();
        assert_eq!(config.target, "/dev/sdb1");
        assert_eq!(config.mode, CheckMode::Check);

        // Test all fields
        let input = json!({
            "target": "/mnt/data",
            "by": "mountpoint",
            "filesystem_type": "ext4",
            "mode": "repair",
            "aggressiveness": "aggressive",
            "allow_repair": true,
            "allow_online_check": false,
            "require_unmounted_for_repair": false,
            "skip_if_mounted": true,
            "force": true,
            "max_pass": 3,
            "btrfs_use_scrub": false,
            "btrfs_allow_offline_check": true,
            "dry_run": true,
            "timeout_ms": 300000,
            "env": {
                "TEST": "value"
            }
        });
        let config = handle.parse_check_config(input).unwrap();
        
        assert_eq!(config.target, "/mnt/data");
        assert_eq!(config.by, CheckTargetKind::Mountpoint);
        assert_eq!(config.filesystem_type, Some("ext4".to_string()));
        assert_eq!(config.mode, CheckMode::Repair);
        assert_eq!(config.aggressiveness, CheckAggressiveness::Aggressive);
        assert!(config.allow_repair);
        assert!(!config.allow_online_check);
        assert!(!config.require_unmounted_for_repair);
        assert!(config.skip_if_mounted);
        assert!(config.force);
        assert_eq!(config.max_pass, Some(3));
        assert!(!config.btrfs_use_scrub);
        assert!(config.btrfs_allow_offline_check);
        assert!(config.dry_run);
        assert_eq!(config.timeout_ms, 300000);
        assert!(config.env.is_some());
    }

    #[test]
    fn test_check_filesystem_support() {
        let handle = FsHandle { alias: "test".to_string() };

        // Test supported filesystems
        assert!(handle.validate_check_filesystem_support("ext2").is_ok());
        assert!(handle.validate_check_filesystem_support("ext3").is_ok());
        assert!(handle.validate_check_filesystem_support("ext4").is_ok());
        assert!(handle.validate_check_filesystem_support("xfs").is_ok());
        assert!(handle.validate_check_filesystem_support("btrfs").is_ok());
        assert!(handle.validate_check_filesystem_support("vfat").is_ok());
        assert!(handle.validate_check_filesystem_support("reiserfs").is_ok());

        // Test unsupported filesystem
        assert!(handle.validate_check_filesystem_support("zfs").is_err());
        assert!(handle.validate_check_filesystem_support("unknown").is_err());
    }

    #[test]
    fn test_build_fsck_command() {
        let handle = FsHandle { alias: "test".to_string() };
        
        let fs_info = CheckFilesystemInfo {
            source: "/dev/sdb1".to_string(),
            fstype: "ext4".to_string(),
            mounted: false,
            readonly: false,
        };

        // Test check mode
        let config = FsCheckConfig {
            target: "/dev/sdb1".to_string(),
            mode: CheckMode::Check,
            aggressiveness: CheckAggressiveness::Safe,
            ..Default::default()
        };
        let (tool, args) = handle.build_fsck_command(&config, &fs_info).unwrap();
        assert_eq!(tool, "fsck.ext4");
        assert!(args.contains(&"-n".to_string()));
        assert!(args.contains(&"/dev/sdb1".to_string()));

        // Test repair mode
        let config = FsCheckConfig {
            target: "/dev/sdb1".to_string(),
            mode: CheckMode::Repair,
            allow_repair: true,
            ..Default::default()
        };
        let (tool, args) = handle.build_fsck_command(&config, &fs_info).unwrap();
        assert_eq!(tool, "fsck.ext4");
        assert!(args.contains(&"-p".to_string()));
        assert!(args.contains(&"/dev/sdb1".to_string()));

        // Test aggressive mode
        let config = FsCheckConfig {
            target: "/dev/sdb1".to_string(),
            mode: CheckMode::Check,
            aggressiveness: CheckAggressiveness::Aggressive,
            ..Default::default()
        };
        let (tool, args) = handle.build_fsck_command(&config, &fs_info).unwrap();
        assert!(args.contains(&"-f".to_string()));
    }

    #[test]
    fn test_build_xfs_repair_command() {
        let handle = FsHandle { alias: "test".to_string() };
        
        let fs_info = CheckFilesystemInfo {
            source: "/dev/sdb1".to_string(),
            fstype: "xfs".to_string(),
            mounted: false,
            readonly: false,
        };

        // Test check mode
        let config = FsCheckConfig {
            target: "/dev/sdb1".to_string(),
            mode: CheckMode::Check,
            ..Default::default()
        };
        let (tool, args) = handle.build_xfs_repair_command(&config, &fs_info).unwrap();
        assert_eq!(tool, "xfs_repair");
        assert!(args.contains(&"-n".to_string()));
        assert!(args.contains(&"/dev/sdb1".to_string()));

        // Test repair mode on unmounted fs
        let config = FsCheckConfig {
            target: "/dev/sdb1".to_string(),
            mode: CheckMode::Repair,
            allow_repair: true,
            ..Default::default()
        };
        let (tool, args) = handle.build_xfs_repair_command(&config, &fs_info).unwrap();
        assert_eq!(tool, "xfs_repair");
        assert!(!args.contains(&"-n".to_string())); // No -n for actual repair
        assert!(args.contains(&"/dev/sdb1".to_string()));

        // Test repair mode on mounted fs (should fallback to check)
        let fs_info_mounted = CheckFilesystemInfo {
            source: "/dev/sdb1".to_string(),
            fstype: "xfs".to_string(),
            mounted: true,
            readonly: false,
        };
        let (tool, args) = handle.build_xfs_repair_command(&config, &fs_info_mounted).unwrap();
        assert!(args.contains(&"-n".to_string())); // Should fallback to check
    }

    #[test]
    fn test_build_btrfs_command() {
        let handle = FsHandle { alias: "test".to_string() };
        
        let fs_info_mounted = CheckFilesystemInfo {
            source: "/dev/sdb1".to_string(),
            fstype: "btrfs".to_string(),
            mounted: true,
            readonly: false,
        };

        let fs_info_unmounted = CheckFilesystemInfo {
            source: "/dev/sdb1".to_string(),
            fstype: "btrfs".to_string(),
            mounted: false,
            readonly: false,
        };

        // Test online scrub
        let config = FsCheckConfig {
            target: "/mnt/data".to_string(),
            mode: CheckMode::Check,
            btrfs_use_scrub: true,
            ..Default::default()
        };
        let (tool, args) = handle.build_btrfs_command(&config, &fs_info_mounted).unwrap();
        assert_eq!(tool, "btrfs");
        assert!(args.contains(&"scrub".to_string()));
        assert!(args.contains(&"start".to_string()));
        assert!(args.contains(&"-B".to_string()));
        assert!(args.contains(&"/mnt/data".to_string()));

        // Test offline check
        let config = FsCheckConfig {
            target: "/dev/sdb1".to_string(),
            mode: CheckMode::Check,
            btrfs_use_scrub: false,
            btrfs_allow_offline_check: true,
            ..Default::default()
        };
        let (tool, args) = handle.build_btrfs_command(&config, &fs_info_unmounted).unwrap();
        assert_eq!(tool, "btrfs");
        assert!(args.contains(&"check".to_string()));
        assert!(args.contains(&"--readonly".to_string()));
        assert!(args.contains(&"/dev/sdb1".to_string()));

        // Test offline repair
        let config = FsCheckConfig {
            target: "/dev/sdb1".to_string(),
            mode: CheckMode::Repair,
            allow_repair: true,
            btrfs_use_scrub: false,
            btrfs_allow_offline_check: true,
            ..Default::default()
        };
        let (tool, args) = handle.build_btrfs_command(&config, &fs_info_unmounted).unwrap();
        assert!(args.contains(&"--repair".to_string()));
    }

    #[test]
    fn test_analyze_fsck_results() {
        let handle = FsHandle { alias: "test".to_string() };
        let config = FsCheckConfig::default();

        // Test clean filesystem
        let tool = CheckTool {
            name: "fsck.ext4".to_string(),
            command: "fsck.ext4 -n /dev/sdb1".to_string(),
            exit_code: 0,
            stdout: "clean".to_string(),
            stderr: "".to_string(),
        };
        let analysis = handle.analyze_fsck_results(&config, &tool).unwrap();
        assert!(!analysis.errors_found);
        assert!(!analysis.repaired);
        assert!(!analysis.needs_repair);
        assert_eq!(analysis.filesystem_state, "clean");

        // Test errors corrected
        let tool = CheckTool {
            name: "fsck.ext4".to_string(),
            command: "fsck.ext4 -p /dev/sdb1".to_string(),
            exit_code: 1,
            stdout: "errors corrected".to_string(),
            stderr: "".to_string(),
        };
        let analysis = handle.analyze_fsck_results(&config, &tool).unwrap();
        assert!(analysis.errors_found);
        assert!(analysis.repaired);
        assert!(!analysis.needs_repair);
        assert_eq!(analysis.filesystem_state, "repaired");

        // Test errors left uncorrected
        let tool = CheckTool {
            name: "fsck.ext4".to_string(),
            command: "fsck.ext4 -n /dev/sdb1".to_string(),
            exit_code: 4,
            stdout: "errors found".to_string(),
            stderr: "".to_string(),
        };
        let analysis = handle.analyze_fsck_results(&config, &tool).unwrap();
        assert!(analysis.errors_found);
        assert!(!analysis.repaired);
        assert!(analysis.needs_repair);
        assert_eq!(analysis.filesystem_state, "errors_detected");
    }

    #[test]
    fn test_analyze_xfs_repair_results() {
        let handle = FsHandle { alias: "test".to_string() };
        let config = FsCheckConfig::default();

        // Test clean filesystem
        let tool = CheckTool {
            name: "xfs_repair".to_string(),
            command: "xfs_repair -n /dev/sdb1".to_string(),
            exit_code: 0,
            stdout: "clean".to_string(),
            stderr: "".to_string(),
        };
        let analysis = handle.analyze_xfs_repair_results(&config, &tool).unwrap();
        assert!(!analysis.errors_found);
        assert!(!analysis.repaired);
        assert_eq!(analysis.filesystem_state, "clean");

        // Test errors found in check mode
        let tool = CheckTool {
            name: "xfs_repair".to_string(),
            command: "xfs_repair -n /dev/sdb1".to_string(),
            exit_code: 1,
            stdout: "errors found".to_string(),
            stderr: "".to_string(),
        };
        let analysis = handle.analyze_xfs_repair_results(&config, &tool).unwrap();
        assert!(analysis.errors_found);
        assert!(!analysis.repaired);
        assert!(analysis.needs_repair);
        assert_eq!(analysis.filesystem_state, "errors_detected");

        // Test errors repaired
        let tool = CheckTool {
            name: "xfs_repair".to_string(),
            command: "xfs_repair /dev/sdb1".to_string(),
            exit_code: 1,
            stdout: "errors repaired".to_string(),
            stderr: "".to_string(),
        };
        let analysis = handle.analyze_xfs_repair_results(&config, &tool).unwrap();
        assert!(analysis.errors_found);
        assert!(analysis.repaired);
        assert!(!analysis.needs_repair);
        assert_eq!(analysis.filesystem_state, "repaired");
    }

    #[test]
    fn test_analyze_btrfs_results() {
        let handle = FsHandle { alias: "test".to_string() };
        let config = FsCheckConfig::default();

        // Test clean filesystem with scrub
        let tool = CheckTool {
            name: "btrfs".to_string(),
            command: "btrfs scrub start -B /mnt/data".to_string(),
            exit_code: 0,
            stdout: "no errors".to_string(),
            stderr: "".to_string(),
        };
        let analysis = handle.analyze_btrfs_results(&config, &tool).unwrap();
        assert!(!analysis.errors_found);
        assert!(!analysis.repaired);
        assert_eq!(analysis.filesystem_state, "clean");

        // Test errors found and corrected with scrub
        let tool = CheckTool {
            name: "btrfs".to_string(),
            command: "btrfs scrub start -B /mnt/data".to_string(),
            exit_code: 1,
            stdout: "errors corrected".to_string(),
            stderr: "".to_string(),
        };
        let analysis = handle.analyze_btrfs_results(&config, &tool).unwrap();
        assert!(analysis.errors_found);
        assert!(analysis.repaired);
        assert!(!analysis.needs_repair);
        assert_eq!(analysis.filesystem_state, "repaired");

        // Test readonly check with errors
        let tool = CheckTool {
            name: "btrfs".to_string(),
            command: "btrfs check --readonly /dev/sdb1".to_string(),
            exit_code: 1,
            stdout: "errors found".to_string(),
            stderr: "".to_string(),
        };
        let analysis = handle.analyze_btrfs_results(&config, &tool).unwrap();
        assert!(analysis.errors_found);
        assert!(!analysis.repaired);
        assert!(analysis.needs_repair);
        assert_eq!(analysis.filesystem_state, "errors_detected");
    }

    #[test]
    fn test_check_error_mapping() {
        let handle = FsHandle { alias: "test".to_string() };

        let error = FsError::InvalidCheckConfig("test".to_string());
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.invalid_check_config");

        let error = FsError::CheckTargetNotFound("test".to_string());
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.check_target_not_found");

        let error = FsError::CheckUnsupportedFilesystem("test".to_string());
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.check_unsupported_filesystem");

        let error = FsError::CheckRepairNotAllowed;
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.check_repair_not_allowed");

        let error = FsError::CheckRequiresUnmountForRepair("test".to_string());
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.check_requires_unmount_for_repair");

        let error = FsError::CheckMustBeOffline("test".to_string());
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.check_must_be_offline");

        let error = FsError::CheckToolNotAvailable("test".to_string());
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.check_tool_not_available");

        let error = FsError::CheckTimeout;
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.check_timeout");

        let error = FsError::CheckFailed("test".to_string());
        assert_eq!(handle.map_error_to_code(&anyhow::anyhow!(error)), "fs.check_failed");
    }

    #[test]
    fn test_build_multi_subject_summary_result_basic() {
        let handle = FsHandle { alias: "test".to_string() };
        
        // Create test subjects
        let subjects = vec![
            QuotaSubject {
                subject: "user1".to_string(),
                subject_type: "user".to_string(),
                uid: Some(1001),
                gid: Some(1001),
                space: None,
                inodes: None,
            },
            QuotaSubject {
                subject: "user2".to_string(),
                subject_type: "user".to_string(),
                uid: Some(1002),
                gid: Some(1002),
                space: None,
                inodes: None,
            },
        ];

        // Create test configuration
        let config = FsQuotaSummaryConfig {
            subject: None,
            subject_type: SubjectType::Auto,
            resolve_uid_gid: false,
            include_space: true,
            include_inodes: true,
            include_grace: true,
            all_subjects: true,
            units: QuotaUnits::Bytes,
            timeout_ms: 5000,
            include_mountpoints: vec![],
            exclude_mountpoints: vec![],
            include_types: vec![],
            exclude_types: vec![],
            include_sources: vec![],
            exclude_sources: vec![],
            env: None,
        };

        // Test with empty filesystems
        let result = handle.build_multi_subject_summary_result(
            &subjects,
            &[],
            &[],
            &[],
            &config,
        );

        assert_eq!(result.backend, "fs");
        assert_eq!(result.verb, "quota_summary");
        assert_eq!(result.alias, "test");
        assert_eq!(result.all_subjects, true);
        assert!(result.subjects.is_some());
        
        let subject_summaries = result.subjects.unwrap();
        assert_eq!(subject_summaries.len(), 2);
        
        // Check first subject summary
        assert_eq!(subject_summaries[0].subject, "user1");
        assert_eq!(subject_summaries[0].subject_type, "user");
        assert_eq!(subject_summaries[0].uid, Some(1001));
        assert_eq!(subject_summaries[0].gid, Some(1001));
        assert!(subject_summaries[0].space.is_none());
        assert!(subject_summaries[0].inodes.is_none());
        
        // Check second subject summary
        assert_eq!(subject_summaries[1].subject, "user2");
        assert_eq!(subject_summaries[1].subject_type, "user");
        assert_eq!(subject_summaries[1].uid, Some(1002));
        assert_eq!(subject_summaries[1].gid, Some(1002));
        assert!(subject_summaries[1].space.is_none());
        assert!(subject_summaries[1].inodes.is_none());
    }

    #[test]
    fn test_aggregate_subject_quota_across_filesystems_with_data() {
        let handle = FsHandle { alias: "test".to_string() };
        
        // Create test subject
        let subject = QuotaSubject {
            subject: "user1".to_string(),
            subject_type: "user".to_string(),
            uid: Some(1001),
            gid: Some(1001),
            space: None,
            inodes: None,
        };

        // Create test filesystems with quota data
        let quota_filesystems = vec![
            QuotaSummaryFilesystem {
                source: "/dev/sda1".to_string(),
                target: "/home".to_string(),
                fstype: "ext4".to_string(),
                space_quota_enabled: true,
                inode_quota_enabled: true,
                space: Some(SpaceQuota {
                    used: 1024 * 1024 * 100, // 100MB
                    soft_limit: Some(1024 * 1024 * 500), // 500MB
                    hard_limit: Some(1024 * 1024 * 1000), // 1GB
                    grace_exceeded: false,
                    grace_time_remaining_sec: Some(7200), // 2 hours
                    used_percent_of_soft: Some(20.0),
                }),
                inodes: Some(InodeQuota {
                    used: 1000,
                    soft_limit: Some(5000),
                    hard_limit: Some(10000),
                    grace_exceeded: false,
                    grace_time_remaining_sec: Some(3600), // 1 hour
                    used_percent_of_soft: Some(20.0),
                }),
            },
            QuotaSummaryFilesystem {
                source: "/dev/sdb1".to_string(),
                target: "/var".to_string(),
                fstype: "ext4".to_string(),
                space_quota_enabled: true,
                inode_quota_enabled: true,
                space: Some(SpaceQuota {
                    used: 1024 * 1024 * 200, // 200MB
                    soft_limit: Some(1024 * 1024 * 300), // 300MB
                    hard_limit: Some(1024 * 1024 * 500), // 500MB
                    grace_exceeded: true,
                    grace_time_remaining_sec: Some(0), // expired
                    used_percent_of_soft: Some(66.7),
                }),
                inodes: Some(InodeQuota {
                    used: 2000,
                    soft_limit: Some(3000),
                    hard_limit: Some(6000),
                    grace_exceeded: true,
                    grace_time_remaining_sec: Some(0), // expired
                    used_percent_of_soft: Some(66.7),
                }),
            },
        ];

        // Create test configuration
        let config = FsQuotaSummaryConfig {
            subject: None,
            subject_type: SubjectType::Auto,
            resolve_uid_gid: false,
            include_space: true,
            include_inodes: true,
            include_grace: true,
            all_subjects: true,
            units: QuotaUnits::Bytes,
            timeout_ms: 5000,
            include_mountpoints: vec![],
            exclude_mountpoints: vec![],
            include_types: vec![],
            exclude_types: vec![],
            include_sources: vec![],
            exclude_sources: vec![],
            env: None,
        };

        // Test aggregation
        let result = handle.aggregate_subject_quota_across_filesystems(&subject, &quota_filesystems, &config);

        // Check subject information
        assert_eq!(result.subject, "user1");
        assert_eq!(result.subject_type, "user");
        assert_eq!(result.uid, Some(1001));
        assert_eq!(result.gid, Some(1001));

        // Check space aggregation
        assert!(result.space.is_some());
        let space = result.space.unwrap();
        assert_eq!(space.used, 1024 * 1024 * 300); // 100MB + 200MB = 300MB
        assert_eq!(space.soft_limit, Some(1024 * 1024 * 800)); // 500MB + 300MB = 800MB
        assert_eq!(space.hard_limit, Some(1024 * 1024 * 1500)); // 1GB + 500MB = 1500MB
        assert_eq!(space.any_grace_exceeded, true); // One filesystem has expired grace

        // Check inode aggregation
        assert!(result.inodes.is_some());
        let inodes = result.inodes.unwrap();
        assert_eq!(inodes.used, 3000); // 1000 + 2000 = 3000
        assert_eq!(inodes.soft_limit, Some(8000)); // 5000 + 3000 = 8000
        assert_eq!(inodes.hard_limit, Some(16000)); // 10000 + 6000 = 16000
        assert_eq!(inodes.any_grace_exceeded, true); // One filesystem has expired grace
    }

    #[test]
    fn test_aggregate_subject_quota_space_only() {
        let handle = FsHandle { alias: "test".to_string() };
        
        // Create test subject
        let subject = QuotaSubject {
            subject: "user1".to_string(),
            subject_type: "user".to_string(),
            uid: Some(1001),
            gid: Some(1001),
            space: None,
            inodes: None,
        };

        // Create filesystem with space quota only
        let quota_filesystems = vec![
            QuotaSummaryFilesystem {
                source: "/dev/sda1".to_string(),
                target: "/home".to_string(),
                fstype: "ext4".to_string(),
                space_quota_enabled: true,
                inode_quota_enabled: false,
                space: Some(SpaceQuota {
                    used: 1024 * 1024 * 150, // 150MB
                    soft_limit: Some(1024 * 1024 * 500), // 500MB
                    hard_limit: Some(1024 * 1024 * 1000), // 1GB
                    grace_exceeded: false,
                    grace_time_remaining_sec: None,
                    used_percent_of_soft: Some(30.0),
                }),
                inodes: None,
            },
        ];

        // Create test configuration - space only
        let config = FsQuotaSummaryConfig {
            subject: None,
            subject_type: SubjectType::Auto,
            resolve_uid_gid: false,
            include_space: true,
            include_inodes: false,
            include_grace: true,
            all_subjects: true,
            units: QuotaUnits::Bytes,
            timeout_ms: 5000,
            include_mountpoints: vec![],
            exclude_mountpoints: vec![],
            include_types: vec![],
            exclude_types: vec![],
            include_sources: vec![],
            exclude_sources: vec![],
            env: None,
        };

        // Test aggregation
        let result = handle.aggregate_subject_quota_across_filesystems(&subject, &quota_filesystems, &config);

        // Check space aggregation
        assert!(result.space.is_some());
        let space = result.space.unwrap();
        assert_eq!(space.used, 1024 * 1024 * 150);
        assert_eq!(space.soft_limit, Some(1024 * 1024 * 500));
        assert_eq!(space.hard_limit, Some(1024 * 1024 * 1000));
        assert_eq!(space.any_grace_exceeded, false);

        // Check that inodes is not included
        assert!(result.inodes.is_none());
    }

    #[test]
    fn test_aggregate_subject_quota_no_limits() {
        let handle = FsHandle { alias: "test".to_string() };
        
        // Create test subject
        let subject = QuotaSubject {
            subject: "user1".to_string(),
            subject_type: "user".to_string(),
            uid: Some(1001),
            gid: Some(1001),
            space: None,
            inodes: None,
        };

        // Create filesystem with no quota limits
        let quota_filesystems = vec![
            QuotaSummaryFilesystem {
                source: "/dev/sda1".to_string(),
                target: "/home".to_string(),
                fstype: "ext4".to_string(),
                space_quota_enabled: true,
                inode_quota_enabled: true,
                space: Some(SpaceQuota {
                    used: 1024 * 1024 * 100, // 100MB
                    soft_limit: None, // No soft limit
                    hard_limit: None, // No hard limit
                    grace_exceeded: false,
                    grace_time_remaining_sec: None,
                    used_percent_of_soft: None,
                }),
                inodes: Some(InodeQuota {
                    used: 1000,
                    soft_limit: None, // No soft limit
                    hard_limit: None, // No hard limit
                    grace_exceeded: false,
                    grace_time_remaining_sec: None,
                    used_percent_of_soft: None,
                }),
            },
        ];

        // Create test configuration
        let config = FsQuotaSummaryConfig {
            subject: None,
            subject_type: SubjectType::Auto,
            resolve_uid_gid: false,
            include_space: true,
            include_inodes: true,
            include_grace: true,
            all_subjects: true,
            units: QuotaUnits::Bytes,
            timeout_ms: 5000,
            include_mountpoints: vec![],
            exclude_mountpoints: vec![],
            include_types: vec![],
            exclude_types: vec![],
            include_sources: vec![],
            exclude_sources: vec![],
            env: None,
        };

        // Test aggregation
        let result = handle.aggregate_subject_quota_across_filesystems(&subject, &quota_filesystems, &config);

        // Check space aggregation
        assert!(result.space.is_some());
        let space = result.space.unwrap();
        assert_eq!(space.used, 1024 * 1024 * 100);
        assert_eq!(space.soft_limit, None);
        assert_eq!(space.hard_limit, None);
        assert_eq!(space.used_percent_of_soft, None);
        assert_eq!(space.any_grace_exceeded, false);

        // Check inode aggregation
        assert!(result.inodes.is_some());
        let inodes = result.inodes.unwrap();
        assert_eq!(inodes.used, 1000);
        assert_eq!(inodes.soft_limit, None);
        assert_eq!(inodes.hard_limit, None);
        assert_eq!(inodes.used_percent_of_soft, None);
        assert_eq!(inodes.any_grace_exceeded, false);
    }

    #[test]
    fn test_build_multi_subject_summary_result_with_data() {
        let handle = FsHandle { alias: "test".to_string() };
        
        // Create test subjects
        let subjects = vec![
            QuotaSubject {
                subject: "user1".to_string(),
                subject_type: "user".to_string(),
                uid: Some(1001),
                gid: Some(1001),
                space: None,
                inodes: None,
            },
        ];

        // Create test filesystems
        let quota_filesystems = vec![
            QuotaSummaryFilesystem {
                source: "/dev/sda1".to_string(),
                target: "/home".to_string(),
                fstype: "ext4".to_string(),
                space_quota_enabled: true,
                inode_quota_enabled: true,
                space: Some(SpaceQuota {
                    used: 1024 * 1024 * 100, // 100MB
                    soft_limit: Some(1024 * 1024 * 500), // 500MB
                    hard_limit: Some(1024 * 1024 * 1000), // 1GB
                    grace_exceeded: false,
                    grace_time_remaining_sec: Some(7200),
                    used_percent_of_soft: Some(20.0),
                }),
                inodes: Some(InodeQuota {
                    used: 1000,
                    soft_limit: Some(5000),
                    hard_limit: Some(10000),
                    grace_exceeded: false,
                    grace_time_remaining_sec: Some(3600),
                    used_percent_of_soft: Some(20.0),
                }),
            },
        ];

        // Create test configuration
        let config = FsQuotaSummaryConfig {
            subject: None,
            subject_type: SubjectType::Auto,
            resolve_uid_gid: false,
            include_space: true,
            include_inodes: true,
            include_grace: true,
            all_subjects: true,
            units: QuotaUnits::Bytes,
            timeout_ms: 5000,
            include_mountpoints: vec!["/home".to_string()],
            exclude_mountpoints: vec![],
            include_types: vec!["ext4".to_string()],
            exclude_types: vec![],
            include_sources: vec![],
            exclude_sources: vec![],
            env: None,
        };

        // Test with real data
        let result = handle.build_multi_subject_summary_result(
            &subjects,
            &quota_filesystems,
            &[],
            &[],
            &config,
        );

        assert_eq!(result.all_subjects, true);
        assert!(result.subjects.is_some());
        
        let subject_summaries = result.subjects.unwrap();
        assert_eq!(subject_summaries.len(), 1);
        
        // Check subject summary with aggregated data
        let summary = &subject_summaries[0];
        assert_eq!(summary.subject, "user1");
        assert_eq!(summary.subject_type, "user");
        assert_eq!(summary.uid, Some(1001));
        assert_eq!(summary.gid, Some(1001));
        
        // Check aggregated space data
        assert!(summary.space.is_some());
        let space = summary.space.as_ref().unwrap();
        assert_eq!(space.used, 1024 * 1024 * 100);
        assert_eq!(space.soft_limit, Some(1024 * 1024 * 500));
        assert_eq!(space.hard_limit, Some(1024 * 1024 * 1000));
        assert_eq!(space.any_grace_exceeded, false);
        
        // Check aggregated inode data
        assert!(summary.inodes.is_some());
        let inodes = summary.inodes.as_ref().unwrap();
        assert_eq!(inodes.used, 1000);
        assert_eq!(inodes.soft_limit, Some(5000));
        assert_eq!(inodes.hard_limit, Some(10000));
        assert_eq!(inodes.any_grace_exceeded, false);

        // Check filters are preserved
        assert_eq!(result.filters.include_mountpoints, vec!["/home".to_string()]);
        assert_eq!(result.filters.include_types, vec!["ext4".to_string()]);
        
        // Check that filesystem data is preserved
        assert_eq!(result.filesystems.len(), 1);
        assert_eq!(result.filesystems[0].target, "/home");
        assert_eq!(result.filesystems[0].fstype, "ext4");
    }
}