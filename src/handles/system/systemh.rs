use anyhow::{bail, Result};
use chrono;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use url::Url;

use crate::core::{
    registry::{Args, Handle, IoStreams},
    status::Status,
};

// ===========================================================================
// Error Types
// ===========================================================================

#[derive(Debug, Error)]
pub enum SystemError {
    #[error("invalid scope: {0}")]
    InvalidScope(String),

    #[error("invalid fields specification: {0}")]
    InvalidFields(String),

    #[error("/proc filesystem unavailable")]
    ProcUnavailable,

    #[error("failed to read {0}: {1}")]
    ReadFailed(String, String),

    #[error("operation timeout")]
    Timeout,

    #[error("too many mounts requested: {0}")]
    TooManyMounts(u32),

    #[error("data too large")]
    DataTooLarge,

    #[error("internal error: {0}")]
    InternalError(String),

    #[error("invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("uptime unavailable: {0}")]
    UptimeUnavailable(String),

    #[error("uptime parse error: {0}")]
    UptimeParseError(String),

    #[error("load unavailable: {0}")]
    LoadUnavailable(String),

    #[error("load parse error: {0}")]
    LoadParseError(String),

    #[error("CPU count unavailable")]
    CpuCountUnavailable,

    #[error("memory unavailable")]
    MemoryUnavailable,

    #[error("meminfo unavailable: {0}")]
    MeminfoUnavailable(String),

    #[error("cgroup unavailable: {0}")]
    CgroupUnavailable(String),

    #[error("meminfo parse error: {0}")]
    MeminfoParseError(String),

    #[error("cgroup parse error: {0}")]
    CgroupParseError(String),

    #[error("memory internal error: {0}")]
    MemoryInternalError(String),

    // CPU-specific errors
    #[error("cpu stat unavailable: {0}")]
    CpuStatUnavailable(String),

    #[error("cpu stat parse error: {0}")]
    CpuStatParseError(String),

    #[error("cpu cpufreq unavailable: {0}")]
    CpuCpufreqUnavailable(String),

    #[error("cpu cpufreq parse error: {0}")]
    CpuCpufreqParseError(String),

    #[error("cpu cgroup unavailable: {0}")]
    CpuCgroupUnavailable(String),

    #[error("cpu cgroup parse error: {0}")]
    CpuCgroupParseError(String),

    #[error("cpu unavailable")]
    CpuUnavailable,

    #[error("cpu internal error: {0}")]
    CpuInternalError(String),

    // Disk-specific errors
    #[error("disk mounts unavailable: {0}")]
    DiskMountsUnavailable(String),

    #[error("disk mounts parse error: {0}")]
    DiskMountsParseError(String),

    #[error("disk statvfs failed for {0}: {1}")]
    DiskStatvfsFailed(String, String),

    #[error("disk diskstats unavailable: {0}")]
    DiskDiskstatsUnavailable(String),

    #[error("disk diskstats parse error: {0}")]
    DiskDiskstatsParseError(String),

    #[error("disk unavailable")]
    DiskUnavailable,

    #[error("disk internal error: {0}")]
    DiskInternalError(String),

    // Environment variable listing errors
    #[error("environment variable listing unavailable: {0}")]
    EnvListUnavailable(String),

    #[error("environment variable listing for PID unavailable: {0}")]
    EnvListPidUnavailable(String),

    #[error("environment variable listing not supported for PID: {0}")]
    EnvListNotSupportedForPid(String),

    #[error("invalid regex filter: {0}")]
    EnvListInvalidRegex(String),

    #[error("environment variable listing internal error: {0}")]
    EnvListInternalError(String),
}

impl SystemError {
    pub fn code(&self) -> String {
        match self {
            Self::InvalidScope(_) => "system.info_scope_invalid".to_string(),
            Self::InvalidFields(_) => "system.info_fields_invalid".to_string(),
            Self::ProcUnavailable => "system.info_proc_unavailable".to_string(),
            Self::ReadFailed(_, _) => "system.info_read_failed".to_string(),
            Self::Timeout => "system.info_timeout".to_string(),
            Self::TooManyMounts(_) => "system.info_too_many_mounts".to_string(),
            Self::DataTooLarge => "system.info_data_too_large".to_string(),
            Self::InternalError(_) => "system.info_internal_error".to_string(),
            Self::InvalidParameter(_) => "system.info_invalid_parameter".to_string(),
            Self::UptimeUnavailable(_) => "system.uptime_unavailable".to_string(),
            Self::UptimeParseError(_) => "system.uptime_parse_error".to_string(),
            Self::LoadUnavailable(_) => "system.load_unavailable".to_string(),
            Self::LoadParseError(_) => "system.load_parse_error".to_string(),
            Self::CpuCountUnavailable => "system.load_cpu_count_unavailable".to_string(),
            Self::MemoryUnavailable => "system.memory_unavailable".to_string(),
            Self::MeminfoUnavailable(_) => "system.memory_meminfo_unavailable".to_string(),
            Self::CgroupUnavailable(_) => "system.memory_cgroup_unavailable".to_string(),
            Self::MeminfoParseError(_) => "system.memory_meminfo_parse_error".to_string(),
            Self::CgroupParseError(_) => "system.memory_cgroup_parse_error".to_string(),
            Self::MemoryInternalError(_) => "system.memory_internal_error".to_string(),

            // CPU-specific error codes
            Self::CpuStatUnavailable(_) => "system.cpu_stat_unavailable".to_string(),
            Self::CpuStatParseError(_) => "system.cpu_stat_parse_error".to_string(),
            Self::CpuCpufreqUnavailable(_) => "system.cpu_cpufreq_unavailable".to_string(),
            Self::CpuCpufreqParseError(_) => "system.cpu_cpufreq_parse_error".to_string(),
            Self::CpuCgroupUnavailable(_) => "system.cpu_cgroup_unavailable".to_string(),
            Self::CpuCgroupParseError(_) => "system.cpu_cgroup_parse_error".to_string(),
            Self::CpuUnavailable => "system.cpu_unavailable".to_string(),
            Self::CpuInternalError(_) => "system.cpu_internal_error".to_string(),

            // Disk-specific error codes
            Self::DiskMountsUnavailable(_) => "system.disk_mounts_unavailable".to_string(),
            Self::DiskMountsParseError(_) => "system.disk_mounts_parse_error".to_string(),
            Self::DiskStatvfsFailed(_, _) => "system.disk_statvfs_failed".to_string(),
            Self::DiskDiskstatsUnavailable(_) => "system.disk_diskstats_unavailable".to_string(),
            Self::DiskDiskstatsParseError(_) => "system.disk_diskstats_parse_error".to_string(),
            Self::DiskUnavailable => "system.disk_unavailable".to_string(),
            Self::DiskInternalError(_) => "system.disk_internal_error".to_string(),

            // Environment variable listing error codes
            Self::EnvListUnavailable(_) => "system.env_list_unavailable".to_string(),
            Self::EnvListPidUnavailable(_) => "system.env_list_pid_unavailable".to_string(),
            Self::EnvListNotSupportedForPid(_) => "system.env_list_not_supported_for_pid".to_string(),
            Self::EnvListInvalidRegex(_) => "system.env_list_invalid_regex".to_string(),
            Self::EnvListInternalError(_) => "system.env_list_internal_error".to_string(),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "ok": false,
            "error": {
                "code": self.code(),
                "message": self.to_string(),
            }
        })
    }
}

// ===========================================================================
// Configuration Structures
// ===========================================================================

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SystemInfoOptions {
    pub scopes: Vec<String>,
    pub fields: Option<Vec<String>>,

    pub sample_duration_ms: u64,
    pub sample_min_ms: u64,
    pub per_cpu: bool,

    pub max_mounts: u32,
    pub max_process_classes: u32,

    pub include_raw: bool,
    pub include_paths: bool,

    pub format: String,
}

impl Default for SystemInfoOptions {
    fn default() -> Self {
        Self {
            scopes: vec![
                "os".to_string(),
                "kernel".to_string(),
                "cpu".to_string(),
                "memory".to_string(),
                "load".to_string(),
            ],
            fields: None,
            sample_duration_ms: 0,
            sample_min_ms: 50,
            per_cpu: false,
            max_mounts: 32,
            max_process_classes: 5,
            include_raw: false,
            include_paths: false,
            format: "json".to_string(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SystemInfoResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,
    pub scopes: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pressure: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virtualization: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    pub warnings: Vec<String>,
}

// ===========================================================================
// System Uptime Configuration & Response
// ===========================================================================

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SystemUptimeOptions {
    pub include_idle: bool,
    pub include_boot_time: bool,
    pub include_human: bool,
    pub include_raw: bool,
    pub include_paths: bool,
    pub format: String,
}

impl Default for SystemUptimeOptions {
    fn default() -> Self {
        Self {
            include_idle: true,
            include_boot_time: true,
            include_human: true,
            include_raw: false,
            include_paths: false,
            format: "json".to_string(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SystemUptimeResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_human: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_time_unix: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_seconds_per_cpu: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    pub warnings: Vec<String>,
}

// ===========================================================================
// System Load Configuration & Response
// ===========================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputFormat {
    Json,
    Text,
}

impl<'de> Deserialize<'de> for OutputFormat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "json" => Ok(OutputFormat::Json),
            "text" => Ok(OutputFormat::Text),
            _ => Err(serde::de::Error::custom(format!("invalid format: {}", s))),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SystemLoadOptions {
    pub normalize_per_cpu: bool,
    pub include_queue: bool,
    pub include_human: bool,
    pub include_raw: bool,
    pub include_paths: bool,
    pub min_cpu_count: u32,
    pub format: OutputFormat,
}

impl Default for SystemLoadOptions {
    fn default() -> Self {
        Self {
            normalize_per_cpu: true,
            include_queue: true,
            include_human: true,
            include_raw: false,
            include_paths: false,
            min_cpu_count: 1,
            format: OutputFormat::Json,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SystemLoadHumanInfo {
    pub status: String,
    pub status_reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_vs_cpu_ratio: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct SystemLoadResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_1m: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_5m: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_15m: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_1m_per_cpu: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_5m_per_cpu: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_15m_per_cpu: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_count_logical: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runnable_processes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_processes: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub human: Option<SystemLoadHumanInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    pub warnings: Vec<String>,
}

// ===========================================================================
// System Memory Configuration & Response
// ===========================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct SystemMemoryOptions {
    pub include_swap: bool,
    pub include_cgroup: bool,
    pub include_hugepages: bool,
    pub include_human: bool,
    pub include_raw: bool,
    pub include_paths: bool,
    pub format: String,
}

impl Default for SystemMemoryOptions {
    fn default() -> Self {
        Self {
            include_swap: true,
            include_cgroup: true,
            include_hugepages: true,
            include_human: true,
            include_raw: false,
            include_paths: false,
            format: "json".to_string(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SystemMemorySystemMetrics {
    pub available: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_total_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_free_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_available_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buffers_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shmem_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sreclaimable_bytes: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_total_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_free_bytes: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_used_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_used_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_used_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_used_pct: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct SystemMemoryHugepagesMetrics {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reserved: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surplus: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct SystemMemoryCgroupMetrics {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unified: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_limit_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_usage_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_used_pct: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_limit_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_usage_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_used_pct: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct SystemMemoryHumanSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup_summary: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SystemMemoryResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemMemorySystemMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hugepages: Option<SystemMemoryHugepagesMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<SystemMemoryCgroupMetrics>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub human: Option<SystemMemoryHumanSummary>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    pub warnings: Vec<String>,
}

// ===========================================================================
// System CPU Configuration & Response
// ===========================================================================

// CPU data structures for parsing /proc/stat
#[derive(Debug, Clone)]
pub struct CpuStatLine {
    pub name: String,
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
    pub guest: u64,
    pub guest_nice: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SystemCpuOptions {
    pub sample_duration_ms: u64,
    pub sample_min_ms: u64,
    pub per_cpu: bool,

    pub include_topology: bool,
    pub include_frequency: bool,
    pub include_cgroup: bool,
    pub include_human: bool,
    pub include_raw: bool,
    pub include_paths: bool,

    pub format: OutputFormat,
}

impl Default for SystemCpuOptions {
    fn default() -> Self {
        Self {
            sample_duration_ms: 250,
            sample_min_ms: 50,
            per_cpu: true,
            include_topology: true,
            include_frequency: true,
            include_cgroup: true,
            include_human: true,
            include_raw: false,
            include_paths: false,
            format: OutputFormat::Json,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SystemCpuSystemMetrics {
    pub available: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub logical_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket_count: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub utilization_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nice_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iowait_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub irq_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub softirq_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steal_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_nice_pct: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_current_hz: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_max_hz: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct SystemCpuCoreMetrics {
    pub id: u32,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub utilization_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nice_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iowait_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub irq_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub softirq_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steal_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_nice_pct: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_current_hz: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_max_hz: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub core_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket_id: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct SystemCpuCgroupMetrics {
    pub available: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub unified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_quota_cores: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_period_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_quota_us: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_user_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_system_seconds: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct SystemCpuHumanInfo {
    pub status: String,
    pub status_reason: String,
    pub per_cpu_hotspots: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SystemCpuResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemCpuSystemMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub per_cpu: Option<Vec<SystemCpuCoreMetrics>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<SystemCpuCgroupMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human: Option<SystemCpuHumanInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    pub warnings: Vec<String>,
}

// ===========================================================================
// System Disk Configuration & Response
// ===========================================================================

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SystemDiskOptions {
    pub mount_points: Vec<String>,
    pub devices: Vec<String>,
    pub fs_types: Vec<String>,
    pub include_virtual: bool,

    pub max_mounts: u32,

    pub include_io: bool,
    pub include_fs_types: bool,
    pub include_human: bool,
    pub include_raw: bool,
    pub include_paths: bool,

    pub format: OutputFormat,
}

impl Default for SystemDiskOptions {
    fn default() -> Self {
        Self {
            mount_points: vec![],
            devices: vec![],
            fs_types: vec![],
            include_virtual: false,
            max_mounts: 64,
            include_io: true,
            include_fs_types: true,
            include_human: true,
            include_raw: false,
            include_paths: false,
            format: OutputFormat::Json,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SystemDiskMountEntry {
    pub mount_point: String,
    pub device: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs_type: Option<String>,
    pub virtual_fs: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avail_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_pct: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub inodes_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inodes_used: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inodes_free: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inodes_used_pct: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_device: Option<String>,
    pub tags: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_summary: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SystemDiskIoDeviceEntry {
    pub name: String,
    pub maj_min: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub reads_completed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writes_completed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sectors_read: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sectors_written: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_bytes: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_reading_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_writing_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ios_in_progress: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_in_io_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weighted_time_in_io_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct SystemDiskIoMetrics {
    pub available: bool,
    pub devices: Vec<SystemDiskIoDeviceEntry>,
}

#[derive(Debug, Serialize)]
pub struct SystemDiskHumanSummary {
    pub summaries: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SystemDiskResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub mounts_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mounts: Option<Vec<SystemDiskMountEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io: Option<SystemDiskIoMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human: Option<SystemDiskHumanSummary>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    pub warnings: Vec<String>,
}

// ===========================================================================
// System Environment Variable Configuration & Response
// ===========================================================================

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SystemEnvListOptions {
    // Target process
    pub pid: Option<i64>,

    // Filters
    pub names: Vec<String>,
    pub prefix_filters: Vec<String>,
    pub regex_filters: Vec<String>,

    // Value behavior
    pub include_values: bool,
    pub include_sensitive: bool,
    pub truncate_length: u32,

    // Limits
    pub max_vars: u32,

    // Sorting
    pub sort_by: String,      // "name" | "length" | "none"
    pub sort_order: String,   // "asc" | "desc"

    // Debug / inspection
    pub include_raw: bool,
    pub include_paths: bool,

    // Output
    pub format: String, // "json" | "text"
}

impl Default for SystemEnvListOptions {
    fn default() -> Self {
        Self {
            pid: None,
            names: Vec::new(),
            prefix_filters: Vec::new(),
            regex_filters: Vec::new(),
            include_values: true,
            include_sensitive: false,
            truncate_length: 512,
            max_vars: 1024,
            sort_by: "name".to_string(),
            sort_order: "asc".to_string(),
            include_raw: false,
            include_paths: false,
            format: "json".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemEnvVarEntry {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub masked: bool,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_length: Option<usize>,
    pub source: String, // "process" | "proc"
}

#[derive(Debug, Serialize)]
pub struct SystemEnvListHumanSummary {
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EnvSourceKind {
    Process, // current process via std::env
    Proc,    // /proc/<pid>/environ
}

#[derive(Debug, Serialize)]
pub struct SystemEnvListResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>, // "process" | "proc"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_count_total: Option<u32>,
    pub env_count_returned: u32,
    pub env_count_masked: u32,
    pub env_count_truncated: u32,
    pub truncated_vars: bool,

    pub variables: Vec<SystemEnvVarEntry>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human: Option<SystemEnvListHumanSummary>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    pub warnings: Vec<String>,
}

// ===========================================================================
// SystemProvider Trait (for testing abstraction)
// ===========================================================================

pub trait SystemProvider {
    fn read_file(&self, path: &str) -> Result<String>;
    fn read_proc_stat(&self) -> Result<String>;
    fn read_proc_meminfo(&self) -> Result<String>;
    fn read_proc_loadavg(&self) -> Result<String>;
    fn read_proc_uptime(&self) -> Result<String>;
    fn read_os_release(&self) -> Result<String>;
    fn get_uname(&self) -> Result<(String, String, String, String)>;
    fn get_hostname(&self) -> Result<String>;
    fn list_mounts(&self) -> Result<Vec<(String, String, String)>>;
    fn get_disk_stats(&self, mount_point: &str) -> Result<(u64, u64, u64)>;
    fn get_cpu_count(&self) -> Result<u32>;
    fn now_unix_ms(&self) -> i64;
    
    // Cgroup memory methods
    fn read_cgroup_memory_max(&self) -> Result<String>;
    fn read_cgroup_memory_current(&self) -> Result<String>;
    fn read_cgroup_memory_swap_max(&self) -> Result<String>;
    fn read_cgroup_memory_swap_current(&self) -> Result<String>;

    // CPU-specific methods
    fn read_cpu_frequency_current(&self, cpu_id: u32) -> Result<String>;
    fn read_cpu_frequency_max(&self, cpu_id: u32) -> Result<String>;
    fn read_cpu_topology(&self, cpu_id: u32) -> Result<(Option<u32>, Option<u32>)>; // (core_id, socket_id)
    
    // Cgroup CPU methods
    fn read_cgroup_cpu_max(&self) -> Result<String>;
    fn read_cgroup_cpu_stat(&self) -> Result<String>;
    fn read_cgroup_cpu_quota(&self) -> Result<String>;
    fn read_cgroup_cpu_period(&self) -> Result<String>;
    fn read_cgroup_cpu_usage(&self) -> Result<String>;
    
    // Sleep for sampling
    fn sleep_ms(&self, duration_ms: u64);

    // Disk-specific methods
    fn read_proc_mounts(&self) -> Result<String>;
    fn read_proc_self_mounts(&self) -> Result<String>;
    fn read_proc_diskstats(&self) -> Result<String>;
    fn statvfs_mount(&self, mount_point: &str) -> Result<(u64, u64, u64, u64, u64, u64, u64, u64)>;

    // Environment variable methods
    fn get_current_process_env(&self) -> Result<Vec<(String, String)>>;
    fn get_process_env(&self, pid: i64) -> Result<Vec<(String, String)>>;
    fn get_current_process_id(&self) -> i64;
}

pub struct RealSystemProvider;

impl SystemProvider for RealSystemProvider {
    fn read_file(&self, path: &str) -> Result<String> {
        fs::read_to_string(path)
            .map_err(|e| SystemError::ReadFailed(path.to_string(), e.to_string()).into())
    }

    fn read_proc_stat(&self) -> Result<String> {
        self.read_file("/proc/stat")
    }

    fn read_proc_meminfo(&self) -> Result<String> {
        self.read_file("/proc/meminfo")
    }

    fn read_proc_loadavg(&self) -> Result<String> {
        self.read_file("/proc/loadavg")
    }

    fn read_proc_uptime(&self) -> Result<String> {
        self.read_file("/proc/uptime")
    }

    fn read_os_release(&self) -> Result<String> {
        self.read_file("/etc/os-release")
    }

    fn get_uname(&self) -> Result<(String, String, String, String)> {
        use std::process::Command;

        let output = Command::new("uname").arg("-a").output()
            .map_err(|e| SystemError::InternalError(format!("uname failed: {}", e)))?;

        let full = String::from_utf8_lossy(&output.stdout).to_string();
        let parts: Vec<&str> = full.split_whitespace().collect();

        let sysname = parts.get(0).unwrap_or(&"").to_string();
        let release = parts.get(2).unwrap_or(&"").to_string();
        let version = parts.get(3).unwrap_or(&"").to_string();
        let machine = parts.get(parts.len() - 1).unwrap_or(&"").to_string();

        Ok((sysname, release, version, machine))
    }

    fn get_hostname(&self) -> Result<String> {
        use std::process::Command;

        let output = Command::new("hostname").output()
            .map_err(|e| SystemError::InternalError(format!("hostname failed: {}", e)))?;

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    fn list_mounts(&self) -> Result<Vec<(String, String, String)>> {
        let content = self.read_file("/proc/mounts")?;
        let mut mounts = Vec::new();

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let device = parts[0].to_string();
                let mount_point = parts[1].to_string();
                let fs_type = parts[2].to_string();
                mounts.push((device, mount_point, fs_type));
            }
        }

        Ok(mounts)
    }

    fn get_disk_stats(&self, mount_point: &str) -> Result<(u64, u64, u64)> {
        use nix::sys::statvfs::statvfs;

        let stats = statvfs(mount_point)
            .map_err(|e| SystemError::ReadFailed(mount_point.to_string(), e.to_string()))?;

        let total = stats.blocks() * stats.block_size();
        let free = stats.blocks_free() * stats.block_size();
        let used = total - free;

        Ok((total, used, free))
    }

    fn get_cpu_count(&self) -> Result<u32> {
        // Count CPUs from /proc/stat
        let content = self.read_proc_stat()?;
        let count = content.lines()
            .filter(|line| line.starts_with("cpu") && line.chars().nth(3).map_or(false, |c| c.is_ascii_digit()))
            .count();
        Ok(count as u32)
    }

    fn now_unix_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as i64
    }

    fn read_cgroup_memory_max(&self) -> Result<String> {
        // Try cgroup v2 first, then fall back to v1
        if let Ok(content) = self.read_file("/sys/fs/cgroup/memory.max") {
            return Ok(content);
        }
        
        // cgroup v1 fallback
        self.read_file("/sys/fs/cgroup/memory/memory.limit_in_bytes")
    }

    fn read_cgroup_memory_current(&self) -> Result<String> {
        // Try cgroup v2 first, then fall back to v1
        if let Ok(content) = self.read_file("/sys/fs/cgroup/memory.current") {
            return Ok(content);
        }
        
        // cgroup v1 fallback
        self.read_file("/sys/fs/cgroup/memory/memory.usage_in_bytes")
    }

    fn read_cgroup_memory_swap_max(&self) -> Result<String> {
        // Try cgroup v2 first, then fall back to v1
        if let Ok(content) = self.read_file("/sys/fs/cgroup/memory.swap.max") {
            return Ok(content);
        }
        
        // cgroup v1 fallback
        self.read_file("/sys/fs/cgroup/memory/memory.memsw.limit_in_bytes")
    }

    fn read_cgroup_memory_swap_current(&self) -> Result<String> {
        // Try cgroup v2 first, then fall back to v1
        if let Ok(content) = self.read_file("/sys/fs/cgroup/memory.swap.current") {
            return Ok(content);
        }
        
        // cgroup v1 fallback
        self.read_file("/sys/fs/cgroup/memory/memory.memsw.usage_in_bytes")
    }

    // CPU-specific methods
    fn read_cpu_frequency_current(&self, cpu_id: u32) -> Result<String> {
        self.read_file(&format!("/sys/devices/system/cpu/cpu{}/cpufreq/scaling_cur_freq", cpu_id))
    }

    fn read_cpu_frequency_max(&self, cpu_id: u32) -> Result<String> {
        self.read_file(&format!("/sys/devices/system/cpu/cpu{}/cpufreq/cpuinfo_max_freq", cpu_id))
    }

    fn read_cpu_topology(&self, cpu_id: u32) -> Result<(Option<u32>, Option<u32>)> {
        let core_id = self.read_file(&format!("/sys/devices/system/cpu/cpu{}/topology/core_id", cpu_id))
            .ok()
            .and_then(|s| s.trim().parse().ok());
            
        let socket_id = self.read_file(&format!("/sys/devices/system/cpu/cpu{}/topology/physical_package_id", cpu_id))
            .ok()
            .and_then(|s| s.trim().parse().ok());
            
        Ok((core_id, socket_id))
    }
    
    // Cgroup CPU methods
    fn read_cgroup_cpu_max(&self) -> Result<String> {
        // Try cgroup v2 first
        if let Ok(content) = self.read_file("/sys/fs/cgroup/cpu.max") {
            return Ok(content);
        }
        
        // cgroup v1 fallback - read both files and format as "quota period"
        let quota = self.read_file("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")?;
        let period = self.read_file("/sys/fs/cgroup/cpu/cpu.cfs_period_us")?;
        Ok(format!("{} {}", quota.trim(), period.trim()))
    }

    fn read_cgroup_cpu_stat(&self) -> Result<String> {
        // Try cgroup v2 first
        if let Ok(content) = self.read_file("/sys/fs/cgroup/cpu.stat") {
            return Ok(content);
        }
        
        // cgroup v1 fallback - read usage from cpuacct
        self.read_file("/sys/fs/cgroup/cpuacct/cpuacct.usage")
    }

    fn read_cgroup_cpu_quota(&self) -> Result<String> {
        self.read_file("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
    }

    fn read_cgroup_cpu_period(&self) -> Result<String> {
        self.read_file("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
    }

    fn read_cgroup_cpu_usage(&self) -> Result<String> {
        self.read_file("/sys/fs/cgroup/cpuacct/cpuacct.usage")
    }
    
    fn sleep_ms(&self, duration_ms: u64) {
        thread::sleep(Duration::from_millis(duration_ms));
    }

    // Disk-specific method implementations
    fn read_proc_mounts(&self) -> Result<String> {
        self.read_file("/proc/mounts")
    }

    fn read_proc_self_mounts(&self) -> Result<String> {
        self.read_file("/proc/self/mounts")
    }

    fn read_proc_diskstats(&self) -> Result<String> {
        self.read_file("/proc/diskstats")
    }

    fn statvfs_mount(&self, mount_point: &str) -> Result<(u64, u64, u64, u64, u64, u64, u64, u64)> {
        use nix::sys::statvfs::statvfs;

        let stats = statvfs(mount_point)
            .map_err(|e| SystemError::DiskStatvfsFailed(mount_point.to_string(), e.to_string()))?;

        // f_frsize: fragment size (preferred block size for I/O)
        // f_bsize: filesystem block size
        let block_size = if stats.fragment_size() > 0 { stats.fragment_size() } else { stats.block_size() };
        
        let total_blocks = stats.blocks();
        let free_blocks = stats.blocks_free();
        let avail_blocks = stats.blocks_available();
        let used_blocks = total_blocks.saturating_sub(free_blocks);
        
        let total_bytes = total_blocks * block_size;
        let free_bytes = free_blocks * block_size;
        let avail_bytes = avail_blocks * block_size;
        let used_bytes = used_blocks * block_size;

        let inodes_total = stats.files();
        let inodes_free = stats.files_free();
        let inodes_avail = stats.files_available();
        let inodes_used = inodes_total.saturating_sub(inodes_free);

        Ok((total_bytes, used_bytes, free_bytes, avail_bytes, inodes_total, inodes_used, inodes_free, inodes_avail))
    }

    // Environment variable methods
    fn get_current_process_env(&self) -> Result<Vec<(String, String)>> {
        let env_vars: Vec<(String, String)> = std::env::vars_os()
            .map(|(k, v)| {
                let key = k.to_string_lossy().into_owned();
                let value = v.to_string_lossy().into_owned();
                (key, value)
            })
            .collect();
        
        Ok(env_vars)
    }

    fn get_process_env(&self, pid: i64) -> Result<Vec<(String, String)>> {
        let environ_path = format!("/proc/{}/environ", pid);
        let environ_content = fs::read(&environ_path)
            .map_err(|e| SystemError::EnvListPidUnavailable(format!("pid={}: {}", pid, e)))?;
        
        let mut env_vars = Vec::new();
        let mut current_var = Vec::new();
        
        for &byte in &environ_content {
            if byte == 0 {
                if !current_var.is_empty() {
                    let var_string = String::from_utf8_lossy(&current_var);
                    if let Some(eq_pos) = var_string.find('=') {
                        let name = var_string[..eq_pos].to_string();
                        let value = var_string[eq_pos + 1..].to_string();
                        env_vars.push((name, value));
                    }
                    current_var.clear();
                }
            } else {
                current_var.push(byte);
            }
        }
        
        // Handle the last variable if the file doesn't end with null byte
        if !current_var.is_empty() {
            let var_string = String::from_utf8_lossy(&current_var);
            if let Some(eq_pos) = var_string.find('=') {
                let name = var_string[..eq_pos].to_string();
                let value = var_string[eq_pos + 1..].to_string();
                env_vars.push((name, value));
            }
        }
        
        Ok(env_vars)
    }

    fn get_current_process_id(&self) -> i64 {
        std::process::id() as i64
    }
}

// ===========================================================================
// SystemHandle Implementation
// ===========================================================================

#[derive(Debug)]
pub struct SystemHandle {
    alias: String,
}

impl SystemHandle {
    pub fn from_url(url: &Url) -> Result<Self> {
        let alias = url.host_str().unwrap_or("").to_string();
        Ok(SystemHandle { alias })
    }

    fn info_verb(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse options
        let opts = self.parse_options(args)?;

        // Validate options
        if let Err(e) = self.validate_options(&opts) {
            let error_json = e.to_json();
            writeln!(io.stdout, "{}", serde_json::to_string_pretty(&error_json)?)?;
            return Ok(Status::err(1, e.to_string()));
        }

        // Collect system information
        let provider = RealSystemProvider;
        let response = match self.collect_info(&opts, &provider) {
            Ok(resp) => resp,
            Err(e) => {
                let error_json = if let Some(sys_err) = e.downcast_ref::<SystemError>() {
                    sys_err.to_json()
                } else {
                    json!({
                        "ok": false,
                        "error": {
                            "code": "system.info_internal_error",
                            "message": e.to_string(),
                        }
                    })
                };
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&error_json)?)?;
                return Ok(Status::err(1, e.to_string()));
            }
        };

        // Format and output response
        match opts.format.as_str() {
            "json" => {
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&response)?)?;
            }
            "text" => {
                let text = self.format_text(&response, &opts)?;
                write!(io.stdout, "{}", text)?;
            }
            _ => {
                let err = SystemError::InvalidParameter(format!("invalid format: {}", opts.format));
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&err.to_json())?)?;
                return Ok(Status::err(1, err.to_string()));
            }
        }

        Ok(Status::ok())
    }

    fn uptime_verb(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse options
        let opts = self.parse_uptime_options(args)?;

        // Validate format
        if opts.format != "json" && opts.format != "text" {
            let err = SystemError::InvalidParameter(format!("format must be 'json' or 'text', got '{}'", opts.format));
            writeln!(io.stdout, "{}", serde_json::to_string_pretty(&err.to_json())?)?;
            return Ok(Status::err(1, err.to_string()));
        }

        // Collect uptime information
        let provider = RealSystemProvider;
        let response = self.collect_uptime(&opts, &provider);

        // Format and output response
        match opts.format.as_str() {
            "json" => {
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&response)?)?;
            }
            "text" => {
                let text = self.format_uptime_text(&response)?;
                write!(io.stdout, "{}", text)?;
            }
            _ => {
                // Already validated above, but for safety
                let err = SystemError::InvalidParameter(format!("invalid format: {}", opts.format));
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&err.to_json())?)?;
                return Ok(Status::err(1, err.to_string()));
            }
        }

        if response.ok {
            Ok(Status::ok())
        } else {
            Ok(Status::err(1, "uptime operation failed"))
        }
    }

    fn parse_uptime_options(&self, args: &Args) -> Result<SystemUptimeOptions> {
        if let Some(input) = args.get("input") {
            serde_json::from_str(input)
                .map_err(|e| SystemError::InvalidParameter(format!("invalid JSON: {}", e)).into())
        } else {
            Ok(SystemUptimeOptions::default())
        }
    }

    pub fn collect_uptime(
        &self,
        opts: &SystemUptimeOptions,
        provider: &dyn SystemProvider
    ) -> SystemUptimeResponse {
        let timestamp_unix_ms = provider.now_unix_ms();
        let mut warnings = Vec::new();

        // Try to read /proc/uptime
        let uptime_result = provider.read_proc_uptime();

        if let Err(e) = &uptime_result {
            // Cannot get uptime at all - return error response
            return SystemUptimeResponse {
                ok: false,
                timestamp_unix_ms,
                uptime_seconds: None,
                uptime_human: None,
                boot_time_unix: None,
                idle_seconds: None,
                idle_seconds_per_cpu: None,
                raw: None,
                paths: if opts.include_paths {
                    Some(json!({
                        "uptime": "/proc/uptime",
                        "btime": "/proc/stat"
                    }))
                } else {
                    None
                },
                error: Some(json!({
                    "code": "system.uptime_unavailable",
                    "message": format!("Unable to determine uptime: /proc/uptime not available ({})", e)
                })),
                warnings,
            };
        }

        let uptime_content = uptime_result.unwrap();
        let uptime_line = uptime_content.trim();
        let parts: Vec<&str> = uptime_line.split_whitespace().collect();

        // Parse uptime_seconds (required field)
        let uptime_seconds = if let Some(uptime_str) = parts.get(0) {
            match uptime_str.parse::<f64>() {
                Ok(val) => Some(val),
                Err(e) => {
                    // Parse error - return error response
                    return SystemUptimeResponse {
                        ok: false,
                        timestamp_unix_ms,
                        uptime_seconds: None,
                        uptime_human: None,
                        boot_time_unix: None,
                        idle_seconds: None,
                        idle_seconds_per_cpu: None,
                        raw: if opts.include_raw {
                            Some(json!({
                                "proc_uptime_line": uptime_line
                            }))
                        } else {
                            None
                        },
                        paths: if opts.include_paths {
                            Some(json!({
                                "uptime": "/proc/uptime",
                                "btime": "/proc/stat"
                            }))
                        } else {
                            None
                        },
                        error: Some(json!({
                            "code": "system.uptime_parse_error",
                            "message": format!("Failed to parse uptime value: {}", e)
                        })),
                        warnings,
                    };
                }
            }
        } else {
            // No uptime value found
            return SystemUptimeResponse {
                ok: false,
                timestamp_unix_ms,
                uptime_seconds: None,
                uptime_human: None,
                boot_time_unix: None,
                idle_seconds: None,
                idle_seconds_per_cpu: None,
                raw: if opts.include_raw {
                    Some(json!({
                        "proc_uptime_line": uptime_line
                    }))
                } else {
                    None
                },
                paths: if opts.include_paths {
                    Some(json!({
                        "uptime": "/proc/uptime",
                        "btime": "/proc/stat"
                    }))
                } else {
                    None
                },
                error: Some(json!({
                    "code": "system.uptime_parse_error",
                    "message": "No uptime value found in /proc/uptime"
                })),
                warnings,
            };
        };

        // Parse idle_seconds (optional field)
        let idle_seconds = if opts.include_idle {
            if let Some(idle_str) = parts.get(1) {
                match idle_str.parse::<f64>() {
                    Ok(val) => Some(val),
                    Err(_) => {
                        warnings.push("Idle time not available: could not parse idle field from /proc/uptime".to_string());
                        None
                    }
                }
            } else {
                warnings.push("Idle time not available: /proc/uptime did not contain idle field".to_string());
                None
            }
        } else {
            None
        };

        // Calculate idle_seconds_per_cpu
        let idle_seconds_per_cpu = if opts.include_idle && idle_seconds.is_some() {
            match provider.get_cpu_count() {
                Ok(cpu_count) if cpu_count > 0 => {
                    Some(idle_seconds.unwrap() / cpu_count as f64)
                }
                Ok(_) => {
                    warnings.push("CPU count is zero, cannot calculate idle_seconds_per_cpu".to_string());
                    None
                }
                Err(_) => {
                    warnings.push("Failed to get CPU count for idle_seconds_per_cpu calculation".to_string());
                    None
                }
            }
        } else {
            None
        };

        // Get boot_time_unix from /proc/stat
        let boot_time_unix = if opts.include_boot_time {
            match provider.read_proc_stat() {
                Ok(stat_content) => {
                    let mut btime = None;
                    for line in stat_content.lines() {
                        if line.starts_with("btime ") {
                            if let Some(btime_str) = line.split_whitespace().nth(1) {
                                if let Ok(val) = btime_str.parse::<i64>() {
                                    btime = Some(val);
                                    break;
                                }
                            }
                        }
                    }

                    if btime.is_none() {
                        // Fallback: calculate from current time - uptime
                        if let Some(uptime) = uptime_seconds {
                            let now_unix_secs = timestamp_unix_ms / 1000;
                            btime = Some(now_unix_secs - uptime as i64);
                            warnings.push("boot_time_unix calculated from fallback (now - uptime), btime not found in /proc/stat".to_string());
                        } else {
                            warnings.push("boot_time_unix not available: btime not found in /proc/stat and no fallback possible".to_string());
                        }
                    }

                    btime
                }
                Err(_) => {
                    // Fallback: calculate from current time - uptime
                    if let Some(uptime) = uptime_seconds {
                        let now_unix_secs = timestamp_unix_ms / 1000;
                        let btime = now_unix_secs - uptime as i64;
                        warnings.push("boot_time_unix calculated from fallback (now - uptime), /proc/stat not available".to_string());
                        Some(btime)
                    } else {
                        warnings.push("boot_time_unix not available: /proc/stat not readable and no fallback possible".to_string());
                        None
                    }
                }
            }
        } else {
            None
        };

        // Format human-readable uptime
        let uptime_human = if opts.include_human && uptime_seconds.is_some() {
            let total_seconds = uptime_seconds.unwrap() as u64;
            let days = total_seconds / 86400;
            let hours = (total_seconds % 86400) / 3600;
            let minutes = (total_seconds % 3600) / 60;
            let seconds = total_seconds % 60;

            let mut parts = Vec::new();
            if days > 0 {
                parts.push(format!("{}d", days));
            }
            if hours > 0 || days > 0 {
                parts.push(format!("{}h", hours));
            }
            if minutes > 0 || hours > 0 || days > 0 {
                parts.push(format!("{}m", minutes));
            }
            parts.push(format!("{:02}s", seconds));

            Some(parts.join(" "))
        } else {
            None
        };

        // Build raw data if requested
        let raw = if opts.include_raw {
            let mut raw_obj = json!({
                "proc_uptime_line": uptime_line
            });

            if opts.include_boot_time {
                if let Ok(stat_content) = provider.read_proc_stat() {
                    for line in stat_content.lines() {
                        if line.starts_with("btime ") {
                            raw_obj["proc_stat_btime_line"] = json!(line);
                            break;
                        }
                    }
                }
            }

            Some(raw_obj)
        } else {
            None
        };

        // Build paths if requested
        let paths = if opts.include_paths {
            Some(json!({
                "uptime": "/proc/uptime",
                "btime": "/proc/stat"
            }))
        } else {
            None
        };

        SystemUptimeResponse {
            ok: true,
            timestamp_unix_ms,
            uptime_seconds,
            uptime_human,
            boot_time_unix,
            idle_seconds,
            idle_seconds_per_cpu,
            raw,
            paths,
            error: None,
            warnings,
        }
    }

    pub fn format_uptime_text(&self, response: &SystemUptimeResponse) -> Result<String> {
        let mut output = String::new();

        output.push_str("System Uptime\n");
        output.push_str("=============\n\n");

        // Format timestamp
        let timestamp_secs = response.timestamp_unix_ms / 1000;
        let dt = chrono::DateTime::from_timestamp(timestamp_secs, 0)
            .unwrap_or_else(|| chrono::DateTime::UNIX_EPOCH);
        output.push_str(&format!("Timestamp : {}\n\n", dt.format("%Y-%m-%dT%H:%M:%SZ")));

        // Uptime
        if let Some(human) = &response.uptime_human {
            output.push_str(&format!("Uptime    : {}\n", human));
        } else {
            output.push_str("Uptime    : (unknown)\n");
        }

        if let Some(seconds) = response.uptime_seconds {
            output.push_str(&format!("Seconds   : {:.2}\n", seconds));
        } else {
            output.push_str("Seconds   : (unknown)\n");
        }

        // Boot time
        if let Some(boot_time) = response.boot_time_unix {
            let boot_dt = chrono::DateTime::from_timestamp(boot_time, 0)
                .unwrap_or_else(|| chrono::DateTime::UNIX_EPOCH);
            output.push_str(&format!("Boot Time : {}\n\n", boot_dt.format("%Y-%m-%dT%H:%M:%SZ")));
        } else {
            output.push_str("Boot Time : (unknown)\n\n");
        }

        // Idle
        if let Some(idle) = response.idle_seconds {
            if let Some(idle_per_cpu) = response.idle_seconds_per_cpu {
                output.push_str(&format!("Idle      : {:.2} s (per CPU: {:.2} s)\n\n", idle, idle_per_cpu));
            } else {
                output.push_str(&format!("Idle      : {:.2} s\n\n", idle));
            }
        } else {
            output.push_str("Idle      : (unknown)\n\n");
        }

        // Warnings
        output.push_str("Warnings:\n");
        if response.warnings.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for warning in &response.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        }

        Ok(output)
    }

    fn memory_verb(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse options
        let opts = self.parse_memory_options(args)?;

        // Validate format
        if opts.format != "json" && opts.format != "text" {
            let err = SystemError::InvalidParameter(format!("format must be 'json' or 'text', got '{}'", opts.format));
            writeln!(io.stdout, "{}", serde_json::to_string_pretty(&err.to_json())?)?;
            return Ok(Status::err(1, err.to_string()));
        }

        // Collect memory information
        let provider = RealSystemProvider;
        let response = self.collect_memory(&opts, &provider);

        // Format and output response
        match opts.format.as_str() {
            "json" => {
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&response)?)?;
            }
            "text" => {
                let text = self.format_memory_text(&response)?;
                write!(io.stdout, "{}", text)?;
            }
            _ => {
                // Already validated above, but for safety
                let err = SystemError::InvalidParameter(format!("invalid format: {}", opts.format));
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&err.to_json())?)?;
                return Ok(Status::err(1, err.to_string()));
            }
        }

        if response.ok {
            Ok(Status::ok())
        } else {
            Ok(Status::err(1, "memory operation failed"))
        }
    }

    fn parse_memory_options(&self, args: &Args) -> Result<SystemMemoryOptions> {
        if let Some(input) = args.get("input") {
            serde_json::from_str(input)
                .map_err(|e| SystemError::InvalidParameter(format!("invalid JSON: {}", e)).into())
        } else {
            Ok(SystemMemoryOptions::default())
        }
    }

    fn load_verb(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse options
        let opts = self.parse_load_options(args)?;

        // Collect load information
        let provider = RealSystemProvider;
        let response = self.collect_load(&opts, &provider);

        // Format and output response
        match opts.format {
            OutputFormat::Json => {
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&response)?)?;
            }
            OutputFormat::Text => {
                let text = self.format_load_text(&response)?;
                write!(io.stdout, "{}", text)?;
            }
        }

        if response.ok {
            Ok(Status::ok())
        } else {
            Ok(Status::err(1, "load operation failed"))
        }
    }

    fn parse_load_options(&self, args: &Args) -> Result<SystemLoadOptions> {
        if let Some(input) = args.get("input") {
            serde_json::from_str(input)
                .map_err(|e| SystemError::InvalidParameter(format!("invalid JSON: {}", e)).into())
        } else {
            Ok(SystemLoadOptions::default())
        }
    }

    fn cpu_verb(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse options
        let opts = self.parse_cpu_options(args)?;

        // Collect CPU information
        let provider = RealSystemProvider;
        let response = self.collect_cpu(&opts, &provider);

        // Format and output response
        match opts.format {
            OutputFormat::Json => {
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&response)?)?;
            }
            OutputFormat::Text => {
                let text = self.format_cpu_text(&response)?;
                write!(io.stdout, "{}", text)?;
            }
        }

        if response.ok {
            Ok(Status::ok())
        } else {
            Ok(Status::err(1, "cpu operation failed"))
        }
    }

    fn parse_cpu_options(&self, args: &Args) -> Result<SystemCpuOptions> {
        if let Some(input) = args.get("input") {
            serde_json::from_str(input)
                .map_err(|e| SystemError::InvalidParameter(format!("invalid JSON: {}", e)).into())
        } else {
            Ok(SystemCpuOptions::default())
        }
    }

    fn disk_verb(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse options
        let opts = self.parse_disk_options(args)?;

        // Collect disk information
        let provider = RealSystemProvider;
        let response = self.collect_disk(&opts, &provider);

        // Format and output response
        match opts.format {
            OutputFormat::Json => {
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&response)?)?;
            }
            OutputFormat::Text => {
                let text = self.format_disk_text(&response)?;
                write!(io.stdout, "{}", text)?;
            }
        }

        if response.ok {
            Ok(Status::ok())
        } else {
            Ok(Status::err(1, "disk operation failed"))
        }
    }

    fn parse_disk_options(&self, args: &Args) -> Result<SystemDiskOptions> {
        if let Some(input) = args.get("input") {
            serde_json::from_str(input)
                .map_err(|e| SystemError::InvalidParameter(format!("invalid JSON: {}", e)).into())
        } else {
            Ok(SystemDiskOptions::default())
        }
    }

    pub fn collect_disk(
        &self,
        opts: &SystemDiskOptions,
        provider: &dyn SystemProvider
    ) -> SystemDiskResponse {
        let timestamp_unix_ms = provider.now_unix_ms();
        let mut warnings = Vec::new();

        // Try to read mount information
        let mount_content = self.read_mounts_content(provider, &mut warnings);
        if mount_content.is_none() {
            return SystemDiskResponse {
                ok: false,
                timestamp_unix_ms,
                mounts_truncated: false,
                mounts: None,
                io: None,
                human: None,
                raw: None,
                paths: if opts.include_paths {
                    Some(json!({
                        "mounts": "/proc/self/mounts"
                    }))
                } else {
                    None
                },
                error: Some(json!({
                    "code": "system.disk_mounts_unavailable",
                    "message": "Unable to read /proc/self/mounts or /proc/mounts."
                })),
                warnings,
            };
        }

        let mount_content = mount_content.unwrap();
        
        // Parse mounts
        let parsed_mounts = self.parse_mounts(&mount_content, &mut warnings);
        
        // Apply filters
        let filtered_mounts = self.filter_mounts(parsed_mounts, opts, &mut warnings);
        
        // Apply limits and get final mount list
        let (final_mounts, mounts_truncated) = self.limit_mounts(filtered_mounts, opts.max_mounts, &mut warnings);
        
        // Get filesystem stats for each mount
        let mut mount_entries = Vec::new();
        for (device, mount_point, fs_type) in final_mounts {
            let mut entry = SystemDiskMountEntry {
                mount_point: mount_point.clone(),
                device: device.clone(),
                fs_type: if opts.include_fs_types { Some(fs_type.clone()) } else { None },
                virtual_fs: self.is_virtual_filesystem(&fs_type),
                total_bytes: None,
                used_bytes: None,
                free_bytes: None,
                avail_bytes: None,
                used_pct: None,
                free_pct: None,
                inodes_total: None,
                inodes_used: None,
                inodes_free: None,
                inodes_used_pct: None,
                io_device: None,
                tags: self.generate_mount_tags(&mount_point),
                human_summary: None,
            };

            // Get filesystem statistics
            if let Ok((total, used, free, avail, inodes_total, inodes_used, inodes_free, _inodes_avail)) = 
                provider.statvfs_mount(&mount_point) {
                
                entry.total_bytes = Some(total);
                entry.used_bytes = Some(used);
                entry.free_bytes = Some(free);
                entry.avail_bytes = Some(avail);
                
                if total > 0 {
                    entry.used_pct = Some(100.0 * used as f64 / total as f64);
                    entry.free_pct = Some(100.0 * free as f64 / total as f64);
                }
                
                entry.inodes_total = Some(inodes_total);
                entry.inodes_used = Some(inodes_used);
                entry.inodes_free = Some(inodes_free);
                
                if inodes_total > 0 {
                    entry.inodes_used_pct = Some(100.0 * inodes_used as f64 / inodes_total as f64);
                }

                // Generate human summary if requested
                if opts.include_human {
                    entry.human_summary = Some(self.generate_mount_human_summary(&entry));
                }
            } else {
                warnings.push(format!("Failed to get filesystem stats for {}", mount_point));
            }

            // Map device to I/O device name if needed
            if opts.include_io {
                entry.io_device = self.map_device_to_io_device(&device);
            }

            mount_entries.push(entry);
        }

        // Get I/O statistics if requested
        let io_metrics = if opts.include_io {
            self.collect_io_metrics(provider, &mount_entries, &mut warnings)
        } else {
            None
        };

        // Generate human summaries
        let human = if opts.include_human {
            Some(SystemDiskHumanSummary {
                summaries: mount_entries.iter()
                    .filter_map(|e| e.human_summary.clone())
                    .collect(),
            })
        } else {
            None
        };

        // Generate raw data if requested
        let raw = if opts.include_raw {
            let mut raw_data = json!({});
            raw_data["mounts"] = json!(mount_content);
            if let Ok(diskstats_content) = provider.read_proc_diskstats() {
                raw_data["diskstats"] = json!(diskstats_content);
            }
            if !raw_data.as_object().unwrap().is_empty() {
                Some(raw_data)
            } else {
                None
            }
        } else {
            None
        };

        // Generate paths if requested
        let paths = if opts.include_paths {
            Some(json!({
                "mounts": "/proc/self/mounts",
                "diskstats": "/proc/diskstats"
            }))
        } else {
            None
        };

        SystemDiskResponse {
            ok: true,
            timestamp_unix_ms,
            mounts_truncated,
            mounts: Some(mount_entries),
            io: io_metrics,
            human,
            raw,
            paths,
            error: None,
            warnings,
        }
    }

    fn read_mounts_content(&self, provider: &dyn SystemProvider, warnings: &mut Vec<String>) -> Option<String> {
        // Try /proc/self/mounts first, then /proc/mounts
        if let Ok(content) = provider.read_proc_self_mounts() {
            Some(content)
        } else if let Ok(content) = provider.read_proc_mounts() {
            warnings.push("Using /proc/mounts instead of /proc/self/mounts".to_string());
            Some(content)
        } else {
            None
        }
    }

    fn parse_mounts(&self, content: &str, warnings: &mut Vec<String>) -> Vec<(String, String, String)> {
        let mut mounts = Vec::new();
        
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let device = self.unescape_mount_field(parts[0]);
                let mount_point = self.unescape_mount_field(parts[1]);
                let fs_type = parts[2].to_string();
                mounts.push((device, mount_point, fs_type));
            } else {
                warnings.push(format!("Skipping malformed mount line: {}", line));
            }
        }
        
        mounts
    }

    pub fn unescape_mount_field(&self, field: &str) -> String {
        // Handle octal escape sequences like \040 for space
        let mut result = String::new();
        let mut chars = field.chars().peekable();
        
        while let Some(c) = chars.next() {
            if c == '\\' && chars.peek() == Some(&'0') {
                // Try to parse octal escape sequence
                chars.next(); // consume '0'
                if let (Some(d1), Some(d2)) = (chars.next(), chars.next()) {
                    if d1.is_ascii_digit() && d2.is_ascii_digit() {
                        if let Ok(octal_val) = u8::from_str_radix(&format!("0{}{}", d1, d2), 8) {
                            result.push(octal_val as char);
                            continue;
                        }
                    }
                }
                // Failed to parse, add literally
                result.push('\\');
                result.push('0');
                if let Some(d1) = chars.peek() {
                    result.push(*d1);
                    chars.next();
                }
                if let Some(d2) = chars.peek() {
                    result.push(*d2);
                    chars.next();
                }
            } else {
                result.push(c);
            }
        }
        
        result
    }

    fn filter_mounts(
        &self, 
        mounts: Vec<(String, String, String)>, 
        opts: &SystemDiskOptions,
        warnings: &mut Vec<String>
    ) -> Vec<(String, String, String)> {
        let mut filtered = Vec::new();
        
        for (device, mount_point, fs_type) in mounts {
            // Apply filters
            let mut include = true;
            
            // Filter by mount points
            if !opts.mount_points.is_empty() {
                include = include && opts.mount_points.contains(&mount_point);
            }
            
            // Filter by devices
            if !opts.devices.is_empty() {
                include = include && opts.devices.contains(&device);
            }
            
            // Filter by filesystem types
            if !opts.fs_types.is_empty() {
                include = include && opts.fs_types.contains(&fs_type);
            }
            
            // Filter virtual filesystems
            if !opts.include_virtual && self.is_virtual_filesystem(&fs_type) {
                include = false;
            }
            
            if include {
                filtered.push((device, mount_point, fs_type));
            }
        }
        
        filtered
    }

    fn is_virtual_filesystem(&self, fs_type: &str) -> bool {
        matches!(fs_type,
            "proc" | "sysfs" | "debugfs" | "devpts" | "devtmpfs" |
            "tmpfs" | "securityfs" | "cgroup" | "cgroup2" | "cgroupfs" |
            "binfmt_misc" | "configfs" | "fusectl" | "mqueue" |
            "hugetlbfs" | "autofs" | "pstore" | "efivarfs" |
            "overlay" | "squashfs" | "iso9660" | "udf"
        )
    }

    fn limit_mounts(
        &self,
        mounts: Vec<(String, String, String)>,
        max_mounts: u32,
        warnings: &mut Vec<String>
    ) -> (Vec<(String, String, String)>, bool) {
        let max_mounts = max_mounts as usize;
        
        if mounts.len() > max_mounts {
            warnings.push(format!("Mount list truncated at max_mounts={}", max_mounts));
            (mounts.into_iter().take(max_mounts).collect(), true)
        } else {
            (mounts, false)
        }
    }

    fn generate_mount_tags(&self, mount_point: &str) -> Vec<String> {
        let mut tags = Vec::new();
        
        match mount_point {
            "/" => tags.push("rootfs".to_string()),
            "/home" => tags.push("home".to_string()),
            "/tmp" => tags.push("tmp".to_string()),
            "/var" => tags.push("var".to_string()),
            "/usr" => tags.push("usr".to_string()),
            "/boot" => tags.push("boot".to_string()),
            path if path.starts_with("/home/") => tags.push("home".to_string()),
            path if path.starts_with("/var/") => tags.push("var".to_string()),
            path if path.starts_with("/mnt/") => tags.push("data".to_string()),
            path if path.starts_with("/media/") => tags.push("media".to_string()),
            _ => {}
        }
        
        tags
    }

    fn generate_mount_human_summary(&self, entry: &SystemDiskMountEntry) -> String {
        let mount_point = &entry.mount_point;
        
        if let (Some(total), Some(used), Some(used_pct)) = (entry.total_bytes, entry.used_bytes, entry.used_pct) {
            let total_str = self.format_bytes_human(total);
            let used_str = self.format_bytes_human(used);
            format!("{}: {} total, {} used ({:.1}%)", mount_point, total_str, used_str, used_pct)
        } else {
            format!("{}: stats unavailable", mount_point)
        }
    }

    fn format_bytes_human(&self, bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
        const DIVISOR: f64 = 1024.0;
        
        if bytes == 0 {
            return "0 B".to_string();
        }
        
        let bytes_f = bytes as f64;
        let mut unit_index = 0;
        let mut value = bytes_f;
        
        while value >= DIVISOR && unit_index < UNITS.len() - 1 {
            value /= DIVISOR;
            unit_index += 1;
        }
        
        if unit_index == 0 {
            format!("{} {}", bytes, UNITS[unit_index])
        } else {
            format!("{:.1} {}", value, UNITS[unit_index])
        }
    }

    pub fn map_device_to_io_device(&self, device: &str) -> Option<String> {
        // Extract base device name from paths like /dev/sda1 -> sda
        if let Some(dev_name) = device.strip_prefix("/dev/") {
            // Handle partition numbers: sda1 -> sda, nvme0n1p1 -> nvme0n1
            if let Some(base) = self.extract_base_device_name(dev_name) {
                Some(base)
            } else {
                Some(dev_name.to_string())
            }
        } else {
            None
        }
    }

    fn extract_base_device_name(&self, dev_name: &str) -> Option<String> {
        // Handle common device naming patterns
        if dev_name.starts_with("nvme") {
            // nvme0n1p1 -> nvme0n1
            if let Some(pos) = dev_name.rfind('p') {
                if dev_name[pos+1..].chars().all(|c| c.is_ascii_digit()) {
                    return Some(dev_name[..pos].to_string());
                }
            }
        } else if dev_name.starts_with("sd") || dev_name.starts_with("hd") || dev_name.starts_with("vd") {
            // sda1 -> sda, hda1 -> hda, vda1 -> vda
            if dev_name.len() > 3 && dev_name[3..].chars().all(|c| c.is_ascii_digit()) {
                return Some(dev_name[..3].to_string());
            }
        } else if dev_name.starts_with("mmcblk") {
            // mmcblk0p1 -> mmcblk0
            if let Some(pos) = dev_name.rfind('p') {
                if dev_name[pos+1..].chars().all(|c| c.is_ascii_digit()) {
                    return Some(dev_name[..pos].to_string());
                }
            }
        }
        
        None
    }

    fn collect_io_metrics(
        &self,
        provider: &dyn SystemProvider,
        mount_entries: &[SystemDiskMountEntry],
        warnings: &mut Vec<String>
    ) -> Option<SystemDiskIoMetrics> {
        // Try to read /proc/diskstats
        let diskstats_content = match provider.read_proc_diskstats() {
            Ok(content) => content,
            Err(_) => {
                warnings.push("Failed to read /proc/diskstats".to_string());
                return Some(SystemDiskIoMetrics {
                    available: false,
                    devices: Vec::new(),
                });
            }
        };

        let mut devices = Vec::new();
        let device_names: std::collections::HashSet<String> = mount_entries
            .iter()
            .filter_map(|entry| entry.io_device.clone())
            .collect();

        for line in diskstats_content.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 14 {
                let major: u32 = parts[0].parse().unwrap_or(0);
                let minor: u32 = parts[1].parse().unwrap_or(0);
                let name = parts[2].to_string();

                // Only include devices that back our mounts
                if device_names.contains(&name) {
                    let device = SystemDiskIoDeviceEntry {
                        name: name.clone(),
                        maj_min: format!("{}:{}", major, minor),
                        reads_completed: parts[3].parse().ok(),
                        writes_completed: parts[7].parse().ok(),
                        sectors_read: parts[5].parse().ok(),
                        sectors_written: parts[9].parse().ok(),
                        read_bytes: parts[5].parse::<u64>().ok().map(|s| s * 512),
                        write_bytes: parts[9].parse::<u64>().ok().map(|s| s * 512),
                        time_reading_ms: parts[6].parse().ok(),
                        time_writing_ms: parts[10].parse().ok(),
                        ios_in_progress: parts[11].parse().ok(),
                        time_in_io_ms: parts[12].parse().ok(),
                        weighted_time_in_io_ms: parts[13].parse().ok(),
                    };
                    devices.push(device);
                }
            }
        }

        Some(SystemDiskIoMetrics {
            available: true,
            devices,
        })
    }

    pub fn format_disk_text(&self, response: &SystemDiskResponse) -> Result<String> {
        let mut output = String::new();
        
        output.push_str("Disk Usage\n");
        output.push_str("==========\n\n");
        
        if let Some(timestamp) = chrono::DateTime::from_timestamp_millis(response.timestamp_unix_ms) {
            output.push_str(&format!("Timestamp : {}\n\n", timestamp.format("%Y-%m-%dT%H:%M:%SZ")));
        }
        
        if let Some(mounts) = &response.mounts {
            output.push_str("Mounts:\n");
            for mount in mounts {
                output.push_str(&format!("  {}         ", mount.mount_point));
                if let Some(fs_type) = &mount.fs_type {
                    output.push_str(&format!("({} on {})\n", fs_type, mount.device));
                } else {
                    output.push_str(&format!("({})\n", mount.device));
                }
                
                if let (Some(total), Some(used), Some(free), Some(avail), Some(used_pct)) = 
                    (mount.total_bytes, mount.used_bytes, mount.free_bytes, mount.avail_bytes, mount.used_pct) {
                    output.push_str(&format!("    Total   : {}\n", self.format_bytes_human(total)));
                    output.push_str(&format!("    Used    : {} ({:.1}%)\n", self.format_bytes_human(used), used_pct));
                    output.push_str(&format!("    Free    : {}\n", self.format_bytes_human(free)));
                    output.push_str(&format!("    Avail   : {}\n", self.format_bytes_human(avail)));
                } else {
                    output.push_str("    Stats   : unavailable\n");
                }
                
                output.push('\n');
            }
            
            if response.mounts_truncated {
                output.push_str(&format!("  ... (first {} entries shown)\n", mounts.len()));
                output.push_str(&format!("  NOTE: mount list truncated at max_mounts={}.\n\n", mounts.len()));
            }
        }
        
        if let Some(io) = &response.io {
            output.push_str("I/O:\n");
            if io.available {
                for device in &io.devices {
                    output.push_str(&format!("  {} ({})\n", device.name, device.maj_min));
                    if let (Some(reads), Some(writes)) = (device.reads_completed, device.writes_completed) {
                        output.push_str(&format!("    Reads   : {}\n", reads));
                        output.push_str(&format!("    Writes  : {}\n", writes));
                    }
                    if let (Some(read_bytes), Some(write_bytes)) = (device.read_bytes, device.write_bytes) {
                        output.push_str(&format!("    RBytes  : {}\n", self.format_bytes_human(read_bytes)));
                        output.push_str(&format!("    WBytes  : {}\n", self.format_bytes_human(write_bytes)));
                    }
                    output.push('\n');
                }
            } else {
                output.push_str("  I/O stats unavailable\n\n");
            }
        }
        
        if !response.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &response.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        } else {
            output.push_str("Warnings:\n  (none)\n");
        }
        
        Ok(output)
    }

    // Environment listing verb implementation
    fn env_list_verb(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse options
        let opts = self.parse_env_list_options(args)?;

        // Validate format
        if opts.format != "json" && opts.format != "text" {
            let err = SystemError::InvalidParameter(format!("format must be 'json' or 'text', got '{}'", opts.format));
            writeln!(io.stdout, "{}", serde_json::to_string_pretty(&err.to_json())?)?;
            return Ok(Status::err(1, err.to_string()));
        }

        // Collect environment information
        let provider = RealSystemProvider;
        let response = self.collect_env_list(&opts, &provider);

        // Format and output response
        match opts.format.as_str() {
            "json" => {
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&response)?)?;
            }
            "text" => {
                let text = self.format_env_list_text(&response)?;
                write!(io.stdout, "{}", text)?;
            }
            _ => {
                // Already validated above, but for safety
                let err = SystemError::InvalidParameter(format!("invalid format: {}", opts.format));
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&err.to_json())?)?;
                return Ok(Status::err(1, err.to_string()));
            }
        }

        if response.ok {
            Ok(Status::ok())
        } else {
            Ok(Status::err(1, "env list operation failed"))
        }
    }

    fn parse_env_list_options(&self, args: &Args) -> Result<SystemEnvListOptions> {
        if let Some(input) = args.get("input") {
            serde_json::from_str(input)
                .map_err(|e| SystemError::InvalidParameter(format!("invalid JSON: {}", e)).into())
        } else {
            Ok(SystemEnvListOptions::default())
        }
    }

    pub fn collect_env_list(
        &self,
        opts: &SystemEnvListOptions,
        provider: &dyn SystemProvider
    ) -> SystemEnvListResponse {
        let timestamp_unix_ms = provider.now_unix_ms();
        let mut warnings = Vec::new();

        // Determine target PID and source
        let (target_pid, source_kind) = match opts.pid {
            Some(pid) => (Some(pid), EnvSourceKind::Proc),
            None => (Some(provider.get_current_process_id()), EnvSourceKind::Process),
        };

        // Get environment variables
        let env_vars_result = match source_kind {
            EnvSourceKind::Process => provider.get_current_process_env(),
            EnvSourceKind::Proc => {
                match target_pid {
                    Some(pid) => provider.get_process_env(pid),
                    None => provider.get_current_process_env(),
                }
            }
        };

        let env_vars = match env_vars_result {
            Ok(vars) => vars,
            Err(e) => {
                let error_value = json!({
                    "code": "system.env_list_unavailable",
                    "message": e.to_string()
                });
                return SystemEnvListResponse {
                    ok: false,
                    timestamp_unix_ms,
                    pid: target_pid,
                    source: Some(self.format_source_kind(&source_kind)),
                    env_count_total: None,
                    env_count_returned: 0,
                    env_count_masked: 0,
                    env_count_truncated: 0,
                    truncated_vars: false,
                    variables: Vec::new(),
                    raw: None,
                    paths: None,
                    human: None,
                    error: Some(error_value),
                    warnings,
                };
            }
        };

        let env_count_total = env_vars.len() as u32;

        // Compile regex filters
        let regex_filters = self.compile_regex_filters(&opts.regex_filters, &mut warnings);
        if regex_filters.is_none() {
            let error_value = json!({
                "code": "system.env_list_invalid_regex",
                "message": "One or more regex filters are invalid"
            });
            return SystemEnvListResponse {
                ok: false,
                timestamp_unix_ms,
                pid: target_pid,
                source: Some(self.format_source_kind(&source_kind)),
                env_count_total: Some(env_count_total),
                env_count_returned: 0,
                env_count_masked: 0,
                env_count_truncated: 0,
                truncated_vars: false,
                variables: Vec::new(),
                raw: None,
                paths: None,
                human: None,
                error: Some(error_value),
                warnings,
            };
        }
        let regex_filters = regex_filters.unwrap();

        // Filter environment variables
        let mut filtered_vars = Vec::new();
        for (name, value) in env_vars {
            if self.should_include_env_var(&name, opts, &regex_filters) {
                filtered_vars.push((name, value));
            }
        }

        // Apply sorting
        self.sort_env_vars(&mut filtered_vars, opts);

        // Apply max_vars limit and truncation tracking
        let mut truncated_vars = false;
        if filtered_vars.len() > opts.max_vars as usize {
            filtered_vars.truncate(opts.max_vars as usize);
            truncated_vars = true;
            warnings.push(format!("Variable list truncated to {} items (was {})", opts.max_vars, env_count_total));
        }

        // Process each variable (masking, truncation, etc.)
        let mut env_count_masked = 0;
        let mut env_count_truncated = 0;
        let mut processed_vars = Vec::new();

        for (name, value) in filtered_vars {
            let should_mask = !opts.include_sensitive && self.is_sensitive_env_var(&name);
            let source_str = self.format_source_kind(&source_kind);
            
            let (final_value, masked, truncated, value_length) = if opts.include_values {
                let (processed_value, was_truncated) = if should_mask {
                    env_count_masked += 1;
                    ("***MASKED***".to_string(), false) // masked values are not truncated
                } else {
                    self.truncate_value(&value, opts.truncate_length)
                };
                
                if was_truncated {
                    env_count_truncated += 1;
                }

                (Some(processed_value), should_mask, was_truncated, Some(value.len()))
            } else {
                // include_values=false
                (None, should_mask, false, Some(value.len()))
            };

            processed_vars.push(SystemEnvVarEntry {
                name,
                value: final_value,
                masked,
                truncated,
                value_length,
                source: source_str,
            });
        }

        let env_count_returned = processed_vars.len() as u32;

        // Build optional sections
        let raw = if opts.include_raw {
            Some(self.build_raw_env_data(&source_kind, target_pid, provider))
        } else {
            None
        };

        let paths = if opts.include_paths {
            Some(self.build_paths_env_data(&source_kind, target_pid))
        } else {
            None
        };

        let human = Some(SystemEnvListHumanSummary {
            summary: format!(
                "{} of {} environment variables listed ({} masked, {} truncated){}",
                env_count_returned,
                env_count_total,
                env_count_masked,
                env_count_truncated,
                if truncated_vars { " [list truncated]" } else { "" }
            ),
        });

        SystemEnvListResponse {
            ok: true,
            timestamp_unix_ms,
            pid: target_pid,
            source: Some(self.format_source_kind(&source_kind)),
            env_count_total: Some(env_count_total),
            env_count_returned,
            env_count_masked,
            env_count_truncated,
            truncated_vars,
            variables: processed_vars,
            raw,
            paths,
            human,
            error: None,
            warnings,
        }
    }

    fn compile_regex_filters(&self, patterns: &[String], warnings: &mut Vec<String>) -> Option<Vec<Regex>> {
        let mut compiled_filters = Vec::new();
        
        for pattern in patterns {
            match Regex::new(pattern) {
                Ok(regex) => compiled_filters.push(regex),
                Err(e) => {
                    warnings.push(format!("Invalid regex '{}': {}", pattern, e));
                    return None; // Any invalid regex fails the entire operation
                }
            }
        }
        
        Some(compiled_filters)
    }

    fn should_include_env_var(&self, name: &str, opts: &SystemEnvListOptions, regex_filters: &[Regex]) -> bool {
        // If names filter is specified, must match exactly
        if !opts.names.is_empty() && !opts.names.contains(&name.to_string()) {
            return false;
        }

        // If prefix filters specified, must match at least one
        if !opts.prefix_filters.is_empty() {
            let matches_prefix = opts.prefix_filters.iter().any(|prefix| name.starts_with(prefix));
            if !matches_prefix {
                return false;
            }
        }

        // If regex filters specified, must match at least one
        if !regex_filters.is_empty() {
            let matches_regex = regex_filters.iter().any(|regex| regex.is_match(name));
            if !matches_regex {
                return false;
            }
        }

        true
    }

    fn sort_env_vars(&self, vars: &mut Vec<(String, String)>, opts: &SystemEnvListOptions) {
        match opts.sort_by.as_str() {
            "name" => {
                match opts.sort_order.as_str() {
                    "desc" => vars.sort_by(|a, b| b.0.cmp(&a.0)),
                    _ => vars.sort_by(|a, b| a.0.cmp(&b.0)),
                }
            }
            "length" => {
                match opts.sort_order.as_str() {
                    "desc" => vars.sort_by(|a, b| b.1.len().cmp(&a.1.len())),
                    _ => vars.sort_by(|a, b| a.1.len().cmp(&b.1.len())),
                }
            }
            _ => {
                // "none" or anything else - preserve natural order
            }
        }
    }

    fn is_sensitive_env_var(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        
        name_lower.contains("password") ||
        name_lower.contains("passwd") ||
        name_lower.contains("secret") ||
        name_lower.contains("token") ||
        name_lower.contains("api_key") ||
        name_lower.contains("access_key") ||
        name_lower.contains("private_key") ||
        name_lower.contains("client_secret") ||
        (name_lower.contains("auth") && name_lower.contains("key"))
    }

    fn truncate_value(&self, value: &str, max_length: u32) -> (String, bool) {
        if max_length == 0 || value.len() <= max_length as usize {
            (value.to_string(), false)
        } else {
            let truncated = value.chars().take(max_length as usize).collect::<String>();
            (truncated, true)
        }
    }

    fn format_source_kind(&self, kind: &EnvSourceKind) -> String {
        match kind {
            EnvSourceKind::Process => "process".to_string(),
            EnvSourceKind::Proc => "proc".to_string(),
        }
    }

    fn build_raw_env_data(&self, source_kind: &EnvSourceKind, target_pid: Option<i64>, provider: &dyn SystemProvider) -> Value {
        let env_vars = match source_kind {
            EnvSourceKind::Process => provider.get_current_process_env().unwrap_or_default(),
            EnvSourceKind::Proc => {
                match target_pid {
                    Some(pid) => provider.get_process_env(pid).unwrap_or_default(),
                    None => provider.get_current_process_env().unwrap_or_default(),
                }
            }
        };

        let environ_strings: Vec<String> = env_vars.into_iter()
            .map(|(name, value)| format!("{}={}", name, value))
            .collect();

        json!({
            "environ": environ_strings
        })
    }

    fn build_paths_env_data(&self, source_kind: &EnvSourceKind, target_pid: Option<i64>) -> Value {
        match source_kind {
            EnvSourceKind::Process => {
                json!({
                    "environ": "/proc/self/environ"
                })
            }
            EnvSourceKind::Proc => {
                match target_pid {
                    Some(pid) => {
                        json!({
                            "environ": format!("/proc/{}/environ", pid)
                        })
                    }
                    None => {
                        json!({
                            "environ": "/proc/self/environ"
                        })
                    }
                }
            }
        }
    }

    pub fn format_env_list_text(&self, response: &SystemEnvListResponse) -> Result<String> {
        let mut output = String::new();
        
        output.push_str("Environment Variables\n");
        output.push_str("=====================\n\n");

        // Basic info
        if let Some(pid) = response.pid {
            output.push_str(&format!("PID       : {}\n", pid));
        }
        if let Some(source) = &response.source {
            output.push_str(&format!("Source    : {}\n", source));
        }
        
        let total_text = if let Some(total) = response.env_count_total {
            total.to_string()
        } else {
            "unknown".to_string()
        };
        
        output.push_str(&format!(
            "Returned  : {} of {} ({} masked, {} truncated)\n\n",
            response.env_count_returned,
            total_text,
            response.env_count_masked,
            response.env_count_truncated
        ));

        if response.variables.is_empty() {
            output.push_str("No environment variables match the criteria.\n");
        } else {
            // Check if we should show values
            let show_values = response.variables.iter().any(|var| var.value.is_some());
            
            if show_values {
                for var in &response.variables {
                    if let Some(value) = &var.value {
                        output.push_str(&format!("{:20} = {}\n", var.name, value));
                    } else {
                        output.push_str(&format!("{:20} = <hidden>\n", var.name));
                    }
                }
            } else {
                output.push_str("Names only:\n");
                for var in &response.variables {
                    output.push_str(&format!("  {}\n", var.name));
                }
            }
        }

        output.push('\n');

        if response.truncated_vars {
            output.push_str(&format!("Note: List truncated to max_vars={}.\n", response.variables.len()));
        }

        if !response.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &response.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        } else {
            output.push_str("Warnings:\n  (none)\n");
        }

        Ok(output)
    }

    pub fn collect_load(
        &self,
        opts: &SystemLoadOptions,
        provider: &dyn SystemProvider
    ) -> SystemLoadResponse {
        let timestamp_unix_ms = provider.now_unix_ms();
        let mut warnings = Vec::new();

        // Try to read /proc/loadavg
        let loadavg_result = provider.read_proc_loadavg();

        if let Err(e) = &loadavg_result {
            // Cannot get load at all - return error response
            return SystemLoadResponse {
                ok: false,
                timestamp_unix_ms,
                load_1m: None,
                load_5m: None,
                load_15m: None,
                load_1m_per_cpu: None,
                load_5m_per_cpu: None,
                load_15m_per_cpu: None,
                cpu_count_logical: None,
                runnable_processes: None,
                total_processes: None,
                human: None,
                raw: None,
                paths: if opts.include_paths {
                    Some(json!({
                        "load": "/proc/loadavg"
                    }))
                } else {
                    None
                },
                error: Some(json!({
                    "code": "system.load_unavailable",
                    "message": format!("Unable to read /proc/loadavg and no fallback load source configured: {}", e)
                })),
                warnings,
            };
        }

        let loadavg_content = loadavg_result.unwrap();
        let loadavg_line = loadavg_content.trim();
        let parts: Vec<&str> = loadavg_line.split_whitespace().collect();

        // Parse load averages
        let load_1m = parts.get(0).and_then(|s| s.parse::<f64>().ok());
        let load_5m = parts.get(1).and_then(|s| s.parse::<f64>().ok());
        let load_15m = parts.get(2).and_then(|s| s.parse::<f64>().ok());

        // Check if we have at least the basic load metrics
        if load_1m.is_none() && load_5m.is_none() && load_15m.is_none() {
            return SystemLoadResponse {
                ok: false,
                timestamp_unix_ms,
                load_1m: None,
                load_5m: None,
                load_15m: None,
                load_1m_per_cpu: None,
                load_5m_per_cpu: None,
                load_15m_per_cpu: None,
                cpu_count_logical: None,
                runnable_processes: None,
                total_processes: None,
                human: None,
                raw: if opts.include_raw {
                    Some(json!({
                        "proc_loadavg_line": loadavg_line
                    }))
                } else {
                    None
                },
                paths: if opts.include_paths {
                    Some(json!({
                        "load": "/proc/loadavg"
                    }))
                } else {
                    None
                },
                error: Some(json!({
                    "code": "system.load_parse_error",
                    "message": "Failed to parse load averages from /proc/loadavg"
                })),
                warnings,
            };
        }

        // Parse queue information if requested
        let (runnable_processes, total_processes) = if opts.include_queue {
            if let Some(queue_part) = parts.get(3) {
                if let Some((runnable_str, total_str)) = queue_part.split_once('/') {
                    let runnable = runnable_str.parse::<u32>().ok();
                    let total = total_str.parse::<u32>().ok();
                    if runnable.is_none() || total.is_none() {
                        warnings.push("Queue info not available: could not parse runnable/total processes from /proc/loadavg".to_string());
                    }
                    (runnable, total)
                } else {
                    warnings.push("Queue info not available: malformed queue field in /proc/loadavg".to_string());
                    (None, None)
                }
            } else {
                warnings.push("Queue info not available: /proc/loadavg did not contain queue field".to_string());
                (None, None)
            }
        } else {
            (None, None)
        };

        // Get CPU count for normalization
        let cpu_count_logical = if opts.normalize_per_cpu {
            match provider.get_cpu_count() {
                Ok(count) if count > 0 => Some(count),
                Ok(_) => {
                    warnings.push("CPU count is zero, cannot normalize load per CPU".to_string());
                    None
                }
                Err(_) => {
                    warnings.push("CPU count could not be determined; per-CPU normalization disabled.".to_string());
                    None
                }
            }
        } else {
            None
        };

        // Calculate per-CPU load averages
        let effective_cpu_count = cpu_count_logical
            .map(|count| count.max(opts.min_cpu_count))
            .unwrap_or(opts.min_cpu_count);

        let (load_1m_per_cpu, load_5m_per_cpu, load_15m_per_cpu) = if opts.normalize_per_cpu && cpu_count_logical.is_some() {
            (
                load_1m.map(|l| l / effective_cpu_count as f64),
                load_5m.map(|l| l / effective_cpu_count as f64),
                load_15m.map(|l| l / effective_cpu_count as f64)
            )
        } else {
            (None, None, None)
        };

        // Generate human-friendly classification
        let human = if opts.include_human {
            Some(self.classify_load(load_1m, load_1m_per_cpu, effective_cpu_count, opts.normalize_per_cpu && cpu_count_logical.is_some()))
        } else {
            None
        };

        // Build raw data if requested
        let raw = if opts.include_raw {
            Some(json!({
                "proc_loadavg_line": loadavg_line
            }))
        } else {
            None
        };

        // Build paths if requested
        let paths = if opts.include_paths {
            Some(json!({
                "load": "/proc/loadavg"
            }))
        } else {
            None
        };

        SystemLoadResponse {
            ok: true,
            timestamp_unix_ms,
            load_1m,
            load_5m,
            load_15m,
            load_1m_per_cpu,
            load_5m_per_cpu,
            load_15m_per_cpu,
            cpu_count_logical,
            runnable_processes,
            total_processes,
            human,
            raw,
            paths,
            error: None,
            warnings,
        }
    }

    pub fn collect_memory(
        &self,
        opts: &SystemMemoryOptions,
        provider: &dyn SystemProvider
    ) -> SystemMemoryResponse {
        let timestamp_unix_ms = provider.now_unix_ms();
        let mut warnings = Vec::new();

        // Try to read /proc/meminfo
        let meminfo_result = provider.read_proc_meminfo();

        if let Err(e) = &meminfo_result {
            // Cannot get memory at all - return error response
            return SystemMemoryResponse {
                ok: false,
                timestamp_unix_ms,
                system: None,
                hugepages: None,
                cgroup: None,
                human: None,
                raw: None,
                paths: if opts.include_paths {
                    Some(json!({
                        "meminfo": "/proc/meminfo"
                    }))
                } else {
                    None
                },
                error: Some(json!({
                    "code": "system.memory_meminfo_unavailable",
                    "message": format!("Unable to read /proc/meminfo: {}", e)
                })),
                warnings,
            };
        }

        let meminfo_content = meminfo_result.unwrap();
        
        // Parse meminfo
        let mut meminfo_map = HashMap::new();
        for line in meminfo_content.lines() {
            if let Some((key, value_part)) = line.split_once(':') {
                let value_str = value_part.trim().split_whitespace().next().unwrap_or("0");
                if let Ok(value) = value_str.parse::<u64>() {
                    meminfo_map.insert(key.to_string(), value);
                }
            }
        }

        // Extract system memory metrics
        let system = self.collect_system_memory(&meminfo_map, &mut warnings);
        
        // Extract hugepages metrics if requested
        let hugepages = if opts.include_hugepages {
            Some(self.collect_hugepages_memory(&meminfo_map, &mut warnings))
        } else {
            None
        };

        // Extract cgroup metrics if requested
        let cgroup = if opts.include_cgroup {
            Some(self.collect_cgroup_memory(provider, &mut warnings))
        } else {
            None
        };

        // Generate human-readable summaries if requested
        let human = if opts.include_human {
            Some(self.generate_memory_human_summary(&system, &cgroup))
        } else {
            None
        };

        // Build raw data if requested
        let raw = if opts.include_raw {
            let mut raw_data = json!({
                "meminfo": meminfo_map
            });
            
            // Add cgroup raw data if available
            if opts.include_cgroup {
                if let Some(cgroup_data) = self.collect_cgroup_raw_data(provider) {
                    raw_data.as_object_mut().unwrap().insert("cgroup".to_string(), cgroup_data);
                }
            }
            
            Some(raw_data)
        } else {
            None
        };

        // Build paths if requested
        let paths = if opts.include_paths {
            let mut paths_data = json!({
                "meminfo": "/proc/meminfo"
            });
            
            if opts.include_cgroup {
                paths_data.as_object_mut().unwrap().insert("cgroup_memory".to_string(), json!([
                    "/sys/fs/cgroup/memory.max",
                    "/sys/fs/cgroup/memory.current",
                    "/sys/fs/cgroup/memory.swap.max",
                    "/sys/fs/cgroup/memory.swap.current"
                ]));
            }
            
            Some(paths_data)
        } else {
            None
        };

        SystemMemoryResponse {
            ok: true,
            timestamp_unix_ms,
            system: Some(system),
            hugepages,
            cgroup,
            human,
            raw,
            paths,
            error: None,
            warnings,
        }
    }

    fn collect_system_memory(&self, meminfo: &HashMap<String, u64>, warnings: &mut Vec<String>) -> SystemMemorySystemMetrics {
        let mem_total_bytes = meminfo.get("MemTotal").copied().map(|kb| kb * 1024);
        let mem_free_bytes = meminfo.get("MemFree").copied().map(|kb| kb * 1024);
        let mem_available_bytes = meminfo.get("MemAvailable").copied().map(|kb| kb * 1024);
        let buffers_bytes = meminfo.get("Buffers").copied().map(|kb| kb * 1024);
        let cached_bytes = meminfo.get("Cached").copied().map(|kb| kb * 1024);
        let shmem_bytes = meminfo.get("Shmem").copied().map(|kb| kb * 1024);
        let sreclaimable_bytes = meminfo.get("SReclaimable").copied().map(|kb| kb * 1024);
        let swap_total_bytes = meminfo.get("SwapTotal").copied().map(|kb| kb * 1024);
        let swap_free_bytes = meminfo.get("SwapFree").copied().map(|kb| kb * 1024);

        // Calculate derived metrics
        let mem_used_bytes = if let (Some(total), Some(available)) = (mem_total_bytes, mem_available_bytes) {
            Some(total - available)
        } else if let (Some(total), Some(free), Some(buffers), Some(cached)) = 
                  (mem_total_bytes, mem_free_bytes, buffers_bytes, cached_bytes) {
            warnings.push("MemAvailable not found, using approximation".to_string());
            Some(total - free - buffers - cached)
        } else {
            warnings.push("Could not calculate memory used".to_string());
            None
        };

        let mem_used_pct = if let (Some(used), Some(total)) = (mem_used_bytes, mem_total_bytes) {
            if total > 0 {
                Some((used as f64 / total as f64) * 100.0)
            } else {
                None
            }
        } else {
            None
        };

        let swap_used_bytes = if let (Some(total), Some(free)) = (swap_total_bytes, swap_free_bytes) {
            Some(total - free)
        } else {
            None
        };

        let swap_used_pct = if let (Some(used), Some(total)) = (swap_used_bytes, swap_total_bytes) {
            if total > 0 {
                Some((used as f64 / total as f64) * 100.0)
            } else {
                Some(0.0)  // No swap means 0% used
            }
        } else {
            None
        };

        SystemMemorySystemMetrics {
            available: true,
            mem_total_bytes,
            mem_free_bytes,
            mem_available_bytes,
            buffers_bytes,
            cached_bytes,
            shmem_bytes,
            sreclaimable_bytes,
            swap_total_bytes,
            swap_free_bytes,
            mem_used_bytes,
            mem_used_pct,
            swap_used_bytes,
            swap_used_pct,
        }
    }

    fn collect_hugepages_memory(&self, meminfo: &HashMap<String, u64>, warnings: &mut Vec<String>) -> SystemMemoryHugepagesMetrics {
        let total = meminfo.get("HugePages_Total").copied();
        let free = meminfo.get("HugePages_Free").copied();
        let reserved = meminfo.get("HugePages_Rsvd").copied();
        let surplus = meminfo.get("HugePages_Surp").copied();
        let page_size_kb = meminfo.get("Hugepagesize").copied();
        let page_bytes = page_size_kb.map(|kb| kb * 1024);

        let available = total.is_some() || free.is_some() || page_size_kb.is_some();
        
        if !available {
            warnings.push("Hugepages metrics not available in /proc/meminfo".to_string());
        }

        SystemMemoryHugepagesMetrics {
            available,
            total,
            free,
            reserved,
            surplus,
            page_bytes,
        }
    }

    fn collect_cgroup_memory(&self, provider: &dyn SystemProvider, warnings: &mut Vec<String>) -> SystemMemoryCgroupMetrics {
        let mut unified = None;
        let mut memory_limit_bytes = None;
        let mut memory_usage_bytes = None;
        let mut swap_limit_bytes = None;
        let mut swap_usage_bytes = None;

        // Try cgroup v2 first
        if let Ok(content) = provider.read_cgroup_memory_max() {
            unified = Some(true);
            let limit_str = content.trim();
            if limit_str == "max" {
                memory_limit_bytes = None;  // No explicit limit
            } else if let Ok(limit) = limit_str.parse::<u64>() {
                memory_limit_bytes = Some(limit);
            }
        } else if let Ok(content) = provider.read_cgroup_memory_current() {
            // If we can read current but not max, still mark as v2 but with warning
            unified = Some(true);
            if let Ok(usage) = content.trim().parse::<u64>() {
                memory_usage_bytes = Some(usage);
            }
            warnings.push("Could not read cgroup memory limit".to_string());
        } else {
            // Try cgroup v1 as fallback
            unified = Some(false);
            warnings.push("Cgroup v2 memory metrics not available, trying v1".to_string());
        }

        // Try to read current usage
        if memory_usage_bytes.is_none() {
            if let Ok(content) = provider.read_cgroup_memory_current() {
                if let Ok(usage) = content.trim().parse::<u64>() {
                    memory_usage_bytes = Some(usage);
                }
            }
        }

        // Try to read swap metrics (optional)
        if let Ok(content) = provider.read_cgroup_memory_swap_max() {
            let limit_str = content.trim();
            if limit_str != "max" {
                if let Ok(limit) = limit_str.parse::<u64>() {
                    swap_limit_bytes = Some(limit);
                }
            }
        }

        if let Ok(content) = provider.read_cgroup_memory_swap_current() {
            if let Ok(usage) = content.trim().parse::<u64>() {
                swap_usage_bytes = Some(usage);
            }
        }

        // Calculate usage percentages
        let memory_used_pct = if let (Some(usage), Some(limit)) = (memory_usage_bytes, memory_limit_bytes) {
            if limit > 0 {
                Some((usage as f64 / limit as f64) * 100.0)
            } else {
                None
            }
        } else {
            None
        };

        let swap_used_pct = if let (Some(usage), Some(limit)) = (swap_usage_bytes, swap_limit_bytes) {
            if limit > 0 {
                Some((usage as f64 / limit as f64) * 100.0)
            } else {
                None
            }
        } else {
            None
        };

        let available = memory_limit_bytes.is_some() || memory_usage_bytes.is_some();
        
        if !available {
            warnings.push("Cgroup memory metrics not available on this system".to_string());
        }

        SystemMemoryCgroupMetrics {
            available,
            unified,
            memory_limit_bytes,
            memory_usage_bytes,
            memory_used_pct,
            swap_limit_bytes,
            swap_usage_bytes,
            swap_used_pct,
        }
    }

    fn generate_memory_human_summary(&self, system: &SystemMemorySystemMetrics, cgroup: &Option<SystemMemoryCgroupMetrics>) -> SystemMemoryHumanSummary {
        let system_summary = if let (Some(total), Some(used), Some(used_pct)) = 
            (system.mem_total_bytes, system.mem_used_bytes, system.mem_used_pct) {
            let total_gb = total as f64 / 1024.0 / 1024.0 / 1024.0;
            let used_gb = used as f64 / 1024.0 / 1024.0 / 1024.0;
            
            let swap_summary = if let (Some(swap_total), Some(swap_used), Some(swap_pct)) = 
                (system.swap_total_bytes, system.swap_used_bytes, system.swap_used_pct) {
                if swap_total > 0 {
                    let swap_used_gb = swap_used as f64 / 1024.0 / 1024.0 / 1024.0;
                    format!(", {:.1} GiB swap used ({:.1}%)", swap_used_gb, swap_pct)
                } else {
                    String::new()
                }
            } else {
                String::new()
            };
            
            Some(format!("{:.1} GiB total, {:.1} GiB used ({:.1}%){}", 
                         total_gb, used_gb, used_pct, swap_summary))
        } else {
            None
        };

        let cgroup_summary = if let Some(cgroup) = cgroup {
            if let (Some(limit), Some(usage), Some(used_pct)) = 
                (cgroup.memory_limit_bytes, cgroup.memory_usage_bytes, cgroup.memory_used_pct) {
                let limit_gb = limit as f64 / 1024.0 / 1024.0 / 1024.0;
                let usage_gb = usage as f64 / 1024.0 / 1024.0 / 1024.0;
                Some(format!("{:.1} GiB limit, {:.1} GiB used ({:.1}%)", 
                           limit_gb, usage_gb, used_pct))
            } else {
                None
            }
        } else {
            None
        };

        SystemMemoryHumanSummary {
            system_summary,
            cgroup_summary,
        }
    }

    fn collect_cgroup_raw_data(&self, provider: &dyn SystemProvider) -> Option<Value> {
        let mut cgroup_data = std::collections::HashMap::new();

        if let Ok(content) = provider.read_cgroup_memory_max() {
            cgroup_data.insert("memory_max".to_string(), content);
        }
        
        if let Ok(content) = provider.read_cgroup_memory_current() {
            cgroup_data.insert("memory_current".to_string(), content);
        }
        
        if let Ok(content) = provider.read_cgroup_memory_swap_max() {
            cgroup_data.insert("memory_swap_max".to_string(), content);
        }
        
        if let Ok(content) = provider.read_cgroup_memory_swap_current() {
            cgroup_data.insert("memory_swap_current".to_string(), content);
        }

        if cgroup_data.is_empty() {
            None
        } else {
            Some(json!(cgroup_data))
        }
    }

    pub fn collect_cpu(
        &self,
        opts: &SystemCpuOptions,
        provider: &dyn SystemProvider
    ) -> SystemCpuResponse {
        let timestamp_unix_ms = provider.now_unix_ms();
        let mut warnings = Vec::new();

        // Calculate effective sampling duration
        let sample_duration = if opts.sample_duration_ms == 0 {
            opts.sample_min_ms
        } else {
            opts.sample_duration_ms.max(opts.sample_min_ms)
        };

        // Read /proc/stat twice for utilization calculation
        let stat_start = provider.read_proc_stat();
        if let Err(e) = &stat_start {
            return SystemCpuResponse {
                ok: false,
                timestamp_unix_ms,
                system: None,
                per_cpu: None,
                cgroup: None,
                human: None,
                raw: None,
                paths: if opts.include_paths {
                    Some(json!({
                        "stat": "/proc/stat"
                    }))
                } else {
                    None
                },
                error: Some(json!({
                    "code": "system.cpu_stat_unavailable",
                    "message": format!("Unable to read /proc/stat: {}", e)
                })),
                warnings,
            };
        }

        let stat_start_content = stat_start.unwrap();
        let cpu_stats_start = match self.parse_proc_stat(&stat_start_content) {
            Ok(stats) => stats,
            Err(e) => {
                return SystemCpuResponse {
                    ok: false,
                    timestamp_unix_ms,
                    system: None,
                    per_cpu: None,
                    cgroup: None,
                    human: None,
                    raw: if opts.include_raw {
                        Some(json!({
                            "proc_stat_start": stat_start_content
                        }))
                    } else {
                        None
                    },
                    paths: if opts.include_paths {
                        Some(json!({
                            "stat": "/proc/stat"
                        }))
                    } else {
                        None
                    },
                    error: Some(json!({
                        "code": "system.cpu_stat_parse_error",
                        "message": format!("Failed to parse /proc/stat: {}", e)
                    })),
                    warnings,
                };
            }
        };

        // Sleep for sampling duration
        provider.sleep_ms(sample_duration);

        // Read /proc/stat again
        let stat_end = provider.read_proc_stat();
        if let Err(e) = &stat_end {
            return SystemCpuResponse {
                ok: false,
                timestamp_unix_ms,
                system: None,
                per_cpu: None,
                cgroup: None,
                human: None,
                raw: if opts.include_raw {
                    Some(json!({
                        "proc_stat_start": stat_start_content
                    }))
                } else {
                    None
                },
                paths: if opts.include_paths {
                    Some(json!({
                        "stat": "/proc/stat"
                    }))
                } else {
                    None
                },
                error: Some(json!({
                    "code": "system.cpu_stat_unavailable",
                    "message": format!("Unable to read /proc/stat for second sample: {}", e)
                })),
                warnings,
            };
        }

        let stat_end_content = stat_end.unwrap();
        let cpu_stats_end = match self.parse_proc_stat(&stat_end_content) {
            Ok(stats) => stats,
            Err(e) => {
                return SystemCpuResponse {
                    ok: false,
                    timestamp_unix_ms,
                    system: None,
                    per_cpu: None,
                    cgroup: None,
                    human: None,
                    raw: if opts.include_raw {
                        Some(json!({
                            "proc_stat_start": stat_start_content,
                            "proc_stat_end": stat_end_content
                        }))
                    } else {
                        None
                    },
                    paths: if opts.include_paths {
                        Some(json!({
                            "stat": "/proc/stat"
                        }))
                    } else {
                        None
                    },
                    error: Some(json!({
                        "code": "system.cpu_stat_parse_error",
                        "message": format!("Failed to parse second /proc/stat: {}", e)
                    })),
                    warnings,
                };
            }
        };

        // Calculate CPU metrics
        let system = self.collect_system_cpu_metrics(&cpu_stats_start, &cpu_stats_end, opts, provider, &mut warnings);
        let per_cpu = if opts.per_cpu {
            Some(self.collect_per_cpu_metrics(&cpu_stats_start, &cpu_stats_end, opts, provider, &mut warnings))
        } else {
            None
        };

        // Collect cgroup metrics
        let cgroup = if opts.include_cgroup {
            Some(self.collect_cpu_cgroup_metrics(provider, &mut warnings))
        } else {
            None
        };

        // Generate human summary
        let human = if opts.include_human {
            Some(self.generate_cpu_human_summary(&system, &per_cpu))
        } else {
            None
        };

        // Prepare raw data
        let raw = if opts.include_raw {
            let mut raw_data = json!({
                "proc_stat_start": stat_start_content,
                "proc_stat_end": stat_end_content,
                "sample_duration_ms": sample_duration
            });

            if opts.include_frequency && system.logical_count.is_some() {
                let freq_data = self.collect_frequency_raw_data(system.logical_count.unwrap(), provider);
                if !freq_data.is_empty() {
                    raw_data["frequency"] = json!(freq_data);
                }
            }

            Some(raw_data)
        } else {
            None
        };

        // Prepare paths
        let paths = if opts.include_paths {
            let mut paths_data = json!({
                "stat": "/proc/stat"
            });

            if opts.include_frequency && system.logical_count.is_some() {
                paths_data["cpufreq_scaling_cur_freq"] = json!(format!("/sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq"));
                paths_data["cpufreq_cpuinfo_max_freq"] = json!(format!("/sys/devices/system/cpu/cpu*/cpufreq/cpuinfo_max_freq"));
            }

            if opts.include_topology && system.logical_count.is_some() {
                paths_data["topology_core_id"] = json!(format!("/sys/devices/system/cpu/cpu*/topology/core_id"));
                paths_data["topology_physical_package_id"] = json!(format!("/sys/devices/system/cpu/cpu*/topology/physical_package_id"));
            }

            if opts.include_cgroup {
                paths_data["cgroup_cpu_max"] = json!("/sys/fs/cgroup/cpu.max");
                paths_data["cgroup_cpu_stat"] = json!("/sys/fs/cgroup/cpu.stat");
            }

            Some(paths_data)
        } else {
            None
        };

        SystemCpuResponse {
            ok: true,
            timestamp_unix_ms,
            system: Some(system),
            per_cpu,
            cgroup,
            human,
            raw,
            paths,
            error: None,
            warnings,
        }
    }

    pub fn parse_proc_stat(&self, content: &str) -> Result<Vec<CpuStatLine>> {
        let mut cpu_stats = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if !line.starts_with("cpu") {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 8 {
                continue; // Skip malformed lines
            }

            let name = parts[0].to_string();
            let user = parts[1].parse().unwrap_or(0);
            let nice = parts[2].parse().unwrap_or(0);
            let system = parts[3].parse().unwrap_or(0);
            let idle = parts[4].parse().unwrap_or(0);
            let iowait = parts[5].parse().unwrap_or(0);
            let irq = parts[6].parse().unwrap_or(0);
            let softirq = parts[7].parse().unwrap_or(0);
            let steal = if parts.len() > 8 { parts[8].parse().unwrap_or(0) } else { 0 };
            let guest = if parts.len() > 9 { parts[9].parse().unwrap_or(0) } else { 0 };
            let guest_nice = if parts.len() > 10 { parts[10].parse().unwrap_or(0) } else { 0 };

            cpu_stats.push(CpuStatLine {
                name,
                user,
                nice,
                system,
                idle,
                iowait,
                irq,
                softirq,
                steal,
                guest,
                guest_nice,
            });
        }

        Ok(cpu_stats)
    }

    pub fn calculate_cpu_utilization(&self, start: &CpuStatLine, end: &CpuStatLine, warnings: &mut Vec<String>) -> (Option<f64>, Option<f64>, Option<f64>, Option<f64>, Option<f64>, Option<f64>, Option<f64>, Option<f64>, Option<f64>, Option<f64>, Option<f64>) {
        let delta_user = end.user.saturating_sub(start.user);
        let delta_nice = end.nice.saturating_sub(start.nice);
        let delta_system = end.system.saturating_sub(start.system);
        let delta_idle = end.idle.saturating_sub(start.idle);
        let delta_iowait = end.iowait.saturating_sub(start.iowait);
        let delta_irq = end.irq.saturating_sub(start.irq);
        let delta_softirq = end.softirq.saturating_sub(start.softirq);
        let delta_steal = end.steal.saturating_sub(start.steal);
        let delta_guest = end.guest.saturating_sub(start.guest);
        let delta_guest_nice = end.guest_nice.saturating_sub(start.guest_nice);

        let total_delta = delta_user + delta_nice + delta_system + delta_idle + delta_iowait + 
                         delta_irq + delta_softirq + delta_steal + delta_guest + delta_guest_nice;

        if total_delta == 0 {
            warnings.push(format!("Zero CPU time delta for {}, utilization may be inaccurate", start.name));
            return (Some(0.0), Some(0.0), Some(0.0), Some(100.0), Some(0.0), Some(0.0), Some(0.0), Some(0.0), Some(0.0), Some(0.0), Some(0.0));
        }

        let total_delta_f = total_delta as f64;
        let utilization_pct = 100.0 * (total_delta - delta_idle) as f64 / total_delta_f;
        let user_pct = 100.0 * delta_user as f64 / total_delta_f;
        let nice_pct = 100.0 * delta_nice as f64 / total_delta_f;
        let system_pct = 100.0 * delta_system as f64 / total_delta_f;
        let idle_pct = 100.0 * delta_idle as f64 / total_delta_f;
        let iowait_pct = 100.0 * delta_iowait as f64 / total_delta_f;
        let irq_pct = 100.0 * delta_irq as f64 / total_delta_f;
        let softirq_pct = 100.0 * delta_softirq as f64 / total_delta_f;
        let steal_pct = 100.0 * delta_steal as f64 / total_delta_f;
        let guest_pct = 100.0 * delta_guest as f64 / total_delta_f;
        let guest_nice_pct = 100.0 * delta_guest_nice as f64 / total_delta_f;

        (
            Some(utilization_pct),
            Some(user_pct),
            Some(nice_pct),
            Some(system_pct),
            Some(idle_pct),
            Some(iowait_pct),
            Some(irq_pct),
            Some(softirq_pct),
            Some(steal_pct),
            Some(guest_pct),
            Some(guest_nice_pct),
        )
    }

    fn collect_system_cpu_metrics(
        &self,
        stats_start: &[CpuStatLine],
        stats_end: &[CpuStatLine],
        opts: &SystemCpuOptions,
        provider: &dyn SystemProvider,
        warnings: &mut Vec<String>
    ) -> SystemCpuSystemMetrics {
        // Find the aggregate CPU line (should be first and named "cpu")
        let cpu_start = stats_start.iter().find(|s| s.name == "cpu");
        let cpu_end = stats_end.iter().find(|s| s.name == "cpu");

        if cpu_start.is_none() || cpu_end.is_none() {
            warnings.push("Could not find aggregate CPU line in /proc/stat".to_string());
            return SystemCpuSystemMetrics {
                available: false,
                logical_count: None,
                physical_count: None,
                socket_count: None,
                utilization_pct: None,
                user_pct: None,
                nice_pct: None,
                system_pct: None,
                idle_pct: None,
                iowait_pct: None,
                irq_pct: None,
                softirq_pct: None,
                steal_pct: None,
                guest_pct: None,
                guest_nice_pct: None,
                frequency_current_hz: None,
                frequency_max_hz: None,
            };
        }

        let cpu_start = cpu_start.unwrap();
        let cpu_end = cpu_end.unwrap();

        // Calculate utilization percentages
        let (utilization_pct, user_pct, nice_pct, system_pct, idle_pct, iowait_pct, 
             irq_pct, softirq_pct, steal_pct, guest_pct, guest_nice_pct) = 
            self.calculate_cpu_utilization(cpu_start, cpu_end, warnings);

        // Count logical CPUs (all cpuN lines except "cpu")
        let logical_count = stats_start.iter()
            .filter(|s| s.name != "cpu" && s.name.starts_with("cpu"))
            .count() as u32;

        // Get topology information if requested
        let (physical_count, socket_count) = if opts.include_topology && logical_count > 0 {
            self.collect_cpu_topology(logical_count, provider, warnings)
        } else {
            (None, None)
        };

        // Get frequency information if requested
        let (frequency_current_hz, frequency_max_hz) = if opts.include_frequency && logical_count > 0 {
            self.collect_cpu_frequencies(logical_count, provider, warnings)
        } else {
            (None, None)
        };

        SystemCpuSystemMetrics {
            available: true,
            logical_count: Some(logical_count),
            physical_count,
            socket_count,
            utilization_pct,
            user_pct,
            nice_pct,
            system_pct,
            idle_pct,
            iowait_pct,
            irq_pct,
            softirq_pct,
            steal_pct,
            guest_pct,
            guest_nice_pct,
            frequency_current_hz,
            frequency_max_hz,
        }
    }

    fn collect_per_cpu_metrics(
        &self,
        stats_start: &[CpuStatLine],
        stats_end: &[CpuStatLine],
        opts: &SystemCpuOptions,
        provider: &dyn SystemProvider,
        warnings: &mut Vec<String>
    ) -> Vec<SystemCpuCoreMetrics> {
        let mut per_cpu = Vec::new();

        // Get all individual CPU lines (cpuN where N is a number)
        let cpu_lines_start: Vec<_> = stats_start.iter()
            .filter(|s| s.name != "cpu" && s.name.starts_with("cpu"))
            .collect();
        let cpu_lines_end: Vec<_> = stats_end.iter()
            .filter(|s| s.name != "cpu" && s.name.starts_with("cpu"))
            .collect();

        for (i, cpu_start) in cpu_lines_start.iter().enumerate() {
            // Find matching CPU in end stats
            let cpu_end = cpu_lines_end.iter()
                .find(|s| s.name == cpu_start.name);

            if cpu_end.is_none() {
                warnings.push(format!("Could not find matching CPU {} in second sample", cpu_start.name));
                continue;
            }

            let cpu_end = cpu_end.unwrap();
            let cpu_id = i as u32;

            // Calculate utilization
            let (utilization_pct, user_pct, nice_pct, system_pct, idle_pct, iowait_pct, 
                 irq_pct, softirq_pct, steal_pct, guest_pct, guest_nice_pct) = 
                self.calculate_cpu_utilization(cpu_start, cpu_end, warnings);

            // Get frequency for this CPU
            let (frequency_current_hz, frequency_max_hz) = if opts.include_frequency {
                self.collect_single_cpu_frequency(cpu_id, provider, warnings)
            } else {
                (None, None)
            };

            // Get topology for this CPU
            let (core_id, socket_id) = if opts.include_topology {
                self.collect_single_cpu_topology(cpu_id, provider, warnings)
            } else {
                (None, None)
            };

            per_cpu.push(SystemCpuCoreMetrics {
                id: cpu_id,
                utilization_pct,
                user_pct,
                nice_pct,
                system_pct,
                idle_pct,
                iowait_pct,
                irq_pct,
                softirq_pct,
                steal_pct,
                guest_pct,
                guest_nice_pct,
                frequency_current_hz,
                frequency_max_hz,
                core_id,
                socket_id,
            });
        }

        per_cpu
    }

    pub fn collect_cpu_topology(&self, logical_count: u32, provider: &dyn SystemProvider, warnings: &mut Vec<String>) -> (Option<u32>, Option<u32>) {
        let mut unique_cores = std::collections::HashSet::new();
        let mut unique_sockets = std::collections::HashSet::new();

        for cpu_id in 0..logical_count {
            if let Ok((core_id, socket_id)) = provider.read_cpu_topology(cpu_id) {
                if let Some(core_id) = core_id {
                    unique_cores.insert(core_id);
                }
                if let Some(socket_id) = socket_id {
                    unique_sockets.insert(socket_id);
                }
            }
        }

        let physical_count = if !unique_cores.is_empty() {
            Some(unique_cores.len() as u32)
        } else {
            warnings.push("CPU topology information not available".to_string());
            None
        };

        let socket_count = if !unique_sockets.is_empty() {
            Some(unique_sockets.len() as u32)
        } else {
            None
        };

        (physical_count, socket_count)
    }

    pub fn collect_cpu_frequencies(&self, logical_count: u32, provider: &dyn SystemProvider, warnings: &mut Vec<String>) -> (Option<u64>, Option<u64>) {
        let mut current_freqs = Vec::new();
        let mut max_freqs = Vec::new();

        for cpu_id in 0..logical_count {
            if let Ok(freq_str) = provider.read_cpu_frequency_current(cpu_id) {
                if let Ok(freq_khz) = freq_str.trim().parse::<u64>() {
                    current_freqs.push(freq_khz * 1000); // Convert kHz to Hz
                }
            }

            if let Ok(freq_str) = provider.read_cpu_frequency_max(cpu_id) {
                if let Ok(freq_khz) = freq_str.trim().parse::<u64>() {
                    max_freqs.push(freq_khz * 1000); // Convert kHz to Hz
                }
            }
        }

        let frequency_current_hz = if !current_freqs.is_empty() {
            let avg = current_freqs.iter().sum::<u64>() / current_freqs.len() as u64;
            Some(avg)
        } else {
            warnings.push("CPU frequency information not available".to_string());
            None
        };

        let frequency_max_hz = if !max_freqs.is_empty() {
            let avg = max_freqs.iter().sum::<u64>() / max_freqs.len() as u64;
            Some(avg)
        } else {
            None
        };

        (frequency_current_hz, frequency_max_hz)
    }

    fn collect_single_cpu_frequency(&self, cpu_id: u32, provider: &dyn SystemProvider, _warnings: &mut Vec<String>) -> (Option<u64>, Option<u64>) {
        let frequency_current_hz = provider.read_cpu_frequency_current(cpu_id)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|khz| khz * 1000);

        let frequency_max_hz = provider.read_cpu_frequency_max(cpu_id)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|khz| khz * 1000);

        (frequency_current_hz, frequency_max_hz)
    }

    fn collect_single_cpu_topology(&self, cpu_id: u32, provider: &dyn SystemProvider, _warnings: &mut Vec<String>) -> (Option<u32>, Option<u32>) {
        provider.read_cpu_topology(cpu_id).unwrap_or((None, None))
    }

    pub fn collect_cpu_cgroup_metrics(&self, provider: &dyn SystemProvider, warnings: &mut Vec<String>) -> SystemCpuCgroupMetrics {
        // Try to read cgroup v2 cpu.max
        if let Ok(cpu_max_content) = provider.read_cgroup_cpu_max() {
            let parts: Vec<&str> = cpu_max_content.trim().split_whitespace().collect();
            
            let (cpu_quota_us, cpu_period_us, unified) = if parts.len() >= 2 {
                // cgroup v2 format: "quota period" or "max period"
                let quota_str = parts[0];
                let period_str = parts[1];
                
                let quota = if quota_str == "max" {
                    None
                } else {
                    quota_str.parse::<i64>().ok()
                };
                
                let period = period_str.parse::<u64>().ok();
                
                (quota, period, Some(true))
            } else {
                warnings.push("Could not parse cgroup cpu.max format".to_string());
                (None, None, Some(true))
            };

            let cpu_quota_cores = if let (Some(quota), Some(period)) = (cpu_quota_us, cpu_period_us) {
                if quota > 0 && period > 0 {
                    Some(quota as f64 / period as f64)
                } else {
                    None
                }
            } else {
                None
            };

            // Try to read cgroup v2 cpu.stat for usage
            let (usage_seconds, usage_user_seconds, usage_system_seconds) = if let Ok(cpu_stat_content) = provider.read_cgroup_cpu_stat() {
                self.parse_cgroup_v2_cpu_stat(&cpu_stat_content, warnings)
            } else {
                warnings.push("Could not read cgroup cpu.stat".to_string());
                (None, None, None)
            };

            SystemCpuCgroupMetrics {
                available: true,
                unified,
                cpu_quota_cores,
                cpu_period_us,
                cpu_quota_us,
                usage_seconds,
                usage_user_seconds,
                usage_system_seconds,
            }
        } else {
            // Try cgroup v1
            let cpu_quota_us = provider.read_cgroup_cpu_quota()
                .ok()
                .and_then(|s| s.trim().parse::<i64>().ok());
                
            let cpu_period_us = provider.read_cgroup_cpu_period()
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok());

            let cpu_quota_cores = if let (Some(quota), Some(period)) = (cpu_quota_us, cpu_period_us) {
                if quota > 0 && period > 0 {
                    Some(quota as f64 / period as f64)
                } else {
                    None
                }
            } else {
                None
            };

            let usage_seconds = provider.read_cgroup_cpu_usage()
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .map(|ns| ns as f64 / 1_000_000_000.0); // Convert nanoseconds to seconds

            if cpu_quota_us.is_some() || cpu_period_us.is_some() || usage_seconds.is_some() {
                SystemCpuCgroupMetrics {
                    available: true,
                    unified: Some(false),
                    cpu_quota_cores,
                    cpu_period_us,
                    cpu_quota_us,
                    usage_seconds,
                    usage_user_seconds: None,
                    usage_system_seconds: None,
                }
            } else {
                warnings.push("CPU cgroup information not available".to_string());
                SystemCpuCgroupMetrics {
                    available: false,
                    unified: None,
                    cpu_quota_cores: None,
                    cpu_period_us: None,
                    cpu_quota_us: None,
                    usage_seconds: None,
                    usage_user_seconds: None,
                    usage_system_seconds: None,
                }
            }
        }
    }

    fn parse_cgroup_v2_cpu_stat(&self, content: &str, _warnings: &mut Vec<String>) -> (Option<f64>, Option<f64>, Option<f64>) {
        let mut usage_usec = None;
        let mut user_usec = None;
        let mut system_usec = None;

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                match parts[0] {
                    "usage_usec" => usage_usec = parts[1].parse::<u64>().ok(),
                    "user_usec" => user_usec = parts[1].parse::<u64>().ok(),
                    "system_usec" => system_usec = parts[1].parse::<u64>().ok(),
                    _ => {}
                }
            }
        }

        (
            usage_usec.map(|us| us as f64 / 1_000_000.0), // Convert microseconds to seconds
            user_usec.map(|us| us as f64 / 1_000_000.0),
            system_usec.map(|us| us as f64 / 1_000_000.0),
        )
    }

    pub fn generate_cpu_human_summary(
        &self,
        system: &SystemCpuSystemMetrics,
        per_cpu: &Option<Vec<SystemCpuCoreMetrics>>
    ) -> SystemCpuHumanInfo {
        let utilization_pct = system.utilization_pct.unwrap_or(0.0);
        
        let (status, status_reason) = if utilization_pct < 5.0 {
            ("idle", format!("Overall CPU utilization is {:.1}%, system is idle.", utilization_pct))
        } else if utilization_pct < 60.0 {
            ("normal", format!("Overall CPU utilization is {:.1}%, well within normal range.", utilization_pct))
        } else if utilization_pct < 85.0 {
            ("busy", format!("Overall CPU utilization is {:.1}%, system is busy but manageable.", utilization_pct))
        } else {
            ("overloaded", format!("Overall CPU utilization is {:.1}%, system is overloaded.", utilization_pct))
        };

        let per_cpu_hotspots = if let Some(per_cpu) = per_cpu {
            per_cpu.iter()
                .filter_map(|cpu| {
                    if let Some(util) = cpu.utilization_pct {
                        if util > 80.0 {
                            Some(format!("cpu{} at {:.1}%", cpu.id, util))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        SystemCpuHumanInfo {
            status: status.to_string(),
            status_reason,
            per_cpu_hotspots,
        }
    }

    fn collect_frequency_raw_data(&self, logical_count: u32, provider: &dyn SystemProvider) -> std::collections::HashMap<String, String> {
        let mut freq_data = std::collections::HashMap::new();

        for cpu_id in 0..logical_count {
            if let Ok(content) = provider.read_cpu_frequency_current(cpu_id) {
                freq_data.insert(format!("cpu{}_scaling_cur_freq", cpu_id), content);
            }
            
            if let Ok(content) = provider.read_cpu_frequency_max(cpu_id) {
                freq_data.insert(format!("cpu{}_cpuinfo_max_freq", cpu_id), content);
            }
        }

        freq_data
    }

    pub fn format_cpu_text(&self, response: &SystemCpuResponse) -> Result<String> {
        let mut output = String::new();
        
        output.push_str("CPU Metrics\n");
        output.push_str("===========\n\n");
        
        // Timestamp
        let timestamp = chrono::DateTime::from_timestamp(response.timestamp_unix_ms / 1000, 0)
            .unwrap_or_else(|| chrono::Utc::now());
        output.push_str(&format!("Timestamp : {}\n\n", timestamp.format("%Y-%m-%dT%H:%M:%SZ")));

        // System CPU info
        if let Some(system) = &response.system {
            output.push_str("System:\n");
            if let Some(count) = system.logical_count {
                output.push_str(&format!("  Logical CPUs : {}\n", count));
            }
            if let Some(count) = system.physical_count {
                output.push_str(&format!("  Physical     : {}\n", count));
            }
            if let Some(count) = system.socket_count {
                output.push_str(&format!("  Sockets      : {}\n", count));
            }
            output.push_str("\n");
            
            if let Some(util) = system.utilization_pct {
                output.push_str(&format!("  Utilization  : {:.1}%\n", util));
            }
            if let Some(user) = system.user_pct {
                output.push_str(&format!("  User         : {:.1}%\n", user));
            }
            if let Some(sys) = system.system_pct {
                output.push_str(&format!("  System       : {:.1}%\n", sys));
            }
            if let Some(idle) = system.idle_pct {
                output.push_str(&format!("  Idle         : {:.1}%\n", idle));
            }
            if let Some(iowait) = system.iowait_pct {
                output.push_str(&format!("  IOwait       : {:.1}%\n", iowait));
            }
            output.push_str("\n");
            
            if let (Some(cur), Some(max)) = (system.frequency_current_hz, system.frequency_max_hz) {
                output.push_str(&format!("  Freq (avg)   : {:.2} GHz (max {:.2} GHz)\n", 
                    cur as f64 / 1_000_000_000.0, max as f64 / 1_000_000_000.0));
            }
            output.push_str("\n");
        }

        // Per-CPU info
        if let Some(per_cpu) = &response.per_cpu {
            output.push_str("Per-CPU:\n");
            for cpu in per_cpu.iter().take(16) { // Limit to first 16 CPUs for readability
                let util_str = cpu.utilization_pct.map_or("N/A".to_string(), |u| format!("{:.1}%", u));
                let freq_str = cpu.frequency_current_hz.map_or(String::new(), |f| format!("  ({:.2} GHz)", f as f64 / 1_000_000_000.0));
                output.push_str(&format!("  cpu{}: {}{}\n", cpu.id, util_str, freq_str));
            }
            
            if per_cpu.len() > 16 {
                output.push_str(&format!("  ... and {} more CPUs\n", per_cpu.len() - 16));
            }
            output.push_str("\n");
        }

        // Cgroup info
        if let Some(cgroup) = &response.cgroup {
            if cgroup.available {
                output.push_str("Cgroup:\n");
                output.push_str(&format!("  Available    : yes\n"));
                if let Some(cores) = cgroup.cpu_quota_cores {
                    output.push_str(&format!("  Quota cores  : {:.1}\n", cores));
                }
                if let Some(period) = cgroup.cpu_period_us {
                    output.push_str(&format!("  Period       : {} us\n", period));
                }
                if let Some(quota) = cgroup.cpu_quota_us {
                    output.push_str(&format!("  Quota        : {} us\n", quota));
                }
                if let Some(usage) = cgroup.usage_seconds {
                    output.push_str(&format!("  Usage        : {:.1} s\n", usage));
                }
                output.push_str("\n");
            }
        }

        // Status
        if let Some(human) = &response.human {
            output.push_str("Status:\n");
            output.push_str(&format!("  {} — {}\n", human.status, human.status_reason));
            
            if !human.per_cpu_hotspots.is_empty() {
                output.push_str("\nHotspots:\n");
                for hotspot in &human.per_cpu_hotspots {
                    output.push_str(&format!("  {}\n", hotspot));
                }
            }
            output.push_str("\n");
        }

        // Warnings
        if !response.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &response.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        } else {
            output.push_str("Warnings:\n  (none)\n");
        }

        Ok(output)
    }

    fn classify_load(&self, load_1m: Option<f64>, load_1m_per_cpu: Option<f64>, cpu_count: u32, use_per_cpu: bool) -> SystemLoadHumanInfo {
        let (load_metric, description_prefix) = if use_per_cpu && load_1m_per_cpu.is_some() {
            (load_1m_per_cpu.unwrap(), "1m load per CPU")
        } else if let Some(load) = load_1m {
            (load, "1m load")
        } else {
            return SystemLoadHumanInfo {
                status: "unknown".to_string(),
                status_reason: "Load information not available".to_string(),
                load_vs_cpu_ratio: None,
            };
        };

        let load_vs_cpu_ratio = if use_per_cpu {
            load_1m_per_cpu
        } else {
            load_1m.map(|l| l / cpu_count as f64)
        };

        let (status, status_reason) = if use_per_cpu {
            // Use per-CPU thresholds
            if load_metric < 0.1 {
                ("idle", format!("{} is very low (< 0.1)", description_prefix))
            } else if load_metric < 0.7 {
                ("normal", format!("{} is within normal range (0.1-0.7)", description_prefix))
            } else if load_metric <= 1.5 {
                ("busy", format!("{} is busy but manageable (0.7-1.5)", description_prefix))
            } else {
                ("overloaded", format!("{} exceeds safe threshold (> 1.5)", description_prefix))
            }
        } else {
            // Use absolute thresholds without CPU normalization
            if load_metric < 1.0 {
                ("idle", format!("{} is low", description_prefix))
            } else if load_metric < cpu_count as f64 * 0.7 {
                ("normal", format!("{} is within normal range for {} CPUs", description_prefix, cpu_count))
            } else if load_metric <= cpu_count as f64 * 1.5 {
                ("busy", format!("{} is busy but manageable for {} CPUs", description_prefix, cpu_count))
            } else {
                ("overloaded", format!("{} is very high for {} CPUs", description_prefix, cpu_count))
            }
        };

        SystemLoadHumanInfo {
            status: status.to_string(),
            status_reason,
            load_vs_cpu_ratio,
        }
    }

    pub fn format_load_text(&self, response: &SystemLoadResponse) -> Result<String> {
        let mut output = String::new();

        output.push_str("System Load\n");
        output.push_str("===========\n\n");

        // Format timestamp
        let timestamp_secs = response.timestamp_unix_ms / 1000;
        let dt = chrono::DateTime::from_timestamp(timestamp_secs, 0)
            .unwrap_or_else(|| chrono::DateTime::UNIX_EPOCH);
        output.push_str(&format!("Timestamp : {}\n\n", dt.format("%Y-%m-%dT%H:%M:%SZ")));

        // Load Averages
        output.push_str("Load Averages:\n");
        if let Some(load_1m) = response.load_1m {
            output.push_str(&format!("  1m  : {:.2}\n", load_1m));
        } else {
            output.push_str("  1m  : (unknown)\n");
        }
        if let Some(load_5m) = response.load_5m {
            output.push_str(&format!("  5m  : {:.2}\n", load_5m));
        } else {
            output.push_str("  5m  : (unknown)\n");
        }
        if let Some(load_15m) = response.load_15m {
            output.push_str(&format!("  15m : {:.2}\n\n", load_15m));
        } else {
            output.push_str("  15m : (unknown)\n\n");
        }

        // CPU info
        if let Some(cpu_count) = response.cpu_count_logical {
            output.push_str("CPU:\n");
            output.push_str(&format!("  Logical CPUs : {}\n", cpu_count));
            if let Some(load_per_cpu) = response.load_1m_per_cpu {
                output.push_str(&format!("  1m per CPU   : {:.3}\n\n", load_per_cpu));
            } else {
                output.push_str("\n");
            }
        }

        // Queue info
        if response.runnable_processes.is_some() || response.total_processes.is_some() {
            output.push_str("Queue:\n");
            if let Some(runnable) = response.runnable_processes {
                output.push_str(&format!("  Runnable     : {}\n", runnable));
            } else {
                output.push_str("  Runnable     : (unknown)\n");
            }
            if let Some(total) = response.total_processes {
                output.push_str(&format!("  Total        : {}\n\n", total));
            } else {
                output.push_str("  Total        : (unknown)\n\n");
            }
        }

        // Status
        if let Some(human) = &response.human {
            output.push_str("Status:\n");
            output.push_str(&format!("  {} — {}\n\n", human.status, human.status_reason));
        }

        // Warnings
        output.push_str("Warnings:\n");
        if response.warnings.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for warning in &response.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        }

        Ok(output)
    }

    pub fn format_memory_text(&self, response: &SystemMemoryResponse) -> Result<String> {
        let mut output = String::new();

        output.push_str("System Memory\n");
        output.push_str("=============\n\n");

        // Format timestamp
        let timestamp_secs = response.timestamp_unix_ms / 1000;
        let dt = chrono::DateTime::from_timestamp(timestamp_secs, 0)
            .unwrap_or_else(|| chrono::DateTime::UNIX_EPOCH);
        output.push_str(&format!("Timestamp : {}\n\n", dt.format("%Y-%m-%dT%H:%M:%SZ")));

        // System Memory
        if let Some(system) = &response.system {
            output.push_str("System:\n");
            
            if let Some(total) = system.mem_total_bytes {
                let total_gb = total as f64 / 1024.0 / 1024.0 / 1024.0;
                output.push_str(&format!("  Total       : {:.1} GiB\n", total_gb));
            } else {
                output.push_str("  Total       : (unknown)\n");
            }
            
            if let (Some(used), Some(pct)) = (system.mem_used_bytes, system.mem_used_pct) {
                let used_gb = used as f64 / 1024.0 / 1024.0 / 1024.0;
                output.push_str(&format!("  Used        : {:.1} GiB ({:.1}%)\n", used_gb, pct));
            } else {
                output.push_str("  Used        : (unknown)\n");
            }
            
            if let Some(free) = system.mem_free_bytes {
                let free_gb = free as f64 / 1024.0 / 1024.0 / 1024.0;
                output.push_str(&format!("  Free        : {:.1} GiB\n", free_gb));
            } else {
                output.push_str("  Free        : (unknown)\n");
            }
            
            if let Some(available) = system.mem_available_bytes {
                let available_gb = available as f64 / 1024.0 / 1024.0 / 1024.0;
                output.push_str(&format!("  Available   : {:.1} GiB\n", available_gb));
            } else {
                output.push_str("  Available   : (unknown)\n");
            }
            
            if let Some(buffers) = system.buffers_bytes {
                let buffers_gb = buffers as f64 / 1024.0 / 1024.0 / 1024.0;
                output.push_str(&format!("  Buffers     : {:.1} GiB\n", buffers_gb));
            } else {
                output.push_str("  Buffers     : (unknown)\n");
            }
            
            if let Some(cached) = system.cached_bytes {
                let cached_gb = cached as f64 / 1024.0 / 1024.0 / 1024.0;
                output.push_str(&format!("  Cached      : {:.1} GiB\n\n", cached_gb));
            } else {
                output.push_str("  Cached      : (unknown)\n\n");
            }

            // Swap
            output.push_str("Swap:\n");
            
            if let Some(total) = system.swap_total_bytes {
                let total_gb = total as f64 / 1024.0 / 1024.0 / 1024.0;
                output.push_str(&format!("  Total       : {:.1} GiB\n", total_gb));
            } else {
                output.push_str("  Total       : (unknown)\n");
            }
            
            if let (Some(used), Some(pct)) = (system.swap_used_bytes, system.swap_used_pct) {
                let used_gb = used as f64 / 1024.0 / 1024.0 / 1024.0;
                output.push_str(&format!("  Used        : {:.1} GiB ({:.1}%)\n", used_gb, pct));
            } else {
                output.push_str("  Used        : (unknown)\n");
            }
            
            if let Some(free) = system.swap_free_bytes {
                let free_gb = free as f64 / 1024.0 / 1024.0 / 1024.0;
                output.push_str(&format!("  Free        : {:.1} GiB\n\n", free_gb));
            } else {
                output.push_str("  Free        : (unknown)\n\n");
            }
        }

        // Cgroup Memory
        if let Some(cgroup) = &response.cgroup {
            output.push_str("Cgroup:\n");
            
            if cgroup.available {
                output.push_str("  Available   : yes\n");
                
                if let Some(limit) = cgroup.memory_limit_bytes {
                    let limit_gb = limit as f64 / 1024.0 / 1024.0 / 1024.0;
                    output.push_str(&format!("  Limit       : {:.1} GiB\n", limit_gb));
                } else {
                    output.push_str("  Limit       : unlimited\n");
                }
                
                if let (Some(used), Some(pct)) = (cgroup.memory_usage_bytes, cgroup.memory_used_pct) {
                    let used_gb = used as f64 / 1024.0 / 1024.0 / 1024.0;
                    output.push_str(&format!("  Used        : {:.1} GiB ({:.1}%)\n\n", used_gb, pct));
                } else {
                    output.push_str("  Used        : (unknown)\n\n");
                }
            } else {
                output.push_str("  Available   : no\n\n");
            }
        }

        // Hugepages
        if let Some(hugepages) = &response.hugepages {
            output.push_str("Hugepages:\n");
            
            if hugepages.available {
                if let Some(total) = hugepages.total {
                    output.push_str(&format!("  Total       : {}\n", total));
                } else {
                    output.push_str("  Total       : 0\n");
                }
                
                if let Some(free) = hugepages.free {
                    output.push_str(&format!("  Free        : {}\n", free));
                } else {
                    output.push_str("  Free        : 0\n");
                }
                
                if let Some(page_bytes) = hugepages.page_bytes {
                    let page_mb = page_bytes as f64 / 1024.0 / 1024.0;
                    output.push_str(&format!("  Page Size   : {:.1} MiB\n\n", page_mb));
                } else {
                    output.push_str("  Page Size   : (unknown)\n\n");
                }
            } else {
                output.push_str("  Available   : no\n\n");
            }
        }

        // Warnings
        output.push_str("Warnings:\n");
        if response.warnings.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for warning in &response.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        }

        Ok(output)
    }

    fn parse_options(&self, args: &Args) -> Result<SystemInfoOptions> {
        if let Some(input) = args.get("input") {
            serde_json::from_str(input)
                .map_err(|e| SystemError::InvalidParameter(format!("invalid JSON: {}", e)).into())
        } else {
            Ok(SystemInfoOptions::default())
        }
    }

    pub fn validate_options(&self, opts: &SystemInfoOptions) -> Result<(), SystemError> {
        // Validate scopes
        let valid_scopes = [
            "os", "kernel", "cpu", "memory", "load",
            "disk", "process", "pressure", "cgroup", "virtualization"
        ];

        for scope in &opts.scopes {
            if !valid_scopes.contains(&scope.as_str()) {
                return Err(SystemError::InvalidScope(scope.clone()));
            }
        }

        // Validate format
        if opts.format != "json" && opts.format != "text" {
            return Err(SystemError::InvalidParameter(
                format!("format must be 'json' or 'text', got '{}'", opts.format)
            ));
        }

        // Validate sample_duration_ms
        if opts.sample_duration_ms > 0 && opts.sample_duration_ms < opts.sample_min_ms {
            return Err(SystemError::InvalidParameter(
                format!("sample_duration_ms ({}) must be >= sample_min_ms ({})",
                    opts.sample_duration_ms, opts.sample_min_ms)
            ));
        }

        Ok(())
    }

    pub fn collect_info(
        &self,
        opts: &SystemInfoOptions,
        provider: &dyn SystemProvider
    ) -> Result<SystemInfoResponse> {
        let timestamp_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let mut response = SystemInfoResponse {
            ok: true,
            timestamp_unix_ms,
            scopes: opts.scopes.clone(),
            os: None,
            kernel: None,
            cpu: None,
            memory: None,
            load: None,
            disk: None,
            process: None,
            pressure: None,
            cgroup: None,
            virtualization: None,
            error: None,
            warnings: Vec::new(),
        };

        // Collect each requested scope
        for scope in &opts.scopes {
            match scope.as_str() {
                "os" => response.os = Some(self.collect_os_scope(provider, &mut response.warnings)),
                "kernel" => response.kernel = Some(self.collect_kernel_scope(provider, &mut response.warnings)),
                "cpu" => response.cpu = Some(self.collect_cpu_scope(opts, provider, &mut response.warnings)),
                "memory" => response.memory = Some(self.collect_memory_scope(provider, &mut response.warnings)),
                "load" => response.load = Some(self.collect_load_scope(provider, &mut response.warnings)),
                "disk" => response.disk = Some(self.collect_disk_scope(opts, provider, &mut response.warnings)),
                "process" => response.process = Some(self.collect_process_scope(provider, &mut response.warnings)),
                "pressure" => response.pressure = Some(self.collect_pressure_scope(provider, &mut response.warnings)),
                "cgroup" => response.cgroup = Some(self.collect_cgroup_scope(provider, &mut response.warnings)),
                "virtualization" => response.virtualization = Some(self.collect_virtualization_scope(provider, &mut response.warnings)),
                _ => {
                    response.warnings.push(format!("unknown scope: {}", scope));
                }
            }
        }

        // Apply field filtering if requested
        if let Some(fields) = &opts.fields {
            self.apply_field_filter(&mut response, fields);
        }

        Ok(response)
    }

    fn collect_os_scope(&self, provider: &dyn SystemProvider, warnings: &mut Vec<String>) -> Value {
        let mut available = true;
        let mut name = String::from("Unknown");
        let mut distribution = None;
        let mut distribution_version = None;
        let mut hostname = String::from("unknown");
        let mut architecture = String::from("unknown");

        // Get uname info
        if let Ok((sysname, _, _, machine)) = provider.get_uname() {
            name = sysname;
            architecture = machine;
        } else {
            available = false;
            warnings.push("Failed to get uname information".to_string());
        }

        // Get hostname
        if let Ok(h) = provider.get_hostname() {
            hostname = h;
        }

        // Parse /etc/os-release for distribution info
        if let Ok(content) = provider.read_os_release() {
            for line in content.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    let value = value.trim_matches('"');
                    match key {
                        "NAME" => distribution = Some(value.to_string()),
                        "VERSION_ID" => distribution_version = Some(value.to_string()),
                        _ => {}
                    }
                }
            }
        }

        json!({
            "available": available,
            "name": name,
            "distribution": distribution,
            "distribution_version": distribution_version,
            "hostname": hostname,
            "architecture": architecture,
        })
    }

    fn collect_kernel_scope(&self, provider: &dyn SystemProvider, warnings: &mut Vec<String>) -> Value {
        let mut available = true;
        let mut release = String::from("unknown");
        let mut version = String::from("unknown");
        let mut machine = String::from("unknown");
        let mut boot_time_unix: Option<i64> = None;
        let mut uptime_seconds: Option<f64> = None;

        // Get uname info
        if let Ok((_, rel, ver, mach)) = provider.get_uname() {
            release = rel;
            version = ver;
            machine = mach;
        } else {
            available = false;
            warnings.push("Failed to get kernel uname information".to_string());
        }

        // Get boot time from /proc/stat
        if let Ok(content) = provider.read_proc_stat() {
            for line in content.lines() {
                if line.starts_with("btime ") {
                    if let Some(btime_str) = line.split_whitespace().nth(1) {
                        if let Ok(btime) = btime_str.parse::<i64>() {
                            boot_time_unix = Some(btime);
                        }
                    }
                }
            }
        }

        // Get uptime from /proc/uptime
        if let Ok(content) = provider.read_proc_uptime() {
            if let Some(uptime_str) = content.split_whitespace().next() {
                if let Ok(uptime) = uptime_str.parse::<f64>() {
                    uptime_seconds = Some(uptime);
                }
            }
        } else {
            warnings.push("Failed to read /proc/uptime".to_string());
        }

        json!({
            "available": available,
            "release": release,
            "version": version,
            "machine": machine,
            "boot_time_unix": boot_time_unix,
            "uptime_seconds": uptime_seconds,
        })
    }

    fn collect_cpu_scope(
        &self,
        opts: &SystemInfoOptions,
        provider: &dyn SystemProvider,
        warnings: &mut Vec<String>
    ) -> Value {
        let mut available = true;
        let mut count_logical = 0;
        let count_physical: Option<u32> = None;
        let mut online_logical = 0;
        let mut utilization_pct: Option<f64> = None;
        let mut per_cpu: Vec<Value> = Vec::new();

        // Count CPUs from /proc/stat
        if let Ok(content) = provider.read_proc_stat() {
            let cpu_lines: Vec<&str> = content.lines()
                .filter(|line| line.starts_with("cpu") && line.chars().nth(3).map_or(false, |c| c.is_ascii_digit()))
                .collect();

            count_logical = cpu_lines.len();
            online_logical = count_logical;

            // If sampling requested, calculate CPU utilization
            if opts.sample_duration_ms > 0 {
                let sample_duration = std::cmp::max(opts.sample_duration_ms, opts.sample_min_ms);

                if let Ok(stats1) = self.parse_cpu_stats(&content) {
                    thread::sleep(Duration::from_millis(sample_duration));

                    if let Ok(content2) = provider.read_proc_stat() {
                        if let Ok(stats2) = self.parse_cpu_stats(&content2) {
                            // Calculate total utilization
                            if let Some(total1) = stats1.get("cpu") {
                                if let Some(total2) = stats2.get("cpu") {
                                    utilization_pct = Some(self.calculate_cpu_usage(total1, total2));
                                }
                            }

                            // Calculate per-CPU utilization if requested
                            if opts.per_cpu {
                                for i in 0..count_logical {
                                    let cpu_key = format!("cpu{}", i);
                                    if let (Some(cpu1), Some(cpu2)) = (stats1.get(&cpu_key), stats2.get(&cpu_key)) {
                                        let util = self.calculate_cpu_usage(cpu1, cpu2);
                                        per_cpu.push(json!({
                                            "id": i,
                                            "utilization_pct": util,
                                        }));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            available = false;
            warnings.push("Failed to read /proc/stat for CPU info".to_string());
        }

        let mut result = json!({
            "available": available,
            "count_logical": count_logical,
            "count_physical": count_physical,
            "online_logical": online_logical,
            "utilization_pct": utilization_pct,
        });

        if opts.per_cpu && !per_cpu.is_empty() {
            result["per_cpu"] = json!(per_cpu);
        }

        result
    }

    fn parse_cpu_stats(&self, content: &str) -> Result<HashMap<String, Vec<u64>>> {
        let mut stats = HashMap::new();

        for line in content.lines() {
            if line.starts_with("cpu") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    let cpu_name = parts[0].to_string();
                    let values: Vec<u64> = parts[1..]
                        .iter()
                        .filter_map(|s| s.parse::<u64>().ok())
                        .collect();
                    if !values.is_empty() {
                        stats.insert(cpu_name, values);
                    }
                }
            }
        }

        Ok(stats)
    }

    fn calculate_cpu_usage(&self, stats1: &[u64], stats2: &[u64]) -> f64 {
        if stats1.len() < 4 || stats2.len() < 4 {
            return 0.0;
        }

        let idle1 = stats1.get(3).unwrap_or(&0);
        let idle2 = stats2.get(3).unwrap_or(&0);

        let total1: u64 = stats1.iter().sum();
        let total2: u64 = stats2.iter().sum();

        let total_diff = total2.saturating_sub(total1) as f64;
        let idle_diff = idle2.saturating_sub(*idle1) as f64;

        if total_diff == 0.0 {
            return 0.0;
        }

        let usage = ((total_diff - idle_diff) / total_diff) * 100.0;
        usage.max(0.0).min(100.0)
    }

    fn collect_memory_scope(&self, provider: &dyn SystemProvider, warnings: &mut Vec<String>) -> Value {
        let mut available = true;
        let mut mem_total_bytes: u64 = 0;
        let mut mem_free_bytes: u64 = 0;
        let mut mem_available_bytes: u64 = 0;
        let mut buffers_bytes: u64 = 0;
        let mut cached_bytes: u64 = 0;
        let mut swap_total_bytes: u64 = 0;
        let mut swap_free_bytes: u64 = 0;

        if let Ok(content) = provider.read_proc_meminfo() {
            for line in content.lines() {
                if let Some((key, value)) = line.split_once(':') {
                    let value = value.trim().split_whitespace().next().unwrap_or("0");
                    if let Ok(kb) = value.parse::<u64>() {
                        let bytes = kb * 1024;
                        match key {
                            "MemTotal" => mem_total_bytes = bytes,
                            "MemFree" => mem_free_bytes = bytes,
                            "MemAvailable" => mem_available_bytes = bytes,
                            "Buffers" => buffers_bytes = bytes,
                            "Cached" => cached_bytes = bytes,
                            "SwapTotal" => swap_total_bytes = bytes,
                            "SwapFree" => swap_free_bytes = bytes,
                            _ => {}
                        }
                    }
                }
            }
        } else {
            available = false;
            warnings.push("Failed to read /proc/meminfo".to_string());
        }

        let usage_pct = if mem_total_bytes > 0 {
            ((mem_total_bytes - mem_available_bytes) as f64 / mem_total_bytes as f64) * 100.0
        } else {
            0.0
        };

        json!({
            "available": available,
            "mem_total_bytes": mem_total_bytes,
            "mem_free_bytes": mem_free_bytes,
            "mem_available_bytes": mem_available_bytes,
            "buffers_bytes": buffers_bytes,
            "cached_bytes": cached_bytes,
            "swap_total_bytes": swap_total_bytes,
            "swap_free_bytes": swap_free_bytes,
            "usage_pct": usage_pct,
        })
    }

    fn collect_load_scope(&self, provider: &dyn SystemProvider, warnings: &mut Vec<String>) -> Value {
        let mut available = true;
        let mut load_1m = 0.0;
        let mut load_5m = 0.0;
        let mut load_15m = 0.0;
        let mut runnable_processes = 0;
        let mut total_processes = 0;

        if let Ok(content) = provider.read_proc_loadavg() {
            let parts: Vec<&str> = content.split_whitespace().collect();

            if parts.len() >= 5 {
                load_1m = parts[0].parse::<f64>().unwrap_or(0.0);
                load_5m = parts[1].parse::<f64>().unwrap_or(0.0);
                load_15m = parts[2].parse::<f64>().unwrap_or(0.0);

                // Parse "runnable/total" field
                if let Some((runnable, total)) = parts[3].split_once('/') {
                    runnable_processes = runnable.parse::<u32>().unwrap_or(0);
                    total_processes = total.parse::<u32>().unwrap_or(0);
                }
            }
        } else {
            available = false;
            warnings.push("Failed to read /proc/loadavg".to_string());
        }

        json!({
            "available": available,
            "load_1m": load_1m,
            "load_5m": load_5m,
            "load_15m": load_15m,
            "runnable_processes": runnable_processes,
            "total_processes": total_processes,
        })
    }

    fn collect_disk_scope(
        &self,
        opts: &SystemInfoOptions,
        provider: &dyn SystemProvider,
        warnings: &mut Vec<String>
    ) -> Value {
        let mut available = true;
        let mut mounts_truncated = false;
        let mut mounts_data = Vec::new();

        if let Ok(mounts) = provider.list_mounts() {
            // Filter to important mount points
            let priority_mounts = ["/", "/home", "/var", "/data", "/boot", "/tmp"];
            let mut selected_mounts = Vec::new();

            // Add priority mounts first
            for (device, mount_point, fs_type) in &mounts {
                if priority_mounts.contains(&mount_point.as_str()) {
                    selected_mounts.push((device.clone(), mount_point.clone(), fs_type.clone()));
                }
            }

            // Add other mounts up to limit
            for (device, mount_point, fs_type) in &mounts {
                if !priority_mounts.contains(&mount_point.as_str())
                    && selected_mounts.len() < opts.max_mounts as usize {
                    selected_mounts.push((device.clone(), mount_point.clone(), fs_type.clone()));
                }
            }

            if mounts.len() > opts.max_mounts as usize {
                mounts_truncated = true;
                warnings.push(format!(
                    "Mount list truncated: {} mounts available, showing {}",
                    mounts.len(), opts.max_mounts
                ));
            }

            // Get stats for each mount
            for (device, mount_point, fs_type) in selected_mounts {
                if let Ok((total_bytes, used_bytes, free_bytes)) = provider.get_disk_stats(&mount_point) {
                    let usage_pct = if total_bytes > 0 {
                        (used_bytes as f64 / total_bytes as f64) * 100.0
                    } else {
                        0.0
                    };

                    mounts_data.push(json!({
                        "mount_point": mount_point,
                        "fs_type": fs_type,
                        "device": device,
                        "total_bytes": total_bytes,
                        "used_bytes": used_bytes,
                        "free_bytes": free_bytes,
                        "usage_pct": usage_pct,
                    }));
                }
            }
        } else {
            available = false;
            warnings.push("Failed to read mount information".to_string());
        }

        json!({
            "available": available,
            "mounts_truncated": mounts_truncated,
            "mounts": mounts_data,
        })
    }

    fn collect_process_scope(&self, provider: &dyn SystemProvider, warnings: &mut Vec<String>) -> Value {
        let available = true;
        let mut total_processes = 0;
        let mut running = 0;
        let mut sleeping = 0;
        let mut zombie = 0;
        let mut stopped = 0;
        let mut blocked = 0;

        // Try to count from /proc/stat first
        if let Ok(content) = provider.read_proc_stat() {
            for line in content.lines() {
                if line.starts_with("processes ") {
                    if let Some(count_str) = line.split_whitespace().nth(1) {
                        total_processes = count_str.parse::<u32>().unwrap_or(0);
                    }
                }
                if line.starts_with("procs_running ") {
                    if let Some(count_str) = line.split_whitespace().nth(1) {
                        running = count_str.parse::<u32>().unwrap_or(0);
                    }
                }
                if line.starts_with("procs_blocked ") {
                    if let Some(count_str) = line.split_whitespace().nth(1) {
                        blocked = count_str.parse::<u32>().unwrap_or(0);
                    }
                }
            }
        }

        // Try to enumerate /proc for more detailed stats
        if let Ok(entries) = std::fs::read_dir("/proc") {
            let mut proc_count = 0;
            let mut state_counts: HashMap<char, u32> = HashMap::new();

            for entry in entries.flatten() {
                if let Ok(file_name) = entry.file_name().into_string() {
                    if file_name.chars().all(|c| c.is_ascii_digit()) {
                        proc_count += 1;

                        // Try to read process state
                        let stat_path = format!("/proc/{}/stat", file_name);
                        if let Ok(content) = fs::read_to_string(&stat_path) {
                            // State is the 3rd field after the command name in parentheses
                            if let Some(state_start) = content.rfind(')') {
                                let after_name = &content[state_start+1..];
                                if let Some(state_char) = after_name.trim().chars().next() {
                                    *state_counts.entry(state_char).or_insert(0) += 1;
                                }
                            }
                        }
                    }
                }
            }

            if proc_count > 0 {
                total_processes = proc_count;
                running = *state_counts.get(&'R').unwrap_or(&0);
                sleeping = *state_counts.get(&'S').unwrap_or(&0) + *state_counts.get(&'I').unwrap_or(&0);
                zombie = *state_counts.get(&'Z').unwrap_or(&0);
                stopped = *state_counts.get(&'T').unwrap_or(&0);
                blocked = *state_counts.get(&'D').unwrap_or(&0);
            }
        } else {
            warnings.push("Could not enumerate /proc for detailed process info".to_string());
        }

        json!({
            "available": available,
            "total_processes": total_processes,
            "running": running,
            "sleeping": sleeping,
            "zombie": zombie,
            "stopped": stopped,
            "blocked": blocked,
        })
    }

    fn collect_pressure_scope(&self, provider: &dyn SystemProvider, warnings: &mut Vec<String>) -> Value {
        let mut available = false;
        let mut cpu_pressure = None;
        let mut io_pressure = None;
        let mut memory_pressure = None;

        // Try to read /proc/pressure/* files
        if let Ok(content) = provider.read_file("/proc/pressure/cpu") {
            available = true;
            cpu_pressure = Some(self.parse_pressure_file(&content));
        }

        if let Ok(content) = provider.read_file("/proc/pressure/io") {
            available = true;
            io_pressure = Some(self.parse_pressure_file(&content));
        }

        if let Ok(content) = provider.read_file("/proc/pressure/memory") {
            available = true;
            memory_pressure = Some(self.parse_pressure_file(&content));
        }

        if !available {
            warnings.push("PSI (Pressure Stall Information) not available on this system".to_string());
        }

        json!({
            "available": available,
            "cpu": cpu_pressure,
            "io": io_pressure,
            "memory": memory_pressure,
        })
    }

    fn parse_pressure_file(&self, content: &str) -> Value {
        let mut some_avg10 = 0.0;
        let mut some_avg60 = 0.0;
        let mut some_avg300 = 0.0;
        let mut full_avg10 = None;
        let mut full_avg60 = None;
        let mut full_avg300 = None;

        for line in content.lines() {
            if line.starts_with("some ") {
                for part in line.split_whitespace().skip(1) {
                    if let Some((key, value)) = part.split_once('=') {
                        if let Ok(val) = value.parse::<f64>() {
                            match key {
                                "avg10" => some_avg10 = val,
                                "avg60" => some_avg60 = val,
                                "avg300" => some_avg300 = val,
                                _ => {}
                            }
                        }
                    }
                }
            } else if line.starts_with("full ") {
                let mut avg10 = 0.0;
                let mut avg60 = 0.0;
                let mut avg300 = 0.0;

                for part in line.split_whitespace().skip(1) {
                    if let Some((key, value)) = part.split_once('=') {
                        if let Ok(val) = value.parse::<f64>() {
                            match key {
                                "avg10" => avg10 = val,
                                "avg60" => avg60 = val,
                                "avg300" => avg300 = val,
                                _ => {}
                            }
                        }
                    }
                }

                full_avg10 = Some(avg10);
                full_avg60 = Some(avg60);
                full_avg300 = Some(avg300);
            }
        }

        let mut result = json!({
            "some_avg10": some_avg10,
            "some_avg60": some_avg60,
            "some_avg300": some_avg300,
        });

        if let Some(val) = full_avg10 {
            result["full_avg10"] = json!(val);
            result["full_avg60"] = json!(full_avg60);
            result["full_avg300"] = json!(full_avg300);
        }

        result
    }

    fn collect_cgroup_scope(&self, provider: &dyn SystemProvider, warnings: &mut Vec<String>) -> Value {
        let mut available = false;
        let mut unified = false;
        let mut paths: HashMap<String, String> = HashMap::new();
        let mut limits = json!({});

        // Check if cgroup v2 (unified) is being used
        if let Ok(content) = provider.read_file("/proc/self/cgroup") {
            available = true;

            for line in content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 {
                    if parts[0] == "0" {
                        // cgroup v2 (unified hierarchy)
                        unified = true;
                        let cgroup_path = parts[2];

                        // Try to find cgroup files
                        let base_path = format!("/sys/fs/cgroup{}", cgroup_path);

                        if let Ok(_) = fs::metadata(&base_path) {
                            paths.insert("base".to_string(), base_path.clone());

                            // Try to read CPU limits
                            let cpu_max_path = format!("{}/cpu.max", base_path);
                            if let Ok(content) = fs::read_to_string(&cpu_max_path) {
                                paths.insert("cpu".to_string(), cpu_max_path);

                                let parts: Vec<&str> = content.trim().split_whitespace().collect();
                                if parts.len() >= 2 {
                                    if let (Ok(quota), Ok(period)) = (
                                        parts[0].parse::<i64>(),
                                        parts[1].parse::<i64>()
                                    ) {
                                        if quota > 0 && period > 0 {
                                            let cpu_quota_pct = (quota as f64 / period as f64) * 100.0;
                                            limits["cpu_quota_pct"] = json!(cpu_quota_pct);
                                        }
                                    }
                                }
                            }

                            // Try to read memory limits
                            let mem_max_path = format!("{}/memory.max", base_path);
                            if let Ok(content) = fs::read_to_string(&mem_max_path) {
                                paths.insert("memory".to_string(), mem_max_path);

                                if let Ok(limit) = content.trim().parse::<u64>() {
                                    limits["memory_limit_bytes"] = json!(limit);
                                }
                            }
                        }
                    }
                }
            }
        } else {
            warnings.push("Could not read /proc/self/cgroup".to_string());
        }

        json!({
            "available": available,
            "unified": unified,
            "paths": paths,
            "limits": limits,
        })
    }

    fn collect_virtualization_scope(&self, provider: &dyn SystemProvider, _warnings: &mut Vec<String>) -> Value {
        let mut available = false;
        let mut is_container = false;
        let mut container_type: Option<String> = None;
        let mut is_virtual_machine = false;
        let mut hypervisor_type: Option<String> = None;

        // Check for container
        if let Ok(_) = fs::metadata("/.dockerenv") {
            available = true;
            is_container = true;
            container_type = Some("docker".to_string());
        }

        // Check /proc/1/cgroup for container hints
        if let Ok(content) = provider.read_file("/proc/1/cgroup") {
            available = true;
            if content.contains("docker") {
                is_container = true;
                container_type = Some("docker".to_string());
            } else if content.contains("lxc") {
                is_container = true;
                container_type = Some("lxc".to_string());
            } else if content.contains("kubepods") {
                is_container = true;
                container_type = Some("kubernetes".to_string());
            }
        }

        // Check for virtualization via /sys/class/dmi/id/product_name
        if let Ok(content) = provider.read_file("/sys/class/dmi/id/product_name") {
            available = true;
            let product = content.trim().to_lowercase();

            if product.contains("virtualbox") {
                is_virtual_machine = true;
                hypervisor_type = Some("virtualbox".to_string());
            } else if product.contains("vmware") {
                is_virtual_machine = true;
                hypervisor_type = Some("vmware".to_string());
            } else if product.contains("kvm") {
                is_virtual_machine = true;
                hypervisor_type = Some("kvm".to_string());
            } else if product.contains("qemu") {
                is_virtual_machine = true;
                hypervisor_type = Some("qemu".to_string());
            }
        }

        // Check /proc/cpuinfo for hypervisor flag
        if let Ok(content) = provider.read_file("/proc/cpuinfo") {
            if content.contains("hypervisor") && !is_virtual_machine {
                is_virtual_machine = true;
                hypervisor_type = Some("unknown".to_string());
            }
        }

        json!({
            "available": available,
            "is_container": is_container,
            "container_type": container_type,
            "is_virtual_machine": is_virtual_machine,
            "hypervisor_type": hypervisor_type,
        })
    }

    fn apply_field_filter(&self, response: &mut SystemInfoResponse, _fields: &[String]) {
        // This is a simplified field filter - a full implementation would
        // recursively traverse and filter JSON objects
        // For now, we'll just note that field filtering was requested
        response.warnings.push("Field filtering is not yet fully implemented".to_string());
    }

    pub fn format_text(&self, response: &SystemInfoResponse, _opts: &SystemInfoOptions) -> Result<String> {
        let mut output = String::new();

        output.push_str("System Info\n");
        output.push_str("===========\n\n");

        // Format timestamp
        let timestamp_secs = response.timestamp_unix_ms / 1000;
        let dt = chrono::DateTime::from_timestamp(timestamp_secs, 0)
            .unwrap_or_else(|| chrono::DateTime::UNIX_EPOCH);
        output.push_str(&format!("Timestamp: {}\n\n", dt.format("%Y-%m-%d %H:%M:%S UTC")));

        // OS scope
        if let Some(os) = &response.os {
            output.push_str("OS:\n");
            if let Some(name) = os.get("name").and_then(|v| v.as_str()) {
                output.push_str(&format!("  Name        : {}\n", name));
            }
            if let Some(distro) = os.get("distribution").and_then(|v| v.as_str()) {
                if let Some(version) = os.get("distribution_version").and_then(|v| v.as_str()) {
                    output.push_str(&format!("  Distro      : {} {}\n", distro, version));
                } else {
                    output.push_str(&format!("  Distro      : {}\n", distro));
                }
            }
            if let Some(hostname) = os.get("hostname").and_then(|v| v.as_str()) {
                output.push_str(&format!("  Hostname    : {}\n", hostname));
            }
            if let Some(arch) = os.get("architecture").and_then(|v| v.as_str()) {
                output.push_str(&format!("  Arch        : {}\n", arch));
            }
            output.push('\n');
        }

        // Kernel scope
        if let Some(kernel) = &response.kernel {
            output.push_str("Kernel:\n");
            if let Some(release) = kernel.get("release").and_then(|v| v.as_str()) {
                output.push_str(&format!("  Release     : {}\n", release));
            }
            if let Some(uptime) = kernel.get("uptime_seconds").and_then(|v| v.as_f64()) {
                let days = (uptime / 86400.0) as u64;
                let hours = ((uptime % 86400.0) / 3600.0) as u64;
                let minutes = ((uptime % 3600.0) / 60.0) as u64;
                output.push_str(&format!("  Uptime      : {}d {}h {}m\n", days, hours, minutes));
            }
            output.push('\n');
        }

        // CPU scope
        if let Some(cpu) = &response.cpu {
            output.push_str("CPU:\n");
            if let Some(count) = cpu.get("count_logical").and_then(|v| v.as_u64()) {
                output.push_str(&format!("  Logical     : {}\n", count));
            }
            if let Some(count) = cpu.get("count_physical").and_then(|v| v.as_u64()) {
                output.push_str(&format!("  Physical    : {}\n", count));
            }
            if let Some(util) = cpu.get("utilization_pct").and_then(|v| v.as_f64()) {
                output.push_str(&format!("  Utilization : {:.1}%\n", util));
            }
            output.push('\n');
        }

        // Memory scope
        if let Some(memory) = &response.memory {
            output.push_str("Memory:\n");
            if let Some(total) = memory.get("mem_total_bytes").and_then(|v| v.as_u64()) {
                let total_gb = total as f64 / 1_073_741_824.0;
                output.push_str(&format!("  Total       : {:.1} GiB\n", total_gb));
            }
            if let Some(avail) = memory.get("mem_available_bytes").and_then(|v| v.as_u64()) {
                let avail_gb = avail as f64 / 1_073_741_824.0;
                output.push_str(&format!("  Available   : {:.1} GiB\n", avail_gb));
            }
            if let Some(usage) = memory.get("usage_pct").and_then(|v| v.as_f64()) {
                output.push_str(&format!("  Used        : {:.1}%\n", usage));
            }
            if let Some(swap_total) = memory.get("swap_total_bytes").and_then(|v| v.as_u64()) {
                if let Some(swap_free) = memory.get("swap_free_bytes").and_then(|v| v.as_u64()) {
                    let swap_total_gb = swap_total as f64 / 1_073_741_824.0;
                    let swap_free_gb = swap_free as f64 / 1_073_741_824.0;
                    output.push_str(&format!("  Swap        : {:.1} GiB total, {:.1} GiB free\n",
                        swap_total_gb, swap_free_gb));
                }
            }
            output.push('\n');
        }

        // Load scope
        if let Some(load) = &response.load {
            output.push_str("Load:\n");
            if let Some(load_1m) = load.get("load_1m").and_then(|v| v.as_f64()) {
                output.push_str(&format!("  1m          : {:.2}\n", load_1m));
            }
            if let Some(load_5m) = load.get("load_5m").and_then(|v| v.as_f64()) {
                output.push_str(&format!("  5m          : {:.2}\n", load_5m));
            }
            if let Some(load_15m) = load.get("load_15m").and_then(|v| v.as_f64()) {
                output.push_str(&format!("  15m         : {:.2}\n", load_15m));
            }
            output.push('\n');
        }

        // Disk scope
        if let Some(disk) = &response.disk {
            if let Some(mounts) = disk.get("mounts").and_then(|v| v.as_array()) {
                if !mounts.is_empty() {
                    output.push_str("Disk:\n");
                    for mount in mounts {
                        if let Some(mount_point) = mount.get("mount_point").and_then(|v| v.as_str()) {
                            output.push_str(&format!("  {}\n", mount_point));

                            if let Some(total) = mount.get("total_bytes").and_then(|v| v.as_u64()) {
                                let total_gb = total as f64 / 1_073_741_824.0;
                                output.push_str(&format!("    Total   : {:.1} GiB\n", total_gb));
                            }
                            if let Some(usage) = mount.get("usage_pct").and_then(|v| v.as_f64()) {
                                output.push_str(&format!("    Used    : {:.1}%\n", usage));
                            }
                        }
                    }
                    output.push('\n');
                }
            }
        }

        // Warnings
        if !response.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &response.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        } else {
            output.push_str("Warnings:\n  (none)\n");
        }

        Ok(output)
    }
}

// ===========================================================================
// Handle Trait Implementation
// ===========================================================================

impl Handle for SystemHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["info", "uptime", "load", "memory", "cpu", "disk", "env.list"]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        match verb {
            "info" => self.info_verb(args, io),
            "uptime" => self.uptime_verb(args, io),
            "load" => self.load_verb(args, io),
            "memory" => self.memory_verb(args, io),
            "cpu" => self.cpu_verb(args, io),
            "disk" => self.disk_verb(args, io),
            "env.list" => self.env_list_verb(args, io),
            _ => bail!("unknown verb for system://: {}", verb),
        }
    }
}

// ===========================================================================
// Registration
// ===========================================================================

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("system", |u| Ok(Box::new(SystemHandle::from_url(u)?)));
}
