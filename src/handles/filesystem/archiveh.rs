use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::{File, create_dir_all};
use std::io::{Write, Read, BufWriter, copy};
use std::path::{Path, PathBuf, Component};
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use url::Url;
use walkdir::WalkDir;
use globset::{Glob, GlobSetBuilder};
use chrono::{DateTime, Utc};

use crate::core::{
    registry::{Args, Handle, IoStreams},
    status::Status,
};

// Archive format imports
use zip::write::{FileOptions, ZipWriter};
use zip::{CompressionMethod, ZipArchive};
use flate2::Compression;
use flate2::write::GzEncoder;
use flate2::read::GzDecoder;
use tar::Archive;
use xz2::read::XzDecoder;
use xz2::write::XzEncoder;
use zstd::stream::read::Decoder as ZstdDecoder;
use zstd::stream::write::Encoder as ZstdEncoder;

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("archive", |u| Ok(Box::new(ArchiveHandle::from_url(u)?)));
}

pub struct ArchiveHandle {
    _url: Url,
}

impl ArchiveHandle {
    pub fn from_url(url: &Url) -> Result<Self> {
        Ok(ArchiveHandle {
            _url: url.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ArchiveFormat {
    Auto,
    Tar,
    TarGz, 
    TarXz,
    TarZstd,
    Zip,
    SevenZ,
    Gzip,
    Raw,
}

impl ArchiveFormat {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "tar" => Ok(Self::Tar),
            "tar.gz" | "tgz" => Ok(Self::TarGz),
            "tar.xz" | "txz" => Ok(Self::TarXz),
            "tar.zst" | "tar.zstd" => Ok(Self::TarZstd),
            "zip" => Ok(Self::Zip),
            "7z" => Ok(Self::SevenZ),
            "gzip" | "gz" => Ok(Self::Gzip),
            "raw" => Ok(Self::Raw),
            _ => bail!("Unsupported archive format: {}", s),
        }
    }

    pub fn detect_from_extension(path: &str) -> Result<Self> {
        let path = path.to_lowercase();
        if path.ends_with(".tar.gz") || path.ends_with(".tgz") {
            Ok(Self::TarGz)
        } else if path.ends_with(".tar.xz") || path.ends_with(".txz") {
            Ok(Self::TarXz)
        } else if path.ends_with(".tar.zst") || path.ends_with(".tar.zstd") {
            Ok(Self::TarZstd)
        } else if path.ends_with(".tar") {
            Ok(Self::Tar)
        } else if path.ends_with(".zip") {
            Ok(Self::Zip)
        } else if path.ends_with(".7z") {
            Ok(Self::SevenZ)
        } else if path.ends_with(".gz") && !path.contains(".tar") {
            Ok(Self::Raw)
        } else if path.ends_with(".xz") && !path.contains(".tar") {
            Ok(Self::Raw)
        } else if (path.ends_with(".zst") || path.ends_with(".zstd")) && !path.contains(".tar") {
            Ok(Self::Raw)
        } else {
            bail!("Cannot detect archive format from extension: {}", path)
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Tar => "tar",
            Self::TarGz => "tar.gz",
            Self::TarXz => "tar.xz", 
            Self::TarZstd => "tar.zstd",
            Self::Zip => "zip",
            Self::SevenZ => "7z",
            Self::Gzip => "gzip",
            Self::Raw => "raw",
        }
    }

    pub fn supports_compression_level(&self) -> bool {
        matches!(self, Self::TarGz | Self::TarXz | Self::TarZstd | Self::Zip | Self::SevenZ | Self::Gzip | Self::Raw)
    }

    pub fn supports_password(&self) -> bool {
        matches!(self, Self::Zip | Self::SevenZ)
    }

    pub fn default_compression_level(&self) -> u32 {
        match self {
            Self::TarGz | Self::Zip | Self::Gzip | Self::Raw => 6,
            Self::TarXz => 6,
            Self::TarZstd => 3,
            Self::SevenZ => 5,
            _ => 0,
        }
    }

    pub fn max_compression_level(&self) -> u32 {
        match self {
            Self::TarGz | Self::Zip | Self::SevenZ | Self::Gzip | Self::Raw => 9,
            Self::TarXz => 9,
            Self::TarZstd => 22,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CompressionKind {
    Auto,
    None,
    Gzip,
    Xz,
    Zstd,
}

impl CompressionKind {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "none" => Ok(Self::None),
            "gzip" => Ok(Self::Gzip),
            "xz" => Ok(Self::Xz),
            "zstd" => Ok(Self::Zstd),
            _ => bail!("Unsupported compression: {}", s),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::None => "none",
            Self::Gzip => "gzip",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
        }
    }

    pub fn detect_from_extension(path: &str) -> Self {
        let path = path.to_lowercase();
        if path.ends_with(".gz") {
            Self::Gzip
        } else if path.ends_with(".xz") {
            Self::Xz
        } else if path.ends_with(".zst") || path.ends_with(".zstd") {
            Self::Zstd
        } else {
            Self::None
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArchiveCreateOptions {
    pub output: String,
    pub sources: Vec<String>,
    pub base_dir: Option<String>,
    pub format: ArchiveFormat,
    pub compression_level: Option<u32>,
    pub include_patterns: Vec<String>,
    pub exclude_patterns: Vec<String>,
    pub include_hidden: bool,
    pub follow_symlinks: bool,
    pub password: Option<String>,
    pub overwrite: bool,
    pub preserve_permissions: bool,
    pub preserve_timestamps: bool,
    pub max_files: u64,
    pub max_size_mb: u64,
    pub progress: bool,
    pub output_format: OutputFormat,
}

#[derive(Debug, Clone)]
pub struct ArchiveExtractOptions {
    pub archive: String,
    pub destination: String,

    pub format: ArchiveFormat,
    pub compression: CompressionKind,

    pub includes: Vec<String>,
    pub excludes: Vec<String>,

    pub overwrite: bool,
    pub create_destination: bool,
    pub fail_on_missing_archive: bool,
    pub strip_components: u32,

    pub allow_absolute_paths: bool,
    pub allow_parent_traversal: bool,
    pub allow_symlinks: bool,
    pub follow_symlinks: bool,

    pub max_entries: u64,
    pub max_total_bytes: Option<u64>,
    pub max_file_bytes: Option<u64>,

    pub include_manifest: bool,
    pub format_output: OutputFormat,
}

#[derive(Debug, Clone)]
pub struct ArchiveListOptions {
    pub archive: String,

    pub format: ArchiveFormat,
    pub compression: CompressionKind,

    pub includes: Vec<String>,
    pub excludes: Vec<String>,

    pub max_entries: u64,
    pub max_total_bytes: Option<u64>,
    pub fail_on_missing_archive: bool,

    pub include_metadata: bool,
    pub include_compressed_size: bool,
    pub format_output: OutputFormat,
}

#[derive(Debug, Clone)]
pub struct ArchiveTestOptions {
    pub archive: String,

    pub format: ArchiveFormat,
    pub compression: CompressionKind,

    pub stop_on_first_error: bool,
    pub report_entries: bool,
    pub verify_data: bool,

    pub max_entries: u64,
    pub max_total_bytes: Option<u64>,
    pub max_file_bytes: Option<u64>,
    pub fail_on_missing_archive: bool,

    pub format_output: OutputFormat,
}

#[derive(Debug, Clone)]
pub struct ArchiveInfoOptions {
    pub archive: String,

    pub format: ArchiveFormat,
    pub compression: CompressionKind,

    pub scan_entries: bool,
    pub max_entries: u64,
    pub max_total_bytes: Option<u64>,
    pub fail_on_missing_archive: bool,

    pub format_output: OutputFormat,
}

#[derive(Debug, Clone)]
pub struct ArchiveAddOptions {
    pub archive: String,
    pub inputs: Vec<String>,

    pub format: ArchiveFormat,
    pub compression: CompressionKind,

    pub base_dir: Option<String>,
    pub includes: Vec<String>,
    pub excludes: Vec<String>,
    pub follow_symlinks: bool,

    pub overwrite: bool,
    pub keep_existing_dirs: bool,

    pub preserve_owner: bool,
    pub preserve_permissions: bool,
    pub preserve_timestamps: bool,
    pub deterministic: bool,

    pub max_entries: u64,
    pub max_total_bytes: Option<u64>,
    pub tmp_dir: Option<String>,
    pub backup_suffix: Option<String>,

    pub format_output: OutputFormat,
}

#[derive(Debug, Clone)]
pub struct ArchiveRemoveOptions {
    pub archive: String,

    pub format: ArchiveFormat,
    pub compression: CompressionKind,

    pub paths: Vec<String>,
    pub patterns: Vec<String>,
    pub dir_prefixes: Vec<String>,

    pub remove_empty_dirs: bool,
    pub dry_run: bool,

    pub max_entries: u64,
    pub max_total_bytes: Option<u64>,
    pub fail_on_missing_archive: bool,

    pub tmp_dir: Option<String>,
    pub backup_suffix: Option<String>,

    pub format_output: OutputFormat,
}

#[derive(Debug, Clone)]
pub enum OutputFormat {
    Json,
    Text,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveListEntry {
    pub path: String,
    pub is_dir: bool,
    pub is_symlink: bool,

    pub size: u64,
    pub compressed_size: Option<u64>,

    pub mode: Option<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub uname: Option<String>,
    pub gname: Option<String>,
    pub mtime_unix: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveListSummary {
    pub archive: String,
    pub format: String,
    pub compression: String,
    pub entries_total: u64,
    pub entries_listed: u64,
    pub bytes_total: u64,
    pub bytes_compressed: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveListResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub query: Value,
    pub summary: Option<ArchiveListSummary>,
    pub manifest: Option<Vec<ArchiveListEntry>>,

    pub error: Option<(String, String)>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveTestEntryResult {
    pub path: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,

    pub status: String,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveTestSummary {
    pub archive: String,
    pub format: String,
    pub compression: String,
    pub entries_tested: u64,
    pub entries_failed: u64,
    pub bytes_tested: u64,
    pub valid: bool,
    pub stopped_early: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveTestResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub query: Value,
    pub summary: Option<ArchiveTestSummary>,
    pub entries: Option<Vec<ArchiveTestEntryResult>>,

    pub error: Option<(String, String)>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveInfoSummary {
    pub archive: String,
    pub format: String,
    pub compression: String,

    pub archive_size_bytes: u64,
    pub archive_mtime_unix: Option<i64>,

    pub entries_total: Option<u64>,
    pub files: Option<u64>,
    pub directories: Option<u64>,
    pub symlinks: Option<u64>,
    pub other: Option<u64>,

    pub uncompressed_bytes_total: Option<u64>,
    pub compression_ratio: Option<f64>,

    pub min_mtime_unix: Option<i64>,
    pub max_mtime_unix: Option<i64>,

    pub encrypted: Option<bool>,
    pub solid: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveInfoZipDetails {
    pub encrypted_entries: u64,
    pub has_encrypted_entries: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveInfoSevenZDetails {
    pub encrypted_entries: u64,
    pub has_encrypted_entries: bool,
    pub solid: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveInfoDetails {
    pub zip: Option<ArchiveInfoZipDetails>,
    pub seven_z: Option<ArchiveInfoSevenZDetails>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveInfoResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub query: Value,
    pub summary: Option<ArchiveInfoSummary>,
    pub details: Option<ArchiveInfoDetails>,

    pub error: Option<(String, String)>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveAddSummary {
    pub archive: String,
    pub format: String,
    pub compression: String,

    pub entries_before: u64,
    pub entries_after: u64,
    pub entries_added: u64,
    pub entries_replaced: u64,
    pub entries_skipped: u64,

    pub uncompressed_bytes_before: u64,
    pub uncompressed_bytes_after: u64,
    pub archive_size_bytes_before: u64,
    pub archive_size_bytes_after: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveAddSkippedEntry {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveAddDetails {
    pub added: Vec<String>,
    pub replaced: Vec<String>,
    pub skipped: Vec<ArchiveAddSkippedEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveAddResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub query: Value,
    pub summary: Option<ArchiveAddSummary>,
    pub details: Option<ArchiveAddDetails>,

    pub error: Option<(String, String)>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveRemoveResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub query: Value,
    pub summary: Option<ArchiveRemoveSummary>,
    pub details: Option<ArchiveRemoveDetails>,

    pub error: Option<(String, String)>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveRemoveSummary {
    pub archive: String,
    pub format: String,
    pub compression: String,

    pub entries_before: u64,
    pub entries_after: u64,
    pub entries_removed: u64,
    pub dirs_removed: u64,

    pub uncompressed_bytes_before: u64,
    pub uncompressed_bytes_after: u64,
    pub archive_size_bytes_before: u64,
    pub archive_size_bytes_after: u64,

    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveRemoveDetails {
    pub removed: Vec<String>,
    pub not_found: Vec<String>,
    pub kept: Vec<String>, // can be truncated for large archives
}

#[derive(Debug, Clone, Serialize)]
pub struct FileEntry {
    pub path: String,
    pub size_bytes: u64,
    pub modified_unix_ms: i64,
    pub file_type: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveExtractManifestEntry {
    pub path: String,   // destination-relative
    pub size: u64,
    pub is_dir: bool,
    pub is_symlink: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveExtractSummary {
    pub archive: String,
    pub destination: String,
    pub format: String,
    pub compression: String,
    pub entries_total: u64,
    pub entries_extracted: u64,
    pub entries_skipped: u64,
    pub bytes_written: u64,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveResult {
    pub output_path: String,
    pub format_detected: String,
    pub files_archived: u64,
    pub directories_archived: u64,
    pub total_size_bytes: u64,
    pub compressed_size_bytes: u64,
    pub compression_ratio: f64,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveStatistics {
    pub files_by_type: HashMap<String, u64>,
    pub largest_files: Vec<FileEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveCreateResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,
    pub query: Value,
    pub result: ArchiveResult,
    pub files: Vec<FileEntry>,
    pub statistics: ArchiveStatistics,
    pub warnings: Vec<String>,
    pub error: Option<(String, String)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveExtractResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub query: Value,
    pub summary: Option<ArchiveExtractSummary>,
    pub manifest: Option<Vec<ArchiveExtractManifestEntry>>,

    pub error: Option<(String, String)>,
    pub warnings: Vec<String>,
}

impl ArchiveCreateOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let output = args.get("output")
            .ok_or_else(|| anyhow::anyhow!("Missing required parameter: output"))?
            .clone();

        if output.is_empty() {
            bail!("Output path cannot be empty");
        }

        let sources_str = args.get("sources")
            .ok_or_else(|| anyhow::anyhow!("Missing required parameter: sources"))?;
        
        let sources: Vec<String> = serde_json::from_str(sources_str)
            .context("Invalid sources format - must be JSON array")?;

        if sources.is_empty() {
            bail!("Sources list cannot be empty");
        }

        let base_dir = args.get("base_dir").cloned();

        // Determine format
        let format = if let Some(format_str) = args.get("format") {
            if format_str == "auto" {
                ArchiveFormat::detect_from_extension(&output)?
            } else {
                ArchiveFormat::from_str(format_str)?
            }
        } else {
            ArchiveFormat::detect_from_extension(&output)?
        };

        let compression_level = if let Some(level_str) = args.get("compression_level") {
            let level = level_str.parse::<u32>()
                .context("Invalid compression_level - must be integer")?;
            
            if format.supports_compression_level() {
                if level < 1 || level > format.max_compression_level() {
                    bail!("Invalid compression level {} for format {}. Must be 1-{}", 
                         level, format.as_str(), format.max_compression_level());
                }
            } else if level != 0 {
                bail!("Compression level not supported for format {}", format.as_str());
            }
            Some(level)
        } else {
            None
        };

        let include_patterns = if let Some(patterns_str) = args.get("include_patterns") {
            serde_json::from_str::<Vec<String>>(patterns_str)
                .context("Invalid include_patterns format - must be JSON array")?
        } else {
            vec![]
        };

        let exclude_patterns = if let Some(patterns_str) = args.get("exclude_patterns") {
            serde_json::from_str::<Vec<String>>(patterns_str)
                .context("Invalid exclude_patterns format - must be JSON array")?
        } else {
            vec![]
        };

        let include_hidden = args.get("include_hidden")
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);

        let follow_symlinks = args.get("follow_symlinks")
            .map(|s| s.parse::<bool>().unwrap_or(false))
            .unwrap_or(false);

        let password = args.get("password").cloned();
        if password.is_some() && !format.supports_password() {
            bail!("Password protection not supported for format {}", format.as_str());
        }

        let overwrite = args.get("overwrite")
            .map(|s| s.parse::<bool>().unwrap_or(false))
            .unwrap_or(false);

        let preserve_permissions = args.get("preserve_permissions")
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);

        let preserve_timestamps = args.get("preserve_timestamps")
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);

        let max_files = args.get("max_files")
            .map(|s| s.parse::<u64>().unwrap_or(100000))
            .unwrap_or(100000);

        let max_size_mb = args.get("max_size_mb")
            .map(|s| s.parse::<u64>().unwrap_or(10240))
            .unwrap_or(10240);

        let progress = args.get("progress")
            .map(|s| s.parse::<bool>().unwrap_or(false))
            .unwrap_or(false);

        let output_format = if let Some(fmt) = args.get("format") {
            match fmt.as_str() {
                "json" => OutputFormat::Json,
                "text" => OutputFormat::Text,
                _ => OutputFormat::Json,
            }
        } else {
            OutputFormat::Json
        };

        Ok(ArchiveCreateOptions {
            output,
            sources,
            base_dir,
            format,
            compression_level,
            include_patterns,
            exclude_patterns,
            include_hidden,
            follow_symlinks,
            password,
            overwrite,
            preserve_permissions,
            preserve_timestamps,
            max_files,
            max_size_mb,
            progress,
            output_format,
        })
    }
}

impl ArchiveExtractOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let archive = args.get("archive")
            .ok_or_else(|| anyhow::anyhow!("Missing required parameter: archive"))?
            .clone();

        if archive.is_empty() {
            bail!("Archive path cannot be empty");
        }

        let destination = args.get("destination")
            .ok_or_else(|| anyhow::anyhow!("Missing required parameter: destination"))?
            .clone();

        if destination.is_empty() {
            bail!("Destination path cannot be empty");
        }

        // Determine format
        let format = if let Some(format_str) = args.get("format") {
            if format_str == "auto" {
                ArchiveFormat::detect_from_extension(&archive)?
            } else {
                ArchiveFormat::from_str(format_str)?
            }
        } else {
            ArchiveFormat::detect_from_extension(&archive)?
        };

        // Determine compression
        let compression = if let Some(compression_str) = args.get("compression") {
            if compression_str == "auto" {
                CompressionKind::detect_from_extension(&archive)
            } else {
                CompressionKind::from_str(compression_str)?
            }
        } else {
            CompressionKind::detect_from_extension(&archive)
        };

        // Validate format/compression combination
        match (&format, &compression) {
            (ArchiveFormat::Raw, CompressionKind::None) => {
                bail!("Raw format requires compression (gzip, xz, or zstd)");
            }
            (ArchiveFormat::Raw, CompressionKind::Auto) => {
                bail!("Raw format requires explicit compression type");
            }
            _ => {}
        }

        let includes = if let Some(includes_str) = args.get("includes") {
            serde_json::from_str::<Vec<String>>(includes_str)
                .context("Invalid includes format - must be JSON array")?
        } else {
            vec![]
        };

        let excludes = if let Some(excludes_str) = args.get("excludes") {
            serde_json::from_str::<Vec<String>>(excludes_str)
                .context("Invalid excludes format - must be JSON array")?
        } else {
            vec![]
        };

        let overwrite = args.get("overwrite")
            .map(|s| s.parse::<bool>().unwrap_or(false))
            .unwrap_or(false);

        let create_destination = args.get("create_destination")
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);

        let fail_on_missing_archive = args.get("fail_on_missing_archive")
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);

        let strip_components = args.get("strip_components")
            .map(|s| s.parse::<u32>().unwrap_or(0))
            .unwrap_or(0);

        let allow_absolute_paths = args.get("allow_absolute_paths")
            .map(|s| s.parse::<bool>().unwrap_or(false))
            .unwrap_or(false);

        let allow_parent_traversal = args.get("allow_parent_traversal")
            .map(|s| s.parse::<bool>().unwrap_or(false))
            .unwrap_or(false);

        let allow_symlinks = args.get("allow_symlinks")
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);

        let follow_symlinks = args.get("follow_symlinks")
            .map(|s| s.parse::<bool>().unwrap_or(false))
            .unwrap_or(false);

        let max_entries = args.get("max_entries")
            .map(|s| s.parse::<u64>().unwrap_or(1000000))
            .unwrap_or(1000000);

        let max_total_bytes = args.get("max_total_bytes")
            .map(|s| s.parse::<u64>().ok())
            .flatten();

        let max_file_bytes = args.get("max_file_bytes")
            .map(|s| s.parse::<u64>().ok())
            .flatten();

        let include_manifest = args.get("include_manifest")
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);

        let format_output = if let Some(fmt) = args.get("format_output") {
            match fmt.as_str() {
                "json" => OutputFormat::Json,
                "text" => OutputFormat::Text,
                _ => OutputFormat::Json,
            }
        } else {
            OutputFormat::Json
        };

        Ok(ArchiveExtractOptions {
            archive,
            destination,
            format,
            compression,
            includes,
            excludes,
            overwrite,
            create_destination,
            fail_on_missing_archive,
            strip_components,
            allow_absolute_paths,
            allow_parent_traversal,
            allow_symlinks,
            follow_symlinks,
            max_entries,
            max_total_bytes,
            max_file_bytes,
            include_manifest,
            format_output,
        })
    }
}

impl ArchiveListOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let archive = args.get("archive")
            .ok_or_else(|| anyhow::anyhow!("Missing required parameter: archive"))?
            .clone();

        if archive.is_empty() {
            bail!("Archive path cannot be empty");
        }

        // Determine format
        let format = if let Some(format_str) = args.get("format") {
            if format_str == "auto" {
                ArchiveFormat::detect_from_extension(&archive)?
            } else {
                ArchiveFormat::from_str(format_str)?
            }
        } else {
            ArchiveFormat::detect_from_extension(&archive)?
        };

        // Determine compression
        let compression = if let Some(compression_str) = args.get("compression") {
            if compression_str == "auto" {
                CompressionKind::detect_from_extension(&archive)
            } else {
                CompressionKind::from_str(compression_str)?
            }
        } else {
            CompressionKind::detect_from_extension(&archive)
        };

        // Validate format/compression combination for raw
        match (&format, &compression) {
            (ArchiveFormat::Raw, CompressionKind::None) => {
                bail!("Raw format requires compression (gzip, xz, or zstd)");
            }
            (ArchiveFormat::Raw, CompressionKind::Auto) => {
                bail!("Raw format requires explicit compression type");
            }
            _ => {}
        }

        let includes = if let Some(includes_str) = args.get("includes") {
            serde_json::from_str::<Vec<String>>(includes_str)
                .context("Invalid includes format - must be JSON array")?
        } else {
            vec![]
        };

        let excludes = if let Some(excludes_str) = args.get("excludes") {
            serde_json::from_str::<Vec<String>>(excludes_str)
                .context("Invalid excludes format - must be JSON array")?
        } else {
            vec![]
        };

        let max_entries = args.get("max_entries")
            .map(|s| s.parse::<u64>().unwrap_or(1000000))
            .unwrap_or(1000000);

        let max_total_bytes = args.get("max_total_bytes")
            .map(|s| s.parse::<u64>().ok())
            .flatten();

        let fail_on_missing_archive = args.get("fail_on_missing_archive")
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);

        let include_metadata = args.get("include_metadata")
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);

        let include_compressed_size = args.get("include_compressed_size")
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);

        let format_output = if let Some(fmt) = args.get("format_output") {
            match fmt.as_str() {
                "json" => OutputFormat::Json,
                "text" => OutputFormat::Text,
                _ => OutputFormat::Json,
            }
        } else {
            OutputFormat::Json
        };

        Ok(ArchiveListOptions {
            archive,
            format,
            compression,
            includes,
            excludes,
            max_entries,
            max_total_bytes,
            fail_on_missing_archive,
            include_metadata,
            include_compressed_size,
            format_output,
        })
    }
}

impl ArchiveTestOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let archive = args.get("archive")
            .ok_or_else(|| anyhow::anyhow!("Missing required parameter: archive"))?
            .clone();

        if archive.is_empty() {
            bail!("Archive path cannot be empty");
        }

        // Determine format
        let format = if let Some(format_str) = args.get("format") {
            if format_str == "auto" {
                ArchiveFormat::detect_from_extension(&archive)?
            } else {
                ArchiveFormat::from_str(format_str)?
            }
        } else {
            ArchiveFormat::detect_from_extension(&archive)?
        };

        // Determine compression
        let compression = if let Some(compression_str) = args.get("compression") {
            if compression_str == "auto" {
                CompressionKind::detect_from_extension(&archive)
            } else {
                CompressionKind::from_str(compression_str)?
            }
        } else {
            CompressionKind::detect_from_extension(&archive)
        };

        // Validate format/compression combination for raw
        match (&format, &compression) {
            (ArchiveFormat::Raw, CompressionKind::None) => {
                bail!("Raw format requires compression (gzip, xz, or zstd)");
            }
            (ArchiveFormat::Raw, CompressionKind::Auto) => {
                bail!("Raw format requires explicit compression type");
            }
            _ => {}
        }

        let stop_on_first_error = args.get("stop_on_first_error")
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);

        let report_entries = args.get("report_entries")
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);

        let verify_data = args.get("verify_data")
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);

        let max_entries = args.get("max_entries")
            .map(|s| s.parse::<u64>().unwrap_or(1000000))
            .unwrap_or(1000000);

        let max_total_bytes = args.get("max_total_bytes")
            .map(|s| s.parse::<u64>().ok())
            .flatten();

        let max_file_bytes = args.get("max_file_bytes")
            .map(|s| s.parse::<u64>().ok())
            .flatten();

        let fail_on_missing_archive = args.get("fail_on_missing_archive")
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);

        let format_output = if let Some(fmt) = args.get("format_output") {
            match fmt.as_str() {
                "json" => OutputFormat::Json,
                "text" => OutputFormat::Text,
                _ => OutputFormat::Json,
            }
        } else {
            OutputFormat::Json
        };

        Ok(ArchiveTestOptions {
            archive,
            format,
            compression,
            stop_on_first_error,
            report_entries,
            verify_data,
            max_entries,
            max_total_bytes,
            max_file_bytes,
            fail_on_missing_archive,
            format_output,
        })
    }
}

impl ArchiveInfoOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let archive = args.get("archive")
            .ok_or_else(|| anyhow::anyhow!("Missing required parameter: archive"))?
            .clone();

        if archive.is_empty() {
            bail!("Archive path cannot be empty");
        }

        // Determine format
        let format = if let Some(format_str) = args.get("format") {
            if format_str == "auto" {
                ArchiveFormat::detect_from_extension(&archive)?
            } else {
                ArchiveFormat::from_str(format_str)?
            }
        } else {
            ArchiveFormat::detect_from_extension(&archive)?
        };

        // Determine compression
        let compression = if let Some(compression_str) = args.get("compression") {
            if compression_str == "auto" {
                CompressionKind::detect_from_extension(&archive)
            } else {
                CompressionKind::from_str(compression_str)?
            }
        } else {
            CompressionKind::detect_from_extension(&archive)
        };

        // Validate format/compression combination for raw
        match (&format, &compression) {
            (ArchiveFormat::Raw, CompressionKind::None) => {
                bail!("Raw format requires compression (gzip, xz, or zstd)");
            }
            (ArchiveFormat::Raw, CompressionKind::Auto) => {
                bail!("Raw format requires explicit compression type");
            }
            _ => {}
        }

        let scan_entries = args.get("scan_entries")
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);

        let max_entries = args.get("max_entries")
            .map(|s| s.parse::<u64>().unwrap_or(1000000))
            .unwrap_or(1000000);

        let max_total_bytes = args.get("max_total_bytes")
            .map(|s| s.parse::<u64>().ok())
            .flatten();

        let fail_on_missing_archive = args.get("fail_on_missing_archive")
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);

        let format_output = if let Some(fmt) = args.get("format_output") {
            match fmt.as_str() {
                "json" => OutputFormat::Json,
                "text" => OutputFormat::Text,
                _ => OutputFormat::Json,
            }
        } else {
            OutputFormat::Json
        };

        Ok(ArchiveInfoOptions {
            archive,
            format,
            compression,
            scan_entries,
            max_entries,
            max_total_bytes,
            fail_on_missing_archive,
            format_output,
        })
    }
}

impl ArchiveAddOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let archive = args.get("archive")
            .ok_or_else(|| anyhow::anyhow!("Missing required parameter: archive"))?
            .clone();

        if archive.is_empty() {
            bail!("Archive path cannot be empty");
        }

        let inputs = if let Some(inputs_str) = args.get("inputs") {
            serde_json::from_str::<Vec<String>>(inputs_str)
                .context("Invalid inputs format - must be JSON array")?
        } else {
            bail!("Missing required parameter: inputs");
        };

        if inputs.is_empty() {
            bail!("Inputs list cannot be empty");
        }

        // Determine format
        let format = if let Some(format_str) = args.get("format") {
            if format_str == "auto" {
                ArchiveFormat::detect_from_extension(&archive)?
            } else {
                ArchiveFormat::from_str(format_str)?
            }
        } else {
            ArchiveFormat::detect_from_extension(&archive)?
        };

        // Determine compression
        let compression = if let Some(compression_str) = args.get("compression") {
            if compression_str == "auto" {
                CompressionKind::detect_from_extension(&archive)
            } else {
                CompressionKind::from_str(compression_str)?
            }
        } else {
            CompressionKind::detect_from_extension(&archive)
        };

        // Validate format/compression combination
        match (&format, &compression) {
            (ArchiveFormat::Raw, _) => {
                bail!("Adding entries to raw compressed streams (gzip/xz/zstd) is not supported");
            }
            (ArchiveFormat::SevenZ, _) => {
                bail!("7z archive modification not yet supported");
            }
            _ => {}
        }

        let base_dir = args.get("base_dir").cloned();

        let includes = if let Some(includes_str) = args.get("includes") {
            serde_json::from_str::<Vec<String>>(includes_str)
                .context("Invalid includes format - must be JSON array")?
        } else {
            vec![]
        };

        let excludes = if let Some(excludes_str) = args.get("excludes") {
            serde_json::from_str::<Vec<String>>(excludes_str)
                .context("Invalid excludes format - must be JSON array")?
        } else {
            vec![]
        };

        let follow_symlinks = args.get("follow_symlinks")
            .map(|s| s.parse::<bool>().unwrap_or(false))
            .unwrap_or(false);

        let overwrite = args.get("overwrite")
            .map(|s| s.parse::<bool>().unwrap_or(false))
            .unwrap_or(false);

        let keep_existing_dirs = args.get("keep_existing_dirs")
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);

        let preserve_owner = args.get("preserve_owner")
            .map(|s| s.parse::<bool>().unwrap_or(false))
            .unwrap_or(false);

        let preserve_permissions = args.get("preserve_permissions")
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);

        let preserve_timestamps = args.get("preserve_timestamps")
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);

        let deterministic = args.get("deterministic")
            .map(|s| s.parse::<bool>().unwrap_or(false))
            .unwrap_or(false);

        let max_entries = args.get("max_entries")
            .map(|s| s.parse::<u64>().unwrap_or(1000000))
            .unwrap_or(1000000);

        let max_total_bytes = args.get("max_total_bytes")
            .map(|s| s.parse::<u64>().ok())
            .flatten();

        let tmp_dir = args.get("tmp_dir").cloned();
        let backup_suffix = args.get("backup_suffix").cloned();

        let format_output = if let Some(fmt) = args.get("format_output") {
            match fmt.as_str() {
                "json" => OutputFormat::Json,
                "text" => OutputFormat::Text,
                _ => OutputFormat::Json,
            }
        } else {
            OutputFormat::Json
        };

        Ok(ArchiveAddOptions {
            archive,
            inputs,
            format,
            compression,
            base_dir,
            includes,
            excludes,
            follow_symlinks,
            overwrite,
            keep_existing_dirs,
            preserve_owner,
            preserve_permissions,
            preserve_timestamps,
            deterministic,
            max_entries,
            max_total_bytes,
            tmp_dir,
            backup_suffix,
            format_output,
        })
    }
}

impl ArchiveRemoveOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let archive = args.get("archive")
            .ok_or_else(|| anyhow::anyhow!("Missing required parameter: archive"))?
            .clone();

        if archive.is_empty() {
            bail!("Archive path cannot be empty");
        }

        // Determine format
        let format = if let Some(format_str) = args.get("format") {
            if format_str == "auto" {
                ArchiveFormat::detect_from_extension(&archive)?
            } else {
                ArchiveFormat::from_str(format_str)?
            }
        } else {
            ArchiveFormat::detect_from_extension(&archive)?
        };

        // Determine compression
        let compression = if let Some(compression_str) = args.get("compression") {
            if compression_str == "auto" {
                CompressionKind::detect_from_extension(&archive)
            } else {
                CompressionKind::from_str(compression_str)?
            }
        } else {
            CompressionKind::detect_from_extension(&archive)
        };

        // Validate format/compression combination
        match (&format, &compression) {
            (ArchiveFormat::Raw, _) => {
                bail!("Removing entries from raw compressed streams (gzip/xz/zstd) is not supported");
            }
            (ArchiveFormat::SevenZ, _) => {
                bail!("7z archive removal not yet supported");
            }
            _ => {}
        }

        let paths = if let Some(paths_str) = args.get("paths") {
            serde_json::from_str::<Vec<String>>(paths_str)
                .context("Invalid paths format - must be JSON array")?
        } else {
            vec![]
        };

        let patterns = if let Some(patterns_str) = args.get("patterns") {
            serde_json::from_str::<Vec<String>>(patterns_str)
                .context("Invalid patterns format - must be JSON array")?
        } else {
            vec![]
        };

        let dir_prefixes = if let Some(dir_prefixes_str) = args.get("dir_prefixes") {
            serde_json::from_str::<Vec<String>>(dir_prefixes_str)
                .context("Invalid dir_prefixes format - must be JSON array")?
        } else {
            vec![]
        };

        // Check if we have at least one selector
        if paths.is_empty() && patterns.is_empty() && dir_prefixes.is_empty() {
            bail!("Nothing to remove - must specify at least one of: paths, patterns, or dir_prefixes");
        }

        let remove_empty_dirs = args.get("remove_empty_dirs")
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);

        let dry_run = args.get("dry_run")
            .map(|s| s.parse::<bool>().unwrap_or(false))
            .unwrap_or(false);

        let max_entries = args.get("max_entries")
            .map(|s| s.parse::<u64>().unwrap_or(1000000))
            .unwrap_or(1000000);

        let max_total_bytes = args.get("max_total_bytes")
            .map(|s| s.parse::<u64>().ok())
            .flatten();

        let fail_on_missing_archive = args.get("fail_on_missing_archive")
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);

        let tmp_dir = args.get("tmp_dir").cloned();
        let backup_suffix = args.get("backup_suffix").cloned();

        let format_output = if let Some(fmt) = args.get("format_output") {
            match fmt.as_str() {
                "json" => OutputFormat::Json,
                "text" => OutputFormat::Text,
                _ => OutputFormat::Json,
            }
        } else {
            OutputFormat::Json
        };

        Ok(ArchiveRemoveOptions {
            archive,
            format,
            compression,
            paths,
            patterns,
            dir_prefixes,
            remove_empty_dirs,
            dry_run,
            max_entries,
            max_total_bytes,
            fail_on_missing_archive,
            tmp_dir,
            backup_suffix,
            format_output,
        })
    }
}

impl ArchiveListResponse {
    pub fn new(opts: &ArchiveListOptions) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let query = json!({
            "archive": opts.archive,
            "format": opts.format.as_str(),
            "compression": opts.compression.as_str(),
            "includes": opts.includes,
            "excludes": opts.excludes,
            "max_entries": opts.max_entries,
            "max_total_bytes": opts.max_total_bytes,
            "fail_on_missing_archive": opts.fail_on_missing_archive,
            "include_metadata": opts.include_metadata,
            "include_compressed_size": opts.include_compressed_size,
            "format_output": match opts.format_output {
                OutputFormat::Json => "json",
                OutputFormat::Text => "text",
            }
        });

        Self {
            ok: true,
            timestamp_unix_ms: timestamp,
            query,
            summary: None,
            manifest: None,
            error: None,
            warnings: Vec::new(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();
        output.push_str("Archive List\n");
        output.push_str("============\n\n");

        if let Some(ref summary) = self.summary {
            output.push_str(&format!("Archive     : {}\n", summary.archive));
            output.push_str(&format!("Format      : {}\n", summary.format));
            output.push_str(&format!("Compression : {}\n\n", summary.compression));

            if self.ok {
                output.push_str(&format!("Entries Total : {}\n", summary.entries_total));
                output.push_str(&format!("Entries Listed: {}\n", summary.entries_listed));
                
                let mb = summary.bytes_total as f64 / 1024.0 / 1024.0;
                output.push_str(&format!("Bytes Total   : {:.1} MB\n", mb));
                
                if let Some(compressed_bytes) = summary.bytes_compressed {
                    let compressed_mb = compressed_bytes as f64 / 1024.0 / 1024.0;
                    output.push_str(&format!("Archive Size  : {:.1} MB\n", compressed_mb));
                }
                
                output.push_str("\nEntries:\n");

                if let Some(ref manifest) = self.manifest {
                    for entry in manifest.iter().take(20) { // Limit display to first 20
                        let type_char = if entry.is_dir {
                            "[D]"
                        } else if entry.is_symlink {
                            "[L]"
                        } else {
                            "[F]"
                        };
                        
                        output.push_str(&format!("  {} {:<30}", type_char, entry.path));
                        
                        if !entry.is_dir {
                            output.push_str(&format!(" size={:<8}", entry.size));
                        } else {
                            output.push_str(&format!(" size={:<8}", ""));
                        }
                        
                        if let Some(ref mode) = entry.mode {
                            output.push_str(&format!(" mode={}", mode));
                        }
                        
                        if let Some(mtime) = entry.mtime_unix {
                            // Convert to human readable time
                            if let Some(datetime) = chrono::DateTime::from_timestamp(mtime, 0) {
                                output.push_str(&format!(" mtime={}", 
                                    datetime.format("%Y-%m-%dT%H:%M:%SZ")));
                            }
                        }
                        
                        output.push('\n');
                    }
                    
                    if manifest.len() > 20 {
                        output.push_str(&format!("  ... and {} more entries\n", manifest.len() - 20));
                    }
                }
            }
        } else {
            // This is an error case, show the archive path from query if available
            if let Some(archive) = self.query.get("archive") {
                if let Some(archive_str) = archive.as_str() {
                    output.push_str(&format!("Archive : {}\n\n", archive_str));
                }
            }
        }

        if !self.ok {
            if let Some((ref code, ref message)) = self.error {
                output.push_str(&format!("Error:\n  [{}] {}\n\n", code, message));
            }
        }

        if !self.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &self.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        } else if self.ok {
            output.push_str("\nWarnings:\n  (none)\n");
        }

        output
    }
}

impl ArchiveTestResponse {
    pub fn new(opts: &ArchiveTestOptions) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let query = json!({
            "archive": opts.archive,
            "format": opts.format.as_str(),
            "compression": opts.compression.as_str(),
            "stop_on_first_error": opts.stop_on_first_error,
            "report_entries": opts.report_entries,
            "verify_data": opts.verify_data,
            "max_entries": opts.max_entries,
            "max_total_bytes": opts.max_total_bytes,
            "max_file_bytes": opts.max_file_bytes,
            "fail_on_missing_archive": opts.fail_on_missing_archive,
            "format_output": match opts.format_output {
                OutputFormat::Json => "json",
                OutputFormat::Text => "text",
            }
        });

        Self {
            ok: true,
            timestamp_unix_ms: timestamp,
            query,
            summary: None,
            entries: None,
            error: None,
            warnings: Vec::new(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();
        output.push_str("Archive Test\n");
        output.push_str("============\n\n");

        if let Some(ref summary) = self.summary {
            output.push_str(&format!("Archive     : {}\n", summary.archive));
            output.push_str(&format!("Format      : {}\n", summary.format));
            output.push_str(&format!("Compression : {}\n\n", summary.compression));

            output.push_str(&format!("Entries Tested : {}\n", summary.entries_tested));
            output.push_str(&format!("Entries Failed : {}\n", summary.entries_failed));
            
            let mb = summary.bytes_tested as f64 / 1024.0 / 1024.0;
            output.push_str(&format!("Bytes Tested   : {:.1} MB\n", mb));
            output.push_str(&format!("Valid          : {}\n", if summary.valid { "yes" } else { "no" }));
            output.push_str(&format!("Stopped Early  : {}\n", if summary.stopped_early { "yes" } else { "no" }));

            if let Some(ref entries) = self.entries {
                if !entries.is_empty() {
                    let failed_entries: Vec<_> = entries.iter().filter(|e| e.status == "error").collect();
                    if !failed_entries.is_empty() {
                        output.push_str("\nFailed Entries:\n");
                        for entry in failed_entries.iter().take(10) { // Limit to first 10 failed
                            if let (Some(code), Some(message)) = (&entry.error_code, &entry.error_message) {
                                output.push_str(&format!("  - {}: [{}] {}\n", entry.path, code, message));
                            } else {
                                output.push_str(&format!("  - {}: failed\n", entry.path));
                            }
                        }
                        if failed_entries.len() > 10 {
                            output.push_str(&format!("  ... and {} more failed entries\n", failed_entries.len() - 10));
                        }
                    }
                }
            }
        } else {
            // This is an error case, show the archive path from query if available
            if let Some(archive) = self.query.get("archive") {
                if let Some(archive_str) = archive.as_str() {
                    output.push_str(&format!("Archive : {}\n\n", archive_str));
                }
            }
        }

        if !self.ok {
            if let Some((ref code, ref message)) = self.error {
                output.push_str(&format!("\nError:\n  [{}] {}\n", code, message));
            }
        }

        if !self.warnings.is_empty() {
            output.push_str("\nWarnings:\n");
            for warning in &self.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        } else if self.ok && self.summary.is_some() {
            output.push_str("\nWarnings:\n  (none)\n");
        }

        output
    }
}

impl ArchiveInfoResponse {
    pub fn new(opts: &ArchiveInfoOptions) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let query = json!({
            "archive": opts.archive,
            "format": opts.format.as_str(),
            "compression": opts.compression.as_str(),
            "scan_entries": opts.scan_entries,
            "max_entries": opts.max_entries,
            "max_total_bytes": opts.max_total_bytes,
            "fail_on_missing_archive": opts.fail_on_missing_archive,
            "format_output": match opts.format_output {
                OutputFormat::Json => "json",
                OutputFormat::Text => "text",
            }
        });

        Self {
            ok: true,
            timestamp_unix_ms: timestamp,
            query,
            summary: None,
            details: None,
            error: None,
            warnings: Vec::new(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();
        output.push_str("Archive Info\n");
        output.push_str("============\n\n");

        if let Some(ref summary) = self.summary {
            output.push_str(&format!("Archive     : {}\n", summary.archive));
            output.push_str(&format!("Format      : {}\n", summary.format));
            output.push_str(&format!("Compression : {}\n\n", summary.compression));

            // File size
            let mb = summary.archive_size_bytes as f64 / 1024.0 / 1024.0;
            output.push_str(&format!("Archive Size    : {:.1} MB\n", mb));
            
            if let Some(mtime) = summary.archive_mtime_unix {
                let dt = DateTime::<Utc>::from_timestamp(mtime, 0);
                if let Some(dt) = dt {
                    output.push_str(&format!("Archive Mtime   : {}\n", dt.format("%Y-%m-%dT%H:%M:%SZ")));
                }
            }

            if let Some(total) = summary.entries_total {
                output.push_str(&format!("Entries Total   : {}\n", total));
                if let Some(files) = summary.files {
                    output.push_str(&format!("Files           : {}\n", files));
                }
                if let Some(dirs) = summary.directories {
                    output.push_str(&format!("Directories     : {}\n", dirs));
                }
                if let Some(symlinks) = summary.symlinks {
                    output.push_str(&format!("Symlinks        : {}\n", symlinks));
                }
                if let Some(other) = summary.other {
                    output.push_str(&format!("Other           : {}\n", other));
                }
                output.push_str("\n");
            }

            if let Some(uncompressed) = summary.uncompressed_bytes_total {
                let uncompressed_mb = uncompressed as f64 / 1024.0 / 1024.0;
                output.push_str(&format!("Uncompressed    : {:.1} MB\n", uncompressed_mb));
                if let Some(ratio) = summary.compression_ratio {
                    output.push_str(&format!("Compression Rate: {:.1}x\n", ratio));
                }
            }

            if let Some(min_mtime) = summary.min_mtime_unix {
                let dt = DateTime::<Utc>::from_timestamp(min_mtime, 0);
                if let Some(dt) = dt {
                    output.push_str(&format!("Min Mtime       : {}\n", dt.format("%Y-%m-%dT%H:%M:%SZ")));
                }
            }
            if let Some(max_mtime) = summary.max_mtime_unix {
                let dt = DateTime::<Utc>::from_timestamp(max_mtime, 0);
                if let Some(dt) = dt {
                    output.push_str(&format!("Max Mtime       : {}\n", dt.format("%Y-%m-%dT%H:%M:%SZ")));
                }
            }

            output.push_str("\n");
            match summary.encrypted {
                Some(true) => output.push_str("Encrypted       : yes\n"),
                Some(false) => output.push_str("Encrypted       : no\n"),
                None => output.push_str("Encrypted       : unknown\n"),
            }

            match summary.solid {
                Some(true) => output.push_str("Solid           : yes\n"),
                Some(false) => output.push_str("Solid           : no\n"),
                None => output.push_str("Solid           : n/a\n"),
            }
        } else {
            // This is an error case, show the archive path from query if available
            if let Some(archive) = self.query.get("archive") {
                if let Some(archive_str) = archive.as_str() {
                    output.push_str(&format!("Archive : {}\n\n", archive_str));
                }
            }
        }

        if !self.ok {
            if let Some((ref code, ref message)) = self.error {
                output.push_str(&format!("\nError:\n  [{}] {}\n", code, message));
            }
        }

        if !self.warnings.is_empty() {
            output.push_str("\nWarnings:\n");
            for warning in &self.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        } else if self.ok && self.summary.is_some() {
            output.push_str("\nWarnings:\n  (none)\n");
        }

        output
    }
}

impl ArchiveCreateResponse {
    pub fn new(opts: &ArchiveCreateOptions) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let query = json!({
            "output": opts.output,
            "sources": opts.sources,
            "format": opts.format.as_str(),
            "compression_level": opts.compression_level,
            "exclude_patterns": opts.exclude_patterns,
            "overwrite": opts.overwrite
        });

        let result = ArchiveResult {
            output_path: opts.output.clone(),
            format_detected: opts.format.as_str().to_string(),
            files_archived: 0,
            directories_archived: 0,
            total_size_bytes: 0,
            compressed_size_bytes: 0,
            compression_ratio: 0.0,
            duration_ms: 0,
        };

        let statistics = ArchiveStatistics {
            files_by_type: HashMap::new(),
            largest_files: Vec::new(),
        };

        Self {
            ok: true,
            timestamp_unix_ms: timestamp,
            query,
            result,
            files: Vec::new(),
            statistics,
            warnings: Vec::new(),
            error: None,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();
        output.push_str("Archive Creation\n");
        output.push_str("================\n\n");

        if self.ok {
            output.push_str(&format!("Output      : {} ({} format)\n", 
                                   self.result.output_path, self.result.format_detected));
            output.push_str(&format!("Files       : {} files, {} directories\n", 
                                   self.result.files_archived, self.result.directories_archived));
            
            let total_mb = self.result.total_size_bytes as f64 / 1024.0 / 1024.0;
            let compressed_mb = self.result.compressed_size_bytes as f64 / 1024.0 / 1024.0;
            let compression = (self.result.compression_ratio * 100.0) as i32;
            
            output.push_str(&format!("Size        : {:.1} MB → {:.1} MB ({}% compression)\n", 
                                   total_mb, compressed_mb, compression));
            output.push_str(&format!("Duration    : {:.2} seconds\n\n", 
                                   self.result.duration_ms as f64 / 1000.0));
        } else {
            if let Some((ref code, ref message)) = self.error {
                output.push_str(&format!("Error: [{}] {}\n\n", code, message));
            }
        }

        if !self.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &self.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        }

        output
    }
}

impl ArchiveExtractResponse {
    pub fn new(opts: &ArchiveExtractOptions) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let query = json!({
            "archive": opts.archive,
            "destination": opts.destination,
            "format": opts.format.as_str(),
            "compression": opts.compression.as_str(),
            "includes": opts.includes,
            "excludes": opts.excludes,
            "overwrite": opts.overwrite,
            "create_destination": opts.create_destination,
            "fail_on_missing_archive": opts.fail_on_missing_archive,
            "strip_components": opts.strip_components,
            "allow_absolute_paths": opts.allow_absolute_paths,
            "allow_parent_traversal": opts.allow_parent_traversal,
            "allow_symlinks": opts.allow_symlinks,
            "follow_symlinks": opts.follow_symlinks,
            "max_entries": opts.max_entries,
            "max_total_bytes": opts.max_total_bytes,
            "max_file_bytes": opts.max_file_bytes
        });

        Self {
            ok: true,
            timestamp_unix_ms: timestamp,
            query,
            summary: None,
            manifest: None,
            error: None,
            warnings: Vec::new(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();
        output.push_str("Archive Extract\n");
        output.push_str("===============\n\n");

        if let Some(ref summary) = self.summary {
            output.push_str(&format!("Archive     : {}\n", summary.archive));
            output.push_str(&format!("Destination : {}\n", summary.destination));
            output.push_str(&format!("Format      : {}\n", summary.format));
            output.push_str(&format!("Compression : {}\n\n", summary.compression));

            if self.ok {
                output.push_str(&format!("Entries Total    : {}\n", summary.entries_total));
                output.push_str(&format!("Entries Extracted: {}\n", summary.entries_extracted));
                output.push_str(&format!("Entries Skipped  : {}\n", summary.entries_skipped));
                
                let mb = summary.bytes_written as f64 / 1024.0 / 1024.0;
                output.push_str(&format!("Bytes Written    : {:.1} MB\n", mb));
                output.push_str(&format!("Duration         : {:.2} s\n\n", 
                                       summary.duration_ms as f64 / 1000.0));
            }
        }

        if !self.ok {
            if let Some((ref code, ref message)) = self.error {
                output.push_str(&format!("Error:\n  [{}] {}\n\n", code, message));
            }
        }

        if !self.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &self.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        } else if self.ok {
            output.push_str("Warnings:\n  (none)\n");
        }

        output
    }
}

impl ArchiveAddResponse {
    pub fn new(opts: &ArchiveAddOptions) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let query = json!({
            "archive": opts.archive,
            "inputs": opts.inputs,
            "format": opts.format.as_str(),
            "compression": opts.compression.as_str(),
            "base_dir": opts.base_dir,
            "includes": opts.includes,
            "excludes": opts.excludes,
            "follow_symlinks": opts.follow_symlinks,
            "overwrite": opts.overwrite,
            "keep_existing_dirs": opts.keep_existing_dirs,
            "preserve_owner": opts.preserve_owner,
            "preserve_permissions": opts.preserve_permissions,
            "preserve_timestamps": opts.preserve_timestamps,
            "deterministic": opts.deterministic,
            "max_entries": opts.max_entries,
            "max_total_bytes": opts.max_total_bytes,
            "tmp_dir": opts.tmp_dir,
            "backup_suffix": opts.backup_suffix,
            "format_output": match opts.format_output {
                OutputFormat::Json => "json",
                OutputFormat::Text => "text",
            }
        });

        Self {
            ok: true,
            timestamp_unix_ms: timestamp,
            query,
            summary: None,
            details: None,
            error: None,
            warnings: Vec::new(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();
        output.push_str("Archive Add\n");
        output.push_str("===========\n\n");

        if let Some(ref summary) = self.summary {
            output.push_str(&format!("Archive     : {}\n", summary.archive));
            output.push_str(&format!("Format      : {}\n", summary.format));
            output.push_str(&format!("Compression : {}\n\n", summary.compression));

            if self.ok {
                output.push_str(&format!("Entries Before : {}\n", summary.entries_before));
                output.push_str(&format!("Entries After  : {}\n", summary.entries_after));
                output.push_str(&format!("Added          : {}\n", summary.entries_added));
                output.push_str(&format!("Replaced       : {}\n", summary.entries_replaced));
                output.push_str(&format!("Skipped        : {}\n\n", summary.entries_skipped));

                let mb_before = summary.uncompressed_bytes_before as f64 / 1024.0 / 1024.0;
                let mb_after = summary.uncompressed_bytes_after as f64 / 1024.0 / 1024.0;
                let archive_mb_before = summary.archive_size_bytes_before as f64 / 1024.0 / 1024.0;
                let archive_mb_after = summary.archive_size_bytes_after as f64 / 1024.0 / 1024.0;
                
                output.push_str(&format!("Uncompressed Before : {:.1} MB\n", mb_before));
                output.push_str(&format!("Uncompressed After  : {:.1} MB\n", mb_after));
                output.push_str(&format!("Archive Size Before : {:.1} MB\n", archive_mb_before));
                output.push_str(&format!("Archive Size After  : {:.1} MB\n\n", archive_mb_after));
            }
        }

        if !self.ok {
            if let Some((ref code, ref message)) = self.error {
                output.push_str(&format!("Error:\n  [{}] {}\n\n", code, message));
            }
        }

        if !self.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &self.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        } else if self.ok {
            output.push_str("Warnings:\n  (none)\n");
        }

        output
    }
}

impl ArchiveRemoveResponse {
    pub fn new(opts: &ArchiveRemoveOptions) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let query = json!({
            "archive": opts.archive,
            "format": opts.format.as_str(),
            "compression": opts.compression.as_str(),
            "paths": opts.paths,
            "patterns": opts.patterns,
            "dir_prefixes": opts.dir_prefixes,
            "remove_empty_dirs": opts.remove_empty_dirs,
            "dry_run": opts.dry_run,
            "max_entries": opts.max_entries,
            "max_total_bytes": opts.max_total_bytes,
            "fail_on_missing_archive": opts.fail_on_missing_archive,
            "tmp_dir": opts.tmp_dir,
            "backup_suffix": opts.backup_suffix,
            "format_output": match opts.format_output {
                OutputFormat::Json => "json",
                OutputFormat::Text => "text",
            }
        });

        Self {
            ok: true,
            timestamp_unix_ms: timestamp,
            query,
            summary: None,
            details: None,
            error: None,
            warnings: Vec::new(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();
        output.push_str("Archive Remove\n");
        output.push_str("==============\n\n");

        if let Some(ref summary) = self.summary {
            output.push_str(&format!("Archive     : {}\n", summary.archive));
            output.push_str(&format!("Format      : {}\n", summary.format));
            output.push_str(&format!("Compression : {}\n\n", summary.compression));

            if self.ok {
                output.push_str(&format!("Entries Before : {}\n", summary.entries_before));
                output.push_str(&format!("Entries After  : {}\n", summary.entries_after));
                output.push_str(&format!("Removed        : {}\n", summary.entries_removed));
                output.push_str(&format!("Dirs Removed   : {}\n\n", summary.dirs_removed));

                let mb_before = summary.uncompressed_bytes_before as f64 / 1024.0 / 1024.0;
                let mb_after = summary.uncompressed_bytes_after as f64 / 1024.0 / 1024.0;
                let archive_mb_before = summary.archive_size_bytes_before as f64 / 1024.0 / 1024.0;
                let archive_mb_after = summary.archive_size_bytes_after as f64 / 1024.0 / 1024.0;
                
                if mb_before >= 1024.0 {
                    output.push_str(&format!("Uncompressed Before : {:.2} GB\n", mb_before / 1024.0));
                    output.push_str(&format!("Uncompressed After  : {:.2} GB\n", mb_after / 1024.0));
                } else {
                    output.push_str(&format!("Uncompressed Before : {:.1} MB\n", mb_before));
                    output.push_str(&format!("Uncompressed After  : {:.1} MB\n", mb_after));
                }
                
                if archive_mb_before >= 1024.0 {
                    output.push_str(&format!("Archive Size Before : {:.2} GB\n", archive_mb_before / 1024.0));
                    output.push_str(&format!("Archive Size After  : {:.2} GB\n", archive_mb_after / 1024.0));
                } else {
                    output.push_str(&format!("Archive Size Before : {:.1} MB\n", archive_mb_before));
                    output.push_str(&format!("Archive Size After  : {:.1} MB\n", archive_mb_after));
                }

                output.push_str(&format!("Dry Run            : {}\n\n", if summary.dry_run { "yes" } else { "no" }));
            }
        }

        if !self.ok {
            if let Some((ref code, ref message)) = self.error {
                output.push_str(&format!("Error:\n  [{}] {}\n\n", code, message));
            }
        }

        if !self.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &self.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        } else if self.ok {
            output.push_str("Warnings:\n  (none)\n");
        }

        output
    }
}

// List error constants
pub const ARCHIVE_LIST_INVALID_ARCHIVE_PATH: &str = "archive.list_invalid_archive_path";
pub const ARCHIVE_LIST_MISSING_ARCHIVE: &str = "archive.list_missing_archive";
pub const ARCHIVE_LIST_INVALID_FORMAT: &str = "archive.list_invalid_format";
pub const ARCHIVE_LIST_INVALID_FORMAT_INFER: &str = "archive.list_invalid_format_infer";
pub const ARCHIVE_LIST_INVALID_COMPRESSION: &str = "archive.list_invalid_compression";
pub const ARCHIVE_LIST_INVALID_FORMAT_COMPRESSION: &str = "archive.list_invalid_format_compression";
pub const ARCHIVE_LIST_INVALID_INCLUDE_PATTERN: &str = "archive.list_invalid_include_pattern";
pub const ARCHIVE_LIST_INVALID_EXCLUDE_PATTERN: &str = "archive.list_invalid_exclude_pattern";
pub const ARCHIVE_LIST_INVALID_MAX_ENTRIES: &str = "archive.list_invalid_max_entries";
pub const ARCHIVE_LIST_INVALID_MAX_SIZE: &str = "archive.list_invalid_max_size";
pub const ARCHIVE_LIST_IO_ERROR: &str = "archive.list_io_error";
pub const ARCHIVE_LIST_ARCHIVE_READ_ERROR: &str = "archive.list_archive_read_error";
pub const ARCHIVE_LIST_COMPRESSION_ERROR: &str = "archive.list_compression_error";
pub const ARCHIVE_LIST_7Z_UNSUPPORTED: &str = "archive.list_7z_unsupported";
pub const ARCHIVE_LIST_MAX_ENTRIES_EXCEEDED: &str = "archive.list_max_entries_exceeded";
pub const ARCHIVE_LIST_MAX_SIZE_EXCEEDED: &str = "archive.list_max_size_exceeded";
pub const ARCHIVE_LIST_INTERNAL_ERROR: &str = "archive.list_internal_error";

// Test error constants
pub const ARCHIVE_TEST_INVALID_ARCHIVE_PATH: &str = "archive.test_invalid_archive_path";
pub const ARCHIVE_TEST_MISSING_ARCHIVE: &str = "archive.test_missing_archive";
pub const ARCHIVE_TEST_INVALID_FORMAT: &str = "archive.test_invalid_format";
pub const ARCHIVE_TEST_INVALID_FORMAT_INFER: &str = "archive.test_invalid_format_infer";
pub const ARCHIVE_TEST_INVALID_COMPRESSION: &str = "archive.test_invalid_compression";
pub const ARCHIVE_TEST_INVALID_FORMAT_COMPRESSION: &str = "archive.test_invalid_format_compression";
pub const ARCHIVE_TEST_INVALID_MAX_ENTRIES: &str = "archive.test_invalid_max_entries";
pub const ARCHIVE_TEST_INVALID_MAX_SIZE: &str = "archive.test_invalid_max_size";
pub const ARCHIVE_TEST_INVALID_MAX_FILE_SIZE: &str = "archive.test_invalid_max_file_size";
pub const ARCHIVE_TEST_IO_ERROR: &str = "archive.test_io_error";
pub const ARCHIVE_TEST_ARCHIVE_READ_ERROR: &str = "archive.test_archive_read_error";
pub const ARCHIVE_TEST_COMPRESSION_ERROR: &str = "archive.test_compression_error";
pub const ARCHIVE_TEST_7Z_UNSUPPORTED: &str = "archive.test_7z_unsupported";
pub const ARCHIVE_TEST_ENTRY_IO_ERROR: &str = "archive.test_entry_io_error";
pub const ARCHIVE_TEST_ENTRY_COMPRESSION_ERROR: &str = "archive.test_entry_compression_error";
pub const ARCHIVE_TEST_ENTRY_CHECKSUM_ERROR: &str = "archive.test_entry_checksum_error";
pub const ARCHIVE_TEST_ENTRY_HEADER_ERROR: &str = "archive.test_entry_header_error";
pub const ARCHIVE_TEST_ENTRY_SIZE_MISMATCH: &str = "archive.test_entry_size_mismatch";
pub const ARCHIVE_TEST_ENTRY_FAILED: &str = "archive.test_entry_failed";
pub const ARCHIVE_TEST_MAX_ENTRIES_EXCEEDED: &str = "archive.test_max_entries_exceeded";
pub const ARCHIVE_TEST_MAX_SIZE_EXCEEDED: &str = "archive.test_max_size_exceeded";
pub const ARCHIVE_TEST_MAX_FILE_SIZE_EXCEEDED: &str = "archive.test_max_file_size_exceeded";
pub const ARCHIVE_TEST_INTERNAL_ERROR: &str = "archive.test_internal_error";

// Error constants
pub const ARCHIVE_CREATE_INVALID_OUTPUT: &str = "archive.create_invalid_output";
pub const ARCHIVE_CREATE_INVALID_SOURCES: &str = "archive.create_invalid_sources";
pub const ARCHIVE_CREATE_INVALID_FORMAT: &str = "archive.create_invalid_format";
pub const ARCHIVE_CREATE_INVALID_COMPRESSION_LEVEL: &str = "archive.create_invalid_compression_level";
pub const ARCHIVE_CREATE_INVALID_BASE_DIR: &str = "archive.create_invalid_base_dir";
pub const ARCHIVE_CREATE_INVALID_PATTERN: &str = "archive.create_invalid_pattern";
pub const ARCHIVE_CREATE_PASSWORD_NOT_SUPPORTED: &str = "archive.create_password_not_supported";
pub const ARCHIVE_CREATE_OUTPUT_EXISTS: &str = "archive.create_output_exists";
pub const ARCHIVE_CREATE_PERMISSION_DENIED: &str = "archive.create_permission_denied";
pub const ARCHIVE_CREATE_SOURCE_NOT_FOUND: &str = "archive.create_source_not_found";
pub const ARCHIVE_CREATE_SOURCE_PERMISSION_DENIED: &str = "archive.create_source_permission_denied";
pub const ARCHIVE_CREATE_MAX_FILES_EXCEEDED: &str = "archive.create_max_files_exceeded";
pub const ARCHIVE_CREATE_MAX_SIZE_EXCEEDED: &str = "archive.create_max_size_exceeded";
pub const ARCHIVE_CREATE_COMPRESSION_FAILED: &str = "archive.create_compression_failed";
pub const ARCHIVE_CREATE_DISK_FULL: &str = "archive.create_disk_full";
pub const ARCHIVE_CREATE_INTERNAL_ERROR: &str = "archive.create_internal_error";

// Extract error constants  
pub const ARCHIVE_EXTRACT_INVALID_ARCHIVE_PATH: &str = "archive.extract_invalid_archive_path";
pub const ARCHIVE_EXTRACT_MISSING_ARCHIVE: &str = "archive.extract_missing_archive";
pub const ARCHIVE_EXTRACT_INVALID_DESTINATION: &str = "archive.extract_invalid_destination";
pub const ARCHIVE_EXTRACT_DESTINATION_MISSING: &str = "archive.extract_destination_missing";
pub const ARCHIVE_EXTRACT_DESTINATION_CREATE_FAILED: &str = "archive.extract_destination_create_failed";
pub const ARCHIVE_EXTRACT_INVALID_FORMAT: &str = "archive.extract_invalid_format";
pub const ARCHIVE_EXTRACT_INVALID_FORMAT_INFER: &str = "archive.extract_invalid_format_infer";
pub const ARCHIVE_EXTRACT_INVALID_COMPRESSION: &str = "archive.extract_invalid_compression";
pub const ARCHIVE_EXTRACT_INVALID_FORMAT_COMPRESSION: &str = "archive.extract_invalid_format_compression";
pub const ARCHIVE_EXTRACT_INVALID_INCLUDE_PATTERN: &str = "archive.extract_invalid_include_pattern";
pub const ARCHIVE_EXTRACT_INVALID_EXCLUDE_PATTERN: &str = "archive.extract_invalid_exclude_pattern";
pub const ARCHIVE_EXTRACT_INVALID_STRIP_COMPONENTS: &str = "archive.extract_invalid_strip_components";
pub const ARCHIVE_EXTRACT_INVALID_MAX_ENTRIES: &str = "archive.extract_invalid_max_entries";
pub const ARCHIVE_EXTRACT_INVALID_MAX_SIZE: &str = "archive.extract_invalid_max_size";
pub const ARCHIVE_EXTRACT_INVALID_MAX_FILE_SIZE: &str = "archive.extract_invalid_max_file_size";
pub const ARCHIVE_EXTRACT_PATH_TRAVERSAL_DETECTED: &str = "archive.extract_path_traversal_detected";
pub const ARCHIVE_EXTRACT_ABSOLUTE_PATH_REJECTED: &str = "archive.extract_absolute_path_rejected";
pub const ARCHIVE_EXTRACT_SYMLINK_REJECTED: &str = "archive.extract_symlink_rejected";
pub const ARCHIVE_EXTRACT_IO_ERROR: &str = "archive.extract_io_error";
pub const ARCHIVE_EXTRACT_ARCHIVE_READ_ERROR: &str = "archive.extract_archive_read_error";
pub const ARCHIVE_EXTRACT_COMPRESSION_ERROR: &str = "archive.extract_compression_error";
pub const ARCHIVE_EXTRACT_7Z_UNSUPPORTED: &str = "archive.extract_7z_unsupported";
pub const ARCHIVE_EXTRACT_MAX_ENTRIES_EXCEEDED: &str = "archive.extract_max_entries_exceeded";
pub const ARCHIVE_EXTRACT_MAX_SIZE_EXCEEDED: &str = "archive.extract_max_size_exceeded";
pub const ARCHIVE_EXTRACT_MAX_FILE_SIZE_EXCEEDED: &str = "archive.extract_max_file_size_exceeded";
pub const ARCHIVE_EXTRACT_INTERNAL_ERROR: &str = "archive.extract_internal_error";

// Info error constants
pub const ARCHIVE_INFO_INVALID_ARCHIVE_PATH: &str = "archive.info_invalid_archive_path";
pub const ARCHIVE_INFO_MISSING_ARCHIVE: &str = "archive.info_missing_archive";
pub const ARCHIVE_INFO_INVALID_FORMAT: &str = "archive.info_invalid_format";
pub const ARCHIVE_INFO_INVALID_FORMAT_INFER: &str = "archive.info_invalid_format_infer";
pub const ARCHIVE_INFO_INVALID_COMPRESSION: &str = "archive.info_invalid_compression";
pub const ARCHIVE_INFO_INVALID_FORMAT_COMPRESSION: &str = "archive.info_invalid_format_compression";
pub const ARCHIVE_INFO_INVALID_MAX_ENTRIES: &str = "archive.info_invalid_max_entries";
pub const ARCHIVE_INFO_INVALID_MAX_SIZE: &str = "archive.info_invalid_max_size";
pub const ARCHIVE_INFO_IO_ERROR: &str = "archive.info_io_error";
pub const ARCHIVE_INFO_ARCHIVE_READ_ERROR: &str = "archive.info_archive_read_error";
pub const ARCHIVE_INFO_COMPRESSION_ERROR: &str = "archive.info_compression_error";
pub const ARCHIVE_INFO_7Z_UNSUPPORTED: &str = "archive.info_7z_unsupported";
pub const ARCHIVE_INFO_MAX_ENTRIES_EXCEEDED: &str = "archive.info_max_entries_exceeded";
pub const ARCHIVE_INFO_MAX_SIZE_EXCEEDED: &str = "archive.info_max_size_exceeded";
pub const ARCHIVE_INFO_INTERNAL_ERROR: &str = "archive.info_internal_error";

// Add error constants
pub const ARCHIVE_ADD_INVALID_ARCHIVE_PATH: &str = "archive.add_invalid_archive_path";
pub const ARCHIVE_ADD_MISSING_ARCHIVE: &str = "archive.add_missing_archive";
pub const ARCHIVE_ADD_INVALID_FORMAT: &str = "archive.add_invalid_format";
pub const ARCHIVE_ADD_INVALID_FORMAT_INFER: &str = "archive.add_invalid_format_infer";
pub const ARCHIVE_ADD_INVALID_COMPRESSION: &str = "archive.add_invalid_compression";
pub const ARCHIVE_ADD_INVALID_FORMAT_COMPRESSION: &str = "archive.add_invalid_format_compression";
pub const ARCHIVE_ADD_INVALID_INPUT: &str = "archive.add_invalid_input";
pub const ARCHIVE_ADD_INVALID_INCLUDE_PATTERN: &str = "archive.add_invalid_include_pattern";
pub const ARCHIVE_ADD_INVALID_EXCLUDE_PATTERN: &str = "archive.add_invalid_exclude_pattern";
pub const ARCHIVE_ADD_INVALID_MAX_ENTRIES: &str = "archive.add_invalid_max_entries";
pub const ARCHIVE_ADD_INVALID_MAX_SIZE: &str = "archive.add_invalid_max_size";
pub const ARCHIVE_ADD_UNSUPPORTED_FOR_RAW: &str = "archive.add_unsupported_for_raw";
pub const ARCHIVE_ADD_7Z_UNSUPPORTED: &str = "archive.add_7z_unsupported";
pub const ARCHIVE_ADD_IO_ERROR: &str = "archive.add_io_error";
pub const ARCHIVE_ADD_ARCHIVE_READ_ERROR: &str = "archive.add_archive_read_error";
pub const ARCHIVE_ADD_ARCHIVE_WRITE_ERROR: &str = "archive.add_archive_write_error";
pub const ARCHIVE_ADD_COMPRESSION_ERROR: &str = "archive.add_compression_error";
pub const ARCHIVE_ADD_BACKUP_FAILED: &str = "archive.add_backup_failed";
pub const ARCHIVE_ADD_MAX_ENTRIES_EXCEEDED: &str = "archive.add_max_entries_exceeded";
pub const ARCHIVE_ADD_MAX_SIZE_EXCEEDED: &str = "archive.add_max_size_exceeded";
pub const ARCHIVE_ADD_INTERNAL_ERROR: &str = "archive.add_internal_error";

// Archive remove error constants
pub const ARCHIVE_REMOVE_INVALID_ARCHIVE_PATH: &str = "archive.remove_invalid_archive_path";
pub const ARCHIVE_REMOVE_MISSING_ARCHIVE: &str = "archive.remove_missing_archive";
pub const ARCHIVE_REMOVE_NOTHING_TO_REMOVE: &str = "archive.remove_nothing_to_remove";
pub const ARCHIVE_REMOVE_INVALID_FORMAT: &str = "archive.remove_invalid_format";
pub const ARCHIVE_REMOVE_INVALID_FORMAT_INFER: &str = "archive.remove_invalid_format_infer";
pub const ARCHIVE_REMOVE_INVALID_COMPRESSION: &str = "archive.remove_invalid_compression";
pub const ARCHIVE_REMOVE_INVALID_FORMAT_COMPRESSION: &str = "archive.remove_invalid_format_compression";
pub const ARCHIVE_REMOVE_INVALID_MAX_ENTRIES: &str = "archive.remove_invalid_max_entries";
pub const ARCHIVE_REMOVE_INVALID_MAX_SIZE: &str = "archive.remove_invalid_max_size";
pub const ARCHIVE_REMOVE_UNSUPPORTED_FOR_RAW: &str = "archive.remove_unsupported_for_raw";
pub const ARCHIVE_REMOVE_7Z_UNSUPPORTED: &str = "archive.remove_7z_unsupported";
pub const ARCHIVE_REMOVE_IO_ERROR: &str = "archive.remove_io_error";
pub const ARCHIVE_REMOVE_ARCHIVE_READ_ERROR: &str = "archive.remove_archive_read_error";
pub const ARCHIVE_REMOVE_ARCHIVE_WRITE_ERROR: &str = "archive.remove_archive_write_error";
pub const ARCHIVE_REMOVE_COMPRESSION_ERROR: &str = "archive.remove_compression_error";
pub const ARCHIVE_REMOVE_BACKUP_FAILED: &str = "archive.remove_backup_failed";
pub const ARCHIVE_REMOVE_REPLACE_FAILED: &str = "archive.remove_replace_failed";
pub const ARCHIVE_REMOVE_MAX_ENTRIES_EXCEEDED: &str = "archive.remove_max_entries_exceeded";
pub const ARCHIVE_REMOVE_MAX_SIZE_EXCEEDED: &str = "archive.remove_max_size_exceeded";
pub const ARCHIVE_REMOVE_INTERNAL_ERROR: &str = "archive.remove_internal_error";

impl Handle for ArchiveHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["create", "extract", "list", "test", "info", "add", "remove"]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        match verb {
            "create" => self.verb_create(args, io),
            "extract" => self.verb_extract(args, io),
            "list" => self.verb_list(args, io),
            "test" => self.verb_test(args, io),
            "info" => self.verb_info(args, io),
            "add" => self.verb_add(args, io),
            "remove" => self.verb_remove(args, io),
            _ => bail!("unknown verb for archive://: {}", verb),
        }
    }
}

impl ArchiveHandle {
    fn verb_create(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let opts = match ArchiveCreateOptions::from_args(args) {
            Ok(opts) => opts,
            Err(e) => {
                let error_msg = map_validation_error(&e);
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        let result = create_archive(opts.clone());
        let response = match result {
            Ok(resp) => resp,
            Err(e) => {
                let error_msg = format!("[{}] {}", ARCHIVE_CREATE_INTERNAL_ERROR, e);
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        let output = match opts.output_format {
            OutputFormat::Json => response.to_json(),
            OutputFormat::Text => response.to_text(),
        };

        writeln!(io.stdout, "{}", output)?;

        if response.ok {
            Ok(Status::ok())
        } else {
            if let Some((code, message)) = &response.error {
                Ok(Status::err(1, format!("[{}] {}", code, message)))
            } else {
                Ok(Status::err(1, "Archive creation failed"))
            }
        }
    }

    fn verb_extract(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let opts = match ArchiveExtractOptions::from_args(args) {
            Ok(opts) => opts,
            Err(e) => {
                let error_msg = map_extract_validation_error(&e);
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        let result = extract_archive(opts.clone());
        let response = match result {
            Ok(resp) => resp,
            Err(e) => {
                let error_msg = format!("[{}] {}", ARCHIVE_EXTRACT_INTERNAL_ERROR, e);
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        let output = match opts.format_output {
            OutputFormat::Json => response.to_json(),
            OutputFormat::Text => response.to_text(),
        };

        writeln!(io.stdout, "{}", output)?;

        if response.ok {
            Ok(Status::ok())
        } else {
            if let Some((code, message)) = &response.error {
                Ok(Status::err(1, format!("[{}] {}", code, message)))
            } else {
                Ok(Status::err(1, "Archive extraction failed"))
            }
        }
    }

    fn verb_list(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let opts = match ArchiveListOptions::from_args(args) {
            Ok(opts) => opts,
            Err(e) => {
                let error_msg = map_list_validation_error(&e);
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        let result = list_archive(opts.clone());
        let response = match result {
            Ok(resp) => resp,
            Err(e) => {
                let error_msg = format!("[{}] {}", ARCHIVE_LIST_INTERNAL_ERROR, e);
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        let output = match opts.format_output {
            OutputFormat::Json => response.to_json(),
            OutputFormat::Text => response.to_text(),
        };

        writeln!(io.stdout, "{}", output)?;

        if response.ok {
            Ok(Status::ok())
        } else {
            if let Some((code, message)) = &response.error {
                Ok(Status::err(1, format!("[{}] {}", code, message)))
            } else {
                Ok(Status::err(1, "Archive listing failed"))
            }
        }
    }

    fn verb_test(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let opts = match ArchiveTestOptions::from_args(args) {
            Ok(opts) => opts,
            Err(e) => {
                let error_msg = map_test_validation_error(&e);
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        let result = test_archive(opts.clone());
        let response = match result {
            Ok(resp) => resp,
            Err(e) => {
                let error_msg = format!("[{}] {}", ARCHIVE_TEST_INTERNAL_ERROR, e);
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        let output = match opts.format_output {
            OutputFormat::Json => response.to_json(),
            OutputFormat::Text => response.to_text(),
        };

        writeln!(io.stdout, "{}", output)?;

        if response.ok {
            Ok(Status::ok())
        } else {
            if let Some((code, message)) = &response.error {
                Ok(Status::err(1, format!("[{}] {}", code, message)))
            } else {
                Ok(Status::err(1, "Archive test failed"))
            }
        }
    }

    fn verb_info(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let opts = match ArchiveInfoOptions::from_args(args) {
            Ok(opts) => opts,
            Err(e) => {
                let error_msg = map_info_validation_error(&e);
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        let result = info_archive(opts.clone());
        let response = match result {
            Ok(resp) => resp,
            Err(e) => {
                let error_msg = format!("[{}] {}", ARCHIVE_INFO_INTERNAL_ERROR, e);
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        let output = match opts.format_output {
            OutputFormat::Json => response.to_json(),
            OutputFormat::Text => response.to_text(),
        };

        writeln!(io.stdout, "{}", output)?;

        if response.ok {
            Ok(Status::ok())
        } else {
            if let Some((code, message)) = &response.error {
                Ok(Status::err(1, format!("[{}] {}", code, message)))
            } else {
                Ok(Status::err(1, "Archive info failed"))
            }
        }
    }

    fn verb_add(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let opts = match ArchiveAddOptions::from_args(args) {
            Ok(opts) => opts,
            Err(e) => {
                let error_msg = map_add_validation_error(&e);
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        let result = add_archive(opts.clone());
        let response = match result {
            Ok(resp) => resp,
            Err(e) => {
                let error_msg = format!("[{}] {}", ARCHIVE_ADD_INTERNAL_ERROR, e);
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        let output = match opts.format_output {
            OutputFormat::Json => response.to_json(),
            OutputFormat::Text => response.to_text(),
        };

        writeln!(io.stdout, "{}", output)?;

        if response.ok {
            Ok(Status::ok())
        } else {
            if let Some((code, message)) = &response.error {
                Ok(Status::err(1, format!("[{}] {}", code, message)))
            } else {
                Ok(Status::err(1, "Archive add failed"))
            }
        }
    }

    fn verb_remove(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let opts = match ArchiveRemoveOptions::from_args(args) {
            Ok(opts) => opts,
            Err(e) => {
                let error_msg = map_remove_validation_error(&e);
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        let result = remove_archive(opts.clone());
        let response = match result {
            Ok(resp) => resp,
            Err(e) => {
                let error_msg = format!("[{}] {}", ARCHIVE_REMOVE_INTERNAL_ERROR, e);
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        let output = match opts.format_output {
            OutputFormat::Json => response.to_json(),
            OutputFormat::Text => response.to_text(),
        };

        writeln!(io.stdout, "{}", output)?;

        if response.ok {
            Ok(Status::ok())
        } else {
            if let Some((code, message)) = &response.error {
                Ok(Status::err(1, format!("[{}] {}", code, message)))
            } else {
                Ok(Status::err(1, "Archive remove failed"))
            }
        }
    }
}

fn map_remove_validation_error(err: &anyhow::Error) -> String {
    let err_str = err.to_string();
    if err_str.contains("Missing required parameter: archive") || err_str.contains("Archive path cannot be empty") {
        format!("[{}] {}", ARCHIVE_REMOVE_INVALID_ARCHIVE_PATH, err_str)
    } else if err_str.contains("Nothing to remove") {
        format!("[{}] {}", ARCHIVE_REMOVE_NOTHING_TO_REMOVE, err_str)
    } else if err_str.contains("Unsupported archive format") || err_str.contains("Cannot detect archive format") {
        format!("[{}] {}", ARCHIVE_REMOVE_INVALID_FORMAT, err_str)
    } else if err_str.contains("Invalid paths format") {
        format!("[{}] {}", ARCHIVE_REMOVE_INVALID_ARCHIVE_PATH, err_str)
    } else if err_str.contains("Invalid patterns format") {
        format!("[{}] {}", ARCHIVE_REMOVE_INVALID_ARCHIVE_PATH, err_str)
    } else if err_str.contains("Invalid dir_prefixes format") {
        format!("[{}] {}", ARCHIVE_REMOVE_INVALID_ARCHIVE_PATH, err_str)
    } else if err_str.contains("Removing entries from raw compressed streams") {
        format!("[{}] {}", ARCHIVE_REMOVE_UNSUPPORTED_FOR_RAW, err_str)
    } else if err_str.contains("7z archive removal not yet supported") {
        format!("[{}] {}", ARCHIVE_REMOVE_7Z_UNSUPPORTED, err_str)
    } else {
        format!("[{}] {}", ARCHIVE_REMOVE_INTERNAL_ERROR, err_str)
    }
}

fn map_validation_error(err: &anyhow::Error) -> String {
    let err_str = err.to_string();
    if err_str.contains("Missing required parameter: output") {
        format!("[{}] {}", ARCHIVE_CREATE_INVALID_OUTPUT, err_str)
    } else if err_str.contains("Output path cannot be empty") {
        format!("[{}] {}", ARCHIVE_CREATE_INVALID_OUTPUT, err_str)
    } else if err_str.contains("Missing required parameter: sources") || err_str.contains("Sources list cannot be empty") {
        format!("[{}] {}", ARCHIVE_CREATE_INVALID_SOURCES, err_str)
    } else if err_str.contains("Unsupported archive format") || err_str.contains("Cannot detect archive format") {
        format!("[{}] {}", ARCHIVE_CREATE_INVALID_FORMAT, err_str)
    } else if err_str.contains("Invalid compression level") {
        format!("[{}] {}", ARCHIVE_CREATE_INVALID_COMPRESSION_LEVEL, err_str)
    } else if err_str.contains("Password protection not supported") {
        format!("[{}] {}", ARCHIVE_CREATE_PASSWORD_NOT_SUPPORTED, err_str)
    } else {
        format!("[{}] {}", ARCHIVE_CREATE_INTERNAL_ERROR, err_str)
    }
}

fn map_extract_validation_error(err: &anyhow::Error) -> String {
    let err_str = err.to_string();
    if err_str.contains("Missing required parameter: archive") {
        format!("[{}] {}", ARCHIVE_EXTRACT_INVALID_ARCHIVE_PATH, err_str)
    } else if err_str.contains("Archive path cannot be empty") {
        format!("[{}] {}", ARCHIVE_EXTRACT_INVALID_ARCHIVE_PATH, err_str)
    } else if err_str.contains("Missing required parameter: destination") {
        format!("[{}] {}", ARCHIVE_EXTRACT_INVALID_DESTINATION, err_str)
    } else if err_str.contains("Destination path cannot be empty") {
        format!("[{}] {}", ARCHIVE_EXTRACT_INVALID_DESTINATION, err_str)
    } else if err_str.contains("Unsupported archive format") || err_str.contains("Cannot detect archive format") {
        format!("[{}] {}", ARCHIVE_EXTRACT_INVALID_FORMAT_INFER, err_str)
    } else if err_str.contains("Unsupported compression") {
        format!("[{}] {}", ARCHIVE_EXTRACT_INVALID_COMPRESSION, err_str)
    } else if err_str.contains("Raw format requires") {
        format!("[{}] {}", ARCHIVE_EXTRACT_INVALID_FORMAT_COMPRESSION, err_str)
    } else if err_str.contains("Invalid includes") {
        format!("[{}] {}", ARCHIVE_EXTRACT_INVALID_INCLUDE_PATTERN, err_str)
    } else if err_str.contains("Invalid excludes") {
        format!("[{}] {}", ARCHIVE_EXTRACT_INVALID_EXCLUDE_PATTERN, err_str)
    } else {
        format!("[{}] {}", ARCHIVE_EXTRACT_INTERNAL_ERROR, err_str)
    }
}

fn map_list_validation_error(err: &anyhow::Error) -> String {
    let err_str = err.to_string();
    if err_str.contains("Missing required parameter: archive") {
        format!("[{}] {}", ARCHIVE_LIST_INVALID_ARCHIVE_PATH, err_str)
    } else if err_str.contains("Archive path cannot be empty") {
        format!("[{}] {}", ARCHIVE_LIST_INVALID_ARCHIVE_PATH, err_str)
    } else if err_str.contains("Unsupported archive format") {
        format!("[{}] {}", ARCHIVE_LIST_INVALID_FORMAT, err_str)
    } else if err_str.contains("Cannot detect archive format") {
        format!("[{}] {}", ARCHIVE_LIST_INVALID_FORMAT_INFER, err_str)
    } else if err_str.contains("Unsupported compression") {
        format!("[{}] {}", ARCHIVE_LIST_INVALID_COMPRESSION, err_str)
    } else if err_str.contains("Raw format requires") {
        format!("[{}] {}", ARCHIVE_LIST_INVALID_FORMAT_COMPRESSION, err_str)
    } else if err_str.contains("Invalid includes") {
        format!("[{}] {}", ARCHIVE_LIST_INVALID_INCLUDE_PATTERN, err_str)
    } else if err_str.contains("Invalid excludes") {
        format!("[{}] {}", ARCHIVE_LIST_INVALID_EXCLUDE_PATTERN, err_str)
    } else {
        format!("[{}] {}", ARCHIVE_LIST_INTERNAL_ERROR, err_str)
    }
}

fn map_test_validation_error(err: &anyhow::Error) -> String {
    let err_str = err.to_string();
    if err_str.contains("Missing required parameter: archive") {
        format!("[{}] {}", ARCHIVE_TEST_INVALID_ARCHIVE_PATH, err_str)
    } else if err_str.contains("Archive path cannot be empty") {
        format!("[{}] {}", ARCHIVE_TEST_INVALID_ARCHIVE_PATH, err_str)
    } else if err_str.contains("Unsupported archive format") {
        format!("[{}] {}", ARCHIVE_TEST_INVALID_FORMAT, err_str)
    } else if err_str.contains("Cannot detect archive format") {
        format!("[{}] {}", ARCHIVE_TEST_INVALID_FORMAT_INFER, err_str)
    } else if err_str.contains("Unsupported compression") {
        format!("[{}] {}", ARCHIVE_TEST_INVALID_COMPRESSION, err_str)
    } else if err_str.contains("Raw format requires") {
        format!("[{}] {}", ARCHIVE_TEST_INVALID_FORMAT_COMPRESSION, err_str)
    } else {
        format!("[{}] {}", ARCHIVE_TEST_INTERNAL_ERROR, err_str)
    }
}

fn map_info_validation_error(err: &anyhow::Error) -> String {
    let err_str = err.to_string();
    if err_str.contains("Missing required parameter: archive") {
        format!("[{}] {}", ARCHIVE_INFO_INVALID_ARCHIVE_PATH, err_str)
    } else if err_str.contains("Archive path cannot be empty") {
        format!("[{}] {}", ARCHIVE_INFO_INVALID_ARCHIVE_PATH, err_str)
    } else if err_str.contains("Unsupported archive format") {
        format!("[{}] {}", ARCHIVE_INFO_INVALID_FORMAT, err_str)
    } else if err_str.contains("Cannot detect archive format") {
        format!("[{}] {}", ARCHIVE_INFO_INVALID_FORMAT_INFER, err_str)
    } else if err_str.contains("Unsupported compression") {
        format!("[{}] {}", ARCHIVE_INFO_INVALID_COMPRESSION, err_str)
    } else if err_str.contains("Raw format requires") {
        format!("[{}] {}", ARCHIVE_INFO_INVALID_FORMAT_COMPRESSION, err_str)
    } else {
        format!("[{}] {}", ARCHIVE_INFO_INTERNAL_ERROR, err_str)
    }
}

pub fn create_archive(opts: ArchiveCreateOptions) -> Result<ArchiveCreateResponse> {
    let mut response = ArchiveCreateResponse::new(&opts);
    let start_time = Instant::now();

    // Validate output path
    let output_path = Path::new(&opts.output);
    if output_path.exists() && !opts.overwrite {
        response.ok = false;
        response.error = Some((ARCHIVE_CREATE_OUTPUT_EXISTS.to_string(), 
                             "Output file exists and overwrite=false".to_string()));
        return Ok(response);
    }

    // Validate base directory
    if let Some(ref base_dir) = opts.base_dir {
        if !Path::new(base_dir).exists() {
            response.ok = false;
            response.error = Some((ARCHIVE_CREATE_INVALID_BASE_DIR.to_string(),
                                 format!("Base directory does not exist: {}", base_dir)));
            return Ok(response);
        }
    }

    // Collect source files
    let files = match collect_source_files(&opts) {
        Ok(files) => files,
        Err(e) => {
            response.ok = false;
            response.error = Some((ARCHIVE_CREATE_SOURCE_NOT_FOUND.to_string(), e.to_string()));
            return Ok(response);
        }
    };

    // Check limits
    if files.len() > opts.max_files as usize {
        response.ok = false;
        response.error = Some((ARCHIVE_CREATE_MAX_FILES_EXCEEDED.to_string(),
                             format!("Number of files ({}) exceeds limit ({})", files.len(), opts.max_files)));
        return Ok(response);
    }

    let total_size: u64 = files.iter().map(|f| f.size_bytes).sum();
    let total_size_mb = total_size / (1024 * 1024);
    if total_size_mb > opts.max_size_mb {
        response.ok = false;
        response.error = Some((ARCHIVE_CREATE_MAX_SIZE_EXCEEDED.to_string(),
                             format!("Total size ({} MB) exceeds limit ({} MB)", total_size_mb, opts.max_size_mb)));
        return Ok(response);
    }

    // Create archive based on format
    let compressed_size = match create_archive_file(&opts, &files) {
        Ok(size) => size,
        Err(e) => {
            response.ok = false;
            response.error = Some((ARCHIVE_CREATE_COMPRESSION_FAILED.to_string(), e.to_string()));
            return Ok(response);
        }
    };

    // Calculate statistics
    let mut files_by_type = HashMap::new();
    let mut file_entries = Vec::new();
    let mut largest_files = files.clone();
    largest_files.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
    largest_files.truncate(5);

    let mut dir_count = 0;
    for file in &files {
        if file.file_type == "directory" {
            dir_count += 1;
        } else {
            let ext = Path::new(&file.path)
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("unknown")
                .to_string();
            
            *files_by_type.entry(ext).or_insert(0) += 1;
        }

        if file_entries.len() < 100 {
            file_entries.push(file.clone());
        }
    }

    let compression_ratio = if total_size > 0 {
        1.0 - (compressed_size as f64 / total_size as f64)
    } else {
        0.0
    };

    response.result = ArchiveResult {
        output_path: opts.output.clone(),
        format_detected: opts.format.as_str().to_string(),
        files_archived: (files.len() - dir_count) as u64,
        directories_archived: dir_count as u64,
        total_size_bytes: total_size,
        compressed_size_bytes: compressed_size,
        compression_ratio,
        duration_ms: start_time.elapsed().as_millis() as u64,
    };

    response.files = file_entries;
    response.statistics = ArchiveStatistics {
        files_by_type,
        largest_files,
    };

    Ok(response)
}

pub fn collect_source_files(opts: &ArchiveCreateOptions) -> Result<Vec<FileEntry>> {
    let mut files = Vec::new();
    let base_path = opts.base_dir.as_ref()
        .map(|p| Path::new(p))
        .unwrap_or_else(|| Path::new("."));

    // Build include/exclude glob sets
    let include_set = if !opts.include_patterns.is_empty() {
        let mut builder = GlobSetBuilder::new();
        for pattern in &opts.include_patterns {
            let glob = Glob::new(pattern)
                .context(format!("Invalid include pattern: {}", pattern))?;
            builder.add(glob);
        }
        Some(builder.build()?)
    } else {
        None
    };

    let exclude_set = if !opts.exclude_patterns.is_empty() {
        let mut builder = GlobSetBuilder::new();
        for pattern in &opts.exclude_patterns {
            let glob = Glob::new(pattern)
                .context(format!("Invalid exclude pattern: {}", pattern))?;
            builder.add(glob);
        }
        Some(builder.build()?)
    } else {
        None
    };

    for source in &opts.sources {
        let source_path = if Path::new(source).is_absolute() {
            PathBuf::from(source)
        } else {
            base_path.join(source)
        };

        if source.contains('*') || source.contains('?') || source.contains('[') {
            // Handle as glob pattern
            let glob = Glob::new(source)?;
            let glob_set = GlobSetBuilder::new().add(glob).build()?;
            
            // Walk from base directory
            for entry in WalkDir::new(base_path).follow_links(opts.follow_symlinks) {
                let entry = entry?;
                let relative_path = entry.path().strip_prefix(base_path)
                    .unwrap_or(entry.path());
                
                if glob_set.is_match(relative_path) {
                    if let Some(file_entry) = process_path_entry(entry.path(), base_path, &opts, &include_set, &exclude_set)? {
                        files.push(file_entry);
                    }
                }
            }
        } else {
            // Handle as regular file/directory
            if source_path.exists() {
                if source_path.is_file() {
                    if let Some(file_entry) = process_path_entry(&source_path, base_path, &opts, &include_set, &exclude_set)? {
                        files.push(file_entry);
                    }
                } else if source_path.is_dir() {
                    for entry in WalkDir::new(&source_path).follow_links(opts.follow_symlinks) {
                        let entry = entry?;
                        if let Some(file_entry) = process_path_entry(entry.path(), base_path, &opts, &include_set, &exclude_set)? {
                            files.push(file_entry);
                        }
                    }
                }
            } else {
                bail!("Source not found: {}", source);
            }
        }
    }

    Ok(files)
}

pub fn process_path_entry(
    path: &Path, 
    base_path: &Path, 
    opts: &ArchiveCreateOptions,
    include_set: &Option<globset::GlobSet>,
    exclude_set: &Option<globset::GlobSet>
) -> Result<Option<FileEntry>> {
    let relative_path = path.strip_prefix(base_path)
        .unwrap_or(path);
    
    let path_str = relative_path.to_string_lossy().to_string();

    // Check hidden files
    if !opts.include_hidden {
        if let Some(file_name) = relative_path.file_name() {
            if file_name.to_string_lossy().starts_with('.') {
                return Ok(None);
            }
        }
    }

    // Apply include patterns
    if let Some(include_set) = include_set {
        if !include_set.is_match(&path_str) {
            return Ok(None);
        }
    }

    // Apply exclude patterns (overrides include)
    if let Some(exclude_set) = exclude_set {
        if exclude_set.is_match(&path_str) {
            return Ok(None);
        }
    }

    let metadata = path.metadata()?;
    let size_bytes = metadata.len();
    let modified_unix_ms = metadata.modified()?
        .duration_since(UNIX_EPOCH)?
        .as_millis() as i64;

    let file_type = if path.is_file() {
        "file"
    } else if path.is_dir() {
        "directory"
    } else {
        "other"
    }.to_string();

    Ok(Some(FileEntry {
        path: path_str,
        size_bytes,
        modified_unix_ms,
        file_type,
    }))
}

fn create_archive_file(opts: &ArchiveCreateOptions, files: &[FileEntry]) -> Result<u64> {
    let output_path = Path::new(&opts.output);
    let base_path = opts.base_dir.as_ref()
        .map(|p| Path::new(p))
        .unwrap_or_else(|| Path::new("."));

    match opts.format {
        ArchiveFormat::Tar => create_tar_archive(output_path, base_path, files, None),
        ArchiveFormat::TarGz => {
            let level = opts.compression_level.unwrap_or(opts.format.default_compression_level());
            create_tar_archive(output_path, base_path, files, Some(Compression::new(level)))
        },
        ArchiveFormat::Zip => create_zip_archive(output_path, base_path, files, opts),
        ArchiveFormat::Gzip => create_gzip_archive(output_path, base_path, files, opts),
        _ => bail!("Archive format {} not yet implemented", opts.format.as_str()),
    }
}

fn create_tar_archive(
    output_path: &Path, 
    base_path: &Path, 
    files: &[FileEntry], 
    compression: Option<Compression>
) -> Result<u64> {
    let file = File::create(output_path)?;
    let writer = BufWriter::new(file);

    let mut archive = if let Some(comp) = compression {
        let encoder = GzEncoder::new(writer, comp);
        tar::Builder::new(Box::new(encoder) as Box<dyn Write>)
    } else {
        tar::Builder::new(Box::new(writer) as Box<dyn Write>)
    };

    for file_entry in files {
        if file_entry.file_type == "file" {
            let full_path = base_path.join(&file_entry.path);
            archive.append_path_with_name(&full_path, &file_entry.path)?;
        } else if file_entry.file_type == "directory" {
            let full_path = base_path.join(&file_entry.path);
            archive.append_dir_all(&file_entry.path, &full_path)?;
        }
    }

    archive.finish()?;
    Ok(output_path.metadata()?.len())
}

fn create_zip_archive(
    output_path: &Path, 
    base_path: &Path, 
    files: &[FileEntry], 
    opts: &ArchiveCreateOptions
) -> Result<u64> {
    let file = File::create(output_path)?;
    let mut archive = ZipWriter::new(file);

    let compression_level = opts.compression_level.unwrap_or(opts.format.default_compression_level());
    let options = FileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .compression_level(Some(compression_level as i32));

    for file_entry in files {
        if file_entry.file_type == "file" {
            let full_path = base_path.join(&file_entry.path);
            archive.start_file(&file_entry.path, options)?;
            
            let mut file = File::open(&full_path)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            archive.write_all(&buffer)?;
        } else if file_entry.file_type == "directory" {
            archive.add_directory(&file_entry.path, options)?;
        }
    }

    archive.finish()?;
    Ok(output_path.metadata()?.len())
}

fn create_gzip_archive(
    output_path: &Path, 
    base_path: &Path, 
    files: &[FileEntry], 
    opts: &ArchiveCreateOptions
) -> Result<u64> {
    if files.len() != 1 || files[0].file_type != "file" {
        bail!("GZIP format only supports single file compression");
    }

    let input_path = base_path.join(&files[0].path);
    let mut input_file = File::open(&input_path)?;
    let output_file = File::create(output_path)?;

    let compression_level = opts.compression_level.unwrap_or(opts.format.default_compression_level());
    let mut encoder = GzEncoder::new(output_file, Compression::new(compression_level));

    std::io::copy(&mut input_file, &mut encoder)?;
    encoder.finish()?;

    Ok(output_path.metadata()?.len())
}

// Helper function to resolve format and compression
fn resolve_format_and_compression(
    format: &ArchiveFormat,
    compression: &CompressionKind,
    archive_path: &str,
) -> Result<(ArchiveFormat, CompressionKind)> {
    let final_format = if *format == ArchiveFormat::Auto {
        ArchiveFormat::detect_from_extension(archive_path)?
    } else {
        format.clone()
    };

    let final_compression = if *compression == CompressionKind::Auto {
        CompressionKind::detect_from_extension(archive_path)
    } else {
        compression.clone()
    };

    Ok((final_format, final_compression))
}

// List raw compressed file (single virtual entry)
fn list_raw_compressed(
    archive_path: &str,
    compression: &CompressionKind,
    _opts: &ArchiveListOptions,
) -> Result<(Vec<ArchiveListEntry>, u64, u64)> {
    let path = Path::new(archive_path);
    let file_metadata = path.metadata()?;
    let compressed_size = file_metadata.len();
    
    // Strip compression extension for virtual entry name
    let virtual_name = match compression {
        CompressionKind::Gzip if archive_path.ends_with(".gz") => {
            archive_path.strip_suffix(".gz").unwrap_or(archive_path)
        }
        CompressionKind::Xz if archive_path.ends_with(".xz") => {
            archive_path.strip_suffix(".xz").unwrap_or(archive_path)
        }
        CompressionKind::Zstd if archive_path.ends_with(".zst") => {
            archive_path.strip_suffix(".zst").unwrap_or(archive_path)
        }
        CompressionKind::Zstd if archive_path.ends_with(".zstd") => {
            archive_path.strip_suffix(".zstd").unwrap_or(archive_path)
        }
        _ => archive_path
    };

    // For virtual name, use just the filename part
    let virtual_name = Path::new(virtual_name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    let mtime_unix = file_metadata.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64);

    let entry = ArchiveListEntry {
        path: virtual_name,
        is_dir: false,
        is_symlink: false,
        size: 0, // We don't know uncompressed size without decompressing
        compressed_size: Some(compressed_size),
        mode: None,
        uid: None,
        gid: None,
        uname: None,
        gname: None,
        mtime_unix,
    };

    Ok((vec![entry], 1, 0))
}

// List tar archive with optional compression
fn list_tar_archive(
    archive_path: &str,
    compression: &CompressionKind,
    opts: &ArchiveListOptions,
    include_globset: &Option<globset::GlobSet>,
    exclude_globset: &Option<globset::GlobSet>,
) -> Result<(Vec<ArchiveListEntry>, u64, u64)> {
    let file = File::open(archive_path)?;
    let mut manifest = Vec::new();
    let mut entries_total = 0u64;
    let mut bytes_total = 0u64;

    // Create appropriate reader based on compression
    let mut archive: Archive<Box<dyn Read>> = match compression {
        CompressionKind::None => {
            Archive::new(Box::new(file))
        }
        CompressionKind::Gzip => {
            let decoder = GzDecoder::new(file);
            Archive::new(Box::new(decoder))
        }
        CompressionKind::Xz => {
            let decoder = XzDecoder::new(file);
            Archive::new(Box::new(decoder))
        }
        CompressionKind::Zstd => {
            let decoder = ZstdDecoder::new(file)?;
            Archive::new(Box::new(decoder))
        }
        _ => bail!("Unsupported compression for tar: {:?}", compression),
    };

    for entry_result in archive.entries()? {
        entries_total += 1;

        // Check max entries limit
        if entries_total > opts.max_entries {
            bail!("Maximum entries limit exceeded: {}", opts.max_entries);
        }

        let entry = entry_result?;
        let header = entry.header();

        // Get path and normalize it
        let path_cow = entry.path()?;
        let path_str = path_cow.to_string_lossy();
        let path = if path_str.starts_with("./") {
            &path_str[2..]
        } else {
            &path_str
        };
        let path = path.to_string();

        // Apply include/exclude filters
        let should_include = if let Some(globset) = include_globset {
            globset.is_match(&path)
        } else {
            true
        };

        let should_exclude = if let Some(globset) = exclude_globset {
            globset.is_match(&path)
        } else {
            false
        };

        if !should_include || should_exclude {
            continue;
        }

        let size = header.size()?;
        bytes_total += size;

        // Check max total bytes limit
        if let Some(max_bytes) = opts.max_total_bytes {
            if bytes_total > max_bytes {
                bail!("Maximum total bytes limit exceeded: {}", max_bytes);
            }
        }

        let mode = if opts.include_metadata {
            Some(format!("{:06o}", header.mode()?))
        } else {
            None
        };

        let uid = if opts.include_metadata {
            header.uid().ok().map(|u| u as u32)
        } else {
            None
        };

        let gid = if opts.include_metadata {
            header.gid().ok().map(|g| g as u32)
        } else {
            None
        };

        let uname = if opts.include_metadata {
            header.username()?.map(|s| s.to_string())
        } else {
            None
        };

        let gname = if opts.include_metadata {
            header.groupname()?.map(|s| s.to_string())
        } else {
            None
        };

        let mtime_unix = if opts.include_metadata {
            header.mtime().ok().map(|t| t as i64)
        } else {
            None
        };

        let entry_type = header.entry_type();
        let is_dir = entry_type.is_dir();
        let is_symlink = entry_type.is_symlink() || entry_type.is_hard_link();

        manifest.push(ArchiveListEntry {
            path,
            is_dir,
            is_symlink,
            size,
            compressed_size: None, // Tar doesn't track per-entry compressed size
            mode,
            uid,
            gid,
            uname,
            gname,
            mtime_unix,
        });
    }

    Ok((manifest, entries_total, bytes_total))
}

// List zip archive
fn list_zip_archive(
    archive_path: &str,
    opts: &ArchiveListOptions,
    include_globset: &Option<globset::GlobSet>,
    exclude_globset: &Option<globset::GlobSet>,
) -> Result<(Vec<ArchiveListEntry>, u64, u64)> {
    let file = File::open(archive_path)?;
    let mut zip = zip::ZipArchive::new(file)?;
    let mut manifest = Vec::new();
    let mut entries_total = 0u64;
    let mut bytes_total = 0u64;

    for i in 0..zip.len() {
        entries_total += 1;

        // Check max entries limit
        if entries_total > opts.max_entries {
            bail!("Maximum entries limit exceeded: {}", opts.max_entries);
        }

        let file = zip.by_index(i)?;
        let path = file.name().to_string();

        // Apply include/exclude filters
        let should_include = if let Some(globset) = include_globset {
            globset.is_match(&path)
        } else {
            true
        };

        let should_exclude = if let Some(globset) = exclude_globset {
            globset.is_match(&path)
        } else {
            false
        };

        if !should_include || should_exclude {
            continue;
        }

        let size = file.size();
        bytes_total += size;

        // Check max total bytes limit
        if let Some(max_bytes) = opts.max_total_bytes {
            if bytes_total > max_bytes {
                bail!("Maximum total bytes limit exceeded: {}", max_bytes);
            }
        }

        let compressed_size = if opts.include_compressed_size {
            Some(file.compressed_size())
        } else {
            None
        };

        let is_dir = path.ends_with('/');
        let mode = if opts.include_metadata && file.unix_mode().is_some() {
            Some(format!("{:06o}", file.unix_mode().unwrap()))
        } else {
            None
        };

        let mtime_unix = if opts.include_metadata {
            file.last_modified()
                .to_time()
                .map(|tm| {
                    // Convert to unix timestamp
                    tm.unix_timestamp()
                })
                .ok()
        } else {
            None
        };

        manifest.push(ArchiveListEntry {
            path,
            is_dir,
            is_symlink: false, // ZIP doesn't typically store symlinks as separate entries
            size,
            compressed_size,
            mode,
            uid: None, // ZIP doesn't store Unix UID/GID
            gid: None,
            uname: None,
            gname: None,
            mtime_unix,
        });
    }

    Ok((manifest, entries_total, bytes_total))
}

// Test functionality
pub fn test_archive(opts: ArchiveTestOptions) -> Result<ArchiveTestResponse> {
    let mut response = ArchiveTestResponse::new(&opts);

    // Validate archive exists
    let archive_path = Path::new(&opts.archive);
    if !archive_path.exists() && opts.fail_on_missing_archive {
        response.ok = false;
        response.error = Some((
            ARCHIVE_TEST_MISSING_ARCHIVE.to_string(),
            format!("Archive '{}' does not exist.", opts.archive)
        ));
        return Ok(response);
    }

    // Determine format and compression
    let (final_format, final_compression) = match resolve_format_and_compression(&opts.format, &opts.compression, &opts.archive) {
        Ok((f, c)) => (f, c),
        Err(e) => {
            response.ok = false;
            response.error = Some((
                ARCHIVE_TEST_INVALID_FORMAT_INFER.to_string(),
                e.to_string()
            ));
            return Ok(response);
        }
    };

    let _archive_size = if archive_path.exists() {
        archive_path.metadata()?.len()
    } else {
        0
    };

    // Test archive entries based on format
    let test_result = match final_format {
        ArchiveFormat::Raw => {
            test_raw_compressed(&opts.archive, &final_compression, &opts)
        }
        ArchiveFormat::Tar | ArchiveFormat::TarGz | ArchiveFormat::TarXz | ArchiveFormat::TarZstd => {
            test_tar_archive(&opts.archive, &final_compression, &opts)
        }
        ArchiveFormat::Zip => {
            test_zip_archive(&opts.archive, &opts)
        }
        ArchiveFormat::SevenZ => {
            response.ok = false;
            response.error = Some((
                ARCHIVE_TEST_7Z_UNSUPPORTED.to_string(),
                "7z archive testing is not supported in this build.".to_string()
            ));
            return Ok(response);
        }
        _ => {
            response.ok = false;
            response.error = Some((
                ARCHIVE_TEST_INVALID_FORMAT.to_string(),
                format!("Unsupported format for testing: {:?}", final_format)
            ));
            return Ok(response);
        }
    };

    match test_result {
        Ok((entries, summary)) => {
            response.summary = Some(ArchiveTestSummary {
                archive: opts.archive.clone(),
                format: final_format.as_str().to_string(),
                compression: final_compression.as_str().to_string(),
                entries_tested: summary.entries_tested,
                entries_failed: summary.entries_failed,
                bytes_tested: summary.bytes_tested,
                valid: summary.entries_failed == 0,
                stopped_early: summary.stopped_early,
            });

            if opts.report_entries {
                response.entries = Some(entries);
            }

            if summary.entries_failed > 0 {
                response.ok = false;
                response.error = Some((
                    ARCHIVE_TEST_ENTRY_FAILED.to_string(),
                    "One or more entries failed integrity checks.".to_string()
                ));
            }
        }
        Err(e) => {
            response.ok = false;
            response.error = Some((
                ARCHIVE_TEST_INTERNAL_ERROR.to_string(),
                e.to_string()
            ));
        }
    }

    Ok(response)
}

// Internal struct for test summaries
struct TestSummary {
    entries_tested: u64,
    entries_failed: u64,
    bytes_tested: u64,
    stopped_early: bool,
}

// Test raw compressed file (single stream)
fn test_raw_compressed(
    archive_path: &str,
    compression: &CompressionKind,
    opts: &ArchiveTestOptions,
) -> Result<(Vec<ArchiveTestEntryResult>, TestSummary)> {
    use std::io::Read;

    let file = File::open(archive_path)?;
    let mut reader: Box<dyn Read> = Box::new(file);

    // Apply decompression
    match compression {
        CompressionKind::Gzip => {
            reader = Box::new(GzDecoder::new(reader));
        }
        CompressionKind::Xz => {
            reader = Box::new(XzDecoder::new(reader));
        }
        CompressionKind::Zstd => {
            reader = Box::new(ZstdDecoder::new(reader)?);
        }
        CompressionKind::None | CompressionKind::Auto => {
            return Err(anyhow::anyhow!("Raw format requires compression"));
        }
    }

    let mut entries = Vec::new();
    let mut bytes_tested = 0u64;
    let entry_path = Path::new(archive_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("data")
        .to_string();

    let mut entry_result = ArchiveTestEntryResult {
        path: entry_path,
        is_dir: false,
        is_symlink: false,
        size: 0,
        status: "ok".to_string(),
        error_code: None,
        error_message: None,
    };

    // Read entire stream to verify decompression
    if opts.verify_data {
        let mut buffer = [0u8; 8192];
        let mut total_size = 0u64;
        
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    total_size += n as u64;
                    bytes_tested += n as u64;
                    
                    // Check limits
                    if let Some(max_file_bytes) = opts.max_file_bytes {
                        if total_size > max_file_bytes {
                            entry_result.status = "error".to_string();
                            entry_result.error_code = Some(ARCHIVE_TEST_MAX_FILE_SIZE_EXCEEDED.to_string());
                            entry_result.error_message = Some(format!("Entry size {} exceeds max_file_bytes {}", total_size, max_file_bytes));
                            break;
                        }
                    }
                    
                    if let Some(max_total_bytes) = opts.max_total_bytes {
                        if bytes_tested > max_total_bytes {
                            return Err(anyhow::anyhow!(ARCHIVE_TEST_MAX_SIZE_EXCEEDED));
                        }
                    }
                }
                Err(e) => {
                    entry_result.status = "error".to_string();
                    entry_result.error_code = Some(ARCHIVE_TEST_ENTRY_COMPRESSION_ERROR.to_string());
                    entry_result.error_message = Some(e.to_string());
                    break;
                }
            }
        }
        
        entry_result.size = total_size;
    }

    let entries_failed = if entry_result.status == "error" { 1 } else { 0 };
    entries.push(entry_result);

    Ok((entries, TestSummary {
        entries_tested: 1,
        entries_failed,
        bytes_tested,
        stopped_early: false,
    }))
}

// Test tar archive with optional compression
fn test_tar_archive(
    archive_path: &str,
    compression: &CompressionKind,
    opts: &ArchiveTestOptions,
) -> Result<(Vec<ArchiveTestEntryResult>, TestSummary)> {
    use std::io::{Read, copy};

    let archive_file = File::open(archive_path)?;
    let mut archive: Box<dyn Read> = Box::new(archive_file);

    // Handle decompression
    match compression {
        CompressionKind::Gzip => {
            archive = Box::new(GzDecoder::new(archive));
        }
        CompressionKind::Xz => {
            archive = Box::new(XzDecoder::new(archive));
        }
        CompressionKind::Zstd => {
            archive = Box::new(ZstdDecoder::new(archive)?);
        }
        _ => {} // No compression or auto-detected
    }

    let mut tar = Archive::new(archive);
    let mut entries = Vec::new();
    let mut bytes_tested = 0u64;
    let mut entries_tested = 0u64;
    let mut entries_failed = 0u64;
    let mut stopped_early = false;

    let tar_entries = match tar.entries() {
        Ok(entries) => entries,
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to read tar entries: {}", e));
        }
    };

    for entry in tar_entries {
        // Check entry limit
        if entries_tested >= opts.max_entries {
            stopped_early = true;
            break;
        }

        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                let err_entry = ArchiveTestEntryResult {
                    path: format!("entry_{}", entries_tested),
                    is_dir: false,
                    is_symlink: false,
                    size: 0,
                    status: "error".to_string(),
                    error_code: Some(ARCHIVE_TEST_ENTRY_HEADER_ERROR.to_string()),
                    error_message: Some(e.to_string()),
                };
                entries.push(err_entry);
                entries_failed += 1;
                entries_tested += 1;
                
                if opts.stop_on_first_error {
                    stopped_early = true;
                    break;
                }
                continue;
            }
        };

        let header = entry.header();
        let path = entry.path()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| format!("entry_{}", entries_tested));

        let size = header.size().unwrap_or(0);
        let is_dir = header.entry_type().is_dir();
        let is_symlink = header.entry_type().is_symlink();

        let mut entry_result = ArchiveTestEntryResult {
            path: path.clone(),
            is_dir,
            is_symlink,
            size,
            status: "ok".to_string(),
            error_code: None,
            error_message: None,
        };

        // Test reading the entry data if verify_data is enabled and it's not a directory
        if opts.verify_data && !is_dir && size > 0 {
            // Check file size limit
            if let Some(max_file_bytes) = opts.max_file_bytes {
                if size > max_file_bytes {
                    entry_result.status = "error".to_string();
                    entry_result.error_code = Some(ARCHIVE_TEST_MAX_FILE_SIZE_EXCEEDED.to_string());
                    entry_result.error_message = Some(format!("Entry size {} exceeds max_file_bytes {}", size, max_file_bytes));
                    entries_failed += 1;
                }
            }

            // Check total bytes limit
            if let Some(max_total_bytes) = opts.max_total_bytes {
                if bytes_tested + size > max_total_bytes {
                    return Err(anyhow::anyhow!(ARCHIVE_TEST_MAX_SIZE_EXCEEDED));
                }
            }

            if entry_result.status == "ok" {
                // Read the entry data to verify integrity
                match copy(&mut entry.take(size), &mut std::io::sink()) {
                    Ok(bytes_read) => {
                        bytes_tested += bytes_read;
                        if bytes_read != size {
                            entry_result.status = "error".to_string();
                            entry_result.error_code = Some(ARCHIVE_TEST_ENTRY_SIZE_MISMATCH.to_string());
                            entry_result.error_message = Some(format!("Expected {} bytes, read {}", size, bytes_read));
                            entries_failed += 1;
                        }
                    }
                    Err(e) => {
                        entry_result.status = "error".to_string();
                        entry_result.error_code = Some(ARCHIVE_TEST_ENTRY_IO_ERROR.to_string());
                        entry_result.error_message = Some(e.to_string());
                        entries_failed += 1;
                    }
                }
            }
        }

        entries.push(entry_result);
        entries_tested += 1;

        if entries_failed > 0 && opts.stop_on_first_error {
            stopped_early = true;
            break;
        }
    }

    Ok((entries, TestSummary {
        entries_tested,
        entries_failed,
        bytes_tested,
        stopped_early,
    }))
}

// Test zip archive
fn test_zip_archive(
    archive_path: &str,
    opts: &ArchiveTestOptions,
) -> Result<(Vec<ArchiveTestEntryResult>, TestSummary)> {
    use std::io::{Read, copy};

    let file = File::open(archive_path)?;
    let mut archive = ZipArchive::new(file)?;
    
    let mut entries = Vec::new();
    let mut bytes_tested = 0u64;
    let mut entries_failed = 0u64;
    let mut stopped_early = false;
    let entry_count = archive.len() as u64;

    let entries_tested = if entry_count > opts.max_entries {
        stopped_early = true;
        opts.max_entries
    } else {
        entry_count
    };

    for i in 0..entries_tested {
        let zip_file = match archive.by_index(i as usize) {
            Ok(f) => f,
            Err(e) => {
                let err_entry = ArchiveTestEntryResult {
                    path: format!("entry_{}", i),
                    is_dir: false,
                    is_symlink: false,
                    size: 0,
                    status: "error".to_string(),
                    error_code: Some(ARCHIVE_TEST_ENTRY_HEADER_ERROR.to_string()),
                    error_message: Some(e.to_string()),
                };
                entries.push(err_entry);
                entries_failed += 1;
                
                if opts.stop_on_first_error {
                    stopped_early = true;
                    break;
                }
                continue;
            }
        };

        let path = zip_file.name().to_string();
        let size = zip_file.size();
        let is_dir = zip_file.is_dir();

        let mut entry_result = ArchiveTestEntryResult {
            path: path.clone(),
            is_dir,
            is_symlink: false, // ZIP doesn't typically store symlinks as separate entries
            size,
            status: "ok".to_string(),
            error_code: None,
            error_message: None,
        };

        // Test reading the file data if verify_data is enabled and it's not a directory
        if opts.verify_data && !is_dir && size > 0 {
            // Check file size limit
            if let Some(max_file_bytes) = opts.max_file_bytes {
                if size > max_file_bytes {
                    entry_result.status = "error".to_string();
                    entry_result.error_code = Some(ARCHIVE_TEST_MAX_FILE_SIZE_EXCEEDED.to_string());
                    entry_result.error_message = Some(format!("Entry size {} exceeds max_file_bytes {}", size, max_file_bytes));
                    entries_failed += 1;
                }
            }

            // Check total bytes limit
            if let Some(max_total_bytes) = opts.max_total_bytes {
                if bytes_tested + size > max_total_bytes {
                    return Err(anyhow::anyhow!(ARCHIVE_TEST_MAX_SIZE_EXCEEDED));
                }
            }

            if entry_result.status == "ok" {
                // Read the file data to verify integrity (includes CRC check)
                match copy(&mut zip_file.take(size), &mut std::io::sink()) {
                    Ok(bytes_read) => {
                        bytes_tested += bytes_read;
                        if bytes_read != size {
                            entry_result.status = "error".to_string();
                            entry_result.error_code = Some(ARCHIVE_TEST_ENTRY_SIZE_MISMATCH.to_string());
                            entry_result.error_message = Some(format!("Expected {} bytes, read {}", size, bytes_read));
                            entries_failed += 1;
                        }
                    }
                    Err(e) => {
                        // This will catch CRC errors and other integrity issues
                        entry_result.status = "error".to_string();
                        entry_result.error_code = Some(ARCHIVE_TEST_ENTRY_CHECKSUM_ERROR.to_string());
                        entry_result.error_message = Some(e.to_string());
                        entries_failed += 1;
                    }
                }
            }
        }

        entries.push(entry_result);

        if entries_failed > 0 && opts.stop_on_first_error {
            stopped_early = true;
            break;
        }
    }

    Ok((entries, TestSummary {
        entries_tested,
        entries_failed,
        bytes_tested,
        stopped_early,
    }))
}

// List functionality
pub fn list_archive(opts: ArchiveListOptions) -> Result<ArchiveListResponse> {
    let mut response = ArchiveListResponse::new(&opts);

    // Validate archive exists
    let archive_path = Path::new(&opts.archive);
    if !archive_path.exists() && opts.fail_on_missing_archive {
        response.ok = false;
        response.error = Some((
            ARCHIVE_LIST_MISSING_ARCHIVE.to_string(),
            format!("Archive '{}' does not exist.", opts.archive)
        ));
        return Ok(response);
    }

    // Build include/exclude glob sets
    let include_globset = if opts.includes.is_empty() {
        None
    } else {
        let mut builder = GlobSetBuilder::new();
        for pattern in &opts.includes {
            let glob = Glob::new(pattern)
                .map_err(|_| {
                    anyhow::anyhow!("Invalid include pattern: {}", pattern)
                })?;
            builder.add(glob);
        }
        Some(builder.build()?)
    };

    let exclude_globset = if opts.excludes.is_empty() {
        None
    } else {
        let mut builder = GlobSetBuilder::new();
        for pattern in &opts.excludes {
            let glob = Glob::new(pattern)
                .map_err(|_| {
                    anyhow::anyhow!("Invalid exclude pattern: {}", pattern)
                })?;
            builder.add(glob);
        }
        Some(builder.build()?)
    };

    let (final_format, final_compression) = resolve_format_and_compression(&opts.format, &opts.compression, &opts.archive)?;

    let archive_size = if archive_path.exists() {
        archive_path.metadata()?.len()
    } else {
        0
    };

    // List archive entries based on format
    let (manifest, entries_total, bytes_total) = match final_format {
        ArchiveFormat::Raw => {
            list_raw_compressed(&opts.archive, &final_compression, &opts)?
        }
        ArchiveFormat::Tar | ArchiveFormat::TarGz | ArchiveFormat::TarXz | ArchiveFormat::TarZstd => {
            list_tar_archive(&opts.archive, &final_compression, &opts, &include_globset, &exclude_globset)?
        }
        ArchiveFormat::Zip => {
            list_zip_archive(&opts.archive, &opts, &include_globset, &exclude_globset)?
        }
        ArchiveFormat::SevenZ => {
            response.ok = false;
            response.error = Some((
                ARCHIVE_LIST_7Z_UNSUPPORTED.to_string(),
                "7z archive listing is not supported in this build.".to_string()
            ));
            return Ok(response);
        }
        _ => {
            response.ok = false;
            response.error = Some((
                ARCHIVE_LIST_INVALID_FORMAT.to_string(),
                format!("Unsupported format for listing: {:?}", final_format)
            ));
            return Ok(response);
        }
    };

    let entries_listed = manifest.len() as u64;

    response.summary = Some(ArchiveListSummary {
        archive: opts.archive.clone(),
        format: final_format.as_str().to_string(),
        compression: final_compression.as_str().to_string(),
        entries_total,
        entries_listed,
        bytes_total,
        bytes_compressed: if archive_size > 0 { Some(archive_size) } else { None },
    });

    response.manifest = Some(manifest);

    Ok(response)
}

// Extract functionality
pub fn extract_archive(opts: ArchiveExtractOptions) -> Result<ArchiveExtractResponse> {
    let mut response = ArchiveExtractResponse::new(&opts);
    let start_time = Instant::now();

    // Validate archive exists
    let archive_path = Path::new(&opts.archive);
    if !archive_path.exists() && opts.fail_on_missing_archive {
        response.ok = false;
        response.error = Some((ARCHIVE_EXTRACT_MISSING_ARCHIVE.to_string(),
                             format!("Archive '{}' does not exist.", opts.archive)));
        return Ok(response);
    }

    // Validate destination
    let dest_path = Path::new(&opts.destination);
    if !dest_path.exists() {
        if opts.create_destination {
            if let Err(e) = create_dir_all(&dest_path) {
                response.ok = false;
                response.error = Some((ARCHIVE_EXTRACT_DESTINATION_CREATE_FAILED.to_string(),
                                     format!("Failed to create destination directory: {}", e)));
                return Ok(response);
            }
        } else {
            response.ok = false;
            response.error = Some((ARCHIVE_EXTRACT_DESTINATION_MISSING.to_string(),
                                 format!("Destination '{}' does not exist and create_destination=false.", opts.destination)));
            return Ok(response);
        }
    }

    // Build include/exclude filters
    let include_set = build_glob_set(&opts.includes, "include")?;
    let exclude_set = build_glob_set(&opts.excludes, "exclude")?;

    // Extract based on format and compression
    let extract_result = match (&opts.format, &opts.compression) {
        (ArchiveFormat::Auto, _) | (ArchiveFormat::Tar, _) |
        (ArchiveFormat::TarGz, _) | (ArchiveFormat::TarXz, _) | (ArchiveFormat::TarZstd, _) => {
            extract_tar_archive(&opts, &include_set, &exclude_set)
        }
        (ArchiveFormat::Zip, _) => {
            extract_zip_archive(&opts, &include_set, &exclude_set)
        }
        (ArchiveFormat::SevenZ, _) => {
            Err(anyhow::anyhow!("7z extraction not yet supported"))
        }
        (ArchiveFormat::Raw, _) | (ArchiveFormat::Gzip, _) => {
            extract_raw_compressed_file(&opts)
        }
    };

    match extract_result {
        Ok((summary, manifest, warnings)) => {
            response.ok = true;
            response.summary = Some(summary);
            if opts.include_manifest {
                response.manifest = Some(manifest);
            }
            response.warnings = warnings;
        }
        Err(e) => {
            response.ok = false;
            response.error = Some((ARCHIVE_EXTRACT_ARCHIVE_READ_ERROR.to_string(), e.to_string()));
        }
    }

    // Update duration
    if let Some(ref mut summary) = response.summary {
        summary.duration_ms = start_time.elapsed().as_millis() as u64;
    }

    Ok(response)
}

// Add functionality
pub fn add_archive(opts: ArchiveAddOptions) -> Result<ArchiveAddResponse> {
    let mut response = ArchiveAddResponse::new(&opts);

    // Validate archive exists
    let archive_path = Path::new(&opts.archive);
    if !archive_path.exists() {
        response.ok = false;
        response.error = Some((
            ARCHIVE_ADD_MISSING_ARCHIVE.to_string(),
            format!("Archive '{}' does not exist.", opts.archive)
        ));
        return Ok(response);
    }

    let (final_format, final_compression) = match resolve_format_and_compression(&opts.format, &opts.compression, &opts.archive) {
        Ok(result) => result,
        Err(e) => {
            response.ok = false;
            response.error = Some((
                ARCHIVE_ADD_INVALID_FORMAT_INFER.to_string(),
                format!("Cannot determine archive format: {}", e)
            ));
            return Ok(response);
        }
    };

    // Check if raw format (not supported for add)
    if final_format == ArchiveFormat::Raw {
        response.ok = false;
        response.error = Some((
            ARCHIVE_ADD_UNSUPPORTED_FOR_RAW.to_string(),
            "Adding entries to raw compressed streams (gzip/xz/zstd) is not supported.".to_string()
        ));
        return Ok(response);
    }

    // Check if 7z format (not yet supported)
    if final_format == ArchiveFormat::SevenZ {
        response.ok = false;
        response.error = Some((
            ARCHIVE_ADD_7Z_UNSUPPORTED.to_string(),
            "7z archive modification not yet supported.".to_string()
        ));
        return Ok(response);
    }

    // Build include/exclude glob sets
    let include_set = match build_glob_set(&opts.includes, "include") {
        Ok(set) => set,
        Err(e) => {
            response.ok = false;
            response.error = Some((
                ARCHIVE_ADD_INVALID_INCLUDE_PATTERN.to_string(),
                e.to_string()
            ));
            return Ok(response);
        }
    };

    let exclude_set = match build_glob_set(&opts.excludes, "exclude") {
        Ok(set) => set,
        Err(e) => {
            response.ok = false;
            response.error = Some((
                ARCHIVE_ADD_INVALID_EXCLUDE_PATTERN.to_string(),
                e.to_string()
            ));
            return Ok(response);
        }
    };

    // Process inputs and collect new entries
    let new_entries = match collect_new_entries(&opts, &include_set, &exclude_set) {
        Ok(entries) => entries,
        Err(e) => {
            response.ok = false;
            response.error = Some((
                ARCHIVE_ADD_IO_ERROR.to_string(),
                format!("Failed to process inputs: {}", e)
            ));
            return Ok(response);
        }
    };

    // Get original archive size
    let archive_size_before = archive_path.metadata()?.len();

    // Perform the add operation based on format
    let add_result = match (&final_format, &final_compression) {
        (ArchiveFormat::Auto, _) | (ArchiveFormat::Tar, _) |
        (ArchiveFormat::TarGz, _) | (ArchiveFormat::TarXz, _) | (ArchiveFormat::TarZstd, _) => {
            add_to_tar_archive(&opts, &final_format, &final_compression, &new_entries)
        }
        (ArchiveFormat::Zip, _) => {
            add_to_zip_archive(&opts, &new_entries)
        }
        _ => {
            response.ok = false;
            response.error = Some((
                ARCHIVE_ADD_INTERNAL_ERROR.to_string(),
                format!("Unsupported format for add: {:?}", final_format)
            ));
            return Ok(response);
        }
    };

    match add_result {
        Ok((summary, details, warnings)) => {
            response.ok = true;
            response.summary = Some(summary);
            response.details = Some(details);
            response.warnings = warnings;
        }
        Err(e) => {
            response.ok = false;
            response.error = Some((ARCHIVE_ADD_ARCHIVE_WRITE_ERROR.to_string(), e.to_string()));
        }
    }

    Ok(response)
}

#[derive(Debug, Clone)]
pub struct NewArchiveEntry {
    pub archive_path: String,
    pub source_path: PathBuf,
    pub is_dir: bool,
    pub size: u64,
}

pub fn collect_new_entries(
    opts: &ArchiveAddOptions,
    include_set: &Option<globset::GlobSet>,
    exclude_set: &Option<globset::GlobSet>,
) -> Result<Vec<NewArchiveEntry>> {
    let mut entries = Vec::new();

    for input in &opts.inputs {
        if input.starts_with("glob:") {
            // Handle glob pattern - expand using globset
            let pattern = &input[5..];
            expand_glob_pattern(pattern, opts, include_set, exclude_set, &mut entries)?;
        } else {
            // Handle regular path
            let path = Path::new(input);
            collect_entries_from_path(path, &entries.len(), opts, include_set, exclude_set, &mut entries)?;
        }
    }

    // Check safety limits
    if entries.len() as u64 > opts.max_entries {
        bail!("Too many entries collected: {} > {}", entries.len(), opts.max_entries);
    }

    if let Some(max_bytes) = opts.max_total_bytes {
        let total_size: u64 = entries.iter().map(|e| e.size).sum();
        if total_size > max_bytes {
            bail!("Total size exceeds limit: {} > {}", total_size, max_bytes);
        }
    }

    Ok(entries)
}

fn expand_glob_pattern(
    pattern: &str,
    opts: &ArchiveAddOptions,
    include_set: &Option<globset::GlobSet>,
    exclude_set: &Option<globset::GlobSet>,
    entries: &mut Vec<NewArchiveEntry>,
) -> Result<()> {
    // Create a glob matcher for the pattern
    let glob = Glob::new(pattern)
        .with_context(|| format!("Invalid glob pattern: {}", pattern))?;
    let matcher = glob.compile_matcher();
    
    // Determine the base directory to search from
    // Extract the static prefix from the glob pattern to minimize search space
    let base_dir = extract_glob_base_dir(pattern);
    let search_root = if base_dir.is_empty() || base_dir == "." {
        std::env::current_dir()?
    } else {
        PathBuf::from(&base_dir)
    };
    
    // If the search root doesn't exist, no matches
    if !search_root.exists() {
        return Ok(());
    }
    
    // Walk the directory tree and test against the glob pattern
    let walker = WalkDir::new(&search_root)
        .follow_links(opts.follow_symlinks)
        .min_depth(0);
    
    for entry in walker {
        let entry = entry.with_context(|| "Failed to read directory entry during glob expansion")?;
        let path = entry.path();
        
        // Convert to relative path for pattern matching
        let relative_path = if let Ok(rel) = path.strip_prefix(&search_root) {
            if base_dir.is_empty() || base_dir == "." {
                rel.to_path_buf()
            } else {
                Path::new(&base_dir).join(rel)
            }
        } else {
            path.to_path_buf()
        };
        
        // Test if the path matches the glob pattern
        let path_str = relative_path.to_string_lossy();
        if matcher.is_match(path_str.as_ref()) {
            // Found a match, add it to entries
            collect_entries_from_path(path, &entries.len(), opts, include_set, exclude_set, entries)
                .with_context(|| format!("Failed to process glob match: {}", path_str))?;
        }
    }
    
    Ok(())
}

fn extract_glob_base_dir(pattern: &str) -> String {
    // Find the first component that contains glob metacharacters
    let components = pattern.split('/');
    let mut base_parts = Vec::new();
    
    for component in components {
        if component.contains('*') || component.contains('?') || component.contains('[') || component.contains('{') {
            break;
        }
        base_parts.push(component);
    }
    
    if base_parts.is_empty() {
        ".".to_string()
    } else {
        // Join the non-glob parts to form the base directory
        base_parts.join("/")
    }
}

fn collect_entries_from_path(
    path: &Path,
    _entry_count: &usize,
    opts: &ArchiveAddOptions,
    include_set: &Option<globset::GlobSet>,
    exclude_set: &Option<globset::GlobSet>,
    entries: &mut Vec<NewArchiveEntry>,
) -> Result<()> {
    let metadata = if opts.follow_symlinks {
        path.metadata()?
    } else {
        path.symlink_metadata()?
    };

    if metadata.is_dir() {
        // Add directory entry
        let archive_path = compute_archive_path(path, opts)?;
        if should_include_entry(&archive_path, include_set, exclude_set) {
            entries.push(NewArchiveEntry {
                archive_path: archive_path.clone(),
                source_path: path.to_path_buf(),
                is_dir: true,
                size: 0,
            });
        }

        // Walk directory recursively
        for entry in WalkDir::new(path).min_depth(1).follow_links(opts.follow_symlinks) {
            let entry = entry?;
            let entry_path = entry.path();
            let entry_metadata = if opts.follow_symlinks {
                entry_path.metadata()?
            } else {
                entry_path.symlink_metadata()?
            };

            let archive_path = compute_archive_path(entry_path, opts)?;
            if should_include_entry(&archive_path, include_set, exclude_set) {
                entries.push(NewArchiveEntry {
                    archive_path,
                    source_path: entry_path.to_path_buf(),
                    is_dir: entry_metadata.is_dir(),
                    size: if entry_metadata.is_file() { entry_metadata.len() } else { 0 },
                });
            }
        }
    } else {
        // Add file entry
        let archive_path = compute_archive_path(path, opts)?;
        if should_include_entry(&archive_path, include_set, exclude_set) {
            entries.push(NewArchiveEntry {
                archive_path,
                source_path: path.to_path_buf(),
                is_dir: false,
                size: metadata.len(),
            });
        }
    }

    Ok(())
}

fn compute_archive_path(path: &Path, opts: &ArchiveAddOptions) -> Result<String> {
    let normalized_path = if let Some(ref base_dir) = opts.base_dir {
        let base = Path::new(base_dir);
        match path.strip_prefix(base) {
            Ok(relative) => relative.to_path_buf(),
            Err(_) => {
                // Path is not under base_dir, use relative path without leading /
                let path_str = path.to_string_lossy();
                Path::new(path_str.trim_start_matches('/')).to_path_buf()
            }
        }
    } else {
        // Use path as-is but remove leading /
        let path_str = path.to_string_lossy();
        Path::new(path_str.trim_start_matches('/')).to_path_buf()
    };

    Ok(normalized_path.to_string_lossy().replace('\\', "/"))
}

fn should_include_entry(
    archive_path: &str,
    include_set: &Option<globset::GlobSet>,
    exclude_set: &Option<globset::GlobSet>,
) -> bool {
    // Check includes first
    if let Some(includes) = include_set {
        if !includes.is_match(archive_path) {
            return false;
        }
    }

    // Check excludes
    if let Some(excludes) = exclude_set {
        if excludes.is_match(archive_path) {
            return false;
        }
    }

    true
}

fn add_to_tar_archive(
    opts: &ArchiveAddOptions,
    format: &ArchiveFormat,
    compression: &CompressionKind,
    new_entries: &[NewArchiveEntry],
) -> Result<(ArchiveAddSummary, ArchiveAddDetails, Vec<String>)> {
    let archive_path = Path::new(&opts.archive);
    let archive_size_before = archive_path.metadata()?.len();

    // Read existing archive entries
    let existing_entries = read_existing_tar_entries(&opts.archive, compression)?;
    let entries_before = existing_entries.len() as u64;
    let uncompressed_bytes_before: u64 = existing_entries.iter().map(|e| e.size).sum();

    // Create temporary file for new archive
    let tmp_path = if let Some(ref tmp_dir) = opts.tmp_dir {
        let tmp_dir_path = Path::new(tmp_dir);
        create_dir_all(tmp_dir_path)?;
        tmp_dir_path.join(format!(".tmp_archive_{}", std::process::id()))
    } else {
        archive_path.with_extension(&format!("tmp_{}", std::process::id()))
    };

    // Create backup if requested
    if let Some(ref suffix) = opts.backup_suffix {
        let backup_path = PathBuf::from(&opts.archive).with_extension(&format!("{}.{}", 
            archive_path.extension().unwrap_or_default().to_string_lossy(), suffix));
        std::fs::copy(&opts.archive, &backup_path)
            .context("Failed to create backup")?;
    }

    // Build index of existing entries for conflict detection
    let mut existing_paths: HashMap<String, usize> = HashMap::new();
    for (idx, entry) in existing_entries.iter().enumerate() {
        existing_paths.insert(entry.path.clone(), idx);
    }

    // Process new entries for conflicts
    let mut details = ArchiveAddDetails {
        added: Vec::new(),
        replaced: Vec::new(),
        skipped: Vec::new(),
    };
    let mut warnings = Vec::new();

    let mut final_entries = existing_entries.clone();
    let mut entries_to_add = Vec::new();

    for new_entry in new_entries {
        if let Some(&existing_idx) = existing_paths.get(&new_entry.archive_path) {
            if opts.overwrite {
                // Mark existing entry for replacement
                details.replaced.push(new_entry.archive_path.clone());
                final_entries[existing_idx].replaced = true;
                entries_to_add.push(new_entry.clone());
            } else {
                // Skip due to conflict
                details.skipped.push(ArchiveAddSkippedEntry {
                    path: new_entry.archive_path.clone(),
                    reason: "already exists and overwrite=false".to_string(),
                });
                warnings.push(format!("Skipped '{}' because overwrite=false and entry exists.", 
                                    new_entry.archive_path));
            }
        } else {
            // New entry to add
            details.added.push(new_entry.archive_path.clone());
            entries_to_add.push(new_entry.clone());
        }
    }

    // Write new archive
    write_tar_archive(&tmp_path, &final_entries, &entries_to_add, format, compression, opts)?;

    // Get new archive size
    let archive_size_after = tmp_path.metadata()?.len();
    let entries_after = (final_entries.len() - final_entries.iter().filter(|e| e.replaced).count() + entries_to_add.len()) as u64;
    let uncompressed_bytes_after = uncompressed_bytes_before + entries_to_add.iter().map(|e| e.size).sum::<u64>() 
        - final_entries.iter().filter(|e| e.replaced).map(|e| e.size).sum::<u64>();

    // Atomic replace
    std::fs::rename(&tmp_path, &opts.archive)?;

    let summary = ArchiveAddSummary {
        archive: opts.archive.clone(),
        format: format.as_str().to_string(),
        compression: compression.as_str().to_string(),
        entries_before,
        entries_after,
        entries_added: details.added.len() as u64,
        entries_replaced: details.replaced.len() as u64,
        entries_skipped: details.skipped.len() as u64,
        uncompressed_bytes_before,
        uncompressed_bytes_after,
        archive_size_bytes_before: archive_size_before,
        archive_size_bytes_after: archive_size_after,
    };

    Ok((summary, details, warnings))
}

#[derive(Clone, Debug)]
struct ExistingTarEntry {
    path: String,
    size: u64,
    data: Vec<u8>,
    replaced: bool,
}

fn read_existing_tar_entries(archive_path: &str, compression: &CompressionKind) -> Result<Vec<ExistingTarEntry>> {
    let file = File::open(archive_path)?;
    let reader: Box<dyn Read> = match compression {
        CompressionKind::None => Box::new(file),
        CompressionKind::Gzip => Box::new(GzDecoder::new(file)),
        CompressionKind::Xz => Box::new(XzDecoder::new(file)),
        CompressionKind::Zstd => Box::new(ZstdDecoder::new(file)?),
        _ => return Ok(Vec::new()),
    };

    let mut archive = tar::Archive::new(reader);
    let mut entries = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().to_string();
        let size = entry.size();
        
        let mut data = Vec::new();
        entry.read_to_end(&mut data)?;

        entries.push(ExistingTarEntry {
            path,
            size,
            data,
            replaced: false,
        });
    }

    Ok(entries)
}

fn write_tar_archive(
    output_path: &Path,
    existing_entries: &[ExistingTarEntry],
    new_entries: &[NewArchiveEntry],
    format: &ArchiveFormat,
    compression: &CompressionKind,
    _opts: &ArchiveAddOptions,
) -> Result<()> {
    let file = File::create(output_path)?;
    
    let writer: Box<dyn Write> = match compression {
        CompressionKind::None => Box::new(file),
        CompressionKind::Gzip => Box::new(GzEncoder::new(file, flate2::Compression::default())),
        CompressionKind::Xz => Box::new(XzEncoder::new(file, 6)),
        CompressionKind::Zstd => Box::new(ZstdEncoder::new(file, 3)?),
        _ => return Err(anyhow::anyhow!("Unsupported compression: {:?}", compression)),
    };

    let mut tar = tar::Builder::new(writer);

    // Write existing entries (not replaced)
    for entry in existing_entries {
        if !entry.replaced {
            let mut header = tar::Header::new_gnu();
            header.set_path(&entry.path)?;
            header.set_size(entry.size);
            header.set_cksum();
            tar.append(&header, entry.data.as_slice())?;
        }
    }

    // Write new entries
    for entry in new_entries {
        if entry.is_dir {
            tar.append_dir(&entry.archive_path, &entry.source_path)?;
        } else {
            tar.append_path_with_name(&entry.source_path, &entry.archive_path)?;
        }
    }

    tar.finish()?;
    Ok(())
}

fn add_to_zip_archive(
    opts: &ArchiveAddOptions,
    new_entries: &[NewArchiveEntry],
) -> Result<(ArchiveAddSummary, ArchiveAddDetails, Vec<String>)> {
    let archive_path = Path::new(&opts.archive);
    let archive_size_before = archive_path.metadata()?.len();

    // Read existing ZIP entries
    let existing_entries = read_existing_zip_entries(&opts.archive)?;
    let entries_before = existing_entries.len() as u64;
    let uncompressed_bytes_before: u64 = existing_entries.iter().map(|e| e.size).sum();

    // Create temporary file for new archive
    let tmp_path = if let Some(ref tmp_dir) = opts.tmp_dir {
        let tmp_dir_path = Path::new(tmp_dir);
        create_dir_all(tmp_dir_path)?;
        tmp_dir_path.join(format!(".tmp_archive_{}", std::process::id()))
    } else {
        archive_path.with_extension(&format!("tmp_{}", std::process::id()))
    };

    // Create backup if requested
    if let Some(ref suffix) = opts.backup_suffix {
        let backup_path = PathBuf::from(&opts.archive).with_extension(&format!("{}.{}", 
            archive_path.extension().unwrap_or_default().to_string_lossy(), suffix));
        std::fs::copy(&opts.archive, &backup_path)
            .context("Failed to create backup")?;
    }

    // Build index of existing entries for conflict detection
    let mut existing_paths: HashMap<String, usize> = HashMap::new();
    for (idx, entry) in existing_entries.iter().enumerate() {
        existing_paths.insert(entry.path.clone(), idx);
    }

    // Process new entries for conflicts
    let mut details = ArchiveAddDetails {
        added: Vec::new(),
        replaced: Vec::new(),
        skipped: Vec::new(),
    };
    let mut warnings = Vec::new();

    let mut final_entries = existing_entries.clone();
    let mut entries_to_add = Vec::new();

    for new_entry in new_entries {
        if let Some(&existing_idx) = existing_paths.get(&new_entry.archive_path) {
            if opts.overwrite {
                // Mark existing entry for replacement
                details.replaced.push(new_entry.archive_path.clone());
                final_entries[existing_idx].replaced = true;
                entries_to_add.push(new_entry.clone());
            } else {
                // Skip due to conflict
                details.skipped.push(ArchiveAddSkippedEntry {
                    path: new_entry.archive_path.clone(),
                    reason: "already exists and overwrite=false".to_string(),
                });
                warnings.push(format!("Skipped '{}' because overwrite=false and entry exists.", 
                                    new_entry.archive_path));
            }
        } else {
            // New entry to add
            details.added.push(new_entry.archive_path.clone());
            entries_to_add.push(new_entry.clone());
        }
    }

    // Write new ZIP archive
    write_zip_archive(&tmp_path, &final_entries, &entries_to_add)?;

    // Get new archive size
    let archive_size_after = tmp_path.metadata()?.len();
    let entries_after = (final_entries.len() - final_entries.iter().filter(|e| e.replaced).count() + entries_to_add.len()) as u64;
    let uncompressed_bytes_after = uncompressed_bytes_before + entries_to_add.iter().map(|e| e.size).sum::<u64>() 
        - final_entries.iter().filter(|e| e.replaced).map(|e| e.size).sum::<u64>();

    // Atomic replace
    std::fs::rename(&tmp_path, &opts.archive)?;

    let summary = ArchiveAddSummary {
        archive: opts.archive.clone(),
        format: "zip".to_string(),
        compression: "none".to_string(),
        entries_before,
        entries_after,
        entries_added: details.added.len() as u64,
        entries_replaced: details.replaced.len() as u64,
        entries_skipped: details.skipped.len() as u64,
        uncompressed_bytes_before,
        uncompressed_bytes_after,
        archive_size_bytes_before: archive_size_before,
        archive_size_bytes_after: archive_size_after,
    };

    Ok((summary, details, warnings))
}

#[derive(Clone, Debug)]
struct ExistingZipEntry {
    path: String,
    size: u64,
    data: Vec<u8>,
    replaced: bool,
}

fn read_existing_zip_entries(archive_path: &str) -> Result<Vec<ExistingZipEntry>> {
    let file = File::open(archive_path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut entries = Vec::new();

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let path = file.name().to_string();
        let size = file.size();
        
        let mut data = Vec::new();
        std::io::copy(&mut file, &mut data)?;

        entries.push(ExistingZipEntry {
            path,
            size,
            data,
            replaced: false,
        });
    }

    Ok(entries)
}

fn write_zip_archive(
    output_path: &Path,
    existing_entries: &[ExistingZipEntry],
    new_entries: &[NewArchiveEntry],
) -> Result<()> {
    let file = File::create(output_path)?;
    let mut zip = ZipWriter::new(file);

    // Write existing entries (not replaced)
    for entry in existing_entries {
        if !entry.replaced {
            zip.start_file(&entry.path, FileOptions::default())?;
            zip.write_all(&entry.data)?;
        }
    }

    // Write new entries
    for entry in new_entries {
        if entry.is_dir {
            zip.add_directory(&entry.archive_path, FileOptions::default())?;
        } else {
            zip.start_file(&entry.archive_path, FileOptions::default())?;
            let mut file = File::open(&entry.source_path)?;
            std::io::copy(&mut file, &mut zip)?;
        }
    }

    zip.finish()?;
    Ok(())
}

fn build_glob_set(patterns: &[String], pattern_type: &str) -> Result<Option<globset::GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }

    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = Glob::new(pattern)
            .context(format!("Invalid {} pattern: {}", pattern_type, pattern))?;
        builder.add(glob);
    }
    Ok(Some(builder.build()?))
}

fn extract_tar_archive(
    opts: &ArchiveExtractOptions,
    include_set: &Option<globset::GlobSet>,
    exclude_set: &Option<globset::GlobSet>,
) -> Result<(ArchiveExtractSummary, Vec<ArchiveExtractManifestEntry>, Vec<String>)> {
    let archive_file = File::open(&opts.archive)?;
    let mut archive: Box<dyn Read> = Box::new(archive_file);

    // Handle decompression
    match opts.compression {
        CompressionKind::Gzip => {
            archive = Box::new(GzDecoder::new(archive));
        }
        CompressionKind::Xz => {
            archive = Box::new(XzDecoder::new(archive));
        }
        CompressionKind::Zstd => {
            archive = Box::new(ZstdDecoder::new(archive)?);
        }
        _ => {} // No compression or auto-detected
    }

    let mut tar = Archive::new(archive);
    let dest_path = Path::new(&opts.destination);

    let mut entries_total = 0u64;
    let mut entries_extracted = 0u64;
    let mut entries_skipped = 0u64;
    let mut bytes_written = 0u64;
    let mut manifest = Vec::new();
    let mut warnings = Vec::new();

    for entry_result in tar.entries()? {
        let mut entry = entry_result?;
        entries_total += 1;

        // Check safety limits early
        if entries_total > opts.max_entries {
            bail!("Maximum number of entries exceeded: {}", opts.max_entries);
        }

        let path = entry.path()?;
        let path_str = path.to_string_lossy();

        // Apply strip_components
        let stripped_path = apply_strip_components(&path_str, opts.strip_components);
        if stripped_path.is_empty() {
            entries_skipped += 1;
            continue;
        }

        // Check filters
        if !should_extract_path(&stripped_path, include_set, exclude_set) {
            entries_skipped += 1;
            continue;
        }

        // Security checks
        let safe_path = match sanitize_path(&stripped_path, dest_path, opts) {
            Ok(p) => p,
            Err(e) => {
                warnings.push(format!("Skipped unsafe path '{}': {}", path_str, e));
                entries_skipped += 1;
                continue;
            }
        };

        // Check if target exists and handle overwrite
        if safe_path.exists() && !opts.overwrite {
            warnings.push(format!("Skipped existing file '{}' (overwrite=false)", stripped_path));
            entries_skipped += 1;
            continue;
        }

        // Extract the entry
        let is_dir = entry.header().entry_type().is_dir();
        let is_symlink = entry.header().entry_type().is_symlink() || entry.header().entry_type().is_hard_link();
        let size = entry.header().size()?;

        // Check file size limits
        if let Some(max_size) = opts.max_file_bytes {
            if size > max_size {
                bail!("File '{}' size ({}) exceeds maximum file size ({})", path_str, size, max_size);
            }
        }

        // Check total size limits
        if let Some(max_total) = opts.max_total_bytes {
            if bytes_written + size > max_total {
                bail!("Total extraction size would exceed maximum ({})", max_total);
            }
        }

        // Handle symlinks
        if is_symlink && !opts.allow_symlinks {
            warnings.push(format!("Skipped symlink '{}' (allow_symlinks=false)", stripped_path));
            entries_skipped += 1;
            continue;
        }

        // Create parent directories
        if let Some(parent) = safe_path.parent() {
            create_dir_all(parent)?;
        }

        // Extract the entry
        entry.unpack(&safe_path)?;
        entries_extracted += 1;

        if !is_dir {
            bytes_written += size;
        }

        manifest.push(ArchiveExtractManifestEntry {
            path: stripped_path,
            size,
            is_dir,
            is_symlink,
        });
    }

    let summary = ArchiveExtractSummary {
        archive: opts.archive.clone(),
        destination: opts.destination.clone(),
        format: opts.format.as_str().to_string(),
        compression: opts.compression.as_str().to_string(),
        entries_total,
        entries_extracted,
        entries_skipped,
        bytes_written,
        duration_ms: 0, // Will be filled in later
    };

    Ok((summary, manifest, warnings))
}

fn extract_zip_archive(
    opts: &ArchiveExtractOptions,
    include_set: &Option<globset::GlobSet>,
    exclude_set: &Option<globset::GlobSet>,
) -> Result<(ArchiveExtractSummary, Vec<ArchiveExtractManifestEntry>, Vec<String>)> {
    let archive_file = File::open(&opts.archive)?;
    let mut zip = ZipArchive::new(archive_file)?;
    let dest_path = Path::new(&opts.destination);

    let entries_total = zip.len() as u64;
    let mut entries_extracted = 0u64;
    let mut entries_skipped = 0u64;
    let mut bytes_written = 0u64;
    let mut manifest = Vec::new();
    let mut warnings = Vec::new();

    // Check safety limits early
    if entries_total > opts.max_entries {
        bail!("Maximum number of entries exceeded: {}", opts.max_entries);
    }

    for i in 0..zip.len() {
        let mut file = zip.by_index(i)?;
        let path_str = file.name().to_string();

        // Apply strip_components
        let stripped_path = apply_strip_components(&path_str, opts.strip_components);
        if stripped_path.is_empty() {
            entries_skipped += 1;
            continue;
        }

        // Check filters
        if !should_extract_path(&stripped_path, include_set, exclude_set) {
            entries_skipped += 1;
            continue;
        }

        // Security checks
        let safe_path = match sanitize_path(&stripped_path, dest_path, opts) {
            Ok(p) => p,
            Err(e) => {
                warnings.push(format!("Skipped unsafe path '{}': {}", path_str, e));
                entries_skipped += 1;
                continue;
            }
        };

        // Check if target exists and handle overwrite
        if safe_path.exists() && !opts.overwrite {
            warnings.push(format!("Skipped existing file '{}' (overwrite=false)", stripped_path));
            entries_skipped += 1;
            continue;
        }

        let is_dir = file.is_dir();
        let size = file.size();

        // Check file size limits
        if let Some(max_size) = opts.max_file_bytes {
            if size > max_size {
                bail!("File '{}' size ({}) exceeds maximum file size ({})", path_str, size, max_size);
            }
        }

        // Check total size limits
        if let Some(max_total) = opts.max_total_bytes {
            if bytes_written + size > max_total {
                bail!("Total extraction size would exceed maximum ({})", max_total);
            }
        }

        // Create parent directories
        if let Some(parent) = safe_path.parent() {
            create_dir_all(parent)?;
        }

        if is_dir {
            create_dir_all(&safe_path)?;
        } else {
            let mut output = File::create(&safe_path)?;
            std::io::copy(&mut file, &mut output)?;
            bytes_written += size;
        }

        entries_extracted += 1;

        manifest.push(ArchiveExtractManifestEntry {
            path: stripped_path,
            size,
            is_dir,
            is_symlink: false,
        });
    }

    let summary = ArchiveExtractSummary {
        archive: opts.archive.clone(),
        destination: opts.destination.clone(),
        format: opts.format.as_str().to_string(),
        compression: opts.compression.as_str().to_string(),
        entries_total,
        entries_extracted,
        entries_skipped,
        bytes_written,
        duration_ms: 0, // Will be filled in later
    };

    Ok((summary, manifest, warnings))
}

fn extract_raw_compressed_file(
    opts: &ArchiveExtractOptions,
) -> Result<(ArchiveExtractSummary, Vec<ArchiveExtractManifestEntry>, Vec<String>)> {
    let archive_path = Path::new(&opts.archive);
    let dest_path = Path::new(&opts.destination);
    
    // Determine output filename (remove compression extension)
    let output_name = archive_path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("extracted_file");
    
    let output_path = dest_path.join(output_name);

    // Check if target exists and handle overwrite
    if output_path.exists() && !opts.overwrite {
        return Ok((
            ArchiveExtractSummary {
                archive: opts.archive.clone(),
                destination: opts.destination.clone(),
                format: opts.format.as_str().to_string(),
                compression: opts.compression.as_str().to_string(),
                entries_total: 1,
                entries_extracted: 0,
                entries_skipped: 1,
                bytes_written: 0,
                duration_ms: 0,
            },
            vec![],
            vec![format!("Skipped existing file '{}' (overwrite=false)", output_name)],
        ));
    }

    let input_file = File::open(archive_path)?;
    let mut decoder: Box<dyn Read> = match opts.compression {
        CompressionKind::Gzip => Box::new(GzDecoder::new(input_file)),
        CompressionKind::Xz => Box::new(XzDecoder::new(input_file)),
        CompressionKind::Zstd => Box::new(ZstdDecoder::new(input_file)?),
        _ => bail!("Invalid compression for raw format: {}", opts.compression.as_str()),
    };

    let mut output_file = File::create(&output_path)?;
    let bytes_written = std::io::copy(&mut decoder, &mut output_file)? as u64;

    // Check size limits
    if let Some(max_total) = opts.max_total_bytes {
        if bytes_written > max_total {
            bail!("Extracted size ({}) exceeds maximum total size ({})", bytes_written, max_total);
        }
    }

    if let Some(max_file) = opts.max_file_bytes {
        if bytes_written > max_file {
            bail!("Extracted file size ({}) exceeds maximum file size ({})", bytes_written, max_file);
        }
    }

    let summary = ArchiveExtractSummary {
        archive: opts.archive.clone(),
        destination: opts.destination.clone(),
        format: opts.format.as_str().to_string(),
        compression: opts.compression.as_str().to_string(),
        entries_total: 1,
        entries_extracted: 1,
        entries_skipped: 0,
        bytes_written,
        duration_ms: 0,
    };

    let manifest = vec![ArchiveExtractManifestEntry {
        path: output_name.to_string(),
        size: bytes_written,
        is_dir: false,
        is_symlink: false,
    }];

    Ok((summary, manifest, vec![]))
}

fn apply_strip_components(path: &str, strip_count: u32) -> String {
    if strip_count == 0 {
        return path.to_string();
    }

    let components: Vec<&str> = path.split('/').collect();
    if components.len() <= strip_count as usize {
        return String::new();
    }

    components[strip_count as usize..].join("/")
}

fn should_extract_path(
    path: &str,
    include_set: &Option<globset::GlobSet>,
    exclude_set: &Option<globset::GlobSet>,
) -> bool {
    // Check includes first
    if let Some(includes) = include_set {
        if !includes.is_match(path) {
            return false;
        }
    }

    // Check excludes
    if let Some(excludes) = exclude_set {
        if excludes.is_match(path) {
            return false;
        }
    }

    true
}

// Made public for testing
pub fn sanitize_path(path: &str, dest_path: &Path, opts: &ArchiveExtractOptions) -> Result<PathBuf> {
    let path_buf = Path::new(path);
    
    // Handle absolute paths
    let relative_path = if path_buf.is_absolute() {
        if !opts.allow_absolute_paths {
            // Strip leading slash and treat as relative
            path_buf.strip_prefix("/").unwrap_or(path_buf)
        } else {
            return Err(anyhow::anyhow!("Absolute paths not allowed in safe mode"));
        }
    } else {
        path_buf
    };

    // Normalize and check for path traversal
    let mut safe_path = dest_path.to_path_buf();
    for component in relative_path.components() {
        match component {
            Component::Normal(name) => safe_path.push(name),
            Component::CurDir => {}, // Skip current dir
            Component::ParentDir => {
                if !opts.allow_parent_traversal {
                    return Err(anyhow::anyhow!("Path traversal detected (..)"));
                }
                safe_path.pop();
            }
            Component::RootDir => {
                if !opts.allow_absolute_paths {
                    return Err(anyhow::anyhow!("Root directory component not allowed"));
                }
            }
            _ => return Err(anyhow::anyhow!("Invalid path component")),
        }
    }

    // Ensure the final path is still within destination
    if !safe_path.starts_with(dest_path) {
        return Err(anyhow::anyhow!("Path escapes destination directory"));
    }

    Ok(safe_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn test_archive_format_detection() {
        assert_eq!(ArchiveFormat::detect_from_extension("test.tar").unwrap(), ArchiveFormat::Tar);
        assert_eq!(ArchiveFormat::detect_from_extension("test.tar.gz").unwrap(), ArchiveFormat::TarGz);
        assert_eq!(ArchiveFormat::detect_from_extension("test.zip").unwrap(), ArchiveFormat::Zip);
        assert_eq!(ArchiveFormat::detect_from_extension("test.7z").unwrap(), ArchiveFormat::SevenZ);
        assert_eq!(ArchiveFormat::detect_from_extension("test.gz").unwrap(), ArchiveFormat::Raw);
        assert_eq!(ArchiveFormat::detect_from_extension("test.xz").unwrap(), ArchiveFormat::Raw);
        assert_eq!(ArchiveFormat::detect_from_extension("test.zst").unwrap(), ArchiveFormat::Raw);
        
        assert!(ArchiveFormat::detect_from_extension("test.unknown").is_err());
    }

    #[test]
    fn test_compression_level_validation() {
        let format = ArchiveFormat::TarGz;
        assert!(format.supports_compression_level());
        assert_eq!(format.max_compression_level(), 9);
        assert_eq!(format.default_compression_level(), 6);

        let format = ArchiveFormat::Tar;
        assert!(!format.supports_compression_level());
    }

    #[test]
    fn test_password_support() {
        assert!(ArchiveFormat::Zip.supports_password());
        assert!(ArchiveFormat::SevenZ.supports_password());
        assert!(!ArchiveFormat::Tar.supports_password());
        assert!(!ArchiveFormat::TarGz.supports_password());
    }

    #[test]
    fn test_create_simple_tar() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let temp_path = temp_dir.path();
        
        // Create test files
        let test_file = temp_path.join("test.txt");
        fs::write(&test_file, "Hello, World!")?;
        
        let opts = ArchiveCreateOptions {
            output: temp_path.join("test.tar").to_string_lossy().to_string(),
            sources: vec![test_file.to_string_lossy().to_string()],
            base_dir: Some(temp_path.to_string_lossy().to_string()),
            format: ArchiveFormat::Tar,
            compression_level: None,
            include_patterns: vec![],
            exclude_patterns: vec![],
            include_hidden: true,
            follow_symlinks: false,
            password: None,
            overwrite: true,
            preserve_permissions: true,
            preserve_timestamps: true,
            max_files: 100000,
            max_size_mb: 10240,
            progress: false,
            output_format: OutputFormat::Json,
        };
        
        let response = create_archive(opts)?;
        assert!(response.ok);
        assert_eq!(response.result.files_archived, 1);
        assert!(response.result.total_size_bytes > 0);
        
        Ok(())
    }

    #[test]
    fn test_compression_detection() {
        assert_eq!(CompressionKind::detect_from_extension("file.gz"), CompressionKind::Gzip);
        assert_eq!(CompressionKind::detect_from_extension("file.xz"), CompressionKind::Xz);
        assert_eq!(CompressionKind::detect_from_extension("file.zst"), CompressionKind::Zstd);
        assert_eq!(CompressionKind::detect_from_extension("file.zstd"), CompressionKind::Zstd);
        assert_eq!(CompressionKind::detect_from_extension("file.tar"), CompressionKind::None);
        assert_eq!(CompressionKind::detect_from_extension("file.txt"), CompressionKind::None);
    }

    #[test]
    fn test_strip_components() {
        assert_eq!(apply_strip_components("a/b/c/file.txt", 0), "a/b/c/file.txt");
        assert_eq!(apply_strip_components("a/b/c/file.txt", 1), "b/c/file.txt");
        assert_eq!(apply_strip_components("a/b/c/file.txt", 2), "c/file.txt");
        assert_eq!(apply_strip_components("a/b/c/file.txt", 3), "file.txt");
        assert_eq!(apply_strip_components("a/b/c/file.txt", 4), "");
        assert_eq!(apply_strip_components("a/b/c/file.txt", 5), "");
    }

    #[test]
    fn test_path_sanitization() -> Result<()> {
        use tempfile::TempDir;
        
        let temp_dir = TempDir::new()?;
        let dest_path = temp_dir.path();
        
        let opts = ArchiveExtractOptions {
            archive: "test.tar".to_string(),
            destination: dest_path.to_string_lossy().to_string(),
            format: ArchiveFormat::Tar,
            compression: CompressionKind::None,
            includes: vec![],
            excludes: vec![],
            overwrite: false,
            create_destination: true,
            fail_on_missing_archive: true,
            strip_components: 0,
            allow_absolute_paths: false,
            allow_parent_traversal: false,
            allow_symlinks: true,
            follow_symlinks: false,
            max_entries: 1000000,
            max_total_bytes: None,
            max_file_bytes: None,
            include_manifest: true,
            format_output: OutputFormat::Json,
        };

        // Safe path
        let safe_result = sanitize_path("subdir/file.txt", dest_path, &opts);
        assert!(safe_result.is_ok());
        assert!(safe_result.unwrap().starts_with(dest_path));

        // Path traversal should fail
        let traversal_result = sanitize_path("../evil.txt", dest_path, &opts);
        assert!(traversal_result.is_err());

        // Absolute path should fail
        let absolute_result = sanitize_path("/etc/passwd", dest_path, &opts);
        assert!(absolute_result.is_err());

        Ok(())
    }

    #[test]
    fn test_filter_matching() {
        let includes = build_glob_set(&vec!["*.txt".to_string(), "docs/*".to_string()], "include").unwrap();
        let excludes = build_glob_set(&vec!["*.tmp".to_string()], "exclude").unwrap();

        assert!(should_extract_path("file.txt", &includes, &excludes));
        assert!(should_extract_path("docs/readme.md", &includes, &excludes));
        assert!(!should_extract_path("file.tmp", &includes, &excludes));
        assert!(!should_extract_path("image.jpg", &includes, &excludes));
    }
}

pub fn info_archive(opts: ArchiveInfoOptions) -> Result<ArchiveInfoResponse> {
    let mut response = ArchiveInfoResponse::new(&opts);

    // Validate input
    if opts.archive.is_empty() {
        response.ok = false;
        response.error = Some((ARCHIVE_INFO_INVALID_ARCHIVE_PATH.to_string(), 
                             "Archive path cannot be empty".to_string()));
        return Ok(response);
    }

    let archive_path = Path::new(&opts.archive);

    // Check if archive exists
    if !archive_path.exists() {
        if opts.fail_on_missing_archive {
            response.ok = false;
            response.error = Some((ARCHIVE_INFO_MISSING_ARCHIVE.to_string(),
                                 format!("Archive '{}' does not exist.", opts.archive)));
            return Ok(response);
        }
    }

    // Get file metadata
    let metadata = match std::fs::metadata(archive_path) {
        Ok(meta) => meta,
        Err(e) => {
            response.ok = false;
            response.error = Some((ARCHIVE_INFO_IO_ERROR.to_string(),
                                 format!("Failed to read archive metadata: {}", e)));
            return Ok(response);
        }
    };

    let archive_size_bytes = metadata.len();
    let archive_mtime_unix = metadata.modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs() as i64);

    // Detect format and compression based on extension and args
    let (format, compression) = match detect_format_and_compression(&opts) {
        Ok((f, c)) => (f, c),
        Err(e) => {
            response.ok = false;
            response.error = Some((ARCHIVE_INFO_INVALID_FORMAT_INFER.to_string(), e.to_string()));
            return Ok(response);
        }
    };

    // Initialize summary
    let mut summary = ArchiveInfoSummary {
        archive: opts.archive.clone(),
        format: format.as_str().to_string(),
        compression: compression.as_str().to_string(),
        archive_size_bytes,
        archive_mtime_unix,
        entries_total: None,
        files: None,
        directories: None,
        symlinks: None,
        other: None,
        uncompressed_bytes_total: None,
        compression_ratio: None,
        min_mtime_unix: None,
        max_mtime_unix: None,
        encrypted: None,
        solid: None,
    };

    let mut details = ArchiveInfoDetails {
        zip: None,
        seven_z: None,
    };

    // If we're not scanning entries, just return basic info
    if !opts.scan_entries {
        summary.compression_ratio = if archive_size_bytes > 0 {
            Some(1.0) // Can't compute without uncompressed size
        } else {
            None
        };

        response.summary = Some(summary);
        response.details = Some(details);
        return Ok(response);
    }

    // Scan archive entries
    match scan_archive_entries(&opts, &format, &compression, archive_path, &mut summary, &mut details) {
        Ok(_) => {},
        Err(e) => {
            response.ok = false;
            response.error = Some((ARCHIVE_INFO_ARCHIVE_READ_ERROR.to_string(), e.to_string()));
            return Ok(response);
        }
    }

    // Calculate compression ratio
    if let Some(uncompressed) = summary.uncompressed_bytes_total {
        if archive_size_bytes > 0 && uncompressed > 0 {
            summary.compression_ratio = Some(uncompressed as f64 / archive_size_bytes as f64);
        }
    }

    response.summary = Some(summary);
    response.details = Some(details);
    Ok(response)
}

fn detect_format_and_compression(opts: &ArchiveInfoOptions) -> Result<(ArchiveFormat, CompressionKind)> {
    let format = match &opts.format {
        ArchiveFormat::Auto => ArchiveFormat::detect_from_extension(&opts.archive)?,
        other => other.clone(),
    };

    let compression = match &opts.compression {
        CompressionKind::Auto => CompressionKind::detect_from_extension(&opts.archive),
        other => other.clone(),
    };

    // Validate format/compression combinations
    match (&format, &compression) {
        (ArchiveFormat::Raw, CompressionKind::None) => {
            bail!("Raw format requires compression (gzip, xz, or zstd)");
        }
        (ArchiveFormat::Raw, CompressionKind::Auto) => {
            bail!("Raw format requires explicit compression type");
        }
        _ => {}
    }

    Ok((format, compression))
}

fn scan_archive_entries(
    opts: &ArchiveInfoOptions,
    format: &ArchiveFormat,
    compression: &CompressionKind,
    archive_path: &Path,
    summary: &mut ArchiveInfoSummary,
    details: &mut ArchiveInfoDetails,
) -> Result<()> {
    match format {
        ArchiveFormat::Raw => scan_raw_entries(opts, compression, archive_path, summary),
        ArchiveFormat::TarGz | ArchiveFormat::TarXz | ArchiveFormat::TarZstd | ArchiveFormat::Tar => {
            scan_tar_entries(opts, format, archive_path, summary)
        }
        ArchiveFormat::Zip => scan_zip_entries(opts, archive_path, summary, details),
        ArchiveFormat::SevenZ => scan_7z_entries(opts, archive_path, summary, details),
        _ => bail!("Unsupported format for scanning: {}", format.as_str()),
    }
}

fn scan_raw_entries(
    _opts: &ArchiveInfoOptions,
    _compression: &CompressionKind,
    _archive_path: &Path,
    summary: &mut ArchiveInfoSummary,
) -> Result<()> {
    // Raw compressed files have only one logical "entry"
    summary.entries_total = Some(1);
    summary.files = Some(1);
    summary.directories = Some(0);
    summary.symlinks = Some(0);
    summary.other = Some(0);

    // For raw files, we could try to determine uncompressed size from headers
    // but this would require format-specific logic, so leaving as None for now
    summary.uncompressed_bytes_total = None;
    summary.min_mtime_unix = summary.archive_mtime_unix;
    summary.max_mtime_unix = summary.archive_mtime_unix;

    Ok(())
}

fn scan_tar_entries(
    opts: &ArchiveInfoOptions,
    format: &ArchiveFormat,
    archive_path: &Path,
    summary: &mut ArchiveInfoSummary,
) -> Result<()> {
    let file = File::open(archive_path)?;
    
    let archive: Box<dyn Read> = match format {
        ArchiveFormat::TarGz => Box::new(GzDecoder::new(file)),
        ArchiveFormat::TarXz => Box::new(XzDecoder::new(file)),
        ArchiveFormat::TarZstd => Box::new(ZstdDecoder::new(file)?),
        ArchiveFormat::Tar => Box::new(file),
        _ => bail!("Invalid tar format"),
    };

    let mut tar = Archive::new(archive);
    
    let mut entries_count = 0u64;
    let mut files_count = 0u64;
    let mut dirs_count = 0u64;
    let mut symlinks_count = 0u64;
    let mut other_count = 0u64;
    let mut total_uncompressed = 0u64;
    let mut min_mtime: Option<i64> = None;
    let mut max_mtime: Option<i64> = None;

    for entry_result in tar.entries()? {
        let entry = entry_result?;
        let header = entry.header();

        entries_count += 1;

        // Check limits
        if entries_count > opts.max_entries {
            return Err(anyhow::anyhow!("Max entries limit exceeded: {}", opts.max_entries));
        }

        // Count by type
        match header.entry_type() {
            tar::EntryType::Directory => dirs_count += 1,
            tar::EntryType::Symlink | tar::EntryType::Link => symlinks_count += 1,
            tar::EntryType::Regular => {
                files_count += 1;
                let size = header.size()?;
                total_uncompressed += size;

                // Check size limits
                if let Some(max_size) = opts.max_total_bytes {
                    if total_uncompressed > max_size {
                        return Err(anyhow::anyhow!("Max total bytes limit exceeded: {}", max_size));
                    }
                }
            }
            _ => other_count += 1,
        }

        // Track modification times
        if let Ok(mtime) = header.mtime() {
            let mtime = mtime as i64;
            min_mtime = Some(min_mtime.map_or(mtime, |min| min.min(mtime)));
            max_mtime = Some(max_mtime.map_or(mtime, |max| max.max(mtime)));
        }
    }

    summary.entries_total = Some(entries_count);
    summary.files = Some(files_count);
    summary.directories = Some(dirs_count);
    summary.symlinks = Some(symlinks_count);
    summary.other = Some(other_count);
    summary.uncompressed_bytes_total = Some(total_uncompressed);
    summary.min_mtime_unix = min_mtime;
    summary.max_mtime_unix = max_mtime;
    summary.encrypted = Some(false); // Tar itself doesn't support encryption

    Ok(())
}

fn scan_zip_entries(
    opts: &ArchiveInfoOptions,
    archive_path: &Path,
    summary: &mut ArchiveInfoSummary,
    details: &mut ArchiveInfoDetails,
) -> Result<()> {
    let file = File::open(archive_path)?;
    let mut zip = ZipArchive::new(file)?;

    let mut entries_count = 0u64;
    let mut files_count = 0u64;
    let mut dirs_count = 0u64;
    let symlinks_count = 0u64;
    let other_count = 0u64;
    let mut total_uncompressed = 0u64;
    let min_mtime: Option<i64> = None;
    let max_mtime: Option<i64> = None;
    let encrypted_entries = 0u64;

    for i in 0..zip.len() {
        entries_count += 1;

        // Check limits
        if entries_count > opts.max_entries {
            return Err(anyhow::anyhow!("Max entries limit exceeded: {}", opts.max_entries));
        }

        let entry = zip.by_index(i)?;

        // Count by type
        if entry.is_dir() {
            dirs_count += 1;
        } else {
            files_count += 1;
            let size = entry.size();
            total_uncompressed += size;

            // Check size limits
            if let Some(max_size) = opts.max_total_bytes {
                if total_uncompressed > max_size {
                    return Err(anyhow::anyhow!("Max total bytes limit exceeded: {}", max_size));
                }
            }
        }

        // Check if entry is encrypted (this is an approximation)
        // The zip crate doesn't expose encryption status directly
        // We'll skip encryption detection for now and set it to false
        
        // Track modification times - simplified for now
        // The zip crate's time handling is complex and version-dependent
        // We'll skip time tracking for zip files for now
    }

    summary.entries_total = Some(entries_count);
    summary.files = Some(files_count);
    summary.directories = Some(dirs_count);
    summary.symlinks = Some(symlinks_count);
    summary.other = Some(other_count);
    summary.uncompressed_bytes_total = Some(total_uncompressed);
    summary.min_mtime_unix = min_mtime;
    summary.max_mtime_unix = max_mtime;
    summary.encrypted = Some(encrypted_entries > 0);

    details.zip = Some(ArchiveInfoZipDetails {
        encrypted_entries,
        has_encrypted_entries: encrypted_entries > 0,
    });

    Ok(())
}

fn scan_7z_entries(
    _opts: &ArchiveInfoOptions,
    _archive_path: &Path,
    _summary: &mut ArchiveInfoSummary,
    _details: &mut ArchiveInfoDetails,
) -> Result<()> {
    // 7z support is not implemented in this codebase yet
    bail!("7z format scanning not yet supported")
}

fn map_add_validation_error(err: &anyhow::Error) -> String {
    let err_str = err.to_string();
    if err_str.contains("Missing required parameter: archive") || err_str.contains("Archive path cannot be empty") {
        format!("[{}] {}", ARCHIVE_ADD_INVALID_ARCHIVE_PATH, err_str)
    } else if err_str.contains("Missing required parameter: inputs") || err_str.contains("Inputs list cannot be empty") {
        format!("[{}] {}", ARCHIVE_ADD_INVALID_INPUT, err_str)
    } else if err_str.contains("Unsupported archive format") || err_str.contains("Cannot detect archive format") {
        format!("[{}] {}", ARCHIVE_ADD_INVALID_FORMAT, err_str)
    } else if err_str.contains("Invalid includes format") {
        format!("[{}] {}", ARCHIVE_ADD_INVALID_INCLUDE_PATTERN, err_str)
    } else if err_str.contains("Invalid excludes format") {
        format!("[{}] {}", ARCHIVE_ADD_INVALID_EXCLUDE_PATTERN, err_str)
    } else if err_str.contains("Adding entries to raw compressed streams") {
        format!("[{}] {}", ARCHIVE_ADD_UNSUPPORTED_FOR_RAW, err_str)
    } else if err_str.contains("7z archive modification not yet supported") {
        format!("[{}] {}", ARCHIVE_ADD_7Z_UNSUPPORTED, err_str)
    } else {
        format!("[{}] {}", ARCHIVE_ADD_INTERNAL_ERROR, err_str)
    }
}

pub fn remove_archive(opts: ArchiveRemoveOptions) -> Result<ArchiveRemoveResponse> {
    let mut response = ArchiveRemoveResponse::new(&opts);
    let start_time = Instant::now();

    // Validate archive exists if required
    let archive_path = Path::new(&opts.archive);
    if !archive_path.exists() {
        if opts.fail_on_missing_archive {
            response.ok = false;
            response.error = Some((
                ARCHIVE_REMOVE_MISSING_ARCHIVE.to_string(),
                format!("Archive '{}' does not exist.", opts.archive)
            ));
            return Ok(response);
        } else {
            response.ok = false;
            response.error = Some((
                ARCHIVE_REMOVE_MISSING_ARCHIVE.to_string(),
                format!("Archive '{}' does not exist.", opts.archive)
            ));
            return Ok(response);
        }
    }

    let (final_format, final_compression) = match resolve_format_and_compression(&opts.format, &opts.compression, &opts.archive) {
        Ok(result) => result,
        Err(e) => {
            response.ok = false;
            response.error = Some((
                ARCHIVE_REMOVE_INVALID_FORMAT_INFER.to_string(),
                format!("Cannot determine archive format: {}", e)
            ));
            return Ok(response);
        }
    };

    // Check if raw format (not supported for remove)
    if final_format == ArchiveFormat::Raw {
        response.ok = false;
        response.error = Some((
            ARCHIVE_REMOVE_UNSUPPORTED_FOR_RAW.to_string(),
            "Removing entries from raw compressed streams (gzip/xz/zstd) is not supported.".to_string()
        ));
        return Ok(response);
    }

    // Check if 7z format (not yet supported)
    if final_format == ArchiveFormat::SevenZ {
        response.ok = false;
        response.error = Some((
            ARCHIVE_REMOVE_7Z_UNSUPPORTED.to_string(),
            "7z archive removal not yet supported.".to_string()
        ));
        return Ok(response);
    }

    // Build glob sets for patterns
    let pattern_set = if !opts.patterns.is_empty() {
        match build_glob_set(&opts.patterns, "patterns") {
            Ok(set) => set, // set is already Option<GlobSet>
            Err(e) => {
                response.ok = false;
                response.error = Some((
                    ARCHIVE_REMOVE_INVALID_ARCHIVE_PATH.to_string(),
                    format!("Invalid pattern: {}", e)
                ));
                return Ok(response);
            }
        }
    } else {
        None
    };

    // Process the archive removal
    match perform_archive_removal(&opts, &final_format, &final_compression, pattern_set.as_ref()) {
        Ok((summary, details, warnings)) => {
            response.ok = true;
            response.summary = Some(summary);
            response.details = Some(details);
            response.warnings = warnings;
        }
        Err(e) => {
            response.ok = false;
            response.error = Some((ARCHIVE_REMOVE_ARCHIVE_READ_ERROR.to_string(), e.to_string()));
        }
    }

    Ok(response)
}

fn perform_archive_removal(
    opts: &ArchiveRemoveOptions,
    format: &ArchiveFormat,
    compression: &CompressionKind,
    pattern_set: Option<&globset::GlobSet>,
) -> Result<(ArchiveRemoveSummary, ArchiveRemoveDetails, Vec<String>)> {
    let archive_path = Path::new(&opts.archive);
    
    // Get original archive size
    let archive_size_before = archive_path.metadata()?.len();
    
    // Read and analyze the archive
    let (entries_before, entries_to_keep, entries_to_remove) = match format {
        ArchiveFormat::Tar | ArchiveFormat::TarGz | ArchiveFormat::TarXz | ArchiveFormat::TarZstd => {
            analyze_tar_archive(opts, compression, pattern_set)?
        }
        ArchiveFormat::Zip => {
            analyze_zip_archive(opts, pattern_set)?
        }
        _ => bail!("Unsupported archive format for removal"),
    };

    let mut warnings = Vec::new();
    
    // Check if any selectors didn't match anything
    let mut not_found = Vec::new();
    for path in &opts.paths {
        if !entries_to_remove.iter().any(|e| e.path == *path) {
            not_found.push(path.clone());
            warnings.push(format!("Path '{}' did not match any entries in archive.", path));
        }
    }

    let entries_removed = entries_to_remove.len() as u64;
    let dirs_removed = entries_to_remove.iter().filter(|e| e.is_dir).count() as u64;
    
    // Calculate bytes
    let uncompressed_bytes_before = entries_before.iter().map(|e| e.size).sum::<u64>();
    let uncompressed_bytes_after = entries_to_keep.iter().map(|e| e.size).sum::<u64>();

    let archive_size_after = if opts.dry_run {
        // Estimate the size after removal (rough approximation)
        let compression_ratio = if uncompressed_bytes_before > 0 {
            archive_size_before as f64 / uncompressed_bytes_before as f64
        } else {
            0.5 // Default compression ratio estimate
        };
        (uncompressed_bytes_after as f64 * compression_ratio) as u64
    } else {
        // Actually perform the removal and get the real size
        let temp_path = perform_actual_removal(opts, format, compression, &entries_to_keep)?;
        let new_size = temp_path.metadata()?.len();
        
        // Handle backup and replacement
        if let Some(backup_suffix) = &opts.backup_suffix {
            let backup_path = format!("{}{}", opts.archive, backup_suffix);
            std::fs::rename(&opts.archive, &backup_path)
                .with_context(|| format!("Failed to create backup at {}", backup_path))?;
        }
        
        std::fs::rename(&temp_path, &opts.archive)
            .context("Failed to replace original archive")?;
            
        new_size
    };

    let summary = ArchiveRemoveSummary {
        archive: opts.archive.clone(),
        format: format.as_str().to_string(),
        compression: compression.as_str().to_string(),
        entries_before: entries_before.len() as u64,
        entries_after: entries_to_keep.len() as u64,
        entries_removed,
        dirs_removed,
        uncompressed_bytes_before,
        uncompressed_bytes_after,
        archive_size_bytes_before: archive_size_before,
        archive_size_bytes_after: archive_size_after,
        dry_run: opts.dry_run,
    };

    let details = ArchiveRemoveDetails {
        removed: entries_to_remove.iter().map(|e| e.path.clone()).collect(),
        not_found,
        kept: if entries_to_keep.len() > 100 {
            // Truncate for large archives
            entries_to_keep.iter().take(100).map(|e| e.path.clone()).collect()
        } else {
            entries_to_keep.iter().map(|e| e.path.clone()).collect()
        },
    };

    Ok((summary, details, warnings))
}

#[derive(Clone)]
struct ArchiveEntry {
    path: String,
    size: u64,
    is_dir: bool,
}

fn analyze_tar_archive(
    opts: &ArchiveRemoveOptions,
    compression: &CompressionKind,
    pattern_set: Option<&globset::GlobSet>,
) -> Result<(Vec<ArchiveEntry>, Vec<ArchiveEntry>, Vec<ArchiveEntry>)> {
    let file = File::open(&opts.archive)?;
    let mut entries_before = Vec::new();
    
    // Read the archive based on compression
    match compression {
        CompressionKind::Gzip => {
            let decoder = GzDecoder::new(file);
            let mut archive = tar::Archive::new(decoder);
            read_tar_entries(&mut archive, &mut entries_before)?;
        }
        CompressionKind::Xz => {
            let decoder = XzDecoder::new(file);
            let mut archive = tar::Archive::new(decoder);
            read_tar_entries(&mut archive, &mut entries_before)?;
        }
        CompressionKind::Zstd => {
            let decoder = ZstdDecoder::new(file)?;
            let mut archive = tar::Archive::new(decoder);
            read_tar_entries(&mut archive, &mut entries_before)?;
        }
        CompressionKind::None => {
            let mut archive = tar::Archive::new(file);
            read_tar_entries(&mut archive, &mut entries_before)?;
        }
        _ => bail!("Unsupported compression for tar archive"),
    }

    // Determine which entries to keep and which to remove
    let (entries_to_keep, entries_to_remove) = filter_entries(&entries_before, opts, pattern_set);

    Ok((entries_before, entries_to_keep, entries_to_remove))
}

fn read_tar_entries<R: Read>(archive: &mut tar::Archive<R>, entries: &mut Vec<ArchiveEntry>) -> Result<()> {
    for entry in archive.entries()? {
        let entry = entry?;
        let path = entry.header().path()?.to_string_lossy().to_string();
        let size = entry.header().size()?;
        let is_dir = entry.header().entry_type() == tar::EntryType::Directory;
        
        entries.push(ArchiveEntry {
            path: normalize_archive_path(&path),
            size,
            is_dir,
        });
    }
    Ok(())
}

fn analyze_zip_archive(
    opts: &ArchiveRemoveOptions,
    pattern_set: Option<&globset::GlobSet>,
) -> Result<(Vec<ArchiveEntry>, Vec<ArchiveEntry>, Vec<ArchiveEntry>)> {
    let file = File::open(&opts.archive)?;
    let mut zip = ZipArchive::new(file)?;
    let mut entries_before = Vec::new();
    
    for i in 0..zip.len() {
        let entry = zip.by_index(i)?;
        let path = entry.name().to_string();
        let size = entry.size();
        let is_dir = entry.is_dir();
        
        entries_before.push(ArchiveEntry {
            path: normalize_archive_path(&path),
            size,
            is_dir,
        });
    }

    // Determine which entries to keep and which to remove
    let (entries_to_keep, entries_to_remove) = filter_entries(&entries_before, opts, pattern_set);

    Ok((entries_before, entries_to_keep, entries_to_remove))
}

fn filter_entries(
    entries: &[ArchiveEntry],
    opts: &ArchiveRemoveOptions,
    pattern_set: Option<&globset::GlobSet>,
) -> (Vec<ArchiveEntry>, Vec<ArchiveEntry>) {
    let mut entries_to_keep = Vec::new();
    let mut entries_to_remove = Vec::new();
    
    for entry in entries {
        let mut should_remove = false;
        
        // Check exact paths
        if opts.paths.iter().any(|p| normalize_archive_path(p) == entry.path) {
            should_remove = true;
        }
        
        // Check directory prefixes
        if !should_remove {
            for prefix in &opts.dir_prefixes {
                let normalized_prefix = normalize_archive_path(prefix);
                let prefix_with_slash = if normalized_prefix.ends_with('/') {
                    normalized_prefix.clone()
                } else {
                    format!("{}/", normalized_prefix)
                };
                
                if entry.path.starts_with(&prefix_with_slash) || entry.path == normalized_prefix {
                    should_remove = true;
                    break;
                }
            }
        }
        
        // Check patterns
        if !should_remove {
            if let Some(pattern_set) = pattern_set {
                if pattern_set.is_match(&entry.path) {
                    should_remove = true;
                }
            }
        }
        
        if should_remove {
            entries_to_remove.push(entry.clone());
        } else {
            entries_to_keep.push(entry.clone());
        }
    }
    
    // Handle empty directories removal
    if opts.remove_empty_dirs {
        let mut final_entries_to_keep = Vec::new();
        
        for entry in entries_to_keep {
            if entry.is_dir {
                // Check if this directory has any children in the kept entries
                let dir_path = if entry.path.ends_with('/') {
                    entry.path.clone()
                } else {
                    format!("{}/", entry.path)
                };
                
                let has_children = entries.iter().any(|e| {
                    !e.is_dir && 
                    e.path.starts_with(&dir_path) && 
                    !entries_to_remove.iter().any(|r| r.path == e.path)
                });
                
                if has_children {
                    final_entries_to_keep.push(entry);
                } else {
                    // This directory is now empty, mark for removal
                    entries_to_remove.push(entry);
                }
            } else {
                final_entries_to_keep.push(entry);
            }
        }
        
        (final_entries_to_keep, entries_to_remove)
    } else {
        (entries_to_keep, entries_to_remove)
    }
}

fn perform_actual_removal(
    opts: &ArchiveRemoveOptions,
    format: &ArchiveFormat,
    compression: &CompressionKind,
    entries_to_keep: &[ArchiveEntry],
) -> Result<PathBuf> {
    let archive_path = Path::new(&opts.archive);
    let archive_dir = archive_path.parent().unwrap_or(Path::new("."));
    
    // Create temp file in the same directory or specified tmp_dir
    let temp_dir = if let Some(tmp_dir) = &opts.tmp_dir {
        Path::new(tmp_dir)
    } else {
        archive_dir
    };
    
    let temp_path = temp_dir.join(format!(".tmp_archive_{}", SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()));
    
    match format {
        ArchiveFormat::Tar | ArchiveFormat::TarGz | ArchiveFormat::TarXz | ArchiveFormat::TarZstd => {
            create_new_tar_archive(&opts.archive, &temp_path, compression, entries_to_keep)?;
        }
        ArchiveFormat::Zip => {
            create_new_zip_archive(&opts.archive, &temp_path, entries_to_keep)?;
        }
        _ => bail!("Unsupported format for archive creation"),
    }
    
    Ok(temp_path)
}

fn create_new_tar_archive(
    original_path: &str,
    new_path: &PathBuf,
    compression: &CompressionKind,
    entries_to_keep: &[ArchiveEntry],
) -> Result<()> {
    let new_file = File::create(new_path)?;
    let new_file = BufWriter::new(new_file);
    
    // Create the new archive with appropriate compression
    match compression {
        CompressionKind::Gzip => {
            let encoder = GzEncoder::new(new_file, Compression::default());
            let mut new_archive = tar::Builder::new(encoder);
            copy_tar_entries(original_path, &mut new_archive, compression, entries_to_keep)?;
            new_archive.finish()?;
        }
        CompressionKind::Xz => {
            let encoder = XzEncoder::new(new_file, 6);
            let mut new_archive = tar::Builder::new(encoder);
            copy_tar_entries(original_path, &mut new_archive, compression, entries_to_keep)?;
            new_archive.finish()?;
        }
        CompressionKind::Zstd => {
            let encoder = ZstdEncoder::new(new_file, 3)?;
            let mut new_archive = tar::Builder::new(encoder);
            copy_tar_entries(original_path, &mut new_archive, compression, entries_to_keep)?;
            new_archive.finish()?;
        }
        CompressionKind::None => {
            let mut new_archive = tar::Builder::new(new_file);
            copy_tar_entries(original_path, &mut new_archive, compression, entries_to_keep)?;
            new_archive.finish()?;
        }
        _ => bail!("Unsupported compression for tar archive"),
    }
    
    Ok(())
}

fn copy_tar_entries<W: Write>(
    original_path: &str,
    new_archive: &mut tar::Builder<W>,
    compression: &CompressionKind,
    entries_to_keep: &[ArchiveEntry],
) -> Result<()> {
    let file = File::open(original_path)?;
    
    // Open original archive for reading
    match compression {
        CompressionKind::Gzip => {
            let decoder = GzDecoder::new(file);
            let mut archive = tar::Archive::new(decoder);
            copy_tar_entries_from_archive(&mut archive, new_archive, entries_to_keep)?;
        }
        CompressionKind::Xz => {
            let decoder = XzDecoder::new(file);
            let mut archive = tar::Archive::new(decoder);
            copy_tar_entries_from_archive(&mut archive, new_archive, entries_to_keep)?;
        }
        CompressionKind::Zstd => {
            let decoder = ZstdDecoder::new(file)?;
            let mut archive = tar::Archive::new(decoder);
            copy_tar_entries_from_archive(&mut archive, new_archive, entries_to_keep)?;
        }
        CompressionKind::None => {
            let mut archive = tar::Archive::new(file);
            copy_tar_entries_from_archive(&mut archive, new_archive, entries_to_keep)?;
        }
        _ => bail!("Unsupported compression for tar archive"),
    }
    
    Ok(())
}

fn copy_tar_entries_from_archive<R: Read, W: Write>(
    source_archive: &mut tar::Archive<R>,
    dest_archive: &mut tar::Builder<W>,
    entries_to_keep: &[ArchiveEntry],
) -> Result<()> {
    for entry in source_archive.entries()? {
        let mut entry = entry?;
        let path = entry.header().path()?.to_string_lossy().to_string();
        let normalized_path = normalize_archive_path(&path);
        
        // Check if this entry should be kept
        if entries_to_keep.iter().any(|e| e.path == normalized_path) {
            dest_archive.append(&entry.header().clone(), &mut entry)?;
        }
    }
    Ok(())
}

fn create_new_zip_archive(
    original_path: &str,
    new_path: &PathBuf,
    entries_to_keep: &[ArchiveEntry],
) -> Result<()> {
    let new_file = File::create(new_path)?;
    let mut new_zip = ZipWriter::new(new_file);
    
    // Open original zip for reading
    let original_file = File::open(original_path)?;
    let mut original_zip = ZipArchive::new(original_file)?;
    
    for i in 0..original_zip.len() {
        let mut file = original_zip.by_index(i)?;
        let path = file.name().to_string();
        let normalized_path = normalize_archive_path(&path);
        
        // Check if this entry should be kept
        if entries_to_keep.iter().any(|e| e.path == normalized_path) {
            let options = FileOptions::default()
                .compression_method(file.compression())
                .unix_permissions(file.unix_mode().unwrap_or(0o755));
                
            new_zip.start_file(&path, options)?;
            
            if !file.is_dir() {
                copy(&mut file, &mut new_zip)?;
            }
        }
    }
    
    new_zip.finish()?;
    Ok(())
}

fn normalize_archive_path(path: &str) -> String {
    let mut normalized = path.replace('\\', "/");
    
    // Remove leading ./ or /
    while normalized.starts_with("./") {
        normalized = normalized[2..].to_string();
    }
    while normalized.starts_with('/') {
        normalized = normalized[1..].to_string();
    }
    
    normalized
}