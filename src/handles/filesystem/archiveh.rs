use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use globset::{Glob, GlobSetBuilder};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs::{self, File, create_dir_all};
use std::io::{BufWriter, Read, Write, copy};
use std::path::{Component, Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use url::Url;
use walkdir::WalkDir;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::{self, Status, error_line},
};
use crate::handles::filesystem::tar_limit::limited_archive;

#[path = "archive_args.rs"]
pub mod archive_args;
pub use archive_args::{Deadline, OutputFormat};
use archive_args::{
    DeadlineReader, Parser, backup_path, check_backup_suffix, fail, io_kind, is_tar_header_limit,
    kind_of,
};

// Archive format imports
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use xz2::read::XzDecoder;
use xz2::write::XzEncoder;
use zip::write::{FileOptions, ZipWriter};
use zip::{CompressionMethod, ZipArchive};
use zstd::stream::read::Decoder as ZstdDecoder;
use zstd::stream::write::Encoder as ZstdEncoder;

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("archive", |u| Ok(Box::new(ArchiveHandle::from_url(u)?)));
}

/// Metadata for `resh archive --help` and `resh archive <verb> --help`.
static ARCHIVE_HELP: HandleHelp = HandleHelp {
    description: "The archive handle creates, inspects, verifies, extracts, and modifies \
        local archive files in tar, tar.gz, tar.xz, tar.zst, zip, and gzip formats using \
        built-in libraries, detecting the format from the file extension. The URL target \
        is left empty, as in archive://.list, and every file path is passed as a \
        key=value argument, with path lists given as JSON arrays. Glob patterns are \
        shell-style: * and ? stay within one directory and ** crosses directories.",
    usage: "resh archive://.<verb>[(key=value,...)]",
    verbs: &[
        VerbHelp {
            name: "list",
            definition: "Lists the entries of an archive with their sizes, modes, owners, \
                and modification times, as JSON.",
            detail: Some(VerbDetail {
                usage: "resh archive://.list archive=<path> [includes=<json-array>]\n  \
                    [excludes=<json-array>] [include_metadata=true|false]\n  \
                    [include_compressed_size=true|false] [max_entries=<n>]\n  \
                    [max_total_bytes=<n>] [format=<archive-format>]\n  \
                    [compression=auto|none|gzip|xz|zstd]\n  \
                    [fail_on_missing_archive=true|false] [timeout_ms=<n>]\n  \
                    [format_output=json|text]",
                example: "resh --json-pretty archive://.list archive=logs.tar.gz",
                example_output: Some(
                    r#"{
  "error": null,
  "manifest": [
    {
      "compressed_size": null,
      "gid": 1000,
      "gname": "",
      "is_dir": false,
      "is_symlink": false,
      "mode": "100644",
      "mtime_unix": 1794055642,
      "path": "app.log",
      "size": 14,
      "uid": 1000,
      "uname": ""
    }
  ],
  "ok": true,
  "query": {
    "archive": "logs.tar.gz",
    "compression": "gzip",
    "excludes": [],
    "fail_on_missing_archive": true,
    "format": "tar.gz",
    "format_output": "json",
    "include_compressed_size": true,
    "include_metadata": true,
    "includes": [],
    "max_entries": 1000000,
    "max_total_bytes": null
  },
  "summary": {
    "archive": "logs.tar.gz",
    "bytes_compressed": 113,
    "bytes_total": 14,
    "compression": "gzip",
    "entries_listed": 1,
    "entries_total": 1,
    "format": "tar.gz"
  },
  "timestamp_unix_ms": 1794055642946,
  "warnings": []
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "info",
            definition: "Reports archive-level details such as format, compression, size, \
                entry counts, compression ratio, and modification time range, as JSON.",
            detail: Some(VerbDetail {
                usage: "resh archive://.info archive=<path> [scan_entries=true|false]\n  \
                    [max_entries=<n>] [max_total_bytes=<n>] [format=<archive-format>]\n  \
                    [compression=auto|none|gzip|xz|zstd]\n  \
                    [fail_on_missing_archive=true|false] [timeout_ms=<n>]\n  \
                    [format_output=json|text]",
                example: "resh --json-pretty archive://.info archive=logs.tar.gz",
                example_output: Some(
                    r#"{
  "details": {
    "seven_z": null,
    "zip": null
  },
  "error": null,
  "ok": true,
  "query": {
    "archive": "logs.tar.gz",
    "compression": "gzip",
    "fail_on_missing_archive": true,
    "format": "tar.gz",
    "format_output": "json",
    "max_entries": 1000000,
    "max_total_bytes": null,
    "scan_entries": true
  },
  "summary": {
    "archive": "logs.tar.gz",
    "archive_mtime_unix": 1794055642,
    "archive_size_bytes": 113,
    "compression": "gzip",
    "compression_ratio": 0.12389380530973453,
    "directories": 0,
    "encrypted": false,
    "entries_total": 1,
    "files": 1,
    "format": "tar.gz",
    "max_mtime_unix": 1794055642,
    "min_mtime_unix": 1794055642,
    "other": 0,
    "solid": null,
    "symlinks": 0,
    "uncompressed_bytes_total": 14
  },
  "timestamp_unix_ms": 1794055642963,
  "warnings": []
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "test",
            definition: "Verifies the integrity of an archive by reading every entry and its \
                data, reporting a per-entry status and an overall valid flag as JSON.",
            detail: Some(VerbDetail {
                usage: "resh archive://.test archive=<path> [verify_data=true|false]\n  \
                    [report_entries=true|false] [stop_on_first_error=true|false]\n  \
                    [max_entries=<n>] [max_total_bytes=<n>] [max_file_bytes=<n>]\n  \
                    [format=<archive-format>] [compression=auto|none|gzip|xz|zstd]\n  \
                    [fail_on_missing_archive=true|false] [timeout_ms=<n>]\n  \
                    [format_output=json|text]",
                example: "resh --json-pretty archive://.test archive=logs.tar.gz",
                example_output: Some(
                    r#"{
  "entries": [
    {
      "error": null,
      "is_dir": false,
      "is_symlink": false,
      "path": "app.log",
      "size": 14,
      "status": "ok"
    }
  ],
  "error": null,
  "ok": true,
  "query": {
    "archive": "logs.tar.gz",
    "compression": "gzip",
    "fail_on_missing_archive": true,
    "format": "tar.gz",
    "format_output": "json",
    "max_entries": 1000000,
    "max_file_bytes": null,
    "max_total_bytes": null,
    "report_entries": true,
    "stop_on_first_error": true,
    "verify_data": true
  },
  "summary": {
    "archive": "logs.tar.gz",
    "bytes_tested": 14,
    "compression": "gzip",
    "entries_failed": 0,
    "entries_tested": 1,
    "format": "tar.gz",
    "stopped_early": false,
    "valid": true
  },
  "timestamp_unix_ms": 1794055642976,
  "warnings": []
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "create",
            definition: "Creates an unencrypted tar, tar.gz, tar.xz, tar.zst, zip, or gzip \
                archive from source files and directories, with optional glob filters, and \
                reports the archived files as JSON (password= is refused).",
            detail: Some(VerbDetail {
                usage: "resh archive://.create output=<path> sources=<json-array>\n  \
                    [format=auto|tar|tar.gz|tar.xz|tar.zst|zip|gzip] [base_dir=<dir>]\n  \
                    [compression_level=<n>] [include_patterns=<json-array>]\n  \
                    [exclude_patterns=<json-array>] [include_hidden=true|false]\n  \
                    [follow_symlinks=true|false] [overwrite=true|false]\n  \
                    [preserve_permissions=true|false] [preserve_timestamps=true|false]\n  \
                    [max_files=<n>] [max_size_mb=<n>] [progress=true|false]\n  \
                    [timeout_ms=<n>] [format_output=json|text] [password=<refused>]",
                example: "resh --json-pretty archive://.create output=logs.tar.gz 'sources=[\"app.log\"]'",
                example_output: Some(
                    r#"{
  "error": null,
  "files": [
    {
      "file_type": "file",
      "modified_unix_ms": 1794055642912,
      "path": "app.log",
      "size_bytes": 14
    }
  ],
  "ok": true,
  "query": {
    "base_dir": null,
    "compression_level": null,
    "exclude_patterns": [],
    "follow_symlinks": false,
    "format": "tar.gz",
    "format_output": "json",
    "include_hidden": true,
    "include_patterns": [],
    "max_files": 100000,
    "max_size_mb": 10240,
    "output": "logs.tar.gz",
    "overwrite": false,
    "preserve_permissions": true,
    "preserve_timestamps": true,
    "progress": false,
    "sources": [
      "app.log"
    ]
  },
  "result": {
    "compressed_size_bytes": 113,
    "compression_ratio": -7.071428571428571,
    "directories_archived": 0,
    "duration_ms": 1,
    "files_archived": 1,
    "format_detected": "tar.gz",
    "output_path": "logs.tar.gz",
    "total_size_bytes": 14
  },
  "statistics": {
    "files_by_type": {
      "log": 1
    },
    "largest_files": [
      {
        "file_type": "file",
        "modified_unix_ms": 1794055642912,
        "path": "app.log",
        "size_bytes": 14
      }
    ]
  },
  "timestamp_unix_ms": 1794055642929,
  "warnings": []
}

Shown with --json-pretty. The format argument selects the archive format
and format_output the report format; 7z archives and raw .xz or .zst
streams cannot be created."#,
                ),
            }),
        },
        VerbHelp {
            name: "extract",
            definition: "Extracts the entries of an archive into a destination directory, \
                rejecting absolute paths and parent traversal by default, and reports a \
                manifest as JSON.",
            detail: Some(VerbDetail {
                usage: "resh archive://.extract archive=<path> destination=<dir>\n  \
                    [includes=<json-array>] [excludes=<json-array>]\n  \
                    [overwrite=true|false] [strip_components=<n>]\n  \
                    [create_destination=true|false] [allow_absolute_paths=true|false]\n  \
                    [allow_parent_traversal=true|false] [allow_symlinks=true|false]\n  \
                    [follow_symlinks=false] [max_entries=<n>]\n  \
                    [max_total_bytes=<n>] [max_file_bytes=<n>]\n  \
                    [format=<archive-format>] [compression=auto|none|gzip|xz|zstd]\n  \
                    [fail_on_missing_archive=true|false] [include_manifest=true|false]\n  \
                    [timeout_ms=<n>] [format_output=json|text]",
                example: "resh --json-pretty archive://.extract archive=logs.tar.gz destination=restore",
                example_output: Some(
                    r#"{
  "error": null,
  "manifest": [
    {
      "is_dir": false,
      "is_symlink": false,
      "path": "app.log",
      "size": 14
    }
  ],
  "ok": true,
  "query": {
    "allow_absolute_paths": false,
    "allow_parent_traversal": false,
    "allow_symlinks": true,
    "archive": "logs.tar.gz",
    "compression": "gzip",
    "create_destination": true,
    "destination": "restore",
    "excludes": [],
    "fail_on_missing_archive": true,
    "follow_symlinks": false,
    "format": "tar.gz",
    "format_output": "json",
    "include_manifest": true,
    "includes": [],
    "max_entries": 1000000,
    "max_file_bytes": null,
    "max_total_bytes": null,
    "overwrite": false,
    "strip_components": 0
  },
  "summary": {
    "archive": "logs.tar.gz",
    "bytes_written": 14,
    "compression": "gzip",
    "destination": "restore",
    "duration_ms": 0,
    "entries_extracted": 1,
    "entries_skipped": 0,
    "entries_total": 1,
    "format": "tar.gz"
  },
  "timestamp_unix_ms": 1794055642992,
  "warnings": []
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "add",
            definition: "Adds files or directories to an existing archive by rewriting it, \
                optionally replacing entries that already exist, and reports the changes as JSON.",
            detail: Some(VerbDetail {
                usage: "resh archive://.add archive=<path> inputs=<json-array>\n  \
                    [base_dir=<dir>] [includes=<json-array>] [excludes=<json-array>]\n  \
                    [overwrite=true|false] [keep_existing_dirs=true|false]\n  \
                    [follow_symlinks=true|false] [preserve_owner=true|false]\n  \
                    [preserve_permissions=true|false] [preserve_timestamps=true|false]\n  \
                    [deterministic=true|false] [backup_suffix=<suffix>]\n  \
                    [tmp_dir=<dir>] [max_entries=<n>] [max_total_bytes=<n>]\n  \
                    [format=<archive-format>] [compression=auto|none|gzip|xz|zstd]\n  \
                    [timeout_ms=<n>] [format_output=json|text]",
                example: "resh --json-pretty archive://.add archive=logs.tar.gz 'inputs=[\"db.log\"]'",
                example_output: Some(
                    r#"{
  "details": {
    "added": [
      "db.log"
    ],
    "replaced": [],
    "skipped": []
  },
  "error": null,
  "ok": true,
  "query": {
    "archive": "logs.tar.gz",
    "backup_suffix": null,
    "base_dir": null,
    "compression": "gzip",
    "deterministic": false,
    "excludes": [],
    "follow_symlinks": false,
    "format": "tar.gz",
    "format_output": "json",
    "includes": [],
    "inputs": [
      "db.log"
    ],
    "keep_existing_dirs": true,
    "max_entries": 1000000,
    "max_total_bytes": null,
    "overwrite": false,
    "preserve_owner": false,
    "preserve_permissions": true,
    "preserve_timestamps": true,
    "tmp_dir": null
  },
  "summary": {
    "archive": "logs.tar.gz",
    "archive_size_bytes_after": 148,
    "archive_size_bytes_before": 113,
    "compression": "gzip",
    "entries_added": 1,
    "entries_after": 2,
    "entries_before": 1,
    "entries_replaced": 0,
    "entries_skipped": 0,
    "format": "tar.gz",
    "uncompressed_bytes_after": 24,
    "uncompressed_bytes_before": 14
  },
  "timestamp_unix_ms": 1794055643010,
  "warnings": []
}

Shown with --json-pretty. Inputs prefixed with glob: are expanded as
patterns."#,
                ),
            }),
        },
        VerbHelp {
            name: "remove",
            definition: "Removes entries from an existing archive by exact path, glob \
                pattern, or directory prefix, rewriting the archive unless dry_run is set.",
            detail: Some(VerbDetail {
                usage: "resh archive://.remove archive=<path> [paths=<json-array>]\n  \
                    [patterns=<json-array>] [dir_prefixes=<json-array>]\n  \
                    [dry_run=true|false] [remove_empty_dirs=true|false]\n  \
                    [backup_suffix=<suffix>] [tmp_dir=<dir>] [max_entries=<n>]\n  \
                    [max_total_bytes=<n>] [format=<archive-format>]\n  \
                    [compression=auto|none|gzip|xz|zstd]\n  \
                    [fail_on_missing_archive=true|false] [timeout_ms=<n>]\n  \
                    [format_output=json|text]",
                example: "resh --json-pretty archive://.remove archive=logs.tar.gz 'paths=[\"db.log\"]'",
                example_output: Some(
                    r#"{
  "details": {
    "kept": [
      "app.log"
    ],
    "not_found": [],
    "removed": [
      "db.log"
    ]
  },
  "error": null,
  "ok": true,
  "query": {
    "archive": "logs.tar.gz",
    "backup_suffix": null,
    "compression": "gzip",
    "dir_prefixes": [],
    "dry_run": false,
    "fail_on_missing_archive": true,
    "format": "tar.gz",
    "format_output": "json",
    "max_entries": 1000000,
    "max_total_bytes": null,
    "paths": [
      "db.log"
    ],
    "patterns": [],
    "remove_empty_dirs": true,
    "tmp_dir": null
  },
  "summary": {
    "archive": "logs.tar.gz",
    "archive_size_bytes_after": 113,
    "archive_size_bytes_before": 148,
    "compression": "gzip",
    "dirs_removed": 0,
    "dry_run": false,
    "entries_after": 1,
    "entries_before": 2,
    "entries_removed": 1,
    "format": "tar.gz",
    "uncompressed_bytes_after": 14,
    "uncompressed_bytes_before": 24
  },
  "timestamp_unix_ms": 1794055643063,
  "warnings": []
}

Shown with --json-pretty. At least one of paths, patterns, or
dir_prefixes is required."#,
                ),
            }),
        },
    ],
};

pub struct ArchiveHandle {
    _url: Url,
}

impl ArchiveHandle {
    pub fn from_url(url: &Url) -> Result<Self> {
        Ok(ArchiveHandle { _url: url.clone() })
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
        matches!(
            self,
            Self::TarGz
                | Self::TarXz
                | Self::TarZstd
                | Self::Zip
                | Self::SevenZ
                | Self::Gzip
                | Self::Raw
        )
    }

    /// Whether `create` can write a password-protected archive in this
    /// format. None can: the zip writer (zip 0.6) cannot encrypt entries,
    /// and 7z creation is not supported. A password is therefore rejected
    /// rather than silently producing an unencrypted archive.
    pub fn supports_password(&self) -> bool {
        false
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
        if path.ends_with(".gz") || path.ends_with(".tgz") {
            Self::Gzip
        } else if path.ends_with(".xz") || path.ends_with(".txz") {
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
    pub deadline: Deadline,
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
    pub deadline: Deadline,
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
    pub deadline: Deadline,
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

    pub deadline: Deadline,
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

    pub deadline: Deadline,
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

    pub deadline: Deadline,
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

    pub deadline: Deadline,
    pub format_output: OutputFormat,
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

    #[serde(serialize_with = "ser_error")]
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
    #[serde(serialize_with = "ser_error")]
    pub error: Option<(String, String)>,
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

    #[serde(serialize_with = "ser_error")]
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

    #[serde(serialize_with = "ser_error")]
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

    #[serde(serialize_with = "ser_error")]
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

    #[serde(serialize_with = "ser_error")]
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
    /// Where the entry is read from.
    #[serde(skip)]
    pub source: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveExtractManifestEntry {
    pub path: String, // destination-relative
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
    #[serde(serialize_with = "ser_error")]
    pub error: Option<(String, String)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveExtractResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub query: Value,
    pub summary: Option<ArchiveExtractSummary>,
    pub manifest: Option<Vec<ArchiveExtractManifestEntry>>,

    #[serde(serialize_with = "ser_error")]
    pub error: Option<(String, String)>,
    pub warnings: Vec<String>,
}

/// The archive format named by `format=` (`auto` or absent: detected from
/// `path`'s extension).
fn parse_format(p: &Parser, path: &str) -> Result<ArchiveFormat> {
    match p.get("format").map(str::to_ascii_lowercase) {
        None => detect_format(path),
        Some(s) if s == "auto" => detect_format(path),
        Some(s) => ArchiveFormat::from_str(&s).map_err(|e| fail("invalid_format", e.to_string())),
    }
}

fn detect_format(path: &str) -> Result<ArchiveFormat> {
    ArchiveFormat::detect_from_extension(path).map_err(|e| {
        fail(
            "invalid_format_infer",
            format!("{e}; pass format= to name the format"),
        )
    })
}

/// Resolves `format=` and `compression=` for a verb that reads `path`.
///
/// A compressed tar format implies its compression, zip and 7z imply none,
/// and `gzip` means a raw gzip stream. With `format=tar` or a raw stream an
/// automatic compression is taken from the extension. A compression that
/// contradicts the format is refused.
fn resolve_read_format(p: &Parser, path: &str) -> Result<(ArchiveFormat, CompressionKind)> {
    use ArchiveFormat as F;
    use CompressionKind as C;
    let format = parse_format(p, path)?;
    let explicit = match p.get("compression").map(str::to_ascii_lowercase) {
        None => None,
        Some(s) if s == "auto" => None,
        Some(s) => Some(
            CompressionKind::from_str(&s)
                .map_err(|e| fail("invalid_compression", e.to_string()))?,
        ),
    };
    let implied = match format {
        F::TarGz | F::Gzip => Some(C::Gzip),
        F::TarXz => Some(C::Xz),
        F::TarZstd => Some(C::Zstd),
        F::Zip | F::SevenZ => Some(C::None),
        F::Tar | F::Raw | F::Auto => None,
    };
    let compression = match (implied, explicit) {
        (Some(i), Some(e)) if i != e => {
            return Err(fail(
                "invalid_format_compression",
                format!(
                    "format {} cannot be read with compression={}",
                    format.as_str(),
                    e.as_str()
                ),
            ));
        }
        (Some(i), _) => i,
        (None, Some(e)) => e,
        (None, None) => C::detect_from_extension(path),
    };
    let format = match (format, &compression) {
        (F::Gzip, _) => F::Raw,
        (F::Tar, C::Gzip) => F::TarGz,
        (F::Tar, C::Xz) => F::TarXz,
        (F::Tar, C::Zstd) => F::TarZstd,
        (f, _) => f,
    };
    if format == F::Raw && compression == C::None {
        return Err(fail(
            "invalid_format_compression",
            "Raw format requires compression (gzip, xz, or zstd)",
        ));
    }
    Ok((format, compression))
}

/// A shell-style glob: `*` and `?` do not match `/`, `**` matches across
/// directories.
fn shell_glob(pattern: &str) -> std::result::Result<Glob, globset::Error> {
    globset::GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()
}

/// Compiles glob patterns, failing with `kind` on the first invalid one.
fn check_globs(patterns: &[String], kind: &'static str, what: &str) -> Result<()> {
    for pattern in patterns {
        shell_glob(pattern)
            .map_err(|e| fail(kind, format!("Invalid {what} pattern {pattern:?}: {e}")))?;
    }
    Ok(())
}

impl ArchiveCreateOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let p = Parser::new(args, "create")?;
        // A password is refused first: no other problem may be reported in
        // a way that suggests the archive could be encrypted.
        let password = p.get("password").map(str::to_string);
        if password.is_some() {
            return Err(fail(
                "password_not_supported",
                "Password protection not supported: encrypted archives cannot be created, so no archive was written",
            ));
        }
        let output = p.required("output", "invalid_output")?;
        let sources = match p.get("sources") {
            None => {
                return Err(fail(
                    "invalid_sources",
                    "Missing required parameter: sources",
                ));
            }
            Some(_) => p.list("sources", "invalid_sources")?,
        };
        if sources.is_empty() {
            return Err(fail("invalid_sources", "Sources list cannot be empty"));
        }
        if sources.iter().any(String::is_empty) {
            return Err(fail("invalid_sources", "A source path cannot be empty"));
        }

        let base_dir = p.optional("base_dir", "invalid_base_dir")?;
        if let Some(dir) = &base_dir {
            if !Path::new(dir).is_dir() {
                return Err(fail(
                    "invalid_base_dir",
                    format!("Base directory does not exist or is not a directory: {dir}"),
                ));
            }
        }

        let format = match p.get("format").map(str::to_ascii_lowercase) {
            None => detect_format(&output).map_err(|e| fail("invalid_format", e.to_string()))?,
            Some(s) if s == "auto" => {
                detect_format(&output).map_err(|e| fail("invalid_format", e.to_string()))?
            }
            Some(s) => {
                ArchiveFormat::from_str(&s).map_err(|e| fail("invalid_format", e.to_string()))?
            }
        };
        if matches!(format, ArchiveFormat::SevenZ | ArchiveFormat::Raw) {
            let hint = if format == ArchiveFormat::Raw {
                "; for a single gzip file pass format=gzip"
            } else {
                ""
            };
            return Err(fail(
                "compression_failed",
                format!(
                    "Archive format {} not yet implemented for create{hint}",
                    format.as_str()
                ),
            ));
        }

        let compression_level = match p.opt_u64("compression_level", "invalid_compression_level")? {
            None => None,
            Some(_) if !format.supports_compression_level() => {
                return Err(fail(
                    "invalid_compression_level",
                    format!(
                        "compression_level is not accepted for format {} (it is not compressed)",
                        format.as_str()
                    ),
                ));
            }
            Some(level) if level < 1 || level > u64::from(format.max_compression_level()) => {
                return Err(fail(
                    "invalid_compression_level",
                    format!(
                        "Invalid compression level {} for format {}. Must be 1-{}",
                        level,
                        format.as_str(),
                        format.max_compression_level()
                    ),
                ));
            }
            Some(level) => Some(level as u32),
        };

        let include_patterns = p.list("include_patterns", "invalid_pattern")?;
        let exclude_patterns = p.list("exclude_patterns", "invalid_pattern")?;
        check_globs(&include_patterns, "invalid_pattern", "include")?;
        check_globs(&exclude_patterns, "invalid_pattern", "exclude")?;

        let max_files = p.u64("max_files", 100_000, "invalid_max_files")?;
        let max_size_mb = p.u64("max_size_mb", 10_240, "invalid_max_size")?;
        if max_size_mb.checked_mul(1024 * 1024).is_none() {
            return Err(fail(
                "invalid_max_size",
                format!("invalid value for max_size_mb: {max_size_mb} is too large"),
            ));
        }

        Ok(ArchiveCreateOptions {
            output,
            sources,
            base_dir,
            format,
            compression_level,
            include_patterns,
            exclude_patterns,
            include_hidden: p.bool("include_hidden", true)?,
            follow_symlinks: p.bool("follow_symlinks", false)?,
            password,
            overwrite: p.bool("overwrite", false)?,
            preserve_permissions: p.bool("preserve_permissions", true)?,
            preserve_timestamps: p.bool("preserve_timestamps", true)?,
            max_files,
            max_size_mb,
            progress: p.bool("progress", false)?,
            deadline: p.deadline()?,
            output_format: p.output_format()?,
        })
    }
}

impl ArchiveExtractOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let p = Parser::new(args, "extract")?;
        let archive = p.required("archive", "invalid_archive_path")?;
        let destination = p.required("destination", "invalid_destination")?;
        let (format, compression) = resolve_read_format(&p, &archive)?;

        let includes = p.list("includes", "invalid_include_pattern")?;
        let excludes = p.list("excludes", "invalid_exclude_pattern")?;
        check_globs(&includes, "invalid_include_pattern", "include")?;
        check_globs(&excludes, "invalid_exclude_pattern", "exclude")?;

        let strip_components = p.u64("strip_components", 0, "invalid_strip_components")?;
        let strip_components = u32::try_from(strip_components).map_err(|_| {
            fail(
                "invalid_strip_components",
                format!("invalid value for strip_components: {strip_components} is too large"),
            )
        })?;

        let follow_symlinks = p.bool("follow_symlinks", false)?;
        if follow_symlinks {
            return Err(fail(
                "invalid_argument",
                "follow_symlinks=true is not supported by extract: extraction never follows \
                 or writes through a symlink",
            ));
        }

        let opts = ArchiveExtractOptions {
            overwrite: p.bool("overwrite", false)?,
            create_destination: p.bool("create_destination", true)?,
            fail_on_missing_archive: p.bool("fail_on_missing_archive", true)?,
            strip_components,
            allow_absolute_paths: p.bool("allow_absolute_paths", false)?,
            allow_parent_traversal: p.bool("allow_parent_traversal", false)?,
            allow_symlinks: p.bool("allow_symlinks", true)?,
            follow_symlinks,
            max_entries: p.u64("max_entries", 1_000_000, "invalid_max_entries")?,
            max_total_bytes: p.opt_u64("max_total_bytes", "invalid_max_size")?,
            max_file_bytes: p.opt_u64("max_file_bytes", "invalid_max_file_size")?,
            include_manifest: p.bool("include_manifest", true)?,
            deadline: p.deadline()?,
            format_output: p.output_format()?,
            archive,
            destination,
            format,
            compression,
            includes,
            excludes,
        };
        Ok(opts)
    }
}

impl ArchiveListOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let p = Parser::new(args, "list")?;
        let archive = p.required("archive", "invalid_archive_path")?;
        let (format, compression) = resolve_read_format(&p, &archive)?;
        let includes = p.list("includes", "invalid_include_pattern")?;
        let excludes = p.list("excludes", "invalid_exclude_pattern")?;
        check_globs(&includes, "invalid_include_pattern", "include")?;
        check_globs(&excludes, "invalid_exclude_pattern", "exclude")?;
        Ok(ArchiveListOptions {
            max_entries: p.u64("max_entries", 1_000_000, "invalid_max_entries")?,
            max_total_bytes: p.opt_u64("max_total_bytes", "invalid_max_size")?,
            fail_on_missing_archive: p.bool("fail_on_missing_archive", true)?,
            include_metadata: p.bool("include_metadata", true)?,
            include_compressed_size: p.bool("include_compressed_size", true)?,
            deadline: p.deadline()?,
            format_output: p.output_format()?,
            archive,
            format,
            compression,
            includes,
            excludes,
        })
    }
}

impl ArchiveTestOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let p = Parser::new(args, "test")?;
        let archive = p.required("archive", "invalid_archive_path")?;
        let (format, compression) = resolve_read_format(&p, &archive)?;
        Ok(ArchiveTestOptions {
            stop_on_first_error: p.bool("stop_on_first_error", true)?,
            report_entries: p.bool("report_entries", true)?,
            verify_data: p.bool("verify_data", true)?,
            max_entries: p.u64("max_entries", 1_000_000, "invalid_max_entries")?,
            max_total_bytes: p.opt_u64("max_total_bytes", "invalid_max_size")?,
            max_file_bytes: p.opt_u64("max_file_bytes", "invalid_max_file_size")?,
            fail_on_missing_archive: p.bool("fail_on_missing_archive", true)?,
            deadline: p.deadline()?,
            format_output: p.output_format()?,
            archive,
            format,
            compression,
        })
    }
}

impl ArchiveInfoOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let p = Parser::new(args, "info")?;
        let archive = p.required("archive", "invalid_archive_path")?;
        let (format, compression) = resolve_read_format(&p, &archive)?;
        Ok(ArchiveInfoOptions {
            scan_entries: p.bool("scan_entries", true)?,
            max_entries: p.u64("max_entries", 1_000_000, "invalid_max_entries")?,
            max_total_bytes: p.opt_u64("max_total_bytes", "invalid_max_size")?,
            fail_on_missing_archive: p.bool("fail_on_missing_archive", true)?,
            deadline: p.deadline()?,
            format_output: p.output_format()?,
            archive,
            format,
            compression,
        })
    }
}

/// Refuses formats that `add` and `remove` cannot rewrite.
fn check_rewritable(format: &ArchiveFormat, verb: &str) -> Result<()> {
    match format {
        ArchiveFormat::Raw | ArchiveFormat::Gzip => Err(fail(
            "unsupported_for_raw",
            format!(
                "{} entries in raw compressed streams (gzip/xz/zstd) is not supported",
                if verb == "add" { "Adding" } else { "Removing" }
            ),
        )),
        ArchiveFormat::SevenZ => Err(fail(
            "7z_unsupported",
            format!("7z archive {verb} is not supported"),
        )),
        _ => Ok(()),
    }
}

impl ArchiveAddOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let p = Parser::new(args, "add")?;
        let archive = p.required("archive", "invalid_archive_path")?;
        let inputs = match p.get("inputs") {
            None => return Err(fail("invalid_input", "Missing required parameter: inputs")),
            Some(_) => p.list("inputs", "invalid_input")?,
        };
        if inputs.is_empty() {
            return Err(fail("invalid_input", "Inputs list cannot be empty"));
        }
        if inputs.iter().any(|i| i.is_empty() || i == "glob:") {
            return Err(fail("invalid_input", "An input path cannot be empty"));
        }
        for input in &inputs {
            if let Some(pattern) = input.strip_prefix("glob:") {
                shell_glob(pattern).map_err(|e| {
                    fail(
                        "invalid_input",
                        format!("Invalid glob input {pattern:?}: {e}"),
                    )
                })?;
            }
        }
        let (format, compression) = resolve_read_format(&p, &archive)?;
        check_rewritable(&format, "add")?;

        let includes = p.list("includes", "invalid_include_pattern")?;
        let excludes = p.list("excludes", "invalid_exclude_pattern")?;
        check_globs(&includes, "invalid_include_pattern", "include")?;
        check_globs(&excludes, "invalid_exclude_pattern", "exclude")?;

        let backup_suffix = p.get("backup_suffix").map(str::to_string);
        if let Some(s) = &backup_suffix {
            check_backup_suffix(s)?;
        }

        Ok(ArchiveAddOptions {
            base_dir: p.optional("base_dir", "invalid_argument")?,
            follow_symlinks: p.bool("follow_symlinks", false)?,
            overwrite: p.bool("overwrite", false)?,
            keep_existing_dirs: p.bool("keep_existing_dirs", true)?,
            preserve_owner: p.bool("preserve_owner", false)?,
            preserve_permissions: p.bool("preserve_permissions", true)?,
            preserve_timestamps: p.bool("preserve_timestamps", true)?,
            deterministic: p.bool("deterministic", false)?,
            max_entries: p.u64("max_entries", 1_000_000, "invalid_max_entries")?,
            max_total_bytes: p.opt_u64("max_total_bytes", "invalid_max_size")?,
            tmp_dir: p.optional("tmp_dir", "invalid_argument")?,
            backup_suffix,
            deadline: p.deadline()?,
            format_output: p.output_format()?,
            archive,
            inputs,
            format,
            compression,
            includes,
            excludes,
        })
    }
}

impl ArchiveRemoveOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let p = Parser::new(args, "remove")?;
        let archive = p.required("archive", "invalid_archive_path")?;
        let paths = p.list("paths", "invalid_argument")?;
        let patterns = p.list("patterns", "invalid_pattern")?;
        let dir_prefixes = p.list("dir_prefixes", "invalid_argument")?;
        if paths.is_empty() && patterns.is_empty() && dir_prefixes.is_empty() {
            return Err(fail(
                "nothing_to_remove",
                "Nothing to remove - must specify at least one of: paths, patterns, or dir_prefixes",
            ));
        }
        if paths
            .iter()
            .chain(&dir_prefixes)
            .any(|s| normalize_archive_path(s).is_empty())
        {
            return Err(fail(
                "invalid_argument",
                "paths and dir_prefixes cannot contain an empty path",
            ));
        }
        check_globs(&patterns, "invalid_pattern", "remove")?;
        let (format, compression) = resolve_read_format(&p, &archive)?;
        check_rewritable(&format, "remove")?;

        let backup_suffix = p.get("backup_suffix").map(str::to_string);
        if let Some(s) = &backup_suffix {
            check_backup_suffix(s)?;
        }

        Ok(ArchiveRemoveOptions {
            remove_empty_dirs: p.bool("remove_empty_dirs", true)?,
            dry_run: p.bool("dry_run", false)?,
            max_entries: p.u64("max_entries", 1_000_000, "invalid_max_entries")?,
            max_total_bytes: p.opt_u64("max_total_bytes", "invalid_max_size")?,
            fail_on_missing_archive: p.bool("fail_on_missing_archive", true)?,
            tmp_dir: p.optional("tmp_dir", "invalid_argument")?,
            backup_suffix,
            deadline: p.deadline()?,
            format_output: p.output_format()?,
            archive,
            format,
            compression,
            paths,
            patterns,
            dir_prefixes,
        })
    }
}

impl ArchiveListResponse {
    pub fn new(opts: &ArchiveListOptions) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
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
                    for entry in manifest.iter().take(20) {
                        // Limit display to first 20
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
                                output.push_str(&format!(
                                    " mtime={}",
                                    datetime.format("%Y-%m-%dT%H:%M:%SZ")
                                ));
                            }
                        }

                        output.push('\n');
                    }

                    if manifest.len() > 20 {
                        output
                            .push_str(&format!("  ... and {} more entries\n", manifest.len() - 20));
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
            .unwrap_or_default()
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
            output.push_str(&format!(
                "Valid          : {}\n",
                if summary.valid { "yes" } else { "no" }
            ));
            output.push_str(&format!(
                "Stopped Early  : {}\n",
                if summary.stopped_early { "yes" } else { "no" }
            ));

            if let Some(ref entries) = self.entries {
                if !entries.is_empty() {
                    let failed_entries: Vec<_> =
                        entries.iter().filter(|e| e.status == "error").collect();
                    if !failed_entries.is_empty() {
                        output.push_str("\nFailed Entries:\n");
                        for entry in failed_entries.iter().take(10) {
                            // Limit to first 10 failed
                            if let Some((code, message)) = &entry.error {
                                output.push_str(&format!(
                                    "  - {}: [{}] {}\n",
                                    entry.path, code, message
                                ));
                            } else {
                                output.push_str(&format!("  - {}: failed\n", entry.path));
                            }
                        }
                        if failed_entries.len() > 10 {
                            output.push_str(&format!(
                                "  ... and {} more failed entries\n",
                                failed_entries.len() - 10
                            ));
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
            .unwrap_or_default()
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
                    output.push_str(&format!(
                        "Archive Mtime   : {}\n",
                        dt.format("%Y-%m-%dT%H:%M:%SZ")
                    ));
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
                    output.push_str(&format!(
                        "Min Mtime       : {}\n",
                        dt.format("%Y-%m-%dT%H:%M:%SZ")
                    ));
                }
            }
            if let Some(max_mtime) = summary.max_mtime_unix {
                let dt = DateTime::<Utc>::from_timestamp(max_mtime, 0);
                if let Some(dt) = dt {
                    output.push_str(&format!(
                        "Max Mtime       : {}\n",
                        dt.format("%Y-%m-%dT%H:%M:%SZ")
                    ));
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
            .unwrap_or_default()
            .as_millis() as i64;

        let query = json!({
            "output": opts.output,
            "sources": opts.sources,
            "format": opts.format.as_str(),
            "base_dir": opts.base_dir,
            "compression_level": opts.compression_level,
            "include_patterns": opts.include_patterns,
            "exclude_patterns": opts.exclude_patterns,
            "include_hidden": opts.include_hidden,
            "follow_symlinks": opts.follow_symlinks,
            "overwrite": opts.overwrite,
            "preserve_permissions": opts.preserve_permissions,
            "preserve_timestamps": opts.preserve_timestamps,
            "max_files": opts.max_files,
            "max_size_mb": opts.max_size_mb,
            "progress": opts.progress,
            "format_output": opts.output_format.as_str()
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
            output.push_str(&format!(
                "Output      : {} ({} format)\n",
                self.result.output_path, self.result.format_detected
            ));
            output.push_str(&format!(
                "Files       : {} files, {} directories\n",
                self.result.files_archived, self.result.directories_archived
            ));

            let total_mb = self.result.total_size_bytes as f64 / 1024.0 / 1024.0;
            let compressed_mb = self.result.compressed_size_bytes as f64 / 1024.0 / 1024.0;
            let compression = (self.result.compression_ratio * 100.0) as i32;

            output.push_str(&format!(
                "Size        : {:.1} MB -> {:.1} MB ({}% compression)\n",
                total_mb, compressed_mb, compression
            ));
            output.push_str(&format!(
                "Duration    : {:.2} seconds\n\n",
                self.result.duration_ms as f64 / 1000.0
            ));
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
            .unwrap_or_default()
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
            "max_file_bytes": opts.max_file_bytes,
            "include_manifest": opts.include_manifest,
            "format_output": opts.format_output.as_str()
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
                output.push_str(&format!(
                    "Entries Extracted: {}\n",
                    summary.entries_extracted
                ));
                output.push_str(&format!("Entries Skipped  : {}\n", summary.entries_skipped));

                let mb = summary.bytes_written as f64 / 1024.0 / 1024.0;
                output.push_str(&format!("Bytes Written    : {:.1} MB\n", mb));
                output.push_str(&format!(
                    "Duration         : {:.2} s\n\n",
                    summary.duration_ms as f64 / 1000.0
                ));
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
            .unwrap_or_default()
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
                output.push_str(&format!(
                    "Archive Size Before : {:.1} MB\n",
                    archive_mb_before
                ));
                output.push_str(&format!(
                    "Archive Size After  : {:.1} MB\n\n",
                    archive_mb_after
                ));
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
            .unwrap_or_default()
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
                    output.push_str(&format!(
                        "Uncompressed Before : {:.2} GB\n",
                        mb_before / 1024.0
                    ));
                    output.push_str(&format!(
                        "Uncompressed After  : {:.2} GB\n",
                        mb_after / 1024.0
                    ));
                } else {
                    output.push_str(&format!("Uncompressed Before : {:.1} MB\n", mb_before));
                    output.push_str(&format!("Uncompressed After  : {:.1} MB\n", mb_after));
                }

                if archive_mb_before >= 1024.0 {
                    output.push_str(&format!(
                        "Archive Size Before : {:.2} GB\n",
                        archive_mb_before / 1024.0
                    ));
                    output.push_str(&format!(
                        "Archive Size After  : {:.2} GB\n",
                        archive_mb_after / 1024.0
                    ));
                } else {
                    output.push_str(&format!(
                        "Archive Size Before : {:.1} MB\n",
                        archive_mb_before
                    ));
                    output.push_str(&format!(
                        "Archive Size After  : {:.1} MB\n",
                        archive_mb_after
                    ));
                }

                output.push_str(&format!(
                    "Dry Run            : {}\n\n",
                    if summary.dry_run { "yes" } else { "no" }
                ));
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
pub const ARCHIVE_CREATE_INVALID_COMPRESSION_LEVEL: &str =
    "archive.create_invalid_compression_level";
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
pub const ARCHIVE_EXTRACT_DESTINATION_CREATE_FAILED: &str =
    "archive.extract_destination_create_failed";
pub const ARCHIVE_EXTRACT_INVALID_FORMAT: &str = "archive.extract_invalid_format";
pub const ARCHIVE_EXTRACT_INVALID_FORMAT_INFER: &str = "archive.extract_invalid_format_infer";
pub const ARCHIVE_EXTRACT_INVALID_COMPRESSION: &str = "archive.extract_invalid_compression";
pub const ARCHIVE_EXTRACT_INVALID_FORMAT_COMPRESSION: &str =
    "archive.extract_invalid_format_compression";
pub const ARCHIVE_EXTRACT_INVALID_INCLUDE_PATTERN: &str = "archive.extract_invalid_include_pattern";
pub const ARCHIVE_EXTRACT_INVALID_EXCLUDE_PATTERN: &str = "archive.extract_invalid_exclude_pattern";
pub const ARCHIVE_EXTRACT_INVALID_STRIP_COMPONENTS: &str =
    "archive.extract_invalid_strip_components";
pub const ARCHIVE_EXTRACT_INVALID_MAX_ENTRIES: &str = "archive.extract_invalid_max_entries";
pub const ARCHIVE_EXTRACT_INVALID_MAX_SIZE: &str = "archive.extract_invalid_max_size";
pub const ARCHIVE_EXTRACT_INVALID_MAX_FILE_SIZE: &str = "archive.extract_invalid_max_file_size";
pub const ARCHIVE_EXTRACT_PATH_TRAVERSAL_DETECTED: &str = "archive.extract_path_traversal_detected";
pub const ARCHIVE_EXTRACT_ABSOLUTE_PATH_REJECTED: &str = "archive.extract_absolute_path_rejected";
pub const ARCHIVE_EXTRACT_SYMLINK_REJECTED: &str = "archive.extract_symlink_rejected";
pub const ARCHIVE_EXTRACT_UNSUPPORTED_ENTRY_TYPE: &str = "archive.extract_unsupported_entry_type";
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
pub const ARCHIVE_REMOVE_INVALID_FORMAT_COMPRESSION: &str =
    "archive.remove_invalid_format_compression";
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

/// Every error code the archive handle can report (on stderr, in the JSON
/// `error` object, or on a `test` entry). Each one is listed in
/// docs/Filesystem_Storage/archive.md.
pub const ERROR_CODES: &[&str] = &[
    // any verb
    "archive.unknown_verb",
    // create
    "archive.create_invalid_argument",
    "archive.create_internal_error",
    "archive.create_timeout",
    "archive.create_invalid_output",
    "archive.create_invalid_sources",
    "archive.create_invalid_format",
    "archive.create_invalid_base_dir",
    "archive.create_invalid_compression_level",
    "archive.create_invalid_pattern",
    "archive.create_invalid_max_files",
    "archive.create_invalid_max_size",
    "archive.create_password_not_supported",
    "archive.create_compression_failed",
    "archive.create_output_exists",
    "archive.create_source_not_found",
    "archive.create_source_permission_denied",
    "archive.create_max_files_exceeded",
    "archive.create_max_size_exceeded",
    "archive.create_permission_denied",
    "archive.create_disk_full",
    // extract
    "archive.extract_invalid_argument",
    "archive.extract_internal_error",
    "archive.extract_timeout",
    "archive.extract_invalid_archive_path",
    "archive.extract_invalid_format",
    "archive.extract_invalid_format_infer",
    "archive.extract_invalid_compression",
    "archive.extract_invalid_format_compression",
    "archive.extract_invalid_max_entries",
    "archive.extract_invalid_max_size",
    "archive.extract_7z_unsupported",
    "archive.extract_missing_archive",
    "archive.extract_io_error",
    "archive.extract_archive_read_error",
    "archive.extract_max_entries_exceeded",
    "archive.extract_max_size_exceeded",
    "archive.extract_invalid_destination",
    "archive.extract_invalid_include_pattern",
    "archive.extract_invalid_exclude_pattern",
    "archive.extract_invalid_strip_components",
    "archive.extract_invalid_max_file_size",
    "archive.extract_destination_missing",
    "archive.extract_destination_create_failed",
    "archive.extract_path_traversal_detected",
    "archive.extract_absolute_path_rejected",
    "archive.extract_symlink_rejected",
    "archive.extract_unsupported_entry_type",
    "archive.extract_max_file_size_exceeded",
    // list
    "archive.list_invalid_argument",
    "archive.list_internal_error",
    "archive.list_timeout",
    "archive.list_invalid_archive_path",
    "archive.list_invalid_format",
    "archive.list_invalid_format_infer",
    "archive.list_invalid_compression",
    "archive.list_invalid_format_compression",
    "archive.list_invalid_max_entries",
    "archive.list_invalid_max_size",
    "archive.list_7z_unsupported",
    "archive.list_missing_archive",
    "archive.list_io_error",
    "archive.list_archive_read_error",
    "archive.list_max_entries_exceeded",
    "archive.list_max_size_exceeded",
    "archive.list_invalid_include_pattern",
    "archive.list_invalid_exclude_pattern",
    // test
    "archive.test_invalid_argument",
    "archive.test_internal_error",
    "archive.test_timeout",
    "archive.test_invalid_archive_path",
    "archive.test_invalid_format",
    "archive.test_invalid_format_infer",
    "archive.test_invalid_compression",
    "archive.test_invalid_format_compression",
    "archive.test_invalid_max_entries",
    "archive.test_invalid_max_size",
    "archive.test_7z_unsupported",
    "archive.test_missing_archive",
    "archive.test_io_error",
    "archive.test_archive_read_error",
    "archive.test_max_entries_exceeded",
    "archive.test_max_size_exceeded",
    "archive.test_invalid_max_file_size",
    "archive.test_entry_failed",
    "archive.test_max_file_size_exceeded",
    "archive.test_entry_header_error",
    "archive.test_entry_io_error",
    "archive.test_entry_compression_error",
    "archive.test_entry_checksum_error",
    "archive.test_entry_size_mismatch",
    // info
    "archive.info_invalid_argument",
    "archive.info_internal_error",
    "archive.info_timeout",
    "archive.info_invalid_archive_path",
    "archive.info_invalid_format",
    "archive.info_invalid_format_infer",
    "archive.info_invalid_compression",
    "archive.info_invalid_format_compression",
    "archive.info_invalid_max_entries",
    "archive.info_invalid_max_size",
    "archive.info_7z_unsupported",
    "archive.info_missing_archive",
    "archive.info_io_error",
    "archive.info_archive_read_error",
    "archive.info_max_entries_exceeded",
    "archive.info_max_size_exceeded",
    // add
    "archive.add_invalid_argument",
    "archive.add_internal_error",
    "archive.add_timeout",
    "archive.add_invalid_archive_path",
    "archive.add_invalid_format",
    "archive.add_invalid_format_infer",
    "archive.add_invalid_compression",
    "archive.add_invalid_format_compression",
    "archive.add_invalid_max_entries",
    "archive.add_invalid_max_size",
    "archive.add_7z_unsupported",
    "archive.add_missing_archive",
    "archive.add_io_error",
    "archive.add_archive_read_error",
    "archive.add_max_entries_exceeded",
    "archive.add_max_size_exceeded",
    "archive.add_invalid_input",
    "archive.add_invalid_include_pattern",
    "archive.add_invalid_exclude_pattern",
    "archive.add_unsupported_for_raw",
    "archive.add_archive_write_error",
    "archive.add_backup_failed",
    // remove
    "archive.remove_invalid_argument",
    "archive.remove_internal_error",
    "archive.remove_timeout",
    "archive.remove_invalid_archive_path",
    "archive.remove_invalid_format",
    "archive.remove_invalid_format_infer",
    "archive.remove_invalid_compression",
    "archive.remove_invalid_format_compression",
    "archive.remove_invalid_max_entries",
    "archive.remove_invalid_max_size",
    "archive.remove_7z_unsupported",
    "archive.remove_missing_archive",
    "archive.remove_io_error",
    "archive.remove_archive_read_error",
    "archive.remove_max_entries_exceeded",
    "archive.remove_max_size_exceeded",
    "archive.remove_nothing_to_remove",
    "archive.remove_invalid_pattern",
    "archive.remove_unsupported_for_raw",
    "archive.remove_archive_write_error",
    "archive.remove_backup_failed",
    "archive.remove_replace_failed",
];

/// The error code for a failure of `kind` in `verb`:
/// `archive.<verb>_<kind>`.
pub fn error_code(verb: &str, kind: &str) -> String {
    let code = format!("archive.{verb}_{kind}");
    debug_assert!(
        ERROR_CODES.contains(&code.as_str()),
        "undocumented archive error code {code}"
    );
    code
}

/// Serializes a `(code, message)` failure as the project-wide JSON error
/// object `{"code": ..., "message": ...}` (or `null`).
fn ser_error<S: serde::Serializer>(
    error: &Option<(String, String)>,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    match error {
        Some((code, message)) => status::error_json(code, message).serialize(s),
        None => s.serialize_none(),
    }
}

/// The kind of a failure that happened while a verb ran. The tar header
/// data limit is a read error of the archive.
fn runtime_kind(err: &anyhow::Error, default: &'static str) -> &'static str {
    if is_tar_header_limit(err) {
        return "archive_read_error";
    }
    if let Some(kind) = kind_of(err) {
        return kind;
    }
    default
}

/// The error code for an argument that was refused before anything ran.
fn validation_code(verb: &str, err: &anyhow::Error) -> String {
    error_code(verb, kind_of(err).unwrap_or("invalid_argument"))
}

/// Writes the standard `Error: [code] message` line on stderr and returns
/// the matching status. The handle writes the line itself because `create`
/// may already have written progress lines, after which the CLI adds
/// nothing.
fn failed(stderr: &mut dyn Write, code: &str, message: &str) -> Result<Status> {
    writeln!(stderr, "{}", error_line(code, message))?;
    Ok(Status::coded(exit_for(code), code, message))
}

/// Common shape of the verb reports.
trait Report {
    fn is_ok(&self) -> bool;
    fn error_pair(&self) -> Option<&(String, String)>;
    fn json(&self) -> String;
    fn text(&self) -> String;
}

macro_rules! impl_report {
    ($($t:ty),*) => {$(
        impl Report for $t {
            fn is_ok(&self) -> bool {
                self.ok
            }
            fn error_pair(&self) -> Option<&(String, String)> {
                self.error.as_ref()
            }
            fn json(&self) -> String {
                self.to_json()
            }
            fn text(&self) -> String {
                self.to_text()
            }
        }
    )*};
}

impl_report!(
    ArchiveCreateResponse,
    ArchiveExtractResponse,
    ArchiveListResponse,
    ArchiveTestResponse,
    ArchiveInfoResponse,
    ArchiveAddResponse,
    ArchiveRemoveResponse
);

/// Runs one verb: parse (a refused argument prints `[code] message` on
/// stderr and nothing on stdout), execute, print the report, and turn its
/// `ok`/`error` into the exit status.
fn run_verb<O, R: Report>(
    verb: &'static str,
    args: &Args,
    io: &mut IoStreams,
    parse: fn(&Args) -> Result<O>,
    output: fn(&O) -> OutputFormat,
    exec: impl FnOnce(O, &mut dyn Write) -> Result<R>,
) -> Result<Status> {
    let opts = match parse(args) {
        Ok(opts) => opts,
        Err(e) => {
            // Invalid usage whatever the kind: nothing was done.
            let code = validation_code(verb, &e);
            let message = e.to_string();
            writeln!(io.stderr, "{}", error_line(&code, &message))?;
            return Ok(Status::coded(EXIT_USAGE, &code, message));
        }
    };
    let format = output(&opts);
    let report = match exec(opts, &mut *io.stderr) {
        Ok(report) => report,
        Err(e) => {
            let code = error_code(verb, runtime_kind(&e, "internal_error"));
            return failed(&mut *io.stderr, &code, &e.to_string());
        }
    };
    let rendered = match format {
        OutputFormat::Json => report.json(),
        OutputFormat::Text => report.text(),
    };
    writeln!(io.stdout, "{}", rendered)?;
    if report.is_ok() {
        return Ok(Status::ok());
    }
    match report.error_pair() {
        Some((code, message)) => failed(&mut *io.stderr, code, message),
        None => {
            let code = error_code(verb, "internal_error");
            failed(&mut *io.stderr, &code, &format!("archive {verb} failed"))
        }
    }
}

/// Exit status: the operation failed.
pub const EXIT_FAILED: i32 = status::exit::FAILED;
/// Exit status: invalid usage or arguments; nothing was done.
pub const EXIT_USAGE: i32 = status::exit::USAGE;
/// Exit status: `timeout_ms` passed before the operation finished.
pub const EXIT_TIMEOUT: i32 = status::exit::TIMEOUT;

/// The exit status for a failure reported with error code `code`: an
/// argument or archive type the verb cannot work with is invalid usage
/// (these are all detected before anything is changed).
pub fn exit_for(code: &str) -> i32 {
    if code.ends_with("_timeout") {
        EXIT_TIMEOUT
    } else if code.contains("_invalid_")
        || code.ends_with("_7z_unsupported")
        || code.ends_with("_unsupported_for_raw")
    {
        EXIT_USAGE
    } else {
        EXIT_FAILED
    }
}

impl Handle for ArchiveHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["create", "extract", "list", "test", "info", "add", "remove"]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&ARCHIVE_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        if should_show_help(verb, args) {
            // `archive://.list(help=1)` shows the help of `list`.
            let help_verb = args
                .get("verb")
                .map(String::as_str)
                .or_else(|| (!crate::core::help::HELP_ALIASES.contains(&verb)).then_some(verb));
            write!(
                io.stdout,
                "{}",
                crate::core::help::render_legacy("archive", &ARCHIVE_HELP, self.verbs(), help_verb)
            )?;
            return Ok(Status::ok());
        }

        match verb {
            "create" => run_verb(
                "create",
                args,
                io,
                ArchiveCreateOptions::from_args,
                |o| o.output_format.clone(),
                |o, progress| create_archive_with_progress(o, progress),
            ),
            "extract" => run_verb(
                "extract",
                args,
                io,
                ArchiveExtractOptions::from_args,
                |o| o.format_output.clone(),
                |o, _| extract_archive(o),
            ),
            "list" => run_verb(
                "list",
                args,
                io,
                ArchiveListOptions::from_args,
                |o| o.format_output.clone(),
                |o, _| list_archive(o),
            ),
            "test" => run_verb(
                "test",
                args,
                io,
                ArchiveTestOptions::from_args,
                |o| o.format_output.clone(),
                |o, _| test_archive(o),
            ),
            "info" => run_verb(
                "info",
                args,
                io,
                ArchiveInfoOptions::from_args,
                |o| o.format_output.clone(),
                |o, _| info_archive(o),
            ),
            "add" => run_verb(
                "add",
                args,
                io,
                ArchiveAddOptions::from_args,
                |o| o.format_output.clone(),
                |o, _| add_archive(o),
            ),
            "remove" => run_verb(
                "remove",
                args,
                io,
                ArchiveRemoveOptions::from_args,
                |o| o.format_output.clone(),
                |o, _| remove_archive(o),
            ),
            _ => Ok(Status::coded(
                crate::core::status::exit::USAGE,
                "archive.unknown_verb",
                format!(
                    "unknown verb for archive://: {verb} (verbs: {}); nothing was done",
                    self.verbs().join(", ")
                ),
            )),
        }
    }
}

/// Creates an archive without progress output.
pub fn create_archive(opts: ArchiveCreateOptions) -> Result<ArchiveCreateResponse> {
    create_archive_with_progress(opts, &mut std::io::sink())
}

/// Creates an archive; with `progress=true` one line per archived entry is
/// written to `progress`.
pub fn create_archive_with_progress(
    opts: ArchiveCreateOptions,
    progress: &mut dyn Write,
) -> Result<ArchiveCreateResponse> {
    let mut response = ArchiveCreateResponse::new(&opts);
    let start_time = Instant::now();
    if let Err(e) = create_inner(&opts, progress, &mut response, start_time) {
        response.ok = false;
        response.error = Some((error_code("create", create_kind(&e)), e.to_string()));
    }
    Ok(response)
}

/// Error kind for a failed `create`.
fn create_kind(e: &anyhow::Error) -> &'static str {
    if let Some(kind) = kind_of(e) {
        return kind;
    }
    match io_kind(e) {
        Some(std::io::ErrorKind::StorageFull) => "disk_full",
        Some(std::io::ErrorKind::PermissionDenied) => "permission_denied",
        _ => "compression_failed",
    }
}

fn create_inner(
    opts: &ArchiveCreateOptions,
    progress: &mut dyn Write,
    response: &mut ArchiveCreateResponse,
    start_time: Instant,
) -> Result<()> {
    let output_path = Path::new(&opts.output);
    match fs::symlink_metadata(output_path) {
        Ok(m) if m.is_dir() => {
            return Err(fail(
                "invalid_output",
                format!("Output path is a directory: {}", opts.output),
            ));
        }
        Ok(_) if !opts.overwrite => {
            return Err(fail(
                "output_exists",
                "Output file exists and overwrite=false",
            ));
        }
        _ => {}
    }

    let files = collect_source_files(opts)?;

    if files.len() as u64 > opts.max_files {
        return Err(fail(
            "max_files_exceeded",
            format!(
                "Number of files ({}) exceeds limit ({})",
                files.len(),
                opts.max_files
            ),
        ));
    }

    let total_size: u64 = files
        .iter()
        .filter(|f| f.file_type == "file")
        .map(|f| f.size_bytes)
        .fold(0u64, u64::saturating_add);
    let max_bytes = opts.max_size_mb.saturating_mul(1024 * 1024);
    if total_size > max_bytes {
        return Err(fail(
            "max_size_exceeded",
            format!(
                "Total size ({} bytes) exceeds limit ({} MB)",
                total_size, opts.max_size_mb
            ),
        ));
    }

    if opts.format == ArchiveFormat::Gzip && (files.len() != 1 || files[0].file_type != "file") {
        return Err(fail(
            "invalid_sources",
            format!(
                "format=gzip compresses exactly one regular file; the sources name {} entries",
                files.len()
            ),
        ));
    }

    let mut warnings = Vec::new();
    let compressed_size = write_new_archive(opts, &files, progress, &mut warnings)?;

    let mut files_by_type = HashMap::new();
    let mut largest_files: Vec<FileEntry> = files
        .iter()
        .filter(|f| f.file_type == "file")
        .cloned()
        .collect();
    largest_files.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
    largest_files.truncate(5);

    let mut dir_count = 0u64;
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
    }

    let compression_ratio = if total_size > 0 {
        1.0 - (compressed_size as f64 / total_size as f64)
    } else {
        0.0
    };

    response.result = ArchiveResult {
        output_path: opts.output.clone(),
        format_detected: opts.format.as_str().to_string(),
        files_archived: files.len() as u64 - dir_count,
        directories_archived: dir_count,
        total_size_bytes: total_size,
        compressed_size_bytes: compressed_size,
        compression_ratio,
        duration_ms: start_time.elapsed().as_millis() as u64,
    };
    response.files = files.iter().take(100).cloned().collect();
    response.statistics = ArchiveStatistics {
        files_by_type,
        largest_files,
    };
    response.warnings = warnings;
    Ok(())
}

/// Lexically normalizes an archive member name: no leading `/`, no `.`
/// components. `None` if a `..` component remains.
fn member_name(path: &Path) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    for c in path.components() {
        match c {
            Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            Component::ParentDir => return None,
        }
    }
    Some(parts.join("/"))
}

fn source_error(e: impl Into<anyhow::Error>, what: &str) -> anyhow::Error {
    let e = e.into();
    if io_kind(&e) == Some(std::io::ErrorKind::PermissionDenied) {
        fail("source_permission_denied", format!("{what}: {e}"))
    } else {
        fail("source_not_found", format!("{what}: {e}"))
    }
}

pub fn collect_source_files(opts: &ArchiveCreateOptions) -> Result<Vec<FileEntry>> {
    let mut files = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let base_path = opts
        .base_dir
        .as_ref()
        .map(|p| Path::new(p))
        .unwrap_or_else(|| Path::new("."));

    let include_set = build_glob_set(&opts.include_patterns, "include")
        .map_err(|e| fail("invalid_pattern", e.to_string()))?;
    let exclude_set = build_glob_set(&opts.exclude_patterns, "exclude")
        .map_err(|e| fail("invalid_pattern", e.to_string()))?;

    // An existing output (overwrite=true) is never archived into itself.
    let output_id = {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(&opts.output).ok().map(|m| (m.dev(), m.ino()))
    };

    let mut push = |entry: Option<FileEntry>, path: &Path| {
        use std::os::unix::fs::MetadataExt;
        if let Some(entry) = entry {
            let is_output = output_id.is_some()
                && fs::symlink_metadata(path)
                    .map(|m| Some((m.dev(), m.ino())) == output_id)
                    .unwrap_or(false);
            if !is_output && !entry.path.is_empty() && seen.insert(entry.path.clone()) {
                files.push(entry);
            }
        }
    };

    for source in &opts.sources {
        opts.deadline.check()?;
        let source_path = if Path::new(source).is_absolute() {
            PathBuf::from(source)
        } else {
            base_path.join(source)
        };

        if source.contains('*') || source.contains('?') || source.contains('[') {
            let glob = shell_glob(source).map_err(|e| {
                fail(
                    "invalid_sources",
                    format!("Invalid source pattern {source:?}: {e}"),
                )
            })?;
            let glob_set = GlobSetBuilder::new()
                .add(glob)
                .build()
                .map_err(|e| fail("invalid_sources", e.to_string()))?;
            for entry in WalkDir::new(base_path).follow_links(opts.follow_symlinks) {
                opts.deadline.check()?;
                let entry = entry.map_err(|e| source_error(e, "cannot read source"))?;
                let relative_path = entry.path().strip_prefix(base_path).unwrap_or(entry.path());
                if glob_set.is_match(relative_path) {
                    let e = process_path_entry(
                        entry.path(),
                        base_path,
                        opts,
                        &include_set,
                        &exclude_set,
                    )?;
                    push(e, entry.path());
                }
            }
            continue;
        }

        let meta = if opts.follow_symlinks {
            fs::metadata(&source_path)
        } else {
            fs::symlink_metadata(&source_path)
        };
        let meta = meta.map_err(|e| source_error(e, &format!("Source not found: {source}")))?;
        if meta.is_dir() {
            for entry in WalkDir::new(&source_path).follow_links(opts.follow_symlinks) {
                opts.deadline.check()?;
                let entry = entry.map_err(|e| source_error(e, "cannot read source"))?;
                let e =
                    process_path_entry(entry.path(), base_path, opts, &include_set, &exclude_set)?;
                push(e, entry.path());
            }
        } else {
            let e = process_path_entry(&source_path, base_path, opts, &include_set, &exclude_set)?;
            push(e, &source_path);
        }
    }

    Ok(files)
}

pub fn process_path_entry(
    path: &Path,
    base_path: &Path,
    opts: &ArchiveCreateOptions,
    include_set: &Option<globset::GlobSet>,
    exclude_set: &Option<globset::GlobSet>,
) -> Result<Option<FileEntry>> {
    let relative_path = path.strip_prefix(base_path).unwrap_or(path);
    let Some(path_str) = member_name(relative_path) else {
        return Err(fail(
            "invalid_sources",
            format!(
                "source {} is outside base_dir; pass base_dir= or an absolute path",
                path.display()
            ),
        ));
    };

    // A hidden file, or anything under a hidden directory.
    if !opts.include_hidden && path_str.split('/').any(|c| c.starts_with('.')) {
        return Ok(None);
    }
    if let Some(include_set) = include_set {
        if !include_set.is_match(&path_str) {
            return Ok(None);
        }
    }
    if let Some(exclude_set) = exclude_set {
        if exclude_set.is_match(&path_str) {
            return Ok(None);
        }
    }

    let metadata = if opts.follow_symlinks {
        path.metadata()
    } else {
        path.symlink_metadata()
    }
    .map_err(|e| source_error(e, &format!("cannot read {}", path.display())))?;
    let modified_unix_ms = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    let ft = metadata.file_type();
    let file_type = if ft.is_file() {
        "file"
    } else if ft.is_dir() {
        "directory"
    } else if ft.is_symlink() {
        "symlink"
    } else {
        "other"
    }
    .to_string();

    Ok(Some(FileEntry {
        path: path_str,
        size_bytes: if ft.is_file() { metadata.len() } else { 0 },
        modified_unix_ms,
        file_type,
        source: path.to_path_buf(),
    }))
}

/// A temporary file next to `target` that no other user can predict or
/// redirect, created with the default (umask) permissions.
fn new_temp_beside(target: &Path) -> Result<(PathBuf, File)> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.{}", temp_archive_name("resh-tmp-")));
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o666)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .with_context(|| format!("cannot create {}", tmp.display()))?;
    Ok((tmp, file))
}

/// Moves a finished temporary file to `target`. Without `overwrite` the
/// move fails if `target` exists by then.
fn publish_temp(tmp: &Path, target: &Path, overwrite: bool) -> Result<()> {
    if overwrite {
        fs::rename(tmp, target).with_context(|| format!("cannot replace {}", target.display()))?;
    } else {
        fs::hard_link(tmp, target).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                fail("output_exists", "Output file exists and overwrite=false")
            } else {
                anyhow::Error::new(e).context(format!("cannot create {}", target.display()))
            }
        })?;
        let _ = fs::remove_file(tmp);
    }
    Ok(())
}

/// Removes a temporary file when dropped unless it was kept.
struct TempGuard(Option<PathBuf>);

impl TempGuard {
    fn keep(mut self) {
        self.0 = None;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = fs::remove_file(p);
        }
    }
}

/// Writes the archive to a temporary file, then moves it into place, and
/// returns its size. On failure no output is left behind.
fn write_new_archive(
    opts: &ArchiveCreateOptions,
    files: &[FileEntry],
    progress: &mut dyn Write,
    warnings: &mut Vec<String>,
) -> Result<u64> {
    let output_path = Path::new(&opts.output);
    let (tmp, file) = new_temp_beside(output_path)?;
    let guard = TempGuard(Some(tmp.clone()));
    let level = opts
        .compression_level
        .unwrap_or(opts.format.default_compression_level());
    let w = BufWriter::new(file);

    let file = match opts.format {
        ArchiveFormat::Tar => {
            let mut b = tar::Builder::new(w);
            fill_new_tar(&mut b, opts, files, progress, warnings)?;
            unbuffer(b.into_inner()?)?
        }
        ArchiveFormat::TarGz => {
            let mut b = tar::Builder::new(GzEncoder::new(w, Compression::new(level)));
            fill_new_tar(&mut b, opts, files, progress, warnings)?;
            unbuffer(b.into_inner()?.finish()?)?
        }
        ArchiveFormat::TarXz => {
            let mut b = tar::Builder::new(XzEncoder::new(w, level));
            fill_new_tar(&mut b, opts, files, progress, warnings)?;
            unbuffer(b.into_inner()?.finish()?)?
        }
        ArchiveFormat::TarZstd => {
            let mut b = tar::Builder::new(ZstdEncoder::new(w, level as i32)?);
            fill_new_tar(&mut b, opts, files, progress, warnings)?;
            unbuffer(b.into_inner()?.finish()?)?
        }
        ArchiveFormat::Zip => {
            let file = unbuffer(w)?;
            write_new_zip(file, opts, files, progress, warnings)?
        }
        ArchiveFormat::Gzip => {
            let entry = &files[0];
            let full_path = entry.source.clone();
            let mut builder = flate2::GzBuilder::new();
            let meta = fs::metadata(&full_path)
                .map_err(|e| source_error(e, &format!("cannot read {}", full_path.display())))?;
            if opts.preserve_timestamps {
                let secs = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                builder = builder.mtime(u32::try_from(secs).unwrap_or(0));
            }
            let mut input = File::open(&full_path)
                .map_err(|e| source_error(e, &format!("cannot read {}", full_path.display())))?;
            let mut encoder = builder.write(w, Compression::new(level));
            copy(
                &mut DeadlineReader::new(&mut input, opts.deadline),
                &mut encoder,
            )?;
            note_progress(opts, progress, 1, 1, &entry.path);
            let file = unbuffer(encoder.finish()?)?;
            if opts.preserve_permissions {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(fs::Permissions::from_mode(
                    meta.permissions().mode() & 0o777,
                ))?;
            }
            file
        }
        _ => bail!(
            "Archive format {} not yet implemented",
            opts.format.as_str()
        ),
    };
    file.sync_all()?;
    drop(file);
    opts.deadline.check()?;
    publish_temp(&tmp, output_path, opts.overwrite)?;
    guard.keep();
    Ok(fs::metadata(output_path)?.len())
}

fn unbuffer(w: BufWriter<File>) -> Result<File> {
    w.into_inner()
        .map_err(|e| anyhow::Error::new(e.into_error()))
}

fn note_progress(
    opts: &ArchiveCreateOptions,
    out: &mut dyn Write,
    n: usize,
    total: usize,
    path: &str,
) {
    if opts.progress {
        let _ = writeln!(out, "archive create: [{n}/{total}] {path}");
    }
}

/// Mode stored when permissions are not preserved.
fn default_mode(file_type: &str) -> u32 {
    match file_type {
        "directory" => 0o755,
        "symlink" => 0o777,
        _ => 0o644,
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn fill_new_tar<W: Write>(
    b: &mut tar::Builder<W>,
    opts: &ArchiveCreateOptions,
    files: &[FileEntry],
    progress: &mut dyn Write,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let total = files.len();
    for (i, entry) in files.iter().enumerate() {
        opts.deadline.check()?;
        let full_path = entry.source.clone();
        if entry.file_type == "other" {
            warnings.push(format!("Skipped special file '{}'", entry.path));
            continue;
        }
        let meta = if entry.file_type == "symlink" {
            fs::symlink_metadata(&full_path)
        } else {
            fs::metadata(&full_path)
        }
        .map_err(|e| source_error(e, &format!("cannot read {}", full_path.display())))?;
        let mut header = tar::Header::new_gnu();
        header.set_metadata_in_mode(&meta, tar::HeaderMode::Complete);
        if !opts.preserve_permissions {
            header.set_mode(default_mode(&entry.file_type));
        }
        if !opts.preserve_timestamps {
            header.set_mtime(now_unix());
        }
        match entry.file_type.as_str() {
            "file" => {
                let f = File::open(&full_path).map_err(|e| {
                    source_error(e, &format!("cannot read {}", full_path.display()))
                })?;
                header.set_size(meta.len());
                b.append_data(
                    &mut header,
                    &entry.path,
                    DeadlineReader::new(f, opts.deadline),
                )?;
            }
            "directory" => {
                header.set_size(0);
                b.append_data(&mut header, &entry.path, std::io::empty())?;
            }
            "symlink" => {
                let target = fs::read_link(&full_path).map_err(|e| {
                    source_error(e, &format!("cannot read {}", full_path.display()))
                })?;
                header.set_size(0);
                b.append_link(&mut header, &entry.path, &target)?;
            }
            _ => {}
        }
        note_progress(opts, progress, i + 1, total, &entry.path);
    }
    b.finish()?;
    Ok(())
}

/// The zip timestamp for `t` (local time, clamped to the range zip can
/// store).
fn zip_time(t: SystemTime) -> zip::DateTime {
    use chrono::{Datelike, Timelike};
    let local: DateTime<chrono::Local> = t.into();
    zip::DateTime::from_date_and_time(
        local.year().clamp(1980, 2107) as u16,
        local.month() as u8,
        local.day() as u8,
        local.hour() as u8,
        local.minute() as u8,
        local.second() as u8,
    )
    .unwrap_or_default()
}

fn write_new_zip(
    file: File,
    opts: &ArchiveCreateOptions,
    files: &[FileEntry],
    progress: &mut dyn Write,
    warnings: &mut Vec<String>,
) -> Result<File> {
    use std::os::unix::fs::PermissionsExt;
    let mut archive = ZipWriter::new(file);
    let level = opts
        .compression_level
        .unwrap_or(opts.format.default_compression_level());
    let total = files.len();
    for (i, entry) in files.iter().enumerate() {
        opts.deadline.check()?;
        let full_path = entry.source.clone();
        if entry.file_type == "other" {
            warnings.push(format!("Skipped special file '{}'", entry.path));
            continue;
        }
        let meta = if entry.file_type == "symlink" {
            fs::symlink_metadata(&full_path)
        } else {
            fs::metadata(&full_path)
        }
        .map_err(|e| source_error(e, &format!("cannot read {}", full_path.display())))?;
        let mode = if opts.preserve_permissions {
            meta.permissions().mode() & 0o7777
        } else {
            default_mode(&entry.file_type)
        };
        let mtime = if opts.preserve_timestamps {
            meta.modified().unwrap_or_else(|_| SystemTime::now())
        } else {
            SystemTime::now()
        };
        let options = FileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .compression_level(Some(level as i32))
            .unix_permissions(mode)
            .last_modified_time(zip_time(mtime))
            .large_file(meta.len() >= 0xFFFF_FFFF);
        match entry.file_type.as_str() {
            "file" => {
                archive.start_file(&entry.path, options)?;
                let f = File::open(&full_path).map_err(|e| {
                    source_error(e, &format!("cannot read {}", full_path.display()))
                })?;
                copy(&mut DeadlineReader::new(f, opts.deadline), &mut archive)?;
            }
            "directory" => archive.add_directory(&entry.path, options)?,
            "symlink" => {
                let target = fs::read_link(&full_path).map_err(|e| {
                    source_error(e, &format!("cannot read {}", full_path.display()))
                })?;
                archive.add_symlink(&entry.path, target.to_string_lossy(), options)?;
            }
            _ => {}
        }
        note_progress(opts, progress, i + 1, total, &entry.path);
    }
    Ok(archive.finish()?)
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

/// Whether the archive exists. A missing archive fails with kind
/// `missing_archive` unless `fail_on_missing` is false; a directory fails
/// with `invalid_archive_path`.
fn archive_present(path: &str, fail_on_missing: bool) -> Result<bool> {
    match fs::metadata(path) {
        Ok(m) if m.is_dir() => Err(fail(
            "invalid_archive_path",
            format!("Archive '{}' is a directory.", path),
        )),
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if fail_on_missing {
                Err(fail(
                    "missing_archive",
                    format!("Archive '{}' does not exist.", path),
                ))
            } else {
                Ok(false)
            }
        }
        Err(e) => Err(fail(
            "io_error",
            format!("Cannot access archive '{}': {}", path, e),
        )),
    }
}

fn missing_warning(path: &str) -> String {
    format!(
        "Archive '{}' does not exist (fail_on_missing_archive=false); nothing to do.",
        path
    )
}

/// Opens the archive for reading; the reader fails once `deadline` passes.
fn open_archive(path: &str, deadline: Deadline) -> Result<DeadlineReader<File>> {
    let file = File::open(path).map_err(|e| {
        let kind = match e.kind() {
            std::io::ErrorKind::NotFound => "missing_archive",
            _ => "io_error",
        };
        fail(kind, format!("Cannot open archive '{}': {}", path, e))
    })?;
    Ok(DeadlineReader::new(file, deadline))
}

/// `reader` decompressed according to `compression`.
fn decompress<R: Read + 'static>(
    reader: R,
    compression: &CompressionKind,
) -> Result<Box<dyn Read>> {
    Ok(match compression {
        CompressionKind::None | CompressionKind::Auto => Box::new(reader),
        CompressionKind::Gzip => Box::new(GzDecoder::new(reader)),
        CompressionKind::Xz => Box::new(XzDecoder::new(reader)),
        CompressionKind::Zstd => Box::new(ZstdDecoder::new(reader)?),
    })
}

/// Format and compression with `Auto` resolved from the archive name
/// (options built by `from_args` are already resolved).
fn effective_format(
    format: &ArchiveFormat,
    compression: &CompressionKind,
    path: &str,
) -> Result<(ArchiveFormat, CompressionKind)> {
    resolve_format_and_compression(format, compression, path)
        .map_err(|e| fail("invalid_format_infer", e.to_string()))
}

fn is_zip_symlink(mode: Option<u32>) -> bool {
    mode.is_some_and(|m| m & 0o170000 == 0o120000)
}

/// Counts the bytes of a raw compressed stream, failing past `max_bytes`.
fn raw_stream_size(
    path: &str,
    compression: &CompressionKind,
    deadline: Deadline,
    max_bytes: Option<u64>,
) -> Result<u64> {
    let mut reader = decompress(open_archive(path, deadline)?, compression)?;
    let budget = max_bytes.map_or(u64::MAX, |m| m.saturating_add(1));
    let n = copy(&mut (&mut reader).take(budget), &mut std::io::sink())?;
    if let Some(max) = max_bytes {
        if n > max {
            return Err(fail(
                "max_size_exceeded",
                format!("Maximum total bytes limit exceeded: {}", max),
            ));
        }
    }
    Ok(n)
}

/// The name of the single member of a raw compressed stream: the file name
/// without its compression extension.
fn raw_member_name(archive_path: &str) -> String {
    let name = Path::new(archive_path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let lower = name.to_ascii_lowercase();
    for ext in [".gz", ".xz", ".zst", ".zstd"] {
        if lower.ends_with(ext) && name.len() > ext.len() {
            return name[..name.len() - ext.len()].to_string();
        }
    }
    if name.is_empty() {
        "data".to_string()
    } else {
        name
    }
}

// List raw compressed file (single virtual entry)
fn list_raw_compressed(
    archive_path: &str,
    compression: &CompressionKind,
    opts: &ArchiveListOptions,
) -> Result<(Vec<ArchiveListEntry>, u64, u64)> {
    let file_metadata = fs::metadata(archive_path)?;
    let size = raw_stream_size(
        archive_path,
        compression,
        opts.deadline,
        opts.max_total_bytes,
    )?;
    let mtime_unix = file_metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64);
    let entry = ArchiveListEntry {
        path: raw_member_name(archive_path),
        is_dir: false,
        is_symlink: false,
        size,
        compressed_size: if opts.include_compressed_size {
            Some(file_metadata.len())
        } else {
            None
        },
        mode: None,
        uid: None,
        gid: None,
        uname: None,
        gname: None,
        mtime_unix: if opts.include_metadata {
            mtime_unix
        } else {
            None
        },
    };
    Ok((vec![entry], 1, size))
}

fn matches_filters(
    path: &str,
    include_globset: &Option<globset::GlobSet>,
    exclude_globset: &Option<globset::GlobSet>,
) -> bool {
    include_globset.as_ref().is_none_or(|g| g.is_match(path))
        && !exclude_globset.as_ref().is_some_and(|g| g.is_match(path))
}

// List tar archive with optional compression
fn list_tar_archive(
    archive_path: &str,
    compression: &CompressionKind,
    opts: &ArchiveListOptions,
    include_globset: &Option<globset::GlobSet>,
    exclude_globset: &Option<globset::GlobSet>,
) -> Result<(Vec<ArchiveListEntry>, u64, u64)> {
    let reader = decompress(open_archive(archive_path, opts.deadline)?, compression)?;
    let mut archive = limited_archive(reader);
    let mut manifest = Vec::new();
    let mut entries_total = 0u64;
    let mut bytes_total = 0u64;

    for entry_result in archive.entries()? {
        let entry = entry_result?;
        opts.deadline.check()?;
        entries_total += 1;
        if entries_total > opts.max_entries {
            return Err(fail(
                "max_entries_exceeded",
                format!("Maximum entries limit exceeded: {}", opts.max_entries),
            ));
        }
        let header = entry.header();
        let path_cow = entry.path()?;
        let path_str = path_cow.to_string_lossy();
        let path = path_str.strip_prefix("./").unwrap_or(&path_str).to_string();
        if !matches_filters(&path, include_globset, exclude_globset) {
            continue;
        }

        let size = entry.size();
        bytes_total = bytes_total.saturating_add(size);
        if let Some(max_bytes) = opts.max_total_bytes {
            if bytes_total > max_bytes {
                return Err(fail(
                    "max_size_exceeded",
                    format!("Maximum total bytes limit exceeded: {}", max_bytes),
                ));
            }
        }

        let meta = opts.include_metadata;
        let entry_type = header.entry_type();
        manifest.push(ArchiveListEntry {
            path,
            is_dir: entry_type.is_dir(),
            is_symlink: entry_type.is_symlink() || entry_type.is_hard_link(),
            size,
            compressed_size: None, // Tar doesn't track per-entry compressed size
            mode: meta
                .then(|| header.mode().ok().map(|m| format!("{:06o}", m)))
                .flatten(),
            uid: meta.then(|| header.uid().ok().map(|u| u as u32)).flatten(),
            gid: meta.then(|| header.gid().ok().map(|g| g as u32)).flatten(),
            uname: meta
                .then(|| header.username().ok().flatten().map(str::to_string))
                .flatten(),
            gname: meta
                .then(|| header.groupname().ok().flatten().map(str::to_string))
                .flatten(),
            mtime_unix: meta
                .then(|| header.mtime().ok().map(|t| t as i64))
                .flatten(),
        });
    }

    Ok((manifest, entries_total, bytes_total))
}

fn zip_mtime(t: zip::DateTime) -> Option<i64> {
    t.to_time().ok().map(|tm| tm.unix_timestamp())
}

// List zip archive
fn list_zip_archive(
    archive_path: &str,
    opts: &ArchiveListOptions,
    include_globset: &Option<globset::GlobSet>,
    exclude_globset: &Option<globset::GlobSet>,
) -> Result<(Vec<ArchiveListEntry>, u64, u64)> {
    let mut zip = zip::ZipArchive::new(open_archive(archive_path, opts.deadline)?)?;
    let mut manifest = Vec::new();
    let entries_total = zip.len() as u64;
    let mut bytes_total = 0u64;
    if entries_total > opts.max_entries {
        return Err(fail(
            "max_entries_exceeded",
            format!("Maximum entries limit exceeded: {}", opts.max_entries),
        ));
    }

    for i in 0..zip.len() {
        opts.deadline.check()?;
        let file = zip.by_index_raw(i)?;
        let path = file.name().to_string();
        if !matches_filters(&path, include_globset, exclude_globset) {
            continue;
        }
        let size = file.size();
        bytes_total = bytes_total.saturating_add(size);
        if let Some(max_bytes) = opts.max_total_bytes {
            if bytes_total > max_bytes {
                return Err(fail(
                    "max_size_exceeded",
                    format!("Maximum total bytes limit exceeded: {}", max_bytes),
                ));
            }
        }
        let meta = opts.include_metadata;
        manifest.push(ArchiveListEntry {
            is_dir: file.is_dir(),
            is_symlink: is_zip_symlink(file.unix_mode()),
            size,
            compressed_size: opts.include_compressed_size.then(|| file.compressed_size()),
            mode: meta
                .then(|| file.unix_mode().map(|m| format!("{:06o}", m)))
                .flatten(),
            uid: None, // ZIP doesn't store Unix UID/GID
            gid: None,
            uname: None,
            gname: None,
            mtime_unix: meta.then(|| zip_mtime(file.last_modified())).flatten(),
            path,
        });
    }

    Ok((manifest, entries_total, bytes_total))
}

// Test functionality
pub fn test_archive(opts: ArchiveTestOptions) -> Result<ArchiveTestResponse> {
    let mut response = ArchiveTestResponse::new(&opts);
    if let Err(e) = test_inner(&opts, &mut response) {
        response.ok = false;
        response.error = Some((
            error_code("test", runtime_kind(&e, "archive_read_error")),
            e.to_string(),
        ));
    }
    Ok(response)
}

fn test_inner(opts: &ArchiveTestOptions, response: &mut ArchiveTestResponse) -> Result<()> {
    let (final_format, final_compression) =
        effective_format(&opts.format, &opts.compression, &opts.archive)?;
    if !archive_present(&opts.archive, opts.fail_on_missing_archive)? {
        response.warnings.push(missing_warning(&opts.archive));
        response.summary = Some(ArchiveTestSummary {
            archive: opts.archive.clone(),
            format: final_format.as_str().to_string(),
            compression: final_compression.as_str().to_string(),
            entries_tested: 0,
            entries_failed: 0,
            bytes_tested: 0,
            valid: false,
            stopped_early: false,
        });
        if opts.report_entries {
            response.entries = Some(Vec::new());
        }
        return Ok(());
    }

    let (entries, summary) = match final_format {
        ArchiveFormat::Raw => test_raw_compressed(&opts.archive, &final_compression, opts)?,
        ArchiveFormat::Tar
        | ArchiveFormat::TarGz
        | ArchiveFormat::TarXz
        | ArchiveFormat::TarZstd => test_tar_archive(&opts.archive, &final_compression, opts)?,
        ArchiveFormat::Zip => test_zip_archive(&opts.archive, opts)?,
        ArchiveFormat::SevenZ => {
            return Err(fail(
                "7z_unsupported",
                "7z archive testing is not supported in this build.",
            ));
        }
        ref other => {
            return Err(fail(
                "invalid_format",
                format!("Unsupported format for testing: {}", other.as_str()),
            ));
        }
    };

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
            "One or more entries failed integrity checks.".to_string(),
        ));
    }
    Ok(())
}

// Internal struct for test summaries
struct TestSummary {
    entries_tested: u64,
    entries_failed: u64,
    bytes_tested: u64,
    stopped_early: bool,
}

fn entry_error(entry: &mut ArchiveTestEntryResult, code: &str, message: String) {
    entry.status = "error".to_string();
    entry.error = Some((code.to_string(), message));
}

fn total_limit_error(max: u64) -> anyhow::Error {
    fail(
        "max_size_exceeded",
        format!("Maximum total bytes limit exceeded: {}", max),
    )
}

// Test raw compressed file (single stream)
fn test_raw_compressed(
    archive_path: &str,
    compression: &CompressionKind,
    opts: &ArchiveTestOptions,
) -> Result<(Vec<ArchiveTestEntryResult>, TestSummary)> {
    let mut reader = decompress(open_archive(archive_path, opts.deadline)?, compression)?;
    let mut entry_result = ArchiveTestEntryResult {
        path: raw_member_name(archive_path),
        is_dir: false,
        is_symlink: false,
        size: 0,
        status: "ok".to_string(),
        error: None,
    };

    let mut bytes_tested = 0u64;
    if opts.verify_data {
        let mut buffer = [0u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    bytes_tested += n as u64;
                    if let Some(max_total_bytes) = opts.max_total_bytes {
                        if bytes_tested > max_total_bytes {
                            return Err(total_limit_error(max_total_bytes));
                        }
                    }
                    if let Some(max_file_bytes) = opts.max_file_bytes {
                        if bytes_tested > max_file_bytes {
                            entry_error(
                                &mut entry_result,
                                ARCHIVE_TEST_MAX_FILE_SIZE_EXCEEDED,
                                format!("Entry size exceeds max_file_bytes {}", max_file_bytes),
                            );
                            break;
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return Err(e.into()),
                Err(e) => {
                    entry_error(
                        &mut entry_result,
                        ARCHIVE_TEST_ENTRY_COMPRESSION_ERROR,
                        e.to_string(),
                    );
                    break;
                }
            }
        }
        entry_result.size = bytes_tested;
    }

    let entries_failed = u64::from(entry_result.status == "error");
    Ok((
        vec![entry_result],
        TestSummary {
            entries_tested: 1,
            entries_failed,
            bytes_tested,
            stopped_early: false,
        },
    ))
}

// Test tar archive with optional compression
fn test_tar_archive(
    archive_path: &str,
    compression: &CompressionKind,
    opts: &ArchiveTestOptions,
) -> Result<(Vec<ArchiveTestEntryResult>, TestSummary)> {
    let reader = decompress(open_archive(archive_path, opts.deadline)?, compression)?;
    let mut tar = limited_archive(reader);
    let mut entries = Vec::new();
    let mut bytes_tested = 0u64;
    let mut entries_tested = 0u64;
    let mut entries_failed = 0u64;
    let mut stopped_early = false;

    let tar_entries = tar
        .entries()
        .map_err(|e| anyhow::anyhow!("Failed to read tar entries: {}", e))?;

    for entry in tar_entries {
        opts.deadline.check()?;
        if entries_tested >= opts.max_entries {
            return Err(fail(
                "max_entries_exceeded",
                format!("Maximum entries limit exceeded: {}", opts.max_entries),
            ));
        }

        let entry = match entry {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return Err(e.into()),
            Err(e) => {
                entries.push(ArchiveTestEntryResult {
                    path: format!("entry_{}", entries_tested),
                    is_dir: false,
                    is_symlink: false,
                    size: 0,
                    status: "error".to_string(),
                    error: Some((ARCHIVE_TEST_ENTRY_HEADER_ERROR.to_string(), e.to_string())),
                });
                entries_failed += 1;
                entries_tested += 1;
                // The stream position is unknown after a bad header.
                stopped_early = true;
                break;
            }
        };

        let header = entry.header();
        let path = entry
            .path()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| format!("entry_{}", entries_tested));
        let size = entry.size();
        let entry_type = header.entry_type();
        let is_dir = entry_type.is_dir();

        let mut entry_result = ArchiveTestEntryResult {
            path,
            is_dir,
            is_symlink: entry_type.is_symlink() || entry_type.is_hard_link(),
            size,
            status: "ok".to_string(),
            error: None,
        };

        if opts.verify_data && !is_dir && size > 0 {
            if let Some(max_total_bytes) = opts.max_total_bytes {
                if bytes_tested.saturating_add(size) > max_total_bytes {
                    return Err(total_limit_error(max_total_bytes));
                }
            }
            if let Some(max_file_bytes) = opts.max_file_bytes.filter(|m| size > *m) {
                entry_error(
                    &mut entry_result,
                    ARCHIVE_TEST_MAX_FILE_SIZE_EXCEEDED,
                    format!(
                        "Entry size {} exceeds max_file_bytes {}",
                        size, max_file_bytes
                    ),
                );
            } else {
                match copy(&mut entry.take(size), &mut std::io::sink()) {
                    Ok(bytes_read) => {
                        bytes_tested += bytes_read;
                        if bytes_read != size {
                            entry_error(
                                &mut entry_result,
                                ARCHIVE_TEST_ENTRY_SIZE_MISMATCH,
                                format!("Expected {} bytes, read {}", size, bytes_read),
                            );
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                        return Err(e.into());
                    }
                    Err(e) => {
                        entry_error(
                            &mut entry_result,
                            ARCHIVE_TEST_ENTRY_IO_ERROR,
                            e.to_string(),
                        );
                    }
                }
            }
        }

        let failed = entry_result.status == "error";
        entries.push(entry_result);
        entries_tested += 1;
        if failed {
            entries_failed += 1;
            if opts.stop_on_first_error {
                stopped_early = true;
                break;
            }
        }
    }

    Ok((
        entries,
        TestSummary {
            entries_tested,
            entries_failed,
            bytes_tested,
            stopped_early,
        },
    ))
}

// Test zip archive
fn test_zip_archive(
    archive_path: &str,
    opts: &ArchiveTestOptions,
) -> Result<(Vec<ArchiveTestEntryResult>, TestSummary)> {
    let mut archive = ZipArchive::new(open_archive(archive_path, opts.deadline)?)?;
    let mut entries = Vec::new();
    let mut bytes_tested = 0u64;
    let mut entries_failed = 0u64;
    let mut entries_tested = 0u64;
    let mut stopped_early = false;
    let entry_count = archive.len() as u64;
    if entry_count > opts.max_entries {
        return Err(fail(
            "max_entries_exceeded",
            format!("Maximum entries limit exceeded: {}", opts.max_entries),
        ));
    }

    for i in 0..archive.len() {
        opts.deadline.check()?;
        entries_tested += 1;
        let mut entry_result = match archive.by_index_raw(i) {
            Ok(f) => ArchiveTestEntryResult {
                path: f.name().to_string(),
                is_dir: f.is_dir(),
                is_symlink: is_zip_symlink(f.unix_mode()),
                size: f.size(),
                status: "ok".to_string(),
                error: None,
            },
            Err(e) => ArchiveTestEntryResult {
                path: format!("entry_{}", i),
                is_dir: false,
                is_symlink: false,
                size: 0,
                status: "error".to_string(),
                error: Some((ARCHIVE_TEST_ENTRY_HEADER_ERROR.to_string(), e.to_string())),
            },
        };
        let size = entry_result.size;

        if entry_result.status == "ok" && opts.verify_data && !entry_result.is_dir && size > 0 {
            if let Some(max_total_bytes) = opts.max_total_bytes {
                if bytes_tested.saturating_add(size) > max_total_bytes {
                    return Err(total_limit_error(max_total_bytes));
                }
            }
            if let Some(max_file_bytes) = opts.max_file_bytes.filter(|m| size > *m) {
                entry_error(
                    &mut entry_result,
                    ARCHIVE_TEST_MAX_FILE_SIZE_EXCEEDED,
                    format!(
                        "Entry size {} exceeds max_file_bytes {}",
                        size, max_file_bytes
                    ),
                );
            } else {
                match archive.by_index(i) {
                    Err(e) => entry_error(
                        &mut entry_result,
                        ARCHIVE_TEST_ENTRY_COMPRESSION_ERROR,
                        e.to_string(),
                    ),
                    // Reading to the end checks the CRC; read one byte past
                    // the recorded size to catch a stream that is longer.
                    Ok(zip_file) => {
                        match copy(&mut zip_file.take(size + 1), &mut std::io::sink()) {
                            Ok(bytes_read) => {
                                bytes_tested += bytes_read.min(size);
                                if bytes_read != size {
                                    entry_error(
                                        &mut entry_result,
                                        ARCHIVE_TEST_ENTRY_SIZE_MISMATCH,
                                        format!("Expected {} bytes, read {}", size, bytes_read),
                                    );
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                                return Err(e.into());
                            }
                            Err(e) => entry_error(
                                &mut entry_result,
                                ARCHIVE_TEST_ENTRY_CHECKSUM_ERROR,
                                e.to_string(),
                            ),
                        }
                    }
                }
            }
        }

        let failed = entry_result.status == "error";
        entries.push(entry_result);
        if failed {
            entries_failed += 1;
            if opts.stop_on_first_error {
                stopped_early = (i + 1) < archive.len();
                break;
            }
        }
    }

    Ok((
        entries,
        TestSummary {
            entries_tested,
            entries_failed,
            bytes_tested,
            stopped_early,
        },
    ))
}

// List functionality
pub fn list_archive(opts: ArchiveListOptions) -> Result<ArchiveListResponse> {
    let mut response = ArchiveListResponse::new(&opts);
    match list_inner(&opts, &mut response) {
        Ok(()) => Ok(response),
        Err(e) => {
            let kind = runtime_kind(&e, "archive_read_error");
            response.ok = false;
            response.error = Some((error_code("list", kind), e.to_string()));
            Ok(response)
        }
    }
}

fn list_inner(opts: &ArchiveListOptions, response: &mut ArchiveListResponse) -> Result<()> {
    let (final_format, final_compression) =
        effective_format(&opts.format, &opts.compression, &opts.archive)?;
    if !archive_present(&opts.archive, opts.fail_on_missing_archive)? {
        response.warnings.push(missing_warning(&opts.archive));
        response.manifest = Some(Vec::new());
        return Ok(());
    }
    let include_globset = build_glob_set(&opts.includes, "include")
        .map_err(|e| fail("invalid_include_pattern", e.to_string()))?;
    let exclude_globset = build_glob_set(&opts.excludes, "exclude")
        .map_err(|e| fail("invalid_exclude_pattern", e.to_string()))?;
    let archive_size = fs::metadata(&opts.archive)?.len();

    let (manifest, entries_total, bytes_total) = match final_format {
        ArchiveFormat::Raw => list_raw_compressed(&opts.archive, &final_compression, opts)?,
        ArchiveFormat::Tar
        | ArchiveFormat::TarGz
        | ArchiveFormat::TarXz
        | ArchiveFormat::TarZstd => list_tar_archive(
            &opts.archive,
            &final_compression,
            opts,
            &include_globset,
            &exclude_globset,
        )?,
        ArchiveFormat::Zip => {
            list_zip_archive(&opts.archive, opts, &include_globset, &exclude_globset)?
        }
        ArchiveFormat::SevenZ => {
            return Err(fail(
                "7z_unsupported",
                "7z archive listing is not supported in this build.",
            ));
        }
        ref other => {
            return Err(fail(
                "invalid_format",
                format!("Unsupported format for listing: {}", other.as_str()),
            ));
        }
    };

    response.summary = Some(ArchiveListSummary {
        archive: opts.archive.clone(),
        format: final_format.as_str().to_string(),
        compression: final_compression.as_str().to_string(),
        entries_total,
        entries_listed: manifest.len() as u64,
        bytes_total,
        bytes_compressed: Some(archive_size),
    });
    response.manifest = Some(manifest);
    Ok(())
}

pub fn info_archive(opts: ArchiveInfoOptions) -> Result<ArchiveInfoResponse> {
    let mut response = ArchiveInfoResponse::new(&opts);
    if let Err(e) = info_inner(&opts, &mut response) {
        response.ok = false;
        response.summary = None;
        response.details = None;
        response.error = Some((
            error_code("info", runtime_kind(&e, "archive_read_error")),
            e.to_string(),
        ));
    }
    Ok(response)
}

fn info_inner(opts: &ArchiveInfoOptions, response: &mut ArchiveInfoResponse) -> Result<()> {
    let (format, compression) = effective_format(&opts.format, &opts.compression, &opts.archive)?;
    if !archive_present(&opts.archive, opts.fail_on_missing_archive)? {
        response.warnings.push(missing_warning(&opts.archive));
        return Ok(());
    }
    if format == ArchiveFormat::SevenZ {
        return Err(fail(
            "7z_unsupported",
            "7z archive inspection is not supported in this build.",
        ));
    }
    let metadata = fs::metadata(&opts.archive).map_err(|e| {
        fail(
            "io_error",
            format!("Failed to read archive metadata: {}", e),
        )
    })?;
    let archive_size_bytes = metadata.len();
    let archive_mtime_unix = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs() as i64);

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

    if opts.scan_entries {
        match format {
            ArchiveFormat::Raw => scan_raw_entries(opts, &compression, &mut summary)?,
            ArchiveFormat::TarGz
            | ArchiveFormat::TarXz
            | ArchiveFormat::TarZstd
            | ArchiveFormat::Tar => scan_tar_entries(opts, &compression, &mut summary)?,
            ArchiveFormat::Zip => scan_zip_entries(opts, &mut summary, &mut details)?,
            ref other => {
                return Err(fail(
                    "invalid_format",
                    format!("Unsupported format for scanning: {}", other.as_str()),
                ));
            }
        }
        if let Some(uncompressed) = summary.uncompressed_bytes_total {
            if archive_size_bytes > 0 && uncompressed > 0 {
                summary.compression_ratio = Some(uncompressed as f64 / archive_size_bytes as f64);
            }
        }
    }

    response.summary = Some(summary);
    response.details = Some(details);
    Ok(())
}

fn scan_raw_entries(
    opts: &ArchiveInfoOptions,
    compression: &CompressionKind,
    summary: &mut ArchiveInfoSummary,
) -> Result<()> {
    let size = raw_stream_size(
        &opts.archive,
        compression,
        opts.deadline,
        opts.max_total_bytes,
    )?;
    summary.entries_total = Some(1);
    summary.files = Some(1);
    summary.directories = Some(0);
    summary.symlinks = Some(0);
    summary.other = Some(0);
    summary.uncompressed_bytes_total = Some(size);
    summary.min_mtime_unix = summary.archive_mtime_unix;
    summary.max_mtime_unix = summary.archive_mtime_unix;
    summary.encrypted = Some(false);
    Ok(())
}

fn scan_tar_entries(
    opts: &ArchiveInfoOptions,
    compression: &CompressionKind,
    summary: &mut ArchiveInfoSummary,
) -> Result<()> {
    let reader = decompress(open_archive(&opts.archive, opts.deadline)?, compression)?;
    let mut tar = limited_archive(reader);

    let (mut entries_count, mut files_count, mut dirs_count) = (0u64, 0u64, 0u64);
    let (mut symlinks_count, mut other_count, mut total_uncompressed) = (0u64, 0u64, 0u64);
    let mut min_mtime: Option<i64> = None;
    let mut max_mtime: Option<i64> = None;

    for entry_result in tar.entries()? {
        let entry = entry_result?;
        opts.deadline.check()?;
        entries_count += 1;
        if entries_count > opts.max_entries {
            return Err(fail(
                "max_entries_exceeded",
                format!("Max entries limit exceeded: {}", opts.max_entries),
            ));
        }

        let header = entry.header();
        let entry_type = header.entry_type();
        if entry_type.is_dir() {
            dirs_count += 1;
        } else if entry_type.is_symlink() || entry_type.is_hard_link() {
            symlinks_count += 1;
        } else if entry_type.is_file() || entry_type.is_contiguous() || entry_type.is_gnu_sparse() {
            files_count += 1;
            total_uncompressed = total_uncompressed.saturating_add(entry.size());
            if let Some(max_size) = opts.max_total_bytes {
                if total_uncompressed > max_size {
                    return Err(fail(
                        "max_size_exceeded",
                        format!("Max total bytes limit exceeded: {}", max_size),
                    ));
                }
            }
        } else {
            other_count += 1;
        }

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
    summary: &mut ArchiveInfoSummary,
    details: &mut ArchiveInfoDetails,
) -> Result<()> {
    let mut zip = ZipArchive::new(open_archive(&opts.archive, opts.deadline)?)?;
    let entries_count = zip.len() as u64;
    if entries_count > opts.max_entries {
        return Err(fail(
            "max_entries_exceeded",
            format!("Max entries limit exceeded: {}", opts.max_entries),
        ));
    }

    let (mut files_count, mut dirs_count, mut symlinks_count) = (0u64, 0u64, 0u64);
    let mut total_uncompressed = 0u64;
    let mut encrypted_entries = 0u64;
    let mut min_mtime: Option<i64> = None;
    let mut max_mtime: Option<i64> = None;

    for i in 0..zip.len() {
        opts.deadline.check()?;
        let (is_dir, mode, size, mtime) = {
            let entry = zip.by_index_raw(i)?;
            (
                entry.is_dir(),
                entry.unix_mode(),
                entry.size(),
                zip_mtime(entry.last_modified()),
            )
        };
        // Opening an entry for reading is refused only for encrypted
        // entries; no data is read here.
        if let Err(zip::result::ZipError::UnsupportedArchive(msg)) = zip.by_index(i) {
            if msg == zip::result::ZipError::PASSWORD_REQUIRED {
                encrypted_entries += 1;
            }
        }
        if is_dir {
            dirs_count += 1;
        } else if is_zip_symlink(mode) {
            symlinks_count += 1;
        } else {
            files_count += 1;
            total_uncompressed = total_uncompressed.saturating_add(size);
            if let Some(max_size) = opts.max_total_bytes {
                if total_uncompressed > max_size {
                    return Err(fail(
                        "max_size_exceeded",
                        format!("Max total bytes limit exceeded: {}", max_size),
                    ));
                }
            }
        }
        if let Some(t) = mtime {
            min_mtime = Some(min_mtime.map_or(t, |m| m.min(t)));
            max_mtime = Some(max_mtime.map_or(t, |m| m.max(t)));
        }
    }

    summary.entries_total = Some(entries_count);
    summary.files = Some(files_count);
    summary.directories = Some(dirs_count);
    summary.symlinks = Some(symlinks_count);
    summary.other = Some(0);
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

// Extract functionality
pub fn extract_archive(opts: ArchiveExtractOptions) -> Result<ArchiveExtractResponse> {
    let mut response = ArchiveExtractResponse::new(&opts);
    let start_time = Instant::now();
    match extract_inner(opts, &mut response) {
        Ok(()) => {}
        Err(e) => {
            response.ok = false;
            response.summary = None;
            response.manifest = None;
            let code = match e.downcast_ref::<UnsafeEntryError>() {
                Some(u) => u.code.to_string(),
                None => error_code("extract", extract_kind(&e)),
            };
            response.error = Some((code, e.to_string()));
        }
    }
    if let Some(ref mut summary) = response.summary {
        summary.duration_ms = start_time.elapsed().as_millis() as u64;
    }
    Ok(response)
}

/// Error kind for a failed extraction: unreadable data is
/// `archive_read_error`, size limits `max_size_exceeded` /
/// `max_file_size_exceeded`, failures to write into the destination
/// `io_error`.
fn extract_kind(e: &anyhow::Error) -> &'static str {
    if is_tar_header_limit(e) {
        return "archive_read_error";
    }
    if let Some(kind) = kind_of(e) {
        return kind;
    }
    match io_kind(e) {
        Some(std::io::ErrorKind::PermissionDenied)
        | Some(std::io::ErrorKind::StorageFull)
        | Some(std::io::ErrorKind::ReadOnlyFilesystem) => "io_error",
        _ => "archive_read_error",
    }
}

fn extract_inner(opts: ArchiveExtractOptions, response: &mut ArchiveExtractResponse) -> Result<()> {
    let (format, compression) = effective_format(&opts.format, &opts.compression, &opts.archive)?;
    let opts = ArchiveExtractOptions {
        format,
        compression,
        ..opts
    };
    if !archive_present(&opts.archive, opts.fail_on_missing_archive)? {
        response.warnings.push(missing_warning(&opts.archive));
        if opts.include_manifest {
            response.manifest = Some(Vec::new());
        }
        return Ok(());
    }
    if opts.format == ArchiveFormat::SevenZ {
        return Err(fail(
            "7z_unsupported",
            "7z extraction is not supported in this build.",
        ));
    }

    let dest_path = Path::new(&opts.destination);
    match fs::metadata(dest_path) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => {
            return Err(fail(
                "invalid_destination",
                format!("Destination '{}' is not a directory.", opts.destination),
            ));
        }
        Err(_) if opts.create_destination => {
            create_dir_all(dest_path).map_err(|e| {
                fail(
                    "destination_create_failed",
                    format!("Failed to create destination directory: {}", e),
                )
            })?;
        }
        Err(_) => {
            return Err(fail(
                "destination_missing",
                format!(
                    "Destination '{}' does not exist and create_destination=false.",
                    opts.destination
                ),
            ));
        }
    }

    let include_set = build_glob_set(&opts.includes, "include")
        .map_err(|e| fail("invalid_include_pattern", e.to_string()))?;
    let exclude_set = build_glob_set(&opts.excludes, "exclude")
        .map_err(|e| fail("invalid_exclude_pattern", e.to_string()))?;

    let (summary, manifest, warnings) = match opts.format {
        ArchiveFormat::Zip => extract_zip_archive(&opts, &include_set, &exclude_set)?,
        ArchiveFormat::Raw | ArchiveFormat::Gzip => extract_raw_compressed_file(&opts)?,
        _ => extract_tar_archive(&opts, &include_set, &exclude_set)?,
    };
    response.summary = Some(summary);
    if opts.include_manifest {
        response.manifest = Some(manifest);
    }
    response.warnings = warnings;
    Ok(())
}

/// Modification time stored by `add deterministic=true` (1980-01-01T00:00:00Z,
/// the earliest time a zip archive can store).
const DETERMINISTIC_MTIME: u64 = 315_532_800;

// Add functionality
pub fn add_archive(opts: ArchiveAddOptions) -> Result<ArchiveAddResponse> {
    let mut response = ArchiveAddResponse::new(&opts);
    if let Err(e) = add_inner(&opts, &mut response) {
        response.ok = false;
        response.summary = None;
        response.details = None;
        response.error = Some((
            error_code("add", runtime_kind(&e, "archive_write_error")),
            e.to_string(),
        ));
    }
    Ok(response)
}

/// One entry of an existing archive.
#[derive(Clone, Debug)]
struct ArchiveEntry {
    /// Normalized name (see [`normalize_archive_path`]).
    path: String,
    size: u64,
    is_dir: bool,
}

/// Name used to compare entries: normalized, without a trailing `/`.
fn entry_key(path: &str) -> String {
    normalize_archive_path(path)
        .trim_end_matches('/')
        .to_string()
}

fn add_inner(opts: &ArchiveAddOptions, response: &mut ArchiveAddResponse) -> Result<()> {
    let (format, compression) = effective_format(&opts.format, &opts.compression, &opts.archive)?;
    check_rewritable(&format, "add")?;
    archive_present(&opts.archive, true)?;
    if let Some(dir) = &opts.tmp_dir {
        if !Path::new(dir).is_dir() {
            return Err(fail(
                "io_error",
                format!("tmp_dir does not exist or is not a directory: {dir}"),
            ));
        }
    }

    let include_set = build_glob_set(&opts.includes, "include")
        .map_err(|e| fail("invalid_include_pattern", e.to_string()))?;
    let exclude_set = build_glob_set(&opts.excludes, "exclude")
        .map_err(|e| fail("invalid_exclude_pattern", e.to_string()))?;

    let mut warnings = Vec::new();
    let mut new_entries = collect_new_entries(opts, &include_set, &exclude_set)?;
    if opts.deterministic {
        new_entries.sort_by(|a, b| a.archive_path.cmp(&b.archive_path));
    }
    new_entries.retain(|e| {
        if e.file_type == "other" {
            warnings.push(format!("Skipped special file '{}'", e.archive_path));
            false
        } else {
            true
        }
    });

    let archive_size_before = fs::metadata(&opts.archive)?.len();
    let existing = match format {
        ArchiveFormat::Zip => index_zip_entries(&opts.archive, opts.deadline, None, None),
        _ => index_tar_entries(&opts.archive, &compression, opts.deadline, None, None),
    }
    .map_err(read_failure)?;
    let entries_before = existing.len() as u64;
    let uncompressed_bytes_before: u64 = existing.iter().map(|e| e.size).sum();
    let existing_by_key: HashMap<String, &ArchiveEntry> =
        existing.iter().map(|e| (entry_key(&e.path), e)).collect();

    let mut details = ArchiveAddDetails {
        added: Vec::new(),
        replaced: Vec::new(),
        skipped: Vec::new(),
    };
    let mut replaced_keys = std::collections::HashSet::new();
    let mut replaced_bytes = 0u64;
    let mut to_add = Vec::new();
    for entry in new_entries {
        let key = entry_key(&entry.archive_path);
        match existing_by_key.get(&key) {
            None => {
                details.added.push(entry.archive_path.clone());
                to_add.push(entry);
            }
            // An existing directory entry is kept as it is.
            Some(old)
                if old.is_dir && entry.file_type == "directory" && opts.keep_existing_dirs => {}
            Some(old) if opts.overwrite => {
                details.replaced.push(entry.archive_path.clone());
                replaced_bytes += old.size;
                replaced_keys.insert(key);
                to_add.push(entry);
            }
            Some(_) => {
                warnings.push(format!(
                    "Skipped '{}' because overwrite=false and entry exists.",
                    entry.archive_path
                ));
                details.skipped.push(ArchiveAddSkippedEntry {
                    path: entry.archive_path,
                    reason: "already exists and overwrite=false".to_string(),
                });
            }
        }
    }

    let added_bytes: u64 = to_add.iter().map(|e| e.size).sum();
    let mut archive_size_after = archive_size_before;
    if to_add.is_empty() {
        warnings.push("Nothing to add; the archive was not rewritten.".to_string());
    } else {
        let tmp = rewrite_temp_path(&opts.archive, opts.tmp_dir.as_deref());
        let guard = TempGuard(Some(tmp.clone()));
        let keep = |key: &str| !replaced_keys.contains(key);
        match format {
            ArchiveFormat::Zip => write_zip_rewrite(&tmp, opts, &keep, &to_add)?,
            _ => write_tar_rewrite(
                &tmp,
                &opts.archive,
                &compression,
                opts.deadline,
                &keep,
                &mut |b| {
                    for entry in &to_add {
                        opts.deadline.check()?;
                        append_new_tar_entry(b, entry, opts)?;
                    }
                    Ok(())
                },
            )?,
        }
        archive_size_after = fs::metadata(&tmp)?.len();
        opts.deadline.check()?;
        if let Some(suffix) = &opts.backup_suffix {
            make_backup(&opts.archive, suffix)?;
        }
        replace_archive(&tmp, &opts.archive)
            .map_err(|e| fail("archive_write_error", format!("{e:#}")))?;
        guard.keep();
    }

    response.summary = Some(ArchiveAddSummary {
        archive: opts.archive.clone(),
        format: format.as_str().to_string(),
        compression: compression.as_str().to_string(),
        entries_before,
        entries_after: entries_before - details.replaced.len() as u64 + to_add.len() as u64,
        entries_added: details.added.len() as u64,
        entries_replaced: details.replaced.len() as u64,
        entries_skipped: details.skipped.len() as u64,
        uncompressed_bytes_before,
        uncompressed_bytes_after: uncompressed_bytes_before - replaced_bytes + added_bytes,
        archive_size_bytes_before: archive_size_before,
        archive_size_bytes_after: archive_size_after,
    });
    response.details = Some(details);
    response.warnings = warnings;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct NewArchiveEntry {
    pub archive_path: String,
    pub source_path: PathBuf,
    pub is_dir: bool,
    /// `file`, `directory`, `symlink` or `other`.
    pub file_type: &'static str,
    pub size: u64,
}

pub fn collect_new_entries(
    opts: &ArchiveAddOptions,
    include_set: &Option<globset::GlobSet>,
    exclude_set: &Option<globset::GlobSet>,
) -> Result<Vec<NewArchiveEntry>> {
    use std::os::unix::fs::MetadataExt;
    let mut entries = Vec::new();
    let archive_id = fs::metadata(&opts.archive).ok().map(|m| (m.dev(), m.ino()));

    for input in &opts.inputs {
        opts.deadline.check()?;
        if let Some(pattern) = input.strip_prefix("glob:") {
            expand_glob_pattern(pattern, opts, include_set, exclude_set, &mut entries)?;
        } else {
            let path = Path::new(input);
            if fs::symlink_metadata(path).is_err() {
                return Err(fail("invalid_input", format!("Input not found: {input}")));
            }
            collect_entries_from_path(path, opts, include_set, exclude_set, &mut entries)?;
        }
    }

    // Never add the archive into itself; keep the first of duplicates.
    let mut seen = std::collections::HashSet::new();
    entries.retain(|e| {
        let is_archive = archive_id.is_some()
            && fs::symlink_metadata(&e.source_path)
                .map(|m| Some((m.dev(), m.ino())) == archive_id)
                .unwrap_or(false);
        !is_archive && !e.archive_path.is_empty() && seen.insert(entry_key(&e.archive_path))
    });

    if entries.len() as u64 > opts.max_entries {
        return Err(fail(
            "max_entries_exceeded",
            format!(
                "Too many entries collected: {} > {}",
                entries.len(),
                opts.max_entries
            ),
        ));
    }
    if let Some(max_bytes) = opts.max_total_bytes {
        let total_size: u64 = entries.iter().map(|e| e.size).fold(0, u64::saturating_add);
        if total_size > max_bytes {
            return Err(fail(
                "max_size_exceeded",
                format!("Total size exceeds limit: {} > {}", total_size, max_bytes),
            ));
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
    let glob = shell_glob(pattern).map_err(|e| {
        fail(
            "invalid_input",
            format!("Invalid glob pattern {pattern:?}: {e}"),
        )
    })?;
    let matcher = glob.compile_matcher();

    let base_dir = extract_glob_base_dir(pattern);
    let search_root = if base_dir.is_empty() || base_dir == "." {
        std::env::current_dir()?
    } else {
        PathBuf::from(&base_dir)
    };
    if !search_root.exists() {
        return Ok(());
    }

    let walker = WalkDir::new(&search_root)
        .follow_links(opts.follow_symlinks)
        .min_depth(0);
    for entry in walker {
        opts.deadline.check()?;
        let entry = entry.map_err(|e| fail("io_error", format!("glob expansion: {e}")))?;
        let path = entry.path();
        let relative_path = if let Ok(rel) = path.strip_prefix(&search_root) {
            if base_dir.is_empty() || base_dir == "." {
                rel.to_path_buf()
            } else if rel.as_os_str().is_empty() {
                // The search root itself, without a trailing '/'.
                PathBuf::from(&base_dir)
            } else {
                Path::new(&base_dir).join(rel)
            }
        } else {
            path.to_path_buf()
        };
        let path_str = relative_path.to_string_lossy();
        if matcher.is_match(path_str.as_ref()) {
            collect_entries_from_path(path, opts, include_set, exclude_set, entries)?;
        }
    }
    Ok(())
}

fn extract_glob_base_dir(pattern: &str) -> String {
    let mut base_parts = Vec::new();
    for component in pattern.split('/') {
        if component.contains(['*', '?', '[', '{']) {
            break;
        }
        base_parts.push(component);
    }
    if base_parts.is_empty() {
        ".".to_string()
    } else {
        base_parts.join("/")
    }
}

fn new_entry(
    path: &Path,
    opts: &ArchiveAddOptions,
    meta: &fs::Metadata,
) -> Result<NewArchiveEntry> {
    let ft = meta.file_type();
    let file_type = if ft.is_file() {
        "file"
    } else if ft.is_dir() {
        "directory"
    } else if ft.is_symlink() {
        "symlink"
    } else {
        "other"
    };
    Ok(NewArchiveEntry {
        archive_path: compute_archive_path(path, opts)?,
        source_path: path.to_path_buf(),
        is_dir: ft.is_dir(),
        file_type,
        size: if ft.is_file() { meta.len() } else { 0 },
    })
}

fn collect_entries_from_path(
    path: &Path,
    opts: &ArchiveAddOptions,
    include_set: &Option<globset::GlobSet>,
    exclude_set: &Option<globset::GlobSet>,
    entries: &mut Vec<NewArchiveEntry>,
) -> Result<()> {
    let read_meta = |p: &Path| {
        if opts.follow_symlinks {
            p.metadata()
        } else {
            p.symlink_metadata()
        }
        .map_err(|e| {
            fail(
                "invalid_input",
                format!("Cannot read input {}: {e}", p.display()),
            )
        })
    };
    let metadata = read_meta(path)?;
    let entry = new_entry(path, opts, &metadata)?;
    if should_include_entry(&entry.archive_path, include_set, exclude_set) {
        entries.push(entry);
    }
    if metadata.is_dir() {
        for walked in WalkDir::new(path)
            .min_depth(1)
            .follow_links(opts.follow_symlinks)
        {
            opts.deadline.check()?;
            let walked = walked.map_err(|e| fail("io_error", format!("Cannot read input: {e}")))?;
            let meta = read_meta(walked.path())?;
            let entry = new_entry(walked.path(), opts, &meta)?;
            if should_include_entry(&entry.archive_path, include_set, exclude_set) {
                entries.push(entry);
            }
        }
    }
    Ok(())
}

/// The archive name for `path`: relative to `base_dir` when it is under it,
/// else the path without its leading `/`; `.` components are dropped and a
/// `..` component is refused.
fn compute_archive_path(path: &Path, opts: &ArchiveAddOptions) -> Result<String> {
    let relative = match &opts.base_dir {
        Some(base) => path.strip_prefix(base).unwrap_or(path),
        None => path,
    };
    member_name(relative).ok_or_else(|| {
        fail(
            "invalid_input",
            format!(
                "input {} would be stored with a '..' component; pass an absolute path or base_dir=",
                path.display()
            ),
        )
    })
}

fn should_include_entry(
    archive_path: &str,
    include_set: &Option<globset::GlobSet>,
    exclude_set: &Option<globset::GlobSet>,
) -> bool {
    matches_filters(archive_path, include_set, exclude_set)
}

/// Appends a new file, directory or symlink, applying the `add` options for
/// permissions, timestamps and owner.
fn append_new_tar_entry<W: Write>(
    b: &mut tar::Builder<W>,
    entry: &NewArchiveEntry,
    opts: &ArchiveAddOptions,
) -> Result<()> {
    let src = &entry.source_path;
    let meta = if entry.file_type == "symlink" {
        fs::symlink_metadata(src)
    } else {
        fs::metadata(src)
    }
    .map_err(|e| {
        fail(
            "io_error",
            format!("Cannot read input {}: {e}", src.display()),
        )
    })?;
    let mut h = tar::Header::new_gnu();
    h.set_metadata_in_mode(&meta, tar::HeaderMode::Complete);
    if !opts.preserve_permissions {
        h.set_mode(default_mode(entry.file_type));
    }
    if opts.deterministic {
        h.set_mtime(DETERMINISTIC_MTIME);
    } else if !opts.preserve_timestamps {
        h.set_mtime(now_unix());
    }
    if opts.preserve_owner && !opts.deterministic {
        if let Some(name) = user_name(h.uid().unwrap_or(0) as u32) {
            let _ = h.set_username(&name);
        }
        if let Some(name) = group_name(h.gid().unwrap_or(0) as u32) {
            let _ = h.set_groupname(&name);
        }
    } else {
        h.set_uid(0);
        h.set_gid(0);
    }
    match entry.file_type {
        "file" => {
            let f = File::open(src).map_err(|e| {
                fail(
                    "io_error",
                    format!("Cannot read input {}: {e}", src.display()),
                )
            })?;
            h.set_size(meta.len());
            b.append_data(
                &mut h,
                &entry.archive_path,
                DeadlineReader::new(f, opts.deadline),
            )?;
        }
        "directory" => {
            h.set_size(0);
            b.append_data(&mut h, &entry.archive_path, std::io::empty())?;
        }
        "symlink" => {
            let target = fs::read_link(src)?;
            h.set_size(0);
            b.append_link(&mut h, &entry.archive_path, &target)?;
        }
        _ => {}
    }
    Ok(())
}

fn user_name(uid: u32) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers refer to live, correctly sized buffers.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: on success pw_name points to a NUL-terminated string in buf.
    let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) };
    Some(name.to_string_lossy().into_owned())
}

fn group_name(gid: u32) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: all pointers refer to live, correctly sized buffers.
    let rc = unsafe {
        libc::getgrgid_r(
            gid,
            &mut grp,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: on success gr_name points to a NUL-terminated string in buf.
    let name = unsafe { std::ffi::CStr::from_ptr(grp.gr_name) };
    Some(name.to_string_lossy().into_owned())
}

/// Lists the entries of a tar archive without keeping their data, failing
/// past `max_entries` entries or `max_bytes` bytes.
fn index_tar_entries(
    archive_path: &str,
    compression: &CompressionKind,
    deadline: Deadline,
    max_entries: Option<u64>,
    max_bytes: Option<u64>,
) -> Result<Vec<ArchiveEntry>> {
    let reader = decompress(open_archive(archive_path, deadline)?, compression)?;
    let mut archive = limited_archive(reader);
    let mut entries = Vec::new();
    let mut total = 0u64;
    for entry in archive.entries()? {
        let entry = entry?;
        deadline.check()?;
        let path = entry.path()?.to_string_lossy().to_string();
        let size = entry.size();
        total = total.saturating_add(size);
        check_index_limits(entries.len() as u64 + 1, total, max_entries, max_bytes)?;
        entries.push(ArchiveEntry {
            path: normalize_archive_path(&path),
            size,
            is_dir: entry.header().entry_type().is_dir(),
        });
    }
    Ok(entries)
}

fn index_zip_entries(
    archive_path: &str,
    deadline: Deadline,
    max_entries: Option<u64>,
    max_bytes: Option<u64>,
) -> Result<Vec<ArchiveEntry>> {
    let mut zip = ZipArchive::new(open_archive(archive_path, deadline)?)?;
    let mut entries = Vec::new();
    let mut total = 0u64;
    for i in 0..zip.len() {
        deadline.check()?;
        let entry = zip.by_index_raw(i)?;
        total = total.saturating_add(entry.size());
        check_index_limits(i as u64 + 1, total, max_entries, max_bytes)?;
        entries.push(ArchiveEntry {
            path: normalize_archive_path(entry.name()),
            size: entry.size(),
            is_dir: entry.is_dir(),
        });
    }
    Ok(entries)
}

fn check_index_limits(
    count: u64,
    total: u64,
    max_entries: Option<u64>,
    max_bytes: Option<u64>,
) -> Result<()> {
    if let Some(max) = max_entries.filter(|m| count > *m) {
        return Err(fail(
            "max_entries_exceeded",
            format!("Maximum entries limit exceeded: {}", max),
        ));
    }
    if let Some(max) = max_bytes.filter(|m| total > *m) {
        return Err(fail(
            "max_size_exceeded",
            format!("Maximum total bytes limit exceeded: {}", max),
        ));
    }
    Ok(())
}

/// Copies the entries of the tar archive at `original_path` for which
/// `keep(key)` is true into `dest`, with their original headers, full
/// (long) names and link targets.
fn copy_tar_entries<W: Write>(
    original_path: &str,
    dest: &mut tar::Builder<W>,
    compression: &CompressionKind,
    deadline: Deadline,
    keep: &dyn Fn(&str) -> bool,
) -> Result<()> {
    let reader = decompress(open_archive(original_path, deadline)?, compression)?;
    let mut source = limited_archive(reader);
    for entry in source.entries()? {
        let mut entry = entry?;
        deadline.check()?;
        let path = entry.path()?.into_owned();
        if !keep(&entry_key(&path.to_string_lossy())) {
            continue;
        }
        let mut header = entry.header().clone();
        let entry_type = header.entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            let target = entry
                .link_name()?
                .map(|l| l.into_owned())
                .unwrap_or_default();
            dest.append_link(&mut header, &path, &target)?;
        } else {
            if entry_type.is_gnu_sparse() {
                // The data read back is the expanded file.
                header.set_entry_type(tar::EntryType::Regular);
            }
            header.set_size(entry.size());
            dest.append_data(&mut header, &path, &mut entry)?;
        }
    }
    Ok(())
}

/// Writes a tar archive to the new temporary file `tmp` (permissions of
/// `original`): the kept entries of `original`, then whatever `extra`
/// appends. Each compressor is finished explicitly so an error at the end
/// of the stream fails the operation.
fn write_tar_rewrite(
    tmp: &Path,
    original: &str,
    compression: &CompressionKind,
    deadline: Deadline,
    keep: &dyn Fn(&str) -> bool,
    extra: &mut dyn FnMut(&mut tar::Builder<&mut dyn Write>) -> Result<()>,
) -> Result<()> {
    let fill = |w: &mut dyn Write,
                extra: &mut dyn FnMut(&mut tar::Builder<&mut dyn Write>) -> Result<()>|
     -> Result<()> {
        let mut b = tar::Builder::new(w);
        copy_tar_entries(original, &mut b, compression, deadline, keep)?;
        extra(&mut b)?;
        b.finish()?;
        Ok(())
    };
    let file = BufWriter::new(create_temp_output(tmp, Path::new(original))?);
    let file = match compression {
        CompressionKind::None | CompressionKind::Auto => {
            let mut w = file;
            fill(&mut w, extra)?;
            w
        }
        CompressionKind::Gzip => {
            let mut e = GzEncoder::new(file, Compression::default());
            fill(&mut e, extra)?;
            e.finish()?
        }
        CompressionKind::Xz => {
            let mut e = XzEncoder::new(file, 6);
            fill(&mut e, extra)?;
            e.finish()?
        }
        CompressionKind::Zstd => {
            let mut e = ZstdEncoder::new(file, 3)?;
            fill(&mut e, extra)?;
            e.finish()?
        }
    };
    finish_output(file)
}

/// An error from reading the existing archive, as kind
/// `archive_read_error` unless it already has a kind.
fn read_failure(e: anyhow::Error) -> anyhow::Error {
    if kind_of(&e).is_some() {
        e
    } else {
        fail("archive_read_error", e.to_string())
    }
}

/// Writes a zip archive to the new temporary file `tmp`: the kept entries
/// of the original copied without recompression, then the new entries.
fn write_zip_rewrite(
    tmp: &Path,
    opts: &ArchiveAddOptions,
    keep: &dyn Fn(&str) -> bool,
    new_entries: &[NewArchiveEntry],
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut zip = ZipWriter::new(create_temp_output(tmp, Path::new(&opts.archive))?);
    copy_zip_entries(&opts.archive, &mut zip, opts.deadline, keep)?;
    for entry in new_entries {
        opts.deadline.check()?;
        let src = &entry.source_path;
        let meta = if entry.file_type == "symlink" {
            fs::symlink_metadata(src)
        } else {
            fs::metadata(src)
        }
        .map_err(|e| {
            fail(
                "io_error",
                format!("Cannot read input {}: {e}", src.display()),
            )
        })?;
        let mode = if opts.preserve_permissions {
            meta.permissions().mode() & 0o7777
        } else {
            default_mode(entry.file_type)
        };
        let mtime = if opts.deterministic {
            UNIX_EPOCH + std::time::Duration::from_secs(DETERMINISTIC_MTIME)
        } else if opts.preserve_timestamps {
            meta.modified().unwrap_or_else(|_| SystemTime::now())
        } else {
            SystemTime::now()
        };
        let time = if opts.deterministic {
            zip::DateTime::default()
        } else {
            zip_time(mtime)
        };
        let options = FileOptions::default()
            .unix_permissions(mode)
            .last_modified_time(time)
            .large_file(meta.len() >= 0xFFFF_FFFF);
        match entry.file_type {
            "file" => {
                zip.start_file(&entry.archive_path, options)?;
                let f = File::open(src).map_err(|e| {
                    fail(
                        "io_error",
                        format!("Cannot read input {}: {e}", src.display()),
                    )
                })?;
                copy(&mut DeadlineReader::new(f, opts.deadline), &mut zip)?;
            }
            "directory" => zip.add_directory(&entry.archive_path, options)?,
            "symlink" => {
                let target = fs::read_link(src)?;
                zip.add_symlink(&entry.archive_path, target.to_string_lossy(), options)?;
            }
            _ => {}
        }
    }
    zip.finish()?.sync_all()?;
    Ok(())
}

/// Copies the entries of the zip at `original` for which `keep(key)` is
/// true, unchanged (compressed data, mode, time, method).
fn copy_zip_entries(
    original: &str,
    zip: &mut ZipWriter<File>,
    deadline: Deadline,
    keep: &dyn Fn(&str) -> bool,
) -> Result<()> {
    let mut source = ZipArchive::new(open_archive(original, deadline)?)?;
    for i in 0..source.len() {
        deadline.check()?;
        let (name, is_dir, mode, mtime, method, size) = {
            let e = source.by_index_raw(i)?;
            (
                e.name().to_string(),
                e.is_dir(),
                e.unix_mode(),
                e.last_modified(),
                e.compression(),
                e.size(),
            )
        };
        if !keep(&entry_key(&name)) {
            continue;
        }
        let mut options = FileOptions::default()
            .compression_method(method)
            .last_modified_time(mtime)
            .large_file(size >= 0xFFFF_FFFF);
        if let Some(m) = mode {
            options = options.unix_permissions(m & 0o7777);
        }
        // Entries are re-encoded (streamed) rather than copied raw: zip
        // 0.6's raw copy drops the file type (directory, symlink) and the
        // encryption flag.
        let mut entry = match source.by_index(i) {
            Ok(e) => e,
            Err(zip::result::ZipError::UnsupportedArchive(msg))
                if msg == zip::result::ZipError::PASSWORD_REQUIRED =>
            {
                return Err(fail(
                    "archive_write_error",
                    format!("encrypted zip entry '{name}' cannot be rewritten"),
                ));
            }
            Err(e) => return Err(e.into()),
        };
        if is_dir {
            zip.add_directory(&name, options)?;
        } else if is_zip_symlink(mode) {
            let mut target = String::new();
            (&mut entry).take(4096).read_to_string(&mut target)?;
            zip.add_symlink(&name, target, options)?;
        } else {
            zip.start_file(&name, options)?;
            copy(&mut entry, zip)?;
        }
    }
    Ok(())
}

/// Path for the temporary rewrite of `archive`: in `tmp_dir` if given, else
/// next to the archive. The name cannot be predicted by another user.
fn rewrite_temp_path(archive: &str, tmp_dir: Option<&str>) -> PathBuf {
    let dir = match tmp_dir {
        Some(d) => PathBuf::from(d),
        None => match Path::new(archive).parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        },
    };
    dir.join(temp_archive_name(".tmp_archive_"))
}

/// Copies `archive` to its backup name without following a symlink there.
fn make_backup(archive: &str, suffix: &str) -> Result<()> {
    let backup = backup_path(archive, suffix);
    crate::core::secure_fs::copy_no_follow(Path::new(archive), &backup).map_err(|e| {
        fail(
            "backup_failed",
            format!("Failed to create backup {}: {e}", backup.display()),
        )
    })?;
    Ok(())
}

/// Moves the finished rewrite `tmp` over `archive`. A `tmp` on another
/// filesystem (`tmp_dir=`) is first copied next to the archive.
fn replace_archive(tmp: &Path, archive: &str) -> Result<()> {
    match fs::rename(tmp, archive) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            let local = rewrite_temp_path(archive, None);
            let guard = TempGuard(Some(local.clone()));
            let mut out = create_temp_output(&local, Path::new(archive))?;
            copy(&mut File::open(tmp)?, &mut out)?;
            out.sync_all()?;
            drop(out);
            fs::rename(&local, archive)?;
            guard.keep();
            let _ = fs::remove_file(tmp);
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Opens a new temporary output file for an archive rewrite: never an
/// existing file or symlink (`create_new` + `O_NOFOLLOW`), and with the
/// original archive's permission bits (0600 if it has none), so a private
/// archive does not become world-readable when it is replaced.
fn create_temp_output(path: &Path, original: &Path) -> Result<File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mode = std::fs::metadata(original)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0o600);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("cannot create temporary archive {}", path.display()))?;
    // The umask may have removed bits the original has.
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    Ok(file)
}

/// A temporary-file name that another local user cannot predict.
fn temp_archive_name(prefix: &str) -> String {
    format!(
        "{prefix}{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    )
}

fn build_glob_set(patterns: &[String], pattern_type: &str) -> Result<Option<globset::GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = shell_glob(pattern)
            .context(format!("Invalid {} pattern: {}", pattern_type, pattern))?;
        builder.add(glob);
    }
    Ok(Some(builder.build()?))
}

pub fn remove_archive(opts: ArchiveRemoveOptions) -> Result<ArchiveRemoveResponse> {
    let mut response = ArchiveRemoveResponse::new(&opts);
    if let Err(e) = remove_inner(&opts, &mut response) {
        response.ok = false;
        response.summary = None;
        response.details = None;
        response.error = Some((
            error_code("remove", runtime_kind(&e, "archive_read_error")),
            e.to_string(),
        ));
    }
    Ok(response)
}

fn remove_inner(opts: &ArchiveRemoveOptions, response: &mut ArchiveRemoveResponse) -> Result<()> {
    let (format, compression) = effective_format(&opts.format, &opts.compression, &opts.archive)?;
    check_rewritable(&format, "remove")?;
    if !archive_present(&opts.archive, opts.fail_on_missing_archive)? {
        response.warnings.push(missing_warning(&opts.archive));
        return Ok(());
    }
    if let Some(dir) = &opts.tmp_dir {
        if !Path::new(dir).is_dir() {
            return Err(fail(
                "io_error",
                format!("tmp_dir does not exist or is not a directory: {dir}"),
            ));
        }
    }
    let pattern_set = build_glob_set(&opts.patterns, "patterns")
        .map_err(|e| fail("invalid_pattern", e.to_string()))?;

    let archive_size_before = fs::metadata(&opts.archive)?.len();
    let entries_before = match format {
        ArchiveFormat::Zip => index_zip_entries(
            &opts.archive,
            opts.deadline,
            Some(opts.max_entries),
            opts.max_total_bytes,
        ),
        _ => index_tar_entries(
            &opts.archive,
            &compression,
            opts.deadline,
            Some(opts.max_entries),
            opts.max_total_bytes,
        ),
    }
    .map_err(read_failure)?;
    let (entries_to_keep, entries_to_remove) =
        filter_entries(&entries_before, opts, pattern_set.as_ref());

    let mut warnings = Vec::new();
    let mut not_found = Vec::new();
    for path in &opts.paths {
        let key = entry_key(path);
        if !entries_to_remove.iter().any(|e| entry_key(&e.path) == key) {
            not_found.push(path.clone());
            warnings.push(format!(
                "Path '{}' did not match any entries in archive.",
                path
            ));
        }
    }
    for pattern in &opts.patterns {
        let matched = shell_glob(pattern)
            .map(|g| g.compile_matcher())
            .map(|m| entries_before.iter().any(|e| m.is_match(&e.path)))
            .unwrap_or(false);
        if !matched {
            warnings.push(format!(
                "Pattern '{}' did not match any entries in archive.",
                pattern
            ));
        }
    }
    for prefix in &opts.dir_prefixes {
        let key = entry_key(prefix);
        let slash = format!("{key}/");
        if !entries_before
            .iter()
            .any(|e| entry_key(&e.path) == key || e.path.starts_with(&slash))
        {
            warnings.push(format!(
                "Directory prefix '{}' did not match any entries in archive.",
                prefix
            ));
        }
    }

    let uncompressed_bytes_before = entries_before.iter().map(|e| e.size).sum::<u64>();
    let uncompressed_bytes_after = entries_to_keep.iter().map(|e| e.size).sum::<u64>();

    let archive_size_after = if opts.dry_run {
        // An estimate: the current compression ratio applied to what stays.
        if uncompressed_bytes_before > 0 {
            (uncompressed_bytes_after as f64 * archive_size_before as f64
                / uncompressed_bytes_before as f64) as u64
        } else {
            archive_size_before
        }
    } else if entries_to_remove.is_empty() {
        warnings.push("Nothing matched; the archive was not rewritten.".to_string());
        archive_size_before
    } else {
        let keep_keys: std::collections::HashSet<String> =
            entries_to_keep.iter().map(|e| entry_key(&e.path)).collect();
        let keep = |key: &str| keep_keys.contains(key);
        let tmp = rewrite_temp_path(&opts.archive, opts.tmp_dir.as_deref());
        let guard = TempGuard(Some(tmp.clone()));
        let written = match format {
            ArchiveFormat::Zip => (|| -> Result<()> {
                let mut zip = ZipWriter::new(create_temp_output(&tmp, Path::new(&opts.archive))?);
                copy_zip_entries(&opts.archive, &mut zip, opts.deadline, &keep)?;
                zip.finish()?.sync_all()?;
                Ok(())
            })(),
            _ => write_tar_rewrite(
                &tmp,
                &opts.archive,
                &compression,
                opts.deadline,
                &keep,
                &mut |_| Ok(()),
            ),
        };
        written.map_err(|e| {
            if kind_of(&e).is_some() || is_tar_header_limit(&e) {
                e
            } else {
                fail("archive_write_error", format!("{e:#}"))
            }
        })?;
        let new_size = fs::metadata(&tmp)?.len();
        opts.deadline.check()?;
        if let Some(suffix) = &opts.backup_suffix {
            make_backup(&opts.archive, suffix)?;
        }
        replace_archive(&tmp, &opts.archive).map_err(|e| {
            fail(
                "replace_failed",
                format!("Failed to replace original archive: {e:#}"),
            )
        })?;
        guard.keep();
        new_size
    };

    response.summary = Some(ArchiveRemoveSummary {
        archive: opts.archive.clone(),
        format: format.as_str().to_string(),
        compression: compression.as_str().to_string(),
        entries_before: entries_before.len() as u64,
        entries_after: entries_to_keep.len() as u64,
        entries_removed: entries_to_remove.len() as u64,
        dirs_removed: entries_to_remove.iter().filter(|e| e.is_dir).count() as u64,
        uncompressed_bytes_before,
        uncompressed_bytes_after,
        archive_size_bytes_before: archive_size_before,
        archive_size_bytes_after: archive_size_after,
        dry_run: opts.dry_run,
    });
    response.details = Some(ArchiveRemoveDetails {
        removed: entries_to_remove.iter().map(|e| e.path.clone()).collect(),
        not_found,
        // Truncated for large archives.
        kept: entries_to_keep
            .iter()
            .take(100)
            .map(|e| e.path.clone())
            .collect(),
    });
    response.warnings = warnings;
    Ok(())
}

fn filter_entries(
    entries: &[ArchiveEntry],
    opts: &ArchiveRemoveOptions,
    pattern_set: Option<&globset::GlobSet>,
) -> (Vec<ArchiveEntry>, Vec<ArchiveEntry>) {
    let path_keys: std::collections::HashSet<String> =
        opts.paths.iter().map(|p| entry_key(p)).collect();
    let prefixes: Vec<String> = opts.dir_prefixes.iter().map(|p| entry_key(p)).collect();

    let (mut keep, mut remove): (Vec<ArchiveEntry>, Vec<ArchiveEntry>) =
        entries.iter().cloned().partition(|entry| {
            let key = entry_key(&entry.path);
            let selected = path_keys.contains(&key)
                || prefixes
                    .iter()
                    .any(|p| key == *p || key.starts_with(&format!("{p}/")))
                || pattern_set.is_some_and(|s| s.is_match(&entry.path) || s.is_match(&key));
            !selected
        });

    // A kept directory that had contents, all of which were removed, is
    // removed too. Deepest directories first, so emptied parents follow.
    if opts.remove_empty_dirs && !remove.is_empty() {
        let mut dirs: Vec<String> = keep
            .iter()
            .filter(|e| e.is_dir)
            .map(|e| entry_key(&e.path))
            .collect();
        dirs.sort_by_key(|d| std::cmp::Reverse(d.matches('/').count()));
        for dir in dirs {
            let prefix = format!("{dir}/");
            let had_contents = entries
                .iter()
                .any(|e| entry_key(&e.path).starts_with(&prefix));
            let has_contents = keep.iter().any(|e| entry_key(&e.path).starts_with(&prefix));
            if had_contents && !has_contents {
                if let Some(pos) = keep.iter().position(|e| entry_key(&e.path) == dir) {
                    remove.push(keep.remove(pos));
                }
            }
        }
    }
    (keep, remove)
}

/// Flushes the buffered writer and syncs the file to disk.
fn finish_output(w: BufWriter<File>) -> Result<()> {
    w.into_inner().map_err(|e| e.into_error())?.sync_all()?;
    Ok(())
}

fn extract_tar_archive(
    opts: &ArchiveExtractOptions,
    include_set: &Option<globset::GlobSet>,
    exclude_set: &Option<globset::GlobSet>,
) -> Result<(
    ArchiveExtractSummary,
    Vec<ArchiveExtractManifestEntry>,
    Vec<String>,
)> {
    let archive = decompress(
        open_archive(&opts.archive, opts.deadline)?,
        &opts.compression,
    )?;
    let mut tar = limited_archive(archive);
    let dest_path = Path::new(&opts.destination);

    let mut entries_total = 0u64;
    let mut entries_extracted = 0u64;
    let mut entries_skipped = 0u64;
    let mut bytes_written = 0u64;
    let mut manifest = Vec::new();
    let mut warnings = Vec::new();

    let mut created_symlinks: Vec<PathBuf> = Vec::new();

    for entry_result in tar.entries()? {
        let mut entry = entry_result?;
        opts.deadline.check()?;
        entries_total += 1;

        // Check safety limits early
        if entries_total > opts.max_entries {
            return Err(fail(
                "max_entries_exceeded",
                format!(
                    "Maximum number of entries exceeded: {}; extraction stopped after {} entries were written",
                    opts.max_entries, entries_extracted
                ),
            ));
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

        // Security checks: an unsafe entry stops the extraction with an error
        let safe_path = sanitize_path(&stripped_path, dest_path, opts)
            .map_err(|e| stop_unsafe(e, &path_str, entries_extracted))?;

        let entry_type = entry.header().entry_type();
        if matches!(entry_type, tar::EntryType::Char | tar::EntryType::Block) {
            return Err(stop_unsafe(
                unsafe_entry(
                    ARCHIVE_EXTRACT_UNSUPPORTED_ENTRY_TYPE,
                    "device nodes are not extracted".to_string(),
                ),
                &path_str,
                entries_extracted,
            ));
        }

        // The destination directory itself (e.g. a "./" entry)
        if safe_path == dest_path {
            entries_skipped += 1;
            continue;
        }

        // Check if target exists (a dangling symlink counts) and handle overwrite
        if fs::symlink_metadata(&safe_path).is_ok() && !opts.overwrite {
            warnings.push(format!(
                "Skipped existing file '{}' (overwrite=false)",
                stripped_path
            ));
            entries_skipped += 1;
            continue;
        }

        // Extract the entry
        let is_dir = entry_type.is_dir();
        let is_symlink = entry_type.is_symlink() || entry_type.is_hard_link();
        // The size the tar reader will write: a PAX size record overrides
        // the header field, and a sparse file's size includes its holes.
        let size = entry.size();
        check_entry_size(opts, &path_str, size, bytes_written)?;

        // Handle symlinks
        if is_symlink && !opts.allow_symlinks {
            warnings.push(format!(
                "Skipped symlink '{}' (allow_symlinks=false)",
                stripped_path
            ));
            entries_skipped += 1;
            continue;
        }

        // Validate link targets before anything on disk is changed
        let hard_link_src = if entry_type.is_hard_link() {
            Some(
                hard_link_source(&entry, dest_path, opts)
                    .map_err(|e| stop_unsafe(e, &path_str, entries_extracted))?,
            )
        } else {
            None
        };
        if entry_type.is_symlink() {
            let target = entry
                .link_name()?
                .map(|t| t.into_owned())
                .unwrap_or_default();
            if !symlink_target_stays_inside(dest_path, &safe_path, &target) {
                return Err(stop_unsafe(
                    unsafe_entry(
                        ARCHIVE_EXTRACT_SYMLINK_REJECTED,
                        format!(
                            "symlink target '{}' points outside the destination",
                            target.display()
                        ),
                    ),
                    &path_str,
                    entries_extracted,
                ));
            }
        }

        // Regular files are written through a temporary file, so a failed
        // entry neither leaves partial data nor destroys an existing file.
        let via_temp =
            entry_type.is_file() || entry_type.is_contiguous() || entry_type.is_gnu_sparse();

        // Create parent directories without following any symlink, then
        // make sure an existing final component is not a link we would
        // write or chmod through.
        let created_dirs = prepare_parent_dirs(dest_path, &safe_path)
            .and_then(|created| {
                if via_temp {
                    refuse_existing_dir(&safe_path)?;
                } else {
                    clear_existing_target(&safe_path, is_dir)?;
                }
                Ok(created)
            })
            .map_err(|e| stop_unsafe(e, &path_str, entries_extracted))?;

        if let Some(link_src) = hard_link_src {
            fs::hard_link(&link_src, &safe_path)?;
        } else if via_temp {
            write_via_temp(&safe_path, |tmp| Ok(entry.unpack(tmp)?))
                .inspect_err(|_| remove_created_dirs(&created_dirs))?;
        } else {
            entry.unpack(&safe_path)?;
            if entry_type.is_symlink() {
                created_symlinks.push(safe_path.clone());
            }
        }
        entries_extracted += 1;

        if !is_dir {
            bytes_written = bytes_written
                .checked_add(size)
                .context("extracted byte count overflow")?;
        }

        manifest.push(ArchiveExtractManifestEntry {
            path: stripped_path,
            size,
            is_dir,
            is_symlink,
        });
    }

    // Lexical checks cannot see through chains of links created by the
    // archive; resolve every created link and reject any that leaves.
    verify_symlinks_inside(dest_path, &created_symlinks)?;

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
) -> Result<(
    ArchiveExtractSummary,
    Vec<ArchiveExtractManifestEntry>,
    Vec<String>,
)> {
    let mut zip = ZipArchive::new(open_archive(&opts.archive, opts.deadline)?)?;
    let dest_path = Path::new(&opts.destination);

    let entries_total = zip.len() as u64;
    let mut entries_extracted = 0u64;
    let mut entries_skipped = 0u64;
    let mut bytes_written = 0u64;
    let mut manifest = Vec::new();
    let mut warnings = Vec::new();
    let mut created_symlinks: Vec<PathBuf> = Vec::new();

    // Check safety limits early
    if entries_total > opts.max_entries {
        return Err(fail(
            "max_entries_exceeded",
            format!("Maximum number of entries exceeded: {}", opts.max_entries),
        ));
    }

    for i in 0..zip.len() {
        opts.deadline.check()?;
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

        // Security checks: an unsafe entry stops the extraction with an error
        let safe_path = sanitize_path(&stripped_path, dest_path, opts)
            .map_err(|e| stop_unsafe(e, &path_str, entries_extracted))?;

        // The destination directory itself
        if safe_path == dest_path {
            entries_skipped += 1;
            continue;
        }

        // Check if target exists (a dangling symlink counts) and handle overwrite
        if fs::symlink_metadata(&safe_path).is_ok() && !opts.overwrite {
            warnings.push(format!(
                "Skipped existing file '{}' (overwrite=false)",
                stripped_path
            ));
            entries_skipped += 1;
            continue;
        }

        let is_dir = file.is_dir();

        // A symlink entry (Unix mode S_IFLNK) holds its target as data.
        if !is_dir && is_zip_symlink(file.unix_mode()) {
            if !opts.allow_symlinks {
                warnings.push(format!(
                    "Skipped symlink '{}' (allow_symlinks=false)",
                    stripped_path
                ));
                entries_skipped += 1;
                continue;
            }
            let mut raw = Vec::new();
            (&mut file).take(4097).read_to_end(&mut raw)?;
            if raw.is_empty() || raw.len() > 4096 || raw.contains(&0) {
                return Err(stop_unsafe(
                    unsafe_entry(
                        ARCHIVE_EXTRACT_SYMLINK_REJECTED,
                        "symlink target is empty, longer than 4096 bytes or contains NUL"
                            .to_string(),
                    ),
                    &path_str,
                    entries_extracted,
                ));
            }
            let target = PathBuf::from(
                <std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(raw),
            );
            if !symlink_target_stays_inside(dest_path, &safe_path, &target) {
                return Err(stop_unsafe(
                    unsafe_entry(
                        ARCHIVE_EXTRACT_SYMLINK_REJECTED,
                        format!(
                            "symlink target '{}' points outside the destination",
                            target.display()
                        ),
                    ),
                    &path_str,
                    entries_extracted,
                ));
            }
            prepare_parent_dirs(dest_path, &safe_path)
                .and_then(|_| clear_existing_target(&safe_path, false))
                .map_err(|e| stop_unsafe(e, &path_str, entries_extracted))?;
            std::os::unix::fs::symlink(&target, &safe_path)?;
            created_symlinks.push(safe_path.clone());
            entries_extracted += 1;
            manifest.push(ArchiveExtractManifestEntry {
                path: stripped_path,
                size: 0,
                is_dir: false,
                is_symlink: true,
            });
            continue;
        }

        // The size the archive records; checked early, but not trusted
        let mut size = file.size();
        check_entry_size(opts, &path_str, size, bytes_written)?;

        // Create parent directories without following any symlink, and
        // never write through an existing link at the final component.
        let created_dirs = prepare_parent_dirs(dest_path, &safe_path)
            .and_then(|created| {
                if is_dir {
                    clear_existing_target(&safe_path, true)?;
                } else {
                    refuse_existing_dir(&safe_path)?;
                }
                Ok(created)
            })
            .map_err(|e| stop_unsafe(e, &path_str, entries_extracted))?;

        if is_dir {
            if !safe_path.is_dir() {
                fs::create_dir(&safe_path)?;
            }
        } else {
            let budget = entry_byte_budget(opts, bytes_written);
            let written = write_via_temp(&safe_path, |tmp| {
                let mut output = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(tmp)?;
                copy_limited(&mut file, &mut output, budget)?
                    .ok_or_else(|| entry_limit_error(opts, &path_str, bytes_written))
            })
            .inspect_err(|_| remove_created_dirs(&created_dirs))?;
            size = written;
            bytes_written = bytes_written
                .checked_add(written)
                .context("extracted byte count overflow")?;
        }

        entries_extracted += 1;

        manifest.push(ArchiveExtractManifestEntry {
            path: stripped_path,
            size,
            is_dir,
            is_symlink: false,
        });
    }

    // Resolve every created link; reject any that leaves the destination.
    verify_symlinks_inside(dest_path, &created_symlinks)?;

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
) -> Result<(
    ArchiveExtractSummary,
    Vec<ArchiveExtractManifestEntry>,
    Vec<String>,
)> {
    let dest_path = Path::new(&opts.destination);

    // The output is named after the archive without its compression
    // extension.
    let output_name = raw_member_name(&opts.archive);
    let output_name = output_name.as_str();
    let output_path = dest_path.join(output_name);

    // Check if target exists (a dangling symlink counts) and handle overwrite
    if fs::symlink_metadata(&output_path).is_ok() && !opts.overwrite {
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
            vec![format!(
                "Skipped existing file '{}' (overwrite=false)",
                output_name
            )],
        ));
    }

    if opts.compression == CompressionKind::None || opts.compression == CompressionKind::Auto {
        return Err(fail(
            "invalid_format_compression",
            format!(
                "Invalid compression for raw format: {}",
                opts.compression.as_str()
            ),
        ));
    }
    let mut decoder = decompress(
        open_archive(&opts.archive, opts.deadline)?,
        &opts.compression,
    )?;

    // Write through a temporary file: a planted symlink at the output name
    // is replaced, not followed, and a failure leaves no partial output.
    refuse_existing_dir(&output_path)?;
    let budget = entry_byte_budget(opts, 0);
    let bytes_written = write_via_temp(&output_path, |tmp| {
        let mut output_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(tmp)?;
        match copy_limited(&mut decoder, &mut output_file, budget)? {
            Some(n) => Ok(n),
            None if opts.max_total_bytes == Some(budget) => Err(fail(
                "max_size_exceeded",
                format!(
                    "Extracted size (more than {}) exceeds maximum total size ({})",
                    budget, budget
                ),
            )),
            None => Err(fail(
                "max_file_size_exceeded",
                format!(
                    "Extracted file size (more than {}) exceeds maximum file size ({})",
                    budget, budget
                ),
            )),
        }
    })?;

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

/// An archive entry that cannot be extracted without risking a write outside
/// the destination. Extraction stops and the response reports `code`.
#[derive(Debug)]
pub struct UnsafeEntryError {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for UnsafeEntryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UnsafeEntryError {}

fn unsafe_entry(code: &'static str, message: String) -> anyhow::Error {
    anyhow::Error::new(UnsafeEntryError { code, message })
}

/// Name the entry in an unsafe-entry error and say how much was already
/// written, so a stopped extraction is never mistaken for a clean one.
fn stop_unsafe(err: anyhow::Error, entry: &str, extracted: u64) -> anyhow::Error {
    let code = err
        .downcast_ref::<UnsafeEntryError>()
        .map(|u| u.code)
        .unwrap_or(ARCHIVE_EXTRACT_IO_ERROR);
    unsafe_entry(
        code,
        format!(
            "Unsafe archive entry '{}': {}; extraction stopped after {} entries were written",
            entry, err, extracted
        ),
    )
}

// Made public for testing
/// Map an archive entry path to a path inside `dest_path`, by its text.
/// Absolute paths are rejected unless `allow_absolute_paths`, in which case
/// they are re-rooted under the destination; `..` is rejected unless
/// `allow_parent_traversal`, and may then never climb above the destination.
/// Symlinks on disk are handled separately by `prepare_parent_dirs`.
pub fn sanitize_path(
    path: &str,
    dest_path: &Path,
    opts: &ArchiveExtractOptions,
) -> Result<PathBuf> {
    let path_buf = Path::new(path);

    // Handle absolute paths
    let relative_path = if path_buf.has_root() {
        if !opts.allow_absolute_paths {
            return Err(unsafe_entry(
                ARCHIVE_EXTRACT_ABSOLUTE_PATH_REJECTED,
                "Absolute paths not allowed (allow_absolute_paths=false)".to_string(),
            ));
        }
        // Re-root under the destination
        path_buf.strip_prefix("/").unwrap_or(path_buf)
    } else {
        path_buf
    };

    // Normalize and check for path traversal
    let mut safe_path = dest_path.to_path_buf();
    for component in relative_path.components() {
        match component {
            Component::Normal(name) => safe_path.push(name),
            Component::CurDir => {} // Skip current dir
            Component::ParentDir => {
                if !opts.allow_parent_traversal {
                    return Err(unsafe_entry(
                        ARCHIVE_EXTRACT_PATH_TRAVERSAL_DETECTED,
                        "Path traversal detected (..)".to_string(),
                    ));
                }
                if safe_path.as_path() == dest_path {
                    return Err(unsafe_entry(
                        ARCHIVE_EXTRACT_PATH_TRAVERSAL_DETECTED,
                        "Path escapes destination directory".to_string(),
                    ));
                }
                safe_path.pop();
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(unsafe_entry(
                    ARCHIVE_EXTRACT_ABSOLUTE_PATH_REJECTED,
                    "Root directory component not allowed".to_string(),
                ));
            }
        }
    }

    // Ensure the final path is still within destination
    if !safe_path.starts_with(dest_path) {
        return Err(unsafe_entry(
            ARCHIVE_EXTRACT_PATH_TRAVERSAL_DETECTED,
            "Path escapes destination directory".to_string(),
        ));
    }

    Ok(safe_path)
}

/// Create the missing parent directories of `target` (a path inside `dest`
/// from `sanitize_path`) one level at a time. Every existing component must
/// be a real directory: a symlink, whether created earlier by the archive or
/// already present in the destination, is refused rather than followed.
/// Returns the directories it created, outermost first.
fn prepare_parent_dirs(dest: &Path, target: &Path) -> Result<Vec<PathBuf>> {
    let rel = target.strip_prefix(dest).map_err(|_| {
        unsafe_entry(
            ARCHIVE_EXTRACT_PATH_TRAVERSAL_DETECTED,
            "Path escapes destination directory".to_string(),
        )
    })?;
    let parents: Vec<_> = rel.components().collect();
    let mut cur = dest.to_path_buf();
    let mut created = Vec::new();
    for comp in parents.iter().take(parents.len().saturating_sub(1)) {
        cur.push(comp);
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(unsafe_entry(
                    ARCHIVE_EXTRACT_SYMLINK_REJECTED,
                    format!("parent '{}' is a symlink", cur.display()),
                ));
            }
            Ok(m) if m.is_dir() => {}
            Ok(_) => anyhow::bail!("parent '{}' is not a directory", cur.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => match fs::create_dir(&cur) {
                Ok(()) => created.push(cur.clone()),
                Err(e) => {
                    // Lost a race with another creator: accept only a real directory
                    let ok = e.kind() == std::io::ErrorKind::AlreadyExists
                        && fs::symlink_metadata(&cur)
                            .map(|m| m.is_dir())
                            .unwrap_or(false);
                    if !ok {
                        return Err(e.into());
                    }
                }
            },
            Err(e) => return Err(e.into()),
        }
    }
    Ok(created)
}

/// Before (over)writing `target`: remove an existing symlink or file there
/// so the write cannot follow it. An existing real directory is kept for a
/// directory entry; for a file entry it is an error.
fn clear_existing_target(target: &Path, is_dir: bool) -> Result<()> {
    match fs::symlink_metadata(target) {
        Ok(m) if m.is_dir() => {
            if is_dir {
                Ok(())
            } else {
                anyhow::bail!("'{}' is an existing directory", target.display())
            }
        }
        Ok(_) => Ok(fs::remove_file(target)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Before writing a file at `target` through `write_via_temp`: an existing
/// directory there is an error. A file or link is left for the final rename.
fn refuse_existing_dir(target: &Path) -> Result<()> {
    match fs::symlink_metadata(target) {
        Ok(m) if m.is_dir() => anyhow::bail!("'{}' is an existing directory", target.display()),
        _ => Ok(()),
    }
}

/// Write a file entry to a new temporary file next to `target` and rename
/// it into place only if `write` succeeds. On failure the temporary file is
/// removed, so a failed entry leaves no partial output and an existing file
/// at `target` is untouched. The rename replaces a file or symlink at
/// `target` itself and never follows it.
fn write_via_temp<T>(target: &Path, write: impl FnOnce(&Path) -> Result<T>) -> Result<T> {
    let parent = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("'{}' has no parent directory", target.display()))?;
    let tmp = parent.join(temp_archive_name(".resh-extract-"));
    let result = write(&tmp).and_then(|v| {
        fs::rename(&tmp, target)?;
        Ok(v)
    });
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Remove directories `prepare_parent_dirs` created for an entry that then
/// failed, deepest first. Only empty directories can be removed.
fn remove_created_dirs(dirs: &[PathBuf]) {
    for d in dirs.iter().rev() {
        let _ = fs::remove_dir(d);
    }
}

/// Copy `reader` to `writer`, writing at most `limit` bytes. Returns the
/// number of bytes copied, or `None` if the reader had more than `limit`
/// (nothing past the limit is written). This counts what the decoder
/// produces, whatever size the archive records for the entry.
fn copy_limited<R: Read + ?Sized, W: Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    limit: u64,
) -> std::io::Result<Option<u64>> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut copied = 0u64;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => return Ok(Some(copied)),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        match copied.checked_add(n as u64) {
            Some(next) if next <= limit => {
                writer.write_all(&buf[..n])?;
                copied = next;
            }
            _ => return Ok(None),
        }
    }
}

/// Bytes the next entry may still write: the smaller of `max_file_bytes`
/// and what is left of `max_total_bytes` after `written` bytes.
fn entry_byte_budget(opts: &ArchiveExtractOptions, written: u64) -> u64 {
    let file = opts.max_file_bytes.unwrap_or(u64::MAX);
    let total = opts
        .max_total_bytes
        .map_or(u64::MAX, |max| max.saturating_sub(written));
    file.min(total)
}

/// Refuse an entry whose size already breaks a limit before anything is
/// written. For zip this is the size the archive records, which may be
/// wrong, so the copy is limited again by `entry_byte_budget`.
fn check_entry_size(
    opts: &ArchiveExtractOptions,
    path_str: &str,
    size: u64,
    written: u64,
) -> Result<()> {
    if let Some(max_size) = opts.max_file_bytes {
        if size > max_size {
            return Err(fail(
                "max_file_size_exceeded",
                format!(
                    "File '{}' size ({}) exceeds maximum file size ({})",
                    path_str, size, max_size
                ),
            ));
        }
    }
    if let Some(max_total) = opts.max_total_bytes {
        if written.checked_add(size).is_none_or(|t| t > max_total) {
            return Err(fail(
                "max_size_exceeded",
                format!("Total extraction size would exceed maximum ({})", max_total),
            ));
        }
    }
    Ok(())
}

/// The error for an entry that produced more than `entry_byte_budget`
/// allowed after `written` bytes, naming the limit that budget came from.
fn entry_limit_error(opts: &ArchiveExtractOptions, path_str: &str, written: u64) -> anyhow::Error {
    let file = opts.max_file_bytes.unwrap_or(u64::MAX);
    match opts.max_total_bytes {
        Some(max_total) if max_total.saturating_sub(written) < file => fail(
            "max_size_exceeded",
            format!("Total extraction size would exceed maximum ({})", max_total),
        ),
        _ => fail(
            "max_file_size_exceeded",
            format!(
                "File '{}' size (more than {}) exceeds maximum file size ({})",
                path_str, file, file
            ),
        ),
    }
}

/// True if a symlink at `link` (inside `dest`) with `target` resolves, by
/// its text, to a location inside `dest`. Absolute targets are refused.
fn symlink_target_stays_inside(dest: &Path, link: &Path, target: &Path) -> bool {
    if target.as_os_str().is_empty() || target.has_root() {
        return false;
    }
    let parent = match link.parent().and_then(|p| p.strip_prefix(dest).ok()) {
        Some(p) => p,
        None => return false,
    };
    let mut depth: Vec<&std::ffi::OsStr> = Vec::new();
    for c in parent.components().chain(target.components()) {
        match c {
            Component::Normal(n) => depth.push(n),
            Component::CurDir => {}
            Component::ParentDir => {
                if depth.pop().is_none() {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

/// Physical location `p` refers to: canonical for the longest existing
/// prefix, with the missing tail appended.
fn physical_location(p: &Path) -> std::io::Result<PathBuf> {
    match p.canonicalize() {
        Ok(c) => Ok(c),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => match (p.parent(), p.file_name()) {
            (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => {
                Ok(physical_location(parent)?.join(name))
            }
            _ => Err(e),
        },
        Err(e) => Err(e),
    }
}

/// After extraction: every symlink the archive created must resolve inside
/// the destination. Offending links are removed and the extraction fails.
fn verify_symlinks_inside(dest: &Path, links: &[PathBuf]) -> Result<()> {
    if links.is_empty() {
        return Ok(());
    }
    let root = dest.canonicalize()?;
    let mut bad = Vec::new();
    for link in links {
        let inside = fs::read_link(link)
            .ok()
            .and_then(|t| link.parent().map(|p| p.join(t)))
            .and_then(|t| physical_location(&t).ok())
            .map(|t| t.starts_with(&root))
            .unwrap_or(false);
        if !inside {
            let _ = fs::remove_file(link);
            bad.push(link.display().to_string());
        }
    }
    if bad.is_empty() {
        Ok(())
    } else {
        Err(unsafe_entry(
            ARCHIVE_EXTRACT_SYMLINK_REJECTED,
            format!(
                "symlinks resolving outside the destination were removed: {}",
                bad.join(", ")
            ),
        ))
    }
}

/// Source of a hard-link entry: the link name is an archive path, so it is
/// mapped like an entry path and must name an existing regular file inside
/// the destination, reached without symlinks.
fn hard_link_source<R: Read>(
    entry: &tar::Entry<R>,
    dest: &Path,
    opts: &ArchiveExtractOptions,
) -> Result<PathBuf> {
    let name = entry
        .link_name()?
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = apply_strip_components(&name, opts.strip_components);
    if name.is_empty() {
        return Err(unsafe_entry(
            ARCHIVE_EXTRACT_SYMLINK_REJECTED,
            "hard link has no target".to_string(),
        ));
    }
    let src = sanitize_path(&name, dest, opts)?;
    let rel = src.strip_prefix(dest)?;
    let mut cur = dest.to_path_buf();
    for comp in rel.components() {
        cur.push(comp);
        let m = fs::symlink_metadata(&cur).map_err(|_| {
            unsafe_entry(
                ARCHIVE_EXTRACT_SYMLINK_REJECTED,
                format!(
                    "hard link target '{}' does not exist in the destination",
                    name
                ),
            )
        })?;
        if m.file_type().is_symlink() {
            return Err(unsafe_entry(
                ARCHIVE_EXTRACT_SYMLINK_REJECTED,
                format!("hard link target '{}' goes through a symlink", name),
            ));
        }
    }
    if !fs::symlink_metadata(&src)?.is_file() {
        return Err(unsafe_entry(
            ARCHIVE_EXTRACT_SYMLINK_REJECTED,
            format!("hard link target '{}' is not a regular file", name),
        ));
    }
    Ok(src)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_archive_format_detection() {
        assert_eq!(
            ArchiveFormat::detect_from_extension("test.tar").unwrap(),
            ArchiveFormat::Tar
        );
        assert_eq!(
            ArchiveFormat::detect_from_extension("test.tar.gz").unwrap(),
            ArchiveFormat::TarGz
        );
        assert_eq!(
            ArchiveFormat::detect_from_extension("test.zip").unwrap(),
            ArchiveFormat::Zip
        );
        assert_eq!(
            ArchiveFormat::detect_from_extension("test.7z").unwrap(),
            ArchiveFormat::SevenZ
        );
        assert_eq!(
            ArchiveFormat::detect_from_extension("test.gz").unwrap(),
            ArchiveFormat::Raw
        );
        assert_eq!(
            ArchiveFormat::detect_from_extension("test.xz").unwrap(),
            ArchiveFormat::Raw
        );
        assert_eq!(
            ArchiveFormat::detect_from_extension("test.zst").unwrap(),
            ArchiveFormat::Raw
        );

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
        // FUNC-06: no format can be written encrypted.
        assert!(!ArchiveFormat::Zip.supports_password());
        assert!(!ArchiveFormat::SevenZ.supports_password());
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
            deadline: Deadline::none(),
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
        assert_eq!(
            CompressionKind::detect_from_extension("file.gz"),
            CompressionKind::Gzip
        );
        assert_eq!(
            CompressionKind::detect_from_extension("file.xz"),
            CompressionKind::Xz
        );
        assert_eq!(
            CompressionKind::detect_from_extension("file.zst"),
            CompressionKind::Zstd
        );
        assert_eq!(
            CompressionKind::detect_from_extension("file.zstd"),
            CompressionKind::Zstd
        );
        assert_eq!(
            CompressionKind::detect_from_extension("file.tar"),
            CompressionKind::None
        );
        assert_eq!(
            CompressionKind::detect_from_extension("file.txt"),
            CompressionKind::None
        );
    }

    #[test]
    fn test_strip_components() {
        assert_eq!(
            apply_strip_components("a/b/c/file.txt", 0),
            "a/b/c/file.txt"
        );
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
            deadline: Deadline::none(),
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
        let includes =
            build_glob_set(&vec!["*.txt".to_string(), "docs/*".to_string()], "include").unwrap();
        let excludes = build_glob_set(&vec!["*.tmp".to_string()], "exclude").unwrap();

        assert!(should_extract_path("file.txt", &includes, &excludes));
        assert!(should_extract_path("docs/readme.md", &includes, &excludes));
        assert!(!should_extract_path("file.tmp", &includes, &excludes));
        assert!(!should_extract_path("image.jpg", &includes, &excludes));
    }

    #[test]
    fn tgz_extension_implies_gzip() {
        assert_eq!(
            CompressionKind::detect_from_extension("logs.tgz"),
            CompressionKind::Gzip
        );
        assert_eq!(
            CompressionKind::detect_from_extension("logs.TGZ"),
            CompressionKind::Gzip
        );
        assert_eq!(
            CompressionKind::detect_from_extension("logs.txz"),
            CompressionKind::Xz
        );
        let (f, c) =
            resolve_format_and_compression(&ArchiveFormat::Auto, &CompressionKind::Auto, "a.tgz")
                .unwrap();
        assert_eq!((f, c), (ArchiveFormat::TarGz, CompressionKind::Gzip));
        let a = create_args(&[("archive", "a.tgz")]);
        let o = ArchiveListOptions::from_args(&a).unwrap();
        assert_eq!(
            (o.format, o.compression),
            (ArchiveFormat::TarGz, CompressionKind::Gzip)
        );
    }

    fn create_args(pairs: &[(&str, &str)]) -> Args {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn create_from_directory_writes_each_entry_once() -> Result<()> {
        let tmp = TempDir::new()?;
        let base = tmp.path();
        fs::create_dir_all(base.join("data/sub"))?;
        fs::write(base.join("data/a.txt"), "a")?;
        fs::write(base.join("data/sub/b.txt"), "b")?;

        for name in ["out.tar", "out.tgz"] {
            let out = base.join(name);
            let opts = ArchiveCreateOptions::from_args(&create_args(&[
                ("output", out.to_str().unwrap()),
                ("sources", r#"["data"]"#),
                ("base_dir", base.to_str().unwrap()),
            ]))?;
            let resp = create_archive(opts)?;
            assert!(resp.ok, "{:?}", resp.error);

            let file = File::open(&out)?;
            let reader: Box<dyn Read> = if name.ends_with(".tgz") {
                Box::new(GzDecoder::new(file))
            } else {
                Box::new(file)
            };
            let mut names: Vec<String> = tar::Archive::new(reader)
                .entries()?
                .map(|e| {
                    e.unwrap()
                        .path()
                        .unwrap()
                        .to_string_lossy()
                        .trim_end_matches('/')
                        .to_string()
                })
                .collect();
            names.sort();
            assert_eq!(
                names,
                vec!["data", "data/a.txt", "data/sub", "data/sub/b.txt"],
                "{}",
                name
            );
        }
        Ok(())
    }

    #[test]
    fn create_format_is_archive_format_and_format_output_is_report() -> Result<()> {
        let opts = ArchiveCreateOptions::from_args(&create_args(&[
            ("output", "x.zip"),
            ("sources", r#"["a"]"#),
            ("format", "tar"),
            ("format_output", "text"),
        ]))?;
        assert_eq!(opts.format, ArchiveFormat::Tar);
        assert!(matches!(opts.output_format, OutputFormat::Text));
        assert!(
            ArchiveCreateOptions::from_args(&create_args(&[
                ("output", "x.zip"),
                ("sources", r#"["a"]"#),
                ("format", "json"),
            ]))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn help_renders_approved_help() -> Result<()> {
        let h = ArchiveHandle::from_url(&Url::parse("archive://--help")?)?;
        let mut stdin = std::io::empty();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut io = IoStreams::new(&mut stdin, &mut out, &mut err);
        let args = create_args(&[("verb", "create")]);
        h.call("help", &args, &mut io)?;
        let text = String::from_utf8(out)?;
        assert!(
            text.starts_with("Handle: archive\nVerb: create\n"),
            "{}",
            text
        );
        Ok(())
    }
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

// Help functionality
fn should_show_help(verb: &str, args: &Args) -> bool {
    verb == "--help"
        || verb == "-h"
        || verb == "help"
        || args.get("help").is_some()
        || args.get("h").is_some()
}

// SEC-01: extraction must never write outside the destination. Each test
// builds its archive in a fresh temporary sandbox laid out as
//   <sandbox>/dest            extraction destination
//   <sandbox>/outside/keep.txt  sentinel that must stay unchanged
// so even a regression could only touch the sandbox.
#[cfg(test)]
mod extract_safety_tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, symlink};
    use tar::{Builder, EntryType, Header};
    use tempfile::TempDir;

    struct Sandbox {
        _tmp: TempDir,
        root: PathBuf,
        dest: PathBuf,
        outside: PathBuf,
    }

    fn sandbox() -> Sandbox {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().to_path_buf();
        let dest = root.join("dest");
        let outside = root.join("outside");
        fs::create_dir_all(&dest).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep.txt"), b"sentinel").unwrap();
        Sandbox {
            _tmp: tmp,
            root,
            dest,
            outside,
        }
    }

    impl Sandbox {
        fn assert_outside_intact(&self) {
            let names: Vec<_> = fs::read_dir(&self.outside)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert_eq!(names, vec!["keep.txt"], "outside dir was modified");
            assert_eq!(
                fs::read(self.outside.join("keep.txt")).unwrap(),
                b"sentinel"
            );
            // nothing may appear next to dest either
            let mut top: Vec<_> = fs::read_dir(&self.root)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|n| !n.ends_with(".tar") && !n.ends_with(".zip") && !n.ends_with(".gz"))
                .collect();
            top.sort();
            assert_eq!(top, vec!["dest", "outside"]);
        }
    }

    /// One tar entry; names and link names are written raw so that unsafe
    /// values that `tar::Builder` would refuse can still be produced.
    enum E<'a> {
        File(&'a str, &'a [u8]),
        Dir(&'a str),
        Symlink(&'a str, &'a str),
        HardLink(&'a str, &'a str),
        Device(&'a str),
    }

    fn raw_header(name: &str, kind: EntryType, link: &str, size: u64) -> Header {
        let mut h = Header::new_gnu();
        {
            let old = h.as_old_mut();
            assert!(name.len() < 100 && link.len() < 100);
            old.name = [0; 100];
            old.name[..name.len()].copy_from_slice(name.as_bytes());
            old.linkname = [0; 100];
            old.linkname[..link.len()].copy_from_slice(link.as_bytes());
        }
        h.set_entry_type(kind);
        h.set_size(size);
        h.set_mode(if kind == EntryType::Directory {
            0o755
        } else {
            0o644
        });
        h.set_mtime(1);
        h.set_cksum();
        h
    }

    fn write_tar(path: &Path, entries: &[E]) {
        let mut b = Builder::new(File::create(path).unwrap());
        for e in entries {
            match e {
                E::File(n, data) => b
                    .append(
                        &raw_header(n, EntryType::Regular, "", data.len() as u64),
                        *data,
                    )
                    .unwrap(),
                E::Dir(n) => b
                    .append(&raw_header(n, EntryType::Directory, "", 0), &[][..])
                    .unwrap(),
                E::Symlink(n, t) => b
                    .append(&raw_header(n, EntryType::Symlink, t, 0), &[][..])
                    .unwrap(),
                E::HardLink(n, t) => b
                    .append(&raw_header(n, EntryType::Link, t, 0), &[][..])
                    .unwrap(),
                E::Device(n) => b
                    .append(&raw_header(n, EntryType::Char, "", 0), &[][..])
                    .unwrap(),
            }
        }
        b.finish().unwrap();
    }

    fn opts(archive: &Path, dest: &Path, format: ArchiveFormat) -> ArchiveExtractOptions {
        ArchiveExtractOptions {
            archive: archive.to_string_lossy().to_string(),
            destination: dest.to_string_lossy().to_string(),
            format,
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
            deadline: Deadline::none(),
            format_output: OutputFormat::Json,
        }
    }

    fn extract_tar(
        sb: &Sandbox,
        entries: &[E],
        tweak: impl Fn(&mut ArchiveExtractOptions),
    ) -> ArchiveExtractResponse {
        let archive = sb.root.join("t.tar");
        write_tar(&archive, entries);
        let mut o = opts(&archive, &sb.dest, ArchiveFormat::Tar);
        tweak(&mut o);
        let r = extract_archive(o).unwrap();
        fs::remove_file(&archive).unwrap();
        r
    }

    fn assert_rejected(r: &ArchiveExtractResponse, code: &str) {
        assert!(!r.ok, "unsafe archive reported ok: {:?}", r.warnings);
        let (c, msg) = r.error.clone().unwrap();
        assert_eq!(c, code, "{msg}");
        assert!(msg.contains("extraction stopped"), "{msg}");
        assert!(
            r.summary.is_none() && r.manifest.is_none(),
            "no success summary on failure"
        );
    }

    #[test]
    fn normal_archive_with_nested_dirs_extracts() {
        let sb = sandbox();
        let r = extract_tar(
            &sb,
            &[
                E::Dir("./"),
                E::Dir("dir/"),
                E::File("a.txt", b"a"),
                E::File("./rel.txt", b"r"),
                E::File("dir/sub/deep/b.txt", b"b"),
                E::Symlink("dir/link", "sub/deep/b.txt"),
                E::HardLink("hard.txt", "a.txt"),
            ],
            |_| {},
        );
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(fs::read(sb.dest.join("a.txt")).unwrap(), b"a");
        assert_eq!(fs::read(sb.dest.join("rel.txt")).unwrap(), b"r");
        assert_eq!(fs::read(sb.dest.join("dir/sub/deep/b.txt")).unwrap(), b"b");
        assert_eq!(fs::read(sb.dest.join("dir/link")).unwrap(), b"b");
        assert_eq!(
            fs::metadata(sb.dest.join("hard.txt")).unwrap().ino(),
            fs::metadata(sb.dest.join("a.txt")).unwrap().ino()
        );
        assert_eq!(r.summary.as_ref().unwrap().entries_extracted, 6);
        sb.assert_outside_intact();
    }

    #[test]
    fn parent_traversal_is_rejected() {
        for name in ["../outside/evil.txt", "a/../../outside/evil.txt", ".."] {
            let sb = sandbox();
            let r = extract_tar(&sb, &[E::File(name, b"x")], |_| {});
            assert_rejected(&r, ARCHIVE_EXTRACT_PATH_TRAVERSAL_DETECTED);
            sb.assert_outside_intact();
        }
        // allow_parent_traversal=true still cannot climb above dest
        let sb = sandbox();
        let r = extract_tar(&sb, &[E::File("../outside/evil.txt", b"x")], |o| {
            o.allow_parent_traversal = true
        });
        assert_rejected(&r, ARCHIVE_EXTRACT_PATH_TRAVERSAL_DETECTED);
        sb.assert_outside_intact();
        let r = extract_tar(&sb, &[E::File("a/../ok.txt", b"x")], |o| {
            o.allow_parent_traversal = true
        });
        assert!(r.ok, "{:?}", r.error);
        assert!(sb.dest.join("ok.txt").is_file());
    }

    #[test]
    fn absolute_paths_are_rejected_or_rerooted() {
        let sb = sandbox();
        let abs = format!("{}/evil.txt", sb.outside.display());
        let r = extract_tar(&sb, &[E::File(&abs, b"x")], |_| {});
        assert_rejected(&r, ARCHIVE_EXTRACT_ABSOLUTE_PATH_REJECTED);
        sb.assert_outside_intact();

        // allow_absolute_paths=true re-roots under dest; never writes there
        let r = extract_tar(&sb, &[E::File(&abs, b"x")], |o| {
            o.allow_absolute_paths = true
        });
        assert!(r.ok, "{:?}", r.error);
        let rerooted = sb.dest.join(abs.trim_start_matches('/'));
        assert_eq!(fs::read(rerooted).unwrap(), b"x");
        sb.assert_outside_intact();
    }

    /// The reproduction from the verification report: `lnk -> ..` followed
    /// by `lnk/escaped_via_symlink.txt`.
    #[test]
    fn archive_symlink_cannot_redirect_later_entries() {
        let sb = sandbox();
        let r = extract_tar(
            &sb,
            &[
                E::Symlink("lnk", ".."),
                E::File("lnk/escaped_via_symlink.txt", b"x"),
            ],
            |_| {},
        );
        assert_rejected(&r, ARCHIVE_EXTRACT_SYMLINK_REJECTED);
        assert!(!sb.root.join("escaped_via_symlink.txt").exists());
        sb.assert_outside_intact();

        for target in [
            "../outside",
            "../outside/keep.txt",
            "/etc",
            "a/../../outside",
            "",
        ] {
            let sb = sandbox();
            let r = extract_tar(
                &sb,
                &[E::Symlink("lnk", target), E::File("lnk/keep.txt", b"pwned")],
                |_| {},
            );
            assert_rejected(&r, ARCHIVE_EXTRACT_SYMLINK_REJECTED);
            assert!(
                fs::symlink_metadata(sb.dest.join("lnk")).is_err(),
                "{target}"
            );
            sb.assert_outside_intact();
        }
    }

    #[test]
    fn in_destination_symlink_is_never_written_through() {
        let sb = sandbox();
        let r = extract_tar(
            &sb,
            &[
                E::Dir("sub/"),
                E::Symlink("inner", "sub"),
                E::File("inner/x.txt", b"x"),
            ],
            |_| {},
        );
        assert_rejected(&r, ARCHIVE_EXTRACT_SYMLINK_REJECTED);
        assert!(!sb.dest.join("sub/x.txt").exists());
        sb.assert_outside_intact();
    }

    #[test]
    fn symlink_chain_escaping_destination_is_removed() {
        // sub/x -> ..  (dest) and y -> sub/x/..  (lexically "sub", but
        // physically the parent of dest)
        let sb = sandbox();
        let r = extract_tar(
            &sb,
            &[
                E::Dir("sub/"),
                E::Symlink("sub/x", ".."),
                E::Symlink("y", "sub/x/.."),
            ],
            |_| {},
        );
        assert!(!r.ok);
        assert_eq!(
            r.error.as_ref().unwrap().0,
            ARCHIVE_EXTRACT_SYMLINK_REJECTED
        );
        assert!(
            fs::symlink_metadata(sb.dest.join("y")).is_err(),
            "escaping link left behind"
        );
        sb.assert_outside_intact();
    }

    #[test]
    fn preexisting_destination_symlink_is_not_followed() {
        // parent component planted in dest
        let sb = sandbox();
        symlink(&sb.outside, sb.dest.join("pre")).unwrap();
        let r = extract_tar(
            &sb,
            &[
                E::File("pre/keep.txt", b"pwned"),
                E::File("pre/new.txt", b"x"),
            ],
            |o| o.overwrite = true,
        );
        assert_rejected(&r, ARCHIVE_EXTRACT_SYMLINK_REJECTED);
        sb.assert_outside_intact();

        // final component planted in dest, overwrite=true: replaced, not followed
        let sb = sandbox();
        symlink(sb.outside.join("keep.txt"), sb.dest.join("target.txt")).unwrap();
        let r = extract_tar(&sb, &[E::File("target.txt", b"new")], |o| {
            o.overwrite = true
        });
        assert!(r.ok, "{:?}", r.error);
        assert!(
            !fs::symlink_metadata(sb.dest.join("target.txt"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(sb.dest.join("target.txt")).unwrap(), b"new");
        sb.assert_outside_intact();

        // final component is a dangling planted link, overwrite=false: skipped
        let sb = sandbox();
        symlink(sb.outside.join("new.txt"), sb.dest.join("dangling")).unwrap();
        let r = extract_tar(&sb, &[E::File("dangling", b"x")], |_| {});
        assert!(r.ok);
        assert_eq!(r.summary.as_ref().unwrap().entries_skipped, 1);
        sb.assert_outside_intact();

        // directory entry over a planted dir link must not chmod the target
        let sb = sandbox();
        symlink(&sb.outside, sb.dest.join("d")).unwrap();
        let before = fs::metadata(&sb.outside).unwrap().mode();
        let r = extract_tar(&sb, &[E::Dir("d/")], |o| o.overwrite = true);
        assert!(r.ok, "{:?}", r.error);
        assert!(fs::symlink_metadata(sb.dest.join("d")).unwrap().is_dir());
        assert_eq!(fs::metadata(&sb.outside).unwrap().mode(), before);
        sb.assert_outside_intact();
    }

    #[test]
    fn hard_link_targets_must_stay_inside() {
        let abs = |sb: &Sandbox| format!("{}/keep.txt", sb.outside.display());
        for target in ["../outside/keep.txt", "missing.txt", "", "dir"] {
            let sb = sandbox();
            let r = extract_tar(&sb, &[E::Dir("dir/"), E::HardLink("hl", target)], |_| {});
            assert!(!r.ok, "{target:?}");
            assert!(fs::symlink_metadata(sb.dest.join("hl")).is_err());
            sb.assert_outside_intact();
        }
        let sb = sandbox();
        let a = abs(&sb);
        let r = extract_tar(&sb, &[E::HardLink("hl", &a)], |_| {});
        assert_rejected(&r, ARCHIVE_EXTRACT_ABSOLUTE_PATH_REJECTED);
        let r = extract_tar(&sb, &[E::HardLink("hl", &a)], |o| {
            o.allow_absolute_paths = true
        });
        assert!(
            !r.ok,
            "re-rooted target does not exist, so it must not link outside"
        );
        assert_eq!(
            fs::metadata(sb.outside.join("keep.txt")).unwrap().nlink(),
            1
        );
        sb.assert_outside_intact();

        // hard link through an in-dest symlink
        let sb = sandbox();
        let r = extract_tar(
            &sb,
            &[
                E::Symlink("s", "."),
                E::File("f", b"f"),
                E::HardLink("hl", "s/f"),
            ],
            |_| {},
        );
        assert_rejected(&r, ARCHIVE_EXTRACT_SYMLINK_REJECTED);
        sb.assert_outside_intact();
    }

    #[test]
    fn device_nodes_are_rejected() {
        let sb = sandbox();
        let r = extract_tar(&sb, &[E::Device("null")], |_| {});
        assert_rejected(&r, ARCHIVE_EXTRACT_UNSUPPORTED_ENTRY_TYPE);
        assert!(fs::symlink_metadata(sb.dest.join("null")).is_err());
    }

    #[test]
    fn allow_symlinks_false_still_skips_links() {
        let sb = sandbox();
        let r = extract_tar(
            &sb,
            &[E::Symlink("lnk", "../outside"), E::File("a", b"a")],
            |o| o.allow_symlinks = false,
        );
        assert!(r.ok, "{:?}", r.error);
        assert!(fs::symlink_metadata(sb.dest.join("lnk")).is_err());
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("allow_symlinks=false"))
        );
        sb.assert_outside_intact();
    }

    fn extract_args(sb: &Sandbox, archive: &Path, extra: &[(&str, &str)]) -> Args {
        let mut a = Args::new();
        a.insert("archive".into(), archive.to_string_lossy().into_owned());
        a.insert("destination".into(), sb.dest.to_string_lossy().into_owned());
        for (k, v) in extra {
            a.insert(k.to_string(), v.to_string());
        }
        a
    }

    /// SEC-08: `allow_symlinks=no` used to parse as true. Every false
    /// spelling now disables link extraction end to end; true spellings keep
    /// the (contained) default.
    #[test]
    fn allow_symlinks_false_spellings_are_honored() {
        for v in ["false", "no", "0", "off", "NO", "Off"] {
            let sb = sandbox();
            let archive = sb.root.join("t.tar");
            write_tar(&archive, &[E::File("a", b"a"), E::Symlink("lnk", "a")]);
            let o = ArchiveExtractOptions::from_args(&extract_args(
                &sb,
                &archive,
                &[("allow_symlinks", v)],
            ))
            .unwrap();
            assert!(!o.allow_symlinks, "allow_symlinks={v} parsed as true");
            let r = extract_archive(o).unwrap();
            assert!(r.ok, "{:?}", r.error);
            assert!(
                fs::symlink_metadata(sb.dest.join("lnk")).is_err(),
                "allow_symlinks={v} still extracted a link"
            );
            assert!(sb.dest.join("a").is_file());
        }
        for v in ["true", "yes", "1", "on"] {
            let sb = sandbox();
            let archive = sb.root.join("t.tar");
            write_tar(&archive, &[E::File("a", b"a")]);
            assert!(
                ArchiveExtractOptions::from_args(&extract_args(
                    &sb,
                    &archive,
                    &[("allow_symlinks", v)]
                ))
                .unwrap()
                .allow_symlinks
            );
        }
    }

    /// SEC-08: malformed security booleans fail explicitly instead of
    /// silently taking a default, and alternate true spellings are honored.
    #[test]
    fn malformed_security_booleans_are_rejected() {
        let sb = sandbox();
        let archive = sb.root.join("t.tar");
        write_tar(&archive, &[E::File("a", b"a")]);
        for key in [
            "allow_symlinks",
            "allow_absolute_paths",
            "allow_parent_traversal",
            "overwrite",
            "follow_symlinks",
        ] {
            for bad in ["maybe", "", "2", "y"] {
                let err =
                    ArchiveExtractOptions::from_args(&extract_args(&sb, &archive, &[(key, bad)]))
                        .expect_err(&format!("{key}={bad:?} accepted"));
                assert!(err.to_string().contains(key), "{err}");
            }
        }
        let o =
            ArchiveExtractOptions::from_args(&extract_args(&sb, &archive, &[("overwrite", "yes")]))
                .unwrap();
        assert!(o.overwrite, "overwrite=yes was ignored");
        assert!(
            fs::read_dir(&sb.dest).unwrap().next().is_none(),
            "parsing extracted something"
        );
        sb.assert_outside_intact();
    }

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let mut z = ZipWriter::new(File::create(path).unwrap());
        for (name, data) in entries {
            if name.ends_with('/') {
                z.add_directory(*name, FileOptions::default()).unwrap();
            } else {
                z.start_file(*name, FileOptions::default()).unwrap();
                z.write_all(data).unwrap();
            }
        }
        z.finish().unwrap();
    }

    fn extract_zip(
        sb: &Sandbox,
        entries: &[(&str, &[u8])],
        tweak: impl Fn(&mut ArchiveExtractOptions),
    ) -> ArchiveExtractResponse {
        let archive = sb.root.join("t.zip");
        write_zip(&archive, entries);
        let mut o = opts(&archive, &sb.dest, ArchiveFormat::Zip);
        tweak(&mut o);
        let r = extract_archive(o).unwrap();
        fs::remove_file(&archive).unwrap();
        r
    }

    #[test]
    fn zip_extraction_is_contained() {
        let sb = sandbox();
        let r = extract_zip(
            &sb,
            &[("d/", b""), ("d/e/f.txt", b"f"), ("top.txt", b"t")],
            |_| {},
        );
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(fs::read(sb.dest.join("d/e/f.txt")).unwrap(), b"f");

        let r = extract_zip(&sb, &[("../outside/evil.txt", b"x")], |_| {});
        assert_rejected(&r, ARCHIVE_EXTRACT_PATH_TRAVERSAL_DETECTED);
        let abs = format!("{}/evil.txt", sb.outside.display());
        let r = extract_zip(&sb, &[(abs.as_str(), b"x")], |_| {});
        assert_rejected(&r, ARCHIVE_EXTRACT_ABSOLUTE_PATH_REJECTED);
        sb.assert_outside_intact();

        symlink(&sb.outside, sb.dest.join("pre")).unwrap();
        let r = extract_zip(&sb, &[("pre/evil.txt", b"x")], |o| o.overwrite = true);
        assert_rejected(&r, ARCHIVE_EXTRACT_SYMLINK_REJECTED);
        symlink(sb.outside.join("keep.txt"), sb.dest.join("leaf.txt")).unwrap();
        let r = extract_zip(&sb, &[("leaf.txt", b"new")], |o| o.overwrite = true);
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(fs::read(sb.dest.join("leaf.txt")).unwrap(), b"new");
        sb.assert_outside_intact();
    }

    #[test]
    fn raw_decompression_does_not_follow_planted_link() {
        let sb = sandbox();
        let gz = sb.root.join("data.gz");
        let mut enc = flate2::write::GzEncoder::new(
            File::create(&gz).unwrap(),
            flate2::Compression::default(),
        );
        enc.write_all(b"payload").unwrap();
        enc.finish().unwrap();
        symlink(sb.outside.join("keep.txt"), sb.dest.join("data")).unwrap();
        let mut o = opts(&gz, &sb.dest, ArchiveFormat::Raw);
        o.compression = CompressionKind::Gzip;
        o.overwrite = true;
        let r = extract_archive(o).unwrap();
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(fs::read(sb.dest.join("data")).unwrap(), b"payload");
        fs::remove_file(&gz).unwrap();
        sb.assert_outside_intact();
    }

    #[test]
    fn sanitize_path_codes() {
        let sb = sandbox();
        let o = opts(Path::new("x.tar"), &sb.dest, ArchiveFormat::Tar);
        let code = |p: &str| {
            sanitize_path(p, &sb.dest, &o)
                .unwrap_err()
                .downcast_ref::<UnsafeEntryError>()
                .unwrap()
                .code
        };
        assert_eq!(code("/etc/passwd"), ARCHIVE_EXTRACT_ABSOLUTE_PATH_REJECTED);
        assert_eq!(code("../x"), ARCHIVE_EXTRACT_PATH_TRAVERSAL_DETECTED);
        assert_eq!(
            sanitize_path("a/./b", &sb.dest, &o).unwrap(),
            sb.dest.join("a/b")
        );
    }
}

// FUNC-06: a password request never yields an unencrypted archive.
// Stage 4: add and remove rewrite tar archives. The result must be a
// complete stream (zstd was truncated), existing entries must keep their
// headers (add used to rebuild them with mode 0, uid 0, mtime 0, and turn
// symlinks into empty files), and a private archive must stay private.
#[cfg(test)]
mod zstd_rewrite_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[derive(Debug, PartialEq)]
    struct Meta {
        path: String,
        mode: u32,
        uid: u64,
        mtime: u64,
        kind: String,
        link: Option<String>,
    }

    fn reader(path: &Path) -> Box<dyn Read> {
        let f = File::open(path).unwrap();
        let name = path.to_string_lossy();
        if name.ends_with(".zst") {
            Box::new(ZstdDecoder::new(f).unwrap())
        } else if name.ends_with(".gz") {
            Box::new(GzDecoder::new(f))
        } else {
            Box::new(f)
        }
    }

    fn entries(path: &Path) -> Vec<Meta> {
        let mut ar = tar::Archive::new(reader(path));
        let mut v: Vec<Meta> = ar
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                let h = e.header();
                Meta {
                    path: e.path().unwrap().display().to_string(),
                    mode: h.mode().unwrap(),
                    uid: h.uid().unwrap(),
                    mtime: h.mtime().unwrap(),
                    kind: format!("{:?}", h.entry_type()),
                    link: e.link_name().unwrap().map(|l| l.display().to_string()),
                }
            })
            .collect();
        v.sort_by(|a, b| a.path.cmp(&b.path));
        v
    }

    fn call(verb: &str, kv: &[(&str, String)]) -> Status {
        let h = ArchiveHandle::from_url(&Url::parse("archive://").unwrap()).unwrap();
        let args: Args = kv.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
        let mut io = IoStreams {
            stdin: &mut i,
            stdout: &mut o,
            stderr: &mut e,
        };
        let st = h.call(verb, &args, &mut io).unwrap();
        assert!(
            st.ok,
            "{verb}: {} {}",
            String::from_utf8_lossy(&o),
            String::from_utf8_lossy(&e)
        );
        st
    }

    fn build(path: &Path) {
        let f = File::create(path).unwrap();
        let w: Box<dyn Write> = if path.to_string_lossy().ends_with(".zst") {
            Box::new(ZstdEncoder::new(f, 3).unwrap().auto_finish())
        } else if path.to_string_lossy().ends_with(".gz") {
            Box::new(GzEncoder::new(f, flate2::Compression::default()))
        } else {
            Box::new(f)
        };
        let mut b = tar::Builder::new(w);
        let mut h = tar::Header::new_gnu();
        h.set_size(4);
        h.set_mode(0o755);
        h.set_uid(1234);
        h.set_mtime(1_700_000_000);
        h.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut h, "run.sh", &b"#!x\n"[..]).unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_size(3);
        h.set_mode(0o640);
        h.set_uid(1234);
        h.set_mtime(1_700_000_001);
        b.append_data(&mut h, "two.txt", &b"two"[..]).unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        h.set_mode(0o777);
        h.set_uid(1234);
        h.set_mtime(1_700_000_002);
        b.append_link(&mut h, "link", "run.sh").unwrap();
        b.into_inner().unwrap().flush().unwrap();
    }

    #[test]
    fn add_and_remove_keep_tar_entries_intact() {
        for name in ["a.tar", "a.tar.gz", "a.tar.zst"] {
            let tmp = TempDir::new().unwrap();
            let archive = tmp.path().join(name);
            build(&archive);
            std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o600)).unwrap();
            let before = entries(&archive);
            assert_eq!(before.len(), 3);

            let extra = tmp.path().join("three.txt");
            std::fs::write(&extra, "three").unwrap();
            let a = archive.display().to_string();
            call(
                "add",
                &[
                    ("archive", a.clone()),
                    ("inputs", format!("[\"{}\"]", extra.display())),
                    ("base_dir", tmp.path().display().to_string()),
                ],
            );
            let after_add = entries(&archive);
            assert_eq!(after_add.len(), 4, "{name}");
            for m in &before {
                assert!(
                    after_add.contains(m),
                    "{name}: add changed {m:?}; now {after_add:?}"
                );
            }
            assert_eq!(
                std::fs::metadata(&archive).unwrap().permissions().mode() & 0o777,
                0o600,
                "{name}"
            );

            call(
                "remove",
                &[
                    ("archive", a.clone()),
                    ("paths", "[\"three.txt\"]".to_string()),
                ],
            );
            assert_eq!(
                entries(&archive),
                before,
                "{name}: remove changed the kept entries"
            );
            assert_eq!(
                std::fs::metadata(&archive).unwrap().permissions().mode() & 0o777,
                0o600,
                "{name}"
            );
            // No temporary file is left behind.
            let left: Vec<_> = std::fs::read_dir(tmp.path())
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|n| n.contains("tmp"))
                .collect();
            assert!(left.is_empty(), "{name}: {left:?}");
        }
    }
}

// RC-09: ZIP `add` rewrote existing entries with default options, losing
// their Unix mode and modification time.
#[cfg(test)]
mod zip_add_metadata_tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn zip_add_keeps_existing_entry_mode_and_time() {
        let tmp = TempDir::new().unwrap();
        let archive = tmp.path().join("a.zip");
        let when = zip::DateTime::from_date_and_time(2020, 1, 2, 3, 4, 6).unwrap();
        {
            let mut z = ZipWriter::new(File::create(&archive).unwrap());
            z.start_file(
                "run.sh",
                FileOptions::default()
                    .unix_permissions(0o755)
                    .last_modified_time(when),
            )
            .unwrap();
            z.write_all(b"#!x").unwrap();
            z.finish().unwrap();
        }
        let extra = tmp.path().join("n.txt");
        std::fs::write(&extra, "n").unwrap();
        let h = ArchiveHandle::from_url(&Url::parse("archive://").unwrap()).unwrap();
        let args: Args = [
            ("archive".to_string(), archive.display().to_string()),
            ("inputs".to_string(), format!("[\"{}\"]", extra.display())),
            ("base_dir".to_string(), tmp.path().display().to_string()),
        ]
        .into_iter()
        .collect();
        let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
        let mut io = IoStreams {
            stdin: &mut i,
            stdout: &mut o,
            stderr: &mut e,
        };
        assert!(
            h.call("add", &args, &mut io).unwrap().ok,
            "{}",
            String::from_utf8_lossy(&e)
        );
        let mut z = ZipArchive::new(File::open(&archive).unwrap()).unwrap();
        assert_eq!(z.len(), 2);
        let f = z.by_name("run.sh").unwrap();
        assert_eq!(f.unix_mode().map(|m| m & 0o777), Some(0o755));
        let t = f.last_modified();
        assert_eq!(
            (t.year(), t.month(), t.day(), t.hour(), t.minute()),
            (2020, 1, 2, 3, 4)
        );
    }
}

// `add backup_suffix=` must not write through a symlink planted at the
// backup name (v1.0.3-beta, release gate RB-2).
#[cfg(test)]
mod backup_symlink_tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::TempDir;

    fn make_archive(dir: &Path, name: &str) -> PathBuf {
        let archive = dir.join(name);
        let src = dir.join("old.txt");
        std::fs::write(&src, "old").unwrap();
        if name.ends_with(".zip") {
            let mut z = ZipWriter::new(File::create(&archive).unwrap());
            z.start_file("old.txt", FileOptions::default()).unwrap();
            z.write_all(b"old").unwrap();
            z.finish().unwrap();
        } else {
            let mut b = tar::Builder::new(File::create(&archive).unwrap());
            b.append_path_with_name(&src, "old.txt").unwrap();
            b.finish().unwrap();
        }
        archive
    }

    fn add_with_backup(dir: &Path, archive: &Path) -> bool {
        let extra = dir.join("n.txt");
        std::fs::write(&extra, "n").unwrap();
        let h = ArchiveHandle::from_url(&Url::parse("archive://").unwrap()).unwrap();
        let args: Args = [
            ("archive".to_string(), archive.display().to_string()),
            ("inputs".to_string(), format!("[\"{}\"]", extra.display())),
            ("base_dir".to_string(), dir.display().to_string()),
            ("backup_suffix".to_string(), "bak".to_string()),
        ]
        .into_iter()
        .collect();
        let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
        let mut io = IoStreams {
            stdin: &mut i,
            stdout: &mut o,
            stderr: &mut e,
        };
        h.call("add", &args, &mut io).map(|s| s.ok).unwrap_or(false)
    }

    #[test]
    fn add_backup_refuses_planted_symlink() {
        for name in ["a.zip", "a.tar"] {
            let tmp = TempDir::new().unwrap();
            let archive = make_archive(tmp.path(), name);
            let victim = tmp.path().join("victim");
            std::fs::write(&victim, "victim").unwrap();
            std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
            symlink(&victim, tmp.path().join(format!("{}.bak", name))).unwrap();

            assert!(!add_with_backup(tmp.path(), &archive), "{}", name);
            assert_eq!(
                std::fs::read_to_string(&victim).unwrap(),
                "victim",
                "{}",
                name
            );
            let mode = std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}", name);
        }
    }

    #[test]
    fn add_backup_still_writes_a_regular_backup() {
        for name in ["a.zip", "a.tar"] {
            let tmp = TempDir::new().unwrap();
            let archive = make_archive(tmp.path(), name);
            let before = std::fs::read(&archive).unwrap();

            assert!(add_with_backup(tmp.path(), &archive), "{}", name);
            let bak = tmp.path().join(format!("{}.bak", name));
            assert!(
                !std::fs::symlink_metadata(&bak)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(std::fs::read(&bak).unwrap(), before, "{}", name);
        }
    }
}

#[cfg(test)]
mod zip_password_tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create(dir: &Path, extra: &[(&str, &str)]) -> (Status, String, String) {
        let h = ArchiveHandle::from_url(&Url::parse("archive://").unwrap()).unwrap();
        let src = dir.join("secret.txt");
        fs::write(&src, b"top secret payload").unwrap();
        let mut args: Args = [
            ("output", dir.join("out.zip").to_string_lossy().into_owned()),
            ("sources", format!("[\"{}\"]", src.display())),
            ("format", "zip".to_string()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        for (k, v) in extra {
            args.insert(k.to_string(), v.to_string());
        }
        let mut i: &[u8] = &[];
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let status = {
            let mut io = IoStreams {
                stdin: &mut i,
                stdout: &mut o,
                stderr: &mut e,
            };
            h.call("create", &args, &mut io).unwrap()
        };
        (
            status,
            String::from_utf8(o).unwrap(),
            String::from_utf8(e).unwrap(),
        )
    }

    #[test]
    fn plain_zip_creation_still_works() {
        let dir = TempDir::new().unwrap();
        let (status, out, _) = create(dir.path(), &[]);
        assert!(status.ok, "{out}");
        let mut zip =
            zip::ZipArchive::new(fs::File::open(dir.path().join("out.zip")).unwrap()).unwrap();
        assert_eq!(zip.len(), 1);
        let mut body = String::new();
        std::io::Read::read_to_string(&mut zip.by_index(0).unwrap(), &mut body).unwrap();
        assert_eq!(body, "top secret payload");
    }

    #[test]
    fn password_request_is_rejected_and_writes_nothing() {
        for pw in ["hunter2", ""] {
            let dir = TempDir::new().unwrap();
            let (status, out, err) = create(dir.path(), &[("password", pw)]);
            assert!(!status.ok, "password={pw:?} must fail: {out}");
            assert_ne!(status.exit_code(), 0);
            let text = format!(
                "{}{}{}",
                out,
                err,
                status.reason.clone().unwrap_or_default()
            );
            assert!(
                text.contains(ARCHIVE_CREATE_PASSWORD_NOT_SUPPORTED),
                "{text}"
            );
            assert!(
                !dir.path().join("out.zip").exists(),
                "no plaintext fallback archive"
            );
            assert!(!text.contains("hunter2"), "password must not be echoed");
        }
    }
}

// v1.0.5-beta: max_file_bytes and max_total_bytes are enforced on the bytes
// an entry actually produces, not on the size the archive records for it.
// A failed entry leaves neither a partial file nor a damaged existing file.
#[cfg(test)]
mod extract_limit_tests {
    use super::*;
    use std::fs;
    use std::io::Cursor;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    struct Sandbox {
        _tmp: TempDir,
        root: PathBuf,
        dest: PathBuf,
        outside: PathBuf,
    }

    fn sandbox() -> Sandbox {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().to_path_buf();
        let dest = root.join("dest");
        let outside = root.join("outside");
        fs::create_dir_all(&dest).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep.txt"), b"sentinel").unwrap();
        Sandbox {
            _tmp: tmp,
            root,
            dest,
            outside,
        }
    }

    impl Sandbox {
        /// Names in the destination, recursively, sorted.
        fn dest_tree(&self) -> Vec<String> {
            let mut out: Vec<String> = WalkDir::new(&self.dest)
                .min_depth(1)
                .into_iter()
                .map(|e| {
                    e.unwrap()
                        .path()
                        .strip_prefix(&self.dest)
                        .unwrap()
                        .display()
                        .to_string()
                })
                .collect();
            out.sort();
            out
        }

        fn assert_outside_intact(&self) {
            assert_eq!(
                fs::read(self.outside.join("keep.txt")).unwrap(),
                b"sentinel"
            );
            assert_eq!(fs::read_dir(&self.outside).unwrap().count(), 1);
        }
    }

    fn opts(archive: &Path, dest: &Path, format: ArchiveFormat) -> ArchiveExtractOptions {
        ArchiveExtractOptions {
            archive: archive.to_string_lossy().to_string(),
            destination: dest.to_string_lossy().to_string(),
            format,
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
            deadline: Deadline::none(),
            format_output: OutputFormat::Json,
        }
    }

    fn zip_bytes(entries: &[(&str, &[u8], CompressionMethod)]) -> Vec<u8> {
        let mut z = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data, method) in entries {
            z.start_file(*name, FileOptions::default().compression_method(*method))
                .unwrap();
            z.write_all(data).unwrap();
        }
        z.finish().unwrap().into_inner()
    }

    fn u16_at(b: &[u8], at: usize) -> usize {
        u16::from_le_bytes([b[at], b[at + 1]]) as usize
    }

    fn u32_at(b: &[u8], at: usize) -> usize {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize
    }

    /// Overwrite the uncompressed size recorded for entry `index`, in both
    /// its central directory record and its local header. The data and CRC
    /// are left as they are, so the entry decodes to more (or fewer) bytes
    /// than it claims.
    fn set_recorded_size(zip: &mut [u8], index: usize, size: u32) {
        let eocd = zip.len() - 22;
        assert_eq!(&zip[eocd..eocd + 4], b"PK\x05\x06");
        let mut p = u32_at(zip, eocd + 16);
        for i in 0..u16_at(zip, eocd + 10) {
            assert_eq!(&zip[p..p + 4], b"PK\x01\x02");
            let local = u32_at(zip, p + 42);
            if i == index {
                zip[p + 24..p + 28].copy_from_slice(&size.to_le_bytes());
                zip[local + 22..local + 26].copy_from_slice(&size.to_le_bytes());
            }
            p += 46 + u16_at(zip, p + 28) + u16_at(zip, p + 30) + u16_at(zip, p + 32);
        }
    }

    fn extract_zip_bytes(
        sb: &Sandbox,
        zip: &[u8],
        tweak: impl Fn(&mut ArchiveExtractOptions),
    ) -> ArchiveExtractResponse {
        let archive = sb.root.join("t.zip");
        fs::write(&archive, zip).unwrap();
        let mut o = opts(&archive, &sb.dest, ArchiveFormat::Zip);
        tweak(&mut o);
        extract_archive(o).unwrap()
    }

    fn assert_limit_refused(r: &ArchiveExtractResponse, what: &str) {
        assert!(!r.ok, "over-limit archive reported ok: {:?}", r.summary);
        let (code, msg) = r.error.clone().unwrap();
        let want = if msg.contains("maximum file size") {
            ARCHIVE_EXTRACT_MAX_FILE_SIZE_EXCEEDED
        } else {
            ARCHIVE_EXTRACT_MAX_SIZE_EXCEEDED
        };
        assert_eq!(code, want, "{msg}");
        assert!(msg.contains(what), "{msg}");
        assert!(r.summary.is_none() && r.manifest.is_none());
    }

    const DEFLATE: CompressionMethod = CompressionMethod::Deflated;
    const STORED: CompressionMethod = CompressionMethod::Stored;

    #[test]
    fn understated_zip_entry_is_refused_under_max_file_bytes() {
        let sb = sandbox();
        let data = vec![0u8; 64 * 1024];
        let mut zip = zip_bytes(&[("big.bin", &data, DEFLATE)]);
        set_recorded_size(&mut zip, 0, 10);
        let r = extract_zip_bytes(&sb, &zip, |o| o.max_file_bytes = Some(100));
        assert_limit_refused(&r, "maximum file size (100)");
        assert!(sb.dest_tree().is_empty(), "{:?}", sb.dest_tree());
    }

    #[test]
    fn understated_zip_entry_is_refused_under_max_total_bytes() {
        let sb = sandbox();
        let data = vec![0u8; 64 * 1024];
        let mut zip = zip_bytes(&[("big.bin", &data, DEFLATE)]);
        set_recorded_size(&mut zip, 0, 10);
        let r = extract_zip_bytes(&sb, &zip, |o| o.max_total_bytes = Some(100));
        assert_limit_refused(&r, "Total extraction size would exceed maximum (100)");
        assert!(sb.dest_tree().is_empty(), "{:?}", sb.dest_tree());
    }

    #[test]
    fn understated_stored_zip_entry_is_refused() {
        let sb = sandbox();
        let data = vec![b'x'; 1000];
        let mut zip = zip_bytes(&[("big.bin", &data, STORED)]);
        set_recorded_size(&mut zip, 0, 10);
        let r = extract_zip_bytes(&sb, &zip, |o| o.max_file_bytes = Some(100));
        assert_limit_refused(&r, "maximum file size (100)");
        assert!(sb.dest_tree().is_empty());
    }

    #[test]
    fn honest_zip_within_both_limits_extracts() {
        let sb = sandbox();
        let zip = zip_bytes(&[("a.txt", b"hello", DEFLATE), ("d/b.txt", b"world!", STORED)]);
        let r = extract_zip_bytes(&sb, &zip, |o| {
            o.max_file_bytes = Some(6);
            o.max_total_bytes = Some(11);
        });
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(r.summary.as_ref().unwrap().bytes_written, 11);
        assert_eq!(fs::read(sb.dest.join("a.txt")).unwrap(), b"hello");
        assert_eq!(fs::read(sb.dest.join("d/b.txt")).unwrap(), b"world!");
        assert_eq!(sb.dest_tree(), vec!["a.txt", "d", "d/b.txt"]);
    }

    #[test]
    fn zip_entry_exactly_at_the_file_limit_extracts() {
        let sb = sandbox();
        let data = vec![b'x'; 100];
        let zip = zip_bytes(&[("f", &data, DEFLATE)]);
        let r = extract_zip_bytes(&sb, &zip, |o| {
            o.max_file_bytes = Some(100);
            o.max_total_bytes = Some(100);
        });
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(fs::read(sb.dest.join("f")).unwrap(), data);

        // The limit applies to the data, so a wrong recorded size that does
        // not take the entry over the limit is not itself a failure.
        let sb = sandbox();
        let mut zip = zip_bytes(&[("f", &data, DEFLATE)]);
        set_recorded_size(&mut zip, 0, 1);
        let r = extract_zip_bytes(&sb, &zip, |o| o.max_file_bytes = Some(100));
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(r.summary.as_ref().unwrap().bytes_written, 100);
        assert_eq!(r.manifest.as_ref().unwrap()[0].size, 100);
    }

    #[test]
    fn zip_entry_one_byte_over_the_file_limit_is_refused() {
        let data = vec![b'x'; 101];
        let sb = sandbox();
        let zip = zip_bytes(&[("f", &data, DEFLATE)]);
        let r = extract_zip_bytes(&sb, &zip, |o| o.max_file_bytes = Some(100));
        assert_limit_refused(&r, "exceeds maximum file size (100)");
        assert!(sb.dest_tree().is_empty());

        let sb = sandbox();
        let mut zip = zip_bytes(&[("f", &data, DEFLATE)]);
        set_recorded_size(&mut zip, 0, 100);
        let r = extract_zip_bytes(&sb, &zip, |o| o.max_file_bytes = Some(100));
        assert_limit_refused(&r, "exceeds maximum file size (100)");
        assert!(sb.dest_tree().is_empty());
    }

    /// Entries completed before the failing one stay; the failing entry
    /// leaves nothing.
    #[test]
    fn entries_whose_sum_exceeds_max_total_bytes_are_refused() {
        let chunk = vec![b'x'; 40];
        for understate in [false, true] {
            let sb = sandbox();
            let mut zip = zip_bytes(&[
                ("1", &chunk, DEFLATE),
                ("2", &chunk, DEFLATE),
                ("3", &chunk, DEFLATE),
            ]);
            if understate {
                for i in 0..3 {
                    set_recorded_size(&mut zip, i, 1);
                }
            }
            let r = extract_zip_bytes(&sb, &zip, |o| o.max_total_bytes = Some(100));
            assert_limit_refused(&r, "Total extraction size would exceed maximum (100)");
            assert_eq!(sb.dest_tree(), vec!["1", "2"], "understate={understate}");
            assert_eq!(fs::read(sb.dest.join("2")).unwrap(), chunk);
        }
    }

    #[test]
    fn small_recorded_size_with_much_larger_data_is_refused() {
        let sb = sandbox();
        let data = vec![0u8; 256 * 1024];
        let mut zip = zip_bytes(&[("ok.txt", b"fine", DEFLATE), ("big.bin", &data, DEFLATE)]);
        assert!(zip.len() < 2048, "fixture must stay small");
        set_recorded_size(&mut zip, 1, 1);
        let r = extract_zip_bytes(&sb, &zip, |o| {
            o.max_file_bytes = Some(1024);
            o.max_total_bytes = Some(4096);
        });
        assert_limit_refused(&r, "maximum file size (1024)");
        assert_eq!(sb.dest_tree(), vec!["ok.txt"]);
    }

    #[test]
    fn zero_byte_limits() {
        let sb = sandbox();
        let zip = zip_bytes(&[("empty", b"", DEFLATE)]);
        let r = extract_zip_bytes(&sb, &zip, |o| {
            o.max_file_bytes = Some(0);
            o.max_total_bytes = Some(0);
        });
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(fs::read(sb.dest.join("empty")).unwrap(), b"");

        for total in [false, true] {
            let sb = sandbox();
            let mut zip = zip_bytes(&[("f", b"12345", STORED)]);
            set_recorded_size(&mut zip, 0, 0);
            let r = extract_zip_bytes(&sb, &zip, |o| {
                if total {
                    o.max_total_bytes = Some(0)
                } else {
                    o.max_file_bytes = Some(0)
                }
            });
            assert!(!r.ok, "total={total}");
            assert!(sb.dest_tree().is_empty(), "total={total}");
        }
    }

    #[test]
    fn maximum_limits_do_not_overflow() {
        let sb = sandbox();
        let mut zip = zip_bytes(&[("a", b"abc", DEFLATE), ("b", b"defg", DEFLATE)]);
        set_recorded_size(&mut zip, 1, u32::MAX);
        let r = extract_zip_bytes(&sb, &zip, |o| {
            o.max_file_bytes = Some(u64::MAX);
            o.max_total_bytes = Some(u64::MAX);
        });
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(r.summary.as_ref().unwrap().bytes_written, 7);

        // Parsed from the command line as well
        let mut args = Args::new();
        args.insert("archive".into(), "x.zip".into());
        args.insert("destination".into(), "d".into());
        args.insert("max_total_bytes".into(), u64::MAX.to_string());
        args.insert("max_file_bytes".into(), "0".into());
        let o = ArchiveExtractOptions::from_args(&args).unwrap();
        assert_eq!(o.max_total_bytes, Some(u64::MAX));
        assert_eq!(o.max_file_bytes, Some(0));
    }

    #[test]
    fn corrupt_entry_data_leaves_no_partial_file() {
        let sb = sandbox();
        let data = vec![b'x'; 1000];
        let mut zip = zip_bytes(&[("f", &data, STORED)]);
        let at = zip.windows(16).position(|w| w == [b'x'; 16]).unwrap();
        zip[at + 500] = b'y'; // the CRC no longer matches
        let r = extract_zip_bytes(&sb, &zip, |_| {});
        assert!(!r.ok);
        assert!(sb.dest_tree().is_empty(), "{:?}", sb.dest_tree());
    }

    #[test]
    fn truncated_or_malformed_zip_is_refused_without_output() {
        let data = vec![b'x'; 1000];
        let zip = zip_bytes(&[("f", &data, DEFLATE)]);
        for bad in [
            &zip[..zip.len() / 2],
            &zip[..zip.len() - 1],
            b"PK\x03\x04junk",
        ] {
            let sb = sandbox();
            let r = extract_zip_bytes(&sb, bad, |o| o.max_file_bytes = Some(10_000));
            assert!(!r.ok);
            assert!(sb.dest_tree().is_empty());
        }
    }

    #[test]
    fn failed_entry_keeps_the_existing_file() {
        let data = vec![b'x'; 1000];
        // Over the limit, and corrupt within the limit
        let mut over = zip_bytes(&[("f", &data, STORED)]);
        set_recorded_size(&mut over, 0, 10);
        let mut corrupt = zip_bytes(&[("f", &data, STORED)]);
        let at = corrupt.windows(16).position(|w| w == [b'x'; 16]).unwrap();
        corrupt[at + 500] = b'y';
        for zip in [over, corrupt] {
            let sb = sandbox();
            fs::write(sb.dest.join("f"), b"original").unwrap();
            let r = extract_zip_bytes(&sb, &zip, |o| {
                o.overwrite = true;
                o.max_file_bytes = Some(100);
            });
            assert!(!r.ok);
            assert_eq!(fs::read(sb.dest.join("f")).unwrap(), b"original");
            assert_eq!(sb.dest_tree(), vec!["f"]);
        }
    }

    #[test]
    fn failed_entry_removes_directories_it_created() {
        let sb = sandbox();
        fs::create_dir(sb.dest.join("keep")).unwrap();
        let data = vec![0u8; 4096];
        let mut zip = zip_bytes(&[("keep/a/b/big.bin", &data, DEFLATE)]);
        set_recorded_size(&mut zip, 0, 1);
        let r = extract_zip_bytes(&sb, &zip, |o| o.max_file_bytes = Some(100));
        assert_limit_refused(&r, "maximum file size (100)");
        assert_eq!(sb.dest_tree(), vec!["keep"]);
    }

    #[test]
    fn limit_failure_never_follows_or_removes_a_link() {
        let sb = sandbox();
        symlink(sb.outside.join("keep.txt"), sb.dest.join("leaf")).unwrap();
        let data = vec![0u8; 4096];
        let mut zip = zip_bytes(&[("leaf", &data, DEFLATE)]);
        set_recorded_size(&mut zip, 0, 1);
        let r = extract_zip_bytes(&sb, &zip, |o| {
            o.overwrite = true;
            o.max_file_bytes = Some(100);
        });
        assert_limit_refused(&r, "maximum file size (100)");
        assert!(
            fs::symlink_metadata(sb.dest.join("leaf"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        sb.assert_outside_intact();

        // Within the limit the link itself is replaced, never written through
        let zip = zip_bytes(&[("leaf", b"new", DEFLATE)]);
        let r = extract_zip_bytes(&sb, &zip, |o| {
            o.overwrite = true;
            o.max_file_bytes = Some(100);
        });
        assert!(r.ok, "{:?}", r.error);
        assert!(sb.dest.join("leaf").is_file());
        assert_eq!(fs::read(sb.dest.join("leaf")).unwrap(), b"new");
        sb.assert_outside_intact();
    }

    #[test]
    fn traversal_and_link_parents_are_still_refused_with_limits() {
        let sb = sandbox();
        let zip = zip_bytes(&[("../outside/evil", b"x", DEFLATE)]);
        let r = extract_zip_bytes(&sb, &zip, |o| o.max_file_bytes = Some(100));
        assert_eq!(
            r.error.unwrap().0,
            ARCHIVE_EXTRACT_PATH_TRAVERSAL_DETECTED.to_string()
        );
        let zip = zip_bytes(&[("/abs/evil", b"x", DEFLATE)]);
        let r = extract_zip_bytes(&sb, &zip, |o| o.max_file_bytes = Some(100));
        assert_eq!(
            r.error.unwrap().0,
            ARCHIVE_EXTRACT_ABSOLUTE_PATH_REJECTED.to_string()
        );
        symlink(&sb.outside, sb.dest.join("pre")).unwrap();
        let zip = zip_bytes(&[("pre/evil", b"x", DEFLATE)]);
        let r = extract_zip_bytes(&sb, &zip, |o| {
            o.overwrite = true;
            o.max_file_bytes = Some(100);
        });
        assert_eq!(
            r.error.unwrap().0,
            ARCHIVE_EXTRACT_SYMLINK_REJECTED.to_string()
        );
        sb.assert_outside_intact();
    }

    /// A PAX `size` record overrides the size field of the header that
    /// follows it; the tar reader honours it, so the limits must too.
    fn tar_with_pax_size(data: &[u8], header_size: u64) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let body = format!("size={}\n", data.len());
        let mut len = body.len() + 2;
        while format!("{len} {body}").len() != len {
            len = format!("{len} {body}").len();
        }
        let record = format!("{len} {body}");
        let mut pax = tar::Header::new_ustar();
        pax.set_path("PaxHeader/big.bin").unwrap();
        pax.set_entry_type(tar::EntryType::XHeader);
        pax.set_size(record.len() as u64);
        pax.set_cksum();
        b.append(&pax, record.as_bytes()).unwrap();
        let mut h = tar::Header::new_ustar();
        h.set_path("big.bin").unwrap();
        h.set_mode(0o644);
        h.set_size(header_size);
        h.set_cksum();
        // append writes all of `data` whatever the header says
        b.append(&h, data).unwrap();
        b.into_inner().unwrap()
    }

    fn extract_tar_bytes(
        sb: &Sandbox,
        tar: &[u8],
        tweak: impl Fn(&mut ArchiveExtractOptions),
    ) -> ArchiveExtractResponse {
        let archive = sb.root.join("t.tar");
        fs::write(&archive, tar).unwrap();
        let mut o = opts(&archive, &sb.dest, ArchiveFormat::Tar);
        tweak(&mut o);
        extract_archive(o).unwrap()
    }

    #[test]
    fn tar_pax_size_is_the_size_that_is_limited() {
        let data = vec![b'x'; 4096];
        let tar = tar_with_pax_size(&data, 10);
        for total in [false, true] {
            let sb = sandbox();
            let r = extract_tar_bytes(&sb, &tar, |o| {
                if total {
                    o.max_total_bytes = Some(100)
                } else {
                    o.max_file_bytes = Some(100)
                }
            });
            assert!(!r.ok, "total={total}: {:?}", r.summary);
            assert!(sb.dest_tree().is_empty(), "{:?}", sb.dest_tree());
        }
        // Without limits the entry is extracted and counted at its real size
        let sb = sandbox();
        let r = extract_tar_bytes(&sb, &tar, |_| {});
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(r.summary.as_ref().unwrap().bytes_written, 4096);
        assert_eq!(fs::read(sb.dest.join("big.bin")).unwrap(), data);
    }

    /// A PAX size record that pushes the running total over
    /// `max_total_bytes` stops extraction at that entry, in a plain and a
    /// gzip-compressed tar: earlier entries are kept, and the failed entry
    /// leaves no file, temporary file or directory.
    #[test]
    fn tar_pax_size_counts_toward_the_total_limit() {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_ustar();
        h.set_path("a.txt").unwrap();
        h.set_mode(0o644);
        h.set_size(60);
        h.set_cksum();
        b.append(&h, &[b'a'; 60][..]).unwrap();
        let record = "11 size=60\n";
        let mut pax = tar::Header::new_ustar();
        pax.set_path("PaxHeader/b.bin").unwrap();
        pax.set_entry_type(tar::EntryType::XHeader);
        pax.set_size(record.len() as u64);
        pax.set_cksum();
        b.append(&pax, record.as_bytes()).unwrap();
        let mut h = tar::Header::new_ustar();
        h.set_path("d/b.bin").unwrap();
        h.set_mode(0o644);
        h.set_size(10);
        h.set_cksum();
        b.append(&h, &[b'b'; 60][..]).unwrap();
        let tar = b.into_inner().unwrap();

        for compression in [CompressionKind::None, CompressionKind::Gzip] {
            let sb = sandbox();
            let bytes = if compression == CompressionKind::Gzip {
                gzip(&tar)
            } else {
                tar.clone()
            };
            let r = extract_tar_bytes(&sb, &bytes, |o| {
                o.compression = compression.clone();
                o.max_total_bytes = Some(100);
            });
            assert_limit_refused(&r, "Total extraction size would exceed maximum (100)");
            assert_eq!(sb.dest_tree(), vec!["a.txt"], "{compression:?}");
            sb.assert_outside_intact();

            let sb = sandbox();
            let r = extract_tar_bytes(&sb, &bytes, |o| {
                o.compression = compression.clone();
                o.max_total_bytes = Some(120);
            });
            assert!(r.ok, "{:?}", r.error);
            assert_eq!(r.summary.as_ref().unwrap().bytes_written, 120);
            assert_eq!(fs::read(sb.dest.join("d/b.bin")).unwrap(), [b'b'; 60]);
        }
    }

    /// A GNU sparse entry stores 512 bytes but unpacks to a file of its
    /// real size; that is the size the limits see and report.
    #[test]
    fn tar_sparse_entry_is_limited_by_its_real_size() {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_path("sparse.bin").unwrap();
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::GNUSparse);
        h.set_size(512);
        {
            let gnu = h.as_gnu_mut().unwrap();
            gnu.sparse[0].set_offset(64 * 1024 - 512);
            gnu.sparse[0].set_length(512);
            gnu.set_real_size(64 * 1024);
        }
        h.set_cksum();
        b.append(&h, &[b'x'; 512][..]).unwrap();
        let tar = b.into_inner().unwrap();

        let sb = sandbox();
        let r = extract_tar_bytes(&sb, &tar, |o| o.max_file_bytes = Some(1024));
        assert_limit_refused(&r, "maximum file size (1024)");
        assert!(sb.dest_tree().is_empty());

        let sb = sandbox();
        let r = extract_tar_bytes(&sb, &tar, |o| o.max_file_bytes = Some(64 * 1024));
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(r.summary.as_ref().unwrap().bytes_written, 64 * 1024);
        assert_eq!(
            fs::metadata(sb.dest.join("sparse.bin")).unwrap().len(),
            64 * 1024
        );
    }

    #[test]
    fn copy_limited_boundaries() {
        let copy = |data: &[u8], limit: u64| {
            let mut out = Vec::new();
            let r = copy_limited(&mut &data[..], &mut out, limit).unwrap();
            (r, out.len())
        };
        assert_eq!(copy(b"", 0), (Some(0), 0));
        assert_eq!(copy(b"a", 0), (None, 0));
        assert_eq!(copy(b"abc", 3), (Some(3), 3));
        assert_eq!(copy(b"abcd", 3), (None, 0));
        assert_eq!(copy(b"abc", u64::MAX), (Some(3), 3));
        // Past the first buffer: nothing beyond the limit is written
        let big = vec![1u8; 200 * 1024];
        assert_eq!(copy(&big, 200 * 1024), (Some(200 * 1024), 200 * 1024));
        let (r, n) = copy(&big, 100 * 1024 + 1);
        assert_eq!(r, None);
        assert!(n <= 100 * 1024 + 1, "{n}");
    }

    #[test]
    fn limit_arithmetic_saturates_instead_of_wrapping() {
        let mut o = opts(Path::new("x.zip"), Path::new("d"), ArchiveFormat::Zip);
        assert_eq!(entry_byte_budget(&o, u64::MAX), u64::MAX);
        o.max_total_bytes = Some(u64::MAX);
        assert_eq!(entry_byte_budget(&o, u64::MAX - 1), 1);
        assert_eq!(entry_byte_budget(&o, u64::MAX), 0);
        o.max_total_bytes = Some(10);
        assert_eq!(entry_byte_budget(&o, 11), 0);
        o.max_file_bytes = Some(3);
        assert_eq!(entry_byte_budget(&o, 0), 3);

        // A recorded size near u64::MAX must not wrap the running total
        let o = {
            let mut o = opts(Path::new("x.zip"), Path::new("d"), ArchiveFormat::Zip);
            o.max_total_bytes = Some(100);
            o
        };
        assert!(check_entry_size(&o, "f", u64::MAX - 5, 10).is_err());
        assert!(check_entry_size(&o, "f", 90, 10).is_ok());
        assert!(check_entry_size(&o, "f", 91, 10).is_err());
    }

    #[test]
    fn truncated_tar_entry_keeps_the_existing_file() {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_ustar();
        h.set_path("f").unwrap();
        h.set_mode(0o644);
        h.set_size(4096);
        h.set_cksum();
        b.append(&h, &vec![b'x'; 4096][..]).unwrap();
        let tar = b.into_inner().unwrap();
        let sb = sandbox();
        fs::write(sb.dest.join("f"), b"original").unwrap();
        let r = extract_tar_bytes(&sb, &tar[..512 + 1000], |o| o.overwrite = true);
        assert!(!r.ok);
        assert_eq!(fs::read(sb.dest.join("f")).unwrap(), b"original");
        assert_eq!(sb.dest_tree(), vec!["f"]);
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn extract_raw_bytes(
        sb: &Sandbox,
        gz: &[u8],
        tweak: impl Fn(&mut ArchiveExtractOptions),
    ) -> ArchiveExtractResponse {
        let archive = sb.root.join("data.gz");
        fs::write(&archive, gz).unwrap();
        let mut o = opts(&archive, &sb.dest, ArchiveFormat::Raw);
        o.compression = CompressionKind::Gzip;
        tweak(&mut o);
        extract_archive(o).unwrap()
    }

    #[test]
    fn raw_stream_over_a_limit_writes_nothing() {
        let gz = gzip(&vec![0u8; 64 * 1024]);
        for total in [false, true] {
            let sb = sandbox();
            let r = extract_raw_bytes(&sb, &gz, |o| {
                if total {
                    o.max_total_bytes = Some(100)
                } else {
                    o.max_file_bytes = Some(100)
                }
            });
            assert_limit_refused(&r, "(100)");
            assert!(sb.dest_tree().is_empty(), "{:?}", sb.dest_tree());
        }
        // Exactly at the limit
        let sb = sandbox();
        let r = extract_raw_bytes(&sb, &gzip(&[7u8; 100]), |o| {
            o.max_file_bytes = Some(100);
            o.max_total_bytes = Some(100);
        });
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(fs::read(sb.dest.join("data")).unwrap(), vec![7u8; 100]);
    }

    #[test]
    fn raw_failure_keeps_the_existing_file() {
        let gz = gzip(&vec![0u8; 64 * 1024]);
        let truncated = &gz[..gz.len() / 2];
        for (data, limit) in [(&gz[..], Some(100)), (truncated, None)] {
            let sb = sandbox();
            fs::write(sb.dest.join("data"), b"original").unwrap();
            let r = extract_raw_bytes(&sb, data, |o| {
                o.overwrite = true;
                o.max_file_bytes = limit;
            });
            assert!(!r.ok);
            assert_eq!(fs::read(sb.dest.join("data")).unwrap(), b"original");
            assert_eq!(sb.dest_tree(), vec!["data"]);
        }
    }

    fn limit_args(pairs: &[(&str, &str)]) -> Args {
        let mut a: Args = [("archive", "t.tar"), ("destination", "out")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        for (k, v) in pairs {
            a.insert(k.to_string(), v.to_string());
        }
        a
    }

    #[test]
    fn byte_limits_parse_whole_numbers_only() {
        for key in ["max_file_bytes", "max_total_bytes"] {
            let o = ArchiveExtractOptions::from_args(&limit_args(&[])).unwrap();
            assert_eq!((o.max_file_bytes, o.max_total_bytes), (None, None));
            for (v, want) in [
                ("0", 0),
                ("1", 1),
                ("100", 100),
                ("007", 7),
                ("18446744073709551615", u64::MAX),
            ] {
                let o = ArchiveExtractOptions::from_args(&limit_args(&[(key, v)])).unwrap();
                let got = if key == "max_file_bytes" {
                    o.max_file_bytes
                } else {
                    o.max_total_bytes
                };
                assert_eq!(got, Some(want), "{key}={v}");
            }
        }
    }

    #[test]
    fn malformed_byte_limits_are_refused() {
        let bad = [
            "",
            " ",
            "\t",
            " 100",
            "100 ",
            "-1",
            "-0",
            "+100",
            "1e6",
            "1E6",
            "1.5",
            "100.0",
            ".5",
            "0x10",
            "10k",
            "10MB",
            "1_000",
            "1,000",
            "abc",
            "none",
            "null",
            "unlimited",
            "inf",
            "NaN",
            "18446744073709551616",
            "99999999999999999999999999",
            "\u{0661}",
        ];
        for (key, code) in [
            ("max_file_bytes", ARCHIVE_EXTRACT_INVALID_MAX_FILE_SIZE),
            ("max_total_bytes", ARCHIVE_EXTRACT_INVALID_MAX_SIZE),
        ] {
            for v in bad {
                let err = ArchiveExtractOptions::from_args(&limit_args(&[(key, v)]))
                    .expect_err(&format!("{key}={v:?} accepted"));
                assert_eq!(validation_code("extract", &err), code, "{key}={v:?}");
                let msg = err.to_string();
                assert!(msg.contains(&format!("{v:?}")), "{msg}");
            }
        }
    }

    /// An invalid limit stops the operation before any output exists, even
    /// next to a valid one and with an archive that would otherwise extract.
    #[test]
    fn invalid_byte_limit_is_refused_before_extraction() {
        let sb = sandbox();
        let archive = sb.root.join("t.tar");
        let mut b = tar::Builder::new(File::create(&archive).unwrap());
        let mut h = tar::Header::new_gnu();
        h.set_size(5);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "a", &b"hello"[..]).unwrap();
        b.finish().unwrap();
        let dest = sb.root.join("new-dest");
        for pairs in [
            &[("max_file_bytes", "1e6")][..],
            &[("max_file_bytes", "100"), ("max_total_bytes", "-1")][..],
        ] {
            let mut a = limit_args(pairs);
            a.insert("archive".into(), archive.display().to_string());
            a.insert("destination".into(), dest.display().to_string());
            assert!(ArchiveExtractOptions::from_args(&a).is_err());
        }
        assert!(!dest.exists());
        sb.assert_outside_intact();
    }
}

#[cfg(test)]
mod tar_header_limit_tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    const LIMIT_MESSAGE: &str = "tar header data for one archive member exceeds 1048576 bytes";

    /// A .tar.gz whose first member is a PAX header declaring 8 GiB of data,
    /// with 2 MiB of it present.
    fn oversized_header_tar_gz() -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_ustar();
        h.set_path("PaxHeader").unwrap();
        h.set_entry_type(tar::EntryType::XHeader);
        h.set_size(8 << 30);
        h.set_cksum();
        b.append(&h, &vec![b'a'; 2 * 1024 * 1024][..]).unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_size(2);
        h.set_mode(0o644);
        b.append_data(&mut h, "a.txt", &b"ok"[..]).unwrap();
        gzip(&b.into_inner().unwrap())
    }

    /// A .tar.gz with a 60 KiB PAX record and a GNU long name.
    fn legitimate_tar_gz(long: &str) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        b.append_pax_extensions([("comment", &[b'c'; 60 * 1024][..])])
            .unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_size(2);
        h.set_mode(0o644);
        b.append_data(&mut h, "a.txt", &b"ok"[..]).unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_size(4);
        h.set_mode(0o644);
        b.append_data(&mut h, long, &b"long"[..]).unwrap();
        gzip(&b.into_inner().unwrap())
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn write(dir: &TempDir, name: &str, data: &[u8]) -> String {
        let path = dir.path().join(name);
        fs::write(&path, data).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn assert_limit<T>(result: Result<T>) {
        let Err(err) = result else {
            panic!("archive should be refused");
        };
        assert!(format!("{err:#}").contains(LIMIT_MESSAGE), "{err:#}");
    }

    #[test]
    fn add_reads_existing_entries_within_the_limit() {
        let dir = TempDir::new().unwrap();
        let path = write(&dir, "bad.tar.gz", &oversized_header_tar_gz());
        let none = Deadline::none();
        assert_limit(index_tar_entries(
            &path,
            &CompressionKind::Gzip,
            none,
            None,
            None,
        ));

        let long = format!("{}/b.txt", "d".repeat(200));
        let path = write(&dir, "good.tar.gz", &legitimate_tar_gz(&long));
        let entries = index_tar_entries(&path, &CompressionKind::Gzip, none, None, None).unwrap();
        let names: Vec<_> = entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(names, ["a.txt", long.as_str()]);
        // The long-named member is copied with its full name and data.
        let mut out = tar::Builder::new(Vec::new());
        copy_tar_entries(&path, &mut out, &CompressionKind::Gzip, none, &|k: &str| {
            k != "a.txt"
        })
        .unwrap();
        let copied = out.into_inner().unwrap();
        let mut ar = tar::Archive::new(&copied[..]);
        let mut e = ar.entries().unwrap().next().unwrap().unwrap();
        assert_eq!(e.path().unwrap().to_string_lossy(), long);
        let mut data = Vec::new();
        e.read_to_end(&mut data).unwrap();
        assert_eq!(data, b"long");
    }

    #[test]
    fn remove_reads_and_copies_entries_within_the_limit() {
        let dir = TempDir::new().unwrap();
        let none = Deadline::none();
        let bad = write(&dir, "bad.tar.gz", &oversized_header_tar_gz());
        assert_limit(index_tar_entries(
            &bad,
            &CompressionKind::Gzip,
            none,
            None,
            None,
        ));
        let mut out = tar::Builder::new(Vec::new());
        assert_limit(copy_tar_entries(
            &bad,
            &mut out,
            &CompressionKind::Gzip,
            none,
            &|_: &str| false,
        ));

        let long = format!("{}/b.txt", "d".repeat(200));
        let good = write(&dir, "good.tar.gz", &legitimate_tar_gz(&long));
        let entries = index_tar_entries(&good, &CompressionKind::Gzip, none, None, None).unwrap();
        assert_eq!(entries.len(), 2);
        let mut out = tar::Builder::new(Vec::new());
        copy_tar_entries(&good, &mut out, &CompressionKind::Gzip, none, &|k: &str| {
            k == "a.txt"
        })
        .unwrap();
        let copied = out.into_inner().unwrap();
        let names: Vec<String> = tar::Archive::new(&copied[..])
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["a.txt"]);
    }
}

#[cfg(test)]
#[path = "archive_verb_tests.rs"]
mod verb_tests;

#[cfg(test)]
mod error_code_tests {
    use super::*;
    use crate::core::status::is_valid_error_code;

    /// Every code the handle can report has the project-wide form and is
    /// listed in the archive docs page.
    #[test]
    fn every_error_code_is_valid_and_documented() {
        let docs = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/Filesystem_Storage/archive.md"
        ))
        .unwrap();
        let mut seen = std::collections::HashSet::new();
        for code in ERROR_CODES {
            assert!(is_valid_error_code(code), "{code}");
            assert!(seen.insert(code), "listed twice: {code}");
            assert!(
                docs.contains(&format!("`{code}`")),
                "not documented: {code}"
            );
        }
        // The fixed codes used outside error_code() are in the list.
        for code in [
            ARCHIVE_TEST_ENTRY_HEADER_ERROR,
            ARCHIVE_TEST_ENTRY_IO_ERROR,
            ARCHIVE_TEST_ENTRY_COMPRESSION_ERROR,
            ARCHIVE_TEST_ENTRY_CHECKSUM_ERROR,
            ARCHIVE_TEST_ENTRY_SIZE_MISMATCH,
            ARCHIVE_TEST_ENTRY_FAILED,
            ARCHIVE_TEST_MAX_FILE_SIZE_EXCEEDED,
            ARCHIVE_EXTRACT_PATH_TRAVERSAL_DETECTED,
            ARCHIVE_EXTRACT_ABSOLUTE_PATH_REJECTED,
            ARCHIVE_EXTRACT_SYMLINK_REJECTED,
            ARCHIVE_EXTRACT_UNSUPPORTED_ENTRY_TYPE,
        ] {
            assert!(ERROR_CODES.contains(&code), "{code}");
        }
    }

    /// Exit status by code: usage errors 2, timeouts 124, the rest 1.
    #[test]
    fn exit_status_follows_the_code() {
        for code in ERROR_CODES {
            let want = if code.ends_with("_timeout") {
                124
            } else if code.contains("_invalid_")
                || *code == "archive.unknown_verb"
                || code.ends_with("_7z_unsupported")
                || code.ends_with("_unsupported_for_raw")
            {
                2
            } else {
                1
            };
            assert_eq!(exit_for(code), want, "{code}");
        }
    }

    /// A failure in a JSON report is a `{"code", "message"}` object.
    #[test]
    fn json_error_is_an_object() {
        let args = Args::from([("archive".to_string(), "/nonexistent/x.tar".to_string())]);
        let opts = ArchiveListOptions::from_args(&args).unwrap();
        let mut r = ArchiveListResponse::new(&opts);
        r.ok = false;
        r.error = Some(("archive.list_missing_archive".into(), "gone".into()));
        let v: Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(
            v["error"],
            json!({"code": "archive.list_missing_archive", "message": "gone"})
        );
    }
}
