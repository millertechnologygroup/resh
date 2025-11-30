use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use percent_encoding::percent_decode_str;
use serde_json::json;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use url::Url;
use uuid::Uuid;
use walkdir::WalkDir;

use crate::core::{
    registry::{Args, Handle, IoStreams},
    status::Status,
};

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("snapshot", |u| Ok(Box::new(SnapshotHandle::from_url(u)?)));
}

#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    pub id: String,
    pub backend: String,
    pub target: PathBuf,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub enum IfExistsMode {
    Error,
    Skip,
    Overwrite,
}

impl IfExistsMode {
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "error" => Ok(IfExistsMode::Error),
            "skip" => Ok(IfExistsMode::Skip),
            "overwrite" => Ok(IfExistsMode::Overwrite),
            _ => bail!("invalid if_exists mode: '{}' (must be 'error', 'skip', or 'overwrite')", s),
        }
    }
}

// Diff-related types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileTypeKind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryStatus {
    Added,
    Removed,
    Modified,
    Unchanged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub exists: bool,
    pub file_type: Option<FileTypeKind>,
    pub size: Option<u64>,
    pub mtime: Option<String>,
    pub mode: Option<String>,
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub file_type: FileTypeKind,
    pub status: EntryStatus,
    pub from: FileInfo,
    pub to: FileInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    pub added: u32,
    pub removed: u32,
    pub modified: u32,
    pub unchanged: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    pub name: String,
    pub from: String,
    pub to: String,
    pub from_kind: String,
    pub to_kind: String,
    pub root: String,
    pub path: String,
    pub summary: DiffSummary,
    pub entries: Vec<DiffEntry>,
}

#[derive(Debug, Clone)]
pub struct SnapshotMeta {
    pub id: String,
    pub backend: String,
    pub target: PathBuf,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub path: PathBuf,
    pub description: Option<String>,
}

// Struct for deserializing snapshot metadata from JSON (for ls operation)
#[derive(Debug, Deserialize)]
struct SnapshotMetaForLs {
    id: String,
    name: Option<String>,
    created_at: Option<String>,
    backend: Option<String>,
    target: Option<String>,
    state: Option<String>,
    size_bytes: Option<u64>,
    tags: Option<Vec<String>>,
    description: Option<String>,
}

// Output struct for ls operation
#[derive(Debug, Serialize)]
struct SnapshotLsOutput {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

#[derive(Debug, Clone)]
pub enum TreeKind {
    Snapshot,
    Live,
}

pub trait SnapshotBackend {
    fn create_snapshot(
        &self,
        target: &Path,
        name: &str,
        description: Option<&str>,
        ttl: Option<Duration>,
        if_exists: IfExistsMode,
    ) -> Result<SnapshotInfo>;
}

pub struct LocalSnapshotBackend {
    base_dir: PathBuf,
}

impl LocalSnapshotBackend {
    pub fn new() -> Result<Self> {
        let base_dir = match dirs::state_dir() {
            Some(dir) => dir.join("resh").join("snapshots"),
            None => PathBuf::from("/tmp").join("resh").join("snapshots"),
        };

        Ok(Self { base_dir })
    }

    fn sanitize_path_component(s: &str) -> String {
        let mut result = String::new();
        for ch in s.chars() {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_' {
                result.push(ch);
            } else {
                result.push('_');
            }
        }
        if result.len() > 120 {
            result.truncate(120);
        }
        if result.is_empty() {
            "_".to_string()
        } else {
            result
        }
    }

    fn get_snapshot_dir(&self, target: &Path, name: &str) -> PathBuf {
        let sanitized_target = Self::sanitize_path_component(&target.to_string_lossy());
        let sanitized_name = Self::sanitize_path_component(name);
        self.base_dir.join(sanitized_target).join(sanitized_name)
    }

    fn copy_recursively(src: &Path, dst: &Path) -> Result<()> {
        if src.is_file() {
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create parent directory: {:?}", parent))?;
            }
            fs::copy(src, dst)
                .with_context(|| format!("failed to copy file from {:?} to {:?}", src, dst))?;
        } else if src.is_dir() {
            fs::create_dir_all(dst)
                .with_context(|| format!("failed to create directory: {:?}", dst))?;

            for entry in WalkDir::new(src) {
                let entry = entry
                    .with_context(|| format!("failed to read directory entry in {:?}", src))?;
                let entry_path = entry.path();
                
                let relative_path = entry_path
                    .strip_prefix(src)
                    .with_context(|| format!("failed to strip prefix {:?} from {:?}", src, entry_path))?;
                let target_path = dst.join(relative_path);

                if entry_path.is_dir() {
                    fs::create_dir_all(&target_path)
                        .with_context(|| format!("failed to create directory: {:?}", target_path))?;
                } else if entry_path.is_file() {
                    if let Some(parent) = target_path.parent() {
                        fs::create_dir_all(parent)
                            .with_context(|| format!("failed to create parent directory: {:?}", parent))?;
                    }
                    fs::copy(entry_path, &target_path)
                        .with_context(|| format!("failed to copy file from {:?} to {:?}", entry_path, target_path))?;
                }
            }
        } else {
            bail!("source path is neither file nor directory: {:?}", src);
        }
        Ok(())
    }
}

impl SnapshotBackend for LocalSnapshotBackend {
    fn create_snapshot(
        &self,
        target: &Path,
        name: &str,
        description: Option<&str>,
        ttl: Option<Duration>,
        if_exists: IfExistsMode,
    ) -> Result<SnapshotInfo> {
        // Validate target exists
        if !target.exists() {
            bail!("target path does not exist: {:?}", target);
        }

        let metadata = fs::metadata(target)
            .with_context(|| format!("failed to get metadata for target: {:?}", target))?;

        if !metadata.is_file() && !metadata.is_dir() {
            bail!("target is neither file nor directory: {:?}", target);
        }

        // Get final snapshot directory
        let snapshot_dir = self.get_snapshot_dir(target, name);

        // Handle existing snapshot
        if snapshot_dir.exists() {
            match if_exists {
                IfExistsMode::Error => {
                    bail!("snapshot already exists: {}", name);
                }
                IfExistsMode::Skip => {
                    // Read existing metadata and return it
                    let meta_file = snapshot_dir.join("meta.json");
                    if meta_file.exists() {
                        let meta_content = fs::read_to_string(&meta_file)
                            .with_context(|| format!("failed to read existing metadata: {:?}", meta_file))?;
                        let meta_value: serde_json::Value = serde_json::from_str(&meta_content)
                            .with_context(|| "failed to parse existing metadata")?;
                        
                        return Ok(SnapshotInfo {
                            id: meta_value["id"].as_str().unwrap_or("").to_string(),
                            backend: meta_value["backend"].as_str().unwrap_or("local").to_string(),
                            target: PathBuf::from(meta_value["target"].as_str().unwrap_or("")),
                            name: meta_value["name"].as_str().unwrap_or("").to_string(),
                            created_at: DateTime::parse_from_rfc3339(meta_value["created_at"].as_str().unwrap_or(""))
                                .map(|dt| dt.with_timezone(&Utc))
                                .unwrap_or_else(|_| Utc::now()),
                            expires_at: meta_value["expires_at"]
                                .as_str()
                                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                                .map(|dt| dt.with_timezone(&Utc)),
                            path: snapshot_dir.clone(),
                        });
                    }
                }
                IfExistsMode::Overwrite => {
                    fs::remove_dir_all(&snapshot_dir)
                        .with_context(|| format!("failed to remove existing snapshot: {:?}", snapshot_dir))?;
                }
            }
        }

        // Create temporary directory for atomic operation
        let temp_dir = snapshot_dir.with_extension(format!("tmp-{}", Uuid::new_v4()));

        // Ensure cleanup on error
        let cleanup = || {
            let _ = fs::remove_dir_all(&temp_dir);
        };

        // Create temp directory
        fs::create_dir_all(&temp_dir)
            .with_context(|| format!("failed to create temp directory: {:?}", temp_dir))
            .map_err(|e| {
                cleanup();
                e
            })?;

        // Copy content
        if target.is_file() {
            let content_file = temp_dir.join("content");
            fs::copy(target, &content_file)
                .with_context(|| format!("failed to copy file content from {:?} to {:?}", target, content_file))
                .map_err(|e| {
                    cleanup();
                    e
                })?;
        } else {
            // For directories, copy everything into the temp directory
            Self::copy_recursively(target, &temp_dir)
                .with_context(|| format!("failed to copy directory content from {:?} to {:?}", target, temp_dir))
                .map_err(|e| {
                    cleanup();
                    e
                })?;
        }

        // Create snapshot info
        let id = Uuid::new_v4().to_string();
        let created_at = Utc::now();
        let expires_at = ttl.map(|duration| created_at + chrono::Duration::from_std(duration).unwrap_or_default());

        let snapshot_info = SnapshotInfo {
            id: id.clone(),
            backend: "local".to_string(),
            target: target.to_path_buf(),
            name: name.to_string(),
            created_at,
            expires_at,
            path: snapshot_dir.clone(),
        };

        // Write metadata
        let meta_file = temp_dir.join("meta.json");
        let meta_json = json!({
            "id": snapshot_info.id,
            "backend": snapshot_info.backend,
            "target": snapshot_info.target.to_string_lossy(),
            "name": snapshot_info.name,
            "created_at": snapshot_info.created_at.to_rfc3339(),
            "expires_at": snapshot_info.expires_at.map(|dt| dt.to_rfc3339()),
            "path": snapshot_info.path.to_string_lossy(),
            "description": description
        });

        fs::write(&meta_file, serde_json::to_string_pretty(&meta_json)?)
            .with_context(|| format!("failed to write metadata file: {:?}", meta_file))
            .map_err(|e| {
                cleanup();
                e
            })?;

        // Atomic rename to final location
        if let Some(parent) = snapshot_dir.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create snapshot parent directory: {:?}", parent))
                .map_err(|e| {
                    cleanup();
                    e
                })?;
        }

        fs::rename(&temp_dir, &snapshot_dir)
            .with_context(|| format!("failed to rename temp directory to final location: {:?} -> {:?}", temp_dir, snapshot_dir))
            .map_err(|e| {
                cleanup();
                e
            })?;

        Ok(snapshot_info)
    }
}

pub struct SnapshotHandle {
    target: PathBuf,
}

impl SnapshotHandle {
    pub fn from_url(url: &Url) -> Result<Self> {
        // Handle case where filename is in host position (e.g., snapshot://test.txt)
        // or in path position (e.g., snapshot:///test.txt)
        let path_str = if url.host_str().is_some() && !url.host_str().unwrap().is_empty() {
            url.host_str().unwrap()
        } else {
            url.path()
        };
        
        // Handle percent-encoding
        let decoded = percent_decode_str(path_str)
            .decode_utf8()
            .with_context(|| format!("invalid UTF-8 in URL path: {}", path_str))?;

        let target = PathBuf::from(decoded.as_ref());
        
        // Normalize path components but don't resolve relative paths yet
        let normalized = normalize_path(&target);
        
        Ok(Self { target: normalized })
    }

    fn find_snapshot_by_id(&self, target: &Path, id: &str) -> Result<(String, PathBuf)> {
        let backend = LocalSnapshotBackend::new()?;
        let sanitized_target = LocalSnapshotBackend::sanitize_path_component(&target.to_string_lossy());
        let target_dir = backend.base_dir.join(&sanitized_target);
        
        if !target_dir.exists() {
            bail!("no snapshots found for target: {:?}", target);
        }
        
        // Search through all snapshot names for this target
        for entry in fs::read_dir(&target_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            
            let snapshot_name = entry.file_name().to_string_lossy().to_string();
            let snapshot_dir = entry.path();
            let meta_file = snapshot_dir.join("meta.json");
            
            if !meta_file.exists() {
                continue;
            }
            
            if let Ok(meta_content) = fs::read_to_string(&meta_file) {
                if let Ok(meta_value) = serde_json::from_str::<serde_json::Value>(&meta_content) {
                    if let Some(stored_id) = meta_value["id"].as_str() {
                        if stored_id == id {
                            return Ok((snapshot_name, snapshot_dir));
                        }
                    }
                }
            }
        }
        
        bail!("snapshot with id '{}' not found for target: {:?}", id, target);
    }

    fn load_snapshot_meta(&self, name: &str, id: &str) -> Result<SnapshotMeta> {
        // If we have an ID, try to find the snapshot by ID first
        let (actual_name, snapshot_dir) = if !id.is_empty() {
            self.find_snapshot_by_id(&self.target, id)?
        } else {
            // Fall back to using the provided name
            let backend = LocalSnapshotBackend::new()?;
            let snapshot_dir = backend.get_snapshot_dir(&self.target, name);
            if !snapshot_dir.exists() {
                bail!("snapshot not found: {} for target: {:?}", name, self.target);
            }
            (name.to_string(), snapshot_dir)
        };
        
        let meta_file = snapshot_dir.join("meta.json");
        
        if !meta_file.exists() {
            bail!("snapshot metadata not found: {} (id: {})", actual_name, id);
        }
        
        let meta_content = fs::read_to_string(&meta_file)
            .with_context(|| format!("failed to read snapshot metadata: {:?}", meta_file))?;
        let meta_value: serde_json::Value = serde_json::from_str(&meta_content)
            .with_context(|| "failed to parse snapshot metadata")?;
        
        // Validate that this is the correct snapshot ID if provided
        let stored_id = meta_value["id"].as_str().unwrap_or("");
        if !id.is_empty() && stored_id != id {
            bail!("snapshot ID mismatch: expected {}, found {}", id, stored_id);
        }
        
        Ok(SnapshotMeta {
            id: stored_id.to_string(),
            backend: meta_value["backend"].as_str().unwrap_or("local").to_string(),
            target: PathBuf::from(meta_value["target"].as_str().unwrap_or("")),
            name: meta_value["name"].as_str().unwrap_or("").to_string(),
            created_at: DateTime::parse_from_rfc3339(meta_value["created_at"].as_str().unwrap_or(""))
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            expires_at: meta_value["expires_at"]
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
            path: snapshot_dir.clone(),
            description: meta_value["description"].as_str().map(|s| s.to_string()),
        })
    }

    fn resolve_tree(&self, id_or_live: &str, name: &str) -> Result<(TreeKind, PathBuf, SnapshotMeta)> {
        if id_or_live == "live" {
            // For live, we need to create a dummy SnapshotMeta with the live target
            let target = if self.target.is_absolute() {
                self.target.clone()
            } else {
                std::env::current_dir()?.join(&self.target)
            };
            
            if !target.exists() {
                bail!("live target path does not exist: {:?}", target);
            }
            
            let dummy_meta = SnapshotMeta {
                id: "live".to_string(),
                backend: "live".to_string(),
                target: target.clone(),
                name: name.to_string(),
                created_at: Utc::now(),
                expires_at: None,
                path: target.clone(),
                description: None,
            };
            
            Ok((TreeKind::Live, target, dummy_meta))
        } else {
            let meta = self.load_snapshot_meta(name, id_or_live)?;
            let snapshot_path = meta.path.clone();
            if !snapshot_path.exists() {
                bail!("snapshot directory not found: {:?}", snapshot_path);
            }
            Ok((TreeKind::Snapshot, snapshot_path, meta))
        }
    }

    fn collect_entries(&self, root: &Path, restrict_path: Option<&str>) -> Result<HashMap<PathBuf, FileInfo>> {
        let mut entries = HashMap::new();
        
        let search_root = if let Some(subpath) = restrict_path {
            if subpath == "/" {
                root.to_path_buf()
            } else {
                root.join(subpath.trim_start_matches('/'))
            }
        } else {
            root.to_path_buf()
        };
        
        if !search_root.exists() {
            return Ok(entries);
        }
        
        for entry in WalkDir::new(&search_root) {
            let entry = entry.with_context(|| format!("failed to walk directory: {:?}", search_root))?;
            let entry_path = entry.path();
            
            let relative_path = entry_path.strip_prefix(&search_root)
                .with_context(|| format!("failed to strip prefix {:?} from {:?}", search_root, entry_path))?;
            
            // Skip the root directory itself
            if relative_path.as_os_str().is_empty() {
                continue;
            }
            
            // Skip snapshot metadata files
            if let Some(file_name) = relative_path.file_name() {
                if file_name == "meta.json" {
                    continue;
                }
            }
            
            let file_info = self.collect_file_info(entry_path)?;
            entries.insert(relative_path.to_path_buf(), file_info);
        }
        
        Ok(entries)
    }

    fn collect_file_info(&self, path: &Path) -> Result<FileInfo> {
        let metadata = fs::metadata(path);
        
        if let Err(_) = metadata {
            return Ok(FileInfo {
                exists: false,
                file_type: None,
                size: None,
                mtime: None,
                mode: None,
                hash: None,
            });
        }
        
        let metadata = metadata.unwrap();
        let file_type = if metadata.is_file() {
            FileTypeKind::File
        } else if metadata.is_dir() {
            FileTypeKind::Dir
        } else if metadata.file_type().is_symlink() {
            FileTypeKind::Symlink
        } else {
            FileTypeKind::Other
        };
        
        let size = if metadata.is_file() { Some(metadata.len()) } else { None };
        
        let mtime = metadata.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| {
                DateTime::from_timestamp(d.as_secs() as i64, d.subsec_nanos())
                    .unwrap_or_else(|| Utc::now())
                    .to_rfc3339()
            });
        
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            Some(format!("{:o}", metadata.permissions().mode() & 0o7777))
        };
        #[cfg(not(unix))]
        let mode = None;
        
        // Compute hash for small files only
        let hash = if metadata.is_file() && metadata.len() <= 16 * 1024 * 1024 {
            self.compute_file_hash(path).ok()
        } else {
            None
        };
        
        Ok(FileInfo {
            exists: true,
            file_type: Some(file_type),
            size,
            mtime,
            mode,
            hash,
        })
    }

    fn compute_file_hash(&self, path: &Path) -> Result<String> {
        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 8192];
        
        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }
        
        Ok(format!("sha256:{:x}", hasher.finalize()))
    }

    fn compare_entries(&self, a: &HashMap<PathBuf, FileInfo>, b: &HashMap<PathBuf, FileInfo>) -> DiffResult {
        let mut entries = Vec::new();
        let mut summary = DiffSummary {
            added: 0,
            removed: 0,
            modified: 0,
            unchanged: 0,
        };
        
        // Collect all unique paths
        let mut all_paths: std::collections::BTreeSet<&PathBuf> = std::collections::BTreeSet::new();
        all_paths.extend(a.keys());
        all_paths.extend(b.keys());
        
        for path in all_paths {
            let from_info = a.get(path);
            let to_info = b.get(path);
            
            let (status, file_type) = match (from_info, to_info) {
                (None, Some(to)) => {
                    summary.added += 1;
                    (EntryStatus::Added, to.file_type.clone().unwrap_or(FileTypeKind::Other))
                }
                (Some(_), None) => {
                    summary.removed += 1;
                    (EntryStatus::Removed, from_info.unwrap().file_type.clone().unwrap_or(FileTypeKind::Other))
                }
                (Some(from), Some(to)) => {
                    if self.files_differ(from, to) {
                        summary.modified += 1;
                        (EntryStatus::Modified, to.file_type.clone().unwrap_or(FileTypeKind::Other))
                    } else {
                        summary.unchanged += 1;
                        continue; // Skip unchanged entries from output
                    }
                }
                (None, None) => continue, // Shouldn't happen
            };
            
            let from_file_info = from_info.cloned().unwrap_or(FileInfo {
                exists: false,
                file_type: None,
                size: None,
                mtime: None,
                mode: None,
                hash: None,
            });
            
            let to_file_info = to_info.cloned().unwrap_or(FileInfo {
                exists: false,
                file_type: None,
                size: None,
                mtime: None,
                mode: None,
                hash: None,
            });
            
            entries.push(DiffEntry {
                path: path.to_string_lossy().to_string(),
                file_type,
                status,
                from: from_file_info,
                to: to_file_info,
            });
        }
        
        DiffResult {
            name: "".to_string(), // Will be filled in by caller
            from: "".to_string(), // Will be filled in by caller
            to: "".to_string(), // Will be filled in by caller
            from_kind: "".to_string(), // Will be filled in by caller
            to_kind: "".to_string(), // Will be filled in by caller
            root: "".to_string(), // Will be filled in by caller
            path: "/".to_string(), // Will be filled in by caller
            summary,
            entries,
        }
    }

    fn files_differ(&self, a: &FileInfo, b: &FileInfo) -> bool {
        if a.exists != b.exists {
            return true;
        }
        if a.file_type != b.file_type {
            return true;
        }
        if a.size != b.size {
            return true;
        }
        if a.mode != b.mode {
            return true;
        }
        // For hash comparison, only compare if both have hashes
        if let (Some(a_hash), Some(b_hash)) = (&a.hash, &b.hash) {
            return a_hash != b_hash;
        }
        // If no hash available, compare mtime
        a.mtime != b.mtime
    }

    fn diff(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments
        let from = args.get("from").map(|s| s.as_str()).unwrap_or("");
        let to = args.get("to").map(|s| s.as_str()).unwrap_or("");
        let path_filter = args.get("path").map(|s| s.as_str()).unwrap_or("/");
        let format = args.get("format").map(|s| s.as_str()).unwrap_or("json");
        
        // Validate arguments
        if from.is_empty() && to.is_empty() {
            let error_msg = "at least one of 'from' or 'to' must be provided";
            writeln!(io.stderr, "Error: {}", error_msg)?;
            return Ok(Status::err(1, error_msg));
        }
        
        if from == "live" && to == "live" {
            let error_msg = "cannot diff live filesystem against itself (both from and to are live)";
            writeln!(io.stderr, "Error: {}", error_msg)?;
            return Ok(Status::err(1, error_msg));
        }
        
        if !from.is_empty() && !to.is_empty() && from == to {
            let error_msg = "cannot diff snapshot against itself (from and to are the same)";
            writeln!(io.stderr, "Error: {}", error_msg)?;
            return Ok(Status::err(1, error_msg));
        }
        
        // Extract name from URL (assume format like snapshot://name.diff(...))
        let name = self.target.to_string_lossy().to_string();
        
        // Resolve trees
        let (from_kind, from_path, from_meta) = if from.is_empty() {
            // If from is empty, use a dummy empty tree
            (TreeKind::Live, PathBuf::new(), SnapshotMeta {
                id: "empty".to_string(),
                backend: "empty".to_string(),
                target: PathBuf::new(),
                name: "empty".to_string(),
                created_at: Utc::now(),
                expires_at: None,
                path: PathBuf::new(),
                description: None,
            })
        } else {
            self.resolve_tree(from, &name).with_context(|| format!("failed to resolve from tree: {}", from))?
        };
        
        let (to_kind, to_path, to_meta) = if to.is_empty() {
            // If to is empty, use a dummy empty tree  
            (TreeKind::Live, PathBuf::new(), SnapshotMeta {
                id: "empty".to_string(),
                backend: "empty".to_string(),
                target: PathBuf::new(),
                name: "empty".to_string(),
                created_at: Utc::now(),
                expires_at: None,
                path: PathBuf::new(),
                description: None,
            })
        } else {
            self.resolve_tree(to, &name).with_context(|| format!("failed to resolve to tree: {}", to))?
        };
        
        // Collect entries
        let from_entries = if from.is_empty() {
            HashMap::new()
        } else {
            self.collect_entries(&from_path, Some(path_filter))
                .with_context(|| format!("failed to collect entries from from tree: {:?}", from_path))?
        };
        
        let to_entries = if to.is_empty() {
            HashMap::new()
        } else {
            self.collect_entries(&to_path, Some(path_filter))
                .with_context(|| format!("failed to collect entries from to tree: {:?}", to_path))?
        };
        
        // Compare
        let mut diff_result = self.compare_entries(&from_entries, &to_entries);
        
        // Fill in metadata
        diff_result.name = name;
        diff_result.from = if from.is_empty() { "empty".to_string() } else { from.to_string() };
        diff_result.to = if to.is_empty() { "empty".to_string() } else { to.to_string() };
        diff_result.from_kind = match from_kind {
            TreeKind::Snapshot => "snapshot".to_string(),
            TreeKind::Live => "live".to_string(),
        };
        diff_result.to_kind = match to_kind {
            TreeKind::Snapshot => "snapshot".to_string(),
            TreeKind::Live => "live".to_string(),
        };
        diff_result.root = if !to_meta.target.as_os_str().is_empty() {
            to_meta.target.to_string_lossy().to_string()
        } else if !from_meta.target.as_os_str().is_empty() {
            from_meta.target.to_string_lossy().to_string()
        } else {
            "/".to_string()
        };
        diff_result.path = path_filter.to_string();
        
        // Output
        match format {
            "json" => {
                let json_output = serde_json::to_string(&diff_result)?;
                writeln!(io.stdout, "{}", json_output)?;
            }
            "summary" => {
                writeln!(io.stdout, "snapshot: {}", diff_result.name)?;
                writeln!(io.stdout, "from: {} ({})", diff_result.from, diff_result.from_kind)?;
                writeln!(io.stdout, "to:   {} ({})", diff_result.to, diff_result.to_kind)?;
                writeln!(io.stdout, "root: {}", diff_result.root)?;
                writeln!(io.stdout, "path: {}", diff_result.path)?;
                writeln!(io.stdout)?;
                writeln!(io.stdout, "added: {}", diff_result.summary.added)?;
                writeln!(io.stdout, "removed: {}", diff_result.summary.removed)?;
                writeln!(io.stdout, "modified: {}", diff_result.summary.modified)?;
                writeln!(io.stdout, "unchanged: {}", diff_result.summary.unchanged)?;
            }
            _ => {
                let error_msg = format!("unknown format: {} (must be json or summary)", format);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                return Ok(Status::err(1, &error_msg));
            }
        }
        
        Ok(Status::ok())
    }

    fn create(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Resolve target path at execution time to handle relative paths correctly
        let target = if self.target.is_absolute() {
            self.target.clone()
        } else {
            let current_dir = std::env::current_dir()
                .context("failed to get current directory")?;
            current_dir.join(&self.target)
        };

        // Parse required arguments
        let name = match args.get("name") {
            Some(name) if !name.trim().is_empty() => name.trim(),
            _ => {
                let error_msg = "missing required argument: name";
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "ok": false,
                    "error": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        // Parse optional arguments
        let backend = args.get("backend").map(|s| s.as_str()).unwrap_or("local");
        if backend != "local" {
            let error_msg = format!("unsupported backend: {} (only local is supported)", backend);
            writeln!(io.stderr, "Error: {}", error_msg)?;
            let error_json = json!({
                "ok": false,
                "error": error_msg
            });
            writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
            return Ok(Status::err(1, &error_msg));
        }

        let description = args.get("description").map(|s| s.as_str());

        let ttl = match args.get("ttl") {
            Some(ttl_str) => {
                match ttl_str.parse::<u64>() {
                    Ok(seconds) => Some(Duration::from_secs(seconds)),
                    Err(_) => {
                        let error_msg = format!("invalid ttl value: {} (must be positive integer seconds)", ttl_str);
                        writeln!(io.stderr, "Error: {}", error_msg)?;
                        let error_json = json!({
                            "ok": false,
                            "error": error_msg
                        });
                        writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                        return Ok(Status::err(1, &error_msg));
                    }
                }
            }
            None => None,
        };

        let if_exists = match args.get("if_exists") {
            Some(mode_str) => {
                match IfExistsMode::from_str(mode_str) {
                    Ok(mode) => mode,
                    Err(e) => {
                        let error_msg = format!("{}", e);
                        writeln!(io.stderr, "Error: {}", error_msg)?;
                        let error_json = json!({
                            "ok": false,
                            "error": error_msg
                        });
                        writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                        return Ok(Status::err(1, &error_msg));
                    }
                }
            }
            None => IfExistsMode::Error,
        };

        // Create backend
        let backend_impl = match LocalSnapshotBackend::new() {
            Ok(backend) => backend,
            Err(e) => {
                let error_msg = format!("failed to initialize snapshot backend: {}", e);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "ok": false,
                    "error": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(1, &error_msg));
            }
        };

        // Create snapshot
        match backend_impl.create_snapshot(&target, name, description, ttl, if_exists.clone()) {
            Ok(snapshot_info) => {
                // Check if this was a skip operation
                let skipped = matches!(if_exists, IfExistsMode::Skip) && 
                             snapshot_info.path.exists() && 
                             snapshot_info.path.join("meta.json").exists();

                let response = json!({
                    "ok": true,
                    "backend": snapshot_info.backend,
                    "id": snapshot_info.id,
                    "name": snapshot_info.name,
                    "target": snapshot_info.target.to_string_lossy(),
                    "path": snapshot_info.path.to_string_lossy(),
                    "created_at": snapshot_info.created_at.to_rfc3339(),
                    "expires_at": snapshot_info.expires_at.map(|dt| dt.to_rfc3339()),
                    "skipped": skipped
                });

                writeln!(io.stdout, "{}", serde_json::to_string(&response)?)?;
                Ok(Status::ok())
            }
            Err(e) => {
                let error_msg = format!("{}", e);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "ok": false,
                    "error": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                Ok(Status::err(1, &error_msg))
            }
        }
    }
    
    // Helper methods for restore functionality
    
    /// Check if a directory is empty (contains no files or subdirectories)
    fn is_dir_empty(&self, path: &Path) -> Result<bool> {
        if !path.exists() {
            return Ok(true);
        }
        
        if !path.is_dir() {
            return Ok(false);
        }
        
        let mut entries = fs::read_dir(path)
            .with_context(|| format!("failed to read directory: {:?}", path))?;
        Ok(entries.next().is_none())
    }
    
    /// Copy files recursively while preserving metadata (permissions, timestamps)
    fn copy_recursive_with_metadata(&self, src: &Path, dst: &Path) -> Result<()> {
        if src.is_file() {
            // Ensure parent directory exists
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create parent directory: {:?}", parent))?;
            }
            
            // Copy file
            fs::copy(src, dst)
                .with_context(|| format!("failed to copy file from {:?} to {:?}", src, dst))?;
            
            // Copy metadata
            if let Ok(metadata) = src.metadata() {
                let _ = fs::set_permissions(dst, metadata.permissions());
                
                // Attempt to set file times
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    use std::time::UNIX_EPOCH;
                    
                    if let Some(atime) = UNIX_EPOCH.checked_add(std::time::Duration::from_secs(metadata.atime() as u64)) {
                        if let Some(mtime) = UNIX_EPOCH.checked_add(std::time::Duration::from_secs(metadata.mtime() as u64)) {
                            let _ = filetime::set_file_times(dst, 
                                filetime::FileTime::from_system_time(atime),
                                filetime::FileTime::from_system_time(mtime));
                        }
                    }
                }
            }
        } else if src.is_dir() {
            // Create destination directory
            fs::create_dir_all(dst)
                .with_context(|| format!("failed to create directory: {:?}", dst))?;
            
            // Copy metadata for directory
            if let Ok(metadata) = src.metadata() {
                let _ = fs::set_permissions(dst, metadata.permissions());
            }
            
            // Recursively copy directory contents
            for entry in WalkDir::new(src) {
                let entry = entry
                    .with_context(|| format!("failed to read directory entry in {:?}", src))?;
                let entry_path = entry.path();
                
                let relative_path = entry_path
                    .strip_prefix(src)
                    .with_context(|| format!("failed to strip prefix {:?} from {:?}", src, entry_path))?;
                let target_path = dst.join(relative_path);
                
                if entry_path == src {
                    continue; // Skip root directory
                }
                
                if entry_path.is_dir() {
                    fs::create_dir_all(&target_path)
                        .with_context(|| format!("failed to create directory: {:?}", target_path))?;
                    
                    // Copy directory metadata
                    if let Ok(metadata) = entry_path.metadata() {
                        let _ = fs::set_permissions(&target_path, metadata.permissions());
                    }
                } else if entry_path.is_file() {
                    if let Some(parent) = target_path.parent() {
                        fs::create_dir_all(parent)
                            .with_context(|| format!("failed to create parent directory: {:?}", parent))?;
                    }
                    
                    fs::copy(entry_path, &target_path)
                        .with_context(|| format!("failed to copy file from {:?} to {:?}", entry_path, target_path))?;
                    
                    // Copy file metadata
                    if let Ok(metadata) = entry_path.metadata() {
                        let _ = fs::set_permissions(&target_path, metadata.permissions());
                        
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::MetadataExt;
                            use std::time::UNIX_EPOCH;
                            
                            if let Some(atime) = UNIX_EPOCH.checked_add(std::time::Duration::from_secs(metadata.atime() as u64)) {
                                if let Some(mtime) = UNIX_EPOCH.checked_add(std::time::Duration::from_secs(metadata.mtime() as u64)) {
                                    let _ = filetime::set_file_times(&target_path, 
                                        filetime::FileTime::from_system_time(atime),
                                        filetime::FileTime::from_system_time(mtime));
                                }
                            }
                        }
                    }
                }
            }
        } else {
            bail!("source path is neither file nor directory: {:?}", src);
        }
        
        Ok(())
    }
    
    /// Find a snapshot by name across all targets
    fn find_snapshot_by_name(&self, name: &str) -> Result<PathBuf> {
        let backend = LocalSnapshotBackend::new()?;
        let base_dir = &backend.base_dir;
        
        if !base_dir.exists() {
            bail!("snapshot storage directory does not exist: {:?}", base_dir);
        }
        
        // Search through all target directories
        for entry in fs::read_dir(base_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            
            let target_dir = entry.path();
            let potential_snapshot = target_dir.join(name);
            
            if potential_snapshot.exists() && potential_snapshot.join("meta.json").exists() {
                return Ok(potential_snapshot);
            }
        }
        
        bail!("snapshot not found: {}", name);
    }
    
    /// Restore operation implementation
    fn do_restore(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse snapshot name from URL target
        let snapshot_name = self.target.to_string_lossy().to_string();
        
        // Parse required arguments
        let target_path = match args.get("target") {
            Some(path) => PathBuf::from(path),
            None => {
                let error_msg = "missing required argument: target";
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "error": "missing_argument",
                    "argument": "target",
                    "message": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(1, error_msg));
            }
        };
        
        // Parse optional arguments
        let force = args.get("force")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);
            
        let mode = args.get("mode")
            .map(|s| s.as_str())
            .unwrap_or("overwrite");
        
        let dry_run = args.get("dry_run")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);
        
        // Validate mode (MVP: only support overwrite)
        if mode != "overwrite" {
            let error_msg = format!("unsupported mode: '{}' (only 'overwrite' is supported in this version)", mode);
            writeln!(io.stderr, "Error: {}", error_msg)?;
            let error_json = json!({
                "error": "unsupported_mode",
                "mode": mode,
                "message": error_msg
            });
            writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
            return Ok(Status::err(1, &error_msg));
        }
        
        // Find snapshot by name across all targets
        let snapshot_dir = match self.find_snapshot_by_name(&snapshot_name) {
            Ok(dir) => dir,
            Err(_) => {
                let error_msg = format!("snapshot not found: {}", snapshot_name);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "error": "snapshot_not_found",
                    "snapshot": snapshot_name,
                    "message": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(2, &error_msg));
            }
        };
        
        // Load snapshot metadata to get original target info
        let meta_file = snapshot_dir.join("meta.json");
        if !meta_file.exists() {
            let error_msg = format!("snapshot metadata not found: {}", snapshot_name);
            writeln!(io.stderr, "Error: {}", error_msg)?;
            let error_json = json!({
                "error": "metadata_not_found",
                "snapshot": snapshot_name,
                "message": error_msg
            });
            writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
            return Ok(Status::err(2, &error_msg));
        }
        
        // Read metadata to determine original target type  
        let meta_content = fs::read_to_string(&meta_file)
            .with_context(|| format!("failed to read snapshot metadata: {:?}", meta_file))?;
        let meta_value: serde_json::Value = serde_json::from_str(&meta_content)
            .with_context(|| "failed to parse snapshot metadata")?;
        
        let original_target = PathBuf::from(meta_value["target"].as_str().unwrap_or(""));
        let is_file_snapshot = original_target.is_file() || snapshot_dir.join("content").exists();
        
        // Check target path constraints
        if target_path.exists() {
            if target_path.is_file() {
                if !force {
                    let error_msg = format!("target file exists (use force=true to overwrite): {:?}", target_path);
                    writeln!(io.stderr, "Error: {}", error_msg)?;
                    let error_json = json!({
                        "error": "target_exists",
                        "target": target_path.to_string_lossy(),
                        "message": error_msg
                    });
                    writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                    return Ok(Status::err(3, &error_msg));
                }
            } else if target_path.is_dir() {
                if !self.is_dir_empty(&target_path)? && !force {
                    let error_msg = format!("target directory exists and is not empty (use force=true to overwrite): {:?}", target_path);
                    writeln!(io.stderr, "Error: {}", error_msg)?;
                    let error_json = json!({
                        "error": "target_not_empty",
                        "target": target_path.to_string_lossy(),
                        "message": error_msg
                    });
                    writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                    return Ok(Status::err(3, &error_msg));
                }
            }
        }
        
        // Handle dry run
        if dry_run {
            let mut actions = Vec::new();
            
            if target_path.exists() && force {
                if target_path.is_file() {
                    actions.push(format!("DELETE FILE {:?}", target_path));
                } else if target_path.is_dir() {
                    actions.push(format!("DELETE DIRECTORY {:?}", target_path));
                }
            }
            
            // Add copy action
            actions.push(format!("COPY {:?} -> {:?}", snapshot_dir, target_path));
            
            let dry_run_result = json!({
                "dry_run": true,
                "snapshot": snapshot_name,
                "target": target_path.to_string_lossy(),
                "mode": mode,
                "force": force,
                "actions": actions
            });
            
            writeln!(io.stdout, "{}", serde_json::to_string_pretty(&dry_run_result)?)?;
            return Ok(Status::ok());
        }
        
        // Perform atomic restore operation
        let parent_dir = match target_path.parent() {
            Some(parent) => parent,
            None => {
                let error_msg = format!("target path has no parent directory: {:?}", target_path);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "error": "invalid_target",
                    "target": target_path.to_string_lossy(),
                    "message": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(1, &error_msg));
            }
        };
        
        // Create parent directory if needed
        fs::create_dir_all(parent_dir)
            .with_context(|| format!("failed to create parent directory: {:?}", parent_dir))?;
        
        // Create temporary directory for atomic operation
        let temp_path = parent_dir.join(format!(".resh-restore-{}.tmp", uuid::Uuid::new_v4()));
        
        // Cleanup function
        let cleanup = |temp: &Path| {
            let _ = fs::remove_dir_all(temp);
        };
        
        // Copy snapshot contents to temp directory - handle file vs directory snapshots
        if is_file_snapshot {
            // For file snapshots, copy the 'content' file to the target location
            let content_file = snapshot_dir.join("content");
            if content_file.exists() {
                if let Err(e) = fs::copy(&content_file, &temp_path) {
                    cleanup(&temp_path);
                    let error_msg = format!("failed to copy snapshot file content: {}", e);
                    writeln!(io.stderr, "Error: {}", error_msg)?;
                    let error_json = json!({
                        "error": "copy_failed",
                        "snapshot": snapshot_name,
                        "message": error_msg
                    });
                    writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                    return Ok(Status::err(4, &error_msg));
                }
                
                // Copy metadata from original file if available
                if let Ok(metadata) = content_file.metadata() {
                    let _ = fs::set_permissions(&temp_path, metadata.permissions());
                    
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        use std::time::UNIX_EPOCH;
                        
                        if let Some(atime) = UNIX_EPOCH.checked_add(std::time::Duration::from_secs(metadata.atime() as u64)) {
                            if let Some(mtime) = UNIX_EPOCH.checked_add(std::time::Duration::from_secs(metadata.mtime() as u64)) {
                                let _ = filetime::set_file_times(&temp_path, 
                                    filetime::FileTime::from_system_time(atime),
                                    filetime::FileTime::from_system_time(mtime));
                            }
                        }
                    }
                }
            } else {
                cleanup(&temp_path);
                let error_msg = format!("snapshot content file not found: {}", snapshot_name);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "error": "content_not_found",
                    "snapshot": snapshot_name,
                    "message": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(2, &error_msg));
            }
        } else {
            // For directory snapshots, copy the entire directory structure
            if let Err(e) = self.copy_recursive_with_metadata(&snapshot_dir, &temp_path) {
                cleanup(&temp_path);
                let error_msg = format!("failed to copy snapshot contents: {}", e);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "error": "copy_failed",
                    "snapshot": snapshot_name,
                    "message": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(4, &error_msg));
            }
            
            // Remove metadata file from temp (it shouldn't be part of restored content)
            let temp_meta = temp_path.join("meta.json");
            if temp_meta.exists() {
                let _ = fs::remove_file(&temp_meta);
            }
        }
        
        // Atomic rename operation
        if target_path.exists() {
            // Create backup path
            let backup_path = parent_dir.join(format!(".resh-backup-{}.bak", uuid::Uuid::new_v4()));
            
            // Move existing target to backup
            if let Err(e) = fs::rename(&target_path, &backup_path) {
                cleanup(&temp_path);
                let error_msg = format!("failed to backup existing target: {}", e);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "error": "backup_failed",
                    "target": target_path.to_string_lossy(),
                    "message": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(4, &error_msg));
            }
            
            // Rename temp to target
            if let Err(e) = fs::rename(&temp_path, &target_path) {
                // Restore backup on failure
                let _ = fs::rename(&backup_path, &target_path);
                cleanup(&temp_path);
                
                let error_msg = format!("failed to restore snapshot: {}", e);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "error": "restore_failed",
                    "snapshot": snapshot_name,
                    "message": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(4, &error_msg));
            }
            
            // Remove backup on success
            let _ = fs::remove_dir_all(&backup_path);
        } else {
            // No existing target, simple rename
            if let Err(e) = fs::rename(&temp_path, &target_path) {
                cleanup(&temp_path);
                let error_msg = format!("failed to restore snapshot: {}", e);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "error": "restore_failed",
                    "snapshot": snapshot_name,
                    "message": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(4, &error_msg));
            }
        }
        
        // Success response
        let response = json!({
            "snapshot": snapshot_name,
            "target": target_path.to_string_lossy(),
            "mode": mode,
            "status": "ok"
        });
        
        writeln!(io.stdout, "{}", serde_json::to_string(&response)?)?;
        Ok(Status::ok())
    }

    /// List snapshots for a group
    fn verb_ls(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Extract group name from the target path 
        // For snapshot://mygroup -> target would be "mygroup"
        let group_name = self.target.to_string_lossy();
        let sanitized_group = LocalSnapshotBackend::sanitize_path_component(&group_name);
        
        // Get base directory structure for snapshots
        let base_dir = match dirs::state_dir() {
            Some(dir) => dir.join("resh").join("snapshots"),
            None => PathBuf::from("/tmp").join("resh").join("snapshots"),
        };
        
        let group_dir = base_dir.join(&sanitized_group);
        
        // If group directory doesn't exist, return empty list
        if !group_dir.exists() {
            self.output_snapshot_list(&[], args, io)?;
            return Ok(Status::ok());
        }
        
        let mut snapshots = Vec::new();
        
        // Enumerate all subdirectories (each is a snapshot ID)
        match fs::read_dir(&group_dir) {
            Ok(entries) => {
                for entry in entries {
                    let entry = match entry {
                        Ok(e) => e,
                        Err(e) => {
                            writeln!(io.stderr, "snapshot://{}.ls: error reading directory entry: {}", group_name, e)?;
                            continue;
                        }
                    };
                    
                    if !entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                        continue;
                    }
                    
                    let snapshot_dir = entry.path();
                    let meta_file = snapshot_dir.join("meta.json");
                    
                    if !meta_file.exists() {
                        writeln!(io.stderr, "snapshot://{}.ls: skipping {}: meta.json not found", group_name, entry.file_name().to_string_lossy())?;
                        continue;
                    }
                    
                    // Read and parse metadata
                    match self.read_snapshot_meta(&meta_file) {
                        Ok(meta) => snapshots.push(meta),
                        Err(e) => {
                            writeln!(io.stderr, "snapshot://{}.ls: skipping {}: {}", group_name, entry.file_name().to_string_lossy(), e)?;
                            continue;
                        }
                    }
                }
            }
            Err(e) => {
                let error_msg = format!("failed to read snapshot group directory: {}", e);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                return Ok(Status::err(1, &error_msg));
            }
        }
        
        // Apply filters
        let filtered = self.apply_filters(snapshots, args, io)?;
        
        // Sort and limit
        let final_list = self.sort_and_limit(filtered, args, io)?;
        
        // Output results
        self.output_snapshot_list(&final_list, args, io)?;
        
        Ok(Status::ok())
    }
    
    /// Read and parse a snapshot meta.json file
    fn read_snapshot_meta(&self, meta_file: &Path) -> Result<SnapshotMetaForLs> {
        let content = fs::read_to_string(meta_file)
            .with_context(|| format!("failed to read meta.json: {:?}", meta_file))?;
        
        let meta: SnapshotMetaForLs = serde_json::from_str(&content)
            .with_context(|| format!("failed to parse meta.json: {:?}", meta_file))?;
        
        Ok(meta)
    }
    
    /// Apply all filters to the snapshot list
    fn apply_filters(&self, snapshots: Vec<SnapshotMetaForLs>, args: &Args, io: &mut IoStreams) -> Result<Vec<SnapshotMetaForLs>> {
        let mut result = Vec::new();
        
        for snapshot in snapshots {
            // Apply state filter
            if let Some(filter_state) = args.get("state") {
                let snapshot_state = snapshot.state.as_deref().unwrap_or("unknown");
                if filter_state.to_lowercase() != snapshot_state.to_lowercase() {
                    continue;
                }
            }
            
            // Apply tag filter
            if let Some(filter_tag) = args.get("tag") {
                let filter_tag_lower = filter_tag.to_lowercase();
                let has_tag = snapshot.tags.as_ref()
                    .map(|tags| tags.iter().any(|tag| tag.to_lowercase() == filter_tag_lower))
                    .unwrap_or(false);
                if !has_tag {
                    continue;
                }
            }
            
            // Apply since/until filters
            let created_at_dt = snapshot.created_at.as_ref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc));
                
            if let Some(since_str) = args.get("since") {
                match DateTime::parse_from_rfc3339(since_str) {
                    Ok(since_dt) => {
                        let since_utc = since_dt.with_timezone(&Utc);
                        if created_at_dt.map_or(true, |dt| dt < since_utc) {
                            continue;
                        }
                    }
                    Err(_) => {
                        writeln!(io.stderr, "snapshot://.ls: warning: invalid 'since' timestamp, ignoring: {}", since_str)?;
                    }
                }
            }
            
            if let Some(until_str) = args.get("until") {
                match DateTime::parse_from_rfc3339(until_str) {
                    Ok(until_dt) => {
                        let until_utc = until_dt.with_timezone(&Utc);
                        if created_at_dt.map_or(true, |dt| dt > until_utc) {
                            continue;
                        }
                    }
                    Err(_) => {
                        writeln!(io.stderr, "snapshot://.ls: warning: invalid 'until' timestamp, ignoring: {}", until_str)?;
                    }
                }
            }
            
            // Apply name_prefix filter
            if let Some(prefix) = args.get("name_prefix") {
                if snapshot.name.as_ref().map_or(true, |name| !name.starts_with(prefix)) {
                    continue;
                }
            }
            
            result.push(snapshot);
        }
        
        Ok(result)
    }
    
    /// Sort snapshots and apply limit
    fn sort_and_limit(&self, mut snapshots: Vec<SnapshotMetaForLs>, args: &Args, io: &mut IoStreams) -> Result<Vec<SnapshotMetaForLs>> {
        // Sort by created_at descending (newest first), then by id for stable ordering
        snapshots.sort_by(|a, b| {
            let a_dt = a.created_at.as_ref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc));
            let b_dt = b.created_at.as_ref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc));
                
            match (a_dt, b_dt) {
                (Some(a_time), Some(b_time)) => b_time.cmp(&a_time), // Descending order (newest first)
                (Some(_), None) => std::cmp::Ordering::Less,          // Valid time comes before invalid
                (None, Some(_)) => std::cmp::Ordering::Greater,       // Invalid time comes after valid
                (None, None) => a.id.cmp(&b.id),                     // Stable sort by id
            }
        });
        
        // Apply limit
        if let Some(limit_str) = args.get("limit") {
            match limit_str.parse::<usize>() {
                Ok(limit) if limit > 0 => {
                    snapshots.truncate(limit);
                }
                Ok(_) => {
                    writeln!(io.stderr, "snapshot://.ls: warning: invalid limit (must be > 0), ignoring: {}", limit_str)?;
                }
                Err(_) => {
                    writeln!(io.stderr, "snapshot://.ls: warning: invalid limit (not a number), ignoring: {}", limit_str)?;
                }
            }
        }
        
        Ok(snapshots)
    }
    
    /// Output the final snapshot list as JSON
    fn output_snapshot_list(&self, snapshots: &[SnapshotMetaForLs], args: &Args, io: &mut IoStreams) -> Result<()> {
        let output: Vec<SnapshotLsOutput> = snapshots.iter().map(|meta| {
            SnapshotLsOutput {
                id: meta.id.clone(),
                name: meta.name.clone(),
                created_at: meta.created_at.clone(),
                backend: meta.backend.clone(),
                target: meta.target.clone(),
                state: meta.state.clone(),
                size_bytes: meta.size_bytes,
                tags: meta.tags.clone(),
                description: meta.description.clone(),
            }
        }).collect();
        
        let json_output = if args.get("json_pretty").map_or(false, |s| s.to_lowercase() == "true") {
            serde_json::to_string_pretty(&output)?
        } else {
            serde_json::to_string(&output)?
        };
        
        writeln!(io.stdout, "{}", json_output)?;
        Ok(())
    }
}

// Helper function to normalize path components similar to file handle
fn normalize_path(p: &Path) -> PathBuf {
    let mut components = Vec::new();
    let mut is_absolute = false;
    
    for component in p.components() {
        match component {
            Component::Normal(name) => components.push(name),
            Component::RootDir => {
                components.clear();
                components.push(std::ffi::OsStr::new("/"));
                is_absolute = true;
            }
            Component::ParentDir => {
                if !components.is_empty() && components.last() != Some(&std::ffi::OsStr::new("/")) {
                    components.pop();
                }
            }
            Component::CurDir => {
                // Skip current directory references but track that this was relative
            }
            _ => {}
        }
    }
    
    if components.is_empty() {
        PathBuf::from(".")
    } else if is_absolute && components.len() == 1 && components[0] == "/" {
        PathBuf::from("/")
    } else if is_absolute {
        components.into_iter().collect()
    } else {
        // For relative paths, keep them relative
        components.into_iter().collect()
    }
}

impl Handle for SnapshotHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["create", "diff", "restore", "ls"]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        match verb {
            "create" => self.create(args, io),
            "diff" => self.diff(args, io),
            "restore" => self.do_restore(args, io),
            "ls" => self.verb_ls(args, io),
            _ => bail!("unknown verb for snapshot://: {} (available: create, diff, restore, ls)", verb),
        }
    }
}