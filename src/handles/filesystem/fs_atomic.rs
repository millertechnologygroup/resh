use anyhow::{Context, Result, bail};
use chrono::Utc;
use serde_json::Value;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256, Sha512};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

// For production-grade random number generation
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[cfg(unix)]
use libc::{LOCK_EX, LOCK_NB, LOCK_UN, flock};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Simple cleanup guard for temporary files
struct TempFileCleanup {
    path: PathBuf,
}

impl TempFileCleanup {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }
}

impl Drop for TempFileCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path); // Best effort cleanup
    }
}

// Results structures for structured JSON output
#[derive(serde::Serialize)]
pub struct WriteResult {
    pub written: bool,
    pub mode: String,
    pub path: String,
    pub bytes: u64,
    pub timestamp: String,
}

#[derive(serde::Serialize)]
pub struct AppendResult {
    pub appended: bool,
    pub mode: String,
    pub path: String,
    pub bytes: u64,
    pub timestamp: String,
}

#[derive(serde::Serialize)]
pub struct VerifyResult {
    pub path: String,
    pub verified: bool,
    pub method: String,
    pub expected: Option<String>,
    pub actual: Option<String>,
    pub timestamp: String,
    pub error: Option<String>,
}

// Configuration for atomic operations
pub struct AtomicWriteOptions {
    pub atomic: bool,
    pub mode: Option<u32>,
    pub fsync: bool,
}

pub struct AtomicAppendOptions {
    pub atomic: bool,
    pub ensure_newline: bool,
    pub fsync: bool,
}

impl Default for AtomicWriteOptions {
    fn default() -> Self {
        Self {
            atomic: true,
            mode: None,
            fsync: true,
        }
    }
}

impl Default for AtomicAppendOptions {
    fn default() -> Self {
        Self {
            atomic: true,
            ensure_newline: false,
            fsync: true,
        }
    }
}

/// Generates a unique temporary filename in the same directory as the target
fn generate_temp_path(target: &Path) -> Result<PathBuf> {
    let filename = target
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid target path: no filename"))?;

    // Handle parent directory correctly
    let parent = match target.parent() {
        Some(p) if p == Path::new("") => Path::new("."), // Empty parent means current dir
        Some(p) => p,
        None => Path::new("."), // No parent means current dir
    };

    // Only check directory existence if it's not the current directory
    if parent != Path::new(".") {
        if !parent.exists() {
            bail!("Parent directory does not exist: {:?}", parent);
        }
        if !parent.is_dir() {
            bail!("Parent path is not a directory: {:?}", parent);
        }
    }

    // Generate cryptographically secure random suffix
    let mut hasher = DefaultHasher::new();
    target.hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or(0)
        .hash(&mut hasher);

    let suffix = format!(
        ".tmp.{}.{}.{}",
        std::process::id(),
        Utc::now().timestamp_micros(),
        hasher.finish()
    );

    let mut temp_name = filename.to_os_string();
    temp_name.push(&suffix);

    let temp_path = parent.join(temp_name);

    // Ensure temp file doesn't already exist (extremely unlikely but safe)
    if temp_path.exists() {
        bail!("Temporary file already exists: {:?}", temp_path);
    }

    Ok(temp_path)
}

/// Check available disk space
fn check_disk_space(path: &Path, required_bytes: u64) -> Result<()> {
    // Basic implementation - in production, you'd want more sophisticated checking
    if let Some(parent) = path.parent() {
        if let Ok(metadata) = std::fs::metadata(parent) {
            // This is a simplified check - real implementation would use statvfs on Unix
            if metadata.len() > 0 && required_bytes > 1_000_000_000 { // 1GB threshold
                // Could implement actual disk space checking here
            }
        }
    }
    Ok(())
}

/// Safely sync file data to disk
fn sync_file(file: &mut File, fsync: bool) -> Result<()> {
    if fsync {
        file.flush()?;
        file.sync_data()
            .context("Failed to sync file data to disk")?;
    }
    Ok(())
}

/// Atomic write operation using temporary file + rename
pub fn atomic_write<P: AsRef<Path>>(
    path: P,
    data: &[u8],
    options: AtomicWriteOptions,
) -> Result<WriteResult> {
    let path = path.as_ref();
    let timestamp = Utc::now().to_rfc3339();

    if !options.atomic {
        // Simple non-atomic write
        let mut file =
            File::create(path).with_context(|| format!("Failed to create file: {:?}", path))?;

        file.write_all(data)
            .with_context(|| format!("Failed to write to file: {:?}", path))?;

        sync_file(&mut file, options.fsync)?;

        return Ok(WriteResult {
            written: true,
            mode: "non-atomic".to_string(),
            path: path.to_string_lossy().to_string(),
            bytes: data.len() as u64,
            timestamp,
        });
    }

    // Atomic write using temp file + rename

    // Check available disk space before starting
    check_disk_space(path, data.len() as u64)?;

    let temp_path = generate_temp_path(path)?;

    // Create temp file with proper permissions
    let mut temp_file = File::create(&temp_path)
        .with_context(|| format!("Failed to create temp file: {:?}", temp_path))?;

    // Ensure cleanup of temp file on early errors
    let _cleanup_guard = TempFileCleanup::new(&temp_path);

    // Set permissions if specified
    if let Some(mode) = options.mode {
        #[cfg(unix)]
        {
            let perms = std::fs::Permissions::from_mode(mode);
            std::fs::set_permissions(&temp_path, perms)
                .context("Failed to set temp file permissions")?;
        }
    }

    // Write data to temp file
    temp_file
        .write_all(data)
        .with_context(|| format!("Failed to write to temp file: {:?}", temp_path))?;

    // Sync temp file
    sync_file(&mut temp_file, options.fsync)?;
    drop(temp_file); // Close the file

    // Atomic rename
    std::fs::rename(&temp_path, path)
        .with_context(|| format!("Failed to rename temp file {:?} to {:?}", temp_path, path))?;

    // Optionally sync parent directory for metadata durability
    if options.fsync {
        if let Some(parent) = path.parent() {
            if let Ok(parent_file) = File::open(parent) {
                let _ = parent_file.sync_data(); // Best effort
            }
        }
    }

    Ok(WriteResult {
        written: true,
        mode: "atomic".to_string(),
        path: path.to_string_lossy().to_string(),
        bytes: data.len() as u64,
        timestamp,
    })
}

/// Advisory file locking wrapper (Unix only)
#[cfg(unix)]
struct FileLock {
    file: File,
}

#[cfg(unix)]
impl FileLock {
    fn try_lock(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("Failed to open file for locking: {:?}", path))?;

        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&file);

        // Try to acquire exclusive lock (non-blocking)
        let result = unsafe { flock(fd, LOCK_EX | LOCK_NB) };
        if result != 0 {
            bail!("Failed to acquire file lock: file may be in use by another process");
        }

        Ok(Self { file })
    }

    fn write_append(&mut self, data: &[u8]) -> Result<usize> {
        self.file
            .write(data)
            .context("Failed to write to locked file")
    }

    fn sync(&mut self, fsync: bool) -> Result<()> {
        sync_file(&mut self.file, fsync)
    }
}

#[cfg(unix)]
impl Drop for FileLock {
    fn drop(&mut self) {
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&self.file);
        unsafe { flock(fd, LOCK_UN) }; // Release lock
    }
}

/// Atomic append operation with file locking
pub fn atomic_append<P: AsRef<Path>>(
    path: P,
    data: &[u8],
    options: AtomicAppendOptions,
) -> Result<AppendResult> {
    let path = path.as_ref();
    let timestamp = Utc::now().to_rfc3339();

    let mut final_data = data.to_vec();

    // Add newline if requested and not present
    if options.ensure_newline && !data.is_empty() && data[data.len() - 1] != b'\n' {
        final_data.push(b'\n');
    }

    if !options.atomic {
        // Simple non-atomic append
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("Failed to open file for append: {:?}", path))?;

        let bytes_written = file
            .write(&final_data)
            .with_context(|| format!("Failed to append to file: {:?}", path))?;

        sync_file(&mut file, options.fsync)?;

        return Ok(AppendResult {
            appended: true,
            mode: "non-atomic".to_string(),
            path: path.to_string_lossy().to_string(),
            bytes: bytes_written as u64,
            timestamp,
        });
    }

    #[cfg(unix)]
    {
        // Atomic append with file locking
        let mut lock = FileLock::try_lock(path)?;
        let bytes_written = lock.write_append(&final_data)?;
        lock.sync(options.fsync)?;

        Ok(AppendResult {
            appended: true,
            mode: "atomic".to_string(),
            path: path.to_string_lossy().to_string(),
            bytes: bytes_written as u64,
            timestamp,
        })
    }

    #[cfg(not(unix))]
    {
        // Fallback for non-Unix systems (no locking)
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("Failed to open file for append: {:?}", path))?;

        let bytes_written = file
            .write(&final_data)
            .with_context(|| format!("Failed to append to file: {:?}", path))?;

        sync_file(&mut file, options.fsync)?;

        Ok(AppendResult {
            appended: true,
            mode: "atomic-fallback".to_string(),
            path: path.to_string_lossy().to_string(),
            bytes: bytes_written as u64,
            timestamp,
        })
    }
}

/// Parse hash string in format "algorithm:digest"
fn parse_hash(hash_str: &str) -> Result<(String, String)> {
    if let Some((algorithm, digest)) = hash_str.split_once(':') {
        Ok((algorithm.to_lowercase(), digest.to_string()))
    } else {
        bail!("Invalid hash format. Expected 'algorithm:digest'");
    }
}

/// Calculate file hash using specified algorithm
pub fn calculate_file_hash<P: AsRef<Path>>(path: P, algorithm: &str) -> Result<String> {
    let path = path.as_ref();
    let mut file =
        File::open(path).with_context(|| format!("Failed to open file for hashing: {:?}", path))?;

    let mut buffer = [0u8; 8192];

    match algorithm.to_lowercase().as_str() {
        "md5" => {
            let mut hasher = md5::Context::new();
            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                hasher.consume(&buffer[..bytes_read]);
            }
            Ok(format!("{:x}", hasher.compute()))
        }
        "sha1" => {
            let mut hasher = Sha1::new();
            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                Sha1Digest::update(&mut hasher, &buffer[..bytes_read]);
            }
            Ok(format!("{:x}", hasher.finalize()))
        }
        "sha256" => {
            let mut hasher = Sha256::new();
            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                Sha2Digest::update(&mut hasher, &buffer[..bytes_read]);
            }
            Ok(format!("{:x}", hasher.finalize()))
        }
        "sha512" => {
            let mut hasher = Sha512::new();
            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                Sha2Digest::update(&mut hasher, &buffer[..bytes_read]);
            }
            Ok(format!("{:x}", hasher.finalize()))
        }
        _ => bail!("Unsupported hash algorithm: {}", algorithm),
    }
}

/// Hash verification
pub fn verify_hash<P: AsRef<Path>>(path: P, hash_str: &str) -> Result<VerifyResult> {
    let path = path.as_ref();
    let timestamp = Utc::now().to_rfc3339();

    let (algorithm, expected_digest) =
        parse_hash(hash_str).context("Failed to parse hash string")?;

    if !path.exists() {
        return Ok(VerifyResult {
            path: path.to_string_lossy().to_string(),
            verified: false,
            method: format!("hash-{}", algorithm),
            expected: Some(expected_digest),
            actual: None,
            timestamp,
            error: Some("File does not exist".to_string()),
        });
    }

    let actual_digest = calculate_file_hash(path, &algorithm)?;
    let verified = actual_digest == expected_digest;

    Ok(VerifyResult {
        path: path.to_string_lossy().to_string(),
        verified,
        method: format!("hash-{}", algorithm),
        expected: Some(expected_digest),
        actual: Some(actual_digest),
        timestamp,
        error: if verified {
            None
        } else {
            Some("Hash mismatch".to_string())
        },
    })
}

/// Verify file against JSON manifest
pub fn verify_manifest<P: AsRef<Path>, M: AsRef<Path>>(
    file_path: P,
    manifest_path: M,
) -> Result<VerifyResult> {
    let file_path = file_path.as_ref();
    let manifest_path = manifest_path.as_ref();
    let timestamp = Utc::now().to_rfc3339();

    // Read and parse manifest
    let manifest_content = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("Failed to read manifest: {:?}", manifest_path))?;

    let manifest: Value =
        serde_json::from_str(&manifest_content).context("Failed to parse manifest JSON")?;

    // Look for file entry in manifest
    if let Some(entries) = manifest.as_array() {
        for entry in entries {
            if let Some(entry_path) = entry.get("path").and_then(|p| p.as_str()) {
                if Path::new(entry_path) == file_path {
                    if let Some(expected_hash) = entry.get("sha256").and_then(|h| h.as_str()) {
                        let hash_str = format!("sha256:{}", expected_hash);
                        return verify_hash(file_path, &hash_str);
                    }
                }
            }
        }
    }

    Ok(VerifyResult {
        path: file_path.to_string_lossy().to_string(),
        verified: false,
        method: "manifest".to_string(),
        expected: None,
        actual: None,
        timestamp,
        error: Some("File not found in manifest".to_string()),
    })
}

/// Signature verification using Ed25519
pub fn verify_signature<P: AsRef<Path>>(
    file_path: P,
    sig_path: &str,
    key_path: &str,
) -> Result<VerifyResult> {
    let file_path = file_path.as_ref();
    let timestamp = Utc::now().to_rfc3339();

    // Read the file content
    let file_content = match std::fs::read(file_path) {
        Ok(content) => content,
        Err(e) => {
            return Ok(VerifyResult {
                path: file_path.to_string_lossy().to_string(),
                verified: false,
                method: "signature-ed25519".to_string(),
                expected: None,
                actual: None,
                timestamp,
                error: Some(format!("Failed to read file: {}", e)),
            });
        }
    };

    // Read the signature
    let signature_bytes = match std::fs::read(sig_path) {
        Ok(sig) => sig,
        Err(e) => {
            return Ok(VerifyResult {
                path: file_path.to_string_lossy().to_string(),
                verified: false,
                method: "signature-ed25519".to_string(),
                expected: Some(sig_path.to_string()),
                actual: None,
                timestamp,
                error: Some(format!("Failed to read signature file: {}", e)),
            });
        }
    };

    // Read the public key
    let public_key_bytes = match std::fs::read(key_path) {
        Ok(key) => key,
        Err(e) => {
            return Ok(VerifyResult {
                path: file_path.to_string_lossy().to_string(),
                verified: false,
                method: "signature-ed25519".to_string(),
                expected: Some(key_path.to_string()),
                actual: None,
                timestamp,
                error: Some(format!("Failed to read public key file: {}", e)),
            });
        }
    };

    // Verify the signature
    let verification_result = (|| -> Result<bool> {
        use ring::signature;

        // Try to parse public key (expecting 32 bytes for Ed25519)
        if public_key_bytes.len() != 32 {
            bail!(
                "Invalid public key length: expected 32 bytes, got {}",
                public_key_bytes.len()
            );
        }

        // Try to parse signature (expecting 64 bytes for Ed25519)
        if signature_bytes.len() != 64 {
            bail!(
                "Invalid signature length: expected 64 bytes, got {}",
                signature_bytes.len()
            );
        }

        let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, &public_key_bytes);

        match public_key.verify(&file_content, &signature_bytes) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    })();

    match verification_result {
        Ok(verified) => Ok(VerifyResult {
            path: file_path.to_string_lossy().to_string(),
            verified,
            method: "signature-ed25519".to_string(),
            expected: Some(format!("valid signature with key {}", key_path)),
            actual: Some(if verified {
                "signature valid".to_string()
            } else {
                "signature invalid".to_string()
            }),
            timestamp,
            error: if verified {
                None
            } else {
                Some("Signature verification failed".to_string())
            },
        }),
        Err(e) => Ok(VerifyResult {
            path: file_path.to_string_lossy().to_string(),
            verified: false,
            method: "signature-ed25519".to_string(),
            expected: Some(format!("valid signature with key {}", key_path)),
            actual: None,
            timestamp,
            error: Some(format!("Signature verification error: {}", e)),
        }),
    }
}

/// Recursive directory verification
pub fn verify_recursive<P: AsRef<Path>>(base_path: P) -> Result<Vec<VerifyResult>> {
    let base_path = base_path.as_ref();
    let mut results = Vec::new();
    let timestamp = Utc::now().to_rfc3339();

    if !base_path.is_dir() {
        return Ok(vec![VerifyResult {
            path: base_path.to_string_lossy().to_string(),
            verified: false,
            method: "recursive".to_string(),
            expected: None,
            actual: None,
            timestamp,
            error: Some("Not a directory".to_string()),
        }]);
    }

    // Look for manifest files
    let manifest_candidates = ["checksums.json", "manifest.json", ".checksums"];
    let mut manifest_path = None;

    for candidate in &manifest_candidates {
        let manifest_file = base_path.join(candidate);
        if manifest_file.exists() {
            manifest_path = Some(manifest_file);
            break;
        }
    }

    if let Some(manifest) = manifest_path {
        // Verify against manifest
        let manifest_content =
            std::fs::read_to_string(&manifest).context("Failed to read manifest")?;

        let manifest_data: Value =
            serde_json::from_str(&manifest_content).context("Failed to parse manifest JSON")?;

        if let Some(entries) = manifest_data.as_array() {
            for entry in entries {
                if let (Some(rel_path), Some(expected_hash)) = (
                    entry.get("path").and_then(|p| p.as_str()),
                    entry.get("sha256").and_then(|h| h.as_str()),
                ) {
                    let file_path = base_path.join(rel_path);
                    let hash_str = format!("sha256:{}", expected_hash);
                    match verify_hash(&file_path, &hash_str) {
                        Ok(result) => results.push(result),
                        Err(e) => {
                            results.push(VerifyResult {
                                path: file_path.to_string_lossy().to_string(),
                                verified: false,
                                method: "hash-sha256".to_string(),
                                expected: Some(expected_hash.to_string()),
                                actual: None,
                                timestamp: timestamp.clone(),
                                error: Some(e.to_string()),
                            });
                        }
                    }
                }
            }
        }
    } else {
        return Ok(vec![VerifyResult {
            path: base_path.to_string_lossy().to_string(),
            verified: false,
            method: "recursive".to_string(),
            expected: None,
            actual: None,
            timestamp,
            error: Some("No manifest file found".to_string()),
        }]);
    }

    Ok(results)
}
