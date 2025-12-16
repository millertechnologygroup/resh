use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::os::unix::fs::symlink;

use super::types::{InstalledPlugin, ArtifactCandidate, EnabledRegistry};

/// Plugin store manages local plugin installation paths, versioning, and current symlinks
pub struct PluginStore {
    plugins_dir: PathBuf,
}

impl PluginStore {
    /// Create a new plugin store instance
    pub fn new() -> Result<Self> {
        let plugins_dir = Self::default_plugins_dir()?;
        fs::create_dir_all(&plugins_dir)
            .with_context(|| format!("Failed to create plugins directory: {:?}", plugins_dir))?;
        
        Ok(Self { plugins_dir })
    }

    /// Create plugin store with custom directory
    pub fn with_dir<P: AsRef<Path>>(plugins_dir: P) -> Result<Self> {
        let plugins_dir = plugins_dir.as_ref().to_path_buf();
        fs::create_dir_all(&plugins_dir)
            .with_context(|| format!("Failed to create plugins directory: {:?}", plugins_dir))?;
        
        Ok(Self { plugins_dir })
    }

    /// Get default plugins directory
    pub fn default_plugins_dir() -> Result<PathBuf> {
        if let Some(data_dir) = dirs::data_local_dir() {
            Ok(data_dir.join("resh").join("plugins"))
        } else {
            Ok(PathBuf::from("/tmp/resh-plugins"))
        }
    }

    /// Get plugin root directory
    pub fn plugin_root(&self, plugin_id: &str) -> PathBuf {
        self.plugins_dir.join(plugin_id)
    }

    /// Get plugin version directory
    pub fn plugin_version_dir(&self, plugin_id: &str, version: &str) -> PathBuf {
        self.plugin_root(plugin_id).join("versions").join(version)
    }

    /// Get staging directory for plugin
    pub fn staging_dir(&self, plugin_id: &str) -> Result<PathBuf> {
        let staging = self.plugin_root(plugin_id).join(".staging").join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&staging)
            .with_context(|| format!("Failed to create staging directory: {:?}", staging))?;
        Ok(staging)
    }

    /// Get current symlink path
    pub fn current_link(&self, plugin_id: &str) -> PathBuf {
        self.plugin_root(plugin_id).join("current")
    }

    /// Get installed plugin metadata file path
    pub fn metadata_file(&self, plugin_id: &str, version: &str) -> PathBuf {
        self.plugin_version_dir(plugin_id, version).join("metadata.json")
    }

    /// Check if plugin is installed
    pub fn is_installed(&self, plugin_id: &str) -> bool {
        self.current_link(plugin_id).exists()
    }

    /// Get currently installed version
    pub fn get_installed_version(&self, plugin_id: &str) -> Result<Option<String>> {
        let current_link = self.current_link(plugin_id);
        
        if !current_link.exists() {
            return Ok(None);
        }

        let target = fs::read_link(&current_link)
            .with_context(|| format!("Failed to read current symlink: {:?}", current_link))?;
        
        // Extract version from versions/<version> path
        if let Some(version) = target.file_name().and_then(|n| n.to_str()) {
            Ok(Some(version.to_string()))
        } else {
            Err(anyhow!("Invalid current symlink target: {:?}", target))
        }
    }

    /// Get installed plugin metadata
    pub fn get_installed_metadata(&self, plugin_id: &str) -> Result<Option<InstalledPlugin>> {
        let version = match self.get_installed_version(plugin_id)? {
            Some(v) => v,
            None => return Ok(None),
        };

        let metadata_file = self.metadata_file(plugin_id, &version);
        if !metadata_file.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&metadata_file)
            .with_context(|| format!("Failed to read metadata file: {:?}", metadata_file))?;
        
        let metadata: InstalledPlugin = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse metadata file: {:?}", metadata_file))?;
        
        Ok(Some(metadata))
    }

    /// Install plugin to version directory
    pub fn install_plugin(
        &self,
        plugin_id: &str,
        version: &str,
        artifact: &ArtifactCandidate,
        extracted_path: &Path,
        source: &str,
    ) -> Result<InstalledPlugin> {
        let version_dir = self.plugin_version_dir(plugin_id, version);
        
        // Remove existing version directory if it exists
        if version_dir.exists() {
            fs::remove_dir_all(&version_dir)
                .with_context(|| format!("Failed to remove existing version dir: {:?}", version_dir))?;
        }

        // Create version directory
        fs::create_dir_all(&version_dir)
            .with_context(|| format!("Failed to create version directory: {:?}", version_dir))?;

        // Copy extracted files to version directory
        self.copy_directory(extracted_path, &version_dir)
            .with_context(|| "Failed to copy plugin files")?;

        // Find binary path
        let bin_path = self.find_binary_path(&version_dir)?;

        // Make binary executable
        if let Some(ref bin_path) = bin_path {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(bin_path)?.permissions();
                perms.set_mode(perms.mode() | 0o755);
                fs::set_permissions(bin_path, perms)?;
            }
        }

        // Create metadata
        let metadata = InstalledPlugin {
            plugin_id: plugin_id.to_string(),
            version: version.to_string(),
            install_path: version_dir.to_string_lossy().to_string(),
            bin_path: bin_path.as_ref().map(|p| p.to_string_lossy().to_string()),
            installed_at: chrono::Utc::now().to_rfc3339(),
            source: source.to_string(),
            sha256: artifact.sha256.clone(),
        };

        // Save metadata
        let metadata_file = self.metadata_file(plugin_id, version);
        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        fs::write(&metadata_file, metadata_json)
            .with_context(|| format!("Failed to write metadata file: {:?}", metadata_file))?;

        Ok(metadata)
    }

    /// Activate a specific version as current
    pub fn activate_version(&self, plugin_id: &str, version: &str) -> Result<()> {
        let version_dir = self.plugin_version_dir(plugin_id, version);
        let current_link = self.current_link(plugin_id);

        if !version_dir.exists() {
            return Err(anyhow!("Version directory does not exist: {:?}", version_dir));
        }

        // Remove existing current link if it exists
        if current_link.exists() {
            fs::remove_file(&current_link)
                .with_context(|| format!("Failed to remove current link: {:?}", current_link))?;
        }

        // Create relative symlink to versions/<version>
        let relative_target = PathBuf::from("versions").join(version);
        symlink(&relative_target, &current_link)
            .with_context(|| format!("Failed to create current symlink: {:?}", current_link))?;

        Ok(())
    }

    /// List all installed versions for a plugin
    pub fn list_versions(&self, plugin_id: &str) -> Result<Vec<String>> {
        let versions_dir = self.plugin_root(plugin_id).join("versions");
        
        if !versions_dir.exists() {
            return Ok(Vec::new());
        }

        let mut versions = Vec::new();
        for entry in fs::read_dir(&versions_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    versions.push(name.to_string());
                }
            }
        }

        // Sort versions
        versions.sort();
        Ok(versions)
    }

    /// Cleanup staging directory
    pub fn cleanup_staging(&self, plugin_id: &str) -> Result<()> {
        let staging_root = self.plugin_root(plugin_id).join(".staging");
        if staging_root.exists() {
            fs::remove_dir_all(&staging_root)
                .with_context(|| format!("Failed to cleanup staging: {:?}", staging_root))?;
        }
        Ok(())
    }

    /// Rollback to previous version if available
    pub fn rollback_to_previous(&self, plugin_id: &str, current_version: &str) -> Result<Option<String>> {
        let versions = self.list_versions(plugin_id)?;
        
        // Find the previous version (latest version that's not the current one)
        let mut available: Vec<_> = versions
            .into_iter()
            .filter(|v| v != current_version)
            .collect();
        
        available.sort();
        
        if let Some(previous_version) = available.last() {
            self.activate_version(plugin_id, previous_version)?;
            Ok(Some(previous_version.clone()))
        } else {
            Ok(None)
        }
    }

    /// Remove an installed plugin completely
    pub fn remove_plugin(&self, plugin_id: &str, version: Option<&str>) -> Result<Vec<PathBuf>> {
        let mut removed_paths = Vec::new();
        
        // If version specified, only remove that version
        if let Some(specific_version) = version {
            let version_dir = self.plugin_version_dir(plugin_id, specific_version);
            if version_dir.exists() {
                removed_paths.push(version_dir.clone());
                fs::remove_dir_all(&version_dir)
                    .with_context(|| format!("Failed to remove version directory: {:?}", version_dir))?;
            }
        }
        
        // Remove current link
        let current_link = self.current_link(plugin_id);
        if current_link.exists() {
            removed_paths.push(current_link.clone());
            fs::remove_file(&current_link)
                .with_context(|| format!("Failed to remove current link: {:?}", current_link))?;
        }
        
        // Remove entire plugin directory if no specific version was requested
        if version.is_none() {
            let plugin_root = self.plugin_root(plugin_id);
            if plugin_root.exists() {
                removed_paths.push(plugin_root.clone());
                fs::remove_dir_all(&plugin_root)
                    .with_context(|| format!("Failed to remove plugin root: {:?}", plugin_root))?;
            }
        }
        
        Ok(removed_paths)
    }

    /// Remove plugin state/cache/config directories (purge)
    pub fn purge_plugin_data(&self, plugin_id: &str) -> Result<Vec<PathBuf>> {
        let mut purged_paths = Vec::new();
        
        // Get XDG directories
        let state_dir = dirs::state_dir()
            .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".local/state"));
        let cache_dir = dirs::cache_dir()
            .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".cache"));
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".config"));
        
        // Plugin-specific directories to purge
        let purge_paths = [
            state_dir.join("resh/plugins").join(plugin_id),
            cache_dir.join("resh/plugins").join(plugin_id),
            config_dir.join("resh/plugins").join(plugin_id),
        ];
        
        for path in &purge_paths {
            if path.exists() {
                purged_paths.push(path.clone());
                fs::remove_dir_all(path)
                    .with_context(|| format!("Failed to purge plugin data: {:?}", path))?;
            }
        }
        
        Ok(purged_paths)
    }

    /// Get plugin lock file path
    pub fn lock_file(&self, plugin_id: &str) -> PathBuf {
        self.plugins_dir.join("locks").join(format!("{}.lock", plugin_id))
    }

    /// Create lock file for plugin operation
    pub fn create_lock(&self, plugin_id: &str) -> Result<std::fs::File> {
        let lock_file = self.lock_file(plugin_id);
        
        // Ensure locks directory exists
        if let Some(parent) = lock_file.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create locks directory: {:?}", parent))?;
        }
        
        // Create exclusive lock file
        use std::fs::OpenOptions;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_file)
            .with_context(|| format!("Failed to acquire lock for plugin: {}", plugin_id))?;
        
        Ok(file)
    }

    /// Remove lock file
    pub fn remove_lock(&self, plugin_id: &str) -> Result<()> {
        let lock_file = self.lock_file(plugin_id);
        if lock_file.exists() {
            fs::remove_file(&lock_file)
                .with_context(|| format!("Failed to remove lock file: {:?}", lock_file))?;
        }
        Ok(())
    }

    /// Get binary path for currently installed plugin
    pub fn get_current_binary_path(&self, plugin_id: &str) -> Result<Option<PathBuf>> {
        if let Some(metadata) = self.get_installed_metadata(plugin_id)? {
            if let Some(bin_path) = metadata.bin_path {
                return Ok(Some(PathBuf::from(bin_path)));
            }
        }
        
        // Try to find binary via current link
        let current_link = self.current_link(plugin_id);
        if current_link.exists() {
            let target = fs::read_link(&current_link)?;
            let version_dir = self.plugin_root(plugin_id).join(target);
            return self.find_binary_path(&version_dir);
        }
        
        Ok(None)
    }

    /// List all files in plugin installation
    pub fn list_plugin_files(&self, plugin_id: &str, version: &str) -> Result<Vec<PathBuf>> {
        let version_dir = self.plugin_version_dir(plugin_id, version);
        let mut files = Vec::new();
        
        if version_dir.exists() {
            self.collect_files(&version_dir, &mut files)?;
            // Sort for deterministic output
            files.sort();
        }
        
        Ok(files)
    }

    /// Recursively collect all files in directory
    fn collect_files(&self, dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() {
                files.push(path);
            } else if path.is_dir() {
                self.collect_files(&path, files)?;
            }
        }
        Ok(())
    }

    /// Copy directory recursively
    fn copy_directory(&self, src: &Path, dst: &Path) -> Result<()> {
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());

            if src_path.is_dir() {
                fs::create_dir_all(&dst_path)?;
                self.copy_directory(&src_path, &dst_path)?;
            } else {
                fs::copy(&src_path, &dst_path)?;
            }
        }
        Ok(())
    }

    /// Find binary path within installed plugin
    fn find_binary_path(&self, install_dir: &Path) -> Result<Option<PathBuf>> {
        // Look for common binary locations
        let possible_paths = vec![
            install_dir.join("bin").join("plugin"),
            install_dir.join("plugin"),
            install_dir.join(format!("bin/{}-{}/plugin", std::env::consts::OS, std::env::consts::ARCH)),
        ];

        for path in possible_paths {
            if path.exists() && path.is_file() {
                return Ok(Some(path));
            }
        }

        // Look for any executable file
        if let Ok(entries) = fs::read_dir(install_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if let Ok(metadata) = path.metadata() {
                            if metadata.permissions().mode() & 0o111 != 0 {
                                return Ok(Some(path));
                            }
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        return Ok(Some(path));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Get enabled registry file path for scope
    pub fn enabled_registry_path(&self, scope: &str) -> Result<PathBuf> {
        match scope {
            "user" => {
                let config_dir = dirs::config_dir()
                    .ok_or_else(|| anyhow!("Could not determine config directory"))?;
                let registry_dir = config_dir.join("resh").join("plugins");
                fs::create_dir_all(&registry_dir)
                    .with_context(|| format!("Failed to create registry directory: {:?}", registry_dir))?;
                Ok(registry_dir.join("enabled.json"))
            }
            "system" => Ok(PathBuf::from("/etc/resh/plugins/enabled.json")),
            _ => Err(anyhow!("Invalid scope: {}. Must be 'user' or 'system'", scope))
        }
    }

    /// Load enabled registry from disk
    pub fn load_enabled_registry(&self, scope: &str) -> Result<EnabledRegistry> {
        let registry_path = self.enabled_registry_path(scope)?;
        
        if !registry_path.exists() {
            return Ok(EnabledRegistry::new());
        }

        let contents = fs::read_to_string(&registry_path)
            .with_context(|| format!("Failed to read enabled registry: {:?}", registry_path))?;

        if contents.trim().is_empty() {
            return Ok(EnabledRegistry::new());
        }

        let registry: EnabledRegistry = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse enabled registry JSON: {:?}", registry_path))?;

        Ok(registry)
    }

    /// Save enabled registry to disk using atomic write
    pub fn save_enabled_registry(&self, scope: &str, registry: &EnabledRegistry) -> Result<()> {
        let registry_path = self.enabled_registry_path(scope)?;
        
        // Create parent directory if needed
        if let Some(parent) = registry_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create parent directory: {:?}", parent))?;
        }

        // Serialize to JSON with stable ordering
        let json_content = serde_json::to_string_pretty(registry)
            .context("Failed to serialize enabled registry")?;

        // Atomic write: write to temp file then rename
        let temp_path = registry_path.with_extension("enabled.json.tmp");
        fs::write(&temp_path, &json_content)
            .with_context(|| format!("Failed to write temp registry file: {:?}", temp_path))?;
        
        // Best effort fsync
        if let Ok(file) = std::fs::File::open(&temp_path) {
            let _ = file.sync_all();
        }

        fs::rename(&temp_path, &registry_path)
            .with_context(|| format!("Failed to rename temp file to registry: {:?}", registry_path))?;

        Ok(())
    }

    /// Check if a plugin is enabled in the registry
    pub fn is_plugin_enabled(&self, plugin_id: &str, scope: &str) -> Result<bool> {
        let registry = self.load_enabled_registry(scope)?;
        Ok(registry.is_enabled(plugin_id))
    }

    /// Get the enabled version of a plugin
    pub fn get_enabled_version(&self, plugin_id: &str, scope: &str) -> Result<Option<String>> {
        let registry = self.load_enabled_registry(scope)?;
        Ok(registry.get_enabled_version(plugin_id).map(|s| s.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_plugin_store_creation() {
        let temp_dir = TempDir::new().unwrap();
        let store = PluginStore::with_dir(temp_dir.path()).unwrap();
        assert!(temp_dir.path().exists());
    }

    #[test]
    fn test_plugin_paths() {
        let temp_dir = TempDir::new().unwrap();
        let store = PluginStore::with_dir(temp_dir.path()).unwrap();
        
        let root = store.plugin_root("test-plugin");
        let version_dir = store.plugin_version_dir("test-plugin", "1.0.0");
        let current_link = store.current_link("test-plugin");
        
        assert_eq!(root, temp_dir.path().join("test-plugin"));
        assert_eq!(version_dir, temp_dir.path().join("test-plugin").join("versions").join("1.0.0"));
        assert_eq!(current_link, temp_dir.path().join("test-plugin").join("current"));
    }

    #[test]
    fn test_is_installed() {
        let temp_dir = TempDir::new().unwrap();
        let store = PluginStore::with_dir(temp_dir.path()).unwrap();
        
        assert!(!store.is_installed("test-plugin"));
        
        // Create a current symlink
        let plugin_root = store.plugin_root("test-plugin");
        let versions_dir = plugin_root.join("versions").join("1.0.0");
        fs::create_dir_all(&versions_dir).unwrap();
        
        let current_link = store.current_link("test-plugin");
        symlink("versions/1.0.0", &current_link).unwrap();
        
        assert!(store.is_installed("test-plugin"));
        assert_eq!(store.get_installed_version("test-plugin").unwrap(), Some("1.0.0".to_string()));
    }
}