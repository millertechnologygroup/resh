use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use super::types::{ArtifactCandidate, EnabledRegistry, InstalledPlugin};

/// Longest plugin id or version accepted as a store path component.
const MAX_COMPONENT_LEN: usize = 128;

/// Directory names inside the plugins directory that are not plugins.
const RESERVED_PLUGIN_IDS: &[&str] = &["locks"];

/// Check that a plugin id or version (`kind`) is safe to use as exactly one
/// path component inside the plugin store.
///
/// Ids and versions come from URLs and from registry or catalog JSON, so they
/// are untrusted. Accepted: 1-128 ASCII characters from `[A-Za-z0-9._+-]`,
/// starting with a letter or digit. That covers ids such as `aws` or
/// `my-helper` and versions such as `1.2.0`, `v2.0.0-rc.1` or `1.0.0+build.5`,
/// and excludes separators, `.`/`..`, hidden names, leading dashes, NUL,
/// percent-encoding and backslashes. Unsafe values are rejected, never
/// rewritten.
pub fn validate_path_component(kind: &str, value: &str) -> Result<()> {
    let bad = |why: &str| Err(anyhow!("Invalid plugin {}: {:?} ({})", kind, value, why));
    if value.is_empty() {
        return bad("must not be empty");
    }
    if value.len() > MAX_COMPONENT_LEN {
        return bad("too long");
    }
    if !value.as_bytes()[0].is_ascii_alphanumeric() {
        return bad("must start with a letter or digit");
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
    {
        return bad("only letters, digits and . _ + - are allowed");
    }
    Ok(())
}

/// Map a path taken from a plugin artifact to a relative path made only of
/// normal components. `.` components are dropped; an empty result (the
/// artifact root itself) is `None`. Absolute paths, `..` and prefixes are
/// rejected, never rewritten.
pub(crate) fn artifact_relative_path(path: &Path) -> Result<Option<PathBuf>> {
    let mut rel = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::Normal(c) => rel.push(c),
            std::path::Component::CurDir => {}
            _ => {
                return Err(anyhow!(
                    "Refusing plugin artifact path {:?}: it must stay inside the artifact",
                    path
                ));
            }
        }
    }
    Ok(if rel.as_os_str().is_empty() {
        None
    } else {
        Some(rel)
    })
}

/// Create `root/rel` one directory at a time. An existing component must be
/// a real directory; a symlink or any other file type is refused.
pub(crate) fn create_dirs_no_follow(root: &Path, rel: &Path) -> Result<()> {
    let mut cur = root.to_path_buf();
    for comp in rel.components() {
        match comp {
            std::path::Component::Normal(c) => cur.push(c),
            _ => return Err(anyhow!("Refusing unsafe plugin path {:?}", rel)),
        }
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_dir() => {}
            Ok(_) => {
                return Err(anyhow!(
                    "Refusing plugin path through a non-directory or symlink: {:?}",
                    cur
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&cur)
                    .with_context(|| format!("Failed to create directory {:?}", cur))?;
            }
            Err(e) => return Err(e).with_context(|| format!("Failed to inspect {:?}", cur)),
        }
    }
    Ok(())
}

/// Create a new file without following a symlink at its final component.
pub(crate) fn create_new_no_follow(path: &Path, mode: u32) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(mode)
        .open(path)
}

/// File mode for plugin files: 0755 if any execute bit is set, else 0644.
/// setuid, setgid, sticky and group/other write bits are never kept.
pub(crate) fn sanitized_mode(mode: u32) -> u32 {
    if mode & 0o111 != 0 { 0o755 } else { 0o644 }
}

fn validate_plugin_id(plugin_id: &str) -> Result<()> {
    validate_path_component("id", plugin_id)?;
    if RESERVED_PLUGIN_IDS.contains(&plugin_id) {
        return Err(anyhow!(
            "Invalid plugin id: {:?} (reserved name)",
            plugin_id
        ));
    }
    Ok(())
}

/// Test-only seam: redirects the default plugin store of the current thread
/// to a temporary directory, so handle-level tests never touch the user's
/// `~/.local/share/resh/plugins`. There is no equivalent outside `cfg(test)`.
#[cfg(test)]
pub(crate) mod test_seam {
    use std::cell::RefCell;
    use std::path::PathBuf;

    thread_local! {
        static PLUGINS_DIR: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    }

    pub fn plugins_dir() -> Option<PathBuf> {
        PLUGINS_DIR.with(|d| d.borrow().clone())
    }

    /// Active until the guard is dropped.
    pub struct Guard;

    pub fn install(dir: PathBuf) -> Guard {
        PLUGINS_DIR.with(|d| *d.borrow_mut() = Some(dir));
        Guard
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            PLUGINS_DIR.with(|d| *d.borrow_mut() = None);
        }
    }
}

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
        #[cfg(test)]
        if let Some(dir) = test_seam::plugins_dir() {
            return Ok(dir);
        }
        if let Some(data_dir) = dirs::data_local_dir() {
            Ok(data_dir.join("resh").join("plugins"))
        } else {
            Ok(PathBuf::from("/tmp/resh-plugins"))
        }
    }

    /// Fail unless every existing component of `path` below the plugins
    /// directory is a real directory or file, not a symlink, so that a
    /// planted link cannot redirect writes or deletes out of the store.
    /// `path` must be strictly inside the plugins directory.
    fn ensure_inside_store(&self, path: &Path) -> Result<()> {
        let rel = path
            .strip_prefix(&self.plugins_dir)
            .map_err(|_| anyhow!("Refusing path outside the plugin store: {:?}", path))?;
        if rel.as_os_str().is_empty() {
            return Err(anyhow!(
                "Refusing to operate on the plugin store root: {:?}",
                path
            ));
        }
        let mut cur = self.plugins_dir.clone();
        for comp in rel.components() {
            match comp {
                std::path::Component::Normal(c) => cur.push(c),
                _ => return Err(anyhow!("Refusing unsafe plugin store path: {:?}", path)),
            }
            match fs::symlink_metadata(&cur) {
                Ok(m) if m.file_type().is_symlink() => {
                    return Err(anyhow!(
                        "Refusing plugin store path through a symlink: {:?}",
                        cur
                    ));
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                Err(e) => return Err(e).with_context(|| format!("Failed to inspect {:?}", cur)),
            }
        }
        Ok(())
    }

    /// `remove_dir_all`, restricted to paths strictly inside the store that
    /// are not reached through a symlink.
    fn remove_tree(&self, path: &Path) -> Result<()> {
        self.ensure_inside_store(path)?;
        fs::remove_dir_all(path).with_context(|| format!("Failed to remove {:?}", path))
    }

    /// Validated plugin root (`<plugins>/<id>`).
    fn checked_plugin_root(&self, plugin_id: &str) -> Result<PathBuf> {
        validate_plugin_id(plugin_id)?;
        let root = self.plugin_root(plugin_id);
        self.ensure_inside_store(&root)?;
        Ok(root)
    }

    /// Validated version directory (`<plugins>/<id>/versions/<version>`).
    fn checked_version_dir(&self, plugin_id: &str, version: &str) -> Result<PathBuf> {
        validate_plugin_id(plugin_id)?;
        validate_path_component("version", version)?;
        let dir = self.plugin_version_dir(plugin_id, version);
        self.ensure_inside_store(&dir)?;
        Ok(dir)
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
        let staging = self
            .checked_plugin_root(plugin_id)?
            .join(".staging")
            .join(uuid::Uuid::new_v4().to_string());
        self.ensure_inside_store(&staging)?;
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
        self.plugin_version_dir(plugin_id, version)
            .join("metadata.json")
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
            validate_path_component("version", version)?;
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
        let version_dir = self.checked_version_dir(plugin_id, version)?;

        // Remove existing version directory if it exists (a dangling or
        // planted symlink is refused by remove_tree, not followed)
        if fs::symlink_metadata(&version_dir).is_ok() {
            self.remove_tree(&version_dir).with_context(|| {
                format!("Failed to remove existing version dir: {:?}", version_dir)
            })?;
        }

        // Create version directory
        fs::create_dir_all(&version_dir)
            .with_context(|| format!("Failed to create version directory: {:?}", version_dir))?;

        // Copy extracted files to version directory. A partial copy is
        // removed again so that no half-installed version is left behind.
        if let Err(e) = self.copy_directory(extracted_path, &version_dir) {
            let _ = self.remove_tree(&version_dir);
            return Err(e).with_context(|| "Failed to copy plugin files");
        }

        // Find binary path
        let bin_path = self.find_binary_path(&version_dir)?;

        // Make binary executable (it is a regular file inside the version
        // directory: copy_directory never creates links)
        if let Some(ref bin_path) = bin_path {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let meta = fs::symlink_metadata(bin_path)?;
                if !meta.file_type().is_file() {
                    return Err(anyhow!(
                        "Plugin binary is not a regular file: {:?}",
                        bin_path
                    ));
                }
                let mut perms = meta.permissions();
                perms.set_mode(sanitized_mode(perms.mode() | 0o755));
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
        let version_dir = self.checked_version_dir(plugin_id, version)?;
        let current_link = self.current_link(plugin_id);

        if !version_dir.exists() {
            return Err(anyhow!(
                "Version directory does not exist: {:?}",
                version_dir
            ));
        }

        // Remove existing current link if it exists (including a dangling one)
        if fs::symlink_metadata(&current_link).is_ok() {
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
        let versions_dir = self.checked_plugin_root(plugin_id)?.join("versions");

        if !versions_dir.exists() {
            return Ok(Vec::new());
        }

        let mut versions = Vec::new();
        for entry in fs::read_dir(&versions_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    if validate_path_component("version", name).is_ok() {
                        versions.push(name.to_string());
                    }
                }
            }
        }

        // Sort versions
        versions.sort();
        Ok(versions)
    }

    /// Cleanup staging directory
    pub fn cleanup_staging(&self, plugin_id: &str) -> Result<()> {
        let staging_root = self.checked_plugin_root(plugin_id)?.join(".staging");
        if fs::symlink_metadata(&staging_root).is_ok() {
            self.remove_tree(&staging_root)
                .with_context(|| format!("Failed to cleanup staging: {:?}", staging_root))?;
        }
        Ok(())
    }

    /// Rollback to previous version if available
    pub fn rollback_to_previous(
        &self,
        plugin_id: &str,
        current_version: &str,
    ) -> Result<Option<String>> {
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
        let plugin_root = self.checked_plugin_root(plugin_id)?;

        // If version specified, only remove that version
        if let Some(specific_version) = version {
            let version_dir = self.checked_version_dir(plugin_id, specific_version)?;
            if fs::symlink_metadata(&version_dir).is_ok() {
                removed_paths.push(version_dir.clone());
                self.remove_tree(&version_dir).with_context(|| {
                    format!("Failed to remove version directory: {:?}", version_dir)
                })?;
            }
        }

        // Remove current link (including a dangling one)
        let current_link = self.current_link(plugin_id);
        if fs::symlink_metadata(&current_link).is_ok() {
            removed_paths.push(current_link.clone());
            fs::remove_file(&current_link)
                .with_context(|| format!("Failed to remove current link: {:?}", current_link))?;
        }

        // Remove entire plugin directory if no specific version was requested
        if version.is_none() {
            if fs::symlink_metadata(&plugin_root).is_ok() {
                removed_paths.push(plugin_root.clone());
                self.remove_tree(&plugin_root)
                    .with_context(|| format!("Failed to remove plugin root: {:?}", plugin_root))?;
            }
        }

        Ok(removed_paths)
    }

    /// Remove plugin state/cache/config directories (purge)
    pub fn purge_plugin_data(&self, plugin_id: &str) -> Result<Vec<PathBuf>> {
        validate_plugin_id(plugin_id)?;
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
            if fs::symlink_metadata(path)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
            {
                return Err(anyhow!(
                    "Refusing to purge plugin data through a symlink: {:?}",
                    path
                ));
            }
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
        self.plugins_dir
            .join("locks")
            .join(format!("{}.lock", plugin_id))
    }

    /// Create lock file for plugin operation
    pub fn create_lock(&self, plugin_id: &str) -> Result<std::fs::File> {
        validate_plugin_id(plugin_id)?;
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
        validate_plugin_id(plugin_id)?;
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
        let version_dir = self.checked_version_dir(plugin_id, version)?;
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

    /// Copy directory recursively without following symlinks.
    ///
    /// Only regular files and directories are copied. Any symlink or other
    /// file type in the source fails the copy: following it could read a
    /// file outside the artifact into the plugin store.
    fn copy_directory(&self, src: &Path, dst: &Path) -> Result<()> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        if !fs::symlink_metadata(src)?.file_type().is_dir() {
            return Err(anyhow!(
                "Refusing to copy plugin files from a non-directory or symlink: {:?}",
                src
            ));
        }
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());
            let file_type = entry.file_type()?; // does not follow symlinks

            if file_type.is_dir() {
                create_dirs_no_follow(dst, Path::new(&entry.file_name()))?;
                self.copy_directory(&src_path, &dst_path)?;
            } else if file_type.is_file() {
                let mut input = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&src_path)
                    .with_context(|| format!("Failed to open plugin file {:?}", src_path))?;
                let mode = sanitized_mode(input.metadata()?.permissions().mode());
                let mut output = create_new_no_follow(&dst_path, mode)
                    .with_context(|| format!("Failed to create plugin file {:?}", dst_path))?;
                std::io::copy(&mut input, &mut output)?;
            } else {
                return Err(anyhow!(
                    "Refusing to install {:?}: plugin files must be regular files or directories, not symlinks or special files",
                    src_path
                ));
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
            install_dir.join(format!(
                "bin/{}-{}/plugin",
                std::env::consts::OS,
                std::env::consts::ARCH
            )),
        ];

        // symlink_metadata: a link is never taken as the plugin binary
        let is_regular = |p: &Path| {
            fs::symlink_metadata(p)
                .map(|m| m.file_type().is_file())
                .unwrap_or(false)
        };

        for path in possible_paths {
            if is_regular(&path) {
                return Ok(Some(path));
            }
        }

        // Look for any executable file
        if let Ok(entries) = fs::read_dir(install_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if is_regular(&path) {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if let Ok(metadata) = fs::symlink_metadata(&path)
                            && metadata.permissions().mode() & 0o111 != 0
                        {
                            return Ok(Some(path));
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
                fs::create_dir_all(&registry_dir).with_context(|| {
                    format!("Failed to create registry directory: {:?}", registry_dir)
                })?;
                Ok(registry_dir.join("enabled.json"))
            }
            "system" => Ok(PathBuf::from("/etc/resh/plugins/enabled.json")),
            _ => Err(anyhow!(
                "Invalid scope: {}. Must be 'user' or 'system'",
                scope
            )),
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

        let registry: EnabledRegistry = serde_json::from_str(&contents).with_context(|| {
            format!("Failed to parse enabled registry JSON: {:?}", registry_path)
        })?;

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

        fs::rename(&temp_path, &registry_path).with_context(|| {
            format!(
                "Failed to rename temp file to registry: {:?}",
                registry_path
            )
        })?;

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
        Ok(registry
            .get_enabled_version(plugin_id)
            .map(|s| s.to_string()))
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
        assert_eq!(
            version_dir,
            temp_dir
                .path()
                .join("test-plugin")
                .join("versions")
                .join("1.0.0")
        );
        assert_eq!(
            current_link,
            temp_dir.path().join("test-plugin").join("current")
        );
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
        assert_eq!(
            store.get_installed_version("test-plugin").unwrap(),
            Some("1.0.0".to_string())
        );
    }

    // SEC-02: untrusted ids and versions must never move store operations
    // outside the plugin store. Every test uses its own temporary sandbox:
    // <sandbox>/plugins is the store, <sandbox>/victim a sentinel outside it.

    fn sandbox() -> (TempDir, PluginStore, PathBuf) {
        let dir = TempDir::new().unwrap();
        let store = PluginStore::with_dir(dir.path().join("plugins")).unwrap();
        let victim = dir.path().join("victim");
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("keep.txt"), b"sentinel").unwrap();
        (dir, store, victim)
    }

    fn artifact() -> ArtifactCandidate {
        ArtifactCandidate {
            kind: "binary".into(),
            url: None,
            path: None,
            sha256: None,
            manifest: super::super::types::PluginManifest {
                name: "demo".into(),
                version: "1.0.0".into(),
                description: None,
                author: None,
                license: None,
                homepage: None,
                repository: None,
                keywords: None,
                platforms: Default::default(),
            },
        }
    }

    fn payload(dir: &Path) -> PathBuf {
        let src = dir.join("payload");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("plugin"), b"#!/bin/sh\n").unwrap();
        src
    }

    fn assert_sentinel_intact(victim: &Path) {
        assert_eq!(fs::read(victim.join("keep.txt")).unwrap(), b"sentinel");
        assert_eq!(
            fs::read_dir(victim).unwrap().count(),
            1,
            "victim dir was modified"
        );
    }

    #[test]
    fn valid_components_are_accepted() {
        for id in [
            "aws",
            "my-helper",
            "security-scanner",
            "demo",
            "Plugin_2",
            "a",
        ] {
            validate_plugin_id(id).unwrap_or_else(|e| panic!("{id}: {e}"));
        }
        for v in [
            "1.0.0",
            "0.1.0",
            "local",
            "unknown",
            "v2.0.0-rc.1",
            "1.0.0+build.5",
            "2024.10.16",
            "1.2.3-beta_1",
        ] {
            validate_path_component("version", v).unwrap_or_else(|e| panic!("{v}: {e}"));
        }
    }

    #[test]
    fn unsafe_components_are_rejected() {
        let long = "a".repeat(MAX_COMPONENT_LEN + 1);
        for bad in [
            "",
            ".",
            "..",
            "../x",
            "../../../../.ssh",
            "/etc",
            "/",
            "a/b",
            "a\\b",
            "..\\x",
            ".staging",
            ".hidden",
            "-rf",
            "+x",
            "%2e%2e",
            "%2fetc",
            "a\0b",
            "C:x",
            "a b",
            "a\nb",
            "~",
            "~root",
            "é",
            long.as_str(),
        ] {
            assert!(
                validate_path_component("version", bad).is_err(),
                "{bad:?} accepted"
            );
            assert!(validate_plugin_id(bad).is_err(), "{bad:?} accepted as id");
        }
        assert!(validate_plugin_id("locks").is_err());
    }

    #[test]
    fn install_with_traversal_version_touches_nothing_outside() {
        let (dir, store, victim) = sandbox();
        let src = payload(dir.path());
        for version in [
            "../../../victim",
            "../../victim",
            "/abs/path",
            "..",
            ".",
            "",
            "a/../../..",
        ] {
            assert!(
                store
                    .install_plugin("demo", version, &artifact(), &src, "test")
                    .is_err(),
                "{version:?}"
            );
            assert_sentinel_intact(&victim);
        }
        for id in ["../victim", "..", "/tmp", "a/b"] {
            assert!(
                store
                    .install_plugin(id, "1.0.0", &artifact(), &src, "test")
                    .is_err(),
                "{id:?}"
            );
            assert_sentinel_intact(&victim);
        }
    }

    #[test]
    fn remove_and_cleanup_refuse_unsafe_targets() {
        let (_dir, store, victim) = sandbox();
        assert!(
            store
                .remove_plugin("demo", Some("../../../victim"))
                .is_err()
        );
        assert!(store.remove_plugin("../victim", None).is_err());
        assert!(store.remove_plugin("..", None).is_err());
        assert!(store.remove_plugin("", None).is_err());
        assert!(store.cleanup_staging("../victim").is_err());
        assert!(store.purge_plugin_data("../victim").is_err());
        assert!(store.list_plugin_files("demo", "../../../victim").is_err());
        assert!(store.activate_version("demo", "../../../victim").is_err());
        assert!(store.create_lock("../victim").is_err());
        assert_sentinel_intact(&victim);
    }

    #[test]
    fn store_root_itself_is_never_removed() {
        let (_dir, store, _victim) = sandbox();
        assert!(store.remove_tree(&store.plugins_dir).is_err());
        assert!(
            store
                .remove_tree(store.plugins_dir.parent().unwrap())
                .is_err()
        );
        assert!(store.plugins_dir.is_dir());
    }

    #[test]
    fn symlinked_plugin_root_is_not_followed() {
        let (_dir, store, victim) = sandbox();
        // A planted <plugins>/demo -> victim link must not redirect
        // install, cleanup or removal into the victim directory.
        symlink(&victim, store.plugin_root("demo")).unwrap();
        let src = payload(_dir.path());
        assert!(
            store
                .install_plugin("demo", "1.0.0", &artifact(), &src, "test")
                .is_err()
        );
        assert!(store.cleanup_staging("demo").is_err());
        assert!(store.remove_plugin("demo", None).is_err());
        assert!(store.remove_plugin("demo", Some("1.0.0")).is_err());
        assert!(store.staging_dir("demo").is_err());
        assert_sentinel_intact(&victim);
    }

    #[test]
    fn symlinked_version_dir_is_not_followed() {
        let (dir, store, victim) = sandbox();
        let versions = store.plugin_root("demo").join("versions");
        fs::create_dir_all(&versions).unwrap();
        symlink(&victim, versions.join("1.0.0")).unwrap();
        let src = payload(dir.path());
        assert!(
            store
                .install_plugin("demo", "1.0.0", &artifact(), &src, "test")
                .is_err()
        );
        assert!(store.remove_plugin("demo", Some("1.0.0")).is_err());
        assert_sentinel_intact(&victim);
    }

    #[test]
    fn valid_install_replace_and_remove_still_work() {
        let (dir, store, victim) = sandbox();
        let src = payload(dir.path());
        let meta = store
            .install_plugin("demo", "1.0.0", &artifact(), &src, "test")
            .unwrap();
        assert_eq!(meta.version, "1.0.0");
        store.activate_version("demo", "1.0.0").unwrap();
        assert_eq!(
            store.get_installed_version("demo").unwrap().as_deref(),
            Some("1.0.0")
        );
        // Reinstalling the same version replaces the directory in place.
        store
            .install_plugin("demo", "1.0.0", &artifact(), &src, "test")
            .unwrap();
        store
            .install_plugin("demo", "1.1.0", &artifact(), &src, "test")
            .unwrap();
        assert_eq!(store.list_versions("demo").unwrap(), vec!["1.0.0", "1.1.0"]);
        store.staging_dir("demo").unwrap();
        store.cleanup_staging("demo").unwrap();
        let removed = store.remove_plugin("demo", Some("1.0.0")).unwrap();
        assert!(!removed.is_empty());
        store.remove_plugin("demo", None).unwrap();
        assert!(!store.plugin_root("demo").exists());
        assert!(store.plugins_dir.is_dir());
        assert_sentinel_intact(&victim);
    }

    #[test]
    fn tampered_current_link_version_is_rejected() {
        let (_dir, store, _victim) = sandbox();
        fs::create_dir_all(store.plugin_root("demo")).unwrap();
        symlink("../../victim/..", store.current_link("demo")).unwrap();
        // file_name() of ".." is None, so this errors as invalid.
        assert!(store.get_installed_version("demo").is_err());
    }
}
