use anyhow::{anyhow, Context, Result};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;
use url::Url;

use super::types::{
    ArtifactCandidate, PluginManifest, RegistryEntry, RequestedVersion, SourceSpec, VerifyMode,
};

/// Registry client for fetching and parsing plugin metadata
pub struct RegistryClient {
    http_client: Client,
    timeout: Duration,
}

impl RegistryClient {
    /// Create new registry client with timeout
    pub fn new(timeout_ms: u64) -> Result<Self> {
        let http_client = Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .user_agent("resh-plugin-client/1.0")
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            http_client,
            timeout: Duration::from_millis(timeout_ms),
        })
    }

    /// Resolve plugin artifact from source specification
    pub fn resolve_plugin(
        &self,
        plugin_id: &str,
        source: &SourceSpec,
        requested_version: &RequestedVersion,
        verify: &VerifyMode,
    ) -> Result<ArtifactCandidate> {
        match source {
            SourceSpec::Registry { url } => self.resolve_from_registry(plugin_id, url, requested_version, verify),
            SourceSpec::Url { url } => self.resolve_from_url(plugin_id, url, verify),
            SourceSpec::File { path } => self.resolve_from_file(plugin_id, path, verify),
        }
    }

    /// Resolve plugin from registry
    fn resolve_from_registry(
        &self,
        plugin_id: &str,
        registry_url: &str,
        requested_version: &RequestedVersion,
        _verify: &VerifyMode,
    ) -> Result<ArtifactCandidate> {
        let registry_entry = self.fetch_registry_entry(registry_url, plugin_id)?;
        let version = self.select_version(&registry_entry, requested_version)?;
        let manifest = registry_entry
            .versions
            .get(&version)
            .ok_or_else(|| anyhow!("Version {} not found in registry", version))?
            .clone();

        // Get platform-specific artifact
        let platform_key = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
        let platform_spec = manifest
            .platforms
            .get(&platform_key)
            .ok_or_else(|| anyhow!("No artifact available for platform: {}", platform_key))?;

        // Construct download URL
        let artifact_url = format!("{}/v1/artifacts/{}/{}/{}", 
            registry_url.trim_end_matches('/'), 
            plugin_id, 
            version,
            &platform_spec.bin
        );

        Ok(ArtifactCandidate {
            kind: if artifact_url.ends_with(".tar.gz") { "tar.gz".to_string() } else { "binary".to_string() },
            url: Some(artifact_url),
            path: None,
            sha256: Some(platform_spec.sha256.clone()),
            manifest,
        })
    }

    /// Resolve plugin from direct URL
    fn resolve_from_url(
        &self,
        plugin_id: &str,
        url: &str,
        _verify: &VerifyMode,
    ) -> Result<ArtifactCandidate> {
        // For URL source, we need to make assumptions about the manifest
        // In a real implementation, we might fetch a companion manifest file
        let kind = if url.ends_with(".tar.gz") {
            "tar.gz".to_string()
        } else {
            "binary".to_string()
        };

        // Create minimal manifest
        let manifest = PluginManifest {
            name: plugin_id.to_string(),
            version: "unknown".to_string(),
            description: None,
            author: None,
            license: None,
            homepage: None,
            repository: None,
            keywords: None,
            platforms: HashMap::new(), // Will be populated after download if needed
        };

        Ok(ArtifactCandidate {
            kind,
            url: Some(url.to_string()),
            path: None,
            sha256: None, // No checksum available for direct URLs unless provided separately
            manifest,
        })
    }

    /// Resolve plugin from local file
    fn resolve_from_file(
        &self,
        plugin_id: &str,
        file_path: &str,
        _verify: &VerifyMode,
    ) -> Result<ArtifactCandidate> {
        let path = Path::new(file_path);
        if !path.exists() {
            return Err(anyhow!("Plugin file does not exist: {}", file_path));
        }

        let kind = if file_path.ends_with(".tar.gz") {
            "tar.gz".to_string()
        } else {
            "binary".to_string()
        };

        // Create minimal manifest
        let manifest = PluginManifest {
            name: plugin_id.to_string(),
            version: "local".to_string(),
            description: None,
            author: None,
            license: None,
            homepage: None,
            repository: None,
            keywords: None,
            platforms: HashMap::new(),
        };

        Ok(ArtifactCandidate {
            kind,
            url: None,
            path: Some(file_path.to_string()),
            sha256: None, // Could compute SHA256 of local file if needed
            manifest,
        })
    }

    /// Fetch plugin entry from registry
    fn fetch_registry_entry(&self, registry_url: &str, plugin_id: &str) -> Result<RegistryEntry> {
        // Try to parse as URL first, fall back to file path
        if let Ok(url) = Url::parse(registry_url) {
            self.fetch_registry_entry_http(&url, plugin_id)
        } else {
            self.fetch_registry_entry_file(registry_url, plugin_id)
        }
    }

    /// Fetch registry entry via HTTP
    fn fetch_registry_entry_http(&self, registry_url: &Url, plugin_id: &str) -> Result<RegistryEntry> {
        let url = format!("{}/v1/plugins/{}", registry_url.as_str().trim_end_matches('/'), plugin_id);
        
        let response = self
            .http_client
            .get(&url)
            .send()
            .with_context(|| format!("Failed to fetch plugin from registry: {}", url))?;

        if !response.status().is_success() {
            return Err(anyhow!("Plugin not found in registry: {} (status: {})", plugin_id, response.status()));
        }

        let entry: RegistryEntry = response
            .json()
            .with_context(|| format!("Failed to parse registry response for plugin: {}", plugin_id))?;

        Ok(entry)
    }

    /// Fetch registry entry from local file
    fn fetch_registry_entry_file(&self, registry_path: &str, plugin_id: &str) -> Result<RegistryEntry> {
        let content = fs::read_to_string(registry_path)
            .with_context(|| format!("Failed to read registry file: {}", registry_path))?;

        let registry: HashMap<String, RegistryEntry> = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse registry file: {}", registry_path))?;

        registry
            .get(plugin_id)
            .cloned()
            .ok_or_else(|| anyhow!("Plugin not found in registry: {}", plugin_id))
    }

    /// Select version from available versions
    fn select_version(&self, entry: &RegistryEntry, requested: &RequestedVersion) -> Result<String> {
        match requested {
            RequestedVersion::Latest => {
                // Find the latest version (highest semver)
                let mut versions: Vec<_> = entry.versions.keys().collect();
                versions.sort_by(|a, b| {
                    // Simple string sort for now - in production should use semver crate
                    b.cmp(a)
                });
                
                versions
                    .first()
                    .map(|v| v.to_string())
                    .ok_or_else(|| anyhow!("No versions available for plugin"))
            }
            RequestedVersion::Specific(version) => {
                if entry.versions.contains_key(version) {
                    Ok(version.clone())
                } else {
                    Err(anyhow!("Version {} not found for plugin", version))
                }
            }
        }
    }

    /// Download artifact from URL
    pub fn download_artifact(&self, url: &str) -> Result<Vec<u8>> {
        let response = self
            .http_client
            .get(url)
            .send()
            .with_context(|| format!("Failed to download artifact from: {}", url))?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to download artifact: HTTP {}", response.status()));
        }

        let bytes = response
            .bytes()
            .context("Failed to read response body")?;

        Ok(bytes.to_vec())
    }

    /// Read artifact from local file
    pub fn read_file_artifact(&self, path: &str) -> Result<Vec<u8>> {
        fs::read(path)
            .with_context(|| format!("Failed to read artifact file: {}", path))
    }

    /// Verify artifact checksum
    pub fn verify_checksum(&self, data: &[u8], expected_sha256: &str) -> Result<()> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let actual_sha256 = format!("{:x}", result);

        if actual_sha256 != expected_sha256 {
            return Err(anyhow!(
                "Checksum verification failed: expected {}, got {}",
                expected_sha256,
                actual_sha256
            ));
        }

        Ok(())
    }

    /// Compare two versions (simple string comparison for now)
    pub fn compare_versions(&self, v1: &str, v2: &str) -> std::cmp::Ordering {
        // Simple lexicographical comparison for now
        // In production, should use semver crate for proper semantic versioning
        v1.cmp(v2)
    }
}

/// Default registry configuration
pub struct DefaultRegistry;

impl DefaultRegistry {
    /// Get default registry URL
    pub fn url() -> &'static str {
        "https://plugins.reshshell.dev"
    }

    /// Get default timeout in milliseconds
    pub fn timeout_ms() -> u64 {
        300000 // 5 minutes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_registry_client_creation() {
        let client = RegistryClient::new(30000).unwrap();
        assert_eq!(client.timeout, Duration::from_millis(30000));
    }

    #[test]
    fn test_version_selection() {
        let client = RegistryClient::new(30000).unwrap();
        
        let mut versions = HashMap::new();
        versions.insert("1.0.0".to_string(), PluginManifest {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: None,
            author: None,
            license: None,
            homepage: None,
            repository: None,
            keywords: None,
            platforms: HashMap::new(),
        });
        versions.insert("1.1.0".to_string(), PluginManifest {
            name: "test".to_string(),
            version: "1.1.0".to_string(),
            description: None,
            author: None,
            license: None,
            homepage: None,
            repository: None,
            keywords: None,
            platforms: HashMap::new(),
        });

        let entry = RegistryEntry {
            plugin_id: "test".to_string(),
            versions,
        };

        // Test latest version selection
        let latest = client.select_version(&entry, &RequestedVersion::Latest).unwrap();
        assert_eq!(latest, "1.1.0"); // Should select highest version

        // Test specific version selection
        let specific = client.select_version(&entry, &RequestedVersion::Specific("1.0.0".to_string())).unwrap();
        assert_eq!(specific, "1.0.0");

        // Test missing version
        let missing = client.select_version(&entry, &RequestedVersion::Specific("2.0.0".to_string()));
        assert!(missing.is_err());
    }

    #[test]
    fn test_compare_versions() {
        let client = RegistryClient::new(30000).unwrap();
        
        assert_eq!(client.compare_versions("1.0.0", "1.0.0"), std::cmp::Ordering::Equal);
        assert_eq!(client.compare_versions("1.0.0", "1.1.0"), std::cmp::Ordering::Less);
        assert_eq!(client.compare_versions("1.1.0", "1.0.0"), std::cmp::Ordering::Greater);
    }
}