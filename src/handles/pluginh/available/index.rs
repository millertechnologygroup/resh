use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::timeout;

use super::model::*;
use super::helpers::{CacheHelper, SelectionHelper, SystemHelper};

/// Index manager for fetching and caching plugin indexes
pub struct IndexManager {
    cache_dir: PathBuf,
    http_client: reqwest::Client,
}

impl IndexManager {
    /// Create new index manager
    pub fn new() -> Result<Self> {
        let cache_dir = CacheHelper::get_cache_dir()?;
        
        let http_client = reqwest::Client::builder()
            .user_agent("resh-plugin-client/0.7.0")
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            cache_dir,
            http_client,
        })
    }

    /// Load indexes based on source specification
    pub async fn load_indexes(
        &self,
        source: &str,
        channel: &str,
        timeout_ms: u32,
        offline: bool,
    ) -> Result<Vec<IndexSnapshot>> {
        let mut indexes = Vec::new();
        let sources = self.resolve_sources(source)?;

        for source_config in sources {
            let config_id = source_config.id.clone(); // Clone the ID before moving
            match self.load_single_index(source_config, channel, timeout_ms, offline).await {
                Ok(index) => indexes.push(index),
                Err(e) => {
                    // For now, log and continue. In a real implementation,
                    // you might want more sophisticated error handling
                    eprintln!("Warning: Failed to load index {}: {}", config_id, e);
                }
            }
        }

        if indexes.is_empty() {
            return Err(anyhow!("No indexes available"));
        }

        SelectionHelper::sort_indexes(&mut indexes);
        Ok(indexes)
    }

    /// Load a single index from source
    async fn load_single_index(
        &self,
        source: IndexSourceConfig,
        channel: &str,
        timeout_ms: u32,
        offline: bool,
    ) -> Result<IndexSnapshot> {
        let cache_key = CacheHelper::cache_key(&source.id, channel);
        let cache_path = self.cache_dir.join(&cache_key);

        // Try cache first if offline or if cache is valid
        if offline || CacheHelper::is_cache_valid(&cache_path, source.ttl_seconds) {
            if let Ok(cached) = self.load_from_cache(&cache_path) {
                return Ok(cached);
            }

            if offline {
                return Err(anyhow!("No valid cache available for offline mode"));
            }
        }

        // Fetch from network if not offline
        if !offline {
            match self.fetch_from_network(&source, channel, timeout_ms).await {
                Ok(index) => {
                    // Save to cache
                    if let Err(e) = self.save_to_cache(&cache_path, &index) {
                        eprintln!("Warning: Failed to save index to cache: {}", e);
                    }
                    return Ok(index);
                }
                Err(fetch_err) => {
                    // Try cache as fallback
                    if let Ok(cached) = self.load_from_cache(&cache_path) {
                        eprintln!("Warning: Network fetch failed, using cached data: {}", fetch_err);
                        return Ok(cached);
                    }
                    return Err(fetch_err);
                }
            }
        }

        Err(anyhow!("Unable to load index: no cache and offline mode"))
    }

    /// Fetch index from network
    async fn fetch_from_network(
        &self,
        source: &IndexSourceConfig,
        channel: &str,
        timeout_ms: u32,
    ) -> Result<IndexSnapshot> {
        let url = if let Some(ref base_url) = source.url {
            format!("{}/index-{}.json", base_url, channel)
        } else {
            return Err(anyhow!("No URL configured for index {}", source.id));
        };

        let timeout_duration = Duration::from_millis(timeout_ms as u64);
        
        let response = timeout(timeout_duration, self.http_client.get(&url).send())
            .await
            .context("Request timed out")?
            .context("Failed to send request")?;

        if !response.status().is_success() {
            return Err(anyhow!("HTTP error {}: {}", response.status(), url));
        }

        let text = timeout(timeout_duration, response.text())
            .await
            .context("Response read timed out")?
            .context("Failed to read response")?;

        let raw_index: RawIndexData = serde_json::from_str(&text)
            .context("Failed to parse index JSON")?;

        self.convert_raw_index(source, raw_index)
    }

    /// Load index from cache
    fn load_from_cache(&self, cache_path: &PathBuf) -> Result<IndexSnapshot> {
        let content = fs::read_to_string(cache_path)
            .context("Failed to read cache file")?;
        
        let index: IndexSnapshot = serde_json::from_str(&content)
            .context("Failed to parse cached index")?;
        
        Ok(index)
    }

    /// Save index to cache
    fn save_to_cache(&self, cache_path: &PathBuf, index: &IndexSnapshot) -> Result<()> {
        let content = serde_json::to_string_pretty(index)?;
        fs::write(cache_path, content)?;
        Ok(())
    }

    /// Convert raw index data to our internal format
    fn convert_raw_index(
        &self,
        source: &IndexSourceConfig,
        raw: RawIndexData,
    ) -> Result<IndexSnapshot> {
        let mut plugins = Vec::new();

        for raw_plugin in raw.plugins {
            let plugin_info = self.convert_raw_plugin(raw_plugin)?;
            
            // Group by plugin name/id
            if let Some(existing) = plugins.iter_mut().find(|p: &&mut IndexPluginEntry| p.id == plugin_info.id) {
                existing.versions.push(PluginVersion {
                    version: plugin_info.version.clone(),
                    channel: plugin_info.channel.clone(),
                    plugin_info,
                });
            } else {
                plugins.push(IndexPluginEntry {
                    id: plugin_info.id.clone(),
                    name: plugin_info.name.clone(),
                    versions: vec![PluginVersion {
                        version: plugin_info.version.clone(),
                        channel: plugin_info.channel.clone(),
                        plugin_info,
                    }],
                });
            }
        }

        // Sort versions within each plugin
        for plugin in &mut plugins {
            plugin.versions.sort_by(|a, b| {
                SelectionHelper::compare_versions(&b.version, &a.version)
            });
        }

        Ok(IndexSnapshot {
            id: source.id.clone(),
            kind: source.kind.clone(),
            url: source.url.clone(),
            plugins,
            fetched_at: Utc::now(),
            ttl_seconds: source.ttl_seconds,
        })
    }

    /// Convert raw plugin data to our internal format
    fn convert_raw_plugin(&self, raw: RawPluginData) -> Result<PluginInfo> {
        // Convert assets
        let mut assets = Vec::new();
        if let Some(raw_assets) = raw.assets {
            for raw_asset in raw_assets {
                assets.push(AssetInfo {
                    kind: raw_asset.kind,
                    os: raw_asset.os,
                    arch: raw_asset.arch,
                    url: raw_asset.url,
                    size: raw_asset.size,
                    sha256: raw_asset.sha256,
                    sig: raw_asset.sig.map(|s| SignatureInfo {
                        r#type: s.r#type,
                        value: s.value,
                    }),
                });
            }
        }

        // Convert dependencies  
        let dependencies = raw.dependencies.unwrap_or_default()
            .into_iter()
            .map(|d| DependencyInfo {
                name: d.name,
                version: d.version,
            })
            .collect();

        // Convert readme
        let readme = raw.readme.map(|r| ReadmeInfo {
            r#type: r.r#type,
            value: r.value,
        });

        // Convert release info
        let release = raw.release.map(|r| ReleaseInfo {
            published_at: r.published_at,
            notes: r.notes,
        });

        // Sort arrays for deterministic output
        let mut authors = raw.authors.unwrap_or_default();
        authors.sort();
        
        let mut keywords = raw.keywords.unwrap_or_default();
        keywords.sort();
        
        let mut handles = raw.handles.unwrap_or_default();
        handles.sort();

        Ok(PluginInfo {
            id: raw.id,
            name: raw.name,
            display_name: raw.display_name,
            version: raw.version,
            channel: raw.channel.unwrap_or_else(|| "stable".to_string()),
            description: raw.description,
            homepage: raw.homepage,
            repository: raw.repository,
            license: raw.license,
            authors,
            keywords,
            handles,
            verbs: raw.verbs,
            compatibility: CompatibilityInfo {
                resh_min: raw.compatibility.resh_min,
                resh_max: raw.compatibility.resh_max,
                os: raw.compatibility.os.unwrap_or_default(),
                arch: raw.compatibility.arch.unwrap_or_default(),
            },
            assets,
            dependencies,
            readme,
            release,
        })
    }

    /// Resolve source specification to list of index sources
    fn resolve_sources(&self, source: &str) -> Result<Vec<IndexSourceConfig>> {
        match source {
            "default" => Ok(self.get_default_sources()),
            "official" => Ok(vec![self.get_official_source()]),
            "community" => Ok(vec![self.get_community_source()]),
            custom_id => {
                if let Some(custom) = self.get_custom_source(custom_id) {
                    Ok(vec![custom])
                } else {
                    Err(anyhow!("Unknown source: {}", custom_id))
                }
            }
        }
    }

    /// Get default index sources (official + community)
    fn get_default_sources(&self) -> Vec<IndexSourceConfig> {
        vec![
            self.get_official_source(),
            self.get_community_source(),
        ]
    }

    /// Get official index source
    fn get_official_source(&self) -> IndexSourceConfig {
        IndexSourceConfig {
            id: "official".to_string(),
            kind: IndexKind::Official,
            url: Some("https://plugins.reshshell.dev".to_string()), // Placeholder URL
            ttl_seconds: 3600, // 1 hour
        }
    }

    /// Get community index source  
    fn get_community_source(&self) -> IndexSourceConfig {
        IndexSourceConfig {
            id: "community".to_string(),
            kind: IndexKind::Community,
            url: Some("https://community-plugins.reshshell.dev".to_string()), // Placeholder URL
            ttl_seconds: 1800, // 30 minutes
        }
    }

    /// Get custom source by ID (placeholder - would load from config)
    fn get_custom_source(&self, _id: &str) -> Option<IndexSourceConfig> {
        // TODO: Load from configuration
        None
    }
}

/// Configuration for an index source
#[derive(Debug, Clone)]
pub struct IndexSourceConfig {
    pub id: String,
    pub kind: IndexKind,
    pub url: Option<String>,
    pub ttl_seconds: u64,
}

/// Raw index data format as received from network
#[derive(Debug, Clone, Deserialize)]
struct RawIndexData {
    pub version: u32,
    pub generated_at: String,
    pub plugins: Vec<RawPluginData>,
}

/// Raw plugin data format as received from network
#[derive(Debug, Clone, Deserialize)]
struct RawPluginData {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub version: String,
    pub channel: Option<String>,
    pub description: String,
    pub homepage: Option<String>,
    pub repository: Option<String>,
    pub license: Option<String>,
    pub authors: Option<Vec<String>>,
    pub keywords: Option<Vec<String>>,
    pub handles: Option<Vec<String>>,
    pub verbs: Option<HashMap<String, Vec<String>>>,
    pub compatibility: RawCompatibilityInfo,
    pub assets: Option<Vec<RawAssetInfo>>,
    pub dependencies: Option<Vec<RawDependencyInfo>>,
    pub readme: Option<RawReadmeInfo>,
    pub release: Option<RawReleaseInfo>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawCompatibilityInfo {
    pub resh_min: String,
    pub resh_max: Option<String>,
    pub os: Option<Vec<String>>,
    pub arch: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawAssetInfo {
    pub kind: String,
    pub os: String,
    pub arch: String,
    pub url: String,
    pub size: u64,
    pub sha256: String,
    pub sig: Option<RawSignatureInfo>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSignatureInfo {
    pub r#type: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RawDependencyInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RawReadmeInfo {
    pub r#type: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RawReleaseInfo {
    pub published_at: String,
    pub notes: Option<String>,
}

impl PluginSelector {
    /// Select a plugin from loaded indexes
    pub fn select_plugin(
        &self,
        indexes: &[IndexSnapshot],
    ) -> Result<PluginResolved> {
        let mut candidates = Vec::new();

        // Find all matching plugins across indexes
        for index in indexes {
            for plugin in &index.plugins {
                if self.matches_plugin(plugin) {
                    for version in &plugin.versions {
                        if self.matches_version(version) && self.is_compatible(version) {
                            candidates.push((index, version));
                        }
                    }
                }
            }
        }

        if candidates.is_empty() {
            return Err(anyhow!("No matching plugin found"));
        }

        // Sort candidates by preference (index priority, then version)
        candidates.sort_by(|a, b| {
            match a.0.kind.priority().cmp(&b.0.kind.priority()) {
                std::cmp::Ordering::Equal => {
                    SelectionHelper::compare_versions(&b.1.version, &a.1.version)
                }
                other => other,
            }
        });

        let (index, version) = candidates[0];
        Ok(PluginResolved {
            plugin: version.plugin_info.clone(),
            source_index: index.id.clone(),
        })
    }

    /// Check if plugin matches name/id criteria
    pub fn matches_plugin(&self, plugin: &IndexPluginEntry) -> bool {
        if let Some(ref name) = self.name {
            if plugin.name == *name {
                return true;
            }
        }

        if let Some(ref id) = self.id {
            if plugin.id == *id {
                return true;
            }
        }

        false
    }

    /// Check if version matches criteria
    pub fn matches_version(&self, version: &PluginVersion) -> bool {
        // Check channel
        if version.channel != self.channel {
            return false;
        }

        // Check exact version if specified
        if let Some(ref required_version) = self.version {
            if version.version != *required_version {
                return false;
            }
        }

        true
    }

    /// Check if plugin version is compatible with current system
    pub fn is_compatible(&self, version: &PluginVersion) -> bool {
        let plugin = &version.plugin_info;
        
        // Check OS compatibility
        let current_os = SystemHelper::current_os();
        let target_os = self.os.as_deref().unwrap_or(&current_os);
        if !plugin.compatibility.os.is_empty() && !plugin.compatibility.os.contains(&target_os.to_string()) {
            return false;
        }

        // Check architecture compatibility  
        let current_arch = SystemHelper::current_arch();
        let target_arch = self.arch.as_deref().unwrap_or(&current_arch);
        if !plugin.compatibility.arch.is_empty() && !plugin.compatibility.arch.contains(&target_arch.to_string()) {
            return false;
        }

        // Check resh version compatibility
        let current_version = SystemHelper::current_resh_version();
        if !self.is_version_compatible(&current_version, &plugin.compatibility.resh_min, plugin.compatibility.resh_max.as_deref()) {
            return false;
        }

        true
    }

    /// Check if current version is within the required range
    fn is_version_compatible(&self, current: &str, min: &str, max: Option<&str>) -> bool {
        // Simple version comparison - could be more sophisticated
        if SelectionHelper::compare_versions(current, min) == std::cmp::Ordering::Less {
            return false;
        }

        if let Some(max_version) = max {
            if SelectionHelper::compare_versions(current, max_version) == std::cmp::Ordering::Greater {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_index_source_config() {
        let config = IndexSourceConfig {
            id: "test".to_string(),
            kind: IndexKind::Official,
            url: Some("https://example.com".to_string()),
            ttl_seconds: 3600,
        };

        assert_eq!(config.id, "test");
        assert_eq!(config.kind.priority(), 0);
    }
}