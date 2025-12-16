use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use crate::core::registry::Args;
use super::model::*;

/// Helper functions for creating envelope responses
pub struct EnvelopeHelper;

impl EnvelopeHelper {
    /// Create a success envelope for available.info
    pub fn create_success_envelope(
        target: &str,
        args: &AvailableInfoArgs,
        actions: Vec<ActionRecord>,
        result: AvailableInfoResult,
    ) -> AvailableInfoEnvelope {
        AvailableInfoEnvelope {
            op: "plugin.available.info".to_string(),
            ok: true,
            target: target.to_string(),
            ts: Utc::now().to_rfc3339(),
            args: args.clone(),
            actions,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error envelope for available.info
    pub fn create_error_envelope(
        target: &str,
        args: &AvailableInfoArgs,
        actions: Vec<ActionRecord>,
        error_code: &AvailableInfoErrorCode,
        message: &str,
        details: Value,
    ) -> AvailableInfoEnvelope {
        AvailableInfoEnvelope {
            op: "plugin.available.info".to_string(),
            ok: false,
            target: target.to_string(),
            ts: Utc::now().to_rfc3339(),
            args: args.clone(),
            actions,
            result: None,
            error: Some(ErrorInfo {
                code: error_code.as_str().to_string(),
                message: message.to_string(),
                details,
            }),
        }
    }
}

/// Helper functions for argument parsing and validation
pub struct ArgsHelper;

impl ArgsHelper {
    /// Parse and validate available.info arguments from raw args
    pub fn parse_available_info_args(args: &Args) -> Result<AvailableInfoArgs> {
        let mut parsed = AvailableInfoArgs::default();

        // Parse name and id - at least one is required
        parsed.name = args.get("name").cloned();
        parsed.id = args.get("id").cloned();

        if parsed.name.is_none() && parsed.id.is_none() {
            return Err(anyhow!("At least one of 'name' or 'id' must be provided"));
        }

        // Parse optional version
        parsed.version = args.get("version").cloned();
        if let Some(ref version) = parsed.version {
            Self::validate_version_format(version)?;
        }

        // Parse channel with validation
        if let Some(channel) = args.get("channel") {
            if !["stable", "beta", "nightly"].contains(&channel.as_str()) {
                return Err(anyhow!("Invalid channel '{}'. Must be one of: stable, beta, nightly", channel));
            }
            parsed.channel = channel.clone();
        }

        // Parse timeout with clamping
        if let Some(timeout_str) = args.get("timeout_ms") {
            match timeout_str.parse::<u32>() {
                Ok(timeout) => {
                    parsed.timeout_ms = timeout.max(100).min(30000);
                    if timeout != parsed.timeout_ms {
                        // Note: We should add a warning action for this
                    }
                }
                Err(_) => return Err(anyhow!("Invalid timeout_ms value: '{}'", timeout_str)),
            }
        }

        // Parse other optional fields
        parsed.os = args.get("os").cloned();
        parsed.arch = args.get("arch").cloned();
        parsed.include = args.get("include").unwrap_or(&"core".to_string()).clone();
        parsed.source = args.get("source").unwrap_or(&"default".to_string()).clone();
        parsed.offline = args.get("offline").map(|s| s == "true").unwrap_or(false);

        Ok(parsed)
    }

    /// Validate version format (basic semver-like check)
    fn validate_version_format(version: &str) -> Result<()> {
        // Basic semver validation - could be more sophisticated
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() < 2 || parts.len() > 3 {
            return Err(anyhow!("Invalid version format: '{}'. Expected format like '1.2.3'", version));
        }

        for part in parts {
            if part.parse::<u32>().is_err() {
                return Err(anyhow!("Invalid version format: '{}'. All parts must be numeric", version));
            }
        }

        Ok(())
    }
}

/// Helper functions for current system detection
pub struct SystemHelper;

impl SystemHelper {
    /// Get current OS
    pub fn current_os() -> String {
        // Check for test environment variable first
        if let Ok(test_os) = std::env::var("TEST_CURRENT_OS") {
            return test_os;
        }
        std::env::consts::OS.to_string()
    }

    /// Get current architecture
    pub fn current_arch() -> String {
        // Check for test environment variable first
        if let Ok(test_arch) = std::env::var("TEST_CURRENT_ARCH") {
            return test_arch;
        }
        std::env::consts::ARCH.to_string()
    }

    /// Get current resh version (placeholder - should be real version)
    pub fn current_resh_version() -> String {
        "0.7.0".to_string() // TODO: Get from actual version
    }
}

/// Helper functions for cache management
pub struct CacheHelper;

impl CacheHelper {
    /// Get cache directory for plugin indexes
    pub fn get_cache_dir() -> Result<PathBuf> {
        let state_dir = std::env::var("RESH_STATE_DIR")
            .or_else(|_| std::env::var("HOME").map(|h| format!("{}/.resh", h)))
            .map_err(|_| anyhow!("Unable to determine state directory"))?;
        
        let cache_dir = PathBuf::from(state_dir).join("cache").join("plugin-indexes");
        fs::create_dir_all(&cache_dir)?;
        Ok(cache_dir)
    }

    /// Get cache key for an index
    pub fn cache_key(index_id: &str, channel: &str) -> String {
        format!("{}_{}.json", index_id, channel)
    }

    /// Check if cache entry is valid (within TTL)
    pub fn is_cache_valid(cache_path: &PathBuf, ttl_seconds: u64) -> bool {
        if !cache_path.exists() {
            return false;
        }

        if let Ok(metadata) = fs::metadata(cache_path) {
            if let Ok(modified) = metadata.modified() {
                if let Ok(elapsed) = modified.elapsed() {
                    return elapsed.as_secs() < ttl_seconds;
                }
            }
        }

        false
    }
}

/// Helper functions for deterministic sorting and selection
pub struct SelectionHelper;

impl SelectionHelper {
    /// Sort plugins deterministically
    pub fn sort_plugins(plugins: &mut Vec<PluginInfo>) {
        plugins.sort_by(|a, b| {
            // Sort by name first, then by version
            match a.name.cmp(&b.name) {
                std::cmp::Ordering::Equal => {
                    // Sort versions in descending order (newest first)
                    Self::compare_versions(&b.version, &a.version)
                }
                other => other,
            }
        });
    }

    /// Compare two version strings (basic semver comparison)
    pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
        let a_parts: Vec<u32> = a.split('.').filter_map(|s| s.parse().ok()).collect();
        let b_parts: Vec<u32> = b.split('.').filter_map(|s| s.parse().ok()).collect();

        for i in 0..std::cmp::max(a_parts.len(), b_parts.len()) {
            let a_part = a_parts.get(i).unwrap_or(&0);
            let b_part = b_parts.get(i).unwrap_or(&0);
            
            match a_part.cmp(b_part) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
            }
        }

        std::cmp::Ordering::Equal
    }

    /// Sort indexes by priority (official > community > custom)
    pub fn sort_indexes(indexes: &mut Vec<IndexSnapshot>) {
        indexes.sort_by(|a, b| {
            match a.kind.priority().cmp(&b.kind.priority()) {
                std::cmp::Ordering::Equal => a.id.cmp(&b.id),
                other => other,
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_validation() {
        assert!(ArgsHelper::validate_version_format("1.2.3").is_ok());
        assert!(ArgsHelper::validate_version_format("0.1").is_ok());
        assert!(ArgsHelper::validate_version_format("invalid").is_err());
        assert!(ArgsHelper::validate_version_format("1.2.3.4").is_err());
    }

    #[test]
    fn test_version_comparison() {
        use std::cmp::Ordering;
        
        assert_eq!(SelectionHelper::compare_versions("1.2.3", "1.2.3"), Ordering::Equal);
        assert_eq!(SelectionHelper::compare_versions("1.2.3", "1.2.2"), Ordering::Greater);
        assert_eq!(SelectionHelper::compare_versions("1.2.2", "1.2.3"), Ordering::Less);
        assert_eq!(SelectionHelper::compare_versions("2.0.0", "1.9.9"), Ordering::Greater);
    }
}