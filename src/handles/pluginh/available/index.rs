//! Plugin indexes for `available.info`: fetched over HTTPS from
//! `<base>/index-<channel>.json` and cached in
//! `$XDG_CACHE_HOME/resh/plugin-indexes/<index>_<channel>.json`.

use chrono::Utc;
use serde::Deserialize;
use std::collections::HashMap;

use super::model::*;
use crate::handles::pluginh::common::{
    CATALOG_INVALID, CaFile, Deadline, IO_ERROR, NOT_FOUND, PResult, PluginError,
    version_sort_key_cmp,
};
use crate::handles::pluginh::net::Fetcher;
use crate::handles::pluginh::paths;

/// Largest index read.
const MAX_INDEX_BYTES: u64 = 32 * 1024 * 1024;

/// One configured index.
#[derive(Debug, Clone)]
pub struct IndexSourceConfig {
    pub id: String,
    pub kind: IndexKind,
    pub url: String,
    pub ttl_seconds: u64,
}

#[cfg(test)]
thread_local! {
    /// Test-only seam: index base URL of this thread (for every index).
    pub static TEST_INDEX_BASE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

fn base_url(env: &str, default: &str) -> String {
    #[cfg(test)]
    if let Some(u) = TEST_INDEX_BASE.with(|b| b.borrow().clone()) {
        return format!(
            "{u}/{}",
            if env.contains("OFFICIAL") {
                "official"
            } else {
                "community"
            }
        );
    }
    // Debug builds only: lets the binary tests point the indexes at a local
    // server. Release builds always use the built-in URLs.
    #[cfg(debug_assertions)]
    if let Ok(u) = std::env::var(env) {
        return u;
    }
    let _ = env;
    default.to_string()
}

/// The indexes of `source` (`default`, `official` or `community`).
pub fn sources(source: &str) -> Vec<IndexSourceConfig> {
    let official = IndexSourceConfig {
        id: "official".into(),
        kind: IndexKind::Official,
        url: base_url(
            "RESH_TEST_PLUGIN_OFFICIAL_URL",
            "https://plugins.reshshell.dev",
        ),
        ttl_seconds: 3600,
    };
    let community = IndexSourceConfig {
        id: "community".into(),
        kind: IndexKind::Community,
        url: base_url(
            "RESH_TEST_PLUGIN_COMMUNITY_URL",
            "https://community-plugins.reshshell.dev",
        ),
        ttl_seconds: 1800,
    };
    match source {
        "official" => vec![official],
        "community" => vec![community],
        _ => vec![official, community],
    }
}

/// Loads every index of `sources`. An index that cannot be loaded is a
/// warning while another one loads; when none loads, the first failure (a
/// timeout first) is the error.
pub fn load_indexes(
    sources: &[IndexSourceConfig],
    channel: &str,
    offline: bool,
    ca: Option<&CaFile>,
    deadline: Deadline,
    warnings: &mut Vec<String>,
) -> PResult<Vec<IndexSnapshot>> {
    let fetcher = if offline {
        None
    } else {
        Some(Fetcher::new(ca, deadline)?)
    };
    let mut out = Vec::new();
    let mut errors: Vec<PluginError> = Vec::new();
    for s in sources {
        match load_one(s, channel, offline, fetcher.as_ref(), warnings) {
            Ok(i) => out.push(i),
            Err(e) => {
                warnings.push(format!("index {} not loaded: {}", s.id, e.message));
                errors.push(e);
            }
        }
    }
    if out.is_empty() {
        let first = errors
            .iter()
            .find(|e| e.exit == crate::core::status::exit::TIMEOUT)
            .or(errors.first())
            .cloned()
            .unwrap_or_else(|| PluginError::failed(NOT_FOUND, "no plugin index is configured"));
        return Err(first);
    }
    out.sort_by(|a, b| {
        a.kind
            .priority()
            .cmp(&b.kind.priority())
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(out)
}

fn cache_dir(create: bool) -> PResult<Option<std::path::PathBuf>> {
    let loc = paths::locations()?;
    if create {
        paths::ensure_dir(&loc.cache, &["resh", "plugin-indexes"], 0o700).map(Some)
    } else {
        paths::existing_dir(&loc.cache, &["resh", "plugin-indexes"])
    }
}

fn load_one(
    s: &IndexSourceConfig,
    channel: &str,
    offline: bool,
    fetcher: Option<&Fetcher>,
    warnings: &mut Vec<String>,
) -> PResult<IndexSnapshot> {
    let name = format!("{}_{}.json", s.id, channel);
    let cached = match cache_dir(false)? {
        Some(dir) => paths::read_file(&dir, &name, MAX_INDEX_BYTES)?
            .and_then(|d| serde_json::from_slice::<IndexSnapshot>(&d).ok())
            .filter(|i| i.url.as_deref() == Some(s.url.as_str())),
        None => None,
    };
    let fresh = cached.as_ref().is_some_and(|c| {
        (Utc::now() - c.fetched_at).num_seconds() < s.ttl_seconds as i64
            && c.fetched_at <= Utc::now()
    });
    if offline || fresh {
        return cached.ok_or_else(|| {
            PluginError::failed(
                NOT_FOUND,
                format!(
                    "no cached {} index (offline=true); run once without offline=true to fetch it",
                    s.id
                ),
            )
        });
    }
    let fetcher = fetcher.expect("online loads have a fetcher");
    let url = url::Url::parse(&format!(
        "{}/index-{channel}.json",
        s.url.trim_end_matches('/')
    ))
    .map_err(|e| PluginError::failed(IO_ERROR, format!("bad index URL for {}: {e}", s.id)))?;
    let body = fetcher.get(&url, MAX_INDEX_BYTES, &format!("the {} index", s.id))?;
    let raw: RawIndexData = serde_json::from_slice(&body).map_err(|e| {
        PluginError::failed(
            CATALOG_INVALID,
            format!("the index at {url} is not valid: {e}"),
        )
    })?;
    let snapshot = convert_raw_index(s, raw);
    match cache_dir(true).and_then(|dir| {
        let dir = dir.expect("created");
        let data = serde_json::to_vec(&snapshot)
            .map_err(|e| PluginError::failed(IO_ERROR, e.to_string()))?;
        paths::write_file_atomic(&dir, &name, &data, 0o600)
    }) {
        Ok(()) => {}
        Err(e) => warnings.push(format!("the {} index was not cached: {}", s.id, e.message)),
    }
    Ok(snapshot)
}

fn convert_raw_index(source: &IndexSourceConfig, raw: RawIndexData) -> IndexSnapshot {
    let mut plugins: Vec<IndexPluginEntry> = Vec::new();
    for raw_plugin in raw.plugins {
        let info = convert_raw_plugin(raw_plugin);
        let version = PluginVersion {
            version: info.version.clone(),
            channel: info.channel.clone(),
            plugin_info: info,
        };
        if let Some(existing) = plugins.iter_mut().find(|p| p.id == version.plugin_info.id) {
            existing.versions.push(version);
        } else {
            plugins.push(IndexPluginEntry {
                id: version.plugin_info.id.clone(),
                name: version.plugin_info.name.clone(),
                versions: vec![version],
            });
        }
    }
    for p in &mut plugins {
        p.versions
            .sort_by(|a, b| version_sort_key_cmp(&b.version, &a.version));
    }
    IndexSnapshot {
        id: source.id.clone(),
        kind: source.kind.clone(),
        url: Some(source.url.clone()),
        plugins,
        fetched_at: Utc::now(),
        ttl_seconds: source.ttl_seconds,
    }
}

fn convert_raw_plugin(raw: RawPluginData) -> PluginInfo {
    let assets = raw
        .assets
        .unwrap_or_default()
        .into_iter()
        .map(|a| AssetInfo {
            kind: a.kind,
            os: a.os,
            arch: a.arch,
            url: a.url,
            size: a.size,
            sha256: a.sha256,
            sig: a.sig.map(|s| SignatureInfo {
                r#type: s.r#type,
                value: s.value,
            }),
        })
        .collect();
    let dependencies = raw
        .dependencies
        .unwrap_or_default()
        .into_iter()
        .map(|d| DependencyInfo {
            name: d.name,
            version: d.version,
        })
        .collect();
    let sorted = |v: Option<Vec<String>>| {
        let mut v = v.unwrap_or_default();
        v.sort();
        v
    };
    PluginInfo {
        id: raw.id,
        name: raw.name,
        display_name: raw.display_name,
        version: raw.version,
        channel: raw.channel.unwrap_or_else(|| "stable".to_string()),
        description: raw.description,
        homepage: raw.homepage,
        repository: raw.repository,
        license: raw.license,
        authors: sorted(raw.authors),
        keywords: sorted(raw.keywords),
        handles: sorted(raw.handles),
        verbs: raw.verbs,
        compatibility: CompatibilityInfo {
            resh_min: raw.compatibility.resh_min,
            resh_max: raw.compatibility.resh_max,
            os: raw.compatibility.os.unwrap_or_default(),
            arch: raw.compatibility.arch.unwrap_or_default(),
        },
        assets,
        dependencies,
        readme: raw.readme.map(|r| ReadmeInfo {
            r#type: r.r#type,
            value: r.value,
        }),
        release: raw.release.map(|r| ReleaseInfo {
            published_at: r.published_at,
            notes: r.notes,
        }),
    }
}

/// Raw index data format as received from the network.
#[derive(Debug, Clone, Deserialize)]
struct RawIndexData {
    plugins: Vec<RawPluginData>,
}

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

/// The running resh version, for `compatibility.resh_min`/`resh_max`.
pub fn resh_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

impl PluginSelector {
    /// The best match across `indexes`: official before community, then the
    /// newest version.
    pub fn select_plugin(&self, indexes: &[IndexSnapshot]) -> PResult<PluginResolved> {
        let mut candidates = Vec::new();
        for index in indexes {
            for plugin in &index.plugins {
                if !self.matches_plugin(plugin) {
                    continue;
                }
                for version in &plugin.versions {
                    if self.matches_version(version) && self.is_compatible(version) {
                        candidates.push((index, version));
                    }
                }
            }
        }
        candidates.sort_by(|a, b| {
            a.0.kind
                .priority()
                .cmp(&b.0.kind.priority())
                .then_with(|| version_sort_key_cmp(&b.1.version, &a.1.version))
        });
        let (index, version) = candidates.first().ok_or_else(|| {
            PluginError::failed(
                NOT_FOUND,
                format!(
                    "no plugin matches {} in channel {}{} for {}-{}",
                    match (&self.name, &self.id) {
                        (Some(n), _) => format!("name={n}"),
                        (None, Some(i)) => format!("id={i}"),
                        _ => String::new(),
                    },
                    self.channel,
                    self.version
                        .as_ref()
                        .map(|v| format!(" version {v}"))
                        .unwrap_or_default(),
                    self.target_os(),
                    self.target_arch(),
                ),
            )
        })?;
        Ok(PluginResolved {
            plugin: version.plugin_info.clone(),
            source_index: index.id.clone(),
        })
    }

    fn target_os(&self) -> String {
        self.os
            .clone()
            .unwrap_or_else(|| std::env::consts::OS.to_string())
    }

    fn target_arch(&self) -> String {
        self.arch
            .clone()
            .unwrap_or_else(|| std::env::consts::ARCH.to_string())
    }

    /// Matches by name or id (either one when both are given).
    pub fn matches_plugin(&self, plugin: &IndexPluginEntry) -> bool {
        self.name.as_ref().is_some_and(|n| plugin.name == *n)
            || self.id.as_ref().is_some_and(|i| plugin.id == *i)
    }

    pub fn matches_version(&self, version: &PluginVersion) -> bool {
        version.channel == self.channel
            && self.version.as_ref().is_none_or(|v| {
                version.version == *v
                    || crate::handles::pluginh::common::compare_versions(&version.version, v)
                        == Some(std::cmp::Ordering::Equal)
            })
    }

    /// The plugin supports the target OS and architecture and this resh.
    pub fn is_compatible(&self, version: &PluginVersion) -> bool {
        let c = &version.plugin_info.compatibility;
        let (os, arch) = (self.target_os(), self.target_arch());
        if !c.os.is_empty() && !c.os.contains(&os) {
            return false;
        }
        if !c.arch.is_empty() && !c.arch.contains(&arch) {
            return false;
        }
        let me = resh_version();
        use crate::handles::pluginh::common::compare_versions;
        if compare_versions(me, &c.resh_min) == Some(std::cmp::Ordering::Less) {
            return false;
        }
        if let Some(max) = &c.resh_max
            && compare_versions(me, max) == Some(std::cmp::Ordering::Greater)
        {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(v: &str, channel: &str, min: &str) -> PluginVersion {
        let raw: RawPluginData = serde_json::from_value(serde_json::json!({
            "id": "resh.docker", "name": "resh.docker", "display_name": "Docker",
            "version": v, "channel": channel, "description": "d",
            "compatibility": {"resh_min": min, "os": ["linux"], "arch": ["x86_64", "aarch64"]}
        }))
        .unwrap();
        let info = convert_raw_plugin(raw);
        PluginVersion {
            version: info.version.clone(),
            channel: info.channel.clone(),
            plugin_info: info,
        }
    }

    #[test]
    fn selection_prefers_newest_compatible_version() {
        let idx = IndexSnapshot {
            id: "official".into(),
            kind: IndexKind::Official,
            url: None,
            plugins: vec![IndexPluginEntry {
                id: "resh.docker".into(),
                name: "resh.docker".into(),
                versions: vec![
                    version("1.9.0", "stable", "0.1"),
                    version("1.10.0", "stable", "0.1"),
                    version("2.0.0", "stable", "999.0"),
                    version("3.0.0", "beta", "0.1"),
                ],
            }],
            fetched_at: Utc::now(),
            ttl_seconds: 1,
        };
        let sel = PluginSelector {
            name: Some("resh.docker".into()),
            id: None,
            version: None,
            channel: "stable".into(),
            os: Some("linux".into()),
            arch: Some("x86_64".into()),
        };
        let r = sel.select_plugin(std::slice::from_ref(&idx)).unwrap();
        assert_eq!(r.plugin.version, "1.10.0");
        let mut s2 = sel.clone();
        s2.os = Some("windows".into());
        assert_eq!(
            s2.select_plugin(std::slice::from_ref(&idx))
                .unwrap_err()
                .code,
            NOT_FOUND
        );
    }
}
