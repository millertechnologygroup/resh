//! `available.list`, `available.search` and `installed.list`.

use std::collections::BTreeMap;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::common::{
    ArgReader, CATALOG_INVALID, CaFile, Deadline, NOT_FOUND, PERMISSION_DENIED, PResult,
    PluginError, is_version, version_sort_key_cmp,
};
use super::net::{Fetcher, parse_https_url};
use super::paths;
use super::plugin::store::PluginStore;
use crate::core::Args;

/// The catalog `available.list` reads by default (built into resh).
const BUILTIN_CATALOG: &str = include_str!("../../../assets/plugins/catalog.json");
/// Default index of `available.search`.
pub const DEFAULT_INDEX_URL: &str = "https://plugins.reshshell.dev/index.json";
/// Largest catalog or index read.
const MAX_CATALOG_BYTES: u64 = 32 * 1024 * 1024;

/// A finished catalog verb: its JSON envelope and, on failure, the error.
pub struct Outcome {
    pub envelope: Value,
    pub error: Option<PluginError>,
}

fn finish(
    op: &str,
    target: &str,
    args: Value,
    actions: Vec<Value>,
    result: Value,
    warnings: Vec<String>,
    error: Option<PluginError>,
) -> Outcome {
    Outcome {
        envelope: json!({
            "op": op,
            "ok": error.is_none(),
            "code": error.as_ref().map_or(0, |e| e.exit),
            "target": target,
            "args": args,
            "actions": actions,
            "result": if error.is_some() && result.is_null() { Value::Null } else { result },
            "warnings": warnings,
            "error": error.as_ref().map(PluginError::json),
            "ts": Utc::now().to_rfc3339(),
        }),
        error,
    }
}

/// The given arguments as strings (for envelopes of refused calls).
pub fn raw_args(args: &Args) -> Value {
    let m: BTreeMap<_, _> = args.iter().collect();
    json!(m)
}

fn read_error(path: &str, e: &std::io::Error) -> PluginError {
    match e.kind() {
        std::io::ErrorKind::NotFound => {
            PluginError::failed(NOT_FOUND, format!("catalog {path} does not exist"))
        }
        std::io::ErrorKind::PermissionDenied => PluginError::failed(
            PERMISSION_DENIED,
            format!("cannot read catalog {path}: {e}"),
        ),
        _ => PluginError::failed(
            super::common::IO_ERROR,
            format!("cannot read catalog {path}: {e}"),
        ),
    }
}

// ---------------------------------------------------------------------------
// available.list
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Catalog {
    version: i64,
    #[serde(default)]
    generated_at: Option<String>,
    plugins: Vec<CatalogPlugin>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CatalogPlugin {
    id: String,
    name: String,
    #[serde(default)]
    description: String,
    version: String,
    #[serde(default)]
    publisher: String,
    #[serde(default)]
    license: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    platforms: Vec<String>,
    #[serde(default)]
    entrypoint: String,
    #[serde(default)]
    homepage: String,
    #[serde(default)]
    repo: String,
    #[serde(default)]
    sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    artifacts: Option<Vec<CatalogArtifact>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CatalogArtifact {
    os: String,
    arch: String,
    url: String,
    sha256: String,
}

struct ListOptions {
    source: String,
    query: Option<String>,
    tags: Vec<String>,
    publisher: Option<String>,
    platform: String,
    include_prerelease: bool,
    limit: usize,
    offset: usize,
    format: &'static str,
}

fn parse_list_args(args: &Args) -> PResult<ListOptions> {
    let r = ArgReader::new(args);
    let source = r.string("source")?.unwrap_or_else(|| "default".into());
    if source != "default" {
        match source.strip_prefix("file:") {
            Some(p) if !p.is_empty() => {}
            _ => {
                return Err(PluginError::usage(format!(
                    "invalid source {source:?}: expected default or file:<path>; nothing was done"
                )));
            }
        }
    }
    let platform = match r.string("platform")? {
        Some(p) => match p.split_once('-') {
            Some((os, arch)) if !os.is_empty() && !arch.is_empty() => p,
            _ => {
                return Err(PluginError::usage(format!(
                    "invalid platform {p:?}: expected <os>-<arch>, such as linux-x86_64; nothing was done"
                )));
            }
        },
        None => super::plugin::registry::platform_key(),
    };
    Ok(ListOptions {
        source,
        query: r.string("query")?,
        tags: r
            .string("tags")?
            .map(|t| {
                t.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        publisher: r.string("publisher")?,
        platform,
        include_prerelease: r.bool("include_prerelease", false)?,
        limit: r.uint("limit", 1, 1000, 100)? as usize,
        offset: r.uint("offset", 0, u32::MAX as u64, 0)? as usize,
        format: r.choice("format", &["summary", "full"], "summary")?,
    })
}

pub fn available_list(target: &str, args: &Args) -> Outcome {
    let opts = match parse_list_args(args) {
        Ok(o) => o,
        Err(e) => {
            return finish(
                "plugin.available.list",
                target,
                raw_args(args),
                vec![],
                Value::Null,
                vec![],
                Some(e),
            );
        }
    };
    let norm_args = json!({
        "source": opts.source,
        "query": opts.query,
        "tags": opts.tags.join(","),
        "publisher": opts.publisher,
        "platform": opts.platform,
        "include_prerelease": opts.include_prerelease,
        "limit": opts.limit,
        "offset": opts.offset,
        "format": opts.format,
    });
    let loaded = (|| -> PResult<(Catalog, usize)> {
        let text = match opts.source.strip_prefix("file:") {
            None => BUILTIN_CATALOG.as_bytes().to_vec(),
            Some(path) => {
                use std::io::Read;
                let f = std::fs::File::open(path).map_err(|e| read_error(path, &e))?;
                let mut buf = Vec::new();
                f.take(MAX_CATALOG_BYTES + 1)
                    .read_to_end(&mut buf)
                    .map_err(|e| read_error(path, &e))?;
                if buf.len() as u64 > MAX_CATALOG_BYTES {
                    return Err(PluginError::failed(
                        CATALOG_INVALID,
                        format!("catalog {path} is larger than {MAX_CATALOG_BYTES} bytes"),
                    ));
                }
                buf
            }
        };
        let cat: Catalog = serde_json::from_slice(&text).map_err(|e| {
            PluginError::failed(
                CATALOG_INVALID,
                format!("catalog {} is not valid: {e}", opts.source),
            )
        })?;
        Ok((cat, text.len()))
    })();
    let (catalog, bytes) = match loaded {
        Ok(c) => c,
        Err(e) => {
            return finish(
                "plugin.available.list",
                target,
                norm_args,
                vec![json!({"type": "catalog.load", "source": opts.source, "ok": false})],
                Value::Null,
                vec![],
                Some(e),
            );
        }
    };
    let items = filter_catalog(&catalog.plugins, &opts);
    let actions = vec![
        json!({"type": "catalog.load", "source": opts.source, "bytes": bytes}),
        json!({"type": "filter.apply", "query": opts.query, "tags": opts.tags}),
    ];
    let result = json!({
        "source": opts.source,
        "catalog_version": catalog.version,
        "generated_at": catalog.generated_at,
        "count": items.len(),
        "items": items,
    });
    finish(
        "plugin.available.list",
        target,
        norm_args,
        actions,
        result,
        vec![],
        None,
    )
}

fn filter_catalog(plugins: &[CatalogPlugin], o: &ListOptions) -> Vec<Value> {
    let mut v: Vec<&CatalogPlugin> = plugins.iter().collect();
    if let Some(q) = &o.query {
        let q = q.to_lowercase();
        v.retain(|p| {
            p.id.to_lowercase().contains(&q)
                || p.name.to_lowercase().contains(&q)
                || p.description.to_lowercase().contains(&q)
                || p.publisher.to_lowercase().contains(&q)
                || p.tags.iter().any(|t| t.to_lowercase().contains(&q))
        });
    }
    if !o.tags.is_empty() {
        v.retain(|p| {
            o.tags
                .iter()
                .all(|t| p.tags.iter().any(|pt| pt.eq_ignore_ascii_case(t)))
        });
    }
    if let Some(pubr) = &o.publisher {
        v.retain(|p| p.publisher.eq_ignore_ascii_case(pubr));
    }
    v.retain(|p| {
        p.platforms.contains(&o.platform)
            || p.artifacts.as_ref().is_some_and(|arts| {
                o.platform
                    .split_once('-')
                    .is_some_and(|(os, arch)| arts.iter().any(|a| a.os == os && a.arch == arch))
            })
    });
    if !o.include_prerelease {
        v.retain(|p| !p.version.split('+').next().unwrap_or("").contains('-'));
    }
    v.sort_by(|a, b| {
        a.id.cmp(&b.id)
            .then_with(|| version_sort_key_cmp(&b.version, &a.version))
            .then_with(|| a.publisher.cmp(&b.publisher))
    });
    v.into_iter()
        .skip(o.offset)
        .take(o.limit)
        .map(|p| {
            if o.format == "full" {
                serde_json::to_value(p).unwrap_or(Value::Null)
            } else {
                json!({
                    "id": p.id,
                    "name": p.name,
                    "version": p.version,
                    "description": p.description,
                    "publisher": p.publisher,
                    "tags": p.tags,
                    "platforms": p.platforms,
                    "homepage": p.homepage,
                    "repo": p.repo,
                    "license": p.license,
                })
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// available.search
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchEntry {
    pub id: String,
    pub display_name: String,
    #[serde(default)]
    pub description: String,
    pub version: String,
    #[serde(default)]
    pub publisher: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub repo: Option<String>,
    #[serde(default)]
    pub artifact: Value,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub platforms: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct SearchIndex {
    plugins: Vec<SearchEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SearchCache {
    source_url: String,
    fetched_at: String,
    plugins: Vec<SearchEntry>,
}

struct SearchOptions {
    q: Option<String>,
    tags: Vec<String>,
    owner: Option<String>,
    name: Option<String>,
    min_version: Option<String>,
    max_results: usize,
    source: String,
    url: url::Url,
    offline: bool,
    refresh: bool,
    timeout_ms: u64,
    ca_file: Option<CaFile>,
}

fn parse_search_args(args: &Args) -> PResult<SearchOptions> {
    let r = ArgReader::new(args);
    let source = r.string("source")?.unwrap_or_else(|| "default".into());
    let url = if source == "default" {
        url::Url::parse(DEFAULT_INDEX_URL).expect("valid default index URL")
    } else {
        parse_https_url("source", &source).map_err(|_| {
            PluginError::usage(format!(
                "invalid source {source:?}: expected default or an https:// index URL; nothing was done"
            ))
        })?
    };
    let min_version = r.string("min_version")?;
    if let Some(v) = &min_version
        && !is_version(v)
    {
        return Err(PluginError::usage(format!(
            "invalid min_version {v:?}: expected a version such as 1.2.0; nothing was done"
        )));
    }
    let offline = r.bool("offline", false)?;
    let refresh = r.bool("refresh", false)?;
    if offline && refresh {
        return Err(PluginError::usage(
            "offline=true and refresh=true contradict each other; nothing was done",
        ));
    }
    let ca_file = r.ca_file()?;
    if offline && ca_file.is_some() {
        return Err(PluginError::usage(
            "ca_file has no use with offline=true (nothing is fetched); nothing was done",
        ));
    }
    let mut tags: Vec<String> = r
        .string("tags")?
        .map(|t| {
            t.split(';')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    tags.sort();
    Ok(SearchOptions {
        q: r.string("q")?,
        tags,
        owner: r.string("owner")?,
        name: r.string("name")?,
        min_version,
        max_results: r.uint("max_results", 1, 200, 25)? as usize,
        source,
        url,
        offline,
        refresh,
        timeout_ms: r.timeout_ms(5000)?,
        ca_file,
    })
}

/// The cache file name of an index URL.
fn cache_name(o: &SearchOptions) -> String {
    if o.source == "default" {
        return "index-cache.json".into();
    }
    let safe: String = o
        .source
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("cache-{safe}.json")
}

fn read_cache(o: &SearchOptions) -> PResult<Option<SearchCache>> {
    let loc = paths::locations()?;
    let Some(dir) = paths::existing_dir(&loc.state, &["resh", "plugins"])? else {
        return Ok(None);
    };
    let Some(data) = paths::read_file(&dir, &cache_name(o), MAX_CATALOG_BYTES)? else {
        return Ok(None);
    };
    // A cache in an older format, or of another URL, is not used.
    Ok(serde_json::from_slice::<SearchCache>(&data)
        .ok()
        .filter(|c| c.source_url == o.url.as_str()))
}

fn write_cache(o: &SearchOptions, cache: &SearchCache) -> PResult<()> {
    let loc = paths::locations()?;
    let dir = paths::ensure_dir(&loc.state, &["resh", "plugins"], 0o700)?;
    let data = serde_json::to_vec(cache)
        .map_err(|e| PluginError::failed(super::common::IO_ERROR, e.to_string()))?;
    paths::write_file_atomic(&dir, &cache_name(o), &data, 0o600)
}

pub fn available_search(target: &str, args: &Args) -> Outcome {
    let op = "plugin.available.search";
    let o = match parse_search_args(args) {
        Ok(o) => o,
        Err(e) => {
            return finish(
                op,
                target,
                raw_args(args),
                vec![],
                Value::Null,
                vec![],
                Some(e),
            );
        }
    };
    let deadline = Deadline::after_ms(o.timeout_ms);
    let norm_args = json!({
        "q": o.q,
        "tags": if o.tags.is_empty() { Value::Null } else { json!(o.tags.join(";")) },
        "owner": o.owner,
        "name": o.name,
        "min_version": o.min_version,
        "max_results": o.max_results,
        "source": o.source,
        "timeout_ms": o.timeout_ms,
        "offline": o.offline,
        "refresh": o.refresh,
    });
    let mut warnings = Vec::new();
    let loaded = (|| -> PResult<(Vec<SearchEntry>, Value)> {
        if !o.refresh
            && let Some(c) = read_cache(&o)?
        {
            let info = json!({"id": o.source, "mode": "cache", "ref": c.source_url, "fetched_at": c.fetched_at});
            return Ok((c.plugins, info));
        }
        if o.offline {
            return Err(PluginError::failed(
                NOT_FOUND,
                format!(
                    "no cached index for {} (offline=true); run once without offline=true to fetch it",
                    o.url
                ),
            ));
        }
        let fetcher = Fetcher::new(o.ca_file.as_ref(), deadline)?;
        let body = fetcher.get(&o.url, MAX_CATALOG_BYTES, "the plugin index")?;
        let index: SearchIndex = serde_json::from_slice(&body).map_err(|e| {
            PluginError::failed(
                CATALOG_INVALID,
                format!("the index at {} is not valid: {e}", o.url),
            )
        })?;
        let cache = SearchCache {
            source_url: o.url.to_string(),
            fetched_at: Utc::now().to_rfc3339(),
            plugins: index.plugins,
        };
        if let Err(e) = write_cache(&o, &cache) {
            warnings.push(format!("the index was not cached: {}", e.message));
        }
        let info = json!({"id": o.source, "mode": "online", "ref": cache.source_url, "fetched_at": cache.fetched_at});
        Ok((cache.plugins, info))
    })();
    let (plugins, source_info) = match loaded {
        Ok(x) => x,
        Err(e) => {
            return finish(
                op,
                target,
                norm_args,
                vec![json!({"type": "catalog.load", "source": o.source, "ok": false})],
                Value::Null,
                warnings,
                Some(e),
            );
        }
    };
    let items = search(&plugins, &o);
    let actions = vec![
        json!({"type": "catalog.load", "source": o.source, "mode": source_info["mode"]}),
        json!({"type": "search.execute", "query": o.q, "filters_applied": true}),
    ];
    let result = json!({
        "source": source_info,
        "query": {
            "q": o.q,
            "tags": o.tags,
            "owner": o.owner,
            "name": o.name,
            "min_version": o.min_version,
            "max_results": o.max_results,
        },
        "count": items.len(),
        "items": items,
    });
    finish(op, target, norm_args, actions, result, warnings, None)
}

fn search(plugins: &[SearchEntry], o: &SearchOptions) -> Vec<Value> {
    let mut hits: Vec<(f64, &SearchEntry, Vec<String>)> = plugins
        .iter()
        .filter(|p| {
            o.owner
                .as_ref()
                .is_none_or(|w| p.publisher.eq_ignore_ascii_case(w))
        })
        .filter(|p| o.name.as_ref().is_none_or(|n| p.id.eq_ignore_ascii_case(n)))
        .filter(|p| {
            o.min_version.as_ref().is_none_or(|m| {
                super::common::compare_versions(&p.version, m)
                    .is_some_and(|ord| ord != std::cmp::Ordering::Less)
            })
        })
        .filter(|p| {
            o.tags
                .iter()
                .all(|t| p.tags.iter().any(|pt| pt.eq_ignore_ascii_case(t)))
        })
        .map(|p| {
            let (score, mut hl) = score(p, o.q.as_deref());
            hl.sort();
            (score, p, hl)
        })
        .filter(|(score, _, _)| *score > 0.0)
        .collect();
    hits.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.1.id.cmp(&b.1.id))
    });
    hits.truncate(o.max_results);
    hits.into_iter()
        .map(|(score, p, highlights)| {
            let mut tags = p.tags.clone();
            tags.sort();
            json!({
                "id": p.id,
                "display_name": p.display_name,
                "version": p.version,
                "publisher": p.publisher,
                "description": p.description,
                "tags": tags,
                "license": p.license,
                "homepage": p.homepage,
                "repo": p.repo,
                "artifact": p.artifact,
                "sha256": p.sha256,
                "score": score,
                "highlights": highlights,
            })
        })
        .collect()
}

/// Score in 0..=1 and the matched fields; without a query every plugin
/// scores 1, and with one a plugin that matches nothing is dropped.
fn score(p: &SearchEntry, q: Option<&str>) -> (f64, Vec<String>) {
    let Some(q) = q.map(str::trim).filter(|q| !q.is_empty()) else {
        return (1.0, vec![]);
    };
    let q = q.to_lowercase();
    let mut s: f64 = 0.0;
    let mut hl = Vec::new();
    let id = p.id.to_lowercase();
    if id == q {
        s += 1.0;
        hl.push("matched:id".to_string());
    } else if id.contains(&q) {
        s += 0.8;
        hl.push("matched:id".to_string());
    }
    if p.display_name.to_lowercase().contains(&q) {
        s += 0.6;
        hl.push("matched:display_name".to_string());
    }
    for t in &p.tags {
        if t.to_lowercase().contains(&q) {
            s += 0.4;
            hl.push(format!("matched:tag:{t}"));
        }
    }
    if p.publisher.to_lowercase().contains(&q) {
        s += 0.3;
        hl.push("matched:publisher".to_string());
    }
    if p.description.to_lowercase().contains(&q) {
        s += 0.2;
        hl.push("matched:desc".to_string());
    }
    (s.min(1.0), hl)
}

// ---------------------------------------------------------------------------
// installed.list
// ---------------------------------------------------------------------------

struct InstalledOptions {
    enabled: Option<bool>,
    name: Option<String>,
    prefix: Option<String>,
    tag: Option<String>,
    source: Option<&'static str>,
    limit: usize,
    offset: usize,
    sort: &'static str,
    order: &'static str,
    format: &'static str,
}

fn parse_installed_args(args: &Args) -> PResult<InstalledOptions> {
    let r = ArgReader::new(args);
    Ok(InstalledOptions {
        enabled: if r.has("enabled") {
            Some(r.bool("enabled", false)?)
        } else {
            None
        },
        name: r.string("name")?,
        prefix: r.string("prefix")?,
        tag: r.string("tag")?,
        source: if r.has("source") {
            Some(r.choice("source", &["registry", "url", "file"], "registry")?)
        } else {
            None
        },
        limit: r.uint("limit", 1, 500, 200)? as usize,
        offset: r.uint("offset", 0, u32::MAX as u64, 0)? as usize,
        sort: r.choice("sort", &["name", "installed_at", "updated_at"], "name")?,
        order: r.choice("order", &["asc", "desc"], "asc")?,
        format: r.choice("format", &["full", "summary", "names"], "full")?,
    })
}

pub fn installed_list(target: &str, args: &Args) -> Outcome {
    let op = "plugin.installed.list";
    let o = match parse_installed_args(args) {
        Ok(o) => o,
        Err(e) => {
            return finish(
                op,
                target,
                raw_args(args),
                vec![],
                Value::Null,
                vec![],
                Some(e),
            );
        }
    };
    let norm_args = json!({
        "enabled": o.enabled,
        "name": o.name,
        "prefix": o.prefix,
        "tag": o.tag,
        "source": o.source,
        "limit": o.limit,
        "offset": o.offset,
        "sort": o.sort,
        "order": o.order,
        "format": o.format,
    });
    let mut actions = Vec::new();
    let mut warnings = Vec::new();
    let store_path = PluginStore::default_root()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let items = (|| -> PResult<Vec<Value>> {
        let store = PluginStore::open(false)?;
        actions.push(json!({
            "type": "scan.installed_dir", "target": "installed_dir", "ok": true,
            "detail": {"path": store_path, "exists": store.is_some()}
        }));
        let Some(store) = store else {
            return Ok(vec![]);
        };
        let mut items = Vec::new();
        for id in store.plugin_ids()? {
            items.push(installed_item(&store, &id));
        }
        actions.push(json!({
            "type": "read.manifests", "target": "manifests", "ok": true,
            "detail": {"count": items.len()}
        }));
        Ok(items)
    })();
    let mut items = match items {
        Ok(i) => i,
        Err(e) => {
            return finish(
                op,
                target,
                norm_args,
                actions,
                Value::Null,
                warnings,
                Some(e),
            );
        }
    };
    let (enabled, w) = super::state::effective_enabled();
    warnings.extend(w);
    actions.push(json!({
        "type": "read.enabled_registry", "target": "enabled_registry", "ok": true,
        "detail": {"count": enabled.values().filter(|v| **v).count()}
    }));
    for it in &mut items {
        let id = it["name"].as_str().unwrap_or_default().to_string();
        it["enabled"] = json!(enabled.get(&id).copied().unwrap_or(false));
    }
    items.retain(|it| {
        let name = it["name"].as_str().unwrap_or_default();
        o.enabled.is_none_or(|e| it["enabled"] == json!(e))
            && o.name.as_ref().is_none_or(|n| name == n)
            && o.prefix
                .as_ref()
                .is_none_or(|p| name.starts_with(p.as_str()))
            && o.source.is_none_or(|s| it["source"]["type"] == json!(s))
            && o.tag.as_ref().is_none_or(|t| {
                it["manifest"]["tags"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|x| x == &json!(t)))
            })
    });
    actions.push(json!({"type": "filter.apply", "target": "apply", "ok": true, "detail": {"count": items.len()}}));
    items.sort_by(|a, b| {
        let key = |v: &Value| v[o.sort].as_str().unwrap_or_default().to_string();
        let ord = if o.sort == "name" {
            let (x, y) = (key(a), key(b));
            x.to_lowercase().cmp(&y.to_lowercase()).then(x.cmp(&y))
        } else {
            key(a)
                .cmp(&key(b))
                .then_with(|| key_name(a).cmp(&key_name(b)))
        };
        if o.order == "desc" {
            ord.reverse()
        } else {
            ord
        }
    });
    actions.push(json!({"type": "sort.apply", "target": "apply", "ok": true, "detail": {"sort": o.sort, "order": o.order}}));
    let total = items.len();
    let page: Vec<Value> = items.into_iter().skip(o.offset).take(o.limit).collect();
    actions.push(json!({"type": "paginate.apply", "target": "apply", "ok": true, "detail": {"offset": o.offset, "limit": o.limit}}));
    let out: Vec<Value> = page
        .into_iter()
        .map(|it| match o.format {
            "names" => it["name"].clone(),
            "summary" => json!({
                "name": it["name"], "version": it["version"], "enabled": it["enabled"],
                "source": it["source"], "health": it["health"],
            }),
            _ => it,
        })
        .collect();
    let result = json!({
        "count": out.len(),
        "total": total,
        "offset": o.offset,
        "limit": o.limit,
        "items": out,
    });
    finish(op, target, norm_args, actions, result, warnings, None)
}

fn key_name(v: &Value) -> String {
    v["name"].as_str().unwrap_or_default().to_string()
}

/// One store entry for installed.list; a damaged entry is reported with
/// `health: "broken"` and the reason.
fn installed_item(store: &PluginStore, id: &str) -> Value {
    match store.installed(id) {
        Ok(Some(m)) => {
            let manifest = read_manifest(std::path::Path::new(&m.install_path));
            let mut v = json!({
                "name": id,
                "version": m.version,
                "enabled": false,
                "source": {"type": m.source},
                "paths": {"install_dir": m.install_path, "binary": m.bin_path},
                "health": "ok",
                "installed_at": m.installed_at,
                "updated_at": m.updated_at.clone().unwrap_or(m.installed_at.clone()),
            });
            if let Some(man) = manifest {
                v["manifest"] = man;
            }
            v
        }
        Ok(None) => json!({
            "name": id, "version": null, "enabled": false, "source": {"type": "unknown"},
            "paths": {"install_dir": store.plugin_dir(id).to_string_lossy()},
            "health": "broken", "problem": "the plugin has no current version",
        }),
        Err(e) => json!({
            "name": id, "version": null, "enabled": false, "source": {"type": "unknown"},
            "paths": {"install_dir": store.plugin_dir(id).to_string_lossy()},
            "health": "broken", "problem": e.message,
        }),
    }
}

/// `description`, `tags` and `capabilities` from the plugin's own
/// `manifest.json`, when it has one.
fn read_manifest(dir: &std::path::Path) -> Option<Value> {
    let data = paths::read_file(dir, "manifest.json", 1024 * 1024).ok()??;
    let m: Value = serde_json::from_slice(&data).ok()?;
    let strings = |k: &str| -> Vec<String> {
        m[k].as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut out = json!({});
    if let Some(d) = m["description"].as_str() {
        out["description"] = json!(d);
    }
    let tags = strings("tags");
    if !tags.is_empty() {
        out["tags"] = json!(tags);
    }
    let caps = strings("capabilities");
    if !caps.is_empty() {
        out["capabilities"] = json!(caps);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_catalog_parses() {
        let c: Catalog = serde_json::from_str(BUILTIN_CATALOG).unwrap();
        assert!(!c.plugins.is_empty());
    }

    fn entry(id: &str, version: &str, tags: &[&str]) -> SearchEntry {
        SearchEntry {
            id: id.into(),
            display_name: id.into(),
            description: String::new(),
            version: version.into(),
            publisher: "acme".into(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            license: None,
            homepage: None,
            repo: None,
            artifact: Value::Null,
            sha256: None,
            platforms: None,
        }
    }

    #[test]
    fn search_scores_filters_and_orders() {
        let mut args = Args::new();
        args.insert("q".into(), "dock".into());
        let o = parse_search_args(&args).unwrap();
        let plugins = vec![
            entry("resh.docker", "1.10.0", &["container"]),
            entry("other", "1.0.0", &["docker"]),
            entry("nothing", "1.0.0", &[]),
        ];
        let hits = search(&plugins, &o);
        assert_eq!(hits.len(), 2, "a plugin matching nothing is dropped");
        assert_eq!(hits[0]["id"], "resh.docker");
        args.insert("min_version".into(), "1.9.0".into());
        let o = parse_search_args(&args).unwrap();
        let hits = search(&plugins, &o);
        assert_eq!(hits.len(), 1, "1.10.0 >= 1.9.0 numerically");
    }
}
