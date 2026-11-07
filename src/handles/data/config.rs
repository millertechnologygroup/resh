use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use globset::{Glob, GlobMatcher};
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use url::Url;
use walkdir::WalkDir;

use crate::core::{
    help::{self, HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::Status,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigEntry {
    pub key: String,
    pub full_key: String,
    pub kind: ConfigEntryKind,
    pub has_value: bool,
    pub meta: ConfigMeta,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ConfigEntryKind {
    Branch,
    Leaf,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct LsResponse {
    prefix: String,
    recursive: bool,
    pattern: Option<String>,
    limit: Option<usize>,
    offset: usize,
    entries: Vec<ConfigEntry>,
}

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("config", |u| Ok(Box::new(ConfigHandle::from_url(u)?)));
}

/// Metadata for `resh config --help` and `resh config <verb> --help`.
static CONFIG_HELP: HandleHelp = HandleHelp {
    description: "The config handle stores JSON configuration values as one file per key \
        under the user's config directory, normally ~/.config/resh/config. A target such as \
        config://app/db/url names the namespace app and the key db/url, while a single \
        segment such as config://theme uses the default namespace. Values can be read, \
        written, listed by prefix, and watched for changes.",
    usage: "resh config://[<namespace>/]<key>.<verb>[(key=value,...)]",
    verbs: &[
        VerbHelp {
            name: "get",
            definition: "Prints the JSON value stored for a key exactly as saved, failing if \
                the key does not exist or its file holds invalid JSON.",
            detail: Some(VerbDetail {
                usage: "resh config://[<namespace>/]<key>.get",
                example: "resh config://app/db/url.get",
                example_output: Some(r#""postgres://db.example.com:5432/app""#),
            }),
        },
        VerbHelp {
            name: "ls",
            definition: "Lists the keys and sub-namespaces under a prefix as a JSON object, \
                with optional recursion, glob filtering on key names, and pagination.",
            detail: Some(VerbDetail {
                usage: "resh config://[<prefix>].ls [recursive=true|false] [pattern=<glob>]\n  \
                    [limit=<n>] [offset=<n>]",
                example: "resh --json-pretty config://app.ls",
                example_output: Some(
                    r#"{
  "entries": [
    {
      "full_key": "app/db",
      "has_value": true,
      "key": "db",
      "kind": "branch",
      "meta": {}
    },
    {
      "full_key": "app/theme",
      "has_value": true,
      "key": "theme",
      "kind": "leaf",
      "meta": {
        "size": 6,
        "updated_at": "2026-10-16T09:12:44.512309817+00:00"
      }
    }
  ],
  "limit": null,
  "offset": 0,
  "pattern": null,
  "prefix": "app",
  "recursive": false
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "watch",
            definition: "Watches the configuration files of the target namespace (all namespaces for a \
                single-segment target) and prints one JSON line \
                per change (op set or rm, or snapshot for initial values) until a timeout or \
                event limit is reached, or forever if neither is given.",
            detail: Some(VerbDetail {
                usage: "resh config://[<prefix>].watch [key=<key>] [prefix=<prefix>]\n  \
                    [timeout_ms=<n>] [max_events=<n>] [initial=true|false]",
                example: "resh config://app.watch prefix=app/db timeout_ms=10000 max_events=5",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "set",
            definition: "Stores a value for a key with an atomic file write, parsing it as \
                JSON when possible and otherwise saving it as a JSON string, and prints nothing on success.",
            detail: Some(VerbDetail {
                usage: "resh config://[<namespace>/]<key>.set value=<value> [raw=true|false]",
                example: "resh config://app/db/url.set value=postgres://db.example.com:5432/app",
                example_output: None,
            }),
        },
    ],
};

pub struct ConfigHandle {
    namespace: String,
    key: String,
    file_path: PathBuf,
    base_path: PathBuf,
    prefix: String,
    original_url: Url,
    /// Why the target cannot be used (a `.` or `..` segment), if it can't.
    invalid_target: Option<String>,
}

/// The arguments each verb accepts. Help usage lists exactly these, and
/// anything else is refused before the verb acts.
const GET_ARGS: &[&str] = &[];
const SET_ARGS: &[&str] = &["value", "raw"];
const LS_ARGS: &[&str] = &["recursive", "pattern", "limit", "offset"];
const WATCH_ARGS: &[&str] = &["key", "prefix", "timeout_ms", "max_events", "initial"];

/// Arguments accepted by `verb`, or `None` for an unknown verb.
fn verb_args(verb: &str) -> Option<&'static [&'static str]> {
    match verb {
        "get" => Some(GET_ARGS),
        "set" => Some(SET_ARGS),
        "ls" => Some(LS_ARGS),
        "watch" => Some(WATCH_ARGS),
        _ => None,
    }
}

/// Refuses an argument `verb` does not take (exit 2). `dry_run` is checked
/// by the dispatcher, which refuses `dry_run=true` for every config verb, so
/// only `dry_run=false` reaches here and it changes nothing.
fn check_args(verb: &str, allowed: &[&str], args: &Args) -> Option<Status> {
    let mut keys: Vec<&String> = args.keys().collect();
    keys.sort();
    let bad = keys
        .into_iter()
        .find(|k| k.as_str() != "dry_run" && !allowed.contains(&k.as_str()))?;
    if bad == "timeout_ms" {
        return Some(Status::err(
            2,
            format!("config {verb} does not take timeout_ms; only watch has a time limit"),
        ));
    }
    Some(Status::err(
        2,
        format!("unknown argument for config {verb}: {bad}"),
    ))
}

/// Reads a boolean argument; an unreadable value is an error (exit 2), never
/// a silent default.
fn bool_arg(args: &Args, key: &str, default: bool) -> std::result::Result<bool, Status> {
    crate::core::lenient::bool_arg(args, key)
        .map(|v| v.unwrap_or(default))
        .map_err(|e| Status::err(2, e.to_string()))
}

/// Reads a non-negative integer argument (exit 2 if it is not one).
fn u64_arg(args: &Args, key: &str) -> std::result::Result<u64, Status> {
    match args.get(key) {
        None => Ok(0),
        Some(v) => v.trim().parse::<u64>().map_err(|_| {
            Status::err(
                2,
                format!("invalid {key} value: {v:?} (expected a non-negative integer)"),
            )
        }),
    }
}

/// Unique suffix for `set`'s temporary file within this process.
static TEMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl ConfigHandle {
    pub fn from_url(u: &Url) -> Result<Self> {
        // XDG_CONFIG_HOME, else ~/.config.
        let config_dir = dirs::config_dir().unwrap_or_else(|| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string())).join(".config")
        });
        Ok(Self::with_config_dir(u, &config_dir))
    }

    /// Builds the handle for `u` with values stored under
    /// `<config_dir>/resh/config`.
    fn with_config_dir(u: &Url, config_dir: &Path) -> Self {
        let base_path = config_dir.join("resh").join("config");
        // Check for help request first
        if Self::should_show_help(u) {
            return Self {
                namespace: String::new(),
                key: String::new(),
                file_path: base_path.clone(),
                base_path,
                prefix: String::new(),
                original_url: u.clone(),
                invalid_target: None,
            };
        }
        // Extract prefix from URL for hierarchical operations
        let prefix = if let Some(host) = u.host_str() {
            // config://namespace/path
            let path = u.path().strip_prefix('/').unwrap_or(u.path());
            if path.is_empty() {
                host.to_string()
            } else {
                format!("{}/{}", host, path)
            }
        } else {
            // config:///path or config://path
            let path = u.path().strip_prefix('/').unwrap_or(u.path());
            path.to_string()
        };

        // For backward compatibility, extract namespace and key from prefix
        let (namespace, key) = if prefix.is_empty() {
            ("default".to_string(), String::new())
        } else {
            let parts: Vec<&str> = prefix.split('/').collect();
            if parts.len() == 1 {
                ("default".to_string(), parts[0].to_string())
            } else {
                (parts[0].to_string(), parts[1..].join("/"))
            }
        };

        // `.` and `..` would resolve outside the namespace (`config://..`
        // names the parent of the config directory), so they are refused.
        let invalid_target = prefix
            .split('/')
            .any(|seg| seg == "." || seg == "..")
            .then(|| {
                format!("invalid config target {prefix:?}: '.' and '..' segments are not allowed")
            });

        // Sanitize namespace and key to only allow [A-Za-z0-9._-/]
        let sanitized_namespace = Self::sanitize_name(&namespace);
        let sanitized_key = if key.is_empty() {
            String::new()
        } else {
            Self::sanitize_path(&key)
        };

        let file_path = if sanitized_key.is_empty() {
            // For ls operations on namespaces/directories
            base_path.join(&sanitized_namespace)
        } else {
            base_path
                .join(&sanitized_namespace)
                .join(format!("{}.json", sanitized_key))
        };

        Self {
            namespace: sanitized_namespace,
            key: sanitized_key,
            file_path,
            base_path,
            prefix: Self::sanitize_prefix(&prefix),
            original_url: u.clone(),
            invalid_target,
        }
    }

    fn sanitize_name(name: &str) -> String {
        name.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    }

    /// The `ls` prefix with the same sanitizing as stored keys: the first
    /// segment as a namespace, the rest as a key path.
    fn sanitize_prefix(prefix: &str) -> String {
        match prefix.split_once('/') {
            None => Self::sanitize_name(prefix),
            Some((ns, rest)) => {
                format!("{}/{}", Self::sanitize_name(ns), Self::sanitize_path(rest))
            }
        }
    }

    fn sanitize_path(path: &str) -> String {
        path.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' || c == '/' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    }

    fn ensure_base_config_dir(&self) -> Result<()> {
        if let Some(parent) = self.file_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {:?}", parent))?;
        }
        Ok(())
    }

    fn verb_get(&self, _args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Reject get on empty keys
        if self.key.is_empty() {
            return Ok(Status::err(
                1,
                "Empty key not allowed for get operation".to_string(),
            ));
        }

        // Read-only: nothing is created when the key is missing.
        let content = match fs::read_to_string(&self.file_path) {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Status::err(1, "not found".to_string()));
            }
            Err(e) => {
                return Ok(Status::err(3, format!("I/O error: {}", e)));
            }
        };

        // Validate that it's valid JSON
        match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(_) => {
                // Write the JSON directly to stdout
                write!(io.stdout, "{}", content).with_context(|| "Failed to write to stdout")?;
                Ok(Status::ok())
            }
            Err(_) => Ok(Status::err(2, "invalid json".to_string())),
        }
    }

    fn verb_set(&self, args: &Args, _io: &mut IoStreams) -> Result<Status> {
        // Reject set on empty keys
        if self.key.is_empty() {
            return Ok(Status::err(
                1,
                "Empty key not allowed for set operation".to_string(),
            ));
        }

        // Get the value argument
        let value = match args.get("value") {
            Some(v) => v,
            None => {
                return Ok(Status::err(1, "missing arg: value".to_string()));
            }
        };

        // Determine if raw mode is enabled
        let raw_mode = match bool_arg(args, "raw", false) {
            Ok(v) => v,
            Err(status) => return Ok(status),
        };

        // Process the value based on raw mode
        let json_value = if raw_mode {
            // In raw mode, parse as JSON directly
            match serde_json::from_str::<serde_json::Value>(value) {
                Ok(v) => v,
                Err(_) => {
                    return Ok(Status::err(2, "invalid json".to_string()));
                }
            }
        } else {
            // Try to parse as JSON first, if that fails treat as string
            match serde_json::from_str::<serde_json::Value>(value) {
                Ok(v) => v,
                Err(_) => serde_json::Value::String(value.clone()),
            }
        };

        // Ensure parent directory exists
        if let Err(e) = self.ensure_base_config_dir() {
            return Ok(Status::err(3, format!("I/O error: {:#}", e)));
        }

        // Perform atomic write using temporary file. The name is not a
        // `.json` file, so `ls`, `get` and `watch` never see it.
        let n = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let temp_path =
            self.file_path
                .with_extension(format!("json.tmp-{}-{}", std::process::id(), n));

        let json_string =
            serde_json::to_string(&json_value).with_context(|| "Failed to serialize JSON")?;

        let written = File::create(&temp_path).and_then(|mut temp_file| {
            temp_file.write_all(json_string.as_bytes())?;
            temp_file.sync_all()
        });
        if let Err(e) = written {
            let _ = fs::remove_file(&temp_path);
            return Ok(Status::err(
                3,
                format!("I/O error: writing {}: {}", temp_path.display(), e),
            ));
        }

        // Atomically rename temp file to final location
        match fs::rename(&temp_path, &self.file_path) {
            Ok(()) => Ok(Status::ok()),
            Err(e) => {
                // Clean up temp file on error
                let _ = fs::remove_file(&temp_path);
                Ok(Status::err(3, format!("I/O error: {}", e)))
            }
        }
    }
}

impl ConfigHandle {
    fn verb_ls(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments
        let recursive = match bool_arg(args, "recursive", false) {
            Ok(v) => v,
            Err(status) => return Ok(status),
        };
        let pattern = args.get("pattern").cloned();
        let limit = if let Some(limit_str) = args.get("limit") {
            match limit_str.parse::<usize>() {
                Ok(l) => Some(l),
                Err(_) => return Ok(Status::err(2, "invalid limit value".to_string())),
            }
        } else {
            None
        };
        let offset = if let Some(offset_str) = args.get("offset") {
            match offset_str.parse::<usize>() {
                Ok(o) => o,
                Err(_) => return Ok(Status::err(2, "invalid offset value".to_string())),
            }
        } else {
            0
        };

        // Build glob matcher if pattern is provided
        let glob_matcher = if let Some(ref pat) = pattern {
            match Glob::new(pat) {
                Ok(glob) => Some(glob.compile_matcher()),
                Err(_) => return Ok(Status::err(2, "invalid pattern".to_string())),
            }
        } else {
            None
        };

        // List config entries
        let entries = match self.list_config_entries(recursive, glob_matcher.as_ref()) {
            Ok(entries) => entries,
            Err(e) => return Ok(Status::err(3, format!("I/O error: {:#}", e))),
        };

        // Sort entries by full_key for deterministic pagination
        let mut sorted_entries = entries;
        sorted_entries.sort_by(|a, b| a.full_key.cmp(&b.full_key));

        // Apply offset and limit
        let paginated_entries: Vec<ConfigEntry> = sorted_entries
            .into_iter()
            .skip(offset)
            .take(limit.unwrap_or(usize::MAX))
            .collect();

        // Build response
        let response = LsResponse {
            prefix: self.prefix.clone(),
            recursive,
            pattern,
            limit,
            offset,
            entries: paginated_entries,
        };

        // Serialize to JSON
        match serde_json::to_string(&response) {
            Ok(json) => {
                write!(io.stdout, "{}", json).with_context(|| "Failed to write JSON to stdout")?;
                Ok(Status::ok())
            }
            Err(e) => {
                write!(io.stderr, "Failed to serialize JSON: {}", e)
                    .with_context(|| "Failed to write error to stderr")?;
                Ok(Status::err(3, "JSON serialization failed".to_string()))
            }
        }
    }

    fn list_config_entries(
        &self,
        recursive: bool,
        glob_matcher: Option<&GlobMatcher>,
    ) -> Result<Vec<ConfigEntry>> {
        let mut entries = Vec::new();
        let search_base = if self.prefix.is_empty() {
            self.base_path.clone()
        } else {
            // `prefix` is sanitized and has no `.`/`..` segments.
            self.base_path.join(&self.prefix)
        };

        if !search_base.exists() {
            return Ok(entries); // Return empty list if path doesn't exist
        }

        // Collect all entries first
        if recursive {
            // min_depth(1): the prefix directory itself is not an entry.
            for entry in WalkDir::new(&search_base)
                .min_depth(1)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if let Some(config_entry) =
                    self.path_to_config_entry(&entry.path(), &search_base, recursive)?
                {
                    if self.matches_pattern(&config_entry, glob_matcher) {
                        entries.push(config_entry);
                    }
                }
            }
        } else {
            if let Ok(dir_entries) = fs::read_dir(&search_base) {
                for entry in dir_entries.filter_map(|e| e.ok()) {
                    if let Some(config_entry) =
                        self.path_to_config_entry(&entry.path(), &search_base, recursive)?
                    {
                        if self.matches_pattern(&config_entry, glob_matcher) {
                            entries.push(config_entry);
                        }
                    }
                }
            }
        }

        Ok(entries)
    }

    fn path_to_config_entry(
        &self,
        path: &Path,
        search_base: &Path,
        recursive: bool,
    ) -> Result<Option<ConfigEntry>> {
        let relative_path = path.strip_prefix(search_base).unwrap_or(path);

        if path.is_file() {
            // Check if it's a .json file
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if file_name.ends_with(".json") {
                    let key_name = file_name.strip_suffix(".json").unwrap();
                    let full_key = if self.prefix.is_empty() {
                        if let Some(parent) = relative_path.parent() {
                            if parent.as_os_str().is_empty() {
                                key_name.to_string()
                            } else {
                                format!("{}/{}", parent.display(), key_name)
                            }
                        } else {
                            key_name.to_string()
                        }
                    } else {
                        if let Some(parent) = relative_path.parent() {
                            if parent.as_os_str().is_empty() {
                                format!("{}/{}", self.prefix, key_name)
                            } else {
                                format!("{}/{}/{}", self.prefix, parent.display(), key_name)
                            }
                        } else {
                            format!("{}/{}", self.prefix, key_name)
                        }
                    };

                    let metadata = fs::metadata(path)?;
                    let size = Some(metadata.len());
                    let updated_at = metadata
                        .modified()
                        .ok()
                        .map(|t| DateTime::<Utc>::from(t).to_rfc3339());

                    return Ok(Some(ConfigEntry {
                        key: key_name.to_string(),
                        full_key,
                        kind: ConfigEntryKind::Leaf,
                        has_value: true,
                        meta: ConfigMeta { size, updated_at },
                    }));
                }
            }
        } else if path.is_dir() {
            // Only include directories if they're immediate children (not recursive) or if recursive is true
            if !recursive && relative_path.components().count() > 1 {
                return Ok(None);
            }

            let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if dir_name.is_empty() || dir_name.starts_with('.') {
                return Ok(None);
            }

            let full_key = if self.prefix.is_empty() {
                relative_path.display().to_string()
            } else {
                format!("{}/{}", self.prefix, relative_path.display())
            };

            // Check if this directory has any .json files (has_value)
            let has_value = fs::read_dir(path)?
                .filter_map(|e| e.ok())
                .any(|e| e.path().is_file() && e.file_name().to_string_lossy().ends_with(".json"));

            return Ok(Some(ConfigEntry {
                key: dir_name.to_string(),
                full_key,
                kind: ConfigEntryKind::Branch,
                has_value,
                meta: ConfigMeta {
                    size: None,
                    updated_at: None,
                },
            }));
        }

        Ok(None)
    }

    fn matches_pattern(&self, entry: &ConfigEntry, glob_matcher: Option<&GlobMatcher>) -> bool {
        if let Some(matcher) = glob_matcher {
            matcher.is_match(&entry.key)
        } else {
            true
        }
    }
}

#[derive(Debug, Serialize)]
struct WatchEvent {
    op: String,
    scope: String,
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<serde_json::Value>,
    version: u64,
    ts: String,
    source: String,
}

struct ConfigChange {
    op: String,
    key: String,
    value: Option<serde_json::Value>,
}

impl ConfigHandle {
    fn verb_watch(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse and validate arguments
        let key = args.get("key").cloned();
        let prefix = args.get("prefix").cloned();

        // Mutual exclusion check
        if key.is_some() && prefix.is_some() {
            writeln!(io.stderr, "key and prefix cannot be used together")?;
            return Ok(Status::err(1, "key and prefix cannot be used together"));
        }

        // timeout_ms and max_events: 0 (the default) means no limit. A value
        // that is not a number is refused rather than run without a limit.
        let parsed = u64_arg(args, "timeout_ms").and_then(|timeout_ms| {
            let max_events = u64_arg(args, "max_events")?;
            let initial = bool_arg(args, "initial", false)?;
            Ok((timeout_ms, max_events, initial))
        });
        let (timeout_ms, max_events, initial) = match parsed {
            Ok(v) => v,
            Err(status) => return Ok(status),
        };

        self.watch_impl(key, prefix, timeout_ms, max_events, initial, io)
    }

    fn watch_impl(
        &self,
        key: Option<String>,
        prefix: Option<String>,
        timeout_ms: u64,
        max_events: u64,
        initial: bool,
        io: &mut IoStreams,
    ) -> Result<Status> {
        let start_time = Instant::now();
        let mut events_emitted = 0u64;
        let mut version_counter = 1u64;

        // Determine the scope for event emission
        let scope = if self.prefix.is_empty() {
            "default".to_string()
        } else {
            self.prefix.clone()
        };

        // Determine watch directory
        let watch_dir = if self.namespace == "default" {
            self.base_path.clone()
        } else {
            self.base_path.join(&self.namespace)
        };

        // Ensure watch directory exists
        if !watch_dir.exists() {
            if let Err(e) = fs::create_dir_all(&watch_dir) {
                writeln!(io.stderr, "Failed to create watch directory: {}", e)?;
                return Ok(Status::err(2, format!("config watch failed: {}", e)));
            }
        }

        // Handle initial events if requested
        if initial {
            let initial_snapshot = self.load_current_snapshot(&watch_dir)?;
            for (file_key, value) in initial_snapshot {
                if self.key_matches_filter(&file_key, &key, &prefix) {
                    let event = WatchEvent {
                        op: "snapshot".to_string(),
                        scope: scope.clone(),
                        key: file_key,
                        value: Some(value),
                        version: version_counter,
                        ts: Utc::now().to_rfc3339(),
                        source: "config".to_string(),
                    };

                    let event_json = serde_json::to_string(&event)
                        .with_context(|| "Failed to serialize watch event")?;
                    writeln!(io.stdout, "{}", event_json)?;

                    events_emitted += 1;
                    version_counter += 1;

                    if max_events > 0 && events_emitted >= max_events {
                        return Ok(Status::ok());
                    }
                }
            }
        }

        // Set up file watching
        let (tx, rx) = mpsc::channel();
        let watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                if let Ok(event) = res {
                    // The receiver is gone only once watch has returned.
                    let _ = tx.send(event);
                }
            },
            NotifyConfig::default(),
        )
        .and_then(|mut w| w.watch(&watch_dir, RecursiveMode::Recursive).map(|()| w));
        let _watcher = match watcher {
            Ok(w) => w,
            Err(e) => {
                writeln!(io.stderr, "Failed to watch {}: {}", watch_dir.display(), e)?;
                return Ok(Status::err(2, format!("config watch failed: {}", e)));
            }
        };

        // Store previous state for change detection
        let mut previous_state = self.load_current_snapshot(&watch_dir)?;

        loop {
            // Check timeout
            if timeout_ms > 0 && start_time.elapsed().as_millis() as u64 >= timeout_ms {
                break;
            }

            // Check max events
            if max_events > 0 && events_emitted >= max_events {
                break;
            }

            // Calculate remaining timeout
            let remaining_timeout = if timeout_ms > 0 {
                let elapsed = start_time.elapsed().as_millis() as u64;
                if elapsed >= timeout_ms {
                    break;
                }
                Some(Duration::from_millis(timeout_ms - elapsed))
            } else {
                None
            };

            // Wait for events
            let event_received = match remaining_timeout {
                Some(timeout) => rx.recv_timeout(timeout).is_ok(),
                None => {
                    // Block indefinitely, but check every 500ms for graceful shutdown
                    rx.recv_timeout(Duration::from_millis(500)).is_ok()
                }
            };

            if event_received || remaining_timeout.is_none() {
                // Load current state and compare with previous
                let current_state = self.load_current_snapshot(&watch_dir)?;
                let changes = self.detect_changes(&previous_state, &current_state);

                for change in changes {
                    if self.key_matches_filter(&change.key, &key, &prefix) {
                        let event = WatchEvent {
                            op: change.op,
                            scope: scope.clone(),
                            key: change.key,
                            value: change.value,
                            version: version_counter,
                            ts: Utc::now().to_rfc3339(),
                            source: "config".to_string(),
                        };

                        match serde_json::to_string(&event) {
                            Ok(event_json) => {
                                writeln!(io.stdout, "{}", event_json)?;
                                events_emitted += 1;
                                version_counter += 1;

                                if max_events > 0 && events_emitted >= max_events {
                                    return Ok(Status::ok());
                                }
                            }
                            Err(e) => {
                                writeln!(io.stderr, "Failed to serialize event: {}", e)?;
                                // Continue on serialization errors
                            }
                        }
                    }
                }

                previous_state = current_state;
            }
        }

        Ok(Status::ok())
    }

    fn load_current_snapshot(
        &self,
        watch_dir: &Path,
    ) -> Result<HashMap<String, serde_json::Value>> {
        let mut snapshot = HashMap::new();

        if !watch_dir.exists() {
            return Ok(snapshot);
        }

        // Entries that cannot be read (removed mid-walk, no permission) are
        // skipped like invalid JSON files.
        for entry in WalkDir::new(watch_dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();

            if path.is_file() {
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    if file_name.ends_with(".json") {
                        // Extract key from path relative to watch directory
                        let Ok(relative_path) = path.strip_prefix(watch_dir) else {
                            continue;
                        };
                        let key = self.path_to_key(relative_path);

                        // Read and parse the JSON content
                        match fs::read_to_string(path) {
                            Ok(content) => {
                                match serde_json::from_str::<serde_json::Value>(&content) {
                                    Ok(value) => {
                                        snapshot.insert(key, value);
                                    }
                                    Err(_) => {
                                        // Skip invalid JSON files
                                        continue;
                                    }
                                }
                            }
                            Err(_) => {
                                // Skip unreadable files
                                continue;
                            }
                        }
                    }
                }
            }
        }

        Ok(snapshot)
    }

    fn path_to_key(&self, relative_path: &Path) -> String {
        let file_stem = relative_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        if let Some(parent) = relative_path.parent() {
            if parent.as_os_str().is_empty() {
                file_stem.to_string()
            } else {
                format!("{}/{}", parent.display(), file_stem)
            }
        } else {
            file_stem.to_string()
        }
    }

    fn detect_changes(
        &self,
        previous: &HashMap<String, serde_json::Value>,
        current: &HashMap<String, serde_json::Value>,
    ) -> Vec<ConfigChange> {
        let mut changes = Vec::new();

        // Check for new and modified keys
        for (key, current_value) in current {
            match previous.get(key) {
                None => {
                    // New key
                    changes.push(ConfigChange {
                        op: "set".to_string(),
                        key: key.clone(),
                        value: Some(current_value.clone()),
                    });
                }
                Some(previous_value) => {
                    // Check if value changed
                    if previous_value != current_value {
                        changes.push(ConfigChange {
                            op: "set".to_string(),
                            key: key.clone(),
                            value: Some(current_value.clone()),
                        });
                    }
                }
            }
        }

        // Check for deleted keys
        for key in previous.keys() {
            if !current.contains_key(key) {
                changes.push(ConfigChange {
                    op: "rm".to_string(),
                    key: key.clone(),
                    value: None,
                });
            }
        }

        changes
    }

    fn key_matches_filter(
        &self,
        key: &str,
        filter_key: &Option<String>,
        filter_prefix: &Option<String>,
    ) -> bool {
        if let Some(exact_key) = filter_key {
            key == exact_key
        } else if let Some(prefix) = filter_prefix {
            key.starts_with(prefix)
        } else {
            true // No filter, match all
        }
    }
}

impl ConfigHandle {
    /// True if the URL is an in-URL help request: `config://--help`,
    /// `config://-h`, `config://--help=<verb>`, or a `help`/`h` query key.
    /// Matching is exact, so keys such as `app/my-hosts` are not help.
    fn should_show_help(url: &Url) -> bool {
        Self::help_flag_token(url).is_some()
            || url.query_pairs().any(|(k, _)| k == "help" || k == "h")
    }

    /// The host or a path segment that is exactly a help flag, optionally
    /// with `=<verb>`.
    fn help_flag_token(url: &Url) -> Option<String> {
        let host = url.host_str().map(str::to_string);
        host.into_iter()
            .chain(url.path().split('/').map(str::to_string))
            .find(|t| help::is_help_flag(t.split('=').next().unwrap_or(t)))
    }

    /// The verb named by `--help=<verb>` or `?help=<verb>`, if any.
    fn extract_help_verb(url: &Url) -> Option<String> {
        if let Some((_, v)) = url
            .query_pairs()
            .find(|(k, v)| k == "help" && !v.is_empty())
        {
            return Some(v.to_string());
        }
        Self::help_flag_token(url)
            .and_then(|t| t.split_once('=').map(|(_, v)| v.to_string()))
            .filter(|v| !v.is_empty())
    }

    /// Writes the handle help, or verb help when `verb` names a documented verb.
    fn display_help(&self, verb: Option<&str>, io: &mut IoStreams) -> Result<Status> {
        let text = help::render_legacy("config", &CONFIG_HELP, self.verbs(), verb);
        write!(io.stdout, "{}", text).with_context(|| "Failed to write help text to stdout")?;
        Ok(Status::ok())
    }
}

impl Handle for ConfigHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["get", "set", "ls", "watch"]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&CONFIG_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check if this is a help request
        if help::HELP_ALIASES.contains(&verb) || Self::should_show_help(&self.original_url) {
            let verb_arg = args
                .get("verb")
                .cloned()
                .or_else(|| Self::extract_help_verb(&self.original_url));
            return self.display_help(verb_arg.as_deref(), io);
        }

        let Some(allowed) = verb_args(verb) else {
            bail!("unknown verb for config://: {}", verb);
        };
        if let Some(refusal) = check_args(verb, allowed, args) {
            return Ok(refusal);
        }
        if let Some(reason) = &self.invalid_target {
            return Ok(Status::err(1, reason.clone()));
        }

        match verb {
            "get" => self.verb_get(args, io),
            "set" => self.verb_set(args, io),
            "ls" => self.verb_ls(args, io),
            "watch" => self.verb_watch(args, io),
            _ => bail!("unknown verb for config://: {}", verb),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::TempDir;

    // Helper to create a test ConfigHandle with a temporary directory
    fn create_test_handle(prefix: &str) -> (ConfigHandle, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("resh").join("config");

        // Create a mock URL for testing (won't trigger help)
        let mock_url = Url::parse("config://test").unwrap();

        let handle = ConfigHandle {
            namespace: "test".to_string(),
            key: "".to_string(),
            file_path: base_path.join("test"),
            base_path,
            prefix: prefix.to_string(),
            original_url: mock_url,
            invalid_target: None,
        };

        (handle, temp_dir)
    }

    // Helper to create a config file
    fn create_config_file(base_path: &Path, namespace: &str, key: &str, content: &str) {
        let ns_path = base_path.join(namespace);
        fs::create_dir_all(&ns_path).unwrap();
        let file_path = ns_path.join(format!("{}.json", key));
        fs::write(file_path, content).unwrap();
    }

    #[test]
    fn help_detection_is_exact() {
        let help = |u: &str| ConfigHandle::should_show_help(&Url::parse(u).unwrap());
        assert!(help("config://--help"));
        assert!(help("config://-h"));
        assert!(help("config://--help=get"));
        assert!(help("config://app?help=get"));
        assert!(!help("config://app/my-hosts"));
        assert!(!help("config://my-httpd/url"));
        assert!(!help("config://pre-hotfix"));
        let verb = |u: &str| ConfigHandle::extract_help_verb(&Url::parse(u).unwrap());
        assert_eq!(verb("config://--help=watch").as_deref(), Some("watch"));
        assert_eq!(verb("config://app?help=get").as_deref(), Some("get"));
        assert_eq!(verb("config://--help"), None);
    }

    #[test]
    fn help_verb_renders_approved_help() {
        let (handle, _temp_dir) = create_test_handle("");
        let run = |verb: &str, args: Args| {
            let (mut i, mut o, mut e) = (
                Cursor::new(Vec::new()),
                Cursor::new(Vec::new()),
                Cursor::new(Vec::new()),
            );
            let mut io = IoStreams {
                stdin: &mut i,
                stdout: &mut o,
                stderr: &mut e,
            };
            handle.call(verb, &args, &mut io).unwrap();
            String::from_utf8(o.into_inner()).unwrap()
        };
        assert!(run("help", Args::new()).starts_with("Handle: config"));
        let mut args = Args::new();
        args.insert("verb".into(), "get".into());
        let out = run("help", args);
        assert!(out.contains("resh config://app/db/url.get"), "{out}");
    }

    #[test]
    fn test_ls_root_lists_all_namespaces() {
        let (handle, _temp_dir) = create_test_handle("");

        // Create some test config files
        create_config_file(&handle.base_path, "app", "config", r#"{"value": "test"}"#);
        create_config_file(&handle.base_path, "app", "feature_flag", r#"true"#);
        create_config_file(&handle.base_path, "db", "url", r#"{"url": "localhost"}"#);

        let args = std::collections::HashMap::new();
        let mut stdout = Cursor::new(Vec::new());
        let mut stderr = Cursor::new(Vec::new());
        let mut stdin = Cursor::new(Vec::new());

        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.verb_ls(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let response: LsResponse = serde_json::from_str(&output).unwrap();

        assert_eq!(response.prefix, "");
        assert_eq!(response.recursive, false);
        assert!(response.entries.len() >= 2);

        // Should contain app and db namespaces
        let namespace_names: Vec<String> = response
            .entries
            .iter()
            .filter(|e| e.kind == ConfigEntryKind::Branch)
            .map(|e| e.key.clone())
            .collect();
        assert!(namespace_names.contains(&"app".to_string()));
        assert!(namespace_names.contains(&"db".to_string()));
    }

    #[test]
    fn test_ls_immediate_children() {
        let (mut handle, _temp_dir) = create_test_handle("app");
        handle.prefix = "app".to_string();

        // Create test structure:
        // app/
        //   ├── env/
        //   │   ├── db/
        //   │   │   ├── url.json
        //   │   │   └── user.json
        //   │   └── cache.json
        //   └── feature_flag.json
        create_config_file(&handle.base_path, "app", "feature_flag", r#"true"#);

        // Create subdirectories
        let app_env_db_path = handle.base_path.join("app").join("env").join("db");
        fs::create_dir_all(&app_env_db_path).unwrap();
        create_config_file(
            &handle.base_path.join("app"),
            "env",
            "cache",
            r#"{"ttl": 300}"#,
        );
        fs::write(app_env_db_path.join("url.json"), r#"{"url": "localhost"}"#).unwrap();
        fs::write(app_env_db_path.join("user.json"), r#"{"user": "admin"}"#).unwrap();

        let args = std::collections::HashMap::new();
        let mut stdout = Cursor::new(Vec::new());
        let mut stderr = Cursor::new(Vec::new());
        let mut stdin = Cursor::new(Vec::new());

        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.verb_ls(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let response: LsResponse = serde_json::from_str(&output).unwrap();

        assert_eq!(response.prefix, "app");
        assert_eq!(response.recursive, false);

        // Should contain feature_flag (leaf) and env (branch)
        let has_feature_flag = response
            .entries
            .iter()
            .any(|e| e.key == "feature_flag" && e.kind == ConfigEntryKind::Leaf);
        let has_env_branch = response
            .entries
            .iter()
            .any(|e| e.key == "env" && e.kind == ConfigEntryKind::Branch);

        assert!(has_feature_flag);
        assert!(has_env_branch);
    }

    #[test]
    fn test_ls_recursive_includes_descendants() {
        let (mut handle, _temp_dir) = create_test_handle("app");
        handle.prefix = "app".to_string();

        // Create test structure
        create_config_file(&handle.base_path, "app", "feature_flag", r#"true"#);

        let app_env_db_path = handle.base_path.join("app").join("env").join("db");
        fs::create_dir_all(&app_env_db_path).unwrap();
        fs::write(app_env_db_path.join("url.json"), r#"{"url": "localhost"}"#).unwrap();

        let mut args = std::collections::HashMap::new();
        args.insert("recursive".to_string(), "true".to_string());

        let mut stdout = Cursor::new(Vec::new());
        let mut stderr = Cursor::new(Vec::new());
        let mut stdin = Cursor::new(Vec::new());

        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.verb_ls(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let response: LsResponse = serde_json::from_str(&output).unwrap();

        assert_eq!(response.recursive, true);

        // Should contain nested entries like app/env/db/url
        let has_nested_url = response
            .entries
            .iter()
            .any(|e| e.full_key.ends_with("env/db/url") && e.kind == ConfigEntryKind::Leaf);
        assert!(has_nested_url);
    }

    #[test]
    fn test_ls_pattern_filters_keys() {
        let (mut handle, _temp_dir) = create_test_handle("app");
        handle.prefix = "app".to_string();

        // Create test files
        create_config_file(
            &handle.base_path,
            "app",
            "db_url",
            r#"{"url": "localhost"}"#,
        );
        create_config_file(&handle.base_path, "app", "db_user", r#"{"user": "admin"}"#);
        create_config_file(&handle.base_path, "app", "cache_ttl", r#"300"#);

        let mut args = std::collections::HashMap::new();
        args.insert("pattern".to_string(), "db*".to_string());

        let mut stdout = Cursor::new(Vec::new());
        let mut stderr = Cursor::new(Vec::new());
        let mut stdin = Cursor::new(Vec::new());

        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.verb_ls(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let response: LsResponse = serde_json::from_str(&output).unwrap();

        assert_eq!(response.pattern, Some("db*".to_string()));

        // Should only contain db_url and db_user, not cache_ttl
        let keys: Vec<String> = response.entries.iter().map(|e| e.key.clone()).collect();
        assert!(keys.contains(&"db_url".to_string()));
        assert!(keys.contains(&"db_user".to_string()));
        assert!(!keys.contains(&"cache_ttl".to_string()));
    }

    #[test]
    fn test_ls_limit_and_offset() {
        let (mut handle, _temp_dir) = create_test_handle("app");
        handle.prefix = "app".to_string();

        // Create multiple test files
        for i in 1..=5 {
            create_config_file(
                &handle.base_path,
                "app",
                &format!("key{}", i),
                &format!(r#"{{"value": {}}}"#, i),
            );
        }

        let mut args = std::collections::HashMap::new();
        args.insert("limit".to_string(), "2".to_string());
        args.insert("offset".to_string(), "1".to_string());

        let mut stdout = Cursor::new(Vec::new());
        let mut stderr = Cursor::new(Vec::new());
        let mut stdin = Cursor::new(Vec::new());

        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.verb_ls(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let response: LsResponse = serde_json::from_str(&output).unwrap();

        assert_eq!(response.limit, Some(2));
        assert_eq!(response.offset, 1);
        assert_eq!(response.entries.len(), 2);
    }

    #[test]
    fn test_ls_nonexistent_prefix_returns_empty() {
        let (mut handle, _temp_dir) = create_test_handle("does/not/exist");
        handle.prefix = "does/not/exist".to_string();

        let args = std::collections::HashMap::new();
        let mut stdout = Cursor::new(Vec::new());
        let mut stderr = Cursor::new(Vec::new());
        let mut stdin = Cursor::new(Vec::new());

        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.verb_ls(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let response: LsResponse = serde_json::from_str(&output).unwrap();

        assert_eq!(response.entries.len(), 0);
    }

    #[test]
    fn test_ls_invalid_limit() {
        let (handle, _temp_dir) = create_test_handle("");

        let mut args = std::collections::HashMap::new();
        args.insert("limit".to_string(), "abc".to_string());

        let mut stdout = Cursor::new(Vec::new());
        let mut stderr = Cursor::new(Vec::new());
        let mut stdin = Cursor::new(Vec::new());

        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.verb_ls(&args, &mut io).unwrap();
        assert!(!result.ok);
        assert_eq!(result.code, Some(2));
        assert_eq!(result.reason, Some("invalid limit value".to_string()));
    }

    #[test]
    fn test_ls_invalid_offset() {
        let (handle, _temp_dir) = create_test_handle("");

        let mut args = std::collections::HashMap::new();
        args.insert("offset".to_string(), "xyz".to_string());

        let mut stdout = Cursor::new(Vec::new());
        let mut stderr = Cursor::new(Vec::new());
        let mut stdin = Cursor::new(Vec::new());

        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.verb_ls(&args, &mut io).unwrap();
        assert!(!result.ok);
        assert_eq!(result.code, Some(2));
        assert_eq!(result.reason, Some("invalid offset value".to_string()));
    }

    #[test]
    fn test_ls_invalid_pattern() {
        let (handle, _temp_dir) = create_test_handle("");

        let mut args = std::collections::HashMap::new();
        args.insert("pattern".to_string(), "[".to_string()); // Invalid glob

        let mut stdout = Cursor::new(Vec::new());
        let mut stderr = Cursor::new(Vec::new());
        let mut stdin = Cursor::new(Vec::new());

        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.verb_ls(&args, &mut io).unwrap();
        assert!(!result.ok);
        assert_eq!(result.code, Some(2));
        assert_eq!(result.reason, Some("invalid pattern".to_string()));
    }

    // --- dispatch tests: every verb through Handle::call -------------------

    fn at(dir: &TempDir, url: &str) -> ConfigHandle {
        ConfigHandle::with_config_dir(&Url::parse(url).unwrap(), dir.path())
    }

    fn call(h: &ConfigHandle, verb: &str, kv: &[(&str, &str)]) -> (Status, String, String) {
        let args: Args = kv
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let (mut i, mut o, mut e) = (
            Cursor::new(Vec::new()),
            Cursor::new(Vec::new()),
            Cursor::new(Vec::new()),
        );
        let mut io = IoStreams {
            stdin: &mut i,
            stdout: &mut o,
            stderr: &mut e,
        };
        let status = h.call(verb, &args, &mut io).unwrap();
        (
            status,
            String::from_utf8(o.into_inner()).unwrap(),
            String::from_utf8(e.into_inner()).unwrap(),
        )
    }

    fn base(dir: &TempDir) -> PathBuf {
        dir.path().join("resh").join("config")
    }

    fn assert_err(status: &Status, code: i32, reason_part: &str) {
        assert!(!status.ok, "expected failure, got {status:?}");
        assert_eq!(status.code, Some(code), "{status:?}");
        let reason = status.reason.clone().unwrap_or_default();
        assert!(
            reason.contains(reason_part),
            "{reason:?} lacks {reason_part:?}"
        );
    }

    #[test]
    fn set_then_get_round_trips_json_and_strings() {
        let dir = TempDir::new().unwrap();
        let h = at(&dir, "config://app/db/url");
        let (s, out, _) = call(&h, "set", &[("value", "postgres://db:5432/app")]);
        assert!(s.ok, "{s:?}");
        assert_eq!(out, "", "set prints nothing");
        assert_eq!(call(&h, "get", &[]).1, r#""postgres://db:5432/app""#);
        assert!(base(&dir).join("app/db/url.json").is_file());

        let n = at(&dir, "config://app/timeout");
        assert!(call(&n, "set", &[("value", "30")]).0.ok);
        assert_eq!(call(&n, "get", &[]).1, "30");
        assert!(call(&n, "set", &[("value", "\"30\"")]).0.ok);
        assert_eq!(call(&n, "get", &[]).1, r#""30""#);
    }

    #[test]
    fn single_segment_uses_default_namespace() {
        let dir = TempDir::new().unwrap();
        let h = at(&dir, "config://theme");
        assert!(call(&h, "set", &[("value", "dark")]).0.ok);
        assert!(base(&dir).join("default/theme.json").is_file());
        assert_eq!(call(&h, "get", &[]).1, r#""dark""#);
    }

    #[test]
    fn set_raw_requires_valid_json() {
        let dir = TempDir::new().unwrap();
        let h = at(&dir, "config://app/flags");
        let (s, _, _) = call(&h, "set", &[("value", r#"{"beta":true}"#), ("raw", "true")]);
        assert!(s.ok);
        assert_eq!(call(&h, "get", &[]).1, r#"{"beta":true}"#);
        let (s, _, _) = call(&h, "set", &[("value", "not json"), ("raw", "true")]);
        assert_err(&s, 2, "invalid json");
        // The failed set left the old value in place.
        assert_eq!(call(&h, "get", &[]).1, r#"{"beta":true}"#);
        // raw=false stores non-JSON text as a string.
        assert!(
            call(&h, "set", &[("value", "plain"), ("raw", "false")])
                .0
                .ok
        );
        assert_eq!(call(&h, "get", &[]).1, r#""plain""#);
    }

    #[test]
    fn set_rejects_unreadable_raw_without_writing() {
        let dir = TempDir::new().unwrap();
        let h = at(&dir, "config://app/k");
        let (s, _, _) = call(&h, "set", &[("value", "1"), ("raw", "ture")]);
        assert_err(&s, 2, "invalid value for raw");
        assert!(!base(&dir).exists(), "nothing written");
    }

    #[test]
    fn set_errors() {
        let dir = TempDir::new().unwrap();
        let (s, _, _) = call(&at(&dir, "config://app/k"), "set", &[]);
        assert_err(&s, 1, "missing arg: value");
        let (s, _, _) = call(&at(&dir, "config://"), "set", &[("value", "1")]);
        assert_err(&s, 1, "Empty key");
        assert!(!base(&dir).exists(), "nothing written");
    }

    #[test]
    fn set_io_error_is_exit_3_and_leaves_no_temp_file() {
        let dir = TempDir::new().unwrap();
        // `app/blocker` is a file, so `app/blocker/k.json` cannot be created.
        fs::create_dir_all(base(&dir).join("app")).unwrap();
        fs::write(base(&dir).join("app/blocker"), "x").unwrap();
        let (s, _, _) = call(
            &at(&dir, "config://app/blocker/k"),
            "set",
            &[("value", "1")],
        );
        assert_err(&s, 3, "I/O error");
        // The key is a directory: the temp file is written, the rename fails.
        fs::create_dir_all(base(&dir).join("app/dir.json")).unwrap();
        let (s, _, _) = call(&at(&dir, "config://app/dir"), "set", &[("value", "1")]);
        assert_err(&s, 3, "I/O error");
        let leftovers: Vec<_> = fs::read_dir(base(&dir).join("app"))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn get_errors() {
        let dir = TempDir::new().unwrap();
        let (s, out, _) = call(&at(&dir, "config://nope/k"), "get", &[]);
        assert_err(&s, 1, "not found");
        assert_eq!(out, "");
        assert!(!base(&dir).exists(), "get must not create directories");

        let (s, _, _) = call(&at(&dir, "config://"), "get", &[]);
        assert_err(&s, 1, "Empty key");

        fs::create_dir_all(base(&dir).join("app")).unwrap();
        fs::write(base(&dir).join("app/bad.json"), "{not json").unwrap();
        let (s, out, _) = call(&at(&dir, "config://app/bad"), "get", &[]);
        assert_err(&s, 2, "invalid json");
        assert_eq!(out, "");

        // A directory where the value file should be: a read error.
        fs::create_dir_all(base(&dir).join("app/isdir.json")).unwrap();
        let (s, _, _) = call(&at(&dir, "config://app/isdir"), "get", &[]);
        assert_err(&s, 3, "I/O error");
    }

    #[test]
    fn dot_segments_are_refused_without_side_effects() {
        let dir = TempDir::new().unwrap();
        for url in ["config://../x", "config://./x", "config://../evil/x"] {
            let h = at(&dir, url);
            for (verb, args) in [
                ("set", vec![("value", "1")]),
                ("get", vec![]),
                ("ls", vec![]),
                ("watch", vec![("timeout_ms", "1")]),
            ] {
                let (s, _, _) = call(&h, verb, &args);
                assert_err(&s, 1, "'.' and '..' segments are not allowed");
            }
        }
        assert!(!dir.path().join("resh").exists(), "nothing created");
    }

    #[test]
    fn unknown_arguments_and_timeout_ms_are_refused() {
        let dir = TempDir::new().unwrap();
        let h = at(&dir, "config://app/k");
        for verb in ["get", "set", "ls"] {
            let (s, _, _) = call(&h, verb, &[("value", "1"), ("timeout_ms", "5")]);
            assert_err(&s, 2, "does not take timeout_ms");
        }
        let (s, _, _) = call(&h, "set", &[("value", "1"), ("vaule", "2")]);
        assert_err(&s, 2, "unknown argument for config set: vaule");
        let (s, _, _) = call(&h, "get", &[("raw", "true")]);
        assert_err(&s, 2, "unknown argument for config get: raw");
        let (s, _, _) = call(&h, "watch", &[("recursive", "true")]);
        assert_err(&s, 2, "unknown argument for config watch: recursive");
        assert!(!base(&dir).exists(), "nothing written");
        // dry_run=false is a no-op (the dispatcher refuses dry_run=true).
        assert!(
            call(&h, "set", &[("value", "1"), ("dry_run", "false")])
                .0
                .ok
        );
    }

    #[test]
    fn unknown_verb_is_an_error() {
        let dir = TempDir::new().unwrap();
        let args = Args::new();
        let (mut i, mut o, mut e) = (
            Cursor::new(Vec::new()),
            Cursor::new(Vec::new()),
            Cursor::new(Vec::new()),
        );
        let mut io = IoStreams {
            stdin: &mut i,
            stdout: &mut o,
            stderr: &mut e,
        };
        let err = at(&dir, "config://app/k")
            .call("delete", &args, &mut io)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("unknown verb for config://: delete")
        );
    }

    fn ls_json(h: &ConfigHandle, kv: &[(&str, &str)]) -> serde_json::Value {
        let (s, out, _) = call(h, "ls", kv);
        assert!(s.ok, "{s:?}");
        serde_json::from_str(&out).unwrap()
    }

    fn full_keys(v: &serde_json::Value) -> Vec<String> {
        v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["full_key"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn ls_lists_namespaces_children_and_descendants() {
        let dir = TempDir::new().unwrap();
        for (url, v) in [
            ("config://app/theme", "dark"),
            ("config://app/db/url", "pg"),
            ("config://app/db/user", "admin"),
            ("config://other/x", "1"),
        ] {
            assert!(call(&at(&dir, url), "set", &[("value", v)]).0.ok);
        }
        let root = ls_json(&at(&dir, "config://"), &[]);
        assert_eq!(full_keys(&root), ["app", "other"]);

        let app = ls_json(&at(&dir, "config://app"), &[]);
        assert_eq!(full_keys(&app), ["app/db", "app/theme"]);
        assert_eq!(app["entries"][0]["kind"], "branch");
        assert_eq!(app["entries"][1]["kind"], "leaf");
        assert_eq!(app["entries"][1]["meta"]["size"], 6);

        // Recursive: every descendant, and not the prefix directory itself.
        let rec = ls_json(&at(&dir, "config://app"), &[("recursive", "true")]);
        assert_eq!(
            full_keys(&rec),
            ["app/db", "app/db/url", "app/db/user", "app/theme"]
        );
        assert_eq!(rec["recursive"], true);

        let sub = ls_json(&at(&dir, "config://app/db"), &[]);
        assert_eq!(full_keys(&sub), ["app/db/url", "app/db/user"]);

        let pat = ls_json(
            &at(&dir, "config://app"),
            &[("recursive", "true"), ("pattern", "u*")],
        );
        assert_eq!(full_keys(&pat), ["app/db/url", "app/db/user"]);

        let page = ls_json(
            &at(&dir, "config://app"),
            &[("recursive", "true"), ("limit", "2"), ("offset", "1")],
        );
        assert_eq!(full_keys(&page), ["app/db/url", "app/db/user"]);
        assert_eq!(page["limit"], 2);
        assert_eq!(page["offset"], 1);

        let none = ls_json(&at(&dir, "config://missing"), &[]);
        assert_eq!(full_keys(&none), Vec::<String>::new());
    }

    #[test]
    fn ls_prefix_is_sanitized_like_stored_keys() {
        let dir = TempDir::new().unwrap();
        assert!(
            call(&at(&dir, "config://app/a b/k"), "set", &[("value", "1")])
                .0
                .ok
        );
        let v = ls_json(&at(&dir, "config://app/a b"), &[]);
        assert_eq!(full_keys(&v), ["app/a_20b/k"]);
    }

    #[test]
    fn ls_argument_errors() {
        let dir = TempDir::new().unwrap();
        let h = at(&dir, "config://app");
        assert_err(&call(&h, "ls", &[("recursive", "maybe")]).0, 2, "recursive");
        assert_err(
            &call(&h, "ls", &[("limit", "-1")]).0,
            2,
            "invalid limit value",
        );
        assert_err(
            &call(&h, "ls", &[("offset", "x")]).0,
            2,
            "invalid offset value",
        );
        assert_err(&call(&h, "ls", &[("pattern", "[")]).0, 2, "invalid pattern");
    }

    fn watch_lines(out: &str) -> Vec<serde_json::Value> {
        out.lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn watch_argument_errors() {
        let dir = TempDir::new().unwrap();
        let h = at(&dir, "config://app/db");
        let (s, _, err) = call(&h, "watch", &[("key", "a"), ("prefix", "b")]);
        assert_err(&s, 1, "key and prefix cannot be used together");
        assert!(err.contains("key and prefix"));
        assert_err(
            &call(&h, "watch", &[("timeout_ms", "abc")]).0,
            2,
            "invalid timeout_ms value",
        );
        assert_err(
            &call(&h, "watch", &[("timeout_ms", "-5")]).0,
            2,
            "invalid timeout_ms value",
        );
        assert_err(
            &call(&h, "watch", &[("max_events", "1.5")]).0,
            2,
            "invalid max_events value",
        );
        assert_err(
            &call(&h, "watch", &[("initial", "sure")]).0,
            2,
            "invalid value for initial",
        );
        assert!(!base(&dir).exists(), "invalid input has no side effect");
    }

    #[test]
    fn watch_cannot_create_its_directory() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("resh")).unwrap();
        fs::write(base(&dir), "not a directory").unwrap();
        let (s, _, _) = call(
            &at(&dir, "config://app/db"),
            "watch",
            &[("timeout_ms", "10")],
        );
        assert_err(&s, 2, "config watch failed");
    }

    #[test]
    fn watch_initial_snapshot_with_filters_and_max_events() {
        let dir = TempDir::new().unwrap();
        for (url, v) in [
            ("config://app/db/url", "pg"),
            ("config://app/db/user", "admin"),
            ("config://app/theme", "dark"),
        ] {
            assert!(call(&at(&dir, url), "set", &[("value", v)]).0.ok);
        }
        let h = at(&dir, "config://app/db");
        let (s, out, _) = call(
            &h,
            "watch",
            &[("initial", "true"), ("prefix", "db/"), ("timeout_ms", "50")],
        );
        assert!(s.ok);
        let mut lines = watch_lines(&out);
        lines.sort_by_key(|l| l["key"].as_str().unwrap().to_string());
        assert_eq!(lines.len(), 2, "{out}");
        assert_eq!(lines[0]["op"], "snapshot");
        assert_eq!(lines[0]["key"], "db/url");
        assert_eq!(lines[0]["value"], "pg");
        assert_eq!(lines[0]["scope"], "app/db");
        assert_eq!(lines[0]["source"], "config");

        // max_events stops after that many lines, without waiting.
        let started = Instant::now();
        let (s, out, _) = call(
            &h,
            "watch",
            &[("initial", "true"), ("key", "theme"), ("max_events", "1")],
        );
        assert!(s.ok);
        assert_eq!(watch_lines(&out).len(), 1);
        assert_eq!(watch_lines(&out)[0]["key"], "theme");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn watch_timeout_ends_quietly_without_changes() {
        let dir = TempDir::new().unwrap();
        let started = Instant::now();
        let (s, out, _) = call(
            &at(&dir, "config://app/x"),
            "watch",
            &[("timeout_ms", "200")],
        );
        assert!(s.ok);
        assert_eq!(out, "");
        let took = started.elapsed();
        assert!(took >= Duration::from_millis(200), "{took:?}");
        assert!(took < Duration::from_secs(5), "{took:?}");
    }

    /// Runs `watch` on a thread while this thread keeps changing values,
    /// until watch has printed `max_events` lines (bounded by timeout_ms).
    fn watch_while(
        dir: &TempDir,
        url: &str,
        kv: &[(&str, &str)],
        mut change: impl FnMut(u32),
    ) -> Vec<serde_json::Value> {
        let h = at(dir, url);
        let kv: Vec<(String, String)> = kv
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let worker = std::thread::spawn(move || {
            let kv: Vec<(&str, &str)> = kv.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            call(&h, "watch", &kv)
        });
        let mut round = 0;
        while !worker.is_finished() && round < 100 {
            std::thread::sleep(Duration::from_millis(100));
            change(round);
            round += 1;
        }
        let (s, out, _) = worker.join().unwrap();
        assert!(s.ok, "{s:?}");
        watch_lines(&out)
    }

    #[test]
    fn watch_reports_set_events_for_matching_keys() {
        let dir = TempDir::new().unwrap();
        let lines = watch_while(
            &dir,
            "config://app/db",
            &[
                ("key", "db/url"),
                ("max_events", "2"),
                ("timeout_ms", "10000"),
            ],
            |n| {
                // An unrelated key is changed every round and never reported.
                let other = at(&dir, "config://app/theme");
                call(&other, "set", &[("value", &n.to_string())]);
                let url = at(&dir, "config://app/db/url");
                call(&url, "set", &[("value", &format!("pg{n}"))]);
            },
        );
        assert_eq!(lines.len(), 2);
        for (i, l) in lines.iter().enumerate() {
            assert_eq!(l["op"], "set");
            assert_eq!(l["key"], "db/url");
            assert_eq!(l["version"], i as u64 + 1);
            assert!(l["value"].as_str().unwrap().starts_with("pg"));
        }
    }

    #[test]
    fn watch_reports_removed_keys() {
        let dir = TempDir::new().unwrap();
        let file = base(&dir).join("app/gone.json");
        let lines = watch_while(
            &dir,
            "config://app/x",
            &[
                ("prefix", "gone"),
                ("max_events", "2"),
                ("timeout_ms", "10000"),
            ],
            |_| {
                if file.exists() {
                    fs::remove_file(&file).unwrap();
                } else {
                    fs::create_dir_all(file.parent().unwrap()).unwrap();
                    fs::write(&file, "true").unwrap();
                }
            },
        );
        // The file alternates between present and absent, so the two events
        // are one set and one rm (in either order).
        let mut ops: Vec<&str> = lines.iter().map(|l| l["op"].as_str().unwrap()).collect();
        ops.sort();
        assert_eq!(ops, ["rm", "set"]);
        for l in &lines {
            assert_eq!(l["key"], "gone");
            assert_eq!(l.get("value").is_some(), l["op"] == "set");
        }
    }

    #[test]
    fn watch_default_namespace_reports_namespaced_keys() {
        let dir = TempDir::new().unwrap();
        let lines = watch_while(
            &dir,
            "config://app",
            &[
                ("prefix", "app/"),
                ("max_events", "1"),
                ("timeout_ms", "10000"),
            ],
            |n| {
                call(
                    &at(&dir, "config://app/k"),
                    "set",
                    &[("value", &n.to_string())],
                );
            },
        );
        assert_eq!(lines[0]["key"], "app/k");
        assert_eq!(lines[0]["scope"], "app");
    }

    #[test]
    fn verb_args_match_help_usage() {
        for verb in CONFIG_HELP.verbs {
            let usage = verb.detail.as_ref().unwrap().usage;
            let mut in_usage: Vec<&str> = usage
                .split(|c: char| c == '[' || c.is_whitespace())
                .filter_map(|w| w.split_once('=').map(|(k, _)| k))
                .collect();
            in_usage.sort();
            let mut parsed = verb_args(verb.name).unwrap().to_vec();
            parsed.sort();
            assert_eq!(
                in_usage, parsed,
                "usage of {} disagrees with its arguments",
                verb.name
            );
        }
    }
}
