use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use globset::{Glob, GlobMatcher};
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use notify::{Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use url::Url;
use walkdir::WalkDir;

use crate::core::{
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

pub struct ConfigHandle {
    namespace: String,
    key: String,
    file_path: PathBuf,
    base_path: PathBuf,
    prefix: String,
}

impl ConfigHandle {
    pub fn from_url(u: &Url) -> Result<Self> {
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

        // For individual key operations, reject empty keys
        if key.is_empty() && !prefix.is_empty() {
            // This might be a root or namespace-level operation (for ls)
        }

        // Sanitize namespace and key to only allow [A-Za-z0-9._-/]
        let sanitized_namespace = Self::sanitize_name(&namespace);
        let sanitized_key = if key.is_empty() { String::new() } else { Self::sanitize_path(&key) };

        // Get base config directory using XDG
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string())).join(".config"));
        
        let base_path = config_dir.join("resh").join("config");
        let file_path = if sanitized_key.is_empty() {
            // For ls operations on namespaces/directories
            base_path.join(&sanitized_namespace)
        } else {
            base_path.join(&sanitized_namespace).join(format!("{}.json", sanitized_key))
        };

        Ok(Self {
            namespace: sanitized_namespace,
            key: sanitized_key,
            file_path,
            base_path,
            prefix,
        })
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
            return Ok(Status::err(1, "Empty key not allowed for get operation".to_string()));
        }

        // Ensure base config directory exists
        self.ensure_base_config_dir()?;

        // Check if file exists
        if !self.file_path.exists() {
            return Ok(Status::err(1, "not found".to_string()));
        }

        // Read the file contents
        let content = match fs::read_to_string(&self.file_path) {
            Ok(content) => content,
            Err(e) => {
                return Ok(Status::err(3, format!("I/O error: {}", e)));
            }
        };

        // Validate that it's valid JSON
        match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(_) => {
                // Write the JSON directly to stdout
                write!(io.stdout, "{}", content)
                    .with_context(|| "Failed to write to stdout")?;
                Ok(Status::ok())
            }
            Err(_) => {
                Ok(Status::err(2, "invalid json".to_string()))
            }
        }
    }

    fn verb_set(&self, args: &Args, _io: &mut IoStreams) -> Result<Status> {
        // Reject set on empty keys
        if self.key.is_empty() {
            return Ok(Status::err(1, "Empty key not allowed for set operation".to_string()));
        }

        // Get the value argument
        let value = match args.get("value") {
            Some(v) => v,
            None => {
                return Ok(Status::err(1, "missing arg: value".to_string()));
            }
        };

        // Determine if raw mode is enabled
        let raw_mode = args.get("raw").map(|v| v == "true").unwrap_or(false);

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
        self.ensure_base_config_dir()?;

        // Perform atomic write using temporary file
        let temp_path = self.file_path.with_extension(format!("tmp-{}", std::process::id()));
        
        // Write to temporary file
        let json_string = serde_json::to_string(&json_value)
            .with_context(|| "Failed to serialize JSON")?;
        
        {
            let mut temp_file = File::create(&temp_path)
                .with_context(|| format!("Failed to create temp file: {:?}", temp_path))?;
            
            temp_file.write_all(json_string.as_bytes())
                .with_context(|| "Failed to write to temp file")?;
            
            temp_file.sync_all()
                .with_context(|| "Failed to sync temp file")?;
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
        let recursive = args.get("recursive").map(|v| v == "true").unwrap_or(false);
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
        let entries = self.list_config_entries(recursive, glob_matcher.as_ref())?;

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
                write!(io.stdout, "{}", json)
                    .with_context(|| "Failed to write JSON to stdout")?;
                Ok(Status::ok())
            }
            Err(e) => {
                write!(io.stderr, "Failed to serialize JSON: {}", e)
                    .with_context(|| "Failed to write error to stderr")?;
                Ok(Status::err(3, "JSON serialization failed".to_string()))
            }
        }
    }

    fn list_config_entries(&self, recursive: bool, glob_matcher: Option<&GlobMatcher>) -> Result<Vec<ConfigEntry>> {
        let mut entries = Vec::new();
        let search_base = if self.prefix.is_empty() {
            self.base_path.clone()
        } else if self.prefix.contains('/') {
            // Multi-part prefix like "app/env"
            let parts: Vec<&str> = self.prefix.split('/').collect();
            let namespace = parts[0];
            let sub_path = parts[1..].join("/");
            self.base_path.join(namespace).join(sub_path)
        } else {
            // Single namespace
            self.base_path.join(&self.prefix)
        };

        if !search_base.exists() {
            return Ok(entries); // Return empty list if path doesn't exist
        }

        // Collect all entries first
        if recursive {
            for entry in WalkDir::new(&search_base).into_iter().filter_map(|e| e.ok()) {
                if let Some(config_entry) = self.path_to_config_entry(&entry.path(), &search_base, recursive)? {
                    if self.matches_pattern(&config_entry, glob_matcher) {
                        entries.push(config_entry);
                    }
                }
            }
        } else {
            if let Ok(dir_entries) = fs::read_dir(&search_base) {
                for entry in dir_entries.filter_map(|e| e.ok()) {
                    if let Some(config_entry) = self.path_to_config_entry(&entry.path(), &search_base, recursive)? {
                        if self.matches_pattern(&config_entry, glob_matcher) {
                            entries.push(config_entry);
                        }
                    }
                }
            }
        }

        Ok(entries)
    }

    fn path_to_config_entry(&self, path: &Path, search_base: &Path, recursive: bool) -> Result<Option<ConfigEntry>> {
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
                    let updated_at = metadata.modified().ok()
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
                .any(|e| e.path().is_file() && 
                    e.file_name().to_string_lossy().ends_with(".json"));

            return Ok(Some(ConfigEntry {
                key: dir_name.to_string(),
                full_key,
                kind: ConfigEntryKind::Branch,
                has_value,
                meta: ConfigMeta { size: None, updated_at: None },
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
        
        // Parse timeout_ms with default 0 (no timeout)
        let timeout_ms = args.get("timeout_ms")
            .map(|s| s.parse::<u64>().unwrap_or_else(|e| {
                let _ = writeln!(io.stderr, "Invalid timeout_ms, using 0: {}", e);
                0
            }))
            .unwrap_or(0);
            
        // Parse max_events with default 0 (no limit)
        let max_events = args.get("max_events")
            .map(|s| s.parse::<u64>().unwrap_or_else(|e| {
                let _ = writeln!(io.stderr, "Invalid max_events, using 0: {}", e);
                0
            }))
            .unwrap_or(0);
            
        // Parse initial with default false
        let initial = args.get("initial")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);

        self.watch_impl(key, prefix, timeout_ms, max_events, initial, io)
    }
    
    fn watch_impl(
        &self, 
        key: Option<String>, 
        prefix: Option<String>, 
        timeout_ms: u64, 
        max_events: u64, 
        initial: bool, 
        io: &mut IoStreams
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
        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                if let Ok(event) = res {
                    let _ = tx.send(event);
                }
            }, 
            NotifyConfig::default()
        ).map_err(|e| anyhow::anyhow!("Failed to create watcher: {}", e))?;
        
        watcher.watch(&watch_dir, RecursiveMode::Recursive)
            .map_err(|e| anyhow::anyhow!("Failed to start watching: {}", e))?;

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
    
    fn load_current_snapshot(&self, watch_dir: &Path) -> Result<HashMap<String, serde_json::Value>> {
        let mut snapshot = HashMap::new();
        
        if !watch_dir.exists() {
            return Ok(snapshot);
        }

        for entry in WalkDir::new(watch_dir) {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() {
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    if file_name.ends_with(".json") {
                        // Extract key from path relative to watch directory
                        let relative_path = path.strip_prefix(watch_dir)?;
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
        let file_stem = relative_path.file_stem()
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
    
    fn detect_changes(&self, previous: &HashMap<String, serde_json::Value>, current: &HashMap<String, serde_json::Value>) -> Vec<ConfigChange> {
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
    
    fn key_matches_filter(&self, key: &str, filter_key: &Option<String>, filter_prefix: &Option<String>) -> bool {
        if let Some(exact_key) = filter_key {
            key == exact_key
        } else if let Some(prefix) = filter_prefix {
            key.starts_with(prefix)
        } else {
            true // No filter, match all
        }
    }
}

impl Handle for ConfigHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["get", "set", "ls", "watch"]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
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
        
        let handle = ConfigHandle {
            namespace: "test".to_string(),
            key: "".to_string(),
            file_path: base_path.join("test"),
            base_path,
            prefix: prefix.to_string(),
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
        let namespace_names: Vec<String> = response.entries.iter()
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
        create_config_file(&handle.base_path.join("app"), "env", "cache", r#"{"ttl": 300}"#);
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
        let has_feature_flag = response.entries.iter()
            .any(|e| e.key == "feature_flag" && e.kind == ConfigEntryKind::Leaf);
        let has_env_branch = response.entries.iter()
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
        let has_nested_url = response.entries.iter()
            .any(|e| e.full_key.ends_with("env/db/url") && e.kind == ConfigEntryKind::Leaf);
        assert!(has_nested_url);
    }

    #[test]
    fn test_ls_pattern_filters_keys() {
        let (mut handle, _temp_dir) = create_test_handle("app");
        handle.prefix = "app".to_string();
        
        // Create test files
        create_config_file(&handle.base_path, "app", "db_url", r#"{"url": "localhost"}"#);
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
            create_config_file(&handle.base_path, "app", &format!("key{}", i), &format!(r#"{{"value": {}}}"#, i));
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
}