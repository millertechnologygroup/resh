use anyhow::{Context, Result, bail};
use chrono;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;
use uuid::Uuid;

use crate::core::{
    help::{self, HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::Status,
};

// ===========================================================================
// Hook System
// ===========================================================================

/// Hook trait for integrating with other handle types
pub trait EventHook: Send + Sync {
    /// Called when an event is emitted
    fn on_emit(&self, event: &EventEnvelope, response: &EventEmitResponse) -> Result<()>;

    /// Called when events are subscribed/consumed
    fn on_subscribe(
        &self,
        request: &EventSubscribeOptions,
        response: &EventSubscribeResponse,
    ) -> Result<()>;

    /// Return the hook name for identification
    fn name(&self) -> &str;
}

/// Hook manager to handle hook registration and execution
#[derive(Default)]
pub struct EventHookManager {
    hooks: Arc<Mutex<HashMap<String, Arc<dyn EventHook>>>>,
}

impl EventHookManager {
    pub fn new() -> Self {
        Self {
            hooks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a new hook
    pub fn register_hook(&self, hook: Arc<dyn EventHook>) {
        let mut hooks = self.hooks.lock().unwrap();
        hooks.insert(hook.name().to_string(), hook);
    }

    /// Remove a hook by name
    pub fn remove_hook(&self, name: &str) {
        let mut hooks = self.hooks.lock().unwrap();
        hooks.remove(name);
    }

    /// Execute emit hooks
    pub fn execute_emit_hooks(&self, event: &EventEnvelope, response: &EventEmitResponse) {
        let hooks = self.hooks.lock().unwrap();
        for (name, hook) in hooks.iter() {
            if let Err(e) = hook.on_emit(event, response) {
                eprintln!("Warning: Hook '{}' failed on emit: {}", name, e);
            }
        }
    }

    /// Execute subscribe hooks
    pub fn execute_subscribe_hooks(
        &self,
        request: &EventSubscribeOptions,
        response: &EventSubscribeResponse,
    ) {
        let hooks = self.hooks.lock().unwrap();
        for (name, hook) in hooks.iter() {
            if let Err(e) = hook.on_subscribe(request, response) {
                eprintln!("Warning: Hook '{}' failed on subscribe: {}", name, e);
            }
        }
    }

    /// List all registered hooks
    pub fn list_hooks(&self) -> Vec<String> {
        let hooks = self.hooks.lock().unwrap();
        hooks.keys().cloned().collect()
    }
}

/// Global hook manager instance - using once_cell for thread-safe static initialization
use std::sync::OnceLock;
static GLOBAL_HOOK_MANAGER: OnceLock<EventHookManager> = OnceLock::new();

fn get_global_hook_manager() -> &'static EventHookManager {
    GLOBAL_HOOK_MANAGER.get_or_init(|| EventHookManager::new())
}

// ===========================================================================
// Built-in Hooks for Handle Integration
// ===========================================================================

/// MQ Hook for message queue integration
pub struct MQHook;

impl EventHook for MQHook {
    fn on_emit(&self, event: &EventEnvelope, _response: &EventEmitResponse) -> Result<()> {
        // Optionally forward events to message queues based on tags
        if event.tags.iter().any(|tag| tag.starts_with("mq:")) {
            if let Some(mq_topic) = event
                .tags
                .iter()
                .find(|tag| tag.starts_with("mq:"))
                .map(|tag| &tag[3..])
            {
                eprintln!(
                    "MQ Hook: Would forward event {} to MQ topic: {}",
                    event.id, mq_topic
                );
            }
        }
        Ok(())
    }

    fn on_subscribe(
        &self,
        _request: &EventSubscribeOptions,
        response: &EventSubscribeResponse,
    ) -> Result<()> {
        // Could pull events from MQ and inject into event stream
        eprintln!(
            "MQ hook processed subscription with {} events",
            response.events_returned
        );
        Ok(())
    }

    fn name(&self) -> &str {
        "mq"
    }
}

/// Log Hook for logging integration  
pub struct LogHook;

impl EventHook for LogHook {
    fn on_emit(&self, event: &EventEnvelope, _response: &EventEmitResponse) -> Result<()> {
        // Log events to configured log destinations based on tags
        if event.tags.iter().any(|tag| tag.starts_with("log:")) {
            if let Some(log_path) = event
                .tags
                .iter()
                .find(|tag| tag.starts_with("log:"))
                .map(|tag| &tag[4..])
            {
                eprintln!(
                    "Log Hook: Event {}: {} -> {}",
                    event.id, event.topic, log_path
                );
            }
        }
        Ok(())
    }

    fn on_subscribe(
        &self,
        request: &EventSubscribeOptions,
        response: &EventSubscribeResponse,
    ) -> Result<()> {
        // Could tail log files and generate events
        eprintln!(
            "Log hook: subscription to {} returned {} events",
            request.topic, response.events_returned
        );
        Ok(())
    }

    fn name(&self) -> &str {
        "log"
    }
}

/// Process Hook for proc:// integration
pub struct ProcHook;

impl EventHook for ProcHook {
    fn on_emit(&self, event: &EventEnvelope, _response: &EventEmitResponse) -> Result<()> {
        // Monitor process events or send signals based on tags
        if event.tags.iter().any(|tag| tag.starts_with("proc:")) {
            if let Some(proc_action) = event
                .tags
                .iter()
                .find(|tag| tag.starts_with("proc:"))
                .map(|tag| &tag[5..])
            {
                eprintln!(
                    "Process Hook: Action requested: {} for event {}",
                    proc_action, event.id
                );
            }
        }
        Ok(())
    }

    fn on_subscribe(
        &self,
        request: &EventSubscribeOptions,
        _response: &EventSubscribeResponse,
    ) -> Result<()> {
        // Monitor process state changes and generate events
        if request.topic.starts_with("proc.") {
            eprintln!("Process monitoring subscription: {}", request.topic);
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "proc"
    }
}

/// Filesystem Watch Hook for fs:// integration
pub struct FsWatchHook;

impl EventHook for FsWatchHook {
    fn on_emit(&self, event: &EventEnvelope, _response: &EventEmitResponse) -> Result<()> {
        // React to filesystem events based on tags
        if event.tags.iter().any(|tag| tag.starts_with("fs:")) {
            if let Some(fs_path) = event
                .tags
                .iter()
                .find(|tag| tag.starts_with("fs:"))
                .map(|tag| &tag[3..])
            {
                eprintln!("FS Hook: Filesystem event for path: {}", fs_path);
            }
        }
        Ok(())
    }

    fn on_subscribe(
        &self,
        request: &EventSubscribeOptions,
        _response: &EventSubscribeResponse,
    ) -> Result<()> {
        // Set up filesystem watchers for event generation
        if request.topic.starts_with("fs.") {
            eprintln!("Filesystem watch subscription: {}", request.topic);
            // Could set up fs watchers and generate events
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "fs"
    }
}

// ===========================================================================
// Public registration function
// ===========================================================================

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("event", |u| Ok(Box::new(EventHandle::from_url(u)?)));

    // Register built-in hooks
    let hook_manager = get_global_hook_manager();
    hook_manager.register_hook(Arc::new(MQHook));
    hook_manager.register_hook(Arc::new(LogHook));
    hook_manager.register_hook(Arc::new(ProcHook));
    hook_manager.register_hook(Arc::new(FsWatchHook));
}

/// Metadata for `resh event --help` and `resh event <verb> --help`.
static EVENT_HELP: HandleHelp = HandleHelp {
    description: "The event handle publishes and reads structured events on an event bus \
        stored as one JSON Lines file per topic under the user's state directory, normally \
        ~/.local/state/resh/events/<topic>.jsonl, so events emitted by one resh command can \
        be read by later commands. The stage has no target, so the verb follows a dot \
        directly, as in event://.emit, and options are passed as arguments.",
    usage: "resh event://.<verb>[(key=value,...)]",
    verbs: &[
        VerbHelp {
            name: "list-topics",
            definition: "Lists topics from built-in sample catalogs for the event, mq, log, \
                proc, and fs_watch sources as a JSON object, filtered by prefix, substring, \
                and source.",
            detail: Some(VerbDetail {
                usage: "resh event://.list-topics [prefix=<text>] [match=<text>]\n  \
                    [sources=<source,...>] [limit=<n>] [include_hidden=true|false]\n  \
                    [include_stats=true|false] [include_schema=true|false]\n  \
                    [format=json|text]",
                example: "resh --json-pretty event://.list-topics prefix=jobs. sources=mq",
                example_output: Some(
                    r#"{
  "error": null,
  "filters": {
    "include_hidden": false,
    "include_schema": false,
    "include_stats": false,
    "limit": 1000,
    "match": null,
    "prefix": "jobs.",
    "sources": [
      "mq"
    ]
  },
  "ok": true,
  "timestamp_unix_ms": 1792166019775,
  "topics": [
    {
      "backends": [
        {
          "handle": "mq",
          "id": "mq:kafka:backups.completed",
          "type": "mq"
        }
      ],
      "category": "jobs",
      "description": "Backup job completion messages",
      "display_name": "jobs.backup.completed",
      "first_seen_unix_ms": 1732000000000,
      "is_hidden": false,
      "name": "jobs.backup.completed",
      "origin": "cron.handle",
      "schema": null,
      "sources": [
        "mq"
      ],
      "stats": null,
      "tags": [
        "backup",
        "job"
      ]
    }
  ],
  "topics_returned": 1,
  "topics_total": 1,
  "truncated": false,
  "warnings": []
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "subscribe",
            definition: "Reads stored events whose topic matches a pattern (with * and ? \
                wildcards), starting at an offset (default latest, which skips events \
                already stored) and applying optional tag, correlation, source, and \
                age filters, and prints the batch as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh event://.subscribe topic=<pattern>\n  \
                    [offset=latest|earliest|next|<n>] [limit=<n>] [group_id=<id>]\n  \
                    [consumer_id=<id>] [auto_commit=true|false]\n  \
                    [manual_commit_offset=<n>] [wait=true|false] [wait_timeout_ms=<n>]\n  \
                    [match_tags=<json-array>] [match_correlation_id=<id>]\n  \
                    [match_source=<name>] [max_latency_ms=<n>] [include_data=true|false]\n  \
                    [include_summary=true|false] [include_raw=true|false]\n  \
                    [format=json|text]",
                example: "resh --json-pretty event://.subscribe topic='jobs.*' offset=earliest",
                example_output: Some(
                    r#"Log hook: subscription to jobs.* returned 1 events
MQ hook processed subscription with 1 events
{
  "committed": false,
  "committed_offset": null,
  "consumer_id": null,
  "effective_offset": "earliest",
  "error": null,
  "events": [
    {
      "backend": "state_file",
      "causation_id": null,
      "correlation_id": null,
      "data": {
        "status": "success"
      },
      "id": "evt_1792166019757_224a64d890cb",
      "key": null,
      "mode": "fire_and_forget",
      "mode_used": "fire_and_forget",
      "offset": "0",
      "priority": "normal",
      "raw": null,
      "schema_version": null,
      "source": null,
      "summary": null,
      "tags": [],
      "timestamp_unix_ms": 1792166019757,
      "topic": "jobs.backup.completed",
      "ttl_ms": null
    }
  ],
  "events_returned": 1,
  "group_id": null,
  "high_watermark": "1",
  "next_offset": "1",
  "offset_end": "0",
  "offset_start": "0",
  "ok": true,
  "timed_out": false,
  "timestamp_unix_ms": 1792166019771,
  "topic": "jobs.*",
  "warnings": []
}

Shown with --json-pretty. Offsets index the matching events in timestamp
order. With group_id, offset=next resumes after the offset committed by an
earlier call (auto_commit=true by default), and wait=true polls until an
event arrives or wait_timeout_ms (default 30000) passes. The built-in log
and mq hooks print the two status lines first, in no fixed order."#,
                ),
            }),
        },
        VerbHelp {
            name: "emit",
            definition: "Appends an event with a JSON payload to a topic's file in the event \
                store and prints the resulting event envelope as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh event://.emit topic=<topic> data=<json> [source=<name>]\n  \
                    [key=<key>] [correlation_id=<id>] [causation_id=<id>]\n  \
                    [tags=<json-array>] [priority=low|normal|high]\n  \
                    [mode=fire_and_forget|wait_for_persist] [ttl_ms=<n>]\n  \
                    [summarize=true|false] [schema_version=<v>] [format=json|text]",
                example: "resh event://.emit topic=jobs.backup.completed \
                    'data={\"status\":\"success\"}'",
                example_output: Some(
                    r#"{
  "error": null,
  "event": {
    "backend": "state_file",
    "causation_id": null,
    "correlation_id": null,
    "data": {
      "status": "success"
    },
    "id": "evt_1792166019757_224a64d890cb",
    "key": null,
    "mode": "fire_and_forget",
    "mode_used": "fire_and_forget",
    "priority": "normal",
    "schema_version": null,
    "source": null,
    "summary": null,
    "tags": [],
    "timestamp_unix_ms": 1792166019757,
    "topic": "jobs.backup.completed",
    "ttl_ms": null
  },
  "ok": true,
  "timestamp_unix_ms": 1792166019757,
  "warnings": []
}

The topic must not contain the wildcards * or ?. With
mode=wait_for_persist the file is synced to disk before the reply."#,
                ),
            }),
        },
        VerbHelp {
            name: "hooks.list",
            definition: "Lists the names of the registered event hooks as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh event://.hooks.list",
                example: "resh --json-pretty event://.hooks.list",
                example_output: Some(
                    r#"{
  "global_hooks": [
    "proc",
    "log",
    "mq",
    "fs"
  ],
  "instance_hooks": [],
  "total": 4
}

Shown with --json-pretty. The order of global_hooks varies between runs."#,
                ),
            }),
        },
        VerbHelp {
            name: "hooks.enable",
            definition: "Registers one of the built-in hooks mq, log, proc, or fs for the \
                current process.",
            detail: Some(VerbDetail {
                usage: "resh event://.hooks.enable name=mq|log|proc|fs",
                example: "resh --json-pretty event://.hooks.enable name=mq",
                example_output: Some(
                    r#"{
  "enabled": true,
  "hook": "mq"
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "hooks.disable",
            definition: "Removes a hook by name for the current process, reporting success \
                even if no hook with that name was registered.",
            detail: Some(VerbDetail {
                usage: "resh event://.hooks.disable name=<hook>",
                example: "resh --json-pretty event://.hooks.disable name=mq",
                example_output: Some(
                    r#"{
  "disabled": true,
  "hook": "mq"
}

Shown with --json-pretty."#,
                ),
            }),
        },
    ],
};

// ===========================================================================
// Event Handle Types
// ===========================================================================

#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum OutputFormat {
    Json,
    Text,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "text" => Ok(Self::Text),
            _ => bail!("invalid output format '{}'; supported: json, text", s),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum EventEmitMode {
    FireAndForget,
    WaitForPersist,
}

impl EventEmitMode {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "fire_and_forget" => Ok(Self::FireAndForget),
            "wait_for_persist" => Ok(Self::WaitForPersist),
            _ => bail!(
                "invalid mode '{}'; supported: fire_and_forget, wait_for_persist",
                s
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum EventPriority {
    Low,
    Normal,
    High,
}

impl EventPriority {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "normal" => Ok(Self::Normal),
            "high" => Ok(Self::High),
            _ => bail!("invalid priority '{}'; supported: low, normal, high", s),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum EventOffset {
    Latest,
    Earliest,
    Next,
    Explicit(String),
}

impl EventOffset {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "latest" => Ok(Self::Latest),
            "earliest" => Ok(Self::Earliest),
            "next" => Ok(Self::Next),
            _ => Ok(Self::Explicit(s.to_string())),
        }
    }
}

#[derive(Clone, Debug)]
pub struct EventEmitOptions {
    pub topic: String,
    pub data: Value,

    pub key: Option<String>,
    pub correlation_id: Option<String>,
    pub causation_id: Option<String>,
    pub source: Option<String>,
    pub tags: Vec<String>,

    pub mode: EventEmitMode,
    pub priority: EventPriority,
    pub ttl_ms: Option<u64>,
    pub summarize: bool,
    pub schema_version: Option<String>,

    pub format: OutputFormat,
}

#[derive(Clone, Debug)]
pub struct EventSubscribeOptions {
    pub topic: String,

    pub offset: EventOffset,
    pub limit: u32,

    pub group_id: Option<String>,
    pub consumer_id: Option<String>,
    pub auto_commit: bool,
    pub manual_commit_offset: Option<String>,

    pub wait: bool,
    pub wait_timeout_ms: Option<u64>,

    pub match_tags: Vec<String>,
    pub match_correlation_id: Option<String>,
    pub match_source: Option<String>,
    pub max_latency_ms: Option<u64>,

    pub include_data: bool,
    pub include_summary: bool,
    pub include_raw: bool,

    pub format: OutputFormat,
}

#[derive(Clone, Debug)]
pub struct EventFilter {
    pub match_tags: Vec<String>,
    pub match_correlation_id: Option<String>,
    pub match_source: Option<String>,
    pub max_latency_ms: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct EventBatch {
    pub events: Vec<EventEnvelope>,
    pub offset_start: Option<String>,
    pub offset_end: Option<String>,
    pub next_offset: Option<String>,
    pub high_watermark: Option<String>,
}

#[derive(Clone, Debug)]
pub struct EventSubscribeResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub topic: String,
    pub group_id: Option<String>,
    pub consumer_id: Option<String>,

    pub effective_offset: String,
    pub offset_start: Option<String>,
    pub offset_end: Option<String>,
    pub next_offset: Option<String>,
    pub high_watermark: Option<String>,

    pub timed_out: bool,
    pub events_returned: u32,
    pub events: Vec<EventEnvelope>,

    pub committed_offset: Option<String>,
    pub committed: bool,

    pub error: Option<EventError>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub id: String,
    pub topic: String,
    pub timestamp_unix_ms: i64,

    pub mode: String,
    pub mode_used: String,
    pub priority: String,
    pub ttl_ms: Option<u64>,

    pub key: Option<String>,
    pub correlation_id: Option<String>,
    pub causation_id: Option<String>,
    pub source: Option<String>,
    pub tags: Vec<String>,
    pub schema_version: Option<String>,

    pub data: Value,
    pub summary: Option<String>,
    pub backend: String,

    pub offset: Option<String>,
    pub raw: Option<Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EventError {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct EventEmitResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub event: Option<EventEnvelope>,
    pub error: Option<EventError>,
    pub warnings: Vec<String>,
}

// ===========================================================================
// Event Backend Trait
// ===========================================================================

pub trait EventBackend: Send + Sync + AsAny {
    fn emit_fire_and_forget(&self, evt: &EventEnvelope) -> Result<()>;
    fn emit_wait_for_persist(&self, evt: &EventEnvelope) -> Result<()>;
    fn name(&self) -> &str;
    fn supports_persistence(&self) -> bool;

    fn subscribe(
        &self,
        topic_pattern: &str,
        offset: &EventOffset,
        limit: u32,
        group_id: Option<&str>,
        consumer_id: Option<&str>,
        wait: bool,
        wait_timeout_ms: Option<u64>,
        filters: &EventFilter,
    ) -> Result<EventBatch>;

    fn commit_offset(&self, topic_pattern: &str, group_id: &str, offset: &str) -> Result<()>;
}

// ===========================================================================
// In-Memory Event Backend
// ===========================================================================

#[derive(Debug, Clone)]
pub struct InMemoryEventBackend {
    events: Arc<Mutex<Vec<EventEnvelope>>>,
    consumer_offsets: Arc<Mutex<std::collections::HashMap<String, usize>>>,
}

impl InMemoryEventBackend {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
            consumer_offsets: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// The process-wide in-memory bus. Every handle in one process that
    /// uses it sees the same events and committed offsets.
    pub fn shared() -> Self {
        static BUS: OnceLock<InMemoryEventBackend> = OnceLock::new();
        BUS.get_or_init(InMemoryEventBackend::new).clone()
    }

    #[allow(dead_code)]
    pub fn get_events(&self) -> Vec<EventEnvelope> {
        self.events.lock().unwrap().clone()
    }

    #[allow(dead_code)]
    pub fn clear_events(&self) {
        self.events.lock().unwrap().clear();
    }

    fn topic_matches_pattern(&self, topic: &str, pattern: &str) -> bool {
        topic_matches_pattern(topic, pattern)
    }
}

/// True if `topic` equals `pattern`, or matches it with `*` (any run of
/// characters) and `?` (one character) as wildcards.
fn topic_matches_pattern(topic: &str, pattern: &str) -> bool {
    if pattern == topic {
        return true;
    }
    if !has_wildcard(pattern) {
        return false;
    }
    let re = regex::escape(pattern)
        .replace(r"\*", ".*")
        .replace(r"\?", ".");
    Regex::new(&format!("^{}$", re))
        .map(|r| r.is_match(topic))
        .unwrap_or(false)
}

fn has_wildcard(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?')
}

/// Keeps events that pass the tag, correlation, source and age filters.
fn apply_filters(
    events: &[EventEnvelope],
    filters: &EventFilter,
    now_ms: i64,
) -> Vec<EventEnvelope> {
    events
        .iter()
        .filter(|evt| {
            if !filters.match_tags.iter().all(|tag| evt.tags.contains(tag)) {
                return false;
            }
            if let Some(ref id) = filters.match_correlation_id {
                if evt.correlation_id.as_ref() != Some(id) {
                    return false;
                }
            }
            if let Some(ref src) = filters.match_source {
                if evt.source.as_ref() != Some(src) {
                    return false;
                }
            }
            if let Some(max_latency_ms) = filters.max_latency_ms {
                if evt.timestamp_unix_ms < now_ms - (max_latency_ms as i64) {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect()
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Selects up to `limit` events of `matching` starting at `start_index`,
/// applies `filters`, and computes the batch offsets. Offsets index
/// `matching`, so they stay stable as new events are appended.
fn select_batch(
    matching: &[EventEnvelope],
    start_index: usize,
    limit: u32,
    filters: &EventFilter,
) -> EventBatch {
    let start_index = start_index.min(matching.len());
    let end_index = std::cmp::min(start_index + limit as usize, matching.len());
    let events = apply_filters(&matching[start_index..end_index], filters, now_unix_ms());
    EventBatch {
        offset_start: if events.is_empty() {
            None
        } else {
            Some(start_index.to_string())
        },
        offset_end: if events.is_empty() {
            None
        } else {
            Some((end_index - 1).to_string())
        },
        events,
        next_offset: Some(end_index.to_string()),
        high_watermark: Some(matching.len().to_string()),
    }
}

/// Resolves a subscribe offset to an index into the matching events.
fn resolve_start_index(
    offset: &EventOffset,
    matching_len: usize,
    group_id: Option<&str>,
    committed: impl FnOnce(&str) -> Result<Option<usize>>,
) -> Result<usize> {
    Ok(match offset {
        EventOffset::Latest => matching_len,
        EventOffset::Earliest => 0,
        EventOffset::Next => {
            let group_id =
                group_id.ok_or_else(|| anyhow::anyhow!("offset='next' requires group_id"))?;
            committed(group_id)?.unwrap_or(0)
        }
        EventOffset::Explicit(offset_str) => offset_str
            .parse::<usize>()
            .map_err(|_| anyhow::anyhow!("invalid numeric offset: {}", offset_str))?,
    })
}

impl EventBackend for InMemoryEventBackend {
    fn emit_fire_and_forget(&self, evt: &EventEnvelope) -> Result<()> {
        let mut events = self
            .events
            .lock()
            .map_err(|_| anyhow::anyhow!("failed to acquire events lock"))?;

        let mut evt_with_offset = evt.clone();
        evt_with_offset.offset = Some(events.len().to_string());

        events.push(evt_with_offset);
        Ok(())
    }

    fn emit_wait_for_persist(&self, evt: &EventEnvelope) -> Result<()> {
        // In-memory backend doesn't support true persistence, so we treat this as fire-and-forget
        self.emit_fire_and_forget(evt)
    }

    fn name(&self) -> &str {
        "in_memory_bus"
    }

    fn supports_persistence(&self) -> bool {
        false
    }

    fn subscribe(
        &self,
        topic_pattern: &str,
        offset: &EventOffset,
        limit: u32,
        group_id: Option<&str>,
        _consumer_id: Option<&str>, // Not used in this simple implementation
        wait: bool,
        wait_timeout_ms: Option<u64>,
        filters: &EventFilter,
    ) -> Result<EventBatch> {
        let deadline = std::time::Instant::now()
            + Duration::from_millis(if wait {
                wait_timeout_ms.unwrap_or(30_000)
            } else {
                0
            });
        let mut start_index: Option<usize> = None;
        loop {
            let matching: Vec<EventEnvelope> = {
                let events = self
                    .events
                    .lock()
                    .map_err(|_| anyhow::anyhow!("failed to acquire events lock"))?;
                events
                    .iter()
                    .filter(|e| self.topic_matches_pattern(&e.topic, topic_pattern))
                    .cloned()
                    .collect()
            };
            let start = match start_index {
                Some(s) => s,
                None => {
                    let s = resolve_start_index(offset, matching.len(), group_id, |g| {
                        let offsets = self
                            .consumer_offsets
                            .lock()
                            .map_err(|_| anyhow::anyhow!("failed to acquire offsets lock"))?;
                        Ok(offsets.get(&format!("{}:{}", g, topic_pattern)).cloned())
                    })?;
                    start_index = Some(s);
                    s
                }
            };
            if start < matching.len() || std::time::Instant::now() >= deadline {
                return Ok(select_batch(&matching, start, limit, filters));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn commit_offset(&self, topic_pattern: &str, group_id: &str, offset: &str) -> Result<()> {
        let mut offsets = self
            .consumer_offsets
            .lock()
            .map_err(|_| anyhow::anyhow!("failed to acquire offsets lock"))?;

        let offset_num = offset
            .parse::<usize>()
            .map_err(|_| anyhow::anyhow!("invalid offset for commit: {}", offset))?;

        let key = format!("{}:{}", group_id, topic_pattern);
        offsets.insert(key, offset_num);

        Ok(())
    }
}

// ===========================================================================
// File-backed Event Backend
// ===========================================================================

/// Event store shared by every resh process of the user: each topic is an
/// append-only JSON Lines file `<base>/<topic>.jsonl`, and committed consumer
/// group offsets live in `<base>/_offsets.json`. The base directory is
/// normally `<state_dir>/resh/events` (`~/.local/state/resh/events`); it is
/// created with mode 0700 and files with mode 0600.
#[derive(Debug, Clone)]
pub struct FileEventBackend {
    base: PathBuf,
}

impl FileEventBackend {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    /// `<state_dir>/resh/events`, or None when the platform has no state
    /// directory.
    pub fn default_base() -> Option<PathBuf> {
        dirs::state_dir().map(|d| d.join("resh").join("events"))
    }

    pub fn base(&self) -> &Path {
        &self.base
    }

    fn ensure_dir(&self) -> Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.base)
            .with_context(|| {
                format!(
                    "event store unavailable: cannot create {}",
                    self.base.display()
                )
            })
    }

    fn open_private(path: &Path, append: bool) -> Result<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut o = std::fs::OpenOptions::new();
        o.create(true).mode(0o600);
        if append {
            o.append(true);
        } else {
            o.write(true).truncate(true);
        }
        o.open(path)
            .with_context(|| format!("event store unavailable: cannot open {}", path.display()))
    }

    fn topic_path(&self, topic: &str) -> PathBuf {
        self.base.join(format!("{}.jsonl", topic))
    }

    fn offsets_path(&self) -> PathBuf {
        self.base.join("_offsets.json")
    }

    fn append(&self, evt: &EventEnvelope, sync: bool) -> Result<()> {
        if has_wildcard(&evt.topic) {
            bail!("emit topic cannot contain the wildcards * or ?");
        }
        self.ensure_dir()?;
        let mut stored = evt.clone();
        stored.offset = None;
        let mut line = serde_json::to_string(&stored)?;
        line.push('\n');
        let mut f = Self::open_private(&self.topic_path(&evt.topic), true)?;
        // One write of the whole line, so concurrent appenders do not interleave.
        f.write_all(line.as_bytes())?;
        if sync {
            f.sync_data()?;
        }
        Ok(())
    }

    fn read_topic_file(path: &Path) -> Result<Vec<EventEnvelope>> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
        };
        // A line that does not parse (for example a partial write) is skipped.
        Ok(text
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect())
    }

    /// All stored events whose topic matches `pattern`, ordered by timestamp
    /// (ties by topic name, then file order), with `offset` set to the index.
    fn load_matching(&self, pattern: &str) -> Result<Vec<EventEnvelope>> {
        let mut events = if !has_wildcard(pattern) {
            Self::read_topic_file(&self.topic_path(pattern))?
        } else {
            let mut topics: Vec<(String, PathBuf)> = match std::fs::read_dir(&self.base) {
                Ok(rd) => rd
                    .filter_map(|e| e.ok())
                    .filter_map(|e| {
                        let path = e.path();
                        let name = path
                            .file_name()?
                            .to_str()?
                            .strip_suffix(".jsonl")?
                            .to_string();
                        Some((name, path))
                    })
                    .filter(|(t, _)| topic_matches_pattern(t, pattern))
                    .collect(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(e) => {
                    return Err(e).with_context(|| format!("cannot read {}", self.base.display()));
                }
            };
            topics.sort();
            let mut all = Vec::new();
            for (_, path) in topics {
                all.extend(Self::read_topic_file(&path)?);
            }
            all.sort_by_key(|e| e.timestamp_unix_ms);
            all
        };
        for (i, e) in events.iter_mut().enumerate() {
            e.offset = Some(i.to_string());
        }
        Ok(events)
    }

    fn read_offsets(&self) -> Result<HashMap<String, usize>> {
        match std::fs::read_to_string(self.offsets_path()) {
            Ok(t) => Ok(serde_json::from_str(&t).unwrap_or_default()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
            Err(e) => Err(e).context("cannot read committed offsets"),
        }
    }
}

impl AsAny for FileEventBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl EventBackend for FileEventBackend {
    fn emit_fire_and_forget(&self, evt: &EventEnvelope) -> Result<()> {
        self.append(evt, false)
    }

    fn emit_wait_for_persist(&self, evt: &EventEnvelope) -> Result<()> {
        self.append(evt, true)
    }

    fn name(&self) -> &str {
        "state_file"
    }

    fn supports_persistence(&self) -> bool {
        true
    }

    fn subscribe(
        &self,
        topic_pattern: &str,
        offset: &EventOffset,
        limit: u32,
        group_id: Option<&str>,
        _consumer_id: Option<&str>,
        wait: bool,
        wait_timeout_ms: Option<u64>,
        filters: &EventFilter,
    ) -> Result<EventBatch> {
        let deadline = std::time::Instant::now()
            + Duration::from_millis(if wait {
                wait_timeout_ms.unwrap_or(30_000)
            } else {
                0
            });
        let mut start_index: Option<usize> = None;
        loop {
            let matching = self.load_matching(topic_pattern)?;
            let start = match start_index {
                Some(s) => s,
                None => {
                    let s = resolve_start_index(offset, matching.len(), group_id, |g| {
                        Ok(self
                            .read_offsets()?
                            .get(&format!("{}:{}", g, topic_pattern))
                            .cloned())
                    })?;
                    start_index = Some(s);
                    s
                }
            };
            if start < matching.len() || std::time::Instant::now() >= deadline {
                return Ok(select_batch(&matching, start, limit, filters));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn commit_offset(&self, topic_pattern: &str, group_id: &str, offset: &str) -> Result<()> {
        let offset_num = offset
            .parse::<usize>()
            .map_err(|_| anyhow::anyhow!("invalid offset for commit: {}", offset))?;
        self.ensure_dir()?;
        let mut offsets = self.read_offsets()?;
        offsets.insert(format!("{}:{}", group_id, topic_pattern), offset_num);
        // Write a temporary file and rename it so readers never see a partial file.
        let tmp = self
            .base
            .join(format!("_offsets.json.{}.tmp", std::process::id()));
        {
            let mut f = Self::open_private(&tmp, false)?;
            f.write_all(serde_json::to_string(&offsets)?.as_bytes())?;
            f.sync_data()?;
        }
        std::fs::rename(&tmp, self.offsets_path()).context("cannot save committed offsets")?;
        Ok(())
    }
}

// ===========================================================================
// List Topics Types
// ===========================================================================

#[derive(Clone, Debug, Serialize)]
pub struct ListTopicsOptions {
    pub prefix: Option<String>,
    pub match_substr: Option<String>,
    pub sources: Vec<String>, // "event" | "mq" | "log" | "proc" | "fs_watch"
    pub limit: u32,
    pub include_hidden: bool,

    pub include_stats: bool,
    pub include_schema: bool,
    pub include_backends: bool,
    pub summarize: bool,

    pub format: OutputFormat,
}

#[derive(Clone, Debug, Serialize)]
pub struct TopicBackendRef {
    pub r#type: String, // "event" | "mq" | "log" | "proc" | "fs_watch"
    pub handle: String, // e.g. "event", "mq", "log"
    pub id: String,     // backend-specific identifier
}

#[derive(Clone, Debug, Serialize)]
pub struct TopicStats {
    pub approx_message_count: Option<u64>,
    pub last_event_unix_ms: Option<i64>,
    pub partitions: Option<u32>,
    pub replication_factor: Option<u32>,
    pub throughput_per_minute: Option<f64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TopicFieldInfo {
    pub name: String,
    pub r#type: String,
    pub required: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct TopicSchemaInfo {
    pub schema_version: Option<String>,
    pub example: Option<Value>,
    pub fields: Vec<TopicFieldInfo>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TopicInfo {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub category: Option<String>,
    pub is_hidden: bool,

    pub sources: Vec<String>,
    pub backends: Vec<TopicBackendRef>,

    pub stats: Option<TopicStats>,
    pub schema: Option<TopicSchemaInfo>,

    pub tags: Vec<String>,
    pub origin: Option<String>,
    pub first_seen_unix_ms: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ListTopicsResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub filters: Value, // echo of applied filters
    pub topics_total: u32,
    pub topics_returned: u32,
    pub truncated: bool,

    pub topics: Vec<TopicInfo>,

    pub error: Option<EventError>,
    pub warnings: Vec<String>,
}

// ===========================================================================
// Topic Provider Trait
// ===========================================================================

pub trait TopicProvider: Send + Sync {
    fn source_type(&self) -> &str; // "event" | "mq" | "log" | "proc" | "fs_watch"

    fn list_topics(
        &self,
        include_hidden: bool,
        include_stats: bool,
        include_schema: bool,
    ) -> Result<Vec<TopicInfo>>;
}

// Add trait object support for downcasting
pub trait AsAny {
    fn as_any(&self) -> &dyn std::any::Any;
}

impl AsAny for InMemoryEventBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// ===========================================================================
// Topic Providers Implementations
// ===========================================================================

/// EventBus Topic Provider - provides topics from the internal event backend  
pub struct EventBusTopicProvider;

impl EventBusTopicProvider {
    pub fn new() -> Self {
        Self
    }
}

impl TopicProvider for EventBusTopicProvider {
    fn source_type(&self) -> &str {
        "event"
    }

    fn list_topics(
        &self,
        include_hidden: bool,
        include_stats: bool,
        include_schema: bool,
    ) -> Result<Vec<TopicInfo>> {
        // For now, return a simple mock topic list
        // In a real implementation, this would query the actual event backend
        let mut topics = vec![TopicInfo {
            name: "events.system".to_string(),
            display_name: "System Events".to_string(),
            description: Some("System-level event notifications".to_string()),
            category: Some("system".to_string()),
            is_hidden: false,
            sources: vec!["event".to_string()],
            backends: vec![TopicBackendRef {
                r#type: "event".to_string(),
                handle: "event".to_string(),
                id: "system".to_string(),
            }],
            stats: if include_stats {
                Some(TopicStats {
                    approx_message_count: Some(42),
                    last_event_unix_ms: Some(chrono::Utc::now().timestamp_millis()),
                    partitions: Some(1),
                    replication_factor: Some(1),
                    throughput_per_minute: Some(1.5),
                })
            } else {
                None
            },
            schema: if include_schema {
                Some(TopicSchemaInfo {
                    schema_version: Some("v1".to_string()),
                    example: Some(serde_json::json!({"type": "system", "message": "example"})),
                    fields: vec![
                        TopicFieldInfo {
                            name: "type".to_string(),
                            r#type: "string".to_string(),
                            required: true,
                        },
                        TopicFieldInfo {
                            name: "message".to_string(),
                            r#type: "string".to_string(),
                            required: true,
                        },
                    ],
                })
            } else {
                None
            },
            tags: vec!["core".to_string()],
            origin: Some("event://".to_string()),
            first_seen_unix_ms: Some(chrono::Utc::now().timestamp_millis() - 86400000), // 1 day ago
        }];

        if !include_hidden {
            topics.retain(|t| !t.is_hidden);
        }

        Ok(topics)
    }
}

/// MQ Topic Provider
pub struct MqTopicProvider;

impl MqTopicProvider {
    pub fn new() -> Self {
        Self
    }
}

impl TopicProvider for MqTopicProvider {
    fn source_type(&self) -> &str {
        "mq"
    }

    fn list_topics(
        &self,
        include_hidden: bool,
        _include_stats: bool,
        _include_schema: bool,
    ) -> Result<Vec<TopicInfo>> {
        // Mock implementation - in practice would query mq:// handle registry
        let mut topics = vec![
            TopicInfo {
                name: "jobs.backup.completed".to_string(),
                display_name: "jobs.backup.completed".to_string(),
                description: Some("Backup job completion messages".to_string()),
                category: Some("jobs".to_string()),
                is_hidden: false,
                sources: vec!["mq".to_string()],
                backends: vec![TopicBackendRef {
                    r#type: "mq".to_string(),
                    handle: "mq".to_string(),
                    id: "mq:kafka:backups.completed".to_string(),
                }],
                stats: None,
                schema: None,
                tags: vec!["backup".to_string(), "job".to_string()],
                origin: Some("cron.handle".to_string()),
                first_seen_unix_ms: Some(1732000000000),
            },
            TopicInfo {
                name: "_internal.heartbeat".to_string(),
                display_name: "_internal.heartbeat".to_string(),
                description: Some("Internal system heartbeat".to_string()),
                category: Some("system".to_string()),
                is_hidden: true,
                sources: vec!["mq".to_string()],
                backends: vec![TopicBackendRef {
                    r#type: "mq".to_string(),
                    handle: "mq".to_string(),
                    id: "mq:kafka:_internal.heartbeat".to_string(),
                }],
                stats: None,
                schema: None,
                tags: vec!["system".to_string(), "heartbeat".to_string()],
                origin: Some("system.handle".to_string()),
                first_seen_unix_ms: Some(1732000000000),
            },
        ];

        if !include_hidden {
            topics.retain(|t| !t.is_hidden);
        }

        Ok(topics)
    }
}

/// Log Topic Provider
pub struct LogTopicProvider;

impl LogTopicProvider {
    pub fn new() -> Self {
        Self
    }
}

impl TopicProvider for LogTopicProvider {
    fn source_type(&self) -> &str {
        "log"
    }

    fn list_topics(
        &self,
        include_hidden: bool,
        _include_stats: bool,
        _include_schema: bool,
    ) -> Result<Vec<TopicInfo>> {
        let mut topics = vec![
            TopicInfo {
                name: "logs.system.auth".to_string(),
                display_name: "logs.system.auth".to_string(),
                description: Some("System authentication log events".to_string()),
                category: Some("logs".to_string()),
                is_hidden: false,
                sources: vec!["log".to_string()],
                backends: vec![TopicBackendRef {
                    r#type: "log".to_string(),
                    handle: "log".to_string(),
                    id: "log:journald:auth.log".to_string(),
                }],
                stats: None,
                schema: None,
                tags: vec!["auth".to_string(), "security".to_string()],
                origin: Some("log.handle".to_string()),
                first_seen_unix_ms: Some(1732000000000),
            },
            TopicInfo {
                name: "logs.app.errors".to_string(),
                display_name: "logs.app.errors".to_string(),
                description: Some("Application error log events".to_string()),
                category: Some("logs".to_string()),
                is_hidden: false,
                sources: vec!["log".to_string()],
                backends: vec![TopicBackendRef {
                    r#type: "log".to_string(),
                    handle: "log".to_string(),
                    id: "log:file:/var/log/app.log".to_string(),
                }],
                stats: None,
                schema: None,
                tags: vec!["application".to_string(), "error".to_string()],
                origin: Some("app.handle".to_string()),
                first_seen_unix_ms: Some(1732000000000),
            },
        ];

        if !include_hidden {
            topics.retain(|t| !t.is_hidden);
        }

        Ok(topics)
    }
}

/// Proc Topic Provider
pub struct ProcTopicProvider;

impl ProcTopicProvider {
    pub fn new() -> Self {
        Self
    }
}

impl TopicProvider for ProcTopicProvider {
    fn source_type(&self) -> &str {
        "proc"
    }

    fn list_topics(
        &self,
        include_hidden: bool,
        _include_stats: bool,
        _include_schema: bool,
    ) -> Result<Vec<TopicInfo>> {
        let mut topics = vec![
            TopicInfo {
                name: "proc.exit".to_string(),
                display_name: "proc.exit".to_string(),
                description: Some("Process exit events".to_string()),
                category: Some("proc".to_string()),
                is_hidden: false,
                sources: vec!["proc".to_string()],
                backends: vec![TopicBackendRef {
                    r#type: "proc".to_string(),
                    handle: "proc".to_string(),
                    id: "proc:signal:SIGCHLD".to_string(),
                }],
                stats: None,
                schema: None,
                tags: vec!["process".to_string(), "exit".to_string()],
                origin: Some("proc.handle".to_string()),
                first_seen_unix_ms: Some(1732000000000),
            },
            TopicInfo {
                name: "proc.cpu.high".to_string(),
                display_name: "proc.cpu.high".to_string(),
                description: Some("High CPU usage events".to_string()),
                category: Some("proc".to_string()),
                is_hidden: false,
                sources: vec!["proc".to_string()],
                backends: vec![TopicBackendRef {
                    r#type: "proc".to_string(),
                    handle: "proc".to_string(),
                    id: "proc:monitor:cpu_threshold".to_string(),
                }],
                stats: None,
                schema: None,
                tags: vec![
                    "process".to_string(),
                    "cpu".to_string(),
                    "performance".to_string(),
                ],
                origin: Some("proc.handle".to_string()),
                first_seen_unix_ms: Some(1732000000000),
            },
        ];

        if !include_hidden {
            topics.retain(|t| !t.is_hidden);
        }

        Ok(topics)
    }
}

/// Filesystem Watch Topic Provider
pub struct FsWatchTopicProvider;

impl FsWatchTopicProvider {
    pub fn new() -> Self {
        Self
    }
}

impl TopicProvider for FsWatchTopicProvider {
    fn source_type(&self) -> &str {
        "fs_watch"
    }

    fn list_topics(
        &self,
        include_hidden: bool,
        _include_stats: bool,
        _include_schema: bool,
    ) -> Result<Vec<TopicInfo>> {
        let mut topics = vec![
            TopicInfo {
                name: "fs.watch./etc".to_string(),
                display_name: "fs.watch./etc".to_string(),
                description: Some("Filesystem changes in /etc directory".to_string()),
                category: Some("fs".to_string()),
                is_hidden: false,
                sources: vec!["fs_watch".to_string()],
                backends: vec![TopicBackendRef {
                    r#type: "fs_watch".to_string(),
                    handle: "fs".to_string(),
                    id: "fs:watch:/etc".to_string(),
                }],
                stats: None,
                schema: None,
                tags: vec!["filesystem".to_string(), "config".to_string()],
                origin: Some("fs.handle".to_string()),
                first_seen_unix_ms: Some(1732000000000),
            },
            TopicInfo {
                name: "fs.watch./var/log".to_string(),
                display_name: "fs.watch./var/log".to_string(),
                description: Some("Filesystem changes in /var/log directory".to_string()),
                category: Some("fs".to_string()),
                is_hidden: false,
                sources: vec!["fs_watch".to_string()],
                backends: vec![TopicBackendRef {
                    r#type: "fs_watch".to_string(),
                    handle: "fs".to_string(),
                    id: "fs:watch:/var/log".to_string(),
                }],
                stats: None,
                schema: None,
                tags: vec!["filesystem".to_string(), "logs".to_string()],
                origin: Some("fs.handle".to_string()),
                first_seen_unix_ms: Some(1732000000000),
            },
        ];

        if !include_hidden {
            topics.retain(|t| !t.is_hidden);
        }

        Ok(topics)
    }
}

// ===========================================================================
// Event Handle Implementation
// ===========================================================================

pub struct EventHandle {
    backend: Box<dyn EventBackend>,
    hook_manager: Arc<EventHookManager>,
}

impl EventHandle {
    pub fn new(backend: Box<dyn EventBackend>) -> Self {
        Self {
            backend,
            hook_manager: Arc::new(EventHookManager::new()),
        }
    }

    /// Uses the file-backed store under the user's state directory, so
    /// events persist across resh invocations. Without a state directory it
    /// falls back to the process-wide in-memory bus (never /tmp).
    pub fn from_url(_url: &Url) -> Result<Self> {
        let backend: Box<dyn EventBackend> = match FileEventBackend::default_base() {
            Some(base) => Box::new(FileEventBackend::new(base)),
            None => Box::new(InMemoryEventBackend::shared()),
        };
        Ok(Self::new(backend))
    }

    /// Register a custom hook with this event handle
    pub fn register_hook(&self, hook: Arc<dyn EventHook>) {
        self.hook_manager.register_hook(hook);
    }

    /// Remove a hook by name
    pub fn remove_hook(&self, name: &str) {
        self.hook_manager.remove_hook(name);
    }

    /// Writes the approved help for `help`, `--help`, `-h`, `--help=<verb>`
    /// and `help(verb=<verb>)`; returns None for any other verb.
    fn check_and_display_help(
        &self,
        verb: &str,
        args: &Args,
        io: &mut IoStreams,
    ) -> Result<Option<Status>> {
        let help_verb = if help::HELP_ALIASES.contains(&verb) {
            args.get("verb").map(String::as_str)
        } else if let Some(v) = verb.strip_prefix("--help=") {
            Some(v)
        } else {
            return Ok(None);
        };
        write!(
            io.stdout,
            "{}",
            help::render_legacy("event", &EVENT_HELP, self.verbs(), help_verb)
        )?;
        Ok(Some(Status::ok()))
    }

    pub fn list_hooks(&self) -> Vec<String> {
        self.hook_manager.list_hooks()
    }

    #[cfg(test)]
    pub fn backend(&self) -> &dyn EventBackend {
        self.backend.as_ref()
    }

    fn validate_topic(topic: &str) -> Result<()> {
        if topic.is_empty() {
            bail!("topic cannot be empty");
        }

        let topic = topic.trim();
        if topic.is_empty() {
            bail!("topic cannot be empty after trimming");
        }

        if topic.len() > 256 {
            bail!("topic cannot exceed 256 characters");
        }

        // Validate against conservative pattern: [a-zA-Z0-9._:*?-]{1,256}
        let valid_chars = topic
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-' | '*' | '?'));

        if !valid_chars {
            bail!(
                "topic contains invalid characters; only alphanumeric, dots, underscores, colons, hyphens, and wildcards (* ?) are allowed"
            );
        }

        Ok(())
    }

    fn validate_tags(tags: &[String]) -> Result<()> {
        for tag in tags {
            if tag.is_empty() {
                bail!("tags cannot be empty");
            }
            if tag.len() > 64 {
                bail!("tag '{}' exceeds maximum length of 64 characters", tag);
            }
            let valid_chars = tag.chars().all(|c| c.is_ascii() && !c.is_ascii_control());
            if !valid_chars {
                bail!("tag '{}' contains invalid characters", tag);
            }
        }
        Ok(())
    }

    fn parse_emit_options(args: &Args) -> Result<EventEmitOptions> {
        // Required parameters
        let topic = args
            .get("topic")
            .ok_or_else(|| anyhow::anyhow!("topic parameter is required"))?
            .clone();

        let data_str = args
            .get("data")
            .ok_or_else(|| anyhow::anyhow!("data parameter is required"))?;

        let data: Value = serde_json::from_str(data_str).context("failed to parse data as JSON")?;

        // Validate required fields
        Self::validate_topic(&topic)?;

        // Optional metadata
        let key = args.get("key").cloned();
        let correlation_id = args.get("correlation_id").cloned();
        let causation_id = args.get("causation_id").cloned();
        let source = args.get("source").cloned();

        let tags: Vec<String> = args
            .get("tags")
            .map(|tags_str| {
                serde_json::from_str::<Vec<String>>(tags_str)
                    .unwrap_or_else(|_| vec![tags_str.clone()])
            })
            .unwrap_or_default();

        Self::validate_tags(&tags)?;

        // Delivery & durability options
        let mode = args
            .get("mode")
            .map(|s| EventEmitMode::from_str(s))
            .unwrap_or(Ok(EventEmitMode::FireAndForget))?;

        let priority = args
            .get("priority")
            .map(|s| EventPriority::from_str(s))
            .unwrap_or(Ok(EventPriority::Normal))?;

        let ttl_ms = args
            .get("ttl_ms")
            .map(|s| {
                s.parse::<u64>()
                    .context("ttl_ms must be a valid positive integer")
            })
            .transpose()?;

        // AI-friendly options
        let summarize = args
            .get("summarize")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);

        let schema_version = args.get("schema_version").cloned();

        // Output format
        let format = args
            .get("format")
            .map(|s| OutputFormat::from_str(s))
            .unwrap_or(Ok(OutputFormat::Json))?;

        Ok(EventEmitOptions {
            topic,
            data,
            key,
            correlation_id,
            causation_id,
            source,
            tags,
            mode,
            priority,
            ttl_ms,
            summarize,
            schema_version,
            format,
        })
    }

    fn parse_subscribe_options(args: &Args) -> Result<EventSubscribeOptions> {
        // Required parameters
        let topic = args
            .get("topic")
            .ok_or_else(|| anyhow::anyhow!("topic parameter is required"))?
            .clone();

        Self::validate_topic(&topic)?;

        // Offset and limit
        let offset = args
            .get("offset")
            .map(|s| EventOffset::from_str(s))
            .unwrap_or(Ok(EventOffset::Latest))?;

        let limit = args
            .get("limit")
            .map(|s| {
                let limit_val = s
                    .parse::<u32>()
                    .context("limit must be a valid positive integer")?;
                if limit_val < 1 || limit_val > 10_000 {
                    bail!("limit must be between 1 and 10,000");
                }
                Ok(limit_val)
            })
            .unwrap_or(Ok(100))?;

        // Consumer group options
        let group_id = args.get("group_id").cloned();
        let consumer_id = args.get("consumer_id").cloned();
        let auto_commit = args
            .get("auto_commit")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(true);
        let manual_commit_offset = args.get("manual_commit_offset").cloned();

        // Wait options
        let wait = args
            .get("wait")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);
        let wait_timeout_ms = args
            .get("wait_timeout_ms")
            .map(|s| {
                s.parse::<u64>()
                    .context("wait_timeout_ms must be a valid positive integer")
            })
            .transpose()?;

        // Filter options
        let match_tags: Vec<String> = args
            .get("match_tags")
            .map(|tags_str| {
                serde_json::from_str::<Vec<String>>(tags_str)
                    .unwrap_or_else(|_| vec![tags_str.clone()])
            })
            .unwrap_or_default();

        let match_correlation_id = args.get("match_correlation_id").cloned();
        let match_source = args.get("match_source").cloned();
        let max_latency_ms = args
            .get("max_latency_ms")
            .map(|s| {
                s.parse::<u64>()
                    .context("max_latency_ms must be a valid positive integer")
            })
            .transpose()?;

        // Include options
        let include_data = args
            .get("include_data")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(true);
        let include_summary = args
            .get("include_summary")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(true);
        let include_raw = args
            .get("include_raw")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);

        // Output format
        let format = args
            .get("format")
            .map(|s| OutputFormat::from_str(s))
            .unwrap_or(Ok(OutputFormat::Json))?;

        // Validation
        if matches!(offset, EventOffset::Next) && group_id.is_none() {
            bail!("offset='next' requires group_id to be specified");
        }

        if manual_commit_offset.is_some() && group_id.is_none() {
            bail!("manual_commit_offset requires group_id to be specified");
        }

        Ok(EventSubscribeOptions {
            topic,
            offset,
            limit,
            group_id,
            consumer_id,
            auto_commit,
            manual_commit_offset,
            wait,
            wait_timeout_ms,
            match_tags,
            match_correlation_id,
            match_source,
            max_latency_ms,
            include_data,
            include_summary,
            include_raw,
            format,
        })
    }

    fn generate_event_id() -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let uuid = Uuid::new_v4();
        let short_uuid = uuid.to_string().replace("-", "")[..12].to_string();
        format!("evt_{}_{}", timestamp, short_uuid)
    }

    fn mode_to_string(mode: &EventEmitMode) -> String {
        match mode {
            EventEmitMode::FireAndForget => "fire_and_forget".to_string(),
            EventEmitMode::WaitForPersist => "wait_for_persist".to_string(),
        }
    }

    fn priority_to_string(priority: &EventPriority) -> String {
        match priority {
            EventPriority::Low => "low".to_string(),
            EventPriority::Normal => "normal".to_string(),
            EventPriority::High => "high".to_string(),
        }
    }

    fn generate_summary_if_requested(data: &Value, topic: &str, summarize: bool) -> Option<String> {
        if !summarize {
            return None;
        }

        // Simple summary generation
        match data {
            Value::Object(map) => {
                let keys: Vec<&String> = map.keys().collect();
                let key_names: Vec<String> = keys.iter().map(|s| (*s).clone()).collect();
                Some(format!(
                    "Event '{}' with {} fields: {}",
                    topic,
                    key_names.len(),
                    key_names.join(", ")
                ))
            }
            Value::String(s) => Some(format!("Event '{}': {}", topic, s)),
            _ => Some(format!("Event '{}' emitted", topic)),
        }
    }

    pub fn emit(&self, opts: EventEmitOptions) -> Result<EventEmitResponse> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        // Validate inputs first
        if let Err(e) = Self::validate_topic(&opts.topic) {
            return Ok(EventEmitResponse {
                ok: false,
                timestamp_unix_ms: timestamp,
                event: None,
                error: Some(EventError {
                    code: "event.emit_invalid_topic".to_string(),
                    message: e.to_string(),
                }),
                warnings: vec![],
            });
        }

        if let Err(e) = Self::validate_tags(&opts.tags) {
            return Ok(EventEmitResponse {
                ok: false,
                timestamp_unix_ms: timestamp,
                event: None,
                error: Some(EventError {
                    code: "event.emit_invalid_topic".to_string(),
                    message: e.to_string(),
                }),
                warnings: vec![],
            });
        }

        let event_id = Self::generate_event_id();

        let mode_str = Self::mode_to_string(&opts.mode);
        let priority_str = Self::priority_to_string(&opts.priority);

        // Generate summary if requested
        let summary = Self::generate_summary_if_requested(&opts.data, &opts.topic, opts.summarize);

        // Create initial envelope
        let mut envelope = EventEnvelope {
            id: event_id,
            topic: opts.topic,
            timestamp_unix_ms: timestamp,
            mode: mode_str.clone(),
            mode_used: mode_str.clone(), // Will be updated if downgraded
            priority: priority_str,
            ttl_ms: opts.ttl_ms,
            key: opts.key,
            correlation_id: opts.correlation_id,
            causation_id: opts.causation_id,
            source: opts.source,
            tags: opts.tags,
            schema_version: opts.schema_version,
            data: opts.data,
            summary,
            backend: self.backend.name().to_string(),
            offset: None, // Will be set by backend
            raw: None,
        };

        let mut warnings = Vec::new();

        // Attempt to emit based on mode
        let emit_result = match opts.mode {
            EventEmitMode::FireAndForget => self.backend.emit_fire_and_forget(&envelope),
            EventEmitMode::WaitForPersist => {
                if self.backend.supports_persistence() {
                    self.backend.emit_wait_for_persist(&envelope)
                } else {
                    // Downgrade to fire-and-forget
                    envelope.mode_used = "fire_and_forget".to_string();
                    warnings.push(
                        "Backend does not support durable persist; mode downgraded to fire_and_forget.".to_string(),
                    );
                    self.backend.emit_fire_and_forget(&envelope)
                }
            }
        };

        match emit_result {
            Ok(()) => {
                let response = EventEmitResponse {
                    ok: true,
                    timestamp_unix_ms: timestamp,
                    event: Some(envelope.clone()),
                    error: None,
                    warnings,
                };

                // Execute emit hooks
                self.hook_manager.execute_emit_hooks(&envelope, &response);
                get_global_hook_manager().execute_emit_hooks(&envelope, &response);

                Ok(response)
            }
            Err(e) => {
                let error_code = if e.to_string().contains("unavailable") {
                    "event.emit_backend_unavailable"
                } else if e.to_string().contains("timeout") {
                    "event.emit_backend_timeout"
                } else if e.to_string().contains("rejected") {
                    "event.emit_backend_rejected"
                } else {
                    "event.emit_internal_error"
                };

                Ok(EventEmitResponse {
                    ok: false,
                    timestamp_unix_ms: timestamp,
                    event: None,
                    error: Some(EventError {
                        code: error_code.to_string(),
                        message: e.to_string(),
                    }),
                    warnings,
                })
            }
        }
    }

    pub fn subscribe(&self, opts: EventSubscribeOptions) -> Result<EventSubscribeResponse> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        // Handle manual commit if specified
        if let Some(ref manual_offset) = opts.manual_commit_offset {
            if opts.limit == 0 {
                // Commit-only operation
                if let Some(ref group_id) = opts.group_id {
                    if let Err(e) = self
                        .backend
                        .commit_offset(&opts.topic, group_id, manual_offset)
                    {
                        return Ok(EventSubscribeResponse {
                            ok: false,
                            timestamp_unix_ms: timestamp,
                            topic: opts.topic,
                            group_id: opts.group_id,
                            consumer_id: opts.consumer_id,
                            effective_offset: "commit".to_string(),
                            offset_start: None,
                            offset_end: None,
                            next_offset: None,
                            high_watermark: None,
                            timed_out: false,
                            events_returned: 0,
                            events: vec![],
                            committed_offset: None,
                            committed: false,
                            error: Some(EventError {
                                code: "event.subscribe_backend_error".to_string(),
                                message: e.to_string(),
                            }),
                            warnings: vec![],
                        });
                    }

                    return Ok(EventSubscribeResponse {
                        ok: true,
                        timestamp_unix_ms: timestamp,
                        topic: opts.topic,
                        group_id: opts.group_id,
                        consumer_id: opts.consumer_id,
                        effective_offset: "commit".to_string(),
                        offset_start: None,
                        offset_end: None,
                        next_offset: None,
                        high_watermark: None,
                        timed_out: false,
                        events_returned: 0,
                        events: vec![],
                        committed_offset: Some(manual_offset.clone()),
                        committed: true,
                        error: None,
                        warnings: vec![],
                    });
                }
            }
        }

        // Create filter
        let filters = EventFilter {
            match_tags: opts.match_tags.clone(),
            match_correlation_id: opts.match_correlation_id.clone(),
            match_source: opts.match_source.clone(),
            max_latency_ms: opts.max_latency_ms,
        };

        // Subscribe to events
        let batch_result = self.backend.subscribe(
            &opts.topic,
            &opts.offset,
            opts.limit,
            opts.group_id.as_deref(),
            opts.consumer_id.as_deref(),
            opts.wait,
            opts.wait_timeout_ms,
            &filters,
        );

        let batch = match batch_result {
            Ok(batch) => batch,
            Err(e) => {
                let error_code = if e.to_string().contains("requires group_id") {
                    "event.subscribe_offset_next_requires_group"
                } else if e.to_string().contains("unavailable") {
                    "event.subscribe_backend_unavailable"
                } else if e.to_string().contains("timeout") {
                    "event.subscribe_backend_timeout"
                } else {
                    "event.subscribe_backend_error"
                };

                return Ok(EventSubscribeResponse {
                    ok: false,
                    timestamp_unix_ms: timestamp,
                    topic: opts.topic,
                    group_id: opts.group_id,
                    consumer_id: opts.consumer_id,
                    effective_offset: format!("{:?}", opts.offset).to_lowercase(),
                    offset_start: None,
                    offset_end: None,
                    next_offset: None,
                    high_watermark: None,
                    timed_out: false,
                    events_returned: 0,
                    events: vec![],
                    committed_offset: None,
                    committed: false,
                    error: Some(EventError {
                        code: error_code.to_string(),
                        message: e.to_string(),
                    }),
                    warnings: vec![],
                });
            }
        };

        // Process events (filter data/summary based on include flags)
        let mut processed_events = batch.events;
        for event in &mut processed_events {
            if !opts.include_data {
                event.data = Value::Null;
            }
            if !opts.include_summary {
                event.summary = None;
            }
            if !opts.include_raw {
                event.raw = None;
            }
        }

        let events_returned = processed_events.len() as u32;
        let timed_out = opts.wait && events_returned == 0;

        // Handle auto-commit
        let mut committed_offset = None;
        let mut committed = false;
        let mut warnings = vec![];

        if opts.auto_commit && opts.group_id.is_some() && !processed_events.is_empty() {
            if let Some(ref next_offset) = batch.next_offset {
                let group_id = opts.group_id.as_ref().unwrap();
                match self
                    .backend
                    .commit_offset(&opts.topic, group_id, next_offset)
                {
                    Ok(()) => {
                        committed_offset = Some(next_offset.clone());
                        committed = true;
                    }
                    Err(e) => {
                        warnings.push(format!("Failed to commit offset: {}", e));
                    }
                }
            }
        }

        let response = EventSubscribeResponse {
            ok: true,
            timestamp_unix_ms: timestamp,
            topic: opts.topic.clone(),
            group_id: opts.group_id.clone(),
            consumer_id: opts.consumer_id.clone(),
            effective_offset: format!("{:?}", opts.offset).to_lowercase(),
            offset_start: batch.offset_start,
            offset_end: batch.offset_end,
            next_offset: batch.next_offset,
            high_watermark: batch.high_watermark,
            timed_out,
            events_returned,
            events: processed_events,
            committed_offset,
            committed,
            error: None,
            warnings,
        };

        // Execute subscribe hooks
        self.hook_manager.execute_subscribe_hooks(&opts, &response);
        get_global_hook_manager().execute_subscribe_hooks(&opts, &response);

        Ok(response)
    }

    fn format_response_as_json(&self, response: &EventEmitResponse) -> Result<String> {
        let mut json_response = json!({
            "ok": response.ok,
            "timestamp_unix_ms": response.timestamp_unix_ms,
            "warnings": response.warnings
        });

        if let Some(ref event) = response.event {
            json_response["event"] = json!({
                "id": event.id,
                "topic": event.topic,
                "timestamp_unix_ms": event.timestamp_unix_ms,
                "mode": event.mode,
                "mode_used": event.mode_used,
                "priority": event.priority,
                "ttl_ms": event.ttl_ms,
                "key": event.key,
                "correlation_id": event.correlation_id,
                "causation_id": event.causation_id,
                "source": event.source,
                "tags": event.tags,
                "schema_version": event.schema_version,
                "data": event.data,
                "summary": event.summary,
                "backend": event.backend
            });
            json_response["error"] = Value::Null;
        } else {
            json_response["event"] = Value::Null;
        }

        if let Some(ref error) = response.error {
            json_response["error"] = json!({
                "code": error.code,
                "message": error.message
            });
        } else {
            json_response["error"] = Value::Null;
        }

        Ok(serde_json::to_string_pretty(&json_response)?)
    }

    fn format_subscribe_response_as_json(
        &self,
        response: &EventSubscribeResponse,
    ) -> Result<String> {
        let mut json_response = json!({
            "ok": response.ok,
            "timestamp_unix_ms": response.timestamp_unix_ms,
            "topic": response.topic,
            "group_id": response.group_id,
            "consumer_id": response.consumer_id,
            "effective_offset": response.effective_offset,
            "offset_start": response.offset_start,
            "offset_end": response.offset_end,
            "next_offset": response.next_offset,
            "high_watermark": response.high_watermark,
            "timed_out": response.timed_out,
            "events_returned": response.events_returned,
            "events": response.events.iter().map(|event| {
                json!({
                    "id": event.id,
                    "topic": event.topic,
                    "timestamp_unix_ms": event.timestamp_unix_ms,
                    "mode": event.mode,
                    "mode_used": event.mode_used,
                    "priority": event.priority,
                    "ttl_ms": event.ttl_ms,
                    "key": event.key,
                    "correlation_id": event.correlation_id,
                    "causation_id": event.causation_id,
                    "source": event.source,
                    "tags": event.tags,
                    "schema_version": event.schema_version,
                    "data": event.data,
                    "summary": event.summary,
                    "backend": event.backend,
                    "offset": event.offset,
                    "raw": event.raw
                })
            }).collect::<Vec<_>>(),
            "committed_offset": response.committed_offset,
            "committed": response.committed,
            "warnings": response.warnings
        });

        if let Some(ref error) = response.error {
            json_response["error"] = json!({
                "code": error.code,
                "message": error.message
            });
        } else {
            json_response["error"] = Value::Null;
        }

        Ok(serde_json::to_string_pretty(&json_response)?)
    }

    fn format_subscribe_response_as_text(
        &self,
        response: &EventSubscribeResponse,
    ) -> Result<String> {
        let mut output = String::new();

        if response.ok {
            output.push_str("Event Subscription Result\n");
            output.push_str("=========================\n\n");
            output.push_str(&format!("Topic       : {}\n", response.topic));
            if let Some(ref group_id) = response.group_id {
                output.push_str(&format!("Group ID    : {}\n", group_id));
            }
            if let Some(ref consumer_id) = response.consumer_id {
                output.push_str(&format!("Consumer ID : {}\n", consumer_id));
            }
            output.push_str(&format!("Offset      : {}", response.effective_offset));
            if let Some(ref offset_start) = response.offset_start {
                output.push_str(&format!(" (resolved to {})", offset_start));
            }
            output.push_str(&format!(
                "\nReturned    : {} event(s)\n",
                response.events_returned
            ));
            output.push_str(&format!(
                "Timed Out   : {}\n\n",
                if response.timed_out { "yes" } else { "no" }
            ));

            if !response.events.is_empty() {
                output.push_str("Events:\n");
                for event in &response.events {
                    let offset_str = event
                        .offset
                        .as_ref()
                        .map(|o| format!("[{}] ", o))
                        .unwrap_or_default();
                    let datetime = chrono::DateTime::from_timestamp_millis(event.timestamp_unix_ms)
                        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                        .unwrap_or_else(|| "unknown".to_string());

                    output.push_str(&format!("  {}{} @ {}\n", offset_str, event.topic, datetime));
                    output.push_str(&format!("    ID        : {}\n", event.id));
                    if let Some(ref source) = event.source {
                        output.push_str(&format!("    Source    : {}\n", source));
                    }
                    output.push_str(&format!("    Priority  : {}\n", event.priority));
                    if !event.tags.is_empty() {
                        output.push_str(&format!("    Tags      : {}\n", event.tags.join(", ")));
                    }
                    if let Some(ref summary) = event.summary {
                        output.push_str(&format!("    Summary   : {}\n", summary));
                    }
                    output.push_str("\n");
                }
            } else if response.timed_out {
                let timeout = 30000; // Default timeout
                output.push_str(&format!(
                    "No events available within timeout ({} ms).\n",
                    timeout
                ));
            } else {
                output.push_str("No events available.\n");
            }
        } else if let Some(ref error) = response.error {
            output.push_str(&format!(
                "Subscription failed: [{}] {}\n",
                error.code, error.message
            ));
        }

        if !response.warnings.is_empty() {
            output.push_str("\nWarnings:\n");
            for warning in &response.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        } else if response.ok {
            output.push_str("Warnings:\n  (none)\n");
        }

        Ok(output)
    }

    fn format_response_as_text(&self, response: &EventEmitResponse) -> Result<String> {
        let mut output = String::new();

        if response.ok {
            if let Some(ref event) = response.event {
                output.push_str("Event Emitted\n");
                output.push_str("=============\n\n");
                output.push_str(&format!("ID        : {}\n", event.id));
                output.push_str(&format!("Topic     : {}\n", event.topic));
                output.push_str(&format!("Backend   : {}\n", event.backend));
                output.push_str(&format!(
                    "Mode      : {} (used: {})\n",
                    event.mode, event.mode_used
                ));
                output.push_str(&format!("Priority  : {}\n", event.priority));
                if let Some(ttl) = event.ttl_ms {
                    output.push_str(&format!("TTL (ms)  : {}\n", ttl));
                }
                if let Some(ref source) = event.source {
                    output.push_str(&format!("Source    : {}\n", source));
                }
                if !event.tags.is_empty() {
                    output.push_str(&format!("Tags      : {}\n", event.tags.join(", ")));
                }
                if let Some(ref correlation_id) = event.correlation_id {
                    output.push_str(&format!("Correlation ID : {}\n", correlation_id));
                }
                if let Some(ref summary) = event.summary {
                    output.push_str(&format!("\nSummary   : {}\n", summary));
                }

                output.push_str("\nData:\n");
                let data_json = serde_json::to_string_pretty(&event.data)?;
                for line in data_json.lines() {
                    output.push_str(&format!("  {}\n", line));
                }
            }
        } else if let Some(ref error) = response.error {
            output.push_str(&format!(
                "Event emission failed: [{}] {}\n",
                error.code, error.message
            ));
        }

        if !response.warnings.is_empty() {
            output.push_str("\nWarnings:\n");
            for warning in &response.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        } else if response.ok {
            output.push_str("\nWarnings:\n  (none)\n");
        }

        Ok(output)
    }

    fn handle_emit(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let opts = match Self::parse_emit_options(args) {
            Ok(opts) => opts,
            Err(e) => {
                let error_code = if e.to_string().contains("topic") {
                    "event.emit_invalid_topic"
                } else if e.to_string().contains("data") {
                    "event.emit_invalid_data"
                } else if e.to_string().contains("mode") {
                    "event.emit_invalid_mode"
                } else if e.to_string().contains("priority") {
                    "event.emit_invalid_priority"
                } else {
                    "event.emit_internal_error"
                };

                let error_response = EventEmitResponse {
                    ok: false,
                    timestamp_unix_ms: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as i64,
                    event: None,
                    error: Some(EventError {
                        code: error_code.to_string(),
                        message: e.to_string(),
                    }),
                    warnings: vec![],
                };

                let output = self.format_response_as_json(&error_response)?;
                write!(io.stdout, "{}", output)?;
                return Ok(Status::err(1, e.to_string()));
            }
        };

        let response = self.emit(opts.clone())?;

        let output = match opts.format {
            OutputFormat::Json => self.format_response_as_json(&response)?,
            OutputFormat::Text => self.format_response_as_text(&response)?,
        };

        write!(io.stdout, "{}", output)?;

        if response.ok {
            Ok(Status::ok())
        } else {
            Ok(Status::err(1, "event emission failed"))
        }
    }

    fn handle_subscribe(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let opts = match Self::parse_subscribe_options(args) {
            Ok(opts) => opts,
            Err(e) => {
                let error_str = e.to_string();
                let error_code = if error_str.contains("requires group_id") {
                    "event.subscribe_offset_next_requires_group"
                } else if error_str.contains("topic") {
                    "event.subscribe_invalid_topic"
                } else if error_str.contains("limit") {
                    "event.subscribe_invalid_limit"
                } else if error_str.contains("offset") {
                    "event.subscribe_invalid_offset"
                } else {
                    "event.subscribe_internal_error"
                };

                let error_response = EventSubscribeResponse {
                    ok: false,
                    timestamp_unix_ms: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as i64,
                    topic: args.get("topic").unwrap_or(&"unknown".to_string()).clone(),
                    group_id: args.get("group_id").cloned(),
                    consumer_id: args.get("consumer_id").cloned(),
                    effective_offset: "error".to_string(),
                    offset_start: None,
                    offset_end: None,
                    next_offset: None,
                    high_watermark: None,
                    timed_out: false,
                    events_returned: 0,
                    events: vec![],
                    committed_offset: None,
                    committed: false,
                    error: Some(EventError {
                        code: error_code.to_string(),
                        message: e.to_string(),
                    }),
                    warnings: vec![],
                };

                let output = self.format_subscribe_response_as_json(&error_response)?;
                write!(io.stdout, "{}", output)?;
                return Ok(Status::err(1, e.to_string()));
            }
        };

        let response = self.subscribe(opts.clone())?;

        let output = match opts.format {
            OutputFormat::Json => self.format_subscribe_response_as_json(&response)?,
            OutputFormat::Text => self.format_subscribe_response_as_text(&response)?,
        };

        write!(io.stdout, "{}", output)?;

        if response.ok {
            Ok(Status::ok())
        } else {
            Ok(Status::err(1, "event subscription failed"))
        }
    }

    fn handle_hooks_list(&self, _args: &Args, io: &mut IoStreams) -> Result<Status> {
        let hooks = self.list_hooks();
        let global_hooks = get_global_hook_manager().list_hooks();

        let response = json!({
            "instance_hooks": hooks,
            "global_hooks": global_hooks,
            "total": hooks.len() + global_hooks.len()
        });

        writeln!(io.stdout, "{}", response)?;
        Ok(Status::ok())
    }

    fn handle_hooks_enable(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let hook_name = args
            .get("name")
            .ok_or_else(|| anyhow::anyhow!("hook name is required"))?;

        let hook_manager = get_global_hook_manager();
        match hook_name.as_str() {
            "mq" => hook_manager.register_hook(Arc::new(MQHook)),
            "log" => hook_manager.register_hook(Arc::new(LogHook)),
            "proc" => hook_manager.register_hook(Arc::new(ProcHook)),
            "fs" => hook_manager.register_hook(Arc::new(FsWatchHook)),
            _ => {
                return Ok(Status::err(1, format!("Unknown hook: {}", hook_name)));
            }
        }

        let response = json!({
            "hook": hook_name,
            "enabled": true
        });

        writeln!(io.stdout, "{}", response)?;
        Ok(Status::ok())
    }

    fn parse_list_topics_options(args: &Args) -> Result<ListTopicsOptions> {
        // Parse prefix
        let prefix = args.get("prefix").cloned();

        // Parse match substring
        let match_substr = args.get("match").cloned();

        // Parse sources
        let sources = if let Some(sources_str) = args.get("sources") {
            if sources_str.starts_with('[') {
                // JSON array format
                serde_json::from_str(sources_str)
                    .map_err(|e| anyhow::anyhow!("invalid sources JSON: {}", e))?
            } else {
                // Comma-separated format
                sources_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect()
            }
        } else {
            vec![
                "event".to_string(),
                "mq".to_string(),
                "log".to_string(),
                "proc".to_string(),
                "fs_watch".to_string(),
            ]
        };

        // Validate sources
        for source in &sources {
            match source.as_str() {
                "event" | "mq" | "log" | "proc" | "fs_watch" => {}
                _ => bail!(
                    "invalid source '{}'; supported: event, mq, log, proc, fs_watch",
                    source
                ),
            }
        }

        // Parse limit
        let limit = if let Some(limit_str) = args.get("limit") {
            let limit: u32 = limit_str.parse().map_err(|_| {
                anyhow::anyhow!("invalid limit '{}'; must be a positive integer", limit_str)
            })?;
            if limit == 0 || limit > 10000 {
                bail!("invalid limit {}; must be between 1 and 10000", limit);
            }
            limit
        } else {
            1000
        };

        // Parse boolean flags
        let include_hidden = args
            .get("include_hidden")
            .map(|s| s == "true")
            .unwrap_or(false);
        let include_stats = args
            .get("include_stats")
            .map(|s| s == "true")
            .unwrap_or(false);
        let include_schema = args
            .get("include_schema")
            .map(|s| s == "true")
            .unwrap_or(false);
        let include_backends = args
            .get("include_backends")
            .map(|s| s == "true")
            .unwrap_or(true);
        let summarize = args.get("summarize").map(|s| s == "true").unwrap_or(true);

        // Parse format
        let format = if let Some(format_str) = args.get("format") {
            OutputFormat::from_str(format_str)?
        } else {
            OutputFormat::Json
        };

        Ok(ListTopicsOptions {
            prefix,
            match_substr,
            sources,
            limit,
            include_hidden,
            include_stats,
            include_schema,
            include_backends,
            summarize,
            format,
        })
    }

    fn list_topics(&self, opts: ListTopicsOptions) -> Result<ListTopicsResponse> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let mut all_topics: Vec<TopicInfo> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();

        // Create topic providers
        let providers: Vec<Box<dyn TopicProvider>> = vec![
            Box::new(EventBusTopicProvider::new()),
            Box::new(MqTopicProvider::new()),
            Box::new(LogTopicProvider::new()),
            Box::new(ProcTopicProvider::new()),
            Box::new(FsWatchTopicProvider::new()),
        ];

        // Collect topics from all requested sources
        for provider in providers {
            let source_type = provider.source_type();
            if !opts.sources.contains(&source_type.to_string()) {
                continue;
            }

            match provider.list_topics(opts.include_hidden, opts.include_stats, opts.include_schema)
            {
                Ok(provider_topics) => {
                    // Merge with existing topics (by name)
                    for new_topic in provider_topics {
                        if let Some(existing_topic) =
                            all_topics.iter_mut().find(|t| t.name == new_topic.name)
                        {
                            // Merge sources and backends
                            for source in &new_topic.sources {
                                if !existing_topic.sources.contains(source) {
                                    existing_topic.sources.push(source.clone());
                                }
                            }
                            for backend in &new_topic.backends {
                                if !existing_topic.backends.iter().any(|b| b.id == backend.id) {
                                    existing_topic.backends.push(backend.clone());
                                }
                            }

                            // Merge stats (keep most recent)
                            if new_topic.stats.is_some()
                                && (existing_topic.stats.is_none()
                                    || new_topic
                                        .stats
                                        .as_ref()
                                        .unwrap()
                                        .last_event_unix_ms
                                        .unwrap_or(0)
                                        > existing_topic
                                            .stats
                                            .as_ref()
                                            .unwrap()
                                            .last_event_unix_ms
                                            .unwrap_or(0))
                            {
                                existing_topic.stats = new_topic.stats;
                            }

                            // Merge schema (prefer existing, or take new if missing)
                            if existing_topic.schema.is_none() {
                                existing_topic.schema = new_topic.schema;
                            }

                            // Merge tags
                            for tag in &new_topic.tags {
                                if !existing_topic.tags.contains(tag) {
                                    existing_topic.tags.push(tag.clone());
                                }
                            }
                        } else {
                            all_topics.push(new_topic);
                        }
                    }
                }
                Err(e) => {
                    warnings.push(format!("{} backend unavailable: {}", source_type, e));
                }
            }
        }

        // Apply filters
        let mut filtered_topics = all_topics;

        // Filter by prefix
        if let Some(prefix) = &opts.prefix {
            filtered_topics.retain(|t| t.name.starts_with(prefix));
        }

        // Filter by match substring
        if let Some(match_str) = &opts.match_substr {
            let match_lower = match_str.to_lowercase();
            filtered_topics.retain(|t| t.name.to_lowercase().contains(&match_lower));
        }

        // Filter hidden topics
        if !opts.include_hidden {
            filtered_topics.retain(|t| !t.is_hidden);
        }

        // Sort by name (could add more sort options later)
        filtered_topics.sort_by(|a, b| a.name.cmp(&b.name));

        // Apply limit and check truncation
        let topics_total = filtered_topics.len() as u32;
        let truncated = topics_total > opts.limit;
        if truncated {
            filtered_topics.truncate(opts.limit as usize);
            warnings.push(format!(
                "Result truncated to limit={}; refine filters or increase limit.",
                opts.limit
            ));
        }
        let topics_returned = filtered_topics.len() as u32;

        // Check for complete failure
        let ok = if topics_returned == 0 && topics_total == 0 && !warnings.is_empty() {
            // If we have no topics and warnings, it might be complete backend failure
            let all_backends_failed = opts
                .sources
                .iter()
                .all(|source| warnings.iter().any(|w| w.contains(source)));
            !all_backends_failed
        } else {
            true
        };

        let error = if !ok {
            Some(EventError {
                code: "event.list_topics_backend_unavailable".to_string(),
                message: "All requested topic backends are unavailable".to_string(),
            })
        } else {
            None
        };

        let filters = json!({
            "prefix": opts.prefix,
            "match": opts.match_substr,
            "sources": opts.sources,
            "limit": opts.limit,
            "include_hidden": opts.include_hidden,
            "include_stats": opts.include_stats,
            "include_schema": opts.include_schema
        });

        Ok(ListTopicsResponse {
            ok,
            timestamp_unix_ms: timestamp,
            filters,
            topics_total,
            topics_returned,
            truncated,
            topics: filtered_topics,
            error,
            warnings,
        })
    }

    fn format_list_topics_response_as_json(&self, response: &ListTopicsResponse) -> Result<String> {
        serde_json::to_string_pretty(response)
            .map_err(|e| anyhow::anyhow!("failed to format list-topics response as JSON: {}", e))
    }

    fn format_list_topics_response_as_text(&self, response: &ListTopicsResponse) -> Result<String> {
        let mut output = String::new();

        output.push_str("Event Topics\n");
        output.push_str("============\n\n");

        output.push_str("Filters:\n");
        if let Some(prefix) = response.filters.get("prefix").and_then(|v| v.as_str()) {
            output.push_str(&format!("  Prefix         : {}\n", prefix));
        } else {
            output.push_str("  Prefix         : (none)\n");
        }

        if let Some(match_str) = response.filters.get("match").and_then(|v| v.as_str()) {
            output.push_str(&format!("  Match          : {}\n", match_str));
        } else {
            output.push_str("  Match          : (none)\n");
        }

        if let Some(sources) = response.filters.get("sources").and_then(|v| v.as_array()) {
            let source_strs: Vec<String> = sources
                .iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect();
            output.push_str(&format!("  Sources        : {}\n", source_strs.join(", ")));
        }

        let include_stats = response
            .filters
            .get("include_stats")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let include_schema = response
            .filters
            .get("include_schema")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        output.push_str(&format!(
            "  Include Stats  : {}\n",
            if include_stats { "yes" } else { "no" }
        ));
        output.push_str(&format!(
            "  Include Schema : {}\n",
            if include_schema { "yes" } else { "no" }
        ));

        output.push_str(&format!("\nTopics ({} total):\n\n", response.topics_total));

        for (i, topic) in response.topics.iter().enumerate() {
            output.push_str(&format!("{}) {}\n", i + 1, topic.name));

            if let Some(description) = &topic.description {
                output.push_str(&format!("   Description : {}\n", description));
            }

            if let Some(category) = &topic.category {
                output.push_str(&format!("   Category    : {}\n", category));
            }

            output.push_str(&format!("   Sources     : {}\n", topic.sources.join(", ")));

            if !topic.backends.is_empty() {
                output.push_str("   Backends    :\n");
                for backend in &topic.backends {
                    output.push_str(&format!("     - {}\n", backend.id));
                }
            }

            if let Some(stats) = &topic.stats {
                if let Some(last_event) = stats.last_event_unix_ms {
                    let datetime = chrono::DateTime::from_timestamp_millis(last_event)
                        .unwrap_or_else(chrono::Utc::now);
                    output.push_str(&format!(
                        "   Last Event  : {}\n",
                        datetime.format("%Y-%m-%dT%H:%M:%SZ")
                    ));
                }
                if let Some(count) = stats.approx_message_count {
                    output.push_str(&format!("   Approx Count: {}\n", count));
                }
            }

            if !topic.tags.is_empty() {
                output.push_str(&format!("   Tags        : {}\n", topic.tags.join(", ")));
            }

            if let Some(schema) = &topic.schema {
                if let Some(example) = &schema.example {
                    output.push_str("\n   Example Payload:\n");
                    let example_str = serde_json::to_string_pretty(example)
                        .unwrap_or_else(|_| "<invalid JSON>".to_string());
                    for line in example_str.lines() {
                        output.push_str(&format!("     {}\n", line));
                    }
                }
            }

            output.push_str("\n");
        }

        if response.truncated {
            output.push_str(&format!("Note: results truncated to limit={}. Refine filters or increase limit to see more.\n\n", response.filters.get("limit").and_then(|v| v.as_u64()).unwrap_or(1000)));
        }

        if !response.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &response.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        } else {
            output.push_str("Warnings:\n  (none)\n");
        }

        if let Some(error) = &response.error {
            output.push_str(&format!("\nError: [{}] {}\n", error.code, error.message));
        }

        Ok(output)
    }

    fn handle_list_topics(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let opts = match Self::parse_list_topics_options(args) {
            Ok(opts) => opts,
            Err(e) => {
                let error_code = if e.to_string().contains("invalid limit") {
                    "event.list_topics_invalid_limit"
                } else if e.to_string().contains("invalid source") {
                    "event.list_topics_invalid_source"
                } else if e.to_string().contains("invalid") {
                    "event.list_topics_invalid_input"
                } else {
                    "event.list_topics_parse_error"
                };

                let error_response = ListTopicsResponse {
                    ok: false,
                    timestamp_unix_ms: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as i64,
                    filters: json!({}),
                    topics_total: 0,
                    topics_returned: 0,
                    truncated: false,
                    topics: vec![],
                    error: Some(EventError {
                        code: error_code.to_string(),
                        message: e.to_string(),
                    }),
                    warnings: vec![],
                };

                let output = self.format_list_topics_response_as_json(&error_response)?;
                write!(io.stdout, "{}", output)?;
                return Ok(Status::err(1, e.to_string()));
            }
        };

        let response = self.list_topics(opts.clone())?;

        let output = match opts.format {
            OutputFormat::Json => self.format_list_topics_response_as_json(&response)?,
            OutputFormat::Text => self.format_list_topics_response_as_text(&response)?,
        };

        write!(io.stdout, "{}", output)?;

        if response.ok {
            Ok(Status::ok())
        } else {
            Ok(Status::err(1, "topic listing failed"))
        }
    }

    fn handle_hooks_disable(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let hook_name = args
            .get("name")
            .ok_or_else(|| anyhow::anyhow!("hook name is required"))?;

        get_global_hook_manager().remove_hook(hook_name);

        let response = json!({
            "hook": hook_name,
            "disabled": true
        });

        writeln!(io.stdout, "{}", response)?;
        Ok(Status::ok())
    }
}

impl Handle for EventHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &[
            "emit",
            "subscribe",
            "list-topics",
            "hooks.list",
            "hooks.enable",
            "hooks.disable",
            "help",
            "--help",
            "-h",
        ]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&EVENT_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check for help requests first
        if let Some(status) = self.check_and_display_help(verb, args, io)? {
            return Ok(status);
        }

        match verb {
            "emit" => self.handle_emit(args, io),
            "subscribe" => self.handle_subscribe(args, io),
            "list-topics" => self.handle_list_topics(args, io),
            "hooks.list" => self.handle_hooks_list(args, io),
            "hooks.enable" => self.handle_hooks_enable(args, io),
            "hooks.disable" => self.handle_hooks_disable(args, io),
            _ => Ok(Status::err(
                1,
                format!("unknown verb '{}' for event handle", verb),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_topic() {
        assert!(EventHandle::validate_topic("system.fs.resized").is_ok());
        assert!(EventHandle::validate_topic("jobs.backup.completed").is_ok());
        assert!(EventHandle::validate_topic("a").is_ok());
        assert!(EventHandle::validate_topic("test-event_123:456").is_ok());

        assert!(EventHandle::validate_topic("").is_err());
        assert!(EventHandle::validate_topic("   ").is_err());
        assert!(EventHandle::validate_topic("invalid@topic").is_err());
        assert!(EventHandle::validate_topic(&"x".repeat(257)).is_err());
    }

    #[test]
    fn test_validate_tags() {
        assert!(EventHandle::validate_tags(&["tag1".to_string(), "tag2".to_string()]).is_ok());
        assert!(EventHandle::validate_tags(&[]).is_ok());

        assert!(EventHandle::validate_tags(&["".to_string()]).is_err());
        assert!(EventHandle::validate_tags(&["x".repeat(65)]).is_err());
        assert!(EventHandle::validate_tags(&["\x00".to_string()]).is_err());
    }

    #[test]
    fn test_mode_priority_conversion() {
        assert_eq!(
            EventEmitMode::from_str("fire_and_forget").unwrap(),
            EventEmitMode::FireAndForget
        );
        assert_eq!(
            EventEmitMode::from_str("wait_for_persist").unwrap(),
            EventEmitMode::WaitForPersist
        );
        assert!(EventEmitMode::from_str("invalid").is_err());

        assert_eq!(EventPriority::from_str("low").unwrap(), EventPriority::Low);
        assert_eq!(
            EventPriority::from_str("normal").unwrap(),
            EventPriority::Normal
        );
        assert_eq!(
            EventPriority::from_str("high").unwrap(),
            EventPriority::High
        );
        assert!(EventPriority::from_str("invalid").is_err());
    }

    #[test]
    fn test_generate_event_id() {
        let id1 = EventHandle::generate_event_id();
        let id2 = EventHandle::generate_event_id();

        assert!(id1.starts_with("evt_"));
        assert!(id2.starts_with("evt_"));
        assert_ne!(id1, id2); // Should be unique
        assert!(id1.len() > 20); // Should have timestamp + UUID
    }

    #[test]
    fn test_generate_summary() {
        let data = json!({"status": "success", "duration": 5230});
        let summary = EventHandle::generate_summary_if_requested(&data, "test.topic", true);
        assert!(summary.is_some());
        assert!(summary.unwrap().contains("test.topic"));

        let no_summary = EventHandle::generate_summary_if_requested(&data, "test.topic", false);
        assert!(no_summary.is_none());
    }

    fn file_handle(dir: &Path) -> EventHandle {
        EventHandle::new(Box::new(FileEventBackend::new(
            dir.join("resh").join("events"),
        )))
    }

    fn args(pairs: &[(&str, &str)]) -> Args {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn emit(h: &EventHandle, topic: &str, data: &str) -> EventEmitResponse {
        let opts =
            EventHandle::parse_emit_options(&args(&[("topic", topic), ("data", data)])).unwrap();
        h.emit(opts).unwrap()
    }

    fn subscribe(h: &EventHandle, pairs: &[(&str, &str)]) -> EventSubscribeResponse {
        h.subscribe(EventHandle::parse_subscribe_options(&args(pairs)).unwrap())
            .unwrap()
    }

    #[test]
    fn file_store_persists_across_handles() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = file_handle(dir.path());
        assert!(emit(&a, "jobs.backup.completed", r#"{"status":"success"}"#).ok);
        assert!(emit(&a, "jobs.backup.failed", r#"{"status":"error"}"#).ok);
        assert!(emit(&a, "other.topic", "1").ok);

        // A separate handle (as in a later resh invocation) sees the events.
        let b = file_handle(dir.path());
        let r = subscribe(
            &b,
            &[("topic", "jobs.backup.completed"), ("offset", "earliest")],
        );
        assert!(r.ok);
        assert_eq!(r.events_returned, 1);
        assert_eq!(r.events[0].data, json!({"status": "success"}));
        assert_eq!(r.events[0].backend, "state_file");

        let r = subscribe(&b, &[("topic", "jobs.*"), ("offset", "earliest")]);
        assert_eq!(r.events_returned, 2);
        assert_eq!(r.high_watermark.as_deref(), Some("2"));

        // Default offset=latest returns only new events.
        let r = subscribe(&b, &[("topic", "jobs.*")]);
        assert_eq!(r.events_returned, 0);

        // limit and explicit offsets, including one past the end.
        let r = subscribe(&b, &[("topic", "jobs.*"), ("offset", "1"), ("limit", "5")]);
        assert_eq!(r.events_returned, 1);
        assert_eq!(r.events[0].topic, "jobs.backup.failed");
        let r = subscribe(&b, &[("topic", "jobs.*"), ("offset", "99")]);
        assert!(r.ok);
        assert_eq!(r.events_returned, 0);
    }

    #[test]
    fn file_store_consumer_group_offsets_persist() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = file_handle(dir.path());
        for n in 0..3 {
            emit(&a, "q.work", &n.to_string());
        }
        let sub = [
            ("topic", "q.work"),
            ("offset", "next"),
            ("group_id", "g1"),
            ("limit", "2"),
        ];
        let r = subscribe(&file_handle(dir.path()), &sub);
        assert_eq!(
            r.events.iter().map(|e| e.data.clone()).collect::<Vec<_>>(),
            [json!(0), json!(1)]
        );
        assert!(r.committed);
        let r = subscribe(&file_handle(dir.path()), &sub);
        assert_eq!(
            r.events.iter().map(|e| e.data.clone()).collect::<Vec<_>>(),
            [json!(2)]
        );
        let r = subscribe(&file_handle(dir.path()), &sub);
        assert_eq!(r.events_returned, 0);
    }

    #[test]
    fn file_store_wait_times_out_without_events() {
        let dir = tempfile::TempDir::new().unwrap();
        let h = file_handle(dir.path());
        let start = std::time::Instant::now();
        let r = subscribe(
            &h,
            &[
                ("topic", "none"),
                ("wait", "true"),
                ("wait_timeout_ms", "250"),
            ],
        );
        assert!(r.timed_out);
        assert!(start.elapsed() >= Duration::from_millis(250));
    }

    #[test]
    fn file_store_permissions_and_layout() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let h = file_handle(dir.path());
        emit(&h, "perm.check", "{}");
        let base = dir.path().join("resh").join("events");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&base), 0o700);
        assert_eq!(mode(&base.join("perm.check.jsonl")), 0o600);
        let line = std::fs::read_to_string(base.join("perm.check.jsonl")).unwrap();
        assert_eq!(line.lines().count(), 1);
        let evt: EventEnvelope = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(evt.topic, "perm.check");

        subscribe(
            &h,
            &[
                ("topic", "perm.check"),
                ("offset", "earliest"),
                ("group_id", "g"),
            ],
        );
        assert_eq!(mode(&base.join("_offsets.json")), 0o600);
    }

    #[test]
    fn file_store_rejects_wildcard_emit_topic() {
        let dir = tempfile::TempDir::new().unwrap();
        let r = emit(&file_handle(dir.path()), "jobs.*", "{}");
        assert!(!r.ok);
        assert!(r.error.unwrap().message.contains("wildcards"));
    }

    #[test]
    fn in_memory_bus_is_shared_within_process() {
        let a = EventHandle::new(Box::new(InMemoryEventBackend::shared()));
        let b = EventHandle::new(Box::new(InMemoryEventBackend::shared()));
        let topic = format!("shared.test{}", std::process::id());
        emit(&a, &topic, "42");
        let r = subscribe(&b, &[("topic", &topic), ("offset", "earliest")]);
        assert_eq!(r.events_returned, 1);
    }

    #[test]
    fn topic_patterns() {
        assert!(topic_matches_pattern("jobs.backup", "jobs.*"));
        assert!(topic_matches_pattern("jobs.a", "jobs.?"));
        assert!(!topic_matches_pattern("jobsXbackup", "jobs.backup"));
        assert!(!topic_matches_pattern("jobsxa", "jobs.?"));
    }

    #[test]
    fn legacy_help_renders_approved_help() {
        let h = EventHandle::new(Box::new(InMemoryEventBackend::new()));
        let run = |verb: &str, a: Args| {
            let (mut i, mut o, mut e) = (
                std::io::Cursor::new(Vec::new()),
                std::io::Cursor::new(Vec::new()),
                std::io::Cursor::new(Vec::new()),
            );
            let mut io = IoStreams {
                stdin: &mut i,
                stdout: &mut o,
                stderr: &mut e,
            };
            h.call(verb, &a, &mut io).unwrap();
            String::from_utf8(o.into_inner()).unwrap()
        };
        assert!(run("--help", Args::new()).starts_with("Handle: event"));
        assert!(run("help", args(&[("verb", "subscribe")])).contains("Verb: subscribe"));
        assert!(run("--help=emit", Args::new()).contains("Verb: emit"));
    }
}
