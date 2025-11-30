use anyhow::{bail, Context, Result};
use chrono;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use url::Url;
use uuid::Uuid;

use crate::core::{
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
    fn on_subscribe(&self, request: &EventSubscribeOptions, response: &EventSubscribeResponse) -> Result<()>;
    
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
    pub fn execute_subscribe_hooks(&self, request: &EventSubscribeOptions, response: &EventSubscribeResponse) {
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
            if let Some(mq_topic) = event.tags.iter().find(|tag| tag.starts_with("mq:")).map(|tag| &tag[3..]) {
                println!("MQ Hook: Would forward event {} to MQ topic: {}", event.id, mq_topic);
            }
        }
        Ok(())
    }
    
    fn on_subscribe(&self, _request: &EventSubscribeOptions, response: &EventSubscribeResponse) -> Result<()> {
        // Could pull events from MQ and inject into event stream
        println!("MQ hook processed subscription with {} events", response.events_returned);
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
            if let Some(log_path) = event.tags.iter().find(|tag| tag.starts_with("log:")).map(|tag| &tag[4..]) {
                println!("Log Hook: Event {}: {} -> {}", event.id, event.topic, log_path);
            }
        }
        Ok(())
    }
    
    fn on_subscribe(&self, request: &EventSubscribeOptions, response: &EventSubscribeResponse) -> Result<()> {
        // Could tail log files and generate events
        println!("Log hook: subscription to {} returned {} events", 
                   request.topic, response.events_returned);
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
            if let Some(proc_action) = event.tags.iter().find(|tag| tag.starts_with("proc:")).map(|tag| &tag[5..]) {
                println!("Process Hook: Action requested: {} for event {}", proc_action, event.id);
            }
        }
        Ok(())
    }
    
    fn on_subscribe(&self, request: &EventSubscribeOptions, _response: &EventSubscribeResponse) -> Result<()> {
        // Monitor process state changes and generate events
        if request.topic.starts_with("proc.") {
            println!("Process monitoring subscription: {}", request.topic);
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
            if let Some(fs_path) = event.tags.iter().find(|tag| tag.starts_with("fs:")).map(|tag| &tag[3..]) {
                println!("FS Hook: Filesystem event for path: {}", fs_path);
            }
        }
        Ok(())
    }
    
    fn on_subscribe(&self, request: &EventSubscribeOptions, _response: &EventSubscribeResponse) -> Result<()> {
        // Set up filesystem watchers for event generation
        if request.topic.starts_with("fs.") {
            println!("Filesystem watch subscription: {}", request.topic);
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

    fn commit_offset(
        &self,
        topic_pattern: &str,
        group_id: &str,
        offset: &str,
    ) -> Result<()>;
}

// ===========================================================================
// In-Memory Event Backend
// ===========================================================================

#[derive(Debug)]
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

    #[allow(dead_code)]
    pub fn get_events(&self) -> Vec<EventEnvelope> {
        self.events.lock().unwrap().clone()
    }

    #[allow(dead_code)]
    pub fn clear_events(&self) {
        self.events.lock().unwrap().clear();
    }

    fn topic_matches_pattern(&self, topic: &str, pattern: &str) -> bool {
        if pattern == topic {
            return true;
        }
        
        // Simple wildcard matching
        if pattern.contains('*') {
            let pattern_regex = pattern.replace(".", "\\.").replace("*", ".*");
            if let Ok(regex) = Regex::new(&format!("^{}$", pattern_regex)) {
                return regex.is_match(topic);
            }
        }
        
        false
    }

    fn apply_filters(&self, events: &[EventEnvelope], filters: &EventFilter, now_ms: i64) -> Vec<EventEnvelope> {
        events.iter().filter(|evt| {
            // Filter by tags
            if !filters.match_tags.is_empty() {
                if !filters.match_tags.iter().all(|tag| evt.tags.contains(tag)) {
                    return false;
                }
            }

            // Filter by correlation_id
            if let Some(ref filter_corr_id) = filters.match_correlation_id {
                if evt.correlation_id.as_ref() != Some(filter_corr_id) {
                    return false;
                }
            }

            // Filter by source
            if let Some(ref filter_source) = filters.match_source {
                if evt.source.as_ref() != Some(filter_source) {
                    return false;
                }
            }

            // Filter by max latency
            if let Some(max_latency_ms) = filters.max_latency_ms {
                if evt.timestamp_unix_ms < now_ms - (max_latency_ms as i64) {
                    return false;
                }
            }

            true
        }).cloned().collect()
    }
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
        use std::time::{SystemTime, UNIX_EPOCH, Duration};

        let events = self.events.lock()
            .map_err(|_| anyhow::anyhow!("failed to acquire events lock"))?;
        
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        // Filter events by topic pattern
        let matching_events: Vec<&EventEnvelope> = events.iter()
            .filter(|evt| self.topic_matches_pattern(&evt.topic, topic_pattern))
            .collect();

        // Determine start index based on offset
        let start_index = match offset {
            EventOffset::Latest => matching_events.len(),
            EventOffset::Earliest => 0,
            EventOffset::Next => {
                if let Some(group_id) = group_id {
                    let offsets = self.consumer_offsets.lock()
                        .map_err(|_| anyhow::anyhow!("failed to acquire offsets lock"))?;
                    let key = format!("{}:{}", group_id, topic_pattern);
                    offsets.get(&key).cloned().unwrap_or(0)
                } else {
                    return Err(anyhow::anyhow!("offset='next' requires group_id"));
                }
            },
            EventOffset::Explicit(offset_str) => {
                offset_str.parse::<usize>()
                    .map_err(|_| anyhow::anyhow!("invalid numeric offset: {}", offset_str))?
            },
        };

        // If waiting and no events available, simulate wait
        if wait && start_index >= matching_events.len() {
            let timeout = wait_timeout_ms.unwrap_or(30000);
            if timeout > 0 {
                std::thread::sleep(Duration::from_millis(std::cmp::min(timeout, 100))); // Short sleep for demo
            }
        }

        // Get events from start_index
        let end_index = std::cmp::min(start_index + limit as usize, matching_events.len());
        let selected_events: Vec<EventEnvelope> = matching_events[start_index..end_index]
            .iter().map(|&e| e.clone()).collect();

        // Apply filters
        let filtered_events = self.apply_filters(&selected_events, filters, now_ms);

        // Calculate offsets
        let offset_start = if filtered_events.is_empty() { None } else { Some(start_index.to_string()) };
        let offset_end = if filtered_events.is_empty() { None } else { Some((end_index - 1).to_string()) };
        let next_offset = Some(end_index.to_string());
        let high_watermark = Some(matching_events.len().to_string());

        Ok(EventBatch {
            events: filtered_events,
            offset_start,
            offset_end,
            next_offset,
            high_watermark,
        })
    }

    fn commit_offset(
        &self,
        topic_pattern: &str,
        group_id: &str,
        offset: &str,
    ) -> Result<()> {
        let mut offsets = self.consumer_offsets.lock()
            .map_err(|_| anyhow::anyhow!("failed to acquire offsets lock"))?;
        
        let offset_num = offset.parse::<usize>()
            .map_err(|_| anyhow::anyhow!("invalid offset for commit: {}", offset))?;
        
        let key = format!("{}:{}", group_id, topic_pattern);
        offsets.insert(key, offset_num);
        
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
    pub sources: Vec<String>,      // "event" | "mq" | "log" | "proc" | "fs_watch"
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
    pub r#type: String,        // "event" | "mq" | "log" | "proc" | "fs_watch"
    pub handle: String,        // e.g. "event", "mq", "log"
    pub id: String,            // backend-specific identifier
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

    pub filters: Value,  // echo of applied filters
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
        let mut topics = vec![
            TopicInfo {
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
            }
        ];

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
                tags: vec!["process".to_string(), "cpu".to_string(), "performance".to_string()],
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

    pub fn from_url(_url: &Url) -> Result<Self> {
        // For now, always use in-memory backend
        let backend = Box::new(InMemoryEventBackend::new());
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
    
    /// List all registered hooks
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
                let limit_val = s.parse::<u32>()
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
            },
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
                    if let Err(e) = self.backend.commit_offset(&opts.topic, group_id, manual_offset) {
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
                match self.backend.commit_offset(&opts.topic, group_id, next_offset) {
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

    fn format_subscribe_response_as_json(&self, response: &EventSubscribeResponse) -> Result<String> {
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

    fn format_subscribe_response_as_text(&self, response: &EventSubscribeResponse) -> Result<String> {
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
            output.push_str(&format!("\nReturned    : {} event(s)\n", response.events_returned));
            output.push_str(&format!("Timed Out   : {}\n\n", if response.timed_out { "yes" } else { "no" }));

            if !response.events.is_empty() {
                output.push_str("Events:\n");
                for event in &response.events {
                    let offset_str = event.offset.as_ref().map(|o| format!("[{}] ", o)).unwrap_or_default();
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
                output.push_str(&format!("No events available within timeout ({} ms).\n", timeout));
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
        let hook_name = args.get("name")
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
                sources_str.split(',').map(|s| s.trim().to_string()).collect()
            }
        } else {
            vec!["event".to_string(), "mq".to_string(), "log".to_string(), "proc".to_string(), "fs_watch".to_string()]
        };
        
        // Validate sources
        for source in &sources {
            match source.as_str() {
                "event" | "mq" | "log" | "proc" | "fs_watch" => {},
                _ => bail!("invalid source '{}'; supported: event, mq, log, proc, fs_watch", source),
            }
        }
        
        // Parse limit
        let limit = if let Some(limit_str) = args.get("limit") {
            let limit: u32 = limit_str.parse()
                .map_err(|_| anyhow::anyhow!("invalid limit '{}'; must be a positive integer", limit_str))?;
            if limit == 0 || limit > 10000 {
                bail!("invalid limit {}; must be between 1 and 10000", limit);
            }
            limit
        } else {
            1000
        };
        
        // Parse boolean flags
        let include_hidden = args.get("include_hidden").map(|s| s == "true").unwrap_or(false);
        let include_stats = args.get("include_stats").map(|s| s == "true").unwrap_or(false);
        let include_schema = args.get("include_schema").map(|s| s == "true").unwrap_or(false);
        let include_backends = args.get("include_backends").map(|s| s == "true").unwrap_or(true);
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
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
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
            
            match provider.list_topics(opts.include_hidden, opts.include_stats, opts.include_schema) {
                Ok(provider_topics) => {
                    // Merge with existing topics (by name)
                    for new_topic in provider_topics {
                        if let Some(existing_topic) = all_topics.iter_mut().find(|t| t.name == new_topic.name) {
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
                            if new_topic.stats.is_some() && (
                                existing_topic.stats.is_none() ||
                                new_topic.stats.as_ref().unwrap().last_event_unix_ms.unwrap_or(0) >
                                existing_topic.stats.as_ref().unwrap().last_event_unix_ms.unwrap_or(0)
                            ) {
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
            warnings.push(format!("Result truncated to limit={}; refine filters or increase limit.", opts.limit));
        }
        let topics_returned = filtered_topics.len() as u32;
        
        // Check for complete failure
        let ok = if topics_returned == 0 && topics_total == 0 && !warnings.is_empty() {
            // If we have no topics and warnings, it might be complete backend failure
            let all_backends_failed = opts.sources.iter().all(|source| {
                warnings.iter().any(|w| w.contains(source))
            });
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
            let source_strs: Vec<String> = sources.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect();
            output.push_str(&format!("  Sources        : {}\n", source_strs.join(", ")));
        }
        
        let include_stats = response.filters.get("include_stats").and_then(|v| v.as_bool()).unwrap_or(false);
        let include_schema = response.filters.get("include_schema").and_then(|v| v.as_bool()).unwrap_or(false);
        output.push_str(&format!("  Include Stats  : {}\n", if include_stats { "yes" } else { "no" }));
        output.push_str(&format!("  Include Schema : {}\n", if include_schema { "yes" } else { "no" }));
        
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
                    output.push_str(&format!("   Last Event  : {}\n", datetime.format("%Y-%m-%dT%H:%M:%SZ")));
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
                    let example_str = serde_json::to_string_pretty(example).unwrap_or_else(|_| "<invalid JSON>".to_string());
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
                    timestamp_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64,
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
        let hook_name = args.get("name")
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
        &["emit", "subscribe", "list-topics", "hooks.list", "hooks.enable", "hooks.disable"]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
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
}
