# Event Handle Documentation

The event handle provides a messaging system for publishing and subscribing to events in Resource Shell. It supports fire-and-forget messaging, wait-for-persist modes, and various filtering options.

## Overview

The event handle lets you:
- Publish events with rich metadata 
- Subscribe to event streams with filters
- List available event topics
- Manage event processing hooks

## Available Verbs

### emit

Publishes an event to a topic.

**Required Parameters:**
- `topic`: The event topic name
- `data`: JSON payload data

**Optional Parameters:**
- `mode`: Delivery mode (`fire_and_forget` or `wait_for_persist`, default: `fire_and_forget`)
- `priority`: Event priority (`low`, `normal`, or `high`, default: `normal`)
- `ttl_ms`: Time to live in milliseconds
- `key`: Partition key for ordering
- `correlation_id`: ID to correlate related events
- `causation_id`: ID of the event that caused this one
- `source`: Source component that emitted the event
- `tags`: JSON array of tags for categorization
- `summarize`: Generate human-readable summary (`true` or `false`, default: `false`)
- `schema_version`: Schema version identifier
- `format`: Output format (`json` or `text`, default: `json`)

**Examples:**

Basic fire-and-forget event:
```bash
event://emit topic="system.fs.resized" data='{"mount": "/data", "old_size_gb": 100, "new_size_gb": 200}' mode="fire_and_forget" format="json"
```

Expected output:
```json
{
  "ok": true,
  "timestamp_unix_ms": 1732538400000,
  "event": {
    "id": "evt_1732538400000_abcd1234efgh",
    "topic": "system.fs.resized",
    "timestamp_unix_ms": 1732538400000,
    "mode": "fire_and_forget",
    "mode_used": "fire_and_forget",
    "priority": "normal",
    "ttl_ms": null,
    "key": null,
    "correlation_id": null,
    "causation_id": null,
    "source": null,
    "tags": [],
    "schema_version": null,
    "data": {
      "mount": "/data",
      "old_size_gb": 100,
      "new_size_gb": 200
    },
    "summary": null,
    "backend": "in_memory_bus"
  },
  "error": null,
  "warnings": []
}
```

Wait-for-persist mode (downgrades to fire-and-forget with warning):
```bash
event://emit topic="jobs.backup.completed" data='{"status": "success"}' mode="wait_for_persist" format="json"
```

Expected output:
```json
{
  "ok": true,
  "timestamp_unix_ms": 1732538400000,
  "event": {
    "id": "evt_1732538400000_abcd1234efgh",
    "topic": "jobs.backup.completed",
    "timestamp_unix_ms": 1732538400000,
    "mode": "wait_for_persist",
    "mode_used": "fire_and_forget",
    "priority": "normal",
    "ttl_ms": null,
    "key": null,
    "correlation_id": null,
    "causation_id": null,
    "source": null,
    "tags": [],
    "schema_version": null,
    "data": {
      "status": "success"
    },
    "summary": null,
    "backend": "in_memory_bus"
  },
  "error": null,
  "warnings": [
    "Backend does not support durable persist; mode downgraded to fire_and_forget."
  ]
}
```

Event with all metadata fields:
```bash
event://emit topic="jobs.backup.completed" data='{"job_id": "backup-2025-11-25T10:00Z", "status": "success", "duration_ms": 5230}' correlation_id="backup-2025-11-25T10:00Z" key="backup-2025" tags='["backup", "cron", "nightly"]' mode="wait_for_persist" priority="high" ttl_ms="600000" source="cron.handle" summarize="true" schema_version="v1" format="json"
```

Expected output:
```json
{
  "ok": true,
  "timestamp_unix_ms": 1732538400000,
  "event": {
    "id": "evt_1732538400000_abcd1234efgh",
    "topic": "jobs.backup.completed",
    "timestamp_unix_ms": 1732538400000,
    "mode": "wait_for_persist",
    "mode_used": "fire_and_forget",
    "priority": "high",
    "ttl_ms": 600000,
    "key": "backup-2025",
    "correlation_id": "backup-2025-11-25T10:00Z",
    "causation_id": null,
    "source": "cron.handle",
    "tags": ["backup", "cron", "nightly"],
    "schema_version": "v1",
    "data": {
      "job_id": "backup-2025-11-25T10:00Z",
      "status": "success", 
      "duration_ms": 5230
    },
    "summary": "Event 'jobs.backup.completed' with 3 fields: job_id, status, duration_ms",
    "backend": "in_memory_bus"
  },
  "error": null,
  "warnings": [
    "Backend does not support durable persist; mode downgraded to fire_and_forget."
  ]
}
```

Event with metadata fields:
```bash
event://emit topic="test.metadata" data='{"key": "value"}' key="partition-key" correlation_id="corr-123" causation_id="cause-456" source="test.service" tags='["tag1", "tag2"]' schema_version="v1" format="json"
```

Expected output includes:
```json
{
  "event": {
    "key": "partition-key",
    "correlation_id": "corr-123",
    "causation_id": "cause-456", 
    "source": "test.service",
    "tags": ["tag1", "tag2"],
    "schema_version": "v1"
  }
}
```

Invalid topic error:
```bash
event://emit topic="" data='{}' format="json"
```

Expected output:
```json
{
  "ok": false,
  "timestamp_unix_ms": 1732538400000,
  "event": null,
  "error": {
    "code": "event.emit_invalid_topic",
    "message": "topic cannot be empty"
  },
  "warnings": []
}
```

### subscribe

Subscribes to events from a topic or topic pattern.

**Required Parameters:**
- `topic`: Topic name or pattern (supports wildcards like `jobs.backup.*`)

**Optional Parameters:**
- `offset`: Starting position (`latest`, `earliest`, `next`, or specific offset, default: `latest`)
- `limit`: Maximum number of events to return (1-10000, default: 100)
- `group_id`: Consumer group for durable subscriptions
- `consumer_id`: Consumer identifier within the group
- `auto_commit`: Auto-commit offsets (`true` or `false`, default: `true`)
- `manual_commit_offset`: Manually commit specific offset
- `wait`: Wait for new events (`true` or `false`, default: `false`)
- `wait_timeout_ms`: Wait timeout in milliseconds
- `match_tags`: JSON array of tags to match
- `match_correlation_id`: Correlation ID to match
- `match_source`: Source component to match
- `max_latency_ms`: Maximum event age in milliseconds
- `include_data`: Include event data (`true` or `false`, default: `true`)
- `include_summary`: Include summaries (`true` or `false`, default: `true`)
- `include_raw`: Include raw data (`true` or `false`, default: `false`)
- `format`: Output format (`json` or `text`, default: `json`)

**Examples:**

Basic subscription from latest position:
```bash
event://subscribe topic="jobs.backup.completed" offset="latest" limit="10" wait="false" include_data="true" include_summary="true" include_raw="false" format="json"
```

Expected output:
```json
{
  "ok": true,
  "timestamp_unix_ms": 1732538400000,
  "topic": "jobs.backup.completed",
  "group_id": null,
  "consumer_id": null,
  "effective_offset": "latest",
  "offset_start": null,
  "offset_end": null,
  "next_offset": null,
  "high_watermark": null,
  "timed_out": false,
  "events_returned": 0,
  "events": [],
  "committed_offset": null,
  "committed": false,
  "error": null,
  "warnings": []
}
```

Subscribe from earliest with events:
```bash
event://subscribe topic="jobs.backup.completed" offset="earliest" limit="2" wait="false" include_data="true" include_summary="true" include_raw="false" format="json"
```

Expected output:
```json
{
  "ok": true,
  "timestamp_unix_ms": 1732538400000,
  "topic": "jobs.backup.completed", 
  "group_id": null,
  "consumer_id": null,
  "effective_offset": "earliest",
  "offset_start": "0",
  "offset_end": "1",
  "next_offset": "2",
  "high_watermark": "2",
  "timed_out": false,
  "events_returned": 2,
  "events": [
    {
      "id": "evt_1732538400000_abcd1234efgh",
      "topic": "jobs.backup.completed",
      "timestamp_unix_ms": 1732538400000,
      "mode": "fire_and_forget",
      "mode_used": "fire_and_forget",
      "priority": "normal",
      "ttl_ms": null,
      "key": null,
      "correlation_id": null,
      "causation_id": null,
      "source": null,
      "tags": ["backup"],
      "schema_version": null,
      "data": {"status": "success"},
      "summary": null,
      "backend": "in_memory_bus",
      "offset": "0",
      "raw": null
    }
  ],
  "committed_offset": null,
  "committed": false,
  "error": null,
  "warnings": []
}
```

Durable subscription with auto-commit:
```bash
event://subscribe topic="jobs.backup.completed" offset="earliest" limit="1" group_id="g1" consumer_id="c1" auto_commit="true" wait="false" include_data="true" include_summary="true" include_raw="false" format="json"
```

Expected output:
```json
{
  "ok": true,
  "timestamp_unix_ms": 1732538400000,
  "topic": "jobs.backup.completed",
  "group_id": "g1",
  "consumer_id": "c1", 
  "effective_offset": "earliest",
  "offset_start": "0",
  "offset_end": "0",
  "next_offset": "1",
  "high_watermark": "1",
  "timed_out": false,
  "events_returned": 1,
  "events": [
    {
      "id": "evt_1732538400000_abcd1234efgh",
      "topic": "jobs.backup.completed",
      "data": {"status": "success"},
      "tags": ["backup"]
    }
  ],
  "committed_offset": "1",
  "committed": true,
  "error": null,
  "warnings": []
}
```

Manual commit operation:
```bash
event://subscribe topic="jobs.backup.completed" offset="earliest" limit="0" group_id="g1" auto_commit="false" manual_commit_offset="12345" wait="false" include_data="true" include_summary="true" include_raw="false" format="json"
```

Expected output:
```json
{
  "ok": true,
  "timestamp_unix_ms": 1732538400000,
  "topic": "jobs.backup.completed",
  "group_id": "g1",
  "consumer_id": null,
  "effective_offset": "commit",
  "offset_start": null,
  "offset_end": null,
  "next_offset": null,
  "high_watermark": null,
  "timed_out": false,
  "events_returned": 0,
  "events": [],
  "committed_offset": "12345",
  "committed": true,
  "error": null,
  "warnings": []
}
```

Filtering by tags:
```bash
event://subscribe topic="test.topic" offset="earliest" limit="10" match_tags='["backup", "job"]' wait="false" include_data="true" include_summary="true" include_raw="false" format="json"
```

Expected output shows only events that have both "backup" and "job" tags:
```json
{
  "ok": true,
  "events_returned": 1,
  "events": [
    {
      "tags": ["backup", "job"],
      "data": {"msg": "test1"}
    }
  ]
}
```

Filtering by correlation ID:
```bash
event://subscribe topic="test.topic" offset="earliest" limit="10" match_correlation_id="corr123" wait="false" include_data="true" include_summary="true" include_raw="false" format="json"
```

Expected output shows only events with matching correlation ID:
```json
{
  "ok": true,
  "events_returned": 1,
  "events": [
    {
      "correlation_id": "corr123",
      "data": {"msg": "test1"}
    }
  ]
}
```

Wildcard topic pattern:
```bash
event://subscribe topic="jobs.backup.*" offset="earliest" limit="10" wait="false" include_data="true" include_summary="true" include_raw="false" format="json"
```

Expected output shows events from both `jobs.backup.completed` and `jobs.backup.failed`:
```json
{
  "ok": true,
  "events_returned": 2,
  "events": [
    {"topic": "jobs.backup.completed"},
    {"topic": "jobs.backup.failed"}
  ]
}
```

Subscribe without data:
```bash
event://subscribe topic="test.topic" offset="earliest" limit="10" include_data="false" include_summary="true" include_raw="false" format="json"
```

Expected output shows null data:
```json
{
  "ok": true,
  "events_returned": 1,
  "events": [
    {
      "data": null
    }
  ]
}
```

Error - offset='next' without group_id:
```bash
event://subscribe topic="test.topic" offset="next" limit="10" wait="false" include_data="true" include_summary="true" include_raw="false" format="json"
```

Expected output:
```json
{
  "ok": false,
  "timestamp_unix_ms": 1732538400000,
  "topic": "test.topic",
  "group_id": null,
  "consumer_id": null,
  "effective_offset": "next",
  "offset_start": null,
  "offset_end": null,
  "next_offset": null,
  "high_watermark": null,
  "timed_out": false,
  "events_returned": 0,
  "events": [],
  "committed_offset": null,
  "committed": false,
  "error": {
    "code": "event.subscribe_offset_next_requires_group",
    "message": "offset='next' requires group_id to be specified"
  },
  "warnings": []
}
```

### list-topics

Lists available event topics from various sources.

**Optional Parameters:**
- `prefix`: Filter topics by name prefix
- `match`: Filter topics by substring match
- `sources`: JSON array of sources to query (`["event", "mq", "log", "proc", "fs_watch"]`, default: all)
- `limit`: Maximum number of topics (1-10000, default: 1000)
- `include_hidden`: Include hidden topics (`true` or `false`, default: `false`)
- `include_stats`: Include statistics (`true` or `false`, default: `false`)
- `include_schema`: Include schema information (`true` or `false`, default: `false`)
- `include_backends`: Include backend information (`true` or `false`, default: `true`)
- `summarize`: Generate topic summaries (`true` or `false`, default: `true`)
- `format`: Output format (`json` or `text`, default: `json`)

**Examples:**

Basic topic listing:
```bash
event://list-topics format="json"
```

Expected output:
```json
{
  "ok": true,
  "timestamp_unix_ms": 1732538400000,
  "filters": {
    "prefix": null,
    "match": null,
    "sources": ["event", "mq", "log", "proc", "fs_watch"],
    "limit": 1000,
    "include_hidden": false,
    "include_stats": false,
    "include_schema": false
  },
  "topics_total": 5,
  "topics_returned": 5,
  "truncated": false,
  "topics": [
    {
      "name": "jobs.backup.completed",
      "display_name": "jobs.backup.completed",
      "description": "Events emitted when backup jobs complete",
      "category": "jobs",
      "is_hidden": false,
      "sources": ["event"],
      "backends": [
        {
          "type": "event",
          "handle": "event",
          "id": "event:jobs.backup.completed"
        }
      ],
      "stats": null,
      "schema": null,
      "tags": ["backup", "job"],
      "origin": "cron.handle",
      "first_seen_unix_ms": 1732000000000
    }
  ],
  "error": null,
  "warnings": []
}
```

Topic listing with statistics:
```bash
event://list-topics include_stats="true" format="json"
```

Expected output includes:
```json
{
  "topics": [
    {
      "name": "jobs.backup.completed",
      "stats": {
        "approx_message_count": 1234,
        "last_event_unix_ms": 1732538400000,
        "partitions": null,
        "replication_factor": null,
        "throughput_per_minute": 5.2
      }
    }
  ]
}
```

Topic listing with schema:
```bash
event://list-topics include_schema="true" format="json"
```

Expected output includes:
```json
{
  "topics": [
    {
      "name": "jobs.backup.completed",
      "schema": {
        "schema_version": "v1",
        "example": {
          "job_id": "backup-2025-11-25T10:00Z",
          "status": "success",
          "duration_ms": 5230
        },
        "fields": [
          {
            "name": "job_id",
            "type": "string",
            "required": true
          },
          {
            "name": "status",
            "type": "string", 
            "required": true
          },
          {
            "name": "duration_ms",
            "type": "integer",
            "required": false
          }
        ]
      }
    }
  ]
}
```

Filter by source:
```bash
event://list-topics sources='["event"]' format="json"
```

Expected output shows only event-sourced topics.

Filter by prefix:
```bash
event://list-topics prefix="jobs." format="json"
```

Expected output shows only topics starting with "jobs.".

### hooks.list

Lists available and enabled event processing hooks.

**Parameters:**
None

**Examples:**

List hooks:
```bash
event://hooks.list
```

Expected output:
```json
{
  "instance_hooks": [],
  "global_hooks": ["mq", "log", "proc", "fs"],
  "total": 4
}
```

### hooks.enable

Enables a specific event processing hook.

**Required Parameters:**
- `name`: Hook name (`mq`, `log`, `proc`, or `fs`)

**Examples:**

Enable MQ hook:
```bash
event://hooks.enable name="mq"
```

Expected output:
```json
{
  "hook": "mq",
  "enabled": true
}
```

Enable log hook:
```bash
event://hooks.enable name="log"
```

Expected output:
```json
{
  "hook": "log", 
  "enabled": true
}
```

### hooks.disable

Disables a specific event processing hook.

**Required Parameters:**
- `name`: Hook name to disable

**Examples:**

Disable MQ hook:
```bash
event://hooks.disable name="mq"
```

Expected output:
```json
{
  "hook": "mq",
  "disabled": true
}
```

## Event Topics

Event topics follow a hierarchical naming pattern:

- **System Events**: `system.*` (filesystem, network, etc.)
- **Job Events**: `jobs.*` (backup, restore, cleanup, etc.)
- **Process Events**: `proc.*` (start, stop, exit, etc.) 
- **Log Events**: `logs.*` (application, system, etc.)
- **Internal Events**: `_internal.*` (hidden by default)

## Topic Patterns

Topic subscriptions support wildcard patterns:

- `*` matches any single level
- `jobs.backup.*` matches `jobs.backup.completed`, `jobs.backup.failed`
- `jobs.*` matches `jobs.backup.completed`, `jobs.restore.started`

## Event Metadata

Events include rich metadata:

- **ID**: Unique identifier (`evt_timestamp_uuid`)
- **Timestamp**: Unix milliseconds when emitted
- **Topic**: Hierarchical topic name
- **Data**: JSON payload
- **Tags**: Array of categorization tags
- **Source**: Component that emitted the event
- **Priority**: Low, normal, or high
- **TTL**: Time-to-live in milliseconds
- **Correlation ID**: For tracking related events
- **Causation ID**: For tracking event chains

## Error Codes

Common error codes:

- `event.emit_invalid_topic`: Invalid topic name
- `event.emit_invalid_data`: Invalid JSON data
- `event.emit_backend_unavailable`: Backend not available
- `event.emit_backend_timeout`: Backend timeout
- `event.subscribe_offset_next_requires_group`: Offset 'next' requires group_id
- `event.subscribe_backend_unavailable`: Subscription backend unavailable
- `event.list_topics_invalid_limit`: Invalid limit parameter
- `event.list_topics_backend_unavailable`: Topic listing backend unavailable

## Backend Information

The event handle currently uses an in-memory backend (`in_memory_bus`) that:

- Stores events in memory (not persistent)
- Does not support true durability (wait_for_persist downgrades to fire_and_forget)
- Provides immediate delivery and consumption
- Resets when the system restarts

Future backends may support persistent storage and distributed messaging.