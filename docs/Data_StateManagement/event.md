# Resource Shell (resh) – Event Handle Documentation

## 1. Overview

Resource Shell (resh) is a command-line tool that runs operations on resources named by URLs.

The `event://` handle is a small local event log. `emit` appends a structured event to a topic, and `subscribe` reads stored events back by topic pattern, with offsets, simple consumer-group offset tracking and filters. Results are printed as JSON.

The stage has no target, so the verb follows a dot directly:

```text
resh event://.<verb> [key=value ...]
```

`event://emit` (no dot) does not parse; the form is `event://.emit`.

### Where events are stored

Events are stored as one JSON Lines file per topic in the resh state directory:

```text
$XDG_STATE_HOME/resh/events/<topic>.jsonl      (default ~/.local/state/resh/events/)
$XDG_STATE_HOME/resh/events/_offsets.json      (committed consumer-group offsets)
```

The directory is created with mode 0700 and the files with mode 0600. Because events are on disk, an event emitted by one `resh` command can be read by a later one. If the platform has no state directory, the handle falls back to an in-memory bus that lasts only for one process (so nothing persists); this does not happen on Linux.

---

## 2. Design Notes

* `emit`, `subscribe` and `list-topics` print a JSON object with `ok`, `error` and `warnings` fields. This output is indented even without `--json-pretty`.
* On failure the JSON object (with `ok: false` and an `error.code`) is printed to stdout, resh prints `Error: <reason>` to stderr, and the exit code is 1.
* This is a local, file-based event log for one host, not a message broker. There is no network transport, no delivery to other hosts, and no push delivery.

---

## 3. Command Syntax and Execution Model

### 3.1 Verbs

| Verb            | Purpose                                                        |
| --------------- | -------------------------------------------------------------- |
| `emit`          | Append an event to a topic file                                |
| `subscribe`     | Read stored events whose topic matches a pattern               |
| `list-topics`   | List topics from a built-in sample catalogue (see section 4.3) |
| `hooks.list`    | List registered hooks                                          |
| `hooks.enable`  | Register a built-in hook for the current process               |
| `hooks.disable` | Remove a hook for the current process                          |

### 3.2 Example commands

Emit an event:

```bash
resh event://.emit topic=jobs.backup.completed 'data={"status":"success"}'
```

Read all stored events for matching topics:

```bash
resh event://.subscribe 'topic=jobs.*' offset=earliest
```

List hooks:

```bash
resh --json-pretty event://.hooks.list
```

### 3.3 emit output

```json
{
  "error": null,
  "event": {
    "backend": "state_file",
    "causation_id": null,
    "correlation_id": null,
    "data": { "status": "success" },
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
```

### 3.4 Error output

```json
{
  "error": {
    "code": "event.emit_invalid_data",
    "message": "failed to parse data as JSON"
  },
  "event": null,
  "ok": false,
  "timestamp_unix_ms": 1792760903628,
  "warnings": []
}
```

---

## 4. Verbs

### 4.1 emit

Appends one event to `<topic>.jsonl`.

| Argument         | Description                                                    |
| ---------------- | -------------------------------------------------------------- |
| `topic`          | Required. Must not contain `*` or `?`                          |
| `data`           | Required. Must be valid JSON                                   |
| `source`, `key`, `correlation_id`, `causation_id` | Stored as given              |
| `tags`           | JSON array of strings                                          |
| `priority`       | `low`, `normal` or `high` (default `normal`)                   |
| `mode`           | `fire_and_forget` (default) or `wait_for_persist` (syncs the file to disk before replying) |
| `ttl_ms`         | Stored in the event only; events are never expired or deleted  |
| `summarize`      | Adds a `summary` field                                         |
| `schema_version` | Stored as given                                                |
| `format`         | `json` (default) or `text`                                     |

```bash
resh event://.emit topic=deploy.finished 'data={"service":"api","version":"1.4.2"}' source=ci 'tags=["deploy","prod"]' correlation_id=run-881
```

### 4.2 subscribe

Reads stored events whose topic matches `topic=` (`*` and `?` wildcards are allowed) and prints them as one batch. It does not keep running or stream; with `wait=true` it polls until at least one event arrives or `wait_timeout_ms` (default 30000) passes.

| Argument               | Description                                                       |
| ---------------------- | ----------------------------------------------------------------- |
| `topic`                | Required topic or pattern                                         |
| `offset`               | `latest` (default; skips events already stored), `earliest`, `next` (needs `group_id`), or a number |
| `limit`                | Maximum events returned                                           |
| `group_id`             | Consumer group whose committed offset `offset=next` resumes from  |
| `auto_commit`          | Commit the new offset for the group (default `true`)              |
| `manual_commit_offset` | Commit this offset instead                                        |
| `consumer_id`          | Echoed in the output only                                         |
| `wait`, `wait_timeout_ms` | Poll for new events (see above)                                |
| `match_tags`           | JSON array; keep events carrying these tags                       |
| `match_correlation_id`, `match_source` | Exact-match filters                               |
| `max_latency_ms`       | Keep only events newer than this many milliseconds                |
| `include_data`, `include_summary`, `include_raw` | Control which fields are filled         |
| `format`               | `json` (default) or `text`                                        |

Offsets index the matching events in timestamp order across all matching topic files. The output includes `events`, `events_returned`, `offset_start`, `offset_end`, `next_offset`, `high_watermark`, `committed`, `committed_offset` and `timed_out`.

Process a topic in batches, resuming where the previous command stopped:

```bash
resh event://.subscribe topic=jobs.work offset=next group_id=workers limit=10
```

The committed offset is stored per group and topic pattern in `_offsets.json`. There is no locking around reading and committing offsets, so two consumers in the same group running at the same time can receive the same events. `consumer_id` does not assign or balance work between consumers.

### 4.3 list-topics

**Returns sample data.** `list-topics` lists topics from built-in sample catalogues for the event, mq, log, proc and fs_watch sources. It does not read the event store, so topics you have emitted to are not listed (look in the events directory instead). Arguments: `prefix`, `match`, `sources`, `limit`, `include_hidden`, `include_stats`, `include_schema`, `format`.

```bash
resh --json-pretty event://.list-topics prefix=jobs. sources=mq
```

### 4.4 Hooks

Four built-in hooks (`mq`, `log`, `proc`, `fs`) are registered at the start of every `resh` process. **They are simulations**: they do not forward events, write logs, signal processes or watch files. They only print notes to stderr, for example:

* on `subscribe`: `MQ hook processed subscription with 1 events` and `Log hook: subscription to jobs.* returned 1 events`;
* on `emit` with a tag such as `mq:orders`: `MQ Hook: Would forward event <id> to MQ topic: orders` (similarly `log:`, `proc:` and `fs:` tags).

stdout is not affected, so the JSON output stays parseable.

* `hooks.list` prints `global_hooks` (normally all four), `instance_hooks` and `total`.
* `hooks.enable name=mq|log|proc|fs` registers the hook in the current process only. An unknown name fails.
* `hooks.disable name=<hook>` removes it in the current process only, and reports `"disabled": true` even if no such hook was registered.

Because each `resh` command is a new process, enabling or disabling a hook has no effect on any later command: all four hooks are active again in the next process.

```bash
resh event://.hooks.disable name=mq
```

### 4.5 Topic and tag rules

* Topics: 1 to 256 characters from letters, digits, `.`, `_`, `:`, `-` (and `*`, `?` in `subscribe` patterns only). The topic is used as the file name.
* Tags: non-empty, at most 64 characters, ASCII, passed as a JSON array.

### 4.6 timeout_ms

No event verb reads `timeout_ms`; it is ignored if given. `subscribe wait=true` is bounded by `wait_timeout_ms` instead.

---

## 5. Limitations

* `list-topics` returns sample data, not the stored topics.
* Hooks are simulations that only write notes to stderr, and enable/disable lasts for one process.
* `ttl_ms` is recorded but not enforced. Topic files grow until you delete them.
* Consumer-group offsets are not locked against concurrent consumers.
* Emitting to a wildcard topic fails with the generic code `event.emit_internal_error`.

---

## 6. Platform Support

Linux is the only supported and tested platform. Persistence depends on the XDG state directory, which is resolved on Linux.

---

## 7. Usage Guidance

* Use `correlation_id` to link events from one workflow run and `match_correlation_id` to read them back.
* Use `group_id` with `offset=next` for a single consumer that processes a topic in batches.
* Delete or rotate old topic files under the events directory when they are no longer needed.

---

## 8. Implementation Notes

* Written in Rust. Each event is appended with a single write of one JSON line, so concurrent `emit` commands do not interleave lines; a line that does not parse is skipped when reading.
* Committed offsets are written to a temporary file and renamed into place.
