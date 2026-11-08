# Resource Shell (resh) – Event Handle Documentation

## 1. Overview

Resource Shell (resh) is a command-line tool that runs operations on resources named by URLs.

The `event://` handle is a local event log for one user on one host. `emit` appends a structured event to a topic, and `subscribe` reads stored events back by topic pattern, with offsets, consumer groups, filters, waiting for new events, and following topics as a stream. Events written by one `resh` command are read by any later or concurrently running `resh` command of the same user. Results are printed as JSON.

The stage has no target, so the verb follows a dot directly:

```text
resh event://.<verb> [key=value ...]
```

`event://emit` (no dot) does not parse; the form is `event://.emit`. A target (`event://jobs.emit`) is refused with exit code 2 (`event.invalid_target`).

### Where events are stored

The event store is a directory in the resh state directory:

```text
$XDG_STATE_HOME/resh/events/          (default ~/.local/state/resh/events/)
  <topic>.jsonl                       one stored event per line
  _store.lock                         store lock; holds the last sequence number
  _offsets.lock                       consumer-group lock
  _offsets.json                       committed consumer-group offsets
  _hooks.json                         hooks enabled or disabled with hooks.enable/disable
  hooks/log/<topic>.log               written by the log hook
  hooks/fs/<topic>.json               written by the fs hook
```

The directory is created with mode 0700 and every file with mode 0600. Reading verbs never create the directory. If there is no state directory (neither `HOME` nor `XDG_STATE_HOME` can be resolved), every verb fails with `event.store_unavailable` (exit 1); there is no in-memory or `/tmp` fallback.

### How processes share the store

* `emit` takes an exclusive lock on `_store.lock`, gives the event the next store-wide sequence number, and appends it with one write. Readers take a shared lock while they read the topic files, so a reader never sees a half-written event or a gap that is filled later.
* Events are ordered by sequence number (the order they were stored in), across all topics. Events written by resh versions before sequence numbers come first, ordered by time.
* A consumer-group read (`group_id` with `auto_commit=true`) holds an exclusive lock on `_offsets.lock` while it reads the committed offset, selects the batch, delivers it and commits the new offset. Consumers of one group therefore never receive the same event, even when they run at the same time.
* Every lock wait is bounded by `timeout_ms` (section 4.6).

---

## 2. Design Notes

* `emit`, `subscribe` and `list-topics` print one indented JSON object with `ok`, `error` and `warnings` fields (also without `--json-pretty`); `format=text` prints a text report instead. `subscribe follow=true` prints one compact JSON line (or text line) per event instead.
* `hooks.list`, `hooks.enable` and `hooks.disable` print one compact JSON object.
* On failure resh prints `Error: [event.<code>] <message>` on stderr and exits with the code in section 3.4. `emit`, `subscribe` (without `follow`) and `list-topics` also print their JSON object with `ok: false` and `error: {"code", "message"}` on stdout (nothing with `format=text`). The hook verbs print nothing on stdout on failure.
* Every argument is checked before anything is read or written: an unknown argument, an invalid value or an argument that has no effect in the given combination is refused with exit code 2, and unknown names get a "did you mean" hint.
* This is a local, file-based event log, not a message broker: there is no network transport and no delivery to other users or hosts.

---

## 3. Command Syntax and Execution Model

### 3.1 Verbs

| Verb            | Purpose                                                                   |
| --------------- | ------------------------------------------------------------------------- |
| `emit`          | Append an event to a topic                                                |
| `subscribe`     | Read stored events whose topic matches a pattern, wait for them or follow |
| `list-topics`   | List the topics in the store with counts and payload fields               |
| `hooks.list`    | List enabled and disabled hooks                                           |
| `hooks.enable`  | Enable a built-in hook (`fs`, `log`, `mq`) for later emits                |
| `hooks.disable` | Disable a built-in hook for later emits                                   |

### 3.2 Example commands

```bash
resh event://.emit topic=jobs.backup.completed 'data={"status":"success"}'
resh event://.subscribe 'topic=jobs.*' offset=earliest
resh event://.subscribe topic=jobs.work offset=next group_id=workers limit=10
resh event://.subscribe 'topic=jobs.*' follow=true
resh event://.hooks.enable name=mq
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
  "hooks": [],
  "ok": true,
  "timestamp_unix_ms": 1792166019757,
  "warnings": []
}
```

`hooks` has one `{"name", "ok", "warning"}` entry per enabled hook (section 4.4).

Failure output (stdout), with `Error: [event.invalid_data] ...` on stderr and exit code 2:

```json
{
  "error": {
    "code": "event.invalid_data",
    "message": "data is not valid JSON (expected value at line 1 column 1); quote text as JSON, for example 'data=\"text\"'"
  },
  "event": null,
  "hooks": [],
  "ok": false,
  "timestamp_unix_ms": 1792760903628,
  "warnings": []
}
```

### 3.4 Exit codes

| Code | Meaning |
| ---- | ------- |
| 0    | Success. A `subscribe wait=true` that ends without events, and a `follow=true` that ends at `timeout_ms` or `max_events`, are successes. |
| 1    | The operation failed: no state directory or the store cannot be created (`store_unavailable`); a file cannot be read or written, or a symlink was found where a file is written (`store_error`); the offsets, hook state or sequence file is not valid (`store_corrupt`); `follow` cannot write to stdout (`output_failed`). |
| 2    | Invalid usage, nothing was done: a missing, unknown or invalid argument (with a "did you mean" hint), an invalid topic, payload or tag list, an unknown hook name, a target in the URL, `dry_run=true`, an unknown verb. |
| 124  | `timeout_ms` passed before the work was done: another process held the store lock, or reading took too long. `emit` wrote nothing and `subscribe` committed nothing. |

### 3.5 Error codes

Every failure carries one of these codes, printed as `Error: [event.<code>] <message>`:

| Code                      | Exit | Meaning |
| ------------------------- | ---- | ------- |
| `event.invalid_argument`  | 2    | An unknown argument, an invalid value (boolean, integer, choice, `sources`), an empty id or text value, `timeout_ms` on a hook verb, `dry_run=true`, or a combination with no effect: `wait_timeout_ms` without `wait=true`, `max_events` without `follow=true`, `wait` with `follow`, `auto_commit` without `group_id`, `manual_commit_offset` with a reading option |
| `event.missing_argument`  | 2    | `topic`, `data` or `name` is missing; `offset=next` or `manual_commit_offset` without `group_id` |
| `event.invalid_topic`     | 2    | The topic is empty, longer than 256 characters, has a character other than letters, digits, `.`, `_`, `:`, `-` (and `*`, `?` in `subscribe`), or `emit` was given a wildcard |
| `event.invalid_data`      | 2    | `data` is not valid JSON |
| `event.invalid_tags`      | 2    | `tags` or `match_tags` is not a JSON array of strings, or a tag is empty, longer than 64 characters or not printable ASCII |
| `event.invalid_target`    | 2    | The URL has a target, as in `event://jobs.emit` |
| `event.unknown_hook`      | 2    | `hooks.enable`/`hooks.disable` with a name other than `fs`, `log`, `mq` (including the removed `proc`) |
| `event.unknown_verb`      | 2    | The verb is not one of the six verbs |
| `event.store_unavailable` | 1    | There is no state directory, the store path is not a directory, or it cannot be created |
| `event.store_error`       | 1    | A store file cannot be opened, read, locked or written, or a symlink or other non-regular file is at a path the handle writes |
| `event.store_corrupt`     | 1    | `_offsets.json`, `_hooks.json` or the sequence number in `_store.lock` is not valid (fix or remove the file) |
| `event.output_failed`     | 1    | `subscribe follow=true` cannot write to stdout; the events of that batch are not committed |
| `event.timeout`           | 124  | `timeout_ms` passed while waiting for a lock or reading the store; nothing was written or committed |

`dry_run=true` is refused (exit 2) by resh before the handle runs; no event verb has a dry-run mode.

**Change note (breaking, after v1.0.6-beta):** the old codes (`event.emit_invalid_data`, `event.emit_invalid_topic`, `event.emit_internal_error`, `event.subscribe_offset_next_requires_group`, `event.subscribe_backend_error`, `event.list_topics_invalid_source` and the others) were replaced by the codes above. Invalid arguments now exit 2 instead of 1. Unknown arguments, `tags` that are not a JSON array (they were taken as one tag), unreadable booleans (they were taken as `false`) and the option combinations listed above are refused instead of ignored. `list-topics` lists the real store instead of sample catalogues, `hooks.list` lists the hooks in a fixed order and adds `disabled`, and `emit` output adds `hooks`. The hooks are real and off by default (section 4.4); the `proc` hook was removed.

---

## 4. Verbs

### 4.1 emit

Appends one event to `<topic>.jsonl`.

| Argument         | Description                                                    | Default           |
| ---------------- | -------------------------------------------------------------- | ----------------- |
| `topic`          | Required. Must not contain `*` or `?`                          |                   |
| `data`           | Required. Any JSON value (quote text as JSON: `data='"text"'`) |                   |
| `source`, `key`, `correlation_id`, `causation_id`, `schema_version` | Stored as given; must not be empty |  |
| `tags`           | JSON array of strings                                          | `[]`              |
| `priority`       | `low`, `normal` or `high`                                      | `normal`          |
| `mode`           | `fire_and_forget`, or `wait_for_persist` to sync the file to disk before the reply | `fire_and_forget` |
| `ttl_ms`         | Lifetime in milliseconds (1 to 100 years). `subscribe` and `list-topics` skip the event once it has passed; the line stays in the file | none |
| `summarize`      | `true` adds a `summary` field                                  | `false`           |
| `format`         | `json` or `text`                                               | `json`            |
| `timeout_ms`     | Longest wait for the store lock; 0 = no limit                  | 30000             |

```bash
resh event://.emit topic=deploy.finished 'data={"service":"api","version":"1.4.2"}' source=ci 'tags=["deploy","prod"]' correlation_id=run-881
```

### 4.2 subscribe

Reads stored events whose topic matches `topic=` and prints them as one batch (or, with `follow=true`, as a stream).

| Argument               | Description                                                       | Default |
| ---------------------- | ----------------------------------------------------------------- | ------- |
| `topic`                | Required topic or pattern; `*` matches any run of characters and `?` one character | |
| `offset`               | `latest` (skip events already stored), `earliest`, `next` (resume after the group's committed offset; needs `group_id`), or an index | `latest` |
| `limit`                | Most events returned per batch (1 to 10000)                       | 100     |
| `group_id`             | Consumer group                                                    | none    |
| `auto_commit`          | Commit the group's new offset after the batch (needs `group_id`)  | `true`  |
| `manual_commit_offset` | Commit this offset for `group_id` and the pattern, and read nothing | none  |
| `consumer_id`          | Echoed in the output only                                         | none    |
| `wait`                 | Wait until at least one event can be returned                     | `false` |
| `wait_timeout_ms`      | How long `wait=true` waits (needs `wait=true`)                    | 30000   |
| `follow`               | Print each event as one line as it arrives (see below)            | `false` |
| `max_events`           | With `follow=true`, stop after this many events                   | no limit |
| `timeout_ms`           | Time limit, 0 = no limit (see 4.6)                                | 30000; `wait_timeout_ms` + 30000 with `wait=true`; no limit with `follow=true` |
| `match_tags`           | JSON array; keep events carrying all these tags                   | none    |
| `match_correlation_id`, `match_source` | Exact-match filters                               | none    |
| `max_latency_ms`       | Keep only events newer than this many milliseconds                | none    |
| `include_data`         | `false` replaces `data` with `null`                               | `true`  |
| `include_summary`      | `false` replaces `summary` with `null`                            | `true`  |
| `include_raw`          | `true` fills `raw` with the stored record (including its sequence number `seq`) | `false` |
| `format`               | `json` or `text`                                                  | `json`  |

Offsets index the matching events in store order (section 1). The scan starts at the offset and keeps events that pass the filters (and whose `ttl_ms` has not passed) until `limit` are kept or the end is reached. The output includes `events`, `events_returned`, `offset_start` and `offset_end` (the indexes of the first and last returned event), `next_offset` (the index after the last event scanned, where the next read continues), `high_watermark` (the number of matching events), `committed`, `committed_offset` and `timed_out`.

With `group_id` and `auto_commit=true`, `next_offset` is committed after every read that scanned at least one event, even when the filters kept none, so a group never reads the same events again. The committed offset is stored per group and topic pattern. Several consumers of one group can run at the same time; each event goes to one of them.

Process a topic in batches, resuming where the previous command stopped:

```bash
resh event://.subscribe topic=jobs.work offset=next group_id=workers limit=10
```

Commit by hand after processing (two commands):

```bash
resh event://.subscribe topic=jobs.work offset=next group_id=workers auto_commit=false
resh event://.subscribe topic=jobs.work group_id=workers manual_commit_offset=10
```

**wait.** With `wait=true`, `subscribe` waits until an event can be returned, then prints the batch. If `wait_timeout_ms` or `timeout_ms` passes first, it prints an empty batch with `timed_out: true` and exits 0.

**follow.** With `follow=true`, `subscribe` prints every matching event as one compact JSON line (the same object as in `events`; with `format=text` one text line) as soon as it is stored, and keeps running until `max_events` events were printed or `timeout_ms` passes (both exit 0), or until it is interrupted. With `group_id`, each batch is committed after it was printed. Errors are reported on stderr only. Do not combine `follow` with `--json-pretty`: that flag holds all output until the command ends and then prints the lines unchanged.

```bash
resh event://.subscribe 'topic=deploy.*' follow=true group_id=notifier offset=next
```

Lines that do not parse are skipped, with a warning naming how many.

### 4.3 list-topics

Lists the topics in the event store, sorted by name.

| Argument         | Description                                                         | Default |
| ---------------- | ------------------------------------------------------------------- | ------- |
| `prefix`         | Only topics starting with this text                                 | none    |
| `match`          | Only topics containing this text (case-insensitive)                 | none    |
| `sources`        | Only `event` is accepted (comma list or JSON array)                 | `event` |
| `limit`          | Most topics returned (1 to 10000); a warning says when more matched | 1000    |
| `include_hidden` | Also list topics whose name starts with `_`                         | `false` |
| `include_stats`  | Fill `stats`: `approx_message_count` (live events) and `last_event_unix_ms` | `false` |
| `include_schema` | Fill `schema`: the latest event's `schema_version`, its `data` as `example`, and its top-level `fields` with their JSON type and `required` (present in every live event) | `false` |
| `format`         | `json` or `text`                                                    | `json`  |
| `timeout_ms`     | Time limit for the read; 0 = no limit                               | 30000   |

Each topic has `name`, `display_name` (the name), `category` (the part before the first `.`, or `null`), `is_hidden`, `sources` and `backends` (the event store), `tags` (all tags of its live events), `first_seen_unix_ms` (its oldest live event), `stats` and `schema` (`null` unless requested). `description` and `origin` are always `null`, and `partitions`, `replication_factor` and `throughput_per_minute` in `stats` are always `null`; they are kept for compatibility. Events whose `ttl_ms` has passed are not counted.

```bash
resh --json-pretty event://.list-topics prefix=jobs. include_stats=true
```

**Change note:** earlier versions listed built-in sample catalogues for the event, mq, log, proc and fs_watch sources. `sources=mq`, `log`, `proc` or `fs_watch` is now refused (exit 2); use the `mq` handle for broker topics.

### 4.4 Hooks

Three built-in hooks act on every event that `emit` stores, while they are enabled. **They are off by default**; enable each one with `hooks.enable`. The state is kept in `_hooks.json` and applies to every later `resh` command of the user.

| Hook  | What it does after an event is stored |
| ----- | ------------------------------------- |
| `fs`  | Replaces `<store>/hooks/fs/<topic>.json` with the event (the stored record, one JSON object including its sequence number `seq`). The file always holds the topic's latest event: under parallel emits a slower one never replaces a newer event. The file is written to a temporary file and renamed into place. |
| `log` | Appends the event as one JSON line to `<store>/hooks/log/<topic>.log`. Read it with `resh log:///<path>.tail`, for example `resh log:///home/alice/.local/state/resh/events/hooks/log/jobs.done.log.tail lines=10`. |
| `mq`  | Puts the stored event (the same one-line JSON object the `log` hook writes: `id`, `topic`, `seq`, `timestamp_unix_ms`, `tags`, `ttl_ms`, `data` and the other event fields) on the `mq` queue named after the topic, through the mq handle's own `put`, so `resh mq://<topic>.get` returns it. A topic that is not a valid queue name (for example one containing `:` or starting with `.`) is skipped with a warning. |

`<store>` is the event store directory (section 1). The hooks run in the order `fs`, `log`, `mq`, after the event was stored. Directories they create are 0700 and files 0600; a symlink or other non-regular file at a path a hook writes is refused, never followed.

A hook never fails the emit. `emit` prints one entry per enabled hook in `hooks`: `{"name": "log", "ok": true, "warning": null}`, or `ok: false` with the reason in `warning`. The warning is also added to `warnings` and printed on stderr as `Warning: <hook> hook: <reason>`. `timeout_ms` bounds the hooks too: a hook that would start after it passed, or the `fs` and `mq` lock waits, are skipped with a warning.

* `hooks.list` prints `global_hooks` (the enabled hooks), `disabled` (the disabled ones), `instance_hooks` (always empty) and `total` (the number of enabled hooks).
* `hooks.enable name=fs|log|mq` and `hooks.disable name=fs|log|mq` print `changed: false` if the hook was already in that state. Any other name fails with `event.unknown_hook` (exit 2), including `proc`.
* If `_hooks.json` is not valid, `hooks.list`, `hooks.enable` and `hooks.disable` fail with `event.store_corrupt`; `emit` still stores the event, runs no hook and adds a warning.
* `hooks.enable` and `hooks.disable` wait at most 10 seconds for the store lock (`event.timeout`). The hook verbs do not take `timeout_ms`.
* `subscribe` runs no hooks.

```bash
resh event://.hooks.enable name=mq
resh event://.emit topic=orders 'data={"id":42}'
resh mq://orders.get
```

**Change note:** earlier versions had four hooks (`fs`, `log`, `mq`, `proc`) that were all on and only printed notes such as `MQ Hook: Would forward event ...` on stderr (on `emit` and `subscribe`). The hooks now do real work and are off by default; `proc` was removed. Old `_hooks.json` files are still read; `proc` entries in them are ignored and dropped on the next change.

### 4.5 Topic and tag rules

* Topics: 1 to 256 characters from letters, digits, `.`, `_`, `:`, `-` (and `*`, `?` in `subscribe` patterns only). The topic is used as the file name. Topics never contain `/`, so `*` and `?` follow the shell's glob rules.
* Tags: non-empty, at most 64 characters, printable ASCII, passed as a JSON array.

### 4.6 timeout_ms

`emit`, `subscribe` and `list-topics` take `timeout_ms` (0 = no limit). It bounds the waits for the store locks and the reading of the topic files:

* `emit` (default 30000): if the store lock is not free in time, nothing is written and the command exits 124.
* `list-topics` (default 30000): exits 124 if the lock wait or the read does not finish in time.
* `subscribe` without `wait`/`follow` (default 30000): exits 124 if the lock wait or the read does not finish in time; nothing is committed.
* `subscribe wait=true` (default `wait_timeout_ms` + 30000): the wait ends at `wait_timeout_ms` or `timeout_ms`, whichever comes first, with `timed_out: true` and exit 0. A lock wait or read that is still running at `timeout_ms` exits 124.
* `subscribe follow=true` (default: no limit): the run ends at `timeout_ms` with exit 0.

`hooks.list`, `hooks.enable` and `hooks.disable` are quick local operations and refuse `timeout_ms` (exit 2).

---

## 5. Limitations

* The hooks write files and queue messages but never delete them: hook log files and mq queues grow until you remove or read them.
* `ttl_ms` hides expired events from `subscribe` and `list-topics`, but nothing deletes them: topic files grow until you delete them.
* Offsets are indexes into the matching events. Deleting or editing a topic file, or emitting events with a resh version older than this one while newer ones run, can shift them.
* `subscribe wait=true` and `follow=true` notice new events by checking the topic files every 100 ms.

---

## 6. Platform Support

Linux is the only supported and tested platform. The store depends on the XDG state directory and on `flock` locks, which work on local filesystems (not reliably on network filesystems).

---

## 7. Usage Guidance

* Use `correlation_id` to link events from one workflow run and `match_correlation_id` to read them back.
* Use `group_id` with `offset=next` for consumers that process a topic in batches; run as many consumers of one group as you need.
* Use `follow=true` with `max_events` or `timeout_ms` in automation so it always ends.
* Delete old topic files under the events directory when they are no longer needed (committed offsets for their patterns then no longer match; reset them with `manual_commit_offset`).

---

## 8. Implementation Notes

* Written in Rust. Each event is appended with a single write of one JSON line while the store lock is held; readers hold the shared lock, so they never see a partial line.
* Committed offsets and the hook state are written to a new temporary file and renamed into place; a symlink at the target path is refused, never followed.
* Locks are `flock` locks on `_store.lock` and `_offsets.lock`; the kernel releases them when a process exits, so a crashed command never leaves the store locked.
