# Resource Shell (resh) – Message Queue Handle Documentation

## 1. Overview

Resource Shell (resh) is a structured command-line framework that standardizes infrastructure operations using a resource-oriented URI execution model.

The `mq://` handle provides a file-based message queue system for local, point-to-point message processing. It enables:

* Queue creation
* FIFO message insertion and retrieval
* Queue inspection
* Non-destructive message preview
* Queue purging
* Atomic concurrent access

Traditional queue implementations often require:

* External messaging systems
* Network services
* Complex broker configuration
* Language-specific client libraries
* Custom retry and durability logic

The `mq://` handle provides a lightweight alternative for local automation workflows using filesystem-backed storage with atomic file operations.

All operations follow the URI pattern:

```
mq://queue-name.verb(options)
```

Messages are processed in FIFO (First In, First Out) order. Atomic file operations ensure message integrity under concurrent producers and consumers.

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

All queue operations use a uniform URI grammar:

```
mq://queue-name.verb(arguments)
```

This ensures predictable invocation semantics across all queue lifecycle operations.

### Safety-First Execution

The handle enforces:

* Atomic write operations (temporary file then rename)
* Atomic retrieval via `_inflight` directory
* Idempotent operations (`create`, `purge`)
* Explicit exit codes for empty queues
* Filesystem-safe queue name sanitization

These controls prevent message corruption, duplication, and partial writes.

### Deterministic Behavior

Operations:

* Follow strict FIFO ordering
* Preserve message content exactly (binary-safe)
* Return consistent exit codes
* Avoid implicit formatting or transformation

### JSON-Based Structured Output

The MQ handle primarily returns raw message content. Exit codes provide structured control flow:

| Exit Code | Meaning                      |
| --------- | ---------------------------- |
| 0         | Success                      |
| 1         | General error                |
| 2         | Empty queue (`get` / `peek`) |

Automation logic should rely on exit codes rather than parsing output.

### AI-Readiness

The deterministic URI grammar and exit-code semantics allow safe integration into automation pipelines and orchestration workflows.

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
mq://queue-name.verb(options)
```

#### Components

| Component    | Description                          |
| ------------ | ------------------------------------ |
| `mq`         | Handle identifier                    |
| `queue-name` | Logical queue identifier (sanitized) |
| `verb`       | Queue operation                      |
| `options`    | Named parameters (where applicable)  |

Queue names are sanitized to be filesystem-safe. Unsafe characters are replaced with underscores and limited to 120 characters.

---

### Example Commands

Create queue:

```bash
resh "mq://tasks.create"
```

Put message:

```bash
resh "mq://tasks.put(data=hello)"
```

Put via stdin:

```bash
echo "process file1.txt" | resh "mq://tasks.put"
```

Get message:

```bash
resh "mq://tasks.get"
```

Peek message:

```bash
resh "mq://tasks.peek"
```

Queue length:

```bash
resh "mq://tasks.len"
```

Purge queue:

```bash
resh "mq://tasks.purge"
```

---

### 3.2 Execution Semantics

#### FIFO Behavior

Messages are retrieved in insertion order:

```bash
resh "mq://demo.put(data=one)"
resh "mq://demo.put(data=two)"
resh "mq://demo.get"   # one
resh "mq://demo.get"   # two
```

#### Atomic Retrieval

`get` operation:

1. Moves message to `_inflight`
2. Reads content
3. Removes file after successful read

#### Empty Queue Handling

```bash
resh "mq://tasks.get"
```

Exit code `2` indicates empty queue.

Example script handling:

```bash
if resh "mq://tasks.get"; then
  echo "Message processed"
else
  echo "Queue empty"
fi
```

---

## 4. Functional Domain – Message Queue Handle

### Operational Scope

The `mq://` handle supports:

* FIFO message queuing
* Local workflow coordination
* Task buffering
* Lightweight job processing
* Concurrent producer/consumer patterns

It is filesystem-based and single-node.

---

### 4.1 Supported Verbs

| Verb                   | Description                          |
| ---------------------- | ------------------------------------ |
| `create`               | Create queue directory (idempotent)  |
| `put`                  | Insert message                       |
| `get`                  | Retrieve and remove oldest message   |
| `peek`                 | View oldest message without removing |
| `len`                  | Return number of queued messages     |
| `purge`                | Remove all messages (idempotent)     |
| `help`, `--help`, `-h` | Display documentation                |
| `--help=VERB`          | Verb-specific help                   |

---

### 4.2 Message Handling Characteristics

* Binary-safe storage
* No encoding transformation
* No whitespace trimming
* No size limit (filesystem dependent)
* Preserves exact input

Example (binary-safe):

```bash
printf "\x00\x01\x02\xff" | resh "mq://binary.put"
resh "mq://binary.get"
```

---

### 4.3 Storage Location

Queues are stored under:

```
~/.local/share/resh/mq/
```

Structure:

```
queue-name/
  msg-0001.msg
  msg-0002.msg
  _inflight/
```

Characteristics:

* One directory per queue
* One file per message
* Timestamp-based ordering
* Atomic rename operations

---

### 4.4 Concurrency Model

Atomic file operations ensure:

* Safe concurrent producers
* Safe concurrent consumers
* No duplication
* No corruption
* No partial writes

Example concurrent pattern:

```bash
for i in {1..100}; do
  echo "Task-$i" | resh "mq://concurrent.put"
done &
```

Consumers may safely retrieve messages concurrently.

---

### 4.5 Performance Characteristics

| Condition        | Behavior                         |
| ---------------- | -------------------------------- |
| Small messages   | Fast filesystem operations       |
| Large messages   | Limited by I/O throughput        |
| Many messages    | Directory scan for FIFO ordering |
| High concurrency | Atomic rename overhead           |

Recommendations:

* Avoid thousands of messages in a single queue
* Purge unused queues
* Monitor queue length using `len`

---

## 5. Platform Support

| Platform   | Support Level |
| ---------- | ------------- |
| Linux      | Supported     |
| macOS/Unix | Supported     |
| Windows    | Supported     |

Operation depends on filesystem availability and user write permissions.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Create queues explicitly before use.
* Handle exit code `2` for empty queues.
* Use meaningful queue names.
* Purge queues when workflows complete.
* Avoid long-running tasks before consuming messages.

### Automation Considerations

* Check queue depth using `len`.
* Use `peek` to inspect without consuming.
* Implement dead-letter queues for failed processing.
* Use idempotent processing logic.

### CI/CD Integration

* Use queues for task orchestration.
* Buffer deployment events.
* Serialize operations through FIFO processing.
* Monitor queue depth before progressing stages.

### Production Recommendations

* Separate workflows into distinct queues.
* Monitor queue length to prevent growth.
* Implement retry logic in consumers.
* Avoid using as a distributed messaging system.

---

## 7. Use Cases by Role

### DevOps Engineers

* Implement lightweight task queues.
* Buffer deployment jobs.
* Coordinate sequential pipeline steps.
* Implement rate-limited processing.

### SRE Engineers

* Use dead-letter queues for failed tasks.
* Monitor queue depth during incidents.
* Implement workflow retries.
* Coordinate recovery steps.

### Network Administrators

* Queue configuration updates.
* Buffer device commands.
* Serialize configuration application steps.

### AI/Automation Engineers

* Orchestrate deterministic task execution.
* Implement workflow coordination.
* Use queue depth as a control signal.
* Integrate structured exit-code logic into agents.

---

## 8. Technical Foundation

The `mq://` handle operates within resh, implemented in Rust.

### Rust Implementation Advantages

* Memory safety
* Deterministic file I/O handling
* Strong error propagation
* Cross-platform compatibility

### Type Safety

Argument parsing enforces:

* Valid queue names
* Recognized verbs
* Proper data handling

Invalid usage results in consistent exit codes.

### Performance Characteristics

* Atomic rename operations
* Minimal memory footprint
* Efficient directory-based FIFO ordering
* Binary-safe operations

### Cross-Platform Architecture

Supported across:

* Linux
* macOS/Unix
* Windows

Functionality depends on local filesystem semantics and user permissions.


