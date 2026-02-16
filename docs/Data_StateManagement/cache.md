# Resource Shell (resh) – Cache Handle Documentation

## 1. Overview

Resource Shell (resh) is a structured command-line framework that standardizes system automation using a resource-oriented URI execution model.

The `cache://` handle provides high-performance access to in-memory data stores, specifically Redis and Memcached. It enables structured storage, retrieval, mutation, and inspection of cached data through a consistent URI-based interface.

Traditional cache interaction typically involves:

* Backend-specific CLI tools
* Direct driver integration in application code
* Unstructured command output
* Manual error handling
* Inconsistent key management patterns

The `cache://` handle addresses these issues by:

* Providing a uniform resource-oriented command structure
* Supporting multiple cache backends through a consistent interface
* Returning structured JSON responses
* Enabling deterministic automation and orchestration workflows

All cache operations follow the resh URI pattern:

```
cache://backend/alias.verb(options)
```

Where:

* `backend` identifies the cache system (`redis`, `memcached`)
* `alias` identifies a named connection profile
* `verb` defines the operation
* `options` define execution parameters

---

## 2. Design Philosophy and Core Principles

The `cache://` handle adheres to resh architectural principles.

### Structured Interface Model

All cache operations follow:

```
cache://backend/alias.verb(options)
```

This standardizes access to Redis and Memcached through a consistent command grammar.

### Safety-First Execution

Operations include:

* Explicit timeout controls (`timeout_ms`)
* Conditional writes (`only_if_not_exists`, `only_if_exists`)
* Structured error reporting
* Namespace isolation

These reduce unintended overwrites and unsafe concurrency behavior.

### Deterministic Behavior

Each operation:

* Produces structured JSON output
* Separates metadata from payload
* Uses explicit success/error indicators
* Provides consistent field names across verbs

### JSON-Based Structured Output

All responses are machine-readable, enabling:

* CI/CD pipeline integration
* Monitoring system ingestion
* Programmatic cache inspection
* Automation gating

### AI-Readiness

The structured interface and predictable response format enable safe integration into automated and AI-driven workflows.

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
cache://backend/alias.verb(options)
```

#### Components

| Component | Description                                                                 |
| --------- | --------------------------------------------------------------------------- |
| `cache`   | Handle identifier                                                           |
| `backend` | `redis` or `memcached`                                                      |
| `alias`   | Logical connection profile                                                  |
| `verb`    | Operation (`connect`, `get`, `set`, `del`, `incr`, `exists`, `keys`, `ttl`) |
| `options` | Named execution parameters                                                  |

---

### Example Commands

Connect to Redis:

```sh
cache://redis/main.connect(url="redis://localhost:6379/0")
```

Set value:

```sh
cache://redis/main.set(key="user:123", value="John Doe", encode="utf8")
```

Get value:

```sh
cache://redis/main.get(key="user:123", decode="utf8")
```

Increment counter:

```sh
cache://redis/main.incr(key="page_views", by="1")
```

Check TTL:

```sh
cache://redis/main.ttl(key="session:abc")
```

---

### 3.2 Execution Semantics

All operations return structured JSON envelopes.

#### Representative Success Response

```json
{
  "backend": "redis",
  "alias": "main",
  "key": "user:123",
  "value": "John Doe",
  "hit": true
}
```

#### Representative Error Response

```json
{
  "error": true,
  "message": "Connection timeout after 1000ms",
  "code": "TIMEOUT"
}
```

Automation logic must evaluate structured response fields rather than parsing raw output.

---

## 4. Functional Domains – Cache Handle

---

### 4.1 Supported Backends

| Backend   | Characteristics                                                   |
| --------- | ----------------------------------------------------------------- |
| Redis     | In-memory data store with persistence options and rich features   |
| Memcached | Lightweight, high-performance in-memory cache without persistence |

Redis supports all documented verbs. Memcached supports core key-value operations.

---

### 4.2 Connection Management

**Verb:** `connect`

Required:

* `url`

Example:

```sh
cache://redis/main.connect(url="redis://localhost:6379/0")
```

Expected response:

```json
{
  "backend": "redis",
  "alias": "main",
  "status": "connected"
}
```

---

### 4.3 Key Retrieval

**Verb:** `get`

Supports:

* Single key retrieval
* Batch retrieval
* Namespace prefixing
* Decode formats (`utf8`, `json`, `bytes`)
* Default fallback values

Example:

```sh
cache://redis/main.get(key="session:abc", decode="json")
```

Batch example:

```sh
cache://redis/main.get(keys=["user:1","user:2"])
```

---

### 4.4 Key Storage

**Verb:** `set`

Supports:

* Single or multiple key writes
* TTL configuration (`ttl_ms`)
* Conditional writes
* Encoding options

Example:

```sh
cache://redis/main.set(
  key="session:abc",
  value="{\"user_id\":42}",
  encode="json",
  ttl_ms="1800000"
)
```

---

### 4.5 Key Deletion

**Verb:** `del`

Supports single or batch deletion.

Example:

```sh
cache://redis/main.del(keys=["session:1","session:2"])
```

---

### 4.6 Increment Operations

**Verb:** `incr`

Used for counters and rate tracking.

Example:

```sh
cache://redis/main.incr(key="api_calls", by="10")
```

Response:

```json
{
  "backend": "redis",
  "alias": "main",
  "key": "api_calls",
  "value": 110,
  "created": false
}
```

---

### 4.7 Existence Checks

**Verb:** `exists`

Example:

```sh
cache://redis/main.exists(key="lock:resource")
```

---

### 4.8 Key Discovery

**Verb:** `keys`

Supports pattern matching.

Example:

```sh
cache://redis/main.keys(pattern="user:*")
```

---

### 4.9 Expiration Inspection

**Verb:** `ttl`

Example:

```sh
cache://redis/main.ttl(key="session:abc")
```

---

### 4.10 Namespaces

Namespaces prepend logical prefixes to keys for environment isolation:

* Without namespace: `user:123`
* With namespace `prod`: `prod:user:123`

This enables separation of development, staging, and production environments.

---

### 4.11 Encoding Options

| Format  | Use Case                     |
| ------- | ---------------------------- |
| `utf8`  | Plain text values            |
| `json`  | Structured data              |
| `bytes` | Binary data (base64 encoded) |

---

## 5. Platform Support

| Platform   | Support Level |
| ---------- | ------------- |
| Linux      | Supported     |
| Unix/macOS | Supported     |
| Windows    | Supported     |

Functionality depends on availability of Redis or Memcached services.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Use TTL values to prevent memory bloat.
* Use namespaces to isolate environments.
* Avoid unbounded key patterns in production.
* Use conditional writes for distributed locks.

### Automation Considerations

* Parse JSON output rather than CLI output.
* Validate `hit` or `exists` fields explicitly.
* Implement fallback logic for cache misses.
* Use batch operations for efficiency.

### CI/CD Integration

* Use cache for build artifact acceleration.
* Store ephemeral pipeline state.
* Validate connectivity during pipeline initialization.

### Production Recommendations

* Monitor timeout values.
* Use consistent key naming conventions.
* Apply TTL to session and lock keys.
* Monitor cache hit rates and adjust accordingly.

---

## 7. Use Cases by Role

### DevOps Engineers

* Store build metadata.
* Implement distributed locks.
* Accelerate deployment workflows.

### SRE Engineers

* Monitor cache performance.
* Manage rate-limiting counters.
* Inspect TTL values during incident response.

### Network Administrators

* Store temporary configuration state.
* Track session-based network metrics.
* Implement distributed coordination.

### AI/Automation Engineers

* Use deterministic cache responses for orchestration.
* Implement structured rate limiting.
* Integrate counters into automation workflows.

---

## 8. Technical Foundation

The `cache://` handle operates within resh, implemented in Rust.

### Rust Implementation Advantages

* Memory safety
* Strong compile-time validation
* Deterministic execution model

### Type Safety

Arguments and response structures are type-validated, ensuring consistent contract enforcement.

### Performance Characteristics

* Low-latency in-memory access
* Efficient batch operations
* Controlled timeout enforcement

### Cross-Platform Architecture

Supported across:

* Linux
* macOS/Unix
* Windows

Behavior is dependent on backend service availability and network configuration.


