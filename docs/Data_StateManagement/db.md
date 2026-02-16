# Resource Shell (resh) – Database Handle Documentation

## 1. Overview

Resource Shell (resh) is a structured command-line framework that standardizes infrastructure operations through a resource-oriented URI execution model.

The `db://` handle provides structured access to SQL databases, including:

* SQLite
* PostgreSQL
* MySQL / MariaDB

It supports:

* Connection management
* Query execution
* Data modification
* Schema inspection
* Transaction control
* Health verification

Traditional database CLI usage typically involves:

* Driver-specific command tools
* Manual connection lifecycle management
* Unstructured output
* Ad hoc transaction handling
* Text parsing of results

The `db://` handle addresses these issues by:

* Providing a consistent URI-based command structure
* Supporting both explicit connect and auto-connect workflows
* Returning structured JSON output
* Enforcing parameter binding for safe query execution
* Supporting deterministic automation integration

All operations follow the URI format:

```
db://driver/alias.verb(options)
```

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

All database operations follow:

```
db://driver/alias.verb(arguments)
```

This standardizes interaction across different SQL engines.

### Safety-First Execution

The handle enforces:

* Parameterized SQL execution
* Explicit transaction boundaries
* Timeout controls
* Structured error reporting
* TLS configuration support

These controls reduce injection risk and operational instability.

### Deterministic Behavior

Operations:

* Return structured JSON
* Provide consistent metadata envelopes
* Separate data from execution metadata
* Use explicit status indicators

### JSON-Based Structured Output

Query and exec operations return:

* Structured row arrays
* Metadata describing columns
* Rows affected counts
* Explicit scalar values

This eliminates reliance on text parsing in automation.

### AI-Readiness

The predictable grammar and structured output allow orchestration agents and automation frameworks to interact with databases safely and deterministically.

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
db://driver/alias.verb(options)
```

#### Components

| Component | Description                      |
| --------- | -------------------------------- |
| `db`      | Handle identifier                |
| `driver`  | `sqlite`, `postgres`, or `mysql` |
| `alias`   | Logical connection name          |
| `verb`    | Database operation               |
| `options` | Named parameters                 |

---

### Examples

Connect to SQLite:

```bash
resh db://sqlite/mydb.connect dsn=sqlite:///path/to/database.db
```

Auto-connect query:

```bash
resh db://mysql/stocks.query \
  dsn='mysql://user:pass@host:3306/stocks' \
  sql="SELECT COUNT(*) FROM stocks"
```

Insert row:

```bash
resh db://postgres/app.exec \
  dsn='postgresql://user:pass@localhost:5432/appdb' \
  sql="INSERT INTO users (email) VALUES ($1)" \
  params='["alice@example.com"]'
```

Begin transaction:

```bash
resh db://postgres/app.transaction action=begin
```

---

### 3.2 Execution Semantics

All operations return structured JSON responses.

#### Query Example (rows mode)

```json
{
  "rows": [
    {"id": 1, "email": "alice@example.com"},
    {"id": 2, "email": "bob@example.com"}
  ],
  "meta": {
    "row_count": 2,
    "truncated": false,
    "columns": [
      {"name": "id", "type": "INTEGER", "ordinal": 1},
      {"name": "email", "type": "TEXT", "ordinal": 2}
    ]
  }
}
```

#### Exec Example

```json
{
  "rows_affected": 1
}
```

#### Ping Example

```json
{
  "status": "ok",
  "driver": "postgres",
  "alias": "app",
  "attempts": 1,
  "latency_ms": 12
}
```

Automation systems should evaluate structured response fields and error codes instead of parsing raw output.

---

## 4. Functional Domain – Database Handle

---

### 4.1 Supported Drivers

| Driver     | Description                         |
| ---------- | ----------------------------------- |
| `sqlite`   | Embedded file or in-memory database |
| `postgres` | PostgreSQL server                   |
| `mysql`    | MySQL/MariaDB server                |

---

### 4.2 Available Verbs

| Verb          | Description                          |
| ------------- | ------------------------------------ |
| `connect`     | Establish connection using DSN       |
| `query`       | Execute SELECT statements            |
| `exec`        | Execute INSERT/UPDATE/DELETE         |
| `tables`      | List or describe tables              |
| `schema`      | Retrieve detailed schema metadata    |
| `ping`        | Test connection health               |
| `transaction` | Begin, commit, rollback transactions |

---

### 4.3 Auto-Connect Capability

The `query` and `exec` verbs support auto-connect when `dsn` is provided.

**Traditional Workflow:**

```bash
resh db://mysql/app.connect dsn='mysql://user:pass@host:3306/app'
resh db://mysql/app.query sql="SELECT COUNT(*) FROM users"
```

**Auto-Connect Workflow:**

```bash
resh db://mysql/app.query \
  dsn='mysql://user:pass@host:3306/app' \
  sql="SELECT COUNT(*) FROM users"
```

Use auto-connect for CLI and short-lived tasks. Use explicit connect for pooled or transactional workflows.

---

### 4.4 Parameter Binding

All SQL execution supports parameter binding.

#### SQLite / MySQL

```bash
sql="SELECT * FROM users WHERE id = ?"
params='[1]'
```

#### PostgreSQL

```bash
sql="SELECT * FROM users WHERE id = $1"
params='[1]'
```

This prevents SQL injection and ensures proper type handling.

---

### 4.5 Transactions

Transaction management:

```bash
# Begin
resh db://postgres/app.transaction action=begin

# Commit
resh db://postgres/app.transaction action=commit tx_id=<uuid>

# Rollback
resh db://postgres/app.transaction action=rollback tx_id=<uuid>
```

Isolation levels supported:

* `default`
* `read_uncommitted`
* `read_committed`
* `repeatable_read`
* `serializable`

Queries and exec operations may include `tx_id` to execute within a transaction.

---

### 4.6 Schema Inspection

Retrieve table list:

```bash
resh db://sqlite/mydb.tables
```

Describe table:

```bash
resh db://sqlite/mydb.tables table=users
```

Detailed schema:

```bash
resh db://postgres/mydb.schema \
  table=users \
  include_indexes=true \
  include_foreign_keys=true
```

---

### 4.7 Health Checking

Ping example:

```bash
resh db://postgres/mydb.ping timeout_ms=2000 retries=2
```

Returns latency and connection metadata.

---

## 5. Platform Support

| Platform   | Support Level |
| ---------- | ------------- |
| Linux      | Supported     |
| macOS/Unix | Supported     |
| Windows    | Supported     |

Database functionality depends on network access and driver compatibility.

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Always use parameterized SQL.
* Avoid embedding credentials in scripts.
* Use TLS for remote databases.
* Limit result sets using `max_rows`.
* Set appropriate timeouts.

### Automation Considerations

* Use structured JSON responses for pipeline gating.
* Validate `rows_affected` or `value` fields.
* Implement retry logic for network databases.
* Monitor connection pool settings.

### CI/CD Integration

* Run schema validation checks.
* Execute migration validation queries.
* Use ping checks before deployment.
* Wrap deployment steps in transactions where appropriate.

### Production Recommendations

* Use connection pooling parameters appropriately.
* Enforce least-privilege database users.
* Monitor slow queries.
* Back up data before structural changes.
* Commit or rollback transactions promptly.

---

## 7. Use Cases by Role

### DevOps Engineers

* Validate database state during deployments.
* Run migration checks.
* Execute maintenance scripts safely.
* Integrate structured queries into CI pipelines.

### SRE Engineers

* Monitor connection health with ping.
* Inspect schema during incident analysis.
* Manage transactions for safe remediation.
* Analyze performance using structured query results.

### Network Administrators

* Validate database connectivity.
* Inspect table structures.
* Monitor authentication and TLS settings.

### AI/Automation Engineers

* Execute deterministic SQL queries.
* Use structured responses for workflow decisions.
* Automate schema inspection.
* Integrate transaction-controlled operations into orchestration engines.

---

## 8. Technical Foundation

The `db://` handle is implemented within resh, written in Rust.

### Rust Implementation Advantages

* Memory safety
* Strong type guarantees
* Structured error propagation
* Efficient async database drivers

### Type Safety

Arguments and parameter bindings are type-validated to reduce runtime ambiguity and injection risk.

### Performance Characteristics

* Efficient connection pooling
* Configurable timeouts
* Structured metadata reporting
* Deterministic execution semantics

### Cross-Platform Architecture

Supported across:

* Linux
* macOS/Unix
* Windows

Behavior is dependent on database driver support and network configuration.

