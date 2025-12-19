# Database Handle (db://)

The Database handle provides access to SQL databases including SQLite, PostgreSQL, and MySQL. You can run queries, manage transactions, inspect table schemas, and more.

**Auto-Connect Feature**: Query and exec verbs now support automatic connection establishment when a DSN parameter is provided, eliminating the need for separate connect commands in many CLI scenarios.

## Available Verbs

The db handle supports these verbs:
- `connect` - Connect to a database
- `query` - Run SELECT queries and get results  
- `exec` - Run INSERT, UPDATE, DELETE statements
- `tables` - List tables or describe table structure
- `schema` - Get detailed table schema information
- `ping` - Test database connection health
- `transaction` - Manage database transactions

## Connect Verb

Establishes a connection to a database using a Data Source Name (DSN).

### Basic Usage

```bash
# SQLite in-memory database
resh db://sqlite/mydb.connect dsn=sqlite::memory:

# SQLite file database  
resh db://sqlite/mydb.connect dsn=sqlite:///path/to/database.db

# PostgreSQL database
resh db://postgres/mydb.connect dsn=postgresql://user:pass@localhost:5432/dbname

# MySQL database
resh db://mysql/mydb.connect dsn=mysql://user:pass@localhost:3306/dbname
```

### Configuration Options

```bash
# Connection with custom pool settings
resh db://postgres/mydb.connect \
  dsn=postgresql://user:pass@localhost:5432/dbname \
  max_connections=10 \
  min_connections=2 \
  connect_timeout_ms=30000 \
  idle_timeout_ms=600000 \
  max_lifetime_ms=1800000

# Connection with TLS settings  
resh db://postgres/mydb.connect \
  dsn=postgresql://user:pass@localhost:5432/dbname \
  tls_mode=require
```

### Example Output

```json
{
  "type": "db_connection",
  "driver": "sqlite",
  "alias": "mydb", 
  "reused": false,
  "pool_stats": {
    "active_connections": 1,
    "idle_connections": 0,
    "max_connections": 10,
    "min_connections": 1
  }
}
```

## Query Verb

Runs SQL SELECT statements and returns results in different formats. Supports both traditional workflow (connect first) and auto-connect (provide DSN with query).

### Traditional Query Examples (after connect)

```bash
# First connect to database
resh db://sqlite/mydb.connect dsn=sqlite:///path/to/database.db

# Then query
resh db://sqlite/mydb.query \
  sql="SELECT id, email FROM users WHERE active = ?" \
  params='[true]' \
  mode=rows
```

### Auto-Connect Query Examples (recommended for CLI)

```bash
# Query with automatic connection establishment
resh db://sqlite/mydb.query \
  dsn=sqlite:///path/to/database.db \
  sql="SELECT id, email FROM users WHERE active = ?" \
  params='[true]' \
  mode=rows

# MySQL auto-connect query
resh db://mysql/stocks.query \
  dsn='mysql://user:pass@host:3306/database' \
  sql="SELECT COUNT(*) FROM stocks WHERE price > ?" \
  params='[100]' \
  mode=scalar

# PostgreSQL auto-connect with complex query
resh db://postgres/analytics.query \
  dsn='postgresql://user:pass@localhost:5432/analytics' \
  sql="SELECT category, AVG(amount) as avg_amount FROM transactions GROUP BY category" \
  mode=rows
```

### Query without Connection (legacy)

```bash
# Query returning single value
resh db://sqlite/mydb.query \
  sql="SELECT COUNT(*) FROM users WHERE active = ?" \
  params='[true]' \
  mode=scalar

# Query with no parameters  
resh db://sqlite/mydb.query \
  sql="SELECT COUNT(*) FROM users" \
  mode=scalar
```

### Query Modes

- `rows` - Returns multiple rows as an array (default)
- `scalar` - Returns single value from first row, first column
- `exec` - For compatibility; use `exec` verb instead for DML

### Query Configuration

```bash
# Query with custom timeout and row limit (traditional)
resh db://sqlite/mydb.query \
  sql="SELECT * FROM users" \
  mode=rows \
  timeout_ms=10000 \
  max_rows=500

# Query with auto-connect and custom configuration
resh db://mysql/mydb.query \
  dsn='mysql://user:pass@host:3306/database' \
  sql="SELECT * FROM large_table" \
  mode=rows \
  timeout_ms=10000 \
  max_rows=500
```

**Auto-Connect Parameters**:
- `dsn` - Database connection string (will auto-connect if no existing connection found)
- When DSN is provided, connection will be established automatically if the alias is not already connected

### Example Output (rows mode)

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

### Example Output (scalar mode)

```json
{
  "value": 2,
  "meta": {
    "row_count": 1,
    "columns": [
      {"name": "COUNT(*)", "type": "INTEGER", "ordinal": 1}
    ]
  }
}
```

## Exec Verb

Runs INSERT, UPDATE, DELETE statements and returns the number of affected rows. Supports both traditional workflow (connect first) and auto-connect (provide DSN with exec).

### Traditional Exec Examples (after connect)

```bash
# First connect to database
resh db://sqlite/mydb.connect dsn=sqlite:///path/to/database.db

# Then execute statements
resh db://sqlite/mydb.exec \
  sql="INSERT INTO users (name, active) VALUES (?, ?)" \
  params='["Alice", true]'
```

### Auto-Connect Exec Examples (recommended for CLI)

```bash
# Insert with automatic connection
resh db://mysql/mydb.exec \
  dsn='mysql://user:pass@host:3306/database' \
  sql="INSERT INTO users (name, email, active) VALUES (?, ?, ?)" \
  params='["Alice", "alice@example.com", true]'

# Update with auto-connect
resh db://postgres/mydb.exec \
  dsn='postgresql://user:pass@localhost:5432/database' \
  sql="UPDATE users SET last_login = NOW() WHERE id = $1" \
  params='[123]'

# Delete with auto-connect
resh db://sqlite/mydb.exec \
  dsn=sqlite:///path/to/database.db \
  sql="DELETE FROM users WHERE active = ?" \
  params='[false]'
```

### Legacy Exec Examples (without connection)

```bash
# Insert with parameters
resh db://sqlite/mydb.exec \
  sql="INSERT INTO users (name, active) VALUES (?, ?)" \
  params='["Alice", true]'

# Update with parameters
resh db://sqlite/mydb.exec \
  sql="UPDATE users SET active = ? WHERE active = ?" \
  params='[false, true]'

# Delete with parameters
resh db://sqlite/mydb.exec \
  sql="DELETE FROM users WHERE active = ?" \
  params='[false]'
```

### Insert with Last Insert ID

```bash
# Get the last inserted ID (SQLite/MySQL) - traditional
resh db://sqlite/mydb.exec \
  sql="INSERT INTO users (name, active) VALUES (?, ?)" \
  params='["Bob", true]' \
  return_last_insert_id=true

# Get the last inserted ID with auto-connect
resh db://mysql/mydb.exec \
  dsn='mysql://user:pass@host:3306/database' \
  sql="INSERT INTO products (name, price) VALUES (?, ?)" \
  params='["Widget", 19.99]' \
  return_last_insert_id=true
```

### Exec Configuration

```bash
# Exec with custom timeout (traditional)
resh db://postgres/mydb.exec \
  sql="UPDATE large_table SET status = $1 WHERE processed = $2" \
  params='["completed", false]' \
  timeout_ms=30000

# Exec with auto-connect and custom timeout
resh db://postgres/mydb.exec \
  dsn='postgresql://user:pass@localhost:5432/database' \
  sql="UPDATE large_table SET status = $1 WHERE processed = $2" \
  params='["completed", false]' \
  timeout_ms=30000
```

### Example Output

```json
{
  "rows_affected": 1
}
```

### Example Output (with last insert ID)

```json
{
  "rows_affected": 1,
  "last_insert_id": 123
}
```

## Tables Verb

Lists tables in the database or describes a specific table's structure.

### List All Tables

```bash
# List base tables only
resh db://sqlite/mydb.tables

# List tables and views
resh db://sqlite/mydb.tables include_views=true

# List with custom limits
resh db://postgres/mydb.tables \
  max_tables=100 \
  timeout_ms=10000
```

### Describe Specific Table

```bash
# Get table structure
resh db://sqlite/mydb.tables table=users

# Include system tables in schema information
resh db://postgres/mydb.tables \
  table=users \
  include_system=true
```

### Example Output (list mode)

```json
{
  "tables": [
    {
      "name": "users",
      "type": "BASE TABLE",
      "schema": "main"
    },
    {
      "name": "orders", 
      "type": "BASE TABLE",
      "schema": "main"
    }
  ],
  "meta": {
    "truncated": false,
    "table_count": 2
  }
}
```

### Example Output (describe mode)

```json
{
  "table": {
    "name": "users",
    "type": "BASE TABLE",
    "schema": "main"
  },
  "columns": [
    {
      "name": "id",
      "data_type": "INTEGER", 
      "is_nullable": false,
      "is_primary_key": true,
      "ordinal_position": 1,
      "default_value": null
    },
    {
      "name": "email",
      "data_type": "TEXT",
      "is_nullable": false, 
      "is_primary_key": false,
      "ordinal_position": 2,
      "default_value": null
    }
  ]
}
```

## Schema Verb

Gets detailed schema information for a specific table including indexes, foreign keys, and constraints.

### Basic Schema Examples

```bash
# Get basic table schema
resh db://sqlite/mydb.schema table=users

# Get schema with indexes
resh db://sqlite/mydb.schema \
  table=users \
  include_indexes=true

# Get complete schema information
resh db://postgres/mydb.schema \
  table=users \
  include_indexes=true \
  include_foreign_keys=true \
  include_unique_constraints=true
```

### Schema Configuration Options

- `include_indexes=true` - Include index information
- `include_foreign_keys=true` - Include foreign key relationships
- `include_unique_constraints=true` - Include unique constraints
- `include_checks=true` - Include check constraints  
- `include_triggers=true` - Include trigger information
- `timeout_ms=5000` - Custom timeout

### Example Output

```json
{
  "table": {
    "name": "users",
    "type": "BASE TABLE",
    "schema": "main"
  },
  "columns": [
    {
      "name": "id", 
      "data_type": "INTEGER",
      "is_nullable": false,
      "is_primary_key": true,
      "ordinal_position": 1,
      "default_value": null
    },
    {
      "name": "email",
      "data_type": "TEXT", 
      "is_nullable": false,
      "is_primary_key": false,
      "ordinal_position": 2,
      "default_value": null
    }
  ],
  "primary_key": {
    "name": "users_pkey",
    "columns": ["id"]
  },
  "indexes": [
    {
      "name": "idx_users_email",
      "columns": ["email"],
      "is_unique": true,
      "is_primary": false
    }
  ],
  "foreign_keys": [
    {
      "name": "fk_users_account",
      "columns": ["account_id"],
      "referenced_table": {
        "schema": "main",
        "name": "accounts"  
      },
      "referenced_columns": ["id"],
      "on_delete": "CASCADE",
      "on_update": "RESTRICT"
    }
  ]
}
```

## Ping Verb

Tests database connection health and measures response time.

### Basic Ping Examples

```bash
# Simple ping test
resh db://sqlite/mydb.ping

# Ping with custom timeout
resh db://postgres/mydb.ping timeout_ms=2000

# Ping with retries and backoff
resh db://mysql/mydb.ping \
  timeout_ms=1000 \
  retries=3 \
  backoff_ms=500

# Detailed ping information
resh db://sqlite/mydb.ping detailed=true
```

### Ping Configuration Options

- `timeout_ms=1000` - Connection timeout (1ms to max)
- `retries=0` - Number of retry attempts (0 to 10)
- `backoff_ms=100` - Delay between retries
- `detailed=false` - Include extra connection information

### Example Output (success)

```json
{
  "status": "ok",
  "driver": "sqlite",
  "alias": "mydb", 
  "attempts": 1,
  "latency_ms": 2
}
```

### Example Output (detailed)

```json
{
  "status": "ok",
  "driver": "postgres",
  "alias": "mydb",
  "attempts": 1, 
  "latency_ms": 15,
  "details": {
    "pool_stats": {
      "active_connections": 2,
      "idle_connections": 3,
      "max_connections": 10
    }
  }
}
```

## Transaction Verb

Manages database transactions with begin, commit, and rollback operations.

### Begin Transaction

```bash
# Start basic transaction
resh db://sqlite/mydb.transaction action=begin

# Start with specific isolation level
resh db://postgres/mydb.transaction \
  action=begin \
  isolation=serializable \
  read_only=false \
  timeout_ms=15000
```

### Commit Transaction

```bash
# Commit transaction using transaction ID
resh db://sqlite/mydb.transaction \
  action=commit \
  tx_id=550e8400-e29b-41d4-a716-446655440000
```

### Rollback Transaction  

```bash
# Rollback transaction using transaction ID
resh db://postgres/mydb.transaction \
  action=rollback \
  tx_id=550e8400-e29b-41d4-a716-446655440000
```

### Transaction Isolation Levels

- `default` - Use database default
- `read_uncommitted` - Allow dirty reads
- `read_committed` - Prevent dirty reads (PostgreSQL default)
- `repeatable_read` - Prevent non-repeatable reads (MySQL default)
- `serializable` - Full isolation

### Example Output (begin)

```json
{
  "status": "ok",
  "action": "begin", 
  "driver": "postgres",
  "alias": "mydb",
  "tx_id": "550e8400-e29b-41d4-a716-446655440000",
  "isolation": "read_committed",
  "read_only": false
}
```

### Example Output (commit/rollback)

```json
{
  "status": "ok",
  "action": "commit",
  "tx_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

## Using Transactions with Queries

Once you have a transaction ID, you can use it with query and exec verbs:

```bash
# Start transaction
resh db://postgres/mydb.transaction action=begin

# Run query within transaction 
resh db://postgres/mydb.query \
  sql="SELECT COUNT(*) FROM users WHERE name = $1" \
  params='["John PostgreSQL"]' \
  mode=scalar \
  tx_id=550e8400-e29b-41d4-a716-446655440000

# Insert within transaction
resh db://postgres/mydb.exec \
  sql="INSERT INTO users (name) VALUES ($1)" \
  params='["John PostgreSQL"]' \
  tx_id=550e8400-e29b-41d4-a716-446655440000

# Commit transaction
resh db://postgres/mydb.transaction \
  action=commit \
  tx_id=550e8400-e29b-41d4-a716-446655440000
```

## Auto-Connect Feature

The auto-connect feature allows query and exec verbs to automatically establish database connections when a DSN parameter is provided. This eliminates the need for separate connect commands in CLI workflows.

### How Auto-Connect Works

1. When a `query` or `exec` command includes a `dsn` parameter
2. If no existing connection is found for the specified alias  
3. A connection is automatically established using the provided DSN
4. The command then executes using the new connection

### Auto-Connect vs Traditional Workflow

**Traditional Workflow:**
```bash
# Step 1: Connect explicitly
resh db://mysql/stocks.connect dsn='mysql://user:pass@host:3306/stocks'

# Step 2: Execute query
resh db://mysql/stocks.query sql="SELECT COUNT(*) FROM stocks"
```

**Auto-Connect Workflow:**
```bash
# Single step: Query with automatic connection
resh db://mysql/stocks.query \
  dsn='mysql://user:pass@host:3306/stocks' \
  sql="SELECT COUNT(*) FROM stocks"
```

### Best Practices

**Use Auto-Connect For:**
- One-off CLI queries and commands
- Batch processing scripts
- Quick data exploration
- Simple automation tasks

**Use Traditional Connect For:**
- Long-running applications
- Multiple operations on same connection
- Transaction-based workflows
- Connection pooling scenarios

### Auto-Connect with Special Characters

When passwords contain shell special characters, use single quotes around the DSN:

```bash
# Password contains $ character - use single quotes
resh db://mysql/prod.query \
  dsn='mysql://user:P@ssw0rd$123@host:3306/database' \
  sql="SELECT version()"

# Alternative: URL-encode special characters  
resh db://mysql/prod.query \
  dsn=mysql://user:P@ssw0rd%24123@host:3306/database \
  sql="SELECT version()"
```

## Parameter Binding

All verbs that accept SQL support parameter binding to prevent SQL injection:

### SQLite Parameter Style

```bash
# Positional parameters with ?
resh db://sqlite/mydb.query \
  sql="SELECT * FROM users WHERE id = ? AND active = ?" \
  params='[1, true]'
```

### PostgreSQL Parameter Style  

```bash
# Positional parameters with $1, $2, etc.
resh db://postgres/mydb.query \
  sql="SELECT * FROM users WHERE id = $1 AND active = $2" \
  params='[1, true]'
```

### MySQL Parameter Style

```bash  
# Positional parameters with ?
resh db://mysql/mydb.query \
  sql="SELECT * FROM users WHERE id = ? AND active = ?" \
  params='[1, true]'
```

### Supported Parameter Types

- Strings: `"text value"`
- Numbers: `42`, `3.14`
- Booleans: `true`, `false`  
- Null: `null`

## Error Handling

All verbs return structured error information when operations fail:

### Example Error Output

```json
{
  "error": {
    "code": "db.connection_not_found",
    "message": "Connection not found for driver 'postgres', alias 'nonexistent'",
    "details": {
      "driver": "postgres", 
      "alias": "nonexistent"
    }
  }
}
```

### Common Error Codes

- `db.unsupported_driver` - Database driver not supported
- `db.connection_not_found` - No connection exists for the alias
- `db.invalid_config` - Invalid connection configuration
- `db.missing_dsn` - Data Source Name not provided
- `db.query_failed` - SQL query execution failed
- `db.exec_failed` - SQL execution failed  
- `db.query_timeout` - Query exceeded timeout limit
- `db.table_not_found` - Table does not exist
- `db.transaction_not_found` - Transaction ID not found
- `db.transaction_timeout` - Transaction exceeded timeout

## Database-Specific Notes

### SQLite

- In-memory databases use `sqlite::memory:` DSN
- File databases use `sqlite:///path/to/file.db` DSN
- Supports transactions, but limited concurrency
- Foreign keys must be enabled with `PRAGMA foreign_keys = ON`

### PostgreSQL  

- Uses `$1, $2` parameter placeholders
- Full ACID transaction support
- Rich schema introspection capabilities
- Supports multiple isolation levels

### MySQL

- Uses `?` parameter placeholders  
- Full transaction support
- Supports AUTO_INCREMENT with last_insert_id
- Schema introspection varies by version

## Best Practices

1. **Always use parameters** instead of string concatenation for SQL queries
2. **Use transactions** for multiple related operations
3. **Set appropriate timeouts** for long-running operations  
4. **Close transactions** promptly with commit or rollback
5. **Use connection pooling** settings appropriate for your workload
6. **Test connections** with ping before critical operations
7. **Handle errors gracefully** by checking error codes in responses