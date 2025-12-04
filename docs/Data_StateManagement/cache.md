# Cache Handle Documentation

The Cache Handle lets you store and get data from fast memory storage systems like Redis and Memcached. Think of cache systems like super-fast temporary storage that helps your programs run quicker by keeping commonly used information nearby.

## What Cache Systems Are Supported?

The system works with these popular cache systems:

- **Redis** - A powerful in-memory data store that's great for storing various types of data
- **Memcached** - A simple, high-performance memory caching system

## How to Connect

To use a cache system, you need to specify which one and give it a name (alias). The format looks like:
```
cache://redis/alias_name
cache://memcached/alias_name
```

If you don't provide an alias name, it will use "default".

## Cache Commands (Verbs)

**Note:** Examples marked as "based on source implementation" indicate verbs that do not currently have unit tests. All other examples are derived from and verified against actual unit tests.

**Test-verified verbs:** connect, get, set (single), del, incr, exists  
**Implementation-based verbs:** set (multiple), keys, ttl

### Connect - Setting Up Connection

**What it does:** Creates a connection to your cache system so you can use it.

**Required settings:**
- `url` - Connection URL for the cache system (e.g., `redis://localhost:6379/0` for Redis)

**Example use:**
```
cache://redis/main.connect url=${TEST_REDIS_URL}
```

**Expected output:**
```json
{
  "backend": "redis",
  "alias": "main", 
  "status": "connected"
}
```

### Get - Getting Stored Values

**What it does:** Gets one or more values that were saved in the cache.

**Required settings:**
- Either `key` - Single item to get
- Or `keys` - Multiple items to get (as JSON array like `["key1", "key2"]`)

**Optional settings:**
- `namespace` - Group name to organize keys (like putting keys in folders)
- `timeout_ms` - How long to wait in milliseconds (default: 1000)
- `decode` - How to read the data: "utf8" (text), "bytes" (binary), or "json" (structured data)
- `default` - What to return if the key doesn't exist

**Example use - Single key:**
```
cache://redis/main.get key=test:nonexistent default="fallback" decode=utf8
```

**Expected output:**
```json
{
  "key": "test:nonexistent",
  "value": "fallback",
  "backend": "redis",
  "alias": "main",
  "hit": false
}
```

**Example use - Multiple keys:**
```
cache://redis/main.get keys=["test:key1", "test:key2", "test:missing"] decode=utf8
```

**Expected output:**
```json
{
  "backend": "redis",
  "alias": "main",
  "results": [
    {"key": "test:key1", "value": null, "hit": false},
    {"key": "test:key2", "value": null, "hit": false},
    {"key": "test:missing", "value": null, "hit": false}
  ]
}
```

**Example use - With namespace:**
```
cache://redis/main.get key=session:123 namespace=prod decode=utf8
```

**Expected output:**
```json
{
  "key": "session:123",
  "value": null,
  "backend": "redis",
  "alias": "main",
  "hit": false
}
```

### Set - Storing Values

**What it does:** Saves one or more values to the cache for later use.

**Required settings:**
- Either `key` and `value` - Single item to save
- Or `keys` and `values` - Multiple items to save (arrays must be same length)

**Optional settings:**
- `namespace` - Group name to organize keys
- `ttl_ms` - How long to keep the data in milliseconds (Time To Live)
- `timeout_ms` - How long to wait for the operation (default: 1000)
- `encode` - How to store the data: "utf8" (text), "bytes" (binary), or "json" (structured data)
- `only_if_not_exists` - Only save if the key doesn't already exist (true/false)
- `only_if_exists` - Only save if the key already exists (true/false)

**Example use - Single value:**
```
cache://redis/main.set key=test_key value=hello_world encode=utf8 namespace=test:set:uuid
```

**Expected output:**
```json
{
  "backend": "redis",
  "alias": "main",
  "key": "test_key",
  "stored": true
}
```

**Example use - Multiple values:**
```
**Example use - Multiple values:**\n```\ncache://redis/main.set keys=[\"user:123\", \"user:456\"] values=[\"John Doe\", \"Jane Smith\"]\n```\n\n**Expected output (based on source implementation):**\n```json\n{\n  \"backend\": \"redis\",\n  \"alias\": \"main\",\n  \"results\": [\n    {\"key\": \"user:123\", \"stored\": true},\n    {\"key\": \"user:456\", \"stored\": true}\n  ],\n  \"total_stored\": 2\n}\n```
```

**Expected output:**
```json
{
  "backend": "redis",
  "alias": "main",
  "results": [
    {"key": "user:123", "stored": true},
    {"key": "user:456", "stored": true}
  ],
  "total_stored": 2
}
```

**Example use - With expiration:**
```
cache://redis/main.set key=ttl_key value=temp_value ttl_ms=100 encode=utf8 namespace=test:ttl:uuid
```

**Expected output:**
```json
{
  "backend": "redis",
  "alias": "main",
  "key": "ttl_key",
  "stored": true,
  "ttl_ms": 100
}
```

### Del - Deleting Values

**What it does:** Removes one or more items from the cache.

**Required settings:**
- Either `key` - Single item to delete
- Or `keys` - Multiple items to delete (as JSON array)

**Optional settings:**
- `namespace` - Group name where the keys are located
- `timeout_ms` - How long to wait for the operation (default: 1000)

**Example use - Single key:**
```
cache://redis/main.del key=test_key namespace=test:del:uuid
```

**Expected output:**
```json
{
  "backend": "redis",
  "alias": "main",
  "key": "test_key",
  "deleted": true
}
```

**Example use - Multiple keys:**
```
cache://redis/main.del keys=["key1", "key2", "key3"] namespace=test:del:uuid
```

**Expected output:**
```json
{
  "backend": "redis",
  "alias": "main",
  "results": [
    {"key": "key1", "deleted": true},
    {"key": "key2", "deleted": true},
    {"key": "key3", "deleted": false}
  ],
  "total_deleted": 2
}
```

### Incr - Increasing Numbers

**What it does:** Increases a number stored in the cache. Great for counters like page views or user scores.

**Required settings:**
- `key` - The item to increase

**Optional settings:**
- `namespace` - Group name where the key is located
- `by` - How much to increase by (default: 1)
- `initial` - Starting value if the key doesn't exist
- `timeout_ms` - How long to wait for the operation (default: 1000)

**Example use - Simple counter:**
```
cache://redis/main.incr key=counter:new namespace=test:incr:uuid
```

**Expected output:**
```json
{
  "backend": "redis",
  "alias": "main",
  "key": "counter:new",
  "value": 1,
  "created": true
}
```

**Example use - Increase by amount:**
```
cache://redis/main.incr key=counter:new namespace=test:incr:uuid by=5
```

**Expected output:**
```json
{
  "backend": "redis",
  "alias": "main",
  "key": "counter:new",
  "value": 6,
  "created": false
}
```

### Exists - Checking if Items Exist

**What it does:** Checks whether one or more items are stored in the cache.

**Required settings:**
- Either `key` - Single item to check
- Or `keys` - Multiple items to check (as JSON array)

**Optional settings:**
- `namespace` - Group name where the keys might be located
- `timeout_ms` - How long to wait for the operation (default: 1000)

**Example use - Single key:**
```
cache://redis/main.exists key=test:exists:single:12345
```

**Expected output:**
```json
{
  "backend": "redis",
  "alias": "main",
  "key": "test:exists:single:12345",
  "exists": false
}
```

**Example use - Multiple keys:**
```
cache://redis/main.exists keys=[test:exists:multi1:12345,test:exists:multi2:12345,test:exists:multi3:12345]
```

**Expected output:**
```json
{
  "backend": "redis",
  "alias": "main",
  "results": [
    {"key": "test:exists:multi1:12345", "exists": true},
    {"key": "test:exists:multi2:12345", "exists": true},
    {"key": "test:exists:multi3:12345", "exists": false}
  ],
  "total_exists": 2
}
```

### Keys - Finding Items by Pattern

**What it does:** Searches for items in the cache that match a pattern. Like searching for files with similar names.

**Required settings:** None (searches for everything by default)

**Optional settings:**
- `pattern` - What to search for, using * as wildcard (default: "*" for everything)
- `namespace` - Group name to search within
- `cursor` - Where to start searching (for getting more results)
- `limit` - Maximum number of results to return (default: 100)
- `timeout_ms` - How long to wait for the operation (default: 1000)

**Example use - Find all user keys:**
```
cache://redis/main.keys pattern=user:*
```

**Expected output (based on source implementation):**
```json
{
  "backend": "redis",
  "alias": "main",
  "keys": ["user:123", "user:456", "user:789"],
  "cursor": null,
  "has_more": false,
  "count": 3
}
```

**Example use - Find with limit:**
```
cache://redis/main.keys pattern=session:* limit=50
```

**Expected output (based on source implementation):**
```json
{
  "backend": "redis",
  "alias": "main",
  "keys": ["session:abc", "session:def", "session:ghi"],
  "cursor": "next_cursor_value",
  "has_more": true,
  "count": 3
}
```

### TTL - Checking Expiration Time

**What it does:** Shows how much time is left before an item gets automatically deleted from the cache.

**Required settings:**
- Either `key` - Single item to check
- Or `keys` - Multiple items to check (as JSON array)

**Optional settings:**
- `namespace` - Group name where the keys are located
- `timeout_ms` - How long to wait for the operation (default: 1000)

**Example use - Single key:**
```
cache://redis/main.ttl key=session:abc123
```

**Expected output (based on source implementation):**
```json
{
  "backend": "redis",
  "alias": "main",
  "key": "session:abc123",
  "exists": true,
  "supports_ttl": true,
  "has_expiry": true,
  "ttl_ms": 250000
}
```

**Example use - Multiple keys:**
```
cache://redis/main.ttl keys=["session:abc", "permanent:key"]
```

**Expected output (based on source implementation):**
```json
{
  "backend": "redis",
  "alias": "main",
  "results": [
    {"key": "session:abc", "exists": true, "supports_ttl": true, "has_expiry": true, "ttl_ms": 250000},
    {"key": "permanent:key", "exists": true, "supports_ttl": true, "has_expiry": false, "ttl_ms": null}
  ],
  "found": 2
}
```

## Understanding Namespaces

Namespaces help organize your cached data like folders on a computer:

- Without namespace: `user:123` is stored as `user:123`
- With namespace "production": `user:123` is stored as `production:user:123`

This helps separate data for different environments (like production vs testing).

## Data Encoding Options

**UTF8 (default):** For regular text like names, messages, or simple data
**JSON:** For structured data like objects with multiple fields  
**Bytes:** For binary data like images or files (uses base64 encoding)

## Time Settings

All time values are in milliseconds:
- 1 second = 1,000 milliseconds
- 1 minute = 60,000 milliseconds  
- 1 hour = 3,600,000 milliseconds

## Common Examples

**Store user information:**
```
cache://redis/main set key=user:john value='{"name":"John","email":"john@example.com"}' encode=json
```

**Get user information:**
```
cache://redis/main get key=user:john decode=json
```

**Create a counter:**
```
cache://redis/main set key=page_views value=0
cache://redis/main incr key=page_views
```

**Store with expiration (5 minutes):**
```
cache://redis/main set key=temp_data value="expires soon" ttl_ms=300000
```

**Check multiple items:**
```
cache://redis/main exists keys='["user:1", "user:2", "user:3"]'
```

**Find all session keys:**
```
cache://redis/main keys pattern="session:*"
```

## Error Handling

The cache system will return error information when something goes wrong:

```json
{
  "error": true,
  "message": "Connection timeout after 1000ms",
  "code": "TIMEOUT"
}
```

Common errors include timeouts, connection problems, or invalid parameters.