# Config Handle Documentation

The Resource Shell's config handle provides a powerful way to store, retrieve, list, and watch configuration settings. It supports JSON data storage with hierarchical organization through namespaces and keys.

## How Config Works

Config data is stored as JSON files in a hierarchical directory structure on your filesystem. Each configuration item has:

- **Namespace**: A top-level grouping (like "app", "db", "cache")
- **Key**: A specific configuration item within that namespace (like "url", "timeout", "enabled")
- **Value**: JSON data of any type (string, number, boolean, object, array)

Config files are stored in `~/.config/resh/config/` by default.

## URL Format

Config URLs follow this pattern:
```
config://namespace/key
config://namespace/path/to/key
config://key                    (uses "default" namespace)
```

## Available Operations

The config handle supports four main operations:

### get - Retrieve Configuration Values

Gets the value of a configuration key.

**Basic Usage:**
```bash
config://test/theme.get
```
**Output:** `{"theme":"dark","font_size":14}`

**With Default Namespace:**
```bash
config://mykey.get
```
**Output:** `{"value":"test"}`

**Error Cases:**
- Missing key returns exit code 1
- Invalid JSON in config file returns exit code 2

### set - Store Configuration Values

Stores a value for a configuration key. Values can be stored as JSON or as strings.

**Basic Usage (String Value):**
```bash
config://test/plain.set(value=dark)
```
Creates a JSON string: `"dark"`

**Raw JSON Mode:**
```bash
config://test/mykey.set(value={"a":1},raw=true)
```
Stores the JSON object directly: `{"a":1}`

**Complex String:**
```bash
config://test/complex.set(value=hello world 123)
```
Creates a JSON string: `"hello world 123"`

**Valid JSON Without Raw Mode:**
```bash
config://test/jsonval.set(value={"valid":"json"})
```
Automatically parses and stores: `{"valid":"json"}`

**Different JSON Types (with raw=true):**
```bash
config://test/number.set(value=42,raw=true)           # 42
config://test/boolean.set(value=true,raw=true)        # true
config://test/null.set(value=null,raw=true)           # null
config://test/array.set(value=[1],raw=true)           # [1]
config://test/object.set(value={"key":"value"},raw=true) # {"key":"value"}
```

**Arguments:**
- `value`: The value to store (required)
- `raw`: If true, parse value as JSON directly. If false (default), try parsing as JSON first, then treat as string if parsing fails

**Error Cases:**
- Missing value argument returns exit code 1
- Invalid JSON with raw=true returns exit code 2

### ls - List Configuration Keys

Lists configuration keys and namespaces with metadata.

**List All Namespaces:**
```bash
config://.ls
```
**Output:**
```json
{
  "prefix": "",
  "recursive": false,
  "pattern": null,
  "limit": null,
  "offset": 0,
  "entries": [
    {
      "key": "app",
      "full_key": "app", 
      "kind": "branch",
      "has_value": true,
      "meta": {"size": null, "updated_at": null}
    },
    {
      "key": "cache",
      "full_key": "cache",
      "kind": "branch", 
      "has_value": true,
      "meta": {"size": null, "updated_at": null}
    }
  ]
}
```

**List Namespace Contents:**
```bash
config://app.ls
```
**Output:**
```json
{
  "prefix": "app",
  "recursive": false,
  "pattern": null,
  "limit": null,
  "offset": 0,
  "entries": [
    {
      "key": "feature_flag",
      "full_key": "app/feature_flag",
      "kind": "leaf",
      "has_value": true,
      "meta": {"size": 4, "updated_at": "2024-01-01T00:00:00Z"}
    },
    {
      "key": "env",
      "full_key": "app/env", 
      "kind": "branch",
      "has_value": true,
      "meta": {"size": null, "updated_at": null}
    }
  ]
}
```

**Recursive Listing:**
```bash
config://app.ls(recursive=true)
```
Shows all descendants including nested keys like `app/env/db/url`.

**Pattern Filtering:**
```bash
config://app.ls(pattern=database*)
```
Only shows keys matching the glob pattern.

**Pagination:**
```bash
config://test.ls(limit=2,offset=1)
```
Returns 2 entries starting from the second entry.

**Nested Path Listing:**
```bash
config://app/env.ls
```
Lists contents of the `app/env` directory.

**Arguments:**
- `recursive`: If true, include all descendants (default: false)
- `pattern`: Glob pattern to filter keys (optional)
- `limit`: Maximum number of entries to return (optional)
- `offset`: Number of entries to skip for pagination (default: 0)

**Entry Types:**
- `leaf`: A configuration value (JSON file)
- `branch`: A directory containing other config items

**Error Cases:**
- Invalid limit value returns exit code 2
- Invalid offset value returns exit code 2
- Invalid glob pattern returns exit code 2

### watch - Monitor Configuration Changes

Watches for changes to configuration values and emits events as JSON lines.

**Basic Key Watching:**
```bash
config://test.watch(key="foo",timeout_ms=1000,initial=true)
```
**Output:**
```json
{"op":"snapshot","scope":"test","key":"foo","value":"initial_value","version":1,"ts":"2024-01-01T00:00:00Z","source":"config"}
```

**Prefix Watching:**
```bash
config://app.watch(prefix="db",timeout_ms=500,initial=true)
```
Watches all keys starting with "db" and emits events for each matching key.

**Change Detection:**
```bash
config://test.watch(key="dynamic",timeout_ms=1000,initial=true)
```
Emits events when files are modified:
```json
{"op":"set","scope":"test","key":"dynamic","value":"modified","version":2,"ts":"2024-01-01T00:00:01Z","source":"config"}
```

**Max Events Limit:**
```bash
config://test.watch(max_events=2,initial=true)
```
Stops after emitting 2 events.

**Arguments:**
- `key`: Watch a specific key (mutually exclusive with prefix)
- `prefix`: Watch all keys with this prefix (mutually exclusive with key)
- `timeout_ms`: Stop watching after this many milliseconds (default: 0 = no timeout)
- `max_events`: Stop after emitting this many events (default: 0 = no limit)
- `initial`: Emit snapshot events for existing values when starting (default: false)

**Event Fields:**
- `op`: Operation type ("snapshot", "set", "rm")
- `scope`: The namespace being watched
- `key`: The specific key that changed
- `value`: The new value (null for "rm" operations)
- `version`: Incrementing event counter
- `ts`: ISO 8601 timestamp
- `source`: Always "config"

**Error Cases:**
- Using both key and prefix arguments returns error
- Invalid timeout_ms or max_events values are treated as 0

## URL Sanitization

Namespace and key names are automatically sanitized to only allow safe characters:
- Allowed: letters, numbers, dots, underscores, hyphens, forward slashes
- Other characters are replaced with underscores

Example: `config://name%space/my$key.set(value=test)` becomes `name_space/my_key.json`

## Namespaces

If no namespace is specified in the URL, the "default" namespace is used:
- `config://mykey.set(value=test)` stores in `default/mykey.json`
- `config://app/setting.set(value=test)` stores in `app/setting.json`

## Atomic Operations

All set operations are atomic - they write to a temporary file first, then rename it to the final location. This prevents partial writes from corrupting your configuration.

## Error Codes

- **0**: Success
- **1**: Missing key, empty key not allowed, or missing required argument
- **2**: Invalid JSON, invalid pattern, invalid limit/offset values
- **3**: I/O error (filesystem problems)

## Examples

**Setting up a database configuration:**
```bash
config://app/db/url.set(value="localhost:5432")
config://app/db/user.set(value="admin")
config://app/db/timeout.set(value=30)
```

**Reading configuration:**
```bash
config://app/db/url.get                    # "localhost:5432" 
config://app/db/timeout.get                # 30
```

**Listing database settings:**
```bash
config://app/db.ls                         # Lists all db/* keys
config://app.ls(pattern=db*)               # Lists keys starting with "db"
```

**Watching for changes:**
```bash
config://app.watch(prefix="db",initial=true) # Monitor all database config changes
```

**Complex JSON values:**
```bash
config://app/settings.set(value={"theme":"dark","notifications":{"email":true,"push":false},"limits":{"timeout":30,"retries":3}},raw=true)
```

This creates a complete configuration system that's both human-readable (JSON files) and programmatically accessible through the Resource Shell interface.