# plugin:// Handle

The `plugin://` handle provides comprehensive plugin management capabilities for the Resource Shell project. This handle manages plugin installation, updates, removal, enablement/disablement, and discovery through multiple sources.

## Overview

The plugin handle follows these patterns:

```
plugin://plugin-id.verb(arguments)
plugin://special-target.verb(arguments)
```

The handle supports nine main operations (verbs):
- **install** - Install a plugin from various sources
- **update** - Update an existing plugin to the latest version
- **remove** - Remove an installed plugin
- **enable** - Enable a disabled plugin
- **disable** - Disable an active plugin
- **available.list** - List available plugins from catalogs
- **available.search** - Search for plugins with filters
- **available.info** - Get detailed information about a plugin
- **installed.list** - List currently installed plugins

## Plugin Sources

The handle supports multiple plugin sources:

- **registry** - Official plugin registry (default)
- **url** - Direct download from HTTP/HTTPS URL
- **file** - Local file path

## Special Targets

Some verbs require special plugin targets:

- `plugin://available.list()` - For catalog listing
- `plugin://available.search()` - For plugin search
- `plugin://available.info()` - For plugin information
- `plugin://installed.list()` - For installed plugins

## Verbs

### plugin://…install

Installs a plugin from a specified source.

**Required Arguments:**
- Plugin ID in the URL path

**Optional Arguments:**
- `source` - Source type: "registry", "url", "file" (default: "registry")
- `registry` - Registry URL when source=registry (default: "https://plugins.reshshell.dev")
- `url` - Download URL when source=url
- `path` - File path when source=file
- `version` - Specific version to install (default: "latest")
- `verify` - Verification mode: "none", "sha256" (default: "sha256")
- `force` - Force installation even if already installed (default: false)
- `allow_downgrade` - Allow installing older version (default: false)
- `dry_run` - Simulate installation without changes (default: false)
- `timeout_ms` - Operation timeout in milliseconds (default: 300000)
- `json_pretty` - Pretty-print JSON output (default: false)

**Examples**

Install from registry:
```sh
plugin://aws.install(source="registry")
```

Install from local file:
```sh
plugin://test-plugin.install(source="file", path="/path/to/plugin.tar.gz")
```

Install specific version:
```sh
plugin://aws.install(version="1.2.3")
```

**Output**

```json
{
  "op": "plugin.install",
  "ok": true,
  "code": 0,
  "ts": "2024-01-01T12:00:00Z",
  "target": "plugin://aws.install()",
  "args": {
    "plugin_id": "aws",
    "source": "registry",
    "version": "latest",
    "verify": "sha256",
    "force": false,
    "dry_run": false
  },
  "result": {
    "plugin_id": "aws",
    "version": "1.2.3",
    "source": "registry",
    "changed": true,
    "deterministic": true
  },
  "actions": [
    {
      "type": "fetch",
      "id": "download",
      "ok": true,
      "detail": "downloaded plugin archive",
      "meta": {"bytes": 1048576}
    }
  ],
  "error": null
}
```

### plugin://…update

Updates an existing plugin to the latest available version.

**Required Arguments:**
- Plugin ID in the URL path

**Optional Arguments:**
- `registry` - Registry URL (default: "https://plugins.reshshell.dev")
- `url` - Direct URL for update package
- `strict` - Require exact version match (default: false)
- `dry_run` - Simulate update without changes (default: false)
- `timeout_ms` - Operation timeout in milliseconds (default: 300000)
- `json_pretty` - Pretty-print JSON output (default: false)

**Examples**

Update from registry:
```sh
plugin://aws.update()
```

Update with custom registry:
```sh
plugin://aws.update(registry="https://custom-registry.com")
```

**Output**

```json
{
  "op": "plugin.update",
  "ok": true,
  "code": 0,
  "ts": "2024-01-01T12:00:00Z",
  "target": "plugin://aws.update()",
  "args": {
    "plugin_id": "aws",
    "strict": false,
    "dry_run": false
  },
  "result": {
    "plugin_id": "aws",
    "old_version": "1.2.2",
    "new_version": "1.2.3",
    "changed": true,
    "deterministic": true
  },
  "actions": [],
  "error": null
}
```

### plugin://…remove

Removes an installed plugin from the system.

**Required Arguments:**
- Plugin ID in the URL path (optionally with @version)

**Optional Arguments:**
- `force` - Force removal without confirmation (default: false)
- `purge` - Remove configuration and data files (default: false)
- `dry_run` - Simulate removal without changes (default: false)
- `timeout_ms` - Operation timeout in milliseconds (default: 30000)
- `json_pretty` - Pretty-print JSON output (default: false)

**Examples**

Remove plugin:
```sh
plugin://aws.remove()
```

Remove with purge:
```sh
plugin://aws.remove(purge="true", force="true")
```

Remove specific version:
```sh
plugin://aws@1.2.3.remove()
```

**Output**

```json
{
  "op": "plugin.remove",
  "ok": true,
  "code": 0,
  "ts": "2024-01-01T12:00:00Z",
  "target": "plugin://aws.remove()",
  "args": {
    "plugin_id": "aws",
    "force": false,
    "purge": false,
    "dry_run": false
  },
  "result": {
    "plugin_id": "aws",
    "version": "1.2.3",
    "changed": true,
    "deterministic": true
  },
  "actions": [],
  "error": null
}
```

### plugin://…enable

Enables a disabled plugin.

**Required Arguments:**
- Plugin ID in the URL path

**Optional Arguments:**
- `scope` - Enable scope: "user", "system" (default: "user")
- `force` - Force enable without validation (default: false)
- `reason` - Reason for enabling (max 200 characters)
- `dry_run` - Simulate enablement without changes (default: false)
- `timeout_ms` - Operation timeout in milliseconds (default: 15000, clamped 1000-120000)
- `json_pretty` - Pretty-print JSON output (default: false)

**Examples**

Enable for user:
```sh
plugin://aws.enable()
```

Enable system-wide:
```sh
plugin://aws.enable(scope="system", reason="Required for deployment")
```

**Output**

```json
{
  "op": "plugin.enable",
  "ok": true,
  "code": 0,
  "ts": "2024-01-01T12:00:00Z",
  "target": "plugin://aws.enable()",
  "args": {
    "plugin_id": "aws",
    "scope": "user",
    "force": false,
    "dry_run": false
  },
  "result": {
    "plugin_id": "aws",
    "scope": "user",
    "changed": true,
    "deterministic": true
  },
  "actions": [],
  "error": null
}
```

### plugin://…disable

Disables an active plugin.

**Required Arguments:**
- Plugin ID in the URL path

**Optional Arguments:**
- `scope` - Disable scope: "user", "system" (default: "user")
- `force` - Force disable without validation (default: false)
- `reason` - Reason for disabling (max 200 characters)
- `dry_run` - Simulate disablement without changes (default: false)
- `timeout_ms` - Operation timeout in milliseconds (default: 15000, clamped 1000-120000)
- `json_pretty` - Pretty-print JSON output (default: false)

**Examples**

Disable for user:
```sh
plugin://aws.disable()
```

Disable with reason:
```sh
plugin://aws.disable(reason="Security vulnerability detected")
```

**Output**

```json
{
  "op": "plugin.disable",
  "ok": true,
  "code": 0,
  "ts": "2024-01-01T12:00:00Z",
  "target": "plugin://aws.disable()",
  "args": {
    "plugin_id": "aws",
    "scope": "user",
    "force": false,
    "dry_run": false
  },
  "result": {
    "plugin_id": "aws",
    "scope": "user",
    "changed": true,
    "deterministic": true
  },
  "actions": [],
  "error": null
}
```

### plugin://available.list

Lists available plugins from plugin catalogs.

**Required Target:**
- Must use `plugin://available.list()`

**Optional Arguments:**
- `source` - Catalog source URL
- `query` - Search term to filter plugins
- `tags` - Tag filters (semicolon-separated)
- `max_results` - Maximum results to return (default: 100, max: 200)
- `sort` - Sort field: "name", "version", "updated" (default: "name")
- `order` - Sort order: "asc", "desc" (default: "asc")
- `json_pretty` - Pretty-print JSON output (default: false)

**Examples**

List all available plugins:
```sh
plugin://available.list()
```

List with filters:
```sh
plugin://available.list(query="aws", tags="cloud;infrastructure", max_results="10")
```

**Output**

```json
{
  "op": "plugin.available.list",
  "ok": true,
  "code": 0,
  "ts": "2024-01-01T12:00:00Z",
  "target": "plugin://available",
  "args": {
    "query": "",
    "tags": [],
    "max_results": 100,
    "sort": "name",
    "order": "asc"
  },
  "result": {
    "source": "https://plugins.reshshell.dev",
    "catalog_version": 1,
    "generated_at": "2024-01-01T10:00:00Z",
    "count": 2,
    "items": [
      {
        "id": "aws",
        "name": "aws",
        "description": "AWS command-line interface plugin",
        "version": "1.2.3",
        "publisher": "Amazon",
        "license": "Apache-2.0",
        "tags": ["aws", "cloud", "infrastructure"],
        "platforms": ["linux-x86_64"],
        "homepage": "https://aws.amazon.com/cli/"
      }
    ]
  },
  "actions": [
    {
      "type": "catalog.load",
      "source": "https://plugins.reshshell.dev",
      "bytes": 0
    }
  ],
  "error": null
}
```

### plugin://available.search

Searches for plugins with advanced filtering and scoring.

**Required Target:**
- Must use `plugin://available.search()`

**Optional Arguments:**
- `q` - Search query string
- `tags` - Tag filters (semicolon-separated)
- `owner` - Plugin owner/publisher filter
- `name` - Plugin name filter
- `min_version` - Minimum version requirement
- `max_results` - Maximum results to return (default: 50, max: 200)
- `source` - Catalog source
- `timeout_ms` - Operation timeout in milliseconds (default: 15000)
- `offline` - Use cached data only (default: false)
- `json_pretty` - Pretty-print JSON output (default: false)

**Examples**

Basic search:
```sh
plugin://available.search(q="docker")
```

Advanced search with filters:
```sh
plugin://available.search(q="container", tags="docker;orchestration", owner="resh-community")
```

**Output**

```json
{
  "op": "plugin.available.search",
  "ok": true,
  "target": "plugin://available.search",
  "args": {
    "q": "docker",
    "tags": [],
    "max_results": 50
  },
  "result": {
    "source": "https://plugins.reshshell.dev",
    "query": {
      "q": "docker",
      "tags": [],
      "owner": "",
      "name": "",
      "min_version": "",
      "max_results": 50
    },
    "count": 1,
    "items": [
      {
        "id": "docker",
        "name": "docker",
        "description": "Docker container management plugin",
        "version": "2.1.0",
        "publisher": "Docker Inc",
        "score": 0.95,
        "relevance": "high"
      }
    ]
  },
  "actions": [
    {
      "type": "catalog.load",
      "source": "https://plugins.reshshell.dev"
    }
  ],
  "error": null
}
```

### plugin://available.info

Gets detailed information about a specific plugin.

**Required Target:**
- Must use `plugin://available.info()`

**Required Arguments:**
- `name` OR `id` - Plugin name or ID to look up

**Optional Arguments:**
- `version` - Specific version to query (default: latest)
- `channel` - Release channel: "stable", "beta", "alpha" (default: "stable")
- `source` - Plugin index source
- `timeout_ms` - Operation timeout in milliseconds (default: 15000, clamped 100-30000)
- `offline` - Use cached data only (default: false)
- `os` - Target operating system filter
- `arch` - Target architecture filter
- `json_pretty` - Pretty-print JSON output (default: false)

**Examples**

Get plugin info by name:
```sh
plugin://available.info(name="resh-aws")
```

Get specific version info:
```sh
plugin://available.info(id="aws", version="1.2.3")
```

Get beta channel info:
```sh
plugin://available.info(name="resh-aws", channel="beta")
```

**Output**

```json
{
  "op": "plugin.available.info",
  "ok": true,
  "ts": "2024-01-01T12:00:00Z",
  "target": "plugin://available",
  "args": {
    "name": "resh-aws",
    "channel": "stable",
    "timeout_ms": 15000,
    "offline": false
  },
  "result": {
    "plugin": {
      "id": "aws",
      "name": "resh-aws",
      "version": "1.2.3",
      "channel": "stable",
      "description": "AWS cloud services integration for resh",
      "author": "Amazon Web Services",
      "license": "Apache-2.0",
      "homepage": "https://aws.amazon.com/cli/",
      "repository": "https://github.com/aws/aws-cli",
      "tags": ["aws", "cloud", "infrastructure"],
      "compatibility": {
        "os": ["linux", "darwin", "windows"],
        "arch": ["x86_64", "arm64"],
        "resh_version": ">=0.1.0"
      }
    }
  },
  "actions": [
    {
      "type": "fetch",
      "id": "index.load",
      "ok": true,
      "detail": "loaded 1 indexes",
      "meta": {"count": 1}
    }
  ],
  "error": null
}
```

### plugin://installed.list

Lists currently installed plugins with detailed information.

**Required Target:**
- Must use `plugin://installed.list()`

**Optional Arguments:**
- `enabled` - Filter by enabled status: true/false
- `name` - Filter by exact plugin name
- `prefix` - Filter by name prefix
- `tag` - Filter by tag
- `source` - Filter by source type
- `limit` - Maximum results to return (default: 200)
- `offset` - Results offset for pagination (default: 0)
- `sort` - Sort field: "name", "version", "updated" (default: "name")
- `order` - Sort order: "asc", "desc" (default: "asc")
- `format` - Output format: "full", "summary" (default: "full")
- `json_pretty` - Pretty-print JSON output (default: false)

**Examples**

List all installed plugins:
```sh
plugin://installed.list()
```

List enabled plugins only:
```sh
plugin://installed.list(enabled="true", format="summary")
```

List with pagination:
```sh
plugin://installed.list(limit="10", offset="20")
```

**Output**

```json
{
  "op": "plugin.installed.list",
  "ok": true,
  "code": 0,
  "ts": "2024-01-01T12:00:00Z",
  "target": "plugin://installed",
  "args": {
    "enabled": null,
    "limit": 200,
    "offset": 0,
    "sort": "name",
    "order": "asc",
    "format": "full"
  },
  "result": {
    "count": 2,
    "total": 2,
    "items": [
      {
        "name": "aws",
        "version": "1.2.3",
        "enabled": true,
        "source": {
          "type": "registry",
          "ref": "https://plugins.reshshell.dev"
        },
        "paths": {
          "install_dir": "/home/user/.local/share/resh/plugins/aws",
          "binary": "/home/user/.local/share/resh/plugins/aws/bin/aws"
        },
        "manifest": {
          "description": "AWS command-line interface plugin",
          "tags": ["aws", "cloud"],
          "capabilities": ["exec", "config"]
        },
        "health": "ok",
        "installed_at": "2024-01-01T10:00:00Z",
        "updated_at": "2024-01-01T11:00:00Z"
      }
    ]
  },
  "actions": [
    {
      "type": "scan",
      "id": "installed.scan",
      "ok": true,
      "detail": "scanned plugin directories",
      "meta": {"scanned": 2}
    }
  ],
  "error": null
}
```

## Error Handling

When operations fail, the handle returns structured error information:

**Common Error Codes:**
- `ERR_INVALID_ARG` - Invalid or missing arguments
- `ERR_NOT_FOUND` - Plugin not found
- `ERR_IO` - File system or network I/O error
- `ERR_TIMEOUT` - Operation timed out
- `PLUGIN_INVALID_TARGET` - Wrong target for verb
- `PLUGIN_NETWORK_ERROR` - Network connectivity issues
- `PLUGIN_CATALOG_UNAVAILABLE` - Plugin catalog unavailable

**Error Output Example**

```json
{
  "op": "plugin.install",
  "ok": false,
  "code": 3,
  "ts": "2024-01-01T12:00:00Z",
  "target": "plugin://nonexistent.install()",
  "args": {
    "plugin_id": "nonexistent"
  },
  "result": null,
  "actions": [],
  "error": {
    "code": "ERR_NOT_FOUND",
    "message": "Plugin 'nonexistent' not found in registry"
  }
}
```

## Plugin Sources

### Registry Source
```sh
plugin://aws.install(source="registry", registry="https://plugins.reshshell.dev")
```

### URL Source
```sh
plugin://custom.install(source="url", url="https://example.com/plugin.tar.gz")
```

### File Source
```sh
plugin://local.install(source="file", path="/path/to/plugin.tar.gz")
```

## Best Practices

1. **Use registry source** for official plugins when possible
2. **Verify plugin integrity** by keeping SHA256 verification enabled
3. **Test with dry_run** before making changes to production systems
4. **Use specific versions** in automated deployments for consistency
5. **Monitor plugin health** through regular installed.list checks
6. **Use appropriate scopes** when enabling/disabling plugins
7. **Set reasonable timeouts** based on your network conditions
8. **Cache plugin catalogs** by using offline mode when appropriate

## Common Use Cases

### Plugin Discovery and Installation
```sh
# Search for plugins
plugin://available.search(q="aws")

# Get detailed info
plugin://available.info(name="resh-aws")

# Install plugin
plugin://aws.install()
```

### Plugin Maintenance
```sh
# List installed plugins
plugin://installed.list()

# Update all or specific plugins
plugin://aws.update()

# Check plugin status
plugin://aws.enable()
```

### Automated Plugin Management
```sh
# Install specific version for reproducibility
plugin://aws.install(version="1.2.3", dry_run="false")

# Bulk operations with filtering
plugin://installed.list(enabled="false")
```

### Development and Testing
```sh
# Install from local file for development
plugin://test-plugin.install(source="file", path="/dev/plugin.tar.gz")

# Test operations without changes
plugin://aws.update(dry_run="true")
```

## Plugin Lifecycle

1. **Discovery** - Use available.search or available.list to find plugins
2. **Information** - Use available.info to get details before installation  
3. **Installation** - Use install to add plugins to the system
4. **Management** - Use enable/disable to control plugin activation
5. **Maintenance** - Use update to keep plugins current
6. **Removal** - Use remove to clean up unwanted plugins

## Security Considerations

- **SHA256 verification** is enabled by default for integrity checking
- **Source validation** ensures plugins come from trusted locations
- **Scope isolation** separates user and system plugin installations
- **Force flags** require explicit confirmation for potentially dangerous operations
- **Timeout limits** prevent indefinite operations that could cause system issues