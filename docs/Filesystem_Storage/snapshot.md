# Snapshot Handle Documentation

The snapshot handle allows you to create, restore, compare, and list filesystem snapshots. Snapshots capture the current state of files and directories, allowing you to save important versions or restore data later.

## Overview

Snapshots work with both files and directories. When you create a snapshot, it saves a complete copy of your data that you can restore or compare later. All snapshots are stored locally on your system.

## Verbs

### create

Creates a new snapshot of a file or directory.

**Basic Usage:**
```
snapshot://TARGET.create(name=SNAPSHOT_NAME)
```

**Arguments:**
- `name` (required): Name for your snapshot
- `description` (optional): Description of the snapshot
- `ttl` (optional): Time in seconds before snapshot expires
- `backend` (optional): Storage backend (only "local" supported, default: "local")
- `if_exists` (optional): What to do if snapshot exists ("error", "skip", "overwrite", default: "error")

**Examples:**

Create a snapshot of a directory:
```
snapshot:///home/user/myproject.create(name=backup-v1)
```

Expected output:
```json
{
  "ok": true,
  "backend": "local",
  "id": "generated-snapshot-id",
  "name": "backup-v1",
  "target": "/home/user/myproject",
  "path": "/path/to/snapshot/storage",
  "created_at": "2025-11-15T18:01:02Z",
  "expires_at": null,
  "skipped": false
}
```

Create a snapshot of a single file:
```
snapshot:///home/user/important.txt.create(name=filebackup)
```

Expected output:
```json
{
  "ok": true,
  "backend": "local", 
  "id": "generated-snapshot-id",
  "name": "filebackup",
  "target": "/home/user/important.txt",
  "path": "/path/to/snapshot/storage",
  "created_at": "2025-11-15T18:01:02Z",
  "expires_at": null,
  "skipped": false
}
```

Create a snapshot with description and expiration:
```
snapshot:///srv/app.create(name=deploy-v2, description="Production deployment backup", ttl=604800)
```

Expected output:
```json
{
  "ok": true,
  "backend": "local",
  "id": "generated-snapshot-id", 
  "name": "deploy-v2",
  "target": "/srv/app",
  "path": "/path/to/snapshot/storage",
  "created_at": "2025-11-15T18:01:02Z",
  "expires_at": "2025-11-22T18:01:02Z",
  "skipped": false
}
```

Skip creating if snapshot already exists:
```
snapshot:///home/user/data.create(name=existing-snapshot, if_exists=skip)
```

Expected output:
```json
{
  "ok": true,
  "backend": "local",
  "id": "existing-snapshot-id",
  "name": "existing-snapshot", 
  "target": "/home/user/data",
  "path": "/path/to/existing/snapshot",
  "created_at": "2025-11-15T18:01:02Z",
  "expires_at": null,
  "skipped": true
}
```

**Error Cases:**

Missing name argument:
```
snapshot:///home/user/data.create()
```

Expected output:
```json
{
  "ok": false,
  "error": "missing required argument: name"
}
```

Target doesn't exist:
```
snapshot:///nonexistent/path.create(name=test)
```

Expected output:
```json
{
  "ok": false,
  "error": "target path does not exist: \"/nonexistent/path\""
}
```

---

### restore

Restores a snapshot to a target location.

**Basic Usage:**
```
snapshot://SNAPSHOT_NAME.restore(target=TARGET_PATH)
```

**Arguments:**
- `target` (required): Where to restore the snapshot
- `force` (optional): Overwrite existing files/directories (true/false, default: false)
- `mode` (optional): Restore mode (only "overwrite" supported, default: "overwrite") 
- `dry_run` (optional): Show what would be done without doing it (true/false, default: false)

**Examples:**

Restore a directory snapshot:
```
snapshot://backup-v1.restore(target=/home/user/restored-project)
```

Expected output:
```json
{
  "snapshot": "backup-v1",
  "target": "/home/user/restored-project",
  "mode": "overwrite",
  "status": "ok"
}
```

Restore a file snapshot:
```
snapshot://filebackup.restore(target=/home/user/recovered.txt)
```

Expected output:
```json
{
  "snapshot": "filebackup", 
  "target": "/home/user/recovered.txt",
  "mode": "overwrite",
  "status": "ok"
}
```

Force restore over existing data:
```
snapshot://backup-v1.restore(target=/home/user/existing-folder, force=true)
```

Expected output:
```json
{
  "snapshot": "backup-v1",
  "target": "/home/user/existing-folder", 
  "mode": "overwrite",
  "status": "ok"
}
```

Dry run to see what would happen:
```
snapshot://backup-v1.restore(target=/home/user/test, force=true, dry_run=true)
```

Expected output:
```json
{
  "dry_run": true,
  "snapshot": "backup-v1",
  "target": "/home/user/test",
  "mode": "overwrite", 
  "force": true,
  "actions": [
    "DELETE DIRECTORY \"/home/user/test\"",
    "COPY \"/path/to/snapshot\" -> \"/home/user/test\""
  ]
}
```

**Error Cases:**

Missing target argument:
```
snapshot://test-snapshot.restore()
```

Expected output:
```json
{
  "error": "missing_argument",
  "argument": "target",
  "message": "missing required argument: target"
}
```

Snapshot not found:
```
snapshot://nonexistent.restore(target=/tmp/test)
```

Expected output:
```json
{
  "error": "snapshot_not_found",
  "snapshot": "nonexistent", 
  "message": "snapshot not found: nonexistent"
}
```

Target exists and not empty without force:
```
snapshot://test-snapshot.restore(target=/existing/nonempty/dir)
```

Expected output:
```json
{
  "error": "target_not_empty",
  "target": "/existing/nonempty/dir",
  "message": "target directory exists and is not empty (use force=true to overwrite): \"/existing/nonempty/dir\""
}
```

---

### diff

Compares snapshots or snapshots with live filesystem.

**Basic Usage:**
```
snapshot://NAME.diff(from=SOURCE, to=TARGET)
```

**Arguments:**
- `from` (optional): Source snapshot ID or "live"
- `to` (optional): Target snapshot ID or "live" 
- `path` (optional): Filter to specific path (default: "/")
- `format` (optional): Output format ("json" or "summary", default: "json")

Note: At least one of `from` or `to` must be provided. You cannot diff "live" against itself.

**Examples:**

Compare two snapshots:
```
snapshot:///srv/app.diff(from=snap-001, to=snap-002, format=json)
```

Expected output:
```json
{
  "name": "/srv/app",
  "from": "snap-001", 
  "to": "snap-002",
  "from_kind": "snapshot",
  "to_kind": "snapshot",
  "root": "/srv/app",
  "path": "/",
  "summary": {
    "added": 2,
    "removed": 1, 
    "modified": 2,
    "unchanged": 5
  },
  "entries": [
    {
      "path": "file1.txt",
      "type": "file",
      "status": "modified",
      "from": {
        "exists": true,
        "file_type": "file",
        "size": 9,
        "mtime": "2025-11-15T18:01:02Z",
        "mode": "0644",
        "hash": "abc123"
      },
      "to": {
        "exists": true, 
        "file_type": "file",
        "size": 17,
        "mtime": "2025-11-15T18:02:02Z",
        "mode": "0644",
        "hash": "def456"
      }
    }
  ]
}
```

Compare snapshot to live filesystem:
```
snapshot:///home/user/project.diff(from=snap-001, to=live, format=json)
```

Expected output:
```json
{
  "name": "/home/user/project",
  "from": "snap-001",
  "to": "live", 
  "from_kind": "snapshot",
  "to_kind": "live",
  "root": "/home/user/project",
  "path": "/",
  "summary": {
    "added": 2,
    "removed": 1,
    "modified": 2,
    "unchanged": 3
  },
  "entries": [
    {
      "path": "new_file.txt",
      "type": "file", 
      "status": "added",
      "from": {
        "exists": false
      },
      "to": {
        "exists": true,
        "file_type": "file",
        "size": 11,
        "mtime": "2025-11-15T18:03:02Z",
        "mode": "0644",
        "hash": "ghi789"
      }
    }
  ]
}
```

Get summary format output:
```
snapshot:///srv/app.diff(from=snap-001, to=live, format=summary)
```

Expected output:
```
snapshot: /srv/app
from: snap-001 (snapshot)
to:   live (live)
root: /srv/app
path: /

added: 2
removed: 1  
modified: 2
unchanged: 5
```

Compare with path filter:
```
snapshot:///srv/app.diff(from=snap-001, to=live, path=/subdir, format=json)
```

Expected output:
```json
{
  "name": "/srv/app",
  "from": "snap-001",
  "to": "live",
  "from_kind": "snapshot", 
  "to_kind": "live",
  "root": "/srv/app",
  "path": "/subdir",
  "summary": {
    "added": 1,
    "removed": 0,
    "modified": 0,
    "unchanged": 1
  },
  "entries": [
    {
      "path": "new_nested.txt",
      "type": "file",
      "status": "added",
      "from": {
        "exists": false
      },
      "to": {
        "exists": true,
        "file_type": "file", 
        "size": 10,
        "mtime": "2025-11-15T18:04:02Z",
        "mode": "0644",
        "hash": "jkl012"
      }
    }
  ]
}
```

**Error Cases:**

No from or to specified:
```
snapshot:///srv/app.diff(format=json)
```

Expected: Command fails with error message about needing at least one of 'from' or 'to'.

Both from and to are live:
```
snapshot:///srv/app.diff(from=live, to=live, format=json) 
```

Expected: Command fails with error message about cannot diff live against itself.

---

### ls

Lists snapshots in a group.

**Basic Usage:**
```
snapshot://GROUP_NAME.ls
```

**Arguments:**
- `state` (optional): Filter by state 
- `tag` (optional): Filter by tag
- `since` (optional): Filter by creation time (RFC3339 format)
- `until` (optional): Filter by creation time (RFC3339 format)
- `name_prefix` (optional): Filter by name prefix
- `limit` (optional): Maximum number of results
- `json_pretty` (optional): Pretty print JSON (true/false, default: false)

**Examples:**

List all snapshots in a group:
```
snapshot://myapp.ls
```

Expected output:
```json
[
  {
    "id": "snap-003",
    "name": "latest-backup",
    "created_at": "2025-11-15T18:03:02Z", 
    "backend": "local",
    "target": "/srv/myapp",
    "state": "ready",
    "size_bytes": 1048576,
    "tags": ["deploy", "prod"],
    "description": "Production deployment backup"
  },
  {
    "id": "snap-002", 
    "name": "previous-backup",
    "created_at": "2025-11-15T17:01:02Z",
    "backend": "local", 
    "target": "/srv/myapp",
    "state": "ready",
    "size_bytes": 1024000,
    "tags": ["deploy"],
    "description": "Previous backup"
  }
]
```

Filter by state:
```
snapshot://myapp.ls(state=ready)
```

Expected output:
```json
[
  {
    "id": "snap-003",
    "name": "ready-snapshot",
    "created_at": "2025-11-15T18:03:02Z",
    "backend": "local",
    "target": "/srv/app", 
    "state": "ready",
    "tags": ["deploy", "prod"]
  },
  {
    "id": "snap-001",
    "name": "ready-snapshot2", 
    "created_at": "2025-11-15T18:01:02Z",
    "backend": "local",
    "target": "/srv/app",
    "state": "ready",
    "tags": ["deploy", "prod"]
  }
]
```

Filter by tag:
```
snapshot://myapp.ls(tag=prod)
```

Expected output:
```json
[
  {
    "id": "snap-003",
    "name": "prod-snapshot2",
    "created_at": "2025-11-15T18:03:02Z",
    "backend": "local",
    "target": "/srv/app",
    "state": "ready", 
    "tags": ["deploy", "prod", "v2"]
  },
  {
    "id": "snap-001",
    "name": "prod-snapshot",
    "created_at": "2025-11-15T18:01:02Z",
    "backend": "local",
    "target": "/srv/app",
    "state": "ready",
    "tags": ["deploy", "prod"]  
  }
]
```

Limit results:
```
snapshot://myapp.ls(limit=2)
```

Expected output:
```json
[
  {
    "id": "snap-003",
    "name": "newest",
    "created_at": "2025-11-15T18:01:02Z",
    "backend": "local",
    "target": "/srv/app",
    "state": "ready"
  },
  {
    "id": "snap-002",
    "name": "middle", 
    "created_at": "2025-11-15T17:01:02Z",
    "backend": "local",
    "target": "/srv/app", 
    "state": "ready"
  }
]
```

Filter by time range:
```
snapshot://myapp.ls(since=2025-11-15T10:00:00Z)
```

Expected output:
```json
[
  {
    "id": "snap-003",
    "name": "late",
    "created_at": "2025-11-15T22:01:02Z",
    "backend": "local",
    "target": "/srv/app",
    "state": "ready"
  },
  {
    "id": "snap-002",
    "name": "middle",
    "created_at": "2025-11-15T12:01:02Z", 
    "backend": "local",
    "target": "/srv/app",
    "state": "ready"
  }
]
```

Filter by name prefix:
```
snapshot://myapp.ls(name_prefix=prod-)
```

Expected output:
```json
[
  {
    "id": "snap-002",
    "name": "prod-v2",
    "created_at": "2025-11-15T18:02:02Z",
    "backend": "local",
    "target": "/srv/app",
    "state": "ready"
  },
  {
    "id": "snap-001", 
    "name": "prod-v1",
    "created_at": "2025-11-15T18:01:02Z",
    "backend": "local",
    "target": "/srv/app",
    "state": "ready"
  }
]
```

Empty group (no snapshots):
```
snapshot://empty-group.ls
```

Expected output:
```json
[]
```

## Common Use Cases

### Backup Before Changes
```
# Create backup before making changes
snapshot:///home/user/project.create(name=before-update)

# Make your changes...

# If something goes wrong, restore the backup
snapshot://before-update.restore(target=/home/user/project, force=true)
```

### Compare Changes
```
# Create snapshot before changes
snapshot:///srv/app.create(name=before-deploy)

# Deploy new version...

# Compare what changed
snapshot:///srv/app.diff(from=before-deploy, to=live, format=summary)
```

### Regular Backups
```
# Create timestamped backup
snapshot:///important/data.create(name=backup-$(date +%Y%m%d), description="Daily backup")

# List recent backups
snapshot://backup.ls(name_prefix=backup-, limit=10)
```

## Storage Location

Snapshots are stored in your system's state directory:
- Linux: `$XDG_STATE_HOME/resh/snapshots` or `$HOME/.local/state/resh/snapshots`
- macOS: `~/Library/Application Support/resh/snapshots`
- Windows: `%APPDATA%/resh/snapshots`

## Important Notes

1. **Snapshots preserve permissions**: File and directory permissions are maintained when creating and restoring snapshots.

2. **Atomic operations**: Restore operations are atomic - if something fails during restore, your original data remains unchanged.

3. **Local storage only**: Currently only local filesystem storage is supported.

4. **Case sensitive**: Snapshot names and operations are case sensitive.

5. **Time zones**: All timestamps are in UTC format (ISO 8601).

6. **Relative paths**: When using relative paths, they are resolved based on your current working directory when the command runs.