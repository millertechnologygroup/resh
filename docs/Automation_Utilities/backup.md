# backup:// Handle

The `backup://` handle provides backup and restore operations using multiple backend systems including restic, borg, rsync, and tar. This handle manages backup creation, listing, restoration, verification, pruning, and scheduling.

## Overview

The backup handle follows a simple pattern:

```
backup://profile.verb(arguments)
```

The handle supports six main operations (verbs):
- **create** - Create a new backup snapshot
- **list** - List existing backup snapshots
- **restore** - Restore files from a backup snapshot
- **verify** - Verify backup integrity
- **prune** - Remove old snapshots according to retention policy
- **schedule** - Set up automated backups

## Supported Backends

The handle automatically selects the best available backend, or you can specify one:

- **restic** - Modern backup program with deduplication and encryption
- **borg** - Deduplicating backup program
- **rsync** - File synchronization tool (basic backup functionality)
- **tar** - Archive utility (simple backup functionality)

Backend selection order: restic → borg → rsync → tar

## Verbs

### backup://…create

Creates a new backup snapshot using the specified backend.

**Required Arguments:**
- `src` - Source path(s) to backup (semicolon-separated)

**Optional Arguments:**
- `backend` - Backend to use (default: "auto")
- `repo_url` - Repository URL or path
- `tag` - Tags for the snapshot (semicolon-separated key=value pairs)
- `label` - Human-readable label for the snapshot
- `exclude` - Exclude patterns (semicolon-separated)
- `dry_run` - Simulate without creating backup (default: false)
- `timeout_ms` - Operation timeout in milliseconds (default: 1800000)
- `json_pretty` - Pretty-print JSON output (default: false)

**Examples**

Basic backup creation:
```sh
backup://myapp.create(src="/data")
```

Backup with specific backend and tags:
```sh
backup://myapp.create(src="/data", backend="restic", tag="env=prod;type=daily", label="daily-backup")
```

**Output**

```json
{
  "op": "backup.create",
  "status": "ok",
  "target": "backup://myapp.create()",
  "backend": {
    "id": "restic",
    "command": ["restic", "backup", "--json", "/data"],
    "timeout_ms": 1800000,
    "simulated": false
  },
  "result": {
    "capabilities": {
      "incremental": true,
      "dedup": true,
      "encryption": true,
      "retention": true,
      "verify": true,
      "cloud_targets": ["s3", "azure", "gcs", "file"]
    },
    "snapshot": {
      "id": "abcd1234",
      "label": "daily-backup",
      "tags": ["env=prod", "type=daily"],
      "created_at": "2024-01-01T12:00:00Z",
      "sources": ["/data"],
      "bytes_sent": 1048576,
      "bytes_total": 2097152
    },
    "backend_raw": {
      "stdout": "backup completed successfully",
      "stderr": ""
    }
  },
  "dry_run": false,
  "duration_ms": 5000,
  "warnings": []
}
```

### backup://…list

Lists all backup snapshots in the repository.

**Optional Arguments:**
- `backend` - Backend to use (default: "auto")
- `repo_url` - Repository URL or path
- `tag` - Filter by tags (semicolon-separated)
- `timeout_ms` - Operation timeout in milliseconds (default: 10000)
- `json_pretty` - Pretty-print JSON output (default: false)

**Examples**

List all snapshots:
```sh
backup://myapp.list()
```

List snapshots with specific tags:
```sh
backup://myapp.list(tag="env=prod")
```

**Output**

```json
{
  "op": "backup.list",
  "status": "ok",
  "target": "backup://myapp.list()",
  "backend": {
    "id": "restic",
    "command": ["restic", "snapshots", "--json"],
    "timeout_ms": 10000,
    "simulated": false
  },
  "result": {
    "snapshots": [
      {
        "id": "abcd1234",
        "label": "daily-backup",
        "tags": ["env=prod", "type=daily"],
        "created_at": "2024-01-01T12:00:00Z",
        "sources": ["/data"],
        "bytes_sent": 1048576,
        "bytes_total": 2097152
      }
    ],
    "total_count": 1,
    "capabilities": {
      "incremental": true,
      "dedup": true,
      "encryption": true,
      "retention": true,
      "verify": true,
      "cloud_targets": ["s3", "azure", "gcs", "file"]
    }
  },
  "dry_run": false,
  "duration_ms": 1000,
  "warnings": []
}
```

### backup://…restore

Restores files from a specific backup snapshot.

**Required Arguments:**
- `snapshot_id` - ID of the snapshot to restore
- `dest` - Destination path for restored files

**Optional Arguments:**
- `backend` - Backend to use (default: "auto")
- `repo_url` - Repository URL or path
- `include` - Include patterns (semicolon-separated)
- `exclude` - Exclude patterns (semicolon-separated)
- `timeout_ms` - Operation timeout in milliseconds (default: 1800000)
- `json_pretty` - Pretty-print JSON output (default: false)

**Examples**

Restore a complete snapshot:
```sh
backup://myapp.restore(snapshot_id="abcd1234", dest="/restore")
```

Restore specific files only:
```sh
backup://myapp.restore(snapshot_id="abcd1234", dest="/restore", include="*.txt;*.conf")
```

**Output**

```json
{
  "op": "backup.restore",
  "status": "ok",
  "target": "backup://myapp.restore()",
  "backend": {
    "id": "restic",
    "command": ["restic", "restore", "abcd1234", "--target", "/restore"],
    "timeout_ms": 1800000,
    "simulated": false
  },
  "result": {
    "restored": {
      "files_restored": 42,
      "bytes_restored": 1048576,
      "success": true
    },
    "snapshot_id": "abcd1234",
    "destination": "/restore",
    "capabilities": {
      "incremental": true,
      "dedup": true,
      "encryption": true,
      "retention": true,
      "verify": true,
      "cloud_targets": ["s3", "azure", "gcs", "file"]
    }
  },
  "dry_run": false,
  "duration_ms": 10000,
  "warnings": []
}
```

### backup://…verify

Verifies the integrity of backup repositories or specific snapshots.

**Optional Arguments:**
- `backend` - Backend to use (default: "auto")
- `repo_url` - Repository URL or path
- `snapshot_id` - Specific snapshot ID to verify
- `mode` - Verification mode: "quick" or "thorough" (default: "quick")
- `timeout_ms` - Operation timeout in milliseconds (default: 3600000)
- `json_pretty` - Pretty-print JSON output (default: false)

**Examples**

Quick repository verification:
```sh
backup://myapp.verify()
```

Thorough verification including data reads:
```sh
backup://myapp.verify(mode="thorough")
```

**Output**

```json
{
  "op": "backup.verify",
  "status": "ok",
  "target": "backup://myapp.verify()",
  "backend": {
    "id": "restic",
    "command": ["restic", "check"],
    "timeout_ms": 3600000,
    "simulated": false
  },
  "result": {
    "verification": {
      "checks": [
        {
          "name": "repository_structure",
          "ok": true,
          "detail": "Repository structure is valid"
        },
        {
          "name": "pack_files",
          "ok": true,
          "detail": "All pack files are intact"
        }
      ],
      "success": true,
      "errors": []
    },
    "mode": "quick",
    "snapshot_id": null,
    "capabilities": {
      "incremental": true,
      "dedup": true,
      "encryption": true,
      "retention": true,
      "verify": true,
      "cloud_targets": ["s3", "azure", "gcs", "file"]
    }
  },
  "dry_run": false,
  "duration_ms": 30000,
  "warnings": []
}
```

### backup://…prune

Removes old snapshots according to retention policies.

**Optional Arguments:**
- `backend` - Backend to use (default: "auto")
- `repo_url` - Repository URL or path
- `keep_daily` - Number of daily snapshots to keep
- `keep_weekly` - Number of weekly snapshots to keep  
- `keep_monthly` - Number of monthly snapshots to keep
- `dry_run` - Simulate without actually removing snapshots (default: false)
- `timeout_ms` - Operation timeout in milliseconds (default: 3600000)
- `json_pretty` - Pretty-print JSON output (default: false)

**Examples**

Dry run to see what would be pruned:
```sh
backup://myapp.prune(keep_daily="7", keep_weekly="4", dry_run="true")
```

Actually prune snapshots:
```sh
backup://myapp.prune(keep_daily="7", keep_weekly="4")
```

**Output**

```json
{
  "op": "backup.prune",
  "status": "ok",
  "target": "backup://myapp.prune()",
  "backend": {
    "id": "restic",
    "command": ["restic", "forget", "--keep-daily", "7", "--keep-weekly", "4", "--prune"],
    "timeout_ms": 3600000,
    "simulated": false
  },
  "result": {
    "pruned": {
      "snapshots_removed": 3,
      "bytes_freed": 5242880,
      "success": true
    },
    "policy": {
      "keep_daily": 7,
      "keep_weekly": 4,
      "keep_monthly": null
    },
    "capabilities": {
      "incremental": true,
      "dedup": true,
      "encryption": true,
      "retention": true,
      "verify": true,
      "cloud_targets": ["s3", "azure", "gcs", "file"]
    }
  },
  "dry_run": false,
  "duration_ms": 15000,
  "warnings": []
}
```

### backup://…schedule

Sets up automated backup scheduling using system schedulers.

**Required Arguments:**
- `when` - Schedule expression (cron format or systemd timer format)
- `src` - Source path(s) to backup

**Optional Arguments:**
- `backend` - Backend to use (default: "auto")
- `enabled` - Whether schedule is enabled (default: true)
- `timeout_ms` - Operation timeout in milliseconds (default: 10000)
- `json_pretty` - Pretty-print JSON output (default: false)

**Examples**

Daily backup at 2 AM:
```sh
backup://myapp.schedule(when="0 2 * * *", src="/data")
```

Weekly backup on Sundays:
```sh
backup://myapp.schedule(when="0 3 * * 0", src="/data", enabled="true")
```

**Output**

```json
{
  "op": "backup.schedule",
  "status": "ok",
  "target": "backup://myapp.schedule()",
  "backend": {
    "id": "restic",
    "command": [],
    "timeout_ms": 10000,
    "simulated": false
  },
  "result": {
    "capabilities": {
      "incremental": true,
      "dedup": true,
      "encryption": true,
      "retention": true,
      "verify": true,
      "cloud_targets": ["s3", "azure", "gcs", "file"]
    },
    "schedule": {
      "when": "0 2 * * *",
      "enabled": true,
      "runner": "systemd",
      "definition_path": "/home/user/resh-backup-myapp.json"
    }
  },
  "dry_run": false,
  "duration_ms": 100,
  "warnings": ["Schedule created but requires manual activation"]
}
```

## Error Handling

When operations fail, the handle returns error envelopes with detailed information:

```json
{
  "op": "backup.create",
  "status": "error",
  "target": "backup://myapp.create()",
  "backend": {
    "id": "restic",
    "command": ["restic", "backup", "/nonexistent"],
    "timeout_ms": 1800000,
    "simulated": false
  },
  "error": {
    "kind": "BACKEND_FAILED",
    "message": "Backend command failed",
    "details": {
      "exit_code": 1,
      "stderr_tail": "Fatal: unable to open config file: stat /nonexistent: no such file or directory"
    }
  },
  "dry_run": false,
  "duration_ms": 500,
  "warnings": []
}
```

## Best Practices

1. **Use descriptive labels and tags** for better organization
2. **Set up retention policies** to manage disk space
3. **Verify backups regularly** to ensure they can be restored
4. **Test restore procedures** before you need them
5. **Use appropriate backends** for your use case:
   - restic: For encrypted, deduplicated backups
   - borg: For local deduplicated backups
   - rsync: For simple file synchronization
   - tar: For basic archival

## Common Use Cases

### Daily Incremental Backups
```sh
backup://app.create(src="/var/app", tag="type=daily", label="daily-backup")
```

### Weekly Full Backups with Retention
```sh
backup://app.create(src="/var/app", tag="type=weekly", label="weekly-backup")
backup://app.prune(keep_weekly="4", keep_daily="7")
```

### Restore Last Backup
```sh
# First list to find the latest snapshot
backup://app.list()
# Then restore using the ID
backup://app.restore(snapshot_id="latest", dest="/restore")
```

### Scheduled Automated Backups
```sh
backup://app.schedule(when="0 2 * * *", src="/var/app")
```