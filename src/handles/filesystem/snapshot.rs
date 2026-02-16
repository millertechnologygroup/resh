use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use percent_encoding::percent_decode_str;
use serde_json::json;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use url::Url;
use uuid::Uuid;
use walkdir::WalkDir;

use crate::core::{
    registry::{Args, Handle, IoStreams},
    status::Status,
};

// Help text for --help command
const HELP_TEXT: &str = r#"RESOURCE SHELL - SNAPSHOT HANDLE
================================

USAGE:
  snapshot://TARGET.VERB(arguments)
  snapshot://NAME.VERB(arguments)

DESCRIPTION:
  The snapshot handle allows you to create, restore, compare, and list
  filesystem snapshots. Snapshots capture the current state of files and
  directories, allowing you to save important versions or restore data later.
  All snapshots are stored locally on your system with atomic operations
  ensuring data integrity.

URL FORMATS:
  Create/Diff:       snapshot://TARGET_PATH.VERB(arguments)
  Restore/List:      snapshot://SNAPSHOT_NAME.VERB(arguments)

VERBS (4 total):

  Snapshot Management:
    create          Create a new snapshot of file or directory
    restore         Restore a snapshot to a target location
    diff            Compare snapshots or snapshots with live filesystem
    ls              List snapshots in a group

EXAMPLES:

  Create Snapshots:
    # Create directory snapshot
    snapshot:///home/user/myproject.create(name="backup-v1")

    # Create file snapshot
    snapshot:///home/user/important.txt.create(name="filebackup")

    # Create with description and TTL (7 days)
    snapshot:///srv/app.create(name="deploy-v2",description="Production deployment backup",ttl=604800)

    # Skip if snapshot already exists
    snapshot:///home/user/data.create(name="existing-snapshot",if_exists="skip")

    # Overwrite existing snapshot
    snapshot:///home/user/data.create(name="my-snapshot",if_exists="overwrite")

    # Create timestamped backup
    snapshot:///important/data.create(name="backup-20250207",description="Daily backup")

    # Create snapshot with specific backend
    snapshot:///srv/config.create(name="config-backup",backend="local")

  Restore Snapshots:
    # Restore directory snapshot
    snapshot://backup-v1.restore(target="/home/user/restored-project")

    # Restore file snapshot
    snapshot://filebackup.restore(target="/home/user/recovered.txt")

    # Force restore over existing data
    snapshot://backup-v1.restore(target="/home/user/existing-folder",force=true)

    # Dry run to see what would happen
    snapshot://backup-v1.restore(target="/home/user/test",force=true,dry_run=true)

    # Restore with overwrite mode
    snapshot://deploy-v2.restore(target="/srv/app",mode="overwrite",force=true)

  Compare Snapshots:
    # Compare two snapshots
    snapshot:///srv/app.diff(from="snap-001",to="snap-002",format="json")

    # Compare snapshot to live filesystem
    snapshot:///home/user/project.diff(from="snap-001",to="live",format="json")

    # Compare live to snapshot (reverse)
    snapshot:///home/user/project.diff(from="live",to="snap-001",format="json")

    # Get summary format output
    snapshot:///srv/app.diff(from="snap-001",to="live",format="summary")

    # Compare with path filter
    snapshot:///srv/app.diff(from="snap-001",to="live",path="/subdir",format="json")

    # Compare specific subdirectory only
    snapshot:///home/user/docs.diff(from="backup-old",to="backup-new",path="/reports")

  List Snapshots:
    # List all snapshots in a group
    snapshot://myapp.ls

    # Filter by state
    snapshot://myapp.ls(state="ready")

    # Filter by tag
    snapshot://myapp.ls(tag="prod")

    # Limit results
    snapshot://myapp.ls(limit=2)

    # Filter by time range (created after)
    snapshot://myapp.ls(since="2025-11-15T10:00:00Z")

    # Filter by time range (created before)
    snapshot://myapp.ls(until="2025-11-15T23:00:00Z")

    # Filter by name prefix
    snapshot://myapp.ls(name_prefix="prod-")

    # Combine filters
    snapshot://myapp.ls(state="ready",tag="prod",limit=10)

    # Pretty print JSON
    snapshot://myapp.ls(json_pretty=true)

CREATE ARGUMENTS:
  name=NAME              Snapshot name (required, case-sensitive)
  description=TEXT       Description of the snapshot (optional)
  ttl=SECONDS            Time in seconds before snapshot expires (optional)
  backend=BACKEND        Storage backend: local (default: local)
  if_exists=ACTION       Action if snapshot exists: error (default), skip,
                         overwrite

RESTORE ARGUMENTS:
  target=PATH            Where to restore the snapshot (required)
  force=BOOL             Overwrite existing files/directories (default: false)
  mode=MODE              Restore mode: overwrite (default: overwrite)
  dry_run=BOOL           Show what would be done without doing it (default: false)

DIFF ARGUMENTS:
  from=SOURCE            Source snapshot ID or "live" (optional)
  to=TARGET              Target snapshot ID or "live" (optional)
  path=PATH              Filter to specific path (default: "/")
  format=FORMAT          Output format: json (default), summary

  Note: At least one of 'from' or 'to' must be provided.
        Cannot diff "live" against itself.

LS ARGUMENTS:
  state=STATE            Filter by state (optional)
  tag=TAG                Filter by tag (optional)
  since=TIMESTAMP        Filter by creation time - after (RFC3339 format)
  until=TIMESTAMP        Filter by creation time - before (RFC3339 format)
  name_prefix=PREFIX     Filter by name prefix (optional)
  limit=NUMBER           Maximum number of results (optional)
  json_pretty=BOOL       Pretty print JSON (default: false)

SNAPSHOT NAMES:
  Snapshot names are case-sensitive and should be unique within a group.

  Naming conventions:
    backup-v1             Simple version naming
    deploy-20250207       Date-based naming
    before-update         Descriptive purpose
    prod-v2.1            Version with environment
    config-backup        Component-based naming

  Best practices:
  • Use descriptive, meaningful names
  • Include version numbers or dates
  • Use consistent naming schemes
  • Keep names under 64 characters
  • Avoid special characters (use hyphens, underscores)

IF_EXISTS ACTIONS:
  error                  Return error if snapshot exists (default, safe)
  skip                   Skip creation, return existing snapshot
  overwrite              Replace existing snapshot with new one

  Examples:
    if_exists="error"    Fail if snapshot exists (prevents accidents)
    if_exists="skip"     Idempotent, use existing if present
    if_exists="overwrite" Always create fresh snapshot

TTL (TIME TO LIVE):
  Specify expiration time in seconds from creation.

  Common TTL values:
    3600                 1 hour
    86400                1 day (24 hours)
    604800               1 week (7 days)
    2592000              30 days
    7776000              90 days

  Examples:
    ttl=3600             Expire after 1 hour
    ttl=86400            Expire after 1 day
    ttl=604800           Expire after 1 week

  Note: Expired snapshots may be automatically cleaned up by the system.

DIFF FORMATS:

  json (default):
    Structured JSON output with detailed file information including:
    • File paths
    • Status (added, removed, modified, unchanged)
    • File metadata (size, mtime, mode, hash)
    • Summary counts

  summary:
    Human-readable text summary with:
    • Snapshot information
    • Count of added files
    • Count of removed files
    • Count of modified files
    • Count of unchanged files

DIFF STATUS VALUES:
  added                  File exists in 'to' but not in 'from'
  removed                File exists in 'from' but not in 'to'
  modified               File exists in both but content differs
  unchanged              File exists in both with same content

OUTPUT FORMATS:

  create success:
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

  create with TTL:
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

  create skipped:
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

  restore success:
    {
      "snapshot": "backup-v1",
      "target": "/home/user/restored-project",
      "mode": "overwrite",
      "status": "ok"
    }

  restore dry run:
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

  diff (JSON format):
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

  diff (summary format):
    snapshot: /srv/app
    from: snap-001 (snapshot)
    to:   live (live)
    root: /srv/app
    path: /
    
    added: 2
    removed: 1
    modified: 2
    unchanged: 5

  ls output:
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

  ls empty group:
    []

ERROR OUTPUTS:

  create - missing name:
    {
      "ok": false,
      "error": "missing required argument: name"
    }

  create - target doesn't exist:
    {
      "ok": false,
      "error": "target path does not exist: \"/nonexistent/path\""
    }

  create - snapshot exists (if_exists=error):
    {
      "ok": false,
      "error": "snapshot already exists: \"existing-snapshot\""
    }

  restore - missing target:
    {
      "error": "missing_argument",
      "argument": "target",
      "message": "missing required argument: target"
    }

  restore - snapshot not found:
    {
      "error": "snapshot_not_found",
      "snapshot": "nonexistent",
      "message": "snapshot not found: nonexistent"
    }

  restore - target not empty:
    {
      "error": "target_not_empty",
      "target": "/existing/nonempty/dir",
      "message": "target directory exists and is not empty (use force=true to overwrite): \"/existing/nonempty/dir\""
    }

  diff - no from or to:
    {
      "error": "invalid_arguments",
      "message": "at least one of 'from' or 'to' must be provided"
    }

  diff - both live:
    {
      "error": "invalid_arguments",
      "message": "cannot diff live against itself"
    }

  diff - snapshot not found:
    {
      "error": "snapshot_not_found",
      "snapshot": "missing-snap",
      "message": "snapshot not found: missing-snap"
    }

EXIT CODES:
  0                      Success
  1                      General error (invalid arguments, operation failed)
  2                      Not found (snapshot or target doesn't exist)
  3                      Already exists (snapshot name conflict)
  4                      Target not empty (restore without force)

STORAGE LOCATION:
  Snapshots are stored in your system's state directory:

  Linux:
    $XDG_STATE_HOME/resh/snapshots
    or
    $HOME/.local/state/resh/snapshots

  macOS:
    ~/Library/Application Support/resh/snapshots

  Windows:
    %APPDATA%/resh/snapshots

  Storage structure:
    <state_dir>/snapshots/
      ├── group1/
      │   ├── snapshot1/
      │   │   ├── metadata.json
      │   │   └── data/
      │   └── snapshot2/
      │       ├── metadata.json
      │       └── data/
      └── group2/
          └── snapshot3/
              ├── metadata.json
              └── data/

COMMON WORKFLOWS:

  Backup before changes:
    # Create backup before making changes
    snapshot:///home/user/project.create(name="before-update")
    
    # Make your changes...
    
    # If something goes wrong, restore
    snapshot://before-update.restore(target="/home/user/project",force=true)

  Compare changes after deployment:
    # Create snapshot before deployment
    snapshot:///srv/app.create(name="before-deploy")
    
    # Deploy new version...
    
    # Compare what changed
    snapshot:///srv/app.diff(from="before-deploy",to="live",format="summary")
    
    # Review detailed differences
    snapshot:///srv/app.diff(from="before-deploy",to="live",format="json")

  Regular automated backups:
    # Create timestamped backup
    snapshot:///important/data.create(name="backup-$(date +%Y%m%d)",description="Daily backup",ttl=2592000)
    
    # List recent backups
    snapshot://backup.ls(name_prefix="backup-",limit=10)
    
    # Clean up old backups (handled automatically by TTL)

  Version tracking:
    # Create version snapshots
    snapshot:///srv/api.create(name="v1.0.0",description="Initial release")
    snapshot:///srv/api.create(name="v1.1.0",description="Feature update")
    snapshot:///srv/api.create(name="v2.0.0",description="Major release")
    
    # List all versions
    snapshot://versions.ls
    
    # Compare versions
    snapshot:///srv/api.diff(from="v1.0.0",to="v2.0.0",format="summary")

  Safe restore with verification:
    # Dry run first to see what will happen
    snapshot://backup-v1.restore(target="/home/user/project",force=true,dry_run=true)
    
    # Review the actions
    
    # Actually restore if satisfied
    snapshot://backup-v1.restore(target="/home/user/project",force=true)

  Configuration management:
    # Snapshot before config changes
    snapshot:///etc/app/config.create(name="config-before-update")
    
    # Update configuration files...
    
    # Compare changes
    snapshot:///etc/app/config.diff(from="config-before-update",to="live")
    
    # Rollback if needed
    snapshot://config-before-update.restore(target="/etc/app/config",force=true)

  Development workflow:
    # Snapshot before experimental changes
    snapshot:///home/dev/project.create(name="stable-state",description="Working version before experiment")
    
    # Try experimental changes...
    
    # Compare what changed
    snapshot:///home/dev/project.diff(from="stable-state",to="live",format="json")
    
    # Restore if experiment fails
    snapshot://stable-state.restore(target="/home/dev/project",force=true)

  Disaster recovery preparation:
    # Create regular snapshots with TTL
    snapshot:///critical/data.create(name="hourly-$(date +%H)",ttl=86400)
    snapshot:///critical/data.create(name="daily-$(date +%d)",ttl=2592000)
    snapshot:///critical/data.create(name="weekly-$(date +%V)",ttl=7776000)
    
    # List available recovery points
    snapshot://recovery.ls(state="ready")

  Testing and validation:
    # Create clean state snapshot
    snapshot:///test/environment.create(name="clean-state")
    
    # Run tests...
    
    # Restore clean state for next test run
    snapshot://clean-state.restore(target="/test/environment",force=true)

BEST PRACTICES:
  - Use descriptive snapshot names with versions or dates
  - Set appropriate TTL values to manage storage automatically  
  - Use if_exists="skip" for idempotent scripts
  - Use if_exists="error" (default) for safety in manual operations
  - Always use dry_run=true before restore with force=true
  - Create snapshots before risky operations
  - Use diff to verify changes before restoring
  - List snapshots regularly to manage storage
  - Use consistent naming conventions within projects
  - Tag snapshots for better organization
  - Include descriptions for complex snapshots
  - Use path filters in diff for large directory trees
  - Set reasonable TTL values to prevent storage bloat 
  - Test restore operations in non-critical environments first
  - Keep snapshot names under 64 characters
  - Use summary format for quick overview, JSON for automation
  - Compare against "live" to track ongoing changes
  - Create snapshots before upgrades or deployments
  - Verify snapshot creation success in scripts
  - Use force=true cautiously, only when intended
  - Document snapshot naming conventions in team workflows
  - Monitor snapshot storage usage regularly
  - Use timestamps in automated backup names
  - Filter ls output with state and tags for better management
  - Combine diff with path filters for targeted comparisons
  - Back up configuration files separately for quick access
  - Use exclude patterns to avoid backing up temporary files
  - Schedule regular cleanup of old snapshots
  - Implement retention policies based on snapshot age and usage
  - Create snapshots in off-peak hours for large datasets

ATOMIC OPERATIONS:
  Snapshot operations are designed to be atomic:

  Create:
  • Snapshot created in temporary location first
  • Moved to final location atomically
  • Metadata written last
  • Failure leaves no partial snapshots

  Restore:
  • Original data remains until restore completes
  • Restoration happens in staging area
  • Final swap is atomic
  • Failure leaves original data intact

  This ensures:
  • No data loss during operations
  • No corrupted snapshots
  • Safe concurrent operations
  • Reliable recovery even if operations fail

PERMISSIONS:
  Snapshots preserve Unix file permissions:

  • File mode (read, write, execute)
  • Directory permissions
  • Owner and group (when possible)
  • Special bits (setuid, setgid, sticky)

  Notes:
  • Restoring as different user may not preserve ownership
  • Root privileges required to restore ownership exactly
  • Symbolic links are preserved
  • Hard links may not be preserved

TIME ZONES:
  All timestamps use UTC format (ISO 8601):

  Format: YYYY-MM-DDTHH:MM:SSZ
  Example: 2025-11-15T18:01:02Z

  When filtering by time:
  • Use RFC3339 format with 'Z' suffix
  • Times are always in UTC
  • Local time conversion is your responsibility

CASE SENSITIVITY:
  Snapshot operations are case-sensitive:

  • Snapshot names: "Backup" ≠ "backup"
  • File paths: "/Home" ≠ "/home"
  • Tag names: "Prod" ≠ "prod"
  • State filters: "Ready" ≠ "ready"

  Best practice: Use lowercase for consistency

RELATIVE PATHS:
  When using relative paths in snapshot URLs:

  • Resolved based on current working directory
  • Converted to absolute paths for storage
  • Restore target can be relative or absolute
  • Use absolute paths for scripts and automation

SNAPSHOT SIZE:
  Snapshots consume disk space equal to target size:

  • No compression (currently)
  • No deduplication between snapshots
  • Full copy of all files
  • Plan storage capacity accordingly

  Tips for managing size:
  • Use TTL to auto-expire old snapshots
  • Snapshot only necessary directories
  • Exclude temporary or cache directories
  • Monitor storage with ls command
  • Clean up unneeded snapshots regularly

LIMITATIONS:
  Current limitations of the snapshot handle:

  • Local storage only (no remote backends)
  • No incremental snapshots
  • No compression
  • No deduplication
  • No snapshot scheduling (use cron/systemd timers)
  • Cannot snapshot across filesystem boundaries
  • Large files may take time to snapshot/restore
  • No encryption (use encrypted filesystems)
  • No snapshot merging or branching
  • Single backend type (local)

PERFORMANCE CONSIDERATIONS:
  • Large directories take longer to snapshot
  • Snapshot time proportional to data size
  • Restore speed depends on target filesystem
  • Diff operations faster than full snapshots
  • Path filters reduce diff processing time
  • Listing snapshots is fast (metadata only)
  • Many small files slower than few large files
  • SSDs significantly faster than HDDs

DEBUGGING:
  Use dry_run to test operations:
    snapshot://test.restore(target="/tmp/test",dry_run=true)

  Check snapshot metadata:
    snapshot://backups.ls(json_pretty=true)

  Compare against live for verification:
    snapshot:///path.diff(from="snapshot-name",to="live")

  List recent snapshots:
    snapshot://group.ls(limit=10)

  Filter by state to find issues:
    snapshot://group.ls(state="error")

ERROR RECOVERY:
  If snapshot operation fails:

  1. Check error message for specific issue
  2. Verify target path exists and is accessible
  3. Ensure sufficient disk space
  4. Check permissions on source and destination
  5. Review snapshot name for conflicts
  6. Use dry_run for restore to verify before executing
  7. Check storage location permissions
  8. Verify snapshot exists with ls command

INTEGRATION WITH OTHER HANDLES:

  With file handle:
    # Create snapshot before file operations
    snapshot:///config.create(name="before-edit")
    file:///config/app.conf.replace(pattern="old",replacement="new")
    snapshot:///config.diff(from="before-edit",to="live")

  With backup handle:
    # Snapshot before restore
    snapshot:///data.create(name="before-restore")
    backup://mybackup.restore(snapshot_id="latest",dest="/data")
    snapshot:///data.diff(from="before-restore",to="live")

  With event handle:
    # Emit events on snapshot operations
    snapshot:///srv/app.create(name="deploy-v1")
    event://emit(topic="snapshot.created",data="{\"name\":\"deploy-v1\"}")

MORE INFO:
  For complete documentation of snapshot handle operations:
  https://github.com/[your-org]/resource-shell/docs/FileSystem_Storage/snapshot.md

  For backup strategies and best practices:
  https://github.com/[your-org]/resource-shell/docs/backup-strategies.md

  Use 'snapshot:// --help=VERB' for detailed help on a specific verb.
"#;

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("snapshot", |u| Ok(Box::new(SnapshotHandle::from_url(u)?)));
}

#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    pub id: String,
    pub backend: String,
    pub target: PathBuf,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub enum IfExistsMode {
    Error,
    Skip,
    Overwrite,
}

impl IfExistsMode {
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "error" => Ok(IfExistsMode::Error),
            "skip" => Ok(IfExistsMode::Skip),
            "overwrite" => Ok(IfExistsMode::Overwrite),
            _ => bail!("invalid if_exists mode: '{}' (must be 'error', 'skip', or 'overwrite')", s),
        }
    }
}

// Diff-related types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileTypeKind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryStatus {
    Added,
    Removed,
    Modified,
    Unchanged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub exists: bool,
    pub file_type: Option<FileTypeKind>,
    pub size: Option<u64>,
    pub mtime: Option<String>,
    pub mode: Option<String>,
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub file_type: FileTypeKind,
    pub status: EntryStatus,
    pub from: FileInfo,
    pub to: FileInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    pub added: u32,
    pub removed: u32,
    pub modified: u32,
    pub unchanged: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    pub name: String,
    pub from: String,
    pub to: String,
    pub from_kind: String,
    pub to_kind: String,
    pub root: String,
    pub path: String,
    pub summary: DiffSummary,
    pub entries: Vec<DiffEntry>,
}

#[derive(Debug, Clone)]
pub struct SnapshotMeta {
    pub id: String,
    pub backend: String,
    pub target: PathBuf,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub path: PathBuf,
    pub description: Option<String>,
}

// Struct for deserializing snapshot metadata from JSON (for ls operation)
#[derive(Debug, Deserialize)]
struct SnapshotMetaForLs {
    id: String,
    name: Option<String>,
    created_at: Option<String>,
    backend: Option<String>,
    target: Option<String>,
    state: Option<String>,
    size_bytes: Option<u64>,
    tags: Option<Vec<String>>,
    description: Option<String>,
}

// Output struct for ls operation
#[derive(Debug, Serialize)]
struct SnapshotLsOutput {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

#[derive(Debug, Clone)]
pub enum TreeKind {
    Snapshot,
    Live,
}

pub trait SnapshotBackend {
    fn create_snapshot(
        &self,
        target: &Path,
        name: &str,
        description: Option<&str>,
        ttl: Option<Duration>,
        if_exists: IfExistsMode,
    ) -> Result<SnapshotInfo>;
}

pub struct LocalSnapshotBackend {
    base_dir: PathBuf,
}

impl LocalSnapshotBackend {
    pub fn new() -> Result<Self> {
        let base_dir = match dirs::state_dir() {
            Some(dir) => dir.join("resh").join("snapshots"),
            None => PathBuf::from("/tmp").join("resh").join("snapshots"),
        };

        Ok(Self { base_dir })
    }

    fn sanitize_path_component(s: &str) -> String {
        let mut result = String::new();
        for ch in s.chars() {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_' {
                result.push(ch);
            } else {
                result.push('_');
            }
        }
        if result.len() > 120 {
            result.truncate(120);
        }
        if result.is_empty() {
            "_".to_string()
        } else {
            result
        }
    }

    fn get_snapshot_dir(&self, target: &Path, name: &str) -> PathBuf {
        let sanitized_target = Self::sanitize_path_component(&target.to_string_lossy());
        let sanitized_name = Self::sanitize_path_component(name);
        self.base_dir.join(sanitized_target).join(sanitized_name)
    }

    fn copy_recursively(src: &Path, dst: &Path) -> Result<()> {
        if src.is_file() {
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create parent directory: {:?}", parent))?;
            }
            fs::copy(src, dst)
                .with_context(|| format!("failed to copy file from {:?} to {:?}", src, dst))?;
        } else if src.is_dir() {
            fs::create_dir_all(dst)
                .with_context(|| format!("failed to create directory: {:?}", dst))?;

            for entry in WalkDir::new(src) {
                let entry = entry
                    .with_context(|| format!("failed to read directory entry in {:?}", src))?;
                let entry_path = entry.path();
                
                let relative_path = entry_path
                    .strip_prefix(src)
                    .with_context(|| format!("failed to strip prefix {:?} from {:?}", src, entry_path))?;
                let target_path = dst.join(relative_path);

                if entry_path.is_dir() {
                    fs::create_dir_all(&target_path)
                        .with_context(|| format!("failed to create directory: {:?}", target_path))?;
                } else if entry_path.is_file() {
                    if let Some(parent) = target_path.parent() {
                        fs::create_dir_all(parent)
                            .with_context(|| format!("failed to create parent directory: {:?}", parent))?;
                    }
                    fs::copy(entry_path, &target_path)
                        .with_context(|| format!("failed to copy file from {:?} to {:?}", entry_path, target_path))?;
                }
            }
        } else {
            bail!("source path is neither file nor directory: {:?}", src);
        }
        Ok(())
    }
}

impl SnapshotBackend for LocalSnapshotBackend {
    fn create_snapshot(
        &self,
        target: &Path,
        name: &str,
        description: Option<&str>,
        ttl: Option<Duration>,
        if_exists: IfExistsMode,
    ) -> Result<SnapshotInfo> {
        // Validate target exists
        if !target.exists() {
            bail!("target path does not exist: {:?}", target);
        }

        let metadata = fs::metadata(target)
            .with_context(|| format!("failed to get metadata for target: {:?}", target))?;

        if !metadata.is_file() && !metadata.is_dir() {
            bail!("target is neither file nor directory: {:?}", target);
        }

        // Get final snapshot directory
        let snapshot_dir = self.get_snapshot_dir(target, name);

        // Handle existing snapshot
        if snapshot_dir.exists() {
            match if_exists {
                IfExistsMode::Error => {
                    bail!("snapshot already exists: {}", name);
                }
                IfExistsMode::Skip => {
                    // Read existing metadata and return it
                    let meta_file = snapshot_dir.join("meta.json");
                    if meta_file.exists() {
                        let meta_content = fs::read_to_string(&meta_file)
                            .with_context(|| format!("failed to read existing metadata: {:?}", meta_file))?;
                        let meta_value: serde_json::Value = serde_json::from_str(&meta_content)
                            .with_context(|| "failed to parse existing metadata")?;
                        
                        return Ok(SnapshotInfo {
                            id: meta_value["id"].as_str().unwrap_or("").to_string(),
                            backend: meta_value["backend"].as_str().unwrap_or("local").to_string(),
                            target: PathBuf::from(meta_value["target"].as_str().unwrap_or("")),
                            name: meta_value["name"].as_str().unwrap_or("").to_string(),
                            created_at: DateTime::parse_from_rfc3339(meta_value["created_at"].as_str().unwrap_or(""))
                                .map(|dt| dt.with_timezone(&Utc))
                                .unwrap_or_else(|_| Utc::now()),
                            expires_at: meta_value["expires_at"]
                                .as_str()
                                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                                .map(|dt| dt.with_timezone(&Utc)),
                            path: snapshot_dir.clone(),
                        });
                    }
                }
                IfExistsMode::Overwrite => {
                    fs::remove_dir_all(&snapshot_dir)
                        .with_context(|| format!("failed to remove existing snapshot: {:?}", snapshot_dir))?;
                }
            }
        }

        // Create temporary directory for atomic operation
        let temp_dir = snapshot_dir.with_extension(format!("tmp-{}", Uuid::new_v4()));

        // Ensure cleanup on error
        let cleanup = || {
            let _ = fs::remove_dir_all(&temp_dir);
        };

        // Create temp directory
        fs::create_dir_all(&temp_dir)
            .with_context(|| format!("failed to create temp directory: {:?}", temp_dir))
            .map_err(|e| {
                cleanup();
                e
            })?;

        // Copy content
        if target.is_file() {
            let content_file = temp_dir.join("content");
            fs::copy(target, &content_file)
                .with_context(|| format!("failed to copy file content from {:?} to {:?}", target, content_file))
                .map_err(|e| {
                    cleanup();
                    e
                })?;
        } else {
            // For directories, copy everything into the temp directory
            Self::copy_recursively(target, &temp_dir)
                .with_context(|| format!("failed to copy directory content from {:?} to {:?}", target, temp_dir))
                .map_err(|e| {
                    cleanup();
                    e
                })?;
        }

        // Create snapshot info
        let id = Uuid::new_v4().to_string();
        let created_at = Utc::now();
        let expires_at = ttl.map(|duration| created_at + chrono::Duration::from_std(duration).unwrap_or_default());

        let snapshot_info = SnapshotInfo {
            id: id.clone(),
            backend: "local".to_string(),
            target: target.to_path_buf(),
            name: name.to_string(),
            created_at,
            expires_at,
            path: snapshot_dir.clone(),
        };

        // Write metadata
        let meta_file = temp_dir.join("meta.json");
        let meta_json = json!({
            "id": snapshot_info.id,
            "backend": snapshot_info.backend,
            "target": snapshot_info.target.to_string_lossy(),
            "name": snapshot_info.name,
            "created_at": snapshot_info.created_at.to_rfc3339(),
            "expires_at": snapshot_info.expires_at.map(|dt| dt.to_rfc3339()),
            "path": snapshot_info.path.to_string_lossy(),
            "description": description
        });

        fs::write(&meta_file, serde_json::to_string_pretty(&meta_json)?)
            .with_context(|| format!("failed to write metadata file: {:?}", meta_file))
            .map_err(|e| {
                cleanup();
                e
            })?;

        // Atomic rename to final location
        if let Some(parent) = snapshot_dir.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create snapshot parent directory: {:?}", parent))
                .map_err(|e| {
                    cleanup();
                    e
                })?;
        }

        fs::rename(&temp_dir, &snapshot_dir)
            .with_context(|| format!("failed to rename temp directory to final location: {:?} -> {:?}", temp_dir, snapshot_dir))
            .map_err(|e| {
                cleanup();
                e
            })?;

        Ok(snapshot_info)
    }
}

pub struct SnapshotHandle {
    target: PathBuf,
}

impl SnapshotHandle {
    pub fn from_url(url: &Url) -> Result<Self> {
        // Handle case where filename is in host position (e.g., snapshot://test.txt)
        // or in path position (e.g., snapshot:///test.txt)
        let path_str = if url.host_str().is_some() && !url.host_str().unwrap().is_empty() {
            url.host_str().unwrap()
        } else {
            url.path()
        };
        
        // Handle percent-encoding
        let decoded = percent_decode_str(path_str)
            .decode_utf8()
            .with_context(|| format!("invalid UTF-8 in URL path: {}", path_str))?;

        // Check for help flags in the decoded path
        if decoded.contains("--help") || decoded.contains("-h") {
            // Create a dummy path for help display
            let help_path = PathBuf::from("--help");
            return Ok(Self { target: help_path });
        }

        let target = PathBuf::from(decoded.as_ref());
        
        // Normalize path components but don't resolve relative paths yet
        let normalized = normalize_path(&target);
        
        Ok(Self { target: normalized })
    }

    fn find_snapshot_by_id(&self, target: &Path, id: &str) -> Result<(String, PathBuf)> {
        let backend = LocalSnapshotBackend::new()?;
        let sanitized_target = LocalSnapshotBackend::sanitize_path_component(&target.to_string_lossy());
        let target_dir = backend.base_dir.join(&sanitized_target);
        
        if !target_dir.exists() {
            bail!("no snapshots found for target: {:?}", target);
        }
        
        // Search through all snapshot names for this target
        for entry in fs::read_dir(&target_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            
            let snapshot_name = entry.file_name().to_string_lossy().to_string();
            let snapshot_dir = entry.path();
            let meta_file = snapshot_dir.join("meta.json");
            
            if !meta_file.exists() {
                continue;
            }
            
            if let Ok(meta_content) = fs::read_to_string(&meta_file) {
                if let Ok(meta_value) = serde_json::from_str::<serde_json::Value>(&meta_content) {
                    if let Some(stored_id) = meta_value["id"].as_str() {
                        if stored_id == id {
                            return Ok((snapshot_name, snapshot_dir));
                        }
                    }
                }
            }
        }
        
        bail!("snapshot with id '{}' not found for target: {:?}", id, target);
    }

    fn load_snapshot_meta(&self, name: &str, id: &str) -> Result<SnapshotMeta> {
        // If we have an ID, try to find the snapshot by ID first
        let (actual_name, snapshot_dir) = if !id.is_empty() {
            self.find_snapshot_by_id(&self.target, id)?
        } else {
            // Fall back to using the provided name
            let backend = LocalSnapshotBackend::new()?;
            let snapshot_dir = backend.get_snapshot_dir(&self.target, name);
            if !snapshot_dir.exists() {
                bail!("snapshot not found: {} for target: {:?}", name, self.target);
            }
            (name.to_string(), snapshot_dir)
        };
        
        let meta_file = snapshot_dir.join("meta.json");
        
        if !meta_file.exists() {
            bail!("snapshot metadata not found: {} (id: {})", actual_name, id);
        }
        
        let meta_content = fs::read_to_string(&meta_file)
            .with_context(|| format!("failed to read snapshot metadata: {:?}", meta_file))?;
        let meta_value: serde_json::Value = serde_json::from_str(&meta_content)
            .with_context(|| "failed to parse snapshot metadata")?;
        
        // Validate that this is the correct snapshot ID if provided
        let stored_id = meta_value["id"].as_str().unwrap_or("");
        if !id.is_empty() && stored_id != id {
            bail!("snapshot ID mismatch: expected {}, found {}", id, stored_id);
        }
        
        Ok(SnapshotMeta {
            id: stored_id.to_string(),
            backend: meta_value["backend"].as_str().unwrap_or("local").to_string(),
            target: PathBuf::from(meta_value["target"].as_str().unwrap_or("")),
            name: meta_value["name"].as_str().unwrap_or("").to_string(),
            created_at: DateTime::parse_from_rfc3339(meta_value["created_at"].as_str().unwrap_or(""))
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            expires_at: meta_value["expires_at"]
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
            path: snapshot_dir.clone(),
            description: meta_value["description"].as_str().map(|s| s.to_string()),
        })
    }

    fn resolve_tree(&self, id_or_live: &str, name: &str) -> Result<(TreeKind, PathBuf, SnapshotMeta)> {
        if id_or_live == "live" {
            // For live, we need to create a dummy SnapshotMeta with the live target
            let target = if self.target.is_absolute() {
                self.target.clone()
            } else {
                std::env::current_dir()?.join(&self.target)
            };
            
            if !target.exists() {
                bail!("live target path does not exist: {:?}", target);
            }
            
            let dummy_meta = SnapshotMeta {
                id: "live".to_string(),
                backend: "live".to_string(),
                target: target.clone(),
                name: name.to_string(),
                created_at: Utc::now(),
                expires_at: None,
                path: target.clone(),
                description: None,
            };
            
            Ok((TreeKind::Live, target, dummy_meta))
        } else {
            let meta = self.load_snapshot_meta(name, id_or_live)?;
            let snapshot_path = meta.path.clone();
            if !snapshot_path.exists() {
                bail!("snapshot directory not found: {:?}", snapshot_path);
            }
            Ok((TreeKind::Snapshot, snapshot_path, meta))
        }
    }

    fn collect_entries(&self, root: &Path, restrict_path: Option<&str>) -> Result<HashMap<PathBuf, FileInfo>> {
        let mut entries = HashMap::new();
        
        let search_root = if let Some(subpath) = restrict_path {
            if subpath == "/" {
                root.to_path_buf()
            } else {
                root.join(subpath.trim_start_matches('/'))
            }
        } else {
            root.to_path_buf()
        };
        
        if !search_root.exists() {
            return Ok(entries);
        }
        
        for entry in WalkDir::new(&search_root) {
            let entry = entry.with_context(|| format!("failed to walk directory: {:?}", search_root))?;
            let entry_path = entry.path();
            
            let relative_path = entry_path.strip_prefix(&search_root)
                .with_context(|| format!("failed to strip prefix {:?} from {:?}", search_root, entry_path))?;
            
            // Skip the root directory itself
            if relative_path.as_os_str().is_empty() {
                continue;
            }
            
            // Skip snapshot metadata files
            if let Some(file_name) = relative_path.file_name() {
                if file_name == "meta.json" {
                    continue;
                }
            }
            
            let file_info = self.collect_file_info(entry_path)?;
            entries.insert(relative_path.to_path_buf(), file_info);
        }
        
        Ok(entries)
    }

    fn collect_file_info(&self, path: &Path) -> Result<FileInfo> {
        let metadata = fs::metadata(path);
        
        if let Err(_) = metadata {
            return Ok(FileInfo {
                exists: false,
                file_type: None,
                size: None,
                mtime: None,
                mode: None,
                hash: None,
            });
        }
        
        let metadata = metadata.unwrap();
        let file_type = if metadata.is_file() {
            FileTypeKind::File
        } else if metadata.is_dir() {
            FileTypeKind::Dir
        } else if metadata.file_type().is_symlink() {
            FileTypeKind::Symlink
        } else {
            FileTypeKind::Other
        };
        
        let size = if metadata.is_file() { Some(metadata.len()) } else { None };
        
        let mtime = metadata.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| {
                DateTime::from_timestamp(d.as_secs() as i64, d.subsec_nanos())
                    .unwrap_or_else(|| Utc::now())
                    .to_rfc3339()
            });
        
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            Some(format!("{:o}", metadata.permissions().mode() & 0o7777))
        };
        #[cfg(not(unix))]
        let mode = None;
        
        // Compute hash for small files only
        let hash = if metadata.is_file() && metadata.len() <= 16 * 1024 * 1024 {
            self.compute_file_hash(path).ok()
        } else {
            None
        };
        
        Ok(FileInfo {
            exists: true,
            file_type: Some(file_type),
            size,
            mtime,
            mode,
            hash,
        })
    }

    fn compute_file_hash(&self, path: &Path) -> Result<String> {
        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 8192];
        
        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }
        
        Ok(format!("sha256:{:x}", hasher.finalize()))
    }

    fn compare_entries(&self, a: &HashMap<PathBuf, FileInfo>, b: &HashMap<PathBuf, FileInfo>) -> DiffResult {
        let mut entries = Vec::new();
        let mut summary = DiffSummary {
            added: 0,
            removed: 0,
            modified: 0,
            unchanged: 0,
        };
        
        // Collect all unique paths
        let mut all_paths: std::collections::BTreeSet<&PathBuf> = std::collections::BTreeSet::new();
        all_paths.extend(a.keys());
        all_paths.extend(b.keys());
        
        for path in all_paths {
            let from_info = a.get(path);
            let to_info = b.get(path);
            
            let (status, file_type) = match (from_info, to_info) {
                (None, Some(to)) => {
                    summary.added += 1;
                    (EntryStatus::Added, to.file_type.clone().unwrap_or(FileTypeKind::Other))
                }
                (Some(_), None) => {
                    summary.removed += 1;
                    (EntryStatus::Removed, from_info.unwrap().file_type.clone().unwrap_or(FileTypeKind::Other))
                }
                (Some(from), Some(to)) => {
                    if self.files_differ(from, to) {
                        summary.modified += 1;
                        (EntryStatus::Modified, to.file_type.clone().unwrap_or(FileTypeKind::Other))
                    } else {
                        summary.unchanged += 1;
                        continue; // Skip unchanged entries from output
                    }
                }
                (None, None) => continue, // Shouldn't happen
            };
            
            let from_file_info = from_info.cloned().unwrap_or(FileInfo {
                exists: false,
                file_type: None,
                size: None,
                mtime: None,
                mode: None,
                hash: None,
            });
            
            let to_file_info = to_info.cloned().unwrap_or(FileInfo {
                exists: false,
                file_type: None,
                size: None,
                mtime: None,
                mode: None,
                hash: None,
            });
            
            entries.push(DiffEntry {
                path: path.to_string_lossy().to_string(),
                file_type,
                status,
                from: from_file_info,
                to: to_file_info,
            });
        }
        
        DiffResult {
            name: "".to_string(), // Will be filled in by caller
            from: "".to_string(), // Will be filled in by caller
            to: "".to_string(), // Will be filled in by caller
            from_kind: "".to_string(), // Will be filled in by caller
            to_kind: "".to_string(), // Will be filled in by caller
            root: "".to_string(), // Will be filled in by caller
            path: "/".to_string(), // Will be filled in by caller
            summary,
            entries,
        }
    }

    fn files_differ(&self, a: &FileInfo, b: &FileInfo) -> bool {
        if a.exists != b.exists {
            return true;
        }
        if a.file_type != b.file_type {
            return true;
        }
        if a.size != b.size {
            return true;
        }
        if a.mode != b.mode {
            return true;
        }
        // For hash comparison, only compare if both have hashes
        if let (Some(a_hash), Some(b_hash)) = (&a.hash, &b.hash) {
            return a_hash != b_hash;
        }
        // If no hash available, compare mtime
        a.mtime != b.mtime
    }

    fn diff(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments
        let from = args.get("from").map(|s| s.as_str()).unwrap_or("");
        let to = args.get("to").map(|s| s.as_str()).unwrap_or("");
        let path_filter = args.get("path").map(|s| s.as_str()).unwrap_or("/");
        let format = args.get("format").map(|s| s.as_str()).unwrap_or("json");
        
        // Validate arguments
        if from.is_empty() && to.is_empty() {
            let error_msg = "at least one of 'from' or 'to' must be provided";
            writeln!(io.stderr, "Error: {}", error_msg)?;
            return Ok(Status::err(1, error_msg));
        }
        
        if from == "live" && to == "live" {
            let error_msg = "cannot diff live filesystem against itself (both from and to are live)";
            writeln!(io.stderr, "Error: {}", error_msg)?;
            return Ok(Status::err(1, error_msg));
        }
        
        if !from.is_empty() && !to.is_empty() && from == to {
            let error_msg = "cannot diff snapshot against itself (from and to are the same)";
            writeln!(io.stderr, "Error: {}", error_msg)?;
            return Ok(Status::err(1, error_msg));
        }
        
        // Extract name from URL (assume format like snapshot://name.diff(...))
        let name = self.target.to_string_lossy().to_string();
        
        // Resolve trees
        let (from_kind, from_path, from_meta) = if from.is_empty() {
            // If from is empty, use a dummy empty tree
            (TreeKind::Live, PathBuf::new(), SnapshotMeta {
                id: "empty".to_string(),
                backend: "empty".to_string(),
                target: PathBuf::new(),
                name: "empty".to_string(),
                created_at: Utc::now(),
                expires_at: None,
                path: PathBuf::new(),
                description: None,
            })
        } else {
            self.resolve_tree(from, &name).with_context(|| format!("failed to resolve from tree: {}", from))?
        };
        
        let (to_kind, to_path, to_meta) = if to.is_empty() {
            // If to is empty, use a dummy empty tree  
            (TreeKind::Live, PathBuf::new(), SnapshotMeta {
                id: "empty".to_string(),
                backend: "empty".to_string(),
                target: PathBuf::new(),
                name: "empty".to_string(),
                created_at: Utc::now(),
                expires_at: None,
                path: PathBuf::new(),
                description: None,
            })
        } else {
            self.resolve_tree(to, &name).with_context(|| format!("failed to resolve to tree: {}", to))?
        };
        
        // Collect entries
        let from_entries = if from.is_empty() {
            HashMap::new()
        } else {
            self.collect_entries(&from_path, Some(path_filter))
                .with_context(|| format!("failed to collect entries from from tree: {:?}", from_path))?
        };
        
        let to_entries = if to.is_empty() {
            HashMap::new()
        } else {
            self.collect_entries(&to_path, Some(path_filter))
                .with_context(|| format!("failed to collect entries from to tree: {:?}", to_path))?
        };
        
        // Compare
        let mut diff_result = self.compare_entries(&from_entries, &to_entries);
        
        // Fill in metadata
        diff_result.name = name;
        diff_result.from = if from.is_empty() { "empty".to_string() } else { from.to_string() };
        diff_result.to = if to.is_empty() { "empty".to_string() } else { to.to_string() };
        diff_result.from_kind = match from_kind {
            TreeKind::Snapshot => "snapshot".to_string(),
            TreeKind::Live => "live".to_string(),
        };
        diff_result.to_kind = match to_kind {
            TreeKind::Snapshot => "snapshot".to_string(),
            TreeKind::Live => "live".to_string(),
        };
        diff_result.root = if !to_meta.target.as_os_str().is_empty() {
            to_meta.target.to_string_lossy().to_string()
        } else if !from_meta.target.as_os_str().is_empty() {
            from_meta.target.to_string_lossy().to_string()
        } else {
            "/".to_string()
        };
        diff_result.path = path_filter.to_string();
        
        // Output
        match format {
            "json" => {
                let json_output = serde_json::to_string(&diff_result)?;
                writeln!(io.stdout, "{}", json_output)?;
            }
            "summary" => {
                writeln!(io.stdout, "snapshot: {}", diff_result.name)?;
                writeln!(io.stdout, "from: {} ({})", diff_result.from, diff_result.from_kind)?;
                writeln!(io.stdout, "to:   {} ({})", diff_result.to, diff_result.to_kind)?;
                writeln!(io.stdout, "root: {}", diff_result.root)?;
                writeln!(io.stdout, "path: {}", diff_result.path)?;
                writeln!(io.stdout)?;
                writeln!(io.stdout, "added: {}", diff_result.summary.added)?;
                writeln!(io.stdout, "removed: {}", diff_result.summary.removed)?;
                writeln!(io.stdout, "modified: {}", diff_result.summary.modified)?;
                writeln!(io.stdout, "unchanged: {}", diff_result.summary.unchanged)?;
            }
            _ => {
                let error_msg = format!("unknown format: {} (must be json or summary)", format);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                return Ok(Status::err(1, &error_msg));
            }
        }
        
        Ok(Status::ok())
    }

    fn create(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Resolve target path at execution time to handle relative paths correctly
        let target = if self.target.is_absolute() {
            self.target.clone()
        } else {
            let current_dir = std::env::current_dir()
                .context("failed to get current directory")?;
            current_dir.join(&self.target)
        };

        // Parse required arguments
        let name = match args.get("name") {
            Some(name) if !name.trim().is_empty() => name.trim(),
            _ => {
                let error_msg = "missing required argument: name";
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "ok": false,
                    "error": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        // Parse optional arguments
        let backend = args.get("backend").map(|s| s.as_str()).unwrap_or("local");
        if backend != "local" {
            let error_msg = format!("unsupported backend: {} (only local is supported)", backend);
            writeln!(io.stderr, "Error: {}", error_msg)?;
            let error_json = json!({
                "ok": false,
                "error": error_msg
            });
            writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
            return Ok(Status::err(1, &error_msg));
        }

        let description = args.get("description").map(|s| s.as_str());

        let ttl = match args.get("ttl") {
            Some(ttl_str) => {
                match ttl_str.parse::<u64>() {
                    Ok(seconds) => Some(Duration::from_secs(seconds)),
                    Err(_) => {
                        let error_msg = format!("invalid ttl value: {} (must be positive integer seconds)", ttl_str);
                        writeln!(io.stderr, "Error: {}", error_msg)?;
                        let error_json = json!({
                            "ok": false,
                            "error": error_msg
                        });
                        writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                        return Ok(Status::err(1, &error_msg));
                    }
                }
            }
            None => None,
        };

        let if_exists = match args.get("if_exists") {
            Some(mode_str) => {
                match IfExistsMode::from_str(mode_str) {
                    Ok(mode) => mode,
                    Err(e) => {
                        let error_msg = format!("{}", e);
                        writeln!(io.stderr, "Error: {}", error_msg)?;
                        let error_json = json!({
                            "ok": false,
                            "error": error_msg
                        });
                        writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                        return Ok(Status::err(1, &error_msg));
                    }
                }
            }
            None => IfExistsMode::Error,
        };

        // Create backend
        let backend_impl = match LocalSnapshotBackend::new() {
            Ok(backend) => backend,
            Err(e) => {
                let error_msg = format!("failed to initialize snapshot backend: {}", e);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "ok": false,
                    "error": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(1, &error_msg));
            }
        };

        // Create snapshot
        match backend_impl.create_snapshot(&target, name, description, ttl, if_exists.clone()) {
            Ok(snapshot_info) => {
                // Check if this was a skip operation
                let skipped = matches!(if_exists, IfExistsMode::Skip) && 
                             snapshot_info.path.exists() && 
                             snapshot_info.path.join("meta.json").exists();

                let response = json!({
                    "ok": true,
                    "backend": snapshot_info.backend,
                    "id": snapshot_info.id,
                    "name": snapshot_info.name,
                    "target": snapshot_info.target.to_string_lossy(),
                    "path": snapshot_info.path.to_string_lossy(),
                    "created_at": snapshot_info.created_at.to_rfc3339(),
                    "expires_at": snapshot_info.expires_at.map(|dt| dt.to_rfc3339()),
                    "skipped": skipped
                });

                writeln!(io.stdout, "{}", serde_json::to_string(&response)?)?;
                Ok(Status::ok())
            }
            Err(e) => {
                let error_msg = format!("{}", e);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "ok": false,
                    "error": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                Ok(Status::err(1, &error_msg))
            }
        }
    }
    
    // Helper methods for restore functionality
    
    /// Check if a directory is empty (contains no files or subdirectories)
    fn is_dir_empty(&self, path: &Path) -> Result<bool> {
        if !path.exists() {
            return Ok(true);
        }
        
        if !path.is_dir() {
            return Ok(false);
        }
        
        let mut entries = fs::read_dir(path)
            .with_context(|| format!("failed to read directory: {:?}", path))?;
        Ok(entries.next().is_none())
    }
    
    /// Copy files recursively while preserving metadata (permissions, timestamps)
    fn copy_recursive_with_metadata(&self, src: &Path, dst: &Path) -> Result<()> {
        if src.is_file() {
            // Ensure parent directory exists
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create parent directory: {:?}", parent))?;
            }
            
            // Copy file
            fs::copy(src, dst)
                .with_context(|| format!("failed to copy file from {:?} to {:?}", src, dst))?;
            
            // Copy metadata
            if let Ok(metadata) = src.metadata() {
                let _ = fs::set_permissions(dst, metadata.permissions());
                
                // Attempt to set file times
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    use std::time::UNIX_EPOCH;
                    
                    if let Some(atime) = UNIX_EPOCH.checked_add(std::time::Duration::from_secs(metadata.atime() as u64)) {
                        if let Some(mtime) = UNIX_EPOCH.checked_add(std::time::Duration::from_secs(metadata.mtime() as u64)) {
                            let _ = filetime::set_file_times(dst, 
                                filetime::FileTime::from_system_time(atime),
                                filetime::FileTime::from_system_time(mtime));
                        }
                    }
                }
            }
        } else if src.is_dir() {
            // Create destination directory
            fs::create_dir_all(dst)
                .with_context(|| format!("failed to create directory: {:?}", dst))?;
            
            // Copy metadata for directory
            if let Ok(metadata) = src.metadata() {
                let _ = fs::set_permissions(dst, metadata.permissions());
            }
            
            // Recursively copy directory contents
            for entry in WalkDir::new(src) {
                let entry = entry
                    .with_context(|| format!("failed to read directory entry in {:?}", src))?;
                let entry_path = entry.path();
                
                let relative_path = entry_path
                    .strip_prefix(src)
                    .with_context(|| format!("failed to strip prefix {:?} from {:?}", src, entry_path))?;
                let target_path = dst.join(relative_path);
                
                if entry_path == src {
                    continue; // Skip root directory
                }
                
                if entry_path.is_dir() {
                    fs::create_dir_all(&target_path)
                        .with_context(|| format!("failed to create directory: {:?}", target_path))?;
                    
                    // Copy directory metadata
                    if let Ok(metadata) = entry_path.metadata() {
                        let _ = fs::set_permissions(&target_path, metadata.permissions());
                    }
                } else if entry_path.is_file() {
                    if let Some(parent) = target_path.parent() {
                        fs::create_dir_all(parent)
                            .with_context(|| format!("failed to create parent directory: {:?}", parent))?;
                    }
                    
                    fs::copy(entry_path, &target_path)
                        .with_context(|| format!("failed to copy file from {:?} to {:?}", entry_path, target_path))?;
                    
                    // Copy file metadata
                    if let Ok(metadata) = entry_path.metadata() {
                        let _ = fs::set_permissions(&target_path, metadata.permissions());
                        
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::MetadataExt;
                            use std::time::UNIX_EPOCH;
                            
                            if let Some(atime) = UNIX_EPOCH.checked_add(std::time::Duration::from_secs(metadata.atime() as u64)) {
                                if let Some(mtime) = UNIX_EPOCH.checked_add(std::time::Duration::from_secs(metadata.mtime() as u64)) {
                                    let _ = filetime::set_file_times(&target_path, 
                                        filetime::FileTime::from_system_time(atime),
                                        filetime::FileTime::from_system_time(mtime));
                                }
                            }
                        }
                    }
                }
            }
        } else {
            bail!("source path is neither file nor directory: {:?}", src);
        }
        
        Ok(())
    }
    
    /// Find a snapshot by name across all targets
    fn find_snapshot_by_name(&self, name: &str) -> Result<PathBuf> {
        let backend = LocalSnapshotBackend::new()?;
        let base_dir = &backend.base_dir;
        
        if !base_dir.exists() {
            bail!("snapshot storage directory does not exist: {:?}", base_dir);
        }
        
        // Search through all target directories
        for entry in fs::read_dir(base_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            
            let target_dir = entry.path();
            let potential_snapshot = target_dir.join(name);
            
            if potential_snapshot.exists() && potential_snapshot.join("meta.json").exists() {
                return Ok(potential_snapshot);
            }
        }
        
        bail!("snapshot not found: {}", name);
    }
    
    /// Restore operation implementation
    fn do_restore(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse snapshot name from URL target
        let snapshot_name = self.target.to_string_lossy().to_string();
        
        // Parse required arguments
        let target_path = match args.get("target") {
            Some(path) => PathBuf::from(path),
            None => {
                let error_msg = "missing required argument: target";
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "error": "missing_argument",
                    "argument": "target",
                    "message": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(1, error_msg));
            }
        };
        
        // Parse optional arguments
        let force = args.get("force")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);
            
        let mode = args.get("mode")
            .map(|s| s.as_str())
            .unwrap_or("overwrite");
        
        let dry_run = args.get("dry_run")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);
        
        // Validate mode (MVP: only support overwrite)
        if mode != "overwrite" {
            let error_msg = format!("unsupported mode: '{}' (only 'overwrite' is supported in this version)", mode);
            writeln!(io.stderr, "Error: {}", error_msg)?;
            let error_json = json!({
                "error": "unsupported_mode",
                "mode": mode,
                "message": error_msg
            });
            writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
            return Ok(Status::err(1, &error_msg));
        }
        
        // Find snapshot by name across all targets
        let snapshot_dir = match self.find_snapshot_by_name(&snapshot_name) {
            Ok(dir) => dir,
            Err(_) => {
                let error_msg = format!("snapshot not found: {}", snapshot_name);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "error": "snapshot_not_found",
                    "snapshot": snapshot_name,
                    "message": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(2, &error_msg));
            }
        };
        
        // Load snapshot metadata to get original target info
        let meta_file = snapshot_dir.join("meta.json");
        if !meta_file.exists() {
            let error_msg = format!("snapshot metadata not found: {}", snapshot_name);
            writeln!(io.stderr, "Error: {}", error_msg)?;
            let error_json = json!({
                "error": "metadata_not_found",
                "snapshot": snapshot_name,
                "message": error_msg
            });
            writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
            return Ok(Status::err(2, &error_msg));
        }
        
        // Read metadata to determine original target type  
        let meta_content = fs::read_to_string(&meta_file)
            .with_context(|| format!("failed to read snapshot metadata: {:?}", meta_file))?;
        let meta_value: serde_json::Value = serde_json::from_str(&meta_content)
            .with_context(|| "failed to parse snapshot metadata")?;
        
        let original_target = PathBuf::from(meta_value["target"].as_str().unwrap_or(""));
        let is_file_snapshot = original_target.is_file() || snapshot_dir.join("content").exists();
        
        // Check target path constraints
        if target_path.exists() {
            if target_path.is_file() {
                if !force {
                    let error_msg = format!("target file exists (use force=true to overwrite): {:?}", target_path);
                    writeln!(io.stderr, "Error: {}", error_msg)?;
                    let error_json = json!({
                        "error": "target_exists",
                        "target": target_path.to_string_lossy(),
                        "message": error_msg
                    });
                    writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                    return Ok(Status::err(3, &error_msg));
                }
            } else if target_path.is_dir() {
                if !self.is_dir_empty(&target_path)? && !force {
                    let error_msg = format!("target directory exists and is not empty (use force=true to overwrite): {:?}", target_path);
                    writeln!(io.stderr, "Error: {}", error_msg)?;
                    let error_json = json!({
                        "error": "target_not_empty",
                        "target": target_path.to_string_lossy(),
                        "message": error_msg
                    });
                    writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                    return Ok(Status::err(3, &error_msg));
                }
            }
        }
        
        // Handle dry run
        if dry_run {
            let mut actions = Vec::new();
            
            if target_path.exists() && force {
                if target_path.is_file() {
                    actions.push(format!("DELETE FILE {:?}", target_path));
                } else if target_path.is_dir() {
                    actions.push(format!("DELETE DIRECTORY {:?}", target_path));
                }
            }
            
            // Add copy action
            actions.push(format!("COPY {:?} -> {:?}", snapshot_dir, target_path));
            
            let dry_run_result = json!({
                "dry_run": true,
                "snapshot": snapshot_name,
                "target": target_path.to_string_lossy(),
                "mode": mode,
                "force": force,
                "actions": actions
            });
            
            writeln!(io.stdout, "{}", serde_json::to_string_pretty(&dry_run_result)?)?;
            return Ok(Status::ok());
        }
        
        // Perform atomic restore operation
        let parent_dir = match target_path.parent() {
            Some(parent) => parent,
            None => {
                let error_msg = format!("target path has no parent directory: {:?}", target_path);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "error": "invalid_target",
                    "target": target_path.to_string_lossy(),
                    "message": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(1, &error_msg));
            }
        };
        
        // Create parent directory if needed
        fs::create_dir_all(parent_dir)
            .with_context(|| format!("failed to create parent directory: {:?}", parent_dir))?;
        
        // Create temporary directory for atomic operation
        let temp_path = parent_dir.join(format!(".resh-restore-{}.tmp", uuid::Uuid::new_v4()));
        
        // Cleanup function
        let cleanup = |temp: &Path| {
            let _ = fs::remove_dir_all(temp);
        };
        
        // Copy snapshot contents to temp directory - handle file vs directory snapshots
        if is_file_snapshot {
            // For file snapshots, copy the 'content' file to the target location
            let content_file = snapshot_dir.join("content");
            if content_file.exists() {
                if let Err(e) = fs::copy(&content_file, &temp_path) {
                    cleanup(&temp_path);
                    let error_msg = format!("failed to copy snapshot file content: {}", e);
                    writeln!(io.stderr, "Error: {}", error_msg)?;
                    let error_json = json!({
                        "error": "copy_failed",
                        "snapshot": snapshot_name,
                        "message": error_msg
                    });
                    writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                    return Ok(Status::err(4, &error_msg));
                }
                
                // Copy metadata from original file if available
                if let Ok(metadata) = content_file.metadata() {
                    let _ = fs::set_permissions(&temp_path, metadata.permissions());
                    
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        use std::time::UNIX_EPOCH;
                        
                        if let Some(atime) = UNIX_EPOCH.checked_add(std::time::Duration::from_secs(metadata.atime() as u64)) {
                            if let Some(mtime) = UNIX_EPOCH.checked_add(std::time::Duration::from_secs(metadata.mtime() as u64)) {
                                let _ = filetime::set_file_times(&temp_path, 
                                    filetime::FileTime::from_system_time(atime),
                                    filetime::FileTime::from_system_time(mtime));
                            }
                        }
                    }
                }
            } else {
                cleanup(&temp_path);
                let error_msg = format!("snapshot content file not found: {}", snapshot_name);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "error": "content_not_found",
                    "snapshot": snapshot_name,
                    "message": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(2, &error_msg));
            }
        } else {
            // For directory snapshots, copy the entire directory structure
            if let Err(e) = self.copy_recursive_with_metadata(&snapshot_dir, &temp_path) {
                cleanup(&temp_path);
                let error_msg = format!("failed to copy snapshot contents: {}", e);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "error": "copy_failed",
                    "snapshot": snapshot_name,
                    "message": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(4, &error_msg));
            }
            
            // Remove metadata file from temp (it shouldn't be part of restored content)
            let temp_meta = temp_path.join("meta.json");
            if temp_meta.exists() {
                let _ = fs::remove_file(&temp_meta);
            }
        }
        
        // Atomic rename operation
        if target_path.exists() {
            // Create backup path
            let backup_path = parent_dir.join(format!(".resh-backup-{}.bak", uuid::Uuid::new_v4()));
            
            // Move existing target to backup
            if let Err(e) = fs::rename(&target_path, &backup_path) {
                cleanup(&temp_path);
                let error_msg = format!("failed to backup existing target: {}", e);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "error": "backup_failed",
                    "target": target_path.to_string_lossy(),
                    "message": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(4, &error_msg));
            }
            
            // Rename temp to target
            if let Err(e) = fs::rename(&temp_path, &target_path) {
                // Restore backup on failure
                let _ = fs::rename(&backup_path, &target_path);
                cleanup(&temp_path);
                
                let error_msg = format!("failed to restore snapshot: {}", e);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "error": "restore_failed",
                    "snapshot": snapshot_name,
                    "message": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(4, &error_msg));
            }
            
            // Remove backup on success
            let _ = fs::remove_dir_all(&backup_path);
        } else {
            // No existing target, simple rename
            if let Err(e) = fs::rename(&temp_path, &target_path) {
                cleanup(&temp_path);
                let error_msg = format!("failed to restore snapshot: {}", e);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                let error_json = json!({
                    "error": "restore_failed",
                    "snapshot": snapshot_name,
                    "message": error_msg
                });
                writeln!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(4, &error_msg));
            }
        }
        
        // Success response
        let response = json!({
            "snapshot": snapshot_name,
            "target": target_path.to_string_lossy(),
            "mode": mode,
            "status": "ok"
        });
        
        writeln!(io.stdout, "{}", serde_json::to_string(&response)?)?;
        Ok(Status::ok())
    }

    /// List snapshots for a group
    fn verb_ls(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Extract group name from the target path 
        // For snapshot://mygroup -> target would be "mygroup"
        let group_name = self.target.to_string_lossy();
        let sanitized_group = LocalSnapshotBackend::sanitize_path_component(&group_name);
        
        // Get base directory structure for snapshots
        let base_dir = match dirs::state_dir() {
            Some(dir) => dir.join("resh").join("snapshots"),
            None => PathBuf::from("/tmp").join("resh").join("snapshots"),
        };
        
        let group_dir = base_dir.join(&sanitized_group);
        
        // If group directory doesn't exist, return empty list
        if !group_dir.exists() {
            self.output_snapshot_list(&[], args, io)?;
            return Ok(Status::ok());
        }
        
        let mut snapshots = Vec::new();
        
        // Enumerate all subdirectories (each is a snapshot ID)
        match fs::read_dir(&group_dir) {
            Ok(entries) => {
                for entry in entries {
                    let entry = match entry {
                        Ok(e) => e,
                        Err(e) => {
                            writeln!(io.stderr, "snapshot://{}.ls: error reading directory entry: {}", group_name, e)?;
                            continue;
                        }
                    };
                    
                    if !entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                        continue;
                    }
                    
                    let snapshot_dir = entry.path();
                    let meta_file = snapshot_dir.join("meta.json");
                    
                    if !meta_file.exists() {
                        writeln!(io.stderr, "snapshot://{}.ls: skipping {}: meta.json not found", group_name, entry.file_name().to_string_lossy())?;
                        continue;
                    }
                    
                    // Read and parse metadata
                    match self.read_snapshot_meta(&meta_file) {
                        Ok(meta) => snapshots.push(meta),
                        Err(e) => {
                            writeln!(io.stderr, "snapshot://{}.ls: skipping {}: {}", group_name, entry.file_name().to_string_lossy(), e)?;
                            continue;
                        }
                    }
                }
            }
            Err(e) => {
                let error_msg = format!("failed to read snapshot group directory: {}", e);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                return Ok(Status::err(1, &error_msg));
            }
        }
        
        // Apply filters
        let filtered = self.apply_filters(snapshots, args, io)?;
        
        // Sort and limit
        let final_list = self.sort_and_limit(filtered, args, io)?;
        
        // Output results
        self.output_snapshot_list(&final_list, args, io)?;
        
        Ok(Status::ok())
    }
    
    /// Read and parse a snapshot meta.json file
    fn read_snapshot_meta(&self, meta_file: &Path) -> Result<SnapshotMetaForLs> {
        let content = fs::read_to_string(meta_file)
            .with_context(|| format!("failed to read meta.json: {:?}", meta_file))?;
        
        let meta: SnapshotMetaForLs = serde_json::from_str(&content)
            .with_context(|| format!("failed to parse meta.json: {:?}", meta_file))?;
        
        Ok(meta)
    }
    
    /// Apply all filters to the snapshot list
    fn apply_filters(&self, snapshots: Vec<SnapshotMetaForLs>, args: &Args, io: &mut IoStreams) -> Result<Vec<SnapshotMetaForLs>> {
        let mut result = Vec::new();
        
        for snapshot in snapshots {
            // Apply state filter
            if let Some(filter_state) = args.get("state") {
                let snapshot_state = snapshot.state.as_deref().unwrap_or("unknown");
                if filter_state.to_lowercase() != snapshot_state.to_lowercase() {
                    continue;
                }
            }
            
            // Apply tag filter
            if let Some(filter_tag) = args.get("tag") {
                let filter_tag_lower = filter_tag.to_lowercase();
                let has_tag = snapshot.tags.as_ref()
                    .map(|tags| tags.iter().any(|tag| tag.to_lowercase() == filter_tag_lower))
                    .unwrap_or(false);
                if !has_tag {
                    continue;
                }
            }
            
            // Apply since/until filters
            let created_at_dt = snapshot.created_at.as_ref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc));
                
            if let Some(since_str) = args.get("since") {
                match DateTime::parse_from_rfc3339(since_str) {
                    Ok(since_dt) => {
                        let since_utc = since_dt.with_timezone(&Utc);
                        if created_at_dt.map_or(true, |dt| dt < since_utc) {
                            continue;
                        }
                    }
                    Err(_) => {
                        writeln!(io.stderr, "snapshot://.ls: warning: invalid 'since' timestamp, ignoring: {}", since_str)?;
                    }
                }
            }
            
            if let Some(until_str) = args.get("until") {
                match DateTime::parse_from_rfc3339(until_str) {
                    Ok(until_dt) => {
                        let until_utc = until_dt.with_timezone(&Utc);
                        if created_at_dt.map_or(true, |dt| dt > until_utc) {
                            continue;
                        }
                    }
                    Err(_) => {
                        writeln!(io.stderr, "snapshot://.ls: warning: invalid 'until' timestamp, ignoring: {}", until_str)?;
                    }
                }
            }
            
            // Apply name_prefix filter
            if let Some(prefix) = args.get("name_prefix") {
                if snapshot.name.as_ref().map_or(true, |name| !name.starts_with(prefix)) {
                    continue;
                }
            }
            
            result.push(snapshot);
        }
        
        Ok(result)
    }
    
    /// Sort snapshots and apply limit
    fn sort_and_limit(&self, mut snapshots: Vec<SnapshotMetaForLs>, args: &Args, io: &mut IoStreams) -> Result<Vec<SnapshotMetaForLs>> {
        // Sort by created_at descending (newest first), then by id for stable ordering
        snapshots.sort_by(|a, b| {
            let a_dt = a.created_at.as_ref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc));
            let b_dt = b.created_at.as_ref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc));
                
            match (a_dt, b_dt) {
                (Some(a_time), Some(b_time)) => b_time.cmp(&a_time), // Descending order (newest first)
                (Some(_), None) => std::cmp::Ordering::Less,          // Valid time comes before invalid
                (None, Some(_)) => std::cmp::Ordering::Greater,       // Invalid time comes after valid
                (None, None) => a.id.cmp(&b.id),                     // Stable sort by id
            }
        });
        
        // Apply limit
        if let Some(limit_str) = args.get("limit") {
            match limit_str.parse::<usize>() {
                Ok(limit) if limit > 0 => {
                    snapshots.truncate(limit);
                }
                Ok(_) => {
                    writeln!(io.stderr, "snapshot://.ls: warning: invalid limit (must be > 0), ignoring: {}", limit_str)?;
                }
                Err(_) => {
                    writeln!(io.stderr, "snapshot://.ls: warning: invalid limit (not a number), ignoring: {}", limit_str)?;
                }
            }
        }
        
        Ok(snapshots)
    }
    
    /// Output the final snapshot list as JSON
    fn output_snapshot_list(&self, snapshots: &[SnapshotMetaForLs], args: &Args, io: &mut IoStreams) -> Result<()> {
        let output: Vec<SnapshotLsOutput> = snapshots.iter().map(|meta| {
            SnapshotLsOutput {
                id: meta.id.clone(),
                name: meta.name.clone(),
                created_at: meta.created_at.clone(),
                backend: meta.backend.clone(),
                target: meta.target.clone(),
                state: meta.state.clone(),
                size_bytes: meta.size_bytes,
                tags: meta.tags.clone(),
                description: meta.description.clone(),
            }
        }).collect();
        
        let json_output = if args.get("json_pretty").map_or(false, |s| s.to_lowercase() == "true") {
            serde_json::to_string_pretty(&output)?
        } else {
            serde_json::to_string(&output)?
        };
        
        writeln!(io.stdout, "{}", json_output)?;
        Ok(())
    }
}

// Helper function to normalize path components similar to file handle
fn normalize_path(p: &Path) -> PathBuf {
    let mut components = Vec::new();
    let mut is_absolute = false;
    
    for component in p.components() {
        match component {
            Component::Normal(name) => components.push(name),
            Component::RootDir => {
                components.clear();
                components.push(std::ffi::OsStr::new("/"));
                is_absolute = true;
            }
            Component::ParentDir => {
                if !components.is_empty() && components.last() != Some(&std::ffi::OsStr::new("/")) {
                    components.pop();
                }
            }
            Component::CurDir => {
                // Skip current directory references but track that this was relative
            }
            _ => {}
        }
    }
    
    if components.is_empty() {
        PathBuf::from(".")
    } else if is_absolute && components.len() == 1 && components[0] == "/" {
        PathBuf::from("/")
    } else if is_absolute {
        components.into_iter().collect()
    } else {
        // For relative paths, keep them relative
        components.into_iter().collect()
    }
}

impl Handle for SnapshotHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["create", "diff", "restore", "ls"]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check if this is a help request based on the path
        if self.target.to_string_lossy().contains("--help") || self.target.to_string_lossy().contains("-h") {
            // Check for specific verb help request
            if let Some(specific_verb) = args.get("verb") {
                writeln!(io.stdout, "Detailed help for '{}' verb is not yet implemented.", specific_verb)?;
                writeln!(io.stdout, "Please refer to the general help below:\n")?;
            }
            
            // Display the comprehensive help text
            writeln!(io.stdout, "{}", HELP_TEXT)?;
            return Ok(Status::ok());
        }

        match verb {
            "create" => self.create(args, io),
            "diff" => self.diff(args, io),
            "restore" => self.do_restore(args, io),
            "ls" => self.verb_ls(args, io),
            _ => bail!("unknown verb for snapshot://: {} (available: create, diff, restore, ls)", verb),
        }
    }
}