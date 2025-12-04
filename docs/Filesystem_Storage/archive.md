# Archive Handle Documentation

The Archive Handle lets you work with different types of compressed files. You can create, extract, list, test, and change archive files easily. Think of archives like boxes that hold many files together in one smaller package.

## What Archive Types Are Supported?

The system works with these common file types:

- **ZIP files** (.zip) - Great for Windows and general use
- **TAR files** (.tar) - Simple archives without compression
- **TAR.GZ files** (.tar.gz, .tgz) - TAR files compressed with gzip 
- **TAR.XZ files** (.tar.xz, .txz) - TAR files compressed with xz
- **TAR.ZSTD files** (.tar.zst, .tar.zstd) - TAR files compressed with zstd
- **GZIP files** (.gz) - Single file compression
- **7-Zip files** (.7z) - High compression archives
- **Raw compressed files** - Direct compression without archiving

## Archive Commands (Verbs)

### Create - Making New Archives

**What it does:** Takes files and folders and puts them into a new archive file.

**Required settings:**
- `output` - Where to save the new archive file
- `sources` - List of files and folders to include (as JSON array)

**Optional settings:**
- `format` - Type of archive to create (auto, tar, tar.gz, tar.xz, tar.zstd, zip, 7z, gzip, raw)
- `base_dir` - Starting folder for relative paths
- `compression_level` - How much to compress (1-9 for most types, 1-22 for zstd)
- `include_patterns` - Only include files matching these patterns (JSON array)
- `exclude_patterns` - Skip files matching these patterns (JSON array)
- `include_hidden` - Include hidden files (true/false, default: true)
- `follow_symlinks` - Follow symbolic links (true/false, default: false)
- `password` - Password protect the archive (ZIP and 7z only)
- `overwrite` - Replace existing archive (true/false, default: false)
- `preserve_permissions` - Keep file permissions (true/false, default: true)
- `preserve_timestamps` - Keep file dates (true/false, default: true)
- `max_files` - Maximum number of files to include (default: 100,000)
- `max_size_mb` - Maximum archive size in MB (default: 10,240 MB)
- `progress` - Show progress while creating (true/false, default: false)

**Example use:**
```
archive://create output=created.tar.gz sources='["/source"]' base_dir=/tmp format=TarGz compression_level=6 overwrite=true preserve_permissions=true preserve_timestamps=true max_files=1000000 max_size_mb=1024 progress=false format_output=json
```

**Example output:**
```json
{
  "ok": true,
  "result": {
    "files_archived": 3,
    "total_size_bytes": 2048,
    "format": "tar.gz",
    "compression": "gzip"
  }
}
```

### Extract - Taking Files Out of Archives

**What it does:** Takes files out of an archive and puts them in a folder.

**Required settings:**
- `archive` - Path to the archive file to extract
- `destination` - Where to put the extracted files

**Optional settings:**
- `format` - Archive type (auto-detected if not specified)
- `compression` - Compression type (auto-detected if not specified)
- `includes` - Only extract files matching these patterns (JSON array)
- `excludes` - Skip files matching these patterns (JSON array)
- `overwrite` - Replace existing files (true/false, default: false)
- `create_destination` - Create destination folder if missing (true/false, default: true)
- `strip_components` - Remove this many folder levels from paths (default: 0)
- `allow_absolute_paths` - Allow absolute paths (true/false, default: false)
- `allow_parent_traversal` - Allow paths with .. (true/false, default: false)
- `allow_symlinks` - Allow symbolic links (true/false, default: true)
- `follow_symlinks` - Follow symbolic links (true/false, default: false)
- `max_entries` - Maximum files to extract (default: 1,000,000)
- `max_total_bytes` - Maximum total size to extract in bytes
- `max_file_bytes` - Maximum single file size in bytes

**Example use:**
```
archive://extract archive=test.tar.gz destination=/tmp/dest format=Auto compression=Auto overwrite=false create_destination=true strip_components=0 allow_absolute_paths=false allow_parent_traversal=false allow_symlinks=true follow_symlinks=false max_entries=1000000 format_output=json
```

**Example output:**
```json
{
  "ok": true,
  "summary": {
    "format": "tar.gz",
    "compression": "gzip",
    "entries_extracted": 3,
    "bytes_extracted": 2048
  }
}
```

### List - Seeing What's Inside Archives

**What it does:** Shows you all the files inside an archive without extracting them.

**Required settings:**
- `archive` - Path to the archive file to examine

**Optional settings:**
- `format` - Archive type (auto-detected if not specified)
- `compression` - Compression type (auto-detected if not specified)
- `includes` - Only show files matching these patterns (JSON array)
- `excludes` - Skip files matching these patterns (JSON array)
- `max_entries` - Maximum files to list (default: 1,000,000)
- `max_total_bytes` - Maximum total size to process in bytes
- `include_metadata` - Show file details like size and date (true/false, default: true)
- `include_compressed_size` - Show compressed file sizes (true/false, default: true)

**Example use:**
```
archive://list archive=test.tar.gz format=Auto compression=Auto max_entries=1000000 include_metadata=true include_compressed_size=true format_output=json
```

**Example output:**
```json
{
  "ok": true,
  "summary": {
    "format": "tar.gz",
    "compression": "gzip",
    "entries_total": 3,
    "entries_listed": 3
  },
  "manifest": [
    {
      "path": "file1.txt",
      "is_dir": false,
      "size": 13,
      "compressed_size": 25,
      "is_symlink": false
    },
    {
      "path": "dir/",
      "is_dir": true,
      "size": 0,
      "compressed_size": 0,
      "is_symlink": false
    },
    {
      "path": "dir/file2.txt",
      "is_dir": false,
      "size": 15,
      "compressed_size": 30,
      "is_symlink": false
    }
  ]
}
```

### Test - Checking Archive Health

**What it does:** Checks if an archive file is valid and not damaged.

**Required settings:**
- `archive` - Path to the archive file to test

**Optional settings:**
- `format` - Archive type (auto-detected if not specified)
- `compression` - Compression type (auto-detected if not specified)
- `stop_on_first_error` - Stop checking after first problem (true/false, default: true)
- `report_entries` - Show each file being checked (true/false, default: true)
- `verify_data` - Check file contents, not just structure (true/false, default: true)
- `max_entries` - Maximum files to test (default: 1,000,000)
- `max_total_bytes` - Maximum total size to test in bytes
- `max_file_bytes` - Maximum single file size to test in bytes

**Example use:**
```
archive://test archive=test.tar.gz format=Auto compression=Auto stop_on_first_error=true report_entries=true verify_data=true max_entries=1000000 fail_on_missing_archive=true format_output=json
```

**Example output:**
```json
{
  "ok": true,
  "summary": {
    "entries_tested": 3,
    "entries_failed": 0,
    "valid": true,
    "stopped_early": false,
    "format": "tar.gz",
    "compression": "gzip"
  },
  "entries": [
    {
      "path": "file1.txt",
      "status": "ok",
      "error_code": null,
      "error_message": null
    },
    {
      "path": "dir/",
      "status": "ok",
      "error_code": null,
      "error_message": null
    },
    {
      "path": "dir/file2.txt",
      "status": "ok",
      "error_code": null,
      "error_message": null
    }
  ]
}
```

### Info - Getting Archive Details

**What it does:** Shows basic information about an archive file like size and format.

**Required settings:**
- `archive` - Path to the archive file to examine

**Optional settings:**
- `format` - Archive type (auto-detected if not specified)
- `compression` - Compression type (auto-detected if not specified)
- `scan_entries` - Count files inside (true/false, default: true)
- `max_entries` - Maximum files to count (default: 1,000,000)
- `max_total_bytes` - Maximum size to scan in bytes

**Example use:**
```
archive://info archive=test.tar.gz format=Auto compression=Auto scan_entries=true max_entries=1000000 fail_on_missing_archive=true format_output=json
```

**Example output:**
```json
{
  "ok": true,
  "summary": {
    "format": "tar.gz",
    "compression": "gzip",
    "archive_size_bytes": 2048,
    "entries_total": 3,
    "files": 2,
    "directories": 1,
    "uncompressed_bytes_total": 4096
  }
}
```

### Add - Adding Files to Existing Archives

**What it does:** Adds new files to an archive that already exists.

**Required settings:**
- `archive` - Path to the existing archive file
- `inputs` - List of files and folders to add (as JSON array)

**Optional settings:**
- `format` - Archive type (auto-detected if not specified)
- `compression` - Compression type (auto-detected if not specified)
- `base_dir` - Starting folder for relative paths
- `includes` - Only add files matching these patterns (JSON array)
- `excludes` - Skip files matching these patterns (JSON array)
- `follow_symlinks` - Follow symbolic links (true/false, default: false)
- `overwrite` - Replace files that already exist in archive (true/false, default: false)
- `preserve_permissions` - Keep file permissions (true/false, default: true)
- `preserve_timestamps` - Keep file dates (true/false, default: true)
- `max_entries` - Maximum files to add (default: 1,000,000)
- `max_total_bytes` - Maximum total size to add in bytes

**Note:** Cannot add files to raw compressed files (.gz, .xz, .zst) or 7z archives.

**Example use:**
```
archive://add archive=test.tar.gz inputs='["glob:**/*.rs"]' format=Auto compression=Auto follow_symlinks=false max_entries=1000000 format_output=json
```

**Example output:**
```json
{
  "ok": true,
  "summary": {
    "entries_added": 5,
    "entries_replaced": 0,
    "entries_skipped": 0
  }
}
```

### Remove - Deleting Files from Archives

**What it does:** Removes specific files or folders from an existing archive.

**Required settings:**
- `archive` - Path to the existing archive file

**At least one of these is required:**
- `paths` - Exact file paths to remove (JSON array)
- `patterns` - Remove files matching these patterns (JSON array)
- `dir_prefixes` - Remove all files starting with these folder paths (JSON array)

**Optional settings:**
- `format` - Archive type (auto-detected if not specified)
- `compression` - Compression type (auto-detected if not specified)
- `remove_empty_dirs` - Remove empty folders after deleting files (true/false, default: false)
- `dry_run` - Show what would be removed without actually doing it (true/false, default: false)
- `max_entries` - Maximum files to process (default: 1,000,000)
- `max_total_bytes` - Maximum size to process in bytes
- `tmp_dir` - Temporary folder for processing
- `backup_suffix` - Create backup file with this ending

**Note:** Cannot remove files from raw compressed files (.gz, .xz, .zst) or 7z archives.

**Example use:**
```
archive://remove archive=test.tar.gz paths='["README.md"]' format=Auto compression=Auto remove_empty_dirs=true dry_run=false max_entries=1000000 format_output=json
```

**Example output:**
```json
{
  "ok": true,
  "summary": {
    "entries_removed": 1,
    "dry_run": false
  }
}
```

## Output Formats

All commands can return results in two ways:
- `format_output=json` - Computer-readable format (default)
- `format_output=text` - Human-readable format

## Safety Features

The system includes several safety features:

- **File limits** - Prevents processing too many files at once
- **Size limits** - Prevents creating or processing huge archives
- **Path validation** - Blocks dangerous file paths by default
- **Permission preservation** - Keeps your file permissions safe
- **Backup options** - Can create backups before making changes

## Common Examples

**Create a TAR.GZ file from a folder:**
```
archive://create output=backup.tar.gz sources='["/home/user/documents"]' format=TarGz compression_level=6 overwrite=true
```

**Extract everything from a TAR.GZ file:**
```
archive://extract archive=backup.tar.gz destination=/restore format=Auto compression=Auto create_destination=true
```

**See what's in an archive:**
```
archive://list archive=backup.tar.gz format=Auto compression=Auto include_metadata=true include_compressed_size=true
```

**Check if an archive is okay:**
```
archive://test archive=backup.tar.gz format=Auto compression=Auto stop_on_first_error=true report_entries=true verify_data=true
```

**Get archive information:**
```
archive://info archive=backup.tar.gz format=Auto compression=Auto scan_entries=true
```

**Add files to an existing archive using glob pattern:**
```
archive://add archive=backup.tar.gz inputs='["glob:**/*.rs"]' format=Auto compression=Auto
```

**Remove specific files from an archive:**
```
archive://remove archive=backup.tar.gz paths='["old_file.txt"]' format=Auto compression=Auto
```

Remember that file paths should use forward slashes (/) and be in JSON array format when listing multiple items like `["file1.txt", "file2.txt"]`.