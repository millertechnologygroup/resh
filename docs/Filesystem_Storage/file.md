# File Handle Documentation

The file handle in Resource Shell lets you work with files and directories on your computer. It provides many useful actions to manage files, check their contents, and manipulate file properties.

## URL Format

File handle URLs use the `file://` scheme followed by the path to the file:
```
file:///path/to/file.txt.verb(arguments)
```

## Available Verbs

### read
Reads and outputs the entire contents of a file.

**Example:**
```
file:///tmp/myfile.txt.read
```

This reads all content from `/tmp/myfile.txt` and prints it to output.

### write
Creates a new file or overwrites an existing file with content.

**Arguments:**
- `data` - Text content to write to the file
- `create` - Whether to create file if it doesn't exist (default: true)

**Examples:**
```
file:///tmp/test.txt.write(data=hello)
```
Creates `/tmp/test.txt` with content "hello".

```
file:///tmp/existing.txt.write(data=new)
```
Overwrites existing file with "new" content.

```
file:///tmp/nofile.txt.write(data=x,create=false)
```
Returns error if file doesn't exist (exit code 2).

### append
Adds content to the end of an existing file.

**Arguments:**
- `data` - Text content to append to the file
- `create` - Whether to create file if it doesn't exist (default: true)

**Examples:**
```
file:///tmp/log.txt.append(data=bar)
```
If file contains "foo", it will now contain "foobar".

```
file:///tmp/missing.txt.append(data=zzz,create=false)
```
Returns error if file doesn't exist (exit code 2).

### exists
Checks if a file or directory exists and returns information about it.

**Output:** JSON with existence status and type information

**Examples:**
```
file:///tmp/existing.txt.exists
```
Returns: `{"path":"/tmp/existing.txt","exists":true,"kind":"file"}`

```
file:///tmp/directory.exists
```
Returns: `{"path":"/tmp/directory","exists":true,"kind":"dir"}`

```
file:///tmp/missing.txt.exists
```
Returns: `{"path":"/tmp/missing.txt","exists":false,"kind":"none"}`

### stat
Returns detailed metadata about a file or directory.

**Arguments:**
- `nofollow` - Don't follow symbolic links (default: false)

**Output:** JSON with file metadata including size, timestamps, and permissions

**Examples:**
```
file:///tmp/test.txt.stat
```
Returns detailed file information including size, modification time, and permissions.

```
file:///tmp/symlink.stat(nofollow=true)
```
Returns information about the symbolic link itself, not the target.

### copy
Copies a file to another location.

**Arguments:**
- `to` - Destination path (required)
- `overwrite` - Allow overwriting existing files (default: false)
- `preserve_mode` - Preserve file permissions (default: true on Unix)
- `preserve_times` - Preserve timestamps (default: false)

**Examples:**
```
file:///tmp/source.txt.copy(to=/tmp/destination.txt)
```
Copies source.txt to destination.txt.

```
file:///tmp/file.txt.copy(to=/tmp/existing.txt,overwrite=true)
```
Overwrites existing destination file.

### delete (remove)
Deletes a file or directory.

**Arguments:**
- `recursive` - Delete directories and their contents (default: false)
- `force` - Don't return error if file doesn't exist (default: false)
- `missing_ok` - Same as force (default: false)

**Examples:**
```
file:///tmp/file.txt.delete
```
Deletes the file.

```
file:///tmp/directory.delete(recursive=true)
```
Deletes directory and all its contents.

```
file:///tmp/missing.txt.delete(missing_ok=true)
```
Succeeds even if file doesn't exist.

### rename
Renames or moves a file to a different location.

**Arguments:**
- `to` - New path (required)
- `overwrite` - Allow overwriting existing files (default: false)
- `create_parents` - Create parent directories if needed (default: false)
- `atomic` - Use atomic operation if possible (default: true)

**Examples:**
```
file:///tmp/old.txt.rename(to="/tmp/new.txt")
```
Renames old.txt to new.txt.

```
file:///tmp/file.txt.rename(to="/another/location.txt",overwrite=true)
```
Moves and renames file, overwriting destination if it exists.

### move (mv)
Moves a file to another location (similar to rename).

**Arguments:**
- `to` - Destination path (required)
- `overwrite` - Allow overwriting existing files (default: false)

**Examples:**
```
file:///tmp/source.txt.move(to=/home/user/dest.txt)
```
Moves source.txt to the destination.

```
file:///tmp/file.txt.mv(to=/tmp/existing.txt,overwrite=true)
```
Moves file and overwrites destination.

### chmod
Changes file permissions (Unix only).

**Arguments:**
- `mode` - Octal permission mode (required)

**Examples:**
```
file:///tmp/script.sh.chmod(mode=755)
```
Makes file executable by owner and readable by all.

```
file:///tmp/secret.txt.chmod(mode=600)
```
Makes file readable and writable by owner only.

### chown
Changes file ownership (Unix only).

**Arguments:**
- `user` - Username to set as owner
- `uid` - User ID to set as owner
- `group` - Group name to set as group
- `gid` - Group ID to set as group
- `recursive` - Apply to directories recursively (default: false)

**Examples:**
```
file:///tmp/file.txt.chown(user=alice)
```
Changes file owner to user 'alice'.

```
file:///tmp/file.txt.chown(uid=1000,gid=100)
```
Changes owner to user ID 1000 and group ID 100.

### md5
Calculates MD5 hash of file contents.

**Output:** JSON with file path, algorithm, hash, and size

**Examples:**
```
file:///tmp/file.txt.md5
```
Returns: `{"path":"/tmp/file.txt","algorithm":"md5","hash":"5d41402abc4b2a76b9719d911017c592","size":5}`

### sha1
Calculates SHA-1 hash of file contents.

**Output:** JSON with file path, algorithm, hash, and size

**Examples:**
```
file:///tmp/file.txt.sha1
```
Returns: `{"path":"/tmp/file.txt","algorithm":"sha1","hash":"356a192b7913b04c54574d18c28d46e6395428ab","size":5}`

### sha256
Calculates SHA-256 hash of file contents.

**Output:** JSON with file path, algorithm, hash, and size

**Examples:**
```
file:///tmp/file.txt.sha256
```
Returns: `{"path":"/tmp/file.txt","algorithm":"sha256","hash":"2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae","size":5}`

### sha512
Calculates SHA-512 hash of file contents.

**Output:** JSON with file path, algorithm, hash, and size

**Examples:**
```
file:///tmp/file.txt.sha512
```
Returns: `{"path":"/tmp/file.txt","algorithm":"sha512","hash":"...","size":5}`

### hash
Calculates file hash using specified algorithm.

**Arguments:**
- `algo` - Hash algorithm: sha256, sha512, blake3 (default: sha256)

**Output:** JSON with file path, algorithm, hash, and size

**Examples:**
```
file:///tmp/file.txt.hash
```
Uses SHA-256 by default.

```
file:///tmp/file.txt.hash(algo=blake3)
```
Calculates BLAKE3 hash.

### verify
Verifies file hash against expected values.

**Arguments:**
- `algo` - Hash algorithm: sha256, sha1, md5, blake3 (default: sha256)
- `expected` - Single expected hash value
- `expected_any` - Semicolon-separated list of acceptable hash values
- `size` - Expected file size in bytes

**Output:** JSON with verification results

**Examples:**
```
file:///tmp/file.txt.verify(algo=sha256,expected=a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447)
```
Verifies file matches expected SHA-256 hash.

```
file:///tmp/file.txt.verify(algo=md5,expected=098f6bcd4621d373cade4e832627b4f6,size=4)
```
Verifies both hash and file size.

### find
Searches for files and directories recursively.

**Arguments:**
- `pattern` - Glob pattern to match filenames
- `type` - Filter by type: f (files), d (directories), l (symlinks)
- `hidden` - Include hidden files (default: false)
- `max_depth` - Maximum directory depth to search

**Output:** JSON array of matching files with metadata

**Examples:**
```
file:///tmp/directory.find
```
Finds all files and directories under /tmp/directory.

```
file:///tmp/directory.find(pattern=*.txt,type=f)
```
Finds only .txt files.

### grep
Searches for text patterns within files.

**Arguments:**
- `pattern` - Text or regex pattern to search for (required)
- `regex` - Treat pattern as regular expression (default: false)
- `ignore_case` - Case-insensitive search (default: false)
- `line_numbers` - Show line numbers (default: true)
- `max_count` - Stop after this many matches

**Examples:**
```
file:///tmp/log.txt.grep(pattern=foo)
```
Searches for "foo" in the file, showing line numbers.

```
file:///tmp/file.txt.grep(pattern=[0-9]+,regex=true)
```
Searches for numbers using regex.

### replace
Replaces text patterns in files.

**Arguments:**
- `pattern` - Text or regex pattern to find (required)
- `replacement` - Text to replace matches with (required)
- `regex` - Treat pattern as regular expression (default: false)
- `global` - Replace all matches, not just first (default: true)
- `backup` - Create backup before modifying (default: false)

**Examples:**
```
file:///tmp/config.txt.replace(pattern=old_value,replacement=new_value)
```
Replaces "old_value" with "new_value" in the file.

### tail
Shows the last lines of a file.

**Arguments:**
- `lines` - Number of lines to show (default: 10)
- `bytes` - Show last N bytes instead of lines
- `follow` - Continue reading as file grows (default: false)

**Examples:**
```
file:///var/log/app.log.tail
```
Shows last 10 lines of the log file.

```
file:///var/log/app.log.tail(lines=5)
```
Shows last 5 lines.

### preview
Shows a preview of file contents with intelligent formatting.

**Arguments:**
- `max_lines` - Maximum lines to show (default: 50)
- `max_bytes` - Maximum bytes to read (default: 64KB)

**Examples:**
```
file:///tmp/document.txt.preview
```
Shows formatted preview of the document.

### schema
Analyzes file structure and generates schema information.

**Arguments:**
- `format` - Output format: auto, json, csv, text (default: auto)
- `sample_size` - Number of records to analyze (default: 1000)

**Examples:**
```
file:///tmp/data.csv.schema
```
Analyzes CSV structure and shows column information.

```
file:///tmp/data.json.schema(format=json)
```
Analyzes JSON structure.

### summary
Provides a summary of file or directory contents.

**Arguments:**
- `max_bytes` - Maximum bytes to read for analysis (default: 1MB)
- `include_hidden` - Include hidden files in directory summary

**Examples:**
```
file:///tmp/document.txt.summary
```
Provides summary of text file contents.

```
file:///tmp/directory.summary
```
Provides summary of directory contents.

### watch
Monitors file for changes and reports them.

**Arguments:**
- `timeout` - How long to watch in seconds (default: 30)
- `events` - Event types to watch: create, modify, delete (default: all)

**Examples:**
```
file:///tmp/config.conf.watch
```
Watches file for changes for 30 seconds.

```
file:///tmp/dir.watch(timeout=60,events=create,modify)
```
Watches directory for create and modify events.

### analyze
Performs detailed analysis of file contents.

**Arguments:**
- `type` - Analysis type: text, binary, image, code (default: auto)
- `deep` - Perform deep analysis (default: false)

**Examples:**
```
file:///tmp/source.py.analyze
```
Analyzes Python source code file.

```
file:///tmp/image.jpg.analyze(type=image)
```
Analyzes image file properties.

### ea.get
Gets extended attributes of a file (Unix only).

**Arguments:**
- `name` - Specific attribute name to retrieve

**Examples:**
```
file:///tmp/file.txt.ea.get
```
Lists all extended attributes.

```
file:///tmp/file.txt.ea.get(name=user.comment)
```
Gets specific extended attribute.

### ea.set
Sets extended attributes on a file (Unix only).

**Arguments:**
- `name` - Attribute name (required)
- `value` - Attribute value (required)

**Examples:**
```
file:///tmp/file.txt.ea.set(name=user.comment,value=Important file)
```
Sets extended attribute.

### tag.add
Adds tags to a file using extended attributes (Unix only).

**Arguments:**
- `tags` - Comma-separated list of tags (required)

**Examples:**
```
file:///tmp/document.pdf.tag.add(tags=work,important,draft)
```
Adds multiple tags to the file.

### tag.rm
Removes tags from a file (Unix only).

**Arguments:**
- `tags` - Comma-separated list of tags to remove (required)

**Examples:**
```
file:///tmp/document.pdf.tag.rm(tags=draft)
```
Removes the "draft" tag from the file.

## Error Codes

Common exit codes returned by file operations:

- `0` - Success
- `1` - General error (file operation failed)
- `2` - File not found or doesn't exist
- `3` - Permission denied
- `95` - Feature not supported on this platform

## Notes

- File paths can contain spaces and special characters
- Use URL encoding for special characters in paths
- Some features (chmod, chown, extended attributes) are Unix-only
- Hash operations have a 10GB file size limit for security
- Write and append operations are atomic when possible
- Always use absolute paths for reliability