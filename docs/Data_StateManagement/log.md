# Log Handle Documentation

The log handle provides access to log files and system services for viewing and analyzing log data. It supports both file-based logs and system service logs through journalctl.

## URL Scheme

The log handle uses the `log://` URL scheme with different formats for different log sources:

- **File logs**: `log:///path/to/logfile.log`  
- **Relative file logs**: `log://./relative/path/log.txt`
- **Service logs**: `log://svc/service-name` (via journalctl)

## Command Syntax

**✅ Preferred Syntax (Space-Separated Arguments)**
```bash
# No quotes needed - arguments are space-separated
resh log:///var/log/syslog.tail lines=10
resh log:///var/log/syslog.tail pattern=ERROR mode=json
resh log://./app.log.tail lines=20 pattern=WARN
resh log:///var/log/syslog.tail lines=10 pattern=CRON mode=json
```

**✅ Alternative Syntax (Quoted URLs with Parentheses)**
```bash
# Quote the entire URL when using parentheses syntax
resh "log:///var/log/syslog.tail(lines=10)"
resh "log:///var/log/syslog.tail(pattern=ERROR,mode=json)"
resh "log://./app.log.tail(lines=20,pattern=WARN)"
```

**❌ Incorrect Syntax (Causes Shell Errors)**
```bash
# Missing quotes - bash interprets parentheses as syntax
resh log:///var/log/syslog.tail(lines=10)
# Error: bash: syntax error near unexpected token '('
```

## Available Verbs

### tail

Shows the last lines of a log file, similar to the Unix `tail` command. This is the primary verb for viewing recent log entries.

**Arguments:**
- `lines` - Number of lines to show (default: 100, must be greater than 0)
- `pattern` - Filter lines that contain this text pattern
- `mode` - Output format: "raw" (default) or "json"

**Examples:**

**Basic tail (last 100 lines):**
```bash
resh log:///tmp/test.log.tail
```
Input: A log file with 5 lines:
```
Line 1
Line 2
Line 3
Line 4
Line 5
```
Output: All 5 lines displayed

**Tail with specific line count:**
```bash
resh log:///tmp/test.log.tail lines=3
```
Input: A log file with 20 lines numbered 1-20
Output: Only the last 3 lines (18, 19, 20) are displayed

**Tail with pattern filtering:**
```bash
resh log:///tmp/app.log.tail lines=10 pattern=ERROR
```
Input: A log file with mixed content:
```
line-1 INFO normal
line-2 ERROR failed
line-3 INFO normal
line-4 ERROR failed
line-5 INFO normal
```
Output: Only lines containing "ERROR" are shown:
```
line-2 ERROR failed
line-4 ERROR failed
```

**Tail with JSON output:**
```bash
resh log:///tmp/app.log.tail lines=30 pattern=ERROR mode=json
```
Input: A log file with 50 lines, some containing "ERROR" in the last 30 lines
Output: JSON structure with:
```json
{
  "path": "/tmp/app.log",
  "requested_lines": 30,
  "returned_lines": 6,
  "pattern": "ERROR", 
  "lines": ["line-33 ERROR something happened", "line-36 ERROR something happened", ...]
}
```

**Empty file handling:**
```bash
resh log:///tmp/empty.log.tail lines=10
```
Input: An empty log file
Output: No output (empty response)

**Empty file with JSON mode:**
```bash
resh log:///tmp/empty.log.tail lines=10 mode=json
```
Input: An empty log file  
Output: JSON with empty results:
```json
{
  "path": "/tmp/empty.log",
  "requested_lines": 10,
  "returned_lines": 0,
  "pattern": null,
  "lines": []
}
```

**File not found (raw mode):**
```bash
resh log:///tmp/nonexistent.log.tail lines=10
```
Input: A path to a non-existent file
Output: Error message and exit status 2:
```
Error: Log file does not exist: /tmp/nonexistent.log
```

**File not found (JSON mode):**
```bash
resh log:///tmp/nonexistent.log.tail lines=10 mode=json
```
Input: A path to a non-existent file
Output: JSON error structure and exit status 2:
```json
{
  "error": "Log file does not exist: /tmp/nonexistent.log",
  "path": "/tmp/nonexistent.log",
  "requested_lines": 10,
  "returned_lines": 0
}
```

## Error Handling

### Invalid Arguments

**Invalid line count:**
```bash
resh log:///tmp/test.log.tail lines=0
```
Output: Error message to stderr and exit status 2:
```
Error: lines must be greater than 0
```

**Invalid mode:**
```bash
resh log:///tmp/test.log.tail lines=10 mode=invalid
```
Output: Error message to stderr and exit status 2:
```
Error: mode must be 'raw' or 'json'
```

### File Access Issues

- **File doesn't exist**: Returns error status 2 with appropriate message
- **Path is not a file**: Returns error status 2 indicating the path is not a file
- **Permission denied**: Standard file access error handling

## Performance Features

The log handle uses efficient algorithms for reading large files:

- **Small files** (under 64KB): Reads entire file and returns last N lines
- **Large files** (over 64KB): Uses backward scanning to read only necessary data from the end of the file

This allows for fast tail operations on very large log files without reading the entire file into memory.

## Service Log Support

For system service logs (using journalctl):
```bash
resh log://svc/systemd.tail lines=50
```

This feature relies on journalctl being available and the service existing on the system.

## File Format Support

The log handle works with any text-based log file format. It treats files as line-based text and doesn't require specific log formats or structured data.

## Practical Examples

### System Log Analysis
```bash
# Check recent system errors
resh log:///var/log/syslog.tail pattern=error mode=json

# Monitor recent cron job execution
resh log:///var/log/syslog.tail pattern=CRON lines=20

# Check systemd service messages
resh log:///var/log/syslog.tail pattern=systemd lines=30 mode=json
```

### Application Log Monitoring
```bash
# Check recent application errors
resh log://./logs/app.log.tail pattern=ERROR lines=50 mode=json

# Monitor nginx error logs
resh log:///var/log/nginx/error.log.tail lines=20

# Debug recent activity with pattern
resh log://./debug.log.tail lines=100 pattern=DEBUG
```

### Automation and Scripting
```bash
# Get structured JSON output for parsing
ERROR_COUNT=$(resh log:///var/log/app.log.tail pattern=ERROR mode=json | jq '.returned_lines')

# Check if any errors occurred recently
resh log:///var/log/syslog.tail pattern=error lines=100 mode=json | jq '.returned_lines > 0'

# Extract specific log lines for processing
resh log:///var/log/app.log.tail pattern=CRITICAL mode=json | jq -r '.lines[]'

# Using alternative quoted syntax in scripts (when needed)
ERROR_COUNT=$(resh "log:///var/log/app.log.tail(pattern=ERROR,mode=json)" | jq '.returned_lines')
```