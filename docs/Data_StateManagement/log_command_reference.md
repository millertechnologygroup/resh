# Log Handle Command Reference

## Correct Command Syntax

When using the resh log handle from the command line, **always quote the URL** to prevent bash from interpreting parentheses as shell syntax.

### ✅ Correct Usage

```bash
# Basic tail (last 100 lines)
./target/release/resh "log:///var/log/syslog.tail"

# Specify number of lines
./target/release/resh "log:///var/log/syslog.tail(lines=10)"

# JSON output mode
./target/release/resh "log:///var/log/syslog.tail(lines=5,mode=json)"

# Pattern filtering
./target/release/resh "log:///var/log/syslog.tail(pattern=ERROR,mode=json)"

# Multiple parameters
./target/release/resh "log:///var/log/syslog.tail(lines=20,pattern=CRON,mode=json)"

# Relative paths
./target/release/resh "log://./app.log.tail(lines=50)"
```

### ❌ Incorrect Usage (Will Cause Bash Syntax Errors)

```bash
# Missing quotes - bash interprets parentheses
./target/release/resh log:///var/log/syslog.tail(lines=10)
# Error: bash: syntax error near unexpected token `('

# Partial quotes don't work
./target/release/resh log:///var/log/syslog.tail"(lines=10)"
# Error: command not found or other issues
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `lines` | number | 100 | Number of lines to return from end of file |
| `mode` | string | "raw" | Output mode: "raw" or "json" |
| `pattern` | string | none | Filter lines containing this text |

## Output Modes

### Raw Mode (Default)
Returns plain text lines, one per line:
```
Dec 19 06:17:01 ASUS-LT CRON[7723]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)
Dec 19 06:17:04 ASUS-LT systemd-resolved[372]: Clock change detected. Flushing caches.
```

### JSON Mode  
Returns structured JSON with metadata:
```json
{
  "lines": [
    "Dec 19 06:17:01 ASUS-LT CRON[7723]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)",
    "Dec 19 06:17:04 ASUS-LT systemd-resolved[372]: Clock change detected. Flushing caches."
  ],
  "path": "/var/log/syslog",
  "pattern": null,
  "requested_lines": 2,
  "returned_lines": 2
}
```

## Common Use Cases

### System Log Analysis
```bash
# Check recent system errors
./target/release/resh "log:///var/log/syslog.tail(pattern=error,mode=json)"

# Monitor cron job execution
./target/release/resh "log:///var/log/syslog.tail(pattern=CRON,lines=20)"

# Check systemd service messages
./target/release/resh "log:///var/log/syslog.tail(pattern=systemd,lines=30,mode=json)"
```

### Application Logs
```bash
# Check recent application errors
./target/release/resh "log://./logs/app.log.tail(pattern=ERROR,lines=50,mode=json)"

# Monitor specific service logs
./target/release/resh "log:///var/log/nginx/error.log.tail(lines=20)"

# Debug recent activity
./target/release/resh "log://./debug.log.tail(lines=100,pattern=DEBUG)"
```

## Error Handling

The log handle provides clear error messages:

```bash
# File doesn't exist
./target/release/resh "log:///nonexistent.log.tail"
# Output: Error: Log file does not exist: /nonexistent.log

# Invalid parameters
./target/release/resh "log:///var/log/syslog.tail(lines=0)"  
# Output: Error: lines must be greater than 0

./target/release/resh "log:///var/log/syslog.tail(mode=invalid)"
# Output: Error: mode must be 'raw' or 'json'
```

## Testing

Run the comprehensive test suite:
```bash
./tests/log_integration_test.sh
```