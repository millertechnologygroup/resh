# Process Control Handle (`proc://`)

The `proc://` handle lets you control and monitor processes running on your system. You can send signals, change priority levels, check output logs, and set resource limits.

## URL Format

```
proc://PID
proc://self
```

- `PID` - The process ID number of the target process
- `self` - Refers to the current process

## Available Verbs

### Signal Operations

#### `signal` - Send a custom signal

Send any signal to a process by name or number.

**Arguments:**
- `sig` - Signal name (like "TERM") or signal number (like 15)

**Examples:**
```bash
proc://1234.signal(sig=TERM)
proc://1234.signal(sig=15)
```

**Success Output:**
```json
{"pid":1234,"verb":"signal","signal":"TERM","signal_num":15,"ok":true}
```

**Error Output (process not found):**
```json
{"pid":99999999,"verb":"signal","signal":"TERM","signal_num":15,"ok":false,"error":"process not found"}
```

**Error Output (invalid signal):**
```json
{"pid":1234,"verb":"signal","ok":false,"error":"invalid signal: NOPE"}
```

**Error Output (missing argument):**
```json
{"pid":1234,"verb":"signal","ok":false,"error":"missing arg: sig"}
```

#### Signal Shortcuts

These verbs send specific signals without needing the `sig` argument:

- `kill` - Send SIGKILL (signal 9) - forces process to stop
- `term` - Send SIGTERM (signal 15) - asks process to stop nicely
- `int` - Send SIGINT (signal 2) - interrupt signal (like Ctrl+C)
- `hup` - Send SIGHUP (signal 1) - hangup signal
- `stop` - Send SIGSTOP (signal 19) - pause process
- `cont` - Send SIGCONT (signal 18) - resume paused process
- `usr1` - Send SIGUSR1 (signal 30) - user-defined signal 1
- `usr2` - Send SIGUSR2 (signal 31) - user-defined signal 2

**Examples:**
```bash
proc://1234.kill
proc://1234.term
proc://1234.int
proc://1234.hup
proc://1234.usr1
proc://1234.usr2
```

**Success Output:**
```json
{"pid":1234,"verb":"kill","signal":"KILL","signal_num":9,"ok":true}
```

### Priority Operations

#### `nice.get` - Get current priority level

Get the nice value (priority level) of a process. Lower numbers mean higher priority.

**Example:**
```bash
proc://self.nice.get
```

**Success Output:**
```json
{"pid":12345,"nice":0}
```

**Error Output (process not found):**
```json
{"pid":null,"verb":"nice.get","ok":false,"error":"no such process"}
```

#### `nice.set` - Set priority level

Set the nice value (priority level) of a process. Range is -20 (highest priority) to 19 (lowest priority).

**Arguments:**
- `value` - New nice value (-20 to 19)

**Example:**
```bash
proc://self.nice.set(value=5)
```

**Success Output:**
```json
{"pid":12345,"nice":5,"changed":true}
```

**Error Output (missing argument):**
```json
{"pid":12345,"verb":"nice.set","ok":false,"error":"missing arg: value"}
```

**Error Output (out of range):**
```json
{"pid":12345,"verb":"nice.set","ok":false,"error":"nice value out of range (-20..19)"}
```

**Error Output (invalid value):**
```json
{"pid":12345,"verb":"nice.set","ok":false,"error":"value must be an integer"}
```

#### `nice.inc` - Increase priority level (make lower priority)

Add to the nice value, making the process lower priority.

**Arguments:**
- `delta` - Amount to add to current nice value

**Example:**
```bash
proc://self.nice.inc(delta=1)
```

**Success Output:**
```json
{"pid":12345,"nice_before":0,"nice_after":1,"delta":1,"changed":true}
```

**Error Output (missing argument):**
```json
{"pid":12345,"verb":"nice.inc","ok":false,"error":"missing arg: delta"}
```

**Error Output (out of range):**
```json
{"pid":12345,"verb":"nice.inc","ok":false,"error":"nice value out of range (-20..19)"}
```

#### `nice.dec` - Decrease priority level (make higher priority)

Subtract from the nice value, making the process higher priority.

**Arguments:**
- `delta` - Amount to subtract from current nice value

**Example:**
```bash
proc://self.nice.dec(delta=1)
```

**Success Output:**
```json
{"pid":12345,"nice_before":1,"nice_after":0,"delta":1,"changed":true}
```

**Error Output (missing argument):**
```json
{"pid":12345,"verb":"nice.dec","ok":false,"error":"missing arg: delta"}
```

#### `setPriority` - Set priority using classes or exact values

Set process priority using either predefined classes or exact nice values.

**Arguments (choose one):**
- `class` - Priority class: "idle", "background", "normal", "high", or "realtime"
- `nice` - Exact nice value (-20 to 19)

**Class Examples:**
```bash
proc://1234.setPriority(class=background)
proc://1234.setPriority(class=normal)
```

**Nice Value Example:**
```bash
proc://1234.setPriority(nice=5)
```

**Success Output (class):**
```json
{"pid":1234,"class":"background","nice":10,"previous_nice":0,"backend":"linux-setpriority"}
```

**Success Output (nice value):**
```json
{"pid":1234,"class":"custom","nice":5,"previous_nice":0,"backend":"linux-setpriority"}
```

**Error Output (invalid class):**
```json
{"pid":1234,"setPriority","ok":false,"error":"invalid class"}
```

**Error Output (invalid nice value):**
```json
{"pid":1234,"setPriority","ok":false,"error":"invalid nice value"}
```

**Priority Class Mappings:**
- `idle` - Nice value 19 (lowest priority)
- `background` - Nice value 10 (low priority)
- `normal` - Nice value 0 (default priority)
- `high` - Nice value -5 (high priority)
- `realtime` - Nice value -10 (very high priority)

### Output Monitoring

#### `io.peek` - Check process output logs

Read recent output from a process's stdout or stderr logs.

**Arguments (all optional):**
- `stream` - Which stream to read: "stdout", "stderr", or "both" (default: "stdout")
- `max_bytes` - Maximum bytes to return (default: 4096)
- `tail` - Read from end of file, max bytes (default: same as max_bytes)
- `encoding` - How to encode output: "auto", "utf8", or "base64" (default: "auto")
- `json` - Return JSON format: "true" or "false" (default: "true")

**Examples:**
```bash
proc://1234.io.peek
proc://1234.io.peek(stream=stderr)
proc://1234.io.peek(stream=both)
proc://1234.io.peek(max_bytes=100,tail=100)
proc://1234.io.peek(encoding=base64)
proc://1234.io.peek(json=false)
```

**Success Output (single stream):**
```json
{"pid":1234,"stream":"stdout","encoding":"utf8","auto_fallback":false,"bytes_read":23,"truncated":false,"data":"hello world\nmore data\n"}
```

**Success Output (both streams):**
```json
{"pid":1234,"streams":{"stdout":{"encoding":"utf8","auto_fallback":false,"bytes_read":13,"truncated":false,"data":"stdout content"},"stderr":{"encoding":"utf8","auto_fallback":false,"bytes_read":13,"truncated":false,"data":"stderr content"}}}
```

**Error Output (invalid stream):**
```json
{"error":"invalid stream value: invalid"}
```

**Error Output (log file not found):**
```json
{"error":"log file not found: /path/to/log"}
```

### Resource Limits

#### `limits.set` - Set resource limits

Set resource limits for a process using the rlimit system.

**Arguments:**
- Resource names with values (see supported resources below)
- `pid` - Target process ID (optional, defaults to handle PID)
- `dry_run` - Check without applying: "true" or "false" (optional)

**Supported Resources:**
- `cpu` - CPU time in seconds (suffix: `s`)
- `as` - Address space in bytes (suffixes: `K`, `M`, `G`)
- `data` - Data segment size in bytes
- `stack` - Stack size in bytes  
- `core` - Core file size in bytes
- `nofile` - Number of open files
- `fsize` - File size in bytes
- `memlock` - Locked memory in bytes
- `nproc` - Number of processes (Linux only)

**Limit Value Formats:**
- Single number: Sets soft limit, keeps hard limit unchanged
- `soft:hard` format: Sets both limits
- `unlimited` - Remove limit
- Suffixes for bytes: `K` (1000), `M` (1000000), `G` (1000000000)
- Suffixes for time: `s` (seconds)

**Examples:**
```bash
proc://1234.limits.set(nofile=4096:8192)
proc://self.limits.set(cpu=300s)
proc://1234.limits.set(as=1G,data=512M)
proc://1234.limits.set(dry_run=true,nofile=4096:8192)
```

**Success Output:**
```json
{"pid":1234,"backend":"rlimit","results":{"nofile":{"requested":"4096:8192","before":{"soft":1024,"hard":4096},"after":{"soft":4096,"hard":8192},"status":"ok"}}}
```

**Error Output (invalid resource):**
```json
{"pid":1234,"backend":"rlimit","results":{"invalid":{"requested":"1024","status":"error","error":"unknown resource: 'invalid'"}}}
```

**Error Output (invalid limit value):**
```json
{"pid":1234,"backend":"rlimit","results":{"nofile":{"requested":"abc","status":"error","error":"invalid limit value: 'abc'"}}}
```

## Platform Support

- **Unix/Linux**: All verbs supported
- **Windows**: Not supported - all verbs will return platform error

## Error Codes

- **1** - General error (unknown verb, invalid signal, etc.)
- **2** - Missing or invalid arguments
- **3** - Process not found or invalid parameters
- **4** - Permission denied or process access error
- **5** - Platform not supported

## Examples

### Basic Process Control
```bash
# Check if process exists by getting its priority
proc://1234.nice.get

# Stop a process nicely, then force kill if needed
proc://1234.term
proc://1234.kill

# Pause and resume a process
proc://1234.stop
proc://1234.cont
```

### Priority Management
```bash
# Set process to background priority
proc://1234.setPriority(class=background)

# Make current process lower priority
proc://self.nice.inc(delta=5)

# Set specific nice value
proc://1234.nice.set(value=10)
```

### Output Monitoring
```bash
# Check recent output
proc://1234.io.peek

# Get last 200 bytes from stderr
proc://1234.io.peek(stream=stderr,max_bytes=200)

# Check both stdout and stderr
proc://1234.io.peek(stream=both)
```

### Resource Management
```bash
# Limit file handles
proc://1234.limits.set(nofile=2048:4096)

# Set CPU time limit
proc://1234.limits.set(cpu=600s)

# Test limits without applying
proc://1234.limits.set(dry_run=true,as=1G)
```