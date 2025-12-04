# MQ Handle Documentation

The MQ (Message Queue) handle in Resource Shell provides a simple file-based message queue system. It allows you to create queues, put messages in them, get messages from them, and manage queue state.

## Queue URLs

MQ handles use URLs in the format: `mq://queue-name`

Queue names are automatically sanitized to be filesystem-safe. Unsafe characters are replaced with underscores, and names are limited to 120 characters.

## Supported Verbs

### create
Creates a new message queue directory structure. This operation is idempotent - calling it multiple times is safe.

**Example:**
```bash
resh "mq://myqueue.create"
```

**Output:** No output on success

### put
Adds a message to the queue. Messages can be provided as an argument or read from stdin.

**Examples:**

Using data argument:
```bash
resh "mq://testqueue.put(data=hello)"
```

Using stdin:
```bash
echo "hello-stdin" | resh "mq://stdinqueue.put"
```

Binary data from stdin:
```bash
printf "\x00\x01\x02\xff\xfe" | resh "mq://binary.put"
```

**Output:** No output on success

### get
Retrieves and removes the oldest message from the queue (FIFO order). Returns exit code 2 if the queue is empty.

**Example:**
```bash
resh "mq://testqueue.get"
```

**Output:** The message content
**Exit Code:** 0 on success, 2 if queue is empty

**FIFO Example:**
```bash
# Put messages in order
resh "mq://fifotest.put(data=one)"
resh "mq://fifotest.put(data=two)"
resh "mq://fifotest.put(data=three)"

# Get messages (returns in same order)
resh "mq://fifotest.get"  # Returns: one
resh "mq://fifotest.get"  # Returns: two  
resh "mq://fifotest.get"  # Returns: three
resh "mq://fifotest.get"  # Exit code 2, empty queue
```

### len
Returns the number of messages currently in the queue.

**Example:**
```bash
resh "mq://testqueue.len"
```

**Output:** Number of messages (e.g., "0", "1", "3")

**Example with multiple messages:**
```bash
# Start with empty queue
resh "mq://len-test-2.len"  # Returns: 0

# Add messages
resh "mq://len-test-2.put(data=one)"
resh "mq://len-test-2.put(data=two)"
resh "mq://len-test-2.put(data=three)"

resh "mq://len-test-2.len"  # Returns: 3
```

### peek
Returns the oldest message from the queue without removing it. Returns exit code 2 if the queue is empty.

**Example:**
```bash
resh "mq://demo.peek"
```

**Output:** The message content
**Exit Code:** 0 on success, 2 if queue is empty

**Non-destructive Example:**
```bash
# Put two messages
resh "mq://demo.put(data=one)"
resh "mq://demo.put(data=two)"

# Peek multiple times (always returns first message)
resh "mq://demo.peek"  # Returns: one
resh "mq://demo.peek"  # Returns: one (still there)

resh "mq://demo.len"   # Returns: 2 (nothing consumed)

# Get consumes the message
resh "mq://demo.get"   # Returns: one
resh "mq://demo.peek"  # Returns: two (now first)
```

### purge
Removes all messages from the queue, making it empty. This operation is idempotent.

**Example:**
```bash
resh "mq://purge-test.purge"
```

**Output:** No output on success

**Complete Example:**
```bash
# Add messages
resh "mq://purge-test.put(data=message1)"
resh "mq://purge-test.put(data=message2)"
resh "mq://purge-test.put(data=message3)"

resh "mq://purge-test.len"    # Returns: 3

# Clear all messages
resh "mq://purge-test.purge"

resh "mq://purge-test.len"    # Returns: 0
resh "mq://purge-test.get"    # Exit code 2, empty queue
```

## Queue Name Sanitization

Queue names with unsafe characters are automatically sanitized:

```bash
# These all refer to the same sanitized queue
resh "mq://deploy/../strange name!!.put(data=weird)"
resh "mq://deploy/../strange name!!.len"     # Returns: 1
resh "mq://deploy/../strange name!!.get"     # Returns: weird
```

## Error Handling

- **Empty Queue**: `get` and `peek` operations return exit code 2 when the queue is empty
- **Invalid Operations**: Unknown verbs return an error message
- **File System Errors**: Directory creation or file operation failures are reported

## Data Handling

- Messages preserve exact content including newlines, tabs, and binary data
- No extra formatting or decoration is added to message output
- Binary data is supported through stdin input and preserved exactly

## Concurrency

The MQ handle uses atomic file operations to ensure message integrity during concurrent access. Messages are written to temporary files and then atomically moved to their final location.